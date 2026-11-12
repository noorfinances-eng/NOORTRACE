// Production du paquet client (CT-4 §7.13, EX-7.18 à EX-7.22, EX-7.30 ;
// INTERFACES.md 4.1) : le travail `paquet` rend la sortie de `paquet-client
// produire` de l'outil de référence (révision 0.7), mêmes `result`,
// `exit_code`, `error.code`, `checks` (OP-4) et membres des `outputs`.
//
// Ordre, celui d'EX-7.30 : dossier (schéma, `entree_illisible` ; fini,
// `dossier_inacheve`), instance (manifeste de l'agent exigé si et seulement si
// `manifest_sha256` n'est pas nul, `usage` sinon ; mêmes SHA-256 et
// identifiants, `chaine_differente` ; sans manifeste, réseau de développement
// seulement, `reseau_non_developpement`), OP-4 hors ligne, résolution des
// références employées pour l'organisation (EX-7.3, EX-7.21), gabarit
// (EX-7.20), captures de chaque étape contre CP-6 et contre l'étape
// (`capture_incomplete`, vérification CP-6), écriture dans un répertoire
// temporaire, contrôle d'EX-7.22, recherche d'EX-7.21, puis renommage. Un
// refus ne laisse aucun paquet. Le paquet s'écrit sous
// `clients/<slug>/paquets/<n>/paquet-client-<slug>`, `n` croissant : un paquet
// remis n'est jamais remplacé (EX-7.30), et chaque production a son
// répertoire, comme `--sortie` de l'outil.

import fs from "node:fs";
import path from "node:path";
import { ecrireHorodatage, keccak256, octetsVersHex, sha256Hex, utf8 } from "@noortrace/noyau";
import { comparerOctets, FICHIERS_RACINE, MANIFESTE_PAQUET, nomPaquet, roleCapture, serialiserDocument, sortieControle } from "../../commun/paquet.mjs";
import { IDS, valider } from "../../commun/schemas.mjs";
import { MOTIF_SLUG } from "../../commun/champs.mjs";
import { lireDossier } from "../dossier.mjs";
import { ErreurReference, octetsSecrets } from "../cles.mjs";
import { lireLignes, MODE_FICHIER, MODE_REPERTOIRE, synchroniser } from "../donnees.mjs";
import { Sortie } from "../sortie.mjs";
import { SOURCE } from "../version.mjs";

/** Identifiant EVM du réseau de développement (EX-7.2). */
const EVM_DEVELOPPEMENT = 2124;

/** Formes textuelles d'un secret de 32 octets cherchées par EX-7.21. */
export function formesSecret(octets) {
  const b = Buffer.from(octets);
  const hex = b.toString("hex");
  const b64 = b.toString("base64");
  const b64u = b.toString("base64url");
  return {
    hexadecimal: hex,
    base64: [...new Set([b64, b64.replace(/=+$/, ""), b64u, b64u.replace(/=+$/, ""), b64u + "=".repeat((4 - (b64u.length % 4)) % 4)])],
  };
}

/** Un fichier contient-il l'une des formes ? (hexadécimal sans tenir compte de la casse, avec ou sans `0x` ; base64 tel quel ; jeton tel quel). */
export function contientSecret(octets, { hexadecimaux, exacts }) {
  const texte = Buffer.from(octets).toString("latin1");
  const bas = texte.toLowerCase();
  if (hexadecimaux.some((h) => bas.includes(h))) return true;
  return exacts.some((e) => e.length > 0 && texte.includes(e));
}

/**
 * Références de clés employées pour l'organisation (EX-7.21, révision 0.7) :
 * celles qu'ont employées les travaux de ce client, telles que `cleRole` les
 * a résolues (lignes `reference_employee` du journal de l'agent), qu'elles
 * viennent du travail ou des comptes de la configuration. Un compte de la
 * configuration qu'aucun travail du client n'a employé n'est pas cherché :
 * l'outil de référence cherche les références que l'exploitant lui donne,
 * celles qu'il a employées pour cette inscription, et les deux sorties
 * `paquet-client` portent alors le même `secrets_checked` (EX-7.24). Rend
 * `[{ reference, role, option }]`, sans doublon de couple option et
 * référence, dans l'ordre du journal ; `option` est le nom de l'option de
 * l'outil de référence qui désigne ce rôle (EX-7.30).
 */
export function referencesEmployees(ctx) {
  const refs = [];
  for (const l of lireLignes(ctx.donnees.journal)) {
    if (l.evenement !== "reference_employee" || l.slug !== ctx.slug || typeof l.reference !== "string") continue;
    refs.push({ reference: l.reference, role: l.role, option: optionDuRole(l.role) });
  }
  const vus = new Set();
  return refs.filter((r) => {
    const cle = JSON.stringify([r.option, r.reference]);
    return vus.has(cle) ? false : vus.add(cle);
  });
}

/** Nom de l'option de l'outil de référence qui désigne la clé d'un rôle (EX-7.3, EX-7.21). */
export function optionDuRole(role) {
  return `--${String(role).replace(/_/g, "-")}`;
}

/** Copie un fichier octet pour octet ; rend ses octets. */
function copier(source, cible) {
  const octets = fs.readFileSync(source);
  fs.writeFileSync(cible, octets, { flag: "wx", mode: MODE_FICHIER });
  return octets;
}

/** Prochain numéro de production sous `paquets/` (1, 2, …). */
function prochainNumero(base) {
  let n = 0;
  try {
    for (const x of fs.readdirSync(base)) if (/^[1-9][0-9]*$/.test(x)) n = Math.max(n, Number(x));
  } catch {
    // aucun paquet encore
  }
  return n + 1;
}

/** Captures de chaque étape contre CP-6 et contre l'étape : rend la liste triée des noms, ou arrête `capture_incomplete`. */
function capturesDesEtapes(ctx, sortie, d) {
  const noms = new Set();
  for (const e of d.steps) {
    if (e.capture === null) continue;
    let index;
    try {
      index = JSON.parse(fs.readFileSync(path.join(ctx.captures, e.capture), "utf8"));
    } catch {
      sortie.arreter("refuse", "capture_incomplete", "CP-6", `${e.capture} absent ou illisible dans les captures du client`);
    }
    if (!valider(IDS.operations, index).valide) sortie.arreter("refuse", "capture_incomplete", "CP-6", `${e.capture} hors de son schéma`);
    if (index.block_number !== e.block_number || index.block_hash !== e.block_hash || index.transaction_hash !== e.transaction_hash) {
      sortie.arreter("refuse", "capture_incomplete", "CP-6", `${e.capture} ne porte pas la transaction de l'étape ${e.step} (${e.subject})`);
    }
    noms.add(e.capture);
    for (const f of [index.files.block, ...index.files.receipts, index.files.certificate]) {
      let o;
      try {
        o = fs.readFileSync(path.join(ctx.captures, f.name));
      } catch {
        sortie.arreter("refuse", "capture_incomplete", "CP-6", `${f.name} absent des captures du client`);
      }
      if (sha256Hex(o) !== f.sha256) sortie.arreter("refuse", "capture_incomplete", "CP-6", `${f.name} : SHA-256 différent de celui de l'index ${e.capture}`);
      noms.add(f.name);
    }
  }
  const liste = [...noms].sort((a, b) => comparerOctets(`captures/${a}`, `captures/${b}`));
  for (const nom of liste) if (!roleCapture(nom)) sortie.arreter("refuse", "capture_incomplete", "CP-6", `nom de capture hors de CP-6 : ${nom}`);
  return liste;
}

/** Produit et contrôle le paquet ; rend la sortie `paquet-client` (EX-7.30). */
export async function produirePaquet(ctx, travail) {
  const sortie = new Sortie("paquet-client", ctx);
  const p = travail.parametres;
  // Dossier : schéma, puis fini.
  if (!fs.existsSync(ctx.client.dossier)) sortie.arreter("inutilisable", "usage", null, `aucun dossier pour le client ${ctx.slug}`);
  const l = lireDossier(ctx.client.dossier);
  if (l.erreur) sortie.arreter("inutilisable", "entree_illisible", null, l.erreur);
  const d = l.dossier;
  const ouverte = d.steps.find((e) => e.state !== "capturee" && e.state !== "faite");
  if (ouverte || d.result === null) {
    sortie.arreter("refuse", "dossier_inacheve", null, ouverte
      ? `dossier non fini (étape ${ouverte.step} (${ouverte.subject}) à l'état ${ouverte.state}) : le paquet se produit à la fin de l'inscription, chaque étape capturee ou faite et result rempli (EX-7.18, 7.10)`
      : "dossier non fini (result nul) : le paquet se produit à la fin de l'inscription (EX-7.18, 7.10)");
  }
  // Instance : celle de l'agent, de mêmes SHA-256 et identifiants que le dossier.
  const ms = d.instance.manifest_sha256;
  const tenu = ctx.instance.manifeste === null ? null : ctx.instance.manifestSha256;
  if (ms !== null && tenu === null) sortie.arreter("inutilisable", "usage", null, `le dossier nomme le manifeste d'instance ${ms} ; l'agent n'en tient aucun`);
  if (ms === null && tenu !== null) sortie.arreter("inutilisable", "usage", null, "le dossier ne nomme aucun manifeste d'instance ; l'agent en tient un");
  if (ms !== tenu || d.instance.evm_chain_id !== ctx.instance.evmChainId || d.instance.bft_chain_id !== ctx.instance.bftChainId) {
    sortie.arreter("refuse", "chaine_differente", null, "l'instance tenue par l'agent n'est pas celle du dossier (SHA-256 du manifeste ou identifiants)");
  }
  if (ms === null && d.instance.evm_chain_id !== EVM_DEVELOPPEMENT) {
    sortie.arreter("refuse", "reseau_non_developpement", null, `sans manifeste d'instance, seul le réseau de développement ${EVM_DEVELOPPEMENT} est admis (EX-7.2)`);
  }
  // OP-4 hors ligne : slug et org_id du dossier (RG-1).
  const org = d.organisation.slug;
  if (!MOTIF_SLUG.test(org) || d.organisation.org_id !== octetsVersHex(keccak256(utf8(org)))) {
    sortie.echec("OP-4", "inutilisable", "entree_illisible", "organisation du dossier : slug hors de RG-1 ou org_id différent de keccak256(slug)");
  }
  sortie.reussie("OP-4");
  // Références employées pour l'organisation (EX-7.3, EX-7.21) : chacune doit se résoudre.
  const cherches = [];
  for (const r of referencesEmployees(ctx)) {
    let octets;
    try {
      octets = octetsSecrets(r.reference, { role: r.role, nature: ctx.instance.nature, evmChainId: ctx.instance.evmChainId });
    } catch (e) {
      if (e instanceof ErreurReference && e.code === "reseau_non_developpement") sortie.arreter("refuse", "reseau_non_developpement", null, e.message);
      sortie.arreter("inutilisable", "entree_illisible", null, `${r.role} : la référence employée pour l'inscription ne se résout plus ; la recherche d'EX-7.21 est impossible`);
    }
    const f = formesSecret(octets);
    octets.fill(0);
    cherches.push({ nom: `${r.role} (référence ${String(r.reference).split(":")[0]}:)`, option: r.option, reference: r.reference, hexadecimaux: [f.hexadecimal], exacts: f.base64 });
  }
  if (ctx.jeton) cherches.push({ nom: "le jeton du nœud", option: "--jeton", reference: ctx.config.jeton, hexadecimaux: [], exacts: [ctx.jeton] });
  // Gabarit (EX-7.20).
  const gabarit = { version: 0, org, org_id: d.organisation.org_id, console_origin: p.console_origin, administrators: p.administrators };
  const vg = valider(`${IDS.paquet}#/$defs/gabarit_service`, gabarit);
  if (!vg.valide) sortie.arreter("inutilisable", "entree_illisible", null, `gabarit hors de paquet-client-v0#/$defs/gabarit_service : ${vg.erreurs[0]} (EX-7.20)`);
  // Captures de chaque étape.
  const captures = capturesDesEtapes(ctx, sortie, d);

  // Écriture dans un répertoire temporaire nommé comme le paquet (le point 4 d'EX-7.22 contrôle le nom).
  const base = path.join(ctx.client.dir, "paquets");
  fs.mkdirSync(base, { recursive: true, mode: MODE_REPERTOIRE });
  const parentTemp = path.join(base, `.production-${ctx.travailId}`);
  const temp = path.join(parentTemp, nomPaquet(org));
  fs.rmSync(parentTemp, { recursive: true, force: true });
  try {
    fs.mkdirSync(path.join(temp, "captures"), { recursive: true, mode: MODE_REPERTOIRE });
    const fichiers = [];
    const entree = (chemin, role, octets) => fichiers.push({ path: chemin, role, sha256: sha256Hex(octets), length: octets.length });
    entree(FICHIERS_RACINE.dossier, "dossier", copier(ctx.client.dossier, path.join(temp, FICHIERS_RACINE.dossier)));
    if (ms !== null) {
      const o = Buffer.from(ctx.instance.manifesteOctets);
      fs.writeFileSync(path.join(temp, FICHIERS_RACINE.manifeste_instance), o, { flag: "wx", mode: MODE_FICHIER });
      entree(FICHIERS_RACINE.manifeste_instance, "manifeste_instance", o);
    }
    const jeu = serialiserDocument(d.result.approver_set);
    fs.writeFileSync(path.join(temp, FICHIERS_RACINE.jeu_approbateurs), jeu, { flag: "wx", mode: MODE_FICHIER });
    entree(FICHIERS_RACINE.jeu_approbateurs, "jeu_approbateurs", jeu);
    const g = serialiserDocument(gabarit);
    fs.writeFileSync(path.join(temp, FICHIERS_RACINE.gabarit_service), g, { flag: "wx", mode: MODE_FICHIER });
    entree(FICHIERS_RACINE.gabarit_service, "gabarit_service", g);
    for (const nom of captures) entree(`captures/${nom}`, roleCapture(nom), copier(path.join(ctx.captures, nom), path.join(temp, "captures", nom)));
    const manifeste = {
      version: 0, org, org_id: d.organisation.org_id,
      instance: { evm_chain_id: d.instance.evm_chain_id, bft_chain_id: d.instance.bft_chain_id, manifest_sha256: ms },
      files: fichiers, prepared_by: p.prepared_by, prepared_at: ecrireHorodatage(ctx.horloge.murale()), source: SOURCE,
    };
    fs.writeFileSync(path.join(temp, MANIFESTE_PAQUET), serialiserDocument(manifeste), { flag: "wx", mode: MODE_FICHIER });

    // Contrôle d'EX-7.22 puis recherche d'EX-7.21, sur le répertoire temporaire.
    const references = cherches.map((c) => ({ option: c.option, reference: c.reference }));
    const rechercheSecrets = (repertoire) => {
      const chemins = [MANIFESTE_PAQUET, ...fichiers.map((x) => x.path)];
      for (const chemin of chemins) {
        const octets = fs.readFileSync(path.join(repertoire, chemin));
        for (const c of cherches) if (contientSecret(octets, c)) return { references, trouve: { fichier: chemin, nom: c.nom } };
      }
      return { references, trouve: null };
    };
    const controle = sortieControle(temp, { rechercheSecrets });
    for (const c of cherches) {
      c.hexadecimaux.length = 0;
      c.exacts.length = 0;
    }
    if (controle.result !== "reussi") {
      if (controle.error.code === "secret_present") ctx.consigner("paquet_secret_trouve", { slug: ctx.slug, fichiers: [controle.outputs.file] });
      sortie.arreter(controle.result, controle.error.code, null, controle.error.message, controle.outputs);
    }
    const dossierFinal = path.join(base, String(prochainNumero(base)));
    fs.mkdirSync(dossierFinal, { mode: MODE_REPERTOIRE });
    const final = path.join(dossierFinal, nomPaquet(org));
    fs.renameSync(temp, final);
    synchroniser(dossierFinal);
    return sortie.rendre("reussi", { outputs: { ...controle.outputs, directory: final } });
  } finally {
    fs.rmSync(parentTemp, { recursive: true, force: true });
  }
}
