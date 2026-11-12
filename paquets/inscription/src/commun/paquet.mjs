// Paquet client (CT-4 §7.13, révision 0.7) : constantes de forme, écriture
// des documents créés (EX-7.18), et contrôle de réception d'EX-7.22,
// `controlerPaquet(repertoire, { schemas })`, utilisable par le client hors
// de l'application ; l'agent l'applique avant toute remise (INTERFACES.md
// 4.3).
//
// Le contrôle suit les six points d'EX-7.22 dans leur ordre et rend chaque
// écart `{ point, fichier, code, erreur }` : `code` est le motif propre à ce
// module (LISEZMOI.md, « Contrôle du paquet »), `erreur` le code de refus
// d'EX-7.30 qui vise ce point (`paquet_manifeste` à `paquet_captures`). Un
// écart au point 1 (manifeste du paquet illisible ou hors de son schéma)
// arrête le contrôle, les points suivants ne pouvant pas se lire sans lui.
// `sortieControle` rend la même sortie que `paquet-client controler` de
// l'outil de référence (EX-7.30) : le premier écart, ou la réussite.

import fs from "node:fs";
import path from "node:path";
import { lireJsonStrict, egaliteJson } from "@noortrace/approbation";
import { keccak256, octetsVersHex, sha256Hex, utf8 } from "@noortrace/noyau";
import { lireFichierRpc } from "@noortrace/ancrage/registre";
import { IDS, registreSchemas, valider } from "./schemas.mjs";

/** Fichiers créés ou recopiés à la racine du paquet, dans l'ordre d'EX-7.19 (le manifeste du paquet exclu). */
export const FICHIERS_RACINE = Object.freeze({
  dossier: "inscription-client.json",
  manifeste_instance: "instance-registre.json",
  jeu_approbateurs: "jeu-approbateurs.json",
  gabarit_service: "gabarit-service-approbation.json",
});

/** Nom du manifeste du paquet. */
export const MANIFESTE_PAQUET = "paquet-client.json";

/** Nom du répertoire du paquet (EX-7.18). */
export const nomPaquet = (slug) => `paquet-client-${slug}`;

/**
 * Dernier paquet produit pour un client : `<répertoire du client>/paquets/<n>/paquet-client-<slug>`
 * de plus grand `n` (chaque production a son répertoire, un paquet remis n'est jamais remplacé), ou null.
 */
export function dernierPaquet(dirClient, slug) {
  const base = path.join(dirClient, "paquets");
  let n = 0;
  try {
    for (const x of fs.readdirSync(base)) if (/^[1-9][0-9]*$/.test(x)) n = Math.max(n, Number(x));
  } catch {
    return null;
  }
  if (n < 1) return null;
  const r = path.join(base, String(n), nomPaquet(slug));
  return fs.existsSync(path.join(r, MANIFESTE_PAQUET)) ? r : null;
}

/** Sérialisation des documents créés par le paquet : `JSON.stringify(objet, null, 2)` et un saut de ligne (EX-7.18). */
export function serialiserDocument(objet) {
  return Buffer.from(JSON.stringify(objet, null, 2) + "\n", "utf8");
}

/** Rôle d'un fichier de `captures/` d'après son nom (CP-6), ou null. */
export function roleCapture(nom) {
  if (/^capture-[0-9]{1,20}-[0-9]{1,5}-(jeu_approbateurs|assignation|approvisionnement|inscription|ancre|cloture)\.json$/.test(nom)) return "capture_index";
  if (/^bloc-[0-9]{1,20}\.json$/.test(nom)) return "capture_bloc";
  if (/^recu-0x[0-9a-f]{64}\.json$/.test(nom)) return "capture_recu";
  if (/^certificat-[0-9]{1,20}\.json$/.test(nom)) return "capture_certificat";
  return null;
}

/** Comparaison par octets de deux chemins (ordre d'EX-7.19 pour `captures/`). */
export function comparerOctets(a, b) {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

/** Code de refus d'EX-7.30 par point d'EX-7.22. */
export const CODE_POINT = Object.freeze({ 1: "paquet_manifeste", 2: "paquet_fichiers", 3: "paquet_forme", 4: "paquet_organisation", 5: "paquet_jeu", 6: "paquet_captures" });

/** Réponse brute du nœud complète (EX-7.22, point 3, révision 0.7) : JSON-RPC 2.0, `id`, `result` objet. */
function reponseRpcComplete(octets) {
  const l = lireFichierRpc(octets);
  if (!l) return false;
  const j = l.json;
  return j.jsonrpc === "2.0" && "id" in j && l.resultat !== null && typeof l.resultat === "object" && !Array.isArray(l.resultat);
}

/** Les octets sont-ils l'écriture d'EX-7.18 de leur objet (`JSON.stringify(objet, null, 2)` et un saut de ligne) ? */
function ecritSelonEx718(octets, valeur) {
  return Buffer.from(octets).equals(serialiserDocument(valeur));
}

/** Rang d'un rôle dans l'ordre d'EX-7.19. */
const RANG = { dossier: 0, manifeste_instance: 1, jeu_approbateurs: 2, gabarit_service: 3 };

function lireJson(octets) {
  try {
    return { valeur: lireJsonStrict(octets) };
  } catch (e) {
    return { erreur: String(e?.message ?? e) };
  }
}

/**
 * Parcourt le répertoire du paquet : rend `{ fichiers: Map<chemin relatif,
 * octets>, anomalies: [{ fichier, code }] }`. Seuls sont admis des fichiers
 * ordinaires à la racine et dans `captures/`, sans lien symbolique ni
 * sous-répertoire de `captures/`.
 */
function parcourir(repertoire) {
  const fichiers = new Map();
  const anomalies = [];
  const lire = (relatif, absolu) => {
    const st = fs.lstatSync(absolu);
    if (st.isFile()) fichiers.set(relatif, new Uint8Array(fs.readFileSync(absolu)));
    else anomalies.push({ fichier: relatif, code: "fichier_non_ordinaire" });
  };
  for (const nom of fs.readdirSync(repertoire).sort(comparerOctets)) {
    const absolu = path.join(repertoire, nom);
    const st = fs.lstatSync(absolu);
    if (nom === "captures" && st.isDirectory()) {
      for (const n of fs.readdirSync(absolu).sort(comparerOctets)) lire(`captures/${n}`, path.join(absolu, n));
    } else lire(nom, absolu);
  }
  return { fichiers, anomalies };
}

/**
 * Contrôle de réception d'un paquet client (EX-7.22). `schemas` : un
 * `RegistreSchemas` où sont chargés les schémas du paquet (par défaut ceux
 * de `schemas/`). Rend `{ valide, ecarts: [{ point, fichier, code }] }`.
 */
export function controlerPaquet(repertoire, { schemas = registreSchemas() } = {}) {
  const { valide, ecarts } = controler(repertoire, schemas);
  return { valide, ecarts };
}

function controler(repertoire, schemas) {
  const ecarts = [];
  const ecart = (point, fichier, code) => ecarts.push({ point, fichier, code, erreur: CODE_POINT[point] });
  let parcours;
  try {
    parcours = parcourir(repertoire);
  } catch {
    ecart(1, MANIFESTE_PAQUET, "repertoire_illisible");
    return { valide: false, ecarts };
  }
  const { fichiers } = parcours;

  // Point 1 : paquet-client.json conforme à son schéma.
  const octetsManifeste = fichiers.get(MANIFESTE_PAQUET);
  if (!octetsManifeste) {
    ecart(1, MANIFESTE_PAQUET, "absent");
    return { valide: false, ecarts };
  }
  const lu = lireJson(octetsManifeste);
  if (lu.erreur) {
    ecart(1, MANIFESTE_PAQUET, "illisible");
    return { valide: false, ecarts };
  }
  const manifeste = lu.valeur;
  if (!valider(IDS.paquet, manifeste, schemas).valide) {
    ecart(1, MANIFESTE_PAQUET, "schema");
    return { valide: false, ecarts };
  }

  // Point 2 : chaque fichier listé une fois, chaque entrée désigne un fichier ordinaire de mêmes SHA-256 et longueur ;
  // ordre d'EX-7.19 ; au moins le dossier, le jeu d'approbateurs et le gabarit.
  for (const a of parcours.anomalies) ecart(2, a.fichier, a.code);
  const vus = new Map();
  for (const f of manifeste.files) {
    if (vus.has(f.path)) {
      ecart(2, f.path, "entree_double");
      continue;
    }
    vus.set(f.path, f);
    const octets = fichiers.get(f.path);
    if (!octets) {
      if (!parcours.anomalies.some((a) => a.fichier === f.path)) ecart(2, f.path, "fichier_absent");
      continue;
    }
    if (sha256Hex(octets) !== f.sha256) ecart(2, f.path, "sha256_different");
    if (octets.length !== f.length) ecart(2, f.path, "longueur_differente");
  }
  for (const chemin of fichiers.keys()) {
    if (chemin !== MANIFESTE_PAQUET && !vus.has(chemin)) ecart(2, chemin, "fichier_non_liste");
  }
  for (const role of ["dossier", "jeu_approbateurs", "gabarit_service"]) {
    if (!manifeste.files.some((f) => f.role === role)) ecart(2, FICHIERS_RACINE[role], "fichier_obligatoire_absent");
  }
  {
    // Ordre d'EX-7.19 : rôles de la racine dans leur ordre, puis captures/ par octets croissants ; le fichier signalé
    // est celui de la première entrée hors de sa place, ou dont le rôle ne correspond pas au chemin.
    const roleDuChemin = (f) => (f.path.startsWith("captures/") ? roleCapture(f.path.slice("captures/".length)) : Object.keys(FICHIERS_RACINE).find((r) => FICHIERS_RACINE[r] === f.path) ?? null);
    const rang = (f) => (f.path.startsWith("captures/") ? 4 : RANG[roleDuChemin(f)] ?? 5);
    const attendu = [...manifeste.files].sort((a, b) => rang(a) - rang(b) || (rang(a) === 4 ? comparerOctets(a.path, b.path) : 0));
    const k = manifeste.files.findIndex((f, i) => f.path !== attendu[i].path || roleDuChemin(f) !== f.role);
    if (k >= 0) ecart(2, manifeste.files[k].path, "ordre_files");
  }

  // Point 3 : chaque fichier conforme à la forme de son rôle (table d'EX-7.18).
  const docs = {};
  for (const f of manifeste.files) {
    const octets = fichiers.get(f.path);
    if (!octets) continue;
    if (f.role === "capture_bloc" || f.role === "capture_recu" || f.role === "capture_certificat") {
      if (!reponseRpcComplete(octets)) ecart(3, f.path, "forme");
      continue;
    }
    const l = lireJson(octets);
    if (l.erreur) {
      ecart(3, f.path, "forme");
      continue;
    }
    const ref = {
      dossier: IDS.inscription,
      manifeste_instance: IDS.instance,
      jeu_approbateurs: `${IDS.politique}#/$defs/jeu_approbateurs`,
      gabarit_service: `${IDS.paquet}#/$defs/gabarit_service`,
      capture_index: IDS.operations,
    }[f.role];
    if (!valider(ref, l.valeur, schemas).valide) {
      ecart(3, f.path, "forme");
      continue;
    }
    if (["jeu_approbateurs", "gabarit_service"].includes(f.role) && !ecritSelonEx718(octets, l.valeur)) {
      ecart(3, f.path, "ecriture");
      continue;
    }
    if (f.role === "dossier") {
      const d = l.valeur;
      const fini = d.result !== null && d.steps.every((e) => e.state === "capturee" || e.state === "faite");
      if (!fini) ecart(3, f.path, "dossier_non_fini");
    }
    if (f.role === "capture_index") (docs.index ??= new Map()).set(f.path, l.valeur);
    else docs[f.role] = { valeur: l.valeur, octets };
  }

  // Point 3 (révision 0.7) : le manifeste du paquet est lui aussi écrit selon EX-7.18.
  if (!ecritSelonEx718(octetsManifeste, manifeste)) ecart(3, MANIFESTE_PAQUET, "ecriture");

  // Point 4 : org, org_id, instance, manifeste d'instance, nom du répertoire (révision 0.7).
  const dossier = docs.dossier?.valeur ?? null;
  if (dossier) {
    if (manifeste.org !== dossier.organisation.slug) ecart(4, MANIFESTE_PAQUET, "org_different");
    const orgId = octetsVersHex(keccak256(utf8(manifeste.org)));
    if (manifeste.org_id !== orgId || manifeste.org_id !== dossier.organisation.org_id) ecart(4, MANIFESTE_PAQUET, "org_id_different");
    const i = dossier.instance;
    if (manifeste.instance.evm_chain_id !== i.evm_chain_id || manifeste.instance.bft_chain_id !== i.bft_chain_id || manifeste.instance.manifest_sha256 !== i.manifest_sha256) {
      ecart(4, MANIFESTE_PAQUET, "instance_differente");
    }
    const octetsInstance = fichiers.get(FICHIERS_RACINE.manifeste_instance);
    if (i.manifest_sha256 === null) {
      if (octetsInstance) ecart(4, FICHIERS_RACINE.manifeste_instance, "manifeste_instance_en_trop");
    } else if (!octetsInstance) ecart(4, FICHIERS_RACINE.manifeste_instance, "manifeste_instance_absent");
    else if (sha256Hex(octetsInstance) !== i.manifest_sha256) ecart(4, FICHIERS_RACINE.manifeste_instance, "manifeste_instance_different");
  } else if (!ecarts.some((e) => e.fichier === FICHIERS_RACINE.dossier)) {
    ecart(4, FICHIERS_RACINE.dossier, "dossier_absent");
  }
  if (path.basename(path.resolve(repertoire)) !== nomPaquet(manifeste.org)) ecart(4, null, "nom_repertoire");

  // Point 5 : jeu d'approbateurs et gabarit.
  if (dossier) {
    const jeu = docs.jeu_approbateurs?.valeur;
    if (!jeu || !dossier.result || !egaliteJson(jeu, dossier.result.approver_set)) ecart(5, FICHIERS_RACINE.jeu_approbateurs, "jeu_different");
  }
  const gabarit = docs.gabarit_service?.valeur;
  if (!gabarit || gabarit.org !== manifeste.org || gabarit.org_id !== manifeste.org_id) ecart(5, FICHIERS_RACINE.gabarit_service, "gabarit_different");

  // Point 6 : captures nommées par les étapes et leurs index, SHA-256 de l'index (CP-6) ; rien d'autre dans captures/.
  if (dossier) {
    const nommes = new Set();
    for (const etape of dossier.steps) {
      if (etape.capture === null) continue;
      const chemin = `captures/${etape.capture}`;
      nommes.add(chemin);
      const octetsIndex = fichiers.get(chemin);
      if (!octetsIndex) {
        ecart(6, chemin, "index_absent");
        continue;
      }
      const l = lireJson(octetsIndex);
      const index = l.erreur ? null : l.valeur;
      if (!index || !valider(IDS.operations, index, schemas).valide) {
        ecart(6, chemin, "index_illisible");
        continue;
      }
      for (const f of [index.files.block, ...index.files.receipts, index.files.certificate]) {
        const c = `captures/${f.name}`;
        nommes.add(c);
        const o = fichiers.get(c);
        if (!o) ecart(6, c, "fichier_capture_absent");
        else if (sha256Hex(o) !== f.sha256) ecart(6, c, "sha256_capture_different");
      }
    }
    for (const chemin of fichiers.keys()) {
      if (chemin.startsWith("captures/") && !nommes.has(chemin)) ecart(6, chemin, "capture_non_nommee");
    }
  }
  // Les écarts se rendent dans l'ordre des points (EX-7.22 : « dans cet ordre »).
  ecarts.sort((a, b) => a.point - b.point);
  return { valide: ecarts.length === 0, ecarts, manifeste };
}

/** Message d'un écart (EX-7.30 : commence par « EX-7.22, point <n> : », jamais une valeur secrète). */
const MESSAGES = {
  repertoire_illisible: "répertoire du paquet illisible",
  absent: "paquet-client.json absent",
  illisible: "paquet-client.json illisible (JSON strict)",
  schema: "paquet-client.json non conforme à paquet-client-v0",
  fichier_non_ordinaire: "fichier qui n'est pas un fichier ordinaire, ou répertoire en plus",
  entree_double: "entrée en double dans files",
  fichier_absent: "fichier de files absent du répertoire",
  sha256_different: "SHA-256 différent de celui de files",
  longueur_differente: "longueur différente de celle de files",
  fichier_non_liste: "fichier du répertoire absent de files",
  fichier_obligatoire_absent: "files ne compte pas le dossier, le jeu d'approbateurs et le gabarit",
  ordre_files: "files ne suit pas l'ordre d'EX-7.19 ou un rôle ne correspond pas au chemin",
  forme: "fichier hors de la forme de son rôle (table d'EX-7.18)",
  ecriture: "document qui n'est pas écrit selon EX-7.18 (JSON.stringify(objet, null, 2) et un saut de ligne)",
  dossier_non_fini: "dossier non fini (une étape n'est ni capturee ni faite, ou result nul)",
  org_different: "org n'est pas le slug du dossier",
  org_id_different: "org_id n'est pas keccak256(org) ou celui du dossier",
  instance_differente: "instance différente de celle du dossier",
  manifeste_instance_en_trop: "instance-registre.json présent alors que manifest_sha256 est nul",
  manifeste_instance_absent: "instance-registre.json absent alors que manifest_sha256 n'est pas nul",
  manifeste_instance_different: "SHA-256 d'instance-registre.json différent de manifest_sha256",
  dossier_absent: "dossier absent",
  nom_repertoire: "le répertoire n'est pas nommé paquet-client-<org>",
  jeu_different: "jeu-approbateurs.json différent de result.approver_set du dossier",
  gabarit_different: "org ou org_id du gabarit différents de ceux du manifeste",
  index_absent: "index de capture d'une étape absent",
  index_illisible: "index de capture illisible ou hors de son schéma",
  fichier_capture_absent: "fichier nommé par un index absent",
  sha256_capture_different: "SHA-256 d'un fichier différent de celui que l'index lui donne (CP-6)",
  capture_non_nommee: "fichier de captures/ nommé par aucun index, ou index nommé par aucune étape",
};

/**
 * Sortie `paquet-client` du contrôle de réception (EX-7.30, opération
 * `controler`) : réussite `{ directory, org, org_id, files, manifest_sha256,
 * secrets_checked }`, ou refus `refuse` (code 1) au premier écart, `error.code`
 * du point, `error.check` nul, `outputs` `{ requirement, point, file }`.
 * `rechercheSecrets(repertoire)`, facultative, fait la recherche d'EX-7.21
 * après les six points : elle rend `{ references: [{ option, reference }],
 * trouve: { fichier, nom } | null }`. `secrets_checked` nomme les options
 * cherchées et leur nombre (EX-7.21, EX-7.30) : `{ count, references }`,
 * chaque `{ option, reference }` (nom de l'option de l'outil de référence et
 * référence d'EX-7.3, jamais la valeur), triées par option puis par
 * référence (ordre des unités de code).
 */
export function resumeSecretsCherches(references = []) {
  const triees = references.map((r) => ({ option: r.option, reference: r.reference })).sort((a, b) => (a.option < b.option ? -1 : a.option > b.option ? 1 : a.reference < b.reference ? -1 : a.reference > b.reference ? 1 : 0));
  return { count: triees.length, references: triees };
}

export function sortieControle(repertoire, { schemas = registreSchemas(), rechercheSecrets = null } = {}) {
  const c = controler(repertoire, schemas);
  const base = { version: 0, command: "paquet-client", checks: [] };
  if (!c.valide) {
    const e = c.ecarts[0];
    return {
      ...base, result: "refuse", exit_code: 1,
      error: { code: e.erreur, check: null, message: `EX-7.22, point ${e.point} : ${e.fichier ? `${e.fichier} : ` : ""}${MESSAGES[e.code] ?? e.code}` },
      outputs: { requirement: "EX-7.22", point: e.point, file: e.fichier },
    };
  }
  let secretsCherches = resumeSecretsCherches([]);
  if (rechercheSecrets) {
    const r = rechercheSecrets(repertoire);
    secretsCherches = resumeSecretsCherches(r.references);
    if (r.trouve) {
      return {
        ...base, result: "refuse", exit_code: 1,
        error: { code: "secret_present", check: null, message: `EX-7.21 : ${r.trouve.fichier} contient la valeur du secret désigné par ${r.trouve.nom} ; remise interdite` },
        outputs: { requirement: "EX-7.21", point: null, file: r.trouve.fichier },
      };
    }
  }
  const octets = fs.readFileSync(path.join(repertoire, MANIFESTE_PAQUET));
  return {
    ...base, result: "reussi", exit_code: 0, error: null,
    outputs: { directory: path.resolve(repertoire), org: c.manifeste.org, org_id: c.manifeste.org_id, files: c.manifeste.files.length, manifest_sha256: sha256Hex(octets), secrets_checked: secretsCherches },
  };
}
