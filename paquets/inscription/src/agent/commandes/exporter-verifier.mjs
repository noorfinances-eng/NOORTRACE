// Pas 10 (CT-4 §7.9, §9.6) : `exporter` écrit les trois parties de CT-6
// §11.2 de la période d'un manifeste depuis les seules captures du client
// (`choisirCaptures`, `exporterPartiesRegistre`), dans `parties/<n>/` ;
// `verifier` exécute le contrôle 8 de CT-6 sur des parties, avec le manifeste
// de la période et, pour R-10 et N-4, les clés du dossier ; sans fichier
// d'ancres, l'ancre `registry` se dérive du manifeste d'instance (RG-20) ou
// des valeurs d'EX-7.2 (`anchor_source` : `publication_exploitant`).

import fs from "node:fs";
import path from "node:path";
import { lireJsonStrict } from "@noortrace/approbation";
import { hacherManifeste, empreinteAncre } from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import { Sortie } from "../sortie.mjs";
import { creerRepertoire } from "../donnees.mjs";
import { controle8 } from "../controle8.mjs";
import { dossierClient } from "./base.mjs";

/** Lit un document JSON sous le répertoire du client (chemin relatif déjà contrôlé par la forme du travail). */
function lireSousClient(ctx, sortie, relatif, quoi) {
  const chemin = path.join(ctx.client.dir, relatif);
  if (!chemin.startsWith(ctx.client.dir + path.sep)) sortie.arreter("inutilisable", "usage", null, `${quoi} : chemin hors du répertoire du client`);
  try {
    return { chemin, valeur: lireJsonStrict(fs.readFileSync(chemin)) };
  } catch {
    sortie.arreter("inutilisable", "entree_illisible", null, `${quoi} illisible : ${relatif}`);
  }
  return null;
}

/** Dates (AAAA-MM-JJ) des captures, pour la `source` de `registre.json`. */
function dates(index) {
  const d = [...new Set(index.map((i) => i.captured_at.slice(0, 10)))].sort();
  return d.length === 1 ? `captures du ${d[0]}` : `captures du ${d[0]} au ${d[d.length - 1]}`;
}

export async function exporter(ctx, travail) {
  const sortie = new Sortie("exporter", ctx);
  const p = travail.parametres;
  const d = dossierClient(ctx, sortie);
  const manifeste = lireSousClient(ctx, sortie, p.manifeste, "manifeste").valeur;
  const cles = p.cles ? lireSousClient(ctx, sortie, p.cles, "cles.json").valeur : null;
  const periodHash = hacherManifeste(manifeste);
  const fingerprint = empreinteAncre(manifeste.org_id, manifeste.journal_id, periodHash);
  const indexes = R.listerCaptures(ctx.captures).map((c) => c.index);
  // Clé du manifeste sous la clé de chaîne émettrice de l'ancre, puis chaque autre clé qui signe (CT-4 EX-9.8).
  const sourceCles = cles?.keys ?? d.recorders.map((r) => ({ key_id: r.key_id, public_key: r.public_key }));
  const cleManifeste = sourceCles.find((k) => k.key_id === manifeste.recorder_key_id);
  let choisies;
  try {
    const ancre = indexes.find((i) => i.role === "ancre");
    void ancre;
    const premieres = R.choisirCaptures({ repertoire: ctx.captures, indexes, periodHash, fingerprint, inscriptions: [] });
    const indexAncre = premieres.find((c) => c.role === "ancre").index;
    const recuAncre = R.lireFichierRpc(R.lecteurRepertoire(ctx.captures).lire(indexAncre.files.receipts[indexAncre.transaction_index].name));
    const journal = recuAncre?.resultat?.logs?.[indexAncre.log_index];
    const emetteur = journal ? R.decoderJournal("ancre", { address: journal.address.toLowerCase(), topics: journal.topics, data: journal.data })?.issuer : null;
    const inscriptions = [];
    if (cleManifeste) inscriptions.push({ clePublique: cleManifeste.public_key, chainKey: emetteur ?? undefined });
    for (const k of sourceCles) if (k !== cleManifeste) inscriptions.push({ clePublique: k.public_key });
    choisies = R.choisirCaptures({ repertoire: ctx.captures, indexes, periodHash, fingerprint, inscriptions });
  } catch (e) {
    sortie.arreter("refuse", "capture_incomplete", null, String(e.message).replace(/^capture_incomplete : /, "").slice(0, 1024));
  }
  const noeud = choisies.find((c) => c.role === "cloture").index.node.rpc;
  const source = `instance ${ctx.instance.bftChainId}, validateur ${noeud}, ${dates(choisies.map((c) => c.index))} (CT-4 §9.6)`;
  let parties;
  try {
    parties = R.exporterPartiesRegistre({ repertoire: ctx.captures, captures: choisies, jeux: ctx.instance.jeux, source });
  } catch (e) {
    sortie.arreter("refuse", "capture_incomplete", null, String(e.message).slice(0, 1024));
  }
  creerRepertoire(ctx.client.parties);
  const existants = fs.readdirSync(ctx.client.parties).filter((n) => /^[1-9][0-9]*$/.test(n)).map(Number);
  const dir = path.join(ctx.client.parties, String((existants.length ? Math.max(...existants) : 0) + 1));
  creerRepertoire(dir);
  const fichiers = [];
  for (const [nom, octets] of [["registre.json", parties.octets.registre], ["certificat-commit.json", parties.octets.certificatCommit], ["validateurs.json", parties.octets.validateurs]]) {
    const chemin = path.join(dir, nom);
    fs.writeFileSync(chemin, octets, { flag: "wx", mode: 0o640 });
    fichiers.push(chemin);
  }
  return sortie.rendre("reussi", {
    outputs: {
      entries: parties.registre.entries.map((e) => ({ role: e.role, block_number: Number(BigInt(e.block.number)) })),
      certificates: parties.certificatCommit.certificates.map((c) => Number(BigInt(c.height))),
      files: fichiers,
    },
  });
}

export async function verifier(ctx, travail) {
  const sortie = new Sortie("verifier", ctx);
  const p = travail.parametres;
  const d = dossierClient(ctx, sortie);
  const parties = path.join(ctx.client.dir, p.parties);
  if (!parties.startsWith(ctx.client.dir + path.sep) || !fs.existsSync(parties)) sortie.arreter("inutilisable", "usage", null, `parties introuvables : ${p.parties}`);
  const manifeste = lireSousClient(ctx, sortie, p.manifeste, "manifeste").valeur;
  let registry;
  let recorders;
  let anchorSource;
  if (p.ancres) {
    const a = lireSousClient(ctx, sortie, p.ancres, "fichier d'ancres").valeur;
    registry = a.registry ?? null;
    recorders = a.recorders ?? [];
    anchorSource = "fichier_ancres";
  } else {
    // RG-20 : ancre dérivée du manifeste d'instance, ou des valeurs d'EX-7.2 ; ce n'est pas une ancre indépendante.
    const i = ctx.instance;
    registry = i.manifeste
      ? R.ancreReviseur(i.manifeste, { source: "manifeste d'instance publié par l'exploitant (RG-20)" })
      : {
        chain_id: i.bftChainId,
        contracts: { period_registry: i.contrats.period_registry, attestation_registry: i.contrats.attestation_registry, recorder_registry: i.contrats.recorder_registry },
        validator_sets: i.jeux.validator_sets.map((s) => ({ from_height: s.from_height, to_height: s.to_height, validators: s.validators, source: s.source })),
        source: "valeurs du réseau de développement (CT-4 EX-7.2)",
      };
    recorders = d.recorders.map((r) => ({ org_id: d.organisation.org_id, journal_id: r.journal_id, key_id: r.key_id, public_key: r.public_key, chain_key: r.chain_key, source: "dossier d'inscription" }));
    anchorSource = "publication_exploitant";
  }
  if (!registry) sortie.arreter("inutilisable", "instance_illisible", null, "ancre registry indérivable du manifeste (RG-20)");
  const cles = d.recorders.map((r) => ({ key_id: r.key_id, public_key: r.public_key }));
  const r = controle8({ parties, manifeste, registry, recorders, cles });
  const outputs = { anchor_source: anchorSource, status: r.status, summary: r.summary, verifications: r.verifications, n4: r.n4, warnings: r.warnings, statement: r.statement };
  return sortie.rendre(r.status === "reussi" ? "reussi" : "echoue", { outputs });
}
