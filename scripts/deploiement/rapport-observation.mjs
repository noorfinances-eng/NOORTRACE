#!/usr/bin/env node
// Rapport d'observation (CT-8 EX-12.10, vérifications OB-1 à OB-4 d'EX-12.16).
//
//   node scripts/deploiement/rapport-observation.mjs <événements> [--politiques <répertoire>] [--json]
//
// <événements> : fichier NDJSON d'événements, ou répertoire de journal de
// CT-2 EX-12.1 (les segments sont lus dans l'ordre des noms, en-têtes
// écartés). Écrit le rapport rapport-observation-v0 en JSON indenté de deux
// espaces : décompte par version, règle (marque d'observation retirée) et
// décision ; anomalies OB-1 et OB-2. Avec --politiques (répertoire des pièces
// des ensembles de politique, nommées par leur policy_sha256 sans 0x, suivi
// de .json), OB-3 et OB-4 s'exécutent aussi et leurs anomalies s'ajoutent.
// Ne lit ni pièce d'argument ni clé. Codes : 0 aucune anomalie ; 1 au moins
// une anomalie ; 2 usage ou entrée illisible.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { messageOptions, texteJSON } from "../lib/deploiement.mjs";
import { CLES_ENTETE, lireEvenementsNDJSON, lireRepertoire, rapportObservation, verifierObservation } from "../lib/exploitation.mjs";

const USAGE = "Usage : node scripts/deploiement/rapport-observation.mjs <fichier NDJSON | répertoire du journal> [--politiques <répertoire>] [--json]";

/** Événements d'un fichier NDJSON ou d'un répertoire de journal (en-têtes de segment écartés). */
export function lireEvenements(chemin) {
  if (!fs.statSync(chemin).isDirectory()) return lireEvenementsNDJSON(fs.readFileSync(chemin));
  const out = [];
  for (const [p, octets] of lireRepertoire(chemin)) {
    if (!p.startsWith("segments/")) continue;
    for (const v of lireEvenementsNDJSON(octets)) {
      const entete = v !== null && typeof v === "object" && !Array.isArray(v) && Object.keys(v).sort().join(",") === [...CLES_ENTETE].join(",");
      if (!entete) out.push(v);
    }
  }
  return out;
}

/** Pièces des ensembles de politique d'un répertoire : Map policy_sha256 -> octets. */
export function lirePolitiques(rep) {
  const m = new Map();
  for (const n of fs.readdirSync(rep).sort()) {
    const r = /^([0-9a-f]{64})\.json$/.exec(n);
    if (r) m.set(`0x${r[1]}`, fs.readFileSync(path.join(rep, n)));
  }
  return m;
}

/** Rapport, avec les anomalies OB-3 et OB-4 quand les pièces sont fournies. */
export function rapport(evenements, politiques = null) {
  const r = rapportObservation(evenements);
  if (politiques) r.anomalies = verifierObservation(evenements, { politiques }).anomalies;
  return r;
}

export function resume(r) {
  const l = [`événements : ${r.events} (seq ${r.first_seq} à ${r.last_seq}) ; appels d'outil : ${r.tool_calls} ; marqués : ${r.observed}`];
  l.push(`autorise ${r.totals.autorise} ; a_approuver ${r.totals.a_approuver} ; refuse ${r.totals.refuse} ; inconnu ${r.totals.inconnu}`);
  for (const x of r.rows) l.push(`${x.policy_version} | ${x.rule} | ${x.would} | ${x.count}${x.seqs.length ? ` | seq ${x.seqs.join(", ")}` : ""}`);
  for (const a of r.anomalies) l.push(`anomalie ${a.check} seq ${a.seq} : ${a.detail}`);
  return l.join("\n") + "\n";
}

export function principal(argv, { sortie = process.stdout, erreur = process.stderr } = {}) {
  let o;
  let entree;
  try {
    const a = parseArgs({ args: argv, strict: true, allowPositionals: true, options: { politiques: { type: "string" }, json: { type: "boolean" } } });
    o = a.values;
    if (a.positionals.length !== 1) throw new Error("un fichier NDJSON ou un répertoire de journal attendu");
    entree = a.positionals[0];
  } catch (err) {
    erreur.write(`Erreur : ${messageOptions(err)}\n${USAGE}\n`);
    return 2;
  }
  let r;
  try {
    const evenements = lireEvenements(entree);
    const politiques = o.politiques === undefined ? null : lirePolitiques(o.politiques);
    r = rapport(evenements, politiques);
  } catch (err) {
    erreur.write(`Erreur : ${err.message}\n`);
    return 2;
  }
  sortie.write(texteJSON(r));
  if (!o.json) sortie.write("\n" + resume(r));
  return r.anomalies.length === 0 ? 0 : 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = principal(process.argv.slice(2));
