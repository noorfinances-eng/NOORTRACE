#!/usr/bin/env node
// Vérification d'un répertoire de journal (CT-8 EX-11.7).
//
//   node scripts/deploiement/verifier-journal.mjs <répertoire du journal> --cles <fichier> [--json]
//
// Lit journal.json, segments/ et manifestes/ (disposition de CT-2 EX-12.1),
// sans réseau ; vérifie l'en-tête de chaque segment (CT-2 EX-12.3), la suite
// des first_seq et des époques, le chaînage d'un segment à l'autre, chaque
// ligne par E-1 à E-8 et la suite par C-1 à C-3 de CT-1, chaque manifeste
// présent recalculé et sa signature. Écrit le rapport verification-journal-v0
// en JSON indenté de deux espaces ; sans --json, un résumé lisible suit.
// Codes : 0 valide ; 1 invalide ; 2 usage (répertoire ou fichier de clés
// illisible).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { messageOptions, texteJSON } from "../lib/deploiement.mjs";
import { lireRepertoire, verifierJournal } from "../lib/exploitation.mjs";
import { analyserJSONStrict } from "../lib/journal.mjs";

const USAGE = "Usage : node scripts/deploiement/verifier-journal.mjs <répertoire du journal> --cles <fichier> [--json]";

/** Résumé lisible d'un rapport verification-journal-v0. */
export function resume(r) {
  const l = [`verdict : ${r.verdict}`, `segments : ${r.segments.length} ; seq ${r.first_seq ?? "-"} à ${r.last_seq ?? "-"}`];
  for (const e of r.errors) l.push(`${e.check}${e.segment ? ` (${e.segment}${e.seq !== null ? `, seq ${e.seq}` : ""})` : ""} : ${e.detail}`);
  return l.join("\n") + "\n";
}

export function principal(argv, { sortie = process.stdout, erreur = process.stderr } = {}) {
  let o;
  let rep;
  try {
    const a = parseArgs({ args: argv, strict: true, allowPositionals: true, options: { cles: { type: "string" }, json: { type: "boolean" } } });
    o = a.values;
    if (a.positionals.length !== 1) throw new Error("un répertoire de journal attendu");
    if (o.cles === undefined) throw new Error("option --cles requise");
    rep = a.positionals[0];
  } catch (err) {
    erreur.write(`Erreur : ${messageOptions(err)}\n${USAGE}\n`);
    return 2;
  }
  let fichiers;
  let cles;
  try {
    if (!fs.statSync(rep).isDirectory()) throw new Error(`${rep} : répertoire attendu`);
    fichiers = lireRepertoire(rep);
    cles = analyserJSONStrict(fs.readFileSync(o.cles));
  } catch (err) {
    erreur.write(`Erreur : ${err.message}\n`);
    return 2;
  }
  let r;
  try {
    r = verifierJournal(fichiers, cles);
  } catch (err) {
    erreur.write(`Erreur : ${o.cles} : ${err.message}\n`);
    return 2;
  }
  sortie.write(texteJSON(r));
  if (!o.json) sortie.write("\n" + resume(r));
  return r.verdict === "valide" ? 0 : 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = principal(process.argv.slice(2));
