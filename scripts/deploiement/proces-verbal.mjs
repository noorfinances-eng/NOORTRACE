#!/usr/bin/env node
// Vérification d'un procès-verbal d'exploitation (CT-8 EX-11.18, PV-1 à PV-10).
//
//   node scripts/deploiement/proces-verbal.mjs verifier <fichier> [--racine <répertoire>] [--cles <fichier>] [--json]
//
// Sans --racine, PV-7 et PV-8 ne sont pas exécutées. Avec --racine, PV-8
// vérifie le journal de la racine avec le fichier de clés (--cles, à défaut
// <racine>/cles.json). Écrit le résultat { version, verdict, checks } en JSON
// indenté de deux espaces ; sans --json, un résumé lisible suit. Codes : 0
// valide ; 1 au moins une vérification échouée ; 2 usage.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { messageOptions, texteJSON } from "../lib/deploiement.mjs";
import { verifierProcesVerbal } from "../lib/exploitation.mjs";
import { analyserJSONStrict } from "../lib/journal.mjs";

const USAGE = "Usage : node scripts/deploiement/proces-verbal.mjs verifier <fichier> [--racine <répertoire>] [--cles <fichier>] [--json]";

export function resume(r) {
  return [`verdict : ${r.verdict}`, ...r.checks.map((c) => `${c.id} ${c.status}${c.detail ? ` : ${c.detail}` : ""}`)].join("\n") + "\n";
}

export function principal(argv, { sortie = process.stdout, erreur = process.stderr } = {}) {
  let o;
  let fichier;
  try {
    const a = parseArgs({ args: argv, strict: true, allowPositionals: true, options: { racine: { type: "string" }, cles: { type: "string" }, json: { type: "boolean" } } });
    o = a.values;
    if (a.positionals[0] !== "verifier" || a.positionals.length !== 2) throw new Error("sous-commande verifier et un fichier attendus");
    fichier = a.positionals[1];
    if (o.cles !== undefined && o.racine === undefined) throw new Error("--cles n'a d'effet qu'avec --racine");
  } catch (err) {
    erreur.write(`Erreur : ${messageOptions(err)}\n${USAGE}\n`);
    return 2;
  }
  let texte;
  let cles = null;
  try {
    texte = fs.readFileSync(fichier);
    if (o.racine !== undefined) {
      if (!fs.statSync(o.racine).isDirectory()) throw new Error(`${o.racine} : répertoire attendu`);
      const f = o.cles ?? path.join(o.racine, "cles.json");
      cles = analyserJSONStrict(fs.readFileSync(f));
    }
  } catch (err) {
    erreur.write(`Erreur : ${err.message}\n`);
    return 2;
  }
  const r = verifierProcesVerbal(texte, { racine: o.racine ?? null, cles });
  sortie.write(texteJSON(r));
  if (!o.json) sortie.write("\n" + resume(r));
  return r.verdict === "valide" ? 0 : 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = principal(process.argv.slice(2));
