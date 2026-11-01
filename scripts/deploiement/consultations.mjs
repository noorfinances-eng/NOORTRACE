#!/usr/bin/env node
// Vérification d'un fichier du journal des consultations et des accès
// (CT-8 EX-11.20, CA-1 à CA-6).
//
//   node scripts/deploiement/consultations.mjs verifier <fichier> [--sources <répertoire>] [--json]
//
// Le nom de base du fichier entre dans CA-3 (prev_sha256 de la ligne 1).
// Avec --sources, CA-5 compare source.record_sha256 au SHA-256 du fichier
// <répertoire>/<source.locator> ; sans, CA-5 n'est pas exécutée. Écrit le
// résultat { version, file, lines, verdict, checks } en JSON indenté de deux
// espaces ; sans --json, un résumé lisible suit. Codes : 0 valide ; 1 au
// moins une vérification échouée ; 2 usage.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { messageOptions, texteJSON } from "../lib/deploiement.mjs";
import { verifierConsultations } from "../lib/exploitation.mjs";

const USAGE = "Usage : node scripts/deploiement/consultations.mjs verifier <fichier> [--sources <répertoire>] [--json]";

/** Enregistrements bruts d'un répertoire de sources : Map locator -> octets (fichiers réguliers, chemins relatifs avec /). */
export function lireSources(rep) {
  const m = new Map();
  const parcourir = (d, rel) => {
    for (const n of fs.readdirSync(d).sort()) {
      const p = path.join(d, n);
      const r = rel ? `${rel}/${n}` : n;
      const st = fs.lstatSync(p);
      if (st.isDirectory()) parcourir(p, r);
      else if (st.isFile()) m.set(r, fs.readFileSync(p));
    }
  };
  parcourir(rep, "");
  return m;
}

export function resume(r) {
  return [`${r.file} : ${r.lines} ligne(s) ; verdict : ${r.verdict}`, ...r.checks.map((c) => `${c.id} ${c.status}${c.line !== null ? ` (ligne ${c.line})` : ""}${c.detail ? ` : ${c.detail}` : ""}`)].join("\n") + "\n";
}

export function principal(argv, { sortie = process.stdout, erreur = process.stderr } = {}) {
  let o;
  let fichier;
  try {
    const a = parseArgs({ args: argv, strict: true, allowPositionals: true, options: { sources: { type: "string" }, json: { type: "boolean" } } });
    o = a.values;
    if (a.positionals[0] !== "verifier" || a.positionals.length !== 2) throw new Error("sous-commande verifier et un fichier attendus");
    fichier = a.positionals[1];
  } catch (err) {
    erreur.write(`Erreur : ${messageOptions(err)}\n${USAGE}\n`);
    return 2;
  }
  let octets;
  let sources = null;
  try {
    octets = fs.readFileSync(fichier);
    if (o.sources !== undefined) sources = lireSources(o.sources);
  } catch (err) {
    erreur.write(`Erreur : ${err.message}\n`);
    return 2;
  }
  const r = verifierConsultations(path.basename(fichier), octets, { sources });
  sortie.write(texteJSON(r));
  if (!o.json) sortie.write("\n" + resume(r));
  return r.verdict === "valide" ? 0 : 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = principal(process.argv.slice(2));
