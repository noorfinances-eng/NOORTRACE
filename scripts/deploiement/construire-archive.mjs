#!/usr/bin/env node
// Contenu de l'archive de déploiement (CT-8 EX-3.6).
//
//   node scripts/deploiement/construire-archive.mjs --sortie <répertoire à créer>
//
// Écrit sous le répertoire (qui ne doit pas exister) les fichiers de
// fichiersArchive (scripts/lib/deploiement.mjs) : deploiement/, les outils de
// scripts/deploiement/ qui s'exécutent sur l'hôte, leurs bibliothèques, les
// schémas, et une copie figée d'ethers et de js-yaml ; puis SHA256SUMS (une
// ligne « <sha256>  <chemin> » par fichier, triée). L'archive publiée est ce
// répertoire mis en tar ; son SHA-256 est publié dans la note de version
// (EX-3.14). Codes : 0 écrit ; 2 usage ou sortie existante.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { fichiersArchive, messageOptions } from "../lib/deploiement.mjs";

const USAGE = "Usage : node scripts/deploiement/construire-archive.mjs --sortie <répertoire à créer>";

export function principal(argv) {
  let o;
  try {
    o = parseArgs({ args: argv, strict: true, allowPositionals: false, options: { sortie: { type: "string" } } }).values;
    if (o.sortie === undefined) throw new Error("option --sortie requise");
  } catch (err) {
    process.stderr.write(`Erreur : ${messageOptions(err)}\n${USAGE}\n`);
    return 2;
  }
  if (fs.existsSync(o.sortie)) {
    process.stderr.write(`Erreur : ${o.sortie} existe déjà\n`);
    return 2;
  }
  const f = fichiersArchive();
  const lignes = [];
  for (const [rel, octets] of f) {
    const p = path.join(o.sortie, ...rel.split("/"));
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, octets, { flag: "wx" });
    lignes.push(`${crypto.createHash("sha256").update(octets).digest("hex")}  ${rel}`);
  }
  fs.writeFileSync(path.join(o.sortie, "SHA256SUMS"), lignes.join("\n") + "\n", { flag: "wx" });
  process.stdout.write(`${f.size} fichiers écrits sous ${o.sortie}, et SHA256SUMS\n`);
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = principal(process.argv.slice(2));
