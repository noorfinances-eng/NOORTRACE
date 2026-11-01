#!/usr/bin/env node
// Vérifications statiques CO-1 à CO-14 des fichiers Compose de référence
// (CT-8 §4.4, EX-4.2), sans construire ni lancer aucun conteneur.
//
//   node scripts/deploiement/verifier-conteneurs.mjs <fichier.yaml>… --images <images.json> [--json]
//   npm run deploiement:conteneurs
//
// La description des images est validée contre conteneurs-v0 ; chaque
// fichier donne un rapport conteneurs-v0 `$defs/rapport` (avec --json : le
// rapport, ou la liste des rapports pour plusieurs fichiers). Codes : 0 tous
// conformes ; 1 au moins un fichier non conforme ; 2 usage, fichier
// illisible ou description invalide.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { chargerSchema, messageOptions, validerSchemaDeploiement, verifierConteneurs } from "../lib/deploiement.mjs";

function principal(argv) {
  let o;
  let fichiers;
  try {
    const p = parseArgs({ args: argv, strict: true, allowPositionals: true, options: { images: { type: "string" }, json: { type: "boolean" } } });
    o = p.values;
    fichiers = p.positionals;
    if (o.images === undefined) throw new Error("option --images requise");
    if (!fichiers.length) throw new Error("au moins un fichier Compose est requis");
  } catch (err) {
    process.stderr.write(`Erreur : ${messageOptions(err)}\nUsage : node scripts/deploiement/verifier-conteneurs.mjs <fichier.yaml>… --images <images.json> [--json]\n`);
    return 2;
  }
  let description;
  const textes = [];
  try {
    description = JSON.parse(fs.readFileSync(o.images, "utf8"));
    const erreurs = validerSchemaDeploiement(description, chargerSchema("conteneurs"));
    if (erreurs.length) throw new Error(`${o.images} : non conforme à conteneurs-v0 : ${erreurs.slice(0, 4).map((e) => `${e.chemin} : ${e.message}`).join(" ; ")}`);
    for (const f of fichiers) textes.push(fs.readFileSync(f, "utf8"));
  } catch (err) {
    process.stderr.write(`Erreur : ${err.message}\n`);
    return 2;
  }
  const rapports = fichiers.map((f, i) => verifierConteneurs(textes[i], description, path.basename(f)));
  if (o.json) process.stdout.write(JSON.stringify(rapports.length === 1 ? rapports[0] : rapports, null, 2) + "\n");
  else {
    for (const r of rapports) {
      process.stdout.write(`${r.file} : ${r.verdict} (sha256 ${r.sha256})\n`);
      for (const c of r.checks.filter((x) => x.status === "echoue")) process.stdout.write(`  ${c.id} : ${c.findings.map((f) => `${f.service ?? "-"}/${f.code}`).join(", ")}\n`);
    }
  }
  return rapports.every((r) => r.verdict === "conforme") ? 0 : 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = principal(process.argv.slice(2));
