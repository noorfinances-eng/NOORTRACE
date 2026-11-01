#!/usr/bin/env node
// Calculateur de dimensionnement (CT-8 §9, EX-9.4).
//
//   node scripts/deploiement/dimensionner.mjs --entrees <fichier.json> [--json]
//
// Valide les entrées contre spec/schemas/dimensionnement-v0.schema.json (un
// fichier de cas des vecteurs, $defs/cas, est admis : ses entrées sont reprises),
// applique les refus d'EX-9.3, puis les lignes DM-1 à DM-22, et écrit la
// sortie (`$defs/sorties`) en JSON indenté de deux espaces ; sans --json, un
// résumé lisible en Gio suit. Codes : 0 calcul fait ; 1 entrées refusées par
// EX-9.3 (sortie `valid: false` et `errors`) ; 2 usage ou entrées invalides
// contre le schéma. Déterministe : mêmes entrées, mêmes octets de sortie.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { chargerSchema, dimensionner, gio, messageOptions, texteJSON, validerSchemaDeploiement } from "../lib/deploiement.mjs";

/** Résumé lisible d'une sortie de dimensionnement. */
export function resume(s) {
  if (!s.valid) return s.errors.map((e) => `refus : journal ${e.journal} : ${e.code}`).join("\n") + "\n";
  const t = s.totals;
  const lignes = [
    `journaux : ${t.journals}`,
    `espace local : ${gio(t.local_bytes)} Gio (${t.local_bytes} octets)`,
    `espace WORM : ${gio(t.worm_bytes)} Gio (${t.worm_bytes} octets)`,
    `archive du journal d'exploitation : ${gio(t.ops_archive_bytes)} Gio`,
    `jetons qualifiés par an : ${t.tokens_qualified_per_year} ; autres : ${t.tokens_other_per_year}`,
    `ancres du registre par an, au plus : ${t.registry_anchors_per_year_max} ; clôtures : ${t.registry_closures_per_year}`,
    `transactions du registre par heure, au plus : ${t.registry_tx_per_hour_max} sur ${t.registry_capacity_tx_per_hour} (part ${t.registry_capacity_share})`,
    `octets écrits par seconde en pointe : ${t.peak_write_bytes_per_s} ; vidages par seconde, au plus : ${t.peak_fsync_per_s_max}`,
  ];
  for (const j of s.journals) {
    lignes.push(`type ${j.id} (${j.count}) : pointe ${j.peak_events_per_s} événements/s${j.peak_over_target ? " (au-delà de la cible)" : ""} ; mémoire de tampons ${gio(j.memory_buffers_max_bytes)} Gio${j.memory_base_bytes === null ? " plus la mémoire à vide, à mesurer (CT-9)" : ""}`);
  }
  return lignes.join("\n") + "\n";
}

function principal(argv) {
  let o;
  try {
    o = parseArgs({ args: argv, strict: true, allowPositionals: false, options: { entrees: { type: "string" }, json: { type: "boolean" } } }).values;
    if (o.entrees === undefined) throw new Error("option --entrees requise");
  } catch (err) {
    process.stderr.write(`Erreur : ${messageOptions(err)}\nUsage : node scripts/deploiement/dimensionner.mjs --entrees <fichier.json> [--json]\n`);
    return 2;
  }
  let entrees;
  try {
    entrees = JSON.parse(fs.readFileSync(o.entrees, "utf8"));
    const schema = chargerSchema("dimensionnement");
    // Un fichier de cas des vecteurs ($defs/cas) est admis : ses entrées sont reprises.
    if (validerSchemaDeploiement(entrees, schema, { fragment: "#/$defs/cas" }).length === 0) entrees = entrees.entrees;
    const erreurs = validerSchemaDeploiement(entrees, schema);
    if (erreurs.length) throw new Error(`${o.entrees} : non conforme à dimensionnement-v0 : ${erreurs.slice(0, 4).map((e) => `${e.chemin} : ${e.message}`).join(" ; ")}`);
  } catch (err) {
    process.stderr.write(`Erreur : ${err.message}\n`);
    return 2;
  }
  const s = dimensionner(entrees);
  process.stdout.write(texteJSON(s));
  if (!o.json) process.stdout.write("\n" + resume(s));
  return s.valid ? 0 : 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = principal(process.argv.slice(2));
