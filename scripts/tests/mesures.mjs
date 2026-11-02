#!/usr/bin/env node
// Outil des mesures et des consignations de CT-9 (spec/CT-9-plan-de-tests.md,
// 11.3, 11.4, 12.1, annexe A.5, A.7, A.8 ; EX-11.11, EX-11.15, EX-12.4,
// EX-A.10) : valide les rapports de mesure et les consignations publiés sous
// spec/vecteurs/ct-9/ contre le schéma plan-de-tests-v0 et le catalogue, et,
// en phase 2, compare un rapport de campagne au rapport de référence.
//
//   node scripts/tests/mesures.mjs [--racine <dépôt>] [--json]
//        [--reference <rapport>] [--campagne <rapport>]
//   npm run mesures:ct9
//
// Sans option : lit mesures/rapport-*.json (#/$defs/rapport_mesure),
// mesures/cas/cas.json et ses cas (attendu valid ou invalid),
// consignations/*.json (#/$defs/consignation_rejeu), consignations/cas/cas.json
// et ses cas ; pour chaque ligne d'un rapport, test_id désigne une entrée TM-
// du catalogue dont l'unité est celle de la ligne, la cible celle de la ligne
// quand le rapport compte pour les cibles, et dont le result_name est porté
// par au moins une ligne ; pour chaque consignation, test_id désigne une
// entrée TR- dont la grille et les sections interdites sont celles de
// l'entrée. Avec --reference et --campagne (EX-11.15) : les deux rapports
// comptent pour les cibles sur le système de référence ; une ligne à cible de
// la campagne est une régression quand p50 ou p99 dépasse 1,2 fois la
// référence, quand la valeur d'un débit (evenements_par_s, blocs_par_s)
// descend sous 0,9 fois la référence, ou quand met passe de vrai à faux ;
// une ligne de la référence absente de la campagne est une lacune nommée
// (avertissement). Codes : 0 conforme ; 1 au moins un écart ou une
// régression ; 2 usage ou fichier illisible. L'outil n'écrit rien.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { RACINE, CATALOGUE, lireJSON } from "../lib/plan-de-tests.mjs";
import { validerSchema } from "../lib/journal.mjs";
import { messageOptions } from "../lib/deploiement.mjs";

const USAGE = "usage : node scripts/tests/mesures.mjs [--racine <dépôt>] [--json] [--reference <rapport>] [--campagne <rapport>]";
export const SCHEMA = "spec/schemas/plan-de-tests-v0.schema.json";
export const REPERTOIRE = "spec/vecteurs/ct-9";
/** Coefficients de régression d'EX-11.15, choix de conception de CT-9 à
 * confirmer à la première campagne. */
export const REGRESSION = Object.freeze({ latence: 1.2, debit: 0.9 });
const DEBITS = new Set(["evenements_par_s", "blocs_par_s"]);
const egal = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/**
 * Vérifie les familles publiées d'un dépôt. Rend { checks: [{ id, file,
 * status, detail }], errors: [string], warnings: [string] }.
 */
export function verifierFamilles(racine = RACINE) {
  const schema = lireJSON(path.join(racine, SCHEMA));
  const catalogue = lireJSON(path.join(racine, CATALOGUE));
  const parId = new Map(catalogue.tests.map((t) => [t.id, t]));
  const rep = path.join(racine, REPERTOIRE);
  const checks = [];
  const errors = [];
  const warnings = [];
  const note = (id, file, ok, detail) => { checks.push({ id, file, status: ok ? "reussi" : "echec", detail }); if (!ok) errors.push(`${id} ${file} : ${detail}`); };
  const valide = (valeur, def) => validerSchema(valeur, schema, { fragment: `#/$defs/${def}` });
  const resume = (e) => e.slice(0, 3).map((x) => `${x.chemin} : ${x.message}`).join(" ; ");

  // Rapports de mesure publiés (EX-11.11, EX-11.13).
  const repMesures = path.join(rep, "mesures");
  const rapports = fs.existsSync(repMesures) ? fs.readdirSync(repMesures).filter((f) => /^rapport-.*\.json$/.test(f)).sort() : [];
  if (!rapports.length) errors.push("aucun rapport de mesure publié sous mesures/");
  for (const f of rapports) {
    const file = `mesures/${f}`;
    const r = lireJSON(path.join(repMesures, f));
    const e = valide(r, "rapport_mesure");
    note("MES-1", file, e.length === 0, e.length ? resume(e) : "conforme à rapport_mesure");
    if (e.length) continue;
    const parTM = new Map();
    for (const l of r.results) {
      const t = parId.get(l.test_id);
      if (!t || t.level !== "TM") { note("MES-2", file, false, `ligne ${l.name} : ${l.test_id} n'est pas une entrée TM- du catalogue`); continue; }
      (parTM.get(t.id) ?? parTM.set(t.id, []).get(t.id)).push(l.name);
      if (l.unit !== t.measure.unit) note("MES-3", file, false, `ligne ${l.name} : unité ${l.unit}, ${t.measure.unit} dans ${t.id}`);
      if (r.counts_for_targets && !egal(l.target, t.measure.target)) note("MES-4", file, false, `ligne ${l.name} : cible ${JSON.stringify(l.target)}, ${JSON.stringify(t.measure.target)} dans ${t.id}`);
      if (!r.counts_for_targets && l.met !== null) note("MES-5", file, false, `ligne ${l.name} : met non null dans un rapport qui ne compte pas pour les cibles`);
    }
    const tousResultNames = new Set(catalogue.tests.filter((t) => t.level === "TM").map((t) => t.measure.result_name));
    for (const [id, noms] of parTM) {
      if (!noms.includes(parId.get(id).measure.result_name)) note("MES-6", file, false, `${id} : aucune ligne ne porte son result_name ${parId.get(id).measure.result_name} (lignes : ${noms.join(", ")})`);
      // EX-11.11 : une ligne supplémentaire rattachée à la même entrée porte un nom propre, distinct de tout result_name du catalogue.
      for (const n of noms) if (n !== parId.get(id).measure.result_name && tousResultNames.has(n)) note("MES-6", file, false, `${id} : la ligne supplémentaire ${n} porte le result_name d'une autre entrée TM-`);
    }
    if (!checks.some((c) => c.file === file && c.status === "echec")) note("MES-2", file, true, `${r.results.length} ligne(s) rattachée(s) à ${parTM.size} entrée(s) TM-`);
  }

  // MES-7 (EX-11.16) : une entrée TM- exécutable dont le result_name n'est dans aucun rapport publié a son résultat dans les tests cités ; lacune nommée, pas une erreur.
  const nomsPublies = new Set(rapports.flatMap((f) => lireJSON(path.join(repMesures, f)).results.map((l) => l.name)));
  for (const t of catalogue.tests) if (t.level === "TM" && t.status.state === "executable" && !nomsPublies.has(t.measure.result_name)) warnings.push(`MES-7 ${t.id} : result_name ${t.measure.result_name} absent de tout rapport publié ; résultat porté par les tests cités (EX-11.16)`);

  // Consignations publiées (EX-12.4), hors cas/.
  const repCons = path.join(rep, "consignations");
  const consignations = fs.existsSync(repCons) ? fs.readdirSync(repCons).filter((f) => f.endsWith(".json")).sort() : [];
  if (!consignations.length) errors.push("aucune consignation publiée sous consignations/");
  for (const f of consignations) {
    const file = `consignations/${f}`;
    const c = lireJSON(path.join(repCons, f));
    const e = valide(c, "consignation_rejeu");
    note("CSG-1", file, e.length === 0, e.length ? resume(e) : "conforme à consignation_rejeu");
    if (e.length) continue;
    const t = parId.get(c.test_id);
    if (!t || t.level !== "TR") { note("CSG-2", file, false, `${c.test_id} n'est pas une entrée TR- du catalogue`); continue; }
    note("CSG-3", file, c.grid === t.replay.grid, c.grid === t.replay.grid ? `grille ${c.grid ?? "null"} de ${t.id}` : `grille ${c.grid}, ${t.replay.grid} dans ${t.id}`);
    const manquantes = t.replay.forbidden_sections.filter((s) => !c.forbidden_sections.includes(s));
    note("CSG-4", file, manquantes.length === 0, manquantes.length ? `sections interdites de ${t.id} absentes : ${manquantes.join(" ; ")}` : `sections interdites de ${t.id} toutes consignées`);
    if (c.grid && !fs.existsSync(path.join(racine, c.grid))) note("CSG-5", file, false, `grille ${c.grid} introuvable`);
  }

  // Cas des deux familles (EX-A.14, EX-A.15).
  for (const [fam, def] of [["mesures", "rapport_mesure"], ["consignations", "consignation_rejeu"]]) {
    const casJson = path.join(rep, fam, "cas", "cas.json");
    if (!fs.existsSync(casJson)) { errors.push(`${fam}/cas/cas.json absent`); continue; }
    const cas = lireJSON(casJson);
    for (const c of cas.cases) {
      const file = `${fam}/cas/${c.file}`;
      const e = valide(lireJSON(path.join(rep, fam, "cas", c.file)), c.def ?? def);
      const verdict = e.length ? "invalid" : "valid";
      note("CAS-1", file, verdict === c.expected, verdict === c.expected ? `${verdict}, comme attendu` : `${verdict}, attendu ${c.expected}${e.length ? ` (${resume(e)})` : ""}`);
    }
  }
  return { checks, errors, warnings };
}

/**
 * Compare un rapport de campagne au rapport de référence (EX-11.15). Rend
 * { regressions: [string], gaps: [string], errors: [string] }.
 */
export function comparerCampagne(reference, campagne) {
  const errors = [];
  for (const [nom, r] of [["référence", reference], ["campagne", campagne]]) {
    if (!r.counts_for_targets) errors.push(`${nom} : counts_for_targets faux ; aucune comparaison`);
    if (!r.system?.reference) errors.push(`${nom} : hors du système de référence ; aucune comparaison`);
  }
  if (errors.length) return { regressions: [], gaps: [], errors };
  const regressions = [];
  const gaps = [];
  const parNom = new Map(campagne.results.map((l) => [l.name, l]));
  for (const ref of reference.results) {
    if (ref.target === null) continue;
    const c = parNom.get(ref.name);
    if (!c) { gaps.push(`${ref.name} (${ref.test_id}) : ligne de la référence absente de la campagne`); continue; }
    for (const p of ["p50", "p99"]) if (typeof ref[p] === "number" && typeof c[p] === "number" && c[p] > REGRESSION.latence * ref[p]) regressions.push(`${ref.name} : ${p} ${c[p]} > ${REGRESSION.latence} × ${ref[p]}`);
    if (DEBITS.has(ref.unit) && typeof ref.value === "number" && typeof c.value === "number" && c.value < REGRESSION.debit * ref.value) regressions.push(`${ref.name} : value ${c.value} < ${REGRESSION.debit} × ${ref.value}`);
    if (ref.met === true && c.met === false) regressions.push(`${ref.name} : met vrai dans la référence, faux dans la campagne`);
  }
  return { regressions, gaps, errors };
}

export function executer(argv) {
  let args;
  try {
    args = parseArgs({ args: argv, allowPositionals: false, options: { racine: { type: "string" }, json: { type: "boolean", default: false }, reference: { type: "string" }, campagne: { type: "string" }, help: { type: "boolean", short: "h", default: false } } }).values;
  } catch (err) {
    return { code: 2, erreur: `${messageOptions(err)}\n${USAGE}` };
  }
  if (args.help) return { code: 0, texte: USAGE };
  if ((args.reference === undefined) !== (args.campagne === undefined)) return { code: 2, erreur: `--reference et --campagne vont ensemble\n${USAGE}` };
  const racine = path.resolve(args.racine ?? RACINE);
  const abs = (p) => path.isAbsolute(p) ? p : path.join(racine, p);
  for (const p of [racine, abs(SCHEMA), abs(CATALOGUE), ...(args.reference ? [abs(args.reference), abs(args.campagne)] : [])]) {
    if (!fs.existsSync(p)) return { code: 2, erreur: `fichier illisible : ${p}\n${USAGE}` };
  }
  let resultat;
  try {
    resultat = verifierFamilles(racine);
    if (args.reference) {
      const schema = lireJSON(abs(SCHEMA));
      const lus = [abs(args.reference), abs(args.campagne)].map((p) => lireJSON(p));
      lus.forEach((r, i) => { const e = validerSchema(r, schema, { fragment: "#/$defs/rapport_mesure" }); if (e.length) resultat.errors.push(`${[args.reference, args.campagne][i]} : non conforme à rapport_mesure (${e[0].chemin} : ${e[0].message})`); });
      const cmp = comparerCampagne(lus[0], lus[1]);
      resultat.comparison = { reference: args.reference, campaign: args.campagne, regressions: cmp.regressions, gaps: cmp.gaps };
      resultat.errors.push(...cmp.errors, ...cmp.regressions.map((r) => `régression : ${r}`));
      resultat.warnings.push(...cmp.gaps);
    }
  } catch (err) {
    return { code: 2, erreur: `lecture impossible : ${err.message}` };
  }
  const rapport = { version: 0, kind: "verification-mesures", verdict: resultat.errors.length ? "echec" : "reussi", checks: resultat.checks, errors: resultat.errors, warnings: resultat.warnings, ...(resultat.comparison ? { comparison: resultat.comparison } : {}) };
  const l = [`Mesures et consignations CT-9 : verdict ${rapport.verdict}`];
  for (const c of rapport.checks) l.push(`  [${c.status === "reussi" ? "OK" : "ÉCHEC"}] ${c.id} ${c.file} : ${c.detail}`);
  if (rapport.comparison) l.push(`  comparaison ${rapport.comparison.campaign} à ${rapport.comparison.reference} : ${rapport.comparison.regressions.length} régression(s), ${rapport.comparison.gaps.length} lacune(s)`);
  for (const w of rapport.warnings) l.push(`  [AVERTISSEMENT] ${w}`);
  for (const e of rapport.errors) l.push(`  [ÉCHEC] ${e}`);
  return { code: rapport.errors.length ? 1 : 0, texte: args.json ? JSON.stringify(rapport, null, 2) : l.join("\n"), rapport };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) {
  const r = executer(process.argv.slice(2));
  if (r.erreur) console.error(r.erreur);
  if (r.texte) console.log(r.texte);
  process.exit(r.code);
}
