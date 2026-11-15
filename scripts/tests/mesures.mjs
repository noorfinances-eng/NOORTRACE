#!/usr/bin/env node
// Outil des mesures, des consignations et des rapports d'exécution de CT-9
// (spec/CT-9-plan-de-tests.md, 11.3, 11.4, 12.1, 14, annexe A.5, A.7, A.8,
// A.12 ; EX-11.11, EX-11.15, EX-12.4, EX-14.1, EX-A.10, EX-A.19) : valide les
// rapports de mesure, les consignations et les rapports d'exécution publiés
// sous spec/vecteurs/ct-9/ contre le schéma plan-de-tests-v0 et le catalogue,
// compare, en phase 2, un rapport de campagne au rapport de référence, et
// valide le rapport d'exécution qu'on lui désigne.
//
//   node scripts/tests/mesures.mjs [--racine <dépôt>] [--json]
//        [--reference <rapport>] [--campagne <rapport>]
//        [--execution <rapport>]
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
// (avertissement).
//
// Rapport d'exécution (EX-A.19) : chaque fichier executions/rapport-*.json
// publié, et le fichier désigné par --execution, sont lus contre
// #/$defs/rapport_execution et contre le catalogue du dépôt lu :
//   EXE-1  forme : conforme à rapport_execution ;
//   EXE-2  chaque test_id est une entrée du catalogue ;
//   EXE-3  chaque entrée executable du catalogue a son résultat, d'un statut
//          autre que non_applicable (sa partie exécutée reste due) ;
//   EXE-4  un résultat par entrée ; seule une entrée qui porte
//          status.depends_on en admet un second, de statut non_applicable,
//          pour sa partie conditionnée (EX-14.1) ;
//   EXE-5  un résultat non_applicable vise une entrée qui porte
//          status.depends_on, et son reason nomme la proposition non adoptée ;
//   EXE-6  un rapport publié s'appelle rapport-<AAAA-MM-JJ>-<etiquette>.json
//          et la date de son nom est son membre date (avertissement pour un
//          fichier désigné hors de executions/).
// Avertissements, sans effet sur le code : résultat echec ou en_attente sans
// reason ; résultat reussi d'une entrée a_ecrire, qui ne cite aucun test ;
// commit du rapport différent de celui du dépôt lu, quand git le donne.
// L'outil ne juge aucune ligne de la porte 2 : il dit si le rapport est
// lisible par qui la juge (section 14).
//
// Codes : 0 conforme ; 1 au moins un écart ou une régression ; 2 usage ou
// fichier illisible. L'outil n'écrit rien.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { spawnSync } from "node:child_process";
import { RACINE, CATALOGUE, lireJSON } from "../lib/plan-de-tests.mjs";
import { validerSchema } from "../lib/journal.mjs";
import { messageOptions } from "../lib/deploiement.mjs";

const USAGE = "usage : node scripts/tests/mesures.mjs [--racine <dépôt>] [--json] [--reference <rapport>] [--campagne <rapport>] [--execution <rapport>]";
export const SCHEMA = "spec/schemas/plan-de-tests-v0.schema.json";
export const REPERTOIRE = "spec/vecteurs/ct-9";
/** Coefficients de régression d'EX-11.15, choix de conception de CT-9 à
 * confirmer à la première campagne. */
export const REGRESSION = Object.freeze({ latence: 1.2, debit: 0.9 });
const DEBITS = new Set(["evenements_par_s", "blocs_par_s"]);
/** Répertoire des rapports d'exécution publiés et forme de leur nom (EX-A.19). */
export const EXECUTIONS = `${REPERTOIRE}/executions`;
const NOM_EXECUTION = /^rapport-([0-9]{4}-[0-9]{2}-[0-9]{2})-[a-z0-9][a-z0-9-]*\.json$/;
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

  // Rapports d'exécution publiés (EX-A.19), hors cas/ ; le répertoire
  // n'existe qu'à partir du premier rapport.
  const repExec = path.join(rep, "executions");
  for (const f of fs.existsSync(repExec) ? fs.readdirSync(repExec).filter((x) => x.endsWith(".json")).sort() : []) {
    const r = verifierExecution(racine, path.join(repExec, f), { schema, catalogue });
    checks.push(...r.checks); errors.push(...r.errors); warnings.push(...r.warnings);
  }

  // Cas des familles (EX-A.14, EX-A.15) ; ceux de executions/ sont lus quand
  // ils existent.
  for (const [fam, def, facultatif] of [["mesures", "rapport_mesure"], ["consignations", "consignation_rejeu"], ["executions", "rapport_execution", true]]) {
    const casJson = path.join(rep, fam, "cas", "cas.json");
    if (!fs.existsSync(casJson)) { if (!facultatif) errors.push(`${fam}/cas/cas.json absent`); continue; }
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

/** Commit du dépôt lu, ou null quand git ne le donne pas (archive extraite,
 * git absent). */
function commitDuDepot(racine) {
  const r = spawnSync("git", ["-C", racine, "rev-parse", "--show-toplevel", "HEAD"], { encoding: "utf8" });
  if (r.status !== 0 || r.error) return null;
  const [sommet, commit] = r.stdout.trim().split("\n");
  let reel;
  try { reel = fs.realpathSync(racine); } catch { return null; }
  return sommet === reel && /^[0-9a-f]{40}$/.test(commit ?? "") ? commit : null;
}

/** Vrai si le fichier est directement sous executions/ du dépôt lu. */
const estPublie = (racine, fichier) => path.dirname(path.resolve(fichier)) === path.resolve(racine, EXECUTIONS);

/**
 * Valide un rapport d'exécution (EX-A.19, EX-14.1) contre le schéma et le
 * catalogue du dépôt lu : EXE-1 à EXE-6 de l'en-tête. Rend { checks: [{ id,
 * file, status, detail }], errors: [string], warnings: [string] }.
 */
export function verifierExecution(racine, fichier, { schema = lireJSON(path.join(racine, SCHEMA)), catalogue = lireJSON(path.join(racine, CATALOGUE)), nom = fichier } = {}) {
  const checks = [];
  const errors = [];
  const warnings = [];
  const publie = estPublie(racine, fichier);
  const file = publie ? `executions/${path.basename(fichier)}` : nom;
  const note = (id, ok, detail) => { checks.push({ id, file, status: ok ? "reussi" : "echec", detail }); if (!ok) errors.push(`${id} ${file} : ${detail}`); };
  const liste = (ids) => (ids.length > 12 ? `${ids.slice(0, 12).join(", ")} et ${ids.length - 12} autre(s)` : ids.join(", "));

  const r = lireJSON(fichier);
  const e = validerSchema(r, schema, { fragment: "#/$defs/rapport_execution" });
  note("EXE-1", e.length === 0, e.length ? e.slice(0, 3).map((x) => `${x.chemin} : ${x.message}`).join(" ; ") : "conforme à rapport_execution");
  if (e.length) return { checks, errors, warnings };

  const parId = new Map(catalogue.tests.map((t) => [t.id, t]));
  const parTest = new Map();
  for (const l of r.results) (parTest.get(l.test_id) ?? parTest.set(l.test_id, []).get(l.test_id)).push(l);

  const inconnus = [...parTest.keys()].filter((id) => !parId.has(id));
  note("EXE-2", inconnus.length === 0, inconnus.length ? `test_id inconnu(s) du catalogue : ${liste(inconnus)}` : `${parTest.size} test_id, tous au catalogue`);

  const executables = catalogue.tests.filter((t) => t.status.state === "executable").map((t) => t.id);
  // Une entrée executable cite un test : sa partie exécutée a un résultat,
  // qu'un non_applicable de sa partie conditionnée ne remplace pas (EX-14.1 :
  // « sa partie non conditionnée reste due »).
  const absents = executables.filter((id) => !(parTest.get(id) ?? []).some((l) => l.status !== "non_applicable"));
  note("EXE-3", absents.length === 0, absents.length ? `${absents.length} entrée(s) executable sans résultat de leur partie exécutée : ${liste(absents)}` : `les ${executables.length} entrées executable ont leur résultat`);

  const enTrop = [];
  for (const [id, ls] of parTest) {
    const conditionnee = (parId.get(id)?.status.depends_on ?? []).length > 0;
    const na = ls.filter((l) => l.status === "non_applicable").length;
    if (ls.length > 2 || (ls.length === 2 && !(conditionnee && na === 1))) enTrop.push(`${id} (${ls.length})`);
  }
  note("EXE-4", enTrop.length === 0, enTrop.length ? `plus d'un résultat pour : ${liste(enTrop)} ; seule une entrée qui porte status.depends_on admet un second résultat, non_applicable, pour sa partie conditionnée` : "un résultat par entrée, plus la partie conditionnée des entrées qui portent status.depends_on");

  const malFondes = [];
  for (const l of r.results.filter((x) => x.status === "non_applicable")) {
    const propositions = parId.get(l.test_id)?.status.depends_on ?? [];
    if (!propositions.length) malFondes.push(`${l.test_id} (aucun status.depends_on au catalogue)`);
    else if (!propositions.some((p) => new RegExp(`(^|[^A-Za-z0-9-])${p}([^0-9]|$)`).test(l.reason ?? ""))) malFondes.push(`${l.test_id} (reason ne nomme pas ${propositions.join(" ni ")})`);
  }
  const nbNA = r.results.filter((x) => x.status === "non_applicable").length;
  note("EXE-5", malFondes.length === 0, malFondes.length ? `non_applicable mal fondé : ${liste(malFondes)}` : `${nbNA} résultat(s) non_applicable, chacun avec sa proposition non adoptée`);

  const forme = NOM_EXECUTION.exec(path.basename(fichier));
  const defautNom = !forme ? `le nom ${path.basename(fichier)} n'a pas la forme rapport-<AAAA-MM-JJ>-<etiquette>.json` : forme[1] !== r.date ? `la date du nom (${forme[1]}) n'est pas le membre date (${r.date})` : null;
  if (publie) note("EXE-6", defautNom === null, defautNom ?? "nom et date conformes à EX-A.19");
  else if (defautNom) warnings.push(`EXE-6 ${file} : ${defautNom} ; exigé à la publication sous executions/`);

  // Avertissements : ils aident qui juge la porte, sans changer le code.
  const sansRaison = r.results.filter((l) => (l.status === "echec" || l.status === "en_attente") && !(l.reason ?? "").trim()).map((l) => `${l.test_id} (${l.status})`);
  if (sansRaison.length) warnings.push(`${file} : résultat sans reason : ${liste(sansRaison)}`);
  const sansTest = r.results.filter((l) => l.status === "reussi" && parId.get(l.test_id)?.status.state === "a_ecrire").map((l) => l.test_id);
  if (sansTest.length) warnings.push(`${file} : reussi pour une entrée a_ecrire, qui ne cite aucun test : ${liste(sansTest)}`);
  const commit = commitDuDepot(racine);
  if (commit && commit !== r.commit) warnings.push(`${file} : le rapport porte le commit ${r.commit}, le dépôt lu est au commit ${commit} ; le catalogue lu n'est pas celui du commit éprouvé`);

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
    args = parseArgs({ args: argv, allowPositionals: false, options: { racine: { type: "string" }, json: { type: "boolean", default: false }, reference: { type: "string" }, campagne: { type: "string" }, execution: { type: "string" }, help: { type: "boolean", short: "h", default: false } } }).values;
  } catch (err) {
    return { code: 2, erreur: `${messageOptions(err)}\n${USAGE}` };
  }
  if (args.help) return { code: 0, texte: USAGE };
  if ((args.reference === undefined) !== (args.campagne === undefined)) return { code: 2, erreur: `--reference et --campagne vont ensemble\n${USAGE}` };
  const racine = path.resolve(args.racine ?? RACINE);
  const abs = (p) => path.isAbsolute(p) ? p : path.join(racine, p);
  for (const p of [racine, abs(SCHEMA), abs(CATALOGUE), ...(args.reference ? [abs(args.reference), abs(args.campagne)] : []), ...(args.execution !== undefined ? [abs(args.execution)] : [])]) {
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
    if (args.execution !== undefined) {
      // Un rapport publié est déjà lu avec les familles : il n'est pas relu.
      if (!estPublie(racine, abs(args.execution))) {
        const ex = verifierExecution(racine, abs(args.execution), { nom: args.execution });
        resultat.checks.push(...ex.checks); resultat.errors.push(...ex.errors); resultat.warnings.push(...ex.warnings);
      }
      const lu = lireJSON(abs(args.execution));
      const compte = {};
      for (const l of Array.isArray(lu?.results) ? lu.results : []) if (typeof l?.status === "string") compte[l.status] = (compte[l.status] ?? 0) + 1;
      resultat.execution = { report: args.execution, counts: compte };
    }
  } catch (err) {
    return { code: 2, erreur: `lecture impossible : ${err.message}` };
  }
  const rapport = { version: 0, kind: "verification-mesures", verdict: resultat.errors.length ? "echec" : "reussi", checks: resultat.checks, errors: resultat.errors, warnings: resultat.warnings, ...(resultat.comparison ? { comparison: resultat.comparison } : {}), ...(resultat.execution ? { execution: resultat.execution } : {}) };
  const l = [`Mesures et consignations CT-9 : verdict ${rapport.verdict}`];
  for (const c of rapport.checks) l.push(`  [${c.status === "reussi" ? "OK" : "ÉCHEC"}] ${c.id} ${c.file} : ${c.detail}`);
  if (rapport.comparison) l.push(`  comparaison ${rapport.comparison.campaign} à ${rapport.comparison.reference} : ${rapport.comparison.regressions.length} régression(s), ${rapport.comparison.gaps.length} lacune(s)`);
  if (rapport.execution) l.push(`  rapport d'exécution ${rapport.execution.report} : ${["reussi", "echec", "en_attente", "non_applicable"].map((s) => `${rapport.execution.counts[s] ?? 0} ${s}`).join(", ")}`);
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
