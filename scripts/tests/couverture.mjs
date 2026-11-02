#!/usr/bin/env node
// Outil de couverture de CT-9 (spec/CT-9-plan-de-tests.md, 5.4, EX-5.8,
// EX-5.9, annexe A.3) : règles (a) à (d) de 5.1, EX-5.5 et EX-4.4 sur le
// catalogue spec/vecteurs/ct-9/catalogue.json.
//
//   node scripts/tests/couverture.mjs [--catalogue <fichier>] [--texte <CT-9>]
//        [--racine <dépôt>] [--json] [--sortie <fichier>] [--strict]
//   npm run tests:couverture
//
// Lit, en lecture seule : spec/CT-1-*.md à CT-8-*.md et spec/README.md
// (identifiants, occurrences de « CT-9 »), spec/vecteurs/ct-7/menaces.json,
// le catalogue, spec/vecteurs/ct-9/index-ta-par-menace.json s'il existe,
// test/*.test.js, .github/workflows/ci.yml et le texte de CT-9 (tables,
// chiffres de 5.5). Imprime un résumé lisible, ou le rapport JSON conforme à
// plan-de-tests-v0#/$defs/rapport_couverture avec --json ; --sortie écrit ce
// rapport dans le fichier donné (seule écriture possible). --strict fait des
// avertissements (section « CT-n §s » citée inconnue, menace citée hors
// TA- inconnue, index absent) des erreurs. Codes : 0 couvert ; 1 au moins un
// écart ; 2 usage ou fichier illisible.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { RACINE, CATALOGUE, TEXTE_CT9, INDEX_PAR_MENACE, calculerCouverture, resumeRapport } from "../lib/plan-de-tests.mjs";
import { messageOptions } from "../lib/deploiement.mjs";

const USAGE = "usage : node scripts/tests/couverture.mjs [--catalogue <fichier>] [--texte <CT-9>] [--racine <dépôt>] [--json] [--sortie <fichier>] [--strict]";

export function executer(argv) {
  let args;
  try {
    args = parseArgs({ args: argv, allowPositionals: false, options: { catalogue: { type: "string" }, texte: { type: "string" }, racine: { type: "string" }, json: { type: "boolean", default: false }, sortie: { type: "string" }, strict: { type: "boolean", default: false }, help: { type: "boolean", short: "h", default: false } } }).values;
  } catch (err) {
    return { code: 2, erreur: `${messageOptions(err)}\n${USAGE}` };
  }
  if (args.help) return { code: 0, texte: USAGE };
  const racine = path.resolve(args.racine ?? RACINE);
  const abs = (p) => path.isAbsolute(p) ? p : path.join(racine, p);
  const cheminCatalogue = args.catalogue ?? CATALOGUE;
  const texteCT9 = args.texte ?? TEXTE_CT9;
  for (const [nom, p] of [["dépôt", racine], ["catalogue", abs(cheminCatalogue)], ["texte de CT-9", abs(texteCT9)]]) {
    if (!fs.existsSync(p)) return { code: 2, erreur: `${nom} illisible : ${p}\n${USAGE}` };
  }
  let resultat;
  try {
    const index = path.dirname(abs(cheminCatalogue)) === path.dirname(abs(CATALOGUE)) || args.catalogue === undefined ? INDEX_PAR_MENACE : path.join(path.dirname(abs(cheminCatalogue)), "index-ta-par-menace.json");
    resultat = calculerCouverture({ racine, cheminCatalogue, texteCT9, index, strict: args.strict, commande: ["node", "scripts/tests/couverture.mjs", ...argv].join(" ") });
  } catch (err) {
    return { code: 2, erreur: `lecture impossible : ${err.message}` };
  }
  const { rapport, avertissements, dependances } = resultat;
  const json = JSON.stringify(rapport, null, 2) + "\n";
  if (args.sortie) fs.writeFileSync(abs(args.sortie), json);
  const texte = args.json ? json.trimEnd() : resumeRapport(rapport)
    + (dependances.length ? `\n- entrées dont une partie dépend d'une proposition non adoptée (section 14, non applicables tant qu'elle ne l'est pas) : ${dependances.join(", ")}` : "")
    + (avertissements.length && !args.strict ? `\n${avertissements.length} avertissement(s) (erreurs avec --strict) :\n${avertissements.map((a) => `  [AVERTISSEMENT] ${a}`).join("\n")}` : "");
  return { code: rapport.verdict === "reussi" ? 0 : 1, texte, rapport };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) {
  const r = executer(process.argv.slice(2));
  if (r.erreur) console.error(r.erreur);
  if (r.texte) console.log(r.texte);
  process.exit(r.code);
}
