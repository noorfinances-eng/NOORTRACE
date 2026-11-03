#!/usr/bin/env node
// Générateur des vecteurs de CT-9 (spec/CT-9-plan-de-tests.md, annexe A) :
// spec/vecteurs/ct-9/.
//
//   node scripts/vecteurs/generer-ct9.mjs [--sortie <répertoire ct-9>]
//        [--tables <fichier>]
//   npm run vecteurs:ct9
//
// Écrit (EX-A.1 à EX-A.3, EX-A.6, EX-A.13) :
//
//   catalogue.json             le catalogue (schéma plan-de-tests-v0, racine),
//                              construit depuis scripts/vecteurs/ct9/
//                              catalogue-donnees.mjs, menaces.json et les
//                              occurrences de « CT-9 » de spec/*.md ;
//   couverture.json            sortie de l'outil de couverture
//                              (scripts/lib/plan-de-tests.mjs, règles (a) à
//                              (d), EX-4.4) sur le dépôt et ce catalogue ;
//   index-ta-par-menace.json   pour chaque MN-, son TA-, son état et les
//                              scénarios qui le composent ;
//   cas/                       onze catalogues réduits à une entrée, valides
//                              et invalides, et attendu.json ;
//   mesures/                   rapports de mesure de la version 0.1 (vide ;
//                              sur les vecteurs, tailles de ligne du segment
//                              recalculées) et cas/ (EX-A.14) ;
//   consignations/             gabarit de consignation d'une épreuve (TR-10)
//                              et cas/ (EX-A.15) ;
//   acceptation-*/             consignes des épreuves TR-4, TR-5, TR-13 à
//                              TR-15 et grilles à part (EX-A.16 ; la grille de
//                              la porte 2 est produite depuis la section 14 du
//                              texte et la table des niveaux, EX-15.2) ;
//   extraits/                  extraits des spécifications remis aux
//                              participants et SHA256SUMS (EX-12.2) ;
//   INDEX.md                   une ligne par entrée du catalogue, par cas, par
//                              rapport, par grille et par extrait.
//
// Avec --tables, le fichier intermédiaire des tables du texte (EX-A.4) est
// écrit au chemin donné, hors de spec/vecteurs/ct-9/ ; sans l'option il n'est
// pas écrit. Le générateur lit sans les écrire spec/CT-1-*.md à CT-8-*.md,
// spec/README.md, spec/CT-9-plan-de-tests.md,
// spec/vecteurs/ct-7/menaces.json, test/*.test.js et
// .github/workflows/ci.yml (EX-4.5). Il n'efface que ses propres entrées
// (ENTREES_GENEREES), refuse une racine qui porte une entrée étrangère et
// n'écrit jamais confrontation/, verificateur-independant/ ni executions/
// (rapports d'exécution de la porte 2, EX-A.19).
// Deux exécutions donnent les mêmes octets (EX-A.1). Il s'arrête (code 1) si
// la source de données est incohérente (catalogue-donnees.mjs), si un
// identifiant cité est inconnu, si un titre ou une étape de CI cités
// n'existent pas, si une menace n'a pas son TA- ou si une occurrence de
// « CT-9 » n'a pas sa réponse ; une différence entre les tables du texte de
// CT-9 et le catalogue n'arrête pas la génération (le texte est collé depuis
// les tables produites ici) mais figure dans couverture.json.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { RACINE, MENACES, CATALOGUE, TEXTE_CT9, lireJSON, occurrencesCT9, calculerCouverture, indexParMenace, imprimerTables, texteTables } from "../lib/plan-de-tests.mjs";
import { construireCatalogue } from "./ct9/catalogue-donnees.mjs";
import { construireMesures, construireConsignations, grilleAncrage, grilleVerdictPoint, grillePorte2, consignes, construireExtraits, EXTRAITS_PAR_EPREUVE } from "./ct9/familles.mjs";

export const REPERTOIRE_CT9 = path.join(RACINE, "spec", "vecteurs", "ct-9");
/** Entrées écrites par le générateur à la racine de ct-9 ; rien d'autre
 * n'est effacé. */
export const ENTREES_GENEREES = Object.freeze(["catalogue.json", "couverture.json", "index-ta-par-menace.json", "cas", "mesures", "consignations", "acceptation-ancrage", "acceptation-ancrage-attendu.json", "acceptation-verdict-point", "acceptation-verdict-point-attendu.json", "acceptation-plan", "acceptation-porte-2", "acceptation-porte-2-attendu.json", "extraits", "INDEX.md"]);
/** Entrées jamais écrites ni effacées (EX-A.1). */
export const ENTREES_ETRANGERES_ADMISES = Object.freeze(["confrontation", "verificateur-independant", "executions"]);
const JSON2 = (v) => JSON.stringify(v, null, 2) + "\n";

// ---------------------------------------------------------------------------
// Famille cas/ (EX-A.3) : chaque cas est un catalogue réduit à une entrée.
// ---------------------------------------------------------------------------

export function construireCas(C) {
  const entree = (id) => structuredClone(C.tests.find((t) => t.id === id));
  const racine = (t) => ({ version: C.version, kind: C.kind, spec: C.spec, spec_version: C.spec_version, date: C.date, levels: C.levels, phase2_steps: C.phase2_steps, tests: [t], non_tests: [], accepted_risks: [], traceability: [] });
  const cas = [];
  const ajouter = (nom, t, expected, keyword) => cas.push({ file: `${nom}.json`, def: "racine", expected, keyword, contenu: racine(t) });
  ajouter("valide-minimal", entree("TV-2"), "valide", null);
  ajouter("valide-ta", entree("TA-3"), "valide", null);
  { const t = entree("TV-2"); t.status = { state: "executable", command: "npm test" }; ajouter("invalide-executable-sans-titre", t, "invalide", "anyOf"); }
  { const t = entree("TE-1"); delete t.status.phase2_step; ajouter("invalide-a-ecrire-sans-etape", t, "invalide", "required"); }
  { const t = entree("TA-3"); delete t.adversarial; ajouter("invalide-ta-sans-adversarial", t, "invalide", "required"); }
  { const t = entree("TV-2"); t.covers = ["E-2"]; ajouter("invalide-identifiant-sans-specification", t, "invalide", "pattern"); }
  { const t = entree("TM-1"); t.measure.measured = 4.2; ajouter("invalide-tm-mesure-inventee", t, "invalide", "type"); }
  { const t = entree("TA-3"); t.status.tests[0].it = ""; ajouter("invalide-ta-titre-vide", t, "invalide", "minLength"); }
  { const t = entree("TA-14"); delete t.status.complement.phase2_step; ajouter("invalide-ta-complement-sans-etape", t, "invalide", "required"); }
  { const t = entree("TA-3"); t.adversarial.threat_test_text = t.adversarial.threat_test_text.replace("Le test échoue si la réponse est retirée : ", ""); ajouter("invalide-ta-prefixe-test", t, "invalide", "pattern"); }
  { const t = entree("TA-99"); delete t.adversarial.composition; ajouter("invalide-ta-scenario-sans-composition", t, "invalide", "required"); }
  for (const c of cas) if (!c.contenu.tests[0]) throw new Error(`cas ${c.file} : entrée source absente du catalogue`);
  return cas;
}

// ---------------------------------------------------------------------------
// INDEX.md (EX-A.2)
// ---------------------------------------------------------------------------

/** Plie un paragraphe à 80 colonnes (les tables ne sont pas pliées). */
export function plier(texte, largeur = 80) {
  const lignes = [];
  let l = "";
  for (const mot of texte.split(" ")) {
    if (l && (l + " " + mot).length > largeur) { lignes.push(l); l = mot; } else l = l ? `${l} ${mot}` : mot;
  }
  if (l) lignes.push(l);
  return lignes;
}

const etatCourt = (t) => t.status.state === "executable" ? (t.status.complement ? "exécutable, complément à écrire" : "exécutable") : `à écrire (étape ${t.status.phase2_step})`;

export function construireIndex(C, rapport, cas, familles = null) {
  const l = [];
  l.push("# Vecteurs CT-9 — plan de tests");
  l.push("");
  l.push("Produit par `scripts/vecteurs/generer-ct9.mjs` (`npm run vecteurs:ct9`) ; ne pas");
  l.push("l'éditer à la main. Spécification :");
  l.push("[`spec/CT-9-plan-de-tests.md`](../../CT-9-plan-de-tests.md), annexe A.");
  l.push("");
  l.push("Le générateur lit les spécifications, `spec/vecteurs/ct-7/menaces.json`,");
  l.push("`test/*.test.js` et `.github/workflows/ci.yml` sans jamais les écrire");
  l.push("(EX-4.5). Il n'écrit ni n'efface `confrontation/` ni");
  l.push("`verificateur-independant/`. Deux exécutions donnent des fichiers identiques");
  l.push("(EX-A.1).");
  l.push("");
  l.push("```bash");
  l.push("npm run vecteurs:ct9");
  l.push("npm run tests:couverture   # code 0 : règles (a) à (d) et EX-4.4 tiennent");
  l.push("```");
  l.push("");
  l.push("## `catalogue.json`");
  l.push("");
  l.push(...plier(`Catalogue ${C.spec} ${C.spec_version} du ${C.date} (schéma \`plan-de-tests-v0\`, racine) : ${C.tests.length} entrées, ${C.non_tests.length} justifications NC-, ${C.accepted_risks.length} risques acceptés, ${C.traceability.length} lignes TC-. Une ligne par entrée : identifiant, niveau, état, titre.`));
  l.push("");
  l.push("| Id | Niveau | État | Titre |");
  l.push("|---|---|---|---|");
  for (const t of C.tests) l.push(`| ${t.id} | ${t.level}- | ${etatCourt(t)} | ${t.title.replace(/\|/g, "\\|")} |`);
  l.push("");
  l.push("## `couverture.json`");
  l.push("");
  l.push(...plier(`Sortie de l'outil de couverture (\`${rapport.tool.command}\`, forme \`rapport_couverture\`) sur le dépôt et ce catalogue : verdict \`${rapport.verdict}\` ; ${rapport.identifiers.total} identifiants définis par CT-1 à CT-8, ${rapport.identifiers.covered_by_tests} couverts par une entrée, ${rapport.identifiers.covered_by_nc} par une justification NC-, ${rapport.identifiers.uncovered} non couvert(s) ; ${rapport.threats.with_ta} menaces sur ${rapport.threats.total} avec un TA- ; ${rapport.traceability.occurrences} occurrences de « CT-9 » et ${rapport.traceability.rows} lignes TC- ; ${rapport.executable.total} entrées exécutables citant ${rapport.executable.titles_checked} titres ou étapes, ${rapport.executable.titles_missing.length} absent(s) ; ${rapport.text_tables.compared} tables du texte comparées, ${rapport.text_tables.differences.length} différence(s).`));
  l.push("");
  l.push("## `index-ta-par-menace.json`");
  l.push("");
  l.push(...plier(`Pour chaque menace MN-1 à MN-${rapport.threats.total} de \`spec/vecteurs/ct-7/menaces.json\` : son TA-, son état (\`executable\` ou \`a_ecrire\`) et les scénarios TA-99 à TA-103 qui le composent (EX-A.13).`));
  l.push("");
  l.push("## `cas/`");
  l.push("");
  l.push(...plier("Chaque fichier est un catalogue réduit à une entrée ; `attendu.json` nomme la définition du schéma (`racine`), le verdict attendu d'ajv (`valide` ou `invalide`) et le mot-clé fautif attendu dans la première erreur (EX-A.3)."));
  l.push("");
  l.push("| Fichier | Attendu | Mot-clé |");
  l.push("|---|---|---|");
  for (const c of cas) l.push(`| \`cas/${c.file}\` | ${c.expected} | ${c.keyword ? `\`${c.keyword}\`` : "—"} |`);
  if (familles) {
    l.push("");
    l.push("## `mesures/`");
    l.push("");
    l.push(...plier(`Rapports de mesure de la version 0.1 (\`$defs/rapport_mesure\`, CT-9 §11.3, EX-11.13) : le rapport vide (chaque ligne porte sa cible et \`null\` partout ailleurs, \`counts_for_targets\` vrai) et le rapport sur les vecteurs (\`counts_for_targets\` faux : ${familles.mesures.segment.lignes.length} tailles de ligne du segment de la démonstration de CT-2 recalculées à la génération, moyenne ${String(familles.mesures.segment.moyenne).replace(".", ",")} octets, ligne de l'annexe A de 2 465 octets, constat de cadence). Les rapports des campagnes de la porte 2 s'écrivent à côté, jamais par le générateur (EX-11.11). \`cas/cas.json\` nomme chaque cas, sa définition, son attendu pour ajv et la raison.`));
    l.push("");
    l.push("| Fichier | Attendu | Raison |");
    l.push("|---|---|---|");
    for (const n of Object.keys(familles.mesures.rapports)) l.push(`| \`mesures/${n}\` | valid | ${n.includes("vide") ? "rapport vide de la version 0.1" : "relevés sur les vecteurs publiés"} |`);
    for (const c of familles.mesures.casJson.cases) l.push(`| \`mesures/cas/${c.file}\` | ${c.expected} | ${c.reason} |`);
    l.push("");
    l.push("## `consignations/`");
    l.push("");
    l.push(...plier("Gabarit de consignation d'une épreuve à l'aveugle (`$defs/consignation_rejeu`, CT-9 §12.1, EX-12.4) pour TR-10 : SHA-256 à zéro, `duration_s` null, verdict d'exemple ; les consignations réelles sont ajoutées par l'examinateur (`<TR-n>-<AAAA-MM-JJ>-<P-nn>.json`), jamais par le générateur. `cas/cas.json` nomme chaque cas, sa définition, son attendu pour ajv et la raison."));
    l.push("");
    l.push("| Fichier | Attendu | Raison |");
    l.push("|---|---|---|");
    l.push("| `consignations/gabarit-TR-10.json` | valid | gabarit de TR-10 |");
    for (const c of familles.consignations.casJson.cases) l.push(`| \`consignations/cas/${c.file}\` | ${c.expected} | ${c.reason} |`);
    l.push("");
    l.push("## Consignes et grilles des épreuves (`acceptation-*`)");
    l.push("");
    l.push(...plier("Consignes remises aux participants des épreuves que leur spécification ne dote d'aucune grille (TR-4, TR-5) et des trois épreuves de CT-9 (TR-13 à TR-15), et grilles à part (`grille-acceptation`, `$defs/grille_acceptation` ; EX-12.7, EX-A.16). Une grille n'est jamais remise au participant ni recopiée dans sa consigne ; `test/plan-de-tests.test.js` vérifie qu'aucune consigne ne contient un élément de sa grille. La grille de la porte 2 est produite depuis la section 14 du texte et la table des niveaux (EX-15.2)."));
    l.push("");
    l.push("| Fichier | Épreuve | Contenu |");
    l.push("|---|---|---|");
    for (const [chemin, g] of Object.entries(familles.grilles)) l.push(`| \`${chemin}\` | ${g.test_id} | grille : ${g.questions.length} questions, ${g.questions.reduce((a, x) => a + x.elements.length, 0)} éléments, ${g.disqualifying.length} affirmation(s) disqualifiante(s) |`);
    for (const chemin of Object.keys(familles.consignes)) l.push(`| \`${chemin}\` | ${CONSIGNES_EPREUVES[chemin]} | consigne remise au participant |`);
    l.push("");
    l.push("## `extraits/`");
    l.push("");
    l.push(...plier("Extraits des spécifications remis aux participants (EX-12.2), découpés par sections de niveau 2 et 3 du texte du commit éprouvé, hors blocs de code, sans autre modification ; `SHA256SUMS` donne le condensé de chaque extrait, consigné à la remise."));
    l.push("");
    l.push("| Fichier | Épreuves | Contenu |");
    l.push("|---|---|---|");
    for (const [n, tr] of Object.entries(EXTRAITS_PAR_EPREUVE)) l.push(`| \`extraits/${n}\` | ${tr.join(", ")} | ${DESCRIPTION_EXTRAITS[n]} |`);
    l.push("| `extraits/SHA256SUMS` | toutes | SHA-256 de chaque extrait |");
  }
  return l.join("\n") + "\n";
}

const CONSIGNES_EPREUVES = Object.freeze({ "acceptation-ancrage/consigne.md": "TR-4", "acceptation-verdict-point/consigne.md": "TR-5", "acceptation-plan/consigne.md": "TR-13, TR-15", "acceptation-porte-2/consigne.md": "TR-14" });
const DESCRIPTION_EXTRAITS = Object.freeze({
  "CT-7-sans-9-A15.md": "CT-7 sans la section 9 ni l'annexe A.15",
  "CT-8-sans-14-A.md": "CT-8 sans la section 14 ni l'annexe A",
  "CT-8-13.md": "CT-8, section 13 seule",
  "CT-8-12.md": "CT-8, section 12 seule",
  "CT-7-7.md": "CT-7, section 7 seule",
  "CT-9-sans-15.md": "CT-9 sans la section 15",
});

// ---------------------------------------------------------------------------
// Génération
// ---------------------------------------------------------------------------

/**
 * Rapports de campagne déjà présents sous mesures/ (EX-11.11) : tout
 * `rapport-*.json` que le générateur ne produit pas. Rend [nom, octets].
 */
function rapportsDeCampagne(sortie, familles) {
  const rep = path.join(sortie, "mesures");
  if (!fs.existsSync(rep)) return [];
  const generes = new Set(Object.keys(familles.mesures.rapports));
  return fs.readdirSync(rep)
    .filter((n) => /^rapport-.*\.json$/.test(n) && !generes.has(n))
    .sort()
    .map((n) => [n, fs.readFileSync(path.join(rep, n))]);
}

/** Vérifie la racine (EX-A.1) puis efface les seules entrées générées. */
function preparerRacine(sortie) {
  if (fs.existsSync(sortie)) {
    const etrangeres = fs.readdirSync(sortie).filter((e) => !ENTREES_GENEREES.includes(e) && !ENTREES_ETRANGERES_ADMISES.includes(e));
    if (etrangeres.length) throw new Error(`racine ${sortie} : entrées étrangères refusées (${etrangeres.join(", ")}) ; rien n'a été effacé`);
    for (const e of ENTREES_GENEREES) fs.rmSync(path.join(sortie, e), { recursive: true, force: true });
  }
  fs.mkdirSync(sortie, { recursive: true });
}

/**
 * Familles mesures/, consignations/, acceptation-* et extraits/ (familles.mjs)
 * : la grille de la porte 2 est produite depuis le texte de CT-9 ; chaque
 * grille référencée par une entrée TR- du catalogue sous ct-9 doit être
 * produite ici, sinon la génération s'arrête.
 */
export function construireFamilles(C, racine) {
  const texteCT9 = fs.readFileSync(path.join(racine, TEXTE_CT9), "utf8");
  const grilles = {
    "acceptation-ancrage-attendu.json": grilleAncrage(),
    "acceptation-verdict-point-attendu.json": grilleVerdictPoint(),
    "acceptation-porte-2-attendu.json": grillePorte2(texteCT9, C),
  };
  for (const t of C.tests.filter((x) => x.level === "TR" && x.replay.grid && x.replay.grid.startsWith("spec/vecteurs/ct-9/"))) {
    const nom = t.replay.grid.slice("spec/vecteurs/ct-9/".length);
    if (nom !== "catalogue.json" && !grilles[nom]) throw new Error(`${t.id} : grille ${t.replay.grid} non produite par le générateur`);
    if (grilles[nom] && grilles[nom].test_id !== t.id) throw new Error(`${nom} : grille de ${grilles[nom].test_id}, référencée par ${t.id}`);
  }
  return { mesures: construireMesures(racine), consignations: construireConsignations(), grilles, consignes: consignes(), extraits: construireExtraits(racine) };
}

function ecrireFamilles(sortie, F) {
  const ecrire = (rel, contenu) => {
    const p = path.join(sortie, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, typeof contenu === "string" ? contenu : JSON2(contenu));
  };
  for (const [n, r] of Object.entries(F.mesures.rapports)) ecrire(`mesures/${n}`, r);
  for (const [n, c] of Object.entries(F.mesures.cas)) ecrire(`mesures/cas/${n}.json`, c);
  ecrire("mesures/cas/cas.json", F.mesures.casJson);
  ecrire("consignations/gabarit-TR-10.json", F.consignations.gabarit);
  for (const [n, c] of Object.entries(F.consignations.cas)) ecrire(`consignations/cas/${n}.json`, c);
  ecrire("consignations/cas/cas.json", F.consignations.casJson);
  for (const [n, g] of Object.entries(F.grilles)) ecrire(n, g);
  for (const [n, t] of Object.entries(F.consignes)) ecrire(n, t);
  for (const [n, t] of Object.entries(F.extraits)) ecrire(`extraits/${n}`, t);
}

/** Erreurs du rapport de couverture qui arrêtent la génération. */
const BLOQUANTES = /^(identifiant cité inconnu|identifiant sans spécification|identifiant en double|titre ou étape absent|menaces sans TA-|MN-[0-9]+ : [0-9]+ TA- de menace|occurrences de « CT-9 » sans ligne TC-|lignes TC- sans occurrence|[0-9]+ identifiant\(s\) non couvert|TA-[0-9]+ : exécutable sans mutant|TA-[0-9]+ : exécutable sans complément|RA-[0-9]+ : measured_by|RA-[0-9]+ : borne chiffrée|TA-[0-9]+ : depends_on|[A-Z]+-[0-9]+ : command ne lance pas)/;

export function generer(sortie = REPERTOIRE_CT9, { racine = RACINE, tables = null } = {}) {
  const menaces = lireJSON(path.join(racine, MENACES));
  const occurrences = occurrencesCT9(racine);
  const C = construireCatalogue({ menaces, occurrences });
  const octets = Buffer.from(JSON2(C), "utf8");
  const { rapport } = calculerCouverture({ racine, catalogue: C, cheminCatalogue: CATALOGUE, octetsCatalogue: octets, texteCT9: TEXTE_CT9, index: indexParMenace(C), date: C.date, commande: "node scripts/tests/couverture.mjs --json" });
  const bloquantes = rapport.errors.filter((e) => BLOQUANTES.test(e));
  if (bloquantes.length) throw new Error(`couverture :\n - ${bloquantes.join("\n - ")}`);
  const cas = construireCas(C);
  const familles = construireFamilles(C, racine);
  // Rapports de campagne (EX-11.11) : écrits par l'ingénieur de la campagne
  // sous mesures/, jamais par le générateur ; conservés octet pour octet.
  const campagnes = rapportsDeCampagne(sortie, familles);

  preparerRacine(sortie);
  fs.writeFileSync(path.join(sortie, "catalogue.json"), octets);
  fs.writeFileSync(path.join(sortie, "couverture.json"), JSON2(rapport));
  fs.writeFileSync(path.join(sortie, "index-ta-par-menace.json"), JSON2({ version: 0, date: C.date, index: indexParMenace(C) }));
  fs.mkdirSync(path.join(sortie, "cas"));
  for (const c of cas) fs.writeFileSync(path.join(sortie, "cas", c.file), JSON2(c.contenu));
  fs.writeFileSync(path.join(sortie, "cas", "attendu.json"), JSON2({
    version: 0, family: "ct-9/cas",
    description: "Cas de la famille cas/ : chaque fichier est un catalogue réduit à une entrée ; def nomme la définition du schéma plan-de-tests-v0 (racine), expected le verdict d'ajv et keyword le mot-clé fautif attendu dans la première erreur.",
    cases: cas.map(({ file, def, expected, keyword }) => ({ file, def, expected, keyword })),
  }));
  ecrireFamilles(sortie, familles);
  for (const [n, octetsRapport] of campagnes) fs.writeFileSync(path.join(sortie, "mesures", n), octetsRapport);
  fs.writeFileSync(path.join(sortie, "INDEX.md"), construireIndex(C, rapport, cas, familles));
  if (tables) {
    const t = path.resolve(tables);
    if (t.startsWith(path.resolve(sortie) + path.sep)) throw new Error("--tables : le fichier intermédiaire ne s'écrit pas sous la racine des vecteurs");
    fs.writeFileSync(t, texteTables(imprimerTables(C)));
  }
  return { catalogue: C, rapport, cas };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) {
  const args = process.argv.slice(2);
  let sortie = REPERTOIRE_CT9;
  let tables = null;
  let ok = true;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--sortie" && args[i + 1]) sortie = path.resolve(args[++i]);
    else if (args[i] === "--tables" && args[i + 1]) tables = args[++i];
    else ok = false;
  }
  if (!ok) {
    console.error("usage : node scripts/vecteurs/generer-ct9.mjs [--sortie <répertoire ct-9>] [--tables <fichier>]");
    process.exit(2);
  }
  let r;
  try {
    r = generer(sortie, { tables });
  } catch (err) {
    console.error(`Erreur : ${err.message}`);
    process.exit(1);
  }
  console.log(`Vecteurs CT-9 écrits dans ${path.relative(process.cwd(), sortie) || "."} : ${r.catalogue.tests.length} entrées, couverture ${r.rapport.verdict}${r.rapport.errors.length ? ` (${r.rapport.errors.length} écart(s), voir couverture.json)` : ""}`);
}
