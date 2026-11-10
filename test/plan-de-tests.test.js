// Tests du plan de tests de CT-9 (spec/CT-9-plan-de-tests.md, annexe A.4,
// EX-A.7 et EX-A.9 ; sections 3, 4, 5, 10, 11, 12, 14, 15).
//
// Ce fichier exige : que le catalogue, le rapport de couverture, les rapports
// de mesure, les consignations et les grilles valident contre le schéma
// plan-de-tests-v0 et que chaque cas des familles cas/, mesures/cas/ et
// consignations/cas/ rende son attendu ; que les règles de couverture (a) à
// (d) et EX-5.5 tiennent, rejouées ici depuis les primitives de la
// bibliothèque (inventaire, occurrences, titres) et non depuis le seul verdict
// de l'outil ; que l'outil de couverture rende 0 et un rapport égal à
// couverture.json hors `date` et `tool.command` ; que chaque table du texte
// égale le catalogue (EX-4.4) et que les chiffres de 5.5 soient ceux du
// rapport ; que deux générations dans des répertoires vides donnent les mêmes
// octets que le dépôt ; que test/adversarial.test.js ait la forme d'EX-10.7
// et porte chaque TA- qui le cite ; que chaque TM- et chaque TR- suivent
// 11.4 et 12.1 ; que les extraits remis égalent le texte du dépôt ; que la
// confrontation Python et le vérificateur Go rendent 0 (en attente sans
// python3 ou sans go). Rien n'est écrit dans le dépôt : les générations et
// les mutations vont dans un répertoire temporaire détruit à la fin.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as P from "../scripts/lib/plan-de-tests.mjs";
import { executer as couverture } from "../scripts/tests/couverture.mjs";
import { executer as mesures, comparerCampagne, verifierFamilles } from "../scripts/tests/mesures.mjs";
import { generer, ENTREES_GENEREES, ENTREES_ETRANGERES_ADMISES, construireCas } from "../scripts/vecteurs/generer-ct9.mjs";
import { extraire, construireExtraits, grillePorte2, delaisPoints, DOSSIER_TR5, EXTRAITS_PAR_EPREUVE } from "../scripts/vecteurs/ct9/familles.mjs";

const R = PROJECT_ROOT;
const CT9 = path.join(R, "spec", "vecteurs", "ct-9");
const SCHEMA = J.analyserJSONStrict(fs.readFileSync(path.join(R, "spec", "schemas", "plan-de-tests-v0.schema.json")));
const lire = (...p) => JSON.parse(fs.readFileSync(path.join(...p), "utf8"));
const texte = (...p) => fs.readFileSync(path.join(...p), "utf8");
const CATALOGUE = lire(CT9, "catalogue.json");
const COUVERTURE = lire(CT9, "couverture.json");
const MENACES = lire(R, P.MENACES);
const TEXTE = texte(R, P.TEXTE_CT9);
const parId = new Map(CATALOGUE.tests.map((t) => [t.id, t]));
const valider = (v, def) => J.validerSchema(v, SCHEMA, def === "racine" ? {} : { fragment: `#/$defs/${def}` });
const egal = (a, b) => JSON.stringify(a) === JSON.stringify(b);

const ADV_FICHIER = "test/adversarial.test.js";
const TMP = [];
const tmp = (nom) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), `noortrace-ct9-${nom}-`)); TMP.push(d); return d; };
after(function () { for (const d of TMP) fs.rmSync(d, { recursive: true, force: true }); });

/** Fichiers d'un répertoire, chemins relatifs triés, hors `exclus` à la
 * racine. */
function fichiers(rep, exclus = []) {
  const out = [];
  const marcher = (d, rel) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (!rel && exclus.includes(e.name)) continue;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) marcher(path.join(d, e.name), r); else out.push(r);
    }
  };
  marcher(rep, "");
  return out;
}

/** Mots-clés JSON Schema désignés par une erreur du validateur du dépôt
 * (message en français). */
const MOT_CLE = [[/membre obligatoire absent/, "required"], [/ne respecte pas le motif/, "pattern"], [/^type .* attendu$/, "type"], [/chaîne de moins de/, "minLength"], [/chaîne de plus de/, "maxLength"], [/aucune des variantes anyOf/, "anyOf"], [/valeur constante/, "const"], [/hors de l'énumération/, "enum"], [/membre non admis/, "additionalProperties"], [/moins de [0-9]+ élément/, "minItems"]];
const motsClesDe = (e) => MOT_CLE.filter(([re]) => re.test(e.message)).map(([, k]) => k);
/** Mots-clés des variantes de tout `anyOf` d'un sous-schéma (sans descendre
 * dans properties/items), pour lire une erreur anyOf comme ajv liste ses
 * branches. */
function motsClesVariantes(s, acc = new Set()) {
  if (!s || typeof s !== "object") return acc;
  if (Array.isArray(s.anyOf)) for (const v of s.anyOf) for (const k of Object.keys(v)) if (J.MOTS_CLES_VALIDATION.includes(k)) acc.add(k);
  for (const k of ["allOf", "then", "else", "if"]) if (s[k]) (Array.isArray(s[k]) ? s[k] : [s[k]]).forEach((x) => motsClesVariantes(x, acc));
  return acc;
}
/** Sous-schéma désigné par un chemin d'erreur, en suivant properties, items
 * et $ref. */
function sousSchema(chemin) {
  let s = SCHEMA;
  const suivre = (x) => (x && x.$ref ? SCHEMA.$defs[x.$ref.split("/").pop()] : x);
  for (const seg of chemin.split("/").slice(1)) {
    s = suivre(s);
    if (s.properties && seg in s.properties) s = s.properties[seg];
    else if (s.items) s = s.items;
    else return null;
  }
  return suivre(s);
}

// ---------------------------------------------------------------------------
describe("CT-9 : catalogue, schéma et cas (section 4, annexe A.2, EX-4.3, EX-A.3, EX-A.7)", function () {
  this.timeout(120_000);

  it("le schéma plan-de-tests-v0 n'emploie aucun mot-clé hors du sous-ensemble du validateur du dépôt, n'a aucune référence croisée et porte son $id", function () {
    expect(J.motsClesHorsSousEnsemble(SCHEMA)).to.deep.equal([]);
    expect(SCHEMA.$id).to.equal("https://noortrace.example/schemas/v0/plan-de-tests.schema.json");
    expect(SCHEMA.$schema).to.equal("https://json-schema.org/draft/2020-12/schema");
    const refs = JSON.stringify(SCHEMA).match(/"\$ref":"([^"]+)"/g).map((x) => x.slice(8, -1));
    for (const r of refs) { expect(r.startsWith("#/$defs/"), r).to.equal(true); expect(SCHEMA.$defs, r).to.have.property(r.slice(8)); }
    for (const d of ["test", "adversarial", "mesure", "rejeu", "revue", "justification_nc", "risque_accepte", "ligne_tc", "rapport_couverture", "rapport_execution", "rapport_mesure", "consignation_rejeu", "grille_acceptation"]) expect(SCHEMA.$defs, d).to.have.property(d);
  });

  it("catalogue.json valide contre la racine, couverture.json contre rapport_couverture, et index-ta-par-menace.json est l'index que le catalogue donne (EX-A.13)", function () {
    expect(valider(CATALOGUE, "racine")).to.deep.equal([]);
    expect(valider(COUVERTURE, "rapport_couverture")).to.deep.equal([]);
    expect(CATALOGUE).to.include({ version: 0, kind: "plan-de-tests", spec: "CT-9", spec_version: "0.6", date: "2026-11-10" });
    const index = lire(CT9, "index-ta-par-menace.json");
    expect(index.index).to.deep.equal(P.indexParMenace(CATALOGUE));
    expect(Object.keys(index.index)).to.have.length(MENACES.threats.length);
    expect(fs.readFileSync(path.join(CT9, "catalogue.json"), "utf8")).to.equal(JSON.stringify(CATALOGUE, null, 2) + "\n");
  });

  it("chaque cas de cas/ rend son attendu (valide ou invalide) et le mot-clé fautif de attendu.json figure parmi les erreurs ou les variantes anyOf qu'elles désignent", function () {
    const attendu = lire(CT9, "cas", "attendu.json");
    expect(attendu.cases).to.have.length(11);
    expect(attendu.cases.filter((c) => c.expected === "valide")).to.have.length(2);
    for (const c of attendu.cases) {
      const erreurs = valider(lire(CT9, "cas", c.file), c.def);
      expect(erreurs.length === 0 ? "valide" : "invalide", c.file).to.equal(c.expected);
      if (c.expected === "valide") { expect(c.keyword).to.equal(null); continue; }
      const mots = new Set(erreurs.flatMap(motsClesDe));
      for (const e of erreurs) if (/anyOf/.test(e.message)) for (const k of motsClesVariantes(sousSchema(e.chemin))) mots.add(k);
      expect([...mots], `${c.file} : ${JSON.stringify(erreurs)}`).to.include(c.keyword);
    }
    expect(fs.readdirSync(path.join(CT9, "cas")).filter((f) => f !== "attendu.json").sort()).to.deep.equal(attendu.cases.map((c) => c.file).sort());
    // Les cas sont ceux que le générateur construit depuis le catalogue
    // (EX-A.3).
    for (const c of construireCas(CATALOGUE)) expect(lire(CT9, "cas", c.file), c.file).to.deep.equal(c.contenu);
  });

  it("EX-3.1 : identifiants uniques, de la famille de leur niveau, numérotés sans trou dans l'ordre du catalogue ; huit niveaux et huit étapes de la phase 2", function () {
    expect(CATALOGUE.levels.map((l) => l.id)).to.deep.equal([...P.NIVEAUX]);
    expect(CATALOGUE.phase2_steps.map((e) => e.step)).to.deep.equal([1, 2, 3, 4, 5, 6, 7, 8]);
    const compteurs = {};
    for (const t of CATALOGUE.tests) {
      compteurs[t.level] = (compteurs[t.level] ?? 0) + 1;
      expect(t.id, t.title).to.equal(`${t.level}-${compteurs[t.level]}`);
    }
    expect(new Set(CATALOGUE.tests.map((t) => t.id)).size).to.equal(CATALOGUE.tests.length);
    expect(CATALOGUE.tests).to.have.length(322);
    expect(compteurs).to.deep.equal({ TU: 39, TV: 76, TI: 20, TE: 17, TA: 103, TM: 44, TR: 15, TQ: 8 });
    CATALOGUE.non_tests.forEach((n, i) => expect(n.id).to.equal(`NC-${i + 1}`));
    CATALOGUE.traceability.forEach((r, i) => expect(r.id).to.equal(`TC-${i + 1}`));
  });

  it("EX-3.10 et EX-4.1 : états executable et a_ecrire, specs déduites de covers, blocs propres au niveau, menaces citées hors TA- existantes", function () {
    const mn = new Set(MENACES.threats.map((t) => t.id));
    const blocs = { TA: "adversarial", TM: "measure", TR: "replay", TQ: "review" };
    for (const t of CATALOGUE.tests) {
      const s = t.status;
      expect(["executable", "a_ecrire"], t.id).to.include(s.state);
      if (s.state === "executable") { expect(s.command, t.id).to.be.a("string"); expect((s.tests?.length ?? 0) + (s.ci_steps?.length ?? 0), t.id).to.be.greaterThan(0); expect(s.phase2_step, t.id).to.equal(undefined); } else { expect(s.phase2_step, t.id).to.be.within(1, 8); expect(s.blocking, t.id).to.be.a("string"); expect(s.complement, t.id).to.equal(undefined); expect(s.tests, t.id).to.equal(undefined); }
      expect(t.specs.length, t.id).to.be.greaterThan(0);
      expect(new Set(t.specs).size, t.id).to.equal(t.specs.length);
      for (const s of t.specs) expect(s, t.id).to.match(/^CT-[1-8]$/);
      for (const c of t.covers) expect(c, t.id).to.match(/^CT-[1-8] /);
      for (const [niv, bloc] of Object.entries(blocs)) expect(bloc in t, `${t.id} ${bloc}`).to.equal(t.level === niv);
      expect(t.preconditions.length, t.id).to.be.greaterThan(0);
      expect(t.steps.length, t.id).to.be.greaterThan(0);
      for (const m of t.threats) expect(mn.has(m), `${t.id} ${m}`).to.equal(true);
    }
  });
});

// ---------------------------------------------------------------------------
describe("CT-9 : couverture (section 5, règles (a) à (d), EX-5.5, EX-4.4, EX-5.10)", function () {
  this.timeout(300_000);
  const INV = P.inventaire(R);

  it("règle (a) rejouée : chaque identifiant défini par CT-1 à CT-8 est couvert par covers, par threats d'un TA- ou par un NC-, et chaque identifiant cité existe ; 2351 identifiants", function () {
    const couverts = new Set();
    const connu = (id) => { const m = /^(CT-[1-8]) (.+)$/.exec(id); return Boolean(m && INV[m[1]]?.ids.has(m[2])); };
    for (const t of CATALOGUE.tests) {
      for (const id of t.covers) { if (/§/.test(id)) continue; expect(connu(id), `${t.id} cite ${id}`).to.equal(true); couverts.add(id); }
      if (t.level === "TA") for (const m of t.threats) couverts.add(`CT-7 ${m}`);
    }
    const parNC = new Set();
    for (const n of CATALOGUE.non_tests) for (const id of n.covers) { expect(connu(id), `${n.id} cite ${id}`).to.equal(true); parNC.add(id); }
    let total = 0, parEntree = 0, parJustification = 0;
    const nonCouverts = [];
    for (const [ct] of P.SPECIFICATIONS) for (const x of INV[ct].ids) { total++; const id = `${ct} ${x}`; if (couverts.has(id)) parEntree++; else if (parNC.has(id)) parJustification++; else nonCouverts.push(id); }
    expect(nonCouverts).to.deep.equal([]);
    expect([total, parEntree, parJustification]).to.deep.equal([COUVERTURE.identifiers.total, COUVERTURE.identifiers.covered_by_tests, COUVERTURE.identifiers.covered_by_nc]);
    expect(total).to.equal(2351);
    expect(COUVERTURE.identifiers.unknown_cited).to.deep.equal([]);
    // EX-4.1 : specs est l'ensemble des spécifications de covers (entrées à covers non vide).
    for (const t of CATALOGUE.tests) if (t.covers.length) expect(t.specs, t.id).to.deep.equal([...new Set(t.covers.map((c) => c.split(" ")[0]))].sort((x, y) => Number(x.slice(3)) - Number(y.slice(3))));
  });

  it("règle (b) rejouée : chaque menace MN-n a exactement un TA-n, chaque TA- sa menace, les égalités d'EX-10.2 tiennent et les 82 risques acceptés sont ceux de menaces.json", function () {
    const TA = CATALOGUE.tests.filter((t) => t.level === "TA");
    for (const m of MENACES.threats) {
      const ta = TA.filter((t) => t.adversarial.threat === m.id);
      expect(ta, m.id).to.have.length(1);
      const t = ta[0];
      expect(t.id).to.equal(`TA-${m.id.slice(3)}`);
      expect(t.threats).to.deep.equal([m.id]);
      expect(t.adversarial.threat_test_text, t.id).to.equal(m.test);
      expect(t.adversarial.threat_test_text.startsWith("Le test échoue si la réponse est retirée : "), t.id).to.equal(true);
      expect(t.covers, t.id).to.deep.equal(m.response.refs);
      expect(t.adversarial.component, t.id).to.equal(m.component);
      expect(t.adversarial.accepted_risk, t.id).to.equal(m.residual?.accepted_risk?.id ?? null);
    }
    for (const t of TA) if (t.adversarial.threat) expect(MENACES.threats.some((m) => m.id === t.adversarial.threat), t.id).to.equal(true);
    const ra = MENACES.threats.filter((m) => m.residual?.accepted_risk);
    expect(CATALOGUE.accepted_risks).to.have.length(ra.length);
    expect(ra).to.have.length(82);
    for (const m of ra) {
      const r = CATALOGUE.accepted_risks.find((x) => x.id === m.residual.accepted_risk.id);
      expect(r, m.id).to.not.equal(undefined);
      expect([r.name, r.bound, r.owner, r.threat]).to.deep.equal([m.residual.accepted_risk.name, m.residual.accepted_risk.bound, m.residual.accepted_risk.owner, m.id]);
      expect(r.test).to.equal(`TA-${m.id.slice(3)}`);
      expect(r.test_state).to.equal(parId.get(r.test).status.state);
    }
    expect(COUVERTURE.threats).to.deep.equal({ total: 98, with_ta: 98, without_ta: [] });
  });

  it("règle (c) rejouée : le compte des occurrences de « CT-9 » dans spec/CT-1-*.md à CT-8-*.md et spec/README.md égale le nombre de lignes TC-, clé par clé (122)", function () {
    const occ = P.occurrencesCT9(R);
    expect(occ).to.have.length(CATALOGUE.traceability.length);
    const brut = P.FICHIERS_TC.reduce((n, [, f]) => n + (texte(R, f).match(/CT-9/g) || []).length, 0);
    expect(brut).to.equal(occ.length);
    const multi = (l) => { const m = {}; for (const k of l) m[k] = (m[k] ?? 0) + 1; return m; };
    expect(multi(CATALOGUE.traceability.map((r) => r.key))).to.deep.equal(multi(occ.map((o) => o.key)));
    for (const r of CATALOGUE.traceability) expect(r.response.length, r.id).to.be.greaterThan(0);
    expect(COUVERTURE.traceability).to.deep.equal({ occurrences: 122, rows: 122, missing: [], orphans: [] });
  });

  it("règle (d) rejouée : chaque titre de describe/it et chaque étape de CI cités par une entrée exécutable existent mot pour mot (224 entrées, 485 citations)", function () {
    const index = P.indexTitres(R);
    const ci = P.etapesCI(texte(R, P.CI));
    let entrees = 0, citations = 0;
    for (const t of CATALOGUE.tests) {
      if (t.status.state !== "executable") continue;
      entrees++;
      for (const x of t.status.tests ?? []) { citations++; expect(P.titreExiste(index, x), `${t.id} : ${x.file} | ${x.describe} | ${x.it ?? ""}`).to.equal(true); }
      for (const s of t.status.ci_steps ?? []) { citations++; expect(ci.has(s), `${t.id} : ${s}`).to.equal(true); }
    }
    expect([entrees, citations]).to.deep.equal([COUVERTURE.executable.total, COUVERTURE.executable.titles_checked]);
    expect(COUVERTURE.executable.titles_missing).to.deep.equal([]);
    // EX-3.10 : la commande citée lance chaque fichier de test cité.
    for (const t of CATALOGUE.tests) if (t.status.state === "executable") for (const x of t.status.tests ?? []) expect(t.status.command, `${t.id} : ${x.file}`).to.include(x.file);
  });

  it("EX-4.4 : chaque table du texte égale, cellule par cellule, la table imprimée depuis le catalogue (quinze tables), et les chiffres de 5.5 sont ceux de couverture.json", function () {
    const r = P.comparerTables(CATALOGUE, TEXTE);
    expect(r.differences).to.deep.equal([]);
    expect(r.compared).to.equal(P.TABLES.length);
    expect(Object.keys(P.tablesDuTexte(TEXTE)).sort()).to.deep.equal([...P.TABLES].sort());
    expect(P.comparerChiffres55(TEXTE, COUVERTURE)).to.deep.equal([]);
    expect(COUVERTURE.text_tables).to.deep.equal({ compared: 15, differences: [] });
    // Les tables 11.5 et 12.2 sont celles des entrées TM- et TR- ; la table
    // TC- a une ligne par occurrence.
    const lu = P.tablesDuTexte(TEXTE);
    expect(lu.TM).to.have.length(2 + 44);
    expect(lu.TR).to.have.length(2 + 15);
    expect(lu.TC).to.have.length(2 + 122);
  });

  it("l'outil de couverture rend 0 sur le dépôt et un rapport égal à couverture.json hors date et tool.command ; --strict rend 0 aussi", function () {
    const r = couverture([]);
    expect(r.code, r.texte).to.equal(0);
    const sans = (x) => { const c = structuredClone(x); delete c.date; delete c.tool.command; return c; };
    expect(sans(r.rapport)).to.deep.equal(sans(COUVERTURE));
    expect(COUVERTURE.tool).to.deep.equal({ name: "scripts/tests/couverture.mjs", command: "node scripts/tests/couverture.mjs --json" });
    expect(r.rapport.verdict).to.equal("reussi");
    expect(couverture(["--strict"]).code).to.equal(0);
    const j = couverture(["--json"]);
    expect(sans(JSON.parse(j.texte))).to.deep.equal(sans(COUVERTURE));
    // Les condensés d'entrée sont ceux des fichiers lus (EX-A.6).
    for (const s of COUVERTURE.inputs.specs) expect(P.sha256Fichier(path.join(R, s.file)), s.file).to.equal(s.sha256);
    expect(COUVERTURE.inputs.catalogue.sha256).to.equal(P.sha256Fichier(path.join(CT9, "catalogue.json")));
    expect(COUVERTURE.inputs.threats.sha256).to.equal(P.sha256Fichier(path.join(R, P.MENACES)));
    expect(COUVERTURE.inputs.tests.map((t) => t.file)).to.deep.equal(P.fichiersTests(R));
    for (const t of COUVERTURE.inputs.tests) expect(P.sha256Fichier(path.join(R, t.file)), t.file).to.equal(t.sha256);
  });

  it("l'outil rend 1 sur un catalogue qui cite un identifiant inconnu, un identifiant sans spécification, un titre absent, une commande qui ne lance pas un fichier cité ou un TA- exécutable sans mutant (écarts nommés, EX-5.5, EX-5.8, EX-3.10, EX-10.3), 2 sur un fichier illisible ou une option inconnue", function () {
    const d = tmp("couverture");
    const mute = structuredClone(CATALOGUE);
    mute.tests[0].covers.push("CT-1 EX-99.1");
    mute.tests[1].covers.push("E-2");
    mute.non_tests[0].covers.push("EX-5.3");
    const ta3 = mute.tests.find((t) => t.id === "TA-3");
    ta3.status.tests[0].it = "titre qui n'existe pas";
    const tu3 = mute.tests.find((t) => t.id === "TU-3");
    tu3.status.command = "npm test";
    const ta4 = mute.tests.find((t) => t.id === "TA-4");
    ta4.status.tests = ta4.status.tests.filter((x) => x.file !== ADV_FICHIER);
    ta4.oracle += " Un mutant est à ajouter.";
    fs.writeFileSync(path.join(d, "catalogue.json"), JSON.stringify(mute, null, 2) + "\n");
    fs.copyFileSync(path.join(CT9, "index-ta-par-menace.json"), path.join(d, "index-ta-par-menace.json"));
    const r = couverture(["--catalogue", path.join(d, "catalogue.json"), "--sortie", path.join(d, "rapport.json")]);
    expect(r.code).to.equal(1);
    expect(r.rapport.errors.some((e) => e.startsWith("identifiant cité inconnu : TU-1 : CT-1 EX-99.1"))).to.equal(true);
    expect(r.rapport.errors).to.include("identifiant sans spécification : TU-2 : E-2");
    expect(r.rapport.errors).to.include("identifiant sans spécification : NC-1 : EX-5.3");
    expect(r.rapport.errors.some((e) => e.startsWith("titre ou étape absent (TA-3)"))).to.equal(true);
    expect(r.rapport.errors).to.include("TU-3 : command ne lance pas test/journal.test.js (EX-3.10)");
    expect(r.rapport.errors.some((e) => e.startsWith("TA-4 : exécutable sans mutant tué"))).to.equal(true);
    expect(r.rapport.errors.some((e) => e.startsWith("TA-4 : exécutable sans complément dont l'oracle"))).to.equal(true);
    expect(r.rapport.identifiers.unknown_cited).to.deep.equal(["TU-1 : CT-1 EX-99.1"]);
    expect(valider(lire(d, "rapport.json"), "rapport_couverture")).to.deep.equal([]);
    expect(couverture(["--catalogue", path.join(d, "nulle-part.json")]).code).to.equal(2);
    expect(couverture(["--inconnue"]).code).to.equal(2);
    expect(fs.readFileSync(path.join(CT9, "catalogue.json"), "utf8")).to.equal(JSON.stringify(CATALOGUE, null, 2) + "\n");
  });
});

// ---------------------------------------------------------------------------
describe("CT-9 : génération déterministe et INDEX.md (EX-A.1, EX-A.2, EX-4.5)", function () {
  this.timeout(600_000);

  it("deux générations dans des répertoires vides donnent les mêmes octets entre elles et que spec/vecteurs/ct-9 (hors confrontation/ et verificateur-independant/)", function () {
    const g1 = path.join(tmp("gen1"), "ct-9");
    const g2 = path.join(tmp("gen2"), "ct-9");
    generer(g1, { racine: R });
    generer(g2, { racine: R });
    const l1 = fichiers(g1);
    expect(l1).to.deep.equal(fichiers(g2));
    // Les rapports de campagne de mesures/ (EX-11.11) sont écrits par
    // l'ingénieur, jamais par le générateur : exclus de la comparaison, et
    // conservés tels quels par une régénération du dépôt (rapportsDeCampagne).
    const campagne = (f) => /^mesures\/rapport-.*\.json$/.test(f) && !l1.includes(f);
    expect(l1).to.deep.equal(fichiers(CT9, [...ENTREES_ETRANGERES_ADMISES]).filter((f) => !campagne(f)));
    for (const f of l1) {
      expect(fs.readFileSync(path.join(g1, f)).equals(fs.readFileSync(path.join(g2, f))), f).to.equal(true);
      expect(fs.readFileSync(path.join(g1, f)).equals(fs.readFileSync(path.join(CT9, f))), `${f} diffère du dépôt`).to.equal(true);
    }
    expect(new Set(l1.map((f) => f.split("/")[0]))).to.deep.equal(new Set(ENTREES_GENEREES));
    for (const f of l1.filter((x) => x.endsWith(".json"))) { const o = fs.readFileSync(path.join(g1, f), "utf8"); expect(o, f).to.equal(JSON.stringify(JSON.parse(o), null, 2) + "\n"); }
  });

  it("le générateur refuse une racine qui porte une entrée étrangère et n'y efface rien", function () {
    const d = path.join(tmp("etranger"), "ct-9");
    fs.mkdirSync(d);
    fs.writeFileSync(path.join(d, "etranger.txt"), "x");
    fs.writeFileSync(path.join(d, "catalogue.json"), "{}");
    expect(() => generer(d, { racine: R })).to.throw(/entrées étrangères refusées \(etranger.txt\)/);
    expect(fs.readFileSync(path.join(d, "catalogue.json"), "utf8")).to.equal("{}");
  });

  it("INDEX.md dit qu'il est produit par le générateur et liste chaque entrée du catalogue, chaque cas, chaque rapport, chaque grille et chaque extrait", function () {
    const index = texte(CT9, "INDEX.md");
    expect(index).to.include("Produit par `scripts/vecteurs/generer-ct9.mjs`");
    expect(index).to.include("ne pas\nl'éditer à la main");
    for (const t of CATALOGUE.tests) expect(index, t.id).to.include(`| ${t.id} | ${t.level}- |`);
    for (const c of lire(CT9, "cas", "attendu.json").cases) expect(index).to.include(`\`cas/${c.file}\``);
    for (const c of lire(CT9, "mesures", "cas", "cas.json").cases) expect(index).to.include(`\`mesures/cas/${c.file}\``);
    for (const c of lire(CT9, "consignations", "cas", "cas.json").cases) expect(index).to.include(`\`consignations/cas/${c.file}\``);
    for (const n of Object.keys(EXTRAITS_PAR_EPREUVE)) expect(index).to.include(`\`extraits/${n}\``);
    for (const g of ["acceptation-ancrage-attendu.json", "acceptation-verdict-point-attendu.json", "acceptation-porte-2-attendu.json"]) expect(index).to.include(`\`${g}\``);
    let code = false;
    for (const l of index.split("\n")) { if (l.startsWith("```")) code = !code; if (!code && !l.startsWith("|")) expect(l.length, l).to.be.at.most(80); }
  });
});

// ---------------------------------------------------------------------------
describe("CT-9 : tests adversariaux (section 10, EX-10.1, EX-10.7, EX-10.8, EX-A.8, EX-A.11)", function () {
  const ADV = "test/adversarial.test.js";
  const titres = P.titresTests(texte(R, ADV));
  const RACINE_DESCRIBE = "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)";
  // Révision 0.2 : describe de premier niveau des TA- joués sur le démon de l'étape 4 (mutants du paquet, EX-10.5).
  const DEMON_DESCRIBE = "CT-9 : tests adversariaux TA- exécutables sur le démon de l'étape 4 (mutants du paquet @noortrace/enregistreur, CT-7 EX-3.2)";
  const TA = CATALOGUE.tests.filter((t) => t.level === "TA");

  it("chaque it commence par ses identifiants TA- puis la menace entre parenthèses, un qualificatif facultatif, et finit par « (tué) » ou « (tués) » sauf les oracles sur un vecteur d'EX-10.4 ; TA-n nomme MN-n ; 71 it : 58 sous le describe racine des bibliothèques et ses neuf describe par composant, 13 sous le describe du démon de l'étape 4", function () {
    expect(titres.cas).to.have.length(71);
    expect(titres.describes[0]).to.equal(RACINE_DESCRIBE);
    expect(titres.describes).to.have.length(11);
    expect(titres.describes[10]).to.equal(DEMON_DESCRIBE);
    expect(titres.cas.filter((c) => c.describes[0] === RACINE_DESCRIBE)).to.have.length(58);
    expect(titres.cas.filter((c) => c.describes[0] === DEMON_DESCRIBE)).to.have.length(13);
    for (const c of titres.cas) {
      expect([RACINE_DESCRIBE, DEMON_DESCRIBE], c.it).to.include(c.describes[0]);
      expect(c.describes, c.it).to.have.length(c.describes[0] === RACINE_DESCRIBE ? 2 : 1);
      // EX-10.7 : après la liste des menaces, un qualificatif séparé par
      // « , » et sans parenthèse est admis (« partie exécutable ») ; les deux
      // oracles sur un vecteur d'EX-10.4 (TA-23, TA-72) portent « oracle sur
      // le vecteur » à la place de « (tué) ».
      const m = /^(TA-[0-9]+(?: et TA-[0-9]+)*) \((MN-[0-9]+(?:, MN-[0-9]+)*)(?:, [^()]*)?\) : .*$/.exec(c.it);
      expect(m, c.it).to.not.equal(null);
      if (!/\(tués?\)$/.test(c.it)) { expect(["TA-23", "TA-72"], c.it).to.include(m[1]); expect(c.it, c.it).to.match(/^TA-[0-9]+ \(MN-[0-9]+, oracle sur les? vecteurs?\) : /); }
      const ta = m[1].split(" et ").map((x) => x.slice(3));
      const mn = m[2].split(", ").map((x) => x.slice(3));
      expect(mn, c.it).to.deep.equal(ta);
    }
  });

  it("chaque entrée TA- exécutable est d'exécution vecteurs_et_depot, ou phase_2 quand elle ne cite que des it du démon de l'étape 4 ou des essais des composants de l'étape 5 ; celles qui citent test/adversarial.test.js y ont leur it, et chaque it du fichier correspond à une entrée exécutable qui le cite", function () {
    const exe = TA.filter((t) => t.status.state === "executable");
    expect(exe).to.have.length(80);
    // Révision 0.4 : essais du composant d'ancrage et de son branchement dans le démon (étape 5).
    const ETAPE_5 = /^test\/(ancrage-|enregistreur-ancrage-|enregistreur-journal-soi\.test\.js$)/;
    for (const t of exe) {
      const surDemon = (t.status.tests ?? []).length > 0 && t.status.tests.every((x) => (x.file === ADV && x.describe === DEMON_DESCRIBE) || ETAPE_5.test(x.file));
      expect(t.adversarial.execution, t.id).to.equal(surDemon ? "phase_2" : "vecteurs_et_depot");
    }
    const cites = new Set();
    for (const t of exe) for (const x of t.status.tests ?? []) if (x.file === ADV) { cites.add(t.id); expect(titres.cas.some((c) => c.it === x.it), `${t.id} : ${x.it}`).to.equal(true); }
    expect(cites.size).to.equal(75);
    // EX-10.3 : un TA- exécutable sans complément cite un it « (tué) », un oracle sur un vecteur (EX-10.4) ou une étape de CI.
    for (const t of exe) if (!t.status.complement) expect((t.status.tests ?? []).some((x) => x.file === ADV) || (t.status.ci_steps ?? []).length > 0, t.id).to.equal(true);
    for (const c of titres.cas) {
      const ids = c.it.split(" (MN-")[0].split(" et ");
      for (const id of ids) {
        const t = parId.get(id);
        expect(t, id).to.not.equal(undefined);
        expect(t.status.state, id).to.equal("executable");
        expect(t.status.tests.some((x) => x.file === ADV && x.it === c.it), `${id} ne cite pas « ${c.it} »`).to.equal(true);
      }
    }
    for (const t of TA) if (t.status.complement) expect(t.status.state, t.id).to.equal("executable");
  });

  it("les scénarios TA-99 à TA-103 composent des TA- à menace, leurs menaces et leurs identifiants couverts sont l'union de ceux des composés, et l'index TA- par menace les nomme", function () {
    const scenarios = TA.filter((t) => !t.adversarial.threat);
    expect(scenarios.map((s) => s.id)).to.deep.equal(["TA-99", "TA-100", "TA-101", "TA-102", "TA-103"]);
    const index = lire(CT9, "index-ta-par-menace.json").index;
    for (const s of scenarios) {
      expect(s.adversarial.composition.length).to.be.greaterThan(1);
      for (const id of s.adversarial.composition) { expect(parId.get(id)?.adversarial?.threat, `${s.id} compose ${id}`).to.be.a("string"); expect(index[parId.get(id).adversarial.threat].scenarios).to.include(s.id); }
      expect(s.threats).to.deep.equal([...new Set(s.adversarial.composition.flatMap((id) => parId.get(id).threats))]);
      expect(s.covers).to.deep.equal([...new Set(s.adversarial.composition.flatMap((id) => parId.get(id).covers))]);
      expect(s.adversarial.component).to.equal(null);
      expect(s.adversarial.threat_test_text).to.equal(null);
    }
    for (const t of TA.filter((x) => x.adversarial.threat)) expect(index[t.adversarial.threat]).to.deep.include({ test: t.id, state: t.status.state });
  });

  it("test/adversarial.test.js : le fichier n'écrit rien dans le dépôt (mutants sous NOORTRACE_TMP, détruits dans un after), copie scripts/lib, verify, conformite et registre, et paquets/enregistreur pour le démon (EX-10.5), et ne convertit aucune exception d'un mutant en écart (EX-10.6)", function () {
    const src = texte(R, ADV);
    const fabrique = texte(R, "test/fixtures/enregistreur-adversarial/demon.mjs");
    expect(fabrique).to.include('for (const d of ["src", "bin", "schemas"])');
    expect(fabrique).to.include('fs.symlinkSync(path.join(RACINE, "node_modules"), path.join(racine, "node_modules"))');
    expect(fabrique).to.include("process.env.NOORTRACE_TMP ?? os.tmpdir()");
    expect(src).to.include("detruireMutants?.();");
    expect(src).to.include('process.env.NOORTRACE_TMP ?? os.tmpdir()');
    expect(src).to.include('process.env.NOORTRACE_RACINE ??');
    expect(src).to.match(/after\(function \(\) \{\s*for \(const r of MUTANTS\) fs\.rmSync\(r, \{ recursive: true, force: true \}\);/);
    expect(src).to.include('for (const d of ["lib", "verify", "conformite", "registre"])');
    expect(src).to.not.match(/catch \(err\) \{\s*(return \[`exception|ecarts = \[\{ exception)/);
    expect(src).to.not.match(/fs\.writeFileSync\(path\.join\(RACINE/);
  });
});

// ---------------------------------------------------------------------------
describe("CT-9 : mesures TM- (section 11, EX-11.14, EX-11.16, annexe A.7, EX-A.9, EX-A.14)", function () {
  this.timeout(120_000);
  const TM = CATALOGUE.tests.filter((t) => t.level === "TM");
  const INV = P.inventaire(R);
  const COMPARAISONS = ["au_plus", "strictement_inferieur", "au_moins", "p50_au_plus", "p95_au_plus", "p99_au_plus", "p50_et_p99_au_plus", "somme_au_plus", "egalite", "aucune_cible"];

  it("chaque entrée TM- : measured null, result_name unique, cible présente sauf aucune_cible, comparaison admise, source définie dans sa spécification (identifiant ou section)", function () {
    expect(TM).to.have.length(44);
    expect(new Set(TM.map((t) => t.measure.result_name)).size).to.equal(TM.length);
    for (const t of TM) {
      const m = t.measure;
      expect(m.measured, t.id).to.equal(null);
      expect(COMPARAISONS, t.id).to.include(m.comparison);
      if (m.comparison === "aucune_cible") expect(m.target, t.id).to.equal(null); else expect(m.target, t.id).to.not.equal(null);
      const src = /^(CT-[1-8]) (§(.+)|(.+))$/.exec(m.source);
      expect(src, `${t.id} source ${m.source}`).to.not.equal(null);
      if (src[3]) expect(INV[src[1]].sections.has(src[3]), `${t.id} : section ${m.source} inconnue`).to.equal(true);
      else expect(INV[src[1]].ids.has(src[4]), `${t.id} : identifiant ${m.source} inconnu`).to.equal(true);
      expect(m.failure_threshold.length, t.id).to.be.greaterThan(0);
      expect(m.percentiles, t.id).to.be.an("array");
    }
    // EX-11.16 : seize entrées exécutables, résultat dans le rapport sur les
    // vecteurs, dans les rapports de campagne de TM-31 (étape 3), de TM-16
    // (étape 4) et de l'étape 5, et dans les tests cités.
    expect(TM.filter((t) => t.status.state === "executable").map((t) => t.id)).to.deep.equal(["TM-6", "TM-10", "TM-11", "TM-12", "TM-13", "TM-14", "TM-15", "TM-16", "TM-17", "TM-18", "TM-19", "TM-20", "TM-30", "TM-31", "TM-41", "TM-42"]);
    // EX-11.14 : TM-22 a pour cible 450 min et un seuil d'échec à 480 min ;
    // les sources en « moins de » (TM-25, TM-35, TM-43) emploient
    // strictement_inferieur.
    const tm22 = parId.get("TM-22");
    expect(tm22.measure.target).to.equal(450);
    expect(tm22.measure.failure_threshold).to.match(/480/);
    for (const id of ["TM-25", "TM-35", "TM-43"]) expect(parId.get(id).measure.comparison, id).to.equal("strictement_inferieur");
    expect(parId.get("TM-43").measure).to.include({ warmup: 3, repetitions: 10, method: "releve" });
    // EX-10.10 : les bornes chiffrées nommées mesurent par des TM- existants.
    for (const r of CATALOGUE.accepted_risks) for (const id of r.measured_by ?? []) expect(parId.get(id)?.level, `${r.id} measured_by ${id}`).to.equal("TM");
    for (const id of ["RA-15", "RA-55", "RA-66"]) expect(CATALOGUE.accepted_risks.find((r) => r.id === id).measured_by?.length, id).to.be.greaterThan(0);
  });

  it("les deux rapports publiés et le gabarit valident ; les onze cas de mesures/cas/ et les six de consignations/cas/ rendent leur attendu ; scripts/tests/mesures.mjs rend 0", function () {
    const casM = lire(CT9, "mesures", "cas", "cas.json");
    const casC = lire(CT9, "consignations", "cas", "cas.json");
    expect(casM.cases).to.have.length(11);
    expect(casC.cases).to.have.length(6);
    expect(casM.cases.map((c) => c.file.replace(".json", ""))).to.deep.equal(["valide-vide", "valide-vecteurs", "invalide-met-sans-valeur", "invalide-compte-hors-reference", "invalide-fsync-desactive-compte", "invalide-disque-memoire-compte", "invalide-met-sans-compter", "invalide-unite-inconnue", "invalide-percentile-autre-methode", "invalide-machine-incomplete", "invalide-test-id-autre-famille"]);
    expect(casC.cases.map((c) => c.file.replace(".json", ""))).to.deep.equal(["valide-gabarit", "invalide-reussi-element-absent", "invalide-reussi-disqualifiant", "invalide-juge-non-independant", "invalide-nom-de-personne", "invalide-sans-materiel"]);
    for (const [fam, cas] of [["mesures", casM], ["consignations", casC]]) {
      for (const c of cas.cases) {
        const e = valider(lire(CT9, fam, "cas", c.file), c.def);
        expect(e.length ? "invalid" : "valid", `${fam}/cas/${c.file}`).to.equal(c.expected);
      }
      expect(fs.readdirSync(path.join(CT9, fam, "cas")).filter((f) => f !== "cas.json").sort()).to.deep.equal(cas.cases.map((c) => c.file).sort());
    }
    for (const f of ["rapport-2026-11-01-vide.json", "rapport-2026-11-01-vecteurs.json"]) expect(valider(lire(CT9, "mesures", f), "rapport_mesure"), f).to.deep.equal([]);
    expect(valider(lire(CT9, "consignations", "gabarit-TR-10.json"), "consignation_rejeu")).to.deep.equal([]);
    const r = mesures([]);
    expect(r.code, r.texte).to.equal(0);
    expect(r.rapport.checks.filter((c) => c.status === "echec")).to.deep.equal([]);
    expect(verifierFamilles(R).errors).to.deep.equal([]);
  });

  it("le rapport sur les vecteurs égale un recalcul en mémoire : tailles de ligne du segment (saut de ligne compris), SHA-256, moyenne, min, max ; ligne de l'annexe A de 2465 octets ; le rapport vide porte les cibles des TM-", function () {
    const rv = lire(CT9, "mesures", "rapport-2026-11-01-vecteurs.json");
    const segment = fs.readFileSync(path.join(R, "spec", "vecteurs", "ct-2", "evenements", "journal-demo", "segment.ndjson"));
    const tailles = segment.toString("utf8").split("\n").filter((l) => l.length).map((l) => Buffer.byteLength(l) + 1);
    const l1 = rv.results.find((x) => x.name === "octets_par_evenement");
    expect(l1.samples).to.deep.equal(tailles);
    expect(l1.n).to.equal(tailles.length);
    expect(l1.min).to.equal(Math.min(...tailles));
    expect(l1.max).to.equal(Math.max(...tailles));
    expect(l1.mean).to.equal(Math.round((tailles.reduce((a, b) => a + b, 0) / tailles.length) * 100) / 100);
    expect(l1.conditions[1]).to.equal(`SHA-256 du segment : ${P.sha256(segment)}`);
    const l2 = rv.results.find((x) => x.name === "octets_ligne_annexe_a");
    expect(l2.value).to.equal(2465);
    expect(l2.samples).to.deep.equal([2465]);
    // TM-10 : délais événement → premier point qui l'engage, recalculés depuis ct-1 (saut par point de 60 s : maximum sous 61 s).
    const l3 = rv.results.find((x) => x.name === "p1_cadence_vecteurs");
    const cadence = delaisPoints(R);
    expect(l3.samples).to.deep.equal(cadence.delais);
    expect(l3.max).to.equal(cadence.max);
    expect(l3.n).to.equal(cadence.delais.length);
    expect(cadence.max).to.be.at.most(61);
    expect(l3.max).to.equal(56.583);
    // EX-11.11 : une ligne supplémentaire d'une entrée TM- porte un nom distinct de tout result_name du catalogue.
    const resultNames = new Set(CATALOGUE.tests.filter((t) => t.level === "TM").map((t) => t.measure.result_name));
    for (const l of rv.results) if (l.name !== parId.get(l.test_id).measure.result_name) expect(resultNames.has(l.name), l.name).to.equal(false);
    expect(rv.counts_for_targets).to.equal(false);
    expect(rv.system.reference).to.equal(false);
    for (const l of rv.results) { expect(l.met, l.name).to.equal(null); expect(l.excluded_reason, l.name).to.equal("vecteurs_seulement"); expect(parId.get(l.test_id)?.level, l.name).to.equal("TM"); }
    const rvide = lire(CT9, "mesures", "rapport-2026-11-01-vide.json");
    expect(rvide.counts_for_targets).to.equal(true);
    for (const l of rvide.results) {
      const t = parId.get(l.test_id);
      expect(l.name, l.test_id).to.equal(t.measure.result_name);
      expect(l.target, l.test_id).to.deep.equal(t.measure.target);
      for (const k of ["n", "value", "p50", "p95", "p99", "min", "max", "mean", "text_value", "met"]) expect(l[k], `${l.name}.${k}`).to.equal(null);
    }
    // Le rapport imprimé en 11.3 est celui du fichier, membres samples omis.
    const bloc = /```json\n(\{\n  "version": 0,\n  "kind": "rapport-mesure",[\s\S]*?)\n```/.exec(TEXTE.slice(TEXTE.indexOf("### 11.3")));
    const imprime = JSON.parse(bloc[1]);
    expect(imprime.system).to.deep.equal(rv.system);
    expect(imprime.method).to.deep.equal(rv.method);
    expect({ ...imprime.results[0], samples: null }).to.deep.equal({ ...rv.results[0], samples: null });
  });

  it("EX-11.15 : la comparaison d'une campagne à la référence signale p50 ou p99 au-delà de 1,2 fois, un débit sous 0,9 fois et met vrai devenu faux, et l'outil rend 1 ; une campagne égale rend 0", function () {
    const d = tmp("campagne");
    const base = lire(CT9, "mesures", "rapport-2026-11-01-vide.json");
    const ref = structuredClone(base);
    ref.results[0] = { ...ref.results[0], n: 20000, p50: 2, p95: 10, p99: 20, min: 1, max: 40, mean: 3, met: true };
    ref.results[2] = { ...ref.results[2], n: 100, value: 800, met: true };
    const camp = structuredClone(ref);
    camp.results[0] = { ...camp.results[0], p99: 25, met: false };
    camp.results[2] = { ...camp.results[2], value: 700 };
    camp.results.pop();
    const cmp = comparerCampagne(ref, camp);
    expect(cmp.regressions).to.deep.equal(["latence_appel_relaye : p99 25 > 1.2 × 20", "latence_appel_relaye : met vrai dans la référence, faux dans la campagne", "debit : value 700 < 0.9 × 800"]);
    expect(cmp.gaps).to.deep.equal(["reprise (TM-8) : ligne de la référence absente de la campagne"]);
    fs.writeFileSync(path.join(d, "reference.json"), JSON.stringify(ref, null, 2) + "\n");
    fs.writeFileSync(path.join(d, "campagne.json"), JSON.stringify(camp, null, 2) + "\n");
    const r = mesures(["--reference", path.join(d, "reference.json"), "--campagne", path.join(d, "campagne.json")]);
    expect(r.code).to.equal(1);
    expect(r.rapport.comparison.regressions).to.have.length(3);
    expect(mesures(["--reference", path.join(d, "reference.json"), "--campagne", path.join(d, "reference.json")]).code).to.equal(0);
    expect(comparerCampagne(base, base).errors).to.deep.equal([]);
    expect(comparerCampagne(lire(CT9, "mesures", "rapport-2026-11-01-vecteurs.json"), base).errors.length).to.be.greaterThan(0);
    expect(mesures(["--reference", path.join(d, "reference.json")]).code).to.equal(2);
    expect(mesures(["--racine", path.join(d, "nulle-part")]).code).to.equal(2);
  });
});

// ---------------------------------------------------------------------------
// Révision 0.4 : campagne de mesures de l'étape 5 (composant d'ancrage). Le
// rapport est écrit par l'ingénieur de la campagne (EX-11.11), jamais par le
// générateur ; tant qu'il n'est pas publié, ce cas échoue en le nommant.
describe("CT-9 : rapport de la campagne de mesures de l'étape 5 (composant d'ancrage ; TM-11 à TM-14, TM-17 à TM-19, TM-30, TM-41, TM-42 ; EX-11.11, EX-11.16)", function () {
  this.timeout(120_000);
  const RAPPORT = "rapport-2026-11-10-ancrage.json";
  const ENTREES = ["TM-11", "TM-12", "TM-13", "TM-14", "TM-17", "TM-18", "TM-19", "TM-30", "TM-41", "TM-42"];

  it("mesures/rapport-2026-11-10-ancrage.json, écrit par scripts/e2e/mesure-ancrage.mjs : conforme à rapport_mesure et accepté par scripts/tests/mesures.mjs ; pour chaque entrée, la ligne de son result_name, à l'unité du catalogue, avec sa valeur et son effectif ; lignes supplémentaires nommées par la table de 11.3 ; met null hors du système de référence", function () {
    for (const id of ENTREES) expect(parId.get(id).status.tests.some((x) => x.file === "test/plan-de-tests.test.js" && x.it === this.test.title), `${id} ne cite pas ce cas`).to.equal(true);
    const chemin = path.join(CT9, "mesures", RAPPORT);
    expect(fs.existsSync(chemin), `mesures/${RAPPORT} non publié : la campagne de l'étape 5 (scripts/e2e/mesure-ancrage.mjs collecter, complements, rapport) n'a pas encore écrit son rapport`).to.equal(true);
    const r = lire(chemin);
    expect(valider(r, "rapport_mesure")).to.deep.equal([]);
    expect(verifierFamilles(R).errors).to.deep.equal([]);
    const s113 = TEXTE.slice(TEXTE.indexOf("### 11.3 "), TEXTE.indexOf("### 11.4 "));
    const nommees = new Map([...s113.matchAll(/^\| `([a-z0-9_]+)` \| (TM-[0-9]+) \|/gm)].map((m) => [m[1], m[2]]));
    for (const l of r.results) {
      const t = parId.get(l.test_id);
      expect(t?.level, l.name).to.equal("TM");
      expect(l.unit, l.name).to.equal(t.measure.unit);
      if (l.name !== t.measure.result_name) expect(nommees.get(l.name), `${l.name} : ligne supplémentaire non nommée par la table de 11.3`).to.equal(l.test_id);
      if (!r.counts_for_targets || !r.system.reference) expect(l.met, l.name).to.equal(null);
    }
    for (const id of ENTREES) {
      const t = parId.get(id);
      const l = r.results.find((x) => x.name === t.measure.result_name);
      expect(l, `${id} : ligne ${t.measure.result_name} absente`).to.not.equal(undefined);
      expect(l.test_id, l.name).to.equal(id);
      expect(l.n, `${l.name} : effectif`).to.be.a("number").and.to.be.at.least(1);
      expect([l.value, l.max, l.text_value].some((v) => v !== null), `${l.name} : aucune valeur`).to.equal(true);
    }
    // Section 14, ligne 6 : w_date_porte_2 et w_ordre dans le même rapport ; w_date_defaut publiée à côté (11.6).
    for (const n of ["w_date_porte_2", "w_ordre", "w_date_defaut"]) expect(r.results.some((l) => l.name === n), n).to.equal(true);
  });
});

// ---------------------------------------------------------------------------
// Révision 0.6 : mesure de d_admission (CT-5 révision 0.6, EX-3.5), deux
// campagnes du 2026-11-10 ; rapports écrits par l'ingénieur de la campagne.
describe("CT-9 : rapports de la mesure de d_admission (TM-13 ; CT-5 EX-3.5, révisions 0.6 et 0.7 ; EX-11.11, EX-11.16)", function () {
  this.timeout(120_000);
  const RAPPORTS = ["rapport-2026-11-10-admission-1.json", "rapport-2026-11-10-admission-2.json"];

  it("mesures/rapport-2026-11-10-admission-1.json et -2.json : conformes à rapport_mesure et acceptés par scripts/tests/mesures.mjs ; ligne p3_d_admission en secondes, un échantillon par échéance satisfaite de la configuration par défaut ; le dépassement de la première campagne est écrit dans ses notes, la seconde n'a aucun échantillon au-delà de 10 s", function () {
    expect(parId.get("TM-13").status.tests.some((x) => x.file === "test/plan-de-tests.test.js" && x.it === this.test.title), "TM-13 ne cite pas ce cas").to.equal(true);
    expect(verifierFamilles(R).errors).to.deep.equal([]);
    const lus = RAPPORTS.map((f) => {
      const chemin = path.join(CT9, "mesures", f);
      expect(fs.existsSync(chemin), `mesures/${f} non publié`).to.equal(true);
      const r = lire(chemin);
      expect(valider(r, "rapport_mesure"), f).to.deep.equal([]);
      const l = r.results.find((x) => x.name === "p3_d_admission");
      expect(l, `${f} : ligne p3_d_admission absente`).to.not.equal(undefined);
      expect(l.test_id, f).to.equal("TM-13");
      expect(l.unit, f).to.equal("s");
      expect(l.samples, f).to.have.length(l.n);
      expect(l.n, f).to.be.at.least(1);
      for (const x of r.results) if (!r.counts_for_targets || !r.system.reference) expect(x.met, `${f} ${x.name}`).to.equal(null);
      return { f, r, l };
    });
    const [premiere, seconde] = lus;
    expect(premiere.r.notes).to.match(/Dépassement de d_admission \(porte2\) : un seul point sur 59/);
    expect(premiere.r.notes).to.match(/suspendus ensemble/);
    expect(Math.max(...seconde.l.samples)).to.be.at.most(10);
    expect(seconde.r.notes).to.match(/defaut : arbre de travail propre ; porte2 : arbre de travail propre/);
    expect(seconde.r.notes).to.match(/TM-13 \(porte2\) : 59 échéances satisfaites ; .*d_admission p50 0 s, p99 0 s, max 0 s/);
  });
});

// ---------------------------------------------------------------------------
describe("CT-9 : rejeu à l'aveugle TR- (section 12, EX-12.2, EX-12.7, section 15, annexe A.8, A.9, EX-A.9, EX-A.15, EX-A.16)", function () {
  const TR = CATALOGUE.tests.filter((t) => t.level === "TR");
  const GRILLES_CT9 = { "TR-4": "acceptation-ancrage-attendu.json", "TR-5": "acceptation-verdict-point-attendu.json", "TR-14": "acceptation-porte-2-attendu.json" };

  it("chaque TR- : grid égal à un fichier existant ou null, a_ecrire à l'étape 8 ; les grilles de ct-9 valident contre grille_acceptation et portent le test_id de leur entrée", function () {
    expect(TR).to.have.length(15);
    for (const t of TR) {
      expect(t.status.state, t.id).to.equal("a_ecrire");
      expect(t.status.phase2_step, t.id).to.equal(8);
      if (t.replay.grid !== null) expect(fs.existsSync(path.join(R, t.replay.grid)), `${t.id} : ${t.replay.grid}`).to.equal(true);
      else expect(["TR-3", "TR-12", "TR-15"], t.id).to.include(t.id);
      expect(t.replay.material.length, t.id).to.be.greaterThan(0);
      expect(t.replay.forbidden_sections.length, t.id).to.be.greaterThan(0);
      // EX-12.3 : la grille est interdite au participant ; exceptions écrites :
      // TR-10 (grille = cas.json, le paquet est tiré au sort parmi ses cas) et
      // TR-13 (l'entrée du catalogue est à la fois matériel et grille).
      if (t.replay.grid && t.id !== "TR-13" && t.replay.grid !== "spec/vecteurs/ct-8/paquets/cas.json") expect(t.replay.forbidden_sections.includes(t.replay.grid), `${t.id} : la grille n'est pas interdite`).to.equal(true);
      if (t.id === "TR-13") { expect(t.replay.material).to.include(t.replay.grid); expect(t.replay.verdict_rule).to.match(/sans entrée concrète ni comparaison exécutable échoue/); expect(TEXTE).to.match(/TR-13[\s\S]{0,200}?à\s+la fois matériel et grille/); }
    }
    for (const [id, f] of Object.entries(GRILLES_CT9)) {
      expect(parId.get(id).replay.grid).to.equal(`spec/vecteurs/ct-9/${f}`);
      const g = lire(CT9, f);
      expect(valider(g, "grille_acceptation"), f).to.deep.equal([]);
      expect(g.test_id).to.equal(id);
    }
    expect(parId.get("TR-13").replay.grid).to.equal("spec/vecteurs/ct-9/catalogue.json");
  });

  it("aucune consigne remise ne contient un élément de sa grille ; chaque consigne et chaque extrait nommés par material existent", function () {
    const consignes = { "TR-4": "acceptation-ancrage/consigne.md", "TR-5": "acceptation-verdict-point/consigne.md", "TR-13": "acceptation-plan/consigne.md", "TR-14": "acceptation-porte-2/consigne.md", "TR-15": "acceptation-plan/consigne.md" };
    for (const [id, c] of Object.entries(consignes)) {
      const t = parId.get(id);
      expect(t.replay.material.some((m) => m.includes(`spec/vecteurs/ct-9/${c}`)), `${id} : material ne nomme pas ${c}`).to.equal(true);
      const tc = texte(CT9, c);
      expect(tc).to.include(`Consigne de l'épreuve ${id === "TR-13" || id === "TR-15" ? "TR-13 et TR-15" : id} de CT-9`);
      let code = false;
      for (const l of tc.split("\n")) { if (l.startsWith("```")) code = !code; if (!code && !l.startsWith("|")) expect(l.length, `${c} : ${l}`).to.be.at.most(80); }
      if (!GRILLES_CT9[id]) continue;
      const g = lire(CT9, GRILLES_CT9[id]);
      for (const q of g.questions) for (const e of q.elements) expect(tc.includes(e.element), `${c} contient l'élément « ${e.element} »`).to.equal(false);
      for (const s of g.disqualifying) expect(tc.includes(s), `${c} contient « ${s} »`).to.equal(false);
      expect(g.questions.length, id).to.be.greaterThan(0);
    }
    for (const t of TR) for (const m of t.replay.material) for (const f of m.match(/spec\/vecteurs\/[a-z0-9./_-]+/g) ?? []) if (!f.includes("<") && !/\/$/.test(f) && !/^spec\/vecteurs\/ct-9\/consignations/.test(f)) expect(fs.existsSync(path.join(R, f)) || fs.existsSync(path.join(R, f.replace(/\/[^/]*$/, ""))), `${t.id} : ${f}`).to.equal(true);
    expect(texte(CT9, "acceptation-verdict-point/consigne.md")).to.include(DOSSIER_TR5);
    expect(fs.existsSync(path.join(R, DOSSIER_TR5, "points-de-controle.json"))).to.equal(true);
  });

  it("les extraits remis égalent le texte des spécifications du dépôt découpé par sections (hors blocs de code), sans la section ni l'annexe retirées, et SHA256SUMS porte leurs condensés", function () {
    const attendus = construireExtraits(R);
    for (const [n, t] of Object.entries(attendus)) expect(texte(CT9, "extraits", n), n).to.equal(t);
    expect(fs.readdirSync(path.join(CT9, "extraits")).sort()).to.deep.equal(Object.keys(attendus).sort());
    const ct7 = texte(R, "spec", "CT-7-securite-et-conformite.md");
    const ct8 = texte(R, "spec", "CT-8-deploiement-et-exploitation.md");
    const sans9 = texte(CT9, "extraits", "CT-7-sans-9-A15.md");
    expect(sans9).to.not.match(/^## 9\. /m);
    expect(sans9).to.not.match(/^### A\.15 /m);
    expect(sans9).to.match(/^### A\.14 /m);
    expect(sans9).to.match(/^### A\.16 /m);
    expect(sans9).to.match(/^## 10\. /m);
    expect(extraire(ct7, { garder: ["7"] })).to.equal(ct7.slice(ct7.indexOf("\n## 7. ") + 1, ct7.indexOf("\n## 8. ")));
    expect(texte(CT9, "extraits", "CT-8-13.md")).to.equal(ct8.slice(ct8.indexOf("\n## 13. ") + 1, ct8.indexOf("\n## 14. ")));
    expect(texte(CT9, "extraits", "CT-8-sans-14-A.md")).to.not.match(/^## (14\. |Annexe A)/m);
    expect(texte(CT9, "extraits", "CT-8-sans-14-A.md")).to.match(/^## Annexe B/m);
    expect(texte(CT9, "extraits", "CT-9-sans-15.md")).to.not.match(/^## 15\. /m);
    expect(texte(CT9, "extraits", "CT-9-sans-15.md")).to.match(/^## 16\. /m);
    for (const l of texte(CT9, "extraits", "SHA256SUMS").trimEnd().split("\n")) {
      const [h, n] = l.split("  ");
      expect(P.sha256Fichier(path.join(CT9, "extraits", n)), n).to.equal(h);
    }
    for (const [n, trs] of Object.entries(EXTRAITS_PAR_EPREUVE)) for (const id of trs) expect(parId.get(id), `${n} ${id}`).to.not.equal(undefined);
  });

  it("la grille de la porte 2 est celle que donnent la section 14 du texte et la table des niveaux ; chaque identifiant cité par les tables de la section 14 existe dans le catalogue", function () {
    expect(lire(CT9, "acceptation-porte-2-attendu.json")).to.deep.equal(grillePorte2(TEXTE, CATALOGUE));
    const s14 = TEXTE.slice(TEXTE.indexOf("\n## 14. "), TEXTE.indexOf("\n## 15. "));
    const lignes = s14.split("\n").filter((l) => l.startsWith("|") && !/^\|---/.test(l) && !/^\| Critère/.test(l));
    expect(lignes).to.have.length(10 + 4);
    const ids = [...s14.matchAll(/\b(TU|TV|TI|TE|TA|TM|TR|TQ)-[0-9]+\b/g)].map((m) => m[0]);
    expect(ids.length).to.be.greaterThan(30);
    for (const id of ids) expect(parId.get(id), `section 14 cite ${id}`).to.not.equal(undefined);
    const g = lire(CT9, "acceptation-porte-2-attendu.json");
    expect(g.questions[0].elements).to.have.length(10);
    expect(g.questions[1].elements).to.have.length(6);
    expect(g.questions[2].elements.map((e) => e.element.split(" ")[0])).to.deep.equal(P.NIVEAUX.map((n) => `${n}-`));
  });

  it("EX-15.5 : aucune épreuve conduite en version 0.1 ; les seules consignations publiées sont le gabarit et ses cas", function () {
    const publiees = fs.readdirSync(path.join(CT9, "consignations")).filter((f) => f.endsWith(".json"));
    expect(publiees).to.deep.equal(["gabarit-TR-10.json"]);
    expect(TEXTE).to.include("Aucune n'a été conduite pour cette\nversion.");
    for (const t of TR) expect(t.replay.participant, t.id).to.not.match(/[A-Z][a-z]+ [A-Z][a-z]+$/);
  });
});

// ---------------------------------------------------------------------------
describe("CT-9 : confrontation tierce et vérificateur Go indépendant (annexe A.10, A.11, EX-A.17, EX-A.18)", function () {
  this.timeout(600_000);
  const CONF = path.join(CT9, "confrontation");
  const GO = path.join(CT9, "verificateur-independant");

  it("recompter.py (python3 -I, bibliothèque standard) rend 0 sur le dépôt et sa sortie égale la sortie publiée confrontation/sorties/recompte.txt", function () {
    const python = spawnSync("python3", ["--version"], { encoding: "utf8" });
    if (python.error || python.status !== 0) this.skip();
    const r = spawnSync("python3", ["-I", path.join(CONF, "recompter.py"), R], { encoding: "utf8", cwd: R, maxBuffer: 64 * 1024 * 1024 });
    expect(r.status, r.stderr + r.stdout).to.equal(0);
    expect(r.stdout).to.equal(texte(CONF, "sorties", "recompte.txt"));
    expect(r.stdout).to.match(/0 discordance/);
    expect(texte(CONF, "LISEZMOI.md")).to.include("python3 -I");
  });

  it("parité JS/Go du condensé D_P (CT-7 EX-A.21) : scripts/conformite/attestation.mjs condenser et go run . condenser du module ct-7 rendent la même première ligne sur l'exemple de ct-7/attestations, égale à condense.json (en attente sans go)", function () {
    const go = spawnSync("go", ["version"], { encoding: "utf8" });
    if (go.error || go.status !== 0) this.skip();
    const fichier = path.join(R, "spec", "vecteurs", "ct-7", "attestations", "exemple", "attestation.json");
    const attendu = lire(R, "spec", "vecteurs", "ct-7", "attestations", "exemple", "condense.json");
    const premiere = (r) => r.stdout.trim().split("\n")[0];
    const rGo = spawnSync("go", ["run", ".", "condenser", fichier], { encoding: "utf8", cwd: path.join(R, "spec", "vecteurs", "ct-7", "verificateur-independant"), env: { ...process.env, GOFLAGS: "-mod=mod" } });
    expect(rGo.status, rGo.stderr).to.equal(0);
    const rJs = spawnSync(process.execPath, [path.join(R, "scripts", "conformite", "attestation.mjs"), "condenser", fichier], { encoding: "utf8", cwd: R });
    expect(rJs.status, rJs.stderr).to.equal(0);
    expect(premiere(rJs)).to.equal(premiere(rGo));
    expect(JSON.stringify(attendu)).to.include(premiere(rGo));
  });

  it("le vérificateur Go rend « 0 discordance » et le code 0 sur le dépôt (gofmt, vet, test, run ; en attente sans go)", function () {
    const go = spawnSync("go", ["version"], { encoding: "utf8" });
    if (go.error || go.status !== 0) this.skip();
    const env = { ...process.env, GOFLAGS: "-mod=mod" };
    const fmt = spawnSync("gofmt", ["-l", "."], { encoding: "utf8", cwd: GO });
    expect(fmt.stdout.trim(), "gofmt").to.equal("");
    const vet = spawnSync("go", ["vet", "./..."], { encoding: "utf8", cwd: GO, env });
    expect(vet.status, vet.stderr).to.equal(0);
    const test = spawnSync("go", ["test", "./..."], { encoding: "utf8", cwd: GO, env, maxBuffer: 64 * 1024 * 1024 });
    expect(test.status, test.stderr + test.stdout).to.equal(0);
    const run = spawnSync("go", ["run", ".", ".."], { encoding: "utf8", cwd: GO, env, maxBuffer: 64 * 1024 * 1024 });
    expect(run.status, run.stderr + run.stdout).to.equal(0);
    expect(run.stdout).to.match(/0 discordance/);
    expect(fs.readFileSync(path.join(GO, "go.mod"), "utf8")).to.match(/^module noortrace-ct9\n\ngo 1\.24\n$/);
    expect(texte(GO, "README.md")).to.match(/ne recalcule pas/);
  });
});
