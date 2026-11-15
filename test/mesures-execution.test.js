// Tests du rapport d'exécution de CT-9 (spec/CT-9-plan-de-tests.md, annexe
// A.12, EX-A.19 ; section 14, EX-14.1) : scripts/tests/mesures.mjs
// --execution <fichier>.
//
// Ce fichier exige : qu'un rapport construit depuis le catalogue (un résultat
// par entrée executable) soit accepté ; que chaque règle EXE-1 à EXE-6 refuse
// le rapport qui la viole et lui seul, en nommant l'entrée fautive ; que la
// partie conditionnée d'une entrée qui porte status.depends_on (TA-26, TA-88)
// soit admise non_applicable avec sa proposition, et refusée ailleurs ; qu'un
// rapport publié sous executions/ soit lu par la commande sans option ; que
// les avertissements n'en changent pas le code ; que l'outil rende 2 sur un
// fichier illisible. Rien n'est écrit dans le dépôt : les rapports et la
// copie réduite du dépôt vont dans un répertoire temporaire détruit à la fin.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { executer as mesures, verifierExecution, verifierFamilles, EXECUTIONS } from "../scripts/tests/mesures.mjs";

const R = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CT9 = path.join(R, "spec", "vecteurs", "ct-9");
const SCHEMA = "spec/schemas/plan-de-tests-v0.schema.json";
const lire = (...p) => JSON.parse(fs.readFileSync(path.join(...p), "utf8"));
const CATALOGUE = lire(CT9, "catalogue.json");
const parId = new Map(CATALOGUE.tests.map((t) => [t.id, t]));
const EXECUTABLES = CATALOGUE.tests.filter((t) => t.status.state === "executable");
/** Commit du dépôt quand git le donne (l'outil avertit quand le rapport en
 * porte un autre), sinon un commit d'exemple : les essais passent aussi sur
 * une archive extraite. */
const AUTRE_COMMIT = "0123456789abcdef0123456789abcdef01234567";
const COMMIT = (() => {
  const g = spawnSync("git", ["-C", R, "rev-parse", "--show-toplevel", "HEAD"], { encoding: "utf8" });
  if (g.status !== 0 || g.error) return AUTRE_COMMIT;
  const [sommet, tete] = g.stdout.trim().split("\n");
  return sommet === fs.realpathSync(R) && /^[0-9a-f]{40}$/.test(tete ?? "") ? tete : AUTRE_COMMIT;
})();

const TMP = [];
const tmp = (nom) => { const d = fs.mkdtempSync(path.join(process.env.NOORTRACE_TMP ?? os.tmpdir(), `noortrace-execution-${nom}-`)); TMP.push(d); return d; };
after(function () { for (const d of TMP) fs.rmSync(d, { recursive: true, force: true }); });

/** Rapport conforme : un résultat reussi par entrée executable, avec la
 * commande que le catalogue cite. */
function rapportDeBase() {
  return {
    version: 0,
    kind: "rapport-execution",
    date: "2026-11-13",
    commit: COMMIT,
    environment: { os: "Ubuntu 24.04", node: "v22.22.0", go: null, python: null },
    results: EXECUTABLES.map((t) => ({ test_id: t.id, status: "reussi", command: t.status.command })),
  };
}
const ecrire = (rep, nom, valeur) => { const f = path.join(rep, nom); fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, typeof valeur === "string" ? valeur : JSON.stringify(valeur, null, 2) + "\n"); return f; };
/** Vérifications en échec d'un rapport, par identifiant. */
const echecs = (r) => r.checks.filter((c) => c.status === "echec").map((c) => c.id);
const verif = (rapport, rep, nom = "rapport-2026-11-13-essai.json") => verifierExecution(R, ecrire(rep, nom, rapport), { nom });
const detail = (r, id) => r.checks.find((c) => c.id === id)?.detail;

/** Copie réduite du dépôt : ce que la commande sans option lit (schéma,
 * catalogue, familles mesures/ et consignations/, grille du gabarit). */
function depotReduit() {
  const d = tmp("depot");
  for (const f of [SCHEMA, "spec/vecteurs/ct-9/catalogue.json", "spec/vecteurs/ct-8/paquets/cas.json"]) { fs.mkdirSync(path.dirname(path.join(d, f)), { recursive: true }); fs.copyFileSync(path.join(R, f), path.join(d, f)); }
  for (const fam of ["mesures", "consignations"]) fs.cpSync(path.join(CT9, fam), path.join(d, "spec", "vecteurs", "ct-9", fam), { recursive: true });
  return d;
}

describe("CT-9 : rapport d'exécution (annexe A.12, EX-A.19 ; section 14, EX-14.1) — scripts/tests/mesures.mjs --execution", function () {
  this.timeout(120_000);

  it("le catalogue porte les entrées que ces essais emploient : des entrées executable, TA-26 executable et TA-88 a_ecrire, seules à porter status.depends_on (PA-1, PA-10)", function () {
    expect(EXECUTABLES.length).to.be.greaterThan(0);
    expect(CATALOGUE.tests.filter((t) => t.status.depends_on).map((t) => [t.id, t.status.state, t.status.depends_on])).to.deep.equal([["TA-26", "executable", ["PA-1"]], ["TA-88", "a_ecrire", ["PA-10"]]]);
    expect(parId.get("TU-1").status.state).to.equal("executable");
    expect(parId.get("TR-1").status.state).to.equal("a_ecrire");
    expect(parId.has("TU-9999")).to.equal(false);
  });

  it("EX-A.19 : un rapport qui porte un résultat par entrée executable est accepté (EXE-1 à EXE-5 réussies, code 0) ; l'outil imprime le compte des statuts", function () {
    const d = tmp("base");
    const f = ecrire(d, "rapport-2026-11-13-essai.json", rapportDeBase());
    const v = verifierExecution(R, f, { nom: "essai" });
    expect(v.errors).to.deep.equal([]);
    expect(v.checks.map((c) => [c.id, c.status, c.file])).to.deep.equal(["EXE-1", "EXE-2", "EXE-3", "EXE-4", "EXE-5"].map((id) => [id, "reussi", "essai"]));
    expect(detail(v, "EXE-3")).to.equal(`les ${EXECUTABLES.length} entrées executable ont leur résultat`);
    expect(v.warnings).to.deep.equal([]);
    const r = mesures(["--execution", f]);
    expect(r.code, r.texte).to.equal(0);
    expect(r.rapport.verdict).to.equal("reussi");
    expect(r.rapport.execution).to.deep.equal({ report: f, counts: { reussi: EXECUTABLES.length } });
    expect(r.texte).to.include(`rapport d'exécution ${f} : ${EXECUTABLES.length} reussi, 0 echec, 0 en_attente, 0 non_applicable`);
    // Les familles publiées restent vérifiées avec le rapport désigné.
    expect(r.rapport.checks.filter((c) => /^(MES|CSG|CAS)-/.test(c.id)).length).to.equal(verifierFamilles(R).checks.length);
    // Sans --execution, aucune vérification EXE- tant que rien n'est publié sous executions/.
    if (!fs.existsSync(path.join(R, EXECUTIONS))) expect(mesures([]).rapport.checks.filter((c) => c.id.startsWith("EXE-"))).to.deep.equal([]);
  });

  it("EXE-1 : un rapport hors de la forme rapport_execution est refusé, et les règles suivantes ne sont pas jouées (membre absent, statut hors de l'énumération, membre de trop, commit qui n'a pas 40 chiffres hexadécimaux, kind d'une autre famille)", function () {
    const d = tmp("forme");
    const cas = {
      "sans-python": (r) => { delete r.environment.python; },
      "statut-inconnu": (r) => { r.results[0].status = "passe"; },
      "membre-de-trop": (r) => { r.results[0].duree_ms = 12; },
      "commit-court": (r) => { r.commit = "cd1d193"; },
      "autre-famille": (r) => { r.kind = "rapport-mesure"; },
      "sans-commande": (r) => { delete r.results[0].command; },
      "condense-court": (r) => { r.results[0].output_sha256 = "abc"; },
    };
    for (const [nom, alterer] of Object.entries(cas)) {
      const r = rapportDeBase();
      alterer(r);
      const v = verif(r, d, `rapport-2026-11-13-${nom}.json`);
      expect(v.checks.map((c) => [c.id, c.status]), nom).to.deep.equal([["EXE-1", "echec"]]);
      expect(v.errors, nom).to.have.length(1);
      expect(mesures(["--execution", path.join(d, `rapport-2026-11-13-${nom}.json`)]).code, nom).to.equal(1);
    }
  });

  it("EXE-2 : un test_id inconnu du catalogue est refusé et nommé ; les autres règles restent jouées", function () {
    const d = tmp("inconnu");
    const r = rapportDeBase();
    r.results.push({ test_id: "TU-9999", status: "reussi", command: "npm test" });
    const v = verif(r, d);
    expect(echecs(v)).to.deep.equal(["EXE-2"]);
    expect(detail(v, "EXE-2")).to.equal("test_id inconnu(s) du catalogue : TU-9999");
    expect(v.checks.map((c) => c.id)).to.deep.equal(["EXE-1", "EXE-2", "EXE-3", "EXE-4", "EXE-5"]);
    expect(mesures(["--execution", path.join(d, "rapport-2026-11-13-essai.json")]).code).to.equal(1);
  });

  it("EXE-3 : une entrée executable sans résultat est refusée et nommée ; un résultat non_applicable ne tient pas lieu de la partie exécutée de TA-26 ; une entrée a_ecrire absente ne manque pas", function () {
    const d = tmp("absent");
    const sans = rapportDeBase();
    const retiree = sans.results.splice(3, 1)[0].test_id;
    let v = verif(sans, d);
    expect(echecs(v)).to.deep.equal(["EXE-3"]);
    expect(detail(v, "EXE-3")).to.equal(`1 entrée(s) executable sans résultat de leur partie exécutée : ${retiree}`);
    const vide = rapportDeBase();
    vide.results = [];
    v = verif(vide, d);
    expect(echecs(v)).to.deep.equal(["EXE-3"]);
    expect(detail(v, "EXE-3")).to.match(new RegExp(`^${EXECUTABLES.length} entrée\\(s\\) executable sans résultat de leur partie exécutée : .* et ${EXECUTABLES.length - 12} autre\\(s\\)$`));
    const conditionne = rapportDeBase();
    Object.assign(conditionne.results.find((l) => l.test_id === "TA-26"), { status: "non_applicable", reason: "PA-1 non adoptée" });
    v = verif(conditionne, d);
    expect(echecs(v)).to.deep.equal(["EXE-3"]);
    expect(detail(v, "EXE-3")).to.equal("1 entrée(s) executable sans résultat de leur partie exécutée : TA-26");
    // Le rapport de base ne porte aucune entrée a_ecrire et il est accepté : EXE-3 ne les exige pas.
    expect(rapportDeBase().results.some((l) => parId.get(l.test_id).status.state === "a_ecrire")).to.equal(false);
  });

  it("EXE-4 : deux résultats pour une même entrée sont refusés ; TA-26 admet un second résultat non_applicable pour sa partie conditionnée par PA-1, et lui seul", function () {
    const d = tmp("double");
    const double = rapportDeBase();
    double.results.push({ ...double.results[0] });
    let v = verif(double, d);
    expect(echecs(v)).to.deep.equal(["EXE-4"]);
    expect(detail(v, "EXE-4")).to.include(`plus d'un résultat pour : ${double.results[0].test_id} (2)`);
    const admis = rapportDeBase();
    admis.results.push({ test_id: "TA-26", status: "non_applicable", command: parId.get("TA-26").status.command, reason: "Partie conditionnée : PA-1 non adoptée par CT-2." });
    v = verif(admis, d);
    expect(v.errors).to.deep.equal([]);
    expect(detail(v, "EXE-5")).to.equal("1 résultat(s) non_applicable, chacun avec sa proposition non adoptée");
    const deuxReussis = rapportDeBase();
    deuxReussis.results.push({ ...deuxReussis.results.find((l) => l.test_id === "TA-26") });
    expect(echecs(verif(deuxReussis, d))).to.deep.equal(["EXE-4"]);
    const trois = structuredClone(admis);
    trois.results.push({ test_id: "TA-26", status: "non_applicable", command: "npm test", reason: "PA-1 non adoptée" });
    v = verif(trois, d);
    expect(echecs(v)).to.deep.equal(["EXE-4"]);
    expect(detail(v, "EXE-4")).to.include("TA-26 (3)");
    // Une entrée sans status.depends_on n'a pas de partie conditionnée : son second résultat non_applicable est de trop (EXE-4) et mal fondé (EXE-5).
    const sansCondition = rapportDeBase();
    sansCondition.results.push({ test_id: "TU-1", status: "non_applicable", command: "npm test", reason: "PA-1 non adoptée" });
    v = verif(sansCondition, d);
    expect(echecs(v)).to.deep.equal(["EXE-4", "EXE-5"]);
    expect(detail(v, "EXE-4")).to.include("plus d'un résultat pour : TU-1 (2)");
    // Deux non_applicable seuls pour TA-88 : un de trop.
    const deuxNA = rapportDeBase();
    for (let i = 0; i < 2; i++) deuxNA.results.push({ test_id: "TA-88", status: "non_applicable", command: "aucune : PA-10 non adoptée", reason: "PA-10 non adoptée" });
    expect(echecs(verif(deuxNA, d))).to.deep.equal(["EXE-4"]);
  });

  it("EXE-5 : non_applicable n'est admis que pour une entrée qui porte status.depends_on, avec la proposition nommée dans reason (PA-10 pour TA-88, et non PA-1 ; PA-1 pour TA-26, et non PA-10)", function () {
    const d = tmp("na");
    const avec = (test_id, reason) => { const r = rapportDeBase(); r.results.push({ test_id, status: "non_applicable", command: "aucune commande : partie conditionnée", ...(reason === undefined ? {} : { reason }) }); return r; };
    expect(verif(avec("TA-88", "PA-10 non adoptée par CT-2 (RA-74 demeure)"), d).errors).to.deep.equal([]);
    expect(verif(avec("TA-26", "proposition PA-1, non adoptée"), d).errors).to.deep.equal([]);
    for (const [id, reason, attendu] of [
      ["TA-88", "PA-1 non adoptée", "TA-88 (reason ne nomme pas PA-10)"],
      ["TA-88", undefined, "TA-88 (reason ne nomme pas PA-10)"],
      ["TA-88", "", "TA-88 (reason ne nomme pas PA-10)"],
      ["TA-88", "CT-7 PA-100 et XPA-10", "TA-88 (reason ne nomme pas PA-10)"],
      ["TA-26", "PA-10 non adoptée", "TA-26 (reason ne nomme pas PA-1)"],
      ["TR-1", "épreuve non conduite", "TR-1 (aucun status.depends_on au catalogue)"],
    ]) {
      const v = verif(avec(id, reason), d);
      expect(echecs(v), `${id} ${reason}`).to.deep.equal(["EXE-5"]);
      expect(detail(v, "EXE-5"), `${id} ${reason}`).to.equal(`non_applicable mal fondé : ${attendu}`);
    }
    // Une entrée executable sans status.depends_on ne se dit pas non_applicable : EXE-3 et EXE-5 le refusent toutes deux.
    const r = rapportDeBase();
    Object.assign(r.results.find((l) => l.test_id === "TU-1"), { status: "non_applicable", reason: "PA-1" });
    expect(echecs(verif(r, d))).to.deep.equal(["EXE-3", "EXE-5"]);
  });

  it("EXE-6 et lecture sans option : un rapport publié sous executions/ est lu par la commande nue ; un nom hors de rapport-<AAAA-MM-JJ>-<etiquette>.json ou une date de nom différente du membre date sont refusés ; hors de executions/, le même défaut n'est qu'un avertissement", function () {
    const d = depotReduit();
    expect(mesures(["--racine", d]).code).to.equal(0);
    expect(mesures(["--racine", d]).rapport.checks.filter((c) => c.id.startsWith("EXE-"))).to.deep.equal([]);
    const publie = ecrire(d, `${EXECUTIONS}/rapport-2026-11-13-essai.json`, rapportDeBase());
    let r = mesures(["--racine", d]);
    expect(r.code, r.texte).to.equal(0);
    expect(r.rapport.checks.filter((c) => c.id.startsWith("EXE-")).map((c) => [c.id, c.status, c.file])).to.deep.equal(["EXE-1", "EXE-2", "EXE-3", "EXE-4", "EXE-5", "EXE-6"].map((id) => [id, "reussi", "executions/rapport-2026-11-13-essai.json"]));
    // Désigné par --execution, un rapport publié n'est pas lu deux fois.
    r = mesures(["--racine", d, "--execution", `${EXECUTIONS}/rapport-2026-11-13-essai.json`]);
    expect(r.code).to.equal(0);
    expect(r.rapport.checks.filter((c) => c.id === "EXE-1")).to.have.length(1);
    expect(r.rapport.execution.counts).to.deep.equal({ reussi: EXECUTABLES.length });
    // Un rapport publié fautif fait échouer la commande nue.
    const fautif = rapportDeBase();
    fautif.results.pop();
    ecrire(d, `${EXECUTIONS}/rapport-2026-11-13-essai.json`, fautif);
    r = mesures(["--racine", d]);
    expect(r.code).to.equal(1);
    expect(r.rapport.errors.filter((e) => e.startsWith("EXE-3 executions/rapport-2026-11-13-essai.json"))).to.have.length(1);
    fs.rmSync(publie);
    // Nom sans la forme, puis date du nom différente du membre date.
    ecrire(d, `${EXECUTIONS}/brouillon.json`, rapportDeBase());
    r = mesures(["--racine", d]);
    expect(r.code).to.equal(1);
    expect(r.rapport.checks.find((c) => c.id === "EXE-6")).to.deep.equal({ id: "EXE-6", file: "executions/brouillon.json", status: "echec", detail: "le nom brouillon.json n'a pas la forme rapport-<AAAA-MM-JJ>-<etiquette>.json" });
    fs.rmSync(path.join(d, EXECUTIONS, "brouillon.json"));
    ecrire(d, `${EXECUTIONS}/rapport-2026-11-12-essai.json`, rapportDeBase());
    r = mesures(["--racine", d]);
    expect(r.code).to.equal(1);
    expect(r.rapport.checks.find((c) => c.id === "EXE-6").detail).to.equal("la date du nom (2026-11-12) n'est pas le membre date (2026-11-13)");
    fs.rmSync(path.join(d, EXECUTIONS, "rapport-2026-11-12-essai.json"));
    for (const nom of ["rapport-2026-11-13-.json", "rapport-2026-11-13-Essai.json", "rapport-2026-11-13.json", "Rapport-2026-11-13-essai.json"]) {
      ecrire(d, `${EXECUTIONS}/${nom}`, rapportDeBase());
      expect(mesures(["--racine", d]).rapport.checks.find((c) => c.id === "EXE-6")?.status, nom).to.equal("echec");
      fs.rmSync(path.join(d, EXECUTIONS, nom));
    }
    // Hors de executions/ : avertissement, code 0.
    const ailleurs = tmp("ailleurs");
    const v = verif(rapportDeBase(), ailleurs, "brouillon.json");
    expect(v.errors).to.deep.equal([]);
    expect(v.checks.map((c) => c.id)).to.not.include("EXE-6");
    expect(v.warnings).to.deep.equal(["EXE-6 brouillon.json : le nom brouillon.json n'a pas la forme rapport-<AAAA-MM-JJ>-<etiquette>.json ; exigé à la publication sous executions/"]);
    expect(mesures(["--racine", d, "--execution", path.join(ailleurs, "brouillon.json")]).code).to.equal(0);
  });

  it("les cas de executions/cas/, quand ils existent, rendent leur attendu comme ceux des autres familles ; leur absence n'est pas une erreur", function () {
    const d = depotReduit();
    const invalide = rapportDeBase();
    invalide.results[0].status = "passe";
    ecrire(d, `${EXECUTIONS}/cas/valide.json`, rapportDeBase());
    ecrire(d, `${EXECUTIONS}/cas/invalide-statut.json`, invalide);
    ecrire(d, `${EXECUTIONS}/cas/cas.json`, { version: 0, kind: "cas-plan-de-tests", cases: [{ file: "valide.json", def: "rapport_execution", expected: "valid" }, { file: "invalide-statut.json", def: "rapport_execution", expected: "invalid" }] });
    let r = mesures(["--racine", d]);
    expect(r.code, r.texte).to.equal(0);
    expect(r.rapport.checks.filter((c) => c.file.startsWith("executions/cas/")).map((c) => [c.id, c.file, c.status, c.detail])).to.deep.equal([["CAS-1", "executions/cas/valide.json", "reussi", "valid, comme attendu"], ["CAS-1", "executions/cas/invalide-statut.json", "reussi", "invalid, comme attendu"]]);
    ecrire(d, `${EXECUTIONS}/cas/cas.json`, { version: 0, kind: "cas-plan-de-tests", cases: [{ file: "invalide-statut.json", expected: "valid" }] });
    r = mesures(["--racine", d]);
    expect(r.code).to.equal(1);
    expect(r.rapport.checks.find((c) => c.file === "executions/cas/invalide-statut.json").status).to.equal("echec");
  });

  it("avertissements, sans effet sur le code : echec ou en_attente sans reason ; reussi pour une entrée a_ecrire, qui ne cite aucun test", function () {
    const d = tmp("avertissements");
    const r = rapportDeBase();
    Object.assign(r.results[0], { status: "echec" });
    Object.assign(r.results[1], { status: "en_attente", reason: "  " });
    Object.assign(r.results[2], { status: "en_attente", reason: "Go absent du poste" });
    Object.assign(r.results[3], { status: "echec", reason: "mutant mal posé : exception avant l'oracle" });
    r.results.push({ test_id: "TR-1", status: "reussi", command: "épreuve à l'aveugle" });
    const v = verif(r, d);
    expect(v.errors).to.deep.equal([]);
    expect(v.warnings).to.deep.equal([
      `rapport-2026-11-13-essai.json : résultat sans reason : ${r.results[0].test_id} (echec), ${r.results[1].test_id} (en_attente)`,
      "rapport-2026-11-13-essai.json : reussi pour une entrée a_ecrire, qui ne cite aucun test : TR-1",
    ]);
    const m = mesures(["--execution", path.join(d, "rapport-2026-11-13-essai.json")]);
    expect(m.code).to.equal(0);
    expect(m.rapport.execution.counts).to.deep.equal({ echec: 2, en_attente: 2, reussi: EXECUTABLES.length - 4 + 1 });
    expect(m.texte).to.include(`${EXECUTABLES.length - 3} reussi, 2 echec, 2 en_attente, 0 non_applicable`);
  });

  it("avertissement de commit : sur un dépôt git, un rapport qui porte un autre commit que celui du dépôt lu est signalé, sans effet sur le code ; au commit du dépôt, rien n'est signalé ; hors d'un dépôt git, rien non plus", function () {
    const depot = depotReduit();
    const horsGit = verifierExecution(depot, ecrire(tmp("commit"), "rapport-2026-11-13-essai.json", rapportDeBase()), { nom: "essai" });
    expect(horsGit.errors).to.deep.equal([]);
    expect(horsGit.warnings).to.deep.equal([]);
    const g = (...a) => { const x = spawnSync("git", ["-C", depot, "-c", "user.name=essai", "-c", "user.email=essai@noortrace.invalid", "-c", "commit.gpgsign=false", ...a], { encoding: "utf8" }); expect(x.status, x.stderr).to.equal(0); return x.stdout.trim(); };
    g("init", "-q");
    g("add", "-A");
    g("commit", "-q", "-m", "essai");
    const tete = g("rev-parse", "HEAD");
    const f = ecrire(tmp("commit"), "rapport-2026-11-13-essai.json", rapportDeBase());
    expect(tete).to.not.equal(COMMIT);
    expect(verifierExecution(depot, f, { nom: "essai" }).warnings).to.deep.equal([`essai : le rapport porte le commit ${COMMIT}, le dépôt lu est au commit ${tete} ; le catalogue lu n'est pas celui du commit éprouvé`]);
    const juste = rapportDeBase();
    juste.commit = tete;
    expect(verifierExecution(depot, ecrire(tmp("commit"), "rapport-2026-11-13-essai.json", juste), { nom: "essai" }).warnings).to.deep.equal([]);
    const m = mesures(["--racine", depot, "--execution", f]);
    expect(m.code, m.texte).to.equal(0);
    expect(m.rapport.warnings.filter((w) => w.includes("le rapport porte le commit"))).to.have.length(1);
  });

  it("usage : --execution sur un fichier absent ou qui n'est pas du JSON rend 2 ; la commande lancée en processus rend le code et, avec --json, le compte des statuts", function () {
    const d = tmp("usage");
    expect(mesures(["--execution", path.join(d, "absent.json")]).code).to.equal(2);
    expect(mesures(["--execution", path.join(d, "absent.json")]).erreur).to.match(/^fichier illisible : /);
    const casse = ecrire(d, "rapport-2026-11-13-casse.json", "{ \"version\": 0,");
    const r2 = mesures(["--execution", casse]);
    expect(r2.code).to.equal(2);
    expect(r2.erreur).to.match(/^lecture impossible : /);
    expect(mesures(["--execution"]).code).to.equal(2);
    const bon = ecrire(d, "rapport-2026-11-13-essai.json", rapportDeBase());
    const sans = rapportDeBase();
    sans.results.shift();
    const mauvais = ecrire(d, "rapport-2026-11-13-lacune.json", sans);
    const outil = path.join(R, "scripts", "tests", "mesures.mjs");
    const p0 = spawnSync(process.execPath, [outil, "--execution", bon, "--json"], { encoding: "utf8" });
    expect(p0.status, p0.stderr).to.equal(0);
    expect(JSON.parse(p0.stdout).execution).to.deep.equal({ report: bon, counts: { reussi: EXECUTABLES.length } });
    const p1 = spawnSync(process.execPath, [outil, "--execution", mauvais], { encoding: "utf8" });
    expect(p1.status).to.equal(1);
    expect(p1.stdout).to.include(`[ÉCHEC] EXE-3 ${mauvais} : 1 entrée(s) executable sans résultat de leur partie exécutée : ${EXECUTABLES[0].id}`);
    const p2 = spawnSync(process.execPath, [outil, "--execution", path.join(d, "absent.json")], { encoding: "utf8" });
    expect(p2.status).to.equal(2);
    expect(p2.stdout).to.equal("");
  });
});
