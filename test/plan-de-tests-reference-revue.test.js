// Bibliothèque du plan de tests (scripts/lib/plan-de-tests.mjs, CT-9 EX-5.4 d) :
// correction de la revue de sécurité interne de l'étape 8 (règle (d) :
// un `it` cité a un corps, n'est ni skip ni only, ne commence
// pas par this.skip() et n'est pas sous un describe.skip). Un mutant de la
// règle (copie de scripts/lib sous NOORTRACE_TMP, règle retirée) doit faire
// échouer l'oracle ; la copie est détruite. Racine des scripts éprouvés : le
// dépôt, ou NOORTRACE_REVUE_RACINE.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";

const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : PROJECT_ROOT;
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const MUTANTS = [];
const importer = (racine) => import(pathToFileURL(path.join(racine, "scripts", "lib", "plan-de-tests.mjs")).href + `?t=${Date.now()}-${Math.random()}`);
function mutant(nom, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-revue-plan-${nom}-`));
  MUTANTS.push(racine);
  fs.mkdirSync(path.join(racine, "scripts"));
  for (const d of ["lib", "conformite", "verify", "registre"]) fs.cpSync(path.join(RACINE, "scripts", d), path.join(racine, "scripts", d), { recursive: true });
  for (const l of ["spec", "node_modules", "package.json"]) fs.symlinkSync(path.join(PROJECT_ROOT, l), path.join(racine, l));
  const f = path.join(racine, "scripts", "lib", "plan-de-tests.mjs");
  const texte = fs.readFileSync(f, "utf8");
  const n = texte.split(ancien).length - 1;
  if (n !== 1) throw new Error(`mutant ${nom} : « ${ancien} » trouvé ${n} fois`);
  fs.writeFileSync(f, texte.replace(ancien, () => nouveau));
  return racine;
}
after(function () {
  for (const r of MUTANTS) fs.rmSync(r, { recursive: true, force: true });
});

/** Les quatorze sources du relecteur (plan-essais.mjs) et ce que la règle (d) doit en dire pour { describe D, it t }. */
const CAS = [
  ["it ordinaire", 'describe("D", () => { it("t", () => {}); });', true],
  ["it.skip", 'describe("D", () => { it.skip("t", () => {}); });', false],
  ["describe.skip englobant", 'describe("D", () => { describe.skip("S", () => { it("t", () => {}); }); });', false],
  ["describe.skip au premier niveau", 'describe.skip("D", () => { it("t", () => {}); });', false],
  ["it sans corps (en attente pour mocha)", 'describe("D", () => { it("t"); });', false],
  ["it dont le corps commence par this.skip()", 'describe("D", function () { it("t", function () { this.skip(); }); });', false],
  ["it dont le corps commence par this.skip() après un commentaire", 'describe("D", function () { it("t", async function () {\n  // en attente\n  this.skip();\n }); });', false],
  ["it dont le this.skip() est conditionnel (ressource absente, EX-3.11)", 'describe("D", function () { it("t", function () { if (!process.env.DOCKER) this.skip(); expect(1).to.equal(1); }); });', true],
  ["it en commentaire", 'describe("D", () => { // it("t", () => {});\n });', false],
  ["it dans une chaîne", "describe(\"D\", () => { const s = 'it(\"t\", () => {})'; });", false],
  ["xit", 'describe("D", () => { xit("t", () => {}); });', false],
  ["xdescribe englobant", 'xdescribe("D", () => { it("t", () => {}); });', false],
  ["it.only", 'describe("D", () => { it.only("t", () => {}); it("autre", () => {}); });', false],
  ["it ordinaire à côté d'un it.only", 'describe("D", () => { it.only("autre", () => {}); it("t", () => {}); });', true],
  ["it à paramètre done", 'describe("D", () => { it("t", (done) => { done(); }); });', true],
  ["it dont le titre est un gabarit avec interpolation", 'describe("D", () => { for (const x of [1]) it(`t`, () => { x; }); });', true],
];

describe("CT-9, référence : règle (d) d'EX-5.4 et tests en attente", function () {
  let P;
  before(async function () {
    P = await importer(RACINE);
  });
  const oracle = (M) => CAS.every(([, src, attendu]) => {
    const idx = new Map([["test/x.test.js", M.titresTests(src)]]);
    return M.titreExiste(idx, { file: "test/x.test.js", describe: "D", it: "t" }) === attendu;
  });

  it("CT-9 EX-5.4 : titreExiste ne tient pour existant qu'un it qui s'exécute : un it sans corps, à this.skip() inconditionnel en tête, it.skip, xit, it.only, ou sous describe.skip/xdescribe est absent ; un this.skip() conditionnel, un it ordinaire à côté d'un it.only et un titre gabarit restent existants", function () {
    for (const [nom, src, attendu] of CAS) {
      const idx = new Map([["test/x.test.js", P.titresTests(src)]]);
      expect(P.titreExiste(idx, { file: "test/x.test.js", describe: "D", it: "t" }), nom).to.equal(attendu);
    }
    expect(oracle(P)).to.equal(true);
    // Un describe.skip n'est pas un describe exécuté ; ses it portent pending.
    const r = P.titresTests('describe("D", () => { describe.skip("S", () => { it("t", () => {}); }); it("u", () => {}); });');
    expect(r.describes).to.deep.equal(["D"]);
    expect(r.cas.map((c) => [c.it, c.pending])).to.deep.equal([["t", true], ["u", false]]);
    expect(P.titreExiste(new Map([["test/x.test.js", r]]), { file: "test/x.test.js", describe: "S" })).to.equal(false);
    expect(P.titreExiste(new Map([["test/x.test.js", r]]), { file: "test/x.test.js", describe: "D", it: "u" })).to.equal(true);
  });

  it("CT-9 EX-5.4 : sur le dépôt, aucun it cité par une entrée exécutable du catalogue n'est un it en attente ou sauté (un titre cité qui existe en ignorant pending existe aussi avec lui)", function () {
    this.timeout(120000);
    const index = P.indexTitres(PROJECT_ROOT);
    const catalogue = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, P.CATALOGUE), "utf8"));
    const enAttente = [];
    for (const t of catalogue.tests) {
      if (t.status.state !== "executable") continue;
      for (const x of t.status.tests ?? []) {
        if (x.it === undefined) continue;
        const r = index.get(x.file);
        const sansPending = Boolean(r && r.cas.some((c) => c.describes.includes(x.describe) && c.it === x.it));
        if (sansPending && !P.titreExiste(index, x)) enAttente.push(`${t.id} : ${x.file} | ${x.it}`);
      }
    }
    expect(enAttente).to.deep.equal([]);
  });

  it("mutant CT-9 EX-5.4 : titreExiste sans le filtre pending tient pour existant un it vidé ou sauté (tué par l'oracle)", async function () {
    const M = await importer(mutant("cas-en-attente", "return r.cas.some((c) => !c.pending && c.describes.includes(t.describe) && c.it === t.it);", "return r.cas.some((c) => c.describes.includes(t.describe) && c.it === t.it);"));
    expect(oracle(M)).to.equal(false);
  });

  it("mutant CT-9 EX-5.4 (describe.skip) : sans la propagation du skip aux describe englobés, un it sous describe.skip est tenu pour existant (tué par l'oracle)", async function () {
    const M = await importer(mutant("describe-saute", "const sousSkip = saute || pile.some((p) => p.skip);", "const sousSkip = saute;"));
    expect(oracle(M)).to.equal(false);
  });
});
