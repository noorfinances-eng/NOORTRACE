import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as S from "../scripts/lib/securite.mjs";
import * as R from "../scripts/conformite/verifier-renvois.mjs";
import { MATRICE } from "../scripts/conformite/matrice-donnees.mjs";

// LA MATRICE DE CONFORMITÉ DE CT-7 (spec/CT-7-securite-et-conformite.md,
// section 8, annexe C, annexe A.8, EX-A.20) : une correspondance technique
// entre des passages de textes et des pièces de preuve, pas un avis
// juridique. Le fichier publié spec/vecteurs/ct-7/matrice-conformite.json est
// conforme à son schéma, égal aux tables 8.2, 8.4, 8.9 et à la table des
// clauses de l'annexe C (MX-8), et réussit MX-1 à MX-9 ; chaque cas invalide
// de matrice/invalides/ échoue exactement aux MX- de son attendu.json ; la
// grille de l'épreuve de conformité (EX-9.2) se recalcule depuis le fichier.

const SPEC = path.join(PROJECT_ROOT, "spec");
const CT7 = fs.readFileSync(path.join(SPEC, "CT-7-securite-et-conformite.md"), "utf8");
const VECT = path.join(SPEC, "vecteurs", "ct-7");
const SPECS = S.lireSpecifications(SPEC);
const SCHEMA = JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", "matrice-conformite-v0.schema.json"), "utf8"));
const lire = (...p) => J.analyserJSONStrict(fs.readFileSync(path.join(...p)));
const annote = (nom) => J.analyserJSONStrict(new RegExp(`<!-- schema: ${nom.replace("/", "\\/")} -->\\n\`\`\`json\\n([\\s\\S]*?)\\n\`\`\``).exec(CT7)[1]);
const ids = (erreurs) => [...new Set(erreurs.map((e) => e.id))].sort((a, b) => Number(a.slice(3)) - Number(b.slice(3)));

describe("CT-7 : matrice de conformité (section 8, annexe A.8, EX-A.20)", function () {
  this.timeout(120_000);
  const publie = lire(VECT, "matrice-conformite.json");

  it("le fichier publié est l'objet de scripts/conformite/matrice-donnees.mjs, écrit JSON.stringify(objet, null, 2) suivi d'un saut de ligne (EX-A.12)", function () {
    expect(fs.readFileSync(path.join(VECT, "matrice-conformite.json"), "utf8")).to.equal(JSON.stringify(MATRICE, null, 2) + "\n");
  });

  it("les exemples annotés matrice-conformite et matrice-conformite/ligne de CT-7 sont conformes au schéma (contains réécrit en not/items/not pour le validateur du dépôt)", function () {
    const schema = R.sansContains(SCHEMA);
    expect(J.validerSchema(annote("matrice-conformite"), schema)).to.deep.equal([]);
    expect(J.validerSchema(annote("matrice-conformite/ligne"), schema, { fragment: "#/$defs/ligne" })).to.deep.equal([]);
    expect(J.motsClesHorsSousEnsemble(schema)).to.deep.equal([]);
    // La réécriture garde la règle d'EX-8.3 que porte le schéma : un statut forcé est refusé.
    const force = structuredClone(publie);
    force.rows.find((r) => r.id === "MC-57").status = "partiel";
    expect(J.validerSchema(force, schema).length).to.be.greaterThan(0);
  });

  it("MX-1 à MX-9 réussissent sur le fichier publié ; MX-8 compare les tables 8.2, 8.4, 8.9 et la table des clauses, cellule par cellule", function () {
    expect(R.verifierMatrice(publie, { specs: SPECS, publie: true })).to.deep.equal([]);
    const t = R.tablesAttenduesMatrice(publie);
    expect(t.lignes).to.deep.equal(S.tablesDe(S.texteSection(CT7, "8.4"))[0].lignes);
    expect(t.textes).to.deep.equal(S.tablesDe(S.texteSection(CT7, "8.2"))[0].lignes);
    expect(t.lacunes).to.deep.equal(S.tablesDe(S.texteSection(CT7, "8.9"))[0].lignes);
    expect(publie.rows).to.have.length(58);
    expect(publie.texts).to.have.length(10);
  });

  it("statut dérivé (EX-8.3) : chaque statut est celui que les relations des éléments donnent ; aucune ligne d'un texte pas encore applicable n'est présentée en vigueur (EX-8.4)", function () {
    for (const r of publie.rows) expect(r.status, r.id).to.equal(R.statutDerive(r.elements));
    const ia = publie.texts.find((t) => t.id === "T-8");
    expect(ia.applicability.status).to.equal("pas_encore_applicable");
    expect(ia.applicability.from.map((f) => f.date)).to.deep.equal(["2027-12-02", "2028-08-02"]);
    for (const r of publie.rows.filter((x) => x.text === "T-8")) expect(r.applicability, r.id).to.equal("pas_encore_applicable");
  });

  it("chaque cas de matrice/invalides/ échoue exactement aux MX- de attendu.json, et la table d'EX-A.14 nomme les mêmes cas et les mêmes MX-", function () {
    const attendu = lire(VECT, "matrice", "invalides", "attendu.json");
    const table = S.tablesDe(S.texteSection(CT7, "A.8"))[1].lignes;
    expect(attendu.cases.map((c) => [c.name, c.failed.join(", ")])).to.deep.equal(table.map((c) => [c[0].replace(/`/g, ""), c[2]]));
    for (const c of attendu.cases) {
      const m = lire(VECT, "matrice", "invalides", `${c.name}.json`);
      expect(ids(R.verifierMatrice(m, { specs: SPECS, publie: false })), c.name).to.deep.equal(c.failed);
    }
  });

  it("la grille de l'épreuve de conformité (EX-9.2) se recalcule depuis le fichier : pièces, non couvert, client, statut et applicabilité de chaque ligne ; sixième question : non", function () {
    const grille = lire(VECT, "acceptation-conformite-attendu.json");
    const table = S.tablesDe(S.texteSection(CT7, "9"))[1].lignes;
    expect(grille.questions.map((q) => q.row)).to.deep.equal(table.filter((c) => c[1].startsWith("MC-")).map((c) => c[1]));
    for (const q of grille.questions) {
      const r = publie.rows.find((x) => x.id === q.row);
      expect(q.expected.c_status, q.row).to.equal(r.status);
      expect(q.expected.c_applicability, q.row).to.equal(r.applicability);
      expect(q.expected.a_pieces.flatMap((x) => x.pieces), q.row).to.deep.equal(r.elements.filter((x) => x.relation === "repond_a" || x.relation === "contribue_a").flatMap((x) => x.pieces.map(R.ecrirePiece)));
      expect(q.expected.b_not_covered, q.row).to.deep.equal(r.elements.filter((x) => x.relation === "ne_couvre_pas").map((x) => x.element));
      expect(q.expected.b_client, q.row).to.deep.equal(r.elements.filter((x) => x.relation === "releve_du_client").map((x) => x.element));
    }
    expect(grille.sixth_question.expected_answer).to.equal("non");
    const consigne = fs.readFileSync(path.join(VECT, "acceptation-conformite", "consigne.md"), "utf8");
    for (const q of grille.questions) expect(consigne, q.row).to.not.include(q.row);
  });

  it("garde du vocabulaire (EX-8.1, EX-8.2) : la section 8 et l'annexe C n'écrivent « est conforme » que dans des phrases qui le nient ; l'avertissement du fichier est celui du texte, mot pour mot", function () {
    const s8 = CT7.slice(CT7.indexOf("\n## 8. "), CT7.indexOf("\n## 9. "));
    const c = CT7.slice(CT7.indexOf("\n## Annexe C"));
    for (const l of (s8 + c).split("\n").filter((x) => /est conforme|sont conformes/i.test(x) && !x.includes('"warning"'))) expect(/jamais|\bne\b|n'|NE DOIT|aucun/i.test(l), l).to.equal(true);
    const avertissement = /> \*\*Avertissement\.\*\* ([\s\S]*?)\n\n/.exec(s8)[1].replace(/\n> /g, " ");
    expect(publie.warning.replace(/’/g, "'")).to.equal(avertissement);
  });
});
