// Rapports des campagnes de mesure de l'étape 8 publiés sous
// spec/vecteurs/ct-9/mesures/ (CT-9 §11.3, EX-11.11, EX-11.16) : TM-30
// (taille d'une preuve OpenTimestamps mise à niveau par deux calendriers
// réels, campagne publique nommée) et TM-44 (capture d'une transaction d'un
// bloc plein qui mêle des clôtures, réseau de développement). Les rapports
// sont écrits par l'ingénieur de la campagne, jamais par le générateur ;
// cet essai les relit, recalcule ce qu'ils déclarent et rejoue leur effet
// sur le calculateur de dimensionnement de CT-8 §9 (membre `coefficients`,
// EX-9.1). Aucun réseau ; rien n'est écrit.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import { COEFFICIENTS, dimensionner } from "../scripts/lib/deploiement.mjs";
import { executer as mesures } from "../scripts/tests/mesures.mjs";
import { TM } from "../scripts/vecteurs/ct9/donnees/tm.mjs";

const R = PROJECT_ROOT;
const MESURES = process.env.NOORTRACE_MESURES_PUBLIEES ?? path.join(R, "spec", "vecteurs", "ct-9", "mesures");
const SCHEMA = J.analyserJSONStrict(fs.readFileSync(path.join(R, "spec", "schemas", "plan-de-tests-v0.schema.json")));
const lire = (...p) => JSON.parse(fs.readFileSync(path.join(...p), "utf8"));
const valider = (v) => J.validerSchema(v, SCHEMA, { fragment: "#/$defs/rapport_mesure" });
const TEXTE_CT9 = fs.readFileSync(path.join(R, "spec", "CT-9-plan-de-tests.md"), "utf8");
const TEXTE_CT8 = fs.readFileSync(path.join(R, "spec", "CT-8-deploiement-et-exploitation.md"), "utf8");
const entree = (id) => TM.find((t) => t.id === id);
/** Entrées du calculateur d'un vecteur de CT-8 §9 (spec/vecteurs/ct-8/dimensionnement/). */
const ENTREES_DIM = lire(R, "spec", "vecteurs", "ct-8", "dimensionnement", "ots-mi-periode.json").entrees;
const moyenne = (xs) => Math.round((xs.reduce((a, b) => a + b, 0) / xs.length) * 100) / 100;

/** Lignes supplémentaires nommées par la table de 11.3 de CT-9 (nom → entrée). */
function lignesNommees() {
  const s113 = TEXTE_CT9.slice(TEXTE_CT9.indexOf("### 11.3 "), TEXTE_CT9.indexOf("### 11.4 "));
  return new Map([...s113.matchAll(/^\| `([a-z0-9_]+)` \| (TM-[0-9]+) \|/gm)].map((m) => [m[1], m[2]]));
}

/** Forme commune : rapport valide, hors du système de référence, lignes rattachées à l'entrée, met null. */
function controlerForme(r, id) {
  expect(valider(r), "conforme à rapport_mesure").to.deep.equal([]);
  expect(r.counts_for_targets, "hors du système de référence : ne compte pour aucune cible").to.equal(false);
  expect(r.system.reference).to.equal(false);
  const t = entree(id);
  const nommees = lignesNommees();
  for (const l of r.results) {
    expect(l.test_id, l.name).to.equal(id);
    expect(l.unit, l.name).to.equal(t.measure.unit);
    if (l.name !== t.measure.result_name) expect(nommees.get(l.name), `${l.name} : ligne supplémentaire non nommée par la table de 11.3`).to.equal(id);
    expect(l.met, l.name).to.equal(null);
    expect(l.target, l.name).to.equal(null);
    expect(l.samples, l.name).to.have.length(l.n);
    expect([l.min, l.max, l.mean], l.name).to.deep.equal([Math.min(...l.samples), Math.max(...l.samples), moyenne(l.samples)]);
  }
  const l = r.results.find((x) => x.name === t.measure.result_name);
  expect(l, `${id} : ligne ${t.measure.result_name} absente`).to.not.equal(undefined);
  return l;
}

describe("CT-9 : rapports des campagnes de mesure de l'étape 8 publiés (TM-30 calendriers publics, TM-44 bloc plein qui mêle des clôtures ; EX-11.11, EX-11.16)", function () {
  this.timeout(120_000);

  it("scripts/tests/mesures.mjs rend 0 sur les rapports publiés, dont les deux rapports de campagne de l'étape 8", function () {
    for (const f of ["rapport-2026-11-13-tm-30-calendriers-publics.json", "rapport-2026-11-13-capture-bloc-plein-clotures.json"]) expect(fs.existsSync(path.join(MESURES, f)), `mesures/${f} non publié`).to.equal(true);
    const r = mesures([]);
    expect(r.code, r.texte).to.equal(0);
    expect(r.rapport.checks.filter((c) => c.status === "echec")).to.deep.equal([]);
  });

  it("TM-30 : rapport de la campagne publique nommée vers deux calendriers réels : ligne b_ots_mis_a_niveau, dix preuves mises à niveau par les deux calendriers, aucune attestation en attente, met null ; chaque preuve dépasse le défaut de 233 octets de CT-8 §9.2, que la valeur relevée remplace dans les entrées du calculateur (coefficients)", function () {
    const r = lire(MESURES, "rapport-2026-11-13-tm-30-calendriers-publics.json");
    const l = controlerForme(r, "TM-30");
    expect(l.n, "dix preuves (repetitions de TM-30)").to.equal(entree("TM-30").measure.repetitions);
    expect(l.conditions.some((c) => /^campagne publique nommée : .*sans compte ni dépense$/.test(c)), "campagne publique nommée, sans compte ni dépense").to.equal(true);
    expect(l.conditions, "aucune preuve encore en attente").to.include(`${l.n} preuve(s) sur ${l.n} sans attestation en attente restante`);
    expect(r.notes).to.match(new RegExp(`^TM-30 : ${l.n} preuve\\(s\\) mise\\(s\\) à niveau par les deux calendriers, 0 par un seul, 0 encore en attente`));
    // Chaque preuve : taille égale à l'échantillon de même rang, deux hauteurs Bitcoin déclarées.
    const preuves = l.conditions.map((c) => /^preuve (\d+) : (\d+) octets \((\d+) en attente\), hauteurs Bitcoin déclarées (\d+) et (\d+), complète le [0-9TZ:.-]+, SHA-256 [0-9a-f]{64}$/.exec(c)).filter(Boolean);
    expect(preuves.map((m) => Number(m[2]))).to.deep.equal(l.samples);
    const attente = r.results.find((x) => x.name === "b_ots_en_attente_public");
    expect(preuves.map((m) => Number(m[3])), "tailles en attente de la ligne supplémentaire").to.deep.equal(attente.samples);
    for (const m of preuves) expect(Number(m[4]) > 0 && Number(m[5]) > 0, `preuve ${m[1]} : deux attestations Bitcoin`).to.equal(true);
    // Lecture pour CT-8 §9.2 : le défaut b_ots de 233 octets est celui d'une preuve en attente.
    expect(COEFFICIENTS.b_ots).to.equal(233);
    for (const s of l.samples) expect(s).to.be.above(COEFFICIENTS.b_ots);
    // La valeur remplace 233 dans les entrées du calculateur : seul le volume des ancres change, de N_ots × (max − 233).
    const avant = dimensionner(ENTREES_DIM);
    const apres = dimensionner({ ...ENTREES_DIM, coefficients: { ...ENTREES_DIM.coefficients, b_ots: l.max } });
    expect(avant.valid && apres.valid).to.equal(true);
    const [a, b] = [avant.journals[0], apres.journals[0]];
    const ecart = b.anchor_bytes_per_year - a.anchor_bytes_per_year;
    expect(Math.abs(ecart - a.ots_submissions_per_year * (l.max - COEFFICIENTS.b_ots)), "écart du volume des ancres").to.be.at.most(1);
    for (const k of Object.keys(a)) if (!["anchor_bytes_per_year", "local_bytes", "worm_bytes"].includes(k)) expect(b[k], k).to.deep.equal(a[k]);
  });

  it("TM-44 : rapport du réseau de développement : ligne b_cap_bloc_plein_clotures, deux compositions (1 clôture et 63 ancres ; 4 clôtures et 60 ancres), trois répétitions, une clôture et une ancre capturées par bloc, CP-1 à CP-6 réussies, met null ; la plus grande capture, index compris, dépasse b_cap = 123 761 octets de CT-8 §9.2 et le remplace dans les entrées du calculateur (coefficients)", function () {
    const r = lire(MESURES, "rapport-2026-11-13-capture-bloc-plein-clotures.json");
    const l = controlerForme(r, "TM-44");
    const t = entree("TM-44");
    for (const c of t.measure.conditions.slice(0, 1)) expect(l.conditions.some((x) => x.startsWith(c.split(",")[0])), c).to.equal(true);
    expect(l.conditions).to.include("index de capture exclu de la ligne, relevé dans notes");
    expect(l.conditions.some((c) => c.startsWith("seuil de deux approbateurs par clôture")), "seuil de deux approbateurs").to.equal(true);
    const re = /composition (\d+) répétition (\d+), bloc (\d+) \((\d+) clôture\(s\) \+ (\d+) ancres, \d+ gaz\), capture de la transaction de (cloture|ancre) d.indice \d+ = (\d+) octets = en-tête (\d+) \+ certificat (\d+) \+ 64 reçus (\d+) \(\d+ à \d+ par reçu, (\d+) pour la transaction capturée\) ; index de capture (\d+) octets en plus ; CP-1 à CP-6 : ([^.]*)\./g;
    const captures = [...r.notes.matchAll(re)].map((m) => ({ composition: Number(m[1]), repetition: Number(m[2]), bloc: Number(m[3]), clotures: Number(m[4]), ancres: Number(m[5]), role: m[6], octets: Number(m[7]), entete: Number(m[8]), certificat: Number(m[9]), recus: Number(m[10]), recu: Number(m[11]), index: Number(m[12]), cp: m[13] }));
    // Deux compositions, trois répétitions, une clôture et une ancre par bloc : 12 captures, autant que d'échantillons.
    expect(captures).to.have.length(l.n);
    expect(captures.map((c) => c.octets)).to.deep.equal(l.samples);
    for (const k of [1, 4]) {
      const cs = captures.filter((c) => c.composition === k);
      expect(cs.map((c) => `${c.repetition}:${c.role}`), `composition ${k}`).to.deep.equal(["1:cloture", "1:ancre", "2:cloture", "2:ancre", "3:cloture", "3:ancre"]);
      for (const c of cs) expect([c.clotures, c.ancres, c.clotures + c.ancres], `composition ${k}`).to.deep.equal([k, 64 - k, 64]);
      expect(new Set(cs.map((c) => c.bloc)).size, `composition ${k} : trois blocs`).to.equal(3);
    }
    for (const c of captures) {
      expect(c.entete + c.certificat + c.recus, `bloc ${c.bloc} ${c.role} : décomposition`).to.equal(c.octets);
      expect(c.cp, `bloc ${c.bloc} ${c.role}`).to.equal("CP-1:reussi CP-2:reussi CP-3:reussi CP-4:reussi CP-5:reussi CP-6:reussi");
      // Le reçu d'une clôture est plus grand que celui d'une ancre (CT-8 §9.2 : 1 816 contre 1 107 à 1 111 au même seuil).
      if (c.role === "cloture") expect(c.recu).to.be.above(1800); else expect(c.recu).to.be.below(1200);
    }
    // Comparaison de l'oracle : la plus grande capture, index compris, contre b_cap de CT-8 §9.2 (TM-31, ancres seules).
    expect(COEFFICIENTS.b_cap).to.equal(123761);
    expect(TEXTE_CT8).to.match(/\| `b_cap` octets de la capture d'une transaction du registre \(index compris\) \| 123 761 \|/);
    const plusGrande = Math.max(...captures.map((c) => c.octets + c.index));
    expect(plusGrande, "plus grande capture, index compris").to.equal(129146);
    expect(plusGrande, "plus grande que b_cap : elle le remplace dans les entrées du calculateur").to.be.above(COEFFICIENTS.b_cap);
    const avant = dimensionner(ENTREES_DIM);
    const apres = dimensionner({ ...ENTREES_DIM, coefficients: { ...ENTREES_DIM.coefficients, b_cap: plusGrande } });
    const [a, b] = [avant.journals[0], apres.journals[0]];
    const n = a.registry_anchors_per_year_max + a.registry_closures_per_year;
    expect(Math.abs(b.capture_bytes_per_year - n * plusGrande), "V_cap = (N_a + N_h) × b_cap (DM-11)").to.be.at.most(1);
    expect(b.capture_bytes_per_year).to.be.above(a.capture_bytes_per_year);
  });
});
