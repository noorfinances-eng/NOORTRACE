// Générateur des règles d'alerte de référence (scripts/lib/supervision.mjs,
// CT-8 §10) : corrections de la revue de sécurité interne de l'étape 8
// (EX-10.10 : règles sur compteur muettes à la première occurrence,
// forme « première occurrence » et cas « série absente puis 1 » ; EX-10.6 :
// clause for d'une heure sur noortrace_sauvegarde_en_retard et
// budget journalier de gaz et tarif réglables ; CT-8 EX-10.9, CT-8 EX-10.7 :
// douze règles demandées par la revue du déploiement, dont les métriques des
// outils de supervision). Les règles et essais proposés par la revue sont
// rejoués par l'évaluateur réduit du dépôt et, quand promtool 3.5.0 est
// présent (NOORTRACE_PROMTOOL ou PATH), par promtool.
//
// Chaque essai éprouve ensuite un mutant de la règle (copie de scripts/lib sous
// NOORTRACE_TMP, règle retirée, oracle en échec, copie détruite). Racine des
// scripts éprouvés : le dépôt, ou NOORTRACE_REVUE_RACINE.

import { expect } from "chai";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import yaml from "js-yaml";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import { rejouerGroupe } from "./fixtures/supervision/promql.mjs";

const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : PROJECT_ROOT;
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const MUTANTS = [];
const TRAVAIL = fs.mkdtempSync(path.join(TMP, "noortrace-revue-supervision-"));

const importer = (racine) => import(pathToFileURL(path.join(racine, "scripts", "lib", "supervision.mjs")).href + `?t=${Date.now()}-${Math.random()}`);
function mutant(nom, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-revue-supervision-${nom}-`));
  MUTANTS.push(racine);
  fs.mkdirSync(path.join(racine, "scripts"));
  fs.cpSync(path.join(RACINE, "scripts", "lib"), path.join(racine, "scripts", "lib"), { recursive: true });
  const f = path.join(racine, "scripts", "lib", "supervision.mjs");
  const texte = fs.readFileSync(f, "utf8");
  const n = texte.split(ancien).length - 1;
  if (n !== 1) throw new Error(`mutant ${nom} : « ${ancien} » trouvé ${n} fois`);
  fs.writeFileSync(f, texte.replace(ancien, () => nouveau));
  return racine;
}
after(function () {
  for (const r of MUTANTS) fs.rmSync(r, { recursive: true, force: true });
  fs.rmSync(TRAVAIL, { recursive: true, force: true });
});

/** promtool 3.5.0 : NOORTRACE_PROMTOOL, sinon promtool du PATH ; null s'il manque ou n'est pas 3.5.0. */
function promtool() {
  const bin = process.env.NOORTRACE_PROMTOOL || "promtool";
  const r = spawnSync(bin, ["--version"], { encoding: "utf8" });
  if (r.error || r.status !== 0) return null;
  return /promtool, version 3\.5\.0 /.test(r.stdout + r.stderr) ? bin : null;
}
const PROMTOOL = promtool();
const CONDITION_PROMTOOL = "promtool 3.5.0 absent (CT-8 EX-10.10 : archive de Prometheus 3.5.0 à SHA-256 fixé, étape de CI d'EX-A.27 ; NOORTRACE_PROMTOOL ou PATH)";

const SIMPLE = /^\((increase|rate)\((.+?)\[([0-9]+[smhd])\]\) (>=?) ([0-9]+)\) or \(\((.+?) unless \6 offset \3\) \4 \5\)$/;

describe("CT-8, référence : règles sur compteur en forme « première occurrence » (EX-10.6, EX-10.10)", function () {
  this.timeout(120000);
  let S;
  before(async function () {
    S = await importer(RACINE);
  });
  const oracle = (M) => {
    const rs = M.reglesCalculees(M.PARAMETRES_DEFAUT);
    const compteurs = rs.filter((r) => /^(increase|rate)\(/.test(r.expr) || r.naissance);
    const simples = rs.filter((r) => r.naissance);
    const composees = rs.filter((r) => M.REGLES_COMPOSEES_PREMIERE_OCCURRENCE.includes(r.alert));
    const bonne = simples.every((r) => SIMPLE.test(r.expr)) && composees.every((r) => !/(^|[^(])increase\(/.test(r.expr) || /unless .+ offset/.test(r.expr));
    // Évaluateur réduit : la série née à 1 dans la fenêtre lève chaque règle simple réécrite.
    const t = yaml.load(M.genererTestsRegles());
    const naissance = t.tests.filter((x) => / : série absente puis /.test(x.name));
    const silence = t.tests.filter((x) => / : série à 0 immobile$/.test(x.name));
    const ecarts = [...naissance, ...silence].flatMap((x) => rejouerGroupe(x, rs.map((r) => ({ ...r, for: r.pour ?? undefined })), t.evaluation_interval));
    // 47 formes simples sur une série noortrace_ des tables de 10.4 à 10.7 (dont les deux règles sur compteur adoptées
    // avec E-C8) ; noortrace_registre_equivocation (noor_bft_equivocations_total, exposé à 0 dès le démarrage du nœud,
    // CT-4 EX-10.9) garde la forme courte (arbitrage du 14 novembre sur EX-10.6).
    return compteurs.length >= 47 && simples.length === 47 && composees.length === 7 && bonne && naissance.length === 47 && silence.length === 47 && ecarts.length === 0;
  };
  it("CT-8 EX-10.10 : les 47 règles « increase|rate(x[w]) OP n » sur une série noortrace_ (noor_bft_equivocations_total, exposé dès le démarrage du nœud, garde la forme courte) s'écrivent « (…) or ((x unless x offset w) OP n) », les 7 formes composées remplacent chaque increase(S[w]) par « ((S unless S offset w) or increase(S[w])) », les quantiles et le taux du processeur ne changent pas ; genererTestsRegles donne pour chacune des 47 un cas « série absente puis N » qui lève et un cas « série à 0 immobile » qui se tait, que l'évaluateur réduit rejoue sans écart", function () {
    expect(oracle(S)).to.equal(true);
    const rs = S.reglesCalculees(S.PARAMETRES_DEFAUT);
    const par = Object.fromEntries(rs.map((r) => [r.alert, r]));
    expect(par.noortrace_fourche.expr).to.equal('(increase(noortrace_journal_lignes_total{event="journal_fork"}[5m]) > 0) or ((noortrace_journal_lignes_total{event="journal_fork"} unless noortrace_journal_lignes_total{event="journal_fork"} offset 5m) > 0)');
    expect(par.noortrace_fourche.ecart).to.equal("E-C6");
    expect(par.noortrace_ancrage_volume.expr).to.match(/^sum\(\(\(noortrace_anchoring_attempts_total unless noortrace_anchoring_attempts_total offset 1h\) or increase\(noortrace_anchoring_attempts_total\[1h\]\)\)\) > 2 \* /);
    expect(par.noortrace_otel_retard.expr).to.equal("histogram_quantile(0.99, sum by (le) (rate(noortrace_otel_reception_lag_ms_bucket[15m]))) > 60000");
    expect(par.noortrace_hote_processeur.expr).to.equal('(1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m]))) > 0.90');
    expect(S.ECARTS_CT8).to.have.property("E-C6");
  });
  it("mutant CT-8 EX-10.10 : sans la réécriture, la série née à 1 ne lève pas la règle (increase vaut 0) : les cas « série absente puis N » échouent (tué par l'oracle)", async function () {
    const M = await importer(mutant("naissance-serie", "return { expr: `(${expr}) or ((${serie} unless ${serie} offset ${fenetre}) ${op} ${n})`, naissance: { serie, fenetre, op, n: Number(n) } };", "return { expr, naissance: { serie, fenetre, op, n: Number(n) } };"));
    expect(oracle(M)).to.equal(false);
  });

  it("CT-8 EX-10.10, CT-8 EX-10.9, CT-8 EX-10.7 (promtool 3.5.0) : promtool check rules sur les règles régénérées, puis promtool test rules sur les essais régénérés et sur les trois fichiers d'essais remis par la revue du déploiement (naissance, règles nouvelles ; essais existants redirigés : le seul cas déplacé par la clause for d'une heure échoue)", function () {
    // promtool évalue chaque groupe à la minute : les cas à deux jours (absent) demandent plusieurs minutes.
    this.timeout(1500000);
    if (!PROMTOOL) {
      this.test.title += ` — en attente : ${CONDITION_PROMTOOL}`;
      this.skip();
    }
    const rep = fs.mkdtempSync(path.join(TRAVAIL, "promtool-"));
    fs.writeFileSync(path.join(rep, "regles.yml"), S.genererRegles());
    fs.writeFileSync(path.join(rep, "regles-noortrace.yml"), S.genererRegles());
    fs.writeFileSync(path.join(rep, "tests-regles.yml"), S.genererTestsRegles());
    const c = spawnSync(PROMTOOL, ["check", "rules", path.join(rep, "regles.yml")], { encoding: "utf8" });
    expect(c.status, c.stdout + c.stderr).to.equal(0);
    const t = spawnSync(PROMTOOL, ["test", "rules", path.join(rep, "tests-regles.yml")], { encoding: "utf8", cwd: rep });
    expect(t.status, t.stdout + t.stderr).to.equal(0);
    const essais = process.env.NOORTRACE_ESSAIS_REGLES_L14;
    if (essais) {
      for (const f of ["essais-naissance.yml", "essais-nouvelles.yml"]) {
        fs.copyFileSync(path.join(essais, f), path.join(rep, f));
        const r = spawnSync(PROMTOOL, ["test", "rules", path.join(rep, f)], { encoding: "utf8", cwd: rep });
        expect(r.status, `${f} : ${r.stdout + r.stderr}`).to.equal(0);
      }
      // Les essais existants du dépôt, redirigés sur les règles régénérées : un seul cas échoue, celui que la clause for
      // d'une heure déplace (E-C7) ; le fichier régénéré (tests-regles.yml ci-dessus) le juge après l'heure.
      fs.copyFileSync(path.join(essais, "tests-regles-existants.yml"), path.join(rep, "tests-regles-existants.yml"));
      const r = spawnSync(PROMTOOL, ["test", "rules", path.join(rep, "tests-regles-existants.yml")], { encoding: "utf8", cwd: rep });
      expect(r.status).to.equal(1);
      expect([...(r.stdout + r.stderr).matchAll(/^\s+name: (.+),$/gm)].map((m) => m[1])).to.deep.equal(["noortrace_sauvegarde_en_retard déclenchée"]);
    }
  });
});

describe("CT-8, référence : seuils et règles nouvelles (EX-10.6, EX-10.9, EX-10.7)", function () {
  let S;
  before(async function () {
    S = await importer(RACINE);
  });
  const NOUVELLES = ["noortrace_enregistreur_cible_muette", "noortrace_journal_exploitation_lignes_perdues", "noortrace_image_differente", "noortrace_hote_cible_muette", "noortrace_extracteur_muet", "noortrace_sonde_muette", "noortrace_releve_externe_absent_registre_gels", "noortrace_releve_externe_absent_console", "noortrace_releve_externe_absent_copie_exploitation", "noortrace_sauvegarde_absente", "noortrace_tache_echec"];
  const oracleSolde = (M) => {
    const defaut = M.seuils(M.parametresRegles({})).solde;
    const budget = M.seuils(M.parametresRegles({ budget_journalier_gaz: 500000000 })).solde;
    const tarif = M.seuils(M.parametresRegles({ instance: { fees: { refill_below_days: 7, gas_limit: 3000000, max_fee_per_gas_wei: "2000000000" } } })).solde;
    return defaut === 78600000 && budget === 7 * 500000000 + 3000000 && tarif === 78600000 * 2000000000;
  };
  it("CT-8 EX-10.6 : <S> = (refill_below_days × budget_journalier_gaz + gas_limit) × max_fee_per_gas_wei ; le défaut reste 78 600 000 ; budget_journalier_gaz et fees.max_fee_per_gas_wei (chaîne décimale) le règlent ; valeurs hors bornes refusées", function () {
    expect(oracleSolde(S)).to.equal(true);
    expect(S.PARAMETRES_DEFAUT.max_fee_per_gas_wei).to.equal(1);
    expect(() => S.parametresRegles({ budget_journalier_gaz: 0 })).to.throw(S.ErreurParametres);
    expect(() => S.parametresRegles({ instance: { fees: { max_fee_per_gas_wei: "0" } } })).to.throw(S.ErreurParametres);
    expect(() => S.parametresRegles({ instance: { fees: { max_fee_per_gas_wei: "1e9" } } })).to.throw(S.ErreurParametres);
    const regle = S.reglesCalculees(S.parametresRegles({ budget_journalier_gaz: 500000000 })).find((r) => r.alert === "noortrace_registre_solde_bas");
    expect(regle.expr).to.equal("noortrace_registre_solde_wei < 3503000000");
  });
  it("mutant CT-8 EX-10.6 : sans la lecture de budget_journalier_gaz, <S> vaut 78 600 000 quelle que soit l'entrée (tué par l'oracle)", async function () {
    const M = await importer(mutant("c09b", "    p.budget_journalier_gaz = docs.budget_journalier_gaz;\n", ""));
    expect(oracleSolde(M)).to.equal(false);
  });
  const oracleFor = (M) => {
    const r = M.reglesCalculees(M.PARAMETRES_DEFAUT).find((x) => x.alert === "noortrace_sauvegarde_en_retard");
    const t = yaml.load(M.genererTestsRegles()).tests.find((x) => x.name === "noortrace_sauvegarde_en_retard déclenchée");
    return r.pour === "1h" && r.ecart === "E-C7" && /m$/.test(t.alert_rule_test[0].eval_time) && Number.parseInt(t.alert_rule_test[0].eval_time, 10) > 61;
  };
  it("CT-8 EX-10.6 : noortrace_sauvegarde_en_retard porte for: 1h (écart E-C7) et son cas déclenché est jugé après l'heure", function () {
    expect(oracleFor(S)).to.equal(true);
  });
  it("mutant CT-8 EX-10.6 : sans la clause for, l'alerte se lève dès le premier point au-delà du RPO (tué par l'oracle)", async function () {
    const M = await importer(mutant("c09a", '"1h", "majeure", "exploitation", "CT-8 EX-11.5", "aucun", "Dernière sauvegarde plus ancienne que le RPO", "E-C7"', 'null, "majeure", "exploitation", "CT-8 EX-11.5", "aucun", "Dernière sauvegarde plus ancienne que le RPO", "E-C7"'));
    expect(oracleFor(M)).to.equal(false);
  });
  const oracleNouvelles = (M) => {
    const rs = M.reglesCalculees(M.PARAMETRES_DEFAUT);
    const noms = new Set(rs.map((r) => r.alert));
    const t = yaml.load(M.genererTestsRegles());
    return NOUVELLES.every((n) => noms.has(n) && rs.find((r) => r.alert === n).ecart === "E-C8" && t.tests.some((x) => x.name === `${n} déclenchée`) && t.tests.some((x) => x.name === `${n} silencieuse`)) && ["noortrace_sonde_derniere_passe_s", "noortrace_extracteur_derniere_passe_s", "noortrace_tache_code", "noortrace_tache_derniere_s"].every((m) => M.metriqueAdmise(m));
  };
  it("CT-8 EX-10.9, CT-8 EX-10.7 : les onze règles nouvelles (cibles muettes up, lignes perdues, image différente, témoins de vie des outils, relectures jamais exposées, sauvegarde absente, tâche en échec) sont dans le fichier avec l'écart E-C8, chacune avec ses deux cas ; les jauges des outils et des tâches sont admises par SV-2 ; l'évaluateur réduit rejoue chaque cas des règles nouvelles sans écart", function () {
    expect(oracleNouvelles(S)).to.equal(true);
    const rs = S.reglesCalculees(S.PARAMETRES_DEFAUT);
    const t = yaml.load(S.genererTestsRegles());
    const ecarts = [];
    for (const n of NOUVELLES) for (const x of t.tests.filter((y) => y.alert_rule_test[0].alertname === n)) ecarts.push(...rejouerGroupe(x, rs.map((r) => ({ ...r, for: r.pour ?? undefined })), t.evaluation_interval));
    expect(ecarts).to.deep.equal([]);
    for (const r of rs) {
      for (const m of S.nomsMetriques(r.expr)) expect(S.metriqueAdmise(m), `${r.alert} : ${m}`).to.equal(true);
    }
    expect(new Set(rs.map((r) => r.alert)).size).to.equal(rs.length);
  });
  it("mutant CT-8 EX-10.9 : sans la jauge noortrace_tache_code dans les métriques admises, la règle noortrace_tache_echec n'est plus admise par SV-2 (tué par l'oracle)", async function () {
    const M = await importer(mutant("admises", '  noortrace_tache_code: "CT-8 EX-8.6 (E-C8)",\n', ""));
    expect(oracleNouvelles(M)).to.equal(false);
  });
});
