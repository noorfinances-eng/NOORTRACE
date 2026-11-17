// CT-5 EX-8.10 et 8.9, CT-8 10.5 (complément du 2026-11-16) : classement des
// codes du registre, refus définitif de l'ancre d'une période, alerte.
//
// - EX-8.10 : la table des codes de CT-4 §7.11 dit, pour chacun, « refus
//   définitif » ou « transitoire ». Le composant d'ancrage passe au
//   planificateur `refus_<code>` pour un code définitif (`codePlanificateur`
//   de paquets/ancrage/src/registre/classement.mjs), le code tel quel sinon.
//   Avant, tous passaient tels quels : aucun ne commençait par `refus_`, et le
//   refus d'OP-9 (`cle_chaine_non_inscrite`) de l'ancre d'une période était
//   repris avec gigue, sans l'alerte `prestataires_epuises`.
// - 8.9, CT-8 10.5 : la règle `noortrace_ancrage_prestataires_epuises_periode`
//   ne lisait que les séries du `jeton_periode` ; elle lit aussi celles de
//   l'ancre de la période (`kind="ancre_registre_periode"`), que le composant
//   exporte : le refus est compté `echec_permanente`, l'ancre `a_reprendre`.
//
// Monté sur le composant réel (serveurs RFC 3161, calendriers et nœud du
// registre factices de test/fixtures/ancrage-composant) : la clé Ed25519 du
// journal est inscrite sous une autre clé de chaîne de l'organisation que
// celle du composant, d'où le refus d'OP-9 de chaque ancre. Les règles sont
// lues dans deploiement/observabilite/ et jouées par l'évaluateur réduit des
// essais, et par promtool 3.5.0 quand il est là. Sous NOORTRACE_REVUE_RACINE,
// le composant et les règles sont lus dans cette racine (code d'avant : essai
// rouge). Les copies (mutants, fichiers de promtool) vont sous NOORTRACE_TMP
// (défaut os.tmpdir()) et sont détruites à la fin.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import yaml from "js-yaml";
import * as N from "@noortrace/noyau";
import { SignataireChaineFichier } from "@noortrace/ancrage/registre";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import { ORG, JOURNAL, attenteCalme, monterComposant, remisePoint, remiseCloture, repertoireTemporaire, enAttente } from "./fixtures/ancrage-composant/outils.mjs";
import { rejouerGroupe } from "./fixtures/supervision/promql.mjs";

const PERIODE = 1793862000; // 2026-11-05T07:00:00Z
const EVENEMENTS = { 1: 1, 20: 1, 40: 1 };
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : PROJECT_ROOT;
const COPIES = [];
const REGLE = "noortrace_ancrage_prestataires_epuises_periode";
const MAX_MS = 300000;

/** Ligne du composant qui classe le code et sa forme d'avant (code de l'`Envoyeur` tel quel). */
const LIGNE_CLASSEMENT = 'code: codePlanificateur(String(r.data.code).replace(/[^a-zA-Z0-9_-]/g, "_")).slice(0, 64) } });';
const LIGNE_AVANT = 'code: String(r.data.code).replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64) } });';

const lire = (...p) => fs.readFileSync(path.join(...p), "utf8");
const cellules = (l) => l.replace(/^\|/, "").replace(/\|\s*$/, "").split(/(?<!\\)\|/).map((c) => c.trim());

/** Copie de paquets/ancrage/src (node_modules liés), la ligne de classement remise à sa forme d'avant. */
function copieSansClassement() {
  const racine = fs.mkdtempSync(path.join(TMP, "noortrace-refus-definitif-mutant-"));
  COPIES.push(racine);
  fs.mkdirSync(path.join(racine, "paquets", "ancrage"), { recursive: true });
  fs.cpSync(path.join(RACINE, "paquets", "ancrage", "src"), path.join(racine, "paquets", "ancrage", "src"), { recursive: true });
  fs.symlinkSync(path.join(PROJECT_ROOT, "node_modules"), path.join(racine, "node_modules"));
  fs.symlinkSync(path.join(PROJECT_ROOT, "paquets", "ancrage", "node_modules"), path.join(racine, "paquets", "ancrage", "node_modules"));
  const f = path.join(racine, "paquets", "ancrage", "src", "composant.mjs");
  const texte = fs.readFileSync(f, "utf8");
  expect(texte.split(LIGNE_CLASSEMENT).length - 1, "ligne de classement du composant").to.equal(1);
  fs.writeFileSync(f, texte.replace(LIGNE_CLASSEMENT, () => LIGNE_AVANT));
  return racine;
}

/** Séries exposées par le composant : nom et étiquettes → valeur. */
function series(texte) {
  const out = [];
  for (const l of texte.split("\n")) {
    const m = /^([a-z_]+)(?:\{([^}]*)\})? (\S+)$/.exec(l);
    if (!m) continue;
    const et = {};
    for (const p of (m[2] ?? "").split(",").filter(Boolean)) {
      const [k, v] = p.split("=");
      et[k] = v.replace(/^"|"$/g, "");
    }
    out.push({ nom: m[1], et, valeur: Number(m[3]) });
  }
  return out;
}

/**
 * Rejoue la période (points, point de clôture, clôture), puis avance de douze minutes : chaque ancre est refusée par
 * OP-9 (la clé Ed25519 du journal est inscrite sous une autre clé de chaîne de l'organisation). Rend l'état utile.
 */
async function parcours({ racineComposant = RACINE === PROJECT_ROOT ? null : RACINE } = {}) {
  const dir = repertoireTemporaire("noortrace-ancrage-refus-definitif-");
  const autre = N.sha256(N.utf8("noortrace/essai/refus-definitif/autre-cle-ed25519"));
  const m = await monterComposant({ dir, periodStart: PERIODE, evenements: EVENEMENTS, racineComposant, registreOptions: { clePublique: autre } });
  if (m.condition) {
    fs.rmSync(dir, { recursive: true, force: true });
    return { condition: m.condition };
  }
  let composant = null;
  try {
    const cleB = new SignataireChaineFichier(N.sha256(N.utf8("noortrace/essai/refus-definitif/cle-chaine-b")));
    m.registre.noeud.inscrire({ orgId: ORG, chainKey: cleB.adresse(), ed25519PubKey: N.octetsVersHex(m.serie.clePublique), journalId: JOURNAL });
    composant = m.creer();
    const calme = attenteCalme(composant);
    await composant.demarrer();
    for (const point of m.serie.points) {
      await m.horloge.aller(N.decoderHorodatage(point.checkpoint_ts), calme);
      m.remis.push(point);
      expect((await composant.remettrePoint(remisePoint(point))).admis, point.checkpoint_ts).to.equal(true);
      await calme();
    }
    expect((await composant.remettreCloture(remiseCloture(m.serie))).admis).to.equal(true);
    await calme();
    await m.horloge.avancer(720000, calme);
    const etat = {
      ancre: composant.demandes().find((d) => d.kind === "ancre_registre_periode"),
      ancresPoints: composant.demandes().filter((d) => d.kind === "ancre_registre_point"),
      alertes: m.journal.lignes.filter((l) => l.event === "alerte_prestataires_epuises").map((l) => ({ ...l.data, level: l.level })),
      reprises: m.journal.de("anchor_retry").map((l) => l.data),
      refus: m.journal.de("anchor_refused").map((l) => l.data),
      envoyeur: m.journal.de("registry_send_failed").map((l) => l.data),
      metriques: composant.metriques(),
    };
    await composant.arreter({ attendre: false });
    return etat;
  } finally {
    if (composant?.etat().demarre) await composant.arreter({ attendre: false });
    await m.fermer();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** Règles du fichier livré (deploiement/observabilite/regles-noortrace.yml de RACINE). */
const regles = () => yaml.load(lire(RACINE, "deploiement", "observabilite", "regles-noortrace.yml")).groups.flatMap((g) => g.rules);

const E = { instance: "127.0.0.1:8500", job: "enregistreur", role: "active" };
const serie = (nom, et) => `${nom}{${Object.entries(et).sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => `${k}="${v}"`).join(", ")}}`;
const QUEUE = serie("noortrace_anchoring_queue_entries", { ...E, kind: "ancre_registre_periode", state: "a_reprendre" });
const TENT = (outcome) => serie("noortrace_anchoring_attempts_total", { ...E, kind: "ancre_registre_periode", outcome, provider: "registre" });

/** Cas des tests de la règle pour la branche de l'ancre de la période ; `attendue` : alerte levée ou non. */
function casRegle(r) {
  const exp = [{ exp_labels: { ...r.labels, ...E, kind: "ancre_registre_periode", state: "a_reprendre" }, exp_annotations: r.annotations }];
  const g = (nom, series, leve) => ({ name: nom, interval: "1m", input_series: series.map(([s, v]) => ({ series: s, values: v })), alert_rule_test: [{ eval_time: "6m", alertname: REGLE, exp_alerts: leve ? exp : [] }] });
  return [
    g("refus définitif de l'ancre d'une période : levée", [[QUEUE, "1x10"], [TENT("echec_permanente"), "0 0 0 1 1 1 1"]], true),
    g("refus définitif, compteur né à 1 (première occurrence) : levée", [[QUEUE, "1x10"], [TENT("echec_permanente"), "_ _ _ 1x10"]], true),
    g("échec transitoire de l'ancre d'une période : silencieuse", [[QUEUE, "1x10"], [TENT("echec_transitoire"), "0 0 0 1 1 1 1"]], false),
    g("aucun refus, compteur à 0 immobile : silencieuse", [[QUEUE, "1x10"], [TENT("echec_permanente"), "0x10"]], false),
  ];
}

after(function () {
  for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
});

describe("CT-5 EX-8.10 : codes du registre classés « refus définitif » ou « transitoire » ; refus d'OP-9 de l'ancre d'une période (complément du 2026-11-16)", function () {
  this.timeout(300000);

  it("la table d'EX-8.10 classe chaque code de la table de CT-4 §7.11 ; le composant préfixe refus_ exactement aux codes « refus définitif » et passe les autres tels quels", async function () {
    const ct5 = lire(PROJECT_ROOT, "spec", "CT-5-ancrage.md");
    const debut = ct5.indexOf("| Code de CT-4 §7.11 | Classement | Motif |");
    expect(debut).to.be.above(0);
    const lignes = ct5.slice(debut).split("\n").slice(2);
    const classes = new Map();
    for (const l of lignes) {
      if (!l.startsWith("|")) break;
      const [codes, classe] = cellules(l);
      for (const c of codes.replace(/\([^)]*\)/g, "").match(/`[a-z0-9_]+`/g)) classes.set(c.replaceAll("`", ""), classe);
    }
    const ct4 = lire(PROJECT_ROOT, "spec", "CT-4-registre.md");
    const t74 = ct4.slice(ct4.indexOf("### 7.11 "), ct4.indexOf("### 7.12 "));
    const codesCt4 = new Set();
    for (const l of t74.split("\n").filter((x) => x.startsWith("| `"))) for (const c of cellules(l)[0].match(/`[a-z0-9_]+`/g)) codesCt4.add(c.replaceAll("`", ""));
    expect(codesCt4.size).to.be.above(40);
    expect([...codesCt4].filter((c) => !classes.has(c)), "codes de CT-4 §7.11 absents de la table d'EX-8.10").to.deep.equal([]);
    const { CODES_REFUS_DEFINITIF, codePlanificateur } = await import(pathToFileURL(path.join(RACINE, "paquets", "ancrage", "src", "registre", "classement.mjs")).href);
    const definitifs = [...classes].filter(([, c]) => c === "refus définitif").map(([k]) => k).sort();
    expect([...CODES_REFUS_DEFINITIF].sort()).to.deep.equal(definitifs);
    expect(definitifs).to.include("cle_chaine_non_inscrite");
    for (const [code, classe] of classes) expect(codePlanificateur(code), code).to.equal(classe === "refus définitif" ? `refus_${code}` : code);
    expect(codePlanificateur("refus_emetteur_inconnu")).to.equal("refus_emetteur_inconnu");
  });

  it("refus d'OP-9 de l'ancre d'une période : tentatives echec_permanente de code refus_cle_chaine_non_inscrite, reprise à retry.max_ms exactement (sans gigue), une seule alerte prestataires_epuises critique ; les ancres des points refusees (alerte majeure) ; l'exportateur compte le refus et la règle de CT-8 se lève sur ses séries", async function () {
    const e = await parcours();
    if (e.condition) return enAttente(this, e.condition);
    // L'Envoyeur rend le code de CT-4 §7.11 ; le composant le passe classé au planificateur.
    expect(e.envoyeur.filter((l) => l.request_id === e.ancre.id).map((l) => l.code)).to.include("cle_chaine_non_inscrite");
    expect(e.ancre.state).to.equal("a_reprendre");
    expect(e.ancre.attempts.length).to.be.at.least(2);
    for (const a of e.ancre.attempts) {
      expect([a.outcome, a.error_code]).to.deep.equal(["echec_permanente", "refus_cle_chaine_non_inscrite"]);
      // L'échec est consigné (anchor_retry, instant `at`) quand l'Envoyeur rend son refus ; la reprise est à retry.max_ms
      // de cet instant, exactement.
      const ligne = e.reprises.find((l) => l.request_id === e.ancre.id && l.attempt === a.n);
      expect(ligne?.error_code).to.equal("refus_cle_chaine_non_inscrite");
      expect(N.decoderHorodatage(a.next_at) - N.decoderHorodatage(ligne.at), "attente sans gigue").to.equal(MAX_MS);
    }
    expect(e.alertes.filter((a) => a.request_id === e.ancre.id).map((a) => [a.severity, a.level])).to.deep.equal([["critique", "error"]]);
    expect(e.ancresPoints.length).to.be.at.least(1);
    for (const p of e.ancresPoints) expect([p.state, p.attempts.at(-1).error_code]).to.deep.equal(["refusee", "refus_cle_chaine_non_inscrite"]);
    expect(e.refus.map((r) => r.error_code).every((c) => c === "refus_cle_chaine_non_inscrite")).to.equal(true);
    // Exportateur (CT-5 EX-8.15) : séries que la règle de CT-8 lit.
    const s = series(e.metriques);
    const file = s.find((x) => x.nom === "noortrace_anchoring_queue_entries" && x.et.kind === "ancre_registre_periode" && x.et.state === "a_reprendre");
    const refus = s.find((x) => x.nom === "noortrace_anchoring_attempts_total" && x.et.kind === "ancre_registre_periode" && x.et.provider === "registre" && x.et.outcome === "echec_permanente");
    expect(file?.valeur).to.equal(1);
    expect(refus?.valeur).to.equal(e.ancre.attempts.length);
    const r = regles().find((x) => x.alert === REGLE);
    const g = { name: "séries exportées", interval: "1m", input_series: [{ series: QUEUE, values: "1x10" }, { series: TENT("echec_permanente"), values: `0 0 0 ${refus.valeur}x7` }], alert_rule_test: [{ eval_time: "6m", alertname: REGLE, exp_alerts: [{ exp_labels: { ...r.labels, ...E, kind: "ancre_registre_periode", state: "a_reprendre" }, exp_annotations: r.annotations }] }] };
    expect(rejouerGroupe(g, regles(), "1m")).to.deep.equal([]);
  });

  it("mutant (composant : code de l'Envoyeur passé tel quel, comme avant) : refus repris comme un échec transitoire, avec gigue, et aucune alerte (tué)", async function () {
    const e = await parcours({ racineComposant: copieSansClassement() });
    if (e.condition) return enAttente(this, e.condition);
    // Les ancres des points parties, refusées par OP-9, restent a_reprendre ; celle de la période attend leur reçu (EX-9.4).
    // CT-5 EX-9.4 et EX-9.5 (complément du 2026-11-16, l'ancre d'un point en reprise quand le point suivant de sa période
    // est admis) : un refus repris comme transitoire a pu être admis ; les ancres des points suivants ne partent pas avant
    // celle qu'il laisse a_reprendre : retenues sans tentative, elles attendent (a_envoyer) ou sont remplacées par la plus
    // récente (remplacee).
    const parties = e.ancresPoints.filter((p) => p.attempts.length > 0);
    expect(parties.length).to.be.at.least(1);
    for (const p of e.ancresPoints.filter((x) => x.attempts.length === 0)) expect(["a_envoyer", "remplacee"]).to.include(p.state);
    const attentes = [];
    for (const p of parties) {
      expect(p.state).to.equal("a_reprendre");
      for (const a of p.attempts) {
        expect([a.outcome, a.error_code]).to.deep.equal(["echec_transitoire", "cle_chaine_non_inscrite"]);
        const ligne = e.reprises.find((l) => l.request_id === p.id && l.attempt === a.n);
        attentes.push(N.decoderHorodatage(a.next_at) - N.decoderHorodatage(ligne.at));
      }
    }
    expect(attentes.length).to.be.above(0);
    expect(attentes.every((d) => d !== MAX_MS)).to.equal(true);
    expect(e.alertes).to.deep.equal([]);
  });
});

describe("CT-8 10.5 : la règle noortrace_ancrage_prestataires_epuises_periode se lève aussi au refus définitif de l'ancre d'une période (complément du 2026-11-16)", function () {
  this.timeout(300000);

  it("évaluateur réduit : levée sur les séries de l'ancre de la période (refus, compteur né à 1), silencieuse sur un échec transitoire ou un compteur à 0 immobile ; la branche du jeton de la période reste celle des tests du fichier livré", function () {
    const R = regles();
    const r = R.find((x) => x.alert === REGLE);
    expect(r.labels).to.include({ severity: "critique", component: "ancrage", runbook: "RB-4" });
    const ecarts = casRegle(r).flatMap((g) => rejouerGroupe(g, R, "1m"));
    expect(ecarts).to.deep.equal([]);
    const t = yaml.load(lire(RACINE, "deploiement", "observabilite", "tests-regles.yml"));
    expect(t.tests.filter((x) => x.alert_rule_test[0].alertname === REGLE).map((x) => x.name)).to.deep.equal([`${REGLE} déclenchée`, `${REGLE} silencieuse`]);
  });

  it("mutant (règle d'avant, séries du jeton de la période seules) : le refus de l'ancre de la période ne la lève pas (tué)", function () {
    const R = regles().map((x) => (x.alert === REGLE ? { ...x, expr: 'noortrace_anchoring_queue_entries{kind="jeton_periode",state="a_reprendre"} > 0 and on () ((noortrace_anchoring_attempts_total{kind="jeton_periode",outcome="echec_permanente"} unless noortrace_anchoring_attempts_total{kind="jeton_periode",outcome="echec_permanente"} offset 1h) or increase(noortrace_anchoring_attempts_total{kind="jeton_periode",outcome="echec_permanente"}[1h])) > 0' } : x));
    const r = R.find((x) => x.alert === REGLE);
    expect(rejouerGroupe(casRegle(r)[0], R, "1m")).to.not.deep.equal([]);
  });

  it("promtool 3.5.0 : check rules sur le fichier livré, puis test rules sur les quatre cas de la branche de l'ancre de la période", function () {
    const bin = process.env.NOORTRACE_PROMTOOL || "promtool";
    const v = spawnSync(bin, ["--version"], { encoding: "utf8" });
    if (v.error || v.status !== 0 || !/promtool, version 3\.5\.0 /.test(v.stdout + v.stderr)) {
      this.test.title += " — en attente : promtool 3.5.0 absent (NOORTRACE_PROMTOOL ou PATH)";
      this.skip();
    }
    const dir = fs.mkdtempSync(path.join(TMP, "noortrace-refus-definitif-promtool-"));
    COPIES.push(dir);
    const fichier = path.join(RACINE, "deploiement", "observabilite", "regles-noortrace.yml");
    fs.copyFileSync(fichier, path.join(dir, "regles-noortrace.yml"));
    const r = regles().find((x) => x.alert === REGLE);
    fs.writeFileSync(path.join(dir, "tests.yml"), yaml.dump({ rule_files: ["regles-noortrace.yml"], evaluation_interval: "1m", tests: casRegle(r) }));
    const c = spawnSync(bin, ["check", "rules", path.join(dir, "regles-noortrace.yml")], { encoding: "utf8" });
    expect(c.status, c.stdout + c.stderr).to.equal(0);
    const t = spawnSync(bin, ["test", "rules", path.join(dir, "tests.yml")], { encoding: "utf8", cwd: dir });
    expect(t.status, t.stdout + t.stderr).to.equal(0);
  });
});
