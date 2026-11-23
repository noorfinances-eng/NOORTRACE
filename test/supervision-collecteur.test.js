import { expect } from "chai";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import yaml from "js-yaml";
import { lireEvenements } from "@noortrace/enregistreur";
import {
  CONDITION_PROMETHEUS, COLLECTE_REFERENCE, REGLES_REFERENCE, SHA256_ARCHIVE, VERSION_PROMETHEUS, Collecteur, ClientCollecteur, ExpositionFichiers,
  binairePrometheus, configurationCollecte, reduireFor, reunirExpositions, secondes,
} from "../scripts/deploiement/collecteur.mjs";
import { membreCompare, instantsReleves } from "../scripts/deploiement/mesure-supervision.mjs";
import { RACINE, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { BIN_CTL, PROVOCATIONS, monterSupervision, demonterSupervision, jouerProvocation, lireSupervision, portLibre } from "./fixtures/supervision-collecteur/montage.mjs";

// SUPERVISION EN MARCHE (CT-8 §10.2, EX-10.4, EX-10.10 ; CT-9 TE-17, TM-34,
// TM-35, part du collecteur de TA-29 et de TA-75) : le collecteur Prometheus
// 3.5.0 lancé par scripts/deploiement/collecteur.mjs sur une installation
// locale, chargé des règles de référence, et l'état des alertes lu par son
// API. Le binaire `prometheus` vient de la même archive officielle que
// `promtool` (SHA-256 fixé, CT-8 EX-10.10) ; il est donné par
// NOORTRACE_PROMETHEUS (ou le PATH). Sans lui, les essais qui lancent le
// collecteur sont en attente, condition nommée (CT-9 EX-3.11). Aucun essai ne
// joint un réseau public : tout écoute sur l'adresse de bouclage.
//
// TE-17 se joue en temps réel, à l'intervalle d'évaluation de la collecte de
// référence (15 s) : il dure une trentaine de minutes. Sa provocation
// « stockage » fait passer l'espace libre du système de fichiers de
// storage.root sous le seuil par un lest de 256 Mio au plus : sur une machine
// dont le disque sert d'autres charges, NOORTRACE_SUPERVISION_STOCKAGE désigne
// un répertoire d'un système de fichiers que rien d'autre n'emploie (le
// stockage du démon y est créé, puis retiré). NOORTRACE_RAPPORT_TE17 désigne
// le fichier où écrire le rapport d'exécution ; NOORTRACE_TRACE_SUPERVISION
// fait suivre les provocations sur la sortie d'erreur.

const OUTILS = path.join(RACINE, "scripts", "deploiement");
const SPEC = path.join(RACINE, "spec");
const CT2 = fs.readFileSync(path.join(SPEC, "CT-2-enregistreur.md"), "utf8");
const CT5 = fs.readFileSync(path.join(SPEC, "CT-5-ancrage.md"), "utf8");
const CT8 = fs.readFileSync(path.join(SPEC, "CT-8-deploiement-et-exploitation.md"), "utf8");
const REGLES = yaml.load(fs.readFileSync(REGLES_REFERENCE, "utf8")).groups.flatMap((g) => g.rules);
const PROMETHEUS = binairePrometheus();
const TRAVAIL = repertoireTemporaire("noortrace-test-collecteur-");
after(() => fs.rmSync(TRAVAIL, { recursive: true, force: true }));

const outil = (nom, args, o = {}) => spawnSync(process.execPath, [path.join(OUTILS, nom), ...args], { encoding: "utf8", cwd: RACINE, ...o });
/** Même lancement sans bloquer la boucle d'événements (serveurs locaux de ce processus) : { code, err }. */
const outilAsync = (nom, args) => new Promise((res) => {
  const p = spawn(process.execPath, [path.join(OUTILS, nom), ...args], { cwd: RACINE, stdio: ["ignore", "ignore", "pipe"] });
  let err = "";
  p.stderr.on("data", (x) => (err += x));
  p.on("close", (code) => res({ code, err }));
});
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const section = (texte, debut, fin) => {
  const i = texte.indexOf(debut);
  if (i < 0) throw new Error(`section introuvable : ${debut}`);
  return texte.slice(i, texte.indexOf(fin, i + debut.length));
};
/** Cellules d'une ligne de table Markdown (« \| » rendu par « | »). */
function cellules(l) {
  const out = [];
  let cur = "";
  for (let i = 1; i < l.length - 1; i++) {
    if (l[i] === "\\" && l[i + 1] === "|") { cur += "|"; i++; continue; }
    if (l[i] === "|") { out.push(cur.trim()); cur = ""; continue; }
    cur += l[i];
  }
  out.push(cur.trim());
  return out;
}
/** Gravité de chaque règle dans les tables de CT-8 §10.4 à §10.7, qui font foi (EX-10.1). */
const GRAVITE_TABLE = new Map();
for (const [a, b] of [["### 10.4 ", "### 10.5 "], ["### 10.5 ", "### 10.6 "], ["### 10.6 ", "### 10.7 "], ["### 10.7 ", "### 10.8 "]]) {
  for (const l of section(CT8, a, b).split("\n")) {
    if (!l.startsWith("| `noortrace_")) continue;
    const c = cellules(l);
    GRAVITE_TABLE.set(c[0].replaceAll("`", ""), c[3].split(" ")[0]);
  }
}
/** Marque l'essai courant en attente, condition dans le titre (CT-9 EX-3.11). */
function enAttente(ctx, condition) {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
}
const sansPrometheus = (ctx) => {
  if (!PROMETHEUS.ok) enAttente(ctx, PROMETHEUS.condition);
};
/** Forme d'un rapport de mesure : membres exigés et aucun membre inconnu ($defs/rapport_mesure), hors système de référence. */
function verifierRapportMesure(r, testId, unite) {
  const d = JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", "plan-de-tests-v0.schema.json"), "utf8")).$defs;
  const forme = (o, def, ou) => {
    for (const k of def.required) expect(o, `${ou} : ${k}`).to.have.property(k);
    for (const k of Object.keys(o)) expect(Object.keys(def.properties), `${ou} : ${k}`).to.include(k);
  };
  forme(r, d.rapport_mesure, "rapport");
  forme(r.system, d.systeme, "system");
  forme(r.method, d.rapport_mesure.properties.method, "method");
  expect(r.version).to.equal(0);
  expect(r.kind).to.equal("rapport-mesure");
  expect(r.commit).to.match(/^[0-9a-f]{40}$/);
  expect(r.measured_at).to.match(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/);
  expect(r.method.percentile_method).to.equal("plus_proche_rang");
  expect(r.system.reference).to.equal(false);
  expect(r.counts_for_targets).to.equal(false);
  const noms = new Set();
  for (const l of r.results) {
    forme(l, d.resultat_mesure, l.name);
    expect(l.name).to.match(/^[a-z][a-z0-9_]*$/);
    expect(noms.has(l.name), `nom de ligne en double : ${l.name}`).to.equal(false);
    noms.add(l.name);
    expect(l.test_id, l.name).to.equal(testId);
    expect(l.unit, l.name).to.equal(unite);
    expect(l.met, l.name).to.equal(null);
    expect(l.excluded_reason, l.name).to.equal("hors_systeme_de_reference");
  }
}

describe("CT-8 §10.2, EX-10.4 : collecteur de la supervision en marche, hors collecteur lancé (scripts/deploiement/collecteur.mjs)", function () {
  const REFERENCE = fs.readFileSync(COLLECTE_REFERENCE, "utf8");

  it("configurationCollecte : les jobs, les intervalles et l'étiquette role de la collecte de référence sont gardés ; seule l'adresse de chaque cible est remplacée ; un job à null est retiré ; les règles chargées sont le fichier donné", function () {
    const ref = yaml.load(REFERENCE);
    const c = configurationCollecte(REFERENCE, { cibles: { enregistreur: "127.0.0.1:18500", hote: "127.0.0.1:19100", noorcore: null }, regles: "/chemin/regles.yml" });
    const lu = yaml.load(c.texte);
    expect(lu.global).to.deep.equal(ref.global);
    expect(c.intervalleS).to.equal(secondes(ref.global.evaluation_interval));
    expect(lu.rule_files).to.deep.equal(["/chemin/regles.yml"]);
    expect(c.jobs).to.deep.equal(["enregistreur", "hote"]);
    expect(c.retires).to.deep.equal(["noorcore"]);
    for (const s of lu.scrape_configs) {
      const r = ref.scrape_configs.find((x) => x.job_name === s.job_name);
      expect(s.static_configs[0].labels, s.job_name).to.deep.equal(r.static_configs[0].labels);
      expect({ ...s, static_configs: null }, s.job_name).to.deep.equal({ ...r, static_configs: null });
    }
    expect(lu.scrape_configs.map((s) => s.static_configs[0].targets)).to.deep.equal([["127.0.0.1:18500"], ["127.0.0.1:19100"]]);
    const court = yaml.load(configurationCollecte(REFERENCE, { cibles: { enregistreur: null, hote: "127.0.0.1:19100", noorcore: null }, regles: "r.yml", intervalleS: 2 }).texte);
    expect(court.global).to.deep.equal({ scrape_interval: "2s", evaluation_interval: "2s" });
  });

  it("configurationCollecte (EX-10.4) : une cible hors de l'adresse de bouclage, un job de la référence sans cible donnée, un job inconnu et un intervalle hors de 1 à 300 s sont refusés", function () {
    const cibles = { enregistreur: "127.0.0.1:18500", hote: "127.0.0.1:19100", noorcore: null };
    expect(() => configurationCollecte(REFERENCE, { cibles: { ...cibles, hote: "192.0.2.10:9100" }, regles: "r.yml" })).to.throw(/adresse de bouclage/);
    expect(() => configurationCollecte(REFERENCE, { cibles: { ...cibles, hote: "127.0.0.1:0" }, regles: "r.yml" })).to.throw(/adresse de bouclage/);
    expect(() => configurationCollecte(REFERENCE, { cibles: { enregistreur: "127.0.0.1:18500", hote: "127.0.0.1:19100" }, regles: "r.yml" })).to.throw(/job noorcore .* aucune cible donnée/);
    expect(() => configurationCollecte(REFERENCE, { cibles: { ...cibles, autre: "127.0.0.1:1" }, regles: "r.yml" })).to.throw(/cible autre : aucun job de ce nom/);
    expect(() => configurationCollecte(REFERENCE, { cibles, regles: "r.yml", intervalleS: 0 })).to.throw(/intervalle/);
  });

  it("reduireFor : seule la clause for de la règle nommée change, le reste du fichier est rendu à l'octet, l'écart est rendu pour être consigné ; règle inconnue, règle sans clause for, durée plus longue que la référence ou mal formée : refus", function () {
    const texte = fs.readFileSync(REGLES_REFERENCE, "utf8");
    const regle = REGLES.find((r) => r.alert === "noortrace_copie_worm_en_retard");
    expect(regle.for).to.equal("1h");
    const r = reduireFor(texte, { noortrace_copie_worm_en_retard: "30s" });
    expect(r.ecarts).to.deep.equal([{ regle: "noortrace_copie_worm_en_retard", reference: "1h", employee: "30s" }]);
    const avant = texte.split("\n");
    const apres = r.texte.split("\n");
    expect(apres.length).to.equal(avant.length);
    const changees = avant.flatMap((l, k) => (l === apres[k] ? [] : [[l.trim(), apres[k].trim()]]));
    expect(changees).to.deep.equal([["for: 1h", "for: 30s"]]);
    const lues = yaml.load(r.texte).groups.flatMap((g) => g.rules);
    expect(lues.filter((x) => x.alert !== regle.alert)).to.deep.equal(REGLES.filter((x) => x.alert !== regle.alert));
    expect(lues.find((x) => x.alert === regle.alert)).to.deep.equal({ ...regle, for: "30s" });
    expect(reduireFor(texte, {})).to.deep.equal({ texte, ecarts: [] });
    expect(() => reduireFor(texte, { noortrace_inconnue: "30s" })).to.throw(/0 règle de ce nom/);
    expect(() => reduireFor(texte, { noortrace_releve_externe_echec: "30s" })).to.throw(/pas de clause for/);
    expect(() => reduireFor(texte, { noortrace_copie_worm_en_retard: "2h" })).to.throw(/dépasse la clause de référence/);
    expect(() => reduireFor(texte, { noortrace_copie_worm_en_retard: "30" })).to.throw(/hors de la forme/);
    // Clauses for en jours des tables de CT-8 §10.7 (2d : relectures et sauvegarde absentes) : lues, jamais refusées.
    expect([secondes("2d"), secondes("1h"), secondes("15s")]).to.deep.equal([172800, 3600, 15]);
    for (const r of REGLES.filter((x) => x.for)) expect(secondes(r.for), r.alert).to.be.above(0);
  });

  it("ExpositionFichiers : les fichiers .prom d'un répertoire sont servis sur 127.0.0.1 par GET /metrics, réunis par ordre des noms, une famille par nom avec une seule ligne # TYPE (deux relevés d'EX-10.9 écrits dans deux fichiers) ; un autre chemin rend 404", async function () {
    const d = path.join(TRAVAIL, "textfile");
    fs.mkdirSync(d);
    fs.writeFileSync(path.join(d, "b.prom"), '# TYPE noortrace_releve_externe_ok gauge\nnoortrace_releve_externe_ok{check="console"} 1\n# TYPE noortrace_releve_externe_dernier_s gauge\nnoortrace_releve_externe_dernier_s{check="console"} 1794553200\n');
    fs.writeFileSync(path.join(d, "a.prom"), '# HELP noortrace_releve_externe_ok Relecture hors du composant\n# TYPE noortrace_releve_externe_ok gauge\nnoortrace_releve_externe_ok{check="registre_gels"} 0\n');
    fs.writeFileSync(path.join(d, "ignore.txt"), "noortrace_hors_exposition 1\n");
    const attendu = [
      "# HELP noortrace_releve_externe_ok Relecture hors du composant",
      "# TYPE noortrace_releve_externe_ok gauge",
      'noortrace_releve_externe_ok{check="registre_gels"} 0',
      'noortrace_releve_externe_ok{check="console"} 1',
      "# TYPE noortrace_releve_externe_dernier_s gauge",
      'noortrace_releve_externe_dernier_s{check="console"} 1794553200',
      "",
    ].join("\n");
    const f = new ExpositionFichiers(d);
    expect(f.exposer()).to.equal(attendu);
    const adresse = await f.demarrer();
    try {
      expect(adresse).to.match(/^127\.0\.0\.1:[0-9]+$/);
      const rep = await fetch(`http://${adresse}/metrics`);
      expect(rep.status).to.equal(200);
      expect(await rep.text()).to.equal(attendu);
      expect((await fetch(`http://${adresse}/autre`)).status).to.equal(404);
    } finally {
      await f.arreter();
    }
    // Histogramme : ses séries _bucket, _sum et _count restent sous sa famille.
    const h = '# TYPE x_ms histogram\nx_ms_bucket{le="1"} 0\nx_ms_bucket{le="+Inf"} 2\nx_ms_sum 7\nx_ms_count 2\n';
    expect(reunirExpositions([h, "# TYPE y gauge\ny 1\n"])).to.equal(`${h}# TYPE y gauge\ny 1\n`);
    expect(reunirExpositions([])).to.equal("");
  });

  it("collecteur.mjs : sans commande, commande inconnue, option inconnue, alerte sans --en-moins-de → 2 ; lancer sans binaire Prometheus 3.5.0 → 3, condition nommée sur la sortie d'erreur ; l'archive de référence est celle d'EX-10.10", function () {
    for (const args of [[], ["autre"], ["lancer", "--inconnue"], ["alerte", "--url", "http://127.0.0.1:1", "--nom", "noortrace_fourche"], ["alerte", "--url", "http://127.0.0.1:1", "--nom", "noortrace_fourche", "--en-moins-de", "5", "--etat", "resolue"]]) {
      const r = outil("collecteur.mjs", args);
      expect(r.status, args.join(" ")).to.equal(2);
      expect(r.stderr, args.join(" ")).to.match(/^Erreur : .*\nUsage : /);
    }
    const absent = outil("collecteur.mjs", ["lancer", "--travail", path.join(TRAVAIL, "absent"), "--cible", "enregistreur=aucune"], { env: { ...process.env, NOORTRACE_PROMETHEUS: path.join(TRAVAIL, "aucun-binaire") } });
    expect(absent.status).to.equal(3);
    expect(absent.stderr).to.equal(`Condition absente : ${CONDITION_PROMETHEUS}\n`);
    expect(binairePrometheus({ chemin: process.execPath })).to.deep.equal({ ok: false, condition: `${CONDITION_PROMETHEUS} ; le binaire trouvé n'est pas de la version ${VERSION_PROMETHEUS}` });
    expect(VERSION_PROMETHEUS).to.equal("3.5.0");
    expect(CT8).to.include(SHA256_ARCHIVE);
    expect(fs.readFileSync(path.join(RACINE, ".github", "workflows", "ci.yml"), "utf8")).to.include(`${SHA256_ARCHIVE}  `);
  });

  it("alerte : un collecteur injoignable rend le code 1 et le dit, sans attendre le délai", function () {
    const r = outil("collecteur.mjs", ["alerte", "--url", "http://127.0.0.1:1", "--nom", "noortrace_fourche", "--en-moins-de", "30"]);
    expect(r.status).to.equal(1);
    expect(r.stderr).to.match(/^Erreur : collecteur injoignable \(alerts\)/);
  });
});

describe("CT-8 EX-10.4, EX-10.10 : Prometheus 3.5.0 en marche, règles de référence chargées, état des alertes lu par l'API (part du collecteur de CT-9 TA-29 et TA-75)", function () {
  this.timeout(300000);
  const INTERVALLE = 2;
  let dir;
  let fichiers;
  let c;
  let temoins;
  const ecrire = (nom, texte) => {
    const f = path.join(dir, "textfile", nom);
    fs.writeFileSync(`${f}.tmp`, texte);
    fs.renameSync(`${f}.tmp`, f);
  };
  // Témoins de vie de l'extracteur des journaux (CT-8 EX-10.5) et de la sonde (EX-10.7) : toute installation de
  // supervision les expose, et les règles noortrace_extracteur_muet et noortrace_sonde_muette de la table de 10.7
  // (absent(…) ou témoin figé depuis plus de 120 s, sans clause for) se déclenchent dès la première évaluation sans
  // eux. Ce montage n'a ni extracteur ni sonde : il écrit leurs témoins, tenus à jour à chaque seconde, pour que la
  // seule alerte de ses essais soit celle qu'ils provoquent. TE-17 et TM-34 lancent l'extracteur et la sonde réels.
  const ecrireTemoins = () => {
    const t = Math.floor(Date.now() / 1000);
    ecrire("temoins.prom", `# TYPE noortrace_extracteur_derniere_passe_s gauge\nnoortrace_extracteur_derniere_passe_s ${t}\n# TYPE noortrace_sonde_derniere_passe_s gauge\nnoortrace_sonde_derniere_passe_s ${t}\n`);
  };

  before(async function () {
    if (!PROMETHEUS.ok) return;
    dir = path.join(TRAVAIL, "marche");
    fs.mkdirSync(path.join(dir, "textfile"), { recursive: true });
    ecrireTemoins();
    temoins = setInterval(ecrireTemoins, 1000);
    fichiers = new ExpositionFichiers(path.join(dir, "textfile"));
    // Intervalle de 2 s et clause for de la copie WORM réduite à 10 s : écarts déclarés, pour des essais courts ; TE-17 garde la référence.
    c = await Collecteur.demarrer({ travail: path.join(dir, "collecteur"), cibles: { enregistreur: null, hote: await fichiers.demarrer(), noorcore: null }, intervalleS: INTERVALLE, reduireFor: { noortrace_copie_worm_en_retard: "10s" } });
    // Première collecte : Prometheus évalue ses règles dès qu'elles sont chargées, avant la première collecte de la
    // cible (jusqu'à un intervalle et demi plus tard) ; tant qu'elle n'a pas eu lieu, les témoins sont absents et les
    // deux règles de témoin se déclenchent. Les essais commencent une fois la cible collectée et ces règles résolues.
    for (let k = 0; k < 60 && (await c.cibles())[0]?.sante !== "up"; k++) await pause(500);
    for (const nom of ["noortrace_extracteur_muet", "noortrace_sonde_muette"]) {
      const s = await c.attendreSilence(nom, { delaiS: 6 * INTERVALLE, aucunePending: true });
      if (!s.silencieuse) throw new Error(`${nom} encore déclenchée après la première collecte des témoins : ${JSON.stringify(s.vues)}`);
    }
  });
  after(async function () {
    clearInterval(temoins);
    await c?.arreter();
    await fichiers?.arreter();
  });
  beforeEach(function () {
    sansPrometheus(this);
  });

  it("le collecteur lancé est Prometheus 3.5.0 à l'empreinte fixée ; les 99 règles de référence (une par ligne des tables de CT-8 §10.4 à §10.7) sont chargées en quatre groupes, un par table, chacun dans l'ordre du fichier, toutes saines, avec leur clause for et leurs étiquettes ; la cible hote porte l'étiquette role ; l'écart de clause for est consigné", async function () {
    expect(PROMETHEUS).to.include({ ok: true, version: "3.5.0" });
    const info = await c.api("status/buildinfo");
    expect(info.version).to.equal("3.5.0");
    const regles = await c.regles();
    expect(regles.length).to.equal(REGLES.length);
    expect(REGLES.length).to.equal(99);
    expect(regles.map((r) => r.nom).sort()).to.deep.equal(REGLES.map((r) => r.alert).sort());
    const groupes = yaml.load(fs.readFileSync(REGLES_REFERENCE, "utf8")).groups;
    expect(groupes.length).to.equal(4);
    for (const g of groupes) expect(regles.filter((r) => r.groupe === g.name).map((r) => r.nom), g.name).to.deep.equal(g.rules.map((r) => r.alert));
    expect(c.ecarts).to.deep.equal([{ regle: "noortrace_copie_worm_en_retard", reference: "1h", employee: "10s" }]);
    for (const r of regles) {
      const ref = REGLES.find((x) => x.alert === r.nom);
      expect(r.for_s, r.nom).to.equal(r.nom === "noortrace_copie_worm_en_retard" ? 10 : ref.for ? secondes(ref.for) : 0);
      expect(r.etiquettes, r.nom).to.deep.equal(ref.labels);
    }
    let saines = [];
    for (let k = 0; k < 20 && saines.length !== REGLES.length; k++) {
      await pause(500);
      saines = (await c.regles()).filter((r) => r.sante === "ok");
    }
    expect(saines.length, "règles évaluées sans erreur").to.equal(REGLES.length);
    let cibles = [];
    for (let k = 0; k < 20 && cibles[0]?.sante !== "up"; k++) {
      await pause(500);
      cibles = await c.cibles();
    }
    expect(cibles).to.deep.equal([{ job: "hote", adresse: fichiers.adresse, role: "hote", sante: "up", erreur: null }]);
    expect(c.jobsRetires).to.deep.equal(["enregistreur", "noorcore"]);
  });

  it("« telle alerte est levée en moins de N secondes » : jauge noortrace_releve_externe_ok{check=\"registre_gels\"} à 0 → noortrace_releve_externe_echec déclenchée (critique, component exploitation, exigence CT-8 EX-10.9) ; jauge à 1 → résolue ; aucune série : levee faux à l'échéance ; la ligne de commande alerte rend 0 puis 1", async function () {
    const nom = "noortrace_releve_externe_echec";
    const absente = await c.attendreAlerte(nom, { delaiS: 3 * INTERVALLE });
    expect(absente).to.deep.include({ levee: false, alerte: null, vues: [] });
    expect(absente.apres_s).to.be.at.least(3 * INTERVALLE);
    ecrire("releve.prom", '# TYPE noortrace_releve_externe_ok gauge\nnoortrace_releve_externe_ok{check="registre_gels"} 0\n');
    const r = await c.attendreAlerte(nom, { delaiS: 6 * INTERVALLE, etiquettes: { check: "registre_gels" } });
    expect(r.levee, JSON.stringify(r.vues)).to.equal(true);
    expect(r.apres_s).to.be.below(6 * INTERVALLE);
    expect(r.alerte).to.include({ nom, etat: "firing", valeur: 0 });
    expect(r.alerte.etiquettes).to.deep.equal({ alertname: nom, check: "registre_gels", component: "exploitation", exigence: "CT-8 EX-10.9", instance: fichiers.adresse, job: "hote", role: "hote", runbook: "aucun", severity: "critique" });
    // Une autre étiquette que celle de la série : pas d'alerte.
    expect((await c.attendreAlerte(nom, { delaiS: 1, etiquettes: { check: "console" } })).levee).to.equal(false);
    const cli = outil("collecteur.mjs", ["alerte", "--url", c.url, "--nom", nom, "--en-moins-de", "10", "--etiquette", "check=registre_gels"]);
    expect(cli.status, cli.stderr).to.equal(0);
    expect(JSON.parse(cli.stdout)).to.deep.include({ levee: true });
    ecrire("releve.prom", '# TYPE noortrace_releve_externe_ok gauge\nnoortrace_releve_externe_ok{check="registre_gels"} 1\n');
    const s = await c.attendreSilence(nom, { delaiS: 6 * INTERVALLE });
    expect(s.silencieuse, JSON.stringify(s.vues)).to.equal(true);
    const cli2 = outil("collecteur.mjs", ["alerte", "--url", c.url, "--nom", nom, "--en-moins-de", "3"]);
    expect(cli2.status).to.equal(1);
    expect(JSON.parse(cli2.stdout)).to.deep.include({ levee: false, alerte: null });
  });

  it("clause for : noortrace_worm_copy_pending ≥ 1 → noortrace_copie_worm_en_retard en cours de clause (pending) puis déclenchée à l'échéance et pas avant ; métrique revenue à 0 → résolue ; métrique jamais mise à jour (0) pendant plus que l'échéance : ni pending ni déclenchée", async function () {
    const nom = "noortrace_copie_worm_en_retard";
    const serie = (v) => ecrire("worm.prom", `# TYPE noortrace_worm_copy_pending gauge\nnoortrace_worm_copy_pending ${v}\n`);
    serie(0);
    const jamais = await c.attendreAlerte(nom, { delaiS: 10 + 3 * INTERVALLE, etat: "pending" });
    expect(jamais.levee, "réponse retirée : métrique jamais mise à jour").to.equal(false);
    expect(jamais.vues).to.deep.equal([]);
    serie(1);
    const pending = await c.attendreAlerte(nom, { delaiS: 6 * INTERVALLE, etat: "pending" });
    expect(pending.levee, JSON.stringify(pending.vues)).to.equal(true);
    const active = Date.parse(pending.alerte.active_depuis);
    const firing = await c.attendreAlerte(nom, { delaiS: 10 + 6 * INTERVALLE });
    expect(firing.levee, JSON.stringify(firing.vues)).to.equal(true);
    expect(firing.alerte.etiquettes).to.include({ severity: "majeure", component: "enregistreur", runbook: "RB-5", exigence: "CT-2 §17.4 Copie WORM en retard" });
    // Pas avant l'échéance : l'état déclenché n'est vu qu'une fois la clause for (10 s) écoulée depuis l'instant d'activation.
    expect(Date.now() - active).to.be.at.least(10000);
    serie(0);
    const s = await c.attendreSilence(nom, { delaiS: 6 * INTERVALLE, aucunePending: true });
    expect(s.silencieuse, JSON.stringify(s.vues)).to.equal(true);
  });

  it("transitions (décompte de CT-9 TE-17) : deux séries d'une même règle déclenchées ensemble comptent une transition, toutes étiquettes confondues ; une seconde levée après résolution en compte une de plus ; une règle déjà déclenchée au début de la fenêtre compte zéro ; la gravité relevée est celle de la règle", async function () {
    const nom = "noortrace_releve_externe_echec";
    const serie = (a, b) => ecrire("releve.prom", `# TYPE noortrace_releve_externe_ok gauge\nnoortrace_releve_externe_ok{check="registre_gels"} ${a}\nnoortrace_releve_externe_ok{check="console"} ${b}\n`);
    serie(1, 1);
    await c.attendreSilence(nom, { delaiS: 6 * INTERVALLE });
    await pause(2 * INTERVALLE * 1000);
    const debut = Math.floor(Date.now() / 1000);
    await pause(1100);
    serie(0, 0);
    const deux = await c.attendreAlerte(nom, { delaiS: 6 * INTERVALLE });
    expect(deux.levee).to.equal(true);
    await pause(2 * INTERVALLE * 1000);
    expect((await c.alertes()).filter((a) => a.nom === nom && a.etat === "firing").length).to.equal(2);
    const milieu = Math.floor(Date.now() / 1000);
    serie(1, 1);
    expect((await c.attendreSilence(nom, { delaiS: 6 * INTERVALLE })).silencieuse).to.equal(true);
    await pause(2 * INTERVALLE * 1000);
    serie(0, 1);
    expect((await c.attendreAlerte(nom, { delaiS: 6 * INTERVALLE })).levee).to.equal(true);
    await pause(2 * INTERVALLE * 1000);
    const fin = Math.ceil(Date.now() / 1000);
    const tout = await c.transitions(debut, fin, 1);
    expect(tout.get(nom)).to.deep.include({ transitions: 2, declenchee_au_debut: false, gravites: ["critique"] });
    expect([...tout.keys()]).to.deep.equal([nom]);
    // Fenêtre ouverte pendant la première levée : l'état initial compte zéro, seule la seconde levée compte.
    const fenetre = await c.transitions(milieu, fin, 1);
    expect(fenetre.get(nom)).to.deep.include({ transitions: 1, declenchee_au_debut: true });
    serie(1, 1);
    expect((await c.attendreSilence(nom, { delaiS: 6 * INTERVALLE })).silencieuse).to.equal(true);
    // Lecture de l'API depuis la seule URL (point de raccord d'un essai qui n'a pas lancé le collecteur).
    const client = new ClientCollecteur(c.url);
    expect((await client.regles()).length).to.equal(REGLES.length);
    expect(await client.requete("vector(1) + 1")).to.deep.equal([{ etiquettes: {}, valeur: 2 }]);
  });
});

// --------------------------------------------------------------------------
// CT-9 TE-17. Conditions d'alerte de CT-2 §17.4, de CT-2 EX-17.8 et de CT-5
// §8.9 : chacune est provoquée par l'essai, ou marquée non provoquée avec son
// motif (liste consignée dans le rapport d'exécution).

/** Conditions provoquées : alerte de la table → provocation et règles qui la portent. */
const PROVOQUEES = {
  "Mode dégradé": { provocations: ["stockage", "serveur"], note: "raisons stockage (et attente si la borne de 14.5 est atteinte) et serveur:<alias> ; cle, bail, horloge et approbation ne sont pas provoquées : clé de classe D en fichier sans panne injectable sur le démon réel, seconde instance absente, réglage de l'horloge système exclu (section 16)" },
  "Appels bloqués": { provocations: ["stockage", "quota"] },
  "Événements en attente": { provocations: ["stockage"] },
  "Disque": { provocations: ["stockage"], note: "règle noortrace_disque_ligne ; noortrace_disque_espace lit node_filesystem_avail_bytes de l'exportateur de nœud, absent du montage" },
  "Quota d'un hôte": { provocations: ["quota"] },
};
/** Conditions non provoquées, avec leur motif. */
const NON_PROVOQUEES = {
  "Bail": "seconde instance absente du déploiement (bail de fichier, une instance)",
  "Ancre en retard": "composant d'ancrage absent du montage (anchoring.ancrage nul) ; échéance queue.anchor_pending_alert_s d'au moins une heure (borne du schéma à relever quand l'ancrage est monté)",
  "Copie WORM en retard": "support WORM absent du déploiement",
  "Verrou WORM non conforme": "support WORM absent du déploiement",
  "Relevé de verrouillage en retard": "support WORM absent du déploiement",
  "Versions inattendues": "support WORM absent du déploiement",
  "Registre des gels invalide": "support WORM absent du déploiement",
  "Gel non posé sur une version d'un gel actif": "support WORM absent du déploiement",
  "Contrôle d'intégrité en échec": "contrôles horaires et quotidiens du fil de supervision (EX-17.5) : cadences fixes, hors de la fenêtre de charge ; règle à fenêtre d'une heure",
  "Gel levé": "support WORM absent du déploiement",
  "Horloge": "réglage de l'horloge système, que la section 16 exclut",
  "Définition d'outil changée": "règle à fenêtre d'une heure (increase(…[1h])) : sa fenêtre d'observation dépasse la fenêtre de charge de l'essai ; provoquée par la campagne de TM-34",
  "Fourche": "seconde instance absente du déploiement",
  "Panne après relais": "panne de stockage à injecter entre l'envoi et la durabilité d'un appel : non provocable de l'extérieur du démon réel",
  "Relais refusé ou identifiant en collision": "service d'approbation en défaut : le service de test du montage ne joue pas ce défaut ; règle critique à rejouer avec le service réel",
  "Remise refusée": "règle à fenêtre d'une heure ; service d'approbation en défaut non joué par le montage",
  "Budget de rédaction": "règle à fenêtre d'une heure",
  "Clé du MAC de relais": "seconde instance absente du déploiement",
  "Ingestion OpenTelemetry refusée": "source OpenTelemetry absente du déploiement",
  "Spans rejetés": "source OpenTelemetry absente du déploiement",
  "Retard de réception": "source OpenTelemetry absente du déploiement",
  "Conventions OpenTelemetry renommées": "source OpenTelemetry absente du déploiement",
  "Span OpenTelemetry rejoué avec un autre contenu": "source OpenTelemetry absente du déploiement",
  "Latence": "fenêtre de quinze minutes d'un quantile de l'histogramme ; un ralentissement de l'amont n'ajoute rien à la latence ajoutée (définition de 16.1) : non provocable sans dégrader la machine",
  "Pièces en attente perdues (révision 0.7)": "redémarrage du démon avec des événements en attente dont les pièces manquent : hors de la fenêtre de charge",
  "Mode observation actif": "version de politique en mode observation : autre déploiement (TE-10), fenêtre de charge distincte",
  "Pertes en mode observation": "version de politique en mode observation : autre déploiement (TE-10), fenêtre de charge distincte",
  // CT-2 révision 0.11, EX-18.10 : la ligne image_mismatch n'est écrite qu'au démarrage d'un démon lancé avec --image-attendue
  // sur un code dont l'empreinte diffère ; règle à fenêtre d'une heure (CT-8 §10.4, noortrace_image_differente).
  "Image différente de la version publiée": "démon de la charge lancé sans --image-attendue (EX-18.10) : la ligne image_mismatch n'est écrite qu'au démarrage d'un code dont l'empreinte diffère de l'image attendue, hors de la fenêtre de charge ; règle à fenêtre d'une heure",
};
const NON_PROVOQUEES_CT5 = "composant d'ancrage absent du montage (anchoring.ancrage nul) : aucune condition de CT-5 §8.9 n'est provoquée par cet essai";

/** Noms des alertes des deux tables de CT-2 §17.4 (table générale et table d'EX-17.8). */
function alertesCT2() {
  const t = section(CT2, "### 17.4 Alertes", "### 17.5 ");
  return t.split("\n").filter((l) => l.startsWith("| ") && !l.startsWith("| Alerte") && !l.startsWith("|---")).map((l) => cellules(l)[0]);
}

/**
 * Métriques d'une table « Nom | Type | Étiquettes | Sens » : nom, type de
 * l'exposition, et jeux d'étiquettes admis (une cellule « `a` ou `b` » donne
 * deux jeux).
 */
function tableMetriques(texte) {
  const out = [];
  for (const l of texte.split("\n")) {
    if (!l.startsWith("| `noortrace_")) continue;
    const c = cellules(l);
    const type = c[1].startsWith("compteur") ? "counter" : c[1].startsWith("jauge") ? "gauge" : c[1].startsWith("histogramme") ? "histogram" : null;
    // Étiquettes : les noms entre accents graves hors parenthèses ; « ou » sépare des variantes.
    let plat = "";
    let prof = 0;
    for (const ch of c[2]) {
      if (ch === "(") prof++;
      else if (ch === ")") prof--;
      else if (prof === 0) plat += ch;
    }
    let jeux = [[]];
    for (const morceau of plat.split(",")) {
      const variantes = morceau.split(/\sou\s/).map((v) => [...v.matchAll(/`([a-z_]+)`/g)].map((x) => x[1])).filter((v) => v.length);
      if (!variantes.length) continue;
      jeux = jeux.flatMap((j) => variantes.map((v) => [...j, ...v]));
    }
    out.push({ nom: c[0].replaceAll("`", ""), type, jeux: jeux.map((j) => j.sort().join(",")) });
  }
  return out;
}

/** Familles et séries d'une exposition au format texte : nom → { type, etiquettes: jeux vus }. */
function lireExposition(texte) {
  const familles = new Map();
  for (const l of texte.split("\n")) {
    const t = /^# TYPE ([a-z_]+) ([a-z]+)$/.exec(l);
    if (t) {
      familles.set(t[1], { type: t[2], jeux: new Set(), suffixes: new Set() });
      continue;
    }
    const s = /^([a-z_]+)(?:\{(.*)\})? \S+$/.exec(l);
    if (!s) continue;
    let nom = s[1];
    let suffixe = "";
    for (const x of ["_bucket", "_sum", "_count"]) {
      if (nom.endsWith(x) && familles.get(nom.slice(0, -x.length))?.type === "histogram") {
        suffixe = x;
        nom = nom.slice(0, -x.length);
      }
    }
    const f = familles.get(nom);
    if (!f) continue;
    f.suffixes.add(suffixe);
    const noms = [...(s[2] ?? "").matchAll(/([a-z_]+)="(?:[^"\\]|\\.)*"/g)].map((x) => x[1]).filter((n) => !(suffixe === "_bucket" && n === "le"));
    f.jeux.add(noms.sort().join(","));
  }
  return familles;
}

describe("CT-9 TE-17 : conditions d'alerte de CT-2 §17.4 et d'EX-17.8, provoquées ou marquées non provoquées (liste du rapport d'exécution)", function () {
  it("TE-17, liste des conditions : chaque alerte de CT-2 §17.4 (table générale et table d'EX-17.8) est provoquée par une provocation du montage ou marquée non provoquée avec son motif ; la gravité attendue de chaque règle d'une provocation est celle de la table de CT-8 §10.4 à §10.7 ; son étiquette exigence nomme la prescription", function () {
    const alertes = alertesCT2();
    // 33 lignes : 31 dans la table générale (révision 0.11 de CT-2 : « Image différente de la version publiée »,
    // EX-18.10), 2 dans celle d'EX-17.8.
    expect(alertes.length).to.equal(33);
    expect([...Object.keys(PROVOQUEES), ...Object.keys(NON_PROVOQUEES)].sort()).to.deep.equal([...alertes].sort());
    for (const [alerte, p] of Object.entries(PROVOQUEES)) {
      for (const nom of p.provocations) {
        const regles = PROVOCATIONS[nom].attendues.map((a) => REGLES.find((r) => r.alert === a.regle));
        expect(regles.some((r) => r.labels.exigence.includes(`CT-2 §17.4 ${alerte}`)), `${alerte} : aucune règle attendue de la provocation ${nom} ne la nomme`).to.equal(true);
      }
    }
    for (const p of Object.values(PROVOCATIONS)) {
      for (const a of p.attendues) {
        expect(GRAVITE_TABLE.get(a.regle), a.regle).to.equal(a.gravite);
        expect(REGLES.find((r) => r.alert === a.regle).labels.severity, a.regle).to.equal(a.gravite);
      }
    }
    // CT-5 §8.9 : dix-neuf alertes nommées (CT-8 §10), aucune provoquée par ce montage.
    expect(section(CT5, "### 8.9 Supervision", "### 8.10 ")).to.include("Alertes prescrites (CT-8 donne les règles)");
  });
});

describe("CT-9 TE-17 : supervision en charge — démon réel de l'enregistreur sous charge à cadence fixe, extracteur, sonde et collecteur Prometheus 3.5.0 chargé des règles de référence (CT-2 §17.4, EX-17.5 à EX-17.8 ; CT-5 §8.9)", function () {
  this.timeout(3 * 3600000);
  const CADENCE = 20;
  const CONNEXIONS = 4;
  const executions = [];
  let dir;
  let stockage;
  let s;
  let debutCharge;
  const trace = (m) => process.env.NOORTRACE_TRACE_SUPERVISION && process.stderr.write(`TE-17 ${new Date().toISOString()} : ${m}\n`);

  before(async function () {
    if (!PROMETHEUS.ok) return;
    dir = repertoireTemporaire("noortrace-te17-");
    if (process.env.NOORTRACE_SUPERVISION_STOCKAGE) stockage = fs.mkdtempSync(path.join(process.env.NOORTRACE_SUPERVISION_STOCKAGE, "noortrace-te17-stockage-"));
    s = await monterSupervision(dir, { cadence: CADENCE, connexions: CONNEXIONS, stockage });
    // Deux intervalles avant la charge (chaque cible collectée), puis deux sous charge avant la première fenêtre.
    await pause(2 * s.collecteur.intervalleS * 1000);
    s.hote.demarrer();
    debutCharge = Math.floor(Date.now() / 1000);
    await pause(2 * s.collecteur.intervalleS * 1000);
  });
  after(async function () {
    if (!s) return;
    const codeDemon = await demonterSupervision(s);
    // Rapport d'exécution (valeurs employées, provocations, conditions non provoquées) : écrit où NOORTRACE_RAPPORT_TE17 le dit.
    if (process.env.NOORTRACE_RAPPORT_TE17) {
      fs.writeFileSync(process.env.NOORTRACE_RAPPORT_TE17, JSON.stringify({
        test_id: "TE-17", prometheus: { version: PROMETHEUS.version, sha256: PROMETHEUS.sha256 }, cadence_appels_par_s: CADENCE, connexions: CONNEXIONS, ecritures_par_s: 1,
        intervalle_evaluation_s: s.collecteur.intervalleS, regles: "règles de référence régénérées depuis la configuration du montage (scripts/deploiement/regles.mjs --configuration, CT-8 EX-10.6)", regles_sha256: createHash("sha256").update(fs.readFileSync(s.regles)).digest("hex"), ecarts_for: s.collecteur.ecarts,
        stockage: stockage ? "système de fichiers désigné par NOORTRACE_SUPERVISION_STOCKAGE" : "sous le répertoire de travail de l'essai",
        seuils: { min_free_bytes: s.m.config.storage.min_free_bytes, marge_octets: s.marge, pending_max_ms: s.m.config.policy.failure.pending_max_ms, pending_max_events: s.m.config.policy.failure.pending_max_events, quota: s.quota },
        fenetre_de_charge: { debut_s: debutCharge, fin_s: Math.ceil(Date.now() / 1000), appels_envoyes: s.hote.envoyes, appels_en_erreur: s.hote.erreurs, codes: Object.fromEntries(s.hote.codes) },
        code_demon: codeDemon, executions, conditions_provoquees: PROVOQUEES, conditions_non_provoquees: { ...NON_PROVOQUEES, "CT-5 §8.9 (toutes)": NON_PROVOQUEES_CT5 },
      }, null, 2) + "\n");
    }
    fs.rmSync(dir, { recursive: true, force: true });
    if (stockage) fs.rmSync(stockage, { recursive: true, force: true });
  });
  beforeEach(function () {
    sansPrometheus(this);
  });

  /**
   * Règle dont la condition est une cible de performance de CT-2 §16.1 (TM-1 : latence ajoutée p99 ≤ 50 ms), tenue sur le seul
   * système de référence de la porte 2 (CT-9 EX-11.1, EX-11.2) : hors de lui, son état dépend de la machine et n'est pas jugé ;
   * il est relevé dans le rapport d'exécution (`latence`).
   */
  const REGLES_DU_SYSTEME_DE_REFERENCE = ["noortrace_latence"];
  const horsMachine = (nom) => !REGLES_DU_SYSTEME_DE_REFERENCE.includes(nom);
  /**
   * Règles d'absence de la table de CT-8 §10.7 (absent(…) pendant 2 jours) dont la série manque par construction du
   * montage : aucune relecture hors du composant (support WORM, console, copie du journal d'exploitation : EX-10.9,
   * conditions non provoquées) ni sauvegarde n'y est configurée. Elles sont en cours de clause dès la première
   * évaluation et le restent pendant toute la fenêtre de charge (2 jours de clause) : TE-17 exige qu'elles le soient
   * (l'absence est vue) et qu'aucune ne soit déclenchée.
   */
  const ABSENCES_DU_MONTAGE = ["noortrace_releve_externe_absent_registre_gels", "noortrace_releve_externe_absent_console", "noortrace_releve_externe_absent_copie_exploitation", "noortrace_sauvegarde_absente"];
  const latence = async () => (await s.collecteur.requete("histogram_quantile(0.99, sum by (le) (rate(noortrace_relay_latency_ms_bucket[15m])))"))[0]?.valeur ?? null;

  /** Juge une provocation selon l'oracle de TE-17 : une transition par règle attendue, gravité de la table, rien hors de la liste. */
  function juger(compte) {
    executions.push(compte);
    const ecarts = [];
    for (const d of compte.declenchees_avant.filter(horsMachine)) ecarts.push(`${d} : déjà déclenchée au début de la fenêtre`);
    for (const a of compte.attendues) {
      if (a.transitions !== 1) ecarts.push(`${a.regle} : ${a.transitions} transition(s) vers l'état déclenché, une attendue (${a.cause})`);
      else if (a.gravites_relevees.join(",") !== GRAVITE_TABLE.get(a.regle)) ecarts.push(`${a.regle} : gravité relevée ${a.gravites_relevees.join(",")}, table de CT-8 : ${GRAVITE_TABLE.get(a.regle)}`);
    }
    for (const r of compte.resolutions) if (!r.resolue) ecarts.push(`${r.regle} : non résolue après la levée de la provocation`);
    for (const h of compte.hors_liste.filter((x) => horsMachine(x.regle))) ecarts.push(`${h.regle} : déclenchée hors de la liste attendue (${h.transitions} transition(s))`);
    expect(ecarts, JSON.stringify(compte, null, 1)).to.deep.equal([]);
  }

  it("TE-17, nominal : sous la charge à cadence fixe, les 99 règles régénérées depuis la configuration du montage sont chargées et saines à 15 s, les cibles enregistreur (role active) et hote collectées ; aucune règle déclenchée ni en cours de clause, hors noortrace_latence (cible de TM-1, relevée, non jugée) et quatre règles d'absence en cours de clause ; /healthz ok, /readyz 200, /metrics l'exposition", async function () {
    const c = s.collecteur;
    expect(c.intervalleS).to.equal(secondes(yaml.load(fs.readFileSync(COLLECTE_REFERENCE, "utf8")).global.evaluation_interval));
    expect(c.ecarts).to.deep.equal([]);
    const debut = Math.floor(Date.now() / 1000);
    await pause(6 * c.intervalleS * 1000);
    const fin = Math.ceil(Date.now() / 1000);
    const regles = await c.regles();
    expect(regles.length).to.equal(REGLES.length);
    expect(regles.filter((r) => r.sante !== "ok").map((r) => `${r.nom} : ${r.erreur}`)).to.deep.equal([]);
    expect((await c.cibles()).map((t) => [t.job, t.role, t.sante]).sort()).to.deep.equal([["enregistreur", "active", "up"], ["hote", "hote", "up"]]);
    const actives = (await c.alertes()).map((a) => `${a.nom} (${a.etat})`);
    expect(actives.filter((x) => horsMachine(x.split(" ")[0]) && !ABSENCES_DU_MONTAGE.includes(x.split(" ")[0]))).to.deep.equal([]);
    expect(actives.filter((x) => ABSENCES_DU_MONTAGE.includes(x.split(" ")[0])).sort(), "absences du montage : en cours de clause, jamais déclenchées").to.deep.equal(ABSENCES_DU_MONTAGE.map((n) => `${n} (pending)`).sort());
    expect([...(await c.transitions(debut, fin, 5)).keys()].filter(horsMachine)).to.deep.equal([]);
    const sante = await lireSupervision(s.m, "/healthz");
    expect([sante.statut, JSON.parse(sante.texte)]).to.deep.equal([200, { status: "ok" }]);
    expect((await lireSupervision(s.m, "/readyz")).statut).to.equal(200);
    const metriques = await lireSupervision(s.m, "/metrics");
    expect(metriques.statut).to.equal(200);
    expect(metriques.texte).to.match(/^# TYPE noortrace_events_total counter$/m);
    expect(s.hote.envoyes).to.be.at.least(6 * c.intervalleS * CADENCE);
    expect(s.hote.erreurs).to.equal(0);
    // La charge passe bien par le collecteur : débit d'événements durables vu de Prometheus.
    const debit = await c.requete("sum(rate(noortrace_events_total[1m]))");
    expect(debit[0].valeur).to.be.above(CADENCE * 0.8);
    executions.push({ nominal: { debut_s: debut, fin_s: fin, appels_envoyes: s.hote.envoyes, debit_evenements_par_s: debit[0].valeur, latence_p99_ms_15m: await latence(), alertes_actives: actives, regles_du_systeme_de_reference: REGLES_DU_SYSTEME_DE_REFERENCE } });
  });

  it("TE-17, provocation « stockage indisponible » (espace libre sous min_free_bytes, RB-1) : mode dégradé stockage, appels d'écriture bloqués, événements en attente (non vide, ancienne) et ligne disk_low — chaque règle attendue passe exactement une fois à l'état déclenché, à la gravité de la table, se résout après la levée, et aucune autre règle ne se déclenche", async function () {
    juger(await jouerProvocation(s, "stockage", trace));
    expect(JSON.parse((await lireSupervision(s.m, "/healthz")).texte)).to.deep.equal({ status: "ok" });
  });

  it("TE-17, provocation « quota d'un hôte » (octets reçus au-delà de received_bytes_per_minute) : noortrace_quota_hote (mineure) et noortrace_appels_bloques (majeure) passent chacune exactement une fois à l'état déclenché, se résolvent, et aucune autre règle ne se déclenche", async function () {
    juger(await jouerProvocation(s, "quota", trace));
  });

  it("TE-17, provocation « serveur d'outils injoignable » (processus stdio arrêté à chaque relance) : noortrace_mode_degrade_serveur (mineure, raison serveur:<alias>) passe exactement une fois à l'état déclenché, avec ses conséquences nommées (quota de l'hôte par les appels en vol), se résout quand le serveur revient, et aucune autre règle ne se déclenche", async function () {
    juger(await jouerProvocation(s, "serveur", trace));
    const sante = JSON.parse((await lireSupervision(s.m, "/healthz")).texte);
    expect(sante).to.deep.equal({ status: "ok" });
  });

  it("TE-17, métriques : chaque métrique de la table de CT-2 §17.2 et de CT-5 EX-8.15 est déclarée par son nom et son type (ligne # TYPE) dans /metrics du démon, lu sur le démon ; chaque série présente porte exactement un jeu d'étiquettes de la table ; un histogramme observé a ses séries _bucket (étiquette le), _sum et _count", async function () {
    const tables = [...tableMetriques(section(CT2, "### 17.2 Métriques", "### 17.3 ")), ...tableMetriques(section(CT5, "**EX-8.15**", "Alertes prescrites")).filter((m) => m.nom !== "noortrace_anchor_pending")];
    expect(tables.filter((m) => !m.nom.startsWith("noortrace_anchoring_")).length, "métriques de CT-2 §17.2 (CT-8 §10.2 : 45)").to.equal(45);
    expect(tables.filter((m) => m.nom.startsWith("noortrace_anchoring_")).length, "métriques propres à CT-5 EX-8.15").to.equal(9);
    const expo = lireExposition((await lireSupervision(s.m, "/metrics")).texte);
    const ecarts = [];
    for (const m of tables) {
      const f = expo.get(m.nom);
      if (!f) {
        ecarts.push(`${m.nom} : non déclarée (aucune ligne # TYPE)`);
        continue;
      }
      if (f.type !== m.type) ecarts.push(`${m.nom} : type ${f.type}, table : ${m.type}`);
      for (const j of f.jeux) if (!m.jeux.includes(j)) ecarts.push(`${m.nom} : série aux étiquettes {${j}}, table : {${m.jeux.join("} ou {")}}`);
      if (f.type === "histogram" && f.jeux.size && !["_bucket", "_sum", "_count"].every((x) => f.suffixes.has(x))) ecarts.push(`${m.nom} : histogramme sans ses séries _bucket, _sum et _count`);
    }
    for (const nom of expo.keys()) if (!tables.some((m) => m.nom === nom)) ecarts.push(`${nom} : exposée, absente des tables`);
    executions.push({ metriques: { declarees: [...expo.keys()], ecarts } });
    expect(ecarts).to.deep.equal([]);
  });

  it("TE-17, dossier : un appel d'écriture relayé pendant la fenêtre de charge, exporté après la clôture de sa période (noortrace-ctl close-period --now, développement), est vérifié par les deux vérificateurs de CT-6 : aucune vérification en échec, clé d'enregistreur d'essai : verdict incomplet, code 3, raison piece_essai seule, énoncé identique", async function () {
    await s.hote.arreter();
    const env = { ...process.env, ...s.m.env };
    const ctl = (args) => spawnSync(process.execPath, [BIN_CTL, ...args, "--configuration", s.m.chemin], { encoding: "utf8", env });
    const cloture = ctl(["close-period", "--now"]);
    expect(cloture.status, cloture.stdout + cloture.stderr).to.equal(0);
    const repertoire = path.join(s.m.config.storage.root, s.m.config.recorder.org_id.slice(2), s.m.config.recorder.journal_id.slice(2));
    const evenements = await lireEvenements(repertoire);
    const ecritures = evenements.filter((e) => e.execution?.tool === "nul__nul.ecrire" && e.execution.status === "executee" && e.execution.is_error === false);
    expect(ecritures.length, "appels d'écriture relayés pendant la fenêtre de charge").to.be.above(0);
    const choisi = ecritures[Math.floor(ecritures.length / 2)];
    const destination = path.join(s.m.config.exports_dir, "dossier-ecriture");
    const exporte = ctl(["dossier", "exporter", "--seq", String(choisi.seq), "--vers", destination]);
    expect(exporte.status, exporte.stdout + exporte.stderr).to.equal(0);
    expect(JSON.parse(exporte.stdout.trim().split("\n").at(-1))).to.deep.include({ event: "dossier_exported" });
    const js = spawnSync(process.execPath, [path.join(RACINE, "scripts", "verify", "dossier.mjs"), destination, "--json"], { cwd: RACINE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    // Décision du porteur du 2026-11-23 (CT-6 EX-6.26) : le montage signe avec la clé d'essai rec-test-01 (pièce d'essai,
    // EX-6.24) : rien n'échoue, mais le verdict est « incomplet », code 3, pour la seule raison « piece_essai » (EX-8.12).
    expect(js.status, js.stdout + js.stderr).to.equal(3);
    const rapportJs = JSON.parse(js.stdout);
    expect([rapportJs.verdict, rapportJs.incomplete_reasons, rapportJs.failed_checks]).to.deep.equal(["incomplet", ["piece_essai"], []]);
    expect(rapportJs.statement.fr).to.include(`seq ${choisi.seq} `);
    const bin = [process.env.NOORTRACE_VERIFIER_BIN, process.env.NOORTRACE_GO_BIN, path.join(RACINE, "verificateur", "dist", "noortrace-verifier-linux-amd64")].find((x) => x && fs.existsSync(x));
    executions.push({ dossier: { seq: choisi.seq, verificateur_js: { code: js.status, verdict: rapportJs.verdict }, verificateur_go: bin ? "lancé" : "absent" } });
    if (!bin) return enAttente(this, "vérificateur Go de CT-6 (NOORTRACE_VERIFIER_BIN, NOORTRACE_GO_BIN ou verificateur/dist/noortrace-verifier-linux-amd64) : vérification JavaScript faite, vérification Go non faite");
    const go = spawnSync(bin, [destination, "--json"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    expect(go.status, go.stdout + go.stderr).to.equal(3);
    const rapportGo = JSON.parse(go.stdout);
    expect([rapportGo.verdict, rapportGo.incomplete_reasons, rapportGo.failed_checks]).to.deep.equal(["incomplet", ["piece_essai"], []]);
    expect(rapportGo.statement).to.deep.equal(rapportJs.statement);
    expect(Object.fromEntries(rapportGo.checks.map((x) => [x.id, x.status]))).to.deep.equal(Object.fromEntries(rapportJs.checks.map((x) => [x.id, x.status])));
  });
});

describe("CT-9 TM-34 et TM-35 : outil des campagnes de mesure de la supervision (scripts/deploiement/mesure-supervision.mjs ; rapports au format $defs/rapport_mesure, hors système de référence)", function () {
  this.timeout(900000);

  it("membreCompare : membre comparé et seuil d'une règle à comparaison simple (jauge, fonction, soustraction à time()), forme « première occurrence » d'EX-10.6 comprise (branche de gauche) ; une expression composée par and ou or au niveau supérieur, ou comparée à autre chose qu'un nombre, n'en a pas ; onze règles de référence sont dans ce cas (cinq composées, six absent())", function () {
    expect(membreCompare("noortrace_pending_oldest_ms > 150000")).to.deep.equal({ membre: "noortrace_pending_oldest_ms", comparateur: ">", seuil: 150000 });
    expect(membreCompare('max by (instance, reason) (noortrace_degraded{reason=~"cle|bail|horloge"}) == 1')).to.deep.equal({ membre: 'max by (instance, reason) (noortrace_degraded{reason=~"cle|bail|horloge"})', comparateur: "==", seuil: 1 });
    expect(membreCompare('time() - noortrace_proces_verbal_dernier_s{kind="sauvegarde"} > 86400').seuil).to.equal(86400);
    expect(membreCompare("(node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) < 0.10")).to.deep.include({ comparateur: "<", seuil: 0.1 });
    expect(membreCompare('noortrace_anchoring_last_success_age_s{kind=~"jeton_periode|jeton_point"} > 900 and on (kind, provider) increase(noortrace_anchoring_attempts_total[15m]) > 0')).to.equal(null);
    expect(membreCompare("a > 0 or b > 0")).to.equal(null);
    expect(membreCompare('x{reason=" and "} > 0')).to.deep.include({ seuil: 0 });
    // Forme « première occurrence » d'EX-10.6 : membre et seuil de la branche de gauche (la règle de la table) ; une
    // branche de droite qui ne répète pas la série, la fenêtre ou le seuil n'est pas cette forme.
    expect(membreCompare('(increase(noortrace_journal_lignes_total{event="journal_fork"}[5m]) > 0) or ((noortrace_journal_lignes_total{event="journal_fork"} unless noortrace_journal_lignes_total{event="journal_fork"} offset 5m) > 0)')).to.deep.equal({ membre: 'increase(noortrace_journal_lignes_total{event="journal_fork"}[5m])', comparateur: ">", seuil: 0 });
    expect(membreCompare("(rate(noortrace_calls_blocked_total[5m]) > 0) or ((noortrace_calls_blocked_total unless noortrace_calls_blocked_total offset 5m) > 0)")).to.deep.equal({ membre: "rate(noortrace_calls_blocked_total[5m])", comparateur: ">", seuil: 0 });
    expect(membreCompare("(increase(a_total[5m]) > 0) or ((a_total unless a_total offset 1h) > 0)")).to.equal(null);
    const composees = REGLES.filter((r) => membreCompare(r.expr) === null).map((r) => r.alert);
    // Révision 0.8 de CT-8 : les six règles de témoin de vie et d'absence adoptées par la table de 10.7 (absent(…), sans
    // comparaison à un nombre, ou absent(…) or (…)) n'ont pas de membre comparé.
    expect(composees).to.deep.equal(["noortrace_otel_conventions", "noortrace_ancrage_prestataire_injoignable", "noortrace_ancrage_prestataires_epuises_periode", "noortrace_ancrage_file", "noortrace_ancrage_volume", "noortrace_extracteur_muet", "noortrace_sonde_muette", "noortrace_releve_externe_absent_registre_gels", "noortrace_releve_externe_absent_console", "noortrace_releve_externe_absent_copie_exploitation", "noortrace_sauvegarde_absente"]);
    // noortrace_ancrage_volume compare à un produit (2 × <A_h>), non à un nombre : sans seuil littéral, elle n'a pas de ligne de valeur.
    expect(REGLES.find((r) => r.alert === "noortrace_ancrage_volume").expr).to.match(/> 2 \* [0-9]+$/);
    expect(membreCompare(REGLES.find((r) => r.alert === "noortrace_registre_mempool").expr)).to.deep.equal({ membre: "noortrace_registre_mempool", comparateur: ">", seuil: 2048 });
  });

  it("TM-35 : relever puis rapport sur un point RPC local — un relevé par seconde de eth_getBlockTransactionCountByNumber(\"pending\"), aucune autre méthode appelée ; rapport conforme à $defs/rapport_mesure : ligne mempool_max_observe (nombre), target = <M> en nombre (moitié de --txpool-max-pending), échantillons bruts désignés par leur SHA-256, counts_for_targets faux, met null ; usage refusé → 2", async function () {
    const files = [0, 3, 7, 2, 0, 0];
    const methodes = [];
    let n = 0;
    const noeud = http.createServer((req, rep) => {
      const corps = [];
      req.on("data", (x) => corps.push(x));
      req.on("end", () => {
        const m = JSON.parse(Buffer.concat(corps).toString("utf8"));
        methodes.push([m.method, JSON.stringify(m.params)]);
        rep.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: `0x${(files[n++] ?? 0).toString(16)}` }));
      });
    });
    await new Promise((r) => noeud.listen(0, "127.0.0.1", r));
    const muet = await portLibre();
    const releves = path.join(TRAVAIL, "mempool.ndjson");
    const fichier = path.join(TRAVAIL, "rapport-tm35.json");
    try {
      const debut = new Date(Date.now() - 1000).toISOString();
      const r = await outilAsync("mesure-supervision.mjs", ["tm-35", "relever", "--rpc", `relais=http://127.0.0.1:${noeud.address().port}`, "--rpc", `muet=http://127.0.0.1:${muet}`, "--duree-s", "4", "--sortie", releves]);
      expect(r.code, r.err).to.equal(0);
      const lignes = fs.readFileSync(releves, "utf8").trim().split("\n").map((l) => JSON.parse(l));
      expect(lignes.map((l) => l.mempool)).to.deep.equal([0, 3, 7, 2].map((v) => ({ relais: v, muet: null })));
      expect(lignes.map((l) => l.prevu_ms)).to.deep.equal([0, 1000, 2000, 3000]);
      expect([...new Set(methodes.map((m) => m.join(" ")))]).to.deep.equal(['eth_getBlockTransactionCountByNumber ["pending"]']);
      const args = ["tm-35", "rapport", "--echantillons", releves, "--debut", debut, "--fin", new Date(Date.now() + 1000).toISOString(), "--txpool-max-pending", "5120", "--source-m", "valeur d'essai", "--charge", "charge d'essai", "--sortie-rapport", fichier, "--note", "essai de l'outil"];
      const rap = outil("mesure-supervision.mjs", args);
      expect(rap.status, rap.stderr).to.equal(0);
      const lu = JSON.parse(fs.readFileSync(fichier, "utf8"));
      verifierRapportMesure(lu, "TM-35", "nombre");
      expect(lu.results.map((l) => l.name)).to.deep.equal(["mempool_max_observe", "mempool_max_muet", "mempool_max_relais"]);
      expect(lu.results[0]).to.include({ n: 4, max: 7, min: 0, mean: 3, target: 2560, samples: null });
      expect(lu.results[0].samples_sha256).to.match(/^[0-9a-f]{64}$/);
      expect(lu.results[0].conditions.join("\n")).to.include("`<M>` = 2560 : moitié de -txpool-max-pending = 5120 ; valeur d'essai");
      expect(lu.results[1]).to.include({ n: null, max: null });
      expect(lu.results[2]).to.include({ n: 4, max: 7 });
      expect(lu.notes).to.include("essai de l'outil");
      expect(lu.configuration_sha256).to.equal(null);
      const catalogue = JSON.parse(fs.readFileSync(path.join(SPEC, "vecteurs", "ct-9", "catalogue.json"), "utf8")).tests.find((t) => t.id === "TM-35").measure;
      expect(lu.results[0]).to.include({ name: catalogue.result_name, unit: catalogue.unit });
      expect(lu.method).to.include({ warmup: catalogue.warmup, repetitions: catalogue.repetitions });
      // Usages refusés.
      for (const mauvais of [["tm-35", "rapport"], ["tm-35", "relever", "--rpc", "x=http://192.0.2.1:8545", "--duree-s", "1", "--sortie", releves], ["tm-34"], ["tm-34", "--travail", path.join(TRAVAIL, "x"), "--sortie-rapport", fichier, "--scenarios", "inconnu"], [], [...args.slice(0, 9), "5121", ...args.slice(10)]]) {
        const u = outil("mesure-supervision.mjs", mauvais, { env: { ...process.env, NOORTRACE_PROMETHEUS: PROMETHEUS.ok ? PROMETHEUS.bin : "" } });
        expect(u.status, mauvais.join(" ") + u.stderr).to.equal(PROMETHEUS.ok || mauvais[0] !== "tm-34" || mauvais.length === 1 ? 2 : 3);
      }
    } finally {
      await new Promise((r) => noeud.close(() => r()));
    }
  });

  it("TM-35, cadence des relevés : --duree-s n donne exactement n relevés, aux instants debut + k × 1000 ms (k de 0 à n − 1), quel que soit l'instant de départ de l'horloge monotone, y compris un départ où (debut + 4000) − debut vaut 3999.9999999999995 en virgule flottante", function () {
    // Instant de départ qui faisait faire un cinquième relevé à l'ancienne borne (comparaison de prevu − debut à la
    // durée), rencontré quand le processus démarre lentement (machine chargée : performance.now() au-delà de 64 ms).
    const debutPiege = 100.743336;
    expect(debutPiege + 4000 - debutPiege).to.be.below(4000);
    for (const debut of [0, 14.590756, debutPiege, 1234.5678, 987654.321]) {
      for (const n of [1, 4, 60]) {
        const instants = instantsReleves(debut, n);
        expect(instants, `debut ${debut}, ${n} s`).to.have.lengthOf(n);
        expect(instants.map((t) => Math.round(t - debut)), `debut ${debut}, ${n} s`).to.deep.equal(Array.from({ length: n }, (_, k) => k * 1000));
      }
    }
  });

  it("TM-34 : campagne courte sur le montage (fenêtre nominale de 60 s, sans scénario) — rapport conforme à $defs/rapport_mesure : supervision_faux_positifs (règles déclenchées en nominal, aucune sauf noortrace_latence), supervision_faux_negatifs sans valeur, une ligne supervision_nominal_<règle> par règle avec son seuil en target, counts_for_targets faux, met null", async function () {
    sansPrometheus(this);
    const travail = path.join(TRAVAIL, "tm34");
    const fichier = path.join(TRAVAIL, "rapport-tm34.json");
    const r = await outilAsync("mesure-supervision.mjs", ["tm-34", "--travail", travail, "--sortie-rapport", fichier, "--duree-nominale-s", "60", "--cadence", "20", "--connexions", "4", "--disque", "inconnu"]);
    expect(r.code, r.err).to.equal(0);
    const lu = JSON.parse(fs.readFileSync(fichier, "utf8"));
    verifierRapportMesure(lu, "TM-34", "nombre");
    const parNom = new Map(lu.results.map((l) => [l.name, l]));
    const brut = JSON.parse(fs.readFileSync(path.join(travail, "campagne.json"), "utf8"));
    // La latence ajoutée au 99e centile dépend de la machine : sous une autre charge, sa règle se déclenche en nominal, et le rapport le compte.
    const declenchees = brut.nominal.faux_positifs.map((x) => x.regle);
    expect(declenchees.filter((x) => x !== "noortrace_latence"), r.err).to.deep.equal([]);
    expect(parNom.get("supervision_faux_positifs")).to.include({ value: declenchees.length, target: 0, n: REGLES.length, connections: 4 });
    expect(parNom.get("supervision_faux_positifs").conditions.at(-1)).to.equal(declenchees.length ? "règles déclenchées en nominal : noortrace_latence (1 transition(s))" : "règles déclenchées en nominal : aucune");
    expect(parNom.get("supervision_faux_negatifs")).to.include({ value: null, target: 0 });
    expect(lu.results.filter((l) => l.name.startsWith("supervision_nominal_")).map((l) => `noortrace_${l.name.slice("supervision_nominal_".length)}`)).to.deep.equal(REGLES.map((x) => x.alert));
    // Règles régénérées depuis la configuration du montage (pending_max_ms 400 000 ms : seuil 200 000 ms).
    expect(parNom.get("supervision_nominal_attente_ancienne")).to.include({ target: 200000, max: 0, min: 0, n: 1 });
    expect(parNom.get("supervision_nominal_registre_mempool")).to.include({ target: 2048, max: null, n: null });
    expect(parNom.get("supervision_nominal_ancrage_file")).to.include({ target: null, max: null });
    expect(lu.configuration_sha256).to.match(/^[0-9a-f]{64}$/);
    expect(parNom.get("supervision_nominal_latence")).to.include({ target: 50, n: 1 });
    expect(brut.nominal.appels_envoyes).to.be.at.least(60 * 20);
    expect(brut.regles).to.equal(REGLES.length);
    expect(lu.system.disk).to.deep.equal({ type: "inconnu", fsync: true });
  });
});
