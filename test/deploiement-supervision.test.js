import { expect } from "chai";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import yaml from "js-yaml";
import * as N from "@noortrace/noyau";
import { Coeur, validerConfiguration, resoudreSecrets, supportWormDepuisConfiguration, principalCtl, OperationsS3, identifiantsS3, controleWorm } from "@noortrace/enregistreur";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as S from "../scripts/lib/supervision.mjs";
import { verifierProcesVerbal } from "../scripts/lib/exploitation.mjs";
import { ExtracteurFichiers } from "../scripts/deploiement/extraire-journaux.mjs";
import { expositionSonde, expositionReleve, formeEtat, formeSante, expediteursManifeste } from "../scripts/deploiement/sonde.mjs";
import { fichiersReference } from "../scripts/deploiement/regles.mjs";
import { rejouerGroupe, analyser, evaluer } from "./fixtures/supervision/promql.mjs";
import { configurationDev, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { IMAGES, dockerDisponible, demarrerS3, arreterTout, certificats, mandataireTls, creerBucketVerrouille, identifiantsRole, fichierSecret } from "./fixtures/enregistreur-worm/outils.mjs";

// SUPERVISION DE RÉFÉRENCE DE CT-8 §10 (spec/CT-8-deploiement-et-exploitation.md,
// §10.2 à §10.10, EX-10.1 à EX-10.12, EX-A.5 à EX-A.7, EX-A.27) : règles
// d'alerte (SV-1 à SV-4), extracteur des journaux rejoué sur les vecteurs
// (SV-5), générateur des règles (SV-6), tableau de bord (SV-7), collecte de
// référence (EX-10.4), sonde (EX-10.7) et relevé hors du composant
// (EX-10.9). Les tests des règles (tests-regles.yml) sont rejoués par
// promtool 3.5.0 quand il est présent (EX-10.10 ; en attente sinon) et, dans
// tous les cas, par l'évaluateur réduit de test/fixtures/supervision/promql.mjs.
// CT-9 : TV-76, TA-29 et TA-75 (ces deux derniers contre un S3 à Object Lock
// dans Docker, en attente sans lui).

const SPEC = path.join(PROJECT_ROOT, "spec");
const OBS = path.join(PROJECT_ROOT, "deploiement", "observabilite");
const VECT = path.join(SPEC, "vecteurs", "ct-8", "supervision");
const OUTILS = path.join(PROJECT_ROOT, "scripts", "deploiement");
const CT8 = fs.readFileSync(path.join(SPEC, "CT-8-deploiement-et-exploitation.md"), "utf8");
const CT2 = fs.readFileSync(path.join(SPEC, "CT-2-enregistreur.md"), "utf8");
const CT5 = fs.readFileSync(path.join(SPEC, "CT-5-ancrage.md"), "utf8");
const lire = (...p) => fs.readFileSync(path.join(...p), "utf8");
const section = (texte, debut, fin) => {
  const i = texte.indexOf(debut);
  return texte.slice(i, texte.indexOf(fin, i + debut.length));
};
const outil = (nom, args, o = {}) => spawnSync(process.execPath, [path.join(OUTILS, nom), ...args], { encoding: "utf8", cwd: PROJECT_ROOT, maxBuffer: 16 * 1024 * 1024, ...o });
/** Même lancement, sans bloquer la boucle d'événements (serveurs locaux et mandataire TLS de ce processus). */
const outilAsync = (nom, args, o = {}) => new Promise((resolve) => {
  const c = spawn(process.execPath, [path.join(OUTILS, nom), ...args], { cwd: PROJECT_ROOT, ...o });
  const out = [];
  const err = [];
  c.stdout.on("data", (d) => out.push(d));
  c.stderr.on("data", (d) => err.push(d));
  c.on("close", (status) => resolve({ status, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
});
const TRAVAIL = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-test-supervision-"));
after(() => fs.rmSync(TRAVAIL, { recursive: true, force: true }));

/** Cellules d'une ligne de table Markdown (« \| » rendu par « | », code compris). */
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
/** Lignes des tables de règles de 10.4 à 10.7 : { section, nom, expr, pour, gravite, exigence, runbook }. */
function tablesRegles() {
  const out = [];
  for (const [a, b] of [["### 10.4 ", "### 10.5 "], ["### 10.5 ", "### 10.6 "], ["### 10.6 ", "### 10.7 "], ["### 10.7 ", "### 10.8 "]]) {
    for (const l of section(CT8, a, b).split("\n")) {
      if (!l.startsWith("| `noortrace_")) continue;
      const c = cellules(l);
      out.push({ section: a.slice(4).trim(), nom: c[0].replaceAll("\u0060", ""), cellule: c[1], pour: c[2], gravite: c[3].split(" ")[0], exigence: c[4].replaceAll("\u0060", ""), runbook: c[5] });
    }
  }
  return out;
}
const TABLES = tablesRegles();
const FICHIER = yaml.load(lire(OBS, "regles-noortrace.yml"));
const REGLES = FICHIER.groups.flatMap((g) => g.rules);
const parNom = new Map(REGLES.map((r) => [r.alert, r]));

/** promtool 3.5.0 : NOORTRACE_PROMTOOL, sinon promtool du PATH ; null s'il manque ou n'est pas 3.5.0. */
function promtool() {
  const bin = process.env.NOORTRACE_PROMTOOL || "promtool";
  const r = spawnSync(bin, ["--version"], { encoding: "utf8" });
  if (r.error || r.status !== 0) return null;
  return /promtool, version 3\.5\.0 /.test(r.stdout + r.stderr) ? bin : null;
}
const PROMTOOL = promtool();
const CONDITION_PROMTOOL = "promtool 3.5.0 absent (CT-8 EX-10.10 : archive de Prometheus 3.5.0 à SHA-256 fixé, étape de CI d'EX-A.27 ; NOORTRACE_PROMTOOL ou PATH)";

describe("CT-8 §10.4 à §10.7 : règles d'alerte de référence (SV-1 à SV-4)", function () {
  it("SV-1 : chaque règle des tables de 10.4 à 10.7 est dans le fichier, dans l'ordre, et rien d'autre ; les deux règles d'EX-10.9 sont dans la table de 10.7 (révision 0.6 de CT-8, écart E-C5 adopté)", function () {
    const noms = REGLES.map((r) => r.alert);
    expect(noms).to.deep.equal(TABLES.map((t) => t.nom));
    for (const n of ["noortrace_releve_externe_echec", "noortrace_releve_externe_perime"]) expect(parNom.get(n).labels).to.include({ exigence: "CT-8 EX-10.9", severity: "critique" });
    expect(TABLES).to.have.length(88);
  });

  it("SV-1 : chaque alerte prescrite par CT-2 §17.4 (deux tables), CT-5 §8.9 et les EX de CT-4 nommés par EX-10.1 a au moins une règle dont l'étiquette exigence la nomme", function () {
    const exigences = REGLES.flatMap((r) => r.labels.exigence.split(" ; "));
    const sec = section(CT2, "### 17.4 ", "### 17.5 ");
    const ct2 = sec.split("\n").filter((l) => l.startsWith("| ") && !l.startsWith("| Alerte")).map((l) => cellules(l)[0].replace(/ \(révision [0-9.]+\)$/, ""));
    expect(ct2).to.have.length(32);
    const norm = (s) => s.toLowerCase();
    for (const a of ct2) {
      const ok = exigences.some((e) => e.startsWith("CT-2 §17.4 ") && (norm(a).startsWith(norm(e.slice(11).replace(/ \(.*$/, ""))) || norm(e.slice(11)).startsWith(norm(a))));
      expect(ok, `CT-2 §17.4 « ${a} »`).to.equal(true);
    }
    const p89 = section(CT5, "Alertes prescrites (CT-8 donne les règles)", "Journal d'exploitation (CT-2 §17.3");
    const ct5 = ["anchor_pending", "registry_pending", "« ancre en retard »", "checkpoint_anchor_late", "inclusion_late", "prestataire_injoignable", "prestataires_epuises", "file_pleine", "file_perdue", "ots_give_up", "ordre_ancres_non_respecte", "empreinte_squattee", "horloge_suspecte", "revoque", "reponse_tardive_promue", "point_manquant", "jeton_anterieur_au_point", "contresignature_tardive", "volume de requêtes"];
    for (const a of ct5) {
      expect(p89.replace(/\n/g, " ").replace(/\u0060/g, ""), a).to.contain(a.replace(/[«»] ?| ?»/g, "").trim());
      expect(exigences.some((e) => e.startsWith("CT-5 §8.9 ") && e.includes(a)), `CT-5 §8.9 ${a}`).to.equal(true);
    }
    for (const ex of ["EX-4.20", "EX-8.3", "EX-8.18", "EX-9.4", "EX-9.6", "EX-10.8", "§13"]) expect(exigences.some((e) => e.startsWith("CT-4 ") && e.includes(ex)), `CT-4 ${ex}`).to.equal(true);
  });

  it("SV-1, SV-4 : gravité, exigence, runbook et clause for de chaque règle égaux à sa ligne de table ; expression égale à celle de la table aux valeurs de référence près, écarts E-C1 à E-C4 compris (noms du code et forme de Prometheus 3, adoptés par la révision 0.6 de CT-8)", function () {
    const p = S.seuils(S.PARAMETRES_DEFAUT);
    const subst = (e) => e.replace("<racine>", p.racine).replace("<A_h>", String(p.a_h)).replace("<M>", String(p.mempool)).replace("<S>", String(p.solde)).replace("<RPO>", String(p.rpo));
    const ecarts = new Map(S.REGLES.filter((r) => r.ecart).map((r) => [r.alert, r.ecart]));
    let precedente = null;
    for (const t of TABLES) {
      const r = parNom.get(t.nom);
      expect(r.labels.severity, t.nom).to.equal(t.gravite);
      expect(r.labels.exigence, t.nom).to.equal(t.exigence);
      const rb = t.runbook.match(/RB-[0-9]+/g);
      expect(r.labels.runbook, t.nom).to.equal(rb ? rb.join(", ") : "aucun");
      const pour = t.pour === "—" ? undefined : t.pour.split(" ")[0];
      expect(r.for, t.nom).to.equal(pour);
      if (t.section === "10.4") expect(r.labels.component).to.equal("enregistreur");
      if (t.section === "10.5") expect(r.labels.component).to.equal("ancrage");
      if (t.section === "10.6") expect(r.labels.component).to.equal("registre");
      const m = /^\u0060([^\u0060]*)\u0060/.exec(t.cellule);
      let attendue = m ? subst(m[1]) : null;
      if (t.cellule.startsWith("même expression")) attendue = precedente.replace(/ > 0$/, " " + /\u0060([^\u0060]*)\u0060/.exec(t.cellule)[1]);
      if (ecarts.has(t.nom)) expect(S.ECARTS_CT8, t.nom).to.have.property(ecarts.get(t.nom));
      expect(r.expr, t.nom).to.equal(attendue);
      precedente = attendue;
    }
  });

  it("SV-3 : étiquettes exactement severity, component, exigence, runbook ; severity et component énumérés (EX-10.2) ; annotations summary et description en français, sans gabarit ; noms uniques de la forme ^noortrace_[a-z0-9_]+$", function () {
    const vus = new Set();
    for (const r of REGLES) {
      expect(r.alert).to.match(/^noortrace_[a-z0-9_]+$/);
      expect(vus.has(r.alert), r.alert).to.equal(false);
      vus.add(r.alert);
      expect(Object.keys(r.labels).sort()).to.deep.equal(["component", "exigence", "runbook", "severity"]);
      expect(S.GRAVITES).to.include(r.labels.severity);
      expect(S.COMPOSANTS).to.include(r.labels.component);
      expect(r.labels.runbook).to.match(/^(aucun|RB-[1-8](, RB-[1-8])*)$/);
      expect(Object.keys(r.annotations).sort()).to.deep.equal(["description", "summary"]);
      for (const v of [...Object.values(r.labels), ...Object.values(r.annotations)]) expect(v).to.not.match(/\{\{|\$labels|\$value|https?:/);
    }
  });

  it("SV-4 : le fichier s'analyse en YAML ; chaque règle a alert, expr, labels, annotations, et for exactement quand la colonne « Pendant » n'est pas vide ; chaque expression s'analyse (évaluateur réduit)", function () {
    expect(Object.keys(FICHIER)).to.deep.equal(["groups"]);
    for (const g of FICHIER.groups) expect(Object.keys(g).sort()).to.deep.equal(["name", "rules"]);
    for (const r of REGLES) {
      const t = TABLES.find((x) => x.nom === r.alert);
      const cles = ["alert", "expr", ...(t ? (t.pour === "—" ? [] : ["for"]) : []), "labels", "annotations"];
      expect(Object.keys(r), r.alert).to.deep.equal(cles);
      expect(() => analyser(r.expr), r.alert).to.not.throw();
    }
  });

  it("SV-2 : chaque nom de métrique d'une expression est dans 10.3, EX-10.7, EX-10.9, CT-2 §17.2 et EX-17.8, CT-5 EX-8.15, la liste noor_* (R8-F43), up ou node_* des trois règles de l'hôte ; node_* hors de ces trois règles seulement dans noortrace_disque_espace (CT-2 §17.4 Disque)", function () {
    for (const r of REGLES) {
      for (const n of S.nomsMetriques(r.expr)) {
        expect(S.metriqueAdmise(n), `${r.alert} : ${n}`).to.equal(true);
        if (n.startsWith("node_")) expect(["noortrace_hote_disque", "noortrace_hote_memoire", "noortrace_hote_processeur", "noortrace_disque_espace"]).to.include(r.alert);
      }
    }
    // Les noms de CT-5 EX-8.15 et de l'extracteur sont ceux du code (écart E-10 de l'étape 7).
    const ancrage = lire(PROJECT_ROOT, "paquets", "ancrage", "src", "planificateur", "supervision.mjs");
    for (const n of Object.keys(S.METRIQUES_ADMISES).filter((x) => x.startsWith("noortrace_anchoring_"))) expect(ancrage, n).to.contain(n);
  });

  it("EX-10.10 (évaluateur réduit) : tests-regles.yml a, pour chaque règle, une série qui la déclenche et une qui ne la déclenche pas, et chaque cas rend l'issue attendue ; un mutant de chaque règle (expression jamais vraie) fait échouer son cas déclenché", function () {
    const t = yaml.load(lire(OBS, "tests-regles.yml"));
    expect(t.rule_files).to.deep.equal(["regles-noortrace.yml"]);
    const ecarts = [];
    for (const r of REGLES) {
      const g = t.tests.filter((x) => x.alert_rule_test[0].alertname === r.alert);
      expect(g.map((x) => x.alert_rule_test[0].exp_alerts.length > 0), r.alert).to.deep.equal([true, false]);
      for (const x of g) ecarts.push(...rejouerGroupe(x, REGLES, t.evaluation_interval));
      const mutant = REGLES.map((y) => (y.alert === r.alert ? { ...y, expr: `(${y.expr}) and on () noortrace_metrique_absente == 1` } : y));
      expect(rejouerGroupe(g[0], mutant, t.evaluation_interval), r.alert).to.not.deep.equal([]);
    }
    expect(ecarts).to.deep.equal([]);
  });
});

describe("CT-8 §10.10, EX-A.27 : promtool 3.5.0 (confrontation tierce, EX-A.31)", function () {
  it("TV-76, EX-10.10 : promtool check rules sur regles-noortrace.yml puis promtool test rules sur tests-regles.yml, code 0", function () {
    if (!PROMTOOL) {
      this.test.title += ` — en attente : ${CONDITION_PROMTOOL}`;
      this.skip();
    }
    const c = spawnSync(PROMTOOL, ["check", "rules", path.join(OBS, "regles-noortrace.yml")], { encoding: "utf8" });
    expect(c.status, c.stdout + c.stderr).to.equal(0);
    const t = spawnSync(PROMTOOL, ["test", "rules", path.join(OBS, "tests-regles.yml")], { encoding: "utf8" });
    expect(t.status, t.stdout + t.stderr).to.equal(0);
  });
});

describe("CT-8 §10.3 : extracteur des journaux (SV-5, EX-10.5)", function () {
  it("TV-76 : supervision/ — l'extracteur rejoué sur journaux/ rend attendu.prom (SV-5), regles.mjs rend le fichier du dépôt et regles-attendues.yml (SV-6), chaque alerte prescrite a sa règle (SV-1)", function () {
    const r = outil("extraire-journaux.mjs", ["--repertoire", path.join(VECT, "journaux")]);
    expect(r.status, r.stderr).to.equal(0);
    expect(r.stdout).to.equal(lire(VECT, "attendu.prom"));
    const a = outil("regles.mjs", []);
    expect(a.status).to.equal(0);
    expect(a.stdout).to.equal(lire(OBS, "regles-noortrace.yml"));
    const b = outil("regles.mjs", ["--configuration", path.join(VECT, "configuration-modifiee.json"), "--ancrage", path.join(VECT, "ancrage-modifie.json")]);
    expect(b.status, b.stderr).to.equal(0);
    expect(b.stdout).to.equal(lire(VECT, "regles-attendues.yml"));
    expect(TABLES.every((t) => parNom.has(t.nom))).to.equal(true);
  });

  it("SV-5 : la bibliothèque (extraireJournaux) rend la même exposition que l'outil ; chaque ligne de la table de 10.3 est exercée par journaux/ et une ligne illisible au moins ; detail vide hors de la table", function () {
    const sources = {};
    const racine = path.join(VECT, "journaux");
    const fichiers = (rep) => fs.readdirSync(rep, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1)).flatMap((e) => (e.isDirectory() ? fichiers(path.join(rep, e.name)) : [path.join(rep, e.name)]));
    for (const s of S.SOURCES) sources[s] = fichiers(path.join(racine, s)).filter((f) => s !== "registre" || f.endsWith(".json")).map((f) => fs.readFileSync(f));
    sources.proces_verbaux = fichiers(path.join(racine, "proces-verbaux")).map((f) => {
      const t = fs.readFileSync(f, "utf8");
      return { document: JSON.parse(t), valide: verifierProcesVerbal(t, {}).checks[0].status === "reussi" };
    });
    const x = S.extraireJournaux(sources);
    expect(x).to.equal(lire(VECT, "attendu.prom"));
    for (const d of ["conforme", "non_conforme", "gel_absent", "garde_violee", "levee", "autre", "recree", "aucune", "empreinte_squattee", "exterieur", "interne", "lecture_impossible", "exports_indisponible", "politique_invalide_au_charger", "horloge_suspecte", "reponse_tardive_promue", "revoque", "marge_retention_basse", "examen_requis", "inconnu", "reseau", "file_pleine"]) expect(x, d).to.contain(`detail="${d}"`);
    expect(x).to.match(/noortrace_journal_illisibles_total\{source="exploitation"\} 2/);
    expect(x).to.match(/noortrace_proces_verbal_dernier_s\{kind="sauvegarde"\} 1793919761/);
    expect(x).to.not.contain('detail="respectee"');
  });

  it("EX-10.5 : lecture en ajout — une ligne sans LF n'est pas lue avant d'être finie ; les compteurs se cumulent d'une passe à l'autre ; un fichier tourné (remplacé) est relu depuis le début ; les fichiers lus ne sont jamais écrits", function () {
    const d = path.join(TRAVAIL, "ajout");
    fs.mkdirSync(path.join(d, "exploitation"), { recursive: true });
    const f = path.join(d, "exploitation", "exploitation.ndjson");
    const l = (ev, ts) => JSON.stringify({ ts, level: "error", component: "noyau", event: ev, data: {} });
    fs.writeFileSync(f, `${l("journal_fork", "2026-11-05T08:00:00.000Z")}\n${l("disk_low", "2026-11-05T08:00:01.000Z").slice(0, 20)}`);
    const x = new ExtracteurFichiers({ exploitation: [path.join(d, "exploitation")] });
    let e = x.passe();
    expect(e).to.contain('event="journal_fork",level="error",detail=""} 1');
    expect(e).to.not.contain("disk_low");
    fs.appendFileSync(f, `${l("disk_low", "2026-11-05T08:00:01.000Z").slice(20)}\n${l("journal_fork", "2026-11-05T08:00:02.000Z")}\n`);
    e = x.passe();
    expect(e).to.contain('event="journal_fork",level="error",detail=""} 2');
    expect(e).to.contain('event="disk_low",level="error",detail=""} 1');
    expect(e).to.contain('noortrace_journal_illisibles_total{source="exploitation"} 0');
    // Rotation : le fichier est remplacé par un fichier neuf, plus court.
    fs.renameSync(f, `${f}.1`);
    fs.writeFileSync(f, `${l("journal_fork", "2026-11-05T09:00:00.000Z")}\n`);
    const tourne = fs.readFileSync(`${f}.1`);
    const nouveau = fs.readFileSync(f);
    e = x.passe();
    expect(e).to.contain('event="journal_fork",level="error",detail=""} 3');
    expect(e).to.contain('noortrace_journal_derniere_ligne_s{source="exploitation",event="journal_fork"} 1793869200');
    // Le fichier tourné garde sa position (même inode) : rien n'est relu deux fois ; aucun fichier lu n'est écrit.
    expect(x.passe()).to.equal(e);
    expect(fs.readFileSync(`${f}.1`).equals(tourne)).to.equal(true);
    expect(fs.readFileSync(f).equals(nouveau)).to.equal(true);
  });

  it("extraire-journaux.mjs : option inconnue → 2 ; ni --repertoire ni source → 2 ; répertoire absent → 1 ; --sortie écrit le fichier par renommage", function () {
    expect(outil("extraire-journaux.mjs", ["--bidule"]).status).to.equal(2);
    expect(outil("extraire-journaux.mjs", []).status).to.equal(2);
    expect(outil("extraire-journaux.mjs", ["--repertoire", path.join(TRAVAIL, "absent")]).status).to.equal(1);
    const s = path.join(TRAVAIL, "extracteur.prom");
    const r = outil("extraire-journaux.mjs", ["--exploitation", path.join(VECT, "journaux", "exploitation"), "--sortie", s]);
    expect(r.status, r.stderr).to.equal(0);
    expect(fs.readFileSync(s, "utf8")).to.contain('source="exploitation",event="journal_fork"');
    expect(fs.readdirSync(TRAVAIL).filter((n) => n.endsWith(".tmp"))).to.deep.equal([]);
  });
});

describe("CT-8 EX-10.6 : générateur des règles (SV-6)", function () {
  it("SV-6 : regles.mjs --reference écrit les quatre fichiers de deploiement/observabilite/ à l'octet ; avec les entrées de l'exemple de 9.5 (--dimensionnement), <A_h> = 76 et le fichier de référence", function () {
    for (const [nom, texte] of fichiersReference()) expect(texte, nom).to.equal(lire(OBS, nom));
    expect(fs.readdirSync(OBS).sort()).to.deep.equal(["prometheus.yml", "regles-noortrace.yml", "tableau-noortrace.json", "tests-regles.yml"]);
    const entrees = JSON.parse(/<!-- schema: dimensionnement -->\n\u0060{3}json\n([\s\S]*?)\n\u0060{3}/.exec(CT8)[1]);
    const f = path.join(TRAVAIL, "entrees-9-5.json");
    fs.writeFileSync(f, JSON.stringify(entrees));
    const r = outil("regles.mjs", ["--dimensionnement", f]);
    expect(r.status, r.stderr).to.equal(0);
    expect(r.stdout).to.equal(lire(OBS, "regles-noortrace.yml"));
  });

  it("SV-6 : les règles régénérées pour d'autres valeurs ont leurs tests (--tests), que l'évaluateur réduit rejoue sans écart ; un seuil change seulement les règles qu'il paramètre", function () {
    const docs = { configuration: JSON.parse(lire(VECT, "configuration-modifiee.json")), ancrage: JSON.parse(lire(VECT, "ancrage-modifie.json")), txpool_max_pending: 1000, rpo_s: 3600 };
    const p = S.parametresRegles(docs);
    const regles = yaml.load(S.genererRegles(docs)).groups.flatMap((g) => g.rules);
    const tests = yaml.load(S.genererTestsRegles(p));
    for (const g of tests.tests) expect(rejouerGroupe(g, regles, tests.evaluation_interval)).to.deep.equal([]);
    const diff = regles.filter((r) => JSON.stringify(r) !== JSON.stringify(parNom.get(r.alert))).map((r) => r.alert).sort();
    expect(diff).to.deep.equal(Object.keys(S.REGLES_PARAMETREES).filter((n) => !["noortrace_ancrage_volume", "noortrace_registre_solde_bas"].includes(n)).sort());
  });

  it("regles.mjs : option inconnue → 2 ; --reference avec une autre option → 2 ; document illisible → 1 ; inclusion_alert_s hors des bornes de noortrace_anchoring_d_registre_s → 1 ; manifeste d'instance : <S> = refill_below_days × 10 800 000 + gas_limit", function () {
    expect(outil("regles.mjs", ["--bidule"]).status).to.equal(2);
    expect(outil("regles.mjs", ["--reference", TRAVAIL, "--tests"]).status).to.equal(2);
    expect(outil("regles.mjs", ["--configuration", path.join(TRAVAIL, "absent.json")]).status).to.equal(1);
    const a = path.join(TRAVAIL, "ancrage-45.json");
    fs.writeFileSync(a, JSON.stringify({ registry: { inclusion_alert_s: 45 } }));
    const r = outil("regles.mjs", ["--ancrage", a]);
    expect(r.status).to.equal(1);
    expect(r.stderr).to.contain("inclusion_alert_s = 45");
    const i = path.join(TRAVAIL, "instance.json");
    fs.writeFileSync(i, JSON.stringify({ fees: { refill_below_days: 3, gas_limit: 2000000 } }));
    const s = outil("regles.mjs", ["--instance", i]);
    expect(s.status, s.stderr).to.equal(0);
    expect(s.stdout).to.contain(`noortrace_registre_solde_wei < ${3 * 10800000 + 2000000}`);
  });
});

describe("CT-8 §10.8, EX-10.4 : tableau de bord et collecte de référence (SV-7)", function () {
  it("SV-7 : chaque expression du tableau ne nomme que des métriques admises par SV-2 ; une rangée par ligne de la table de 10.8, dans l'ordre ; uid et panneaux", function () {
    const t = JSON.parse(lire(OBS, "tableau-noortrace.json"));
    expect(t.uid).to.equal("noortrace");
    const exprs = S.expressionsTableau(t);
    expect(exprs.length).to.be.greaterThan(25);
    for (const e of exprs) {
      expect(() => analyser(e), e).to.not.throw();
      for (const n of S.nomsMetriques(e)) expect(S.metriqueAdmise(n), `${e} : ${n}`).to.equal(true);
    }
    const rangees = section(CT8, "### 10.8 ", "### 10.9 ").split("\n").filter((l) => l.startsWith("| ") && !l.startsWith("| Rangée")).map((l) => cellules(l)[0]);
    expect(t.panels.filter((p) => p.type === "row").map((p) => p.title)).to.deep.equal(rangees);
  });

  it("EX-10.4 : prometheus.yml — chaque cible sur 127.0.0.1 porte l'étiquette role (active ou passive, validateur ou relais, hote) ; job noorcore (règle noortrace_registre_cible_muette) ; règles de référence chargées", function () {
    const p = yaml.load(lire(OBS, "prometheus.yml"));
    expect(p.rule_files).to.deep.equal(["regles-noortrace.yml"]);
    const jobs = p.scrape_configs.map((s) => s.job_name);
    expect(jobs).to.include.members(["enregistreur", "noorcore", "hote"]);
    for (const s of p.scrape_configs) {
      for (const c of s.static_configs) {
        for (const t of c.targets) expect(t).to.match(/^127\.0\.0\.1:[0-9]+$/);
        expect(["active", "passive", "validateur", "relais", "hote"]).to.include(c.labels.role);
      }
    }
    expect(p.scrape_configs.find((s) => s.job_name === "enregistreur").static_configs[0].labels.role).to.equal("active");
  });
});

/** Serveur HTTP local qui répond par une fonction (méthode, chemin, corps) → [statut, corps]. */
async function serveur(f) {
  const s = http.createServer((req, res) => {
    const m = [];
    req.on("data", (d) => m.push(d));
    req.on("end", () => {
      const [statut, corps] = f(req.method, req.url, Buffer.concat(m).toString("utf8"));
      res.writeHead(statut, { "content-type": "application/json" }).end(typeof corps === "string" ? corps : JSON.stringify(corps));
    });
  });
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${s.address().port}`, fermer: () => new Promise((r) => s.close(r)) };
}

describe("CT-8 EX-10.7, EX-10.9 : sonde et relevé hors du composant", function () {
  it("EX-10.7 : sonde.mjs sur des services locaux — approbation prête (1, tickets, âge du jeu), console prête (1), point RPC (hauteur, mempool), solde de l'expéditeur ; point RPC muet → sonde_ok 0 ; aucune transaction soumise", async function () {
    const methodes = [];
    const app = await serveur((m, u) => (u === "/v0/etat" ? [200, { ready: true, set_read_at: "2026-11-05T10:00:00.000Z", open_tickets: 2 }] : [404, {}]));
    const cons = await serveur((m, u) => (u === "/v0/sante" ? [200, { ready: true, service_reachable: true, identity_ready: true, checked_at: "2026-11-05T10:00:00.000Z" }] : [404, {}]));
    const rpc = await serveur((m, u, corps) => {
      const q = JSON.parse(corps);
      methodes.push(q.method);
      const r = { eth_blockNumber: "0x4e20", eth_getBlockTransactionCountByNumber: "0x3", eth_getBalance: "0x4af6e00" }[q.method];
      return [200, { jsonrpc: "2.0", id: q.id, result: r }];
    });
    try {
      const r = await outilAsync("sonde.mjs", ["--approbation", app.url, "--console", cons.url, "--rpc", `validateur-1=${rpc.url}`, "--rpc", "validateur-2=http://127.0.0.1:9", "--expediteur", "0xF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266", "--delai", "1000"]);
      expect(r.status, r.stderr).to.equal(0);
      expect(r.stdout).to.contain("noortrace_approbation_pret 1\n");
      expect(r.stdout).to.contain("noortrace_approbation_tickets_ouverts 2\n");
      expect(r.stdout).to.match(/noortrace_approbation_jeu_lu_age_s [0-9]+/);
      expect(r.stdout).to.contain("noortrace_console_prete 1\n");
      expect(r.stdout).to.contain('noortrace_registre_sonde_ok{target="validateur-1"} 1');
      expect(r.stdout).to.contain('noortrace_registre_sonde_ok{target="validateur-2"} 0');
      expect(r.stdout).to.contain('noortrace_registre_hauteur{target="validateur-1"} 20000');
      expect(r.stdout).to.contain('noortrace_registre_mempool{target="validateur-1"} 3');
      expect(r.stdout).to.contain(`noortrace_registre_solde_wei{sender="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"} ${BigInt("0x4af6e00")}`);
      expect(r.stdout).to.not.contain('target="validateur-2"} 2');
      expect([...new Set(methodes)].sort()).to.deep.equal(["eth_blockNumber", "eth_getBalance", "eth_getBlockTransactionCountByNumber"]);
      for (const n of S.nomsMetriques(r.stdout.split("\n").filter((l) => l && !l.startsWith("#")).map((l) => l.split(" ")[0]).join(" + "))) expect(S.metriqueAdmise(n), n).to.equal(true);
    } finally {
      await app.fermer();
      await cons.fermer();
      await rpc.fermer();
    }
  });

  it("EX-10.7 : noortrace_approbation_pret vaut 0 sans réponse (service arrêté ou configuration refusée), pour un statut autre que 200, pour un corps hors de la forme de CT-3 EX-12.12, et pour ready faux ; même règle pour la console (CT-3 EX-13.44)", function () {
    const e = (approbation, console) => expositionSonde({ approbation, console, rpc: [], soldes: [] }, Date.parse("2026-11-05T10:00:10.000Z"));
    const ok = { ready: true, set_read_at: null, open_tickets: 0 };
    expect(e({ statut: 200, corps: ok }, undefined)).to.contain("noortrace_approbation_pret 1\n");
    expect(e(null, undefined)).to.contain("noortrace_approbation_pret 0\n");
    expect(e({ statut: 503, corps: ok }, undefined)).to.contain("noortrace_approbation_pret 0\n");
    expect(e({ statut: 200, corps: { ...ok, autre: 1 } }, undefined)).to.contain("noortrace_approbation_pret 0\n");
    expect(e({ statut: 200, corps: { ...ok, ready: false } }, undefined)).to.contain("noortrace_approbation_pret 0\n");
    expect(e({ statut: 200, corps: { ...ok, ready: false } }, undefined)).to.contain("noortrace_approbation_tickets_ouverts 0\n");
    expect(formeEtat({ ready: true, set_read_at: "2026-13-01T00:00:00Z", open_tickets: 0 })).to.equal(false);
    expect(e(null, null)).to.contain("noortrace_console_prete 0\n");
    expect(formeSante({ ready: true, service_reachable: true, identity_ready: true, checked_at: "2026-11-05T10:00:00Z" })).to.equal(true);
    expect(expediteursManifeste({ accounts: [{ role: "tresorerie", address: "0x" + "11".repeat(20), to_height: null }, { role: "relayeur", address: "0x" + "AB".repeat(20), to_height: null }, { role: "deployeur", address: "0x" + "22".repeat(20), to_height: 9 }] })).to.deep.equal(["0x" + "ab".repeat(20)]);
  });

  it("EX-10.9 : sonde.mjs releve écrit noortrace_releve_externe_ok{check} (1 si la commande rend 0, 0 sinon) et noortrace_releve_externe_dernier_s ; commande absente → 1 et jauge à 0 ; check inconnu → 2", function () {
    const f = path.join(TRAVAIL, "releve.prom");
    let r = outil("sonde.mjs", ["releve", "--check", "console", "--sortie", f, "--", process.execPath, "-e", "process.exit(0)"]);
    expect(r.status, r.stderr).to.equal(0);
    expect(fs.readFileSync(f, "utf8")).to.contain('noortrace_releve_externe_ok{check="console"} 1');
    r = outil("sonde.mjs", ["releve", "--check", "console", "--sortie", f, "--", process.execPath, "-e", "process.exit(3)"]);
    expect(r.status).to.equal(0);
    expect(fs.readFileSync(f, "utf8")).to.contain('noortrace_releve_externe_ok{check="console"} 0');
    expect(fs.readFileSync(f, "utf8")).to.match(/noortrace_releve_externe_dernier_s\{check="console"\} [0-9]+(\.[0-9]+)?\n/);
    r = outil("sonde.mjs", ["releve", "--check", "console", "--sortie", f, "--", path.join(TRAVAIL, "commande-absente")]);
    expect(r.status).to.equal(1);
    expect(fs.readFileSync(f, "utf8")).to.contain('noortrace_releve_externe_ok{check="console"} 0');
    expect(outil("sonde.mjs", ["releve", "--check", "autre", "--sortie", f, "--", "true"]).status).to.equal(2);
    expect(outil("sonde.mjs", ["--bidule"]).status).to.equal(2);
    expect(expositionReleve("registre_gels", true, 1793872800123)).to.contain('noortrace_releve_externe_dernier_s{check="registre_gels"} 1793872800.123');
  });
});

// ---------------------------------------------------------------------------
// TA-29, TA-75 : contre un S3 à Object Lock (LocalStack, Docker)
// ---------------------------------------------------------------------------

/** Rejoue une règle du fichier de référence sur une série échantillonnée chaque minute ; rend l'état à chaque instant demandé. */
function alerteAux(nomRegle, regles, series, instants) {
  const r = regles.find((x) => x.alert === nomRegle);
  const arbre = analyser(r.expr);
  const pour = r.for ? Number(/^([0-9]+)([smh])$/.exec(r.for)[1]) * { s: 1000, m: 60000, h: 3600000 }[/^([0-9]+)([smh])$/.exec(r.for)[2]] : 0;
  const fin = Math.max(...instants);
  const etats = new Map();
  let depuis = null;
  for (let t = 0; t <= fin; t += 60000) {
    const v = evaluer(arbre, series, t);
    if (v.length) depuis ??= t;
    else depuis = null;
    if (instants.includes(t)) etats.set(t, depuis !== null && t - depuis >= pour);
  }
  return instants.map((t) => etats.get(t));
}

/** Rejoue une règle par promtool sur les mêmes séries ; null sans promtool. */
function promtoolAux(nomRegle, serie, valeurs, cas) {
  if (!PROMTOOL) return null;
  const r = REGLES.find((x) => x.alert === nomRegle);
  const f = path.join(TRAVAIL, `ta-${nomRegle}.yml`);
  const tests = {
    rule_files: [path.join(OBS, "regles-noortrace.yml")],
    evaluation_interval: "1m",
    tests: [{ interval: "1m", input_series: [{ series: serie, values: valeurs }], alert_rule_test: cas.map(([t, attendue, et]) => ({ eval_time: t, alertname: nomRegle, exp_alerts: attendue ? [{ exp_labels: { ...et, ...r.labels }, exp_annotations: r.annotations }] : [] })) }],
  };
  fs.writeFileSync(f, yaml.dump(tests));
  return spawnSync(PROMTOOL, ["test", "rules", f], { encoding: "utf8" });
}

describe("CT-9 TA-29 et TA-75 : alertes de la supervision sur un S3 à Object Lock (CT-2 EX-12.16, EX-12.18, EX-17.5, EX-17.7)", function () {
  this.timeout(600000);
  const docker = dockerDisponible([IMAGES.s3]);
  let dir;
  let s3;
  let tls;
  let prox;
  let n = 0;
  const RAPIDE = [20, 20, 20];
  const horloge = (decalage) => ({ murale: () => Date.now() + decalage, monotone: () => performance.now() + 1e7 + decalage });
  const versHeureSuivante = () => 3600000 - (Date.now() % 3600000) + 2000;

  before(async function () {
    if (!docker.ok) return;
    dir = repertoireTemporaire("noortrace-supervision-worm-");
    s3 = await demarrerS3(`noortrace-test-supervision-s3-${process.pid}`);
    tls = certificats(path.join(dir, "tls"));
    fs.writeFileSync(path.join(dir, "ca.pem"), tls.caPem);
    prox = await mandataireTls(tls, { port: s3.port });
  });
  after(async function () {
    await prox?.fermer();
    arreterTout();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });
  beforeEach(function () {
    if (!docker.ok) {
      this.currentTest.title += ` — en attente : ${docker.condition}`;
      this.skip();
    }
  });

  async function journal() {
    const d = path.join(dir, `j${++n}`);
    const bucket = `noortrace-sup-${process.pid}-${n}`;
    await creerBucketVerrouille(prox.origine, bucket, { ca: tls.caPem, jours: 4018, mode: "COMPLIANCE" });
    const { config, env } = configurationDev(d, { journal_id: N.octetsVersHex(N.keccak256(N.utf8(`journal-supervision-${process.pid}-${n}`))) });
    config.storage.seal.worm = {
      type: "s3-object-lock", bucket, prefix: "journal-test/", mode: "compliance", retain_days: 4018,
      credentials: { file: fichierSecret(path.join(d, "secrets", "worm-ecrivain"), identifiantsRole("ecrivain")) },
      endpoint: prox.origine, region: null, legal_hold_on_write: false, lock_audit_interval_days: 30, copy_pieces: false,
    };
    const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)), { reglesSupplementaires: [controleWorm] });
    expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
    const s = resoudreSecrets(v.config, { env });
    expect(s.erreurs).to.deep.equal([]);
    const fichier = path.join(d, "configuration.json");
    fs.writeFileSync(fichier, JSON.stringify(config));
    const ref = (role) => JSON.stringify({ file: fichierSecret(path.join(d, "secrets", role), identifiantsRole(role)) });
    return { d, config: v.config, env, secrets: s.secrets, fichier, ref };
  }
  async function coeur(j, decalage = 0, o = {}) {
    const worm = o.worm ?? supportWormDepuisConfiguration(j.config, j.secrets, { tls: { ca: tls.caPem }, delais: RAPIDE });
    const c = await Coeur.demarrer({ config: j.config, secrets: j.secrets, worm, horloge: horloge(decalage) });
    return { c, worm };
  }
  const valeur = (texte, nom) => {
    const m = new RegExp(`^${nom} ([0-9.e+-]+)$`, "m").exec(texte);
    return m ? Number(m[1]) : null;
  };

  it("TA-29 (MN-29) : support WORM injoignable et segment fermé → noortrace_worm_copy_pending ≥ 1, la règle noortrace_copie_worm_en_retard (for 1h) se déclenche à l'échéance et pas avant ; support rétabli → balayage, métrique à 0, alerte résolue ; réponse retirée (pas de comparaison horaire, métrique jamais mise à jour) : aucune alerte", async function () {
    const j = await journal();
    const a = await coeur(j);
    await a.c.arreter();
    const coupe = await mandataireTls(tls, { port: s3.port });
    await coupe.fermer();
    const jc = { ...j.config, storage: { ...j.config.storage, seal: { ...j.config.storage.seal, worm: { ...j.config.storage.seal.worm, endpoint: coupe.origine } } } };
    const worm = supportWormDepuisConfiguration(jc, j.secrets, { tls: { ca: tls.caPem }, delais: RAPIDE });
    const b = await coeur(j, versHeureSuivante(), { worm });
    try {
      await b.c.tic();
      await worm.vider();
      await worm.balayer();
      const ferme = valeur(b.c.metriques.exposer(), "noortrace_worm_copy_pending");
      expect(ferme, "noortrace_worm_copy_pending, support fermé").to.be.at.least(1);
      expect(b.c.journal.trouver("worm_copy_failed")[0].data.raison).to.equal("injoignable");
      worm.operations = supportWormDepuisConfiguration(j.config, j.secrets, { tls: { ca: tls.caPem }, delais: RAPIDE }).operations;
      const r = await worm.balayer();
      expect(r.manquantes).to.equal(0);
      const rouvert = valeur(b.c.metriques.exposer(), "noortrace_worm_copy_pending");
      expect(rouvert).to.equal(0);
      // Horloge accélérée de la supervision : la valeur relevée support fermé tient 90 min, puis la valeur relevée après réouverture.
      const ech = [...Array(91)].map((_, k) => ({ t: k * 60000, v: ferme })).concat([...Array(10)].map((_, k) => ({ t: (91 + k) * 60000, v: rouvert })));
      const series = [{ et: { __name__: "noortrace_worm_copy_pending", instance: "127.0.0.1:8500", job: "enregistreur", role: "active" }, ech }];
      expect(alerteAux("noortrace_copie_worm_en_retard", REGLES, series, [59 * 60000, 60 * 60000, 90 * 60000, 92 * 60000])).to.deep.equal([false, true, true, false]);
      const sansReponse = [{ et: series[0].et, ech: ech.map((e) => ({ t: e.t, v: 0 })) }];
      expect(alerteAux("noortrace_copie_worm_en_retard", REGLES, sansReponse, [60 * 60000, 90 * 60000])).to.deep.equal([false, false]);
      const p = promtoolAux("noortrace_copie_worm_en_retard", 'noortrace_worm_copy_pending{instance="127.0.0.1:8500", job="enregistreur", role="active"}', `${ferme}x90 ${rouvert}x10`, [["59m", false], ["60m", true, { instance: "127.0.0.1:8500", job: "enregistreur", role: "active" }], ["92m", false]]);
      if (p) expect(p.status, p.stdout + p.stderr).to.equal(0);
    } finally {
      await b.c.arreter();
    }
  });

  it("TA-75 (MN-75) : gel posé, une version passée à off hors de l'outil, règles du démon coupées (component enregistreur) ; la relecture du Lecteur hors du démon (sonde.mjs releve, noortrace-ctl worm gel etat) rend un code non nul et nomme la version off ; noortrace_releve_externe_ok{check=\"registre_gels\"} vaut 0 et la règle critique d'EX-10.9 (component exploitation) se déclenche ; gel intact : jauge à 1, règle silencieuse", async function () {
    const j = await journal();
    const a = await coeur(j);
    const P = Math.floor(a.c.horlogeBrute.murale() / 3600000) * 3600;
    await a.c.arreter();
    const b = await coeur(j, versHeureSuivante());
    await b.c.tic();
    await b.worm.vider();
    await b.c.arreter();
    const sortie = [];
    const code = await principalCtl(["worm", "gel", "poser", "--configuration", j.fichier, "--identifiants", j.ref("gardien-pose"), "--identite", "j.dupont", "--de", String(P), "--a", String(P), "--motif", "litige"], { stdout: { write: (t) => sortie.push(t) }, stderr: { write: () => {} }, env: j.env, tls: { ca: tls.caPem }, delais: RAPIDE });
    expect(code).to.equal(0);
    const gel = sortie.join("").trim();
    const releve = (fichier) => outilAsync("sonde.mjs", ["releve", "--check", "registre_gels", "--sortie", fichier, "--", process.execPath, path.join(PROJECT_ROOT, "paquets", "enregistreur", "bin", "noortrace-ctl"), "worm", "gel", "etat", "--configuration", j.fichier, "--identifiants", j.ref("lecteur"), "--gel", gel], { env: { ...process.env, ...j.env, NODE_EXTRA_CA_CERTS: path.join(dir, "ca.pem") } });
    const regles = REGLES.filter((r) => r.labels.component !== "enregistreur");
    const regle = REGLES.find((r) => r.alert === "noortrace_releve_externe_echec");
    expect(regle.labels).to.include({ component: "exploitation", severity: "critique", exigence: "CT-8 EX-10.9" });
    const serie = (v) => [{ et: { __name__: "noortrace_releve_externe_ok", check: "registre_gels", instance: "127.0.0.1:9100", job: "hote", role: "hote" }, ech: [...Array(6)].map((_, k) => ({ t: k * 60000, v })) }];
    // Gel intact : relecture réussie.
    const f1 = path.join(dir, "releve-intact.prom");
    const r1 = await releve(f1);
    expect(r1.status, r1.stderr).to.equal(0);
    const v1 = valeur(fs.readFileSync(f1, "utf8"), 'noortrace_releve_externe_ok\\{check="registre_gels"\\}');
    expect(v1).to.equal(1);
    expect(alerteAux("noortrace_releve_externe_echec", regles, serie(v1), [3 * 60000])).to.deep.equal([false]);
    // Version passée à off hors de l'outil, par l'administrateur.
    const ops = new OperationsS3({ worm: j.config.storage.seal.worm, identifiants: identifiantsS3(new TextEncoder().encode(identifiantsRole("administrateur"))), tls: { ca: tls.caPem }, delais: RAPIDE });
    const pose = JSON.parse((await ops.lire(`journal-test/gels/${gel}/0001-pose.json`)).corps.toString("utf8"));
    const o = JSON.parse((await ops.lire(pose.objects.key)).corps.toString("utf8").split("\n")[0]);
    expect((await ops.poserGel(o.key, o.version_id, false)).statut).to.equal(200);
    const f2 = path.join(dir, "releve-off.prom");
    const r2 = await releve(f2);
    expect(r2.status, r2.stderr).to.equal(0);
    const etat = JSON.parse(r2.stdout.trim().split("\n").at(-1));
    expect(etat.actif).to.equal(true);
    expect(etat.versions.find((v) => v.key === o.key && v.version_id === o.version_id)).to.include({ legal_hold: "off", attendu: "on" });
    const codeEtat = await principalCtl(["worm", "gel", "etat", "--configuration", j.fichier, "--identifiants", j.ref("lecteur"), "--gel", gel], { stdout: { write: () => {} }, stderr: { write: () => {} }, env: j.env, tls: { ca: tls.caPem }, delais: RAPIDE });
    expect(codeEtat, "code de noortrace-ctl worm gel etat").to.not.equal(0);
    const v2 = valeur(fs.readFileSync(f2, "utf8"), 'noortrace_releve_externe_ok\\{check="registre_gels"\\}');
    expect(v2, "jauge après une relecture en échec (code non nul de gel etat)").to.equal(0);
    expect(alerteAux("noortrace_releve_externe_echec", regles, serie(v2), [0, 3 * 60000])).to.deep.equal([true, true]);
    const p = promtoolAux("noortrace_releve_externe_echec", 'noortrace_releve_externe_ok{check="registre_gels", instance="127.0.0.1:9100", job="hote", role="hote"}', `${v2}x5`, [["3m", true, { check: "registre_gels", instance: "127.0.0.1:9100", job: "hote", role: "hote" }]]);
    if (p) expect(p.status, p.stdout + p.stderr).to.equal(0);
  });
});
