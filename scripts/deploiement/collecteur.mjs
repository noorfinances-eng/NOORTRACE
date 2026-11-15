#!/usr/bin/env node
// Collecteur de la supervision en marche (CT-8 §10.2, EX-10.4 ; CT-9 TE-17,
// TM-34, TM-35, compléments de TA-29 et de TA-75) : lance Prometheus 3.5.0 sur
// une installation locale, avec la collecte de référence
// (deploiement/observabilite/prometheus.yml) dont seules les adresses des
// cibles sont remplacées, charge un fichier de règles (par défaut les règles
// de référence, deploiement/observabilite/regles-noortrace.yml) et lit l'état
// des alertes par l'API HTTP de Prometheus.
//
// Le binaire `prometheus` vient de la même archive officielle que `promtool`
// (CT-8 EX-10.10 : Prometheus 3.5.0 pour Linux amd64, SHA-256 de l'archive
// e811827af26d822afb09a4f28314f61b618b12cff5369835a67f674d8b46f39a). Cet outil
// ne télécharge rien : il reçoit le chemin du binaire (--prometheus, ou la
// variable NOORTRACE_PROMETHEUS, ou `prometheus` du PATH), contrôle sa version
// et, pour Linux amd64, son SHA-256 (SHA256_BINAIRE). Tout écoute sur l'adresse
// de bouclage ; rien ne joint un réseau.
//
//   node scripts/deploiement/collecteur.mjs lancer --travail <répertoire>
//       --cible <job>=<adresse:port|aucune>… [--textfile <répertoire>]
//       [--prometheus <binaire>] [--regles <fichier>] [--intervalle <secondes>]
//       [--reduire-for <règle>=<durée>]… [--port <n>]
//     Lance le collecteur, écrit une ligne JSON { url, pid, regles, ecarts } sur
//     la sortie standard et reste en marche jusqu'à SIGTERM ou SIGINT. Chaque
//     job de la collecte de référence (enregistreur, hote, noorcore) reçoit
//     une adresse, ou « aucune » qui le retire. --textfile sert sur un port
//     libre, à la place de l'exportateur de nœud, les fichiers .prom du
//     répertoire (ceux de extraire-journaux.mjs et de sonde.mjs) : il donne la
//     cible du job hote.
//
//   node scripts/deploiement/collecteur.mjs alerte --url <collecteur> --nom <règle>
//       --en-moins-de <secondes> [--etat firing|pending] [--etiquette <nom>=<valeur>]…
//     Code 0 si l'alerte est levée dans le délai (une ligne JSON la décrit),
//     1 sinon.
//
// Codes : 0 ; 1 échec (collecteur non démarré, alerte non levée) ; 2 usage ;
// 3 binaire Prometheus 3.5.0 absent ou d'une autre empreinte.
//
// Bibliothèque (import) : binairePrometheus, configurationCollecte,
// reduireFor, ExpositionFichiers, Collecteur (demarrer, regles, alertes,
// cibles, requete, requetePlage, attendreAlerte, attendreSilence,
// transitions, arreter) et, sans collecteur lancé, ClientCollecteur (même
// lecture de l'API depuis une URL).

import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import yaml from "js-yaml";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

export const VERSION_PROMETHEUS = "3.5.0";
/** SHA-256 de l'archive officielle prometheus-3.5.0.linux-amd64.tar.gz (CT-8 EX-10.10). */
export const SHA256_ARCHIVE = "e811827af26d822afb09a4f28314f61b618b12cff5369835a67f674d8b46f39a";
/** SHA-256 du binaire `prometheus` de cette archive (Linux amd64). */
export const SHA256_BINAIRE = "4ee49f574d80682b6571f017c8f42f2532aa3603b725b51ecb0cb864f06c2282";
export const CONDITION_PROMETHEUS = "binaire prometheus 3.5.0 absent (même archive que promtool, CT-8 EX-10.10 : Prometheus 3.5.0 pour Linux amd64 à SHA-256 fixé ; variable NOORTRACE_PROMETHEUS ou PATH)";
export const COLLECTE_REFERENCE = path.join(RACINE, "deploiement", "observabilite", "prometheus.yml");
export const REGLES_REFERENCE = path.join(RACINE, "deploiement", "observabilite", "regles-noortrace.yml");

export class ErreurCollecteur extends Error {}
/** Erreur de ligne de commande (code 2). */
export class ErreurUsage extends ErreurCollecteur {}

const pause = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Binaire Prometheus 3.5.0 : `chemin`, sinon NOORTRACE_PROMETHEUS, sinon
 * `prometheus` du PATH. Rend { ok: true, bin } ou { ok: false, condition }.
 * Sur Linux amd64, le SHA-256 du fichier doit être celui de l'archive
 * officielle ; ailleurs, seule la version est contrôlée, et le dit.
 * @param {{chemin?: string, env?: NodeJS.ProcessEnv}} [o]
 */
export function binairePrometheus(o = {}) {
  const env = o.env ?? process.env;
  const bin = o.chemin || env.NOORTRACE_PROMETHEUS || "prometheus";
  const r = spawnSync(bin, ["--version"], { encoding: "utf8" });
  if (r.error || r.status !== 0) return { ok: false, condition: CONDITION_PROMETHEUS };
  if (!new RegExp(`^prometheus, version ${VERSION_PROMETHEUS.replaceAll(".", "\\.")} `, "m").test(r.stdout + r.stderr)) {
    return { ok: false, condition: `${CONDITION_PROMETHEUS} ; le binaire trouvé n'est pas de la version ${VERSION_PROMETHEUS}` };
  }
  let empreinte = null;
  if (process.platform === "linux" && process.arch === "x64") {
    let fichier = bin;
    if (!bin.includes(path.sep)) {
      const w = spawnSync("sh", ["-c", 'command -v "$1"', "sh", bin], { encoding: "utf8" });
      fichier = w.stdout.trim();
    }
    empreinte = crypto.createHash("sha256").update(fs.readFileSync(fichier)).digest("hex");
    if (empreinte !== SHA256_BINAIRE) return { ok: false, condition: `${CONDITION_PROMETHEUS} ; le binaire trouvé a une autre empreinte (${empreinte})` };
  }
  return { ok: true, bin, version: VERSION_PROMETHEUS, sha256: empreinte };
}

/** Port TCP libre sur l'adresse de bouclage (relâché aussitôt). */
function portLibre() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

const ADRESSE_LOCALE = /^127\.0\.0\.1:([0-9]{1,5})$/;

/**
 * Configuration de collecte d'une installation locale, tirée de la collecte de
 * référence : mêmes intervalles (sauf `intervalleS`), mêmes jobs, mêmes
 * étiquettes `role` (CT-8 EX-10.4) ; seule l'adresse de chaque cible est
 * remplacée, et un job dont la cible vaut null est retiré.
 * @param {string} reference texte de deploiement/observabilite/prometheus.yml
 * @param {{cibles: Record<string, string|null>, regles: string, intervalleS?: number}} o
 *   `cibles` : une entrée par job de la référence, adresse `127.0.0.1:<port>` ou null ;
 *   `regles` : chemin du fichier de règles à charger
 * @returns {{texte: string, intervalleS: number, jobs: string[], retires: string[]}}
 */
export function configurationCollecte(reference, o) {
  const c = yaml.load(reference);
  const jobs = c.scrape_configs.map((s) => s.job_name);
  for (const j of Object.keys(o.cibles)) if (!jobs.includes(j)) throw new ErreurCollecteur(`cible ${j} : aucun job de ce nom dans la collecte de référence (${jobs.join(", ")})`);
  const retires = [];
  const gardes = [];
  for (const s of c.scrape_configs) {
    if (!(s.job_name in o.cibles)) throw new ErreurCollecteur(`job ${s.job_name} de la collecte de référence : aucune cible donnée (adresse 127.0.0.1:<port>, ou null pour le retirer)`);
    const adresse = o.cibles[s.job_name];
    if (adresse === null) {
      retires.push(s.job_name);
      continue;
    }
    const m = ADRESSE_LOCALE.exec(adresse);
    if (!m || Number(m[1]) < 1 || Number(m[1]) > 65535) throw new ErreurCollecteur(`cible ${s.job_name} : ${adresse} n'est pas une adresse de bouclage 127.0.0.1:<port> (CT-8 EX-10.4)`);
    if (s.static_configs.length !== 1 || s.static_configs[0].targets.length !== 1) throw new ErreurCollecteur(`job ${s.job_name} : une seule cible attendue dans la collecte de référence`);
    s.static_configs[0].targets = [adresse];
    gardes.push(s);
  }
  c.scrape_configs = gardes;
  c.rule_files = [o.regles];
  if (o.intervalleS !== undefined) {
    if (!Number.isInteger(o.intervalleS) || o.intervalleS < 1 || o.intervalleS > 300) throw new ErreurCollecteur("intervalle : entier de 1 à 300 secondes attendu");
    c.global.scrape_interval = `${o.intervalleS}s`;
    c.global.evaluation_interval = `${o.intervalleS}s`;
  }
  const lu = /^([0-9]+)s$/.exec(c.global.evaluation_interval);
  if (!lu || c.global.scrape_interval !== c.global.evaluation_interval) throw new ErreurCollecteur("collecte de référence : scrape_interval et evaluation_interval égaux, en secondes, attendus");
  return { texte: yaml.dump(c, { lineWidth: -1 }), intervalleS: Number(lu[1]), jobs: gardes.map((s) => s.job_name), retires };
}

const DUREE = /^[0-9]+[smhd]$/;

/**
 * Réduit la clause `for` de règles nommées, et d'elles seules, dans le texte
 * d'un fichier de règles ; le reste du fichier est rendu octet pour octet.
 * C'est un écart déclaré à la règle de référence : l'expression est évaluée
 * telle quelle par le collecteur, seule la durée de maintien change. Le
 * résultat `ecarts` se consigne dans le rapport de l'essai.
 * @param {string} texte fichier de règles
 * @param {Record<string, string>} durees nom de règle → durée (`30s`, `2m`, `1h`)
 * @returns {{texte: string, ecarts: {regle: string, reference: string, employee: string}[]}}
 */
export function reduireFor(texte, durees) {
  const lignes = texte.split("\n");
  const ecarts = [];
  for (const [regle, duree] of Object.entries(durees)) {
    if (!DUREE.test(duree)) throw new ErreurCollecteur(`reduire-for ${regle} : durée ${duree} hors de la forme <entier>s|m|h|d`);
    const debuts = lignes.flatMap((l, k) => (/^\s*- alert: (\S+)\s*$/.exec(l)?.[1] === regle ? [k] : []));
    if (debuts.length !== 1) throw new ErreurCollecteur(`reduire-for ${regle} : ${debuts.length} règle de ce nom dans le fichier (une attendue)`);
    let k = debuts[0] + 1;
    let fait = false;
    for (; k < lignes.length && !/^\s*- alert: /.test(lignes[k]) && !/^\s*- name: /.test(lignes[k]); k++) {
      const m = /^(\s*for: )(\S+)\s*$/.exec(lignes[k]);
      if (!m) continue;
      if (secondes(duree) > secondes(m[2])) throw new ErreurCollecteur(`reduire-for ${regle} : ${duree} dépasse la clause de référence (${m[2]})`);
      ecarts.push({ regle, reference: m[2], employee: duree });
      lignes[k] = `${m[1]}${duree}`;
      fait = true;
      break;
    }
    if (!fait) throw new ErreurCollecteur(`reduire-for ${regle} : la règle n'a pas de clause for`);
  }
  return { texte: lignes.join("\n"), ecarts };
}

/** Durée Prometheus simple (`15s`, `5m`, `2h`, `2d` : clauses `for` des tables de CT-8 §10.7) en secondes. */
export function secondes(duree) {
  const m = /^([0-9]+)([smhd])$/.exec(duree);
  if (!m) throw new ErreurCollecteur(`durée ${duree} hors de la forme <entier>s|m|h|d`);
  return Number(m[1]) * { s: 1, m: 60, h: 3600, d: 86400 }[m[2]];
}

/**
 * Réunit des expositions au format texte de Prometheus en une seule, une
 * famille par nom (une seule ligne `# TYPE`), comme le collecteur de fichiers
 * de l'exportateur de nœud le fait de ses fichiers .prom.
 * @param {string[]} textes
 */
export function reunirExpositions(textes) {
  /** @type {Map<string, {entete: string[], series: string[]}>} */
  const familles = new Map();
  const famille = (nom) => {
    if (!familles.has(nom)) familles.set(nom, { entete: [], series: [] });
    return familles.get(nom);
  };
  for (const texte of textes) {
    let courante = null;
    for (const l of texte.split("\n")) {
      if (l.trim() === "") continue;
      const e = /^# (TYPE|HELP) ([a-zA-Z_:][a-zA-Z0-9_:]*)( .*)?$/.exec(l);
      if (e) {
        courante = e[2];
        const f = famille(courante);
        if (!f.entete.some((x) => x.startsWith(`# ${e[1]} ${e[2]} `) || x === `# ${e[1]} ${e[2]}`)) f.entete.push(l);
        continue;
      }
      if (l.startsWith("#")) continue;
      const nom = /^([a-zA-Z_:][a-zA-Z0-9_:]*)/.exec(l)?.[1];
      if (!nom) continue;
      const base = courante !== null && (nom === courante || [`${courante}_bucket`, `${courante}_sum`, `${courante}_count`].includes(nom)) ? courante : nom;
      famille(base).series.push(l);
    }
  }
  const out = [];
  for (const f of familles.values()) out.push(...f.entete, ...f.series);
  return out.length ? out.join("\n") + "\n" : "";
}

/**
 * Point d'exposition des fichiers .prom d'un répertoire (`GET /metrics`), sur
 * l'adresse de bouclage : tient, sur une installation locale, la place du
 * collecteur de fichiers de l'exportateur de nœud (CT-8 §10.2, lignes « Sonde »
 * et « Extracteur des journaux »). Il n'expose aucune métrique `node_*`.
 */
export class ExpositionFichiers {
  /** @param {string} repertoire */
  constructor(repertoire) {
    this.repertoire = repertoire;
    this.serveur = null;
    this.adresse = null;
  }

  /** Exposition courante : fichiers .prom du répertoire, par ordre d'octets des noms. */
  exposer() {
    let noms;
    try {
      noms = fs.readdirSync(this.repertoire).filter((n) => n.endsWith(".prom")).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    } catch {
      noms = [];
    }
    const textes = [];
    for (const n of noms) {
      try {
        textes.push(fs.readFileSync(path.join(this.repertoire, n), "utf8"));
      } catch {
        // fichier retiré entre la liste et la lecture : absent de cette passe
      }
    }
    return reunirExpositions(textes);
  }

  /** Écoute sur 127.0.0.1 (port libre si `port` vaut 0) ; rend l'adresse `127.0.0.1:<port>`. */
  demarrer(port = 0) {
    this.serveur = http.createServer((req, rep) => {
      if (req.method !== "GET" || req.url !== "/metrics") return rep.writeHead(404).end();
      rep.writeHead(200, { "content-type": "text/plain; version=0.0.4" }).end(this.exposer());
    });
    return new Promise((resolve, reject) => {
      this.serveur.once("error", reject);
      this.serveur.listen(port, "127.0.0.1", () => {
        this.adresse = `127.0.0.1:${this.serveur.address().port}`;
        resolve(this.adresse);
      });
    });
  }

  arreter() {
    return new Promise((r) => (this.serveur ? this.serveur.close(() => r()) : r()));
  }
}

const memesEtiquettes = (voulues, portees) => Object.entries(voulues ?? {}).every(([k, v]) => portees[k] === v);

/** Lecture de l'API HTTP d'un collecteur Prometheus (`/api/v1`). */
export class ClientCollecteur {
  /** @param {string} url origine du collecteur, `http://127.0.0.1:<port>` */
  constructor(url) {
    this.url = url.replace(/\/$/, "");
  }

  /** `GET /api/v1/<chemin>` ; rend `data` ou lève ErreurCollecteur. */
  async api(chemin, params = {}) {
    const u = new URL(`${this.url}/api/v1/${chemin}`);
    for (const [k, v] of Object.entries(params)) u.searchParams.set(k, String(v));
    let rep;
    try {
      rep = await fetch(u, { signal: AbortSignal.timeout(15000) });
    } catch (e) {
      throw new ErreurCollecteur(`collecteur injoignable (${chemin}) : ${e.cause?.code ?? e.message}`);
    }
    const corps = await rep.json().catch(() => null);
    if (!rep.ok || corps?.status !== "success") throw new ErreurCollecteur(`collecteur : ${chemin} → ${rep.status} ${corps?.error ?? ""}`.trim());
    return corps.data;
  }

  /** Règles chargées : { groupe, nom, expr, for_s, etiquettes, etat, sante }. */
  async regles() {
    const d = await this.api("rules", { type: "alert" });
    return d.groups.flatMap((g) => g.rules.map((r) => ({ groupe: g.name, nom: r.name, expr: r.query, for_s: r.duration, etiquettes: r.labels ?? {}, etat: r.state, sante: r.health, erreur: r.lastError ?? null })));
  }

  /** Alertes actives : { nom, etat (`pending` ou `firing`), etiquettes, active_depuis, valeur }. */
  async alertes() {
    const d = await this.api("alerts");
    return d.alerts.map((a) => ({ nom: a.labels.alertname, etat: a.state, etiquettes: a.labels, active_depuis: a.activeAt, valeur: Number(a.value) }));
  }

  /** Cibles de collecte actives : { job, adresse, role, sante (`up`, `down`, `unknown`), erreur }. */
  async cibles() {
    const d = await this.api("targets", { state: "active" });
    return d.activeTargets.map((t) => ({ job: t.labels.job, adresse: t.labels.instance, role: t.labels.role ?? null, sante: t.health, erreur: t.lastError || null }));
  }

  /** Requête instantanée ; rend [{ etiquettes, valeur }] (vecteur) ou [{ etiquettes: {}, valeur }] (scalaire). */
  async requete(expr, instantS) {
    const d = await this.api("query", instantS === undefined ? { query: expr } : { query: expr, time: instantS });
    if (d.resultType === "scalar") return [{ etiquettes: {}, valeur: Number(d.result[1]) }];
    if (d.resultType !== "vector") throw new ErreurCollecteur(`requête ${expr} : résultat ${d.resultType} inattendu`);
    return d.result.map((s) => ({ etiquettes: s.metric, valeur: Number(s.value[1]) }));
  }

  /** Requête sur une plage ; rend [{ etiquettes, points: [[instantS, valeur], …] }]. */
  async requetePlage(expr, debutS, finS, pasS) {
    const d = await this.api("query_range", { query: expr, start: debutS, end: finS, step: pasS });
    return d.result.map((s) => ({ etiquettes: s.metric, points: s.values.map(([t, v]) => [Number(t), Number(v)]) }));
  }

  /**
   * « Telle alerte est levée en moins de N secondes » : interroge l'API
   * jusqu'à voir une alerte de ce nom dans l'état voulu (`firing` par défaut :
   * expression vraie depuis la clause `for` entière ; `pending` : expression
   * vraie, clause `for` en cours), avec les étiquettes données s'il y en a.
   * Ne lève jamais pour une alerte absente : rend `levee` faux à l'échéance,
   * avec ce qui a été vu, pour que l'essai d'un mutant constate l'absence.
   * @param {string} nom nom de la règle (`alertname`)
   * @param {{delaiS: number, etat?: "firing"|"pending", etiquettes?: Record<string, string>, pasMs?: number}} o
   * @returns {Promise<{levee: boolean, apres_s: number, alerte: object|null, vues: object[]}>}
   */
  async attendreAlerte(nom, o) {
    if (!(o?.delaiS > 0)) throw new ErreurCollecteur("attendreAlerte : delaiS (secondes, > 0) attendu");
    const etat = o.etat ?? "firing";
    if (etat !== "firing" && etat !== "pending") throw new ErreurCollecteur("attendreAlerte : etat firing ou pending");
    const debut = performance.now();
    let vues = [];
    for (;;) {
      vues = (await this.alertes()).filter((a) => a.nom === nom && memesEtiquettes(o.etiquettes, a.etiquettes));
      const trouvee = vues.find((a) => a.etat === etat);
      const ecoule = (performance.now() - debut) / 1000;
      if (trouvee) return { levee: true, apres_s: ecoule, alerte: trouvee, vues };
      if (ecoule >= o.delaiS) return { levee: false, apres_s: ecoule, alerte: null, vues };
      await pause(Math.min(o.pasMs ?? 500, Math.max(1, (o.delaiS - ecoule) * 1000)));
    }
  }

  /**
   * Attend qu'aucune alerte de ce nom ne soit plus déclenchée (`firing`), ni
   * en cours de clause `for` si `aucunePending` est vrai.
   * @returns {Promise<{silencieuse: boolean, apres_s: number, vues: object[]}>}
   */
  async attendreSilence(nom, o) {
    if (!(o?.delaiS > 0)) throw new ErreurCollecteur("attendreSilence : delaiS (secondes, > 0) attendu");
    const debut = performance.now();
    for (;;) {
      const vues = (await this.alertes()).filter((a) => a.nom === nom && memesEtiquettes(o.etiquettes, a.etiquettes) && (o.aucunePending || a.etat === "firing"));
      const ecoule = (performance.now() - debut) / 1000;
      if (!vues.length) return { silencieuse: true, apres_s: ecoule, vues };
      if (ecoule >= o.delaiS) return { silencieuse: false, apres_s: ecoule, vues };
      await pause(Math.min(o.pasMs ?? 500, Math.max(1, (o.delaiS - ecoule) * 1000)));
    }
  }

  /**
   * Transitions de chaque règle vers l'état déclenché sur une fenêtre, au
   * sens du décompte de CT-9 TE-17 : une règle compte une transition quand
   * l'ensemble de ses séries `ALERTS{alertstate="firing"}` passe d'aucune série
   * à au moins une, toutes étiquettes confondues ; les transitions simultanées
   * de plusieurs séries comptent une ; une règle déjà déclenchée au début de
   * la fenêtre compte zéro pour cet état initial.
   * @param {number} debutS début de la fenêtre (secondes UNIX entières)
   * @param {number} finS fin de la fenêtre (secondes UNIX entières)
   * @param {number} pasS pas de lecture en secondes entières, au plus l'intervalle d'évaluation
   * @returns {Promise<Map<string, {transitions: number, declenchee_au_debut: boolean, instants: number[], gravites: string[]}>>}
   */
  async transitions(debutS, finS, pasS) {
    if (![debutS, finS, pasS].every(Number.isInteger) || !(finS > debutS) || !(pasS > 0)) throw new ErreurCollecteur("transitions : début, fin et pas en secondes entières, fenêtre et pas positifs attendus");
    const series = await this.requetePlage('count by (alertname, severity) (ALERTS{alertstate="firing"})', debutS, finS, pasS);
    /** @type {Map<string, {presents: Set<number>, gravites: Set<string>}>} */
    const parRegle = new Map();
    for (const s of series) {
      const nom = s.etiquettes.alertname;
      if (!parRegle.has(nom)) parRegle.set(nom, { presents: new Set(), gravites: new Set() });
      const r = parRegle.get(nom);
      if (s.etiquettes.severity !== undefined) r.gravites.add(s.etiquettes.severity);
      for (const [t] of s.points) r.presents.add(Math.round(t));
    }
    const out = new Map();
    for (const [nom, r] of parRegle) {
      const instants = [];
      let avant = r.presents.has(debutS);
      for (let t = debutS + pasS; t <= finS; t += pasS) {
        const ici = r.presents.has(t);
        if (ici && !avant) instants.push(t);
        avant = ici;
      }
      out.set(nom, { transitions: instants.length, declenchee_au_debut: r.presents.has(debutS), instants, gravites: [...r.gravites].sort() });
    }
    return out;
  }
}

/** Collecteur Prometheus lancé par le harnais sur l'adresse de bouclage. */
export class Collecteur extends ClientCollecteur {
  constructor(url, interne) {
    super(url);
    Object.assign(this, interne);
  }

  /**
   * Lance Prometheus et attend qu'il soit prêt et que ses règles soient chargées.
   * @param {{travail: string, cibles: Record<string, string|null>, binaire?: string, regles?: string, collecte?: string,
   *   intervalleS?: number, reduireFor?: Record<string, string>, port?: number, delaiDemarrageS?: number}} o
   *   `travail` : répertoire du collecteur (configuration, règles employées, base de séries, journal) ;
   *   `cibles` : adresse de chaque job de la collecte de référence, ou null pour le retirer ;
   *   `regles` : fichier de règles à charger (défaut : règles de référence) ;
   *   `reduireFor` : clauses `for` réduites, écart consigné dans `ecarts`
   * @returns {Promise<Collecteur>}
   */
  static async demarrer(o) {
    const b = binairePrometheus({ chemin: o.binaire });
    if (!b.ok) throw new ErreurCollecteur(b.condition);
    fs.mkdirSync(o.travail, { recursive: true });
    const source = o.regles ?? REGLES_REFERENCE;
    const r = reduireFor(fs.readFileSync(source, "utf8"), o.reduireFor ?? {});
    const fichierRegles = path.join(o.travail, "regles.yml");
    fs.writeFileSync(fichierRegles, r.texte);
    const c = configurationCollecte(fs.readFileSync(o.collecte ?? COLLECTE_REFERENCE, "utf8"), { cibles: o.cibles, regles: fichierRegles, intervalleS: o.intervalleS });
    const fichierConfig = path.join(o.travail, "prometheus.yml");
    fs.writeFileSync(fichierConfig, c.texte);
    const port = o.port ?? (await portLibre());
    const url = `http://127.0.0.1:${port}`;
    const journal = path.join(o.travail, "prometheus.log");
    const sortie = fs.openSync(journal, "a");
    const p = spawn(b.bin, [`--config.file=${fichierConfig}`, `--storage.tsdb.path=${path.join(o.travail, "donnees")}`, `--web.listen-address=127.0.0.1:${port}`, "--log.level=warn"], { cwd: o.travail, stdio: ["ignore", sortie, sortie] });
    fs.closeSync(sortie);
    const collecteur = new Collecteur(url, { p, travail: o.travail, fichierRegles, fichierConfig, journal, intervalleS: c.intervalleS, jobs: c.jobs, jobsRetires: c.retires, ecarts: r.ecarts, binaire: b });
    const limite = performance.now() + (o.delaiDemarrageS ?? 60) * 1000;
    for (;;) {
      if (p.exitCode !== null || p.signalCode !== null) throw new ErreurCollecteur(`Prometheus s'est arrêté au démarrage (code ${p.exitCode}) : ${fs.readFileSync(journal, "utf8").slice(-2000)}`);
      const pret = await fetch(`${url}/-/ready`, { signal: AbortSignal.timeout(2000) }).then((x) => x.ok, () => false);
      if (pret) break;
      if (performance.now() > limite) {
        await collecteur.arreter();
        throw new ErreurCollecteur(`Prometheus n'est pas prêt après ${o.delaiDemarrageS ?? 60} s : ${fs.readFileSync(journal, "utf8").slice(-2000)}`);
      }
      await pause(200);
    }
    return collecteur;
  }

  /** Arrête Prometheus (SIGTERM, puis SIGKILL après 20 s) ; rend son code de sortie. */
  arreter() {
    const p = this.p;
    return new Promise((r) => {
      if (p.exitCode !== null || p.signalCode !== null) return r(p.exitCode);
      const tueur = setTimeout(() => p.kill("SIGKILL"), 20000);
      p.once("exit", (code) => {
        clearTimeout(tueur);
        r(code);
      });
      p.kill("SIGTERM");
    });
  }
}

const USAGE = [
  "Usage : node scripts/deploiement/collecteur.mjs lancer --travail <répertoire> --cible <job>=<127.0.0.1:port|aucune>… [--textfile <répertoire>]",
  "          [--prometheus <binaire>] [--regles <fichier>] [--intervalle <s>] [--reduire-for <règle>=<durée>]… [--port <n>]",
  "        node scripts/deploiement/collecteur.mjs alerte --url <collecteur> --nom <règle> --en-moins-de <s> [--etat firing|pending] [--etiquette <nom>=<valeur>]…",
].join("\n");

const paires = (liste, quoi) => Object.fromEntries((liste ?? []).map((x) => {
  const k = x.indexOf("=");
  if (k < 1) throw new ErreurUsage(`${quoi} : <nom>=<valeur> attendu (${x})`);
  return [x.slice(0, k), x.slice(k + 1)];
}));

export async function principal(argv, sortie = process.stdout, erreur = process.stderr) {
  const [commande, ...reste] = argv;
  try {
    if (commande === "lancer") {
      const o = parseArgs({ args: reste, strict: true, allowPositionals: false, options: {
        travail: { type: "string" }, cible: { type: "string", multiple: true }, textfile: { type: "string" }, prometheus: { type: "string" },
        regles: { type: "string" }, intervalle: { type: "string" }, "reduire-for": { type: "string", multiple: true }, port: { type: "string" },
      } }).values;
      if (!o.travail) throw new ErreurUsage("--travail attendu");
      for (const k of ["intervalle", "port"]) if (o[k] !== undefined && !/^[0-9]{1,5}$/.test(o[k])) throw new ErreurUsage(`--${k} : entier attendu`);
      const cibles = Object.fromEntries(Object.entries(paires(o.cible, "--cible")).map(([j, a]) => [j, a === "aucune" ? null : a]));
      const b = binairePrometheus({ chemin: o.prometheus });
      if (!b.ok) {
        erreur.write(`Condition absente : ${b.condition}\n`);
        return 3;
      }
      let fichiers = null;
      if (o.textfile !== undefined) {
        if ("hote" in cibles) throw new ErreurUsage("--textfile donne la cible du job hote : ne pas la donner aussi par --cible");
        fichiers = new ExpositionFichiers(o.textfile);
        cibles.hote = await fichiers.demarrer();
      }
      let c;
      try {
        c = await Collecteur.demarrer({ travail: o.travail, cibles, binaire: o.prometheus, regles: o.regles, intervalleS: o.intervalle === undefined ? undefined : Number(o.intervalle), reduireFor: paires(o["reduire-for"], "--reduire-for"), port: o.port === undefined ? undefined : Number(o.port) });
      } catch (e) {
        await fichiers?.arreter();
        throw e;
      }
      sortie.write(JSON.stringify({ url: c.url, pid: c.p.pid, intervalle_s: c.intervalleS, jobs: c.jobs, jobs_retires: c.jobsRetires, regles: (await c.regles()).length, ecarts: c.ecarts, textfile: fichiers?.adresse ?? null }) + "\n");
      return await new Promise((resolve) => {
        const finir = async () => {
          await c.arreter();
          await fichiers?.arreter();
          resolve(0);
        };
        process.once("SIGTERM", finir);
        process.once("SIGINT", finir);
        c.p.once("exit", async () => {
          await fichiers?.arreter();
          resolve(1);
        });
      });
    }
    if (commande === "alerte") {
      const o = parseArgs({ args: reste, strict: true, allowPositionals: false, options: {
        url: { type: "string" }, nom: { type: "string" }, "en-moins-de": { type: "string" }, etat: { type: "string" }, etiquette: { type: "string", multiple: true },
      } }).values;
      if (!o.url || !o.nom || !/^[1-9][0-9]{0,5}$/.test(o["en-moins-de"] ?? "")) throw new ErreurUsage("--url, --nom et --en-moins-de <secondes> attendus");
      if (o.etat !== undefined && o.etat !== "firing" && o.etat !== "pending") throw new ErreurUsage("--etat : firing ou pending");
      const r = await new ClientCollecteur(o.url).attendreAlerte(o.nom, { delaiS: Number(o["en-moins-de"]), etat: o.etat, etiquettes: paires(o.etiquette, "--etiquette") });
      sortie.write(JSON.stringify(r) + "\n");
      return r.levee ? 0 : 1;
    }
    throw new ErreurUsage(commande === undefined ? "commande attendue (lancer ou alerte)" : `commande inconnue : ${commande}`);
  } catch (e) {
    const usage = e instanceof ErreurUsage || (typeof e?.code === "string" && e.code.startsWith("ERR_PARSE_ARGS"));
    if (!usage && !(e instanceof ErreurCollecteur)) throw e;
    erreur.write(`Erreur : ${e.message}\n${usage ? USAGE + "\n" : ""}`);
    return usage ? 2 : 1;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = await principal(process.argv.slice(2));
