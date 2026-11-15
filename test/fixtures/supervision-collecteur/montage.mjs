// Montage des essais de la supervision en marche (CT-9 TE-17, TM-34) : un
// démon réel de l'enregistreur (`bin/noortrace --config`, classe D, bail de
// fichier, frontal MCP, serveur d'outils nul lancé en stdio), un service
// d'approbation de test servi en HTTP, et un hôte qui émet à cadence fixe par
// le connecteur stdio (CT-9 EX-11.9 : chaque latence est comptée depuis
// l'instant prévu de l'envoi). Rien ne joint un réseau : tout écoute sur
// l'adresse de bouclage, sur des ports libres choisis à l'exécution.
//
// Importé sans être lancé, ce module ne fait rien.

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { RACINE, BIN_NOORTRACE } from "../enregistreur-coeur/outils.mjs";
import { configurationMcp, hoteDemo, serveurStdio, reglageOutil } from "../enregistreur-mcp/outils.mjs";
import { ClientHote, metaModerne } from "../enregistreur-mcp/client-hote.mjs";
import { Collecteur, ExpositionFichiers } from "../../../scripts/deploiement/collecteur.mjs";

export const SERVEUR_NUL = path.join(RACINE, "test", "fixtures", "supervision-collecteur", "serveur-nul.mjs");
export const BIN_CTL = path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace-ctl");

/** Port TCP libre sur l'adresse de bouclage (relâché aussitôt). */
export function portLibre() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

const pause = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Écrit la configuration du montage sous `dir` et démarre le service
 * d'approbation de test.
 * @param {string} dir répertoire de travail (créé)
 * @param {{stockage?: string, modifier?: (config: object) => void, quota?: object, decider?: Function}} [o]
 *   `stockage` : `storage.root` (défaut : `<dir>/stockage`) ; `modifier` : retouche de la configuration avant écriture
 */
export async function preparerMontage(dir, o = {}) {
  fs.mkdirSync(dir, { recursive: true });
  const etat = path.join(dir, "serveur-nul");
  fs.mkdirSync(etat, { recursive: true });
  const moi = os.userInfo().username;
  const servers = {
    nul: serveurStdio([process.execPath, SERVEUR_NUL, "--etat", etat], { protocol: "auto", tools: { "nul.ecrire": reglageOutil({ class: "ecriture" }) } }),
  };
  const hosts = [
    hoteDemo({ id: "hote-cadence", match: { peer_user: moi }, launched_by: "${peer_user}", ...(o.quota ? { quota: o.quota } : {}) }),
  ];
  // La prise du frontal va dans un répertoire au nom court : un chemin de prise Unix est borné à 107 octets.
  const prise = fs.mkdtempSync(path.join(process.env.NOORTRACE_TMP ?? os.tmpdir(), "nt-sup-"));
  const { config, env } = configurationMcp(dir, { servers, hosts, socket: path.join(prise, "mcp.sock") });
  config.model.hosts = [];
  // Relance du serveur d'outils : assez d'essais pour qu'il revienne après une panne provoquée (bornes du schéma).
  config.restart = { max_attempts: 100, backoff_ms: 1000 };
  // Répertoire des exports d'essai (CT-2 EX-15.13), sous le répertoire de travail.
  config.exports_dir = path.join(dir, "exports");
  fs.mkdirSync(config.exports_dir, { recursive: true, mode: 0o750 });
  config.supervision.health_listen = `127.0.0.1:${await portLibre()}`;
  if (o.stockage) config.storage.root = o.stockage;
  const service = new ServiceApprobationFactice({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id, decider: o.decider ?? (() => ({ decision: "autorise", rule: null })) });
  const serveurService = await service.servir(0);
  config.policy.approval.service = { ...config.policy.approval.service, url: `http://127.0.0.1:${serveurService.address().port}`, socket: null, token: { env: "NOORTRACE_TEST_JETON_APPROBATION" } };
  env.NOORTRACE_TEST_JETON_APPROBATION = "jeton-noyau-de-test";
  o.modifier?.(config);
  const chemin = path.join(dir, "configuration.json");
  fs.writeFileSync(chemin, JSON.stringify(config, null, 2));
  return { dir, etat, prise, config, env, chemin, service, serveurService, supervision: `http://${config.supervision.health_listen}`, journalExploitation: config.supervision.ops_log.path };
}

/**
 * Lance `bin/noortrace --config` et attend la ligne « demon demarre ».
 * @returns {Promise<{p: import("node:child_process").ChildProcess, arreter: () => Promise<number|null>, erreurs: () => string}>}
 */
export async function demarrerDemon(m) {
  const p = spawn(process.execPath, [BIN_NOORTRACE, "--config", m.chemin], { env: { ...process.env, ...m.env }, stdio: ["ignore", "pipe", "pipe"] });
  let sortie = "";
  let erreurs = "";
  p.stderr.on("data", (x) => (erreurs += x));
  await new Promise((res, rej) => {
    const surSortie = (code) => rej(new Error(`le démon s'est arrêté au démarrage (code ${code}) : ${erreurs}`));
    p.once("exit", surSortie);
    p.stdout.on("data", (x) => {
      sortie += x;
      if (/demon demarre/.test(sortie)) {
        p.removeListener("exit", surSortie);
        res();
      }
    });
  });
  const arreter = () => new Promise((r) => {
    if (p.exitCode !== null || p.signalCode !== null) return r(p.exitCode);
    const tueur = setTimeout(() => p.kill("SIGKILL"), 20000);
    p.once("exit", (c) => {
      clearTimeout(tueur);
      r(c);
    });
    p.kill("SIGTERM");
  });
  return { p, arreter, erreurs: () => erreurs };
}

/** Arrête le service d'approbation de test et retire le répertoire de la prise. */
export function arreterMontage(m) {
  fs.rmSync(m.prise, { recursive: true, force: true });
  return new Promise((r) => m.serveurService.close(() => r()));
}

/** `GET` sur le point de supervision du démon : { statut, texte }. */
export async function lireSupervision(m, chemin) {
  const rep = await fetch(`${m.supervision}${chemin}`, { signal: AbortSignal.timeout(5000) });
  return { statut: rep.status, texte: await rep.text() };
}

/**
 * Hôte de test à cadence fixe (CT-9 EX-11.9) : `connexions` connecteurs
 * stdio, un appel `tools/call` toutes les `1000 / cadence` ms, réparti à tour
 * de rôle ; l'instant prévu de chaque envoi est fixé d'avance sur l'horloge
 * monotone, et la latence d'un appel se compte depuis cet instant prévu (les
 * réponses lentes ne retardent ni l'envoi ni la mesure des suivantes).
 */
export class HoteCadence {
  /**
   * @param {{socket: string, connexions?: number, cadence: number, outil?: string, env?: NodeJS.ProcessEnv,
   *   ecritureToutesLesMs?: number, listeToutesLesMs?: number, gardeLatences?: boolean}} p
   *   `cadence` : appels `nul.lire` par seconde, toutes connexions confondues ;
   *   `ecritureToutesLesMs` : en plus, un appel d'écriture `nul.ecrire` à cet intervalle (aucun si absent) ;
   *   `listeToutesLesMs` : en plus, un `tools/list` à cet intervalle, comme un hôte qui relit sa liste (aucun si absent)
   */
  constructor(p) {
    this.socket = p.socket;
    this.nbConnexions = p.connexions ?? 1;
    this.cadence = p.cadence;
    this.outil = p.outil ?? "nul__nul.lire";
    this.env = p.env ?? process.env;
    this.clients = [];
    this.envoyes = 0;
    this.reponses = 0;
    this.erreurs = 0;
    /** codes d'erreur JSON-RPC rendus → nombre */
    this.codes = new Map();
    /** latences en ms depuis l'instant prévu */
    this.latences = [];
    this.gardeLatences = p.gardeLatences !== false;
    this.minuteur = null;
    this.enVol = 0;
    this.ecritureToutesLesMs = p.ecritureToutesLesMs ?? null;
    this.listeToutesLesMs = p.listeToutesLesMs ?? null;
    this.minuteurs = [];
    /** appels d'écriture : envoyés, rendus sans erreur, codes d'erreur */
    this.ecritures = { envoyees: 0, reussies: 0, codes: new Map() };
    /** `tools/list` périodiques : envoyés, rendus avec la liste, sans la liste */
    this.listes = { envoyees: 0, completes: 0, autres: 0 };
    /** arguments de la charge (remplaçables pendant l'émission : provocation du quota d'octets reçus) */
    this.arguments = { cle: "charge" };
  }

  /** Ouvre les connexions et liste les outils sur chacune. */
  async ouvrir() {
    for (let k = 0; k < this.nbConnexions; k++) {
      const c = new ClientHote(["--socket", this.socket], this.env);
      this.clients.push(c);
    }
    const listes = await Promise.all(this.clients.map((c) => c.requete("tools/list", { _meta: metaModerne() })));
    return listes[0];
  }

  /** Un appel hors cadence sur la première connexion ; rend la réponse JSON-RPC. */
  appeler(outil, args = {}) {
    return this.clients[0].requete("tools/call", { name: outil, arguments: args, _meta: metaModerne() });
  }

  _envoyer(prevu) {
    const c = this.clients[this.envoyes % this.clients.length];
    this.envoyes++;
    this.enVol++;
    c.requete("tools/call", { name: this.outil, arguments: this.arguments, _meta: metaModerne() }).then((r) => {
      this.enVol--;
      this.reponses++;
      if (this.gardeLatences) this.latences.push(performance.now() - prevu);
      const code = r.error?.code ?? (r.result?.isError ? "isError" : null);
      if (code !== null) {
        this.erreurs++;
        this.codes.set(String(code), (this.codes.get(String(code)) ?? 0) + 1);
      }
    });
  }

  /** Démarre l'émission à cadence fixe. */
  demarrer() {
    const pas = 1000 / this.cadence;
    this.debut = performance.now();
    let n = 0;
    const battre = () => {
      const maintenant = performance.now();
      // Tous les envois dont l'instant prévu est passé partent, à leur instant prévu compté.
      while (this.debut + n * pas <= maintenant) {
        this._envoyer(this.debut + n * pas);
        n++;
      }
      this.minuteur = setTimeout(battre, Math.max(1, this.debut + n * pas - performance.now()));
    };
    battre();
    if (this.ecritureToutesLesMs) {
      this.minuteurs.push(setInterval(() => {
        this.ecritures.envoyees++;
        this.clients[0].requete("tools/call", { name: "nul__nul.ecrire", arguments: { cle: "ecriture" }, _meta: metaModerne() }).then((r) => {
          const code = r.error?.code ?? (r.result?.isError ? "isError" : null);
          if (code === null) this.ecritures.reussies++;
          else this.ecritures.codes.set(String(code), (this.ecritures.codes.get(String(code)) ?? 0) + 1);
        });
      }, this.ecritureToutesLesMs));
    }
    if (this.listeToutesLesMs) {
      this.minuteurs.push(setInterval(() => {
        this.listes.envoyees++;
        this.clients[this.clients.length - 1].requete("tools/list", { _meta: metaModerne() }).then((r) => {
          if (Array.isArray(r.result?.tools) && r.result.tools.length) this.listes.completes++;
          else this.listes.autres++;
        });
      }, this.listeToutesLesMs));
    }
  }

  /** Arrête l'émission et attend les réponses en vol (au plus `delaiMs`). */
  async arreter(delaiMs = 10000) {
    clearTimeout(this.minuteur);
    this.minuteur = null;
    for (const x of this.minuteurs) clearInterval(x);
    this.minuteurs = [];
    this.fin = performance.now();
    const limite = performance.now() + delaiMs;
    while (this.enVol > 0 && performance.now() < limite) await pause(50);
  }

  async fermer() {
    await Promise.all(this.clients.map((c) => c.fermer()));
    this.clients = [];
  }
}

// --------------------------------------------------------------------------
// Installation locale de supervision autour du montage : extracteur des
// journaux et sonde de référence (CT-8 §10.3, EX-10.7) lancés comme processus,
// leurs fichiers .prom servis à la place de l'exportateur de nœud, collecteur
// Prometheus chargé des règles (scripts/deploiement/collecteur.mjs).


const OUTILS = path.join(RACINE, "scripts", "deploiement");
const MIO = 1024 * 1024;
/** `policy.failure.pending_max_ms` du montage (borne du schéma respectée ; voir monterSupervision). */
export const PENDING_MAX_MS = 400000;

/** Octets libres du système de fichiers qui porte `chemin` (comme le démon : `bavail × bsize`). */
export function octetsLibres(chemin) {
  const s = fs.statfsSync(chemin);
  return Number(s.bavail) * Number(s.bsize);
}

/** Relais TCP local vers `hote:port` : le fermer rend la cible injoignable sans l'arrêter. */
export class RelaisTcp {
  constructor(port, hote = "127.0.0.1") {
    this.cible = { port, host: hote };
    this.serveur = null;
    this.prises = new Set();
    this.port = null;
  }

  ouvrir(port = this.port ?? 0) {
    this.serveur = net.createServer((entrant) => {
      const sortant = net.connect(this.cible);
      for (const s of [entrant, sortant]) {
        this.prises.add(s);
        s.on("close", () => this.prises.delete(s));
        s.on("error", () => {});
      }
      entrant.pipe(sortant);
      sortant.pipe(entrant);
      entrant.on("close", () => sortant.destroy());
      sortant.on("close", () => entrant.destroy());
    });
    return new Promise((resolve, reject) => {
      this.serveur.once("error", reject);
      this.serveur.listen(port, "127.0.0.1", () => {
        this.port = this.serveur.address().port;
        resolve(this.port);
      });
    });
  }

  fermer() {
    for (const s of this.prises) s.destroy();
    return new Promise((r) => (this.serveur ? this.serveur.close(() => r()) : r()));
  }
}

/** Point d'état de test du service d'approbation (`GET /v0/etat`, forme de CT-3 EX-12.12, `ready` vrai). */
function servirEtatApprobation() {
  const luLe = new Date().toISOString();
  const serveur = http.createServer((req, rep) => {
    if (req.method !== "GET" || req.url !== "/v0/etat") return rep.writeHead(404).end();
    rep.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ ready: true, set_read_at: luLe, open_tickets: 0 }));
  });
  return new Promise((resolve) => serveur.listen(0, "127.0.0.1", () => resolve(serveur)));
}

function lancerOutil(nom, args, journal) {
  const sortie = fs.openSync(journal, "a");
  const p = spawn(process.execPath, [path.join(OUTILS, nom), ...args], { cwd: RACINE, stdio: ["ignore", sortie, sortie] });
  fs.closeSync(sortie);
  return p;
}

const tuer = (p) => new Promise((r) => {
  if (!p || p.exitCode !== null || p.signalCode !== null) return r();
  p.once("exit", () => r());
  p.kill("SIGTERM");
});

/**
 * Monte l'installation locale de supervision : démon, serveur d'outils nul,
 * service d'approbation de test, extracteur, sonde, collecteur, hôte à cadence
 * fixe (non démarré).
 * @param {string} dir répertoire de travail (créé)
 * @param {{cadence: number, connexions?: number, stockage?: string, margeOctets?: number, regles?: string,
 *   registre?: {rpc: number, metriques: number}|null, intervalleS?: number, gardeLatences?: boolean}} o
 *   `margeOctets` : `storage.min_free_bytes` vaut l'espace libre au montage moins cette marge (défaut 256 Mio),
 *   pour que la provocation « stockage » tienne dans un lest de cette taille ;
 *   `regles` : fichier de règles chargé ; par défaut, les règles régénérées depuis la configuration du montage par
 *   scripts/deploiement/regles.mjs --configuration (CT-8 EX-10.6 ; précondition de CT-9 TE-17 : seuils abaissés ou
 *   relevés dans les bornes du schéma, règles régénérées, valeurs consignées : `s.regles`) ;
 *   `registre` : ports locaux du point RPC et des métriques d'un nœud du réseau de développement ;
 *   la sonde et le job noorcore les joignent par un relais TCP, que la provocation « registre » ferme
 */
export async function monterSupervision(dir, o) {
  fs.mkdirSync(dir, { recursive: true });
  const stockage = o.stockage ?? path.join(dir, "stockage");
  fs.mkdirSync(stockage, { recursive: true });
  const marge = o.margeOctets ?? 256 * MIO;
  // Quotas de l'hôte de test : seul received_bytes_per_minute sert de provocation ; le temps de capture par minute est porté
  // à la borne du schéma, sans quoi une charge de 50 appels/s sur une machine lente le dépasse en nominal (quota « redaction »).
  const quota = { max_concurrent: 32, piece_bytes_per_minute: 268435456, received_bytes_per_minute: 16 * MIO, redaction_ms_per_minute: 86400000 };
  const m = await preparerMontage(path.join(dir, "montage"), {
    stockage,
    quota,
    modifier: (c) => {
      c.storage.min_free_bytes = Math.max(1, octetsLibres(stockage) - marge);
      // Borne d'âge de la file d'attente (EX-14.9) relevée de 300 000 à 400 000 ms : la provocation « stockage » est
      // maintenue 330 s (clause for de 300 s de noortrace_attente_non_vide et deux intervalles) ; à 300 000 ms, le plus
      // ancien événement en attente atteignait la borne pendant la provocation et le démon entrait aussi en mode
      // « attente », dont la série de noortrace_mode_degrade_majeur se déclenchait après la résolution de celle de
      // « stockage » (deux transitions au lieu d'une). Le seuil de noortrace_attente_ancienne suit (moitié : 200 000 ms).
      c.policy.failure.pending_max_ms = PENDING_MAX_MS;
    },
  });
  // Règles régénérées depuis la configuration du montage (CT-8 EX-10.6) : min_free_bytes, storage.root et
  // pending_max_ms y sont ceux du démon.
  let regles = o.regles ?? null;
  if (!regles) {
    regles = path.join(dir, "regles-montage.yml");
    const g = spawnSync(process.execPath, [path.join(OUTILS, "regles.mjs"), "--configuration", m.chemin, "--sortie", regles], { cwd: RACINE, encoding: "utf8" });
    if (g.status !== 0) {
      await arreterMontage(m);
      throw new Error(`régénération des règles depuis la configuration du montage (regles.mjs) : code ${g.status} ${g.stderr}`);
    }
  }
  const textfile = path.join(dir, "textfile");
  fs.mkdirSync(textfile, { recursive: true });
  const s = { dir, m, stockage, marge, quota, textfile, regles, demon: null, hote: null, collecteur: null, fichiers: null, extracteur: null, sonde: null, etatApprobation: null, relaisRpc: null, relaisMetriques: null, registre: o.registre ?? null };
  try {
    s.demon = await demarrerDemon(m);
    s.extracteur = lancerOutil("extraire-journaux.mjs", ["--exploitation", m.journalExploitation, "--intervalle", "15", "--sortie", path.join(textfile, "journaux.prom")], path.join(dir, "extracteur.log"));
    s.etatApprobation = await servirEtatApprobation();
    const argsSonde = ["--approbation", `http://127.0.0.1:${s.etatApprobation.address().port}`, "--intervalle", "15", "--sortie", path.join(textfile, "sonde.prom")];
    let cibleNoeud = null;
    if (s.registre) {
      s.relaisRpc = new RelaisTcp(s.registre.rpc);
      s.relaisMetriques = new RelaisTcp(s.registre.metriques);
      argsSonde.push("--rpc", `validateur=http://127.0.0.1:${await s.relaisRpc.ouvrir()}`);
      cibleNoeud = `127.0.0.1:${await s.relaisMetriques.ouvrir()}`;
    }
    s.sonde = lancerOutil("sonde.mjs", argsSonde, path.join(dir, "sonde.log"));
    s.fichiers = new ExpositionFichiers(textfile);
    const cibleHote = await s.fichiers.demarrer();
    s.collecteur = await Collecteur.demarrer({ travail: path.join(dir, "collecteur"), regles, intervalleS: o.intervalleS, cibles: { enregistreur: m.config.supervision.health_listen, hote: cibleHote, noorcore: cibleNoeud } });
    s.hote = new HoteCadence({ socket: m.config.mcp.socket, connexions: o.connexions ?? 16, cadence: o.cadence, ecritureToutesLesMs: 1000, listeToutesLesMs: 5000, gardeLatences: o.gardeLatences });
    await s.hote.ouvrir();
  } catch (e) {
    await demonterSupervision(s);
    throw e;
  }
  return s;
}

/** Arrête tout ce que `monterSupervision` a lancé ; rend le code de sortie du démon. */
export async function demonterSupervision(s) {
  await s.hote?.arreter(2000).catch(() => {});
  await s.hote?.fermer().catch(() => {});
  const code = s.demon ? await s.demon.arreter() : null;
  await s.collecteur?.arreter();
  await s.fichiers?.arreter();
  await tuer(s.extracteur);
  await tuer(s.sonde);
  await s.relaisRpc?.fermer();
  await s.relaisMetriques?.fermer();
  if (s.etatApprobation) await new Promise((r) => s.etatApprobation.close(() => r()));
  await arreterMontage(s.m);
  return code;
}

/**
 * Provocations jouables sur le montage. Chaque règle attendue porte sa
 * gravité (table de CT-8 §10.4 à §10.7), la chaîne causale qui la justifie et
 * le délai, compté depuis la provocation et hors clause `for`, au bout duquel
 * sa condition est vraie (`condition_s`).
 */
export const PROVOCATIONS = Object.freeze({
  stockage: {
    condition: "CT-2 §17.4 Mode dégradé (stockage) ; Appels bloqués ; Événements en attente ; Disque",
    runbook: "RB-1",
    geste: "lest écrit sur le système de fichiers de storage.root : l'espace libre passe sous storage.min_free_bytes ; levée : lest retiré",
    attendues: [
      { regle: "noortrace_mode_degrade_majeur", gravite: "majeure", condition_s: 15, cause: "espace libre sous min_free_bytes → mode dégradé « stockage » (CT-2 §14.2)" },
      { regle: "noortrace_appels_bloques", gravite: "majeure", condition_s: 30, cause: "stockage indisponible → appels d'écriture bloqués, -31010 (CT-2 §14.2, colonne E)" },
      { regle: "noortrace_attente_non_vide", gravite: "majeure", condition_s: 15, cause: "stockage indisponible → lectures passantes, événements en attente (CT-2 §14.5)" },
      { regle: "noortrace_attente_ancienne", gravite: "majeure", condition_s: 215, cause: "événements en attente → le plus ancien dépasse la moitié de pending_max_ms (400 000 ms dans le montage : seuil 200 000 ms des règles régénérées)" },
      { regle: "noortrace_disque_ligne", gravite: "majeure", condition_s: 30, cause: "espace libre sous min_free_bytes → ligne disk_low du journal d'exploitation, comptée par l'extracteur" },
    ],
    maintien_s: 330,
    resolution_s: 420,
    async appliquer(s) {
      const octets = Math.max(0, octetsLibres(s.stockage) - s.m.config.storage.min_free_bytes) + 64 * MIO;
      const f = fs.openSync(path.join(s.stockage, "lest"), "w");
      try {
        const bloc = Buffer.alloc(MIO, 1);
        for (let k = 0; k < Math.ceil(octets / MIO); k++) fs.writeSync(f, bloc);
        fs.fsyncSync(f);
      } finally {
        fs.closeSync(f);
      }
      return { lest_octets: Math.ceil(octets / MIO) * MIO, min_free_bytes: s.m.config.storage.min_free_bytes, libres_apres: octetsLibres(s.stockage) };
    },
    async lever(s) {
      fs.rmSync(path.join(s.stockage, "lest"), { force: true });
    },
  },
  quota: {
    condition: "CT-2 §17.4 Quota d'un hôte ; Appels bloqués",
    runbook: "aucun",
    geste: "arguments de 32 Kio sur chaque appel de la charge jusqu'au premier refus -31013 compté par le démon (noortrace_calls_blocked_total{code=\"-31013\",reason=\"quota\"}) : le quota received_bytes_per_minute de l'hôte est dépassé ; levée : arguments d'origine",
    attendues: [
      { regle: "noortrace_quota_hote", gravite: "mineure", condition_s: 60, cause: "octets reçus au-delà de received_bytes_per_minute → -31013, direction quota (CT-2 EX-4.47)" },
      { regle: "noortrace_appels_bloques", gravite: "majeure", condition_s: 60, cause: "quota atteint → appels refusés, comptés par noortrace_calls_blocked_total" },
    ],
    maintien_s: 45,
    resolution_s: 450,
    async appliquer(s) {
      // Le refus « avant l'analyse » (CT-2 EX-4.47) est compté par le démon mais rendu avec un id nul, que l'hôte ne rapproche
      // d'aucune requête : le compte se lit sur /metrics du démon, non dans les réponses de l'hôte (défaut signalé).
      const compte = async () => {
        const m = /^noortrace_calls_blocked_total\{class="",code="-31013",reason="quota"\} ([0-9]+)$/m.exec((await lireSupervision(s.m, "/metrics")).texte);
        return m ? Number(m[1]) : 0;
      };
      const avant = await compte();
      s.hote.arguments = { cle: "x".repeat(32 * 1024) };
      const limite = performance.now() + 120000;
      let apres = avant;
      while (apres === avant && performance.now() < limite) {
        await pause(500);
        apres = await compte();
      }
      s.hote.arguments = { cle: "charge" };
      return { refus_avant: avant, refus_apres: apres, reponses_hote_31013: s.hote.codes.get("-31013") ?? 0 };
    },
    async lever() {},
  },
  serveur: {
    condition: "CT-2 §17.4 Mode dégradé (serveur:<alias>)",
    runbook: "aucun",
    geste: "le serveur d'outils s'arrête et s'arrête à chaque relance (fichier « panne ») ; levée : fichier retiré",
    attendues: [
      { regle: "noortrace_mode_degrade_serveur", gravite: "mineure", condition_s: 30, cause: "serveur d'outils injoignable → noortrace_degraded{reason=\"serveur:nul\"} à 1 (CT-2 EX-14.7, EX-14.11, révision 0.10)" },
      { regle: "noortrace_quota_hote", gravite: "mineure", condition_s: 60, cause: "serveur injoignable → les appels en vol attendent les relances → max_concurrent de l'hôte atteint → -31013, direction quota" },
      { regle: "noortrace_appels_bloques", gravite: "majeure", condition_s: 60, cause: "même chaîne : appels refusés par le quota, comptés par noortrace_calls_blocked_total" },
    ],
    maintien_s: 105,
    resolution_s: 450,
    async appliquer(s) {
      fs.writeFileSync(path.join(s.m.etat, "panne"), "");
      return {};
    },
    async lever(s) {
      fs.rmSync(path.join(s.m.etat, "panne"), { force: true });
    },
  },
  definition: {
    condition: "CT-2 §17.4 Définition d'outil changée",
    runbook: "aucun",
    geste: "le serveur d'outils change la description de nul.lire et annonce notifications/tools/list_changed ; aucune levée (règle à fenêtre d'une heure)",
    attendues: [
      { regle: "noortrace_definition_outil_changee", gravite: "mineure", condition_s: 30, cause: "empreinte de la définition changée → noortrace_tool_definition_changes_total (CT-2 EX-4.16)" },
    ],
    maintien_s: 60,
    resolution_s: 0,
    async appliquer(s) {
      fs.writeFileSync(path.join(s.m.etat, "definition"), `Rend un texte fixe (lecture) ; definition changee a ${Date.now()}`);
      return {};
    },
    async lever() {},
  },
  registre: {
    condition: "CT-4 EX-10.5 ; cible noorcore muette (CT-8 §10.6)",
    runbook: "RB-7",
    geste: "les relais TCP vers le point RPC et les métriques du nœud sont fermés ; levée : relais rouverts sur les mêmes ports",
    attendues: [
      { regle: "noortrace_registre_sonde", gravite: "critique", condition_s: 30, cause: "point RPC injoignable → noortrace_registre_sonde_ok à 0 (sonde, CT-8 EX-10.7)" },
      { regle: "noortrace_registre_cible_muette", gravite: "critique", condition_s: 30, cause: "métriques du nœud injoignables → up{job=\"noorcore\"} à 0" },
    ],
    maintien_s: 165,
    resolution_s: 90,
    async appliquer(s) {
      await s.relaisRpc.fermer();
      await s.relaisMetriques.fermer();
      return {};
    },
    async lever(s) {
      await s.relaisRpc.ouvrir();
      await s.relaisMetriques.ouvrir();
    },
  },
});

/**
 * Joue une provocation selon le décompte de CT-9 TE-17 : fenêtre d'observation
 * de l'application à la résolution des règles levées ; chaque règle attendue
 * est suivie jusqu'à sa clause `for` plus trois intervalles d'évaluation après
 * que sa condition est vraie ; la provocation est maintenue au moins
 * `maintien_s`, puis levée ; les transitions de toutes les règles sont lues
 * sur la fenêtre (`collecteur.transitions`).
 * @returns {Promise<object>} compte rendu de la provocation (rapport d'exécution)
 */
export async function jouerProvocation(s, nom, trace = () => {}) {
  const p = PROVOCATIONS[nom];
  const c = s.collecteur;
  const regles = new Map((await c.regles()).map((r) => [r.nom, r]));
  const deja = (await c.alertes()).filter((a) => a.etat === "firing").map((a) => a.nom);
  const debut = Math.floor(Date.now() / 1000);
  const t0 = performance.now();
  trace(`provocation « ${nom} » : ${p.geste}`);
  const detail = await p.appliquer(s);
  let suivies;
  try {
    suivies = await Promise.all(p.attendues.map(async (a) => {
      const r = regles.get(a.regle);
      const delaiS = a.condition_s + r.for_s + 3 * c.intervalleS;
      const vu = await c.attendreAlerte(a.regle, { delaiS });
      trace(`  ${a.regle} : ${vu.levee ? `levée après ${vu.apres_s.toFixed(1)} s` : `non levée en ${delaiS} s`}`);
      return { ...a, for_s: r.for_s, delai_s: delaiS, levee: vu.levee, apres_s: Math.round(vu.apres_s * 10) / 10, gravite_relevee: vu.alerte?.etiquettes.severity ?? null, etiquettes: vu.alerte?.etiquettes ?? null };
    }));
    const reste = p.maintien_s * 1000 - (performance.now() - t0);
    if (reste > 0) await pause(reste);
  } finally {
    await p.lever(s);
  }
  const maintenue = Math.round((performance.now() - t0) / 100) / 10;
  trace(`  levée de la provocation après ${maintenue} s ; attente de la résolution (au plus ${p.resolution_s} s)`);
  const resolutions = [];
  if (p.resolution_s > 0) {
    for (const a of suivies.filter((x) => x.levee)) {
      const r = await c.attendreSilence(a.regle, { delaiS: p.resolution_s });
      resolutions.push({ regle: a.regle, resolue: r.silencieuse, apres_s: Math.round(r.apres_s * 10) / 10 });
    }
    await pause(2 * c.intervalleS * 1000);
  }
  const fin = Math.ceil(Date.now() / 1000);
  const tr = await c.transitions(debut, fin, Math.min(5, c.intervalleS));
  const attendues = new Set(p.attendues.map((a) => a.regle));
  return {
    provocation: nom,
    condition: p.condition,
    runbook: p.runbook,
    geste: p.geste,
    detail,
    fenetre: { debut_s: debut, fin_s: fin, maintenue_s: maintenue },
    declenchees_avant: deja,
    attendues: suivies.map((a) => ({ ...a, transitions: tr.get(a.regle)?.transitions ?? 0, gravites_relevees: tr.get(a.regle)?.gravites ?? [] })),
    resolutions,
    hors_liste: [...tr].filter(([n, v]) => !attendues.has(n) && v.transitions > 0).map(([n, v]) => ({ regle: n, transitions: v.transitions, gravites: v.gravites })),
  };
}
