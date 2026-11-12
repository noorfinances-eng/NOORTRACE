#!/usr/bin/env node
// noortrace-pont-stdio : pont d'un serveur d'outils stdio vers Streamable HTTP
// (CT-8 §3.4, EX-3.7 et EX-3.8 ; image noortrace/pont-stdio).
//
//   noortrace-pont-stdio --ecoute <adresse>:<port> --jeton <fichier>
//       [--chemin /mcp] [--sessions-max <n>] [--delai-ms <n>] [--octets-max <n>]
//       -- <commande absolue> [arguments…]
//   noortrace-pont-stdio sonde --url http://127.0.0.1:<port>/sante
//
// Le pont lance la commande du serveur d'outils comme enfant, une fois par
// session, et la sert en Streamable HTTP (ère héritée de MCP : `initialize`,
// sessions `Mcp-Session-Id`) à l'enregistreur, qui le déclare comme un
// serveur `http` (`policy.servers.<alias>.transport`, CT-2 §15). Aucun
// interpréteur de commandes : la commande est exécutée directement
// (`execve`), par son chemin absolu, sans recherche dans le PATH.
//
// Protocole HTTP, sur `--chemin` (`/mcp` par défaut) :
//   - POST, `Authorization: Bearer <jeton>` exigé (401 sinon) ; le jeton est
//     le contenu exact du fichier `--jeton` (secret `jeton-pont-<alias>`,
//     CLE-15), sans saut de ligne final ; l'en-tête que l'enregistreur
//     présente (`identifiant-outil-<alias>`) contient donc `Bearer <jeton>`.
//     Une requête qui porte un en-tête `Origin` est refusée (403) : seul un
//     navigateur en pose un, et aucun navigateur ne doit joindre le pont.
//     Corps : un seul message JSON-RPC (pas de lot), `application/json`,
//     `--octets-max` octets au plus (413 au-delà).
//       * `initialize` sans session : nouvel enfant, réponse de l'enfant en
//         `application/json` avec l'en-tête `Mcp-Session-Id` ;
//       * requête d'une session : transmise à son enfant, réponse de même
//         identifiant rendue en `application/json` (504 après `--delai-ms`,
//         502 si l'enfant se termine avant) ;
//       * notification ou réponse d'une session : transmise, 202 ;
//       * sans session hors `initialize` : 400 ; session inconnue : 404.
//   - DELETE avec `Mcp-Session-Id` : termine l'enfant de la session (204).
//   - GET : 405 (pas de flux ouvert par le serveur).
// Sur `/sante` : GET sans authentification, 200 `{"status":"ok",…}` tant
// que le pont écoute (sonde du conteneur).
//
// Ce que le pont ne relaie pas : les requêtes du serveur vers le client
// (échantillonnage, élicitation, racines) reçoivent de lui l'erreur -32601,
// comme l'enregistreur le ferait (`relay` faux) ; les notifications du serveur
// hors réponse sont ignorées. La sortie d'erreur de l'enfant reste dans les
// journaux du conteneur du pont (EX-3.8) ; le pont y écrit ses propres lignes
// JSON, sans jamais le jeton ni le contenu des messages.
//
// `sonde --url <url>` : sonde du conteneur (forme `CMD`, sans interpréteur,
// CO-12), même règle que `noortrace-ctl sonde` : `GET <url>` en HTTP sur une
// adresse de boucle locale écrite en clair (127.0.0.0/8 ou [::1]), sans
// identifiants, 2 500 ms au plus ; code 0 sur une réponse 200, 1 sinon.
//
// Codes de sortie du service : 0 arrêt demandé (SIGTERM, SIGINT) ; 1 échec à
// l'écoute ; 2 usage ou jeton refusé (rien n'écoute).
//
// Écrit sans dépendance tierce (décision D-13 de l'étape 7) : modules de
// Node.js seulement.

import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

export const VERSION = "0.1.0";
export const DELAI_SONDE_MS = 2500;
export const DEFAUTS = Object.freeze({ chemin: "/mcp", sessionsMax: 8, delaiMs: 300000, octetsMax: 4 * 1024 * 1024 });
/** Taille maximale d'une ligne de l'enfant (au-delà, la session est close). */
export const LIGNE_MAX = 16 * 1024 * 1024;
const CHEMIN_SANTE = "/sante";

const USAGE =
  "usage : noortrace-pont-stdio --ecoute <adresse>:<port> --jeton <fichier> [--chemin /mcp] [--sessions-max <n>] [--delai-ms <n>] [--octets-max <n>] -- <commande absolue> [arguments…]\n" +
  "        noortrace-pont-stdio sonde --url http://127.0.0.1:<port>/sante";

export class ErreurUsage extends Error {}

const entier = (nom, v, min, max) => {
  if (!/^[0-9]{1,10}$/.test(v ?? "")) throw new ErreurUsage(`${nom} : entier attendu`);
  const n = Number(v);
  if (n < min || n > max) throw new ErreurUsage(`${nom} : entre ${min} et ${max}`);
  return n;
};

/**
 * Adresse d'écoute `<IPv4>:<port>` ou `[<IPv6>]:<port>`, adresse écrite en
 * clair (aucun nom à résoudre).
 */
export function analyserEcoute(texte) {
  const m = /^(?:\[([0-9a-fA-F:.]+)\]|([0-9.]+)):([0-9]{1,5})$/.exec(texte ?? "");
  if (!m) throw new ErreurUsage("--ecoute : <adresse IPv4>:<port> ou [<adresse IPv6>]:<port> attendu");
  const hote = m[1] ?? m[2];
  if (m[1] ? !net.isIPv6(hote) : !net.isIPv4(hote)) throw new ErreurUsage("--ecoute : adresse IP écrite en clair attendue");
  const port = entier("--ecoute (port)", m[3], 0, 65535);
  return { hote, port };
}

/**
 * Options du service. Lève ErreurUsage.
 * @param {string[]} argv arguments qui suivent le nom du programme
 */
export function analyserOptions(argv) {
  const sep = argv.indexOf("--");
  if (sep < 0) throw new ErreurUsage("« -- » puis la commande du serveur d'outils attendus");
  const commande = argv.slice(sep + 1);
  if (commande.length === 0) throw new ErreurUsage("commande du serveur d'outils absente après « -- »");
  if (!path.isAbsolute(commande[0])) throw new ErreurUsage("la commande du serveur d'outils doit être un chemin absolu (aucune recherche dans le PATH)");
  const o = { ...DEFAUTS, commande };
  const vus = new Set();
  const avant = argv.slice(0, sep);
  for (let k = 0; k < avant.length; k += 2) {
    const nom = avant[k];
    const v = avant[k + 1];
    if (vus.has(nom)) throw new ErreurUsage(`option répétée : ${nom}`);
    vus.add(nom);
    if (v === undefined) throw new ErreurUsage(`option ${nom} sans sa valeur`);
    if (nom === "--ecoute") o.ecoute = analyserEcoute(v);
    else if (nom === "--jeton") o.jeton = v;
    else if (nom === "--chemin") {
      if (!/^\/[A-Za-z0-9._~/-]*$/.test(v) || v === CHEMIN_SANTE) throw new ErreurUsage("--chemin : chemin absolu d'URL attendu, autre que /sante");
      o.chemin = v;
    } else if (nom === "--sessions-max") o.sessionsMax = entier(nom, v, 1, 1024);
    else if (nom === "--delai-ms") o.delaiMs = entier(nom, v, 1, 86400000);
    else if (nom === "--octets-max") o.octetsMax = entier(nom, v, 1024, 256 * 1024 * 1024);
    else throw new ErreurUsage(`option inconnue : ${nom}`);
  }
  if (!o.ecoute) throw new ErreurUsage("--ecoute est exigée");
  if (!o.jeton) throw new ErreurUsage("--jeton est exigée");
  return o;
}

/**
 * Lit le jeton : fichier lisible de son seul propriétaire (0400 ou 0600),
 * propriété du compte du pont, contenu imprimable sans espace ni saut de ligne
 * (comme les secrets de CT-2 EX-15.3). Lève ErreurUsage.
 */
export function lireJeton(fichier, uid = process.getuid?.() ?? null) {
  let st;
  try {
    st = fs.statSync(fichier);
  } catch {
    throw new ErreurUsage(`--jeton : fichier ${fichier} illisible`);
  }
  if (!st.isFile()) throw new ErreurUsage(`--jeton : ${fichier} n'est pas un fichier`);
  if ((st.mode & 0o077) !== 0) throw new ErreurUsage(`--jeton : ${fichier} lisible par d'autres que son propriétaire (0400 ou 0600 attendu)`);
  if (uid !== null && st.uid !== uid) throw new ErreurUsage(`--jeton : ${fichier} appartient à un autre compte que celui du pont`);
  let texte;
  try {
    texte = fs.readFileSync(fichier, "utf8");
  } catch {
    throw new ErreurUsage(`--jeton : fichier ${fichier} illisible`);
  }
  if (!/^[\x21-\x7e]{16,4096}$/.test(texte)) throw new ErreurUsage("--jeton : 16 à 4096 caractères imprimables, sans espace ni saut de ligne final, attendus");
  return texte;
}

const empreinte = (s) => crypto.createHash("sha256").update(s, "utf8").digest();

/** Comparaison en temps constant de l'en-tête Authorization. */
function autorise(entete, attendu) {
  if (typeof entete !== "string") return false;
  return crypto.timingSafeEqual(empreinte(entete), attendu);
}

const journal = (sortie, evenement, data = {}) => {
  sortie.write(`${JSON.stringify({ ts: new Date().toISOString(), composant: "pont-stdio", evenement, ...data })}\n`);
};

const erreurRpc = (id, code, message) => JSON.stringify({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });

function repondre(res, statut, corps, entetes = {}) {
  if (res.headersSent || res.destroyed) return;
  const h = { ...entetes };
  if (corps !== undefined) {
    h["content-type"] ??= "application/json";
    h["content-length"] = Buffer.byteLength(corps);
  }
  res.writeHead(statut, h);
  res.end(corps);
}

/**
 * Nature d'un message JSON-RPC : `requete` (méthode et identifiant),
 * `notification` (méthode sans identifiant), `reponse` (identifiant, résultat
 * ou erreur, sans méthode), ou null.
 */
export function natureMessage(m) {
  if (m === null || typeof m !== "object" || Array.isArray(m)) return null;
  const aId = Object.hasOwn(m, "id") && (typeof m.id === "string" || (typeof m.id === "number" && Number.isFinite(m.id)));
  if (typeof m.method === "string") return aId ? "requete" : Object.hasOwn(m, "id") ? null : "notification";
  if (aId && (Object.hasOwn(m, "result") || Object.hasOwn(m, "error"))) return "reponse";
  return null;
}

/** Une session : un enfant, ses attentes par identifiant. */
class Session {
  constructor(id, options, sortieJournal, surFin) {
    this.id = id;
    this.attentes = new Map();
    this.tampon = [];
    this.tailleTampon = 0;
    this.close = false;
    this.journal = sortieJournal;
    const env = {};
    for (const k of ["PATH", "TMPDIR", "LANG", "TZ"]) if (process.env[k] !== undefined) env[k] = process.env[k];
    this.enfant = spawn(options.commande[0], options.commande.slice(1), { stdio: ["pipe", "pipe", "inherit"], env, shell: false });
    this.enfant.stdin.on("error", () => {});
    this.enfant.stdout.on("data", (c) => this._donnees(c));
    this.enfant.once("error", (e) => this._fin({ erreur: e.code ?? e.message }));
    this.enfant.once("exit", (code, signal) => this._fin({ code, signal }));
    this.surFin = surFin;
  }

  _donnees(c) {
    let debut = 0;
    for (;;) {
      const k = c.indexOf(0x0a, debut);
      if (k < 0) break;
      this.tampon.push(c.subarray(debut, k));
      const ligne = Buffer.concat(this.tampon);
      this.tampon = [];
      this.tailleTampon = 0;
      debut = k + 1;
      this._ligne(ligne);
    }
    if (debut < c.length) {
      this.tampon.push(c.subarray(debut));
      this.tailleTampon += c.length - debut;
      if (this.tailleTampon > LIGNE_MAX) {
        journal(this.journal, "ligne_trop_longue", { session: this.id });
        this.terminer();
      }
    }
  }

  _ligne(octets) {
    const texte = octets.toString("utf8").replace(/\r$/, "");
    if (texte.trim() === "") return;
    let m;
    try {
      m = JSON.parse(texte);
    } catch {
      journal(this.journal, "ligne_invalide", { session: this.id });
      return;
    }
    const nature = natureMessage(m);
    if (nature === "reponse") {
      const cle = JSON.stringify(m.id);
      const a = this.attentes.get(cle);
      if (a) {
        this.attentes.delete(cle);
        a.resoudre({ issue: "reponse", texte });
      } else journal(this.journal, "reponse_sans_attente", { session: this.id });
    } else if (nature === "requete") {
      // Requête du serveur vers le client : non relayée.
      journal(this.journal, "requete_serveur_refusee", { session: this.id, methode: m.method });
      this.ecrire(erreurRpc(m.id, -32601, "Method not found"));
    } else if (nature === "notification") {
      // Notification du serveur (progression, journal, liste changée) : ignorée.
    } else journal(this.journal, "ligne_invalide", { session: this.id });
  }

  ecrire(texte) {
    if (this.close) return false;
    try {
      this.enfant.stdin.write(`${texte}\n`);
      return true;
    } catch {
      return false;
    }
  }

  /** Transmet une requête et attend sa réponse. */
  requete(m, texte, delaiMs) {
    const cle = JSON.stringify(m.id);
    if (this.attentes.has(cle)) return Promise.resolve({ issue: "doublon" });
    return new Promise((resoudre) => {
      const minuteur = setTimeout(() => {
        this.attentes.delete(cle);
        resoudre({ issue: "delai" });
      }, delaiMs);
      this.attentes.set(cle, {
        resoudre: (r) => {
          clearTimeout(minuteur);
          resoudre(r);
        },
      });
      if (!this.ecrire(texte)) {
        this.attentes.get(cle)?.resoudre({ issue: "fin" });
        this.attentes.delete(cle);
      }
    });
  }

  oublier(m) {
    this.attentes.delete(JSON.stringify(m.id));
  }

  _fin(info) {
    if (this.close) return;
    this.close = true;
    journal(this.journal, "enfant_termine", { session: this.id, ...info });
    for (const a of this.attentes.values()) a.resoudre({ issue: "fin" });
    this.attentes.clear();
    this.surFin(this);
  }

  terminer() {
    if (this.enfant.exitCode !== null || this.enfant.signalCode !== null) return;
    try {
      this.enfant.stdin.end();
    } catch {
      // déjà fermé
    }
    this.enfant.kill("SIGTERM");
    const t = setTimeout(() => this.enfant.kill("SIGKILL"), 5000);
    t.unref();
  }
}

/**
 * Crée le pont (sans écouter). Rend `{ serveur, sessions, ecouter(), fermer() }`.
 * @param {{ecoute: {hote: string, port: number}, jeton: string, chemin: string, sessionsMax: number, delaiMs: number, octetsMax: number, commande: string[]}} o
 *   `jeton` : valeur du jeton (déjà lue par lireJeton)
 * @param {{journal?: NodeJS.WritableStream}} [io]
 */
export function creerPont(o, io = {}) {
  const sortieJournal = io.journal ?? process.stderr;
  const attendu = empreinte(`Bearer ${o.jeton}`);
  const sessions = new Map();

  const traiterPost = async (req, res, corps) => {
    let m;
    try {
      m = JSON.parse(corps.toString("utf8"));
    } catch {
      return repondre(res, 400, erreurRpc(null, -32700, "Parse error"));
    }
    if (Array.isArray(m)) return repondre(res, 400, erreurRpc(null, -32600, "lots non admis par le pont"));
    const nature = natureMessage(m);
    if (!nature) return repondre(res, 400, erreurRpc(null, -32600, "Invalid Request"));
    const idSession = req.headers["mcp-session-id"];
    if (idSession === undefined) {
      if (nature !== "requete" || m.method !== "initialize") return repondre(res, 400, erreurRpc(nature === "requete" ? m.id : null, -32600, "Mcp-Session-Id exigé hors initialize"));
      if (sessions.size >= o.sessionsMax) return repondre(res, 503, erreurRpc(m.id, -32000, "trop de sessions ouvertes"));
      const id = crypto.randomBytes(16).toString("hex");
      const s = new Session(id, o, sortieJournal, (x) => sessions.delete(x.id));
      sessions.set(id, s);
      journal(sortieJournal, "session_ouverte", { session: id });
      const r = await s.requete(m, corps.toString("utf8"), o.delaiMs);
      if (r.issue !== "reponse") {
        s.terminer();
        sessions.delete(id);
        return repondre(res, r.issue === "delai" ? 504 : 502, erreurRpc(m.id, -32603, r.issue === "delai" ? "délai dépassé" : "serveur d'outils terminé"));
      }
      const reponse = JSON.parse(r.texte);
      if (Object.hasOwn(reponse, "error")) {
        s.terminer();
        sessions.delete(id);
        return repondre(res, 200, r.texte);
      }
      return repondre(res, 200, r.texte, { "mcp-session-id": id });
    }
    const s = typeof idSession === "string" ? sessions.get(idSession) : undefined;
    if (!s) return repondre(res, 404, erreurRpc(nature === "requete" ? m.id : null, -32001, "Session not found"));
    if (nature === "requete" && m.method === "initialize") return repondre(res, 400, erreurRpc(m.id, -32600, "session déjà initialisée"));
    if (nature !== "requete") {
      s.ecrire(corps.toString("utf8"));
      return repondre(res, 202);
    }
    let fermee = false;
    res.once("close", () => {
      fermee = true;
      if (!res.writableFinished) s.oublier(m);
    });
    const r = await s.requete(m, corps.toString("utf8"), o.delaiMs);
    if (fermee && !res.writable) return undefined;
    if (r.issue === "reponse") return repondre(res, 200, r.texte);
    if (r.issue === "doublon") return repondre(res, 400, erreurRpc(m.id, -32600, "identifiant déjà en cours"));
    if (r.issue === "delai") return repondre(res, 504, erreurRpc(m.id, -32603, "délai dépassé"));
    return repondre(res, 502, erreurRpc(m.id, -32603, "serveur d'outils terminé"));
  };

  const serveur = http.createServer((req, res) => {
    const url = (req.url ?? "").split("?")[0];
    if (url === CHEMIN_SANTE) {
      if (req.method !== "GET" && req.method !== "HEAD") return repondre(res, 405, undefined, { allow: "GET, HEAD" });
      return repondre(res, 200, JSON.stringify({ status: "ok", sessions: sessions.size, version: VERSION }));
    }
    if (url !== o.chemin) return repondre(res, 404, JSON.stringify({ erreur: "chemin_inconnu" }));
    if (req.headers.origin !== undefined) return repondre(res, 403, JSON.stringify({ erreur: "origine_refusee" }));
    if (!autorise(req.headers.authorization, attendu)) return repondre(res, 401, JSON.stringify({ erreur: "non_autorise" }), { "www-authenticate": "Bearer" });
    if (req.method === "DELETE") {
      const id = req.headers["mcp-session-id"];
      if (typeof id !== "string") return repondre(res, 400, JSON.stringify({ erreur: "session_absente" }));
      const s = sessions.get(id);
      if (!s) return repondre(res, 404, JSON.stringify({ erreur: "session_inconnue" }));
      sessions.delete(id);
      journal(sortieJournal, "session_fermee", { session: id });
      s.terminer();
      return repondre(res, 204);
    }
    if (req.method !== "POST") return repondre(res, 405, undefined, { allow: "POST, DELETE" });
    const type = String(req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
    if (type !== "application/json") return repondre(res, 415, JSON.stringify({ erreur: "application/json attendu" }));
    const accept = String(req.headers.accept ?? "*/*").toLowerCase();
    if (!accept.includes("application/json") && !accept.includes("*/*")) return repondre(res, 406, JSON.stringify({ erreur: "application/json non accepté" }));
    const morceaux = [];
    let recu = 0;
    let trop = false;
    req.on("data", (c) => {
      if (trop) return;
      recu += c.length;
      if (recu > o.octetsMax) {
        trop = true;
        repondre(res, 413, JSON.stringify({ erreur: "corps_trop_grand" }), { connection: "close" });
        req.destroy();
        return;
      }
      morceaux.push(c);
    });
    req.on("end", () => {
      if (trop) return;
      traiterPost(req, res, Buffer.concat(morceaux)).catch((e) => {
        journal(sortieJournal, "erreur_interne", { message: e.message });
        repondre(res, 500, erreurRpc(null, -32603, "Internal error"));
      });
    });
    return undefined;
  });

  return {
    serveur,
    sessions,
    ecouter: () =>
      new Promise((resoudre, rejeter) => {
        serveur.once("error", rejeter);
        serveur.listen(o.ecoute.port, o.ecoute.hote, () => {
          serveur.off("error", rejeter);
          resoudre(serveur.address());
        });
      }),
    fermer: () =>
      new Promise((resoudre) => {
        for (const s of sessions.values()) s.terminer();
        sessions.clear();
        serveur.close(() => resoudre());
        serveur.closeAllConnections?.();
      }),
  };
}

/** Adresse de boucle locale écrite en clair (127.0.0.0/8 ou ::1). */
export function boucleLocale(hote) {
  const h = hote.replace(/^\[|\]$/g, "");
  if (net.isIPv4(h)) return h.split(".")[0] === "127";
  if (net.isIPv6(h)) {
    try {
      return new URL(`http://[${h}]/`).hostname === "[::1]";
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Sonde : exactement `--url <url>` ; rend 0 sur une réponse 200, 1 sinon.
 * @param {string[]} args
 * @param {{stdout?: NodeJS.WritableStream, stderr?: NodeJS.WritableStream}} [io]
 */
export async function sonde(args, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const echec = (raison) => {
    stderr.write(`noortrace-pont-stdio sonde : ${raison}\n`);
    return 1;
  };
  if (args.length !== 2 || args[0] !== "--url") return echec("usage : sonde --url <url>");
  let url;
  try {
    url = new URL(args[1]);
  } catch {
    return echec("URL invalide");
  }
  if (url.protocol !== "http:") return echec("URL http: attendue");
  if (url.username || url.password) return echec("identifiants refusés dans l'URL");
  if (!boucleLocale(url.hostname)) return echec("adresse de boucle locale écrite en clair attendue");
  return new Promise((resoudre) => {
    let fini = false;
    const finir = (code, message) => {
      if (fini) return;
      fini = true;
      clearTimeout(minuteur);
      req.destroy();
      if (code === 0) stdout.write("200\n");
      else stderr.write(`noortrace-pont-stdio sonde : ${message}\n`);
      resoudre(code);
    };
    const req = http.request(url, { method: "GET", agent: false, headers: { connection: "close" } }, (res) => {
      res.resume();
      if (res.statusCode === 200) res.on("end", () => finir(0));
      else finir(1, `statut ${res.statusCode}`);
    });
    const minuteur = setTimeout(() => finir(1, `aucune réponse en ${DELAI_SONDE_MS} ms`), DELAI_SONDE_MS);
    req.on("error", (e) => finir(1, e.code ?? e.message));
    req.end();
  });
}

/** Point d'entrée. */
export async function principal(argv, io = {}) {
  const stderr = io.stderr ?? process.stderr;
  if (argv[0] === "sonde") return sonde(argv.slice(1), io);
  let o;
  try {
    o = analyserOptions(argv);
    o.jeton = lireJeton(o.jeton);
  } catch (e) {
    if (!(e instanceof ErreurUsage)) throw e;
    stderr.write(`noortrace-pont-stdio : ${e.message}\n${USAGE}\n`);
    return 2;
  }
  const pont = creerPont(o, { journal: stderr });
  try {
    const a = await pont.ecouter();
    journal(stderr, "demarrage", { version: VERSION, ecoute: `${a.address}:${a.port}`, chemin: o.chemin, commande: o.commande[0] });
  } catch (e) {
    journal(stderr, "ecoute_impossible", { message: e.code ?? e.message });
    return 1;
  }
  return new Promise((resoudre) => {
    const arreter = (signal) => {
      journal(stderr, "arret", { signal });
      pont.fermer().then(() => resoudre(0));
    };
    process.once("SIGTERM", () => arreter("SIGTERM"));
    process.once("SIGINT", () => arreter("SIGINT"));
  });
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  principal(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      process.stderr.write(`noortrace-pont-stdio : ${e.stack ?? e.message}\n`);
      process.exit(1);
    },
  );
}
