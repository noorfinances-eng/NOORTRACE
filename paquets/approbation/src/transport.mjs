// Transport et authentification (CT-3 12.1, EX-12.1, EX-12.2, EX-12.4,
// EX-12.13) : requêtes HTTP/1.1 `POST <base>/v0/<méthode>`, corps et réponse
// objets JSON en UTF-8 (`Content-Type: application/json`), lus en JSON strict
// (clés uniques, aucun substitut isolé) ; erreurs de 12.8 en 4xx ou 5xx de
// corps `{ "error": { "code", "message", "data" } }` ; `GET <base>/v0/etat`
// (EX-12.12).
//
// Deux canaux, chacun sur son écoute : celui du noyau (méthodes 12.2 à 12.6)
// et celui de la console (méthodes de 12.9 ; à l'étape 4, `voter`,
// `recuser`, `retirer`). Une méthode de l'autre canal est refusée
// (`requete_invalide`, EX-12.13). Authentification : jeton porteur distinct
// par canal, comparé en temps constant ; ou mTLS (certificat client signé par
// l'autorité de la configuration) ; sur une prise Unix, la prise est créée
// avec le mode de la configuration (0660 par défaut) dans un répertoire non
// inscriptible par les autres (lecture 2 du LISEZMOI : Node.js n'expose pas
// l'identité du pair).

import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { timingSafeEqual } from "node:crypto";
import { ErreurJson } from "@noortrace/noyau";
import { lireJsonStrict, jcsIntegral } from "./json.mjs";
import { ErreurService } from "./erreurs.mjs";
import { METHODES_NOYAU, METHODES_CONSOLE, METHODES_CONSOLE_ETAPE_6 } from "./service.mjs";

/** Compare deux jetons en temps constant. */
export function jetonsEgaux(a, b) {
  const x = Buffer.from(String(a), "utf8");
  const y = Buffer.from(String(b), "utf8");
  if (x.length !== y.length) {
    timingSafeEqual(x, x);
    return false;
  }
  return timingSafeEqual(x, y);
}

function repondre(res, statut, objet) {
  let texte;
  try {
    texte = jcsIntegral(objet);
  } catch {
    statut = 500;
    texte = JSON.stringify({ error: { code: "requete_invalide", message: "reponse non serialisable", data: {} } });
  }
  const corps = Buffer.from(texte, "utf8");
  res.writeHead(statut, { "content-type": "application/json", "content-length": corps.length, "cache-control": "no-store" });
  res.end(corps);
}

function repondreErreur(res, e) {
  repondre(res, e.statut, e.corps());
}

/**
 * Écoute d'un canal.
 */
export class Ecoute {
  /**
   * @param {{canal: "noyau"|"console", service: import("./service.mjs").ServiceApprobation,
   *   config: {socket?: string|null, socket_mode?: string, tcp?: {host: string, port: number}|null,
   *     tls?: {cert: string, key: string, client_ca?: string}|null},
   *   jeton: string|null, bodyMax: number, base?: string}} p
   */
  constructor(p) {
    this.canal = p.canal;
    this.service = p.service;
    this.config = p.config;
    this.jeton = p.jeton;
    this.bodyMax = p.bodyMax;
    this.base = p.base ?? process.cwd();
    this.serveur = null;
    this.adresse = null;
  }

  #authentifie(req) {
    if (this.config.tls?.client_ca && !req.socket.authorized) return false;
    if (this.jeton === null) return true;
    const h = req.headers.authorization;
    if (typeof h !== "string" || !h.startsWith("Bearer ")) return false;
    return jetonsEgaux(h.slice(7), this.jeton);
  }

  async #traiter(req, res) {
    try {
      if (!this.#authentifie(req)) {
        this.service.supervision.consigner("auth_refusee", { canal: this.canal });
        return repondre(res, 401, new ErreurService("requete_invalide", {}, "authentification").corps());
      }
      const url = new URL(req.url, "http://localhost");
      const m = /^\/v0\/([a-z_]+)$/.exec(url.pathname);
      if (!m) return repondreErreur(res, new ErreurService("requete_invalide", {}, "chemin inconnu"));
      const methode = m[1];
      if (req.method === "GET" && methode === "etat") return repondre(res, 200, this.service.etat());
      if (req.method !== "POST") return repondreErreur(res, new ErreurService("requete_invalide", {}, "methode HTTP"));
      const type = String(req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
      if (type !== "application/json") return repondreErreur(res, new ErreurService("requete_invalide", {}, "content-type"));
      const octets = await this.#lireCorps(req);
      if (octets === null) return repondreErreur(res, new ErreurService("requete_invalide", {}, "corps trop grand"));
      let corps;
      try {
        corps = lireJsonStrict(octets);
      } catch (e) {
        if (e instanceof ErreurJson) return repondreErreur(res, new ErreurService("requete_invalide", {}, "JSON strict"));
        throw e;
      }
      if (corps === null || typeof corps !== "object" || Array.isArray(corps)) {
        return repondreErreur(res, new ErreurService("requete_invalide", {}, "objet attendu"));
      }
      const r = await this.#dispatcher(methode, corps);
      repondre(res, 200, r);
    } catch (e) {
      if (e instanceof ErreurService) return repondreErreur(res, e);
      this.service.supervision.consigner("erreur", { kind: "transport", message: e.message });
      repondre(res, 500, { error: { code: "requete_invalide", message: "erreur interne", data: {} } });
    }
  }

  #lireCorps(req) {
    return new Promise((resoudre, rejeter) => {
      const morceaux = [];
      let taille = 0;
      let trop = false;
      req.on("data", (x) => {
        taille += x.length;
        if (taille > this.bodyMax) trop = true;
        else morceaux.push(x);
      });
      req.on("end", () => resoudre(trop ? null : new Uint8Array(Buffer.concat(morceaux))));
      req.on("error", rejeter);
    });
  }

  #dispatcher(methode, corps) {
    const s = this.service;
    if (this.canal === "noyau") {
      if (!METHODES_NOYAU.includes(methode)) throw new ErreurService("requete_invalide", {}, "methode hors du canal du noyau");
      return s[methode](corps);
    }
    if (METHODES_CONSOLE.includes(methode)) return s.console(methode, corps);
    if (METHODES_CONSOLE_ETAPE_6.includes(methode)) throw new ErreurService("requete_invalide", {}, "methode du canal de la console non servie a l'etape 4");
    throw new ErreurService("requete_invalide", {}, "methode hors du canal de la console");
  }

  /** Démarre l'écoute ; rend l'adresse (port réel en TCP). */
  async demarrer() {
    const c = this.config;
    const gestion = (req, res) => {
      this.#traiter(req, res);
    };
    if (c.tls) {
      const lire = (f) => fs.readFileSync(path.resolve(this.base, f));
      this.serveur = https.createServer(
        {
          cert: lire(c.tls.cert),
          key: lire(c.tls.key),
          ...(c.tls.client_ca ? { ca: lire(c.tls.client_ca), requestCert: true, rejectUnauthorized: true } : {}),
          minVersion: "TLSv1.2",
        },
        gestion,
      );
    } else {
      this.serveur = http.createServer(gestion);
    }
    this.serveur.requestTimeout = 60000;
    this.serveur.headersTimeout = 10000;
    if (c.socket) {
      const dir = path.dirname(c.socket);
      const st = await fsp.stat(dir);
      if ((st.mode & 0o002) !== 0) throw new Error(`répertoire de prise inscriptible par tous : ${dir} (EX-12.2)`);
      await fsp.rm(c.socket, { force: true });
      await new Promise((ok, ko) => this.serveur.once("error", ko).listen(c.socket, ok));
      await fsp.chmod(c.socket, parseInt(c.socket_mode ?? "0660", 8));
      this.adresse = { socket: c.socket };
    } else {
      await new Promise((ok, ko) => this.serveur.once("error", ko).listen(c.tcp.port, c.tcp.host, ok));
      const a = this.serveur.address();
      this.adresse = { host: c.tcp.host, port: a.port };
    }
    return this.adresse;
  }

  async arreter() {
    if (!this.serveur) return;
    await new Promise((ok) => {
      this.serveur.close(() => ok());
      this.serveur.closeAllConnections?.();
    });
    if (this.config.socket) await fsp.rm(this.config.socket, { force: true });
    this.serveur = null;
  }
}
