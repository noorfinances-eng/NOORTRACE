// Mode miroir du frontal modèle (CT-2 §5.1.3, EX-5.6, EX-5.8, EX-14.12).
//
// Un équipement du client copie le trafic déchiffré ; un **adaptateur de
// capture**, processus séparé (`bin/noortrace-miroir`), réassemble les
// transactions HTTP/1.1 de chaque connexion copiée et les remet au démon par
// la prise locale `model.mirror.socket`, sous la forme d'un couple (requête,
// réponse) horodaté, avec l'adresse source du flux. Le démon construit
// l'événement comme en passerelle, avec `is_error` selon le statut HTTP
// observé ; la connexion d'hôte est l'entrée de `model.hosts` dont
// `match.source_addresses` contient l'adresse source (ou l'entrée
// `"inconnu"`). Rien n'est bloqué ni retenu ; une réponse tronquée dans la
// copie donne une forme incomplète ; pendant un mode dégradé, l'échange est
// mis en attente dans les bornes de 14.5, puis perdu et consigné
// (`exchange_lost`, EX-14.12). HTTP/2 n'est pas réassemblé (section 21).
//
// Prise du démon (LISEZMOI, lecture 78) : une ligne JSON par couple,
//   { "version": 0, "source", "t_requete", "t_reponse",
//     "request": { "method", "target", "headers": [[nom, valeur]…], "body": base64 },
//     "response": { "status", "headers": […], "body": base64, "body_length", "complete" } | null }
// et une ligne de réponse par couple : { "ok": true, "seq", "pending_id" } ou
// { "ok": false, "reason" }.
//
// Entrée de l'adaptateur (lecture 79) : la copie, flux d'octets de chaque
// connexion TCP et de chaque sens, en trames : une ligne JSON
//   { "connexion", "sens": "client"|"serveur"|"fin", "source", "longueur" }
// suivie de `longueur` octets.
//
// Authentification (CT-2 EX-5.6, EX-18.1 ; complément du 2026-11-16) :
//   - la copie est écoutée par défaut sur la boucle locale
//     (`MIROIR_ECOUTE_DEFAUT`) ; une adresse hors de la boucle locale n'est
//     admise qu'avec une authentification de la source de la copie : TLS
//     avec certificat client d'une autorité propre (`model.mirror.tls` et
//     `client_ca`), ou une liste fermée de sources (`allowed_sources`) ;
//     sinon l'adaptateur refuse de démarrer (`ecoute_non_authentifiee`) ;
//     une connexion de copie non admise est fermée avant toute lecture ;
//   - la prise du démon est en mode 0600 (seul le compte du démon la joint)
//     sans `model.mirror.peer_user` ; avec lui, en mode 0660, et chaque
//     connexion prouve son compte par la preuve de fichier d'EX-4.39
//     (défi, `.noortrace-defi-<défi>` créé par le pair, propriétaire lu par
//     le démon) : un autre compte est refusé (`auth_failed`).

import net from "node:net";
import tls from "node:tls";
import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { decoderHorodatage } from "@noortrace/noyau";
import { normaliserCible, trouverRoute, hotePourAdresse, declarationsFournisseur, listeAdresses, adresseDans, ecouteLocaleModele } from "./formats.mjs";
import { analyserCorpsJson } from "./extraction.mjs";
import { MoteurEchanges } from "./echange.mjs";
import {
  ecouterPriseUnix, preparerRepertoirePrise, libererCheminPrise, GardeIdentification, verifierPreuveFichier, DecoupeurLignes, PREFIXE_DEFI,
} from "../mcp/hote-stdio.mjs";
import { MIROIR_TRAME_MAX_OCTETS, MIROIR_CONNEXIONS_MAX, regleCheminPrise } from "../bornes.mjs";

/** Adresse d'écoute de la copie par défaut (CT-2 EX-5.6) : la boucle locale. */
export const MIROIR_ECOUTE_DEFAUT = "127.0.0.1:8410";

/** Mode de la prise du démon : réservée au compte du démon sans `peer_user`, au groupe avec (EX-18.1). */
export const MODE_PRISE_MIROIR = 0o600;
export const MODE_PRISE_MIROIR_PAIR = 0o660;

/**
 * La copie a-t-elle une authentification de sa source (EX-5.6) : TLS avec
 * certificat client (autorité donnée), ou liste fermée de sources non vide ?
 * @param {{tls?: {ca?: unknown}|null, sources?: string[]|null}} o
 */
export function copieAuthentifiee(o) {
  return Boolean(o.tls && o.tls.ca) || (Array.isArray(o.sources) && o.sources.length > 0);
}

/** Borne d'une ligne de la prise du miroir : corps en base64 et en-têtes. */
function borneLigne(lim) {
  return Math.ceil(((lim.model_request_max_bytes + lim.model_response_max_bytes) * 4) / 3) + 65536;
}

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** En-têtes d'un couple : liste de paires de chaînes, lue en minuscules. */
function entetesCouple(liste) {
  if (!Array.isArray(liste)) return null;
  const o = {};
  for (const p of liste) {
    if (!Array.isArray(p) || p.length !== 2 || typeof p[0] !== "string" || typeof p[1] !== "string") return null;
    const n = p[0].toLowerCase();
    o[n] = n in o ? `${o[n]}, ${p[1]}` : p[1];
  }
  return o;
}

function base64(v) {
  if (typeof v !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(v) || v.length % 4 !== 0) return null;
  return new Uint8Array(Buffer.from(v, "base64"));
}

/** Récepteur des couples de l'adaptateur, dans le démon. */
export class RecepteurMiroir {
  /**
   * @param {object} o
   * @param {import("../coeur.mjs").Coeur} o.coeur
   * @param {MoteurEchanges} [o.moteur]
   * @param {object} [o.registre]
   * @param {object} [o.config]
   * @param {object} [o.redacteur]
   * @param {object} [o.observateur]
   */
  constructor(o) {
    this.coeur = o.coeur;
    this.moteur = o.moteur ?? new MoteurEchanges({ coeur: o.coeur, redacteur: o.redacteur, registre: o.registre, config: o.config, observateur: o.observateur });
    this.prises = new Set();
    this.enCours = new Set();
  }

  get config() {
    return this.moteur.config;
  }

  get journal() {
    return this.moteur.journal;
  }

  get registre() {
    return this.moteur.registre;
  }

  /**
   * Prise locale `model.mirror.socket` (EX-5.6, EX-18.1) : réservée au compte
   * du démon (mode 0600) sans `peer_user` ; avec lui, mode 0660 dans un
   * répertoire contrôlé (EX-4.39), et preuve d'identité du pair à chaque connexion.
   */
  async ecouter() {
    const chemin = this.config.model.mirror.socket;
    this.pair = this.config.model.mirror.peer_user ?? null;
    if (this.pair !== null) {
      // Même règle de répertoire que mcp.socket : un pair ne peut ni renommer la preuve d'un autre, ni tenir le chemin.
      preparerRepertoirePrise(chemin);
      libererCheminPrise(chemin);
      this.garde = new GardeIdentification();
    } else {
      fs.mkdirSync(chemin.slice(0, chemin.lastIndexOf("/")) || "/", { recursive: true });
      try {
        if (fs.lstatSync(chemin).isSocket()) fs.rmSync(chemin);
      } catch {
        // absente
      }
    }
    this.serveur = net.createServer((s) => (this.pair !== null ? this._identifier(s) : this._connexion(s)));
    // EX-18.1 : mode posé dès la création de la prise, sans fenêtre plus ouverte.
    await ecouterPriseUnix(this.serveur, chemin, this.pair !== null ? MODE_PRISE_MIROIR_PAIR : MODE_PRISE_MIROIR);
  }

  /**
   * Preuve d'identité du pair de la prise (EX-5.6, EX-4.39) : défi, fichier
   * `.noortrace-defi-<défi>` créé par le pair dans le répertoire de la prise,
   * propriétaire égal à `model.mirror.peer_user` ; sinon `auth_failed` et
   * connexion fermée, sans lire un couple.
   * @param {net.Socket} socket
   */
  _identifier(socket) {
    this.prises.add(socket);
    socket.on("close", () => this.prises.delete(socket));
    socket.on("error", () => {});
    const refuser = (raison, detail = null) => {
      this.garde.identifiee(socket);
      this.journal.consigner("warning", "frontal_modele", "auth_failed", { transport: "miroir", reason: raison, ...(detail ? { detail } : {}) });
      socket.destroy();
    };
    if (!this.garde.admettre(socket, (r) => refuser(r))) return;
    const defi = randomBytes(16).toString("hex");
    const instantDefi = Date.now();
    socket.write(`${JSON.stringify({ noortrace_defi: defi })}\n`);
    let fini = false;
    const d = new DecoupeurLignes(4096, (l) => {
      if (fini) return;
      fini = true;
      socket.removeAllListeners("data");
      let preuve = null;
      try {
        preuve = JSON.parse(Buffer.from(l).toString("utf8")).noortrace_preuve;
      } catch {
        preuve = null;
      }
      if (preuve !== defi) return refuser("preuve");
      const v = verifierPreuveFichier(this.config.model.mirror.socket, defi, instantDefi);
      if (v.refus) return refuser(v.refus, v.detail);
      if (v.utilisateur !== this.pair) return refuser("pair_refuse", v.utilisateur ?? "compte_inconnu");
      this.garde.identifiee(socket);
      socket.write(`${JSON.stringify({ noortrace_identite: "acceptee" })}\n`);
      // Le pair n'écrit aucun couple avant `acceptee` (adaptateur, `lancerAdaptateur`).
      this._connexion(socket);
    }, () => refuser("preuve"));
    socket.on("data", (x) => d.pousser(x));
  }

  async arreter() {
    // Étape 8 (CT-2 EX-5.6) : les prises sont détruites d'abord ; `close` n'attend
    // alors plus un adaptateur connecté, et l'arrêt du démon n'est pas retenu.
    for (const p of this.prises) p.destroy();
    await new Promise((r) => (this.serveur ? this.serveur.close(() => r()) : r()));
    await Promise.allSettled([...this.enCours]);
  }

  _connexion(socket) {
    if (!this.prises.has(socket)) {
      this.prises.add(socket);
      socket.on("close", () => this.prises.delete(socket));
      socket.on("error", () => {});
    }
    const borne = borneLigne(this.config.limits);
    // Ligne en cours : morceaux reçus, sans recopie ; la fin de ligne n'est cherchée que dans le morceau nouveau.
    let morceaux = [];
    let longueur = 0;
    let chaine = Promise.resolve();
    socket.on("data", (d) => {
      let reste = d;
      for (;;) {
        const k = reste.indexOf(10);
        if (k < 0) {
          morceaux.push(reste);
          longueur += reste.length;
          if (longueur > borne) {
            this.journal.consigner("warning", "frontal_modele", "mirror_line_refused", { reason: "taille" });
            morceaux = [];
            longueur = 0;
            socket.destroy();
          }
          return;
        }
        const ligne = Buffer.concat([...morceaux, reste.subarray(0, k)]);
        morceaux = [];
        longueur = 0;
        reste = reste.subarray(k + 1);
        if (ligne.length > borne) {
          this.journal.consigner("warning", "frontal_modele", "mirror_line_refused", { reason: "taille" });
          socket.destroy();
          return;
        }
        // Couples traités dans l'ordre de la prise ; la réponse d'un couple suit sa durabilité.
        chaine = chaine
          .then(() => this._couple(ligne))
          .catch((e) => {
            // Étape 8 (CT-2 EX-5.6) : une exception d'un couple est une réponse `ok: false`
            // consignée ; les couples suivants de la connexion sont traités.
            this.journal.consigner("error", "frontal_modele", "exchange_lost", { mode: "miroir", reason: String(e?.message ?? e).slice(0, 200) });
            return { ok: false, reason: "erreur_interne" };
          })
          .then((r) => {
            if (!socket.destroyed) socket.write(`${JSON.stringify(r)}\n`);
          });
        const p = chaine.catch(() => {});
        this.enCours.add(p);
        p.finally(() => this.enCours.delete(p));
      }
    });
  }

  /**
   * Un couple (requête, réponse) remis par l'adaptateur.
   * @param {Uint8Array} ligne
   * @returns {Promise<{ok: boolean, seq?: number|null, pending_id?: string|null, reason?: string}>}
   */
  async _couple(ligne) {
    const cfg = this.config;
    let c;
    try {
      c = JSON.parse(Buffer.from(ligne).toString("utf8"));
    } catch {
      return this._refus("couple_illisible");
    }
    if (!estObjet(c) || c.version !== 0 || !estObjet(c.request) || (c.response !== null && !estObjet(c.response))) return this._refus("couple_mal_forme");
    const q = c.request;
    const eq = entetesCouple(q.headers);
    const corpsReq = base64(q.body ?? "");
    if (typeof q.method !== "string" || typeof q.target !== "string" || !eq || !corpsReq) return this._refus("couple_mal_forme");
    let tReq;
    let tRep;
    try {
      tReq = decoderHorodatage(c.t_requete);
      tRep = c.t_reponse === null ? null : decoderHorodatage(c.t_reponse);
    } catch {
      return this._refus("couple_mal_forme");
    }
    if (!Number.isFinite(tReq) || (tRep !== null && !Number.isFinite(tRep))) return this._refus("couple_mal_forme");
    const t_recu = this.moteur.monotone();
    // Connexion d'hôte par l'adresse source du flux (EX-5.8 point 3).
    const hote = hotePourAdresse(cfg, typeof c.source === "string" ? c.source : null);
    const cible = normaliserCible(/^https?:\/\//i.test(q.target) ? (() => {
      try {
        const u = new URL(q.target);
        return `${u.pathname}${u.search}`;
      } catch {
        return "";
      }
    })() : q.target);
    const trouve = cible.ok ? trouverRoute(cfg.policy.model?.routes ?? [], q.method, cible.chemin) : null;
    if (!trouve || trouve.genre !== "echange") {
      this.journal.consigner("info", "frontal_modele", "model_route_not_found", { method: q.method, path_length: Buffer.byteLength(q.target), mode: "miroir" });
      return this._refus("route_inconnue");
    }
    const route = trouve.route;
    if (!hote) {
      // Consigné sans événement (EX-5.8).
      this.journal.consigner("warning", "frontal_modele", "auth_failed", { transport: "miroir", reason: "hote_inconnu", route: route.path });
      return this._refus("hote_inconnu");
    }
    // Une requête que la passerelle refuserait (EX-5.7) ne peut ni être rédigée ni être stockée : consignée, sans événement (lecture 80).
    const ce = eq["content-encoding"];
    const refus = (raison, donnees = {}) => {
      this.journal.consigner("warning", "frontal_modele", "model_request_refused", { route: route.path, raison, mode: "miroir", ...donnees }, { host: hote.id });
      return this._refus(raison);
    };
    if (corpsReq.length > cfg.limits.model_request_max_bytes) return refus("taille", { length: corpsReq.length });
    if (ce !== undefined && ce.trim().toLowerCase() !== "identity") return refus("content_encoding", { length: corpsReq.length, content_type: eq["content-type"] ?? null });
    const analyse = analyserCorpsJson(corpsReq, this.moteur.bornes);
    if (!analyse.ok) return refus("corps_non_analysable", { length: corpsReq.length, content_type: eq["content-type"] ?? null });
    if (route.format === "gemini") {
      // Serveurs MCP et contenu en cache déclarés au fournisseur (EX-5.32) : la requête est déjà
      // partie, le miroir ne peut que consigner ; l'échange donne son événement (lecture 76).
      const d = declarationsFournisseur(analyse.valeur);
      if (d.mcp > 0) this.journal.consigner("warning", "frontal_modele", "provider_mcp_bypass", { route: route.path, entries: d.mcp, mode: "miroir" }, { host: hote.id });
      if (d.cache) this.journal.consigner("warning", "frontal_modele", "provider_cache_reference", { route: route.path, mode: "miroir" }, { host: hote.id });
    }
    // Le miroir ne bloque rien : ni mode dégradé, ni quota (EX-5.6, EX-14.12).
    const p = await this.moteur.preparer({ route, trouve, hote, entetes: eq, valeur: analyse.valeur, t_recu, mode: "miroir" });
    if (p.refus) return this._refus(p.refus);
    const etat = p.etat;
    etat.cheminAmont = q.target;
    etat.t_envoi = 0;
    if (c.response === null) {
      // Aucune réponse dans la copie : l'hôte n'a rien reçu de lisible ; échange en erreur (lecture 80).
      etat.t_reponse = tRep === null ? 0 : Math.max(0, tRep - tReq);
      const e = await this.moteur.sceller(etat, { genre: "hote_parti" });
      return { ok: true, seq: e?.seq ?? null };
    }
    const r = c.response;
    const er = entetesCouple(r.headers);
    const corpsRep = base64(r.body ?? "");
    if (!Number.isInteger(r.status) || r.status < 100 || r.status > 599 || !er || !corpsRep) {
      etat.t_reponse = 0;
      const e = await this.moteur.sceller(etat, { genre: "hote_parti" });
      return { ok: true, seq: e?.seq ?? null, note: "reponse_mal_formee" };
    }
    const capture = this.moteur.capture(etat, { statut: r.status, entetes: er, notesReponse: { ...(er["request-id"] ? { "request-id": er["request-id"] } : {}), ...(er["x-request-id"] ? { "x-request-id": er["x-request-id"] } : {}) } });
    capture.ecrire(corpsRep);
    // Corps observé au-delà de ce que la copie remet (borne de l'adaptateur) : capture arrêtée à la borne (EX-5.33).
    if (Number.isSafeInteger(r.body_length) && r.body_length > corpsRep.length) {
      capture.tronque = true;
      capture.recues = r.body_length - corpsRep.length + capture.recues;
      capture.reass?.couper();
    }
    await capture.terminer({ coupe: r.complete !== true });
    etat.t_reponse = tRep === null ? 0 : Math.max(0, tRep - tReq);
    const e = await this.moteur.sceller(etat, { genre: r.complete === true ? "reponse" : "coupure" });
    return { ok: true, seq: e?.seq ?? null };
  }

  _refus(raison) {
    return { ok: false, reason: raison };
  }
}

// ------------------------------------------------------------ adaptateur de capture (processus séparé)

const LIGNE_MAX = 65536;

/**
 * Réassemblage HTTP/1.1 d'un sens d'une connexion copiée : messages
 * successifs (en-têtes, puis corps par `Content-Length`, `chunked`, ou
 * jusqu'à la fermeture pour une réponse sans longueur).
 */
class Sens {
  constructor(o) {
    this.requete = o.requete;
    this.borne = o.borne;
    this.tampon = Buffer.alloc(0);
    this.etat = "tete";
    this.courant = null;
    this.prochainSansCorps = o.sansCorps ?? (() => false);
  }

  ajouter(o, emettre) {
    // Étape 8 (CT-2 EX-5.6) : un sens illisible (HTTP/2, trame hors forme) ne
    // garde plus rien ; les octets sont comptés et jetés.
    if (this.etat === "illisible") {
      this.ignores = (this.ignores ?? 0) + o.length;
      this.tampon = Buffer.alloc(0);
      return;
    }
    this.tampon = this.tampon.length ? Buffer.concat([this.tampon, o]) : Buffer.from(o);
    for (;;) {
      if (this.etat === "tete") {
        const k = this.tampon.indexOf("\r\n\r\n");
        if (k < 0) {
          if (this.tampon.length > LIGNE_MAX) this._illisible();
          return;
        }
        const lignes = this.tampon.subarray(0, k).toString("latin1").split("\r\n");
        this.tampon = this.tampon.subarray(k + 4);
        const depart = lignes.shift();
        const entetes = lignes.map((l) => {
          const j = l.indexOf(":");
          return j > 0 ? [l.slice(0, j), l.slice(j + 1).trim()] : null;
        });
        if (entetes.includes(null)) {
          this._illisible();
          return;
        }
        const get = (n) => entetes.filter(([x]) => x.toLowerCase() === n).map(([, v]) => v);
        const m = { depart, entetes, morceaux: [], octets: 0, total: 0, t: Date.now() };
        if (!this.requete) {
          const st = /^HTTP\/1\.[01] ([0-9]{3})/.exec(depart);
          if (!st) {
            this._illisible();
            return;
          }
          m.statut = Number(st[1]);
          if (m.statut >= 100 && m.statut < 200) continue; // réponse intermédiaire : ignorée
        } else if (!/^\S+ \S+ HTTP\/1\.[01]$/.test(depart)) {
          this._illisible();
          return;
        }
        const te = get("transfer-encoding").join(",").toLowerCase();
        const cl = get("content-length");
        if (!this.requete && (this.prochainSansCorps() || m.statut === 204 || m.statut === 304)) m.mode = "aucun";
        else if (te.includes("chunked")) m.mode = "chunked";
        else if (cl.length) {
          m.mode = "longueur";
          m.reste = Number(cl[0]);
          if (!Number.isSafeInteger(m.reste) || m.reste < 0) {
            this._illisible();
            return;
          }
        } else m.mode = this.requete ? "aucun" : "fermeture";
        this.courant = m;
        this.etat = "corps";
        this.sousEtat = "taille";
      }
      if (this.etat !== "corps") return;
      const m = this.courant;
      const garder = (x) => {
        m.total += x.length;
        if (m.octets + x.length <= this.borne) {
          m.morceaux.push(x);
          m.octets += x.length;
        } else if (m.octets < this.borne) {
          m.morceaux.push(x.subarray(0, this.borne - m.octets));
          m.octets = this.borne;
        }
      };
      if (m.mode === "aucun") {
        this._fini(emettre);
        continue;
      }
      if (m.mode === "fermeture") {
        garder(this.tampon);
        this.tampon = Buffer.alloc(0);
        return;
      }
      if (m.mode === "longueur") {
        const n = Math.min(m.reste, this.tampon.length);
        garder(this.tampon.subarray(0, n));
        this.tampon = this.tampon.subarray(n);
        m.reste -= n;
        if (m.reste === 0) {
          this._fini(emettre);
          continue;
        }
        return;
      }
      // chunked
      if (this.sousEtat === "taille") {
        const k = this.tampon.indexOf("\r\n");
        if (k < 0) return;
        const n = parseInt(this.tampon.subarray(0, k).toString("latin1").split(";")[0].trim(), 16);
        this.tampon = this.tampon.subarray(k + 2);
        if (!Number.isSafeInteger(n) || n < 0) {
          this._illisible();
          return;
        }
        if (n === 0) this.sousEtat = "remorque";
        else {
          this.sousEtat = "donnees";
          m.reste = n;
        }
        continue;
      }
      if (this.sousEtat === "donnees") {
        const n = Math.min(m.reste, this.tampon.length);
        garder(this.tampon.subarray(0, n));
        this.tampon = this.tampon.subarray(n);
        m.reste -= n;
        if (m.reste > 0) return;
        this.sousEtat = "crlf";
      }
      if (this.sousEtat === "crlf") {
        if (this.tampon.length < 2) return;
        this.tampon = this.tampon.subarray(2);
        this.sousEtat = "taille";
        continue;
      }
      if (this.sousEtat === "remorque") {
        const k = this.tampon.indexOf("\r\n");
        if (k < 0) return;
        this.tampon = this.tampon.subarray(k + 2);
        if (k === 0) {
          this._fini(emettre);
          continue;
        }
      }
    }
  }

  /** Le sens ne se lit plus (CT-2 EX-5.6) : tampon et message en cours abandonnés. */
  _illisible() {
    this.etat = "illisible";
    this.tampon = Buffer.alloc(0);
    this.courant = null;
  }

  _fini(emettre) {
    const m = this.courant;
    this.courant = null;
    this.etat = "tete";
    m.complet = true;
    m.fin = Date.now();
    emettre(m);
  }

  /** Fermeture du sens : le message en cours finit (complet s'il se lit jusqu'à la fermeture). */
  fermer(emettre) {
    const m = this.courant;
    if (!m) return;
    this.courant = null;
    m.complet = m.mode === "fermeture";
    m.fin = Date.now();
    emettre(m);
  }
}

const iso = (ms) => new Date(ms).toISOString();

/**
 * Adaptateur de capture du miroir : réassemble les transactions HTTP/1.1 de
 * chaque connexion copiée et remet chaque couple au démon.
 */
export class AdaptateurMiroir {
  /**
   * @param {{remettre: (couple: object) => void, borneRequete?: number, borneReponse?: number}} o
   */
  constructor(o) {
    this.remettre = o.remettre;
    this.borneRequete = o.borneRequete ?? 33554432;
    this.borneReponse = o.borneReponse ?? 33554432;
    this.connexions = new Map();
  }

  _connexion(id, source) {
    let c = this.connexions.get(id);
    if (!c) {
      // Étape 8 (CT-2 EX-5.6) : connexions copiées suivies bornées ; la plus ancienne est close (requêtes sans réponse remises seules).
      if (this.connexions.size >= MIROIR_CONNEXIONS_MAX) this.fin(this.connexions.keys().next().value);
      c = { source, requetes: [] };
      c.client = new Sens({ requete: true, borne: this.borneRequete });
      c.serveur = new Sens({ requete: false, borne: this.borneReponse, sansCorps: () => /^HEAD /.test(c.requetes[0]?.depart ?? "") });
      this.connexions.set(id, c);
    }
    return c;
  }

  /**
   * Octets copiés d'un sens d'une connexion.
   * @param {string} id
   * @param {"client"|"serveur"} sens
   * @param {Uint8Array} octets
   * @param {string} source adresse source du flux (l'hôte)
   */
  octets(id, sens, octets, source) {
    const c = this._connexion(id, source);
    if (sens === "client") c.client.ajouter(octets, (m) => c.requetes.push(m));
    else c.serveur.ajouter(octets, (m) => this._apparier(c, m));
  }

  _apparier(c, rep) {
    const req = c.requetes.shift();
    if (!req) return;
    const [methode, cible] = req.depart.split(" ");
    this.remettre({
      version: 0,
      source: c.source,
      t_requete: iso(req.fin),
      t_reponse: iso(rep.fin),
      request: { method: methode, target: cible, headers: req.entetes, body: Buffer.concat(req.morceaux).toString("base64") },
      response: { status: rep.statut, headers: rep.entetes, body: Buffer.concat(rep.morceaux).toString("base64"), body_length: rep.total, complete: rep.complet === true },
    });
  }

  /** Fin de la connexion copiée : réponse en cours close, requêtes sans réponse remises seules. */
  fin(id) {
    const c = this.connexions.get(id);
    if (!c) return;
    this.connexions.delete(id);
    c.serveur.fermer((m) => this._apparier(c, m));
    for (const req of c.requetes.splice(0)) {
      const [methode, cible] = req.depart.split(" ");
      this.remettre({ version: 0, source: c.source, t_requete: iso(req.fin), t_reponse: null, request: { method: methode, target: cible, headers: req.entetes, body: Buffer.concat(req.morceaux).toString("base64") }, response: null });
    }
  }
}

/** Délai de la preuve d'identité de l'adaptateur sur la prise du démon. */
const DELAI_PREUVE_MS = 10000;

/**
 * Preuve d'identité de l'adaptateur sur la prise du démon (EX-5.6, EX-4.39) :
 * lit le défi, crée en exclusion le fichier de preuve dans le répertoire de
 * la prise, envoie la preuve et attend `acceptee` ; sinon erreur
 * `preuve_refusee`.
 * @param {net.Socket} versDemon
 * @param {string} socket chemin de la prise
 */
async function prouverIdentite(versDemon, socket) {
  let fichier = null;
  try {
    await new Promise((res, rej) => {
      let tampon = "";
      const delai = setTimeout(() => rej(new Error("délai de la preuve dépassé")), DELAI_PREUVE_MS);
      delai.unref?.();
      const fin = (e) => {
        clearTimeout(delai);
        versDemon.removeListener("data", surDonnees);
        versDemon.removeListener("close", surFermeture);
        if (e) rej(e);
        else res();
      };
      const surFermeture = () => fin(new Error("prise fermée par le démon pendant la preuve"));
      const surDonnees = (d) => {
        tampon += d.toString("utf8");
        let k;
        while ((k = tampon.indexOf("\n")) >= 0) {
          const l = tampon.slice(0, k);
          tampon = tampon.slice(k + 1);
          let m = null;
          try {
            m = JSON.parse(l);
          } catch {
            return fin(new Error("ligne illisible pendant la preuve"));
          }
          if (fichier === null && typeof m?.noortrace_defi === "string" && /^[0-9a-f]{32}$/.test(m.noortrace_defi)) {
            fichier = path.join(path.dirname(socket), PREFIXE_DEFI + m.noortrace_defi);
            fs.closeSync(fs.openSync(fichier, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600));
            versDemon.write(`${JSON.stringify({ noortrace_preuve: m.noortrace_defi })}\n`);
          } else if (fichier !== null && m?.noortrace_identite === "acceptee") return fin(null);
          else return fin(new Error("réponse inattendue pendant la preuve"));
        }
      };
      versDemon.on("data", surDonnees);
      versDemon.on("close", surFermeture);
    });
  } catch (e) {
    if (fichier !== null) fs.rmSync(fichier, { force: true });
    versDemon.destroy();
    throw Object.assign(new Error(`preuve d'identité refusée par le démon (${e.message})`), { code: "preuve_refusee" });
  }
}

/**
 * Processus de l'adaptateur : lit la copie en trames sur `ecoute` et remet
 * les couples à la prise du démon, dans l'ordre.
 *
 * Étape 8 (CT-2 EX-5.6, EX-18.1) : `ecoute` vaut par défaut la boucle locale
 * (`MIROIR_ECOUTE_DEFAUT`) ; une adresse hors de la boucle locale exige une
 * authentification de la source de la copie (`tls` avec `ca`, ou `sources`),
 * sinon `ecoute_non_authentifiee` avant toute connexion. Une connexion de
 * copie dont l'adresse est hors de `sources`, ou sans certificat client de
 * l'autorité `tls.ca`, est fermée avant toute lecture. `preuve` : la prise du
 * démon exige la preuve d'identité (`model.mirror.peer_user`). Un chemin de
 * prise du démon de plus de `CHEMIN_PRISE_MAX_OCTETS` octets est refusé avant
 * toute connexion (`chemin_prise_trop_long`, complément du 2026-11-16).
 * @param {{socket: string, ecoute?: string, sources?: string[]|null, tls?: {cert: Buffer, key: Buffer, ca?: Buffer|null}|null,
 *   preuve?: boolean, sortie?: NodeJS.WritableStream, surPerte?: (x: object) => void}} o
 * @returns {Promise<{serveur: net.Server, perte: Promise<object>, perdue: () => boolean, arreter: () => Promise<void>}>}
 */
export async function lancerAdaptateur(o) {
  const ecoute = o.ecoute ?? MIROIR_ECOUTE_DEFAUT;
  const sources = Array.isArray(o.sources) ? o.sources : [];
  const optionsTls = o.tls ?? null;
  if (!ecouteLocaleModele(ecoute) && !copieAuthentifiee({ tls: optionsTls, sources })) {
    throw Object.assign(new Error(`écoute de la copie ${ecoute} hors de la boucle locale sans authentification de la source (certificat client ou liste de sources ; CT-2 EX-5.6)`), { code: "ecoute_non_authentifiee" });
  }
  // EX-18.1, EX-6.10 (complément du 2026-11-16) : un chemin plus long serait tronqué et joindrait une autre prise.
  const regle = regleCheminPrise(o.socket);
  if (regle) throw Object.assign(new Error(`prise du démon ${o.socket} : ${regle}`), { code: "chemin_prise_trop_long" });
  const listeSources = sources.length ? listeAdresses(sources) : null;
  const versDemon = net.connect(o.socket);
  await new Promise((res, rej) => {
    versDemon.once("connect", res);
    versDemon.once("error", rej);
  });
  versDemon.on("error", () => {});
  if (o.preuve) await prouverIdentite(versDemon, o.socket);
  versDemon.on("data", () => {});
  // Étape 8 (CT-2 EX-5.6) : la prise du démon fermée (redémarrage, panne) est
  // une perte dite et rendue (`perte`, `surPerte`) ; l'adaptateur n'écrit plus
  // dans le vide : il refuse la copie (`arreter`) et le processus s'arrête avec un code non nul.
  let perdue = false;
  let signalerPerte;
  const perte = new Promise((r) => (signalerPerte = r));
  versDemon.on("close", () => {
    if (perdue) return;
    perdue = true;
    o.sortie?.write("noortrace-miroir: prise du demon fermee, capture arretee\n");
    signalerPerte({ raison: "prise_demon_fermee" });
    o.surPerte?.({ raison: "prise_demon_fermee" });
  });
  const adaptateur = new AdaptateurMiroir({ remettre: (c) => { if (!perdue && !versDemon.destroyed) versDemon.write(`${JSON.stringify(c)}\n`); } });
  const copies = new Set();
  const refuser = (s, motif) => {
    o.sortie?.write(`noortrace-miroir: connexion de copie refusee (${s.remoteAddress ?? "?"}, ${motif})\n`);
    s.destroy();
  };
  // Liste fermée de sources : vérifiée sur la connexion brute, avant la poignée de main TLS et toute lecture.
  const sourceAdmise = (s) => listeSources === null || adresseDans(listeSources, s.remoteAddress);
  const surCopie = (s) => {
    if (!optionsTls && !sourceAdmise(s)) return refuser(s, "source");
    let tampon = Buffer.alloc(0);
    let trame = null;
    copies.add(s);
    s.on("close", () => copies.delete(s));
    s.on("error", () => {});
    s.on("data", (d) => {
      tampon = tampon.length ? Buffer.concat([tampon, d]) : d;
      for (;;) {
        if (!trame) {
          const k = tampon.indexOf(10);
          if (k < 0) {
            if (tampon.length > LIGNE_MAX) s.destroy();
            return;
          }
          try {
            trame = JSON.parse(tampon.subarray(0, k).toString("utf8"));
          } catch {
            s.destroy();
            return;
          }
          tampon = tampon.subarray(k + 1);
          // Longueur de trame bornée (CT-2 EX-5.6) : une trame qui annonce des gigaoctets n'est pas accumulée.
          if (!Number.isSafeInteger(trame.longueur) || trame.longueur < 0 || trame.longueur > MIROIR_TRAME_MAX_OCTETS || typeof trame.connexion !== "string") {
            s.destroy();
            return;
          }
        }
        if (tampon.length < trame.longueur) return;
        const corps = tampon.subarray(0, trame.longueur);
        tampon = tampon.subarray(trame.longueur);
        if (trame.sens === "fin") adaptateur.fin(trame.connexion);
        else if (trame.sens === "client" || trame.sens === "serveur") adaptateur.octets(trame.connexion, trame.sens, corps, trame.source ?? null);
        trame = null;
      }
    });
  };
  let serveur;
  if (optionsTls) {
    // Certificat client exigé quand l'autorité est donnée : la poignée de main échoue sans lui (EX-5.6).
    serveur = tls.createServer({ cert: optionsTls.cert, key: optionsTls.key, ca: optionsTls.ca ?? undefined, requestCert: Boolean(optionsTls.ca), rejectUnauthorized: Boolean(optionsTls.ca), minVersion: "TLSv1.2" }, surCopie);
    serveur.on("connection", (s) => {
      if (!sourceAdmise(s)) refuser(s, "source");
    });
    serveur.on("tlsClientError", (e, s) => o.sortie?.write(`noortrace-miroir: connexion de copie refusee (${s?.remoteAddress ?? "?"}, tls : ${e?.code ?? "erreur"})\n`));
  } else serveur = net.createServer(surCopie);
  const [h, p] = ecoute.split(/:(?=[0-9]+$)/);
  await new Promise((res) => serveur.listen(Number(p), h, res));
  o.sortie?.write(`noortrace-miroir: copie ecoutee sur ${serveur.address().address}:${serveur.address().port}\n`);
  const arreter = async () => {
    for (const c of copies) c.destroy();
    await new Promise((r) => serveur.close(() => r()));
    versDemon.end();
  };
  perte.then(() => arreter().catch(() => {}));
  return { serveur, perte, perdue: () => perdue, arreter };
}
