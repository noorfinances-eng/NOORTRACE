// Mode ICAP du frontal modèle (CT-2 §5.1.2, EX-5.3 à EX-5.5, EX-5.8,
// EX-14.12 ; RFC 3507) : le démon est un serveur ICAP qui expose deux
// services, `icap://<hôte>:1344/noortrace/reqmod` et `/noortrace/respmod`,
// et ICAPS (`model.icap.tls_listen`). Le mandataire du client, qui déchiffre
// le trafic, lui soumet la requête (REQMOD) puis la réponse (RESPMOD) de
// chaque échange de modèle.
//
// - OPTIONS : `Methods`, `ISTag`, `Encapsulated: null-body=0`,
//   `Options-TTL`, aucun `Preview` annoncé ; toute réponse porte `ISTag`.
// - REQMOD : en-têtes `X-Noortrace-*` retirés, connexion d'hôte par
//   l'adresse que le mandataire transmet (EX-5.8), pièces « requête » et
//   « prompt système » durables, puis requête modifiée (`200`) augmentée de
//   `X-Noortrace-Exchange: <i>.<m>` (128 bits aléatoires, 128 premiers bits
//   d'un HMAC-SHA-256 sous une clé éphémère) ; jamais `204`. Blocage, réponse
//   HTTP encapsulée et aucun événement : requête refusée par EX-5.7, mode
//   dégradé bloquant (14.2, colonne M), et les cas de la lecture 76.
// - RESPMOD : `100 Continue` à un Preview ; réponse rendue inchangée,
//   morceau par morceau, au fil de la réception (jamais `204`), analysée en
//   parallèle ; échange retrouvé par `X-Noortrace-Exchange` dont le MAC
//   vérifie, à défaut par (méthode, URI, en-têtes, instant), sinon pièce
//   « requête » `{"noortrace_requete_inconnue": true}`.
//
// Clients ICAP admis : mTLS d'ICAPS (`client_ca`) ou adresses sources
// (`allowed_sources`) ; un client refusé reçoit `403` (EX-5.3).

import net from "node:net";
import tls from "node:tls";
import fs from "node:fs";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { VERSION_ENREGISTREUR } from "../coeur.mjs";
import { normaliserCible, trouverRoute, reponseRefus, listeAdresses, adresseDans, hotePourAdresse, declarationsFournisseur, refusEnFlux, examinerRequeteGemini } from "./formats.mjs";
import { analyserCorpsJson } from "./extraction.mjs";
import { MoteurEchanges } from "./echange.mjs";

/** Chemins des deux services (EX-5.3). */
export const SERVICE_REQMOD = "/noortrace/reqmod";
export const SERVICE_RESPMOD = "/noortrace/respmod";
/** Étiquette de service (RFC 3507 §4.7), entre guillemets. */
export const ISTAG = `"noortrace-${VERSION_ENREGISTREUR}"`;
const MOTIF_ECHANGE = /^([0-9a-f]{32})\.([0-9a-f]{32})$/;
const TETE_MAX = 65536;
const RAISONS_ICAP = { 200: "OK", 100: "Continue", 400: "Bad Request", 403: "Forbidden", 404: "ICAP Service not found", 405: "Method not allowed for service", 501: "Method not implemented", 505: "ICAP Version not supported" };

/** Erreur de lecture d'un message ICAP : réponse `400`, connexion fermée. */
class ErreurIcap extends Error {
  constructor(statut, raison) {
    super(raison);
    this.statut = statut;
    this.raison = raison;
  }
}

/**
 * Lecteur d'octets d'une prise, en tirage : lignes, blocs d'en-têtes, nombre
 * exact d'octets, avec contre-pression.
 */
export class LecteurOctets {
  constructor(socket) {
    this.socket = socket;
    this.tampon = Buffer.alloc(0);
    this.fini = false;
    this.attente = null;
    socket.on("data", (d) => {
      this.tampon = this.tampon.length ? Buffer.concat([this.tampon, d]) : d;
      if (this.tampon.length > 4 * TETE_MAX) socket.pause();
      this._reveiller();
    });
    const fin = () => {
      this.fini = true;
      this._reveiller();
    };
    socket.on("end", fin);
    socket.on("close", fin);
    socket.on("error", fin);
  }

  _reveiller() {
    const a = this.attente;
    this.attente = null;
    a?.();
  }

  async _attendre() {
    if (this.fini) return false;
    this.socket.resume();
    await new Promise((r) => (this.attente = r));
    return true;
  }

  _prendre(n) {
    const x = this.tampon.subarray(0, n);
    this.tampon = this.tampon.subarray(n);
    if (this.tampon.length < 2 * TETE_MAX) this.socket.resume();
    return x;
  }

  /** Octets jusqu'au séparateur exclu (séparateur consommé), null à la fin, erreur au-delà de max. */
  async jusqua(sep, max) {
    for (;;) {
      const k = this.tampon.indexOf(sep);
      if (k >= 0) {
        if (k > max) throw new ErreurIcap(400, "trop_long");
        const x = Buffer.from(this._prendre(k));
        this._prendre(sep.length);
        return x;
      }
      if (this.tampon.length > max) throw new ErreurIcap(400, "trop_long");
      if (!(await this._attendre())) {
        if (this.tampon.length) throw new ErreurIcap(400, "tronque");
        return null;
      }
    }
  }

  /** Exactement n octets. */
  async octets(n) {
    while (this.tampon.length < n) if (!(await this._attendre())) throw new ErreurIcap(400, "tronque");
    return Buffer.from(this._prendre(n));
  }

  /** Les octets disponibles (au moins un), au plus n. */
  async morceau(n) {
    while (!this.tampon.length) if (!(await this._attendre())) throw new ErreurIcap(400, "tronque");
    return Buffer.from(this._prendre(Math.min(n, this.tampon.length)));
  }
}

/** En-têtes d'un bloc (`Nom: valeur` par ligne), noms en minuscules pour la lecture, lignes gardées pour la recopie. */
export function lireEntetes(lignes) {
  const liste = [];
  const parNom = {};
  for (const l of lignes) {
    const k = l.indexOf(":");
    if (k <= 0 || /[\s]/.test(l.slice(0, k))) throw new ErreurIcap(400, "entete_mal_forme");
    const nom = l.slice(0, k);
    const valeur = l.slice(k + 1).trim();
    liste.push([nom, valeur]);
    const n = nom.toLowerCase();
    parNom[n] = n in parNom ? `${parNom[n]}, ${valeur}` : valeur;
  }
  return { liste, parNom };
}

/**
 * Valeur de l'en-tête `Encapsulated` (RFC 3507 §4.4.1) : entités dans
 * l'ordre, décalages croissants, la dernière étant le corps.
 * @param {string|undefined} v
 * @returns {{nom: string, decalage: number}[]}
 */
export function lireEncapsulated(v) {
  if (typeof v !== "string") throw new ErreurIcap(400, "encapsulated_absent");
  const entites = v.split(",").map((x) => x.trim()).map((x) => {
    const m = /^(req-hdr|res-hdr|req-body|res-body|null-body|opt-body)=([0-9]{1,9})$/.exec(x);
    if (!m) throw new ErreurIcap(400, "encapsulated_mal_forme");
    return { nom: m[1], decalage: Number(m[2]) };
  });
  for (let k = 1; k < entites.length; k++) if (entites[k].decalage < entites[k - 1].decalage) throw new ErreurIcap(400, "encapsulated_mal_forme");
  const dernier = entites[entites.length - 1].nom;
  if (!/-body$/.test(dernier)) throw new ErreurIcap(400, "encapsulated_mal_forme");
  if (entites.slice(0, -1).some((e) => /-body$/.test(e.nom))) throw new ErreurIcap(400, "encapsulated_mal_forme");
  return entites;
}

/** Message HTTP encapsulé : ligne de départ et en-têtes. */
function lireMessageHttp(octets) {
  const texte = octets.toString("latin1");
  if (!texte.endsWith("\r\n\r\n")) throw new ErreurIcap(400, "entete_http_mal_forme");
  const lignes = texte.slice(0, -4).split("\r\n");
  const depart = lignes.shift();
  return { depart, ...lireEntetes(lignes) };
}

function ecrireMessageHttp(depart, liste) {
  return Buffer.from(`${depart}\r\n${liste.map(([n, v]) => `${n}: ${v}\r\n`).join("")}\r\n`, "latin1");
}

const morceauChunk = (o) => Buffer.concat([Buffer.from(`${o.length.toString(16)}\r\n`), o, Buffer.from("\r\n")]);

/** Corps encapsulé en codage `chunked` (RFC 3507 §4.4.1) : morceaux remis un à un ; `ieof` d'un Preview. */
async function* lireCorpsChunked(lecteur, borneLigne = 1024) {
  for (;;) {
    const ligne = await lecteur.jusqua("\r\n", borneLigne);
    if (ligne === null) throw new ErreurIcap(400, "tronque");
    const [taille, ...ext] = ligne.toString("latin1").split(";").map((x) => x.trim());
    if (!/^[0-9a-fA-F]{1,8}$/.test(taille)) throw new ErreurIcap(400, "chunk_mal_forme");
    const n = parseInt(taille, 16);
    if (n === 0) {
      // Fin du corps (ou du Preview) : remorque éventuelle jusqu'à la ligne vide.
      for (;;) {
        const t = await lecteur.jusqua("\r\n", borneLigne);
        if (t === null) throw new ErreurIcap(400, "tronque");
        if (t.length === 0) break;
      }
      yield { fin: true, ieof: ext.includes("ieof") };
      return;
    }
    const donnees = await lecteur.octets(n);
    const crlf = await lecteur.octets(2);
    if (crlf.toString("latin1") !== "\r\n") throw new ErreurIcap(400, "chunk_mal_forme");
    yield { donnees };
  }
}

/** Cible d'une requête HTTP encapsulée : chemin et chaîne de requête, d'une forme absolue ou d'origine. */
function cibleDe(cible) {
  if (/^https?:\/\//i.test(cible)) {
    try {
      const u = new URL(cible);
      return `${u.pathname}${u.search}`;
    } catch {
      return null;
    }
  }
  return cible;
}

export class ServeurIcap {
  /**
   * @param {object} o
   * @param {import("../coeur.mjs").Coeur} o.coeur
   * @param {MoteurEchanges} [o.moteur]
   * @param {object} [o.registre] registre de corrélation (5.6)
   * @param {object} [o.config]
   * @param {object} [o.redacteur]
   * @param {object} [o.observateur]
   */
  constructor(o) {
    this.coeur = o.coeur;
    this.moteur = o.moteur ?? new MoteurEchanges({ coeur: o.coeur, redacteur: o.redacteur, registre: o.registre, config: o.config, observateur: o.observateur });
    this.cle = randomBytes(32);
    /** Échanges dont le REQMOD a été servi, en attente de leur RESPMOD : i → entrée. */
    this.enAttente = new Map();
    this.serveurs = [];
    this.prises = new Set();
    this.ferme = false;
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

  /** Écoute sur `model.icap.listen` (ICAP) et `model.icap.tls_listen` (ICAPS, certificat de `model.tls`). */
  async ecouter() {
    const ic = this.config.model.icap;
    const ecouter = (serveur, adresse) =>
      new Promise((res, rej) => {
        const [h, p] = adresse.split(/:(?=[0-9]+$)/);
        serveur.once("error", rej);
        serveur.listen(Number(p), h.replace(/^\[|\]$/g, ""), () => res(serveur));
      });
    const s = net.createServer((x) => this._connexion(x, false));
    this.serveurs.push(await ecouter(s, ic.listen));
    if (ic.tls_listen) {
      const t = this.config.model.tls;
      // Plancher TLS 1.2, comme la passerelle (lecture 74).
      const opts = { cert: fs.readFileSync(t.cert_file), key: fs.readFileSync(t.key_file), minVersion: "TLSv1.2" };
      if (ic.client_ca) Object.assign(opts, { ca: fs.readFileSync(ic.client_ca), requestCert: true, rejectUnauthorized: true });
      const st = tls.createServer(opts, (x) => this._connexion(x, true));
      st.on("tlsClientError", (e) => this.journal.consigner("warning", "frontal_modele", "auth_failed", { transport: "icaps", reason: e?.code ?? "tls" }));
      this.serveurs.push(await ecouter(st, ic.tls_listen));
    }
  }

  /** Adresses d'écoute : `[icap, icaps?]`. */
  adresses() {
    return this.serveurs.map((s) => s.address());
  }

  async arreter() {
    this.ferme = true;
    for (const s of this.serveurs) s.close();
    const limite = Date.now() + (this.config.mcp?.drain_timeout_ms ?? 10000);
    while (this.prises.size && Date.now() < limite) await new Promise((r) => setTimeout(r, 20));
    for (const p of this.prises) p.destroy();
    for (const e of this.enAttente.values()) clearTimeout(e.minuteur);
  }

  _ecrireReponse(socket, statut, entetes = [], suite = null) {
    const lignes = [`ICAP/1.0 ${statut} ${RAISONS_ICAP[statut] ?? "Error"}`, `ISTag: ${ISTAG}`, ...entetes.map(([n, v]) => `${n}: ${v}`)];
    socket.write(`${lignes.join("\r\n")}\r\n\r\n`);
    if (suite) socket.write(suite);
  }

  _erreur(socket, statut, raison) {
    this.journal.consigner("warning", "frontal_modele", "icap_request_refused", { status: statut, reason: raison });
    this._ecrireReponse(socket, statut, [["Encapsulated", "null-body=0"], ["Connection", "close"]]);
    socket.end();
  }

  async _connexion(socket, chiffre) {
    this.prises.add(socket);
    socket.on("close", () => this.prises.delete(socket));
    socket.on("error", () => {});
    const ic = this.config.model.icap;
    // Authentification du client ICAP (EX-5.3) : mTLS (ICAPS) ou adresse source admise.
    const sources = ic.allowed_sources ?? [];
    const admis = chiffre ? (ic.client_ca ? socket.authorized === true : sources.length === 0 || adresseDans(listeAdresses(sources), socket.remoteAddress)) : sources.length === 0 ? ic.client_ca === null : adresseDans(listeAdresses(sources), socket.remoteAddress);
    if (!admis) {
      this.journal.consigner("warning", "frontal_modele", "auth_failed", { transport: chiffre ? "icaps" : "icap", reason: "client_icap_refuse" });
      this._ecrireReponse(socket, 403, [["Encapsulated", "null-body=0"], ["Connection", "close"]]);
      socket.end();
      return;
    }
    const lecteur = new LecteurOctets(socket);
    try {
      while (!socket.destroyed) {
        const tete = await lecteur.jusqua("\r\n\r\n", TETE_MAX);
        if (tete === null) break;
        const lignes = tete.toString("latin1").split("\r\n");
        const m = /^([A-Z]+) (\S+) (ICAP\/\d\.\d)$/.exec(lignes.shift());
        if (!m) throw new ErreurIcap(400, "ligne_de_requete");
        if (m[3] !== "ICAP/1.0") throw new ErreurIcap(505, "version");
        const ent = lireEntetes(lignes);
        let chemin;
        try {
          chemin = new URL(m[2]).pathname;
        } catch {
          throw new ErreurIcap(400, "uri");
        }
        const service = chemin === SERVICE_REQMOD ? "REQMOD" : chemin === SERVICE_RESPMOD ? "RESPMOD" : null;
        if (!["OPTIONS", "REQMOD", "RESPMOD"].includes(m[1])) throw new ErreurIcap(501, "methode");
        if (!service) throw new ErreurIcap(404, "service");
        if (m[1] === "OPTIONS") {
          await this._lireEncapsule(lecteur, ent.parNom, { optionnel: true });
          this._ecrireReponse(socket, 200, [["Methods", service], ["Service", `noortrace-enregistreur/${VERSION_ENREGISTREUR}`], ["Encapsulated", "null-body=0"], ["Options-TTL", "3600"], ["Max-Connections", "1000"]]);
          continue;
        }
        if (m[1] !== service) throw new ErreurIcap(405, "methode_du_service");
        const garder = await (m[1] === "REQMOD" ? this._reqmod(socket, lecteur, ent, chiffre) : this._respmod(socket, lecteur, ent));
        if (garder === false || /close/i.test(ent.parNom.connection ?? "")) {
          socket.end();
          break;
        }
      }
    } catch (e) {
      if (e instanceof ErreurIcap && !socket.destroyed) {
        if (e.raison !== "tronque") this._erreur(socket, e.statut, e.raison);
        else socket.destroy();
      } else if (!(e instanceof ErreurIcap)) {
        this.journal.consigner("error", "frontal_modele", "model_internal_error", { message: String(e?.message ?? e).slice(0, 200), mode: "icap" });
        socket.destroy();
      }
    }
  }

  /** En-têtes HTTP encapsulés (sections avant le corps) ; le corps reste à lire. */
  async _lireEncapsule(lecteur, parNom, o = {}) {
    if (o.optionnel && parNom.encapsulated === undefined) return { entites: [], sections: {} };
    const entites = lireEncapsulated(parNom.encapsulated);
    const corps = entites[entites.length - 1];
    const brut = corps.decalage ? await lecteur.octets(corps.decalage) : Buffer.alloc(0);
    const sections = {};
    for (let k = 0; k < entites.length - 1; k++) sections[entites[k].nom] = lireMessageHttp(brut.subarray(entites[k].decalage, entites[k + 1].decalage));
    return { entites, sections, corps: corps.nom };
  }

  /** Corps entier (REQMOD), Preview compris (100 Continue), dans une borne. */
  async _corpsEntier(socket, lecteur, parNom, borne) {
    const morceaux = [];
    let n = 0;
    let depasse = false;
    const preview = parNom.preview !== undefined;
    for await (const x of lireCorpsChunked(lecteur)) {
      if (x.fin) {
        if (preview && !x.ieof) {
          this._ecrireReponse(socket, 100);
          for await (const y of lireCorpsChunked(lecteur)) {
            if (y.fin) break;
            n += y.donnees.length;
            if (n > borne) depasse = true;
            else morceaux.push(y.donnees);
          }
        }
        break;
      }
      n += x.donnees.length;
      if (n > borne) depasse = true;
      else morceaux.push(x.donnees);
    }
    return { octets: Buffer.concat(morceaux), longueur: n, depasse };
  }

  _identifiant() {
    const i = randomBytes(16).toString("hex");
    return { i, valeur: `${i}.${createHmac("sha256", this.cle).update(i).digest("hex").slice(0, 32)}` };
  }

  _verifierIdentifiant(v) {
    const m = typeof v === "string" ? MOTIF_ECHANGE.exec(v.trim()) : null;
    if (!m) return null;
    const attendu = Buffer.from(createHmac("sha256", this.cle).update(m[1]).digest("hex").slice(0, 32));
    return timingSafeEqual(attendu, Buffer.from(m[2])) ? m[1] : null;
  }

  // ---------------------------------------------------------------- REQMOD (EX-5.4)

  _bloquer(socket, format, cas, enFlux) {
    // Réponse HTTP encapsulée au statut et au corps d'EX-5.7 ou de 14.2 ; aucun événement.
    const r = reponseRefus(format, cas, { enFlux });
    const tete = ecrireMessageHttp(`HTTP/1.1 ${r.statut} ${http_raison(r.statut)}`, [["Content-Type", r.contentType], ["Content-Length", String(Buffer.byteLength(r.corps))]]);
    this._ecrireReponse(socket, 200, [["Encapsulated", `res-hdr=0, res-body=${tete.length}`]], Buffer.concat([tete, morceauChunk(Buffer.from(r.corps)), Buffer.from("0\r\n\r\n")]));
    this.moteur.observateur.refus?.({ raison: cas, statut: r.statut, contentType: r.contentType, corps: r.corps, mode: "icap" });
  }

  _requeteInchangee(socket, req, liste, corps, encapsule) {
    const tete = ecrireMessageHttp(req.depart, liste);
    if (encapsule === "null-body") {
      this._ecrireReponse(socket, 200, [["Encapsulated", `req-hdr=0, null-body=${tete.length}`]], tete);
      return;
    }
    this._ecrireReponse(socket, 200, [["Encapsulated", `req-hdr=0, req-body=${tete.length}`]], Buffer.concat([tete, corps.length ? morceauChunk(corps) : Buffer.alloc(0), Buffer.from("0\r\n\r\n")]));
  }

  async _reqmod(socket, lecteur, ent) {
    const t_recu = this.moteur.monotone();
    const cfg = this.config;
    const enc = await this._lireEncapsule(lecteur, ent.parNom);
    const req = enc.sections["req-hdr"];
    if (!req) throw new ErreurIcap(400, "req_hdr_absent");
    const corps = enc.corps === "req-body" ? await this._corpsEntier(socket, lecteur, ent.parNom, cfg.limits.model_request_max_bytes) : { octets: Buffer.alloc(0), longueur: 0, depasse: false };
    const ld = /^(\S+) (\S+) (HTTP\/\d\.\d)$/.exec(req.depart);
    if (!ld) throw new ErreurIcap(400, "requete_http_mal_formee");
    // En-têtes X-Noortrace-* retirés (EX-5.4), lus d'abord pour la délégation (EX-5.8).
    const liste = req.liste.filter(([n]) => !n.toLowerCase().startsWith("x-noortrace-"));
    const cibleBrute = cibleDe(ld[2]);
    const cible = cibleBrute === null ? { ok: false } : normaliserCible(cibleBrute);
    const trouve = cible.ok ? trouverRoute(cfg.policy.model?.routes ?? [], ld[1], cible.chemin) : null;
    if (!trouve || trouve.genre !== "echange") {
      // Hors des échanges capturés : rendue sans X-Noortrace-*, sans identifiant (lecture 75).
      this.journal.consigner("info", "frontal_modele", "model_route_not_found", { method: ld[1], path_length: Buffer.byteLength(cibleBrute ?? ""), mode: "icap" });
      this._requeteInchangee(socket, req, liste, corps.octets, enc.corps);
      return true;
    }
    const route = trouve.route;
    const enFlux = route.format === "gemini" && refusEnFlux(trouve.methodeGemini, cible.requete);
    const adresse = cfg.model.icap.client_address_header ? (ent.parNom[cfg.model.icap.client_address_header.toLowerCase()] ?? null) : null;
    const hote = hotePourAdresse(cfg, adresse);
    if (!hote) {
      this.journal.consigner("warning", "frontal_modele", "auth_failed", { transport: "icap", reason: "hote_inconnu", status: 401, route: route.path });
      this._bloquer(socket, route.format, "hote_inconnu", enFlux);
      return !corps.depasse;
    }
    const quotas = this.moteur.quotas(hote);
    quotas.recevoir(this.moteur.monotone(), corps.longueur);
    const refuser = (cas, donnees = {}) => {
      this.journal.consigner("warning", "frontal_modele", "model_request_refused", { route: route.path, raison: cas, mode: "icap", ...donnees }, { host: hote.id });
      this._bloquer(socket, route.format, cas, enFlux);
    };
    if (corps.depasse) {
      refuser("taille", { length: corps.longueur });
      return false;
    }
    // Chaîne de requête d'une route gemini (EX-5.29) : mêmes refus qu'en passerelle (lecture 76).
    if (route.format === "gemini") {
      const q = examinerRequeteGemini(trouve.methodeGemini, cible.requete);
      if (!q.ok) {
        refuser(q.raison, { params: q.noms });
        return true;
      }
    }
    const ce = req.parNom["content-encoding"];
    if (ce !== undefined && ce.trim().toLowerCase() !== "identity") {
      refuser("content_encoding", { length: corps.longueur, content_type: req.parNom["content-type"] ?? null });
      return true;
    }
    const analyse = analyserCorpsJson(new Uint8Array(corps.octets), this.moteur.bornes);
    if (!analyse.ok) {
      refuser("corps_non_analysable", { length: corps.longueur, content_type: req.parNom["content-type"] ?? null });
      return true;
    }
    if (route.format === "gemini") {
      // Serveurs MCP et contenu en cache déclarés au fournisseur (EX-5.32) : refusés ou consignés selon la route (lecture 76).
      const d = declarationsFournisseur(analyse.valeur);
      if (d.mcp > 0) {
        if (route.provider_mcp !== "relayer") {
          refuser("serveurs_mcp_fournisseur", { entries: d.mcp });
          return true;
        }
        this.journal.consigner("warning", "frontal_modele", "provider_mcp_bypass", { route: route.path, entries: d.mcp, mode: "icap" }, { host: hote.id });
      }
      if (d.cache) {
        if (route.provider_cache !== "relayer") {
          refuser("cache_fournisseur");
          return true;
        }
        this.journal.consigner("warning", "frontal_modele", "provider_cache_reference", { route: route.path, mode: "icap" }, { host: hote.id });
      }
    }
    if (this.moteur.controlerQuota(hote, this.moteur.monotone(), { echange: true })) {
      this._bloquer(socket, route.format, "degrade", enFlux);
      return true;
    }
    const p = await this.moteur.preparer({ route, trouve, hote, entetes: req.parNom, valeur: analyse.valeur, t_recu, mode: "icap" });
    if (p.refus) {
      this._bloquer(socket, route.format, p.refus, enFlux);
      return true;
    }
    const id = this._identifiant();
    const etat = p.etat;
    etat.cheminAmont = cibleBrute;
    const entree = { etat, methode: ld[1], cible: ld[2], entetes: liste, t: this.moteur.monotone() };
    // Une requête partie sans RESPMOD dans le délai du premier octet : échange en erreur (lecture 77).
    entree.minuteur = setTimeout(() => {
      if (this.enAttente.get(id.i) !== entree) return;
      this.enAttente.delete(id.i);
      this.moteur.sceller(etat, { genre: "delai", phase: "premier_octet", timeout_ms: cfg.model.first_byte_timeout_ms }).catch(() => {});
    }, cfg.model.first_byte_timeout_ms);
    entree.minuteur.unref?.();
    this.enAttente.set(id.i, entree);
    etat.t_envoi = this.moteur.monotone();
    this._requeteInchangee(socket, req, [...liste, ["X-Noortrace-Exchange", id.valeur]], corps.octets, enc.corps);
    return true;
  }

  // ---------------------------------------------------------------- RESPMOD (EX-5.5)

  /** Échange du REQMOD : identifiant dont le MAC vérifie, à défaut (méthode, URI, en-têtes, instant). */
  _retrouver(req) {
    if (!req) return null;
    const v = req.parNom["x-noortrace-exchange"];
    if (v !== undefined) {
      const i = this._verifierIdentifiant(v);
      if (i === null) this.journal.consigner("warning", "frontal_modele", "icap_exchange_refused", { reason: "mac" });
      const e = i === null ? undefined : this.enAttente.get(i);
      if (e) {
        this.enAttente.delete(i);
        return e;
      }
    }
    const ld = /^(\S+) (\S+) (HTTP\/\d\.\d)$/.exec(req.depart);
    if (!ld) return null;
    const cle = JSON.stringify(req.liste.filter(([n]) => !n.toLowerCase().startsWith("x-noortrace-")));
    let meilleur = null;
    for (const [i, e] of this.enAttente) {
      if (e.methode === ld[1] && e.cible === ld[2] && JSON.stringify(e.entetes.filter(([n]) => n.toLowerCase() !== "x-noortrace-exchange")) === cle) {
        if (!meilleur || e.t > meilleur[1].t) meilleur = [i, e];
      }
    }
    if (meilleur) {
      this.enAttente.delete(meilleur[0]);
      this.journal.consigner("info", "frontal_modele", "icap_correlation_heuristique", { route: meilleur[1].etat.route.path });
      return meilleur[1];
    }
    return null;
  }

  async _respmod(socket, lecteur, ent) {
    const cfg = this.config;
    const enc = await this._lireEncapsule(lecteur, ent.parNom);
    const req = enc.sections["req-hdr"] ?? null;
    const res = enc.sections["res-hdr"];
    if (!res) throw new ErreurIcap(400, "res_hdr_absent");
    const ls = /^(HTTP\/\d\.\d) ([0-9]{3})(?: .*)?$/.exec(res.depart);
    if (!ls) throw new ErreurIcap(400, "reponse_http_mal_formee");
    const preview = ent.parNom.preview !== undefined;
    let entree = this._retrouver(req);
    let etat = entree?.etat ?? null;
    if (entree) clearTimeout(entree.minuteur);
    if (!etat && req) {
      // RESPMOD sans REQMOD retrouvé : pièce « requête » inconnue (EX-5.4).
      const ld = /^(\S+) (\S+) (HTTP\/\d\.\d)$/.exec(req.depart);
      const c = ld ? cibleDe(ld[2]) : null;
      const n = c === null ? { ok: false } : normaliserCible(c);
      const trouve = n.ok ? trouverRoute(cfg.policy.model?.routes ?? [], ld[1], n.chemin) : null;
      const adresse = cfg.model.icap.client_address_header ? (ent.parNom[cfg.model.icap.client_address_header.toLowerCase()] ?? null) : null;
      const hote = hotePourAdresse(cfg, adresse);
      if (trouve?.genre === "echange" && hote) {
        etat = await this.moteur.preparerInconnue({ route: trouve.route, hote, mode: "icap", segment: trouve.segment ?? null, t_recu: this.moteur.monotone() });
        this.journal.consigner("warning", "frontal_modele", "icap_requete_inconnue", { route: trouve.route.path }, { host: hote.id });
      }
    }
    if (!etat) {
      this.journal.consigner("info", "frontal_modele", "icap_respmod_non_capture", { reason: req ? "route_ou_hote" : "req_hdr_absent" });
    }
    // Réponse rendue inchangée, morceau par morceau, au fil de la réception (jamais 204).
    const tete = ecrireMessageHttp(res.depart, res.liste);
    if (enc.corps === "null-body") {
      this._ecrireReponse(socket, 200, [["Encapsulated", `res-hdr=0, null-body=${tete.length}`]], tete);
      if (etat) {
        const capture = this.moteur.capture(etat, { statut: Number(ls[2]), entetes: res.parNom });
        await capture.terminer();
        this.moteur.sceller(etat, { genre: "reponse" }).catch(() => {});
      }
      return true;
    }
    const capture = etat ? this.moteur.capture(etat, { statut: Number(ls[2]), entetes: res.parNom }) : null;
    let entetesEnvoyes = false;
    const envoyerEntetes = () => {
      if (entetesEnvoyes) return;
      entetesEnvoyes = true;
      this._ecrireReponse(socket, 200, [["Encapsulated", `res-hdr=0, res-body=${tete.length}`]], tete);
    };
    // Sans Preview, la réponse commence aussitôt ; avec un Preview, après le 100 Continue.
    if (!preview) envoyerEntetes();
    let complet = false;
    // Morceaux d'un Preview, rendus après la décision de lire le reste (RFC 3507 §4.5).
    const retenus = [];
    const rendre = async (o) => {
      // Analysé avant d'être rendu au mandataire (5.6).
      capture?.ecrire(o);
      if (!socket.write(morceauChunk(o))) await new Promise((r) => socket.once("drain", r));
    };
    try {
      for await (const x of lireCorpsChunked(lecteur)) {
        if (x.fin) {
          if (preview && !x.ieof) this._ecrireReponse(socket, 100);
          envoyerEntetes();
          for (const o of retenus.splice(0)) await rendre(o);
          if (preview && !x.ieof) {
            for await (const y of lireCorpsChunked(lecteur)) {
              if (y.fin) break;
              await rendre(y.donnees);
            }
          }
          complet = true;
          break;
        }
        if (preview) retenus.push(x.donnees);
        else await rendre(x.donnees);
      }
    } catch (e) {
      // Le mandataire coupe au milieu du corps : forme incomplète (EX-5.13), échange scellé.
      if (capture) {
        await capture.terminer({ coupe: true });
        this.moteur.sceller(etat, { genre: "coupure" }).catch(() => {});
      }
      throw e;
    }
    envoyerEntetes();
    if (capture) await capture.terminer({ coupe: !complet });
    socket.write("0\r\n\r\n");
    if (etat) this.moteur.sceller(etat, { genre: "reponse" }).catch(() => {});
    return true;
  }
}

function http_raison(statut) {
  return { 400: "Bad Request", 401: "Unauthorized", 413: "Payload Too Large", 415: "Unsupported Media Type", 503: "Service Unavailable", 504: "Gateway Timeout" }[statut] ?? "Error";
}
