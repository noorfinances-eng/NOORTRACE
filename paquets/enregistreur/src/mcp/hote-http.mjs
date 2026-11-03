// Transport Streamable HTTP vers les hôtes (CT-2 §4.7.2, §4.8) : un seul
// chemin (`mcp.http.path`, `/mcp` par défaut), POST seulement en ère moderne
// (GET et DELETE : 405 ; `Mcp-Session-Id` et `Last-Event-ID` ignorés,
// EX-4.34) ; sessions de l'ère héritée (EX-4.37) ; `Origin` validée ;
// authentification sur toute connexion, locale comprise : jeton statique
// comparé en temps constant, ou jeton OAuth 2.1 d'audience l'URI canonique
// (EX-4.39) ; en-têtes MCP comparés au corps (EX-4.35) ; réponse JSON ou flux
// SSE sans tampon, `X-Accel-Buffering: no`, commentaire toutes les 15 s
// (EX-4.36). Aucun en-tête de l'hôte n'est relayé ni journalisé (EX-4.41).
// Les échecs d'authentification sont limités par identifiant de jeton
// présenté et par connexion (EX-18.3) ; les octets d'un corps sont comptés au
// quota de la connexion d'hôte dès leur lecture, corps refusé compris, et le
// quota est contrôlé avant toute analyse (4.4 pas 1, EX-4.47) ; le statut
// HTTP d'une erreur produite par le frontal lui est indiqué par le frontal,
// jamais lu dans le texte de la réponse (EX-4.35).

import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import { randomBytes, createPublicKey, verify as verifierSignature } from "node:crypto";
import { egauxTempsConstant } from "./hote-stdio.mjs";
import { analyserTexte, decoderUtf8Strict, membre, valeurDe } from "./json-texte.mjs";
import { reponseErreur, VERSION_MODERNE } from "./messages.mjs";
import { entetesParametres } from "./agregation.mjs";
import { LimiteurEchecs } from "../sdk/limiteur.mjs";

/** Sessions de l'ère héritée gardées au plus, par identité authentifiée et en tout (EX-4.37 ; lecture 159). */
export const SESSIONS_HERITEES_PAR_IDENTITE = 64;
export const SESSIONS_HERITEES_MAX = 4096;

/** Bornes de la lecture du JWKS (lecture 159). */
export const JWKS_DELAI_MS = 10000;
export const JWKS_TAILLE_MAX = 1048576;

const CLE_CONNEXION = Symbol("noortrace.mcp.connexion");

/**
 * Valeur d'un en-tête `Mcp-Param-*` reçu, sentinelle `=?base64?…?=` décodée
 * (EX-4.35) ; null pour une sentinelle illisible (base64 non canonique, texte
 * non UTF-8).
 * @param {string} h
 * @returns {string|null}
 */
export function decoderEnteteParametre(h) {
  const m = /^=\?base64\?([A-Za-z0-9+/]*={0,2})\?=$/.exec(h);
  if (!m) return h;
  const b = Buffer.from(m[1], "base64");
  if (b.toString("base64") !== m[1]) return null;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(b);
  } catch {
    return null;
  }
}

/** Valeur attendue d'un en-tête `Mcp-Param-*` : l'argument primitif en texte, ou null. */
function texteArgument(v) {
  return v === undefined || v === null || typeof v === "object" ? null : String(v);
}

/** Erreur d'authentification : statut HTTP 401 ou 403. */
export class ErreurAuthentification extends Error {
  constructor(statut, raison) {
    super(raison);
    this.statut = statut;
    this.raison = raison;
  }
}

function b64url(s) {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/**
 * Vérifie un jeton d'accès JWT (EX-4.39) : signature (RS256, ES256, EdDSA)
 * par une clé du JWKS, audience = URI canonique (RFC 8707), émetteur parmi
 * les serveurs d'autorisation, `exp` et `nbf`, portées requises.
 * @param {string} jeton
 * @param {{jwks: {keys: object[]}, resource: string, issuers: string[], scopes: string[], maintenant: number}} o
 * @returns {{sub: string}}
 * @throws {ErreurAuthentification}
 */
export function verifierJwt(jeton, o) {
  const parties = jeton.split(".");
  if (parties.length !== 3) throw new ErreurAuthentification(401, "jeton_mal_forme");
  let entete;
  let charge;
  try {
    entete = JSON.parse(b64url(parties[0]).toString("utf8"));
    charge = JSON.parse(b64url(parties[1]).toString("utf8"));
  } catch {
    throw new ErreurAuthentification(401, "jeton_mal_forme");
  }
  const algos = { RS256: "sha256", ES256: "sha256", EdDSA: null };
  if (!Object.hasOwn(algos, entete.alg)) throw new ErreurAuthentification(401, "algorithme");
  // L'algorithme est lié au type de la clé (RFC 8725 §3.1, lecture 162) : RS256 ↔ RSA,
  // ES256 ↔ EC P-256, EdDSA ↔ OKP Ed25519 ; une clé d'un autre type n'est
  // jamais essayée.
  const typeAdmis = { RS256: (k) => k.kty === "RSA", ES256: (k) => k.kty === "EC" && k.crv === "P-256", EdDSA: (k) => k.kty === "OKP" && k.crv === "Ed25519" }[entete.alg];
  const cles = (Array.isArray(o.jwks?.keys) ? o.jwks.keys : []).filter((k) => k && typeof k === "object" && (!entete.kid || k.kid === entete.kid) && typeAdmis(k) && (k.alg === undefined || k.alg === entete.alg));
  const donnees = Buffer.from(`${parties[0]}.${parties[1]}`);
  const sig = b64url(parties[2]);
  const valide = cles.some((jwk) => {
    try {
      const cle = createPublicKey({ key: jwk, format: "jwk" });
      return verifierSignature(algos[entete.alg], donnees, entete.alg === "ES256" ? { key: cle, dsaEncoding: "ieee-p1363" } : cle, sig);
    } catch {
      return false;
    }
  });
  if (!valide) throw new ErreurAuthentification(401, "signature");
  const s = Math.floor(o.maintenant / 1000);
  if (typeof charge.exp !== "number" || charge.exp <= s) throw new ErreurAuthentification(401, "expire");
  if (typeof charge.nbf === "number" && charge.nbf > s) throw new ErreurAuthentification(401, "pas_encore_valide");
  const aud = Array.isArray(charge.aud) ? charge.aud : [charge.aud];
  if (!aud.includes(o.resource)) throw new ErreurAuthentification(401, "audience");
  if (!o.issuers.includes(charge.iss)) throw new ErreurAuthentification(401, "emetteur");
  if (typeof charge.sub !== "string" || !charge.sub) throw new ErreurAuthentification(401, "sujet");
  const portees = typeof charge.scope === "string" ? charge.scope.split(" ") : [];
  if (!o.scopes.every((p) => portees.includes(p))) throw new ErreurAuthentification(403, "portee");
  return { sub: charge.sub };
}

/**
 * JWKS lu par HTTPS, gardé cinq minutes ; une seule lecture en vol, bornée
 * en durée et en taille (lecture 159).
 * @param {string} uri
 * @param {{requete?: Function, delaiMs?: number, tailleMax?: number}} [o] `requete` : `https.get` (essais : `http.get`)
 */
export function chargeurJwksHttps(uri, o = {}) {
  const requete = o.requete ?? https.get;
  const delaiMs = o.delaiMs ?? JWKS_DELAI_MS;
  const tailleMax = o.tailleMax ?? JWKS_TAILLE_MAX;
  let cache = null;
  let instant = 0;
  let enVol = null;
  const lire = () =>
    new Promise((res, rej) => {
      let fini = false;
      const finir = (e, v) => {
        if (fini) return;
        fini = true;
        clearTimeout(minuteur);
        if (e) {
          q.destroy();
          rej(e);
        } else res(v);
      };
      const q = requete(uri, (r) => {
        const m = [];
        let n = 0;
        r.on("data", (c) => {
          n += c.length;
          if (n > tailleMax) return finir(new Error(`JWKS : taille au-delà de ${tailleMax} octets`));
          m.push(c);
        });
        r.on("end", () => {
          try {
            finir(null, JSON.parse(Buffer.concat(m).toString("utf8")));
          } catch (e) {
            finir(e);
          }
        });
        r.on("error", (e) => finir(e));
      });
      q.on("error", (e) => finir(e));
      const minuteur = setTimeout(() => finir(new Error(`JWKS : délai de ${delaiMs} ms dépassé`)), delaiMs);
      minuteur.unref?.();
    });
  return () => {
    if (cache && Date.now() - instant < 300000) return Promise.resolve(cache);
    if (!enVol) {
      enVol = lire().then(
        (v) => {
          cache = v;
          instant = Date.now();
          enVol = null;
          return v;
        },
        (e) => {
          enVol = null;
          throw e;
        },
      );
    }
    return enVol;
  };
}

export class ServeurHttpMcp {
  /**
   * @param {{frontal: import("./frontal.mjs").FrontalMcp, jetons?: Map<string, Uint8Array>, chargerJwks?: () => Promise<object>}} p
   */
  constructor(p) {
    this.frontal = p.frontal;
    this.cfg = p.frontal.config.mcp.http;
    this.jetons = p.jetons ?? new Map();
    this.chargerJwks = p.chargerJwks ?? (this.cfg.oauth ? chargeurJwksHttps(this.cfg.oauth.jwks_uri) : null);
    /** Sessions modernes par identité, héritées par Mcp-Session-Id. */
    this.parIdentite = new Map();
    this.heritees = new Map();
    this.limiteur = new LimiteurEchecs({ monotone: () => this.frontal.monotone() });
    this.compteurConnexions = 0;
  }

  get journal() {
    return this.frontal.journal;
  }

  async ecouter() {
    const [hote, port] = this.cfg.listen.split(/:(?=[0-9]+$)/);
    const gestion = (req, res) => this._requete(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500).end();
      else res.end();
    });
    this.serveur = this.cfg.tls
      ? https.createServer({ cert: fs.readFileSync(this.cfg.tls.cert_file), key: fs.readFileSync(this.cfg.tls.key_file) }, gestion)
      : http.createServer(gestion);
    await new Promise((res, rej) => {
      this.serveur.once("error", rej);
      this.serveur.listen(Number(port), hote.replace(/^\[|\]$/g, ""), res);
    });
  }

  adresse() {
    return this.serveur.address();
  }

  async fermer() {
    this.serveur?.closeAllConnections?.();
    await new Promise((r) => (this.serveur ? this.serveur.close(() => r()) : r()));
  }

  _metadonnees() {
    const o = this.cfg.oauth;
    return { resource: o.resource, authorization_servers: o.authorization_servers, scopes_supported: o.required_scopes, bearer_methods_supported: ["header"] };
  }

  _authentifier(req) {
    const a = req.headers.authorization;
    const m = typeof a === "string" ? /^Bearer ([\x21-\x7e]+)$/.exec(a) : null;
    if (!m) throw new ErreurAuthentification(401, "absent");
    const recu = Buffer.from(m[1], "utf8");
    // EX-18.3 : ce jeton, ou cette connexion, a trop échoué : refus pendant 60 s (lecture 163).
    req[CLE_CONNEXION].jeton = this.limiteur.cleJeton(recu);
    if (this.limiteur.bloque(req[CLE_CONNEXION].jeton) || this.limiteur.bloque(req[CLE_CONNEXION].connexion)) throw new ErreurAuthentification(401, "jeton_limite");
    let id = null;
    for (const [k, v] of this.jetons) if (egauxTempsConstant(recu, v)) id = k;
    if (id !== null) {
      const hote = this.frontal.hotePour({ static_token: id });
      if (!hote) throw new ErreurAuthentification(403, "hote_inconnu");
      return { hote, identite: { jeton: id }, cle: `${hote.id}\u0000jeton:${id}` };
    }
    if (!this.cfg.oauth) throw new ErreurAuthentification(401, "jeton_inconnu");
    return null;
  }

  async _authentifierOauth(req) {
    const m = /^Bearer ([\x21-\x7e]+)$/.exec(req.headers.authorization);
    const o = this.cfg.oauth;
    const jwks = await this.chargerJwks();
    const { sub } = verifierJwt(m[1], { jwks, resource: o.resource, issuers: o.authorization_servers, scopes: o.required_scopes, maintenant: this.frontal.murale() });
    const hote = this.frontal.hotePour({ oauth_subject: sub }) ?? (this.frontal.config.mcp.hosts ?? []).find((h) => h.match.oauth_subject === "*") ?? null;
    if (!hote) throw new ErreurAuthentification(403, "hote_inconnu");
    return { hote, identite: { oauth_subject: sub }, cle: `${hote.id}\u0000oauth:${sub}` };
  }

  _refuserAuth(req, res, e) {
    // EX-18.3 : un échec d'authentification (401) compte pour le jeton présenté
    // et pour la connexion ; un refus pendant la limitation n'en ajoute pas.
    if (e.statut === 401 && e.raison !== "jeton_limite") {
      if (req[CLE_CONNEXION].jeton) this.limiteur.echec(req[CLE_CONNEXION].jeton);
      this.limiteur.echec(req[CLE_CONNEXION].connexion);
    }
    this.journal.consigner("warning", "frontal_mcp", "auth_failed", { transport: "http", reason: e.raison, status: e.statut });
    const h = {};
    if (e.statut === 401) {
      const o = this.cfg.oauth;
      h["www-authenticate"] = o
        ? `Bearer resource_metadata="${new URL(`/.well-known/oauth-protected-resource${this.cfg.path}`, o.resource).href}", scope="${o.required_scopes.join(" ")}"`
        : "Bearer";
    }
    res.writeHead(e.statut, h).end();
  }

  async _requete(req, res) {
    const url = new URL(req.url, "http://127.0.0.1");
    if (req.method === "GET" && this.cfg.oauth && url.pathname === `/.well-known/oauth-protected-resource${this.cfg.path}`) {
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(this._metadonnees()));
      return;
    }
    if (url.pathname !== this.cfg.path) {
      res.writeHead(404).end();
      return;
    }
    // Origin (EX-4.34) : présente et invalide → 403.
    const origine = req.headers.origin;
    if (typeof origine === "string" && !this.cfg.allowed_origins.includes(origine)) {
      this.journal.consigner("warning", "frontal_mcp", "origin_refused", {});
      res.writeHead(403).end();
      return;
    }
    // Connexion (EX-18.3 : limitation par connexion, jamais par adresse source).
    const sock = req.socket;
    if (!sock[CLE_CONNEXION]) {
      sock[CLE_CONNEXION] = `connexion:${++this.compteurConnexions}`;
      sock.once("close", () => this.limiteur.oublier(sock[CLE_CONNEXION]));
    }
    req[CLE_CONNEXION] = { connexion: sock[CLE_CONNEXION], jeton: null };
    let auth;
    try {
      auth = this._authentifier(req) ?? (await this._authentifierOauth(req));
    } catch (e) {
      if (e instanceof ErreurAuthentification) return this._refuserAuth(req, res, e);
      return this._refuserAuth(req, res, new ErreurAuthentification(401, "jwks"));
    }
    const idSession = req.headers["mcp-session-id"];
    const heritee = typeof idSession === "string" ? this.heritees.get(idSession) : undefined;
    const sienne = heritee !== undefined && heritee.cle === auth.cle;
    if (req.method === "GET" || req.method === "DELETE") {
      if (sienne) return this._heriteeHorsPost(req, res, heritee);
      // EX-4.34 : en ère moderne, Mcp-Session-Id est ignoré (405) ; une session héritée inconnue : 404 (EX-4.37, lecture 164).
      if (typeof idSession === "string" && req.headers["mcp-protocol-version"] !== VERSION_MODERNE) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(405, { allow: "POST" }).end();
      return;
    }
    if (req.method !== "POST") {
      res.writeHead(405, { allow: "POST" }).end();
      return;
    }
    const corps = await this._lireCorps(req, res, auth.hote);
    if (corps === null) return;
    // 4.4 pas 1, EX-4.47 : quota contrôlé avant toute analyse.
    const refus = this.frontal.refusAvantAnalyse(auth.hote);
    if (refus !== null) {
      res.writeHead(200, { "content-type": "application/json" }).end(refus);
      return;
    }
    // Analyse préalable : ère et en-têtes (EX-4.35, EX-4.37), temps compté (EX-4.47).
    let noeud = null;
    let texte = null;
    const t0 = this.frontal.monotone();
    try {
      texte = decoderUtf8Strict(corps);
      noeud = analyserTexte(texte, { profondeurMax: this.frontal.config.limits.json_max_depth, membresMax: this.frontal.config.limits.json_max_members });
    } catch {
      noeud = null;
    }
    this.frontal.compterCapture(auth.hote, this.frontal.monotone() - t0);
    const methode = noeud?.t === "objet" ? membre(noeud, "method") : null;
    const nomMethode = methode?.t === "chaine" ? methode.valeur : null;
    const estNotification = noeud?.t === "objet" && !membre(noeud, "id") && nomMethode !== null;
    const meta = membre(membre(noeud, "params"), "_meta");
    const moderne = Boolean(membre(meta, "io.modelcontextprotocol/protocolVersion"));
    let session;
    if (nomMethode === "initialize" && typeof idSession !== "string") {
      session = this.frontal.ouvrirSession({ hote: auth.hote, identite: auth.identite, transport: "http" });
      const id = randomBytes(16).toString("hex");
      session.idSession = id;
      const h = { session, cle: auth.cle, flux: null };
      session.emettre = (x) => h.flux?.write(`data: ${x}\n\n`);
      this._garderHeritee(id, h);
      res.setHeader("mcp-session-id", id);
    } else if (sienne) {
      session = heritee.session;
    } else if (typeof idSession === "string" && !moderne) {
      // Session héritée inconnue ou terminée : 404, l'hôte réinitialise (EX-4.37).
      res.writeHead(404).end();
      return;
    } else {
      // Ère moderne : un Mcp-Session-Id est ignoré, jamais frappé ni renvoyé (EX-4.34).
      if (noeud?.t === "objet" && !moderne && nomMethode !== null) {
        // Requête sans `_meta` moderne et sans session héritée (EX-4.37).
        res.writeHead(400, { "content-type": "application/json" }).end(reponseErreur(this._idBrut(texte, noeud), -32602, { reason: "meta_requis" }));
        return;
      }
      if (noeud?.t === "objet" && moderne) {
        const erreur = this._controlerEntetes(req, texte, noeud, auth);
        if (erreur) {
          res.writeHead(400, { "content-type": "application/json" }).end(erreur);
          return;
        }
        const accept = String(req.headers.accept ?? "");
        if (!(accept.includes("application/json") && accept.includes("text/event-stream"))) {
          res.writeHead(406, { "content-type": "application/json" }).end(reponseErreur(this._idBrut(texte, noeud), -32600, { reason: "accept" }));
          return;
        }
      }
      session = this.parIdentite.get(auth.cle);
      if (!session || session.fermee) {
        session = this.frontal.ouvrirSession({ hote: auth.hote, identite: auth.identite, transport: "http" });
        this.parIdentite.set(auth.cle, session);
      }
    }
    if (estNotification) {
      await this.frontal.recevoir(session, corps, { cadre: "corps" });
      res.writeHead(202).end();
      return;
    }
    // Flux de réponse : JSON, ou SSE dès la première notification (EX-4.36).
    let sse = false;
    let veille = null;
    const ouvrirSse = () => {
      if (sse) return;
      sse = true;
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", "x-accel-buffering": "no" });
      res.flushHeaders?.();
      veille = setInterval(() => res.write(":\n\n"), 15000);
      veille.unref?.();
    };
    let annuler;
    const annulation = new Promise((r) => (annuler = r));
    res.on("close", () => {
      if (!res.writableFinished && session.ere !== "heritee") annuler(Date.now());
    });
    const canal = { notifier: (x) => (ouvrirSse(), res.write(`data: ${x}\n\n`)), annulation };
    if (nomMethode === "subscriptions/listen") {
      // Flux d'écoute moderne (EX-4.15, lecture 173) : accusé puis notifications
      // de liste sur ce flux SSE, fermé par l'hôte (annulation).
      res.on("close", () => clearInterval(veille));
    }
    const r = await this.frontal.recevoir(session, corps, { cadre: "corps", canal, compte: true });
    clearInterval(veille);
    if (r === null) {
      if (!res.writableEnded) res.end();
      return;
    }
    if (sse) {
      res.end(`data: ${r}\n\n`);
      return;
    }
    // Statut d'une erreur que le frontal a produite lui-même (EX-4.35 : méthode
    // inconnue 404 ; EX-4.37 : 400), indiqué par le frontal ; jamais lu dans le
    // texte, qui peut porter les octets d'un résultat d'outil (EX-4.20).
    if (!res.writableEnded) res.writeHead(canal.statutHttp ?? 200, { "content-type": "application/json" }).end(r);
  }

  /**
   * Garde une session de l'ère héritée (EX-4.37), bornée par identité et en
   * tout : au-delà, la plus ancienne est terminée (l'hôte qui la présente
   * reçoit 404 et réinitialise ; lecture 159).
   */
  _garderHeritee(id, h) {
    const memes = [...this.heritees.values()].filter((x) => x.cle === h.cle);
    if (memes.length >= SESSIONS_HERITEES_PAR_IDENTITE) this._terminerHeritee(memes[0]);
    if (this.heritees.size >= SESSIONS_HERITEES_MAX) this._terminerHeritee(this.heritees.values().next().value);
    this.heritees.set(id, h);
  }

  _terminerHeritee(h) {
    this.heritees.delete(h.session.idSession);
    this.frontal.fermerSession(h.session);
    h.flux?.end();
  }

  _idBrut(texte, noeud) {
    const id = membre(noeud, "id");
    return id && (id.t === "chaine" || id.t === "nombre") ? texte.slice(id.d, id.f) : null;
  }

  /** EX-4.35 : MCP-Protocol-Version, Mcp-Method, Mcp-Name, Mcp-Param-* égaux au corps. */
  _controlerEntetes(req, texte, noeud, auth) {
    const idBrut = this._idBrut(texte, noeud);
    const ecart = (quoi) => {
      this.journal.consigner("warning", "frontal_mcp", "header_mismatch", { header: quoi }, { host: auth.hote.id, request_id: idBrut });
      return reponseErreur(idBrut, -32020, { header: quoi });
    };
    const params = membre(noeud, "params");
    const v = membre(membre(params, "_meta"), "io.modelcontextprotocol/protocolVersion");
    if (req.headers["mcp-protocol-version"] !== v?.valeur) return ecart("MCP-Protocol-Version");
    const methode = membre(noeud, "method")?.valeur;
    if (req.headers["mcp-method"] !== methode) return ecart("Mcp-Method");
    const nomPorte = { "tools/call": "name", "prompts/get": "name", "resources/read": "uri" }[methode];
    if (nomPorte && req.headers["mcp-name"] !== membre(params, nomPorte)?.valeur) return ecart("Mcp-Name");
    const recus = Object.keys(req.headers).filter((h) => h.startsWith("mcp-param-"));
    if (methode === "tools/call" && recus.length) {
      const nom = membre(params, "name")?.valeur;
      const session = this.parIdentite.get(auth.cle);
      const def = session?.liste?.parNom.get(nom)?.definition ?? this.frontal.agregat.parNom.get(nom)?.definition;
      const args = valeurDe(membre(params, "arguments") ?? { t: "objet", membres: [] });
      const attendus = new Map(entetesParametres(def).filter((x) => typeof x.entete === "string").map((x) => [`mcp-param-${x.entete.toLowerCase()}`, x.propriete]));
      for (const h of recus) {
        if (!attendus.has(h)) {
          this.journal.consigner("info", "frontal_mcp", "header_ignored", { header: "Mcp-Param-*" }, { host: auth.hote.id, request_id: idBrut });
          continue;
        }
        // EX-4.35 : sentinelle =?base64?…?= décodée avant comparaison avec la valeur de l'argument (lecture 161).
        const recuDecode = decoderEnteteParametre(String(req.headers[h]));
        const attendu = texteArgument(args[attendus.get(h)]);
        if (recuDecode === null || attendu === null || recuDecode !== attendu) return ecart("Mcp-Param");
      }
    }
    return null;
  }

  async _lireCorps(req, res, hote) {
    const borne = this.frontal.config.limits.request_max_bytes;
    const morceaux = [];
    let taille = 0;
    for await (const c of req) {
      // 4.4 pas 1, EX-4.47 : comptés dès leur lecture, corps refusé compris.
      this.frontal.compterRecus(hote, c.length);
      taille += c.length;
      if (taille > borne) {
        this.journal.consigner("warning", "frontal_mcp", "request_too_large", { length: taille });
        res.writeHead(413, { "content-type": "application/json", connection: "close" }).end(reponseErreur(null, -31013, { limit_bytes: borne, direction: "requete" }));
        req.destroy();
        return null;
      }
      morceaux.push(c);
    }
    return new Uint8Array(Buffer.concat(morceaux));
  }

  /** GET (flux de notifications) et DELETE d'une session héritée (EX-4.37). */
  _heriteeHorsPost(req, res, h) {
    if (req.method === "DELETE") {
      this._terminerHeritee(h);
      res.writeHead(200).end();
      return;
    }
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", "x-accel-buffering": "no" });
    res.flushHeaders?.();
    h.flux = res;
    const veille = setInterval(() => res.write(":\n\n"), 15000);
    veille.unref?.();
    res.on("close", () => {
      clearInterval(veille);
      if (h.flux === res) h.flux = null;
    });
  }
}
