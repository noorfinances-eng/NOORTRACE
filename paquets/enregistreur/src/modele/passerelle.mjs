// Passerelle du frontal modèle (CT-2 §5.1.1, §5.3, §5.3.3, §5.7) : l'hôte
// adresse ses requêtes d'API de modèle à l'enregistreur par l'URL de base de
// son SDK ; la passerelle authentifie la connexion d'hôte (EX-5.8 : jeton
// statique ou jeton OAuth), trouve la route (EX-5.2, EX-5.28), refuse ce qui
// ne peut pas être capturé (EX-5.7, EX-5.29, EX-5.32, EX-5.33) ou dépasse les
// quotas de la connexion (EX-4.47), fait écrire les pièces de la requête
// avant l'envoi (EX-5.10, moteur des échanges), relaie la requête au
// fournisseur avec les en-têtes de la liste autorisée (5.3, EX-5.26), relaie
// la réponse à l'hôte octet pour octet, sans tampon, en la capturant en
// parallèle (EX-5.11), puis fait sceller l'échange. Elle ne réémet jamais
// une requête (EX-5.25).
//
// Ni un secret, ni un jeton, ni une pièce, ni un corps ne vont au journal
// d'exploitation (EX-17.3).

import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import { sha256Hex, utf8 } from "@noortrace/noyau";
import { egauxTempsConstant } from "../mcp/hote-stdio.mjs";
import { verifierJwt, ErreurAuthentification } from "../mcp/hote-http.mjs";
import {
  normaliserCible, trouverRoute, examinerRequeteGemini, refusEnFlux, reponseRefus, entetesVersFournisseur, entetesVersHote,
  nomsConnexion, nomEnteteAuth, declarationsFournisseur, parametresRequete,
} from "./formats.mjs";
import { analyserCorpsJson } from "./extraction.mjs";
import { MoteurEchanges } from "./echange.mjs";

/** En-têtes qu'une requête ne peut porter qu'une fois (authentification, cadrage, délégation). */
const UNIQUES = new Set([
  "x-noortrace-token", "x-noortrace-run-id", "x-noortrace-on-behalf-of", "x-noortrace-prompt-version", "authorization", "x-api-key", "api-key",
  "x-goog-api-key", "content-type", "content-length", "content-encoding", "transfer-encoding", "host",
]);

const SOCKET_SCELLEMENT = Symbol("noortrace.modele.scellement");

/** Jetons de la passerelle (EX-5.8) : `model.static_tokens` et `mcp.http.static_tokens`. */
export function jetonsPasserelle(config, secrets) {
  const m = new Map();
  (config.mcp?.http?.static_tokens ?? []).forEach((t, k) => {
    const s = secrets.get(`/mcp/http/static_tokens/${k}/token`);
    if (s) m.set(t.id, s);
  });
  (config.model?.static_tokens ?? []).forEach((t, k) => {
    const s = secrets.get(`/model/static_tokens/${k}/token`);
    if (s) m.set(t.id, s);
  });
  return m;
}

/**
 * URI de la passerelle, audience des jetons OAuth de ses connexions d'hôte
 * (EX-5.8 point 2) : `https://` avec `model.tls`, `http://` sinon, suivi de
 * `model.listen` (LISEZMOI, lecture 72).
 * @param {object} config
 */
export function uriPasserelle(config) {
  return `${config.model.tls ? "https" : "http"}://${config.model.listen}`;
}

/** JWKS lu par HTTPS, gardé cinq minutes. */
export function chargeurJwks(uri) {
  let cache = null;
  let instant = 0;
  return () => {
    if (cache && Date.now() - instant < 300000) return Promise.resolve(cache);
    return new Promise((res, rej) => {
      https
        .get(uri, (r) => {
          const m = [];
          r.on("data", (c) => m.push(c));
          r.on("end", () => {
            try {
              cache = JSON.parse(Buffer.concat(m).toString("utf8"));
              instant = Date.now();
              res(cache);
            } catch (e) {
              rej(e);
            }
          });
        })
        .on("error", rej);
    });
  };
}

export class PasserelleModele {
  /**
   * @param {object} o
   * @param {import("../coeur.mjs").Coeur} o.coeur
   * @param {Map<string, Uint8Array>} [o.secrets] secrets résolus par pointeur
   * @param {object|null} [o.redacteur] rédacteur (INTERFACES.md, section e) ; à défaut celui du cœur
   * @param {import("./correlation.mjs").RegistreCorrelation} [o.registre] registre de corrélation (5.6)
   * @param {MoteurEchanges} [o.moteur] moteur partagé (sinon créé ici)
   * @param {object} [o.config] configuration (défaut : celle du cœur, rechargements compris)
   * @param {() => Promise<object>} [o.chargerJwks] JWKS des jetons OAuth (défaut : `mcp.http.oauth.jwks_uri`)
   * @param {{echange?: Function, refus?: Function}} [o.observateur] crochets des tests, dans le processus
   */
  constructor(o) {
    this.coeur = o.coeur;
    this.moteur = o.moteur ?? new MoteurEchanges({ coeur: o.coeur, redacteur: o.redacteur, registre: o.registre, config: o.config, observateur: o.observateur });
    this.secrets = o.secrets ?? this.coeur.secrets ?? new Map();
    this.jetons = jetonsPasserelle(this.config, this.secrets);
    const oauth = this.config.mcp?.http?.oauth ?? null;
    this.chargerJwks = o.chargerJwks ?? (oauth ? chargeurJwks(oauth.jwks_uri) : null);
    this.enVol = new Set();
    this.ferme = false;
    this.agents = { http: new http.Agent({ keepAlive: true }), https: new https.Agent({ keepAlive: true }) };
  }

  get config() {
    return this.moteur.config;
  }

  get registre() {
    return this.moteur.registre;
  }

  get journal() {
    return this.moteur.journal;
  }

  get metriques() {
    return this.moteur.metriques;
  }

  get observateur() {
    return this.moteur.observateur;
  }

  monotone() {
    return this.moteur.monotone();
  }

  // ---------------------------------------------------------------- écoute

  /** Écoute sur `model.listen` (TLS si `model.tls`). */
  async ecouter() {
    const m = this.config.model;
    const [hote, port] = m.listen.split(/:(?=[0-9]+$)/);
    const gestion = (req, res) => {
      const p = this._requete(req, res).catch((e) => {
        this.journal.consigner("error", "frontal_modele", "model_internal_error", { message: String(e?.message ?? e).slice(0, 200) });
        if (!res.headersSent) res.writeHead(500, { connection: "close" }).end();
        else res.destroy();
      });
      this.enVol.add(p);
      p.finally(() => this.enVol.delete(p));
    };
    // CT-2 ne fixe pas de version de TLS : plancher TLS 1.2, celui de Node.js, écrit ici (lecture 74).
    this.serveur = m.tls ? https.createServer({ cert: fs.readFileSync(m.tls.cert_file), key: fs.readFileSync(m.tls.key_file), minVersion: "TLSv1.2" }, gestion) : http.createServer(gestion);
    // Cadrage refusé par l'analyseur HTTP (Content-Length et Transfer-Encoding, EX-5.26) : 400, sans relais.
    this.serveur.on("clientError", (e, socket) => {
      this.journal.consigner("warning", "frontal_modele", "model_request_refused", { raison: "cadrage", code: e?.code ?? null });
      if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
      else socket.destroy();
    });
    if (m.tls) {
      this.serveur.on("tlsClientError", (e) => this.journal.consigner("warning", "frontal_modele", "tls_refused", { code: e?.code ?? null }));
    }
    await new Promise((res, rej) => {
      this.serveur.once("error", rej);
      this.serveur.listen(Number(port), hote.replace(/^\[|\]$/g, ""), res);
    });
  }

  adresse() {
    return this.serveur?.address() ?? null;
  }

  /**
   * Arrêt propre (13.5) : plus aucun échange nouveau ; ceux en cours sont
   * attendus jusqu'à `drain_timeout_ms`.
   */
  async arreter() {
    this.ferme = true;
    if (this.serveur) {
      this.serveur.close();
      this.serveur.closeIdleConnections?.();
    }
    const delai = this.config.mcp?.drain_timeout_ms ?? 10000;
    let minuteur;
    await Promise.race([Promise.allSettled([...this.enVol]), new Promise((r) => (minuteur = setTimeout(r, delai)))]);
    clearTimeout(minuteur);
    this.serveur?.closeAllConnections?.();
    this.agents.http.destroy();
    this.agents.https.destroy();
  }

  // ---------------------------------------------------------------- réception

  _refuser(res, cas, x) {
    if (cas !== "degrade") {
      this.journal.consigner("warning", "frontal_modele", "model_request_refused", { route: x.route?.path ?? null, raison: cas, ...(x.donnees ?? {}) }, { host: x.hote?.id ?? null });
    }
    const r = reponseRefus(x.route.format, cas, { enFlux: x.enFlux });
    res.writeHead(r.statut, { "content-type": r.contentType, "content-length": Buffer.byteLength(r.corps), ...(x.fermer ? { connection: "close" } : {}) });
    res.end(r.corps);
    this.observateur.refus?.({ raison: cas, statut: r.statut, contentType: r.contentType, corps: r.corps });
  }

  _vide(res, statut, x = {}) {
    res.writeHead(statut, { "content-length": 0, ...(x.fermer ? { connection: "close" } : {}) });
    res.end();
    this.observateur.refus?.({ raison: x.raison ?? null, statut, contentType: null, corps: null });
  }

  /**
   * Corps complet de la requête dans la borne (EX-5.33) ; au-delà, la lecture
   * s'arrête (la connexion sera fermée après le refus) ; `coupe` si l'hôte
   * est parti avant la fin.
   */
  _lireCorps(req, borne) {
    return new Promise((resoudre) => {
      const morceaux = [];
      let n = 0;
      let fini = false;
      const fin = (x) => {
        if (fini) return;
        fini = true;
        resoudre({ octets: new Uint8Array(Buffer.concat(morceaux)), longueur: Math.min(n, borne + 1), ...x });
      };
      req.on("data", (c) => {
        if (fini) return;
        n += c.length;
        if (n > borne) {
          req.pause();
          fin({ depasse: true });
          return;
        }
        morceaux.push(c);
      });
      req.on("end", () => fin({ depasse: false }));
      req.on("error", () => fin({ depasse: false, coupe: true }));
      req.on("close", () => {
        if (!req.complete) fin({ depasse: false, coupe: true });
      });
    });
  }

  /**
   * Connexion d'hôte (EX-5.8) : jeton statique comparé en temps constant, ou
   * jeton OAuth dont l'audience est l'URI de la passerelle ; porté par
   * `X-Noortrace-Token`, ou, en `credentials: "propre"`, par l'en-tête de la
   * route (`Authorization` seulement pour un jeton OAuth).
   * @returns {Promise<{hote: object, identite: object}|null>}
   */
  async _identifier(route, h) {
    let valeur = null;
    let parEnteteRoute = false;
    if (typeof h["x-noortrace-token"] === "string") valeur = h["x-noortrace-token"];
    else if (route.credentials === "propre") {
      const nom = nomEnteteAuth(route.auth_header);
      let v = h[nom];
      if (nom === "authorization") v = typeof v === "string" && /^Bearer [\x21-\x7e]+$/.test(v) ? v.slice(7) : null;
      valeur = typeof v === "string" ? v : null;
      parEnteteRoute = true;
    }
    if (valeur === null) {
      // Jeton OAuth en mode propre : en-tête Authorization (EX-5.8 point 2).
      if (route.credentials === "propre" && typeof h.authorization === "string" && /^Bearer [\x21-\x7e]+$/.test(h.authorization)) {
        return this._identifierOauth(h.authorization.slice(7));
      }
      return null;
    }
    const recu = utf8(valeur);
    let id = null;
    for (const [k, v] of this.jetons) if (egauxTempsConstant(recu, v)) id = k;
    if (id !== null) {
      const hote = (this.config.model.hosts ?? []).find((x) => x.match?.static_token === id) ?? null;
      return hote ? { hote, identite: {} } : null;
    }
    if (!parEnteteRoute || nomEnteteAuth(route.auth_header) === "authorization") return this._identifierOauth(valeur);
    return null;
  }

  async _identifierOauth(jeton) {
    const oauth = this.config.mcp?.http?.oauth ?? null;
    const hotes = (this.config.model.hosts ?? []).filter((x) => typeof x.match?.oauth_subject === "string");
    if (!oauth || !hotes.length || !this.chargerJwks || jeton.split(".").length !== 3) return null;
    try {
      const jwks = await this.chargerJwks();
      const { sub } = verifierJwt(jeton, { jwks, resource: uriPasserelle(this.config), issuers: oauth.authorization_servers, scopes: oauth.required_scopes, maintenant: this.moteur.murale() });
      const hote = hotes.find((x) => x.match.oauth_subject === sub) ?? null;
      return hote ? { hote, identite: { oauth_subject: sub } } : null;
    } catch (e) {
      const raison = e instanceof ErreurAuthentification ? e.raison : "jwks";
      this.journal.consigner("warning", "frontal_modele", "auth_failed", { transport: "passerelle", reason: `oauth_${raison}`, status: 401 });
      return null;
    }
  }

  async _requete(req, res) {
    const t_recu = this.monotone();
    const h = req.headers;
    if (this.ferme) return this._vide(res, 503, { fermer: true, raison: "arret" });
    // En-têtes uniques (authentification, cadrage, délégation) en double : refus.
    const vus = new Map();
    for (let k = 0; k < req.rawHeaders.length; k += 2) {
      const nom = req.rawHeaders[k].toLowerCase();
      vus.set(nom, (vus.get(nom) ?? 0) + 1);
    }
    const doubles = [...vus].filter(([n, c]) => c > 1 && (UNIQUES.has(n) || n.startsWith("x-noortrace-"))).map(([n]) => n);
    if (doubles.length) {
      this.journal.consigner("warning", "frontal_modele", "model_request_refused", { raison: "entete_double", headers: doubles });
      return this._vide(res, 400, { fermer: true, raison: "entete_double" });
    }
    const cible = normaliserCible(req.url);
    if (!cible.ok) {
      this.journal.consigner("warning", "frontal_modele", "model_request_refused", { raison: "chemin", length: Buffer.byteLength(req.url ?? "") });
      return this._vide(res, 400, { raison: "chemin" });
    }
    const trouve = trouverRoute(this.config.policy.model?.routes ?? [], req.method, cible.chemin);
    if (!trouve) {
      this.journal.consigner("info", "frontal_modele", "model_route_not_found", { method: req.method, path_length: Buffer.byteLength(cible.chemin) });
      return this._vide(res, 404, { raison: "route_inconnue" });
    }
    const route = trouve.route;
    const enFlux = route.format === "gemini" && refusEnFlux(trouve.methodeGemini, cible.requete);
    const id = await this._identifier(route, h);
    if (!id) {
      this.journal.consigner("warning", "frontal_modele", "auth_failed", { transport: "passerelle", reason: "hote_inconnu", status: 401, route: route.path });
      return this._refuser(res, "hote_inconnu", { route, enFlux, fermer: true, donnees: { status: 401 } });
    }
    const hote = id.hote;
    // La durabilité de l'échange précédent sur cette connexion précède la requête suivante (5.3.1 pas 8).
    const precedent = req.socket[SOCKET_SCELLEMENT];
    if (precedent) await precedent;
    const quotas = this.moteur.quotas(hote);
    if (trouve.genre === "passthrough") return this._passthrough(req, res, { route, indice: trouve.indice, hote, cible, quotas });

    // Chaîne de requête d'une route gemini (EX-5.29).
    let requeteAmont = cible.requete === null ? "" : `?${cible.requete}`;
    if (route.format === "gemini") {
      const q = examinerRequeteGemini(trouve.methodeGemini, cible.requete);
      if (!q.ok) return this._refuser(res, q.raison, { route, hote, enFlux, donnees: { params: q.noms } });
      requeteAmont = q.amont;
    }
    // Corps (EX-5.33, EX-5.7) ; octets reçus comptés, requête refusée comprise (EX-4.47).
    const lim = this.config.limits;
    const corps = await this._lireCorps(req, lim.model_request_max_bytes);
    quotas.recevoir(this.monotone(), corps.longueur);
    if (corps.coupe) return;
    if (corps.depasse) return this._refuser(res, "taille", { route, hote, enFlux, fermer: true, donnees: { length: corps.longueur } });
    const ce = h["content-encoding"];
    if (ce !== undefined && ce.trim().toLowerCase() !== "identity") {
      return this._refuser(res, "content_encoding", { route, hote, enFlux, donnees: { length: corps.octets.length, content_type: h["content-type"] ?? null } });
    }
    const t0 = this.monotone();
    const analyse = analyserCorpsJson(corps.octets, this.moteur.bornes);
    // Le temps d'analyse compte pour les requêtes suivantes : il est ajouté
    // après le contrôle du quota, comme celui de la rédaction (EX-4.47, lecture 73).
    const dureeAnalyse = this.monotone() - t0;
    if (!analyse.ok) {
      quotas.tempsCapture(this.monotone(), dureeAnalyse);
      return this._refuser(res, "corps_non_analysable", { route, hote, enFlux, donnees: { length: corps.octets.length, content_type: h["content-type"] ?? null } });
    }
    // Serveurs MCP et contenu en cache déclarés au fournisseur (EX-5.32).
    if (route.format === "gemini") {
      const d = declarationsFournisseur(analyse.valeur);
      if (d.mcp > 0) {
        if (route.provider_mcp !== "relayer") return this._refuser(res, "serveurs_mcp_fournisseur", { route, hote, enFlux, donnees: { entries: d.mcp } });
        this.journal.consigner("warning", "frontal_modele", "provider_mcp_bypass", { route: route.path, entries: d.mcp }, { host: hote.id });
      }
      if (d.cache) {
        if (route.provider_cache !== "relayer") return this._refuser(res, "cache_fournisseur", { route, hote, enFlux });
        this.journal.consigner("warning", "frontal_modele", "provider_cache_reference", { route: route.path }, { host: hote.id });
      }
    }
    // Quotas de la connexion d'hôte (EX-4.47 ; 14.2, ligne « Mémoire », colonne M).
    const quotaAtteint = this.moteur.controlerQuota(hote, this.monotone(), { echange: true });
    quotas.tempsCapture(this.monotone(), dureeAnalyse);
    if (quotaAtteint) return this._refuser(res, "degrade", { route, hote, enFlux });
    const fin = this._echange(req, res, { route, indice: trouve.indice, hote, identite: id.identite, cible, trouve, requeteAmont, corps: corps.octets, valeur: analyse.valeur, t_recu, enFlux });
    req.socket[SOCKET_SCELLEMENT] = fin.then(
      () => {},
      () => {},
    );
    return fin;
  }

  // ---------------------------------------------------------------- échange

  async _echange(req, res, x) {
    const { route, hote } = x;
    const cfg = this.config;
    const h = req.headers;
    const p = await this.moteur.preparer({ route, trouve: x.trouve, hote, entetes: h, valeur: x.valeur, t_recu: x.t_recu, mode: "passerelle", identite: x.identite });
    if (p.refus) return this._refuser(res, p.refus, { route, hote, enFlux: x.enFlux, fermer: p.refus === "hote_inconnu" });
    const etat = p.etat;
    // Envoi (5.3.1 pas 4 ; 5.3.3 pas 9).
    const ch = nomsConnexion(h.connection);
    const { envoyes, notes, retires } = entetesVersFournisseur(h, { forward: cfg.model.forward_headers, strip: cfg.model.strip_headers, nomsConnexion: ch });
    const nomAuth = nomEnteteAuth(route.auth_header);
    if (route.credentials === "propre") {
      const s = this.secrets.get(`/policy/model/routes/${x.indice}/secret`);
      if (s) envoyes[nomAuth] = nomAuth === "authorization" ? `Bearer ${Buffer.from(s).toString("utf8")}` : Buffer.from(s).toString("utf8");
    } else if (typeof h[nomAuth] === "string") {
      envoyes[nomAuth] = h[nomAuth];
    }
    const base = route.upstream.replace(/\/+$/, "");
    const cheminAmont = route.format === "gemini" ? `${route.path}/${x.trouve.segment}:${x.trouve.methodeGemini}` : route.path;
    const url = new URL(`${base}${cheminAmont}${x.requeteAmont}`);
    envoyes["accept-encoding"] = "identity";
    envoyes["content-length"] = String(x.corps.length);
    Object.assign(etat, {
      notes,
      retires,
      url,
      cheminAmont: `${cheminAmont}${x.requeteAmont}`,
      requeteSha: route.format === "gemini" || x.cible.requete === null ? null : sha256Hex(utf8(x.cible.requete)),
      enFlux: x.enFlux,
      t_envoi: this.monotone(),
    });
    this.metriques.observer("noortrace_relay_latency_ms", { path: "modele", class: "modele" }, Math.max(0, etat.t_envoi - x.t_recu));
    return this._relayer(res, etat, envoyes, x.corps);
  }

  _relayer(res, etat, envoyes, corps) {
    const cfg = this.config;
    return new Promise((resoudre) => {
      const mod = etat.url.protocol === "https:" ? https : http;
      const agent = etat.url.protocol === "https:" ? this.agents.https : this.agents.http;
      let issue = null;
      let minuteur = null;
      const armer = (ms, f) => {
        clearTimeout(minuteur);
        minuteur = setTimeout(f, ms);
      };
      const finir = (r) => {
        if (issue) return;
        issue = r;
        clearTimeout(minuteur);
        if (r.genre === "delai" && !res.headersSent && !res.destroyed) {
          // Rien n'a encore été relayé : 504 au format de la route (EX-5.24, EX-5.30).
          const x = reponseRefus(etat.route.format, "delai", { enFlux: etat.enFlux });
          res.writeHead(x.statut, { "content-type": x.contentType, "content-length": Buffer.byteLength(x.corps) });
          res.end(x.corps);
        }
        resoudre(this.moteur.sceller(etat, r));
      };
      const amont = mod.request(etat.url, { method: "POST", headers: envoyes, agent });
      let connecte = false;
      const delai = (phase, ms) => {
        amont.destroy();
        finir({ genre: "delai", phase, timeout_ms: ms });
      };
      amont.on("socket", (s) => {
        const evenement = etat.url.protocol === "https:" ? "secureConnect" : "connect";
        if (!s.connecting && !s.pending) {
          // Connexion réutilisée : le délai du premier octet court dès l'envoi.
          connecte = true;
          armer(cfg.model.first_byte_timeout_ms, () => delai("premier_octet", cfg.model.first_byte_timeout_ms));
          return;
        }
        armer(cfg.model.connect_timeout_ms, () => delai("connexion", cfg.model.connect_timeout_ms));
        s.once(evenement, () => {
          connecte = true;
          armer(cfg.model.first_byte_timeout_ms, () => delai("premier_octet", cfg.model.first_byte_timeout_ms));
        });
      });
      amont.on("error", () => {
        if (issue || etat.reponseCommencee) return;
        // Avant toute réponse : connexion impossible, ou coupure avant le premier octet.
        finir({ genre: "delai", phase: connecte ? "premier_octet" : "connexion", timeout_ms: connecte ? cfg.model.first_byte_timeout_ms : cfg.model.connect_timeout_ms });
      });
      // L'hôte qui part avant la réponse : la requête amont est fermée.
      const hotePart = () => {
        if (!res.writableFinished && !issue && !etat.reponseCommencee) {
          amont.destroy();
          finir({ genre: "hote_parti" });
        }
      };
      res.on("close", hotePart);
      amont.on("response", (rep) => {
        if (issue) {
          rep.destroy();
          return;
        }
        res.off("close", hotePart);
        etat.reponseCommencee = true;
        this._recevoir(res, rep, amont, etat, { armer, desarmer: () => clearTimeout(minuteur), finir });
      });
      amont.end(corps);
      etat.t_envoi = this.monotone();
    });
  }

  _recevoir(res, rep, amont, etat, c) {
    const cfg = this.config;
    const route = etat.route;
    const ch = nomsConnexion(rep.headers.connection);
    const { rendus, notes } = entetesVersHote(rep.headers, { forward: cfg.model.forward_headers, strip: cfg.model.strip_headers, nomsConnexion: ch });
    const capture = this.moteur.capture(etat, { statut: rep.statusCode, entetes: rep.headers, notesReponse: notes });
    // Statut et en-têtes relayés dès réception (EX-5.11 (a)) ; cadrage calculé par la passerelle.
    res.writeHead(rep.statusCode, rendus);
    res.flushHeaders?.();
    let fini = false;
    const arreterTout = async (r) => {
      if (fini) return;
      fini = true;
      c.desarmer();
      amont.destroy();
      if (!res.writableEnded) res.destroy();
      await capture.terminer({ coupe: true });
      c.finir(r);
    };
    const armerInactivite = () => c.armer(cfg.model.idle_timeout_ms, () => arreterTout({ genre: "inactivite", timeout_ms: cfg.model.idle_timeout_ms }));
    armerInactivite();
    // L'hôte ferme pendant la réponse : connexion amont fermée, forme incomplète (EX-5.13).
    res.on("close", () => {
      if (res.writableFinished || fini) return;
      this.journal.consigner("warning", "frontal_modele", "host_disconnected", { route: route.path }, { host: etat.hote.id });
      arreterTout({ genre: "hote_parti" });
    });
    rep.on("data", (o) => {
      armerInactivite();
      // Analysé avant d'être écrit vers l'hôte (5.6).
      capture.ecrire(o);
      if (!res.write(o)) {
        rep.pause();
        res.once("drain", () => rep.resume());
      }
    });
    rep.on("end", async () => {
      if (fini) return;
      fini = true;
      c.desarmer();
      await capture.terminer({ coupe: false });
      res.end();
      c.finir({ genre: "reponse" });
    });
    // Coupure amont pendant la réponse (EX-5.13) : ce qui a été reçu a été relayé.
    const coupure = () => {
      if (fini || rep.complete) return;
      this.journal.consigner("warning", "frontal_modele", "provider_error", { route: route.path, phase: "flux", status: rep.statusCode }, { host: etat.hote.id });
      arreterTout({ genre: "coupure" });
    };
    rep.on("close", coupure);
    rep.on("error", coupure);
  }

  // ---------------------------------------------------------------- passthrough (EX-5.2, 5.8)

  async _passthrough(req, res, x) {
    const { route, hote, cible } = x;
    const cfg = this.config;
    if (route.format === "gemini" && (parametresRequete(cible.requete) ?? []).some((p) => p.nom === "key")) {
      return this._refuser(res, "cle_dans_url", { route, hote, donnees: { params: ["key"] } });
    }
    const corps = await this._lireCorps(req, cfg.limits.model_request_max_bytes);
    x.quotas.recevoir(this.monotone(), corps.longueur);
    if (corps.coupe) return;
    if (corps.depasse) return this._refuser(res, "taille", { route, hote, fermer: true, donnees: { length: corps.longueur } });
    if (this.moteur.controlerQuota(hote, this.monotone(), { echange: false })) return this._refuser(res, "degrade", { route, hote });
    const ch = nomsConnexion(req.headers.connection);
    const { envoyes } = entetesVersFournisseur(req.headers, { forward: cfg.model.forward_headers, strip: cfg.model.strip_headers, nomsConnexion: ch });
    const nomAuth = nomEnteteAuth(route.auth_header);
    if (route.credentials === "propre") {
      const s = this.secrets.get(`/policy/model/routes/${x.indice}/secret`);
      if (s) envoyes[nomAuth] = nomAuth === "authorization" ? `Bearer ${Buffer.from(s).toString("utf8")}` : Buffer.from(s).toString("utf8");
    } else if (typeof req.headers[nomAuth] === "string") envoyes[nomAuth] = req.headers[nomAuth];
    envoyes["accept-encoding"] = "identity";
    if (req.method === "POST") envoyes["content-length"] = String(corps.octets.length);
    const url = new URL(`${route.upstream.replace(/\/+$/, "")}${cible.chemin}${cible.requete === null ? "" : `?${cible.requete}`}`);
    const mod = url.protocol === "https:" ? https : http;
    await new Promise((resoudre) => {
      const amont = mod.request(url, { method: req.method, headers: envoyes, agent: url.protocol === "https:" ? this.agents.https : this.agents.http, timeout: cfg.model.first_byte_timeout_ms });
      const echec = () => {
        if (!res.headersSent) {
          const r = reponseRefus(route.format, "delai", {});
          res.writeHead(r.statut, { "content-type": r.contentType, "content-length": Buffer.byteLength(r.corps) });
          res.end(r.corps);
        } else res.destroy();
        resoudre();
      };
      amont.on("timeout", () => amont.destroy());
      amont.on("error", echec);
      amont.on("response", (rep) => {
        const { rendus } = entetesVersHote(rep.headers, { forward: cfg.model.forward_headers, strip: cfg.model.strip_headers, nomsConnexion: nomsConnexion(rep.headers.connection) });
        res.writeHead(rep.statusCode, rendus);
        rep.pipe(res);
        rep.on("end", resoudre);
        rep.on("close", () => {
          if (!rep.complete) {
            res.destroy();
            resoudre();
          }
        });
        this.journal.consigner("info", "frontal_modele", "model_passthrough", { route: route.path, method: req.method, path_length: Buffer.byteLength(cible.chemin), status: rep.statusCode }, { host: hote.id });
      });
      amont.end(req.method === "POST" ? corps.octets : undefined);
    });
  }
}
