// Transport HTTP d'une requête d'horodatage (CT-5 EX-5.5, AN-7) : `POST` sur
// TLS 1.2 au moins avec vérification du certificat du serveur, en-têtes exacts,
// authentification `basic` (RFC 7617, sur TLS seulement) ou `certificat_client`,
// en-tête de corrélation, corps de réponse borné à 128 Kio, `http://` admis pour
// le seul rôle `interne` vers une adresse locale (AN-1, règle 4). Aucun
// mandataire : la requête part directement vers `url`.
//
// L'interface injectable est `{ envoyer({ url, octets, entetes, delaiMs, auth, tls, role }) → { status, entetes, corps, tronque } }`.
// Une erreur de transport lève `ErreurTransport` (`code` : `url`, `resolution`,
// `connexion`, `tls`, `reinitialisation`, `delai`).

import https from "node:https";
import http from "node:http";

/** Borne du corps d'une réponse (EX-5.5 : 128 Kio). */
export const CORPS_MAX = 131072;
/** Types de contenu admis en réponse (RFC 3161 §3.4, R1-F9). */
export const TYPES_REPONSE = Object.freeze(["application/timestamp-reply", "application/timestamp-response"]);
/** Type de contenu de la requête. */
export const TYPE_REQUETE = "application/timestamp-query";
/** Hôtes locaux admis en `http://` pour le rôle `interne`. */
export const HOTES_LOCAUX = Object.freeze(["127.0.0.1", "::1", "[::1]", "localhost"]);

/** Erreur de transport (EX-5.12 : transitoire). */
export class ErreurTransport extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ErreurTransport";
    this.code = code;
  }
}

/** Classe une erreur de socket de Node en code de transport. */
function codeDe(err) {
  const c = err && err.code;
  if (c === "ENOTFOUND" || c === "EAI_AGAIN" || c === "EAI_FAIL") return "resolution";
  if (c === "ECONNREFUSED" || c === "EHOSTUNREACH" || c === "ENETUNREACH" || c === "ETIMEDOUT") return "connexion";
  if (c === "ECONNRESET" || c === "EPIPE" || c === "HPE_INVALID_CONSTANT" || (typeof c === "string" && c.startsWith("HPE_"))) return "reinitialisation";
  if (typeof c === "string" && (c.startsWith("ERR_TLS") || c.startsWith("ERR_SSL") || c.includes("CERT") || c === "DEPTH_ZERO_SELF_SIGNED_CERT" || c === "SELF_SIGNED_CERT_IN_CHAIN" || c === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" || c === "UNABLE_TO_GET_ISSUER_CERT_LOCALLY" || c === "ERR_OSSL_EVP_UNSUPPORTED")) return "tls";
  if (err && /certificate|tls|ssl|handshake/i.test(err.message ?? "")) return "tls";
  return "connexion";
}

/** `url` admise : `https://`, ou `http://` pour le rôle `interne` vers un hôte local. */
export function controlerUrl(url, role) {
  let u;
  try {
    u = new URL(url);
  } catch {
    throw new ErreurTransport("url", "url illisible");
  }
  if (u.protocol === "https:") return u;
  if (u.protocol === "http:") {
    if (role === "interne" && HOTES_LOCAUX.includes(u.hostname)) return u;
    throw new ErreurTransport("url", "http:// n'est admis que pour le rôle interne vers une adresse locale (EX-5.5, AN-1)");
  }
  throw new ErreurTransport("url", `schéma ${u.protocol} refusé`);
}

/** En-têtes exacts d'EX-5.5 pour une requête de `octets.length` octets. */
export function entetesRequete({ taille, correlationHeader = null, attemptId = null }) {
  const h = { "Content-Type": TYPE_REQUETE, Accept: TYPES_REPONSE.join(", "), "Content-Length": String(taille) };
  if (correlationHeader && attemptId) h[correlationHeader] = attemptId;
  return h;
}

/** Valeur d'un en-tête `Authorization: Basic` (RFC 7617) depuis `utilisateur:motdepasse` en octets. */
export function autorisationBasic(secretOctets) {
  if (!(secretOctets instanceof Uint8Array) || secretOctets.length === 0) throw new ErreurTransport("url", "secret basic absent");
  return `Basic ${Buffer.from(secretOctets).toString("base64")}`;
}

/**
 * Transport par défaut. `options.ca` : autorités de confiance pour le serveur
 * (PEM ; défaut : celles de Node) ; `options.agent` (`https.Agent`) et
 * `options.agentHttp` (`http.Agent`) : agents injectables, tests seulement.
 */
export function transportHttps(options = {}) {
  return {
    async envoyer({ url, octets, entetes = {}, delaiMs = 10000, auth = null, tls = null, role = null }) {
      const u = controlerUrl(url, role);
      const enTls = u.protocol === "https:";
      const h = { ...entetes };
      const requete = { method: "POST", headers: h, timeout: delaiMs };
      if (enTls) {
        requete.minVersion = "TLSv1.2";
        requete.rejectUnauthorized = true;
        if (options.ca ?? tls?.ca) requete.ca = options.ca ?? tls.ca;
        if (tls?.servername) requete.servername = tls.servername;
      }
      if (auth && auth.method === "basic") {
        if (!enTls) throw new ErreurTransport("url", "authentification basic sur TLS seulement (EX-5.5)");
        h.Authorization = autorisationBasic(auth.secret);
      } else if (auth && auth.method === "certificat_client") {
        if (!enTls) throw new ErreurTransport("url", "certificat client sur TLS seulement (EX-5.5)");
        if (!(auth.secret instanceof Uint8Array)) throw new ErreurTransport("url", "certificat client absent");
        const pem = Buffer.from(auth.secret);
        requete.key = pem;
        requete.cert = pem;
      }
      if (enTls && options.agent) requete.agent = options.agent;
      if (!enTls && options.agentHttp) requete.agent = options.agentHttp;
      const module = enTls ? https : http;
      return new Promise((resoudre, rejeter) => {
        let fini = false;
        const finir = (f, v) => {
          if (fini) return;
          fini = true;
          f(v);
        };
        const req = module.request(u, requete, (rep) => {
          const morceaux = [];
          let total = 0;
          let tronque = false;
          rep.on("data", (d) => {
            if (tronque) return;
            total += d.length;
            if (total > CORPS_MAX) {
              tronque = true;
              const reste = CORPS_MAX - (total - d.length);
              if (reste > 0) morceaux.push(d.subarray(0, reste));
              rep.destroy();
              finir(resoudre, { status: rep.statusCode, entetes: rep.headers, corps: new Uint8Array(Buffer.concat(morceaux)), tronque: true });
              return;
            }
            morceaux.push(d);
          });
          rep.on("end", () => finir(resoudre, { status: rep.statusCode, entetes: rep.headers, corps: new Uint8Array(Buffer.concat(morceaux)), tronque: false }));
          rep.on("error", (err) => finir(rejeter, new ErreurTransport(codeDe(err), err.message)));
        });
        req.on("timeout", () => {
          req.destroy(new ErreurTransport("delai", `aucune réponse en ${delaiMs} ms`));
        });
        req.on("error", (err) => finir(rejeter, err instanceof ErreurTransport ? err : new ErreurTransport(codeDe(err), err.message)));
        req.end(Buffer.from(octets));
      });
    },

    /** `GET` borné, pour les captures de CRL (EX-5.10 étape 10). */
    async obtenir(url, delaiMs = 10000) {
      let u;
      try {
        u = new URL(url);
      } catch {
        throw new ErreurTransport("url", "url illisible");
      }
      if (u.protocol !== "https:" && u.protocol !== "http:") throw new ErreurTransport("url", `schéma ${u.protocol} refusé`);
      const module = u.protocol === "https:" ? https : http;
      const requete = { method: "GET", timeout: delaiMs };
      if (u.protocol === "https:") {
        requete.minVersion = "TLSv1.2";
        requete.rejectUnauthorized = true;
        if (options.ca) requete.ca = options.ca;
      }
      if (u.protocol === "https:" && options.agent) requete.agent = options.agent;
      if (u.protocol === "http:" && options.agentHttp) requete.agent = options.agentHttp;
      return new Promise((resoudre, rejeter) => {
        const req = module.request(u, requete, (rep) => {
          const morceaux = [];
          let total = 0;
          rep.on("data", (d) => {
            total += d.length;
            if (total > 4 * CORPS_MAX) {
              rep.destroy();
              rejeter(new ErreurTransport("taille", "CRL de plus de 512 Kio"));
              return;
            }
            morceaux.push(d);
          });
          rep.on("end", () => resoudre({ status: rep.statusCode, entetes: rep.headers, corps: new Uint8Array(Buffer.concat(morceaux)) }));
          rep.on("error", (err) => rejeter(new ErreurTransport(codeDe(err), err.message)));
        });
        req.on("timeout", () => req.destroy(new ErreurTransport("delai", `aucune réponse en ${delaiMs} ms`)));
        req.on("error", (err) => rejeter(err instanceof ErreurTransport ? err : new ErreurTransport(codeDe(err), err.message)));
        req.end();
      });
    },
  };
}
