// Frontal HTTP du serveur RFC 3161 interne (RFC 3161 §3.4 : `POST`, corps
// `application/timestamp-query`, réponse `application/timestamp-reply`).
// AN-27 : en clair (`node:http`) seulement sur une adresse locale (127.0.0.1,
// ::1, localhost) ; ailleurs, TLS (`node:https`) avec authentification du
// client par certificat (`requestCert`, `rejectUnauthorized`) sous une AC de
// clients fournie. Le corps est borné (4 Kio par défaut). AN-28 : aucun jeton
// n'est journalisé par le serveur ; le `journal` injecté ne reçoit que les
// démarrages, les refus et les erreurs (jamais une empreinte, un nonce, un
// jeton). L'horloge est celle de l'appelant (règle 2 d'INTERFACES.md).

import http from "node:http";
import https from "node:https";
import { repondre } from "./reponse.mjs";

export class ErreurServeur extends Error {
  constructor(message) {
    super(message);
    this.name = "ErreurServeur";
  }
}

export const ADRESSES_LOCALES = Object.freeze(["127.0.0.1", "::1", "localhost"]);
export const TYPE_REQUETE = "application/timestamp-query";
export const TYPE_REPONSE = "application/timestamp-reply";
export const TAILLE_MAX_CORPS = 4096;
/** Chemin de santé : `GET` seulement, réponse `ok`, rien journalisé (sonde du conteneur). */
export const CHEMIN_SANTE = "/sante";

const JOURNAL_MUET = { consigner() {} };

/** Type de média sans paramètres, en minuscules. */
function typeMedia(entete) {
  return typeof entete === "string" ? entete.split(";")[0].trim().toLowerCase() : "";
}

/**
 * Démarre le serveur.
 * @param {object} o
 * @param {import("./autorite.mjs").Autorite} o.autorite
 * @param {{hote: string, port: number}|{tls: {cle: string|Buffer, certificat: string|Buffer, acClients: string|Buffer|(string|Buffer)[], hote?: string, port: number}}} o.ecoute
 * @param {{consigner: (niveau: string, evenement: string, data?: object) => void}} [o.journal]
 * @param {{murale: () => number, ecartMs?: number|(() => number)}} o.horloge
 * @param {number} [o.tailleMaxCorps]
 * @param {string|null} [o.chemin] chemin HTTP exigé (`/` par exemple) ; null : tout chemin
 * @returns {Promise<{adresse: {hote: string, port: number, url: string, tls: boolean}, fermer: () => Promise<void>, serveur: import("node:http").Server}>}
 */
export async function demarrerServeur(o) {
  if (!o || !o.autorite) throw new TypeError("demarrerServeur : autorite attendue");
  if (!o.horloge || typeof o.horloge.murale !== "function") throw new TypeError("demarrerServeur : horloge.murale() attendue");
  if (!o.ecoute || typeof o.ecoute !== "object") throw new TypeError("demarrerServeur : ecoute attendue");
  const journal = o.journal ?? JOURNAL_MUET;
  const tailleMax = o.tailleMaxCorps ?? TAILLE_MAX_CORPS;
  if (!Number.isInteger(tailleMax) || tailleMax < 128) throw new RangeError("tailleMaxCorps : entier ≥ 128 attendu");
  const chemin = o.chemin ?? null;

  let serveur;
  let hote;
  let port;
  let tls = false;
  if (o.ecoute.tls) {
    const t = o.ecoute.tls;
    if (!t.cle || !t.certificat || !t.acClients) throw new ErreurServeur("TLS : cle, certificat et acClients attendus (AN-27 : authentification du client)");
    hote = t.hote ?? "127.0.0.1";
    port = t.port;
    tls = true;
    serveur = https.createServer({
      key: t.cle,
      cert: t.certificat,
      ca: Array.isArray(t.acClients) ? t.acClients : [t.acClients],
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: "TLSv1.2",
    });
  } else {
    hote = o.ecoute.hote;
    port = o.ecoute.port;
    if (typeof hote !== "string" || !ADRESSES_LOCALES.includes(hote)) {
      throw new ErreurServeur(`écoute en clair sur ${hote} refusée : 127.0.0.1, ::1 ou localhost seulement, sinon TLS avec authentification du client (AN-27)`);
    }
    serveur = http.createServer();
  }
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new RangeError("port : entier 0 à 65535 attendu");

  const refusHttp = (rep, statut, raison, entetes = {}) => {
    journal.consigner("warning", "tsa_http_refus", { status: statut, reason: raison });
    // `Connection: close` : la réponse part, puis la connexion est fermée sans lire le reste d'un corps trop long.
    rep.writeHead(statut, { "Content-Type": "text/plain; charset=utf-8", Connection: "close", ...entetes });
    rep.end(`${raison}\n`);
  };

  serveur.on("request", (req, rep) => {
    // Santé (sonde du conteneur, `noortrace-tsa-interne sonde`) : `GET /sante` rend 200 sans rien lire de l'autorité
    // ni rien journaliser ; aucune autre requête que `POST` n'est servie.
    if (req.method === "GET" && req.url === CHEMIN_SANTE) {
      rep.writeHead(200, { "Content-Type": "text/plain; charset=utf-8", "Content-Length": 3, Connection: "close" });
      rep.end("ok\n");
      return;
    }
    if (req.method !== "POST") return refusHttp(rep, 405, "méthode refusée : POST seulement", { Allow: "POST" });
    if (chemin !== null && req.url !== chemin) return refusHttp(rep, 404, "chemin inconnu");
    if (typeMedia(req.headers["content-type"]) !== TYPE_REQUETE) return refusHttp(rep, 415, `Content-Type ${TYPE_REQUETE} exigé`);
    const annonce = Number(req.headers["content-length"]);
    if (Number.isFinite(annonce) && annonce > tailleMax) return refusHttp(rep, 413, `corps de ${annonce} octets au-delà de ${tailleMax}`);
    const morceaux = [];
    let taille = 0;
    let refuse = false;
    req.on("data", (m) => {
      if (refuse) return;
      taille += m.length;
      if (taille > tailleMax) {
        refuse = true;
        morceaux.length = 0;
        refusHttp(rep, 413, `corps au-delà de ${tailleMax} octets`);
        return;
      }
      morceaux.push(m);
    });
    req.on("end", () => {
      if (refuse) return;
      let resultat;
      try {
        resultat = repondre({ requete: new Uint8Array(Buffer.concat(morceaux)), autorite: o.autorite, horloge: o.horloge });
      } catch (e) {
        journal.consigner("error", "tsa_erreur", { message: e.message });
        rep.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
        rep.end("erreur interne\n");
        return;
      }
      if (resultat.statut !== "granted") {
        const data = { fail_info: resultat.echec, reason: resultat.raison };
        if (resultat.echec === "timeNotAvailable") data.tsa_clock_offset_ms = typeof o.horloge.ecartMs === "function" ? o.horloge.ecartMs() : (o.horloge.ecartMs ?? 0);
        journal.consigner(resultat.echec === "systemFailure" ? "error" : "warning", "tsa_refus", data);
      }
      rep.writeHead(200, { "Content-Type": TYPE_REPONSE, "Content-Length": resultat.octets.length });
      rep.end(Buffer.from(resultat.octets));
    });
    req.on("error", (e) => {
      journal.consigner("warning", "tsa_http_refus", { status: null, reason: `lecture du corps interrompue : ${e.code ?? e.message}` });
    });
  });
  serveur.on("tlsClientError", (e) => {
    journal.consigner("warning", "tsa_tls_refus", { reason: e.code ?? e.message });
  });

  await new Promise((resoudre, rejeter) => {
    serveur.once("error", rejeter);
    serveur.listen(port, hote, () => {
      serveur.off("error", rejeter);
      resoudre();
    });
  });
  const a = serveur.address();
  const hoteUrl = a.family === "IPv6" ? `[${a.address}]` : a.address;
  const adresse = { hote: a.address, port: a.port, url: `${tls ? "https" : "http"}://${hoteUrl}:${a.port}/`, tls };
  journal.consigner("info", "tsa_demarrage", {
    address: adresse.hote,
    port: adresse.port,
    tls,
    policy_oid: o.autorite.politique,
    accuracy_s: o.autorite.precisionS,
    tsa_clock_offset_ms: typeof o.horloge.ecartMs === "function" ? o.horloge.ecartMs() : (o.horloge.ecartMs ?? 0),
  });

  return {
    adresse,
    serveur,
    fermer: () =>
      new Promise((resoudre) => {
        serveur.close(() => resoudre());
        serveur.closeAllConnections?.();
      }),
  };
}
