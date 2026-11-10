// Outils des tests du lot A du composant d'ancrage (client RFC 3161) :
// chemins des vecteurs CT-5 et CT-6, lecture des ancres de test, serveur
// d'horodatage local factice (réponses rejouées depuis les vecteurs),
// transport factice, agent de tunnel pour les essais sur le réseau public,
// T-10 à partir d'un fichier d'ancres, répertoires temporaires sous
// `os.tmpdir()`.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { verifierRevocation } from "@noortrace/ancrage/rfc3161";

export const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const SPEC = path.join(RACINE, "spec");
export const CT5 = path.join(SPEC, "vecteurs", "ct-5");
export const CT6 = path.join(SPEC, "vecteurs", "ct-6");
export const CLES = path.join(CT6, "rfc3161", "cles");
export const JETONS = path.join(CT6, "rfc3161", "jetons");

/** Répertoire temporaire neuf. */
export function repertoireTemporaire(prefixe = "noortrace-ancrage-a-") {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefixe));
}

export const octets = (p) => new Uint8Array(fs.readFileSync(p));
export const texte = (p) => fs.readFileSync(p, "utf8");
export const json = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
export const sha256Hex = (o) => "0x" + createHash("sha256").update(o).digest("hex");

/** Nonce d'une étiquette (CT-5 annexe A.2 : 64 premiers bits de SHA-256 de l'étiquette). */
export function nonceDepuisEtiquette(etiquette) {
  return BigInt("0x" + createHash("sha256").update(etiquette, "utf8").digest("hex").slice(0, 16));
}

/** PEM de l'AC de test de CT-6. */
export const AC_TEST_PEM = texte(path.join(CLES, "ac-test.pem"));
export const TSA_TEST_PEM = texte(path.join(CLES, "tsa-test.pem"));

/** Prestataire de test d'`ancrage-v0`, résolu (aucun secret), sur l'AC de test. */
export function prestataireTest(surcharges = {}) {
  return {
    id: "tsa-test",
    role: "second_rang",
    url: "https://horodatage-test.example/tsa",
    auth: { method: "aucune", secret: null },
    hash: "sha256",
    policy_oid: null,
    accepted_policies: ["1.3.6.1.4.1.99999.1.1"],
    anchor_certificates: [AC_TEST_PEM],
    qualified: null,
    min_interval_ms: 0,
    request_timeout_ms: 10000,
    correlation_header: "X-Request-ID",
    source: "autorité de test des vecteurs CT-6, sans valeur hors des tests",
    ...surcharges,
  };
}

/** Horloge injectée : `murale` fixée à `sentMs`, `monotone` qui avance de `dureeMs` entre deux lectures. */
export function horlogeFixe(sentMs, dureeMs = 0) {
  let appels = 0;
  return { murale: () => sentMs, monotone: () => (appels++ === 0 ? 1000 : 1000 + dureeMs) };
}

/** Aléa injecté : rend les octets donnés, dans l'ordre, puis répète le dernier. */
export function aleaFixe(...tirages) {
  let i = 0;
  return (n) => {
    const t = tirages[Math.min(i++, tirages.length - 1)];
    const o = new Uint8Array(n);
    o.set(t.subarray(0, n));
    return o;
  };
}

/** Transport factice qui rend une réponse HTTP représentée ; `appels` garde ce qui a été envoyé. */
export function transportFactice(reponse) {
  const appels = [];
  return {
    appels,
    async envoyer(req) {
      appels.push(req);
      if (typeof reponse === "function") return reponse(req);
      if (reponse instanceof Error) throw reponse;
      return reponse;
    },
    async obtenir(url) {
      appels.push({ get: url });
      if (typeof reponse === "function") return reponse({ get: url });
      return reponse;
    },
  };
}

/** Réponse HTTP 200 `application/timestamp-reply` d'un corps donné. */
export function reponse200(corps, entetes = {}) {
  return { status: 200, entetes: { "content-type": "application/timestamp-reply", ...entetes }, corps, tronque: false };
}

/** Certificats TLS de test (AC et serveur sur 127.0.0.1) produits par openssl ; `null` sans openssl. */
export function certificatsTls(dir) {
  try {
    fs.mkdirSync(dir, { recursive: true });
    const o = (args) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
    o(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=autorite TLS de test noortrace"]);
    o(["req", "-newkey", "rsa:2048", "-nodes", "-keyout", "serveur.key", "-out", "serveur.csr", "-subj", "/CN=127.0.0.1"]);
    fs.writeFileSync(path.join(dir, "ext.cnf"), "subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=CA:FALSE\n");
    o(["x509", "-req", "-in", "serveur.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "serveur.pem", "-days", "2", "-extfile", "ext.cnf"]);
    return { caPem: fs.readFileSync(path.join(dir, "ca.pem")), cert: fs.readFileSync(path.join(dir, "serveur.pem")), key: fs.readFileSync(path.join(dir, "serveur.key")) };
  } catch {
    return null;
  }
}

/**
 * Serveur d'horodatage local factice : `repondre(req, corps) → { status, entetes, corps }`
 * ou une promesse ; `tls` : `{ cert, key, minVersion, maxVersion }` pour HTTPS.
 * Rend `{ url, port, requetes, fermer() }`.
 */
export function serveurTsa({ repondre, tls: optionsTls = null, hote = "127.0.0.1" }) {
  const requetes = [];
  const sockets = new Set();
  const gestionnaire = (req, rep) => {
    const morceaux = [];
    req.on("data", (d) => morceaux.push(d));
    req.on("end", async () => {
      const corps = Buffer.concat(morceaux);
      requetes.push({ method: req.method, headers: req.headers, corps });
      const r = await repondre(req, corps);
      if (r === null) return; // ne répond jamais (délai)
      rep.writeHead(r.status, r.entetes ?? {});
      rep.end(r.corps ? Buffer.from(r.corps) : undefined);
    });
  };
  const serveur = optionsTls ? https.createServer(optionsTls, gestionnaire) : http.createServer(gestionnaire);
  serveur.on("connection", (s) => {
    sockets.add(s);
    s.on("close", () => sockets.delete(s));
  });
  return new Promise((res) => {
    serveur.listen(0, hote, () => {
      const port = serveur.address().port;
      res({
        url: `${optionsTls ? "https" : "http"}://${hote}:${port}/tsa`,
        port,
        requetes,
        fermer: () => new Promise((r) => {
          for (const s of sockets) s.destroy();
          serveur.close(() => r());
        }),
      });
    });
  });
}

/**
 * Agent HTTPS qui tunnelle par `CONNECT` au travers du mandataire désigné par
 * `HTTPS_PROXY` quand il est défini (essais sur le réseau public depuis une
 * machine qui n'a pas d'accès direct) ; `undefined` sinon. Côté test
 * seulement : le transport de production n'emploie aucun mandataire.
 */
export function agentDepuisEnvironnement() {
  const proxy = process.env.HTTPS_PROXY ?? process.env.https_proxy;
  if (!proxy) return undefined;
  const p = new URL(proxy);
  return new https.Agent({
    keepAlive: false,
    createConnection(options, rappel) {
      const socket = net.connect(Number(p.port), p.hostname);
      const hote = `${options.host}:${options.port}`;
      socket.once("error", rappel);
      socket.once("connect", () => {
        socket.write(`CONNECT ${hote} HTTP/1.1\r\nHost: ${hote}\r\n\r\n`);
        let entete = "";
        const lire = (d) => {
          entete += d.toString("latin1");
          const fin = entete.indexOf("\r\n\r\n");
          if (fin === -1) return;
          socket.removeListener("data", lire);
          if (!/^HTTP\/1\.[01] 200/.test(entete)) return rappel(new Error(`mandataire : ${entete.split("\r\n")[0]}`));
          const sec = tls.connect({ socket, servername: options.servername ?? options.host, minVersion: "TLSv1.2", rejectUnauthorized: true, ca: options.ca });
          sec.once("secureConnect", () => rappel(null, sec));
          sec.once("error", rappel);
        };
        socket.on("data", lire);
      });
    },
  });
}

/** Même tunnel `CONNECT`, sans TLS, pour les URL `http://` (points de distribution de CRL). */
export function agentHttpDepuisEnvironnement() {
  const proxy = process.env.HTTPS_PROXY ?? process.env.https_proxy;
  if (!proxy) return undefined;
  const p = new URL(proxy);
  return new http.Agent({
    keepAlive: false,
    createConnection(options, rappel) {
      const socket = net.connect(Number(p.port), p.hostname);
      const hote = `${options.host}:${options.port}`;
      socket.once("error", rappel);
      socket.once("connect", () => {
        socket.write(`CONNECT ${hote} HTTP/1.1\r\nHost: ${hote}\r\n\r\n`);
        let entete = "";
        const lire = (d) => {
          entete += d.toString("latin1");
          const fin = entete.indexOf("\r\n\r\n");
          if (fin === -1) return;
          socket.removeListener("data", lire);
          if (!/^HTTP\/1\.[01] 200/.test(entete)) return rappel(new Error(`mandataire : ${entete.split("\r\n")[0]}`));
          rappel(null, socket);
        };
        socket.on("data", lire);
      });
    },
  });
}

/**
 * T-10 à partir du résultat de `verifierJeton` et d'un fichier d'ancres de
 * CT-6 (`revocation.crls`, `revocation.statements`) : héritage des prérequis
 * quand T-7 n'a pas réussi, sinon `verifierRevocation`.
 */
export function t10(resultat, fichierAncres) {
  const t7 = resultat.checks["T-7"];
  if (t7 !== "reussi") return { statut: "non_execute", raison: t7 === "echoue" ? "prerequis_en_echec" : resultat.raisons["T-7"], preuves: [], revocations: [] };
  return verifierRevocation({
    chemin: resultat.chemin,
    autorite: { nom: resultat.autorite.nom, certificat: resultat.autorite.certificat, identite: resultat.identite },
    crls: fichierAncres ? fichierAncres.revocation.crls : [],
    crlsJeton: resultat.jeton.crls,
    declarations: fichierAncres ? fichierAncres.revocation.statements : [],
    aInstant: resultat.tstInfo.genTime,
  });
}

/** Marque l'essai courant en attente avec sa condition dans le titre. */
export function enAttente(ctx, condition) {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
}

/** `openssl` est disponible. */
export function opensslDisponible() {
  try {
    execFileSync("openssl", ["version"], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}
