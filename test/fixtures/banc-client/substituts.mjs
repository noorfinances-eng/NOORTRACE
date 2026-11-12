// Substituts locaux du banc « client fictif » de l'étape 7 (étape 7 ; inventaire
// de l'étape 7, section 2.3) : chaque dépendance externe d'une installation
// complète de production (CT-8 §5, FL-) est remplacée par un service local,
// servi sur l'adresse interne de l'hôte de banc (une adresse RFC 5737 portée
// par une interface de l'hôte, ou 127.0.0.1), sous un nom `.example` que les
// conteneurs résolvent par `extra_hosts` et l'hôte par son fichier des hôtes :
//
// - autorité TLS d'essai (openssl, boîte noire) : un certificat de serveur
//   pour tous les noms du banc, un certificat de client (TLS mutuel des
//   prestataires RFC 3161) ;
// - deux prestataires RFC 3161 (serveur interne de `paquets/ancrage`, TLS
//   mutuel, AN-27), rôles `principal` et `secours`, statut `qualified`
//   déclaratif d'exemple, et leur serveur de CRL ;
// - deux calendriers OpenTimestamps factices en TLS (promesses ; chaîne
//   regtest d'en-têtes tenue à jour) ;
// - KMS et S3 à verrouillage d'objets simulés par LocalStack (image des
//   essais, épinglée par condensé), derrière deux mandataires TLS ;
// - registre : réseau de développement 2124 (chain/scripts/dev-net.sh),
//   derrière un mandataire TLS ;
// - fournisseur OIDC des essais de la console, récepteur de webhook (HMAC
//   recalculé).
//
// Aucun de ces services ne joint un réseau public. Les clés d'essai sont
// tirées au moment de l'essai et n'existent que sous le répertoire de travail.

import fs from "node:fs";
import net from "node:net";
import tls from "node:tls";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { Noeud, attestationEnAttente, ecrireTimestamp } from "@noortrace/ancrage/ots";
import { initialiserAutorite, chargerAutorite, publierCrl, CompteurMemoire, demarrerServeur } from "@noortrace/ancrage/serveur-interne";
import { chaineRegtest } from "../ancrage-ots/outils.mjs";
import { aleatoireFixe, qualifiedExemple } from "../ancrage-composant/outils.mjs";
import { IMAGES } from "../enregistreur-worm/outils.mjs";
import { demarrerFournisseur } from "../exploitation-console/fournisseur-oidc.mjs";

/** Noms du banc (domaines réservés `.example`, RFC 2606). */
export const NOMS = Object.freeze({
  kms: "kms.eu-central-2.amazonaws.example",
  s3: "s3.organisation-exemple.example",
  rpc: "registre.organisation-exemple.example",
  tsaPrincipal: "horodatage.prestataire-qualifie.example",
  tsaSecours: "horodatage.prestataire-secours.example",
  crl: "crl.organisation-exemple.example",
  calendrierA: "a.calendrier.example",
  calendrierB: "b.calendrier.example",
  oidc: "identite.organisation-exemple.example",
  webhook: "relais.organisation-exemple.example",
  console: "console.organisation-exemple.example",
  modeleInterdit: "modele.fournisseur-interdit.example",
});

/** Ports du banc sur l'adresse interne (aucun n'est publié par production.yaml). */
export const PORTS = Object.freeze({
  kms: 4443, s3: 4444, rpc: 4445, tsaPrincipal: 4446, tsaSecours: 4447, crl: 4448, calendrierA: 4449, calendrierB: 4450, webhook: 4451,
});

/** Image de LocalStack des essais (KMS et S3 à verrouillage d'objets). */
export const IMAGE_LOCALSTACK = IMAGES.s3;

/** Lance une commande, rend `{ code, stdout, stderr }`. */
export function lancer(commande, args, o = {}) {
  const r = spawnSync(commande, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, ...o });
  return { code: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", erreur: r.error ?? null };
}

/** Attend qu'une condition (éventuellement asynchrone) soit vraie, ou lève après `delaiMs`. */
export async function attendre(cond, delaiMs = 60000, description = "condition", pasMs = 500) {
  const limite = Date.now() + delaiMs;
  let derniere = null;
  for (;;) {
    try {
      const v = await cond();
      if (v) return v;
    } catch (e) {
      derniere = e;
    }
    if (Date.now() > limite) throw new Error(`${description} : non atteinte en ${delaiMs} ms${derniere ? ` (${derniere.message})` : ""}`);
    await new Promise((r) => setTimeout(r, pasMs));
  }
}

// ------------------------------------------------------------------ PKI

/**
 * Autorité TLS d'essai, certificat de serveur pour tous les noms du banc
 * (plus `approbation`, nom du service sur le réseau `console`, et
 * `enregistreur`), certificat de client (TLS mutuel). Clés EC P-256.
 * @param {string} dir
 * @param {string} ipInterne
 */
export function pki(dir, ipInterne) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const o = (args) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  const ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"];
  o(["req", "-x509", ...ec, "-keyout", "ca.key", "-out", "ca.pem", "-days", "7", "-subj", "/O=organisation-exemple (banc)/CN=AC TLS du banc client fictif"]);
  const noms = [...Object.values(NOMS), "approbation", "enregistreur", "pont-fichiers"];
  const san = [...noms.map((n) => `DNS:${n}`), `IP:${ipInterne}`, "IP:127.0.0.1"].join(",");
  o(["req", ...ec, "-keyout", "serveur.key", "-out", "serveur.csr", "-subj", "/O=organisation-exemple (banc)/CN=serveurs du banc"]);
  fs.writeFileSync(path.join(dir, "ext-serveur.cnf"), `subjectAltName=${san}\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n`);
  o(["x509", "-req", "-in", "serveur.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "serveur.pem", "-days", "7", "-extfile", "ext-serveur.cnf"]);
  o(["req", ...ec, "-keyout", "client.key", "-out", "client.csr", "-subj", "/O=organisation-exemple (banc)/CN=enregistreur du client fictif"]);
  fs.writeFileSync(path.join(dir, "ext-client.cnf"), "basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n");
  o(["x509", "-req", "-in", "client.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "client.pem", "-days", "7", "-extfile", "ext-client.cnf"]);
  for (const f of fs.readdirSync(dir)) if (/\.(key|csr|srl|cnf)$/.test(f)) fs.chmodSync(path.join(dir, f), 0o600);
  const lire = (n) => fs.readFileSync(path.join(dir, n));
  return {
    dir,
    ca: lire("ca.pem"),
    cert: lire("serveur.pem"),
    key: lire("serveur.key"),
    clientCert: lire("client.pem"),
    clientKey: lire("client.key"),
    /** Chaîne PEM « certificat puis clé » (forme des secrets `tls-*` de CT-8 IC-8). */
    serveurPem: Buffer.concat([lire("serveur.pem"), lire("serveur.key")]),
    clientPem: Buffer.concat([lire("client.key"), lire("client.pem")]),
  };
}

// ------------------------------------------------------- relais réseau

const fermerServeur = (s, sockets) => new Promise((r) => {
  for (const x of sockets) x.destroy();
  s.close(() => r());
});

/** Relais TCP `hote:port` → `cible` (sans terminaison : TLS de bout en bout). */
export function relaisTcp({ hote, port, cible }) {
  const sockets = new Set();
  const s = net.createServer((c) => {
    const d = net.connect(cible.port, cible.hote ?? "127.0.0.1");
    for (const x of [c, d]) {
      sockets.add(x);
      x.on("close", () => sockets.delete(x));
      x.on("error", () => {
        c.destroy();
        d.destroy();
      });
    }
    c.pipe(d).pipe(c);
  });
  return new Promise((ok, ko) => {
    s.once("error", ko);
    s.listen(port, hote, () => ok({ hote, port, fermer: () => fermerServeur(s, sockets) }));
  });
}

/** Mandataire TLS (terminaison, certificat du banc) `hote:port` → `cible` en clair. */
export function mandataireTls({ hote, port, pkiBanc, cible }) {
  const sockets = new Set();
  const s = tls.createServer({ cert: pkiBanc.cert, key: pkiBanc.key, minVersion: "TLSv1.2" }, (c) => {
    const d = net.connect(cible.port, cible.hote ?? "127.0.0.1");
    for (const x of [c, d]) {
      sockets.add(x);
      x.on("close", () => sockets.delete(x));
      x.on("error", () => {
        c.destroy();
        d.destroy();
      });
    }
    c.pipe(d).pipe(c);
  });
  return new Promise((ok, ko) => {
    s.once("error", ko);
    s.listen(port, hote, () => ok({ hote, port, fermer: () => fermerServeur(s, sockets) }));
  });
}

// --------------------------------------------------- RFC 3161 et CRL

/** Serveur de CRL du banc (HTTP, `GET /<nom>/crl.pem`, CRL republiée à l'instant). */
export async function serveurCrl({ hote, port }) {
  const autorites = new Map();
  const s = http.createServer((req, rep) => {
    const m = /^\/([a-z0-9-]+)\/crl\.pem$/.exec(req.url ?? "");
    const a = m ? autorites.get(m[1]) : null;
    if (!a) {
      rep.writeHead(404);
      rep.end();
      return;
    }
    const r = publierCrl({ repertoire: a, horloge: { murale: () => Date.now() }, revoques: [] });
    rep.writeHead(200, { "content-type": "application/pkix-crl" });
    rep.end(Buffer.from(r.octets));
  });
  await new Promise((ok, ko) => {
    s.once("error", ko);
    s.listen(port, hote, ok);
  });
  return {
    url: (nom) => `http://${NOMS.crl}:${port}/${nom}/crl.pem`,
    declarer: (nom, repertoire) => autorites.set(nom, repertoire),
    fermer: () => fermerServeur(s, new Set()),
  };
}

/**
 * Prestataire RFC 3161 du banc : autorité du serveur interne de
 * `paquets/ancrage` (P-256), servie en TLS avec authentification du client
 * (AN-27) sur l'adresse interne, sous un nom `.example`. Rend le membre
 * `rfc3161.providers[]` d'`ancrage-v0` (secret du certificat de client à
 * l'emplacement que monte production.yaml).
 */
export async function prestataireRfc3161({ nom, role, hote, port, nomDns, dir, crl, pkiBanc, secret, politique }) {
  const repertoire = path.join(dir, nom);
  crl.declarer(nom, repertoire);
  const horloge = { murale: () => Date.now() };
  const init = initialiserAutorite({
    repertoire, algorithme: "p-256", politique, crlUrl: crl.url(nom), validiteJours: 365, horloge: { murale: () => Date.now() - 86400000 }, aleatoire: aleatoireFixe(Date.now() % 1000),
    sujetAc: { O: "organisation-exemple (banc)", CN: `AC ${nom} (banc)` }, sujetUnite: { O: "organisation-exemple (banc)", CN: `TSA ${nom} (banc, non qualifiee)` },
  });
  const autorite = chargerAutorite({ repertoire, compteur: new CompteurMemoire(1n) });
  const lignes = [];
  const serveur = await demarrerServeur({
    autorite, horloge,
    ecoute: { tls: { cle: pkiBanc.key, certificat: pkiBanc.cert, acClients: pkiBanc.ca, hote, port } },
    journal: { consigner: (niveau, evenement, data) => lignes.push({ niveau, evenement, data }) },
  });
  const prestataire = {
    id: nom,
    role,
    url: `https://${nomDns}:${port}`,
    auth: { method: "certificat_client", secret: { file: secret } },
    hash: "sha256",
    policy_oid: politique,
    accepted_policies: [politique],
    anchor_certificates: [init.acPem],
    qualified: qualifiedExemple("AT"),
    min_interval_ms: 0,
    request_timeout_ms: 10000,
    correlation_header: "X-Request-ID",
    source: `prestataire du banc client fictif (serveur interne de paquets/ancrage, ${nom}), statut qualifié déclaratif d'exemple, sans valeur hors du banc`,
  };
  return { nom, repertoire, init, prestataire, lignes, fermer: () => serveur.fermer() };
}

// ------------------------------------------- calendriers OpenTimestamps

/**
 * Deux calendriers factices en TLS sur l'adresse interne : `POST /digest`
 * rend une promesse (attestation en attente de l'URI du calendrier),
 * `GET /timestamp/<e>` rend 404 « Pending » (aucune chaîne Bitcoin : le
 * contrôle 5 attend la mise à niveau, CT-8 IC-15). Le fichier d'en-têtes
 * regtest est écrit pour `headers_source`.
 */
export async function calendriers({ hote, pkiBanc, fichierEntetes }) {
  fs.writeFileSync(fichierEntetes, `${JSON.stringify(chaineRegtest({ debut: 0, nombre: 1040, racines: new Map() }).document, null, 2)}\n`);
  const requetes = [];
  const serveurs = [];
  const uris = [];
  for (const [nom, port] of [[NOMS.calendrierA, PORTS.calendrierA], [NOMS.calendrierB, PORTS.calendrierB]]) {
    const uri = `https://${nom}:${port}`;
    const s = https.createServer({ key: pkiBanc.key, cert: pkiBanc.cert }, (req, rep) => {
      const morceaux = [];
      req.on("data", (d) => morceaux.push(d));
      req.on("end", () => {
        const corps = Buffer.concat(morceaux);
        requetes.push({ uri, methode: req.method, url: req.url, at: new Date().toISOString() });
        if (req.method === "POST" && req.url === "/digest" && corps.length === 32) {
          const n = new Noeud();
          n.ajouterAttestation(attestationEnAttente(uri));
          rep.writeHead(200, { "content-type": "application/vnd.opentimestamps.v1" });
          rep.end(Buffer.from(ecrireTimestamp(n)));
          return;
        }
        if (req.method === "GET" && /^\/timestamp\/[0-9a-f]{64}$/.test(req.url ?? "")) {
          rep.writeHead(404, { "content-type": "text/plain" });
          rep.end("Pending confirmation in Bitcoin blockchain");
          return;
        }
        rep.writeHead(400);
        rep.end();
      });
    });
    await new Promise((ok, ko) => {
      s.once("error", ko);
      s.listen(port, hote, ok);
    });
    serveurs.push(s);
    uris.push(uri);
  }
  return { uris, requetes, fermer: () => Promise.all(serveurs.map((s) => fermerServeur(s, new Set()))) };
}

// ------------------------------------------------ webhook, OIDC

/** Récepteur du webhook de notifications (HTTPS, HMAC d'EX-13.41 recalculé sur les octets reçus). */
export async function recepteurWebhook({ hote, port, pkiBanc, cle }) {
  const recues = [];
  const s = https.createServer({ key: pkiBanc.key, cert: pkiBanc.cert }, (req, rep) => {
    const morceaux = [];
    req.on("data", (d) => morceaux.push(d));
    req.on("end", () => {
      const octets = Buffer.concat(morceaux);
      const attendu = `sha256=${crypto.createHmac("sha256", Buffer.from(cle, "utf8")).update(Buffer.concat([Buffer.from("noortrace/notification/v0\n", "utf8"), octets])).digest("hex")}`;
      const signature = req.headers["noortrace-signature"] ?? null;
      let document = null;
      try {
        document = JSON.parse(octets.toString("utf8"));
      } catch {
        document = null;
      }
      recues.push({ at: new Date().toISOString(), chemin: req.url, signature_valide: signature === attendu, document });
      rep.writeHead(204);
      rep.end();
    });
  });
  await new Promise((ok, ko) => {
    s.once("error", ko);
    s.listen(port, hote, ok);
  });
  return { url: `https://${NOMS.webhook}:${port}/noortrace/notifications`, recues, fermer: () => fermerServeur(s, new Set()) };
}

/** Fournisseur OIDC des essais de la console, servi sous `NOMS.oidc` (relais de l'adresse interne vers la boucle locale). */
export async function fournisseurOidc({ hote, pkiBanc, clientId, secret }) {
  const f = await demarrerFournisseur({ cert: pkiBanc.cert, key: pkiBanc.key, clientId, secret, hote: NOMS.oidc });
  const port = Number(new URL(f.url).port);
  const relais = hote === "127.0.0.1" ? null : await relaisTcp({ hote, port, cible: { hote: "127.0.0.1", port } });
  return { fournisseur: f, issuer: f.issuer, fermer: async () => {
    await relais?.fermer();
    await f.fermer?.();
  } };
}

// ------------------------------------------------------ LocalStack

/**
 * LocalStack (KMS et S3) dans un conteneur, publié sur la boucle locale ;
 * deux mandataires TLS sur l'adresse interne. Rend les origines HTTPS du
 * banc et l'origine locale.
 */
export async function localStack({ nom, hote, pkiBanc }) {
  lancer("docker", ["rm", "-f", "-v", nom]);
  const r = lancer("docker", ["run", "-d", "--name", nom, "-p", "127.0.0.1::4566", "-e", "SERVICES=kms,s3", "-e", "EAGER_SERVICE_LOADING=1", IMAGE_LOCALSTACK]);
  if (r.code !== 0) throw new Error(`LocalStack : docker run a échoué : ${r.stderr.trim()}`);
  const port = Number(lancer("docker", ["port", nom, "4566/tcp"]).stdout.trim().split("\n")[0].split(":").pop());
  const locale = `http://127.0.0.1:${port}`;
  await attendre(async () => {
    const x = await fetch(`${locale}/_localstack/health`).catch(() => null);
    if (!x?.ok) return false;
    const j = await x.json();
    return ["running", "available"].includes(j.services?.kms) && ["running", "available"].includes(j.services?.s3);
  }, 180000, "LocalStack prêt (kms, s3)");
  const kms = await mandataireTls({ hote, port: PORTS.kms, pkiBanc, cible: { port } });
  const s3 = await mandataireTls({ hote, port: PORTS.s3, pkiBanc, cible: { port } });
  return {
    nom, locale,
    origineKms: `https://${NOMS.kms}:${PORTS.kms}`,
    origineS3: `https://${NOMS.s3}:${PORTS.s3}`,
    fermer: async () => {
      await kms.fermer();
      await s3.fermer();
      lancer("docker", ["rm", "-f", "-v", nom]);
    },
  };
}

/** Empreinte hexadécimale (0x…) d'un fichier. */
export const sha256Fichier = (f) => `0x${crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex")}`;

export { N };
