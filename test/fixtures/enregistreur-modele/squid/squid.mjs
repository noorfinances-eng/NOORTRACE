// Outils de l'épreuve d'intégration ICAP TI-19 de CT-9 (CT-2 §19.6, CT-8
// EX-5.4) : image Squid avec OpenSSL et ssl-bump (Dockerfile de ce
// répertoire), autorités de test (interception, fournisseur simulé),
// configuration de Squid (ssl-bump, services ICAP REQMOD et RESPMOD,
// `icap_send_client_ip`), lancement du conteneur, relais d'écoute du lien
// ICAP en clair (les octets de chaque sens sont gardés pour relever `ISTag`,
// les statuts et la requête encapsulée par RESPMOD), et client qui traverse
// Squid par CONNECT. Clés jetables, sans valeur ; `openssl` et Docker requis.

import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const ICI = path.dirname(fileURLToPath(import.meta.url));
/** Image construite par le Dockerfile de ce répertoire (Squid 6.13, Debian squid-openssl 6.13-2+deb13u3). */
export const IMAGE_SQUID = "noortrace/squid-openssl:6.13-2-deb13u3";
export const VERSION_SQUID = "squid-openssl 6.13-2+deb13u3 (Squid 6.13, Debian 13)";
/** Module chargé par `--import` dans le démon : `*.example` → 127.0.0.1. */
export const RESOLUTION_EXAMPLE = path.join(ICI, "resolution-example.mjs");
/** Nom du fournisseur simulé, sous le domaine réservé `.example`. */
export const NOM_FOURNISSEUR = "api.fournisseur.example";
/** Nombre d'essais d'un lancement dont le port choisi était pris. */
const ESSAIS_PORTS = 5;

/**
 * Docker répond-il, et l'image Squid est-elle présente ou constructible ?
 * Sans mandataire sortant, l'archive Debian est lue en http ; derrière un
 * mandataire à inspection TLS (HTTPS_PROXY, autorité dans SSL_CERT_FILE ou
 * NODE_EXTRA_CA_CERTS), en https avec cette autorité passée en secret de
 * construction, jamais copiée dans l'image.
 * @returns {{ok: boolean, condition: string|null}}
 */
export function imageSquid() {
  const v = spawnSync("docker", ["info", "--format", "{{.ServerVersion}}"], { encoding: "utf8" });
  if (v.status !== 0) return { ok: false, condition: "Docker absent ou démon dockerd injoignable" };
  if (spawnSync("docker", ["image", "inspect", IMAGE_SQUID], { encoding: "utf8" }).status === 0) return { ok: true, condition: null };
  const args = ["build", "--network", "host", "-t", IMAGE_SQUID];
  const mandataire = process.env.HTTPS_PROXY ?? process.env.https_proxy ?? null;
  const autorite = [process.env.SSL_CERT_FILE, process.env.NODE_EXTRA_CA_CERTS].find((f) => f && fs.existsSync(f)) ?? null;
  if (mandataire) args.push("--build-arg", `HTTPS_PROXY=${mandataire}`);
  if (mandataire && autorite) args.push("--secret", `id=autorite_sortante,src=${autorite}`);
  const b = spawnSync("docker", [...args, ICI], { encoding: "utf8", timeout: 900000 });
  if (b.status !== 0) return { ok: false, condition: `image ${IMAGE_SQUID} non construite (docker build en échec : ${`${b.stderr ?? ""}`.trim().split("\n").at(-1) ?? ""})` };
  return { ok: true, condition: null };
}

/** `openssl` est-il disponible ? */
export function opensslDisponible() {
  return spawnSync("openssl", ["version"], { encoding: "utf8" }).status === 0;
}

const ossl = (args, cwd) => execFileSync("openssl", args, { cwd, stdio: "pipe" });

/**
 * Autorité d'interception de Squid (rôle de CT-7 CLE-27, ici jetable) et
 * autorité du fournisseur simulé avec son certificat serveur pour
 * NOM_FOURNISSEUR. Fichiers lisibles par l'utilisateur `proxy` du conteneur.
 * @param {string} dir
 */
export function autorites(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const ca = (nom, cn) =>
    ossl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", `${nom}.key`, "-out", `${nom}.pem`, "-days", "2", "-subj", `/CN=${cn}`,
      "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], dir);
  ca("interception", "autorite-interception-de-test");
  ca("ca-fournisseur", "autorite-fournisseur-de-test");
  fs.writeFileSync(path.join(dir, "fournisseur.ext"), `subjectAltName=DNS:${NOM_FOURNISSEUR}\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n`);
  ossl(["req", "-newkey", "rsa:2048", "-nodes", "-keyout", "fournisseur.key", "-out", "fournisseur.csr", "-subj", `/CN=${NOM_FOURNISSEUR}`], dir);
  ossl(["x509", "-req", "-in", "fournisseur.csr", "-CA", "ca-fournisseur.pem", "-CAkey", "ca-fournisseur.key", "-CAcreateserial", "-out", "fournisseur.pem", "-days", "2", "-extfile", "fournisseur.ext"], dir);
  for (const n of fs.readdirSync(dir)) fs.chmodSync(path.join(dir, n), 0o644);
  const p = (n) => path.join(dir, n);
  return { dir, interception: p("interception.pem"), interceptionCle: p("interception.key"), caFournisseur: p("ca-fournisseur.pem"), fournisseur: p("fournisseur.pem"), fournisseurCle: p("fournisseur.key") };
}

/**
 * squid.conf de l'épreuve : ssl-bump (peek puis bump) avec l'autorité
 * d'interception, confiance sortante dans la seule autorité du fournisseur
 * simulé, services ICAP REQMOD et RESPMOD vers `icap://127.0.0.1:<portIcap>`
 * (CT-2 §19.6 : un service par méthode, adaptation limitée à la destination
 * du fournisseur), adresse du client transmise (`icap_send_client_ip on` :
 * en-tête `X-Client-IP`, CT-2 EX-5.8), aucun contournement (`bypass=off`),
 * aucun cache. Les chemins sont ceux du montage dans le conteneur.
 */
export function confSquid({ port, portIcap }) {
  const m = "/etc/squid/noortrace";
  return [
    `http_port 127.0.0.1:${port} ssl-bump tls-cert=${m}/interception.pem tls-key=${m}/interception.key generate-host-certificates=on dynamic_cert_mem_cache_size=4MB`,
    "sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/spool/squid/ssl_db -M 4MB",
    "sslcrtd_children 2 startup=1 idle=1",
    "acl etape1 at_step SslBump1",
    "ssl_bump peek etape1",
    "ssl_bump bump all",
    `tls_outgoing_options cafile=${m}/ca-fournisseur.pem`,
    `acl fournisseurs dstdomain ${NOM_FOURNISSEUR}`,
    // Le tunnel CONNECT n'est pas un échange : seules les requêtes déchiffrées sont adaptées.
    "acl CONNECT method CONNECT",
    "http_access allow localhost",
    "http_access deny all",
    "icap_enable on",
    "icap_send_client_ip on",
    "icap_persistent_connections on",
    "icap_service_failure_limit -1",
    `icap_service service_reqmod reqmod_precache icap://127.0.0.1:${portIcap}/noortrace/reqmod bypass=off`,
    `icap_service service_respmod respmod_precache icap://127.0.0.1:${portIcap}/noortrace/respmod bypass=off`,
    "adaptation_access service_reqmod deny CONNECT",
    "adaptation_access service_reqmod allow fournisseurs",
    "adaptation_access service_reqmod deny all",
    "adaptation_access service_respmod deny CONNECT",
    "adaptation_access service_respmod allow fournisseurs",
    "adaptation_access service_respmod deny all",
    "cache deny all",
    "pid_filename none",
    "visible_hostname squid-ti19",
    // Journaux dans /var/log/squid, inscriptible par l'utilisateur `proxy`.
    "access_log stdio:/var/log/squid/access.log",
    "cache_log /var/log/squid/cache.log",
    "logfile_rotate 0",
    "shutdown_lifetime 1 seconds",
    "coredump_dir /var/spool/squid",
    "",
  ].join("\n");
}

/** Port TCP libre de la boucle locale, au moment de l'appel seulement (voir lancerSquid). */
function portLibre() {
  return new Promise((res) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
}

const ecoute = (port) =>
  new Promise((res) => {
    const s = net.connect({ host: "127.0.0.1", port }, () => {
      s.destroy();
      res(true);
    });
    s.on("error", () => res(false));
  });

/** Arrête et supprime le conteneur, avec ses volumes anonymes. */
export function arreterSquid(nom) {
  spawnSync("docker", ["rm", "-f", "-v", nom], { encoding: "utf8" });
}

/**
 * Lance Squid (réseau de l'hôte : il joint le relais ICAP et le fournisseur
 * simulé sur 127.0.0.1 ; NOM_FOURNISSEUR résolu par --add-host) et attend
 * qu'il écoute. Le port d'écoute est choisi libre ; s'il a été pris avant
 * l'ouverture par Squid, un autre est choisi, au plus ESSAIS_PORTS essais.
 * @param {string} nom conteneur
 * @param {string} dirConf répertoire monté (autorités, squid.conf écrit ici)
 * @param {number} portIcap port du relais ICAP
 * @returns {Promise<{nom: string, port: number, journal: () => string}>}
 */
export async function lancerSquid(nom, dirConf, portIcap) {
  for (let essai = 1; ; essai++) {
    const port = await portLibre();
    fs.writeFileSync(path.join(dirConf, "squid.conf"), confSquid({ port, portIcap }), { mode: 0o644 });
    arreterSquid(nom);
    execFileSync("docker", ["run", "-d", "--name", nom, "--network", "host", "--add-host", `${NOM_FOURNISSEUR}:127.0.0.1`,
      "-v", `${dirConf}:/etc/squid/noortrace:ro`, "-e", "SQUID_CONF=/etc/squid/noortrace/squid.conf", IMAGE_SQUID], { encoding: "utf8" });
    // Sortie du conteneur (avant l'abandon des privilèges), puis journaux de Squid.
    const journal = () => {
      const r = spawnSync("docker", ["logs", nom], { encoding: "utf8" });
      const j = spawnSync("docker", ["exec", nom, "cat", "/var/log/squid/cache.log", "/var/log/squid/access.log"], { encoding: "utf8" });
      return `${r.stdout ?? ""}${r.stderr ?? ""}${j.stdout ?? ""}`;
    };
    const limite = Date.now() + 60000;
    for (;;) {
      const etat = spawnSync("docker", ["inspect", "-f", "{{.State.Running}}", nom], { encoding: "utf8" }).stdout.trim();
      if (etat !== "true") break;
      if ((await ecoute(port)) && /Accepting (SSL bumped )?HTTP Socket connections/.test(journal())) return { nom, port, journal };
      if (Date.now() > limite) throw new Error(`Squid n'écoute pas : ${journal().slice(-3000)}`);
      await new Promise((r) => setTimeout(r, 200));
    }
    const sortie = journal();
    arreterSquid(nom);
    if (essai < ESSAIS_PORTS && /Address already in use|EADDRINUSE|Cannot open HTTP Port/i.test(sortie)) continue;
    throw new Error(`Squid arrêté : ${sortie.slice(-3000)}`);
  }
}

/**
 * Relais du lien ICAP en clair (127.0.0.1) entre Squid et le serveur ICAP du
 * démon : chaque connexion est transmise telle quelle à la cible courante, et
 * les octets de chaque sens sont gardés. `viser(port)` change la cible des
 * connexions suivantes et coupe les connexions ouvertes.
 */
export async function relaisIcap() {
  const r = { cible: null, connexions: [], ouvertes: new Set() };
  const serveur = net.createServer((client) => {
    const c = { client: [], serveur: [] };
    r.connexions.push(c);
    const amont = net.connect({ host: "127.0.0.1", port: r.cible });
    r.ouvertes.add(client);
    r.ouvertes.add(amont);
    const fin = () => {
      client.destroy();
      amont.destroy();
      r.ouvertes.delete(client);
      r.ouvertes.delete(amont);
    };
    client.on("data", (d) => {
      c.client.push(d);
      amont.write(d);
    });
    amont.on("data", (d) => {
      c.serveur.push(d);
      client.write(d);
    });
    client.on("end", () => amont.end());
    amont.on("end", () => client.end());
    client.on("error", fin);
    amont.on("error", fin);
    client.on("close", fin);
    amont.on("close", fin);
  });
  await new Promise((ok) => serveur.listen(0, "127.0.0.1", ok));
  return {
    port: serveur.address().port,
    viser(port) {
      r.cible = port;
      for (const s of r.ouvertes) s.destroy();
      r.ouvertes.clear();
    },
    /** Marque le début d'une phase : `messages(depuis)` ne rend que les connexions ouvertes ensuite. */
    marque: () => r.connexions.length,
    messages: (depuis = 0) => r.connexions.slice(depuis).map((c) => analyserConnexion(Buffer.concat(c.client).toString("latin1"), Buffer.concat(c.serveur).toString("latin1"))),
    fermer: () =>
      new Promise((ok) => {
        for (const s of r.ouvertes) s.destroy();
        serveur.close(() => ok());
      }),
  };
}

/** En-têtes d'un bloc (première ligne, puis `Nom: valeur`), noms en minuscules. */
function bloc(texte) {
  const [premiere, ...lignes] = texte.split("\r\n");
  const entetes = {};
  for (const l of lignes) {
    const k = l.indexOf(":");
    if (k > 0) entetes[l.slice(0, k).trim().toLowerCase()] = l.slice(k + 1).trim();
  }
  return { premiere, entetes };
}

/**
 * Messages ICAP d'une connexion : requêtes du client (méthode, en-têtes ICAP,
 * en-tête HTTP encapsulé `req-hdr` s'il y en a) et réponses du serveur
 * (statut, en-têtes ICAP), dans l'ordre ; les réponses `100 Continue` sont
 * gardées à part. Chaque message commence en début de ligne.
 */
function analyserConnexion(client, serveur) {
  const requetes = [];
  for (const m of client.matchAll(/(?:^|\r\n)((OPTIONS|REQMOD|RESPMOD) icap:\/\/[^\r\n]* ICAP\/1\.0)\r\n/g)) {
    const debut = m.index + (m[0].startsWith("\r\n") ? 2 : 0);
    const finEntete = client.indexOf("\r\n\r\n", debut);
    if (finEntete < 0) continue;
    const icap = bloc(client.slice(debut, finEntete));
    let reqHdr = null;
    const enc = icap.entetes.encapsulated ?? "";
    if (/(^|,\s*)req-hdr=0/.test(enc)) {
      const finReq = client.indexOf("\r\n\r\n", finEntete + 4);
      if (finReq > 0) reqHdr = bloc(client.slice(finEntete + 4, finReq));
    }
    requetes.push({ methode: m[2], icap, reqHdr });
  }
  const reponses = [];
  const continues = [];
  for (const m of serveur.matchAll(/(?:^|\r\n)(ICAP\/1\.0 ([0-9]{3})[^\r\n]*)\r\n/g)) {
    const debut = m.index + (m[0].startsWith("\r\n") ? 2 : 0);
    const finEntete = serveur.indexOf("\r\n\r\n", debut);
    if (finEntete < 0) continue;
    const r = { statut: Number(m[2]), ...bloc(serveur.slice(debut, finEntete)) };
    (r.statut === 100 ? continues : reponses).push(r);
  }
  return { requetes, reponses, continues };
}

/**
 * Requête HTTPS qui traverse Squid : CONNECT vers `hote:port`, TLS avec
 * l'autorité d'interception (Squid présente un certificat qu'il a généré),
 * puis la requête. Rend { statut, entetes, corps (Buffer) }.
 */
export function appelParSquid(portSquid, { hote = NOM_FOURNISSEUR, port, chemin, entetes, corps, ca }) {
  return new Promise((res, rej) => {
    const c = http.request({ host: "127.0.0.1", port: portSquid, method: "CONNECT", path: `${hote}:${port}`, headers: { host: `${hote}:${port}` } });
    c.on("connect", (r, socket) => {
      if (r.statusCode !== 200) {
        socket.destroy();
        return rej(new Error(`CONNECT refusé par Squid : ${r.statusCode}`));
      }
      const t = tls.connect({ socket, servername: hote, ca: fs.readFileSync(ca) });
      // Agent propre à cette requête : sa connexion est le tunnel TLS ouvert dans Squid (aucune résolution du nom ici).
      const agent = new https.Agent({ keepAlive: false });
      agent.createConnection = () => t;
      const q = https.request({ host: hote, port, path: chemin, method: "POST", headers: { host: `${hote}:${port}`, ...entetes }, agent }, (x) => {
        const m = [];
        x.on("data", (k) => m.push(k));
        x.on("end", () => {
          t.destroy();
          res({ statut: x.statusCode, entetes: x.headers, corps: Buffer.concat(m) });
        });
      });
      q.on("error", rej);
      q.end(corps);
    });
    c.on("error", rej);
    c.end();
  });
}
