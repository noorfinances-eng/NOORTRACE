// Outils des tests du lot WORM et haute disponibilité
// (test/enregistreur-worm-*.test.js, test/enregistreur-ha-*.test.js) :
// services réels lancés dans Docker, images épinglées par condensé ;
// certificats de test générés à l'exécution par openssl (adresse 127.0.0.1) ;
// mandataire TLS devant le service S3 (le schéma n'admet qu'une origine
// HTTPS pour `storage.seal.worm.endpoint`) ; mandataire TCP coupable pour
// simuler une partition réseau ; création d'un bucket verrouillé par
// l'exploitant (EX-12.30).
//
// Services : LocalStack (S3 avec Object Lock : versions, rétention par défaut
// en mode COMPLIANCE ou GOVERNANCE, legal hold, écritures conditionnelles
// `If-None-Match`, `Content-MD5`), PostgreSQL 16 et etcd 3.5. LocalStack
// n'applique pas les politiques d'accès : le contrôle des rôles (EX-12.32,
// EX-18.9) se fait contre MinIO (image d'un registre public, épinglée par
// condensé : MinIO DEVELOPMENT.2025-07-23T15-54-02Z, qui contient `mc`),
// qui applique les politiques IAM et Object Lock.

import fs from "node:fs";
import net from "node:net";
import tls from "node:tls";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { AccesS3, requeteS3ConfigurationVerrou } from "@noortrace/enregistreur";

/** Images épinglées par condensé. */
export const IMAGES = Object.freeze({
  s3: "mirror.gcr.io/localstack/localstack@sha256:17c2f79ca4e1f804eb912291a19713d4134806325ef0d21d4c1053161dfa72d0",
  postgresql: "mirror.gcr.io/library/postgres@sha256:e62fbf9d3e2b49816a32c400ed2dba83e3b361e6833e624024309c35d334b412",
  etcd: "gcr.io/etcd-development/etcd@sha256:15b1882f07aeaf357a48fbbcf35a566ae3ea110395704711488ea263fa86838d",
  s3iam: "mirror.gcr.io/bitnamilegacy/minio@sha256:8935e75fa5d11295c17171e4aa49efe390a1193cd7f12e4d21b92af9ffef09d7",
});

const lances = new Set();

/**
 * Docker et les images sont-ils disponibles ? `{ ok, condition }`, la
 * condition manquante nommée pour le titre d'un test mis en attente.
 * @param {string[]} images
 */
export function dockerDisponible(images = Object.values(IMAGES)) {
  const v = spawnSync("docker", ["info", "--format", "{{.ServerVersion}}"], { encoding: "utf8" });
  if (v.status !== 0) return { ok: false, condition: "Docker absent ou démon dockerd injoignable" };
  for (const i of images) {
    if (spawnSync("docker", ["image", "inspect", i], { encoding: "utf8" }).status === 0) continue;
    const p = spawnSync("docker", ["pull", i], { encoding: "utf8", timeout: 600000 });
    if (p.status !== 0) return { ok: false, condition: `image ${i} indisponible (docker pull en échec)` };
  }
  return { ok: true, condition: null };
}

function portLibre() {
  return new Promise((res) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
}

async function attendre(f, delaiMs = 60000, pasMs = 250) {
  const limite = Date.now() + delaiMs;
  let derniere;
  while (Date.now() < limite) {
    try {
      const r = await f();
      if (r) return r;
    } catch (e) {
      derniere = e;
    }
    await new Promise((r) => setTimeout(r, pasMs));
  }
  throw new Error(`délai dépassé${derniere ? ` : ${derniere.message}` : ""}`);
}

/** Arrête et supprime un conteneur lancé par ces outils, avec ses volumes anonymes. */
export function arreterConteneur(nom) {
  spawnSync("docker", ["rm", "-f", "-v", nom], { encoding: "utf8" });
  lances.delete(nom);
}

/** Arrête et supprime tous les conteneurs lancés par ces outils (à appeler dans after()). */
export function arreterTout() {
  for (const n of [...lances]) arreterConteneur(n);
}

process.on("exit", () => {
  for (const n of lances) spawnSync("docker", ["rm", "-f", "-v", n]);
});

function lancer(nom, args) {
  arreterConteneur(nom);
  execFileSync("docker", ["run", "-d", "--rm", "--name", nom, ...args], { encoding: "utf8" });
  lances.add(nom);
}

/** Met un conteneur en pause (partition franche) ou le reprend. */
export function suspendre(nom, pause = true) {
  execFileSync("docker", [pause ? "pause" : "unpause", nom]);
}

/**
 * Service S3 à Object Lock (LocalStack) ; rend son origine HTTP locale.
 * @param {string} nom
 * @returns {Promise<{nom: string, port: number, origine: string}>}
 */
export async function demarrerS3(nom) {
  const port = await portLibre();
  lancer(nom, ["-p", `127.0.0.1:${port}:4566`, "-e", "SERVICES=s3", "-e", "EAGER_SERVICE_LOADING=1", IMAGES.s3]);
  await attendre(async () => {
    const r = await fetch(`http://127.0.0.1:${port}/_localstack/health`).catch(() => null);
    if (!r?.ok) return false;
    const j = await r.json();
    return j.services?.s3 === "running" || j.services?.s3 === "available";
  }, 120000);
  return { nom, port, origine: `http://127.0.0.1:${port}` };
}

/**
 * PostgreSQL 16, authentification SCRAM-SHA-256 par mot de passe.
 * @returns {Promise<{nom: string, port: number, dsn: string}>}
 */
export async function demarrerPostgresql(nom) {
  const port = await portLibre();
  lancer(nom, [
    "-p", `127.0.0.1:${port}:5432`,
    "-e", "POSTGRES_USER=noortrace", "-e", "POSTGRES_PASSWORD=mot-de-passe-de-test", "-e", "POSTGRES_DB=bail",
    "-e", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256", "-e", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
    IMAGES.postgresql,
  ]);
  const dsn = `postgresql://noortrace:mot-de-passe-de-test@127.0.0.1:${port}/bail`;
  await attendre(() => spawnSync("docker", ["exec", nom, "pg_isready", "-U", "noortrace", "-h", "127.0.0.1"], { encoding: "utf8" }).status === 0, 90000, 500);
  // Le serveur d'initialisation redémarre une fois : on attend une vraie requête.
  await attendre(() => spawnSync("docker", ["exec", "-e", "PGPASSWORD=mot-de-passe-de-test", nom, "psql", "-U", "noortrace", "-h", "127.0.0.1", "-d", "bail", "-c", "select 1"], { encoding: "utf8" }).status === 0, 90000, 500);
  return { nom, port, dsn };
}

/** Requête SQL dans le conteneur (psql), pour les tests hostiles. */
export function psql(nom, sql) {
  const r = spawnSync("docker", ["exec", "-e", "PGPASSWORD=mot-de-passe-de-test", nom, "psql", "-U", "noortrace", "-h", "127.0.0.1", "-d", "bail", "-At", "-c", sql], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(r.stderr);
  return r.stdout.trim();
}

/**
 * etcd 3.5, un membre, sans TLS (`lease.store.tls: null`).
 * @returns {Promise<{nom: string, port: number, origine: string}>}
 */
export async function demarrerEtcd(nom) {
  const port = await portLibre();
  lancer(nom, [
    "-p", `127.0.0.1:${port}:2379`, IMAGES.etcd,
    "/usr/local/bin/etcd", "--listen-client-urls", "http://0.0.0.0:2379", "--advertise-client-urls", `http://127.0.0.1:${port}`,
  ]);
  const origine = `http://127.0.0.1:${port}`;
  await attendre(async () => (await fetch(`${origine}/health`).catch(() => null))?.ok, 60000);
  return { nom, port, origine };
}

/**
 * Service S3 qui applique les politiques IAM et Object Lock (MinIO) ; le
 * compte racine est le rôle `administrateur` d'`identifiantsRole`.
 * @returns {Promise<{nom: string, port: number, origine: string}>}
 */
export async function demarrerS3Iam(nom) {
  const port = await portLibre();
  const racine = JSON.parse(identifiantsRole("administrateur"));
  lancer(nom, ["-p", `127.0.0.1:${port}:9000`, "-e", `MINIO_ROOT_USER=${racine.access_key_id}`, "-e", `MINIO_ROOT_PASSWORD=${racine.secret_access_key}`, IMAGES.s3iam]);
  const origine = `http://127.0.0.1:${port}`;
  // L'image lance un premier serveur pour sa configuration, l'arrête, puis
  // lance le serveur définitif : attendre la fin de la configuration.
  await attendre(() => /MinIO setup finished/.test(spawnSync("docker", ["logs", nom], { encoding: "utf8" }).stdout + spawnSync("docker", ["logs", nom], { encoding: "utf8" }).stderr), 120000, 500);
  await attendre(async () => (await fetch(`${origine}/minio/health/live`).catch(() => null))?.ok, 120000, 500);
  await attendre(() => spawnSync("docker", ["exec", nom, "mc", "alias", "set", "local", "http://127.0.0.1:9000", racine.access_key_id, racine.secret_access_key], { encoding: "utf8" }).status === 0, 60000, 500);
  return { nom, port, origine };
}

/**
 * Crée l'utilisateur d'un rôle (identifiants d'`identifiantsRole`) et lui
 * attache une politique IAM, par `mc admin` dans le conteneur MinIO.
 * @param {string} nom conteneur
 * @param {string} role
 * @param {object} politique document de politique (Version 2012-10-17)
 */
export async function roleIam(nom, role, politique) {
  const id = JSON.parse(identifiantsRole(role));
  // L'image relance le serveur après sa configuration initiale : une commande
  // refusée faute de connexion est réessayée.
  const mc = async (args, entree) => {
    let r;
    await attendre(() => {
      r = spawnSync("docker", ["exec", "-i", nom, ...args], { encoding: "utf8", input: entree });
      if (r.status !== 0 && !/connection refused|server not initialized/i.test(`${r.stdout}${r.stderr}`)) throw new Error(`${args.join(" ")} : ${r.stdout}${r.stderr}`);
      return r.status === 0;
    }, 60000, 500).catch((e) => {
      throw new Error(`${args.join(" ")} : ${r?.stdout ?? ""}${r?.stderr ?? ""} ${e.message}`);
    });
  };
  await mc(["mc", "admin", "user", "add", "local", id.access_key_id, id.secret_access_key]);
  await mc(["mc", "admin", "policy", "create", "local", `politique-${role}`, "/dev/stdin"], JSON.stringify(politique));
  await mc(["mc", "admin", "policy", "attach", "local", `politique-${role}`, "--user", id.access_key_id]);
}

/**
 * Autorité de test et certificat de serveur pour 127.0.0.1 (openssl).
 * @param {string} dir
 * @returns {{ca: string, cert: string, key: string, caPem: Buffer}}
 */
export function certificats(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const o = (args) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  o(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=autorite de test noortrace"]);
  o(["req", "-newkey", "rsa:2048", "-nodes", "-keyout", "serveur.key", "-out", "serveur.csr", "-subj", "/CN=127.0.0.1"]);
  fs.writeFileSync(path.join(dir, "ext.cnf"), "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n");
  o(["x509", "-req", "-in", "serveur.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "serveur.pem", "-days", "2", "-extfile", "ext.cnf"]);
  return { ca: path.join(dir, "ca.pem"), cert: path.join(dir, "serveur.pem"), key: path.join(dir, "serveur.key"), caPem: fs.readFileSync(path.join(dir, "ca.pem")) };
}

/**
 * Mandataire TLS (terminaison) vers un service TCP local.
 * @returns {Promise<{port: number, origine: string, fermer: () => Promise<void>}>}
 */
export function mandataireTls(c, cible) {
  const sockets = new Set();
  const serveur = tls.createServer({ cert: fs.readFileSync(c.cert), key: fs.readFileSync(c.key) }, (s) => {
    const d = net.connect(cible.port, "127.0.0.1");
    sockets.add(s);
    sockets.add(d);
    s.pipe(d).pipe(s);
    const fin = () => {
      s.destroy();
      d.destroy();
    };
    s.on("error", fin);
    d.on("error", fin);
    s.on("close", () => sockets.delete(s));
    d.on("close", () => sockets.delete(d));
  });
  return new Promise((res) => {
    serveur.listen(0, "127.0.0.1", () => {
      const port = serveur.address().port;
      res({
        port,
        origine: `https://127.0.0.1:${port}`,
        fermer: () => new Promise((r) => {
          for (const s of sockets) s.destroy();
          serveur.close(() => r());
        }),
      });
    });
  });
}

/**
 * Mandataire TCP que le test peut couper (partition réseau simulée) : coupé,
 * il ferme les connexions en cours et laisse les nouvelles sans réponse.
 */
export class PartitionTcp {
  constructor(cible) {
    this.cible = cible;
    this.coupe = false;
    this.sockets = new Set();
  }

  ecouter() {
    this.serveur = net.createServer((s) => {
      this.sockets.add(s);
      s.on("close", () => this.sockets.delete(s));
      s.on("error", () => {});
      if (this.coupe) return;
      const d = net.connect(this.cible.port, "127.0.0.1");
      this.sockets.add(d);
      d.on("close", () => this.sockets.delete(d));
      d.on("error", () => s.destroy());
      s.pipe(d).pipe(s);
    });
    return new Promise((r) => this.serveur.listen(0, "127.0.0.1", () => {
      this.port = this.serveur.address().port;
      r(this.port);
    }));
  }

  couper() {
    this.coupe = true;
    for (const s of this.sockets) s.destroy();
  }

  retablir() {
    this.coupe = false;
  }

  fermer() {
    for (const s of this.sockets) s.destroy();
    return new Promise((r) => this.serveur.close(() => r()));
  }
}

/** Identifiants S3 d'un rôle (LocalStack n'applique pas IAM : la séparation des rôles est portée par les références, EX-12.36). */
export function identifiantsRole(nom) {
  return JSON.stringify({ access_key_id: `test-${nom}`, secret_access_key: `secret-${nom}` });
}

/**
 * Crée le bucket verrouillé et pose la rétention par défaut, comme
 * l'exploitant (EX-12.30, CT-8 IC-9) : bucket avec Object Lock, puis
 * `PutObjectLockConfiguration` (requête exacte d'EX-12.39).
 * @param {string} origine origine (HTTP ou HTTPS) du service
 * @param {string} bucket
 * @param {{jours?: number, mode?: string, ca?: Buffer, sansRegle?: boolean}} [o] `sansRegle` : Object Lock
 *   activé sans rétention par défaut (verrou absent)
 */
export async function creerBucketVerrouille(origine, bucket, o = {}) {
  const a = new AccesS3({ endpoint: origine, region: "us-east-1", bucket, identifiants: JSON.parse(identifiantsRole("administrateur")), tls: { ca: o.ca } });
  const r1 = await a.envoyer({ method: "PUT", target: "/", headers: [["x-amz-bucket-object-lock-enabled", "true"]], body: null });
  if (r1.statut !== 200) throw new Error(`création du bucket : ${r1.statut}`);
  if (o.sansRegle) return a;
  const r2 = await a.envoyer(requeteS3ConfigurationVerrou(o.jours ?? 4018, o.mode ?? "COMPLIANCE"));
  if (r2.statut !== 200) throw new Error(`rétention par défaut : ${r2.statut}`);
  return a;
}

/** Fichier de secret 0600 (EX-15.3). */
export function fichierSecret(chemin, contenu) {
  fs.mkdirSync(path.dirname(chemin), { recursive: true });
  fs.writeFileSync(chemin, contenu, { mode: 0o600 });
  fs.chmodSync(chemin, 0o600);
  return chemin;
}

export { attendre, portLibre };
