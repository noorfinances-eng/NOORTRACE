// Outils des tests des signataires des classes A, B et C
// (test/enregistreur-signataires-*.test.js) : services réels et logiciels
// système, chacun mis en attente par le test qui l'emploie quand il manque,
// avec un titre qui nomme la condition.
//
// - SoftHSM2 (paquet du système, `softhsm2-util` et `libsofthsm2.so`) : jeton
//   initialisé dans un répertoire du test (SOFTHSM2_CONF), paires Ed25519
//   générées par la cérémonie de test `pkcs11-ceremonie.py` (identité
//   d'administration, jamais celle du démon).
// - Vault et OpenBao en conteneurs épinglés par condensé, en mode
//   développement (HTTP) derrière le mandataire TLS des tests WORM (le schéma
//   n'admet qu'une URL `https://`) ; moteur Transit monté, clés `ed25519`
//   non exportables, politique d'usage (lire la clé, signer) et jeton
//   d'usage distinct du jeton racine (EX-11.4).
// - LocalStack (image des tests WORM, service `kms`) : chiffrement de la
//   graine par `Encrypt` avec contexte (classe C).
// - swtpm (TPM 2.0 logiciel) et tpm2-tools : scellement de la graine sous une
//   politique PCR (classe C).

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ClientKms, contexteChiffrement } from "@noortrace/enregistreur";
import { IMAGES, attendre, portLibre, mandataireTls } from "../enregistreur-worm/outils.mjs";

const ICI = path.dirname(fileURLToPath(import.meta.url));
export const CEREMONIE_PKCS11 = path.join(ICI, "pkcs11-ceremonie.py");

/** Images épinglées par condensé (Vault 1.20.4, OpenBao 2.4.3). */
export const IMAGES_SIGNATAIRES = Object.freeze({
  "vault-transit": "mirror.gcr.io/hashicorp/vault@sha256:268bb80aa9c6d13d65fcfa05c0c268caca068952240a8087291a6ce0b66e3a10",
  "openbao-transit": "quay.io/openbao/openbao@sha256:48174d0c98dbb955731c5d54a7e7083987fd25a7fb5d793181db8576ada8ed64",
  kms: IMAGES.s3,
});

const lances = new Set();
process.on("exit", () => {
  for (const n of lances) spawnSync("docker", ["rm", "-f", "-v", n]);
});

/** Supprime un conteneur lancé ici, avec ses volumes anonymes. */
export function arreterConteneur(nom) {
  spawnSync("docker", ["rm", "-f", "-v", nom], { encoding: "utf8" });
  lances.delete(nom);
}

/** Supprime tous les conteneurs lancés ici. */
export function arreterConteneurs() {
  for (const n of [...lances]) arreterConteneur(n);
}

/** Met un conteneur en pause (service qui ne répond plus) ou le reprend. */
export function suspendreConteneur(nom, pause = true) {
  execFileSync("docker", [pause ? "pause" : "unpause", nom]);
}

/** Docker et une image (sans téléchargement s'il est déjà fait) : `{ ok, condition }`. */
export function dockerEtImage(image) {
  const v = spawnSync("docker", ["info", "--format", "{{.ServerVersion}}"], { encoding: "utf8" });
  if (v.status !== 0) return { ok: false, condition: "Docker absent ou démon dockerd injoignable" };
  if (spawnSync("docker", ["image", "inspect", image], { encoding: "utf8" }).status === 0) return { ok: true, condition: null };
  const p = spawnSync("docker", ["pull", image], { encoding: "utf8", timeout: 600000 });
  return p.status === 0 ? { ok: true, condition: null } : { ok: false, condition: `image ${image} indisponible (docker pull en échec)` };
}

// ---------------------------------------------------------------- SoftHSM2

/** Module SoftHSM2 du système, ou null. */
export function moduleSoftHsm() {
  for (const m of ["/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "/usr/lib64/pkcs11/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so"]) {
    if (fs.existsSync(m)) return m;
  }
  return null;
}

/** SoftHSM2 et python3 disponibles : `{ ok, condition }`. */
export function softHsmDisponible() {
  if (spawnSync("softhsm2-util", ["--version"], { encoding: "utf8" }).status !== 0) return { ok: false, condition: "SoftHSM2 absent (softhsm2-util)" };
  if (!moduleSoftHsm()) return { ok: false, condition: "SoftHSM2 absent (libsofthsm2.so)" };
  if (spawnSync("python3", ["-c", "import ctypes"], { encoding: "utf8" }).status !== 0) return { ok: false, condition: "python3 (ctypes) absent" };
  return { ok: true, condition: null };
}

/**
 * Jeton SoftHSM2 neuf dans `dir` ; rend { module, env, pin, ceremonie(label, forme, extractible) → clé publique hex }.
 * @param {string} dir
 */
export function jetonSoftHsm(dir, etiquette = "noortrace") {
  fs.mkdirSync(path.join(dir, "jetons"), { recursive: true });
  const conf = path.join(dir, "softhsm2.conf");
  fs.writeFileSync(conf, `directories.tokendir = ${path.join(dir, "jetons")}\nobjectstore.backend = file\nlog.level = ERROR\n`);
  const env = { ...process.env, SOFTHSM2_CONF: conf };
  const pin = "5678";
  execFileSync("softhsm2-util", ["--init-token", "--free", "--label", etiquette, "--so-pin", "1234", "--pin", pin], { env, stdio: "pipe" });
  const module = moduleSoftHsm();
  return {
    module,
    etiquette,
    env: { SOFTHSM2_CONF: conf },
    pin,
    ceremonie(label, forme = "oid", extractible = false) {
      return execFileSync("python3", ["-I", "-S", CEREMONIE_PKCS11, module, etiquette, pin, label, forme, ...(extractible ? ["extractible"] : [])], { env, encoding: "utf8" }).trim();
    },
  };
}

// ---------------------------------------------------------------- Vault / OpenBao

async function http(methode, url, jeton, corps) {
  const r = await fetch(url, { method: methode, headers: { "x-vault-token": jeton, "content-type": "application/json" }, body: corps ? JSON.stringify(corps) : undefined });
  const texte = await r.text();
  if (r.status >= 300) throw new Error(`${methode} ${url} : ${r.status} ${texte.slice(0, 300)}`);
  return texte ? JSON.parse(texte) : null;
}

/**
 * Serveur Vault ou OpenBao (mode développement) derrière TLS, moteur Transit monté.
 * @param {"vault-transit"|"openbao-transit"} type
 * @param {string} nom nom du conteneur
 * @param {{cert: string, key: string}} tls certificats de test (127.0.0.1)
 */
export async function demarrerTransit(type, nom, tls) {
  const port = await portLibre();
  arreterConteneur(nom);
  const pre = type === "vault-transit" ? "VAULT" : "BAO";
  execFileSync("docker", ["run", "-d", "--rm", "--name", nom, "-p", `127.0.0.1:${port}:8200`, "-e", `${pre}_DEV_ROOT_TOKEN_ID=racine-de-test`, "-e", `${pre}_DEV_LISTEN_ADDRESS=0.0.0.0:8200`, "-e", "SKIP_SETCAP=true", IMAGES_SIGNATAIRES[type]], { encoding: "utf8" });
  lances.add(nom);
  const direct = `http://127.0.0.1:${port}`;
  await attendre(async () => (await fetch(`${direct}/v1/sys/health`).catch(() => null))?.ok, 120000);
  await http("POST", `${direct}/v1/sys/mounts/transit`, "racine-de-test", { type: "transit" });
  const prox = await mandataireTls(tls, { port });
  return {
    nom,
    type,
    direct,
    origine: prox.origine,
    prox,
    /** Crée une clé Transit (cérémonie, jeton racine) ; rend sa clé publique (base64). */
    async creerCle(nomCle, o = {}) {
      await http("POST", `${direct}/v1/transit/keys/${nomCle}`, "racine-de-test", { type: o.type ?? "ed25519", exportable: o.exportable ?? false });
      const d = (await http("GET", `${direct}/v1/transit/keys/${nomCle}`, "racine-de-test")).data;
      return d.keys[String(d.latest_version)].public_key;
    },
    /** Journal d'audit `file` du serveur (CT-2 §11.6 : « audit devices pour Vault et OpenBao »). */
    async activerAudit() {
      await http("PUT", `${direct}/v1/sys/audit/fichier`, "racine-de-test", { type: "file", options: { file_path: "/vault/logs/audit.log" } });
    },
    /** Contenu du journal d'audit (lignes JSON). */
    lireAudit() {
      return execFileSync("docker", ["exec", nom, "cat", "/vault/logs/audit.log"], { encoding: "utf8" });
    },
    /** Moteur KV version 2 monté sous `kv`, et un secret écrit (cérémonie, jeton racine). */
    async ecrireKv(chemin, donnees) {
      await http("POST", `${direct}/v1/sys/mounts/kv`, "racine-de-test", { type: "kv", options: { version: "2" } }).catch(() => {});
      await http("POST", `${direct}/v1/kv/data/${chemin}`, "racine-de-test", { data: donnees });
    },
    /** Jeton d'une politique écrite à la main. */
    async jetonPolitique(nomPolitique, politique) {
      await http("PUT", `${direct}/v1/sys/policies/acl/${nomPolitique}`, "racine-de-test", { policy: politique });
      return (await http("POST", `${direct}/v1/auth/token/create`, "racine-de-test", { policies: [nomPolitique], no_default_policy: true, ttl: "2h" })).auth.client_token;
    },
    /** Rotation dans le backend (nouvelle version de la clé). */
    async tournerDansBackend(nomCle) {
      await http("POST", `${direct}/v1/transit/keys/${nomCle}/rotate`, "racine-de-test", {});
    },
    /** Jeton d'usage : lire les clés nommées et signer, rien d'autre (EX-11.4). */
    async jetonUsage(cles) {
      const politique = cles.map((k) => `path "transit/keys/${k}" { capabilities = ["read"] }\npath "transit/sign/${k}" { capabilities = ["update"] }\n`).join("");
      await http("PUT", `${direct}/v1/sys/policies/acl/signataire`, "racine-de-test", { policy: politique });
      return (await http("POST", `${direct}/v1/auth/token/create`, "racine-de-test", { policies: ["signataire"], no_default_policy: true, ttl: "2h" })).auth.client_token;
    },
    async arreter() {
      await prox.fermer();
      arreterConteneur(nom);
    },
  };
}

// ---------------------------------------------------------------- LocalStack KMS

/**
 * LocalStack, service `kms` ; rend { origine, env, client, creerCleSymetrique(), chiffrerGraine(arn, graine, ctx) }.
 * @param {string} nom
 */
export async function demarrerKmsLocalStack(nom) {
  const port = await portLibre();
  arreterConteneur(nom);
  execFileSync("docker", ["run", "-d", "--rm", "--name", nom, "-p", `127.0.0.1:${port}:4566`, "-e", "SERVICES=kms", "-e", "EAGER_SERVICE_LOADING=1", IMAGES.s3], { encoding: "utf8" });
  lances.add(nom);
  const origine = `http://127.0.0.1:${port}`;
  await attendre(async () => {
    const r = await fetch(`${origine}/_localstack/health`).catch(() => null);
    if (!r?.ok) return false;
    const j = await r.json();
    return j.services?.kms === "running" || j.services?.kms === "available";
  }, 120000);
  const env = { AWS_ACCESS_KEY_ID: "test", AWS_SECRET_ACCESS_KEY: "test", AWS_ENDPOINT_URL_KMS: origine };
  const client = new ClientKms({ region: "us-east-1", env, delaiMs: 20000 });
  return {
    nom,
    origine,
    env,
    client,
    async creerCleSymetrique() {
      return (await client.appeler("CreateKey", { KeySpec: "SYMMETRIC_DEFAULT", KeyUsage: "ENCRYPT_DECRYPT" })).KeyMetadata.Arn;
    },
    /** Cérémonie : chiffre la graine sous le contexte (org_id, journal_id, key_id). */
    async chiffrerGraine(arn, graine, ctx) {
      const r = await client.appeler("Encrypt", { KeyId: arn, Plaintext: Buffer.from(graine).toString("base64"), EncryptionContext: contexteChiffrement(ctx).carte });
      return Buffer.from(r.CiphertextBlob, "base64");
    },
    arreter: () => arreterConteneur(nom),
  };
}

// ---------------------------------------------------------------- swtpm

/** swtpm et tpm2-tools disponibles : `{ ok, condition }`. */
export function tpmDisponible() {
  if (spawnSync("swtpm", ["--version"], { encoding: "utf8" }).status !== 0) return { ok: false, condition: "swtpm absent" };
  for (const o of ["tpm2_createprimary", "tpm2_create", "tpm2_load", "tpm2_unseal", "tpm2_createpolicy", "tpm2_pcrextend"]) {
    if (spawnSync(o, ["--version"], { encoding: "utf8" }).status !== 0) return { ok: false, condition: `tpm2-tools absent (${o})` };
  }
  return { ok: true, condition: null };
}

/**
 * TPM 2.0 logiciel (swtpm, socket TCP) ; rend { env: { TPM2TOOLS_TCTI }, sceller, etendrePcr, arreter }.
 * @param {string} dir
 */
export async function demarrerSwtpm(dir) {
  const etat = path.join(dir, "etat-tpm");
  fs.mkdirSync(etat, { recursive: true });
  // La TCTI `swtpm` joint le canal de contrôle au port suivant celui des commandes.
  const port = await portLibre();
  const ctrl = port + 1;
  const p = spawn("swtpm", ["socket", "--tpm2", "--tpmstate", `dir=${etat}`, "--server", `type=tcp,port=${port},bindaddr=127.0.0.1`, "--ctrl", `type=tcp,port=${ctrl},bindaddr=127.0.0.1`, "--flags", "not-need-init,startup-clear"], { stdio: "ignore" });
  const env = { TPM2TOOLS_TCTI: `swtpm:host=127.0.0.1,port=${port}` };
  const outil = (n, args, o = {}) => execFileSync(n, args, { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"], ...o });
  await attendre(() => {
    try {
      outil("tpm2_getrandom", ["--hex", "4"]);
      return true;
    } catch {
      return false;
    }
  }, 30000);
  return {
    env,
    /** Cérémonie : scelle la graine sous la politique PCR, parent primaire du propriétaire (ECC, SHA-256). */
    sceller(graine, pcrs, base) {
      const t = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-ceremonie-tpm-"));
      try {
        // Sans gestionnaire de ressources : objets et sessions purgés après chaque pas.
        const purger = () => {
          outil("tpm2_flushcontext", ["-t"]);
          outil("tpm2_flushcontext", ["-s"]);
          outil("tpm2_flushcontext", ["-l"]);
        };
        outil("tpm2_createprimary", ["-C", "o", "-g", "sha256", "-G", "ecc", "-c", path.join(t, "p.ctx")]);
        purger();
        outil("tpm2_createpolicy", ["--policy-pcr", "-l", pcrs, "-L", path.join(t, "pol.dat")]);
        purger();
        fs.writeFileSync(path.join(t, "graine"), Buffer.from(graine), { mode: 0o600 });
        outil("tpm2_create", ["-C", path.join(t, "p.ctx"), "-L", path.join(t, "pol.dat"), "-i", path.join(t, "graine"), "-u", `${base}.pub`, "-r", `${base}.priv`]);
        purger();
        return { public_file: `${base}.pub`, private_file: `${base}.priv` };
      } finally {
        fs.rmSync(t, { recursive: true, force: true });
      }
    },
    /** Étend un PCR (changement de micrologiciel ou de chargeur simulé). */
    etendrePcr(index) {
      outil("tpm2_pcrextend", [`${index}:sha256=${"ab".repeat(32)}`]);
    },
    arreter() {
      p.kill("SIGTERM");
    },
  };
}
