// Simulateurs des services de clés sans émulateur fiable (tests
// test/enregistreur-signataires-*.test.js), écrits pour ces tests d'après les
// pages officielles citées par CT-2 §11.2 et son annexe C :
//
// - AWS KMS, classe B : LocalStack 4.0.3 (l'image épinglée des tests WORM)
//   répond `InternalError` à `CreateKey` avec `KeySpec:
//   ECC_NIST_EDWARDS25519` (essayé) ; le simulateur sert `GetPublicKey`,
//   `Sign`, `DescribeKey` (et `Encrypt`/`Decrypt` pour les entrées hostiles de
//   la classe C) en protocole JSON 1.1 (`X-Amz-Target: TrentService.<Action>`),
//   vérifie la signature SigV4 de chaque requête (service `kms`), refuse
//   `MessageType` autre que `RAW`, `ED25519_PH_SHA_512` hors
//   `ECC_NIST_EDWARDS25519`, un message de plus de 4096 octets
//   (https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html).
// - Google Cloud KMS : jeton OAuth par assertion JWT RS256 d'un compte de
//   service (signature vérifiée), `getPublicKey` (`pem`, `pemCrc32c`,
//   `algorithm`, `name`), `asymmetricSign` (`data`, `dataCrc32c` vérifié,
//   `verifiedDataCrc32c`, `signatureCrc32c`), état d'une version,
//   `encrypt`/`decrypt` avec `additionalAuthenticatedData` et leurs CRC32C
//   (pages de référence REST v1 citées).
// - serveurs de métadonnées : IMDSv2 d'EC2 et métadonnées de Compute Engine
//   (identités d'instance, LISEZMOI lecture 193) ;
// - Azure Key Vault : jeton Entra ID (client_credentials, portée vérifiée),
//   `wrapkey`/`unwrapkey` en `RSA-OAEP-256` et `A256KW`
//   (api-version 7.4, page `wrap-key` citée).
//
// Chaque simulateur a des « modes » hostiles : lent, signature d'un autre
// message, d'une autre clé, de mauvaise longueur, somme CRC32C fausse, clé
// d'un autre type, réponse illisible. Tous écoutent en HTTPS sur 127.0.0.1
// (autorité de test des tests WORM).

import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import {
  createCipheriv, createDecipheriv, createHash, createHmac, createVerify, generateKeyPairSync,
  privateDecrypt, publicEncrypt, randomBytes, constants,
} from "node:crypto";
import { clePubliqueEd25519, signerEd25519 } from "@noortrace/noyau";
import { crc32c } from "@noortrace/enregistreur";

const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");
const spki = (graine) => Buffer.concat([SPKI_ED25519, Buffer.from(clePubliqueEd25519(graine))]);
const pem = (der) => `-----BEGIN PUBLIC KEY-----\n${der.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----\n`;
const attendre = (ms) => new Promise((r) => setTimeout(r, ms));

function lireCorps(req) {
  return new Promise((res) => {
    const m = [];
    req.on("data", (c) => m.push(c));
    req.on("end", () => res(Buffer.concat(m)));
  });
}

function servir(tls, gerer) {
  const compte = { requetes: [] };
  const serveur = https.createServer({ cert: fs.readFileSync(tls.cert), key: fs.readFileSync(tls.key) }, async (req, rep) => {
    const corps = await lireCorps(req);
    compte.requetes.push({ methode: req.method, url: req.url, entetes: req.headers, corps });
    try {
      const r = await gerer(req, corps);
      if (r.detruire) return req.socket.destroy();
      rep.writeHead(r.statut, { "content-type": r.type ?? "application/json" });
      rep.end(typeof r.corps === "string" || Buffer.isBuffer(r.corps) ? r.corps : JSON.stringify(r.corps));
    } catch (e) {
      rep.writeHead(500, { "content-type": "application/json" });
      rep.end(JSON.stringify({ erreur: String(e.message) }));
    }
  });
  return new Promise((res) =>
    serveur.listen(0, "127.0.0.1", () => {
      const port = serveur.address().port;
      res({ serveur, port, origine: `https://127.0.0.1:${port}`, compte, fermer: () => new Promise((r) => { serveur.closeAllConnections?.(); serveur.close(() => r()); }) });
    }),
  );
}

// ---------------------------------------------------------------- AWS KMS

/** Vérifie la signature SigV4 d'une requête KMS (côté serveur, d'après la documentation SigV4). */
function verifierSigv4(req, corps, identifiants, region) {
  const auth = String(req.headers.authorization ?? "");
  const m = /^AWS4-HMAC-SHA256 Credential=([^/]+)\/(\d{8})\/([^/]+)\/kms\/aws4_request, SignedHeaders=([a-z0-9;-]+), Signature=([0-9a-f]{64})$/.exec(auth);
  if (!m) return "en-tête Authorization mal formé";
  const [, id, jour, reg, signes, sig] = m;
  if (id !== identifiants.access_key_id) return "UnrecognizedClientException";
  if (reg !== region) return "région de la portée";
  const noms = signes.split(";");
  for (const n of ["host", "x-amz-date", "x-amz-target"]) if (!noms.includes(n)) return `${n} non signé`;
  const canon = ["POST", "/", "", noms.map((n) => `${n}:${String(req.headers[n]).trim()}\n`).join(""), signes, createHash("sha256").update(corps).digest("hex")].join("\n");
  const aSigner = ["AWS4-HMAC-SHA256", req.headers["x-amz-date"], `${jour}/${reg}/kms/aws4_request`, createHash("sha256").update(canon).digest("hex")].join("\n");
  let k = createHmac("sha256", `AWS4${identifiants.secret_access_key}`).update(jour).digest();
  for (const x of [reg, "kms", "aws4_request"]) k = createHmac("sha256", k).update(x).digest();
  if (createHmac("sha256", k).update(aSigner).digest("hex") !== sig) return "SignatureDoesNotMatch";
  if (identifiants.session_token && req.headers["x-amz-security-token"] !== identifiants.session_token) return "jeton de session";
  return null;
}

/**
 * Simulateur d'AWS KMS (une région, un compte).
 * @param {{cert: string, key: string}} tls
 * @param {{region?: string, compte?: string, identifiants?: object}} [o]
 */
export async function simulateurAwsKms(tls, o = {}) {
  const region = o.region ?? "eu-west-3";
  const compteAws = o.compte ?? "111122223333";
  const identifiants = o.identifiants ?? { access_key_id: "AKIDSIMULATEUR", secret_access_key: "secret-du-simulateur", session_token: null };
  /** @type {Map<string, {spec: string, usage: string, graine?: Uint8Array, aes?: Buffer, etat: string}>} */
  const cles = new Map();
  const etat = { mode: null, delaiMs: 0 };
  const err = (type, message, statut = 400) => ({ statut, corps: { __type: type, message } });
  const sim = await servir(tls, async (req, corps) => {
    if (etat.delaiMs) await attendre(etat.delaiMs);
    if (req.method !== "POST" || req.url !== "/") return err("UnknownOperationException", "POST / attendu", 404);
    if (req.headers["content-type"] !== "application/x-amz-json-1.1") return err("SerializationException", "Content-Type");
    const refus = verifierSigv4(req, corps, identifiants, region);
    if (refus) return err(refus.includes("Unrecognized") ? "UnrecognizedClientException" : "InvalidSignatureException", refus, 403);
    const action = String(req.headers["x-amz-target"] ?? "").replace(/^TrentService\./, "");
    let p;
    try {
      p = JSON.parse(corps.toString("utf8"));
    } catch {
      return err("SerializationException", "JSON");
    }
    const k = cles.get(p.KeyId);
    if (!k) return err("NotFoundException", "clé inconnue");
    const arn = k.arn;
    if (k.etat !== "Enabled") return err("DisabledException", "clé désactivée");
    if (action === "DescribeKey") return { statut: 200, corps: { KeyMetadata: { Arn: arn, KeyId: arn.split("/").pop(), KeySpec: k.spec, KeyUsage: k.usage, KeyState: k.etat } } };
    if (action === "GetPublicKey") {
      if (k.usage !== "SIGN_VERIFY") return err("UnsupportedOperationException", "clé symétrique");
      const algos = k.spec === "ECC_NIST_EDWARDS25519" ? ["ED25519_SHA_512", "ED25519_PH_SHA_512"] : ["ECDSA_SHA_256"];
      const g = etat.mode === "autre_cle_publique" ? randomBytes(32) : k.graine;
      return { statut: 200, corps: { KeyId: arn, PublicKey: spki(g).toString("base64"), KeySpec: k.spec, KeyUsage: k.usage, SigningAlgorithms: algos } };
    }
    if (action === "Sign") {
      if (k.usage !== "SIGN_VERIFY") return err("InvalidKeyUsageException", "usage");
      const msg = Buffer.from(String(p.Message ?? ""), "base64");
      if (msg.length > 4096) return err("ValidationException", "Message : 4096 octets au plus");
      if (p.MessageType !== "RAW" && p.MessageType !== "DIGEST") return err("ValidationException", "MessageType");
      if (p.SigningAlgorithm === "ED25519_SHA_512" && p.MessageType !== "RAW") return err("ValidationException", "ED25519_SHA_512 exige MessageType RAW");
      if (!["ED25519_SHA_512", "ED25519_PH_SHA_512"].includes(p.SigningAlgorithm)) return err("InvalidKeyUsageException", "algorithme");
      let sig;
      if (etat.mode === "prehache" || p.SigningAlgorithm === "ED25519_PH_SHA_512") sig = signerEd25519(k.graine, createHash("sha512").update(msg).digest());
      else if (etat.mode === "autre_cle") sig = signerEd25519(randomBytes(32), msg);
      else if (etat.mode === "autre_message") sig = signerEd25519(k.graine, Buffer.concat([msg, Buffer.from([0])]));
      else sig = signerEd25519(k.graine, msg);
      if (etat.mode === "longueur") sig = Buffer.from(sig).subarray(0, 63);
      if (etat.mode === "illisible") return { statut: 200, corps: "{non json" };
      return { statut: 200, corps: { KeyId: arn, Signature: Buffer.from(sig).toString("base64"), SigningAlgorithm: p.SigningAlgorithm } };
    }
    if (action === "Encrypt" || action === "Decrypt") {
      if (k.usage !== "ENCRYPT_DECRYPT") return err("InvalidKeyUsageException", "usage");
      const aad = Buffer.from(JSON.stringify(Object.entries(p.EncryptionContext ?? {}).sort()));
      if (action === "Encrypt") {
        const iv = randomBytes(12);
        const c = createCipheriv("aes-256-gcm", k.aes, iv).setAAD(aad);
        const ch = Buffer.concat([c.update(Buffer.from(p.Plaintext, "base64")), c.final()]);
        return { statut: 200, corps: { KeyId: arn, CiphertextBlob: Buffer.concat([iv, c.getAuthTag(), ch]).toString("base64"), EncryptionAlgorithm: "SYMMETRIC_DEFAULT" } };
      }
      const b = Buffer.from(String(p.CiphertextBlob), "base64");
      try {
        const d = createDecipheriv("aes-256-gcm", k.aes, b.subarray(0, 12)).setAAD(aad);
        d.setAuthTag(b.subarray(12, 28));
        let clair = Buffer.concat([d.update(b.subarray(28)), d.final()]);
        if (etat.mode === "graine_courte") clair = clair.subarray(0, 31);
        return { statut: 200, corps: { KeyId: etat.mode === "autre_cle_kms" ? `${arn}0` : arn, Plaintext: clair.toString("base64"), EncryptionAlgorithm: "SYMMETRIC_DEFAULT" } };
      } catch {
        return err("InvalidCiphertextException", "contexte ou chiffré");
      }
    }
    return err("UnknownOperationException", action, 400);
  });
  return Object.assign(sim, {
    region,
    identifiants,
    etat,
    env: { AWS_ACCESS_KEY_ID: identifiants.access_key_id, AWS_SECRET_ACCESS_KEY: identifiants.secret_access_key, AWS_ENDPOINT_URL_KMS: sim.origine },
    /** Crée une clé (cérémonie : identité d'administration) ; rend son ARN. */
    creerCle(spec = "ECC_NIST_EDWARDS25519", o2 = {}) {
      const id = o2.id ?? randomBytes(16).toString("hex").replace(/^(.{8})(.{4})(.{4})(.{4})/, "$1-$2-$3-$4-");
      const arn = `arn:aws:kms:${region}:${compteAws}:key/${id}`;
      const k = spec === "SYMMETRIC_DEFAULT" ? { arn, spec, usage: "ENCRYPT_DECRYPT", aes: randomBytes(32), etat: "Enabled" } : { arn, spec, usage: "SIGN_VERIFY", graine: o2.graine ?? randomBytes(32), etat: "Enabled" };
      cles.set(arn, k);
      if (o2.alias) cles.set(`arn:aws:kms:${region}:${compteAws}:alias/${o2.alias}`, k);
      return { arn, cle: k };
    },
    cles,
  });
}

// ---------------------------------------------------------------- Google Cloud KMS

/**
 * Simulateur de Cloud KMS et de son point de jeton OAuth.
 * @param {{cert: string, key: string}} tls
 */
export async function simulateurCloudKms(tls) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const compteService = { type: "service_account", client_email: "signataire@projet-test.iam.gserviceaccount.com", private_key_id: "cle-1", private_key: privateKey.export({ type: "pkcs8", format: "pem" }) };
  const jetons = new Set();
  /** @type {Map<string, object>} */
  const versions = new Map();
  /** @type {Map<string, Buffer>} */
  const clesSym = new Map();
  const etat = { mode: null, delaiMs: 0 };
  const err = (statut, status, message) => ({ statut, corps: { error: { code: statut, status, message } } });
  const sim = await servir(tls, async (req, corps) => {
    if (etat.delaiMs) await attendre(etat.delaiMs);
    const u = new URL(req.url, "https://x");
    if (u.pathname === "/token") {
      const f = new URLSearchParams(corps.toString("utf8"));
      if (f.get("grant_type") !== "urn:ietf:params:oauth:grant-type:jwt-bearer") return { statut: 400, corps: { error: "unsupported_grant_type" } };
      const [e, c, s] = String(f.get("assertion")).split(".");
      const ok = createVerify("RSA-SHA256").update(`${e}.${c}`).verify(publicKey, Buffer.from(s ?? "", "base64url"));
      const charge = JSON.parse(Buffer.from(c ?? "", "base64url").toString("utf8") || "{}");
      if (!ok || charge.iss !== compteService.client_email || charge.aud !== `${sim.origine}/token` || charge.scope !== "https://www.googleapis.com/auth/cloudkms") return { statut: 400, corps: { error: "invalid_grant" } };
      const j = randomBytes(16).toString("hex");
      jetons.add(j);
      return { statut: 200, corps: { access_token: j, expires_in: 3599, token_type: "Bearer" } };
    }
    const porteur = /^Bearer (.+)$/.exec(String(req.headers.authorization ?? ""))?.[1];
    if (!porteur || !jetons.has(porteur)) return err(401, "UNAUTHENTICATED", "jeton");
    const m = /^\/v1\/(projects\/.+?)(\/publicKey|:asymmetricSign|:decrypt|:encrypt)?$/.exec(u.pathname);
    if (!m) return err(404, "NOT_FOUND", "chemin");
    const [, nom, op] = m;
    if (op === ":decrypt" || op === ":encrypt") {
      const k = clesSym.get(nom);
      if (!k) return err(404, "NOT_FOUND", "clé");
      const p = JSON.parse(corps.toString("utf8"));
      const aad = Buffer.from(p.additionalAuthenticatedData ?? "", "base64");
      if (p.additionalAuthenticatedDataCrc32c !== undefined && String(p.additionalAuthenticatedDataCrc32c) !== String(crc32c(aad))) return err(400, "INVALID_ARGUMENT", "additionalAuthenticatedDataCrc32c");
      if (op === ":encrypt") {
        const iv = randomBytes(12);
        const c = createCipheriv("aes-256-gcm", k, iv).setAAD(aad);
        const ch = Buffer.concat([iv, Buffer.alloc(16), c.update(Buffer.from(p.plaintext, "base64")), c.final()]);
        c.getAuthTag().copy(ch, 12);
        return { statut: 200, corps: { name: `${nom}/cryptoKeyVersions/1`, ciphertext: ch.toString("base64"), ciphertextCrc32c: String(crc32c(ch)) } };
      }
      const b = Buffer.from(p.ciphertext, "base64");
      if (String(p.ciphertextCrc32c) !== String(crc32c(b))) return err(400, "INVALID_ARGUMENT", "ciphertextCrc32c");
      try {
        const d = createDecipheriv("aes-256-gcm", k, b.subarray(0, 12)).setAAD(aad);
        d.setAuthTag(b.subarray(12, 28));
        const clair = Buffer.concat([d.update(b.subarray(28)), d.final()]);
        const crc = etat.mode === "crc_faux" ? crc32c(clair) ^ 1 : crc32c(clair);
        return { statut: 200, corps: { plaintext: clair.toString("base64"), plaintextCrc32c: String(crc), usedPrimary: true, protectionLevel: "SOFTWARE" } };
      } catch {
        return err(400, "INVALID_ARGUMENT", "Decryption failed: the ciphertext is invalid.");
      }
    }
    const v = versions.get(nom);
    if (!v) return err(404, "NOT_FOUND", "version");
    if (!op && req.method === "GET") return { statut: 200, corps: { name: nom, state: v.state, algorithm: v.algorithm, protectionLevel: "SOFTWARE" } };
    if (op === "/publicKey" && req.method === "GET") {
      const g = etat.mode === "autre_cle_publique" ? randomBytes(32) : v.graine;
      const texte = pem(spki(g));
      return { statut: 200, corps: { pem: texte, algorithm: v.algorithm, pemCrc32c: String(crc32c(Buffer.from(texte))), name: nom, protectionLevel: "SOFTWARE" } };
    }
    if (op === ":asymmetricSign" && req.method === "POST") {
      const p = JSON.parse(corps.toString("utf8"));
      if (p.digest) return err(400, "INVALID_ARGUMENT", "EC_SIGN_ED25519 : data, pas digest");
      const data = Buffer.from(p.data ?? "", "base64");
      if (p.dataCrc32c !== undefined && String(p.dataCrc32c) !== String(crc32c(data))) return err(400, "INVALID_ARGUMENT", "dataCrc32c");
      let sig = Buffer.from(signerEd25519(etat.mode === "autre_cle" ? randomBytes(32) : v.graine, data));
      if (etat.mode === "longueur") sig = sig.subarray(0, 63);
      const crc = etat.mode === "crc_faux" ? crc32c(sig) ^ 1 : crc32c(sig);
      return { statut: 200, corps: { signature: sig.toString("base64"), signatureCrc32c: String(crc), verifiedDataCrc32c: etat.mode === "non_verifie" ? false : p.dataCrc32c !== undefined, name: etat.mode === "autre_version" ? `${nom.replace(/\d+$/, "")}9` : nom, protectionLevel: "SOFTWARE" } };
    }
    return err(400, "INVALID_ARGUMENT", "opération");
  });
  return Object.assign(sim, {
    etat,
    compteService: { ...compteService, token_uri: `${sim.origine}/token` },
    /** Écrit le fichier de compte de service et rend l'environnement du démon. */
    environnement(fichier) {
      fs.writeFileSync(fichier, JSON.stringify({ ...compteService, token_uri: `${sim.origine}/token` }), { mode: 0o600 });
      return { GOOGLE_APPLICATION_CREDENTIALS: fichier, CLOUDSDK_API_ENDPOINT_OVERRIDES_CLOUDKMS: `${sim.origine}/` };
    },
    creerVersion(nom, algorithm = "EC_SIGN_ED25519", graine = randomBytes(32)) {
      versions.set(nom, { algorithm, graine, state: "ENABLED" });
      return versions.get(nom);
    },
    creerCleSymetrique(nom) {
      clesSym.set(nom, randomBytes(32));
    },
    /** Jeton d'accès reconnu (délivré hors du point /token, comme par un serveur de métadonnées). */
    jetonInstance() {
      const j = randomBytes(16).toString("hex");
      jetons.add(j);
      return j;
    },
    versions,
  });
}

// ---------------------------------------------------------------- Azure Key Vault

/**
 * Simulateur d'Azure Key Vault (wrapkey, unwrapkey) et du point de jeton Entra ID.
 * @param {{cert: string, key: string}} tls
 */
export async function simulateurAzure(tls) {
  const client = { tenant: "locataire-test", id: "client-signataire", secret: "secret-client-test" };
  const jetons = new Set();
  /** @type {Map<string, {rsa?: object, aes?: Buffer}>} */
  const cles = new Map();
  const etat = { mode: null, delaiMs: 0 };
  const err = (statut, code) => ({ statut, corps: { error: { code, message: code } } });
  const sim = await servir(tls, async (req, corps) => {
    if (etat.delaiMs) await attendre(etat.delaiMs);
    const u = new URL(req.url, "https://x");
    if (u.pathname === `/${client.tenant}/oauth2/v2.0/token`) {
      const f = new URLSearchParams(corps.toString("utf8"));
      if (f.get("grant_type") !== "client_credentials" || f.get("client_id") !== client.id || f.get("client_secret") !== client.secret) return { statut: 401, corps: { error: "invalid_client" } };
      if (f.get("scope") !== "https://vault.azure.net/.default") return { statut: 400, corps: { error: "invalid_scope" } };
      const j = randomBytes(16).toString("hex");
      jetons.add(j);
      return { statut: 200, corps: { access_token: j, expires_in: 3599, token_type: "Bearer" } };
    }
    const porteur = /^Bearer (.+)$/.exec(String(req.headers.authorization ?? ""))?.[1];
    if (!porteur || !jetons.has(porteur)) return err(401, "Unauthorized");
    if (u.searchParams.get("api-version") !== "7.4") return err(400, "BadParameter");
    const m = /^\/keys\/([^/]+)\/([^/]+)\/(wrapkey|unwrapkey)$/.exec(u.pathname);
    if (!m || req.method !== "POST") return err(404, "NotFound");
    const [, nom, version, op] = m;
    const k = cles.get(`${nom}/${version}`);
    if (!k) return err(404, "KeyNotFound");
    const p = JSON.parse(corps.toString("utf8"));
    const valeur = Buffer.from(String(p.value), "base64url");
    const kid = `${sim.origine}/keys/${nom}/${version}`;
    let sortie;
    try {
      if (p.alg === "RSA-OAEP-256" && k.rsa) {
        const o = { key: op === "wrapkey" ? k.rsa.publicKey : k.rsa.privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" };
        sortie = op === "wrapkey" ? publicEncrypt(o, valeur) : privateDecrypt(o, valeur);
      } else if (p.alg === "A256KW" && k.aes) {
        const iv = Buffer.from("a6a6a6a6a6a6a6a6", "hex");
        const c = op === "wrapkey" ? createCipheriv("id-aes256-wrap", k.aes, iv) : createDecipheriv("id-aes256-wrap", k.aes, iv);
        sortie = Buffer.concat([c.update(valeur), c.final()]);
      } else {
        return err(400, "BadParameter");
      }
    } catch {
      return err(400, "BadParameter");
    }
    if (etat.mode === "autre_kid") return { statut: 200, corps: { kid: `${sim.origine}/keys/autre/${version}`, value: sortie.toString("base64url") } };
    if (etat.mode === "graine_longue" && op === "unwrapkey") sortie = Buffer.concat([sortie, Buffer.from([0])]);
    return { statut: 200, corps: { kid, value: sortie.toString("base64url") } };
  });
  return Object.assign(sim, {
    etat,
    client,
    env: { AZURE_TENANT_ID: client.tenant, AZURE_CLIENT_ID: client.id, AZURE_CLIENT_SECRET: client.secret, AZURE_AUTHORITY_HOST: sim.origine },
    creerCle(nom, version, type = "RSA") {
      cles.set(`${nom}/${version}`, type === "RSA" ? { rsa: generateKeyPairSync("rsa", { modulusLength: 2048 }) } : { aes: randomBytes(32) });
    },
    /** wrapKey côté cérémonie (même calcul que le service). */
    async envelopper(nom, version, alg, graine) {
      const k = cles.get(`${nom}/${version}`);
      if (alg === "RSA-OAEP-256") return publicEncrypt({ key: k.rsa.publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, Buffer.from(graine));
      const c = createCipheriv("id-aes256-wrap", k.aes, Buffer.from("a6a6a6a6a6a6a6a6", "hex"));
      return Buffer.concat([c.update(Buffer.from(graine)), c.final()]);
    },
  });
}


// ---------------------------------------------------------------- serveurs de métadonnées

function servirHttp(gerer) {
  const compte = { requetes: [] };
  const serveur = http.createServer(async (req, rep) => {
    compte.requetes.push({ methode: req.method, url: req.url, entetes: req.headers });
    const r = await gerer(req);
    rep.writeHead(r.statut, { "content-type": r.type ?? "text/plain", ...(r.entetes ?? {}) });
    rep.end(typeof r.corps === "string" ? r.corps : JSON.stringify(r.corps));
  });
  return new Promise((res) =>
    serveur.listen(0, "127.0.0.1", () => {
      const port = serveur.address().port;
      res({ serveur, port, hote: `127.0.0.1:${port}`, origine: `http://127.0.0.1:${port}`, compte, fermer: () => new Promise((r) => { serveur.closeAllConnections?.(); serveur.close(() => r()); }) });
    }),
  );
}

/**
 * IMDSv2 d'une instance EC2, d'après les pages « Configure the Instance
 * Metadata Service options » et « Retrieve security credentials from
 * instance metadata » (guide EC2, relues le 2026-11-03) : `PUT
 * /latest/api/token` avec `X-aws-ec2-metadata-token-ttl-seconds` (21600 dans
 * l'exemple) rend un jeton ; chaque `GET` porte `X-aws-ec2-metadata-token`
 * (« requests without a valid token or with an expired token receive a 401 ») ;
 * `…/iam/security-credentials/` rend le nom du rôle, `…/<rôle>` le JSON
 * `{ Code, LastUpdated, Type, AccessKeyId, SecretAccessKey, Token, Expiration }`.
 * Borne du TTL appliquée ici : 1 à 21600 s (non lue sur ces pages).
 * @param {{access_key_id: string, secret_access_key: string, session_token: string}} identifiants
 */
export async function simulateurImds(identifiants, role = "role-signataire") {
  const jetons = new Set();
  return servirHttp(async (req) => {
    if (req.method === "PUT" && req.url === "/latest/api/token") {
      const ttl = Number(req.headers["x-aws-ec2-metadata-token-ttl-seconds"]);
      if (!(ttl >= 1 && ttl <= 21600)) return { statut: 400, corps: "" };
      const j = randomBytes(16).toString("base64");
      jetons.add(j);
      return { statut: 200, corps: j };
    }
    if (!jetons.has(req.headers["x-aws-ec2-metadata-token"])) return { statut: 401, corps: "" };
    if (req.url === "/latest/meta-data/iam/security-credentials/") return { statut: 200, corps: role };
    if (req.url === `/latest/meta-data/iam/security-credentials/${role}`) {
      return {
        statut: 200,
        corps: { Code: "Success", LastUpdated: new Date().toISOString(), Type: "AWS-HMAC", AccessKeyId: identifiants.access_key_id, SecretAccessKey: identifiants.secret_access_key, Token: identifiants.session_token, Expiration: new Date(Date.now() + 6 * 3600000).toISOString() },
      };
    }
    return { statut: 404, corps: "" };
  });
}

/**
 * Serveur de métadonnées de Compute Engine, d'après la page « Authenticate
 * workloads using service accounts » (relue le 2026-11-03) : `GET
 * /computeMetadata/v1/instance/service-accounts/default/token` avec
 * `Metadata-Flavor: Google` rend `{ access_token, expires_in, token_type }`.
 * Refus d'une requête sans l'en-tête (403) et en-tête `Metadata-Flavor:
 * Google` dans la réponse : non lus sur cette page (comportement du service
 * que vérifient les bibliothèques d'authentification de Google).
 * @param {() => string} jeton fabrique d'un jeton reconnu par le service KMS simulé
 * @param {{sansEntete?: boolean}} [o] réponse sans `Metadata-Flavor` (serveur qui n'en est pas un)
 */
export async function simulateurMetadonneesGoogle(jeton, o = {}) {
  return servirHttp(async (req) => {
    if (req.headers["metadata-flavor"] !== "Google") return { statut: 403, corps: "" };
    if (req.url !== "/computeMetadata/v1/instance/service-accounts/default/token") return { statut: 404, corps: "" };
    return { statut: 200, type: "application/json", entetes: o.sansEntete ? {} : { "metadata-flavor": "Google" }, corps: { access_token: jeton(), expires_in: 3599, token_type: "Bearer" } };
  });
}
