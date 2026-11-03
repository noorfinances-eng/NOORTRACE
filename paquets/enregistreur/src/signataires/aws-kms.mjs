// AWS KMS : classe B (signature, CT-2 §11.2) et enveloppe de la classe C
// (`Encrypt`/`Decrypt`, EX-11.9).
//
// Protocole JSON d'AWS KMS : POST / , `Content-Type:
// application/x-amz-json-1.1`, `X-Amz-Target: TrentService.<Action>`,
// signature SigV4 (service `kms`). Actions employées (identité d'usage seule,
// EX-11.4) :
//   GetPublicKey {KeyId}                → PublicKey (SPKI DER, base64), KeySpec,
//                                          KeyUsage, SigningAlgorithms
//   Sign {KeyId, Message, MessageType: "RAW", SigningAlgorithm: "ED25519_SHA_512"}
//                                        → Signature (base64), SigningAlgorithm
//   DescribeKey {KeyId}                 → KeyMetadata.KeyState (santé)
//   Decrypt {KeyId, CiphertextBlob, EncryptionContext, EncryptionAlgorithm: "SYMMETRIC_DEFAULT"}
//                                        → Plaintext (base64)
// `ECC_NIST_EDWARDS25519` et `ED25519_SHA_512` avec `MessageType: RAW` seuls :
// `ED25519_PH_SHA_512` double-hache et est exclu (EX-11.1) ; message de
// 4096 octets au plus (EX-11.7).
//
// Identité IAM : variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` et
// `AWS_SESSION_TOKEN`, ou rôle de l'instance par IMDSv2 (IdentiteAws,
// lectures 182 et 193) ;
// point d'accès `https://kms.<region>.amazonaws.com`, ou celui de
// `AWS_ENDPOINT_URL_KMS` / `AWS_ENDPOINT_URL` (variables des SDK d'AWS).

import { createHash, createHmac } from "node:crypto";
import { Signataire } from "../signataires.mjs";
import { ErreurSignataire, requete, json, base64Strict, clePubliqueSpki } from "./commun.mjs";

/** Borne de Sign avec MessageType RAW (R3 F-5). */
export const BORNE_MESSAGE_AWS_KMS = 4096;

const sha256hex = (b) => createHash("sha256").update(b).digest("hex");
const hmac = (k, d) => createHmac("sha256", k).update(d).digest();

/**
 * Identifiants IAM de l'environnement du démon (lecture 182).
 * @param {NodeJS.ProcessEnv} env
 * @returns {{access_key_id: string, secret_access_key: string, session_token: string|null}}
 */
export function identifiantsAwsEnvironnement(env) {
  const id = env.AWS_ACCESS_KEY_ID;
  const secret = env.AWS_SECRET_ACCESS_KEY;
  if (!id || !secret) throw new ErreurSignataire("identité IAM absente (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)", { code: "identite" });
  return { access_key_id: id, secret_access_key: secret, session_token: env.AWS_SESSION_TOKEN || null };
}

/**
 * Identité IAM du démon (lecture 182) : variables d'environnement
 * (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) ; à
 * défaut, identité du rôle de l'instance EC2 par IMDSv2 au point
 * `AWS_EC2_METADATA_SERVICE_ENDPOINT` (variable des kits d'AWS ; aucune
 * adresse par défaut n'est écrite ici, lecture 193), sauf si
 * `AWS_EC2_METADATA_DISABLED` vaut `true` :
 *   PUT  /latest/api/token  (`X-aws-ec2-metadata-token-ttl-seconds: 21600`) → jeton
 *   GET  /latest/meta-data/iam/security-credentials/            → nom du rôle
 *   GET  /latest/meta-data/iam/security-credentials/<rôle>      → { Code, AccessKeyId,
 *        SecretAccessKey, Token, Expiration }
 * Les identifiants temporaires sont gardés jusqu'à cinq minutes de leur fin.
 */
export class IdentiteAws {
  /**
   * @param {{env?: NodeJS.ProcessEnv, delaiMs?: number, maintenant?: () => number}} [o]
   */
  constructor(o = {}) {
    this.env = o.env ?? process.env;
    this.delai = o.delaiMs ?? 5000;
    this.maintenant = o.maintenant ?? Date.now;
    this.cache = null;
    this.fin = 0;
  }

  /** @returns {Promise<{access_key_id: string, secret_access_key: string, session_token: string|null}>} */
  async valeur() {
    if (this.env.AWS_ACCESS_KEY_ID && this.env.AWS_SECRET_ACCESS_KEY) return identifiantsAwsEnvironnement(this.env);
    const point = this.env.AWS_EC2_METADATA_SERVICE_ENDPOINT;
    if (!point || String(this.env.AWS_EC2_METADATA_DISABLED).toLowerCase() === "true") {
      throw new ErreurSignataire("identité IAM absente (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, ou AWS_EC2_METADATA_SERVICE_ENDPOINT)", { code: "identite" });
    }
    if (this.cache && this.maintenant() < this.fin - 300000) return this.cache;
    const base = point.replace(/\/+$/, "");
    const r1 = await requete({ url: `${base}/latest/api/token`, methode: "PUT", entetes: { "x-aws-ec2-metadata-token-ttl-seconds": "21600" }, delaiMs: this.delai });
    if (r1.statut !== 200) throw new ErreurSignataire(`IMDSv2 : jeton refusé (statut ${r1.statut})`, { code: "identite" });
    const jeton = r1.corps.toString("utf8").trim();
    const lire = async (chemin) => {
      const r = await requete({ url: `${base}/latest/meta-data/iam/security-credentials/${chemin}`, entetes: { "x-aws-ec2-metadata-token": jeton }, delaiMs: this.delai });
      if (r.statut !== 200) throw new ErreurSignataire(`IMDSv2 : statut ${r.statut}`, { code: "identite" });
      return r.corps.toString("utf8");
    };
    const role = (await lire("")).split("\n")[0].trim();
    if (!/^[\w+=,.@-]{1,128}$/.test(role)) throw new ErreurSignataire("IMDSv2 : aucun rôle d'instance", { code: "identite" });
    const c = json(Buffer.from(await lire(encodeURIComponent(role))));
    if (c?.Code !== "Success" || !c.AccessKeyId || !c.SecretAccessKey || !c.Token) throw new ErreurSignataire("IMDSv2 : identifiants du rôle illisibles", { code: "identite" });
    this.cache = { access_key_id: c.AccessKeyId, secret_access_key: c.SecretAccessKey, session_token: c.Token };
    this.fin = Date.parse(c.Expiration) || this.maintenant() + 3600000;
    return this.cache;
  }
}

/**
 * Origine du service KMS d'une région.
 * @param {string} region
 * @param {NodeJS.ProcessEnv} env
 */
export function origineKms(region, env) {
  return (env.AWS_ENDPOINT_URL_KMS || env.AWS_ENDPOINT_URL || `https://kms.${region}.amazonaws.com`).replace(/\/+$/, "");
}

/** Région d'un ARN KMS. */
export function regionArn(arn) {
  return String(arn).split(":")[3] ?? null;
}

/**
 * En-têtes SigV4 d'une requête POST / au service `kms` (AWS Signature Version 4).
 * @param {object} p
 * @param {string} p.hote valeur de l'en-tête Host
 * @param {string} p.region
 * @param {string} p.cible `TrentService.<Action>`
 * @param {Buffer} p.corps
 * @param {{access_key_id: string, secret_access_key: string, session_token: string|null}} p.identifiants
 * @param {number} [p.instant] ms
 */
export function entetesSigv4Kms(p) {
  const d = new Date(p.instant ?? Date.now()).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const jour = d.slice(0, 8);
  const entetes = {
    "content-type": "application/x-amz-json-1.1",
    host: p.hote,
    "x-amz-date": d,
    "x-amz-target": p.cible,
  };
  if (p.identifiants.session_token) entetes["x-amz-security-token"] = p.identifiants.session_token;
  const noms = Object.keys(entetes).sort();
  const canon = ["POST", "/", "", noms.map((n) => `${n}:${entetes[n]}\n`).join(""), noms.join(";"), sha256hex(p.corps)].join("\n");
  const portee = `${jour}/${p.region}/kms/aws4_request`;
  const aSigner = ["AWS4-HMAC-SHA256", d, portee, sha256hex(canon)].join("\n");
  let k = hmac(`AWS4${p.identifiants.secret_access_key}`, jour);
  k = hmac(k, p.region);
  k = hmac(k, "kms");
  k = hmac(k, "aws4_request");
  const sig = createHmac("sha256", k).update(aSigner).digest("hex");
  entetes.authorization = `AWS4-HMAC-SHA256 Credential=${p.identifiants.access_key_id}/${portee}, SignedHeaders=${noms.join(";")}, Signature=${sig}`;
  return entetes;
}

/** Client minimal de l'API JSON d'AWS KMS (une tentative par appel). */
export class ClientKms {
  /**
   * @param {{region: string, env?: NodeJS.ProcessEnv, delaiMs?: number, ca?: Buffer|string|null, identifiants?: object}} o
   */
  constructor(o) {
    this.region = o.region;
    const env = o.env ?? process.env;
    this.origine = origineKms(o.region, env);
    this.identite = o.identifiants ? { valeur: async () => o.identifiants } : new IdentiteAws({ env, delaiMs: o.delaiMs });
    this.delai = o.delaiMs ?? 5000;
    this.ca = o.ca ?? null;
  }

  /**
   * @param {string} action
   * @param {object} corps
   * @returns {Promise<object>}
   */
  async appeler(action, corps) {
    const octets = Buffer.from(JSON.stringify(corps));
    const u = new URL(this.origine);
    const entetes = entetesSigv4Kms({ hote: u.host, region: this.region, cible: `TrentService.${action}`, corps: octets, identifiants: await this.identite.valeur() });
    const r = await requete({ url: `${this.origine}/`, methode: "POST", entetes, corps: octets, delaiMs: this.delai, ca: this.ca });
    const j = json(r.corps);
    if (r.statut !== 200) {
      const type = String(j?.__type ?? "").split("#").pop();
      throw new ErreurSignataire(`aws-kms ${action} : statut ${r.statut}${type ? ` (${type})` : ""}`, { statut: r.statut, code: type || null });
    }
    if (!j || typeof j !== "object") throw new ErreurSignataire(`aws-kms ${action} : réponse illisible`);
    return j;
  }
}

/** Classe B : clé `ECC_NIST_EDWARDS25519` d'AWS KMS. */
export class SignataireAwsKms extends Signataire {
  /**
   * @param {object} p
   * @param {{key_arn: string, region: string}} p.backend
   * @param {string} p.keyId
   * @param {string|null} [p.nextKeyId] clé suivante : alias `alias/<next_key_id>` du même compte (lecture 177)
   * @param {ClientKms} p.client
   */
  constructor(p) {
    super();
    this.backend = p.backend;
    this.keyId = p.keyId;
    this.nextKeyId = p.nextKeyId ?? null;
    this.client = p.client;
  }

  get classe() {
    return "B";
  }

  get typeBackend() {
    return "aws-kms";
  }

  clesConnues() {
    return [this.keyId, ...(this.nextKeyId ? [this.nextKeyId] : [])];
  }

  /** KeyId de la requête : l'ARN configuré, ou l'ARN d'alias de la clé suivante. */
  identifiantKms(keyId) {
    if (keyId === this.keyId) return this.backend.key_arn;
    if (keyId === this.nextKeyId) {
      const [arn, partition, service, region, compte] = this.backend.key_arn.split(":");
      return [arn, partition, service, region, compte, `alias/${this.nextKeyId}`].join(":");
    }
    throw new ErreurSignataire(`clé ${keyId} inconnue du signataire`);
  }

  localisation(keyId) {
    return { key_arn: this.identifiantKms(keyId), region: this.backend.region };
  }

  async clePublique(keyId) {
    const r = await this.client.appeler("GetPublicKey", { KeyId: this.identifiantKms(keyId) });
    if (r.KeySpec !== "ECC_NIST_EDWARDS25519") throw new ErreurSignataire(`clé KMS ${r.KeySpec} : ECC_NIST_EDWARDS25519 attendue (EX-11.1)`, { code: "type" });
    if (r.KeyUsage !== "SIGN_VERIFY") throw new ErreurSignataire(`clé KMS d'usage ${r.KeyUsage} : SIGN_VERIFY attendu`, { code: "usage" });
    if (!Array.isArray(r.SigningAlgorithms) || !r.SigningAlgorithms.includes("ED25519_SHA_512")) {
      throw new ErreurSignataire("clé KMS sans ED25519_SHA_512 (EX-11.1)", { code: "type" });
    }
    return clePubliqueSpki(base64Strict(r.PublicKey, "PublicKey"));
  }

  async signer(keyId, message) {
    if (message.length > BORNE_MESSAGE_AWS_KMS) throw new ErreurSignataire(`message de ${message.length} octets : au plus ${BORNE_MESSAGE_AWS_KMS} (EX-11.7)`, { code: "borne" });
    const r = await this.client.appeler("Sign", {
      KeyId: this.identifiantKms(keyId),
      Message: Buffer.from(message).toString("base64"),
      MessageType: "RAW",
      SigningAlgorithm: "ED25519_SHA_512",
    });
    if (r.SigningAlgorithm !== undefined && r.SigningAlgorithm !== "ED25519_SHA_512") throw new ErreurSignataire(`algorithme rendu ${r.SigningAlgorithm} (EX-11.1)`);
    // Format binaire non documenté (R3 NV-11) : l'enveloppe commune vérifie
    // 64 octets R ‖ S sous la clé publique (EX-11.6).
    return base64Strict(r.Signature, "Signature");
  }

  async sante() {
    const r = await this.client.appeler("DescribeKey", { KeyId: this.backend.key_arn });
    const etat = r.KeyMetadata?.KeyState;
    return etat === "Enabled" ? "ok" : `clé KMS dans l'état ${etat ?? "inconnu"}`;
  }
}

/**
 * Classe C, enveloppe AWS KMS : déchiffre la graine enveloppée (EX-11.9).
 * @param {object} p
 * @param {{key_arn: string, region: string}} p.wrap
 * @param {Uint8Array} p.chiffre contenu du fichier scellé (CiphertextBlob brut)
 * @param {{carte: object}} p.contexte contexte de chiffrement (org_id, journal_id, key_id)
 * @param {ClientKms} p.client
 * @returns {Promise<Uint8Array>} 32 octets
 */
export async function desenvelopperAwsKms(p) {
  const r = await p.client.appeler("Decrypt", {
    KeyId: p.wrap.key_arn,
    CiphertextBlob: Buffer.from(p.chiffre).toString("base64"),
    EncryptionContext: p.contexte.carte,
    EncryptionAlgorithm: "SYMMETRIC_DEFAULT",
  });
  if (r.KeyId !== undefined && r.KeyId !== p.wrap.key_arn) throw new ErreurSignataire("aws-kms Decrypt : clé rendue différente de la clé configurée");
  return base64Strict(r.Plaintext, "Plaintext");
}
