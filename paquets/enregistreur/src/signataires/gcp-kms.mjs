// Google Cloud KMS : classe B (signature `EC_SIGN_ED25519`, CT-2 §11.2) et
// enveloppe de la classe C (`decrypt`, EX-11.9).
//
// Requêtes (API REST v1 de Cloud KMS, pages citées par la table des backends) :
//   GET  v1/{key_version}/publicKey        → pem, pemCrc32c, algorithm, name
//   POST v1/{key_version}:asymmetricSign   {"data": base64, "dataCrc32c": "<entier>"}
//        → signature (base64), signatureCrc32c, verifiedDataCrc32c, name
//   GET  v1/{key_version}                  → state (santé)
//   POST v1/{key}:decrypt                  {"ciphertext", "ciphertextCrc32c",
//        "additionalAuthenticatedData", "additionalAuthenticatedDataCrc32c"}
//        → plaintext (base64), plaintextCrc32c
// `EC_SIGN_ED25519` est PureEdDSA : le champ `data` porte le message brut
// (jamais `digest`). Les sommes CRC32C sont envoyées et contrôlées dans les
// deux sens ; une réponse dont la somme ne concorde pas est une panne.
//
// Identité IAM (lecture 182) : jeton OAuth 2.0 obtenu d'un compte de service
// (`GOOGLE_APPLICATION_CREDENTIALS`, assertion JWT RS256, RFC 7523, portée
// `https://www.googleapis.com/auth/cloudkms`) ; point d'accès
// `https://cloudkms.googleapis.com/`, ou celui de
// `CLOUDSDK_API_ENDPOINT_OVERRIDES_CLOUDKMS` (propriété de gcloud).

import fs from "node:fs";
import { createSign } from "node:crypto";
import { Signataire } from "../signataires.mjs";
import { ErreurSignataire, requete, json, base64Strict, clePubliquePem, crc32c } from "./commun.mjs";

export const PORTEE_CLOUDKMS = "https://www.googleapis.com/auth/cloudkms";

/** Origine de l'API Cloud KMS. */
export function origineCloudKms(env) {
  return (env.CLOUDSDK_API_ENDPOINT_OVERRIDES_CLOUDKMS || "https://cloudkms.googleapis.com/").replace(/\/+$/, "");
}

/** Jeton OAuth d'un compte de service (fichier de clé JSON), mis en cache jusqu'à une minute de sa fin. */
export class JetonGoogle {
  /**
   * @param {{env?: NodeJS.ProcessEnv, delaiMs?: number, ca?: Buffer|string|null, maintenant?: () => number}} o
   */
  constructor(o = {}) {
    const env = o.env ?? process.env;
    const f = env.GOOGLE_APPLICATION_CREDENTIALS;
    if (!f) throw new ErreurSignataire("identité IAM absente (GOOGLE_APPLICATION_CREDENTIALS)", { code: "identite" });
    let compte;
    try {
      compte = JSON.parse(fs.readFileSync(f, "utf8"));
    } catch {
      throw new ErreurSignataire("fichier de compte de service illisible", { code: "identite" });
    }
    if (compte.type !== "service_account" || !compte.client_email || !compte.private_key || !compte.token_uri) {
      throw new ErreurSignataire("fichier de compte de service incomplet (type, client_email, private_key, token_uri)", { code: "identite" });
    }
    this.compte = compte;
    this.delai = o.delaiMs ?? 5000;
    this.ca = o.ca ?? null;
    this.maintenant = o.maintenant ?? Date.now;
    this.jeton = null;
    this.fin = 0;
  }

  async valeur() {
    const t = this.maintenant();
    if (this.jeton && t < this.fin - 60000) return this.jeton;
    const s = Math.floor(t / 1000);
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const entete = b64({ alg: "RS256", typ: "JWT", ...(this.compte.private_key_id ? { kid: this.compte.private_key_id } : {}) });
    const charge = b64({ iss: this.compte.client_email, scope: PORTEE_CLOUDKMS, aud: this.compte.token_uri, iat: s, exp: s + 3600 });
    const sig = createSign("RSA-SHA256").update(`${entete}.${charge}`).sign(this.compte.private_key).toString("base64url");
    const corps = new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: `${entete}.${charge}.${sig}` }).toString();
    const r = await requete({ url: this.compte.token_uri, methode: "POST", entetes: { "content-type": "application/x-www-form-urlencoded" }, corps, delaiMs: this.delai, ca: this.ca });
    const j = json(r.corps);
    if (r.statut !== 200 || typeof j?.access_token !== "string") throw new ErreurSignataire(`jeton Google refusé : statut ${r.statut}`, { statut: r.statut, code: "identite" });
    this.jeton = j.access_token;
    this.fin = t + Number(j.expires_in ?? 3600) * 1000;
    return this.jeton;
  }
}

/**
 * Jeton OAuth du compte de service d'une instance Google (serveur de
 * métadonnées, lecture 193) : `GET http://<hôte>/computeMetadata/v1/instance/
 * service-accounts/default/token`, en-tête `Metadata-Flavor: Google` exigé
 * dans la requête et dans la réponse ; hôte `metadata.google.internal`, ou
 * celui de `GCE_METADATA_HOST` (variable des bibliothèques d'authentification
 * de Google).
 */
export class JetonMetadonneesGoogle {
  /** @param {{env?: NodeJS.ProcessEnv, delaiMs?: number, maintenant?: () => number}} [o] */
  constructor(o = {}) {
    const env = o.env ?? process.env;
    this.hote = env.GCE_METADATA_HOST || "metadata.google.internal";
    this.delai = o.delaiMs ?? 5000;
    this.maintenant = o.maintenant ?? Date.now;
    this.jeton = null;
    this.fin = 0;
  }

  async valeur() {
    const t = this.maintenant();
    if (this.jeton && t < this.fin - 60000) return this.jeton;
    const r = await requete({ url: `http://${this.hote}/computeMetadata/v1/instance/service-accounts/default/token`, entetes: { "metadata-flavor": "Google" }, delaiMs: this.delai });
    const j = json(r.corps);
    if (r.statut !== 200 || r.entetes["metadata-flavor"] !== "Google" || typeof j?.access_token !== "string") {
      throw new ErreurSignataire(`jeton du serveur de métadonnées refusé : statut ${r.statut}`, { statut: r.statut, code: "identite" });
    }
    this.jeton = j.access_token;
    this.fin = t + Number(j.expires_in ?? 3600) * 1000;
    return this.jeton;
  }
}

/** Client minimal de l'API REST de Cloud KMS (une tentative par appel). */
export class ClientCloudKms {
  /**
   * @param {{env?: NodeJS.ProcessEnv, delaiMs?: number, ca?: Buffer|string|null, jeton?: {valeur: () => Promise<string>}}} o
   */
  constructor(o = {}) {
    const env = o.env ?? process.env;
    this.origine = origineCloudKms(env);
    this.delai = o.delaiMs ?? 5000;
    this.ca = o.ca ?? null;
    // Compte de service par fichier de clé s'il est désigné, sinon celui de l'instance.
    this.jeton = o.jeton ?? (env.GOOGLE_APPLICATION_CREDENTIALS ? new JetonGoogle({ env, delaiMs: this.delai, ca: this.ca }) : new JetonMetadonneesGoogle({ env, delaiMs: this.delai }));
  }

  async appeler(methode, chemin, corps = null) {
    const entetes = { authorization: `Bearer ${await this.jeton.valeur()}`, accept: "application/json" };
    if (corps) entetes["content-type"] = "application/json";
    const r = await requete({ url: `${this.origine}/v1/${chemin}`, methode, entetes, corps: corps ? JSON.stringify(corps) : null, delaiMs: this.delai, ca: this.ca });
    const j = json(r.corps);
    if (r.statut !== 200) {
      const statut = typeof j?.error?.status === "string" ? j.error.status : "";
      throw new ErreurSignataire(`gcp-kms : statut ${r.statut}${statut ? ` (${statut})` : ""}`, { statut: r.statut, code: statut || null });
    }
    if (!j || typeof j !== "object") throw new ErreurSignataire("gcp-kms : réponse illisible");
    return j;
  }
}

/** Entier CRC32C tel que l'API l'écrit (int64 en chaîne). */
const crcTexte = (o) => String(crc32c(o));

/** Classe B : version de clé `EC_SIGN_ED25519` de Cloud KMS. */
export class SignataireCloudKms extends Signataire {
  /**
   * @param {object} p
   * @param {{key_version: string}} p.backend
   * @param {string} p.keyId
   * @param {string|null} [p.nextKeyId] clé suivante : `…/cryptoKeys/<next_key_id>/cryptoKeyVersions/1` du même trousseau (lecture 177)
   * @param {ClientCloudKms} p.client
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
    return "gcp-kms";
  }

  clesConnues() {
    return [this.keyId, ...(this.nextKeyId ? [this.nextKeyId] : [])];
  }

  nomRessource(keyId) {
    if (keyId === this.keyId) return this.backend.key_version;
    if (keyId === this.nextKeyId) return this.backend.key_version.replace(/\/cryptoKeys\/[^/]+\/cryptoKeyVersions\/[0-9]+$/, `/cryptoKeys/${this.nextKeyId}/cryptoKeyVersions/1`);
    throw new ErreurSignataire(`clé ${keyId} inconnue du signataire`);
  }

  localisation(keyId) {
    return { key_version: this.nomRessource(keyId) };
  }

  async clePublique(keyId) {
    const nom = this.nomRessource(keyId);
    const r = await this.client.appeler("GET", `${nom}/publicKey`);
    if (r.algorithm !== "EC_SIGN_ED25519") throw new ErreurSignataire(`version de clé ${r.algorithm} : EC_SIGN_ED25519 attendu (EX-11.1)`, { code: "type" });
    if (r.name !== undefined && r.name !== nom) throw new ErreurSignataire("gcp-kms : clé publique d'une autre version");
    if (r.pemCrc32c !== undefined && String(r.pemCrc32c) !== crcTexte(Buffer.from(String(r.pem), "utf8"))) throw new ErreurSignataire("gcp-kms : pemCrc32c ne concorde pas");
    return clePubliquePem(r.pem);
  }

  async signer(keyId, message) {
    const nom = this.nomRessource(keyId);
    const r = await this.client.appeler("POST", `${nom}:asymmetricSign`, { data: Buffer.from(message).toString("base64"), dataCrc32c: crcTexte(message) });
    if (r.verifiedDataCrc32c !== true) throw new ErreurSignataire("gcp-kms : dataCrc32c non vérifié par le service");
    if (r.name !== nom) throw new ErreurSignataire("gcp-kms : signature d'une autre version de clé");
    const sig = base64Strict(r.signature, "signature");
    if (String(r.signatureCrc32c) !== crcTexte(sig)) throw new ErreurSignataire("gcp-kms : signatureCrc32c ne concorde pas");
    return sig;
  }

  async sante() {
    const r = await this.client.appeler("GET", this.backend.key_version);
    return r.state === "ENABLED" ? "ok" : `version de clé dans l'état ${r.state ?? "inconnu"}`;
  }
}

/**
 * Classe C, enveloppe Cloud KMS : déchiffre la graine (EX-11.9), données
 * associées = contexte de chiffrement en JCS (lecture 179).
 * @param {object} p
 * @param {{key: string}} p.wrap
 * @param {Uint8Array} p.chiffre
 * @param {{octets: Uint8Array}} p.contexte
 * @param {ClientCloudKms} p.client
 * @returns {Promise<Uint8Array>}
 */
export async function desenvelopperCloudKms(p) {
  const r = await p.client.appeler("POST", `${p.wrap.key}:decrypt`, {
    ciphertext: Buffer.from(p.chiffre).toString("base64"),
    ciphertextCrc32c: crcTexte(p.chiffre),
    additionalAuthenticatedData: Buffer.from(p.contexte.octets).toString("base64"),
    additionalAuthenticatedDataCrc32c: crcTexte(p.contexte.octets),
  });
  const clair = base64Strict(r.plaintext, "plaintext");
  if (String(r.plaintextCrc32c) !== crcTexte(clair)) throw new ErreurSignataire("gcp-kms : plaintextCrc32c ne concorde pas");
  return clair;
}
