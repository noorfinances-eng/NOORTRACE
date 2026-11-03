// Outils communs aux signataires des classes A, B et C (CT-2 §11) : requêtes
// HTTP(S) bornées dans le temps (une seule tentative : la seconde est celle de
// l'enveloppe commune, EX-11.18), extraction d'une clé publique Ed25519 d'un
// SubjectPublicKeyInfo (RFC 8410), CRC32C (contrôles d'intégrité de Google
// Cloud KMS), contexte de chiffrement de la classe C (EX-11.9). Aucun secret
// n'est jamais placé dans un message d'erreur.

import http from "node:http";
import https from "node:https";
import { jcsOctets } from "@noortrace/noyau";

/** Erreur d'un backend de signature (message sans secret ni donnée signée). */
export class ErreurSignataire extends Error {
  /**
   * @param {string} message
   * @param {{code?: string|null, statut?: number|null, cause?: unknown}} [o]
   */
  constructor(message, o = {}) {
    super(message, o.cause === undefined ? undefined : { cause: o.cause });
    this.name = "ErreurSignataire";
    this.code = o.code ?? null;
    this.statut = o.statut ?? null;
  }
}

/** Préfixe DER d'un SubjectPublicKeyInfo Ed25519 (RFC 8410 : OID 1.3.101.112). */
const PREFIXE_SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Clé publique Ed25519 de 32 octets d'un SubjectPublicKeyInfo DER.
 * @param {Uint8Array} der
 * @returns {Uint8Array}
 */
export function clePubliqueSpki(der) {
  const b = Buffer.from(der);
  if (b.length !== 44 || !b.subarray(0, 12).equals(PREFIXE_SPKI_ED25519)) {
    throw new ErreurSignataire("clé publique : SubjectPublicKeyInfo Ed25519 (RFC 8410) attendu");
  }
  return new Uint8Array(b.subarray(12));
}

/**
 * Clé publique Ed25519 d'un PEM « PUBLIC KEY ».
 * @param {string} pem
 * @returns {Uint8Array}
 */
export function clePubliquePem(pem) {
  const m = /-----BEGIN PUBLIC KEY-----([\s\S]*?)-----END PUBLIC KEY-----/.exec(String(pem));
  if (!m) throw new ErreurSignataire("clé publique : PEM « PUBLIC KEY » attendu");
  return clePubliqueSpki(Buffer.from(m[1].replace(/\s+/g, ""), "base64"));
}

const TABLE_CRC32C = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0x82f63b78 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

/**
 * CRC32C (Castagnoli, RFC 3720 annexe B.4), en entier non signé.
 * @param {Uint8Array} octets
 * @returns {number}
 */
export function crc32c(octets) {
  let c = 0xffffffff;
  for (const o of octets) c = TABLE_CRC32C[(c ^ o) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/**
 * Contexte de chiffrement de la classe C (EX-11.9) : `org_id`, `journal_id`
 * et `key_id`, et rien d'autre (aucune donnée sensible : il peut paraître en
 * clair dans les journaux du KMS). Sous forme de carte (AWS
 * `EncryptionContext`) et d'octets JCS (Google `additionalAuthenticatedData`,
 * LISEZMOI, lecture 179).
 * @param {{org_id: string, journal_id: string, key_id: string}} c
 */
export function contexteChiffrement(c) {
  const carte = { org_id: c.org_id, journal_id: c.journal_id, key_id: c.key_id };
  return { carte, octets: jcsOctets(carte) };
}

/**
 * Requête HTTP(S) à une seule tentative, bornée par `delaiMs` (la connexion
 * est détruite à l'échéance), corps borné à `tailleMax`.
 * @param {object} p
 * @param {string} p.url
 * @param {string} [p.methode]
 * @param {Record<string, string>} [p.entetes]
 * @param {Uint8Array|string|null} [p.corps]
 * @param {number} p.delaiMs
 * @param {Buffer|string|null} [p.ca] autorité supplémentaire (essais) ; à défaut celles du système
 * @param {number} [p.tailleMax]
 * @returns {Promise<{statut: number, entetes: object, corps: Buffer}>}
 */
export function requete(p) {
  const u = new URL(p.url);
  const mod = u.protocol === "https:" ? https : u.protocol === "http:" ? http : null;
  if (!mod) return Promise.reject(new ErreurSignataire(`schéma d'URL non admis : ${u.protocol}`));
  const tailleMax = p.tailleMax ?? 1 << 20;
  return new Promise((res, rej) => {
    let fini = false;
    const finir = (f, v) => {
      if (fini) return;
      fini = true;
      clearTimeout(minuteur);
      f(v);
    };
    const corps = p.corps === undefined || p.corps === null ? null : Buffer.from(p.corps);
    const options = {
      method: p.methode ?? "GET",
      headers: { ...(p.entetes ?? {}), ...(corps ? { "content-length": String(corps.length) } : {}) },
      agent: false,
    };
    if (p.ca && mod === https) options.ca = p.ca;
    const req = mod.request(u, options, (r) => {
      const morceaux = [];
      let n = 0;
      r.on("data", (c) => {
        n += c.length;
        if (n > tailleMax) {
          req.destroy();
          finir(rej, new ErreurSignataire("réponse trop longue", { code: "taille" }));
          return;
        }
        morceaux.push(c);
      });
      r.on("end", () => finir(res, { statut: r.statusCode, entetes: r.headers, corps: Buffer.concat(morceaux) }));
      r.on("error", (e) => finir(rej, new ErreurSignataire(`réponse interrompue : ${e.code ?? e.message}`, { code: "transport", cause: e })));
    });
    const minuteur = setTimeout(() => {
      req.destroy();
      finir(rej, new ErreurSignataire("délai du backend dépassé", { code: "delai" }));
    }, p.delaiMs);
    req.on("error", (e) => finir(rej, new ErreurSignataire(`backend injoignable : ${e.code ?? e.message}`, { code: "transport", cause: e })));
    req.end(corps ?? undefined);
  });
}

/**
 * Corps JSON d'une réponse, ou null s'il est illisible.
 * @param {Buffer} corps
 */
export function json(corps) {
  try {
    return JSON.parse(corps.toString("utf8"));
  } catch {
    return null;
  }
}

/**
 * Base64 (RFC 4648 § 4) décodé strictement, ou erreur.
 * @param {unknown} texte
 * @param {string} quoi
 * @returns {Uint8Array}
 */
export function base64Strict(texte, quoi) {
  if (typeof texte !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(texte) || texte.length % 4 !== 0) {
    throw new ErreurSignataire(`${quoi} : base64 attendu`);
  }
  return new Uint8Array(Buffer.from(texte, "base64"));
}

/**
 * Base64url sans remplissage (RFC 4648 § 5, JWK et Azure Key Vault), décodé strictement.
 * @param {unknown} texte
 * @param {string} quoi
 * @returns {Uint8Array}
 */
export function base64urlStrict(texte, quoi) {
  if (typeof texte !== "string" || !/^[A-Za-z0-9_-]*$/.test(texte)) throw new ErreurSignataire(`${quoi} : base64url attendu`);
  return new Uint8Array(Buffer.from(texte, "base64url"));
}
