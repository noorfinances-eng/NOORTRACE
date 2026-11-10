// Requête `TimeStampReq`, octet pour octet (CT-5 EX-5.1 à EX-5.4, AN-5,
// AN-6) : construction, relecture par le lecteur DER borné, tirage du nonce.

import { createHash } from "node:crypto";
import {
  ErreurDer, ETIQUETTE, encoderTlv, encoderEntierNonNegatif, encoderOid, concat, hexVersOctets, octetsVersHex,
  lireUnique, enfants, attendre, lireEntier, lireOid, lireBooleen, lireOctets, lireAlgorithme, parametresAbsentsOuNuls,
  estUniversel,
} from "./der.mjs";
import { OID } from "./x509.mjs";

/** Octets de `hashAlgorithm` pour SHA-256 (EX-5.1 : paramètres `NULL` explicites). */
export const ALGORITHME_SHA256 = hexVersOctets("300d0609608648016503040201050000".slice(0, 30));

/** Borne du nonce : entier non signé de 64 bits, non nul (EX-5.3). */
export const NONCE_MAX = (1n << 64n) - 1n;

/** Refus de construction ou de relecture d'une requête (AN-5, AN-6). */
export class ErreurRequete extends Error {
  constructor(regle, message) {
    super(message);
    this.name = "ErreurRequete";
    this.regle = regle;
  }
}

/** Nonce en `bigint` depuis un `bigint`, un hexadécimal `0x…` ou un entier sûr. */
export function nonceVersBigint(nonce) {
  if (typeof nonce === "bigint") return nonce;
  if (typeof nonce === "number" && Number.isSafeInteger(nonce) && nonce >= 0) return BigInt(nonce);
  if (typeof nonce === "string" && /^0x[0-9a-fA-F]+$/.test(nonce)) return BigInt(nonce);
  throw new ErreurRequete("AN-6", "nonce : bigint ou hexadécimal 0x attendu");
}

/** Nonce en hexadécimal de 16 chiffres (`hex8` du schéma). */
export function nonceVersHex8(nonce) {
  const n = nonceVersBigint(nonce);
  if (n < 0n || n > NONCE_MAX) throw new ErreurRequete("AN-6", `nonce ${n} hors de [1, 2^64 - 1]`);
  return "0x" + n.toString(16).padStart(16, "0");
}

/**
 * Construit la requête d'EX-5.1 : `{ octets, sha256, nonce (hex8), taille }`.
 * `hash` vaut `"sha256"` seulement (EX-5.2) ; `certReq`, s'il est donné, doit
 * être vrai (EX-5.4) ; `policy_oid` nul : pas de `reqPolicy`.
 */
export function construireRequete({ imprint, hash = "sha256", nonce, policy_oid = null, certReq = true }) {
  if (hash !== "sha256") throw new ErreurRequete("AN-5", "algorithme : sha256 seulement (EX-5.2)");
  let empreinte;
  try {
    empreinte = imprint instanceof Uint8Array ? imprint : hexVersOctets(imprint);
  } catch {
    throw new ErreurRequete("AN-5", "empreinte : hexadécimal attendu");
  }
  if (empreinte.length !== 32) throw new ErreurRequete("AN-5", "empreinte : 32 octets attendus (SHA-256)");
  if (certReq !== true) throw new ErreurRequete("AN-5", "certReq vaut toujours TRUE (EX-5.4)");
  const n = nonceVersBigint(nonce);
  if (n < 1n || n > NONCE_MAX) throw new ErreurRequete("AN-6", `nonce ${n} hors de [1, 2^64 - 1]`);
  let politique = new Uint8Array(0);
  if (policy_oid !== null && policy_oid !== undefined) {
    if (typeof policy_oid !== "string" || !/^[0-2](\.(0|[1-9][0-9]*))+$/.test(policy_oid)) throw new ErreurRequete("AN-5", "policy_oid : OID en notation pointée attendu");
    politique = encoderOid(policy_oid);
  }
  const messageImprint = encoderTlv(0x30, concat(ALGORITHME_SHA256, encoderTlv(0x04, empreinte)));
  const corps = concat(
    Uint8Array.of(0x02, 0x01, 0x01), // version 1
    messageImprint,
    politique,
    encoderEntierNonNegatif(n),
    Uint8Array.of(0x01, 0x01, 0xff), // certReq TRUE
  );
  const octets = encoderTlv(0x30, corps);
  const relue = relireRequete(octets);
  if (relue.nonce !== nonceVersHex8(n) || relue.imprint !== octetsVersHex(empreinte) || (relue.policy_oid ?? null) !== (policy_oid ?? null)) {
    throw new ErreurRequete("AN-5", "relecture de la requête différente de la construction");
  }
  return { octets, sha256: octetsVersHex(new Uint8Array(createHash("sha256").update(octets).digest())), nonce: relue.nonce, taille: octets.length };
}

/**
 * Relit une requête avec le lecteur borné : exactement les champs d'EX-5.1,
 * dans l'ordre, sans autre forme. Rend `{ version, hash, imprint, policy_oid,
 * nonce (hex8), nonceBigint, certReq, taille }` ; lève `ErreurRequete` (AN-5).
 */
export function relireRequete(octets) {
  let seq;
  let e;
  try {
    seq = lireUnique(octets, 1);
    attendre(seq, ETIQUETTE.SEQUENCE, true, "TimeStampReq");
    e = enfants(seq);
  } catch (err) {
    throw new ErreurRequete("AN-5", `requête illisible : ${err.message}`);
  }
  try {
    let i = 0;
    const version = lireEntier(e[i++], { minimal: true });
    if (version !== 1n) throw new ErreurDer("version différente de 1");
    const mi = attendre(e[i++], ETIQUETTE.SEQUENCE, true, "MessageImprint");
    const mie = enfants(mi);
    if (mie.length !== 2) throw new ErreurDer("MessageImprint mal formé");
    const alg = lireAlgorithme(mie[0]);
    if (alg.oid !== OID.sha256 || alg.parametres === null || !parametresAbsentsOuNuls(alg)) throw new ErreurDer("hashAlgorithm : SHA-256 avec paramètres NULL attendu");
    const empreinte = lireOctets(mie[1]);
    if (empreinte.length !== 32) throw new ErreurDer("hashedMessage : 32 octets attendus");
    let policy = null;
    if (e[i] && estUniversel(e[i], ETIQUETTE.OID, false)) policy = lireOid(e[i++]);
    if (!e[i] || !estUniversel(e[i], ETIQUETTE.INTEGER, false)) throw new ErreurDer("nonce attendu");
    const nonceTlv = e[i++];
    if (nonceTlv.contenu.length > 1 && nonceTlv.contenu[0] === 0x00 && (nonceTlv.contenu[1] & 0x80) === 0) {
      throw new ErreurRequete("AN-5", "nonce : zéro de tête superflu (encodage non minimal)");
    }
    const nonce = lireEntier(nonceTlv, { minimal: true });
    if (nonce < 1n || nonce > NONCE_MAX) throw new ErreurRequete("AN-6", `nonce ${nonce} hors de [1, 2^64 - 1]`);
    if (!e[i]) throw new ErreurDer("certReq attendu");
    const certReq = lireBooleen(e[i++]);
    if (!certReq) throw new ErreurDer("certReq vaut toujours TRUE (EX-5.4)");
    if (i !== e.length) throw new ErreurDer("champ supplémentaire dans TimeStampReq");
    return { version: 1, hash: "sha256", imprint: octetsVersHex(empreinte), policy_oid: policy, nonce: nonceVersHex8(nonce), nonceBigint: nonce, certReq: true, taille: octets.length };
  } catch (err) {
    if (err instanceof ErreurRequete) throw err;
    throw new ErreurRequete("AN-5", err.message);
  }
}

/**
 * Tire un nonce de 64 bits dans `[1, 2^64 − 1]` avec la fonction d'aléa
 * injectée (`aleatoire(8)` → `Uint8Array`) ; un tirage nul est rejoué (EX-5.3).
 */
export function tirerNonce(aleatoire) {
  for (let essai = 0; essai < 64; essai++) {
    const o = aleatoire(8);
    if (!(o instanceof Uint8Array) || o.length !== 8) throw new ErreurRequete("AN-6", "aleatoire(8) doit rendre huit octets");
    let n = 0n;
    for (const b of o) n = (n << 8n) | BigInt(b);
    if (n !== 0n) return n;
  }
  throw new ErreurRequete("AN-6", "le générateur rend toujours zéro");
}
