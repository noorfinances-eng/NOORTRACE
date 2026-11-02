// Hachage et signatures (CT-1 §6, §8, §10.2, §10.6, annexe B ; CT-7 §7.2).
//
// SHA-256 et Ed25519 par node:crypto ; Keccak-256 et secp256k1 (EIP-191,
// recouvrement d'adresse) par @noble/hashes et @noble/curves.
//
// Ed25519 est vérifié sous la forme sans cofacteur de la RFC 8032 §5.1.7,
// celle d'OpenSSL, après des refus explicites que la RFC 8032 et CT-1 §6.2
// exigent : S non réduit modulo l'ordre, R ou A d'encodage non canonique
// (y ≥ p), A de petit ordre.

import { createHash, createPrivateKey, createPublicKey, sign as signerNode, verify as verifierNode } from "node:crypto";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { concatener, estHex, hexVersOctets, octetsVersHex, utf8 } from "./conventions.mjs";

/**
 * Préfixes de domaine, octets UTF-8 des étiquettes terminées par un saut de
 * ligne (CT-1 annexe B, §10.6 ; CT-7 §7.2 pour P_P).
 */
export const PREFIXES = Object.freeze({
  P_H: utf8("noortrace/evenement/v0\n"),
  P_S: utf8("noortrace/signature-evenement/v0\n"),
  P_M: utf8("noortrace/manifeste/v0\n"),
  P_SM: utf8("noortrace/signature-manifeste/v0\n"),
  P_A: utf8("noortrace/approbation/v0\n"),
  P_R: utf8("noortrace/signature-rotation/v0\n"),
  P_K: utf8("noortrace/point-de-controle/v0\n"),
  P_SK: utf8("noortrace/signature-point-de-controle/v0\n"),
  P_P: utf8("noortrace/attestation-perimetre/v0\n"),
});

/**
 * SHA-256 d'une suite d'octets.
 * @param {Uint8Array} octets
 * @returns {Uint8Array} 32 octets
 */
export function sha256(octets) {
  return Uint8Array.from(createHash("sha256").update(octets).digest());
}

/**
 * Keccak-256 (celui d'Ethereum, non SHA3-256) d'une suite d'octets.
 * @param {Uint8Array} octets
 * @returns {Uint8Array} 32 octets
 */
export function keccak256(octets) {
  return keccak_256(octets);
}

/**
 * SHA-256 en hexadécimal préfixé.
 * @param {Uint8Array} octets
 * @returns {string}
 */
export function sha256Hex(octets) {
  return octetsVersHex(sha256(octets));
}

// ---------------------------------------------------------------- Ed25519

const P_ED = 2n ** 255n - 19n;
const L_ED = 2n ** 252n + 27742317777372353535851937790883648493n;
const PREFIXE_SPKI = Uint8Array.from(Buffer.from("302a300506032b6570032100", "hex"));
const PREFIXE_PKCS8 = Uint8Array.from(Buffer.from("302e020100300506032b657004220420", "hex"));

/** Les huit encodages canoniques des points de petit ordre (CT-1 annexe B). */
export const POINTS_PETIT_ORDRE = Object.freeze([
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
]);

function entierPetitBoutiste(octets) {
  let x = 0n;
  for (let k = octets.length - 1; k >= 0; k--) x = (x << 8n) | BigInt(octets[k]);
  return x;
}

function coordonneeY(octets) {
  const copie = Uint8Array.from(octets);
  copie[31] &= 0x7f;
  return entierPetitBoutiste(copie);
}

// Coordonnées y des points de petit ordre : un encodage dont le y est l'une
// d'elles est refusé quel que soit le bit de signe (pour x = 0, le bit de
// signe à 1 est de toute façon un encodage invalide, RFC 8032 §5.1.3).
const Y_PETIT_ORDRE = new Set(POINTS_PETIT_ORDRE.map((h) => coordonneeY(Uint8Array.from(Buffer.from(h, "hex")))));

/**
 * Dit si 32 octets sont un encodage canonique de point Ed25519 (y < p).
 * @param {Uint8Array} octets
 * @returns {boolean}
 */
export function encodageEd25519Canonique(octets) {
  return octets instanceof Uint8Array && octets.length === 32 && coordonneeY(octets) < P_ED;
}

/**
 * Dit si une clé publique Ed25519 est admise par CT-1 §6.2 : 32 octets,
 * encodage canonique, pas un point de petit ordre.
 * @param {Uint8Array} cle
 * @returns {boolean}
 */
export function clePubliqueEd25519Admise(cle) {
  return encodageEd25519Canonique(cle) && !Y_PETIT_ORDRE.has(coordonneeY(cle));
}

function objetClePublique(cle) {
  return createPublicKey({ key: Buffer.from(concatener(PREFIXE_SPKI, cle)), format: "der", type: "spki" });
}

function objetClePrivee(graine) {
  if (!(graine instanceof Uint8Array) || graine.length !== 32) throw new TypeError("graine Ed25519 de 32 octets attendue");
  return createPrivateKey({ key: Buffer.from(concatener(PREFIXE_PKCS8, graine)), format: "der", type: "pkcs8" });
}

/**
 * Clé publique Ed25519 (RFC 8032 §5.1.5) d'une graine de 32 octets.
 * @param {Uint8Array} graine
 * @returns {Uint8Array} 32 octets
 */
export function clePubliqueEd25519(graine) {
  const spki = createPublicKey(objetClePrivee(graine)).export({ format: "der", type: "spki" });
  return Uint8Array.from(spki.subarray(spki.length - 32));
}

/**
 * Signature Ed25519 « pure » (RFC 8032 §5.1.6 : ni pré-hachage, ni contexte).
 * @param {Uint8Array} graine clé privée de 32 octets
 * @param {Uint8Array} message
 * @returns {Uint8Array} 64 octets R || S
 */
export function signerEd25519(graine, message) {
  return Uint8Array.from(signerNode(null, message, objetClePrivee(graine)));
}

/**
 * Vérifie une signature Ed25519 selon CT-1 §6.2 : 64 octets, S < ℓ, R et A
 * d'encodage canonique, A hors des points de petit ordre, équation sans
 * cofacteur [S]B = R + [k]A.
 * @param {Uint8Array} clePublique 32 octets
 * @param {Uint8Array} message
 * @param {Uint8Array} signature 64 octets
 * @returns {boolean}
 */
export function verifierEd25519(clePublique, message, signature) {
  if (!(signature instanceof Uint8Array) || signature.length !== 64) return false;
  if (!(message instanceof Uint8Array)) return false;
  if (!clePubliqueEd25519Admise(clePublique)) return false;
  if (!encodageEd25519Canonique(signature.subarray(0, 32))) return false;
  if (entierPetitBoutiste(signature.subarray(32, 64)) >= L_ED) return false;
  try {
    return verifierNode(null, message, objetClePublique(clePublique), signature);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- EIP-191

const N_SECP = secp256k1.Point.CURVE().n;
const DEMI_N = N_SECP >> 1n;
const PREFIXE_EIP191 = utf8("\x19Ethereum Signed Message:\n32");

function entierGrandBoutiste(octets) {
  let x = 0n;
  for (const o of octets) x = (x << 8n) | BigInt(o);
  return x;
}

function octetsGrandBoutiste(x, longueur) {
  const sortie = new Uint8Array(longueur);
  for (let k = longueur - 1; k >= 0; k--) {
    sortie[k] = Number(x & 0xffn);
    x >>= 8n;
  }
  return sortie;
}

/**
 * Message EIP-191 (version 0x45, `personal_sign`) d'un condensé de 32 octets :
 * M = keccak256("\x19Ethereum Signed Message:\n32" || D) (CT-1 §6.3).
 * @param {Uint8Array} condense 32 octets
 * @returns {Uint8Array} 32 octets
 */
export function messageEip191(condense) {
  if (!(condense instanceof Uint8Array) || condense.length !== 32) throw new TypeError("condensé de 32 octets attendu");
  return keccak256(concatener(PREFIXE_EIP191, condense));
}

/**
 * Adresse Ethereum (20 octets, hexadécimal minuscule) d'une clé privée
 * secp256k1.
 * @param {Uint8Array} clePrivee 32 octets
 * @returns {string}
 */
export function adresseDepuisClePrivee(clePrivee) {
  const publique = secp256k1.getPublicKey(clePrivee, false);
  return octetsVersHex(keccak256(publique.subarray(1)).subarray(12));
}

/**
 * Signe un condensé de 32 octets en EIP-191 (`personal_sign`), RFC 6979,
 * forme canonique (s bas) : r (32) || s (32) || v (1), v ∈ {27, 28}.
 * C'est `signer.signMessage(getBytes(D))` d'ethers.
 * @param {Uint8Array} clePrivee 32 octets
 * @param {Uint8Array} condense 32 octets
 * @returns {Uint8Array} 65 octets
 */
export function signerEip191(clePrivee, condense) {
  const recouvrable = secp256k1.sign(messageEip191(condense), clePrivee, { prehash: false, lowS: true, format: "recovered" });
  // Forme « recovered » de @noble/curves 2 : octet de recouvrement en tête.
  return concatener(recouvrable.subarray(1, 65), Uint8Array.of(27 + recouvrable[0]));
}

/**
 * Recouvre l'adresse qui a signé un condensé en EIP-191, avec les refus de
 * CT-1 §6.3 et CT-7 EX-7.6 : 65 octets, r et s dans [1, n − 1], s dans la
 * moitié basse de l'ordre, v ∈ {27, 28}.
 * @param {Uint8Array} condense 32 octets (D_A, D_P…)
 * @param {Uint8Array} signature 65 octets
 * @returns {{adresse: string|null, canonique: boolean, raison: string|null}}
 */
export function recouvrerAdresseEip191(condense, signature) {
  if (!(signature instanceof Uint8Array) || signature.length !== 65) {
    return { adresse: null, canonique: false, raison: "signature de 65 octets attendue" };
  }
  const r = entierGrandBoutiste(signature.subarray(0, 32));
  const s = entierGrandBoutiste(signature.subarray(32, 64));
  const v = signature[64];
  if (v !== 27 && v !== 28) return { adresse: null, canonique: false, raison: `v vaut ${v}, 27 ou 28 attendu` };
  if (r < 1n || r >= N_SECP || s < 1n || s >= N_SECP) return { adresse: null, canonique: false, raison: "r ou s hors de [1, n − 1]" };
  if (s > DEMI_N) return { adresse: null, canonique: false, raison: "s dans la moitié haute de l'ordre (forme non canonique)" };
  try {
    const sig = new secp256k1.Signature(r, s, v - 27);
    const point = sig.recoverPublicKey(messageEip191(condense));
    const publique = point.toBytes(false);
    return { adresse: octetsVersHex(keccak256(publique.subarray(1)).subarray(12)), canonique: true, raison: null };
  } catch {
    return { adresse: null, canonique: true, raison: "aucune clé publique ne se recouvre" };
  }
}

/**
 * Vérifie qu'une signature EIP-191 hexadécimale sur un condensé est
 * canonique et recouvre l'adresse attendue.
 * @param {Uint8Array} condense
 * @param {string} signatureHex
 * @param {string} adresse adresse attendue, minuscules
 * @returns {boolean}
 */
export function verifierEip191(condense, signatureHex, adresse) {
  if (!estHex(signatureHex, 65) || !estHex(adresse, 20)) return false;
  const { adresse: recouvree } = recouvrerAdresseEip191(condense, hexVersOctets(signatureHex));
  return recouvree === adresse;
}

/**
 * Met une signature EIP-191 en forme haute (s ← n − s, v complémenté) : même
 * point, même adresse pour un vérificateur laxiste, refusée par CT-1 §6.3.
 * Sert aux tests de refus.
 * @param {Uint8Array} signature 65 octets canoniques
 * @returns {Uint8Array}
 */
export function formeHauteEip191(signature) {
  const s = entierGrandBoutiste(signature.subarray(32, 64));
  return concatener(signature.subarray(0, 32), octetsGrandBoutiste(N_SECP - s, 32), Uint8Array.of(signature[64] === 27 ? 28 : 27));
}
