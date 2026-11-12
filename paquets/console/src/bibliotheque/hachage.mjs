// Primitives de hachage (CT-1 §6.1 et §6.3, CT-3 EX-9.17, EX-13.12) :
// SHA-256 et Keccak-256 de @noble/hashes 2.4.0, mêmes octets sous Node 22 et
// dans Chromium, sans module natif ni WebCrypto.

import { sha256 as sha256Noble } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

/**
 * SHA-256 (FIPS 180-4).
 * @param {Uint8Array} octets
 * @returns {Uint8Array} 32 octets
 */
export function sha256(octets) {
  if (!(octets instanceof Uint8Array)) throw new TypeError("sha256 : Uint8Array attendu");
  return sha256Noble(octets);
}

/**
 * Keccak-256 (celui d'Ethereum, non SHA3-256).
 * @param {Uint8Array} octets
 * @returns {Uint8Array} 32 octets
 */
export function keccak256(octets) {
  if (!(octets instanceof Uint8Array)) throw new TypeError("keccak256 : Uint8Array attendu");
  return keccak_256(octets);
}
