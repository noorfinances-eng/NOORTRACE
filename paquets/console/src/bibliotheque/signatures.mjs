// Signatures EIP-191 des votes et des inscriptions (CT-3 EX-9.3, EX-9.21,
// EX-9.22, EX-13.12, EX-13.16, EX-13.24 ; CT-1 §6.3) : préimage et condensé
// EIP-191 version 0x45, données et requête `personal_sign`, contrôle de forme
// fait par la bibliothèque elle-même avant toute primitive (EX-9.22),
// normalisation d'EX-9.3 sans la clé, recouvrement secp256k1 par
// @noble/curves 2.4.0 et calcul de l'adresse. La bibliothèque vérifie et
// recouvre ; elle ne signe jamais.

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak256 } from "./hachage.mjs";
import { concatener, depuisEntier, depuisHex, utf8Strict, versEntier, versHex } from "./octets.mjs";

/** Ordre `n` du groupe de secp256k1. */
export const N_SECP256K1 = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const DEMI_N = N_SECP256K1 >> 1n;

const ADRESSE = /^0x[0-9a-f]{40}$/;
const HEX_LIBRE = /^0x[0-9a-fA-F]*$/;

/**
 * Préimage EIP-191 version 0x45 : `0x19 ‖ "Ethereum Signed Message:\n" ‖
 * décimal(L) ‖ octets`, `L` étant la longueur des octets (CT-3 EX-13.12,
 * 13.9 pas 5).
 * @param {Uint8Array} octets
 * @returns {Uint8Array}
 */
export function preimageEip191(octets) {
  if (!(octets instanceof Uint8Array)) throw new TypeError("preimageEip191 : Uint8Array attendu");
  return concatener(Uint8Array.of(0x19), utf8Strict(`Ethereum Signed Message:\n${octets.length}`), octets);
}

/**
 * Keccak-256 de la préimage EIP-191 : `"0x…"`.
 * @param {Uint8Array} octets
 * @returns {string}
 */
export function condenseEip191(octets) {
  return versHex(keccak256(preimageEip191(octets)));
}

/**
 * Premier paramètre de `personal_sign` : `"0x"` et l'hexadécimal minuscule des
 * octets UTF-8 du texte, ou des octets donnés (CT-3 EX-13.12, EX-13.16).
 * @param {string|Uint8Array} texteOuOctets
 * @returns {string}
 */
export function donneesPersonalSign(texteOuOctets) {
  if (texteOuOctets instanceof Uint8Array) return versHex(texteOuOctets);
  if (typeof texteOuOctets === "string") return versHex(utf8Strict(texteOuOctets));
  throw new TypeError("donneesPersonalSign : chaine ou Uint8Array attendu");
}

/**
 * Requête EIP-1193 `personal_sign` : la donnée d'abord, puis l'adresse en
 * minuscules (CT-3 EX-13.24, EX-13.16).
 * @param {string} donnees `"0x…"` : `D_A` (66 caractères) ou rendu de `donneesPersonalSign`
 * @param {string} adresse
 * @returns {{method: "personal_sign", params: [string, string]}}
 */
export function requetePersonalSign(donnees, adresse) {
  if (typeof donnees !== "string" || !/^0x(?:[0-9a-f]{2})+$/.test(donnees)) {
    throw new TypeError("requetePersonalSign : donnees en hexadecimal minuscule attendues");
  }
  if (typeof adresse !== "string" || !ADRESSE.test(adresse.toLowerCase())) {
    throw new TypeError("requetePersonalSign : adresse attendue");
  }
  return { method: "personal_sign", params: [donnees, adresse.toLowerCase()] };
}

/**
 * Contrôle de forme et normalisation d'EX-9.3 et d'EX-9.21 (points 2 à 5),
 * sans primitive : `{ r, s, v }` normalisés, ou `null` (`signature_invalide`).
 * La chaîne est lue en casse indifférente, puis écrite en minuscules.
 * @param {string} signature
 * @returns {{r: bigint, s: bigint, v: number, hex: string}|null}
 */
export function normaliserSignature(signature) {
  if (typeof signature !== "string") throw new TypeError("normaliserSignature : chaine attendue");
  if (!HEX_LIBRE.test(signature)) return null;
  const o = depuisHex(signature.toLowerCase());
  if (o === null || o.length !== 65) return null;
  const r = versEntier(o.subarray(0, 32));
  let s = versEntier(o.subarray(32, 64));
  let v = o[64];
  if (r < 1n || r > N_SECP256K1 - 1n || s < 1n || s > N_SECP256K1 - 1n) return null;
  if (v !== 0 && v !== 1 && v !== 27 && v !== 28) return null;
  if (v < 27) v += 27;
  if (s > DEMI_N) {
    s = N_SECP256K1 - s;
    v = v === 27 ? 28 : 27;
  }
  const hex = versHex(concatener(depuisEntier(r, 32), depuisEntier(s, 32), Uint8Array.of(v)));
  return { r, s, v, hex };
}

/**
 * Adresse (20 derniers octets de keccak256(X ‖ Y)) recouvrée d'une signature
 * normalisée sur un condensé de 32 octets, ou `null` si le recouvrement est
 * impossible.
 * @param {{r: bigint, s: bigint, v: number}} sig
 * @param {Uint8Array} condense
 * @returns {string|null}
 */
export function recouvrerAdresse(sig, condense) {
  let point;
  try {
    point = new secp256k1.Signature(sig.r, sig.s, sig.v - 27).recoverPublicKey(condense);
  } catch {
    return null;
  }
  const brut = point.toBytes(false);
  if (brut.length !== 65 || brut[0] !== 0x04) return null;
  return versHex(keccak256(brut.subarray(1)).subarray(12));
}

/**
 * Vérifie une signature EIP-191 des octets signés pour l'adresse attendue
 * (CT-3 EX-9.3, EX-9.21 points 2 à 7, EX-9.22) : la forme est contrôlée avant
 * toute primitive, puis la signature est normalisée, l'adresse recouvrée sur le
 * condensé EIP-191 des octets et comparée à l'adresse attendue.
 * `signature` est la forme normalisée quand la signature est valide, `null`
 * sinon ; `recovered` est nul si la forme est refusée ou si le recouvrement est
 * impossible.
 * @param {Uint8Array} octets 32 octets de `D_A`, ou octets du texte
 * @param {string} signature telle que reçue
 * @param {string} adresse attendue
 * @returns {{valide: boolean, reason: null|"signature_invalide"|"adresse_differente", signature: string|null, recovered: string|null}}
 */
export function verifierSignature(octets, signature, adresse) {
  if (!(octets instanceof Uint8Array)) throw new TypeError("verifierSignature : Uint8Array attendu");
  if (typeof signature !== "string") throw new TypeError("verifierSignature : signature en chaine attendue");
  if (typeof adresse !== "string") throw new TypeError("verifierSignature : adresse en chaine attendue");
  const sig = normaliserSignature(signature);
  if (sig === null) return { valide: false, reason: "signature_invalide", signature: null, recovered: null };
  const condense = keccak256(preimageEip191(octets));
  const recovered = recouvrerAdresse(sig, condense);
  if (recovered === null) return { valide: false, reason: "signature_invalide", signature: null, recovered: null };
  if (recovered !== adresse) return { valide: false, reason: "adresse_differente", signature: null, recovered };
  return { valide: true, reason: null, signature: sig.hex, recovered };
}
