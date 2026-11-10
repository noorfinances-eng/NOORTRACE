// Utilitaires d'octets du sous-module « registre » : entiers grand-boutistes,
// quantités JSON-RPC, RLP strict (CT-6 EX-11.5, règle 1 ; CT-4 §6.7.3) et
// base64 tel que le décodeur du nœud l'accepte (CT-6 EX-11.6).
//
// Tout décodage est borné et refuse les formes non minimales : un entier RLP
// à zéro de tête, une longueur longue pour une charge courte, un octet seul
// sous 0x80 écrit en chaîne d'un octet sont des défauts, jamais tolérés.

import { concatener, estHex, hexVersOctets as hexVersOctetsNoyau, octetsVersHex } from "@noortrace/noyau";

export { concatener, octetsVersHex };

/**
 * Décode l'hexadécimal minuscule préfixé `0x` ; la chaîne `0x` vide est
 * admise (données d'appel vides d'un approvisionnement, `data` d'un
 * journal sans donnée), ce que le noyau refuse.
 * @param {string} texte
 * @param {number} [octets] longueur exigée
 */
export function hexVersOctets(texte, octets) {
  if (texte === "0x" && (octets === undefined || octets === 0)) return new Uint8Array(0);
  return hexVersOctetsNoyau(texte, octets);
}

const MAX_U64 = (1n << 64n) - 1n;
const MAX_U256 = (1n << 256n) - 1n;

/** Dit si `v` est une suite d'octets. */
export function estOctets(v) {
  return v instanceof Uint8Array;
}

/**
 * Convertit une valeur en `bigint` non négatif : `bigint`, entier sûr,
 * chaîne décimale sans zéro de tête, ou quantité hexadécimale `0x…`.
 * @returns {bigint|null} null si la forme est refusée
 */
export function versEntier(v) {
  if (typeof v === "bigint") return v < 0n ? null : v;
  if (typeof v === "number") return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  if (typeof v === "string") {
    if (/^(0|[1-9][0-9]{0,77})$/.test(v)) return BigInt(v);
    if (/^0x(0|[1-9a-f][0-9a-f]{0,63})$/.test(v)) return BigInt(v);
  }
  return null;
}

/** Entier `x` sur ses octets grand-boutistes minimaux (zéro : vide). */
export function entierVersOctetsMinimaux(x) {
  if (typeof x !== "bigint" || x < 0n) throw new TypeError("entier non négatif attendu");
  if (x === 0n) return new Uint8Array(0);
  let h = x.toString(16);
  if (h.length % 2) h = "0" + h;
  return Uint8Array.from(Buffer.from(h, "hex"));
}

/** Entier `x` sur `n` octets grand-boutistes, complété à gauche par des zéros. */
export function entierVersOctets(x, n) {
  if (typeof x !== "bigint" || x < 0n) throw new TypeError("entier non négatif attendu");
  if (x >= 1n << BigInt(8 * n)) throw new RangeError(`entier trop grand pour ${n} octets`);
  const sortie = new Uint8Array(n);
  let r = x;
  for (let k = n - 1; k >= 0 && r > 0n; k--) {
    sortie[k] = Number(r & 0xffn);
    r >>= 8n;
  }
  return sortie;
}

/** Octets grand-boutistes vers `bigint`. */
export function octetsVersEntier(octets) {
  let x = 0n;
  for (const o of octets) x = (x << 8n) | BigInt(o);
  return x;
}

/** `u256(x)` : 32 octets. */
export const u256 = (x) => entierVersOctets(x, 32);
/** `u64(x)` : 8 octets. */
export const u64 = (x) => entierVersOctets(x, 8);

/** Quantité JSON-RPC (`0x0`, `0x84c`) : hexadécimal minuscule sans zéro de tête. */
export function estQuantite(v) {
  return typeof v === "string" && /^0x(0|[1-9a-f][0-9a-f]*)$/.test(v);
}

/** Quantité JSON-RPC vers `bigint`, ou null. */
export function quantiteVersEntier(v, max = MAX_U256) {
  if (!estQuantite(v)) return null;
  const x = BigInt(v);
  return x > max ? null : x;
}

/** Entier vers quantité JSON-RPC. */
export function entierVersQuantite(x) {
  const e = typeof x === "bigint" ? x : BigInt(x);
  if (e < 0n) throw new RangeError("quantité négative");
  return "0x" + e.toString(16);
}

export { MAX_U64, MAX_U256 };

/** Égalité d'octets. */
export function octetsEgaux(a, b) {
  if (!estOctets(a) || !estOctets(b) || a.length !== b.length) return false;
  let d = 0;
  for (let k = 0; k < a.length; k++) d |= a[k] ^ b[k];
  return d === 0;
}

/** Hexadécimal préfixé de `n` octets (ou de longueur quelconque). */
export function estHexOctets(v, n) {
  return estHex(v, n);
}

// ------------------------------------------------------------------- RLP

function longueurRlp(base, n) {
  if (n <= 55) return Uint8Array.of(base + n);
  const L = entierVersOctetsMinimaux(BigInt(n));
  return concatener(Uint8Array.of(base + 55 + L.length), L);
}

/** Encodage RLP d'une chaîne d'octets. */
export function rlpOctets(b) {
  if (!estOctets(b)) throw new TypeError("octets attendus");
  if (b.length === 1 && b[0] < 0x80) return Uint8Array.from(b);
  return concatener(longueurRlp(0x80, b.length), b);
}

/** Encodage RLP d'une liste d'éléments déjà encodés. */
export function rlpListe(elements) {
  const charge = concatener(...elements);
  return concatener(longueurRlp(0xc0, charge.length), charge);
}

/** Encodage RLP d'un entier non négatif (octets minimaux, zéro : chaîne vide). */
export function rlpEntier(x) {
  return rlpOctets(entierVersOctetsMinimaux(typeof x === "bigint" ? x : BigInt(x)));
}

/**
 * Encodage RLP d'une valeur imbriquée : `Uint8Array` (chaîne), `bigint`
 * (entier), tableau (liste).
 */
export function rlp(valeur) {
  if (estOctets(valeur)) return rlpOctets(valeur);
  if (typeof valeur === "bigint") return rlpEntier(valeur);
  if (Array.isArray(valeur)) return rlpListe(valeur.map(rlp));
  throw new TypeError("valeur RLP : octets, bigint ou tableau attendu");
}

/** Erreur de décodage RLP (forme non canonique, troncature, profondeur). */
export class ErreurRlp extends Error {
  constructor(message) {
    super(message);
    this.name = "ErreurRlp";
  }
}

const PROFONDEUR_RLP = 16;

/**
 * Décode un élément RLP à la position `i` ; rend `{ valeur, fin }`.
 * Formes non canoniques refusées (go-ethereum, `rlp.Stream`).
 */
function decoderRlpA(octets, i, profondeur) {
  if (profondeur > PROFONDEUR_RLP) throw new ErreurRlp("profondeur RLP dépassée");
  if (i >= octets.length) throw new ErreurRlp("RLP tronqué");
  const p = octets[i];
  const lireLongueur = (nb) => {
    if (i + 1 + nb > octets.length) throw new ErreurRlp("longueur RLP tronquée");
    if (octets[i + 1] === 0) throw new ErreurRlp("longueur RLP à zéro de tête");
    const L = octetsVersEntier(octets.subarray(i + 1, i + 1 + nb));
    if (L <= 55n) throw new ErreurRlp("forme longue pour une charge courte");
    if (L > BigInt(octets.length)) throw new ErreurRlp("longueur RLP au-delà des octets");
    return Number(L);
  };
  if (p < 0x80) return { valeur: Uint8Array.of(p), fin: i + 1 };
  if (p <= 0xb7) {
    const n = p - 0x80;
    if (i + 1 + n > octets.length) throw new ErreurRlp("chaîne RLP tronquée");
    if (n === 1 && octets[i + 1] < 0x80) throw new ErreurRlp("octet seul encodé en chaîne");
    return { valeur: Uint8Array.from(octets.subarray(i + 1, i + 1 + n)), fin: i + 1 + n };
  }
  if (p <= 0xbf) {
    const nb = p - 0xb7;
    const n = lireLongueur(nb);
    const debut = i + 1 + nb;
    if (debut + n > octets.length) throw new ErreurRlp("chaîne RLP tronquée");
    return { valeur: Uint8Array.from(octets.subarray(debut, debut + n)), fin: debut + n };
  }
  let n;
  let debut;
  if (p <= 0xf7) {
    n = p - 0xc0;
    debut = i + 1;
  } else {
    const nb = p - 0xf7;
    n = lireLongueur(nb);
    debut = i + 1 + nb;
  }
  if (debut + n > octets.length) throw new ErreurRlp("liste RLP tronquée");
  const fin = debut + n;
  const elements = [];
  let j = debut;
  while (j < fin) {
    const e = decoderRlpA(octets, j, profondeur + 1);
    elements.push(e.valeur);
    j = e.fin;
  }
  if (j !== fin) throw new ErreurRlp("liste RLP mal bornée");
  return { valeur: elements, fin };
}

/**
 * Décode une valeur RLP complète (chaînes en `Uint8Array`, listes en tableaux).
 * @throws {ErreurRlp}
 */
export function decoderRlp(octets) {
  if (!estOctets(octets)) throw new ErreurRlp("octets attendus");
  const { valeur, fin } = decoderRlpA(octets, 0, 0);
  if (fin !== octets.length) throw new ErreurRlp("octets en trop après la valeur RLP");
  return valeur;
}

/** Entier RLP décodé (chaîne d'octets minimale) vers `bigint`, ou null si non minimal. */
export function entierRlp(valeur, max = MAX_U256) {
  if (!estOctets(valeur)) return null;
  if (valeur.length > 0 && valeur[0] === 0) return null;
  if (valeur.length > 32) return null;
  const x = octetsVersEntier(valeur);
  return x > max ? null : x;
}

// ---------------------------------------------------------------- base64

const ALPHABET_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const VALEURS_B64 = new Map([...ALPHABET_B64].map((c, k) => [c, k]));

/**
 * Décode le base64 standard tel que le décodeur du nœud l'accepte (CT-6
 * EX-11.6) : alphabet standard, remplissage `=` présent et bien placé, bits
 * de bourrage non nuls tolérés, `\n` et `\r` ignorés ; alphabet URL,
 * remplissage absent ou mal placé refusés.
 * @returns {{octets: Uint8Array, canonique: boolean}|null}
 */
export function decoderBase64Noeud(texte) {
  if (typeof texte !== "string") return null;
  const propre = texte.replace(/[\n\r]/g, "");
  if (propre.length % 4 !== 0) return null;
  const m = /^([A-Za-z0-9+/]*)(=*)$/.exec(propre);
  if (!m) return null;
  const corps = m[1];
  const rembourrage = m[2].length;
  if (rembourrage > 2) return null;
  const reste = corps.length % 4;
  if ((reste === 0 && rembourrage !== 0) || (reste === 2 && rembourrage !== 2) || (reste === 3 && rembourrage !== 1) || reste === 1) return null;
  const sortie = [];
  let tampon = 0;
  let bits = 0;
  let canonique = true;
  for (const c of corps) {
    tampon = (tampon << 6) | VALEURS_B64.get(c);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      sortie.push((tampon >> bits) & 0xff);
    }
  }
  if (bits > 0 && (tampon & ((1 << bits) - 1)) !== 0) canonique = false;
  if (propre !== texte) canonique = false;
  return { octets: Uint8Array.from(sortie), canonique };
}

/** Encode en base64 standard avec remplissage. */
export function encoderBase64(octets) {
  return Buffer.from(octets).toString("base64");
}

/** Octets UTF-8 d'une chaîne. */
export function utf8Octets(texte) {
  return new TextEncoder().encode(texte);
}

/** Décode des octets UTF-8 bien formés, ou rend null. */
export function utf8Texte(octets) {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(octets);
  } catch {
    return null;
  }
}
