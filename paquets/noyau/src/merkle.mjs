// Arbre de Merkle RFC 6962 des événements d'une période (CT-1 §9), période
// vide à racine nulle (§9.2), preuve d'inclusion (§9.3, vérification de la
// RFC 9162 §2.1.3.2), preuve de cohérence (§10.7, RFC 9162 §2.1.4).
//
// Les vérifications exécutent les algorithmes de CT-1 tels qu'ils sont écrits,
// sans deviner la position des nœuds : un chemin trop court, trop long ou
// permuté est refusé.

import { ZERO32, concatener, estHex, hexVersOctets, octetsEgaux, octetsVersHex } from "./conventions.mjs";
import { sha256 } from "./hachage.mjs";

const OCTET_FEUILLE = Uint8Array.of(0x00);
const OCTET_NOEUD = Uint8Array.of(0x01);

function octets32(x) {
  return x instanceof Uint8Array ? x : hexVersOctets(x, 32);
}

/**
 * Feuille L = SHA-256(0x00 || D) d'un hash d'événement.
 * @param {string|Uint8Array} hash 32 octets
 * @returns {string}
 */
export function feuille(hash) {
  return octetsVersHex(sha256(concatener(OCTET_FEUILLE, octets32(hash))));
}

/**
 * Nœud N(g, d) = SHA-256(0x01 || g || d).
 * @param {string|Uint8Array} gauche
 * @param {string|Uint8Array} droite
 * @returns {string}
 */
export function noeud(gauche, droite) {
  return octetsVersHex(sha256(concatener(OCTET_NOEUD, octets32(gauche), octets32(droite))));
}

function noeudOctets(g, d) {
  return sha256(concatener(OCTET_NOEUD, g, d));
}

/**
 * Plus grande puissance de deux strictement inférieure à n (n ≥ 2).
 * @param {number} n
 * @returns {number}
 */
export function puissanceInferieure(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function mth(feuilles, debut, fin) {
  const n = fin - debut;
  if (n === 1) return feuilles[debut];
  const k = puissanceInferieure(n);
  return noeudOctets(mth(feuilles, debut, debut + k), mth(feuilles, debut + k, fin));
}

function feuillesOctets(hashes) {
  if (!Array.isArray(hashes)) throw new TypeError("tableau de hash attendu");
  return hashes.map((h) => sha256(concatener(OCTET_FEUILLE, octets32(h))));
}

/**
 * Racine MTH des hash d'événements D[0..n-1] (RFC 6962 §2.1) ; 32 octets
 * nuls pour n = 0 (convention NOORTRACE de la période vide, CT-1 §9.2).
 * @param {(string|Uint8Array)[]} hashes
 * @returns {string}
 */
export function racineMerkle(hashes) {
  if (hashes.length === 0) return ZERO32;
  return octetsVersHex(mth(feuillesOctets(hashes), 0, hashes.length));
}

function chemin(m, feuilles, debut, fin) {
  const n = fin - debut;
  if (n === 1) return [];
  const k = puissanceInferieure(n);
  if (m < k) return [...chemin(m, feuilles, debut, debut + k), mth(feuilles, debut + k, fin)];
  return [...chemin(m - k, feuilles, debut + k, fin), mth(feuilles, debut, debut + k)];
}

/**
 * Preuve d'inclusion de la feuille m dans l'arbre des hash D (RFC 6962
 * §2.1.1), sous la forme du fichier chemin.json (CT-1 §9.3).
 * @param {number} m indice de la feuille, 0 ≤ m < n
 * @param {(string|Uint8Array)[]} hashes
 * @returns {{version: 0, tree_size: number, leaf_index: number, leaf_hash: string, path: string[], root: string}}
 */
export function preuveInclusion(m, hashes) {
  const n = hashes.length;
  if (!Number.isSafeInteger(m) || m < 0 || m >= n) throw new RangeError("indice de feuille hors de l'arbre");
  const f = feuillesOctets(hashes);
  return {
    version: 0,
    tree_size: n,
    leaf_index: m,
    leaf_hash: octetsVersHex(f[m]),
    path: chemin(m, f, 0, n).map(octetsVersHex),
    root: octetsVersHex(mth(f, 0, n)),
  };
}

/**
 * Vérifie une preuve d'inclusion par l'algorithme de CT-1 §9.3 (RFC 9162
 * §2.1.3.2) : accepte si et seulement si le chemin a exactement la longueur
 * attendue pour (m, n) et mène à la racine.
 * @param {{leaf_hash: string, leaf_index: number, tree_size: number, path: string[], root: string}} preuve
 * @returns {boolean}
 */
export function verifierInclusion(preuve) {
  const { leaf_hash, leaf_index: m, tree_size: n, path, root } = preuve ?? {};
  if (!Number.isSafeInteger(m) || !Number.isSafeInteger(n) || m < 0 || n < 1) return false;
  if (!estHex(leaf_hash, 32) || !estHex(root, 32) || !Array.isArray(path) || !path.every((h) => estHex(h, 32))) return false;
  if (m >= n) return false;
  let fn = BigInt(m);
  let sn = BigInt(n - 1);
  let r = hexVersOctets(leaf_hash);
  for (const hHex of path) {
    const h = hexVersOctets(hHex);
    if (sn === 0n) return false;
    if (fn % 2n === 1n || fn === sn) {
      r = noeudOctets(h, r);
      while (fn % 2n === 0n && fn !== 0n) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else {
      r = noeudOctets(r, h);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && octetsEgaux(r, hexVersOctets(root));
}

function sousPreuve(m, feuilles, debut, fin, complet) {
  const n = fin - debut;
  if (m === n) return complet ? [] : [mth(feuilles, debut, fin)];
  const k = puissanceInferieure(n);
  if (m <= k) return [...sousPreuve(m, feuilles, debut, debut + k, complet), mth(feuilles, debut + k, fin)];
  return [...sousPreuve(m - k, feuilles, debut + k, fin, false), mth(feuilles, debut, debut + k)];
}

/**
 * Preuve de cohérence PROOF(m, D[0..n-1]) (RFC 9162 §2.1.4.1, CT-1 §10.7),
 * 0 < m ≤ n ; vide pour m = n.
 * @param {number} m taille du premier arbre
 * @param {(string|Uint8Array)[]} hashes les n feuilles (hash d'événements) du second
 * @returns {string[]}
 */
export function preuveCoherence(m, hashes) {
  const n = hashes.length;
  if (!Number.isSafeInteger(m) || m < 1 || m > n) throw new RangeError("tailles hors de la définition (0 < m ≤ n)");
  return sousPreuve(m, feuillesOctets(hashes), 0, n, true).map(octetsVersHex);
}

function estPuissanceDeDeux(x) {
  return x > 0n && (x & (x - 1n)) === 0n;
}

/**
 * Vérifie une preuve de cohérence par l'algorithme de CT-1 §10.7 (RFC 9162
 * §2.1.4.2). Rejette m = 0 et n < m ; pour m = n, exige un chemin vide et des
 * racines égales.
 * @param {{first_size: number, second_size: number, first_root: string, second_root: string, path: string[]}} preuve
 * @returns {{valide: boolean, raison: string|null}}
 */
export function verifierCoherence(preuve) {
  const { first_size, second_size, first_root, second_root, path } = preuve ?? {};
  const refus = (raison) => ({ valide: false, raison });
  if (!Number.isSafeInteger(first_size) || !Number.isSafeInteger(second_size)) return refus("tailles illisibles");
  if (!estHex(first_root, 32) || !estHex(second_root, 32) || !Array.isArray(path) || !path.every((h) => estHex(h, 32))) {
    return refus("racines ou chemin illisibles");
  }
  const m = BigInt(first_size);
  const n = BigInt(second_size);
  if (m === 0n) return refus("m = 0");
  if (m < 0n || n < m) return refus("n < m");
  if (m === n) {
    if (path.length !== 0) return refus("m = n avec chemin");
    return first_root === second_root ? { valide: true, raison: null } : refus("m = n et racines différentes");
  }
  if (path.length === 0) return refus("chemin vide");
  let noeuds = path.map((h) => hexVersOctets(h));
  if (estPuissanceDeDeux(m)) noeuds = [hexVersOctets(first_root), ...noeuds];
  let fn = m - 1n;
  let sn = n - 1n;
  while (fn % 2n === 1n) {
    fn >>= 1n;
    sn >>= 1n;
  }
  let fr = noeuds[0];
  let sr = noeuds[0];
  for (const h of noeuds.slice(1)) {
    if (sn === 0n) return refus("chemin trop long");
    if (fn % 2n === 1n || fn === sn) {
      fr = noeudOctets(h, fr);
      sr = noeudOctets(h, sr);
      while (fn % 2n === 0n && fn !== 0n) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else {
      sr = noeudOctets(sr, h);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  if (sn !== 0n) return refus("chemin trop court");
  if (!octetsEgaux(fr, hexVersOctets(first_root)) || !octetsEgaux(sr, hexVersOctets(second_root))) return refus("racines différentes");
  return { valide: true, raison: null };
}
