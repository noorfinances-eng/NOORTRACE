// Console d'approbation de référence : bibliothèque sans interface ni
// dépendance (spec/CT-3-approbations.md, révision 0.3, EX-13.32).
//
// Module ECMAScript sans aucune importation : il s'exécute à l'identique sous
// Node et dans un navigateur. Il n'emploie ni eval, ni Function, ni réseau, ni
// DOM (la découverte EIP-6963 reçoit sa cible d'événements en argument), et
// n'a aucun état global mutable : ses tables sont calculées une fois et
// gelées.
//
// Contenu :
//
//   primitives          SHA-256, HMAC-SHA-256, PBKDF2-HMAC-SHA-256, Keccak-256
//                       (remplissage 0x01), secp256k1 (recouvrement, signature
//                       RFC 6979 à s bas, adresse), EIP-191 version 0x45,
//                       scrypt (RFC 7914), AES-128-CTR, base64 strict (RFC 4648
//                       §4), JCS v0 (CT-1 §4), analyse JSON stricte (CT-2 §4.4
//                       pas 1), UTF-8 strict ;
//   contrôle local      hachage d'un événement (CT-1 §6.1), feuilles et
//                       résolution (EX-9.16), condensés, empreinte et groupes
//                       (EX-9.17 à EX-9.19), modèle d'affichage (EX-9.15) ;
//   portefeuille        requête personal_sign (EX-13.24), vérification de la
//                       signature et de la réponse (EX-9.21, EX-13.29), corps
//                       de voter (EX-12.16), découverte EIP-6963 (EX-13.22),
//                       fichier de clé chiffré (EX-13.28) ;
//   annuaire            identité de session (EX-13.7), message d'inscription
//                       (EX-13.12), vérification d'une inscription (EX-13.15),
//                       opérations (EX-13.13, EX-13.17, EX-13.10), recopie du
//                       réglage administrators (EX-13.37), contrôles avant un
//                       vote (EX-13.18) et sur le canal (EX-12.14, EX-12.16,
//                       EX-12.19), annuaire exporté (EX-13.19).
//
// Les raisons rendues sont celles de $defs/code_console de
// console-approbation-v0 et de $defs/code_erreur_annuaire et
// $defs/code_erreur_export d'annuaire-approbateurs-v0.

// ---------------------------------------------------------------------------
// Constantes
// ---------------------------------------------------------------------------

/** Préfixe du hachage d'un événement (CT-1 §6.1). */
export const PREFIXE_EVENEMENT = "noortrace/evenement/v0\n";
/** Préfixe du condensé d'approbation P_A (CT-1 §6.3). */
export const PREFIXE_APPROBATION = "noortrace/approbation/v0\n";
/** Première et deuxième lignes du message d'inscription (EX-13.12). */
export const LIGNE_TITRE_INSCRIPTION = "noortrace/inscription/v0";
export const LIGNE_AVERTISSEMENT_INSCRIPTION = "Je lie cette adresse a mon identite pour approuver dans NOORTRACE. Ce message n'est pas un vote.";
/** Ordre de secp256k1 et premier du corps. */
export const N_SECP256K1 = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const P_SECP256K1 = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const MOITIE_N = N_SECP256K1 / 2n;
const G_SECP256K1 = Object.freeze([0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n]);
/** États où un ticket reçoit des votes (EX-9.15, contrôle 1). */
export const ETATS_COLLECTE = Object.freeze(["ouvert", "seuil_atteint", "verification"]);
/** Longueur maximale d'un motif, en points de code (EX-9.10). */
export const MAX_MOTIF = 1024;
/** Codes EIP-1193 normalisés et code de la console (13.14, EX-13.29). */
export const CODES_EIP1193 = Object.freeze({ 4001: "refus_approbateur", 4100: "non_autorise", 4200: "methode_non_prise_en_charge", 4900: "deconnecte", 4901: "chaine_deconnectee" });
/** Bornes du fichier de clé (EX-13.28). */
export const BORNES_FICHIER_CLE = Object.freeze({ c_max: 10000000, n_max: 262144, r_max: 8, p_max: 4, sel_min: 16, c_faible: 262144, n_faible: 131072 });
/** Délai d'attente du portefeuille par défaut et ses bornes (EX-13.30). */
export const DELAI_SIGNATURE_MS = Object.freeze({ defaut: 300000, min: 30000, max: 1800000 });
/** Délai après lequel la page dit qu'aucun portefeuille ne s'est annoncé (EX-13.22, pas 6). */
export const DELAI_ANNONCE_MS = 1000;
/** Méthodes du canal de la console qui modifient l'annuaire ou y préparent un défi (12.9). */
export const METHODES_ANNUAIRE = Object.freeze(["preparer_inscription", "inscrire", "valider", "revoquer", "desactiver", "reactiver", "lier_demandeur", "delier_demandeur"]);

const RE_HEX32 = /^0x[0-9a-f]{64}$/;
const RE_ADRESSE = /^0x[0-9a-f]{40}$/;
const RE_HORODATAGE = /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$/;
const RE_IDENTITE = /^(oidc https:\/\/[!-"$->@-~]+ [!-~]{1,255}|utilisateur [!-~]{1,128} [!-~]{1,255})$/;
const RE_ORIGINE = /^https:\/\/[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[1-9][0-9]{0,4})?$/;
const RE_ORGANISATION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const RE_NONCE = /^[0-9a-f]{32}$/;
const RE_ENTREE = /^apb-[0-9a-z]+(-[0-9a-z]+)*$/;
const RE_UUID4 = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
const RE_INDICE = /^(0|[1-9][0-9]{0,8})$/;

/** Erreur qui porte un code de la console ou de l'annuaire. */
export class ErreurConsole extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "ErreurConsole";
    this.code = code;
  }
}

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const aCles = (o, cles) => estObjet(o) && Object.keys(o).length === cles.length && cles.every((k) => Object.hasOwn(o, k));
const copie = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));
const longueurPoints = (s) => [...s].length;

// ---------------------------------------------------------------------------
// Octets
// ---------------------------------------------------------------------------

/** Octets UTF-8 d'une chaîne. */
export function utf8(texte) {
  return new TextEncoder().encode(texte);
}

/** Vrai si les octets sont de l'UTF-8 valide (RFC 3629), par un décodeur fatal. */
export function estUtf8(octets) {
  try {
    new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(octets);
    return true;
  } catch {
    return false;
  }
}

/** Hexadécimal minuscule préfixé 0x. */
export function enHex(octets) {
  let s = "0x";
  for (const b of octets) s += (b < 16 ? "0" : "") + b.toString(16);
  return s;
}

/** Octets d'une chaîne hexadécimale 0x… (majuscules admises), ou null si elle est mal formée. */
export function depuisHex(texte) {
  if (typeof texte !== "string" || !/^0x([0-9a-fA-F]{2})*$/.test(texte)) return null;
  const o = new Uint8Array((texte.length - 2) / 2);
  for (let i = 0; i < o.length; i++) o[i] = parseInt(texte.slice(2 + 2 * i, 4 + 2 * i), 16);
  return o;
}

/** Octets d'un hexadécimal sans 0x (fichier de clé, majuscules admises), ou null. */
const depuisHexNu = (texte) => (typeof texte === "string" ? depuisHex("0x" + texte) : null);

/** Concaténation de tableaux d'octets. */
export function concat(...parties) {
  const n = parties.reduce((a, p) => a + p.length, 0);
  const o = new Uint8Array(n);
  let i = 0;
  for (const p of parties) {
    o.set(p, i);
    i += p.length;
  }
  return o;
}

const egalOctets = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const versEntier = (o) => (o.length === 0 ? 0n : BigInt(enHex(o)));
const depuisEntier = (n, longueur = 32) => {
  const o = new Uint8Array(longueur);
  for (let i = longueur - 1; i >= 0; i--, n >>= 8n) o[i] = Number(n & 0xffn);
  return o;
};
/** Octets d'une donnée : Uint8Array tel quel, hexadécimal 0x décodé. */
const octetsDe = (d) => {
  if (d instanceof Uint8Array) return d;
  const o = depuisHex(d);
  if (o === null) throw new ErreurConsole("donnees_invalides", "octets ou hexadécimal 0x attendus");
  return o;
};

// ---------------------------------------------------------------------------
// SHA-256, HMAC, PBKDF2 (FIPS 180-4, RFC 2104, RFC 8018)
// ---------------------------------------------------------------------------

const K256 = Object.freeze([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const H256 = Object.freeze([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);

/** SHA-256 des octets (FIPS 180-4) ; rend 32 octets. */
export function sha256(donnees) {
  const m = donnees instanceof Uint8Array ? donnees : utf8(String(donnees));
  const l = m.length;
  const n = Math.ceil((l + 9) / 64) * 64;
  const b = new Uint8Array(n);
  b.set(m);
  b[l] = 0x80;
  const bits = l * 8;
  const vue = new DataView(b.buffer);
  vue.setUint32(n - 8, Math.floor(bits / 0x100000000));
  vue.setUint32(n - 4, bits >>> 0);
  const h = Uint32Array.from(H256);
  const w = new Uint32Array(64);
  for (let off = 0; off < n; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = vue.getUint32(off + 4 * i);
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15], y = w[i - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, bb, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K256[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & bb) ^ (a & c) ^ (bb & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = bb; bb = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + bb) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }
  const out = new Uint8Array(32);
  const vo = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) vo.setUint32(4 * i, h[i]);
  return out;
}

/** HMAC-SHA-256 (RFC 2104). */
export function hmacSha256(cle, message) {
  let k = cle.length > 64 ? sha256(cle) : cle;
  const bloc = new Uint8Array(64);
  bloc.set(k);
  const ipad = bloc.map((x) => x ^ 0x36);
  const opad = bloc.map((x) => x ^ 0x5c);
  k = null;
  return sha256(concat(opad, sha256(concat(ipad, message))));
}

/** PBKDF2 avec HMAC-SHA-256 (RFC 8018 §5.2). */
export function pbkdf2Sha256(motDePasse, sel, iterations, longueur) {
  const nb = Math.ceil(longueur / 32);
  const out = new Uint8Array(nb * 32);
  // Clé HMAC préparée une fois : les deux blocs internes sont recalculés à chaque tour par hmacSha256.
  for (let i = 1; i <= nb; i++) {
    let u = hmacSha256(motDePasse, concat(sel, Uint8Array.of(i >>> 24, (i >>> 16) & 0xff, (i >>> 8) & 0xff, i & 0xff)));
    const t = Uint8Array.from(u);
    for (let j = 1; j < iterations; j++) {
      u = hmacSha256(motDePasse, u);
      for (let x = 0; x < 32; x++) t[x] ^= u[x];
    }
    out.set(t, (i - 1) * 32);
  }
  return out.slice(0, longueur);
}

// ---------------------------------------------------------------------------
// Keccak-256 (remplissage 0x01 d'Ethereum, et non 0x06 de SHA-3)
// ---------------------------------------------------------------------------

const MASQUE64 = (1n << 64n) - 1n;
const RC_KECCAK = Object.freeze([
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an, 0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
]);
const ROT_KECCAK = Object.freeze([0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]);
const rotl64 = (x, n) => (n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASQUE64);

function permutationKeccak(a) {
  for (let tour = 0; tour < 24; tour++) {
    const c = [0n, 0n, 0n, 0n, 0n];
    for (let x = 0; x < 5; x++) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
      for (let y = 0; y < 25; y += 5) a[y + x] ^= d;
    }
    const b = new Array(25);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(a[x + 5 * y], ROT_KECCAK[x + 5 * y]);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 25; y += 5) a[y + x] = b[y + x] ^ (~b[y + ((x + 1) % 5)] & MASQUE64 & b[y + ((x + 2) % 5)]);
    a[0] ^= RC_KECCAK[tour];
  }
}

/** Keccak-256 des octets ; rend 32 octets. */
export function keccak256(octets) {
  const taux = 136;
  const n = Math.floor(octets.length / taux) * taux + taux;
  const m = new Uint8Array(n);
  m.set(octets);
  m[octets.length] ^= 0x01;
  m[n - 1] ^= 0x80;
  const a = new Array(25).fill(0n);
  for (let off = 0; off < n; off += taux) {
    for (let i = 0; i < taux / 8; i++) {
      let v = 0n;
      for (let k = 7; k >= 0; k--) v = (v << 8n) | BigInt(m[off + 8 * i + k]);
      a[i] ^= v;
    }
    permutationKeccak(a);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) for (let k = 0; k < 8; k++) out[8 * i + k] = Number((a[i] >> BigInt(8 * k)) & 0xffn);
  return out;
}

// ---------------------------------------------------------------------------
// secp256k1 : coordonnées jacobiennes, recouvrement, signature RFC 6979
// ---------------------------------------------------------------------------

const modp = (a) => {
  const r = a % P_SECP256K1;
  return r >= 0n ? r : r + P_SECP256K1;
};
const modn = (a) => {
  const r = a % N_SECP256K1;
  return r >= 0n ? r : r + N_SECP256K1;
};
function inverseMod(a, m) {
  let [r0, r1] = [((a % m) + m) % m, m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new ErreurConsole("signature_invalide", "inverse modulaire inexistant");
  return ((s0 % m) + m) % m;
}
function puissanceMod(b, e, m) {
  let r = 1n;
  b %= m;
  for (; e > 0n; e >>= 1n, b = (b * b) % m) if (e & 1n) r = (r * b) % m;
  return r;
}
// Point jacobien [X, Y, Z] ; null est le point à l'infini.
function doubler(p) {
  if (p === null || p[1] === 0n) return null;
  const [x, y, z] = p;
  const yy = modp(y * y);
  const s = modp(4n * x * yy);
  const m = modp(3n * x * x);
  const x3 = modp(m * m - 2n * s);
  return [x3, modp(m * (s - x3) - 8n * yy * yy), modp(2n * y * z)];
}
function additionner(p, q) {
  if (p === null) return q;
  if (q === null) return p;
  const [x1, y1, z1] = p;
  const [x2, y2, z2] = q;
  const z1z1 = modp(z1 * z1), z2z2 = modp(z2 * z2);
  const u1 = modp(x1 * z2z2), u2 = modp(x2 * z1z1);
  const s1 = modp(y1 * z2 * z2z2), s2 = modp(y2 * z1 * z1z1);
  if (u1 === u2) return s1 === s2 ? doubler(p) : null;
  const h = modp(u2 - u1), r = modp(s2 - s1);
  const hh = modp(h * h), hhh = modp(h * hh);
  const v = modp(u1 * hh);
  const x3 = modp(r * r - hhh - 2n * v);
  return [x3, modp(r * (v - x3) - s1 * hhh), modp(z1 * z2 * h)];
}
function multiplier(k, p) {
  let r = null;
  for (let i = BigInt(k.toString(2).length) - 1n; i >= 0n; i--) {
    r = doubler(r);
    if ((k >> i) & 1n) r = additionner(r, p);
  }
  return r;
}
function affine(p) {
  if (p === null) return null;
  const zi = inverseMod(p[2], P_SECP256K1);
  const zi2 = modp(zi * zi);
  return [modp(p[0] * zi2), modp(p[1] * zi2 * zi)];
}
const GJ = Object.freeze([G_SECP256K1[0], G_SECP256K1[1], 1n]);

/** Adresse (20 derniers octets de keccak256(X ‖ Y)) d'un point affine, en minuscules. */
function adresseDuPoint([x, y]) {
  return enHex(keccak256(concat(depuisEntier(x), depuisEntier(y))).slice(12));
}

/** Adresse de la clé privée `cle` (32 octets), ou null si la clé est hors de [1, n − 1]. */
export function adresseDeCle(cle) {
  const k = versEntier(cle);
  if (k < 1n || k >= N_SECP256K1) return null;
  return adresseDuPoint(affine(multiplier(k, GJ)));
}

/**
 * Recouvre l'adresse du signataire de `h` (32 octets) depuis r, s et
 * l'identifiant de recouvrement `recid` ∈ {0, 1}. Lève signature_invalide si
 * le recouvrement est impossible. N'exige pas s bas : la normalisation est
 * faite avant (EX-9.3).
 */
export function recouvrerAdresse(h, r, s, recid) {
  if (r < 1n || r >= N_SECP256K1 || s < 1n || s >= N_SECP256K1 || (recid !== 0 && recid !== 1)) throw new ErreurConsole("signature_invalide");
  const x = r;
  const alpha = modp(x * x * x + 7n);
  const beta = puissanceMod(alpha, (P_SECP256K1 + 1n) / 4n, P_SECP256K1);
  if (modp(beta * beta) !== alpha) throw new ErreurConsole("signature_invalide", "r n'est l'abscisse d'aucun point");
  const y = (beta & 1n) === BigInt(recid) ? beta : P_SECP256K1 - beta;
  const e = modn(versEntier(h));
  const ri = inverseMod(r, N_SECP256K1);
  const q = additionner(multiplier(modn(s * ri), [x, y, 1n]), multiplier(modn(-e * ri), GJ));
  if (q === null) throw new ErreurConsole("signature_invalide", "point à l'infini");
  return adresseDuPoint(affine(q));
}

/**
 * Signature ECDSA déterministe (RFC 6979, HMAC-SHA-256) de `h` (32 octets) par
 * la clé `cle` (32 octets) : s dans la moitié basse, v = 27 + recid. Rend la
 * signature r ‖ s ‖ v en hexadécimal 0x.
 */
export function signerHachage(cle, h) {
  const d = versEntier(cle);
  if (d < 1n || d >= N_SECP256K1) throw new ErreurConsole("cle_invalide");
  const x = depuisEntier(d);
  const h1 = depuisEntier(modn(versEntier(h)));
  let v = new Uint8Array(32).fill(1);
  let k = new Uint8Array(32);
  k = hmacSha256(k, concat(v, Uint8Array.of(0), x, h1));
  v = hmacSha256(k, v);
  k = hmacSha256(k, concat(v, Uint8Array.of(1), x, h1));
  v = hmacSha256(k, v);
  const e = modn(versEntier(h));
  for (;;) {
    v = hmacSha256(k, v);
    const kk = versEntier(v);
    if (kk >= 1n && kk < N_SECP256K1) {
      const R = affine(multiplier(kk, GJ));
      const r = modn(R[0]);
      let s = modn(inverseMod(kk, N_SECP256K1) * (e + r * d));
      if (r !== 0n && s !== 0n) {
        let recid = Number(R[1] & 1n) | (R[0] >= N_SECP256K1 ? 2 : 0);
        if (s > MOITIE_N) {
          s = N_SECP256K1 - s;
          recid ^= 1;
        }
        x.fill(0);
        if (recid > 1) throw new ErreurConsole("signature_invalide", "identifiant de recouvrement hors de {0, 1}");
        return enHex(concat(depuisEntier(r), depuisEntier(s), Uint8Array.of(27 + recid)));
      }
    }
    k = hmacSha256(k, concat(v, Uint8Array.of(0)));
    v = hmacSha256(k, v);
  }
}

/** Condensé EIP-191 version 0x45 des octets : keccak256(0x19 ‖ « Ethereum Signed Message:\n » ‖ décimal(L) ‖ octets). */
export function condenseEIP191(donnees) {
  const o = octetsDe(donnees);
  return keccak256(preimageEIP191(o));
}

/** Préimage EIP-191 version 0x45 des octets. */
export function preimageEIP191(donnees) {
  const o = octetsDe(donnees);
  return concat(Uint8Array.of(0x19), utf8(`Ethereum Signed Message:\n${o.length}`), o);
}

// ---------------------------------------------------------------------------
// scrypt (RFC 7914) et AES-128-CTR (FIPS 197, SP 800-38A)
// ---------------------------------------------------------------------------

function salsa208(b) {
  const x = Uint32Array.from(b);
  const R = (a, n) => (a << n) | (a >>> (32 - n));
  for (let i = 0; i < 8; i += 2) {
    x[4] ^= R(x[0] + x[12], 7); x[8] ^= R(x[4] + x[0], 9); x[12] ^= R(x[8] + x[4], 13); x[0] ^= R(x[12] + x[8], 18);
    x[9] ^= R(x[5] + x[1], 7); x[13] ^= R(x[9] + x[5], 9); x[1] ^= R(x[13] + x[9], 13); x[5] ^= R(x[1] + x[13], 18);
    x[14] ^= R(x[10] + x[6], 7); x[2] ^= R(x[14] + x[10], 9); x[6] ^= R(x[2] + x[14], 13); x[10] ^= R(x[6] + x[2], 18);
    x[3] ^= R(x[15] + x[11], 7); x[7] ^= R(x[3] + x[15], 9); x[11] ^= R(x[7] + x[3], 13); x[15] ^= R(x[11] + x[7], 18);
    x[1] ^= R(x[0] + x[3], 7); x[2] ^= R(x[1] + x[0], 9); x[3] ^= R(x[2] + x[1], 13); x[0] ^= R(x[3] + x[2], 18);
    x[6] ^= R(x[5] + x[4], 7); x[7] ^= R(x[6] + x[5], 9); x[4] ^= R(x[7] + x[6], 13); x[5] ^= R(x[4] + x[7], 18);
    x[11] ^= R(x[10] + x[9], 7); x[8] ^= R(x[11] + x[10], 9); x[9] ^= R(x[8] + x[11], 13); x[10] ^= R(x[9] + x[8], 18);
    x[12] ^= R(x[15] + x[14], 7); x[13] ^= R(x[12] + x[15], 9); x[14] ^= R(x[13] + x[12], 13); x[15] ^= R(x[14] + x[13], 18);
  }
  for (let i = 0; i < 16; i++) b[i] = (b[i] + x[i]) >>> 0;
}
function blockMix(b, r) {
  const X = b.slice((2 * r - 1) * 16, 2 * r * 16);
  const y = new Uint32Array(b.length);
  for (let i = 0; i < 2 * r; i++) {
    for (let j = 0; j < 16; j++) X[j] ^= b[i * 16 + j];
    salsa208(X);
    const dest = (i % 2 === 0 ? i / 2 : r + (i - 1) / 2) * 16;
    y.set(X, dest);
  }
  b.set(y);
}

/** scrypt (RFC 7914) ; `n` puissance de 2. */
export function scrypt(motDePasse, sel, n, r, p, longueur) {
  const B = pbkdf2Sha256(motDePasse, sel, 1, p * 128 * r);
  const mots = 32 * r;
  for (let i = 0; i < p; i++) {
    const X = new Uint32Array(mots);
    const vue = new DataView(B.buffer, B.byteOffset + i * 128 * r, 128 * r);
    for (let k = 0; k < mots; k++) X[k] = vue.getUint32(4 * k, true);
    const V = new Uint32Array(mots * n);
    for (let j = 0; j < n; j++) {
      V.set(X, j * mots);
      blockMix(X, r);
    }
    for (let j = 0; j < n; j++) {
      const idx = X[(2 * r - 1) * 16] & (n - 1);
      for (let k = 0; k < mots; k++) X[k] ^= V[idx * mots + k];
      blockMix(X, r);
    }
    for (let k = 0; k < mots; k++) vue.setUint32(4 * k, X[k], true);
    V.fill(0);
  }
  return pbkdf2Sha256(motDePasse, B, 1, longueur);
}

const SBOX = (() => {
  const s = new Uint8Array(256);
  let p = 1, q = 1;
  do {
    p = p ^ ((p << 1) & 0xff) ^ (p & 0x80 ? 0x1b : 0);
    q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff;
    if (q & 0x80) q ^= 0x09;
    const x = q ^ ((q << 1) | (q >>> 7)) ^ ((q << 2) | (q >>> 6)) ^ ((q << 3) | (q >>> 5)) ^ ((q << 4) | (q >>> 4));
    s[p] = (x ^ 0x63) & 0xff;
  } while (p !== 1);
  s[0] = 0x63;
  return Object.freeze(Array.from(s));
})();
const xtime = (a) => ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;

function chiffrerBlocAes128(cle, bloc) {
  const w = new Uint8Array(176);
  w.set(cle);
  let rcon = 1;
  for (let i = 16; i < 176; i += 4) {
    let t = w.slice(i - 4, i);
    if (i % 16 === 0) {
      t = Uint8Array.of(SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]);
      rcon = xtime(rcon);
    }
    for (let j = 0; j < 4; j++) w[i + j] = w[i - 16 + j] ^ t[j];
  }
  const s = Uint8Array.from(bloc);
  for (let i = 0; i < 16; i++) s[i] ^= w[i];
  for (let tour = 1; tour <= 10; tour++) {
    for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    const t = Uint8Array.from(s);
    for (let c = 0; c < 4; c++) for (let l = 0; l < 4; l++) s[4 * c + l] = t[4 * ((c + l) % 4) + l];
    if (tour < 10) {
      for (let c = 0; c < 4; c++) {
        const [a0, a1, a2, a3] = s.slice(4 * c, 4 * c + 4);
        const e = a0 ^ a1 ^ a2 ^ a3;
        s[4 * c] = a0 ^ e ^ xtime(a0 ^ a1);
        s[4 * c + 1] = a1 ^ e ^ xtime(a1 ^ a2);
        s[4 * c + 2] = a2 ^ e ^ xtime(a2 ^ a3);
        s[4 * c + 3] = a3 ^ e ^ xtime(a3 ^ a0);
      }
    }
    for (let i = 0; i < 16; i++) s[i] ^= w[16 * tour + i];
  }
  w.fill(0);
  return s;
}

/** AES-128 en mode CTR (compteur de 128 bits gros-boutiste, initial `iv`) ; chiffrement et déchiffrement sont la même opération. */
export function aes128Ctr(cle, iv, donnees) {
  const out = new Uint8Array(donnees.length);
  let compteur = versEntier(iv);
  for (let off = 0; off < donnees.length; off += 16) {
    const flux = chiffrerBlocAes128(cle, depuisEntier(compteur, 16));
    for (let i = 0; i < 16 && off + i < donnees.length; i++) out[off + i] = donnees[off + i] ^ flux[i];
    compteur = (compteur + 1n) & ((1n << 128n) - 1n);
  }
  return out;
}

// ---------------------------------------------------------------------------
// base64 strict, JCS v0, JSON strict, égalité JSON, horodatages
// ---------------------------------------------------------------------------

const ALPHABET64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Décodage base64 strict (RFC 4648 §4) : alphabet standard, longueur multiple
 * de 4, remplissage « = » final seulement et bits de remplissage nuls (forme
 * canonique) ; rend null sinon.
 */
export function base64Strict(texte) {
  if (typeof texte !== "string" || texte.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(texte)) return null;
  const pad = texte.endsWith("==") ? 2 : texte.endsWith("=") ? 1 : 0;
  const out = new Uint8Array((texte.length / 4) * 3 - pad);
  let j = 0;
  for (let i = 0; i < texte.length; i += 4) {
    const v = [0, 1, 2, 3].map((k) => (texte[i + k] === "=" ? 0 : ALPHABET64.indexOf(texte[i + k])));
    const n = (v[0] << 18) | (v[1] << 12) | (v[2] << 6) | v[3];
    const derniers = i + 4 === texte.length;
    if (derniers && pad === 2 && (n & 0xffff) !== 0) return null;
    if (derniers && pad === 1 && (n & 0xff) !== 0) return null;
    out[j++] = (n >>> 16) & 0xff;
    if (j < out.length) out[j++] = (n >>> 8) & 0xff;
    if (j < out.length) out[j++] = n & 0xff;
  }
  return out;
}

/** Encodage base64 (RFC 4648 §4). */
export function base64(octets) {
  let s = "";
  for (let i = 0; i < octets.length; i += 3) {
    const n = (octets[i] << 16) | ((octets[i + 1] ?? 0) << 8) | (octets[i + 2] ?? 0);
    s += ALPHABET64[(n >>> 18) & 63] + ALPHABET64[(n >>> 12) & 63] + (i + 1 < octets.length ? ALPHABET64[(n >>> 6) & 63] : "=") + (i + 2 < octets.length ? ALPHABET64[n & 63] : "=");
  }
  return s;
}

const chaineBienFormee = (s) => {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
};

/**
 * JCS v0 (CT-1 §4) : clés triées par unités UTF-16, chaînes échappées comme
 * JSON.stringify, entiers de l'intervalle sûr seulement, aucun espace. Lève
 * ErreurConsole sur toute autre valeur.
 */
export function jcs(valeur) {
  if (valeur === null) return "null";
  switch (typeof valeur) {
    case "boolean":
      return valeur ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(valeur)) throw new ErreurConsole("jcs", "JCS v0 : entier sûr attendu");
      return valeur === 0 ? "0" : String(valeur);
    case "string":
      if (!chaineBienFormee(valeur)) throw new ErreurConsole("jcs", "JCS v0 : substitut isolé");
      return JSON.stringify(valeur);
    case "object": {
      if (Array.isArray(valeur)) return "[" + valeur.map(jcs).join(",") + "]";
      const membres = [];
      for (const k of Object.keys(valeur).sort()) {
        if (!chaineBienFormee(k)) throw new ErreurConsole("jcs", "JCS v0 : substitut isolé");
        if (valeur[k] !== undefined) membres.push(JSON.stringify(k) + ":" + jcs(valeur[k]));
      }
      return "{" + membres.join(",") + "}";
    }
    default:
      throw new ErreurConsole("jcs", "JCS v0 : valeur non JSON");
  }
}

/**
 * Analyse JSON stricte (RFC 8259) des octets ou du texte, comme le frontal de
 * CT-2 (§4.4 pas 1) : UTF-8 strict, marque d'ordre d'octets, clé en double,
 * substitut isolé et nombre hors de la double précision refusés ; profondeur
 * au plus 128, au plus 100 000 membres ou éléments par objet ou tableau. Lève
 * ErreurConsole("json").
 */
export function analyserJSONStrict(entree, { profondeurMax = 128, membresMax = 100000 } = {}) {
  let texte = entree;
  if (entree instanceof Uint8Array) {
    if (entree.length >= 3 && entree[0] === 0xef && entree[1] === 0xbb && entree[2] === 0xbf) throw new ErreurConsole("json", "marque d'ordre d'octets");
    try {
      texte = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(entree);
    } catch {
      throw new ErreurConsole("json", "UTF-8 invalide");
    }
  }
  if (typeof texte !== "string") throw new ErreurConsole("json", "texte attendu");
  let i = 0;
  const err = (m) => {
    throw new ErreurConsole("json", `${m} (caractère ${i})`);
  };
  const blancs = () => {
    while (i < texte.length && " \t\n\r".includes(texte[i])) i++;
  };
  const chaine = () => {
    i++;
    let out = "";
    for (;;) {
      if (i >= texte.length) err("chaîne non terminée");
      const c = texte.charCodeAt(i);
      if (c === 0x22) {
        i++;
        if (!chaineBienFormee(out)) err("substitut isolé");
        return out;
      }
      if (c < 0x20) err("caractère de contrôle");
      if (c !== 0x5c) {
        out += texte[i++];
        continue;
      }
      const e = texte[i + 1];
      i += 2;
      const simples = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
      if (Object.hasOwn(simples, e)) out += simples[e];
      else if (e === "u") {
        const h = texte.slice(i, i + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(h)) err("échappement \\u invalide");
        i += 4;
        out += String.fromCharCode(parseInt(h, 16));
      } else err("échappement invalide");
    }
  };
  const valeur = (profondeur) => {
    blancs();
    if (i >= texte.length) err("fin inattendue");
    const c = texte[i];
    if (c === "{" || c === "[") {
      if (profondeur >= profondeurMax) err("profondeur maximale dépassée");
      i++;
      blancs();
      const objet = c === "{";
      const out = objet ? {} : [];
      let compte = 0;
      if (texte[i] === (objet ? "}" : "]")) {
        i++;
        return out;
      }
      for (;;) {
        if (++compte > membresMax) err("trop de membres");
        if (objet) {
          blancs();
          if (texte[i] !== '"') err("nom de membre attendu");
          const k = chaine();
          blancs();
          if (texte[i] !== ":") err("« : » attendu");
          i++;
          const v = valeur(profondeur + 1);
          if (Object.hasOwn(out, k)) err(`clé en double « ${k} »`);
          Object.defineProperty(out, k, { value: v, enumerable: true, writable: true, configurable: true });
        } else out.push(valeur(profondeur + 1));
        blancs();
        if (texte[i] === ",") {
          i++;
          continue;
        }
        if (texte[i] === (objet ? "}" : "]")) {
          i++;
          return out;
        }
        err("séparateur attendu");
      }
    }
    if (c === '"') return chaine();
    for (const [mot, v] of [["true", true], ["false", false], ["null", null]]) {
      if (texte.startsWith(mot, i)) {
        i += mot.length;
        return v;
      }
    }
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(texte.slice(i, i + 1024));
    if (!m) err("valeur invalide");
    const n = Number(m[0]);
    if (!Number.isFinite(n)) err("nombre hors de la double précision");
    i += m[0].length;
    return n;
  };
  const v = valeur(0);
  blancs();
  if (i < texte.length) err("texte après la valeur");
  return v;
}

/**
 * Égalité de deux valeurs JSON (EX-9.16) : chaînes égales point de code par
 * point de code, nombres égaux en valeur, objets égaux membre par membre sans
 * égard à l'ordre, tableaux élément par élément.
 */
export function egalJSON(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((v, i) => egalJSON(v, b[i]));
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i] && egalJSON(a[k], b[k]));
}

/** Millisecondes UNIX d'un horodatage de CT-1 §3 (UTC, millisecondes, date du calendrier), ou NaN. */
export function msHorodatage(ts) {
  if (typeof ts !== "string" || !RE_HORODATAGE.test(ts)) return NaN;
  const ms = Date.parse(ts);
  return !Number.isNaN(ms) && new Date(ms).toISOString() === ts ? ms : NaN;
}
/** Horodatage de CT-1 §3 d'un instant en millisecondes. */
export const horodatage = (ms) => new Date(ms).toISOString();

// ---------------------------------------------------------------------------
// Contrôle local avant la signature (9.6)
// ---------------------------------------------------------------------------

/** Hachage d'un événement : SHA-256(« noortrace/evenement/v0\n » ‖ JCS(E')), E' sans hash ni sig (CT-1 §6.1). */
export function hachageEvenement(evenement) {
  if (!estObjet(evenement)) throw new ErreurConsole("evenement_invalide");
  const corps = {};
  for (const k of Object.keys(evenement)) if (k !== "hash" && k !== "sig") corps[k] = evenement[k];
  return enHex(sha256(concat(utf8(PREFIXE_EVENEMENT), utf8(jcs(corps)))));
}

const echapper = (k) => k.replace(/~/g, "~0").replace(/\//g, "~1");

/**
 * Feuilles d'une valeur JSON (EX-9.16) : un scalaire, un objet sans membre et
 * un tableau vide sont une feuille de pointeur vide ; un objet donne les
 * feuilles de ses membres dans l'ordre JCS des noms ; un tableau celles de ses
 * éléments. Rend [{ pointer, value }].
 */
export function feuilles(valeur, prefixe = "") {
  if (estObjet(valeur)) {
    const cles = Object.keys(valeur).sort();
    if (cles.length === 0) return [{ pointer: prefixe, value: {} }];
    return cles.flatMap((k) => feuilles(valeur[k], `${prefixe}/${echapper(k)}`));
  }
  if (Array.isArray(valeur)) {
    if (valeur.length === 0) return [{ pointer: prefixe, value: [] }];
    return valeur.flatMap((v, i) => feuilles(v, `${prefixe}/${i}`));
  }
  return [{ pointer: prefixe, value: valeur }];
}

/** Résolution d'un pointeur selon les pas 1 et 2 d'EX-4.4 appliqués à `valeur` ; rend { resolu, valeur }. */
export function resoudre(valeur, pointeur) {
  if (pointeur === "") return { resolu: true, valeur };
  let x = valeur;
  for (const j of pointeur.slice(1).split("/").map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"))) {
    if (estObjet(x) && Object.hasOwn(x, j)) x = x[j];
    else if (Array.isArray(x) && RE_INDICE.test(j) && Number(j) < x.length) x = x[Number(j)];
    else return { resolu: false, valeur: undefined };
  }
  return { resolu: true, valeur: x };
}

/** A = { decision, journal_id, org_id, request_hash, ticket } (CT-1 §6.3), dans l'ordre de CT-1. */
export function objetA({ decision, journal_id, org_id, request_hash, ticket }) {
  return { decision, journal_id, org_id, request_hash, ticket };
}

/** Empreinte abrégée (EX-9.18) : 8 premiers chiffres, U+2026, 8 derniers, sans 0x. */
export function empreinte(x) {
  const h = String(x).toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(h)) throw new ErreurConsole("valeur_invalide", "32 octets en hexadécimal attendus");
  return `${h.slice(0, 8)}…${h.slice(56)}`;
}

/** Les 64 chiffres en 8 groupes de 8 séparés par une espace (EX-9.18). */
export function groupes(x) {
  const h = String(x).toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(h)) throw new ErreurConsole("valeur_invalide", "32 octets en hexadécimal attendus");
  return h.match(/.{8}/g).join(" ");
}

/** Ce que la console calcule pour un objet A (EX-9.17) : $defs/condenses. */
export function condenses(a) {
  const A = objetA(a);
  const texte = jcs(A);
  const d = sha256(concat(utf8(PREFIXE_APPROBATION), utf8(texte)));
  const h = condenseEIP191(d);
  return { a: A, jcs: texte, d_a: enHex(d), fingerprint: empreinte(enHex(d)), groups: groupes(enHex(d)), h: enHex(h), h_fingerprint: empreinte(enHex(h)), utf8: estUtf8(d) };
}

const jetonRedige = (v) => typeof v === "string" && (v.includes("[REDIGE:") || v.includes("[PSEUDO:"));

/** Valeur de la pièce « arguments » (contrôle 3 d'EX-9.15), ou undefined si elle ne se vérifie pas. */
function valeurPiece(vue, ref) {
  if (!estObjet(ref)) return undefined;
  if (vue.arguments_piece !== null) {
    const o = base64Strict(vue.arguments_piece);
    if (o === null || enHex(sha256(o)) !== ref.sha256 || o.length !== ref.length) return undefined;
    try {
      return analyserJSONStrict(o);
    } catch {
      return undefined;
    }
  }
  if (!Object.hasOwn(ref, "value") || ref.redacted === true) return undefined;
  try {
    const o = utf8(jcs(ref.value));
    return enHex(sha256(o)) === ref.sha256 && o.length === ref.length ? ref.value : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Modèle d'affichage d'EX-9.4 tiré d'une vue du ticket (`$defs/vue_ticket`) et
 * du contexte { session: { session_identity, entry, addresses, is_requester },
 * decision, approver, reason, now } : les treize contrôles d'EX-9.15 dans
 * l'ordre (liste `blocking` complète), les condensés (EX-9.17), les
 * avertissements (EX-9.15, EX-9.19, EX-13.18) et `signable`
 * (`$defs/modele_affichage`). `intent_status` dit comment afficher
 * l'intention (contrôle 4 d'EX-9.15) : `reference_non_verifiable` quand
 * l'événement retenu la porte par une référence (objet), `en_clair` sinon ;
 * `effects` reprend les effets de la vue, chacun avec ses pointeurs vers le
 * résultat non résolus (`unresolved`, EX-12.14), affichés « connu après
 * exécution ».
 */
export function modeleAffichage(vue, { session, decision = null, approver: adresseChoisie = null, reason = null, now }) {
  const blocking = [];
  // Les adresses se comparent en minuscules (CT-1 §3) ; une adresse EIP-55 vaut sa forme minuscule.
  const approver = typeof adresseChoisie === "string" ? adresseChoisie.toLowerCase() : adresseChoisie;
  const ev = vue.retained_event;
  const req = vue.request;
  // 1. État.
  if (!ETATS_COLLECTE.includes(vue.state)) blocking.push("ticket_clos_aux_votes");
  // 2. Événement retenue.
  let evOk = false;
  try {
    evOk = estObjet(ev) && ev.execution?.status === "retenue" && ev.policy?.decision === "a_approuver" && ev.policy?.ticket === vue.ticket && hachageEvenement(ev) === ev.hash && ev.hash === vue.request_hash;
  } catch {
    evOk = false;
  }
  if (!evOk) blocking.push("evenement_invalide");
  let args = feuilles(req.arguments).map(({ pointer, value }) => ({ pointer, value, status: "non_verifiable" }));
  let digests = null;
  if (evOk) {
    // 3. Pièce « arguments ».
    const piece = valeurPiece(vue, ev.execution.arguments);
    if (piece === undefined) blocking.push("piece_invalide");
    // 4. Champs liés.
    const d = ev.delegation ?? {};
    const lies =
      ev.execution.tool === req.tool_announced &&
      ev.policy.rule === vue.rule.policy_rule &&
      ev.org_id === vue.org_id &&
      ev.journal_id === vue.journal_id &&
      ["launched_by", "on_behalf_of", "scope", "run_id"].every((k) => d[k] === req.delegation?.[k]) &&
      (typeof ev.intent !== "string" || ev.intent === req.intent);
    if (!lies) blocking.push("champ_different");
    // 5. Arguments, feuille par feuille (EX-9.16).
    if (piece !== undefined) {
      let different = false;
      args = feuilles(req.arguments).map(({ pointer, value }) => {
        const q = resoudre(piece, pointer);
        if (!q.resolu || jetonRedige(q.valeur)) return { pointer, value, status: "non_verifiable" };
        if (egalJSON(q.valeur, value)) return { pointer, value, status: "verifie" };
        different = true;
        return { pointer, value, status: "different" };
      });
      if (different) blocking.push("argument_different");
      if (feuilles(piece).some(({ pointer }) => !resoudre(req.arguments, pointer).resolu)) blocking.push("argument_absent_de_l_affichage");
    }
    // 6. Condensés : A formé depuis l'événement vérifié, pour les deux décisions.
    const base = { journal_id: ev.journal_id, org_id: ev.org_id, request_hash: ev.hash, ticket: ev.policy.ticket };
    digests = { approuve: condenses({ decision: "approuve", ...base }), refuse: condenses({ decision: "refuse", ...base }) };
    if (digests.approuve.d_a !== vue.digests?.approuve || digests.refuse.d_a !== vue.digests?.refuse) blocking.push("empreinte_divergente");
  }
  // 7. Jeu figé.
  const fige = vue.approver_set !== null;
  if (!fige) blocking.push("jeu_non_fige");
  // 8. Décision choisie.
  if (decision !== "approuve" && decision !== "refuse") blocking.push("decision_absente");
  // 9. Annuaire : identité, entrée active, adresse active attribuée à la session.
  let annuaireOk = false;
  if (session.entry === "absente") blocking.push("identite_inconnue");
  else if (session.entry !== "active") blocking.push("identite_desactivee");
  else if (approver === null || !session.addresses.includes(approver)) blocking.push("adresse_non_attribuee");
  else annuaireOk = true;
  // 10 et 11. Membre du jeu figé, puis éligible.
  if (annuaireOk && fige) {
    if (!vue.approver_set.members.includes(approver)) blocking.push("hors_jeu");
    else if (!vue.eligible.includes(approver)) blocking.push(vue.separation.self_approval === "interdite" && vue.separation.requester_addresses.includes(approver) ? "auto_approbation" : "recuse");
  }
  // 12. Session du demandeur.
  if (session.is_requester && vue.separation.self_approval === "interdite") blocking.push("session_du_demandeur");
  // 13. Motif.
  if (typeof reason === "string" && longueurPoints(reason) > MAX_MOTIF) blocking.push("motif_trop_long");
  const warnings = [];
  if (digests && (decision === "approuve" || decision === "refuse") && digests[decision].utf8) warnings.push("condense_utf8");
  const banniere = vue.separation.self_approval === "interdite" && !vue.separation.requester_declared;
  if (banniere) warnings.push("separation_non_verifiable");
  if (vue.added_members.length > 0) warnings.push("membres_ajoutes");
  if (vue.separation.requester_directory_addresses.some((a) => !vue.separation.requester_addresses.includes(a))) warnings.push("separation_incomplete");
  const deadline = vue.deadline;
  return {
    version: 0,
    ticket: vue.ticket,
    state: vue.state,
    org_id: vue.org_id,
    journal_id: vue.journal_id,
    tool: { announced: req.tool_announced, original: req.tool_original, server_alias: req.server_alias, class: req.class },
    arguments: args,
    effects: copie(vue.effects),
    rule: copie(vue.rule),
    opening: copie(vue.opening),
    intent: req.intent,
    intent_status: estObjet(ev?.intent) ? "reference_non_verifiable" : "en_clair",
    delegation: copie(req.delegation),
    separation_banner: banniere,
    request: { request_hash: vue.request_hash, seq: ev?.seq, ts: ev?.ts },
    digests,
    decision,
    approver,
    deadline,
    remaining_ms: deadline === null ? null : msHorodatage(deadline) - msHorodatage(now),
    contest: copie(vue.contest),
    approver_set: copie(vue.approver_set),
    effective_required: vue.effective_required,
    votes: copie(vue.votes),
    warnings,
    blocking,
    signable: blocking.length === 0,
  };
}

/**
 * Contexte de session du modèle d'affichage tiré de l'annuaire (contrôles 9 et
 * 12 d'EX-9.15) : état de l'entrée de la session, son adresse active, et si
 * le `launched_by` du ticket est l'un de ses alias de demandeur.
 */
export function sessionDepuisAnnuaire(annuaire, session_identity, launched_by) {
  const e = annuaire.entries.find((x) => x.session_identity === session_identity);
  if (!e) return { session_identity, entry: "absente", addresses: [], is_requester: false };
  return {
    session_identity,
    entry: e.active ? "active" : "desactivee",
    addresses: e.active ? e.addresses.filter((a) => a.state === "active").map((a) => a.address) : [],
    is_requester: e.requester_identities.includes(launched_by),
  };
}

// ---------------------------------------------------------------------------
// Portefeuille : requête, réponse, vote (9.7, 13.10, 13.14)
// ---------------------------------------------------------------------------

/** Premier paramètre de personal_sign pour un texte (ses octets UTF-8) ou des octets : 0x et hexadécimal minuscule. */
export function donneesPersonalSign(texteOuOctets) {
  return enHex(texteOuOctets instanceof Uint8Array ? texteOuOctets : utf8(String(texteOuOctets)));
}

/**
 * Requête EIP-1193 de signature (EX-13.24) : { method: "personal_sign",
 * params: [données en hexadécimal minuscule, adresse en minuscules] }, la
 * donnée d'abord. `donnees` : D_A (« 0x » et 64 chiffres) ou le résultat de
 * donneesPersonalSign d'un texte d'inscription.
 */
export function requetePersonalSign(donnees, adresse) {
  const o = octetsDe(donnees);
  const a = String(adresse).toLowerCase();
  if (!RE_ADRESSE.test(a)) throw new ErreurConsole("adresse_invalide", "adresse de 20 octets attendue");
  return { method: "personal_sign", params: [enHex(o), a] };
}

/**
 * Normalisation d'EX-9.3 et recouvrement (EX-9.21, pas 2 à 7) : chiffres
 * hexadécimaux mis en minuscules, 65 octets exigés, r et s dans [1, n − 1],
 * v ∈ {0, 1, 27, 28}, v + 27 pour 0 et 1, s haut ramené en bas avec v
 * inversé, recouvrement sur le condensé EIP-191 des octets, comparaison à
 * l'adresse attendue. Rend { ok, reason, signature, recovered } ; reason est
 * signature_invalide ou adresse_differente.
 */
export function verifierSignature(octets, signature, adresse) {
  const refus = (reason, recovered = null) => ({ ok: false, reason, signature: null, recovered });
  if (typeof signature !== "string" || !/^0x[0-9a-fA-F]*$/.test(signature)) return refus("signature_invalide");
  const sig = signature.toLowerCase();
  if (sig.length !== 132) return refus("signature_invalide");
  const r = BigInt("0x" + sig.slice(2, 66));
  let s = BigInt("0x" + sig.slice(66, 130));
  let v = parseInt(sig.slice(130), 16);
  if (r < 1n || r >= N_SECP256K1 || s < 1n || s >= N_SECP256K1) return refus("signature_invalide");
  if (v === 0 || v === 1) v += 27;
  if (v !== 27 && v !== 28) return refus("signature_invalide");
  if (s > MOITIE_N) {
    s = N_SECP256K1 - s;
    v = v === 27 ? 28 : 27;
  }
  const normalisee = "0x" + sig.slice(2, 66) + s.toString(16).padStart(64, "0") + v.toString(16);
  let recovered;
  try {
    recovered = recouvrerAdresse(condenseEIP191(octetsDe(octets)), r, s, v - 27);
  } catch {
    return refus("signature_invalide");
  }
  if (recovered !== String(adresse).toLowerCase()) return refus("adresse_differente", recovered);
  return { ok: true, reason: null, signature: normalisee, recovered };
}

/**
 * Issue d'une requête de signature au portefeuille (EX-9.21, EX-13.29) :
 * `reponse` est { result } (promesse tenue) ou { error: { code, message } }
 * (promesse rompue, code null sans code numérique). Rend { outcome, reason,
 * signature, recovered } ; outcome vaut accepte ou refuse.
 */
export function verifierReponse(reponse, donnees, adresse) {
  const refus = (reason, recovered = null) => ({ outcome: "refuse", reason, signature: null, recovered });
  if (estObjet(reponse) && Object.hasOwn(reponse, "error")) {
    const code = reponse.error?.code;
    return refus(Number.isInteger(code) && Object.hasOwn(CODES_EIP1193, code) ? CODES_EIP1193[code] : "erreur_portefeuille");
  }
  const result = estObjet(reponse) ? reponse.result : undefined;
  if (typeof result !== "string" || !/^0x[0-9a-fA-F]*$/.test(result)) return refus("reponse_invalide");
  const v = verifierSignature(donnees, result, adresse);
  if (!v.ok) return refus(v.reason, v.recovered);
  return { outcome: "accepte", reason: null, signature: v.signature, recovered: v.recovered };
}

/**
 * Corps exact de voter (EX-9.21 pas 8, EX-12.16, $defs/requete_voter) :
 * { ticket, approver, decision, signature, reason, session_identity }.
 */
export function requeteVoter(vue, decision, signature, adresse, motif, session) {
  return { ticket: vue.ticket, approver: String(adresse).toLowerCase(), decision, signature, reason: motif ?? null, session_identity: session };
}

// ---------------------------------------------------------------------------
// Découverte EIP-6963 (EX-13.22)
// ---------------------------------------------------------------------------

/** Vrai si `info` d'une annonce a la forme exigée au pas 2 d'EX-13.22 (le fournisseur est contrôlé à part). */
export function infoAnnonceValide(info) {
  return (
    estObjet(info) &&
    typeof info.uuid === "string" &&
    RE_UUID4.test(info.uuid) &&
    typeof info.name === "string" &&
    info.name.length > 0 &&
    longueurPoints(info.name) <= 64 &&
    typeof info.icon === "string" &&
    info.icon.startsWith("data:") &&
    typeof info.rdns === "string"
  );
}

/**
 * Liste des fournisseurs annoncés (EX-13.22), sans aucun choix : une annonce
 * invalide est écartée (annonce_invalide) ; la première annonce d'un uuid
 * l'ajoute ; une réannonce par le même objet est sans effet ; une annonce du
 * même uuid par un autre objet écarte les deux et exclut l'uuid pour la vie
 * de la page (annonce_en_double). `estFournisseur(provider)` dit si l'objet a
 * une fonction request (par défaut : un objet doté d'une fonction request).
 */
export class Decouverte {
  #liste = [];
  #exclus = new Set();
  #rejets = [];
  #indice = 0;
  #estFournisseur;
  #ecouteur = null;
  #cible = null;
  #auChangement;

  constructor({ estFournisseur = (p) => p !== null && typeof p === "object" && typeof p.request === "function", auChangement = null } = {}) {
    this.#estFournisseur = estFournisseur;
    this.#auChangement = auChangement;
  }

  /** Traite une annonce (le `detail` d'un événement eip6963:announceProvider). */
  annoncer(detail) {
    const index = this.#indice++;
    const rejeter = (i, reason) => this.#rejets.push({ index: i, reason });
    // Chaque membre est lu une seule fois et copié : un accesseur ne peut pas
    // rendre une valeur au contrôle et une autre à l'enregistrement.
    let copie = null;
    try {
      if (estObjet(detail)) {
        const info = detail.info;
        const provider = detail.provider;
        if (estObjet(info)) copie = { info: { uuid: info.uuid, name: info.name, icon: info.icon, rdns: info.rdns }, provider };
      }
    } catch {
      copie = null;
    }
    if (copie === null || !infoAnnonceValide(copie.info) || !this.#estFournisseur(copie.provider)) {
      rejeter(index, "annonce_invalide");
    } else {
      const { uuid, name, icon, rdns } = copie.info;
      const provider = copie.provider;
      const present = this.#liste.find((f) => f.uuid === uuid);
      if (this.#exclus.has(uuid)) rejeter(index, "annonce_en_double");
      else if (!present) this.#liste.push({ uuid, name, icon, rdns, provider, index });
      else if (present.provider !== provider) {
        this.#liste = this.#liste.filter((f) => f.uuid !== uuid);
        this.#exclus.add(uuid);
        rejeter(present.index, "annonce_en_double");
        rejeter(index, "annonce_en_double");
      }
    }
    if (this.#auChangement) this.#auChangement(this.fournisseurs(), this.rejets());
  }

  /** Fournisseurs proposés, dans l'ordre de leur première annonce. */
  fournisseurs() {
    return this.#liste.map(({ uuid, name, icon, rdns, provider }) => ({ uuid, name, icon, rdns, provider }));
  }

  /** Annonces écartées, par indice croissant. */
  rejets() {
    return [...this.#rejets].sort((a, b) => a.index - b.index);
  }

  /**
   * Pas 1 d'EX-13.22 : ajoute l'écouteur d'eip6963:announceProvider sur
   * `cible` (window dans la page) puis émet eip6963:requestProvider. `Evenement`
   * est le constructeur Event de l'environnement.
   */
  ecouter(cible, Evenement) {
    if (this.#ecouteur) return;
    this.#cible = cible;
    this.#ecouteur = (e) => this.annoncer(e.detail);
    cible.addEventListener("eip6963:announceProvider", this.#ecouteur);
    cible.dispatchEvent(new Evenement("eip6963:requestProvider"));
  }
}

/** Les annonces d'un vecteur (provider nommé par une chaîne) passées à Decouverte ; rend { providers, rejected }. */
export function decouvrir(annonces) {
  const d = new Decouverte({ estFournisseur: (p) => typeof p === "string" && p.length > 0 });
  for (const a of annonces) d.annoncer(a);
  return { providers: d.fournisseurs().map(({ uuid, name, rdns, provider }) => ({ uuid, name, rdns, provider })), rejected: d.rejets() };
}

// ---------------------------------------------------------------------------
// Fichier de clé chiffré (EX-13.28)
// ---------------------------------------------------------------------------

const hexOctets = (v, n) => {
  const o = depuisHexNu(v);
  return o !== null && (n === null || o.length === n) ? o : null;
};

/**
 * Contrôle et déchiffrement d'un fichier de clé (Web3 Secret Storage v3,
 * EX-13.28, pas 1 à 6 et 9). `fichier` : texte JSON ou valeur déjà lue.
 * Rend { outcome, reason, address, warnings, cle } ; `cle` (32 octets) n'est
 * rendue que si le fichier est accepté, et l'appelant l'efface après usage.
 */
export function lireFichierCle(fichier, motDePasse, adresse) {
  const refus = (reason, warnings = [], address = null) => ({ outcome: "refuse", reason, address, warnings, cle: null });
  let doc = fichier;
  if (typeof fichier === "string") {
    try {
      doc = analyserJSONStrict(fichier);
    } catch {
      return refus("fichier_cle_invalide");
    }
  }
  // 1. Format.
  const c = doc?.crypto;
  if (!estObjet(doc) || doc.version !== 3 || typeof doc.id !== "string" || !estObjet(c)) return refus("fichier_cle_invalide");
  const iv = estObjet(c.cipherparams) ? hexOctets(c.cipherparams.iv, 16) : null;
  const ct = hexOctets(c.ciphertext, 32);
  const mac = hexOctets(c.mac, 32);
  if (typeof c.cipher !== "string" || iv === null || ct === null || typeof c.kdf !== "string" || !estObjet(c.kdfparams) || mac === null) return refus("fichier_cle_invalide");
  // 2. Dérivation admise.
  const kp = c.kdfparams;
  const sel = hexOctets(kp.salt, null);
  const B = BORNES_FICHIER_CLE;
  let deriver;
  const warnings = [];
  if (c.cipher !== "aes-128-ctr" || sel === null || sel.length < B.sel_min || kp.dklen !== 32) return refus("fichier_cle_non_pris_en_charge");
  if (c.kdf === "pbkdf2") {
    if (kp.prf !== "hmac-sha256" || !Number.isInteger(kp.c) || kp.c < 1 || kp.c > B.c_max) return refus("fichier_cle_non_pris_en_charge");
    if (kp.c < B.c_faible) warnings.push("derivation_faible");
    deriver = (mdp) => pbkdf2Sha256(mdp, sel, kp.c, 32);
  } else if (c.kdf === "scrypt") {
    const { n, r, p } = kp;
    if (!Number.isInteger(n) || n < 2 || n > B.n_max || (n & (n - 1)) !== 0 || !Number.isInteger(r) || r < 1 || r > B.r_max || !Number.isInteger(p) || p < 1 || p > B.p_max) return refus("fichier_cle_non_pris_en_charge");
    if (n < B.n_faible) warnings.push("derivation_faible");
    deriver = (mdp) => scrypt(mdp, sel, n, r, p, 32);
  } else return refus("fichier_cle_non_pris_en_charge");
  // 4. Dérivation et MAC, avant tout déchiffrement.
  const mdp = utf8(String(motDePasse));
  const dk = deriver(mdp);
  mdp.fill(0);
  if (!egalOctets(keccak256(concat(dk.slice(16, 32), ct)), mac)) {
    dk.fill(0);
    return refus("mot_de_passe_ou_mac", warnings);
  }
  // 5. Déchiffrement et intervalle de la clé.
  const cle = aes128Ctr(dk.slice(0, 16), iv, ct);
  dk.fill(0);
  const adr = adresseDeCle(cle);
  if (adr === null) {
    cle.fill(0);
    return refus("cle_invalide", warnings);
  }
  // 6. Adresse choisie.
  if (adr !== String(adresse).toLowerCase()) {
    cle.fill(0);
    return refus("adresse_differente", warnings, adr);
  }
  return { outcome: "accepte", reason: null, address: adr, warnings, cle };
}

/**
 * Signature d'un vote par une clé déchiffrée dans la page (EX-13.28, pas 7 et
 * 8) : ECDSA RFC 6979 sur H = condensé EIP-191 des 32 octets de D_A, s bas,
 * v = 27 + recid ; la clé est effacée ensuite, quoi qu'il arrive.
 */
export function signerCondense(cle, d_a) {
  try {
    const d = octetsDe(d_a);
    if (d.length !== 32) throw new ErreurConsole("donnees_invalides", "D_A de 32 octets attendu");
    return signerHachage(cle, condenseEIP191(d));
  } finally {
    cle.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Identité de session (EX-13.7)
// ---------------------------------------------------------------------------

/** Vrai si `texte` est une identité de session canonique (EX-13.7). */
export const estIdentite = (texte) => typeof texte === "string" && texte.length <= 256 && RE_IDENTITE.test(texte);

/** Forme canonique d'EX-13.7 de { kind: "oidc", iss, sub } ou { kind: "utilisateur", domain, name } ; lève identite_invalide. */
export function identiteCanonique(champs) {
  const texte = champs?.kind === "oidc" ? `oidc ${champs.iss} ${champs.sub}` : champs?.kind === "utilisateur" ? `utilisateur ${champs.domain} ${champs.name}` : null;
  if (!estIdentite(texte)) throw new ErreurConsole("identite_invalide");
  return texte;
}

/** Champs d'une identité de session canonique ; lève identite_invalide. */
export function analyserIdentite(texte) {
  if (!estIdentite(texte)) throw new ErreurConsole("identite_invalide");
  const [kind, a, b] = texte.split(" ");
  return kind === "oidc" ? { kind, iss: a, sub: b } : { kind, domain: a, name: b };
}

// ---------------------------------------------------------------------------
// Message d'inscription (EX-13.12)
// ---------------------------------------------------------------------------

const CLES_MESSAGE = Object.freeze([
  ["origin", "Origine: "],
  ["org", "Organisation: "],
  ["org_id", "Identifiant d'organisation: "],
  ["identity", "Identite: "],
  ["address", "Adresse: "],
  ["issued_at", "Emis le: "],
  ["expires_at", "Expire le: "],
  ["nonce", "Nonce: "],
]);
const champsValides = (f) =>
  aCles(f, CLES_MESSAGE.map(([k]) => k)) &&
  typeof f.origin === "string" && RE_ORIGINE.test(f.origin) && f.origin.length <= 270 &&
  typeof f.org === "string" && RE_ORGANISATION.test(f.org) &&
  typeof f.org_id === "string" && RE_HEX32.test(f.org_id) &&
  estIdentite(f.identity) &&
  typeof f.address === "string" && RE_ADRESSE.test(f.address) &&
  !Number.isNaN(msHorodatage(f.issued_at)) &&
  !Number.isNaN(msHorodatage(f.expires_at)) &&
  typeof f.nonce === "string" && RE_NONCE.test(f.nonce);

/** Texte exact du message d'inscription (dix lignes, LF, sans LF final) ; lève message_invalide si un champ sort de sa grammaire. */
export function messageInscription(champs) {
  if (!champsValides(champs)) throw new ErreurConsole("message_invalide");
  return [LIGNE_TITRE_INSCRIPTION, LIGNE_AVERTISSEMENT_INSCRIPTION, ...CLES_MESSAGE.map(([k, cle]) => cle + champs[k])].join("\n");
}

/**
 * Analyse d'un message d'inscription (EX-13.12) : ASCII imprimable et LF,
 * dix lignes, les deux premières à l'identique, chaque clé à sa place, chaque
 * valeur dans sa grammaire, puis reconstruction et égalité octet pour octet.
 * Rend les champs ; lève message_invalide.
 */
export function analyserMessageInscription(texte) {
  if (typeof texte !== "string" || !/^[ -~\n]*$/.test(texte)) throw new ErreurConsole("message_invalide");
  const lignes = texte.split("\n");
  if (lignes.length !== 10 || lignes[0] !== LIGNE_TITRE_INSCRIPTION || lignes[1] !== LIGNE_AVERTISSEMENT_INSCRIPTION) throw new ErreurConsole("message_invalide");
  const champs = {};
  for (const [i, [k, cle]] of CLES_MESSAGE.entries()) {
    if (!lignes[i + 2].startsWith(cle)) throw new ErreurConsole("message_invalide");
    champs[k] = lignes[i + 2].slice(cle.length);
  }
  if (messageInscription(champs) !== texte) throw new ErreurConsole("message_invalide");
  return champs;
}

/** Ce que AN-2 exige d'un texte : longueur, donnée de personal_sign, condensé EIP-191, longueur de la préimage. */
export function mesuresMessage(texte) {
  const o = utf8(texte);
  return { length: o.length, personal_sign_data: enHex(o), eip191_digest: enHex(condenseEIP191(o)), preimage_length: preimageEIP191(o).length };
}

// ---------------------------------------------------------------------------
// Annuaire : formes des requêtes, inscription, opérations (13.4 à 13.6)
// ---------------------------------------------------------------------------

const RE_SIGNATURE_BRUTE = /^0x([0-9a-f]{2})*$/;
const identiteRequete = (v) => typeof v === "string" && v.length >= 1 && v.length <= 1024;
const motifRequete = (v) => v === null || (typeof v === "string" && v.length >= 1 && v.length <= 1024);
const demandeurRequete = (v) => typeof v === "string" && v.length >= 1 && v.length <= 256;
const FORMES = Object.freeze({
  preparer_inscription: (q) => aCles(q, ["session_identity", "address"]) && identiteRequete(q.session_identity) && RE_ADRESSE.test(q.address),
  inscrire: (q) =>
    aCles(q, ["session_identity", "address", "message", "signature"]) &&
    identiteRequete(q.session_identity) &&
    typeof q.address === "string" && RE_ADRESSE.test(q.address) &&
    typeof q.message === "string" && q.message.length <= 4096 &&
    typeof q.signature === "string" && q.signature.length <= 1024 && RE_SIGNATURE_BRUTE.test(q.signature),
  valider: (q) => aCles(q, ["session_identity", "entry", "address"]) && identiteRequete(q.session_identity) && typeof q.entry === "string" && RE_ENTREE.test(q.entry) && q.entry.length <= 128 && typeof q.address === "string" && RE_ADRESSE.test(q.address),
  revoquer: (q) => aCles(q, ["session_identity", "entry", "address", "reason"]) && identiteRequete(q.session_identity) && typeof q.entry === "string" && RE_ENTREE.test(q.entry) && q.entry.length <= 128 && typeof q.address === "string" && RE_ADRESSE.test(q.address) && motifRequete(q.reason),
  desactiver: (q) => aCles(q, ["session_identity", "entry", "reason"]) && identiteRequete(q.session_identity) && typeof q.entry === "string" && RE_ENTREE.test(q.entry) && q.entry.length <= 128 && motifRequete(q.reason),
  lier_demandeur: (q) => aCles(q, ["session_identity", "entry", "launched_by"]) && identiteRequete(q.session_identity) && typeof q.entry === "string" && RE_ENTREE.test(q.entry) && q.entry.length <= 128 && demandeurRequete(q.launched_by),
});
const forme = (methode, q) => {
  const f = FORMES[methode] ?? FORMES[{ reactiver: "desactiver", delier_demandeur: "lier_demandeur" }[methode]];
  return Boolean(f && f(q));
};

const entreeDe = (annuaire, session) => annuaire.entries.find((e) => e.session_identity === session);
const entreeDeAdresse = (annuaire, adresse) => annuaire.entries.find((e) => e.addresses.some((a) => a.address === adresse));
const ADRESSE_VIDE = Object.freeze({ validated_at: null, validated_by: null, revoked_at: null, revoked_by: null, revocation_cause: null, revocation_reason: null, replaced_by: null });

/** Identifiant d'une nouvelle entrée : compteur sur 4 chiffres (vecteurs) ou 64 bits aléatoires (EX-13.9, EX-7.1). */
function nouvelIdentifiant(annuaire, mode) {
  if (mode === "compteur") return `apb-${String(annuaire.entries.length + 1).padStart(4, "0")}`;
  const o = new Uint8Array(8);
  globalThis.crypto.getRandomValues(o);
  return `apb-${enHex(o).slice(2)}`;
}

/** Opération acceptée : ajoutée à operations, revision incrémentée, updated_at posé (EX-12.17). */
function inscrireOperation(annuaire, at, op, by, entry, { address = null, launched_by = null, reason = null, administrators = null } = {}) {
  annuaire.revision += 1;
  annuaire.updated_at = at;
  annuaire.operations.push({ seq: annuaire.revision, at, op, by, entry, address, launched_by, reason, administrators });
}

/**
 * Recopie du réglage administrators de la configuration du service dans
 * l'annuaire (EX-13.37) : si la liste diffère, comme liste, de la copie de
 * l'annuaire, l'opération changer_administrateurs est inscrite (by
 * « configuration », entry nul, administrators { before, after }), revision
 * incrémentée et updated_at posé à `at`. Une liste hors de la forme
 * d'EX-13.9 (1 à 64 identités canoniques distinctes) lève identite_invalide.
 * Ne modifie pas ses arguments. Rend { annuaire, changed }.
 */
export function recopierAdministrateurs(annuaire, administrateurs, at) {
  if (!Array.isArray(administrateurs) || administrateurs.length < 1 || administrateurs.length > 64 || new Set(administrateurs).size !== administrateurs.length || !administrateurs.every(estIdentite)) {
    throw new ErreurConsole("identite_invalide", "réglage administrators hors de la forme d'EX-13.9");
  }
  const doc = copie(annuaire);
  if (egalJSON(doc.administrators, administrateurs)) return { annuaire: doc, changed: false };
  const before = doc.administrators;
  doc.administrators = [...administrateurs];
  inscrireOperation(doc, at, "changer_administrateurs", "configuration", null, { administrators: { before, after: [...administrateurs] } });
  return { annuaire: doc, changed: true };
}

/**
 * Vérification d'une inscription par le service (EX-13.15), dans l'ordre des
 * treize pas ; le défi est marqué présenté dès le pas 4. `defis` :
 * [{ fields, used }] ($defs/defi). Rend { accepted, reason, entry, signature,
 * defis } : `entry` est l'entrée qui reçoit l'adresse (existante, ou
 * `nouvelle` pour une entrée à créer), `signature` la forme normalisée gardée
 * dans la preuve, `defis` la liste après le pas 4.
 */
export function verifierInscription(annuaire, defis, requete, recuA, { identifiant = "aleatoire" } = {}) {
  let liste = copie(defis);
  const refus = (reason) => ({ accepted: false, reason, entry: null, signature: null, defis: liste });
  if (!forme("inscrire", requete)) return refus("requete_invalide");
  if (!estIdentite(requete.session_identity)) return refus("identite_invalide");
  let champs;
  try {
    champs = analyserMessageInscription(requete.message);
  } catch {
    return refus("message_invalide");
  }
  const defi = liste.find((d) => d.fields.nonce === champs.nonce);
  if (!defi) return refus("nonce_inconnu");
  if (defi.used) return refus("nonce_deja_utilise");
  defi.used = true;
  const r = msHorodatage(recuA);
  if (!(msHorodatage(champs.issued_at) <= r && r < msHorodatage(champs.expires_at))) return refus("inscription_expiree");
  if (champs.origin !== annuaire.console_origin) return refus("origine_differente");
  if (champs.org !== annuaire.org || champs.org_id !== annuaire.org_id) return refus("organisation_differente");
  if (champs.identity !== requete.session_identity || champs.identity !== defi.fields.identity) return refus("identite_differente");
  if (champs.address !== requete.address || champs.address !== defi.fields.address) return refus("adresse_differente");
  if (requete.message !== messageInscription(defi.fields)) return refus("message_invalide");
  const v = verifierSignature(utf8(requete.message), requete.signature, requete.address);
  if (!v.ok) return refus("signature_invalide");
  const e = entreeDe(annuaire, requete.session_identity);
  if (e && !e.active) return refus("identite_desactivee");
  if (entreeDeAdresse(annuaire, requete.address)) return refus("adresse_deja_attribuee");
  return { accepted: true, reason: null, entry: e ? e.id : nouvelIdentifiant(annuaire, identifiant), signature: v.signature, defis: liste };
}

/**
 * Applique une méthode de l'annuaire (12.9) : preparer_inscription (EX-13.13),
 * inscrire (EX-13.15), valider, revoquer, desactiver, reactiver,
 * lier_demandeur, delier_demandeur (EX-13.17), en tenant les invariants
 * d'EX-13.10. `options` : { defis, nonce (preparer_inscription), identifiant
 * ("compteur" pour les vecteurs, "aleatoire" sinon) }. Ne modifie pas ses
 * arguments. Rend { annuaire, defis, accepted, reason, response }.
 */
export function appliquerOperation(annuaire, methode, requete, at, { defis = [], nonce = null, identifiant = "aleatoire" } = {}) {
  const doc = copie(annuaire);
  let liste = copie(defis);
  const refus = (reason) => ({ annuaire: copie(annuaire), defis: liste, accepted: false, reason, response: null });
  const accepte = (response) => ({ annuaire: doc, defis: liste, accepted: true, reason: null, response });
  if (!METHODES_ANNUAIRE.includes(methode) || !forme(methode, requete)) return refus("requete_invalide");
  if (!estIdentite(requete.session_identity)) return refus("identite_invalide");
  const session = requete.session_identity;
  const admin = doc.administrators.includes(session);

  if (methode === "preparer_inscription") {
    const e = entreeDe(doc, session);
    if (e && !e.active) return refus("identite_desactivee");
    if (entreeDeAdresse(doc, requete.address)) return refus("adresse_deja_attribuee");
    if (typeof nonce !== "string" || !RE_NONCE.test(nonce)) {
      const o = new Uint8Array(16);
      globalThis.crypto.getRandomValues(o);
      nonce = enHex(o).slice(2);
    }
    const fields = { origin: doc.console_origin, org: doc.org, org_id: doc.org_id, identity: session, address: requete.address, issued_at: at, expires_at: horodatage(msHorodatage(at) + doc.registration_ttl_ms), nonce };
    liste = liste.filter((d) => !(d.fields.identity === session && d.fields.address === requete.address));
    liste.push({ fields, used: false });
    return { annuaire: doc, defis: liste, accepted: true, reason: null, response: { fields, message: messageInscription(fields) } };
  }

  if (methode === "inscrire") {
    const v = verifierInscription(doc, liste, requete, at, { identifiant });
    liste = v.defis;
    if (!v.accepted) return refus(v.reason);
    const champs = analyserMessageInscription(requete.message);
    let e = entreeDe(doc, session);
    if (!e) {
      e = { id: v.entry, session_identity: session, external_id: null, display_name: null, active: true, requester_identities: [], created_at: at, addresses: [] };
      doc.entries.push(e);
    }
    e.addresses.push({ address: requete.address, state: "en_attente", proof: { message: requete.message, signature: v.signature, nonce: champs.nonce, issued_at: champs.issued_at, expires_at: champs.expires_at, received_at: at }, ...ADRESSE_VIDE });
    inscrireOperation(doc, at, "inscrire", session, e.id, { address: requete.address });
    return accepte({ entry: e.id, address: requete.address, state: "en_attente", revision: doc.revision });
  }

  if (methode === "revoquer") {
    const e = doc.entries.find((x) => x.id === requete.entry);
    if (!e) return refus("entree_inconnue");
    const a = e.addresses.find((x) => x.address === requete.address);
    if (!a) return refus("adresse_inconnue");
    const personne = e.session_identity === session;
    if (!admin && !personne) return refus("revocation_non_autorisee");
    if (a.state !== "en_attente" && a.state !== "active") return refus("etat_incompatible");
    Object.assign(a, { state: "revoquee", revoked_at: at, revoked_by: session, revocation_cause: personne ? "personne" : "administrateur", revocation_reason: requete.reason, replaced_by: null });
    inscrireOperation(doc, at, "revoquer", session, e.id, { address: a.address, reason: requete.reason });
    return accepte({ entry: e.id, address: a.address, state: "revoquee", revision: doc.revision });
  }

  // Méthodes d'administrateur.
  if (!admin) return refus("non_administrateur");
  const e = doc.entries.find((x) => x.id === requete.entry);
  if (!e) return refus("entree_inconnue");
  const reponseEntree = () => ({ entry: e.id, active: e.active, requester_identities: [...e.requester_identities], revision: doc.revision });

  if (methode === "valider") {
    const a = e.addresses.find((x) => x.address === requete.address);
    if (!a) return refus("adresse_inconnue");
    if (e.session_identity === session) return refus("auto_validation");
    if (!e.active) return refus("identite_desactivee");
    if (a.state !== "en_attente") return refus("etat_incompatible");
    for (const p of e.addresses) {
      if (p.state === "active") Object.assign(p, { state: "revoquee", revoked_at: at, revoked_by: session, revocation_cause: "remplacee", revocation_reason: null, replaced_by: a.address });
    }
    Object.assign(a, { state: "active", validated_at: at, validated_by: session });
    inscrireOperation(doc, at, "valider", session, e.id, { address: a.address });
    return accepte({ entry: e.id, address: a.address, state: "active", revision: doc.revision });
  }
  if (methode === "desactiver") {
    if (!e.active) return refus("etat_incompatible");
    e.active = false;
    for (const a of e.addresses) {
      if (a.state === "en_attente" || a.state === "active") Object.assign(a, { state: "revoquee", revoked_at: at, revoked_by: session, revocation_cause: "desactivation", revocation_reason: null, replaced_by: null });
    }
    liste = liste.filter((d) => d.fields.identity !== e.session_identity);
    inscrireOperation(doc, at, "desactiver", session, e.id, { reason: requete.reason });
    return accepte(reponseEntree());
  }
  if (methode === "reactiver") {
    if (e.active) return refus("etat_incompatible");
    e.active = true;
    inscrireOperation(doc, at, "reactiver", session, e.id, { reason: requete.reason });
    return accepte(reponseEntree());
  }
  if (methode === "lier_demandeur") {
    if (doc.entries.some((x) => x.requester_identities.includes(requete.launched_by))) return refus("demandeur_deja_lie");
    e.requester_identities.push(requete.launched_by);
    inscrireOperation(doc, at, "lier_demandeur", session, e.id, { launched_by: requete.launched_by });
    return accepte(reponseEntree());
  }
  // delier_demandeur
  if (!e.requester_identities.includes(requete.launched_by)) return refus("demandeur_inconnu");
  e.requester_identities = e.requester_identities.filter((x) => x !== requete.launched_by);
  inscrireOperation(doc, at, "delier_demandeur", session, e.id, { launched_by: requete.launched_by });
  return accepte(reponseEntree());
}

/** Résumé des entrées ($defs/resume_entree) : identifiant, état, alias, adresses et leur état. */
export function resumeEntrees(annuaire) {
  return annuaire.entries.map((e) => ({ id: e.id, active: e.active, requester_identities: [...e.requester_identities], addresses: e.addresses.map((a) => ({ address: a.address, state: a.state })) }));
}

/**
 * L'annuaire tel que la méthode annuaire le rend à une session (EX-12.17) :
 * complet pour un administrateur ; sinon réduit à l'entrée de la session et
 * aux opérations qui la visent.
 */
export function annuaireDeSession(annuaire, session) {
  if (annuaire.administrators.includes(session)) return copie(annuaire);
  const doc = copie(annuaire);
  doc.entries = doc.entries.filter((e) => e.session_identity === session);
  const ids = doc.entries.map((e) => e.id);
  doc.operations = doc.operations.filter((o) => ids.includes(o.entry));
  return doc;
}

// ---------------------------------------------------------------------------
// Contrôles de la console à chaque action (EX-13.18)
// ---------------------------------------------------------------------------

/**
 * Contrôle d'une action de vote (`voter`) ou de récusation (`recuser`)
 * (EX-13.18) : la première raison dans l'ordre jeu_non_fige,
 * identite_inconnue, identite_desactivee, adresse_non_attribuee, hors_jeu,
 * session_du_demandeur (vote seulement). `ticket` : { launched_by,
 * self_approval, policy_requester_addresses, directory_requester_addresses,
 * members } ; members nul tant que le jeu n'est pas figé. L'avertissement
 * separation_incomplete porte les adresses que l'annuaire attribue au
 * demandeur et que la politique ne déclare pas, triées. L'adresse est
 * comparée en minuscules. Rend { allowed, reason, warnings }.
 */
export function controleVote(annuaire, session, action, adresseChoisie, ticket) {
  const adresse = typeof adresseChoisie === "string" ? adresseChoisie.toLowerCase() : adresseChoisie;
  const manquantes = [...new Set(ticket.directory_requester_addresses.filter((a) => !ticket.policy_requester_addresses.includes(a)))].sort();
  const warnings = manquantes.length ? [{ code: "separation_incomplete", addresses: manquantes }] : [];
  const r = (reason) => ({ allowed: reason === null, reason, warnings });
  if (ticket.members === null) return r("jeu_non_fige");
  const e = entreeDe(annuaire, session);
  if (!e) return r("identite_inconnue");
  if (!e.active) return r("identite_desactivee");
  if (!e.addresses.some((a) => a.state === "active" && a.address === adresse)) return r("adresse_non_attribuee");
  if (!ticket.members.includes(adresse)) return r("hors_jeu");
  if (action === "voter" && ticket.self_approval === "interdite" && e.requester_identities.includes(ticket.launched_by)) return r("session_du_demandeur");
  return r(null);
}

/**
 * Le `by` d'un retrait que la console peut envoyer (EX-13.18, EX-7.15) : le
 * launched_by du ticket quand il est un alias de demandeur de l'entrée de la
 * session, sinon l'identité de session quand elle est administrateur, sinon
 * null (la console n'offre pas l'action).
 */
export function actionRetrait(annuaire, session, ticket, administrateurs = annuaire.administrators) {
  const e = entreeDe(annuaire, session);
  if (e && e.requester_identities.includes(ticket.launched_by)) return ticket.launched_by;
  if (administrateurs.includes(session)) return session;
  return null;
}

/**
 * Contrôle de l'identité de session par le service, sur le canal de la
 * console, avant que l'entrée de 7.4 ne soit formée (EX-12.13, EX-12.14,
 * EX-12.16, EX-12.19). `methode` : tickets, consulter, voter, recuser ou
 * retirer ; `requete` : son corps, déjà conforme à sa définition de schéma ;
 * `ticket` : { launched_by, eligible }, `eligible` étant les membres
 * éligibles du jeu figé, ou, avant le gel, ceux du jeu de repli ; `null`
 * pour un ticket inconnu dans l'organisation (et toujours pour tickets).
 * Rend null si la méthode passe, sinon la première raison : identite_invalide ;
 * puis, pour tickets et consulter, session_non_autorisee pour une session
 * hors de l'organisation (ni administrateur, ni entrée active), ticket_inconnu,
 * et session_non_autorisee pour une session qui ne peut pas voir les
 * arguments du ticket (EX-12.14) ; pour voter et recuser,
 * session_non_autorisee (adresse) puis ticket_inconnu ; pour retirer,
 * ticket_inconnu puis session_non_autorisee (EX-12.19).
 */
export function controleCanal(annuaire, methode, requete, ticket) {
  const session = requete?.session_identity;
  if (!estIdentite(session)) return "identite_invalide";
  const e = entreeDe(annuaire, session);
  const active = e && e.active ? e.addresses.find((a) => a.state === "active")?.address ?? null : null;
  const admin = annuaire.administrators.includes(session);
  if (methode === "tickets" || methode === "consulter") {
    // (a) Session de l'organisation : administrateur, ou entrée active de l'annuaire.
    if (!admin && !(e && e.active)) return "session_non_autorisee";
    if (methode === "tickets") return null;
    // (b) Ticket inconnu dans l'organisation ; (c) session qui ne peut pas voir ses arguments.
    if (ticket === null) return "ticket_inconnu";
    return admin || (active !== null && ticket.eligible.includes(active)) ? null : "session_non_autorisee";
  }
  if (methode === "voter" || methode === "recuser") {
    if (active === null || String(requete.approver).toLowerCase() !== active) return "session_non_autorisee";
    return ticket === null ? "ticket_inconnu" : null;
  }
  if (methode === "retirer") {
    if (ticket === null) return "ticket_inconnu";
    const demandeur = requete.by === ticket.launched_by && Boolean(e && e.active && e.requester_identities.includes(ticket.launched_by));
    const administrateur = requete.by === session && admin;
    return demandeur || administrateur ? null : "session_non_autorisee";
  }
  throw new ErreurConsole("requete_invalide", `méthode du canal inconnue : ${String(methode)}`);
}

// ---------------------------------------------------------------------------
// Annuaire exporté (EX-13.19)
// ---------------------------------------------------------------------------

const avant = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Rejeu d'une opération d'un annuaire exporté (règles d'EX-13.15 hors nonce
 * et horloge, d'EX-13.17 et d'EX-13.37) ; rend vrai si elle se rejoue. Les
 * droits d'administrateur se jugent sur la liste en vigueur à l'opération
 * (`etat.administrators`).
 */
function rejouerOperation(etat, doc, op) {
  if (op.op === "changer_administrateurs") {
    const a = op.administrators;
    if (!estObjet(a) || !egalJSON(a.before, etat.administrators) || egalJSON(a.after, a.before)) return false;
    etat.administrators = copie(a.after);
    return op.by === "configuration" && op.entry === null && op.address === null && op.launched_by === null && op.reason === null;
  }
  if (op.administrators !== null) return false;
  const admin = etat.administrators.includes(op.by);
  const e = etat.entries.find((x) => x.id === op.entry);
  switch (op.op) {
    case "inscrire": {
      if (e && e.session_identity !== op.by) return false;
      if (!e && etat.entries.some((x) => x.session_identity === op.by)) return false;
      const source = doc.entries.find((x) => x.id === op.entry)?.addresses.find((a) => a.address === op.address);
      if (!source || !estObjet(source.proof)) return false;
      let champs;
      try {
        champs = analyserMessageInscription(source.proof.message);
      } catch {
        return false;
      }
      if (champs.origin !== doc.console_origin || champs.org !== doc.org || champs.org_id !== doc.org_id || champs.identity !== op.by || champs.address !== op.address) return false;
      if (!verifierSignature(utf8(source.proof.message), source.proof.signature, op.address).ok) return false;
      if (e && !e.active) return false;
      if (etat.entries.some((x) => x.addresses.some((a) => a.address === op.address))) return false;
      let cible = e;
      if (!cible) {
        cible = { id: op.entry, session_identity: op.by, active: true, requester_identities: [], created_at: op.at, addresses: [] };
        etat.entries.push(cible);
      }
      cible.addresses.push({ address: op.address, state: "en_attente", proof: copie(source.proof), ...ADRESSE_VIDE });
      return op.launched_by === null && op.reason === null;
    }
    case "revoquer": {
      if (!e) return false;
      const a = e.addresses.find((x) => x.address === op.address);
      if (!a) return false;
      const personne = e.session_identity === op.by;
      if (!admin && !personne) return false;
      if (a.state !== "en_attente" && a.state !== "active") return false;
      Object.assign(a, { state: "revoquee", revoked_at: op.at, revoked_by: op.by, revocation_cause: personne ? "personne" : "administrateur", revocation_reason: op.reason, replaced_by: null });
      return op.launched_by === null;
    }
    default: {
      if (!admin || !e) return false;
      if (op.op === "valider") {
        const a = e.addresses.find((x) => x.address === op.address);
        if (!a || e.session_identity === op.by || !e.active || a.state !== "en_attente") return false;
        for (const p of e.addresses) if (p.state === "active") Object.assign(p, { state: "revoquee", revoked_at: op.at, revoked_by: op.by, revocation_cause: "remplacee", revocation_reason: null, replaced_by: a.address });
        Object.assign(a, { state: "active", validated_at: op.at, validated_by: op.by });
        return op.launched_by === null && op.reason === null;
      }
      if (op.op === "desactiver") {
        if (!e.active) return false;
        e.active = false;
        for (const a of e.addresses) if (a.state === "en_attente" || a.state === "active") Object.assign(a, { state: "revoquee", revoked_at: op.at, revoked_by: op.by, revocation_cause: "desactivation", revocation_reason: null, replaced_by: null });
        return op.address === null && op.launched_by === null;
      }
      if (op.op === "reactiver") {
        if (e.active) return false;
        e.active = true;
        return op.address === null && op.launched_by === null;
      }
      if (op.op === "lier_demandeur") {
        if (typeof op.launched_by !== "string" || etat.entries.some((x) => x.requester_identities.includes(op.launched_by))) return false;
        e.requester_identities.push(op.launched_by);
        return op.address === null;
      }
      if (op.op === "delier_demandeur") {
        if (!e.requester_identities.includes(op.launched_by)) return false;
        e.requester_identities = e.requester_identities.filter((x) => x !== op.launched_by);
        return op.address === null;
      }
      return false;
    }
  }
}

/** Ce qui se compare au rejeu : l'entrée sans external_id ni display_name, données sans effet (EX-13.9). */
const entreeComparable = (e) => ({ id: e.id, session_identity: e.session_identity, active: e.active, requester_identities: e.requester_identities, created_at: e.created_at, addresses: e.addresses });

/**
 * Vérification hors ligne d'un annuaire exporté (EX-13.19) : rend la liste
 * complète des écarts { code, pointer }, triée par pointeur puis par code
 * (unités UTF-16). Le contrôle du schéma est fait par l'appelant, qui passe
 * `conforme(document)` ; un document non conforme, ou que la vérification ne
 * peut pas parcourir, donne exactement [{ code: "schema", pointer: null }].
 */
export function verifierAnnuaireExporte(document, { conforme = null } = {}) {
  const schema = [{ code: "schema", pointer: null }];
  if (conforme !== null && !conforme(document)) return schema;
  try {
    const erreurs = [];
    const ecart = (code, pointer) => erreurs.push({ code, pointer });
    const doc = document;
    // 2. Révision, numéros, instants.
    if (doc.revision !== doc.operations.length) ecart("revision_incoherente", "/revision");
    doc.operations.forEach((o, j) => {
      if (o.seq !== j + 1) ecart("revision_incoherente", `/operations/${j}/seq`);
      if (j > 0 && msHorodatage(o.at) < msHorodatage(doc.operations[j - 1].at)) ecart("revision_incoherente", `/operations/${j}/at`);
    });
    const derniere = doc.operations.length ? doc.operations[doc.operations.length - 1].at : null;
    if (doc.updated_at !== derniere) ecart("revision_incoherente", "/updated_at");
    // 3. Unicités, une adresse active par entrée.
    const ids = new Set(), identites = new Set(), adresses = new Set();
    doc.entries.forEach((e, i) => {
      if (ids.has(e.id)) ecart("identifiant_double", `/entries/${i}/id`);
      ids.add(e.id);
      if (identites.has(e.session_identity)) ecart("identite_double", `/entries/${i}/session_identity`);
      identites.add(e.session_identity);
      e.addresses.forEach((a, k) => {
        if (adresses.has(a.address)) ecart("adresse_double", `/entries/${i}/addresses/${k}/address`);
        adresses.add(a.address);
      });
      if (e.addresses.filter((a) => a.state === "active").length > 1) ecart("deux_adresses_actives", `/entries/${i}/addresses`);
    });
    // 4 et 5. Preuves, auto-validation.
    doc.entries.forEach((e, i) =>
      e.addresses.forEach((a, k) => {
        const p = a.proof;
        const ptr = `/entries/${i}/addresses/${k}`;
        let champs = null;
        try {
          champs = analyserMessageInscription(p.message);
        } catch {
          champs = null;
        }
        const sig = typeof p.signature === "string" ? p.signature : "";
        const canonique = /^0x[0-9a-f]{130}$/.test(sig) && ["1b", "1c"].includes(sig.slice(130)) && BigInt("0x" + sig.slice(66, 130)) <= MOITIE_N;
        if (champs === null || !canonique || !verifierSignature(utf8(p.message), sig, a.address).ok) ecart("preuve_invalide", `${ptr}/proof`);
        else {
          const recu = msHorodatage(p.received_at);
          const concordante =
            champs.origin === doc.console_origin && champs.org === doc.org && champs.org_id === doc.org_id && champs.identity === e.session_identity && champs.address === a.address &&
            champs.nonce === p.nonce && champs.issued_at === p.issued_at && champs.expires_at === p.expires_at &&
            msHorodatage(champs.issued_at) <= recu && recu < msHorodatage(champs.expires_at);
          if (!concordante) ecart("preuve_discordante", `${ptr}/proof`);
        }
        if (a.validated_by !== null && a.validated_by === e.session_identity) ecart("auto_validation", `${ptr}/validated_by`);
      }),
    );
    // 6. Rejeu des opérations depuis un annuaire vide ; la liste des
    // administrateurs de départ est le before de la première opération
    // changer_administrateurs, ou, sans elle, administrators (EX-13.37).
    const premier = doc.operations.find((o) => o.op === "changer_administrateurs");
    const etat = { entries: [], administrators: copie(premier ? premier.administrators?.before ?? [] : doc.administrators) };
    const j = doc.operations.findIndex((o) => !rejouerOperation(etat, doc, o));
    if (j !== -1) ecart("operations_incoherentes", `/operations/${j}`);
    else if (!egalJSON(etat.administrators, doc.administrators)) ecart("operations_incoherentes", "/administrators");
    else if (!egalJSON(etat.entries.map(entreeComparable), doc.entries.map(entreeComparable))) ecart("operations_incoherentes", "/entries");
    return erreurs.sort((a, b) => avant(a.pointer, b.pointer) || avant(a.code, b.code));
  } catch {
    return schema;
  }
}
