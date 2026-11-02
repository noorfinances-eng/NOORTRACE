// Conventions d'encodage de CT-1 §3 : octets en hexadécimal minuscule préfixé
// 0x, horodatages RFC 3339 à la milliseconde décodés strictement, secondes
// UNIX, entiers sûrs, base64 canonique (RFC 4648 §4).
//
// Aucune horloge n'est lue ici : un instant est toujours un paramètre.

/** Plus grand entier sûr admis par CT-1 §3 et §4 : 2^53 − 1. */
export const ENTIER_MAX = Number.MAX_SAFE_INTEGER;

/** Trente-deux octets nuls en hexadécimal préfixé (racine vide, premier prev_hash). */
export const ZERO32 = "0x" + "00".repeat(32);

const MOTIF_HEX = /^0x(?:[0-9a-f]{2})*$/;

/**
 * Dit si une valeur est une chaîne hexadécimale minuscule préfixée 0x, de
 * longueur paire, et, si `octets` est donné, d'exactement ce nombre d'octets.
 * @param {unknown} valeur
 * @param {number} [octets]
 * @returns {boolean}
 */
export function estHex(valeur, octets) {
  if (typeof valeur !== "string" || !MOTIF_HEX.test(valeur)) return false;
  return octets === undefined || valeur.length === 2 + 2 * octets;
}

/**
 * Décode une chaîne hexadécimale minuscule préfixée 0x en octets. Refuse les
 * majuscules, l'absence de préfixe et une longueur impaire (CT-1 §3).
 * @param {string} texte
 * @param {number} [octets] longueur exigée, en octets
 * @returns {Uint8Array}
 */
export function hexVersOctets(texte, octets) {
  if (!estHex(texte, octets)) {
    throw new TypeError(
      `hexadécimal minuscule préfixé 0x attendu${octets === undefined ? "" : ` (${octets} octets)`}`,
    );
  }
  return Uint8Array.from(Buffer.from(texte.slice(2), "hex"));
}

/**
 * Encode des octets en hexadécimal minuscule préfixé 0x.
 * @param {Uint8Array} octets
 * @returns {string}
 */
export function octetsVersHex(octets) {
  if (!(octets instanceof Uint8Array)) throw new TypeError("octets attendus (Uint8Array)");
  return "0x" + Buffer.from(octets.buffer, octets.byteOffset, octets.byteLength).toString("hex");
}

/**
 * Concatène des suites d'octets.
 * @param {...Uint8Array} parties
 * @returns {Uint8Array}
 */
export function concatener(...parties) {
  let longueur = 0;
  for (const p of parties) {
    if (!(p instanceof Uint8Array)) throw new TypeError("octets attendus (Uint8Array)");
    longueur += p.length;
  }
  const sortie = new Uint8Array(longueur);
  let i = 0;
  for (const p of parties) {
    sortie.set(p, i);
    i += p.length;
  }
  return sortie;
}

/**
 * Compare deux suites d'octets en temps proportionnel à leur longueur.
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function octetsEgaux(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/**
 * Dit si une valeur est un entier JSON admis par CT-1 (intervalle sûr).
 * @param {unknown} valeur
 * @returns {boolean}
 */
export function estEntierSur(valeur) {
  return typeof valeur === "number" && Number.isSafeInteger(valeur);
}

const MOTIF_HORODATAGE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{3})Z$/;

/**
 * Dit si une année du calendrier grégorien proleptique est bissextile.
 * @param {number} annee
 * @returns {boolean}
 */
function bissextile(annee) {
  return (annee % 4 === 0 && annee % 100 !== 0) || annee % 400 === 0;
}

const JOURS_PAR_MOIS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/**
 * Nombre de jours depuis le 1970-01-01 d'une date du calendrier grégorien
 * proleptique (algorithme « days from civil », sans Date : aucune
 * renormalisation possible, années 0000 à 9999 comprises).
 * @param {number} a année
 * @param {number} m mois, 1 à 12
 * @param {number} j jour, 1 à 31
 * @returns {number}
 */
function joursDepuisEpoque(a, m, j) {
  const y = m <= 2 ? a - 1 : a;
  const ere = Math.floor(y / 400);
  const ane = y - ere * 400;
  const mp = (m + 9) % 12;
  const jda = Math.floor((153 * mp + 2) / 5) + j - 1;
  const jde = ane * 365 + Math.floor(ane / 4) - Math.floor(ane / 100) + jda;
  return ere * 146097 + jde - 719468;
}

/**
 * Décode un horodatage de CT-1 §3 (`AAAA-MM-JJThh:mm:ss.mmmZ`) en
 * millisecondes depuis l'époque UNIX. Une date qui n'existe pas dans le
 * calendrier grégorien proleptique (30 février, 31 avril, 29 février d'une
 * année non bissextile) est refusée, jamais renormalisée ; pas de seconde
 * intercalaire.
 * @param {unknown} texte
 * @returns {number|null} l'instant en millisecondes, ou null si le texte ne se décode pas
 */
export function decoderHorodatage(texte) {
  if (typeof texte !== "string") return null;
  const r = MOTIF_HORODATAGE.exec(texte);
  if (!r) return null;
  const [a, mo, j, h, mi, s, ms] = r.slice(1).map((x) => Number(x));
  if (mo < 1 || mo > 12) return null;
  const jours = mo === 2 && bissextile(a) ? 29 : JOURS_PAR_MOIS[mo - 1];
  if (j < 1 || j > jours) return null;
  if (h > 23 || mi > 59 || s > 59) return null;
  return joursDepuisEpoque(a, mo, j) * 86400000 + h * 3600000 + mi * 60000 + s * 1000 + ms;
}

/**
 * Dit si une valeur est un horodatage de CT-1 §3 qui se décode.
 * @param {unknown} texte
 * @returns {boolean}
 */
export function estHorodatage(texte) {
  return decoderHorodatage(texte) !== null;
}

/**
 * Écrit un instant (millisecondes depuis l'époque, entier) au format de
 * CT-1 §3. Années 0000 à 9999 seulement.
 * @param {number} ms
 * @returns {string}
 */
export function ecrireHorodatage(ms) {
  if (!Number.isSafeInteger(ms)) throw new TypeError("instant entier en millisecondes attendu");
  const d = new Date(ms);
  const a = d.getUTCFullYear();
  if (Number.isNaN(a) || a < 0 || a > 9999) throw new RangeError("année hors de 0000 à 9999");
  const deux = (n) => String(n).padStart(2, "0");
  return (
    `${String(a).padStart(4, "0")}-${deux(d.getUTCMonth() + 1)}-${deux(d.getUTCDate())}` +
    `T${deux(d.getUTCHours())}:${deux(d.getUTCMinutes())}:${deux(d.getUTCSeconds())}` +
    `.${String(d.getUTCMilliseconds()).padStart(3, "0")}Z`
  );
}

const MOTIF_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * Décode un base64 canonique (RFC 4648 §4, alphabet standard, remplissage
 * exact, sans saut de ligne, bits de bourrage nuls : le réencodage redonne la
 * chaîne). Rend null pour toute autre forme.
 * @param {unknown} texte
 * @param {number} [maxOctets] taille maximale des octets décodés
 * @returns {Uint8Array|null}
 */
export function decoderBase64Canonique(texte, maxOctets) {
  if (typeof texte !== "string" || !MOTIF_BASE64.test(texte)) return null;
  const octets = Buffer.from(texte, "base64");
  if (octets.toString("base64") !== texte) return null;
  if (maxOctets !== undefined && octets.length > maxOctets) return null;
  return Uint8Array.from(octets);
}

/**
 * Encode des octets en base64 canonique (RFC 4648 §4).
 * @param {Uint8Array} octets
 * @returns {string}
 */
export function encoderBase64(octets) {
  if (!(octets instanceof Uint8Array)) throw new TypeError("octets attendus (Uint8Array)");
  return Buffer.from(octets.buffer, octets.byteOffset, octets.byteLength).toString("base64");
}

/**
 * Encode un texte en UTF-8.
 * @param {string} texte
 * @returns {Uint8Array}
 */
export function utf8(texte) {
  return new TextEncoder().encode(texte);
}
