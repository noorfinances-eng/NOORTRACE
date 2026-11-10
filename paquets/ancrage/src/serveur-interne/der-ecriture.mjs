// Encodeur DER du serveur RFC 3161 interne (lot E). Écrit depuis X.690
// (ISO/IEC 8825-1) : longueurs définies minimales, INTEGER minimal (octet 00
// de tête seulement si le bit de poids fort du premier octet significatif
// vaut 1), BOOLEAN `ff`, GeneralizedTime à la seconde sans fraction (X.690
// §11.7), SET OF trié par les octets des encodages (X.690 §11.6), aucune
// valeur DEFAULT encodée (X.690 §11.5 ; CT-6 EX-9.21). Les fonctions rendent
// des Uint8Array ; les appelants composent des structures sans jamais
// réencoder ce qu'ils recopient (messageImprint, nonce, noms de certificats).

const ENCODEUR_UTF8 = new TextEncoder();

/** Concatène des tableaux d'octets. */
export function concat(...parties) {
  let n = 0;
  for (const p of parties) n += p.length;
  const sortie = new Uint8Array(n);
  let i = 0;
  for (const p of parties) {
    sortie.set(p, i);
    i += p.length;
  }
  return sortie;
}

/** Octets de longueur DER (forme courte sous 128, forme longue minimale au-delà). */
export function longueur(n) {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError("longueur DER : entier non négatif attendu");
  if (n < 0x80) return Uint8Array.of(n);
  const octets = [];
  let reste = n;
  while (reste > 0) {
    octets.unshift(reste % 256);
    reste = Math.floor(reste / 256);
  }
  return Uint8Array.of(0x80 | octets.length, ...octets);
}

/** Élément TLV : étiquette (un octet, numéro < 31), longueur, contenu. */
export function tlv(etiquette, contenu) {
  if (!Number.isInteger(etiquette) || etiquette < 0 || etiquette > 0xff) throw new RangeError("étiquette DER hors d'un octet");
  if ((etiquette & 0x1f) === 0x1f) throw new RangeError("étiquette DER : numéro 31 et au-delà non pris en charge");
  return concat(Uint8Array.of(etiquette), longueur(contenu.length), contenu);
}

export const ETIQUETTE = Object.freeze({
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8STRING: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  PRINTABLESTRING: 0x13,
  IA5STRING: 0x16,
  UTCTIME: 0x17,
  GENERALIZEDTIME: 0x18,
});

/** SEQUENCE des éléments donnés, dans l'ordre. */
export function sequence(...elements) {
  return tlv(ETIQUETTE.SEQUENCE, concat(...elements));
}

/** SET dont l'ordre des éléments est celui de l'appelant (SET à composants nommés : ordre des étiquettes, X.690 §10.3). */
export function ensemble(...elements) {
  return tlv(ETIQUETTE.SET, concat(...elements));
}

/**
 * Compare deux encodages comme des chaînes d'octets, le plus court complété
 * par des zéros à sa fin (X.690 §11.6).
 */
export function comparerOctets(a, b) {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = i < a.length ? a[i] : 0;
    const y = i < b.length ? b[i] : 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/** SET OF : éléments triés par leurs octets (X.690 §11.6). */
export function ensembleDe(...elements) {
  const tries = [...elements].sort(comparerOctets);
  return tlv(ETIQUETTE.SET, concat(...tries));
}

/** Octets grand-boutiens non signés d'un bigint ≥ 0, sans zéro de tête (vide pour 0). */
export function octetsNonSignes(valeur) {
  if (typeof valeur !== "bigint" || valeur < 0n) throw new RangeError("entier non négatif attendu");
  const hex = valeur.toString(16);
  const pair = hex.length % 2 ? `0${hex}` : hex;
  const sortie = new Uint8Array(pair.length / 2);
  for (let i = 0; i < sortie.length; i++) sortie[i] = parseInt(pair.slice(2 * i, 2 * i + 2), 16);
  return valeur === 0n ? new Uint8Array(0) : sortie;
}

/**
 * INTEGER DER d'un entier (number sûr ou bigint). Les négatifs sont encodés en
 * complément à deux minimal ; les non négatifs reçoivent un octet 00 de tête
 * seulement si le bit de poids fort du premier octet vaut 1.
 */
export function entier(valeur) {
  let v = typeof valeur === "number" ? BigInt(valeur) : valeur;
  if (typeof v !== "bigint") throw new TypeError("INTEGER : number ou bigint attendu");
  if (typeof valeur === "number" && !Number.isSafeInteger(valeur)) throw new RangeError("INTEGER : entier sûr attendu");
  if (v >= 0n) {
    const octets = octetsNonSignes(v);
    const contenu = octets.length === 0 || octets[0] & 0x80 ? concat(Uint8Array.of(0), octets) : octets;
    return tlv(ETIQUETTE.INTEGER, contenu);
  }
  // Complément à deux minimal.
  let bits = 8;
  while (-(1n << BigInt(bits - 1)) > v) bits += 8;
  const contenu = octetsNonSignes((1n << BigInt(bits)) + v);
  return tlv(ETIQUETTE.INTEGER, contenu);
}

/**
 * INTEGER DER depuis des octets grand-boutiens non signés (numéro de série,
 * nonce) : zéros de tête retirés, 00 ajouté si le bit haut vaut 1.
 */
export function entierDepuisOctets(octets) {
  let debut = 0;
  while (debut < octets.length - 1 && octets[debut] === 0) debut++;
  const corps = octets.length === 0 ? Uint8Array.of(0) : octets.subarray(debut);
  const contenu = corps[0] & 0x80 ? concat(Uint8Array.of(0), corps) : corps;
  return tlv(ETIQUETTE.INTEGER, contenu);
}

/** BOOLEAN DER : `ff` ou `00`. */
export function booleen(valeur) {
  return tlv(ETIQUETTE.BOOLEAN, Uint8Array.of(valeur ? 0xff : 0x00));
}

/** NULL. */
export function nul() {
  return Uint8Array.of(0x05, 0x00);
}

/** OCTET STRING primitive. */
export function chaineOctets(octets) {
  return tlv(ETIQUETTE.OCTET_STRING, octets);
}

/** BIT STRING primitive d'octets entiers (aucun bit inutilisé). */
export function chaineBits(octets) {
  return tlv(ETIQUETTE.BIT_STRING, concat(Uint8Array.of(0), octets));
}

/**
 * BIT STRING d'une liste de bits nommés (KeyUsage, PKIFailureInfo) : en DER,
 * les bits à zéro de fin sont retirés et le nombre de bits inutilisés est
 * celui du dernier octet (X.690 §11.2.2).
 */
export function bitsNommes(positions) {
  if (positions.length === 0) return tlv(ETIQUETTE.BIT_STRING, Uint8Array.of(0));
  const max = Math.max(...positions);
  if (!positions.every((p) => Number.isInteger(p) && p >= 0)) throw new RangeError("bit nommé : position entière attendue");
  const octets = new Uint8Array(Math.floor(max / 8) + 1);
  for (const p of positions) octets[Math.floor(p / 8)] |= 0x80 >> p % 8;
  const inutilises = 7 - (max % 8);
  return tlv(ETIQUETTE.BIT_STRING, concat(Uint8Array.of(inutilises), octets));
}

/** OBJECT IDENTIFIER depuis sa forme pointée. */
export function oid(texte) {
  if (typeof texte !== "string" || !/^[0-9]+(\.[0-9]+)+$/.test(texte)) throw new RangeError(`OID mal formé : ${texte}`);
  const arcs = texte.split(".").map((a) => BigInt(a));
  if (arcs[0] > 2n || (arcs[0] < 2n && arcs[1] > 39n)) throw new RangeError(`OID hors de la norme : ${texte}`);
  const valeurs = [arcs[0] * 40n + arcs[1], ...arcs.slice(2)];
  const octets = [];
  for (const v of valeurs) {
    const groupe = [];
    let reste = v;
    do {
      groupe.unshift(Number(reste & 0x7fn));
      reste >>= 7n;
    } while (reste > 0n);
    for (let i = 0; i < groupe.length - 1; i++) groupe[i] |= 0x80;
    octets.push(...groupe);
  }
  return tlv(ETIQUETTE.OID, Uint8Array.from(octets));
}

/** UTF8String. */
export function utf8(texte) {
  return tlv(ETIQUETTE.UTF8STRING, ENCODEUR_UTF8.encode(texte));
}

/** PrintableString (jeu restreint de X.680 §41.4 ; refus hors du jeu). */
export function imprimable(texte) {
  if (!/^[A-Za-z0-9 '()+,\-./:=?]*$/.test(texte)) throw new RangeError("PrintableString : caractère hors du jeu");
  return tlv(ETIQUETTE.PRINTABLESTRING, ENCODEUR_UTF8.encode(texte));
}

/** IA5String (ASCII). */
export function ia5(texte) {
  for (const c of texte) if (c.charCodeAt(0) > 0x7f) throw new RangeError("IA5String : caractère hors de l'ASCII");
  return tlv(ETIQUETTE.IA5STRING, ENCODEUR_UTF8.encode(texte));
}

function deuxChiffres(n) {
  return String(n).padStart(2, "0");
}

/** Champs UTC d'un instant en millisecondes, tronqué à la seconde. */
function champsUtc(ms) {
  if (!Number.isFinite(ms)) throw new RangeError("instant : nombre fini attendu");
  const d = new Date(Math.floor(ms / 1000) * 1000);
  const annee = d.getUTCFullYear();
  if (annee < 0 || annee > 9999) throw new RangeError("instant hors des années 0000 à 9999");
  return {
    annee,
    corps: `${deuxChiffres(d.getUTCMonth() + 1)}${deuxChiffres(d.getUTCDate())}${deuxChiffres(d.getUTCHours())}${deuxChiffres(d.getUTCMinutes())}${deuxChiffres(d.getUTCSeconds())}`,
  };
}

/** GeneralizedTime `YYYYMMDDHHMMSSZ` à la seconde (X.690 §11.7 : aucune fraction nulle). */
export function tempsGeneralise(ms) {
  const { annee, corps } = champsUtc(ms);
  return tlv(ETIQUETTE.GENERALIZEDTIME, ENCODEUR_UTF8.encode(`${String(annee).padStart(4, "0")}${corps}Z`));
}

/** UTCTime `YYMMDDHHMMSSZ`, années 1950 à 2049 seulement (RFC 5280 §4.1.2.5.1). */
export function tempsUtc(ms) {
  const { annee, corps } = champsUtc(ms);
  if (annee < 1950 || annee > 2049) throw new RangeError("UTCTime : années 1950 à 2049 seulement");
  return tlv(ETIQUETTE.UTCTIME, ENCODEUR_UTF8.encode(`${deuxChiffres(annee % 100)}${corps}Z`));
}

/** `Time` de RFC 5280 §4.1.2.5 : UTCTime jusqu'en 2049, GeneralizedTime ensuite. */
export function temps(ms) {
  return champsUtc(ms).annee <= 2049 ? tempsUtc(ms) : tempsGeneralise(ms);
}

/** Étiquette contextuelle [n] EXPLICIT (constructed) autour d'un élément. */
export function explicite(n, ...elements) {
  if (!Number.isInteger(n) || n < 0 || n > 30) throw new RangeError("étiquette contextuelle 0 à 30 attendue");
  return tlv(0xa0 | n, concat(...elements));
}

/**
 * Étiquette contextuelle [n] IMPLICIT : remplace l'étiquette de l'élément en
 * gardant sa forme (primitive ou construite).
 */
export function implicite(n, element) {
  if (!Number.isInteger(n) || n < 0 || n > 30) throw new RangeError("étiquette contextuelle 0 à 30 attendue");
  const copie = Uint8Array.from(element);
  copie[0] = 0x80 | (element[0] & 0x20) | n;
  return copie;
}

/** AlgorithmIdentifier : OID et paramètres (absents, ou donnés encodés). */
export function identifiantAlgorithme(oidTexte, parametres = null) {
  return parametres ? sequence(oid(oidTexte), parametres) : sequence(oid(oidTexte));
}

/** Texte PEM d'un DER. */
export function pem(etiquette, der) {
  const b64 = Buffer.from(der).toString("base64");
  const lignes = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${etiquette}-----\n${lignes.join("\n")}\n-----END ${etiquette}-----\n`;
}

/** DER du premier bloc PEM d'une étiquette donnée (ou du premier bloc, quelle que soit l'étiquette). */
export function depuisPem(texte, etiquetteAttendue = null) {
  const t = typeof texte === "string" ? texte : Buffer.from(texte).toString("latin1");
  const re = /-----BEGIN ([A-Z0-9 ]+)-----\r?\n([A-Za-z0-9+/=\r\n]+?)-----END \1-----/g;
  let m;
  while ((m = re.exec(t)) !== null) {
    if (etiquetteAttendue === null || m[1] === etiquetteAttendue) {
      const corps = m[2].replace(/[\r\n]/g, "");
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(corps)) throw new RangeError("PEM : base64 mal formé");
      return new Uint8Array(Buffer.from(corps, "base64"));
    }
  }
  throw new RangeError(`PEM : aucun bloc ${etiquetteAttendue ?? ""} trouvé`);
}

/** Hexadécimal minuscule préfixé `0x` (CT-1 §3). */
export function versHex(octets) {
  return `0x${Buffer.from(octets).toString("hex")}`;
}

/** Octets d'un hexadécimal minuscule préfixé `0x`. */
export function depuisHex(texte) {
  if (typeof texte !== "string" || !/^0x([0-9a-f]{2})*$/.test(texte)) throw new RangeError("hexadécimal minuscule préfixé 0x attendu");
  return new Uint8Array(Buffer.from(texte.slice(2), "hex"));
}

/** Égalité d'octets. */
export function memesOctets(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
