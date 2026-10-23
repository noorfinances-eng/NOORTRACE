// Contrôle 4 de l'architecture : jeton d'horodatage RFC 3161 sur periodHash
// (spec/CT-6-verificateur.md §9). Implémentation de référence JavaScript des
// vérifications T-1 à T-11 et des avertissements AV-T-1 à AV-T-4.
//
// Ce module ne fait aucun accès réseau, ne lit pas l'horloge du système
// (EX-3.2) et ne consulte aucun magasin de certificats (EX-3.3) : la seule
// validation de chemin est celle de T-7, écrite ici, à l'instant genTime du
// jeton, contre les autorités du fichier d'ancres du réviseur. node:crypto ne
// sert qu'à importer des clés publiques et à vérifier des signatures.
//
// Contenu :
//   - un lecteur DER borné (§9.3, EX-9.4) : longueurs définies minimales,
//     étiquettes de numéro < 31, BOOLEAN 00 ou ff, types universels de forme
//     correcte, profondeur 32, aucun octet en trop ;
//   - la lecture d'un certificat X.509, d'une CRL, d'un TimeStampToken et de
//     son TSTInfo ;
//   - les vérifications T-1 à T-11 (verifierJeton) et le statut du contrôle 4
//     (EX-9.18), les faits rapportés (EX-9.19) et la proposition de l'énoncé
//     (EX-9.20) ;
//   - le contrôle des parties « horodatage » d'un fichier d'ancres (N-1).
//
// Les textes (détails, résumé) sont produits en français et en anglais ; la
// fonction verifierJeton les rend dans la langue demandée, sauf la
// proposition de l'énoncé, toujours dans les deux langues (EX-8.3).

import crypto from "node:crypto";

// ---------------------------------------------------------------------------
// Identifiants (§9.4)
// ---------------------------------------------------------------------------

export const OID = {
  signedData: "1.2.840.113549.1.7.2",
  tstInfo: "1.2.840.113549.1.9.16.1.4",
  contentType: "1.2.840.113549.1.9.3",
  messageDigest: "1.2.840.113549.1.9.4",
  signingTime: "1.2.840.113549.1.9.5",
  signingCertificate: "1.2.840.113549.1.9.16.2.12",
  signingCertificateV2: "1.2.840.113549.1.9.16.2.47",
  md5: "1.2.840.113549.2.5",
  sha1: "1.3.14.3.2.26",
  sha224: "2.16.840.1.101.3.4.2.4",
  sha256: "2.16.840.1.101.3.4.2.1",
  sha384: "2.16.840.1.101.3.4.2.2",
  sha512: "2.16.840.1.101.3.4.2.3",
  rsaEncryption: "1.2.840.113549.1.1.1",
  md5WithRSAEncryption: "1.2.840.113549.1.1.4",
  sha1WithRSAEncryption: "1.2.840.113549.1.1.5",
  sha256WithRSAEncryption: "1.2.840.113549.1.1.11",
  sha384WithRSAEncryption: "1.2.840.113549.1.1.12",
  sha512WithRSAEncryption: "1.2.840.113549.1.1.13",
  rsassaPss: "1.2.840.113549.1.1.10",
  mgf1: "1.2.840.113549.1.1.8",
  ecPublicKey: "1.2.840.10045.2.1",
  ecdsaWithSHA1: "1.2.840.10045.4.1",
  ecdsaWithSHA256: "1.2.840.10045.4.3.2",
  ecdsaWithSHA384: "1.2.840.10045.4.3.3",
  ecdsaWithSHA512: "1.2.840.10045.4.3.4",
  p256: "1.2.840.10045.3.1.7",
  p384: "1.3.132.0.34",
  p521: "1.3.132.0.35",
  dsa: "1.2.840.10040.4.1",
  dsaWithSHA1: "1.2.840.10040.4.3",
  ed25519: "1.3.101.112",
  ed448: "1.3.101.113",
  idKpTimeStamping: "1.3.6.1.5.5.7.3.8",
  qcStatements: "1.3.6.1.5.5.7.1.3",
  qtstStatement1: "0.4.0.19422.1.1",
  subjectKeyIdentifier: "2.5.29.14",
  keyUsage: "2.5.29.15",
  basicConstraints: "2.5.29.19",
  extKeyUsage: "2.5.29.37",
  cRLNumber: "2.5.29.20",
  cRLReasons: "2.5.29.21",
  deltaCRLIndicator: "2.5.29.27",
  issuingDistributionPoint: "2.5.29.28",
  authorityKeyIdentifier: "2.5.29.35",
  commonName: "2.5.4.3",
};

const NOM_EMPREINTE = { [OID.md5]: "md5", [OID.sha1]: "sha1", [OID.sha224]: "sha224", [OID.sha256]: "sha256", [OID.sha384]: "sha384", [OID.sha512]: "sha512" };
const LIBELLE_EMPREINTE = { sha1: "SHA-1", md5: "MD5", sha224: "SHA-224", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
const EMPREINTES_ADMISES = new Set(["sha256", "sha384", "sha512"]);
const NOM_SIGNATURE = {
  [OID.rsaEncryption]: "rsaEncryption",
  [OID.sha256WithRSAEncryption]: "sha256WithRSAEncryption",
  [OID.sha384WithRSAEncryption]: "sha384WithRSAEncryption",
  [OID.sha512WithRSAEncryption]: "sha512WithRSAEncryption",
  [OID.rsassaPss]: "id-RSASSA-PSS",
  [OID.ecdsaWithSHA256]: "ecdsa-with-SHA256",
  [OID.ecdsaWithSHA384]: "ecdsa-with-SHA384",
  [OID.ecdsaWithSHA512]: "ecdsa-with-SHA512",
};
const COURBES_ADMISES = { [OID.p256]: "P-256", [OID.p384]: "P-384", [OID.p521]: "P-521" };
const NOMS_COURBES_NODE = { prime256v1: "P-256", secp384r1: "P-384", secp521r1: "P-521" };

/** Bornes de la section 15.1 et de EX-4.13 pour le contrôle 4. */
export const BORNES = {
  tailleJeton: 64 * 1024,
  profondeurDER: 32,
  certificatsJeton: 16,
  cheminMax: 4, // n ≤ 4 : cinq certificats au plus, ancre non comprise (EX-9.13)
  bitsNumeroSerie: 160,
  precisionSecondes: 86400, // accuracy.seconds au plus une journée (EX-9.15, règle 2)
};

// ---------------------------------------------------------------------------
// Textes bilingues
// ---------------------------------------------------------------------------

/** Un texte dans les deux langues. */
export const T = (fr, en = fr) => ({ fr, en });
const joindre = (morceaux, sep = T(" ; ", "; ")) => ({
  fr: morceaux.map((m) => m.fr).join(sep.fr),
  en: morceaux.map((m) => m.en).join(sep.en),
});
const hex = (b) => "0x" + Buffer.from(b).toString("hex");

// ---------------------------------------------------------------------------
// Lecteur DER borné (§9.3)
// ---------------------------------------------------------------------------

/** Erreur de lecture DER : le jeton, le certificat ou la CRL est inexploitable. */
export class ErreurDER extends Error {}

const UNIVERSEL_CONSTRUIT = new Set([16, 17]);

/**
 * Nœud TLV lu dans `buf` : `etiquette` (premier octet), `classe` (0 universel,
 * 1 application, 2 contexte, 3 privé), `construit`, `numero`, `debut` (position
 * de l'étiquette), `debutValeur`, `fin` (fin de la valeur), `profondeur`, et
 * pour un nœud construit `enfants`. Les octets bruts sont `octets()`, la valeur
 * `valeur()`.
 */
class Noeud {
  constructor(buf, debut, etiquette, debutValeur, fin, profondeur) {
    this.buf = buf;
    this.debut = debut;
    this.etiquette = etiquette;
    this.classe = etiquette >> 6;
    this.construit = (etiquette & 0x20) !== 0;
    this.numero = etiquette & 0x1f;
    this.debutValeur = debutValeur;
    this.fin = fin;
    this.profondeur = profondeur;
    this.enfants = null;
  }
  octets() {
    return this.buf.subarray(this.debut, this.fin);
  }
  valeur() {
    return this.buf.subarray(this.debutValeur, this.fin);
  }
  get longueur() {
    return this.fin - this.debutValeur;
  }
}

/**
 * Lit exactement une structure DER dans `buf`, sans octet après elle.
 * `profondeurInitiale` : profondeur du premier nœud (0 au sommet d'un fichier).
 */
export function lireDER(buf, { profondeurInitiale = 0, profondeurMax = BORNES.profondeurDER } = {}) {
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);
  const [noeud, fin] = lireTLV(buf, 0, buf.length, profondeurInitiale, profondeurMax);
  if (fin !== buf.length) throw new ErreurDER(`${buf.length - fin} octet(s) après la fin de la structure`);
  return noeud;
}

function lireTLV(buf, pos, limite, profondeur, profondeurMax) {
  if (profondeur > profondeurMax) throw new ErreurDER(`profondeur d'imbrication supérieure à ${profondeurMax}`);
  if (pos >= limite) throw new ErreurDER("structure tronquée (étiquette attendue)");
  const etiquette = buf[pos];
  if ((etiquette & 0x1f) === 0x1f) throw new ErreurDER(`étiquette de numéro ≥ 31 à la position ${pos}`);
  let p = pos + 1;
  if (p >= limite) throw new ErreurDER("structure tronquée (longueur attendue)");
  const l0 = buf[p++];
  let longueur;
  if (l0 < 0x80) longueur = l0;
  else if (l0 === 0x80) throw new ErreurDER(`longueur indéfinie à la position ${pos}`);
  else {
    const n = l0 & 0x7f;
    if (n > 4) throw new ErreurDER(`longueur sur ${n} octets à la position ${pos}`);
    if (p + n > limite) throw new ErreurDER("structure tronquée (octets de longueur)");
    if (buf[p] === 0) throw new ErreurDER(`longueur non minimale à la position ${pos}`);
    longueur = 0;
    for (let i = 0; i < n; i++) longueur = longueur * 256 + buf[p + i];
    p += n;
    if (longueur < 0x80) throw new ErreurDER(`longueur non minimale à la position ${pos}`);
  }
  const fin = p + longueur;
  if (fin > limite) throw new ErreurDER(`longueur ${longueur} au-delà de la structure englobante à la position ${pos}`);
  const noeud = new Noeud(buf, pos, etiquette, p, fin, profondeur);
  if (noeud.classe === 0) {
    if (UNIVERSEL_CONSTRUIT.has(noeud.numero) !== noeud.construit) throw new ErreurDER(`type universel ${noeud.numero} de forme ${noeud.construit ? "construite" : "primitive"} à la position ${pos}`);
    if (noeud.numero === 1 && (longueur !== 1 || (buf[p] !== 0x00 && buf[p] !== 0xff))) throw new ErreurDER(`BOOLEAN mal codé à la position ${pos}`);
    if (noeud.numero === 5 && longueur !== 0) throw new ErreurDER(`NULL de longueur non nulle à la position ${pos}`);
    if (noeud.numero === 2 && longueur === 0) throw new ErreurDER(`INTEGER vide à la position ${pos}`);
    if (noeud.numero === 3 && (longueur === 0 || buf[p] > 7 || (longueur === 1 && buf[p] !== 0))) throw new ErreurDER(`BIT STRING mal codé à la position ${pos}`);
    if (noeud.numero === 0) throw new ErreurDER(`étiquette universelle 0 à la position ${pos}`);
  }
  if (noeud.construit) {
    noeud.enfants = [];
    let q = p;
    while (q < fin) {
      const [enfant, suite] = lireTLV(buf, q, fin, profondeur + 1, profondeurMax);
      noeud.enfants.push(enfant);
      q = suite;
    }
  }
  return [noeud, fin];
}

// Accès typés : chacun lève ErreurDER si la forme n'est pas celle attendue.

function attendre(noeud, etiquette, quoi) {
  if (!noeud) throw new ErreurDER(`${quoi} absent`);
  if (noeud.etiquette !== etiquette) throw new ErreurDER(`${quoi} : étiquette 0x${noeud.etiquette.toString(16).padStart(2, "0")} au lieu de 0x${etiquette.toString(16).padStart(2, "0")}`);
  return noeud;
}
const sequence = (n, quoi) => attendre(n, 0x30, quoi).enfants;
const ensemble = (n, quoi) => attendre(n, 0x31, quoi).enfants;

/** OID d'un nœud 06, en notation pointée. */
export function oid(noeud, quoi = "OID") {
  return decoderOID(attendre(noeud, 0x06, quoi).valeur(), quoi);
}

/** Notation pointée des octets de valeur d'un OID (forme minimale exigée). */
export function decoderOID(v, quoi = "OID") {
  if (v.length === 0) throw new ErreurDER(`${quoi} vide`);
  const sous = [];
  let courant = 0n;
  let debutSous = true;
  for (let i = 0; i < v.length; i++) {
    const b = v[i];
    if (debutSous && b === 0x80) throw new ErreurDER(`${quoi} : sous-identifiant non minimal`);
    courant = (courant << 7n) | BigInt(b & 0x7f);
    debutSous = false;
    if ((b & 0x80) === 0) {
      sous.push(courant);
      courant = 0n;
      debutSous = true;
    } else if (i === v.length - 1) throw new ErreurDER(`${quoi} tronqué`);
  }
  const premier = sous[0];
  const tete = premier < 40n ? [0n, premier] : premier < 80n ? [1n, premier - 40n] : [2n, premier - 80n];
  return [...tete, ...sous.slice(1)].map(String).join(".");
}

/** Entier (BigInt, complément à deux) d'un nœud 02 ou d'une étiquette implicite donnée. */
export function entier(noeud, quoi = "INTEGER", etiquette = 0x02) {
  return entierDepuis(attendre(noeud, etiquette, quoi).valeur());
}
function entierDepuis(v) {
  let x = 0n;
  for (const b of v) x = (x << 8n) | BigInt(b);
  if (v.length && v[0] & 0x80) x -= 1n << BigInt(8 * v.length);
  return x;
}
function petitEntier(noeud, quoi, etiquette = 0x02) {
  const x = entier(noeud, quoi, etiquette);
  if (x < -(2n ** 53n) || x > 2n ** 53n) throw new ErreurDER(`${quoi} hors des bornes`);
  return Number(x);
}
const octetString = (noeud, quoi) => attendre(noeud, 0x04, quoi).valeur();
function bitString(noeud, quoi) {
  const v = attendre(noeud, 0x03, quoi).valeur();
  return { inutilises: v[0], octets: v.subarray(1) };
}
const booleen = (noeud, quoi) => attendre(noeud, 0x01, quoi).valeur()[0] === 0xff;

/**
 * Chaîne d'un attribut de nom (UTF8String, PrintableString, IA5String,
 * NumericString, TeletexString, BMPString). Lève ErreurDER pour tout autre
 * type et pour des octets qui ne se décodent pas (UTF-8 invalide, BMPString
 * de longueur impaire) : jamais une autre exception (EX-15.2).
 */
function chaine(noeud) {
  const v = noeud.valeur();
  switch (noeud.etiquette) {
    case 0x0c:
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(v);
      } catch {
        throw new ErreurDER("UTF8String invalide");
      }
    case 0x13:
    case 0x16:
    case 0x12:
      return v.toString("latin1");
    case 0x14:
      return v.toString("latin1");
    case 0x1e: {
      if (v.length % 2) throw new ErreurDER("BMPString de longueur impaire");
      let s = "";
      for (let i = 0; i < v.length; i += 2) s += String.fromCharCode((v[i] << 8) | v[i + 1]);
      return s;
    }
    default:
      throw new ErreurDER(`type de chaîne 0x${noeud.etiquette.toString(16)} non lu`);
  }
}

// ---------------------------------------------------------------------------
// Temps
// ---------------------------------------------------------------------------

/**
 * Instant exact : `s` secondes UNIX (Number entier) et `frac` chiffres de la
 * fraction de seconde (chaîne, éventuellement vide, sans zéro final).
 */
function instant(s, frac = "") {
  return { s, frac: frac.replace(/0+$/, "") };
}

// Calendrier grégorien proleptique sans Date (algorithmes « days_from_civil »
// et « civil_from_days » de H. Hinnant) : années 0000 à 9999 lues telles
// quelles, sans la correspondance 0..99 → 1900..1999 de Date.UTC, et aucune
// RangeError au-delà de l'intervalle de Date (EX-9.15, EX-6.11).
const JOURS_MOIS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
const bissextile = (a) => (a % 4 === 0 && a % 100 !== 0) || a % 400 === 0;
function joursDepuisCivil(an, mois, jour) {
  const a = mois <= 2 ? an - 1 : an;
  const ere = Math.floor(a / 400);
  const ade = a - ere * 400;
  const jda = Math.floor((153 * (mois + (mois > 2 ? -3 : 9)) + 2) / 5) + jour - 1;
  const jde = ade * 365 + Math.floor(ade / 4) - Math.floor(ade / 100) + jda;
  return ere * 146097 + jde - 719468;
}
function civilDepuisJours(jours) {
  const z = jours + 719468;
  const ere = Math.floor(z / 146097);
  const jde = z - ere * 146097;
  const ade = Math.floor((jde - Math.floor(jde / 1460) + Math.floor(jde / 36524) - Math.floor(jde / 146096)) / 365);
  const jda = jde - (365 * ade + Math.floor(ade / 4) - Math.floor(ade / 100));
  const mp = Math.floor((5 * jda + 2) / 153);
  const jour = jda - Math.floor((153 * mp + 2) / 5) + 1;
  const mois = mp < 10 ? mp + 3 : mp - 9;
  return { an: ade + ere * 400 + (mois <= 2 ? 1 : 0), mois, jour };
}
/** Plus grand instant admis (EX-9.15, règle 2) : 9999-12-31T23:59:59.999999Z. */
export const INSTANT_MAX = instant(joursDepuisCivil(9999, 12, 31) * 86400 + 86399, "999999");
/** Compare deux instants : -1, 0 ou 1. */
export function comparerInstants(a, b) {
  if (a.s !== b.s) return a.s < b.s ? -1 : 1;
  const n = Math.max(a.frac.length, b.frac.length);
  const fa = a.frac.padEnd(n, "0");
  const fb = b.frac.padEnd(n, "0");
  return fa === fb ? 0 : fa < fb ? -1 : 1;
}
/** RFC 3339 UTC, fraction seulement si non nulle, sans zéro final (EX-6.11) ; années 0000 à 9999. */
export function rfc3339(i) {
  const jours = Math.floor(i.s / 86400);
  const reste = i.s - jours * 86400;
  const { an, mois, jour } = civilDepuisJours(jours);
  if (an < 0 || an > 9999) throw new RangeError(`instant hors des années 0000 à 9999 (${i.s} s)`);
  const d2 = (n) => String(n).padStart(2, "0");
  const base = `${String(an).padStart(4, "0")}-${d2(mois)}-${d2(jour)}T${d2(Math.floor(reste / 3600))}:${d2(Math.floor((reste % 3600) / 60))}:${d2(reste % 60)}`;
  return i.frac ? `${base}.${i.frac}Z` : `${base}Z`;
}
/** Instant d'un horodatage CT-1 (AAAA-MM-JJThh:mm:ss.mmmZ) ou RFC 3339 UTC. */
export function instantDepuisRfc3339(texte) {
  const m = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?Z$/.exec(texte ?? "");
  if (!m) return null;
  const s = secondesUTC(+m[1], +m[2], +m[3], +m[4], +m[5], +m[6]);
  return s === null ? null : instant(s, m[7] ?? "");
}
function secondesUTC(an, mois, jour, h, mi, se) {
  if (an < 0 || an > 9999 || mois < 1 || mois > 12 || jour < 1 || h > 23 || mi > 59 || se > 59) return null;
  if (jour > (mois === 2 && bissextile(an) ? 29 : JOURS_MOIS[mois - 1])) return null;
  return joursDepuisCivil(an, mois, jour) * 86400 + h * 3600 + mi * 60 + se;
}
/** UTCTime ou GeneralizedTime d'un certificat ou d'une CRL (RFC 5280 §4.1.2.5). */
function tempsCertificat(noeud, quoi) {
  const t = noeud?.valeur().toString("latin1");
  let m;
  if (noeud?.etiquette === 0x17 && (m = /^([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z$/.exec(t))) {
    const aa = +m[1];
    const s = secondesUTC(aa < 50 ? 2000 + aa : 1900 + aa, +m[2], +m[3], +m[4], +m[5], +m[6]);
    if (s !== null) return instant(s);
  } else if (noeud?.etiquette === 0x18 && (m = /^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z$/.exec(t))) {
    const s = secondesUTC(+m[1], +m[2], +m[3], +m[4], +m[5], +m[6]);
    if (s !== null) return instant(s);
  }
  throw new ErreurDER(`${quoi} : temps illisible`);
}
/**
 * genTime de TSTInfo (EX-9.15, règle 1) : AAAAMMJJhhmmss[.f…]Z, fraction sans
 * zéro final, date existante. Rend l'instant ou null.
 */
export function lireGenTime(texte) {
  const m = /^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(?:\.([0-9]*[1-9]))?Z$/.exec(texte);
  if (!m) return null;
  const s = secondesUTC(+m[1], +m[2], +m[3], +m[4], +m[5], +m[6]);
  return s === null ? null : instant(s, m[7] ?? "");
}
/** Ajoute une précision {seconds, millis, micros} (sous-champs absents : zéro) à un instant. */
function ajouterPrecision(i, acc) {
  const n = Math.max(i.frac.length, 6);
  const echelle = 10n ** BigInt(n);
  const total = BigInt(i.s) * echelle + BigInt(i.frac.padEnd(n, "0") || "0") + BigInt(acc.seconds ?? 0) * echelle + BigInt(acc.millis ?? 0) * 10n ** BigInt(n - 3) + BigInt(acc.micros ?? 0) * 10n ** BigInt(n - 6);
  return instant(Number(total / echelle), (total % echelle).toString().padStart(n, "0"));
}

// ---------------------------------------------------------------------------
// Algorithmes
// ---------------------------------------------------------------------------

/** AlgorithmIdentifier : { oid, params (nœud ou null) }. */
function algorithme(noeud, quoi) {
  const e = sequence(noeud, quoi);
  if (e.length < 1 || e.length > 2) throw new ErreurDER(`${quoi} : AlgorithmIdentifier mal formé`);
  return { oid: oid(e[0], quoi), params: e[1] ?? null };
}
const paramsNulOuAbsents = (alg) => alg.params === null || (alg.params.etiquette === 0x05 && alg.params.longueur === 0);

/** Fonction d'empreinte d'un AlgorithmIdentifier : nom node ou null. */
function fonctionEmpreinte(alg) {
  return NOM_EMPREINTE[alg.oid] ?? null;
}

/**
 * Règle T-5 pour un algorithme de signature, avec la fonction d'empreinte
 * exigée (`empreinte`, pour SignerInfo) ou libre (signature de certificat ou de
 * CRL). Rend { verdict: "admis", nom, hash, schema, saltLength } ou
 * { verdict: "refuse" | "hors_perimetre", motif }.
 */
function regleSignature(alg, empreinte = null) {
  const exigerHash = (h) => (empreinte !== null && h !== empreinte ? { verdict: "refuse", motif: T(`fonction ${h} différente de digestAlgorithm (${empreinte})`, `hash ${h} differs from digestAlgorithm (${empreinte})`) } : null);
  switch (alg.oid) {
    case OID.rsaEncryption:
      if (empreinte === null) return { verdict: "refuse", motif: T("rsaEncryption sans fonction d'empreinte", "rsaEncryption without a hash function") };
      if (!paramsNulOuAbsents(alg)) return { verdict: "refuse", motif: T("paramètres de rsaEncryption non nuls", "rsaEncryption parameters not NULL") };
      return { verdict: "admis", nom: "rsaEncryption", hash: empreinte, schema: "rsa" };
    case OID.sha256WithRSAEncryption:
    case OID.sha384WithRSAEncryption:
    case OID.sha512WithRSAEncryption: {
      const h = { [OID.sha256WithRSAEncryption]: "sha256", [OID.sha384WithRSAEncryption]: "sha384", [OID.sha512WithRSAEncryption]: "sha512" }[alg.oid];
      if (!paramsNulOuAbsents(alg)) return { verdict: "refuse", motif: T(`paramètres de ${NOM_SIGNATURE[alg.oid]} non nuls`, `${NOM_SIGNATURE[alg.oid]} parameters not NULL`) };
      return exigerHash(h) ?? { verdict: "admis", nom: NOM_SIGNATURE[alg.oid], hash: h, schema: "rsa" };
    }
    case OID.ecdsaWithSHA256:
    case OID.ecdsaWithSHA384:
    case OID.ecdsaWithSHA512: {
      const h = { [OID.ecdsaWithSHA256]: "sha256", [OID.ecdsaWithSHA384]: "sha384", [OID.ecdsaWithSHA512]: "sha512" }[alg.oid];
      if (alg.params !== null) return { verdict: "refuse", motif: T(`paramètres de ${NOM_SIGNATURE[alg.oid]} présents`, `${NOM_SIGNATURE[alg.oid]} parameters present`) };
      return exigerHash(h) ?? { verdict: "admis", nom: NOM_SIGNATURE[alg.oid], hash: h, schema: "ecdsa" };
    }
    case OID.rsassaPss:
      return reglePss(alg, empreinte);
    case OID.sha1WithRSAEncryption:
    case OID.md5WithRSAEncryption:
    case OID.ecdsaWithSHA1:
      return { verdict: "refuse", motif: T(`signature sur SHA-1 ou MD5 (${alg.oid})`, `signature over SHA-1 or MD5 (${alg.oid})`) };
    default:
      return { verdict: "hors_perimetre", motif: T(`algorithme de signature ${alg.oid} hors de la version 0`, `signature algorithm ${alg.oid} outside version 0`) };
  }
}

/** RSASSA-PSS (RFC 4056 §3) : hashAlgorithm = digestAlgorithm, MGF1 de même fonction, trailerField 1. */
function reglePss(alg, empreinte) {
  const refus = (fr, en) => ({ verdict: "refuse", motif: T(fr, en) });
  if (!alg.params || alg.params.etiquette !== 0x30) return refus("RSASSA-PSS sans paramètres", "RSASSA-PSS without parameters");
  let hash = "sha1";
  let mgfHash = "sha1";
  let saltLength = 20;
  let trailer = 1;
  try {
    for (const p of alg.params.enfants) {
      const [interne] = p.enfants ?? [];
      if (p.etiquette === 0xa0) hash = fonctionEmpreinte(algorithme(interne, "hashAlgorithm")) ?? "inconnue";
      else if (p.etiquette === 0xa1) {
        const mgf = algorithme(interne, "maskGenAlgorithm");
        if (mgf.oid !== OID.mgf1 || !mgf.params) return refus("maskGenAlgorithm autre que MGF1", "maskGenAlgorithm other than MGF1");
        mgfHash = fonctionEmpreinte(algorithme(mgf.params, "MGF1")) ?? "inconnue";
      } else if (p.etiquette === 0xa2) saltLength = petitEntier(interne, "saltLength");
      else if (p.etiquette === 0xa3) trailer = petitEntier(interne, "trailerField");
      else return refus("paramètre RSASSA-PSS inconnu", "unknown RSASSA-PSS parameter");
    }
  } catch (err) {
    if (err instanceof ErreurDER) return refus(`paramètres RSASSA-PSS illisibles : ${err.message}`, `unreadable RSASSA-PSS parameters: ${err.message}`);
    throw err;
  }
  if (!EMPREINTES_ADMISES.has(hash)) return refus(`RSASSA-PSS sur ${hash}`, `RSASSA-PSS over ${hash}`);
  if (empreinte !== null && hash !== empreinte) return refus(`hashAlgorithm de RSASSA-PSS (${hash}) différent de digestAlgorithm (${empreinte})`, `RSASSA-PSS hashAlgorithm (${hash}) differs from digestAlgorithm (${empreinte})`);
  if (mgfHash !== hash) return refus("MGF1 d'une autre fonction que hashAlgorithm", "MGF1 with a hash other than hashAlgorithm");
  if (trailer !== 1) return refus("trailerField différent de 1", "trailerField other than 1");
  if (saltLength < 0) return refus("saltLength négatif", "negative saltLength");
  return { verdict: "admis", nom: "id-RSASSA-PSS", hash, schema: "pss", saltLength };
}

/**
 * Règle T-5 pour une clé publique (SubjectPublicKeyInfo) : RSA ≥ 2048 bits ;
 * ECDSA sur P-256, P-384, P-521. Rend { verdict, cle, type, bits, courbe, motif }.
 */
function regleCle(spkiDer) {
  let cle;
  try {
    cle = crypto.createPublicKey({ key: Buffer.from(spkiDer), format: "der", type: "spki" });
  } catch {
    return { verdict: "hors_perimetre", motif: T("clé publique d'un type non lu", "public key of an unsupported type") };
  }
  const details = cle.asymmetricKeyDetails ?? {};
  if (cle.asymmetricKeyType === "rsa") {
    const bits = details.modulusLength;
    if (bits < 2048) return { verdict: "refuse", cle, type: "rsa", bits, motif: T(`clé RSA de ${bits} bits (< 2048)`, `RSA key of ${bits} bits (< 2048)`) };
    return { verdict: "admis", cle, type: "rsa", bits };
  }
  if (cle.asymmetricKeyType === "ec") {
    const courbe = NOMS_COURBES_NODE[details.namedCurve];
    if (!courbe) return { verdict: "hors_perimetre", cle, type: "ec", motif: T(`courbe ${details.namedCurve} hors de la version 0`, `curve ${details.namedCurve} outside version 0`) };
    const bits = { "P-256": 256, "P-384": 384, "P-521": 521 }[courbe];
    return { verdict: "admis", cle, type: "ec", bits, courbe };
  }
  return { verdict: "hors_perimetre", cle, type: cle.asymmetricKeyType, motif: T(`clé ${cle.asymmetricKeyType} hors de la version 0`, `${cle.asymmetricKeyType} key outside version 0`) };
}

/** Accord entre un schéma de signature admis et le type de la clé. */
const schemaCompatible = (regle, cle) => (regle.schema === "ecdsa" ? cle.type === "ec" : cle.type === "rsa");

/** Vérifie une signature admise sous une clé admise. */
function verifierSignature(regle, cle, donnees, signature) {
  try {
    if (regle.schema === "rsa") {
      if (signature.length !== Math.ceil(cle.bits / 8)) return false;
      return crypto.verify(regle.hash, donnees, cle.cle, signature);
    }
    if (regle.schema === "pss") {
      if (signature.length !== Math.ceil(cle.bits / 8)) return false;
      return crypto.verify(regle.hash, donnees, { key: cle.cle, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: regle.saltLength }, signature);
    }
    if (regle.schema === "ecdsa") return crypto.verify(regle.hash, donnees, { key: cle.cle, dsaEncoding: "der" }, signature);
  } catch {
    return false;
  }
  return false;
}

/**
 * Signature d'un objet signé (certificat, CRL) par une clé : "ok", "invalide",
 * ou "non_admis" (algorithme ou clé hors de T-5).
 */
function signatureObjet(objet, cleEmetteur) {
  const regle = regleSignature(objet.algorithmeSignature);
  if (regle.verdict !== "admis" || cleEmetteur.verdict !== "admis" || !schemaCompatible(regle, cleEmetteur)) return "non_admis";
  if (objet.signatureInutilises !== 0) return "invalide";
  return verifierSignature(regle, cleEmetteur, objet.tbs, objet.signature) ? "ok" : "invalide";
}

// ---------------------------------------------------------------------------
// Certificats X.509 et CRL
// ---------------------------------------------------------------------------

/** Extensions [3] d'un certificat ou d'une CRL : [{ oid, critique, valeur }]. */
function lireExtensions(noeudSeq, quoi) {
  const out = [];
  const vus = new Set();
  for (const ext of sequence(noeudSeq, quoi)) {
    const e = sequence(ext, `${quoi} : extension`);
    if (e.length < 2 || e.length > 3) throw new ErreurDER(`${quoi} : extension mal formée`);
    const id = oid(e[0], `${quoi} : extnID`);
    let critique = false;
    if (e.length === 3) {
      critique = booleen(e[1], `${quoi} : critical`);
      // Valeur DEFAULT encodée (X.690 §11.5) : tolérée seulement dans TSTInfo (EX-9.5).
      if (!critique) throw new ErreurDER(`${quoi} : critical codé explicitement à FALSE (valeur DEFAULT encodée)`);
    }
    const valeur = octetString(e[e.length - 1], `${quoi} : extnValue`);
    if (vus.has(id)) throw new ErreurDER(`${quoi} : extension ${id} en double`);
    vus.add(id);
    out.push({ oid: id, critique, valeur });
  }
  return out;
}

/**
 * Valeur du premier attribut commonName d'un Name, ou null : absent, ou d'un
 * type de chaîne non lu (UniversalString, VisibleString…). Le nom ne sert qu'au
 * rapport (EX-9.19) : un type non lu ne rend pas le certificat illisible. Les
 * octets invalides d'une UTF8String ou d'une BMPString sont refusés plus tôt,
 * par controlerNom (EX-9.4).
 */
function nomCommun(nameNoeud) {
  try {
    for (const rdn of nameNoeud.enfants ?? []) {
      for (const atv of rdn.enfants ?? []) {
        const [t, v] = atv.enfants ?? [];
        if (t?.etiquette === 0x06 && decoderOID(t.valeur()) === OID.commonName) return v ? chaine(v) : null;
      }
    }
  } catch (err) {
    if (!(err instanceof ErreurDER)) throw err;
  }
  return null;
}
/**
 * Contrôle de forme d'un Name : SEQUENCE OF SET OF SEQUENCE { OID, valeur }.
 * Une valeur UTF8String qui n'est pas de l'UTF-8 valide, ou une BMPString de
 * longueur impaire, rend l'objet illisible (EX-9.4), comme pour OpenSSL et
 * crypto/x509 de Go (parseASN1String) ; les autres types ne sont pas décodés.
 */
function controlerNom(nameNoeud, quoi) {
  for (const rdn of sequence(nameNoeud, quoi)) {
    const atvs = ensemble(rdn, `${quoi} : RDN`);
    if (atvs.length === 0) throw new ErreurDER(`${quoi} : RDN vide`);
    for (const atv of atvs) {
      const e = sequence(atv, `${quoi} : AttributeTypeAndValue`);
      if (e.length !== 2) throw new ErreurDER(`${quoi} : AttributeTypeAndValue mal formé`);
      const type = oid(e[0], `${quoi} : type d'attribut`);
      if (e[1].etiquette === 0x0c || e[1].etiquette === 0x1e) {
        try {
          chaine(e[1]);
        } catch (err) {
          if (!(err instanceof ErreurDER)) throw err;
          throw new ErreurDER(`${quoi} : attribut ${type} : ${err.message}`);
        }
      }
    }
  }
}

/**
 * Lit un certificat X.509 depuis son nœud (déjà lu par le lecteur borné) ou
 * ses octets DER. Rend { der, sha256, tbs, numero (BigInt), emetteur, sujet
 * (octets DER des Name), cn, notBefore, notAfter, spki, cle (règle T-5),
 * extensions, algorithmeSignature, signature, … }.
 */
export function lireCertificat(entree, { quoi = "certificat" } = {}) {
  const noeud = Buffer.isBuffer(entree) || entree instanceof Uint8Array ? lireDER(entree) : entree;
  const [tbsN, algN, sigN, ...reste] = sequence(noeud, quoi);
  if (reste.length || !sigN) throw new ErreurDER(`${quoi} : Certificate mal formé`);
  const tbs = sequence(tbsN, `${quoi} : TBSCertificate`);
  let i = 0;
  let version = 1;
  if (tbs[0]?.etiquette === 0xa0) {
    if (tbs[0].enfants.length !== 1) throw new ErreurDER(`${quoi} : version mal formée`);
    version = petitEntier(tbs[0].enfants[0], `${quoi} : version`) + 1;
    // Valeur DEFAULT encodée (X.690 §11.5) : version v1 explicite (EX-9.21).
    if (version === 1) throw new ErreurDER(`${quoi} : version v1 codée explicitement (valeur DEFAULT encodée)`);
    i = 1;
  }
  if (version < 1 || version > 3) throw new ErreurDER(`${quoi} : version ${version}`);
  const numero = entier(tbs[i++], `${quoi} : serialNumber`);
  const algInterneN = tbs[i++];
  algorithme(algInterneN, `${quoi} : signature`);
  const emetteurN = tbs[i++];
  controlerNom(emetteurN, `${quoi} : issuer`);
  const validite = sequence(tbs[i++], `${quoi} : validity`);
  if (validite.length !== 2) throw new ErreurDER(`${quoi} : validity mal formée`);
  const notBefore = tempsCertificat(validite[0], `${quoi} : notBefore`);
  const notAfter = tempsCertificat(validite[1], `${quoi} : notAfter`);
  const sujetN = tbs[i++];
  controlerNom(sujetN, `${quoi} : subject`);
  const spkiN = attendre(tbs[i++], 0x30, `${quoi} : subjectPublicKeyInfo`);
  let extensions = [];
  while (i < tbs.length) {
    const n = tbs[i++];
    if (n.etiquette === 0x81 || n.etiquette === 0x82) {
      if (version < 2) throw new ErreurDER(`${quoi} : identifiant unique dans un certificat v1`);
      continue;
    }
    if (n.etiquette === 0xa3) {
      if (version !== 3 || n.enfants.length !== 1 || i !== tbs.length) throw new ErreurDER(`${quoi} : extensions mal placées`);
      extensions = lireExtensions(n.enfants[0], `${quoi} : extensions`);
      continue;
    }
    throw new ErreurDER(`${quoi} : élément inattendu dans TBSCertificate`);
  }
  // basicConstraints lu dès la lecture : cA codé explicitement à FALSE est une
  // valeur DEFAULT encodée et rend le certificat illisible (EX-9.21).
  const bcExt = extensions.find((e) => e.oid === OID.basicConstraints);
  if (bcExt) {
    let cAFauxExplicite = false;
    try {
      const e = sequence(lireDER(bcExt.valeur), `${quoi} : basicConstraints`);
      cAFauxExplicite = e[0]?.etiquette === 0x01 && !booleen(e[0], `${quoi} : cA`);
    } catch (err) {
      // Une extension mal formée est jugée par T-7 et T-8, qui la lisent.
      if (!(err instanceof ErreurDER)) throw err;
    }
    if (cAFauxExplicite) throw new ErreurDER(`${quoi} : cA codé explicitement à FALSE (valeur DEFAULT encodée)`);
  }
  const algorithmeSignature = algorithme(algN, `${quoi} : signatureAlgorithm`);
  // Les deux AlgorithmIdentifier doivent être identiques (RFC 5280 §4.1.1.2).
  if (!egalOctets(algN.octets(), algInterneN.octets())) throw new ErreurDER(`${quoi} : signatureAlgorithm différent de TBSCertificate.signature`);
  const sig = bitString(sigN, `${quoi} : signatureValue`);
  const der = Buffer.from(noeud.octets());
  return {
    der,
    sha256: crypto.createHash("sha256").update(der).digest(),
    version,
    tbs: tbsN.octets(),
    numero,
    emetteur: Buffer.from(emetteurN.octets()),
    sujet: Buffer.from(sujetN.octets()),
    cn: nomCommun(sujetN),
    notBefore,
    notAfter,
    spki: Buffer.from(spkiN.octets()),
    cle: regleCle(spkiN.octets()),
    extensions,
    extension: (id) => extensions.find((e) => e.oid === id) ?? null,
    algorithmeSignature,
    signatureInutilises: sig.inutilises,
    signature: Buffer.from(sig.octets),
  };
}

const egalOctets = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

/** basicConstraints : { cA, pathLen } ou null. */
function contraintesDeBase(cert) {
  const ext = cert.extension(OID.basicConstraints);
  if (!ext) return null;
  const e = sequence(lireDER(ext.valeur), "basicConstraints");
  let k = 0;
  let cA = false;
  if (e[k]?.etiquette === 0x01) cA = booleen(e[k++], "cA");
  const pathLen = e[k] ? petitEntier(e[k++], "pathLenConstraint") : null;
  if (k !== e.length) throw new ErreurDER("basicConstraints mal formé");
  return { cA, pathLen, critique: ext.critique };
}
/** keyUsage : ensemble des numéros de bits positionnés, ou null. */
function usagesCle(cert) {
  const ext = cert.extension(OID.keyUsage);
  if (!ext) return null;
  const { octets } = bitString(lireDER(ext.valeur), "keyUsage");
  const bits = new Set();
  for (let i = 0; i < octets.length * 8; i++) if (octets[i >> 3] & (0x80 >> (i & 7))) bits.add(i);
  return bits;
}
/** extKeyUsage : { critique, oids }, ou null. */
function usagesEtendus(cert) {
  const ext = cert.extension(OID.extKeyUsage);
  if (!ext) return null;
  return { critique: ext.critique, oids: sequence(lireDER(ext.valeur), "extKeyUsage").map((n) => oid(n, "KeyPurposeId")) };
}
/** Valeur de subjectKeyIdentifier, ou null. */
function identifiantCleSujet(cert) {
  const ext = cert.extension(OID.subjectKeyIdentifier);
  return ext ? Buffer.from(octetString(lireDER(ext.valeur), "subjectKeyIdentifier")) : null;
}

/**
 * Lit une CRL X.509 (RFC 5280 §5). Rend { der, tbs, emetteur, thisUpdate,
 * nextUpdate, revoques: [{ numero, date, raison }], extensions, … }.
 */
export function lireCRL(entree, { quoi = "CRL" } = {}) {
  const noeud = Buffer.isBuffer(entree) || entree instanceof Uint8Array ? lireDER(entree) : entree;
  const [tbsN, algN, sigN, ...reste] = sequence(noeud, quoi);
  if (reste.length || !sigN) throw new ErreurDER(`${quoi} : CertificateList mal formée`);
  const tbs = sequence(tbsN, `${quoi} : TBSCertList`);
  let i = 0;
  let version = 1;
  if (tbs[0]?.etiquette === 0x02) version = petitEntier(tbs[i++], `${quoi} : version`) + 1;
  const algInterneN = tbs[i++];
  algorithme(algInterneN, `${quoi} : signature`);
  const emetteurN = tbs[i++];
  controlerNom(emetteurN, `${quoi} : issuer`);
  const thisUpdate = tempsCertificat(tbs[i++], `${quoi} : thisUpdate`);
  let nextUpdate = null;
  if (tbs[i] && (tbs[i].etiquette === 0x17 || tbs[i].etiquette === 0x18)) nextUpdate = tempsCertificat(tbs[i++], `${quoi} : nextUpdate`);
  const revoques = [];
  if (tbs[i]?.etiquette === 0x30) {
    for (const r of tbs[i++].enfants) {
      const e = sequence(r, `${quoi} : revokedCertificate`);
      if (e.length < 2 || e.length > 3) throw new ErreurDER(`${quoi} : revokedCertificate mal formé`);
      let raison = null;
      if (e[2]) {
        if (version !== 2) throw new ErreurDER(`${quoi} : extensions d'entrée dans une CRL v1`);
        for (const x of lireExtensions(e[2], `${quoi} : crlEntryExtensions`)) {
          if (x.oid === OID.cRLReasons) {
            const n = attendre(lireDER(x.valeur), 0x0a, "cRLReasons");
            raison = Number(entierDepuis(n.valeur()));
          }
        }
      }
      revoques.push({ numero: entier(e[0], `${quoi} : userCertificate`), date: tempsCertificat(e[1], `${quoi} : revocationDate`), raison });
    }
  }
  let extensions = [];
  if (tbs[i]?.etiquette === 0xa0) {
    if (version !== 2 || tbs[i].enfants.length !== 1) throw new ErreurDER(`${quoi} : crlExtensions mal placées`);
    extensions = lireExtensions(tbs[i++].enfants[0], `${quoi} : crlExtensions`);
  }
  if (i !== tbs.length) throw new ErreurDER(`${quoi} : élément inattendu dans TBSCertList`);
  const algorithmeSignature = algorithme(algN, `${quoi} : signatureAlgorithm`);
  if (!egalOctets(algN.octets(), algInterneN.octets())) throw new ErreurDER(`${quoi} : signatureAlgorithm différent de TBSCertList.signature`);
  const sig = bitString(sigN, `${quoi} : signatureValue`);
  const der = Buffer.from(noeud.octets());
  return {
    der,
    sha256: crypto.createHash("sha256").update(der).digest(),
    version,
    tbs: tbsN.octets(),
    emetteur: Buffer.from(emetteurN.octets()),
    thisUpdate,
    nextUpdate,
    revoques,
    extensions,
    extension: (id) => extensions.find((e) => e.oid === id) ?? null,
    algorithmeSignature,
    signatureInutilises: sig.inutilises,
    signature: Buffer.from(sig.octets),
  };
}

// ---------------------------------------------------------------------------
// PEM et ancres d'horodatage
// ---------------------------------------------------------------------------

/** Octets DER d'un bloc PEM unique d'étiquette donnée ; lève ErreurDER sinon. */
export function decoderPEM(texte, etiquette) {
  const re = new RegExp(`^-----BEGIN ${etiquette}-----\\n((?:[A-Za-z0-9+/=]{1,76}\\n)+)-----END ${etiquette}-----\\n?$`);
  const m = re.exec(texte ?? "");
  if (!m) throw new ErreurDER(`PEM ${etiquette} mal formé`);
  const b64 = m[1].replace(/\n/g, "");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(b64)) throw new ErreurDER(`PEM ${etiquette} : base64 invalide`);
  const der = Buffer.from(b64, "base64");
  if (der.toString("base64") !== b64) throw new ErreurDER(`PEM ${etiquette} : base64 non canonique`);
  return der;
}
/** Bloc PEM (lignes de 64 caractères, saut de ligne final). */
export function encoderPEM(der, etiquette) {
  const b64 = Buffer.from(der).toString("base64");
  return `-----BEGIN ${etiquette}-----\n${b64.match(/.{1,64}/g).join("\n")}\n-----END ${etiquette}-----\n`;
}

/**
 * Prépare les parties « horodatage » d'un fichier d'ancres déjà conforme à son
 * schéma : autorités (certificat et intermédiaires lus), CRL lues, déclarations.
 * Lève ErreurDER si un PEM ne se lit pas (défaut N-1).
 */
export function preparerAncresTsa(ancres) {
  if (!ancres) return null;
  const autorites = (ancres.tsa_authorities ?? []).map((a, k) => ({
    index: k,
    pointeur: `/tsa_authorities/${k}`,
    nom: a.name,
    certificat: lireCertificatAncre(a.certificate, `/tsa_authorities/${k}/certificate`),
    intermediaires: (a.intermediates ?? []).map((p, j) => lireCertificatAncre(p, `/tsa_authorities/${k}/intermediates/${j}`)),
    politiques: a.accepted_policies ?? null,
    qualifie: a.qualified ?? null,
  }));
  const crls = (ancres.revocation?.crls ?? []).map((p, k) => ({ pointeur: `/revocation/crls/${k}`, crl: lireCRL(decoderPEM(p, "X509 CRL"), { quoi: `/revocation/crls/${k}` }) }));
  const declarations = (ancres.revocation?.statements ?? []).map((d, k) => ({ pointeur: `/revocation/statements/${k}`, ...d }));
  return { autorites, crls, declarations };
}
function lireCertificatAncre(pem, pointeur) {
  const c = lireCertificat(decoderPEM(pem, "CERTIFICATE"), { quoi: pointeur });
  if (c.version !== 3) throw new ErreurDER(`${pointeur} : certificat X.509 v${c.version}, v3 attendu`);
  return c;
}

/**
 * Défauts N-1 des parties « horodatage » d'un fichier d'ancres conforme à son
 * schéma (EX-12.2) : PEM illisibles, noms d'autorités en double, dates
 * inexistantes. Rend une liste de messages (vide si conforme).
 */
export function controlerAncresTsa(ancres) {
  const defauts = [];
  try {
    preparerAncresTsa(ancres);
  } catch (err) {
    if (!(err instanceof ErreurDER)) throw err;
    defauts.push(err.message);
  }
  const noms = new Set();
  for (const [k, a] of (ancres?.tsa_authorities ?? []).entries()) {
    if (noms.has(a.name)) defauts.push(`/tsa_authorities/${k}/name : nom d'autorité en double (${a.name})`);
    noms.add(a.name);
    if (a.qualified) {
      for (const champ of ["valid_from", "valid_to"]) {
        const v = a.qualified[champ];
        if (v !== null && !horodatageExiste(v)) defauts.push(`/tsa_authorities/${k}/qualified/${champ} : date inexistante (${v})`);
      }
      const de = instantDepuisRfc3339(a.qualified.valid_from);
      const a2 = a.qualified.valid_to === null ? null : instantDepuisRfc3339(a.qualified.valid_to);
      if (de && a2 && comparerInstants(de, a2) > 0) defauts.push(`/tsa_authorities/${k}/qualified : valid_from postérieur à valid_to`);
    }
  }
  for (const [k, d] of (ancres?.revocation?.statements ?? []).entries()) {
    if (!horodatageExiste(d.not_revoked_at)) defauts.push(`/revocation/statements/${k}/not_revoked_at : date inexistante (${d.not_revoked_at})`);
  }
  return defauts;
}
const horodatageExiste = (v) => {
  const ms = Date.parse(v);
  return !Number.isNaN(ms) && new Date(ms).toISOString() === v;
};

// ---------------------------------------------------------------------------
// TimeStampToken et TSTInfo
// ---------------------------------------------------------------------------

/**
 * Lit un TimeStampToken selon T-1 (EX-9.7). Lève ErreurDER au premier défaut.
 * Rend la structure utile aux vérifications suivantes.
 */
export function lireJeton(octets) {
  const buf = Buffer.from(octets);
  if (buf.length > BORNES.tailleJeton) throw new ErreurDER(`fichier de ${buf.length} octets, au-delà de ${BORNES.tailleJeton}`);
  const racine = lireDER(buf);
  const ci = sequence(racine, "ContentInfo");
  if (ci.length !== 2) throw new ErreurDER("ContentInfo mal formé");
  if (oid(ci[0], "contentType") !== OID.signedData) throw new ErreurDER("contentType différent de id-signedData (une réponse TimeStampResp n'est pas un jeton)");
  const contenu = attendre(ci[1], 0xa0, "content [0]");
  if (contenu.enfants.length !== 1) throw new ErreurDER("content [0] mal formé");
  const sd = sequence(contenu.enfants[0], "SignedData");
  let i = 0;
  const version = petitEntier(sd[i++], "SignedData.version");
  if (version !== 3) throw new ErreurDER(`SignedData.version ${version}, 3 attendue`);
  const algosEmpreinte = ensemble(sd[i++], "digestAlgorithms").map((n) => algorithme(n, "digestAlgorithm"));
  const eci = sequence(sd[i++], "encapContentInfo");
  if (eci.length !== 2) throw new ErreurDER("encapContentInfo sans eContent");
  if (oid(eci[0], "eContentType") !== OID.tstInfo) throw new ErreurDER("eContentType différent de id-ct-TSTInfo");
  const ec = attendre(eci[1], 0xa0, "eContent [0]");
  if (ec.enfants.length !== 1) throw new ErreurDER("eContent [0] mal formé");
  const eContentNoeud = attendre(ec.enfants[0], 0x04, "eContent (OCTET STRING primitive)");
  const eContent = Buffer.from(eContentNoeud.valeur());
  let certificats = [];
  let crls = [];
  if (sd[i]?.etiquette === 0xa0) {
    const elements = sd[i++].enfants;
    if (elements.length > BORNES.certificatsJeton) throw new ErreurDER(`${elements.length} certificats dans le jeton, au plus ${BORNES.certificatsJeton}`);
    certificats = elements.map((n, k) => {
      if (n.etiquette !== 0x30) throw new ErreurDER(`certificates[${k}] n'est pas un Certificate X.509`);
      return lireCertificat(n, { quoi: `certificates[${k}]` });
    });
  }
  if (sd[i]?.etiquette === 0xa1) {
    // CRL du jeton : lues par T-10, qui écarte (AV-T-3) celles qui ne se lisent pas.
    crls = sd[i++].enfants.filter((n) => n.etiquette === 0x30);
  }
  const signerInfos = ensemble(sd[i++], "signerInfos");
  if (i !== sd.length) throw new ErreurDER("élément inattendu dans SignedData");
  if (signerInfos.length !== 1) throw new ErreurDER(`${signerInfos.length} SignerInfo, exactement un attendu`);
  const si = sequence(signerInfos[0], "SignerInfo");
  let j = 0;
  const siVersion = petitEntier(si[j++], "SignerInfo.version");
  const sidN = si[j++];
  let sid;
  if (siVersion === 1 && sidN?.etiquette === 0x30) {
    const ias = sidN.enfants;
    if (ias.length !== 2) throw new ErreurDER("issuerAndSerialNumber mal formé");
    controlerNom(ias[0], "sid.issuer");
    sid = { type: "issuerAndSerialNumber", emetteur: Buffer.from(ias[0].octets()), numero: entier(ias[1], "sid.serialNumber") };
  } else if (siVersion === 3 && sidN?.etiquette === 0x80) {
    sid = { type: "subjectKeyIdentifier", ski: Buffer.from(sidN.valeur()) };
  } else throw new ErreurDER(`SignerInfo version ${siVersion} avec un sid incompatible`);
  const algoEmpreinte = algorithme(si[j++], "SignerInfo.digestAlgorithm");
  const attrsN = attendre(si[j++], 0xa0, "signedAttrs [0]");
  const attributs = attrsN.enfants.map((a, k) => {
    const e = sequence(a, `signedAttrs[${k}]`);
    if (e.length !== 2) throw new ErreurDER(`signedAttrs[${k}] mal formé`);
    return { oid: oid(e[0], `signedAttrs[${k}].attrType`), valeurs: ensemble(e[1], `signedAttrs[${k}].attrValues`) };
  });
  const algoSignature = algorithme(si[j++], "SignerInfo.signatureAlgorithm");
  const signature = Buffer.from(octetString(si[j++], "SignerInfo.signature"));
  if (si[j]?.etiquette === 0xa1) j++;
  if (j !== si.length) throw new ErreurDER("élément inattendu dans SignerInfo");
  // signedAttrs signés sous l'étiquette SET OF (31), octets reçus (EX-9.12).
  const signedAttrsSignes = Buffer.from(attrsN.octets());
  signedAttrsSignes[0] = 0x31;
  const tst = lireTSTInfo(eContent, eContentNoeud.profondeur + 1);
  return { octets: buf, version, algosEmpreinte, eContent, certificats, crls, signerInfo: { version: siVersion, sid, algoEmpreinte, attributs, algoSignature, signature, signedAttrsSignes }, tst };
}

/**
 * Lit TSTInfo (RFC 3161 §2.4.2) dans les octets de eContent. La forme est
 * contrôlée ici (T-1) ; les valeurs (genTime, précision, extensions) le sont
 * par T-9.
 */
export function lireTSTInfo(octets, profondeurInitiale = 0) {
  const racine = lireDER(octets, { profondeurInitiale });
  const e = sequence(racine, "TSTInfo");
  let i = 0;
  const version = petitEntier(e[i++], "TSTInfo.version");
  if (version !== 1) throw new ErreurDER(`TSTInfo.version ${version}, 1 attendue`);
  const politique = oid(e[i++], "TSTInfo.policy");
  const mi = sequence(e[i++], "messageImprint");
  if (mi.length !== 2) throw new ErreurDER("messageImprint mal formé");
  const empreinteAlgo = algorithme(mi[0], "messageImprint.hashAlgorithm");
  const empreinte = Buffer.from(octetString(mi[1], "messageImprint.hashedMessage"));
  const numeroN = attendre(e[i++], 0x02, "TSTInfo.serialNumber");
  const numero = entier(numeroN);
  const genTimeN = attendre(e[i++], 0x18, "TSTInfo.genTime");
  const genTimeTexte = genTimeN.valeur().toString("latin1");
  // Précision lue sans limite de taille (BigInt) ; T-9 la borne (EX-9.15, règle 2).
  let precision = null;
  if (e[i]?.etiquette === 0x30) {
    precision = { seconds: null, millis: null, micros: null };
    for (const p of e[i++].enfants) {
      if (p.etiquette === 0x02 && precision.seconds === null && precision.millis === null && precision.micros === null) precision.seconds = entier(p, "accuracy.seconds");
      else if (p.etiquette === 0x80 && precision.millis === null && precision.micros === null) precision.millis = entier(p, "accuracy.millis", 0x80);
      else if (p.etiquette === 0x81 && precision.micros === null) precision.micros = entier(p, "accuracy.micros", 0x81);
      else throw new ErreurDER("accuracy mal formé");
    }
  }
  let ordre = false;
  if (e[i]?.etiquette === 0x01) {
    ordre = booleen(e[i++], "ordering");
    if (!ordre) throw new ErreurDER("ordering codé explicitement à FALSE (valeur DEFAULT encodée)");
  }
  let nonce = null;
  if (e[i]?.etiquette === 0x02) nonce = entier(e[i++], "nonce");
  let tsa = null;
  if (e[i]?.etiquette === 0xa0) {
    const g = e[i++];
    if (g.enfants.length !== 1) throw new ErreurDER("tsa [0] mal formé");
    tsa = g.enfants[0];
    if (tsa.etiquette === 0xa4) {
      if (tsa.enfants.length !== 1) throw new ErreurDER("tsa directoryName mal formé");
      controlerNom(tsa.enfants[0], "tsa.directoryName");
    }
  }
  let extensions = [];
  if (e[i]?.etiquette === 0xa1) {
    const n = e[i++];
    extensions = n.enfants.map((x, k) => {
      const c = sequence(x, `TSTInfo.extensions[${k}]`);
      if (c.length < 2 || c.length > 3) throw new ErreurDER(`TSTInfo.extensions[${k}] mal formée`);
      const critique = c.length === 3 ? booleen(c[1], "critical") : false;
      return { oid: oid(c[0], "extnID"), critique, explicitFalse: c.length === 3 && !critique, valeur: Buffer.from(octetString(c[c.length - 1], "extnValue")) };
    });
  }
  if (i !== e.length) throw new ErreurDER("élément inattendu dans TSTInfo");
  return {
    version,
    politique,
    empreinteAlgo,
    empreinte,
    numero,
    numeroOctets: Buffer.from(numeroN.valeur()),
    genTimeTexte,
    precision,
    ordre,
    nonce,
    tsa,
    extensions,
  };
}

// ---------------------------------------------------------------------------
// Vérifications T-1 à T-11 (§9.5)
// ---------------------------------------------------------------------------

export const LIBELLES = {
  "T-1": T("structure du jeton", "token structure"),
  "T-2": T("empreinte = periodHash", "imprint = periodHash"),
  "T-3": T("attributs signés", "signed attributes"),
  "T-4": T("certificat signataire identifié", "signer certificate identified"),
  "T-5": T("algorithmes admis", "admitted algorithms"),
  "T-6": T("signature", "signature"),
  "T-7": T("chemin de certification jusqu'à une autorité de l'ancre, à genTime", "certification path to an anchor authority, at genTime"),
  "T-8": T("usage horodatage du certificat signataire", "time-stamping usage of the signer certificate"),
  "T-9": T("contenu de TSTInfo", "TSTInfo content"),
  "T-10": T("révocation", "revocation"),
  "T-11": T("statut qualifié déclaré par l'ancre", "qualified status declared by the anchor"),
};
export const IDS = Object.keys(LIBELLES);

/**
 * Avertissements dans l'ordre de EX-6.15 : vérification qui les lève, dans
 * l'ordre de ses numéros, puis identifiant, puis ordre d'émission (celui de
 * leur objet).
 */
function ordonnerAvertissements(liste) {
  const numero = (id) => Number(/-([0-9]+)$/.exec(id ?? "")?.[1] ?? Infinity);
  return liste
    .map((w, i) => ({ w, i }))
    .sort((a, b) => numero(a.w.check) - numero(b.w.check) || numero(a.w.id) - numero(b.w.id) || a.i - b.i)
    .map((x) => x.w);
}

const RAISONS_ORDRE = ["prerequis_en_echec", "hors_perimetre_version", "partie_absente", "ancre_absente"];
const reussi = (detail) => ({ status: "reussi", reason: null, detail });
const echoue = (detail) => ({ status: "echoue", reason: null, detail });
const nonExecute = (reason, detail) => ({ status: "non_execute", reason, detail });

/**
 * Statut d'une vérification dont les prérequis ne sont pas tous réussis
 * (EX-5.5) : `prerequis_en_echec` si l'un a échoué ou n'a pas été exécuté pour
 * cette raison, sinon la première raison admise dans l'ordre de EX-6.5.
 */
function heriter(prerequis) {
  const manquants = prerequis.filter(([, p]) => p.status !== "reussi").map(([id, p]) => ({ id, raison: p.status === "echoue" ? "prerequis_en_echec" : p.reason, echec: p.status === "echoue" }));
  const r = RAISONS_ORDRE.find((x) => manquants.some((m) => m.raison === x)) ?? "prerequis_en_echec";
  const cause = manquants.find((m) => m.raison === r) ?? manquants[0];
  if (cause.echec) return nonExecute(r, T(`prérequis ${cause.id} en échec`, `prerequisite ${cause.id} failed`));
  return nonExecute(r, T(`prérequis ${cause.id} non exécuté (${cause.raison})`, `prerequisite ${cause.id} not run (${cause.raison})`));
}

const nomCN = (cert) => (cert.cn !== null ? `CN=${cert.cn}` : hex(cert.sha256));

/**
 * Vérifie le jeton de la partie `jeton_rfc3161` (T-1 à T-11) et rend le statut
 * du contrôle 4.
 *
 * Paramètres :
 *   octets      : octets de jeton-rfc3161.der (partie présente) ;
 *   periodHash  : periodHash recalculé depuis manifeste.json (CT-1 §10.2), en
 *                 hexadécimal 0x, ou null s'il n'est pas calculable (P-1 en échec) ;
 *   ancres      : le fichier d'ancres (objet déjà conforme à N-1), ou null ;
 *   tsEvenement : ts de l'événement prouvé (pour AV-T-4), ou null ;
 *   langue      : "fr" (défaut) ou "en", langue des détails et du résumé.
 *
 * Rend { checks: [{ id, controls, status, reason, admitted, detail }],
 *        warnings: [{ id, check, detail }], status, reason, summary,
 *        anchors_used, facts (null sauf contrôle réussi), proposition ({fr, en}
 *        ou null) }.
 */
export function verifierJeton(octets, { periodHash = null, ancres = null, tsEvenement = null, langue = "fr" } = {}) {
  const r = evaluerJeton(octets, { periodHash, ancres, tsEvenement });
  return mettreEnLangue(r, langue);
}

/** Rend les textes bilingues d'un résultat dans une langue ; la proposition reste bilingue. */
export function mettreEnLangue(r, langue) {
  const choisir = (t) => (t === null || t === undefined ? null : typeof t === "string" ? t : t[langue]);
  return {
    checks: r.checks.map((c) => ({ id: c.id, controls: [4], status: c.status, reason: c.reason, admitted: c.status === "non_execute" ? c.reason !== "prerequis_en_echec" : null, detail: choisir(c.detail) })),
    warnings: r.warnings.map((w) => ({ id: w.id, check: w.check, detail: choisir(w.detail) })),
    status: r.status,
    reason: r.reason,
    summary: choisir(r.summary),
    anchors_used: r.anchors_used,
    facts: r.facts,
    proposition: r.proposition,
  };
}

/** Évaluation bilingue (textes { fr, en }). */
export function evaluerJeton(octets, { periodHash = null, ancres = null, tsEvenement = null } = {}) {
  const res = {};
  const avertissements = [];
  const ancresTsa = ancres ? preparerAncresTsa(ancres) : null;

  // T-1 : structure.
  let jeton = null;
  try {
    jeton = lireJeton(octets);
    res["T-1"] = reussi(T("TimeStampToken DER : ContentInfo id-signedData, SignedData version 3, un seul SignerInfo, eContentType id-ct-TSTInfo", "DER TimeStampToken: ContentInfo id-signedData, SignedData version 3, a single SignerInfo, eContentType id-ct-TSTInfo"));
  } catch (err) {
    if (!(err instanceof ErreurDER)) throw err;
    res["T-1"] = echoue(T(`jeton inexploitable : ${err.message}`, `unusable token: ${err.message}`));
  }
  if (jeton) for (const x of jeton.tst.extensions) if (x.explicitFalse) avertissements.push({ id: "AV-T-1", check: "T-1", detail: T(`extension ${x.oid} de TSTInfo : critical codé explicitement à FALSE`, `TSTInfo extension ${x.oid}: critical explicitly encoded as FALSE`) });

  // T-2 : empreinte = periodHash.
  if (res["T-1"].status !== "reussi") res["T-2"] = heriter([["T-1", res["T-1"]]]);
  else if (periodHash === null) res["T-2"] = nonExecute("prerequis_en_echec", T("periodHash non calculable (manifeste.json inexploitable)", "periodHash cannot be computed (manifeste.json unusable)"));
  else {
    const { empreinteAlgo, empreinte } = jeton.tst;
    const attendu = Buffer.from(periodHash.slice(2), "hex");
    if (empreinteAlgo.oid !== OID.sha256 || !paramsNulOuAbsents(empreinteAlgo)) res["T-2"] = echoue(T(`messageImprint : algorithme ${empreinteAlgo.oid}, SHA-256 attendu`, `messageImprint: algorithm ${empreinteAlgo.oid}, SHA-256 expected`));
    else if (!egalOctets(empreinte, attendu)) res["T-2"] = echoue(T(`messageImprint ${hex(empreinte)} différent du periodHash recalculé ${periodHash}`, `messageImprint ${hex(empreinte)} differs from the recomputed periodHash ${periodHash}`));
    else res["T-2"] = reussi(T(`messageImprint SHA-256 égal au periodHash recalculé ${periodHash}`, `SHA-256 messageImprint equal to the recomputed periodHash ${periodHash}`));
  }

  // T-3 : attributs signés.
  let attrs = null;
  if (res["T-1"].status !== "reussi") res["T-3"] = heriter([["T-1", res["T-1"]]]);
  else {
    const si = jeton.signerInfo;
    attrs = {};
    let defaut = null;
    for (const a of si.attributs) {
      if (attrs[a.oid]) defaut ??= T(`attribut ${a.oid} présent deux fois`, `attribute ${a.oid} present twice`);
      if (a.valeurs.length !== 1) defaut ??= T(`attribut ${a.oid} à ${a.valeurs.length} valeurs`, `attribute ${a.oid} with ${a.valeurs.length} values`);
      attrs[a.oid] = a.valeurs[0];
    }
    const fonction = fonctionEmpreinte(si.algoEmpreinte);
    if (!defaut) {
      try {
        if (!attrs[OID.contentType]) defaut = T("attribut content-type absent", "content-type attribute missing");
        else if (oid(attrs[OID.contentType], "content-type") !== OID.tstInfo) defaut = T("content-type différent de id-ct-TSTInfo", "content-type differs from id-ct-TSTInfo");
        else if (!attrs[OID.messageDigest]) defaut = T("attribut message-digest absent", "message-digest attribute missing");
        else if (!fonction) defaut = T(`digestAlgorithm ${si.algoEmpreinte.oid} inconnu : empreinte de eContent non calculable`, `unknown digestAlgorithm ${si.algoEmpreinte.oid}: eContent digest cannot be computed`);
        else {
          const md = octetString(attrs[OID.messageDigest], "message-digest");
          const calcule = crypto.createHash(fonction).update(jeton.eContent).digest();
          if (!egalOctets(md, calcule)) defaut = T(`message-digest ${hex(md)} différent de l'empreinte ${LIBELLE_EMPREINTE[fonction]} de eContent ${hex(calcule)}`, `message-digest ${hex(md)} differs from the ${LIBELLE_EMPREINTE[fonction]} digest of eContent ${hex(calcule)}`);
          else if (!attrs[OID.signingCertificate] && !attrs[OID.signingCertificateV2]) defaut = T("ni signingCertificate ni signingCertificateV2", "neither signingCertificate nor signingCertificateV2");
        }
      } catch (err) {
        if (!(err instanceof ErreurDER)) throw err;
        defaut = T(`attribut illisible : ${err.message}`, `unreadable attribute: ${err.message}`);
      }
    }
    if (defaut) res["T-3"] = echoue(defaut);
    else {
      const ess = [attrs[OID.signingCertificate] ? "signingCertificate" : null, attrs[OID.signingCertificateV2] ? "signingCertificateV2" : null].filter(Boolean).join(", ");
      res["T-3"] = reussi(T(`attributs signés : content-type, message-digest égal à l'empreinte de eContent, ${ess}`, `signed attributes: content-type, message-digest equal to the digest of eContent, ${ess}`));
    }
  }

  // T-4 : certificat signataire.
  let S = null;
  const candidats = [];
  if (jeton) {
    const ajouter = (c, origine) => {
      if (!candidats.some((x) => egalOctets(x.cert.der, c.der))) candidats.push({ cert: c, origine });
    };
    jeton.certificats.forEach((c, k) => ajouter(c, `certificates[${k}]`));
    for (const a of ancresTsa?.autorites ?? []) {
      ajouter(a.certificat, `${a.pointeur}/certificate`);
      a.intermediaires.forEach((c, j) => ajouter(c, `${a.pointeur}/intermediates/${j}`));
    }
  }
  if (res["T-1"].status !== "reussi") res["T-4"] = heriter([["T-1", res["T-1"]]]);
  else {
    const sid = jeton.signerInfo.sid;
    const designes = candidats.filter(({ cert }) => (sid.type === "issuerAndSerialNumber" ? egalOctets(cert.emetteur, sid.emetteur) && cert.numero === sid.numero : (() => {
      try {
        const ski = identifiantCleSujet(cert);
        return ski !== null && egalOctets(ski, sid.ski);
      } catch {
        return false;
      }
    })()));
    if (designes.length === 0) res["T-4"] = nonExecute("ancre_absente", T("le certificat que désigne sid n'est ni dans le jeton ni dans le fichier d'ancres", "the certificate designated by sid is neither in the token nor in the anchors file"));
    else if (designes.length > 1) res["T-4"] = echoue(T(`${designes.length} certificats distincts désignés par sid`, `${designes.length} distinct certificates designated by sid`));
    else {
      S = designes[0].cert;
      const defaut = controlerESS(attrs ?? attributsDe(jeton), S);
      if (defaut) {
        res["T-4"] = echoue(defaut);
        S = null;
      } else {
        res["T-4"] = reussi(identificationESS(attrs ?? attributsDe(jeton), S));
        if (hashAlgorithmEssExplicite(attrs ?? attributsDe(jeton))) avertissements.push({ id: "AV-T-1", check: "T-4", detail: T("hashAlgorithm de ESSCertIDv2 codé explicitement à SHA-256 (valeur DEFAULT encodée, tolérée)", "ESSCertIDv2 hashAlgorithm explicitly encoded as SHA-256 (DEFAULT value encoded, tolerated)") });
      }
    }
  }

  // T-5 : algorithmes.
  let regle = null;
  if (res["T-4"].status !== "reussi") res["T-5"] = heriter([["T-4", res["T-4"]]]);
  else {
    const si = jeton.signerInfo;
    const fonction = fonctionEmpreinte(si.algoEmpreinte);
    if (!fonction || !EMPREINTES_ADMISES.has(fonction) || !paramsNulOuAbsents(si.algoEmpreinte)) res["T-5"] = echoue(T(`digestAlgorithm ${fonction ? LIBELLE_EMPREINTE[fonction] : si.algoEmpreinte.oid} refusé`, `digestAlgorithm ${fonction ? LIBELLE_EMPREINTE[fonction] : si.algoEmpreinte.oid} refused`));
    else {
      regle = regleSignature(si.algoSignature, fonction);
      if (regle.verdict === "refuse") res["T-5"] = echoue(regle.motif);
      else if (regle.verdict === "hors_perimetre") res["T-5"] = nonExecute("hors_perimetre_version", regle.motif);
      else if (S.cle.verdict === "refuse") res["T-5"] = echoue(S.cle.motif);
      else if (S.cle.verdict === "hors_perimetre") res["T-5"] = nonExecute("hors_perimetre_version", S.cle.motif);
      else if (!schemaCompatible(regle, S.cle)) res["T-5"] = echoue(T(`signature ${regle.nom} incompatible avec une clé ${S.cle.type}`, `${regle.nom} signature incompatible with a ${S.cle.type} key`));
      else {
        const cleTexte = S.cle.type === "rsa" ? `RSA ${S.cle.bits} bits` : `ECDSA ${S.cle.courbe}`;
        res["T-5"] = reussi(T(`algorithmes admis : ${LIBELLE_EMPREINTE[fonction]}, ${regle.nom}, ${cleTexte}`, `admitted algorithms: ${LIBELLE_EMPREINTE[fonction]}, ${regle.nom}, ${cleTexte}`));
      }
    }
    if (res["T-5"].status !== "reussi") regle = null;
  }

  // T-6 : signature.
  if (res["T-5"].status !== "reussi") res["T-6"] = heriter([["T-5", res["T-5"]]]);
  else if (verifierSignature(regle, S.cle, jeton.signerInfo.signedAttrsSignes, jeton.signerInfo.signature)) res["T-6"] = reussi(T("signature valide sur les attributs signés", "valid signature over the signed attributes"));
  else res["T-6"] = echoue(T("signature invalide sur les attributs signés", "invalid signature over the signed attributes"));

  // T-9 : contenu de TSTInfo (calculé avant T-7, qui en dépend).
  let genTime = null;
  if (res["T-1"].status !== "reussi") res["T-9"] = heriter([["T-1", res["T-1"]]]);
  else {
    const tst = jeton.tst;
    genTime = lireGenTime(tst.genTimeTexte);
    let defaut = null;
    let regle3NonEvaluee = false;
    if (!genTime) defaut = T(`genTime ${tst.genTimeTexte} hors du format AAAAMMJJhhmmss[.f]Z ou date inexistante`, `genTime ${tst.genTimeTexte} not in the YYYYMMDDhhmmss[.f]Z format or nonexistent date`);
    const p = tst.precision;
    if (!defaut && p && ((p.seconds !== null && (p.seconds < 0n || p.seconds > BigInt(BORNES.precisionSecondes))) || (p.millis !== null && (p.millis < 1n || p.millis > 999n)) || (p.micros !== null && (p.micros < 1n || p.micros > 999n)))) defaut = T(`accuracy hors des bornes (seconds de 0 à ${BORNES.precisionSecondes}, millis et micros de 1 à 999)`, `accuracy outside the bounds (seconds from 0 to ${BORNES.precisionSecondes}, millis and micros from 1 to 999)`);
    if (!defaut && p && comparerInstants(ajouterPrecision(genTime, p), INSTANT_MAX) > 0) defaut = T("genTime + accuracy au-delà de 9999-12-31T23:59:59.999999Z", "genTime + accuracy beyond 9999-12-31T23:59:59.999999Z");
    if (!defaut && tst.numero < 0n) defaut = T("serialNumber négatif", "negative serialNumber");
    if (!defaut && tst.numero >= 1n << BigInt(BORNES.bitsNumeroSerie)) defaut = T(`serialNumber de plus de ${BORNES.bitsNumeroSerie} bits`, `serialNumber longer than ${BORNES.bitsNumeroSerie} bits`);
    if (!defaut && tst.tsa) {
      if (tst.tsa.etiquette !== 0xa4) avertissements.push({ id: "AV-T-2", check: "T-9", detail: T("champ tsa sous une autre forme que directoryName : non comparé", "tsa field in another form than directoryName: not compared") });
      else if (!S) regle3NonEvaluee = true;
      else if (!egalOctets(tst.tsa.enfants[0].octets(), S.sujet)) defaut = T("champ tsa différent du sujet du certificat signataire", "tsa field differs from the signer certificate subject");
    }
    const critique = !defaut && tst.extensions.find((x) => x.critique);
    if (critique) defaut = T(`extension critique ${critique.oid} dans TSTInfo`, `critical extension ${critique.oid} in TSTInfo`);
    if (!defaut) {
      const qc = tst.extensions.find((x) => x.oid === OID.qcStatements);
      if (qc) {
        try {
          for (const st of sequence(lireDER(qc.valeur), "qcStatements")) {
            const e = sequence(st, "QCStatement");
            if (e.length < 1 || e.length > 2) throw new ErreurDER("QCStatement mal formé");
            oid(e[0], "statementId");
          }
        } catch (err) {
          if (!(err instanceof ErreurDER)) throw err;
          defaut = T(`qcStatements mal formée : ${err.message}`, `malformed qcStatements: ${err.message}`);
        }
      }
    }
    if (defaut) {
      res["T-9"] = echoue(defaut);
      genTime = null;
    } else if (regle3NonEvaluee) {
      // Règle 3 non évaluable : le certificat signataire n'est pas établi (EX-9.15).
      const h = heriter([["T-4", res["T-4"]]]);
      res["T-9"] = nonExecute(h.reason, T(`champ tsa non comparé : ${h.detail.fr}`, `tsa field not compared: ${h.detail.en}`));
      genTime = null;
    } else {
      if (p) tst.precision = { seconds: p.seconds === null ? null : Number(p.seconds), millis: p.millis === null ? null : Number(p.millis), micros: p.micros === null ? null : Number(p.micros) };
      const prec = p ? precisionTexte(tst.precision) : T("sans précision", "no accuracy");
      res["T-9"] = reussi(T(`TSTInfo version 1, politique ${tst.politique}, genTime ${rfc3339(genTime)}, précision ${prec.fr}, numéro de série ${hexEntier(tst.numero)}`, `TSTInfo version 1, policy ${tst.politique}, genTime ${rfc3339(genTime)}, accuracy ${prec.en}, serial number ${hexEntier(tst.numero)}`));
    }
  }

  // T-7 : chemin à genTime ; exige T-6 (genTime authentifié par la signature, EX-9.13).
  let chemin = null;
  if (res["T-4"].status !== "reussi" || res["T-6"].status !== "reussi" || res["T-9"].status !== "reussi") res["T-7"] = heriter([["T-4", res["T-4"]], ["T-6", res["T-6"]], ["T-9", res["T-9"]]]);
  else if (!ancresTsa || ancresTsa.autorites.length === 0) res["T-7"] = nonExecute("ancre_absente", T(ancresTsa ? "aucune autorité d'horodatage dans le fichier d'ancres" : "aucun fichier d'ancres", ancresTsa ? "no time-stamping authority in the anchors file" : "no anchors file"));
  else {
    chemin = chercherChemin(S, candidats.map((c) => c.cert), ancresTsa.autorites, genTime, jeton.tst.politique);
    if (chemin) {
      const noms = [...chemin.certificats, chemin.autorite.certificat].map(nomCN);
      if (chemin.identite) noms.pop();
      const fr = noms.map((n) => `« ${n} »`).join(" → ");
      const en = noms.map((n) => `"${n}"`).join(" → ");
      res["T-7"] = reussi(T(`chemin ${fr} (${chemin.autorite.pointeur}), valide à genTime ${rfc3339(genTime)}${chemin.autorite.politiques ? `, politique ${jeton.tst.politique} admise par l'ancre` : ""}`, `path ${en} (${chemin.autorite.pointeur}), valid at genTime ${rfc3339(genTime)}${chemin.autorite.politiques ? `, policy ${jeton.tst.politique} admitted by the anchor` : ""}`));
    } else res["T-7"] = echoue(motifEchecChemin(S, candidats.map((c) => c.cert), ancresTsa.autorites, genTime, jeton.tst.politique));
  }

  // T-8 : usage horodatage.
  if (res["T-4"].status !== "reussi") res["T-8"] = heriter([["T-4", res["T-4"]]]);
  else {
    let defaut = null;
    try {
      const eku = usagesEtendus(S);
      const ku = usagesCle(S);
      const bc = contraintesDeBase(S);
      if (!eku) defaut = T("extendedKeyUsage absent", "extendedKeyUsage missing");
      else if (!eku.critique) defaut = T("extendedKeyUsage non critique", "extendedKeyUsage not critical");
      else if (eku.oids.length !== 1 || eku.oids[0] !== OID.idKpTimeStamping) defaut = T(`extendedKeyUsage ${eku.oids.join(", ")} au lieu de id-kp-timeStamping seul`, `extendedKeyUsage ${eku.oids.join(", ")} instead of id-kp-timeStamping alone`);
      else if (ku && (ku.size === 0 || [...ku].some((b) => b > 1))) defaut = T("keyUsage contenant autre chose que digitalSignature et nonRepudiation", "keyUsage containing more than digitalSignature and nonRepudiation");
      else if (bc && bc.cA) defaut = T("basicConstraints avec cA vrai", "basicConstraints with cA true");
    } catch (err) {
      if (!(err instanceof ErreurDER)) throw err;
      defaut = T(`extension illisible : ${err.message}`, `unreadable extension: ${err.message}`);
    }
    res["T-8"] = defaut ? echoue(defaut) : reussi(T("extendedKeyUsage critique réduit à id-kp-timeStamping", "critical extendedKeyUsage reduced to id-kp-timeStamping"));
  }

  // T-10 : révocation.
  let preuvesRevocation = null;
  const ancresEmployees = [];
  if (res["T-7"].status !== "reussi") res["T-10"] = heriter([["T-7", res["T-7"]]]);
  else {
    const r10 = revocation(chemin, ancresTsa, jeton.crls, genTime, avertissements);
    res["T-10"] = r10.resultat;
    preuvesRevocation = r10.preuves;
    ancresEmployees.push(...r10.pointeurs);
  }

  // T-11 : statut qualifié déclaré.
  if (res["T-7"].status !== "reussi") res["T-11"] = heriter([["T-7", res["T-7"]]]);
  else {
    const q = chemin.autorite.qualifie;
    if (!q) res["T-11"] = nonExecute("ancre_absente", T(`l'ancre ${chemin.autorite.pointeur} ne déclare aucun statut qualifié`, `the anchor ${chemin.autorite.pointeur} declares no qualified status`));
    else {
      const de = instantDepuisRfc3339(q.valid_from);
      const a = q.valid_to === null ? null : instantDepuisRfc3339(q.valid_to);
      if (comparerInstants(de, genTime) <= 0 && (a === null || comparerInstants(genTime, a) <= 0)) res["T-11"] = reussi(T(`statut qualifié ${q.framework} déclaré par l'ancre ${chemin.autorite.pointeur} à genTime`, `${q.framework} qualified status declared by the anchor ${chemin.autorite.pointeur} at genTime`));
      else res["T-11"] = nonExecute("ancre_absente", T(`statut qualifié déclaré par l'ancre ${chemin.autorite.pointeur} hors de genTime`, `qualified status declared by the anchor ${chemin.autorite.pointeur} does not cover genTime`));
    }
  }

  // AV-T-4 : ts de l'événement postérieur à genTime + accuracy.
  if (genTime && tsEvenement) {
    const ts = instantDepuisRfc3339(tsEvenement);
    const borne = ajouterPrecision(genTime, jeton.tst.precision ?? {});
    if (ts && comparerInstants(ts, borne) > 0) avertissements.push({ id: "AV-T-4", check: "T-9", detail: T(`ts de l'événement ${tsEvenement} postérieur à genTime + accuracy (${rfc3339(borne)})`, `event ts ${tsEvenement} later than genTime + accuracy (${rfc3339(borne)})`) });
  }

  // Statut du contrôle 4 (EX-9.18) : T-11 n'y entre pas.
  const coeur = IDS.filter((id) => id !== "T-11").map((id) => res[id]);
  let status;
  let reason = null;
  if (coeur.some((c) => c.status === "echoue")) status = "echoue";
  else if (coeur.some((c) => c.status === "non_execute")) {
    status = "non_execute";
    reason = RAISONS_ORDRE.find((x) => coeur.some((c) => c.reason === x));
  } else status = "reussi";

  const anchors_used = chemin ? [chemin.autorite.pointeur, ...ancresEmployees] : [];
  let facts = null;
  let proposition = null;
  let summary;
  if (status === "reussi") {
    const tst = jeton.tst;
    const borne = tst.precision ? ajouterPrecision(genTime, tst.precision) : null;
    const qualifie = res["T-11"].status === "reussi" ? { framework: chemin.autorite.qualifie.framework, source: chemin.autorite.qualifie.source } : null;
    facts = {
      authority: chemin.autorite.nom,
      tsu_certificate_sha256: hex(S.sha256),
      tsu_subject_cn: S.cn,
      gen_time: rfc3339(genTime),
      accuracy: tst.precision ? { seconds: tst.precision.seconds, millis: tst.precision.millis, micros: tst.precision.micros } : null,
      upper_bound: borne ? rfc3339(borne) : null,
      policy: tst.politique,
      serial_number: hexEntier(tst.numero),
      digest_algorithm: fonctionEmpreinte(jeton.signerInfo.algoEmpreinte),
      signature_algorithm: regleSignature(jeton.signerInfo.algoSignature, fonctionEmpreinte(jeton.signerInfo.algoEmpreinte)).nom,
      key_bits: S.cle.bits,
      qualified_claim: revendiqueQualifie(tst),
      qualified: qualifie,
      revocation: preuvesRevocation,
    };
    proposition = propositionEnonce(facts, periodHash);
    const unite = S.cn ?? hex(S.sha256);
    const quand = borne ? T(`au plus tard ${rfc3339(borne)}`, `no later than ${rfc3339(borne)}`) : T(`au plus tard ${rfc3339(genTime)} à la précision de la politique près`, `no later than ${rfc3339(genTime)} within the policy accuracy`);
    const qual = qualifie ? T(`horodatage qualifié ${qualifie.framework === "eidas" ? "eIDAS" : "ZertES"} déclaré par le réviseur`, `${qualifie.framework === "eidas" ? "eIDAS" : "ZertES"} qualified time-stamp declared by the reviewer`) : T("aucun statut qualifié déclaré", "no qualified status declared");
    summary = T(`selon ${chemin.autorite.nom} (unité ${unite}), ${quand.fr} ; ${qual.fr}`, `according to ${chemin.autorite.nom} (unit ${unite}), ${quand.en}; ${qual.en}`);
  } else if (status === "echoue") {
    const ids = IDS.filter((id) => res[id].status === "echoue");
    summary = T(`vérification(s) en échec : ${ids.join(", ")}`, `failed check(s): ${ids.join(", ")}`);
  } else {
    // Le résumé reprend la cause première : une non-exécution qui n'est pas héritée d'un prérequis.
    const candidates = IDS.filter((id) => id !== "T-11" && res[id].status === "non_execute" && res[id].reason === reason);
    const premier = candidates.find((id) => !/^prérequis /.test(res[id].detail.fr)) ?? candidates[0];
    summary = res[premier].detail;
  }

  return {
    checks: IDS.map((id) => ({ id, ...res[id] })),
    warnings: ordonnerAvertissements(avertissements),
    status,
    reason,
    summary,
    anchors_used,
    facts,
    proposition,
  };
}

const hexEntier = (n) => {
  const h = n.toString(16);
  return "0x" + (h.length % 2 ? "0" + h : h);
};
function precisionTexte(p) {
  const fr = [];
  const en = [];
  if (p.seconds !== null) {
    fr.push(`${p.seconds} s`);
    en.push(`${p.seconds} s`);
  }
  if (p.millis !== null) {
    fr.push(`${p.millis} ms`);
    en.push(`${p.millis} ms`);
  }
  if (p.micros !== null) {
    fr.push(`${p.micros} µs`);
    en.push(`${p.micros} µs`);
  }
  return fr.length ? T(fr.join(" "), en.join(" ")) : T("0 s", "0 s");
}
function attributsDe(jeton) {
  const a = {};
  for (const x of jeton.signerInfo.attributs) a[x.oid] ??= x.valeurs[0];
  return a;
}
function revendiqueQualifie(tst) {
  const qc = tst.extensions.find((x) => x.oid === OID.qcStatements);
  if (!qc) return false;
  try {
    return sequence(lireDER(qc.valeur), "qcStatements").some((st) => oid(st.enfants[0]) === OID.qtstStatement1);
  } catch {
    return false;
  }
}

/** Règles 1 à 3 de T-4 sur les identifiants ESS. Rend un défaut { fr, en } ou null. */
function controlerESS(attrs, S) {
  try {
    if (attrs[OID.signingCertificate]) {
      const sc = sequence(attrs[OID.signingCertificate], "SigningCertificate");
      const premier = sequence(sequence(sc[0], "certs")[0], "ESSCertID");
      const h = octetString(premier[0], "certHash");
      if (!egalOctets(h, crypto.createHash("sha1").update(S.der).digest())) return T("certHash de ESSCertID différent du SHA-1 du certificat signataire", "ESSCertID certHash differs from the SHA-1 of the signer certificate");
      const d = issuerSerial(premier[1], S);
      if (d) return d;
    }
    if (attrs[OID.signingCertificateV2]) {
      const sc = sequence(attrs[OID.signingCertificateV2], "SigningCertificateV2");
      const premier = sequence(sequence(sc[0], "certs")[0], "ESSCertIDv2");
      let k = 0;
      let fonction = "sha256";
      if (premier[0]?.etiquette === 0x30) fonction = fonctionEmpreinte(algorithme(premier[k++], "ESSCertIDv2.hashAlgorithm"));
      if (!fonction || !["sha1", "sha256", "sha384", "sha512"].includes(fonction)) return T("hashAlgorithm de ESSCertIDv2 inconnu", "unknown ESSCertIDv2 hashAlgorithm");
      const h = octetString(premier[k++], "certHash");
      if (!egalOctets(h, crypto.createHash(fonction).update(S.der).digest())) return T(`certHash de ESSCertIDv2 (${hex(h)}) différent de l'empreinte ${LIBELLE_EMPREINTE[fonction]} du certificat signataire (${hex(crypto.createHash(fonction).update(S.der).digest())})`, `ESSCertIDv2 certHash (${hex(h)}) differs from the ${LIBELLE_EMPREINTE[fonction]} digest of the signer certificate (${hex(crypto.createHash(fonction).update(S.der).digest())})`);
      const d = issuerSerial(premier[k], S);
      if (d) return d;
    }
  } catch (err) {
    if (!(err instanceof ErreurDER)) throw err;
    return T(`identifiant ESS illisible : ${err.message}`, `unreadable ESS identifier: ${err.message}`);
  }
  return null;
}
/** Vrai si le premier ESSCertIDv2 encode hashAlgorithm = SHA-256, sa valeur DEFAULT (EX-9.21). */
function hashAlgorithmEssExplicite(attrs) {
  if (!attrs[OID.signingCertificateV2]) return false;
  try {
    const premier = sequence(sequence(sequence(attrs[OID.signingCertificateV2], "SigningCertificateV2")[0], "certs")[0], "ESSCertIDv2");
    return premier[0]?.etiquette === 0x30 && algorithme(premier[0], "ESSCertIDv2.hashAlgorithm").oid === OID.sha256;
  } catch (err) {
    if (!(err instanceof ErreurDER)) throw err;
    return false;
  }
}
function issuerSerial(noeud, S) {
  if (!noeud) return null;
  const e = sequence(noeud, "IssuerSerial");
  if (e.length !== 2) throw new ErreurDER("IssuerSerial mal formé");
  const noms = sequence(e[0], "GeneralNames");
  const trouve = noms.some((g) => g.etiquette === 0xa4 && g.enfants.length === 1 && egalOctets(g.enfants[0].octets(), S.emetteur));
  if (!trouve) return T("issuerSerial : aucun directoryName égal à l'émetteur du certificat signataire", "issuerSerial: no directoryName equal to the signer certificate issuer");
  if (entier(e[1], "IssuerSerial.serialNumber") !== S.numero) return T("issuerSerial : numéro différent de celui du certificat signataire", "issuerSerial: serial number differs from the signer certificate's");
  return null;
}
function identificationESS(attrs, S) {
  if (attrs[OID.signingCertificateV2]) {
    const premier = sequence(sequence(sequence(attrs[OID.signingCertificateV2], "SigningCertificateV2")[0], "certs")[0], "ESSCertIDv2");
    const fonction = premier[0]?.etiquette === 0x30 ? fonctionEmpreinte(algorithme(premier[0], "hashAlgorithm")) : "sha256";
    const h = crypto.createHash(fonction).update(S.der).digest();
    return T(`certificat signataire « ${nomCN(S)} » désigné par ESSCertIDv2 (${LIBELLE_EMPREINTE[fonction]} ${hex(h)})`, `signer certificate "${nomCN(S)}" designated by ESSCertIDv2 (${LIBELLE_EMPREINTE[fonction]} ${hex(h)})`);
  }
  const h = crypto.createHash("sha1").update(S.der).digest();
  return T(`certificat signataire « ${nomCN(S)} » désigné par ESSCertID (SHA-1 ${hex(h)})`, `signer certificate "${nomCN(S)}" designated by ESSCertID (SHA-1 ${hex(h)})`);
}

// ---------------------------------------------------------------------------
// T-7 : chemin de certification à genTime (EX-9.13)
// ---------------------------------------------------------------------------

const EXTENSIONS_CRITIQUES_ADMISES = new Set([OID.basicConstraints, OID.keyUsage, OID.extKeyUsage]);

/** Règles 3 à 6 pour le certificat d'indice i du chemin ; rend un motif ou null. */
function regleCertificatChemin(c, i, genTime) {
  if (comparerInstants(c.notBefore, genTime) > 0) return T(`« ${nomCN(c)} » pas encore valide à genTime (notBefore ${rfc3339(c.notBefore)})`, `"${nomCN(c)}" not yet valid at genTime (notBefore ${rfc3339(c.notBefore)})`);
  if (comparerInstants(genTime, c.notAfter) > 0) return T(`« ${nomCN(c)} » expiré à genTime (notAfter ${rfc3339(c.notAfter)})`, `"${nomCN(c)}" expired at genTime (notAfter ${rfc3339(c.notAfter)})`);
  const inconnue = c.extensions.find((x) => x.critique && !EXTENSIONS_CRITIQUES_ADMISES.has(x.oid));
  if (inconnue) return T(`« ${nomCN(c)} » porte l'extension critique ${inconnue.oid}`, `"${nomCN(c)}" carries the critical extension ${inconnue.oid}`);
  if (i >= 1) {
    let bc;
    let ku;
    try {
      bc = contraintesDeBase(c);
      ku = usagesCle(c);
    } catch {
      return T(`« ${nomCN(c)} » : extension illisible`, `"${nomCN(c)}": unreadable extension`);
    }
    if (!bc || !bc.critique || !bc.cA) return T(`« ${nomCN(c)} » n'est pas une AC (basicConstraints critique, cA vrai)`, `"${nomCN(c)}" is not a CA (critical basicConstraints, cA true)`);
    if (bc.pathLen !== null && bc.pathLen < i - 1) return T(`« ${nomCN(c)} » : pathLenConstraint ${bc.pathLen} insuffisant`, `"${nomCN(c)}": pathLenConstraint ${bc.pathLen} too small`);
    if (ku && !ku.has(5)) return T(`« ${nomCN(c)} » : keyUsage sans keyCertSign`, `"${nomCN(c)}": keyUsage without keyCertSign`);
  }
  return null;
}

/**
 * Cherche un chemin S = c0, …, cn (n ≤ 4) jusqu'à une autorité de l'ancre
 * (EX-9.13). Rend { certificats, autorite, identite } ou null. Choix
 * déterministe (EX-9.13, « Chemin retenu ») : la première autorité, dans
 * l'ordre du fichier, pour laquelle un chemin existe ; pour elle, le chemin le
 * plus court (n = 0 d'abord, l'identité avant la signature de S par A) ; à
 * longueur égale, le premier dans l'ordre des candidats (jeton, puis ancres),
 * comparés de c1 à cn.
 */
function chercherChemin(S, candidats, autorites, genTime, politique) {
  // Une signature de certificat n'est vérifiée qu'une fois par couple (certificat, émetteur) :
  // la recherche reste bornée même avec seize certificats de mêmes noms (§15.2).
  const memo = new Map();
  const signe = (enfant, parent) => {
    const cle = enfant.sha256.toString("hex") + parent.sha256.toString("hex");
    if (!memo.has(cle)) memo.set(cle, signatureObjet(enfant, parent.cle) === "ok");
    return memo.get(cle);
  };
  const valide = new Map();
  const regleOk = (c, i) => {
    const cle = `${c.sha256.toString("hex")}:${i}`;
    if (!valide.has(cle)) valide.set(cle, regleCertificatChemin(c, i, genTime) === null);
    return valide.get(cle);
  };
  for (const A of autorites) {
    if (A.politiques !== null && !A.politiques.includes(politique)) continue;
    if (!regleOk(S, 0)) continue;
    if (egalOctets(S.der, A.certificat.der)) return { certificats: [S], autorite: A, identite: true };
    for (let n = 0; n <= BORNES.cheminMax; n++) {
      const r = etendre([S], n, A, candidats, regleOk, signe);
      if (r) return { certificats: r, autorite: A, identite: false };
    }
  }
  return null;
}
/** Chemin de longueur exacte n (c0 = S déjà placé) se terminant sous A, premier dans l'ordre des candidats. */
function etendre(chemin, n, A, candidats, regleOk, signe) {
  const i = chemin.length - 1;
  const c = chemin[i];
  if (i === n) return egalOctets(c.emetteur, A.certificat.sujet) && signe(c, A.certificat) ? chemin : null;
  for (const suivant of candidats) {
    if (chemin.some((x) => egalOctets(x.der, suivant.der))) continue;
    if (!egalOctets(c.emetteur, suivant.sujet)) continue;
    if (!regleOk(suivant, i + 1)) continue;
    if (!signe(c, suivant)) continue;
    const r = etendre([...chemin, suivant], n, A, candidats, regleOk, signe);
    if (r) return r;
  }
  return null;
}
/** Motif lisible de l'absence de chemin : le défaut du chemin le plus direct. */
function motifEchecChemin(S, candidats, autorites, genTime, politique) {
  const d = regleCertificatChemin(S, 0, genTime);
  if (d) return d;
  if (autorites.every((A) => A.politiques !== null && !A.politiques.includes(politique))) return T(`politique ${politique} admise par aucune autorité de l'ancre`, `policy ${politique} admitted by no anchor authority`);
  return T(`aucun chemin de « ${nomCN(S)} » jusqu'à une autorité du fichier d'ancres`, `no path from "${nomCN(S)}" to an authority of the anchors file`);
}

// ---------------------------------------------------------------------------
// T-10 : révocation (EX-9.16)
// ---------------------------------------------------------------------------

const RAISONS_TOLEREES = new Set([0, 3, 4, 5]);
/** Noms des codes de cRLReasons (RFC 5280 §5.3.1). */
const NOMS_RAISONS = { 0: "unspecified", 1: "keyCompromise", 2: "cACompromise", 3: "affiliationChanged", 4: "superseded", 5: "cessationOfOperation", 6: "certificateHold", 8: "removeFromCRL", 9: "privilegeWithdrawn", 10: "aACompromise" };

function revocation(chemin, ancresTsa, crlsJeton, genTime, avertissements) {
  const certs = chemin.identite ? [] : chemin.certificats;
  const sources = ancresTsa.crls.map((x) => ({ crl: x.crl, pointeur: x.pointeur, origine: T(`CRL de l'ancre (${x.pointeur}`, `anchor CRL (${x.pointeur}`) }));
  crlsJeton.forEach((noeud, k) => {
    try {
      sources.push({ crl: lireCRL(noeud, { quoi: `crls[${k}]` }), pointeur: null, origine: T(`CRL du jeton (crls[${k}]`, `token CRL (crls[${k}]`) });
    } catch (err) {
      if (!(err instanceof ErreurDER)) throw err;
      avertissements.push({ id: "AV-T-3", check: "T-10", detail: T(`CRL du jeton (crls[${k}]) écartée : illisible (${err.message})`, `token CRL (crls[${k}]) discarded: unreadable (${err.message})`) });
    }
  });
  const disqualifie = (entree) => !(entree.raison !== null && RAISONS_TOLEREES.has(entree.raison) && comparerInstants(entree.date, genTime) > 0);
  const texteRaison = (entree) => (entree.raison === null ? T("sans raison", "no reason") : T(`raison ${NOMS_RAISONS[entree.raison] ?? entree.raison}`, `reason ${NOMS_RAISONS[entree.raison] ?? entree.raison}`));
  const preuves = [];
  const pointeurs = [];
  const details = [];
  const ecartees = new Set();
  let echec = null;
  let manque = null;
  for (let i = 0; i < certs.length && !echec; i++) {
    const c = certs[i];
    const cleEmetteur = i + 1 < certs.length ? certs[i + 1].cle : chemin.autorite.certificat.cle;
    let preuve = null;
    for (const src of sources) {
      const crl = src.crl;
      // Une CRL d'un autre émetteur n'est pas consultée et ne lève rien (EX-9.16).
      if (!egalOctets(crl.emetteur, c.emetteur)) continue;
      let motif = null;
      if (crl.extension(OID.deltaCRLIndicator)) motif = "delta";
      else if (crl.extension(OID.issuingDistributionPoint)?.critique) motif = "partielle";
      else if (signatureObjet(crl, cleEmetteur) !== "ok") motif = "signature";
      else if (comparerInstants(crl.thisUpdate, genTime) < 0) motif = "thisUpdate";
      if (motif) {
        const cle = `${src.pointeur ?? src.origine.fr}:${motif}`;
        if (!ecartees.has(cle)) {
          ecartees.add(cle);
          const m = { delta: T("CRL delta", "delta CRL"), partielle: T("CRL partielle", "partial CRL"), signature: T("signature invalide", "invalid signature"), thisUpdate: T("thisUpdate antérieur à genTime", "thisUpdate earlier than genTime") }[motif];
          avertissements.push({ id: "AV-T-3", check: "T-10", detail: T(`${src.origine.fr}) écartée : ${m.fr}`, `${src.origine.en}) discarded: ${m.en}`) });
        }
        continue;
      }
      const entree = crl.revoques.find((r) => r.numero === c.numero);
      if (entree && disqualifie(entree)) {
        const raison = texteRaison(entree);
        echec = T(`${src.origine.fr}) : « ${nomCN(c)} » révoqué le ${rfc3339(entree.date)} (${raison.fr})`, `${src.origine.en}): "${nomCN(c)}" revoked on ${rfc3339(entree.date)} (${raison.en})`);
        break;
      }
      if (!preuve) preuve = { src, crl, entree };
    }
    if (echec) break;
    if (!preuve) {
      const d = ancresTsa.declarations.find((x) => x.certificate_sha256 === hex(c.sha256) && comparerInstants(instantDepuisRfc3339(x.not_revoked_at), genTime) >= 0);
      if (d) {
        preuves.push({ certificate_sha256: hex(c.sha256), evidence: "declaration", issued_at: rfc3339(instantDepuisRfc3339(d.not_revoked_at)) });
        pointeurs.push(d.pointeur);
        details.push(T(`déclaration de l'ancre (${d.pointeur}, ${d.not_revoked_at}) : « ${nomCN(c)} » non révoqué`, `anchor statement (${d.pointeur}, ${d.not_revoked_at}): "${nomCN(c)}" not revoked`));
        continue;
      }
      manque ??= T(`aucune preuve de non-révocation de « ${nomCN(c)} » postérieure à genTime`, `no proof of non-revocation of "${nomCN(c)}" later than genTime`);
      continue;
    }
    preuves.push({ certificate_sha256: hex(c.sha256), evidence: "crl", issued_at: rfc3339(preuve.crl.thisUpdate) });
    if (preuve.src.pointeur && !pointeurs.includes(preuve.src.pointeur)) pointeurs.push(preuve.src.pointeur);
    const qui = i === 0 ? T("certificat de la TSA", "TSA certificate") : T(`« ${nomCN(c)} »`, `"${nomCN(c)}"`);
    const etat = preuve.entree ? T(`révoqué le ${rfc3339(preuve.entree.date)} pour la raison ${NOMS_RAISONS[preuve.entree.raison]}, après genTime`, `revoked on ${rfc3339(preuve.entree.date)} for reason ${NOMS_RAISONS[preuve.entree.raison]}, after genTime`) : T("non révoqué", "not revoked");
    details.push(T(`${preuve.src.origine.fr}, thisUpdate ${rfc3339(preuve.crl.thisUpdate)}, postérieure à genTime) : ${qui.fr} ${etat.fr}`, `${preuve.src.origine.en}, thisUpdate ${rfc3339(preuve.crl.thisUpdate)}, later than genTime): ${qui.en} ${etat.en}`));
  }
  // Certificat de l'autorité A (EX-9.16) : seules les CRL complètes du fichier d'ancres
  // qui le listent comptent, prises sans vérification de signature ; elles ne
  // peuvent que retirer la confiance que le réviseur accorde à son autorité.
  if (!echec) {
    const A = chemin.autorite.certificat;
    for (const x of ancresTsa.crls) {
      const crl = x.crl;
      if (!egalOctets(crl.emetteur, A.emetteur) || crl.extension(OID.deltaCRLIndicator) || crl.extension(OID.issuingDistributionPoint)?.critique) continue;
      const entree = crl.revoques.find((r) => r.numero === A.numero);
      if (!entree) continue;
      if (disqualifie(entree)) {
        const raison = texteRaison(entree);
        echec = T(`CRL de l'ancre (${x.pointeur}) : certificat de l'autorité ${chemin.autorite.pointeur} « ${nomCN(A)} » révoqué le ${rfc3339(entree.date)} (${raison.fr})`, `anchor CRL (${x.pointeur}): certificate of authority ${chemin.autorite.pointeur} "${nomCN(A)}" revoked on ${rfc3339(entree.date)} (${raison.en})`);
        break;
      }
      if (!pointeurs.includes(x.pointeur)) pointeurs.push(x.pointeur);
      details.push(T(`CRL de l'ancre (${x.pointeur}) : certificat de l'autorité révoqué le ${rfc3339(entree.date)} pour la raison ${NOMS_RAISONS[entree.raison]}, après genTime`, `anchor CRL (${x.pointeur}): authority certificate revoked on ${rfc3339(entree.date)} for reason ${NOMS_RAISONS[entree.raison]}, after genTime`));
    }
  }
  if (echec) return { resultat: echoue(echec), preuves: null, pointeurs: [] };
  if (manque) return { resultat: nonExecute("ancre_absente", manque), preuves: null, pointeurs: [] };
  if (certs.length === 0) return { resultat: reussi(joindre([T("chemin réduit au certificat de l'ancre : rien à prouver", "path reduced to the anchor certificate: nothing to prove"), ...details])), preuves, pointeurs };
  return { resultat: reussi(joindre(details)), preuves, pointeurs };
}

// ---------------------------------------------------------------------------
// Proposition de l'énoncé (EX-9.20)
// ---------------------------------------------------------------------------

/** Proposition française et anglaise que le contrôle 4 réussi fournit à l'énoncé. */
export function propositionEnonce(faits, periodHash) {
  const unite = faits.tsu_subject_cn ?? faits.tsu_certificate_sha256;
  const quandFr = faits.upper_bound ? `${faits.upper_bound} UTC` : `${faits.gen_time} UTC, à la précision près de la politique ${faits.policy}, que le jeton n'indique pas`;
  const quandEn = faits.upper_bound ? `${faits.upper_bound} UTC` : `${faits.gen_time} UTC, within the accuracy of policy ${faits.policy}, not stated in the token`;
  let fr = `selon ${faits.authority} (unité ${unite}), le manifeste d'empreinte ${periodHash} existait au plus tard le ${quandFr}`;
  let en = `according to ${faits.authority} (unit ${unite}), the manifest with digest ${periodHash} existed no later than ${quandEn}`;
  if (faits.qualified) {
    const cadre = faits.qualified.framework === "eidas" ? "eIDAS" : "ZertES";
    fr += ` ; horodatage qualifié ${cadre} selon le réviseur (${faits.qualified.source})`;
    en += `; ${cadre} qualified timestamp according to the reviewer (${faits.qualified.source})`;
  }
  return { fr, en };
}
