// Lecteur DER borné du composant d'ancrage (CT-6 §9.3 : EX-9.4, EX-9.5,
// EX-9.21 ; §15.1), écrit depuis le seul texte de la spécification, et petit
// encodeur DER pour la requête `TimeStampReq` d'EX-5.1.
//
// Règles de lecture : longueurs définies sous forme minimale (jamais de forme
// indéfinie), numéros d'étiquette inférieurs à 31, `BOOLEAN` codé `00` ou `ff`,
// profondeur d'imbrication au plus 32, aucun octet après la fin d'une
// structure qui n'en admet pas, `UTF8String` en UTF-8 valide, `BMPString` de
// longueur paire. Toute autre forme lève `ErreurDer` : la structure est
// inexploitable (T-1 pour un jeton, N-1 pour un certificat ou une CRL
// d'ancre, AN-5 pour une requête). Les valeurs `DEFAULT` encodées sont jugées
// par les lecteurs de structures (`x509.mjs`, `reponse.mjs`) qui connaissent
// la valeur par défaut de chaque champ.

/** Profondeur d'imbrication maximale d'une structure DER (CT-6 §15.1). */
export const PROFONDEUR_MAX = 32;

/** Classes d'étiquette. */
export const CLASSE = Object.freeze({ UNIVERSEL: 0, APPLICATION: 1, CONTEXTE: 2, PRIVE: 3 });

/** Numéros d'étiquette universels employés. */
export const ETIQUETTE = Object.freeze({
  BOOLEAN: 1,
  INTEGER: 2,
  BIT_STRING: 3,
  OCTET_STRING: 4,
  NULL: 5,
  OID: 6,
  ENUMERATED: 10,
  UTF8_STRING: 12,
  SEQUENCE: 16,
  SET: 17,
  NUMERIC_STRING: 18,
  PRINTABLE_STRING: 19,
  TELETEX_STRING: 20,
  IA5_STRING: 22,
  UTC_TIME: 23,
  GENERALIZED_TIME: 24,
  UNIVERSAL_STRING: 28,
  BMP_STRING: 30,
});

/** Défaillance de lecture DER : la structure est inexploitable. */
export class ErreurDer extends Error {
  constructor(message, position) {
    super(position === undefined ? message : `${message} (octet ${position})`);
    this.name = "ErreurDer";
    this.position = position;
  }
}

const decodeurUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Lit un TLV à la position `pos`, à la profondeur `profondeur` (la racine est
 * à 1). `finMax` borne la fin admise (fin du conteneur).
 * @returns {{classe:number, construit:boolean, numero:number, debut:number, debutContenu:number,
 *   longueur:number, fin:number, contenu:Uint8Array, tlv:Uint8Array, profondeur:number}}
 */
export function lireTlv(octets, pos, profondeur = 1, finMax = octets.length) {
  if (profondeur > PROFONDEUR_MAX) throw new ErreurDer(`profondeur d'imbrication supérieure à ${PROFONDEUR_MAX}`, pos);
  if (pos + 2 > finMax) throw new ErreurDer("structure tronquée", pos);
  const t = octets[pos];
  const classe = t >> 6;
  const construit = (t & 0x20) !== 0;
  const numero = t & 0x1f;
  if (numero === 0x1f) throw new ErreurDer("numéro d'étiquette supérieur ou égal à 31", pos);
  if (t === 0x00 || t === 0x20) throw new ErreurDer("étiquette universelle 0 (fin de contenu) hors d'un encodage indéfini", pos);
  let p = pos + 1;
  const l0 = octets[p++];
  let longueur;
  if (l0 < 0x80) {
    longueur = l0;
  } else {
    const n = l0 & 0x7f;
    if (n === 0) throw new ErreurDer("longueur indéfinie", pos);
    if (n > 4) throw new ErreurDer("longueur sur plus de quatre octets", pos);
    if (p + n > finMax) throw new ErreurDer("longueur tronquée", pos);
    if (octets[p] === 0) throw new ErreurDer("longueur non minimale (octet de tête nul)", pos);
    longueur = 0;
    for (let i = 0; i < n; i++) longueur = longueur * 256 + octets[p + i];
    if (longueur < 0x80) throw new ErreurDer("longueur non minimale (forme longue pour une valeur courte)", pos);
    p += n;
  }
  const fin = p + longueur;
  if (fin > finMax) throw new ErreurDer("contenu tronqué", pos);
  return {
    classe,
    construit,
    numero,
    debut: pos,
    debutContenu: p,
    longueur,
    fin,
    contenu: octets.subarray(p, fin),
    tlv: octets.subarray(pos, fin),
    profondeur,
  };
}

/** Lit la suite des TLV qui remplissent exactement `octets` (contenu d'un constructeur). */
export function lireSuite(octets, profondeur) {
  const elements = [];
  let pos = 0;
  while (pos < octets.length) {
    const e = lireTlv(octets, pos, profondeur);
    elements.push(e);
    pos = e.fin;
  }
  return elements;
}

/** Lit le TLV unique que `octets` contient, sans octet en trop. */
export function lireUnique(octets, profondeur = 1) {
  const e = lireTlv(octets, 0, profondeur);
  if (e.fin !== octets.length) throw new ErreurDer("octets après la fin de la structure", e.fin);
  return e;
}

/** Types universels qui sont toujours construits (DER) ; les autres types universels employés sont toujours primitifs. */
const UNIVERSELS_CONSTRUITS = new Set([ETIQUETTE.SEQUENCE, ETIQUETTE.SET]);
const UNIVERSELS_PRIMITIFS = new Set([
  ETIQUETTE.BOOLEAN, ETIQUETTE.INTEGER, ETIQUETTE.BIT_STRING, ETIQUETTE.OCTET_STRING, ETIQUETTE.NULL, ETIQUETTE.OID, ETIQUETTE.ENUMERATED,
  ETIQUETTE.UTF8_STRING, ETIQUETTE.NUMERIC_STRING, ETIQUETTE.PRINTABLE_STRING, ETIQUETTE.TELETEX_STRING, ETIQUETTE.IA5_STRING,
  ETIQUETTE.UTC_TIME, ETIQUETTE.GENERALIZED_TIME, ETIQUETTE.UNIVERSAL_STRING, ETIQUETTE.BMP_STRING,
]);

/**
 * Parcourt un TLV et tout ce qu'il contient (lecture bornée, profondeur
 * comprise) sans en interpréter les valeurs : chaque constructeur est
 * découpé en ses éléments, les étiquettes universelles doivent avoir la forme
 * (construite ou primitive) que le DER leur impose. Lève `ErreurDer` à la
 * première défaillance ; sert aux valeurs d'attribut `ANY` d'un jeton (T-1,
 * CT-6 EX-9.7 : « toute défaillance de lecture selon 9.3 », correction R-A-2).
 */
export function parcourir(tlv) {
  if (tlv.classe === CLASSE.UNIVERSEL) {
    if (UNIVERSELS_CONSTRUITS.has(tlv.numero) && !tlv.construit) throw new ErreurDer(`type universel ${tlv.numero} de forme primitive`, tlv.debut);
    if (UNIVERSELS_PRIMITIFS.has(tlv.numero) && tlv.construit) throw new ErreurDer(`type universel ${tlv.numero} de forme construite`, tlv.debut);
    if (tlv.numero === ETIQUETTE.BOOLEAN && (tlv.longueur !== 1 || (tlv.contenu[0] !== 0x00 && tlv.contenu[0] !== 0xff))) throw new ErreurDer("BOOLEAN hors de 00 ou ff", tlv.debut);
    if (tlv.numero === ETIQUETTE.NULL && tlv.longueur !== 0) throw new ErreurDer("NULL de longueur non nulle", tlv.debut);
  }
  if (tlv.construit) for (const e of enfants(tlv)) parcourir(e);
}

/** Les éléments d'un constructeur (profondeur + 1). */
export function enfants(tlv) {
  if (!tlv.construit) throw new ErreurDer("constructeur attendu", tlv.debut);
  return lireSuite(tlv.contenu, tlv.profondeur + 1).map((e) => decaler(e, tlv.debutContenu));
}

/** Décale les positions d'un élément lu dans un sous-tableau pour les rapporter au tableau d'origine. */
function decaler(e, base) {
  return { ...e, debut: e.debut + base, debutContenu: e.debutContenu + base, fin: e.fin + base };
}

/** Vrai si l'élément porte la classe et le numéro donnés. */
export function est(tlv, classe, numero, construit) {
  return tlv.classe === classe && tlv.numero === numero && (construit === undefined || tlv.construit === construit);
}

/** Élément universel de ce numéro, construit ou non. */
export function estUniversel(tlv, numero, construit) {
  return est(tlv, CLASSE.UNIVERSEL, numero, construit);
}

/** Élément de contexte [n]. */
export function estContexte(tlv, numero, construit) {
  return est(tlv, CLASSE.CONTEXTE, numero, construit);
}

/** Exige un élément universel de ce numéro. */
export function attendre(tlv, numero, construit, quoi) {
  if (!estUniversel(tlv, numero, construit)) throw new ErreurDer(`${quoi ?? "élément"} attendu`, tlv.debut);
  return tlv;
}

/** Exige un élément de contexte [n]. */
export function attendreContexte(tlv, numero, construit, quoi) {
  if (!estContexte(tlv, numero, construit)) throw new ErreurDer(`${quoi ?? `[${numero}]`} attendu`, tlv.debut);
  return tlv;
}

/** `BOOLEAN` : `00` ou `ff` seulement. */
export function lireBooleen(tlv) {
  attendre(tlv, ETIQUETTE.BOOLEAN, false, "BOOLEAN");
  if (tlv.longueur !== 1) throw new ErreurDer("BOOLEAN d'une longueur autre que 1", tlv.debut);
  const v = tlv.contenu[0];
  if (v === 0x00) return false;
  if (v === 0xff) return true;
  throw new ErreurDer("BOOLEAN codé autrement que 00 ou ff", tlv.debut);
}

/**
 * `INTEGER` en complément à deux, rendu en `bigint`. `minimal` exige la forme
 * minimale (aucun octet de tête superflu), que seule la relecture d'une
 * requête contrôle (AN-5) : CT-6 EX-9.6 ne la contrôle pas en version 0.
 */
export function lireEntier(tlv, { minimal = false, numero = ETIQUETTE.INTEGER } = {}) {
  attendre(tlv, numero, false, numero === ETIQUETTE.ENUMERATED ? "ENUMERATED" : "INTEGER");
  const c = tlv.contenu;
  if (c.length === 0) throw new ErreurDer("INTEGER vide", tlv.debut);
  if (minimal && c.length > 1) {
    if (c[0] === 0x00 && (c[1] & 0x80) === 0) throw new ErreurDer("INTEGER non minimal (zéro de tête superflu)", tlv.debut);
    if (c[0] === 0xff && (c[1] & 0x80) !== 0) throw new ErreurDer("INTEGER non minimal (ff de tête superflu)", tlv.debut);
  }
  let v = 0n;
  for (const o of c) v = (v << 8n) | BigInt(o);
  if (c[0] & 0x80) v -= 1n << BigInt(8 * c.length);
  return v;
}

/** Octets de valeur d'un `INTEGER` non négatif, privés de leurs zéros de tête (pour comparer des numéros de série). */
export function entierOctetsNormalises(tlv) {
  attendre(tlv, ETIQUETTE.INTEGER, false, "INTEGER");
  let c = tlv.contenu;
  if (c.length === 0) throw new ErreurDer("INTEGER vide", tlv.debut);
  let i = 0;
  while (i < c.length - 1 && c[i] === 0) i++;
  return c.subarray(i);
}

/** `OBJECT IDENTIFIER` en notation pointée ; sous-identifiants en forme minimale. */
export function lireOid(tlv) {
  attendre(tlv, ETIQUETTE.OID, false, "OBJECT IDENTIFIER");
  return oidVersTexte(tlv.contenu, tlv.debut);
}

/** Décode les octets de valeur d'un OID. */
export function oidVersTexte(c, position) {
  if (c.length === 0) throw new ErreurDer("OID vide", position);
  if ((c[c.length - 1] & 0x80) !== 0) throw new ErreurDer("OID tronqué", position);
  const sous = [];
  let v = 0n;
  let debut = true;
  for (const o of c) {
    if (debut && o === 0x80) throw new ErreurDer("sous-identifiant d'OID non minimal", position);
    debut = false;
    v = (v << 7n) | BigInt(o & 0x7f);
    if ((o & 0x80) === 0) {
      sous.push(v);
      v = 0n;
      debut = true;
    }
  }
  const premier = sous[0];
  let texte;
  if (premier < 40n) texte = `0.${premier}`;
  else if (premier < 80n) texte = `1.${premier - 40n}`;
  else texte = `2.${premier - 80n}`;
  for (let i = 1; i < sous.length; i++) texte += `.${sous[i]}`;
  return texte;
}

/** `NULL` : contenu vide. */
export function lireNull(tlv) {
  attendre(tlv, ETIQUETTE.NULL, false, "NULL");
  if (tlv.longueur !== 0) throw new ErreurDer("NULL non vide", tlv.debut);
  return null;
}

/** `OCTET STRING` primitive. */
export function lireOctets(tlv) {
  attendre(tlv, ETIQUETTE.OCTET_STRING, false, "OCTET STRING primitive");
  return tlv.contenu;
}

/** `BIT STRING` primitive : `{ bitsInutilises, octets }`. */
export function lireBits(tlv) {
  attendre(tlv, ETIQUETTE.BIT_STRING, false, "BIT STRING primitive");
  if (tlv.longueur === 0) throw new ErreurDer("BIT STRING vide", tlv.debut);
  const inutilises = tlv.contenu[0];
  if (inutilises > 7) throw new ErreurDer("BIT STRING : plus de sept bits inutilisés", tlv.debut);
  if (tlv.longueur === 1 && inutilises !== 0) throw new ErreurDer("BIT STRING vide avec des bits inutilisés", tlv.debut);
  return { bitsInutilises: inutilises, octets: tlv.contenu.subarray(1) };
}

/** Vrai si le bit `i` (numérotation X.509, bit 0 = bit de poids fort du premier octet) est levé. */
export function bitLeve(bits, i) {
  const o = bits.octets[Math.floor(i / 8)];
  if (o === undefined) return false;
  return (o & (0x80 >> i % 8)) !== 0;
}

/** Numéros d'étiquette des types de chaîne d'un `DirectoryString` et assimilés. */
export const CHAINES = Object.freeze({
  [ETIQUETTE.UTF8_STRING]: "UTF8String",
  [ETIQUETTE.PRINTABLE_STRING]: "PrintableString",
  [ETIQUETTE.IA5_STRING]: "IA5String",
  [ETIQUETTE.TELETEX_STRING]: "TeletexString",
  [ETIQUETTE.NUMERIC_STRING]: "NumericString",
  [ETIQUETTE.BMP_STRING]: "BMPString",
  [ETIQUETTE.UNIVERSAL_STRING]: "UniversalString",
});

/**
 * Lit une valeur de chaîne : `UTF8String` en UTF-8 valide, `BMPString` de
 * longueur paire (CT-6 EX-9.4), les autres types décodés quand c'est possible.
 * Rend `{ type, texte }`, `texte` nul pour un type non décodé.
 */
export function lireChaine(tlv) {
  if (tlv.classe !== CLASSE.UNIVERSEL || tlv.construit) throw new ErreurDer("chaîne primitive attendue", tlv.debut);
  const type = CHAINES[tlv.numero];
  if (!type) throw new ErreurDer("type de chaîne inattendu", tlv.debut);
  const c = tlv.contenu;
  switch (tlv.numero) {
    case ETIQUETTE.UTF8_STRING:
      try {
        return { type, texte: decodeurUtf8.decode(c) };
      } catch {
        throw new ErreurDer("UTF8String dont les octets ne sont pas de l'UTF-8 valide", tlv.debut);
      }
    case ETIQUETTE.BMP_STRING: {
      if (c.length % 2 !== 0) throw new ErreurDer("BMPString de longueur impaire", tlv.debut);
      let s = "";
      for (let i = 0; i < c.length; i += 2) s += String.fromCharCode((c[i] << 8) | c[i + 1]);
      return { type, texte: s };
    }
    case ETIQUETTE.PRINTABLE_STRING:
    case ETIQUETTE.IA5_STRING:
    case ETIQUETTE.NUMERIC_STRING:
    case ETIQUETTE.TELETEX_STRING: {
      let s = "";
      for (const o of c) s += String.fromCharCode(o);
      return { type, texte: s };
    }
    default:
      return { type, texte: null };
  }
}

const JOURS_MOIS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/** Date existante du calendrier grégorien proleptique. */
export function dateExiste(annee, mois, jour) {
  if (mois < 1 || mois > 12 || jour < 1) return false;
  let max = JOURS_MOIS[mois - 1];
  if (mois === 2 && ((annee % 4 === 0 && annee % 100 !== 0) || annee % 400 === 0)) max = 29;
  return jour <= max;
}

/** Millisecondes UTC d'une date-heure (années 0000 à 9999, proleptique). */
export function instantUtc(annee, mois, jour, h, m, s, ms = 0) {
  const d = new Date(0);
  d.setUTCFullYear(annee, mois - 1, jour);
  d.setUTCHours(h, m, s, ms);
  return d.getTime();
}

/**
 * `GeneralizedTime` `AAAAMMJJhhmmss[.f…]Z` (CT-6 EX-9.15, règle 1) : fraction
 * sans zéro final, date existante. Rend `{ texte, ms, fraction }` (`fraction`
 * en chaîne de chiffres, vide sans fraction) ; `null` si la forme ne tient pas.
 */
export function lireGeneralizedTime(tlv) {
  attendre(tlv, ETIQUETTE.GENERALIZED_TIME, false, "GeneralizedTime");
  let texte = "";
  for (const o of tlv.contenu) texte += String.fromCharCode(o);
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(texte);
  if (!m) return { texte, ms: null, fraction: "" };
  const fraction = m[7] ?? "";
  if (fraction !== "" && fraction.endsWith("0")) return { texte, ms: null, fraction };
  const [annee, mois, jour, h, mi, s] = m.slice(1, 7).map(Number);
  if (!dateExiste(annee, mois, jour) || h > 23 || mi > 59 || s > 59) return { texte, ms: null, fraction };
  const ms = Math.floor(Number(`0.${fraction || "0"}`) * 1000);
  return { texte, ms: instantUtc(annee, mois, jour, h, mi, s, ms), fraction };
}

/**
 * `Time` d'un certificat ou d'une CRL : `UTCTime` (`AAMMJJhhmmssZ`, `20AA` pour
 * `AA < 50`, `19AA` sinon, RFC 5280 §4.1.2.5) ou `GeneralizedTime` à la
 * seconde. Rend les millisecondes UTC ; lève si la forme ne tient pas.
 */
export function lireTemps(tlv) {
  let texte = "";
  for (const o of tlv.contenu) texte += String.fromCharCode(o);
  if (estUniversel(tlv, ETIQUETTE.UTC_TIME, false)) {
    const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(texte);
    if (!m) throw new ErreurDer("UTCTime mal formé", tlv.debut);
    const aa = Number(m[1]);
    const annee = aa < 50 ? 2000 + aa : 1900 + aa;
    const [mois, jour, h, mi, s] = m.slice(2, 7).map(Number);
    if (!dateExiste(annee, mois, jour) || h > 23 || mi > 59 || s > 59) throw new ErreurDer("UTCTime : date inexistante", tlv.debut);
    return instantUtc(annee, mois, jour, h, mi, s);
  }
  if (estUniversel(tlv, ETIQUETTE.GENERALIZED_TIME, false)) {
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(texte);
    if (!m) throw new ErreurDer("GeneralizedTime mal formé", tlv.debut);
    const [annee, mois, jour, h, mi, s] = m.slice(1, 7).map(Number);
    if (!dateExiste(annee, mois, jour) || h > 23 || mi > 59 || s > 59) throw new ErreurDer("GeneralizedTime : date inexistante", tlv.debut);
    return instantUtc(annee, mois, jour, h, mi, s);
  }
  throw new ErreurDer("Time attendu", tlv.debut);
}

/** Égalité octet pour octet de deux suites. */
export function octetsEgaux(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** `AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }` → `{ oid, parametres: tlv|null, tlv }`. */
export function lireAlgorithme(tlv) {
  attendre(tlv, ETIQUETTE.SEQUENCE, true, "AlgorithmIdentifier");
  const e = enfants(tlv);
  if (e.length < 1 || e.length > 2) throw new ErreurDer("AlgorithmIdentifier mal formé", tlv.debut);
  return { oid: lireOid(e[0]), parametres: e[1] ?? null, tlv };
}

/** Paramètres d'algorithme absents ou `NULL` explicite. */
export function parametresAbsentsOuNuls(alg) {
  if (alg.parametres === null) return true;
  return estUniversel(alg.parametres, ETIQUETTE.NULL, false) && alg.parametres.longueur === 0;
}

// --- Encodeur (requête d'EX-5.1) ---

/** Octets de longueur DER minimale. */
export function encoderLongueur(n) {
  if (n < 0x80) return Uint8Array.of(n);
  const octets = [];
  let v = n;
  while (v > 0) {
    octets.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return Uint8Array.of(0x80 | octets.length, ...octets);
}

/** TLV à partir d'un octet d'étiquette et d'un contenu. */
export function encoderTlv(etiquette, contenu) {
  const l = encoderLongueur(contenu.length);
  const out = new Uint8Array(1 + l.length + contenu.length);
  out[0] = etiquette;
  out.set(l, 1);
  out.set(contenu, 1 + l.length);
  return out;
}

/** `INTEGER` DER minimal d'un entier non négatif (`bigint`). */
export function encoderEntierNonNegatif(v) {
  if (typeof v !== "bigint" || v < 0n) throw new TypeError("entier non négatif attendu");
  const octets = [];
  let r = v;
  if (r === 0n) octets.push(0);
  while (r > 0n) {
    octets.unshift(Number(r & 0xffn));
    r >>= 8n;
  }
  if (octets[0] & 0x80) octets.unshift(0);
  return encoderTlv(0x02, Uint8Array.from(octets));
}

/** `OBJECT IDENTIFIER` DER d'une notation pointée. */
export function encoderOid(texte) {
  if (!/^[0-2](\.(0|[1-9][0-9]*))+$/.test(texte)) throw new TypeError(`OID mal formé : ${texte}`);
  const parts = texte.split(".").map((p) => BigInt(p));
  if ((parts[0] < 2n && parts[1] > 39n) || parts.length < 2) throw new TypeError(`OID mal formé : ${texte}`);
  const sous = [parts[0] * 40n + parts[1], ...parts.slice(2)];
  const octets = [];
  for (const s of sous) {
    const groupe = [];
    let v = s;
    groupe.unshift(Number(v & 0x7fn));
    v >>= 7n;
    while (v > 0n) {
      groupe.unshift(Number(v & 0x7fn) | 0x80);
      v >>= 7n;
    }
    octets.push(...groupe);
  }
  return encoderTlv(0x06, Uint8Array.from(octets));
}

/** Concatène des suites d'octets. */
export function concat(...parties) {
  let n = 0;
  for (const p of parties) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parties) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Octets d'un texte en hexadécimal (avec ou sans `0x`). */
export function hexVersOctets(hex) {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new TypeError("hexadécimal mal formé");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** Hexadécimal minuscule préfixé `0x`. */
export function octetsVersHex(octets) {
  let s = "0x";
  for (const o of octets) s += o.toString(16).padStart(2, "0");
  return s;
}
