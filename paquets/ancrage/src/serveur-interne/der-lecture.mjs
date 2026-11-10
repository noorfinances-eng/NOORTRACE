// Lecteur DER borné du serveur interne (lot E), écrit depuis X.690 et le
// profil de lecture de CT-6 §9.3 (EX-9.4) : longueurs définies sous forme
// minimale, numéros d'étiquette inférieurs à 31, BOOLEAN `00` ou `ff`,
// profondeur d'imbrication bornée (32), aucun octet après la fin d'une
// structure qui n'en admet pas. Il sert à relire la requête `TimeStampReq`
// reçue et les certificats PEM confiés au serveur ; il ne remplace pas le
// lecteur du lot A (`src/rfc3161/der.mjs`), écrit en parallèle.

export const PROFONDEUR_MAX = 32;

export class ErreurDer extends Error {
  constructor(message) {
    super(message);
    this.name = "ErreurDer";
  }
}

/**
 * Un élément lu : étiquette (octet entier), forme construite ou non, octets de
 * contenu, octets complets (étiquette, longueur et contenu), fin dans le
 * tampon d'origine.
 * @typedef {{etiquette: number, construit: boolean, contenu: Uint8Array, complet: Uint8Array, fin: number}} Element
 */

/**
 * Lit l'élément qui commence à `debut` dans `octets`, sans descendre dans son
 * contenu.
 * @returns {Element}
 */
export function lireElement(octets, debut = 0) {
  if (debut >= octets.length) throw new ErreurDer("fin prématurée : étiquette attendue");
  const etiquette = octets[debut];
  if ((etiquette & 0x1f) === 0x1f) throw new ErreurDer("numéro d'étiquette 31 ou au-delà refusé");
  if (debut + 1 >= octets.length) throw new ErreurDer("fin prématurée : longueur attendue");
  const premier = octets[debut + 1];
  let longueur;
  let position = debut + 2;
  if (premier < 0x80) {
    longueur = premier;
  } else if (premier === 0x80) {
    throw new ErreurDer("longueur indéfinie refusée");
  } else {
    const nb = premier & 0x7f;
    if (nb > 4) throw new ErreurDer("longueur sur plus de quatre octets refusée");
    if (position + nb > octets.length) throw new ErreurDer("fin prématurée dans la longueur");
    longueur = 0;
    for (let i = 0; i < nb; i++) longueur = longueur * 256 + octets[position + i];
    if (octets[position] === 0) throw new ErreurDer("longueur non minimale (octet de tête nul)");
    if (longueur < 0x80) throw new ErreurDer("longueur non minimale (forme longue pour une valeur courte)");
    position += nb;
  }
  if (position + longueur > octets.length) throw new ErreurDer("contenu tronqué");
  return {
    etiquette,
    construit: (etiquette & 0x20) !== 0,
    contenu: octets.subarray(position, position + longueur),
    complet: octets.subarray(debut, position + longueur),
    fin: position + longueur,
  };
}

/**
 * Lit la suite d'éléments qui remplit exactement `octets` (contenu d'une
 * SEQUENCE ou d'un SET), en refusant tout octet de trop.
 * @returns {Element[]}
 */
export function lireSuite(octets, profondeur = 0) {
  if (profondeur > PROFONDEUR_MAX) throw new ErreurDer("profondeur d'imbrication au-delà de 32");
  const elements = [];
  let position = 0;
  while (position < octets.length) {
    const e = lireElement(octets, position);
    elements.push(e);
    position = e.fin;
  }
  return elements;
}

/** L'unique élément de `octets`, sans octet après lui. */
export function lireUnique(octets) {
  const e = lireElement(octets, 0);
  if (e.fin !== octets.length) throw new ErreurDer("octets après la fin de la structure");
  return e;
}

/** Exige une étiquette précise. */
export function exiger(element, etiquette, nom) {
  if (element.etiquette !== etiquette) {
    throw new ErreurDer(`${nom} : étiquette 0x${etiquette.toString(16).padStart(2, "0")} attendue, 0x${element.etiquette.toString(16).padStart(2, "0")} lue`);
  }
  return element;
}

/**
 * Vérifie qu'un contenu d'INTEGER est minimal (X.690 §8.3.2) et rend ses octets.
 */
export function contenuEntier(element, nom = "INTEGER") {
  exiger(element, 0x02, nom);
  const c = element.contenu;
  if (c.length === 0) throw new ErreurDer(`${nom} : contenu vide`);
  if (c.length > 1 && ((c[0] === 0x00 && (c[1] & 0x80) === 0) || (c[0] === 0xff && (c[1] & 0x80) !== 0))) {
    throw new ErreurDer(`${nom} : encodage non minimal`);
  }
  return c;
}

/** Valeur bigint (signée) d'un INTEGER. */
export function valeurEntier(element, nom = "INTEGER") {
  const c = contenuEntier(element, nom);
  let v = 0n;
  for (const o of c) v = (v << 8n) | BigInt(o);
  if (c[0] & 0x80) v -= 1n << BigInt(8 * c.length);
  return v;
}

/** Valeur d'un BOOLEAN DER (`00` ou `ff` seulement). */
export function valeurBooleen(element, nom = "BOOLEAN") {
  exiger(element, 0x01, nom);
  if (element.contenu.length !== 1) throw new ErreurDer(`${nom} : un octet attendu`);
  if (element.contenu[0] === 0xff) return true;
  if (element.contenu[0] === 0x00) return false;
  throw new ErreurDer(`${nom} : valeur autre que 00 ou ff`);
}

/** Forme pointée d'un OBJECT IDENTIFIER. */
export function valeurOid(element, nom = "OBJECT IDENTIFIER") {
  exiger(element, 0x06, nom);
  const c = element.contenu;
  if (c.length === 0) throw new ErreurDer(`${nom} : contenu vide`);
  const arcs = [];
  let v = 0n;
  let enCours = false;
  for (let i = 0; i < c.length; i++) {
    const o = c[i];
    if (!enCours && o === 0x80) throw new ErreurDer(`${nom} : sous-identifiant non minimal`);
    v = (v << 7n) | BigInt(o & 0x7f);
    enCours = (o & 0x80) !== 0;
    if (!enCours) {
      if (arcs.length === 0) {
        if (v < 40n) arcs.push(0n, v);
        else if (v < 80n) arcs.push(1n, v - 40n);
        else arcs.push(2n, v - 80n);
      } else {
        arcs.push(v);
      }
      v = 0n;
    }
  }
  if (enCours) throw new ErreurDer(`${nom} : sous-identifiant tronqué`);
  return arcs.map(String).join(".");
}

/** AlgorithmIdentifier : `{ algorithme, parametres }` (`parametres` : élément ou null). */
export function lireIdentifiantAlgorithme(element, nom = "AlgorithmIdentifier") {
  exiger(element, 0x30, nom);
  const parties = lireSuite(element.contenu, 1);
  if (parties.length < 1 || parties.length > 2) throw new ErreurDer(`${nom} : un ou deux éléments attendus`);
  return { algorithme: valeurOid(parties[0], `${nom}.algorithm`), parametres: parties[1] ?? null };
}

/** Vrai si les paramètres d'un AlgorithmIdentifier sont absents ou NULL (`05 00`). */
export function parametresAbsentsOuNuls(parametres) {
  return parametres === null || (parametres.etiquette === 0x05 && parametres.contenu.length === 0);
}

const DECODEUR_UTF8 = new TextDecoder("utf-8", { fatal: true });

/**
 * Texte d'un GeneralizedTime ou d'un UTCTime DER, puis l'instant UTC en
 * millisecondes (RFC 5280 §4.1.2.5 : UTCTime `AA` lu `20AA` sous 50, `19AA`
 * sinon).
 */
export function valeurTemps(element, nom = "Time") {
  let texte;
  try {
    texte = DECODEUR_UTF8.decode(element.contenu);
  } catch {
    throw new ErreurDer(`${nom} : texte illisible`);
  }
  let m;
  if (element.etiquette === 0x17) {
    m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(texte);
    if (!m) throw new ErreurDer(`${nom} : UTCTime hors de la forme AAMMJJhhmmssZ`);
    const aa = Number(m[1]);
    return Date.UTC(aa < 50 ? 2000 + aa : 1900 + aa, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
  }
  if (element.etiquette === 0x18) {
    m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d*[1-9])?Z$/.exec(texte);
    if (!m) throw new ErreurDer(`${nom} : GeneralizedTime hors de la forme AAAAMMJJhhmmss[.f]Z`);
    const fraction = m[7] ? Number(m[7]) : 0;
    return Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6])) + Math.floor(fraction * 1000);
  }
  throw new ErreurDer(`${nom} : UTCTime ou GeneralizedTime attendu`);
}
