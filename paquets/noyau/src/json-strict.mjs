// Lecture JSON stricte et forme canonique JCS v0 (CT-1 §4).
//
// La lecture stricte refuse ce que JCS v0 ne sait pas représenter : clé en
// double (après décodage des échappements), substitut isolé, nombre non
// entier (fraction ou exposant, même de valeur entière) et entier hors de
// l'intervalle sûr. Ces refus sont ceux du contrôle E-2 ; une erreur de
// syntaxe, elle, rend la partie inexploitable (« pas du JSON »).

import { utf8 } from "./conventions.mjs";

/** Codes d'erreur de forme canonique (contrôle E-2). */
export const CODES_FORME_CANONIQUE = Object.freeze([
  "cle_en_double",
  "substitut_isole",
  "nombre_non_entier",
  "nombre_hors_intervalle",
]);

/** Profondeur d'imbrication maximale acceptée par la lecture et par JCS. */
export const PROFONDEUR_MAX = 256;

/**
 * Erreur de lecture JSON ou de forme canonique. `code` vaut `syntaxe`,
 * `utf8`, `profondeur`, `type`, ou l'un des CODES_FORME_CANONIQUE ;
 * `formeCanonique` dit si l'erreur relève de E-2.
 */
export class ErreurJson extends Error {
  /**
   * @param {string} code
   * @param {string} message
   */
  constructor(code, message) {
    super(message);
    this.name = "ErreurJson";
    this.code = code;
    this.formeCanonique = CODES_FORME_CANONIQUE.includes(code);
  }
}

const decodeurUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Décode des octets UTF-8 bien formés, sans marque d'ordre d'octets (CT-1 §3).
 * @param {Uint8Array} octets
 * @returns {string}
 */
export function decoderUtf8(octets) {
  if (!(octets instanceof Uint8Array)) throw new TypeError("octets attendus (Uint8Array)");
  let texte;
  try {
    texte = decodeurUtf8.decode(octets);
  } catch {
    throw new ErreurJson("utf8", "texte UTF-8 mal formé");
  }
  if (texte.charCodeAt(0) === 0xfeff) throw new ErreurJson("utf8", "marque d'ordre d'octets refusée");
  return texte;
}

function definir(objet, cle, valeur) {
  if (cle === "__proto__") {
    Object.defineProperty(objet, cle, { value: valeur, enumerable: true, writable: true, configurable: true });
  } else {
    objet[cle] = valeur;
  }
}

/**
 * Lit un texte JSON (RFC 8259) avec les refus de JCS v0.
 *
 * Options : `nombres: "libres"` admet fractions, exposants et grands
 * nombres (lus comme des nombres ECMAScript) ; `substituts: "admis"` admet les
 * substituts isolés. Par défaut, les deux sont refusés (contrôle E-2). La clé
 * en double est toujours refusée.
 * @param {string|Uint8Array} source texte, ou octets UTF-8
 * @param {{nombres?: "stricts"|"libres", substituts?: "refuses"|"admis"}} [options]
 * @returns {unknown} la valeur lue (objets à prototype ordinaire)
 * @throws {ErreurJson}
 */
export function analyserJson(source, options = {}) {
  const texte = typeof source === "string" ? source : decoderUtf8(source);
  const nombresLibres = options.nombres === "libres";
  const substitutsAdmis = options.substituts === "admis";
  let i = 0;
  const n = texte.length;

  const erreur = (code, message) => new ErreurJson(code, `${message} (position ${i})`);
  const espaces = () => {
    while (i < n) {
      const c = texte.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };

  const lireChaine = () => {
    // texte[i] === '"'
    i++;
    let sortie = "";
    let debut = i;
    while (true) {
      if (i >= n) throw erreur("syntaxe", "chaîne non terminée");
      const c = texte.charCodeAt(i);
      if (c === 0x22) {
        sortie += texte.slice(debut, i);
        i++;
        break;
      }
      if (c < 0x20) throw erreur("syntaxe", "caractère de contrôle non échappé dans une chaîne");
      if (c === 0x5c) {
        sortie += texte.slice(debut, i);
        i++;
        if (i >= n) throw erreur("syntaxe", "échappement incomplet");
        const e = texte[i];
        i++;
        switch (e) {
          case '"': sortie += '"'; break;
          case "\\": sortie += "\\"; break;
          case "/": sortie += "/"; break;
          case "b": sortie += "\b"; break;
          case "f": sortie += "\f"; break;
          case "n": sortie += "\n"; break;
          case "r": sortie += "\r"; break;
          case "t": sortie += "\t"; break;
          case "u": {
            const h = texte.slice(i, i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(h)) throw erreur("syntaxe", "échappement \\u invalide");
            i += 4;
            sortie += String.fromCharCode(parseInt(h, 16));
            break;
          }
          default:
            throw erreur("syntaxe", `échappement \\${e} invalide`);
        }
        debut = i;
        continue;
      }
      i++;
    }
    if (!substitutsAdmis && !chaineBienFormee(sortie)) {
      throw erreur("substitut_isole", "substitut isolé dans une chaîne");
    }
    return sortie;
  };

  const lireNombre = () => {
    const debut = i;
    if (texte[i] === "-") i++;
    if (texte[i] === "0") {
      i++;
    } else if (texte[i] >= "1" && texte[i] <= "9") {
      while (texte[i] >= "0" && texte[i] <= "9") i++;
    } else {
      throw erreur("syntaxe", "nombre invalide");
    }
    let fractionnaire = false;
    if (texte[i] === ".") {
      i++;
      if (!(texte[i] >= "0" && texte[i] <= "9")) throw erreur("syntaxe", "fraction invalide");
      while (texte[i] >= "0" && texte[i] <= "9") i++;
      fractionnaire = true;
    }
    if (texte[i] === "e" || texte[i] === "E") {
      i++;
      if (texte[i] === "+" || texte[i] === "-") i++;
      if (!(texte[i] >= "0" && texte[i] <= "9")) throw erreur("syntaxe", "exposant invalide");
      while (texte[i] >= "0" && texte[i] <= "9") i++;
      fractionnaire = true;
    }
    const brut = texte.slice(debut, i);
    const valeur = Number(brut);
    if (nombresLibres) return valeur === 0 ? 0 : valeur;
    if (fractionnaire) throw erreur("nombre_non_entier", `nombre non entier ${brut}`);
    if (!Number.isSafeInteger(valeur)) throw erreur("nombre_hors_intervalle", `entier hors de l'intervalle sûr ${brut}`);
    return valeur === 0 ? 0 : valeur;
  };

  const lireValeur = (profondeur) => {
    if (profondeur > PROFONDEUR_MAX) throw erreur("profondeur", "imbrication trop profonde");
    espaces();
    if (i >= n) throw erreur("syntaxe", "valeur attendue");
    const c = texte[i];
    if (c === "{") {
      i++;
      const objet = {};
      const vues = new Set();
      espaces();
      if (texte[i] === "}") {
        i++;
        return objet;
      }
      while (true) {
        espaces();
        if (texte[i] !== '"') throw erreur("syntaxe", "nom de membre attendu");
        const cle = lireChaine();
        if (vues.has(cle)) throw erreur("cle_en_double", `clé en double ${JSON.stringify(cle)}`);
        vues.add(cle);
        espaces();
        if (texte[i] !== ":") throw erreur("syntaxe", "deux-points attendu");
        i++;
        definir(objet, cle, lireValeur(profondeur + 1));
        espaces();
        if (texte[i] === ",") {
          i++;
          continue;
        }
        if (texte[i] === "}") {
          i++;
          return objet;
        }
        throw erreur("syntaxe", "virgule ou accolade fermante attendue");
      }
    }
    if (c === "[") {
      i++;
      const tableau = [];
      espaces();
      if (texte[i] === "]") {
        i++;
        return tableau;
      }
      while (true) {
        tableau.push(lireValeur(profondeur + 1));
        espaces();
        if (texte[i] === ",") {
          i++;
          continue;
        }
        if (texte[i] === "]") {
          i++;
          return tableau;
        }
        throw erreur("syntaxe", "virgule ou crochet fermant attendu");
      }
    }
    if (c === '"') return lireChaine();
    if (c === "-" || (c >= "0" && c <= "9")) return lireNombre();
    if (texte.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (texte.startsWith("false", i)) {
      i += 5;
      return false;
    }
    if (texte.startsWith("null", i)) {
      i += 4;
      return null;
    }
    throw erreur("syntaxe", "valeur JSON attendue");
  };

  const valeur = lireValeur(0);
  espaces();
  if (i !== n) throw erreur("syntaxe", "texte après la valeur JSON");
  return valeur;
}

/**
 * Dit si une chaîne ECMAScript est une suite de points de code bien formée
 * (aucun substitut isolé).
 * @param {string} s
 * @returns {boolean}
 */
export function chaineBienFormee(s) {
  for (let k = 0; k < s.length; k++) {
    const c = s.charCodeAt(k);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(k + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return false;
      k++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

const ECHAPPEMENTS_COURTS = { 0x08: "\\b", 0x09: "\\t", 0x0a: "\\n", 0x0c: "\\f", 0x0d: "\\r", 0x22: '\\"', 0x5c: "\\\\" };

function ecrireChaine(s) {
  if (!chaineBienFormee(s)) throw new ErreurJson("substitut_isole", "substitut isolé dans une chaîne");
  let sortie = '"';
  let debut = 0;
  for (let k = 0; k < s.length; k++) {
    const c = s.charCodeAt(k);
    if (c < 0x20 || c === 0x22 || c === 0x5c) {
      sortie += s.slice(debut, k);
      sortie += ECHAPPEMENTS_COURTS[c] ?? "\\u" + c.toString(16).padStart(4, "0");
      debut = k + 1;
    }
  }
  return sortie + s.slice(debut) + '"';
}

function estObjetSimple(v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function ecrire(valeur, profondeur) {
  if (profondeur > PROFONDEUR_MAX) throw new ErreurJson("profondeur", "imbrication trop profonde");
  if (valeur === null) return "null";
  switch (typeof valeur) {
    case "boolean":
      return valeur ? "true" : "false";
    case "number":
      if (!Number.isFinite(valeur) || !Number.isInteger(valeur)) {
        throw new ErreurJson("nombre_non_entier", `nombre non entier ${valeur}`);
      }
      if (!Number.isSafeInteger(valeur)) {
        throw new ErreurJson("nombre_hors_intervalle", `entier hors de l'intervalle sûr ${valeur}`);
      }
      return valeur === 0 ? "0" : String(valeur);
    case "string":
      return ecrireChaine(valeur);
    case "object": {
      if (Array.isArray(valeur)) {
        const parties = [];
        for (let k = 0; k < valeur.length; k++) {
          if (!(k in valeur)) throw new ErreurJson("type", "tableau à trou");
          parties.push(ecrire(valeur[k], profondeur + 1));
        }
        return "[" + parties.join(",") + "]";
      }
      if (!estObjetSimple(valeur)) throw new ErreurJson("type", "objet JSON simple attendu");
      const cles = Object.keys(valeur).sort();
      const parties = [];
      for (const cle of cles) {
        const v = valeur[cle];
        if (v === undefined) throw new ErreurJson("type", `membre ${JSON.stringify(cle)} indéfini`);
        parties.push(ecrireChaine(cle) + ":" + ecrire(v, profondeur + 1));
      }
      return "{" + parties.join(",") + "}";
    }
    default:
      throw new ErreurJson("type", `type ${typeof valeur} non représentable en JSON`);
  }
}

/**
 * Forme canonique JCS v0 d'une valeur JSON (CT-1 §4) : membres triés par
 * unités de code UTF-16, aucun espace, chaînes échappées comme
 * `JSON.stringify` d'ECMAScript 2019, entiers sûrs seulement (`-0` s'écrit
 * `0`), substitut isolé refusé.
 * @param {unknown} valeur
 * @returns {string}
 * @throws {ErreurJson} valeur sans forme canonique (E-2) ou non JSON
 */
export function jcs(valeur) {
  return ecrire(valeur, 0);
}

/**
 * Forme canonique JCS v0 encodée en UTF-8 (ce que l'on hache et signe).
 * @param {unknown} valeur
 * @returns {Uint8Array}
 */
export function jcsOctets(valeur) {
  return utf8(jcs(valeur));
}

/**
 * Forme canonique d'un texte JSON, ou null si le texte est invalide pour JCS
 * v0 (syntaxe, clé en double, substitut isolé, nombre non entier ou hors de
 * l'intervalle sûr).
 * @param {string|Uint8Array} source
 * @returns {string|null}
 */
export function canoniserTexte(source) {
  try {
    return jcs(analyserJson(source));
  } catch (e) {
    if (e instanceof ErreurJson) return null;
    throw e;
  }
}

/**
 * Égalité de deux valeurs JSON (objets comparés membre à membre, quel que
 * soit l'ordre ; tableaux dans l'ordre).
 * @param {unknown} a
 * @param {unknown} b
 * @returns {boolean}
 */
export function egaliteJson(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    if (a.length !== b.length) return false;
    for (let k = 0; k < a.length; k++) if (!egaliteJson(a[k], b[k])) return false;
    return true;
  }
  const ca = Object.keys(a);
  const cb = Object.keys(b);
  if (ca.length !== cb.length) return false;
  for (const c of ca) {
    if (!Object.prototype.hasOwnProperty.call(b, c) || !egaliteJson(a[c], b[c])) return false;
  }
  return true;
}
