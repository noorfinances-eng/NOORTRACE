// Lecture JSON stricte et forme canonique JCS v0 (CT-1 §4).
//
// La lecture stricte refuse ce que JCS v0 ne sait pas représenter : clé en
// double (après décodage des échappements), substitut isolé, nombre non
// entier (fraction ou exposant, même de valeur entière) et entier hors de
// l'intervalle sûr. Ces refus sont ceux du contrôle E-2 ; une erreur de
// syntaxe, elle, rend la partie inexploitable (« pas du JSON »).
//
// Profondeur d'imbrication : CT-1 §4 n'en fixe aucune ; la lecture et la forme
// canonique n'en appliquent donc aucune par défaut. L'option `profondeurMax`
// applique une borne explicite (celle de CT-6 EX-4.13 est PROFONDEUR_CT6, 128
// niveaux). La lecture, l'écriture canonique et l'égalité sont itératives :
// une imbrication arbitraire n'épuise jamais la pile d'appels.

import { utf8 } from "./conventions.mjs";

/** Codes d'erreur de forme canonique (contrôle E-2). */
export const CODES_FORME_CANONIQUE = Object.freeze([
  "cle_en_double",
  "substitut_isole",
  "nombre_non_entier",
  "nombre_hors_intervalle",
]);

/**
 * Profondeur d'imbrication que CT-6 EX-4.13 (et EX-15.1) fixe au vérificateur :
 * 128 niveaux. CT-1 n'en fixe aucune : cette borne ne s'applique que si on la
 * passe en option `profondeurMax`.
 */
export const PROFONDEUR_CT6 = 128;

// Borne de profondeur d'une option : entier ≥ 0, ou Infinity (aucune borne).
function borneProfondeur(options) {
  const p = options?.profondeurMax;
  if (p === undefined || p === null) return Infinity;
  if (p !== Infinity && !(Number.isSafeInteger(p) && p >= 0)) throw new TypeError("profondeurMax : entier ≥ 0 attendu");
  return p;
}

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
    // Un substitut encodé sur trois octets (ED A0..BF 80..BF, forme CESU-8)
    // est un substitut isolé au sens de CT-1 §4 : E-2, et non « pas du JSON ».
    // Il l'est seulement si le texte, ces séquences mises à part, est de
    // l'UTF-8 bien formé ; sinon l'erreur reste une erreur d'UTF-8.
    if (substitutsEncodesSeuls(octets)) throw new ErreurJson("substitut_isole", "substitut encodé en UTF-8 (forme CESU-8) : substitut isolé");
    throw new ErreurJson("utf8", "texte UTF-8 mal formé");
  }
  if (texte.charCodeAt(0) === 0xfeff) throw new ErreurJson("utf8", "marque d'ordre d'octets refusée");
  return texte;
}

// Dit si les seuls défauts UTF-8 d'une suite d'octets sont des substituts
// encodés (ED A0..BF 80..BF) : chacun est remplacé par U+FFFD (EF BF BD, même
// longueur), puis le décodage strict est retenté.
function substitutsEncodesSeuls(octets) {
  let copie = null;
  for (let k = 0; k + 2 < octets.length; k++) {
    if (octets[k] === 0xed && octets[k + 1] >= 0xa0 && octets[k + 1] <= 0xbf && octets[k + 2] >= 0x80 && octets[k + 2] <= 0xbf) {
      copie ??= Uint8Array.from(octets);
      copie[k] = 0xef;
      copie[k + 1] = 0xbf;
      copie[k + 2] = 0xbd;
      k += 2;
    }
  }
  if (copie === null) return false;
  try {
    decodeurUtf8.decode(copie);
    return true;
  } catch {
    return false;
  }
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
 * en double est toujours refusée. `profondeurMax` borne le nombre de
 * conteneurs (objets, tableaux) imbriqués ; par défaut, aucune borne (CT-1 §4
 * n'en fixe pas), et la lecture, itérative, n'épuise jamais la pile.
 * @param {string|Uint8Array} source texte, ou octets UTF-8
 * @param {{nombres?: "stricts"|"libres", substituts?: "refuses"|"admis", profondeurMax?: number}} [options]
 * @returns {unknown} la valeur lue (objets à prototype ordinaire)
 * @throws {ErreurJson}
 */
export function analyserJson(source, options = {}) {
  const texte = typeof source === "string" ? source : decoderUtf8(source);
  const nombresLibres = options.nombres === "libres";
  const profondeurMax = borneProfondeur(options);
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

  // Lit un nom de membre et le deux-points qui le suit ; refuse la clé en double.
  const lireNom = (cadre) => {
    espaces();
    if (texte[i] !== '"') throw erreur("syntaxe", "nom de membre attendu");
    const cle = lireChaine();
    if (cadre.vues.has(cle)) throw erreur("cle_en_double", `clé en double ${JSON.stringify(cle)}`);
    cadre.vues.add(cle);
    espaces();
    if (texte[i] !== ":") throw erreur("syntaxe", "deux-points attendu");
    i++;
    cadre.cle = cle;
  };

  // Parcours itératif : une pile de conteneurs ouverts remplace la récursion,
  // pour qu'aucune imbrication n'épuise la pile d'appels.
  const pile = [];
  let valeur;
  lecture: while (true) {
    // Une valeur commence en i.
    espaces();
    if (i >= n) throw erreur("syntaxe", "valeur attendue");
    const c = texte[i];
    if (c === "{" || c === "[") {
      if (pile.length + 1 > profondeurMax) throw erreur("profondeur", `imbrication de plus de ${profondeurMax} niveaux`);
      i++;
      espaces();
      if (c === "{") {
        if (texte[i] === "}") {
          i++;
          valeur = {};
        } else {
          const cadre = { objet: {}, vues: new Set(), cle: null };
          pile.push(cadre);
          lireNom(cadre);
          continue lecture;
        }
      } else if (texte[i] === "]") {
        i++;
        valeur = [];
      } else {
        pile.push({ tableau: [] });
        continue lecture;
      }
    } else if (c === '"') {
      valeur = lireChaine();
    } else if (c === "-" || (c >= "0" && c <= "9")) {
      valeur = lireNombre();
    } else if (texte.startsWith("true", i)) {
      i += 4;
      valeur = true;
    } else if (texte.startsWith("false", i)) {
      i += 5;
      valeur = false;
    } else if (texte.startsWith("null", i)) {
      i += 4;
      valeur = null;
    } else {
      throw erreur("syntaxe", "valeur JSON attendue");
    }
    // La valeur est complète : on la range dans son conteneur, et on ferme les
    // conteneurs qui s'achèvent.
    while (true) {
      if (pile.length === 0) break lecture;
      const cadre = pile[pile.length - 1];
      espaces();
      if (cadre.objet) {
        definir(cadre.objet, cadre.cle, valeur);
        if (texte[i] === ",") {
          i++;
          lireNom(cadre);
          continue lecture;
        }
        if (texte[i] !== "}") throw erreur("syntaxe", "virgule ou accolade fermante attendue");
        i++;
        valeur = cadre.objet;
      } else {
        cadre.tableau.push(valeur);
        if (texte[i] === ",") {
          i++;
          continue lecture;
        }
        if (texte[i] !== "]") throw erreur("syntaxe", "virgule ou crochet fermant attendu");
        i++;
        valeur = cadre.tableau;
      }
      pile.pop();
    }
  }
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

// Écriture itérative : une pile de tâches (valeur à écrire, texte à émettre,
// sortie d'un conteneur) remplace la récursion. Les conteneurs en cours
// d'écriture sont suivis pour refuser une structure cyclique.
function ecrire(racine, profondeurMax) {
  const sortie = [];
  const enCours = new Set();
  const pile = [{ valeur: racine, profondeur: 0 }];
  while (pile.length) {
    const tache = pile.pop();
    if (tache.texte !== undefined) {
      sortie.push(tache.texte);
      continue;
    }
    if (tache.sortie !== undefined) {
      enCours.delete(tache.sortie);
      continue;
    }
    const { valeur, profondeur } = tache;
    if (valeur === null) {
      sortie.push("null");
      continue;
    }
    switch (typeof valeur) {
      case "boolean":
        sortie.push(valeur ? "true" : "false");
        continue;
      case "number":
        if (!Number.isFinite(valeur) || !Number.isInteger(valeur)) {
          throw new ErreurJson("nombre_non_entier", `nombre non entier ${valeur}`);
        }
        if (!Number.isSafeInteger(valeur)) {
          throw new ErreurJson("nombre_hors_intervalle", `entier hors de l'intervalle sûr ${valeur}`);
        }
        sortie.push(valeur === 0 ? "0" : String(valeur));
        continue;
      case "string":
        sortie.push(ecrireChaine(valeur));
        continue;
      case "object": {
        if (profondeur + 1 > profondeurMax) throw new ErreurJson("profondeur", `imbrication de plus de ${profondeurMax} niveaux`);
        if (enCours.has(valeur)) throw new ErreurJson("type", "structure cyclique");
        if (Array.isArray(valeur)) {
          for (let k = 0; k < valeur.length; k++) if (!(k in valeur)) throw new ErreurJson("type", "tableau à trou");
          enCours.add(valeur);
          pile.push({ sortie: valeur }, { texte: "]" });
          for (let k = valeur.length - 1; k >= 0; k--) {
            pile.push({ valeur: valeur[k], profondeur: profondeur + 1 });
            if (k > 0) pile.push({ texte: "," });
          }
          sortie.push("[");
          continue;
        }
        if (!estObjetSimple(valeur)) throw new ErreurJson("type", "objet JSON simple attendu");
        const cles = Object.keys(valeur).sort();
        for (const cle of cles) if (valeur[cle] === undefined) throw new ErreurJson("type", `membre ${JSON.stringify(cle)} indéfini`);
        enCours.add(valeur);
        pile.push({ sortie: valeur }, { texte: "}" });
        for (let k = cles.length - 1; k >= 0; k--) {
          pile.push({ valeur: valeur[cles[k]], profondeur: profondeur + 1 }, { texte: ecrireChaine(cles[k]) + ":" });
          if (k > 0) pile.push({ texte: "," });
        }
        sortie.push("{");
        continue;
      }
      default:
        throw new ErreurJson("type", `type ${typeof valeur} non représentable en JSON`);
    }
  }
  return sortie.join("");
}

/**
 * Forme canonique JCS v0 d'une valeur JSON (CT-1 §4) : membres triés par
 * unités de code UTF-16, aucun espace, chaînes échappées comme
 * `JSON.stringify` d'ECMAScript 2019, entiers sûrs seulement (`-0` s'écrit
 * `0`), substitut isolé refusé. Aucune borne de profondeur par défaut (CT-1
 * §4 n'en fixe pas) ; `options.profondeurMax` en applique une.
 * @param {unknown} valeur
 * @param {{profondeurMax?: number}} [options]
 * @returns {string}
 * @throws {ErreurJson} valeur sans forme canonique (E-2), non JSON, cyclique, ou au-delà de profondeurMax
 */
export function jcs(valeur, options = {}) {
  return ecrire(valeur, borneProfondeur(options));
}

/**
 * Forme canonique JCS v0 encodée en UTF-8 (ce que l'on hache et signe).
 * @param {unknown} valeur
 * @param {{profondeurMax?: number}} [options]
 * @returns {Uint8Array}
 */
export function jcsOctets(valeur, options = {}) {
  return utf8(jcs(valeur, options));
}

/**
 * Forme canonique d'un texte JSON, ou null si le texte est invalide pour JCS
 * v0 (syntaxe, clé en double, substitut isolé, nombre non entier ou hors de
 * l'intervalle sûr).
 * @param {string|Uint8Array} source
 * @param {{profondeurMax?: number}} [options]
 * @returns {string|null}
 */
export function canoniserTexte(source, options = {}) {
  try {
    return jcs(analyserJson(source, { profondeurMax: options.profondeurMax }), { profondeurMax: options.profondeurMax });
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
  // Parcours itératif par paires ; une paire déjà comparée (ou en cours de
  // comparaison, dans une structure cyclique) n'est pas reprise.
  const vues = new Map();
  const pile = [[a, b]];
  while (pile.length) {
    const [x, y] = pile.pop();
    if (x === y) continue;
    if (typeof x !== typeof y || x === null || y === null || typeof x !== "object") return false;
    if (Array.isArray(x) !== Array.isArray(y)) return false;
    let deja = vues.get(x);
    if (deja?.has(y)) continue;
    if (!deja) vues.set(x, (deja = new Set()));
    deja.add(y);
    if (Array.isArray(x)) {
      if (x.length !== y.length) return false;
      for (let k = 0; k < x.length; k++) pile.push([x[k], y[k]]);
      continue;
    }
    const cx = Object.keys(x);
    const cy = Object.keys(y);
    if (cx.length !== cy.length) return false;
    for (const c of cx) {
      if (!Object.prototype.hasOwnProperty.call(y, c)) return false;
      pile.push([x[c], y[c]]);
    }
  }
  return true;
}
