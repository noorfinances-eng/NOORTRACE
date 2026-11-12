// JSON strict et forme canonique (CT-1 §4, CT-3 EX-9.6 et EX-9.15,
// contrôle 3) : lecture stricte d'un texte JSON (RFC 8259 ; clé en double,
// substitut isolé, UTF-8 mal formé et marque d'ordre d'octets refusés) ;
// forme canonique JCS v0 de CT-1 §4 (RFC 8785 restreinte aux entiers de
// [-(2^53-1), 2^53-1]) ; égalité de valeurs JSON de CT-1 (EX-9.16) ; copie
// profonde. Lecture, écriture, égalité et copie sont itératives : aucune
// récursion dont la hauteur dépende de l'entrée.

import { ErreurConsole } from "./erreurs.mjs";
import { decoderUtf8 } from "./octets.mjs";

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** Pose un membre propre, y compris `__proto__`, comme le fait JSON.parse. */
function poser(objet, cle, valeur) {
  Object.defineProperty(objet, cle, { value: valeur, writable: true, enumerable: true, configurable: true });
}

function refus(detail) {
  return new ErreurConsole("piece_invalide", detail);
}

/** Vrai si la chaîne est une suite de points de code bien formée. */
export function chaineBienFormee(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (d < 0xdc00 || d > 0xdfff) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/**
 * Lit un texte JSON strict (RFC 8259) : clé en double, substitut isolé (écrit
 * en clair ou par échappement), UTF-8 mal formé, marque d'ordre d'octets,
 * nombre hors de la double précision et toute autre écart à la grammaire lèvent
 * `ErreurConsole` de code `piece_invalide`.
 * @param {string|Uint8Array} entree chaîne, ou octets UTF-8
 * @returns {unknown}
 */
export function analyserJsonStrict(entree) {
  let texte;
  if (entree instanceof Uint8Array) {
    if (entree.length >= 3 && entree[0] === 0xef && entree[1] === 0xbb && entree[2] === 0xbf) {
      throw refus("marque d'ordre d'octets");
    }
    texte = decoderUtf8(entree);
    if (texte === null) throw refus("UTF-8 mal forme");
  } else if (typeof entree === "string") {
    if (!chaineBienFormee(entree)) throw refus("substitut isole");
    texte = entree;
  } else {
    throw new TypeError("analyserJsonStrict : chaine ou Uint8Array attendu");
  }
  return lire(texte);
}

function lire(t) {
  const NOMBRE = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
  let i = 0;
  const n = t.length;
  const blancs = () => {
    while (i < n) {
      const c = t.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };
  const lireChaine = () => {
    // t[i] === '"'
    i++;
    let s = "";
    let debut = i;
    while (true) {
      if (i >= n) throw refus("chaine non terminee");
      const c = t.charCodeAt(i);
      if (c === 0x22) {
        s += t.slice(debut, i);
        i++;
        break;
      }
      if (c < 0x20) throw refus("caractere de controle dans une chaine");
      if (c === 0x5c) {
        s += t.slice(debut, i);
        const e = t[i + 1];
        if (e === undefined) throw refus("echappement incomplet");
        if (e === '"') s += '"';
        else if (e === "\\") s += "\\";
        else if (e === "/") s += "/";
        else if (e === "b") s += "\b";
        else if (e === "f") s += "\f";
        else if (e === "n") s += "\n";
        else if (e === "r") s += "\r";
        else if (e === "t") s += "\t";
        else if (e === "u") {
          const h = t.slice(i + 2, i + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(h)) throw refus("echappement \\u invalide");
          s += String.fromCharCode(parseInt(h, 16));
          i += 4;
        } else throw refus("echappement inconnu");
        i += 2;
        debut = i;
        continue;
      }
      i++;
    }
    if (!chaineBienFormee(s)) throw refus("substitut isole");
    return s;
  };
  const lireScalaire = () => {
    const c = t[i];
    if (c === '"') return lireChaine();
    if (t.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (t.startsWith("false", i)) {
      i += 5;
      return false;
    }
    if (t.startsWith("null", i)) {
      i += 4;
      return null;
    }
    NOMBRE.lastIndex = i;
    const r = NOMBRE.exec(t);
    if (r === null) throw refus("valeur attendue");
    i += r[0].length;
    const v = Number(r[0]);
    if (!Number.isFinite(v)) throw refus("nombre hors de la double precision");
    return v;
  };

  // Pile de conteneurs : { conteneur, cles (objets : Set), cle (en attente) }.
  const pile = [];
  let racine;
  let aRacine = false;
  const deposer = (v) => {
    if (pile.length === 0) {
      racine = v;
      aRacine = true;
      return;
    }
    const haut = pile[pile.length - 1];
    if (Array.isArray(haut.conteneur)) haut.conteneur.push(v);
    else poser(haut.conteneur, haut.cle, v);
  };

  blancs();
  // Automate : attente d'une valeur, puis de « , » ou de la fermeture.
  let attendValeur = true;
  while (true) {
    if (attendValeur) {
      blancs();
      if (i >= n) throw refus("valeur attendue");
      const c = t[i];
      if (c === "{" || c === "[") {
        i++;
        const conteneur = c === "{" ? {} : [];
        const cadre = { conteneur, cles: c === "{" ? new Set() : null, cle: null };
        deposer(conteneur);
        pile.push(cadre);
        blancs();
        if (t[i] === (c === "{" ? "}" : "]")) {
          i++;
          pile.pop();
          attendValeur = false;
          if (pile.length === 0) break;
          continue;
        }
        if (cadre.cles) {
          if (t[i] !== '"') throw refus("nom de membre attendu");
          const cle = lireChaine();
          if (cadre.cles.has(cle)) throw refus("cle en double");
          cadre.cles.add(cle);
          cadre.cle = cle;
          blancs();
          if (t[i] !== ":") throw refus("deux-points attendus");
          i++;
        }
        continue;
      }
      const v = lireScalaire();
      deposer(v);
      attendValeur = false;
      if (pile.length === 0) break;
      continue;
    }
    blancs();
    const haut = pile[pile.length - 1];
    const fermeture = haut.cles ? "}" : "]";
    if (t[i] === ",") {
      i++;
      blancs();
      if (haut.cles) {
        if (t[i] !== '"') throw refus("nom de membre attendu");
        const cle = lireChaine();
        if (haut.cles.has(cle)) throw refus("cle en double");
        haut.cles.add(cle);
        haut.cle = cle;
        blancs();
        if (t[i] !== ":") throw refus("deux-points attendus");
        i++;
      }
      attendValeur = true;
      continue;
    }
    if (t[i] === fermeture) {
      i++;
      pile.pop();
      if (pile.length === 0) break;
      continue;
    }
    throw refus("virgule ou fermeture attendue");
  }
  blancs();
  if (i !== n || !aRacine) throw refus("texte apres la valeur");
  return racine;
}

/** Profondeur maximale d'un texte du format v0 (CT-1 §4, règle 7). */
const PROFONDEUR_V0 = 128;

/**
 * Forme canonique JCS v0 (CT-1 §4) d'une valeur JSON. Lève `TypeError` pour
 * une valeur hors de JCS v0 : nombre non entier ou hors de
 * [-(2^53-1), 2^53-1], substitut isolé, valeur qui n'est pas du JSON, cycle,
 * profondeur au-delà de 128 conteneurs imbriqués, racine comprise (règle 7).
 * @param {unknown} valeur
 * @returns {string}
 */
export function jcs(valeur) {
  const sortie = [];
  const enCours = new Set();
  let profondeur = 0;
  // Pile de tâches : valeur à écrire, ou texte à émettre, ou fin de conteneur.
  const taches = [{ v: valeur }];
  while (taches.length) {
    const tache = taches.pop();
    if (tache.texte !== undefined) {
      sortie.push(tache.texte);
      continue;
    }
    if (tache.fin !== undefined) {
      enCours.delete(tache.fin);
      profondeur--;
      continue;
    }
    const v = tache.v;
    if (v === null) sortie.push("null");
    else if (v === true) sortie.push("true");
    else if (v === false) sortie.push("false");
    else if (typeof v === "number") {
      if (!Number.isSafeInteger(v)) throw new TypeError("JCS v0 : nombre non entier ou hors de l'intervalle sur");
      sortie.push(Object.is(v, -0) ? "0" : String(v));
    } else if (typeof v === "string") {
      if (!chaineBienFormee(v)) throw new TypeError("JCS v0 : substitut isole");
      sortie.push(JSON.stringify(v));
    } else if (Array.isArray(v) || estObjetSimple(v)) {
      if (enCours.has(v)) throw new TypeError("JCS v0 : cycle");
      enCours.add(v);
      profondeur++;
      if (profondeur > PROFONDEUR_V0) throw new TypeError("JCS v0 : profondeur au-dela de 128 (CT-1 section 4, regle 7)");
      const suite = [];
      if (Array.isArray(v)) {
        suite.push({ texte: "[" });
        v.forEach((x, k) => {
          if (k > 0) suite.push({ texte: "," });
          suite.push({ v: x });
        });
        suite.push({ texte: "]" });
      } else {
        const cles = Object.keys(v).sort();
        suite.push({ texte: "{" });
        cles.forEach((c, k) => {
          if (!chaineBienFormee(c)) throw new TypeError("JCS v0 : substitut isole dans un nom");
          suite.push({ texte: (k > 0 ? "," : "") + JSON.stringify(c) + ":" });
          suite.push({ v: v[c] });
        });
        suite.push({ texte: "}" });
      }
      suite.push({ fin: v });
      for (let k = suite.length - 1; k >= 0; k--) taches.push(suite[k]);
    } else {
      throw new TypeError("JCS v0 : valeur qui n'est pas du JSON");
    }
  }
  return sortie.join("");
}

function estObjetSimple(v) {
  if (!estObjet(v)) return false;
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
}

/**
 * Égalité de deux valeurs JSON au sens de CT-1 (CT-3 EX-9.16) : chaînes égales
 * unité pour unité, nombres égaux en valeur, objets égaux membre par membre
 * sans égard à l'ordre, tableaux élément par élément.
 * @param {unknown} a
 * @param {unknown} b
 * @returns {boolean}
 */
export function egaliteJson(a, b) {
  const pile = [[a, b]];
  while (pile.length) {
    const [x, y] = pile.pop();
    if (x === null || y === null || typeof x !== "object" || typeof y !== "object") {
      if (typeof x === "number" && typeof y === "number") {
        if (x !== y) return false;
        continue;
      }
      if (x !== y) return false;
      continue;
    }
    if (Array.isArray(x) !== Array.isArray(y)) return false;
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

/**
 * Copie profonde d'une valeur JSON (objets neufs, membres `__proto__`
 * compris comme membres propres).
 * @template T
 * @param {T} valeur
 * @returns {T}
 */
export function cloner(valeur) {
  if (valeur === null || typeof valeur !== "object") return valeur;
  const racine = Array.isArray(valeur) ? [] : {};
  const pile = [[valeur, racine]];
  while (pile.length) {
    const [source, cible] = pile.pop();
    if (Array.isArray(source)) {
      for (let k = 0; k < source.length; k++) {
        const x = source[k];
        if (x !== null && typeof x === "object") {
          const c = Array.isArray(x) ? [] : {};
          cible.push(c);
          pile.push([x, c]);
        } else cible.push(x);
      }
    } else {
      for (const k of Object.keys(source)) {
        const x = source[k];
        if (x !== null && typeof x === "object") {
          const c = Array.isArray(x) ? [] : {};
          poser(cible, k, c);
          pile.push([x, c]);
        } else poser(cible, k, x);
      }
    }
  }
  return racine;
}
