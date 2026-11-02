// JCS intégral (CT-2 §8.1, EX-8.1) : la RFC 8785 appliquée telle quelle aux
// pièces. Membres triés par unités de code UTF-16, tableaux dans l'ordre,
// chaînes échappées comme en CT-1 §4 règle 3, littéraux en minuscules, aucun
// espace, nombres écrits par la règle ES6 Number::toString sur la double la
// plus proche du texte reçu, -0 écrit 0. Les structures de CT-1 (événement,
// manifeste, valeur en ligne) restent en JCS v0 : c'est `jcs` du noyau, que
// ce module ne remplace pas (EX-8.3).
//
// La lecture stricte (clé en double, substitut isolé) est celle du noyau,
// avec l'option `nombres: "libres"` ; un nombre que la double précision ne
// représente pas (débordement vers l'infini) est refusé à l'écriture.

import { ErreurJson, analyserJson, chaineBienFormee, utf8 } from "@noortrace/noyau";

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

function ecrireNombre(n) {
  if (!Number.isFinite(n)) throw new ErreurJson("nombre_non_representable", `nombre sans représentation JSON (${n})`);
  // Number::toString d'ES6 ; String(-0) vaut déjà "0".
  return String(n);
}

function estObjetSimple(v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/**
 * Forme canonique JCS intégral d'une valeur JSON (EX-8.1). Écriture
 * itérative : aucune imbrication n'épuise la pile ; une structure cyclique,
 * un tableau à trou, un membre indéfini, un nombre non fini et un substitut
 * isolé sont refusés.
 * @param {unknown} racine
 * @returns {string}
 * @throws {ErreurJson}
 */
export function jcsIntegral(racine) {
  const sortie = [];
  const enCours = new Set();
  const pile = [{ valeur: racine }];
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
    const v = tache.valeur;
    if (v === null) {
      sortie.push("null");
      continue;
    }
    switch (typeof v) {
      case "boolean":
        sortie.push(v ? "true" : "false");
        continue;
      case "number":
        sortie.push(ecrireNombre(v));
        continue;
      case "string":
        sortie.push(ecrireChaine(v));
        continue;
      case "object": {
        if (enCours.has(v)) throw new ErreurJson("type", "structure cyclique");
        if (Array.isArray(v)) {
          for (let k = 0; k < v.length; k++) if (!(k in v)) throw new ErreurJson("type", "tableau à trou");
          enCours.add(v);
          pile.push({ sortie: v }, { texte: "]" });
          for (let k = v.length - 1; k >= 0; k--) {
            pile.push({ valeur: v[k] });
            if (k > 0) pile.push({ texte: "," });
          }
          sortie.push("[");
          continue;
        }
        if (!estObjetSimple(v)) throw new ErreurJson("type", "objet JSON simple attendu");
        const cles = Object.keys(v).sort();
        for (const cle of cles) if (v[cle] === undefined) throw new ErreurJson("type", `membre ${JSON.stringify(cle)} indéfini`);
        enCours.add(v);
        pile.push({ sortie: v }, { texte: "}" });
        for (let k = cles.length - 1; k >= 0; k--) {
          pile.push({ valeur: v[cles[k]] }, { texte: ecrireChaine(cles[k]) + ":" });
          if (k > 0) pile.push({ texte: "," });
        }
        sortie.push("{");
        continue;
      }
      default:
        throw new ErreurJson("type", `type ${typeof v} non représentable en JSON`);
    }
  }
  return sortie.join("");
}

/**
 * JCS intégral encodé en UTF-8 : les octets d'une pièce JSON (EX-8.2).
 * @param {unknown} valeur
 * @returns {Uint8Array}
 */
export function jcsIntegralOctets(valeur) {
  return utf8(jcsIntegral(valeur));
}

/**
 * Lit un texte JSON reçu (RFC 8259) avec les refus de la lecture stricte
 * (clé en double, substitut isolé), nombres non entiers admis.
 * @param {string|Uint8Array} source
 * @param {{profondeurMax?: number}} [options]
 * @returns {unknown}
 * @throws {ErreurJson}
 */
export function analyserJsonIntegral(source, options = {}) {
  return analyserJson(source, { nombres: "libres", profondeurMax: options.profondeurMax });
}

/**
 * Forme canonique JCS intégral d'un texte JSON, ou null s'il n'en a pas (pas
 * du JSON, clé en double, substitut isolé, nombre qui déborde la double).
 * @param {string|Uint8Array} source
 * @returns {string|null}
 */
export function canoniserTexteIntegral(source) {
  try {
    return jcsIntegral(analyserJsonIntegral(source));
  } catch (e) {
    if (e instanceof ErreurJson) return null;
    throw e;
  }
}
