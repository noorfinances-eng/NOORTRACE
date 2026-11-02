// JSON du service (CT-3 EX-12.1) : lecture stricte d'un corps reçu (clés
// uniques, aucun substitut isolé, nombres quelconques mais finis), écriture
// JCS intégral (CT-2 §8.1 : RFC 8785, nombres par la règle ES6
// Number::toString), qui sert aussi à la clé de rapprochement (EX-7.3).
//
// La lecture stricte est celle du noyau (`analyserJson`, option
// `nombres: "libres"`) ; ce module n'y ajoute que le refus d'un nombre qui
// déborde la double précision (1e400 se lit Infinity), qu'aucune forme JSON
// ne réécrit.

import { ErreurJson, analyserJson, chaineBienFormee, egaliteJson } from "@noortrace/noyau";

export { egaliteJson };

/**
 * Lit un texte JSON strict (EX-12.1).
 * @param {string|Uint8Array} source
 * @param {{substituts?: "refuses"|"admis", profondeurMax?: number}} [options]
 * @returns {unknown}
 * @throws {ErreurJson}
 */
export function lireJsonStrict(source, options = {}) {
  const v = analyserJson(source, {
    nombres: "libres",
    substituts: options.substituts ?? "refuses",
    profondeurMax: options.profondeurMax ?? 256,
  });
  verifierNombresFinis(v);
  return v;
}

function verifierNombresFinis(racine) {
  const pile = [racine];
  while (pile.length) {
    const v = pile.pop();
    if (typeof v === "number") {
      if (!Number.isFinite(v)) throw new ErreurJson("nombre_non_representable", "nombre hors de la double précision");
    } else if (Array.isArray(v)) {
      for (const x of v) pile.push(x);
    } else if (v !== null && typeof v === "object") {
      for (const x of Object.values(v)) pile.push(x);
    }
  }
}

const ECHAPPEMENTS = { 0x08: "\\b", 0x09: "\\t", 0x0a: "\\n", 0x0c: "\\f", 0x0d: "\\r", 0x22: '\\"', 0x5c: "\\\\" };

function ecrireChaine(s) {
  if (!chaineBienFormee(s)) throw new ErreurJson("substitut_isole", "substitut isolé dans une chaîne");
  let sortie = '"';
  let debut = 0;
  for (let k = 0; k < s.length; k++) {
    const c = s.charCodeAt(k);
    if (c < 0x20 || c === 0x22 || c === 0x5c) {
      sortie += s.slice(debut, k) + (ECHAPPEMENTS[c] ?? "\\u" + c.toString(16).padStart(4, "0"));
      debut = k + 1;
    }
  }
  return sortie + s.slice(debut) + '"';
}

/**
 * Forme JCS intégral d'une valeur JSON (CT-2 EX-8.1). Écriture itérative.
 * @param {unknown} racine
 * @returns {string}
 * @throws {ErreurJson} nombre non fini, substitut isolé, valeur non JSON, cycle
 */
export function jcsIntegral(racine) {
  const sortie = [];
  const enCours = new Set();
  const pile = [{ v: racine }];
  while (pile.length) {
    const t = pile.pop();
    if (t.texte !== undefined) {
      sortie.push(t.texte);
      continue;
    }
    if (t.fin !== undefined) {
      enCours.delete(t.fin);
      continue;
    }
    const v = t.v;
    if (v === null) sortie.push("null");
    else if (typeof v === "boolean") sortie.push(v ? "true" : "false");
    else if (typeof v === "number") {
      if (!Number.isFinite(v)) throw new ErreurJson("nombre_non_representable", "nombre non fini");
      sortie.push(String(v));
    } else if (typeof v === "string") sortie.push(ecrireChaine(v));
    else if (Array.isArray(v) || typeof v === "object") {
      if (enCours.has(v)) throw new ErreurJson("cycle", "structure cyclique");
      enCours.add(v);
      const taches = [];
      if (Array.isArray(v)) {
        for (let k = 0; k < v.length; k++) {
          if (!(k in v)) throw new ErreurJson("trou", "tableau à trou");
          if (k > 0) taches.push({ texte: "," });
          taches.push({ v: v[k] });
        }
        pile.push({ fin: v }, { texte: "]" }, ...taches.reverse(), { texte: "[" });
      } else {
        const cles = Object.keys(v).sort();
        cles.forEach((c, k) => {
          if (v[c] === undefined) throw new ErreurJson("indefini", `membre ${c} indéfini`);
          if (k > 0) taches.push({ texte: "," });
          taches.push({ texte: ecrireChaine(c) + ":" }, { v: v[c] });
        });
        pile.push({ fin: v }, { texte: "}" }, ...taches.reverse(), { texte: "{" });
      }
    } else {
      throw new ErreurJson("non_json", `valeur non JSON (${typeof v})`);
    }
  }
  return sortie.join("");
}

/**
 * Copie profonde d'une valeur JSON (objets à prototype ordinaire, `__proto__`
 * gardé comme membre).
 * @template T
 * @param {T} v
 * @returns {T}
 */
export function cloner(v) {
  if (v === null || typeof v !== "object") return v;
  if (Array.isArray(v)) return v.map(cloner);
  const r = {};
  for (const [k, x] of Object.entries(v)) {
    if (k === "__proto__") Object.defineProperty(r, k, { value: cloner(x), enumerable: true, writable: true, configurable: true });
    else r[k] = cloner(x);
  }
  return r;
}

/** Ordre des chaînes par unités de code UTF-16 (CT-1 §4, CT-3 A.4). */
export function comparerChaines(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Longueur en points de code (CT-3 EX-9.10 : motif compté en points de code). */
export function longueurPointsDeCode(s) {
  let n = 0;
  for (const _ of s) n++;
  return n;
}
