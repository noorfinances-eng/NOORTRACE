// Évaluation de la politique d'approbation (CT-3 §4.4 à §4.12, §5.3, §6) :
// sélection de l'outil, pointeurs, typage numérique et comparaisons exactes
// en entiers de précision arbitraire, chaînes et booléens, prédicats, logique
// à trois valeurs de Kleene, issue d'une règle, chaîne `policy.rule`,
// algorithme EVALUER, portée et usage des fenêtres, CANDIDATS.
//
// EVALUER ne lit de la demande que le nom annoncé, les arguments en clair et
// `delegation.launched_by` (EX-3.5) ; il ne dépend d'aucun flottant, d'aucun
// ordre de table de hachage ni de l'ordre des membres d'un objet (EX-6.6).
// Il rend la copie des fenêtres après l'évaluation ; il n'a pas d'effet : la
// consommation d'une unité est appliquée par l'appelant (EX-6.5).

import { decoderHorodatage, ecrireHorodatage } from "@noortrace/noyau";
import { cloner, egaliteJson } from "./json.mjs";

export const VRAI = "VRAI";
export const FAUX = "FAUX";
export const INDETERMINE = "INDETERMINE";

// ------------------------------------------------------------ sélection (EX-4.3)

/**
 * Un sélecteur désigne-t-il le nom annoncé ? Nom exact, casse comprise ;
 * préfixe suivi d'un seul `*` final ; `*` seul.
 * @param {string[]} selecteurs
 * @param {string} nom
 */
export function selectionne(selecteurs, nom) {
  return selecteurs.some((s) => (s.endsWith("*") ? nom.startsWith(s.slice(0, -1)) : s === nom));
}

// ------------------------------------------------------------ pointeurs (EX-4.4)

const INDICE = /^(0|[1-9][0-9]{0,8})$/;

/**
 * Résout un pointeur JSON sur R = { arguments: A }.
 * @param {string} p
 * @param {unknown} R
 * @returns {{resolu: boolean, valeur?: unknown}}
 */
export function resoudre(p, R) {
  if (p === "") return { resolu: true, valeur: R };
  const jetons = p.slice(1).split("/").map((j) => j.replace(/~1/g, "/").replace(/~0/g, "~"));
  let x = R;
  for (const j of jetons) {
    if (x !== null && typeof x === "object" && !Array.isArray(x) && Object.prototype.hasOwnProperty.call(x, j)) {
      x = x[j];
    } else if (Array.isArray(x) && INDICE.test(j) && Number(j) < x.length) {
      x = x[Number(j)];
    } else {
      return { resolu: false };
    }
  }
  return { resolu: true, valeur: x };
}

// ------------------------------------------------------------ nombres (EX-4.5, EX-4.6)

export const GRAMMAIRE_DECIMALE = /^-?(0|[1-9][0-9]{0,29})(\.[0-9]{1,18})?$/;
const SUR = 2 ** 53 - 1;

/**
 * Valeur numérique (m, e) d'une valeur résolue, ou null si elle n'est pas
 * numérique : nombre JSON entier de [-(2^53-1), 2^53-1], ou chaîne de la
 * grammaire D. Aucune conversion par flottant.
 * @param {unknown} v
 * @returns {{m: bigint, e: number}|null}
 */
export function numerique(v) {
  if (typeof v === "number") {
    if (!Number.isInteger(v) || Math.abs(v) > SUR) return null;
    return { m: BigInt(v), e: 0 };
  }
  if (typeof v === "string" && GRAMMAIRE_DECIMALE.test(v)) {
    const point = v.indexOf(".");
    const e = point < 0 ? 0 : v.length - point - 1;
    return { m: BigInt(v.replace(".", "")), e };
  }
  return null;
}

/**
 * Compare deux valeurs numériques exactes.
 * @returns {-1|0|1}
 */
export function comparer(a, b) {
  const E = Math.max(a.e, b.e);
  const x = a.m * 10n ** BigInt(E - a.e);
  const y = b.m * 10n ** BigInt(E - b.e);
  return x < y ? -1 : x > y ? 1 : 0;
}

// ------------------------------------------------------------ prédicats (table 4.9)

const typeJson = (v) => (v === null ? "null" : Array.isArray(v) ? "array" : typeof v);

/**
 * Valeur d'un prédicat sur R.
 * @param {{path: string, op: string, value: unknown}} pr
 * @param {unknown} R
 * @returns {"VRAI"|"FAUX"|"INDETERMINE"}
 */
export function predicat(pr, R) {
  const r = resoudre(pr.path, R);
  if (pr.op === "existe") return r.resolu ? VRAI : FAUX;
  if (!r.resolu) return INDETERMINE;
  const v = r.valeur;
  const bool = (b) => (b ? VRAI : FAUX);
  switch (pr.op) {
    case "egal":
      if (typeJson(v) !== typeJson(pr.value)) return INDETERMINE;
      return bool(v === pr.value);
    case "dans":
      if (typeof v !== "string") return INDETERMINE;
      return bool(pr.value.includes(v));
    case "commence_par":
      if (typeof v !== "string") return INDETERMINE;
      return bool(v.startsWith(pr.value));
    case "finit_par":
      if (typeof v !== "string") return INDETERMINE;
      return bool(v.endsWith(pr.value));
    default: {
      const n = numerique(v);
      if (n === null) return INDETERMINE;
      const c = comparer(n, numerique(pr.value));
      switch (pr.op) {
        case "egal_numerique": return bool(c === 0);
        case "strictement_superieur": return bool(c > 0);
        case "superieur_ou_egal": return bool(c >= 0);
        case "strictement_inferieur": return bool(c < 0);
        case "inferieur_ou_egal": return bool(c <= 0);
        default: throw new RangeError(`opérateur inconnu : ${pr.op}`);
      }
    }
  }
}

/**
 * Valeur d'une condition (EX-4.8, logique de Kleene ; indépendante de l'ordre).
 * @param {object} c
 * @param {unknown} R
 */
export function valeur(c, R) {
  if (Array.isArray(c.all)) {
    const vs = c.all.map((x) => valeur(x, R));
    if (vs.includes(FAUX)) return FAUX;
    return vs.includes(INDETERMINE) ? INDETERMINE : VRAI;
  }
  if (Array.isArray(c.any)) {
    const vs = c.any.map((x) => valeur(x, R));
    if (vs.includes(VRAI)) return VRAI;
    return vs.includes(INDETERMINE) ? INDETERMINE : FAUX;
  }
  if (Array.isArray(c.none)) {
    const vs = c.none.map((x) => valeur(x, R));
    if (vs.includes(VRAI)) return FAUX;
    return vs.includes(INDETERMINE) ? INDETERMINE : VRAI;
  }
  return predicat(c, R);
}

/** ET de deux valeurs (all à deux éléments). */
export function et(a, b) {
  if (a === FAUX || b === FAUX) return FAUX;
  if (a === INDETERMINE || b === INDETERMINE) return INDETERMINE;
  return VRAI;
}

// ------------------------------------------------------------ portée et fenêtres (EX-5.2 à EX-5.6)

/**
 * Portée K d'une demande pour une règle `fenetre`, ou null si elle est
 * indéterminée (pointeur non résolu ou valeur qui n'est pas une chaîne).
 * @param {object} regle
 * @param {object} d requête evaluer
 * @param {unknown} R
 */
export function portee(regle, d, R) {
  const values = [];
  for (const p of regle.window.same_arguments) {
    const r = resoudre(p, R);
    if (!r.resolu || typeof r.valeur !== "string") return null;
    values.push(r.valeur);
  }
  return {
    policy_version: d.code.policy_version,
    rule: regle.name,
    tool: d.tool_announced,
    launched_by: d.delegation.launched_by,
    values,
  };
}

/**
 * Fenêtre qui couvre la demande à l'instant t (EX-5.5), ou null.
 * @param {object[]} fenetres état F
 * @param {object} K portée de la demande
 * @param {number} t instant en millisecondes
 */
export function fenetreCouvrante(fenetres, K, t) {
  return (
    fenetres.find(
      (w) => egaliteJson(w.scope, K) && decoderHorodatage(w.start) <= t && t < decoderHorodatage(w.end) && w.remaining >= 1,
    ) ?? null
  );
}

// ------------------------------------------------------------ issue et EVALUER (6.2 à 6.4)

/**
 * ISSUE(r, v, d, F, t) de la table 6.3.
 * @returns {{k: number, x?: string, m?: string, fenetre?: object, K?: object|null}}
 */
export function issue(r, v, d, F, t, K) {
  if (r.level === "automatique") {
    if (r.decision === "autorise") return v === VRAI ? { k: 1, x: "autorise", m: "" } : { k: 0 };
    return { k: 5, x: "refuse", m: v === VRAI ? "" : " [indetermine]" };
  }
  if (r.level === "revue") return { k: 4, x: "a_approuver", m: v === VRAI ? "" : " [indetermine]" };
  // fenetre
  if (v !== VRAI) return { k: 3, x: "a_approuver", m: " [indetermine]" };
  const w = fenetreCouvrante(F, K, t);
  if (w) return { k: 2, x: "autorise", m: ` [fenetre ${w.ticket} ${w.end}]`, fenetre: w };
  return { k: 3, x: "a_approuver", m: "" };
}

/**
 * EVALUER(P, d, F, t) de 6.2. Sans effet : `windows` est la copie de F après
 * la consommation éventuelle (une fenêtre épuisée y reste, remaining 0).
 * @param {object} P politique valide
 * @param {object} d requête evaluer (CT-2 EX-7.4)
 * @param {object[]} F fenêtres ouvertes ($defs/fenetre_ouverte)
 * @param {number} t instant d'évaluation en millisecondes
 * @returns {{rule: string, decision: string, contest_ms: number|null, opening: object|null,
 *   windows: object[], fenetre: string|null}} `fenetre` : ticket de la fenêtre consommée
 */
export function evaluer(P, d, F, t) {
  const R = { arguments: d.arguments };
  const C = [];
  P.rules.forEach((r, i) => {
    if (!selectionne(r.tools, d.tool_announced)) return;
    let v = r.when === null ? VRAI : valeur(r.when, R);
    let K = null;
    if (r.level === "fenetre") {
      K = portee(r, d, R);
      v = et(v, K !== null ? VRAI : INDETERMINE);
    }
    if (v === FAUX) return;
    const o = issue(r, v, d, F, t, K);
    if (o.k > 0) C.push({ ...o, i, K });
  });
  const windows = cloner(F);
  if (C.length === 0) {
    const decision = P.default.level === "automatique" ? P.default.decision : "a_approuver";
    return {
      rule: P.default.name,
      decision,
      contest_ms: decision === "a_approuver" ? P.default.contest_ms : null,
      opening: null,
      windows,
      fenetre: null,
    };
  }
  const kMax = Math.max(...C.map((c) => c.k));
  const retenue = C.filter((c) => c.k === kMax).sort((a, b) => a.i - b.i)[0];
  const r = P.rules[retenue.i];
  let fenetre = null;
  if (kMax === 2) {
    const w = windows.find((x) => x.ticket === retenue.fenetre.ticket && egaliteJson(x.scope, retenue.fenetre.scope));
    w.remaining -= 1;
    fenetre = w.ticket;
  }
  const decision = retenue.x;
  let opening = null;
  if (decision === "a_approuver" && kMax === 3 && retenue.m === "") {
    opening = { scope: retenue.K, duration_ms: r.window.duration_ms, max_calls: r.window.max_calls };
  }
  return {
    rule: r.name + retenue.m,
    decision,
    contest_ms: decision === "a_approuver" ? r.contest_ms : null,
    opening,
    windows,
    fenetre,
  };
}

/**
 * Ticket de la fenêtre nommée par la marque ` [fenetre <ticket> <fin>]` d'une
 * chaîne `policy.rule` (lue après la dernière occurrence de ` [`), ou null.
 * @param {string|null} rule
 */
export function fenetreDeMarque(rule) {
  if (typeof rule !== "string") return null;
  const k = rule.lastIndexOf(" [");
  if (k < 0) return null;
  const m = /^ \[fenetre (apr-[0-9a-z]+(?:-[0-9a-z]+)*) ([0-9T:.\-Z]+)\]$/.exec(rule.slice(k));
  return m ? { ticket: m[1], fin: m[2] } : null;
}

// ------------------------------------------------------------ outils susceptibles (EX-4.11)

/**
 * CANDIDATS(P, L) : noms de L, dans l'ordre de L, sans doublon, qu'une règle
 * peut soumettre à approbation ou refuser, quels que soient les arguments.
 * @param {object} P
 * @param {string[]} L
 * @returns {string[]}
 */
export function candidats(P, L) {
  const vus = new Set();
  const sortie = [];
  const defautPermissif = P.default.level === "automatique" && P.default.decision === "autorise";
  for (const nom of L) {
    if (vus.has(nom)) continue;
    vus.add(nom);
    const regles = P.rules.filter((r) => selectionne(r.tools, nom));
    const c1 = regles.some((r) => r.level === "fenetre" || r.level === "revue" || r.decision === "refuse");
    const c2 = !defautPermissif && !regles.some((r) => r.when === null);
    if (c1 || c2) sortie.push(nom);
  }
  return sortie;
}

/** Fin d'une fenêtre ouverte à `debut` pour `duree` millisecondes (EX-5.4). */
export function finFenetre(debut, duree) {
  return ecrireHorodatage(decoderHorodatage(debut) + duree);
}
