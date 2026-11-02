// Validation de la politique d'approbation (CT-3 §4.2, EX-4.2, EX-8.2) et
// avertissements (EX-4.14).
//
// Le schéma est vérifié d'abord : un document non conforme donne exactement
// une erreur `{ code: "schema", pointer: null }`. Sur un document conforme,
// toutes les erreurs des points 1 à 7 sont rapportées, triées par pointeur
// puis par code, chaînes comparées par unités UTF-16 (annexe A.4).

import { chaineBienFormee } from "@noortrace/noyau";
import { IDS, registreSchemas } from "./schema.mjs";
import { comparerChaines } from "./json.mjs";

const echapper = (s) => String(s).replace(/~/g, "~0").replace(/\//g, "~1");

/** Nombre de jetons d'un pointeur (après son premier caractère). */
export function jetonsPointeur(p) {
  return p === "" ? 0 : p.split("/").length - 1;
}

/** Profondeur d'une condition (EX-4.2 point 3) : un prédicat seul est au niveau 1. */
export function profondeurCondition(c) {
  const enfants = c.all ?? c.any ?? c.none;
  if (!enfants) return 1;
  return 1 + Math.max(...enfants.map(profondeurCondition));
}

/** Prédicats d'une condition, avec leur pointeur dans le document. */
export function predicats(c, ici, sortie = []) {
  for (const op of ["all", "any", "none"]) {
    if (Array.isArray(c[op])) {
      c[op].forEach((x, k) => predicats(x, `${ici}/${op}/${k}`, sortie));
      return sortie;
    }
  }
  sortie.push({ predicat: c, pointeur: ici });
  return sortie;
}

function chainesMalFormees(v, ici, sortie) {
  if (typeof v === "string") {
    if (!chaineBienFormee(v)) sortie.push(ici);
  } else if (Array.isArray(v)) {
    v.forEach((x, k) => chainesMalFormees(x, `${ici}/${k}`, sortie));
  } else if (v !== null && typeof v === "object") {
    for (const [k, x] of Object.entries(v)) chainesMalFormees(x, `${ici}/${echapper(k)}`, sortie);
  }
  return sortie;
}

/**
 * Valide un document `politique-approbation-v0` (EX-4.2, EX-8.2).
 * @param {unknown} P
 * @param {{environment: "production"|"developpement", expire_after_ms: number}} ctx
 * @returns {{code: string, pointer: string|null}[]} liste complète des erreurs, vide si le document est valide
 */
export function validerPolitique(P, ctx) {
  if (!registreSchemas().estValide(IDS.politique, P)) return [{ code: "schema", pointer: null }];
  const erreurs = [];
  const err = (code, pointer) => erreurs.push({ code, pointer });
  // 1. noms uniques, règle par défaut lue la première
  const vus = new Set([P.default.name]);
  P.rules.forEach((r, i) => {
    if (vus.has(r.name)) err("nom_double", `/rules/${i}/name`);
    vus.add(r.name);
  });
  P.rules.forEach((r, i) => {
    // 2. pointeurs d'au plus 32 jetons ; 3. profondeur et nombre de prédicats
    if (r.when !== null) {
      const ps = predicats(r.when, `/rules/${i}/when`);
      for (const { predicat, pointeur } of ps) if (jetonsPointeur(predicat.path) > 32) err("pointeur_trop_long", `${pointeur}/path`);
      if (profondeurCondition(r.when) > 8) err("condition_trop_profonde", `/rules/${i}/when`);
      if (ps.length > 64) err("trop_de_predicats", `/rules/${i}/when`);
    }
    if (r.window !== null) {
      r.window.same_arguments.forEach((p, k) => {
        if (jetonsPointeur(p) > 32) err("pointeur_trop_long", `/rules/${i}/window/same_arguments/${k}`);
      });
    }
  });
  // 4. chaînes bien formées
  for (const p of chainesMalFormees(P, "", [])) err("substitut_isole", p);
  // 5. launched_by unique dans separation.identities
  const demandeurs = new Set();
  P.separation.identities.forEach((x, k) => {
    if (demandeurs.has(x.launched_by)) err("launched_by_double", `/separation/identities/${k}/launched_by`);
    demandeurs.add(x.launched_by);
  });
  // 6. contest_ms < expire_after_ms
  if (P.default.contest_ms !== null && !(P.default.contest_ms < ctx.expire_after_ms)) err("contest_ms_trop_long", "/default/contest_ms");
  P.rules.forEach((r, i) => {
    if (r.contest_ms !== null && !(r.contest_ms < ctx.expire_after_ms)) err("contest_ms_trop_long", `/rules/${i}/contest_ms`);
  });
  // 7. jeu d'approbateurs (EX-8.2)
  const j = P.approver_set;
  if (j.source === "statique") {
    if (j.threshold.size !== j.members.length || j.threshold.required > j.threshold.size) err("seuil_statique_incoherent", "/approver_set/threshold");
    if (ctx.environment === "production") err("jeu_statique_en_production", "/approver_set/source");
  }
  return erreurs.sort((a, b) => comparerChaines(a.pointer, b.pointer) || comparerChaines(a.code, b.code));
}

function nombreDeNoneAuDessus(c, cible, n = 0) {
  if (c === cible) return n;
  for (const op of ["all", "any", "none"]) {
    if (Array.isArray(c[op])) {
      for (const x of c[op]) {
        const r = nombreDeNoneAuDessus(x, cible, n + (op === "none" ? 1 : 0));
        if (r !== null) return r;
      }
      return null;
    }
  }
  return null;
}

/**
 * Avertissements d'EX-4.14, sans effet sur la validation ni l'évaluation ; leur
 * texte n'est pas fixé par CT-3. Le deuxième point (pointeur qu'une règle de
 * rédaction `champ` rédige) n'est pas calculable ici : `charger` ne transmet
 * pas la politique de rédaction (lecture 4 du LISEZMOI).
 * @param {object} P document valide
 * @param {{outils?: string[], requesters?: string[]}} ctx
 * @returns {{code: string, pointer: string, detail: string}[]}
 */
export function avertissementsPolitique(P, ctx = {}) {
  const sortie = [];
  const avert = (code, pointer, detail) => sortie.push({ code, pointer, detail });
  const outils = ctx.outils ?? null;
  P.rules.forEach((r, i) => {
    if (outils) {
      r.tools.forEach((s, k) => {
        const touche = outils.some((n) => (s.endsWith("*") ? n.startsWith(s.slice(0, -1)) : n === s));
        if (!touche) avert("selecteur_sans_outil", `/rules/${i}/tools/${k}`, "le sélecteur ne désigne aucun outil de la liste reçue");
      });
    }
    if (r.level === "fenetre") {
      if (r.tools.length > 1 || r.tools.some((s) => s.endsWith("*"))) avert("fenetre_plusieurs_outils", `/rules/${i}/tools`, "fenêtre à plusieurs sélecteurs ou à joker");
      if (r.window.same_arguments.length === 0) avert("fenetre_sans_portee", `/rules/${i}/window/same_arguments`, "fenêtre sans same_arguments");
      if (r.when === null) avert("fenetre_sans_condition", `/rules/${i}/when`, "fenêtre sans condition");
    }
    if (r.level === "automatique" && r.decision === "refuse" && r.when !== null) {
      for (const { predicat, pointeur } of predicats(r.when, `/rules/${i}/when`)) {
        if (predicat.op !== "egal" && predicat.op !== "dans") continue;
        if (nombreDeNoneAuDessus(r.when, predicat) % 2 === 0) avert("liste_d_exclusion", pointeur, "egal ou dans sous un nombre pair de none dans un refus");
      }
    }
  });
  if (P.separation.self_approval === "interdite") {
    const declares = new Set(P.separation.identities.map((x) => x.launched_by));
    for (const d of ctx.requesters ?? []) {
      if (!declares.has(d)) avert("separation_non_verifiable", "/separation/identities", `demandeur configuré sans entrée : ${d}`);
    }
  }
  return sortie;
}
