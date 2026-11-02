// Validation de la politique d'approbation par le démon (CT-2 EX-15.4 pas 3,
// CT-3 EX-4.2 et EX-8.2) : le membre `/policy/approval/rules` est un document
// `politique-approbation-v0` que CT-2 valide sans l'évaluer. Un document
// refusé l'est avant d'être annoncé dans la chaîne (pas 6), plutôt
// qu'annoncé puis refusé par le service, ce qui bloquerait tout outil
// susceptible d'approbation.
//
// Ordre de CT-3 EX-4.2 : le schéma d'abord (un document non conforme donne
// exactement une erreur `schema`, pointeur nul, et aucune autre) ; sur un
// document conforme, toutes les erreurs des points 1 à 7, chacune avec un
// code de `$defs/code_erreur_politique` de `ticket-v0` et le pointeur JSON
// du membre fautif, triées par pointeur puis par code (unités UTF-16, sans
// ordre numérique des indices, annexe A.4 de CT-3).
//
// Les avertissements d'EX-4.14 qui ne dépendent pas de la liste des outils
// annoncés sont rapportés sans refuser (CT-2 EX-15.4 pas 3) ; celui d'un
// sélecteur qui ne désigne aucun outil est écrit par le service à `charger`.

import { IDS, registreSchemas } from "../schema.mjs";

/** Bornes de CT-3 EX-4.2 (points 2 et 3). */
export const BORNES_POLITIQUE = Object.freeze({ jetonsPointeur: 32, profondeur: 8, predicats: 64 });

const echapper = (s) => String(s).replace(/~/g, "~0").replace(/\//g, "~1");

/** Comparaison des chaînes en unités UTF-16 (ordre de Array.prototype.sort). */
const comparerUtf16 = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** Chaîne bien formée : aucun substitut isolé (CT-1 §4, règle 3). */
export function chaineSansSubstitut(s) {
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

/** Nombre de jetons d'un pointeur JSON (`/arguments/a` en a deux). */
export function jetonsPointeur(p) {
  return p === "" ? 0 : p.split("/").length - 1;
}

/** Prédicat (feuille) d'une condition. */
const estPredicat = (c) => c !== null && typeof c === "object" && "op" in c && "path" in c;

/** Combinaison d'une condition : [clé, éléments] ou null. */
function combinaison(c) {
  for (const k of ["all", "any", "none"]) if (c && Array.isArray(c[k])) return [k, c[k]];
  return null;
}

/**
 * Parcourt une condition : profondeur (un prédicat seul est au niveau 1,
 * chaque combinaison ajoute un niveau), prédicats avec leur pointeur JSON et
 * le nombre de `none` qui les englobent.
 * @param {object} c
 * @param {string} ptr pointeur JSON de la condition
 * @returns {{profondeur: number, predicats: {p: object, ptr: string, none: number}[]}}
 */
export function parcourirCondition(c, ptr) {
  const predicats = [];
  const visiter = (x, px, none) => {
    if (estPredicat(x)) {
      predicats.push({ p: x, ptr: px, none });
      return 1;
    }
    const cb = combinaison(x);
    if (!cb) return 1;
    const [k, elements] = cb;
    let m = 0;
    elements.forEach((e, i) => {
      m = Math.max(m, visiter(e, `${px}/${k}/${i}`, none + (k === "none" ? 1 : 0)));
    });
    return m + 1;
  };
  const profondeur = c === null ? 0 : visiter(c, ptr, 0);
  return { profondeur, predicats };
}

/**
 * Validation d'un document `politique-approbation-v0` (CT-3 EX-4.2, EX-8.2).
 * @param {unknown} doc
 * @param {{environment: string, expire_after_ms: number, schema?: boolean}} o
 *   `environment` : `recorder.environment` ; `expire_after_ms` :
 *   `/policy/approval/expire_after_ms` ; `schema: false` saute le schéma
 *   (déjà vérifié avec la configuration, EX-15.4 pas 2)
 * @returns {{code: string, pointer: string|null}[]} erreurs triées (vide : valide)
 */
export function validerPolitiqueApprobation(doc, o) {
  if (o.schema !== false && !registreSchemas().valider(IDS.approbation, doc).valide) return [{ code: "schema", pointer: null }];
  const erreurs = [];
  const err = (code, pointer) => erreurs.push({ code, pointer });

  // 1. Noms uniques, règle par défaut comprise (lue la première).
  const noms = new Set([doc.default.name]);
  doc.rules.forEach((r, i) => {
    if (noms.has(r.name)) err("nom_double", `/rules/${i}/name`);
    noms.add(r.name);
  });

  // 2. et 3. Pointeurs, profondeur et nombre de prédicats.
  doc.rules.forEach((r, i) => {
    if (r.when !== null) {
      const { profondeur, predicats } = parcourirCondition(r.when, `/rules/${i}/when`);
      for (const { p, ptr } of predicats) if (jetonsPointeur(p.path) > BORNES_POLITIQUE.jetonsPointeur) err("pointeur_trop_long", `${ptr}/path`);
      if (profondeur > BORNES_POLITIQUE.profondeur) err("condition_trop_profonde", `/rules/${i}/when`);
      if (predicats.length > BORNES_POLITIQUE.predicats) err("trop_de_predicats", `/rules/${i}/when`);
    }
    (r.window?.same_arguments ?? []).forEach((p, k) => {
      if (jetonsPointeur(p) > BORNES_POLITIQUE.jetonsPointeur) err("pointeur_trop_long", `/rules/${i}/window/same_arguments/${k}`);
    });
  });

  // 4. Chaînes bien formées (clés et valeurs).
  const chaines = (v, ptr) => {
    if (typeof v === "string") {
      if (!chaineSansSubstitut(v)) err("substitut_isole", ptr);
    } else if (Array.isArray(v)) {
      v.forEach((x, k) => chaines(x, `${ptr}/${k}`));
    } else if (v !== null && typeof v === "object") {
      for (const [k, x] of Object.entries(v)) {
        if (!chaineSansSubstitut(k)) err("substitut_isole", `${ptr}/${echapper(k)}`);
        chaines(x, `${ptr}/${echapper(k)}`);
      }
    }
  };
  chaines(doc, "");

  // 5. Un launched_by une seule fois dans separation.identities.
  const vus = new Set();
  doc.separation.identities.forEach((id, k) => {
    if (vus.has(id.launched_by)) err("launched_by_double", `/separation/identities/${k}/launched_by`);
    vus.add(id.launched_by);
  });

  // 6. contest_ms < expire_after_ms (5.6).
  const E = o.expire_after_ms;
  if (doc.default.contest_ms !== null && !(doc.default.contest_ms < E)) err("contest_ms_trop_long", "/default/contest_ms");
  doc.rules.forEach((r, i) => {
    if (r.contest_ms !== null && !(r.contest_ms < E)) err("contest_ms_trop_long", `/rules/${i}/contest_ms`);
  });

  // 7. Jeu d'approbateurs (EX-8.2).
  const j = doc.approver_set;
  if (j.source === "statique") {
    if (j.threshold.size !== j.members.length || j.threshold.required > j.threshold.size) err("seuil_statique_incoherent", "/approver_set/threshold");
    if (o.environment === "production") err("jeu_statique_en_production", "/approver_set/source");
  }

  return erreurs.sort((a, b) => comparerUtf16(a.pointer, b.pointer) || comparerUtf16(a.code, b.code));
}

/**
 * Avertissements d'EX-4.14 de CT-3 qui ne dépendent pas de la liste des
 * outils annoncés (CT-2 EX-15.4 pas 3) : diagnostics, sans refus.
 * @param {object} doc document conforme
 * @param {{requesters?: string[], redaction?: object|null}} [o]
 *   `requesters` : `launched_by` fixes des connexions d'hôte (EX-7.15) ;
 *   `redaction` : politique de rédaction de l'ensemble
 * @returns {{code: string, pointer: string}[]}
 */
export function avertissementsPolitiqueApprobation(doc, o = {}) {
  const av = [];
  const a = (code, pointer) => av.push({ code, pointer });
  // Chemins que la rédaction rédige ou supprime dans les arguments (détecteur champ).
  const chemins = [];
  for (const r of o.redaction?.rules ?? []) {
    if (typeof r.path === "string" && (r.scopes ?? []).includes("arguments") && (r.detectors ?? []).some((d) => d.type === "champ")) chemins.push(`/arguments${r.path}`);
  }
  const vise = (p) => chemins.some((c) => p === c || p.startsWith(`${c}/`) || c.startsWith(`${p}/`));
  doc.rules.forEach((r, i) => {
    const { predicats } = r.when === null ? { predicats: [] } : parcourirCondition(r.when, `/rules/${i}/when`);
    for (const { p, ptr, none } of predicats) {
      if (vise(p.path)) a("pointeur_redige", `${ptr}/path`);
      // Liste d'exclusion : egal ou dans sous un nombre pair de none d'une règle automatique refuse.
      if (r.level === "automatique" && r.decision === "refuse" && (p.op === "egal" || p.op === "dans") && none % 2 === 0) a("liste_exclusion", ptr);
    }
    if (r.level === "fenetre") {
      if (r.tools.length > 1 || r.tools.some((t) => t.endsWith("*"))) a("fenetre_plusieurs_outils", `/rules/${i}/tools`);
      if (r.window.same_arguments.length === 0) a("fenetre_sans_same_arguments", `/rules/${i}/window/same_arguments`);
      if (r.when === null) a("fenetre_sans_condition", `/rules/${i}/when`);
      (r.window.same_arguments ?? []).forEach((p, k) => {
        if (vise(p)) a("pointeur_redige", `/rules/${i}/window/same_arguments/${k}`);
      });
    }
  });
  if (doc.separation.self_approval === "interdite") {
    const connus = new Set(doc.separation.identities.map((x) => x.launched_by));
    for (const l of o.requesters ?? []) if (!connus.has(l)) a("demandeur_sans_identite", "/separation/identities");
  }
  return av;
}

/** `launched_by` fixes des connexions d'hôte (`mcp.hosts`, `sdk.hosts`), triés, sans doublon (EX-7.15). */
export function demandeursFixes(config) {
  const l = [...(config.mcp?.hosts ?? []), ...(config.sdk?.hosts ?? [])].map((h) => h.launched_by).filter((x) => typeof x === "string" && !x.includes("${"));
  return [...new Set(l)].sort(comparerUtf16);
}

/**
 * Règle du pas 3 d'EX-15.4 pour `validerConfiguration(octets, {
 * reglesSupplementaires })` : erreurs de CT-3 EX-4.2 et EX-8.2 sous
 * `/policy/approval/rules`, avertissements d'EX-4.14.
 * @param {object} c document de configuration (conforme au schéma)
 * @returns {{erreurs: object[], avertissements: object[]}}
 */
export function controlePolitiqueApprobation(c) {
  const doc = c?.policy?.approval?.rules;
  if (!doc || typeof doc !== "object") return { erreurs: [], avertissements: [] };
  const base = "/policy/approval/rules";
  const erreurs = validerPolitiqueApprobation(doc, { environment: c.recorder.environment, expire_after_ms: c.policy.approval.expire_after_ms }).map((e) => ({
    pointeur: e.pointer === null ? base : `${base}${e.pointer}`,
    regle: `${e.code} (CT-3 EX-4.2)`,
    valeur: undefined,
  }));
  if (erreurs.length) return { erreurs, avertissements: [] };
  const avertissements = avertissementsPolitiqueApprobation(doc, { requesters: demandeursFixes(c), redaction: c.policy.redaction ?? null }).map((x) => ({
    pointeur: `${base}${x.pointer}`,
    regle: `${x.code} (CT-3 EX-4.14)`,
    valeur: undefined,
  }));
  return { erreurs, avertissements };
}
