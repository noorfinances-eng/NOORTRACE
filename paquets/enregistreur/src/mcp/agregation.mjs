// Agrégation de `tools/list` (CT-2 §4.3) : nom annoncé `<alias>__<nom
// d'origine>` (EX-4.10), rejets d'EX-4.11 (nom réservé, nom invalide,
// collision y compris après gabarit et normalisation d'une connexion d'hôte,
// propriété `x-mcp-header` invalide en transport HTTP), classe d'un outil
// (EX-14.1), empreinte de chaque définition annoncée (EX-4.16), ordre
// déterministe par alias puis nom d'origine en unités UTF-16 et pages de
// `tools.page_size` outils (EX-4.13).

import { sha256Hex } from "@noortrace/noyau";
import { jcsIntegralOctets } from "../jcs-integral.mjs";

/** Motif d'`execution.tool` de CT-1 (EX-4.10). */
export const MOTIF_NOM_CT1 = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;

/** Motif d'un alias de serveur (EX-4.9). */
export const MOTIF_ALIAS = /^[a-z0-9][a-z0-9-]{0,31}$/;

/** Raisons fixes d'un rejet (EX-4.11, annexe B). */
export const RAISONS_REJET = Object.freeze(["nom_reserve", "nom_invalide", "collision", "x_mcp_header"]);

/** Comparaison par unités UTF-16 (CT-1 §4). */
export function comparerUtf16(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Nom annoncé d'un outil (EX-4.10).
 * @param {string} alias
 * @param {string} original
 * @param {boolean} prefixe `tools.prefix`
 */
export function nomAnnonce(alias, original, prefixe) {
  return prefixe ? `${alias}__${original}` : original;
}

/**
 * Nom vu par le modèle sous le gabarit et la normalisation d'une connexion
 * d'hôte (EX-4.11 règle 3, EX-5.22) : `{alias}`, `{tool}`, `{tool_announced}`
 * substitués ; `sanitize` remplace par `_` tout caractère hors
 * `A-Z a-z 0-9 _ -`.
 * @param {{template: string, sanitize: boolean}} n
 * @param {{alias: string, original: string, announced: string}} o
 * @returns {string}
 */
export function nomNormalise(n, o) {
  const brut = n.template.replace(/\{(alias|tool|tool_announced)\}/g, (_, k) => (k === "alias" ? o.alias : k === "tool" ? o.original : o.announced));
  return n.sanitize ? brut.replace(/[^A-Za-z0-9_-]/g, "_") : brut;
}

/**
 * Classe d'un outil (EX-14.1) : configuration de l'outil, du serveur, puis
 * `readOnlyHint: true` (indication non fiable), à défaut `ecriture`.
 * @param {object|undefined} serveur `policy.servers.<alias>`
 * @param {string} original
 * @param {object|undefined} definition
 * @returns {"lecture"|"ecriture"}
 */
export function classeOutil(serveur, original, definition) {
  const c = serveur?.tools?.[original]?.class;
  if (c) return c;
  if (serveur?.class_default) return serveur.class_default;
  return definition?.annotations?.readOnlyHint === true ? "lecture" : "ecriture";
}

/**
 * Propriétés `x-mcp-header` d'une définition (EX-4.35) : `[{ propriete, entete }]`.
 * @param {object} definition
 */
export function entetesParametres(definition) {
  const props = definition?.inputSchema?.properties;
  if (!props || typeof props !== "object" || Array.isArray(props)) return [];
  const r = [];
  for (const [p, s] of Object.entries(props)) {
    if (s && typeof s === "object" && "x-mcp-header" in s) r.push({ propriete: p, entete: s["x-mcp-header"], schema: s });
  }
  return r;
}

/**
 * Contraintes d'une propriété `x-mcp-header` (EX-4.11 règle 4) : nom
 * d'en-tête jeton RFC 9110, sans doublon (casse ignorée), propriété de type
 * primitif. Lecture consignée au LISEZMOI (la page Streamable HTTP n'est pas
 * citée mot pour mot par CT-2).
 * @param {object} definition
 * @returns {boolean}
 */
export function entetesValides(definition) {
  const vus = new Set();
  for (const { entete, schema } of entetesParametres(definition)) {
    if (typeof entete !== "string" || !/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/.test(entete)) return false;
    const k = entete.toLowerCase();
    if (vus.has(k)) return false;
    vus.add(k);
    const t = schema.type;
    if (t !== undefined && !["string", "number", "integer", "boolean"].includes(t)) return false;
  }
  return true;
}

/**
 * Agrège les listes des serveurs.
 * @param {object} p
 * @param {{alias: string, tools: object[]}[]} p.serveurs dernière liste reçue avec succès de chaque serveur
 * @param {boolean} p.prefixe `tools.prefix`
 * @param {{template: string, sanitize: boolean}[]} [p.normalisations] gabarits des connexions d'hôte
 * @param {object} [p.configServeurs] `policy.servers`
 * @returns {{annonces: object[], rejets: object[]}}
 *   annonce : `{ server_alias, original, announced, class, definition, definition_sha256, http_admis }`
 */
export function agreger(p) {
  const rejets = [];
  const candidats = [];
  for (const s of p.serveurs) {
    for (const outil of s.tools) {
      const original = typeof outil?.name === "string" ? outil.name : null;
      if (original === null) {
        rejets.push({ server_alias: s.alias, original: String(outil?.name ?? ""), reason: "nom_invalide" });
        continue;
      }
      if (original.startsWith("noortrace.")) {
        rejets.push({ server_alias: s.alias, original, reason: "nom_reserve" });
        continue;
      }
      const announced = nomAnnonce(s.alias, original, p.prefixe);
      if (announced.length > 128 || !MOTIF_NOM_CT1.test(announced)) {
        rejets.push({ server_alias: s.alias, original, reason: "nom_invalide" });
        continue;
      }
      candidats.push({ alias: s.alias, original, announced, outil });
    }
  }
  // Règle 3 : collisions, sous l'identité et sous chaque normalisation.
  const formes = [{ template: "{tool_announced}", sanitize: false }, ...(p.normalisations ?? [])];
  const enCollision = new Set();
  for (const n of formes) {
    const groupes = new Map();
    candidats.forEach((c, k) => {
      const nom = nomNormalise(n, c);
      if (!groupes.has(nom)) groupes.set(nom, []);
      groupes.get(nom).push(k);
    });
    for (const g of groupes.values()) if (g.length > 1) for (const k of g) enCollision.add(k);
  }
  const annonces = [];
  candidats.forEach((c, k) => {
    if (enCollision.has(k)) {
      rejets.push({ server_alias: c.alias, original: c.original, reason: "collision" });
      return;
    }
    const definition = definitionAnnoncee(c.outil, c.announced);
    annonces.push({
      server_alias: c.alias,
      original: c.original,
      announced: c.announced,
      class: classeOutil(p.configServeurs?.[c.alias], c.original, definition),
      definition,
      definition_sha256: sha256Hex(jcsIntegralOctets(definition)),
      http_admis: entetesValides(definition),
    });
  });
  const ordre = (a, b) => comparerUtf16(a.server_alias, b.server_alias) || comparerUtf16(a.original, b.original);
  annonces.sort(ordre);
  rejets.sort(ordre);
  return { annonces, rejets };
}

/**
 * Définition telle qu'annoncée à l'hôte : l'objet Tool reçu du serveur, nom
 * remplacé par le nom annoncé à sa place, autres membres inchangés (EX-4.16).
 * @param {object} outil
 * @param {string} announced
 * @returns {object}
 */
export function definitionAnnoncee(outil, announced) {
  const d = {};
  for (const [k, v] of Object.entries(outil)) Object.defineProperty(d, k, { value: k === "name" ? announced : v, enumerable: true, writable: true, configurable: true });
  return d;
}

/**
 * Pages de la liste agrégée (EX-4.13).
 * @param {object[]} annonces
 * @param {number} taille
 * @returns {object[][]}
 */
export function paginer(annonces, taille) {
  const pages = [];
  for (let k = 0; k < annonces.length; k += taille) pages.push(annonces.slice(k, k + taille));
  if (!pages.length) pages.push([]);
  return pages;
}
