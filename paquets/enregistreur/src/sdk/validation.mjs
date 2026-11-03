// Validation des entrées du point d'entrée SDK (CT-2 §6.2, EX-6.6) : chaque
// paramètre des méthodes `noortrace/sdk/*` est contrôlé à l'entrée, avant
// toute pièce, tout événement et tout mode dégradé ; un refus est un -32602
// dont `data.reason` dit la règle (jamais la valeur reçue). Une donnée
// d'entrée invalide n'atteint ainsi jamais la construction de l'événement
// (EX-7.1).

/** Motif d'un nom d'outil de CT-1 (`$defs/nom_outil` d'evenement-v0), 128 caractères au plus. */
export const MOTIF_NOM_OUTIL = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;

/** Motif d'une valeur de `context` (EX-6.6). */
export const MOTIF_SHA256 = /^0x[0-9a-f]{64}$/;

/** Borne d'un `intent` déclaré, en caractères (EX-6.6). */
export const INTENTION_MAX_DECLAREE = 1048576;

/** Sortes d'un document de contexte (6.2, CT-1 `context[].kind`). */
export const SORTES_CONTEXTE = Object.freeze(["document", "donnees", "memoire", "autre"]);

/** Formats de `echangeModele` (6.2). */
export const FORMATS_SDK = Object.freeze(["anthropic-messages", "openai-chat", "openai-responses", "gemini", "autre"]);

/** Actions d'un effet (CT-1 §5.3, `$defs/effect`). */
export const ACTIONS_EFFET = Object.freeze(["lecture", "ecriture", "suppression", "envoi", "execution"]);

/** Motif du libellé de fournisseur (`$defs/model_route/provider_label`, EX-5.19). */
export const MOTIF_LIBELLE = /^[a-z0-9][a-z0-9.-]{0,31}$/;

/** Motif d'un type de média de CT-1 (`type_mime`), 127 caractères au plus. */
const MOTIF_TYPE_MIME = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;

/** Paramètres admis par méthode (6.2) : un membre inconnu est refusé (aucun paramètre ajouté, 6.5). */
export const PARAMETRES = Object.freeze({
  ouvrir: ["run_id", "on_behalf_of"],
  declarerContexte: ["session", "kind", "media_type", "bytes_base64"],
  debutAppel: ["session", "tool", "arguments", "class", "context", "intent", "effects"],
  finAppel: ["call", "result", "is_error", "duration_ms"],
  echangeModele: ["session", "format", "provider_label", "request", "response", "status", "duration_ms", "is_error"],
  fermer: ["session"],
});

/** Paramètres requis par méthode. */
export const REQUIS = Object.freeze({
  ouvrir: [],
  declarerContexte: ["session", "kind", "bytes_base64"],
  debutAppel: ["session", "tool", "arguments"],
  finAppel: ["call", "is_error", "duration_ms"],
  echangeModele: ["session", "format", "provider_label", "request", "response", "duration_ms", "is_error"],
  fermer: ["session"],
});

/** Erreur de validation : `raison` va dans `data.reason` de -32602. */
export class ErreurEntree extends Error {
  /** @param {string} raison */
  constructor(raison) {
    super(`entree invalide : ${raison}`);
    this.name = "ErreurEntree";
    this.raison = raison;
  }
}

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const longueur = (s) => [...s].length;

/**
 * Membres d'un objet de paramètres : inconnus refusés, requis présents.
 * @param {string} methode
 * @param {unknown} params
 * @returns {object}
 */
export function controlerParametres(methode, params) {
  const p = params === undefined || params === null ? {} : params;
  if (!estObjet(p)) throw new ErreurEntree("params_non_objet");
  for (const k of Object.keys(p)) if (!PARAMETRES[methode].includes(k)) throw new ErreurEntree("parametre_inconnu");
  for (const k of REQUIS[methode]) if (!(k in p)) throw new ErreurEntree(`${k}_absent`);
  return p;
}

/**
 * Nom court déclaré par le SDK (6.2, EX-6.6) : motif de CT-1, sans `__`, hors
 * `noortrace.`, et nom `<alias>__<tool>` dans la borne de 128 caractères.
 * @param {unknown} tool
 * @param {string} alias alias de l'entrée de `sdk.hosts`
 * @returns {string} le nom de l'événement `<alias>__<tool>`
 */
export function nomOutilSdk(tool, alias) {
  if (typeof tool !== "string" || !MOTIF_NOM_OUTIL.test(tool)) throw new ErreurEntree("tool_hors_motif");
  if (tool.includes("__")) throw new ErreurEntree("tool_double_soulignement");
  if (tool.startsWith("noortrace.")) throw new ErreurEntree("tool_reserve");
  const nom = `${alias}__${tool}`;
  if (!MOTIF_NOM_OUTIL.test(nom)) throw new ErreurEntree("tool_hors_motif");
  return nom;
}

/**
 * Effets déclarés (EX-6.6) : forme de CT-1 §5.3 (`$defs/effect`), au plus
 * 1 024 effets.
 * @param {unknown} effets
 * @returns {object[]|null}
 */
export function controlerEffets(effets) {
  if (effets === null || effets === undefined) return null;
  if (!Array.isArray(effets) || effets.length > 1024) throw new ErreurEntree("effects_hors_forme");
  for (const e of effets) {
    if (!estObjet(e)) throw new ErreurEntree("effects_hors_forme");
    const cles = Object.keys(e).sort().join(",");
    if (cles !== "action,amount,currency,object,system") throw new ErreurEntree("effects_hors_forme");
    if (typeof e.system !== "string" || longueur(e.system) < 1 || longueur(e.system) > 128) throw new ErreurEntree("effects_hors_forme");
    if (!ACTIONS_EFFET.includes(e.action)) throw new ErreurEntree("effects_hors_forme");
    if (typeof e.object !== "string" || longueur(e.object) < 1 || longueur(e.object) > 512) throw new ErreurEntree("effects_hors_forme");
    if (e.amount !== null && (typeof e.amount !== "string" || !/^-?(0|[1-9][0-9]*)(\.[0-9]{1,8})?$/.test(e.amount))) throw new ErreurEntree("effects_hors_forme");
    if (e.currency !== null && (typeof e.currency !== "string" || !/^[A-Z]{3}$/.test(e.currency))) throw new ErreurEntree("effects_hors_forme");
    if ((e.amount === null) !== (e.currency === null)) throw new ErreurEntree("effects_hors_forme");
  }
  return effets;
}

/**
 * `intent` déclaré (EX-6.6) : chaîne d'au plus 1 048 576 caractères, ou null.
 * @param {unknown} intent
 * @returns {string|null}
 */
export function controlerIntention(intent) {
  if (intent === null || intent === undefined) return null;
  if (typeof intent !== "string") throw new ErreurEntree("intent_hors_forme");
  if (intent.length > INTENTION_MAX_DECLAREE && longueur(intent) > INTENTION_MAX_DECLAREE) throw new ErreurEntree("intent_trop_long");
  return intent;
}

/**
 * `class` déclarée (6.2) : `lecture`, `ecriture` ou null.
 * @param {unknown} c
 * @returns {"lecture"|"ecriture"|null}
 */
export function controlerClasse(c) {
  if (c === null || c === undefined) return null;
  if (c !== "lecture" && c !== "ecriture") throw new ErreurEntree("class_hors_forme");
  return c;
}

/**
 * `context` déclaré (EX-6.6) : chaque valeur de forme `0x` + 64 chiffres
 * hexadécimaux minuscules, et déclarée par `declarerContexte` dans la même
 * session.
 * @param {unknown} context
 * @param {Map<string, object>} declares références de contexte de la session, par sha256
 * @returns {object[]} les références de contexte, dans l'ordre déclaré (EX-7.7)
 */
export function controlerContexte(context, declares) {
  if (context === null || context === undefined) return [];
  if (!Array.isArray(context)) throw new ErreurEntree("context_hors_forme");
  return context.map((s) => {
    if (typeof s !== "string" || !MOTIF_SHA256.test(s)) throw new ErreurEntree("context_hors_motif");
    const r = declares.get(s);
    if (!r) throw new ErreurEntree("context_non_declare");
    return r;
  });
}

/**
 * Type de média déclaré pour un document de contexte (6.2) : chaîne ou null.
 * @param {unknown} m
 * @returns {string|null}
 */
export function controlerTypeMedia(m) {
  if (m === null || m === undefined) return null;
  if (typeof m !== "string" || m.length > 255) throw new ErreurEntree("media_type_hors_forme");
  return m;
}

/** Le type de média déclaré respecte-t-il le motif `type_mime` de CT-1 ? */
export function typeMimeAdmis(m) {
  return typeof m === "string" && m.length <= 127 && MOTIF_TYPE_MIME.test(m);
}

/**
 * Décodage strict de `bytes_base64` (RFC 4648 §4, remplissage exigé).
 * @param {unknown} b
 * @returns {Uint8Array}
 */
export function decoderBase64Strict(b) {
  if (typeof b !== "string" || b.length % 4 !== 0 || !/^[A-Za-z0-9+/]*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(b)) {
    throw new ErreurEntree("bytes_base64_invalide");
  }
  const o = new Uint8Array(Buffer.from(b, "base64"));
  // Forme canonique : les bits de remplissage sont nuls (une seule écriture par contenu).
  if (Buffer.from(o).toString("base64") !== b) throw new ErreurEntree("bytes_base64_invalide");
  return o;
}

/**
 * Entier de durée déclaré (`duration_ms`) : entier sûr, au moins 0.
 * @param {unknown} d
 * @returns {number}
 */
export function controlerDuree(d) {
  if (!Number.isSafeInteger(d) || d < 0) throw new ErreurEntree("duration_ms_hors_forme");
  return d;
}

/**
 * Booléen (`is_error`).
 * @param {unknown} b
 * @param {string} nom
 * @returns {boolean}
 */
export function controlerBooleen(b, nom) {
  if (typeof b !== "boolean") throw new ErreurEntree(`${nom}_hors_forme`);
  return b;
}

/**
 * Statut HTTP déclaré d'un échange (6.2) : entier de 100 à 599, ou null.
 * @param {unknown} s
 * @returns {number|null}
 */
export function controlerStatut(s) {
  if (s === null || s === undefined) return null;
  if (!Number.isInteger(s) || s < 100 || s > 599) throw new ErreurEntree("status_hors_forme");
  return s;
}

/**
 * Identifiant de session ou d'appel : chaîne.
 * @param {unknown} v
 * @param {string} nom
 * @returns {string}
 */
export function controlerIdentifiant(v, nom) {
  if (typeof v !== "string" || v.length === 0 || v.length > 64) throw new ErreurEntree(`${nom}_inconnu`);
  return v;
}
