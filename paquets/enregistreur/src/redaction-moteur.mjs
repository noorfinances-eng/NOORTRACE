// Moteur de la rédaction avant hachage (CT-2 §10) : politique compilée,
// sélection des règles (EX-10.14), passages jusqu'à stabilité, détecteurs de
// texte sur les segments situés entre les jetons (EX-10.9), détecteur `champ`
// (EX-10.11), actions `remplacer`, `pseudonyme` (EX-10.12) et `supprimer`
// (10.2.3), comptes du journal d'exploitation (EX-10.17), marquage
// `redacted` par comparaison des sérialisations (EX-10.16), pièces de §8
// (JSON, texte, non JSON, non rédigeable, EX-8.7), valeurs en ligne (EX-7.2,
// EX-8.6, EX-6.6, EX-10.24), exécution de `extract` (EX-7.6 pas 3).
//
// Le moteur est synchrone et sans entrée-sortie : il s'exécute dans un fil
// de calcul (EX-3.6, `redaction-fil.mjs`), ou dans le fil appelant pour les
// essais, toujours sous la borne de temps d'EX-10.23. Il ne garde rien : la
// valeur en clair ne sort jamais de la mémoire, sauf vers le coffre chiffré
// quand il est activé (EX-10.22).

import { createHmac } from "node:crypto";
import { creerReference, utf8 } from "@noortrace/noyau";
import { jcsIntegral, jcsIntegralOctets, analyserJsonIntegral } from "./jcs-integral.mjs";
import { Piece, pieceNonRedigeable, typeMediaNormalise } from "./pieces.mjs";
import { DETECTEURS_NOMMES, detecterRegex } from "./redaction-detecteurs.mjs";
import { controlerMotif, executerSousBorne, DepassementBudget, premiereCorrespondance } from "./redaction-motifs.mjs";
import { evaluerEffets } from "./effets.mjs";

/** Portées de 10.2.2. */
export const PORTEES = Object.freeze(["arguments", "resultat", "requete", "reponse", "prompt_systeme", "contexte"]);
/** Portées sans outil : seule `tools: "*"` y rend une règle applicable (10.2.1). */
export const PORTEES_SANS_OUTIL = Object.freeze(["requete", "reponse", "prompt_systeme"]);
/** Les cinq détecteurs nommés (10.3). */
export const TYPES_NOMMES = Object.freeze(["iban", "avs", "carte", "email", "telephone"]);
/** Type du jeton du prompt système remplacé dans la requête (EX-10.7). */
export const TYPE_PROMPT = "prompt-systeme";
/** Jeton du prompt système dans la pièce « requête » (EX-8.5, EX-10.7). */
export const JETON_PROMPT_SYSTEME = "[REDIGE:prompt-systeme]";
/** Longueur maximale d'un motif de décision rédigé, en points de code (EX-10.24). */
export const LONGUEUR_MAX_MOTIF = 1024;

const echapperRe = (s) => s.replace(/[\\^$.*+?()[\]{}|/-]/g, "\\$&");
const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** Pose un membre, y compris un membre nommé `__proto__`, sans toucher au prototype. */
function poser(objet, cle, valeur) {
  if (cle === "__proto__") Object.defineProperty(objet, cle, { value: valeur, enumerable: true, writable: true, configurable: true });
  else objet[cle] = valeur;
}

/** Copie profonde d'une valeur JSON (la valeur reçue n'est jamais modifiée). */
export function clonerJson(v) {
  if (Array.isArray(v)) return v.map(clonerJson);
  if (estObjet(v)) {
    const c = Object.getPrototypeOf(v) === null ? Object.create(null) : {};
    for (const k of Object.keys(v)) poser(c, k, clonerJson(v[k]));
    return c;
  }
  return v;
}

/** Octets égaux. */
function egaux(a, b) {
  if (a.length !== b.length) return false;
  for (let k = 0; k < a.length; k++) if (a[k] !== b[k]) return false;
  return true;
}

/**
 * Pseudonyme à clé (EX-10.12) : HMAC-SHA-256(K, UTF-8(t) ‖ 0x00 ‖ UTF-8(V)),
 * douze chiffres hexadécimaux minuscules.
 * @param {Uint8Array} cle
 * @param {string} type
 * @param {string} valeur
 * @returns {string} le jeton `[PSEUDO:<t>:<hex12>]`
 */
export function jetonPseudonyme(cle, type, valeur) {
  const h = createHmac("sha256", cle);
  h.update(Buffer.from(type, "utf8"));
  h.update(Buffer.from([0]));
  h.update(Buffer.from(valeur, "utf8"));
  return `[PSEUDO:${type}:${h.digest().subarray(0, 6).toString("hex")}]`;
}

/** Politique de rédaction compilée (10.2), prête à l'emploi. */
export class PolitiqueCompilee {
  /**
   * @param {object} doc document `politique-redaction-v0`, déjà contrôlé (EX-10.6)
   * @param {{cle?: Uint8Array|null}} [o] clé de pseudonymisation résolue (EX-10.12)
   */
  constructor(doc, o = {}) {
    this.doc = doc;
    this.name = doc.name;
    this.cle = o.cle ?? null;
    const motifs = new Map();
    for (const [nom, m] of Object.entries(doc.named_patterns ?? {})) {
      const c = controlerMotif(m.pattern);
      if (!c.admis) throw new TypeError(`motif nommé ${nom} refusé : ${c.raison}`);
      motifs.set(nom, c.regexp);
    }
    const types = new Set([...TYPES_NOMMES, TYPE_PROMPT, ...motifs.keys()]);
    this.regles = doc.rules.map((r) => {
      const detecteurs = r.detectors.map((d) => {
        if (d.type === "regex") {
          const regexp = motifs.get(d.name);
          if (!regexp) throw new TypeError(`règle ${r.id} : motif nommé ${d.name} inconnu`);
          return { type: "regex", jeton: d.name, regexp };
        }
        if (d.type === "champ") {
          types.add(d.label);
          return { type: "champ", jeton: d.label };
        }
        return { type: d.type, jeton: d.type };
      });
      if (r.action.kind === "pseudonyme" && !this.cle) throw new TypeError(`règle ${r.id} : pseudonyme sans clé (EX-10.6)`);
      return {
        id: r.id,
        portees: new Set(r.scopes),
        outils: r.tools,
        path: r.path,
        detecteurs,
        action: r.action.kind,
        texte: detecteurs.filter((d) => d.type !== "champ"),
      };
    });
    this.types = types;
    const alt = [...types].sort((a, b) => b.length - a.length).map(echapperRe).join("|");
    this.reJeton = new RegExp(`\\[(?:REDIGE:(?:${alt})|PSEUDO:(?:${alt}):[0-9a-f]{12})\\]`, "g");
    this.reJetonEntier = new RegExp(`^\\[(?:REDIGE:(?:${alt})|PSEUDO:(?:${alt}):[0-9a-f]{12})\\]$`);
    this.motifs = motifs;
  }

  /** La chaîne est-elle exactement un jeton de la politique (EX-10.9, EX-10.11) ? */
  estJeton(s) {
    return typeof s === "string" && this.reJetonEntier.test(s);
  }

  /**
   * Règles retenues pour une pièce (EX-10.14).
   * @param {string} portee
   * @param {string|null} outil nom annoncé, ou null
   * @param {string|null} [alias] alias du serveur de l'outil, à défaut le préfixe `<alias>__` du nom
   */
  retenues(portee, outil, alias) {
    const sansOutil = PORTEES_SANS_OUTIL.includes(portee);
    const nom = sansOutil ? null : outil ?? null;
    let a = alias ?? null;
    if (nom && a === null) {
      const k = nom.indexOf("__");
      if (k > 0) a = nom.slice(0, k);
    }
    return this.regles.filter((r) => {
      if (!r.portees.has(portee)) return false;
      if (r.outils === "*") return true;
      if (nom === null) return false;
      return r.outils.includes(nom) || (a !== null && r.outils.includes(`${a}__*`));
    });
  }

  /** Jeton de remplacement d'une correspondance (10.2.3). */
  jeton(action, type, valeur) {
    return action === "pseudonyme" ? jetonPseudonyme(this.cle, type, valeur) : `[REDIGE:${type}]`;
  }
}

// ------------------------------------------------------------ application

/** Comptes ordonnés par première apparition (EX-10.17, B.3 `matches`). */
class Comptes {
  constructor() {
    this.m = new Map();
  }
  ajouter(regle, detecteur, n) {
    if (!n) return;
    const k = `${regle}\u0000${detecteur}`;
    const x = this.m.get(k);
    if (x) x.count += n;
    else this.m.set(k, { rule: regle, detector: detecteur, count: n });
  }
  liste() {
    return [...this.m.values()].map((x) => ({ ...x }));
  }
}

/**
 * Applique un détecteur de texte à une chaîne, segment par segment entre les
 * jetons (EX-10.9).
 * @returns {{texte: string, n: number}}
 */
function appliquerDetecteur(pol, det, action, s) {
  if (s.length === 0) return { texte: s, n: 0 };
  const fn = det.type === "regex" ? (seg) => detecterRegex(det.regexp, seg, 0, seg.length) : (seg) => DETECTEURS_NOMMES[det.type](seg, 0, seg.length);
  let sortie = "";
  let n = 0;
  let curseur = 0;
  const traiterSegment = (a, b) => {
    if (b <= a) return;
    const seg = s.slice(a, b);
    let k = 0;
    for (const m of fn(seg)) {
      sortie += seg.slice(k, m.debut) + pol.jeton(action, det.jeton, m.valeur);
      k = m.fin;
      n++;
    }
    sortie += seg.slice(k);
  };
  pol.reJeton.lastIndex = 0;
  for (const m of s.matchAll(pol.reJeton)) {
    traiterSegment(curseur, m.index);
    sortie += m[0];
    curseur = m.index + m[0].length;
  }
  traiterSegment(curseur, s.length);
  return n ? { texte: sortie, n } : { texte: s, n: 0 };
}

/** Applique en profondeur d'abord (membres dans l'ordre de JCS) une transformation de chaîne. */
function parcourirChaines(v, f) {
  if (typeof v === "string") return f(v);
  if (Array.isArray(v)) {
    for (let k = 0; k < v.length; k++) v[k] = parcourirChaines(v[k], f);
    return v;
  }
  if (estObjet(v)) {
    for (const k of Object.keys(v).sort()) poser(v, k, parcourirChaines(v[k], f));
    return v;
  }
  return v;
}

/** Localise un pointeur RFC 6901 dans une boîte `{ racine }` : conteneur et clé. */
function localiser(boite, pointeur) {
  if (pointeur === undefined || pointeur === "") return { trouve: true, conteneur: boite, cle: "racine" };
  if (!pointeur.startsWith("/")) return { trouve: false };
  let conteneur = boite;
  let cle = "racine";
  for (const brut of pointeur.slice(1).split("/")) {
    const v = conteneur[cle];
    const jeton = brut.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(v)) {
      if (!/^(0|[1-9][0-9]*)$/.test(jeton) || Number(jeton) >= v.length) return { trouve: false };
      conteneur = v;
      cle = Number(jeton);
    } else if (estObjet(v) && Object.prototype.hasOwnProperty.call(v, jeton)) {
      conteneur = v;
      cle = jeton;
    } else {
      return { trouve: false };
    }
  }
  return { trouve: true, conteneur, cle };
}

/**
 * Applique une règle à la valeur d'une boîte ; rend vrai si la valeur a changé.
 * `cheminRacine` : la chaîne est la racine et `path` n'est pas résolu
 * (valeurs en ligne, EX-10.18, EX-10.24).
 */
function appliquerRegle(pol, r, boite, comptes, notes, o = {}) {
  let loc;
  if (o.racineSeule) loc = { trouve: true, conteneur: boite, cle: "racine" };
  else loc = localiser(boite, r.path);
  if (!loc.trouve) {
    if (!notes.has(r.id)) notes.set(r.id, "pointeur_non_resolu");
    return false;
  }
  const { conteneur, cle } = loc;
  if (r.action === "supprimer" && !o.texteSeul) {
    const label = r.detecteurs[0].jeton;
    const jeton = `[REDIGE:${label}]`;
    if (conteneur === boite || Array.isArray(conteneur)) {
      if (conteneur[cle] === jeton) return false;
      conteneur[cle] = jeton;
    } else {
      delete conteneur[cle];
    }
    comptes.ajouter(r.id, "champ", 1);
    return true;
  }
  let change = false;
  for (const d of o.texteSeul ? r.texte : r.detecteurs) {
    if (d.type === "champ") {
      const v = conteneur[cle];
      if (pol.estJeton(v)) continue;
      const valeur = typeof v === "string" ? v : jcsIntegral(v);
      const nouveau = pol.jeton(r.action, d.jeton, valeur);
      if (Array.isArray(conteneur) || conteneur === boite) conteneur[cle] = nouveau;
      else poser(conteneur, cle, nouveau);
      comptes.ajouter(r.id, "champ", 1);
      change = true;
      continue;
    }
    let n = 0;
    const nouveau = parcourirChaines(conteneur[cle], (s) => {
      const x = appliquerDetecteur(pol, d, r.action, s);
      n += x.n;
      return x.texte;
    });
    if (Array.isArray(conteneur) || conteneur === boite) conteneur[cle] = nouveau;
    else poser(conteneur, cle, nouveau);
    if (n) {
      comptes.ajouter(r.id, d.type, n);
      change = true;
    }
  }
  return change;
}

/** Garde contre une suite de passages qui ne se stabiliserait pas (impossible selon EX-10.14). */
const PASSAGES_MAX = 10000;

/**
 * Rédige une valeur selon une liste de règles, par passages (EX-10.14).
 * @param {PolitiqueCompilee} pol
 * @param {object[]} regles règles retenues, dans l'ordre
 * @param {unknown} valeur valeur reçue (non modifiée)
 * @param {{racineSeule?: boolean, texteSeul?: boolean, suivi?: {regle: string|null}}} [o]
 * @returns {{valeur: unknown, comptes: object[], notes: {rule: string, note: string}[], passages: number}}
 */
export function appliquerRegles(pol, regles, valeur, o = {}) {
  const boite = { racine: clonerJson(valeur) };
  const comptes = new Comptes();
  const notes = new Map();
  let passages = 0;
  for (;;) {
    passages++;
    let change = false;
    for (const r of regles) {
      if (o.suivi) o.suivi.regle = r.id;
      if (appliquerRegle(pol, r, boite, comptes, notes, o)) change = true;
    }
    if (!change) break;
    if (passages >= PASSAGES_MAX) throw new Error("rédaction instable");
  }
  return { valeur: boite.racine, comptes: comptes.liste(), notes: [...notes].map(([rule, note]) => ({ rule, note })), passages };
}

/**
 * Rédige la valeur d'une pièce JSON ou texte (EX-10.14), sans borne de temps.
 * @param {PolitiqueCompilee} pol
 * @param {{portee: string, outil?: string|null, alias?: string|null, valeur: unknown}} d
 */
export function redigerValeur(pol, d) {
  if (!PORTEES.includes(d.portee)) throw new TypeError(`portée inconnue : ${d.portee}`);
  return appliquerRegles(pol, pol.retenues(d.portee, d.outil ?? null, d.alias ?? null), d.valeur);
}

// ------------------------------------------------------------ pièces (§8, EX-8.7, EX-10.16, EX-10.23)

const DECODEUR_STRICT = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Pièce dont la référence est calculée ici (le fil appelant ne rehache pas). */
function piece(octets, options) {
  return Object.assign(Object.create(Piece.prototype), { octets, reference: creerReference(octets, options) });
}

/**
 * Produit une pièce rédigée (EX-10.1, EX-10.16, EX-8.7), sous la borne
 * d'EX-10.23 opération 1.
 * @param {PolitiqueCompilee} pol
 * @param {object} d demande :
 *   `{ genre: "json", portee, outil?, alias?, valeur, origine?, media_type?, content_type? }` ;
 *   `{ genre: "texte", portee, outil?, alias?, texte, origine?, content_type? }` ;
 *   `{ genre: "octets", portee, outil?, alias?, octets, content_type?, codage_inconnu? }` ;
 *   `{ genre: "contexte", outil?, alias?, octets, media_type? }` (document remis par le SDK, 8.2) ;
 *   `origine` : valeur (ou texte) de comparaison d'EX-10.16 quand elle diffère de l'entrée
 *   (prompt remplacé dans la requête, EX-8.5 ; texte d'intention, EX-10.18)
 * @param {{budgetMs: number, avecValeur?: boolean, avecOriginal?: boolean, longueur?: (n: number) => void}} o
 * @returns {{piece: Piece, valeur?: unknown, original?: Uint8Array, redacted: boolean, comptes: object[],
 *   notes: object[], non_redigeable: string|null, depassement: {regle: string|null}|null, applicable: boolean}}
 */
export function produirePiece(pol, d, o) {
  if (d.genre === "contexte") {
    const t = typeof d.media_type === "string" ? d.media_type.split(";")[0].trim().toLowerCase() : "";
    if (t === "application/json" || /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+\+json$/.test(t)) {
      let valeur;
      let ok = true;
      try {
        valeur = analyserJsonIntegral(d.octets);
      } catch {
        ok = false;
      }
      if (ok) return produirePiece(pol, { genre: "json", portee: "contexte", outil: d.outil, alias: d.alias, valeur, media_type: "application/json", content_type: d.media_type }, o);
    }
    return produirePiece(pol, { genre: "octets", portee: "contexte", outil: d.outil, alias: d.alias, octets: d.octets, content_type: d.media_type ?? null }, o);
  }
  const regles = pol.retenues(d.portee, d.outil ?? null, d.alias ?? null);
  const suivi = { regle: null };
  const base = { comptes: [], notes: [], non_redigeable: null, depassement: null, applicable: regles.length > 0 };

  if (d.genre === "octets") {
    const octets = d.octets instanceof Uint8Array ? d.octets : new Uint8Array(d.octets);
    o.longueur?.(octets.length);
    let texte = null;
    if (!d.codage_inconnu) {
      try {
        texte = DECODEUR_STRICT.decode(octets);
      } catch {
        texte = null;
      }
    }
    if (texte === null) {
      // EX-8.7 règle 3 : contenu non rédigeable.
      if (!regles.length) return { ...base, piece: piece(octets, { redacted: false, media_type: typeMediaNormalise(d.content_type) }), redacted: false };
      const p = pieceNonRedigeable({ content_type: d.content_type ?? null, length: octets.length, reason: d.codage_inconnu ? "codage_inconnu" : "non_utf8" });
      return { ...base, piece: p, redacted: true, non_redigeable: d.codage_inconnu ? "codage_inconnu" : "non_utf8", original: o.avecOriginal ? octets.slice() : undefined };
    }
    let r;
    try {
      r = executerSousBorne(() => appliquerRegles(pol, regles, texte, { suivi }), o.budgetMs, "piece");
    } catch (e) {
      if (!(e instanceof DepassementBudget)) throw e;
      const p = pieceNonRedigeable({ content_type: d.content_type ?? null, length: octets.length, reason: "budget_redaction" });
      return { ...base, piece: p, redacted: true, non_redigeable: "budget_redaction", depassement: { regle: suivi.regle }, original: o.avecOriginal ? octets.slice() : undefined };
    }
    const change = r.valeur !== texte;
    const sortie = change ? utf8(r.valeur) : octets;
    return {
      ...base,
      piece: piece(sortie, { redacted: change, media_type: typeMediaNormalise(d.content_type) }),
      redacted: change,
      comptes: r.comptes,
      notes: r.notes,
      valeur: o.avecValeur ? r.valeur : undefined,
      original: o.avecOriginal && change ? octets.slice() : undefined,
    };
  }

  const texte = d.genre === "texte";
  if (!texte && d.genre !== "json") throw new TypeError(`genre de pièce inconnu : ${d.genre}`);
  const entree = texte ? d.texte : d.valeur;
  if (texte && typeof entree !== "string") throw new TypeError("pièce texte : chaîne attendue");
  // Sérialisation de la valeur reçue, une fois, avant la rédaction (EX-10.16, EX-8.7 `length`).
  const origine = d.origine !== undefined ? d.origine : entree;
  const octetsOrigine = texte ? utf8(origine) : jcsIntegralOctets(origine);
  o.longueur?.(texte ? utf8(entree).length : d.origine !== undefined ? jcsIntegralOctets(entree).length : octetsOrigine.length);
  let r;
  try {
    r = executerSousBorne(() => appliquerRegles(pol, regles, entree, { suivi }), o.budgetMs, "piece");
  } catch (e) {
    // Une imbrication qui épuise la pile est une forme de données qui dépasse
    // ce que la rédaction peut traiter : même issue que la borne (EX-10.23).
    if (!(e instanceof DepassementBudget) && !(e instanceof RangeError)) throw e;
    const longueur = texte ? utf8(entree).length : d.origine !== undefined ? jcsIntegralOctets(entree).length : octetsOrigine.length;
    const p = pieceNonRedigeable({ content_type: d.content_type ?? null, length: longueur, reason: "budget_redaction" });
    return { ...base, piece: p, redacted: true, non_redigeable: "budget_redaction", depassement: { regle: suivi.regle }, original: o.avecOriginal ? octetsOrigine : undefined };
  }
  const octets = texte ? utf8(r.valeur) : jcsIntegralOctets(r.valeur);
  const redacted = !egaux(octets, octetsOrigine);
  const options = texte ? { redacted, media_type: "text/plain" } : { redacted, ...(d.media_type ? { media_type: d.media_type } : {}) };
  return {
    ...base,
    piece: piece(octets, options),
    redacted,
    comptes: r.comptes,
    notes: r.notes,
    valeur: o.avecValeur ? r.valeur : undefined,
    original: o.avecOriginal && redacted ? octetsOrigine : undefined,
  };
}

// ------------------------------------------------------------ valeurs en ligne

/** Règles à détecteurs de texte, toutes portées et tous outils (EX-7.2, EX-8.6, EX-5.36, EX-10.24). */
function reglesTexte(pol) {
  return pol.regles.filter((r) => r.texte.length > 0 && r.action !== "supprimer");
}

/**
 * Une valeur déclarée en ligne passe-t-elle les détecteurs (EX-7.2 `run_id`,
 * EX-8.6 nom de prompt, EX-5.36 segment de modèle) ? Aucun détecteur de
 * texte de la politique, quels que soient la portée, les outils et le `path`
 * de sa règle, ne doit y trouver de correspondance. Sous la borne
 * d'EX-10.23 opération 3 : un dépassement vaut correspondance.
 * @param {PolitiqueCompilee} pol
 * @param {string} valeur
 * @param {number} budgetMs
 * @returns {{admise: boolean, depassement: boolean}}
 */
export function examinerValeurLigne(pol, valeur, budgetMs) {
  try {
    const r = executerSousBorne(() => appliquerRegles(pol, reglesTexte(pol), valeur, { racineSeule: true, texteSeul: true }), budgetMs, "valeur");
    return { admise: r.comptes.length === 0, depassement: false };
  } catch (e) {
    if (!(e instanceof DepassementBudget)) throw e;
    return { admise: false, depassement: true };
  }
}

/**
 * Motif d'une décision (EX-10.24) : règles à détecteurs de texte, toutes
 * portées, tous outils, `path` ignoré, avec leur action, par passages ;
 * tronqué à 1024 points de code. Un dépassement de la borne rend `null`.
 * @param {PolitiqueCompilee} pol
 * @param {string|null} motif
 * @param {number} budgetMs
 * @returns {{motif: string|null, comptes: object[], depassement: boolean}}
 */
export function redigerMotifDecision(pol, motif, budgetMs) {
  if (motif === null || motif === undefined) return { motif: null, comptes: [], depassement: false };
  try {
    const r = executerSousBorne(() => appliquerRegles(pol, reglesTexte(pol), motif, { racineSeule: true, texteSeul: true }), budgetMs, "valeur");
    const points = Array.from(r.valeur);
    return { motif: points.length > LONGUEUR_MAX_MOTIF ? points.slice(0, LONGUEUR_MAX_MOTIF).join("") : r.valeur, comptes: r.comptes, depassement: false };
  } catch (e) {
    if (!(e instanceof DepassementBudget)) throw e;
    return { motif: null, comptes: [], depassement: true };
  }
}

/**
 * Effets déclarés par le SDK (EX-6.6) : `system` et `object` soumis aux
 * détecteurs de texte des règles de portée `arguments` applicables à
 * l'outil, avec leur action, la chaîne étant la racine. Un dépassement de la
 * borne omet l'effet (EX-10.23 opération 3).
 * @param {PolitiqueCompilee} pol
 * @param {object[]} effets
 * @param {{outil: string, alias?: string|null, budgetMs: number}} o
 * @returns {{effets: object[], omis: {index: number, raison: string}[], comptes: object[]}}
 */
export function redigerEffetsDeclares(pol, effets, o) {
  const regles = pol.retenues("arguments", o.outil, o.alias ?? null).filter((r) => r.texte.length > 0 && r.action !== "supprimer");
  const sortie = [];
  const omis = [];
  const comptes = new Comptes();
  effets.forEach((e, index) => {
    try {
      const x = executerSousBorne(
        () => {
          const s = appliquerRegles(pol, regles, e.system, { racineSeule: true, texteSeul: true });
          const ob = appliquerRegles(pol, regles, e.object, { racineSeule: true, texteSeul: true });
          return { s, ob };
        },
        o.budgetMs,
        "valeur",
      );
      for (const c of [...x.s.comptes, ...x.ob.comptes]) comptes.ajouter(c.rule, c.detector, c.count);
      sortie.push({ ...e, system: x.s.valeur, object: x.ob.valeur });
    } catch (err) {
      if (!(err instanceof DepassementBudget)) throw err;
      omis.push({ index, raison: "budget_redaction" });
    }
  });
  return { effets: sortie, omis, comptes: comptes.liste() };
}

// ------------------------------------------------------------ extract (EX-7.6 pas 3, EX-10.23 opération 2)

const cacheExtract = new Map();

/**
 * Exécute `extract` sous la borne : première correspondance (leftmost-first),
 * premier groupe capturant s'il a participé, sinon la correspondance
 * entière ; `null` sans correspondance ou pour un motif hors du sous-ensemble.
 * @param {string} motif
 * @param {string} texte
 * @param {number} budgetMs
 * @returns {string|null}
 * @throws {DepassementBudget} opération `extract`
 */
export function executerExtract(motif, texte, budgetMs) {
  let c = cacheExtract.get(motif);
  if (c === undefined) {
    const r = controlerMotif(motif);
    c = r.admis ? r.regexp : null;
    if (cacheExtract.size > 1024) cacheExtract.clear();
    cacheExtract.set(motif, c);
  }
  if (c === null) return null;
  return executerSousBorne(() => premiereCorrespondance(c, texte), budgetMs, "extract");
}

/**
 * Évalue les effets d'un appel relayé (EX-7.6) avec `extract` sous la borne
 * (EX-10.23 opération 2) : un dépassement omet l'effet (`budget_redaction`)
 * et, pour une écriture sans effet, déclare l'effet par défaut.
 * @param {object} p paramètres d'`evaluerEffets`
 * @param {number} budgetMs
 */
export function evaluerEffetsBornes(p, budgetMs) {
  return evaluerEffets({ ...p, executerExtract: (motif, texte) => executerExtract(motif, texte, budgetMs) });
}

/**
 * Opérations exécutées par un fil de calcul (EX-3.6) ou dans le fil appelant.
 * @param {PolitiqueCompilee} pol
 * @param {number} budgetMs
 * @param {string} op
 * @param {object} a
 * @param {{longueur?: (n: number) => void}} [rappels]
 */
export function executerOperation(pol, budgetMs, op, a, rappels = {}) {
  switch (op) {
    case "piece":
      return produirePiece(pol, a.demande, { budgetMs, avecValeur: a.avecValeur, avecOriginal: a.avecOriginal, longueur: rappels.longueur });
    case "ligne":
      return examinerValeurLigne(pol, a.valeur, budgetMs);
    case "motif":
      return redigerMotifDecision(pol, a.motif, budgetMs);
    case "effets_declares":
      return redigerEffetsDeclares(pol, a.effets, { outil: a.outil, alias: a.alias, budgetMs });
    case "effets":
      return evaluerEffetsBornes(a.params, budgetMs);
    default:
      throw new TypeError(`opération inconnue : ${op}`);
  }
}
