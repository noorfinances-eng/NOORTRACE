// Implémentation de référence de la partie calculable de la spécification
// CT-2 de NOORTRACE (spec/CT-2-enregistreur.md) : ce que l'enregistreur
// calcule entre la capture et l'événement CT-1.
//
//   - analyse JSON stricte et JCS intégral des pièces (section 8) ;
//   - rédaction avant hachage : politique versionnée, détecteurs exacts,
//     actions remplacer, pseudonyme à clé et supprimer (section 10) ;
//   - pièces d'un tools/call relayé, lignes relayées et réponse rendue à
//     l'hôte, erreurs de l'enregistreur (section 4.4, 8.2) ;
//   - agrégation de tools/list : préfixe, séparateur, rejets, pagination
//     (section 4.3) ;
//   - analyseur SSE et formes consolidées de l'API Messages d'Anthropic,
//     d'OpenAI Chat Completions et d'OpenAI Responses (section 5.4) ;
//   - pièces d'un échange de modèle, extraction de code.model, de l'intention
//     et du prompt système, corrélation appel ↔ échange (sections 5.5, 5.6) ;
//   - construction des événements CT-1 depuis la capture, gabarits d'effets,
//     écrivain (seq, ts, prev_hash), segments, journal d'intention et
//     événement de reprise (sections 7, 9, 12) ;
//   - empreinte de l'ensemble de politique (section 8.5, EX-10.21).
//
// Fonctions pures : node:crypto seulement (et scripts/lib/journal.mjs pour
// tout ce qui relève de CT-1 : JCS v0, scellement, chaîne, schémas), aucun
// accès au système de fichiers, aucune lecture d'horloge : les instants sont
// des paramètres. Seule exception, la borne de temps d'EX-10.23 : ce qui
// exécute des motifs (rédaction d'une pièce, extract d'un gabarit d'effets,
// examen d'une valeur en ligne) tourne dans un contexte node:vm avec l'option
// timeout, qui interrompt une recherche en cours ; hors dépassement, le
// résultat ne dépend pas de la machine. Les scripts
// (scripts/vecteurs/generer-ct2.mjs) lisent et écrivent les fichiers.

import { createHmac } from "node:crypto";
import vm from "node:vm";
import * as J from "./journal.mjs";

// ---------------------------------------------------------------------------
// Constantes
// ---------------------------------------------------------------------------

/** Version du logiciel de l'enregistreur de référence (code.recorder). */
export const VERSION_ENREGISTREUR = "0.1.0";

/** Identité de l'enregistreur auprès des hôtes et des serveurs d'outils (EX-4.4, EX-4.7). */
export const IDENTITE_ENREGISTREUR = { name: "noortrace-enregistreur", version: VERSION_ENREGISTREUR };

/** Identifiant du schéma de la politique de rédaction et de celui de la configuration. */
export const ID_SCHEMA_POLITIQUE_REDACTION = "https://noortrace.example/schemas/v0/politique-redaction.schema.json";
export const ID_SCHEMA_CONFIGURATION = "https://noortrace.example/schemas/v0/configuration-enregistreur.schema.json";

/** Les six portées de rédaction (CT-2 §10.2.2). */
export const PORTEES = ["arguments", "resultat", "requete", "reponse", "prompt_systeme", "contexte"];
/** Portées sans outil : seule une règle à `tools: "*"` s'y applique. */
const PORTEES_SANS_OUTIL = new Set(["requete", "reponse", "prompt_systeme"]);

/** Les cinq détecteurs nommés (CT-2 §10.3). */
export const DETECTEURS_NOMMES = ["iban", "avs", "carte", "email", "telephone"];

/** Longueur de l'IBAN par code pays (CT-2 §10.3.2). */
export const LONGUEURS_IBAN = { CH: 21, LI: 21, DE: 22, FR: 27, IT: 27, AT: 20, ES: 24, NL: 18, BE: 16, GB: 22, LU: 20 };

/** Jeton de la pièce « requête » quand le prompt système en est retiré (EX-8.5, EX-10.7). */
export const JETON_PROMPT_SYSTEME = "[REDIGE:prompt-systeme]";

/** Motif CT-1 de execution.tool (CT-1 §5.3) et motif d'un alias de serveur (EX-4.9). */
export const RE_NOM_OUTIL = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
export const RE_ALIAS = /^[a-z0-9][a-z0-9-]{0,31}$/;
/** Séparateur entre l'alias et le nom d'origine (EX-4.10). */
export const SEPARATEUR_ALIAS = "__";

/**
 * Codes et messages des erreurs JSON-RPC de l'enregistreur (CT-2 §4.4,
 * EX-4.24) : hors de la plage -32768 à -32000 que JSON-RPC 2.0 réserve, dont
 * MCP 2026-07-28 dit les vingt premiers codes (à partir de -32000) hérités ;
 * les deux derniers chiffres sont ceux de la version 0.2. -31015 n'est pas
 * attribué : l'issue d'une politique d'approbation est un résultat isError
 * (EX-4.49), pas une erreur.
 */
export const ERREURS = Object.freeze({
  MODE_DEGRADE: Object.freeze({ code: -31010, message: "noortrace: appel bloque, enregistreur en mode degrade" }),
  DELAI: Object.freeze({ code: -31011, message: "noortrace: delai du serveur d'outils depasse" }),
  ANNULE: Object.freeze({ code: -31012, message: "noortrace: appel annule par l'hote" }),
  TAILLE: Object.freeze({ code: -31013, message: "noortrace: taille maximale depassee" }),
  INJOIGNABLE: Object.freeze({ code: -31014, message: "noortrace: serveur d'outils injoignable" }),
  NON_RELAYABLE: Object.freeze({ code: -31016, message: "noortrace: resultat ou requete non relayable par la configuration" }),
  NON_DURABLE: Object.freeze({ code: -31017, message: "noortrace: appel execute, evenement non durable" }),
});

/**
 * Vrai si l'enregistreur peut émettre ce code (EX-4.24) : un code de la table
 * de 4.4, un code JSON-RPC standard, ou -32020, -32021, -32022 de MCP ; jamais
 * la plage héritée de MCP (les vingt premiers codes à partir de -32000), ni le
 * reste de -32020 à -32099, ni -32002, -32042, ni 100 à 599.
 */
export function codeEmissible(code) {
  if (!Number.isSafeInteger(code)) return false;
  if (Object.values(ERREURS).some((e) => e.code === code)) return true;
  return [-32700, -32600, -32601, -32602, -32603, -32020, -32021, -32022].includes(code);
}

/** Budget de rédaction par défaut, en millisecondes (limits.redaction_budget_ms, EX-10.23). */
export const BUDGET_REDACTION_MS = 1000;

/** Bornes par défaut de l'analyse JSON (CT-2 4.4 pas 1 : limits.json_max_depth, limits.json_max_members). */
export const PROFONDEUR_JSON_MAX = 128;
export const MEMBRES_JSON_MAX = 100000;

/** Texte de la pièce « résultat » d'un événement de reprise (EX-12.14). */
export const TEXTE_REPRISE = "resultat inconnu : enregistreur arrete pendant le relais";
/** Texte de la pièce « résultat » d'un événement en attente dont le résultat a été perdu (EX-14.10). */
export const TEXTE_ATTENTE = "resultat perdu pendant le mode degrade";

/** Délégation des événements du journal sur lui-même (CT-1 §5.3, EX-15.6). */
export const DELEGATION_JOURNAL = Object.freeze({ launched_by: "noortrace-enregistreur", on_behalf_of: null, scope: "journal:administration", run_id: null });

// ---------------------------------------------------------------------------
// Erreurs
// ---------------------------------------------------------------------------

/** Document de configuration ou politique refusé (CT-2 §15.4) : le démon ne démarre pas, le rechargement est refusé. */
export class ErreurConfiguration extends Error {
  constructor(message, erreurs = []) {
    super(message);
    this.name = "ErreurConfiguration";
    this.erreurs = erreurs;
  }
}

/** Mode dégradé (CT-2 §14) : `raison` est la valeur de data.reason de l'erreur -31010. */
export class ErreurModeDegrade extends Error {
  constructor(raison, message) {
    super(message ?? `mode degrade : ${raison}`);
    this.name = "ErreurModeDegrade";
    this.raison = raison;
  }
}

// ---------------------------------------------------------------------------
// Analyse JSON stricte avec nombres quelconques, et JCS intégral (section 8)
// ---------------------------------------------------------------------------

const RE_NOMBRE = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

/**
 * Analyse stricte d'un texte JSON (RFC 8259), telle que la fait le frontal
 * (CT-2 §4.4 pas 1, §5.3.1 pas 2) : clés en double, substituts isolés, octets
 * UTF-8 invalides et marque d'ordre d'octets refusés ; nombres convertis en
 * double précision IEEE 754 (la valeur la plus proche du texte), un nombre qui
 * déborde (1e400) refusé. Avec `positions: true`, rend aussi l'étendue de
 * chaque valeur dans le texte, par pointeur JSON (indices en unités UTF-16 du
 * texte décodé) : c'est ce qui permet de relayer des octets reçus sans les
 * resérialiser (EX-4.20). La profondeur d'imbrication et le nombre de membres
 * ou d'éléments par objet ou tableau sont bornés (`profondeurMax`,
 * `membresMax`, 4.4 pas 1) : un texte qui les dépasse est refusé, jamais une
 * pile épuisée. Lève J.ErreurJSON ; `raison` vaut « nombre_hors_double » pour
 * un nombre que la double précision ne contient pas, « bornes » pour une
 * borne dépassée.
 */
export function analyserJSONIntegral(entree, { positions = false, profondeurMax = PROFONDEUR_JSON_MAX, membresMax = MEMBRES_JSON_MAX } = {}) {
  let texte;
  if (typeof entree === "string") texte = entree;
  else {
    const buf = Buffer.isBuffer(entree) ? entree : Buffer.from(entree);
    if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) throw new J.ErreurJSON("marque d'ordre d'octets en tête du document", true);
    try {
      texte = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buf);
    } catch {
      throw new J.ErreurJSON("octets UTF-8 invalides", true);
    }
  }
  const etendues = positions ? new Map() : null;
  let i = 0;
  let profondeur = 0;
  const n = texte.length;
  const erreur = (m, canonique = false, raison = null) => {
    const e = new J.ErreurJSON(`${m} (caractère ${i})`, canonique);
    e.raison = raison;
    throw e;
  };
  const blancs = () => {
    for (;;) {
      const c = texte.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };
  const unite = () => {
    const h = texte.slice(i, i + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(h)) erreur("échappement \\u invalide");
    i += 4;
    return parseInt(h, 16);
  };
  const chaine = () => {
    i++;
    let out = "";
    for (;;) {
      if (i >= n) erreur("chaîne non terminée");
      const c = texte.charCodeAt(i);
      if (c === 0x22) {
        i++;
        return out;
      }
      if (c < 0x20) erreur("caractère de contrôle non échappé dans une chaîne");
      if (c !== 0x5c) {
        out += texte[i++];
        continue;
      }
      const e = texte[i + 1];
      i += 2;
      switch (e) {
        case '"': out += '"'; break;
        case "\\": out += "\\"; break;
        case "/": out += "/"; break;
        case "b": out += "\b"; break;
        case "f": out += "\f"; break;
        case "n": out += "\n"; break;
        case "r": out += "\r"; break;
        case "t": out += "\t"; break;
        case "u": {
          const cu = unite();
          if (cu >= 0xd800 && cu <= 0xdbff) {
            if (texte[i] !== "\\" || texte[i + 1] !== "u") erreur("substitut haut isolé", true);
            i += 2;
            const bas = unite();
            if (bas < 0xdc00 || bas > 0xdfff) erreur("substitut haut sans substitut bas", true);
            out += String.fromCharCode(cu, bas);
          } else if (cu >= 0xdc00 && cu <= 0xdfff) {
            erreur("substitut bas isolé", true);
          } else {
            out += String.fromCharCode(cu);
          }
          break;
        }
        default:
          erreur("échappement invalide");
      }
    }
  };
  const nombre = () => {
    RE_NOMBRE.lastIndex = i;
    const m = RE_NOMBRE.exec(texte);
    if (!m) erreur("nombre invalide");
    const v = Number(m[0]);
    if (!Number.isFinite(v)) erreur(`nombre « ${m[0].slice(0, 40)} » hors de la double précision IEEE 754`, true, "nombre_hors_double");
    i += m[0].length;
    return v;
  };
  const litteral = (mot, val) => {
    if (!texte.startsWith(mot, i)) erreur("littéral invalide");
    i += mot.length;
    return val;
  };
  const echapper = (k) => k.replace(/~/g, "~0").replace(/\//g, "~1");
  const valeur = (pointeur) => {
    blancs();
    if (i >= n) erreur("fin de texte inattendue");
    const debut = i;
    const c = texte[i];
    let v;
    if (c === "{" || c === "[") {
      profondeur++;
      if (profondeur > profondeurMax) erreur(`imbrication de plus de ${profondeurMax} niveaux`, false, "bornes");
    }
    if (c === "{") {
      i++;
      v = {};
      let membres = 0;
      blancs();
      if (texte[i] === "}") i++;
      else {
        for (;;) {
          if (++membres > membresMax) erreur(`objet de plus de ${membresMax} membres`, false, "bornes");
          blancs();
          if (texte[i] !== '"') erreur("nom de membre attendu");
          const k = chaine();
          blancs();
          if (texte[i] !== ":") erreur("« : » attendu");
          i++;
          const x = valeur(`${pointeur}/${echapper(k)}`);
          if (Object.hasOwn(v, k)) erreur(`clé en double « ${k} »`, true);
          Object.defineProperty(v, k, { value: x, enumerable: true, writable: true, configurable: true });
          blancs();
          if (texte[i] === ",") {
            i++;
            continue;
          }
          if (texte[i] === "}") {
            i++;
            break;
          }
          erreur("« , » ou « } » attendu");
        }
      }
    } else if (c === "[") {
      i++;
      v = [];
      blancs();
      if (texte[i] === "]") i++;
      else {
        for (;;) {
          if (v.length >= membresMax) erreur(`tableau de plus de ${membresMax} éléments`, false, "bornes");
          v.push(valeur(`${pointeur}/${v.length}`));
          blancs();
          if (texte[i] === ",") {
            i++;
            continue;
          }
          if (texte[i] === "]") {
            i++;
            break;
          }
          erreur("« , » ou « ] » attendu");
        }
      }
    } else if (c === '"') v = chaine();
    else if (c === "t") v = litteral("true", true);
    else if (c === "f") v = litteral("false", false);
    else if (c === "n") v = litteral("null", null);
    else if (c === "-" || (c >= "0" && c <= "9")) v = nombre();
    else erreur(`caractère inattendu « ${c} »`);
    if (c === "{" || c === "[") profondeur--;
    if (etendues) etendues.set(pointeur, { debut, fin: i });
    return v;
  };
  const v = valeur("");
  blancs();
  if (i < n) erreur("texte après la valeur JSON");
  return positions ? { valeur: v, positions: etendues, texte } : v;
}

/**
 * Retire d'un texte JSON (déjà analysé, donc valide) les blancs non
 * significatifs : U+0020, U+0009, U+000A, U+000D hors des chaînes (EX-4.43).
 * Aucune valeur ne change ; ordre des membres, échappements et écriture des
 * nombres sont conservés.
 */
export function sansBlancs(texte) {
  let out = "";
  let dansChaine = false;
  for (let i = 0; i < texte.length; i++) {
    const c = texte[i];
    if (dansChaine) {
      out += c;
      if (c === "\\") out += texte[++i];
      else if (c === '"') dansChaine = false;
    } else if (c === '"') {
      dansChaine = true;
      out += c;
    } else if (c !== " " && c !== "\t" && c !== "\n" && c !== "\r") out += c;
  }
  return out;
}

/** Valeur décimale exacte d'un texte de nombre JSON, sous la forme { signe, chiffres, exposant } normalisée (sans zéro de tête ni de queue). */
function decimalExact(t) {
  const m = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(t);
  if (!m) return null;
  let chiffres = m[2] + (m[3] ?? "");
  let exposant = BigInt(m[4] ?? "0") - BigInt((m[3] ?? "").length);
  chiffres = chiffres.replace(/^0+/, "");
  if (chiffres === "") return { signe: "", chiffres: "0", exposant: 0n };
  const queue = chiffres.length - chiffres.replace(/0+$/, "").length;
  chiffres = chiffres.slice(0, chiffres.length - queue);
  exposant += BigInt(queue);
  return { signe: m[1], chiffres, exposant };
}

/**
 * Vrai si le texte d'un nombre JSON a exactement la valeur décimale de sa forme
 * JCS intégral (EX-4.44) : `0.75`, `1.0`, `1e3` oui ; `12345678901234567890`
 * (forme 12345678901234567000) et `0.10000000000000000001` (forme 0.1) non ;
 * un nombre hors de la double précision non plus.
 */
export function nombreExact(texte) {
  const v = Number(texte);
  if (!Number.isFinite(v)) return false;
  const a = decimalExact(texte);
  const b = decimalExact(J.canonicaliserJCSIntegral(v));
  if (!a || !b) return false;
  if (a.chiffres === "0" && b.chiffres === "0") return true;
  return a.signe === b.signe && a.chiffres === b.chiffres && a.exposant === b.exposant;
}

/** Les textes des nombres d'un texte JSON valide, hors des chaînes, dans l'ordre. */
export function textesDesNombres(texte) {
  const out = [];
  let dansChaine = false;
  for (let i = 0; i < texte.length; i++) {
    const c = texte[i];
    if (dansChaine) {
      if (c === "\\") i++;
      else if (c === '"') dansChaine = false;
    } else if (c === '"') dansChaine = true;
    else if (c === "-" || (c >= "0" && c <= "9")) {
      RE_NOMBRE.lastIndex = i;
      const m = RE_NOMBRE.exec(texte);
      out.push(m[0]);
      i += m[0].length - 1;
    }
  }
  return out;
}

/**
 * Lecture d'une requête d'hôte par le frontal MCP (4.4 pas 1, EX-4.3, EX-4.43,
 * EX-4.44) : rend { msg, positions, texte } ou { erreur: objet error JSON-RPC,
 * id: null ou l'id lu }. `cadrage` vaut `ligne` (stdio, connecteur, démon)
 * ou `corps` (corps POST en Streamable HTTP). Une ligne qui contient un CR
 * rend -32700 (`cr_dans_la_ligne`) ; un texte qui n'est pas du JSON strict
 * ou qui dépasse les bornes -32700 ; un lot -32600 (`lot_non_pris_en_charge`) ;
 * un nombre hors de la double précision -32602 (`arguments_non_canonisables`,
 * id null : l'analyse s'arrête) ; un nombre des arguments dont la forme JCS
 * intégral n'a pas la même valeur décimale -32602 (`nombre_non_representable`,
 * avec l'id lu).
 */
export function lireRequeteHote(texte, { cadrage = "ligne", profondeurMax = PROFONDEUR_JSON_MAX, membresMax = MEMBRES_JSON_MAX } = {}) {
  const t = typeof texte === "string" ? texte : Buffer.from(texte).toString("utf8");
  if (cadrage === "ligne" && t.includes("\r")) return { erreur: { code: -32700, message: "Parse error", data: { reason: "cr_dans_la_ligne" } }, id: null };
  let r;
  try {
    r = analyserJSONIntegral(texte, { positions: true, profondeurMax, membresMax });
  } catch (e) {
    if (e?.raison === "nombre_hors_double") return { erreur: { code: -32602, message: "Invalid params", data: { reason: "arguments_non_canonisables" } }, id: null };
    return { erreur: { code: -32700, message: "Parse error" }, id: null };
  }
  const msg = r.valeur;
  if (Array.isArray(msg)) return { erreur: { code: -32600, message: "Invalid Request", data: { reason: "lot_non_pris_en_charge" } }, id: null };
  if (msg === null || typeof msg !== "object" || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") return { erreur: { code: -32600, message: "Invalid Request" }, id: null };
  if (msg.method === "tools/call" && r.positions.has("/params/arguments")) {
    const e = r.positions.get("/params/arguments");
    if (!textesDesNombres(r.texte.slice(e.debut, e.fin)).every(nombreExact)) return { erreur: { code: -32602, message: "Invalid params", data: { reason: "nombre_non_representable" } }, id: msg.id ?? null };
  }
  return r.positions ? { msg, positions: r.positions, texte: r.texte } : { msg };
}

/** Octets UTF-8 du JCS intégral d'une valeur (la sérialisation des pièces JSON, EX-8.1). */
export function octetsJCSIntegral(valeur) {
  return Buffer.from(J.canonicaliserJCSIntegral(valeur), "utf8");
}

/** JCS intégral d'un texte JSON reçu ; lève J.ErreurFormat (ou J.ErreurJSON) si le texte n'a pas de forme canonique. */
export function jcsIntegralDuTexte(texte) {
  return J.canonicaliserJCSIntegral(analyserJSONIntegral(texte));
}

/** Copie profonde d'une valeur JSON (les membres « __proto__ » restent des membres). */
export function copieJSON(v) {
  if (Array.isArray(v)) return v.map(copieJSON);
  if (v !== null && typeof v === "object") {
    const o = {};
    for (const k of Object.keys(v)) Object.defineProperty(o, k, { value: copieJSON(v[k]), enumerable: true, writable: true, configurable: true });
    return o;
  }
  return v;
}

/** Pose un membre (y compris « __proto__ ») comme propriété propre. */
function poser(o, k, v) {
  Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
}

/** Longueur d'une chaîne en points de code (bornes de CT-1, maxLength des schémas). */
export const longueurPointsDeCode = (s) => [...s].length;

/** Tronque une chaîne à `max` points de code. */
export function tronquer(s, max) {
  const cps = [...s];
  return cps.length <= max ? s : cps.slice(0, max).join("");
}

// ---------------------------------------------------------------------------
// Pointeurs JSON (RFC 6901)
// ---------------------------------------------------------------------------

/** Décode un pointeur JSON en jetons (~1 décodé avant ~0, RFC 6901 §4) ; lève une erreur si la syntaxe est invalide. */
export function jetonsPointeur(pointeur) {
  if (pointeur === "") return [];
  if (typeof pointeur !== "string" || pointeur[0] !== "/" || /~[^01]|~$/.test(pointeur)) throw new Error(`pointeur JSON invalide : ${JSON.stringify(pointeur)}`);
  return pointeur.slice(1).split("/").map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"));
}

/**
 * Résout un pointeur JSON dans `racine` : rend { trouve, parent, cle, valeur }
 * (parent null pour la racine). Comparaison des noms octet par octet, aucune
 * normalisation (RFC 6901 §4) ; un indice de tableau est `0` ou `[1-9][0-9]*`
 * et existe ; `-` ne résout pas.
 */
export function resoudrePointeur(racine, pointeur) {
  let jetons;
  try {
    jetons = jetonsPointeur(pointeur);
  } catch {
    return { trouve: false };
  }
  let parent = null;
  let cle = null;
  let courant = racine;
  for (const t of jetons) {
    if (Array.isArray(courant)) {
      if (!/^(0|[1-9][0-9]*)$/.test(t) || Number(t) >= courant.length) return { trouve: false };
      parent = courant;
      cle = Number(t);
    } else if (courant !== null && typeof courant === "object") {
      if (!Object.hasOwn(courant, t)) return { trouve: false };
      parent = courant;
      cle = t;
    } else return { trouve: false };
    courant = parent[cle];
  }
  return { trouve: true, parent, cle, valeur: courant };
}

// ---------------------------------------------------------------------------
// Détecteurs (CT-2 §10.3)
// ---------------------------------------------------------------------------

const SEP = new Set([" ", " ", " "]);
const estSep = (c) => SEP.has(c);
const estChiffre = (c) => c !== undefined && c >= "0" && c <= "9";
const estMajuscule = (c) => c !== undefined && c >= "A" && c <= "Z";
const estAlnumAscii = (c) => c !== undefined && ((c >= "0" && c <= "9") || (c >= "A" && c <= "Z") || (c >= "a" && c <= "z"));
const estAlnumMajuscule = (c) => estChiffre(c) || estMajuscule(c);
/**
 * Frontière avant la position p : début de chaîne, fin de la correspondance
 * précédente du même détecteur (`depart`, EX-10.9), ou caractère qui n'est ni
 * un chiffre ni une lettre ASCII.
 */
const frontiereAvant = (s, p, depart = 0) => p === 0 || p === depart || !estAlnumAscii(s[p - 1]);
/** Frontière à la position q (le caractère qui suit le candidat) : fin de chaîne, ou caractère qui n'est ni un chiffre ni une lettre ASCII. */
const frontiereApres = (s, q) => q >= s.length || !estAlnumAscii(s[q]);

/**
 * Reste MOD 97-10 (ISO/IEC 7064) d'un IBAN normalisé, calculé comme le décrit
 * CT-2 §10.3.2 : quatre premiers caractères déplacés à la fin, lettres
 * remplacées par deux chiffres (A = 10 … Z = 35), réduction par blocs de neuf
 * chiffres au plus, de gauche à droite.
 */
export function resteIban(N) {
  const R = N.slice(4) + N.slice(0, 4);
  let D = "";
  for (const c of R) D += estMajuscule(c) ? String(c.charCodeAt(0) - 55) : c;
  let r = 0;
  for (let k = 0; k < D.length; k += 9) r = Number(String(r) + D.slice(k, k + 9)) % 97;
  return r;
}

/** Clés de contrôle IBAN `KK` qui rendent valide un IBAN de pays `CC` et de BBAN `bban` (génération, Pay.UK : 98 − reste). */
export function cleIban(CC, bban) {
  const r = resteIban(CC + "00" + bban);
  return String(98 - r).padStart(2, "0");
}

/** Clé de contrôle d'un numéro AVS (CT-2 §10.3.3) : sur les douze premiers chiffres, poids 1, 3, 1, 3, … de gauche à droite. */
export function cleAvs(douze) {
  let S = 0;
  for (let k = 0; k < 12; k++) S += Number(douze[k]) * (k % 2 === 0 ? 1 : 3);
  return (10 - (S % 10)) % 10;
}

/** Somme de Luhn (CT-2 §10.3.4) : vrai si la suite de chiffres passe la vérification. */
export function luhnValide(N) {
  let S = 0;
  for (let k = 0; k < N.length; k++) {
    let d = Number(N[N.length - 1 - k]);
    if (k % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    S += d;
  }
  return S % 10 === 0;
}

/** Dernier chiffre qui rend valide (Luhn) une suite de chiffres. */
export function chiffreLuhn(prefixe) {
  for (let d = 0; d <= 9; d++) if (luhnValide(prefixe + d)) return String(d);
  throw new Error("inatteignable");
}

function trouverIban(s, depart) {
  for (let p = depart; p + 4 <= s.length; p++) {
    if (!frontiereAvant(s, p, depart) || !estMajuscule(s[p]) || !estMajuscule(s[p + 1]) || !estChiffre(s[p + 2]) || !estChiffre(s[p + 3])) continue;
    const L = LONGUEURS_IBAN[s.slice(p, p + 2)];
    if (!L) continue;
    let q = p + 4;
    let N = s.slice(p, p + 4);
    let ok = true;
    while (N.length < L) {
      if (q < s.length && estSep(s[q]) && estAlnumMajuscule(s[q + 1])) q++; // séparateur isolé entre deux alphanumériques
      if (!estAlnumMajuscule(s[q])) {
        ok = false;
        break;
      }
      N += s[q++];
    }
    if (!ok || !frontiereApres(s, q) || resteIban(N) !== 1) continue;
    return { debut: p, fin: q, valeur: N };
  }
  return null;
}

function trouverAvs(s, depart) {
  for (let p = depart; p + 13 <= s.length; p++) {
    if (!frontiereAvant(s, p, depart) || s[p] !== "7" || s[p + 1] !== "5" || s[p + 2] !== "6") continue;
    let q = p + 3;
    let N = "756";
    let sep = null;
    let ok = true;
    for (const groupe of [4, 4, 2]) {
      const c = s[q];
      if (c === "." || estSep(c)) {
        if (sep !== null && sep !== c) {
          ok = false;
          break;
        }
        sep = c;
        q++;
      }
      for (let k = 0; k < groupe; k++) {
        if (!estChiffre(s[q])) {
          ok = false;
          break;
        }
        N += s[q++];
      }
      if (!ok) break;
    }
    if (!ok || !frontiereApres(s, q) || cleAvs(N) !== Number(N[12])) continue;
    return { debut: p, fin: q, valeur: N };
  }
  return null;
}

function trouverCarte(s, depart) {
  let p = depart;
  while (p < s.length) {
    if (!estChiffre(s[p])) {
      p++;
      continue;
    }
    // La suite maximale de chiffres et de séparateurs isolés (espaces admis, trait d'union) qui commence en p.
    let q = p;
    let N = "";
    while (q < s.length) {
      if (estChiffre(s[q])) {
        N += s[q++];
      } else if ((estSep(s[q]) || s[q] === "-") && estChiffre(s[q + 1])) {
        q++;
      } else break;
    }
    if (frontiereAvant(s, p, depart) && frontiereApres(s, q) && N.length >= 12 && N.length <= 19 && luhnValide(N)) return { debut: p, fin: q, valeur: N };
    p = q;
  }
  return null;
}

const CLASSE_ATEXT = "A-Za-z0-9!#$%&'*+/=?^_`{|}~-";
const RE_CAR_LOCAL = new RegExp(`[.${CLASSE_ATEXT}]`);
const RE_CAR_DOMAINE = /[A-Za-z0-9.-]/;
const RE_LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

/**
 * Détecteur email (CT-2 §10.3.5) : chaque « @ » est un point de départ ; la
 * partie locale est la suite maximale à sa gauche de caractères
 * atext ou « . » (au plus 64, lue sur 65), le domaine la suite maximale à sa
 * droite de [A-Za-z0-9.-] (au plus 255, lue sur 256), privée d'un « . » ou
 * d'un « - » final. Coût linéaire en la longueur de la chaîne.
 */
function trouverEmail(s, depart) {
  for (let a = s.indexOf("@", depart); a !== -1; a = s.indexOf("@", a + 1)) {
    let g = a;
    while (g > depart && a - g <= 64 && RE_CAR_LOCAL.test(s[g - 1])) g--;
    if (a - g > 64 || a - g === 0) continue;
    const local = s.slice(g, a);
    if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) continue;
    let d = a + 1;
    while (d < s.length && d - a - 1 <= 255 && RE_CAR_DOMAINE.test(s[d])) d++;
    if (d - a - 1 > 255) continue;
    let fin = d;
    if (fin > a + 1 && (s[fin - 1] === "." || s[fin - 1] === "-")) fin--;
    const domaine = s.slice(a + 1, fin);
    const labels = domaine.split(".");
    if (labels.length < 2 || !labels.every((l) => RE_LABEL.test(l)) || !/^[A-Za-z]{2,}$/.test(labels[labels.length - 1])) continue;
    return { debut: g, fin, valeur: `${local}@${domaine.toLowerCase()}` };
  }
  return null;
}

const estSepTelephone = (c) => estSep(c) || c === "-" || c === ".";

/**
 * Détecteur telephone (CT-2 §10.3.6) : le plus long préfixe qui respecte les
 * contraintes ; un groupe « (chiffres) » n'entre dans le candidat que si un
 * chiffre le suit ; aucun préfixe plus court n'est essayé si le caractère qui
 * suit le candidat n'est pas une frontière.
 */
function trouverTelephone(s, depart) {
  for (let p = depart; p < s.length; p++) {
    if (s[p] !== "+" || !frontiereAvant(s, p, depart) || !(s[p + 1] >= "1" && s[p + 1] <= "9")) continue;
    let i = p + 2;
    let fin = p + 2;
    let groupe = false;
    while (i < s.length) {
      const c = s[i];
      if (estChiffre(c)) {
        i++;
        fin = i;
      } else if (estSepTelephone(c)) {
        if (estSepTelephone(s[i - 1])) break;
        i++;
      } else if (c === "(") {
        if (groupe) break;
        let j = i + 1;
        while (j < s.length && estChiffre(s[j])) j++;
        if (j === i + 1 || s[j] !== ")") break;
        groupe = true;
        i = j + 1;
      } else break;
    }
    if (!frontiereApres(s, fin)) continue;
    let chiffres = "";
    for (let k = p + 1; k < fin; k++) if (estChiffre(s[k])) chiffres += s[k];
    if (chiffres.length < 8 || chiffres.length > 15) continue;
    return { debut: p, fin, valeur: "+" + chiffres };
  }
  return null;
}

function trouverRegex(re, s, depart) {
  let i = depart;
  while (i <= s.length) {
    re.lastIndex = i;
    const m = re.exec(s);
    if (!m) return null;
    if (m[0].length === 0) {
      const cp = s.codePointAt(m.index);
      i = m.index + (cp !== undefined && cp > 0xffff ? 2 : 1);
      continue;
    }
    return { debut: m.index, fin: m.index + m[0].length, valeur: m[0] };
  }
  return null;
}

const TROUVEURS = { iban: trouverIban, avs: trouverAvs, carte: trouverCarte, email: trouverEmail, telephone: trouverTelephone };

/**
 * Découpe une chaîne en segments séparés par les jetons (EX-10.9) : rend
 * [{ texte, jeton }] dans l'ordre ; `reJetons` est l'expression des jetons de
 * la politique (null : aucun jeton reconnu).
 */
export function segmentsHorsJetons(s, reJetons) {
  if (!reJetons) return [{ texte: s, jeton: false }];
  const out = [];
  let i = 0;
  reJetons.lastIndex = 0;
  for (let m = reJetons.exec(s); m; m = reJetons.exec(s)) {
    if (m.index > i) out.push({ texte: s.slice(i, m.index), jeton: false });
    out.push({ texte: m[0], jeton: true });
    i = m.index + m[0].length;
  }
  if (i < s.length || out.length === 0) out.push({ texte: s.slice(i), jeton: false });
  return out;
}

/**
 * Applique un détecteur de texte à une chaîne (EX-10.9) : sur chaque segment
 * hors jeton, indépendamment, correspondances de gauche à droite, sans
 * chevauchement, chaque recherche reprenant après la fin de la précédente, qui
 * vaut frontière. `jeton(valeurNormalisee)` donne le remplacement. Rend
 * { texte, nombre }.
 */
export function appliquerDetecteurTexte(s, trouveur, jeton, reJetons = null) {
  let out = "";
  let nombre = 0;
  for (const seg of segmentsHorsJetons(s, reJetons)) {
    if (seg.jeton) {
      out += seg.texte;
      continue;
    }
    const x = seg.texte;
    let i = 0;
    for (;;) {
      const m = trouveur(x, i);
      if (!m) break;
      out += x.slice(i, m.debut) + jeton(m.valeur);
      i = m.fin;
      nombre++;
    }
    out += x.slice(i);
  }
  return { texte: out, nombre };
}

/** Les correspondances d'un détecteur nommé dans une chaîne (pour les tests et l'inspection) : [{ debut, fin, valeur }]. */
export function correspondances(type, s, motif) {
  const trouveur = type === "regex" ? (x, d) => trouverRegex(compilerMotif(motif), x, d) : TROUVEURS[type];
  if (!trouveur) throw new Error(`détecteur inconnu : ${type}`);
  const out = [];
  let i = 0;
  for (;;) {
    const m = trouveur(s, i);
    if (!m) return out;
    out.push(m);
    i = m.fin;
  }
}

// ---------------------------------------------------------------------------
// Borne de temps des motifs (EX-10.23)
// ---------------------------------------------------------------------------

/** Contexte node:vm où s'exécute une opération bornée, et le script qui appelle la fonction de l'opération. */
const CONTEXTE_BUDGET = vm.createContext(Object.create(null));
const SCRIPT_BUDGET = new vm.Script("operation()", { filename: "noortrace-budget-redaction" });

/** Règle de rédaction en cours d'application, pour la note d'un dépassement (EX-10.23 : opération, portée, règle, sans valeur). */
let regleEnCours = null;

/**
 * Exécute `fn` sous la borne de temps d'EX-10.23 : `budgetMs` millisecondes
 * (entier ≥ 1, défaut limits.redaction_budget_ms = 1000) mesurées depuis le
 * début de l'opération ; l'exécution est interrompue au dépassement, même au
 * milieu d'une recherche d'expression régulière (contexte node:vm, option
 * timeout). `budgetMs` null ou Infinity : sans borne propre, pour une partie
 * d'une opération que l'appelant borne déjà (aucune imbrication). Rend
 * { ok: true, valeur } ou { ok: false } au dépassement ; seule l'erreur
 * ERR_SCRIPT_EXECUTION_TIMEOUT est interceptée.
 */
export function sousBudget(fn, budgetMs = BUDGET_REDACTION_MS) {
  if (budgetMs === null || budgetMs === Infinity) return { ok: true, valeur: fn() };
  if (!Number.isSafeInteger(budgetMs) || budgetMs < 1) throw new Error(`budget de rédaction invalide : ${budgetMs}`);
  const precedente = CONTEXTE_BUDGET.operation;
  CONTEXTE_BUDGET.operation = fn;
  try {
    return { ok: true, valeur: SCRIPT_BUDGET.runInContext(CONTEXTE_BUDGET, { timeout: budgetMs }) };
  } catch (e) {
    if (e?.code === "ERR_SCRIPT_EXECUTION_TIMEOUT") return { ok: false };
    throw e;
  } finally {
    CONTEXTE_BUDGET.operation = precedente;
  }
}

/** Note d'un dépassement (journal d'exploitation redaction_budget_exceeded, compteur noortrace_redaction_budget_exceeded_total{operation,scope}) : jamais de valeur. */
function noterDepassement(onDepassement, operation, scope, rule = null) {
  const note = { event: "redaction_budget_exceeded", operation, scope, rule };
  if (typeof onDepassement === "function") onDepassement(note);
  return note;
}

// ---------------------------------------------------------------------------
// Politique de rédaction (CT-2 §10.2, §10.4)
// ---------------------------------------------------------------------------

/** Taille développée maximale d'un motif (EX-10.6, règle c). */
export const TAILLE_DEVELOPPEE_MAX = 1000;

/**
 * Vérifie qu'une expression régulière est du sous-ensemble commun
 * ECMAScript/RE2 d'EX-10.6 (liste autorisée : littéraux, échappements
 * nommés, `\xHH`, `\d \D \w \W \b \B`, classes non vides sans classe POSIX,
 * groupes simples, non capturants et nommés, quantificateurs bornés à 1000
 * et écrits sans zéro non significatif, paresseux admis, ancres `^ $`,
 * alternative), puis, sur l'arbre du motif,
 * les règles de structure et de taille d'EX-10.6, dans cet ordre :
 *   a) aucun quantificateur sur un groupe dont le corps contient, à quelque
 *      profondeur que ce soit, un quantificateur ou une alternative ;
 *   b) le corps d'un groupe quantifié contient au moins un littéral, un
 *      échappement de caractère ou une classe ;
 *   c) taille développée d'au plus 1000 ;
 * et enfin qu'elle se compile en ECMAScript (drapeau « u », seules les
 * ouvertures de groupe nommé `(?P<nom>` reconnues par l'analyse étant écrites
 * `(?<nom>`, sourceECMAScript). Rend la liste des erreurs, vide si le motif est
 * admis ; un motif refusé par une règle de structure ou de taille porte une
 * seule erreur, celle de la première règle en échec.
 */
export function erreursMotifRE2(motif) {
  if (typeof motif !== "string") return ["motif : chaîne attendue"];
  const { erreurs, arbre, ouverturesP } = analyserMotif(motif);
  if (erreurs.length) return erreurs;
  const structure = erreurStructureMotif(arbre);
  if (structure) return [structure];
  try {
    new RegExp(reecrireOuverturesP(motif, ouverturesP), "u");
  } catch (e) {
    return [`expression invalide en ECMAScript : ${e.message}`];
  }
  return [];
}

/** Écrit `(?<` à chacune des positions (en points de code) d'une ouverture `(?P<` reconnue par l'analyse, et ne change rien d'autre (EX-10.6). */
function reecrireOuverturesP(motif, ouverturesP) {
  if (!ouverturesP.length) return motif;
  const cps = [...motif];
  for (const i of ouverturesP) cps[i + 2] = "";
  return cps.join("");
}

/**
 * Source ECMAScript d'un motif admis (EX-10.6) : chaque ouverture de groupe
 * nommé `(?P<nom>` reconnue par l'analyse (parenthèse non échappée, hors
 * classe) est écrite `(?<nom>`, seule forme qu'ECMAScript admet ; aucune autre
 * suite n'est modifiée (une suite « (?P< » dans une classe ou après une
 * parenthèse échappée garde son sens). Lève une erreur pour un motif hors du
 * sous-ensemble commun.
 */
export function sourceECMAScript(motif) {
  const { erreurs, ouverturesP } = analyserMotif(String(motif));
  if (erreurs.length) throw new Error(`motif hors du sous-ensemble commun : ${erreurs.join(", ")}`);
  return reecrireOuverturesP(String(motif), ouverturesP);
}

/**
 * Analyse lexicale et syntaxique d'un motif selon la liste autorisée
 * d'EX-10.6 : rend { erreurs, arbre, ouverturesP } (arbre null si le motif
 * est refusé ; ouverturesP : positions, en points de code, de la parenthèse
 * de chaque ouverture de groupe nommé écrite `(?P<nom>`).
 */
function analyserMotif(motif) {
  const erreurs = [];
  const ouverturesP = [];
  const META = new Set(["\\", "^", "$", ".", "|", "?", "*", "+", "(", ")", "[", "]", "{", "}"]);
  const ECH_LITTERAL = new Set(["\\", "^", "$", ".", "|", "?", "*", "+", "(", ")", "[", "]", "{", "}", "/"]);
  const ECH_CONTROLE = new Set(["t", "n", "r", "f", "v"]);
  const ECH_CLASSE = new Set(["d", "D", "w", "W"]);
  const noms = new Set();
  const cps = [...motif];
  let i = 0;
  const err = (m) => {
    erreurs.push(`${m} (position ${i})`);
    throw new Error("arrêt");
  };
  // Un échappement hors classe ou dans une classe : rend { genre: "car"|"classe"|"assertion", cp }.
  const echappement = (dansClasse) => {
    const e = cps[i + 1];
    if (e === undefined) err("échappement final");
    if (ECH_LITTERAL.has(e)) {
      i += 2;
      return { genre: "car", cp: e.codePointAt(0) };
    }
    if (dansClasse && e === "-") {
      i += 2;
      return { genre: "car", cp: 0x2d };
    }
    if (ECH_CONTROLE.has(e)) {
      i += 2;
      return { genre: "car", cp: { t: 9, n: 10, r: 13, f: 12, v: 11 }[e] };
    }
    if (e === "x") {
      const h = cps.slice(i + 2, i + 4).join("");
      if (!/^[0-9A-Fa-f]{2}$/.test(h)) err("\\x exige deux chiffres hexadécimaux (\\x{…} est refusé)");
      i += 4;
      return { genre: "car", cp: parseInt(h, 16) };
    }
    if (ECH_CLASSE.has(e)) {
      i += 2;
      return { genre: "classe" };
    }
    if (!dansClasse && (e === "b" || e === "B")) {
      i += 2;
      return { genre: "assertion" };
    }
    err(`échappement \\${e} hors du sous-ensemble commun`);
  };
  const classe = () => {
    i++; // [
    if (cps[i] === "^") i++;
    const debut = i;
    let elements = 0;
    while (cps[i] !== "]") {
      if (cps[i] === undefined) err("classe non fermée");
      if (cps[i] === "[") err("« [ » non échappé dans une classe (classes POSIX refusées)");
      let a;
      const premier = i === debut;
      if (cps[i] === "\\") a = echappement(true);
      else if (cps[i] === "-") {
        if (!premier && cps[i + 1] !== "]") err("« - » littéral seulement en première ou dernière position");
        a = { genre: "car", cp: 0x2d };
        i++;
      } else a = { genre: "car", cp: cps[i++].codePointAt(0) };
      elements++;
      if (cps[i] === "-" && cps[i + 1] !== "]" && cps[i + 1] !== undefined) {
        i++;
        let b;
        if (cps[i] === "\\") b = echappement(true);
        else if (cps[i] === "[") err("« [ » non échappé dans une classe");
        else b = { genre: "car", cp: cps[i++].codePointAt(0) };
        if (a.genre !== "car" || b.genre !== "car") err("intervalle dont une borne est une classe");
        if (a.cp > b.cp) err("intervalle décroissant");
      }
    }
    if (elements === 0) err("classe vide");
    i++; // ]
  };
  // Quantificateur à la position courante : rend null, ou { min, max } (max null : non borné).
  const quantificateur = () => {
    const c = cps[i];
    let q;
    if (c === "*") q = { min: 0, max: null };
    else if (c === "+") q = { min: 1, max: null };
    else if (c === "?") q = { min: 0, max: 1 };
    if (q) i++;
    else if (c === "{") {
      const reste = cps.slice(i).join("");
      // n et m de la forme 0|[1-9][0-9]{0,3} : Go et RE2 refusent un zéro non significatif et lisent alors « { » comme un littéral.
      const m = /^\{(0|[1-9][0-9]{0,3})(,((?:0|[1-9][0-9]{0,3})?))?\}/.exec(reste);
      if (!m && /^\{[0-9]{1,4}(,[0-9]{0,4})?\}/.test(reste)) err("zéro non significatif dans un quantificateur");
      if (!m) err("« { » qui n'ouvre pas un quantificateur (à échapper)");
      const n = Number(m[1]);
      const mm = m[2] === undefined ? n : m[3] === "" ? null : Number(m[3]);
      if (n > 1000 || (mm !== null && (mm > 1000 || mm < n))) err("quantificateur hors de 0 ≤ n ≤ m ≤ 1000");
      q = { min: n, max: mm, borne: m[2] === undefined ? "exacte" : mm === null ? "ouverte" : "intervalle" };
      i += [...m[0]].length;
    } else return null;
    if (cps[i] === "?") i++;
    if (cps[i] === "*" || cps[i] === "+" || cps[i] === "?" || cps[i] === "{") err("quantificateur répété ou possessif");
    return q;
  };
  // Arbre : { t: "atome", consomme }, { t: "groupe", corps }, { t: "alt", branches }, { t: "seq", elements }, { t: "quant", sous, min, max, borne, pos }.
  const alternative = (profondeur) => {
    const branches = [];
    for (;;) {
      branches.push(sequence(profondeur));
      if (cps[i] === "|") {
        i++;
        continue;
      }
      return { t: "alt", branches };
    }
  };
  const sequence = (profondeur) => {
    const elements = [];
    for (;;) {
      const c = cps[i];
      if (c === undefined || c === "|" || c === ")") {
        if (c === ")" && profondeur === 0) err("« ) » sans « ( »");
        return { t: "seq", elements };
      }
      let noeud;
      if (c === "^" || c === "$") {
        i++;
        noeud = { t: "atome", consomme: false };
      } else if (c === "\\") {
        const e = echappement(false);
        noeud = { t: "atome", consomme: e.genre !== "assertion" };
      } else if (c === "[") {
        classe();
        noeud = { t: "atome", consomme: true };
      } else if (c === "(") {
        const ouverture = i;
        i++;
        if (cps[i] === "?") {
          const reste = cps.slice(i).join("");
          const m = /^\?(?::|P?<([A-Za-z][A-Za-z0-9_]{0,31})>)/.exec(reste);
          if (!m) err("construction (?…) hors du sous-ensemble commun (recherches avant ou arrière, groupes atomiques, drapeaux)");
          if (m[0].startsWith("?P<")) ouverturesP.push(ouverture);
          if (m[1] !== undefined) {
            if (noms.has(m[1])) err(`nom de groupe en double : ${m[1]}`);
            noms.add(m[1]);
          }
          i += [...m[0]].length;
        }
        const corps = alternative(profondeur + 1);
        if (cps[i] !== ")") err("groupe non fermé");
        i++;
        noeud = { t: "groupe", corps };
      } else if (c === ".") err("« . » refusé (son sens diffère entre ECMAScript et RE2 ; écrire [^\\n])");
      else if (META.has(c)) err(`« ${c} » non échappé`);
      else {
        i++;
        noeud = { t: "atome", consomme: true };
      }
      const pos = i;
      const q = quantificateur();
      if (q) {
        if (noeud.t === "atome" && !noeud.consomme) err("quantificateur sur une ancre ou une frontière");
        noeud = { t: "quant", sous: noeud, ...q, pos };
      }
      elements.push(noeud);
    }
  };
  let arbre = null;
  try {
    arbre = alternative(0);
    if (i < cps.length) err("« ) » sans « ( »");
  } catch (e) {
    if (e.message !== "arrêt") throw e;
  }
  return { erreurs, arbre: erreurs.length ? null : arbre, ouverturesP: erreurs.length ? [] : ouverturesP };
}

/** Les nœuds d'un arbre de motif, en profondeur d'abord, dans l'ordre du motif. */
function* noeudsMotif(n) {
  yield n;
  if (n.t === "groupe") yield* noeudsMotif(n.corps);
  else if (n.t === "alt") for (const b of n.branches) yield* noeudsMotif(b);
  else if (n.t === "seq") for (const e of n.elements) yield* noeudsMotif(e);
  else if (n.t === "quant") yield* noeudsMotif(n.sous);
}

/** Taille développée d'un nœud (EX-10.6, règle c). */
function tailleDeveloppee(n) {
  switch (n.t) {
    case "atome":
      return 1;
    case "groupe":
      return tailleDeveloppee(n.corps);
    case "alt":
      return n.branches.reduce((s, b) => s + tailleDeveloppee(b), 0);
    case "seq":
      return n.elements.reduce((s, e) => s + tailleDeveloppee(e), 0);
    case "quant": {
      const facteur = n.borne === "exacte" ? Math.max(n.min, 1) : n.borne === "ouverte" ? n.min + 1 : n.borne === "intervalle" ? Math.max(n.max, 1) : 1;
      return tailleDeveloppee(n.sous) * facteur;
    }
    default:
      throw new Error(`nœud de motif inconnu : ${n.t}`);
  }
}

/** Règles a) à c) d'EX-10.6 sur l'arbre d'un motif : la première en échec, ou null. */
function erreurStructureMotif(arbre) {
  const groupesQuantifies = [...noeudsMotif(arbre)].filter((n) => n.t === "quant" && n.sous.t === "groupe");
  // a) Aucune répétition imbriquée ou ambiguë.
  for (const q of groupesQuantifies) {
    const interieur = [...noeudsMotif(q.sous.corps)];
    if (interieur.some((n) => n.t === "quant" || (n.t === "alt" && n.branches.length > 1))) return `répétition imbriquée ou ambiguë (EX-10.6 a) (position ${q.pos})`;
  }
  // b) Aucun groupe quantifié qui peut être vide.
  for (const q of groupesQuantifies) {
    if (![...noeudsMotif(q.sous.corps)].some((n) => n.t === "atome" && n.consomme)) return `groupe quantifié qui peut être vide (EX-10.6 b) (position ${q.pos})`;
  }
  // c) Taille développée d'au plus 1000.
  const taille = tailleDeveloppee(arbre);
  if (taille > TAILLE_DEVELOPPEE_MAX) return `taille développée ${taille} au-delà de ${TAILLE_DEVELOPPEE_MAX} (EX-10.6 c)`;
  return null;
}

/** Taille développée d'un motif (EX-10.6, règle c), ou null s'il n'est pas fait des constructions de la liste autorisée. */
export function tailleDeveloppeeMotif(motif) {
  const { arbre } = analyserMotif(String(motif));
  return arbre === null ? null : tailleDeveloppee(arbre);
}

/** Compile un motif nommé (RE2, sans drapeau) en expression ECMAScript globale à points de code (sourceECMAScript, EX-10.6). */
function compilerMotif(motif) {
  return new RegExp(sourceECMAScript(motif), "gu");
}

/** Compile un `extract` de gabarit d'effets comme un motif nommé, sans le drapeau g : la première correspondance depuis le début (EX-7.6, EX-10.6). */
export function compilerExtract(motif) {
  return new RegExp(sourceECMAScript(motif), "u");
}

/** Les types de jetons qu'une politique peut produire : les cinq détecteurs nommés, les motifs et les étiquettes employés. */
function typesDeJetons(doc) {
  const types = new Set(DETECTEURS_NOMMES);
  for (const r of doc.rules ?? []) for (const d of r.detectors ?? []) {
    if (d.type === "regex") types.add(d.name);
    if (d.type === "champ") types.add(d.label);
  }
  types.add("prompt-systeme");
  return [...types];
}

/**
 * Valide une politique de rédaction : schéma (`schemas` : registre qui
 * contient le schéma de la politique), puis les règles qu'il n'exprime pas
 * (EX-10.6). Le contrôle des jetons (aucun motif nommé ne fait correspondre
 * un jeton de la politique) exécute chaque motif : il tient, motif par motif,
 * dans `budgetMs` (limits.redaction_budget_ms, EX-10.23, quatrième
 * opération) ; au-delà, le motif est refusé (« motif trop coûteux sur les
 * jetons »). Rend la liste des erreurs (chaînes), vide si la politique est
 * recevable.
 */
export function erreursPolitiqueRedaction(doc, { schemas, budgetMs = BUDGET_REDACTION_MS } = {}) {
  const erreurs = [];
  if (schemas?.[ID_SCHEMA_POLITIQUE_REDACTION]) {
    for (const e of J.validerSchema(doc, schemas[ID_SCHEMA_POLITIQUE_REDACTION], { registre: schemas })) erreurs.push(`schéma ${e.chemin} : ${e.message}`);
  }
  if (!doc || typeof doc !== "object" || !Array.isArray(doc.rules)) return erreurs.length ? erreurs : ["politique : objet à règles attendu"];
  const ids = new Set();
  const motifs = doc.named_patterns ?? {};
  doc.rules.forEach((r, i) => {
    const ou = `rules[${i}]${r?.id ? ` (${r.id})` : ""}`;
    if (ids.has(r.id)) erreurs.push(`${ou} : id en double`);
    ids.add(r.id);
    const detecteurs = Array.isArray(r.detectors) ? r.detectors : [];
    if (detecteurs.some((d) => d.type === "champ") && r.path === undefined) erreurs.push(`${ou} : un détecteur champ exige path`);
    if (r.action?.kind === "supprimer" && (r.path === undefined || detecteurs.length !== 1 || detecteurs[0].type !== "champ")) erreurs.push(`${ou} : supprimer exige path et le seul détecteur champ`);
    if (r.action?.kind === "pseudonyme" && (doc.pseudonym_key === null || doc.pseudonym_key === undefined)) erreurs.push(`${ou} : pseudonyme exige pseudonym_key non nul`);
    for (const d of detecteurs) if (d.type === "regex" && !Object.hasOwn(motifs, d.name)) erreurs.push(`${ou} : motif nommé inconnu ${d.name}`);
  });
  const types = typesDeJetons(doc);
  for (const [nom, def] of Object.entries(motifs)) {
    const e = erreursMotifRE2(def.pattern);
    if (e.length) {
      erreurs.push(`named_patterns.${nom} : ${e.join(", ")}`);
      continue;
    }
    const re = compilerMotif(def.pattern);
    const jetons = types.flatMap((t) => [`[REDIGE:${t}]`, `[PSEUDO:${t}:000000000000]`]);
    const b = sousBudget(() => jetons.filter((jeton) => trouverRegex(re, jeton, 0)), budgetMs);
    if (!b.ok) {
      erreurs.push(`named_patterns.${nom} : motif trop coûteux sur les jetons (EX-10.23)`);
      continue;
    }
    for (const jeton of b.valeur) erreurs.push(`named_patterns.${nom} : fait correspondre le jeton ${jeton} (idempotence, EX-10.6)`);
  }
  return erreurs;
}

/**
 * Charge une politique de rédaction : la valide (lève ErreurConfiguration si
 * elle est refusée), compile ses motifs. `clePseudonyme` : la valeur du secret
 * `pseudonym_key` (Buffer), résolue par l'appelant ; requise si une règle
 * emploie l'action pseudonyme. `budgetMs` : limits.redaction_budget_ms,
 * qui borne le contrôle des jetons (EX-10.23).
 */
export function chargerPolitique(doc, { schemas, clePseudonyme = null, budgetMs = BUDGET_REDACTION_MS } = {}) {
  const erreurs = erreursPolitiqueRedaction(doc, { schemas, budgetMs });
  if (erreurs.length) throw new ErreurConfiguration(`politique de rédaction ${doc?.name ?? "?"} refusée`, erreurs);
  if (doc.rules.some((r) => r.action.kind === "pseudonyme") && !clePseudonyme) throw new ErreurConfiguration(`politique ${doc.name} : la clé de pseudonymisation n'est pas résolue`);
  const motifs = new Map(Object.entries(doc.named_patterns ?? {}).map(([nom, def]) => [nom, compilerMotif(def.pattern)]));
  return { doc, name: doc.name, motifs, reJetons: expressionJetons(typesDeJetons(doc)), types: new Set(typesDeJetons(doc)), clePseudonyme: clePseudonyme ? Buffer.from(clePseudonyme) : null };
}

/** L'expression des jetons d'une politique (EX-10.9) : [REDIGE:t] et [PSEUDO:t:<12 hex>] pour chaque type t. */
export function expressionJetons(types) {
  const alt = [...types].map((x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
  return new RegExp(`\\[(?:REDIGE:(?:${alt})|PSEUDO:(?:${alt}):[0-9a-f]{12})\\]`, "gu");
}

/** Vrai si la valeur est exactement un jeton de la politique (EX-10.11). */
export function estJeton(politique, v) {
  if (typeof v !== "string" || !politique?.reJetons) return false;
  const re = new RegExp(`^(?:${politique.reJetons.source})$`, "u");
  return re.test(v);
}

/**
 * Décode la valeur résolue d'une référence de secret selon son `encoding`
 * (CT-2 §15.2, EX-10.12) : hex (préfixe 0x facultatif, longueur paire),
 * base64 (RFC 4648 §4, avec remplissage) ou utf8. Lève une erreur si la valeur
 * ne se décode pas.
 */
export function decoderSecret(valeur, encoding) {
  if (encoding === "hex") {
    const h = valeur.startsWith("0x") ? valeur.slice(2) : valeur;
    if (!/^(?:[0-9a-fA-F]{2})+$/.test(h)) throw new ErreurConfiguration("secret hex invalide");
    return Buffer.from(h, "hex");
  }
  if (encoding === "base64") {
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(valeur) || valeur === "") throw new ErreurConfiguration("secret base64 invalide");
    return Buffer.from(valeur, "base64");
  }
  if (encoding === "utf8") return Buffer.from(valeur, "utf8");
  throw new ErreurConfiguration(`encoding de secret inconnu : ${encoding}`);
}

/** Pseudonyme à clé (EX-10.12) : « [PSEUDO:t:<12 hex>] », HMAC-SHA-256(K, UTF-8(t) ‖ 0x00 ‖ UTF-8(V)) tronqué à six octets. */
export function pseudonyme(cle, type, valeur) {
  const P = createHmac("sha256", cle).update(Buffer.concat([Buffer.from(type, "utf8"), Buffer.from([0]), Buffer.from(valeur, "utf8")])).digest();
  return `[PSEUDO:${type}:${P.subarray(0, 6).toString("hex")}]`;
}

/** Vrai si la règle s'applique à une pièce de portée `portee` rattachée à l'outil annoncé `outil` (EX-10.14). */
export function regleApplicable(regle, portee, outil = null, alias = null) {
  if (!regle.scopes.includes(portee)) return false;
  if (regle.tools === "*") return true;
  if (PORTEES_SANS_OUTIL.has(portee) || outil === null) return false;
  if (regle.tools.includes(outil)) return true;
  const a = alias ?? (outil.includes(SEPARATEUR_ALIAS) ? outil.slice(0, outil.indexOf(SEPARATEUR_ALIAS)) : null);
  return a !== null && regle.tools.includes(`${a}${SEPARATEUR_ALIAS}*`);
}

/** Remplace en place chaque chaîne d'une valeur, en profondeur d'abord, membres dans l'ordre JCS (EX-10.14). */
function transformerChaines(v, fn) {
  if (typeof v === "string") return fn(v);
  if (Array.isArray(v)) {
    for (let i = 0; i < v.length; i++) v[i] = transformerChaines(v[i], fn);
    return v;
  }
  if (v !== null && typeof v === "object") {
    for (const k of Object.keys(v).sort()) poser(v, k, transformerChaines(v[k], fn));
    return v;
  }
  return v;
}

/** Sérialisation qui sert à comparer avant et après rédaction (EX-10.16) : le texte pour une pièce texte, le JCS intégral sinon. */
const serialisationPiece = (v) => (typeof v === "string" ? v : J.canonicaliserJCSIntegral(v));

/** Un passage de la politique sur une valeur (EX-10.14) : rend { valeur, change, comptes, notes }. */
function passageRedaction(politique, v, { portee, outil, alias }) {
  const notes = [];
  const comptes = [];
  let change = false;
  for (const regle of politique.doc.rules) {
    if (!regleApplicable(regle, portee, outil, alias)) continue;
    regleEnCours = regle.id;
    const pointeur = regle.path ?? "";
    const r = resoudrePointeur(v, pointeur);
    if (!r.trouve) {
      notes.push(`règle ${regle.id} : pointeur ${pointeur} non résolu, sans effet`);
      continue;
    }
    const lire = () => (r.parent === null ? v : r.parent[r.cle]);
    const ecrire = (x) => {
      if (r.parent === null) v = x;
      else if (Array.isArray(r.parent)) r.parent[r.cle] = x;
      else poser(r.parent, r.cle, x);
    };
    const action = regle.action.kind;
    for (const [rang, d] of regle.detectors.entries()) {
      let nombre = 0;
      if (d.type === "champ") {
        const actuelle = lire();
        // Une valeur qui est déjà un jeton est laissée telle quelle (EX-10.11).
        if (!(r.parent !== null && !Array.isArray(r.parent) && !Object.hasOwn(r.parent, r.cle)) && !estJeton(politique, actuelle)) {
          if (action === "supprimer") {
            if (r.parent === null || Array.isArray(r.parent)) ecrire(`[REDIGE:${d.label}]`);
            else delete r.parent[r.cle];
          } else if (action === "pseudonyme") {
            ecrire(pseudonyme(politique.clePseudonyme, d.label, typeof actuelle === "string" ? actuelle : J.canonicaliserJCSIntegral(actuelle)));
          } else {
            ecrire(`[REDIGE:${d.label}]`);
          }
          nombre = 1;
        }
      } else {
        const type = d.type === "regex" ? d.name : d.type;
        const trouveur = d.type === "regex" ? (s, i) => trouverRegex(politique.motifs.get(d.name), s, i) : TROUVEURS[d.type];
        const jeton = action === "pseudonyme" ? (val) => pseudonyme(politique.clePseudonyme, type, val) : () => `[REDIGE:${type}]`;
        ecrire(
          transformerChaines(lire(), (s) => {
            const res = appliquerDetecteurTexte(s, trouveur, jeton, politique.reJetons);
            nombre += res.nombre;
            return res.texte;
          }),
        );
      }
      if (nombre > 0) {
        change = true;
        comptes.push({ rule: regle.id, rang, detector: d.type, count: nombre });
      }
    }
  }
  return { valeur: v, change, comptes, notes };
}

/** Les passages d'EX-10.14 sur une copie de la valeur, sans borne de temps : { valeur, correspondances, notes }. */
function passagesRedaction(politique, valeur, { portee, outil, alias }) {
  let v = copieJSON(valeur);
  let notes = [];
  const cumul = new Map();
  for (let passage = 0; ; passage++) {
    if (passage > 64) throw new Error("rédaction : la règle des passages ne converge pas (bogue)");
    const r = passageRedaction(politique, v, { portee, outil, alias });
    v = r.valeur;
    if (passage === 0) notes = r.notes;
    for (const c of r.comptes) {
      const cle = `${c.rule}\u0000${c.rang}`;
      if (cumul.has(cle)) cumul.get(cle).count += c.count;
      else cumul.set(cle, { rule: c.rule, detector: c.detector, count: c.count });
    }
    if (!r.change) break;
  }
  return { valeur: v, correspondances: [...cumul.values()], notes };
}

/**
 * Applique une politique chargée (chargerPolitique) à la valeur d'une pièce
 * (EX-10.14) : passages successifs (règles dans l'ordre, celles dont la portée
 * et l'outil conviennent, chacune sur la valeur produite par la précédente)
 * jusqu'à ce qu'un passage ne change plus rien. `texte` : la pièce est une
 * chaîne (prompt système, intention, contexte text/plain), dont la racine est
 * la chaîne elle-même. Rend { valeur, redacted, correspondances: [{ rule,
 * detector, count }] (additionnées sur les passages), notes, depasse } ;
 * `valeur` d'entrée n'est pas modifiée. Toute la rédaction (tous passages,
 * toutes règles) tient dans `budgetMs` (EX-10.23, défaut 1000) : au-delà,
 * `depasse` est vrai, `valeur` est null et la copie partielle est jetée ;
 * l'appelant remplace la pièce par la pièce « non rédigeable »
 * (`budget_redaction`, EX-8.7) ; `onDepassement` reçoit la note
 * redaction_budget_exceeded (opération `piece`, portée, règle).
 * La sérialisation de la valeur en clair (EX-10.16) est calculée une fois,
 * avant la rédaction : elle sert à `redacted` et, au-delà du budget, à la
 * longueur de la pièce non rédigeable (`longueurClair`, octets UTF-8, EX-8.7).
 */
export function rediger(politique, valeur, { portee, outil = null, alias = null, budgetMs = BUDGET_REDACTION_MS, onDepassement = null } = {}) {
  if (!PORTEES.includes(portee)) throw new Error(`portée inconnue : ${portee}`);
  if (!politique) return { valeur: copieJSON(valeur), redacted: false, correspondances: [], notes: [], depasse: false };
  const clair = serialisationPiece(valeur);
  regleEnCours = null;
  const r = sousBudget(() => passagesRedaction(politique, valeur, { portee, outil, alias }), budgetMs);
  if (!r.ok) {
    const note = noterDepassement(onDepassement, "piece", portee, regleEnCours);
    return { valeur: null, redacted: true, correspondances: [], notes: [`budget_redaction : règle ${note.rule ?? "?"}, portée ${portee}`], depasse: true, longueurClair: Buffer.byteLength(clair, "utf8") };
  }
  const { valeur: v, correspondances, notes } = r.valeur;
  const redacted = serialisationPiece(v) !== clair;
  return { valeur: v, redacted, correspondances, notes, depasse: false };
}

/** Les détecteurs de texte d'une règle (EX-10.6 : iban, avs, carte, email, telephone, regex), sans le détecteur champ. */
const detecteursTexte = (regle) => (regle.detectors ?? []).filter((d) => d.type !== "champ");

/**
 * Applique à une chaîne les détecteurs de texte des règles données, chacune
 * avec son action (remplacer ou pseudonyme ; supprimer, qui n'a que le
 * détecteur champ, ne joue pas), dans l'ordre, par passages jusqu'au point
 * fixe comme EX-10.14. La chaîne est la racine : `path` ne s'applique pas à
 * une valeur en ligne. Sans borne de temps : l'appelant l'exécute sous
 * sousBudget. Rend { texte, correspondances: [{ rule, detector, count }] }.
 */
function redigerChaineParDetecteurs(politique, chaine, regles) {
  let texte = chaine;
  const cumul = new Map();
  for (let passage = 0; ; passage++) {
    if (passage > 64) throw new Error("rédaction : la règle des passages ne converge pas (bogue)");
    let change = false;
    for (const regle of regles) {
      regleEnCours = regle.id;
      const action = regle.action?.kind;
      if (action !== "remplacer" && action !== "pseudonyme") continue;
      detecteursTexte(regle).forEach((d, rang) => {
        const type = d.type === "regex" ? d.name : d.type;
        const trouveur = d.type === "regex" ? (x, i) => trouverRegex(politique.motifs.get(d.name), x, i) : TROUVEURS[d.type];
        const jeton = action === "pseudonyme" ? (val) => pseudonyme(politique.clePseudonyme, type, val) : () => `[REDIGE:${type}]`;
        const res = appliquerDetecteurTexte(texte, trouveur, jeton, politique.reJetons);
        if (res.nombre > 0) {
          change = true;
          texte = res.texte;
          const cle = `${regle.id}\u0000${rang}`;
          if (cumul.has(cle)) cumul.get(cle).count += res.nombre;
          else cumul.set(cle, { rule: regle.id, detector: d.type, count: res.nombre });
        }
      });
    }
    if (!change) break;
  }
  return { texte, correspondances: [...cumul.values()] };
}

/**
 * Examen d'une valeur déclarée qui entre en ligne dans la chaîne (`run_id`,
 * EX-7.2 ; nom de prompt, EX-8.6) par les détecteurs de texte de **toutes**
 * les règles de la politique, quelle que soit leur portée. Tient dans
 * `budgetMs` (EX-10.23, opération `valeur`) : au-delà, la valeur est traitée
 * comme une valeur où un détecteur a trouvé une correspondance. Rend
 * { correspondance, depasse }.
 */
export function examinerValeurEnLigne(politique, valeur, { budgetMs = BUDGET_REDACTION_MS, onDepassement = null, scope = null } = {}) {
  if (!politique || typeof valeur !== "string") return { correspondance: false, depasse: false };
  const regles = politique.doc.rules.filter((r) => detecteursTexte(r).length > 0).map((r) => ({ ...r, action: { kind: "remplacer" } }));
  regleEnCours = null;
  const b = sousBudget(() => redigerChaineParDetecteurs(politique, valeur, regles).correspondances.length > 0, budgetMs);
  if (!b.ok) {
    noterDepassement(onDepassement, "valeur", scope, regleEnCours);
    return { correspondance: true, depasse: true };
  }
  return { correspondance: b.valeur, depasse: false };
}

/**
 * Rédaction d'une chaîne en ligne par les détecteurs de texte de toutes les
 * règles dont les détecteurs sont des détecteurs de texte, quelles que soient
 * leur portée et leurs outils, avec leur action (EX-10.24 : motif d'une
 * décision) ; `champ` et `supprimer` ne s'y appliquent pas. Tient dans
 * `budgetMs` (EX-10.23) : au-delà, rend { texte: null, depasse: true }.
 * Rend { texte, redacted, correspondances, depasse }.
 */
export function redigerTexteEnLigne(politique, chaine, { budgetMs = BUDGET_REDACTION_MS, onDepassement = null, scope = null } = {}) {
  if (!politique || typeof chaine !== "string") return { texte: chaine, redacted: false, correspondances: [], depasse: false };
  const regles = politique.doc.rules.filter((r) => detecteursTexte(r).length > 0);
  regleEnCours = null;
  const b = sousBudget(() => redigerChaineParDetecteurs(politique, chaine, regles), budgetMs);
  if (!b.ok) {
    noterDepassement(onDepassement, "valeur", scope, regleEnCours);
    return { texte: null, redacted: false, correspondances: [], depasse: true };
  }
  return { texte: b.valeur.texte, redacted: b.valeur.texte !== chaine, correspondances: b.valeur.correspondances, depasse: false };
}

// ---------------------------------------------------------------------------
// Pièces (CT-2 §8) et références (CT-1 §5.4)
// ---------------------------------------------------------------------------

/** Référence CT-1 §5.4 d'une pièce stockée : { sha256, length, redacted[, media_type] }. */
export function referencePiece(octets, { redacted = false, media_type } = {}) {
  const o = Buffer.from(octets);
  const ref = { sha256: J.sha256(o), length: o.length, redacted: Boolean(redacted) };
  if (media_type !== undefined && media_type !== null) ref.media_type = media_type;
  return ref;
}

/**
 * Pièce JSON (EX-8.1, EX-10.1) : la valeur est rédigée par les règles de la
 * portée, puis sérialisée en JCS intégral ; les octets stockés sont
 * exactement ceux qui sont hachés. Rend { valeur, octets, reference,
 * correspondances, notes }. Au-delà du budget, la pièce « non rédigeable »
 * (EX-8.7 règle 3) : `length` est `longueurRecue`, les octets du corps reçu
 * (échange de modèle, corps HTTP), ou, pour une pièce tirée d'un message
 * JSON-RPC (arguments, résultat d'outil), la longueur du JCS intégral de la
 * valeur en clair, la sérialisation qu'EX-10.16 calcule déjà.
 */
export function pieceJSON(valeur, { politique = null, portee = null, outil = null, alias = null, media_type, budgetMs = BUDGET_REDACTION_MS, onDepassement = null, contentType = null, longueurRecue = null } = {}) {
  const r = portee ? rediger(politique, valeur, { portee, outil, alias, budgetMs, onDepassement }) : { valeur: copieJSON(valeur), redacted: false, correspondances: [], notes: [] };
  if (r.depasse) return pieceNonRedigeable({ content_type: contentType, length: longueurRecue ?? r.longueurClair, reason: "budget_redaction" }, r.notes);
  const octets = octetsJCSIntegral(r.valeur);
  return { valeur: r.valeur, octets, reference: referencePiece(octets, { redacted: r.redacted, media_type }), correspondances: r.correspondances, notes: r.notes };
}

/** Pièce texte (prompt système, intention, contexte text/plain) : la chaîne rédigée, en octets UTF-8, media_type text/plain (EX-8.6, EX-10.18) ; pièce « non rédigeable » au-delà du budget (EX-10.23). */
export function pieceTexte(texte, { politique = null, portee = null, outil = null, alias = null, media_type = "text/plain", budgetMs = BUDGET_REDACTION_MS, onDepassement = null, contentType = null } = {}) {
  const r = portee ? rediger(politique, texte, { portee, outil, alias, budgetMs, onDepassement }) : { valeur: texte, redacted: false, correspondances: [], notes: [] };
  if (r.depasse) return pieceNonRedigeable({ content_type: contentType, length: r.longueurClair, reason: "budget_redaction" }, r.notes);
  const octets = Buffer.from(r.valeur, "utf8");
  return { valeur: r.valeur, octets, reference: referencePiece(octets, { redacted: r.redacted, media_type }), correspondances: r.correspondances, notes: r.notes };
}

const RE_TYPE_MIME = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;

/**
 * Type de média d'un en-tête Content-Type : en minuscules, sans paramètres ;
 * application/octet-stream sans en-tête, ou si le résultat ne respecte pas le
 * motif type_mime de CT-1 (127 caractères au plus) : une donnée d'entrée ne
 * rend jamais l'événement invalide (EX-8.7, EX-7.1).
 */
export function typeDeMedia(contentType) {
  if (contentType === null || contentType === undefined || String(contentType).trim() === "") return "application/octet-stream";
  const t = String(contentType).split(";")[0].trim().toLowerCase();
  return RE_TYPE_MIME.test(t) && t.length <= 127 ? t : "application/octet-stream";
}

/** Vrai pour un type de média JSON : application/json ou un type de suffixe +json (5.3.1 pas 5). */
export const estTypeJSON = (media) => media === "application/json" || /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+\+json$/.test(media);

/** Vrai si une règle de la politique s'applique à la portée (et à l'outil). */
function reglesApplicables(politique, portee, outil = null, alias = null) {
  return Boolean(politique) && politique.doc.rules.some((r) => regleApplicable(r, portee, outil, alias));
}

/** Objet de la pièce « non rédigeable » (EX-8.7). */
export const formeNonRedigeable = ({ content_type = null, length, reason }) => ({ noortrace_non_redigeable: { content_type, length, reason } });

/** Pièce « non rédigeable » (EX-8.7 règle 3, EX-10.23) : JCS intégral de l'objet, redacted: true, sans media_type ; `nonRedigeable` porte la raison. */
export function pieceNonRedigeable({ content_type = null, length, reason }, notes = []) {
  const valeur = formeNonRedigeable({ content_type, length, reason });
  const octets = octetsJCSIntegral(valeur);
  return { valeur, octets, reference: referencePiece(octets, { redacted: true }), correspondances: [], notes, nonRedigeable: reason };
}

/** Vrai si une valeur rédigée est la forme « non rédigeable » d'EX-8.7 (objet au seul membre noortrace_non_redigeable). */
export function estNonRedigeable(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length === 1 && Object.hasOwn(v, "noortrace_non_redigeable");
}

/**
 * Refus avant relais d'un appel dont la pièce « arguments » est devenue la
 * pièce non rédigeable au-delà du budget (EX-10.23, 4.4 pas 4, debutAppel) :
 * pour un outil de classe `ecriture` ou susceptible d'approbation, quand la
 * réponse d'evaluer mène à un relais (autorise) ou à un événement retenue
 * (a_approuver, ticket nouveau), l'appel est refusé par -31010, raison
 * `redaction`, sans intention ni événement : un appel d'écriture ne part
 * jamais sans ses arguments dans la preuve, et les approbateurs ne voient
 * jamais une demande vide. Une réponse refuse (événement refusee, rien n'est
 * relayé) ou en_attente (aucun événement), ou un outil de lecture, suit son
 * cours. Rend null ou { error }.
 */
export function refusArgumentsNonRedigeables(piece, { classe, susceptible = false, reponse = null } = {}) {
  if (piece?.nonRedigeable !== "budget_redaction") return null;
  if (classe !== "ecriture" && !susceptible) return null;
  if (reponse && (reponse.decision === "refuse" || reponse.ticket_state === "en_attente")) return null;
  return { error: erreurEnregistreur("MODE_DEGRADE", { reason: "redaction" }) };
}

/**
 * Pièce non JSON (EX-8.7) : si les octets sont de l'UTF-8 valide (une marque
 * d'ordre d'octets est gardée comme caractère), les règles de la portée
 * s'appliquent au texte, quel que soit le type de média, et la pièce est
 * l'UTF-8 du texte rédigé (les octets reçus si rien n'a joué) ; sinon, si une
 * règle s'applique à la portée, la pièce est l'objet « non rédigeable »
 * (redacted: true, sans media_type) ; sinon les octets tels quels.
 */
export function pieceBrute(octets, { contentType = null, politique = null, portee = null, outil = null, alias = null, raison = "non_utf8", budgetMs = BUDGET_REDACTION_MS, onDepassement = null } = {}) {
  const media_type = typeDeMedia(contentType);
  const o = Buffer.from(octets);
  let texte = null;
  try {
    texte = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(o);
  } catch {
    texte = null;
  }
  if (portee && texte !== null) {
    const r = rediger(politique, texte, { portee, outil, alias, budgetMs, onDepassement });
    if (r.depasse) return { ...pieceNonRedigeable({ content_type: contentType ?? null, length: o.length, reason: "budget_redaction" }, r.notes), valeur: null };
    const out = r.redacted ? Buffer.from(r.valeur, "utf8") : o;
    return { valeur: null, octets: out, reference: referencePiece(out, { redacted: r.redacted, media_type }), correspondances: r.correspondances, notes: r.notes };
  }
  if (portee && texte === null && reglesApplicables(politique, portee, outil, alias)) {
    return pieceNonRedigeable({ content_type: contentType ?? null, length: o.length, reason: raison });
  }
  return { valeur: null, octets: o, reference: referencePiece(o, { redacted: false, media_type }), correspondances: [], notes: [] };
}

/** Fenêtre glissante des quotas d'une connexion d'hôte (EX-4.47) : une minute. */
export const FENETRE_QUOTA_MS = 60000;

/**
 * Quotas d'une connexion d'hôte (EX-4.47), sur une minute glissante de
 * l'horloge monotone : requêtes en cours (`max_concurrent`), octets reçus
 * (`received_bytes_per_minute`), octets de pièces écrits
 * (`piece_bytes_per_minute`) et temps de capture (`redaction_ms_per_minute` :
 * analyse JSON, rédaction et sérialisation des pièces de ses requêtes, borne
 * de temps comprise ou non). `admettre(t, octetsRecus)` est appelé au pas 1,
 * quand la requête est lue : il rend null (la requête entre, comptée en
 * cours) ou l'erreur -31013 de direction `quota` (`limit_requests`,
 * `limit_bytes` ou `limit_ms`), sans relais ni pièce. `noter(t, { octetsPieces,
 * msCapture })` ajoute ce que la requête a écrit et coûté ; `terminer()` la
 * retire des requêtes en cours. Un hôte ne peut ainsi ni remplir le volume,
 * ni occuper le calcul de l'enregistreur par la seule taille de ses requêtes.
 */
export class QuotaConnexion {
  constructor({ max_concurrent, piece_bytes_per_minute, received_bytes_per_minute, redaction_ms_per_minute }) {
    this.quota = { max_concurrent, piece_bytes_per_minute, received_bytes_per_minute, redaction_ms_per_minute };
    this.enCours = 0;
    this.entrees = [];
  }

  somme(t, cle) {
    this.entrees = this.entrees.filter((e) => e.t > t - FENETRE_QUOTA_MS);
    return this.entrees.reduce((s, e) => s + (e[cle] ?? 0), 0);
  }

  admettre(t, octetsRecus) {
    const q = this.quota;
    const refus = (data) => erreurEnregistreur("TAILLE", { ...data, direction: "quota" });
    if (this.enCours >= q.max_concurrent) return refus({ limit_requests: q.max_concurrent });
    if (this.somme(t, "recus") + octetsRecus > q.received_bytes_per_minute) return refus({ limit_bytes: q.received_bytes_per_minute });
    if (this.somme(t, "pieces") >= q.piece_bytes_per_minute) return refus({ limit_bytes: q.piece_bytes_per_minute });
    if (this.somme(t, "ms") >= q.redaction_ms_per_minute) return refus({ limit_ms: q.redaction_ms_per_minute });
    this.entrees.push({ t, recus: octetsRecus });
    this.enCours++;
    return null;
  }

  noter(t, { octetsPieces = 0, msCapture = 0 } = {}) {
    this.entrees.push({ t, pieces: octetsPieces, ms: msCapture });
  }

  terminer() {
    if (this.enCours > 0) this.enCours--;
  }
}

/** Objet error JSON-RPC d'une erreur de l'enregistreur (table de 4.4) ; `data` absent pour -31012. */
export function erreurEnregistreur(cle, data) {
  const e = ERREURS[cle];
  if (!e) throw new Error(`erreur inconnue : ${cle}`);
  const o = { code: e.code, message: e.message };
  if (data !== undefined) o.data = data;
  return o;
}

/** Forme de la pièce « résultat » d'une erreur JSON-RPC, du serveur ou de l'enregistreur (EX-4.22, 4.4 pas 12). */
export function formeErreurJsonRpc(error) {
  return { noortrace_jsonrpc_error: copieJSON(error) };
}

/**
 * Pièce « arguments » d'un tools/call : `params.arguments`, `{}` si absent,
 * rédigée (portée arguments), JCS intégral (CT-2 §8.2) ; pièce « non
 * rédigeable » au-delà du budget (EX-10.23), dont `length` est la longueur du
 * JCS intégral des arguments en clair (EX-8.7).
 */
export function pieceArguments(params, { politique = null, outil = null, alias = null, budgetMs = BUDGET_REDACTION_MS, onDepassement = null } = {}) {
  const v = params && Object.hasOwn(params, "arguments") ? params.arguments : {};
  return pieceJSON(v, { politique, portee: "arguments", outil, alias, budgetMs, onDepassement });
}

/**
 * Pièce « résultat » d'un tools/call (4.4 pas 12) depuis le message JSON-RPC
 * reçu du serveur d'outils : le membre `result` entier, ou
 * `{"noortrace_jsonrpc_error": error}`. Rend la pièce et `is_error`.
 */
export function pieceResultatMCP(message, { politique = null, outil = null, alias = null, budgetMs = BUDGET_REDACTION_MS, onDepassement = null } = {}) {
  const options = { politique, portee: "resultat", outil, alias, budgetMs, onDepassement };
  if (message && Object.hasOwn(message, "result")) {
    const r = message.result;
    if (r === null || typeof r !== "object" || Array.isArray(r)) {
      const p = pieceJSON(formeErreurJsonRpc(erreurResultatInvalide(r)), options);
      return { ...p, is_error: true };
    }
    const p = pieceJSON(r, options);
    return { ...p, is_error: r.isError === true };
  }
  if (message && Object.hasOwn(message, "error")) {
    const p = pieceJSON(formeErreurJsonRpc(message.error), options);
    return { ...p, is_error: true };
  }
  throw new Error("réponse JSON-RPC sans result ni error");
}

/** Pièce « résultat » d'une erreur de l'enregistreur (délai, annulation, taille, injoignable) : is_error vrai. */
export function pieceErreurEnregistreur(cle, data, { politique = null, outil = null, alias = null, budgetMs = BUDGET_REDACTION_MS, onDepassement = null } = {}) {
  const p = pieceJSON(formeErreurJsonRpc(erreurEnregistreur(cle, data)), { politique, portee: "resultat", outil, alias, budgetMs, onDepassement });
  return { ...p, is_error: true };
}

/** Pièce de définition d'outil (EX-4.16, EX-7.7) : l'objet Tool annoncé, JCS intégral, jamais rédigé, application/json. */
export function pieceDefinitionOutil(definition) {
  return pieceJSON(definition, { media_type: "application/json" });
}

/** Pièce « liste annoncée » (EX-4.45) : `{"tools": [définitions servies, dans l'ordre servi]}`, JCS intégral, application/json. */
export function pieceListeAnnoncee(definitions) {
  return pieceJSON({ tools: definitions }, { media_type: "application/json" });
}

/**
 * Le contexte d'un appel par le frontal MCP (EX-4.45, EX-7.7) : la définition
 * servie, la définition courante si elle diffère, la liste annoncée ; chacune
 * `kind: "autre"`. Les pièces sont des résultats de pieceDefinitionOutil et
 * pieceListeAnnoncee.
 */
export function contexteAppel({ servie, courante = null, liste = null, definitions = true, listeDansContexte = true }) {
  const out = [];
  if (definitions && servie) out.push({ ...servie.reference, kind: "autre" });
  if (definitions && courante && (!servie || courante.reference.sha256 !== servie.reference.sha256)) out.push({ ...courante.reference, kind: "autre" });
  if (listeDansContexte && liste) out.push({ ...liste.reference, kind: "autre" });
  return out;
}

/** Pièce « document d'ensemble de politique » (EX-8.11, EX-10.21) et empreinte : { policy_version, policy_sha256, octets, reference }. */
export function empreinteEnsemblePolitique(policy) {
  const octets = octetsJCSIntegral(policy);
  return { policy_version: policy.version, policy_sha256: J.sha256(octets), octets, reference: referencePiece(octets, { media_type: "application/json" }) };
}

/** Pièce « résultat » d'un événement de reprise (EX-12.14). */
export function pieceReprise(intention_sha256) {
  return pieceJSON({ intention_sha256, noortrace_reprise: TEXTE_REPRISE });
}

/** Pièce « résultat » d'un événement en attente dont le résultat a été perdu (EX-14.10). */
export function pieceAttente(pending_id) {
  return pieceJSON({ noortrace_attente: TEXTE_ATTENTE, pending_id });
}

// ---------------------------------------------------------------------------
// Relais de tools/call : lignes JSON-RPC (CT-2 §4.4)
// ---------------------------------------------------------------------------

const CLE_META = (k) => `io.modelcontextprotocol/${k}`;

/**
 * La requête tools/call envoyée au serveur d'outils (4.4 pas 9), construite
 * depuis le texte reçu de l'hôte : `params.arguments` recopié octet pour octet
 * (EX-4.20), `params.name` = nom d'origine, `_meta` réécrit (EX-4.7) :
 * protocolVersion négociée avec ce serveur, clientInfo de l'enregistreur,
 * clientCapabilities transmises par l'appelant, progressToken remplacé par le
 * jeton propre `progressToken` (relayé tel quel si l'appelant n'en donne pas),
 * autres clés relayées ; `inputResponses` et `requestState` recopiés octet pour
 * octet.
 * Rend { ligne, progressTokenHote }.
 */
export function ligneAmontToolsCall(texteHote, { idAmont, nomOrigine, protocolVersion, clientCapabilities = {}, progressToken = null }) {
  // Blancs non significatifs retirés avant toute recopie (EX-4.43) : aucune valeur ne change.
  const { valeur: msg, positions, texte } = analyserJSONIntegral(sansBlancs(typeof texteHote === "string" ? texteHote : Buffer.from(texteHote).toString("utf8")), { positions: true });
  const params = msg.params ?? {};
  const brut = (p) => {
    const e = positions.get(p);
    return texte.slice(e.debut, e.fin);
  };
  const metaHote = params._meta && typeof params._meta === "object" ? params._meta : {};
  const meta = {};
  const reecrites = {
    [CLE_META("protocolVersion")]: protocolVersion,
    [CLE_META("clientCapabilities")]: clientCapabilities,
    [CLE_META("clientInfo")]: IDENTITE_ENREGISTREUR,
  };
  for (const k of Object.keys(metaHote)) {
    if (Object.hasOwn(reecrites, k)) poser(meta, k, reecrites[k]);
    else if (k === "progressToken") poser(meta, k, progressToken ?? metaHote[k]);
    else poser(meta, k, metaHote[k]);
  }
  for (const [k, v] of Object.entries(reecrites)) if (!Object.hasOwn(meta, k)) poser(meta, k, v);
  let corps = `{"name":${JSON.stringify(nomOrigine)}`;
  if (Object.hasOwn(params, "arguments")) corps += `,"arguments":${brut("/params/arguments")}`;
  for (const k of ["inputResponses", "requestState"]) if (Object.hasOwn(params, k)) corps += `,${JSON.stringify(k)}:${brut(`/params/${k}`)}`;
  corps += `,"_meta":${JSON.stringify(meta)}}`;
  return {
    ligne: `{"jsonrpc":"2.0","id":${JSON.stringify(idAmont)},"method":"tools/call","params":${corps}}`,
    progressTokenHote: Object.hasOwn(metaHote, "progressToken") ? metaHote.progressToken : null,
  };
}

/** Insère un membre en tête (`debut`) ou en fin d'un objet JSON donné par son texte brut. */
function insererMembre(brutObjet, membre, { debut = false } = {}) {
  const interieurVide = /^\{\s*\}$/.test(brutObjet);
  if (interieurVide) return `{${membre}}`;
  if (debut) return `{${membre},${brutObjet.slice(1)}`;
  const fin = brutObjet.lastIndexOf("}");
  return `${brutObjet.slice(0, fin)},${membre}${brutObjet.slice(fin)}`;
}

/**
 * La réponse rendue à l'hôte (4.4 pas 14) depuis le texte reçu du serveur :
 * `id` de l'hôte ; `result` recopié octet pour octet avec deux réécritures,
 * `_meta["io.modelcontextprotocol/serverInfo"]` posé à l'identité de
 * l'enregistreur et `resultType: "complete"` ajouté s'il manque et que l'hôte
 * est de l'ère moderne ; une erreur JSON-RPC est recopiée telle quelle (même
 * code, message, data).
 */
export function ligneHoteReponse(texteAmont, { idHote, idHoteTexte = null, hoteModerne = true }) {
  const { valeur: msg, positions, texte } = analyserJSONIntegral(sansBlancs(typeof texteAmont === "string" ? texteAmont : Buffer.from(texteAmont).toString("utf8")), { positions: true });
  const brut = (p) => {
    const e = positions.get(p);
    return texte.slice(e.debut, e.fin);
  };
  // L'id de l'hôte est recopié depuis son texte quand il est donné (un entier au-delà de 2^53 n'est pas altéré, 4.4 pas 14).
  const id = idHoteTexte ?? JSON.stringify(idHote);
  if (Object.hasOwn(msg, "error")) return `{"jsonrpc":"2.0","id":${id},"error":${brut("/error")}}`;
  const result = msg.result;
  if (result === null || typeof result !== "object" || Array.isArray(result)) return `{"jsonrpc":"2.0","id":${id},"error":${JSON.stringify(erreurResultatInvalide(result))}}`;
  let r = brut("/result");
  const serverInfo = JSON.stringify(IDENTITE_ENREGISTREUR);
  const cleServerInfo = JSON.stringify(CLE_META("serverInfo"));
  const debutResult = positions.get("/result").debut;
  if (Object.hasOwn(result, "_meta") && (result._meta === null || typeof result._meta !== "object" || Array.isArray(result._meta))) {
    // _meta présent mais pas un objet : remplacé par un objet qui ne porte que serverInfo.
    const em = positions.get("/result/_meta");
    r = r.slice(0, em.debut - debutResult) + `{${cleServerInfo}:${serverInfo}}` + r.slice(em.fin - debutResult);
  } else if (Object.hasOwn(result, "_meta")) {
    const em = positions.get("/result/_meta");
    let m = texte.slice(em.debut, em.fin);
    const ptrSi = `/result/_meta/${CLE_META("serverInfo").replace(/~/g, "~0").replace(/\//g, "~1")}`;
    if (positions.has(ptrSi)) {
      const es = positions.get(ptrSi);
      m = texte.slice(em.debut, es.debut) + serverInfo + texte.slice(es.fin, em.fin);
    } else m = insererMembre(m, `${cleServerInfo}:${serverInfo}`);
    r = r.slice(0, em.debut - debutResult) + m + r.slice(em.fin - debutResult);
  } else {
    r = insererMembre(r, `"_meta":{${cleServerInfo}:${serverInfo}}`);
  }
  if (hoteModerne && !Object.hasOwn(result, "resultType")) r = insererMembre(r, `"resultType":"complete"`, { debut: true });
  return `{"jsonrpc":"2.0","id":${id},"result":${r}}`;
}

/** Erreur JSON-RPC rendue à l'hôte par l'enregistreur (EX-4.24) ; `idHoteTexte` : l'id recopié depuis le texte de l'hôte. */
export function ligneHoteErreur(idHote, error, { idHoteTexte = null } = {}) {
  if (idHoteTexte !== null) return `{"jsonrpc":"2.0","id":${idHoteTexte},"error":${JSON.stringify(error)}}`;
  return JSON.stringify({ jsonrpc: "2.0", id: idHote, error });
}

/**
 * Résultat rendu à l'hôte par l'enregistreur lui-même (4.4 pas 5 et 6,
 * EX-4.49) : refus par la politique ou signal d'approbation, objet
 * CallToolResult sérialisé tel quel (ordre de ses membres) ; `idHoteTexte` :
 * l'id recopié depuis le texte de l'hôte (4.4 pas 14).
 */
export function ligneHoteResultatEnregistreur(idHote, result, { idHoteTexte = null } = {}) {
  const id = idHoteTexte ?? JSON.stringify(idHote);
  return `{"jsonrpc":"2.0","id":${id},"result":${JSON.stringify(result)}}`;
}

/** Texte brut de l'id d'une requête JSON-RPC (4.4 pas 14), ou null s'il n'y en a pas. */
export function texteIdRequete(texteHote) {
  const { positions, texte } = analyserJSONIntegral(texteHote, { positions: true });
  const e = positions.get("/id");
  return e ? texte.slice(e.debut, e.fin) : null;
}

/** Type JSON d'une valeur, pour data.result_type (4.4 pas 12). */
const typeJSON = (v) => (v === null ? "null" : Array.isArray(v) ? "array" : typeof v);

/** Erreur -32603 d'un résultat amont qui n'est pas un objet (4.4 pas 12). */
export function erreurResultatInvalide(result) {
  return { code: -32603, message: "noortrace: resultat amont invalide", data: { result_type: typeJSON(result) } };
}

/** Notification d'annulation envoyée à un serveur stdio (EX-4.22, page Cancellation : requestId, reason). */
export function ligneAnnulation(idAmont, reason) {
  return JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: idAmont, reason } });
}

/** Identifiant amont propre au frontal : « e- » suivi d'un compteur décimal sur douze chiffres (4.4 pas 9). */
export const idAmont = (n) => `e-${String(n).padStart(12, "0")}`;

// ---------------------------------------------------------------------------
// Agrégation de tools/list (CT-2 §4.3)
// ---------------------------------------------------------------------------

/** Comparaison par unités de code UTF-16 (CT-1 §4). */
const comparer = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Classe d'un outil (EX-14.1) : configuration de l'outil, puis classe par
 * défaut du serveur, puis `annotations.readOnlyHint === true` → lecture
 * (indication non fiable, EX-4.17), à défaut ecriture.
 */
export function classeOutil({ configurationOutil = null, classeParDefaut = null, annotations = null } = {}) {
  if (configurationOutil?.class) return configurationOutil.class;
  if (classeParDefaut) return classeParDefaut;
  if (annotations?.readOnlyHint === true) return "lecture";
  return "ecriture";
}

/** Vérifie les alias et le préfixe d'une configuration de serveurs (EX-4.9, EX-4.10) ; lève ErreurConfiguration. */
export function verifierAlias(alias, { prefix = true } = {}) {
  const erreurs = [];
  const vus = new Set();
  for (const a of alias) {
    if (!RE_ALIAS.test(a)) erreurs.push(`alias ${JSON.stringify(a)} : motif ^[a-z0-9][a-z0-9-]{0,31}$ attendu`);
    if (a === "noortrace") erreurs.push("alias noortrace réservé");
    if (vus.has(a)) erreurs.push(`alias ${a} en double`);
    vus.add(a);
  }
  if (prefix === false && alias.length !== 1) erreurs.push(`tools.prefix: false exige un seul serveur d'outils (${alias.length} configurés)`);
  if (erreurs.length) throw new ErreurConfiguration("configuration des serveurs d'outils refusée", erreurs);
}

/** Nom annoncé d'un outil (EX-4.10). */
export const nomAnnonce = (alias, original, prefix = true) => (prefix ? `${alias}${SEPARATEUR_ALIAS}${original}` : original);

/** Découpe un nom annoncé au premier « __ » (ou le prend tel quel sans préfixe) : { alias, original }. */
export function resoudreNomAnnonce(nom, { prefix = true, aliasUnique = null } = {}) {
  if (!prefix) return { alias: aliasUnique, original: nom };
  const k = nom.indexOf(SEPARATEUR_ALIAS);
  if (k < 0) return null;
  return { alias: nom.slice(0, k), original: nom.slice(k + SEPARATEUR_ALIAS.length) };
}

/**
 * Agrège les listes d'outils des serveurs (EX-4.10, EX-4.11, EX-4.13) :
 * `serveurs` = [{ alias, tools: [Tool], class_default?, tools_config? }].
 * Rejette les noms réservés (`nom_reserve`), les noms annoncés hors du motif
 * de CT-1 ou de plus de 128 caractères (`nom_invalide`) et les collisions
 * (`collision`, tous les outils du nom en collision, y compris après le
 * gabarit et la normalisation de chaque connexion d'hôte de `normalisations`
 * = [{ template, sanitize }]). Ordre déterministe par
 * alias puis nom d'origine ; pages de `page_size`. Rend { announced,
 * rejected, pages }, chaque outil annoncé avec sa définition telle
 * qu'annoncée (nom annoncé, autres membres inchangés).
 */
export function agregerOutils(serveurs, { prefix = true, page_size = 100, normalisations = [] } = {}) {
  verifierAlias(serveurs.map((s) => s.alias), { prefix });
  const candidats = [];
  const rejected = [];
  for (const s of serveurs) {
    for (const t of s.tools) {
      const original = t.name;
      if (typeof original !== "string" || original.startsWith("noortrace.")) {
        rejected.push({ server_alias: s.alias, original, reason: "nom_reserve" });
        continue;
      }
      const announced = nomAnnonce(s.alias, original, prefix);
      if (!RE_NOM_OUTIL.test(announced)) {
        rejected.push({ server_alias: s.alias, original, reason: "nom_invalide" });
        continue;
      }
      const definition = copieJSON(t);
      definition.name = announced;
      const classe = classeOutil({ configurationOutil: s.tools_config?.[original] ?? null, classeParDefaut: s.class_default ?? null, annotations: t.annotations ?? null });
      candidats.push({ server_alias: s.alias, original, announced, class: classe, definition });
    }
  }
  // Collision (EX-4.11, règle 3) : même nom annoncé, ou même nom après le gabarit et la normalisation d'une connexion d'hôte.
  const enCollision = new Set();
  for (const n of [null, ...normalisations]) {
    const parNom = new Map();
    for (const c of candidats) {
      const cle = n === null ? c.announced : nomVuParModele(c.announced, { template: n.template ?? "{tool_announced}", sanitize: n.sanitize === true });
      if (!parNom.has(cle)) parNom.set(cle, []);
      parNom.get(cle).push(c);
    }
    for (const groupe of parNom.values()) if (groupe.length > 1) for (const c of groupe) enCollision.add(c);
  }
  const announced = [];
  for (const c of candidats) {
    if (enCollision.has(c)) rejected.push({ server_alias: c.server_alias, original: c.original, reason: "collision" });
    else announced.push(c);
  }
  announced.sort((a, b) => comparer(a.server_alias, b.server_alias) || comparer(a.original, b.original));
  rejected.sort((a, b) => comparer(a.server_alias, b.server_alias) || comparer(String(a.original), String(b.original)) || comparer(a.reason, b.reason));
  const pages = [];
  for (let k = 0; k < announced.length; k += page_size) pages.push(announced.slice(k, k + page_size).map((c) => c.announced));
  return { announced, rejected, pages };
}

// ---------------------------------------------------------------------------
// Analyseur SSE (CT-2 §5.4.1, HTML Living Standard « Parsing an event stream »)
// ---------------------------------------------------------------------------

/**
 * Analyseur incrémental d'un flux text/event-stream : les octets arrivent par
 * fragments arbitraires (`pousser`), les événements sont distribués à chaque
 * ligne vide. Décodage UTF-8 avec retrait d'une marque d'ordre d'octets
 * initiale ; fins de ligne CRLF, LF ou CR (un CR en fin de fragment suivi d'un
 * LF au fragment suivant ne fait qu'une fin de ligne) ; commentaires ignorés
 * et comptés ; `event`, `data` (valeurs jointes par LF), `id` et `retry` lus
 * et ignorés ; type par défaut « message » ; un tampon data vide ne distribue
 * rien ; un événement inachevé en fin de flux n'est pas distribué.
 */
export class AnalyseurSSE {
  constructor() {
    this.decodeur = new TextDecoder("utf-8");
    this.ligne = "";
    this.crPrecedent = false;
    this.data = "";
    this.type = "";
    this.dernierId = null;
    this.commentaires = 0;
    this.evenements = [];
  }

  /** Fournit un fragment d'octets ; rend les événements distribués par ce fragment. */
  pousser(fragment) {
    return this.#traiter(this.decodeur.decode(Buffer.from(fragment), { stream: true }));
  }

  /** Fin du flux : rend les événements encore distribuables (aucun : un événement sans ligne vide finale est perdu). */
  terminer() {
    return this.#traiter(this.decodeur.decode());
  }

  #traiter(texte) {
    const out = [];
    for (const c of texte) {
      if (this.crPrecedent) {
        this.crPrecedent = false;
        if (c === "\n") continue;
      }
      if (c === "\r" || c === "\n") {
        if (c === "\r") this.crPrecedent = true;
        const e = this.#ligne(this.ligne);
        if (e) out.push(e);
        this.ligne = "";
        continue;
      }
      this.ligne += c;
    }
    this.evenements.push(...out);
    return out;
  }

  #ligne(l) {
    if (l === "") {
      if (this.data === "") {
        this.type = "";
        return null;
      }
      const data = this.data.endsWith("\n") ? this.data.slice(0, -1) : this.data;
      const e = { type: this.type === "" ? "message" : this.type, data };
      this.data = "";
      this.type = "";
      return e;
    }
    if (l[0] === ":") {
      this.commentaires++;
      return null;
    }
    const k = l.indexOf(":");
    const champ = k < 0 ? l : l.slice(0, k);
    let valeur = k < 0 ? "" : l.slice(k + 1);
    if (valeur[0] === " ") valeur = valeur.slice(1);
    if (champ === "event") this.type = valeur;
    else if (champ === "data") this.data += valeur + "\n";
    else if (champ === "id") {
      if (!valeur.includes("\u0000")) this.dernierId = valeur;
    }
    return null;
  }
}

/** Les événements d'un flux SSE complet, éventuellement découpé en fragments : { evenements, commentaires }. */
export function analyserSSE(octets, { fragments = null } = {}) {
  const a = new AnalyseurSSE();
  const o = Buffer.from(octets);
  if (fragments === null) a.pousser(o);
  else {
    let k = 0;
    for (const t of fragments) {
      a.pousser(o.subarray(k, k + t));
      k += t;
    }
    if (k < o.length) a.pousser(o.subarray(k));
  }
  a.terminer();
  return { evenements: a.evenements, commentaires: a.commentaires };
}

// ---------------------------------------------------------------------------
// Formes consolidées (CT-2 §5.4.2 à 5.4.4)
// ---------------------------------------------------------------------------

/** Analyse la valeur data d'un événement ; null si ce n'est pas du JSON. */
function dataJSON(e) {
  try {
    return analyserJSONIntegral(e.data);
  } catch {
    return null;
  }
}

/** Index admis par EX-5.27 (1) : nombre JSON de valeur entière, entre 0 et 2^53. */
const indexAdmis = (v) => typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 2 ** 53;
const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Forme consolidée de l'API Messages d'Anthropic (EX-5.15, EX-5.27).
 * `evenements` : événements SSE distribués. Rend { forme (objet, ou null si
 * aucun message_start ni error), incomplet, erreur, is_error, ignores }.
 */
export function consoliderAnthropic(evenements) {
  let forme = null;
  let incomplet = false;
  let fin = false;
  let erreur = false;
  let ignores = 0;
  const tampons = new Map();
  for (const e of evenements) {
    if (fin || erreur) {
      ignores++;
      continue;
    }
    const d = dataJSON(e);
    if (!estObjet(d)) {
      ignores++;
      continue;
    }
    const type = typeof d.type === "string" ? d.type : e.type;
    if (forme === null && type !== "message_start" && type !== "ping" && type !== "error") {
      incomplet = true; // tout événement avant message_start (EX-5.15 pas 1)
      ignores++;
      continue;
    }
    switch (type) {
      case "message_start": {
        if (forme === null && estObjet(d.message)) forme = copieJSON(d.message);
        else ignores++;
        break;
      }
      case "content_block_start": {
        const idx = d.index;
        if (!Array.isArray(forme.content)) forme.content = [];
        const contenu = forme.content;
        if (!indexAdmis(idx) || idx > contenu.length || !estObjet(d.content_block)) {
          ignores++;
          break;
        }
        contenu[idx] = copieJSON(d.content_block);
        tampons.delete(idx);
        if (contenu[idx].type === "tool_use") tampons.set(idx, "");
        break;
      }
      case "content_block_delta": {
        const idx = d.index;
        const contenu = Array.isArray(forme.content) ? forme.content : [];
        const bloc = indexAdmis(idx) && idx < contenu.length ? contenu[idx] : null;
        const delta = d.delta;
        if (!estObjet(bloc) || !estObjet(delta)) {
          ignores++;
          break;
        }
        if (delta.type === "text_delta" && typeof delta.text === "string") bloc.text = (typeof bloc.text === "string" ? bloc.text : "") + delta.text;
        else if (delta.type === "input_json_delta" && typeof delta.partial_json === "string") tampons.set(idx, (tampons.get(idx) ?? "") + delta.partial_json);
        else if (delta.type === "thinking_delta" && typeof delta.thinking === "string") bloc.thinking = (typeof bloc.thinking === "string" ? bloc.thinking : "") + delta.thinking;
        else if (delta.type === "signature_delta" && typeof delta.signature === "string") bloc.signature = delta.signature;
        else if (delta.type === "citations_delta" && estObjet(delta.citation)) {
          if (!Array.isArray(bloc.citations)) bloc.citations = [];
          bloc.citations.push(copieJSON(delta.citation));
        } else ignores++;
        break;
      }
      case "content_block_stop": {
        const idx = d.index;
        const contenu = Array.isArray(forme.content) ? forme.content : [];
        const bloc = indexAdmis(idx) && idx < contenu.length ? contenu[idx] : null;
        if (!estObjet(bloc)) {
          ignores++;
          break;
        }
        if (tampons.has(idx)) {
          const t = tampons.get(idx);
          if (t === "") poser(bloc, "input", {});
          else {
            try {
              poser(bloc, "input", analyserJSONIntegral(t));
            } catch {
              poser(bloc, "input", {});
              poser(bloc, "noortrace_input_json_invalide", t);
            }
          }
          tampons.delete(idx);
        }
        break;
      }
      case "message_delta": {
        if (estObjet(d.delta)) for (const k of Object.keys(d.delta)) poser(forme, k, copieJSON(d.delta[k]));
        if (estObjet(d.usage)) {
          if (!estObjet(forme.usage)) forme.usage = {};
          for (const k of Object.keys(d.usage)) poser(forme.usage, k, copieJSON(d.usage[k]));
        }
        break;
      }
      case "message_stop":
        fin = true;
        break;
      case "error":
        erreur = true;
        if (forme === null) forme = {};
        poser(forme, "noortrace_erreur_flux", copieJSON(d));
        break;
      default:
        ignores++; // ping et types inconnus
    }
  }
  if (!fin && !erreur) incomplet = true;
  if (forme && incomplet) forme.noortrace_flux_incomplet = true;
  return { forme, incomplet: incomplet || forme === null, erreur, is_error: erreur || incomplet || forme === null, ignores };
}

/** Forme consolidée d'OpenAI Chat Completions (EX-5.16, EX-5.27). */
export function consoliderChat(evenements) {
  let forme = null;
  let premierId;
  let incomplet = false;
  let fin = false;
  let arret = false;
  let ignores = 0;
  const choix = new Map();
  const appels = new Map();
  for (const e of evenements) {
    if (fin || arret) {
      ignores++;
      continue;
    }
    if (e.data === "[DONE]") {
      fin = true;
      continue;
    }
    const d = dataJSON(e);
    if (!estObjet(d)) {
      ignores++;
      continue;
    }
    const id = J.canonicaliserJCSIntegral(Object.hasOwn(d, "id") ? d.id : null);
    if (forme === null) {
      forme = {};
      premierId = id;
      for (const k of ["id", "created", "model", "system_fingerprint", "service_tier"]) if (Object.hasOwn(d, k)) poser(forme, k, copieJSON(d[k]));
      forme.object = "chat.completion";
      forme.choices = [];
    } else if (id !== premierId) {
      // Un chunk d'un autre id arrête le réassemblage (EX-5.16 pas 5).
      incomplet = true;
      arret = true;
      ignores++;
      continue;
    }
    for (const c of Array.isArray(d.choices) ? d.choices : []) {
      if (!estObjet(c) || !indexAdmis(c.index)) {
        ignores++;
        continue;
      }
      if (!choix.has(c.index)) {
        const nouveau = { index: c.index, message: { role: "assistant", content: null }, finish_reason: null };
        choix.set(c.index, nouveau);
        forme.choices.push(nouveau);
      }
      const ch = choix.get(c.index);
      const delta = estObjet(c.delta) ? c.delta : {};
      if (typeof delta.role === "string") ch.message.role = delta.role;
      if (typeof delta.content === "string") ch.message.content = (ch.message.content ?? "") + delta.content;
      if (typeof delta.refusal === "string") ch.message.refusal = (ch.message.refusal ?? "") + delta.refusal;
      for (const f of Array.isArray(delta.tool_calls) ? delta.tool_calls : []) {
        if (!estObjet(f) || !indexAdmis(f.index)) {
          ignores++;
          continue;
        }
        const cle = `${c.index}/${f.index}`;
        if (!appels.has(cle)) {
          const nouveau = { index: f.index, id: null, type: "function", function: { name: "", arguments: "" } };
          appels.set(cle, { appel: nouveau, id: false, type: false, name: false });
          if (!Array.isArray(ch.message.tool_calls)) ch.message.tool_calls = [];
          ch.message.tool_calls.push(nouveau);
        }
        const a = appels.get(cle);
        // Seule une valeur non nulle fixe id, type et name (EX-5.16 pas 2).
        if (!a.id && f.id !== undefined && f.id !== null) {
          a.appel.id = copieJSON(f.id);
          a.id = true;
        }
        if (!a.type && f.type !== undefined && f.type !== null) {
          a.appel.type = copieJSON(f.type);
          a.type = true;
        }
        if (!a.name && estObjet(f.function) && f.function.name !== undefined && f.function.name !== null) {
          a.appel.function.name = copieJSON(f.function.name);
          a.name = true;
        }
        if (estObjet(f.function) && typeof f.function.arguments === "string") a.appel.function.arguments += f.function.arguments;
      }
      if (c.finish_reason !== null && c.finish_reason !== undefined) ch.finish_reason = copieJSON(c.finish_reason);
    }
    if (d.usage !== null && d.usage !== undefined) forme.usage = copieJSON(d.usage);
  }
  if (forme && !fin) incomplet = true;
  if (forme && incomplet) forme.noortrace_flux_incomplet = true;
  return { forme, incomplet: incomplet || forme === null, erreur: false, is_error: incomplet || forme === null, ignores };
}

const EVENEMENTS_RESPONSE = new Set(["response.created", "response.in_progress", "response.completed", "response.failed", "response.incomplete"]);
const TERMINAUX_RESPONSE = new Set(["response.completed", "response.failed", "response.incomplete"]);

/** Forme consolidée d'OpenAI Responses (EX-5.17, EX-5.27). */
export function consoliderResponses(evenements) {
  let dernier = null;
  let dernierType = null;
  let erreurFlux = null;
  let ignores = 0;
  const itemsTermines = new Map();
  for (const e of evenements) {
    const d = dataJSON(e);
    if (!estObjet(d)) {
      ignores++;
      continue;
    }
    const type = typeof d.type === "string" ? d.type : e.type;
    if (EVENEMENTS_RESPONSE.has(type)) {
      if (estObjet(d.response)) {
        dernier = d.response;
        dernierType = type;
      } else ignores++;
    } else if (type === "response.output_item.done") {
      if (!indexAdmis(d.output_index) || !Object.hasOwn(d, "item")) ignores++;
      else itemsTermines.set(d.output_index, d.item);
    } else if (type === "error") {
      erreurFlux = { code: Object.hasOwn(d, "code") ? copieJSON(d.code) : null, message: Object.hasOwn(d, "message") ? copieJSON(d.message) : null };
    } else ignores++;
  }
  if (dernier === null) {
    if (erreurFlux) return { forme: { noortrace_erreur_flux: erreurFlux }, incomplet: true, erreur: true, is_error: true, ignores };
    return { forme: null, incomplet: true, erreur: false, is_error: true, ignores };
  }
  const forme = copieJSON(dernier);
  let incomplet = false;
  if (!TERMINAUX_RESPONSE.has(dernierType)) {
    incomplet = true;
    forme.noortrace_flux_incomplet = true;
    if (!Array.isArray(forme.output)) forme.output = [];
    for (const k of [...itemsTermines.keys()].sort((a, b) => a - b)) {
      if (k > forme.output.length) {
        ignores++;
        continue;
      }
      forme.output[k] = copieJSON(itemsTermines.get(k));
    }
  }
  if (erreurFlux) forme.noortrace_erreur_flux = erreurFlux;
  return { forme, incomplet, erreur: erreurFlux !== null, is_error: incomplet || erreurFlux !== null || dernierType === "response.failed", ignores };
}

const CONSOLIDEURS = { "anthropic-messages": consoliderAnthropic, "openai-chat": consoliderChat, "openai-responses": consoliderResponses };

/** Forme consolidée d'un flux SSE (octets), selon le format de la route. */
export function consoliderFlux(format, octets, options = {}) {
  const consolideur = CONSOLIDEURS[format];
  if (!consolideur) throw new Error(`format sans réassemblage en version 0 : ${format}`);
  const { evenements, commentaires } = analyserSSE(octets, options);
  return { ...consolideur(evenements), evenements: evenements.length, commentaires };
}

// ---------------------------------------------------------------------------
// Extraction (CT-2 §5.5)
// ---------------------------------------------------------------------------

/** Formats de modèle de la version 0 (EX-5.7). */
export const FORMATS_V0 = Object.keys(CONSOLIDEURS);

/** Vrai si le corps de requête a la forme attendue du format (EX-5.7). */
export function requeteDeForme(format, corps) {
  if (corps === null || typeof corps !== "object" || Array.isArray(corps)) return false;
  if (format === "openai-responses") return Object.hasOwn(corps, "input") || Object.hasOwn(corps, "previous_response_id");
  return Array.isArray(corps.messages);
}

const textesDeParties = (contenu, types) => {
  if (typeof contenu === "string") return [contenu];
  if (Array.isArray(contenu)) return contenu.filter((p) => p && types.includes(p.type) && typeof p.text === "string").map((p) => p.text);
  return [];
};

/** Les morceaux du prompt système d'une requête, dans l'ordre (table de 5.5). */
function morceauxPrompt(format, corps) {
  if (format === "anthropic-messages") {
    if (typeof corps.system === "string") return [corps.system];
    if (Array.isArray(corps.system)) return corps.system.filter((b) => b && b.type === "text" && typeof b.text === "string").map((b) => b.text);
    return [];
  }
  if (format === "openai-chat") {
    return (corps.messages ?? []).filter((m) => m && (m.role === "system" || m.role === "developer")).flatMap((m) => textesDeParties(m.content, ["text"]));
  }
  if (format === "openai-responses") {
    const out = typeof corps.instructions === "string" ? [corps.instructions] : [];
    if (Array.isArray(corps.input)) for (const it of corps.input) if (it && (it.role === "developer" || it.role === "system")) out.push(...textesDeParties(it.content, ["input_text", "text"]));
    return out;
  }
  return [];
}

/** Le prompt système d'une requête (morceaux séparés par \n), ou null s'il n'y en a pas. */
export function extrairePromptSysteme(format, corps) {
  const m = morceauxPrompt(format, corps);
  return m.length ? m.join("\n") : null;
}

/** La requête dont le prompt système est remplacé par le jeton [REDIGE:prompt-systeme] (EX-8.5). */
export function remplacerPromptSysteme(format, corps) {
  const c = copieJSON(corps);
  if (format === "anthropic-messages" && Object.hasOwn(c, "system") && c.system !== null) c.system = JETON_PROMPT_SYSTEME;
  if (format === "openai-chat") for (const m of c.messages ?? []) if (m && (m.role === "system" || m.role === "developer")) m.content = JETON_PROMPT_SYSTEME;
  if (format === "openai-responses") {
    if (typeof c.instructions === "string") c.instructions = JETON_PROMPT_SYSTEME;
    if (Array.isArray(c.input)) for (const it of c.input) if (it && (it.role === "developer" || it.role === "system")) it.content = JETON_PROMPT_SYSTEME;
  }
  return c;
}

/** Texte produit par l'assistant (table de 5.5), ou null. */
export function extraireIntention(format, reponse) {
  if (!reponse || typeof reponse !== "object") return null;
  let morceaux = [];
  if (format === "anthropic-messages") morceaux = (Array.isArray(reponse.content) ? reponse.content : []).filter((b) => b && b.type === "text" && typeof b.text === "string").map((b) => b.text);
  else if (format === "openai-chat") {
    const c = reponse.choices?.[0]?.message?.content;
    morceaux = typeof c === "string" ? [c] : [];
  } else if (format === "openai-responses") {
    for (const it of Array.isArray(reponse.output) ? reponse.output : []) if (it && it.type === "message") morceaux.push(...textesDeParties(it.content, ["output_text"]));
  }
  const t = morceaux.join("\n");
  return t === "" ? null : t;
}

/**
 * Appels d'outils demandés par le modèle (table de 5.5) : [{ id, name,
 * arguments, position }] ; `arguments` est l'objet `input` (Anthropic) ou la
 * chaîne JSON reçue (OpenAI), `position` l'indice du bloc ou de l'item.
 */
export function extraireAppelsOutils(format, reponse) {
  if (!reponse || typeof reponse !== "object") return [];
  if (format === "anthropic-messages") {
    return (Array.isArray(reponse.content) ? reponse.content : []).map((b, position) => ({ b, position })).filter(({ b }) => b && b.type === "tool_use").map(({ b, position }) => ({ id: b.id ?? null, name: b.name, arguments: b.input, position }));
  }
  if (format === "openai-chat") {
    return (reponse.choices?.[0]?.message?.tool_calls ?? []).map((t, position) => ({ id: t.id ?? null, name: t.function?.name, arguments: t.function?.arguments, position }));
  }
  if (format === "openai-responses") {
    return (Array.isArray(reponse.output) ? reponse.output : []).map((it, position) => ({ it, position })).filter(({ it }) => it && it.type === "function_call").map(({ it, position }) => ({ id: it.call_id ?? null, name: it.name, arguments: it.arguments, position }));
  }
  return [];
}

/** Texte de l'assistant qui précède l'appel d'outil à la position `position` de la réponse (EX-5.22). */
export function texteAvantAppel(format, reponse, position) {
  if (format === "anthropic-messages") {
    const t = reponse.content.slice(0, position).filter((b) => b && b.type === "text" && typeof b.text === "string").map((b) => b.text).join("\n");
    return t === "" ? null : t;
  }
  if (format === "openai-chat") return extraireIntention(format, reponse);
  if (format === "openai-responses") {
    const t = reponse.output.slice(0, position).filter((it) => it && it.type === "message").flatMap((it) => textesDeParties(it.content, ["output_text"])).join("\n");
    return t === "" ? null : t;
  }
  return null;
}

/**
 * code.model (EX-5.19) : `<libellé>/<model>`, le `model` étant lu dans la
 * réponse (rédigée), à défaut dans la requête (rédigée) si elle a la forme
 * attendue ; sinon null ; 256 caractères au plus.
 */
export function codeModele(libelle, reponse, requete) {
  const m = typeof reponse?.model === "string" ? reponse.model : typeof requete?.model === "string" ? requete.model : null;
  return m === null ? null : tronquer(`${libelle}/${m}`, 256);
}

/**
 * Intention tirée d'une réponse de modèle (EX-5.21, EX-10.18) : `texteRedige`
 * est le texte extrait de la réponse rédigée, `texteClair` celui que la
 * réponse en clair aurait donné (pour la seule comparaison). Une chaîne s'il
 * est intact et d'au plus 4096 caractères, sinon une référence à une pièce
 * text/plain, redacted si les deux textes diffèrent. Rend { intent, piece }.
 */
export function intentionRedigee(texteRedige, texteClair) {
  if (texteRedige === null || texteRedige === undefined) return { intent: null, piece: null, correspondances: [] };
  const redacted = texteRedige !== texteClair;
  if (!redacted && longueurPointsDeCode(texteRedige) <= 4096) return { intent: texteRedige, piece: null, correspondances: [] };
  const octets = Buffer.from(texteRedige, "utf8");
  const piece = { valeur: texteRedige, octets, reference: referencePiece(octets, { redacted, media_type: "text/plain" }), correspondances: [], notes: [] };
  return { intent: piece.reference, piece, correspondances: [] };
}

/**
 * Intention déclarée (SDK, `debutAppel`) : le texte rédigé par les règles de la
 * portée (`arguments` par défaut, EX-10.18) ; une chaîne s'il est intact et
 * d'au plus 4096 caractères, sinon une référence à une pièce text/plain. Rend
 * { intent, piece (ou null), correspondances }.
 */
export function intentionDepuisTexte(texte, { politique = null, portee = "arguments", budgetMs = BUDGET_REDACTION_MS, onDepassement = null } = {}) {
  if (texte === null || texte === undefined) return { intent: null, piece: null, correspondances: [] };
  const p = pieceTexte(texte, { politique, portee, media_type: "text/plain", budgetMs, onDepassement });
  if (!p.reference.redacted && longueurPointsDeCode(p.valeur) <= 4096) return { intent: p.valeur, piece: null, correspondances: p.correspondances };
  return { intent: p.reference, piece: p, correspondances: p.correspondances };
}

/**
 * Le prompt laissé dans la requête et rédigé chaîne par chaîne par les règles
 * prompt_systeme (EX-8.5, mode inline). Sans borne de temps propre : c'est une
 * partie de la rédaction de la pièce « requête », qu'echangeModele exécute
 * sous un seul budget (EX-10.23).
 */
export function redigerPromptEnPlace(format, corps, politique) {
  const c = copieJSON(corps);
  const r = (s) => (typeof s === "string" ? rediger(politique, s, { portee: "prompt_systeme", budgetMs: null }).valeur : s);
  const parties = (contenu, types) => {
    if (typeof contenu === "string") return r(contenu);
    if (Array.isArray(contenu)) for (const p of contenu) if (p && types.includes(p.type) && typeof p.text === "string") p.text = r(p.text);
    return contenu;
  };
  if (format === "anthropic-messages") {
    if (typeof c.system === "string") c.system = r(c.system);
    else if (Array.isArray(c.system)) for (const b of c.system) if (b && b.type === "text" && typeof b.text === "string") b.text = r(b.text);
  }
  if (format === "openai-chat") for (const m of c.messages ?? []) if (m && (m.role === "system" || m.role === "developer")) m.content = parties(m.content, ["text"]);
  if (format === "openai-responses") {
    if (typeof c.instructions === "string") c.instructions = r(c.instructions);
    if (Array.isArray(c.input)) for (const it of c.input) if (it && (it.role === "developer" || it.role === "system")) it.content = parties(it.content, ["input_text", "text"]);
  }
  return c;
}

/** Corps d'erreur au format du fournisseur pour un refus de la passerelle (EX-5.7, 14.2). */
export function corpsErreurPasserelle(format, { type, message, code = null }) {
  if (format === "anthropic-messages") return { type: "error", error: { type, message } };
  return { error: { message, type, param: null, code: code ?? type } };
}

/**
 * Pièces et grandeurs d'un échange de modèle (CT-2 §5.3, §5.5, §8.2). Entrée :
 * `format`, `provider_label`, `requete` = { corps: octets reçus, content_type,
 * content_encoding }, `reponse` = { status, content_type, corps: octets }, la
 * politique chargée, `prompt_in_request` (`reference` par défaut ou `inline`),
 * `prompt_system` (`redige` par défaut ou `named` avec `prompt_version_name`).
 * Une requête comprimée ou non analysable est refusée (EX-5.7) : rend alors
 * { refus: { status, corps, raison } } sans pièce. Sinon rend { pieces: {
 * requete, reponse, prompt_systeme, intention }, consolidated, forme (la
 * réponse en clair, pour la seule corrélation), forme_redigee, code_model,
 * prompt_version, intent, tool_calls, is_error, incomplete, correspondances }.
 */
export function echangeModele({ format, provider_label, requete, reponse, politique = null, prompt_in_request = "reference", prompt_system = "redige", prompt_version_name = null, budgetMs = BUDGET_REDACTION_MS, onDepassement = null }) {
  const correspondancesTotales = [];
  const noter = (p, piece) => {
    for (const c of p.correspondances ?? []) correspondancesTotales.push({ piece, ...c });
  };
  // Requête (EX-5.7).
  if (requete.content_encoding && String(requete.content_encoding).toLowerCase() !== "identity") {
    return { refus: { status: 415, raison: "content_encoding", corps: corpsErreurPasserelle(format, { type: "invalid_request_error", message: "noortrace: requete comprimee refusee", code: "noortrace_requete_invalide" }) } };
  }
  let corpsRequete;
  try {
    corpsRequete = analyserJSONIntegral(requete.corps);
  } catch {
    return { refus: { status: 400, raison: "corps_non_analysable", corps: corpsErreurPasserelle(format, { type: "invalid_request_error", message: "noortrace: corps de requete non analysable", code: "noortrace_requete_invalide" }) } };
  }
  let pieceRequete;
  let piecePrompt = null;
  const longueurRequete = Buffer.from(requete.corps ?? []).length;
  const deForme = requeteDeForme(format, corpsRequete);
  if (!deForme) {
    pieceRequete = pieceJSON(corpsRequete, { politique, portee: "requete", budgetMs, onDepassement, contentType: requete.content_type ?? null, longueurRecue: longueurRequete });
  } else {
    const prompt = extrairePromptSysteme(format, corpsRequete);
    if (prompt !== null) {
      piecePrompt = prompt_system === "named" ? pieceTexte(`[PROMPT:${prompt_version_name}]`) : pieceTexte(prompt, { politique, portee: "prompt_systeme", budgetMs, onDepassement });
      noter(piecePrompt, "prompt_systeme");
    }
    // La pièce « requête » est une seule opération sous le budget (EX-10.23), rédaction du prompt laissé en place comprise.
    const preparer = () => (prompt === null ? corpsRequete : prompt_in_request === "reference" ? remplacerPromptSysteme(format, corpsRequete) : redigerPromptEnPlace(format, corpsRequete, politique));
    regleEnCours = null;
    const b = politique ? sousBudget(() => passagesRedaction(politique, preparer(), { portee: "requete", outil: null, alias: null }), budgetMs) : { ok: true, valeur: { valeur: copieJSON(preparer()), correspondances: [], notes: [] } };
    if (!b.ok) {
      const note = noterDepassement(onDepassement, "piece", "requete", regleEnCours);
      pieceRequete = pieceNonRedigeable({ content_type: requete.content_type ?? null, length: longueurRequete, reason: "budget_redaction" }, [`budget_redaction : règle ${note.rule ?? "?"}, portée requete`]);
    } else {
      const r = b.valeur;
      const octets = octetsJCSIntegral(r.valeur);
      const redacted = J.canonicaliserJCSIntegral(r.valeur) !== J.canonicaliserJCSIntegral(corpsRequete);
      pieceRequete = { valeur: r.valeur, octets, reference: referencePiece(octets, { redacted }), correspondances: r.correspondances, notes: r.notes };
    }
  }
  noter(pieceRequete, "requete");

  // Réponse.
  const status = reponse.status;
  const mediaReponse = typeDeMedia(reponse.content_type);
  let forme = null;
  let consolidated = null;
  let incomplete = false;
  let is_error = false;
  let pieceReponse;
  if (status >= 400) {
    const o = Buffer.from(reponse.corps ?? []);
    let body = null;
    if (o.length > 0) {
      let texte = null;
      try {
        texte = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(o);
      } catch {
        texte = null;
      }
      if (texte === null) body = formeNonRedigeable({ content_type: reponse.content_type ?? null, length: o.length, reason: "non_utf8" });
      else if (estTypeJSON(mediaReponse)) {
        try {
          body = analyserJSONIntegral(o);
        } catch {
          body = texte;
        }
      } else body = texte;
    }
    pieceReponse = pieceJSON({ noortrace_http_error: { status, content_type: reponse.content_type ?? null, body } }, { politique, portee: "reponse", budgetMs, onDepassement, contentType: reponse.content_type ?? null, longueurRecue: o.length });
    is_error = true;
  } else if (mediaReponse === "text/event-stream") {
    const c = consoliderFlux(format, reponse.corps);
    incomplete = c.incomplet;
    is_error = c.is_error;
    if (c.forme === null) {
      pieceReponse = pieceBrute(reponse.corps, { contentType: "text/event-stream", politique, portee: "reponse", budgetMs, onDepassement });
    } else {
      forme = c.forme;
      consolidated = c.forme;
      pieceReponse = pieceJSON(c.forme, { politique, portee: "reponse", budgetMs, onDepassement, contentType: reponse.content_type ?? null, longueurRecue: Buffer.from(reponse.corps ?? []).length });
    }
  } else {
    let analysee = false;
    if (estTypeJSON(mediaReponse)) {
      try {
        forme = analyserJSONIntegral(reponse.corps);
        analysee = true;
      } catch {
        forme = null;
      }
    }
    if (analysee) pieceReponse = pieceJSON(forme, { politique, portee: "reponse", budgetMs, onDepassement, contentType: reponse.content_type ?? null, longueurRecue: Buffer.from(reponse.corps ?? []).length });
    else {
      pieceReponse = pieceBrute(reponse.corps, { contentType: reponse.content_type, politique, portee: "reponse", budgetMs, onDepassement });
      is_error = true;
    }
  }
  noter(pieceReponse, "reponse");

  // Valeurs en ligne tirées des seules valeurs rédigées (EX-5.21, EX-10.2).
  const formeRedigee = forme === null ? null : pieceReponse.valeur;
  const intention = status >= 400 ? intentionRedigee(null, null) : intentionRedigee(extraireIntention(format, formeRedigee), extraireIntention(format, forme));
  return {
    pieces: { requete: pieceRequete, reponse: pieceReponse, prompt_systeme: piecePrompt, intention: intention.piece },
    consolidated,
    forme,
    forme_redigee: formeRedigee,
    code_model: codeModele(provider_label, status >= 400 ? null : formeRedigee, deForme ? pieceRequete.valeur : null),
    prompt_version: piecePrompt ? piecePrompt.reference.sha256 : null,
    intent: intention.intent,
    tool_calls: status >= 400 ? [] : extraireAppelsOutils(format, forme).map(({ id, name, arguments: a }) => ({ id, name, arguments: a })),
    is_error,
    incomplete,
    correspondances: correspondancesTotales,
  };
}

/**
 * Pièces d'un sampling/createMessage relayé (EX-4.29) : requête = `params` de
 * CreateMessageRequest, réponse = CreateMessageResult, code.model =
 * « hote/ » + model, is_error faux.
 */
export function echangeSampling({ params, resultat, politique = null, budgetMs = BUDGET_REDACTION_MS, onDepassement = null }) {
  const requete = pieceJSON(params, { politique, portee: "requete", budgetMs, onDepassement });
  const reponse = pieceJSON(resultat, { politique, portee: "reponse", budgetMs, onDepassement });
  return { pieces: { requete, reponse }, code_model: typeof resultat?.model === "string" ? tronquer(`hote/${resultat.model}`, 256) : null, is_error: false };
}

// ---------------------------------------------------------------------------
// Corrélation appel d'outil ↔ échange de modèle (CT-2 §5.6, EX-5.22)
// ---------------------------------------------------------------------------

/**
 * Nom vu par le modèle (EX-5.22) : gabarit de la connexion d'hôte appliqué
 * (`{tool_announced}`, et `{alias}`, `{tool}` du schéma de configuration),
 * puis, si demandé, les caractères hors A-Z a-z 0-9 _ - remplacés par `_`.
 */
export function nomVuParModele(nom, { template = "{tool_announced}", sanitize = false, alias = null, original = null } = {}) {
  const decoupe = resoudreNomAnnonce(nom) ?? { alias: null, original: nom };
  const n = template
    .split("{tool_announced}").join(nom)
    .split("{alias}").join(alias ?? decoupe.alias ?? "")
    .split("{tool}").join(original ?? decoupe.original);
  return sanitize ? n.replace(/[^A-Za-z0-9_-]/g, "_") : n;
}

/**
 * Cherche l'échange de modèle qui a produit un tools/call (EX-5.22).
 * `appel` = { tool_announced, arguments (valeur en clair), t_recu (ms),
 * run_id (déclaré ou null), groupe (host_group de la connexion d'hôte) } ;
 * `echanges` = le registre de corrélation : [{ seq, t (ms, inscription),
 * run_id, groupe, format, forme (réponse en clair), forme_redigee,
 * code_model, prompt_version, consommes (Set) }]. Seuls les échanges du même
 * groupe, et du même run_id quand les deux sont déclarés, sont candidats.
 * Rend { echange, appel, texte, texteClair } : l'échange et l'appel
 * correspondants, le texte de l'assistant qui précède l'appel tiré de la
 * réponse rédigée, et celui que la réponse en clair donnerait (pour la seule
 * comparaison) ; sans correspondance, tout vaut null (aucun échange antérieur
 * n'est repris). Marque l'appel consommé.
 */
export function correler(appel, echanges, { fenetre_ms = 600000, template = "{tool_announced}", sanitize = false } = {}) {
  const groupe = appel.groupe ?? appel.hote;
  const candidats = echanges
    .filter((e) => (e.groupe ?? e.hote) === groupe && !(appel.run_id && e.run_id && e.run_id !== appel.run_id) && e.t <= appel.t_recu && e.t >= appel.t_recu - fenetre_ms)
    .sort((a, b) => b.t - a.t || b.seq - a.seq);
  const vu = nomVuParModele(appel.tool_announced, { template, sanitize });
  const cible = J.canonicaliserJCSIntegral(appel.arguments ?? {});
  for (const e of candidats) {
    for (const c of extraireAppelsOutils(e.format, e.forme)) {
      if (e.consommes?.has(c.position)) continue;
      if (c.name !== appel.tool_announced && c.name !== vu) continue;
      let args;
      if (typeof c.arguments === "string") {
        try {
          args = analyserJSONIntegral(c.arguments);
        } catch {
          continue;
        }
      } else args = c.arguments;
      let canon;
      try {
        canon = J.canonicaliserJCSIntegral(args ?? {});
      } catch {
        continue;
      }
      if (canon !== cible) continue;
      e.consommes ??= new Set();
      e.consommes.add(c.position);
      return { echange: e, appel: c, texte: texteAvantAppel(e.format, e.forme_redigee ?? e.forme, c.position), texteClair: texteAvantAppel(e.format, e.forme, c.position) };
    }
  }
  return { echange: null, appel: null, texte: null, texteClair: null };
}

// ---------------------------------------------------------------------------
// Effets déclarés (EX-7.6)
// ---------------------------------------------------------------------------

const RE_MONTANT = /^-?(0|[1-9][0-9]*)(\.[0-9]{1,8})?$/;

/** Valeur d'un pointeur de gabarit (`/arguments/…`, `/result/…`) convertie en chaîne ; undefined si le pointeur ne résout pas. */
function valeurGabarit(pointeur, source) {
  const r = resoudrePointeur(source, pointeur);
  if (!r.trouve || r.valeur === null) return undefined;
  return typeof r.valeur === "string" ? r.valeur : J.canonicaliserJCSIntegral(r.valeur);
}

/**
 * Contrôle de démarrage des gabarits d'effets (EX-7.6, EX-15.4 pas 3) :
 * chaque `extract` non nul est du sous-ensemble commun d'EX-10.6, règles de
 * structure et de taille comprises, et d'au plus 1 024 caractères. Rend la
 * liste des erreurs (chaînes), vide si les gabarits sont recevables.
 */
export function erreursGabaritsEffets(gabarits, { ou = "effects" } = {}) {
  const erreurs = [];
  (gabarits ?? []).forEach((g, i) => {
    if (g?.extract === null || g?.extract === undefined) return;
    if (typeof g.extract !== "string" || longueurPointsDeCode(g.extract) > 1024) return erreurs.push(`${ou}[${i}].extract : chaîne de 1 024 caractères au plus attendue`);
    const e = erreursMotifRE2(g.extract);
    if (e.length) erreurs.push(`${ou}[${i}].extract : ${e.join(", ")}`);
  });
  return erreurs;
}

/**
 * Évalue les gabarits d'effets d'un outil (EX-7.6) sur les valeurs
 * **rédigées** des pièces « arguments » et « résultat » (l'appelant les
 * passe) : `object` est un pointeur (s'il commence par « / ») ou
 * une chaîne fixe, `extract` une expression régulière optionnelle (première
 * correspondance, leftmost-first : premier groupe capturant s'il a participé,
 * sinon la correspondance entière ; `(?P<` réécrit en `(?<` comme pour un
 * motif nommé, EX-10.6), `amount` un pointeur ou null, `currency` un
 * pointeur, trois majuscules ou null. Un pointeur qui ne résout pas, une
 * expression qui ne correspond pas, un montant qui n'est pas une chaîne
 * décimale de CT-1 ou un couple montant/devise incomplet donnent un effet omis
 * et une note. L'évaluation de chaque gabarit tient dans `budgetMs`
 * (EX-10.23) : au-delà, l'effet est omis avec la raison budget_redaction.
 * `defaut` : les effets par défaut de l'outil (effetsParDefaut ; un effet
 * pour une classe ecriture) : quand aucun effet n'est produit alors qu'une
 * pièce source est la pièce non rédigeable (EX-8.7) ou qu'un extract a
 * dépassé le budget, ce sont eux qui sont déclarés (EX-7.6, EX-10.23), pour
 * qu'une écriture exécutée ne reste jamais sans effet déclaré par la seule
 * taille ou forme de ses données. Rend { effects, notes }.
 */
export function evaluerGabaritsEffets(gabarits, { arguments: args = null, result = null, budgetMs = BUDGET_REDACTION_MS, onDepassement = null, defaut = null } = {}) {
  const source = { arguments: args, result };
  const effects = [];
  const notes = [];
  let horsBudget = estNonRedigeable(args) || estNonRedigeable(result);
  (gabarits ?? []).forEach((g, i) => {
    let object = g.object.startsWith("/") ? valeurGabarit(g.object, source) : g.object;
    if (object === undefined) return notes.push(`effet ${i} : pointeur ${g.object} non résolu`);
    if (g.extract) {
      const re = compilerExtract(g.extract);
      const b = sousBudget(() => re.exec(object), budgetMs);
      if (!b.ok) {
        noterDepassement(onDepassement, "extract", null, null);
        horsBudget = true;
        return notes.push(`effet ${i} : effect_omitted, budget_redaction`);
      }
      const m = b.valeur;
      if (!m) return notes.push(`effet ${i} : extraction sans correspondance`);
      object = m[1] ?? m[0];
    }
    object = tronquer(object, 512);
    if (object === "") return notes.push(`effet ${i} : objet vide`);
    let amount = null;
    let currency = null;
    if (g.amount !== null && g.amount !== undefined) {
      amount = valeurGabarit(g.amount, source);
      if (amount === undefined) return notes.push(`effet ${i} : pointeur ${g.amount} non résolu`);
      if (!RE_MONTANT.test(amount)) return notes.push(`effet ${i} : montant hors du format décimal de CT-1`);
    }
    if (g.currency !== null && g.currency !== undefined) {
      currency = g.currency.startsWith("/") ? valeurGabarit(g.currency, source) : g.currency;
      if (currency === undefined) return notes.push(`effet ${i} : pointeur ${g.currency} non résolu`);
      if (!/^[A-Z]{3}$/.test(currency)) return notes.push(`effet ${i} : devise hors du format ISO 4217`);
    }
    if ((amount === null) !== (currency === null)) return notes.push(`effet ${i} : montant et devise doivent être tous deux renseignés ou tous deux nuls`);
    effects.push({ system: tronquer(g.system, 128), action: g.action, object, amount, currency });
  });
  if (effects.length === 0 && horsBudget && defaut?.length) {
    notes.push("effets par défaut : pièce non rédigeable ou extract au-delà du budget (EX-7.6, EX-10.23)");
    return { effects: copieJSON(defaut), notes };
  }
  return { effects, notes };
}

/**
 * Effets déclarés par le SDK (EX-6.6, EX-7.6) : les chaînes `system` et
 * `object` passent par les détecteurs de texte des règles de portée
 * `arguments` de l'outil, avec leur action (remplacement par le jeton), puis
 * les pas 2 et 4 d'EX-7.6 (troncature, montant, devise). L'examen des
 * chaînes d'un effet tient dans `budgetMs` (EX-10.23) : au-delà, l'effet est
 * omis. Rend { effects, notes }.
 */
export function effetsDeclares(effets, { politique = null, outil = null, alias = null, budgetMs = BUDGET_REDACTION_MS, onDepassement = null } = {}) {
  const effects = [];
  const notes = [];
  const regles = politique ? politique.doc.rules.filter((r) => regleApplicable(r, "arguments", outil, alias)) : [];
  (effets ?? []).forEach((e, i) => {
    let system = e.system;
    let object = e.object;
    if (regles.length) {
      regleEnCours = null;
      const b = sousBudget(() => [redigerChaineParDetecteurs(politique, system, regles).texte, redigerChaineParDetecteurs(politique, object, regles).texte], budgetMs);
      if (!b.ok) {
        noterDepassement(onDepassement, "valeur", "arguments", regleEnCours);
        return notes.push(`effet ${i} : effect_omitted, budget_redaction`);
      }
      [system, object] = b.valeur;
    }
    system = tronquer(system, 128);
    object = tronquer(object, 512);
    if (system === "" || object === "") return notes.push(`effet ${i} : system ou objet vide`);
    const amount = e.amount ?? null;
    const currency = e.currency ?? null;
    if (amount !== null && (typeof amount !== "string" || !RE_MONTANT.test(amount))) return notes.push(`effet ${i} : montant hors du format décimal de CT-1`);
    if (currency !== null && (typeof currency !== "string" || !/^[A-Z]{3}$/.test(currency))) return notes.push(`effet ${i} : devise hors du format ISO 4217`);
    if ((amount === null) !== (currency === null)) return notes.push(`effet ${i} : montant et devise doivent être tous deux renseignés ou tous deux nuls`);
    effects.push({ system, action: e.action, object, amount, currency });
  });
  return { effects, notes };
}

/** Effets par défaut sans gabarit (EX-7.6) : un effet ecriture pour un outil de classe ecriture, aucun pour une lecture. */
export function effetsParDefaut({ classe, alias, original }) {
  return classe === "ecriture" ? [{ system: tronquer(alias, 128), action: "ecriture", object: tronquer(original, 512), amount: null, currency: null }] : [];
}

// ---------------------------------------------------------------------------
// Construction des événements CT-1 (CT-2 §7) et écrivain (§7.3, §7.4, §12)
// ---------------------------------------------------------------------------

/** policy.redaction (EX-10.20) : `nom` si l'une des références a redacted: true, sinon null. */
export function redactionDe(nom, references) {
  return references.some((r) => r && typeof r === "object" && r.redacted === true) ? nom : null;
}

/** Les références d'un événement partiel, pour policy.redaction. */
function referencesPartiel(p) {
  return [p.execution?.arguments, p.execution?.result, typeof p.intent === "object" ? p.intent : null, ...(p.context ?? [])];
}

/**
 * Événement partiel d'un appel d'outil (CT-2 §7.2) : les huit champs, sans
 * l'enveloppe. `policy` = { rule, decision, ticket } rendu par CT-3 ;
 * policy.redaction est calculé (EX-10.20) avec `nomRedaction`.
 */
export function partielAppelOutil({ delegation, code, intent = null, policy, approval = null, tool, arguments: args, status, result = null, duration_ms = null, is_error = null, effects = [], context = [], nomRedaction = null }) {
  const p = {
    delegation: { ...delegation },
    code: { ...code },
    intent,
    policy: { rule: policy.rule ?? null, decision: policy.decision, ticket: policy.ticket ?? null, redaction: null },
    approval,
    execution: { tool, arguments: args, status, result, duration_ms, is_error },
    effects,
    context,
  };
  p.policy.redaction = redactionDe(nomRedaction, referencesPartiel(p));
  return p;
}

/** Événement partiel d'un échange de modèle (CT-2 §7.2) : toujours executee, policy sans_objet. */
export function partielEchangeModele({ delegation, code, intent = null, requete, reponse, duration_ms, is_error, nomRedaction = null }) {
  const p = {
    delegation: { ...delegation },
    code: { ...code },
    intent,
    policy: { rule: null, decision: "sans_objet", ticket: null, redaction: null },
    approval: null,
    execution: { tool: J.OUTIL_MODELE, arguments: requete, status: "executee", result: reponse, duration_ms, is_error },
    effects: [],
    context: [],
  };
  p.policy.redaction = redactionDe(nomRedaction, referencesPartiel(p));
  return p;
}

/** Événement partiel d'une décision d'approbation (CT-2 §9.1, EX-7.11) : arguments en ligne = A. */
export function partielDecision({ delegation, code, approval, org_id, journal_id }) {
  const A = J.objetApprobation({ approval, org_id, journal_id });
  return {
    delegation: { ...delegation },
    code: { ...code },
    intent: null,
    policy: { rule: null, decision: "sans_objet", ticket: approval.ticket, redaction: null },
    approval,
    execution: { tool: J.OUTIL_APPROBATION, arguments: J.referenceEnLigne(A), status: "executee", result: null, duration_ms: null, is_error: null },
    effects: [],
    context: [],
  };
}

/** Événement partiel d'un changement de politique (CT-2 §9.1, EX-15.6). */
export function partielPolitique({ policy_version, policy_sha256, recorder = VERSION_ENREGISTREUR }) {
  return {
    delegation: { ...DELEGATION_JOURNAL },
    code: { model: null, prompt_version: null, policy_version, recorder },
    intent: null,
    policy: { rule: null, decision: "sans_objet", ticket: null, redaction: null },
    approval: null,
    execution: { tool: J.OUTIL_POLITIQUE, arguments: J.referenceEnLigne({ policy_version, policy_sha256 }), status: "executee", result: null, duration_ms: null, is_error: null },
    effects: [{ system: "noortrace", action: "ecriture", object: `politique:${policy_version}`, amount: null, currency: null }],
    context: [],
  };
}

/** Événement partiel d'une rotation de clé (CT-1 §8, CT-2 §11.4). */
export function partielRotation({ annonce, policy_version, recorder = VERSION_ENREGISTREUR }) {
  return {
    delegation: { ...DELEGATION_JOURNAL },
    code: { model: null, prompt_version: null, policy_version, recorder },
    intent: null,
    policy: { rule: null, decision: "sans_objet", ticket: null, redaction: null },
    approval: null,
    execution: { tool: J.OUTIL_ROTATION, arguments: J.referenceEnLigne(annonce), status: "executee", result: null, duration_ms: null, is_error: null },
    effects: [{ system: "noortrace", action: "ecriture", object: `cle:${annonce.new_key_id}`, amount: null, currency: null }],
    context: [],
  };
}

const msDe = (t) => (typeof t === "number" ? t : J.msHorodatage(t));

/**
 * L'écrivain unique d'un journal (CT-2 §3.4, §7.3, §7.4) : fixe seq, ts,
 * prev_hash et recorder_key_id dans l'ordre d'arrivée, valide l'événement
 * (schéma de CT-1 et contrôles E-1 à E-7, EX-7.1) avant de le faire signer,
 * puis le scelle. `cles` : key_id → clé privée (KeyObject ou graine) ;
 * `dernier` : le dernier événement durable (reprise), ou null.
 */
export class Ecrivain {
  constructor({ org_id, journal_id, recorder_key_id, cles, schemas, max_backstep_ms = 5000, max_forward_ms = 60000, dernier = null }) {
    this.org_id = org_id;
    this.journal_id = journal_id;
    this.recorder_key_id = dernier ? J.cleSuivanteAttendue(dernier) : recorder_key_id;
    this.cles = cles;
    this.schemas = schemas;
    this.max_backstep_ms = max_backstep_ms;
    this.max_forward_ms = max_forward_ms;
    this.dernier = dernier;
    this.lecturePrecedente = null; // { lu, mono } : dernière lecture d'horloge murale et monotone (EX-7.13)
    this.evenements = [];
  }

  /**
   * ts selon EX-7.9 : max(ts lu, ts précédent) ; mode dégradé « horloge » au-delà
   * du seuil de recul, et, quand l'instant monotone `mono` est donné, au-delà de
   * la tolérance d'avance d'EX-7.13 (saut en avant).
   */
  horodater(tsLu, { capture = false, mono = null } = {}) {
    const lu = msDe(tsLu);
    if (Number.isNaN(lu)) throw new Error(`horodatage invalide : ${tsLu}`);
    if (!capture && mono !== null && this.lecturePrecedente) {
      const avanceMurale = lu - this.lecturePrecedente.lu;
      const avanceMonotone = mono - this.lecturePrecedente.mono;
      if (avanceMurale > avanceMonotone + this.max_forward_ms) throw new ErreurModeDegrade("horloge", `horloge murale avancée de ${avanceMurale - avanceMonotone} ms de plus que l'horloge monotone (EX-7.13)`);
    }
    if (!this.dernier) return J.horodatage(lu);
    const prec = J.msHorodatage(this.dernier.ts);
    if (!capture && lu < prec - this.max_backstep_ms) throw new ErreurModeDegrade("horloge", `horloge reculée de ${prec - lu} ms, au-delà du seuil de ${this.max_backstep_ms} ms`);
    return J.horodatage(Math.max(lu, prec));
  }

  /**
   * Scelle un événement partiel : `ts_lu` (horloge murale à l'instant de
   * l'écriture, avec `mono` l'instant de l'horloge monotone, EX-7.13) ou
   * `captured_at` (événement en attente, EX-14.10). Pour une décision
   * d'approbation, `approval.at` reçoit le ts attribué (EX-7.11). Rend
   * l'événement complet ; lève une erreur (bogue de l'enregistreur, EX-7.1) si
   * l'événement construit n'est pas valide, sans le signer.
   */
  sceller(partiel, { ts_lu, captured_at, mono = null } = {}) {
    const ts = captured_at !== undefined ? this.horodater(captured_at, { capture: true }) : this.horodater(ts_lu, { mono });
    if (captured_at === undefined && mono !== null) this.lecturePrecedente = { lu: msDe(ts_lu), mono };
    if (partiel.execution?.tool === J.OUTIL_APPROBATION && partiel.approval) partiel = { ...partiel, approval: { ...partiel.approval, at: ts } };
    const corps = {
      version: J.VERSION_FORMAT,
      seq: this.dernier ? this.dernier.seq + 1 : 1,
      ts,
      org_id: this.org_id,
      journal_id: this.journal_id,
      recorder_key_id: this.recorder_key_id,
      prev_hash: this.dernier ? this.dernier.hash : J.HASH_NUL,
      ...partiel,
    };
    const ordonne = {};
    for (const k of J.CLES_EVENEMENT) if (k !== "hash" && k !== "sig") ordonne[k] = corps[k];
    // EX-7.1 : contrôles E-1 à E-7 avant toute signature (sig provisoire de 64 octets nuls, que ces contrôles ne lisent pas).
    const provisoire = { ...ordonne, hash: J.hachageEvenement(ordonne), sig: "0x" + "00".repeat(64) };
    const res = J.controlesEvenement(provisoire, { schemas: this.schemas });
    const echecs = Object.entries(res).filter(([id, x]) => x.ok === false && ["E-1", "E-2", "E-3", "E-4", "E-5", "E-6", "E-7", "E-9", "E-10"].includes(id));
    if (echecs.length) throw new Error(`événement seq ${ordonne.seq} refusé avant signature (EX-7.1) : ${echecs.map(([id, x]) => `${id} ${x.detail}`).join(" ; ")}`);
    const cle = this.cles instanceof Map ? this.cles.get(this.recorder_key_id) : this.cles[this.recorder_key_id];
    const ev = J.scellerEvenement(ordonne, cle);
    this.dernier = ev;
    this.recorder_key_id = J.cleSuivanteAttendue(ev);
    this.evenements.push(ev);
    return ev;
  }
}

/** En-tête de segment (EX-12.3) : objet JSON en JCS v0, sur la première ligne, suivi de \n. */
export function enteteSegment({ epoch, first_seq, instance_id, org_id, journal_id, opened_at, prev_hash, recorder = VERSION_ENREGISTREUR, recorder_key_id }) {
  return J.canonicaliserJCS({ epoch, first_seq, instance_id, journal_id, noortrace_segment: 0, opened_at, org_id, prev_hash, recorder, recorder_key_id }) + "\n";
}

/** Ligne de segment (EX-12.3) : l'événement complet (hash et sig compris) en JCS v0, suivi de \n. */
export const ligneSegment = (ev) => J.canonicaliserJCS(ev) + "\n";

/** Segment complet : en-tête puis une ligne par événement. */
export function segment(entete, evenements) {
  return enteteSegment(entete) + evenements.map(ligneSegment).join("");
}

/**
 * Relit un segment (EX-12.10, pas 2 et 3 ; EX-12.11) : rend { entete,
 * evenements, longueurValide, tronque, corrompu }. Une fin de fichier
 * incomplète (dernière ligne sans \n ou illisible, octets nuls de remplissage)
 * est une écriture tronquée : `longueurValide` est la longueur à laquelle
 * tronquer. Une ligne complète suivie d'autres lignes et invalide (schéma,
 * seq, prev_hash, hash recalculé, signature) est une corruption : `corrompu`
 * la décrit, et rien n'est à tronquer en silence.
 */
export function relireSegment(texte, { schemas, clesPubliques } = {}) {
  const buf = Buffer.isBuffer(texte) ? texte : Buffer.from(texte, "utf8");
  const nl = buf.indexOf(0x0a);
  if (nl < 0) return { entete: null, evenements: [], longueurValide: 0, tronque: buf.length > 0, corrompu: null };
  const entete = analyserJSONIntegral(buf.subarray(0, nl));
  const cles = J.normaliserCles(clesPubliques);
  let pos = nl + 1;
  let prevSeq = entete.first_seq - 1;
  let prevHash = entete.prev_hash;
  let cle = entete.recorder_key_id;
  const evenements = [];
  const fin = (tronque, corrompu = null) => ({ entete, evenements, longueurValide: pos, tronque, corrompu });
  while (pos < buf.length) {
    const finLigne = buf.indexOf(0x0a, pos);
    const reste = buf.subarray(pos);
    if (finLigne < 0 || reste.every((o) => o === 0x00 || o === 0x0a)) return fin(true);
    const derniere = finLigne === buf.length - 1;
    let ev;
    try {
      ev = J.analyserJSONStrict(buf.subarray(pos, finLigne));
    } catch {
      return derniere ? fin(true) : fin(false, { seq: prevSeq + 1, raison: "ligne illisible suivie d'autres lignes" });
    }
    const seq = ev?.seq ?? prevSeq + 1;
    if (schemas && J.validerSchema(ev, schemas[J.ID_SCHEMA_EVENEMENT], { registre: schemas }).length) return fin(false, { seq, raison: "ligne hors du schéma d'événement" });
    if (ev.seq !== prevSeq + 1 || ev.prev_hash !== prevHash) return fin(false, { seq, raison: "seq ou prev_hash rompt la chaîne" });
    const recalcule = J.hachageEvenement(ev);
    if (recalcule !== ev.hash) return fin(false, { seq, raison: "hash recalculé différent", hash: ev.hash, recalcule });
    if (cles.size && (ev.recorder_key_id !== cle || !cles.has(cle) || !J.verifierSignatureEvenement(ev, cles.get(cle).public_key))) return fin(false, { seq, raison: "signature invalide ou clé inattendue" });
    evenements.push(ev);
    prevSeq = ev.seq;
    prevHash = ev.hash;
    cle = J.cleSuivanteAttendue(ev);
    pos = finLigne + 1;
  }
  return fin(false);
}

// ---------------------------------------------------------------------------
// Journal d'intention et reprise (CT-2 §12.5)
// ---------------------------------------------------------------------------

/** intent_id (EX-12.12) : « i- », l'époque du bail sur 20 chiffres, « - », le compteur de l'écrivain sur 12 chiffres. */
export const idIntention = (epoch, n) => `i-${String(epoch).padStart(20, "0")}-${String(n).padStart(12, "0")}`;

/** Ligne intention (EX-12.12), neuf clés, JCS intégral, sans \n : `arguments` est la référence complète de la pièce. */
export function ligneIntention({ intent_id, upstream_id, host, written_at, org_id, journal_id, tool, arguments: args, ticket = null }) {
  return J.canonicaliserJCSIntegral({ arguments: args, host, intent_id, journal_id, org_id, ticket, tool, upstream_id, written_at });
}

/** Ligne contexte d'intention (EX-12.12) : l'événement partiel réduit, sans enveloppe ni sortie d'exécution. */
export function ligneContexteIntention(intent_id, partiel) {
  const event = {
    delegation: partiel.delegation,
    code: partiel.code,
    intent: partiel.intent,
    policy: partiel.policy,
    approval: partiel.approval,
    execution: { tool: partiel.execution.tool, arguments: partiel.execution.arguments },
    effects: partiel.effects ?? [],
    context: partiel.context ?? [],
  };
  return J.canonicaliserJCSIntegral({ event, intent_context: intent_id });
}

/** Ligne levée (EX-12.13). */
export const ligneLevee = (intent_id, seq) => J.canonicaliserJCSIntegral({ lifted: intent_id, seq });

/** intention_sha256 (EX-12.14) : SHA-256 de la ligne intention, sans son \n. */
export const empreinteIntention = (ligne) => J.sha256(Buffer.from(ligne, "utf8"));

/**
 * Relit un journal d'intention (texte NDJSON) et rend les intentions dans
 * l'ordre du fichier : [{ intent_id, ligne, objet, contexte (objet event ou
 * null), levee (seq ou null) }], et l'ensemble `leves` des seq désignés par une
 * ligne levée. Seule une dernière ligne illisible est une fin tronquée ; une
 * ligne illisible suivie d'autres lignes est une corruption (EX-12.22) : lève
 * ErreurModeDegrade « stockage ».
 */
export function lireJournalIntention(texte, { avecLeves = false } = {}) {
  const intentions = [];
  const parId = new Map();
  const leves = new Set();
  const lignes = String(texte).split("\n");
  for (let k = 0; k < lignes.length; k++) {
    const ligne = lignes[k];
    if (ligne === "") continue;
    let o;
    try {
      o = analyserJSONIntegral(ligne);
    } catch {
      if (lignes.slice(k + 1).some((l) => l !== "")) throw new ErreurModeDegrade("stockage", `intention_corrompue : ligne ${k + 1} illisible suivie d'autres lignes (EX-12.22)`);
      break; // fin tronquée : le reste n'est pas durable
    }
    if (Object.hasOwn(o, "intent_id")) {
      const it = { intent_id: o.intent_id, ligne, objet: o, contexte: null, levee: null };
      intentions.push(it);
      parId.set(o.intent_id, it);
    } else if (Object.hasOwn(o, "intent_context")) {
      const it = parId.get(o.intent_context);
      if (it) it.contexte = o.event;
    } else if (Object.hasOwn(o, "lifted")) {
      const it = parId.get(o.lifted);
      if (it) it.levee = o.seq;
      if (Number.isInteger(o.seq)) leves.add(o.seq);
    }
  }
  return avecLeves ? { intentions, leves } : intentions;
}

/**
 * Reprise après arrêt (EX-12.13, EX-12.14) : pour chaque intention sans
 * levée, soit un événement durable la lève implicitement (candidats : appels
 * `executee` de même outil, mêmes arguments et même ticket, de ts ≥
 * written_at, ni désignés par une ligne levée ni déjà appariés ; le plus petit
 * seq), soit un événement de reprise est à sceller. Sans ligne contexte,
 * l'événement est reconstruit sans rien fabriquer : `resoudreHote(host)` rend
 * la délégation de configuration de l'entrée (run_id null), la politique en
 * vigueur et la décision sont relues dans `evenementsDurables` ; une donnée
 * introuvable lève ErreurModeDegrade « stockage » (intention_irreconstructible).
 * `resoudreOutil(tool)` rend { alias, original, classe } pour l'effet par
 * défaut ; `nomRedaction` : la politique de rédaction en vigueur. Rend
 * [{ intent_id, implicite: seq } | { intent_id, partiel, piece,
 * intention_sha256, sans_contexte }].
 */
export function reprise(texteIntentions, evenementsDurables, { resoudreOutil, resoudreHote = null, nomRedaction = null } = {}) {
  const { intentions, leves } = lireJournalIntention(texteIntentions, { avecLeves: true });
  const apparies = new Set();
  const durables = [...evenementsDurables].sort((a, b) => a.seq - b.seq);
  const out = [];
  for (const it of intentions) {
    if (it.levee !== null) continue;
    const t = J.msHorodatage(it.objet.written_at);
    const argsRef = it.objet.arguments;
    const durable = durables.find(
      (e) =>
        !apparies.has(e.seq) &&
        !leves.has(e.seq) &&
        e.execution?.status === "executee" &&
        J.msHorodatage(e.ts) >= t &&
        e.execution?.tool === it.objet.tool &&
        e.execution?.arguments?.sha256 === argsRef?.sha256 &&
        (e.policy?.ticket ?? null) === (it.objet.ticket ?? null),
    );
    if (durable) {
      apparies.add(durable.seq);
      out.push({ intent_id: it.intent_id, implicite: durable.seq });
      continue;
    }
    const intention_sha256 = empreinteIntention(it.ligne);
    const piece = pieceReprise(intention_sha256);
    const ctx = it.contexte;
    const outil = resoudreOutil ? resoudreOutil(it.objet.tool) : null;
    const effets = ctx && Array.isArray(ctx.effects) && ctx.effects.length ? ctx.effects : outil ? effetsParDefaut(outil) : [];
    let partiel;
    if (ctx) {
      partiel = {
        delegation: ctx.delegation,
        code: ctx.code,
        intent: ctx.intent,
        policy: { ...ctx.policy, redaction: null },
        approval: ctx.approval,
        execution: { tool: it.objet.tool, arguments: ctx.execution?.arguments ?? argsRef, status: "executee", result: piece.reference, duration_ms: 0, is_error: true },
        effects: effets,
        context: ctx.context ?? [],
      };
    } else {
      const irreconstructible = (quoi) => new ErreurModeDegrade("stockage", `intention_irreconstructible : ${quoi} introuvable pour ${it.intent_id} (EX-12.13)`);
      const delegation = resoudreHote ? resoudreHote(it.objet.host) : null;
      if (!delegation) throw irreconstructible(`l'entrée de connexion d'hôte ${it.objet.host}`);
      if (!argsRef || typeof argsRef !== "object" || !Number.isInteger(argsRef.length)) throw irreconstructible("la référence des arguments");
      const politiques = durables.filter((e) => e.execution?.tool === J.OUTIL_POLITIQUE && J.msHorodatage(e.ts) <= t);
      if (!politiques.length) throw irreconstructible("l'événement de politique en vigueur");
      const policy_version = politiques[politiques.length - 1].code.policy_version;
      let policy = { rule: null, decision: "autorise", ticket: null };
      let approval = null;
      if (it.objet.ticket) {
        const retenue = durables.find((e) => e.execution?.status === "retenue" && e.policy?.ticket === it.objet.ticket);
        const decision = durables.find((e) => e.execution?.tool === J.OUTIL_APPROBATION && e.approval?.ticket === it.objet.ticket);
        if (!retenue || !decision) throw irreconstructible("l'appel retenu ou la décision du ticket");
        policy = { rule: retenue.policy.rule, decision: retenue.policy.decision, ticket: retenue.policy.ticket };
        approval = decision.approval;
      }
      partiel = {
        delegation: { ...delegation, run_id: null },
        code: { model: null, prompt_version: null, policy_version, recorder: VERSION_ENREGISTREUR },
        intent: null,
        policy: { ...policy, redaction: null },
        approval,
        execution: { tool: it.objet.tool, arguments: argsRef, status: "executee", result: piece.reference, duration_ms: 0, is_error: true },
        effects: effets,
        context: [],
      };
    }
    partiel.policy.redaction = redactionDe(ctx?.policy?.redaction ?? nomRedaction, referencesPartiel(partiel));
    out.push({ intent_id: it.intent_id, partiel, piece, intention_sha256, sans_contexte: ctx === null });
  }
  return out;
}
