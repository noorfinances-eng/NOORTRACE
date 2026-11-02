// Extraction et pièces d'un échange de modèle (CT-2 §5.5, 5.3.1 pas 3 et 7,
// EX-5.19 à EX-5.21, EX-5.31, EX-5.33, EX-5.36, §8.2, EX-8.5 à EX-8.7) :
// pièces « prompt système », « requête », « réponse » et « intention »
// dérivées de la requête et de la réponse reçues, `code.model`, `intent`,
// appels d'outils demandés par le modèle (pour la corrélation de 5.6) et
// texte qui précède chacun d'eux.
//
// Les valeurs de l'événement sont tirées de la réponse **rédigée** ; les
// appels d'outils et la décision de corrélation, de la forme en clair, qui
// ne quitte pas la mémoire (5.6).

import { Piece, pieceJson, pieceTexte, pieceNonRedigeable, typeMediaNormalise } from "../pieces.mjs";
import { formeAttendue, porteusesPrompt, estTypeJson, typeMedia } from "./formats.mjs";
import { analyserJsonStrict } from "./flux.mjs";

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const DECODEUR_STRICT = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Borne d'une intention en ligne, en caractères (EX-5.21, CT-1 §5.3). */
export const LONGUEUR_INTENTION_MAX = 4096;
/** Borne de `code.model` (EX-5.19). */
export const MODELE_MAX = 256;

/**
 * Rédacteur de repli, sans règle (aucun rédacteur configuré) : pièces telles
 * quelles, de la forme de §8.
 */
export const SANS_REDACTION = Object.freeze({
  async redigerPiece(d) {
    if (d.genre === "texte") return { piece: pieceTexte(d.texte), valeur: d.texte, redacted: d.origine !== undefined && d.origine !== d.texte, non_redigeable: null };
    if (d.genre === "octets") return { piece: new Piece(d.octets, { redacted: false, media_type: typeMediaNormalise(d.content_type) }), redacted: false, non_redigeable: null };
    const redacted = d.origine !== undefined;
    return { piece: pieceJson(d.valeur, { redacted }), valeur: d.valeur, redacted, non_redigeable: null };
  },
});

// ------------------------------------------------------------ pièces de la requête (5.3.1 pas 3, EX-8.5, EX-8.6)

/**
 * Pièces « prompt système » et « requête » (5.3.1 pas 3) d'un corps analysé.
 * @param {object} p
 * @param {string} p.format
 * @param {unknown} p.valeur corps analysé en JSON strict
 * @param {"reference"|"inline"} p.prompt_in_request
 * @param {"redige"|"named"} p.prompt_system
 * @param {string|null} [p.nomPrompt] nom de version du prompt (EX-8.6, `named`)
 * @param {object} p.redacteur `redigerPiece(demande, ctx)` (INTERFACES.md, section e)
 * @param {object} [p.ctx] contexte de consignation (id, host)
 * @returns {Promise<{attendue: boolean, prompt: Piece|null, requete: Piece, requeteRedigee: unknown, nonRedigeable: string|null}>}
 */
export async function piecesRequete(p) {
  const r = p.redacteur ?? SANS_REDACTION;
  const ctx = p.ctx ?? {};
  const attendue = formeAttendue(p.format, p.valeur);
  if (!attendue) {
    const req = await r.redigerPiece({ genre: "json", portee: "requete", valeur: p.valeur, avecValeur: true }, ctx);
    return { attendue, prompt: null, requete: req.piece, requeteRedigee: req.valeur, nonRedigeable: req.non_redigeable ?? null };
  }
  const copie = structuredClone(p.valeur);
  const { porteuses, remplacer } = porteusesPrompt(p.format, copie);
  const avecPrompt = porteuses.length > 0 || (p.format === "gemini" && estObjet(copie.systemInstruction) && Array.isArray(copie.systemInstruction.parts));
  let prompt = null;
  if (avecPrompt) {
    const texte = porteuses.map((x) => x.texte).join("\n");
    if (p.prompt_system === "named" && typeof p.nomPrompt === "string") {
      // Identifiant de version nommé (EX-8.6) : aucune empreinte du clair.
      prompt = pieceTexte(`[PROMPT:${p.nomPrompt}]`, { redacted: true });
    } else {
      prompt = (await r.redigerPiece({ genre: "texte", portee: "prompt_systeme", texte }, ctx)).piece;
    }
    if (p.prompt_in_request === "inline") {
      // Chaque chaîne porteuse rédigée seule (la chaîne est la racine), avant la portée requete.
      for (const x of porteuses) {
        const rx = await r.redigerPiece({ genre: "texte", portee: "prompt_systeme", texte: x.texte, avecValeur: true }, ctx);
        if (typeof rx.valeur === "string") x.poser(rx.valeur);
      }
    } else {
      remplacer();
    }
  }
  const req = await r.redigerPiece({ genre: "json", portee: "requete", valeur: copie, origine: p.valeur, avecValeur: true }, ctx);
  return { attendue, prompt, requete: req.piece, requeteRedigee: req.valeur, nonRedigeable: req.non_redigeable ?? null };
}

// ------------------------------------------------------------ pièce de la réponse (5.3.1 pas 5 et 7, EX-5.31, EX-5.33)

/**
 * Valeur du membre `body` de `noortrace_http_error` (5.3.1 pas 7, EX-5.31).
 * @param {{format: string, contentType: string|null, corps: Uint8Array, bornes?: object, codageInconnu?: boolean}} p
 */
export function corpsErreurHttp(p) {
  if (p.codageInconnu) return { noortrace_non_redigeable: { content_type: p.contentType ?? null, length: p.corps.length, reason: "codage_inconnu" } };
  if (p.corps.length === 0) return null;
  let texte = null;
  try {
    texte = DECODEUR_STRICT.decode(p.corps);
  } catch {
    texte = null;
  }
  if (texte !== null && (p.format === "gemini" || estTypeJson(typeMedia(p.contentType)))) {
    const sansBom = texte.charCodeAt(0) === 0xfeff ? null : texte;
    if (sansBom !== null) {
      const a = analyserJsonStrict(sansBom, p.bornes);
      if (a.ok) return a.valeur;
    }
  }
  if (texte !== null) return texte;
  return { noortrace_non_redigeable: { content_type: p.contentType ?? null, length: p.corps.length, reason: "non_utf8" } };
}

/**
 * Analyse JSON stricte d'un corps reçu (5.3.1 pas 5) : UTF-8 strict, sans
 * marque d'ordre d'octets.
 * @param {Uint8Array} corps
 * @param {object} [bornes]
 * @returns {{ok: true, valeur: unknown}|{ok: false}}
 */
export function analyserCorpsJson(corps, bornes) {
  let texte;
  try {
    texte = DECODEUR_STRICT.decode(corps);
  } catch {
    return { ok: false };
  }
  if (texte.charCodeAt(0) === 0xfeff) return { ok: false };
  return analyserJsonStrict(texte, bornes);
}

/**
 * Pièce « réponse » d'un échange (5.3.1 pas 7, EX-5.11 (d), EX-5.31,
 * EX-5.33, EX-8.7) et la forme en clair qui sert aux appels d'outils.
 * @param {object} p
 * @param {string} p.format
 * @param {number} p.statut statut HTTP amont
 * @param {string|null} p.contentType `Content-Type` reçu
 * @param {Uint8Array} p.corps corps reçu (décomprimé), dans la borne
 * @param {boolean} [p.flux] corps lu par l'analyseur SSE (statut 2xx, `text/event-stream`)
 * @param {{forme: object|null, incomplet: boolean, is_error: boolean}|null} [p.consolidee] forme close
 * @param {number|null} [p.tronque] octets reçus en tout quand la borne d'EX-5.33 a été atteinte
 * @param {boolean} [p.codageInconnu] codage de contenu inconnu ou décompression en échec (EX-5.9)
 * @param {object} [p.bornes] bornes de l'analyse JSON (4.4 pas 1)
 * @param {{ok: boolean, valeur?: unknown}} [p.analyse] analyse déjà faite d'un corps JSON hors flux
 * @param {object} p.redacteur
 * @param {object} [p.ctx]
 * @returns {Promise<{piece: Piece, valeurRedigee: unknown, formeClair: unknown, is_error: boolean, incomplet: boolean}>}
 */
export async function pieceReponse(p) {
  const r = p.redacteur ?? SANS_REDACTION;
  const ctx = p.ctx ?? {};
  const json = async (valeur) => r.redigerPiece({ genre: "json", portee: "reponse", valeur, avecValeur: true }, ctx);
  const octets = async () => r.redigerPiece({ genre: "octets", portee: "reponse", octets: p.corps, content_type: p.contentType ?? null, codage_inconnu: p.codageInconnu === true }, ctx);
  const deuxCent = p.statut >= 200 && p.statut < 300;
  if (!deuxCent) {
    // Statut d'erreur : objet noortrace_http_error (5.3.1 pas 7) ; au-delà de la borne, forme taille.
    if (p.tronque !== null && p.tronque !== undefined) {
      return { piece: pieceNonRedigeable({ content_type: p.contentType ?? null, length: p.tronque, reason: "taille" }), valeurRedigee: undefined, formeClair: null, is_error: true, incomplet: false };
    }
    const body = corpsErreurHttp(p);
    const v = { noortrace_http_error: { status: p.statut, content_type: p.contentType ?? null, body } };
    const x = await json(v);
    return { piece: x.piece, valeurRedigee: x.valeur, formeClair: v, is_error: true, incomplet: false };
  }
  if (p.flux) {
    const c = p.consolidee;
    if (c && c.forme !== null) {
      const x = await json(c.forme);
      return { piece: x.piece, valeurRedigee: x.valeur, formeClair: c.forme, is_error: c.is_error, incomplet: c.incomplet };
    }
    // Aucune forme : flux brut (EX-8.7, EX-5.35 pas 7).
    const x = await octets();
    return { piece: x.piece, valeurRedigee: undefined, formeClair: null, is_error: true, incomplet: true };
  }
  if (p.tronque !== null && p.tronque !== undefined) {
    return { piece: pieceNonRedigeable({ content_type: p.contentType ?? null, length: p.tronque, reason: "taille" }), valeurRedigee: undefined, formeClair: null, is_error: true, incomplet: false };
  }
  if (!p.codageInconnu && estTypeJson(typeMedia(p.contentType))) {
    const a = p.analyse ?? analyserCorpsJson(p.corps, p.bornes);
    if (a.ok) {
      const x = await json(a.valeur);
      return { piece: x.piece, valeurRedigee: x.valeur, formeClair: a.valeur, is_error: false, incomplet: false };
    }
  }
  // Corps non JSON, ou déclaré JSON qui ne s'analyse pas (EX-8.7).
  const x = await octets();
  return { piece: x.piece, valeurRedigee: undefined, formeClair: null, is_error: true, incomplet: false };
}

// ------------------------------------------------------------ valeurs (5.5, EX-5.19, EX-5.21, EX-5.36)

/** Tronque une chaîne à n points de code. */
function tronquer(s, n) {
  const pts = [...s];
  return pts.length > n ? pts.slice(0, n).join("") : s;
}

/**
 * `code.model` (5.5, EX-5.19, EX-5.36) : `<libellé>/` suivi du modèle de la
 * réponse rédigée, à défaut de celui de la requête rédigée de forme attendue
 * (Gemini : segment de modèle admis) ; null sinon.
 * @param {{format: string, label: string, reponseRedigee: unknown, requeteRedigee: unknown, attendue: boolean, segment?: string|null}} p
 * @returns {string|null}
 */
export function modeleDe(p) {
  let m = null;
  if (p.format === "gemini") {
    const v = estObjet(p.reponseRedigee) ? p.reponseRedigee.modelVersion : undefined;
    m = typeof v === "string" && v !== "" ? v : p.segment ?? null;
  } else {
    const v = estObjet(p.reponseRedigee) ? p.reponseRedigee.model : undefined;
    if (typeof v === "string" && v !== "") m = v;
    else if (p.attendue && estObjet(p.requeteRedigee) && typeof p.requeteRedigee.model === "string" && p.requeteRedigee.model !== "") m = p.requeteRedigee.model;
  }
  return m === null ? null : tronquer(`${p.label}/${m}`, MODELE_MAX);
}

function textesAnthropic(forme, avant) {
  if (!estObjet(forme) || !Array.isArray(forme.content)) return [];
  const t = [];
  forme.content.forEach((b, i) => {
    if (i < avant && estObjet(b) && b.type === "text" && typeof b.text === "string") t.push(b.text);
  });
  return t;
}

function textesResponses(forme, avant) {
  if (!estObjet(forme) || !Array.isArray(forme.output)) return [];
  const t = [];
  forme.output.forEach((it, i) => {
    if (i >= avant || !estObjet(it) || it.type !== "message" || !Array.isArray(it.content)) return;
    for (const c of it.content) if (estObjet(c) && c.type === "output_text" && typeof c.text === "string") t.push(c.text);
  });
  return t;
}

function partsGemini(forme) {
  const c = estObjet(forme) && Array.isArray(forme.candidates) ? forme.candidates[0] : undefined;
  return estObjet(c) && estObjet(c.content) && Array.isArray(c.content.parts) ? c.content.parts : [];
}

function texteGemini(forme, avant) {
  let s = "";
  partsGemini(forme).forEach((p, i) => {
    if (i < avant && estObjet(p) && p.thought !== true && typeof p.text === "string") s += p.text;
  });
  return s;
}

function contenuChat(forme) {
  const c = estObjet(forme) && Array.isArray(forme.choices) ? forme.choices[0] : undefined;
  const m = estObjet(c) ? c.message : undefined;
  return estObjet(m) && typeof m.content === "string" ? m.content : null;
}

const videNul = (s) => (s === null || s === "" ? null : s);

/**
 * Texte de l'assistant (table de 5.5) ; un texte vide vaut null.
 * @param {string} format
 * @param {unknown} forme réponse ou forme consolidée
 * @returns {string|null}
 */
export function intentionDe(format, forme) {
  switch (format) {
    case "anthropic-messages":
      return videNul(textesAnthropic(forme, Infinity).join("\n"));
    case "openai-chat":
      return videNul(contenuChat(forme));
    case "openai-responses":
      return videNul(textesResponses(forme, Infinity).join("\n"));
    case "gemini":
      return videNul(texteGemini(forme, Infinity));
    default:
      return null;
  }
}

/**
 * Appels d'outils demandés par le modèle (table de 5.5), dans l'ordre, avec
 * leur position (bloc, item, appel ou part).
 * @param {string} format
 * @param {unknown} forme forme en clair
 * @returns {{id: unknown, name: unknown, arguments: unknown, position: number}[]}
 */
export function appelsDemandes(format, forme) {
  const sortie = [];
  if (format === "anthropic-messages") {
    if (estObjet(forme) && Array.isArray(forme.content)) {
      forme.content.forEach((b, i) => {
        if (estObjet(b) && b.type === "tool_use") sortie.push({ id: b.id ?? null, name: b.name ?? null, arguments: b.input, position: i });
      });
    }
  } else if (format === "openai-chat") {
    const c = estObjet(forme) && Array.isArray(forme.choices) ? forme.choices[0] : undefined;
    const tcs = estObjet(c) && estObjet(c.message) && Array.isArray(c.message.tool_calls) ? c.message.tool_calls : [];
    tcs.forEach((tc, i) => {
      if (estObjet(tc)) sortie.push({ id: tc.id ?? null, name: estObjet(tc.function) ? tc.function.name ?? null : null, arguments: estObjet(tc.function) ? tc.function.arguments : undefined, position: i });
    });
  } else if (format === "openai-responses") {
    if (estObjet(forme) && Array.isArray(forme.output)) {
      forme.output.forEach((it, i) => {
        if (estObjet(it) && it.type === "function_call") sortie.push({ id: it.call_id ?? null, name: it.name ?? null, arguments: it.arguments, position: i });
      });
    }
  } else if (format === "gemini") {
    partsGemini(forme).forEach((p, i) => {
      if (!estObjet(p) || !estObjet(p.functionCall)) return;
      const f = p.functionCall;
      sortie.push({ id: typeof f.id === "string" ? f.id : null, name: f.name ?? null, arguments: "args" in f ? f.args : {}, position: i });
    });
  }
  return sortie;
}

/**
 * Texte de l'assistant qui précède un appel demandé (5.6).
 * @param {string} format
 * @param {unknown} forme
 * @param {number} position
 * @returns {string|null}
 */
export function intentionAvant(format, forme, position) {
  switch (format) {
    case "anthropic-messages":
      return videNul(textesAnthropic(forme, position).join("\n"));
    case "openai-chat":
      return videNul(contenuChat(forme));
    case "openai-responses":
      return videNul(textesResponses(forme, position).join("\n"));
    case "gemini":
      return videNul(texteGemini(forme, position));
    default:
      return null;
  }
}

/**
 * Arguments d'un appel demandé, en valeur comparable (EX-5.22 point 2) ;
 * undefined s'ils ne correspondent jamais.
 * @param {string} format
 * @param {unknown} args
 */
export function argumentsComparables(format, args) {
  if (format === "openai-chat" || format === "openai-responses") {
    if (typeof args !== "string") return undefined;
    const a = analyserJsonStrict(args);
    return a.ok ? a.valeur : undefined;
  }
  if (format === "gemini") return estObjet(args) ? args : undefined;
  return args;
}

/**
 * Intention bornée (EX-5.21) : la chaîne rédigée si elle a au plus 4096
 * caractères et égale le texte en clair ; sinon une pièce `text/plain`,
 * `redacted` si une règle l'a modifiée.
 * @param {string|null} redige texte tiré de la réponse rédigée
 * @param {string|null} clair texte tiré de la réponse en clair
 * @returns {{intent: string|object|null, piece: Piece|null}}
 */
export function intentionBornee(redige, clair) {
  if (redige === null) return { intent: null, piece: null };
  const differe = redige !== clair;
  if (!differe && [...redige].length <= LONGUEUR_INTENTION_MAX) return { intent: redige, piece: null };
  const piece = pieceTexte(redige, { redacted: differe });
  return { intent: piece.reference, piece };
}
