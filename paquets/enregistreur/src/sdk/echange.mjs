// Échange de modèle déclaré par le SDK (`noortrace/sdk/echangeModele`, CT-2
// table de 6.2, EX-6.8, EX-7.7) : pièces « prompt système », « requête »,
// « réponse » et « intention », `code.model`, `intent`, `is_error`, à partir
// de la requête et de la réponse que l'agent déclare. Le SDK ne déclare que
// des valeurs JSON : il n'y a ni corps HTTP, ni flux SSE, ni chaîne de requête
// (le démon n'a rien vu passer, 6.3). La dérivation reprend celle du frontal
// modèle (`src/modele/extraction.mjs`, `flux.mjs`), sans la changer :
//
//   - format v0 (`anthropic-messages`, `openai-chat`, `openai-responses`) :
//     5.3.1 pas 3 (pièces de la requête), réponse JSON rédigée par la portée
//     `reponse`, extraction de 5.5 ;
//   - `gemini` (EX-6.8) : membres ajoutés par le SDK Python retirés et
//     consignés, `mcpServers` et `cachedContent` consignés sans refus, réponse
//     objet ou tableau de morceaux consolidé par EX-5.35, `status ≥ 400` :
//     `noortrace_http_error`, `is_error` déclaré OU calculé, `code.model` de
//     `modelVersion`, à défaut de `request.model` admis (EX-5.28, EX-5.36) ;
//   - `autre` : `code.model = provider_label + "/" + request.model` si présent,
//     `intent` et `prompt_version` nuls.

import { piecesRequete, modeleDe, intentionDe, intentionBornee, SANS_REDACTION, MODELE_MAX } from "../modele/extraction.mjs";
import { consoliderMorceauxGemini, CLE_INCOMPLET, CLE_ERREUR_FLUX } from "../modele/flux.mjs";
import { declarationsFournisseur, MOTIF_SEGMENT } from "../modele/formats.mjs";

/** Membres que le SDK Python ajoute à ses objets de réponse (EX-6.8 point 3). */
export const MEMBRES_SDK_RETIRES = Object.freeze(["sdkHttpResponse", "automaticFunctionCallingHistory", "parsed"]);

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

function tronquer(s, n) {
  const pts = [...s];
  return pts.length > n ? pts.slice(0, n).join("") : s;
}

/**
 * Retire les membres du SDK Python d'un objet de premier niveau (EX-6.8 point 3).
 * @param {object} o
 * @param {(nom: string) => void} noter
 * @returns {object}
 */
function sansMembresSdk(o, noter) {
  if (!estObjet(o)) return o;
  let copie = o;
  for (const m of MEMBRES_SDK_RETIRES) {
    if (Object.prototype.hasOwnProperty.call(o, m)) {
      if (copie === o) copie = { ...o };
      delete copie[m];
      noter(m);
    }
  }
  return copie;
}

/**
 * Dérive un échange déclaré par le SDK.
 * @param {object} p
 * @param {"anthropic-messages"|"openai-chat"|"openai-responses"|"gemini"|"autre"} p.format
 * @param {string} p.provider_label
 * @param {unknown} p.request
 * @param {unknown} p.response
 * @param {number|null} p.status
 * @param {boolean} p.is_error déclaré
 * @param {{prompt_in_request: string, prompt_system: string}} p.model `model` de la configuration
 * @param {string|null} p.nomPrompt nom de version du prompt (EX-8.6, `named`)
 * @param {object|null} p.redacteur rédacteur (section e)
 * @param {(v: string) => Promise<boolean>} [p.admettreValeurLigne] détecteurs de texte (EX-5.36)
 * @param {(evenement: string, data: object) => void} p.consigner journal d'exploitation
 * @param {object} [p.ctx] contexte de consignation de la rédaction
 * @returns {Promise<{pieces: import("../pieces.mjs").Piece[], requete: object, reponse: object, prompt: object|null,
 *   intention: object|null, code: {model: string|null, prompt_version: string|null}, intent: unknown, is_error: boolean,
 *   formeClair: unknown, formeRedigee: unknown, retires: string[]}>}
 */
export async function deriverEchangeSdk(p) {
  const r = p.redacteur ?? SANS_REDACTION;
  const ctx = p.ctx ?? {};
  const retires = [];
  let request = p.request;
  let response = p.response;
  let calculeErreur = false;
  let formeClair = null;

  if (p.format === "gemini") {
    // EX-6.8 point 3 : avant tout traitement.
    const noter = (m) => {
      retires.push(m);
      p.consigner("sdk_member_removed", { member: m });
    };
    response = Array.isArray(response) ? response.map((x) => sansMembresSdk(x, noter)) : sansMembresSdk(response, noter);
    // EX-6.8 point 1 : déclarations au fournisseur consignées, jamais refusées.
    const d = declarationsFournisseur(request);
    if (d.mcp > 0) p.consigner("provider_mcp_bypass", { entries: d.mcp, via: "sdk" });
    if (d.cache) p.consigner("provider_cache_reference", { via: "sdk" });
  }

  // Pièces de la requête (5.3.1 pas 3 ; EX-6.8 point 1 pour gemini) ; `autre` : la valeur rédigée seule.
  let pr;
  if (p.format === "autre") {
    const x = await r.redigerPiece({ genre: "json", portee: "requete", valeur: request, avecValeur: true }, ctx);
    pr = { attendue: false, prompt: null, requete: x.piece, requeteRedigee: x.valeur };
  } else {
    pr = await piecesRequete({
      format: p.format,
      valeur: request,
      prompt_in_request: p.model.prompt_in_request,
      prompt_system: p.model.prompt_system,
      nomPrompt: p.model.prompt_system === "named" ? p.nomPrompt : null,
      redacteur: r,
      ctx,
    });
  }

  // Valeur de la pièce « réponse ».
  let valeurReponse = response;
  if (p.format === "gemini") {
    if (p.status !== null && p.status >= 400) {
      // EX-6.8 point 4 : objet noortrace_http_error, content_type null, body = response.
      valeurReponse = { noortrace_http_error: { status: p.status, content_type: null, body: response } };
      calculeErreur = true;
      formeClair = null;
    } else if (Array.isArray(response)) {
      // EX-6.8 point 2 : morceaux d'un flux consolidés par EX-5.35 ; fin du tableau = fin normale.
      const c = consoliderMorceauxGemini(response);
      valeurReponse = c.forme;
      formeClair = c.forme;
      if (c.is_error || c.incomplet || (estObjet(c.forme) && (CLE_INCOMPLET in c.forme || CLE_ERREUR_FLUX in c.forme))) calculeErreur = true;
    } else {
      formeClair = response;
    }
  } else {
    formeClair = response;
  }
  const rep = await r.redigerPiece({ genre: "json", portee: "reponse", valeur: valeurReponse, avecValeur: true }, ctx);
  const reponseRedigee = rep.non_redigeable ? undefined : rep.valeur;

  // code.model.
  let model = null;
  if (p.format === "autre") {
    const m = estObjet(pr.requeteRedigee) ? pr.requeteRedigee.model : undefined;
    model = typeof m === "string" && m !== "" ? tronquer(`${p.provider_label}/${m}`, MODELE_MAX) : null;
  } else if (p.format === "gemini") {
    // EX-6.8 point 5 : modelVersion de la réponse rédigée, sinon request.model admis.
    let segment = null;
    const rm = estObjet(pr.requeteRedigee) ? pr.requeteRedigee.model : undefined;
    if (typeof rm === "string") {
      const s = rm.startsWith("models/") ? rm.slice("models/".length) : rm;
      if (MOTIF_SEGMENT.test(s) && (p.admettreValeurLigne ? await p.admettreValeurLigne(s) : true)) segment = s;
    }
    model = modeleDe({ format: "gemini", label: p.provider_label, reponseRedigee, requeteRedigee: pr.requeteRedigee, attendue: pr.attendue, segment });
  } else {
    model = modeleDe({ format: p.format, label: p.provider_label, reponseRedigee, requeteRedigee: pr.requeteRedigee, attendue: pr.attendue });
  }

  // intent (5.5, EX-5.21) ; `autre` : null.
  let ib = { intent: null, piece: null };
  if (p.format !== "autre" && formeClair !== null) {
    const redige = reponseRedigee === undefined ? null : intentionDe(p.format, reponseRedigee);
    ib = intentionBornee(redige, intentionDe(p.format, formeClair));
  }
  const prompt_version = p.format === "autre" ? null : pr.prompt?.sha256 ?? null;
  const pieces = [pr.prompt, pr.requete, rep.piece, ib.piece].filter(Boolean);
  return {
    pieces,
    requete: pr.requete.reference,
    reponse: rep.piece.reference,
    prompt: pr.prompt,
    intention: ib.piece,
    code: { model, prompt_version },
    intent: ib.intent,
    is_error: p.is_error === true || calculeErreur,
    formeClair,
    formeRedigee: reponseRedigee,
    retires,
  };
}
