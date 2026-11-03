// Projection d'un span retenu sur un événement de CT-1 (CT-2 EX-6.35,
// EX-6.36, EX-7.7) : pièces rédigées (déclaration de source, requête ou
// arguments, réponse ou résultat, prompt système, intention, enveloppe),
// puis l'événement partiel (sorte inférence : `noortrace.modele.echange` ;
// sorte outil : `<alias>__<N>`), sans aucune valeur ni clé nouvelle de CT-1.
// Les horodatages du span ne servent qu'à `duration_ms` et restent dans la
// pièce d'enveloppe ; `ts` est fixé par l'écrivain (EX-6.36).

import { pieceTexte, pieceJson, pieceNonRedigeable, pieceDeclarationSource } from "../pieces.mjs";
import { partielAppelOutil, partielEchange } from "../capture.mjs";
import { evaluerEffets } from "../effets.mjs";
import { jcsIntegralOctets } from "../jcs-integral.mjs";
import { utf8 } from "@noortrace/noyau";
import { intentionBornee, SANS_REDACTION } from "../modele/extraction.mjs";
import { JETON_PROMPT as JETON_PROMPT_SYSTEME } from "../modele/formats.mjs";

/** Marque d'un attribut de contenu absent (EX-6.35). */
export const CLE_ABSENT = "noortrace_otel_absent";

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

function poser(o, k, v) {
  Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
}

function tronquer(s, n) {
  const pts = [...s];
  return pts.length > n ? pts.slice(0, n).join("") : s;
}

/** Attributs de OUT (EX-6.35, sorte inférence). */
export function estSortie(cle) {
  return cle === "gen_ai.output.messages" || cle === "gen_ai.completion" || cle.startsWith("gen_ai.response.") || cle.startsWith("gen_ai.usage.");
}

/**
 * Nom déclaré N d'un span d'outil et nom de l'outil de l'événement (EX-6.35).
 * @param {object} N forme normalisée
 * @param {string} alias alias de la source
 * @returns {{N: string, valide: boolean, outil: string}}
 */
export function nomOutilSpan(N, alias) {
  const a = N.attributes;
  let n = "";
  if (typeof a["gen_ai.tool.name"] === "string" && a["gen_ai.tool.name"] !== "") n = a["gen_ai.tool.name"];
  else if (N.name.startsWith("execute_tool ")) n = N.name.slice("execute_tool ".length);
  else if (N.name.startsWith("tools/call ")) n = N.name.slice("tools/call ".length);
  const complet = `${alias}__${n}`;
  const valide = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/.test(n) && !n.includes("__") && !n.startsWith("noortrace.") && complet.length <= 128;
  return { N: n, valide, outil: valide ? complet : `${alias}__nom-invalide` };
}

/**
 * Texte du prompt système T (EX-6.35) et ses chaînes porteuses dans Req.
 * @param {object} req copie de Req
 * @returns {{textes: string[], porteuses: {lire: () => string, poser: (s: string) => void}[]}}
 */
function porteusesPrompt(req) {
  const textes = [];
  const porteuses = [];
  const si = req["gen_ai.system_instructions"];
  if (typeof si === "string") {
    textes.push(si);
    porteuses.push({ lire: () => req["gen_ai.system_instructions"], poser: (s) => (req["gen_ai.system_instructions"] = s) });
  } else if (Array.isArray(si)) {
    for (const e of si) {
      if (estObjet(e) && e.type === "text" && typeof e.content === "string") {
        textes.push(e.content);
        porteuses.push({ lire: () => e.content, poser: (s) => (e.content = s) });
      }
    }
  }
  const msgs = req["gen_ai.input.messages"];
  if (Array.isArray(msgs)) {
    for (const m of msgs) {
      if (!estObjet(m) || m.role !== "system" || !Array.isArray(m.parts)) continue;
      for (const p of m.parts) {
        if (estObjet(p) && p.type === "text" && typeof p.content === "string") {
          textes.push(p.content);
          porteuses.push({ lire: () => p.content, poser: (s) => (p.content = s), message: true });
        }
      }
    }
  }
  return { textes, porteuses };
}

/** Projection textuelle de l'enveloppe (membres textuels d'EX-6.35, pointeurs gardés). */
function projectionTextuelle(env) {
  return {
    name: env.name,
    trace_state: env.trace_state,
    attributes: env.attributes,
    events: env.events.map((e) => ({ name: e.name, attributes: e.attributes })),
    status: { message: env.status.message },
    resource: { attributes: env.resource.attributes },
    scope: { name: env.scope.name, version: env.scope.version, attributes: env.scope.attributes },
    schema_url: env.schema_url,
  };
}

/** Remet les membres textuels rédigés dans l'enveloppe ; les membres structurels restent tels quels. */
function fusionnerTextuels(env, v) {
  const prendre = (cible, cle, source) => {
    if (estObjet(source) && own(source, cle)) poser(cible, cle, source[cle]);
    else delete cible[cle];
  };
  const r = structuredClone(env);
  for (const k of ["name", "trace_state", "attributes", "schema_url"]) prendre(r, k, v);
  r.events = env.events.map((e, i) => {
    const x = structuredClone(e);
    const ve = Array.isArray(v?.events) ? v.events[i] : undefined;
    prendre(x, "name", ve);
    prendre(x, "attributes", ve);
    return x;
  });
  prendre(r.status, "message", v?.status);
  prendre(r.resource, "attributes", v?.resource);
  for (const k of ["name", "version", "attributes"]) prendre(r.scope, k, v?.scope);
  return r;
}

/**
 * Projette un span retenu (EX-6.35, EX-6.36).
 * @param {object} p
 * @param {object} p.N forme normalisée
 * @param {"inference"|"outil"} p.sorte
 * @param {string} p.alias alias de la source
 * @param {object} p.hote entrée de `otel.hosts`
 * @param {object} p.source entrée de `policy.otel.sources`
 * @param {{prompt_in_request: string, prompt_system: string}} p.model `model` de la configuration
 * @param {number} p.pieceMax `limits.piece_max_bytes`
 * @param {object|null} p.redacteur rédacteur (section e)
 * @param {object} [p.ctx] contexte de consignation
 * @returns {Promise<object>} projection : pièces, références, valeurs rédigées, M, N
 */
export async function projeterSpan(p) {
  const r = p.redacteur ?? SANS_REDACTION;
  const ctx = p.ctx ?? {};
  const N = p.N;
  const trop = [];
  // Borne de `limits.piece_max_bytes` (EX-6.35) : forme `taille`, longueur du JCS intégral de la valeur en clair.
  const borner = (nom, piece, longueurClair) => {
    if (piece.octets.length <= p.pieceMax) return piece;
    trop.push({ piece: nom, length: longueurClair });
    return pieceNonRedigeable({ content_type: null, length: longueurClair, reason: "taille" });
  };
  const json = async (portee, valeur, outil, extra = {}) => {
    const x = await r.redigerPiece({ genre: "json", portee, outil, alias: outil ? p.alias : null, valeur, avecValeur: true, ...extra }, ctx);
    return { piece: x.piece, valeur: x.non_redigeable ? undefined : x.valeur, nonRedigeable: x.non_redigeable ?? null };
  };
  const enveloppe = async (env, outil) => {
    const clair = jcsIntegralOctets(env).length;
    const x = await r.redigerPiece({ genre: "json", portee: "contexte", outil, alias: outil ? p.alias : null, valeur: projectionTextuelle(env), avecValeur: true }, ctx);
    let piece;
    if (x.non_redigeable) piece = pieceNonRedigeable({ content_type: null, length: clair, reason: "budget_redaction" });
    else piece = pieceJson(fusionnerTextuels(env, x.valeur), { redacted: x.redacted === true, media_type: "application/json" });
    return borner("envelope", piece, clair);
  };

  const source = pieceDeclarationSource("otel", p.alias);
  const sortie = { sorte: p.sorte, source, trop, prompt: null, intention: null };

  if (p.sorte === "inference") {
    const req = {};
    const resp = {};
    for (const [k, v] of Object.entries(N.attributes)) {
      if (!k.startsWith("gen_ai.")) continue;
      poser(estSortie(k) ? resp : req, k, v);
    }
    // Prompt système (EX-6.35, 8.2, EX-8.6).
    const copie = structuredClone(req);
    const { textes, porteuses } = porteusesPrompt(copie);
    if (textes.length) {
      const T = textes.join("\n");
      let piece;
      if (p.model.prompt_system === "named" && typeof p.hote.prompt_version_name === "string") piece = pieceTexte(`[PROMPT:${p.hote.prompt_version_name}]`, { redacted: true });
      else piece = (await r.redigerPiece({ genre: "texte", portee: "prompt_systeme", texte: T }, ctx)).piece;
      sortie.prompt = borner("system_prompt", piece, utf8(T).length);
    }
    if (p.model.prompt_in_request === "inline") {
      for (const x of porteuses) {
        const y = await r.redigerPiece({ genre: "texte", portee: "prompt_systeme", texte: x.lire(), avecValeur: true }, ctx);
        if (typeof y.valeur === "string") x.poser(y.valeur);
      }
    } else {
      if (own(copie, "gen_ai.system_instructions")) copie["gen_ai.system_instructions"] = JETON_PROMPT_SYSTEME;
      for (const x of porteuses) if (x.message) x.poser(JETON_PROMPT_SYSTEME);
    }
    // EX-10.16 : comparaison avec Req reçu quand le prompt y a été remplacé ou rédigé en place (EX-8.5).
    const change = jcsIntegralOctets(copie).length !== jcsIntegralOctets(req).length || Buffer.compare(Buffer.from(jcsIntegralOctets(copie)), Buffer.from(jcsIntegralOctets(req))) !== 0;
    const rq = await json("requete", copie, null, change ? { origine: req } : {});
    const rp = await json("reponse", resp, null);
    sortie.requete = borner("request", rq.piece, jcsIntegralOctets(req).length);
    sortie.reponse = borner("response", rp.piece, jcsIntegralOctets(resp).length);
    sortie.requeteRedigee = rq.valeur;
    sortie.reponseRedigee = rp.valeur;
    // M et fournisseur (EX-6.36), tirés des pièces rédigées.
    const rr = estObjet(rp.valeur) ? rp.valeur : {};
    const qr = estObjet(rq.valeur) ? rq.valeur : {};
    let M = null;
    if (typeof rr["gen_ai.response.model"] === "string" && rr["gen_ai.response.model"] !== "") M = rr["gen_ai.response.model"];
    else if (typeof qr["gen_ai.request.model"] === "string" && qr["gen_ai.request.model"] !== "") M = qr["gen_ai.request.model"];
    const f = typeof qr["gen_ai.provider.name"] === "string" ? qr["gen_ai.provider.name"] : typeof qr["gen_ai.system"] === "string" ? qr["gen_ai.system"] : null;
    const fournisseur = f !== null && /^[a-z0-9][a-z0-9._-]{0,31}$/.test(f) ? f : "inconnu";
    sortie.M = M;
    sortie.model = M === null ? null : tronquer(`${fournisseur}/${M}`, 256);
    sortie.prompt_version = sortie.prompt ? sortie.prompt.sha256 : null;
    // intent (EX-6.36, EX-5.21) : premier élément de gen_ai.output.messages, parts `text`.
    const texteDe = (o) => {
      const msgs = estObjet(o) ? o["gen_ai.output.messages"] : undefined;
      const premier = Array.isArray(msgs) ? msgs[0] : undefined;
      if (!estObjet(premier) || !Array.isArray(premier.parts)) return null;
      const t = premier.parts.filter((x) => estObjet(x) && x.type === "text" && typeof x.content === "string").map((x) => x.content);
      return t.length ? t.join("\n") : null;
    };
    const redige = rp.valeur === undefined ? null : texteDe(rp.valeur);
    const ib = intentionBornee(redige === "" ? null : redige, texteDe(resp));
    sortie.intent = ib.intent;
    sortie.intention = ib.piece;
    const env = structuredClone(N);
    env.attributes = {};
    for (const [k, v] of Object.entries(N.attributes)) if (!k.startsWith("gen_ai.")) poser(env.attributes, k, v);
    sortie.enveloppe = await enveloppe(env, null);
    sortie.outil = "noortrace.modele.echange";
  } else {
    const nom = nomOutilSpan(N, p.alias);
    sortie.N = nom.N;
    sortie.nomValide = nom.valide;
    sortie.outil = nom.outil;
    const a = N.attributes;
    const args = own(a, "gen_ai.tool.call.arguments") ? a["gen_ai.tool.call.arguments"] : { [CLE_ABSENT]: "gen_ai.tool.call.arguments" };
    const res = own(a, "gen_ai.tool.call.result") ? a["gen_ai.tool.call.result"] : { [CLE_ABSENT]: "gen_ai.tool.call.result" };
    const pa = await json("arguments", args, nom.outil);
    const pr = await json("resultat", res, nom.outil);
    sortie.arguments = borner("arguments", pa.piece, jcsIntegralOctets(args).length);
    sortie.resultat = borner("result", pr.piece, jcsIntegralOctets(res).length);
    sortie.argumentsRediges = sortie.arguments === pa.piece ? pa.valeur : undefined;
    sortie.resultatRedige = sortie.resultat === pr.piece ? pr.valeur : undefined;
    sortie.sourceNonRedigeable = pa.nonRedigeable !== null || pr.nonRedigeable !== null || sortie.arguments !== pa.piece || sortie.resultat !== pr.piece;
    const env = structuredClone(N);
    env.attributes = {};
    for (const [k, v] of Object.entries(N.attributes)) if (k !== "gen_ai.tool.call.arguments" && k !== "gen_ai.tool.call.result") poser(env.attributes, k, v);
    sortie.enveloppe = await enveloppe(env, nom.outil);
  }
  sortie.pieces = [
    source,
    ...(p.sorte === "inference" ? [sortie.prompt, sortie.requete, sortie.reponse, sortie.intention] : [sortie.arguments, sortie.resultat]).filter(Boolean),
    sortie.enveloppe,
  ];
  return sortie;
}

/**
 * Durée déclarée (EX-6.36) : ⌊(fin − début) / 10^6⌋ si les deux sont non nuls
 * et fin ≥ début, bornée à 2^53 − 1 ; sinon 0.
 * @param {object} N
 * @returns {number}
 */
export function dureeDeclaree(N) {
  const d = BigInt(N.start_time_unix_nano);
  const f = BigInt(N.end_time_unix_nano);
  if (d === 0n || f === 0n || f < d) return 0;
  const ms = (f - d) / 1000000n;
  const max = (1n << 53n) - 1n;
  return Number(ms > max ? max : ms);
}

/**
 * `is_error` (EX-6.36) : `status.code` 2 ou `error.type` chaîne non vide.
 * @param {object} N
 */
export function erreurDeclaree(N) {
  const t = N.attributes["error.type"];
  return N.status.code === 2 || (typeof t === "string" && t !== "");
}

/**
 * Événement partiel d'un span (EX-6.36).
 * @param {object} x projection (`projeterSpan`)
 * @param {object} o
 * @param {object} o.N forme normalisée
 * @param {object} o.hote entrée de `otel.hosts`
 * @param {string|null} o.run_id `gen_ai.conversation.id` admis, ou null
 * @param {string} o.policy_version
 * @param {string} o.recorder
 * @param {string|null} o.nomRedaction
 * @param {object[]} [o.effets] effets évalués (sorte outil)
 * @returns {object}
 */
export function partielSpan(x, o) {
  const delegation = { launched_by: o.hote.launched_by, on_behalf_of: o.hote.on_behalf_of ?? null, scope: o.hote.scope, run_id: o.run_id };
  const context = [x.source.referenceContexte("autre"), x.enveloppe.referenceContexte("autre")];
  const duration_ms = dureeDeclaree(o.N);
  const is_error = erreurDeclaree(o.N);
  if (x.sorte === "inference") {
    return partielEchange({
      delegation,
      code: { model: x.model, prompt_version: x.prompt_version, policy_version: o.policy_version, recorder: o.recorder },
      intent: x.intent,
      requete: x.requete.reference,
      reponse: x.reponse.reference,
      duration_ms,
      is_error,
      context,
      nomRedaction: o.nomRedaction,
    });
  }
  return partielAppelOutil({
    delegation,
    code: { model: null, prompt_version: null, policy_version: o.policy_version, recorder: o.recorder },
    intent: null,
    policy: { rule: null, decision: "autorise", ticket: null },
    approval: null,
    tool: x.outil,
    arguments: x.arguments.reference,
    status: "executee",
    result: x.resultat.reference,
    duration_ms,
    is_error,
    effects: o.effets ?? [],
    context,
    nomRedaction: o.nomRedaction,
  });
}

/**
 * Effets d'un span d'outil (EX-6.36, EX-7.6) : gabarit
 * `policy.otel.sources.<alias>.tools.<N>.effects` évalué sur les valeurs
 * rédigées ; sans gabarit, classe `tools.<N>.class`, à défaut `class_default`,
 * à défaut `ecriture`, et l'effet par défaut pour `ecriture`.
 * @param {object} x projection
 * @param {{alias: string, source: object, redacteur?: object|null}} o
 * @returns {Promise<{effets: object[], omis: object[]}>}
 */
export async function effetsSpan(x, o) {
  const reglage = own(o.source.tools ?? {}, x.N) ? o.source.tools[x.N] : null;
  const classe = reglage?.class ?? o.source.class_default ?? "ecriture";
  const params = {
    gabarit: reglage?.effects ?? null,
    classe,
    alias: o.alias,
    nomOrigine: x.nomValide ? x.N : "nom-invalide",
    arguments: x.argumentsRediges,
    resultat: x.resultatRedige,
    sourceNonRedigeable: x.sourceNonRedigeable,
  };
  if (typeof o.redacteur?.evaluerEffets === "function") return o.redacteur.evaluerEffets(params);
  return evaluerEffets({ ...params, executerExtract: o.redacteur?.executerExtract });
}
