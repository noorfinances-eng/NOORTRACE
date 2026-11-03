// Représentation commune d'un `ExportTraceServiceRequest` décodé (JSON,
// EX-6.29, ou protobuf, EX-6.30), forme normalisée N(S) d'un span (EX-6.31)
// et classification (EX-6.32). Un corps protobuf et un corps JSON qui portent
// les mêmes valeurs donnent la même forme normalisée.
//
// Représentation : `{ resource_spans: [{ resource: { attributes, dropped_attributes_count } | null,
// scope_spans: [{ scope: { name, version, attributes, dropped_attributes_count } | null, spans, schema_url }],
// schema_url }] }` ; un span porte ses champs de la table d'EX-6.31 (identifiants
// en hexadécimal minuscule, horodatages en BigInt) ; un attribut est `{ key, value, ignorer }`,
// une valeur `{ type, v }` (`string`, `bool`, `int` en BigInt, `double`, `array`,
// `kvlist`, `bytes`, ou `null` pour une valeur absente).

import { analyserJsonIntegral } from "../jcs-integral.mjs";

/** Corps non décodable (EX-6.29, EX-6.30) : réponse 400. */
export class ErreurDecodage extends Error {
  /** @param {string} raison */
  constructor(raison) {
    super(`corps OTLP non decodable : ${raison}`);
    this.name = "ErreurDecodage";
    this.raison = raison;
  }
}

/** Bornes des entiers 32 bits. */
export const BORNES_32 = Object.freeze({ uint32: [0n, (1n << 32n) - 1n], int32: [-(1n << 31n), (1n << 31n) - 1n] });

/** Valeur absente d'un `AnyValue` vide (V = null). */
export function valeurAbsente() {
  return { type: null, v: null };
}

/** Attributs dont la valeur chaîne JSON est analysée, dans les attributs du span seulement (EX-6.31). */
export const ATTRIBUTS_CONTENU = Object.freeze([
  "gen_ai.input.messages",
  "gen_ai.output.messages",
  "gen_ai.system_instructions",
  "gen_ai.tool.definitions",
  "gen_ai.tool.call.arguments",
  "gen_ai.tool.call.result",
]);

const MAX_SUR = (1n << 53n) - 1n;

function poser(o, k, v) {
  Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
}

/**
 * V(AnyValue) (EX-6.31).
 * @param {{type: string|null, v: unknown}} x
 * @param {{doubles: number}} comptes
 * @returns {unknown}
 */
function valeurV(x, comptes) {
  switch (x.type) {
    case "string":
    case "bool":
      return x.v;
    case "int":
      return x.v <= MAX_SUR && x.v >= -MAX_SUR ? Number(x.v) : x.v.toString();
    case "double": {
      const d = x.v;
      if (Number.isNaN(d)) return "NaN";
      if (d === Infinity) return "Infinity";
      if (d === -Infinity) return "-Infinity";
      return Object.is(d, -0) ? 0 : d;
    }
    case "array":
      return x.v.map((y) => valeurV(y, comptes));
    case "kvlist":
      return objetA(x.v, comptes, false);
    case "bytes":
      return Buffer.from(x.v).toString("base64");
    default:
      return null;
  }
}

/**
 * A(liste) (EX-6.31) : la première occurrence d'une clé est gardée, les
 * suivantes ignorées et comptées (`otel_cle_double`), à tout niveau.
 * @param {object[]} liste
 * @param {{doubles: number}} comptes
 * @param {boolean} contenu attributs du span : chaînes JSON des six attributs de contenu analysées
 * @param {{profondeurMax?: number}} [bornes]
 * @returns {object}
 */
export function objetA(liste, comptes, contenu, bornes = {}) {
  const o = {};
  const vues = new Set();
  for (const kv of liste) {
    if (kv.ignorer) continue;
    if (vues.has(kv.key)) {
      comptes.doubles++;
      continue;
    }
    vues.add(kv.key);
    let v = valeurV(kv.value, comptes);
    if (contenu && typeof v === "string" && ATTRIBUTS_CONTENU.includes(kv.key)) v = analyserContenu(v, bornes);
    poser(o, kv.key, v);
  }
  return o;
}

/**
 * Attribut de contenu (EX-6.31) : une chaîne qui s'analyse en JSON strict
 * (EX-5.7 point 2, nombres en JCS intégral) est remplacée par la valeur
 * analysée ; sinon la chaîne est gardée.
 * @param {string} s
 * @param {{profondeurMax?: number}} bornes
 */
export function analyserContenu(s, bornes = {}) {
  if (s.charCodeAt(0) === 0xfeff) return s;
  try {
    return analyserJsonIntegral(s, { profondeurMax: bornes.profondeurMax });
  } catch {
    return s;
  }
}

/**
 * Forme normalisée N(S) d'un span (EX-6.31), dans l'ordre du document.
 * @param {object} requete représentation commune
 * @param {{profondeurMax?: number}} [bornes]
 * @returns {{spans: {path: number[], N: object}[], doubles: number}}
 */
export function normaliser(requete, bornes = {}) {
  const comptes = { doubles: 0 };
  const spans = [];
  requete.resource_spans.forEach((rs, r) => {
    const resource = { attributes: objetA(rs.resource?.attributes ?? [], comptes, false), dropped_attributes_count: rs.resource?.dropped_attributes_count ?? 0 };
    rs.scope_spans.forEach((ss, s) => {
      const scope = { name: ss.scope?.name ?? "", version: ss.scope?.version ?? "", attributes: objetA(ss.scope?.attributes ?? [], comptes, false) };
      const schema_url = ss.schema_url !== "" ? ss.schema_url : rs.schema_url !== "" ? rs.schema_url : null;
      ss.spans.forEach((sp, p) => {
        const N = {
          trace_id: sp.trace_id,
          span_id: sp.span_id,
          parent_span_id: sp.parent_span_id === "" ? null : sp.parent_span_id,
          trace_state: sp.trace_state,
          name: sp.name,
          flags: sp.flags,
          kind: sp.kind,
          start_time_unix_nano: sp.start_time_unix_nano.toString(),
          end_time_unix_nano: sp.end_time_unix_nano.toString(),
          attributes: objetA(sp.attributes, comptes, true, bornes),
          dropped_attributes_count: sp.dropped_attributes_count,
          dropped_events_count: sp.dropped_events_count,
          dropped_links_count: sp.dropped_links_count,
          events: sp.events.map((e) => ({ name: e.name, time_unix_nano: e.time_unix_nano.toString(), attributes: objetA(e.attributes, comptes, false), dropped_attributes_count: e.dropped_attributes_count })),
          links_count: sp.links_count,
          status: { code: sp.status?.code ?? 0, message: sp.status?.message ?? "" },
          resource: structuredClone(resource),
          scope: structuredClone(scope),
          schema_url,
        };
        spans.push({ path: [r, s, p], N });
      });
    });
  });
  return { spans, doubles: comptes.doubles };
}

/** Opérations par sorte (EX-6.32, registre L5-6). */
export const OPERATIONS_INFERENCE = Object.freeze(["chat", "generate_content", "text_completion"]);

/**
 * Classification d'un span (EX-6.32).
 * @param {object} N forme normalisée
 * @param {string[]} ingest sortes retenues par la source (`policy.otel.sources.<alias>.ingest`)
 * @returns {{issue: "ignore"|"rejete"|"retenu", raison: string|null, sorte: "inference"|"outil"|null}}
 */
export function classer(N, ingest) {
  const a = N.attributes;
  let operation = null;
  if (typeof a["gen_ai.operation.name"] === "string") operation = a["gen_ai.operation.name"];
  else if (a["mcp.method.name"] === "tools/call") operation = "execute_tool";
  if (operation === null) return { issue: "ignore", raison: "hors_genai", sorte: null };
  const sorte = OPERATIONS_INFERENCE.includes(operation) ? "inference" : operation === "execute_tool" ? "outil" : null;
  if (sorte === null) return { issue: "ignore", raison: "operation_non_retenue", sorte: null };
  if (!ingest.includes(sorte)) return { issue: "ignore", raison: "sorte_desactivee", sorte };
  const nul = (h) => /^0+$/.test(h);
  const invalide =
    !/^[0-9a-f]{32}$/.test(N.trace_id) || nul(N.trace_id) || !/^[0-9a-f]{16}$/.test(N.span_id) || nul(N.span_id) || (N.parent_span_id !== null && (!/^[0-9a-f]{16}$/.test(N.parent_span_id) || nul(N.parent_span_id)));
  if (invalide) return { issue: "rejete", raison: "identifiants_invalides", sorte };
  return { issue: "retenu", raison: null, sorte };
}

/** Nombre de spans d'une requête (EX-6.28 `spans_per_request`). */
export function nombreSpans(requete) {
  let n = 0;
  for (const rs of requete.resource_spans) for (const ss of rs.scope_spans) n += ss.spans.length;
  return n;
}
