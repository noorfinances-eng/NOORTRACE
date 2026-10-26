// Ingestion OpenTelemetry de l'enregistreur (CT-2 révision 0.5, §6.8,
// EX-6.25 à EX-6.41) : référence SANS RÉSEAU de la réception OTLP/HTTP d'un
// lot de traces (protobuf et JSON), de la forme normalisée d'un span, de sa
// classification, des doublons et recouvrements, des pièces rédigées et de
// l'événement CT-1 de rang déclaratif qu'il donne. Les fonctions s'appuient
// sur scripts/lib/capture.mjs (rédaction, pièces, événements partiels) et
// scripts/lib/journal.mjs (JCS, hachage) ; aucune valeur ni aucun champ
// nouveau de CT-1 n'est employé : un span se projette sur les valeurs
// existantes (EX-6.23, EX-6.36).
//
// Versions épinglées (EX-6.25) : OTLP de opentelemetry-proto v1.11.1,
// conventions sémantiques GenAI v1.41.1 (statut Development).

import zlib from "node:zlib";
import * as J from "./journal.mjs";
import * as C from "./capture.mjs";

/** Version des conventions sémantiques GenAI lues par l'ingestion (EX-6.25, `policy.otel.semconv`). */
export const SEMCONV = "1.41.1";
/** Version d'OTLP (`opentelemetry-proto`) lue par l'ingestion (EX-6.25). */
export const VERSION_OTLP = "1.11.1";
/** Types de média admis (EX-6.27). */
export const TYPE_PROTOBUF = "application/x-protobuf";
export const TYPE_JSON = "application/json";
/** Taille maximale de la table des doublons (EX-6.33). */
export const DOUBLONS_MAX = 1000000;

/** Textes fixes des refus (EX-6.27), en ASCII. */
export const TEXTES_REFUS = Object.freeze({
  400: "noortrace: corps OTLP non decodable",
  401: "noortrace: source OpenTelemetry non authentifiee",
  404: "noortrace: chemin inconnu",
  405: "noortrace: methode non admise",
  413: "noortrace: corps OTLP trop grand",
  415: "noortrace: type de contenu ou codage non admis",
  429: "noortrace: quota de la source atteint",
  503: "noortrace: enregistreur en mode degrade",
});

/** Refus d'une requête OTLP (EX-6.27 à EX-6.30) : `status` HTTP et raison (journal d'exploitation, jamais le contenu). */
export class ErreurOTLP extends Error {
  constructor(status, raison) {
    super(`${status} ${raison}`);
    this.status = status;
    this.raison = raison;
  }
}
const refus = (raison) => {
  throw new ErreurOTLP(400, raison);
};

/** Les six attributs de contenu qu'un span PEUT porter en chaîne JSON (EX-6.31). */
export const ATTRIBUTS_CONTENU = Object.freeze(["gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.system_instructions", "gen_ai.tool.definitions", "gen_ai.tool.call.arguments", "gen_ai.tool.call.result"]);
const CONTENU = new Set(ATTRIBUTS_CONTENU);

// ---------------------------------------------------------------------------
// Forme logique commune aux deux encodages
// ---------------------------------------------------------------------------
//
// { resourceSpans: [{ resource: null | { attributes, droppedAttributesCount },
//   scopeSpans: [{ scope: null | { name, version, attributes, droppedAttributesCount },
//   spans: [Span], schemaUrl }], schemaUrl }] }
// Span : { traceId, spanId, parentSpanId (hexadécimal minuscule), traceState,
//   name, kind, startTimeUnixNano, endTimeUnixNano (BigInt), attributes,
//   droppedAttributesCount, events: [{ timeUnixNano, name, attributes,
//   droppedAttributesCount }], droppedEventsCount, links (nombre), droppedLinksCount,
//   status: null | { code, message }, flags }
// KeyValue : { key: chaîne | null (keyStrindex sans key), keyStrindex, value: null | AnyValue }
// AnyValue : { type: null | "string" | "bool" | "int" (BigInt) | "double" | "array" | "kvlist" | "bytes" (Buffer) | "strindex", value }

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof C.NombreJSON);
const RE_ENTIER = /^-?(0|[1-9][0-9]*)$/;
const RE_NATUREL = /^(0|[1-9][0-9]*)$/;
const RE_HEX_PAIR = /^([0-9a-fA-F]{2})*$/;
const MAX_U64 = 2n ** 64n - 1n;
const MIN_I64 = -(2n ** 63n);
const MAX_I64 = 2n ** 63n - 1n;

// ---------------------------------------------------------------------------
// Décodage JSON (EX-6.29)
// ---------------------------------------------------------------------------

/** Lit un champ JSON : `null` vaut absent. */
const champ = (o, nom) => (Object.hasOwn(o, nom) && o[nom] !== null ? o[nom] : undefined);

function jsonMessage(o, nom) {
  const v = champ(o, nom);
  if (v === undefined) return undefined;
  if (!estObjet(v)) refus(`champ message ${nom} non objet`);
  return v;
}
function jsonRepete(o, nom) {
  const v = champ(o, nom);
  if (v === undefined) return [];
  if (!Array.isArray(v)) refus(`champ répété ${nom} non tableau`);
  return v;
}
function jsonChaine(o, nom) {
  const v = champ(o, nom);
  if (v === undefined) return "";
  if (typeof v !== "string") refus(`champ chaîne ${nom}`);
  return v;
}
function jsonHex(o, nom) {
  const v = jsonChaine(o, nom);
  if (!RE_HEX_PAIR.test(v)) refus(`identifiant ${nom} non hexadécimal`);
  return v.toLowerCase();
}
/** Entier 32 bits : nombre JSON entier dans les bornes, ou chaîne décimale (sauf énumération). */
function jsonEntier32(o, nom, { signe = false, enumeration = false } = {}) {
  const v = champ(o, nom);
  if (v === undefined) return 0;
  let t;
  if (v instanceof C.NombreJSON) t = v.texte;
  else if (typeof v === "string" && !enumeration) t = v;
  else refus(enumeration ? `énumération ${nom} en chaîne` : `entier ${nom}`);
  if (!RE_ENTIER.test(t)) refus(`entier ${nom}`);
  const n = BigInt(t);
  if (signe ? n < -(2n ** 31n) || n > 2n ** 31n - 1n : n < 0n || n > 2n ** 32n - 1n) refus(`entier ${nom} hors bornes`);
  return Number(n);
}
function jsonFixed64(o, nom) {
  const v = champ(o, nom);
  if (v === undefined) return 0n;
  const t = v instanceof C.NombreJSON ? v.texte : typeof v === "string" ? v : refus(`fixed64 ${nom}`);
  if (!RE_NATUREL.test(t)) refus(`fixed64 ${nom}`);
  const n = BigInt(t);
  if (n > MAX_U64) refus(`fixed64 ${nom} hors bornes`);
  return n;
}
function base64Strict(s) {
  if (typeof s !== "string") refus("bytesValue non chaîne");
  const standard = /^[A-Za-z0-9+/]*={0,2}$/.test(s);
  const url = /^[A-Za-z0-9_-]*={0,2}$/.test(s);
  if (!standard && !url) refus("bytesValue non base64");
  const sans = s.replace(/=+$/, "");
  if (sans.length % 4 === 1 || (s.length !== sans.length && s.length % 4 !== 0)) refus("bytesValue non base64");
  const b = Buffer.from(sans, standard ? "base64" : "base64url");
  if (b.toString(standard ? "base64" : "base64url").replace(/=+$/, "") !== sans) refus("bytesValue non base64");
  return b;
}
const MEMBRES_ANYVALUE = ["stringValue", "boolValue", "intValue", "doubleValue", "arrayValue", "kvlistValue", "bytesValue", "stringValueStrindex"];

function jsonAnyValue(o, bornes, profondeur) {
  const presents = MEMBRES_ANYVALUE.filter((m) => champ(o, m) !== undefined);
  if (presents.length > 1) refus("AnyValue à plusieurs membres");
  if (presents.length === 0) return { type: null, value: null };
  const m = presents[0];
  const v = o[m];
  switch (m) {
    case "stringValue":
      if (typeof v !== "string") refus("stringValue");
      return { type: "string", value: v };
    case "boolValue":
      if (typeof v !== "boolean") refus("boolValue");
      return { type: "bool", value: v };
    case "intValue": {
      const t = v instanceof C.NombreJSON ? v.texte : typeof v === "string" ? v : refus("intValue");
      if (!RE_ENTIER.test(t)) refus("intValue");
      const n = BigInt(t);
      if (n < MIN_I64 || n > MAX_I64) refus("intValue hors bornes");
      return { type: "int", value: n };
    }
    case "doubleValue": {
      if (v instanceof C.NombreJSON) {
        const d = Number(v.texte);
        if (!Number.isFinite(d)) refus("doubleValue hors de la double précision");
        return { type: "double", value: d };
      }
      if (v === "NaN") return { type: "double", value: NaN };
      if (v === "Infinity") return { type: "double", value: Infinity };
      if (v === "-Infinity") return { type: "double", value: -Infinity };
      return refus("doubleValue");
    }
    case "arrayValue": {
      if (!estObjet(v)) refus("arrayValue");
      if (profondeur + 1 > bornes.profondeurMax) refus("imbrication d'AnyValue au-delà de la borne");
      const valeurs = jsonRepete(v, "values");
      if (valeurs.length > bornes.membresMax) refus("arrayValue au-delà de la borne");
      return { type: "array", value: valeurs.map((x) => (estObjet(x) ? jsonAnyValue(x, bornes, profondeur + 1) : refus("élément d'arrayValue"))) };
    }
    case "kvlistValue": {
      if (!estObjet(v)) refus("kvlistValue");
      if (profondeur + 1 > bornes.profondeurMax) refus("imbrication d'AnyValue au-delà de la borne");
      const valeurs = jsonRepete(v, "values");
      if (valeurs.length > bornes.membresMax) refus("kvlistValue au-delà de la borne");
      return { type: "kvlist", value: valeurs.map((x) => jsonKeyValue(x, bornes, profondeur + 1)) };
    }
    case "bytesValue":
      return { type: "bytes", value: base64Strict(v) };
    case "stringValueStrindex":
      jsonEntier32(o, m, { signe: true });
      return { type: "strindex", value: null };
    default:
      return refus("AnyValue");
  }
}
function jsonKeyValue(o, bornes, profondeur = 0) {
  if (!estObjet(o)) refus("KeyValue non objet");
  const keyPresent = champ(o, "key") !== undefined;
  const key = jsonChaine(o, "key");
  const strPresent = champ(o, "keyStrindex") !== undefined;
  const keyStrindex = jsonEntier32(o, "keyStrindex", { signe: true });
  const v = jsonMessage(o, "value");
  return { key: !keyPresent && strPresent ? null : key, keyStrindex, keyPresent, value: v === undefined ? null : jsonAnyValue(v, bornes, profondeur) };
}
const jsonAttributs = (o, nom, bornes) => jsonRepete(o, nom).map((x) => jsonKeyValue(x, bornes));

function jsonSpan(o, bornes) {
  if (!estObjet(o)) refus("Span non objet");
  const status = jsonMessage(o, "status");
  return {
    traceId: jsonHex(o, "traceId"),
    spanId: jsonHex(o, "spanId"),
    traceState: jsonChaine(o, "traceState"),
    parentSpanId: jsonHex(o, "parentSpanId"),
    name: jsonChaine(o, "name"),
    kind: jsonEntier32(o, "kind", { signe: true, enumeration: true }),
    startTimeUnixNano: jsonFixed64(o, "startTimeUnixNano"),
    endTimeUnixNano: jsonFixed64(o, "endTimeUnixNano"),
    attributes: jsonAttributs(o, "attributes", bornes),
    droppedAttributesCount: jsonEntier32(o, "droppedAttributesCount"),
    events: jsonRepete(o, "events").map((e) => {
      if (!estObjet(e)) refus("Span.Event non objet");
      return { timeUnixNano: jsonFixed64(e, "timeUnixNano"), name: jsonChaine(e, "name"), attributes: jsonAttributs(e, "attributes", bornes), droppedAttributesCount: jsonEntier32(e, "droppedAttributesCount") };
    }),
    droppedEventsCount: jsonEntier32(o, "droppedEventsCount"),
    links: jsonRepete(o, "links").map((l) => (estObjet(l) ? l : refus("Span.Link non objet"))).length,
    droppedLinksCount: jsonEntier32(o, "droppedLinksCount"),
    status: status === undefined ? null : { message: jsonChaine(status, "message"), code: jsonEntier32(status, "code", { signe: true, enumeration: true }) },
    flags: jsonEntier32(o, "flags"),
  };
}

/**
 * Décodage d'un corps OTLP/JSON (EX-6.29) en forme logique. JSON strict
 * (clé en double, substitut isolé, marque d'ordre d'octets, bornes) ;
 * nombres lus sur leur texte là où le champ est un entier ; identifiants en
 * hexadécimal de longueur paire, jamais en base64 ; énumérations en nombre ;
 * champ inconnu ignoré ; `null` vaut absent. Lève ErreurOTLP(400).
 */
export function decoderJSON(octets, { profondeurMax = C.PROFONDEUR_JSON_MAX, membresMax = C.MEMBRES_JSON_MAX } = {}) {
  let doc;
  try {
    doc = C.analyserJSONIntegral(Buffer.from(octets), { profondeurMax, membresMax, nombresTexte: true });
  } catch {
    refus("corps JSON non analysable");
  }
  if (!estObjet(doc)) refus("racine non objet");
  const bornes = { profondeurMax, membresMax };
  return {
    resourceSpans: jsonRepete(doc, "resourceSpans").map((rs) => {
      if (!estObjet(rs)) refus("ResourceSpans non objet");
      const res = jsonMessage(rs, "resource");
      return {
        resource: res === undefined ? null : { attributes: jsonAttributs(res, "attributes", bornes), droppedAttributesCount: jsonEntier32(res, "droppedAttributesCount") },
        scopeSpans: jsonRepete(rs, "scopeSpans").map((ss) => {
          if (!estObjet(ss)) refus("ScopeSpans non objet");
          const sc = jsonMessage(ss, "scope");
          return {
            scope: sc === undefined ? null : { name: jsonChaine(sc, "name"), version: jsonChaine(sc, "version"), attributes: jsonAttributs(sc, "attributes", bornes), droppedAttributesCount: jsonEntier32(sc, "droppedAttributesCount") },
            spans: jsonRepete(ss, "spans").map((s) => jsonSpan(s, bornes)),
            schemaUrl: jsonChaine(ss, "schemaUrl"),
          };
        }),
        schemaUrl: jsonChaine(rs, "schemaUrl"),
      };
    }),
  };
}

// ---------------------------------------------------------------------------
// Décodage protobuf (EX-6.30)
// ---------------------------------------------------------------------------

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

class Lecteur {
  constructor(buf, debut = 0, fin = buf.length) {
    this.b = buf;
    this.i = debut;
    this.fin = fin;
  }
  varint() {
    let r = 0n;
    for (let k = 0; k < 10; k++) {
      if (this.i >= this.fin) refus("varint tronqué");
      const o = this.b[this.i++];
      if (k === 9 && o > 1) refus("varint de plus de 64 bits");
      r |= BigInt(o & 0x7f) << BigInt(7 * k);
      if ((o & 0x80) === 0) return r;
    }
    return refus("varint de plus de dix octets");
  }
  octets(n) {
    if (n > this.fin - this.i) refus("longueur au-delà du message");
    const s = this.b.subarray(this.i, this.i + n);
    this.i += n;
    return s;
  }
}

/**
 * Lit un message : `table` associe un numéro de champ à `[nom, typeDeFil, répété]` ;
 * rend { nom: valeur brute (BigInt, Buffer) ou [valeurs] }. Un champ connu au
 * mauvais type de fil, un champ non répété présent deux fois, une étiquette 0,
 * un type de fil 3, 4, 6 ou 7 : 400 ; un champ inconnu est sauté.
 */
function lireMessage(buf, table) {
  const L = new Lecteur(buf);
  const out = {};
  while (L.i < L.fin) {
    const etiquette = L.varint();
    const numero = etiquette >> 3n;
    const fil = Number(etiquette & 7n);
    if (numero === 0n) refus("étiquette de champ 0");
    if (fil === 3 || fil === 4 || fil === 6 || fil === 7) refus(`type de fil ${fil}`);
    let valeur;
    if (fil === 0) valeur = L.varint();
    else if (fil === 1) valeur = L.octets(8);
    else if (fil === 5) valeur = L.octets(4);
    else {
      const n = L.varint();
      if (n > BigInt(L.fin - L.i)) refus("longueur au-delà du message");
      valeur = L.octets(Number(n));
    }
    const def = table[Number(numero)];
    if (!def) continue;
    const [nom, filAttendu, repete] = def;
    if (fil !== filAttendu) refus(`champ ${nom} au mauvais type de fil`);
    if (repete) (out[nom] ??= []).push(valeur);
    else {
      if (Object.hasOwn(out, nom)) refus(`champ ${nom} présent deux fois`);
      out[nom] = valeur;
    }
  }
  return out;
}

const T = { LEN: 2, VARINT: 0, I64: 1, I32: 5 };
const TABLES = {
  requete: { 1: ["resourceSpans", T.LEN, true] },
  resourceSpans: { 1: ["resource", T.LEN, false], 2: ["scopeSpans", T.LEN, true], 3: ["schemaUrl", T.LEN, false] },
  resource: { 1: ["attributes", T.LEN, true], 2: ["droppedAttributesCount", T.VARINT, false] },
  scopeSpans: { 1: ["scope", T.LEN, false], 2: ["spans", T.LEN, true], 3: ["schemaUrl", T.LEN, false] },
  scope: { 1: ["name", T.LEN, false], 2: ["version", T.LEN, false], 3: ["attributes", T.LEN, true], 4: ["droppedAttributesCount", T.VARINT, false] },
  span: {
    1: ["traceId", T.LEN, false], 2: ["spanId", T.LEN, false], 3: ["traceState", T.LEN, false], 4: ["parentSpanId", T.LEN, false], 5: ["name", T.LEN, false],
    6: ["kind", T.VARINT, false], 7: ["startTimeUnixNano", T.I64, false], 8: ["endTimeUnixNano", T.I64, false], 9: ["attributes", T.LEN, true],
    10: ["droppedAttributesCount", T.VARINT, false], 11: ["events", T.LEN, true], 12: ["droppedEventsCount", T.VARINT, false], 13: ["links", T.LEN, true],
    14: ["droppedLinksCount", T.VARINT, false], 15: ["status", T.LEN, false], 16: ["flags", T.I32, false],
  },
  event: { 1: ["timeUnixNano", T.I64, false], 2: ["name", T.LEN, false], 3: ["attributes", T.LEN, true], 4: ["droppedAttributesCount", T.VARINT, false] },
  status: { 2: ["message", T.LEN, false], 3: ["code", T.VARINT, false] },
  keyValue: { 1: ["key", T.LEN, false], 2: ["value", T.LEN, false], 3: ["keyStrindex", T.VARINT, false] },
  anyValue: {
    1: ["stringValue", T.LEN, false], 2: ["boolValue", T.VARINT, false], 3: ["intValue", T.VARINT, false], 4: ["doubleValue", T.I64, false],
    5: ["arrayValue", T.LEN, false], 6: ["kvlistValue", T.LEN, false], 7: ["bytesValue", T.LEN, false], 8: ["stringValueStrindex", T.VARINT, false],
  },
  liste: { 1: ["values", T.LEN, true] },
};

function pbChaine(b) {
  if (b === undefined) return "";
  try {
    return UTF8.decode(b);
  } catch {
    return refus("chaîne UTF-8 invalide");
  }
}
const pbHex = (b) => (b === undefined ? "" : Buffer.from(b).toString("hex"));
const pbU32 = (v) => (v === undefined ? 0 : Number(BigInt.asUintN(32, v)));
const pbI32 = (v) => (v === undefined ? 0 : Number(BigInt.asIntN(32, v)));
const pbFixed64 = (b) => (b === undefined ? 0n : Buffer.from(b).readBigUInt64LE(0));

function pbAnyValue(buf, bornes, profondeur) {
  const m = lireMessage(buf, TABLES.anyValue);
  const presents = Object.keys(m);
  if (presents.length > 1) refus("AnyValue à plusieurs membres du oneof");
  if (presents.length === 0) return { type: null, value: null };
  const [nom] = presents;
  const v = m[nom];
  switch (nom) {
    case "stringValue": return { type: "string", value: pbChaine(v) };
    case "boolValue":
      if (v !== 0n && v !== 1n) refus("bool_value autre que 0 ou 1");
      return { type: "bool", value: v === 1n };
    case "intValue": return { type: "int", value: BigInt.asIntN(64, v) };
    case "doubleValue": return { type: "double", value: Buffer.from(v).readDoubleLE(0) };
    case "arrayValue":
    case "kvlistValue": {
      if (profondeur + 1 > bornes.profondeurMax) refus("imbrication d'AnyValue au-delà de la borne");
      const valeurs = lireMessage(v, TABLES.liste).values ?? [];
      if (valeurs.length > bornes.membresMax) refus("liste d'AnyValue au-delà de la borne");
      return nom === "arrayValue" ? { type: "array", value: valeurs.map((x) => pbAnyValue(x, bornes, profondeur + 1)) } : { type: "kvlist", value: valeurs.map((x) => pbKeyValue(x, bornes, profondeur + 1)) };
    }
    case "bytesValue": return { type: "bytes", value: Buffer.from(v) };
    case "stringValueStrindex": return { type: "strindex", value: null };
    default: return refus("AnyValue");
  }
}
function pbKeyValue(buf, bornes, profondeur = 0) {
  const m = lireMessage(buf, TABLES.keyValue);
  const keyPresent = m.key !== undefined;
  return { key: !keyPresent && m.keyStrindex !== undefined ? null : pbChaine(m.key), keyStrindex: pbI32(m.keyStrindex), keyPresent, value: m.value === undefined ? null : pbAnyValue(m.value, bornes, profondeur) };
}
const pbAttributs = (liste, bornes) => (liste ?? []).map((x) => pbKeyValue(x, bornes));
function pbSpan(buf, bornes) {
  const m = lireMessage(buf, TABLES.span);
  let status = null;
  if (m.status !== undefined) {
    const st = lireMessage(m.status, TABLES.status);
    status = { message: pbChaine(st.message), code: pbI32(st.code) };
  }
  return {
    traceId: pbHex(m.traceId), spanId: pbHex(m.spanId), traceState: pbChaine(m.traceState), parentSpanId: pbHex(m.parentSpanId), name: pbChaine(m.name),
    kind: pbI32(m.kind), startTimeUnixNano: pbFixed64(m.startTimeUnixNano), endTimeUnixNano: pbFixed64(m.endTimeUnixNano),
    attributes: pbAttributs(m.attributes, bornes), droppedAttributesCount: pbU32(m.droppedAttributesCount),
    events: (m.events ?? []).map((e) => {
      const ev = lireMessage(e, TABLES.event);
      return { timeUnixNano: pbFixed64(ev.timeUnixNano), name: pbChaine(ev.name), attributes: pbAttributs(ev.attributes, bornes), droppedAttributesCount: pbU32(ev.droppedAttributesCount) };
    }),
    droppedEventsCount: pbU32(m.droppedEventsCount), links: (m.links ?? []).length, droppedLinksCount: pbU32(m.droppedLinksCount),
    status, flags: m.flags === undefined ? 0 : Buffer.from(m.flags).readUInt32LE(0),
  };
}

/**
 * Décodage d'un corps OTLP/protobuf (EX-6.30) en forme logique : décodeur
 * écrit à la main (types de fil 0, 1, 2, 5 ; 3, 4, 6, 7 refusés ; varint de
 * dix octets au plus ; champ non répété en double et deux membres du oneof
 * d'AnyValue refusés ; UTF-8 strict ; champs inconnus sautés). Lève
 * ErreurOTLP(400).
 */
export function decoderProtobuf(octets, { profondeurMax = C.PROFONDEUR_JSON_MAX, membresMax = C.MEMBRES_JSON_MAX } = {}) {
  const bornes = { profondeurMax, membresMax };
  const racine = lireMessage(Buffer.from(octets), TABLES.requete);
  return {
    resourceSpans: (racine.resourceSpans ?? []).map((b) => {
      const rs = lireMessage(b, TABLES.resourceSpans);
      let resource = null;
      if (rs.resource !== undefined) {
        const r = lireMessage(rs.resource, TABLES.resource);
        resource = { attributes: pbAttributs(r.attributes, bornes), droppedAttributesCount: pbU32(r.droppedAttributesCount) };
      }
      return {
        resource,
        scopeSpans: (rs.scopeSpans ?? []).map((sb) => {
          const ss = lireMessage(sb, TABLES.scopeSpans);
          let scope = null;
          if (ss.scope !== undefined) {
            const sc = lireMessage(ss.scope, TABLES.scope);
            scope = { name: pbChaine(sc.name), version: pbChaine(sc.version), attributes: pbAttributs(sc.attributes, bornes), droppedAttributesCount: pbU32(sc.droppedAttributesCount) };
          }
          return { scope, spans: (ss.spans ?? []).map((s) => pbSpan(s, bornes)), schemaUrl: pbChaine(ss.schemaUrl) };
        }),
        schemaUrl: pbChaine(rs.schemaUrl),
      };
    }),
  };
}

// ---------------------------------------------------------------------------
// Encodage protobuf (générateur des vecteurs)
// ---------------------------------------------------------------------------

function varintOctets(n) {
  let v = BigInt.asUintN(64, BigInt(n));
  const out = [];
  do {
    let o = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) o |= 0x80;
    out.push(o);
  } while (v > 0n);
  return Buffer.from(out);
}
const etiquette = (numero, fil) => varintOctets((BigInt(numero) << 3n) | BigInt(fil));
const len = (numero, contenu) => Buffer.concat([etiquette(numero, 2), varintOctets(contenu.length), contenu]);
const chaine = (numero, s, toujours = false) => (s === "" && !toujours ? Buffer.alloc(0) : len(numero, Buffer.from(s, "utf8")));
const hexChamp = (numero, h) => (h === "" ? Buffer.alloc(0) : len(numero, Buffer.from(h, "hex")));
const varintChamp = (numero, v, toujours = false) => (BigInt(v) === 0n && !toujours ? Buffer.alloc(0) : Buffer.concat([etiquette(numero, 0), varintOctets(v)]));
const fixed64Champ = (numero, v) => {
  if (BigInt(v) === 0n) return Buffer.alloc(0);
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(v));
  return Buffer.concat([etiquette(numero, 1), b]);
};

function encAnyValue(a) {
  switch (a.type) {
    case null: return Buffer.alloc(0);
    case "string": return chaine(1, a.value, true);
    case "bool": return varintChamp(2, a.value ? 1 : 0, true);
    case "int": return varintChamp(3, a.value, true);
    case "double": {
      const b = Buffer.alloc(8);
      b.writeDoubleLE(a.value);
      return Buffer.concat([etiquette(4, 1), b]);
    }
    case "array": return len(5, Buffer.concat(a.value.map((x) => len(1, encAnyValue(x)))));
    case "kvlist": return len(6, Buffer.concat(a.value.map((x) => len(1, encKeyValue(x)))));
    case "bytes": return len(7, a.value);
    case "strindex": return varintChamp(8, 0, true);
    default: throw new TypeError(`type d'AnyValue inconnu ${a.type}`);
  }
}
function encKeyValue(kv) {
  return Buffer.concat([chaine(1, kv.key ?? ""), kv.value === null ? Buffer.alloc(0) : len(2, encAnyValue(kv.value)), varintChamp(3, kv.keyStrindex ?? 0)]);
}
const encAttributs = (numero, liste) => Buffer.concat(liste.map((kv) => len(numero, encKeyValue(kv))));
function encSpan(s) {
  const parts = [
    hexChamp(1, s.traceId), hexChamp(2, s.spanId), chaine(3, s.traceState), hexChamp(4, s.parentSpanId), chaine(5, s.name),
    varintChamp(6, s.kind), fixed64Champ(7, s.startTimeUnixNano), fixed64Champ(8, s.endTimeUnixNano), encAttributs(9, s.attributes),
    varintChamp(10, s.droppedAttributesCount),
    ...s.events.map((e) => len(11, Buffer.concat([fixed64Champ(1, e.timeUnixNano), chaine(2, e.name), encAttributs(3, e.attributes), varintChamp(4, e.droppedAttributesCount)]))),
    varintChamp(12, s.droppedEventsCount),
  ];
  if (s.links !== 0) throw new TypeError("encoderProtobuf : les liens ne sont pas encodés (le décodeur ne les garde pas)");
  parts.push(varintChamp(14, s.droppedLinksCount));
  if (s.status !== null) parts.push(len(15, Buffer.concat([chaine(2, s.status.message), varintChamp(3, s.status.code)])));
  if (s.flags !== 0) {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(s.flags);
    parts.push(Buffer.concat([etiquette(16, 5), b]));
  }
  return Buffer.concat(parts);
}

/**
 * Encodage protobuf d'une forme logique (générateur des vecteurs) : champs
 * dans l'ordre croissant de leur numéro, chacun une fois, valeurs par défaut
 * de proto3 omises (0, "", false, listes vides), messages présents émis même
 * vides, membre du oneof d'AnyValue toujours émis : mêmes octets que
 * `SerializeToString(deterministic=True)` de la bibliothèque Python.
 */
export function encoderProtobuf(logique) {
  return Buffer.concat(logique.resourceSpans.map((rs) => len(1, Buffer.concat([
    rs.resource === null ? Buffer.alloc(0) : len(1, encResource(rs.resource)),
    ...rs.scopeSpans.map((ss) => len(2, Buffer.concat([
      ss.scope === null ? Buffer.alloc(0) : len(1, encScope(ss.scope)),
      ...ss.spans.map((s) => len(2, encSpan(s))),
      chaine(3, ss.schemaUrl),
    ]))),
    chaine(3, rs.schemaUrl),
  ]))));
}
function encResource(r) {
  return Buffer.concat([encAttributs(1, r.attributes), varintChamp(2, r.droppedAttributesCount)]);
}
function encScope(sc) {
  return Buffer.concat([chaine(1, sc.name), chaine(2, sc.version), encAttributs(3, sc.attributes), varintChamp(4, sc.droppedAttributesCount)]);
}
/** Briques d'encodage protobuf (générateur des vecteurs : champs inconnus, champ en double). */
export const PB = Object.freeze({ champLen: len, span: encSpan, scope: encScope, resource: encResource });

// ---------------------------------------------------------------------------
// Forme normalisée (EX-6.31)
// ---------------------------------------------------------------------------

const MAX_SUR = 2n ** 53n - 1n;

/**
 * V(AnyValue) d'EX-6.31. `compte` reçoit les clés en double des
 * `kvlist_value` imbriquées (`otel_cle_double`, A(liste) s'applique à tout
 * niveau) ; les attributs de contenu ne sont jamais analysés dans une
 * `kvlist_value` (EX-6.31 : seulement dans les attributs du span).
 */
export function valeurAnyValue(a, compte = { doubles: 0 }) {
  if (a === null) return null;
  switch (a.type) {
    case "string": return a.value;
    case "bool": return a.value;
    case "int": return a.value >= -MAX_SUR && a.value <= MAX_SUR ? Number(a.value) : a.value.toString();
    case "double": return Number.isNaN(a.value) ? "NaN" : a.value === Infinity ? "Infinity" : a.value === -Infinity ? "-Infinity" : a.value === 0 ? 0 : a.value;
    case "array": return a.value.map((x) => valeurAnyValue(x, compte));
    case "kvlist": return attributs(a.value, compte, { contenu: false }).valeur;
    case "bytes": return a.value.toString("base64");
    default: return null;
  }
}

/**
 * A(liste) d'EX-6.31 : objet `key` → V ; la première occurrence d'une clé est
 * gardée, les suivantes comptées (`otel_cle_double`, à tout niveau,
 * `kvlist_value` comprises) ; un `keyStrindex` sans `key` fait ignorer
 * l'attribut ; avec `contenu` (attributs du span seulement, EX-6.31), les six
 * attributs de contenu en chaîne JSON stricte sont remplacés par la valeur
 * analysée. Rend { valeur, doubles }.
 */
export function attributs(liste, compte = { doubles: 0 }, { contenu = true } = {}) {
  const o = {};
  for (const kv of liste ?? []) {
    if (kv.key === null) continue;
    if (Object.hasOwn(o, kv.key)) {
      compte.doubles++;
      continue;
    }
    let v = valeurAnyValue(kv.value, compte);
    if (contenu && CONTENU.has(kv.key) && typeof v === "string") {
      try {
        v = C.analyserJSONIntegral(Buffer.from(v, "utf8"));
      } catch {
        /* chaîne gardée */
      }
    }
    Object.defineProperty(o, kv.key, { value: v, enumerable: true, writable: true, configurable: true });
  }
  return { valeur: o, doubles: compte.doubles };
}

/** Forme normalisée N(S) d'un span (EX-6.31), noms de champs proto en snake_case. */
export function formeNormalisee(rs, ss, s, compte = { doubles: 0 }) {
  // Les attributs de contenu ne sont analysés que dans les attributs du span (EX-6.31).
  const A = (liste, contenu = false) => attributs(liste, compte, { contenu }).valeur;
  return {
    trace_id: s.traceId,
    span_id: s.spanId,
    parent_span_id: s.parentSpanId === "" ? null : s.parentSpanId,
    trace_state: s.traceState,
    name: s.name,
    flags: s.flags,
    kind: s.kind,
    start_time_unix_nano: s.startTimeUnixNano.toString(),
    end_time_unix_nano: s.endTimeUnixNano.toString(),
    attributes: A(s.attributes, true),
    dropped_attributes_count: s.droppedAttributesCount,
    dropped_events_count: s.droppedEventsCount,
    dropped_links_count: s.droppedLinksCount,
    events: s.events.map((e) => ({ name: e.name, time_unix_nano: e.timeUnixNano.toString(), attributes: A(e.attributes), dropped_attributes_count: e.droppedAttributesCount })),
    links_count: s.links,
    status: { code: s.status?.code ?? 0, message: s.status?.message ?? "" },
    resource: { attributes: A(rs.resource?.attributes), dropped_attributes_count: rs.resource?.droppedAttributesCount ?? 0 },
    scope: { name: ss.scope?.name ?? "", version: ss.scope?.version ?? "", attributes: A(ss.scope?.attributes) },
    schema_url: ss.schemaUrl !== "" ? ss.schemaUrl : rs.schemaUrl !== "" ? rs.schemaUrl : null,
  };
}

// ---------------------------------------------------------------------------
// Classification (EX-6.32), doublons (EX-6.33), recouvrement (EX-6.34)
// ---------------------------------------------------------------------------

/** Opérations GenAI retenues et leur sorte (EX-6.32). */
export const SORTES = Object.freeze({ chat: "inference", generate_content: "inference", text_completion: "inference", execute_tool: "outil" });

/** Opération d'un span : `gen_ai.operation.name`, à défaut `execute_tool` pour `mcp.method.name` = `tools/call`, sinon null. */
export function operation(N) {
  const op = N.attributes["gen_ai.operation.name"];
  if (typeof op === "string") return op;
  return N.attributes["mcp.method.name"] === "tools/call" ? "execute_tool" : null;
}

const idValide = (h, n) => typeof h === "string" && h.length === n && /^[0-9a-f]+$/.test(h) && !/^0+$/.test(h);

/**
 * Classe un span (EX-6.32) : { sorte, issue: "retenu" | "ignore" | "rejete",
 * raison }. `sourcePolitique` : l'entrée `policy.otel.sources.<alias>`.
 */
export function classer(N, sourcePolitique) {
  const op = operation(N);
  if (op === null) return { sorte: null, issue: "ignore", raison: "hors_genai" };
  const sorte = SORTES[op] ?? null;
  if (sorte === null) return { sorte: null, issue: "ignore", raison: "operation_non_retenue" };
  if (!(sourcePolitique?.ingest ?? []).includes(sorte)) return { sorte, issue: "ignore", raison: "sorte_desactivee" };
  if (!idValide(N.trace_id, 32) || !idValide(N.span_id, 16) || (N.parent_span_id !== null && !idValide(N.parent_span_id, 16))) return { sorte, issue: "rejete", raison: "identifiants_invalides" };
  return { sorte, issue: "retenu", raison: null };
}

/**
 * Table des doublons (EX-6.33) : clés (alias, trace_id, span_id) des spans
 * scellés ou écartés comme recouvrements, gardées `fenetreMs`, au plus
 * `max` clés, les plus anciennes sortant les premières (sorties comptées,
 * `otel_dedup_evicted`).
 */
export class TableDoublons {
  constructor({ fenetreMs = 3600000, max = DOUBLONS_MAX } = {}) {
    this.fenetreMs = fenetreMs;
    this.max = max;
    this.cles = new Map();
    this.empreintes = new Map();
    this.sorties = 0;
  }
  static cle(alias, trace_id, span_id) {
    return `${alias}\u0000${trace_id}\u0000${span_id}`;
  }
  purger(t) {
    for (const [k, at] of this.cles) {
      if (at >= t - this.fenetreMs) break;
      this.cles.delete(k);
    }
  }
  contient(cle, t) {
    this.purger(t);
    return this.cles.has(cle);
  }
  /** Empreinte de la forme normalisée gardée avec la clé (EX-6.33), ou null si inconnue. */
  empreinte(cle) {
    return this.empreintes.get(cle) ?? null;
  }
  ajouter(cle, t, empreinte = null) {
    this.cles.delete(cle);
    this.cles.set(cle, t);
    if (empreinte !== null) this.empreintes.set(cle, empreinte);
    while (this.cles.size > this.max) {
      const k = this.cles.keys().next().value;
      this.cles.delete(k);
      this.empreintes.delete(k);
      this.sorties++;
    }
  }
}

/**
 * Registre de recouvrement (EX-6.34) : par groupe d'hôte, les appels d'outils
 * et échanges scellés par le frontal MCP, la passerelle ou le SDK
 * (`{ kind, channel, host_group, seen_name | model, t, seq }`), avec leur
 * appariement. `apparier` rend l'entrée la plus ancienne non appariée de la
 * fenêtre `[t − fenetreMs, t]` et la marque appariée, ou null.
 */
export class RegistreRecouvrement {
  constructor(entrees = [], { fenetreMs = 600000 } = {}) {
    this.fenetreMs = fenetreMs;
    this.entrees = entrees.map((e) => ({ ...e, apparie: false }));
  }
  inscrire(e) {
    this.entrees.push({ ...e, apparie: false });
  }
  apparier({ host_group, sorte, nom, t }) {
    const kind = sorte === "outil" ? "appel_outil" : "echange_modele";
    let meilleur = null;
    for (const e of this.entrees) {
      if (e.apparie || e.host_group !== host_group || e.kind !== kind) continue;
      if (e.t < t - this.fenetreMs || e.t > t) continue;
      if ((sorte === "outil" ? e.seen_name : e.model) !== nom) continue;
      if (meilleur === null || e.t < meilleur.t) meilleur = e;
    }
    if (meilleur) meilleur.apparie = true;
    return meilleur;
  }
}

// ---------------------------------------------------------------------------
// Pièces (EX-6.35) et événement (EX-6.36)
// ---------------------------------------------------------------------------

/** Pièce de déclaration de source (EX-6.35 pas 1) : JCS intégral, sans rédaction, ses octets ne dépendent que de l'alias. */
export const pieceDeclarationSource = (alias) => C.pieceDeclarationCanal("otel", alias);

const estSortie = (k) => k === "gen_ai.output.messages" || k === "gen_ai.completion" || k.startsWith("gen_ai.response.") || k.startsWith("gen_ai.usage.");
const RE_FOURNISSEUR = /^[a-z0-9][a-z0-9._-]{0,31}$/;
const RE_NOM_DECLARE = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/;
const RE_RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

/** Texte du prompt système d'un span d'inférence (EX-6.35 pas 2) : morceaux, ou null. */
function morceauxPromptOtel(req) {
  const t = [];
  const si = req["gen_ai.system_instructions"];
  if (typeof si === "string") t.push(si);
  else if (Array.isArray(si)) for (const p of si) if (estObjet(p) && p.type === "text" && typeof p.content === "string") t.push(p.content);
  const im = req["gen_ai.input.messages"];
  if (Array.isArray(im)) for (const m of im) if (estObjet(m) && m.role === "system" && Array.isArray(m.parts)) for (const p of m.parts) if (estObjet(p) && p.type === "text" && typeof p.content === "string") t.push(p.content);
  return t;
}
/** Applique `f` à chaque chaîne porteuse du prompt dans une copie de Req (EX-6.35 pas 2). */
function surChainesPrompt(req, f) {
  const r = C.copieJSON(req);
  if (Object.hasOwn(r, "gen_ai.system_instructions")) {
    const si = r["gen_ai.system_instructions"];
    if (typeof si === "string") r["gen_ai.system_instructions"] = f(si, true);
    else if (Array.isArray(si)) {
      let porteur = false;
      for (const p of si) if (estObjet(p) && p.type === "text" && typeof p.content === "string") porteur = true;
      if (f.remplacer) r["gen_ai.system_instructions"] = C.JETON_PROMPT_SYSTEME;
      else if (porteur) for (const p of si) if (estObjet(p) && p.type === "text" && typeof p.content === "string") p.content = f(p.content, false);
    } else if (f.remplacer) r["gen_ai.system_instructions"] = C.JETON_PROMPT_SYSTEME;
  }
  const im = r["gen_ai.input.messages"];
  if (Array.isArray(im)) for (const m of im) if (estObjet(m) && m.role === "system" && Array.isArray(m.parts)) for (const p of m.parts) if (estObjet(p) && p.type === "text" && typeof p.content === "string") p.content = f(p.content, false);
  return r;
}
/** Texte de sortie (intent, EX-6.36) : `content` chaînes des parts `text` du premier message de `gen_ai.output.messages`, joints par `\n`. */
function texteSortie(resp) {
  const om = resp?.["gen_ai.output.messages"];
  if (!Array.isArray(om) || !estObjet(om[0]) || !Array.isArray(om[0].parts)) return null;
  const t = om[0].parts.filter((p) => estObjet(p) && p.type === "text" && typeof p.content === "string").map((p) => p.content);
  return t.length ? t.join("\n") : null;
}
/** Nom déclaré N d'un span d'outil (EX-6.35 pas 3). */
export function nomDeclare(N) {
  const g = N.attributes["gen_ai.tool.name"];
  if (typeof g === "string" && g !== "") return g;
  if (N.name.startsWith("execute_tool ")) return N.name.slice("execute_tool ".length);
  if (N.name.startsWith("tools/call ")) return N.name.slice("tools/call ".length);
  return "";
}
/** Nom de l'outil `<alias>__<N>` ou `<alias>__nom-invalide` (EX-6.35 pas 3). */
export function nomOutil(alias, N) {
  const valide = RE_NOM_DECLARE.test(N) && !N.includes("__") && !N.startsWith("noortrace.") && C.longueurPointsDeCode(`${alias}__${N}`) <= 128;
  return { tool: `${alias}__${valide ? N : "nom-invalide"}`, original: valide ? N : "nom-invalide", valide };
}
/** `execution.duration_ms` (EX-6.36) : ⌊(fin − début) / 10^6⌋ si les deux sont non nuls et fin ≥ début, borné à 2^53 − 1 ; sinon 0. */
export function dureeSpan(N) {
  const a = BigInt(N.start_time_unix_nano);
  const b = BigInt(N.end_time_unix_nano);
  if (a === 0n || b === 0n || b < a) return 0;
  const d = (b - a) / 1000000n;
  return d > MAX_SUR ? Number(MAX_SUR) : Number(d);
}
/** `execution.is_error` (EX-6.36) : `status.code` 2, ou `error.type` chaîne non vide. */
export const erreurSpan = (N) => N.status.code === 2 || (typeof N.attributes["error.type"] === "string" && N.attributes["error.type"] !== "");

/**
 * Pièce d'enveloppe (EX-6.35) : N(S) dont `attributes` ne garde que les
 * attributs choisis par `garder`. Les règles de portée `contexte` ne
 * s'appliquent qu'aux membres textuels de N(S) (`name`, `trace_state`,
 * `attributes`, `events[].name`, `events[].attributes`, `status.message`,
 * `resource`, `scope`, `schema_url`), lus dans une projection de mêmes
 * pointeurs ; les membres structurels (`trace_id`, `span_id`,
 * `parent_span_id`, `flags`, `kind`, horodatages, `events[].time_unix_nano`,
 * compteurs) restent tels quels : un horodatage de 19 chiffres qui passe
 * Luhn n'est pas un numéro de carte (EX-6.38 : l'ordre déclaré des actes
 * se lit dans cette pièce).
 */
function enveloppe(N, garder, { politique, outil, budgetMs, onDepassement }) {
  const e = C.copieJSON(N);
  const a = {};
  for (const k of Object.keys(e.attributes)) if (garder(k)) Object.defineProperty(a, k, { value: e.attributes[k], enumerable: true, writable: true, configurable: true });
  e.attributes = a;
  const projection = {
    name: e.name,
    trace_state: e.trace_state,
    attributes: e.attributes,
    events: e.events.map((ev) => ({ name: ev.name, attributes: ev.attributes })),
    status: { message: e.status.message },
    resource: e.resource,
    scope: e.scope,
    schema_url: e.schema_url,
  };
  const r = C.rediger(politique, projection, { portee: "contexte", outil, budgetMs, onDepassement });
  if (r.depasse) return C.pieceNonRedigeable({ content_type: null, length: Buffer.byteLength(J.canonicaliserJCSIntegral(e), "utf8"), reason: "budget_redaction" }, r.notes);
  const t = r.valeur ?? {};
  const pris = (o, k) => (estObjet(o) && Object.hasOwn(o, k) ? { v: o[k] } : null);
  const sortie = {};
  const poser = (k, v) => Object.defineProperty(sortie, k, { value: v, enumerable: true, writable: true, configurable: true });
  for (const k of Object.keys(e)) {
    if (k === "events") {
      const evs = Array.isArray(t.events) ? t.events : [];
      poser(k, e.events.map((ev, i) => {
        const o = {};
        const p = estObjet(evs[i]) ? evs[i] : {};
        if (Object.hasOwn(p, "name")) o.name = p.name;
        o.time_unix_nano = ev.time_unix_nano;
        if (Object.hasOwn(p, "attributes")) o.attributes = p.attributes;
        o.dropped_attributes_count = ev.dropped_attributes_count;
        return o;
      }));
    } else if (k === "status") {
      const m = pris(t.status, "message");
      poser(k, m ? { code: e.status.code, message: m.v } : { code: e.status.code });
    } else if (Object.hasOwn(projection, k)) {
      const m = pris(t, k);
      if (m) poser(k, m.v);
    } else poser(k, e[k]);
  }
  const octets = C.octetsJCSIntegral(sortie);
  const redacted = J.canonicaliserJCSIntegral(sortie) !== J.canonicaliserJCSIntegral(e);
  return { valeur: sortie, octets, reference: C.referencePiece(octets, { redacted, media_type: "application/json" }), correspondances: r.correspondances, notes: r.notes };
}

/**
 * Pièces d'un span retenu (EX-6.35). `source` : { alias, host:
 * { prompt_version_name }, policy_source }, `options` : { prompt_in_request,
 * prompt_system } ; `politique` : politique de rédaction chargée. Rend
 * { source, envelope, request | arguments, response | result, system_prompt,
 * intent (pièce ou null), tool, original, intention }.
 */
export function piecesSpan(N, sorte, { source, options = {}, politique = null, budgetMs = C.BUDGET_REDACTION_MS, onDepassement = null }) {
  const declaration = pieceDeclarationSource(source.alias);
  if (sorte === "outil") {
    const n = nomDeclare(N);
    const { tool, original } = nomOutil(source.alias, n);
    const a = Object.hasOwn(N.attributes, "gen_ai.tool.call.arguments") ? N.attributes["gen_ai.tool.call.arguments"] : { noortrace_otel_absent: "gen_ai.tool.call.arguments" };
    const r = Object.hasOwn(N.attributes, "gen_ai.tool.call.result") ? N.attributes["gen_ai.tool.call.result"] : { noortrace_otel_absent: "gen_ai.tool.call.result" };
    const args = C.pieceJSON(a, { politique, portee: "arguments", outil: tool, budgetMs, onDepassement });
    const result = C.pieceJSON(r, { politique, portee: "resultat", outil: tool, budgetMs, onDepassement });
    const envelope = enveloppe(N, (k) => k !== "gen_ai.tool.call.arguments" && k !== "gen_ai.tool.call.result", { politique, outil: tool, budgetMs, onDepassement });
    return { source: declaration, envelope, arguments: args, result, system_prompt: null, intent: null, tool, original, nom: n };
  }
  const req = {};
  const resp = {};
  for (const k of Object.keys(N.attributes)) {
    if (!k.startsWith("gen_ai.") && !estSortie(k)) continue;
    Object.defineProperty(estSortie(k) ? resp : req, k, { value: N.attributes[k], enumerable: true, writable: true, configurable: true });
  }
  const morceaux = morceauxPromptOtel(req);
  const T = morceaux.length ? morceaux.join("\n") : null;
  let system_prompt = null;
  if (T !== null) system_prompt = options.prompt_system === "named" ? C.pieceTexte(`[PROMPT:${source.host?.prompt_version_name}]`) : C.pieceTexte(T, { politique, portee: "prompt_systeme", budgetMs, onDepassement });
  const inline = options.prompt_in_request === "inline";
  let reqStockee = req;
  let horsBudget = false;
  if (T !== null) {
    // En ligne, la rédaction des chaînes du prompt tient dans la borne de temps d'EX-10.23 : au-delà, la pièce « requête » est la pièce non rédigeable.
    if (inline) {
      reqStockee = surChainesPrompt(req, (s) => {
        if (!politique || horsBudget) return s;
        const r = C.rediger(politique, s, { portee: "prompt_systeme", budgetMs, onDepassement });
        if (r.depasse) {
          horsBudget = true;
          return s;
        }
        return r.valeur;
      });
    } else {
      const remplacer = () => C.JETON_PROMPT_SYSTEME;
      remplacer.remplacer = true;
      reqStockee = surChainesPrompt(req, remplacer);
    }
  }
  const request = horsBudget ? C.pieceNonRedigeable({ content_type: null, length: Buffer.byteLength(J.canonicaliserJCSIntegral(req), "utf8"), reason: "budget_redaction" }) : C.pieceJSON(reqStockee, { politique, portee: "requete", budgetMs, onDepassement });
  // EX-8.5 : le remplacement par le jeton marque la requête rédigée ; en ligne, elle l'est si une règle a changé la valeur.
  if (!request.nonRedigeable) {
    const redacted = (T !== null && !inline) || J.canonicaliserJCSIntegral(request.valeur) !== J.canonicaliserJCSIntegral(req);
    request.reference = C.referencePiece(request.octets, { redacted });
  }
  const response = C.pieceJSON(resp, { politique, portee: "reponse", budgetMs, onDepassement });
  const intention = C.intentionRedigee(response.nonRedigeable ? null : texteSortie(response.valeur), texteSortie(resp));
  const envelope = enveloppe(N, (k) => !k.startsWith("gen_ai."), { politique, outil: null, budgetMs, onDepassement });
  return { source: declaration, envelope, request, response, system_prompt, intent: intention.piece, intention };
}

/** Modèle M d'un span d'inférence (EX-6.36), lu dans les pièces rédigées. */
export function modeleSpan(p) {
  const rm = p.response?.valeur?.["gen_ai.response.model"];
  if (typeof rm === "string" && rm !== "") return rm;
  const qm = p.request?.valeur?.["gen_ai.request.model"];
  return typeof qm === "string" && qm !== "" ? qm : null;
}
/** Fournisseur (EX-6.36) : `gen_ai.provider.name`, à défaut `gen_ai.system`, de la requête rédigée, s'il respecte le motif ; sinon `inconnu`. */
export function fournisseurSpan(p) {
  const v = p.request?.valeur ?? {};
  const f = Object.hasOwn(v, "gen_ai.provider.name") ? v["gen_ai.provider.name"] : v["gen_ai.system"];
  return typeof f === "string" && RE_FOURNISSEUR.test(f) ? f : "inconnu";
}

/** `delegation.run_id` (EX-6.36) : `gen_ai.conversation.id` si l'entrée l'admet et qu'il passe EX-7.2 (motif et détecteurs). */
export function runIdSpan(N, host, politique, { budgetMs = C.BUDGET_REDACTION_MS, onDepassement = null } = {}) {
  const v = N.attributes["gen_ai.conversation.id"];
  if (host?.accept_declared_delegation !== true || typeof v !== "string" || !RE_RUN_ID.test(v)) return null;
  return C.examinerValeurEnLigne(politique, v, { budgetMs, onDepassement, scope: "run_id" }).correspondance ? null : v;
}

const ctx = (p) => ({ ...p.reference, kind: "autre" });

/**
 * Événement partiel d'un span retenu (EX-6.36), sans l'enveloppe de CT-1
 * (`version` à `prev_hash`, que l'écrivain pose avec son `ts`). `source` :
 * { alias, host: { launched_by, on_behalf_of, scope, accept_declared_delegation },
 * policy_source, policy_version }.
 */
export function partielSpan(N, sorte, pieces, { source, politique = null, budgetMs = C.BUDGET_REDACTION_MS, onDepassement = null }) {
  const nomRedaction = politique?.name ?? null;
  const delegation = { launched_by: source.host.launched_by, on_behalf_of: source.host.on_behalf_of ?? null, scope: source.host.scope, run_id: runIdSpan(N, source.host, politique, { budgetMs, onDepassement }) };
  const context = [ctx(pieces.source), ctx(pieces.envelope)];
  if (sorte === "inference") {
    const M = modeleSpan(pieces);
    const p = C.partielEchangeModele({
      delegation,
      code: { model: M === null ? null : C.tronquer(`${fournisseurSpan(pieces)}/${M}`, 256), prompt_version: pieces.system_prompt ? pieces.system_prompt.reference.sha256 : null, policy_version: source.policy_version, recorder: C.VERSION_ENREGISTREUR },
      intent: pieces.intention.intent,
      requete: pieces.request.reference,
      reponse: pieces.response.reference,
      duration_ms: dureeSpan(N),
      is_error: erreurSpan(N),
      nomRedaction,
    });
    p.context = context;
    p.policy.redaction = C.redactionDe(nomRedaction, [p.execution.arguments, p.execution.result, typeof p.intent === "object" ? p.intent : null, ...p.context]);
    return p;
  }
  const reglage = source.policy_source?.tools?.[pieces.nom] ?? null;
  const classe = reglage?.class ?? source.policy_source?.class_default ?? "ecriture";
  const defaut = C.effetsParDefaut({ classe, alias: source.alias, original: pieces.original });
  let effects = defaut;
  if (Array.isArray(reglage?.effects) && reglage.effects.length > 0) {
    effects = C.evaluerGabaritsEffets(reglage.effects, { arguments: pieces.arguments.valeur, result: pieces.result.valeur, budgetMs, onDepassement, defaut }).effects;
  }
  return C.partielAppelOutil({
    delegation,
    code: { model: null, prompt_version: null, policy_version: source.policy_version, recorder: C.VERSION_ENREGISTREUR },
    intent: null,
    policy: { rule: null, decision: "autorise", ticket: null },
    tool: pieces.tool,
    arguments: pieces.arguments.reference,
    status: "executee",
    result: pieces.result.reference,
    duration_ms: dureeSpan(N),
    is_error: erreurSpan(N),
    effects,
    context,
    nomRedaction,
  });
}

// ---------------------------------------------------------------------------
// Réponses (EX-6.27) et traitement d'une requête OTLP (EX-6.26 à EX-6.38)
// ---------------------------------------------------------------------------

const texteSucces = (n) => `noortrace: ${n} span(s) rejete(s), identifiants invalides`;

/** Corps de réponse exact (EX-6.27) : `encodage` = "json" ou "protobuf" ; `rejetes` = nombre de spans rejetés, ou `refus` = statut HTTP. */
export function corpsReponse(encodage, { rejetes = 0, refus = null } = {}) {
  if (refus !== null) {
    const texte = TEXTES_REFUS[refus];
    return encodage === "protobuf" ? len(2, Buffer.from(texte, "utf8")) : Buffer.from(JSON.stringify({ message: texte }), "utf8");
  }
  if (rejetes === 0) return encodage === "protobuf" ? Buffer.alloc(0) : Buffer.from("{}", "utf8");
  if (encodage === "protobuf") return len(1, Buffer.concat([varintChamp(1, rejetes), chaine(2, texteSucces(rejetes))]));
  return Buffer.from(JSON.stringify({ partialSuccess: { rejectedSpans: String(rejetes), errorMessage: texteSucces(rejetes) } }), "utf8");
}

/**
 * Traite une requête OTLP/HTTP (EX-6.26 à EX-6.38), sans réseau ni
 * écriture : `requete` = { methode, chemin, entetes: { "content-type",
 * "content-encoding", token_id }, corps } ; `contexte` = { source: { alias,
 * host, policy_source, policy_version }, jeton (id du jeton de la source),
 * options: { path, encodings, max_body_bytes, json_max_depth,
 * json_max_members, dedup_window_ms, overlap_window_ms, retry_after_s,
 * prompt_in_request, prompt_system }, politique, t_reception (ms), doublons
 * (TableDoublons), recouvrement (RegistreRecouvrement), degrade, quota }.
 * Rend { status, contentType, corps, retryAfter, rejetes, spans, partiels,
 * compteurs, journal } : `spans` dans l'ordre du document ({ path, trace_id,
 * span_id, issue, reason, overlap_seq, normalized, pieces, partiel }),
 * `partiels` les événements partiels à sceller dans l'ordre (EX-6.38).
 */
export function traiterRequete({ methode, chemin, entetes = {}, corps }, contexte) {
  const o = contexte.options ?? {};
  const encodings = o.encodings ?? ["protobuf", "json"];
  const media = C.typeDeMedia(entetes["content-type"] ?? null);
  const encodage = media === TYPE_PROTOBUF && encodings.includes("protobuf") ? "protobuf" : media === TYPE_JSON && encodings.includes("json") ? "json" : null;
  const contentType = encodage === "protobuf" ? TYPE_PROTOBUF : TYPE_JSON;
  const compteurs = { scelle: 0, ignore: 0, doublon: 0, recouvrement: 0, rejete: 0 };
  const journal = [];
  const brut = String(chemin ?? "");
  const iq = brut.indexOf("?");
  // Une chaîne de requête est ignorée et consignée, sans sa valeur (EX-6.26).
  const chaineRequete = iq >= 0;
  const codage = entetes["content-encoding"];
  const recus = Buffer.from(corps ?? []).length;
  const ligneRequete = (status, decodes = null) => ({ event: "otel_request", data: { source: contexte.source?.alias ?? null, content_type: media, encoding: codage ?? null, query_string: chaineRequete, received_bytes: recus, decoded_bytes: decodes, spans: 0, ...compteurs, status } });
  const reponse = (status, extra = {}) => {
    journal.push({ event: "otel_refused", data: { status, reason: extra.raison ?? null } });
    if (status === 401) journal.push({ event: "auth_failed", data: { component: "otel" } });
    // Toute requête est consignée par otel_request, refus compris (6.8.14).
    journal.push(ligneRequete(status));
    return { status, contentType, corps: corpsReponse(encodage ?? "json", { refus: status }), retryAfter: status === 429 || status === 503 ? (o.retry_after_s ?? 5) : null, rejetes: 0, spans: [], partiels: [], compteurs, journal, allow: status === 405 ? "POST" : null };
  };
  // Ordre des décisions (EX-6.27) : chemin (404, normalisation refusée comprise), méthode (405), jeton (401),
  // quota (429), mode dégradé (503), type de contenu (415), codage de contenu (415), taille reçue (413),
  // gzip invalide (400) ou taille décomprimée (413), décodage et bornes (400).
  const n = C.normaliserChemin(iq >= 0 ? brut.slice(0, iq) : brut);
  if (n.refus || n.chemin !== (o.path ?? "/v1/traces")) return reponse(404, { raison: "chemin" });
  if (methode !== "POST") return reponse(405, { raison: "methode" });
  if (entetes.token_id === null || entetes.token_id === undefined || entetes.token_id !== contexte.jeton) return reponse(401, { raison: "authentification" });
  if (contexte.quota) return reponse(429, { raison: "quota" });
  if (contexte.degrade) return reponse(503, { raison: contexte.degrade });
  if (encodage === null) return reponse(415, { raison: "type_de_contenu" });
  const gzip = codage !== undefined && codage !== null && String(codage).toLowerCase() !== "identity";
  if (gzip && String(codage).toLowerCase() !== "gzip") return reponse(415, { raison: "codage" });
  const max = o.max_body_bytes ?? 67108864;
  let octets = Buffer.from(corps ?? []);
  if (octets.length > max) return reponse(413, { raison: "taille" });
  if (gzip) {
    try {
      octets = zlib.gunzipSync(octets, { maxOutputLength: max });
    } catch (e) {
      if (e?.code === "ERR_BUFFER_TOO_LARGE" || e instanceof RangeError) return reponse(413, { raison: "taille_decomprimee" });
      return reponse(400, { raison: "gzip" });
    }
  }
  const bornes = { profondeurMax: o.json_max_depth ?? C.PROFONDEUR_JSON_MAX, membresMax: o.json_max_members ?? C.MEMBRES_JSON_MAX };
  let logique;
  try {
    logique = encodage === "protobuf" ? decoderProtobuf(octets, bornes) : decoderJSON(octets, bornes);
  } catch (e) {
    if (e instanceof ErreurOTLP) return reponse(e.status, { raison: e.raison });
    throw e;
  }
  // Nombre de spans d'une requête (EX-6.28, quota.spans_per_request) : au-delà, 413, rien n'est scellé.
  const totalSpans = logique.resourceSpans.reduce((n, rs) => n + rs.scopeSpans.reduce((m, ss) => m + ss.spans.length, 0), 0);
  if (Number.isInteger(o.spans_per_request) && totalSpans > o.spans_per_request) return reponse(413, { raison: "spans_par_requete" });
  const { source, politique = null } = contexte;
  const t = contexte.t_reception;
  // Événements encore admis dans la minute glissante (EX-6.28, quota.events_per_minute), contrôlés span par span :
  // au-delà, les spans déjà scellés restent, la réponse est 429 et le lot renvoyé donne des doublons.
  const restants = Number.isInteger(contexte.evenements_restants) ? contexte.evenements_restants : Infinity;
  let quotaAtteint = false;
  const doublons = contexte.doublons ?? new TableDoublons({ fenetreMs: o.dedup_window_ms ?? 3600000 });
  const sortiesAvant = doublons.sorties;
  const recouvrement = contexte.recouvrement ?? new RegistreRecouvrement([], { fenetreMs: o.overlap_window_ms ?? 600000 });
  const vus = new Map();
  const spans = [];
  const partiels = [];
  const compte = { doubles: 0 };
  logique.resourceSpans.forEach((rs, r) => rs.scopeSpans.forEach((ss, s) => ss.spans.forEach((sp, k) => {
    if (quotaAtteint) return;
    const N = formeNormalisee(rs, ss, sp, compte);
    const c = classer(N, source.policy_source);
    const entree = { path: [r, s, k], trace_id: N.trace_id, span_id: N.span_id, issue: null, reason: c.raison, overlap_seq: null, normalized: N, pieces: null, partiel: null, sorte: c.sorte };
    spans.push(entree);
    if (c.issue === "ignore") {
      entree.issue = "ignore";
      entree.normalized = null;
      compteurs.ignore++;
      return;
    }
    if (c.issue === "rejete") {
      entree.issue = "rejete";
      compteurs.rejete++;
      journal.push({ event: "otel_span_rejected", data: { trace_id: N.trace_id, span_id: N.span_id, reason: c.raison } });
      return;
    }
    const cle = TableDoublons.cle(source.alias, N.trace_id, N.span_id);
    // Empreinte de N(S) gardée avec la clé : un même span rejoué avec un autre contenu est signalé (EX-6.33).
    const empreinte = J.sha256(Buffer.from(J.canonicaliserJCSIntegral(N), "utf8"));
    if (vus.has(cle) || doublons.contient(cle, t)) {
      entree.issue = "doublon";
      compteurs.doublon++;
      const connue = vus.get(cle) ?? doublons.empreinte(cle);
      if (connue !== null && connue !== undefined && connue !== empreinte) journal.push({ event: "otel_span_conflict", data: { trace_id: N.trace_id, span_id: N.span_id, sha256_connu: connue, sha256_recu: empreinte } });
      if (!vus.has(cle)) vus.set(cle, empreinte);
      return;
    }
    if (compteurs.scelle >= restants) {
      quotaAtteint = true;
      spans.pop();
      return;
    }
    vus.set(cle, empreinte);
    const pieces = piecesSpan(N, c.sorte, { source, options: o, politique });
    if (source.policy_source?.overlap !== "conserver") {
      const nom = c.sorte === "outil" ? pieces.nom : modeleSpan(pieces);
      const apparie = nom === null ? null : recouvrement.apparier({ host_group: source.host.host_group, sorte: c.sorte, nom, t });
      if (apparie) {
        entree.issue = "recouvrement";
        entree.overlap_seq = apparie.seq;
        compteurs.recouvrement++;
        doublons.ajouter(cle, t, empreinte);
        journal.push({ event: "otel_span_overlap", data: { trace_id: N.trace_id, span_id: N.span_id, seq: apparie.seq } });
        return;
      }
    }
    entree.issue = "scelle";
    entree.pieces = pieces;
    entree.partiel = partielSpan(N, c.sorte, pieces, { source, politique });
    partiels.push(entree.partiel);
    compteurs.scelle++;
    doublons.ajouter(cle, t, empreinte);
  })));
  if (compte.doubles) journal.push({ event: "otel_cle_double", data: { count: compte.doubles } });
  if (quotaAtteint) {
    const q = reponse(429, { raison: "evenements_par_minute" });
    return { ...q, rejetes: compteurs.rejete, spans, partiels, compteurs };
  }
  // Seules les sorties de cette requête sont consignées (EX-6.33).
  if (doublons.sorties > sortiesAvant) journal.push({ event: "otel_dedup_evicted", data: { count: doublons.sorties - sortiesAvant } });
  journal.push({ ...ligneRequete(200, octets.length), data: { ...ligneRequete(200, octets.length).data, spans: spans.length } });
  return { status: 200, contentType, corps: corpsReponse(encodage, { rejetes: compteurs.rejete }), retryAfter: null, rejetes: compteurs.rejete, spans, partiels, compteurs, journal, allow: null };
}

/**
 * Scelle les partiels d'une requête dans une chaîne (EX-6.38) : `seq_start`,
 * `prev_hash`, un `ts` de l'écrivain par événement (EX-6.36 : jamais un
 * horodatage du span). Rend les événements de CT-1.
 */
export function scellerPartiels(partiels, { seq_start, prev_hash, ts, org_id, journal_id, recorder_key_id, cle }) {
  let prev = prev_hash;
  return partiels.map((p, i) => {
    const ev = J.scellerEvenement({ version: 0, seq: seq_start + i, ts: ts[i], org_id, journal_id, recorder_key_id, prev_hash: prev, ...p }, cle);
    prev = ev.hash;
    return ev;
  });
}

/** Retard de réception (EX-6.41, `noortrace_otel_reception_lag_ms`) : `ts` moins la fin déclarée du span, en millisecondes, 0 si négatif ; null sans fin déclarée. */
export function retardReception(ts, N) {
  const fin = BigInt(N.end_time_unix_nano);
  if (fin === 0n) return null;
  const d = BigInt(J.msHorodatage(ts)) * 1000000n - fin;
  return d <= 0n ? 0 : Number(d / 1000000n);
}
