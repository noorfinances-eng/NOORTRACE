// Décodage protobuf d'un `ExportTraceServiceRequest` (CT-2 EX-6.30 ;
// `opentelemetry-proto` v1.11.1, champs de la table d'EX-6.30). Écrit à neuf
// sur l'encodage binaire de proto3, sans bibliothèque : un champ dont le type
// de fil ne correspond pas à la table, une étiquette de champ 0, un type de
// fil 3, 4, 6 ou 7, un varint de plus de dix octets, une longueur qui dépasse
// le message englobant, un corps tronqué, un champ non répété présent deux
// fois, deux membres du `oneof` d'`AnyValue`, une chaîne qui n'est pas de
// l'UTF-8 valide, `bool_value` autre que 0 ou 1 : refus (400). Un champ de
// numéro inconnu est sauté selon son type de fil (0, 1, 2, 5). Les bornes de
// profondeur et de membres s'appliquent à l'imbrication des `array_value` et
// `kvlist_value` et au nombre de leurs éléments.

import { ErreurDecodage, BORNES_32, valeurAbsente } from "./representation.mjs";

const VARINT = 0;
const I64 = 1;
const LEN = 2;
const I32 = 5;
const DECODEUR = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Champs lus, par message : numéro → `[nom, type de fil, répété]`.
 * `entity_refs` (Resource, 3) est sauté comme un champ inconnu.
 */
const CHAMPS = {
  requete: { 1: ["resource_spans", LEN, true] },
  resourceSpans: { 1: ["resource", LEN, false], 2: ["scope_spans", LEN, true], 3: ["schema_url", LEN, false] },
  resource: { 1: ["attributes", LEN, true], 2: ["dropped_attributes_count", VARINT, false] },
  scopeSpans: { 1: ["scope", LEN, false], 2: ["spans", LEN, true], 3: ["schema_url", LEN, false] },
  scope: { 1: ["name", LEN, false], 2: ["version", LEN, false], 3: ["attributes", LEN, true], 4: ["dropped_attributes_count", VARINT, false] },
  span: {
    1: ["trace_id", LEN, false],
    2: ["span_id", LEN, false],
    3: ["trace_state", LEN, false],
    4: ["parent_span_id", LEN, false],
    5: ["name", LEN, false],
    6: ["kind", VARINT, false],
    7: ["start_time_unix_nano", I64, false],
    8: ["end_time_unix_nano", I64, false],
    9: ["attributes", LEN, true],
    10: ["dropped_attributes_count", VARINT, false],
    11: ["events", LEN, true],
    12: ["dropped_events_count", VARINT, false],
    13: ["links", LEN, true],
    14: ["dropped_links_count", VARINT, false],
    15: ["status", LEN, false],
    16: ["flags", I32, false],
  },
  event: { 1: ["time_unix_nano", I64, false], 2: ["name", LEN, false], 3: ["attributes", LEN, true], 4: ["dropped_attributes_count", VARINT, false] },
  status: { 2: ["message", LEN, false], 3: ["code", VARINT, false] },
  keyValue: { 1: ["key", LEN, false], 2: ["value", LEN, false], 3: ["key_strindex", VARINT, false] },
  anyValue: {
    1: ["string_value", LEN, false],
    2: ["bool_value", VARINT, false],
    3: ["int_value", VARINT, false],
    4: ["double_value", I64, false],
    5: ["array_value", LEN, false],
    6: ["kvlist_value", LEN, false],
    7: ["bytes_value", LEN, false],
    8: ["string_value_strindex", VARINT, false],
  },
  liste: { 1: ["values", LEN, true] },
};

/**
 * Lit les champs d'un message : `{ nom: valeur brute | [valeurs brutes] }`
 * (VARINT : BigInt ; I64 : 8 octets ; I32 : 4 octets ; LEN : sous-tableau).
 * @param {Uint8Array} o
 * @param {object} table
 */
function lireMessage(o, table) {
  const champs = {};
  let i = 0;
  const varint = () => {
    let x = 0n;
    for (let k = 0; k < 10; k++) {
      if (i >= o.length) throw new ErreurDecodage("pb_tronque");
      const b = o[i++];
      x |= BigInt(b & 0x7f) << BigInt(7 * k);
      if ((b & 0x80) === 0) return x & ((1n << 64n) - 1n);
    }
    throw new ErreurDecodage("pb_varint_trop_long");
  };
  while (i < o.length) {
    const etiquette = varint();
    const numero = etiquette >> 3n;
    const fil = Number(etiquette & 7n);
    if (numero === 0n) throw new ErreurDecodage("pb_etiquette_nulle");
    if (![VARINT, I64, LEN, I32].includes(fil)) throw new ErreurDecodage("pb_type_de_fil");
    let valeur;
    if (fil === VARINT) valeur = varint();
    else if (fil === I64 || fil === I32) {
      const n = fil === I64 ? 8 : 4;
      if (i + n > o.length) throw new ErreurDecodage("pb_tronque");
      valeur = o.subarray(i, i + n);
      i += n;
    } else {
      const l = varint();
      if (l > BigInt(o.length - i)) throw new ErreurDecodage("pb_longueur");
      valeur = o.subarray(i, i + Number(l));
      i += Number(l);
    }
    const def = numero <= 1000n ? table[Number(numero)] : undefined;
    if (!def) continue; // champ inconnu, sauté selon son type de fil
    const [nom, attendu, repete] = def;
    if (fil !== attendu) throw new ErreurDecodage(`pb_type_de_fil:${nom}`);
    if (repete) (champs[nom] ??= []).push(valeur);
    else {
      if (nom in champs) throw new ErreurDecodage(`pb_champ_double:${nom}`);
      champs[nom] = valeur;
    }
  }
  return champs;
}

const chaine = (v) => {
  if (v === undefined) return "";
  try {
    return DECODEUR.decode(v);
  } catch {
    throw new ErreurDecodage("pb_utf8");
  }
};
const hex = (v) => (v === undefined ? "" : Buffer.from(v).toString("hex"));
const fixe64 = (v) => (v === undefined ? 0n : Buffer.from(v).readBigUInt64LE(0));
const fixe32 = (v) => (v === undefined ? 0 : Buffer.from(v).readUInt32LE(0));

function uint32(v) {
  if (v === undefined) return 0;
  if (v > BORNES_32.uint32[1]) throw new ErreurDecodage("pb_uint32");
  return Number(v);
}

function enumeration(v) {
  if (v === undefined) return 0;
  const s = BigInt.asIntN(64, v);
  if (s < BORNES_32.int32[0] || s > BORNES_32.int32[1]) throw new ErreurDecodage("pb_enum");
  return Number(s);
}

/**
 * Décode un corps protobuf (EX-6.30).
 * @param {Uint8Array} octets
 * @param {{profondeurMax: number, membresMax: number}} bornes
 * @returns {object} représentation commune
 * @throws {ErreurDecodage}
 */
export function decoderProtobuf(octets, bornes) {
  const attributs = (liste, profondeur) => {
    const l = liste ?? [];
    if (l.length > bornes.membresMax) throw new ErreurDecodage("membres");
    return l.map((b) => {
      const kv = lireMessage(b, CHAMPS.keyValue);
      if (kv.key === undefined && kv.key_strindex !== undefined) return { key: null, value: valeurAbsente(), ignorer: true };
      return { key: chaine(kv.key), value: kv.value === undefined ? valeurAbsente() : anyValue(kv.value, profondeur), ignorer: false };
    });
  };
  const anyValue = (b, profondeur) => {
    const a = lireMessage(b, CHAMPS.anyValue);
    const presents = Object.keys(a);
    if (presents.length > 1) throw new ErreurDecodage("pb_oneof");
    if (presents.length === 0) return valeurAbsente();
    const k = presents[0];
    const v = a[k];
    switch (k) {
      case "string_value":
        return { type: "string", v: chaine(v) };
      case "bool_value":
        if (v !== 0n && v !== 1n) throw new ErreurDecodage("pb_bool");
        return { type: "bool", v: v === 1n };
      case "int_value":
        return { type: "int", v: BigInt.asIntN(64, v) };
      case "double_value":
        return { type: "double", v: Buffer.from(v).readDoubleLE(0) };
      case "bytes_value":
        return { type: "bytes", v: new Uint8Array(v) };
      case "array_value": {
        if (profondeur + 1 > bornes.profondeurMax) throw new ErreurDecodage("profondeur");
        const l = lireMessage(v, CHAMPS.liste).values ?? [];
        if (l.length > bornes.membresMax) throw new ErreurDecodage("membres");
        return { type: "array", v: l.map((x) => anyValue(x, profondeur + 1)) };
      }
      case "kvlist_value":
        if (profondeur + 1 > bornes.profondeurMax) throw new ErreurDecodage("profondeur");
        return { type: "kvlist", v: attributs(lireMessage(v, CHAMPS.liste).values, profondeur + 1) };
      default:
        return valeurAbsente();
    }
  };
  const span = (b) => {
    const s = lireMessage(b, CHAMPS.span);
    const st = s.status === undefined ? null : lireMessage(s.status, CHAMPS.status);
    return {
      trace_id: hex(s.trace_id),
      span_id: hex(s.span_id),
      trace_state: chaine(s.trace_state),
      parent_span_id: hex(s.parent_span_id),
      name: chaine(s.name),
      kind: enumeration(s.kind),
      start_time_unix_nano: fixe64(s.start_time_unix_nano),
      end_time_unix_nano: fixe64(s.end_time_unix_nano),
      attributes: attributs(s.attributes, 0),
      dropped_attributes_count: uint32(s.dropped_attributes_count),
      events: (s.events ?? []).map((eb) => {
        const e = lireMessage(eb, CHAMPS.event);
        return { time_unix_nano: fixe64(e.time_unix_nano), name: chaine(e.name), attributes: attributs(e.attributes, 0), dropped_attributes_count: uint32(e.dropped_attributes_count) };
      }),
      dropped_events_count: uint32(s.dropped_events_count),
      links_count: (s.links ?? []).length,
      dropped_links_count: uint32(s.dropped_links_count),
      status: st === null ? null : { message: chaine(st.message), code: enumeration(st.code) },
      flags: fixe32(s.flags),
    };
  };
  const racine = lireMessage(octets, CHAMPS.requete);
  return {
    resource_spans: (racine.resource_spans ?? []).map((rb) => {
      const rs = lireMessage(rb, CHAMPS.resourceSpans);
      const res = rs.resource === undefined ? null : lireMessage(rs.resource, CHAMPS.resource);
      return {
        resource: res === null ? null : { attributes: attributs(res.attributes, 0), dropped_attributes_count: uint32(res.dropped_attributes_count) },
        scope_spans: (rs.scope_spans ?? []).map((sb) => {
          const ss = lireMessage(sb, CHAMPS.scopeSpans);
          const sc = ss.scope === undefined ? null : lireMessage(ss.scope, CHAMPS.scope);
          return {
            scope: sc === null ? null : { name: chaine(sc.name), version: chaine(sc.version), attributes: attributs(sc.attributes, 0), dropped_attributes_count: uint32(sc.dropped_attributes_count) },
            spans: (ss.spans ?? []).map(span),
            schema_url: chaine(ss.schema_url),
          };
        }),
        schema_url: chaine(rs.schema_url),
      };
    }),
  };
}

// ------------------------------------------------------------ encodage (réponses, essais)

/** Varint d'un entier naturel. */
export function varint(n) {
  let x = BigInt(n);
  const o = [];
  do {
    let b = Number(x & 0x7fn);
    x >>= 7n;
    if (x !== 0n) b |= 0x80;
    o.push(b);
  } while (x !== 0n);
  return o;
}

/** Champ LEN (numéro, octets). */
export function champLen(numero, octets) {
  return [...varint((numero << 3) | LEN), ...varint(octets.length), ...octets];
}

/** Champ VARINT. */
export function champVarint(numero, n) {
  return [...varint((numero << 3) | VARINT), ...varint(n)];
}
