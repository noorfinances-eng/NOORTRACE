// Lots OTLP de test (sans dépendance au démon) : constructeur de lots
// OTLP/JSON et encodeur protobuf d'un lot OTLP/JSON
// (`ExportTraceServiceRequest` de `opentelemetry-proto` v1.11.1, champs dans
// l'ordre croissant de leur numéro, chacun une fois). Employé par les tests
// et par l'agent de démonstration du parcours (son exportateur).

const kv = (key, v) => ({ key, value: typeof v === "string" ? { stringValue: v } : typeof v === "boolean" ? { boolValue: v } : Number.isInteger(v) ? { intValue: String(v) } : { doubleValue: v } });

let compteur = 0;
/** Identifiants de test : trace de 32 et span de 16 chiffres hexadécimaux, non nuls. */
export function identifiants() {
  compteur++;
  return { traceId: (compteur.toString(16).padStart(8, "0") + "aa").repeat(4).slice(0, 32), spanId: (compteur.toString(16).padStart(6, "0") + "bb").repeat(2).slice(0, 16) };
}

/**
 * Span OTLP/JSON.
 * @param {{nom?: string, attributs?: object, debut?: string, fin?: string, statut?: number, ids?: object, evenements?: object[]}} s
 */
export function span(s = {}) {
  const ids = s.ids ?? identifiants();
  return {
    ...ids,
    name: s.nom ?? "span",
    kind: s.kind ?? 1,
    startTimeUnixNano: s.debut ?? "1794307798000000000",
    endTimeUnixNano: s.fin ?? "1794307799000000000",
    attributes: Object.entries(s.attributs ?? {}).map(([k, v]) => kv(k, v)),
    ...(s.evenements ? { events: s.evenements } : {}),
    status: { code: s.statut ?? 1 },
  };
}

/** Span d'outil (`execute_tool`). */
export function spanOutil(nom, o = {}) {
  return span({ ...o, nom: `execute_tool ${nom}`, attributs: { "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": nom, ...(o.attributs ?? {}) } });
}

/** Span d'inférence (`chat`). */
export function spanInference(modele, o = {}) {
  return span({ ...o, nom: `chat ${modele}`, attributs: { "gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai", "gen_ai.request.model": modele, "gen_ai.response.model": modele, ...(o.attributs ?? {}) } });
}

/** Lot OTLP/JSON d'une ressource et d'une portée. */
export function lot(spans, o = {}) {
  return {
    resourceSpans: [
      {
        resource: { attributes: [kv("service.name", o.service ?? "agent-sinistres")] },
        scopeSpans: [{ scope: { name: "essais", version: "1.0.0" }, spans }],
      },
    ],
  };
}

// ------------------------------------------------------------ encodeur protobuf

function varint(n) {
  let x = BigInt(n);
  if (x < 0n) x = BigInt.asUintN(64, x);
  const o = [];
  do {
    let b = Number(x & 0x7fn);
    x >>= 7n;
    if (x !== 0n) b |= 0x80;
    o.push(b);
  } while (x !== 0n);
  return o;
}
const tag = (n, fil) => varint((n << 3) | fil);
const len = (n, octets) => [...tag(n, 2), ...varint(octets.length), ...octets];
const str = (n, s) => len(n, [...Buffer.from(s, "utf8")]);
const hex = (n, h) => len(n, [...Buffer.from(h, "hex")]);
const vint = (n, v) => [...tag(n, 0), ...varint(v)];
function fixe64(n, v) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(v));
  return [...tag(n, 1), ...b];
}
function fixe32(n, v) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(v);
  return [...tag(n, 5), ...b];
}

function anyValue(v) {
  if (!v) return [];
  if ("stringValue" in v) return str(1, v.stringValue);
  if ("boolValue" in v) return vint(2, v.boolValue ? 1 : 0);
  if ("intValue" in v) return vint(3, BigInt(v.intValue));
  if ("doubleValue" in v) {
    const b = Buffer.alloc(8);
    b.writeDoubleLE(Number(v.doubleValue));
    return [...tag(4, 1), ...b];
  }
  if ("arrayValue" in v) return len(5, (v.arrayValue.values ?? []).flatMap((x) => len(1, anyValue(x))));
  if ("kvlistValue" in v) return len(6, (v.kvlistValue.values ?? []).flatMap((x) => len(1, keyValue(x))));
  if ("bytesValue" in v) return len(7, [...Buffer.from(v.bytesValue, "base64")]);
  return [];
}
function keyValue(a) {
  return [...str(1, a.key), ...len(2, anyValue(a.value))];
}

/** Encode un lot OTLP/JSON en protobuf (`ExportTraceServiceRequest`). */
export function encoderProtobuf(requete) {
  const spanPb = (s) => [
    ...hex(1, s.traceId),
    ...hex(2, s.spanId),
    ...(s.traceState ? str(3, s.traceState) : []),
    ...(s.parentSpanId ? hex(4, s.parentSpanId) : []),
    ...(s.name ? str(5, s.name) : []),
    ...(s.kind ? vint(6, s.kind) : []),
    ...(s.startTimeUnixNano ? fixe64(7, s.startTimeUnixNano) : []),
    ...(s.endTimeUnixNano ? fixe64(8, s.endTimeUnixNano) : []),
    ...(s.attributes ?? []).flatMap((a) => len(9, keyValue(a))),
    ...(s.events ?? []).flatMap((e) => len(11, [...(e.timeUnixNano ? fixe64(1, e.timeUnixNano) : []), ...(e.name ? str(2, e.name) : []), ...(e.attributes ?? []).flatMap((a) => len(3, keyValue(a)))])),
    ...(s.status ? len(15, [...(s.status.message ? str(2, s.status.message) : []), ...(s.status.code ? vint(3, s.status.code) : [])]) : []),
    ...(s.flags ? fixe32(16, s.flags) : []),
  ];
  const octets = (requete.resourceSpans ?? []).flatMap((rs) =>
    len(1, [
      ...(rs.resource ? len(1, (rs.resource.attributes ?? []).flatMap((a) => len(1, keyValue(a)))) : []),
      ...(rs.scopeSpans ?? []).flatMap((ss) =>
        len(2, [
          ...(ss.scope ? len(1, [...(ss.scope.name ? str(1, ss.scope.name) : []), ...(ss.scope.version ? str(2, ss.scope.version) : [])]) : []),
          ...(ss.spans ?? []).flatMap((s) => len(2, spanPb(s))),
        ]),
      ),
    ]),
  );
  return new Uint8Array(octets);
}
