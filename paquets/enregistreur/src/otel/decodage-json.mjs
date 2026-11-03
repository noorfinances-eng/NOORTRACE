// Décodage JSON d'un `ExportTraceServiceRequest` (CT-2 EX-6.29 ; OTLP/JSON de
// `opentelemetry-proto` v1.11.1, EX-6.25). JSON strict au sens d'EX-5.7
// point 2 (clé en double, substitut isolé, marque d'ordre d'octets, texte qui
// n'est pas du JSON : refus), sauf qu'un nombre est lu sur son texte là où le
// champ est un entier. Clés en lowerCamelCase (un nom snake_case est un champ
// inconnu, ignoré) ; un champ inconnu est ignoré à tout niveau ; `null` vaut
// champ absent ; un champ message est un objet, un champ répété un tableau, un
// champ chaîne une chaîne, sinon refus. Le résultat est la représentation
// commune aux deux encodages (`representation.mjs`), dont la forme normalisée
// ne dépend pas de l'encodage reçu (EX-6.30, EX-6.31).

import { analyserTexte, decoderUtf8Strict, ErreurTexteJson, membre } from "../mcp/json-texte.mjs";
import { ErreurDecodage, BORNES_32, valeurAbsente } from "./representation.mjs";

const DEUX_64 = 1n << 64n;
const MIN_I64 = -(1n << 63n);
const MAX_I64 = (1n << 63n) - 1n;
const MOTIF_ENTIER = /^-?(0|[1-9][0-9]*)$/;
const MOTIF_NATUREL = /^(0|[1-9][0-9]*)$/;

/**
 * Décode un corps JSON (EX-6.29).
 * @param {Uint8Array} octets
 * @param {{profondeurMax: number, membresMax: number}} bornes `limits.json_max_depth`, `limits.json_max_members`
 * @returns {object} représentation commune (`{ resource_spans: [...] }`)
 * @throws {ErreurDecodage}
 */
export function decoderJson(octets, bornes) {
  let texte;
  let racine;
  try {
    texte = decoderUtf8Strict(octets);
    racine = analyserTexte(texte, { profondeurMax: bornes.profondeurMax, membresMax: bornes.membresMax });
  } catch (e) {
    if (e instanceof ErreurTexteJson) throw new ErreurDecodage(`json_${e.raison}`);
    if (e instanceof RangeError) throw new ErreurDecodage("json_profondeur");
    throw e;
  }
  const L = new Lecteur(texte, bornes);
  return L.requete(racine);
}

class Lecteur {
  constructor(texte, bornes) {
    this.texte = texte;
    this.bornes = bornes;
  }

  // ------------------------------------------------------------ formes de champ

  /** Membre présent et non nul, ou undefined. */
  champ(noeud, nom) {
    const v = membre(noeud, nom);
    return v === undefined || v.t === "nul" ? undefined : v;
  }

  message(noeud, nom) {
    const v = this.champ(noeud, nom);
    if (v === undefined) return undefined;
    if (v.t !== "objet") throw new ErreurDecodage(`message_attendu:${nom}`);
    return v;
  }

  repete(noeud, nom) {
    const v = this.champ(noeud, nom);
    if (v === undefined) return [];
    if (v.t !== "tableau") throw new ErreurDecodage(`tableau_attendu:${nom}`);
    return v.elements;
  }

  repeteMessages(noeud, nom) {
    return this.repete(noeud, nom).map((e) => {
      if (e.t !== "objet") throw new ErreurDecodage(`message_attendu:${nom}`);
      return e;
    });
  }

  chaine(noeud, nom) {
    const v = this.champ(noeud, nom);
    if (v === undefined) return "";
    if (v.t !== "chaine") throw new ErreurDecodage(`chaine_attendue:${nom}`);
    return v.valeur;
  }

  litteral(v) {
    return this.texte.slice(v.d, v.f);
  }

  /** Identifiant (`traceId`, `spanId`, `parentSpanId`) : hexadécimal de longueur paire, jamais du base64. */
  identifiant(noeud, nom) {
    const v = this.champ(noeud, nom);
    if (v === undefined) return "";
    if (v.t !== "chaine" || v.valeur.length % 2 !== 0 || !/^[0-9A-Fa-f]*$/.test(v.valeur)) throw new ErreurDecodage(`identifiant:${nom}`);
    return v.valeur.toLowerCase();
  }

  /** Énumération (`kind`, `status.code`) : nombre JSON entier, jamais une chaîne ; énumération ouverte (int32). */
  enumeration(noeud, nom) {
    const v = this.champ(noeud, nom);
    if (v === undefined) return 0;
    if (v.t !== "nombre" || !MOTIF_ENTIER.test(this.litteral(v))) throw new ErreurDecodage(`enumeration:${nom}`);
    const n = BigInt(this.litteral(v));
    if (n < -(1n << 31n) || n > (1n << 31n) - 1n) throw new ErreurDecodage(`enumeration:${nom}`);
    return Number(n);
  }

  /** `fixed64` (`*TimeUnixNano`) : chaîne ou nombre de forme décimale naturelle, au plus 2^64 − 1. */
  fixed64(noeud, nom) {
    const v = this.champ(noeud, nom);
    if (v === undefined) return 0n;
    const s = v.t === "chaine" ? v.valeur : v.t === "nombre" ? this.litteral(v) : null;
    if (s === null || !MOTIF_NATUREL.test(s)) throw new ErreurDecodage(`fixed64:${nom}`);
    const n = BigInt(s);
    if (n >= DEUX_64) throw new ErreurDecodage(`fixed64:${nom}`);
    return n;
  }

  /** Entier 32 bits (`flags`, `droppedAttributesCount`, …) : nombre ou chaîne décimale, sans fraction ni exposant, dans les bornes du type. */
  entier32(noeud, nom, type = "uint32") {
    const v = this.champ(noeud, nom);
    if (v === undefined) return 0;
    const s = v.t === "chaine" ? v.valeur : v.t === "nombre" ? this.litteral(v) : null;
    const motif = type === "uint32" ? MOTIF_NATUREL : MOTIF_ENTIER;
    if (s === null || !motif.test(s)) throw new ErreurDecodage(`entier32:${nom}`);
    const n = BigInt(s);
    const [min, max] = BORNES_32[type];
    if (n < min || n > max) throw new ErreurDecodage(`entier32:${nom}`);
    return Number(n);
  }

  // ------------------------------------------------------------ messages

  requete(racine) {
    if (racine.t !== "objet") throw new ErreurDecodage("racine_non_objet");
    return { resource_spans: this.repeteMessages(racine, "resourceSpans").map((r) => this.resourceSpans(r)) };
  }

  resourceSpans(n) {
    const res = this.message(n, "resource");
    return {
      resource: res === undefined ? null : { attributes: this.attributs(res, "attributes", 0), dropped_attributes_count: this.entier32(res, "droppedAttributesCount") },
      scope_spans: this.repeteMessages(n, "scopeSpans").map((s) => this.scopeSpans(s)),
      schema_url: this.chaine(n, "schemaUrl"),
    };
  }

  scopeSpans(n) {
    const sc = this.message(n, "scope");
    return {
      scope:
        sc === undefined
          ? null
          : { name: this.chaine(sc, "name"), version: this.chaine(sc, "version"), attributes: this.attributs(sc, "attributes", 0), dropped_attributes_count: this.entier32(sc, "droppedAttributesCount") },
      spans: this.repeteMessages(n, "spans").map((s) => this.span(s)),
      schema_url: this.chaine(n, "schemaUrl"),
    };
  }

  span(n) {
    const st = this.message(n, "status");
    return {
      trace_id: this.identifiant(n, "traceId"),
      span_id: this.identifiant(n, "spanId"),
      trace_state: this.chaine(n, "traceState"),
      parent_span_id: this.identifiant(n, "parentSpanId"),
      name: this.chaine(n, "name"),
      kind: this.enumeration(n, "kind"),
      start_time_unix_nano: this.fixed64(n, "startTimeUnixNano"),
      end_time_unix_nano: this.fixed64(n, "endTimeUnixNano"),
      attributes: this.attributs(n, "attributes", 0),
      dropped_attributes_count: this.entier32(n, "droppedAttributesCount"),
      events: this.repeteMessages(n, "events").map((e) => ({
        time_unix_nano: this.fixed64(e, "timeUnixNano"),
        name: this.chaine(e, "name"),
        attributes: this.attributs(e, "attributes", 0),
        dropped_attributes_count: this.entier32(e, "droppedAttributesCount"),
      })),
      dropped_events_count: this.entier32(n, "droppedEventsCount"),
      links_count: this.repeteMessages(n, "links").length,
      dropped_links_count: this.entier32(n, "droppedLinksCount"),
      status: st === undefined ? null : { message: this.chaine(st, "message"), code: this.enumeration(st, "code") },
      flags: this.entier32(n, "flags"),
    };
  }

  /** Liste de `KeyValue` (EX-6.29) ; `profondeur` : imbrication des `arrayValue` et `kvlistValue`. */
  attributs(n, nom, profondeur) {
    const elements = this.repeteMessages(n, nom);
    if (elements.length > this.bornes.membresMax) throw new ErreurDecodage("membres");
    return elements.map((kv) => {
      const cle = this.champ(kv, "key");
      if (cle !== undefined && cle.t !== "chaine") throw new ErreurDecodage("chaine_attendue:key");
      const strindex = this.champ(kv, "keyStrindex");
      if (strindex !== undefined) this.entier32(kv, "keyStrindex", "int32");
      // Un `keyStrindex` sans `key` fait ignorer l'attribut (L5-2).
      if (cle === undefined && strindex !== undefined) return { key: null, value: valeurAbsente(), ignorer: true };
      const v = this.message(kv, "value");
      return { key: cle === undefined ? "" : cle.valeur, value: v === undefined ? valeurAbsente() : this.anyValue(v, profondeur), ignorer: false };
    });
  }

  /** `AnyValue` : zéro ou un membre du `oneof` ; deux ou plus : refus. */
  anyValue(n, profondeur) {
    const presents = ["stringValue", "boolValue", "intValue", "doubleValue", "arrayValue", "kvlistValue", "bytesValue", "stringValueStrindex"].filter((k) => this.champ(n, k) !== undefined);
    if (presents.length > 1) throw new ErreurDecodage("anyvalue_plusieurs_membres");
    if (presents.length === 0) return valeurAbsente();
    const k = presents[0];
    const v = this.champ(n, k);
    switch (k) {
      case "stringValue":
        if (v.t !== "chaine") throw new ErreurDecodage("stringValue");
        return { type: "string", v: v.valeur };
      case "boolValue":
        if (v.t !== "vrai" && v.t !== "faux") throw new ErreurDecodage("boolValue");
        return { type: "bool", v: v.t === "vrai" };
      case "intValue": {
        const s = v.t === "chaine" ? v.valeur : v.t === "nombre" ? this.litteral(v) : null;
        if (s === null || !MOTIF_ENTIER.test(s)) throw new ErreurDecodage("intValue");
        const x = BigInt(s);
        if (x < MIN_I64 || x > MAX_I64) throw new ErreurDecodage("intValue");
        return { type: "int", v: x };
      }
      case "doubleValue":
        if (v.t === "nombre") return { type: "double", v: v.valeur };
        if (v.t === "chaine" && ["NaN", "Infinity", "-Infinity"].includes(v.valeur)) return { type: "double", v: Number(v.valeur) };
        throw new ErreurDecodage("doubleValue");
      case "bytesValue": {
        if (v.t !== "chaine") throw new ErreurDecodage("bytesValue");
        return { type: "bytes", v: decoderBase64Otlp(v.valeur) };
      }
      case "arrayValue": {
        if (v.t !== "objet") throw new ErreurDecodage("arrayValue");
        if (profondeur + 1 > this.bornes.profondeurMax) throw new ErreurDecodage("profondeur");
        const valeurs = this.repeteMessages(v, "values");
        if (valeurs.length > this.bornes.membresMax) throw new ErreurDecodage("membres");
        return { type: "array", v: valeurs.map((x) => this.anyValue(x, profondeur + 1)) };
      }
      case "kvlistValue": {
        if (v.t !== "objet") throw new ErreurDecodage("kvlistValue");
        if (profondeur + 1 > this.bornes.profondeurMax) throw new ErreurDecodage("profondeur");
        return { type: "kvlist", v: this.attributs(v, "values", profondeur + 1) };
      }
      default:
        // `stringValueStrindex`, champ du signal des profils : valeur absente (L5-2).
        this.entier32(n, "stringValueStrindex", "int32");
        return valeurAbsente();
    }
  }
}

/**
 * Base64 de RFC 4648 § 4 ou § 5, avec ou sans remplissage (EX-6.29).
 * @param {string} s
 * @returns {Uint8Array}
 */
export function decoderBase64Otlp(s) {
  const standard = /^[A-Za-z0-9+/]*={0,2}$/;
  const url = /^[A-Za-z0-9_-]*={0,2}$/;
  if (!standard.test(s) && !url.test(s)) throw new ErreurDecodage("bytesValue");
  const sans = s.replace(/=+$/, "");
  if (sans.length % 4 === 1) throw new ErreurDecodage("bytesValue");
  if (s.includes("=") && s.length % 4 !== 0) throw new ErreurDecodage("bytesValue");
  return new Uint8Array(Buffer.from(sans.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
}
