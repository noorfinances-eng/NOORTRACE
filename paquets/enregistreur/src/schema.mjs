// Validation JSON Schema (draft 2020-12) des documents du démon : la
// configuration (`configuration-enregistreur-v0`, qui référence
// `politique-redaction-v0` et `politique-approbation-v0`, EX-15.1) et les
// messages du service d'approbation (`ticket-v0`, EX-7.16, SG-1). Le
// validateur du noyau est limité aux mots-clés des schémas de CT-1 et refuse
// `minProperties`, `maxProperties` et `propertyNames`, qu'emploient ces
// schémas : ce module en est le pendant, limité aux mots-clés employés ici,
// et refuse tout autre mot-clé à l'enregistrement (jamais d'ignorance
// silencieuse). Toutes les erreurs sont rapportées (EX-15.4 pas 2), avec le
// pointeur JSON de l'instance et la règle du schéma.
//
// Sémantique : `$ref` s'applique avec les mots-clés voisins ; `minLength` et
// `maxLength` comptent des points de code ; `pattern` est une expression
// ECMA-262 en mode Unicode, non ancrée ; `integer` est un nombre de partie
// fractionnaire nulle.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { egaliteJson } from "@noortrace/noyau";

const MOTS_CLES = new Set([
  "$schema", "$id", "$ref", "$defs", "title", "description", "type", "const", "enum", "required", "properties",
  "additionalProperties", "propertyNames", "minProperties", "maxProperties", "items", "prefixItems", "minItems",
  "maxItems", "uniqueItems", "minLength", "maxLength", "pattern", "minimum", "maximum", "exclusiveMinimum",
  "exclusiveMaximum", "multipleOf", "allOf", "anyOf", "oneOf", "not", "if", "then", "else",
]);

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

function typeDe(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "number") return Number.isInteger(v) ? "integer" : "number";
  return typeof v;
}

function admetType(t, v) {
  const r = typeDe(v);
  return t === r || (t === "number" && r === "integer");
}

function echapper(segment) {
  return String(segment).replace(/~/g, "~0").replace(/\//g, "~1");
}

/** Registre de schémas, identifiés par leur `$id`. */
export class RegistreSchemasConfiguration {
  constructor() {
    /** @type {Map<string, object>} */
    this.ressources = new Map();
    /** @type {Map<string, RegExp>} */
    this.motifs = new Map();
  }

  /**
   * Enregistre un schéma ; refuse un mot-clé inconnu.
   * @param {object} schema
   */
  ajouter(schema) {
    if (!estObjet(schema) || typeof schema.$id !== "string") throw new Error("schéma à $id attendu");
    this.controler(schema, schema.$id);
    this.ressources.set(schema.$id, schema);
  }

  controler(s, ici) {
    if (typeof s === "boolean") return;
    if (!estObjet(s)) throw new Error(`${ici} : un schéma est un objet ou un booléen`);
    for (const [cle, v] of Object.entries(s)) {
      if (!MOTS_CLES.has(cle)) throw new Error(`${ici} : mot-clé non pris en charge ${cle}`);
      if (["properties", "$defs"].includes(cle)) for (const [n, x] of Object.entries(v)) this.controler(x, `${ici}/${cle}/${n}`);
      else if (["allOf", "anyOf", "oneOf", "prefixItems"].includes(cle)) v.forEach((x, k) => this.controler(x, `${ici}/${cle}/${k}`));
      else if (["additionalProperties", "items", "not", "if", "then", "else", "propertyNames"].includes(cle)) this.controler(v, `${ici}/${cle}`);
      else if (cle === "pattern" && !this.motifs.has(v)) this.motifs.set(v, new RegExp(v, "u"));
    }
  }

  /**
   * Résout une référence depuis la ressource courante.
   * @param {string} ref
   * @param {string} base `$id` de la ressource courante
   * @returns {{schema: object|boolean, base: string}}
   */
  resoudre(ref, base) {
    const [uri, fragment = ""] = ref.split("#");
    const id = uri === "" ? base : uri;
    const racine = this.ressources.get(id);
    if (!racine) throw new Error(`référence introuvable : ${ref}`);
    let s = racine;
    if (fragment) {
      for (const seg of fragment.split("/").slice(1)) {
        const cle = seg.replace(/~1/g, "/").replace(/~0/g, "~");
        s = s?.[cle];
        if (s === undefined) throw new Error(`référence introuvable : ${ref}`);
      }
    }
    return { schema: s, base: id };
  }

  /**
   * Valide une instance contre un schéma enregistré, ou un sous-schéma
   * désigné par une référence (`<$id>#/$defs/x`).
   * @param {string} ref
   * @param {unknown} instance
   * @returns {{valide: boolean, erreurs: {pointeur: string, regle: string, valeur: unknown}[]}}
   */
  valider(ref, instance) {
    const { schema, base } = this.resoudre(ref, "");
    const erreurs = [];
    this.valeur(schema, instance, "", base, `${ref}`, erreurs);
    return { valide: erreurs.length === 0, erreurs };
  }

  valeur(s, v, pointeur, base, chemin, erreurs) {
    if (s === true) return;
    if (s === false) {
      erreurs.push({ pointeur, regle: `${chemin} (false)`, valeur: v });
      return;
    }
    const err = (mot, detail) => erreurs.push({ pointeur, regle: `${mot}${detail ? ` : ${detail}` : ""}`, valeur: v });
    if (s.$ref !== undefined) {
      const r = this.resoudre(s.$ref, base);
      this.valeur(r.schema, v, pointeur, r.base, s.$ref, erreurs);
    }
    if (s.type !== undefined) {
      const types = Array.isArray(s.type) ? s.type : [s.type];
      if (!types.some((t) => admetType(t, v))) {
        err("type", `${types.join("|")} attendu, ${typeDe(v)} reçu`);
        return;
      }
    }
    if ("const" in s && !egaliteJson(s.const, v)) err("const", JSON.stringify(s.const));
    if (s.enum !== undefined && !s.enum.some((x) => egaliteJson(x, v))) err("enum", s.enum.map((x) => JSON.stringify(x)).join(", "));
    if (typeof v === "string") {
      const n = [...v].length;
      if (s.minLength !== undefined && n < s.minLength) err("minLength", String(s.minLength));
      if (s.maxLength !== undefined && n > s.maxLength) err("maxLength", String(s.maxLength));
      if (s.pattern !== undefined && !this.motifs.get(s.pattern).test(v)) err("pattern", s.pattern);
    }
    if (typeof v === "number") {
      if (s.minimum !== undefined && v < s.minimum) err("minimum", String(s.minimum));
      if (s.maximum !== undefined && v > s.maximum) err("maximum", String(s.maximum));
      if (s.exclusiveMinimum !== undefined && v <= s.exclusiveMinimum) err("exclusiveMinimum", String(s.exclusiveMinimum));
      if (s.exclusiveMaximum !== undefined && v >= s.exclusiveMaximum) err("exclusiveMaximum", String(s.exclusiveMaximum));
      if (s.multipleOf !== undefined && !Number.isInteger(v / s.multipleOf)) err("multipleOf", String(s.multipleOf));
    }
    if (Array.isArray(v)) {
      if (s.minItems !== undefined && v.length < s.minItems) err("minItems", String(s.minItems));
      if (s.maxItems !== undefined && v.length > s.maxItems) err("maxItems", String(s.maxItems));
      if (s.uniqueItems === true) {
        for (let i = 0; i < v.length; i++) for (let j = i + 1; j < v.length; j++) if (egaliteJson(v[i], v[j])) err("uniqueItems", `éléments ${i} et ${j}`);
      }
      const prefixe = s.prefixItems ?? [];
      prefixe.forEach((x, k) => {
        if (k < v.length) this.valeur(x, v[k], `${pointeur}/${k}`, base, `${chemin}/prefixItems/${k}`, erreurs);
      });
      if (s.items !== undefined) {
        for (let k = prefixe.length; k < v.length; k++) this.valeur(s.items, v[k], `${pointeur}/${k}`, base, `${chemin}/items`, erreurs);
      }
    }
    if (estObjet(v)) {
      const cles = Object.keys(v);
      if (s.minProperties !== undefined && cles.length < s.minProperties) err("minProperties", String(s.minProperties));
      if (s.maxProperties !== undefined && cles.length > s.maxProperties) err("maxProperties", String(s.maxProperties));
      for (const r of s.required ?? []) if (!Object.prototype.hasOwnProperty.call(v, r)) err("required", r);
      for (const c of cles) {
        const ici = `${pointeur}/${echapper(c)}`;
        if (s.propertyNames !== undefined) {
          const sous = [];
          this.valeur(s.propertyNames, c, ici, base, `${chemin}/propertyNames`, sous);
          if (sous.length) erreurs.push({ pointeur: ici, regle: `propertyNames : nom de membre refusé (${sous[0].regle})`, valeur: c });
        }
        if (s.properties && Object.prototype.hasOwnProperty.call(s.properties, c)) {
          this.valeur(s.properties[c], v[c], ici, base, `${chemin}/properties/${c}`, erreurs);
        } else if (s.additionalProperties !== undefined) {
          if (s.additionalProperties === false) erreurs.push({ pointeur: ici, regle: "additionalProperties : membre inconnu", valeur: undefined });
          else this.valeur(s.additionalProperties, v[c], ici, base, `${chemin}/additionalProperties`, erreurs);
        }
      }
    }
    for (const [k, x] of (s.allOf ?? []).entries()) this.valeur(x, v, pointeur, base, `${chemin}/allOf/${k}`, erreurs);
    if (s.anyOf !== undefined) {
      if (!s.anyOf.some((x) => this.estValide(x, v, base))) err("anyOf", "aucune branche ne valide");
    }
    if (s.oneOf !== undefined) {
      const valides = s.oneOf.map((x) => this.estValide(x, v, base));
      const n = valides.filter(Boolean).length;
      if (n !== 1) {
        if (n === 0 && s.oneOf.length === 2 && s.oneOf.some((x) => x?.type === "null")) {
          // Forme courante « null ou X » : rapporter les erreurs de X.
          const autre = s.oneOf.find((x) => x?.type !== "null");
          if (v !== null) {
            this.valeur(autre, v, pointeur, base, `${chemin}/oneOf`, erreurs);
            return;
          }
        }
        err("oneOf", n === 0 ? "aucune branche ne valide" : `${n} branches valident`);
      }
    }
    if (s.not !== undefined && this.estValide(s.not, v, base)) err("not", "");
    if (s.if !== undefined) {
      if (this.estValide(s.if, v, base)) {
        if (s.then !== undefined) this.valeur(s.then, v, pointeur, base, `${chemin}/then`, erreurs);
      } else if (s.else !== undefined) {
        this.valeur(s.else, v, pointeur, base, `${chemin}/else`, erreurs);
      }
    }
  }

  estValide(s, v, base) {
    const e = [];
    this.valeur(s, v, "", base, "", e);
    return e.length === 0;
  }
}

const ICI = path.dirname(fileURLToPath(import.meta.url));

/** Fichiers de schémas embarqués (copies de spec/schemas, comparées par les tests). */
export const FICHIERS_SCHEMAS = Object.freeze([
  "evenement-v0.schema.json",
  "politique-redaction-v0.schema.json",
  "politique-approbation-v0.schema.json",
  "configuration-enregistreur-v0.schema.json",
  "ticket-v0.schema.json",
]);

/** `$id` des schémas employés. */
export const IDS = Object.freeze({
  configuration: "https://noortrace.example/schemas/v0/configuration-enregistreur.schema.json",
  ticket: "https://noortrace.example/schemas/v0/ticket.schema.json",
  approbation: "https://noortrace.example/schemas/v0/politique-approbation.schema.json",
  redaction: "https://noortrace.example/schemas/v0/politique-redaction.schema.json",
  evenement: "https://noortrace.example/schemas/v0/evenement.schema.json",
});

let registre = null;

/**
 * Registre des schémas embarqués (`schemas/` du paquet), chargé une fois.
 * @returns {RegistreSchemasConfiguration}
 */
export function registreSchemas() {
  if (registre) return registre;
  const r = new RegistreSchemasConfiguration();
  for (const f of FICHIERS_SCHEMAS) r.ajouter(JSON.parse(fs.readFileSync(path.join(ICI, "..", "schemas", f), "utf8")));
  registre = r;
  return r;
}
