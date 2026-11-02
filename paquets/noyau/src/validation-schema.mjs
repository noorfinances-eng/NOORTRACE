// Validation JSON Schema (draft 2020-12) limitée aux mots-clés que les
// schémas de CT-1 emploient réellement. Tout autre mot-clé est refusé à
// l'enregistrement du schéma : jamais d'ignorance silencieuse (un mot-clé
// inconnu, ignoré, accepterait des documents que le schéma refuse).
//
// Sémantique retenue, celle du draft 2020-12 : `$ref` s'applique avec les
// mots-clés voisins ; `minLength` et `maxLength` comptent des points de code ;
// `pattern` est une expression ECMA-262 en mode Unicode, non ancrée ;
// `integer` est un nombre de partie fractionnaire nulle.

import { egaliteJson } from "./json-strict.mjs";

const URI_DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema";

const SOUS_SCHEMA = new Set(["additionalProperties", "items", "not", "if", "then", "else"]);
const LISTE_SCHEMAS = new Set(["allOf", "anyOf", "oneOf", "prefixItems"]);
const TABLE_SCHEMAS = new Set(["properties", "$defs"]);
const VALEURS = new Set([
  "$schema", "$id", "$ref", "title", "description", "type", "const", "enum", "required",
  "minItems", "maxItems", "uniqueItems", "minLength", "maxLength", "pattern",
  "minimum", "maximum", "multipleOf",
]);

/** Mots-clés reconnus ; tout autre est refusé. */
export const MOTS_CLES = Object.freeze([...SOUS_SCHEMA, ...LISTE_SCHEMAS, ...TABLE_SCHEMAS, ...VALEURS].sort());

const TYPES = new Set(["null", "boolean", "object", "array", "number", "integer", "string"]);

/** Défaut d'un schéma (mot-clé inconnu, valeur mal formée, référence introuvable). */
export class ErreurSchema extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "ErreurSchema";
  }
}

function estObjet(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function entierNonNegatif(v) {
  return Number.isSafeInteger(v) && v >= 0;
}

/**
 * Contrôle récursivement la forme d'un schéma : mots-clés connus, valeurs bien
 * typées, motifs compilables.
 */
function controlerSchema(schema, chemin, racine, motifs) {
  if (typeof schema === "boolean") return;
  if (!estObjet(schema)) throw new ErreurSchema(`${chemin} : un schéma est un objet ou un booléen`);
  for (const [cle, valeur] of Object.entries(schema)) {
    const ici = `${chemin}/${cle}`;
    if (SOUS_SCHEMA.has(cle)) {
      controlerSchema(valeur, ici, false, motifs);
    } else if (LISTE_SCHEMAS.has(cle)) {
      if (!Array.isArray(valeur) || valeur.length === 0) throw new ErreurSchema(`${ici} : tableau non vide de schémas attendu`);
      valeur.forEach((s, k) => controlerSchema(s, `${ici}/${k}`, false, motifs));
    } else if (TABLE_SCHEMAS.has(cle)) {
      if (!estObjet(valeur)) throw new ErreurSchema(`${ici} : objet attendu`);
      if (cle === "$defs" && !racine) throw new ErreurSchema(`${ici} : $defs n'est admis qu'à la racine d'une ressource`);
      for (const [nom, s] of Object.entries(valeur)) controlerSchema(s, `${ici}/${nom}`, false, motifs);
    } else if (VALEURS.has(cle)) {
      switch (cle) {
        case "$schema":
          if (!racine || valeur !== URI_DRAFT_2020_12) throw new ErreurSchema(`${ici} : seul le draft 2020-12 est admis, à la racine`);
          break;
        case "$id":
          if (!racine || typeof valeur !== "string" || !/^https?:\/\/[^#]+$/.test(valeur)) {
            throw new ErreurSchema(`${ici} : $id absolu sans fragment, à la racine seulement`);
          }
          break;
        case "$ref":
          if (typeof valeur !== "string") throw new ErreurSchema(`${ici} : $ref est une chaîne`);
          break;
        case "title":
        case "description":
          if (typeof valeur !== "string") throw new ErreurSchema(`${ici} : chaîne attendue`);
          break;
        case "type": {
          const liste = Array.isArray(valeur) ? valeur : [valeur];
          if (liste.length === 0 || !liste.every((t) => TYPES.has(t))) throw new ErreurSchema(`${ici} : type inconnu`);
          break;
        }
        case "enum":
          if (!Array.isArray(valeur) || valeur.length === 0) throw new ErreurSchema(`${ici} : tableau non vide attendu`);
          break;
        case "required":
          if (!Array.isArray(valeur) || !valeur.every((x) => typeof x === "string")) throw new ErreurSchema(`${ici} : tableau de chaînes attendu`);
          break;
        case "minItems":
        case "maxItems":
        case "minLength":
        case "maxLength":
          if (!entierNonNegatif(valeur)) throw new ErreurSchema(`${ici} : entier positif ou nul attendu`);
          break;
        case "uniqueItems":
          if (typeof valeur !== "boolean") throw new ErreurSchema(`${ici} : booléen attendu`);
          break;
        case "pattern":
          if (typeof valeur !== "string") throw new ErreurSchema(`${ici} : chaîne attendue`);
          try {
            motifs.set(valeur, new RegExp(valeur, "u"));
          } catch {
            throw new ErreurSchema(`${ici} : expression régulière invalide`);
          }
          break;
        case "minimum":
        case "maximum":
          if (typeof valeur !== "number" || !Number.isFinite(valeur)) throw new ErreurSchema(`${ici} : nombre attendu`);
          break;
        case "multipleOf":
          if (typeof valeur !== "number" || !(valeur > 0)) throw new ErreurSchema(`${ici} : nombre strictement positif attendu`);
          break;
        case "const":
          break;
        default:
          break;
      }
    } else {
      throw new ErreurSchema(`${ici} : mot-clé « ${cle} » inconnu de ce validateur, refusé`);
    }
  }
}

function longueurPointsDeCode(s) {
  let n = 0;
  for (const _ of s) n++;
  return n;
}

function typeDe(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

function aLeType(v, type) {
  switch (type) {
    case "null": return v === null;
    case "boolean": return typeof v === "boolean";
    case "object": return estObjet(v);
    case "array": return Array.isArray(v);
    case "number": return typeof v === "number" && Number.isFinite(v);
    case "integer": return typeof v === "number" && Number.isInteger(v);
    case "string": return typeof v === "string";
    default: return false;
  }
}

function decoderPointeur(fragment) {
  if (fragment === "") return [];
  if (!fragment.startsWith("/")) throw new ErreurSchema(`fragment « #${fragment} » non pris en charge (pointeur JSON attendu)`);
  return fragment.slice(1).split("/").map((s) => s.replace(/~1/g, "/").replace(/~0/g, "~"));
}

/**
 * Registre de schémas : chaque schéma racine porte un `$id` absolu ; les
 * `$ref` se résolvent dans la ressource courante (`#…`) ou vers un autre
 * schéma du registre (`https://…#…`).
 */
export class RegistreSchemas {
  /**
   * @param {object[]} schemas schémas racines, chacun avec `$schema` 2020-12 et `$id`
   * @throws {ErreurSchema} mot-clé inconnu, valeur mal formée, `$id` en double
   */
  constructor(schemas) {
    /** @type {Map<string, object>} */
    this.ressources = new Map();
    /** @type {Map<string, RegExp>} */
    this.motifs = new Map();
    for (const s of schemas) {
      if (!estObjet(s) || typeof s.$id !== "string") throw new ErreurSchema("schéma racine avec $id attendu");
      if (s.$schema !== URI_DRAFT_2020_12) throw new ErreurSchema(`${s.$id} : $schema 2020-12 attendu`);
      controlerSchema(s, s.$id + "#", true, this.motifs);
      if (this.ressources.has(s.$id)) throw new ErreurSchema(`${s.$id} : $id en double`);
      this.ressources.set(s.$id, s);
    }
    // Toutes les références doivent se résoudre dès l'enregistrement.
    for (const [id, s] of this.ressources) this.#verifierReferences(s, id);
  }

  #verifierReferences(schema, base) {
    if (!estObjet(schema)) return;
    for (const [cle, valeur] of Object.entries(schema)) {
      if (cle === "$ref") this.resoudre(valeur, base);
      else if (SOUS_SCHEMA.has(cle)) this.#verifierReferences(valeur, base);
      else if (LISTE_SCHEMAS.has(cle)) valeur.forEach((s) => this.#verifierReferences(s, base));
      else if (TABLE_SCHEMAS.has(cle)) Object.values(valeur).forEach((s) => this.#verifierReferences(s, base));
    }
  }

  /**
   * Résout une référence relative à une ressource.
   * @param {string} ref
   * @param {string} base `$id` de la ressource courante
   * @returns {{schema: object|boolean, base: string}}
   */
  resoudre(ref, base) {
    const diese = ref.indexOf("#");
    const uri = diese === -1 ? ref : ref.slice(0, diese);
    const fragment = diese === -1 ? "" : ref.slice(diese + 1);
    const cible = uri === "" ? base : uri;
    const racine = this.ressources.get(cible);
    if (!racine) throw new ErreurSchema(`référence ${ref} : ressource ${cible} inconnue du registre`);
    let schema = racine;
    for (const segment of decoderPointeur(fragment)) {
      if (!estObjet(schema) || !Object.prototype.hasOwnProperty.call(schema, segment)) {
        throw new ErreurSchema(`référence ${ref} : ${segment} introuvable`);
      }
      schema = schema[segment];
    }
    if (typeof schema !== "boolean" && !estObjet(schema)) throw new ErreurSchema(`référence ${ref} : ne désigne pas un schéma`);
    return { schema, base: cible };
  }

  /**
   * Valide une instance contre un schéma du registre.
   * @param {string} ref `$id`, éventuellement suivi d'un fragment `#/$defs/…`
   * @param {unknown} instance
   * @returns {{valide: boolean, erreurs: string[]}}
   */
  valider(ref, instance) {
    const { schema, base } = this.resoudre(ref, "");
    const erreurs = [];
    const valide = this.#valider(schema, instance, base, "", erreurs);
    return { valide, erreurs };
  }

  #valider(schema, v, base, chemin, erreurs) {
    if (schema === true) return true;
    if (schema === false) {
      erreurs.push(`${chemin || "/"} : aucune valeur n'est admise ici`);
      return false;
    }
    const lieu = chemin || "/";
    let ok = true;
    const echec = (message) => {
      erreurs.push(`${lieu} : ${message}`);
      ok = false;
    };
    const essai = (s, valeur, ch) => this.#valider(s, valeur, base, ch, []);

    if ("$ref" in schema) {
      const r = this.resoudre(schema.$ref, base);
      if (!this.#valider(r.schema, v, r.base, chemin, erreurs)) ok = false;
    }
    if ("type" in schema) {
      const liste = Array.isArray(schema.type) ? schema.type : [schema.type];
      if (!liste.some((t) => aLeType(v, t))) echec(`type ${typeDe(v)}, attendu ${liste.join(" ou ")}`);
    }
    if ("const" in schema && !egaliteJson(v, schema.const)) echec(`valeur différente de la constante ${JSON.stringify(schema.const)}`);
    if ("enum" in schema && !schema.enum.some((e) => egaliteJson(v, e))) echec(`valeur hors de l'énumération`);

    if (typeof v === "string") {
      if ("minLength" in schema || "maxLength" in schema) {
        const n = longueurPointsDeCode(v);
        if ("minLength" in schema && n < schema.minLength) echec(`chaîne de ${n} caractère(s), au moins ${schema.minLength}`);
        if ("maxLength" in schema && n > schema.maxLength) echec(`chaîne de ${n} caractère(s), au plus ${schema.maxLength}`);
      }
      if ("pattern" in schema && !this.motifs.get(schema.pattern).test(v)) echec(`chaîne non conforme au motif ${schema.pattern}`);
    }
    if (typeof v === "number") {
      if ("minimum" in schema && v < schema.minimum) echec(`${v} inférieur au minimum ${schema.minimum}`);
      if ("maximum" in schema && v > schema.maximum) echec(`${v} supérieur au maximum ${schema.maximum}`);
      if ("multipleOf" in schema) {
        const q = v / schema.multipleOf;
        if (!Number.isInteger(q)) echec(`${v} n'est pas multiple de ${schema.multipleOf}`);
      }
    }
    if (Array.isArray(v)) {
      if ("minItems" in schema && v.length < schema.minItems) echec(`${v.length} élément(s), au moins ${schema.minItems}`);
      if ("maxItems" in schema && v.length > schema.maxItems) echec(`${v.length} élément(s), au plus ${schema.maxItems}`);
      if (schema.uniqueItems === true) {
        for (let a = 0; a < v.length; a++) {
          for (let b = a + 1; b < v.length; b++) {
            if (egaliteJson(v[a], v[b])) {
              echec(`éléments ${a} et ${b} égaux (uniqueItems)`);
              a = v.length;
              break;
            }
          }
        }
      }
      const prefixe = schema.prefixItems ?? [];
      prefixe.forEach((s, k) => {
        if (k < v.length && !this.#valider(s, v[k], base, `${chemin}/${k}`, erreurs)) ok = false;
      });
      if ("items" in schema) {
        for (let k = prefixe.length; k < v.length; k++) {
          if (!this.#valider(schema.items, v[k], base, `${chemin}/${k}`, erreurs)) ok = false;
        }
      }
    }
    if (estObjet(v)) {
      for (const requis of schema.required ?? []) {
        if (!Object.prototype.hasOwnProperty.call(v, requis)) echec(`membre « ${requis} » manquant`);
      }
      const proprietes = schema.properties ?? {};
      for (const [cle, valeur] of Object.entries(v)) {
        const ch = `${chemin}/${cle}`;
        if (Object.prototype.hasOwnProperty.call(proprietes, cle)) {
          if (!this.#valider(proprietes[cle], valeur, base, ch, erreurs)) ok = false;
        } else if ("additionalProperties" in schema) {
          if (schema.additionalProperties === false) {
            echec(`membre « ${cle} » non admis`);
          } else if (!this.#valider(schema.additionalProperties, valeur, base, ch, erreurs)) {
            ok = false;
          }
        }
      }
    }

    for (const s of schema.allOf ?? []) {
      if (!this.#valider(s, v, base, chemin, erreurs)) ok = false;
    }
    if ("anyOf" in schema && !schema.anyOf.some((s) => essai(s, v, chemin))) echec("aucune branche de anyOf ne convient");
    if ("oneOf" in schema) {
      const n = schema.oneOf.filter((s) => essai(s, v, chemin)).length;
      if (n !== 1) echec(n === 0 ? "aucune branche de oneOf ne convient" : `${n} branches de oneOf conviennent, une seule attendue`);
    }
    if ("not" in schema && essai(schema.not, v, chemin)) echec("valeur refusée par not");
    if ("if" in schema) {
      if (essai(schema.if, v, chemin)) {
        if ("then" in schema && !this.#valider(schema.then, v, base, chemin, erreurs)) ok = false;
      } else if ("else" in schema && !this.#valider(schema.else, v, base, chemin, erreurs)) {
        ok = false;
      }
    }
    return ok;
  }
}
