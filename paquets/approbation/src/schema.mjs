// Validation JSON Schema (draft 2020-12) des documents du service : politique
// d'approbation (`politique-approbation-v0`, CT-3 EX-4.2), messages et
// documents de ticket (`ticket-v0`), annuaire des approbateurs
// (`annuaire-approbateurs-v0`, EX-13.38), configuration du service
// (`configuration-approbation-v0`, EX-10.12, notifications d'EX-13.40) et
// corps du canal de la console (`console-service-v0`,
// `console-approbation-v0`, EX-12.13).
// Les schémas sont des copies de spec/schemas, comparées par les tests.
//
// Le validateur du noyau est limité aux mots-clés des schémas de CT-1 et
// refuse `propertyNames` et `maxProperties`, qu'emploient ces schémas : ce
// module en est le pendant, limité aux mots-clés employés ici ; il refuse
// tout autre mot-clé à l'enregistrement (jamais d'ignorance silencieuse).
// Sémantique : `$ref` s'applique avec ses voisins ; `minLength` et `maxLength`
// comptent des points de code ; `pattern` est une expression ECMA-262 en mode
// Unicode, non ancrée ; `integer` est un nombre de partie fractionnaire nulle.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { egaliteJson } from "@noortrace/noyau";

const MOTS_CLES = new Set([
  "$schema", "$id", "$ref", "$defs", "title", "description", "type", "const", "enum", "required", "properties",
  "additionalProperties", "propertyNames", "maxProperties", "prefixItems", "items", "minItems", "maxItems", "uniqueItems",
  "minLength", "maxLength", "pattern", "minimum", "maximum", "allOf", "anyOf", "oneOf", "not", "if", "then", "else",
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

const echapper = (s) => String(s).replace(/~/g, "~0").replace(/\//g, "~1");

/** Registre de schémas identifiés par leur `$id`. */
export class RegistreSchemas {
  constructor() {
    /** @type {Map<string, object>} */
    this.ressources = new Map();
    /** @type {Map<string, RegExp>} */
    this.motifs = new Map();
  }

  /** @param {object} schema schéma racine à `$id` */
  ajouter(schema) {
    if (!estObjet(schema) || typeof schema.$id !== "string") throw new Error("schéma à $id attendu");
    this.#controler(schema, schema.$id);
    this.ressources.set(schema.$id, schema);
  }

  #controler(s, ici) {
    if (typeof s === "boolean") return;
    if (!estObjet(s)) throw new Error(`${ici} : un schéma est un objet ou un booléen`);
    for (const [cle, v] of Object.entries(s)) {
      if (!MOTS_CLES.has(cle)) throw new Error(`${ici} : mot-clé non pris en charge : ${cle}`);
      if (cle === "properties" || cle === "$defs") for (const [n, x] of Object.entries(v)) this.#controler(x, `${ici}/${cle}/${n}`);
      else if (cle === "allOf" || cle === "anyOf" || cle === "oneOf" || cle === "prefixItems") v.forEach((x, k) => this.#controler(x, `${ici}/${cle}/${k}`));
      else if (["additionalProperties", "items", "not", "if", "then", "else", "propertyNames"].includes(cle)) this.#controler(v, `${ici}/${cle}`);
      else if (cle === "pattern" && !this.motifs.has(v)) this.motifs.set(v, new RegExp(v, "u"));
    }
  }

  /**
   * @param {string} ref
   * @param {string} base `$id` de la ressource courante
   */
  resoudre(ref, base) {
    const diese = ref.indexOf("#");
    const uri = diese < 0 ? ref : ref.slice(0, diese);
    const fragment = diese < 0 ? "" : ref.slice(diese + 1);
    const id = uri === "" ? base : uri;
    const racine = this.ressources.get(id);
    if (!racine) throw new Error(`référence introuvable : ${ref}`);
    let s = racine;
    if (fragment) {
      for (const seg of fragment.split("/").slice(1)) {
        const cle = seg.replace(/~1/g, "/").replace(/~0/g, "~");
        if (!estObjet(s) || !Object.prototype.hasOwnProperty.call(s, cle)) throw new Error(`référence introuvable : ${ref}`);
        s = s[cle];
      }
    }
    return { schema: s, base: id };
  }

  /**
   * Valide une instance contre un schéma ou un sous-schéma (`<$id>#/$defs/x`).
   * @param {string} ref
   * @param {unknown} instance
   * @returns {{valide: boolean, erreurs: {pointeur: string, regle: string}[]}}
   */
  valider(ref, instance, options = {}) {
    const { schema, base } = this.resoudre(ref, "");
    const erreurs = [];
    this.#detailler = options.detailler === true;
    try {
      this.#valeur(schema, instance, "", base, erreurs);
    } finally {
      this.#detailler = false;
    }
    return { valide: erreurs.length === 0, erreurs };
  }

  /**
   * Option `detailler` de `valider` (rapport de configuration, EX-10.12) :
   * un membre requis manquant est rapporté à son propre pointeur, et un
   * `oneOf` ou un `anyOf` dont une seule branche admet le type de la valeur
   * rapporte les erreurs de cette branche plutôt que son propre pointeur.
   */
  #detailler = false;

  /** @returns {boolean} */
  estValide(ref, instance) {
    return this.valider(ref, instance).valide;
  }

  /** Rapporte les erreurs de la seule branche qui admet le type de `v`, s'il y en a une seule. */
  #brancheUnique(branches, v, pointeur, base, erreurs) {
    const candidates = [];
    for (const x of branches) {
      const e = [];
      this.#valeur(x, v, pointeur, base, e);
      if (!e.some((y) => y.pointeur === pointeur && y.regle.startsWith("type"))) candidates.push(e);
    }
    if (candidates.length !== 1 || candidates[0].length === 0) return false;
    erreurs.push(...candidates[0]);
    return true;
  }

  #essai(s, v, base) {
    const e = [];
    this.#valeur(s, v, "", base, e);
    return e.length === 0;
  }

  #valeur(s, v, pointeur, base, erreurs) {
    if (s === true) return;
    if (s === false) {
      erreurs.push({ pointeur, regle: "false" });
      return;
    }
    const err = (regle) => erreurs.push({ pointeur, regle });
    if (s.$ref !== undefined) {
      const r = this.resoudre(s.$ref, base);
      this.#valeur(r.schema, v, pointeur, r.base, erreurs);
    }
    if (s.type !== undefined) {
      const types = Array.isArray(s.type) ? s.type : [s.type];
      if (!types.some((t) => admetType(t, v))) {
        err(`type ${types.join("|")}`);
        return;
      }
    }
    if ("const" in s && !egaliteJson(s.const, v)) err("const");
    if (s.enum !== undefined && !s.enum.some((x) => egaliteJson(x, v))) err("enum");
    if (typeof v === "string") {
      if (s.minLength !== undefined || s.maxLength !== undefined) {
        let n = 0;
        for (const _ of v) n++;
        if (s.minLength !== undefined && n < s.minLength) err("minLength");
        if (s.maxLength !== undefined && n > s.maxLength) err("maxLength");
      }
      if (s.pattern !== undefined && !this.motifs.get(s.pattern).test(v)) err(`pattern ${s.pattern}`);
    }
    if (typeof v === "number") {
      if (s.minimum !== undefined && v < s.minimum) err("minimum");
      if (s.maximum !== undefined && v > s.maximum) err("maximum");
    }
    if (Array.isArray(v)) {
      if (s.minItems !== undefined && v.length < s.minItems) err("minItems");
      if (s.maxItems !== undefined && v.length > s.maxItems) err("maxItems");
      if (s.uniqueItems === true) {
        let double = false;
        for (let i = 0; i < v.length && !double; i++) for (let j = i + 1; j < v.length && !double; j++) double = egaliteJson(v[i], v[j]);
        if (double) err("uniqueItems");
      }
      // 2020-12 : prefixItems s'applique rang par rang, items aux éléments qui suivent
      const prefixe = s.prefixItems ?? [];
      prefixe.forEach((x, k) => {
        if (k < v.length) this.#valeur(x, v[k], `${pointeur}/${k}`, base, erreurs);
      });
      if (s.items !== undefined) v.forEach((x, k) => {
        if (k >= prefixe.length) this.#valeur(s.items, x, `${pointeur}/${k}`, base, erreurs);
      });
    }
    if (estObjet(v)) {
      const cles = Object.keys(v);
      if (s.maxProperties !== undefined && cles.length > s.maxProperties) err("maxProperties");
      for (const r of s.required ?? []) {
        if (Object.prototype.hasOwnProperty.call(v, r)) continue;
        if (this.#detailler) erreurs.push({ pointeur: `${pointeur}/${echapper(r)}`, regle: "required" });
        else err(`required ${r}`);
      }
      for (const c of cles) {
        const ici = `${pointeur}/${echapper(c)}`;
        if (s.propertyNames !== undefined && !this.#essai(s.propertyNames, c, base)) erreurs.push({ pointeur: ici, regle: "propertyNames" });
        if (s.properties && Object.prototype.hasOwnProperty.call(s.properties, c)) this.#valeur(s.properties[c], v[c], ici, base, erreurs);
        else if (s.additionalProperties === false) erreurs.push({ pointeur: ici, regle: "additionalProperties" });
        else if (s.additionalProperties !== undefined) this.#valeur(s.additionalProperties, v[c], ici, base, erreurs);
      }
    }
    for (const x of s.allOf ?? []) this.#valeur(x, v, pointeur, base, erreurs);
    if (s.anyOf !== undefined && !s.anyOf.some((x) => this.#essai(x, v, base))) {
      if (!this.#detailler || !this.#brancheUnique(s.anyOf, v, pointeur, base, erreurs)) err("anyOf");
    }
    if (s.oneOf !== undefined) {
      const n = s.oneOf.filter((x) => this.#essai(x, v, base)).length;
      if (n !== 1 && !(n === 0 && this.#detailler && this.#brancheUnique(s.oneOf, v, pointeur, base, erreurs))) err(`oneOf (${n})`);
    }
    if (s.not !== undefined && this.#essai(s.not, v, base)) err("not");
    if (s.if !== undefined) {
      if (this.#essai(s.if, v, base)) {
        if (s.then !== undefined) this.#valeur(s.then, v, pointeur, base, erreurs);
      } else if (s.else !== undefined) this.#valeur(s.else, v, pointeur, base, erreurs);
    }
  }
}

const ICI = path.dirname(fileURLToPath(import.meta.url));

/** Schémas embarqués : copies de spec/schemas, comparées octet pour octet par les tests. */
export const FICHIERS_SCHEMAS = Object.freeze([
  "evenement-v0.schema.json",
  "politique-approbation-v0.schema.json",
  "ticket-v0.schema.json",
  "annuaire-approbateurs-v0.schema.json",
  "configuration-approbation-v0.schema.json",
  "console-service-v0.schema.json",
  "console-approbation-v0.schema.json",
]);

/** Répertoire des schémas embarqués. */
export const REPERTOIRE_SCHEMAS = path.join(ICI, "..", "schemas");

/** `$id` des schémas employés. */
export const IDS = Object.freeze({
  politique: "https://noortrace.example/schemas/v0/politique-approbation.schema.json",
  ticket: "https://noortrace.example/schemas/v0/ticket.schema.json",
  evenement: "https://noortrace.example/schemas/v0/evenement.schema.json",
  annuaire: "https://noortrace.example/schemas/v0/annuaire-approbateurs.schema.json",
  configuration: "https://noortrace.example/schemas/v0/configuration-approbation.schema.json",
  consoleService: "https://noortrace.example/schemas/v0/console-service.schema.json",
  consoleApprobation: "https://noortrace.example/schemas/v0/console-approbation.schema.json",
});

let registre = null;

/**
 * Registre des schémas embarqués, chargé une fois.
 * @returns {RegistreSchemas}
 */
export function registreSchemas() {
  if (registre) return registre;
  const r = new RegistreSchemas();
  for (const f of FICHIERS_SCHEMAS) r.ajouter(JSON.parse(fs.readFileSync(path.join(REPERTOIRE_SCHEMAS, f), "utf8")));
  registre = r;
  return r;
}

/**
 * Valide contre une définition de `ticket-v0` (`$defs/<nom>`).
 * @param {string} nom
 * @param {unknown} v
 */
export function conformeTicket(nom, v) {
  return registreSchemas().estValide(`${IDS.ticket}#/$defs/${nom}`, v);
}
