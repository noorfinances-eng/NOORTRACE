// Fichier cles.json (CT-1 §11.2) : clés Ed25519 de l'enregistreur et leur
// validité annoncée. Sa lecture est la première partie du contrôle E-8 :
// schéma, org_id et journal_id de l'événement prouvé, key_id et public_key
// uniques, valid_to ≥ valid_from. Un fichier qui n'y satisfait pas est
// « inexploitable » : E-8 échoue, et E-11, P-5, K-3 ne sont pas exécutés.

import { decoderHorodatage, hexVersOctets } from "./conventions.mjs";
import { clePubliqueEd25519Admise } from "./hachage.mjs";
import { validerSchema } from "./schemas.mjs";

/**
 * @typedef {object} CleIndexee
 * @property {string} key_id
 * @property {string} public_key hexadécimal préfixé
 * @property {Uint8Array} octets clé publique, 32 octets
 * @property {boolean} admise clé publique admise par CT-1 §6.2 (canonique, pas de petit ordre)
 * @property {number} debut valid_from en millisecondes
 * @property {number|null} fin valid_to en millisecondes, null sans borne haute
 */

/**
 * Lit cles.json et l'indexe par key_id.
 * @param {unknown} cles contenu de cles.json
 * @param {{org_id?: string, journal_id?: string}} [attendus] identifiants de l'événement prouvé
 * @returns {{exploitable: boolean, erreurs: string[], cles: Map<string, CleIndexee>}}
 */
export function indexerCles(cles, attendus = {}) {
  const erreurs = [];
  const index = new Map();
  const schema = validerSchema("cles", cles);
  if (!schema.valide) {
    erreurs.push(...schema.erreurs.map((e) => `cles.json non conforme à son schéma : ${e}`));
    return { exploitable: false, erreurs, cles: index };
  }
  if (attendus.org_id !== undefined && cles.org_id !== attendus.org_id) {
    erreurs.push(`cles.json : org_id ${cles.org_id} différent de celui de l'événement ${attendus.org_id}`);
  }
  if (attendus.journal_id !== undefined && cles.journal_id !== attendus.journal_id) {
    erreurs.push(`cles.json : journal_id ${cles.journal_id} différent de celui de l'événement ${attendus.journal_id}`);
  }
  const publiques = new Set();
  for (const k of cles.keys) {
    if (index.has(k.key_id)) erreurs.push(`cles.json : key_id ${k.key_id} en double`);
    if (publiques.has(k.public_key)) erreurs.push(`cles.json : clé publique ${k.public_key} sous deux identifiants`);
    publiques.add(k.public_key);
    const debut = decoderHorodatage(k.valid_from);
    const fin = k.valid_to === null ? null : decoderHorodatage(k.valid_to);
    if (debut === null) erreurs.push(`cles.json : valid_from de ${k.key_id} n'est pas une date existante`);
    if (k.valid_to !== null && fin === null) erreurs.push(`cles.json : valid_to de ${k.key_id} n'est pas une date existante`);
    if (debut !== null && fin !== null && fin < debut) erreurs.push(`cles.json : valid_to de ${k.key_id} antérieur à valid_from`);
    if (!index.has(k.key_id)) {
      const octets = hexVersOctets(k.public_key, 32);
      index.set(k.key_id, {
        key_id: k.key_id,
        public_key: k.public_key,
        octets,
        admise: clePubliqueEd25519Admise(octets),
        debut,
        fin,
      });
    }
  }
  return { exploitable: erreurs.length === 0, erreurs, cles: index };
}

/**
 * Dit si un instant (millisecondes) est dans la validité annoncée d'une clé,
 * bornes incluses ; valid_to nul : pas de borne haute.
 * @param {CleIndexee} cle
 * @param {number} instant
 * @returns {boolean}
 */
export function dansValidite(cle, instant) {
  return instant >= cle.debut && (cle.fin === null || instant <= cle.fin);
}
