// Registre des schémas de CT-1 (copies embarquées de spec/schemas) et
// validation par nom.
//
// Deux schémas dérivés, construits en mémoire, valident l'enveloppe de
// voisins.json et de approbations.json sans leurs événements : CT-1 §11.4
// range un défaut de l'enveloppe sous C-1 (voisins) ou A-1 (approbations), et
// un défaut d'un événement sous E-1. Les événements sont ensuite validés un à
// un contre le schéma d'événement.

import {
  SCHEMA_ATTESTATION_PERIMETRE,
  SCHEMA_DOSSIER,
  SCHEMA_EVENEMENT,
  SCHEMA_MANIFESTE,
  SCHEMA_POINT_DE_CONTROLE,
} from "./schemas-v0.mjs";
import { RegistreSchemas } from "./validation-schema.mjs";

const DRAFT = "https://json-schema.org/draft/2020-12/schema";
const ID_DOSSIER = SCHEMA_DOSSIER.$id;
const ID_ENVELOPPE_VOISINS = "https://noortrace.example/schemas/v0/noyau/enveloppe-voisins.schema.json";
const ID_ENVELOPPE_APPROBATIONS = "https://noortrace.example/schemas/v0/noyau/enveloppe-approbations.schema.json";

function cloner(v) {
  return v === undefined ? v : JSON.parse(JSON.stringify(v));
}

// Rend absolues les références internes d'un fragment du schéma de dossier.
function referencesAbsolues(s) {
  if (Array.isArray(s)) return s.map(referencesAbsolues);
  if (s && typeof s === "object") {
    const sortie = {};
    for (const [k, v] of Object.entries(s)) {
      sortie[k] = k === "$ref" && typeof v === "string" && v.startsWith("#") ? ID_DOSSIER + v : referencesAbsolues(v);
    }
    return sortie;
  }
  return s;
}

const enveloppeVoisins = (() => {
  const s = cloner(SCHEMA_DOSSIER.$defs.voisins);
  s.properties.previous = { type: ["object", "null"] };
  s.properties.next = { type: ["object", "null"] };
  return { $schema: DRAFT, $id: ID_ENVELOPPE_VOISINS, ...referencesAbsolues(s) };
})();

const enveloppeApprobations = (() => {
  const s = cloner(SCHEMA_DOSSIER.$defs.approbations);
  s.properties.events.items = { type: "object" };
  return { $schema: DRAFT, $id: ID_ENVELOPPE_APPROBATIONS, ...referencesAbsolues(s) };
})();

/** Registre des cinq schémas de CT-1 et des deux enveloppes dérivées. */
export const REGISTRE = new RegistreSchemas([
  SCHEMA_EVENEMENT,
  SCHEMA_MANIFESTE,
  SCHEMA_POINT_DE_CONTROLE,
  SCHEMA_ATTESTATION_PERIMETRE,
  SCHEMA_DOSSIER,
  enveloppeVoisins,
  enveloppeApprobations,
]);

/** Noms de schémas admis par `validerSchema`, avec leur référence. */
export const SCHEMAS = Object.freeze({
  evenement: SCHEMA_EVENEMENT.$id,
  manifeste: SCHEMA_MANIFESTE.$id,
  "point-de-controle": SCHEMA_POINT_DE_CONTROLE.$id,
  "attestation-perimetre": SCHEMA_ATTESTATION_PERIMETRE.$id,
  "attestation-signee": SCHEMA_ATTESTATION_PERIMETRE.$id + "#/$defs/attestation_signee",
  "jeu-approbateurs": SCHEMA_ATTESTATION_PERIMETRE.$id + "#/$defs/jeu_approbateurs",
  dossier: ID_DOSSIER,
  voisins: ID_DOSSIER + "#/$defs/voisins",
  chemin: ID_DOSSIER + "#/$defs/chemin",
  manifeste_sig: ID_DOSSIER + "#/$defs/manifeste_sig",
  cles: ID_DOSSIER + "#/$defs/cles",
  approbations: ID_DOSSIER + "#/$defs/approbations",
  points_de_controle: ID_DOSSIER + "#/$defs/points_de_controle",
  preuve_coherence: ID_DOSSIER + "#/$defs/preuve_coherence",
  attestation_perimetre: ID_DOSSIER + "#/$defs/attestation_perimetre",
  "enveloppe-voisins": ID_ENVELOPPE_VOISINS,
  "enveloppe-approbations": ID_ENVELOPPE_APPROBATIONS,
});

/**
 * Valide une instance contre un schéma de CT-1 désigné par son nom (clé de
 * SCHEMAS).
 * @param {keyof typeof SCHEMAS} nom
 * @param {unknown} instance
 * @returns {{valide: boolean, erreurs: string[]}}
 */
export function validerSchema(nom, instance) {
  const ref = SCHEMAS[nom];
  if (!ref) throw new RangeError(`schéma inconnu : ${nom}`);
  return REGISTRE.valider(ref, instance);
}
