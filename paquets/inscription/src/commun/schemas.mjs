// Schémas du paquet d'inscription (INTERFACES.md 0.4) : copies à l'identique
// de spec/schemas, chargées dans un `RegistreSchemas` de
// `@noortrace/approbation`. `instance-registre-v0` emploie le mot-clé
// `contains`, que ce validateur refuse à l'enregistrement (aucune ignorance
// silencieuse) : le manifeste d'instance se valide par `verifierManifesteSchema`
// de `@noortrace/ancrage/registre` (LISEZMOI.md, « Écarts »).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { RegistreSchemas } from "@noortrace/approbation";
import { verifierManifesteSchema } from "@noortrace/ancrage/registre";

/** Répertoire des copies de spec/schemas. */
export const REPERTOIRE_SCHEMAS = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "schemas");

/** Les neuf copies (INTERFACES.md 0.4), dans l'ordre du contrat. */
export const FICHIERS_SCHEMAS = Object.freeze([
  "inscription-client-v0.schema.json",
  "operations-registre-v0.schema.json",
  "instance-registre-v0.schema.json",
  "paquet-client-v0.schema.json",
  "configuration-approbation-v0.schema.json",
  "annuaire-approbateurs-v0.schema.json",
  "evenement-v0.schema.json",
  "ticket-v0.schema.json",
  "politique-approbation-v0.schema.json",
]);

const BASE = "https://noortrace.example/schemas/v0/";

/** `$id` des schémas employés. */
export const IDS = Object.freeze({
  inscription: `${BASE}inscription-client.schema.json`,
  operations: `${BASE}operations-registre.schema.json`,
  instance: `${BASE}instance-registre.schema.json`,
  paquet: `${BASE}paquet-client.schema.json`,
  configurationApprobation: `${BASE}configuration-approbation.schema.json`,
  annuaire: `${BASE}annuaire-approbateurs.schema.json`,
  politique: `${BASE}politique-approbation.schema.json`,
});

let registre = null;

/**
 * Registre des schémas du paquet, chargé une fois : tous sauf
 * `instance-registre-v0` (mot-clé `contains`, voir l'en-tête).
 * @returns {RegistreSchemas}
 */
export function registreSchemas() {
  if (registre) return registre;
  const r = new RegistreSchemas();
  for (const f of FICHIERS_SCHEMAS) {
    if (f === "instance-registre-v0.schema.json") continue;
    r.ajouter(JSON.parse(fs.readFileSync(path.join(REPERTOIRE_SCHEMAS, f), "utf8")));
  }
  registre = r;
  return r;
}

/**
 * Valide un document contre une référence de schéma (`IDS.x` ou
 * `IDS.x#/$defs/y`) ; le manifeste d'instance passe par
 * `verifierManifesteSchema`. Rend `{ valide, erreurs: string[] }`.
 */
export function valider(ref, document, schemas = registreSchemas()) {
  if (ref === IDS.instance) {
    const v = verifierManifesteSchema(document);
    return { valide: v.valide, erreurs: v.erreurs ?? [] };
  }
  const v = schemas.valider(ref, document);
  return { valide: v.valide, erreurs: v.erreurs.map((e) => `${e.pointeur || "/"} : ${e.regle}`) };
}
