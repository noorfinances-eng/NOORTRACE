// Validation des documents du registre contre leurs schémas (CT-4 §9.4 :
// index de capture `operations-registre-v0`, envoi, issue, demande de
// signature ; CT-6 §11.2 : `registre-v0`, `certificat_commit`,
// `validateurs-v0`), avec le validateur JSON Schema du noyau.
//
// Le validateur du noyau ne connaît pas `contains`, `minContains` et
// `maxContains`, que `registre-v0` emploie pour compter les rôles des
// entrées : ces trois mots-clés sont retirés du schéma enregistré et la
// règle qu'ils portent (exactement une `cloture`, une `ancre`, au plus 8
// `inscription`, au plus une `ancre_point_de_controle`) est appliquée à part
// par `verifierRegistreV0`. Le test compare les copies embarquées aux
// fichiers de spec/schemas, cette amputation exceptée.

import { RegistreSchemas } from "@noortrace/noyau";
import { SCHEMA_INSTANCE_REGISTRE, SCHEMA_OPERATIONS_REGISTRE, SCHEMA_REGISTRE, SCHEMA_VALIDATEURS } from "./schemas-v0.mjs";

export { SCHEMA_INSTANCE_REGISTRE, SCHEMA_OPERATIONS_REGISTRE, SCHEMA_REGISTRE, SCHEMA_VALIDATEURS };
export const ID_INSTANCE = SCHEMA_INSTANCE_REGISTRE.$id;

export const ID_OPERATIONS = SCHEMA_OPERATIONS_REGISTRE.$id;
export const ID_REGISTRE = SCHEMA_REGISTRE.$id;
export const ID_VALIDATEURS = SCHEMA_VALIDATEURS.$id;

/** Bornes de rôles de `registre.json` (CT-6 EX-11.10, EX-11.23). */
export const BORNES_ROLES = Object.freeze({ cloture: [1, 1], ancre: [1, 1], inscription: [0, 8], ancre_point_de_controle: [0, 1] });

function schemaRegistreSansContains() {
  const copie = JSON.parse(JSON.stringify(SCHEMA_REGISTRE));
  delete copie.properties.entries.allOf;
  return copie;
}

/** Les quatre noms de contrats qu'un manifeste d'instance porte au moins une fois (`contains` du schéma). */
export const NOMS_CONTRATS = Object.freeze(["AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"]);

function schemaInstanceSansContains() {
  const copie = JSON.parse(JSON.stringify(SCHEMA_INSTANCE_REGISTRE));
  delete copie.properties.contracts.allOf;
  return copie;
}

/** Registre des quatre schémas (`registre-v0` et `instance-registre-v0` sans leurs `contains`, appliqués à part). */
export const REGISTRE_SCHEMAS = new RegistreSchemas([SCHEMA_OPERATIONS_REGISTRE, schemaRegistreSansContains(), SCHEMA_VALIDATEURS, schemaInstanceSansContains()]);

/** Valide un manifeste d'instance (`instance-registre-v0`, RG-16) : schéma et présence de chacun des quatre contrats. */
export function verifierManifesteSchema(manifeste) {
  const r = REGISTRE_SCHEMAS.valider(ID_INSTANCE, manifeste);
  const erreurs = [...r.erreurs];
  if (r.valide) {
    for (const nom of NOMS_CONTRATS) if (!manifeste.contracts.some((c) => c && c.name === nom)) erreurs.push(`/contracts : aucun contrat ${nom}`);
  }
  return { valide: erreurs.length === 0, erreurs };
}

/** Valide un index de capture (racine d'`operations-registre-v0`). */
export function verifierIndexCapture(index) {
  return REGISTRE_SCHEMAS.valider(ID_OPERATIONS, index);
}

/** Valide un envoi (`#/$defs/envoi`). */
export function verifierEnvoi(envoi) {
  return REGISTRE_SCHEMAS.valider(`${ID_OPERATIONS}#/$defs/envoi`, envoi);
}

/** Valide une issue (`#/$defs/issue`). */
export function verifierIssue(issue) {
  return REGISTRE_SCHEMAS.valider(`${ID_OPERATIONS}#/$defs/issue`, issue);
}

/** Valide une demande de signature (`#/$defs/demande_signature`). */
export function verifierDemandeSchema(demande) {
  return REGISTRE_SCHEMAS.valider(`${ID_OPERATIONS}#/$defs/demande_signature`, demande);
}

/**
 * Valide `registre.json` : schéma `registre-v0` et comptes de rôles
 * (exactement une `cloture`, une `ancre`, au plus 8 `inscription`, au plus
 * une `ancre_point_de_controle`).
 */
export function verifierRegistreV0(registre) {
  const r = REGISTRE_SCHEMAS.valider(ID_REGISTRE, registre);
  const erreurs = [...r.erreurs];
  if (r.valide) {
    const comptes = {};
    for (const e of registre.entries) comptes[e.role] = (comptes[e.role] ?? 0) + 1;
    for (const [role, [min, max]] of Object.entries(BORNES_ROLES)) {
      const n = comptes[role] ?? 0;
      if (n < min || n > max) erreurs.push(`/entries : ${n} entrée(s) de rôle ${role}, attendu entre ${min} et ${max}`);
    }
  }
  return { valide: erreurs.length === 0, erreurs };
}

/** Valide `certificat-commit.json` (`registre-v0#/$defs/certificat_commit`). */
export function verifierCertificatCommitV0(document) {
  return REGISTRE_SCHEMAS.valider(`${ID_REGISTRE}#/$defs/certificat_commit`, document);
}

/** Valide `validateurs.json` (`validateurs-v0`). */
export function verifierValidateursV0(document) {
  return REGISTRE_SCHEMAS.valider(ID_VALIDATEURS, document);
}
