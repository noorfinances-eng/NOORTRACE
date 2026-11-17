// Classement des échecs du registre pour le planificateur (CT-5 EX-8.10 ;
// complément du 2026-11-16).
//
// Le planificateur tient pour définitif un code qui commence par `refus_` :
// l'ancre d'un point passe `refusee` (alerte `prestataires_epuises` majeure),
// celle d'une période est reprise au pas `retry.max_ms`, sans gigue, avec
// l'alerte `prestataires_epuises` critique (8.9). Tout autre code est
// transitoire : reprise à l'attente d'EX-8.9, gigue comprise. L'`Envoyeur`
// rend les codes de CT-4 §7.11 tels quels ; le composant les passe au
// planificateur par `codePlanificateur`, qui préfixe `refus_` aux codes que
// la table de CT-5 EX-8.10 classe « refus définitif ».
//
// Définitifs : les refus d'inscription et de clé (état de la clé au
// registre, signature de la clé de chaîne), qu'un renvoi des mêmes octets
// rend à l'identique tant que l'exploitant n'a pas agi (inscrire la clé,
// changer de clé de chaîne, corriger la configuration).
// `empreinte_squattee` garde son code et sa conduite propre (EX-9.7).

/** Codes de CT-4 §7.11 classés « refus définitif » par CT-5 EX-8.10 (complément du 2026-11-16). */
export const CODES_REFUS_DEFINITIF = Object.freeze([
  // OP-9 : clé de chaîne non inscrite, ou clé Ed25519 du document inscrite sous une autre clé de chaîne.
  "cle_chaine_non_inscrite",
  // OP-8 : état de la clé au registre ; une clé révoquée n'est jamais réinscrite.
  "cle_chaine_autre_organisation",
  "cle_deja_active",
  "cle_revoquee",
  "cle_ed25519_active",
  "cle_inconnue",
  "organisation_inconnue",
  // OP-4 : clé de classe de garde D sur une instance de production.
  "cle_invalide",
  // OP-7 : signature de la clé de chaîne non canonique, ou signataire qui n'est pas l'émetteur.
  "signature_non_canonique",
  "signataire_hors_jeu",
]);

const DEFINITIFS = new Set(CODES_REFUS_DEFINITIF);

/** Préfixe des codes définitifs pour le planificateur (CT-5 EX-8.10). */
export const PREFIXE_REFUS = "refus_";

/**
 * Code d'un échec du registre tel que le planificateur le reçoit (entrée
 * `echec_registre`) : `refus_<code>` pour un code de `CODES_REFUS_DEFINITIF`,
 * le code inchangé sinon (déjà préfixé, `empreinte_squattee`, transitoire).
 * @param {string} code code rendu par l'`Envoyeur` (CT-4 §7.11) ou par le composant
 * @returns {string}
 */
export function codePlanificateur(code) {
  const c = String(code);
  return DEFINITIFS.has(c) ? `${PREFIXE_REFUS}${c}` : c;
}
