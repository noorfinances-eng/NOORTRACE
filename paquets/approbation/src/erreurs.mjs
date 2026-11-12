// Erreurs du service (CT-3 §12.8) : une raison de la liste fermée, un message
// ASCII et des données ; rendues en HTTP 4xx ou 5xx de corps
// `{ "error": { "code", "message", "data" } }`.

/** Raisons de la table 12.8 que le service émet (`$defs/raison` de ticket-v0, et celles du canal de la console). */
export const RAISONS_SERVICE = Object.freeze([
  "requete_invalide",
  "non_pret",
  "politique_invalide",
  "politique_inconnue",
  "ticket_inconnu",
  "ticket_deja_ouvert",
  "ticket_non_ouvert",
  "ticket_clos_aux_votes",
  "jeu_non_fige",
  "signature_invalide",
  "hors_jeu",
  "auto_approbation",
  "recuse",
  "motif_trop_long",
  "plafond_atteint",
  "vote_identique",
  "retrait_non_autorise",
  "session_non_autorisee",
  "identite_invalide",
  "non_administrateur",
  "entree_inconnue",
  "adresse_inconnue",
  "message_invalide",
  "nonce_inconnu",
  "nonce_deja_utilise",
  "inscription_expiree",
  "origine_differente",
  "organisation_differente",
  "identite_differente",
  "adresse_differente",
  "identite_desactivee",
  "adresse_deja_attribuee",
  "etat_incompatible",
  "auto_validation",
  "revocation_non_autorisee",
  "demandeur_deja_lie",
  "demandeur_inconnu",
]);

// Statut HTTP d'une erreur (lecture 20 du LISEZMOI, rubrique e.2 des
// interfaces) : toute raison absente de cette table, qui refuse une entrée de
// ticket ou une opération de l'annuaire, reçoit 409.
const STATUTS = {
  requete_invalide: 400,
  identite_invalide: 400,
  message_invalide: 400,
  politique_invalide: 422,
  session_non_autorisee: 403,
  non_administrateur: 403,
  auto_validation: 403,
  revocation_non_autorisee: 403,
  ticket_inconnu: 404,
  entree_inconnue: 404,
  adresse_inconnue: 404,
  nonce_inconnu: 404,
  demandeur_inconnu: 404,
  non_pret: 503,
  politique_inconnue: 409,
  plafond_atteint: 429,
};

const MESSAGES = {
  requete_invalide: "corps ou entree non conforme",
  non_pret: "jeu d'approbateurs jamais lu",
  politique_invalide: "politique d'approbation refusee",
  politique_inconnue: "version de politique non chargee",
  ticket_inconnu: "identifiant de ticket inconnu",
  ticket_deja_ouvert: "ticket deja ouvert pour une autre demande",
  ticket_non_ouvert: "ticket non ouvert",
  ticket_clos_aux_votes: "ticket clos aux votes",
  jeu_non_fige: "jeu d'approbateurs non fige",
  signature_invalide: "signature invalide",
  hors_jeu: "adresse hors du jeu fige",
  auto_approbation: "separation des taches",
  recuse: "membre recuse",
  motif_trop_long: "motif de plus de 1024 caracteres",
  plafond_atteint: "plafond de tickets non decides atteint",
  vote_identique: "vote identique au vote courant",
  retrait_non_autorise: "retrait non autorise",
  session_non_autorisee: "session non autorisee",
  identite_invalide: "identite de session hors de la forme canonique",
  non_administrateur: "identite absente de administrators",
  entree_inconnue: "entree absente de l'annuaire",
  adresse_inconnue: "adresse absente de l'entree",
  message_invalide: "message d'inscription non conforme",
  nonce_inconnu: "nonce d'inscription inconnu",
  nonce_deja_utilise: "nonce d'inscription deja presente",
  inscription_expiree: "reception hors de la validite du message",
  origine_differente: "origine differente de console_origin",
  organisation_differente: "organisation differente de celle de l'annuaire",
  identite_differente: "identite differente de la session ou du defi",
  adresse_differente: "adresse differente de la requete ou du defi",
  identite_desactivee: "entree desactivee",
  adresse_deja_attribuee: "adresse deja presente dans l'annuaire",
  etat_incompatible: "operation impossible dans cet etat",
  auto_validation: "validation par la personne de l'entree",
  revocation_non_autorisee: "revocation par une autre identite",
  demandeur_deja_lie: "alias de demandeur deja lie",
  demandeur_inconnu: "alias de demandeur absent de l'entree",
};

/** Erreur rendue par le service. */
export class ErreurService extends Error {
  /**
   * @param {string} code raison de la table 12.8
   * @param {object} [data]
   * @param {string} [message] texte ASCII
   */
  constructor(code, data = {}, message) {
    super(message ?? MESSAGES[code] ?? code);
    this.name = "ErreurService";
    this.code = code;
    this.data = data;
  }

  /** Statut HTTP de l'erreur (4xx, sauf indisponibilité). */
  get statut() {
    return STATUTS[this.code] ?? 409;
  }

  /** Corps de la réponse d'erreur (12.8). */
  corps() {
    return { error: { code: this.code, message: this.message.replace(/[^\x20-\x7e]/g, "?"), data: this.data } };
  }
}
