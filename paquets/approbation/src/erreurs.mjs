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
]);

const STATUTS = {
  requete_invalide: 400,
  identite_invalide: 400,
  politique_invalide: 422,
  ticket_inconnu: 404,
  session_non_autorisee: 403,
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
