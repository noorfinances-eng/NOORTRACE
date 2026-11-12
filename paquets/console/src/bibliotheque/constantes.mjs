// Listes figées de CT-3 : les quatorze méthodes du canal de la console
// (table d'EX-12.13), les onze méthodes qui exigent une authentification
// récente avant d'être relayées (EX-13.8) et l'énumération `$defs/code_console`
// de console-approbation-v0 (13.14, EX-13.29).

/** Les quatorze méthodes de la table d'EX-12.13, dans l'ordre de la table. */
export const METHODES_CANAL = Object.freeze([
  "tickets",
  "consulter",
  "voter",
  "recuser",
  "retirer",
  "annuaire",
  "preparer_inscription",
  "inscrire",
  "valider",
  "revoquer",
  "desactiver",
  "reactiver",
  "lier_demandeur",
  "delier_demandeur",
]);

/** Les onze méthodes d'EX-13.8, dans l'ordre de la liste. */
export const METHODES_REAUTHENTIFICATION = Object.freeze([
  "voter",
  "recuser",
  "retirer",
  "preparer_inscription",
  "inscrire",
  "valider",
  "revoquer",
  "desactiver",
  "reactiver",
  "lier_demandeur",
  "delier_demandeur",
]);

/** L'énumération `$defs/code_console`, dans l'ordre du schéma. */
export const CODES_CONSOLE = Object.freeze([
  "evenement_invalide",
  "piece_invalide",
  "champ_different",
  "argument_different",
  "argument_absent_de_l_affichage",
  "empreinte_divergente",
  "ticket_clos_aux_votes",
  "jeu_non_fige",
  "identite_inconnue",
  "identite_desactivee",
  "adresse_non_attribuee",
  "hors_jeu",
  "auto_approbation",
  "recuse",
  "session_du_demandeur",
  "motif_trop_long",
  "decision_absente",
  "aucun_fournisseur",
  "fournisseur_non_choisi",
  "annonce_invalide",
  "annonce_en_double",
  "adresse_non_exposee",
  "refus_approbateur",
  "non_autorise",
  "methode_non_prise_en_charge",
  "deconnecte",
  "chaine_deconnectee",
  "erreur_portefeuille",
  "reponse_invalide",
  "delai_depasse",
  "signature_invalide",
  "adresse_differente",
  "fichier_cle_invalide",
  "fichier_cle_non_pris_en_charge",
  "mot_de_passe_ou_mac",
  "cle_invalide",
  "message_invalide",
  "origine_differente",
  "identite_differente",
  "reponse_service_invalide",
]);
