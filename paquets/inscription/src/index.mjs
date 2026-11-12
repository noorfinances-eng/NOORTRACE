// Point d'entrée de @noortrace/inscription : API programmatique de l'agent
// (démarrage, remise d'un travail ou d'une confirmation par un client de la
// prise, sans navigateur), formes des travaux et des champs, contrôle de
// réception du paquet client (EX-7.22). LISEZMOI.md, « API programmatique ».

export { demarrerAgent, preparerDemarrage, comptePair, AUXILIAIRE_PAIR, TAILLE_REQUETE_MAX, FILE_MAX, ErreurConfiguration } from "./agent/index.mjs";
export { remettre, remettreTravail, remettreConfirmation, ErreurAgent } from "./agent/client.mjs";
export { lireTravail, lireConfirmation, lireIdentite, COMMANDES, COMMANDE_OUTIL, OPERATIONS_CONFIRMATION } from "./commun/travaux.mjs";
export { controlerPaquet, nomPaquet, FICHIERS_RACINE, MANIFESTE_PAQUET } from "./commun/paquet.mjs";
export { ErreurChamp, ressembleASecret } from "./commun/champs.mjs";
export { lireReference, motifRefusReference } from "./commun/references.mjs";
export { registreSchemas, IDS, FICHIERS_SCHEMAS } from "./commun/schemas.mjs";
