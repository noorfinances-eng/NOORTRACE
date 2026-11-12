// Bibliothèque de la console (« @noortrace/console ») : réexporte chaque
// export de la section 1 du contrat de l'étape 6 (CT-3 EX-13.32, hors fichier
// de clé : le parcours d n'est pas offert), et les exports en plus que nomme
// le LISEZMOI.md de la bibliothèque. Chaque module de src/bibliotheque/ est
// atteignable depuis ce module.

// 1.3 Module d'annuaire.
export * from "./annuaire.mjs";
// 1.4 Signatures et portefeuille.
export { donneesPersonalSign, requetePersonalSign, preimageEip191, condenseEip191, verifierSignature } from "./signatures.mjs";
export { codeErreurPortefeuille, verifierReponse, analyserComptes, echeanceAttente, requeteVoter } from "./portefeuille.mjs";
// 1.5 Vue, condensés, modèle d'affichage, découverte, constantes.
export { analyserJsonStrict, jcs } from "./json.mjs";
export { hachageEvenement, condenses, empreinte, groupes } from "./condenses.mjs";
export { modeleAffichage, sessionDuModele } from "./modele.mjs";
export { decouvrir, Decouverte } from "./decouverte.mjs";
export { METHODES_CANAL, METHODES_REAUTHENTIFICATION, CODES_CONSOLE } from "./constantes.mjs";

// Exports en plus (LISEZMOI.md de la bibliothèque).
export { egaliteJson, cloner } from "./json.mjs";
export { sha256, keccak256 } from "./hachage.mjs";
export { versHex, depuisHex, utf8, concatener, estUtf8, decoderBase64 } from "./octets.mjs";
export { decoderInstant, encoderInstant, estInstant } from "./instants.mjs";
export { formeRequete, DEFINITION_REQUETE } from "./formes.mjs";
export { N_SECP256K1 } from "./signatures.mjs";
export { feuilles, resoudrePointeur } from "./modele.mjs";
