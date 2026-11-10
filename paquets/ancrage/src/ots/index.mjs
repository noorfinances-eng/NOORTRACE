// Sous-module « ots » du composant d'ancrage (CT-5 §6 ; CT-6 §10) : client
// OpenTimestamps. Voir INTERFACES.md, rubrique B, et LISEZMOI-B.md.

export {
  EN_TETE_MAGIQUE, VERSION, OP, PROFIL_V0, ETIQUETTE_BITCOIN, ETIQUETTE_EN_ATTENTE, BORNES, ErreurOts, Noeud,
  lireOts, ecrireOts, lireTimestamp, ecrireTimestamp, fusionnerOts, construirePreuve, engagementOctets,
  attestationBitcoin, attestationEnAttente, attestationsEnAttente, appliquerOperation,
  encoderVaruint, encoderVarbytes, comparerOctets, comparerAttestations, comparerOperations,
} from "./format.mjs";
export { STATUT, RAISON, VERIFICATIONS, verifierOts, verifierChaineEntetes, executerArbre, hauteursAttestees, etatPreuve, admissionApresFusion } from "./verification.mjs";
export {
  SCHEMA_ENTETES_BITCOIN, BORNES_ENTETES, RESEAUX, ErreurEntetes, fichierEntetes, lireFichierEntetes, rpcBitcoinHttp,
  bornesFichierEntetes, decomposerEnTete, dsha, inverser, setCompact, getCompact, hachageEnEntier, premierDefautDeChainage, octetsDesEnTetes,
} from "./entetes.mjs";
export { ACCEPT_OTS, DEFAUTS, ErreurTransport, engagement, soumettre, mettreANiveau, cadenceMiseANiveau, relireReponseCalendrier, transportHttps } from "./calendriers.mjs";
export { DepotOts, ErreurDepot, nomObjet, nomPeriode } from "./depot.mjs";
