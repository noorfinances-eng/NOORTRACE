// Sous-module « rfc3161 » du composant d'ancrage (CT-5 §5, §10.2, §11 ; CT-6
// §9, §12.2, §12.4, §13.1, §13.4) : client RFC 3161 et vérification des jetons
// à l'acquisition. Contrat : INTERFACES.md, rubrique A ; écarts et lectures :
// LISEZMOI-A.md.

export { construireRequete, relireRequete, tirerNonce, nonceVersBigint, nonceVersHex8, ErreurRequete, NONCE_MAX, ALGORITHME_SHA256 } from "./requete.mjs";
export { lireReponse, lireJeton, lireTstInfo, ErreurReponse, FAILURE_INFO, TAILLE_MAX_JETON, CERTIFICATS_MAX } from "./reponse.mjs";
export {
  verifierJeton, normaliserAncres, ancresDepuisPrestataire, chercherChemin, ErreurAncres, VERIFICATIONS_ACQUISITION, CHEMIN_MAX,
  genTimeVersRfc3339, microsecondesVersRfc3339, accuracyMicrosecondes,
} from "./verification.mjs";
export { verifierRevocation, capturerCrls, RAISONS_TOLEREES } from "./revocation.mjs";
export { classerErreur, lireRetryAfter, bornerRetryAfter, attenteReprise, attenteTransitoire, issueDepuisClasse, RETRY_DEFAUT, RETRY_AFTER_MAX_S, ECHECS_PERMANENTS, ECHECS_TRANSITOIRES, HTTP_TRANSITOIRES, HTTP_RETRY_AFTER } from "./classement.mjs";
export { acquerir, controlerPrestataire, identifiantTentative, identifiantDemande, typeMedia, FRAICHEUR_DEFAUT } from "./acquisition.mjs";
export { DepotAncres, ErreurDepot, choisirPromu, nomPeriode, nomObjet, controlerIdentifiant, copieAutonome } from "./depot.mjs";
export { construireFiche, verifierFiche, epreuveAcceptation, nomFiche, clesInterdites, empreinteEpreuve, CLES_INTERDITES, MENTION_NON_QUALIFIE } from "./fiche.mjs";
export { transportHttps, controlerUrl, entetesRequete, autorisationBasic, ErreurTransport, CORPS_MAX, TYPES_REPONSE, TYPE_REQUETE, HOTES_LOCAUX } from "./transport.mjs";
export {
  lireCertificatPem, lireCertificat, lireCrl, lireCrlDer, decoderPem, certificatVersPem, crlVersPem, pointsDistributionCrl, urisOcsp, entreeRevocation,
  OID, HACHAGES, hacher, sha256Hex,
} from "./x509.mjs";
export { analyserAlgorithmeSignature, verifierSignatureBrute, verifierSignatureEmise, hachageAdmis, NOMS_SIGNATURE } from "./signatures.mjs";
export { ErreurDer, PROFONDEUR_MAX, lireTlv, lireSuite, lireUnique, enfants, parcourir as parcourirDer, lireEntier, lireOid, lireBooleen, lireChaine, lireGeneralizedTime, lireTemps, encoderTlv, encoderEntierNonNegatif, encoderOid } from "./der.mjs";
