// Sous-module « registre » du composant d'ancrage (CT-5 §9, EX-8.10, EX-10.4 ;
// CT-4 §4.5, §6.4 à §6.7, §7.3, §8.3, §8.6, §9 ; CT-6 §11) : ancre des points
// et des périodes au registre, capture et export. Contrat : INTERFACES.md,
// rubrique D ; écarts et lectures : LISEZMOI-D.md.

export {
  SignataireChaine, SignataireChaineFichier,
  adresseDepuisClePublique, recouvrerSignataire, recouvrerClePublique65, clePubliqueNonCompressee, lireSignature, signatureDepuisDer,
} from "./cle-chaine.mjs";

export {
  LIBELLE_PERIODE, LIBELLE_POINT_DE_CONTROLE, DOC_TYPE_PERIODE, DOC_TYPE_POINT_DE_CONTROLE, TABLE_DOC_TYPES,
  SELECTEURS, SIGNATURES_FONCTIONS, SUJETS, SIGNATURES_EVENEMENTS, EVENEMENT_PAR_ROLE, OPERATIONS_JEU,
  verifierDocType, libelleDocType, empreinteAncre, verifierSlug, verifierNomJournal,
  lirePeriodMeta, verifierPeriodMeta, encoderTuplePeriodMeta, encoderPeriodMeta,
  periodDigest, anchorDigest, registerDigest, revokeDigestEnregistreur, revokeDigestAncre, adminOpDigest, hachageSigne,
  verifierSignatureCondense, verifierJeuSignatures,
  encoderAnchor, encoderSubmitPeriod, encoderRegisterRecorder, encoderRevokeRecorder,
  encoderLookup, encoderIsAnchored, encoderAnchorDigest, encoderPeriodDigest, encoderIsActiveRecorder, encoderRecorderOf,
  encoderRecorderByPubKey, encoderIsKnown, encoderLatestPeriodOf, encoderGetPeriod,
  mots, decoderLookup, decoderRecorder, decoderBool, decoderBytes32, decoderUint, decoderGetPeriod, decoderJournal, adresseMinuscule,
} from "./encodage.mjs";

export {
  construireTransaction, signerTransaction, serialiserTransaction, chargeASignerDe, lireTransaction, verifierRG15,
  fraisRemplacement, adresseCreation, ErreurTransaction, LIMITE_GAZ_MAX, FRAIS_NOMINAUX,
} from "./transaction.mjs";

export {
  rlp, rlpOctets, rlpListe, rlpEntier, decoderRlp, entierRlp, ErreurRlp, decoderBase64Noeud, encoderBase64,
  versEntier, entierVersOctets, entierVersOctetsMinimaux, octetsVersEntier, estQuantite, quantiteVersEntier, entierVersQuantite,
} from "./octets.mjs";

export {
  DOMAINE_BLOC_BFT, CHAMPS_ENTETE, hachageBlocBft, champsEntete, bloomJournaux, lireRecu, encoderRecu, hexPrefix,
  racineTrie, racineListe, racineRecus, racineTransactions,
} from "./trie.mjs";

export {
  DOMAINE_BFT, BORNES_CERTIFICAT, lireJeu, hachageJeu, hachageJeuHex, quorum, lireJeux, jeuPourHauteur, membresObjetJson, lireLigne,
  condenseEnveloppe, verifierEnveloppe, lireCertificat, verifierCertificat, classerErreurCertificat,
} from "./certificat.mjs";

export { ClientRpc, ErreurRpc, transportHttp, lireReponseRpc, clientSurPoint, TAILLE_REPONSE_MAX } from "./rpc.mjs";

export {
  ErreurLecture, appelLecture, lookup, isAnchored, anchorDigestContrat, periodDigestContrat, recorderOf, recorderByPubKey,
  isActiveRecorder, isKnown, latestPeriodOf, getPeriod, classerEmpreinte,
} from "./lookup.mjs";

export {
  ROLES_CAPTURE, BORNES_CAPTURE, nomBloc, nomRecu, nomCertificat, nomIndex, lireFichierRpc, lecteurRepertoire, listerCaptures,
  verifierCapture, capturer, obtenirCertificat, ecrireExclusif, synchroniserRepertoire, serialiserIndex,
} from "./capture.mjs";

export { Envoyeur, DELAIS_DEFAUT, lireEnvois, envoisSansIssue, envoisSansIssueParHash, nomEnvoi, nomIssue } from "./envoi.mjs";

export {
  ROLES_EXPORTES, BORNES_EXPORT, lireCapture, roleEntree, entreeRegistre, exporterPartiesRegistre, choisirCaptures,
} from "./export.mjs";

export { condenseDemande, verifierDemande } from "./demande.mjs";

export {
  ligneRegles, verifierGenese, verifierJeuxValidateurs, contratsEnService, verifierContrats, ancreReviseur, verifierManifeste,
  verifierManifesteRepertoire,
} from "./manifeste.mjs";

export {
  SCHEMA_OPERATIONS_REGISTRE, SCHEMA_REGISTRE, SCHEMA_VALIDATEURS, SCHEMA_INSTANCE_REGISTRE, REGISTRE_SCHEMAS, BORNES_ROLES, NOMS_CONTRATS,
  verifierIndexCapture, verifierEnvoi, verifierIssue, verifierDemandeSchema, verifierRegistreV0, verifierCertificatCommitV0, verifierValidateursV0,
  verifierManifesteSchema,
} from "./schemas.mjs";
