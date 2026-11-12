// Sous-module « planificateur » du composant d'ancrage (CT-5 §4, §8, §9.2,
// §10.2, §12 ; rubrique C d'INTERFACES.md) : configuration (AN-1) et
// projection (EX-8.2), machine à états déterministe à horloge injectée et sans
// réseau (EX-8.13), rejeu des traces (EX-8.16, AN-42), file durable (EX-8.5),
// échéances et cadence (AN-2), admission par le noyau (AN-3), sélection et
// comptages (AN-4), coût (AN-59), complétude au registre (AN-61), supervision
// (EX-8.15). Les noms exportés qui pourraient coïncider avec ceux d'un autre
// sous-module (lecteur DER du lot A, docType du lot D) portent un suffixe.

export { validerConfiguration, commeServeurInterne, projection, validerProjection, validerSchemaAncrage, motifCertificatPemIllisible, REGISTRE_ANCRAGE, ID_SCHEMA_ANCRAGE, ID_SCHEMA_PLANIFICATEUR, PROFILS } from "./configuration.mjs";
export { SCHEMA_ANCRAGE, SCHEMA_PLANIFICATEUR } from "./schemas-ancrage.mjs";
export { creerPlanificateur, Planificateur, ErreurPlanificateur, noncesAleatoires, SORTES, TAILLE_CAPTURE_REPRESENTEE, DOC_TYPE_PERIODE as DOC_TYPE_PERIODE_PLANIFICATEUR } from "./planificateur.mjs";
export { rejouerTrace, comparer as comparerTrace, noncesVecteurs, nonceVecteur, nonceOtsVecteur, JOURNAUX_VECTEURS, ETIQUETTES as ETIQUETTES_VECTEURS } from "./traces.mjs";
export { FileDurable, lireFiles, decoderFile, dernieresLignes, fusionner as fusionnerLignesFile, trierDemandes, fichiersDeFile, controlerDemande, validerLigneDemande, totalTentatives, supprimerResidusCompactage, idCoherent, ErreurDemandeNonConforme, estFinale, ETATS_FINAUX, TAILLE_MAX_LIGNE, FENETRE_TENTATIVES, COMPACT_BYTES_DEFAUT, DELAI_APRES_ECHEC_MS, SUFFIXE_COMPACTAGE, nomFichier as nomFichierFile } from "./file.mjs";
export { echeances, tableEcheances, constaterCadence } from "./echeances.mjs";
export { admettrePoint, admettreManifeste, verifierSerie, indexCles, REGLES_ADMISSION } from "./admission.mjs";
export { pointsAAncrer, compterJetons, tableComptages } from "./comptages.mjs";
export { cout, GAZ_ANCRE_MAX, GAZ_CLOTURE_MAX } from "./cout.mjs";
export { verifierCompletudeRegistre } from "./completude.mjs";
export { Supervision, METRIQUES_ANCRAGE, EVENEMENTS_JOURNAL, EVENEMENTS_TENTATIVE, BORNES_HISTOGRAMME, MAX_LIGNES_DEFAUT, normaliserValeurEtiquette } from "./supervision.mjs";
export { construireRequete as requeteTimeStampReq, relireRequete as relireTimeStampReq, encoderOid as encoderOidDer, nonceEntier, nonceHex, ErreurRequete as ErreurRequeteDer } from "./requete-der.mjs";
