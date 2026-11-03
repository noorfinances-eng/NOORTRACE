// Signataires des classes A, B et C (CT-2 §11.2) et fabrique (EX-15.4 pas 5).

export { ErreurSignataire, clePubliqueSpki, clePubliquePem, crc32c, contexteChiffrement } from "./commun.mjs";
export { SignatairePkcs11, MECANISMES_PKCS11, MODULE_LOGICIEL, AUXILIAIRE_PKCS11 } from "./pkcs11.mjs";
export { SignataireTransit } from "./transit.mjs";
export { SignataireAwsKms, ClientKms, IdentiteAws, entetesSigv4Kms, identifiantsAwsEnvironnement, origineKms, desenvelopperAwsKms, BORNE_MESSAGE_AWS_KMS } from "./aws-kms.mjs";
export { SignataireCloudKms, ClientCloudKms, JetonGoogle, JetonMetadonneesGoogle, origineCloudKms, desenvelopperCloudKms, PORTEE_CLOUDKMS } from "./gcp-kms.mjs";
export { JetonAzure, desenvelopperAzure, porteeAzure, VERSION_API_KEYVAULT } from "./azure.mjs";
export { desceller } from "./tpm2.mjs";
export { SignataireEnveloppe, fichierCleSuivante, TAILLE_GRAINE } from "./enveloppe.mjs";
export { signataireDepuisConfiguration, environnementAuxiliaire, variablesSecretes } from "./fabrique.mjs";
export { rapprocher, compterAuditTransit, compterObjetsSignes, principalRapprochement } from "./rapprochement.mjs";
