// Identifiants d'objets employés par le serveur interne (CT-6 §9.4 ; RFC 3161
// §2.4.2 ; RFC 5035 §3 ; RFC 5280 §4.2.1 et §5.2 ; RFC 5754).

export const OID = Object.freeze({
  // CMS et RFC 3161
  signedData: "1.2.840.113549.1.7.2",
  tstInfo: "1.2.840.113549.1.9.16.1.4",
  contentType: "1.2.840.113549.1.9.3",
  messageDigest: "1.2.840.113549.1.9.4",
  signingCertificateV2: "1.2.840.113549.1.9.16.2.47",
  // Condensés
  sha256: "2.16.840.1.101.3.4.2.1",
  sha384: "2.16.840.1.101.3.4.2.2",
  sha512: "2.16.840.1.101.3.4.2.3",
  sha1: "1.3.14.3.2.26",
  md5: "1.2.840.113549.2.5",
  // Clés et signatures
  rsaEncryption: "1.2.840.113549.1.1.1",
  sha256WithRSAEncryption: "1.2.840.113549.1.1.11",
  ecPublicKey: "1.2.840.10045.2.1",
  ecdsaWithSHA256: "1.2.840.10045.4.3.2",
  courbeP256: "1.2.840.10045.3.1.7",
  // Extensions X.509
  subjectKeyIdentifier: "2.5.29.14",
  keyUsage: "2.5.29.15",
  basicConstraints: "2.5.29.19",
  cRLNumber: "2.5.29.20",
  cRLReasons: "2.5.29.21",
  cRLDistributionPoints: "2.5.29.31",
  authorityKeyIdentifier: "2.5.29.35",
  extKeyUsage: "2.5.29.37",
  timeStamping: "1.3.6.1.5.5.7.3.8",
  // Attributs de nom
  commonName: "2.5.4.3",
  countryName: "2.5.4.6",
  organizationName: "2.5.4.10",
  organizationalUnitName: "2.5.4.11",
});

/** Condensés admis par le serveur (AN-23) et longueur attendue de `hashedMessage`. */
export const CONDENSES_ADMIS = Object.freeze({
  [OID.sha256]: { nom: "sha256", longueur: 32 },
  [OID.sha384]: { nom: "sha384", longueur: 48 },
  [OID.sha512]: { nom: "sha512", longueur: 64 },
});

/** Bits de `PKIFailureInfo` (RFC 3161 §2.4.2). */
export const ECHEC = Object.freeze({
  badAlg: 0,
  badRequest: 2,
  badDataFormat: 5,
  timeNotAvailable: 14,
  unacceptedPolicy: 15,
  unacceptedExtension: 16,
  addInfoNotAvailable: 17,
  systemFailure: 25,
});

/** Valeurs de `PKIStatus` (RFC 3161 §2.4.2). */
export const STATUT = Object.freeze({
  granted: 0,
  grantedWithMods: 1,
  rejection: 2,
  waiting: 3,
  revocationWarning: 4,
  revocationNotification: 5,
});
