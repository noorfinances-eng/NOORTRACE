// Algorithmes de signature admis (CT-6 EX-9.11, EX-9.23, EX-9.24) et
// vérification par `node:crypto` (RSA PKCS #1 v1.5, RSASSA-PSS, ECDSA
// P-256/384/521). La structure des algorithmes est lue par le lecteur DER
// borné ; aucune exponentiation n'est faite sous une clé hors des bornes.

import { createPublicKey, verify, constants } from "node:crypto";
import { ETIQUETTE, enfants, lireEntier, lireAlgorithme, lireOid, lireUnique, attendre, estContexte, parametresAbsentsOuNuls, estUniversel } from "./der.mjs";
import { OID, HACHAGES } from "./x509.mjs";

const HACHAGES_ADMIS = new Set([OID.sha256, OID.sha384, OID.sha512]);
const RSA_AVEC_HACHAGE = Object.freeze({ [OID.sha256WithRSA]: OID.sha256, [OID.sha384WithRSA]: OID.sha384, [OID.sha512WithRSA]: OID.sha512 });
const ECDSA_AVEC_HACHAGE = Object.freeze({ [OID.ecdsaSha256]: OID.sha256, [OID.ecdsaSha384]: OID.sha384, [OID.ecdsaSha512]: OID.sha512 });

/** Nom lisible d'un algorithme de signature (rapport). */
export const NOMS_SIGNATURE = Object.freeze({
  [OID.rsaEncryption]: "rsaEncryption",
  [OID.sha256WithRSA]: "sha256WithRSAEncryption",
  [OID.sha384WithRSA]: "sha384WithRSAEncryption",
  [OID.sha512WithRSA]: "sha512WithRSAEncryption",
  [OID.rsassaPss]: "RSASSA-PSS",
  [OID.ecdsaSha256]: "ecdsa-with-SHA256",
  [OID.ecdsaSha384]: "ecdsa-with-SHA384",
  [OID.ecdsaSha512]: "ecdsa-with-SHA512",
  [OID.ed25519]: "Ed25519",
  [OID.ed448]: "Ed448",
  [OID.sha1WithRSA]: "sha1WithRSAEncryption",
});

/** Le `digestAlgorithm` d'un `SignerInfo` est admis (SHA-256, SHA-384, SHA-512 ; paramètres absents ou `NULL`). */
export function hachageAdmis(alg) {
  return HACHAGES_ADMIS.has(alg.oid) && parametresAbsentsOuNuls(alg);
}

/**
 * Lit les paramètres `RSASSA-PSS-params` (RFC 4055 §3.1) : `{ hachage, mgf,
 * mgfHachage, sel, champFin }` avec leurs valeurs par défaut. Lève si la
 * structure ne se lit pas.
 */
export function lireParametresPss(parametres) {
  const r = { hachage: OID.sha1, mgf: OID.mgf1, mgfHachage: OID.sha1, sel: 20, champFin: 1 };
  if (parametres === null) return r;
  attendre(parametres, ETIQUETTE.SEQUENCE, true, "RSASSA-PSS-params");
  for (const champ of enfants(parametres)) {
    const e = enfants(champ);
    if (e.length !== 1) throw new TypeError("RSASSA-PSS-params mal formés");
    if (estContexte(champ, 0, true)) r.hachage = lireAlgorithme(e[0]).oid;
    else if (estContexte(champ, 1, true)) {
      const mgf = lireAlgorithme(e[0]);
      r.mgf = mgf.oid;
      r.mgfHachage = mgf.parametres ? lireAlgorithme(mgf.parametres).oid : OID.sha1;
    } else if (estContexte(champ, 2, true)) {
      const n = lireEntier(e[0]);
      r.sel = n < 0n || n > 65536n ? -1 : Number(n);
    } else if (estContexte(champ, 3, true)) {
      const n = lireEntier(e[0]);
      r.champFin = n < 0n || n > 65536n ? -1 : Number(n);
    } else throw new TypeError("RSASSA-PSS-params : champ inattendu");
  }
  return r;
}

/**
 * Analyse un `AlgorithmIdentifier` de signature. `hachageSignerInfo` est l'OID
 * du `digestAlgorithm` du `SignerInfo` quand on juge la signature du jeton
 * (EX-9.11 : la fonction de l'algorithme doit l'égaler) ; `null` pour la
 * signature d'un certificat ou d'une CRL (règle 3 de T-7, règle 1 de T-10).
 *
 * Rend `{ oid, nom, famille: "rsa-pkcs1"|"rsa-pss"|"ecdsa"|null, hachage: oid|null,
 * typeCle: "rsa"|"ec"|null, admis: boolean, connu: boolean, motif }`.
 * `connu` est faux pour un identifiant hors de la table de CT-6 §9.4.
 */
export function analyserAlgorithmeSignature(alg, hachageSignerInfo = null) {
  const r = { oid: alg.oid, nom: NOMS_SIGNATURE[alg.oid] ?? alg.oid, famille: null, hachage: null, typeCle: null, admis: false, connu: true, motif: null, sel: null };
  const refuser = (motif) => {
    r.motif = motif;
    return r;
  };
  if (alg.oid === OID.rsaEncryption) {
    r.famille = "rsa-pkcs1";
    r.typeCle = "rsa";
    if (!parametresAbsentsOuNuls(alg)) return refuser("rsaEncryption avec des paramètres");
    if (hachageSignerInfo === null) return refuser("rsaEncryption ne nomme pas de fonction de hachage");
    r.hachage = hachageSignerInfo;
    r.admis = HACHAGES_ADMIS.has(hachageSignerInfo);
    if (!r.admis) r.motif = "fonction de hachage refusée";
    return r;
  }
  if (RSA_AVEC_HACHAGE[alg.oid]) {
    r.famille = "rsa-pkcs1";
    r.typeCle = "rsa";
    r.hachage = RSA_AVEC_HACHAGE[alg.oid];
    if (!parametresAbsentsOuNuls(alg)) return refuser("paramètres inattendus");
    if (hachageSignerInfo !== null && hachageSignerInfo !== r.hachage) return refuser("fonction de la signature différente de digestAlgorithm");
    r.admis = true;
    return r;
  }
  if (alg.oid === OID.rsassaPss) {
    r.famille = "rsa-pss";
    r.typeCle = "rsa";
    let p;
    try {
      p = lireParametresPss(alg.parametres);
    } catch {
      return refuser("paramètres RSASSA-PSS illisibles");
    }
    r.hachage = p.hachage;
    r.sel = p.sel;
    if (!HACHAGES_ADMIS.has(p.hachage)) return refuser("RSASSA-PSS : fonction de hachage refusée");
    if (hachageSignerInfo !== null && p.hachage !== hachageSignerInfo) return refuser("RSASSA-PSS : hashAlgorithm différent de digestAlgorithm");
    if (p.mgf !== OID.mgf1 || p.mgfHachage !== p.hachage) return refuser("RSASSA-PSS : maskGenAlgorithm autre que MGF1 avec la même fonction");
    if (p.champFin !== 1) return refuser("RSASSA-PSS : trailerField différent de 1");
    if (p.sel < 0) return refuser("RSASSA-PSS : saltLength hors bornes");
    r.admis = true;
    return r;
  }
  if (ECDSA_AVEC_HACHAGE[alg.oid]) {
    r.famille = "ecdsa";
    r.typeCle = "ec";
    r.hachage = ECDSA_AVEC_HACHAGE[alg.oid];
    if (alg.parametres !== null && !estUniversel(alg.parametres, ETIQUETTE.NULL, false)) return refuser("paramètres inattendus");
    if (hachageSignerInfo !== null && hachageSignerInfo !== r.hachage) return refuser("fonction de la signature différente de digestAlgorithm");
    r.admis = true;
    return r;
  }
  if (alg.oid === OID.sha1WithRSA || alg.oid === "1.2.840.113549.1.1.4" || alg.oid === "1.2.840.10045.4.1") {
    r.famille = alg.oid === "1.2.840.10045.4.1" ? "ecdsa" : "rsa-pkcs1";
    r.typeCle = alg.oid === "1.2.840.10045.4.1" ? "ec" : "rsa";
    return refuser("signature sur SHA-1 ou MD5 refusée");
  }
  r.connu = false;
  return refuser(`algorithme ${alg.oid} hors de la version 0`);
}

/** Signature ECDSA `SEQUENCE { r, s }` lisible par le lecteur borné. */
function signatureEcdsaLisible(signature) {
  try {
    const seq = lireUnique(signature, 1);
    attendre(seq, ETIQUETTE.SEQUENCE, true, "signature ECDSA");
    const e = enfants(seq);
    if (e.length !== 2) return false;
    lireEntier(e[0]);
    lireEntier(e[1]);
    return true;
  } catch {
    return false;
  }
}

/**
 * Vérifie une signature sous une clé publique lue par `lireClePublique`
 * (`cle.admise` doit être vrai : la borne d'EX-9.23 est contrôlée avant tout
 * calcul) avec un algorithme analysé et admis. Rend `true` ou `false`, jamais
 * une exception.
 */
export function verifierSignatureBrute({ cle, algorithme, donnees, signature }) {
  if (!cle || !cle.admise || !algorithme || !algorithme.admis) return false;
  if (algorithme.typeCle !== cle.type) return false;
  const h = HACHAGES[algorithme.hachage];
  if (!h) return false;
  let objetCle;
  try {
    objetCle = createPublicKey({ key: Buffer.from(cle.octets), format: "der", type: "spki" });
  } catch {
    return false;
  }
  try {
    if (algorithme.famille === "rsa-pkcs1") {
      const tailleModule = Math.ceil(cle.bits / 8);
      if (signature.length !== tailleModule) return false;
      return verify(h.noeud, Buffer.from(donnees), { key: objetCle, padding: constants.RSA_PKCS1_PADDING }, Buffer.from(signature));
    }
    if (algorithme.famille === "rsa-pss") {
      const tailleModule = Math.ceil(cle.bits / 8);
      if (signature.length !== tailleModule) return false;
      return verify(h.noeud, Buffer.from(donnees), { key: objetCle, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: algorithme.sel }, Buffer.from(signature));
    }
    if (algorithme.famille === "ecdsa") {
      if (!signatureEcdsaLisible(signature)) return false;
      return verify(h.noeud, Buffer.from(donnees), { key: objetCle, dsaEncoding: "der" }, Buffer.from(signature));
    }
  } catch {
    return false;
  }
  return false;
}

/**
 * Signature d'un certificat ou d'une CRL (`objet.tbs`, `objet.signatureAlgorithme`,
 * `objet.signature`) sous la clé publique d'un émetteur (`emetteur.clePublique`),
 * avec un algorithme admis par T-5 et une clé dans les bornes d'EX-9.23.
 */
export function verifierSignatureEmise(objet, emetteur) {
  const alg = analyserAlgorithmeSignature(objet.signatureAlgorithme, null);
  if (!alg.admis) return false;
  return verifierSignatureBrute({ cle: emetteur.clePublique, algorithme: alg, donnees: objet.tbs, signature: objet.signature });
}

/** Nom de la fonction de hachage d'un OID, ou l'OID. */
export function nomHachage(oid) {
  return HACHAGES[oid]?.nom ?? oid;
}

export { lireOid };
