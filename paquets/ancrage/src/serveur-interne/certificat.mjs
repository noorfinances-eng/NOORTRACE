// Relecture bornée d'un certificat X.509 (RFC 5280 §4.1) par le serveur
// interne : numéro de série, émetteur et sujet (octets tels quels, recopiés
// dans `issuerAndSerialNumber`, `issuerSerial` et le champ `tsa` du jeton),
// validité, `SubjectPublicKeyInfo`, extensions. Les extensions sont lues
// pour les contrôles d'AN-22 et d'AN-31 (EKU critique réduit à
// `id-kp-timeStamping`, pas d'AC, validité d'au plus trois ans).

import { ErreurDer, lireUnique, lireSuite, exiger, contenuEntier, valeurBooleen, valeurOid, valeurTemps, lireIdentifiantAlgorithme } from "./der-lecture.mjs";
import { OID } from "./oids.mjs";
import { depuisPem } from "./der-ecriture.mjs";

/**
 * @typedef {object} CertificatLu
 * @property {Uint8Array} der certificat complet
 * @property {Uint8Array} tbs `TBSCertificate` complet
 * @property {Uint8Array} serie INTEGER complet du numéro de série (étiquette et longueur comprises)
 * @property {Uint8Array} emetteur `Name` émetteur, octets complets
 * @property {Uint8Array} sujet `Name` sujet, octets complets
 * @property {number} notBefore ms UTC
 * @property {number} notAfter ms UTC
 * @property {Uint8Array} spki `SubjectPublicKeyInfo` complet
 * @property {string} algorithmeCle OID de l'algorithme de la clé publique
 * @property {string} algorithmeSignature OID de l'algorithme de signature du certificat
 * @property {{oid: string, critique: boolean, valeur: Uint8Array}[]} extensions
 */

/**
 * Relit un certificat DER ou PEM.
 * @param {Uint8Array|string} entree
 * @returns {CertificatLu}
 */
export function lireCertificat(entree) {
  const der = typeof entree === "string" || (entree.length > 10 && entree[0] === 0x2d) ? depuisPem(entree, "CERTIFICATE") : entree;
  const racine = exiger(lireUnique(der), 0x30, "Certificate");
  const parties = lireSuite(racine.contenu, 1);
  if (parties.length !== 3) throw new ErreurDer("Certificate : trois éléments attendus");
  const tbs = exiger(parties[0], 0x30, "TBSCertificate");
  const algorithmeSignature = lireIdentifiantAlgorithme(parties[1], "signatureAlgorithm").algorithme;
  exiger(parties[2], 0x03, "signatureValue");

  const champs = lireSuite(tbs.contenu, 2);
  let i = 0;
  if (champs[i]?.etiquette === 0xa0) {
    const v = lireSuite(champs[i].contenu, 3);
    if (v.length !== 1) throw new ErreurDer("version : un INTEGER attendu");
    const version = contenuEntier(v[0], "version");
    if (version.length === 1 && version[0] === 0) throw new ErreurDer("version v1 encodée explicitement (valeur DEFAULT, EX-9.21)");
    i++;
  }
  contenuEntier(champs[i], "serialNumber");
  const serie = champs[i++].complet;
  lireIdentifiantAlgorithme(champs[i++], "signature");
  const emetteur = exiger(champs[i++], 0x30, "issuer").complet;
  const validite = exiger(champs[i++], 0x30, "validity");
  const dates = lireSuite(validite.contenu, 3);
  if (dates.length !== 2) throw new ErreurDer("validity : deux instants attendus");
  const notBefore = valeurTemps(dates[0], "notBefore");
  const notAfter = valeurTemps(dates[1], "notAfter");
  const sujet = exiger(champs[i++], 0x30, "subject").complet;
  const spki = exiger(champs[i++], 0x30, "subjectPublicKeyInfo");
  const spkiParties = lireSuite(spki.contenu, 3);
  if (spkiParties.length !== 2) throw new ErreurDer("subjectPublicKeyInfo : deux éléments attendus");
  const algorithmeCle = lireIdentifiantAlgorithme(spkiParties[0], "subjectPublicKeyInfo.algorithm").algorithme;
  exiger(spkiParties[1], 0x03, "subjectPublicKey");

  const extensions = [];
  while (i < champs.length) {
    const e = champs[i++];
    if (e.etiquette === 0x81 || e.etiquette === 0x82) continue; // issuerUniqueID, subjectUniqueID
    if (e.etiquette !== 0xa3) throw new ErreurDer(`TBSCertificate : élément inattendu 0x${e.etiquette.toString(16)}`);
    const liste = lireSuite(e.contenu, 3);
    if (liste.length !== 1) throw new ErreurDer("extensions : une SEQUENCE attendue");
    for (const ext of lireSuite(exiger(liste[0], 0x30, "Extensions").contenu, 4)) {
      const p = lireSuite(exiger(ext, 0x30, "Extension").contenu, 5);
      if (p.length < 2 || p.length > 3) throw new ErreurDer("Extension : deux ou trois éléments attendus");
      const oidExt = valeurOid(p[0], "extnID");
      let critique = false;
      let k = 1;
      if (p[k].etiquette === 0x01) {
        critique = valeurBooleen(p[k++], "critical");
        if (!critique) throw new ErreurDer(`extension ${oidExt} : critical FALSE encodé (valeur DEFAULT, EX-9.21)`);
      }
      const valeur = exiger(p[k], 0x04, "extnValue").contenu;
      if (k !== p.length - 1) throw new ErreurDer("Extension : élément en trop");
      extensions.push({ oid: oidExt, critique, valeur });
    }
  }
  return { der, tbs: tbs.complet, serie, emetteur, sujet, notBefore, notAfter, spki: spki.complet, algorithmeCle, algorithmeSignature, extensions };
}

/** Extension d'un OID donné, ou null. */
export function extension(certificat, oidExt) {
  return certificat.extensions.find((e) => e.oid === oidExt) ?? null;
}

/** Vrai si `basicConstraints` déclare une AC. */
export function estAutoriteDeCertification(certificat) {
  const bc = extension(certificat, OID.basicConstraints);
  if (!bc) return false;
  const parties = lireSuite(exiger(lireUnique(bc.valeur), 0x30, "BasicConstraints").contenu, 1);
  return parties.length > 0 && parties[0].etiquette === 0x01 && valeurBooleen(parties[0], "cA");
}

/** Liste des OID de `extKeyUsage` et sa criticité, ou null si l'extension est absente. */
export function usagesEtendus(certificat) {
  const eku = extension(certificat, OID.extKeyUsage);
  if (!eku) return null;
  const liste = lireSuite(exiger(lireUnique(eku.valeur), 0x30, "ExtKeyUsageSyntax").contenu, 1).map((e) => valeurOid(e, "KeyPurposeId"));
  return { critique: eku.critique, usages: liste };
}

/** Valeur de `subjectKeyIdentifier` (octets de l'OCTET STRING interne), ou null. */
export function identifiantCleSujet(certificat) {
  const ski = extension(certificat, OID.subjectKeyIdentifier);
  if (!ski) return null;
  return exiger(lireUnique(ski.valeur), 0x04, "SubjectKeyIdentifier").contenu;
}

/**
 * Contrôles d'un certificat d'unité d'horodatage (AN-22, AN-31 ; CT-6 T-8) :
 * EKU critique réduit à `id-kp-timeStamping`, pas d'AC, validité d'au plus
 * trois ans. Rend la liste des défauts (vide si conforme).
 * @param {CertificatLu} certificat
 * @returns {string[]}
 */
export function defautsUnite(certificat) {
  const defauts = [];
  const eku = usagesEtendus(certificat);
  if (!eku) defauts.push("extKeyUsage absent (AN-22)");
  else {
    if (!eku.critique) defauts.push("extKeyUsage non critique (AN-22)");
    if (eku.usages.length !== 1 || eku.usages[0] !== OID.timeStamping) defauts.push("extKeyUsage autre que id-kp-timeStamping seul (AN-22)");
  }
  if (estAutoriteDeCertification(certificat)) defauts.push("certificat d'AC (AN-22)");
  const jours = (certificat.notAfter - certificat.notBefore) / 86400000;
  if (jours > JOURS_MAX_UNITE) defauts.push(`validité de ${Math.ceil(jours)} jours, au-delà de trois ans (AN-31)`);
  return defauts;
}

/** Trois ans, bissextile comprise (AN-31). */
export const JOURS_MAX_UNITE = 1096;
