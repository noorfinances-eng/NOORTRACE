// Autorité du serveur RFC 3161 interne (lot E) : la clé et le certificat de
// l'unité d'horodatage, la politique, la précision, le compteur de série ;
// l'émission de certificats X.509 (RFC 5280 §4.1) et de CRL (§5.1) pour
// `initialiserAutorite`. La clé est fournie en octets PKCS#8 par l'appelant
// (classe D de développement, CT-7 §5 ; une classe A à C se branche par un
// `signataire` injecté). Les contrôles d'AN-22, AN-30 et AN-31 sont faits à
// la construction : un certificat d'unité hors profil est refusé avant
// toute émission.

import crypto from "node:crypto";
import { sequence, ensembleDe, entier, entierDepuisOctets, booleen, nul, chaineOctets, chaineBits, bitsNommes, oid, utf8, imprimable, ia5, temps, explicite, implicite, identifiantAlgorithme, memesOctets } from "./der-ecriture.mjs";
import { lireCertificat, defautsUnite, identifiantCleSujet } from "./certificat.mjs";
import { lireUnique, lireSuite, exiger } from "./der-lecture.mjs";
import { OID } from "./oids.mjs";

export class ErreurAutorite extends Error {
  constructor(message) {
    super(message);
    this.name = "ErreurAutorite";
  }
}

const RSA_BITS_MIN = 3072;
const RSA_BITS_MAX = 8192;

/** Relit une clé privée PKCS#8 (PEM ou DER) en KeyObject. */
export function lireClePrivee(entree) {
  try {
    if (typeof entree === "string") return crypto.createPrivateKey({ key: entree, format: "pem" });
    const b = Buffer.from(entree);
    if (b.length > 10 && b[0] === 0x2d) return crypto.createPrivateKey({ key: b, format: "pem" });
    return crypto.createPrivateKey({ key: b, format: "der", type: "pkcs8" });
  } catch (e) {
    throw new ErreurAutorite(`clé privée illisible (PKCS#8 PEM ou DER attendu) : ${e.message}`);
  }
}

/**
 * Décrit une clé : `{ type: "rsa"|"p-256", bits, signatureAlgorithme (DER),
 * signer(octets) }`. Refuse RSA de moins de 3072 bits, au-delà de 8192 bits
 * ou d'exposant pair, et toute courbe autre que P-256 (AN-31 ; CT-6 EX-9.23).
 */
export function decrireCle(cle) {
  const d = cle.asymmetricKeyDetails ?? {};
  if (cle.asymmetricKeyType === "rsa") {
    if (!(d.modulusLength >= RSA_BITS_MIN)) throw new ErreurAutorite(`clé RSA de ${d.modulusLength} bits : 3072 au moins (AN-31)`);
    if (d.modulusLength > RSA_BITS_MAX) throw new ErreurAutorite(`clé RSA de ${d.modulusLength} bits : 8192 au plus (CT-6 EX-9.23)`);
    if (typeof d.publicExponent === "bigint" && (d.publicExponent % 2n === 0n || d.publicExponent < 3n || d.publicExponent > 2147483647n)) {
      throw new ErreurAutorite("clé RSA : exposant public impair entre 3 et 2^31 − 1 attendu (CT-6 EX-9.23)");
    }
    return {
      type: "rsa",
      bits: d.modulusLength,
      signatureAlgorithme: identifiantAlgorithme(OID.sha256WithRSAEncryption, nul()),
      signer: (octets) => new Uint8Array(crypto.sign("sha256", Buffer.from(octets), { key: cle, padding: crypto.constants.RSA_PKCS1_PADDING })),
    };
  }
  if (cle.asymmetricKeyType === "ec") {
    if (d.namedCurve !== "prime256v1") throw new ErreurAutorite(`courbe ${d.namedCurve} : P-256 seule admise (AN-31)`);
    return {
      type: "p-256",
      bits: 256,
      signatureAlgorithme: identifiantAlgorithme(OID.ecdsaWithSHA256),
      signer: (octets) => new Uint8Array(crypto.sign("sha256", Buffer.from(octets), { key: cle, dsaEncoding: "der" })),
    };
  }
  throw new ErreurAutorite(`type de clé ${cle.asymmetricKeyType} : RSA ou ECDSA P-256 attendu (AN-31)`);
}

/** SubjectPublicKeyInfo DER d'une clé (privée ou publique). */
export function spkiDe(cle) {
  const pub = cle.type === "private" ? crypto.createPublicKey(cle) : cle;
  return new Uint8Array(pub.export({ type: "spki", format: "der" }));
}

/** SHA-256. */
export function sha256(octets) {
  return new Uint8Array(crypto.createHash("sha256").update(Buffer.from(octets)).digest());
}

/**
 * Identifiant de clé (RFC 7093 §2, méthode 1 : les 160 bits de gauche du
 * SHA-256 du `subjectPublicKey`), sans SHA-1.
 */
export function identifiantCle(spki) {
  // Le BIT STRING subjectPublicKey est le second élément du SPKI ; son contenu est haché hors de l'octet de bits inutilisés.
  const parties = lireSuite(exiger(lireUnique(spki), 0x30, "SubjectPublicKeyInfo").contenu, 1);
  if (parties.length !== 2) throw new ErreurAutorite("SubjectPublicKeyInfo : deux éléments attendus");
  const bits = exiger(parties[1], 0x03, "subjectPublicKey").contenu;
  return sha256(bits.subarray(1)).subarray(0, 20);
}

const ATTRIBUTS_NOM = Object.freeze({
  C: { oid: OID.countryName, encoder: imprimable },
  O: { oid: OID.organizationName, encoder: utf8 },
  OU: { oid: OID.organizationalUnitName, encoder: utf8 },
  CN: { oid: OID.commonName, encoder: utf8 },
});

/**
 * `Name` DER d'un sujet donné par ses attributs, dans l'ordre C, O, OU, CN
 * (un RDN par attribut ; `countryName` en PrintableString, les autres en
 * UTF8String).
 * @param {{C?: string, O?: string, OU?: string, CN?: string}} sujet
 */
export function construireNom(sujet) {
  const rdns = [];
  for (const cle of ["C", "O", "OU", "CN"]) {
    const v = sujet[cle];
    if (v === undefined || v === null) continue;
    if (typeof v !== "string" || v.length === 0) throw new ErreurAutorite(`nom : attribut ${cle} vide`);
    const a = ATTRIBUTS_NOM[cle];
    rdns.push(ensembleDe(sequence(oid(a.oid), a.encoder(v))));
  }
  if (rdns.length === 0) throw new ErreurAutorite("nom : au moins un attribut attendu");
  return sequence(...rdns);
}

/** Une `Extension` (RFC 5280 §4.1) : OID, critique ou non (DEFAULT omis), valeur DER enveloppée en OCTET STRING. */
export function extensionX509(oidExt, critique, valeurDer) {
  return critique ? sequence(oid(oidExt), booleen(true), chaineOctets(valeurDer)) : sequence(oid(oidExt), chaineOctets(valeurDer));
}

/**
 * Émet un certificat X.509 v3 signé par `cleEmetteur` (auto-signé si
 * `emetteur` est le nom du sujet).
 * @param {{cleEmetteur: crypto.KeyObject, emetteur: Uint8Array, sujet: Uint8Array, spki: Uint8Array, serie: bigint,
 *   notBefore: number, notAfter: number, extensions: Uint8Array[]}} o
 * @returns {Uint8Array} DER
 */
export function emettreCertificat(o) {
  const cle = decrireCle(o.cleEmetteur);
  if (o.serie <= 0n) throw new ErreurAutorite("numéro de série positif attendu (RFC 5280 §4.1.2.2)");
  if (!(o.notBefore < o.notAfter)) throw new ErreurAutorite("validité : notBefore antérieur à notAfter attendu");
  const tbs = sequence(
    explicite(0, entier(2)), // v3
    entier(o.serie),
    cle.signatureAlgorithme,
    o.emetteur,
    sequence(temps(o.notBefore), temps(o.notAfter)),
    o.sujet,
    o.spki,
    explicite(3, sequence(...o.extensions)),
  );
  return sequence(tbs, cle.signatureAlgorithme, chaineBits(cle.signer(tbs)));
}

/**
 * Émet une CRL v2 complète (RFC 5280 §5.1) : `thisUpdate`, `nextUpdate`,
 * entrées révoquées (absentes si aucune), `authorityKeyIdentifier` et
 * `cRLNumber`.
 * @param {{cleEmetteur: crypto.KeyObject, emetteur: Uint8Array, identifiantCleEmetteur: Uint8Array|null, thisUpdate: number,
 *   nextUpdate: number, numero: bigint, revoques?: {serie: bigint, date: number, raison?: number|null}[]}} o
 */
export function emettreCrl(o) {
  const cle = decrireCle(o.cleEmetteur);
  if (!(o.thisUpdate < o.nextUpdate)) throw new ErreurAutorite("CRL : thisUpdate antérieur à nextUpdate attendu");
  if (o.numero < 0n) throw new ErreurAutorite("CRL : numéro non négatif attendu");
  const entrees = (o.revoques ?? []).map((r) => {
    const parties = [entier(r.serie), temps(r.date)];
    if (r.raison !== undefined && r.raison !== null) {
      // CRLReason ::= ENUMERATED (étiquette 0x0a), un octet.
      parties.push(sequence(extensionX509(OID.cRLReasons, false, Uint8Array.of(0x0a, 0x01, r.raison))));
    }
    return sequence(...parties);
  });
  const extensions = [];
  if (o.identifiantCleEmetteur) extensions.push(extensionX509(OID.authorityKeyIdentifier, false, sequence(implicite(0, chaineOctets(o.identifiantCleEmetteur)))));
  extensions.push(extensionX509(OID.cRLNumber, false, entier(o.numero)));
  const parties = [entier(1), cle.signatureAlgorithme, o.emetteur, temps(o.thisUpdate), temps(o.nextUpdate)];
  if (entrees.length > 0) parties.push(sequence(...entrees));
  parties.push(explicite(0, sequence(...extensions)));
  const tbs = sequence(...parties);
  return sequence(tbs, cle.signatureAlgorithme, chaineBits(cle.signer(tbs)));
}

/** Extensions du certificat d'une AC racine (CA:TRUE critique, keyCertSign et cRLSign, SKI). */
export function extensionsAc(spki) {
  return [
    extensionX509(OID.basicConstraints, true, sequence(booleen(true))),
    extensionX509(OID.keyUsage, true, bitsNommes([5, 6])),
    extensionX509(OID.subjectKeyIdentifier, false, chaineOctets(identifiantCle(spki))),
  ];
}

/**
 * Extensions du certificat d'une unité d'horodatage (AN-22, AN-31) :
 * keyUsage digitalSignature critique, EKU critique `id-kp-timeStamping`
 * seul, basicConstraints sans AC (SEQUENCE vide : `cA` DEFAULT omis), SKI,
 * AKI de l'AC, point de distribution de CRL.
 */
export function extensionsUnite(spki, identifiantCleAc, crlUrl) {
  const ext = [
    extensionX509(OID.basicConstraints, false, sequence()),
    extensionX509(OID.keyUsage, true, bitsNommes([0])),
    extensionX509(OID.extKeyUsage, true, sequence(oid(OID.timeStamping))),
    extensionX509(OID.subjectKeyIdentifier, false, chaineOctets(identifiantCle(spki))),
    extensionX509(OID.authorityKeyIdentifier, false, sequence(implicite(0, chaineOctets(identifiantCleAc)))),
  ];
  if (crlUrl) {
    // DistributionPoint { distributionPoint [0] EXPLICIT DistributionPointName (CHOICE) { fullName [0] IMPLICIT GeneralNames { uniformResourceIdentifier [6] IA5String } } }
    const nomComplet = implicite(0, sequence(implicite(6, ia5(crlUrl))));
    ext.push(extensionX509(OID.cRLDistributionPoints, false, sequence(sequence(explicite(0, nomComplet)))));
  }
  return ext;
}

/**
 * Unité d'horodatage prête à émettre.
 */
export class Autorite {
  /**
   * @param {object} o
   * @param {string|Uint8Array} [o.clePrivee] clé PKCS#8 (PEM ou DER) de l'unité, classe D
   * @param {{type: "rsa"|"p-256", signer: (octets: Uint8Array) => Uint8Array}} [o.signataire] à la place de la clé (classes A à C)
   * @param {string|Uint8Array} o.certificat certificat de l'unité (PEM ou DER)
   * @param {(string|Uint8Array)[]} [o.chaine] certificats supplémentaires portés dans `certificates` (l'AC si l'exploitant le veut)
   * @param {string} o.politique OID de la politique (AN-29)
   * @param {number} [o.precisionS] précision déclarée, 1 par défaut, au plus 1 (AN-24)
   * @param {{suivant: () => bigint, fermer: () => void}} o.compteur compteur de série durable (AN-26)
   * @param {boolean} [o.tsaDansJeton] écrire `tsa` (directoryName du sujet de l'unité) dans TSTInfo ; vrai par défaut
   */
  constructor(o) {
    if (!o || typeof o !== "object") throw new TypeError("Autorite : options attendues");
    if (typeof o.politique !== "string" || !/^[0-9]+(\.[0-9]+)+$/.test(o.politique)) throw new ErreurAutorite("politique : OID attendu (AN-29)");
    oid(o.politique);
    const precisionS = o.precisionS ?? 1;
    if (!Number.isInteger(precisionS) || precisionS < 0 || precisionS > 1) throw new ErreurAutorite("precisionS : entier 0 ou 1 attendu (AN-24 : au plus 1 s)");
    if (!o.compteur || typeof o.compteur.suivant !== "function") throw new ErreurAutorite("compteur : objet à méthode suivant() attendu (AN-26)");

    this.certificat = lireCertificat(o.certificat);
    const defauts = defautsUnite(this.certificat);
    if (defauts.length > 0) throw new ErreurAutorite(`certificat de l'unité refusé : ${defauts.join(" ; ")}`);

    if (o.signataire) {
      if (!["rsa", "p-256"].includes(o.signataire.type) || typeof o.signataire.signer !== "function") throw new ErreurAutorite("signataire : { type, signer } attendu");
      this.cle = { type: o.signataire.type, bits: null, signer: o.signataire.signer, signatureAlgorithme: o.signataire.type === "rsa" ? identifiantAlgorithme(OID.sha256WithRSAEncryption, nul()) : identifiantAlgorithme(OID.ecdsaWithSHA256) };
      const alg = this.certificat.algorithmeCle;
      if ((this.cle.type === "rsa") !== (alg === OID.rsaEncryption)) throw new ErreurAutorite("signataire : type de clé différent de celui du certificat");
    } else {
      if (o.clePrivee === undefined) throw new ErreurAutorite("clePrivee ou signataire attendu");
      const cle = lireClePrivee(o.clePrivee);
      this.cle = decrireCle(cle);
      if (!memesOctets(spkiDe(cle), this.certificat.spki)) throw new ErreurAutorite("la clé privée ne correspond pas à la clé publique du certificat de l'unité");
    }

    this.chaine = (o.chaine ?? []).map((c) => lireCertificat(c));
    this.politique = o.politique;
    this.precisionS = precisionS;
    this.compteur = o.compteur;
    this.tsaDansJeton = o.tsaDansJeton ?? true;
    this.certHash = sha256(this.certificat.der);
  }

  /** `rsa` ou `p-256`. */
  get algorithme() {
    return this.cle.type;
  }

  /** Identifiant de clé du sujet du certificat de l'unité, ou null. */
  get identifiantCleSujet() {
    return identifiantCleSujet(this.certificat);
  }

  /** Vrai si `instantMs` est dans la validité du certificat de l'unité (bornes incluses). */
  dansValidite(instantMs) {
    return instantMs >= this.certificat.notBefore && instantMs <= this.certificat.notAfter;
  }

  /** Numéro de série suivant, durable (AN-26). */
  serieSuivante() {
    return this.compteur.suivant();
  }

  /** Signature (RSA PKCS#1 v1.5 SHA-256 ou ECDSA P-256 SHA-256 en DER). */
  signer(octets) {
    return this.cle.signer(octets);
  }

  fermer() {
    this.compteur.fermer?.();
  }
}

export { entierDepuisOctets };
