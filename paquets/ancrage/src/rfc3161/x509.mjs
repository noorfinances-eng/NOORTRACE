// Lecture stricte des certificats X.509 et des listes de révocation (CRL)
// par le lecteur DER borné (CT-6 §9.3 : EX-9.4, EX-9.21 ; §9.4 identifiants ;
// EX-9.23 bornes des clés RSA). Aucune valeur n'est réencodée : les `Name`
// sont comparés sur leurs octets, les signatures portent sur le TBS tel que
// reçu.

import { createHash } from "node:crypto";
import {
  ErreurDer, ETIQUETTE, enfants, lireUnique, attendre, estContexte, estUniversel, lireBooleen, lireEntier,
  entierOctetsNormalises, lireOid, lireOctets, lireBits, lireChaine, lireTemps, lireAlgorithme, bitLeve, octetsEgaux,
  octetsVersHex, parcourir,
} from "./der.mjs";

/** Identifiants d'objets (CT-6 §9.4 et RFC 5280). */
export const OID = Object.freeze({
  signedData: "1.2.840.113549.1.7.2",
  tstInfo: "1.2.840.113549.1.9.16.1.4",
  contentType: "1.2.840.113549.1.9.3",
  messageDigest: "1.2.840.113549.1.9.4",
  signingCertificate: "1.2.840.113549.1.9.16.2.12",
  signingCertificateV2: "1.2.840.113549.1.9.16.2.47",
  md5: "1.2.840.113549.2.5",
  sha1: "1.3.14.3.2.26",
  sha224: "2.16.840.1.101.3.4.2.4",
  sha256: "2.16.840.1.101.3.4.2.1",
  sha384: "2.16.840.1.101.3.4.2.2",
  sha512: "2.16.840.1.101.3.4.2.3",
  rsaEncryption: "1.2.840.113549.1.1.1",
  sha1WithRSA: "1.2.840.113549.1.1.5",
  sha256WithRSA: "1.2.840.113549.1.1.11",
  sha384WithRSA: "1.2.840.113549.1.1.12",
  sha512WithRSA: "1.2.840.113549.1.1.13",
  rsassaPss: "1.2.840.113549.1.1.10",
  mgf1: "1.2.840.113549.1.1.8",
  ecPublicKey: "1.2.840.10045.2.1",
  ecdsaSha256: "1.2.840.10045.4.3.2",
  ecdsaSha384: "1.2.840.10045.4.3.3",
  ecdsaSha512: "1.2.840.10045.4.3.4",
  p256: "1.2.840.10045.3.1.7",
  p384: "1.3.132.0.34",
  p521: "1.3.132.0.35",
  ed25519: "1.3.101.112",
  ed448: "1.3.101.113",
  timeStamping: "1.3.6.1.5.5.7.3.8",
  qcStatements: "1.3.6.1.5.5.7.1.3",
  qtstStatement: "0.4.0.19422.1.1",
  commonName: "2.5.4.3",
  subjectKeyIdentifier: "2.5.29.14",
  keyUsage: "2.5.29.15",
  basicConstraints: "2.5.29.19",
  cRLNumber: "2.5.29.20",
  cRLReasons: "2.5.29.21",
  deltaCRLIndicator: "2.5.29.27",
  issuingDistributionPoint: "2.5.29.28",
  cRLDistributionPoints: "2.5.29.31",
  extKeyUsage: "2.5.29.37",
  authorityInfoAccess: "1.3.6.1.5.5.7.1.1",
  ocsp: "1.3.6.1.5.5.7.48.1",
});

/** Fonctions de hachage par OID, avec le nom de `node:crypto`. */
export const HACHAGES = Object.freeze({
  [OID.md5]: { nom: "md5", noeud: "md5", octets: 16 },
  [OID.sha1]: { nom: "sha1", noeud: "sha1", octets: 20 },
  [OID.sha224]: { nom: "sha224", noeud: "sha224", octets: 28 },
  [OID.sha256]: { nom: "sha256", noeud: "sha256", octets: 32 },
  [OID.sha384]: { nom: "sha384", noeud: "sha384", octets: 48 },
  [OID.sha512]: { nom: "sha512", noeud: "sha512", octets: 64 },
});

/** Empreinte par une fonction de `HACHAGES`. */
export function hacher(oidHachage, octets) {
  const h = HACHAGES[oidHachage];
  if (!h) throw new TypeError(`fonction de hachage inconnue : ${oidHachage}`);
  return new Uint8Array(createHash(h.noeud).update(octets).digest());
}

/** SHA-256 en hexadécimal préfixé. */
export function sha256Hex(octets) {
  return octetsVersHex(hacher(OID.sha256, octets));
}

/** Types de chaîne admis pour `tsu_subject_cn` (CT-6 EX-9.19). */
const TYPES_CN = new Set(["UTF8String", "PrintableString", "IA5String", "TeletexString", "NumericString", "BMPString"]);

/**
 * Lit un `Name` (SEQUENCE OF SET OF AttributeTypeAndValue) : contrôle les
 * chaînes (EX-9.4) et rend `{ octets (DER complet), attributs: [{oid, type, texte}], cn }`.
 */
export function lireNom(tlv) {
  attendre(tlv, ETIQUETTE.SEQUENCE, true, "Name");
  const attributs = [];
  let cn = null;
  let cnVu = false;
  for (const rdn of enfants(tlv)) {
    attendre(rdn, ETIQUETTE.SET, true, "RelativeDistinguishedName");
    const atvs = enfants(rdn);
    if (atvs.length === 0) throw new ErreurDer("RelativeDistinguishedName vide", rdn.debut);
    for (const atv of atvs) {
      attendre(atv, ETIQUETTE.SEQUENCE, true, "AttributeTypeAndValue");
      const e = enfants(atv);
      if (e.length !== 2) throw new ErreurDer("AttributeTypeAndValue mal formé", atv.debut);
      const oid = lireOid(e[0]);
      // EX-9.4 : une valeur d'un autre type de chaîne n'est pas décodée, mais sa forme DER est contrôlée (lecture bornée ;
      // R-A-2 : un type universel de forme construite, par exemple, rend le nom illisible).
      parcourir(e[1]);
      let type = null;
      let texte = null;
      if (e[1].classe === 0 && !e[1].construit && (e[1].numero === ETIQUETTE.UTF8_STRING || e[1].numero === ETIQUETTE.BMP_STRING || e[1].numero === ETIQUETTE.PRINTABLE_STRING || e[1].numero === ETIQUETTE.IA5_STRING || e[1].numero === ETIQUETTE.TELETEX_STRING || e[1].numero === ETIQUETTE.NUMERIC_STRING || e[1].numero === ETIQUETTE.UNIVERSAL_STRING)) {
        const c = lireChaine(e[1]);
        type = c.type;
        texte = c.texte;
      }
      attributs.push({ oid, type, texte });
      if (oid === OID.commonName && !cnVu) {
        cnVu = true;
        cn = type !== null && TYPES_CN.has(type) ? texte : null;
      }
    }
  }
  return { octets: tlv.tlv, attributs, cn };
}

/**
 * Lit `Extensions ::= SEQUENCE OF Extension` ; un `critical` encodé à `FALSE`
 * est une valeur `DEFAULT` encodée (EX-9.21) : refusée, sauf si `tolererCritiqueFaux`
 * (extensions de `TSTInfo`, EX-9.5), auquel cas l'extension porte `critiqueEncodeFaux`.
 */
export function lireExtensions(tlv, { tolererCritiqueFaux = false } = {}) {
  attendre(tlv, ETIQUETTE.SEQUENCE, true, "Extensions");
  const extensions = [];
  const vus = new Set();
  for (const ext of enfants(tlv)) {
    attendre(ext, ETIQUETTE.SEQUENCE, true, "Extension");
    const e = enfants(ext);
    if (e.length < 2 || e.length > 3) throw new ErreurDer("Extension mal formée", ext.debut);
    const oid = lireOid(e[0]);
    let critique = false;
    let critiqueEncodeFaux = false;
    let iValeur = 1;
    if (e.length === 3) {
      critique = lireBooleen(e[1]);
      if (!critique) {
        if (!tolererCritiqueFaux) throw new ErreurDer("critical encodé à FALSE (valeur DEFAULT encodée, EX-9.21)", e[1].debut);
        critiqueEncodeFaux = true;
      }
      iValeur = 2;
    }
    const valeur = lireOctets(e[iValeur]);
    if (vus.has(oid)) throw new ErreurDer(`extension ${oid} en double`, ext.debut);
    vus.add(oid);
    extensions.push({ oid, critique, critiqueEncodeFaux, valeur, tlv: ext });
  }
  return extensions;
}

/** Longueur en bits d'un entier non négatif. */
export function bitsDe(v) {
  return v <= 0n ? 0 : v.toString(2).length;
}

const BORNE_RSA_MIN = 2048;
const BORNE_RSA_MAX = 8192;
const EXPOSANT_MAX = (1n << 31n) - 1n;

/**
 * Lit un `SubjectPublicKeyInfo` : `{ octets, algorithme, type: "rsa"|"ec"|"autre",
 * bits, exposant, courbe, admise, motif }`. `admise` applique EX-9.23 (RSA de
 * 2048 à 8192 bits, exposant impair de 3 à 2³¹ − 1) et la table d'EX-9.11
 * (ECDSA sur P-256, P-384, P-521) ; elle se contrôle avant tout calcul.
 */
export function lireClePublique(tlv) {
  attendre(tlv, ETIQUETTE.SEQUENCE, true, "SubjectPublicKeyInfo");
  const e = enfants(tlv);
  if (e.length !== 2) throw new ErreurDer("SubjectPublicKeyInfo mal formé", tlv.debut);
  const algorithme = lireAlgorithme(e[0]);
  const bits = lireBits(e[1]);
  if (bits.bitsInutilises !== 0) throw new ErreurDer("clé publique : bits inutilisés", e[1].debut);
  const cle = { octets: tlv.tlv, algorithme, type: "autre", bits: null, exposant: null, courbe: null, admise: false, motif: null };
  if (algorithme.oid === OID.rsaEncryption || algorithme.oid === OID.rsassaPss) {
    cle.type = "rsa";
    const rsa = lireUnique(bits.octets, tlv.profondeur + 3);
    attendre(rsa, ETIQUETTE.SEQUENCE, true, "RSAPublicKey");
    const ne = enfants(rsa);
    if (ne.length !== 2) throw new ErreurDer("RSAPublicKey mal formé", rsa.debut);
    const n = lireEntier(ne[0]);
    const ex = lireEntier(ne[1]);
    if (n <= 0n || ex <= 0n) throw new ErreurDer("RSAPublicKey : module ou exposant non positif", rsa.debut);
    cle.bits = bitsDe(n);
    cle.exposant = ex;
    if (cle.bits < BORNE_RSA_MIN) cle.motif = `clé RSA de ${cle.bits} bits, en deçà de ${BORNE_RSA_MIN}`;
    else if (cle.bits > BORNE_RSA_MAX) cle.motif = `clé RSA de ${cle.bits} bits, au-delà de ${BORNE_RSA_MAX} (EX-9.23)`;
    else if (ex % 2n === 0n || ex < 3n || ex > EXPOSANT_MAX) cle.motif = "exposant public hors de 3 à 2^31 - 1 ou pair (EX-9.23)";
    cle.admise = cle.motif === null;
  } else if (algorithme.oid === OID.ecPublicKey) {
    cle.type = "ec";
    if (algorithme.parametres && estUniversel(algorithme.parametres, ETIQUETTE.OID, false)) {
      cle.courbe = lireOid(algorithme.parametres);
      if (cle.courbe === OID.p256) cle.bits = 256;
      else if (cle.courbe === OID.p384) cle.bits = 384;
      else if (cle.courbe === OID.p521) cle.bits = 521;
    }
    cle.admise = cle.bits !== null;
    if (!cle.admise) cle.motif = `courbe ${cle.courbe ?? "non nommée"} hors de la version 0`;
  } else {
    cle.motif = `type de clé ${algorithme.oid} hors de la version 0`;
    if (algorithme.oid === OID.ed25519) cle.bits = 256;
    if (algorithme.oid === OID.ed448) cle.bits = 448;
  }
  return cle;
}

/**
 * Lit un certificat X.509 v3 en DER. Rend ses champs et ses octets ; lève
 * `ErreurDer` pour toute forme hors du profil de CT-6 §9.3.
 */
export function lireCertificat(octets, profondeurBase = 1) {
  const racine = lireUnique(octets, profondeurBase);
  attendre(racine, ETIQUETTE.SEQUENCE, true, "Certificate");
  const e = enfants(racine);
  if (e.length !== 3) throw new ErreurDer("Certificate mal formé", racine.debut);
  const tbs = e[0];
  attendre(tbs, ETIQUETTE.SEQUENCE, true, "TBSCertificate");
  const signatureAlgorithme = lireAlgorithme(e[1]);
  const signature = lireBits(e[2]);
  if (signature.bitsInutilises !== 0) throw new ErreurDer("signatureValue : bits inutilisés", e[2].debut);
  const t = enfants(tbs);
  let i = 0;
  let version = 1;
  if (t[i] && estContexte(t[i], 0, true)) {
    const v = enfants(t[i]);
    if (v.length !== 1) throw new ErreurDer("version mal formée", t[i].debut);
    const n = lireEntier(v[0]);
    if (n === 0n) throw new ErreurDer("version encodée à v1 (valeur DEFAULT encodée, EX-9.21)", t[i].debut);
    if (n !== 1n && n !== 2n) throw new ErreurDer("version de certificat inconnue", t[i].debut);
    version = Number(n) + 1;
    i++;
  }
  if (t.length < i + 6) throw new ErreurDer("TBSCertificate incomplet", tbs.debut);
  const serieTlv = attendre(t[i++], ETIQUETTE.INTEGER, false, "serialNumber");
  const numeroSerie = entierOctetsNormalises(serieTlv);
  const algorithmeTbs = lireAlgorithme(t[i++]);
  const emetteur = lireNom(t[i++]);
  const validite = attendre(t[i++], ETIQUETTE.SEQUENCE, true, "Validity");
  const dates = enfants(validite);
  if (dates.length !== 2) throw new ErreurDer("Validity mal formée", validite.debut);
  const notBefore = lireTemps(dates[0]);
  const notAfter = lireTemps(dates[1]);
  const sujet = lireNom(t[i++]);
  const clePublique = lireClePublique(t[i++]);
  let extensions = [];
  while (i < t.length) {
    const x = t[i++];
    if (estContexte(x, 1, false) || estContexte(x, 2, false)) continue; // issuerUniqueID, subjectUniqueID
    if (estContexte(x, 3, true)) {
      if (version !== 3) throw new ErreurDer("extensions dans un certificat qui n'est pas v3", x.debut);
      const ex = enfants(x);
      if (ex.length !== 1) throw new ErreurDer("extensions mal formées", x.debut);
      extensions = lireExtensions(ex[0]);
      continue;
    }
    throw new ErreurDer("champ inattendu dans TBSCertificate", x.debut);
  }
  if (!octetsEgaux(algorithmeTbs.tlv.tlv, signatureAlgorithme.tlv.tlv)) {
    throw new ErreurDer("signature du TBS et signatureAlgorithm différents", e[1].debut);
  }
  const cert = {
    octets,
    tbs: tbs.tlv,
    version,
    numeroSerie,
    numeroSerieHex: octetsVersHex(numeroSerie),
    signatureAlgorithme,
    signature: signature.octets,
    emetteur,
    sujet,
    notBefore,
    notAfter,
    clePublique,
    extensions,
    sha256: sha256Hex(octets),
  };
  cert.contraintesBase = lireContraintesBase(cert);
  cert.usagesCle = lireUsagesCle(cert);
  cert.usagesEtendus = lireUsagesEtendus(cert);
  cert.identifiantCle = lireIdentifiantCle(cert);
  return cert;
}

/** Extension d'un certificat ou d'une CRL par OID, ou `null`. */
export function extension(objet, oid) {
  return objet.extensions.find((x) => x.oid === oid) ?? null;
}

/** `basicConstraints` : `{ critique, ca, cheminMax }` ou `null` ; `cA` encodé à `FALSE` refusé (EX-9.21). */
function lireContraintesBase(cert) {
  const x = extension(cert, OID.basicConstraints);
  if (!x) return null;
  const seq = lireUnique(x.valeur, x.tlv.profondeur + 2);
  attendre(seq, ETIQUETTE.SEQUENCE, true, "BasicConstraints");
  const e = enfants(seq);
  let ca = false;
  let cheminMax = null;
  let i = 0;
  if (e[i] && estUniversel(e[i], ETIQUETTE.BOOLEAN, false)) {
    ca = lireBooleen(e[i]);
    if (!ca) throw new ErreurDer("cA encodé à FALSE (valeur DEFAULT encodée, EX-9.21)", e[i].debut);
    i++;
  }
  if (e[i] && estUniversel(e[i], ETIQUETTE.INTEGER, false)) {
    const n = lireEntier(e[i]);
    if (n < 0n) throw new ErreurDer("pathLenConstraint négatif", e[i].debut);
    cheminMax = n > 1024n ? 1024 : Number(n);
    i++;
  }
  if (i !== e.length) throw new ErreurDer("BasicConstraints mal formé", seq.debut);
  return { critique: x.critique, ca, cheminMax };
}

/** `keyUsage` : `{ critique, bits }` ou `null`. */
function lireUsagesCle(cert) {
  const x = extension(cert, OID.keyUsage);
  if (!x) return null;
  const b = lireUnique(x.valeur, x.tlv.profondeur + 2);
  const bits = lireBits(b);
  return { critique: x.critique, bits, a: (i) => bitLeve(bits, i) };
}

/** `extKeyUsage` : `{ critique, oids }` ou `null`. */
function lireUsagesEtendus(cert) {
  const x = extension(cert, OID.extKeyUsage);
  if (!x) return null;
  const seq = lireUnique(x.valeur, x.tlv.profondeur + 2);
  attendre(seq, ETIQUETTE.SEQUENCE, true, "ExtKeyUsageSyntax");
  const oids = enfants(seq).map((o) => lireOid(o));
  if (oids.length === 0) throw new ErreurDer("extKeyUsage vide", seq.debut);
  return { critique: x.critique, oids };
}

/** `subjectKeyIdentifier` : octets, ou `null`. */
function lireIdentifiantCle(cert) {
  const x = extension(cert, OID.subjectKeyIdentifier);
  if (!x) return null;
  const o = lireUnique(x.valeur, x.tlv.profondeur + 2);
  return lireOctets(o);
}

/** URI `http(s)` des points de distribution de CRL d'un certificat (RFC 5280 §4.2.1.13). */
export function pointsDistributionCrl(cert) {
  const x = extension(cert, OID.cRLDistributionPoints);
  if (!x) return [];
  const uris = [];
  try {
    const seq = lireUnique(x.valeur, x.tlv.profondeur + 2);
    for (const dp of enfants(seq)) {
      for (const champ of enfants(dp)) {
        if (!estContexte(champ, 0, true)) continue; // distributionPoint
        for (const nom of enfants(champ)) {
          if (!estContexte(nom, 0, true)) continue; // fullName : GeneralNames
          for (const gn of enfants(nom)) {
            if (estContexte(gn, 6, false)) {
              let s = "";
              for (const o of gn.contenu) s += String.fromCharCode(o);
              if (/^https?:\/\//i.test(s)) uris.push(s);
            }
          }
        }
      }
    }
  } catch {
    return uris;
  }
  return uris;
}

/** URI OCSP de l'`authorityInfoAccess` d'un certificat. */
export function urisOcsp(cert) {
  const x = extension(cert, OID.authorityInfoAccess);
  if (!x) return [];
  const uris = [];
  try {
    const seq = lireUnique(x.valeur, x.tlv.profondeur + 2);
    for (const ad of enfants(seq)) {
      const e = enfants(ad);
      if (e.length !== 2 || lireOid(e[0]) !== OID.ocsp || !estContexte(e[1], 6, false)) continue;
      let s = "";
      for (const o of e[1].contenu) s += String.fromCharCode(o);
      uris.push(s);
    }
  } catch {
    return uris;
  }
  return uris;
}

/** Le certificat porte le `qcStatement` `esi4-qtstStatement-1` (prétention, jamais une preuve). */
export function porteQtstStatement(objetAvecExtensions) {
  const x = extension(objetAvecExtensions, OID.qcStatements);
  if (!x) return false;
  try {
    const seq = lireUnique(x.valeur, x.tlv.profondeur + 2);
    attendre(seq, ETIQUETTE.SEQUENCE, true, "QCStatements");
    for (const st of enfants(seq)) {
      attendre(st, ETIQUETTE.SEQUENCE, true, "QCStatement");
      const e = enfants(st);
      if (e.length < 1 || e.length > 2) throw new ErreurDer("QCStatement mal formé", st.debut);
      if (lireOid(e[0]) === OID.qtstStatement) return true;
    }
  } catch {
    return false;
  }
  return false;
}

/** `qcStatements` bien formée (`SEQUENCE OF QCStatement`), ou absente. Lève sinon. */
export function controlerQcStatements(objetAvecExtensions) {
  const x = extension(objetAvecExtensions, OID.qcStatements);
  if (!x) return;
  const seq = lireUnique(x.valeur, x.tlv.profondeur + 2);
  attendre(seq, ETIQUETTE.SEQUENCE, true, "QCStatements");
  for (const st of enfants(seq)) {
    attendre(st, ETIQUETTE.SEQUENCE, true, "QCStatement");
    const e = enfants(st);
    if (e.length < 1 || e.length > 2) throw new ErreurDer("QCStatement mal formé", st.debut);
    lireOid(e[0]);
  }
}

/**
 * Lit une CRL (`CertificateList`, RFC 5280 §5) : `{ octets, tbs, version,
 * signatureAlgorithme, signature, emetteur, thisUpdate, nextUpdate, revoques:
 * [{ numeroSerie, date, raison }], extensions, complete, sha256 }`.
 */
export function lireCrlDer(octets, profondeurBase = 1) {
  const racine = lireUnique(octets, profondeurBase);
  attendre(racine, ETIQUETTE.SEQUENCE, true, "CertificateList");
  const e = enfants(racine);
  if (e.length !== 3) throw new ErreurDer("CertificateList mal formée", racine.debut);
  const tbs = attendre(e[0], ETIQUETTE.SEQUENCE, true, "TBSCertList");
  const signatureAlgorithme = lireAlgorithme(e[1]);
  const signature = lireBits(e[2]);
  if (signature.bitsInutilises !== 0) throw new ErreurDer("signatureValue : bits inutilisés", e[2].debut);
  const t = enfants(tbs);
  let i = 0;
  let version = 1;
  if (t[i] && estUniversel(t[i], ETIQUETTE.INTEGER, false)) {
    const n = lireEntier(t[i]);
    if (n !== 1n) throw new ErreurDer("version de CRL inconnue", t[i].debut);
    version = 2;
    i++;
  }
  if (t.length < i + 3) throw new ErreurDer("TBSCertList incomplet", tbs.debut);
  const algorithmeTbs = lireAlgorithme(t[i++]);
  const emetteur = lireNom(t[i++]);
  const thisUpdate = lireTemps(t[i++]);
  let nextUpdate = null;
  if (t[i] && (estUniversel(t[i], ETIQUETTE.UTC_TIME, false) || estUniversel(t[i], ETIQUETTE.GENERALIZED_TIME, false))) {
    nextUpdate = lireTemps(t[i++]);
  }
  const revoques = [];
  if (t[i] && estUniversel(t[i], ETIQUETTE.SEQUENCE, true)) {
    for (const r of enfants(t[i])) {
      attendre(r, ETIQUETTE.SEQUENCE, true, "entrée de CRL");
      const re = enfants(r);
      if (re.length < 2 || re.length > 3) throw new ErreurDer("entrée de CRL mal formée", r.debut);
      const numeroSerie = entierOctetsNormalises(re[0]);
      const date = lireTemps(re[1]);
      let raison = null;
      if (re[2]) {
        const exts = lireExtensions(re[2]);
        const rc = exts.find((x) => x.oid === OID.cRLReasons);
        if (rc) {
          const en = lireUnique(rc.valeur, rc.tlv.profondeur + 2);
          const v = lireEntier(en, { numero: ETIQUETTE.ENUMERATED });
          raison = v < 0n || v > 1024n ? 1024 : Number(v);
        }
      }
      revoques.push({ numeroSerie, numeroSerieHex: octetsVersHex(numeroSerie), date, raison });
    }
    i++;
  }
  let extensions = [];
  if (t[i] && estContexte(t[i], 0, true)) {
    const ex = enfants(t[i]);
    if (ex.length !== 1) throw new ErreurDer("crlExtensions mal formées", t[i].debut);
    extensions = lireExtensions(ex[0]);
    i++;
  }
  if (i !== t.length) throw new ErreurDer("champ inattendu dans TBSCertList", tbs.debut);
  if (!octetsEgaux(algorithmeTbs.tlv.tlv, signatureAlgorithme.tlv.tlv)) {
    throw new ErreurDer("signature du TBS et signatureAlgorithm différents", e[1].debut);
  }
  const idp = extensions.find((x) => x.oid === OID.issuingDistributionPoint);
  const complete = !extensions.some((x) => x.oid === OID.deltaCRLIndicator) && !(idp && idp.critique);
  return {
    octets,
    tbs: tbs.tlv,
    version,
    signatureAlgorithme,
    signature: signature.octets,
    emetteur,
    thisUpdate,
    nextUpdate,
    revoques,
    extensions,
    complete,
    sha256: sha256Hex(octets),
  };
}

/** Entrée de révocation d'une CRL pour un certificat (même numéro de série), ou `null`. */
export function entreeRevocation(crl, cert) {
  return crl.revoques.find((r) => octetsEgaux(r.numeroSerie, cert.numeroSerie)) ?? null;
}

const ALPHABET_B64 = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * Décode un bloc PEM d'une étiquette donnée (`CERTIFICATE`, `X509 CRL`) :
 * exactement un bloc, base64 canonique (remplissage exact, bits de bourrage
 * nuls). Lève `ErreurDer` sinon.
 */
export function decoderPem(texte, etiquette) {
  if (typeof texte !== "string") throw new ErreurDer("PEM : texte attendu");
  const re = new RegExp(`^-----BEGIN ${etiquette}-----\\r?\\n([A-Za-z0-9+/=\\r\\n]+?)-----END ${etiquette}-----\\r?\\n?$`);
  const m = re.exec(texte);
  if (!m) throw new ErreurDer(`PEM : un seul bloc ${etiquette} attendu`);
  const b64 = m[1].replace(/[\r\n]/g, "");
  if (b64.length === 0 || b64.length % 4 !== 0 || !ALPHABET_B64.test(b64)) throw new ErreurDer("PEM : base64 mal formé");
  const octets = new Uint8Array(Buffer.from(b64, "base64"));
  if (Buffer.from(octets).toString("base64") !== b64) throw new ErreurDer("PEM : base64 non canonique");
  return octets;
}

/** Lit un certificat PEM (un seul) avec le lecteur borné. */
export function lireCertificatPem(pem) {
  return lireCertificat(decoderPem(pem, "CERTIFICATE"));
}

/** Lit une CRL en PEM ou en DER (octets) avec le lecteur borné. */
export function lireCrl(source) {
  if (typeof source === "string") return lireCrlDer(decoderPem(source, "X509 CRL"));
  if (source instanceof Uint8Array) {
    if (source.length > 0 && source[0] === 0x2d) return lireCrlDer(decoderPem(Buffer.from(source).toString("latin1"), "X509 CRL"));
    return lireCrlDer(source);
  }
  throw new ErreurDer("CRL : PEM ou DER attendu");
}

/** Certificat en PEM (lignes de 64 caractères, saut de ligne final). */
export function certificatVersPem(octets) {
  const b64 = Buffer.from(octets).toString("base64");
  const lignes = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lignes.join("\n")}\n-----END CERTIFICATE-----\n`;
}

/** CRL en PEM. */
export function crlVersPem(octets) {
  const b64 = Buffer.from(octets).toString("base64");
  const lignes = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN X509 CRL-----\n${lignes.join("\n")}\n-----END X509 CRL-----\n`;
}
