// Lecture d'une `TimeStampResp` (RFC 3161 §2.4.2 ; CT-5 EX-5.10 étape 2,
// AN-8) et d'un `TimeStampToken` (CT-6 EX-9.7, T-1 : structure) par le
// lecteur DER borné. Rien n'est réencodé : le jeton rendu est la tranche
// d'octets de la réponse, telle que reçue.

import {
  ErreurDer, ETIQUETTE, lireUnique, enfants, attendre, attendreContexte, estUniversel, estContexte, lireEntier,
  entierOctetsNormalises, lireOid, lireOctets, lireBits, lireBooleen, lireAlgorithme, lireGeneralizedTime, lireChaine,
  bitLeve, octetsVersHex, parcourir,
} from "./der.mjs";
import { OID, lireCertificat, lireCrlDer, lireNom, lireExtensions, controlerQcStatements, porteQtstStatement } from "./x509.mjs";

/** Taille maximale d'un jeton (CT-6 EX-9.3 : 64 Kio). */
export const TAILLE_MAX_JETON = 65536;
/** Nombre maximal de certificats dans un jeton (CT-6 EX-9.7, §15.1). */
export const CERTIFICATS_MAX = 16;

/** Noms des bits de `PKIFailureInfo` (RFC 3161 §2.4.2). */
export const FAILURE_INFO = Object.freeze({ 0: "badAlg", 2: "badRequest", 5: "badDataFormat", 14: "timeNotAvailable", 15: "unacceptedPolicy", 16: "unacceptedExtension", 17: "addInfoNotAvailable", 25: "systemFailure" });

/** Réponse illisible (EX-5.10 étape 2 : `reponse_illisible`). */
export class ErreurReponse extends Error {
  constructor(message) {
    super(message);
    this.name = "ErreurReponse";
    this.code = "reponse_illisible";
  }
}

/**
 * Lit une `TimeStampResp` : `{ status, statusString, failureInfo, failureInfoBits,
 * token (octets du TimeStampToken, tels que reçus) }`. `status` 0 ou 1 exige un
 * jeton ; 2 à 5 n'en portent pas ; toute autre valeur, ou toute forme hors du
 * lecteur borné, lève `ErreurReponse`. Le jeton n'est pas analysé ici
 * (`lireJeton`, T-1).
 */
export function lireReponse(octets) {
  try {
    const seq = lireUnique(octets, 1);
    attendre(seq, ETIQUETTE.SEQUENCE, true, "TimeStampResp");
    const e = enfants(seq);
    if (e.length < 1 || e.length > 2) throw new ErreurDer("TimeStampResp mal formée", seq.debut);
    const psi = attendre(e[0], ETIQUETTE.SEQUENCE, true, "PKIStatusInfo");
    const p = enfants(psi);
    if (p.length < 1 || p.length > 3) throw new ErreurDer("PKIStatusInfo mal formé", psi.debut);
    const statusBig = lireEntier(p[0]);
    if (statusBig < 0n || statusBig > 5n) throw new ErreurDer(`PKIStatus ${statusBig} hors de 0 à 5`, p[0].debut);
    const status = Number(statusBig);
    let statusString = null;
    let failureInfo = null;
    let failureInfoBits = null;
    let i = 1;
    if (p[i] && estUniversel(p[i], ETIQUETTE.SEQUENCE, true)) {
      statusString = enfants(p[i]).map((s) => {
        attendre(s, ETIQUETTE.UTF8_STRING, false, "PKIFreeText");
        return lireChaine(s).texte;
      });
      i++;
    }
    if (p[i] && estUniversel(p[i], ETIQUETTE.BIT_STRING, false)) {
      const bits = lireBits(p[i]);
      const leves = [];
      for (let b = 0; b < bits.octets.length * 8 - bits.bitsInutilises; b++) if (bitLeve(bits, b)) leves.push(b);
      failureInfoBits = leves;
      if (leves.length === 1 && FAILURE_INFO[leves[0]]) failureInfo = FAILURE_INFO[leves[0]];
      else if (leves.length >= 1) failureInfo = "autre";
      i++;
    }
    if (i !== p.length) throw new ErreurDer("PKIStatusInfo : champ inattendu", psi.debut);
    let token = null;
    if (e[1]) {
      attendre(e[1], ETIQUETTE.SEQUENCE, true, "TimeStampToken");
      token = e[1].tlv;
    }
    if ((status === 0 || status === 1) && token === null) throw new ErreurDer("statut granted sans TimeStampToken", seq.debut);
    if (status >= 2 && token !== null) throw new ErreurDer("statut de rejet avec un TimeStampToken", seq.debut);
    return { status, statusString, failureInfo, failureInfoBits, token };
  } catch (err) {
    if (err instanceof ErreurDer) throw new ErreurReponse(`TimeStampResp illisible : ${err.message}`);
    throw err;
  }
}

/**
 * Lit `Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY }` ; chaque
 * valeur (`ANY`) est parcourue en entier par le lecteur borné (R-A-2 : une
 * structure malformée dans `signedAttrs` met T-1 en échec, CT-6 EX-9.7), sans
 * être interprétée ici.
 */
function lireAttributs(tlv) {
  const attributs = [];
  for (const a of enfants(tlv)) {
    attendre(a, ETIQUETTE.SEQUENCE, true, "Attribute");
    const e = enfants(a);
    if (e.length !== 2) throw new ErreurDer("Attribute mal formé", a.debut);
    const oid = lireOid(e[0]);
    attendre(e[1], ETIQUETTE.SET, true, "attrValues");
    const valeurs = enfants(e[1]);
    if (valeurs.length === 0) throw new ErreurDer("attrValues vide", e[1].debut);
    for (const v of valeurs) parcourir(v);
    attributs.push({ oid, valeurs, tlv: a });
  }
  return attributs;
}

/** Lit un `GeneralName` : `{ type, nom (Name lu, pour directoryName), tlv }`. */
function lireGeneralName(tlv) {
  if (tlv.classe !== 2) throw new ErreurDer("GeneralName attendu", tlv.debut);
  if (tlv.numero === 4) {
    const e = enfants(tlv);
    if (e.length !== 1) throw new ErreurDer("directoryName mal formé", tlv.debut);
    return { type: "directoryName", nom: lireNom(e[0]), tlv };
  }
  const types = { 0: "otherName", 1: "rfc822Name", 2: "dNSName", 3: "x400Address", 5: "ediPartyName", 6: "uniformResourceIdentifier", 7: "iPAddress", 8: "registeredID" };
  if (!types[tlv.numero]) throw new ErreurDer("GeneralName d'étiquette inconnue", tlv.debut);
  return { type: types[tlv.numero], nom: null, tlv };
}

/** Lit un entier d'`accuracy` sans limite de taille (T-1) ; rendu en `bigint`, borné par T-9. */
function lireEntierAccuracy(tlv) {
  return lireEntier(tlv);
}

/**
 * Lit `TSTInfo` (RFC 3161 §2.4.2) depuis les octets de valeur d'`eContent`.
 * Structure seulement (T-1) : `version` 1, `ordering` encodé à `FALSE` refusé
 * (EX-9.21), `critical` à `FALSE` dans une extension toléré avec AV-T-1
 * (EX-9.5). Les valeurs (genTime, accuracy, tsa, extensions critiques) sont
 * jugées par T-9.
 */
export function lireTstInfo(octets, profondeurBase = 1) {
  const avertissements = [];
  const seq = lireUnique(octets, profondeurBase);
  attendre(seq, ETIQUETTE.SEQUENCE, true, "TSTInfo");
  const e = enfants(seq);
  let i = 0;
  if (e.length < 5) throw new ErreurDer("TSTInfo incomplet", seq.debut);
  const version = lireEntier(e[i++]);
  if (version !== 1n) throw new ErreurDer("TSTInfo.version différente de 1", seq.debut);
  const policy = lireOid(e[i++]);
  const mi = attendre(e[i++], ETIQUETTE.SEQUENCE, true, "MessageImprint");
  const mie = enfants(mi);
  if (mie.length !== 2) throw new ErreurDer("MessageImprint mal formé", mi.debut);
  const hashAlgorithme = lireAlgorithme(mie[0]);
  const hashedMessage = lireOctets(mie[1]);
  const serialTlv = attendre(e[i++], ETIQUETTE.INTEGER, false, "serialNumber");
  const serialNumber = lireEntier(serialTlv);
  const genTimeTlv = attendre(e[i++], ETIQUETTE.GENERALIZED_TIME, false, "genTime");
  const genTime = lireGeneralizedTime(genTimeTlv);
  let accuracy = null;
  if (e[i] && estUniversel(e[i], ETIQUETTE.SEQUENCE, true)) {
    const a = enfants(e[i]);
    accuracy = { seconds: null, millis: null, micros: null };
    let j = 0;
    if (a[j] && estUniversel(a[j], ETIQUETTE.INTEGER, false)) accuracy.seconds = lireEntierAccuracy(a[j++]);
    if (a[j] && estContexte(a[j], 0, false)) accuracy.millis = lireEntier({ ...a[j], classe: 0, numero: ETIQUETTE.INTEGER }), j++;
    if (a[j] && estContexte(a[j], 1, false)) accuracy.micros = lireEntier({ ...a[j], classe: 0, numero: ETIQUETTE.INTEGER }), j++;
    if (j !== a.length) throw new ErreurDer("Accuracy mal formée", e[i].debut);
    i++;
  }
  let ordering = false;
  if (e[i] && estUniversel(e[i], ETIQUETTE.BOOLEAN, false)) {
    ordering = lireBooleen(e[i]);
    if (!ordering) throw new ErreurDer("ordering encodé à FALSE (valeur DEFAULT encodée, EX-9.21)", e[i].debut);
    i++;
  }
  let nonce = null;
  if (e[i] && estUniversel(e[i], ETIQUETTE.INTEGER, false)) {
    nonce = lireEntier(e[i++]);
  }
  let tsa = null;
  if (e[i] && estContexte(e[i], 0, true)) {
    const g = enfants(e[i]);
    if (g.length !== 1) throw new ErreurDer("tsa mal formé", e[i].debut);
    tsa = lireGeneralName(g[0]);
    i++;
  }
  let extensions = [];
  if (e[i] && estContexte(e[i], 1, true)) {
    extensions = lireExtensions({ ...e[i], classe: 0, numero: ETIQUETTE.SEQUENCE }, { tolererCritiqueFaux: true });
    if (extensions.some((x) => x.critiqueEncodeFaux)) avertissements.push("AV-T-1");
    i++;
  }
  if (i !== e.length) throw new ErreurDer("TSTInfo : champ inattendu", seq.debut);
  return {
    octets,
    version: 1,
    policy,
    hashAlgorithme,
    hashedMessage,
    serialNumber,
    serialNumberHex: octetsVersHex(entierOctetsNormalises(serialTlv)),
    serialNumberOctets: serialTlv.contenu,
    genTime,
    accuracy,
    ordering,
    nonce,
    tsa,
    extensions,
    avertissements,
  };
}

/**
 * Lit un `TimeStampToken` selon EX-9.7 : `ContentInfo` de `signedData`,
 * `SignedData` version 3, `eContentType` `id-ct-TSTInfo`, au plus 16
 * certificats X.509 lus strictement, exactement un `SignerInfo` avec
 * `signedAttrs`, `TSTInfo` complet dans `eContent`. Lève `ErreurDer` pour
 * toute défaillance (T-1 en échec).
 */
export function lireJeton(octets) {
  if (!(octets instanceof Uint8Array)) throw new ErreurDer("octets attendus");
  if (octets.length > TAILLE_MAX_JETON) throw new ErreurDer(`jeton de ${octets.length} octets, au-delà de ${TAILLE_MAX_JETON} (EX-9.3)`);
  const avertissements = [];
  const ci = lireUnique(octets, 1);
  attendre(ci, ETIQUETTE.SEQUENCE, true, "ContentInfo");
  const cie = enfants(ci);
  if (cie.length !== 2) throw new ErreurDer("ContentInfo mal formé", ci.debut);
  if (lireOid(cie[0]) !== OID.signedData) throw new ErreurDer("contentType différent de id-signedData", cie[0].debut);
  attendreContexte(cie[1], 0, true, "content [0]");
  const c0 = enfants(cie[1]);
  if (c0.length !== 1) throw new ErreurDer("content [0] mal formé", cie[1].debut);
  const sd = attendre(c0[0], ETIQUETTE.SEQUENCE, true, "SignedData");
  const s = enfants(sd);
  let i = 0;
  if (s.length < 4) throw new ErreurDer("SignedData incomplet", sd.debut);
  const version = lireEntier(s[i++]);
  if (version !== 3n) throw new ErreurDer("SignedData.version différente de 3", sd.debut);
  const da = attendre(s[i++], ETIQUETTE.SET, true, "digestAlgorithms");
  const digestAlgorithms = enfants(da).map((x) => lireAlgorithme(x));
  const eci = attendre(s[i++], ETIQUETTE.SEQUENCE, true, "EncapsulatedContentInfo");
  const ecie = enfants(eci);
  if (ecie.length !== 2) throw new ErreurDer("EncapsulatedContentInfo sans eContent", eci.debut);
  const eContentType = lireOid(ecie[0]);
  if (eContentType !== OID.tstInfo) throw new ErreurDer("eContentType différent de id-ct-TSTInfo", ecie[0].debut);
  attendreContexte(ecie[1], 0, true, "eContent [0]");
  const ec = enfants(ecie[1]);
  if (ec.length !== 1) throw new ErreurDer("eContent mal formé", ecie[1].debut);
  const eContent = lireOctets(ec[0]);
  let certificats = [];
  let certificatsPresents = false;
  if (s[i] && estContexte(s[i], 0, true)) {
    certificatsPresents = true;
    const cs = enfants(s[i]);
    if (cs.length > CERTIFICATS_MAX) throw new ErreurDer(`plus de ${CERTIFICATS_MAX} certificats`, s[i].debut);
    for (const c of cs) {
      attendre(c, ETIQUETTE.SEQUENCE, true, "Certificate");
      certificats.push(lireCertificat(c.tlv, c.profondeur));
    }
    i++;
  }
  const crls = [];
  let crlsIllisibles = 0;
  if (s[i] && estContexte(s[i], 1, true)) {
    for (const c of enfants(s[i])) {
      if (!estUniversel(c, ETIQUETTE.SEQUENCE, true)) {
        crlsIllisibles++;
        continue;
      }
      try {
        crls.push(lireCrlDer(c.tlv, c.profondeur));
      } catch {
        crlsIllisibles++;
      }
    }
    i++;
  }
  if (!s[i]) throw new ErreurDer("signerInfos absent", sd.debut);
  const sis = attendre(s[i++], ETIQUETTE.SET, true, "signerInfos");
  if (i !== s.length) throw new ErreurDer("SignedData : champ inattendu", sd.debut);
  const siList = enfants(sis);
  if (siList.length !== 1) throw new ErreurDer(`${siList.length} SignerInfo au lieu d'un`, sis.debut);
  const signerInfo = lireSignerInfo(siList[0]);
  const tstInfo = lireTstInfo(eContent, ec[0].profondeur + 1);
  avertissements.push(...tstInfo.avertissements);
  return { octets, sha256: null, version: 3, digestAlgorithms, eContent, certificats, certificatsPresents, crls, crlsIllisibles, signerInfo, tstInfo, avertissements };
}

/** Lit un `SignerInfo` (RFC 5652 §5.3) : version 1 avec `issuerAndSerialNumber`, ou 3 avec `subjectKeyIdentifier [0]`. */
function lireSignerInfo(tlv) {
  attendre(tlv, ETIQUETTE.SEQUENCE, true, "SignerInfo");
  const e = enfants(tlv);
  if (e.length < 5 || e.length > 7) throw new ErreurDer("SignerInfo mal formé", tlv.debut);
  let i = 0;
  const version = lireEntier(e[i++]);
  let sid;
  if (version === 1n) {
    const ias = attendre(e[i++], ETIQUETTE.SEQUENCE, true, "IssuerAndSerialNumber");
    const x = enfants(ias);
    if (x.length !== 2) throw new ErreurDer("IssuerAndSerialNumber mal formé", ias.debut);
    sid = { type: "issuerAndSerialNumber", emetteur: lireNom(x[0]), numeroSerie: entierOctetsNormalises(x[1]) };
  } else if (version === 3n) {
    const ski = attendreContexte(e[i++], 0, false, "subjectKeyIdentifier [0]");
    sid = { type: "subjectKeyIdentifier", valeur: ski.contenu };
  } else throw new ErreurDer("SignerInfo.version autre que 1 ou 3", tlv.debut);
  const digestAlgorithme = lireAlgorithme(e[i++]);
  if (!e[i] || !estContexte(e[i], 0, true)) throw new ErreurDer("signedAttrs absent", tlv.debut);
  const signedAttrsTlv = e[i++];
  const signedAttrs = { tlv: signedAttrsTlv.tlv, attributs: lireAttributs({ ...signedAttrsTlv, classe: 0, numero: ETIQUETTE.SET }) };
  const signatureAlgorithme = lireAlgorithme(e[i++]);
  if (!e[i]) throw new ErreurDer("signature absente", tlv.debut);
  const signature = lireOctets(e[i++]);
  let unsignedAttrs = null;
  if (e[i] && estContexte(e[i], 1, true)) {
    unsignedAttrs = lireAttributs({ ...e[i], classe: 0, numero: ETIQUETTE.SET });
    i++;
  }
  if (i !== e.length) throw new ErreurDer("SignerInfo : champ inattendu", tlv.debut);
  return { version: Number(version), sid, digestAlgorithme, signedAttrs, signatureAlgorithme, signature, unsignedAttrs };
}

/** Le jeton (ou son `TSTInfo`) porte la prétention `esi4-qtstStatement-1`. */
export function pretentionQualifiee(jeton, certificatSignataire) {
  if (porteQtstStatement(jeton.tstInfo)) return true;
  if (certificatSignataire && porteQtstStatement(certificatSignataire)) return true;
  return false;
}

export { controlerQcStatements };
