// Vecteurs CT-6, famille rfc3161 (spec/CT-6-verificateur.md, annexe A.3) :
// autorité et unité d'horodatage de test, CRL, jetons RFC 3161 sur le
// periodHash des trois manifestes de CT-1, et une variante invalide par
// vérification T- que la structure du jeton permet de viser.
//
//   import { genererRfc3161 } from "./ct6/rfc3161.mjs";
//   genererRfc3161({ racine: "spec/vecteurs/ct-6" });
//   node scripts/vecteurs/ct6/rfc3161.mjs [--sortie <répertoire ct-6>]
//
// Tout est déterministe : les jetons sont construits en DER par ce module,
// genTime, numéros de série et nonces sont fixes, et RSA PKCS #1 v1.5 est
// déterministe. Les clés RSA de test sont des ENTRÉES (EX-A.4) : le module lit
// rfc3161/cles/*.cle.pem s'ils existent et ne les réécrit jamais. Absentes, il
// les dérive d'une graine documentée (cleRsaDepuisGraine) : rejouer la
// dérivation redonne les mêmes clés, octet pour octet. Ces clés sont
// publiques et ne servent qu'aux tests.
//
// Le module vérifie chaque jeton avec scripts/lib/horodatage.mjs avant
// d'écrire attendu.json : un statut qui ne correspond pas à la conception du
// vecteur arrête la génération.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as H from "../../lib/horodatage.mjs";
import { hachageManifeste, analyserJSONStrict } from "../../lib/journal.mjs";

const PROJECT_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const OID = H.OID;

// ---------------------------------------------------------------------------
// Écriture DER (forme définie minimale, SET OF triés)
// ---------------------------------------------------------------------------

function longueur(n) {
  if (n < 0x80) return Buffer.from([n]);
  const o = [];
  for (let x = n; x > 0; x = Math.floor(x / 256)) o.unshift(x & 0xff);
  return Buffer.from([0x80 | o.length, ...o]);
}
/** TLV d'étiquette donnée (un octet). */
export const tlv = (etiquette, contenu) => Buffer.concat([Buffer.from([etiquette]), longueur(contenu.length), contenu]);
export const seq = (...e) => tlv(0x30, Buffer.concat(e));
/** SET OF trié selon X.690 §11.6 (comparaison des encodages). */
export const set = (...e) => tlv(0x31, Buffer.concat([...e].sort(Buffer.compare)));
export const nul = () => Buffer.from([0x05, 0x00]);
export const bool = (v) => tlv(0x01, Buffer.from([v ? 0xff : 0x00]));
export const octets = (b) => tlv(0x04, Buffer.from(b));
export const bits = (b, inutilises = 0) => tlv(0x03, Buffer.concat([Buffer.from([inutilises]), Buffer.from(b)]));
export const utf8 = (s) => tlv(0x0c, Buffer.from(s, "utf8"));
export const imprimable = (s) => tlv(0x13, Buffer.from(s, "latin1"));
export const explicite = (n, contenu) => tlv(0xa0 | n, contenu);
export const implicite = (n, contenu) => tlv(0x80 | n, contenu);
export function entier(v) {
  let x = BigInt(v);
  if (x < 0n) throw new Error("entier négatif non prévu");
  let h = x.toString(16);
  if (h.length % 2) h = "0" + h;
  let b = Buffer.from(h, "hex");
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
}
export function oid(texte) {
  const p = texte.split(".").map(BigInt);
  const sous = [p[0] * 40n + p[1], ...p.slice(2)];
  const out = [];
  for (const s of sous) {
    const groupe = [];
    let x = s;
    do {
      groupe.unshift(Number(x & 0x7fn));
      x >>= 7n;
    } while (x > 0n);
    for (let i = 0; i < groupe.length - 1; i++) groupe[i] |= 0x80;
    out.push(...groupe);
  }
  return tlv(0x06, Buffer.from(out));
}
/** UTCTime avant 2050, GeneralizedTime ensuite (RFC 5280 §4.1.2.5) ; `iso` : AAAA-MM-JJThh:mm:ssZ. */
export function temps(iso) {
  const m = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/.exec(iso);
  if (!m) throw new Error(`instant ${iso}`);
  const corps = `${m[2]}${m[3]}${m[4]}${m[5]}${m[6]}Z`;
  return +m[1] < 2050 ? tlv(0x17, Buffer.from(m[1].slice(2) + corps, "latin1")) : tlv(0x18, Buffer.from(m[1] + corps, "latin1"));
}
export const tempsGeneralise = (texte) => tlv(0x18, Buffer.from(texte, "latin1"));

/** Name X.501 : C (PrintableString), O et CN (UTF8String). */
export function nom({ C, O, CN }) {
  const rdn = (id, valeur) => set(seq(oid(id), valeur));
  return seq(...[C && rdn("2.5.4.6", imprimable(C)), O && rdn("2.5.4.10", utf8(O)), CN && rdn("2.5.4.3", utf8(CN))].filter(Boolean));
}
/** Extension X.509 ; `critiqueExplicite` encode critical à FALSE, valeur DEFAULT interdite (EX-9.21, vecteur t1-default-explicite). */
const extension = ({ oid: id, critique = false, critiqueExplicite = false, valeur }) => seq(oid(id), ...(critique ? [bool(true)] : critiqueExplicite ? [bool(false)] : []), octets(valeur));
const ALG = {
  sha1: seq(oid(OID.sha1)),
  sha256: seq(oid(OID.sha256)),
  sha256Nul: seq(oid(OID.sha256), nul()),
  sha256WithRSAEncryption: seq(oid(OID.sha256WithRSAEncryption), nul()),
  sha1WithRSAEncryption: seq(oid(OID.sha1WithRSAEncryption), nul()),
  rsaEncryption: seq(oid(OID.rsaEncryption), nul()),
};
export { ALG };

// ---------------------------------------------------------------------------
// Clés RSA dérivées d'une graine (documentées, pour les tests seulement)
// ---------------------------------------------------------------------------

const PREMIERS_IMPAIRS = [];
for (let n = 3; PREMIERS_IMPAIRS.length < 600; n += 2) if (PREMIERS_IMPAIRS.every((p) => n % p !== 0)) PREMIERS_IMPAIRS.push(n);
const TEMOINS = [2, ...PREMIERS_IMPAIRS.slice(0, 39)]; // les 40 premiers nombres premiers
const E = 65537n;
function puissanceModulaire(b, e, m) {
  let r = 1n;
  b %= m;
  for (; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
  }
  return r;
}
function millerRabin(n, temoins) {
  let d = n - 1n;
  let s = 0;
  while (!(d & 1n)) {
    d >>= 1n;
    s++;
  }
  suivant: for (const a of temoins) {
    let x = puissanceModulaire(BigInt(a), d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let r = 1; r < s; r++) {
      x = (x * x) % n;
      if (x === n - 1n) continue suivant;
    }
    return false;
  }
  return true;
}
/** Flux d'octets : SHA-256(UTF-8(« étiquette/i »)) pour i = 0, 1, … */
function flux(etiquette, n) {
  const parties = [];
  for (let i = 0, total = 0; total < n; i++, total += 32) parties.push(crypto.createHash("sha256").update(`${etiquette}/${i}`, "utf8").digest());
  return Buffer.concat(parties).subarray(0, n);
}
function premierDepuis(etiquette, octetsPremier) {
  const b = flux(etiquette, octetsPremier);
  b[0] |= 0xc0;
  b[b.length - 1] |= 0x01;
  for (let p = BigInt("0x" + b.toString("hex")); ; p += 2n) {
    if (!PREMIERS_IMPAIRS.every((q) => p % BigInt(q) !== 0n)) continue;
    if ((p - 1n) % E === 0n) continue;
    if (millerRabin(p, TEMOINS)) return p;
  }
}
function inverse(a, m) {
  let [r0, r1, s0, s1] = [a % m, m, 1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error("non inversible");
  return ((s0 % m) + m) % m;
}
const pgcd = (a, b) => (b === 0n ? a : pgcd(b, a % b));
const b64url = (x) => {
  let h = x.toString(16);
  if (h.length % 2) h = "0" + h;
  return Buffer.from(h, "hex").toString("base64url");
};
/**
 * Clé privée RSA de `bits` bits (e = 65537) dérivée de l'étiquette :
 * p (resp. q) est le premier entier, à partir de la valeur des bits/16 premiers
 * octets du flux SHA-256(UTF-8(« étiquette/p/i »)) (resp. « /q/ »), deux bits de
 * tête et bit de poids faible positionnés, puis par pas de 2, qui n'a aucun
 * diviseur parmi les 600 premiers nombres premiers impairs, tel que p − 1 ne
 * soit pas multiple de e, et qui passe Miller-Rabin pour les témoins 2, 3, …, 173
 * (les 40 premiers nombres premiers) ; d = e⁻¹ mod ppcm(p − 1, q − 1).
 */
export function cleRsaDepuisGraine(etiquette, taille = 3072) {
  let p = premierDepuis(`${etiquette}/p`, taille / 16);
  let q = premierDepuis(`${etiquette}/q`, taille / 16);
  if (p < q) [p, q] = [q, p];
  const n = p * q;
  const lambda = ((p - 1n) * (q - 1n)) / pgcd(p - 1n, q - 1n);
  const d = inverse(E, lambda);
  const jwk = { kty: "RSA", n: b64url(n), e: b64url(E), d: b64url(d), p: b64url(p), q: b64url(q), dp: b64url(d % (p - 1n)), dq: b64url(d % (q - 1n)), qi: b64url(inverse(q, p)) };
  return crypto.createPrivateKey({ key: jwk, format: "jwk" });
}

// ---------------------------------------------------------------------------
// Constantes des vecteurs (EX-A.4, EX-A.5)
// ---------------------------------------------------------------------------

export const GRAINES = {
  "ac-test": "noortrace/vecteurs/v0/ct-6/rsa/ac-test",
  "tsa-test": "noortrace/vecteurs/v0/ct-6/rsa/tsa-test",
};
export const SUJETS = {
  ac: { C: "CH", O: "NOORTRACE vecteurs", CN: "AC de test CT-6" },
  tsa: { C: "CH", O: "NOORTRACE vecteurs", CN: "TSA de test CT-6" },
};
/**
 * Sujet de tsa-cn-utf8-invalide.pem : C et O lisibles, CN en UTF8String
 * d'octets ff fe, qui ne se décodent pas en UTF-8 : le certificat est
 * illisible (EX-9.4), comme pour OpenSSL et crypto/x509 de Go.
 */
export const NOM_CN_UTF8_INVALIDE = seq(
  set(seq(oid("2.5.4.6"), imprimable("CH"))),
  set(seq(oid("2.5.4.10"), utf8("NOORTRACE vecteurs"))),
  set(seq(oid("2.5.4.3"), tlv(0x0c, Buffer.from([0xff, 0xfe])))),
);
/**
 * Sujet de tsa-sans-cn.pem : C et O seulement. tsu_subject_cn vaut null et
 * l'énoncé nomme l'unité par le SHA-256 de son certificat (EX-9.19, EX-9.20).
 */
export const NOM_SANS_CN = nom({ C: "CH", O: "NOORTRACE vecteurs, unité sans CN" });
export const NOM_UNITE_EPINGLEE = "Unité TSA épinglée de test CT-6";
export const POLITIQUE = "1.3.6.1.4.1.99999.1.1";
export const OID_EXTENSION_CRITIQUE = "1.3.6.1.4.1.99999.2";
export const NOM_AUTORITE = "AC de test CT-6";
export const CRL_THIS_UPDATE = "2026-11-06T00:00:00Z";
export const CRL_NEXT_UPDATE = "2026-12-06T00:00:00Z";
export const DATE_REVOCATION = "2026-11-05T12:00:00Z";
const ETIQUETTE_NONCE = (n) => `noortrace/vecteurs/v0/ct-6/nonce-tsa/periode-${n}`;
/** genTime = period_end + 5 s, écrit en GeneralizedTime. */
const genTimeDe = (periodEnd) => new Date((periodEnd + 5) * 1000).toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z";

const ski = (clePublique) => {
  const spki = H.lireDER(clePublique.export({ type: "spki", format: "der" }));
  return crypto.createHash("sha1").update(spki.enfants[1].valeur().subarray(1)).digest();
};

/** Certificat X.509 v3 signé en sha256WithRSAEncryption. */
export function construireCertificat({ numero, emetteur, sujet, debut, fin, clePublique, extensions = [], cleEmetteur }) {
  const tbs = seq(
    explicite(0, entier(2)),
    entier(numero),
    ALG.sha256WithRSAEncryption,
    emetteur,
    seq(temps(debut), temps(fin)),
    sujet,
    clePublique.export({ type: "spki", format: "der" }),
    explicite(3, seq(...extensions.map(extension))),
  );
  return seq(tbs, ALG.sha256WithRSAEncryption, bits(crypto.sign("sha256", tbs, cleEmetteur)));
}

/** CRL X.509 v2 complète signée en sha256WithRSAEncryption. */
export function construireCRL({ emetteur, thisUpdate, nextUpdate, revoques = [], numeroCrl, skiEmetteur, cleEmetteur }) {
  const entrees = revoques.map((r) => seq(entier(r.numero), temps(r.date), ...(r.raison === undefined || r.raison === null ? [] : [seq(extension({ oid: OID.cRLReasons, valeur: tlv(0x0a, Buffer.from([r.raison])) }))])));
  const tbs = seq(
    entier(1),
    ALG.sha256WithRSAEncryption,
    emetteur,
    temps(thisUpdate),
    temps(nextUpdate),
    ...(entrees.length ? [seq(...entrees)] : []),
    explicite(0, seq(extension({ oid: OID.authorityKeyIdentifier, valeur: seq(implicite(0, skiEmetteur)) }), extension({ oid: OID.cRLNumber, valeur: entier(numeroCrl) }))),
  );
  return seq(tbs, ALG.sha256WithRSAEncryption, bits(crypto.sign("sha256", tbs, cleEmetteur)));
}

/**
 * TimeStampToken (RFC 3161 §2.4.2) en DER. Options :
 *   empreinte        : messageImprint.hashedMessage (32 octets) ;
 *   genTime          : GeneralizedTime (texte AAAAMMJJhhmmss[.f]Z) ;
 *   serie, nonce     : entiers (nonce null : absent) ; precision : secondes (null : absente) ;
 *   tsaNom           : Name du champ tsa (null : absent) ;
 *   certificats      : DER des certificats du champ certificates ;
 *   signataire       : DER du certificat désigné par sid et par l'identifiant ESS ;
 *   cle              : clé privée de signature ;
 *   hash             : "sha256" (défaut) ou "sha1" : digestAlgorithm et message-digest ;
 *   extensionsTst    : [{ oid, critique, valeur }] ajoutées à TSTInfo ;
 *   certHash         : certHash de l'identifiant ESS imposé (défaut : empreinte du signataire) ;
 *   eContentPourDigest : TSTInfo dont message-digest est l'empreinte (défaut : le vrai).
 * Options réservées aux tests (cas que les vecteurs n'emploient pas) :
 *   algSignature, signer : AlgorithmIdentifier DER et fonction (données → signature) ;
 *   algImprint       : AlgorithmIdentifier DER de messageImprint ;
 *   ess              : "v2" (défaut), "v1" (signingCertificate en SHA-1), "les-deux" ou "aucun" ;
 *   attributsEnPlus  : attributs DER ajoutés à signedAttrs ;
 *   sid              : "issuerAndSerialNumber" (défaut) ou "ski" ;
 *   crls             : CRL DER du champ crls du SignedData ;
 *   tsaGeneralName   : GeneralName DER du champ tsa (remplace tsaNom) ;
 *   extensionsTstBrutes : extensions DER de TSTInfo, telles quelles ;
 *   precisionBrute   : Accuracy DER, telle quelle (remplace precision).
 */
export function construireJeton({ empreinte, genTime, serie, nonce, precision = 1, politique = POLITIQUE, tsaNom = null, certificats, signataire, cle, hash = "sha256", extensionsTst = [], certHash = null, eContentPourDigest = null, algSignature = null, signer = null, algImprint = ALG.sha256Nul, ess = "v2", attributsEnPlus = [], sid = "issuerAndSerialNumber", crls = [], tsaGeneralName = null, extensionsTstBrutes = null, precisionBrute = null }) {
  const extTst = extensionsTstBrutes ?? extensionsTst.map(extension);
  const tsa = tsaGeneralName ?? (tsaNom ? tlv(0xa4, tsaNom) : null);
  const eContent = seq(
    entier(1),
    oid(politique),
    seq(algImprint, octets(empreinte)),
    entier(serie),
    tempsGeneralise(genTime),
    ...(precisionBrute ? [precisionBrute] : precision === null ? [] : [seq(entier(precision))]),
    ...(nonce === null ? [] : [entier(nonce)]),
    ...(tsa ? [explicite(0, tsa)] : []),
    ...(extTst.length ? [tlv(0xa1, Buffer.concat(extTst))] : []),
  );
  const s = identiteSignataire(signataire);
  const algEmpreinte = hash === "sha1" ? ALG.sha1 : ALG.sha256;
  const algSig = algSignature ?? (hash === "sha1" ? ALG.sha1WithRSAEncryption : ALG.sha256WithRSAEncryption);
  const issuerSerial = seq(seq(tlv(0xa4, s.emetteur)), entier(s.numero));
  const essV1 = seq(oid(OID.signingCertificate), set(seq(seq(seq(octets(certHash ?? crypto.createHash("sha1").update(signataire).digest()), issuerSerial)))));
  const essV2 = seq(oid(OID.signingCertificateV2), set(seq(seq(seq(octets(certHash ?? crypto.createHash("sha256").update(signataire).digest()), issuerSerial)))));
  const attributs = set(
    seq(oid(OID.contentType), set(oid(OID.tstInfo))),
    seq(oid(OID.messageDigest), set(octets(crypto.createHash(hash).update(eContentPourDigest ?? eContent).digest()))),
    ...{ v2: [essV2], v1: [essV1], "les-deux": [essV1, essV2], aucun: [] }[ess],
    ...attributsEnPlus,
  );
  const signature = signer ? signer(attributs) : crypto.sign(hash, attributs, cle);
  const attributsImplicites = Buffer.from(attributs);
  attributsImplicites[0] = 0xa0;
  const identifiant = sid === "ski" ? implicite(0, Buffer.from(H.lireDER(s.extension(OID.subjectKeyIdentifier).valeur).valeur())) : seq(s.emetteur, entier(s.numero));
  const signerInfo = seq(entier(sid === "ski" ? 3 : 1), identifiant, algEmpreinte, attributsImplicites, algSig, octets(signature));
  const signedData = seq(
    entier(3),
    set(algEmpreinte),
    seq(oid(OID.tstInfo), explicite(0, octets(eContent))),
    ...(certificats.length ? [tlv(0xa0, Buffer.concat([...certificats].sort(Buffer.compare)))] : []),
    ...(crls.length ? [tlv(0xa1, Buffer.concat(crls))] : []),
    set(signerInfo),
  );
  return seq(oid(OID.signedData), explicite(0, signedData));
}

/**
 * Émetteur et numéro du certificat signataire. Le lecteur strict de
 * horodatage.mjs refuse un certificat qui encode une valeur DEFAULT
 * (tsa-critique-faux.pem, EX-9.21) : ces deux champs sont alors lus par le seul
 * lecteur DER, pour construire le jeton que T-1 doit refuser.
 */
function identiteSignataire(der) {
  try {
    return H.lireCertificat(der);
  } catch (err) {
    if (!(err instanceof H.ErreurDER)) throw err;
    const tbs = H.lireDER(der).enfants[0].enfants;
    const k = tbs[0].etiquette === 0xa0 ? 1 : 0;
    return { emetteur: Buffer.from(tbs[k + 2].octets()), numero: H.entier(tbs[k]), extension: () => null };
  }
}

// ---------------------------------------------------------------------------
// Matériel de test : clés, certificats, CRL
// ---------------------------------------------------------------------------

/** Clés de test : lues dans `repertoireCles` si présentes, sinon dérivées des graines. */
export function chargerCles(repertoireCles) {
  const cles = {};
  for (const [id, graine] of Object.entries(GRAINES)) {
    const fichier = repertoireCles ? path.join(repertoireCles, `${id}.cle.pem`) : null;
    cles[id] = fichier && fs.existsSync(fichier) ? crypto.createPrivateKey(fs.readFileSync(fichier, "utf8")) : cleRsaDepuisGraine(graine);
  }
  return cles;
}

/** Certificats, CRL et fichiers PEM de rfc3161/cles et rfc3161/crl, construits depuis les clés. */
export function materielTest(cles) {
  const pubAc = crypto.createPublicKey(cles["ac-test"]);
  const pubTsa = crypto.createPublicKey(cles["tsa-test"]);
  const nomAc = nom(SUJETS.ac);
  const nomTsa = nom(SUJETS.tsa);
  const skiAc = ski(pubAc);
  const skiTsa = ski(pubTsa);
  const ac = construireCertificat({
    numero: 1,
    emetteur: nomAc,
    sujet: nomAc,
    debut: "2026-01-01T00:00:00Z",
    fin: "2036-01-01T00:00:00Z",
    clePublique: pubAc,
    cleEmetteur: cles["ac-test"],
    extensions: [
      { oid: OID.basicConstraints, critique: true, valeur: seq(bool(true)) },
      { oid: OID.keyUsage, critique: true, valeur: bits(Buffer.from([0x06]), 1) }, // keyCertSign, cRLSign
      { oid: OID.subjectKeyIdentifier, valeur: octets(skiAc) },
    ],
  });
  const tsa = (numero, debut, fin, ekuCritique = true, { sujet = nomTsa, skiCritiqueExplicite = false } = {}) =>
    construireCertificat({
      numero,
      emetteur: nomAc,
      sujet,
      debut,
      fin,
      clePublique: pubTsa,
      cleEmetteur: cles["ac-test"],
      extensions: [
        { oid: OID.keyUsage, critique: true, valeur: bits(Buffer.from([0x80]), 7) }, // digitalSignature
        { oid: OID.extKeyUsage, critique: ekuCritique, valeur: seq(oid(OID.idKpTimeStamping)) },
        { oid: OID.subjectKeyIdentifier, critiqueExplicite: skiCritiqueExplicite, valeur: octets(skiTsa) },
        { oid: OID.authorityKeyIdentifier, valeur: seq(implicite(0, skiAc)) },
      ],
    });
  const certs = {
    "ac-test": ac,
    "tsa-test": tsa(2, "2026-06-01T00:00:00Z", "2027-06-01T00:00:00Z"),
    "tsa-expiree": tsa(3, "2026-01-01T00:00:00Z", "2026-06-30T23:59:59Z"),
    "tsa-eku-non-critique": tsa(4, "2026-06-01T00:00:00Z", "2027-06-01T00:00:00Z", false),
    "tsa-critique-faux": tsa(5, "2026-06-01T00:00:00Z", "2027-06-01T00:00:00Z", true, { skiCritiqueExplicite: true }),
    "tsa-cn-utf8-invalide": tsa(6, "2026-06-01T00:00:00Z", "2027-06-01T00:00:00Z", true, { sujet: NOM_CN_UTF8_INVALIDE }),
    "tsa-sans-cn": tsa(7, "2026-06-01T00:00:00Z", "2027-06-01T00:00:00Z", true, { sujet: NOM_SANS_CN }),
  };
  const crls = {
    "crl-vide": construireCRL({ emetteur: nomAc, thisUpdate: CRL_THIS_UPDATE, nextUpdate: CRL_NEXT_UPDATE, numeroCrl: 1, skiEmetteur: skiAc, cleEmetteur: cles["ac-test"] }),
    "crl-tsa-revoquee": construireCRL({ emetteur: nomAc, thisUpdate: CRL_THIS_UPDATE, nextUpdate: CRL_NEXT_UPDATE, revoques: [{ numero: 2, date: DATE_REVOCATION, raison: 1 }], numeroCrl: 2, skiEmetteur: skiAc, cleEmetteur: cles["ac-test"] }),
  };
  return { cles, certs, crls, nomTsa };
}

/**
 * Parties « horodatage » des fichiers d'ancres de test (EX-A.10) :
 * tsa_authorities et revocation de ancres-test.json,
 * ancres-qualification-declaree.json et ancres-tsa-revoquee.json.
 */
export function fragmentsAncres(materiel) {
  const autorite = (qualified) => ({
    name: NOM_AUTORITE,
    certificate: H.encoderPEM(materiel.certs["ac-test"], "CERTIFICATE"),
    intermediates: [],
    accepted_policies: [POLITIQUE],
    qualified,
    source: "AC de test des vecteurs CT-6 (spec/vecteurs/ct-6/rfc3161/cles/ac-test.pem), clé publique de test, sans valeur hors des tests",
  });
  const revocation = (crl) => ({ crls: [H.encoderPEM(materiel.crls[crl], "X509 CRL")], statements: [] });
  // Unité épinglée : le réviseur désigne le certificat de l'unité elle-même (EX-9.13, identité).
  const unite = (qualified) => ({
    name: NOM_UNITE_EPINGLEE,
    certificate: H.encoderPEM(materiel.certs["tsa-test"], "CERTIFICATE"),
    intermediates: [],
    accepted_policies: [POLITIQUE],
    qualified,
    source: "unité TSA de test des vecteurs CT-6 (spec/vecteurs/ct-6/rfc3161/cles/tsa-test.pem), épinglée par le réviseur ; clé publique de test, sans valeur hors des tests",
  });
  const qualifie = { framework: "eidas", valid_from: "2026-01-01T00:00:00.000Z", valid_to: null, source: "déclaration de test, sans valeur" };
  return {
    test: { tsa_authorities: [autorite(null)], revocation: revocation("crl-vide") },
    qualification_declaree: { tsa_authorities: [autorite(qualifie)], revocation: revocation("crl-vide") },
    tsa_revoquee: { tsa_authorities: [autorite(null)], revocation: revocation("crl-tsa-revoquee") },
    unite_epinglee_revoquee: { tsa_authorities: [unite(null)], revocation: revocation("crl-tsa-revoquee") },
    deux_autorites: { tsa_authorities: [unite(qualifie), autorite(null)], revocation: revocation("crl-vide") },
  };
}

/** Fichier d'ancres complet réduit aux parties d'horodatage (pour les attendus et les tests). */
export function ancresHorodatage(fragment) {
  return { version: 0, label: "ancres d'horodatage de test CT-6", prepared_by: "générateur des vecteurs CT-6", prepared_at: "2026-11-10T08:00:00.000Z", ...fragment, bitcoin: null, registry: null, recorders: [] };
}

/** periodHash des trois manifestes de CT-1 (EX-A.2). */
export const PERIOD_HASHES = [
  "0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914",
  "0xe867be7f64b77e49a9c3066d33aa39cffc5b5a588edec54f99cb2d07ff33bf19",
  "0x5852e3c7f403875b9b634f5e5d7074ea197fc34ecf80e092b9686d8c2dc80594",
];

/** Les trois manifestes de CT-1 et leur periodHash recalculé, contrôlé contre EX-A.2. */
export function manifestesCT1(repertoireCT1 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-1")) {
  return [1, 2, 3].map((n) => {
    const m = analyserJSONStrict(fs.readFileSync(path.join(repertoireCT1, "manifestes", `periode-${n}.json`)));
    const periodHash = hachageManifeste(m);
    if (periodHash !== PERIOD_HASHES[n - 1]) throw new Error(`manifeste de la période ${n} : periodHash ${periodHash} au lieu de ${PERIOD_HASHES[n - 1]} (EX-A.2)`);
    return { n, manifeste: m, periodHash };
  });
}

/**
 * Les jetons de rfc3161/jetons (EX-A.5), avec la conception de chaque vecteur :
 * période dont le dossier vérifie le jeton, ancres, vérification visée.
 */
export function jetonsTest(materiel, manifestes) {
  const { certs, cles, nomTsa } = materiel;
  const base = (n, autres = {}) => {
    const { manifeste, periodHash } = manifestes[n - 1];
    return construireJeton({
      empreinte: Buffer.from(periodHash.slice(2), "hex"),
      genTime: genTimeDe(manifeste.period_end),
      serie: n,
      nonce: BigInt("0x" + crypto.createHash("sha256").update(ETIQUETTE_NONCE(n), "utf8").digest().subarray(0, 8).toString("hex")),
      tsaNom: nomTsa,
      certificats: [certs["tsa-test"]],
      signataire: certs["tsa-test"],
      cle: cles["tsa-test"],
      ...autres,
    });
  };
  const p1 = manifestes[0].manifeste;
  const genTimePlusUn = genTimeDe(p1.period_end + 1);
  const t6 = Buffer.from(base(1));
  t6[t6.length - 1] ^= 0xff;
  const eContentOrigine = H.lireJeton(base(1)).eContent;
  return {
    "periode-1": { octets: base(1), alteration: null, cible: null },
    "periode-2": { octets: base(2), alteration: null, cible: null },
    "periode-3": { octets: base(3), alteration: null, cible: null },
    "t1-octet-en-trop": { octets: Buffer.concat([base(1), Buffer.from([0x00])]), alteration: "un octet 00 après le ContentInfo", cible: "T-1" },
    "t3-message-digest": { octets: base(1, { genTime: genTimePlusUn, eContentPourDigest: eContentOrigine }), alteration: "genTime avancé d'une seconde dans TSTInfo ; signedAttrs re-signés, à l'identique puisque message-digest, empreinte du TSTInfo d'origine, est inchangé", cible: "T-3" },
    "t4-ess-autre-certificat": { octets: base(1, { certHash: crypto.createHash("sha256").update(certs["ac-test"]).digest() }), alteration: "certHash de ESSCertIDv2 = SHA-256 de ac-test.pem, re-signé", cible: "T-4" },
    "t5-sha1": { octets: base(1, { hash: "sha1" }), alteration: "digestAlgorithm SHA-1, message-digest SHA-1, signature sha1WithRSAEncryption", cible: "T-5" },
    "t6-signature": { octets: t6, alteration: "dernier octet de la signature inversé (xor ff)", cible: "T-6" },
    "t7-tsa-expiree": { octets: base(1, { certificats: [certs["tsa-expiree"]], signataire: certs["tsa-expiree"] }), alteration: "signé par la même clé, certificates = [tsa-expiree.pem]", cible: "T-7" },
    "t8-eku-non-critique": { octets: base(1, { certificats: [certs["tsa-eku-non-critique"]], signataire: certs["tsa-eku-non-critique"] }), alteration: "certificates = [tsa-eku-non-critique.pem]", cible: "T-8" },
    "t9-extension-critique": { octets: base(1, { extensionsTst: [{ oid: OID_EXTENSION_CRITIQUE, critique: true, valeur: nul() }] }), alteration: `extension critique d'OID ${OID_EXTENSION_CRITIQUE} dans TSTInfo, re-signé`, cible: "T-9" },
    "t1-default-explicite": { octets: base(1, { certificats: [certs["tsa-critique-faux"]], signataire: certs["tsa-critique-faux"] }), alteration: "certificates = [tsa-critique-faux.pem] : extension subjectKeyIdentifier avec critical codé explicitement à FALSE (valeur DEFAULT encodée, EX-9.21)", cible: "T-1" },
    "t1-cn-utf8-invalide": { octets: base(1, { certificats: [certs["tsa-cn-utf8-invalide"]], signataire: certs["tsa-cn-utf8-invalide"], tsaNom: null }), alteration: "certificates = [tsa-cn-utf8-invalide.pem] (CN en UTF8String d'octets ff fe, UTF-8 invalide), champ tsa absent : certificat illisible (EX-9.4)", cible: "T-1" },
    "periode-1-unite-sans-cn": { octets: base(1, { certificats: [certs["tsa-sans-cn"]], signataire: certs["tsa-sans-cn"], tsaNom: NOM_SANS_CN }), alteration: "certificates = [tsa-sans-cn.pem] (sujet sans commonName), tsa = son sujet : jeton valide, tsu_subject_cn nul, unité nommée par le SHA-256 de son certificat (EX-9.19, EX-9.20)", cible: null },
  };
}

/**
 * Cas vérifiés : chaque jeton contre le periodHash du dossier qui l'emploie et
 * le fichier d'ancres indiqué, avec les statuts attendus de T-1 à T-11.
 */
function casVerifies(jetons, manifestes, ancres) {
  const cas = [];
  const ajouter = (jeton, periode, ancresNom, attendu) => cas.push({ jeton, periode, ancresNom, attendu });
  // Conception : liste des vérifications en échec, et statut du contrôle 4.
  ajouter("periode-1", 1, "ancres-test", { echecs: [], controle: "reussi" });
  ajouter("periode-2", 2, "ancres-test", { echecs: [], controle: "reussi" });
  ajouter("periode-3", 3, "ancres-test", { echecs: [], controle: "reussi" });
  ajouter("periode-2", 1, "ancres-test", { echecs: ["T-2"], controle: "echoue" });
  ajouter("periode-1", 1, "ancres-tsa-revoquee", { echecs: ["T-10"], controle: "echoue" });
  ajouter("periode-1", 1, "ancres-qualification-declaree", { echecs: [], controle: "reussi", t11: "reussi" });
  ajouter("periode-1", 1, "ancres-unite-epinglee-revoquee", { echecs: ["T-10"], controle: "echoue" });
  ajouter("periode-1", 1, "ancres-deux-autorites", { echecs: [], controle: "reussi", t11: "reussi" });
  ajouter("periode-1-unite-sans-cn", 1, "ancres-test", { echecs: [], controle: "reussi" });
  ajouter("periode-1", 1, null, { echecs: [], controle: "non_execute" });
  for (const [nomJeton, j] of Object.entries(jetons)) if (j.cible) ajouter(nomJeton, 1, "ancres-test", { echecs: [j.cible], controle: "echoue" });
  return cas.map((c) => {
    const ph = manifestes[c.periode - 1].periodHash;
    const r = H.evaluerJeton(jetons[c.jeton].octets, { periodHash: ph, ancres: c.ancresNom ? ancres[c.ancresNom] : null });
    const echecs = r.checks.filter((x) => x.status === "echoue").map((x) => x.id);
    const t11 = r.checks.find((x) => x.id === "T-11");
    if (JSON.stringify(echecs) !== JSON.stringify(c.attendu.echecs) || r.status !== c.attendu.controle || (c.attendu.t11 && t11.status !== c.attendu.t11))
      throw new Error(`vecteur rfc3161 ${c.jeton} (période ${c.periode}, ${c.ancresNom}) : échecs ${JSON.stringify(echecs)}, contrôle ${r.status}, attendus ${JSON.stringify(c.attendu)}`);
    return {
      token: `jetons/${c.jeton}.der`,
      dossier_period_hash: ph,
      anchors: c.ancresNom ? `ancres/${c.ancresNom}.json` : null,
      checks: r.checks.map((x) => ({ id: x.id, status: x.status, reason: x.reason })),
      failed_checks: echecs,
      control_status: r.status,
      control_reason: r.reason,
      warnings: r.warnings.map((w) => w.id),
      facts: r.facts,
    };
  });
}

// Résultats d'openssl ts -verify (OpenSSL 3.0.13) : présumés par l'annexe A.3
// (établis par R1), ou relevés par la confrontation (A.8,
// confrontation/sorties/rfc3161.txt) et inscrits ici.
const OPENSSL_PRESUME = {
  "periode-1": { resultat: "Verification: OK", source: "R1 F6.08" },
  "periode-2": { resultat: "Verification: OK", source: "R1 F6.08" },
  "periode-3": { resultat: "Verification: OK", source: "R1 F6.08" },
  "t1-octet-en-trop": { resultat: "Verification: OK (l'octet qui suit le ContentInfo est ignoré ; openssl asn1parse relève « Error in encoding »)", source: "relevé par la confrontation (A.8)" },
  "t3-message-digest": { resultat: "digest failure", source: "relevé par la confrontation (A.8)" },
  "t4-ess-autre-certificat": { resultat: "ess cert id not found", source: "relevé par la confrontation (A.8)" },
  "t5-sha1": { resultat: "Verification: OK (OpenSSL n'applique pas la table de EX-9.11)", source: "relevé par la confrontation (A.8)" },
  "t6-signature": { resultat: "invalid padding / signature failure", source: "relevé par la confrontation (A.8)" },
  "t7-tsa-expiree": { resultat: "certificate has expired", source: "R1 F5.14" },
  "t8-eku-non-critique": { resultat: "refus de l'extendedKeyUsage non critique", source: "R1 F5.12 (code lu)" },
  "t9-extension-critique": { resultat: "Verification: OK (extension critique inconnue de TSTInfo non refusée)", source: "relevé par la confrontation (A.8)" },
  "t1-default-explicite": { resultat: "Verification: OK (critical FALSE encodé n'est pas refusé ; openssl asn1parse du certificat imprime « BOOLEAN :0 »)", source: "relevé par la confrontation (A.8)" },
  "t1-cn-utf8-invalide": { resultat: "invalid utf8string (le jeton n'est pas lu)", source: "relevé par la confrontation (A.8)" },
  "periode-1-unite-sans-cn": { resultat: "Verification: OK", source: "relevé par la confrontation (A.8)" },
};

/**
 * Octets de eContent (TSTInfo) d'un jeton lus par le seul lecteur DER, sans
 * lire ses certificats : vaut aussi pour un jeton que T-1 refuse pour un
 * certificat (t1-default-explicite).
 */
function eContentBrut(octets) {
  const signedData = H.lireDER(octets).enfants[1].enfants[0];
  const encap = signedData.enfants[2];
  return Buffer.from(encap.enfants[1].enfants[0].valeur());
}

/**
 * Écrit la famille rfc3161 dans `<racine>/rfc3161` : cles/ (clés si absentes,
 * certificats), crl/, jetons/, attendu.json. Rend { jetons, materiel,
 * fragments, attendu } pour le générateur principal.
 */
export function genererRfc3161({ racine = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-6"), repertoireCT1 } = {}) {
  const dossier = path.join(racine, "rfc3161");
  const repCles = path.join(dossier, "cles");
  fs.mkdirSync(repCles, { recursive: true });
  // Tout rfc3161/ est réécrit, sauf cles/, qui est une entrée (EX-A.1).
  for (const e of fs.readdirSync(dossier)) if (e !== "cles") fs.rmSync(path.join(dossier, e), { recursive: true, force: true });

  // Les certificats de cles/ sont générés : seules les clés (*.cle.pem) sont des entrées.
  for (const f of fs.readdirSync(repCles)) if (f.endsWith(".pem") && !f.endsWith(".cle.pem")) fs.rmSync(path.join(repCles, f));
  const cles = chargerCles(repCles);
  for (const id of Object.keys(GRAINES)) {
    const fichier = path.join(repCles, `${id}.cle.pem`);
    if (!fs.existsSync(fichier)) fs.writeFileSync(fichier, cles[id].export({ type: "pkcs8", format: "pem" }));
  }
  const materiel = materielTest(cles);
  for (const [id, der] of Object.entries(materiel.certs)) fs.writeFileSync(path.join(repCles, `${id}.pem`), H.encoderPEM(der, "CERTIFICATE"));
  fs.mkdirSync(path.join(dossier, "crl"));
  for (const [id, der] of Object.entries(materiel.crls)) fs.writeFileSync(path.join(dossier, "crl", `${id}.pem`), H.encoderPEM(der, "X509 CRL"));

  const manifestes = manifestesCT1(repertoireCT1);
  const jetons = jetonsTest(materiel, manifestes);
  fs.mkdirSync(path.join(dossier, "jetons"));
  for (const [id, j] of Object.entries(jetons)) fs.writeFileSync(path.join(dossier, "jetons", `${id}.der`), j.octets);

  const fragments = fragmentsAncres(materiel);
  const ancres = {
    "ancres-test": ancresHorodatage(fragments.test),
    "ancres-qualification-declaree": ancresHorodatage(fragments.qualification_declaree),
    "ancres-tsa-revoquee": ancresHorodatage(fragments.tsa_revoquee),
    "ancres-unite-epinglee-revoquee": ancresHorodatage(fragments.unite_epinglee_revoquee),
    "ancres-deux-autorites": ancresHorodatage(fragments.deux_autorites),
  };
  const sha = (b) => "0x" + crypto.createHash("sha256").update(b).digest("hex");
  const attendu = {
    description: "Vecteurs CT-6 de la famille rfc3161 (spec/CT-6-verificateur.md, annexe A.3). Les statuts sont ceux de l'implémentation de référence (scripts/lib/horodatage.mjs) avec les seules parties d'horodatage des fichiers d'ancres de test (tsa_authorities, revocation).",
    keys: {
      derivation: "RSA 3072, e = 65537 ; p et q dérivés des étiquettes <graine>/p et <graine>/q par scripts/vecteurs/ct6/rfc3161.mjs (cleRsaDepuisGraine) ; SHA-256 des clés : PKCS #8 DER ; clés publiques, pour les tests seulement",
      seeds: GRAINES,
      files: Object.fromEntries([...Object.keys(GRAINES).map((id) => [`cles/${id}.cle.pem`, sha(cles[id].export({ type: "pkcs8", format: "der" }))]), ...Object.entries(materiel.certs).map(([id, der]) => [`cles/${id}.pem`, sha(der)])]),
    },
    crls: Object.fromEntries(Object.entries(materiel.crls).map(([id, der]) => [`crl/${id}.pem`, sha(der)])),
    tokens: Object.entries(jetons).map(([id, j]) => {
      const tst = H.lireTSTInfo(eContentBrut(j.octets.subarray(0, id === "t1-octet-en-trop" ? j.octets.length - 1 : j.octets.length)));
      return {
        file: `jetons/${id}.der`,
        sha256: sha(j.octets),
        period_hash: "0x" + tst.empreinte.toString("hex"),
        gen_time: H.rfc3339(H.lireGenTime(tst.genTimeTexte)),
        serial_number: "0x" + tst.numero.toString(16).padStart(2, "0"),
        alteration: j.alteration,
        target: j.cible,
        openssl_ts_verify: {
          command: `openssl ts -verify -digest <period_hash sans 0x> -in jetons/${id}.der -token_in -CAfile cles/ac-test.pem -attime <genTime en secondes UNIX>`,
          presumed_result: OPENSSL_PRESUME[id]?.resultat ?? null,
          source: OPENSSL_PRESUME[id]?.source ?? "non présumé : relevé par la confrontation (annexe A.8)",
        },
      };
    }),
    openssl_ts_verify_other_period: {
      command: "openssl ts -verify -digest <periodHash de la période 1> -in jetons/periode-2.der -token_in -CAfile cles/ac-test.pem -attime <genTime>",
      presumed_result: "message imprint mismatch",
      source: "R1 F6.08",
    },
    cases: casVerifies(jetons, manifestes, ancres),
  };
  fs.writeFileSync(path.join(dossier, "attendu.json"), JSON.stringify(attendu, null, 2) + "\n");
  return { jetons, materiel, fragments, ancres, attendu, manifestes };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const i = process.argv.indexOf("--sortie");
  const racine = i !== -1 ? path.resolve(process.argv[i + 1]) : undefined;
  const r = genererRfc3161({ racine });
  process.stdout.write(`rfc3161 : ${Object.keys(r.jetons).length} jetons, ${r.attendu.cases.length} cas vérifiés\n`);
}
