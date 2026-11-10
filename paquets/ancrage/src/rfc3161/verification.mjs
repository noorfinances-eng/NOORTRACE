// Vérification d'un jeton à l'acquisition : T-1 à T-9 de CT-6 §9.5 (EX-9.7 à
// EX-9.15, EX-9.23, EX-9.24), sur l'empreinte demandée et avec les ancres du
// prestataire (`anchor_certificates`, `accepted_policies`) à la place de
// `tsa_authorities[]` (CT-5 EX-5.10 étape 6 ; CT-6 EX-13.2). T-10 est
// différée (`revocation.mjs`) ; T-11 n'est jamais exécutée (EX-5.9).
//
// Statuts et raisons : ceux de CT-6 EX-6.1 et §6.2 (`reussi`, `echoue`,
// `non_execute` ; `prerequis_en_echec`, `ancre_absente`, `hors_perimetre_version`).

import { ErreurDer, ETIQUETTE, enfants, attendre, estUniversel, estContexte, lireOid, lireOctets, lireEntier, entierOctetsNormalises, lireAlgorithme, lireUnique, octetsEgaux, hexVersOctets, octetsVersHex, lireNull } from "./der.mjs";
import { OID, HACHAGES, hacher, lireCertificat, lireCertificatPem, lireNom, controlerQcStatements } from "./x509.mjs";
import { lireJeton, pretentionQualifiee } from "./reponse.mjs";
import { analyserAlgorithmeSignature, hachageAdmis, verifierSignatureBrute, verifierSignatureEmise, nomHachage } from "./signatures.mjs";

/** Identifiants des vérifications exécutées à l'acquisition. */
export const VERIFICATIONS_ACQUISITION = Object.freeze(["T-1", "T-2", "T-3", "T-4", "T-5", "T-6", "T-7", "T-8", "T-9"]);

/** Longueur maximale d'un chemin, ancre non comprise (CT-6 §15.1 : 5 certificats). */
export const CHEMIN_MAX = 5;

/** Ancres inexploitables (N-1 : un certificat d'ancre ne se lit pas). */
export class ErreurAncres extends Error {
  constructor(message) {
    super(message);
    this.name = "ErreurAncres";
    this.code = "N-1";
  }
}

const reussi = () => ({ statut: "reussi", raison: null, detail: null });
const echoue = (detail) => ({ statut: "echoue", raison: null, detail });
const nonExecute = (raison, detail = null) => ({ statut: "non_execute", raison, detail });
/** Statut hérité de prérequis (CT-6 EX-5.5) : un échec donne `prerequis_en_echec`, une non-exécution reprend sa raison. */
function heriter(...prerequis) {
  if (prerequis.some((p) => p.statut === "echoue")) return nonExecute("prerequis_en_echec");
  const n = prerequis.find((p) => p.statut === "non_execute");
  return nonExecute(n ? n.raison : "prerequis_en_echec");
}

/** Lit un certificat donné en PEM ou en DER. */
function certificatDepuis(source, quoi) {
  try {
    if (typeof source === "string") return lireCertificatPem(source);
    if (source instanceof Uint8Array) return lireCertificat(source);
    if (source && source.octets instanceof Uint8Array && source.sujet) return source;
  } catch (err) {
    throw new ErreurAncres(`${quoi} illisible : ${err.message}`);
  }
  throw new ErreurAncres(`${quoi} : PEM ou DER attendu`);
}

/**
 * Normalise les ancres en une liste d'autorités `{ nom, certificat, intermediaires,
 * politiquesAdmises, qualified }`. Formes admises : `null` (aucune ancre) ;
 * `{ certificatsPem[], politiquesAdmises|null }` (forme réduite d'un
 * prestataire) ; `{ autorites: [{ nom, certificat|certificatPem, intermediaires|intermediairesPem, politiquesAdmises }] }` ;
 * le fichier d'ancres de CT-6 §12.2 (`tsa_authorities[]`).
 */
export function normaliserAncres(ancres) {
  if (ancres === null || ancres === undefined) return { autorites: [] };
  if (Array.isArray(ancres.tsa_authorities)) {
    return {
      autorites: ancres.tsa_authorities.map((a, i) => ({
        nom: a.name ?? `autorite-${i + 1}`,
        certificat: certificatDepuis(a.certificate, `tsa_authorities[${i}].certificate`),
        intermediaires: (a.intermediates ?? []).map((p, j) => certificatDepuis(p, `tsa_authorities[${i}].intermediates[${j}]`)),
        politiquesAdmises: a.accepted_policies ?? null,
        qualified: a.qualified ?? null,
      })),
    };
  }
  if (Array.isArray(ancres.autorites)) {
    return {
      autorites: ancres.autorites.map((a, i) => ({
        nom: a.nom ?? `autorite-${i + 1}`,
        certificat: certificatDepuis(a.certificat ?? a.certificatPem, `autorites[${i}].certificat`),
        intermediaires: (a.intermediaires ?? a.intermediairesPem ?? []).map((p, j) => certificatDepuis(p, `autorites[${i}].intermediaires[${j}]`)),
        politiquesAdmises: a.politiquesAdmises ?? null,
        qualified: a.qualified ?? null,
      })),
    };
  }
  if (Array.isArray(ancres.certificatsPem)) {
    return {
      autorites: ancres.certificatsPem.map((pem, i) => {
        const certificat = certificatDepuis(pem, `certificatsPem[${i}]`);
        return { nom: certificat.sujet.cn ?? certificat.sha256, certificat, intermediaires: [], politiquesAdmises: ancres.politiquesAdmises ?? null, qualified: null };
      }),
    };
  }
  throw new ErreurAncres("forme des ancres inconnue");
}

/** Forme réduite des ancres d'un prestataire d'`ancrage-v0` (EX-5.10 étape 6). */
export function ancresDepuisPrestataire(prestataire) {
  return { certificatsPem: prestataire.anchor_certificates ?? [], politiquesAdmises: prestataire.accepted_policies ?? null };
}

/** Texte RFC 3339 d'un `genTime` lu (`AAAAMMJJhhmmss[.f]Z` → `AAAA-MM-JJThh:mm:ss[.f]Z`). */
export function genTimeVersRfc3339(texte) {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(texte);
  if (!m) return null;
  return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] ?? ""}Z`;
}

/** Instant en microsecondes UTC → RFC 3339 UTC, fraction sans zéro final. */
export function microsecondesVersRfc3339(us) {
  const s = Math.floor(us / 1e6);
  const frac = us - s * 1e6;
  const d = new Date(s * 1000);
  const base = d.toISOString().slice(0, 19);
  if (frac === 0) return `${base}Z`;
  return `${base}.${String(frac).padStart(6, "0").replace(/0+$/, "")}Z`;
}

/** `accuracy` lue → microsecondes (entier) ; `null` sans `accuracy`. */
export function accuracyMicrosecondes(accuracy) {
  if (!accuracy) return null;
  const s = accuracy.seconds ?? 0n;
  const ms = accuracy.millis ?? 0n;
  const us = accuracy.micros ?? 0n;
  const total = s * 1000000n + ms * 1000n + us;
  return total > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(total);
}

/**
 * Cherche un chemin `S = c₀, …, cₙ` (n ≤ 4) vers une autorité (EX-9.13,
 * règles 1 à 7), déterministe : première autorité, chemin le plus court,
 * premier dans l'ordre des candidats. Rend `{ chemin: [cert…], autorite, identite }`
 * ou `null`. `instant` est `genTime` en millisecondes (`null` : la règle 4 ne
 * tient jamais).
 */
export function chercherChemin({ S, candidats, autorites, politique, instant }) {
  if (instant === null || instant === undefined) return null;
  const dates = (c) => c.notBefore <= instant && instant <= c.notAfter;
  const extensionsAdmises = (c) => c.extensions.every((x) => !x.critique || x.oid === OID.basicConstraints || x.oid === OID.keyUsage || x.oid === OID.extKeyUsage);
  const regleAc = (c, i) => {
    const bc = c.contraintesBase;
    if (!bc || !bc.critique || !bc.ca) return false;
    if (bc.cheminMax !== null && bc.cheminMax < i - 1) return false;
    if (c.usagesCle && !c.usagesCle.a(5)) return false;
    return true;
  };
  const feuilleAdmise = (c) => dates(c) && extensionsAdmises(c);
  for (const A of autorites) {
    if (A.politiquesAdmises !== null && !A.politiquesAdmises.includes(politique)) continue; // règle 7
    // n = 0, identité : l'ancre désigne l'unité elle-même ; règles 4 et 6 sur S.
    if (octetsEgaux(S.octets, A.certificat.octets)) {
      if (feuilleAdmise(S)) return { chemin: [S], autorite: A, identite: true };
      continue;
    }
    if (!feuilleAdmise(S)) continue;
    // n = 0, S émis par A.
    if (octetsEgaux(S.emetteur.octets, A.certificat.sujet.octets) && verifierSignatureEmise(S, A.certificat)) {
      return { chemin: [S], autorite: A, identite: false };
    }
    // n = 1 à 4 : recherche en profondeur par longueur croissante, dans l'ordre des candidats.
    for (let n = 1; n <= CHEMIN_MAX - 1; n++) {
      const trouve = etendre([S], n);
      if (trouve) return { chemin: trouve, autorite: A, identite: false };
    }
    function etendre(chemin, n) {
      const dernier = chemin[chemin.length - 1];
      const i = chemin.length; // indice du prochain cᵢ
      for (const c of candidats) {
        if (chemin.some((d) => octetsEgaux(d.octets, c.octets))) continue;
        if (!octetsEgaux(dernier.emetteur.octets, c.sujet.octets)) continue;
        if (!dates(c) || !extensionsAdmises(c) || !regleAc(c, i)) continue;
        if (!verifierSignatureEmise(dernier, c)) continue;
        const suite = [...chemin, c];
        if (i === n) {
          if (octetsEgaux(c.emetteur.octets, A.certificat.sujet.octets) && verifierSignatureEmise(c, A.certificat)) return suite;
          continue;
        }
        const r = etendre(suite, n);
        if (r) return r;
      }
      return null;
    }
  }
  return null;
}

/** Lit le premier `ESSCertID` (v1, SHA-1) : `{ certHash, issuerSerial }`. */
function lireEssCertId(valeur) {
  const sc = attendre(valeur, ETIQUETTE.SEQUENCE, true, "SigningCertificate");
  const e = enfants(sc);
  if (e.length < 1 || e.length > 2) throw new ErreurDer("SigningCertificate mal formé", sc.debut);
  const certs = enfants(attendre(e[0], ETIQUETTE.SEQUENCE, true, "certs"));
  if (certs.length === 0) throw new ErreurDer("SigningCertificate sans ESSCertID", sc.debut);
  const id = enfants(attendre(certs[0], ETIQUETTE.SEQUENCE, true, "ESSCertID"));
  if (id.length < 1 || id.length > 2) throw new ErreurDer("ESSCertID mal formé", certs[0].debut);
  return { hachage: OID.sha1, certHash: lireOctets(id[0]), issuerSerial: id[1] ? lireIssuerSerial(id[1]) : null, hachageEncode: false };
}

/** Lit le premier `ESSCertIDv2` : `{ hachage, certHash, issuerSerial, hachageEncode }`. */
function lireEssCertIdV2(valeur) {
  const sc = attendre(valeur, ETIQUETTE.SEQUENCE, true, "SigningCertificateV2");
  const e = enfants(sc);
  if (e.length < 1 || e.length > 2) throw new ErreurDer("SigningCertificateV2 mal formé", sc.debut);
  const certs = enfants(attendre(e[0], ETIQUETTE.SEQUENCE, true, "certs"));
  if (certs.length === 0) throw new ErreurDer("SigningCertificateV2 sans ESSCertIDv2", sc.debut);
  const id = enfants(attendre(certs[0], ETIQUETTE.SEQUENCE, true, "ESSCertIDv2"));
  let i = 0;
  let hachage = OID.sha256;
  let hachageEncode = false;
  if (id[i] && estUniversel(id[i], ETIQUETTE.SEQUENCE, true)) {
    hachage = lireAlgorithme(id[i++]).oid;
    hachageEncode = true;
  }
  if (!id[i]) throw new ErreurDer("ESSCertIDv2 sans certHash", certs[0].debut);
  const certHash = lireOctets(id[i++]);
  const issuerSerial = id[i] ? lireIssuerSerial(id[i++]) : null;
  if (i !== id.length) throw new ErreurDer("ESSCertIDv2 mal formé", certs[0].debut);
  return { hachage, certHash, issuerSerial, hachageEncode };
}

/** `IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber INTEGER }` → `{ directoryName (Name)|null, numeroSerie }`. */
function lireIssuerSerial(tlv) {
  const e = enfants(attendre(tlv, ETIQUETTE.SEQUENCE, true, "IssuerSerial"));
  if (e.length !== 2) throw new ErreurDer("IssuerSerial mal formé", tlv.debut);
  const noms = enfants(attendre(e[0], ETIQUETTE.SEQUENCE, true, "GeneralNames"));
  let directoryName = null;
  for (const g of noms) {
    if (estContexte(g, 4, true)) {
      const n = enfants(g);
      if (n.length !== 1) throw new ErreurDer("directoryName mal formé", g.debut);
      directoryName = lireNom(n[0]);
    }
  }
  return { directoryName, numeroSerie: entierOctetsNormalises(e[1]) };
}

/**
 * Exécute T-1 à T-9 sur un jeton. Entrées : `octets` du `TimeStampToken`,
 * `imprintAttendue` (hex32 ou 32 octets ; `null` : T-2 non exécutée,
 * `prerequis_en_echec`), `ancres` (voir `normaliserAncres`), `aGenTime`
 * (toujours vrai : T-7 est évaluée à `genTime`, EX-9.13).
 */
export function verifierJeton({ octets, imprintAttendue, ancres = null, aGenTime = true }) {
  if (aGenTime !== true) throw new TypeError("T-7 est évaluée à genTime (EX-9.13) : aGenTime doit être vrai");
  const { autorites } = normaliserAncres(ancres);
  const checks = {};
  const avertissements = [];
  const r = {
    checks,
    raisons: {},
    details: {},
    avertissements,
    jeton: null,
    tstInfo: null,
    certificatSignataire: null,
    chemin: [],
    autorite: null,
    identite: false,
    faits: null,
  };
  const poser = (id, s) => {
    checks[id] = s.statut;
    r.raisons[id] = s.raison;
    r.details[id] = s.detail;
    return s;
  };
  const avertir = (id, detail) => avertissements.push({ id, detail });

  // T-1 : structure.
  let jeton;
  try {
    jeton = lireJeton(octets);
    r.jeton = jeton;
    for (const av of jeton.avertissements) avertir(av, "critical encodé à FALSE dans une extension de TSTInfo (EX-9.5)");
    if (jeton.crlsIllisibles > 0) avertir("AV-T-3", `${jeton.crlsIllisibles} CRL du jeton illisible(s)`);
    poser("T-1", reussi());
  } catch (err) {
    const detail = err instanceof ErreurDer ? err.message : `jeton inexploitable : ${err.message}`;
    poser("T-1", echoue(detail));
    for (const id of VERIFICATIONS_ACQUISITION.slice(1)) poser(id, nonExecute("prerequis_en_echec"));
    return r;
  }
  const tst = jeton.tstInfo;
  const si = jeton.signerInfo;
  r.tstInfo = resumerTstInfo(tst);

  // T-2 : empreinte.
  if (imprintAttendue === null || imprintAttendue === undefined) {
    poser("T-2", nonExecute("prerequis_en_echec", "aucune empreinte attendue"));
  } else {
    const attendue = imprintAttendue instanceof Uint8Array ? imprintAttendue : hexVersOctets(imprintAttendue);
    const alg = tst.hashAlgorithme;
    const algOk = alg.oid === OID.sha256 && (alg.parametres === null || (estUniversel(alg.parametres, ETIQUETTE.NULL, false) && alg.parametres.longueur === 0));
    if (!algOk) poser("T-2", echoue(`hashAlgorithm ${alg.oid} au lieu de SHA-256`));
    else if (tst.hashedMessage.length !== 32 || !octetsEgaux(tst.hashedMessage, attendue)) poser("T-2", echoue("hashedMessage différent de l'empreinte attendue"));
    else poser("T-2", reussi());
  }

  // T-3 : attributs signés.
  poser("T-3", verifierAttributsSignes(jeton));

  // T-4 : certificat signataire.
  const candidats = [...jeton.certificats];
  for (const A of autorites) candidats.push(A.certificat, ...A.intermediaires);
  const t4 = verifierSignataire(jeton, candidats, autorites.length > 0, avertir);
  poser("T-4", t4.statut);
  const S = t4.S;
  r.certificatSignataire = S;

  // T-9 : contenu de TSTInfo (règles 1, 2, 4, 5 ; règle 3 avec S).
  const t9 = verifierContenuTstInfo(tst, S, checks["T-4"] === "reussi" ? null : t4.statut, avertir);
  poser("T-9", t9);

  // T-8 : usage horodatage.
  if (checks["T-4"] !== "reussi") poser("T-8", heriter(t4.statut));
  else poser("T-8", verifierUsageHorodatage(S));

  // T-5 : algorithmes et clé.
  let algSignature = null;
  if (checks["T-4"] !== "reussi") {
    poser("T-5", heriter(t4.statut));
  } else {
    const t5 = verifierAlgorithmes({ jeton, S, candidats, autorites, instant: tst.genTime.ms });
    algSignature = t5.algorithme;
    poser("T-5", t5.statut);
  }

  // T-6 : signature.
  if (checks["T-5"] !== "reussi") {
    poser("T-6", heriter({ statut: checks["T-5"], raison: r.raisons["T-5"] }));
  } else {
    const donnees = new Uint8Array(si.signedAttrs.tlv);
    donnees[0] = 0x31; // [0] IMPLICIT → SET OF (EX-9.12)
    const ok = verifierSignatureBrute({ cle: S.clePublique, algorithme: algSignature, donnees, signature: si.signature });
    poser("T-6", ok ? reussi() : echoue("signature invalide sous la clé du certificat signataire"));
  }

  // T-7 : chemin à genTime.
  const prerequisT7 = [{ statut: checks["T-4"], raison: r.raisons["T-4"] }, { statut: checks["T-6"], raison: r.raisons["T-6"] }, { statut: checks["T-9"], raison: r.raisons["T-9"] }];
  if (prerequisT7.some((p) => p.statut !== "reussi")) {
    poser("T-7", heriter(...prerequisT7));
  } else if (autorites.length === 0) {
    poser("T-7", nonExecute("ancre_absente", "aucune autorité d'horodatage"));
  } else {
    const chemin = chercherChemin({ S, candidats, autorites, politique: tst.policy, instant: tst.genTime.ms });
    if (!chemin) poser("T-7", echoue(`aucun chemin de ${candidats.length} candidat(s) vers l'une des ${autorites.length} autorité(s) ne satisfait les sept règles d'EX-9.13 à genTime`));
    else {
      poser("T-7", reussi());
      r.chemin = chemin.chemin;
      r.autorite = chemin.autorite;
      r.identite = chemin.identite;
    }
  }

  r.faits = construireFaits({ jeton, S, autorite: r.autorite, algSignature, reussie: checks["T-7"] === "reussi" });
  return r;
}

/** Résumé exploitable du `TSTInfo` (instants en millisecondes, nonce en `bigint`). */
function resumerTstInfo(tst) {
  const accuracyUs = accuracyMicrosecondes(tst.accuracy);
  const genTimeUs = tst.genTime.ms === null ? null : tst.genTime.ms * 1000 + fractionMicros(tst.genTime.fraction);
  return {
    genTime: tst.genTime.ms,
    genTimeTexte: genTimeVersRfc3339(tst.genTime.texte),
    genTimeBrut: tst.genTime.texte,
    accuracy: tst.accuracy ? { seconds: nombreBorne(tst.accuracy.seconds), millis: nombreBorne(tst.accuracy.millis), micros: nombreBorne(tst.accuracy.micros) } : null,
    accuracyMs: accuracyUs === null ? null : accuracyUs / 1000,
    accuracyUs,
    upperBound: genTimeUs === null ? null : microsecondesVersRfc3339(genTimeUs + (accuracyUs ?? 0)),
    upperBoundMs: genTimeUs === null ? null : Math.ceil((genTimeUs + (accuracyUs ?? 0)) / 1000),
    serialNumber: tst.serialNumberHex,
    policy: tst.policy,
    nonce: tst.nonce,
    nonceHex: tst.nonce === null ? null : "0x" + (tst.nonce < 0n ? "-" : "") + (tst.nonce < 0n ? -tst.nonce : tst.nonce).toString(16),
    ordering: tst.ordering,
    tsa: tst.tsa ? { type: tst.tsa.type, nom: tst.tsa.nom ? octetsVersHex(tst.tsa.nom.octets) : null, cn: tst.tsa.nom?.cn ?? null } : null,
    tsuSubject: null,
  };
}

/** Microsecondes d'une fraction de seconde (chaîne de chiffres). */
function fractionMicros(fraction) {
  if (!fraction) return 0;
  return Math.floor(Number(`0.${fraction}`) * 1e6);
}

function nombreBorne(v) {
  if (v === null || v === undefined) return null;
  return v > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(v);
}

/** T-3 (EX-9.9). */
function verifierAttributsSignes(jeton) {
  const si = jeton.signerInfo;
  const vus = new Set();
  for (const a of si.signedAttrs.attributs) {
    if (vus.has(a.oid)) return echoue(`attribut ${a.oid} en double`);
    vus.add(a.oid);
    if (a.valeurs.length !== 1) return echoue(`attribut ${a.oid} avec ${a.valeurs.length} valeur(s)`);
  }
  const ct = si.signedAttrs.attributs.find((a) => a.oid === OID.contentType);
  if (!ct) return echoue("content-type absent");
  try {
    if (lireOid(ct.valeurs[0]) !== OID.tstInfo) return echoue("content-type différent de id-ct-TSTInfo");
  } catch (err) {
    return echoue(`content-type illisible : ${err.message}`);
  }
  const md = si.signedAttrs.attributs.find((a) => a.oid === OID.messageDigest);
  if (!md) return echoue("message-digest absent");
  const h = HACHAGES[si.digestAlgorithme.oid];
  if (!h) return echoue(`digestAlgorithm ${si.digestAlgorithme.oid} : empreinte non calculable`);
  let valeur;
  try {
    valeur = lireOctets(md.valeurs[0]);
  } catch (err) {
    return echoue(`message-digest illisible : ${err.message}`);
  }
  if (!octetsEgaux(valeur, hacher(si.digestAlgorithme.oid, jeton.eContent))) return echoue("message-digest différent de l'empreinte d'eContent");
  if (!si.signedAttrs.attributs.some((a) => a.oid === OID.signingCertificate || a.oid === OID.signingCertificateV2)) return echoue("ni signingCertificate ni signingCertificateV2");
  return reussi();
}

/** T-4 (EX-9.10) : `{ statut, S }`. */
function verifierSignataire(jeton, candidats, aAutorites, avertir) {
  const sid = jeton.signerInfo.sid;
  const designes = [];
  for (const c of candidats) {
    let d = false;
    if (sid.type === "issuerAndSerialNumber") d = octetsEgaux(sid.emetteur.octets, c.emetteur.octets) && octetsEgaux(sid.numeroSerie, c.numeroSerie);
    else d = c.identifiantCle !== null && octetsEgaux(sid.valeur, c.identifiantCle);
    if (d && !designes.some((x) => octetsEgaux(x.octets, c.octets))) designes.push(c);
  }
  const sidTexte = sid.type === "issuerAndSerialNumber" ? `issuerAndSerialNumber (émetteur ${octetsVersHex(sid.emetteur.octets).slice(0, 18)}…, numéro ${octetsVersHex(sid.numeroSerie)})` : `subjectKeyIdentifier ${octetsVersHex(sid.valeur)}`;
  if (designes.length === 0) {
    const detail = `aucun des ${candidats.length} candidat(s) (${jeton.certificats.length} du jeton, ${candidats.length - jeton.certificats.length} des ancres) n'est désigné par le sid ${sidTexte} ; le réviseur peut ajouter le certificat de l'unité à ses intermediates`;
    if (aAutorites) return { statut: echoue(detail), S: null };
    if (jeton.certificatsPresents) return { statut: echoue(`${detail} ; le jeton porte des certificats sans celui de l'unité (RFC 3161 §2.4.1)`), S: null };
    return { statut: nonExecute("ancre_absente", "jeton sans certificats et aucune autorité d'horodatage"), S: null };
  }
  if (designes.length > 1) return { statut: echoue(`${designes.length} candidats distincts désignés par le sid`), S: null };
  const S = designes[0];
  const attributs = jeton.signerInfo.signedAttrs.attributs;
  try {
    const v1 = attributs.find((a) => a.oid === OID.signingCertificate);
    if (v1) {
      const id = lireEssCertId(v1.valeurs[0]);
      if (!octetsEgaux(id.certHash, hacher(OID.sha1, S.octets))) return { statut: echoue("certHash de signingCertificate différent du SHA-1 du certificat signataire"), S };
      const is = controlerIssuerSerial(id.issuerSerial, S);
      if (is) return { statut: echoue(is), S };
    }
    const v2 = attributs.find((a) => a.oid === OID.signingCertificateV2);
    if (v2) {
      const id = lireEssCertIdV2(v2.valeurs[0]);
      if (id.hachageEncode && id.hachage === OID.sha256) avertir("AV-T-1", "hashAlgorithm encodé à SHA-256 dans le premier ESSCertIDv2 (valeur DEFAULT, EX-9.21)");
      if (!HACHAGES[id.hachage]) return { statut: echoue(`hashAlgorithm ${id.hachage} de l'ESSCertIDv2 inconnu`), S };
      if (!octetsEgaux(id.certHash, hacher(id.hachage, S.octets))) return { statut: echoue("certHash de signingCertificateV2 différent de l'empreinte du certificat signataire"), S };
      const is = controlerIssuerSerial(id.issuerSerial, S);
      if (is) return { statut: echoue(is), S };
    }
  } catch (err) {
    return { statut: echoue(`identifiant de certificat illisible : ${err.message}`), S };
  }
  return { statut: reussi(), S };
}

/** Règle 3 de T-4 : `issuerSerial`, s'il est présent, désigne l'émetteur et le numéro de S. Rend un détail d'échec ou `null`. */
function controlerIssuerSerial(issuerSerial, S) {
  if (!issuerSerial) return null;
  if (!issuerSerial.directoryName || !octetsEgaux(issuerSerial.directoryName.octets, S.emetteur.octets)) return "issuerSerial : émetteur différent de celui du certificat signataire";
  if (!octetsEgaux(issuerSerial.numeroSerie, S.numeroSerie)) return "issuerSerial : numéro différent de celui du certificat signataire";
  return null;
}

/** T-5 (EX-9.11, EX-9.23, EX-9.24) : `{ statut, algorithme }`. */
function verifierAlgorithmes({ jeton, S, candidats, autorites, instant }) {
  const si = jeton.signerInfo;
  if (!hachageAdmis(si.digestAlgorithme)) return { statut: echoue(`digestAlgorithm ${nomHachage(si.digestAlgorithme.oid)} refusé`), algorithme: null };
  const alg = analyserAlgorithmeSignature(si.signatureAlgorithme, si.digestAlgorithme.oid);
  const cle = S.clePublique;
  if (cle.admise) {
    if (alg.admis && alg.typeCle === cle.type) return { statut: reussi(), algorithme: alg };
    const motif = alg.admis ? `algorithme ${alg.nom} pour une clé ${cle.type}` : `${alg.nom} : ${alg.motif}`;
    return { statut: echoue(`clé admise et algorithme non admis pour elle (EX-9.24, cas 1) : ${motif}`), algorithme: alg };
  }
  if (cle.type === "rsa") return { statut: echoue(cle.motif), algorithme: alg };
  if (alg.admis) return { statut: echoue(`algorithme admis ${alg.nom} sous une clé non admise (${cle.motif} ; EX-9.24, cas 1)`), algorithme: alg };
  // Cas 2 et 3 : clé d'un type hors de la version 0, algorithme non admis.
  if (autorites.length === 0) return { statut: nonExecute("ancre_absente", `${cle.motif} ; aucune autorité d'horodatage (EX-9.24, cas 3)`), algorithme: alg };
  const rattachement = chercherChemin({ S, candidats, autorites, politique: jeton.tstInfo.policy, instant });
  if (!rattachement) return { statut: echoue(`${cle.motif}, algorithme ${alg.nom} : aucun rattachement du certificat de l'unité à une autorité (EX-9.24, cas 2)`), algorithme: alg };
  return {
    statut: nonExecute("hors_perimetre_version", `clé ${cle.algorithme.oid} et algorithme ${alg.oid} hors de la version 0 : signature du jeton non vérifiée ; certificat de l'unité rattaché à l'autorité ${rattachement.autorite.nom} ; aucune date n'est établie`),
    algorithme: alg,
  };
}

/** T-8 (EX-9.14). */
function verifierUsageHorodatage(S) {
  const eku = S.usagesEtendus;
  if (!eku) return echoue("extKeyUsage absent");
  if (!eku.critique) return echoue("extKeyUsage non critique");
  if (eku.oids.length !== 1 || eku.oids[0] !== OID.timeStamping) return echoue("extKeyUsage autre que la seule valeur id-kp-timeStamping");
  const ku = S.usagesCle;
  if (ku) {
    const ds = ku.a(0);
    const nr = ku.a(1);
    if (!ds && !nr) return echoue("keyUsage sans digitalSignature ni nonRepudiation");
    for (let i = 2; i < 9; i++) if (ku.a(i)) return echoue("keyUsage avec un usage autre que digitalSignature et nonRepudiation");
  }
  if (S.contraintesBase && S.contraintesBase.ca) return echoue("basicConstraints cA vrai sur le certificat signataire");
  return reussi();
}

const MAX_US = Date.UTC(9999, 11, 31, 23, 59, 59, 999) * 1000 + 999;

/** T-9 (EX-9.15). `statutT4` est nul quand T-4 a réussi, sinon le statut à hériter pour la règle 3. */
function verifierContenuTstInfo(tst, S, statutT4, avertir) {
  if (tst.genTime.ms === null) return echoue(`genTime ${JSON.stringify(tst.genTime.texte)} n'est pas un GeneralizedTime AAAAMMJJhhmmss[.f]Z d'une date existante`);
  if (tst.accuracy) {
    const { seconds, millis, micros } = tst.accuracy;
    if (seconds !== null && (seconds < 0n || seconds > 86400n)) return echoue("accuracy.seconds hors de 0 à 86 400");
    if (millis !== null && (millis < 1n || millis > 999n)) return echoue("accuracy.millis hors de 1 à 999");
    if (micros !== null && (micros < 1n || micros > 999n)) return echoue("accuracy.micros hors de 1 à 999");
  }
  const genTimeUs = tst.genTime.ms * 1000 + fractionMicros(tst.genTime.fraction);
  if (genTimeUs + (accuracyMicrosecondes(tst.accuracy) ?? 0) > MAX_US) return echoue("genTime + accuracy au-delà de 9999-12-31T23:59:59.999999Z");
  if (tst.extensions.some((x) => x.critique)) return echoue("extension critique dans TSTInfo");
  try {
    controlerQcStatements(tst);
  } catch (err) {
    return echoue(`qcStatements mal formée : ${err.message}`);
  }
  if (tst.tsa) {
    if (tst.tsa.type !== "directoryName") {
      avertir("AV-T-2", `tsa de forme ${tst.tsa.type}, non comparé`);
    } else if (statutT4 !== null) {
      return heriter(statutT4);
    } else if (!octetsEgaux(tst.tsa.nom.octets, S.sujet.octets)) {
      return echoue("tsa différent du sujet du certificat signataire");
    }
  }
  return reussi();
}

/** Faits d'EX-9.19 pour le contrôle 4 (ceux qui ne dépendent pas de T-10, T-11). */
function construireFaits({ jeton, S, autorite, algSignature, reussie }) {
  const tst = jeton.tstInfo;
  const resume = resumerTstInfo(tst);
  return {
    authority: autorite ? autorite.nom : null,
    tsu_certificate_sha256: S ? S.sha256 : null,
    tsu_subject_cn: S ? S.sujet.cn : null,
    gen_time: resume.genTimeTexte,
    accuracy: resume.accuracy,
    upper_bound: resume.upperBound,
    policy: tst.policy,
    serial_number: tst.serialNumberHex,
    digest_algorithm: nomHachage(jeton.signerInfo.digestAlgorithme.oid),
    signature_algorithm: algSignature ? algSignature.nom : (jeton.signerInfo.signatureAlgorithme.oid),
    key_bits: S ? S.clePublique.bits : null,
    qualified_claim: pretentionQualifiee(jeton, S),
    chemin_complet: reussie,
  };
}

export { lireNull, lireEntier, lireUnique };
