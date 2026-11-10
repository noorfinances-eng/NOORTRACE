// Réponse du serveur interne : `TimeStampReq` (octets) → `TimeStampResp`
// (octets), RFC 3161 §2.4.2. Accordée (`granted`, PKIStatus 0) avec un
// `TimeStampToken` (RFC 5652 `SignedData` version 3, `eContent`
// `id-ct-TSTInfo`, attributs signés `content-type`, `message-digest` et
// `signingCertificateV2` à `ESSCertIDv2` SHA-256, signature
// `sha256WithRSAEncryption` ou `ecdsa-with-SHA256`, certificat de l'unité
// dans `certificates` quand `certReq` est vrai : AN-30), ou refusée
// (PKIStatus 2 `rejection`, `failInfo` nommé, `statusString` facultatif,
// aucun jeton) : `badAlg` (AN-23), `unacceptedPolicy` (AN-29),
// `unacceptedExtension`, `badRequest`, `badDataFormat`, `timeNotAvailable`
// quand l'écart mesuré de l'horloge dépasse la précision déclarée (AN-24),
// `systemFailure` quand l'unité ne peut pas signer. L'horloge est injectée
// (`horloge.murale()`, `horloge.ecartMs`) : rien n'est lu de la machine.

import { sequence, ensembleDe, entier, oid, chaineOctets, bitsNommes, utf8, explicite, implicite, identifiantAlgorithme, tlv, ETIQUETTE } from "./der-ecriture.mjs";
import { lireRequete, RefusRequete } from "./requete.mjs";
import { construireTstInfo } from "./tstinfo.mjs";
import { sha256 } from "./autorite.mjs";
import { OID, ECHEC, STATUT } from "./oids.mjs";

/** Retire les signes diacritiques (NFD puis suppression des marques combinantes). */
export function sansAccents(texte) {
  return texte.normalize("NFD").replace(/[̀-ͯ]/g, "");
}

/**
 * `TimeStampResp` de refus : `PKIStatusInfo { status, statusString?, failInfo }`, sans jeton.
 * @param {keyof typeof ECHEC} echec nom du bit de `PKIFailureInfo`
 * @param {string|null} [message] texte libre (`PKIFreeText`), jamais un secret ni une pièce
 * @param {number} [statut] `PKIStatus`, 2 par défaut
 */
export function reponseRejet(echec, message = null, statut = STATUT.rejection) {
  const bit = ECHEC[echec];
  if (bit === undefined) throw new RangeError(`PKIFailureInfo inconnu : ${echec}`);
  if (!Number.isInteger(statut) || statut < 2 || statut > 5) throw new RangeError("PKIStatus de refus : 2 à 5 attendu");
  const parties = [entier(statut)];
  // Le texte libre part sur le réseau sans accent, lisible tel quel par `openssl ts -reply -text`.
  if (typeof message === "string" && message.length > 0) parties.push(sequence(utf8(sansAccents(message).slice(0, 200))));
  parties.push(bitsNommes([bit]));
  return sequence(sequence(...parties));
}

/**
 * `TimeStampToken` (ContentInfo id-signedData) d'un `TSTInfo` signé par l'autorité.
 * @param {import("./autorite.mjs").Autorite} autorite
 * @param {Uint8Array} tstInfo DER
 * @param {boolean} certReq inclure les certificats (RFC 3161 §2.4.1)
 */
export function construireJeton(autorite, tstInfo, certReq) {
  const cert = autorite.certificat;
  const sha256Alg = identifiantAlgorithme(OID.sha256);
  const encap = sequence(oid(OID.tstInfo), explicite(0, chaineOctets(tstInfo)));

  // ESSCertIDv2 : hashAlgorithm absent (DEFAULT SHA-256, X.690 §11.5), certHash, issuerSerial.
  const essCertIdV2 = sequence(chaineOctets(autorite.certHash), sequence(sequence(explicite(4, cert.emetteur)), cert.serie));
  const attributs = ensembleDe(
    sequence(oid(OID.contentType), ensembleDe(oid(OID.tstInfo))),
    sequence(oid(OID.messageDigest), ensembleDe(chaineOctets(sha256(tstInfo)))),
    sequence(oid(OID.signingCertificateV2), ensembleDe(sequence(sequence(essCertIdV2)))),
  );
  // La signature porte sur l'encodage SET OF (étiquette 31) ; le SignerInfo porte [0] IMPLICIT (RFC 5652 §5.4).
  const signature = autorite.signer(attributs);
  const signerInfo = sequence(
    entier(1),
    sequence(cert.emetteur, cert.serie),
    sha256Alg,
    implicite(0, attributs),
    autorite.cle.signatureAlgorithme,
    chaineOctets(signature),
  );
  const parties = [entier(3), ensembleDe(sha256Alg), encap];
  if (certReq) parties.push(implicite(0, ensembleDe(cert.der, ...autorite.chaine.map((c) => c.der))));
  parties.push(ensembleDe(signerInfo));
  return sequence(oid(OID.signedData), explicite(0, sequence(...parties)));
}

/** Écart mesuré de l'horloge (ms), ou NaN s'il n'est pas un nombre fini. */
function ecartMesure(horloge) {
  const e = typeof horloge.ecartMs === "function" ? horloge.ecartMs() : horloge.ecartMs;
  if (e === undefined || e === null) return 0;
  return typeof e === "number" && Number.isFinite(e) ? e : NaN;
}

function iso(ms) {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * Répond à une requête.
 * @param {{requete: Uint8Array, autorite: import("./autorite.mjs").Autorite, horloge: {murale: () => number, ecartMs?: number|(() => number)}}} o
 * @returns {{octets: Uint8Array, statut: "granted"|"rejection", serial: bigint|null, echec: string|null, raison: string|null,
 *   jeton: Uint8Array|null, tstInfo: Uint8Array|null, genTime: string|null, requete: object|null}}
 */
export function repondre(o) {
  if (!o || !(o.requete instanceof Uint8Array)) throw new TypeError("repondre : requete (Uint8Array) attendue");
  if (!o.autorite || typeof o.autorite.signer !== "function") throw new TypeError("repondre : autorite attendue");
  if (!o.horloge || typeof o.horloge.murale !== "function") throw new TypeError("repondre : horloge.murale() attendue (règle 2 d'INTERFACES.md)");
  const { autorite, horloge } = o;
  const refus = (echec, raison, requete = null) => ({ octets: reponseRejet(echec, raison), statut: "rejection", serial: null, echec, raison, jeton: null, tstInfo: null, genTime: null, requete });

  let requete;
  try {
    requete = lireRequete(o.requete);
  } catch (e) {
    if (e instanceof RefusRequete) return refus(e.echec, e.message);
    throw e;
  }
  if (requete.reqPolicy !== null && requete.reqPolicy !== autorite.politique) {
    return refus("unacceptedPolicy", `politique ${requete.reqPolicy} non servie (AN-29)`, requete);
  }
  const ecart = ecartMesure(horloge);
  if (!Number.isFinite(ecart) || Math.abs(ecart) > autorite.precisionS * 1000) {
    return refus("timeNotAvailable", `écart d'horloge ${Number.isFinite(ecart) ? `${ecart} ms` : "inconnu"} au-delà de la précision déclarée (AN-24)`, requete);
  }
  const maintenant = horloge.murale();
  if (typeof maintenant !== "number" || !Number.isFinite(maintenant)) return refus("timeNotAvailable", "horloge murale illisible (AN-24)", requete);
  const genTimeMs = Math.floor(maintenant / 1000) * 1000;
  if (!autorite.dansValidite(genTimeMs)) return refus("systemFailure", "certificat de l'unité hors de sa période de validité", requete);

  let serie;
  try {
    serie = autorite.serieSuivante();
  } catch (e) {
    return { ...refus("systemFailure", `compteur de série indisponible : ${e.message}`, requete), erreur: e };
  }
  const tstInfo = construireTstInfo({
    politique: autorite.politique,
    messageImprint: requete.messageImprint,
    serie,
    genTimeMs,
    precisionS: autorite.precisionS,
    nonce: requete.nonce,
    tsa: autorite.tsaDansJeton ? autorite.certificat.sujet : null,
  });
  let jeton;
  try {
    jeton = construireJeton(autorite, tstInfo, requete.certReq);
  } catch (e) {
    return { ...refus("systemFailure", `signature impossible : ${e.message}`, requete), erreur: e };
  }
  const octets = sequence(sequence(entier(STATUT.granted)), jeton);
  return { octets, statut: "granted", serial: serie, echec: null, raison: null, jeton, tstInfo, genTime: iso(genTimeMs), requete };
}

export { tlv, ETIQUETTE };
