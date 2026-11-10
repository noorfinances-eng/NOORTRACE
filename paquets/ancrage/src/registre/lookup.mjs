// Lectures d'état par `eth_call` (CT-4 OP-9, §8.3 ; CT-5 EX-9.7) : `lookup`,
// `isAnchored`, `anchorDigest` d'`AttestationRegistry` ; `recorderOf`,
// `recorderByPubKey`, `isActiveRecorder` de `RecorderRegistry` ; `isKnown`,
// `latestPeriodOf`, `getPeriod` de `PeriodRegistry`. Ces lectures ne sont
// pas des preuves (CT-6 §11.1) : elles évitent une transaction qui
// échouerait, et classent une empreinte déjà prise (`deja_fait`,
// `empreinte_squattee`).

import {
  decoderBool, decoderBytes32, decoderGetPeriod, decoderLookup, decoderRecorder, decoderUint,
  encoderAnchorDigest, encoderGetPeriod, encoderIsActiveRecorder, encoderIsAnchored, encoderIsKnown, encoderLatestPeriodOf,
  encoderLookup, encoderPeriodDigest, encoderRecorderByPubKey, encoderRecorderOf,
} from "./encodage.mjs";
import { octetsVersHex } from "./octets.mjs";
import { ErreurRpc } from "./rpc.mjs";

/** Erreur d'une lecture d'état : nœud injoignable ou retour illisible. */
export class ErreurLecture extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ErreurLecture";
    this.code = code;
  }
}

/**
 * `eth_call` d'une donnée vers un contrat, à `latest` par défaut ; rend
 * l'hexadécimal du retour. Lève `ErreurLecture("noeud_injoignable")` si
 * aucun point ne répond, `ErreurLecture("appel_refuse")` sur une erreur
 * JSON-RPC (revert).
 */
export async function appelLecture(rpc, contrat, donnees, { hauteur = "latest", point } = {}) {
  const params = [{ to: contrat, data: octetsVersHex(donnees) }, hauteur];
  let reponse;
  try {
    reponse = point ? await rpc.appeler("eth_call", params, { point }) : await rpc.appelerPremier("eth_call", params);
  } catch (e) {
    if (e instanceof ErreurRpc) throw new ErreurLecture("noeud_injoignable", e.message);
    throw e;
  }
  if (reponse.erreur) throw new ErreurLecture("appel_refuse", reponse.erreur.message);
  if (typeof reponse.resultat !== "string" || !/^0x([0-9a-f]{2})*$/.test(reponse.resultat)) throw new ErreurLecture("retour_illisible", "retour d'eth_call illisible");
  return reponse.resultat;
}

function decoder(decodeur, hex, nom) {
  const v = decodeur(hex);
  if (v === null) throw new ErreurLecture("retour_illisible", `retour de ${nom} illisible`);
  return v;
}

/** `AttestationRegistry.lookup(fingerprint)` → `{ issuer, docType, issuedAt, revokedAt, anchored }`. */
export async function lookup({ rpc, contrat, fingerprint, hauteur, point }) {
  const r = decoder(decoderLookup, await appelLecture(rpc, contrat, encoderLookup(fingerprint), { hauteur, point }), "lookup");
  return { ...r, anchored: r.issuedAt !== 0n || r.issuer !== "0x" + "00".repeat(20) };
}

/** `AttestationRegistry.isAnchored(fingerprint)`. */
export async function isAnchored({ rpc, contrat, fingerprint, hauteur, point }) {
  return decoder(decoderBool, await appelLecture(rpc, contrat, encoderIsAnchored(fingerprint), { hauteur, point }), "isAnchored");
}

/** `AttestationRegistry.anchorDigest(fingerprint, docType)` rendu par le contrat (EX-6.1, OP-6). */
export async function anchorDigestContrat({ rpc, contrat, fingerprint, docType, hauteur, point }) {
  return decoder(decoderBytes32, await appelLecture(rpc, contrat, encoderAnchorDigest(fingerprint, docType), { hauteur, point }), "anchorDigest");
}

/** `PeriodRegistry.periodDigest(meta)` rendu par le contrat. */
export async function periodDigestContrat({ rpc, contrat, meta, hauteur, point }) {
  return decoder(decoderBytes32, await appelLecture(rpc, contrat, encoderPeriodDigest(meta), { hauteur, point }), "periodDigest");
}

/** `RecorderRegistry.recorderOf(orgId, chainKey)`. */
export async function recorderOf({ rpc, contrat, orgId, chainKey, hauteur, point }) {
  return decoder(decoderRecorder, await appelLecture(rpc, contrat, encoderRecorderOf(orgId, chainKey), { hauteur, point }), "recorderOf");
}

/** `RecorderRegistry.recorderByPubKey(orgId, ed25519PubKey)`. */
export async function recorderByPubKey({ rpc, contrat, orgId, clePublique, hauteur, point }) {
  return decoder(decoderRecorder, await appelLecture(rpc, contrat, encoderRecorderByPubKey(orgId, clePublique), { hauteur, point }), "recorderByPubKey");
}

/** `RecorderRegistry.isActiveRecorder(orgId, chainKey)`. */
export async function isActiveRecorder({ rpc, contrat, orgId, chainKey, hauteur, point }) {
  return decoder(decoderBool, await appelLecture(rpc, contrat, encoderIsActiveRecorder(orgId, chainKey), { hauteur, point }), "isActiveRecorder");
}

/** `PeriodRegistry.isKnown(orgId, periodHash)`. */
export async function isKnown({ rpc, contrat, orgId, periodHash, hauteur, point }) {
  return decoder(decoderBool, await appelLecture(rpc, contrat, encoderIsKnown(orgId, periodHash), { hauteur, point }), "isKnown");
}

/** `PeriodRegistry.latestPeriodOf(orgId, journalId)` : identifiant, 0 sans période. */
export async function latestPeriodOf({ rpc, contrat, orgId, journalId, hauteur, point }) {
  return decoder(decoderUint, await appelLecture(rpc, contrat, encoderLatestPeriodOf(orgId, journalId), { hauteur, point }), "latestPeriodOf");
}

/** `PeriodRegistry.getPeriod(id)`. */
export async function getPeriod({ rpc, contrat, id, hauteur, point }) {
  return decoder(decoderGetPeriod, await appelLecture(rpc, contrat, encoderGetPeriod(id), { hauteur, point }), "getPeriod");
}

/**
 * Classe une empreinte avant un `anchor` (OP-9, CT-4 §8.3, CT-5 EX-9.7) :
 * `libre` si elle n'est pas ancrée ; `deja_fait` si `lookup` rend
 * l'émetteur attendu et le `docType` attendu ; `empreinte_squattee` dans tout
 * autre cas. Rend `{ etat, lookup }`.
 */
export async function classerEmpreinte({ rpc, contrat, fingerprint, emetteur, docType, hauteur, point }) {
  const prise = await isAnchored({ rpc, contrat, fingerprint, hauteur, point });
  if (!prise) return { etat: "libre", lookup: null };
  const l = await lookup({ rpc, contrat, fingerprint, hauteur, point });
  if (l.issuer === emetteur && l.docType === docType) return { etat: "deja_fait", lookup: l };
  return { etat: "empreinte_squattee", lookup: l };
}
