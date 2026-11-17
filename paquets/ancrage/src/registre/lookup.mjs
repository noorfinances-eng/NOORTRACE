// Lectures d'état par `eth_call` (CT-4 OP-9, §8.3 ; CT-5 EX-9.7) : `lookup`,
// `isAnchored`, `anchorDigest` d'`AttestationRegistry` ; `recorderOf`,
// `recorderByPubKey`, `isActiveRecorder` de `RecorderRegistry` ; `isKnown`,
// `latestPeriodOf`, `getPeriod` de `PeriodRegistry` ; et une lecture de
// journaux, `inscriptionAilleurs` (OP-8, événements `RecorderRegistered`).
// Ces lectures ne sont pas des preuves (CT-6 §11.1) : elles évitent une
// transaction qui échouerait, et classent une empreinte déjà prise
// (`deja_fait`, `empreinte_squattee`).

import {
  decoderBool, decoderBytes32, decoderGetPeriod, decoderLookup, decoderRecorder, decoderUint,
  encoderAnchorDigest, encoderGetPeriod, encoderIsActiveRecorder, encoderIsAnchored, encoderIsKnown, encoderLatestPeriodOf,
  encoderLookup, encoderPeriodDigest, encoderRecorderByPubKey, encoderRecorderOf, SUJETS,
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

/** Plus grande tranche de blocs d'un `eth_getLogs` (CT-4 EX-5.11, borne du nœud). */
export const TRANCHE_JOURNAUX = 16384n;

/** Refus pour débit d'un nœud (noorcore : erreur `-32000`, message `rate limited`). */
const REFUS_DEBIT = /\brate limited\b/i;
/** Première pause après un refus pour débit, doublée à chaque refus (CT-3 EX-8.1, même règle). */
export const PAUSE_DEBIT_MS = 250;
/** Plafond d'une pause après un refus pour débit. */
export const PAUSE_DEBIT_MAX_MS = 4000;
/** Somme des pauses admises pour une même tranche ; au-delà, la lecture est impossible. */
export const ATTENTE_DEBIT_MAX_MS = 30000;
const pause = (ms) => new Promise((ok) => setTimeout(ok, ms));

/**
 * CT-4 OP-8 (complément du 2026-11-16 ; CT-5 EX-9.4 ; EX-8.22) : première
 * inscription de la clé de chaîne `chainKey` sous une autre organisation que
 * `orgId` au `RecorderRegistry` `contrat`, active ou révoquée, ou `null`.
 * Même lecture que l'outil de référence : `eth_getLogs` des événements
 * `RecorderRegistered` dont le deuxième sujet indexé (`topics[2]`) est cette
 * clé de chaîne, du bloc `depuis` (bloc de déploiement du contrat, 0 à
 * défaut) à la tête, en tranches de 16 384 blocs, sur le premier point qui
 * répond à `eth_blockNumber` (la tête et les journaux sont lus sur le même
 * nœud). Rend `{ org_id, block_number, transaction_hash }`. Une lecture
 * impossible (point injoignable, erreur JSON-RPC, retour illisible) lève
 * `ErreurLecture("noeud_injoignable")` : la vérification n'est jamais sautée.
 *
 * Refus pour débit : noorcore refuse un `eth_getLogs` par l'erreur `-32000`,
 * message `rate limited`, quand on lui en enchaîne une dizaine d'affilée,
 * ce que fait la lecture en tranches dès que le contrat est ancien (relevé
 * sur le réseau de développement 2124, comme CT-3 EX-8.1). Ce refus ne dit
 * rien des journaux : la tranche est redemandée, aux mêmes paramètres, après
 * une pause de `PAUSE_DEBIT_MS` doublée à chaque refus et plafonnée à
 * `PAUSE_DEBIT_MAX_MS`, tant que les pauses de la tranche ne dépassent pas
 * `ATTENTE_DEBIT_MAX_MS` ; au-delà, `noeud_injoignable`. `attendre` (pause en
 * millisecondes) est remplaçable par les essais.
 */
export async function inscriptionAilleurs({ rpc, contrat, depuis = 0, orgId, chainKey, attendre = pause }) {
  const adresse = String(contrat).toLowerCase();
  const sujet = "0x" + "00".repeat(12) + String(chainKey).slice(2).toLowerCase();
  const organisation = String(orgId).toLowerCase();
  const echec = (detail) => new ErreurLecture("noeud_injoignable", `eth_getLogs de RecorderRegistered : ${detail} ; l'inscription de ${chainKey} sous une autre organisation n'a pas pu être vérifiée (OP-8)`);
  let point;
  let tete;
  try {
    const r = await rpc.appelerPremier("eth_blockNumber", []);
    if (r.erreur || typeof r.resultat !== "string" || !/^0x[0-9a-f]+$/i.test(r.resultat)) throw echec(r.erreur?.message ?? "eth_blockNumber illisible");
    point = r.point;
    tete = BigInt(r.resultat);
    let de = BigInt(depuis ?? 0);
    if (de < 0n) de = 0n;
    for (; de <= tete; de += TRANCHE_JOURNAUX) {
      const a = de + TRANCHE_JOURNAUX - 1n < tete ? de + TRANCHE_JOURNAUX - 1n : tete;
      const q = (x) => "0x" + x.toString(16);
      const params = [{ fromBlock: q(de), toBlock: q(a), address: adresse, topics: [SUJETS.RecorderRegistered, null, sujet] }];
      let j = await rpc.appeler("eth_getLogs", params, { point });
      for (let p = PAUSE_DEBIT_MS, cumul = 0; j.erreur && REFUS_DEBIT.test(String(j.erreur.message)) && cumul + p <= ATTENTE_DEBIT_MAX_MS; cumul += p, p = Math.min(2 * p, PAUSE_DEBIT_MAX_MS)) {
        await attendre(p);
        j = await rpc.appeler("eth_getLogs", params, { point });
      }
      if (j.erreur) throw echec(j.erreur.message ?? "erreur JSON-RPC");
      if (!Array.isArray(j.resultat)) throw echec("retour illisible");
      for (const l of j.resultat) {
        const t = Array.isArray(l?.topics) ? l.topics.map((x) => String(x).toLowerCase()) : [];
        if (String(l?.address).toLowerCase() !== adresse || t.length < 4 || t[0] !== SUJETS.RecorderRegistered || t[2] !== sujet) continue;
        if (t[1] !== organisation) return { org_id: t[1], block_number: Number(BigInt(l.blockNumber)), transaction_hash: String(l.transactionHash).toLowerCase() };
      }
    }
  } catch (e) {
    if (e instanceof ErreurLecture) throw e;
    if (e instanceof ErreurRpc) throw echec(e.message);
    throw e;
  }
  return null;
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
 * autre cas. Rend `{ etat, lookup, lectures }`.
 *
 * Revue de sécurité de l'étape 8 (CT-5 EX-9.7 ; cause S-4) : une lecture n'est pas une
 * preuve (CT-6 §11.1). Quand plusieurs points sont configurés et qu'aucun
 * `point` n'est imposé, `lookup` est lu sur les deux premiers points qui
 * répondent ; une lecture que le second point contredit, ou un second point
 * injoignable, rend `indeterminee` (l'appelant classe l'échec transitoire,
 * jamais un refus définitif). `CONFIRMATION_SQUAT` à faux rétablit la lecture
 * au premier point qui répond (remplacement ciblé si le porteur renverse la décision).
 */
export const CONFIRMATION_SQUAT = true;

export async function classerEmpreinte({ rpc, contrat, fingerprint, emetteur, docType, hauteur, point }) {
  const points = typeof rpc.points === "function" ? rpc.points() : [];
  const recouper = CONFIRMATION_SQUAT && point === undefined && points.length >= 2;
  if (!recouper) {
    const prise = await isAnchored({ rpc, contrat, fingerprint, hauteur, point });
    if (!prise) return { etat: "libre", lookup: null, lectures: 1 };
    const l = await lookup({ rpc, contrat, fingerprint, hauteur, point });
    if (l.issuer === emetteur && l.docType === docType) return { etat: "deja_fait", lookup: l, lectures: 1 };
    return { etat: "empreinte_squattee", lookup: l, lectures: 1 };
  }
  const lectures = [];
  let derniereErreur = null;
  for (const p of points) {
    try {
      lectures.push({ point: p, lookup: await lookup({ rpc, contrat, fingerprint, hauteur, point: p }) });
    } catch (e) {
      if (!(e instanceof ErreurLecture)) throw e;
      derniereErreur = e;
    }
    if (lectures.length === 2) break;
  }
  if (lectures.length === 0) throw derniereErreur ?? new ErreurLecture("noeud_injoignable", "aucun point ne répond à lookup");
  const [a, b] = lectures;
  if (!b) return { etat: "indeterminee", lookup: a.lookup, lectures: 1, detail: "un seul point répond : lecture non recoupée" };
  const meme = a.lookup.anchored === b.lookup.anchored && a.lookup.issuer === b.lookup.issuer && a.lookup.docType === b.lookup.docType;
  if (!meme) return { etat: "indeterminee", lookup: a.lookup, lectures: 2, detail: `lookup différent sur ${a.point} et ${b.point}` };
  const l = a.lookup;
  if (!l.anchored) return { etat: "libre", lookup: null, lectures: 2 };
  if (l.issuer === emetteur && l.docType === docType) return { etat: "deja_fait", lookup: l, lectures: 2 };
  return { etat: "empreinte_squattee", lookup: l, lectures: 2 };
}
