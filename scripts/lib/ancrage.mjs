// Référence JavaScript du composant d'ancrage NOORTRACE (spec/CT-5-ancrage.md).
//
// Ce module ne touche jamais au réseau : il construit les requêtes RFC 3161
// (EX-5.1), les fichiers .ots (EX-6.4), calcule les comptages (EX-4.11) et le
// coût (section 12), vérifie l'admission d'un point et la table des échéances
// (AN-2, AN-3), et expose le planificateur de la section 8 comme une machine à
// états déterministe à horloge injectée (EX-8.13) : les réponses des
// prestataires, des calendriers et du registre lui arrivent en entrées
// ($defs/evenement_entree du schéma planificateur-ancrage-v0) et il rend des
// actions ($defs/action_attendue). `rejouerTrace` exécute une trace normative
// de CT-5 §8.10 et rend la liste d'actions et la file finale que les tests
// comparent à `expected` et `queue_after`.
//
// Les appels réseau (HTTP vers les prestataires et les calendriers, JSON-RPC
// vers le registre) relèvent d'un adaptateur distinct que les vecteurs
// n'exercent pas ; les nonces et gigues viennent de l'objet `aleatoire`
// injecté (dérivés d'étiquettes dans les vecteurs, annexe A.2).

import crypto from "node:crypto";
import * as J from "./journal.mjs";
import { DOC_TYPE_PERIODE, anchorFingerprint, journalIdOf } from "./noortrace.mjs";
import * as O from "./ots.mjs";
import { decoderPEM, evaluerJeton, lireCertificat, lireDER, lireGenTime, lireJeton, rfc3339 } from "./horodatage.mjs";

export class ErreurAncrage extends Error {
  constructor(message, regle = null) {
    super(message);
    this.regle = regle;
  }
}

// ---------------------------------------------------------------------------
// Constantes
// ---------------------------------------------------------------------------

/** Les six sortes de demandes (CT-5 §8.2). */
export const SORTES = ["ancre_registre_point", "jeton_point", "ots_point", "ancre_registre_periode", "jeton_periode", "ots_periode"];
/** États d'une demande (EX-8.3). */
export const ETATS = ["a_envoyer", "attente_registre", "envoyee", "a_reprendre", "en_attente", "obtenue", "complete", "sans_objet", "refusee", "remplacee"];
export const ETATS_FINAUX = new Set(["obtenue", "complete", "sans_objet", "refusee", "remplacee"]);
export const ROLES = ["principal", "secours", "second_rang", "interne"];
/** Politique de l'autorité de test de CT-6 (serveur interne des vecteurs, EX-7.4). */
export const POLITIQUE_TEST = "1.3.6.1.4.1.99999.1.1";
/** AlgorithmIdentifier sha256 avec paramètres NULL explicites (EX-5.1). */
export const ALGORITHME_SHA256_DER = Buffer.from("300d06096086480165030402010500", "hex");
/** Taille représentée d'un index de capture dans les traces (annexe A.2). */
export const TAILLE_INDEX_CAPTURE = 4096;
/** Calendriers des traces (annexe A.2). */
export const CALENDRIERS_VECTEURS = ["https://alice.btc.calendar.opentimestamps.org", "https://bob.btc.calendar.opentimestamps.org"];
const DUREE_PERIODE_MS = J.DUREE_PERIODE * 1000;
const NONCE_MAX = (1n << 64n) - 1n;
const RE_OID = /^[0-2](\.(0|[1-9][0-9]*))+$/;
const RE_INSTANT = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,3})?Z$/;

/** Valeurs par défaut de la projection de configuration (EX-8.2). */
export const DEFAUTS_CONFIGURATION = Object.freeze({
  checkpoint_interval_s: 60,
  manifest: { fallback_after_s: 300 },
  checkpoints: { interval_s: 300, provider_role: "principal", fallback_after_s: 120, countersign_idle: false },
  freshness: { max_response_delay_s: 60, clock_tolerance_s: 120 },
  retry: { initial_ms: 5000, factor: 2, max_ms: 300000, jitter_ms: 250 },
  registry: { checkpoints: "nouveaux_evenements", squat_wait_s: 5, inclusion_alert_s: 60 },
  opentimestamps: { enabled: true, min_responses: 2, timeout_ms: 5000, checkpoint: "aucun", upgrade: { first_after_s: 21600, interval_s: 1800, give_up_after_s: 1209600 } },
  queue: { max_pending: 100000, anchor_pending_alert_s: 7200 },
});

// ---------------------------------------------------------------------------
// Instants
// ---------------------------------------------------------------------------

/** Millisecondes UNIX d'un instant RFC 3339 UTC (avec ou sans fraction). */
export function ms(texte) {
  if (typeof texte !== "string" || !RE_INSTANT.test(texte)) throw new ErreurAncrage(`instant RFC 3339 UTC attendu, reçu ${JSON.stringify(texte)}`);
  const v = Date.parse(texte);
  if (Number.isNaN(v)) throw new ErreurAncrage(`instant invalide : ${texte}`);
  return v;
}
/** Instant RFC 3339 UTC à la milliseconde (format des horodatages CT-1). */
export const iso = (v) => new Date(v).toISOString();
const sha256Hex = (b) => "0x" + crypto.createHash("sha256").update(b).digest("hex");
const sha256 = (b) => crypto.createHash("sha256").update(b).digest();

// ---------------------------------------------------------------------------
// TimeStampReq DER (EX-5.1, AN-5, AN-6)
// ---------------------------------------------------------------------------

function longueurDER(n) {
  if (n < 0x80) return Buffer.from([n]);
  if (n < 0x100) return Buffer.from([0x81, n]);
  if (n < 0x10000) return Buffer.from([0x82, n >> 8, n & 0xff]);
  throw new ErreurAncrage(`longueur DER ${n} hors des bornes de ce module`);
}
const tlv = (etiquette, corps) => Buffer.concat([Buffer.from([etiquette]), longueurDER(corps.length), corps]);

/** INTEGER DER minimal d'un entier non négatif (octet 00 de tête seulement si le bit haut vaut 1). */
export function encoderEntierDER(valeur) {
  let v = BigInt(valeur);
  if (v < 0n) throw new ErreurAncrage("INTEGER DER : entier non négatif attendu");
  const octets = [];
  do {
    octets.unshift(Number(v & 0xffn));
    v >>= 8n;
  } while (v > 0n);
  if (octets[0] & 0x80) octets.unshift(0);
  return tlv(0x02, Buffer.from(octets));
}

/** OBJECT IDENTIFIER DER d'un OID en notation pointée. */
export function encoderOIDDER(texte) {
  if (typeof texte !== "string" || !RE_OID.test(texte)) throw new ErreurAncrage(`OID invalide : ${JSON.stringify(texte)}`);
  const arcs = texte.split(".").map(Number);
  if (arcs[0] < 2 && arcs[1] > 39) throw new ErreurAncrage(`OID invalide : ${texte}`);
  const octets = [];
  const base128 = (n) => {
    const b = [n & 0x7f];
    n = Math.floor(n / 128);
    while (n > 0) {
      b.unshift((n & 0x7f) | 0x80);
      n = Math.floor(n / 128);
    }
    return b;
  };
  octets.push(...base128(arcs[0] * 40 + arcs[1]));
  for (const a of arcs.slice(2)) octets.push(...base128(a));
  return tlv(0x06, Buffer.from(octets));
}

function octetsEmpreinte(digest, quoi = "empreinte") {
  const b = typeof digest === "string" ? (J.estHex32(digest) ? Buffer.from(digest.slice(2), "hex") : null) : Buffer.isBuffer(digest) || digest instanceof Uint8Array ? Buffer.from(digest) : null;
  if (!b || b.length !== 32) throw new ErreurAncrage(`${quoi} : 32 octets attendus (SHA-256)`, "AN-5");
  return b;
}

/**
 * Construit la TimeStampReq d'EX-5.1, octet pour octet : version 1,
 * messageImprint SHA-256 (paramètres NULL), reqPolicy si `policy_oid` est non
 * nul, nonce de 64 bits (INTEGER minimal), certReq TRUE. Refuse tout ce qui
 * n'est pas une requête de CT-5 (AN-5, AN-6) : empreinte d'une autre taille,
 * nonce nul ou hors de [1, 2^64 - 1], certReq faux, OID mal formé.
 */
export function construireRequete({ digest, nonce, policy_oid = null, cert_req = true } = {}) {
  const empreinte = octetsEmpreinte(digest);
  let n;
  try {
    n = BigInt(nonce);
  } catch {
    throw new ErreurAncrage("nonce : entier attendu", "AN-6");
  }
  if (typeof nonce === "number" && !Number.isSafeInteger(nonce)) throw new ErreurAncrage("nonce : entier sûr attendu", "AN-6");
  if (n < 1n || n > NONCE_MAX) throw new ErreurAncrage(`nonce ${n} hors de [1, 2^64 - 1]`, "AN-6");
  if (cert_req !== true) throw new ErreurAncrage("certReq vaut toujours TRUE (EX-5.4)", "AN-5");
  const parties = [encoderEntierDER(1n), tlv(0x30, Buffer.concat([ALGORITHME_SHA256_DER, tlv(0x04, empreinte)]))];
  if (policy_oid !== null && policy_oid !== undefined) parties.push(encoderOIDDER(policy_oid));
  parties.push(encoderEntierDER(n), tlv(0x01, Buffer.from([0xff])));
  return tlv(0x30, Buffer.concat(parties));
}

function lireTLV(buf, pos, quoi) {
  if (pos + 2 > buf.length) throw new ErreurAncrage(`${quoi} : DER tronqué`);
  const etiquette = buf[pos];
  let longueur = buf[pos + 1];
  let p = pos + 2;
  if (longueur & 0x80) {
    const n = longueur & 0x7f;
    if (n === 0 || n > 2 || p + n > buf.length) throw new ErreurAncrage(`${quoi} : longueur DER mal formée`);
    longueur = 0;
    for (let i = 0; i < n; i++) longueur = longueur * 256 + buf[p++];
    if (longueur < 0x80 || (n === 2 && longueur < 0x100)) throw new ErreurAncrage(`${quoi} : longueur DER non minimale`);
  }
  if (p + longueur > buf.length) throw new ErreurAncrage(`${quoi} : DER tronqué`);
  return { etiquette, debut: p, fin: p + longueur };
}
function decoderOIDOctets(b) {
  if (b.length === 0 || b[b.length - 1] & 0x80) throw new ErreurAncrage("OID mal formé");
  const arcs = [];
  let v = 0;
  for (let i = 0; i < b.length; i++) {
    if (v === 0 && b[i] === 0x80) throw new ErreurAncrage("OID : sous-identifiant non minimal");
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      arcs.push(v);
      v = 0;
    }
  }
  const premier = arcs[0] < 40 ? 0 : arcs[0] < 80 ? 1 : 2;
  return [premier, arcs[0] - premier * 40, ...arcs.slice(1)].join(".");
}

/**
 * Relit une TimeStampReq de CT-5 et rend { version, digest, policy_oid, nonce
 * (BigInt), cert_req } ; refuse (ErreurAncrage) toute forme hors d'EX-5.1.
 */
export function lireRequete(octets) {
  const buf = Buffer.from(octets);
  const seq = lireTLV(buf, 0, "TimeStampReq");
  if (seq.etiquette !== 0x30 || seq.fin !== buf.length) throw new ErreurAncrage("TimeStampReq : SEQUENCE attendue sur tout le fichier");
  let pos = seq.debut;
  const suivant = (etiquette, quoi) => {
    const n = lireTLV(buf, pos, quoi);
    if (n.etiquette !== etiquette) throw new ErreurAncrage(`${quoi} : étiquette 0x${n.etiquette.toString(16)}, attendue 0x${etiquette.toString(16)}`);
    pos = n.fin;
    return buf.subarray(n.debut, n.fin);
  };
  const version = suivant(0x02, "version");
  if (!version.equals(Buffer.from([1]))) throw new ErreurAncrage("version : 1 attendue");
  const mi = lireTLV(buf, pos, "messageImprint");
  if (mi.etiquette !== 0x30) throw new ErreurAncrage("messageImprint : SEQUENCE attendue");
  const algo = lireTLV(buf, mi.debut, "hashAlgorithm");
  if (!buf.subarray(mi.debut, algo.fin).equals(ALGORITHME_SHA256_DER)) throw new ErreurAncrage("hashAlgorithm : sha256 avec paramètres NULL attendu (EX-5.2)");
  const hm = lireTLV(buf, algo.fin, "hashedMessage");
  if (hm.etiquette !== 0x04 || hm.fin - hm.debut !== 32 || hm.fin !== mi.fin) throw new ErreurAncrage("hashedMessage : OCTET STRING de 32 octets attendu");
  const digest = "0x" + buf.subarray(hm.debut, hm.fin).toString("hex");
  pos = mi.fin;
  let policy_oid = null;
  if (lireTLV(buf, pos, "champ").etiquette === 0x06) policy_oid = decoderOIDOctets(suivant(0x06, "reqPolicy"));
  const nonceOctets = suivant(0x02, "nonce");
  if (nonceOctets.length === 0 || nonceOctets.length > 9) throw new ErreurAncrage("nonce : 1 à 9 octets attendus");
  if (nonceOctets[0] & 0x80) throw new ErreurAncrage("nonce : entier négatif");
  if (nonceOctets.length > 1 && nonceOctets[0] === 0 && !(nonceOctets[1] & 0x80)) throw new ErreurAncrage("nonce : zéro de tête superflu (encodage non minimal)");
  const nonce = BigInt("0x" + nonceOctets.toString("hex"));
  if (nonce < 1n || nonce > NONCE_MAX) throw new ErreurAncrage(`nonce ${nonce} hors de [1, 2^64 - 1]`);
  const certReq = suivant(0x01, "certReq");
  if (!certReq.equals(Buffer.from([0xff]))) throw new ErreurAncrage("certReq : TRUE (ff) attendu");
  if (pos !== seq.fin) throw new ErreurAncrage("champ supplémentaire après certReq");
  return { version: 1, digest, policy_oid, nonce, cert_req: true };
}

// ---------------------------------------------------------------------------
// Nonces, étiquettes et identifiants des vecteurs (annexe A.2)
// ---------------------------------------------------------------------------

/** 64 premiers bits de SHA-256(UTF-8(étiquette)), entier non signé (nonce RFC 3161 des vecteurs). */
export function nonceDepuisEtiquette(etiquette) {
  return BigInt("0x" + sha256(Buffer.from(etiquette, "utf8")).subarray(0, 8).toString("hex"));
}
/** 16 premiers octets de SHA-256(UTF-8(étiquette)) (nonce OpenTimestamps des vecteurs). */
export function nonceOtsDepuisEtiquette(etiquette) {
  return sha256(Buffer.from(etiquette, "utf8")).subarray(0, 16);
}
/** Nonce de 64 bits en hexadécimal 0x sur 16 chiffres (champ `nonce` des traces). */
export const hexNonce = (n) => "0x" + BigInt(n).toString(16).padStart(16, "0");

/** Étiquettes de dérivation des vecteurs (annexe A.2). `sorte` : « point » ou « periode » ; `hash` en 0x. */
export const ETIQUETTES = Object.freeze({
  nonceTsa: ({ journal, sorte, hash, n }) => `noortrace/vecteurs/v0/ct-5/nonce-tsa/${journal}/${sorte}/${hash.slice(2)}/${n}`,
  nonceOts: ({ journal, sorte, hash }) => `noortrace/vecteurs/v0/ct-5/ots/nonce/${journal}/${sorte}/${hash.slice(2)}`,
  calendrier: ({ journal, sorte, hash, calendrier }) => `noortrace/vecteurs/v0/ct-5/ots/calendrier/${calendrier}/${journal}/${sorte}/${hash.slice(2)}`,
});

/** Noms de journaux des vecteurs, par journal_id (journal de référence de CT-1 et journal-sinistres de CT-1 §13). */
export const JOURNAUX_VECTEURS = Object.freeze(Object.fromEntries(["journal-principal", "journal-sinistres"].map((nom) => [journalIdOf(nom), nom])));
export function nomJournalVecteurs(journal_id) {
  const nom = JOURNAUX_VECTEURS[journal_id];
  if (!nom) throw new ErreurAncrage(`journal_id ${journal_id} inconnu des vecteurs (journal-principal ou journal-sinistres attendus)`);
  return nom;
}

/** attempt_id d'EX-5.13 : <kind>:<16 premiers hex de l'empreinte>:<n>. */
export const identifiantCorrelation = (kind, hash, n) => `${kind}:${hash.slice(2, 18)}:${n}`;

/**
 * Source d'aléa des vecteurs : nonces dérivés des étiquettes d'A.2, gigues
 * consommées dans la liste `gigues` (jitter_ms de la trace, EX-8.9).
 */
export function aleatoireVecteurs({ gigues = [] } = {}) {
  let i = 0;
  return {
    nonceTsa: ({ subject, n }) => nonceDepuisEtiquette(ETIQUETTES.nonceTsa({ journal: nomJournalVecteurs(subject.journal_id), sorte: subject.kind, hash: subject.hash, n })),
    nonceOts: ({ subject }) => nonceOtsDepuisEtiquette(ETIQUETTES.nonceOts({ journal: nomJournalVecteurs(subject.journal_id), sorte: subject.kind, hash: subject.hash })),
    gigue: () => {
      if (i >= gigues.length) throw new ErreurAncrage(`gigue injectée épuisée (jitter_ms porte ${gigues.length} valeur(s))`);
      return gigues[i++];
    },
  };
}

/** Source d'aléa d'exploitation (générateur cryptographique du système). */
export function aleatoireSysteme(jitter_ms = DEFAUTS_CONFIGURATION.retry.jitter_ms) {
  return {
    nonceTsa: () => {
      for (;;) {
        const n = BigInt("0x" + crypto.randomBytes(8).toString("hex"));
        if (n >= 1n) return n;
      }
    },
    nonceOts: () => crypto.randomBytes(16),
    gigue: () => crypto.randomInt(0, jitter_ms + 1),
  };
}

// ---------------------------------------------------------------------------
// OpenTimestamps : engagement, fichier .ots, fusion (EX-6.2, EX-6.4, EX-6.6)
// ---------------------------------------------------------------------------

/** Engagement e = SHA-256(empreinte || nonce de 16 octets) (EX-6.2). */
export function engagementOts(empreinte, nonce) {
  const n = Buffer.from(nonce);
  if (n.length !== 16) throw new ErreurAncrage("nonce OpenTimestamps : 16 octets attendus", "AN-17");
  return sha256(Buffer.concat([octetsEmpreinte(empreinte), n]));
}

const FAUX_EN_TETE = (empreinte) => Buffer.concat([O.EN_TETE_MAGIQUE, Buffer.from([O.VERSION_MAJEURE, O.OP.sha256]), empreinte]);

/**
 * Relit un Timestamp sérialisé par un calendrier (sans en-tête de fichier :
 * l'arbre seul, EX-6.2, étape 3) et rend ses branches ; `message` est
 * l'engagement sur lequel il porte. Refuse une opération hors du profil
 * {f0, f1, 08} ou un arbre sans attestation.
 */
export function lireReponseCalendrier(octets, message = Buffer.alloc(32)) {
  const { arbre } = O.lireOts(Buffer.concat([FAUX_EN_TETE(Buffer.from(message)), Buffer.from(octets)]));
  const profil = new Set([O.OP.append, O.OP.prepend, O.OP.sha256]);
  let attestations = 0;
  const parcourir = (branches) => {
    for (const b of branches) {
      if (b.type === "attestation") attestations++;
      else {
        if (!profil.has(b.op)) throw new ErreurAncrage(`réponse de calendrier : opération 0x${b.op.toString(16)} hors du profil {f0, f1, 08}`, "AN-17");
        parcourir(b.arbre);
      }
    }
  };
  parcourir(arbre);
  if (attestations === 0) throw new ErreurAncrage("réponse de calendrier sans attestation", "AN-17");
  return arbre;
}

/**
 * Fichier .ots d'EX-6.4 : en-tête, empreinte, f0 nonce, 08, puis la fusion des
 * réponses des calendriers (listes de branches sous l'engagement), sérialisée
 * dans l'ordre de la bibliothèque de référence (ots.mjs, encoderArbre).
 */
export function construireOts({ empreinte, nonce, reponses }) {
  const n = Buffer.from(nonce);
  if (n.length !== 16) throw new ErreurAncrage("nonce OpenTimestamps : 16 octets attendus", "AN-18");
  const branches = (reponses ?? []).flat();
  if (branches.length === 0) throw new ErreurAncrage("aucune réponse de calendrier à écrire", "AN-18");
  return O.encoderOts(octetsEmpreinte(empreinte), O.chemin([{ op: O.OP.append, argument: n }, { op: O.OP.sha256 }], branches));
}

/** Attestations d'une preuve : [{ genre, uri | hauteur, resultat }] après exécution des opérations (O-3). */
export function attestationsOts(octets) {
  const preuve = O.lireOts(octets);
  return O.executer(preuve).attestations;
}

/** « complete » si la preuve porte une attestation Bitcoin, « en_attente » sinon (EX-6.7). */
export function etatPreuve(octets) {
  return attestationsOts(octets).some((a) => a.genre === "bitcoin") ? "complete" : "en_attente";
}

/**
 * Mise à niveau (EX-6.6) : remplace, dans la preuve, l'attestation en attente
 * de l'URI donnée par les branches reçues du calendrier (le Timestamp servi
 * pour l'engagement de ce calendrier), puis resérialise. Rend les octets de la
 * nouvelle version ; lève ErreurAncrage si l'URI n'est pas en attente.
 */
export function fusionnerOts(octets, { uri, reponse }) {
  const preuve = O.lireOts(octets);
  let faite = false;
  const parcourir = (branches) => {
    const i = branches.findIndex((b) => b.type === "attestation" && b.attestation.genre === "en_attente" && b.attestation.uri === uri);
    if (i >= 0 && !faite) {
      branches.splice(i, 1, ...reponse);
      faite = true;
      return;
    }
    for (const b of branches) if (b.type === "operation") parcourir(b.arbre);
  };
  parcourir(preuve.arbre);
  if (!faite) throw new ErreurAncrage(`aucune attestation en attente de ${uri} dans la preuve`, "AN-19");
  return O.encoderOts(preuve.empreinte, preuve.arbre);
}

// ---------------------------------------------------------------------------
// TimeStampResp : lecture, construction, classement (EX-5.10 à EX-5.12)
// ---------------------------------------------------------------------------

/** Bits de PKIFailureInfo (RFC 3161 §2.4.2). */
export const PKI_FAILURE_INFO = Object.freeze({ badAlg: 0, badRequest: 2, badDataFormat: 5, timeNotAvailable: 14, unacceptedPolicy: 15, unacceptedExtension: 16, addInfoNotAvailable: 17, systemFailure: 25 });
const NOM_FAILURE_INFO = Object.fromEntries(Object.entries(PKI_FAILURE_INFO).map(([k, v]) => [v, k]));
/** Types de contenu admis pour une réponse (EX-5.5). */
export const TYPES_CONTENU_REPONSE = ["application/timestamp-reply", "application/timestamp-response"];
/** Taille maximale du corps d'une réponse (EX-5.5). */
export const TAILLE_MAX_REPONSE = 128 * 1024;

/**
 * Relit une TimeStampResp : rend { status, status_string (ou null), fail_info
 * (nom ou null, le premier bit levé), fail_info_bits, token (octets du
 * TimeStampToken ou null) }. Lève ErreurAncrage si la forme n'est pas celle de
 * RFC 3161 §2.4.2 (lecteur DER borné de CT-6 §9.3).
 */
export function lireReponseTsa(octets) {
  const buf = Buffer.from(octets);
  if (buf.length > TAILLE_MAX_REPONSE) throw new ErreurAncrage(`réponse de ${buf.length} octets, au plus ${TAILLE_MAX_REPONSE}`);
  let racine;
  try {
    racine = lireDER(buf);
  } catch (e) {
    throw new ErreurAncrage(`TimeStampResp illisible : ${e.message}`);
  }
  if (racine.etiquette !== 0x30 || racine.enfants.length < 1 || racine.enfants.length > 2) throw new ErreurAncrage("TimeStampResp : SEQUENCE { status, timeStampToken OPTIONAL } attendue");
  const psi = racine.enfants[0];
  if (psi.etiquette !== 0x30 || psi.enfants.length < 1 || psi.enfants.length > 3) throw new ErreurAncrage("PKIStatusInfo mal formé");
  const st = psi.enfants[0];
  if (st.etiquette !== 0x02 || st.longueur !== 1) throw new ErreurAncrage("PKIStatusInfo.status : INTEGER d'un octet attendu");
  const status = st.valeur()[0];
  let status_string = null;
  let fail_info = null;
  const bits = [];
  for (const n of psi.enfants.slice(1)) {
    if (n.etiquette === 0x30 && status_string === null && fail_info === null) status_string = n.enfants.map((u) => u.valeur().toString("utf8")).join(" ");
    else if (n.etiquette === 0x03 && fail_info === null) {
      const v = n.valeur();
      for (let i = 1; i < v.length; i++) for (let b = 0; b < 8; b++) if (v[i] & (0x80 >> b)) bits.push((i - 1) * 8 + b);
      fail_info = bits.length ? (NOM_FAILURE_INFO[bits[0]] ?? `bit_${bits[0]}`) : null;
    } else throw new ErreurAncrage("PKIStatusInfo : élément inattendu");
  }
  const token = racine.enfants.length === 2 ? Buffer.from(racine.enfants[1].octets()) : null;
  if (token && racine.enfants[1].etiquette !== 0x30) throw new ErreurAncrage("timeStampToken : ContentInfo attendu");
  return { status, status_string, fail_info, fail_info_bits: bits, token };
}

/**
 * Construit une TimeStampResp DER : `status` (0 à 5), `status_string`
 * (PKIFreeText d'une UTF8String, facultatif), `fail_info` (nom ou liste de
 * noms de PKIFailureInfo, facultatif ; BIT STRING DER sans bits de queue),
 * `token` (TimeStampToken DER, exigé pour 0 et 1, interdit sinon).
 */
export function construireReponseTsa({ status, status_string = null, fail_info = null, token = null }) {
  if (!Number.isInteger(status) || status < 0 || status > 5) throw new ErreurAncrage("status : entier de 0 à 5 attendu");
  if ((status <= 1) !== (token !== null)) throw new ErreurAncrage("timeStampToken présent si et seulement si status vaut 0 ou 1");
  const parties = [encoderEntierDER(status)];
  if (status_string !== null) parties.push(tlv(0x30, tlv(0x0c, Buffer.from(status_string, "utf8"))));
  if (fail_info !== null) {
    const noms = Array.isArray(fail_info) ? fail_info : [fail_info];
    const positions = noms.map((n) => {
      if (!(n in PKI_FAILURE_INFO)) throw new ErreurAncrage(`PKIFailureInfo inconnu : ${n}`);
      return PKI_FAILURE_INFO[n];
    });
    const max = Math.max(...positions);
    const octets = Buffer.alloc(Math.floor(max / 8) + 1);
    for (const p of positions) octets[Math.floor(p / 8)] |= 0x80 >> p % 8;
    const inutilises = 7 - (max % 8);
    parties.push(tlv(0x03, Buffer.concat([Buffer.from([inutilises]), octets])));
  }
  const psi = tlv(0x30, Buffer.concat(parties));
  return tlv(0x30, token ? Buffer.concat([psi, Buffer.from(token)]) : psi);
}

/**
 * Attente de reprise d'EX-8.9, hors état : `k` est le rang de l'échec
 * transitoire consécutif (1 pour le premier), `premier_408_servi` dit si le
 * rejeu immédiat du premier 408 a déjà eu lieu, `gigue` un entier de
 * [0, jitter_ms]. Rend { delay_ms, reason }.
 */
export function calculerAttente({ http_status = null, retry_after_s = null, k = 1, premier_408_servi = false, retry = DEFAUTS_CONFIGURATION.retry, gigue = 0 } = {}) {
  if ((http_status === 429 || http_status === 503) && retry_after_s !== null && retry_after_s !== undefined) return { delay_ms: retry_after_s * 1000, reason: "retry_after" };
  if (http_status === 408 && !premier_408_servi) return { delay_ms: 0, reason: "immediat" };
  const base = Math.min(retry.max_ms, retry.initial_ms * retry.factor ** (k - 1));
  return { delay_ms: base + gigue, reason: "backoff" };
}

const msInstant = (i) => i.s * 1000 + Math.round(Number(("0." + (i.frac || "0")).slice(0, 12)) * 1000);
function anchorsDuPrestataire(prestataire) {
  const certs = prestataire?.anchor_certificates ?? [];
  if (!certs.length) return null;
  return {
    tsa_authorities: certs.map((pem, i) => ({ name: `${prestataire.id ?? "prestataire"}${certs.length > 1 ? ` (${i + 1})` : ""}`, certificate: pem, intermediates: [], accepted_policies: prestataire.accepted_policies ?? null, qualified: null })),
    revocation: { crls: [], statements: [] },
  };
}

/**
 * Classement d'une réponse RFC 3161 reçue, étapes 1 à 8 d'EX-5.10 (AN-8 à
 * AN-11) : `requete` (octets de la TimeStampReq envoyée), `reponse` (corps
 * reçu, ou null), `http` ({ status, content_type, body_size, retry_after_s }),
 * `sent_at` et `received_at` (RFC 3339), `prestataire` ({ id, accepted_policies,
 * anchor_certificates (PEM), qualified }), `freshness`, `tardives_precedentes`
 * (réponses tardives consécutives déjà reçues pour la demande). Les étapes 3 à
 * 6 emploient verifierJeton de horodatage.mjs (T-1 à T-9, T-7 à genTime).
 * Rend { outcome, error_code, class, critical, warnings, http_status,
 * pki_status, failure_info, nonce_in_response, imprint_matches, checks_passed,
 * token, token_sha256, token_size, gen_time, accuracy_s, upper_bound, detail }.
 */
export function evaluerReponse({ requete, reponse = null, http = {}, sent_at, received_at, prestataire = {}, freshness = DEFAUTS_CONFIGURATION.freshness, tardives_precedentes = 0 } = {}) {
  const req = lireRequete(requete);
  const res = { outcome: "echec_permanente", error_code: null, class: "permanente", critical: false, warnings: [], http_status: http.status ?? 200, pki_status: null, failure_info: null, nonce_in_response: null, imprint_matches: null, checks_passed: [], token: null, token_sha256: null, token_size: null, gen_time: null, accuracy_s: null, upper_bound: null, detail: "" };
  const echec = (code, classe, detail, extra = {}) => ({ ...res, ...extra, outcome: classe === "transitoire" ? "echec_transitoire" : "echec_permanente", error_code: code, class: classe, detail });
  // 1. transport
  const statut = http.status ?? 200;
  if (statut !== 200) return echec(`http_${statut}`, HTTP_TRANSITOIRES.has(statut) ? "transitoire" : "permanente", `http ${statut}${http.retry_after_s != null ? ` ; Retry-After ${http.retry_after_s} s` : ""}`);
  const type = http.content_type ?? TYPES_CONTENU_REPONSE[0];
  if (!TYPES_CONTENU_REPONSE.includes(String(type).split(";")[0].trim().toLowerCase())) return echec("type_contenu", "permanente", `Content-Type ${type} non admis`);
  const taille = http.body_size ?? (reponse ? reponse.length : 0);
  if (taille > TAILLE_MAX_REPONSE) return echec("taille", "permanente", `corps de ${taille} octets, au plus ${TAILLE_MAX_REPONSE}`);
  // 2. TimeStampResp
  let rep;
  try {
    rep = lireReponseTsa(reponse ?? Buffer.alloc(0));
  } catch (e) {
    return echec("reponse_illisible", "permanente", e.message);
  }
  res.pki_status = rep.status;
  res.failure_info = rep.fail_info;
  if (rep.status === 2) {
    if (rep.fail_info === null) return echec("statut_2", "permanente", "PKIStatus 2 (rejection) sans PKIFailureInfo");
    return echec(`echec_${rep.fail_info}`, ECHECS_TRANSITOIRES.has(rep.fail_info) ? "transitoire" : "permanente", `PKIStatus 2 (rejection) ; ${rep.fail_info}`);
  }
  if (rep.status === 3) return echec("statut_3", "transitoire", "PKIStatus 3 (waiting)");
  if (rep.status === 4 || rep.status === 5) return echec(`statut_${rep.status}`, "permanente", `PKIStatus ${rep.status} (${NOMS_PKI[rep.status]})`, { critical: true });
  if (!rep.token) return echec("reponse_illisible", "permanente", `PKIStatus ${rep.status} sans TimeStampToken`);
  res.token = rep.token;
  res.token_sha256 = sha256Hex(rep.token);
  res.token_size = rep.token.length;
  // 3 à 6. jeton
  const ev = evaluerJeton(rep.token, { periodHash: req.digest, ancres: anchorsDuPrestataire(prestataire) });
  const statutT = Object.fromEntries(ev.checks.map((c) => [c.id, c.status]));
  res.checks_passed = ev.checks.filter((c) => c.status === "reussi" && /^T-[1-9]$/.test(c.id)).map((c) => c.id);
  let tst = null;
  try {
    tst = lireJeton(rep.token).tst;
  } catch {
    tst = null;
  }
  if (!tst) return echec("verification_T-1", "permanente", "jeton inexploitable (T-1)", { token: res.token, token_sha256: res.token_sha256, token_size: res.token_size });
  const imprint = tst.empreinte.length === 32 && "0x" + tst.empreinte.toString("hex") === req.digest && tst.empreinteAlgo.oid === "2.16.840.1.101.3.4.2.1";
  res.imprint_matches = imprint;
  res.nonce_in_response = tst.nonce === null ? null : hexNonce(tst.nonce);
  const genTime = tst.genTimeTexte ? lireGenTime(tst.genTimeTexte) : null;
  if (genTime) {
    res.gen_time = rfc3339(genTime);
    const p = tst.precision ?? {};
    const acc = Number(p.seconds ?? 0n) + Number(p.millis ?? 0n) / 1000 + Number(p.micros ?? 0n) / 1e6;
    res.accuracy_s = tst.precision ? acc : null;
    res.upper_bound = iso(msInstant(genTime) + Math.round(acc * 1000));
  }
  if (!imprint) return echec("empreinte_differente", "permanente", "messageImprint different de l'empreinte demandee", res);
  if (tst.nonce === null) return echec("nonce_absent", "permanente", "nonce absent du TSTInfo", res);
  if (tst.nonce !== req.nonce) return echec("nonce_different", "permanente", `nonce ${res.nonce_in_response} different de ${hexNonce(req.nonce)}`, res);
  if (req.policy_oid !== null && tst.politique !== req.policy_oid) return echec("politique_differente", "permanente", `politique ${tst.politique} differente de la politique demandee ${req.policy_oid}`, res);
  const admises = prestataire.accepted_policies ?? null;
  if (admises !== null && !admises.includes(tst.politique)) return echec("politique_refusee", "permanente", `politique ${tst.politique} hors de accepted_policies`, res);
  for (let i = 1; i <= 9; i++) if (statutT[`T-${i}`] !== "reussi") return echec(`verification_T-${i}`, "permanente", `verification T-${i} ${statutT[`T-${i}`] ?? "absente"}`, res);
  // 7 et 8. fraîcheur et horloge
  const envoi = ms(sent_at);
  const reception = ms(received_at);
  const genMs = msInstant(genTime);
  if (reception - envoi > freshness.max_response_delay_s * 1000) {
    if (tardives_precedentes + 1 < 3) return { ...res, outcome: "reponse_tardive", error_code: "reponse_tardive", class: "transitoire", detail: `reponse recue ${Math.trunc((reception - envoi) / 1000)} s apres l'envoi` };
    res.warnings.push("reponse_tardive");
  }
  if (Math.abs(genMs - envoi) > freshness.clock_tolerance_s * 1000) res.warnings.push("horloge_suspecte");
  return { ...res, outcome: "obtenue", error_code: null, class: null, detail: `${NOMS_PKI[rep.status]} ; T-1 a T-9 reussies${res.warnings.length ? " ; avertissement " + res.warnings.join(", ") : ""}` };
}

// ---------------------------------------------------------------------------
// Comptages (EX-4.11) et coût (section 12)
// ---------------------------------------------------------------------------

const lire = (o, chemin, defaut) => {
  let v = o;
  for (const k of chemin) v = v == null ? undefined : v[k];
  return v === undefined || v === null ? defaut : v;
};

/**
 * Comptages par journal et par heure, par jour et par an (EX-4.11, AN-4) pour
 * une configuration (document ancrage-v0, projection ou objet partiel aux
 * mêmes chemins). `hours_per_year` : 8 760, ou 8 784 pour une année bissextile.
 */
export function compterJetons(config = {}, { hours_per_year = 8760 } = {}) {
  const cT = lire(config, ["rfc3161", "checkpoints", "interval_s"], DEFAUTS_CONFIGURATION.checkpoints.interval_s);
  const cK = lire(config, ["checkpoint_interval_s"], DEFAUTS_CONFIGURATION.checkpoint_interval_s);
  const role = lire(config, ["rfc3161", "checkpoints", "provider_role"], DEFAUTS_CONFIGURATION.checkpoints.provider_role);
  const registre = lire(config, ["registry", "checkpoints"], DEFAUTS_CONFIGURATION.registry.checkpoints);
  const otsActif = lire(config, ["opentimestamps", "enabled"], true);
  const otsPoint = lire(config, ["opentimestamps", "checkpoint"], "aucun");
  if (!Number.isInteger(cT) || cT < 60 || cT > 3600 || 3600 % cT !== 0) throw new ErreurAncrage(`interval_s ${cT} : diviseur de 3600 entre 60 et 3600 attendu`, "AN-1");
  if (!Number.isInteger(cK) || cK < 1 || 3600 % cK !== 0) throw new ErreurAncrage(`checkpoint_interval_s ${cK} : diviseur de 3600 attendu`, "AN-1");
  const nT = 3600 / cT;
  const points = role === "aucun" ? 0 : nT - 1;
  const heure = {
    tokens: 1 + points,
    qualified_tokens: 1 + (role === "principal" ? points : 0),
    checkpoint_tokens: points,
    checkpoint_provider_role: role,
    // EX-4.11 : points aux instants period_start + j × c_K (j = 0 … 3600 / c_K − 1) et point de clôture,
    // chacun ancré au plus une fois, plus l'ancre du manifeste.
    registry_anchors_max: 1 + (registre === "aucun" ? 0 : 1 + 3600 / cK),
    submit_period: 1,
    ots_submissions: (otsActif ? 1 : 0) + (otsActif && otsPoint === "mi_periode" ? 1 : 0),
  };
  const fois = (n) => Object.fromEntries(Object.entries(heure).map(([k, v]) => [k, typeof v === "number" ? v * n : v]));
  return { n_T: nT, deadlines_per_hour: nT - 1, per_hour: heure, per_day: fois(24), per_year: { hours: hours_per_year, ...fois(hours_per_year) } };
}

const arrondi3 = (x) => Math.round(x * 1000) / 1000;

/**
 * Formule de coût (EX-12.1, EX-12.2) sur les entrées d'un cas `$defs/cas_cout` ;
 * rend les six grandeurs attendues, arrondies à trois décimales. Les prix sont
 * des paramètres symboliques : aucun prix ne figure dans ce module.
 */
export function cout(i) {
  const H = i.hours_per_year;
  const Jn = i.journals;
  const cT = i.rfc3161_checkpoint_interval_s;
  const cK = i.checkpoint_interval_s;
  for (const [k, v] of Object.entries({ hours_per_year: H, journals: Jn, rfc3161_checkpoint_interval_s: cT, checkpoint_interval_s: cK })) if (!Number.isInteger(v) || v <= 0) throw new ErreurAncrage(`${k} : entier > 0 attendu`, "AN-59");
  if (3600 % cT !== 0 || 3600 % cK !== 0) throw new ErreurAncrage("cadences : diviseurs de 3600 attendus", "AN-59");
  const role = i.checkpoints_provider_role;
  const a = i.countersign_idle ? 1 : i.activity_ratio;
  if (!(a >= 0 && a <= 1)) throw new ErreurAncrage("activity_ratio : nombre de [0, 1] attendu", "AN-59");
  const nT = 3600 / cT;
  const points = role === "aucun" ? 0 : (nT - 1) * a;
  const Nq = H * (1 + (role === "principal" ? points : 0));
  const Ns = role === "second_rang" || role === "interne" ? H * points : 0;
  const Na = H * (1 + (i.registry_checkpoints === "aucun" ? 0 : 1 + 3600 / cK));
  const G = Na * 96977 + H * 314256;
  const r = i.billable_retry_ratio ?? 0;
  const F = i.subscription_fee ?? 0;
  const Q = i.subscription_quota ?? null;
  const bq = Nq * (1 + r);
  const bs = Ns * (1 + r);
  let C;
  if (F === 0) C = i.unit_price_qualified * bq + i.unit_price_second_rank * bs;
  else C = F + i.unit_price_qualified * (Q === null ? 0 : Math.max(0, bq - Q)) + i.unit_price_second_rank * bs;
  return {
    qualified_tokens_per_journal: arrondi3(Nq),
    second_rank_tokens_per_journal: arrondi3(Ns),
    registry_anchors_per_journal: arrondi3(Na),
    gas_upper_bound_per_journal: arrondi3(G),
    cost_per_journal: arrondi3(C),
    cost_total: arrondi3(Jn * C),
  };
}

// ---------------------------------------------------------------------------
// Configuration (EX-4.8, EX-4.9, EX-8.2)
// ---------------------------------------------------------------------------

/** Projection d'EX-8.2 d'un document ancrage-v0 : les seules clés que le planificateur emploie, `qualified` réduit à un booléen. */
export function projeterConfiguration(doc) {
  const d = DEFAUTS_CONFIGURATION;
  const r = doc?.rfc3161 ?? {};
  const o = doc?.opentimestamps ?? {};
  const cp = r.checkpoints ?? {};
  const up = o.upgrade ?? {};
  return {
    checkpoint_interval_s: doc?.checkpoint_interval_s ?? d.checkpoint_interval_s,
    rfc3161: {
      providers: (r.providers ?? []).map((p) => ({
        id: p.id,
        role: p.role,
        policy_oid: p.policy_oid ?? null,
        qualified: p.qualified !== null && p.qualified !== undefined && p.qualified !== false,
        min_interval_ms: p.min_interval_ms ?? 0,
        request_timeout_ms: p.request_timeout_ms ?? 10000,
      })),
      manifest: { fallback_after_s: r.manifest?.fallback_after_s ?? d.manifest.fallback_after_s },
      checkpoints: {
        interval_s: cp.interval_s ?? d.checkpoints.interval_s,
        provider_role: cp.provider_role ?? d.checkpoints.provider_role,
        fallback_after_s: cp.fallback_after_s ?? d.checkpoints.fallback_after_s,
        countersign_idle: cp.countersign_idle ?? d.checkpoints.countersign_idle,
      },
      freshness: { max_response_delay_s: r.freshness?.max_response_delay_s ?? d.freshness.max_response_delay_s, clock_tolerance_s: r.freshness?.clock_tolerance_s ?? d.freshness.clock_tolerance_s },
      retry: { initial_ms: r.retry?.initial_ms ?? d.retry.initial_ms, factor: r.retry?.factor ?? d.retry.factor, max_ms: r.retry?.max_ms ?? d.retry.max_ms, jitter_ms: r.retry?.jitter_ms ?? d.retry.jitter_ms },
    },
    registry: { checkpoints: doc?.registry?.checkpoints ?? d.registry.checkpoints, squat_wait_s: doc?.registry?.squat_wait_s ?? d.registry.squat_wait_s, inclusion_alert_s: doc?.registry?.inclusion_alert_s ?? d.registry.inclusion_alert_s },
    opentimestamps: {
      enabled: o.enabled ?? d.opentimestamps.enabled,
      calendars: [...(o.calendars ?? [])],
      min_responses: o.min_responses ?? d.opentimestamps.min_responses,
      timeout_ms: o.timeout_ms ?? d.opentimestamps.timeout_ms,
      checkpoint: o.checkpoint ?? d.opentimestamps.checkpoint,
      upgrade: { first_after_s: up.first_after_s ?? d.opentimestamps.upgrade.first_after_s, interval_s: up.interval_s ?? d.opentimestamps.upgrade.interval_s, give_up_after_s: up.give_up_after_s ?? d.opentimestamps.upgrade.give_up_after_s },
    },
    queue: { max_pending: doc?.queue?.max_pending ?? d.queue.max_pending, anchor_pending_alert_s: doc?.queue?.anchor_pending_alert_s ?? d.queue.anchor_pending_alert_s },
  };
}

const ADRESSES_LOCALES = new Set(["127.0.0.1", "::1", "[::1]", "localhost"]);
function hoteDeUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/**
 * Règles d'EX-4.9 (AN-1), hors schéma : rend { valide, violations: [{ rule,
 * message }] }, toutes les règles violées étant listées. `checkpoint_interval_s`
 * est la valeur de l'enregistreur (CT-2) quand elle est connue ; `profil`
 * « production » applique la règle 4. `lecteurCertificat` lit un PEM (règle 8).
 */
export function verifierConfiguration(doc, { profil = "production", checkpoint_interval_s = null, lecteurCertificat = null } = {}) {
  const violations = [];
  const v = (rule, message) => violations.push({ rule, message });
  const cK = doc?.checkpoint_interval_s;
  const r = doc?.rfc3161 ?? {};
  const providers = Array.isArray(r.providers) ? r.providers : [];
  const cp = r.checkpoints ?? {};
  const o = doc?.opentimestamps ?? {};
  // 1
  if (!Number.isInteger(cK) || 3600 % cK !== 0) v(1, `checkpoint_interval_s ${JSON.stringify(cK)} n'est pas un diviseur de 3600`);
  if (checkpoint_interval_s !== null && cK !== checkpoint_interval_s) v(1, `checkpoint_interval_s ${cK} différent de la valeur de l'enregistreur ${checkpoint_interval_s}`);
  // En production, la valeur de l'enregistreur est exigée : la comparaison n'est jamais sautée (EX-4.9, règle 1).
  if (checkpoint_interval_s === null && profil === "production") v(1, "valeur checkpoint_interval_s de l'enregistreur inconnue : la comparaison de la règle 1 ne peut pas être faite");
  // 2
  const parRole = (role) => providers.filter((p) => p.role === role);
  if (parRole("principal").length !== 1) v(2, `${parRole("principal").length} prestataire(s) de rôle principal, un exactement attendu`);
  if (parRole("secours").length > 1) v(2, `${parRole("secours").length} prestataires de rôle secours, un au plus`);
  const ids = providers.map((p) => p.id);
  if (new Set(ids).size !== ids.length) v(2, "identifiants de prestataires non distincts");
  // 3
  if (!Number.isInteger(cp.interval_s) || 3600 % cp.interval_s !== 0 || (Number.isInteger(cK) && cp.interval_s % cK !== 0)) v(3, `rfc3161.checkpoints.interval_s ${JSON.stringify(cp.interval_s)} n'est pas un multiple de checkpoint_interval_s et un diviseur de 3600`);
  // 4
  if (profil === "production") {
    if (cp.provider_role === "aucun") v(4, "provider_role « aucun » hors production seulement");
    if (doc?.registry?.checkpoints === "aucun") v(4, "registry.checkpoints « aucun » hors production seulement");
    if (o.enabled !== true) v(4, "opentimestamps.enabled doit être vrai en production");
    const principal = parRole("principal")[0];
    if (principal && (principal.qualified === null || principal.qualified === undefined)) v(4, `le principal ${principal.id} n'a pas de statut qualified`);
    const secours = parRole("secours")[0];
    if (secours && (secours.qualified === null || secours.qualified === undefined)) v(4, `le secours ${secours.id} n'a pas de statut qualified`);
    for (const p of providers) {
      const url = String(p.url ?? "");
      if (p.role !== "interne" && !url.startsWith("https://")) v(4, `prestataire ${p.id} (${p.role}) : url en https:// exigée`);
      if (p.role === "interne" && url.startsWith("http://") && !ADRESSES_LOCALES.has(hoteDeUrl(url))) v(4, `prestataire interne ${p.id} : http:// admis vers une adresse locale seulement`);
    }
  }
  // 5
  if (o.enabled === true) {
    const cals = Array.isArray(o.calendars) ? o.calendars : [];
    if (new Set(cals).size < 2) v(5, "au moins deux calendriers distincts attendus");
    if (!(o.min_responses <= cals.length)) v(5, `min_responses ${o.min_responses} supérieur au nombre de calendriers ${cals.length}`);
    if (!Array.isArray(o.upgrade?.whitelist) || o.upgrade.whitelist.length < 1) v(5, "upgrade.whitelist vide");
  }
  // 6
  if (!(r.retention_years >= 10)) v(6, `retention_years ${JSON.stringify(r.retention_years)} inférieur à 10`);
  if (!(r.retry?.initial_ms <= r.retry?.max_ms)) v(6, "retry.initial_ms supérieur à retry.max_ms");
  if (!(o.upgrade?.interval_s >= 60)) v(6, `upgrade.interval_s ${JSON.stringify(o.upgrade?.interval_s)} inférieur à 60`);
  // 7
  if (cp.provider_role === "second_rang" && parRole("second_rang").length === 0) v(7, "provider_role second_rang sans prestataire de ce rôle");
  if (cp.provider_role === "interne" && parRole("interne").length === 0) v(7, "provider_role interne sans prestataire de ce rôle");
  // 8
  const lecteur = lecteurCertificat ?? ((pem) => lireCertificat(decoderPEM(pem, "CERTIFICATE")));
  for (const p of providers) {
    for (const [i, pem] of (Array.isArray(p.anchor_certificates) ? p.anchor_certificates : []).entries()) {
      try {
        lecteur(pem);
      } catch (e) {
        v(8, `prestataire ${p.id}, anchor_certificates[${i}] : ${e.message}`);
      }
    }
  }
  return { valide: violations.length === 0, violations };
}

// ---------------------------------------------------------------------------
// Échéances, admission, série (AN-2, AN-3)
// ---------------------------------------------------------------------------

/** Échéances D_k = period_start + k × c_T, k = 1 … n_T − 1, puis la clôture (k = n_T) (EX-4.2). */
export function echeancesPeriode(period_start, interval_s) {
  if (!Number.isInteger(interval_s) || interval_s < 60 || 3600 % interval_s !== 0) throw new ErreurAncrage(`interval_s ${interval_s} : diviseur de 3600 entre 60 et 3600 attendu`, "AN-2");
  const nT = 3600 / interval_s;
  const liste = [];
  for (let k = 1; k <= nT; k++) liste.push({ k, at_ms: (period_start + k * interval_s) * 1000, at: iso((period_start + k * interval_s) * 1000), closing: k === nT });
  return liste;
}

/**
 * Admission d'un point à ancrer (AN-3 ; CT-1 §10.5, règles 2 à 5) : règles
 * internes, signature sous la clé en vigueur (`cles` : document cles.json ou
 * Map de normaliserCles ; `evenements` pour la clé en vigueur à last_seq),
 * place dans la série (`serie` : les points admis avant lui, dans l'ordre).
 * Rend { admis: true, checkpoint_hash, fingerprint } ou { admis: false, regle,
 * erreurs }.
 */
export function admettrePoint(point, { serie = [], cles = null, evenements = null } = {}) {
  const refus = (regle, ...erreurs) => ({ admis: false, regle, erreurs });
  const internes = J.verifierPointDeControle(point);
  if (internes.length) return refus("format", ...internes);
  const precedent = serie.length ? serie[serie.length - 1] : null;
  if (precedent) {
    if (point.org_id !== precedent.org_id || point.journal_id !== precedent.journal_id || point.period_start !== precedent.period_start) return refus("serie", "org_id, journal_id ou period_start différents de la série");
    const attendu = J.hachagePointDeControle(precedent);
    if (point.prev_checkpoint_hash !== attendu) return refus("chainage", `prev_checkpoint_hash ${point.prev_checkpoint_hash}, attendu ${attendu}`);
    if (point.tree_size < precedent.tree_size) return refus("tree_size_decroissant", `tree_size ${point.tree_size} < ${precedent.tree_size}`);
    if (J.msHorodatage(point.checkpoint_ts) < J.msHorodatage(precedent.checkpoint_ts)) return refus("checkpoint_ts_decroissant", `checkpoint_ts ${point.checkpoint_ts} antérieur à ${precedent.checkpoint_ts}`);
  } else if (point.prev_checkpoint_hash !== J.HASH_NUL) return refus("chainage", "premier point de la période : prev_checkpoint_hash nul attendu");
  if (Math.floor(J.msHorodatage(point.checkpoint_ts) / 1000) < point.period_start) return refus("period_start", `checkpoint_ts ${point.checkpoint_ts} antérieur à period_start`);
  if (Math.floor(J.msHorodatage(point.checkpoint_ts) / 1000) >= point.period_start + J.DUREE_PERIODE + J.DUREE_PERIODE) return refus("period_start", `checkpoint_ts ${point.checkpoint_ts} trop postérieur à la période`);
  if (evenements) {
    // CT-1 §10.5, règle 2 : root, last_hash et last_seq recalculés depuis les événements de la période.
    const evs = J.evenementsDePeriode(evenements.filter((e) => e && typeof e === "object" && Number.isSafeInteger(e.seq)), point.period_start).sort((a, b) => a.seq - b.seq);
    const hashes = evs.map((e) => e.hash);
    if (point.tree_size > hashes.length) return refus("racine", `tree_size ${point.tree_size} supérieur au nombre d'événements connus de la période (${hashes.length})`);
    const root = J.racineMerkle(hashes.slice(0, point.tree_size));
    if (point.root !== root) return refus("racine", `root ${point.root} différent de la racine recalculée ${root}`);
    if (point.tree_size > 0) {
      if (point.last_seq !== evs[0].seq + point.tree_size - 1) return refus("last_seq", `last_seq ${point.last_seq} différent de first_seq + tree_size - 1 (${evs[0].seq + point.tree_size - 1})`);
      if (point.last_hash !== hashes[point.tree_size - 1]) return refus("last_hash", `last_hash ${point.last_hash} différent du hash de l'événement ${point.last_seq}`);
    } else {
      const avantPeriode = evenements.filter((e) => e && Number.isSafeInteger(e.seq) && J.msHorodatage(e.ts) < point.period_start * 1000).sort((a, b) => a.seq - b.seq);
      const dernier = avantPeriode.length ? avantPeriode[avantPeriode.length - 1] : null;
      const attenduLast = dernier ? dernier.hash : J.HASH_NUL;
      if (point.last_hash !== attenduLast) return refus("last_hash", `last_hash ${point.last_hash} différent du hash du dernier événement avant la période (${attenduLast})`);
      if (dernier && point.last_seq !== dernier.seq) return refus("last_seq", `last_seq ${point.last_seq} différent de ${dernier.seq}`);
    }
    const attendue = J.cleEnVigueurPoint(evenements, point.last_seq);
    if (attendue !== null && attendue !== point.key_id) return refus("cle_en_vigueur", `key_id ${point.key_id}, clé en vigueur ${attendue}`);
  }
  if (cles) {
    const jeu = cles instanceof Map ? cles : J.normaliserCles(cles);
    const cle = jeu.get(point.key_id);
    if (!cle) return refus("cle_absente", `clé ${point.key_id} absente du jeu de clés`);
    if (!J.verifierSignaturePointDeControle(point, cle.public_key)) return refus("signature", `signature invalide sous ${point.key_id}`);
    const t = J.msHorodatage(point.checkpoint_ts);
    const de = cle.valid_from === null || cle.valid_from === undefined ? -Infinity : J.msHorodatage(cle.valid_from);
    const a = cle.valid_to === null || cle.valid_to === undefined ? Infinity : J.msHorodatage(cle.valid_to);
    if (!(t >= de && t <= a)) return refus("validite_cle", `checkpoint_ts ${point.checkpoint_ts} hors de la validité de ${point.key_id}`);
  }
  const checkpoint_hash = J.hachagePointDeControle(point);
  return { admis: true, checkpoint_hash, fingerprint: J.empreinteAncrePoint(point.org_id, point.journal_id, checkpoint_hash) };
}

/** Tolérance d'alignement et de cadence des points, en secondes (CT-1 §10.5, règle 1 ; CT-2 révision 0.4). */
export const TOLERANCE_CADENCE_S = 1;

/**
 * Constat de cadence d'une série (AN-2, EX-4.1) : l'écart entre deux points
 * consécutifs, et entre le début (point de clôture de la période précédente,
 * ou `period_start`) et le premier point, ne dépasse pas `c_K + tolérance`.
 * Un écart est un constat qui alimente l'alerte `point_manquant` (8.9), pas un
 * refus de la série : un arrêt légitime de l'enregistreur en produit aussi.
 * Rend { conforme, ecarts: [{ from, to, gap_s }] }.
 */
export function constaterCadence({ period_start, points = [], checkpoint_interval_s = DEFAUTS_CONFIGURATION.checkpoint_interval_s, tolerance_s = TOLERANCE_CADENCE_S, previous_closing_ts = null }) {
  const tries = [...points].sort((a, b) => J.msHorodatage(a.checkpoint_ts) - J.msHorodatage(b.checkpoint_ts));
  const borne = (checkpoint_interval_s + tolerance_s) * 1000;
  const ecarts = [];
  let depuis = previous_closing_ts !== null ? J.msHorodatage(previous_closing_ts) : period_start * 1000;
  let texte = previous_closing_ts ?? iso(period_start * 1000);
  for (const p of tries) {
    const t = J.msHorodatage(p.checkpoint_ts);
    if (t - depuis > borne) ecarts.push({ from: texte, to: p.checkpoint_ts, gap_s: Math.trunc((t - depuis) / 1000) });
    depuis = t;
    texte = p.checkpoint_ts;
  }
  return { conforme: ecarts.length === 0, ecarts };
}

/**
 * Table des échéances d'une période (AN-2) : pour chaque D_k, le point
 * sélectionné (premier point de checkpoint_ts ≥ D_k, EX-4.3), son état
 * (`satisfaite`, `sans_objet`, `remplacee`, `ouverte`), les délais d_jeton et
 * d_registre. `points` : [{ checkpoint_hash, tree_size, checkpoint_ts }] ;
 * `ancres` : [{ checkpoint_hash, kind: « rfc3161 » | « registre », bound }]
 * (`bound` : genTime + précision, ou instant du bloc, RFC 3339). Le dernier
 * point contresigné n'avance que sur un point dont le jeton est dans `ancres`
 * (EX-4.3). Alertes : `checkpoint_anchor_late` (échéance remplacee, EX-4.4),
 * `jeton_anterieur_au_point` (genTime + précision < checkpoint_ts −
 * clock_tolerance_s), `contresignature_tardive` (genTime + précision −
 * checkpoint_ts > c_T), `point_manquant` (constat de cadence).
 */
export function tableEcheances({ period_start, config = {}, points = [], ancres = [], previous_closing_ts = null }) {
  const cT = lire(config, ["rfc3161", "checkpoints", "interval_s"], DEFAUTS_CONFIGURATION.checkpoints.interval_s);
  const cK = lire(config, ["checkpoint_interval_s"], DEFAUTS_CONFIGURATION.checkpoint_interval_s);
  const idle = lire(config, ["rfc3161", "checkpoints", "countersign_idle"], false);
  const tolerance = lire(config, ["rfc3161", "freshness", "clock_tolerance_s"], DEFAUTS_CONFIGURATION.freshness.clock_tolerance_s);
  const tries = [...points].sort((a, b) => J.msHorodatage(a.checkpoint_ts) - J.msHorodatage(b.checkpoint_ts));
  const jetons = new Map();
  const registres = new Map();
  for (const a of ancres) (a.kind === "registre" ? registres : jetons).set(a.checkpoint_hash, ms(a.bound));
  const lignes = [];
  const alerts = [];
  const signales = new Set();
  let dernierContresigne = 0;
  let dernierSelectionne = null;
  for (const e of echeancesPeriode(period_start, cT)) {
    if (e.closing) break;
    const point = tries.find((p) => J.msHorodatage(p.checkpoint_ts) >= e.at_ms) ?? null;
    const ligne = { k: e.k, deadline: e.at, checkpoint_hash: point?.checkpoint_hash ?? null, tree_size: point?.tree_size ?? null, state: "ouverte", d_jeton_s: null, d_registre_s: null };
    if (point) {
      const nouveau = point.tree_size > dernierContresigne || idle;
      if (point !== dernierSelectionne) {
        dernierSelectionne = point;
        if (nouveau && jetons.has(point.checkpoint_hash)) dernierContresigne = point.tree_size;
      }
      if (!nouveau) ligne.state = "sans_objet";
      else if (jetons.has(point.checkpoint_hash)) {
        ligne.state = "satisfaite";
        const borne = jetons.get(point.checkpoint_hash);
        ligne.d_jeton_s = Math.trunc((borne - e.at_ms) / 1000);
        if (!signales.has(point.checkpoint_hash)) {
          signales.add(point.checkpoint_hash);
          const ts = J.msHorodatage(point.checkpoint_ts);
          if (borne < ts - tolerance * 1000) alerts.push({ code: "jeton_anterieur_au_point", k: e.k, checkpoint_hash: point.checkpoint_hash });
          if (borne - ts > cT * 1000) alerts.push({ code: "contresignature_tardive", k: e.k, checkpoint_hash: point.checkpoint_hash });
        }
      }
      if (registres.has(point.checkpoint_hash)) ligne.d_registre_s = Math.trunc((registres.get(point.checkpoint_hash) - J.msHorodatage(point.checkpoint_ts)) / 1000);
    }
    lignes.push(ligne);
  }
  // EX-4.4 : une échéance non satisfaite dont une échéance ultérieure est satisfaite (par un autre point) est remplacée.
  for (let i = 0; i < lignes.length; i++) {
    if (lignes[i].state !== "ouverte") continue;
    const suivante = lignes.slice(i + 1).find((l) => l.state === "satisfaite" && l.checkpoint_hash !== lignes[i].checkpoint_hash);
    if (suivante) lignes[i].state = "remplacee";
  }
  const cadence = constaterCadence({ period_start, points, checkpoint_interval_s: cK, previous_closing_ts });
  return {
    period_start,
    interval_s: cT,
    deadlines: lignes,
    cadence,
    alerts: [...lignes.filter((l) => l.state === "remplacee").map((l) => ({ code: "checkpoint_anchor_late", k: l.k })), ...alerts, ...cadence.ecarts.map((x) => ({ code: "point_manquant", from: x.from, to: x.to, gap_s: x.gap_s }))],
  };
}

/**
 * Complétude au registre (AN-61, EX-10.7) : contrôle de série hors dossier.
 * `journaux` : [{ org_id, journal_id, points }] (points publiés de la série,
 * objets signés ou { checkpoint_hash, checkpoint_ts }) de tous les journaux
 * servis par les clés de chaîne `emetteurs` (inscriptions et rotations de
 * RecorderRegistry) ; `ancres` : les événements Anchored capturés
 * ({ fingerprint, doc_type, block_number, log_index, issuer }), entre le bloc
 * `de_bloc` (exclu : ancre de la période précédente) et `a_bloc` (inclus :
 * ancre de la période). Toute ancre de docType point de contrôle d'un de ces
 * émetteurs DOIT avoir pour empreinte keccak256(org_id ‖ journal_id ‖
 * checkpointHash) d'un point publié (sinon `ancre_orpheline`, alerte
 * critique : série réécrite ou clé de chaîne compromise) ; l'ordre des blocs
 * DOIT suivre celui des checkpoint_ts d'une même série (`hors_ordre`).
 * Chaque entrée de `journaux` est la série d'une période ; l'appelant sert la
 * série de la période et celle de la période suivante quand elle existe, dont
 * les premiers points peuvent être ancrés avant l'ancre de la période. Rend
 * { complet, orphelines, hors_ordre, rattachees }.
 */
export function verifierCompletudeRegistre({ journaux = [], ancres = [], emetteurs = [], de_bloc = -1, a_bloc = Number.MAX_SAFE_INTEGER }) {
  // Chaque entrée de journaux est la série d'une période (EX-10.7) : l'ordre
  // des blocs est confronté à celui des checkpoint_ts série par série.
  const index = new Map();
  for (const [serie, j] of journaux.entries()) {
    for (const p of j.points ?? []) {
      const h = p.checkpoint_hash ?? J.hachagePointDeControle(p);
      index.set(J.empreinteAncrePoint(j.org_id, j.journal_id, h).toLowerCase(), { serie, journal_id: j.journal_id, checkpoint_hash: h, checkpoint_ts: p.checkpoint_ts });
    }
  }
  const emet = new Set(emetteurs.map((a) => String(a).toLowerCase()));
  const vues = ancres
    .filter((a) => String(a.doc_type).toLowerCase() === J.DOC_TYPE_POINT_DE_CONTROLE && emet.has(String(a.issuer).toLowerCase()) && a.block_number > de_bloc && a.block_number <= a_bloc)
    .sort((x, y) => x.block_number - y.block_number || x.log_index - y.log_index);
  const orphelines = [];
  const rattachees = [];
  for (const a of vues) {
    const r = index.get(String(a.fingerprint).toLowerCase());
    if (!r) orphelines.push({ fingerprint: a.fingerprint, block_number: a.block_number, log_index: a.log_index, issuer: a.issuer });
    else rattachees.push({ fingerprint: a.fingerprint, block_number: a.block_number, log_index: a.log_index, ...r });
  }
  const hors_ordre = [];
  const dernier = new Map();
  for (const r of rattachees) {
    const prec = dernier.get(r.serie);
    if (prec && J.msHorodatage(r.checkpoint_ts) < J.msHorodatage(prec.checkpoint_ts)) hors_ordre.push({ fingerprint: r.fingerprint, block_number: r.block_number, checkpoint_ts: r.checkpoint_ts, after_checkpoint_ts: prec.checkpoint_ts });
    dernier.set(r.serie, r);
  }
  return { complet: orphelines.length === 0 && hors_ordre.length === 0, orphelines, hors_ordre, rattachees };
}

// ---------------------------------------------------------------------------
// File NDJSON (EX-8.5)
// ---------------------------------------------------------------------------

/** Ligne de file d'une demande : forme canonique JCS intégral (CT-2 §8.1). */
export const ligneFile = (demande) => J.canonicaliserJCSIntegral(demande);

/** Texte NDJSON d'une liste de demandes (une ligne par demande, saut de ligne final). */
export function ecrireFile(demandes) {
  return demandes.map((d) => ligneFile(d) + "\n").join("");
}

/**
 * Relit une file NDJSON (EX-8.5, règle 3) : les lignes sont rejouées dans
 * l'ordre, la dernière ligne d'un `id` fait foi, une ligne finale tronquée est
 * ignorée et signalée (`truncated`), jamais réparée. Rend { demandes (dans
 * l'ordre de première apparition), lines, truncated, errors }.
 */
export function lireFile(texte) {
  const brut = Buffer.isBuffer(texte) ? texte.toString("utf8") : String(texte ?? "");
  const morceaux = brut.split("\n");
  const derniere = morceaux.pop();
  const parId = new Map();
  const errors = [];
  let truncated = false;
  let lines = 0;
  const admettre = (ligne, i) => {
    let d;
    try {
      d = JSON.parse(ligne);
    } catch {
      return false;
    }
    if (!d || typeof d !== "object" || Array.isArray(d) || typeof d.id !== "string" || !SORTES.includes(d.kind) || !ETATS.includes(d.state)) {
      errors.push(`ligne ${i + 1} : demande mal formée`);
      return true;
    }
    if (d.id !== `${d.kind}:${d.subject?.hash}`) errors.push(`ligne ${i + 1} : id ${d.id} différent de <kind>:<hash>`);
    const prec = parId.get(d.id);
    if (prec && ETATS_FINAUX.has(prec.state) && prec.state !== d.state) errors.push(`ligne ${i + 1} : ${d.id} déjà dans l'état final ${prec.state}`);
    parId.set(d.id, d);
    return true;
  };
  morceaux.forEach((ligne, i) => {
    if (ligne === "") return;
    lines++;
    if (!admettre(ligne, i)) errors.push(`ligne ${i + 1} : JSON illisible`);
  });
  if (derniere !== "") {
    lines++;
    if (!admettre(derniere, morceaux.length)) truncated = true;
  }
  return { demandes: [...parId.values()], lines, truncated, errors };
}

const RE_FICHIER_FILE = /^file-([0-9]+)(?:\.([0-9]+)\.compact)?\.ndjson$/;

/**
 * Relit tous les fichiers de file d'un répertoire (EX-8.5, EX-8.12) :
 * `fichiers` est une liste { nom, texte } (`file-<epoch>.ndjson` ou
 * `file-<epoch>.<n>.compact.ndjson`) ; les fichiers sont rejoués par époque
 * croissante, compactés avant l'original d'une même époque, et la dernière
 * ligne d'un id fait foi à travers eux (ordre de première apparition, comme
 * lireFile). Rend { demandes, lines, truncated
 * (noms des fichiers dont la dernière ligne est tronquée), errors, files
 * (ordre de lecture) }.
 */
export function lireFiles(fichiers) {
  const lus = (fichiers ?? []).map((f) => {
    const m = RE_FICHIER_FILE.exec(f.nom);
    if (!m) throw new ErreurAncrage(`fichier de file ${JSON.stringify(f.nom)} : file-<epoch>.ndjson ou file-<epoch>.<n>.compact.ndjson attendu`);
    return { nom: f.nom, texte: f.texte, epoch: Number(m[1]), compact: m[2] !== undefined, rang: m[2] === undefined ? 0 : Number(m[2]) };
  });
  lus.sort((a, b) => a.epoch - b.epoch || (a.compact === b.compact ? a.rang - b.rang : a.compact ? -1 : 1));
  const parId = new Map();
  const truncated = [];
  const errors = [];
  let lines = 0;
  for (const f of lus) {
    const r = lireFile(f.texte);
    lines += r.lines;
    if (r.truncated) truncated.push(f.nom);
    for (const e of r.errors) errors.push(`${f.nom} : ${e}`);
    for (const d of r.demandes) parId.set(d.id, d);
  }
  return { demandes: [...parId.values()], lines, truncated, errors, files: lus.map((f) => f.nom) };
}

// ---------------------------------------------------------------------------
// Planificateur (section 8)
// ---------------------------------------------------------------------------

const SORTE_PERIODE = (kind) => kind.endsWith("_periode");
const SORTE_PREFIXE = (kind) => kind.split("_").slice(0, -1).join("_");
const idDemande = (kind, hash) => `${kind}:${hash}`;
const copie = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));
const NOMS_PKI = ["granted", "grantedWithMods", "rejection", "waiting", "revocationWarning", "revocationNotification"];
const ECHECS_TRANSITOIRES = new Set(["timeNotAvailable", "systemFailure"]);
const HTTP_TRANSITOIRES = new Set([408, 429, 500, 502, 503, 504]);

function normaliserProjection(config) {
  const p = projeterConfiguration(config ?? {});
  const parId = new Map();
  const parRole = {};
  for (const pr of p.rfc3161.providers) {
    if (typeof pr.id !== "string" || !ROLES.includes(pr.role)) throw new ErreurAncrage(`prestataire mal formé : ${JSON.stringify(pr)}`, "AN-1");
    if (parId.has(pr.id)) throw new ErreurAncrage(`prestataire ${pr.id} en double`, "AN-1");
    parId.set(pr.id, pr);
    if (pr.role === "principal" || pr.role === "secours") {
      if (parRole[pr.role]) throw new ErreurAncrage(`deux prestataires de rôle ${pr.role}`, "AN-1");
      parRole[pr.role] = pr;
    } else parRole[pr.role] ??= pr;
  }
  if (!parRole.principal) throw new ErreurAncrage("aucun prestataire de rôle principal", "AN-1");
  const cT = p.rfc3161.checkpoints.interval_s;
  if (!Number.isInteger(cT) || 3600 % cT !== 0 || cT % p.checkpoint_interval_s !== 0) throw new ErreurAncrage(`interval_s ${cT} : multiple de checkpoint_interval_s et diviseur de 3600 attendu`, "AN-1");
  const role = p.rfc3161.checkpoints.provider_role;
  if (role !== "aucun" && !parRole[role]) throw new ErreurAncrage(`provider_role ${role} sans prestataire de ce rôle`, "AN-1");
  return { projection: p, parId, parRole, nT: 3600 / cT };
}

class Planificateur {
  constructor(config, { maintenant = null, aleatoire = null } = {}) {
    const { projection, parId, parRole, nT } = normaliserProjection(config);
    this.cfg = projection;
    this.prestataires = parId;
    this.roles = parRole;
    this.nT = nT;
    this.maintenant = maintenant;
    this.aleatoire = aleatoire ?? aleatoireVecteurs();
    this.demandes = new Map();
    this.interne = new Map();
    this.periodes = new Map();
    this.timers = [];
    this.seq = 0;
    this.actions = [];
    this.lignes = [];
    this.dernierEnvoi = new Map();
    this.pretes = [];
    this.relues = 0;
    this.horloge = -Infinity;
    this.demarre = false;
  }

  // --- état interne ---------------------------------------------------------

  int(id) {
    let s = this.interne.get(id);
    if (!s) {
      s = { enCours: new Map(), engages: new Set(), epuises: new Set(), reprises: new Map(), k: new Map(), premier408: new Set(), tardives: 0, alertes: new Set(), attenteAt: null, inclusionAt: null, miseANiveauAt: null, differe: null, renvois: 0, soumisA: null };
      this.interne.set(id, s);
    }
    return s;
  }
  actives() {
    let n = 0;
    for (const d of this.demandes.values()) if (!ETATS_FINAUX.has(d.state)) n++;
    return n;
  }
  /** La file, dans l'ordre (created_at, id). */
  file() {
    return [...this.demandes.values()].sort((a, b) => (a.created_at < b.created_at ? -1 : a.created_at > b.created_at ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  }
  emettre(t, action, request_id, detail) {
    const a = { t: iso(t), action, request_id, detail };
    this.actions.push(a);
    return a;
  }
  ecrire(d, t, state) {
    d.state = state;
    this.emettre(t, "ecrire_file", d.id, { state });
    this.lignes.push(ligneFile(d));
  }
  programmer(d, t, at, reason) {
    d.due_at = iso(at);
    this.emettre(t, "programmer", d.id, { next_at: iso(at), reason });
  }
  timer(at, type, id, extra = {}) {
    this.timers.push({ at, seq: this.seq++, type, id, ...extra });
  }
  journaliser(t, request_id, detail) {
    this.emettre(t, "journaliser", request_id, detail);
  }
  alerter(t, request_id, code, severity) {
    this.emettre(t, "alerter", request_id, { code, severity });
  }

  // --- périodes et échéances (EX-8.4, règle 1) ----------------------------

  cle(s) {
    return `${s.org_id}|${s.journal_id}|${s.period_start}`;
  }
  /**
   * La période d'un sujet, créée au besoin (EX-8.4, règle 1) : ses échéances
   * déjà atteintes sont tenues ouvertes, les autres programmées (`nouvelle`) ;
   * une période connue à sa clôture seulement (`fermee`) n'a aucune échéance
   * de point à tenir.
   */
  periode(sujet, t, { nouvelle = false, fermee = false } = {}) {
    const k = this.cle(sujet);
    let p = this.periodes.get(k);
    if (p) return p;
    p = { org_id: sujet.org_id, journal_id: sujet.journal_id, period_start: sujet.period_start, close: fermee, echeances: new Map(), dernierAncre: 0, dernierPoint: null, dernierPointAt: null };
    this.periodes.set(k, p);
    if (fermee) return p;
    for (let i = 1; i < this.nT; i++) {
      const at = this.D(p, i);
      if (at <= t) p.echeances.set(i, { state: "ouverte", demande: null });
      else {
        p.echeances.set(i, { state: "fermee", demande: null });
        if (nouvelle) this.timer(at, "echeance", k, { k: i });
      }
    }
    return p;
  }
  D(p, k) {
    return (p.period_start + k * this.cfg.rfc3161.checkpoints.interval_s) * 1000;
  }
  /**
   * Dernier point contresigné de la période (EX-4.3, EX-8.4 règle 1) : le plus
   * grand tree_size des demandes jeton_point dont le jeton est obtenu ou dont la
   * demande n'est pas dans un état final ; une demande refusee, remplacee ou
   * sans_objet ne compte pas. Recalculé à chaque décision, comme au démarrage.
   */
  dernierContresigne(p) {
    let m = 0;
    const c = this.cle(p);
    for (const d of this.demandes.values()) {
      if (d.kind !== "jeton_point" || this.cle(d.subject) !== c) continue;
      if (d.state === "obtenue" || !ETATS_FINAUX.has(d.state)) m = Math.max(m, d.subject.tree_size);
    }
    return m;
  }
  /** Échéance médiane k_m = ⌈n_T / 2⌉ de l'option mi_periode (EX-6.1) ; aucune si n_T = 1. */
  echeanceMediane() {
    return this.nT > 1 ? Math.ceil(this.nT / 2) : null;
  }
  finPeriode(p) {
    return (p.period_start + J.DUREE_PERIODE) * 1000;
  }

  // --- horloge et minuteries ----------------------------------------------

  avancer(t) {
    for (;;) {
      this.timers.sort((a, b) => a.at - b.at || a.seq - b.seq);
      if (!this.timers.length || this.timers[0].at > t) return;
      const m = this.timers.shift();
      this.declencher(m);
    }
  }
  declencher(m) {
    const t = m.at;
    const d = this.demandes.get(m.id);
    switch (m.type) {
      case "echeance": {
        const p = this.periodes.get(m.id);
        const e = p?.echeances.get(m.k);
        if (!e || e.state !== "fermee") return;
        e.state = "ouverte";
        this.emettre(t, "echeance", null, { k: m.k, state: "ouverte" });
        return;
      }
      case "attente_registre": {
        if (!d || d.state !== "attente_registre" || this.int(d.id).attenteAt !== t) return;
        this.examinerAttenteRegistre(d, t);
        break;
      }
      case "reprise": {
        if (!d || ETATS_FINAUX.has(d.state)) return;
        const s = this.int(d.id);
        if (s.reprises.get(m.provider ?? null) !== t) return;
        s.reprises.delete(m.provider ?? null);
        if (d.kind.startsWith("ots_")) this.soumettreOts(d, t);
        else this.pret(d, this.prestataires.get(m.provider), t);
        break;
      }
      case "releve": {
        if (!d || ETATS_FINAUX.has(d.state)) return;
        const s = this.int(d.id);
        const secours = this.roles.secours;
        if (!secours || s.engages.has(secours.id) || s.epuises.has(secours.id)) return;
        this.relever(d, t, "delai");
        break;
      }
      case "mise_a_niveau": {
        if (!d || d.state !== "en_attente" || this.int(d.id).miseANiveauAt !== t) return;
        const n = d.attempts.length + 1;
        d.attempts.push(this.tentative(d, { n, provider: null, t, nonce: null, detail: "mise a niveau demandee" }));
        this.int(d.id).enCours.set(null, n);
        // EX-8.5, règle 1 : la ligne est écrite avant que la requête parte.
        this.ecrire(d, t, "en_attente");
        this.emettre(t, "mettre_a_niveau_ots", d.id, { attempt: n });
        break;
      }
      case "inclusion": {
        if (!d || d.state !== "envoyee" || this.int(d.id).inclusionAt !== t) return;
        const s = this.int(d.id);
        s.renvois++;
        this.alerter(t, d.id, "inclusion_late", s.renvois === 1 ? "mineure" : "majeure");
        this.cloreTentativeRegistre(d, t);
        const n = d.attempts.length + 1;
        d.attempts.push(this.tentative(d, { n, provider: null, t, nonce: null, detail: s.renvois === 1 ? "renvoi des memes octets" : "remplacement au meme nonce" }));
        this.ecrire(d, t, "envoyee");
        this.emettre(t, "envoyer_registre", d.id, this.detailRegistre(d));
        s.inclusionAt = t + this.cfg.registry.inclusion_alert_s * 1000;
        this.timer(s.inclusionAt, "inclusion", d.id);
        break;
      }
      case "repli_cloture": {
        if (!d || d.state !== "attente_registre") return;
        const ancre = this.demandes.get(idDemande("ancre_registre_periode", d.subject.hash)) ?? null;
        if (!ancre || ancre.state === "obtenue" || ancre.state === "refusee") return;
        this.repliCloture(d, t);
        break;
      }
      case "cadence": {
        // EX-8.15 : aucun point admis pendant plus de 2 × c_K (alerte point_manquant, majeure).
        const p = this.periodes.get(m.id);
        if (!p || p.close || p.dernierPointAt !== m.depuis) return;
        this.journaliser(t, null, { event: "point_manquant", last_checkpoint_ts: p.dernierPoint.declared_at, gap_s: Math.trunc((t - m.depuis) / 1000) });
        this.alerter(t, null, "point_manquant", "majeure");
        return;
      }
      case "dispatch":
        break;
      default:
        throw new ErreurAncrage(`minuterie inconnue ${m.type}`);
    }
    this.servir(t);
  }

  // --- entrées ----------------------------------------------------------------

  /** Reçoit une entrée ($defs/evenement_entree) et rend les actions qu'elle produit (minuteries échues comprises). */
  recevoir(entree) {
    if (!entree || typeof entree !== "object") throw new ErreurAncrage("entrée : objet attendu");
    const t = entree.t !== undefined ? ms(entree.t) : this.maintenant ? this.maintenant() : null;
    if (t === null) throw new ErreurAncrage("entrée sans instant et planificateur sans horloge");
    if (t < this.horloge) throw new ErreurAncrage(`horloge en recul : ${iso(t)} après ${iso(this.horloge)}`);
    if (!this.demarre && entree.type !== "demarrage") throw new ErreurAncrage("première entrée : demarrage attendu");
    const depart = this.actions.length;
    this.avancer(t);
    const data = entree.data ?? {};
    switch (entree.type) {
      case "demarrage":
        this.demarrer(t);
        break;
      case "point_produit":
        this.pointProduit(t, data);
        break;
      case "periode_close":
        this.periodeClose(t, data);
        break;
      case "tic":
        break;
      case "reponse_rfc3161":
        this.reponseRfc3161(t, data);
        break;
      case "reponse_ots":
        this.reponseOts(t, data);
        break;
      case "inclusion_registre":
        this.inclusionRegistre(t, data);
        break;
      case "echec_registre":
        this.echecRegistre(t, data);
        break;
      case "stockage_relu":
        this.reconstruire(t, data);
        break;
      case "arret":
        this.journaliser(t, null, { event: "anchoring_stopped", queue_entries: this.demandes.size });
        break;
      default:
        throw new ErreurAncrage(`type d'entrée inconnu : ${JSON.stringify(entree.type)}`);
    }
    for (;;) {
      this.servir(t);
      this.timers.sort((a, b) => a.at - b.at || a.seq - b.seq);
      if (!this.timers.length || this.timers[0].at > t) break;
      this.avancer(t);
    }
    this.horloge = t;
    return this.actions.slice(depart);
  }

  /** Charge la file relue au démarrage (lignes ou objets $defs/demande ; la dernière ligne d'un id fait foi). */
  charger(demandes) {
    for (const brut of demandes ?? []) {
      const d = typeof brut === "string" ? JSON.parse(brut) : copie(brut);
      if (!d || typeof d.id !== "string" || !SORTES.includes(d.kind) || !ETATS.includes(d.state)) throw new ErreurAncrage(`ligne de file mal formée : ${JSON.stringify(brut).slice(0, 80)}`);
      this.demandes.set(d.id, d);
    }
    this.relues = this.demandes.size;
  }

  demarrer(t) {
    this.demarre = true;
    this.journaliser(t, null, { event: "anchoring_started", queue_entries: this.relues });
    const file = this.file();
    // périodes relues : échéances et derniers points depuis les demandes de points
    const closes = new Set(file.filter((d) => SORTE_PERIODE(d.kind)).map((d) => this.cle(d.subject)));
    for (const d of file) this.periode(d.subject, t, { fermee: closes.has(this.cle(d.subject)) });
    for (const d of file) {
      const p = this.periode(d.subject, t);
      // Une demande refusee ne tient plus ses échéances : le point suivant les sert (EX-4.3, EX-8.8).
      if (d.kind === "jeton_point" && d.state !== "refusee") {
        const etat = d.state === "obtenue" ? "satisfaite" : d.state === "remplacee" ? "remplacee" : d.state === "sans_objet" ? "sans_objet" : "ouverte";
        for (const k of d.deadlines) p.echeances.set(k, { state: etat, demande: d.id });
      }
      if (d.kind === "ancre_registre_point" && d.state !== "refusee") p.dernierAncre = Math.max(p.dernierAncre, d.subject.tree_size);
    }
    for (const p of this.periodes.values()) {
      if (p.close) continue;
      for (const [k, e] of p.echeances) if (e.state === "fermee" && this.D(p, k) > t) this.timer(this.D(p, k), "echeance", this.cle(p), { k });
    }
    // EX-8.12 : transitions de reprise
    for (const d of file) {
      if (ETATS_FINAUX.has(d.state)) continue;
      const s = this.int(d.id);
      for (const a of d.attempts) {
        if (a.provider !== null) s.engages.add(a.provider);
        if (a.outcome === "echec_permanente" && a.provider !== null) s.epuises.add(a.provider);
      }
      if (d.kind.startsWith("ancre_registre_")) {
        if (d.state === "envoyee") {
          this.journaliser(t, d.id, { event: "anchor_retry", kind: d.kind, mode: "renvoi" });
          this.emettre(t, "envoyer_registre", d.id, this.detailRegistre(d));
          s.inclusionAt = t + this.cfg.registry.inclusion_alert_s * 1000;
          this.timer(s.inclusionAt, "inclusion", d.id);
        } else if (d.state === "a_envoyer") this.programmer(d, t, t, "attente_nonce");
        continue;
      }
      if (d.kind.startsWith("ots_")) {
        if (d.state === "envoyee") {
          this.perdreTentatives(d, t);
          d.due_at = iso(t);
          this.ecrire(d, t, "a_reprendre");
          this.programmer(d, t, t, "immediat");
          s.reprises.set(null, t);
          this.timer(t, "reprise", d.id, { provider: null });
        } else if (d.state === "a_reprendre") {
          const at = Math.max(ms(d.due_at ?? iso(t)), t);
          s.reprises.set(null, at);
          this.timer(at, "reprise", d.id, { provider: null });
        } else if (d.state === "en_attente") {
          const at = Math.max(ms(d.due_at ?? iso(t)), t);
          s.soumisA = ms(d.attempts[0]?.started_at ?? d.created_at);
          s.miseANiveauAt = at;
          this.programmer(d, t, at, "mise_a_niveau");
          this.timer(at, "mise_a_niveau", d.id);
        }
        continue;
      }
      // jetons
      if (d.state === "envoyee") {
        const perdus = this.perdreTentatives(d, t);
        d.due_at = iso(t);
        this.ecrire(d, t, "a_reprendre");
        this.programmer(d, t, t, "immediat");
        for (const prov of perdus) {
          s.reprises.set(prov, t);
          this.timer(t, "reprise", d.id, { provider: prov });
        }
      } else if (d.state === "attente_registre") {
        s.attenteAt = t;
        this.programmer(d, t, t, "attente_registre");
        this.timer(t, "attente_registre", d.id);
      } else if (d.state === "a_reprendre") {
        const at = Math.max(ms(d.due_at ?? iso(t)), t);
        const dernier = [...d.attempts].reverse().find((a) => a.provider !== null);
        const prov = dernier && !s.epuises.has(dernier.provider) ? dernier.provider : this.designe(d)?.id ?? null;
        if (prov !== null) {
          s.reprises.set(prov, at);
          this.timer(at, "reprise", d.id, { provider: prov });
        }
      } else if (d.state === "a_envoyer") this.pret(d, this.designe(d), t);
    }
  }
  /**
   * Reconstruction (EX-8.12) : à chaque démarrage, quel que soit l'état de la
   * file relue, les objets durables sans ancre obtenue que l'enregistreur relit
   * dans son stockage (CT-2 §12 ; entrée `stockage_relu` : `periods`, données de
   * periode_close, et `checkpoints`, données de point_produit) sont confrontés
   * aux demandes : toute demande manquante d'une période close est recréée, et
   * le dernier point de chaque période ouverte sans aucune demande est traité
   * comme un point admis ; `anchoring_queue_rebuilt` porte le nombre de demandes
   * recréées, et l'alerte file_perdue est levée s'il est non nul.
   */
  reconstruire(t, data) {
    const avant = this.demandes.size;
    const periodes = Array.isArray(data.periods) ? data.periods : [];
    const points = Array.isArray(data.checkpoints) ? data.checkpoints : [];
    const closes = new Set();
    for (const d of this.demandes.values()) if (SORTE_PERIODE(d.kind)) closes.add(this.cle(d.subject));
    let nPeriodes = 0;
    for (const m of periodes) {
      closes.add(this.cle(m));
      const sortes = ["ancre_registre_periode", "jeton_periode", ...(this.cfg.opentimestamps.enabled ? ["ots_periode"] : [])];
      const manquantes = sortes.filter((k) => !this.demandes.has(idDemande(k, m.period_hash)));
      if (!manquantes.length) continue;
      nPeriodes++;
      this.periodeClose(t, m, { seulement: manquantes });
    }
    const derniers = new Map();
    for (const k of points) {
      const c = this.cle(k);
      if (closes.has(c)) continue;
      const prec = derniers.get(c);
      if (!prec || ms(k.checkpoint_ts) >= ms(prec.checkpoint_ts)) derniers.set(c, k);
    }
    let nPoints = 0;
    for (const k of derniers.values()) {
      if (["ancre_registre_point", "jeton_point", "ots_point"].some((kind) => this.demandes.has(idDemande(kind, k.checkpoint_hash)))) continue;
      nPoints++;
      this.pointProduit(t, k);
    }
    const recreees = this.demandes.size - avant;
    this.journaliser(t, null, { event: "anchoring_queue_rebuilt", recreated: recreees, periods: nPeriodes, checkpoints: nPoints });
    if (recreees > 0) this.alerter(t, null, "file_perdue", "critique");
  }
  /** Tentatives en cours au redémarrage : la réponse a pu se perdre (EX-8.12). Rend les prestataires concernés. */
  perdreTentatives(d, t) {
    const perdus = [];
    for (const a of d.attempts) {
      if (a.outcome !== "en_cours") continue;
      a.outcome = "echec_transitoire";
      a.error_code = "redemarrage";
      a.next_at = iso(t);
      a.detail = "redemarrage : reponse non recue";
      perdus.push(a.provider);
    }
    return perdus;
  }

  // --- création des demandes --------------------------------------------------

  tentative(d, { n, provider, t, nonce, detail }) {
    return { n, provider, started_at: iso(t), nonce, correlation_id: identifiantCorrelation(d.kind, d.subject.hash, n), outcome: "en_cours", error_code: null, http_status: null, pki_status: null, failure_info: null, retry_after_s: null, next_at: null, detail };
  }
  creer(kind, sujet, deadlines, t) {
    const id = idDemande(kind, sujet.hash);
    if (this.demandes.has(id)) {
      this.journaliser(t, id, { event: "anchor_duplicate_ignored", state: this.demandes.get(id).state });
      return null;
    }
    const d = { version: 0, id, kind, subject: { kind: sujet.kind, org_id: sujet.org_id, journal_id: sujet.journal_id, period_start: sujet.period_start, hash: sujet.hash, tree_size: sujet.tree_size, declared_at: sujet.declared_at }, deadlines, state: "a_envoyer", created_at: iso(t), due_at: null, attempts: [], result: null, replaced_by: null };
    this.demandes.set(id, d);
    this.int(id);
    return d;
  }
  designe(d) {
    if (d.kind === "jeton_periode") return this.roles.principal;
    const role = this.cfg.rfc3161.checkpoints.provider_role;
    return role === "aucun" ? null : this.roles[role];
  }
  releveAdmise(d) {
    return !!this.roles.secours && (d.kind === "jeton_periode" || (d.kind === "jeton_point" && this.cfg.rfc3161.checkpoints.provider_role === "principal"));
  }
  delaiReleve(d) {
    return (d.kind === "jeton_periode" ? this.cfg.rfc3161.manifest.fallback_after_s : this.cfg.rfc3161.checkpoints.fallback_after_s) * 1000;
  }
  detailRegistre(d) {
    const s = d.subject;
    return s.kind === "point"
      ? { fingerprint: J.empreinteAncrePoint(s.org_id, s.journal_id, s.hash), doc_type: J.DOC_TYPE_POINT_DE_CONTROLE }
      : { fingerprint: anchorFingerprint({ orgId: s.org_id, journalId: s.journal_id, periodHash: s.hash }), doc_type: DOC_TYPE_PERIODE };
  }
  cleOccupee() {
    for (const d of this.demandes.values()) if (d.kind.startsWith("ancre_registre_") && d.state === "envoyee") return true;
    return false;
  }

  // --- point admis (EX-8.4, règles 1 et 3 ; EX-9.3 à EX-9.5) ---------------

  pointProduit(t, data) {
    const sujet = { kind: "point", org_id: data.org_id, journal_id: data.journal_id, period_start: data.period_start, hash: data.checkpoint_hash, tree_size: data.tree_size, declared_at: data.checkpoint_ts };
    const p = this.periode(sujet, t, { nouvelle: true });
    const tsPoint = ms(data.checkpoint_ts);
    if (this.demandes.has(idDemande("ancre_registre_point", sujet.hash)) || this.demandes.has(idDemande("jeton_point", sujet.hash))) {
      this.journaliser(t, null, { event: "anchor_duplicate_ignored", checkpoint_hash: sujet.hash });
      return;
    }
    // Cadence (EX-8.15, alerte point_manquant) : dernier point admis de la période ouverte ;
    // c'est aussi le point de clôture quand la période se ferme (repli d'EX-4.2).
    if (!p.close) {
      p.dernierPoint = { ...sujet };
      p.dernierPointAt = t;
      this.timer(t + 2 * this.cfg.checkpoint_interval_s * 1000, "cadence", this.cle(p), { depuis: t });
    }
    if (this.actives() >= this.cfg.queue.max_pending) {
      this.journaliser(t, null, { event: "anchor_queue_full", tree_size: sujet.tree_size, active: this.actives(), max_pending: this.cfg.queue.max_pending });
      this.alerter(t, null, "file_pleine", "critique");
      return;
    }
    // ancre au registre (EX-4.6, EX-9.3)
    const regle = this.cfg.registry.checkpoints;
    let ancre = null;
    if (regle !== "aucun" && (regle === "tous" || sujet.tree_size > p.dernierAncre)) {
      ancre = this.creer("ancre_registre_point", sujet, [], t);
      this.ecrire(ancre, t, "a_envoyer");
      p.dernierAncre = sujet.tree_size;
      for (const autre of this.file()) {
        if (autre === ancre || autre.kind !== "ancre_registre_point" || autre.state !== "a_envoyer" || this.cle(autre.subject) !== this.cle(sujet)) continue;
        autre.replaced_by = ancre.id;
        autre.due_at = null;
        this.emettre(t, "remplacer", autre.id, { replaced_by: ancre.id });
        this.ecrire(autre, t, "remplacee");
        this.journaliser(t, autre.id, { event: "anchor_replaced", replaced_by: ancre.id });
      }
      if (this.cleOccupee()) this.programmer(ancre, t, t, "attente_nonce");
      else this.envoyerRegistre(ancre, t);
    } else this.journaliser(t, null, { event: "checkpoint_not_anchored", reason: regle === "aucun" ? "ancre_des_points_desactivee" : "aucun_nouvel_evenement", tree_size: sujet.tree_size });
    // échéances (EX-4.3, EX-8.4 règle 1)
    const choisies = [];
    for (const [k, e] of p.echeances) if (e.state === "ouverte" && e.demande === null && this.D(p, k) <= tsPoint) choisies.push(k);
    if (choisies.length) {
      const designe = this.designe(d0(sujet));
      const nouveau = sujet.tree_size > this.dernierContresigne(p) || this.cfg.rfc3161.checkpoints.countersign_idle;
      if (nouveau && designe) {
        const j = this.creer("jeton_point", sujet, choisies, t);
        for (const k of choisies) {
          p.echeances.get(k).demande = j.id;
          this.emettre(t, "echeance", j.id, { k, state: "ouverte" });
        }
        if (ancre && ancre.state !== "obtenue") {
          this.ecrire(j, t, "attente_registre");
          const s = this.int(j.id);
          s.attenteAt = t + this.cfg.registry.squat_wait_s * 1000;
          this.programmer(j, t, s.attenteAt, "attente_registre");
          this.timer(s.attenteAt, "attente_registre", j.id);
        } else {
          this.ecrire(j, t, "a_envoyer");
          this.pret(j, designe, t);
        }
      } else {
        for (const k of choisies) {
          p.echeances.get(k).state = "sans_objet";
          this.emettre(t, "echeance", null, { k, state: "sans_objet" });
        }
        this.journaliser(t, null, { event: "deadline_sans_objet", reason: nouveau ? "contresignature_desactivee" : "aucun_nouvel_evenement", deadlines: choisies, tree_size: sujet.tree_size });
      }
    }
    // Option mi_periode (EX-6.1) : le point sélectionné à l'échéance médiane k_m = ⌈n_T / 2⌉ reçoit
    // une preuve OpenTimestamps, que l'échéance soit contresignée ou close sans_objet.
    const km = this.echeanceMediane();
    if (km !== null && choisies.includes(km) && this.cfg.opentimestamps.enabled && this.cfg.opentimestamps.checkpoint === "mi_periode") {
      const o = this.creer("ots_point", sujet, [], t);
      if (o) {
        this.ecrire(o, t, "a_envoyer");
        this.soumettreOts(o, t);
      }
    }
  }

  // --- clôture (EX-8.4, règle 2) -------------------------------------------------

  /**
   * Clôture (EX-8.4, règle 2) : les trois demandes de la période ; `seulement`
   * restreint les sortes créées (reconstruction d'EX-8.12).
   */
  periodeClose(t, data, { seulement = null } = {}) {
    const sujet = { kind: "periode", org_id: data.org_id, journal_id: data.journal_id, period_start: data.period_start, hash: data.period_hash, tree_size: null, declared_at: data.generated_at };
    const p = this.periode(sujet, t, { fermee: true });
    p.close = true;
    const veut = (kind) => seulement === null || seulement.includes(kind);
    const a = veut("ancre_registre_periode") ? this.creer("ancre_registre_periode", sujet, [], t) : null;
    const j = veut("jeton_periode") ? this.creer("jeton_periode", sujet, [], t) : null;
    const o = this.cfg.opentimestamps.enabled && veut("ots_periode") ? this.creer("ots_periode", sujet, [], t) : null;
    if (a) this.ecrire(a, t, "a_envoyer");
    if (j) this.ecrire(j, t, "attente_registre");
    if (o) this.ecrire(o, t, "a_envoyer");
    if (a) {
      if (this.cleOccupee()) this.programmer(a, t, t, "attente_nonce");
      else this.envoyerRegistre(a, t);
    }
    if (j) {
      const s = this.int(j.id);
      s.attenteAt = t + this.cfg.registry.inclusion_alert_s * 1000;
      this.programmer(j, t, s.attenteAt, "attente_registre");
      this.timer(s.attenteAt, "attente_registre", j.id);
      // EX-4.2, EX-8.4 règle 2 : repli sur le point de clôture si l'ancre de la période tarde.
      this.timer(t + this.cfg.registry.squat_wait_s * 1000, "repli_cloture", j.id);
    }
    if (o) this.soumettreOts(o, t);
  }

  /**
   * Repli de la clôture (EX-4.2, EX-8.4 règle 2) : `jeton_periode` attend
   * l'inclusion de l'ancre de la période depuis plus de `squat_wait_s` ; le
   * point de clôture, s'il engage un nouvel événement par rapport au dernier
   * point contresigné et n'a pas déjà de demande de jeton (point sélectionné par
   * une échéance antérieure, EX-4.3), reçoit une demande `jeton_point` sans
   * échéance auprès du prestataire des points. Sa requête ne révèle pas
   * `periodHash` ; le jeton qualifié de la clôture reste dû (EX-3.4, EX-4.5).
   */
  repliCloture(dp, t) {
    const p = this.periodes.get(this.cle(dp.subject));
    const k = p?.dernierPoint ?? null;
    if (!k || this.demandes.has(idDemande("jeton_point", k.hash))) return;
    if (!(k.tree_size > this.dernierContresigne(p) || this.cfg.rfc3161.checkpoints.countersign_idle)) return;
    const designe = this.designe(d0(k));
    if (!designe) return;
    const j = this.creer("jeton_point", k, [], t);
    if (!j) return;
    this.journaliser(t, j.id, { event: "checkpoint_closing_fallback", tree_size: k.tree_size, period_request: dp.id, squat_wait_s: this.cfg.registry.squat_wait_s });
    const ancre = this.demandes.get(idDemande("ancre_registre_point", k.hash)) ?? null;
    if (ancre && ancre.state !== "obtenue" && ancre.state !== "refusee") {
      this.ecrire(j, t, "attente_registre");
      const s = this.int(j.id);
      s.attenteAt = t + this.cfg.registry.squat_wait_s * 1000;
      this.programmer(j, t, s.attenteAt, "attente_registre");
      this.timer(s.attenteAt, "attente_registre", j.id);
    } else {
      this.ecrire(j, t, "a_envoyer");
      this.pret(j, designe, t);
    }
  }

  // --- envois -----------------------------------------------------------------------

  pret(d, prestataire, t) {
    if (!prestataire) return;
    if (!this.pretes.some((x) => x.id === d.id && x.provider === prestataire.id)) this.pretes.push({ id: d.id, provider: prestataire.id, seq: this.seq++ });
    void t;
  }
  rang(d) {
    return d.kind === "jeton_periode" ? 0 : 1;
  }
  servir(t) {
    // 1. requêtes RFC 3161 prêtes (EX-8.7 : jeton_periode d'abord, puis jeton_point par checkpoint_ts ; min_interval_ms)
    this.pretes.sort((x, y) => {
      const a = this.demandes.get(x.id);
      const b = this.demandes.get(y.id);
      return this.rang(a) - this.rang(b) || a.subject.period_start - b.subject.period_start || (a.subject.declared_at < b.subject.declared_at ? -1 : a.subject.declared_at > b.subject.declared_at ? 1 : 0) || x.seq - y.seq;
    });
    for (const e of [...this.pretes]) {
      const d = this.demandes.get(e.id);
      const pr = this.prestataires.get(e.provider);
      if (!d || ETATS_FINAUX.has(d.state) || !pr) {
        this.pretes = this.pretes.filter((x) => x !== e);
        continue;
      }
      const libre = (this.dernierEnvoi.get(pr.id) ?? -Infinity) + pr.min_interval_ms;
      if (libre <= t) {
        this.pretes = this.pretes.filter((x) => x !== e);
        this.envoyerRfc3161(d, pr, t);
      } else {
        const s = this.int(d.id);
        if (s.differe !== libre) {
          s.differe = libre;
          this.programmer(d, t, libre, "backoff");
          this.timer(libre, "dispatch", d.id);
        }
      }
    }
    // 2. registre : une transaction par clé de chaîne (EX-9.4), la période d'abord (EX-8.7)
    if (!this.cleOccupee()) {
      const candidats = this.file().filter((d) => d.kind.startsWith("ancre_registre_") && d.state === "a_envoyer");
      candidats.sort((a, b) => (SORTE_PERIODE(a.kind) ? 0 : 1) - (SORTE_PERIODE(b.kind) ? 0 : 1));
      if (candidats.length) this.envoyerRegistre(candidats[0], t);
    }
    // 3. soumissions OpenTimestamps en attente d'envoi
    for (const d of this.file()) if (d.kind.startsWith("ots_") && d.state === "a_envoyer") this.soumettreOts(d, t);
  }
  envoyerRfc3161(d, pr, t) {
    const s = this.int(d.id);
    const n = d.attempts.length + 1;
    const nonce = this.aleatoire.nonceTsa({ kind: d.kind, subject: d.subject, n });
    const requete = construireRequete({ digest: d.subject.hash, nonce, policy_oid: pr.policy_oid });
    d.attempts.push(this.tentative(d, { n, provider: pr.id, t, nonce: hexNonce(nonce), detail: "requete envoyee" }));
    this.dernierEnvoi.set(pr.id, t);
    d.due_at = null;
    s.differe = null;
    // EX-8.5, règle 1 (AN-32) : la ligne envoyee, avec le nonce et l'attempt_id, précède l'envoi.
    this.ecrire(d, t, "envoyee");
    this.emettre(t, "envoyer_rfc3161", d.id, { provider: pr.id, attempt: n, digest: d.subject.hash, nonce: hexNonce(nonce), policy_oid: pr.policy_oid, request_sha256: sha256Hex(requete), request_size: requete.length });
    s.enCours.set(pr.id, n);
    s.engages.add(pr.id);
    if (n === 1 && this.releveAdmise(d) && pr.id !== this.roles.secours.id) this.timer(t + this.delaiReleve(d), "releve", d.id);
  }
  envoyerRegistre(d, t) {
    const s = this.int(d.id);
    const n = d.attempts.length + 1;
    d.attempts.push(this.tentative(d, { n, provider: null, t, nonce: null, detail: "transaction envoyee" }));
    d.due_at = null;
    this.ecrire(d, t, "envoyee");
    this.emettre(t, "envoyer_registre", d.id, this.detailRegistre(d));
    s.inclusionAt = t + this.cfg.registry.inclusion_alert_s * 1000;
    this.timer(s.inclusionAt, "inclusion", d.id);
  }
  soumettreOts(d, t) {
    const s = this.int(d.id);
    const n = d.attempts.length + 1;
    const nonce = this.aleatoire.nonceOts({ kind: d.kind, subject: d.subject });
    const cals = this.cfg.opentimestamps.calendars;
    d.attempts.push(this.tentative(d, { n, provider: null, t, nonce: null, detail: `soumission a ${cals.length} calendriers` }));
    d.due_at = null;
    this.ecrire(d, t, "envoyee");
    this.emettre(t, "soumettre_ots", d.id, { digest: d.subject.hash, nonce: "0x" + Buffer.from(nonce).toString("hex"), calendars: [...cals] });
    s.enCours.set(null, n);
    s.soumisA ??= t;
  }
  relever(d, t, cause) {
    const s = this.int(d.id);
    const secours = this.roles.secours;
    this.emettre(t, "releve", d.id, { provider: secours.id });
    this.journaliser(t, d.id, { event: "anchor_fallback", to: secours.id, reason: cause });
    this.pret(d, secours, t);
  }

  // --- registre (EX-8.10, EX-9.6, EX-9.7) -----------------------------------------

  jetonDuSujet(d) {
    return this.demandes.get(idDemande(d.subject.kind === "point" ? "jeton_point" : "jeton_periode", d.subject.hash)) ?? null;
  }
  inclusionRegistre(t, data) {
    const d = this.demandes.get(data.request_id);
    if (!d || !d.kind.startsWith("ancre_registre_") || ETATS_FINAUX.has(d.state) || d.state === "a_envoyer") {
      this.journaliser(t, data.request_id ?? null, { event: "anchor_duplicate_ignored", reason: d ? `etat ${d.state}` : "demande_inconnue" });
      return;
    }
    const s = this.int(d.id);
    const att = d.attempts[d.attempts.length - 1];
    att.outcome = "obtenue";
    att.detail = `ancre incluse au bloc ${data.block_number}`;
    d.result = { sha256: data.capture_sha256, size: TAILLE_INDEX_CAPTURE, provider: null, obtained_at: iso(t), bound: null };
    d.due_at = null;
    this.emettre(t, "stocker", d.id, { sha256: data.capture_sha256, size: TAILLE_INDEX_CAPTURE, bound: null });
    this.ecrire(d, t, "obtenue");
    const envoi = ms(d.attempts[0].started_at);
    if (t - envoi > this.cfg.registry.inclusion_alert_s * 1000 && s.renvois === 0) this.alerter(t, d.id, "inclusion_late", "mineure");
    const j = this.jetonDuSujet(d);
    if (j && j.state === "attente_registre") this.pret(j, this.designe(j), t);
  }
  echecRegistre(t, data) {
    const d = this.demandes.get(data.request_id);
    if (!d || !d.kind.startsWith("ancre_registre_") || ETATS_FINAUX.has(d.state)) {
      this.journaliser(t, data.request_id ?? null, { event: "anchor_duplicate_ignored", reason: d ? `etat ${d.state}` : "demande_inconnue" });
      return;
    }
    const att = d.attempts[d.attempts.length - 1] ?? null;
    if (data.code === "empreinte_squattee") {
      if (att) {
        att.outcome = "echec_permanente";
        att.error_code = data.code;
        att.detail = "empreinte deja ancree par un tiers";
      }
      d.due_at = null;
      this.ecrire(d, t, "refusee");
      this.alerter(t, d.id, "empreinte_squattee", "critique");
      this.journaliser(t, d.id, { event: "anchor_refused", error_code: data.code });
      const j = this.jetonDuSujet(d);
      if (j && j.state === "attente_registre") this.pret(j, this.designe(j), t);
      return;
    }
    this.cloreTentativeRegistre(d, t, data.code, `registre : ${data.code}`);
    this.journaliser(t, d.id, { event: "anchor_retry", kind: d.kind, error_code: data.code });
    const n = d.attempts.length + 1;
    d.attempts.push(this.tentative(d, { n, provider: null, t, nonce: null, detail: "renvoi des memes octets" }));
    this.ecrire(d, t, "envoyee");
    this.emettre(t, "envoyer_registre", d.id, this.detailRegistre(d));
    const s = this.int(d.id);
    s.inclusionAt = t + this.cfg.registry.inclusion_alert_s * 1000;
    this.timer(s.inclusionAt, "inclusion", d.id);
  }
  /** Clôt la tentative de registre en cours (sans reçu) avant un renvoi ou un remplacement au même nonce. */
  cloreTentativeRegistre(d, t, code = "recu_absent", detail = null) {
    const att = d.attempts[d.attempts.length - 1] ?? null;
    if (!att || att.outcome !== "en_cours") return;
    att.outcome = "echec_transitoire";
    att.error_code = code;
    att.next_at = iso(t);
    att.detail = detail ?? `aucun recu en ${this.cfg.registry.inclusion_alert_s} s`;
  }
  examinerAttenteRegistre(d, t) {
    const s = this.int(d.id);
    const ancre = this.demandes.get(idDemande(d.subject.kind === "point" ? "ancre_registre_point" : "ancre_registre_periode", d.subject.hash)) ?? null;
    if (!ancre || ancre.state === "obtenue" || ancre.state === "refusee") {
      this.pret(d, this.designe(d), t);
      return;
    }
    if (d.kind === "jeton_point") {
      const limite = ms(d.created_at) + this.cfg.registry.squat_wait_s * 1000;
      if (t < limite) {
        s.attenteAt = limite;
        this.programmer(d, t, limite, "attente_registre");
        this.timer(limite, "attente_registre", d.id);
        return;
      }
      this.journaliser(t, d.id, { event: "ordre_ancres_non_respecte", tree_size: d.subject.tree_size, squat_wait_s: this.cfg.registry.squat_wait_s });
      this.pret(d, this.designe(d), t);
      return;
    }
    const age = Math.trunc((t - ms(d.created_at)) / 1000);
    if (age >= this.cfg.registry.inclusion_alert_s) {
      this.journaliser(t, d.id, { event: "registry_pending", age_s: age });
      if (!s.alertes.has("registry_pending")) {
        s.alertes.add("registry_pending");
        this.alerter(t, d.id, "registry_pending", "majeure");
      }
    }
    if (age >= this.cfg.queue.anchor_pending_alert_s && !s.alertes.has("anchor_pending")) {
      s.alertes.add("anchor_pending");
      this.journaliser(t, d.id, { event: "anchor_pending", age_s: age });
      this.alerter(t, d.id, "anchor_pending", "majeure");
    }
    s.attenteAt = t + this.cfg.registry.inclusion_alert_s * 1000;
    this.programmer(d, t, s.attenteAt, "attente_registre");
    this.timer(s.attenteAt, "attente_registre", d.id);
  }

  // --- réponses RFC 3161 (EX-5.10 à EX-5.12, EX-8.6, EX-8.8, EX-8.9) -------------

  classer(d, att, data, t) {
    const f = this.cfg.rfc3161.freshness;
    const res = { issue: "echec_permanente", code: null, piece: false, critique: false, avertissements: [], bound: null, detail: "" };
    const nomHttp = () => `http ${data.http_status}${data.retry_after_s != null ? ` ; Retry-After ${data.retry_after_s} s` : ""}`;
    if (data.transport === "erreur_transport") return { ...res, issue: "echec_transitoire", code: "erreur_transport", detail: "erreur de transport" };
    if (data.transport === "delai") return { ...res, issue: "echec_transitoire", code: "delai", detail: "delai de reponse depasse" };
    if (data.transport !== "reponse") return { ...res, code: "reponse_illisible", detail: "transport inconnu" };
    if (data.http_status !== 200) return { ...res, issue: HTTP_TRANSITOIRES.has(data.http_status) ? "echec_transitoire" : "echec_permanente", code: `http_${data.http_status}`, detail: nomHttp() };
    // EX-5.10, étape 1 : Content-Type et taille, quand l'entrée les porte (EX-5.5).
    if (data.content_type !== undefined && data.content_type !== null && !TYPES_CONTENU_REPONSE.includes(String(data.content_type).split(";")[0].trim().toLowerCase())) return { ...res, code: "type_contenu", detail: `Content-Type ${data.content_type} non admis` };
    if (Number.isInteger(data.body_size) && data.body_size > TAILLE_MAX_REPONSE) return { ...res, code: "taille", detail: `corps de ${data.body_size} octets, au plus ${TAILLE_MAX_REPONSE}` };
    const st = data.pki_status;
    if (!Number.isInteger(st)) return { ...res, code: "reponse_illisible", detail: "TimeStampResp illisible" };
    if (st === 2) {
      const fi = data.failure_info;
      if (fi === null || fi === undefined) return { ...res, code: "statut_2", detail: "PKIStatus 2 (rejection)" };
      return { ...res, issue: ECHECS_TRANSITOIRES.has(fi) ? "echec_transitoire" : "echec_permanente", code: `echec_${fi}`, detail: `PKIStatus 2 (rejection) ; ${fi}` };
    }
    if (st === 3) return { ...res, issue: "echec_transitoire", code: "statut_3", detail: "PKIStatus 3 (waiting)" };
    if (st === 4 || st === 5) return { ...res, code: `statut_${st}`, critique: true, detail: `PKIStatus ${st} (${NOMS_PKI[st]})` };
    if (st !== 0 && st !== 1) return { ...res, code: `statut_${st}`, detail: `PKIStatus ${st} inconnu` };
    if (data.imprint_matches !== true) return { ...res, code: "empreinte_differente", piece: true, detail: "messageImprint different de l'empreinte demandee" };
    if (data.nonce_in_response === null || data.nonce_in_response === undefined) return { ...res, code: "nonce_absent", piece: true, detail: "nonce absent du TSTInfo" };
    if (data.nonce_in_response !== att.nonce) return { ...res, code: "nonce_different", piece: true, detail: `nonce ${data.nonce_in_response} different de ${att.nonce}` };
    // EX-5.10, étape 5 : politique (résultat d'evaluerReponse porté par l'entrée, absent ou « conforme » sinon).
    if (data.policy_check === "politique_differente" || data.policy_check === "politique_refusee") return { ...res, code: data.policy_check, piece: true, detail: data.policy_check === "politique_differente" ? "politique differente de la politique demandee" : "politique hors de accepted_policies" };
    const passes = new Set(data.checks_passed ?? []);
    for (let i = 1; i <= 9; i++) if (!passes.has(`T-${i}`)) return { ...res, code: `verification_T-${i}`, piece: true, detail: `verification T-${i} en echec` };
    const genTime = ms(data.gen_time);
    const bound = genTime + (data.accuracy_s ?? 0) * 1000;
    const envoi = ms(att.started_at);
    const s = this.int(d.id);
    if (t - envoi > f.max_response_delay_s * 1000) {
      if (s.tardives + 1 < 3) return { ...res, issue: "reponse_tardive", code: "reponse_tardive", piece: true, bound, detail: `reponse recue ${Math.trunc((t - envoi) / 1000)} s apres l'envoi` };
      res.avertissements.push("reponse_tardive");
    }
    if (Math.abs(genTime - envoi) > f.clock_tolerance_s * 1000) res.avertissements.push("horloge_suspecte");
    return { ...res, issue: "obtenue", code: null, bound, detail: `${NOMS_PKI[st]} ; T-1 a T-9 reussies${res.avertissements.length ? " ; avertissement " + res.avertissements.join(", ") : ""}` };
  }
  reponseRfc3161(t, data) {
    const d = this.demandes.get(data.request_id);
    const att = d?.attempts.find((a) => a.n === data.attempt) ?? null;
    const jeton = Number.isInteger(data.pki_status) && data.pki_status <= 1 && typeof data.token_sha256 === "string";
    if (!d || !att || !d.kind.startsWith("jeton_")) {
      this.journaliser(t, data.request_id ?? null, { event: "anchor_response_rejected", error_code: "tentative_inconnue", attempt: data.attempt ?? null });
      return;
    }
    if (ETATS_FINAUX.has(d.state) || att.outcome !== "en_cours") {
      // réponse à une tentative close (remplacée, relevée, redémarrage) : pièce conservée, état inchangé (EX-8.5, règle 2)
      if (jeton) this.emettre(t, "stocker", d.id, { sha256: data.token_sha256, size: data.token_size, bound: data.gen_time ? iso(ms(data.gen_time) + (data.accuracy_s ?? 0) * 1000) : null });
      this.journaliser(t, d.id, { event: "anchor_response_rejected", error_code: ETATS_FINAUX.has(d.state) ? "demande_close" : "tentative_close", attempt: att.n, provider: att.provider, kept: jeton });
      return;
    }
    const s = this.int(d.id);
    const pr = this.prestataires.get(att.provider);
    const r = this.classer(d, att, data, t);
    att.http_status = data.http_status ?? null;
    att.pki_status = data.pki_status ?? null;
    att.failure_info = data.failure_info ?? null;
    att.retry_after_s = data.retry_after_s ?? null;
    att.error_code = r.code;
    att.detail = r.detail;
    s.enCours.delete(pr.id);
    if (r.issue === "obtenue") {
      att.outcome = "obtenue";
      s.tardives = 0;
      d.result = { sha256: data.token_sha256, size: data.token_size, provider: pr.id, obtained_at: iso(t), bound: iso(r.bound) };
      d.due_at = null;
      this.emettre(t, "stocker", d.id, { sha256: data.token_sha256, size: data.token_size, bound: iso(r.bound) });
      this.ecrire(d, t, "obtenue");
      this.satisfaire(d, t, pr, r);
      return;
    }
    if (r.piece && jeton) this.emettre(t, "stocker", d.id, { sha256: data.token_sha256, size: data.token_size, bound: r.bound === null ? null : iso(r.bound) });
    const classe = r.issue === "echec_permanente" ? "permanente" : "transitoire";
    att.outcome = r.issue;
    this.emettre(t, "rejeter_reponse", d.id, { error_code: r.code, class: classe });
    this.journaliser(t, d.id, { event: "anchor_response_rejected", error_code: r.code, attempt: att.n, provider: pr.id });
    if (r.critique) this.alerter(t, d.id, "revoque", "critique");
    if (classe === "transitoire") {
      if (r.issue === "reponse_tardive") s.tardives++;
      const { delai, raison } = this.attenteReprise(d, pr, data);
      const next = t + delai;
      att.next_at = iso(next);
      s.reprises.set(pr.id, next);
      if (s.enCours.size === 0) {
        d.due_at = iso(next);
        this.ecrire(d, t, "a_reprendre");
      } else this.ecrire(d, t, "envoyee");
      this.programmer(d, t, next, raison);
      this.timer(next, "reprise", d.id, { provider: pr.id });
      return;
    }
    // permanente : relève ou refus (EX-5.12, EX-8.8)
    s.epuises.add(pr.id);
    s.reprises.delete(pr.id);
    const secours = this.roles.secours;
    if (this.releveAdmise(d) && !s.engages.has(secours.id) && !s.epuises.has(secours.id)) {
      this.ecrire(d, t, s.enCours.size ? "envoyee" : "a_envoyer");
      this.relever(d, t, r.code);
      return;
    }
    if (s.enCours.size || s.reprises.size) {
      this.ecrire(d, t, s.enCours.size ? "envoyee" : "a_reprendre");
      return;
    }
    if (d.kind === "jeton_point") {
      d.due_at = null;
      this.ecrire(d, t, "refusee");
      this.alerter(t, d.id, "prestataires_epuises", "majeure");
      this.journaliser(t, d.id, { event: "anchor_refused", error_code: r.code, provider: pr.id });
      this.rendreEcheances(d);
      return;
    }
    // jeton_periode : jamais abandonné (EX-4.5, EX-5.7) ; reprise au pas retry.max_ms en alternant les prestataires
    if (!s.alertes.has("prestataires_epuises")) {
      s.alertes.add("prestataires_epuises");
      this.alerter(t, d.id, "prestataires_epuises", "critique");
    }
    const suivant = secours && pr.id === this.roles.principal.id ? secours : this.roles.principal;
    const next = t + this.cfg.rfc3161.retry.max_ms;
    att.next_at = iso(next);
    s.epuises.delete(suivant.id);
    s.reprises.set(suivant.id, next);
    d.due_at = iso(next);
    this.ecrire(d, t, "a_reprendre");
    this.programmer(d, t, next, "backoff");
    this.timer(next, "reprise", d.id, { provider: suivant.id });
  }
  /**
   * Une demande de point refusee rend la main à ses échéances encore ouvertes :
   * elle ne compte plus comme contresignée (EX-4.3, EX-8.4 règle 1) et le point
   * suivant les sert ; une demande refusee ne tient aucune échéance au démarrage.
   */
  rendreEcheances(d) {
    const p = this.periodes.get(this.cle(d.subject));
    if (!p) return;
    for (const k of d.deadlines) {
      const e = p.echeances.get(k);
      if (e && e.state === "ouverte" && e.demande === d.id) e.demande = null;
    }
  }
  attenteReprise(d, pr, data) {
    const s = this.int(d.id);
    const cle = pr?.id ?? null;
    const k = (s.k.get(cle) ?? 0) + 1;
    s.k.set(cle, k);
    const immediat = data.http_status === 408 && !s.premier408.has(cle);
    if (immediat) s.premier408.add(cle);
    const retryAfter = (data.http_status === 429 || data.http_status === 503) && data.retry_after_s !== null && data.retry_after_s !== undefined;
    const gigue = immediat || retryAfter ? 0 : this.aleatoire.gigue();
    const a = calculerAttente({ http_status: data.http_status ?? null, retry_after_s: data.retry_after_s ?? null, k, premier_408_servi: !immediat, retry: this.cfg.rfc3161.retry, gigue });
    return { delai: a.delay_ms, raison: a.reason };
  }
  /** Jeton promu : échéances satisfaites, journal, alertes, EX-4.4 sur les demandes antérieures de la période. */
  satisfaire(d, t, pr, r) {
    const p = this.periode(d.subject, t);
    const avert = r.avertissements.length ? { warnings: [...r.avertissements] } : {};
    let kmax;
    if (d.kind === "jeton_point") {
      for (const k of d.deadlines) {
        p.echeances.get(k).state = "satisfaite";
        this.emettre(t, "echeance", d.id, { k, state: "satisfaite" });
      }
      // Repli de la clôture (EX-4.2) : aucune échéance ; les délais se comptent depuis la fin de la période.
      const repli = d.deadlines.length === 0;
      kmax = repli ? this.nT : Math.max(...d.deadlines);
      const reference = repli ? this.finPeriode(p) : this.D(p, kmax);
      const ts = ms(d.subject.declared_at);
      // EX-3.5 et 8.9 : quatre composantes de d_jeton, différences des instants
      // tronqués à la seconde depuis la référence (leur somme est d_jeton_s) :
      // point, premier envoi, envoi de la tentative promue, borne du jeton.
      const promue = d.attempts.find((a) => a.outcome === "obtenue");
      const sec = (x) => Math.trunc((x - reference) / 1000);
      const s1 = sec(ts), s2 = sec(ms(d.attempts[0].started_at)), s3 = sec(ms(promue.started_at)), s4 = sec(r.bound);
      this.journaliser(t, d.id, { event: "checkpoint_countersigned", tree_size: d.subject.tree_size, provider: pr.id, deadlines: [...d.deadlines], d_jeton_s: s4, d_point_s: s1, d_attente_s: s2 - s1, d_releve_s: s3 - s2, d_tsa_s: s4 - s3, ...(repli ? { closing_fallback: true } : {}), ...avert });
    } else {
      kmax = this.nT;
      this.emettre(t, "echeance", d.id, { k: this.nT, state: "satisfaite" });
      this.journaliser(t, d.id, { event: "period_timestamped", provider: pr.id, d_jeton_s: Math.trunc((r.bound - this.finPeriode(p)) / 1000), ...avert });
    }
    if (r.avertissements.includes("horloge_suspecte")) this.alerter(t, d.id, "horloge_suspecte", "mineure");
    // EX-5.11 : la troisième réponse tardive promue l'est avec une alerte.
    if (r.avertissements.includes("reponse_tardive")) this.alerter(t, d.id, "reponse_tardive_promue", "mineure");
    if (d.kind === "jeton_point") {
      // AN-2 (EX-4.3) : jeton antérieur au point déclaré, ou contresignature plus de c_T après lui.
      const ts = ms(d.subject.declared_at);
      if (r.bound < ts - this.cfg.rfc3161.freshness.clock_tolerance_s * 1000) this.alerter(t, d.id, "jeton_anterieur_au_point", "majeure");
      if (r.bound - ts > this.cfg.rfc3161.checkpoints.interval_s * 1000) this.alerter(t, d.id, "contresignature_tardive", "mineure");
    }
    // EX-4.4 : aucune demande antérieure de point n'est rattrapée
    const role = this.cfg.rfc3161.checkpoints.provider_role;
    const severite = role === "interne" ? "mineure" : "majeure";
    const remplacees = new Set();
    for (const [k, e] of p.echeances) {
      if (k >= kmax || e.state !== "ouverte") continue;
      const r2 = e.demande ? this.demandes.get(e.demande) : null;
      if (r2 && !ETATS_FINAUX.has(r2.state) && !remplacees.has(r2.id)) {
        remplacees.add(r2.id);
        r2.replaced_by = d.id;
        r2.due_at = null;
        this.emettre(t, "remplacer", r2.id, { replaced_by: d.id });
        this.ecrire(r2, t, "remplacee");
        for (const k2 of r2.deadlines) {
          p.echeances.get(k2).state = "remplacee";
          this.emettre(t, "echeance", r2.id, { k: k2, state: "remplacee" });
        }
        this.journaliser(t, r2.id, { event: "checkpoint_anchor_late", tree_size: r2.subject.tree_size, deadlines: [...r2.deadlines], replaced_by: d.id, window_s: Math.trunc((r.bound - this.D(p, Math.min(...r2.deadlines))) / 1000) });
        this.alerter(t, r2.id, "checkpoint_anchor_late", severite);
      } else if (!r2 || ETATS_FINAUX.has(r2.state)) {
        e.state = "remplacee";
        this.emettre(t, "echeance", r2 ? r2.id : null, { k, state: "remplacee" });
      }
    }
    // Le jeton de clôture rend sans objet un repli de clôture encore en cours (EX-4.2).
    if (d.kind === "jeton_periode") {
      for (const r2 of this.file()) {
        if (r2.kind !== "jeton_point" || r2.deadlines.length !== 0 || ETATS_FINAUX.has(r2.state) || this.cle(r2.subject) !== this.cle(d.subject)) continue;
        r2.replaced_by = d.id;
        r2.due_at = null;
        this.emettre(t, "remplacer", r2.id, { replaced_by: d.id });
        this.ecrire(r2, t, "remplacee");
        this.journaliser(t, r2.id, { event: "anchor_replaced", replaced_by: d.id });
      }
    }
  }

  // --- réponses OpenTimestamps (EX-8.11) ------------------------------------------

  reponseOts(t, data) {
    const d = this.demandes.get(data.request_id);
    if (!d || !d.kind.startsWith("ots_") || ETATS_FINAUX.has(d.state)) {
      this.journaliser(t, data.request_id ?? null, { event: "anchor_response_rejected", error_code: ETATS_FINAUX.has(d?.state) ? "demande_close" : "tentative_inconnue" });
      return;
    }
    const s = this.int(d.id);
    const att = [...d.attempts].reverse().find((a) => a.outcome === "en_cours") ?? null;
    if (!att) {
      this.journaliser(t, d.id, { event: "anchor_response_rejected", error_code: "tentative_inconnue" });
      return;
    }
    s.enCours.delete(null);
    const o = this.cfg.opentimestamps;
    const n = data.calendars_answered ?? 0;
    const stocker = () => {
      d.result = { sha256: data.proof_sha256, size: data.proof_size, provider: null, obtained_at: iso(t), bound: null };
      this.emettre(t, "stocker", d.id, { sha256: data.proof_sha256, size: data.proof_size, bound: null });
    };
    if (d.state === "envoyee" || d.state === "a_reprendre") {
      if (data.attestation === "aucune" || n < o.min_responses) {
        att.outcome = "echec_transitoire";
        att.error_code = "reponses_insuffisantes";
        att.detail = `${n} calendrier(s) ; moins de ${o.min_responses} reponses valables`;
        const { delai, raison } = this.attenteReprise(d, null, {});
        const next = t + delai;
        att.next_at = iso(next);
        s.reprises.set(null, next);
        d.due_at = iso(next);
        this.ecrire(d, t, "a_reprendre");
        this.programmer(d, t, next, raison);
        this.timer(next, "reprise", d.id, { provider: null });
        return;
      }
      att.outcome = "obtenue";
      if (data.attestation === "complete") {
        att.detail = `${n} calendriers ; attestation Bitcoin`;
        stocker();
        d.due_at = null;
        this.ecrire(d, t, "complete");
        this.journaliser(t, d.id, { event: "ots_complete", reexport: true });
        return;
      }
      att.detail = `${n} calendriers ; attestation en attente`;
      stocker();
      const next = t + o.upgrade.first_after_s * 1000;
      att.next_at = iso(next);
      this.ecrire(d, t, "en_attente");
      s.miseANiveauAt = next;
      this.programmer(d, t, next, "mise_a_niveau");
      this.timer(next, "mise_a_niveau", d.id);
      return;
    }
    // en_attente : réponse à une mise à niveau
    if (data.attestation === "complete") {
      att.outcome = "obtenue";
      att.detail = "mise a niveau : attestation Bitcoin";
      stocker();
      d.due_at = null;
      this.ecrire(d, t, "complete");
      this.journaliser(t, d.id, { event: "ots_complete", reexport: true });
      return;
    }
    att.outcome = "echec_transitoire";
    att.error_code = "en_attente";
    att.detail = "mise a niveau : engagement en attente";
    let intervalle = Math.max(60, o.upgrade.interval_s) * 1000;
    if (t - (s.soumisA ?? ms(d.created_at)) >= o.upgrade.give_up_after_s * 1000) {
      if (!s.alertes.has("ots_give_up")) {
        s.alertes.add("ots_give_up");
        this.alerter(t, d.id, "ots_give_up", "majeure");
      }
      intervalle = 86400 * 1000;
    }
    const next = t + intervalle;
    att.next_at = iso(next);
    this.ecrire(d, t, "en_attente");
    s.miseANiveauAt = next;
    this.programmer(d, t, next, "mise_a_niveau");
    this.timer(next, "mise_a_niveau", d.id);
  }
}

/** Objet minimal de demande pour les fonctions qui ne lisent que la sorte (désignation du prestataire). */
const d0 = (sujet) => ({ kind: sujet.kind === "point" ? "jeton_point" : "jeton_periode" });

/**
 * Planificateur à horloge injectée et sans réseau (EX-8.13) : `config` est un
 * document ancrage-v0 ou sa projection ; `maintenant()` rend l'instant courant
 * en millisecondes UNIX pour les entrées sans `t` ; `aleatoire` fournit les
 * nonces et gigues (aleatoireSysteme en exploitation, aleatoireVecteurs dans
 * les traces). L'objet rendu expose `charger(demandes)`, `recevoir(entree)`,
 * `file()`, `actions` et `lignes` (lignes NDJSON écrites).
 */
export function creerPlanificateur(config, { maintenant = null, aleatoire = null } = {}) {
  return new Planificateur(config, { maintenant, aleatoire });
}

/**
 * Rejoue une trace normative (racine du schéma planificateur-ancrage-v0,
 * EX-8.16) : rend { actions, file, lignes }, `actions` à comparer à `expected`
 * et `file` à `queue_after` (formes canoniques JCS v0, dans l'ordre).
 */
export function rejouerTrace(trace, { aleatoire = null } = {}) {
  const p = new Planificateur(trace.config, { aleatoire: aleatoire ?? aleatoireVecteurs({ gigues: trace.jitter_ms ?? [] }) });
  p.charger(trace.queue_before ?? []);
  for (const e of trace.inputs ?? []) p.recevoir(e);
  return { actions: p.actions, file: p.file(), lignes: p.lignes };
}

/** Compare le rejeu d'une trace à son attendu : rend la liste des écarts (vide si la trace est reproduite). */
export function verifierTrace(trace, options = {}) {
  const { actions, file } = rejouerTrace(trace, options);
  const ecarts = [];
  const can = (v) => J.canonicaliserJCS(v);
  const n = Math.max(actions.length, trace.expected.length);
  for (let i = 0; i < n; i++) {
    const a = actions[i] === undefined ? null : can(actions[i]);
    const b = trace.expected[i] === undefined ? null : can(trace.expected[i]);
    if (a !== b) {
      ecarts.push({ index: i, obtenu: actions[i] ?? null, attendu: trace.expected[i] ?? null });
      if (ecarts.length >= 5) break;
    }
  }
  const m = Math.max(file.length, trace.queue_after.length);
  for (let i = 0; i < m; i++) {
    const a = file[i] === undefined ? null : can(file[i]);
    const b = trace.queue_after[i] === undefined ? null : can(trace.queue_after[i]);
    if (a !== b) ecarts.push({ queue: i, obtenu: file[i] ?? null, attendu: trace.queue_after[i] ?? null });
  }
  return ecarts;
}
