// Point de contrôle de la période en cours (CT-1 §10.5, §10.6) : hachage,
// signature portée dans l'objet, preuve de cohérence vers le manifeste
// (§10.7), vérification d'une série de points contre son manifeste et ses
// événements, avec les noms de règles de §10.5.

import { ZERO32, concatener, decoderHorodatage, estHex, hexVersOctets, octetsVersHex } from "./conventions.mjs";
import { jcs, jcsOctets } from "./json-strict.mjs";
import { PREFIXES, sha256Hex, signerEd25519, verifierEd25519 } from "./hachage.mjs";
import { preuveCoherence, racineMerkle } from "./merkle.mjs";
import { dansValidite, indexerCles } from "./cles.mjs";
import { hashRecalcule, nouvelleCle } from "./controles-evenement.mjs";
import { validerSchema } from "./schemas.mjs";
import { ecartsManifeste } from "./manifeste.mjs";

/** Noms des règles de série, dans l'ordre de CT-1 §10.5. */
export const REGLES_SERIE = Object.freeze([
  "chainage",
  "tree_size_decroissant",
  "checkpoint_ts_decroissant",
  "period_start",
  "root",
  "last_seq",
  "last_hash",
  "dernier_point",
  "cle_en_vigueur",
  "signature",
  "validite_cle",
]);

/**
 * Corps K' d'un point : l'objet privé de `sig` (onze clés).
 * @param {object} point
 * @returns {object}
 */
export function corpsPoint(point) {
  const { sig, ...corps } = point;
  return corps;
}

/**
 * Forme canonique C_K = JCS(K').
 * @param {object} point
 * @returns {string}
 */
export function formeCanoniquePoint(point) {
  return jcs(corpsPoint(point));
}

/**
 * checkpointHash = SHA-256(P_K || JCS(K')) (CT-1 §10.6).
 * @param {object} point
 * @returns {string}
 */
export function hacherPoint(point) {
  return sha256Hex(concatener(PREFIXES.P_K, jcsOctets(corpsPoint(point))));
}

/**
 * Message signé d'un point : P_SK || JCS(K').
 * @param {object} point
 * @returns {Uint8Array}
 */
export function messageSignaturePoint(point) {
  return concatener(PREFIXES.P_SK, jcsOctets(corpsPoint(point)));
}

/**
 * Signe un point (Ed25519 de la clé `key_id`) et rend le point aux douze clés.
 * @param {object} point point avec ou sans `sig`
 * @param {Uint8Array} graine
 * @returns {object}
 */
export function signerPoint(point, graine) {
  const corps = corpsPoint(point);
  return { ...corps, sig: octetsVersHex(signerEd25519(graine, messageSignaturePoint(corps))) };
}

/**
 * Vérifie la signature d'un point sous une clé publique.
 * @param {object} point
 * @param {Uint8Array} clePublique
 * @returns {boolean}
 */
export function verifierSignaturePoint(point, clePublique) {
  if (!estHex(point?.sig, 64)) return false;
  try {
    return verifierEd25519(clePublique, messageSignaturePoint(point), hexVersOctets(point.sig));
  } catch {
    return false;
  }
}

/**
 * Preuve de cohérence d'un point vers le manifeste de sa période, sous la
 * forme `consistency` de points-de-controle.json ; null pour tree_size = 0
 * (aucune preuve ne part d'une racine nulle, CT-1 §10.7).
 * @param {number} treeSize
 * @param {string[]} hashesPeriode les `count` hash d'événements de la période
 * @returns {{version: 0, first_size: number, second_size: number, first_root: string, second_root: string, path: string[]}|null}
 */
export function coherencePoint(treeSize, hashesPeriode) {
  if (treeSize === 0) return null;
  return {
    version: 0,
    first_size: treeSize,
    second_size: hashesPeriode.length,
    first_root: racineMerkle(hashesPeriode.slice(0, treeSize)),
    second_root: racineMerkle(hashesPeriode),
    path: preuveCoherence(treeSize, hashesPeriode),
  };
}

/**
 * Clé en vigueur après l'événement de seq `lastSeq` (CT-1 §10.5, règle 5) :
 * la clé de cet événement, ou new_key_id s'il est une rotation. Sans
 * événement (lastSeq = 0), la clé du premier événement du journal.
 * @param {Map<number, object>} parSeq événements indexés par seq
 * @param {number} lastSeq
 * @returns {string|null}
 */
export function cleEnVigueur(parSeq, lastSeq) {
  const e = parSeq.get(lastSeq);
  if (e) return nouvelleCle(e) ?? e.recorder_key_id;
  if (lastSeq === 0) return parSeq.get(1)?.recorder_key_id ?? null;
  return null;
}

/**
 * Vérifie une série de points de contrôle d'une période contre son manifeste,
 * les événements du journal et cles.json (règles 2 à 5 de CT-1 §10.5). La
 * cadence (règle 1) n'est pas une règle de validité et n'est pas contrôlée.
 * @param {object[]} points la série, dans l'ordre
 * @param {object} manifeste manifeste de la période
 * @param {object[]} evenements événements du journal (au moins ceux de la période et le précédent)
 * @param {unknown} cles contenu de cles.json
 * @returns {{valide: boolean, rules_failed: string[], errors: string[]}}
 * @throws {TypeError} manifeste non conforme à son schéma ou à ses relations (à vérifier d'abord)
 */
export function verifierSeriePointsDeControle(points, manifeste, evenements, cles) {
  if (!Array.isArray(points)) throw new TypeError("tableau de points attendu");
  if (!Array.isArray(evenements)) throw new TypeError("tableau d'événements attendu");
  const ecartsM = ecartsManifeste(manifeste);
  if (ecartsM.length) throw new TypeError(`manifeste non conforme : ${ecartsM.join(" ; ")}`);
  const erreurs = [];
  const regles = new Set();
  const ecart = (regle, message) => {
    regles.add(regle);
    erreurs.push(message);
  };
  const parSeq = new Map();
  for (const e of evenements) if (e && typeof e === "object") parSeq.set(e.seq, e);
  const index = indexerCles(cles, { org_id: manifeste.org_id, journal_id: manifeste.journal_id });
  // Hash recalculés des événements connus de la période, dans l'ordre des seq,
  // jusqu'au premier qui manque.
  const hashesPeriode = [];
  for (let s = manifeste.first_seq; s <= manifeste.last_seq && parSeq.has(s); s++) hashesPeriode.push(hashRecalcule(parSeq.get(s)));
  const debutPeriode = manifeste.period_start * 1000;

  let precedent = null;
  points.forEach((p, i) => {
    const ici = `point[${i}]`;
    const schema = validerSchema("point-de-controle", p);
    if (!schema.valide) {
      ecart("period_start", `${ici} : en-tête non conforme au schéma du point (${schema.erreurs[0]})`);
      precedent = null;
      return;
    }
    const ts = decoderHorodatage(p.checkpoint_ts);
    if (p.org_id !== manifeste.org_id || p.journal_id !== manifeste.journal_id) {
      ecart("period_start", `${ici} : org_id ou journal_id différent de celui du manifeste`);
    }
    if (p.period_start !== manifeste.period_start) {
      ecart("period_start", `${ici} : period_start ${p.period_start} différent de celui du manifeste (${manifeste.period_start})`);
    }
    if (ts === null || ts < debutPeriode) ecart("period_start", `${ici} : checkpoint_ts ${p.checkpoint_ts} antérieur à period_start`);

    const chaine = precedent ? hacherPoint(precedent) : ZERO32;
    if (p.prev_checkpoint_hash !== chaine) {
      ecart("chainage", `${ici} : prev_checkpoint_hash ${p.prev_checkpoint_hash} différent de checkpointHash du point précédent ${chaine}`);
    }
    if (precedent && p.tree_size < precedent.tree_size) {
      ecart("tree_size_decroissant", `${ici} : tree_size ${p.tree_size} décroît (précédent ${precedent.tree_size})`);
    }
    if (precedent && ts !== null && ts < decoderHorodatage(precedent.checkpoint_ts)) {
      ecart("checkpoint_ts_decroissant", `${ici} : checkpoint_ts ${p.checkpoint_ts} antérieur au précédent ${precedent.checkpoint_ts}`);
    }

    if (p.tree_size > hashesPeriode.length || hashesPeriode.slice(0, p.tree_size).some((h) => h === null)) {
      ecart("root", `${ici} : tree_size ${p.tree_size} au-delà des événements connus de la période`);
    } else {
      const racine = racineMerkle(hashesPeriode.slice(0, p.tree_size));
      if (p.root !== racine) ecart("root", `${ici} : root ${p.root} différent de la racine des ${p.tree_size} premières feuilles (${racine})`);
    }
    const lastSeqAttendu = manifeste.first_seq + p.tree_size - 1;
    if (p.last_seq !== lastSeqAttendu) ecart("last_seq", `${ici} : last_seq ${p.last_seq} différent de first_seq + tree_size − 1 (${lastSeqAttendu})`);
    const lastHash = p.last_seq === 0 ? ZERO32 : hashRecalcule(parSeq.get(p.last_seq));
    if (lastHash === null) ecart("last_hash", `${ici} : événement ${p.last_seq} inconnu, last_hash invérifiable`);
    else if (p.last_hash !== lastHash) ecart("last_hash", `${ici} : last_hash ${p.last_hash} différent du hash de l'événement ${p.last_seq} (${lastHash})`);

    const attendue = cleEnVigueur(parSeq, p.last_seq);
    if (p.key_id !== attendue) ecart("cle_en_vigueur", `${ici} : key_id ${p.key_id}, clé en vigueur attendue ${attendue}`);
    const cle = index.exploitable ? index.cles.get(p.key_id) : undefined;
    if (!cle || !verifierSignaturePoint(p, cle.octets)) ecart("signature", `${ici} : signature invalide sous ${p.key_id}`);
    if (cle && ts !== null && !dansValidite(cle, ts)) ecart("validite_cle", `${ici} : checkpoint_ts ${p.checkpoint_ts} hors de la validité de la clé ${p.key_id}`);
    precedent = p;
  });

  const dernier = points[points.length - 1];
  if (!dernier) {
    ecart("dernier_point", "série vide : aucun point ne rejoint le manifeste");
  } else {
    if (dernier.tree_size !== manifeste.count) ecart("dernier_point", `dernier point : tree_size ${dernier.tree_size} différent de count ${manifeste.count}`);
    if (dernier.root !== manifeste.root) ecart("dernier_point", `dernier point : root ${dernier.root} différent de celui du manifeste`);
    if (dernier.last_seq !== manifeste.last_seq) {
      ecart("dernier_point", `dernier point : last_seq ${dernier.last_seq} différent de celui du manifeste ${manifeste.last_seq}`);
    }
  }
  return { valide: erreurs.length === 0, rules_failed: REGLES_SERIE.filter((r) => regles.has(r)), errors: erreurs };
}
