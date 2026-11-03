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

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// Le hachage et la signature portent sur l'objet en mémoire : la borne de
// profondeur de CT-1 §4 (règle 7) s'applique à la lecture et à E-1, non ici.
const SANS_BORNE = Object.freeze({ profondeurMax: Infinity });

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
  return jcs(corpsPoint(point), SANS_BORNE);
}

/**
 * checkpointHash = SHA-256(P_K || JCS(K')) (CT-1 §10.6).
 * @param {object} point
 * @returns {string}
 */
export function hacherPoint(point) {
  return sha256Hex(concatener(PREFIXES.P_K, jcsOctets(corpsPoint(point), SANS_BORNE)));
}

/**
 * Message signé d'un point : P_SK || JCS(K').
 * @param {object} point
 * @returns {Uint8Array}
 */
export function messageSignaturePoint(point) {
  return concatener(PREFIXES.P_SK, jcsOctets(corpsPoint(point), SANS_BORNE));
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
 * Clé en vigueur d'un point (CT-1 §10.5, règle 5, qui renvoie à la règle de
 * `recorder_key_id` du manifeste, §10.1) : la clé de l'événement `lastSeq`,
 * ou son new_key_id s'il est une rotation. Sans cet événement (journal encore
 * vide, last_seq = 0, ou événement non fourni), la règle de §10.1 telle
 * qu'écrite : la dernière clé annoncée dont valid_from ≤ l'instant du point,
 * c'est-à-dire, dans cles.json, la clé de plus grand valid_from ≤ instant (à
 * valid_from égal, la dernière du fichier).
 * @param {Map<number, object>} parSeq événements indexés par seq
 * @param {number} lastSeq
 * @param {{indexCles?: {exploitable: boolean, cles: Map<string, import("./cles.mjs").CleIndexee>}|null, instant?: number|null}} [contexte]
 *   cles.json lu par indexerCles et instant du point (checkpoint_ts, en millisecondes), pour la règle de §10.1
 * @returns {string|null} null si aucune clé ne se déduit
 */
export function cleEnVigueur(parSeq, lastSeq, contexte = {}) {
  const e = parSeq.get(lastSeq);
  if (e) return nouvelleCle(e) ?? e.recorder_key_id;
  const { indexCles, instant } = contexte;
  if (!indexCles?.exploitable || typeof instant !== "number") return null;
  let retenue = null;
  for (const cle of indexCles.cles.values()) {
    if (cle.debut !== null && cle.debut <= instant && (retenue === null || cle.debut >= retenue.debut)) retenue = cle;
  }
  return retenue?.key_id ?? null;
}

/**
 * Vérifie une série de points de contrôle d'une période contre son manifeste,
 * les événements fournis et cles.json (règles 2 à 5 de CT-1 §10.5). La
 * cadence (règle 1) n'est pas une règle de validité et n'est pas contrôlée.
 *
 * Chaque règle est évaluée point par point (révision 0.5). Elle est violée
 * quand les données fournies la contredisent (`rules_failed`), non évaluée
 * quand il manque pour ce point une donnée sans laquelle elle ne se décide
 * pas (`rules_not_evaluated`, `{ rule, reason }`) : `root` (n ≥ 1) et
 * `last_hash` (last_seq ≥ 1) exigent les événements fournis ; un événement
 * manquant donne `piece_hors_dossier`, un événement fourni dont le hash ne se
 * recalcule pas `prerequis_en_echec`. Un événement manquant ne rend jamais
 * une règle violée, et aucune valeur par défaut ne le remplace. Une règle
 * violée pour un point n'est pas aussi rapportée non évaluée pour ce point.
 * Pour un même point et une même règle, un événement manquant et un autre
 * sans forme canonique donnent `prerequis_en_echec`. `signature`,
 * `validite_cle` et, sans l'événement last_seq, `cle_en_vigueur` lisent
 * cles.json : sans lui (null ou absent), non évaluées (`piece_hors_dossier`) ;
 * cles.json qui ne passe pas la première partie de E-8 sans référence à un
 * événement, non évaluées (`prerequis_en_echec`). Les deux listes suivent
 * l'ordre de REGLES_SERIE, puis, pour une règle, `prerequis_en_echec` avant
 * `piece_hors_dossier`. La série n'est valide que si les deux listes sont
 * vides.
 * @param {object[]} points la série, dans l'ordre
 * @param {object} manifeste manifeste de la période
 * @param {object[]} evenements événements fournis (tout ou partie de la période, et le dernier de la précédente)
 * @param {unknown} cles contenu de cles.json, ou null s'il n'est pas fourni
 * @returns {{valide: boolean, rules_failed: string[], rules_not_evaluated: {rule: string, reason: string}[], errors: string[]}}
 * @throws {TypeError} manifeste non conforme à son schéma ou à ses relations (à vérifier d'abord)
 */
export function verifierSeriePointsDeControle(points, manifeste, evenements, cles) {
  if (!Array.isArray(points)) throw new TypeError("tableau de points attendu");
  if (!Array.isArray(evenements)) throw new TypeError("tableau d'événements attendu");
  const ecartsM = ecartsManifeste(manifeste);
  if (ecartsM.length) throw new TypeError(`manifeste non conforme : ${ecartsM.join(" ; ")}`);
  const erreurs = [];
  const regles = new Set();
  const nonEvaluees = new Map();
  let violeesIci = new Set();
  const ecart = (regle, message) => {
    regles.add(regle);
    violeesIci.add(regle);
    erreurs.push(message);
  };
  const nonEvaluee = (regle, raison) => {
    if (violeesIci.has(regle)) return;
    const cle = `${regle}|${raison}`;
    if (!nonEvaluees.has(cle)) nonEvaluees.set(cle, { rule: regle, reason: raison });
  };
  const parSeq = new Map();
  for (const e of evenements) if (e && typeof e === "object" && !Array.isArray(e)) parSeq.set(e.seq, e);
  // Première partie de E-8 lue sans référence à un événement (CT-1 §10.5).
  const sansCles = cles === null || cles === undefined;
  const index = sansCles ? null : indexerCles(cles);
  const raisonCles = sansCles ? "piece_hors_dossier" : index.exploitable ? null : "prerequis_en_echec";
  /** Hash recalculé de l'événement seq : { hash } ; { raison } s'il manque ou ne se recalcule pas. */
  const hashDe = (seq) => {
    if (!parSeq.has(seq)) return { raison: "piece_hors_dossier" };
    const h = hashRecalcule(parSeq.get(seq));
    return h === null ? { raison: "prerequis_en_echec" } : { hash: h };
  };
  const debutPeriode = manifeste.period_start * 1000;

  let precedent = null;
  points.forEach((p, i) => {
    violeesIci = new Set();
    const ici = `point[${i}]`;
    // Racine nulle pour tree_size ≥ 1, ou non nulle pour tree_size = 0 : le
    // schéma la refuse aussi (allOf), mais CT-1 §10.5 (révision 0.5) la range
    // sous root ; seul un autre défaut de schéma viole period_start.
    const racineSeule = estObjet(p) && !validerSchema("point-de-controle", p).valide && Number.isSafeInteger(p.tree_size) && estHex(p.root, 32) &&
      validerSchema("point-de-controle", { ...p, root: p.tree_size === 0 ? ZERO32 : "0x" + "11".repeat(32) }).valide;
    const schema = racineSeule ? { valide: true } : validerSchema("point-de-controle", p);
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

    // root (règle 2) : n = 0 exige 32 octets nuls ; n ≥ 1, les événements
    // first_seq à first_seq + n − 1 fournis, de hash recalculable.
    const reportsRoot = [];
    if (p.tree_size === 0) {
      if (p.root !== ZERO32) ecart("root", `${ici} : root ${p.root} non nulle pour tree_size 0`);
    } else if (p.root === ZERO32) {
      ecart("root", `${ici} : root nulle pour tree_size ${p.tree_size}`);
    } else {
      const hashes = [];
      let raison = null;
      for (let s = manifeste.first_seq; s < manifeste.first_seq + p.tree_size; s++) {
        const h = hashDe(s);
        if (h.raison) {
          // prerequis_en_echec l'emporte sur piece_hors_dossier (CT-6 EX-6.5).
          if (raison !== "prerequis_en_echec") raison = h.raison;
        } else hashes.push(h.hash);
      }
      if (raison) reportsRoot.push(raison);
      else {
        const racine = racineMerkle(hashes);
        if (p.root !== racine) ecart("root", `${ici} : root ${p.root} différent de la racine recalculée ${racine}`);
      }
    }
    const lastSeqAttendu = manifeste.first_seq + p.tree_size - 1;
    if (p.last_seq !== lastSeqAttendu) ecart("last_seq", `${ici} : last_seq ${p.last_seq} différent de first_seq + tree_size − 1 (${lastSeqAttendu})`);
    // tree_size supérieur à count : last_seq dépasse celui du manifeste.
    if (p.tree_size > manifeste.count) ecart("last_seq", `${ici} : tree_size ${p.tree_size} supérieur à count ${manifeste.count}`);
    // last_hash (règle 2) : last_seq = 0 exige 32 octets nuls ; sinon
    // l'événement last_seq fourni, de hash recalculable, et 32 octets nuls ne
    // le remplacent jamais.
    const reportsLast = [];
    if (p.last_seq === 0) {
      if (p.last_hash !== ZERO32) ecart("last_hash", `${ici} : last_hash ${p.last_hash} non nul pour last_seq 0`);
    } else {
      const h = hashDe(p.last_seq);
      if (h.raison) reportsLast.push(h.raison);
      else if (p.last_hash !== h.hash) ecart("last_hash", `${ici} : last_hash ${p.last_hash} différent du hash de l'événement ${p.last_seq} (${h.hash})`);
    }

    const reportsCles = [];
    if (parSeq.has(p.last_seq) || !raisonCles) {
      const attendue = cleEnVigueur(parSeq, p.last_seq, { indexCles: index, instant: ts });
      if (p.key_id !== attendue) ecart("cle_en_vigueur", `${ici} : key_id ${p.key_id}, clé en vigueur attendue ${attendue}`);
    } else reportsCles.push("cle_en_vigueur");
    if (raisonCles) reportsCles.push("signature", "validite_cle");
    else {
      const cle = index.cles.get(p.key_id);
      if (!cle) ecart("signature", `${ici} : clé ${p.key_id} absente du jeu de clés`);
      else if (!verifierSignaturePoint(p, cle.octets)) ecart("signature", `${ici} : signature invalide sous ${p.key_id}`);
      if (cle && ts !== null && !dansValidite(cle, ts)) ecart("validite_cle", `${ici} : checkpoint_ts ${p.checkpoint_ts} hors de la validité de la clé ${p.key_id}`);
    }
    for (const r of reportsRoot) nonEvaluee("root", r);
    for (const r of reportsLast) nonEvaluee("last_hash", r);
    for (const regle of reportsCles) nonEvaluee(regle, raisonCles);
    precedent = p;
  });

  violeesIci = new Set();
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
  const rangs = new Map(REGLES_SERIE.map((r, k) => [r, k]));
  const rangRaison = (r) => (r === "prerequis_en_echec" ? 0 : 1);
  const rulesNotEvaluated = [...nonEvaluees.values()].sort((x, y) => rangs.get(x.rule) - rangs.get(y.rule) || rangRaison(x.reason) - rangRaison(y.reason));
  const rulesFailed = REGLES_SERIE.filter((r) => regles.has(r));
  return {
    valide: rulesFailed.length === 0 && rulesNotEvaluated.length === 0,
    rules_failed: rulesFailed,
    rules_not_evaluated: rulesNotEvaluated,
    errors: erreurs,
  };
}
