// Chaînage du journal (CT-1 §7) : vérification d'une suite d'événements dans
// l'ordre du fichier, avec tous les symptômes de la table 7.2.
//
// Ordre de l'analyse : chaque événement pour lui-même (E-1 à E-11), puis la
// suite des seq sur tout le fichier (C-1 : suppression, insertion,
// réordonnancement), puis chaque couple d'événements consécutifs dans l'ordre
// du fichier (C-2 : prev_hash contre le hash recalculé du précédent ; C-1 :
// ts, org_id, journal_id ; C-3 : clé).
//
// Les trous de seq se lisent sur l'ensemble des seq présents, non couple par
// couple : un réordonnancement (seq 6 avant seq 5) n'est pas aussi rapporté
// comme deux trous, puisqu'aucun seq ne manque.
//
// cles.json est lu sans référence à un événement (schéma, unicité, ordre des
// validités) ; son org_id et son journal_id sont comparés à ceux de chaque
// événement, et un écart est un symptôme E-8 de cet événement : un premier
// événement altéré ne fait donc pas disparaître les E-8 des autres (CT-1 §7.2 :
// le vérificateur de chaîne rapporte tous les symptômes).

import { ZERO32, decoderHorodatage } from "./conventions.mjs";
import { CONTROLES_EVENEMENT, controlerEvenement, nouvelleCle } from "./controles-evenement.mjs";
import { indexerCles } from "./cles.mjs";

/** Ordre de rapport des contrôles (CT-1 §11.4). */
export const ORDRE_CONTROLES = Object.freeze([
  "D-1", "D-2",
  ...CONTROLES_EVENEMENT,
  "C-1", "C-2", "C-3",
  "M-1", "M-2", "M-3",
  "P-1", "P-2", "P-3", "P-4", "P-5",
  "A-1", "A-2", "A-3", "A-4",
  "K-1", "K-2", "K-3", "K-4", "K-5", "K-6", "K-7", "K-8", "K-9",
]);

/** Type de diagnostic de chaque contrôle d'événement. */
const TYPE_DIAGNOSTIC = {
  "E-1": "schema",
  "E-2": "forme_canonique",
  "E-3": "sorte",
  "E-4": "redaction",
  "E-5": "approbation",
  "E-6": "reference",
  "E-7": "modification",
  "E-8": "signature",
  "E-9": "approbateur",
  "E-10": "rotation",
  "E-11": "validite_cle",
};

/**
 * Trie une liste d'identifiants de contrôles dans l'ordre de CT-1 §11.4, sans
 * doublon.
 * @param {Iterable<string>} ids
 * @returns {string[]}
 */
export function trierControles(ids) {
  const ensemble = new Set(ids);
  return ORDRE_CONTROLES.filter((id) => ensemble.has(id));
}

/**
 * @typedef {object} Diagnostic
 * @property {string} type suppression, insertion, reordonnancement, rupture, horodatage, identite, cle, origine, ou le type d'un contrôle E- (modification, signature…)
 * @property {string} controle identifiant du contrôle (C-1, C-2, E-7…)
 * @property {number|null} seq seq de l'événement concerné
 * @property {string} message
 */

/**
 * Vérifie un journal : chaque événement pour lui-même, puis le chaînage dans
 * l'ordre du fichier (CT-1 §7.2). Tous les symptômes sont rapportés.
 * @param {unknown[]} evenements les événements, dans l'ordre du fichier
 * @param {unknown} cles contenu de cles.json (clés de l'enregistreur)
 * @returns {{valide: boolean, controles_en_echec: string[], diagnostics: Diagnostic[]}}
 */
export function verifierJournal(evenements, cles) {
  if (!Array.isArray(evenements)) throw new TypeError("tableau d'événements attendu");
  const diagnostics = [];
  const indexCles = indexerCles(cles);
  if (!indexCles.exploitable) {
    diagnostics.push({ type: "cles", controle: "E-8", seq: null, message: `cles.json inexploitable : ${indexCles.erreurs.join(" ; ")}` });
  }

  // 1. Chaque événement pour lui-même.
  const hashes = [];
  evenements.forEach((e, position) => {
    const { controles, hash } = controlerEvenement(e, { indexCles });
    hashes.push(hash);
    const seq = e && typeof e === "object" ? e.seq : null;
    // Première partie de E-8 pour cet événement : org_id et journal_id de cles.json.
    const identite = [];
    if (indexCles.exploitable && e && typeof e === "object") {
      if (cles.org_id !== e.org_id) identite.push(`cles.json : org_id ${cles.org_id} différent de celui de l'événement ${e.org_id}`);
      if (cles.journal_id !== e.journal_id) identite.push(`cles.json : journal_id ${cles.journal_id} différent de celui de l'événement ${e.journal_id}`);
    }
    for (const id of CONTROLES_EVENEMENT) {
      const r = controles[id];
      const details = id === "E-8" ? [...identite, ...(r.statut === "echoue" ? r.details : [])] : r.statut === "echoue" ? r.details : [];
      if (details.length === 0) continue;
      if (id === "E-8" && !indexCles.exploitable) continue;
      let message;
      if (id === "E-7") {
        message = `seq ${seq} : hash recalculé ${hash} différent de hash ${e.hash} (contenu modifié après scellement)`;
      } else if (id === "E-8") {
        const modifie = controles["E-7"].statut === "echoue";
        message = `seq ${seq} : ${details.join(" ; ")}${modifie ? " (contenu modifié)" : ""}`;
      } else {
        message = `seq ${seq} (position ${position}) : ${details.join(" ; ")}`;
      }
      diagnostics.push({ type: TYPE_DIAGNOSTIC[id], controle: id, seq, message });
    }
  });

  // 2. La suite des seq sur tout le fichier (C-1).
  const seqs = evenements.map((e) => (e && typeof e === "object" && Number.isSafeInteger(e.seq) ? e.seq : null));
  const analyseSeq = [];
  const positions = new Map();
  seqs.forEach((s, p) => {
    if (s === null) return;
    if (!positions.has(s)) positions.set(s, []);
    positions.get(s).push(p);
  });
  for (const [s, ps] of positions) {
    if (ps.length > 1) {
      analyseSeq.push({
        position: ps[1],
        d: { type: "insertion", controle: "C-1", seq: s, message: `seq ${s} présent ${ps.length} fois (positions ${ps.join(", ")}) : événement inséré` },
      });
    }
  }
  for (let p = 1; p < seqs.length; p++) {
    if (seqs[p] !== null && seqs[p - 1] !== null && seqs[p] < seqs[p - 1]) {
      analyseSeq.push({
        position: p,
        d: {
          type: "reordonnancement",
          controle: "C-1",
          seq: seqs[p],
          message: `seq ${seqs[p]} (position ${p}) après seq ${seqs[p - 1]} (position ${p - 1}) : ordre du journal non respecté`,
        },
      });
    }
  }
  const distincts = [...positions.keys()].sort((a, b) => a - b);
  for (let k = 1; k < distincts.length; k++) {
    const a = distincts[k - 1];
    const b = distincts[k];
    if (b > a + 1) {
      analyseSeq.push({
        position: positions.get(b)[0],
        d: { type: "suppression", controle: "C-1", seq: b, message: `trou entre seq ${a} et seq ${b} : ${b - a - 1} événement(s) supprimé(s)` },
      });
    }
  }
  analyseSeq.sort((x, y) => x.position - y.position);
  diagnostics.push(...analyseSeq.map((x) => x.d));

  // 3. L'origine de la chaîne : prev_hash nul si et seulement si seq = 1.
  evenements.forEach((e, p) => {
    if (!e || typeof e !== "object") return;
    if (e.seq === 1 && e.prev_hash !== ZERO32) {
      diagnostics.push({ type: "origine", controle: "C-2", seq: 1, message: `seq 1 (position ${p}) : prev_hash non nul` });
    } else if (e.seq !== 1 && e.prev_hash === ZERO32) {
      diagnostics.push({ type: "origine", controle: "C-2", seq: e.seq, message: `seq ${e.seq} (position ${p}) : prev_hash nul hors du premier événement` });
    }
  });

  // 4. Chaque couple consécutif dans l'ordre du fichier.
  for (let p = 1; p < evenements.length; p++) {
    const a = evenements[p - 1];
    const b = evenements[p];
    if (!a || typeof a !== "object" || !b || typeof b !== "object") continue;
    const hashA = hashes[p - 1];
    if (hashA === null || b.prev_hash !== hashA) {
      diagnostics.push({
        type: "rupture",
        controle: "C-2",
        seq: b.seq,
        message: `seq ${b.seq} (position ${p}) : prev_hash ${b.prev_hash} différent du hash recalculé de l'événement précédent dans le fichier, seq ${a.seq} (${hashA})`,
      });
    }
    const ta = decoderHorodatage(a.ts);
    const tb = decoderHorodatage(b.ts);
    if (ta !== null && tb !== null && tb < ta) {
      diagnostics.push({ type: "horodatage", controle: "C-1", seq: b.seq, message: `seq ${b.seq} : ts ${b.ts} antérieur à celui de seq ${a.seq} (${a.ts})` });
    }
    if (a.org_id !== b.org_id || a.journal_id !== b.journal_id) {
      diagnostics.push({ type: "identite", controle: "C-1", seq: b.seq, message: `seq ${b.seq} : org_id ou journal_id différent de celui de seq ${a.seq}` });
    }
    const attendue = nouvelleCle(a) ?? a.recorder_key_id;
    if (b.recorder_key_id !== attendue) {
      diagnostics.push({ type: "cle", controle: "C-3", seq: b.seq, message: `seq ${b.seq} : recorder_key_id ${b.recorder_key_id}, ${attendue} attendue après seq ${a.seq}` });
    }
  }

  const enEchec = trierControles([...diagnostics.map((d) => d.controle), ...(indexCles.exploitable ? [] : ["E-8"])]);
  return { valide: enEchec.length === 0, controles_en_echec: enEchec, diagnostics };
}
