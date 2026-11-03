// Chaînage du journal (CT-1 §7) : vérification d'une suite d'événements dans
// l'ordre du fichier, avec tous les symptômes de la table 7.2, selon la règle
// exacte de §7.2 (révision 0.5), en trois temps rapportés dans cet ordre :
//
// 1. chaque événement pour lui-même, dans l'ordre du fichier : E-1 à E-11,
//    puis l'origine (C-2, type origine : prev_hash nul si et seulement si
//    seq = 1) ; cles.json est lu d'abord, sans référence à un événement
//    (symptôme E-8 de type cles et de seq nul en tête s'il ne passe pas) ; son
//    org_id et son journal_id sont comparés à ceux de chaque événement, et un
//    écart est un symptôme E-8 de cet événement ;
// 2. la suite des seq sur tout le fichier (C-1), parmi les événements dont seq
//    est un entier : insertions (seq présents plus d'une fois, dans l'ordre de
//    première apparition), puis suppressions (trous de l'ensemble trié des seq
//    distincts, désignant le seq qui suit le trou, dans l'ordre croissant),
//    puis réordonnancements (seq inférieur à celui de l'événement qui le
//    précède, dans l'ordre du fichier). Un réordonnancement n'est pas aussi
//    rapporté comme deux trous, puisqu'aucun seq ne manque ;
// 3. chaque couple d'événements consécutifs dans l'ordre du fichier : C-2
//    (rupture : prev_hash contre le hash recalculé du précédent), C-1
//    (horodatage, puis journal : org_id et journal_id), C-3 (clé).
//
// Une relation dont un terme ne se calcule pas (hash d'un événement qui n'est
// pas un objet ou sans forme canonique, horodatage qui n'est pas une date
// existante) n'est pas tenue : le symptôme est rapporté (CT-1 §11.4, révision
// 0.5, appliqué au journal).

import { ZERO32, decoderHorodatage } from "./conventions.mjs";
import { CONTROLES_EVENEMENT, controlerEvenement, nouvelleCle } from "./controles-evenement.mjs";
import { indexerCles } from "./cles.mjs";

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

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

/** Type de symptôme de chaque contrôle d'événement (CT-1 §7.2). */
const TYPE_DIAGNOSTIC = {
  "E-1": "schema",
  "E-2": "format",
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
 * @property {string} type cles, origine, insertion, suppression, reordonnancement, rupture, horodatage, journal, cle, ou le
 *   type d'un contrôle E- (CT-1 §7.2 : schema, format, sorte, redaction, approbation, reference, modification,
 *   signature, approbateur, rotation, validite_cle)
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

  // 1. Chaque événement pour lui-même : E-1 à E-11, puis l'origine.
  const hashes = [];
  evenements.forEach((e, position) => {
    const { controles, hash } = controlerEvenement(e, { indexCles });
    hashes.push(hash);
    // Le seq d'un symptôme est celui de l'événement s'il est un entier, sinon null.
    const seq = estObjet(e) && Number.isSafeInteger(e.seq) ? e.seq : null;
    // Première partie de E-8 pour cet événement : org_id et journal_id de cles.json.
    const identite = [];
    if (indexCles.exploitable && estObjet(e)) {
      if (cles.org_id !== e.org_id || cles.journal_id !== e.journal_id) identite.push("org_id ou journal_id de l'événement différents de ceux de cles.json du journal");
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
    // L'origine de la chaîne : prev_hash nul si et seulement si seq = 1.
    if (!estObjet(e)) return;
    if (e.seq === 1 && e.prev_hash !== ZERO32) {
      diagnostics.push({ type: "origine", controle: "C-2", seq: 1, message: `seq 1 (position ${position}) : prev_hash non nul` });
    } else if (e.seq !== 1 && e.prev_hash === ZERO32) {
      diagnostics.push({ type: "origine", controle: "C-2", seq, message: `seq ${e.seq} (position ${position}) : prev_hash nul hors du premier événement` });
    }
  });

  // 2. La suite des seq sur tout le fichier (C-1), parmi les événements dont
  // seq est un entier : insertions, puis suppressions, puis réordonnancements.
  const entiers = [];
  evenements.forEach((e, p) => {
    if (estObjet(e) && Number.isSafeInteger(e.seq)) entiers.push({ seq: e.seq, position: p });
  });
  const positions = new Map();
  for (const { seq: s, position: p } of entiers) {
    if (!positions.has(s)) positions.set(s, []);
    positions.get(s).push(p);
  }
  for (const [s, ps] of positions) {
    if (ps.length > 1) {
      diagnostics.push({ type: "insertion", controle: "C-1", seq: s, message: `seq ${s} présent ${ps.length} fois (positions ${ps.join(", ")}) : événement inséré` });
    }
  }
  const distincts = [...positions.keys()].sort((a, b) => a - b);
  for (let k = 1; k < distincts.length; k++) {
    const a = distincts[k - 1];
    const b = distincts[k];
    if (b > a + 1) {
      diagnostics.push({ type: "suppression", controle: "C-1", seq: b, message: `trou entre seq ${a} et seq ${b} : ${b - a - 1} événement(s) supprimé(s)` });
    }
  }
  for (let k = 1; k < entiers.length; k++) {
    const { seq: s, position: p } = entiers[k];
    const avant = entiers[k - 1];
    if (s < avant.seq) {
      diagnostics.push({
        type: "reordonnancement",
        controle: "C-1",
        seq: s,
        message: `seq ${s} (position ${p}) après seq ${avant.seq} (position ${avant.position}) : ordre du journal non respecté`,
      });
    }
  }

  // 3. Chaque couple consécutif dans l'ordre du fichier.
  const seqDe = (e) => (estObjet(e) && Number.isSafeInteger(e.seq) ? e.seq : null);
  for (let p = 1; p < evenements.length; p++) {
    const a = evenements[p - 1];
    const b = evenements[p];
    if (!estObjet(b)) continue;
    const sb = seqDe(b);
    const hashA = hashes[p - 1];
    if (hashA === null || b.prev_hash !== hashA) {
      diagnostics.push({
        type: "rupture",
        controle: "C-2",
        seq: sb,
        message: `seq ${b.seq} (position ${p}) : prev_hash ${b.prev_hash} différent du hash recalculé de l'événement précédent dans le fichier, seq ${a?.seq} (${hashA})`,
      });
    }
    if (!estObjet(a)) continue;
    const ta = decoderHorodatage(a.ts);
    const tb = decoderHorodatage(b.ts);
    if (ta === null || tb === null) {
      diagnostics.push({ type: "horodatage", controle: "C-1", seq: sb, message: `seq ${b.seq} : ts ${b.ts} ou ts ${a.ts} de seq ${a.seq} n'est pas une date existante : ordre invérifiable` });
    } else if (tb < ta) {
      diagnostics.push({ type: "horodatage", controle: "C-1", seq: sb, message: `seq ${b.seq} : ts ${b.ts} antérieur à celui de seq ${a.seq} (${a.ts})` });
    }
    if (typeof b.org_id !== "string" || typeof b.journal_id !== "string" || a.org_id !== b.org_id || a.journal_id !== b.journal_id) {
      diagnostics.push({ type: "journal", controle: "C-1", seq: sb, message: `seq ${b.seq} : org_id ou journal_id différent de celui de seq ${a.seq}` });
    }
    const attendue = nouvelleCle(a) ?? a.recorder_key_id;
    if (typeof b.recorder_key_id !== "string" || b.recorder_key_id !== attendue) {
      diagnostics.push({ type: "cle", controle: "C-3", seq: sb, message: `seq ${b.seq} : recorder_key_id ${b.recorder_key_id}, ${attendue} attendue après seq ${a.seq}` });
    }
  }

  const enEchec = trierControles([...diagnostics.map((d) => d.controle), ...(indexCles.exploitable ? [] : ["E-8"])]);
  return { valide: enEchec.length === 0, controles_en_echec: enEchec, diagnostics };
}
