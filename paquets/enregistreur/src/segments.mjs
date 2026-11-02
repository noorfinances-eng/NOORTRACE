// Segments (CT-2 §12.1, §12.2, §12.4) : fichiers NDJSON en ajout seul,
// `segments/seg-<first_seq sur 16 chiffres>-<epoch sur 20 chiffres>.ndjson`.
// Première ligne : l'en-tête, objet JSON en JCS v0 ; puis un événement
// complet (dix-sept clés) en JCS v0 par ligne, suivi de \n (EX-12.3).
// Relecture et détection d'écriture tronquée (EX-12.10) ; une ligne dont le
// hash recalculé diffère est une corruption, jamais tronquée en silence
// (EX-12.11).

import fs from "node:fs/promises";
import path from "node:path";
import {
  ErreurJson, analyserJson, ecrireHorodatage, hacherEvenement, jcs, utf8, validerSchema,
  verifierSignatureEvenement, annonceRotation, hexVersOctets, decoderUtf8,
} from "@noortrace/noyau";
import { decouperLignes } from "./fichiers.mjs";

const MOTIF_NOM = /^seg-([0-9]{16})-([0-9]{20})\.ndjson$/;

/**
 * Nom d'un segment.
 * @param {number} firstSeq
 * @param {number} epoque
 * @returns {string}
 */
export function nomSegment(firstSeq, epoque) {
  return `seg-${String(firstSeq).padStart(16, "0")}-${String(epoque).padStart(20, "0")}.ndjson`;
}

/**
 * En-tête de segment (EX-12.3, table) : JCS v0, clés triées.
 * @param {{epoch: number, first_seq: number, instance_id: string, journal_id: string, org_id: string,
 *   opened_at: number|string, prev_hash: string, recorder: string, recorder_key_id: string}} p
 * @returns {object}
 */
export function enteteSegment(p) {
  return {
    epoch: p.epoch,
    first_seq: p.first_seq,
    instance_id: p.instance_id,
    journal_id: p.journal_id,
    noortrace_segment: 0,
    opened_at: typeof p.opened_at === "number" ? ecrireHorodatage(p.opened_at) : p.opened_at,
    org_id: p.org_id,
    prev_hash: p.prev_hash,
    recorder: p.recorder,
    recorder_key_id: p.recorder_key_id,
  };
}

/**
 * Octets d'une ligne de segment : JCS v0 suivi de \n.
 * @param {object} objet en-tête ou événement complet
 * @returns {Uint8Array}
 */
export function ligneSegment(objet) {
  return utf8(jcs(objet) + "\n");
}

/**
 * Liste les segments d'un journal, triés par nom (ordre des first_seq, puis
 * des époques, EX-12.1).
 * @param {string} repertoireSegments
 * @returns {Promise<{nom: string, chemin: string, first_seq: number, epoch: number}[]>}
 */
export async function listerSegments(repertoireSegments) {
  let noms;
  try {
    noms = await fs.readdir(repertoireSegments);
  } catch (e) {
    if (e.code === "ENOENT") return [];
    throw e;
  }
  return noms
    .filter((n) => MOTIF_NOM.test(n))
    .sort()
    .map((nom) => {
      const [, s, e] = MOTIF_NOM.exec(nom);
      return { nom, chemin: path.join(repertoireSegments, nom), first_seq: Number(s), epoch: Number(e) };
    });
}

function estRemplissageNul(octets) {
  for (const o of octets) if (o !== 0) return false;
  return true;
}

/**
 * Relit un segment (EX-12.10 pas 2). Une ligne est valide si elle se termine
 * par \n, s'analyse en JSON strict, valide contre le schéma d'événement, a le
 * seq attendu, le prev_hash attendu, un hash égal au recalculé et une
 * signature qui vérifie sous la clé en vigueur.
 *
 * Classement d'une ligne qui ne l'est pas (lecture consignée dans le
 * LISEZMOI) : une dernière ligne sans \n, ou faite d'octets nuls, est une
 * écriture tronquée ; toute autre ligne invalide (hash différent, EX-12.11 ;
 * signature, chaînage ou schéma en défaut sur une ligne complète ; ligne
 * illisible suivie d'autres lignes) est une corruption.
 *
 * @param {Uint8Array} octets contenu du fichier
 * @param {{verifierSignatures?: boolean, clePublique?: (keyId: string) => Uint8Array|null,
 *   prevHashAttendu?: string|null, firstSeqAttendu?: number|null}} [options]
 * @returns {{entete: object|null, evenements: object[], finValide: number, tronque: boolean,
 *   corruption: {seq: number|null, raison: string, attendu?: string, recalcule?: string}|null}}
 */
export function relireSegment(octets, options = {}) {
  const lignes = decouperLignes(octets);
  const resultat = { entete: null, evenements: [], finValide: 0, tronque: false, corruption: null };
  if (lignes.length === 0) {
    resultat.tronque = octets.length > 0;
    return resultat;
  }
  const tronquerOuCorrompre = (k, raison, extra = {}) => {
    const reste = lignes.slice(k);
    const tronquee = reste.length === 1 && (!reste[0].complete || estRemplissageNul(reste[0].octets));
    const nuls = reste.every((l) => estRemplissageNul(l.octets));
    if (tronquee || nuls) resultat.tronque = true;
    else resultat.corruption = { seq: extra.seq ?? null, raison, ...extra };
  };

  // En-tête.
  const l0 = lignes[0];
  if (!l0.complete) {
    resultat.tronque = true;
    return resultat;
  }
  try {
    resultat.entete = analyserJson(l0.octets);
  } catch {
    tronquerOuCorrompre(0, "entete_illisible");
    return resultat;
  }
  resultat.finValide = l0.fin;
  const entete = resultat.entete;
  if (options.firstSeqAttendu !== undefined && options.firstSeqAttendu !== null && entete.first_seq !== options.firstSeqAttendu) {
    resultat.corruption = { seq: null, raison: "first_seq_discontinu" };
    return resultat;
  }
  let seqAttendu = entete.first_seq;
  let prevAttendu = entete.prev_hash;
  if (options.prevHashAttendu !== undefined && options.prevHashAttendu !== null && prevAttendu !== options.prevHashAttendu) {
    resultat.corruption = { seq: null, raison: "prev_hash_entete" };
    return resultat;
  }
  let cleCourante = entete.recorder_key_id;
  const nouvellesCles = new Map();
  for (let k = 1; k < lignes.length; k++) {
    const l = lignes[k];
    if (!l.complete) {
      tronquerOuCorrompre(k, "ligne_incomplete");
      return resultat;
    }
    let e;
    try {
      e = analyserJson(l.octets);
    } catch (err) {
      tronquerOuCorrompre(k, err instanceof ErreurJson ? "json_invalide" : "illisible");
      return resultat;
    }
    const schema = validerSchema("evenement", e);
    if (!schema.valide) {
      tronquerOuCorrompre(k, "schema", { seq: e?.seq ?? null });
      return resultat;
    }
    if (e.seq !== seqAttendu || e.prev_hash !== prevAttendu) {
      tronquerOuCorrompre(k, "chainage", { seq: e.seq });
      return resultat;
    }
    const recalcule = hacherEvenement(e);
    if (recalcule !== e.hash) {
      resultat.corruption = { seq: e.seq, raison: "hash_different", attendu: e.hash, recalcule };
      return resultat;
    }
    if (options.verifierSignatures) {
      const keyId = e.recorder_key_id;
      const pub = nouvellesCles.get(keyId) ?? options.clePublique?.(keyId) ?? null;
      // Une clé dont la clé publique n'est pas connue (clé initiale que le
      // signataire ne détient plus) n'est pas vérifiée ici ; la chaîne, elle,
      // l'est (hash, seq, prev_hash).
      if (keyId !== cleCourante || (pub && !verifierSignatureEvenement(e, pub))) {
        tronquerOuCorrompre(k, "signature", { seq: e.seq });
        return resultat;
      }
    }
    const a = annonceRotation(e);
    if (a && e.execution.tool === "noortrace.journal.rotation-cle") {
      nouvellesCles.set(a.new_key_id, hexVersOctets(a.new_public_key, 32));
      cleCourante = a.new_key_id;
    }
    resultat.evenements.push(e);
    resultat.finValide = l.fin;
    seqAttendu++;
    prevAttendu = e.hash;
  }
  return resultat;
}

/**
 * Lecture rapide des événements d'un segment réputé fermé proprement
 * (EX-12.10 pas 2 : seul le dernier est validé en entier).
 * @param {Uint8Array} octets
 * @returns {{entete: object, evenements: object[]}}
 */
export function lireSegmentFerme(octets) {
  const texte = decoderUtf8(octets);
  const lignes = texte.split("\n");
  if (lignes[lignes.length - 1] === "") lignes.pop();
  const entete = JSON.parse(lignes[0]);
  return { entete, evenements: lignes.slice(1).map((l) => JSON.parse(l)) };
}

