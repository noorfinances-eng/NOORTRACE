// Complétude au registre (CT-5 EX-10.7, AN-61) : toute ancre `Anchored` de
// `docType` point de contrôle émise par une clé de chaîne du journal dans la
// fenêtre de blocs de la période (`from_block` exclu, `to_block` inclus) a
// pour empreinte `keccak256(org_id ‖ journal_id ‖ checkpointHash)` d'un point
// d'une série publiée (la période et la suivante) ; sinon elle est orpheline.
// Dans chaque série, l'ordre des blocs (puis des `log_index`) des ancres
// rattachées suit celui des `checkpoint_ts`. Les entrées sont celles de
// `$defs/cas_completude.input`.

import { DOC_TYPE_POINT, decoderHorodatage, empreinteAncre, estHex } from "@noortrace/noyau";

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const estAdresse = (a) => typeof a === "string" && /^0x[0-9a-f]{40}$/.test(a);

/**
 * Contrôle les entrées (bornes et formes de `$defs/cas_completude.input`).
 * @param {object} e
 */
function controler(e) {
  if (!estObjet(e)) throw new TypeError("entrées de complétude : objet attendu");
  if (!Number.isSafeInteger(e.from_block) || e.from_block < -1) throw new RangeError("from_block : entier ≥ −1");
  if (!Number.isSafeInteger(e.to_block) || e.to_block < 0) throw new RangeError("to_block : entier ≥ 0");
  if (e.to_block <= e.from_block) throw new RangeError("to_block doit suivre from_block");
  if (!Array.isArray(e.issuers) || e.issuers.length < 1 || e.issuers.length > 64 || !e.issuers.every(estAdresse)) throw new TypeError("issuers : 1 à 64 adresses attendues");
  if (!Array.isArray(e.journals) || e.journals.length < 1 || e.journals.length > 64) throw new TypeError("journals : 1 à 64 séries attendues");
  for (const j of e.journals) {
    if (!estObjet(j) || !estHex(j.org_id, 32) || !estHex(j.journal_id, 32) || !Array.isArray(j.points) || j.points.length > 10000) throw new TypeError("série : org_id, journal_id et points attendus");
    for (const p of j.points) {
      if (!estObjet(p) || !estHex(p.checkpoint_hash, 32) || decoderHorodatage(p.checkpoint_ts) === null) throw new TypeError("point : checkpoint_hash et checkpoint_ts attendus");
    }
  }
  if (!Array.isArray(e.anchors) || e.anchors.length > 10000) throw new TypeError("anchors : tableau attendu");
  for (const a of e.anchors) {
    if (!estObjet(a) || !estHex(a.fingerprint, 32) || !estHex(a.doc_type, 32) || !Number.isSafeInteger(a.block_number) || a.block_number < 0 || !Number.isSafeInteger(a.log_index) || a.log_index < 0 || !estAdresse(a.issuer)) {
      throw new TypeError("ancre : fingerprint, doc_type, block_number, log_index et issuer attendus");
    }
  }
}

/**
 * EX-10.7 : `{ complete, orphans, out_of_order, attached }` d'une période.
 * @param {object} entrees `$defs/cas_completude.input`
 * @returns {{complete: boolean, orphans: string[], out_of_order: string[], attached: number}}
 */
export function verifierCompletudeRegistre(entrees) {
  controler(entrees);
  const emetteurs = new Set(entrees.issuers.map((a) => a.toLowerCase()));
  // Empreinte d'ancre de chaque point publié → (série, instant).
  const parEmpreinte = new Map();
  entrees.journals.forEach((j, serie) => {
    for (const p of j.points) {
      const f = empreinteAncre(j.org_id, j.journal_id, p.checkpoint_hash);
      if (!parEmpreinte.has(f)) parEmpreinte.set(f, { serie, ts: decoderHorodatage(p.checkpoint_ts) });
    }
  });
  const retenues = entrees.anchors
    .filter((a) => a.doc_type === DOC_TYPE_POINT && emetteurs.has(a.issuer.toLowerCase()) && a.block_number > entrees.from_block && a.block_number <= entrees.to_block)
    .sort((a, b) => a.block_number - b.block_number || a.log_index - b.log_index);
  const orphans = [];
  const out_of_order = [];
  let attached = 0;
  const dernierTs = new Map();
  for (const a of retenues) {
    const point = parEmpreinte.get(a.fingerprint);
    if (!point) {
      orphans.push(a.fingerprint);
      continue;
    }
    attached += 1;
    const precedent = dernierTs.get(point.serie);
    if (precedent !== undefined && point.ts < precedent) out_of_order.push(a.fingerprint);
    else dernierTs.set(point.serie, point.ts);
  }
  return { complete: orphans.length === 0 && out_of_order.length === 0, orphans, out_of_order, attached };
}
