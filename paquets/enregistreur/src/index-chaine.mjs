// Index dérivés de la chaîne (CT-2 EX-7.17, EX-12.1, EX-12.10 pas 4) : il n'y
// a aucun fichier d'état mutable ; ce que l'écrivain et le noyau doivent
// savoir de la chaîne (politiques annoncées, clés, tickets) se dérive des
// événements durables, à la reprise puis au fil de l'écriture.

import { NOMS_RESERVES, annonceRotation, decoderHorodatage } from "@noortrace/noyau";

export class IndexChaine {
  constructor() {
    /** version → policy_sha256 de chaque événement de politique (EX-9.1). */
    this.politiques = new Map();
    /** Dernier événement de politique : { policy_version, policy_sha256, seq, ts }. */
    this.dernierePolitique = null;
    /** Historique des politiques par ordre de seq : [{ policy_version, policy_sha256, ts }]. */
    this.historiquePolitiques = [];
    /** key_id → { public_key|null, valid_from (ms), valid_to (ms|null) } annoncées par la chaîne. */
    this.cles = new Map();
    /** Événements de rotation dans l'ordre. */
    this.rotations = [];
    /** ticket → événements `retenue` (EX-7.17, SG-2). */
    this.retenues = new Map();
    /** ticket → événement de décision scellé (SG-3, RL-1). */
    this.decisions = new Map();
    /** ticket → premier événement `executee` qui porte l'approbation (RL-3, EX-7.20). */
    this.premiersExecutes = new Map();
    /** hash → seq des événements `retenue` (SG-2). */
    this.retenuesParHash = new Map();
  }

  /**
   * Ajoute un événement durable.
   * @param {object} e
   */
  ajouter(e) {
    const outil = e.execution?.tool;
    if (outil === NOMS_RESERVES.POLITIQUE) {
      const v = e.execution.arguments.value;
      this.politiques.set(v.policy_version, v.policy_sha256);
      this.dernierePolitique = { policy_version: v.policy_version, policy_sha256: v.policy_sha256, seq: e.seq, ts: e.ts };
      this.historiquePolitiques.push({ policy_version: v.policy_version, policy_sha256: v.policy_sha256, ts: decoderHorodatage(e.ts) });
    } else if (outil === NOMS_RESERVES.ROTATION) {
      const a = annonceRotation(e);
      if (a) {
        const t = decoderHorodatage(e.ts);
        const ancienne = this.cles.get(a.old_key_id);
        if (ancienne) ancienne.valid_to = t;
        else this.cles.set(a.old_key_id, { public_key: null, valid_from: null, valid_to: t });
        this.cles.set(a.new_key_id, { public_key: a.new_public_key, valid_from: t, valid_to: null });
        this.rotations.push(e);
      }
    } else if (outil === NOMS_RESERVES.DECISION) {
      if (e.approval?.ticket) this.decisions.set(e.approval.ticket, e);
    } else if (outil !== NOMS_RESERVES.ECHANGE) {
      const st = e.execution?.status;
      const ticket = e.policy?.ticket;
      if (st === "retenue" && ticket) {
        if (!this.retenues.has(ticket)) this.retenues.set(ticket, []);
        this.retenues.get(ticket).push(e);
        this.retenuesParHash.set(e.hash, e);
      }
      if (st === "executee" && e.approval?.ticket && !this.premiersExecutes.has(e.approval.ticket)) {
        this.premiersExecutes.set(e.approval.ticket, e);
      }
    }
    if (!this.cles.has(e.recorder_key_id)) {
      this.cles.set(e.recorder_key_id, { public_key: null, valid_from: decoderHorodatage(e.ts), valid_to: null });
    }
  }

  /**
   * Version de politique en vigueur à un instant (EX-12.13 : « celle du
   * dernier événement de politique dont le ts est au plus written_at »).
   * @param {number} instant ms
   * @returns {string|null}
   */
  versionA(instant) {
    let v = null;
    for (const h of this.historiquePolitiques) if (h.ts <= instant) v = h.policy_version;
    return v;
  }

  /**
   * Retenue sans décision d'un ticket (EX-7.17, EX-7.18).
   * @param {string} ticket
   * @returns {object|null}
   */
  retenueSansDecision(ticket) {
    if (this.decisions.has(ticket)) return null;
    const l = this.retenues.get(ticket);
    return l?.length ? l[l.length - 1] : null;
  }
}
