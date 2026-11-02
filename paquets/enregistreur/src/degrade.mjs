// État du mode dégradé (CT-2 §14) : raisons actives (`stockage`, `cle`,
// `bail`, `horloge`, `attente`, `approbation`), instant d'entrée, lignes
// `degraded_enter` / `degraded_exit` du journal d'exploitation et jauge
// `noortrace_degraded{reason}` (EX-14.7, EX-14.11). La chaîne ne reçoit rien
// à l'entrée en mode dégradé (EX-14.7).

import { RAISONS_DEGRADE } from "./erreurs.mjs";

export class EtatDegrade {
  /**
   * @param {{consigner: Function}|null} journal
   * @param {{jauge: Function}|null} metriques
   * @param {() => number} murale
   */
  constructor(journal, metriques, murale = () => Date.now()) {
    this.journal = journal;
    this.metriques = metriques;
    this.murale = murale;
    /** @type {Map<string, {depuis: number, details: object}>} */
    this.actives = new Map();
    for (const r of RAISONS_DEGRADE) this.metriques?.jauge("noortrace_degraded", { reason: r }, 0);
  }

  /**
   * @param {string} raison
   * @param {object} [details]
   */
  entrer(raison, details = {}) {
    if (this.actives.has(raison)) return;
    this.actives.set(raison, { depuis: this.murale(), details });
    this.journal?.consigner("error", "noyau", "degraded_enter", { reason: raison, ...details });
    this.metriques?.jauge("noortrace_degraded", { reason: raison }, 1);
  }

  /** @param {string} raison */
  sortir(raison) {
    if (!this.actives.has(raison)) return;
    this.actives.delete(raison);
    this.journal?.consigner("info", "noyau", "degraded_exit", { reason: raison });
    this.metriques?.jauge("noortrace_degraded", { reason: raison }, 0);
  }

  /** @param {string} raison */
  actif(raison) {
    return this.actives.has(raison);
  }

  /** Une raison active au moins. */
  get enModeDegrade() {
    return this.actives.size > 0;
  }

  /** Raisons actives, dans l'ordre de la matrice. */
  raisons() {
    return RAISONS_DEGRADE.filter((r) => this.actives.has(r));
  }

  /** Plus ancien instant d'entrée, ms, ou null. */
  depuis() {
    let d = null;
    for (const v of this.actives.values()) if (d === null || v.depuis < d) d = v.depuis;
    return d;
  }
}
