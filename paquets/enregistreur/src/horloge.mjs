// Horloges et règle de `ts` (CT-2 §7.4) : `ts` est lu sur l'horloge murale
// UTC à l'instant où l'écrivain fixe `seq`, à la milliseconde, puis
// ts = max(ts lu, ts précédent) (EX-7.9). Un recul au-delà de
// `clock.max_backstep_ms` ou un saut en avant au-delà de l'avance monotone
// plus `clock.max_forward_ms` (EX-7.13) font entrer l'enregistreur en mode
// dégradé « horloge », bloquant pour tout (14.2). Les durées viennent de
// l'horloge monotone.

import { ErreurEnregistreur } from "./erreurs.mjs";

/** Horloges du système : murale (ms UNIX) et monotone (ms). */
export const HORLOGE_SYSTEME = Object.freeze({
  murale: () => Date.now(),
  monotone: () => Number(process.hrtime.bigint() / 1000000n),
});

/**
 * Horloge réglable pour les tests : murale et monotone avancent ensemble,
 * la murale peut être déplacée seule (recul, saut).
 */
export class HorlogeReglable {
  /** @param {number} murale instant initial, ms UNIX */
  constructor(murale) {
    this.m = murale;
    this.mono = 1_000_000;
  }

  murale() {
    return this.m;
  }

  monotone() {
    return this.mono;
  }

  /** Avance les deux horloges. @param {number} ms */
  avancer(ms) {
    this.m += ms;
    this.mono += ms;
  }

  /** Place l'horloge murale seule (recul ou saut). @param {number} instant */
  placerMurale(instant) {
    this.m = instant;
  }

  /** Place les deux horloges à un instant mural. @param {number} instant */
  aller(instant) {
    if (instant >= this.m) this.avancer(instant - this.m);
    else this.m = instant;
  }
}

/** Valeurs par défaut des réglages de `clock` (7.4). */
export const DEFAUTS_HORLOGE = Object.freeze({
  max_backstep_ms: 5000,
  warn_skew_ms: 1000,
  max_forward_ms: 60000,
  max_wait_ms: 3600000,
});

/**
 * Contrôle de l'horloge par l'écrivain (EX-7.9, EX-7.10, EX-7.13).
 */
export class ControleurHorloge {
  /**
   * @param {{murale: () => number, monotone: () => number}} horloge
   * @param {object} reglages membre `clock` de la configuration
   * @param {{entrer: Function, sortir: Function, actif: Function}} degrade état du mode dégradé
   * @param {{consigner: Function}} [journal] journal d'exploitation
   */
  constructor(horloge, reglages, degrade, journal) {
    this.horloge = horloge;
    this.reglages = { ...DEFAUTS_HORLOGE, ...(reglages ?? {}) };
    this.degrade = degrade;
    this.journal = journal;
    this.dernierLu = null;
    this.dernierMonotone = null;
    this.saut = false;
    this.ecart = 0;
  }

  /** Instant monotone (pour les durées). */
  monotone() {
    return this.horloge.monotone();
  }

  /** Instant mural brut (journal d'exploitation, written_at, generated_at). */
  murale() {
    return this.horloge.murale();
  }

  /**
   * Confirmation de l'exploitant après un saut en avant
   * (`noortrace-ctl clock --accept`, EX-7.13) : consignée.
   */
  accepter() {
    this.saut = false;
    this.dernierLu = null;
    this.dernierMonotone = null;
    this.journal?.consigner("info", "noyau", "clock_accepted", {});
    this.degrade.sortir("horloge");
  }

  /**
   * Contrôle de saut en avant d'EX-7.13 pour un instant lu hors du
   * scellement (point de contrôle, clôture, EX-12.24) : même comparaison
   * qu'avant de fixer `ts` (avance murale depuis l'événement précédent contre
   * avance monotone, plus `clock.max_forward_ms`). Un saut fait entrer en mode
   * dégradé « horloge » et rend faux ; la référence (dernier événement) n'est
   * pas déplacée.
   * @param {number} lu instant mural lu
   * @returns {boolean} vrai si l'instant est admis
   */
  controlerAvance(lu) {
    if (this.dernierLu === null || this.dernierMonotone === null) return true;
    const mono = this.horloge.monotone();
    const avanceMurale = lu - this.dernierLu;
    const avanceMonotone = mono - this.dernierMonotone;
    if (avanceMurale <= avanceMonotone + this.reglages.max_forward_ms) return true;
    if (!this.saut) {
      this.saut = true;
      this.journal?.consigner("error", "noyau", "clock_forward_jump", { ecart_ms: avanceMurale - avanceMonotone });
    }
    this.degrade.entrer("horloge", { event: "clock_forward_jump" });
    return false;
  }

  /**
   * Fixe `ts` pour un événement (EX-7.9) : lève une ErreurEnregistreur
   * (raison `horloge`) en mode dégradé « horloge ».
   * @param {number|null} tsPrecedent `ts` du dernier événement durable, ms
   * @param {{captureA?: number}} [options] instant de capture d'un événement en attente (EX-14.10)
   * @returns {number} ts en millisecondes
   */
  fixerTs(tsPrecedent, options = {}) {
    const lu = this.horloge.murale();
    const mono = this.horloge.monotone();
    const r = this.reglages;
    // Saut en avant (EX-7.13) : avance murale plus grande que l'avance monotone plus la tolérance.
    if (this.dernierLu !== null && this.dernierMonotone !== null) {
      const avanceMurale = lu - this.dernierLu;
      const avanceMonotone = mono - this.dernierMonotone;
      if (avanceMurale > avanceMonotone + r.max_forward_ms) {
        if (!this.saut) {
          this.saut = true;
          this.journal?.consigner("error", "noyau", "clock_forward_jump", { ecart_ms: avanceMurale - avanceMonotone });
        }
        this.degrade.entrer("horloge", { event: "clock_forward_jump" });
        throw new ErreurEnregistreur("horloge", "noortrace: enregistreur en mode degrade (horloge)");
      }
    }
    if (this.saut) {
      // Revenue dans la tolérance : sortie du mode.
      this.saut = false;
    }
    if (tsPrecedent !== null && lu < tsPrecedent - r.max_backstep_ms) {
      this.ecart = lu - tsPrecedent;
      if (!this.degrade.actif("horloge")) {
        this.journal?.consigner("error", "noyau", "clock_backstep", { ecart_ms: tsPrecedent - lu });
      }
      this.degrade.entrer("horloge", { event: "clock_backstep" });
      throw new ErreurEnregistreur("horloge", "noortrace: enregistreur en mode degrade (horloge)");
    }
    if (this.degrade.actif("horloge")) {
      // Recul sous le seuil mais horloge pas encore revenue au ts précédent :
      // le mode ne se lève qu'une fois ts précédent rejoint (EX-7.9, EX-14.11).
      if (tsPrecedent !== null && lu < tsPrecedent) {
        throw new ErreurEnregistreur("horloge", "noortrace: enregistreur en mode degrade (horloge)");
      }
      this.degrade.sortir("horloge");
    }
    if (tsPrecedent !== null && tsPrecedent - lu > r.warn_skew_ms) {
      this.journal?.consigner("warning", "noyau", "clock_skew", { ecart_ms: tsPrecedent - lu });
    }
    this.ecart = tsPrecedent === null ? 0 : lu - tsPrecedent;
    this.dernierLu = lu;
    this.dernierMonotone = mono;
    const base = options.captureA ?? lu;
    return tsPrecedent === null ? base : Math.max(base, tsPrecedent);
  }
}
