// Remise au composant d'ancrage de CT-5 (et au registre de CT-4) : à chaque
// point de contrôle écrit (EX-12.27) et à chaque clôture de période (3.1,
// « Clôture de période »). Jamais bloquant (14.2, lignes « Ancrage » et
// « Registre ») : la remise est faite sans attendre le résultat, une erreur
// est consignée (`anchor_pending`) et la supervision réessaie. Le composant
// d'ancrage lui-même est un lot suivant ; ce module fixe l'interface et une
// implémentation en mémoire.

import { empreinteAncre, hacherPoint, periodMeta } from "@noortrace/noyau";

/**
 * Interface du composant d'ancrage vu du cœur.
 * @abstract
 */
export class ComposantAncrage {
  /**
   * Un point de contrôle vient d'être écrit et synchronisé dans la série.
   * @param {{point: object, checkpointHash: string, fingerprint: string, chemin: string}} remise
   * @returns {Promise<void>|void}
   */
  remettrePoint(remise) {
    void remise;
  }

  /**
   * Une période vient d'être close.
   * @param {{manifeste: object, signature: object, periodHash: string, fingerprint: string, periodMeta: object,
   *   cheminManifeste: string, cheminSignature: string, cheminSerie: string}} remise
   * @returns {Promise<void>|void}
   */
  remettreCloture(remise) {
    void remise;
  }
}

/** Composant qui garde les remises en mémoire (tests, démonstration). */
export class AncrageMemoire extends ComposantAncrage {
  constructor() {
    super();
    this.points = [];
    this.clotures = [];
  }

  remettrePoint(remise) {
    this.points.push(remise);
  }

  remettreCloture(remise) {
    this.clotures.push(remise);
  }
}

/**
 * Remise d'un point (forme commune).
 * @param {object} point
 * @param {string} chemin
 */
export function remisePoint(point, chemin) {
  const checkpointHash = hacherPoint(point);
  return { point, checkpointHash, fingerprint: empreinteAncre(point.org_id, point.journal_id, checkpointHash), chemin };
}

/**
 * Remise d'une clôture (forme commune) : manifeste, signature, periodHash,
 * empreinte d'ancre et PeriodMeta de CT-1 §10.4.
 */
export function remiseCloture(p) {
  return {
    ...p,
    fingerprint: empreinteAncre(p.manifeste.org_id, p.manifeste.journal_id, p.periodHash),
    periodMeta: periodMeta(p.manifeste),
  };
}
