// Limitation des échecs d'authentification par jeton statique (CT-2 EX-18.3) :
// par identifiant de jeton présenté (les huit premiers caractères
// hexadécimaux du SHA-256 du jeton) et par connexion, 10 échecs par minute,
// puis refus de ce jeton ou de cette connexion pendant 60 s ; jamais par
// adresse source. Un jeton valide n'est jamais refusé à cause des échecs d'un
// autre : la clé est celle du jeton présenté.

import { createHash } from "node:crypto";

export const ECHECS_PAR_MINUTE = 10;
export const DUREE_REFUS_MS = 60000;

export class LimiteurEchecs {
  /** @param {{monotone: () => number}} o */
  constructor(o) {
    this.monotone = o.monotone;
    /** @type {Map<string, {echecs: number[], jusqua: number}>} */
    this.etats = new Map();
  }

  /**
   * Clé d'un jeton présenté (EX-18.3).
   * @param {Uint8Array} jeton
   * @returns {string}
   */
  cleJeton(jeton) {
    return "jeton:" + createHash("sha256").update(jeton).digest("hex").slice(0, 8);
  }

  _etat(cle) {
    let e = this.etats.get(cle);
    if (!e) {
      e = { echecs: [], jusqua: 0 };
      this.etats.set(cle, e);
    }
    return e;
  }

  /** La clé est-elle refusée en ce moment ? */
  bloque(cle) {
    const e = this.etats.get(cle);
    return e !== undefined && this.monotone() < e.jusqua;
  }

  /** Note un échec ; au dixième dans la minute, refus pendant 60 s. */
  echec(cle) {
    const t = this.monotone();
    const e = this._etat(cle);
    e.echecs = e.echecs.filter((x) => x > t - 60000);
    e.echecs.push(t);
    if (e.echecs.length >= ECHECS_PAR_MINUTE) {
      e.jusqua = t + DUREE_REFUS_MS;
      e.echecs = [];
    }
    if (this.etats.size > 100000) this.etats.delete(this.etats.keys().next().value);
  }

  /** Oublie une clé (connexion fermée). */
  oublier(cle) {
    this.etats.delete(cle);
  }
}
