// Système d'identité local, hors production (CT-3 EX-13.47, contrat 2.9) :
// scrypt (N = 131 072, r = 8, p = 1, 32 octets) comparé en temps constant ;
// même calcul sur un sel fixe pour un nom inconnu ; deux calculs à la fois au
// plus ; verrou progressif par nom (min(2^(f − 5), 900) s dès f ≥ 5), 10 000
// noms suivis au plus, les noms non verrouillés oubliés d'abord.

import crypto from "node:crypto";
import { egauxTempsConstant } from "./outils.mjs";

export const PARAMETRES_SCRYPT = Object.freeze({ N: 131072, r: 8, p: 1, maxmem: 128 * 1024 * 1024 + 64 * 1024 * 1024 });
export const MAX_NOMS = 10000;
export const MAX_CALCULS = 2;

/** Sel fixe du calcul fait pour un nom inconnu : 16 premiers octets de SHA-256 d'une étiquette. */
const SEL_INCONNU = crypto.createHash("sha256").update("noortrace/console/local/sel-nom-inconnu").digest().subarray(0, 16);
const CLE_INCONNUE = Buffer.alloc(32);

/** scrypt des octets UTF-8 du mot de passe, sans normalisation. */
export function deriver(motDePasse, sel) {
  return new Promise((resoudre, rejeter) => {
    crypto.scrypt(Buffer.from(motDePasse, "utf8"), sel, 32, PARAMETRES_SCRYPT, (e, cle) => (e ? rejeter(e) : resoudre(cle)));
  });
}

/** Délai du verrou en secondes après `f` échecs consécutifs (0 sous 5). */
export const delaiVerrouS = (f) => (f < 5 ? 0 : Math.min(2 ** (f - 5), 900));

export class SystemeLocal {
  /**
   * @param {{comptes: Map<string, {salt: Buffer, key: Buffer}>, domaine: string, horloge: () => number}} o
   */
  constructor({ comptes, domaine, horloge }) {
    this.comptes = comptes;
    this.domaine = domaine;
    this.horloge = horloge;
    this.calculs = 0;
    /** @type {Map<string, {f: number, dernierMs: number}>} nom → échecs, dans l'ordre de la dernière mise à jour */
    this.echecs = new Map();
  }

  /** Identité de session d'un compte (EX-13.7, EX-13.47). */
  identite(nom) {
    return `utilisateur ${this.domaine} ${nom}`;
  }

  /**
   * Vérifie un nom et un mot de passe.
   * @returns {Promise<{ok: true, identite: string, authTimeMs: number} | {ok: false, code: string, retryAfterS?: number}>}
   */
  async verifier(nom, motDePasse) {
    const recuMs = this.horloge();
    const e = this.echecs.get(nom);
    if (e && e.f >= 5) {
      const resteMs = e.dernierMs + delaiVerrouS(e.f) * 1000 - recuMs;
      if (resteMs > 0) return { ok: false, code: "essai_trop_tot", retryAfterS: Math.ceil(resteMs / 1000) };
    }
    if (this.calculs >= MAX_CALCULS) return { ok: false, code: "essai_trop_tot", retryAfterS: 1 };
    this.calculs++;
    let bon;
    try {
      const compte = this.comptes.get(nom);
      const cle = await deriver(motDePasse, compte ? compte.salt : SEL_INCONNU);
      bon = egauxTempsConstant(cle, compte ? compte.key : CLE_INCONNUE) && compte !== undefined;
    } finally {
      this.calculs--;
    }
    const verifieMs = this.horloge();
    if (bon) {
      this.echecs.delete(nom);
      return { ok: true, identite: this.identite(nom), authTimeMs: verifieMs };
    }
    this.noterEchec(nom, verifieMs);
    return { ok: false, code: "identifiants_refuses" };
  }

  /** Compte un échec du nom ; au-delà de 10 000 noms suivis, oublie d'abord le plus ancien des noms non verrouillés. */
  noterEchec(nom, instantMs) {
    const avant = this.echecs.get(nom);
    this.echecs.delete(nom);
    if (this.echecs.size >= MAX_NOMS) {
      let oublie = null;
      for (const [n, x] of this.echecs) {
        if (x.f < 5) {
          oublie = n;
          break;
        }
      }
      if (oublie === null) [oublie] = this.echecs.keys();
      this.echecs.delete(oublie);
    }
    this.echecs.set(nom, { f: (avant?.f ?? 0) + 1, dernierMs: instantMs });
  }
}
