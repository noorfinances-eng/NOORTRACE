// File des échanges de modèle observés (CT-2 EX-6.11 (3), EX-6.13) : seul
// `echangeModele` appelé depuis un point d'observation d'un adaptateur de cadre
// (6.6, lot suivant) passe par une file, bornée (`fileMax`, défaut 1 000),
// vidée par une unique tâche de fond. File pleine : l'échange le plus récent
// est abandonné, compté (`echangesPerdus`) et noté sur la sortie d'erreur ;
// une erreur de cette file n'atteint jamais l'agent. Un échange que la tâche
// ne peut pas remettre parce que le démon est injoignable reste en tête, tant
// que sa requête n'a pas été écrite sur la prise (`envoyee` faux), et il est
// retenté après la reprise de connexion ; un échange dont la requête a été
// écrite sans réponse n'est jamais renvoyé : il est abandonné et compté.
//
// Ce module n'ajoute rien à l'interface publique d'EX-6.9 (le client et la
// session) : c'est l'outil des adaptateurs, dont les points d'observation ne
// doivent jamais bloquer ni faire échouer l'agent. Un appel d'outil n'y passe
// jamais (EX-6.11).

import { ErreurNoortraceIndisponible } from "./erreurs.mjs";
import { delaiReprise } from "./index.mjs";

export class FileEchanges {
  /**
   * @param {import("./index.mjs").Session} session
   * @param {{fileMax?: number, sortie?: {write: (s: string) => void}}} [o]
   */
  constructor(session, o = {}) {
    this.session = session;
    this.fileMax = o.fileMax ?? 1000;
    this.sortie = o.sortie ?? process.stderr;
    this.file = [];
    this.echangesPerdus = 0;
    this.tache = null;
  }

  /**
   * Met un échange en file, sans jamais attendre ni lever (EX-6.11 (3)).
   * @param {object} p paramètres de `session.echangeModele`
   * @returns {boolean} l'échange est en file
   */
  ajouter(p) {
    if (this.file.length >= this.fileMax) {
      this.echangesPerdus++;
      this.sortie.write(`noortrace-sdk: file des echanges pleine (${this.fileMax}) ; echange abandonne, ${this.echangesPerdus} perdu(s)\n`);
      return false;
    }
    this.file.push(p);
    if (!this.tache) this.tache = this._vider().finally(() => (this.tache = null));
    return true;
  }

  /** Attend que la file soit vide (arrêt, essais). */
  async vide() {
    while (this.tache) await this.tache;
  }

  async _vider() {
    let n = 0;
    while (this.file.length) {
      const p = this.file[0];
      try {
        await this.session.echangeModele(p);
        this.file.shift();
        n = 0;
      } catch (e) {
        if (e instanceof ErreurNoortraceIndisponible && !e.envoyee) {
          // Démon injoignable avant l'écriture : l'échange reste en tête et sera remis après la reprise (EX-6.13).
          await new Promise((r) => {
            const t = setTimeout(r, delaiReprise(Math.min(n, 4)));
            t.unref?.();
          });
          n++;
          continue;
        }
        this.file.shift();
        this.echangesPerdus++;
        this.sortie.write(`noortrace-sdk: echange non remis (${e?.name ?? "erreur"}) ; ${this.echangesPerdus} perdu(s)\n`);
      }
    }
  }
}
