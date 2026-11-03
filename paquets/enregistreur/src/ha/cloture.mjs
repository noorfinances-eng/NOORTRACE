// Jeton de clôture côté stockage et bascule (CT-2 §13.3, §13.4) :
//   - EX-13.5 (1) : un fichier d'intention ou d'attente n'est ouvert que si
//     son époque n'est inférieure à aucune époque présente dans les noms du
//     répertoire (le segment l'est déjà par l'écrivain) ;
//   - 13.4 pas 1 : avant toute acquisition, la ligne de contrôle de la clé du
//     MAC de relais est comparée à celle du dernier fichier `mac-*` (EX-7.22) ;
//     une différence est une erreur de configuration (`relay_mac_key_mismatch`)
//     et l'instance ne prend pas le bail ;
//   - EX-13.10 (3) : le repreneur consigne la taille finale de chaque fichier
//     d'époque inférieure, et la supervision signale toute croissance
//     ultérieure comme une fourche (`journal_fork`, alerte critique).
// Le moyen de rendre le stockage du prédécesseur inaccessible en écriture
// (EX-13.10 (1), `lease.fencing` : détachement du volume ou réservation
// persistante) est exécuté par l'orchestrateur (CT-8) : le démon n'a ni le
// droit ni le moyen de détacher un volume ; il le nomme dans `lease_acquired`.

import fs from "node:fs/promises";
import path from "node:path";
import { decouperLignes } from "../fichiers.mjs";
import { analyserJsonIntegral } from "../jcs-integral.mjs";
import { ligneControleMac } from "../approbations.mjs";
import { ErreurEnregistreur } from "../erreurs.mjs";

/** Répertoires et motifs des fichiers qui portent une époque dans leur nom (12.1). */
export const FICHIERS_A_EPOQUE = Object.freeze([
  ["segments", /^seg-[0-9]{16}-([0-9]{20})\.ndjson$/],
  ["intentions", /^intentions-([0-9]{20})\.ndjson$/],
  ["attente", /^attente-([0-9]{20})\.ndjson$/],
  ["approbations", /^(?:approbations|mac)-([0-9]{20})\.ndjson$/],
  ["worm", /^copies-([0-9]{20})\.ndjson$/],
]);

async function noms(dir) {
  try {
    return await fs.readdir(dir);
  } catch {
    return [];
  }
}

/**
 * Plus grande époque présente dans les noms d'un répertoire, ou null.
 * @param {string} dir
 * @param {RegExp} motif groupe 1 = époque sur 20 chiffres
 */
export async function epoqueMaxNoms(dir, motif) {
  let max = null;
  for (const n of await noms(dir)) {
    const r = motif.exec(n);
    if (r) max = Math.max(max ?? 0, Number(r[1]));
  }
  return max;
}

/**
 * EX-13.5 (1) : refuse l'ouverture d'un fichier d'époque `epoque` dans un
 * répertoire où une époque supérieure est présente (un écrivain d'époque
 * inférieure a perdu son bail).
 * @param {string} repertoireJournal
 * @param {"intentions"|"attente"} sorte
 * @param {number} epoque
 */
export async function verifierEpoqueOuverture(repertoireJournal, sorte, epoque) {
  const [dir, motif] = FICHIERS_A_EPOQUE.find(([d]) => d === sorte);
  const max = await epoqueMaxNoms(path.join(repertoireJournal, dir), motif);
  if (max !== null && max > epoque) {
    throw new ErreurEnregistreur("bail", `noortrace: un ecrivain d'epoque superieure existe (${sorte}, EX-13.5)`);
  }
}

/**
 * Compare la ligne de contrôle de la clé du MAC de relais à celle du dernier
 * fichier `mac-*` (13.4 pas 1, EX-7.22), sans rien écrire ni tronquer : le
 * bail n'est pas encore détenu.
 * @param {string} repertoireJournal
 * @param {Uint8Array} cleMac
 * @returns {Promise<boolean|null>} null : aucun fichier ou ligne illisible
 */
export async function controleCleMac(repertoireJournal, cleMac) {
  const dir = path.join(repertoireJournal, "approbations");
  const fichiers = (await noms(dir)).filter((n) => /^mac-[0-9]{20}\.ndjson$/.test(n)).sort();
  if (!fichiers.length) return null;
  const octets = new Uint8Array(await fs.readFile(path.join(dir, fichiers.at(-1))));
  const premiere = decouperLignes(octets)[0];
  if (!premiere?.complete) return null;
  let o;
  try {
    o = analyserJsonIntegral(premiere.octets);
  } catch {
    return null;
  }
  if (o?.kind !== "controle" || typeof o.mac !== "string") return null;
  return o.mac === ligneControleMac(cleMac).mac;
}

/**
 * Tailles des fichiers d'époque inférieure à `epoque` (EX-13.10 (3)).
 * @param {string} repertoireJournal
 * @param {number} epoque
 * @returns {Promise<{fichier: string, octets: number}[]>} chemins relatifs au journal
 */
export async function taillesAnterieures(repertoireJournal, epoque) {
  const r = [];
  for (const [dir, motif] of FICHIERS_A_EPOQUE) {
    for (const n of (await noms(path.join(repertoireJournal, dir))).sort()) {
      const m = motif.exec(n);
      if (!m || Number(m[1]) >= epoque) continue;
      try {
        const st = await fs.stat(path.join(repertoireJournal, dir, n));
        r.push({ fichier: `${dir}/${n}`, octets: st.size });
      } catch {
        // supprimé entre-temps
      }
    }
  }
  return r;
}

/**
 * Surveillance de la fourche (EX-13.10 (3), 17.4 « Fourche ») : toute
 * croissance d'un fichier d'époque inférieure après la reprise est consignée
 * `journal_fork` (une fois par fichier). Un fichier supprimé par la rotation
 * de l'écrivain (EX-12.13) n'est pas une fourche.
 */
export class SurveillanceFourche {
  /**
   * @param {string} repertoireJournal
   * @param {{fichier: string, octets: number}[]} tailles
   * @param {{consigner: Function}} journal
   * @param {{intervalleMs?: number, maintenant?: () => number}} [o]
   */
  constructor(repertoireJournal, tailles, journal, o = {}) {
    this.repertoire = repertoireJournal;
    this.tailles = new Map(tailles.map((t) => [t.fichier, t.octets]));
    this.journal = journal;
    this.signales = new Set();
    this.intervalle = o.intervalleMs ?? 10000;
    this.maintenant = o.maintenant ?? (() => Date.now());
    this.dernier = null;
  }

  /**
   * Contrôle les tailles ; rend les fourches constatées par cet appel.
   * @param {{force?: boolean}} [o]
   */
  async controler(o = {}) {
    const t = this.maintenant();
    if (!o.force && this.dernier !== null && t - this.dernier < this.intervalle) return [];
    this.dernier = t;
    const nouvelles = [];
    for (const [fichier, avant] of this.tailles) {
      if (this.signales.has(fichier)) continue;
      let st;
      try {
        st = await fs.stat(path.join(this.repertoire, fichier));
      } catch {
        continue;
      }
      if (st.size > avant) {
        this.signales.add(fichier);
        nouvelles.push({ fichier, octets_avant: avant, octets: st.size });
        this.journal.consigner("error", "stockage", "journal_fork", { fichier, octets_avant: avant, octets: st.size });
      }
    }
    return nouvelles;
  }
}
