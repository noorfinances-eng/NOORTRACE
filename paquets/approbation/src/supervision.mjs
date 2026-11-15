// Supervision du service : journal du service (hors chaîne, CT-3 3.4 et
// 10.4 : lectures du jeu, votes, objections, notifications et leur livraison,
// escalades, ouvertures et fermetures de fenêtre, opérations de l'annuaire
// refusées, alertes, avertissements de la politique), compteurs.
//
// Aucune ligne ne porte d'argument en clair ni d'empreinte des arguments
// (EX-7.24), ni le corps ni la clé d'une notification (EX-13.42) : les
// détails viennent de la machine et du service, qui n'y mettent que des
// identifiants, des noms d'outils, des adresses, des raisons et des instants.
// Les notifications elles-mêmes sont formées par le service et livrées par
// `notifications.mjs` (13.19).
//
// Le journal est tourné comme la boîte d'envoi : au-delà
// de `BORNES.journal_service_octets`, le fichier courant devient `.1`, les
// précédents prennent le numéro suivant, `BORNES.journal_service_fichiers`
// fichiers tournés au plus. Un fait qu'un pair peut provoquer à volonté
// (refus d'authentification) est consigné par période (`consignerCompte`) :
// une ligne à la première occurrence, puis une ligne de compte à la fin de
// la période, et non une ligne par requête.

import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { ecrireHorodatage } from "@noortrace/noyau";
import { BORNES } from "./bornes.mjs";

/** Fichier NDJSON en ajout seul, écritures ordonnées, tourné au-delà d'une taille. */
class FichierNdjson {
  /** @param {string} chemin @param {{tailleMax?: number, fichiers?: number}} [o] */
  constructor(chemin, o = {}) {
    this.chemin = chemin;
    this.tailleMax = o.tailleMax ?? BORNES.journal_service_octets;
    this.fichiers = o.fichiers ?? BORNES.journal_service_fichiers;
    this.file = Promise.resolve();
    fs.mkdirSync(path.dirname(chemin), { recursive: true, mode: 0o700 });
    let taille = 0;
    try {
      taille = fs.statSync(chemin).size;
    } catch {
      taille = 0;
    }
    this.taille = taille;
  }

  ajouter(objet) {
    const ligne = JSON.stringify(objet) + "\n";
    this.file = this.file
      .then(async () => {
        await fsp.appendFile(this.chemin, ligne, { mode: 0o600 });
        this.taille += Buffer.byteLength(ligne);
        if (this.taille > this.tailleMax) await this.#tourner();
      })
      .catch(() => {});
    return this.file;
  }

  /** Rotation : le fichier courant devient `.1`, les précédents le numéro suivant, `fichiers` au plus. */
  async #tourner() {
    await fsp.rm(`${this.chemin}.${this.fichiers}`, { force: true });
    for (let k = this.fichiers - 1; k >= 1; k--) {
      try {
        await fsp.rename(`${this.chemin}.${k}`, `${this.chemin}.${k + 1}`);
      } catch (e) {
        if (e.code !== "ENOENT") throw e;
      }
    }
    await fsp.rename(this.chemin, `${this.chemin}.1`);
    this.taille = 0;
  }

  attendre() {
    return this.file;
  }
}

/** Journal du service et compteurs. */
export class Supervision {
  /**
   * @param {{journal: string, horloge?: () => number, sortie?: (ligne: object) => void,
   *   tailleJournal?: number, fichiersJournal?: number}} p `tailleJournal`, `fichiersJournal` : essais seulement
   */
  constructor(p) {
    this.journal = new FichierNdjson(p.journal, { tailleMax: p.tailleJournal, fichiers: p.fichiersJournal });
    this.horloge = p.horloge ?? Date.now;
    this.sortie = p.sortie ?? null;
    /** @type {Map<string, number>} */
    this.compteurs = new Map();
    /** Périodes ouvertes de `consignerCompte` : clé → { type, detail, debut, n }. */
    this.periodes = new Map();
  }

  /**
   * Consigne un fait répétable à volonté par un pair, par période :
   * la première occurrence d'une période écrit une ligne (`count` 1), les
   * suivantes sont comptées ; à la première occurrence après la période, une
   * ligne `<type>_periode` porte le compte de la période close. Le compteur
   * `evenements_<type>` compte chaque occurrence.
   * @param {string} type
   * @param {object} [detail]
   * @param {number} [periodeMs]
   */
  consignerCompte(type, detail = {}, periodeMs = BORNES.auth_refusee_periode_ms) {
    const cle = `${type}\u0000${JSON.stringify(detail)}`;
    const t = this.horloge();
    let p = this.periodes.get(cle);
    if (p && t - p.debut >= periodeMs) {
      this.#clorePeriode(cle, p);
      p = undefined;
    }
    this.compter(`evenements_${type}`);
    if (p) {
      p.n += 1;
      return this.journal.attendre();
    }
    this.periodes.set(cle, { type, detail, debut: t, n: 1, periodeMs });
    const ligne = { ts: ecrireHorodatage(t), type, ...detail, count: 1, periode_ms: periodeMs };
    this.sortie?.(ligne);
    return this.journal.ajouter(ligne);
  }

  #clorePeriode(cle, p) {
    this.periodes.delete(cle);
    if (p.n <= 1) return;
    const ligne = { ts: ecrireHorodatage(this.horloge()), type: `${p.type}_periode`, ...p.detail, count: p.n, debut: ecrireHorodatage(p.debut), periode_ms: p.periodeMs };
    this.sortie?.(ligne);
    this.journal.ajouter(ligne);
  }

  /** Incrémente un compteur. */
  compter(nom, n = 1) {
    this.compteurs.set(nom, (this.compteurs.get(nom) ?? 0) + n);
  }

  /**
   * Consigne un fait dans le journal du service.
   * @param {string} type
   * @param {object} [detail]
   */
  consigner(type, detail = {}) {
    const ligne = { ts: ecrireHorodatage(this.horloge()), type, ...detail };
    this.compter(`evenements_${type}`);
    this.sortie?.(ligne);
    return this.journal.ajouter(ligne);
  }

  /** Clôt les périodes de `consignerCompte` et attend l'écriture des lignes en cours. */
  async vider() {
    for (const [cle, p] of [...this.periodes]) this.#clorePeriode(cle, p);
    await this.journal.attendre();
  }
}
