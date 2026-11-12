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

import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { ecrireHorodatage } from "@noortrace/noyau";

/** Fichier NDJSON en ajout seul, écritures ordonnées. */
class FichierNdjson {
  constructor(chemin) {
    this.chemin = chemin;
    this.file = Promise.resolve();
    fs.mkdirSync(path.dirname(chemin), { recursive: true, mode: 0o700 });
  }

  ajouter(objet) {
    const ligne = JSON.stringify(objet) + "\n";
    this.file = this.file.then(() => fsp.appendFile(this.chemin, ligne, { mode: 0o600 })).catch(() => {});
    return this.file;
  }

  attendre() {
    return this.file;
  }
}

/** Journal du service et compteurs. */
export class Supervision {
  /**
   * @param {{journal: string, horloge?: () => number, sortie?: (ligne: object) => void}} p
   */
  constructor(p) {
    this.journal = new FichierNdjson(p.journal);
    this.horloge = p.horloge ?? Date.now;
    this.sortie = p.sortie ?? null;
    /** @type {Map<string, number>} */
    this.compteurs = new Map();
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

  /** Attend l'écriture des lignes en cours. */
  async vider() {
    await this.journal.attendre();
  }
}
