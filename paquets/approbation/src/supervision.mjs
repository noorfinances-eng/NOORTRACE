// Supervision du service : journal du service (hors chaîne, CT-3 3.4 et
// 10.4 : lectures du jeu, votes, objections, notifications, escalades,
// ouvertures et fermetures de fenêtre, alertes, avertissements de la
// politique), boîte d'envoi des notifications (EX-7.12, EX-7.13, EX-13.3),
// compteurs et état servi par `GET /v0/etat` (EX-12.12).
//
// Aucune ligne ne porte d'argument en clair ni d'empreinte des arguments
// (EX-7.24) : les détails viennent de la machine, qui n'y met que des
// identifiants de ticket, des noms d'outils, des adresses et des instants.

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

/** Journal du service, notifications et compteurs. */
export class Supervision {
  /**
   * @param {{journal: string, notifications: string, horloge?: () => number, console_origin?: string|null,
   *   sortie?: (ligne: object) => void}} p
   */
  constructor(p) {
    this.journal = new FichierNdjson(p.journal);
    this.boite = new FichierNdjson(p.notifications);
    this.horloge = p.horloge ?? Date.now;
    this.console_origin = p.console_origin ?? null;
    this.sortie = p.sortie ?? null;
    /** @type {Map<string, number>} */
    this.compteurs = new Map();
    /** Écouteurs de notifications (étape 6 : canaux de la console). */
    this.ecouteurs = new Set();
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

  /**
   * Notification (EX-7.12) : identifiant du ticket, nom annoncé, échéance et
   * lien vers la console ; jamais les arguments. Déposée dans la boîte
   * d'envoi et remise aux écouteurs.
   * @param {object} n
   */
  notifier(n) {
    const lien = this.console_origin && n.ticket ? `${this.console_origin}/#ticket=${encodeURIComponent(n.ticket)}` : null;
    const ligne = { ts: ecrireHorodatage(this.horloge()), ...n, link: lien };
    this.compter(`notifications_${n.kind}`);
    for (const f of this.ecouteurs) {
      try {
        f(ligne);
      } catch {
        // un écouteur en défaut ne bloque pas le service
      }
    }
    return this.boite.ajouter(ligne);
  }

  /** Attend l'écriture des lignes en cours. */
  async vider() {
    await this.journal.attendre();
    await this.boite.attendre();
  }
}
