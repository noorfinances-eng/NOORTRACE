// Bail et jeton de clôture (CT-2 §13). Un enregistreur n'écrit un journal
// que s'il détient le bail ; l'époque obtenue à l'acquisition, strictement
// croissante, est le jeton de clôture inscrit dans l'en-tête de chaque
// segment et dans le nom des fichiers d'intention, d'attente et des
// approbations (EX-13.1, EX-13.4). Les magasins `postgresql` et `etcd`, et la
// bascule entre hôtes, relèvent du lot de haute disponibilité : ce module
// fixe l'interface et fournit le magasin `file` d'un seul hôte.

import fs from "node:fs";
import path from "node:path";
import { ErreurEnregistreur } from "./erreurs.mjs";

/**
 * Interface d'un magasin de bail.
 * @abstract
 */
export class MagasinBail {
  /** Type (`file`, `postgresql`, `etcd`). */
  get type() {
    throw new Error("à implémenter");
  }

  /**
   * Acquiert le bail ; rend l'époque (entier ≥ 1, strictement croissante).
   * @returns {Promise<number>}
   * @throws {ErreurEnregistreur} raison `bail_non_detenu` si un autre le détient
   */
  async acquerir() {
    throw new Error("à implémenter");
  }

  /** Le bail est tenu pour valide (horloge monotone, EX-13.3). */
  valide() {
    return false;
  }

  /**
   * Revérifie l'époque auprès du magasin après un fdatasync et avant de
   * répondre (EX-13.10 (2)) ; le magasin `file` n'a rien à revérifier.
   * @returns {Promise<boolean>}
   */
  async verifierApresEcriture() {
    return this.valide();
  }

  /** Libère le bail (arrêt propre). */
  async liberer() {}
}

function processusVivant(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === "EPERM";
  }
}

/**
 * Magasin `file` (13.2) : un seul hôte. Le verrou `flock(2)` n'est pas offert
 * par Node.js sans module natif ; il est émulé par un fichier verrou créé en
 * exclusion (O_CREAT | O_EXCL) qui porte le PID du détenteur, libéré à l'arrêt
 * et repris quand son détenteur n'est plus vivant (arrêt brutal). L'époque est
 * le contenu de `<path>.epoch`, incrémenté et forcé sur disque à chaque
 * acquisition. Lecture consignée dans le LISEZMOI.
 */
export class MagasinBailFichier extends MagasinBail {
  /** @param {string} chemin `lease.store.path` */
  constructor(chemin) {
    super();
    this.chemin = chemin;
    this.epoque = 0;
    this.detenu = false;
  }

  get type() {
    return "file";
  }

  async acquerir() {
    fs.mkdirSync(path.dirname(this.chemin), { recursive: true, mode: 0o700 });
    for (let essai = 0; essai < 2; essai++) {
      try {
        const fd = fs.openSync(this.chemin, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
        fs.writeSync(fd, `${process.pid}\n`);
        fs.fdatasyncSync(fd);
        fs.closeSync(fd);
        break;
      } catch (e) {
        if (e.code !== "EEXIST") throw e;
        const pid = Number.parseInt(fs.readFileSync(this.chemin, "utf8"), 10);
        if (Number.isSafeInteger(pid) && pid > 0 && pid !== process.pid && processusVivant(pid)) {
          throw new ErreurEnregistreur("bail_non_detenu", "noortrace: bail non detenu", { donnees: { event: "lease_standby" } });
        }
        // Détenteur mort (arrêt brutal) : le verrou est repris.
        fs.rmSync(this.chemin, { force: true });
        if (essai === 1) throw new ErreurEnregistreur("bail_non_detenu", "noortrace: bail non detenu");
      }
    }
    const fichierEpoque = `${this.chemin}.epoch`;
    let precedente = 0;
    if (fs.existsSync(fichierEpoque)) {
      const t = fs.readFileSync(fichierEpoque, "utf8").trim();
      if (!/^[0-9]{1,20}$/.test(t)) throw new ErreurEnregistreur("bail", "noortrace: epoque du bail illisible");
      precedente = Number(t);
    }
    const epoque = precedente + 1;
    const tmp = `${fichierEpoque}.tmp`;
    const fd = fs.openSync(tmp, "w", 0o600);
    fs.writeSync(fd, `${epoque}\n`);
    fs.fdatasyncSync(fd);
    fs.closeSync(fd);
    fs.renameSync(tmp, fichierEpoque);
    const d = fs.openSync(path.dirname(this.chemin), "r");
    fs.fsyncSync(d);
    fs.closeSync(d);
    this.epoque = epoque;
    this.detenu = true;
    return epoque;
  }

  valide() {
    return this.detenu;
  }

  async liberer() {
    if (!this.detenu) return;
    this.detenu = false;
    try {
      const pid = Number.parseInt(fs.readFileSync(this.chemin, "utf8"), 10);
      if (pid === process.pid) fs.rmSync(this.chemin, { force: true });
    } catch {
      // déjà libéré
    }
  }

  /** Perte du bail simulée (tests du mode dégradé « bail »). */
  perdre() {
    this.detenu = false;
  }
}

/** Magasin en mémoire, d'époque donnée (tests, rejeu de vecteurs). */
export class MagasinBailMemoire extends MagasinBail {
  /** @param {number} [epoque] prochaine époque rendue */
  constructor(epoque = 1) {
    super();
    this.prochaine = epoque;
    this.epoque = 0;
    this.detenu = false;
  }

  get type() {
    return "file";
  }

  async acquerir() {
    this.epoque = this.prochaine++;
    this.detenu = true;
    return this.epoque;
  }

  valide() {
    return this.detenu;
  }

  async liberer() {
    this.detenu = false;
  }

  perdre() {
    this.detenu = false;
  }
}
