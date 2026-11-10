// Compteur de numéros de série du serveur interne (AN-26 : unique et
// strictement croissant à travers les redémarrages ; RFC 3161 §2.4.2 : la
// propriété est préservée même après une interruption du service). Le
// numéro suivant est écrit et synchronisé (`fsync` du fichier puis du
// répertoire) AVANT que la réponse qui le porte soit rendue ; un seul
// processus émetteur par répertoire, tenu par un fichier de verrou créé en
// exclusivité (`O_EXCL`). Le compteur ne consigne rien d'autre : le journal
// des jetons est tenu par le client (AN-28).

import fs from "node:fs";
import path from "node:path";

export class ErreurCompteur extends Error {
  constructor(message) {
    super(message);
    this.name = "ErreurCompteur";
  }
}

const FICHIER_SERIE = "serie";
const FICHIER_VERROU = "serie.verrou";
const FICHIER_TEMPORAIRE = "serie.tmp";

/** Vrai si un processus de ce pid existe encore (EPERM compte comme vivant). */
function processusVivant(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === "EPERM";
  }
}

/** Répertoires dont un compteur est ouvert dans ce processus (verrou par chemin, dans le processus aussi : R-E-1). */
const OUVERTS = new Set();

export class Compteur {
  /**
   * Ouvre (ou crée) le compteur d'un répertoire et prend son verrou. Un second
   * compteur du même processus sur le même répertoire est refusé (AN-26 : un
   * seul émetteur par clé ; le fichier de verrou porte le pid, qui ne distingue
   * pas deux compteurs d'un même processus).
   * @param {{repertoire: string, debut?: bigint|number, pid?: number, vivant?: (pid: number) => boolean}} o
   *   `debut` : premier numéro émis par un compteur neuf (1 par défaut) ;
   *   `vivant` : test de vie d'un processus, injectable pour les essais.
   */
  static ouvrir(o) {
    if (!o || typeof o.repertoire !== "string" || o.repertoire.length === 0) throw new TypeError("compteur : repertoire attendu");
    const debut = BigInt(o.debut ?? 1);
    if (debut < 1n) throw new RangeError("compteur : debut ≥ 1 attendu");
    fs.mkdirSync(o.repertoire, { recursive: true, mode: 0o700 });
    const clef = Compteur.clefRepertoire(o.repertoire);
    if (OUVERTS.has(clef)) throw new ErreurCompteur(`compteur ${o.repertoire} : déjà ouvert dans ce processus (AN-26 : un seul émetteur par clé)`);
    const c = new Compteur(o.repertoire, o.pid ?? process.pid, o.vivant ?? processusVivant);
    c.#clef = clef;
    c.#verrouiller();
    OUVERTS.add(clef);
    try {
      c.#relire(debut);
    } catch (e) {
      c.fermer();
      throw e;
    }
    return c;
  }

  /** Clé du registre des compteurs ouverts : le chemin réel du répertoire. */
  static clefRepertoire(repertoire) {
    try {
      return fs.realpathSync(repertoire);
    } catch {
      return path.resolve(repertoire);
    }
  }

  /** Répertoires (chemins réels) dont un compteur est ouvert dans ce processus. */
  static ouverts() {
    return [...OUVERTS];
  }

  #repertoire;
  #pid;
  #vivant;
  #courant = null;
  #ouvert = false;
  #clef = null;

  constructor(repertoire, pid, vivant) {
    this.#repertoire = repertoire;
    this.#pid = pid;
    this.#vivant = vivant;
  }

  get repertoire() {
    return this.#repertoire;
  }

  /** Dernier numéro émis (ou `debut − 1` pour un compteur neuf). */
  get courant() {
    return this.#courant;
  }

  get ouvert() {
    return this.#ouvert;
  }

  #cheminVerrou() {
    return path.join(this.#repertoire, FICHIER_VERROU);
  }

  #verrouiller() {
    const verrou = this.#cheminVerrou();
    for (let essai = 0; essai < 2; essai++) {
      try {
        const fd = fs.openSync(verrou, "wx", 0o600);
        fs.writeSync(fd, `${this.#pid}\n`);
        fs.fsyncSync(fd);
        fs.closeSync(fd);
        this.#ouvert = true;
        return;
      } catch (e) {
        if (e.code !== "EEXIST") throw e;
        const detenteur = Number.parseInt(fs.readFileSync(verrou, "utf8"), 10);
        if (Number.isInteger(detenteur) && detenteur !== this.#pid && this.#vivant(detenteur)) {
          throw new ErreurCompteur(`compteur ${this.#repertoire} : verrou tenu par le processus ${detenteur} (AN-26 : un seul émetteur par clé)`);
        }
        // Verrou périmé (processus disparu) : repris.
        fs.unlinkSync(verrou);
      }
    }
    throw new ErreurCompteur(`compteur ${this.#repertoire} : verrou impossible à prendre`);
  }

  #relire(debut) {
    const chemin = path.join(this.#repertoire, FICHIER_SERIE);
    let texte;
    try {
      texte = fs.readFileSync(chemin, "utf8");
    } catch (e) {
      if (e.code !== "ENOENT") throw e;
      this.#courant = debut - 1n;
      return;
    }
    if (!/^[0-9]+\n?$/.test(texte)) throw new ErreurCompteur(`compteur ${chemin} : contenu illisible`);
    this.#courant = BigInt(texte.trim());
  }

  /**
   * Réserve et rend le numéro suivant, durable avant le retour : écriture
   * d'un fichier temporaire, `fsync`, renommage atomique, `fsync` du
   * répertoire.
   * @returns {bigint}
   */
  suivant() {
    if (!this.#ouvert) throw new ErreurCompteur("compteur fermé");
    const n = this.#courant + 1n;
    const tmp = path.join(this.#repertoire, FICHIER_TEMPORAIRE);
    const fd = fs.openSync(tmp, "w", 0o600);
    try {
      fs.writeSync(fd, `${n}\n`);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, path.join(this.#repertoire, FICHIER_SERIE));
    const fdRep = fs.openSync(this.#repertoire, "r");
    try {
      fs.fsyncSync(fdRep);
    } finally {
      fs.closeSync(fdRep);
    }
    this.#courant = n;
    return n;
  }

  /** Rend le verrou. */
  fermer() {
    if (!this.#ouvert) return;
    this.#ouvert = false;
    if (this.#clef !== null) OUVERTS.delete(this.#clef);
    try {
      const verrou = this.#cheminVerrou();
      const detenteur = Number.parseInt(fs.readFileSync(verrou, "utf8"), 10);
      if (detenteur === this.#pid) fs.unlinkSync(verrou);
    } catch {
      // Déjà retiré.
    }
  }
}

/** Compteur en mémoire (essais, démonstration) : même interface, rien d'écrit. */
export class CompteurMemoire {
  #courant;
  constructor(debut = 1n) {
    this.#courant = BigInt(debut) - 1n;
  }
  get courant() {
    return this.#courant;
  }
  get ouvert() {
    return true;
  }
  suivant() {
    this.#courant += 1n;
    return this.#courant;
  }
  fermer() {}
}
