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
/**
 * Revue de sécurité de l'étape 8 (AN-26) : avec `epoque`, le compteur ouvert ne descend
 * jamais sous `secondes(horloge) × 2^20` : une restauration du fichier
 * `serie` depuis une sauvegarde, ou sa perte, ne rejoue aucun numéro émis
 * avant tant que l'horloge de l'hôte ne recule pas d'une seconde au-delà du
 * dernier démarrage. 2^20 numéros par seconde : au-delà de toute cadence.
 */
export const EPOQUE_PAS = 1n << 20n;
/**
 * Revue de sécurité de l'étape 8 (AN-26) : chaque numéro est réservé par la création
 * exclusive d'un fichier `serie-<n>` (le système de fichiers départage deux
 * processus de conteneurs différents, que le verrou par pid ne voit pas) ; les
 * réservations plus anciennes que `RESERVATIONS_GARDEES` sont retirées.
 */
export const RESERVATIONS_GARDEES = 64;
const MOTIF_RESERVATION = /^serie-([0-9]{1,30})$/;

/** Vrai si un processus de ce pid existe encore (EPERM compte comme vivant). */
function processusVivant(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === "EPERM";
  }
}

/** Répertoires dont un compteur est ouvert dans ce processus (verrou par chemin, dans le processus aussi : AN-26). */
const OUVERTS = new Set();

export class Compteur {
  /**
   * Ouvre (ou crée) le compteur d'un répertoire et prend son verrou. Un second
   * compteur du même processus sur le même répertoire est refusé (AN-26 : un
   * seul émetteur par clé ; le fichier de verrou porte le pid, qui ne distingue
   * pas deux compteurs d'un même processus).
   * @param {{repertoire: string, debut?: bigint|number, pid?: number, vivant?: (pid: number) => boolean,
   *   epoque?: boolean, horloge?: {murale: () => number}, reservations?: boolean}} o
   *   `debut` : premier numéro émis par un compteur neuf (1 par défaut) ;
   *   `vivant` : test de vie d'un processus, injectable pour les essais ;
   *   `epoque` (CT-5 AN-26) : plancher `secondes(horloge) × 2^20` à l'ouverture ;
   *   `reservations` (vrai par défaut) : réservation exclusive de chaque numéro par un fichier `serie-<n>`.
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
    c.#reservations = o.reservations !== false;
    c.#verrouiller();
    OUVERTS.add(clef);
    try {
      c.#relire(debut);
      if (o.epoque === true) {
        const horloge = o.horloge ?? { murale: () => Date.now() };
        const secondes = BigInt(Math.max(0, Math.floor(horloge.murale() / 1000)));
        const plancher = secondes * EPOQUE_PAS - 1n;
        if (c.#courant < plancher) c.#courant = plancher;
      }
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
  #reservations = true;

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
    let n = this.#courant + 1n;
    if (this.#reservations) {
      // Revue de sécurité de l'étape 8 (CT-5 AN-26) : un numéro déjà réservé par un autre processus (fichier `serie-<n>` présent) est sauté.
      for (let essais = 0; ; essais++) {
        try {
          fs.closeSync(fs.openSync(path.join(this.#repertoire, `serie-${n}`), "wx", 0o600));
          break;
        } catch (e) {
          if (e.code !== "EEXIST") throw e;
          if (essais >= 100000) throw new ErreurCompteur(`compteur ${this.#repertoire} : aucun numéro libre après ${essais} réservations`);
          n += 1n;
        }
      }
    }
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
    if (this.#reservations) this.#elaguerReservations(n);
    return n;
  }

  /** Retire les fichiers de réservation plus anciens que les `RESERVATIONS_GARDEES` derniers numéros. */
  #elaguerReservations(n) {
    const seuil = n - BigInt(RESERVATIONS_GARDEES);
    let noms;
    try {
      noms = fs.readdirSync(this.#repertoire);
    } catch {
      return;
    }
    for (const nom of noms) {
      const m = MOTIF_RESERVATION.exec(nom);
      if (!m || BigInt(m[1]) >= seuil) continue;
      try {
        fs.unlinkSync(path.join(this.#repertoire, nom));
      } catch {
        // Déjà retiré par un autre processus.
      }
    }
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
