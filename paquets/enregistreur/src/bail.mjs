// Bail et jeton de clôture (CT-2 §13). Un enregistreur n'écrit un journal
// que s'il détient le bail ; l'époque obtenue à l'acquisition, strictement
// croissante, est le jeton de clôture inscrit dans l'en-tête de chaque
// segment et dans le nom des fichiers d'intention, d'attente et des
// approbations (EX-13.1, EX-13.4). Les magasins `postgresql` et `etcd`, et la
// bascule entre hôtes, relèvent du lot de haute disponibilité : ce module
// fixe l'interface et fournit le magasin `file` d'un seul hôte.

import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
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

/** Code de sortie de `flock(1)` quand le verrou est tenu ailleurs (`--conflict-exit-code`). */
const CONFLIT = 75;

/**
 * Magasin `file` (13.2) : un seul hôte. Acquisition par `flock(LOCK_EX |
 * LOCK_NB)` sur `lease.store.path`, verrou tenu « tant que le descripteur est
 * ouvert », libéré par le noyau à la mort du processus ; en cas de succès,
 * lecture de `path.epoch`, écriture de `epoch + 1`, fdatasync (table de 13.2),
 * sous ce verrou.
 *
 * Node.js n'offre pas `flock(2)` sans module natif : le verrou est pris et
 * tenu par un processus auxiliaire, `flock(1)` d'util-linux (même appel
 * système), lancé par le démon avec un tube sur son entrée standard. Le
 * verrou est sur la description de fichier ouverte par l'auxiliaire ; celui-ci
 * vit tant que le tube est ouvert, c'est-à-dire tant que le démon vit : à la
 * mort du démon (même par SIGKILL), le noyau ferme le tube, l'auxiliaire lit
 * la fin de fichier, se termine, et le noyau libère le verrou. Un démon figé
 * garde le tube ouvert, donc le verrou (EX-13.10, dernier alinéa). Un
 * auxiliaire qui meurt seul (tué) libère le verrou : le bail n'est plus tenu
 * pour valide (`valide()` faux), l'écrivain cesse d'écrire (EX-13.6). Le
 * fichier verrou n'est jamais supprimé (le supprimer pendant qu'un autre
 * processus le tient ouvert donnerait deux verrous sur deux fichiers). Le
 * contenu du fichier verrou n'est pas lu : aucun PID n'entre dans la décision.
 * Lecture consignée dans le LISEZMOI.
 */
export class MagasinBailFichier extends MagasinBail {
  /**
   * @param {string} chemin `lease.store.path`
   * @param {{programme?: string}} [o] chemin de `flock(1)` (défaut : `flock` du PATH)
   */
  constructor(chemin, o = {}) {
    super();
    this.chemin = chemin;
    this.programme = o.programme ?? "flock";
    this.epoque = 0;
    this.detenu = false;
    this.auxiliaire = null;
  }

  get type() {
    return "file";
  }

  /**
   * Lance `flock --exclusive --nonblock` sur le fichier verrou ; rend
   * l'auxiliaire qui le tient, ou lève `bail_non_detenu` (tenu ailleurs).
   */
  async _verrouiller() {
    const p = spawn(
      this.programme,
      ["--exclusive", "--nonblock", "--conflict-exit-code", String(CONFLIT), this.chemin, "-c", "echo verrou_pris; exec cat >/dev/null"],
      // `-c` passe la commande à l'interpréteur de `SHELL` : celui du système.
      { stdio: ["pipe", "pipe", "ignore"], env: { ...process.env, SHELL: "/bin/sh" } },
    );
    const issue = await new Promise((resoudre) => {
      let sortie = "";
      p.stdout.on("data", (d) => {
        sortie += d;
        if (sortie.includes("verrou_pris\n")) resoudre("pris");
      });
      p.once("exit", (code) => resoudre(code === CONFLIT ? "conflit" : `sortie ${code}`));
      p.once("error", (e) => resoudre(`erreur ${e.code ?? e.message}`));
    });
    if (issue === "pris") return p;
    p.stdin?.destroy();
    if (issue === "conflit") throw new ErreurEnregistreur("bail_non_detenu", "noortrace: bail non detenu", { donnees: { event: "lease_standby" } });
    throw new ErreurEnregistreur("bail", `noortrace: verrou du bail file impossible (flock(1) : ${issue})`);
  }

  async acquerir() {
    if (this.detenu) throw new ErreurEnregistreur("bail", "noortrace: bail déjà détenu par cette instance");
    fs.mkdirSync(path.dirname(this.chemin), { recursive: true, mode: 0o700 });
    // Fichier verrou créé s'il manque (jamais tronqué ni supprimé).
    fs.closeSync(fs.openSync(this.chemin, fs.constants.O_WRONLY | fs.constants.O_CREAT, 0o600));
    const aux = await this._verrouiller();
    try {
      // Époque incrémentée sous le verrou (table de 13.2).
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
    } catch (e) {
      aux.stdin.destroy();
      throw e;
    }
    this.auxiliaire = aux;
    this.detenu = true;
    aux.once("exit", () => {
      // Auxiliaire terminé hors de `liberer` : le verrou est rendu par le noyau.
      if (this.auxiliaire === aux) {
        this.auxiliaire = null;
        this.detenu = false;
      }
    });
    // Ni l'auxiliaire ni son tube ne retiennent le démon à sa sortie.
    aux.unref();
    aux.stdin.unref?.();
    aux.stdout.unref?.();
    return this.epoque;
  }

  valide() {
    return this.detenu;
  }

  async liberer() {
    const aux = this.auxiliaire;
    this.detenu = false;
    this.auxiliaire = null;
    if (!aux || aux.exitCode !== null || aux.signalCode !== null) return;
    // L'attente de la sortie de l'auxiliaire retient le processus jusqu'à elle.
    aux.ref();
    await new Promise((resoudre) => {
      const t = setTimeout(() => {
        aux.kill("SIGKILL");
      }, 2000);
      t.unref?.();
      aux.once("exit", () => {
        clearTimeout(t);
        resoudre();
      });
      aux.stdin.end();
    });
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
