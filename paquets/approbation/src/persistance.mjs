// Persistance et reprise du service (CT-3 EX-7.22 à EX-7.24).
//
// Disposition dans le répertoire d'état :
//   etat/journal.ndjson     une ligne par entrée traitée : l'enregistrement
//                           { n, meta?, versions?, tickets?, fenetres? } (documents
//                           entiers, état absolu, jamais un delta), chiffré ;
//   etat/instantane.chiffre l'état complet { n, meta, versions, tickets, fenetres } au
//                           dernier compactage, chiffré ;
//   etat/verrou             fichier de verrou (pid), un seul service par répertoire.
//
// Chaque ligne est écrite puis synchronisée (fdatasync) avant que l'effet de
// l'entrée soit rendu visible (EX-7.22). Les arguments en clair des tickets
// actifs et les valeurs des portées de fenêtre sont chiffrés au repos
// (EX-7.24) : tout enregistrement l'est, en AES-256-GCM, clé de 32 octets de
// la configuration, nonce aléatoire de 12 octets par enregistrement, données
// associées « noortrace/approbation/etat/v0 » ‖ nature ‖ n.
//
// Reprise : l'instantané, puis les lignes du journal dont `n` le suit ; une
// dernière ligne incomplète ou indéchiffrable (arrêt brutal pendant
// l'écriture) est tronquée ; toute autre ligne illisible arrête le démarrage.
// Un compactage écrit l'instantané (fichier temporaire, fsync, renommage,
// fsync du répertoire) puis vide le journal ; interrompu, il laisse des lignes
// déjà reflétées par l'instantané, sautées à la relecture (n ≤ n de
// l'instantané). Les enregistrements portent des documents entiers : les
// rejouer deux fois donne le même état.

import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const ETIQUETTE = "noortrace/approbation/etat/v0";

function aad(nature, n) {
  return Buffer.from(`${ETIQUETTE}\n${nature}\n${n}`, "utf8");
}

/**
 * Chiffre un objet JSON.
 * @param {Uint8Array} cle 32 octets
 * @param {string} nature `ligne` ou `instantane`
 * @param {number} n numéro d'enregistrement
 * @param {object} objet
 * @returns {string} base64 de nonce ‖ chiffré ‖ étiquette
 */
export function chiffrer(cle, nature, n, objet) {
  const nonce = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", cle, nonce);
  c.setAAD(aad(nature, n));
  const corps = Buffer.concat([c.update(Buffer.from(JSON.stringify(objet), "utf8")), c.final()]);
  return Buffer.concat([nonce, corps, c.getAuthTag()]).toString("base64");
}

/**
 * Déchiffre ; lève une erreur si l'étiquette ne vérifie pas.
 * @param {Uint8Array} cle
 * @param {string} nature
 * @param {number} n
 * @param {string} texte
 */
export function dechiffrer(cle, nature, n, texte) {
  const o = Buffer.from(texte, "base64");
  if (o.length < 28) throw new Error("enregistrement trop court");
  const d = createDecipheriv("aes-256-gcm", cle, o.subarray(0, 12));
  d.setAAD(aad(nature, n));
  d.setAuthTag(o.subarray(o.length - 16));
  const clair = Buffer.concat([d.update(o.subarray(12, o.length - 16)), d.final()]);
  return JSON.parse(clair.toString("utf8"));
}

function processusVivant(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === "EPERM";
  }
}

/** Magasin d'état chiffré, en ajout seul avec compactage. */
export class MagasinEtat {
  /**
   * @param {{repertoire: string, cle: Uint8Array, compacterApres?: number}} p
   */
  constructor(p) {
    if (!(p.cle instanceof Uint8Array) || p.cle.length !== 32) throw new TypeError("clé de stockage de 32 octets attendue");
    this.dir = path.join(p.repertoire, "etat");
    this.cle = p.cle;
    this.compacterApres = p.compacterApres ?? 2000;
    this.n = 0;
    this.lignes = 0;
    this.fd = null;
    this.verrou = null;
  }

  get cheminJournal() {
    return path.join(this.dir, "journal.ndjson");
  }

  get cheminInstantane() {
    return path.join(this.dir, "instantane.chiffre");
  }

  /** Prend le verrou du répertoire (un seul service à la fois). */
  async #verrouiller() {
    const chemin = path.join(this.dir, "verrou");
    for (let essai = 0; essai < 2; essai++) {
      try {
        const fd = await fsp.open(chemin, "wx", 0o600);
        await fd.writeFile(String(process.pid));
        await fd.sync();
        await fd.close();
        this.verrou = chemin;
        return;
      } catch (e) {
        if (e.code !== "EEXIST") throw e;
        const pid = Number((await fsp.readFile(chemin, "utf8").catch(() => "")).trim());
        if (Number.isInteger(pid) && pid > 0 && pid !== process.pid && processusVivant(pid)) {
          throw new Error(`répertoire d'état déjà tenu par le processus ${pid}`);
        }
        // verrou d'un processus arrêté brutalement : repris
        await fsp.rm(chemin, { force: true });
      }
    }
    throw new Error("verrou du répertoire d'état non obtenu");
  }

  /**
   * Ouvre le magasin et relit l'état (EX-7.23).
   * @returns {Promise<{meta: object|null, versions: object[], tickets: object[], fenetres: object[], tronque: boolean}>}
   */
  async ouvrir() {
    await fsp.mkdir(this.dir, { recursive: true, mode: 0o700 });
    await this.#verrouiller();
    const etat = { meta: null, versions: [], tickets: new Map(), fenetres: [] };
    let nInstantane = 0;
    if (fs.existsSync(this.cheminInstantane)) {
      const brut = (await fsp.readFile(this.cheminInstantane, "utf8")).trim();
      const sep = brut.indexOf(" ");
      nInstantane = Number(brut.slice(0, sep));
      const s = dechiffrer(this.cle, "instantane", nInstantane, brut.slice(sep + 1));
      etat.meta = s.meta;
      etat.versions = s.versions ?? [];
      for (const t of s.tickets) etat.tickets.set(t.ticket, t);
      etat.fenetres = s.fenetres;
    }
    this.n = nInstantane;
    let tronque = false;
    if (fs.existsSync(this.cheminJournal)) {
      const octets = await fsp.readFile(this.cheminJournal);
      let debut = 0;
      while (debut < octets.length) {
        const fin = octets.indexOf(0x0a, debut);
        const complete = fin >= 0;
        const ligne = octets.subarray(debut, complete ? fin : octets.length).toString("utf8");
        const derniere = !complete || fin + 1 >= octets.length;
        let enr = null;
        try {
          const sep = ligne.indexOf(" ");
          const n = Number(ligne.slice(0, sep));
          if (!complete) throw new Error("ligne incomplète");
          enr = { n, ...dechiffrer(this.cle, "ligne", n, ligne.slice(sep + 1)) };
        } catch (e) {
          if (derniere) {
            await fsp.truncate(this.cheminJournal, debut);
            tronque = true;
            break;
          }
          throw new Error(`journal d'état corrompu à l'octet ${debut} : ${e.message}`);
        }
        if (enr.n > this.n) {
          if (enr.n !== this.n + 1) throw new Error(`journal d'état : enregistrement ${enr.n} après ${this.n}`);
          if (enr.meta) etat.meta = enr.meta;
          if (enr.versions) etat.versions = enr.versions;
          for (const t of enr.tickets ?? []) etat.tickets.set(t.ticket, t);
          if (enr.fenetres) etat.fenetres = enr.fenetres;
          this.n = enr.n;
        }
        this.lignes++;
        debut = complete ? fin + 1 : octets.length;
      }
    }
    this.fd = await fsp.open(this.cheminJournal, "a", 0o600);
    return { meta: etat.meta, versions: etat.versions, tickets: [...etat.tickets.values()], fenetres: etat.fenetres, tronque };
  }

  /**
   * Ajoute un enregistrement et le synchronise (EX-7.22).
   * @param {{meta?: object, versions?: object[], tickets?: object[], fenetres?: object[]}} enr
   */
  async ajouter(enr) {
    const n = this.n + 1;
    const ligne = `${n} ${chiffrer(this.cle, "ligne", n, enr)}\n`;
    await this.fd.write(ligne);
    await this.fd.datasync();
    this.n = n;
    this.lignes++;
  }

  /** Faut-il compacter ? */
  get aCompacter() {
    return this.lignes >= this.compacterApres;
  }

  /**
   * Écrit l'instantané de l'état complet puis vide le journal.
   * @param {{meta: object, versions: object[], tickets: object[], fenetres: object[]}} etat
   */
  async compacter(etat) {
    const tmp = this.cheminInstantane + ".tmp";
    const fd = await fsp.open(tmp, "w", 0o600);
    await fd.writeFile(`${this.n} ${chiffrer(this.cle, "instantane", this.n, etat)}\n`);
    await fd.sync();
    await fd.close();
    await fsp.rename(tmp, this.cheminInstantane);
    const dfd = await fsp.open(this.dir, "r");
    await dfd.sync();
    await dfd.close();
    await this.fd.truncate(0);
    await this.fd.sync();
    this.lignes = 0;
  }

  async fermer() {
    await this.fd?.close();
    this.fd = null;
    if (this.verrou) await fsp.rm(this.verrou, { force: true });
    this.verrou = null;
  }
}
