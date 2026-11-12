// Persistance et reprise du service (CT-3 EX-7.22 à EX-7.24).
//
// Disposition dans le répertoire d'état :
//   etat/journal.ndjson     une ligne par entrée traitée : l'enregistrement
//                           { n, meta?, versions?, tickets?, fenetres?, annuaire?, defis? }
//                           (documents entiers, état absolu, jamais un delta), chiffré ;
//   etat/instantane.chiffre l'état complet { n, meta, versions, tickets, fenetres,
//                           annuaire?, defis? } au dernier compactage, chiffré ;
//   etat/verrou             fichier de verrou (pid), un seul service par répertoire.
//
// Chaque ligne est écrite puis synchronisée (fdatasync) avant que l'effet de
// l'entrée soit rendu visible (EX-7.22). Les arguments en clair des tickets
// actifs et les valeurs des portées de fenêtre sont chiffrés au repos
// (EX-7.24) : tout enregistrement l'est, en AES-256-GCM, clé de 32 octets de
// la configuration, nonce aléatoire de 12 octets par enregistrement, données
// associées « noortrace/approbation/etat/v0 » ‖ LF ‖ nature ‖ LF ‖ n (EX-7.30).
// L'annuaire des approbateurs (`annuaire`, document `annuaire-approbateurs-v0`)
// et ses défis d'inscription non expirés (`defis`) sont des membres des mêmes
// enregistrements, écrits en entier à chaque changement (EX-13.38) ; le
// dernier lu fait foi. `annuaire` n'est écrit qu'à la première opération
// acceptée (EX-13.38, point 1).
//
// Reprise : l'instantané, puis les lignes du journal dont `n` le suit ; une
// dernière ligne incomplète ou indéchiffrable (arrêt brutal pendant
// l'écriture) est tronquée ; toute autre ligne illisible arrête le démarrage.
// Un compactage écrit l'instantané (fichier temporaire, fsync, renommage,
// fsync du répertoire) puis vide le journal ; interrompu, il laisse des lignes
// déjà reflétées par l'instantané, sautées à la relecture (n ≤ n de
// l'instantané). Les enregistrements portent des documents entiers : les
// rejouer deux fois donne le même état.
//
// Arguments en clair (EX-7.24) : les membres `request.arguments`,
// `request.retained_event`, `request.arguments_piece` et
// `opening.scope.values` d'un ticket, et `scope.values` d'une fenêtre, ne
// sont jamais écrits dans le journal ni dans l'instantané : ils vont, chiffrés,
// dans un fichier par ticket ou par fenêtre, `etat/arguments/t-<ticket>` ou
// `f-<ticket>` (écriture atomique : fichier temporaire, fsync, renommage,
// fsync du répertoire), écrit AVANT la ligne qui rend l'état durable, et
// supprimé (puis fsync du répertoire) APRÈS la ligne qui porte le passage en
// `consomme`, `clos` ou `abandonne`, ou la fermeture de la fenêtre. L'effacement
// est ainsi effectif au passage même (« effacés au passage en consomme, clos ou
// abandonne », EX-7.24), sans copie dans les lignes antérieures. À la reprise,
// le document `ticket-v0` est recomposé de sa ligne et de son fichier ; un
// fichier d'un ticket terminé ou inconnu (arrêt entre la ligne et la
// suppression) est supprimé.
//
// Échec d'écriture (EX-7.22) : un numéro d'enregistrement n'est jamais
// réattribué ; après un échec de `write` ou de `fdatasync`, le magasin refuse
// tout ajout (`enPanne`) jusqu'à `reprendre(état complet)`, qui écrit un
// instantané de tout l'état en mémoire sous le dernier numéro attribué, recopie
// les fichiers d'arguments et vide le journal par un nouveau descripteur :
// aucune ligne n'est ajoutée derrière une ligne dont la durabilité n'est pas
// établie, et aucun effet n'est rendu visible avant que tout l'état soit durable.

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

const ETATS_TERMINAUX = ["consomme", "clos", "abandonne"];

/** Erreur d'un magasin en panne : aucun ajout avant `reprendre`. */
function erreurPanne() {
  return Object.assign(new Error("magasin d'état en panne : reprise par l'état complet requise (EX-7.22)"), { code: "EPANNE" });
}

/**
 * Sépare un ticket de ses arguments en clair (EX-7.24).
 * @returns {{doc: object, secret: string|null}} `secret` : JSON des membres retirés, ou null s'ils sont tous nuls
 */
function separerTicket(t) {
  const { intent, ...r } = t.request ?? {};
  const s = {
    arguments: r.arguments ?? null,
    retained_event: r.retained_event ?? null,
    arguments_piece: r.arguments_piece ?? null,
    scope_values: t.opening?.scope?.values ?? null,
    // intention de la requête evaluer, gardée et effacée avec les arguments (EX-7.24, révision 0.6)
    intent: intent ?? null,
  };
  if (s.arguments === null && s.retained_event === null && s.arguments_piece === null && s.scope_values === null) {
    return { doc: t.request && "intent" in t.request ? { ...t, request: r } : t, secret: null };
  }
  const doc = { ...t, request: { ...r, arguments: null, retained_event: null, arguments_piece: null } };
  if (t.opening) doc.opening = { ...t.opening, scope: { ...t.opening.scope, values: null } };
  return { doc, secret: JSON.stringify(s) };
}

/** Sépare une fenêtre de la valeur de sa portée (EX-7.24). */
function separerFenetre(w) {
  const v = w.scope?.values ?? null;
  if (v === null) return { doc: w, secret: null };
  return { doc: { ...w, scope: { ...w.scope, values: null } }, secret: JSON.stringify(v) };
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
    /** Vrai après un échec d'écriture : aucun ajout avant `reprendre` (EX-7.22). */
    this.enPanne = false;
    /** Arguments en clair persistés à part (EX-7.24) : nom de fichier → JSON. */
    this.secrets = new Map();
  }

  get dirArguments() {
    return path.join(this.dir, "arguments");
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
   * @returns {Promise<{meta: object|null, versions: object[], tickets: object[], fenetres: object[],
   *   annuaire: object|null, defis: object[]|null, tronque: boolean}>}
   */
  async ouvrir() {
    await fsp.mkdir(this.dir, { recursive: true, mode: 0o700 });
    await this.#verrouiller();
    const etat = { meta: null, versions: [], tickets: new Map(), fenetres: [], annuaire: null, defis: null };
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
      if (s.annuaire !== undefined) etat.annuaire = s.annuaire;
      if (s.defis !== undefined) etat.defis = s.defis;
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
          if (enr.annuaire) etat.annuaire = enr.annuaire;
          if (enr.defis) etat.defis = enr.defis;
          this.n = enr.n;
        }
        this.lignes++;
        debut = complete ? fin + 1 : octets.length;
      }
    }
    // Arguments en clair (EX-7.24) : recomposition des documents, purge des fichiers
    // de tickets terminés ou inconnus et de fenêtres fermées ; un état écrit avant
    // cette disposition (arguments dans les lignes) est recopié aussitôt.
    await fsp.mkdir(this.dirArguments, { recursive: true, mode: 0o700 });
    const fichiers = new Map();
    for (const nom of await fsp.readdir(this.dirArguments)) {
      const chemin = path.join(this.dirArguments, nom);
      if (!/^[tf]-apr-[0-9a-z-]+$/.test(nom)) {
        await fsp.rm(chemin, { force: true });
        continue;
      }
      const brut = (await fsp.readFile(chemin, "utf8")).trim();
      const o = dechiffrer(this.cle, "arguments", 0, brut.slice(brut.indexOf(" ") + 1));
      if (o.nom !== nom) throw new Error(`fichier d'arguments ${nom} : nom différent`);
      fichiers.set(nom, o.secret);
    }
    let migrer = false;
    const tickets = [...etat.tickets.values()];
    for (const t of tickets) {
      const nom = `t-${t.ticket}`;
      const terminal = ETATS_TERMINAUX.includes(t.state);
      if (separerTicket(t).secret !== null) migrer = true;
      if (terminal || !fichiers.has(nom)) continue;
      const x = JSON.parse(fichiers.get(nom));
      t.request.arguments = x.arguments;
      t.request.retained_event = x.retained_event;
      t.request.arguments_piece = x.arguments_piece;
      t.request.intent = x.intent ?? null;
      if (t.opening) t.opening.scope.values = x.scope_values;
      this.secrets.set(nom, fichiers.get(nom));
    }
    for (const w of etat.fenetres ?? []) {
      const nom = `f-${w.ticket}`;
      if (separerFenetre(w).secret !== null) migrer = true;
      if (!fichiers.has(nom)) continue;
      w.scope.values = JSON.parse(fichiers.get(nom));
      this.secrets.set(nom, fichiers.get(nom));
    }
    let purge = false;
    for (const nom of fichiers.keys()) {
      if (!this.secrets.has(nom)) {
        await fsp.rm(path.join(this.dirArguments, nom), { force: true });
        purge = true;
      }
    }
    if (purge) await this.#synchroniserRepertoire(this.dirArguments);
    this.fd = await fsp.open(this.cheminJournal, "a", 0o600);
    const docs = { meta: etat.meta, versions: etat.versions, tickets, fenetres: etat.fenetres };
    if (etat.annuaire !== null) docs.annuaire = etat.annuaire;
    if (etat.defis !== null) docs.defis = etat.defis;
    if (migrer) await this.reprendre(docs);
    return { ...docs, annuaire: etat.annuaire, defis: etat.defis, tronque };
  }

  async #synchroniserRepertoire(dir) {
    const dfd = await fsp.open(dir, "r");
    try {
      await dfd.sync();
    } finally {
      await dfd.close();
    }
  }

  /** Écrit le fichier d'arguments `nom` (atomique, EX-7.24). */
  async #ecrireSecret(nom, secret) {
    const chemin = path.join(this.dirArguments, nom);
    const tmp = chemin + ".tmp";
    const fd = await fsp.open(tmp, "w", 0o600);
    try {
      await fd.writeFile(`0 ${chiffrer(this.cle, "arguments", 0, { nom, secret })}\n`);
      await fd.sync();
    } finally {
      await fd.close();
    }
    await fsp.rename(tmp, chemin);
  }

  /**
   * Met les fichiers d'arguments dans l'état `cible` : écritures (ajouts et
   * changements) puis suppressions, chacune suivie du fsync du répertoire.
   * @param {Map<string, string>} cible
   * @param {{ecrire: boolean, supprimer: boolean}} o
   */
  async #appliquerSecrets(cible, o) {
    let change = false;
    if (o.ecrire) {
      for (const [nom, secret] of cible) {
        if (this.secrets.get(nom) === secret) continue;
        await this.#ecrireSecret(nom, secret);
        this.secrets.set(nom, secret);
        change = true;
      }
    }
    if (change) await this.#synchroniserRepertoire(this.dirArguments);
    change = false;
    if (o.supprimer) {
      for (const nom of [...this.secrets.keys()]) {
        if (cible.has(nom)) continue;
        await fsp.rm(path.join(this.dirArguments, nom), { force: true });
        this.secrets.delete(nom);
        change = true;
      }
    }
    if (change) await this.#synchroniserRepertoire(this.dirArguments);
  }

  /**
   * Sépare un enregistrement de ses arguments en clair (EX-7.24) ; rend
   * l'enregistrement sans arguments et l'état des fichiers d'arguments après lui.
   */
  #separer(enr, complet) {
    const cible = complet ? new Map() : new Map(this.secrets);
    const clair = { ...enr };
    if (enr.tickets) {
      clair.tickets = enr.tickets.map((t) => {
        const { doc, secret } = separerTicket(t);
        const nom = `t-${t.ticket}`;
        if (secret === null || ETATS_TERMINAUX.includes(t.state)) cible.delete(nom);
        else cible.set(nom, secret);
        return doc;
      });
    }
    if (enr.fenetres) {
      for (const nom of [...cible.keys()]) if (nom.startsWith("f-")) cible.delete(nom);
      clair.fenetres = enr.fenetres.map((w) => {
        const { doc, secret } = separerFenetre(w);
        if (secret !== null) cible.set(`f-${w.ticket}`, secret);
        return doc;
      });
    }
    return { clair, cible };
  }

  /**
   * Ajoute un enregistrement et le synchronise (EX-7.22).
   * @param {{meta?: object, versions?: object[], tickets?: object[], fenetres?: object[], annuaire?: object, defis?: object[]}} enr
   */
  async ajouter(enr) {
    if (this.enPanne) throw erreurPanne();
    // Le numéro est attribué avant l'écriture et jamais réattribué, même après un échec.
    const n = ++this.n;
    try {
      const { clair, cible } = this.#separer(enr, false);
      await this.#appliquerSecrets(cible, { ecrire: true, supprimer: false });
      await this.fd.write(`${n} ${chiffrer(this.cle, "ligne", n, clair)}\n`);
      await this.fd.datasync();
      this.lignes++;
      await this.#appliquerSecrets(cible, { ecrire: false, supprimer: true });
    } catch (e) {
      this.enPanne = true;
      throw e;
    }
  }

  /**
   * Reprise après un échec d'écriture (EX-7.22) : instantané de l'état complet
   * sous le dernier numéro attribué, fichiers d'arguments recopiés, journal vidé
   * par un nouveau descripteur. Le magasin accepte de nouveau les ajouts.
   * @param {{meta: object, versions: object[], tickets: object[], fenetres: object[]}} etat
   */
  async reprendre(etat) {
    this.enPanne = true;
    await this.fd?.close().catch(() => {});
    this.fd = null;
    const { clair, cible } = this.#separer(etat, true);
    // Ordre : arguments de l'état complet, instantané, journal vidé, puis seulement
    // suppression des autres fichiers d'arguments ; un arrêt entre deux pas ne perd
    // les arguments d'aucun ticket actif.
    this.secrets = new Map();
    await this.#appliquerSecrets(cible, { ecrire: true, supprimer: false });
    await this.#ecrireInstantane(clair);
    const vide = await fsp.open(this.cheminJournal, "w", 0o600);
    try {
      await vide.sync();
    } finally {
      await vide.close();
    }
    this.fd = await fsp.open(this.cheminJournal, "a", 0o600);
    let supprime = false;
    for (const nom of await fsp.readdir(this.dirArguments)) {
      if (cible.has(nom)) continue;
      await fsp.rm(path.join(this.dirArguments, nom), { force: true });
      supprime = true;
    }
    if (supprime) await this.#synchroniserRepertoire(this.dirArguments);
    this.lignes = 0;
    this.enPanne = false;
  }

  async #ecrireInstantane(clair) {
    const tmp = this.cheminInstantane + ".tmp";
    const fd = await fsp.open(tmp, "w", 0o600);
    try {
      await fd.writeFile(`${this.n} ${chiffrer(this.cle, "instantane", this.n, clair)}\n`);
      await fd.sync();
    } finally {
      await fd.close();
    }
    await fsp.rename(tmp, this.cheminInstantane);
    await this.#synchroniserRepertoire(this.dir);
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
    if (this.enPanne) throw erreurPanne();
    try {
      await this.#ecrireInstantane(this.#separer(etat, true).clair);
      await this.fd.truncate(0);
      await this.fd.sync();
    } catch (e) {
      this.enPanne = true;
      throw e;
    }
    this.lignes = 0;
  }

  async fermer() {
    await this.fd?.close();
    this.fd = null;
    if (this.verrou) await fsp.rm(this.verrou, { force: true });
    this.verrou = null;
  }
}
