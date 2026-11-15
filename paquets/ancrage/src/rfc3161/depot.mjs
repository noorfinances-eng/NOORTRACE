// Dépôt des pièces d'horodatage (CT-5 EX-5.14, EX-5.15, AN-14, AN-15) :
// `<racine>/<org_id>/<journal_id>/ancres/periode-<period_start>/` avec les
// noms exacts, création exclusive (jamais de réécriture, CT-4 EX-9.3), `fsync`
// du fichier et de son répertoire, `acquisitions.ndjson` en ajout seul (une
// ligne JCS intégral par tentative, EX-5.13, jamais le secret). Rien n'est
// jamais supprimé.

import fs from "node:fs";
import path from "node:path";
import { jcs, analyserJson, ErreurJson } from "@noortrace/noyau";

/** Motif d'un identifiant de prestataire ou de tentative admis dans un nom de fichier (ASCII, triable). */
const IDENTIFIANT = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

/** Erreur d'écriture (EX-5.10 étape 9 : `ecriture`, transitoire). */
export class ErreurDepot extends Error {
  constructor(message, cause) {
    super(message);
    this.name = "ErreurDepot";
    this.code = "ecriture";
    this.cause = cause;
  }
}

/** `fsync` d'un répertoire. */
function synchroniserRepertoire(rep) {
  const fd = fs.openSync(rep, "r");
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/** Fenêtre relue pour trouver la dernière fin de ligne d'un fichier NDJSON (1 Mio : borne d'une ligne). */
const FENETRE_FRAGMENT = 1048576;
let compteurProvisoires = 0;

/**
 * Tronque une fin de fichier sans saut de ligne à la dernière ligne complète
 * (CT-5 EX-5.14) ; rend le nombre d'octets retirés. `fd` est ouvert en
 * lecture et écriture.
 */
export function tronquerFragment(fd) {
  const taille = fs.fstatSync(fd).size;
  if (taille === 0) return 0;
  const dernier = Buffer.alloc(1);
  fs.readSync(fd, dernier, 0, 1, taille - 1);
  if (dernier[0] === 0x0a) return 0;
  const fenetre = Math.min(taille, FENETRE_FRAGMENT + 1);
  const queue = Buffer.alloc(fenetre);
  fs.readSync(fd, queue, 0, fenetre, taille - fenetre);
  const i = queue.lastIndexOf(0x0a);
  const fin = i === -1 ? taille - fenetre : taille - fenetre + i + 1;
  fs.ftruncateSync(fd, fin);
  fs.fsyncSync(fd);
  return taille - fin;
}

/**
 * Écrit `octets` en entier dans un fichier provisoire du répertoire de
 * `chemin`, le synchronise, puis pose `chemin` par un lien exclusif (jamais
 * d'écrasement) ; le provisoire est retiré dans tous les cas. `erreur(message,
 * cause)` construit l'erreur levée ; `quoi` nomme la pièce dans les messages.
 * Rend vrai si le nom a été posé, faux s'il existait déjà (CT-5 EX-5.14,
 * CT-5 EX-6.5, CT-4 EX-9.3 : règle d'écriture unique des dépôts). `mode` :
 * droits du fichier posé (0600 par défaut ; la capture du registre passe
 * 0644, ses fichiers étant remis par un autre compte que celui qui capture).
 */
export function ecrireEntierPuisLier(chemin, octets, erreur = (message, cause) => Object.assign(new Error(message), { cause }), quoi = path.basename(chemin), mode = 0o600) {
  const o = octets instanceof Uint8Array ? octets : Buffer.from(octets);
  compteurProvisoires += 1;
  const provisoire = path.join(path.dirname(chemin), `.${path.basename(chemin)}.partiel-${process.pid}-${compteurProvisoires}`);
  let fd;
  try {
    fd = fs.openSync(provisoire, "wx", mode);
  } catch (err) {
    throw erreur(`ouverture impossible : ${err.message}`, err);
  }
  try {
    let ecrit = 0;
    while (ecrit < o.length) ecrit += fs.writeSync(fd, o, ecrit, o.length - ecrit);
    fs.fsyncSync(fd);
  } catch (err) {
    fs.closeSync(fd);
    fs.rmSync(provisoire, { force: true });
    throw erreur(`écriture impossible (${quoi}) : ${err.message}`, err);
  }
  fs.closeSync(fd);
  try {
    fs.linkSync(provisoire, chemin);
  } catch (err) {
    fs.rmSync(provisoire, { force: true });
    if (err.code === "EEXIST") return false;
    throw erreur(`écriture impossible (${quoi}) : ${err.message}`, err);
  }
  fs.rmSync(provisoire, { force: true });
  return true;
}

/**
 * Copie autonome d'une valeur JSON relue : chaque chaîne est recopiée, pour
 * qu'aucune ne soit une tranche du texte entier du fichier (le moteur garde
 * alors tout ce texte en mémoire tant que la tranche vit). Sans cette copie,
 * un résumé d'export ou l'index des nonces gardait `acquisitions.ndjson` en
 * entier par valeur retenue (épreuves de l'étape 5 : tas épuisé après
 * 2 799 exports à c_T = 60 s).
 * @template T
 * @param {T} v
 * @returns {T}
 */
export function copieAutonome(v) {
  if (typeof v === "string") return Buffer.from(v, "utf8").toString("utf8");
  if (Array.isArray(v)) return v.map(copieAutonome);
  if (v !== null && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [copieAutonome(k), copieAutonome(x)]));
  return v;
}

/** Nom d'une période : dix chiffres (EX-5.14). */
export function nomPeriode(periodStart) {
  if (!Number.isSafeInteger(periodStart) || periodStart < 0 || periodStart > 9999999999) throw new TypeError("period_start : entier de dix chiffres au plus attendu");
  return `periode-${String(periodStart).padStart(10, "0")}`;
}

/** Nom d'objet : `manifeste` ou `point-<checkpointHash sans 0x>`. */
export function nomObjet(objet, imprint) {
  if (objet === "manifeste") return "manifeste";
  if (objet === "point") {
    if (!/^0x[0-9a-f]{64}$/.test(imprint)) throw new TypeError("checkpointHash hex32 attendu");
    return `point-${imprint.slice(2)}`;
  }
  throw new TypeError("objet : manifeste ou point attendu");
}

/** Vérifie qu'un identifiant peut entrer dans un nom de fichier. */
export function controlerIdentifiant(id, quoi) {
  if (typeof id !== "string" || !IDENTIFIANT.test(id)) throw new TypeError(`${quoi} : identifiant ASCII attendu`);
  return id;
}

/** Choix du jeton promu d'EX-5.8 parmi des enregistrements `obtenue` (AN-13). */
export function choisirPromu(enregistrements) {
  const valables = enregistrements.filter((e) => e.outcome === "obtenue" && e.upper_bound);
  if (valables.length === 0) return null;
  const qualifies = valables.filter((e) => e.qualified !== null && e.qualified !== undefined);
  const base = qualifies.length > 0 ? qualifies : valables;
  let meilleur = base[0];
  for (const e of base.slice(1)) if (e.upper_bound < meilleur.upper_bound) meilleur = e;
  return meilleur;
}

/** Dépôt d'un journal. */
export class DepotAncres {
  /** Index en mémoire des nonces consignés (AN-6), construit à la première consultation puis tenu à jour. */
  #nonces = null;
  /** Périodes dont les lignes illisibles ont déjà été signalées (une fois par fichier et par démarrage). */
  #signalees = new Set();

  /**
   * @param {{racine: string, orgId: string, journalId: string, signaler?: ((periodStart: number, illisibles: {ligne: number, raison: string}[]) => void)|null}} o
   *   `signaler` : appelé une fois par période et par ouverture quand `acquisitions.ndjson` porte des lignes illisibles
   */
  constructor({ racine, orgId, journalId, signaler = null }) {
    if (!/^0x[0-9a-f]{64}$/.test(orgId) || !/^0x[0-9a-f]{64}$/.test(journalId)) throw new TypeError("org_id et journal_id hex32 attendus");
    this.racine = racine;
    this.orgId = orgId;
    this.journalId = journalId;
    this.signaler = typeof signaler === "function" ? signaler : null;
    // CT-2 EX-12.1 : le répertoire du journal est nommé par ses identifiants en hexadécimal minuscule sans `0x`
    // (lectures du branchement : le répertoire d'ancres d'EX-5.14 est sous ce répertoire, celui que l'enregistreur écrit et copie).
    this.repertoireJournal = path.join(racine, orgId.slice(2), journalId.slice(2), "ancres");
  }

  /** Ouvre (crée s'il le faut) le dépôt d'un journal. */
  static ouvrir({ racine, orgId, journalId, signaler = null }) {
    const d = new DepotAncres({ racine, orgId, journalId, signaler });
    fs.mkdirSync(d.repertoireJournal, { recursive: true });
    return d;
  }

  /** Répertoire d'une période, créé avec `rfc3161/` et `ots/`. */
  repertoire(periodStart) {
    const rep = path.join(this.repertoireJournal, nomPeriode(periodStart));
    fs.mkdirSync(path.join(rep, "rfc3161"), { recursive: true });
    fs.mkdirSync(path.join(rep, "ots"), { recursive: true });
    return rep;
  }

  /** Nom de base d'une pièce RFC 3161 : `<objet>-<provider_id>-<attempt_id>`. */
  nomPiece({ objet, imprint, providerId, attemptId }) {
    return `${nomObjet(objet, imprint)}-${controlerIdentifiant(providerId, "provider_id")}-${controlerIdentifiant(attemptId, "attempt_id")}`;
  }

  /**
   * Écrit une pièce (jamais de réécriture), `fsync` du fichier puis du
   * répertoire. Rend le chemin relatif au répertoire de la période.
   * `sousRepertoire` : `rfc3161` ou `ots`.
   *
   * Revue de sécurité de l'étape 8 (EX-5.14) : une pièce n'existe sous son nom qu'entière.
   * Les octets vont dans un fichier provisoire du même répertoire, écrits en
   * boucle jusqu'au dernier (`write(2)` peut rendre une écriture courte quand
   * la place manque), synchronisés, puis le nom définitif est posé par un lien
   * exclusif (`link(2)` échoue si le nom existe) ; le provisoire est retiré,
   * le répertoire synchronisé. Toute écriture incomplète est une `ErreurDepot`
   * et ne laisse rien sous le nom définitif.
   */
  ecrirePiece(periodStart, sousRepertoire, nom, octets) {
    const rep = this.repertoire(periodStart);
    const chemin = path.join(rep, sousRepertoire, nom);
    const existe = () => new ErreurDepot(`fichier existant, jamais réécrit : ${path.join(sousRepertoire, nom)}`, Object.assign(new Error("EEXIST"), { code: "EEXIST" }));
    if (fs.existsSync(chemin)) throw existe();
    if (!ecrireEntierPuisLier(chemin, octets, (message, err) => new ErreurDepot(message, err), `${sousRepertoire}/${nom}`)) throw existe();
    synchroniserRepertoire(path.join(rep, sousRepertoire));
    return path.join(sousRepertoire, nom);
  }

  /**
   * Ajoute une ligne JCS intégral à `acquisitions.ndjson`, `fsync` compris.
   * Revue de sécurité de l'étape 8 (CT-5 EX-5.14) : avant l'ajout, une fin de fichier sans saut de ligne
   * (coupure pendant un ajout) est tronquée à la dernière ligne complète ; la
   * ligne est écrite en boucle jusqu'au dernier octet ; une écriture en échec
   * est effacée jusqu'au début de la ligne. Un fragment ne cache donc jamais
   * l'acquisition suivante, et une ligne courte n'est jamais dite écrite.
   */
  ajouterAcquisition(periodStart, enregistrement) {
    const rep = this.repertoire(periodStart);
    const ligne = Buffer.from(jcs(enregistrement) + "\n", "utf8");
    const chemin = path.join(rep, "acquisitions.ndjson");
    const existait = fs.existsSync(chemin);
    let fd;
    try {
      fd = fs.openSync(chemin, fs.constants.O_RDWR | fs.constants.O_APPEND | fs.constants.O_CREAT, 0o600);
      tronquerFragment(fd);
      const debut = fs.fstatSync(fd).size;
      let ecrit = 0;
      try {
        while (ecrit < ligne.length) ecrit += fs.writeSync(fd, ligne, ecrit, ligne.length - ecrit);
      } catch (err) {
        try {
          fs.ftruncateSync(fd, debut);
          fs.fsyncSync(fd);
        } catch {
          // Le fragment, s'il reste, est tronqué à l'ajout suivant.
        }
        throw err;
      }
      fs.fsyncSync(fd);
    } catch (err) {
      throw new ErreurDepot(`acquisitions.ndjson : ${err.message}`, err);
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
    }
    if (!existait) synchroniserRepertoire(rep);
    if (this.#nonces !== null && typeof enregistrement?.nonce === "string") this.#nonces.add(enregistrement.nonce);
    return "acquisitions.ndjson";
  }

  /**
   * Rejoue `acquisitions.ndjson` d'une période. Une ligne tronquée (sans saut
   * de ligne final) est signalée (`tronquee`), non lue ; une ligne illisible
   * (JSON strict refusé, valeur autre qu'un objet) est ignorée et signalée
   * dans `illisibles` (`{ ligne, raison }`, comme la file d'EX-8.5 règle 3),
   * jamais réparée, et n'interdit jamais la lecture des autres.
   * @returns {{enregistrements: object[], tronquee: boolean, illisibles: {ligne: number, raison: string}[]}}
   */
  lireAcquisitions(periodStart) {
    const chemin = path.join(this.repertoireJournal, nomPeriode(periodStart), "acquisitions.ndjson");
    if (!fs.existsSync(chemin)) return { enregistrements: [], tronquee: false, illisibles: [] };
    const texte = fs.readFileSync(chemin, "utf8");
    const lignes = texte.split("\n");
    const tronquee = lignes[lignes.length - 1] !== "";
    const completes = lignes.slice(0, -1);
    const enregistrements = [];
    const illisibles = [];
    for (let k = 0; k < completes.length; k++) {
      const l = completes[k];
      if (l === "") continue;
      let valeur;
      try {
        valeur = analyserJson(l);
      } catch (e) {
        illisibles.push({ ligne: k + 1, raison: e instanceof ErreurJson ? `json_${e.code}` : "ligne_illisible" });
        continue;
      }
      if (valeur === null || typeof valeur !== "object" || Array.isArray(valeur)) {
        illisibles.push({ ligne: k + 1, raison: "enregistrement_non_objet" });
        continue;
      }
      enregistrements.push(copieAutonome(valeur));
    }
    // Revue de sécurité de l'étape 8 (CT-5 EX-5.14) : une ligne tronquée est signalée comme une ligne illisible (une acquisition manque au fichier).
    if ((illisibles.length || tronquee) && this.signaler && !this.#signalees.has(periodStart)) {
      this.#signalees.add(periodStart);
      try {
        this.signaler(periodStart, tronquee ? [...illisibles, { ligne: lignes.length, raison: "tronquee" }] : illisibles);
      } catch {
        // Le signalement ne bloque jamais la lecture.
      }
    }
    return { enregistrements, tronquee, illisibles };
  }

  /** Périodes présentes dans le dépôt (par `period_start`). */
  periodes() {
    if (!fs.existsSync(this.repertoireJournal)) return [];
    return fs
      .readdirSync(this.repertoireJournal)
      .filter((n) => /^periode-\d{10}$/.test(n))
      .map((n) => Number(n.slice(8)))
      .sort((a, b) => a - b);
  }

  /**
   * Le nonce (hex8 ou bigint) figure déjà dans un enregistrement d'acquisition
   * du journal (AN-6). L'index est construit en mémoire à la première
   * consultation (toutes les périodes du dépôt, une fois) puis tenu à jour par
   * `ajouterAcquisition` : la relecture de toutes les périodes à chaque
   * tentative disparaît ; une ligne illisible n'empêche rien.
   */
  nonceConnu(nonce) {
    const hex = typeof nonce === "bigint" ? "0x" + nonce.toString(16).padStart(16, "0") : nonce;
    return this.#indexNonces().has(hex);
  }

  #indexNonces() {
    if (this.#nonces === null) {
      const index = new Set();
      for (const p of this.periodes()) {
        for (const e of this.lireAcquisitions(p).enregistrements) if (typeof e.nonce === "string") index.add(e.nonce);
      }
      this.#nonces = index;
    }
    return this.#nonces;
  }

  /** Oublie l'index des nonces (reconstruit à la prochaine consultation) : après une écriture par un autre processus. */
  oublierIndexNonces() {
    this.#nonces = null;
  }

  /**
   * Dernier état de chaque tentative d'une période : le fichier est en ajout
   * seul, et l'étape 10 d'EX-5.10 (T-10 différée) ajoute une ligne pour une
   * tentative déjà consignée (`checks.T-10`, `revoked`, `files.crls`) ; la
   * dernière ligne d'un `attempt_id` fait foi.
   */
  dernieresAcquisitions(periodStart) {
    const { enregistrements, tronquee, illisibles } = this.lireAcquisitions(periodStart);
    const parTentative = new Map();
    for (const e of enregistrements) parTentative.set(typeof e.attempt_id === "string" ? e.attempt_id : Symbol("sans_attempt_id"), e);
    return { enregistrements: [...parTentative.values()], tronquee, illisibles };
  }

  /**
   * Un enregistrement `obtenue` de cet objet porte déjà `promoted` et n'est pas
   * révoqué (le choix d'EX-5.8 est fait une fois, sauf révocation). Revue de sécurité de l'étape 8
   * (CT-5 EX-5.10) : `promoted` ne compte qu'avec `outcome` `obtenue`, comme pour
   * l'exportateur (EX-5.8 : le choix se fait parmi les jetons valables).
   */
  dejaPromu(objet, imprint, periodStart) {
    const nom = nomObjet(objet, imprint);
    return this.dernieresAcquisitions(periodStart).enregistrements.some((e) => e.object_name === nom && e.outcome === "obtenue" && e.promoted === true && e.revoked !== true);
  }

  /**
   * L'enregistrement du jeton promu d'un objet (EX-5.8), ou `null` : le dernier
   * marqué `promoted`, d'issue `obtenue` et non révoqué (dernier état de chaque
   * tentative) ; à défaut (aucun choix consigné), le choix d'EX-5.8 parmi les `obtenue`.
   */
  promu(objet, periodStart, imprint = null) {
    const { enregistrements } = this.dernieresAcquisitions(periodStart);
    const siens = enregistrements.filter((e) => e.object === objet && (imprint === null || e.imprint === imprint));
    const marques = siens.filter((e) => e.outcome === "obtenue" && e.promoted === true && e.revoked !== true);
    if (marques.length > 0) return marques[marques.length - 1];
    return choisirPromu(siens.filter((e) => e.revoked !== true));
  }
}
