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
  /** Index en mémoire des nonces consignés (AN-6), construit à la première consultation puis tenu à jour (R-A-1). */
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
    // (lecture F2 : le répertoire d'ancres d'EX-5.14 est sous ce répertoire, celui que l'enregistreur écrit et copie).
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
   * Écrit une pièce en création exclusive (jamais de réécriture), `fsync` du
   * fichier puis du répertoire. Rend le chemin relatif au répertoire de la
   * période. `sousRepertoire` : `rfc3161` ou `ots`.
   */
  ecrirePiece(periodStart, sousRepertoire, nom, octets) {
    const rep = this.repertoire(periodStart);
    const chemin = path.join(rep, sousRepertoire, nom);
    let fd;
    try {
      fd = fs.openSync(chemin, "wx");
    } catch (err) {
      throw new ErreurDepot(err.code === "EEXIST" ? `fichier existant, jamais réécrit : ${path.join(sousRepertoire, nom)}` : `ouverture impossible : ${err.message}`, err);
    }
    try {
      fs.writeSync(fd, octets);
      fs.fsyncSync(fd);
    } catch (err) {
      throw new ErreurDepot(`écriture impossible : ${err.message}`, err);
    } finally {
      fs.closeSync(fd);
    }
    synchroniserRepertoire(path.join(rep, sousRepertoire));
    return path.join(sousRepertoire, nom);
  }

  /** Ajoute une ligne JCS intégral à `acquisitions.ndjson`, `fsync` compris. */
  ajouterAcquisition(periodStart, enregistrement) {
    const rep = this.repertoire(periodStart);
    const ligne = jcs(enregistrement) + "\n";
    const chemin = path.join(rep, "acquisitions.ndjson");
    const existait = fs.existsSync(chemin);
    let fd;
    try {
      fd = fs.openSync(chemin, "a");
      fs.writeSync(fd, ligne);
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
   * jamais réparée, et n'interdit jamais la lecture des autres (R-A-1).
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
    if (illisibles.length && this.signaler && !this.#signalees.has(periodStart)) {
      this.#signalees.add(periodStart);
      try {
        this.signaler(periodStart, illisibles);
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
   * tentative disparaît (R-A-1) ; une ligne illisible n'empêche rien.
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

  /** Un enregistrement `obtenue` de cet objet porte déjà `promoted` et n'est pas révoqué (le choix d'EX-5.8 est fait une fois, sauf révocation). */
  dejaPromu(objet, imprint, periodStart) {
    const nom = nomObjet(objet, imprint);
    return this.dernieresAcquisitions(periodStart).enregistrements.some((e) => e.object_name === nom && e.promoted === true && e.revoked !== true);
  }

  /**
   * L'enregistrement du jeton promu d'un objet (EX-5.8), ou `null` : le dernier
   * marqué `promoted` et non révoqué (dernier état de chaque tentative) ; à
   * défaut (aucun choix consigné), le choix d'EX-5.8 parmi les `obtenue`.
   */
  promu(objet, periodStart, imprint = null) {
    const { enregistrements } = this.dernieresAcquisitions(periodStart);
    const siens = enregistrements.filter((e) => e.object === objet && (imprint === null || e.imprint === imprint));
    const marques = siens.filter((e) => e.promoted === true && e.revoked !== true);
    if (marques.length > 0) return marques[marques.length - 1];
    return choisirPromu(siens.filter((e) => e.revoked !== true));
  }
}
