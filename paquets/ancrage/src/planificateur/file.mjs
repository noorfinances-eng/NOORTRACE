// File d'attente durable de CT-5 EX-8.5 : un fichier NDJSON en ajout seul par
// époque de bail (`<queue.path>/file-<epoch>.ndjson`), une ligne par état
// successif d'une demande (forme canonique JCS intégral d'un `$defs/demande`),
// écrite et synchronisée (`fdatasync`) avant que l'action qui en découle soit
// entreprise (règle 1, AN-32). À la lecture, la dernière ligne d'un `id` fait
// foi (règle 3), une ligne tronquée en fin de fichier est ignorée et
// consignée (`anchor_queue_truncated_line`), jamais réparée ; tous les
// fichiers `file-*.ndjson` du répertoire, compactés ou non, sont relus et
// fusionnés dans l'ordre des époques puis des lignes (règle 6).
//
// Révision 0.6 de CT-5 : chaque ligne écrite porte au plus 32 tentatives et
// `attempts_total` (règle 7 ; la fenêtre est tenue par le planificateur, le
// schéma la vérifie ici), une ligne d'avant la révision (sans
// `attempts_total`) de plus de 32 tentatives est lue telle quelle ; le
// fichier courant est **compacté** (règle 5) : fichier neuf
// `file-<epoch>.ndjson.compactage` qui garde la dernière ligne de chaque `id`,
// octets recopiés tels quels, `fdatasync`, `rename` sur le fichier courant,
// `fsync` du répertoire, réouverture du descripteur d'ajout ; à la clôture
// (appel du composant) et dès que la taille dépasse `queue.compact_bytes` et
// `2 × S_0` ; un échec laisse l'ancien fichier valide et ne bloque rien. Un
// `.compactage` trouvé à l'ouverture est supprimé (EX-8.12) : c'est le seul
// fichier que le composant supprime (EX-8.14).

import fs from "node:fs";
import path from "node:path";
import { ErreurJson, analyserJson, jcs } from "@noortrace/noyau";
import { ID_SCHEMA_PLANIFICATEUR, REGISTRE_ANCRAGE } from "./configuration.mjs";

/** États finaux d'une demande (CT-5 EX-8.3). */
export const ETATS_FINAUX = Object.freeze(["obtenue", "complete", "sans_objet", "refusee", "remplacee"]);

/** Taille maximale d'une ligne de file admise à la lecture (octets). */
export const TAILLE_MAX_LIGNE = 1048576;

/** Nombre maximal de tentatives portées par une ligne écrite (CT-5 EX-8.5, règle 7 ; révision 0.6). */
export const FENETRE_TENTATIVES = 32;

/** Défaut de `queue.compact_bytes` (CT-5 EX-4.8, EX-8.5 règle 5 ; révision 0.6). */
export const COMPACT_BYTES_DEFAUT = 16777216;

/** Délai minimal entre deux compactages sur dépassement de taille après un échec (horloge monotone, EX-8.5 règle 5). */
export const DELAI_APRES_ECHEC_MS = 60000;

/** Suffixe du fichier neuf d'un compactage (EX-8.5 règle 5). */
export const SUFFIXE_COMPACTAGE = ".compactage";

const MOTIF_FICHIER = /^file-(\d{1,18})(?:\.(\d{1,9})\.compact)?\.ndjson$/;
const MOTIF_RESIDU = /^file-\d{1,18}\.ndjson\.compactage$/;
const REF_DEMANDE = `${ID_SCHEMA_PLANIFICATEUR}#/$defs/demande`;
const REF_TENTATIVE = `${ID_SCHEMA_PLANIFICATEUR}#/$defs/tentative`;
/** Borne de `attempts` des lignes d'avant la révision 0.6 (schéma 0.5 : 100 000). */
const MAX_TENTATIVES_AVANT_06 = 100000;

/**
 * Valide une ligne lue contre `$defs/demande`, avec la lecture des lignes
 * d'avant la révision 0.6 (EX-8.5, règle 7) : une ligne **sans**
 * `attempts_total` qui porte plus de 32 tentatives est lue telle quelle (ses
 * 32 premières tentatives et le reste de la ligne contre `$defs/demande`,
 * chacune des suivantes contre `$defs/tentative`, 100 000 au plus) ; une ligne
 * qui porte `attempts_total` reste bornée à 32 tentatives.
 * @param {unknown} valeur
 * @returns {{valide: boolean, erreurs: string[]}}
 */
export function validerLigneDemande(valeur) {
  const ancienne = valeur !== null && typeof valeur === "object" && !Array.isArray(valeur) && !Object.hasOwn(valeur, "attempts_total") && Array.isArray(valeur.attempts) && valeur.attempts.length > FENETRE_TENTATIVES;
  if (!ancienne) return REGISTRE_ANCRAGE.valider(REF_DEMANDE, valeur);
  if (valeur.attempts.length > MAX_TENTATIVES_AVANT_06) return { valide: false, erreurs: [`/attempts : plus de ${MAX_TENTATIVES_AVANT_06} éléments`] };
  const v = REGISTRE_ANCRAGE.valider(REF_DEMANDE, { ...valeur, attempts: valeur.attempts.slice(0, FENETRE_TENTATIVES) });
  if (!v.valide) return v;
  for (let i = FENETRE_TENTATIVES; i < valeur.attempts.length; i++) {
    const t = REGISTRE_ANCRAGE.valider(REF_TENTATIVE, valeur.attempts[i]);
    if (!t.valide) return { valide: false, erreurs: t.erreurs.map((e) => `/attempts/${i}${String(e).startsWith("/") ? "" : " : "}${e}`) };
  }
  return { valide: true, erreurs: [] };
}

/**
 * `attempts_total` d'une demande lue (EX-8.5, règle 7) : la valeur écrite, ou,
 * pour une ligne d'avant la révision 0.6, le nombre de ses tentatives.
 * @param {{attempts: object[], attempts_total?: number}} demande
 */
export function totalTentatives(demande) {
  return Number.isSafeInteger(demande.attempts_total) ? demande.attempts_total : demande.attempts.length;
}

/**
 * Une demande est-elle dans un état final ?
 * @param {{state: string}} demande
 */
export function estFinale(demande) {
  return ETATS_FINAUX.includes(demande.state);
}

/** Demande refusée par le schéma `$defs/demande` (jamais écrite dans la file) : `code` et `chemin` (pointeur JSON de l'écart). */
export class ErreurDemandeNonConforme extends TypeError {
  constructor(message, chemin) {
    super(message);
    this.name = "ErreurDemandeNonConforme";
    this.code = "demande_non_conforme";
    this.chemin = chemin;
  }
}

/**
 * Contrôle qu'un objet est une `$defs/demande` du schéma et que son `id` vaut
 * `<kind>:<subject.hash>` (EX-8.2) ; lève `ErreurDemandeNonConforme` sinon.
 * @param {unknown} demande
 */
export function controlerDemande(demande) {
  const v = REGISTRE_ANCRAGE.valider(REF_DEMANDE, demande);
  if (!v.valide) throw new ErreurDemandeNonConforme(`demande non conforme à $defs/demande : ${v.erreurs[0]}`, /^(\/[^ ]*)/.exec(String(v.erreurs[0]))?.[1] ?? "");
  if (!idCoherent(demande)) throw new ErreurDemandeNonConforme(`demande non conforme à $defs/demande : /id : différent de <kind>:<subject.hash> (EX-8.2)`, "/id");
}

/** L'identifiant d'une demande est sa clé d'idempotence `<kind>:<subject.hash>` (EX-8.2 ; correction R-C-4). */
export function idCoherent(demande) {
  return demande.id === `${demande.kind}:${demande.subject?.hash}`;
}

/**
 * Nom du fichier d'une époque.
 * @param {number|bigint} epoque
 */
export function nomFichier(epoque) {
  if (!(Number.isSafeInteger(epoque) && epoque >= 0) && typeof epoque !== "bigint") throw new RangeError("époque : entier non négatif attendu");
  return `file-${String(epoque)}.ndjson`;
}

/**
 * Décode un fichier de file : une demande par ligne, la dernière ligne d'un id
 * fait foi ; une ligne tronquée en fin de fichier, ou illisible, est ignorée
 * et signalée.
 * @param {Buffer|Uint8Array} octets
 * @param {string} [fichier] nom rapporté dans les signalements
 * @returns {{lignes: object[], tronquees: {fichier: string, ligne: number, raison: string}[]}}
 */
export function decoderFile(octets, fichier = "") {
  const { entrees, tronquees } = parcourirFile(octets, fichier);
  return { lignes: entrees.map((e) => e.valeur), tronquees };
}

/**
 * Lignes à garder par un compactage (EX-8.5, règle 5, pas (a) et (b)) : la
 * dernière ligne de chaque `id`, octets tels quels (saut de ligne compris),
 * dans l'ordre où ces dernières lignes figurent dans le fichier ; une ligne
 * tronquée en fin de fichier, ou que la lecture de la règle 3 ignore, n'est
 * pas recopiée.
 * @param {Buffer|Uint8Array} octets
 * @returns {{lignes: Buffer[], demandes: number, octets: number, tronquees: {fichier: string, ligne: number, raison: string}[]}}
 */
export function dernieresLignes(octets) {
  const buf = Buffer.from(octets.buffer, octets.byteOffset, octets.byteLength);
  const { entrees, tronquees } = parcourirFile(buf);
  const derniere = new Map();
  for (const e of entrees) derniere.set(e.valeur.id, e);
  const gardees = [...derniere.values()].sort((a, b) => a.debut - b.debut);
  const lignes = gardees.map((e) => buf.subarray(e.debut, e.fin + 1));
  return { lignes, demandes: gardees.length, octets: lignes.reduce((n, l) => n + l.length, 0), tronquees };
}

/**
 * Parcours d'un fichier de file : chaque ligne lisible avec sa position
 * (`debut` : premier octet, `fin` : position du saut de ligne).
 * @param {Buffer|Uint8Array} octets
 * @param {string} [fichier]
 */
function parcourirFile(octets, fichier = "") {
  const entrees = [];
  const tronquees = [];
  const buf = Buffer.from(octets.buffer, octets.byteOffset, octets.byteLength);
  let debut = 0;
  let numero = 0;
  while (debut < buf.length) {
    const fin = buf.indexOf(0x0a, debut);
    numero += 1;
    if (fin === -1) {
      tronquees.push({ fichier, ligne: numero, raison: "ligne_tronquee" });
      break;
    }
    const ligne = buf.subarray(debut, fin);
    const debutLigne = debut;
    debut = fin + 1;
    if (ligne.length === 0) {
      tronquees.push({ fichier, ligne: numero, raison: "ligne_vide" });
      continue;
    }
    if (ligne.length > TAILLE_MAX_LIGNE) {
      tronquees.push({ fichier, ligne: numero, raison: "ligne_trop_longue" });
      continue;
    }
    let valeur;
    try {
      valeur = analyserJson(ligne);
    } catch (e) {
      tronquees.push({ fichier, ligne: numero, raison: e instanceof ErreurJson ? `json_${e.code}` : "ligne_illisible" });
      continue;
    }
    const v = validerLigneDemande(valeur);
    if (!v.valide) {
      tronquees.push({ fichier, ligne: numero, raison: "demande_non_conforme" });
      continue;
    }
    if (!idCoherent(valeur)) {
      // EX-8.2 : `id = <kind>:<hash>` ; une ligne dont l'id désigne un autre objet ferait envoyer des requêtes sur
      // `subject.hash` sous l'identifiant d'un autre (R-C-4) : signalée comme une ligne tronquée, jamais relue.
      tronquees.push({ fichier, ligne: numero, raison: "id_incoherent" });
      continue;
    }
    if (jcs(valeur) !== ligne.toString("utf8")) {
      tronquees.push({ fichier, ligne: numero, raison: "forme_non_canonique" });
      continue;
    }
    entrees.push({ valeur, debut: debutLigne, fin });
  }
  return { entrees, tronquees };
}

/**
 * Fusionne des lignes par `id` : la dernière lue fait foi ; l'ordre rendu est
 * celui de la première apparition de chaque `id`.
 * @param {object[]} lignes
 * @returns {Map<string, object>}
 */
export function fusionner(lignes) {
  const parId = new Map();
  for (const l of lignes) parId.set(l.id, l);
  return parId;
}

/**
 * Trie des demandes comme `queue_after` des traces : `created_at` puis `id`.
 * @param {object[]} demandes
 */
export function trierDemandes(demandes) {
  return [...demandes].sort((a, b) => (a.created_at < b.created_at ? -1 : a.created_at > b.created_at ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/**
 * Fichiers de file d'un répertoire, dans l'ordre des époques (puis l'original
 * avant ses compactions).
 * @param {string} repertoire
 * @returns {{nom: string, epoque: bigint, compact: number|null}[]}
 */
export function fichiersDeFile(repertoire) {
  const noms = fs.existsSync(repertoire) ? fs.readdirSync(repertoire) : [];
  const fichiers = [];
  for (const nom of noms) {
    const m = MOTIF_FICHIER.exec(nom);
    if (!m) continue;
    fichiers.push({ nom, epoque: BigInt(m[1]), compact: m[2] === undefined ? null : Number(m[2]) });
  }
  return fichiers.sort((a, b) => {
    if (a.epoque !== b.epoque) return a.epoque < b.epoque ? -1 : 1;
    if (a.compact === null) return b.compact === null ? 0 : -1;
    if (b.compact === null) return 1;
    return a.compact - b.compact;
  });
}

/**
 * Relit tous les fichiers `file-*.ndjson` du répertoire et fusionne leurs
 * lignes par `id` (EX-8.5, règle 6).
 * @param {string} repertoire
 * @returns {{demandes: object[], parId: Map<string, object>, tronquees: {fichier: string, ligne: number, raison: string}[], fichiers: string[]}}
 *   `demandes` dans l'ordre de première apparition des id (ordre des fichiers puis des lignes)
 */
export function lireFiles(repertoire) {
  const fichiers = fichiersDeFile(repertoire);
  const lignes = [];
  const tronquees = [];
  for (const f of fichiers) {
    const d = decoderFile(fs.readFileSync(path.join(repertoire, f.nom)), f.nom);
    lignes.push(...d.lignes);
    tronquees.push(...d.tronquees);
  }
  const parId = fusionner(lignes);
  // Ordre de première apparition de chaque id (celui du fichier), comme
  // `queue_before` des traces ; `trierDemandes` donne l'ordre de `queue_after`.
  return { demandes: [...parId.values()], parId, tronquees, fichiers: fichiers.map((f) => f.nom) };
}

/** `fsync` d'un répertoire (EX-8.5, règle 5, pas (e) ; création du répertoire de file). */
function synchroniserRepertoire(repertoire) {
  const fd = fs.openSync(repertoire, "r");
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Supprime les fichiers temporaires de compactage `file-<epoch>.ndjson.compactage`
 * d'un répertoire de file (EX-8.12 : ignorés à la lecture, puis supprimés ;
 * seuls fichiers que le composant supprime, EX-8.14).
 * @param {string} repertoire
 * @returns {string[]} noms supprimés
 */
export function supprimerResidusCompactage(repertoire) {
  if (!fs.existsSync(repertoire)) return [];
  const supprimes = [];
  for (const nom of fs.readdirSync(repertoire)) {
    if (!MOTIF_RESIDU.test(nom)) continue;
    fs.rmSync(path.join(repertoire, nom), { force: true });
    supprimes.push(nom);
  }
  if (supprimes.length) synchroniserRepertoire(repertoire);
  return supprimes;
}

/** Erreur d'un pas du compactage, avec son nom (`step` de la ligne `anchor_queue_compaction_failed`). */
class ErreurPasCompactage extends Error {
  constructor(pas, cause) {
    super(`compactage, pas ${pas} : ${cause?.message ?? cause}`);
    this.pas = pas;
    this.cause = cause;
  }
}

/**
 * Fichier de file d'une époque, en ajout seul, synchronisé à chaque ligne,
 * compacté selon la règle 5 d'EX-8.5 (révision 0.6).
 */
export class FileDurable {
  /**
   * @param {{repertoire: string, epoque: number|bigint, fdatasync?: boolean, fd: number, chemin: string,
   *   compactBytes?: number, monotone?: () => number, journal?: ((niveau: string, evenement: string, champs: object) => void)|null,
   *   crochet?: ((pas: string, file: FileDurable) => void)|null, residus?: string[]}} p
   */
  constructor({ repertoire, epoque, fdatasync, fd, chemin, compactBytes = COMPACT_BYTES_DEFAUT, monotone = () => performance.now(), journal = null, crochet = null, residus = [] }) {
    this.repertoire = repertoire;
    this.epoque = epoque;
    this.synchroniser = fdatasync;
    this.fd = fd;
    this.chemin = chemin;
    this.lignesEcrites = 0;
    /** `queue.compact_bytes` (EX-4.8). */
    this.compactBytes = compactBytes;
    this.monotone = monotone;
    this.journal = journal;
    /** Crochet d'essai appelé avant chaque pas du compactage (`relecture`, `ecriture`, `fdatasync`, `renommage`, `repertoire`, `reouverture`). */
    this.crochet = crochet;
    /** Taille courante du fichier, en octets. */
    this.taille = fs.fstatSync(fd).size;
    /** `S_0` : taille laissée par le compactage précédent (0 avant le premier compactage de l'ouverture). */
    this.s0 = 0;
    /** Plus grande taille atteinte depuis l'ouverture (mesure TM-17). */
    this.tailleMax = this.taille;
    /** Instant monotone du dernier échec de compactage (au plus une tentative par minute sur dépassement de taille). */
    this.dernierEchec = null;
    this.enCompactage = false;
    /** Lignes demandées pendant un compactage : écrites juste après, dans l'ordre (aucune n'est perdue). */
    this.differees = [];
    /** Descripteur à rouvrir (échec de la réouverture après un renommage). */
    this.aRouvrir = false;
    this.compactages = 0;
    this.echecsCompactage = 0;
    /** `.compactage` résiduels supprimés à l'ouverture (EX-8.12). */
    this.residus = residus;
  }

  /**
   * Ouvre (ou crée) `file-<epoch>.ndjson` dans le répertoire ; le répertoire
   * est créé s'il manque et son parent synchronisé ; un fichier
   * `file-*.ndjson.compactage` resté d'un arrêt est supprimé (EX-8.12).
   * @param {{repertoire: string, epoque: number|bigint, fdatasync?: boolean, compactBytes?: number,
   *   monotone?: () => number, journal?: Function|null, crochet?: Function|null}} p
   * @returns {FileDurable}
   */
  static ouvrir({ repertoire, epoque, fdatasync = true, compactBytes = COMPACT_BYTES_DEFAUT, monotone, journal = null, crochet = null }) {
    if (typeof repertoire !== "string" || repertoire.length === 0) throw new TypeError("répertoire attendu");
    if (!Number.isSafeInteger(compactBytes) || compactBytes < 1) throw new RangeError("compactBytes : entier positif attendu");
    const nom = nomFichier(epoque);
    const chemin = path.join(repertoire, nom);
    if (!fs.existsSync(repertoire)) {
      fs.mkdirSync(repertoire, { recursive: true, mode: 0o700 });
      synchroniserRepertoire(path.dirname(repertoire));
    }
    const residus = supprimerResidusCompactage(repertoire);
    const fd = fs.openSync(chemin, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT, 0o600);
    return new FileDurable({ repertoire, epoque, fdatasync, fd, chemin, compactBytes, ...(monotone ? { monotone } : {}), journal, crochet, residus });
  }

  /**
   * Écrit une ligne (JCS intégral de la demande) et ne rend la main qu'après
   * `fdatasync` (EX-8.5, règle 1) ; puis, entre deux écritures, compacte le
   * fichier si sa taille dépasse `compact_bytes` et `2 × S_0` (règle 5).
   * Pendant un compactage, la ligne est différée et écrite juste après lui.
   * @param {object} demande `$defs/demande`
   * @returns {{octets: number, ligne: string, differee?: boolean}}
   */
  ecrire(demande) {
    controlerDemande(demande);
    const ligne = jcs(demande) + "\n";
    if (this.enCompactage) {
      this.differees.push(ligne);
      return { octets: Buffer.byteLength(ligne), ligne, differee: true };
    }
    const octets = this.#ajouter(ligne);
    this.declencher();
    return { octets, ligne };
  }

  #ajouter(ligne) {
    if (this.aRouvrir) this.#rouvrir();
    if (this.fd === null) throw new Error("file fermée");
    const octets = Buffer.from(ligne, "utf8");
    let ecrit = 0;
    while (ecrit < octets.length) ecrit += fs.writeSync(this.fd, octets, ecrit, octets.length - ecrit);
    if (this.synchroniser) fs.fdatasyncSync(this.fd);
    this.lignesEcrites += 1;
    this.taille += octets.length;
    if (this.taille > this.tailleMax) this.tailleMax = this.taille;
    return octets.length;
  }

  #rouvrir() {
    const fd = fs.openSync(this.chemin, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT, 0o600);
    this.fd = fd;
    this.aRouvrir = false;
    this.taille = fs.fstatSync(fd).size;
  }

  /** Seuil de taille courant : `max(compact_bytes, 2 × S_0)` (EX-8.5, règle 5). */
  seuil() {
    return Math.max(this.compactBytes, 2 * this.s0);
  }

  /**
   * Déclencheur sur dépassement de taille (EX-8.5, règle 5) : compacte si la
   * taille dépasse à la fois `compact_bytes` et `2 × S_0`, au plus une fois
   * par minute de l'horloge monotone après un échec.
   * @returns {object|null} le compte rendu du compactage, ou null s'il n'a pas lieu
   */
  declencher() {
    if (this.enCompactage || this.fd === null) return null;
    if (!(this.taille > this.compactBytes && this.taille > 2 * this.s0)) return null;
    if (this.dernierEchec !== null && this.monotone() - this.dernierEchec < DELAI_APRES_ECHEC_MS) return null;
    return this.compacter({ declencheur: "taille" });
  }

  #pas(pas) {
    if (this.crochet) this.crochet(pas, this);
  }

  #consigner(niveau, evenement, champs) {
    if (!this.journal) return;
    try {
      this.journal(niveau, evenement, champs);
    } catch {
      // Le journal ne bloque jamais la file (EX-8.1).
    }
  }

  /**
   * Compacte le fichier courant (EX-8.5, règle 5) : (a) relecture selon la
   * règle 3 ; (b) fichier neuf `file-<epoch>.ndjson.compactage` avec la
   * dernière ligne de chaque `id`, octets recopiés tels quels, dans l'ordre où
   * ces lignes figurent ; (c) `fdatasync` ; (d) `rename` sur le fichier
   * courant ; (e) `fsync` du répertoire ; (f) réouverture du descripteur
   * d'ajout. Aucun état ne change. Une erreur aux pas (a) à (d) laisse
   * l'ancien fichier en place : le fichier neuf est supprimé, l'ajout
   * continue sur l'ancien descripteur ; ligne `anchor_queue_compaction_failed`
   * (`step`, `errno`, `bytes`) ; rien n'est bloqué. Une erreur au pas (e),
   * le renommage fait, est consignée de même (`step` `repertoire`), mais
   * l'ajout continue sur le fichier courant (le neuf) : l'ancien descripteur
   * désigne un fichier sans nom (lecture du texte, signalée). Succès : ligne
   * `anchor_queue_compacted` (`bytes_before`, `bytes_after`, `requests`).
   * @param {{declencheur?: "cloture"|"taille"}} [o]
   * @returns {{fait: boolean, declencheur: string, bytes_before?: number, bytes_after?: number, requests?: number, step?: string, errno?: string|null}}
   */
  compacter({ declencheur = "cloture" } = {}) {
    if (this.fd === null && !this.aRouvrir) return { fait: false, declencheur, raison: "file_fermee" };
    if (this.enCompactage) return { fait: false, declencheur, raison: "compactage_en_cours" };
    this.enCompactage = true;
    const neuf = this.chemin + SUFFIXE_COMPACTAGE;
    let tailleAvant = this.taille;
    let fdNeuf = null;
    let renomme = false;
    let resultat;
    try {
      let garde;
      try {
        this.#pas("relecture");
        const octets = fs.readFileSync(this.chemin);
        tailleAvant = octets.length;
        garde = dernieresLignes(octets);
      } catch (e) {
        throw new ErreurPasCompactage("relecture", e);
      }
      try {
        this.#pas("ecriture");
        fdNeuf = fs.openSync(neuf, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC, 0o600);
        const contenu = Buffer.concat(garde.lignes);
        let ecrit = 0;
        while (ecrit < contenu.length) ecrit += fs.writeSync(fdNeuf, contenu, ecrit, contenu.length - ecrit);
      } catch (e) {
        throw new ErreurPasCompactage("ecriture", e);
      }
      try {
        this.#pas("fdatasync");
        fs.fdatasyncSync(fdNeuf);
        fs.closeSync(fdNeuf);
        fdNeuf = null;
      } catch (e) {
        throw new ErreurPasCompactage("fdatasync", e);
      }
      try {
        this.#pas("renommage");
        fs.renameSync(neuf, this.chemin);
        renomme = true;
      } catch (e) {
        throw new ErreurPasCompactage("renommage", e);
      }
      try {
        this.#pas("repertoire");
        synchroniserRepertoire(this.repertoire);
      } catch (e) {
        throw new ErreurPasCompactage("repertoire", e);
      }
      // (f) Réouverture : l'ancien descripteur désigne désormais un fichier sans nom.
      this.#basculerDescripteur();
      this.taille = garde.octets;
      this.s0 = garde.octets;
      this.dernierEchec = null;
      this.compactages += 1;
      resultat = { fait: true, declencheur, bytes_before: tailleAvant, bytes_after: garde.octets, requests: garde.demandes };
      this.#consigner("info", "anchor_queue_compacted", { bytes_before: tailleAvant, bytes_after: garde.octets, requests: garde.demandes });
    } catch (e) {
      const pas = e instanceof ErreurPasCompactage ? e.pas : "relecture";
      const cause = e instanceof ErreurPasCompactage ? e.cause : e;
      if (fdNeuf !== null) {
        try {
          fs.closeSync(fdNeuf);
        } catch {
          // déjà fermé
        }
      }
      if (!renomme) {
        try {
          fs.rmSync(neuf, { force: true });
        } catch {
          // un fichier neuf qui reste est supprimé à l'ouverture suivante (EX-8.12)
        }
      } else {
        // Pas (e) en échec après le renommage : le fichier courant est déjà le fichier neuf, l'ancien descripteur
        // désigne un fichier sans nom ; l'ajout continue sur le fichier courant (lecture du porteur à confirmer).
        this.#basculerDescripteur();
        this.taille = fs.statSync(this.chemin).size;
        this.s0 = this.taille;
      }
      this.dernierEchec = this.monotone();
      this.echecsCompactage += 1;
      const errno = typeof cause?.code === "string" ? cause.code : null;
      resultat = { fait: false, declencheur, step: pas, errno, bytes: tailleAvant };
      this.#consigner("error", "anchor_queue_compaction_failed", { step: pas, errno, bytes: tailleAvant });
    } finally {
      this.enCompactage = false;
    }
    // Lignes demandées pendant l'opération : écrites maintenant, dans l'ordre.
    while (this.differees.length) this.#ajouter(this.differees.shift());
    return resultat;
  }

  /** Pas (f) : rouvre le descripteur d'ajout sur le fichier courant ; en échec, la prochaine écriture le rouvre (ou lève, et la file tolérante garde la ligne). */
  #basculerDescripteur() {
    const ancien = this.fd;
    this.fd = null;
    this.aRouvrir = true;
    if (ancien !== null) {
      try {
        fs.closeSync(ancien);
      } catch {
        // descripteur déjà fermé
      }
    }
    try {
      this.#pas("reouverture");
      this.#rouvrir();
    } catch {
      // réouverture différée à la prochaine écriture
    }
  }

  /** Relit ce seul fichier. */
  lire() {
    const d = decoderFile(fs.readFileSync(this.chemin), path.basename(this.chemin));
    return { demandes: [...fusionner(d.lignes).values()], tronquees: d.tronquees };
  }

  /** Mesures de la file (TM-17) : taille courante et maximale, `S_0`, seuil, compactages réussis et en échec. */
  mesures() {
    return { taille: this.taille, taille_max: this.tailleMax, s0: this.s0, seuil: this.seuil(), compact_bytes: this.compactBytes, compactages: this.compactages, echecs: this.echecsCompactage, lignes: this.lignesEcrites };
  }

  /** Ferme le descripteur. */
  fermer() {
    if (this.fd !== null) {
      fs.closeSync(this.fd);
      this.fd = null;
    }
    this.aRouvrir = false;
  }

  /**
   * Compacte un fichier d'époque **antérieure** dont toutes les demandes sont
   * finales en `file-<epoch>.<n>.compact.ndjson` (dernière ligne de chaque id) ;
   * l'original est conservé (EX-8.5, règle 5, dernier alinéa : règle des
   * versions 0.1 à 0.5, inchangée pour ces fichiers). Refuse le fichier
   * courant, que compacte la méthode d'instance `compacter`, et un fichier qui
   * porte une demande active.
   * @param {string} repertoire
   * @param {number|bigint} epoque
   * @param {{courante?: number|bigint|null, indice?: number}} [options]
   * @returns {{chemin: string, demandes: number}}
   */
  static compacter(repertoire, epoque, options = {}) {
    if (options.courante !== undefined && options.courante !== null && String(options.courante) === String(epoque)) {
      throw new Error("ce compactage des époques antérieures n'a pas lieu sur le fichier courant, compacté par compacter() (EX-8.5, règle 5)");
    }
    const source = path.join(repertoire, nomFichier(epoque));
    const d = decoderFile(fs.readFileSync(source), nomFichier(epoque));
    const finales = [...fusionner(d.lignes).values()];
    if (finales.some((x) => !estFinale(x))) throw new Error("compaction refusée : une demande du fichier n'est pas finale");
    const indice = options.indice ?? 1;
    const chemin = path.join(repertoire, `file-${String(epoque)}.${indice}.compact.ndjson`);
    const fd = fs.openSync(chemin, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    try {
      for (const x of finales) fs.writeSync(fd, jcs(x) + "\n");
      fs.fdatasyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    return { chemin, demandes: finales.length };
  }
}
