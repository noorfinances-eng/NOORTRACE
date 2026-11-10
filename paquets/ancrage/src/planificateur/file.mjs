// File d'attente durable de CT-5 EX-8.5 : un fichier NDJSON en ajout seul par
// époque de bail (`<queue.path>/file-<epoch>.ndjson`), une ligne par état
// successif d'une demande (forme canonique JCS intégral d'un `$defs/demande`),
// écrite et synchronisée (`fdatasync`) avant que l'action qui en découle soit
// entreprise (règle 1, AN-32). À la lecture, la dernière ligne d'un `id` fait
// foi (règle 3), une ligne tronquée en fin de fichier est ignorée et
// consignée (`anchor_queue_truncated_line`), jamais réparée ; tous les
// fichiers `file-*.ndjson` du répertoire, compactés ou non, sont relus et
// fusionnés dans l'ordre des époques puis des lignes (règle 6). La compaction
// (règle 5) n'a jamais lieu sur le fichier courant.

import fs from "node:fs";
import path from "node:path";
import { ErreurJson, analyserJson, jcs } from "@noortrace/noyau";
import { ID_SCHEMA_PLANIFICATEUR, REGISTRE_ANCRAGE } from "./configuration.mjs";

/** États finaux d'une demande (CT-5 EX-8.3). */
export const ETATS_FINAUX = Object.freeze(["obtenue", "complete", "sans_objet", "refusee", "remplacee"]);

/** Taille maximale d'une ligne de file admise à la lecture (octets). */
export const TAILLE_MAX_LIGNE = 1048576;

const MOTIF_FICHIER = /^file-(\d{1,18})(?:\.(\d{1,9})\.compact)?\.ndjson$/;
const REF_DEMANDE = `${ID_SCHEMA_PLANIFICATEUR}#/$defs/demande`;

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
  const lignes = [];
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
    const v = REGISTRE_ANCRAGE.valider(REF_DEMANDE, valeur);
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
    lignes.push(valeur);
  }
  return { lignes, tronquees };
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

/**
 * Fichier de file d'une époque, en ajout seul, synchronisé à chaque ligne.
 */
export class FileDurable {
  /**
   * @param {{repertoire: string, epoque: number|bigint, fdatasync?: boolean, fd: number, chemin: string}} p
   */
  constructor({ repertoire, epoque, fdatasync, fd, chemin }) {
    this.repertoire = repertoire;
    this.epoque = epoque;
    this.synchroniser = fdatasync;
    this.fd = fd;
    this.chemin = chemin;
    this.lignesEcrites = 0;
  }

  /**
   * Ouvre (ou crée) `file-<epoch>.ndjson` dans le répertoire ; le répertoire
   * est créé s'il manque et son parent synchronisé.
   * @param {{repertoire: string, epoque: number|bigint, fdatasync?: boolean}} p
   * @returns {FileDurable}
   */
  static ouvrir({ repertoire, epoque, fdatasync = true }) {
    if (typeof repertoire !== "string" || repertoire.length === 0) throw new TypeError("répertoire attendu");
    const nom = nomFichier(epoque);
    const chemin = path.join(repertoire, nom);
    if (!fs.existsSync(repertoire)) {
      fs.mkdirSync(repertoire, { recursive: true, mode: 0o700 });
      const parent = fs.openSync(path.dirname(repertoire), "r");
      try {
        fs.fsyncSync(parent);
      } finally {
        fs.closeSync(parent);
      }
    }
    const fd = fs.openSync(chemin, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT, 0o600);
    return new FileDurable({ repertoire, epoque, fdatasync, fd, chemin });
  }

  /**
   * Écrit une ligne (JCS intégral de la demande) et ne rend la main qu'après
   * `fdatasync` (EX-8.5, règle 1).
   * @param {object} demande `$defs/demande`
   * @returns {{octets: number, ligne: string}}
   */
  ecrire(demande) {
    if (this.fd === null) throw new Error("file fermée");
    controlerDemande(demande);
    const ligne = jcs(demande) + "\n";
    const octets = Buffer.from(ligne, "utf8");
    let ecrit = 0;
    while (ecrit < octets.length) ecrit += fs.writeSync(this.fd, octets, ecrit, octets.length - ecrit);
    if (this.synchroniser) fs.fdatasyncSync(this.fd);
    this.lignesEcrites += 1;
    return { octets: octets.length, ligne };
  }

  /** Relit ce seul fichier. */
  lire() {
    const d = decoderFile(fs.readFileSync(this.chemin), path.basename(this.chemin));
    return { demandes: [...fusionner(d.lignes).values()], tronquees: d.tronquees };
  }

  /** Ferme le descripteur. */
  fermer() {
    if (this.fd !== null) {
      fs.closeSync(this.fd);
      this.fd = null;
    }
  }

  /**
   * Compacte un fichier d'époque **antérieure** dont toutes les demandes sont
   * finales en `file-<epoch>.<n>.compact.ndjson` (dernière ligne de chaque id) ;
   * l'original est conservé. Refuse le fichier courant et un fichier qui
   * porte une demande active.
   * @param {string} repertoire
   * @param {number|bigint} epoque
   * @param {{courante?: number|bigint|null, indice?: number}} [options]
   * @returns {{chemin: string, demandes: number}}
   */
  static compacter(repertoire, epoque, options = {}) {
    if (options.courante !== undefined && options.courante !== null && String(options.courante) === String(epoque)) {
      throw new Error("la compaction n'a jamais lieu sur le fichier courant (EX-8.5, règle 5)");
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
