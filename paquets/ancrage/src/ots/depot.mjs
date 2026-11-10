// Dépôt des preuves OpenTimestamps (CT-5 EX-6.5, EX-5.14) : sous la racine de
// stockage de l'enregistreur, par journal et par période,
// `ancres/periode-<period_start>/ots/<objet>-<n>.ots` et
// `ancres/periode-<period_start>/entetes-bitcoin.json`, écrits en création
// exclusive, synchronisés sur le disque, jamais réécrits ; une mise à niveau
// écrit la version `<n+1>` à côté de la précédente ; la dernière version est
// celle que l'enregistrement d'acquisition désigne et que l'exportateur remet.
// Le dépôt ne touche à aucun autre fichier du répertoire d'ancres (ceux du
// client RFC 3161 et `acquisitions.ndjson` relèvent du lot A).

import fs from "node:fs";
import path from "node:path";
import { estHex, utf8 } from "@noortrace/noyau";
import { BORNES, lireOts } from "./format.mjs";
import { lireFichierEntetes, BORNES_ENTETES } from "./entetes.mjs";

const MOTIF_OBJET = /^(manifeste|point-[0-9a-f]{64})$/;
const MOTIF_VERSION = /^(manifeste|point-[0-9a-f]{64})-([1-9][0-9]{0,8})\.ots$/;
const FICHIER_ENTETES = "entetes-bitcoin.json";
const TENTATIVES_EXCLUSIVES = 8;

/** Erreur du dépôt ; `code` stable. */
export class ErreurDepot extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ErreurDepot";
    this.code = code;
  }
}

/**
 * Nom d'objet d'EX-5.14 : `manifeste` ou `point-<checkpointHash sans 0x>`.
 * @param {{type: "manifeste"|"point", checkpointHash?: string}} p
 */
export function nomObjet({ type, checkpointHash }) {
  if (type === "manifeste") return "manifeste";
  if (type === "point") {
    if (!estHex(checkpointHash, 32)) throw new ErreurDepot("objet", "checkpointHash de 32 octets attendu");
    return `point-${checkpointHash.slice(2)}`;
  }
  throw new ErreurDepot("objet", "type d'objet inconnu");
}

/** `period_start` sur dix chiffres (EX-5.14). */
export function nomPeriode(periodStart) {
  if (!Number.isInteger(periodStart) || periodStart < 0 || periodStart > 9999999999) throw new ErreurDepot("periode", "period_start entier sur dix chiffres attendu");
  return `periode-${String(periodStart).padStart(10, "0")}`;
}

function synchroniserRepertoire(repertoire) {
  const fd = fs.openSync(repertoire, "r");
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/** Écrit `octets` dans `chemin` en création exclusive, `fsync` du fichier puis du répertoire. */
function ecrireExclusif(chemin, octets) {
  const fd = fs.openSync(chemin, "wx", 0o644);
  try {
    let ecrit = 0;
    while (ecrit < octets.length) ecrit += fs.writeSync(fd, octets, ecrit, octets.length - ecrit);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  synchroniserRepertoire(path.dirname(chemin));
}

/** Dépôt des preuves `.ots` et du fichier d'en-têtes d'un journal. */
export class DepotOts {
  /**
   * @param {{racine: string, orgId: string, journalId: string}} p
   */
  static ouvrir({ racine, orgId, journalId }) {
    if (typeof racine !== "string" || racine.length === 0) throw new ErreurDepot("racine", "racine de stockage attendue");
    if (!estHex(orgId, 32) || !estHex(journalId, 32)) throw new ErreurDepot("journal", "org_id et journal_id de 32 octets attendus");
    return new DepotOts(racine, orgId, journalId);
  }

  constructor(racine, orgId, journalId) {
    this.racine = racine;
    this.orgId = orgId;
    this.journalId = journalId;
    // CT-2 EX-12.1 : identifiants sans `0x` dans le nom du répertoire du journal (même règle que DepotAncres, lecture F2).
    this.repertoireJournal = path.join(racine, orgId.slice(2), journalId.slice(2), "ancres");
  }

  /** Répertoire `ancres/periode-<period_start>/` d'une période. */
  repertoirePeriode(periodStart) {
    return path.join(this.repertoireJournal, nomPeriode(periodStart));
  }

  /** Versions existantes d'un objet, triées par numéro croissant. */
  versions({ periodStart, objet }) {
    if (!MOTIF_OBJET.test(objet)) throw new ErreurDepot("objet", "nom d'objet refusé");
    const repertoire = path.join(this.repertoirePeriode(periodStart), "ots");
    let noms;
    try {
      noms = fs.readdirSync(repertoire);
    } catch (e) {
      if (e.code === "ENOENT") return [];
      throw e;
    }
    const versions = [];
    for (const nom of noms) {
      const m = MOTIF_VERSION.exec(nom);
      if (m && m[1] === objet) versions.push({ version: Number(m[2]), nom, chemin: path.join(repertoire, nom) });
    }
    return versions.sort((a, b) => a.version - b.version);
  }

  /**
   * Écrit une nouvelle version `<objet>-<n+1>.ots` (EX-6.5) ; la preuve doit
   * être lisible (O-1). Rend le chemin et le numéro de version.
   * @param {{periodStart: number, objet: string, octets: Uint8Array}} p
   */
  ecrire({ periodStart, objet, octets }) {
    if (!MOTIF_OBJET.test(objet)) throw new ErreurDepot("objet", "nom d'objet refusé");
    if (!(octets instanceof Uint8Array) || octets.length === 0 || octets.length > BORNES.TAILLE_FICHIER) throw new ErreurDepot("octets", "preuve vide ou de plus de 256 Kio");
    lireOts(octets); // une preuve illisible n'est jamais écrite
    const repertoire = path.join(this.repertoirePeriode(periodStart), "ots");
    fs.mkdirSync(repertoire, { recursive: true });
    for (let essai = 0; essai < TENTATIVES_EXCLUSIVES; essai += 1) {
      const existantes = this.versions({ periodStart, objet });
      const version = existantes.length === 0 ? 1 : existantes[existantes.length - 1].version + 1;
      const nom = `${objet}-${version}.ots`;
      const chemin = path.join(repertoire, nom);
      try {
        ecrireExclusif(chemin, octets);
        return { chemin, nom, version, fichier: path.posix.join("ots", nom) };
      } catch (e) {
        if (e.code !== "EEXIST") throw e;
      }
    }
    throw new ErreurDepot("concurrence", "création exclusive refusée à répétition");
  }

  /**
   * Dernière version d'un objet (celle que l'exportateur remet), ou null.
   * @param {{periodStart: number, objet: string}} p
   */
  derniere({ periodStart, objet }) {
    const versions = this.versions({ periodStart, objet });
    if (versions.length === 0) return null;
    const d = versions[versions.length - 1];
    const octets = new Uint8Array(fs.readFileSync(d.chemin));
    return { ...d, octets, fichier: path.posix.join("ots", d.nom) };
  }

  /**
   * Écrit `entetes-bitcoin.json` de la période (EX-6.8), création exclusive ;
   * un fichier existant n'est jamais réécrit (`fichier_existant`).
   * @param {{periodStart: number, document: object}} p
   */
  ecrireEntetes({ periodStart, document }) {
    lireFichierEntetes(document);
    const texte = JSON.stringify(document, null, 2) + "\n";
    const octets = utf8(texte);
    if (octets.length > BORNES_ENTETES.TAILLE_FICHIER) throw new ErreurDepot("octets", "fichier d'en-têtes de plus de 64 Mio");
    const repertoire = this.repertoirePeriode(periodStart);
    fs.mkdirSync(repertoire, { recursive: true });
    const chemin = path.join(repertoire, FICHIER_ENTETES);
    try {
      ecrireExclusif(chemin, octets);
    } catch (e) {
      if (e.code === "EEXIST") throw new ErreurDepot("fichier_existant", "entetes-bitcoin.json existe déjà pour cette période");
      throw e;
    }
    return { chemin, fichier: FICHIER_ENTETES, taille: octets.length };
  }

  /** Lit `entetes-bitcoin.json` de la période (document contrôlé), ou null. */
  lireEntetes(periodStart) {
    const chemin = path.join(this.repertoirePeriode(periodStart), FICHIER_ENTETES);
    let octets;
    try {
      octets = new Uint8Array(fs.readFileSync(chemin));
    } catch (e) {
      if (e.code === "ENOENT") return null;
      throw e;
    }
    return { chemin, ...lireFichierEntetes(octets) };
  }
}
