// Données de l'agent (INTERFACES.md 3.6) : répertoire du compte de l'agent,
// groupe de l'interface, mode 0750 ; journaux en ajout seul
// (`journal-agent.ndjson`, `confirmations.ndjson`, `notes-internes.ndjson`), état des travaux
// (`travaux/<id>.json`, réécrit par renommage), et, par client, le dossier,
// les captures, les demandes, les sorties, les parties et le paquet.
//
// Écritures : un document se réécrit par fichier temporaire, `fsync`,
// renommage et `fsync` du répertoire (EX-7.16, EX-7.24) ; un journal en ajout
// seul s'écrit par `O_APPEND` puis `fsync`. Les fichiers sont créés en 0640 et
// les répertoires en 0750 ; le groupe vient du bit setgid du répertoire des
// données (LISEZMOI.md, « Déploiement »). Aucun fichier de clé, de graine ni
// de jeton n'est jamais écrit ici.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

export const MODE_FICHIER = 0o640;
export const MODE_REPERTOIRE = 0o750;

/** `fsync` d'un répertoire (sans effet sur un système qui le refuse). */
export function synchroniser(repertoire) {
  let fd;
  try {
    fd = fs.openSync(repertoire, "r");
    fs.fsyncSync(fd);
  } catch {
    // Certains systèmes de fichiers refusent fsync sur un répertoire.
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/** Crée un répertoire (et ses parents) en 0750. */
export function creerRepertoire(repertoire) {
  fs.mkdirSync(repertoire, { recursive: true, mode: MODE_REPERTOIRE });
}

/** Réécrit un fichier par fichier temporaire, `fsync` et renommage. */
export function ecrireAtomique(chemin, octets) {
  const dir = path.dirname(chemin);
  creerRepertoire(dir);
  const temp = path.join(dir, `.${path.basename(chemin)}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`);
  const fd = fs.openSync(temp, "wx", MODE_FICHIER);
  try {
    fs.writeFileSync(fd, octets);
    fs.fchmodSync(fd, MODE_FICHIER);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(temp, chemin);
  synchroniser(dir);
}

/** Écrit un fichier qui ne doit pas exister ; rend false s'il existait. */
export function ecrireNouveau(chemin, octets) {
  creerRepertoire(path.dirname(chemin));
  let fd;
  try {
    fd = fs.openSync(chemin, "wx", MODE_FICHIER);
  } catch (e) {
    if (e && e.code === "EEXIST") return false;
    throw e;
  }
  try {
    fs.writeFileSync(fd, octets);
    fs.fchmodSync(fd, MODE_FICHIER);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  synchroniser(path.dirname(chemin));
  return true;
}

/** Taille du journal de l'agent au-delà de laquelle il est tourné (revue de l'étape 8) : 16 Mio. */
export const JOURNAL_MAX_OCTETS = 16 * 1024 * 1024;

/**
 * Ajoute une ligne JSON à un journal en ajout seul, puis `fsync`. Avec
 * `tailleMax`, le journal est borné : quand il atteint cette taille, il est
 * renommé en `<chemin>.1` (la génération précédente est remplacée) et un
 * journal neuf commence ; le total tenu par un journal borné est donc d'au
 * plus deux fois `tailleMax` et une ligne. Sans `tailleMax` (registre des
 * confirmations, registre des notes), le journal n'est jamais tourné.
 */
export function ajouterLigne(chemin, objet, { tailleMax = null } = {}) {
  creerRepertoire(path.dirname(chemin));
  const ligne = Buffer.from(JSON.stringify(objet) + "\n", "utf8");
  if (tailleMax !== null) {
    let taille = 0;
    try {
      taille = fs.statSync(chemin).size;
    } catch {
      taille = 0;
    }
    if (taille > 0 && taille + ligne.length > tailleMax) {
      fs.renameSync(chemin, `${chemin}.1`);
      synchroniser(path.dirname(chemin));
    }
  }
  const fd = fs.openSync(chemin, "a", MODE_FICHIER);
  try {
    fs.writeSync(fd, ligne);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/** Sérialisation des documents de l'agent : `JSON.stringify(objet, null, 2)` et un saut de ligne. */
export const serialiser = (objet) => Buffer.from(JSON.stringify(objet, null, 2) + "\n", "utf8");

/** Chemins des données d'un agent. */
export function chemins(donnees) {
  const client = (slug) => {
    const dir = path.join(donnees, "clients", slug);
    return {
      dir,
      dossier: path.join(dir, "dossier.json"),
      captures: path.join(dir, "captures"),
      demandes: path.join(dir, "demandes"),
      sorties: path.join(dir, "sorties"),
      parties: path.join(dir, "parties"),
      paquets: path.join(dir, "paquets"),
      lectureJeu: path.join(dir, "lecture-jeu.json"),
    };
  };
  return {
    racine: donnees,
    journal: path.join(donnees, "journal-agent.ndjson"),
    confirmations: path.join(donnees, "confirmations.ndjson"),
    // Notes internes (CT-4 EX-7.23, complément du 2026-11-19) : nom interne et remise du paquet, en ajout seul, hors
    // du répertoire des clients, que le paquet et les parties ne lisent pas.
    notes: path.join(donnees, "notes-internes.ndjson"),
    travaux: path.join(donnees, "travaux"),
    travail: (id) => path.join(donnees, "travaux", `${id}.json`),
    clients: path.join(donnees, "clients"),
    client,
  };
}

/** Lit les lignes JSON d'un journal en ajout seul ; une dernière ligne tronquée est ignorée. */
export function lireLignes(chemin) {
  let texte;
  try {
    texte = fs.readFileSync(chemin, "utf8");
  } catch {
    return [];
  }
  const lignes = [];
  for (const l of texte.split("\n")) {
    if (!l) continue;
    try {
      lignes.push(JSON.parse(l));
    } catch {
      // ligne tronquée par un arrêt brutal : ignorée
    }
  }
  return lignes;
}
