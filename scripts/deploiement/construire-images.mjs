#!/usr/bin/env node
// Construction reproductible des images noortrace/* (CT-8 EX-3.13 ; étape 7). Outil de la personne qui construit, jamais de l'hôte du client.
//
//   node scripts/deploiement/construire-images.mjs [--images <n1,n2,…>] [--version 0.1.0]
//       [--double] [--sortie <répertoire>] [--archive] [--ca <fichier PEM>]
//
// Pour chaque image de conteneurs/<nom>/Dockerfile (contexte : la
// racine du dépôt, filtré par <nom>/Dockerfile.dockerignore) :
//   - vérifie que chaque `FROM` désigne son image par étiquette exacte ET
//     condensé (`<nom>:<étiquette>@sha256:<64 hex>`), ou une étape antérieure ;
//   - construit avec BuildKit (`docker buildx build`, constructeur `default`),
//     `--no-cache`, plate-forme linux/amd64, sans attestation (provenance et
//     SBOM portent des instants), `SOURCE_DATE_EPOCH` = date du commit HEAD
//     (ou la variable d'environnement si elle est posée), exportateur
//     `type=image,rewrite-timestamp=true` : l'heure de l'image et de chaque
//     fichier des couches est ramenée à SOURCE_DATE_EPOCH ;
//   - étiquette le résultat `noortrace/<nom>:<version>` ;
//   - avec --double, construit une seconde fois, sans cache, depuis une copie
//     des fichiers du contexte à un autre chemin (heures de fichiers ramenées au
//     2000-01-01),
//     à un autre instant, sous l'étiquette provisoire
//     `noortrace-reconstruction/<nom>:<version>`, compare les deux condensés
//     de manifeste, puis retire l'étiquette provisoire ;
//   - avec --sortie, écrit <sortie>/condenses.json (condensés, tailles,
//     images de base, SOURCE_DATE_EPOCH, révision) et, avec --archive,
//     <sortie>/noortrace-images-<version>.tar (`docker save` des images
//     étiquetées, pour un banc sans registre : `docker load -i …`).
// Rien n'est poussé vers un registre (aucun `docker push`), aucune étiquette
// git n'est posée.
//
// Réseau : la construction tire les images de base de leur registre public et
// les paquets npm de leur registre (intégrité fixée par package-lock.json) ;
// derrière un mandataire qui réécrit TLS, --ca passe son autorité en secret
// BuildKit, jamais écrit dans une couche.
//
// Codes : 0 construit (et, avec --double, condensés égaux) ; 1 échec de
// construction, épinglage refusé, ou condensés différents ; 2 usage.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

export const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
export const REPERTOIRE_IMAGES = path.join(RACINE, "conteneurs");
/** Images construites, dans l'ordre de construction. */
export const IMAGES = Object.freeze(["enregistreur", "attributs", "approbation", "console", "pont-stdio", "verificateur", "tsa-interne"]);
/** Chemins du dépôt que les contextes de construction emploient (copie de la seconde construction). */
export const CHEMINS_CONTEXTE = Object.freeze(["package.json", "package-lock.json", "paquets", "verificateur", "conteneurs", "LICENSE", "NOTICE"]);
export const VERSION_DEFAUT = "0.1.0";
const RE_FROM_EPINGLE = /^[a-z0-9][a-z0-9._/-]*(?::[0-9]+)?\/?[a-z0-9._/-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}@sha256:[0-9a-f]{64}$/;

/**
 * Lit les lignes `FROM` d'un Dockerfile : `[{ image, etape }]`.
 * @param {string} texte
 */
export function lignesFrom(texte) {
  const r = [];
  for (const ligne of texte.split("\n")) {
    const m = /^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$/i.exec(ligne.trim());
    if (m) r.push({ image: m[1], etape: m[2] ?? null });
  }
  return r;
}

/**
 * Contrôle d'épinglage d'un Dockerfile : chaque FROM est une étape antérieure
 * ou `<nom>:<étiquette exacte>@sha256:<64 hex>` (ni `latest`, ni étiquette
 * seule, ni condensé seul). Rend la liste des refus (vide si conforme).
 */
export function controlerEpinglage(texte) {
  const refus = [];
  const etapes = new Set();
  for (const { image, etape } of lignesFrom(texte)) {
    if (etapes.has(image)) {
      // étape antérieure
    } else if (!RE_FROM_EPINGLE.test(image)) refus.push(`${image} : étiquette exacte et condensé exigés`);
    else if (/:latest@/.test(image)) refus.push(`${image} : étiquette latest refusée`);
    if (etape) etapes.add(etape);
  }
  if (lignesFrom(texte).length === 0) refus.push("aucune ligne FROM");
  if (/^\s*#\s*syntax\s*=/im.test(texte)) refus.push("directive syntax refusée (elle tire une interface de construction d'un registre)");
  return refus;
}

/** SOURCE_DATE_EPOCH : variable d'environnement, sinon date du commit HEAD. */
export function sourceDateEpoch(env = process.env) {
  if (env.SOURCE_DATE_EPOCH !== undefined) {
    if (!/^[0-9]{1,12}$/.test(env.SOURCE_DATE_EPOCH)) throw new Error("SOURCE_DATE_EPOCH : entier de secondes attendu");
    return env.SOURCE_DATE_EPOCH;
  }
  return execFileSync("git", ["-C", RACINE, "log", "-1", "--format=%ct"], { encoding: "utf8" }).trim();
}

/** Révision : commit HEAD, suivi de `-modifie` si l'arbre de travail diffère de HEAD dans les chemins du contexte. */
export function revision() {
  const tete = execFileSync("git", ["-C", RACINE, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const etat = execFileSync("git", ["-C", RACINE, "status", "--porcelain", "--", ...CHEMINS_CONTEXTE], { encoding: "utf8" });
  return etat.trim() === "" ? tete : `${tete}-modifie`;
}

/** Fichiers du contexte (suivis, ou non suivis et non ignorés par git). */
export function fichiersContexte() {
  const sortie = execFileSync("git", ["-C", RACINE, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", ...CHEMINS_CONTEXTE], { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
  return [...new Set(sortie.split("\0").filter(Boolean))].filter((f) => fs.existsSync(path.join(RACINE, f))).sort();
}

/** Heure donnée aux fichiers de la copie : 2000-01-01, antérieure à tout commit. */
const HEURE_COPIE = 946684800;

/**
 * Copie les fichiers du contexte sous `cible`, modes gardés, heures ramenées
 * au 2000-01-01 : la seconde construction voit d'autres heures de fichiers,
 * antérieures au commit, que l'option rewrite-timestamp ne corrigerait pas.
 */
export function copierContexte(cible) {
  for (const f of fichiersContexte()) {
    const src = path.join(RACINE, f);
    const dst = path.join(cible, f);
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    const st = fs.lstatSync(src);
    if (st.isSymbolicLink()) fs.symlinkSync(fs.readlinkSync(src), dst);
    else {
      fs.copyFileSync(src, dst);
      fs.chmodSync(dst, st.mode & 0o7777);
      fs.utimesSync(dst, HEURE_COPIE, HEURE_COPIE);
    }
  }
}

function docker(args, o = {}) {
  const r = spawnSync("docker", args, { encoding: "utf8", maxBuffer: 256 * 1024 * 1024, stdio: o.stdio ?? ["ignore", "pipe", "pipe"], env: { ...process.env, ...(o.env ?? {}) } });
  if (r.error) throw r.error;
  return r;
}

/**
 * Construit une image ; rend son condensé de manifeste.
 * @param {{nom: string, contexte: string, version: string, sde: string, revision: string, etiquette: string, ca?: string|null, journal: string}} o
 */
export function construire(o) {
  const meta = path.join(o.journal, `${o.etiquette.replace(/[/:]/g, "_")}.metadata.json`);
  const args = [
    "buildx", "build", "--builder", "default", "--no-cache", "--platform", "linux/amd64",
    "--provenance=false", "--sbom=false",
    "--build-arg", `SOURCE_DATE_EPOCH=${o.sde}`,
    "--build-arg", `VERSION=${o.version}`,
    "--build-arg", `REVISION=${o.revision}`,
    "--metadata-file", meta,
    "--output", `type=image,name=${o.etiquette},rewrite-timestamp=true,unpack=false`,
    "-f", path.join(o.contexte, "conteneurs", o.nom, "Dockerfile"),
  ];
  if (o.ca) args.push("--secret", `id=ca_bundle,src=${o.ca}`);
  args.push(o.contexte);
  const r = docker(args, { env: { SOURCE_DATE_EPOCH: o.sde, BUILDX_NO_DEFAULT_ATTESTATIONS: "1" } });
  fs.writeFileSync(path.join(o.journal, `${o.etiquette.replace(/[/:]/g, "_")}.log`), `${r.stdout}${r.stderr}`);
  if (r.status !== 0) throw new Error(`construction de ${o.etiquette} en échec (code ${r.status}) ; journal : ${o.journal}\n${r.stderr.split("\n").slice(-15).join("\n")}`);
  const m = JSON.parse(fs.readFileSync(meta, "utf8"));
  const condense = m["containerimage.digest"];
  if (!/^sha256:[0-9a-f]{64}$/.test(condense ?? "")) throw new Error(`condensé illisible pour ${o.etiquette}`);
  return condense;
}

/** Taille de l'image dans le magasin local (`docker image inspect`, `Size`). */
export function tailleImage(reference) {
  const r = docker(["image", "inspect", "--format", "{{.Size}}", reference]);
  return r.status === 0 ? Number(r.stdout.trim()) : null;
}

/** Images de base nommées par les Dockerfiles. */
export function imagesDeBase(noms = IMAGES) {
  const bases = {};
  for (const nom of noms) {
    const texte = fs.readFileSync(path.join(REPERTOIRE_IMAGES, nom, "Dockerfile"), "utf8");
    const etapes = new Set();
    bases[nom] = [];
    for (const { image, etape } of lignesFrom(texte)) {
      if (!etapes.has(image)) bases[nom].push(image);
      if (etape) etapes.add(etape);
    }
  }
  return bases;
}

const USAGE = "usage : construire-images.mjs [--images <n1,n2,…>] [--version <x.y.z>] [--double] [--sortie <répertoire>] [--archive] [--ca <fichier PEM>]";

export async function principal(argv, io = {}) {
  const out = io.stdout ?? process.stdout;
  const err = io.stderr ?? process.stderr;
  let o;
  try {
    o = parseArgs({
      args: argv,
      options: {
        images: { type: "string" },
        version: { type: "string", default: VERSION_DEFAUT },
        double: { type: "boolean", default: false },
        sortie: { type: "string" },
        archive: { type: "boolean", default: false },
        ca: { type: "string" },
      },
      strict: true,
      allowPositionals: false,
    }).values;
  } catch (e) {
    err.write(`${e.message}\n${USAGE}\n`);
    return 2;
  }
  const noms = o.images ? o.images.split(",") : [...IMAGES];
  if (noms.some((n) => !IMAGES.includes(n)) || new Set(noms).size !== noms.length) {
    err.write(`--images : parmi ${IMAGES.join(", ")}, sans répétition\n${USAGE}\n`);
    return 2;
  }
  if (!/^[0-9]+\.[0-9]+\.[0-9]+$/.test(o.version)) {
    err.write(`--version : x.y.z attendu\n${USAGE}\n`);
    return 2;
  }
  if (o.archive && !o.sortie) {
    err.write(`--archive exige --sortie\n${USAGE}\n`);
    return 2;
  }
  if (o.ca && !fs.existsSync(o.ca)) {
    err.write(`--ca : ${o.ca} absent\n`);
    return 2;
  }
  for (const nom of noms) {
    const refus = controlerEpinglage(fs.readFileSync(path.join(REPERTOIRE_IMAGES, nom, "Dockerfile"), "utf8"));
    if (refus.length) {
      err.write(`${nom} : ${refus.join(" ; ")}\n`);
      return 1;
    }
  }
  const sde = sourceDateEpoch();
  const rev = revision();
  const travail = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-images-"));
  const journal = path.join(travail, "journaux");
  fs.mkdirSync(journal);
  err.write(`SOURCE_DATE_EPOCH=${sde} (${new Date(Number(sde) * 1000).toISOString()}), révision ${rev}, journaux sous ${journal}\n`);
  const resultat = { version: 0, images_version: o.version, source_date_epoch: Number(sde), revision: rev, plateforme: "linux/amd64", bases: imagesDeBase(noms), images: {} };
  let code = 0;
  try {
    for (const nom of noms) {
      const etiquette = `noortrace/${nom}:${o.version}`;
      const t0 = Date.now();
      const c1 = construire({ nom, contexte: RACINE, version: o.version, sde, revision: rev, etiquette, ca: o.ca ?? null, journal });
      const entree = { image: `noortrace/${nom}`, tag: o.version, condense: c1, reference: `${etiquette}@${c1}`, octets: tailleImage(etiquette), duree_s: Math.round((Date.now() - t0) / 1000) };
      err.write(`${etiquette} : ${c1} (${entree.duree_s} s)\n`);
      resultat.images[nom] = entree;
    }
    if (o.double) {
      const copie = path.join(travail, "depot-copie");
      copierContexte(copie);
      for (const nom of noms) {
        const etiquette = `noortrace-reconstruction/${nom}:${o.version}`;
        const c2 = construire({ nom, contexte: copie, version: o.version, sde, revision: rev, etiquette, ca: o.ca ?? null, journal });
        const e = resultat.images[nom];
        e.condense_seconde_construction = c2;
        e.egal = c2 === e.condense;
        docker(["image", "rm", etiquette]);
        err.write(`${nom} : seconde construction ${c2} ${e.egal ? "égale" : "DIFFÉRENTE"}\n`);
        if (!e.egal) code = 1;
      }
      fs.rmSync(copie, { recursive: true, force: true });
      resultat.construction_reproductible = Object.values(resultat.images).filter((e) => !e.egal).length;
    }
    if (o.sortie) {
      fs.mkdirSync(o.sortie, { recursive: true });
      if (o.archive) {
        const archive = path.join(o.sortie, `noortrace-images-${o.version}.tar`);
        const r = docker(["save", "--platform", "linux/amd64", "-o", archive, ...noms.map((n) => `noortrace/${n}:${o.version}`)]);
        if (r.status !== 0) throw new Error(`docker save en échec : ${r.stderr}`);
        resultat.archive = { fichier: path.basename(archive), octets: fs.statSync(archive).size };
      }
      fs.writeFileSync(path.join(o.sortie, "condenses.json"), `${JSON.stringify(resultat, null, 2)}\n`);
    }
  } catch (e) {
    err.write(`${e.message}\n`);
    code = 1;
  }
  out.write(`${JSON.stringify(resultat, null, 2)}\n`);
  if (code === 0) fs.rmSync(travail, { recursive: true, force: true });
  return code;
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  principal(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
