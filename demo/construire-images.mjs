#!/usr/bin/env node
// Construction des images de la démonstration de référence (CT-2 §19.1).
// Outil de la personne qui construit ; aucune image n'est poussée vers un
// registre, aucune étiquette git n'est posée.
//
//   npm run compile                                  # hh-artifacts/ : codes de création des contrats (registre-dev)
//   node demo/construire-images.mjs [--images <n1,n2,…>] [--version 0.1.0] [--double]
//       [--sortie <répertoire>] [--ca <fichier PEM>] [--garder-cache]
//
// Même méthode que les images de CT-8 (`scripts/deploiement/construire-images.mjs`,
// dont ce script reprend les fonctions) : chaque `FROM` épinglé par étiquette
// exacte et condensé, magasin d'images containerd exigé, BuildKit sans cache,
// linux/amd64, sans attestation, `SOURCE_DATE_EPOCH` = date du commit HEAD,
// exportateur OCI avec `rewrite-timestamp`, archive chargée sous
// `noortrace/<nom>:<version>` et identifiant comparé au condensé de la
// construction. Les images sont construites une à une.
//
// Ce que ce script ajoute :
//   - avant de construire `registre-dev`, il vérifie que l'image locale du
//     nœud (`noortrace/noorcore:618fcef-noortrace`, au condensé que nomme le
//     fichier de construction) et les cinq fichiers de `hh-artifacts/` sont
//     là ; sinon il le dit et rend 1 sans rien construire de cette image ;
//   - avec --double, la seconde construction part d'une copie du contexte à
//     un autre chemin, comme pour les images de CT-8 ; la copie reçoit en plus
//     la genèse du réseau de développement et les cinq fichiers de
//     `hh-artifacts/`, qui ne sont pas suivis par git ;
//   - après chaque image, les enregistrements du cache de construction créés
//     par la construction sont purgés par identifiant (`docker buildx prune
//     --all --filter id=…` : sans --all, ceux qu'une image chargée partage
//     restent), sauf avec --garder-cache : le cache des autres
//     constructions n'est pas touché.
//
// Codes : 0 construit (et, avec --double, condensés égaux) ; 1 échec,
// préalable absent, épinglage refusé, magasin d'images classique ou Docker
// injoignable, ou condensés différents ; 2 usage.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { RACINE, construire, controlerEpinglage, copierContexte, lignesFrom, magasinImages, revision, sourceDateEpoch, tailleImage } from "../scripts/deploiement/construire-images.mjs";

/** Images de la démonstration, dans l'ordre de construction. */
export const IMAGES_DEMO = Object.freeze(["outils-demo", "modele-demo", "agent-demo", "approbateur-demo", "registre-dev", "verificateur-demo"]);
/** Fichiers de `hh-artifacts/` que le contexte de `registre-dev` emploie. */
export const ARTEFACTS = Object.freeze(["AttestationRegistry", "CuratorSet", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"].map((n) => `hh-artifacts/contracts/${n}.sol/${n}.json`));
const GENESE = "chain/config/alloc-dev.json";
const VERSION_DEFAUT = "0.1.0";

function docker(args) {
  const r = spawnSync("docker", args, { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
  if (r.error) throw r.error;
  return r;
}

const dockerfile = (nom) => fs.readFileSync(path.join(RACINE, "conteneurs", nom, "Dockerfile"), "utf8");

/** Identifiants des enregistrements du cache de construction du constructeur `default`. */
export function identifiantsCache() {
  const r = docker(["buildx", "du", "--builder", "default", "--verbose"]);
  if (r.status !== 0) return new Set();
  return new Set([...r.stdout.matchAll(/^ID:\s+(\S+)$/gm)].map((m) => m[1]));
}

/**
 * Purge les enregistrements du cache absents de `avant` ; rend le nombre de
 * ceux qui ont disparu. `--all` : sans lui, BuildKit garde, sans erreur
 * (« Total: 0B », code 0), un enregistrement partagé avec une image du
 * magasin containerd, c'est-à-dire presque tous ceux d'une construction
 * chargée (constaté avec Docker 29.8.2 : 1,7 Go laissés par les constructions
 * d'une passe) ; le filtre par identifiant borne la purge à cet
 * enregistrement, et le cache des autres constructions n'est pas touché.
 */
export function purgerCacheCree(avant) {
  const crees = [...identifiantsCache()].filter((id) => !avant.has(id));
  // Un enregistrement parent n'est purgé qu'une fois ses enfants partis : quelques passes suffisent.
  for (let passe = 0; passe < 8; passe++) {
    const nouveaux = [...identifiantsCache()].filter((id) => !avant.has(id));
    if (nouveaux.length === 0) break;
    for (const id of nouveaux) docker(["buildx", "prune", "--builder", "default", "--force", "--all", "--filter", `id=${id}`]);
  }
  const restants = identifiantsCache();
  return crees.filter((id) => !restants.has(id)).length;
}

/** Préalables de `registre-dev` absents (liste vide si tout est là). */
export function prealablesRegistreDev() {
  const manques = [];
  const noeud = lignesFrom(dockerfile("registre-dev")).find((l) => l.etape === "noeud")?.image ?? null;
  if (!noeud) manques.push("étape « noeud » absente du fichier de construction");
  else {
    const [reference, condense] = noeud.split("@");
    const r = docker(["image", "inspect", "--format", "{{.Id}}", reference]);
    if (r.status !== 0) manques.push(`image locale ${reference} absente (chain/docker/Dockerfile, avec le correctif de chain/patches/, hors du dépôt)`);
    else if (r.stdout.trim() !== condense) manques.push(`image locale ${reference} au condensé ${r.stdout.trim()}, attendu ${condense}`);
  }
  for (const f of [...ARTEFACTS, GENESE]) if (!fs.existsSync(path.join(RACINE, f))) manques.push(`${f} absent${f.startsWith("hh-artifacts") ? " (npm run compile)" : ""}`);
  return manques;
}

const USAGE = "usage : demo/construire-images.mjs [--images <n1,n2,…>] [--version <x.y.z>] [--double] [--sortie <répertoire>] [--ca <fichier PEM>] [--garder-cache]";

export async function principal(argv, io = {}) {
  const out = io.stdout ?? process.stdout;
  const err = io.stderr ?? process.stderr;
  let o;
  try {
    o = parseArgs({
      args: argv,
      options: { images: { type: "string" }, version: { type: "string", default: VERSION_DEFAUT }, double: { type: "boolean", default: false }, sortie: { type: "string" }, ca: { type: "string" }, "garder-cache": { type: "boolean", default: false } },
      strict: true,
      allowPositionals: false,
    }).values;
  } catch (e) {
    err.write(`${e.message}\n${USAGE}\n`);
    return 2;
  }
  const noms = o.images ? o.images.split(",") : [...IMAGES_DEMO];
  if (noms.some((n) => !IMAGES_DEMO.includes(n)) || new Set(noms).size !== noms.length) {
    err.write(`--images : parmi ${IMAGES_DEMO.join(", ")}, sans répétition\n${USAGE}\n`);
    return 2;
  }
  if (!/^[0-9]+\.[0-9]+\.[0-9]+$/.test(o.version)) {
    err.write(`--version : x.y.z attendu\n${USAGE}\n`);
    return 2;
  }
  if (o.ca && !fs.existsSync(o.ca)) {
    err.write(`--ca : ${o.ca} absent\n`);
    return 2;
  }
  for (const nom of noms) {
    const refus = controlerEpinglage(dockerfile(nom));
    if (refus.length) {
      err.write(`${nom} : ${refus.join(" ; ")}\n`);
      return 1;
    }
  }
  const magasin = magasinImages();
  if (magasin !== "containerd") {
    err.write(magasin === null ? "docker info en échec : Docker absent ou démon dockerd injoignable\n" : `magasin d'images ${magasin} : refusé (voir scripts/deploiement/construire-images.mjs)\n`);
    return 1;
  }
  if (noms.includes("registre-dev")) {
    const manques = prealablesRegistreDev();
    if (manques.length) {
      err.write(`registre-dev : préalable absent : ${manques.join(" ; ")}\n`);
      return 1;
    }
  }
  const sde = sourceDateEpoch();
  const rev = revision();
  const travail = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-images-demo-"));
  const journal = path.join(travail, "journaux");
  fs.mkdirSync(journal);
  err.write(`SOURCE_DATE_EPOCH=${sde} (${new Date(Number(sde) * 1000).toISOString()}), révision ${rev}, magasin d'images ${magasin}, journaux sous ${journal}\n`);
  const resultat = { version: 0, images_version: o.version, source_date_epoch: Number(sde), revision: rev, plateforme: "linux/amd64", magasin_images: magasin, images: {} };
  let code = 0;
  let copie = null;
  try {
    if (o.double) {
      copie = path.join(travail, "depot-copie");
      copierContexte(copie);
      for (const f of [...ARTEFACTS, GENESE]) {
        if (!fs.existsSync(path.join(RACINE, f))) continue;
        fs.mkdirSync(path.dirname(path.join(copie, f)), { recursive: true });
        fs.copyFileSync(path.join(RACINE, f), path.join(copie, f));
        fs.utimesSync(path.join(copie, f), 946684800, 946684800);
      }
    }
    for (const nom of noms) {
      const etiquette = `noortrace/${nom}:${o.version}`;
      const avant = o["garder-cache"] ? null : identifiantsCache();
      const t0 = Date.now();
      const c1 = construire({ nom, contexte: RACINE, version: o.version, sde, revision: rev, etiquette, ca: o.ca ?? null, journal, charger: true });
      const entree = { image: `noortrace/${nom}`, tag: o.version, condense: c1, reference: `${etiquette}@${c1}`, octets: tailleImage(etiquette), duree_s: Math.round((Date.now() - t0) / 1000) };
      err.write(`${etiquette} : ${c1} (${entree.duree_s} s)\n`);
      if (o.double) {
        const c2 = construire({ nom, contexte: copie, version: o.version, sde, revision: rev, etiquette: `noortrace-reconstruction/${nom}:${o.version}`, ca: o.ca ?? null, journal, charger: false });
        entree.condense_seconde_construction = c2;
        entree.egal = c2 === c1;
        err.write(`${nom} : seconde construction ${c2} ${entree.egal ? "égale" : "DIFFÉRENTE"}\n`);
        if (!entree.egal) code = 1;
      }
      if (avant) {
        entree.cache_purge = purgerCacheCree(avant);
        err.write(`${nom} : ${entree.cache_purge} enregistrement(s) du cache de construction purgé(s)\n`);
      }
      resultat.images[nom] = entree;
    }
    if (o.sortie) {
      fs.mkdirSync(o.sortie, { recursive: true });
      fs.writeFileSync(path.join(o.sortie, "condenses-demo.json"), `${JSON.stringify(resultat, null, 2)}\n`);
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
