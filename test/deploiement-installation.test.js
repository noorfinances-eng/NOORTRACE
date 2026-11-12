// Installation et exploitation outillées (étape 7 ; CT-8 IC-2, EX-8.6
// TP-1 à TP-8, EX-11.2 à EX-11.4, EX-11.22, EX-11.23, §10.12 à §10.19 ;
// écarts E-6 et E-9 de l'inventaire de l'étape 7) :
//
// - IC-2 : `deploiement/hote/preparer-hote.sh` sur le système de référence
//   de CT-9 EX-11.1 (Ubuntu 24.04, x86_64), rejoué avec des commandes
//   système simulées (paquets, services, horloge, moteur) : idempotence,
//   refus d'une archive de Node.js au mauvais SHA-256, refus d'un autre
//   système ; l'installation réelle des paquets (flux FL-31, réseau public)
//   est en attente, sa condition dans le titre ;
// - TP-1 à TP-8 et la sauvegarde : gabarits systemd posés par
//   `poser-taches.sh`, vérifiés hors ligne par `systemd-analyze verify` et
//   `systemd-analyze calendar` ; `executer-tache.sh` consigne une ligne
//   horodatée avec le code de sortie de chaque exécution ;
// - TP-6 : `archiver-journal-exploitation.mjs` sur des fichiers tournés par
//   le journal d'exploitation réel de l'enregistreur ;
// - sauvegarde (13.4, EX-11.2 à EX-11.4) : `sauvegarde.mjs` (archive,
//   procès-verbal `sauvegarde` vérifié par `proces-verbal.mjs`, en boîte
//   noire), forme de l'archive, recette GNU tar d'EX-13.15, refus ;
// - TE-9, chemin A de 11.4 : démon réel, sauvegarde, destruction, extraction,
//   époque du bail recréée (pas 6), reprise, dossier qui chevauche la reprise
//   vérifié par le vérificateur de référence (boîte noire) ; durées relevées
//   hors système de référence (TM-37 : publiées, jamais comptées) ;
// - E-6 : l'installation rapide ancre : configuration, rapide.yaml, document
//   ancrage-v0 (principal = serveur RFC 3161 interne, hors production, CT-5
//   révision 0.9), et démon réel qui obtient le jeton de clôture du serveur
//   interne de paquets/ancrage et la preuve OpenTimestamps du manifeste
//   auprès de calendriers factices (TLS, 127.0.0.1) ;
// - E-9 : validation d'ancrage-v0 par un outil du dépôt, sans réseau ;
// - copies dérivées des runbooks égales aux blocs de CT-8, dans
//   l'archive de déploiement.
//
// Aucun essai ne joint un réseau public. Tout fichier va sous NOORTRACE_TMP
// (ou os.tmpdir()), jamais dans le dépôt.

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { JournalExploitation } from "@noortrace/enregistreur";
import * as D from "../scripts/lib/deploiement.mjs";
import * as S from "../scripts/lib/sauvegarde.mjs";
import { configurationRapide, controlerAncrageRapide, ancrageRapide } from "../scripts/deploiement/configurer-rapide.mjs";
import { initialiserAutorite, chargerAutorite, demarrerServeur, publierCrl, FICHIERS_AUTORITE } from "@noortrace/ancrage/serveur-interne";
import { blocsRunbooks, copiesRunbooks, ecartsRunbooks, provenance } from "../scripts/deploiement/extraire-runbooks.mjs";
import { archiver, relireSerie } from "../scripts/deploiement/archiver-journal-exploitation.mjs";
import { configurationDev, graine } from "./fixtures/enregistreur-coeur/outils.mjs";
import { construireJournal, DemonEssai, attendre } from "./fixtures/enregistreur-export/outils.mjs";
import { calendriersTls, enAttente } from "./fixtures/enregistreur-ancrage/outils.mjs";
import { materielTls } from "./fixtures/ancrage-composant/outils.mjs";

const RACINE = D.RACINE;
const DEP = path.join(RACINE, "deploiement");
const OUTILS = path.join(RACINE, "scripts", "deploiement");
const CT8 = fs.readFileSync(path.join(RACINE, "spec", "CT-8-deploiement-et-exploitation.md"), "utf8");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const sha = (o) => crypto.createHash("sha256").update(o).digest("hex");
const lireJSON = (f) => JSON.parse(fs.readFileSync(f, "utf8"));

function outil(nom, args, o = {}) {
  return spawnSync(process.execPath, [path.join(OUTILS, nom), ...args], { encoding: "utf8", cwd: o.cwd ?? RACINE, env: o.env ?? process.env, maxBuffer: 64 * 1024 * 1024 });
}

function bash(script, args, o = {}) {
  return spawnSync("/bin/bash", [script, ...args], { encoding: "utf8", cwd: o.cwd ?? RACINE, env: o.env ?? process.env });
}

const commande = (c) => spawnSync("/bin/sh", ["-c", `command -v ${c}`], { encoding: "utf8" }).status === 0;

/** Fichier de clés (cles.json de CT-1) de la clé d'essai rec-test-01 des outils du cœur. */
function clesEssai(chemin, org, journal) {
  const cles = { version: 0, org_id: org, journal_id: journal, keys: [{ key_id: "rec-test-01", algorithm: "ed25519", public_key: N.octetsVersHex(N.clePubliqueEd25519(graine("rec-test-01"))), valid_from: "2026-01-01T00:00:00.000Z", valid_to: null, source: "clé d'essai rec-test-01 des outils du cœur, sans valeur hors des tests" }] };
  fs.writeFileSync(chemin, JSON.stringify(cles, null, 2) + "\n");
  return chemin;
}

/** Copie d'un journal des vecteurs de CT-8 sans ses fichiers d'essai (attendu.json, cles.json). */
function copieJournalVecteur(nom, vers) {
  const src = path.join(RACINE, "spec", "vecteurs", "ct-8", "journaux", nom);
  fs.cpSync(src, vers, { recursive: true });
  for (const f of ["attendu.json", "cles.json"]) fs.rmSync(path.join(vers, f), { force: true });
  return { racine: vers, cles: path.join(src, "cles.json") };
}

let TRAVAIL;
before(function () {
  TRAVAIL = fs.mkdtempSync(path.join(TMP, "noortrace-lot-d-"));
});
after(function () {
  if (TRAVAIL) fs.rmSync(TRAVAIL, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// IC-2
// ---------------------------------------------------------------------------

const PREPARER = path.join(DEP, "hote", "preparer-hote.sh");

/**
 * Commandes système simulées (dpkg-query, apt-get, systemctl, chronyc, docker,
 * id, usermod, findmnt, node) sous `rep/bin`, état sous `rep/etat`, appels
 * consignés dans `rep/appels`. `node` : version rendue, ou null (absent).
 */
function hoteSimule(rep, { node = "v22.23.4", installes = [], actifs = [], uid = 0, fs: typeFs = "ext4", groupes = "exploitant" } = {}) {
  const bin = path.join(rep, "bin");
  const etat = path.join(rep, "etat");
  fs.mkdirSync(bin, { recursive: true });
  fs.mkdirSync(path.join(etat, "paquets"), { recursive: true });
  fs.mkdirSync(path.join(etat, "services"), { recursive: true });
  for (const p of installes) fs.writeFileSync(path.join(etat, "paquets", p), "");
  for (const s of actifs) fs.writeFileSync(path.join(etat, "services", s), "");
  fs.writeFileSync(path.join(etat, "groupes"), groupes);
  const appels = path.join(rep, "appels");
  const ecrire = (nom, corps) => fs.writeFileSync(path.join(bin, nom), `#!/bin/bash\necho "${nom} $*" >> "${appels}"\n${corps}\n`, { mode: 0o755 });
  ecrire("dpkg-query", `p="\${@: -1}"; if [ "$1" = "-W" ] && [ "$2" = "-f=\\\${db:Status-Status}" ]; then [ -e "${etat}/paquets/$p" ] && printf installed; exit 0; fi; for q in "\${@:3}"; do echo "$q 1.0-simule"; done`);
  ecrire("apt-get", `if [ "$1" = update ]; then exit 0; fi; for a in "$@"; do case "$a" in -*|install) ;; *) : > "${etat}/paquets/$a" ;; esac; done`);
  ecrire("systemctl", `case "$1" in is-enabled|is-active) [ -e "${etat}/services/\${@: -1}" ] ;; enable) : > "${etat}/services/\${@: -1}" ;; *) exit 0 ;; esac`);
  ecrire("chronyc", `if [ "$1" = "-c" ]; then echo "C0A80001,ntp.simule,3,1700000000.0,0.000001,0.000001,0.000001,-1.0,0.0,0.01,0.001,0.001,64.0,Normal"; else echo "Leap status     : Normal"; fi`);
  ecrire("docker", `echo "docker simulé $*"`);
  ecrire("id", `if [ "$1" = "-u" ]; then echo ${uid}; elif [ "$1" = "-nG" ]; then cat "${etat}/groupes"; else exit 0; fi`);
  ecrire("usermod", `echo " docker" >> "${etat}/groupes"`);
  ecrire("findmnt", `echo ${typeFs}`);
  if (node) ecrire("node", `echo ${node}`);
  const osRelease = path.join(rep, "os-release");
  fs.writeFileSync(osRelease, 'NAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n');
  // PATH : commandes simulées d'abord, puis le système pour sed, awk, tar, sha256sum… ; un `node` réel n'est pas visible.
  const sysbin = path.join(rep, "sysbin");
  fs.mkdirSync(sysbin, { recursive: true });
  for (const c of ["bash", "sed", "awk", "tr", "cut", "grep", "sha256sum", "tar", "xz", "install", "ln", "uname", "cat", "printf", "date", "dirname", "mkdir", "rm", "env", "sh"]) {
    const r = spawnSync("/bin/sh", ["-c", `command -v ${c}`], { encoding: "utf8" });
    if (r.status === 0 && r.stdout.trim().startsWith("/")) fs.symlinkSync(r.stdout.trim(), path.join(sysbin, c));
  }
  return { bin, etat, appels, osRelease, env: { PATH: `${bin}:${sysbin}`, LC_ALL: "C" }, lireAppels: () => (fs.existsSync(appels) ? fs.readFileSync(appels, "utf8").split("\n").filter(Boolean) : []) };
}

describe("CT-8 IC-2 : préparation de l'hôte (deploiement/hote/preparer-hote.sh, système de référence Ubuntu 24.04)", function () {
  this.timeout(60000);

  it("TE-7 (IC-2) : syntaxe, usage (code 2), système non pris en charge (code 3) ; aucune adresse ni domaine hors des plages réservées ; SHA-256 de Node.js 22.23.4 épinglé (même version que la base des images et que le travail de version)", function () {
    expect(spawnSync("/bin/bash", ["-n", PREPARER]).status).to.equal(0);
    const t = fs.readFileSync(PREPARER, "utf8");
    expect((t.match(/[a-z][a-z0-9-]*\.(org|com|net|io|dev|example|invalid)\b/gi) ?? []).filter((d) => d !== "docker.io"), "domaine").to.deep.equal([]);
    expect(t).to.not.match(/https?:\/\//);
    expect(t.match(/(?<![0-9.])[0-9]{1,3}(\.[0-9]{1,3}){3}(?![0-9.])/g), "adresse IPv4").to.equal(null);
    expect(t).to.include('readonly VERSION_NODE="v22.23.4"');
    expect(t).to.include('SHA256_NODE="1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce"');
    // Version unique (étape 7) : celle des images (conteneurs/*/Dockerfile) et du travail de version.
    for (const nom of ["enregistreur", "attributs", "approbation", "console", "pont-stdio"]) {
      expect(fs.readFileSync(path.join(RACINE, "conteneurs", nom, "Dockerfile"), "utf8"), nom).to.match(/^FROM node:22\.23\.4-bookworm-slim@sha256:[0-9a-f]{64} AS /m);
    }
    expect(fs.readFileSync(path.join(RACINE, ".github", "workflows", "version.yml"), "utf8")).to.include("22.23.4");
    const h = hoteSimule(path.join(TRAVAIL, "ic2-usage"));
    const u = bash(PREPARER, ["--inconnue"], { env: h.env });
    expect(u.status).to.equal(2);
    expect(u.stderr).to.match(/^Erreur : option inconnue : --inconnue\nUsage : /);
    expect(bash(PREPARER, ["--declaration-cache", "x", "--os-release", h.osRelease], { env: h.env }).status).to.equal(2);
    const nonRoot = hoteSimule(path.join(TRAVAIL, "ic2-non-root"), { uid: 1000 });
    const nr = bash(PREPARER, ["--os-release", nonRoot.osRelease], { env: nonRoot.env });
    expect(nr.status).to.equal(2);
    expect(nr.stderr).to.include("sudo");
    const debian = path.join(TRAVAIL, "os-debian");
    fs.writeFileSync(debian, 'ID=debian\nVERSION_ID="12"\n');
    const d = bash(PREPARER, ["--os-release", debian], { env: h.env });
    expect(d.status).to.equal(3);
    expect(d.stdout).to.include("non pris en charge : debian 12");
    expect(h.lireAppels().filter((l) => /^(apt-get|systemctl enable|usermod)/.test(l))).to.deep.equal([]);
  });

  it("TE-7 (IC-2) : hôte simulé vierge : simulation (code 4, aucune action), puis installation (code 0, sorties de vérification au procès-verbal), puis second passage idempotent (aucune action, même résultat)", function () {
    const h = hoteSimule(path.join(TRAVAIL, "ic2-vierge"), { installes: ["curl", "openssl", "ca-certificates", "xz-utils"] });
    const pv = path.join(TRAVAIL, "ic2-vierge", "pv");
    fs.mkdirSync(pv);
    const stockage = path.join(TRAVAIL, "ic2-vierge", "stockage");
    fs.mkdirSync(stockage);
    // --prefixe propre à l'essai : sans lui, la vérification lisait le node réel de /usr/local/bin de la machine d'essai.
    const args = ["--os-release", h.osRelease, "--prefixe", path.join(TRAVAIL, "ic2-vierge", "prefixe"), "--utilisateur", "exploitant", "--stockage", stockage, "--declaration-cache", "cache protégé par batterie, fiche du contrôleur", "--pv", pv];
    const sim = bash(PREPARER, ["--simulation", ...args], { env: h.env });
    expect(sim.status, sim.stdout + sim.stderr).to.equal(4);
    expect(sim.stdout).to.include("à faire : apt-get install docker.io docker-compose-v2 chrony");
    expect(h.lireAppels().filter((l) => /^(apt-get|systemctl enable|usermod)/.test(l))).to.deep.equal([]);
    const r1 = bash(PREPARER, args, { env: h.env });
    expect(r1.status, r1.stdout + r1.stderr).to.equal(0);
    const appels1 = h.lireAppels();
    expect(appels1).to.include("apt-get install -y -q --no-install-recommends docker.io docker-compose-v2 chrony");
    expect(appels1).to.include.members(["systemctl enable --now docker", "systemctl enable --now chrony", "usermod -aG docker exploitant"]);
    expect(fs.readdirSync(pv).sort()).to.deep.equal(["IC-2-chronyc-tracking.txt", "IC-2-docker-compose-version.txt", "IC-2-docker-version.txt", "IC-2-node-version.txt", "IC-2-paquets.txt", "IC-2-stockage.txt"]);
    expect(fs.readFileSync(path.join(pv, "IC-2-node-version.txt"), "utf8")).to.equal("v22.23.4\n");
    expect(fs.readFileSync(path.join(pv, "IC-2-stockage.txt"), "utf8")).to.include("cache protégé par batterie");
    expect(r1.stdout).to.match(/IC-2 bilan +hôte prêt/);
    fs.rmSync(h.appels);
    const r2 = bash(PREPARER, args, { env: h.env });
    expect(r2.status, r2.stdout + r2.stderr).to.equal(0);
    expect(h.lireAppels().filter((l) => /^(apt-get|systemctl enable|usermod)/.test(l)), "second passage").to.deep.equal([]);
    expect(r2.stdout.split("\n").filter((l) => /^IC-2 (paquets|services|node|groupe)/.test(l)).every((l) => l.includes("déjà fait"))).to.equal(true);
    const sim2 = bash(PREPARER, ["--simulation", ...args], { env: h.env });
    expect(sim2.status).to.equal(0);
  });

  it("TE-7 (IC-2) : Node.js absent : archive au mauvais SHA-256 refusée (code 1, rien d'installé) ; stockage NFS refusé (CT-2 EX-12.2)", function () {
    const h = hoteSimule(path.join(TRAVAIL, "ic2-node"), { node: null, installes: ["docker.io", "docker-compose-v2", "chrony", "curl", "openssl", "ca-certificates", "xz-utils"], actifs: ["docker", "chrony"] });
    const prefixe = path.join(TRAVAIL, "ic2-node", "prefixe");
    const faux = path.join(TRAVAIL, "ic2-node", "node-v22.23.4-linux-x64.tar.xz");
    fs.writeFileSync(faux, "pas une archive de Node.js");
    const sans = bash(PREPARER, ["--os-release", h.osRelease, "--prefixe", prefixe], { env: h.env });
    expect(sans.status).to.equal(1);
    expect(sans.stdout).to.include("Node.js 22 absent");
    const r = bash(PREPARER, ["--os-release", h.osRelease, "--prefixe", prefixe, "--archive-node", faux], { env: h.env });
    expect(r.status).to.equal(1);
    expect(r.stdout).to.include("archive refusée, rien n'est installé");
    expect(fs.existsSync(prefixe)).to.equal(false);
    const nfs = hoteSimule(path.join(TRAVAIL, "ic2-nfs"), { fs: "nfs4", installes: ["docker.io", "docker-compose-v2", "chrony", "curl", "openssl", "ca-certificates", "xz-utils"], actifs: ["docker", "chrony"] });
    const st = path.join(TRAVAIL, "ic2-nfs", "stockage");
    fs.mkdirSync(st);
    // --prefixe propre à l'essai : sans lui, la vérification lit $prefixe/bin/node de la machine
    // d'essai (/usr/local/bin/node : Node.js 20 sur l'exécuteur ubuntu-24.04 de la CI), échoue
    // à l'étape node et n'atteint jamais l'étape stockage.
    const n = bash(PREPARER, ["--os-release", nfs.osRelease, "--prefixe", path.join(TRAVAIL, "ic2-nfs", "prefixe"), "--stockage", st], { env: nfs.env });
    expect(n.status, n.stdout + n.stderr).to.equal(1);
    expect(n.stdout).to.match(/^IC-2 node +déjà fait \(v22\.23\.4\)$/m);
    expect(n.stdout).to.match(/^IC-2 stockage +échec : .* sur nfs4 : ext4, xfs ou btrfs exigé, jamais NFS ni SMB \(CT-2 EX-12\.2\)$/m);
  });

  it("TE-7 (IC-2) : l'archive officielle node-v22.23.4-linux-x64.tar.xz (NOORTRACE_ARCHIVE_NODE) a le SHA-256 épinglé : installée sur l'hôte simulé sans Node.js (code 0), node --version = v22.23.4 au procès-verbal, LICENSE de Node.js dans l'arbre extrait", function () {
    const archive = process.env.NOORTRACE_ARCHIVE_NODE;
    if (!archive || !fs.existsSync(archive)) {
      enAttente(this, "archive officielle node-v22.23.4-linux-x64.tar.xz absente (NOORTRACE_ARCHIVE_NODE)");
      return;
    }
    const h = hoteSimule(path.join(TRAVAIL, "ic2-archive"), { node: null, installes: ["docker.io", "docker-compose-v2", "chrony", "curl", "openssl", "ca-certificates", "xz-utils"], actifs: ["docker", "chrony"] });
    const prefixe = path.join(TRAVAIL, "ic2-archive", "prefixe");
    const pv = path.join(TRAVAIL, "ic2-archive", "pv");
    fs.mkdirSync(pv);
    const r = bash(PREPARER, ["--os-release", h.osRelease, "--prefixe", prefixe, "--archive-node", archive, "--pv", pv], { env: h.env });
    expect(r.status, r.stdout + r.stderr).to.equal(0);
    expect(r.stdout).to.match(/IC-2 node +fait \(v22\.23\.4\)/);
    expect(fs.readFileSync(path.join(pv, "IC-2-node-version.txt"), "utf8")).to.equal("v22.23.4\n");
    expect(fs.readFileSync(path.join(prefixe, "lib", "nodejs", "node-v22.23.4-linux-x64", "LICENSE"), "utf8")).to.match(/^Node\.js is licensed for use as follows:/);
  });

  it("TE-7 (IC-2) : installation réelle sur une machine vierge du système de référence", function () {
    if (process.env.NOORTRACE_ESSAI_HOTE_VIERGE !== "1") {
      enAttente(this, "machine vierge Ubuntu 24.04 avec ses sources de paquets (flux FL-31, réseau public) et l'archive node-v22.23.4-linux-x64.tar.xz ; NOORTRACE_ESSAI_HOTE_VIERGE=1 et NOORTRACE_ARCHIVE_NODE");
      return;
    }
    const r = spawnSync("sudo", ["bash", PREPARER, "--archive-node", process.env.NOORTRACE_ARCHIVE_NODE], { encoding: "utf8" });
    expect(r.status, r.stdout + r.stderr).to.equal(0);
    const r2 = spawnSync("sudo", ["bash", PREPARER, "--archive-node", process.env.NOORTRACE_ARCHIVE_NODE], { encoding: "utf8" });
    expect(r2.status).to.equal(0);
    expect(r2.stdout).to.not.match(/IC-2 \S+ +fait/);
  });
});

// ---------------------------------------------------------------------------
// TP-1 à TP-8
// ---------------------------------------------------------------------------

const TACHES = path.join(DEP, "taches");
const CADENCES = {
  "noortrace-tp1.timer": ["TP-1", "*-*-* *:05:00"],
  "noortrace-tp2.timer": ["TP-2", "*-*-* 04:20:00"],
  "noortrace-tp3.timer": ["TP-3", "*-*-* 03:40:00"],
  "noortrace-tp4.timer": ["TP-4", "*-*-* 05:10:00"],
  "noortrace-tp5.timer": ["TP-5", "*-*-* 05:40:00"],
  "noortrace-tp6.timer": ["TP-6", "*-*-* *:00/15:00"],
  "noortrace-tp7.timer": ["TP-7", "*-01-15 09:00:00"],
  "noortrace-tp8.timer": ["TP-8", "*-*-01 06:30:00"],
  "noortrace-sauvegarde.timer": ["SAUVEGARDE", "*-*-* 01:30:00"],
};

/**
 * `systemd-analyze verify` des unités de `rep` (service gabarit instancié pour chaque tâche, et
 * minuteurs), avec --recursive-errors=no : code de sortie, sortie d'erreur, et lignes qui citent
 * l'un de nos fichiers (chemin sous `rep`) ou l'une de nos unités (`notres`).
 */
function verifierUnites(rep, env = {}) {
  const unitesNommees = [...Object.values(CADENCES).map(([id]) => `noortrace-tache@${id}.service`), ...Object.keys(CADENCES)];
  const v = spawnSync("systemd-analyze", ["verify", "--man=no", "--recursive-errors=no", ...unitesNommees], { encoding: "utf8", cwd: rep, env: { ...process.env, ...env } });
  const notres = v.stderr.split("\n").filter((l) => l.includes(`${rep}/`) || /noortrace-(tache@[A-Za-z0-9-]*\.service|tp[1-8]\.timer|sauvegarde\.timer)/.test(l));
  return { status: v.status, stderr: v.stderr, notres };
}

describe("CT-8 EX-8.6 : tâches planifiées TP-1 à TP-8 et sauvegarde (gabarits systemd de deploiement/taches/)", function () {
  this.timeout(120000);

  it("TE-7 (TP-1 à TP-8) : poser-taches.sh écrit le service gabarit et un minuteur par tâche ; systemd-analyze verify accepte chaque unité ; chaque cadence est celle d'EX-8.6 ; second passage identique, réglages jamais remplacés", function () {
    const rep = path.join(TRAVAIL, "taches-pose");
    const unites = path.join(rep, "unites");
    const env = path.join(rep, "taches.env");
    const tout = Object.values(CADENCES).map(([t]) => t).join(",");
    const r = bash(path.join(TACHES, "poser-taches.sh"), ["--racine", RACINE, "--taches", tout, "--sortie", unites, "--environnement", env, "--sans-activation"]);
    expect(r.status, r.stderr).to.equal(0);
    expect(fs.readdirSync(unites).sort()).to.deep.equal(["noortrace-tache@.service", ...Object.keys(CADENCES)].sort());
    expect(fs.statSync(env).mode & 0o777).to.equal(0o600);
    expect(fs.readFileSync(env, "utf8")).to.include(`NOORTRACE_RACINE=${RACINE}\n`);
    const service = fs.readFileSync(path.join(unites, "noortrace-tache@.service"), "utf8");
    expect(service).to.include(`ExecStart=/bin/bash ${RACINE}/deploiement/taches/executer-tache.sh %i`);
    expect(service).to.include("EnvironmentFile=/etc/noortrace/taches.env");
    for (const [f, [id, cal]] of Object.entries(CADENCES)) {
      const t = fs.readFileSync(path.join(unites, f), "utf8");
      expect(t, f).to.include(`Unit=noortrace-tache@${id}.service`);
      expect(t, f).to.include("Persistent=true");
      if (!commande("systemd-analyze")) continue;
      const c = spawnSync("systemd-analyze", ["calendar", t.match(/^OnCalendar=(.+)$/m)[1]], { encoding: "utf8" });
      expect(c.status, f).to.equal(0);
      expect(c.stdout, f).to.include(`Normalized form: ${cal}`);
    }
    // Copie de réglages modifiée : jamais remplacée ; unités identiques au second passage.
    fs.appendFileSync(env, "NOORTRACE_INSTANCE=enregistreur-1\n");
    const avant = Object.fromEntries(fs.readdirSync(unites).map((f) => [f, fs.readFileSync(path.join(unites, f), "utf8")]));
    const r2 = bash(path.join(TACHES, "poser-taches.sh"), ["--racine", RACINE, "--taches", tout, "--sortie", unites, "--environnement", env, "--sans-activation"]);
    expect(r2.status).to.equal(0);
    expect(Object.fromEntries(fs.readdirSync(unites).map((f) => [f, fs.readFileSync(path.join(unites, f), "utf8")]))).to.deep.equal(avant);
    expect(fs.readFileSync(env, "utf8")).to.include("NOORTRACE_INSTANCE=enregistreur-1\n");
    expect(bash(path.join(TACHES, "poser-taches.sh"), ["--racine", RACINE, "--taches", "TP-9", "--sortie", unites, "--sans-activation"]).status).to.equal(2);
    expect(bash(path.join(TACHES, "poser-taches.sh"), ["--racine", "relatif", "--sortie", unites]).status).to.equal(2);
    if (!commande("systemd-analyze")) {
      enAttente(this, "systemd-analyze absent (systemd du système de référence)");
      return;
    }
    // Seules nos unités sont jugées : --recursive-errors=no (systemd 250 et suivants) ne compte que
    // les diagnostics des unités nommées, et toute ligne qui cite l'un de nos fichiers ou de nos
    // unités fait échouer l'essai. Les unités du système chargées en dépendance (docker.service,
    // sysinit.target…) ne sont pas les nôtres : leurs avertissements, propres à la machine
    // (system-xfs_scrub.slice, walinuxagent.service sur l'exécuteur de la CI), sont écartés.
    const v = verifierUnites(unites);
    expect(v.status, v.stderr).to.equal(0);
    expect(v.notres, v.stderr).to.deep.equal([]);
    // Unité du système bruyante (même nom que celle dont dépend le service gabarit, placée devant le
    // chemin de recherche du système) : nos unités restent acceptées.
    const bruit = path.join(rep, "bruit");
    fs.mkdirSync(bruit);
    fs.writeFileSync(path.join(bruit, "docker.service"), "[Unit]\nDescription=unité du système simulée, bruyante\n[Service]\nMemoryLimit=1G\nCleInconnueDuSysteme=1\nExecStart=/bin/true\n");
    const vb = verifierUnites(unites, { SYSTEMD_UNIT_PATH: `${bruit}:` });
    expect(vb.status, vb.stderr).to.equal(0);
    expect(vb.notres, vb.stderr).to.deep.equal([]);
    // Le bruit est bien chargé : la vérification de toutes les dépendances (ancienne forme de l'essai,
    // qui exigeait une sortie d'erreur vide) le rapporte, comme sur l'exécuteur de la CI.
    const toutes = spawnSync("systemd-analyze", ["verify", "--man=no", "noortrace-tache@TP-1.service"], { encoding: "utf8", cwd: unites, env: { ...process.env, SYSTEMD_UNIT_PATH: `${bruit}:` } });
    expect(toutes.stderr).to.include(`${path.join(bruit, "docker.service")}:`);
    // Témoin : une erreur dans nos unités fait toujours échouer la vérification.
    const fausses = path.join(rep, "unites-fausses");
    fs.cpSync(unites, fausses, { recursive: true });
    const tp1 = path.join(fausses, "noortrace-tp1.timer");
    fs.writeFileSync(tp1, fs.readFileSync(tp1, "utf8").replace("Persistent=true\n", "Persistent=true\nCleInconnue=1\n"));
    const gabarit = path.join(fausses, "noortrace-tache@.service");
    fs.writeFileSync(gabarit, fs.readFileSync(gabarit, "utf8").replace("ExecStart=/bin/bash ", "ExecStart=/bin/bash-absent "));
    const vf = verifierUnites(fausses, { SYSTEMD_UNIT_PATH: `${bruit}:` });
    expect(vf.status).to.not.equal(0);
    expect(vf.notres.some((l) => l.includes("noortrace-tp1.timer") && l.includes("CleInconnue")), vf.stderr).to.equal(true);
    expect(vf.notres.some((l) => l.startsWith("noortrace-tache@TP-1.service") && l.includes("/bin/bash-absent")), vf.stderr).to.equal(true);
  });

  it("TE-7 (TP-1 à TP-8) : executer-tache.sh consigne une ligne horodatée avec le code de sortie de chaque exécution (EX-8.6) ; tâche sans commande du client : code 3 ; tâche inconnue : code 2", function () {
    const rep = path.join(TRAVAIL, "taches-exec");
    const env = { ...process.env, NOORTRACE_RACINE: RACINE, NOORTRACE_EXPLOITATION: rep, NOORTRACE_TP2_COMMANDE: "", NOORTRACE_TP3_COMMANDE: "echo en-tetes; exit 5" };
    const executer = path.join(TACHES, "executer-tache.sh");
    expect(bash(executer, ["TP-7"], { env }).status).to.equal(0);
    expect(bash(executer, ["TP-2"], { env }).status).to.equal(3);
    expect(bash(executer, ["TP-3"], { env }).status).to.equal(5);
    expect(bash(executer, ["TP-9"], { env }).status).to.equal(2);
    expect(bash(executer, ["TP-1"], { env }).status).to.equal(2);
    const lignes = fs.readFileSync(path.join(rep, "taches", "taches.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(lignes.map((l) => [l.task, l.exit_code])).to.deep.equal([["TP-7", 0], ["TP-2", 3], ["TP-3", 5], ["TP-1", 2]]);
    for (const l of lignes) {
      expect(l.ts).to.match(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/);
      expect(Object.keys(l)).to.deep.equal(["ts", "task", "exit_code", "duration_ms", "detail"]);
    }
    expect(lignes[1].detail).to.include("NOORTRACE_TP2_COMMANDE");
    expect(lignes[3].detail).to.include("NOORTRACE_TP1_IDENTIFIANTS non réglé");
  });

  it("TE-7 (TP-6) : executer-tache.sh TP-6 archive les fichiers tournés du volume exploitation (moteur simulé : docker volume inspect)", function () {
    const rep = path.join(TRAVAIL, "taches-tp6");
    const volume = path.join(rep, "volume-exploitation");
    fs.mkdirSync(volume, { recursive: true });
    const j = new JournalExploitation({ chemin: path.join(volume, "exploitation.ndjson"), rotation: 600, conserver: 4 });
    for (let i = 0; i < 12; i++) j.consigner("info", "noyau", "essai_tp6", { i });
    const bin = path.join(rep, "bin");
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, "docker"), `#!/bin/sh\n[ "$1 $2" = "volume inspect" ] && echo "${volume}" && exit 0\nexit 1\n`, { mode: 0o755 });
    const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, NOORTRACE_RACINE: RACINE, NOORTRACE_EXPLOITATION: rep, NOORTRACE_INSTANCE: "enregistreur-1" };
    const r = bash(path.join(TACHES, "executer-tache.sh"), ["TP-6"], { env });
    expect(r.status, r.stdout + r.stderr).to.equal(0);
    const index = fs.readFileSync(path.join(rep, "journal-exploitation", "enregistreur-1", "index.ndjson"), "utf8").trim().split("\n");
    expect(index.length).to.equal(fs.readdirSync(volume).filter((f) => /\.ndjson\.[0-9]+$/.test(f)).length);
    expect(lireJSON(path.join(rep, "taches", "taches.ndjson")).exit_code).to.equal(0);
  });
});

// ---------------------------------------------------------------------------
// TP-6
// ---------------------------------------------------------------------------

describe("CT-8 EX-11.22, EX-11.23 (TP-6) : archivage des fichiers tournés du journal d'exploitation", function () {
  it("TE-9 (EX-11.22) : chaque fichier tourné complet est archivé une fois, octets inchangés, nommé par sa première ligne et son SHA-256 ; un second passage n'archive rien ; la série relue est continue", function () {
    const rep = path.join(TRAVAIL, "tp6-a");
    const chemin = path.join(rep, "log", "exploitation.ndjson");
    let t = Date.UTC(2026, 10, 5, 8, 0, 0);
    const j = new JournalExploitation({ chemin, rotation: 700, conserver: 5, murale: () => (t += 1000) });
    for (let i = 0; i < 10; i++) j.consigner("info", "noyau", "essai_tp6", { i });
    const tournes = fs.readdirSync(path.dirname(chemin)).filter((f) => /\.[0-9]+$/.test(f)).sort();
    expect(tournes.length).to.be.at.least(2);
    const vers = path.join(rep, "archive");
    const r = archiver({ journal: chemin, instance: "enregistreur-1", vers, maintenant: () => "2026-11-05T09:00:00.000Z" });
    expect(r.errors).to.deep.equal([]);
    expect(r.archived.length).to.equal(tournes.length);
    for (const e of r.archived) {
      const octets = fs.readFileSync(path.join(vers, "enregistreur-1", e.file));
      expect(octets.equals(fs.readFileSync(path.join(path.dirname(chemin), e.source)))).to.equal(true);
      expect(e.file).to.equal(`exploitation-${e.first_ts.replace(/[-:.]/g, "")}-${sha(octets).slice(0, 16)}.ndjson`);
    }
    const ordre = r.archived.map((e) => e.first_ts);
    expect(ordre).to.deep.equal([...ordre].sort());
    expect(archiver({ journal: chemin, instance: "enregistreur-1", vers }).archived).to.deep.equal([]);
    // Nouvelles rotations, en deçà de keep_files : seules les nouvelles sont archivées.
    for (let i = 10; i < 14; i++) j.consigner("info", "noyau", "essai_tp6", { i });
    const r3 = archiver({ journal: chemin, instance: "enregistreur-1", vers });
    expect(r3.errors).to.deep.equal([]);
    expect(r3.archived.length).to.be.at.least(1);
    expect(r3.already).to.be.at.least(1);
    const cli = outil("archiver-journal-exploitation.mjs", ["--verifier", "--instance", "enregistreur-1", "--vers", vers, "--json"]);
    expect(cli.status, cli.stderr).to.equal(0);
    expect(JSON.parse(cli.stdout).verdict).to.equal("continu");
  });

  it("TE-9 (EX-11.23) : discontinuité quand des rotations ont écarté des fichiers entre deux passages ; fichier archivé altéré ; fichier tourné incomplet non archivé ; codes 1 et 2", function () {
    const rep = path.join(TRAVAIL, "tp6-b");
    const chemin = path.join(rep, "log", "exploitation.ndjson");
    let t = Date.UTC(2026, 10, 5, 8, 0, 0);
    const j = new JournalExploitation({ chemin, rotation: 500, conserver: 2, murale: () => (t += 1000) });
    for (let i = 0; i < 6; i++) j.consigner("info", "noyau", "essai_tp6", { i });
    const vers = path.join(rep, "archive");
    expect(archiver({ journal: chemin, instance: "i1", vers }).errors).to.deep.equal([]);
    for (let i = 6; i < 30; i++) j.consigner("info", "noyau", "essai_tp6", { i });
    const r = outil("archiver-journal-exploitation.mjs", ["--journal", chemin, "--instance", "i1", "--vers", vers, "--json"]);
    expect(r.status).to.equal(1);
    expect(JSON.parse(r.stdout).errors.join(" ")).to.include("discontinuité possible");
    const index = fs.readFileSync(path.join(vers, "i1", "index.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    fs.appendFileSync(path.join(vers, "i1", index[0].file), "{}\n");
    expect(relireSerie(path.join(vers, "i1")).join(" ")).to.include("longueur ou SHA-256 différents");
    expect(outil("archiver-journal-exploitation.mjs", ["--verifier", "--instance", "i1", "--vers", vers]).status).to.equal(1);
    const rep2 = path.join(TRAVAIL, "tp6-c");
    fs.mkdirSync(path.join(rep2, "log"), { recursive: true });
    fs.writeFileSync(path.join(rep2, "log", "x.ndjson.1"), '{"ts":"2026-11-05T08:00:00.000Z","event":"a"}\n{"ts":"2026-11-05T08:00:01');
    const r2 = archiver({ journal: path.join(rep2, "log", "x.ndjson"), instance: "i2", vers: path.join(rep2, "a") });
    expect(r2.archived).to.deep.equal([]);
    expect(r2.errors.join(" ")).to.include("incomplet");
    expect(outil("archiver-journal-exploitation.mjs", ["--instance", "i1"]).status).to.equal(2);
    expect(outil("archiver-journal-exploitation.mjs", ["--verifier", "--journal", chemin, "--instance", "i1", "--vers", vers]).status).to.equal(2);
  });
});

// ---------------------------------------------------------------------------
// Sauvegarde
// ---------------------------------------------------------------------------

describe("CT-8 §11.2, EX-11.2 à EX-11.4 et 13.4 : sauvegarde.mjs (archive déterministe et procès-verbal sauvegarde)", function () {
  this.timeout(120000);

  function creer(rep, journal, cles, extra = []) {
    return outil("sauvegarde.mjs", ["creer", "--journal", journal, "--cles", cles, "--archive", path.join(rep, "a.tar"), "--pv", path.join(rep, "pv.json"), "--id", "pv-2026-11-12-001", "--executant", "tache-sauvegarde", "--motif", "sauvegarde quotidienne, tache SAUVEGARDE", "--source", "volume noortrace_journal, hote essai", "--destination", "archive a.tar, coffre d'essai", "--date", "2026-11-12T01:30:00.000Z", ...extra]);
  }

  it("TE-9 (EX-11.2, EX-11.4) : archive au format de 13.4 (forme relue, longueur L, recette GNU tar d'EX-13.15 à l'octet), procès-verbal sauvegarde : PV-1 à PV-10 réussies par proces-verbal.mjs sur l'archive extraite, continuité égale à verifier-journal", function () {
    const rep = path.join(TRAVAIL, "sauvegarde-a");
    fs.mkdirSync(rep);
    const j = copieJournalVecteur("valide-manifeste", path.join(rep, "journal"));
    const r = creer(rep, j.racine, j.cles);
    expect(r.status, r.stderr).to.equal(0);
    const octets = fs.readFileSync(path.join(rep, "a.tar"));
    const lu = S.lireArchive(octets);
    expect(lu.erreurs).to.deep.equal([]);
    expect(lu.mtime).to.equal(Date.UTC(2026, 10, 12, 1, 30) / 1000);
    expect(octets.length).to.equal(S.longueurArchive(lu.fichiers.map((f) => f.length)));
    const pv = lireJSON(path.join(rep, "pv.json"));
    expect(pv.kind).to.equal("sauvegarde");
    expect(pv.files.map((f) => f.path)).to.deep.equal(lu.fichiers.map((f) => f.path));
    expect(pv.files.map((f) => f.path)).to.deep.equal(["journal.json", "manifestes/periode-1793865600.json", "manifestes/periode-1793865600.sig", "segments/seg-0000000000000001-00000000000000000001.ndjson"]);
    const vj = JSON.parse(outil("verifier-journal.mjs", [j.racine, "--cles", j.cles, "--json"]).stdout);
    expect(pv.continuity).to.deep.equal({ last_seq: vj.last_seq, last_hash: vj.last_hash, last_period_start: 1793865600 });
    const rapport = fs.readFileSync(path.join(rep, "pv.json.verification-journal.json"));
    expect(pv.verification.report_sha256).to.equal(`0x${sha(rapport)}`);
    const ext = path.join(rep, "extrait");
    const x = outil("sauvegarde.mjs", ["extraire", "--archive", path.join(rep, "a.tar"), "--pv", path.join(rep, "pv.json"), "--vers", ext, "--json"]);
    expect(x.status, x.stderr).to.equal(0);
    expect(JSON.parse(x.stdout)).to.include({ verdict: "extrait", files: 4, highest_segment_epoch: "1" });
    expect(fs.statSync(ext).mode & 0o777).to.equal(0o700);
    const pvv = outil("proces-verbal.mjs", ["verifier", path.join(rep, "pv.json"), "--racine", ext, "--cles", j.cles, "--json"]);
    expect(pvv.status, pvv.stdout).to.equal(0);
    expect(JSON.parse(pvv.stdout).checks.map((c) => [c.id, c.status])).to.deep.equal(Array.from({ length: 10 }, (_, i) => [`PV-${i + 1}`, i === 8 ? "non_execute" : "reussi"]));
    if (commande("tar") && /GNU tar/.test(spawnSync("tar", ["--version"], { encoding: "utf8" }).stdout)) {
      const liste = path.join(rep, "liste.txt");
      fs.writeFileSync(liste, pv.files.map((f) => f.path).join("\n") + "\n");
      const g = spawnSync("tar", ["--format=ustar", "--no-recursion", "--owner=0", "--group=0", "--numeric-owner", "--mode=0644", `--mtime=@${lu.mtime}`, "-cf", path.join(rep, "g.tar"), "-T", liste], { cwd: ext, env: { ...process.env, LC_ALL: "C" } });
      expect(g.status).to.equal(0);
      expect(fs.readFileSync(path.join(rep, "g.tar")).equals(octets), "recette GNU tar d'EX-13.15").to.equal(true);
    }
    expect(outil("sauvegarde.mjs", ["verifier", "--archive", path.join(rep, "a.tar"), "--pv", path.join(rep, "pv.json")]).status).to.equal(0);
  });

  it("TE-9 (EX-11.1 point 2, PV-10) : lien, fichier spécial, répertoire secrets et clé privée (DER Ed25519 ou PEM) refusés, code 1, rien n'est écrit ; segment en cours d'écriture gardé jusqu'à sa dernière fin de ligne et signalé", function () {
    const cas = {
      lien: (r) => fs.symlinkSync("journal.json", path.join(r, "lien.json")),
      secrets: (r) => {
        fs.mkdirSync(path.join(r, "secrets"));
        fs.writeFileSync(path.join(r, "secrets", "x"), "y");
      },
      der: (r) => fs.writeFileSync(path.join(r, "cle"), Buffer.concat([S.PREFIXE_CLE_ED25519, Buffer.alloc(32, 7)])),
      pem: (r) => fs.writeFileSync(path.join(r, "cle.pem"), "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
      chemin: (r) => fs.writeFileSync(path.join(r, "nom interdit"), "x"),
    };
    for (const [nom, alterer] of Object.entries(cas)) {
      const rep = path.join(TRAVAIL, `sauvegarde-refus-${nom}`);
      fs.mkdirSync(rep);
      const j = copieJournalVecteur("valide", path.join(rep, "journal"));
      alterer(j.racine);
      const r = creer(rep, j.racine, j.cles);
      expect(r.status, `${nom} : ${r.stderr}`).to.equal(1);
      expect(r.stderr, nom).to.match(/^Refus : /);
      expect(fs.readdirSync(rep), nom).to.deep.equal(["journal"]);
    }
    const rep = path.join(TRAVAIL, "sauvegarde-partiel");
    fs.mkdirSync(rep);
    const j = copieJournalVecteur("valide", path.join(rep, "journal"));
    const seg = path.join(j.racine, "segments", "seg-0000000000000001-00000000000000000001.ndjson");
    const complet = fs.readFileSync(seg);
    const partiel = '{"seq":8,"partiel';
    fs.appendFileSync(seg, partiel);
    const r = creer(rep, j.racine, j.cles);
    expect(r.status, r.stderr).to.equal(0);
    const pv = lireJSON(path.join(rep, "pv.json"));
    const f = pv.files.find((x) => x.path.startsWith("segments/"));
    expect([f.length, f.sha256_source]).to.deep.equal([complet.length, `0x${sha(complet)}`]);
    expect(pv.observations).to.include(`segments/seg-0000000000000001-00000000000000000001.ndjson (${complet.length} octets sur ${complet.length + partiel.length})`);
  });

  it("TE-9 (EX-11.4, EX-13.13, EX-13.14) : verifier refuse une archive altérée (contenu, mode, ordre, gzip) ou un procès-verbal qui la contredit ; extraire refuse un membre .., une destination existante ; usage : code 2", function () {
    const rep = path.join(TRAVAIL, "sauvegarde-alteree");
    fs.mkdirSync(rep);
    const j = copieJournalVecteur("valide", path.join(rep, "journal"));
    expect(creer(rep, j.racine, j.cles).status).to.equal(0);
    const archive = path.join(rep, "a.tar");
    const pv = path.join(rep, "pv.json");
    const bon = fs.readFileSync(archive);
    const verifier = (octets, p = pv) => {
      fs.writeFileSync(path.join(rep, "b.tar"), octets);
      return outil("sauvegarde.mjs", ["verifier", "--archive", path.join(rep, "b.tar"), "--pv", p, "--json"]);
    };
    const contenu = Buffer.from(bon);
    contenu[512 + 3] ^= 1;
    expect(JSON.parse(verifier(contenu).stdout).errors.join(" ")).to.include("SHA-256");
    const mode = Buffer.from(bon);
    mode.write("0000755\0", 100, "latin1");
    const rm = verifier(mode);
    expect(rm.status).to.equal(1);
    expect(rm.stdout).to.include("mode").and.to.include("chksum faux");
    const gz = verifier(Buffer.concat([Buffer.from([0x1f, 0x8b]), bon.subarray(0, 1001)]));
    expect(gz.status).to.equal(1);
    expect(gz.stdout).to.include("gzip");
    const triee = S.ecrireArchive([{ path: "b", octets: Buffer.from("1") }, { path: "a", octets: Buffer.from("2") }], 1);
    expect(S.lireArchive(triee).fichiers.map((x) => x.path)).to.deep.equal(["a", "b"]);
    const inverse = Buffer.concat([triee.subarray(1024, 2048), triee.subarray(0, 1024), triee.subarray(2048)]);
    expect(S.lireArchive(inverse).erreurs.join(" ")).to.include("ordre des noms non strictement croissant");
    const p2 = lireJSON(pv);
    p2.files[0].sha256_destination = `0x${"0".repeat(64)}`;
    fs.writeFileSync(path.join(rep, "pv2.json"), JSON.stringify(p2));
    expect(verifier(bon, path.join(rep, "pv2.json")).status).to.equal(1);
    // Membre « .. » forgé (en-tête recalculé) : refusé par la relecture et par l'extraction.
    const forge = Buffer.from(bon);
    forge.fill(0, 0, 100);
    forge.write("../journal.json", 0, "latin1");
    forge.write("        ", 148, "latin1");
    let somme = 0;
    for (let i = 0; i < 512; i++) somme += forge[i];
    forge.write(somme.toString(8).padStart(6, "0") + "\0 ", 148, "latin1");
    expect(S.lireArchive(forge).erreurs.join(" ")).to.include("composant . ou ..");
    fs.writeFileSync(path.join(rep, "forge.tar"), forge);
    const x = outil("sauvegarde.mjs", ["extraire", "--archive", path.join(rep, "forge.tar"), "--pv", pv, "--vers", path.join(rep, "x")]);
    expect(x.status).to.equal(1);
    expect(fs.existsSync(path.join(rep, "x"))).to.equal(false);
    expect(() => S.extraire([{ path: "../x", octets: Buffer.alloc(0) }], path.join(rep, "y"))).to.throw(/composant/);
    expect(outil("sauvegarde.mjs", ["extraire", "--archive", archive, "--pv", pv, "--vers", j.racine]).status).to.equal(1);
    expect(outil("sauvegarde.mjs", ["-h"]).stderr).to.match(/^Erreur : option inconnue : -h\nUsage : /);
    expect(outil("sauvegarde.mjs", ["creer", "--journal", j.racine]).status).to.equal(2);
    expect(outil("sauvegarde.mjs", ["verifier", "--archive", archive, "--pv", pv, "--vers", "x"]).status).to.equal(2);
    expect(creer(rep, j.racine, j.cles).status, "archive existante").to.equal(2);
  });

  it("EX-13.14 : découpage nom/préfixe à 100 et 155 octets ; nom non représentable refusé", function () {
    const long = `${"a".repeat(60)}/${"b".repeat(60)}/c.json`;
    const o = S.ecrireArchive([{ path: long, octets: Buffer.from("{}") }], 0);
    expect(o.subarray(345, 345 + 121).toString("latin1")).to.equal(`${"a".repeat(60)}/${"b".repeat(60)}`);
    expect(S.lireArchive(o).fichiers[0].path).to.equal(long);
    expect(() => S.decouper("a".repeat(101))).to.throw(/non représentable/);
  });
});

// ---------------------------------------------------------------------------
// TE-9 : chemin A de 11.4 sur le démon réel
// ---------------------------------------------------------------------------

describe("CT-8 §11.4 chemin A (TE-9, TM-37 hors système de référence) : sauvegarde, perte du volume, restauration et reprise du démon réel", function () {
  this.timeout(600000);
  let j;
  let demon;
  const mesures = {};

  after(async function () {
    if (demon) await demon.arreter().catch(() => {});
    await j?.fermer?.();
  });

  it("TE-9 : archive du journal, volume détruit, pas 2 à 6 (procès-verbal, extraction, verifier-journal, époque du bail recréée), reprise d'époque supérieure, dossiers du dernier événement restauré et du premier après la reprise valides, chaîne continue ; PV-1 à PV-10 de la sauvegarde ; durées publiées sans compter", async function () {
    const dir = path.join(TRAVAIL, "chemin-a");
    fs.mkdirSync(dir);
    j = await construireJournal(dir);
    const cles = clesEssai(path.join(dir, "cles.json"), j.config.recorder.org_id, j.config.recorder.journal_id);
    const sauvegardes = path.join(dir, "sauvegardes");
    fs.mkdirSync(sauvegardes);
    const t0 = performance.now();
    const s = outil("sauvegarde.mjs", ["creer", "--journal", j.repertoire, "--cles", cles, "--archive", path.join(sauvegardes, "a.tar"), "--pv", path.join(sauvegardes, "pv.json"), "--id", "pv-2026-11-12-001", "--executant", "tache-sauvegarde", "--motif", "TE-9 chemin A", "--source", "volume journal d'essai", "--destination", "archive a.tar"]);
    mesures.sauvegarde_ms = Math.round(performance.now() - t0);
    expect(s.status, s.stderr).to.equal(0);
    const pv = lireJSON(path.join(sauvegardes, "pv.json"));
    const avant = JSON.parse(outil("verifier-journal.mjs", [j.repertoire, "--cles", cles, "--json"]).stdout);
    expect(pv.continuity.last_seq).to.equal(avant.last_seq);
    // Perte : le répertoire du journal est mis hors service (pas 1), le magasin de bail perdu.
    const t1 = performance.now();
    fs.renameSync(j.repertoire, `${j.repertoire}.hors-service`);
    const bail = j.config.lease.store.path;
    fs.rmSync(path.dirname(bail), { recursive: true, force: true });
    // Pas 2 et 3 : contrôle de l'archive contre le procès-verbal, extraction dans un répertoire neuf.
    const x = outil("sauvegarde.mjs", ["extraire", "--archive", path.join(sauvegardes, "a.tar"), "--pv", path.join(sauvegardes, "pv.json"), "--vers", j.repertoire, "--json"]);
    expect(x.status, x.stderr).to.equal(0);
    const E = JSON.parse(x.stdout).highest_segment_epoch;
    // Pas 5 : verifier-journal sur le répertoire restauré.
    const apres = JSON.parse(outil("verifier-journal.mjs", [j.repertoire, "--cles", cles, "--json"]).stdout);
    expect(apres.verdict).to.equal("valide");
    expect([apres.last_seq, apres.last_hash]).to.deep.equal([pv.continuity.last_seq, pv.continuity.last_hash]);
    const pvv = outil("proces-verbal.mjs", ["verifier", path.join(sauvegardes, "pv.json"), "--racine", j.repertoire, "--cles", cles, "--json"]);
    expect(pvv.status, pvv.stdout).to.equal(0);
    // Pas 6 : magasin de bail perdu, époque E écrite dans <lease.store.path>.epoch (mode 0600).
    fs.mkdirSync(path.dirname(bail), { recursive: true, mode: 0o700 });
    fs.writeFileSync(`${bail}.epoch`, `${E}\n`, { mode: 0o600 });
    demon = new DemonEssai({ cheminConfig: j.cheminConfig, env: j.env, journal: j.journal, horloge: j.finMs + 1000 });
    const acquisitionsAvant = demon.de("lease_acquired").length;
    await demon.demarrer();
    mesures.reprise_ms = Math.round(performance.now() - t1);
    await attendre(() => demon.de("lease_acquired").length > acquisitionsAvant, 30000, "lease_acquired de la reprise");
    const acquis = demon.de("lease_acquired").at(-1);
    expect(Number(acquis.data.epoch)).to.equal(Number(E) + 1);
    const nouveau = await demon.commande({ cmd: "evenement", n: 9 });
    expect(nouveau.seq).to.equal(apres.last_seq + 1);
    const neufs = fs.readdirSync(path.join(j.repertoire, "segments")).filter((f) => BigInt(f.slice(-25, -7)) > BigInt(E));
    expect(neufs).to.have.lengthOf(1);
    const entete = JSON.parse(fs.readFileSync(path.join(j.repertoire, "segments", neufs[0]), "utf8").split("\n")[0]);
    expect(entete.prev_hash, "en-tête du premier segment après la reprise (CT-2 EX-12.3, EX-13.9)").to.equal(apres.last_hash);
    // Pas 7 : clôture de la période ouverte, export et vérification des deux dossiers.
    await demon.commande({ cmd: "avancer", ms: (j.P + 7200) * 1000 - (j.finMs + 1000) + 2000 });
    const manifeste = path.join(j.repertoire, "manifestes", `periode-${String(j.P + 3600).padStart(10, "0")}.json`);
    await attendre(() => fs.existsSync(manifeste), 60000, "clôture de la période de la reprise");
    for (const [nom, seq] of [["restaure", apres.last_seq], ["reprise", nouveau.seq]]) {
      const dest = path.join(j.exports, `te9-${nom}`);
      await demon.commande({ cmd: "exporter", seq, destination: dest });
      const v = spawnSync(process.execPath, [path.join(RACINE, "scripts", "verify", "dossier.mjs"), dest, "--json"], { encoding: "utf8", cwd: RACINE, maxBuffer: 64 * 1024 * 1024 });
      expect(v.status, `${nom} : ${v.stdout.slice(0, 2000)}`).to.equal(0);
    }
    const fin = JSON.parse(outil("verifier-journal.mjs", [j.repertoire, "--cles", cles, "--json"]).stdout);
    expect(fin.verdict).to.equal("valide");
    expect(fin.last_seq).to.be.at.least(nouveau.seq);
    mesures.total_ms = Math.round(performance.now() - t1);
    // TM-37 : durées de ce banc publiées, jamais comptées (CT-9 EX-11.2 : hors système de référence).
    console.log(`      TM-37 (hors système de référence, reference=false) : ${JSON.stringify(mesures)}`);
  });

  it("TE-9 : chemin B (copies WORM) et chemin C (journal neuf) — hors de cet essai", function () {
    enAttente(this, "chemin B éprouvé par test/enregistreur-worm-restauration.test.js (simulateur S3 à verrouillage, Docker) ; chemin C : rotation de chaîne et journal neuf au registre, étape 8 ; TM-37 sur le système de référence de CT-9 §11.1");
  });
});

// ---------------------------------------------------------------------------
// E-6 : l'installation rapide ancre
// ---------------------------------------------------------------------------

describe("CT-8 §7.3, EX-7.3 (ancrage de l'installation rapide) : l'installation rapide désigne un document d'ancrage que rapide.yaml monte, et produit des preuves OpenTimestamps", function () {
  this.timeout(300000);
  const config = lireJSON(path.join(DEP, "config", "rapide", "configuration.json"));
  const ancrage = lireJSON(path.join(DEP, "config", "rapide", "ancrage.json"));

  it("TE-6 (ancrage) : configuration → /etc/noortrace/ancrage.json ; rapide.yaml le monte, sert le serveur interne (horodatage, horodatage-init) sans secret RFC 3161 ; images.json l'admet ; ancrage-v0 conforme, admis par AN-1 en développement (principal = serveur interne), refusé en production ; calendriers de 7.3, sans registre ni jeton de point ; configurer-rapide le contrôle et y recopie l'AC", function () {
    expect(config.anchoring.ancrage).to.equal("/etc/noortrace/ancrage.json");
    const texte = fs.readFileSync(path.join(DEP, "compose", "rapide.yaml"), "utf8");
    expect(texte).to.include("      - type: bind\n        source: ./config/rapide/ancrage.json\n        target: /etc/noortrace/ancrage.json\n        read_only: true\n        bind:\n          create_host_path: false\n");
    expect(texte).to.not.match(/^ {2}(- )?tsa-|^ {6}- tsa-/m);
    expect(texte).to.include('    network_mode: "service:enregistreur"\n');
    expect(texte).to.include('    command: ["servir", "--repertoire", "/var/lib/noortrace-tsa", "--hote", "127.0.0.1", "--port", "2020"]\n');
    const images = lireJSON(path.join(DEP, "images", "images.json"));
    expect(images.services.horodatage).to.include({ image: "noortrace/tsa-interne", network_mode: "service:enregistreur", user: "10004:10004" });
    expect(images.services["horodatage-init"]).to.include({ image: "noortrace/tsa-interne", network_mode: "none", kind: "outil" });
    const v = D.verifierConteneurs(texte, images, "rapide.yaml");
    expect(v.verdict, JSON.stringify(v.checks?.filter?.((c) => c.status !== "reussi"))).to.equal("conforme");
    expect(D.validerSchemaDeploiement(ancrage, D.chargerSchema("ancrage"))).to.deep.equal([]);
    expect(ancrage.opentimestamps.enabled).to.equal(true);
    expect(ancrage.opentimestamps.calendars).to.deep.equal(config.anchoring.opentimestamps.calendars);
    expect(config.anchoring.registry.enabled).to.equal(false);
    expect([ancrage.registry.checkpoints, ancrage.rfc3161.checkpoints.provider_role]).to.deep.equal(["aucun", "aucun"]);
    expect(ancrage.checkpoint_interval_s).to.equal(config.checkpoint_interval_s ?? 60);
    expect(ancrage.rfc3161.providers).to.have.lengthOf(1);
    expect(ancrage.rfc3161.providers[0]).to.include({ id: "tsa-interne", role: "principal", url: "http://127.0.0.1:2020/", qualified: null });
    expect(ancrage.rfc3161.providers[0].auth).to.deep.equal({ method: "aucune", secret: null });
    const an1 = spawnSync(process.execPath, [path.join(RACINE, "paquets", "ancrage", "bin", "noortrace-ancrage"), "configuration", path.join(DEP, "config", "rapide", "ancrage.json"), "--profil", "developpement", "--checkpoint-interval", "60"], { encoding: "utf8" });
    expect(an1.status, an1.stdout + an1.stderr).to.equal(0);
    const prod = spawnSync(process.execPath, [path.join(RACINE, "paquets", "ancrage", "bin", "noortrace-ancrage"), "configuration", path.join(DEP, "config", "rapide", "ancrage.json"), "--profil", "production", "--checkpoint-interval", "60"], { encoding: "utf8" });
    expect(prod.status, "jamais un document de production").to.equal(1);
    expect(prod.stdout + prod.stderr).to.include("n'est admis comme principal que hors production");
    const autre = structuredClone(config);
    autre.anchoring.ancrage = null;
    expect(() => controlerAncrageRapide(autre)).to.throw(/anchoring.ancrage/);
    const cadence = structuredClone(config);
    cadence.checkpoint_interval_s = 30;
    expect(() => controlerAncrageRapide(cadence)).to.throw(/AN-1, règle 1/);
    const texteConf = fs.readFileSync(path.join(DEP, "config", "rapide", "configuration.json"), "utf8");
    expect(configurationRapide({ org: "organisation-exemple", journal: "journal-rapide", serveurOutils: "https://outils.interne.example/mcp" })).to.equal(texteConf);
    const acTest = fs.readFileSync(path.join(RACINE, "spec", "vecteurs", "ct-6", "rfc3161", "cles", "ac-test.pem"), "utf8");
    expect(ancrageRapide({ acPem: acTest, configuration: texteConf })).to.equal(fs.readFileSync(path.join(DEP, "config", "rapide", "ancrage.json"), "utf8"));
    expect(() => ancrageRapide({ acPem: fs.readFileSync(path.join(RACINE, "spec", "vecteurs", "ct-6", "rfc3161", "cles", "tsa-test.pem"), "utf8"), configuration: texteConf })).to.throw(/certificat d'autorité/);
    expect(() => ancrageRapide({ acPem: "pas un certificat", configuration: texteConf })).to.throw(/un seul certificat PEM/);
    const rep = path.join(TRAVAIL, "e6-ir3");
    fs.mkdirSync(rep);
    const sorties = ["--sortie", path.join(rep, "configuration.json")];
    const r = outil("configurer-rapide.mjs", ["--org", "organisation-exemple", "--journal", "journal-rapide", "--serveur-outils", "https://outils.interne.example/mcp", ...sorties, "--ac-horodatage", path.join(RACINE, "spec", "vecteurs", "ct-6", "rfc3161", "cles", "ac-test.pem"), "--sortie-ancrage", path.join(rep, "ancrage.json")]);
    expect(r.status, r.stderr).to.equal(0);
    expect(r.stdout).to.include(`ancrage_sha256 ${sha(fs.readFileSync(path.join(DEP, "config", "rapide", "ancrage.json")))}\nconfiguration valide\n`);
    expect(fs.readFileSync(path.join(rep, "ancrage.json"), "utf8")).to.equal(fs.readFileSync(path.join(DEP, "config", "rapide", "ancrage.json"), "utf8"));
    expect(outil("configurer-rapide.mjs", ["--org", "organisation-exemple", "--journal", "journal-rapide", "--serveur-outils", "https://outils.interne.example/mcp", "--sortie", path.join(rep, "c2.json"), "--ac-horodatage", path.join(RACINE, "spec", "vecteurs", "ct-6", "rfc3161", "cles", "ac-test.pem")]).status).to.equal(2);
    expect(fs.existsSync(path.join(rep, "c2.json"))).to.equal(false);
  });

  it("TE-6 (ancrage, IR-8) : démon réel avec le document de l'installation rapide (calendriers factices en TLS, serveur interne lancé par l'essai, chemins) : jeton de clôture du serveur interne et preuve OpenTimestamps du manifeste ; dossier exporté avec jeton-rfc3161.der et preuve.ots, valide pour le vérificateur de référence, contrôle 4 réussi contre l'AC du serveur", async function () {
    const dir = path.join(TRAVAIL, "e6");
    fs.mkdirSync(dir);
    const tls = materielTls(path.join(dir, "tls"));
    if (!tls) {
      enAttente(this, "openssl indisponible pour le matériel TLS des calendriers factices");
      return;
    }
    const BASE = Date.UTC(2026, 10, 5, 7, 0, 2);
    const P = Math.floor(BASE / 3600000) * 3600;
    // Serveur interne de paquets/ancrage, à l'horloge du démon (horloge réglable) : init p-256, écoute sur 127.0.0.1.
    let instantTsa = BASE;
    const horlogeTsa = { murale: () => instantTsa, monotone: () => performance.now() };
    const repTsa = path.join(dir, "tsa");
    initialiserAutorite({ repertoire: repTsa, algorithme: "p-256", politique: "1.3.6.1.4.1.99999.1.1", crlUrl: "http://127.0.0.1:2020/crl.pem", horloge: { murale: () => BASE - 60000 }, aleatoire: (n) => new Uint8Array(crypto.randomBytes(n)) });
    const autorite = chargerAutorite({ repertoire: repTsa });
    const tsa = await demarrerServeur({ autorite, ecoute: { hote: "127.0.0.1", port: 0 }, horloge: horlogeTsa });
    const acPem = fs.readFileSync(path.join(repTsa, FICHIERS_AUTORITE.ac), "utf8");
    const calendriers = await calendriersTls({ tls, fichierEntetes: path.join(dir, "entetes.json") });
    let demon;
    try {
      const { config: c, env } = configurationDev(path.join(dir, "enregistreur"));
      c.exports_dir = path.join(dir, "exports");
      fs.mkdirSync(c.exports_dir, { mode: 0o750 });
      const doc = structuredClone(ancrage);
      doc.opentimestamps.calendars = calendriers.uris;
      doc.opentimestamps.upgrade.whitelist = calendriers.uris;
      doc.queue.path = path.join(c.storage.root, "ancrage");
      doc.rfc3161.providers[0].url = tsa.adresse.url;
      doc.rfc3161.providers[0].anchor_certificates = [acPem];
      // Seuls ces membres diffèrent du document de l'archive.
      const diff = [];
      const cmp = (a, b, p) => (JSON.stringify(a) === JSON.stringify(b) ? null : a && b && typeof a === "object" && !Array.isArray(a) ? Object.keys({ ...a, ...b }).forEach((k) => cmp(a[k], b[k], `${p}/${k}`)) : diff.push(p));
      cmp(ancrage, doc, "");
      expect(diff.sort()).to.deep.equal(["/opentimestamps/calendars", "/opentimestamps/upgrade/whitelist", "/queue/path", "/rfc3161/providers"]);
      const cheminDoc = path.join(dir, "ancrage.json");
      fs.writeFileSync(cheminDoc, JSON.stringify(doc, null, 2) + "\n");
      c.anchoring.ancrage = cheminDoc;
      const cheminConfig = path.join(dir, "configuration.json");
      fs.writeFileSync(cheminConfig, JSON.stringify(c, null, 2));
      demon = new DemonEssai({ cheminConfig, env: { ...env, NODE_EXTRA_CA_CERTS: path.join(dir, "tls", "ca-extra.pem") }, journal: c.supervision.ops_log.path, horloge: BASE });
      fs.writeFileSync(path.join(dir, "tls", "ca-extra.pem"), tls.ca);
      await demon.demarrer();
      const attache = await demon.attendreLigne((l) => l.event === "anchoring_attached", 30000, "anchoring_attached");
      expect(attache.data).to.include({ profile: "developpement", registry: false, providers: 1 });
      const ev = await demon.commande({ cmd: "evenement", n: 1 });
      instantTsa = BASE + 3600000 + 2000;
      await demon.commande({ cmd: "avancer", ms: 3600000 + 2000 });
      const jeton = await demon.attendreLigne((l) => l.event === "period_timestamped", 60000, "period_timestamped");
      expect(jeton.data).to.include({ provider: "tsa-interne" });
      const repJournal = path.join(c.storage.root, c.recorder.org_id.slice(2), c.recorder.journal_id.slice(2));
      const ots = path.join(repJournal, "ancres", `periode-${String(P).padStart(10, "0")}`, "ots");
      await attendre(() => fs.existsSync(ots) && fs.readdirSync(ots).some((f) => /^manifeste-[0-9]+\.ots$/.test(f)), 60000, "preuve OpenTimestamps du manifeste");
      expect(calendriers.etat.requetes.filter((q) => q.methode === "POST" && q.url === "/digest").length).to.be.at.least(2);
      const rfc = path.join(repJournal, "ancres", `periode-${String(P).padStart(10, "0")}`, "rfc3161");
      expect(fs.readdirSync(rfc).filter((f) => f.endsWith(".der")).length).to.be.at.least(1);
      const dest = path.join(c.exports_dir, "premier");
      await demon.commande({ cmd: "exporter", seq: ev.seq, destination: dest });
      const fichiers = fs.readdirSync(dest, { recursive: true }).map(String);
      expect(fichiers.some((f) => path.basename(f) === "preuve.ots"), JSON.stringify(fichiers)).to.equal(true);
      expect(fichiers.some((f) => path.basename(f) === "jeton-rfc3161.der"), JSON.stringify(fichiers)).to.equal(true);
      // Réviseur : l'AC du serveur interne et une CRL publiée après genTime (T-10).
      const crl = publierCrl({ repertoire: repTsa, horloge: { murale: () => BASE + 3600000 + 120000 } });
      expect(Number(crl.numero)).to.equal(2);
      const ancres = path.join(dir, "ancres.json");
      fs.writeFileSync(ancres, JSON.stringify({ version: 0, label: "Ancres de l'essai de l'installation rapide", prepared_by: "essai TE-6", prepared_at: "2026-11-05T08:10:00.000Z", tsa_authorities: [{ name: "AC interne de développement (interne, non qualifié)", certificate: acPem, intermediates: [], accepted_policies: ["1.3.6.1.4.1.99999.1.1"], qualified: null, source: "AC du serveur interne lancé par l'essai" }], revocation: { crls: [fs.readFileSync(path.join(repTsa, FICHIERS_AUTORITE.crl), "utf8")], statements: [] }, bitcoin: null, registry: null, recorders: [] }, null, 2));
      const v = spawnSync(process.execPath, [path.join(RACINE, "scripts", "verify", "dossier.mjs"), dest, "--ancres", ancres, "--json"], { encoding: "utf8", cwd: RACINE, maxBuffer: 64 * 1024 * 1024 });
      expect(v.status, v.stdout.slice(0, 3000)).to.equal(0);
      const c4 = JSON.parse(v.stdout).controls.find((x) => x.number === 4);
      expect(c4.status, JSON.stringify(c4)).to.equal("reussi");
    } finally {
      if (demon) await demon.arreter().catch(() => {});
      await calendriers.fermer();
      await tsa.fermer();
      autorite.fermer();
    }
  });
});

// ---------------------------------------------------------------------------
// E-9 : validation d'ancrage-v0 sans réseau
// ---------------------------------------------------------------------------

describe("CT-8 IC-13 : validation du document ancrage-v0 par un outil du dépôt, à version exacte, sans réseau", function () {
  it("TE-7 (IC-13) : noortrace-ancrage configuration (schéma ancrage-v0 puis les huit règles d'AN-1) accepte l'exemple de CT-5 §4.4 en production et refuse un document invalide (code 1), avec un PATH réduit et sans mandataire ; la validation de schéma du dépôt concorde", function () {
    const ct5 = fs.readFileSync(path.join(RACINE, "spec", "CT-5-ancrage.md"), "utf8");
    const i = ct5.indexOf("<!-- schema: ancrage -->");
    const debut = ct5.indexOf("```json\n", i) + 8;
    const exemple = JSON.parse(ct5.slice(debut, ct5.indexOf("\n```", debut)));
    const rep = path.join(TRAVAIL, "e9");
    fs.mkdirSync(rep);
    const bon = path.join(rep, "ancrage.json");
    fs.writeFileSync(bon, JSON.stringify(exemple, null, 2));
    const mauvais = path.join(rep, "ancrage-invalide.json");
    fs.writeFileSync(mauvais, JSON.stringify({ ...exemple, checkpoint_interval_s: 7 }, null, 2));
    const env = { PATH: "/usr/bin:/bin", HTTPS_PROXY: "http://127.0.0.1:9", HTTP_PROXY: "http://127.0.0.1:9", NO_PROXY: "" };
    const lancer = (f) => spawnSync(process.execPath, [path.join(RACINE, "paquets", "ancrage", "bin", "noortrace-ancrage"), "configuration", f, "--profil", "production", "--checkpoint-interval", "60"], { encoding: "utf8", env, cwd: RACINE });
    const ok = lancer(bon);
    expect(ok.status, ok.stdout + ok.stderr).to.equal(0);
    expect(ok.stdout).to.match(/^configuration valide \(AN-1, profil production\)/);
    const ko = lancer(mauvais);
    expect(ko.status).to.equal(1);
    expect(D.validerSchemaDeploiement(exemple, D.chargerSchema("ancrage"))).to.deep.equal([]);
    expect(D.validerSchemaDeploiement({ ...exemple, checkpoint_interval_s: 7 }, D.chargerSchema("ancrage")).map((e) => e.chemin)).to.deep.equal(["/checkpoint_interval_s"]);
    const version = lireJSON(path.join(RACINE, "paquets", "ancrage", "package.json")).version;
    expect(version).to.match(/^[0-9]+\.[0-9]+\.[0-9]+$/);
  });
});

// ---------------------------------------------------------------------------
// Copies dérivées des runbooks
// ---------------------------------------------------------------------------

describe("CT-8 §10.12 à §10.19 (§10.11) : copies dérivées des runbooks RB-1 à RB-8", function () {
  const RUBRIQUES = ["Détection", "Impact sur la preuve", "Invariants", "Pas", "Vérification de sortie", "Événements journalisés", "Après l'incident"];

  it("Copies dérivées (§10.11) : deploiement/runbooks/RB-n.md égaux, octet pour octet, à la ligne de provenance suivie du bloc de CT-8 ; sept rubriques dans l'ordre d'EX-10.13 ; extraire-runbooks.mjs --verifier rend 0, et 1 sur une copie modifiée ou en trop", function () {
    const blocs = blocsRunbooks(CT8);
    expect(blocs.map((b) => [b.id, b.section])).to.deep.equal(Array.from({ length: 8 }, (_, k) => [`RB-${k + 1}`, `10.${12 + k}`]));
    expect(ecartsRunbooks(CT8, path.join(DEP, "runbooks"))).to.deep.equal([]);
    for (const b of blocs) {
      const t = fs.readFileSync(path.join(DEP, "runbooks", `${b.id}.md`), "utf8");
      expect(t).to.equal(`${provenance(b)}\n\n${b.bloc}`);
      expect(CT8.includes(b.bloc), b.id).to.equal(true);
      expect(b.bloc.startsWith(`### ${b.section} ${b.id} `)).to.equal(true);
      const positions = RUBRIQUES.map((r) => b.bloc.indexOf(`- **${r}.**`));
      expect(positions.every((p) => p > 0), `${b.id} : ${positions}`).to.equal(true);
      expect([...positions].sort((x, y) => x - y)).to.deep.equal(positions);
    }
    expect(outil("extraire-runbooks.mjs", ["--verifier"]).status).to.equal(0);
    const rep = path.join(TRAVAIL, "runbooks");
    expect(outil("extraire-runbooks.mjs", ["--sortie", rep]).status).to.equal(0);
    expect(outil("extraire-runbooks.mjs", ["--verifier", "--sortie", rep]).status).to.equal(0);
    fs.appendFileSync(path.join(rep, "RB-3.md"), "ajout\n");
    fs.writeFileSync(path.join(rep, "RB-9.md"), "x\n");
    const r = outil("extraire-runbooks.mjs", ["--verifier", "--sortie", rep]);
    expect(r.status).to.equal(1);
    expect(r.stdout).to.include("RB-3.md : différent du bloc de CT-8").and.to.include("RB-9.md : fichier sans runbook");
    expect(outil("extraire-runbooks.mjs", ["--x"]).status).to.equal(2);
    const sansRb = path.join(TRAVAIL, "ct8-sans-rb.md");
    fs.writeFileSync(sansRb, CT8.replace("### 10.15 RB-4", "### 10.15 RB-X"));
    expect(outil("extraire-runbooks.mjs", ["--verifier", "--spec", sansRb]).status).to.equal(2);
    expect(copiesRunbooks(CT8).size).to.equal(8);
  });

  it("Archive, IC-2, IC-16 : l'archive de déploiement emporte les runbooks, le script de préparation de l'hôte, les gabarits des tâches et les outils de sauvegarde et d'archivage, qui s'exécutent depuis l'archive sans le dépôt", function () {
    this.timeout(120000);
    const f = D.fichiersArchive();
    for (const k of [...Array.from({ length: 8 }, (_, i) => `deploiement/runbooks/RB-${i + 1}.md`), "deploiement/hote/preparer-hote.sh", "deploiement/taches/executer-tache.sh", "deploiement/taches/poser-taches.sh", "deploiement/taches/taches.env.modele", "deploiement/taches/systemd/noortrace-tache@.service", "deploiement/taches/systemd/noortrace-tp8.timer", "deploiement/config/rapide/ancrage.json", "scripts/deploiement/sauvegarde.mjs", "scripts/deploiement/archiver-journal-exploitation.mjs", "scripts/lib/sauvegarde.mjs"]) {
      expect(f.has(k), k).to.equal(true);
    }
    expect(f.has("scripts/deploiement/extraire-runbooks.mjs")).to.equal(false);
    const rep = path.join(TRAVAIL, "archive");
    expect(outil("construire-archive.mjs", ["--sortie", rep]).status).to.equal(0);
    const j = copieJournalVecteur("valide", path.join(TRAVAIL, "archive-journal"));
    const r = spawnSync(process.execPath, [path.join(rep, "scripts", "deploiement", "sauvegarde.mjs"), "creer", "--journal", j.racine, "--cles", j.cles, "--archive", path.join(TRAVAIL, "archive-s.tar"), "--pv", path.join(TRAVAIL, "archive-pv.json"), "--id", "pv-2026-11-12-002", "--executant", "e", "--motif", "m", "--source", "s", "--destination", "d"], { encoding: "utf8", cwd: rep, env: { PATH: "/usr/bin:/bin" } });
    expect(r.status, r.stderr).to.equal(0);
    expect(spawnSync("/bin/bash", ["-n", path.join(rep, "deploiement", "hote", "preparer-hote.sh")]).status).to.equal(0);
    const p = spawnSync("/bin/bash", [path.join(rep, "deploiement", "taches", "poser-taches.sh"), "--racine", rep, "--sortie", path.join(TRAVAIL, "archive-unites"), "--environnement", path.join(TRAVAIL, "archive-taches.env"), "--sans-activation"], { encoding: "utf8" });
    expect(p.status, p.stderr).to.equal(0);
  });
});
