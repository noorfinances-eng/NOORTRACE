// Étape 7 : images de conteneur noortrace/* et leur construction
// reproductible (CT-8 EX-3.5, EX-3.6, EX-3.7 à EX-3.9, EX-3.13, EX-4.4,
// CO-12 ; décisions D-1, D-2, D-12, D-13).
//
// Trois parties :
//   1. les fichiers de construction (conteneurs/<nom>/), lus sans
//      moteur de conteneurs : épinglage des images de base, étape finale sans
//      RUN, point d'entrée = programme, compte, /etc/passwd, répertoires et
//      modes, contextes filtrés ;
//   2. le pont stdio et le serveur de fichiers minimal du pont d'exemple
//      (conteneurs/pont-stdio/), éprouvés en processus, sans moteur ;
//   3. les images construites (TE-15, TM-24, TM-26, TM-28, base de TA-25),
//      en attente sans démon Docker ou sans les images
//      noortrace/<nom>:0.1.0 dans le magasin local (construites par
//      `node scripts/deploiement/construire-images.mjs`, qui joint les
//      registres publics : jamais par un essai).
//
// Aucun essai ne joint un réseau public : les conteneurs lancés ont
// `--network none`, et le projet Compose de l'installation rapide reçoit un
// fichier de surcharge qui rend ses réseaux `internal` (ni calendrier
// OpenTimestamps ni autre sortie).

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import * as pont from "../conteneurs/pont-stdio/noortrace-pont-stdio.mjs";
import * as fichiers from "../conteneurs/pont-stdio/serveur-fichiers.mjs";
import { IMAGES, controlerEpinglage, lignesFrom, lireMagasin } from "../scripts/deploiement/construire-images.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REP_IMAGES = path.join(RACINE, "conteneurs");
const PONT = path.join(REP_IMAGES, "pont-stdio", "noortrace-pont-stdio.mjs");
const SERVEUR_FICHIERS = path.join(REP_IMAGES, "pont-stdio", "serveur-fichiers.mjs");
const DESCRIPTION = JSON.parse(fs.readFileSync(path.join(RACINE, "deploiement", "images", "images.json"), "utf8"));
const COMPOSE = Object.fromEntries(["rapide", "production"].map((n) => [n, yaml.load(fs.readFileSync(path.join(RACINE, "deploiement", "compose", `${n}.yaml`), "utf8"))]));
const VERSION = "0.1.0";
const SOURCE_DATE_EPOCH = Number(spawnSync("git", ["-C", RACINE, "log", "-1", "--format=%ct"], { encoding: "utf8" }).stdout?.trim());

/** Programme, point d'entrée de chaque image (EX-3.6). */
const PROGRAMMES = {
  enregistreur: "noortrace",
  attributs: "noortrace-attributs",
  approbation: "noortrace-approbation",
  console: "noortrace-console",
  "pont-stdio": "noortrace-pont-stdio",
  verificateur: "noortrace-verifier",
  "tsa-interne": "noortrace-tsa-interne",
};

/**
 * Images de base admises, avec la date de publication relevée sur le registre
 * le 2026-11-12 (index par condensé) ; deux semaines au moins avant le
 * 2026-11-12 exigées (contraintes de l'étape 7).
 */
const BASES = {
  "node:22.23.4-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d": "2026-10-21",
  "gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f": "2026-08-21",
  "gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab": "2026-08-21",
  "golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5": "2026-10-21",
};

/**
 * Répertoires que les images DOIVENT créer (CT-8 EX-3.5), avec le compte, le
 * groupe et le mode. `/run/noortrace` porte en plus le bit collant (3770 au
 * lieu de 2770) : le démon refuse de créer sa prise dans un répertoire
 * inscriptible par le groupe sans ce bit (CT-2 EX-4.39, constat de l'étape 7 ;
 * demande de révision d'EX-3.5).
 */
const REPERTOIRES = {
  enregistreur: {
    "/var/lib/noortrace": "10001:10001:0700",
    "/var/log/noortrace": "10001:10001:0750",
    "/run/noortrace": "0:10010:3770",
    "/var/lib/noortrace-exports": "10001:10005:2750",
  },
  attributs: { "/var/lib/noortrace": "10001:10001:0700" },
  approbation: { "/var/lib/noortrace-approbation": "10002:10002:0700", "/run/noortrace": "0:10010:3770" },
  console: {},
  "pont-stdio": { "/srv/pieces": "10101:10101:0750" },
  verificateur: { "/var/lib/noortrace-exports": "10001:10005:2750" },
  "tsa-interne": { "/var/lib/noortrace-tsa": "10004:10004:0700" },
};

const serviceDe = (nom) => Object.entries(DESCRIPTION.services).find(([, s]) => s.image === `noortrace/${nom}`);
const lire = (...p) => fs.readFileSync(path.join(...p), "utf8");
const dockerfile = (nom) => lire(REP_IMAGES, nom, "Dockerfile");

/** Instructions de la dernière étape d'un Dockerfile (lignes continuées jointes). */
function etapeFinale(texte) {
  const lignes = texte.replace(/\\\n/g, " ").split("\n").filter((l) => l.trim() !== "" && !l.trim().startsWith("#"));
  const k = lignes.map((l) => /^FROM\s/i.test(l.trim())).lastIndexOf(true);
  return lignes.slice(k).map((l) => l.trim());
}

/** Répertoires créés par `install -d -o <u> -g <g> -m <mode> /out/<chemin>`. */
function repertoiresDeclares(texte) {
  const r = {};
  for (const m of texte.matchAll(/install -d -o ([0-9]+) -g ([0-9]+) -m ([0-7]{4}) \/out(\/[^\s;\\]+)/g)) r[m[4]] = `${m[1]}:${m[2]}:${m[3]}`;
  return r;
}

const pause = (ms) => new Promise((r) => setTimeout(r, ms));

describe("Étape 7 : images noortrace/* et construction reproductible (CT-8 §3.3, §3.6, EX-4.4)", function () {
  this.timeout(600000);

  describe("fichiers de construction, sans moteur de conteneurs", function () {
    it("EX-3.6 et images.json : un répertoire de construction par image noortrace/* construite depuis conteneurs/ (statut existante, révision 0.6 de CT-8), et les images des fichiers Compose en font partie", function () {
      const aConstruire = Object.values(DESCRIPTION.services)
        .filter((s) => s.image.startsWith("noortrace/") && s.image !== "noortrace/noorcore")
        .map((s) => {
          expect(s.status, s.image).to.equal("existante");
          expect(s.source, s.image).to.include(`conteneurs/${s.image.replace(/^noortrace\//, "")}/Dockerfile`);
          return s.image.replace(/^noortrace\//, "");
        });
      expect([...new Set(aConstruire)].sort()).to.deep.equal([...IMAGES].sort());
      for (const nom of IMAGES) {
        for (const f of ["Dockerfile", "Dockerfile.dockerignore", "passwd", "group"]) expect(fs.existsSync(path.join(REP_IMAGES, nom, f)), `${nom}/${f}`).to.equal(true);
      }
      for (const [fichier, c] of Object.entries(COMPOSE)) {
        for (const [svc, s] of Object.entries(c.services)) {
          const m = /^noortrace\/([a-z-]+):/.exec(s.image);
          if (m && m[1] !== "noorcore") expect(IMAGES, `${fichier}.yaml, ${svc}`).to.include(m[1]);
          expect(s, `${fichier}.yaml, ${svc} : CO-3`).to.not.have.property("build");
        }
      }
    });

    it("EX-3.13 : chaque FROM désigne son image de base par étiquette exacte et condensé, ou une étape antérieure ; chaque base a été publiée au moins deux semaines avant le 2026-11-12 ; aucune directive syntax", function () {
      for (const nom of IMAGES) {
        const texte = dockerfile(nom);
        expect(controlerEpinglage(texte), nom).to.deep.equal([]);
        const etapes = new Set();
        for (const { image, etape } of lignesFrom(texte)) {
          if (!etapes.has(image)) {
            expect(BASES, `${nom} : ${image}`).to.have.property(image);
            expect(BASES[image] <= "2026-10-29", `${nom} : ${image} publiée le ${BASES[image]}`).to.equal(true);
          }
          if (etape) etapes.add(etape);
        }
      }
      expect(controlerEpinglage("FROM node:22\n")).to.have.lengthOf(1);
      expect(controlerEpinglage("FROM node@sha256:" + "a".repeat(64) + "\n")).to.have.lengthOf(1);
      expect(controlerEpinglage("FROM node:latest@sha256:" + "a".repeat(64) + "\n")).to.have.lengthOf(1);
      expect(controlerEpinglage("# syntax=docker/dockerfile:1\nFROM node:22.23.4@sha256:" + "a".repeat(64) + "\n")).to.have.lengthOf(1);
    });

    it("CO-12, EX-4.4, EX-3.6 : l'étape finale n'exécute rien (aucun RUN, SHELL, CMD ni HEALTHCHECK), son point d'entrée est le programme en forme exec, son compte est celui de images.json, et le programme de la sonde des fichiers Compose y est installé", function () {
      for (const nom of IMAGES) {
        const finale = etapeFinale(dockerfile(nom));
        const [svc, s] = serviceDe(nom);
        for (const i of finale) expect(/^(RUN|SHELL|CMD|HEALTHCHECK|ONBUILD|VOLUME|ADD)\b/i.test(i), `${nom} : ${i}`).to.equal(false);
        expect(finale.filter((i) => /^ENTRYPOINT\b/i.test(i)), nom).to.deep.equal([`ENTRYPOINT ["/usr/local/bin/${PROGRAMMES[nom]}"]`]);
        expect(finale.filter((i) => /^USER\b/i.test(i)), nom).to.deep.equal([`USER ${s.user}`]);
        expect(finale, nom).to.include("WORKDIR /");
        if (s.probe.type === "commande") {
          expect(s.probe.test[0]).to.equal("CMD");
          const prog = s.probe.test[1];
          expect(prog.startsWith("/usr/local/bin/"), svc).to.equal(true);
          const texte = dockerfile(nom);
          expect(texte, `${nom} : lien ${prog}`).to.include("/out/usr/local/bin/");
          expect(texte.split(/[\s/;]+/), `${nom} : lien ${prog}`).to.include(path.basename(prog));
        }
      }
    });

    it("EX-3.5 : le /etc/passwd de chaque image nomme les comptes de images.json (noortrace et noortrace-approbation dans les deux images qui partagent la prise), et le compte du service", function () {
      for (const nom of IMAGES) {
        const [svc, s] = serviceDe(nom);
        const passwd = lire(REP_IMAGES, nom, "passwd").trim().split("\n").map((l) => l.split(":"));
        const group = lire(REP_IMAGES, nom, "group").trim().split("\n").map((l) => l.split(":"));
        for (const l of passwd) expect(l, `${nom}/passwd`).to.have.lengthOf(7);
        for (const l of group) expect(l, `${nom}/group`).to.have.lengthOf(4);
        const parNom = new Map(passwd.map((l) => [l[0], Number(l[2])]));
        for (const c of s.passwd) expect(parNom.get(c.name), `${svc} : ${c.name}`).to.equal(c.uid);
        const [uid, gid] = s.user.split(":").map(Number);
        expect(passwd.some((l) => Number(l[2]) === uid && Number(l[3]) === gid), `${svc} : compte ${s.user}`).to.equal(true);
        expect(group.some((l) => Number(l[2]) === gid), `${svc} : groupe ${gid}`).to.equal(true);
        expect(new Set(passwd.map((l) => l[2])).size, `${nom} : UID uniques`).to.equal(passwd.length);
        for (const l of passwd) expect(l[6], `${nom} : ${l[0]}`).to.equal("/sbin/nologin");
      }
    });

    it("EX-3.5, recopie dans un volume neuf : chaque image crée les répertoires exigés à leur compte et mode ; deux images qui montent un même volume nommé lui donnent les mêmes droits, quel que soit le premier conteneur qui le monte", function () {
      for (const nom of IMAGES) expect(repertoiresDeclares(dockerfile(nom)), nom).to.include(REPERTOIRES[nom]);
      for (const [fichier, c] of Object.entries(COMPOSE)) {
        const parVolume = new Map();
        for (const s of Object.values(c.services)) {
          const m = /^noortrace\/([a-z-]+):/.exec(s.image);
          if (!m || m[1] === "noorcore") continue;
          for (const v of s.volumes ?? []) if (v.type === "volume") parVolume.set(v.source, [...(parVolume.get(v.source) ?? []), { nom: m[1], cible: v.target }]);
        }
        for (const [vol, montages] of parVolume) {
          const droits = montages.map((x) => repertoiresDeclares(dockerfile(x.nom))[x.cible]);
          for (const [k, d] of droits.entries()) expect(d, `${fichier}.yaml, volume ${vol} : ${montages[k].nom} doit créer ${montages[k].cible}`).to.be.a("string");
          expect(new Set(droits).size, `${fichier}.yaml, volume ${vol} : ${JSON.stringify(montages)} → ${droits}`).to.equal(1);
        }
      }
    });

    it("EX-3.13 : chaque contexte de construction exclut tout par défaut (Dockerfile.dockerignore commence par *), et n'admet ni node_modules, ni secrets, ni l'état local", function () {
      for (const nom of IMAGES) {
        const lignes = lire(REP_IMAGES, nom, "Dockerfile.dockerignore").split("\n").filter((l) => l.trim() && !l.startsWith("#"));
        expect(lignes[0], nom).to.equal("*");
        for (const l of lignes.slice(1)) expect(/node_modules|secrets|\.env|\.git\b/.test(l), `${nom} : ${l}`).to.equal(false);
      }
    });

    it("EX-3.13 : le script de construction fixe SOURCE_DATE_EPOCH et rewrite-timestamp (exportateur OCI, archive chargée), construit sans cache et sans attestation, ne pousse rien, refuse le magasin d'images classique de Docker (rewrite-timestamp y est ignoré) ; les étapes Node.js installent par npm ci --omit=dev sans dépendance facultative ni script ; les programmes de bin/ reçoivent la ligne de lancement /usr/local/bin/node", function () {
      const script = lire(RACINE, "scripts", "deploiement", "construire-images.mjs");
      for (const m of ["type=oci,", "rewrite-timestamp=true", "SOURCE_DATE_EPOCH", "--no-cache", "--provenance=false", "--sbom=false", "linux/amd64", '"load", "-i"']) expect(script, m).to.include(m);
      // Sorties de `docker info --format '{{.Driver}} {{json .DriverStatus}}'` : Docker 29 (magasin containerd), Docker 28 par défaut (classique).
      expect(lireMagasin('overlayfs [["driver-type","io.containerd.snapshotter.v1"]]\n')).to.equal("containerd");
      expect(lireMagasin('overlay2 [["Backing Filesystem","extfs"],["Supports d_type","true"],["Using metacopy","false"],["Native Overlay Diff","true"],["userxattr","false"]]\n')).to.equal("classique (overlay2)");
      expect(/["']push["']/.test(script)).to.equal(false);
      for (const nom of ["enregistreur", "attributs", "approbation", "console"]) {
        const t = dockerfile(nom);
        expect(t, nom).to.match(/npm ci --omit=dev --omit=optional --omit=peer --ignore-scripts/);
        expect(t, nom).to.include("preparer-application /opt/noortrace");
      }
      for (const nom of IMAGES) expect(dockerfile(nom), `${nom} : heures des fichiers`).to.match(/ARG SOURCE_DATE_EPOCH\n/).and.to.include('touch -h -d "@${SOURCE_DATE_EPOCH}"');
      const prep = lire(REP_IMAGES, "commun", "preparer-application.sh");
      expect(prep).to.include('touch -h -d "@$SOURCE_DATE_EPOCH"');
      expect(prep).to.include("#!/usr/local/bin/node");
      expect(dockerfile("pont-stdio")).to.include("#!/usr/local/bin/node");
      for (const f of [PONT, SERVEUR_FICHIERS]) expect(lire(f).split("\n")[0]).to.equal("#!/usr/bin/env node");
    });
  });

  describe("serveur de fichiers minimal du dépôt (EX-3.8), en processus", function () {
    let racine;
    let dehors;
    before(function () {
      const base = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-fichiers-"));
      racine = path.join(base, "pieces");
      dehors = path.join(base, "dehors");
      fs.mkdirSync(path.join(racine, "sinistres"), { recursive: true });
      fs.mkdirSync(dehors);
      fs.writeFileSync(path.join(racine, "sinistres", "a.txt"), "déclaration\n");
      fs.writeFileSync(path.join(dehors, "secret.txt"), "hors racine\n");
      fs.symlinkSync(path.join(dehors, "secret.txt"), path.join(racine, "lien-dehors"));
      fs.symlinkSync(dehors, path.join(racine, "rep-dehors"));
      racine = fs.realpathSync(racine);
    });
    after(function () {
      fs.rmSync(path.dirname(racine), { recursive: true, force: true });
    });

    const appel = (nom, args, id = 1) => fichiers.traiterMessage(racine, { jsonrpc: "2.0", id, method: "tools/call", params: { name: nom, arguments: args } });

    it("initialize rend la version demandée si elle est connue, sinon la plus récente ; tools/list rend list_directory, read_file et write_file (noms de la configuration modèle de production) ; une méthode inconnue rend -32601, une notification aucune réponse", function () {
      const init = (v) => fichiers.traiterMessage(racine, { jsonrpc: "2.0", id: "e-1", method: "initialize", params: { protocolVersion: v, capabilities: {}, clientInfo: { name: "essai", version: "0" } } });
      expect(init("2025-06-18").result.protocolVersion).to.equal("2025-06-18");
      expect(init("2025-11-25").result.protocolVersion).to.equal("2025-11-25");
      expect(init("2099-01-01").result.protocolVersion).to.equal("2025-11-25");
      expect(init("2025-03-26").result.capabilities).to.deep.equal({ tools: { listChanged: false } });
      const outils = fichiers.traiterMessage(racine, { jsonrpc: "2.0", id: 2, method: "tools/list" }).result.tools.map((o) => o.name);
      const modele = JSON.parse(lire(RACINE, "deploiement", "config", "modele-production", "configuration.json")).policy.servers.fichiers.tools;
      expect(outils.sort()).to.deep.equal(Object.keys(modele).sort());
      expect(fichiers.traiterMessage(racine, { jsonrpc: "2.0", id: 3, method: "resources/list" }).error.code).to.equal(-32601);
      expect(fichiers.traiterMessage(racine, { jsonrpc: "2.0", method: "notifications/initialized" })).to.equal(null);
      expect(appel("effacer", { path: "a" }).error.code).to.equal(-32602);
    });

    it("list_directory, read_file et write_file sous la racine ; écriture par renommage, mode 0640 ; un chemin hors de la racine (.., absolu, lien symbolique vers l'extérieur) est refusé en isError sans rien lire ni écrire", function () {
      expect(appel("list_directory", { path: "." }).result.content[0].text).to.equal("[DIR] sinistres\n[LINK] lien-dehors\n[LINK] rep-dehors");
      expect(appel("read_file", { path: "sinistres/a.txt" }).result).to.deep.equal({ content: [{ type: "text", text: "déclaration\n" }], isError: false });
      expect(appel("read_file", { path: path.join(racine, "sinistres", "a.txt") }).result.isError).to.equal(false);
      const w = appel("write_file", { path: "sinistres/b.txt", content: "réponse" });
      expect(w.result.isError).to.equal(false);
      expect(fs.readFileSync(path.join(racine, "sinistres", "b.txt"), "utf8")).to.equal("réponse");
      expect(fs.statSync(path.join(racine, "sinistres", "b.txt")).mode & 0o777).to.equal(0o640 & ~process.umask());
      expect(fs.readdirSync(path.join(racine, "sinistres")).filter((n) => n.endsWith(".partiel"))).to.deep.equal([]);
      for (const [nom, args] of [
        ["read_file", { path: "../dehors/secret.txt" }],
        ["read_file", { path: path.join(dehors, "secret.txt") }],
        ["read_file", { path: "lien-dehors" }],
        ["list_directory", { path: "rep-dehors" }],
        ["write_file", { path: "rep-dehors/x.txt", content: "x" }],
        ["write_file", { path: "lien-dehors", content: "x" }],
        ["write_file", { path: "../x.txt", content: "x" }],
        ["read_file", { path: "a\0b" }],
        ["read_file", { path: "absent.txt" }],
      ]) {
        const r = appel(nom, args);
        expect(r.result.isError, `${nom} ${JSON.stringify(args)}`).to.equal(true);
      }
      expect(fs.readFileSync(path.join(dehors, "secret.txt"), "utf8")).to.equal("hors racine\n");
      expect(fs.readdirSync(dehors)).to.deep.equal(["secret.txt"]);
      expect(appel("write_file", { path: "gros.txt", content: "x".repeat(fichiers.OCTETS_MAX + 1) }).result.isError).to.equal(true);
    });

    it("programme stdio : un message par ligne, une ligne invalide reçoit -32700, fin à la fin de l'entrée (code 0) ; une racine relative est refusée (code 2)", function () {
      const entree = [
        JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "e", version: "0" } } }),
        JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
        "{pas du json",
        JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "read_file", arguments: { path: "sinistres/a.txt" } } }),
      ].join("\n");
      const r = spawnSync(process.execPath, [SERVEUR_FICHIERS, racine], { input: `${entree}\n`, encoding: "utf8" });
      expect(r.status).to.equal(0);
      const lignes = r.stdout.trim().split("\n").map((l) => JSON.parse(l));
      expect(lignes.map((l) => l.id)).to.deep.equal([1, null, 2]);
      expect(lignes[1].error.code).to.equal(-32700);
      expect(lignes[2].result.content[0].text).to.equal("déclaration\n");
      expect(spawnSync(process.execPath, [SERVEUR_FICHIERS, "pieces"], { encoding: "utf8" }).status).to.equal(2);
    });
  });

  describe("pont stdio vers Streamable HTTP (EX-3.7), en processus", function () {
    const JETON = "jeton-pont-essai-0123456789abcdef";
    let base;
    let racine;
    let instance;
    let port;
    let journal;

    const poster = (corps, entetes = {}) =>
      new Promise((resoudre, rejeter) => {
        const texte = typeof corps === "string" ? corps : JSON.stringify(corps);
        const req = http.request({ host: "127.0.0.1", port, path: entetes[":chemin"] ?? "/mcp", method: entetes[":methode"] ?? "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${JETON}`, ...Object.fromEntries(Object.entries(entetes).filter(([k]) => !k.startsWith(":"))) } }, (res) => {
          const m = [];
          res.on("data", (c) => m.push(c));
          res.on("end", () => {
            const t = Buffer.concat(m).toString("utf8");
            let json = null;
            try {
              json = t ? JSON.parse(t) : null;
            } catch {
              json = null;
            }
            resoudre({ statut: res.statusCode, entetes: res.headers, texte: t, json });
          });
        });
        req.on("error", rejeter);
        req.end(entetes[":methode"] === "GET" || entetes[":methode"] === "DELETE" ? undefined : texte);
      });
    const initialiser = () => poster({ jsonrpc: "2.0", id: "e-000000000001", method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "noortrace", version: "0.1.0" } } });

    before(async function () {
      base = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-pont-"));
      racine = path.join(base, "pieces");
      fs.mkdirSync(racine);
      fs.writeFileSync(path.join(racine, "a.txt"), "contenu\n");
      journal = [];
      const sortie = { write: (l) => journal.push(...l.trim().split("\n").map((x) => JSON.parse(x))) };
      instance = pont.creerPont({ ...pont.DEFAUTS, ecoute: { hote: "127.0.0.1", port: 0 }, jeton: JETON, sessionsMax: 2, delaiMs: 3000, octetsMax: 4096, commande: [process.execPath, SERVEUR_FICHIERS, racine] }, { journal: sortie });
      port = (await instance.ecouter()).port;
    });
    after(async function () {
      await instance.fermer();
      fs.rmSync(base, { recursive: true, force: true });
    });

    it("session : initialize ouvre un enfant et rend Mcp-Session-Id ; tools/call relayé et sa réponse rendue en application/json ; notification 202 ; DELETE termine l'enfant (204), la session devient inconnue (404) ; aucune ligne du journal du pont ne contient le jeton", async function () {
      const r = await initialiser();
      expect(r.statut).to.equal(200);
      expect(r.entetes["content-type"]).to.equal("application/json");
      expect(r.json.result.protocolVersion).to.equal("2025-11-25");
      const s = r.entetes["mcp-session-id"];
      expect(s).to.match(/^[0-9a-f]{32}$/);
      expect((await poster({ jsonrpc: "2.0", method: "notifications/initialized" }, { "mcp-session-id": s })).statut).to.equal(202);
      const appel = await poster({ jsonrpc: "2.0", id: "e-000000000002", method: "tools/call", params: { name: "read_file", arguments: { path: "a.txt" } } }, { "mcp-session-id": s });
      expect(appel.statut).to.equal(200);
      expect(appel.json).to.deep.equal({ jsonrpc: "2.0", id: "e-000000000002", result: { content: [{ type: "text", text: "contenu\n" }], isError: false } });
      expect(instance.sessions.size).to.equal(1);
      expect((await poster("", { "mcp-session-id": s, ":methode": "DELETE" })).statut).to.equal(204);
      expect(instance.sessions.size).to.equal(0);
      const apres = await poster({ jsonrpc: "2.0", id: 9, method: "tools/list" }, { "mcp-session-id": s });
      expect(apres.statut).to.equal(404);
      expect(apres.json.error.code).to.equal(-32001);
      await pause(200);
      expect(journal.map((l) => l.evenement)).to.include.members(["session_ouverte", "session_fermee", "enfant_termine"]);
      expect(JSON.stringify(journal)).to.not.include(JETON);
    });

    it("refus : sans jeton ou avec un autre jeton (401), en-tête Origin (403), GET (405), autre chemin (404), type de contenu (415), corps trop grand (413), lot JSON (400), JSON invalide (400, -32700), requête sans session hors initialize (400), initialize dans une session (400) ; /sante sans authentification (200)", async function () {
      const msg = { jsonrpc: "2.0", id: 1, method: "tools/list" };
      expect((await poster(msg, { authorization: "" })).statut).to.equal(401);
      expect((await poster(msg, { authorization: `Bearer ${JETON}x` })).statut).to.equal(401);
      expect((await poster(msg, { authorization: JETON })).statut).to.equal(401);
      expect((await poster(msg, { origin: "https://exemple.invalid" })).statut).to.equal(403);
      expect((await poster("", { ":methode": "GET" })).statut).to.equal(405);
      expect((await poster(msg, { ":chemin": "/autre" })).statut).to.equal(404);
      expect((await poster(msg, { "content-type": "text/plain" })).statut).to.equal(415);
      expect((await poster({ jsonrpc: "2.0", id: 1, method: "x", params: { p: "y".repeat(5000) } })).statut).to.equal(413);
      expect((await poster([msg])).statut).to.equal(400);
      const invalide = await poster("{");
      expect([invalide.statut, invalide.json.error.code]).to.deep.equal([400, -32700]);
      expect((await poster(msg)).statut).to.equal(400);
      const s = (await initialiser()).entetes["mcp-session-id"];
      expect((await poster({ jsonrpc: "2.0", id: 2, method: "initialize", params: {} }, { "mcp-session-id": s })).statut).to.equal(400);
      expect((await poster("", { "mcp-session-id": s, ":methode": "DELETE" })).statut).to.equal(204);
      const sante = await poster("", { ":chemin": "/sante", ":methode": "GET", authorization: "" });
      expect(sante.statut).to.equal(200);
      expect(sante.json.status).to.equal("ok");
    });

    it("bornes : au-delà de --sessions-max, 503 ; une requête en vol dont l'enfant se termine reçoit 502 et la session est close (404 ensuite) ; une requête sans réponse reçoit 504 après --delai-ms", async function () {
      const s1 = (await initialiser()).entetes["mcp-session-id"];
      const s2 = (await initialiser()).entetes["mcp-session-id"];
      expect((await initialiser()).statut).to.equal(503);
      const enfantDe = (s) => [...instance.sessions.values()].find((x) => x.id === s).enfant;
      // Requête en vol vers un enfant figé, puis tué : 502.
      const e2 = enfantDe(s2);
      e2.kill("SIGSTOP");
      const enVol = poster({ jsonrpc: "2.0", id: 5, method: "tools/list" }, { "mcp-session-id": s2 });
      await pause(300);
      e2.kill("SIGKILL");
      expect((await enVol).statut).to.equal(502);
      expect(instance.sessions.has(s2)).to.equal(false);
      expect((await poster({ jsonrpc: "2.0", id: 6, method: "tools/list" }, { "mcp-session-id": s2 })).statut).to.equal(404);
      // Délai : un enfant figé ne répond pas ; 504 après --delai-ms (3 000 ms ici).
      const e1 = enfantDe(s1);
      e1.kill("SIGSTOP");
      const t0 = Date.now();
      const lente = await poster({ jsonrpc: "2.0", id: 7, method: "tools/list" }, { "mcp-session-id": s1 });
      expect(lente.statut).to.equal(504);
      expect(Date.now() - t0).to.be.within(2900, 6000);
      e1.kill("SIGCONT");
      // La réponse tardive est ignorée ; la session sert la requête suivante.
      expect((await poster({ jsonrpc: "2.0", id: 8, method: "tools/list" }, { "mcp-session-id": s1 })).statut).to.equal(200);
      expect((await poster("", { "mcp-session-id": s1, ":methode": "DELETE" })).statut).to.equal(204);
    });

    it("programme : usage refusé (code 2, rien n'écoute) sans « -- », commande relative, écoute par nom, jeton lisible par le groupe, jeton avec saut de ligne ; arrêt par SIGTERM (code 0) ; sonde : 0 sur 200, 1 sur connexion refusée, 1 sur une adresse qui n'est pas de boucle locale (sans connexion)", async function () {
      const jeton = path.join(base, "jeton");
      fs.writeFileSync(jeton, JETON, { mode: 0o400 });
      const jetonOuvert = path.join(base, "jeton-ouvert");
      fs.writeFileSync(jetonOuvert, JETON, { mode: 0o640 });
      fs.chmodSync(jetonOuvert, 0o640);
      const jetonSaut = path.join(base, "jeton-saut");
      fs.writeFileSync(jetonSaut, `${JETON}\n`, { mode: 0o400 });
      const lancer = (args) => spawnSync(process.execPath, [PONT, ...args], { encoding: "utf8", timeout: 10000 });
      const cmd = ["--", process.execPath, SERVEUR_FICHIERS, racine];
      expect(lancer(["--ecoute", "127.0.0.1:0", "--jeton", jeton]).status).to.equal(2);
      expect(lancer(["--ecoute", "127.0.0.1:0", "--jeton", jeton, "--", "node", SERVEUR_FICHIERS]).status).to.equal(2);
      expect(lancer(["--ecoute", "localhost:9101", "--jeton", jeton, ...cmd]).status).to.equal(2);
      expect(lancer(["--ecoute", "127.0.0.1:0", "--jeton", jetonOuvert, ...cmd]).status).to.equal(2);
      expect(lancer(["--ecoute", "127.0.0.1:0", "--jeton", jetonSaut, ...cmd]).status).to.equal(2);
      expect(lancer(["--ecoute", "127.0.0.1:0", "--jeton", jeton, "--inconnue", "1", ...cmd]).status).to.equal(2);
      const p = spawn(process.execPath, [PONT, "--ecoute", "127.0.0.1:0", "--jeton", jeton, ...cmd], { stdio: ["ignore", "ignore", "pipe"] });
      let err = "";
      p.stderr.on("data", (c) => (err += c));
      await new Promise((r) => {
        const t = setInterval(() => {
          if (err.includes("demarrage")) {
            clearInterval(t);
            r();
          }
        }, 50);
      });
      const portLance = Number(/"ecoute":"127\.0\.0\.1:([0-9]+)"/.exec(err)[1]);
      expect(lancer(["sonde", "--url", `http://127.0.0.1:${portLance}/sante`]).status).to.equal(0);
      const code = new Promise((r) => p.once("exit", r));
      p.kill("SIGTERM");
      expect(await code).to.equal(0);
      expect(lancer(["sonde", "--url", `http://127.0.0.1:${portLance}/sante`]).status).to.equal(1);
      for (const url of ["http://192.0.2.1:9101/sante", "http://localhost:9101/sante", "https://127.0.0.1:9101/sante", "http://u:p@127.0.0.1:9101/sante"]) {
        const r = lancer(["sonde", "--url", url]);
        expect(r.status, url).to.equal(1);
      }
      expect(lancer(["sonde"]).status).to.equal(1);
    });
  });

  describe("images construites (TE-15, TM-24, TM-26, TM-28, base de TA-25)", function () {
    const ETIQUETTES = IMAGES.map((n) => `noortrace/${n}:${VERSION}`);
    const nettoyage = { conteneurs: new Set(), volumes: new Set(), images: new Set(), repertoires: new Set(), projets: [] };
    const suffixe = crypto.randomBytes(4).toString("hex");
    let etat;

    const docker = (args, o = {}) => spawnSync("docker", args, { encoding: "utf8", maxBuffer: 256 * 1024 * 1024, timeout: o.timeout ?? 300000, input: o.input });
    const dockerOk = (args, o) => {
      const r = docker(args, o);
      if (r.status !== 0) throw new Error(`docker ${args.join(" ")} : code ${r.status} : ${r.stderr}`);
      return r.stdout;
    };
    const volume = (nom) => {
      const v = `noortrace-essai-images-${suffixe}-${nom}`;
      dockerOk(["volume", "create", v]);
      nettoyage.volumes.add(v);
      return v;
    };
    /** stat d'un chemin vu par la racine d'un conteneur de l'image de l'enregistreur. */
    const statVolume = (v, chemin = "/v") =>
      JSON.parse(
        dockerOk(["run", "--rm", "--network", "none", "--user", "0:0", "-v", `${v}:/v`, "--entrypoint", "/usr/local/bin/node", `noortrace/enregistreur:${VERSION}`, "-e", `const s=require("fs").statSync(${JSON.stringify(chemin)});console.log(JSON.stringify({uid:s.uid,gid:s.gid,mode:(s.mode&0o7777).toString(8).padStart(4,"0")}))`]),
      );

    before(function () {
      const info = docker(["info", "--format", "{{.ServerVersion}}"]);
      if (info.status !== 0) {
        etat = { ok: false, condition: "Docker absent ou démon dockerd injoignable" };
        return;
      }
      const absentes = ETIQUETTES.filter((e) => docker(["image", "inspect", e]).status !== 0);
      etat = absentes.length
        ? { ok: false, condition: `images absentes du magasin local (${absentes.join(", ")}) : node scripts/deploiement/construire-images.mjs (la construction joint les registres publics ; un essai ne construit pas)` }
        : { ok: true };
    });
    beforeEach(function () {
      if (!etat.ok) {
        this.currentTest.title += ` — en attente : ${etat.condition}`;
        this.skip();
      }
    });
    after(function () {
      // Les répertoires où un conteneur a donné des fichiers à 10001, 10002 ou 10101 sont rendus
      // au compte de l'essai avant d'être supprimés (un compte non root ne peut pas vider un
      // répertoire qui ne lui appartient plus).
      if (etat?.ok) {
        for (const r of nettoyage.repertoires) {
          spawnSync("docker", ["run", "--rm", "--network", "none", "--user", "0:0", "-v", `${r}:/t`, "--entrypoint", "/usr/local/bin/node", `noortrace/enregistreur:${VERSION}`, "-e", `const fs=require("fs"),p=require("path");const f=(x)=>{fs.lchownSync(x,${process.getuid?.() ?? 0},${process.getgid?.() ?? 0});if(fs.lstatSync(x).isDirectory()){fs.chmodSync(x,0o700);for(const n of fs.readdirSync(x))f(p.join(x,n));}};f("/t")`], { encoding: "utf8" });
        }
      }
      for (const p of nettoyage.projets) spawnSync("docker", ["compose", ...p, "down", "-v", "--remove-orphans"], { encoding: "utf8" });
      for (const c of nettoyage.conteneurs) spawnSync("docker", ["rm", "-f", "-v", c], { encoding: "utf8" });
      for (const v of nettoyage.volumes) spawnSync("docker", ["volume", "rm", "-f", v], { encoding: "utf8" });
      for (const i of nettoyage.images) spawnSync("docker", ["image", "rm", "-f", i], { encoding: "utf8" });
      for (const r of nettoyage.repertoires) fs.rmSync(r, { recursive: true, force: true });
    });

    it("TE-15, EX-4.4, EX-3.6 : docker inspect de chaque image : point d'entrée = programme, sans Cmd, compte de images.json, répertoire de travail /, plate-forme linux/amd64, créée à SOURCE_DATE_EPOCH (date du commit)", function () {
      for (const nom of IMAGES) {
        const [, s] = serviceDe(nom);
        const i = JSON.parse(dockerOk(["image", "inspect", `noortrace/${nom}:${VERSION}`]))[0];
        expect(i.Config.Entrypoint, nom).to.deep.equal([`/usr/local/bin/${PROGRAMMES[nom]}`]);
        expect(i.Config.Cmd ?? null, nom).to.equal(null);
        expect(i.Config.User, nom).to.equal(s.user);
        expect(i.Config.WorkingDir, nom).to.equal("/");
        expect(`${i.Os}/${i.Architecture}`, nom).to.equal("linux/amd64");
        expect(Date.parse(i.Created) / 1000, `${nom} : ${i.Created}`).to.equal(SOURCE_DATE_EPOCH);
        expect(i.Config.Labels["org.opencontainers.image.version"], nom).to.equal(VERSION);
      }
    });

    it("TE-15, CO-12, EX-4.4 : système de fichiers de chaque image (docker export) : aucun interpréteur de commandes ni /usr/bin/env ; programmes requis présents (flock pour le bail file, chattr et lsattr pour le compagnon) ; /etc/passwd et /etc/group du dépôt ; répertoires d'EX-3.5 aux comptes et modes ; lancement de /bin/sh impossible", function () {
      const interdits = ["bin/sh", "bin/bash", "bin/dash", "bin/ash", "bin/busybox", "usr/bin/env", "usr/bin/sh", "usr/bin/bash", "usr/bin/perl", "usr/bin/python3", "usr/local/bin/python3", "sbin/apk", "usr/bin/apt", "usr/bin/dpkg"];
      const requis = {
        enregistreur: ["usr/local/bin/node", "usr/bin/flock", "usr/local/bin/noortrace", "usr/local/bin/noortrace-ctl"],
        attributs: ["usr/local/bin/node", "usr/bin/chattr", "usr/bin/lsattr", "usr/local/bin/noortrace-attributs"],
        approbation: ["usr/local/bin/node", "usr/local/bin/noortrace-approbation"],
        console: ["usr/local/bin/node", "usr/local/bin/noortrace-console"],
        "pont-stdio": ["usr/local/bin/node", "usr/local/bin/noortrace-pont-stdio", "opt/mcp/server-filesystem/bin/server-filesystem"],
        verificateur: ["usr/local/bin/noortrace-verifier"],
        "tsa-interne": ["usr/local/bin/node", "usr/local/bin/noortrace-tsa-interne"],
      };
      const versOctal = (perm) => {
        let m = 0;
        const t = perm.slice(1);
        const bits = [0o400, 0o200, 0o100, 0o40, 0o20, 0o10, 0o4, 0o2, 0o1];
        for (let k = 0; k < 9; k++) if (!["-", "S", "T"].includes(t[k])) m |= bits[k];
        if (/[sS]/.test(t[2])) m |= 0o4000;
        if (/[sS]/.test(t[5])) m |= 0o2000;
        if (/[tT]/.test(t[8])) m |= 0o1000;
        return m.toString(8).padStart(4, "0");
      };
      for (const nom of IMAGES) {
        const c = dockerOk(["create", `noortrace/${nom}:${VERSION}`]).trim();
        nettoyage.conteneurs.add(c);
        const r = spawnSync("bash", ["-o", "pipefail", "-c", `docker export ${c} | tar -tv --numeric-owner -f -`], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
        expect(r.status, `${nom} : ${r.stderr}`).to.equal(0);
        const entrees = new Map();
        for (const l of r.stdout.split("\n").filter(Boolean)) {
          const m = /^(\S{10}) ([0-9]+)\/([0-9]+)\s+[0-9]+ \S+ \S+ (.+?)(?: -> (.+))?$/.exec(l);
          if (m) entrees.set(m[4].replace(/\/$/, ""), { type: m[1][0], uid: m[2], gid: m[3], mode: versOctal(m[1]), cible: m[5] ?? null });
        }
        for (const f of interdits) expect(entrees.has(f), `${nom} : ${f}`).to.equal(false);
        for (const f of requis[nom]) expect(entrees.has(f), `${nom} : ${f}`).to.equal(true);
        for (const [rep, attendu] of Object.entries(REPERTOIRES[nom])) {
          const e = entrees.get(rep.slice(1));
          expect(e, `${nom} : ${rep}`).to.not.equal(undefined);
          expect(`${e.uid}:${e.gid}:${e.mode}`, `${nom} : ${rep}`).to.equal(attendu);
        }
        const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-passwd-"));
        nettoyage.repertoires.add(tmp);
        for (const f of ["passwd", "group"]) {
          dockerOk(["cp", `${c}:/etc/${f}`, path.join(tmp, f)]);
          expect(fs.readFileSync(path.join(tmp, f), "utf8"), `${nom} : /etc/${f}`).to.equal(lire(REP_IMAGES, nom, f));
        }
        const sh = docker(["run", "--rm", "--network", "none", "--entrypoint", "/bin/sh", `noortrace/${nom}:${VERSION}`, "-c", "true"]);
        expect(sh.status, nom).to.not.equal(0);
        expect(sh.stderr, nom).to.match(/no such file or directory|not found/i);
      }
    });

    // Étape 7 : la licence de Node.js manquait aux images
    // qui en portent le binaire. Elle vient de l'image de construction, dont
    // /usr/local/LICENSE et /usr/local/bin/node sont ceux de l'archive officielle
    // node-v22.23.4-linux-x64.tar.xz (SHA-256 relevés le 2026-11-12, contrôlés à la construction).
    it("licences : les six images Node.js portent /usr/share/doc/nodejs/LICENSE (0:0, 0644), égal au LICENSE de l'archive officielle de Node.js 22.23.4, dont /usr/local/bin/node est le binaire ; LICENSE et NOTICE du projet sous /usr/share/doc/noortrace/ ; licence MIT de chaque dépendance npm (@noble/*) dans node_modules", function () {
      const SHA_LICENCE = "c738ae413cf561f174e34f6961f8ca458aae2369a73640dda6234c629b98bcc4";
      const SHA_NODE = "94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90";
      const sha = (f) => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");
      for (const nom of ["enregistreur", "attributs", "approbation", "console", "pont-stdio", "tsa-interne"]) {
        const c = dockerOk(["create", `noortrace/${nom}:${VERSION}`]).trim();
        nettoyage.conteneurs.add(c);
        const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-licences-"));
        nettoyage.repertoires.add(tmp);
        dockerOk(["cp", `${c}:/usr/share/doc/nodejs/LICENSE`, path.join(tmp, "LICENSE-nodejs")]);
        dockerOk(["cp", `${c}:/usr/local/bin/node`, path.join(tmp, "node")]);
        expect(sha(path.join(tmp, "LICENSE-nodejs")), `${nom} : licence de Node.js`).to.equal(SHA_LICENCE);
        expect(sha(path.join(tmp, "node")), `${nom} : binaire de Node.js`).to.equal(SHA_NODE);
        const liste = spawnSync("bash", ["-o", "pipefail", "-c", `docker export ${c} | tar -tv --numeric-owner -f - usr/share/doc/nodejs/LICENSE usr/share/doc/noortrace/LICENSE usr/share/doc/noortrace/NOTICE`], { encoding: "utf8" });
        expect(liste.status, `${nom} : ${liste.stderr}`).to.equal(0);
        for (const l of liste.stdout.trim().split("\n")) expect(l, nom).to.match(/^-rw-r--r-- 0\/0 /);
        if (nom !== "pont-stdio") {
          const noble = docker(["run", "--rm", "--network", "none", "--entrypoint", "/usr/local/bin/node", `noortrace/${nom}:${VERSION}`, "-e", "const fs=require('fs'),p=require('path');const r=[];const v=(d)=>{for(const e of fs.readdirSync(d,{withFileTypes:true})){const f=p.join(d,e.name);if(e.isDirectory()&&!e.isSymbolicLink()){if(/@noble\\/[a-z]+$/.test(f))r.push([f,fs.existsSync(p.join(f,'LICENSE'))]);else v(f)}}};v('/opt/noortrace');console.log(JSON.stringify(r))"]);
          const paquets = JSON.parse(noble.stdout);
          expect(paquets.length, `${nom} : dépendances @noble`).to.be.at.least(1);
          for (const [f, licence] of paquets) expect(licence, `${nom} : ${f}/LICENSE`).to.equal(true);
        }
      }
    });

    it("TE-15, recopie dans un volume neuf : la racine d'un volume nommé neuf reprend le propriétaire, le groupe et le mode (bits setgid et collant compris) du répertoire de l'image qui le monte la première, montage en lecture seule compris ; après recopie par l'image du service d'approbation, le démon (10001, groupe 10010) crée sa prise dans /run/noortrace", function () {
      const cas = [
        ["enregistreur", "/var/lib/noortrace"],
        ["enregistreur", "/var/log/noortrace"],
        ["enregistreur", "/run/noortrace"],
        ["enregistreur", "/var/lib/noortrace-exports"],
        ["attributs", "/var/lib/noortrace"],
        ["approbation", "/run/noortrace"],
        ["approbation", "/var/lib/noortrace-approbation"],
        ["verificateur", "/var/lib/noortrace-exports", "ro"],
      ];
      const argsSortie = { enregistreur: ["--version"], attributs: ["--une-fois", "--racine", "/nulle-part"], approbation: ["--version"], verificateur: ["--version"] };
      for (const [nom, cible, ro] of cas) {
        const v = volume(`${nom}-${path.basename(cible)}`);
        const [, s] = serviceDe(nom);
        docker(["run", "--rm", "--network", "none", "--read-only", "--user", s.user, "-v", `${v}:${cible}${ro ? ":ro" : ""}`, `noortrace/${nom}:${VERSION}`, ...argsSortie[nom]]);
        const st = statVolume(v);
        expect(`${st.uid}:${st.gid}:${st.mode}`, `${nom} ${cible}${ro ? " (ro)" : ""}`).to.equal(REPERTOIRES[nom][cible]);
      }
      const prises = volume("prises-partagees");
      dockerOk(["run", "--rm", "--network", "none", "--read-only", "--user", "10002:10002", "--group-add", "10010", "-v", `${prises}:/run/noortrace`, "--entrypoint", "/usr/local/bin/node", `noortrace/approbation:${VERSION}`, "-e", "require('net').createServer().listen('/run/noortrace/approbation.sock',function(){this.close()})"]);
      const sortie = dockerOk(["run", "--rm", "--network", "none", "--read-only", "--user", "10001:10001", "--group-add", "10010", "-v", `${prises}:/run/noortrace`, "--entrypoint", "/usr/local/bin/node", `noortrace/enregistreur:${VERSION}`, "-e", "const n=require('net');const s=n.createServer().listen('/run/noortrace/mcp.sock',()=>{const st=require('fs').statSync('/run/noortrace/mcp.sock');console.log(st.uid+':'+st.gid);s.close()})"]);
      expect(sortie.trim()).to.equal("10001:10010");
    });

    it("TE-15, IR-5, IR-6 : installation rapide (rapide.yaml du dépôt, secrets d'IR-2, configurations d'IR-3, réseaux rendus internes) : validate-config et valider-configuration rendent 0 ; enregistreur et approbation healthy ; docker inspect tient images.json (compte, groupe 10010, racine en lecture seule, capacités retirées, no-new-privileges) ; noortrace-ctl sonde en forme exec rend 0 ; le bail file tient flock(1) sans interpréteur ; volumes recopiés aux droits d'EX-3.5", async function () {
      const T = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-rapide-"));
      nettoyage.repertoires.add(T);
      fs.cpSync(path.join(RACINE, "deploiement", "compose"), path.join(T, "compose"), { recursive: true });
      fs.mkdirSync(path.join(T, "config", "rapide"), { recursive: true });
      for (const f of ["configuration.json", "ancrage.json"]) fs.copyFileSync(path.join(RACINE, "deploiement", "config", "rapide", f), path.join(T, "config", "rapide", f));
      // IR-2 : clé Ed25519 en PKCS#8 DER, secrets de 32 octets en hexadécimal, 0400.
      fs.mkdirSync(path.join(T, "secrets"), { mode: 0o700 });
      const secrets = path.join(T, "secrets");
      fs.writeFileSync(path.join(secrets, "cle-enregistreur"), crypto.generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "der" }), { mode: 0o400 });
      const declares = Object.keys(COMPOSE.rapide.secrets);
      for (const n of declares.filter((x) => x !== "cle-enregistreur")) fs.writeFileSync(path.join(secrets, n), crypto.randomBytes(32).toString("hex"), { mode: 0o400 });
      // IR-3 : configuration du service, telle que CT-8 §7.2 l'écrit.
      const r = JSON.parse(fs.readFileSync(path.join(T, "config", "rapide", "configuration.json"), "utf8")).recorder;
      const approbation = { version: 0, environment: "developpement", org: "organisation-exemple", org_id: r.org_id, journal_id: r.journal_id, state_dir: "/var/lib/noortrace-approbation", storage_key: { file: "/run/secrets/cle-stockage-approbation" }, noyau: { socket: "/run/noortrace/approbation.sock", socket_mode: "0660", tcp: null, tls: null, token: null }, console: null, etat: { host: "127.0.0.1", port: 8601 }, administrators: ["utilisateur console.invalid administrateur"], console_origin: "https://console.invalid", notifications: null, rpc: null };
      fs.writeFileSync(path.join(T, "config", "rapide", "approbation.json"), `${JSON.stringify(approbation, null, 2)}\n`, { mode: 0o400 });
      fs.chmodSync(path.join(T, "config", "rapide", "configuration.json"), 0o400);
      // Propriétaires d'IR-2 et IR-3 (chown par la racine d'un conteneur : l'essai n'exige pas d'être root sur l'hôte).
      const chown = { "secrets/cle-stockage-approbation": "10002:10002", "config/rapide/approbation.json": "10002:10002", "config/rapide/configuration.json": "10001:10001" };
      for (const n of declares) chown[`secrets/${n}`] ??= "10001:10001";
      dockerOk(["run", "--rm", "--network", "none", "--user", "0:0", "-v", `${T}:/t`, "--entrypoint", "/usr/local/bin/node", `noortrace/enregistreur:${VERSION}`, "-e", `for (const [f,c] of Object.entries(${JSON.stringify(chown)})) { const [u,g]=c.split(":").map(Number); require("fs").chownSync("/t/"+f,u,g); }`]);
      fs.writeFileSync(path.join(T, "sans-sortie.yaml"), "networks:\n  hotes:\n    internal: true\n  sortie:\n    internal: true\n");
      const projet = ["-p", `noortrace-essai-images-${suffixe}`, "--project-directory", T, "-f", path.join(T, "compose", "rapide.yaml"), "-f", path.join(T, "sans-sortie.yaml")];
      nettoyage.projets.push(projet);
      const dc = (args, o) => docker(["compose", ...projet, ...args], o);
      const v1 = dc(["run", "--rm", "--no-deps", "enregistreur", "validate-config", "/etc/noortrace/configuration.json"]);
      expect(v1.status, v1.stderr).to.equal(0);
      const v2 = dc(["run", "--rm", "--no-deps", "approbation", "valider-configuration", "/etc/noortrace-approbation/configuration.json"]);
      expect(v2.status, v2.stderr).to.equal(0);
      expect(v2.stdout.trim().split("\n").at(-1)).to.equal('{"valide":true,"errors":[]}');
      const up = dc(["up", "-d", "enregistreur", "approbation"]);
      expect(up.status, up.stderr).to.equal(0);
      const sante = () => Object.fromEntries(dc(["ps", "--format", "{{.Service}}={{.Health}}"]).stdout.trim().split("\n").map((l) => l.split("=")));
      const t0 = Date.now();
      let h = {};
      while (Date.now() - t0 < 150000) {
        h = sante();
        if (h.enregistreur === "healthy" && h.approbation === "healthy") break;
        await pause(2000);
      }
      expect(h, dc(["logs", "--tail", "20"]).stdout).to.deep.equal({ approbation: "healthy", enregistreur: "healthy" });
      console.log(`      ir6_sain_s ${Math.round((Date.now() - t0) / 1000)} (enregistreur et approbation healthy après up -d)`);
      for (const svc of ["enregistreur", "approbation"]) {
        const id = dc(["ps", "-q", svc]).stdout.trim();
        const i = JSON.parse(dockerOk(["inspect", id]))[0];
        const d = DESCRIPTION.services[svc];
        expect(i.Config.User, svc).to.equal(d.user);
        expect(i.HostConfig.GroupAdd, svc).to.deep.equal(d.group_add);
        expect(i.HostConfig.ReadonlyRootfs, svc).to.equal(true);
        expect(i.HostConfig.CapDrop, svc).to.deep.equal(["ALL"]);
        expect(i.HostConfig.CapAdd ?? [], svc).to.deep.equal(d.cap_add);
        expect(i.HostConfig.SecurityOpt, svc).to.include("no-new-privileges:true");
        expect(i.State.Health.Status, svc).to.equal("healthy");
        expect(i.Image, svc).to.equal(JSON.parse(dockerOk(["image", "inspect", `noortrace/${svc}:${VERSION}`]))[0].Id);
      }
      const sonde = dc(["exec", "-T", "enregistreur", "/usr/local/bin/noortrace-ctl", "sonde", "--url", "http://127.0.0.1:8500/readyz"]);
      expect([sonde.status, sonde.stdout.trim()]).to.deep.equal([0, "200"]);
      const top = dockerOk(["top", dc(["ps", "-q", "enregistreur"]).stdout.trim(), "-o", "pid,user,args"]);
      expect(top).to.match(/10001\s+flock --exclusive --nonblock --close --conflict-exit-code 75 \/var\/lib\/noortrace\/bail \/usr\/local\/bin\/node -e/);
      expect(top).to.not.match(/\/bin\/sh|\bcat\b/);
      for (const [vol, attendu] of [["journal", "10001:10001:0700"], ["exploitation", "10001:10001:0750"], ["prises", "0:10010:3770"], ["exports", "10001:10005:2750"], ["approbation-etat", "10002:10002:0700"]]) {
        const st = statVolume(`noortrace-essai-images-${suffixe}_${vol}`);
        expect(`${st.uid}:${st.gid}:${st.mode}`, vol).to.equal(attendu);
      }
    });

    it("TE-6, IR-1 à IR-8 avec Docker : installation rapide réelle depuis l'archive (rapide.yaml du dépôt, réseaux rendus internes, serveur d'outils factice sur le réseau interne) : autorité du serveur interne créée par horodatage-init, document d'ancrage écrit par configurer-rapide ; enregistreur, approbation et horodatage healthy ; appel d'agent enregistré ; close-period --now ; jeton RFC 3161 du serveur interne dans le dossier exporté ; vérificateur de référence et noortrace-verifier : contrôle 4 réussi contre l'AC du serveur, contrôle 5 non exécuté sans preuve OpenTimestamps (calendriers injoignables)", async function () {
      const openssl = spawnSync("openssl", ["version"], { encoding: "utf8" });
      if (openssl.status !== 0) {
        this.test.title += " — en attente : openssl absent (certificats du serveur d'outils factice)";
        this.skip();
      }
      // Les projets d'essai précédents sont arrêtés : un seul projet à la fois (mémoire, disque).
      for (const p of nettoyage.projets.splice(0)) spawnSync("docker", ["compose", ...p, "down", "-v", "--remove-orphans"], { encoding: "utf8" });
      const T = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-installation-rapide-"));
      nettoyage.repertoires.add(T);
      const duree = {};
      let t0 = Date.now();
      const mesurer = (pas) => {
        duree[pas] = Math.round((Date.now() - t0) / 1000);
        t0 = Date.now();
      };
      // IR-1 : archive de déploiement écrite par l'outil de la version (sans téléchargement).
      const archive = path.join(T, "archive");
      const a = spawnSync(process.execPath, [path.join(RACINE, "scripts", "deploiement", "construire-archive.mjs"), "--sortie", archive], { encoding: "utf8" });
      expect(a.status, a.stderr).to.equal(0);
      const dep = path.join(archive, "deploiement");
      mesurer("ir1");
      // Serveur d'outils factice (banc) : TLS signé par une AC de l'essai, nom du serveur de la configuration de référence.
      const outils = path.join(T, "outils");
      fs.mkdirSync(outils);
      for (const f of ["serveur-outils.mjs", "agent.mjs"]) fs.copyFileSync(path.join(RACINE, "test", "fixtures", "installation-rapide", f), path.join(outils, f));
      const ossl = (args) => {
        const r = spawnSync("openssl", args, { cwd: outils, encoding: "utf8" });
        if (r.status !== 0) throw new Error(`openssl ${args.join(" ")} : ${r.stderr}`);
      };
      ossl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.cle.pem", "-out", "ca.pem", "-days", "2", "-subj", "/CN=AC de l'essai du serveur d'outils"]);
      ossl(["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "cle.pem", "-out", "req.pem", "-subj", "/CN=outils.interne.example"]);
      fs.writeFileSync(path.join(outils, "ext.cnf"), "subjectAltName=DNS:outils.interne.example\nextendedKeyUsage=serverAuth\n");
      ossl(["x509", "-req", "-in", "req.pem", "-CA", "ca.pem", "-CAkey", "ca.cle.pem", "-CAcreateserial", "-out", "certificat.pem", "-days", "2", "-extfile", "ext.cnf"]);
      for (const f of fs.readdirSync(outils)) fs.chmodSync(path.join(outils, f), 0o444);
      fs.writeFileSync(path.join(T, "sans-sortie.yaml"), "networks:\n  hotes:\n    internal: true\n  sortie:\n    internal: true\n");
      fs.writeFileSync(
        path.join(T, "outils.yaml"),
        `services:\n  enregistreur:\n    volumes:\n      - type: bind\n        source: ${outils}/ca.pem\n        target: /etc/noortrace/outils-ca.pem\n        read_only: true\n  outils-factice:\n    image: noortrace/enregistreur:${VERSION}\n    entrypoint: ["/usr/local/bin/node", "/outils/serveur-outils.mjs", "/outils/cle.pem", "/outils/certificat.pem", "443"]\n    user: "65534:65534"\n    read_only: true\n    volumes:\n      - type: bind\n        source: ${outils}\n        target: /outils\n        read_only: true\n    networks:\n      sortie:\n        aliases:\n          - outils.interne.example\n`,
      );
      const projet = ["-p", `noortrace-essai-rapide-${suffixe}`, "--project-directory", dep, "-f", path.join(dep, "compose", "rapide.yaml"), "-f", path.join(T, "sans-sortie.yaml"), "-f", path.join(T, "outils.yaml")];
      nettoyage.projets.push(projet);
      const dc = (args, o) => docker(["compose", ...projet, ...args], o);
      const dcOk = (args, o) => {
        const r = dc(args, o);
        if (r.status !== 0) throw new Error(`docker compose ${args.join(" ")} : code ${r.status} : ${r.stderr}`);
        return r.stdout;
      };
      // IR-2 : secrets, autorité du serveur interne, certificat de l'AC et CRL.
      const secrets = path.join(dep, "secrets");
      fs.mkdirSync(secrets, { mode: 0o700 });
      fs.writeFileSync(path.join(secrets, "cle-enregistreur"), crypto.generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "der" }), { mode: 0o400 });
      for (const n of ["cle-mac-relais", "jeton-hote", "jeton-passerelle", "cle-stockage-approbation"]) fs.writeFileSync(path.join(secrets, n), crypto.randomBytes(32).toString("hex"), { mode: 0o400 });
      expect(Object.keys(COMPOSE.rapide.secrets).sort()).to.deep.equal(["cle-enregistreur", "cle-mac-relais", "cle-stockage-approbation", "jeton-hote", "jeton-passerelle"]);
      const init = dcOk(["--profile", "outils", "run", "--rm", "-T", "horodatage-init", "init", "--repertoire", "/var/lib/noortrace-tsa", "--politique", "1.3.6.1.4.1.99999.1.1", "--crl-url", "http://127.0.0.1:2020/crl.pem", "--algorithme", "p-256"]);
      expect(init).to.include("autorité créée dans /var/lib/noortrace-tsa");
      const acPem = dcOk(["--profile", "outils", "run", "--rm", "-T", "horodatage-init", "ac", "--repertoire", "/var/lib/noortrace-tsa"]);
      expect(new crypto.X509Certificate(acPem).ca).to.equal(true);
      const ficAc = path.join(dep, "config", "rapide", "ac-horodatage.pem");
      fs.writeFileSync(ficAc, acPem);
      mesurer("ir2");
      // IR-3 : configuration de l'enregistreur et document d'ancrage (configurer-rapide), configuration du service.
      const ir3 = spawnSync(process.execPath, [path.join(archive, "scripts", "deploiement", "configurer-rapide.mjs"), "--org", "organisation-exemple", "--journal", "journal-rapide", "--serveur-outils", "https://outils.interne.example/mcp", "--sortie", path.join(dep, "config", "rapide", "configuration.json"), "--ac-horodatage", ficAc, "--sortie-ancrage", path.join(dep, "config", "rapide", "ancrage.json")], { encoding: "utf8", cwd: dep });
      expect(ir3.status, ir3.stderr).to.equal(0);
      expect(ir3.stdout).to.match(/\nancrage_sha256 [0-9a-f]{64}\nconfiguration valide\n$/);
      const doc = JSON.parse(fs.readFileSync(path.join(dep, "config", "rapide", "ancrage.json"), "utf8"));
      expect(doc.rfc3161.providers[0]).to.include({ role: "principal", url: "http://127.0.0.1:2020/", qualified: null });
      expect(doc.rfc3161.providers[0].anchor_certificates).to.deep.equal([acPem]);
      const fConf = path.join(dep, "config", "rapide", "configuration.json");
      const conf = JSON.parse(fs.readFileSync(fConf, "utf8"));
      // Banc : le serveur d'outils du client est le serveur factice du réseau interne, signé par l'AC de l'essai.
      conf.policy.servers.outils.transport.tls = { ca_file: "/etc/noortrace/outils-ca.pem", cert_file: null, key_file: null };
      fs.writeFileSync(fConf, `${JSON.stringify(conf, null, 2)}\n`);
      fs.chmodSync(fConf, 0o400);
      const approbation = { version: 0, environment: "developpement", org: "organisation-exemple", org_id: conf.recorder.org_id, journal_id: conf.recorder.journal_id, state_dir: "/var/lib/noortrace-approbation", storage_key: { file: "/run/secrets/cle-stockage-approbation" }, noyau: { socket: "/run/noortrace/approbation.sock", socket_mode: "0660", tcp: null, tls: null, token: null }, console: null, etat: { host: "127.0.0.1", port: 8601 }, administrators: ["utilisateur console.invalid administrateur"], console_origin: "https://console.invalid", notifications: null, rpc: null };
      fs.writeFileSync(path.join(dep, "config", "rapide", "approbation.json"), `${JSON.stringify(approbation, null, 2)}\n`, { mode: 0o400 });
      const chown = { "secrets/cle-enregistreur": "10001:10001", "secrets/cle-mac-relais": "10001:10001", "secrets/jeton-hote": "10001:10001", "secrets/jeton-passerelle": "10001:10001", "secrets/cle-stockage-approbation": "10002:10002", "config/rapide/configuration.json": "10001:10001", "config/rapide/approbation.json": "10002:10002" };
      dockerOk(["run", "--rm", "--network", "none", "--user", "0:0", "-v", `${dep}:/t`, "--entrypoint", "/usr/local/bin/node", `noortrace/enregistreur:${VERSION}`, "-e", `for (const [f,c] of Object.entries(${JSON.stringify(chown)})) { const [u,g]=c.split(":").map(Number); require("fs").chownSync("/t/"+f,u,g); }`]);
      mesurer("ir3");
      // IR-5 : validation par le démon et par le service.
      const v1 = dc(["run", "--rm", "--no-deps", "enregistreur", "validate-config", "/etc/noortrace/configuration.json"]);
      expect(v1.status, v1.stderr).to.equal(0);
      const v2 = dc(["run", "--rm", "--no-deps", "approbation", "valider-configuration", "/etc/noortrace-approbation/configuration.json"]);
      expect(v2.status, v2.stderr).to.equal(0);
      mesurer("ir5");
      // IR-6 : démarrage ; le serveur interne est sain dans l'espace réseau de l'enregistreur.
      dcOk(["up", "-d"]);
      const sante = () => Object.fromEntries(dc(["ps", "--format", "{{.Service}}={{.Health}}"]).stdout.trim().split("\n").map((l) => l.split("=")));
      let h = {};
      const debut = Date.now();
      while (Date.now() - debut < 150000) {
        h = sante();
        if (h.enregistreur === "healthy" && h.approbation === "healthy" && h.horodatage === "healthy") break;
        await pause(2000);
      }
      expect([h.enregistreur, h.approbation, h.horodatage], dc(["logs", "--tail", "20"]).stdout).to.deep.equal(["healthy", "healthy", "healthy"]);
      const idEnr = dc(["ps", "-q", "enregistreur"]).stdout.trim();
      const iTsa = JSON.parse(dockerOk(["inspect", dc(["ps", "-q", "horodatage"]).stdout.trim()]))[0];
      expect(iTsa.HostConfig.NetworkMode).to.equal(`container:${idEnr}`);
      expect([iTsa.Config.User, iTsa.HostConfig.ReadonlyRootfs, iTsa.HostConfig.CapDrop]).to.deep.equal(["10004:10004", true, ["ALL"]]);
      expect(dc(["exec", "-T", "horodatage", "/usr/local/bin/noortrace-tsa-interne", "sonde", "--url", "http://127.0.0.1:2020/sante"]).status).to.equal(0);
      expect(dc(["exec", "-T", "enregistreur", "/usr/local/bin/noortrace-ctl", "sonde", "--url", "http://127.0.0.1:8500/readyz"]).status).to.equal(0);
      mesurer("ir6");
      // IR-7 : un appel d'agent, depuis l'espace réseau de l'enregistreur (ports non publiés sur un réseau interne).
      fs.copyFileSync(path.join(secrets, "jeton-hote"), path.join(T, "jeton-hote"));
      fs.chmodSync(path.join(T, "jeton-hote"), 0o444);
      const noeud = (args) => dockerOk(["run", "--rm", "--network", `container:${idEnr}`, "--user", "65534:65534", "-v", `${outils}:/outils:ro`, "-v", `${path.join(T, "jeton-hote")}:/jeton-hote:ro`, "--entrypoint", "/usr/local/bin/node", `noortrace/enregistreur:${VERSION}`, ...args]);
      const reponses = noeud(["/outils/agent.mjs", "http://127.0.0.1:8300/mcp", "/jeton-hote", "outils__read_file"]).trim().split("\n").map((l) => JSON.parse(l));
      const appel = JSON.parse(reponses.find((r) => r.method === "tools/call").corps);
      expect(appel.result?.isError, JSON.stringify(appel)).to.equal(false);
      // L'événement est écrit après la réponse relayée (CT-2 §14.5) : la métrique est relue jusqu'à 30 s.
      let metriques = "";
      const m0 = Date.now();
      while (Date.now() - m0 < 30000) {
        metriques = noeud(["-e", 'fetch("http://127.0.0.1:8500/metrics").then((r) => r.text()).then((t) => process.stdout.write(t))']);
        if (/^noortrace_events_total\{[^}]*kind="appel_outil"[^}]*status="executee"[^}]*\} [1-9]/m.test(metriques)) break;
        await pause(1000);
      }
      expect(metriques.split("\n").filter((l) => l.startsWith("noortrace_events_total")).join("\n")).to.match(/^noortrace_events_total\{[^}]*kind="appel_outil"[^}]*status="executee"[^}]*\} [1-9]/m);
      expect(metriques).to.match(/^noortrace_observation_mode 1$/m);
      mesurer("ir7");
      // IR-8 : clôture anticipée, jeton de clôture du serveur interne, export, vérificateur en conteneur.
      const cloture = dcOk(["exec", "-T", "enregistreur", "/usr/local/bin/noortrace-ctl", "close-period", "--now"]);
      expect(cloture).to.include('"event":"period_closed_early"');
      const journalOps = () => dcOk(["exec", "-T", "enregistreur", "/usr/local/bin/node", "-e", 'const fs=require("fs");for(const f of fs.readdirSync("/var/log/noortrace"))process.stdout.write(fs.readFileSync("/var/log/noortrace/"+f,"utf8"))']);
      let jeton = null;
      const d0 = Date.now();
      while (!jeton && Date.now() - d0 < 60000) {
        jeton = journalOps().split("\n").filter(Boolean).map((l) => JSON.parse(l)).find((l) => l.event === "period_timestamped");
        if (!jeton) await pause(1000);
      }
      expect(jeton?.data, "period_timestamped").to.include({ provider: "tsa-interne" });
      const ots = journalOps().split("\n").filter(Boolean).map((l) => JSON.parse(l)).find((l) => l.event === "ots_submitted");
      expect(ots?.data).to.include({ calendars_answered: 0, attestation: "aucune" });
      const exp = dcOk(["exec", "-T", "enregistreur", "/usr/local/bin/noortrace-ctl", "dossier", "exporter", "--dernier", "--vers", "/var/lib/noortrace-exports/premier"]);
      expect(exp).to.include('"event":"dossier_exported"');
      const conteneur = dc(["--profile", "outils", "run", "--rm", "verificateur", "/var/lib/noortrace-exports/premier"]);
      expect(conteneur.status, conteneur.stdout.slice(-1500)).to.equal(0);
      mesurer("ir8");
      // Réviseur : CRL republiée après genTime (T-10) et fichier d'ancres qui porte l'AC du serveur interne.
      dcOk(["--profile", "outils", "run", "--rm", "-T", "horodatage-init", "crl", "--repertoire", "/var/lib/noortrace-tsa"]);
      const crl = dcOk(["--profile", "outils", "run", "--rm", "-T", "horodatage-init", "ac", "--crl", "--repertoire", "/var/lib/noortrace-tsa"]);
      const ancres = path.join(T, "ancres.json");
      fs.writeFileSync(ancres, `${JSON.stringify({ version: 0, label: "Ancres du réviseur pour le premier dossier de l'installation rapide", prepared_by: "essai de l'installation rapide", prepared_at: new Date().toISOString().replace(/\.[0-9]{3}Z$/, ".000Z"), tsa_authorities: [{ name: "AC interne de développement (interne, non qualifié)", certificate: acPem, intermediates: [], accepted_policies: ["1.3.6.1.4.1.99999.1.1"], qualified: null, source: "certificat de l'AC du serveur RFC 3161 interne, lu au pas IR-2 ; non qualifié" }], revocation: { crls: [crl], statements: [] }, bitcoin: null, registry: null, recorders: [] }, null, 2)}\n`);
      const dossier = path.join(T, "premier");
      fs.mkdirSync(dossier);
      dockerOk(["run", "--rm", "--network", "none", "--user", "0:0", "-v", `noortrace-essai-rapide-${suffixe}_exports:/e:ro`, "-v", `${dossier}:/c`, "--entrypoint", "/usr/local/bin/node", `noortrace/enregistreur:${VERSION}`, "-e", `const fs=require("fs");fs.cpSync("/e/premier","/c",{recursive:true});for(const f of fs.readdirSync("/c"))fs.chownSync("/c/"+f,${process.getuid?.() ?? 0},${process.getgid?.() ?? 0});fs.chownSync("/c",${process.getuid?.() ?? 0},${process.getgid?.() ?? 0})`]);
      const fichiersDossier = fs.readdirSync(dossier).sort();
      expect(fichiersDossier).to.include("jeton-rfc3161.der").and.not.include("preuve.ots");
      const verifs = [["référence", process.execPath, [path.join(RACINE, "scripts", "verify", "dossier.mjs")]]];
      if (process.env.NOORTRACE_VERIFIER_BIN) verifs.push(["noortrace-verifier", process.env.NOORTRACE_VERIFIER_BIN, []]);
      for (const [nom, prog, avant] of verifs) {
        const r = spawnSync(prog, [...avant, dossier, "--ancres", ancres, "--json"], { encoding: "utf8", cwd: RACINE, maxBuffer: 64 * 1024 * 1024 });
        expect(r.status, `${nom} : ${r.stdout.slice(0, 2000)}${r.stderr}`).to.equal(0);
        const rapport = JSON.parse(r.stdout);
        expect(rapport.verdict, nom).to.equal("valide");
        const c = Object.fromEntries(rapport.controls.map((x) => [x.number, x]));
        expect(c[4].status, `${nom} : ${JSON.stringify(c[4])}`).to.equal("reussi");
        expect(c[4].anchors_used, nom).to.deep.equal(["/tsa_authorities/0", "/revocation/crls/0"]);
        expect([c[5].status, c[5].reason], nom).to.deep.equal(["non_execute", "partie_absente"]);
        for (const n of [1, 2, 3, 6]) expect(c[n].status, `${nom} : contrôle ${n}`).to.equal("reussi");
      }
      if (!process.env.NOORTRACE_VERIFIER_BIN) console.log("      noortrace-verifier non rejoué : NOORTRACE_VERIFIER_BIN absent");
      console.log(`      ${JSON.stringify({ result_name: "installation_rapide_docker_s", measured: duree, unit: "s", met: null })}`);
    });

    it("EX-3.7, EX-3.8 : pont-fichiers lancé avec la commande exacte de production.yaml (compte 10101, sans réseau, racine en lecture seule, capacités retirées) : sonde en forme exec 0 ; initialize, write_file et list_directory par Streamable HTTP depuis l'espace réseau du pont ; le pont et le serveur tournent sous 10101 sans interpréteur ; le fichier écrit appartient à 10101", function () {
      const T = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-pont-image-"));
      nettoyage.repertoires.add(T);
      fs.mkdirSync(path.join(T, "fichiers"));
      fs.writeFileSync(path.join(T, "fichiers", "a.txt"), "pièce\n");
      const jeton = crypto.randomBytes(24).toString("hex");
      fs.writeFileSync(path.join(T, "jeton-pont-fichiers"), jeton, { mode: 0o400 });
      dockerOk(["run", "--rm", "--network", "none", "--user", "0:0", "-v", `${T}:/t`, "--entrypoint", "/usr/local/bin/node", `noortrace/enregistreur:${VERSION}`, "-e", 'const fs=require("fs");for(const f of ["jeton-pont-fichiers","fichiers","fichiers/a.txt"])fs.chownSync("/t/"+f,10101,10101)']);
      const svc = COMPOSE.production.services["pont-fichiers"];
      const nom = `noortrace-essai-images-${suffixe}-pont`;
      nettoyage.conteneurs.add(nom);
      dockerOk(["run", "-d", "--name", nom, "--network", "none", "--user", svc.user, "--read-only", "--tmpfs", "/run/temporaire:size=67108864,mode=1777", "-e", "TMPDIR=/run/temporaire", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "-v", `${path.join(T, "fichiers")}:/srv/pieces`, "-v", `${path.join(T, "jeton-pont-fichiers")}:/run/secrets/jeton-pont-fichiers:ro`, `noortrace/pont-stdio:${VERSION}`, ...svc.command]);
      let sonde;
      for (let k = 0; k < 20; k++) {
        sonde = docker(["exec", nom, ...svc.healthcheck.test.slice(1)]);
        if (sonde.status === 0) break;
        spawnSync("sleep", ["0.5"]);
      }
      expect([sonde.status, sonde.stdout.trim()], docker(["logs", nom]).stderr).to.deep.equal([0, "200"]);
      const client = `const h={"content-type":"application/json",accept:"application/json, text/event-stream",authorization:"Bearer ${jeton}"};
const u="http://127.0.0.1:9101/mcp";
(async()=>{const p=(c,s)=>fetch(u,{method:"POST",headers:s?{...h,"mcp-session-id":s}:h,body:JSON.stringify(c)});
let r=await p({jsonrpc:"2.0",id:"e-1",method:"initialize",params:{protocolVersion:"2025-11-25",capabilities:{},clientInfo:{name:"essai",version:"0"}}});
const s=r.headers.get("mcp-session-id");const sortie=[r.status,await r.json()];
r=await p({jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"write_file",arguments:{path:"b.txt",content:"écrit"}}},s);sortie.push(r.status,await r.json());
r=await p({jsonrpc:"2.0",id:3,method:"tools/call",params:{name:"list_directory",arguments:{path:"/srv/pieces"}}},s);sortie.push(r.status,await r.json());
console.log(JSON.stringify(sortie));})()`;
      const [s1, init, s2, ecrit, s3, liste] = JSON.parse(dockerOk(["run", "--rm", "--network", `container:${nom}`, "--entrypoint", "/usr/local/bin/node", `noortrace/enregistreur:${VERSION}`, "-e", client]));
      expect([s1, s2, s3]).to.deep.equal([200, 200, 200]);
      expect(init.result.serverInfo.name).to.equal("noortrace-serveur-fichiers");
      expect(ecrit.result.isError).to.equal(false);
      expect(liste.result.content[0].text).to.equal("[FILE] a.txt\n[FILE] b.txt");
      const top = dockerOk(["top", nom, "-o", "pid,user,args"]);
      expect(top).to.match(/10101\s+\/usr\/local\/bin\/node \/usr\/local\/bin\/noortrace-pont-stdio --ecoute 0\.0\.0\.0:9101/);
      expect(top).to.match(/10101\s+\/usr\/local\/bin\/node \/opt\/mcp\/server-filesystem\/bin\/server-filesystem \/srv\/pieces/);
      expect(top).to.not.match(/\/bin\/sh/);
      expect(docker(["logs", nom]).stderr).to.not.include(jeton);
      const st = fs.statSync(path.join(T, "fichiers", "b.txt"));
      expect([st.uid, st.gid, st.mode & 0o777]).to.deep.equal([10101, 10101, 0o640]);
    });

    it("TA-25 (base) : le conteneur en marche désigne l'image par son condensé, égal à celui de la construction (relevé NOORTRACE_IMAGES_CONDENSES s'il est donné) ; une image modifiée d'un seul fichier a un autre condensé, et la comparaison au condensé publié la signale", function () {
      const attendu = JSON.parse(dockerOk(["image", "inspect", `noortrace/enregistreur:${VERSION}`]))[0].Id;
      if (process.env.NOORTRACE_IMAGES_CONDENSES) expect(JSON.parse(fs.readFileSync(process.env.NOORTRACE_IMAGES_CONDENSES, "utf8")).images.enregistreur.condense).to.equal(attendu);
      const comparer = (conteneur) => {
        const image = JSON.parse(dockerOk(["inspect", conteneur]))[0].Image;
        return image === attendu ? { ecart: false, image } : { ecart: true, image, attendu };
      };
      const c1 = dockerOk(["create", "--network", "none", `noortrace/enregistreur:${VERSION}`, "--version"]).trim();
      nettoyage.conteneurs.add(c1);
      expect(comparer(c1).ecart).to.equal(false);
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-modif-"));
      nettoyage.repertoires.add(tmp);
      fs.writeFileSync(path.join(tmp, "octet"), "x");
      dockerOk(["cp", path.join(tmp, "octet"), `${c1}:/opt/noortrace/octet`]);
      const modifiee = `noortrace-essai-images/enregistreur-modifiee:${suffixe}`;
      dockerOk(["commit", c1, modifiee]);
      nettoyage.images.add(modifiee);
      const c2 = dockerOk(["create", "--network", "none", modifiee, "--version"]).trim();
      nettoyage.conteneurs.add(c2);
      const r = comparer(c2);
      expect(r.ecart).to.equal(true);
      expect(r.image).to.not.equal(attendu);
    });

    it("TE-15, EX-3.9 : compagnon sous le compte 0, sans réseau, racine en lecture seule, avec exactement LINUX_IMMUTABLE, FOWNER et DAC_READ_SEARCH : pose i sur les segments fermés et les manifestes, a sur le segment courant et le journal d'intention, sur des fichiers 0400 du compte 10001 dans des répertoires 0700 ; sans DAC_READ_SEARCH il ne voit rien, ne pose rien et rend 1 (attribute_unreadable) ; sans FOWNER chattr échoue (code 1)", function () {
      const v = volume("attributs");
      const O = "a".repeat(64);
      const J = "b".repeat(64);
      const peupler = `const fs=require("fs"),p=require("path");const r=p.join("/var/lib/noortrace","${O}","${J}");for(const d of ["segments","manifestes","intentions"])fs.mkdirSync(p.join(r,d),{recursive:true,mode:0o700});for(const n of ["seg-0000000000000001-00000000000000000001.ndjson","seg-0000000000000002-00000000000000000001.ndjson"])fs.writeFileSync(p.join(r,"segments",n),"{}\\n",{mode:0o400});fs.writeFileSync(p.join(r,"manifestes","periode-0000000001.json"),"{}",{mode:0o400});fs.writeFileSync(p.join(r,"intentions","intentions-00000000000000000001.ndjson"),"",{mode:0o600});`;
      dockerOk(["run", "--rm", "--network", "none", "--user", "10001:10001", "-v", `${v}:/var/lib/noortrace`, "--entrypoint", "/usr/local/bin/node", `noortrace/enregistreur:${VERSION}`, "-e", peupler]);
      const base = ["run", "--rm", "--network", "none", "--user", "0:0", "--read-only", "--tmpfs", "/run/temporaire:size=1048576,mode=1777", "-e", "TMPDIR=/run/temporaire", "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL", "-v", `${v}:/var/lib/noortrace`];
      const caps = (l) => l.flatMap((c) => ["--cap-add", c]);
      const TROIS = ["LINUX_IMMUTABLE", "FOWNER", "DAC_READ_SEARCH"];
      const attributs = () => {
        const r = docker([...base, ...caps(["DAC_READ_SEARCH"]), "--entrypoint", "/usr/bin/lsattr", `noortrace/attributs:${VERSION}`, "-R", `/var/lib/noortrace/${O}/${J}`]);
        const m = {};
        for (const l of r.stdout.split("\n")) {
          const x = /^(\S{4,})\s+\/var\/lib\/noortrace\/[a-f]{64}\/[a-f]{64}\/(\S+)$/.exec(l);
          if (x && /\.(ndjson|json)$/.test(x[2])) m[x[2]] = x[1].replace(/-/g, "").replace(/e/g, "");
        }
        return m;
      };
      try {
        const sansDac = docker([...base, ...caps(["LINUX_IMMUTABLE", "FOWNER"]), `noortrace/attributs:${VERSION}`, "--racine", "/var/lib/noortrace", "--une-fois"]);
        // Panne bruyante (étape 7) : la racine illisible est une erreur du passage.
        expect(sansDac.status, sansDac.stderr).to.equal(1);
        expect(sansDac.stderr).to.include('"event":"attribute_unreadable"');
        expect(Object.values(attributs()).join("")).to.equal("");
        const sansFowner = docker([...base, ...caps(["LINUX_IMMUTABLE", "DAC_READ_SEARCH"]), `noortrace/attributs:${VERSION}`, "--racine", "/var/lib/noortrace", "--une-fois"]);
        expect(sansFowner.status).to.equal(1);
        expect(sansFowner.stderr).to.include("attribute_failed");
        const complet = docker([...base, ...caps(TROIS), `noortrace/attributs:${VERSION}`, "--racine", "/var/lib/noortrace", "--une-fois"]);
        expect(complet.status, complet.stderr).to.equal(0);
        expect(attributs()).to.deep.equal({
          "segments/seg-0000000000000001-00000000000000000001.ndjson": "i",
          "segments/seg-0000000000000002-00000000000000000001.ndjson": "a",
          "intentions/intentions-00000000000000000001.ndjson": "a",
          "manifestes/periode-0000000001.json": "i",
        });
      } finally {
        docker([...base, ...caps(TROIS), "--entrypoint", "/usr/bin/chattr", `noortrace/attributs:${VERSION}`, "-R", "-i", "-a", `/var/lib/noortrace/${O}`]);
      }
    });

    it("TM-26 : le compagnon en service (--intervalle-s 60, compte 0, trois capacités) pose i sur dix segments fermés toutes les 6 s ; délai entre la fermeture et l'attribut lu par lsattr ; ligne compagnon_pose_attribut (p50, max ; met = max ≤ 60 s) ; chaque segment scellé en 75 s au plus", async function () {
      this.timeout(300000);
      const v = volume("tm26");
      const O = "c".repeat(64);
      const J = "d".repeat(64);
      const dir = `/var/lib/noortrace/${O}/${J}/segments`;
      const ecrire = (n) => dockerOk(["run", "--rm", "--network", "none", "--user", "10001:10001", "-v", `${v}:/var/lib/noortrace`, "--entrypoint", "/usr/local/bin/node", `noortrace/enregistreur:${VERSION}`, "-e", `require("fs").mkdirSync(${JSON.stringify(dir)},{recursive:true,mode:0o700});require("fs").writeFileSync(${JSON.stringify(dir)}+"/seg-${String(n).padStart(16, "0")}-00000000000000000001.ndjson","{}\\n",{mode:0o400})`]);
      ecrire(0);
      const nom = `noortrace-essai-images-${suffixe}-compagnon`;
      const caps = ["LINUX_IMMUTABLE", "FOWNER", "DAC_READ_SEARCH"].flatMap((c) => ["--cap-add", c]);
      dockerOk(["run", "-d", "--name", nom, "--network", "none", "--user", "0:0", "--read-only", "--tmpfs", "/run/temporaire:size=1048576,mode=1777", "-e", "TMPDIR=/run/temporaire", "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL", ...caps, "-v", `${v}:/var/lib/noortrace`, `noortrace/attributs:${VERSION}`, "--racine", "/var/lib/noortrace", "--intervalle-s", "60"]);
      nettoyage.conteneurs.add(nom);
      const ferme = [];
      const pose = [];
      try {
        await pause(2000);
        expect(docker(["exec", nom, "/usr/local/bin/noortrace-attributs", "sonde"]).status).to.equal(0);
        // Un segment toutes les 6 s : l'écriture du segment k ferme le segment k-1 ; l'instant
        // de fermeture est pris juste avant l'écriture (borne haute du délai).
        const debut = Date.now();
        let k = 1;
        for (;;) {
          if (k <= 10 && Date.now() - debut >= (k - 1) * 6000) {
            ferme[k - 1] = Date.now();
            ecrire(k);
            k++;
          }
          const r = docker(["exec", nom, "/usr/bin/lsattr", dir]);
          for (const l of r.stdout.split("\n")) {
            const x = /^(\S+)\s+\S*\/seg-([0-9]{16})-[0-9]{20}\.ndjson$/.exec(l);
            if (!x) continue;
            const n = Number(x[2]);
            if (n < 10 && ferme[n] !== undefined && pose[n] === undefined && x[1].includes("i")) pose[n] = Date.now();
          }
          if (k > 10 && pose.filter((t) => t !== undefined).length === 10) break;
          if (Date.now() - debut > 240000) break;
          await pause(1000);
        }
      } finally {
        spawnSync("docker", ["rm", "-f", nom], { encoding: "utf8" });
        docker(["run", "--rm", "--network", "none", "--user", "0:0", "--cap-drop", "ALL", ...caps, "-v", `${v}:/var/lib/noortrace`, "--entrypoint", "/usr/bin/chattr", `noortrace/attributs:${VERSION}`, "-R", "-i", "-a", `/var/lib/noortrace/${O}`]);
      }
      const delais = ferme.map((t, n) => (pose[n] === undefined ? null : (pose[n] - t) / 1000));
      expect(delais.every((d) => d !== null), JSON.stringify(delais)).to.equal(true);
      const tries = [...delais].sort((a, b) => a - b);
      const ligne = { result_name: "compagnon_pose_attribut", unit: "s", repetitions: delais.length, p50: tries[Math.floor((tries.length - 1) / 2)], max: tries.at(-1), target: 60, met: tries.at(-1) <= 60, conditions: [`système de fichiers du volume : ${spawnSync("df", ["--output=fstype", "/var/lib/docker"], { encoding: "utf8" }).stdout.split("\n")[1]?.trim() ?? "inconnu"}`, "lsattr dans le conteneur du compagnon"] };
      console.log(`      ${JSON.stringify({ ...ligne, delais })}`);
      expect(delais).to.have.lengthOf(10);
      // `met` est la mesure (cible de CT-8 EX-3.9) : la ligne est rendue, vraie ou fausse ;
      // l'essai échoue seulement si un segment fermé n'est pas scellé en 75 s.
      expect(Math.max(...delais), JSON.stringify(delais)).to.be.at.most(75);
    });

    it("TM-24 : taille de chaque image dans le magasin local (docker image inspect, Size) ; lignes image_<nom>_octets ; durée de téléchargement non mesurée (aucun registre : images construites ou chargées par docker load)", function () {
      const lignes = IMAGES.map((nom) => ({ result_name: `image_${nom.replace(/-/g, "_")}_octets`, measured: JSON.parse(dockerOk(["image", "inspect", `noortrace/${nom}:${VERSION}`]))[0].Size, unit: "octets", met: null }));
      lignes.push({ result_name: "ir6_telechargement_s", measured: null, unit: "s", met: null, raison: "aucune image publiée (D-3)" });
      for (const l of lignes) console.log(`      ${JSON.stringify(l)}`);
      for (const l of lignes.slice(0, -1)) expect(l.measured, l.result_name).to.be.a("number").and.to.be.above(1000000);
    });

    it("TM-28, EX-3.13 : deux constructions sans cache, depuis deux copies des sources à deux instants, donnent pour chaque image le même condensé, égal à celui de l'image du magasin local ; ligne construction_reproductible = 0", function () {
      if (!process.env.NOORTRACE_IMAGES_CONDENSES) {
        this.test.title += " — en attente : relevé de deux constructions absent (node scripts/deploiement/construire-images.mjs --double --sortie <rép>, puis NOORTRACE_IMAGES_CONDENSES=<rép>/condenses.json ; la construction joint les registres publics, un essai ne construit pas)";
        this.skip();
      }
      const releve = JSON.parse(fs.readFileSync(process.env.NOORTRACE_IMAGES_CONDENSES, "utf8"));
      expect(Object.keys(releve.images).sort()).to.deep.equal([...IMAGES].sort());
      expect(releve.source_date_epoch).to.equal(SOURCE_DATE_EPOCH);
      for (const nom of IMAGES) {
        const e = releve.images[nom];
        expect(e.condense, nom).to.match(/^sha256:[0-9a-f]{64}$/);
        expect(e.condense_seconde_construction, nom).to.equal(e.condense);
        expect(JSON.parse(dockerOk(["image", "inspect", `noortrace/${nom}:${VERSION}`]))[0].Id, nom).to.equal(e.condense);
      }
      expect(releve.construction_reproductible).to.equal(0);
      console.log(`      ${JSON.stringify({ result_name: "construction_reproductible", measured: releve.construction_reproductible, unit: "nombre", target: 0, met: releve.construction_reproductible === 0 })}`);
    });
  });
});
