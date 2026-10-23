import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";

// SORTIES PUBLIÉES DE LA CONFRONTATION DES VECTEURS CT-6 PAR DES
// IMPLÉMENTATIONS TIERCES (spec/CT-6-verificateur.md, annexe A.8 ;
// spec/vecteurs/ct-6/confrontation/). Les sorties sont des entrées du
// générateur (EX-A.1) : rien ne les réécrit quand les vecteurs changent. Ces
// tests exigent qu'elles portent sur les vecteurs du dépôt : SHA-256 des
// fichiers cités égaux à ceux des fichiers, un cas par cas de attendu.json,
// les statuts du registre égaux à ceux de registre/attendu.json, aucune
// discordance, aucun chemin local. Quand openssl est présent, la
// confrontation rfc3161 est aussi rejouée (code 0 exigé).

const CT6 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-6");
const SORTIES = path.join(CT6, "confrontation", "sorties");
const lire = (...p) => fs.readFileSync(path.join(...p), "utf8");
const lireJSON = (...p) => JSON.parse(lire(...p));
const sha256 = (...p) => "0x" + crypto.createHash("sha256").update(fs.readFileSync(path.join(...p))).digest("hex");
const echapper = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

describe("CT-6 : sorties publiées de la confrontation par des outils tiers (annexe A.8)", function () {
  it("aucun chemin local dans les sorties publiées", function () {
    for (const f of fs.readdirSync(SORTIES)) {
      const texte = lire(SORTIES, f);
      expect(texte, f).not.to.match(/\/home\/|\/tmp\/|\/root\/|[A-Z]:\\/);
    }
  });

  it("rfc3161.txt (openssl) : SHA-256 des jetons, certificats et clés égaux aux fichiers ; un bloc par cas de attendu.json ; aucune discordance", function () {
    const sortie = lire(SORTIES, "rfc3161.txt");
    const attendu = lireJSON(CT6, "rfc3161", "attendu.json");
    for (const t of attendu.tokens) {
      const h = sha256(CT6, "rfc3161", t.file);
      expect(t.sha256, t.file).to.equal(h);
      expect(sortie, t.file).to.match(new RegExp(`^-- ${echapper(t.file)} \\(cible[^\\n]*\\n  SHA-256 du fichier : vecteur ${h} ; openssl ${h} : concorde$`, "m"));
    }
    for (const [f, h] of Object.entries(attendu.keys.files)) {
      expect(sortie, f).to.match(new RegExp(`^  ${echapper(f)} SHA-256 [^:]*: vecteur ${h} ; openssl ${h} : concorde$`, "m"));
    }
    const section3 = sortie.split("== 3.")[1].split("== 4.")[0];
    expect(section3.match(/^-- jetons\//gm).length).to.equal(attendu.cases.length);
    expect(sortie).to.match(/^Bilan des cas : \d+ concordances, 0 discordances,/m);
    expect(sortie).to.match(/^Discordances au total \(sections 1 à 4\) : 0$/m);
    expect(sortie).not.to.match(/DISCORDANCE/);
  });

  it("ots.txt (python-opentimestamps) : SHA-256 des en-têtes et des preuves égaux aux fichiers ; un bloc par cas ; aucune discordance", function () {
    const sortie = lire(SORTIES, "ots.txt");
    const attendu = lireJSON(CT6, "ots", "attendu.json");
    for (const nom of Object.keys(attendu.headers)) {
      const h = sha256(CT6, "ots", nom);
      expect(sortie, nom).to.match(new RegExp(`^-- ${echapper(nom)}\\n  SHA-256 du fichier : vecteur ${h} ; outil ${h} : concorde$`, "m"));
    }
    for (const p of attendu.proofs) {
      const h = sha256(CT6, "ots", p.file);
      const taille = fs.statSync(path.join(CT6, "ots", p.file)).size;
      expect(sortie, p.file).to.match(new RegExp(`^  SHA-256 et taille : vecteur \\('${h}', ${taille}\\) ; outil \\('${h}', ${taille}\\) : concorde$`, "m"));
    }
    const section3 = sortie.split("== 3.")[1];
    expect(section3.match(/^-- preuves\//gm).length).to.equal(attendu.cases.length);
    expect(sortie).to.match(/^Bilan des vérifications O- : \d+ concordances, 0 discordances$/m);
    expect(sortie).to.match(/^Discordances au total : 0$/m);
  });

  it("registre.txt (go-ethereum et noorcore) : chaque jeu de parties et chaque variante, statuts égaux à registre/attendu.json ; aucun écart", function () {
    const sortie = lire(SORTIES, "registre.txt");
    const attendu = lireJSON(CT6, "registre", "attendu.json");
    const blocs = sortie.split("== 3.")[1].split(/\n(?=\S)/);
    for (const j of [...attendu.jeux_de_parties, ...attendu.variantes]) {
      const bloc = blocs.find((b) => b.split("\n")[0] === j.nom);
      expect(bloc, j.nom).to.be.a("string");
      const lus = Object.fromEntries([...bloc.matchAll(/^  \[concordant\] (\S+)\s+go = \S+\s+attendu = (\S+)$/gm)].map((m) => [m[1], m[2]]));
      expect(lus, j.nom).to.deep.equal(j.statuses);
    }
    expect(sortie).not.to.match(/ÉCART/);
    expect(sortie).to.match(/^concordances : \d+, écarts : 0$/m);
  });

  it("registre-certificats.txt : chaque certificat de la capture vérifié par certificat-commit.mjs (VALIDE, code 0), chemins relatifs", function () {
    const sortie = lire(SORTIES, "registre-certificats.txt");
    const certificats = fs.readdirSync(path.join(CT6, "registre", "capture")).filter((f) => /^certificat-\d+\.json$/.test(f));
    expect(certificats.length).to.be.above(0);
    for (const f of certificats) {
      const bloc = sortie.split(/^\$ node /m).find((b) => b.startsWith(`scripts/verify/certificat-commit.mjs spec/vecteurs/ct-6/registre/capture/${f} `));
      expect(bloc, f).to.be.a("string");
      expect(bloc, f).to.include(`Source        : fichier spec/vecteurs/ct-6/registre/capture/${f}\n`);
      expect(bloc, f).to.match(/^Résultat      : VALIDE /m);
      expect(bloc, f).to.match(/\$ echo \$\?\n0\n/);
    }
  });

  it("rejeu de confronter_rfc3161.py (python3 et openssl présents) : code 0, aucune discordance", function () {
    this.timeout(120_000);
    const python = spawnSync("python3", ["--version"], { encoding: "utf8" });
    const openssl = spawnSync("openssl", ["version"], { encoding: "utf8" });
    if (python.status !== 0 || openssl.status !== 0) this.skip();
    const travail = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-confrontation-rfc3161-"));
    try {
      const r = spawnSync("python3", ["-I", path.join(CT6, "confrontation", "rfc3161", "confronter_rfc3161.py"), CT6, travail], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
      expect(r.status, r.stdout.split("\n").slice(-12).join("\n") + r.stderr).to.equal(0);
      expect(r.stdout).to.match(/^Discordances au total \(sections 1 à 4\) : 0$/m);
    } finally {
      fs.rmSync(travail, { recursive: true, force: true });
    }
  });
});
