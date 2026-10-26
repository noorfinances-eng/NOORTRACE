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
const CT5 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-5");
const SORTIES = path.join(CT6, "confrontation", "sorties");
const SORTIES5 = path.join(CT5, "confrontation", "sorties");
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

// ---------------------------------------------------------------------------
// CT-5 (spec/CT-5-ancrage.md, annexe A.6 ; spec/vecteurs/ct-5/confrontation/) :
// requêtes et réponses par OpenSSL, fichiers .ots par python-opentimestamps,
// jetons des dossiers de CT-6 à partie points-de-controle.json (CT-6 EX-A.17),
// preuves de cohérence RFC 9162 des vecteurs CT-1 révision 0.3 (CT-1 §10.7) par
// transparency-dev/merkle v0.0.2.
describe("CT-5 : sorties publiées de la confrontation par des outils tiers (annexe A.6)", function () {
  const lire5 = (f) => lire(SORTIES5, f);
  const lireJSON5 = (...p) => lireJSON(CT5, ...p);
  const sha5 = (...p) => sha256(CT5, ...p);

  it("aucun chemin local dans les sorties publiées ; aucune discordance", function () {
    expect(fs.readdirSync(SORTIES5).sort()).to.deep.equal(["coherence.txt", "ots.txt", "reponses.txt", "requetes.txt"]);
    for (const f of fs.readdirSync(SORTIES5)) {
      const texte = lire5(f);
      expect(texte, f).not.to.match(/\/home\/|\/tmp\/|\/root\/|[A-Z]:\\/);
      expect(texte, f).not.to.match(/DISCORDANCE/);
      expect(texte, f).to.match(/^Discordances au total : 0$/m);
    }
  });

  it("requetes.txt (openssl ts -query, asn1parse, ts -verify) : SHA-256 de chaque .tsq égal au fichier, un bloc par cas de requetes.json, jeton de CT-1 §11.2 vérifié", function () {
    const sortie = lire5("requetes.txt");
    const requetes = lireJSON5("requetes", "requetes.json");
    for (const c of requetes.cases) {
      const h = sha5("requetes", c.expected.file);
      expect(c.expected.sha256, c.id).to.equal(h);
      expect(sortie, c.id).to.match(new RegExp(`^-- ${echapper(c.id)} \\(requetes/${echapper(c.expected.file)}\\)\\n  SHA-256 du fichier : vecteur ${h} ; openssl ${h} : concorde$`, "m"));
      expect(sortie, c.id).to.match(new RegExp(`^  Nonce : vecteur ${c.expected.nonce} ; openssl ${c.expected.nonce} : concorde$`, "m"));
    }
    expect(sortie.split("== 2.")[0].match(/^-- /gm).length).to.equal(requetes.cases.length);
    expect(sortie.split("== 2.")[1].split("== 3.")[0].match(/^-- /gm).length).to.equal(lireJSON5("requetes", "refusees.json").cases.length);
    expect(sortie).to.match(/^  openssl ts -verify -queryfile requetes\/requete-point-k2\.tsq -token_in -in reponses\/granted-requete-point-k2\.der : vecteur Verification: OK ; openssl Verification: OK : concorde$/m);
  });

  it("reponses.txt (openssl ts -reply, -token_out, ts -verify) : SHA-256 de chaque .tsr égal au fichier, un bloc par cas, verdict openssl_verify concordant, jetons des dossiers de CT-6 à partie points-de-controle.json", function () {
    const sortie = lire5("reponses.txt");
    const reponses = lireJSON5("reponses", "reponses.json");
    const section1 = sortie.split("== 2.")[0];
    expect(section1.match(/^-- /gm).length).to.equal(reponses.cases.length);
    for (const c of reponses.cases) {
      expect(section1, c.id).to.match(new RegExp(`^-- ${echapper(c.id)} \\(requête [^)]+\\)$`, "m"));
      if (c.input.response === null) continue;
      const h = sha5("reponses", c.input.response);
      expect(c.input.response_sha256, c.id).to.equal(h);
      expect(section1, c.id).to.include(`  SHA-256 du fichier : vecteur ${h} ; openssl ${h} : concorde`);
      if (c.expected.token) expect(section1, c.id).to.include(`  jeton extrait = fichier reponses/${c.expected.token} : vecteur True ; openssl True : concorde`);
      if (c.expected.openssl_verify !== null) expect(section1, c.id).to.include(`  openssl ts -verify -queryfile (à genTime) : vecteur ${c.expected.openssl_verify} ; openssl ${c.expected.openssl_verify} : concorde`);
    }
    const dossiers = fs.readdirSync(path.join(CT6, "dossiers")).filter((n) => fs.existsSync(path.join(CT6, "dossiers", n, "points-de-controle.json"))).sort();
    const section2 = sortie.split("== 2.")[1];
    expect(section2.match(/^-- dossiers\//gm).length).to.equal(dossiers.length);
    for (const n of dossiers) expect(section2, n).to.match(new RegExp(`^-- dossiers/${echapper(n)} \\(`, "m"));
    expect(section2.match(/openssl ts -verify -digest <checkpoint_hash> -token_in[^\n]* : vecteur OK ; openssl OK : concorde$/gm).length).to.be.at.least(8);
  });

  it("ots.txt (python-opentimestamps) : SHA-256 et taille de chaque .ots égaux au fichier, réécriture identique, mise à niveau égale à la preuve complète de CT-6", function () {
    const sortie = lire5("ots.txt");
    const ots = lireJSON5("ots", "ots.json");
    for (const c of ots.cases) {
      const h = sha5("ots", c.file);
      const taille = fs.statSync(path.join(CT5, "ots", c.file)).size;
      expect([c.sha256, c.size], c.id).to.deep.equal([h, taille]);
      expect(sortie, c.id).to.match(new RegExp(`^-- ${echapper(c.id)} \\(${echapper(c.file)}\\)\\n  SHA-256 et taille : vecteur \\('${h}', ${taille}\\) ; outil \\('${h}', ${taille}\\) : concorde$`, "m"));
      expect(sortie, c.id).to.include(`  nonce : vecteur ${c.nonce} ; outil ${c.nonce} : concorde`);
    }
    const m = lireJSON5("ots", "mise-a-niveau.json");
    expect(sortie).to.include(`  preuve fusionnée : SHA-256 : vecteur ${m.expected.merged_sha256} ; outil ${m.expected.merged_sha256} : concorde`);
    expect(sortie).to.match(/^  preuve fusionnée = preuve complète de CT-6 \(octets\) : vecteur True ; outil True : concorde$/m);
    expect(sortie.match(/^  réécriture par la bibliothèque identique aux octets du fichier : vecteur True ; outil True : concorde$/gm).length).to.equal(ots.cases.length);
  });

  it("coherence.txt (transparency-dev/merkle v0.0.2) : SHA-256 de merkle/coherence.json et de chaque points-de-controle.json égaux aux fichiers, un bloc par cas et par dossier à partie, aucune discordance", function () {
    const sortie = lire5("coherence.txt");
    const CT1 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-1");
    const coherence = lireJSON(CT1, "merkle", "coherence.json");
    expect(sortie).to.include(`  SHA-256 de ct-1/merkle/coherence.json : ${sha256(CT1, "merkle", "coherence.json")}`);
    const section2 = sortie.split("== 2.")[1].split("== 3.")[0];
    expect(section2.match(/^-- /gm).length).to.equal(coherence.cases.length);
    for (const c of coherence.cases) {
      expect(section2, c.name).to.match(new RegExp(`^-- ${echapper(c.name)} : attendu ${c.valid ? "acceptee" : "refusee"}`, "m"));
      if (c.valid) expect(section2, c.name).to.match(new RegExp(`^-- ${echapper(c.name)} : attendu acceptee\\n(?:[^\\n]*\\n){0,2}  path = preuve générée par la bibliothèque, nœud pour nœud : vecteur \\[${c.path.join(" ")}\\] ; bibliothèque \\[${c.path.join(" ")}\\] : concorde$`, "m"));
    }
    const section3 = sortie.split("== 3.")[1].split("== 4.")[0];
    for (const p of lireJSON(CT1, "points-de-controle", "attendu.json").periodes) {
      expect(section3, p.file).to.match(new RegExp(`^-- ${echapper(p.file)} \\(manifeste [^\\n]*, ${p.count} point\\(s\\)\\)$`, "m"));
    }
    const section4 = sortie.split("== 4.")[1];
    for (const [etiquette, racine] of [["ct-1", CT1], ["ct-6", CT6]]) {
      const dossiers = fs.readdirSync(path.join(racine, "dossiers")).filter((n) => fs.existsSync(path.join(racine, "dossiers", n, "points-de-controle.json"))).sort();
      expect(dossiers.length, etiquette).to.be.above(0);
      expect(section4.match(new RegExp(`^-- ${etiquette}/dossiers/`, "gm")).length).to.equal(dossiers.length);
      for (const n of dossiers) {
        expect(section4, n).to.match(new RegExp(`^-- ${etiquette}/dossiers/${echapper(n)} \\([^\\n]*\\n  SHA-256 de points-de-controle.json : ${sha256(racine, "dossiers", n, "points-de-controle.json")}$`, "m"));
      }
    }
    expect(section4.match(/^  proof\.VerifyConsistency : vecteur acceptee ; bibliothèque acceptee : concorde$/gm).length).to.be.at.least(8);
    expect(section4).to.match(/^  proof\.VerifyConsistency : vecteur refusee ; bibliothèque refusee : concorde$/m);
    expect(sortie).to.match(/^Discordances au total : 0$/m);
  });

  it("rejeu de confrontation/coherence (go présent et module tiers déjà dans le cache local) : code 0, aucune discordance", function () {
    // Sauté dans le job tests de la CI, où le cache de modules est vide et le
    // réseau coupé (GOPROXY=off) : le job confrontation de ci.yml, qui résout
    // le module épinglé par go.sum, le rejoue (CT-5 EX-A.7).
    this.timeout(180_000);
    const module_ = path.join(CT5, "confrontation", "coherence");
    const env = { ...process.env, GOPROXY: "off" };
    const cache = spawnSync("go", ["mod", "download", "-json", "github.com/transparency-dev/merkle"], { cwd: module_, encoding: "utf8", env });
    if (cache.error || cache.status !== 0) this.skip();
    const r = spawnSync("go", ["run", ".", path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-1"), CT6], { cwd: module_, encoding: "utf8", env, maxBuffer: 64 * 1024 * 1024 });
    expect(r.status, r.stdout.split("\n").slice(-6).join("\n") + r.stderr).to.equal(0);
    expect(r.stdout).to.match(/^Discordances au total : 0$/m);
  });

  it("rejeu de confronter_requetes.py et confronter_reponses.py (python3 et openssl présents) : code 0, aucune discordance", function () {
    this.timeout(180_000);
    const python = spawnSync("python3", ["--version"], { encoding: "utf8" });
    const openssl = spawnSync("openssl", ["version"], { encoding: "utf8" });
    if (python.status !== 0 || openssl.status !== 0) this.skip();
    for (const nom of ["requetes", "reponses"]) {
      const travail = fs.mkdtempSync(path.join(os.tmpdir(), `noortrace-confrontation-ct5-${nom}-`));
      try {
        const r = spawnSync("python3", ["-I", path.join(CT5, "confrontation", nom, `confronter_${nom}.py`), CT5, travail], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
        expect(r.status, nom + " : " + r.stdout.split("\n").slice(-8).join("\n") + r.stderr).to.equal(0);
        expect(r.stdout, nom).to.match(/^Discordances au total : 0$/m);
      } finally {
        fs.rmSync(travail, { recursive: true, force: true });
      }
    }
  });
});
