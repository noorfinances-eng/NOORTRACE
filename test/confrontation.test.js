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

// ---------------------------------------------------------------------------
// CT-2 (spec/CT-2-enregistreur.md, annexes B.5 et B.8 ; spec/vecteurs/ct-2/
// confrontation/) : cas pieces-modele/gemini-* par le SDK google-genai 2.33.0,
// famille otel/ par opentelemetry-proto 1.45.1 et protobuf 7.36.2. Les sorties
// publiées doivent porter sur les vecteurs du dépôt (SHA-256 des fichiers
// cités, un bloc par cas) et ne relever aucune discordance. Quand un
// interpréteur Python porte exactement les versions d'exigences.txt
// (NOORTRACE_PYTHON_CONFRONTATION, sinon python3), chaque programme est rejoué
// et sa sortie doit égaler, octet pour octet, la sortie publiée.
describe("CT-2 : sorties publiées de la confrontation par des outils tiers (annexes B.5 et B.8)", function () {
  const CT2 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-2");
  const CONFRONTATION2 = path.join(CT2, "confrontation");
  const SORTIES2 = path.join(CONFRONTATION2, "sorties");
  const MODELE = path.join(CT2, "pieces-modele");
  const OTEL = path.join(CT2, "otel");
  const lire2 = (f) => lire(SORTIES2, f);
  const casGemini = fs.readdirSync(MODELE).filter((n) => n.startsWith("gemini-")).sort();
  const casOtel = fs.readdirSync(OTEL).sort();
  const section = (texte, n) => texte.split(`\n== ${n}. `)[1].split(/\n== \d+\. /)[0];

  it("aucun chemin local dans les sorties publiées ; aucune discordance", function () {
    expect(fs.readdirSync(SORTIES2).sort()).to.deep.equal(["gemini.txt", "otel.txt"]);
    for (const f of fs.readdirSync(SORTIES2)) {
      const texte = lire2(f);
      expect(texte, f).not.to.match(/\/home\/|\/tmp\/|\/root\/|[A-Z]:\\/);
      expect(texte, f).not.to.match(/DISCORDANCE/);
      expect(texte, f).to.match(/^Discordances au total : 0$/m);
    }
  });

  it("gemini.txt (google-genai 2.33.0) : chaque cas gemini-*, SHA-256 des requêtes et des réponses égaux aux fichiers, formes consolidées et refus", function () {
    const sortie = lire2("gemini.txt");
    expect(sortie).to.match(/^Confrontation des vecteurs CT-2 pieces-modele\/gemini-\* par google-genai 2\.33\.0 \(pydantic 2\.14\.1, /m);
    expect(casGemini.length).to.be.above(0);
    const s1 = section(sortie, 1);
    const s3 = section(sortie, 3);
    const s5 = section(sortie, 5);
    const s6 = section(sortie, 6);
    expect(s1.match(/^-- /gm).length).to.equal(casGemini.length);
    expect(s3.match(/^-- /gm).length).to.equal(casGemini.length);
    for (const cas of casGemini) {
      const fichiers = fs.readdirSync(path.join(MODELE, cas));
      const req = fichiers.includes("requete.brut") ? "requete.brut" : "requete.json";
      expect(s1, cas).to.include(`-- ${cas} (${req}, SHA-256 ${sha256(MODELE, cas, req)}`);
      const rep = ["reponse.sse", "reponse.json", "reponse-morceaux.json"].find((f) => fichiers.includes(f));
      if (rep) expect(s3, cas).to.include(`-- ${cas} (${rep}, SHA-256 ${sha256(MODELE, cas, rep)}`);
      else expect(s3, cas).to.include(`-- ${cas} : aucune réponse`);
      const a = lireJSON(MODELE, cas, "attendu.json");
      if (a.consolidated !== null) expect(s5, cas).to.match(new RegExp(`^-- ${echapper(cas)} \\(consolidated, `, "m"));
      if (a.refused !== null) expect(s6, cas).to.match(new RegExp(`^-- ${echapper(cas)} \\(statut ${a.refused.status}, raison ${a.refused.reason}, `, "m"));
    }
    expect(sortie).to.match(new RegExp(`^Cas gemini-\\* : ${casGemini.length} ; discordances : 0 ;`, "m"));
  });

  it("otel.txt (opentelemetry-proto 1.45.1, protobuf 7.36.2) : chaque cas, SHA-256 des requêtes égaux aux fichiers, identifiants de chaque span", function () {
    const sortie = lire2("otel.txt");
    expect(sortie).to.match(/^Confrontation des vecteurs CT-2 otel\/ par opentelemetry-proto 1\.45\.1 et protobuf 7\.36\.2$/m);
    const s1 = section(sortie, 1);
    expect(s1.match(/^-- /gm).length).to.equal(casOtel.length);
    const blocs = s1.split(/\n(?=-- )/);
    for (const cas of casOtel) {
      const req = fs.readdirSync(path.join(OTEL, cas)).find((f) => f.startsWith("requete.") && f !== "requete-entetes.json");
      const a = lireJSON(OTEL, cas, "attendu.json");
      const bloc = blocs.find((b) => b.startsWith(`-- ${cas} (`));
      expect(bloc, cas).to.be.a("string");
      expect(bloc, cas).to.include(`-- ${cas} (${req}, SHA-256 ${sha256(OTEL, cas, req)}, `);
      expect(bloc, cas).to.match(new RegExp(`, statut attendu ${a.status}\\)`));
      if (a.status !== 200) continue;
      for (const sp of a.spans) {
        expect(bloc, `${cas} ${sp.span_id}`).to.include(`  span [${sp.path.join(", ")}] (issue ${sp.issue}`);
        expect(bloc, `${cas} ${sp.span_id}`).to.include(`trace_id : vecteur ${sp.trace_id} ; outil ${sp.trace_id} : concorde`);
        expect(bloc, `${cas} ${sp.span_id}`).to.include(`span_id : vecteur ${sp.span_id} ; outil ${sp.span_id} : concorde`);
        if (sp.normalized) expect(bloc, `${cas} ${sp.span_id}`).to.include(`start_time_unix_nano : vecteur ${sp.normalized.start_time_unix_nano} ; outil ${sp.normalized.start_time_unix_nano} : concorde`);
      }
    }
    for (const paire of ["json-exemple-6-8-16 / pb-exemple-6-8-16", "json-identifiants-invalides / pb-identifiants-invalides"]) {
      expect(section(sortie, 2), paire).to.include(`-- paire ${paire}`);
    }
    expect(sortie).to.match(new RegExp(`^Cas otel/ : ${casOtel.length} ;[^\\n]* divergences voulues : 4 ;[^\\n]* discordances : 0$`, "m"));
  });

  for (const [outil, programme, sortiePubliee] of [
    ["gemini", "confronter_gemini.py", "gemini.txt"],
    ["otel", "confronter_otel.py", "otel.txt"],
  ]) {
    it(`rejeu de ${outil}/${programme} (interpréteur aux versions d'exigences.txt présent) : code 0, sortie égale à sorties/${sortiePubliee}`, function () {
      this.timeout(180_000);
      const exigences = lire(CONFRONTATION2, outil, "exigences.txt").split("\n").filter((l) => /^[A-Za-z0-9_.-]+==/.test(l)).map((l) => l.split("=="));
      const python = process.env.NOORTRACE_PYTHON_CONFRONTATION || "python3";
      const code = `import importlib.metadata as m, json\nout = {}\nfor p in ${JSON.stringify(exigences.map(([p]) => p))}:\n    try: out[p] = m.version(p)\n    except m.PackageNotFoundError: out[p] = None\nprint(json.dumps(out))`;
      const versions = spawnSync(python, ["-I", "-c", code], { encoding: "utf8" });
      if (versions.error || versions.status !== 0) this.skip();
      const lues = JSON.parse(versions.stdout);
      if (!exigences.every(([p, v]) => lues[p] === v)) this.skip();
      const r = spawnSync(python, ["-I", path.join(CONFRONTATION2, outil, programme), CT2], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
      expect(r.status, r.stdout.split("\n").slice(-8).join("\n") + r.stderr).to.equal(0);
      expect(r.stdout).to.equal(lire2(sortiePubliee));
    });
  }
});

// ---------------------------------------------------------------------------
// CT-3 (spec/CT-3-approbations.md, révision 0.3, EX-A.14, EX-A.18, EX-A.19) :
// sorties publiées de spec/vecteurs/ct-3/confrontation/ (jamais écrites par le
// générateur), par ethers (celui du dépôt) et par eth-account 0.14.0. Les deux
// programmes n'importent rien de scripts/ ; leurs lignes portent sur les mêmes
// signatures, dans le même ordre, avec les mêmes adresses attendues. Le
// script ethers est toujours rejoué ; le script eth-account l'est quand un
// interpréteur Python porte exactement les versions d'exigences.txt
// (NOORTRACE_PYTHON_CONFRONTATION, sinon python3).
// ---------------------------------------------------------------------------

describe("CT-3 : sorties publiées de la confrontation des signatures par des outils tiers (EX-A.18)", function () {
  const CT3 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-3");
  const CONFRONTATION3 = path.join(CT3, "confrontation");
  const SORTIES3 = path.join(CONFRONTATION3, "sorties");
  const sortieEthers = () => lire(SORTIES3, "ethers.txt");
  const sortieEthAccount = () => lire(SORTIES3, "eth-account.txt");
  const exigences = () =>
    lire(CONFRONTATION3, "eth-account", "exigences.txt")
      .split("\n")
      .filter((l) => /^[A-Za-z0-9_.-]+==/.test(l))
      .map((l) => l.split("=="));
  const versionExigee = (p) => exigences().find(([n]) => n === p)[1];
  const lignesSignatures = (texte) => texte.split("\n").filter((l) => l !== "" && !l.startsWith("# ")).map((l) => l.split(" | "));
  const BILAN = /^# bilan : (\d+) signatures et fichiers ; concorde (\d+), acceptee_par_la_bibliotheque (\d+), refusee_par_la_bibliotheque (\d+), discordance 0$/m;

  it("deux sorties publiées, aucun chemin local, aucune discordance ; en-têtes aux versions d'ethers du dépôt et d'exigences.txt", function () {
    expect(fs.readdirSync(SORTIES3).sort()).to.deep.equal(["eth-account.txt", "ethers.txt"]);
    for (const f of fs.readdirSync(SORTIES3)) {
      const texte = lire(SORTIES3, f);
      expect(texte, f).not.to.match(/\/home\/|\/tmp\/|\/root\/|[A-Z]:\\/);
      expect(texte, f).not.to.match(/\| discordance$/m);
      expect(texte, f).to.match(BILAN);
      const [, total, ...parts] = texte.match(BILAN).map(Number);
      expect(lignesSignatures(texte).length, f).to.equal(total);
      expect(parts.reduce((a, b) => a + b, 0), f).to.equal(total);
    }
    const version = lireJSON(PROJECT_ROOT, "node_modules", "ethers", "package.json").version;
    expect(sortieEthers().split("\n")[0]).to.equal(`# Confrontation des signatures des vecteurs CT-3 par ethers ${version} (verifyMessage, decryptKeystoreJsonSync)`);
    expect(versionExigee("eth-account")).to.equal("0.14.0");
    expect(sortieEthAccount().split("\n")[0]).to.equal(
      `# Confrontation des signatures des vecteurs CT-3 par eth-account ${versionExigee("eth-account")} (eth-keys ${versionExigee("eth-keys")}, eth-keyfile ${versionExigee("eth-keyfile")} ; Account.recover_message, encode_defunct, Account.decrypt)`,
    );
  });

  it("les deux programmes n'importent rien de scripts/ ; eth-account par encode_defunct(hexstr=) pour un vote et (primitive=) pour une inscription", function () {
    const js = lire(CONFRONTATION3, "ethers", "confronter_ethers.mjs");
    const importsJs = js.split("\n").filter((l) => /^\s*import\b|\bimport\(|\brequire\(/.test(l));
    expect(importsJs.length).to.be.above(0);
    for (const l of importsJs) expect(l).to.match(/^import [^;]+ from "(node:[a-z]+|ethers)";$/);
    const py = lire(CONFRONTATION3, "eth-account", "confronter_eth_account.py");
    const importsPy = py.split("\n").filter((l) => /^\s*(import|from)\s/.test(l));
    for (const l of importsPy) expect(l).to.match(/^(import (hashlib|importlib\.metadata|json|os|sys)|from eth_account(\.messages)? import (Account|encode_defunct))$/);
    expect(py).to.include("encode_defunct(hexstr=d_a)");
    expect(py).to.include('encode_defunct(primitive=texte.encode("utf-8"))');
    expect(py).not.to.match(/encode_defunct\(text=d_a|primitive=int\(/);
  });

  it("ethers.txt et eth-account.txt portent sur les vecteurs du dépôt : mêmes signatures, même ordre, mêmes adresses attendues ; une ligne par requête, inscription et preuve de l'annuaire de référence", function () {
    const e = lignesSignatures(sortieEthers());
    const a = lignesSignatures(sortieEthAccount());
    expect(a.map((l) => [l[0], l[1], l[2], l[4]])).to.deep.equal(e.map((l) => [l[0], l[1], l[2], l[4]]));
    const fichiers = (...p) => fs.readdirSync(path.join(CT3, ...p)).filter((f) => f.endsWith(".json")).sort();
    for (const sortie of [sortieEthers(), sortieEthAccount()]) {
      for (const f of fichiers("console", "requetes")) expect(sortie, f).to.match(new RegExp(`^console/requetes \\| ${echapper(f)} \\| 0 \\| 0x[0-9a-f]{40} \\| 0x[0-9a-f]{40} \\| concorde$`, "m"));
      for (const c of lireJSON(CT3, "annuaire", "inscriptions.json").cases) expect(sortie, c.id).to.include(`annuaire/inscriptions | ${c.id} | 0 |`);
      const ref = lireJSON(CT3, "annuaire", "annuaires", "reference.json");
      ref.entries.forEach((en, i) => en.addresses.forEach((ad, k) => expect(sortie).to.include(`annuaire/annuaires | reference.json#/entries/${i}/addresses/${k} | 0 | ${ad.address} | ${ad.address} | concorde`)));
      for (const c of lireJSON(CT3, "signatures", "normalisation.json").cases) expect(sortie, c.id).to.include(`signatures | normalisation.json#${c.id} | 0 |`);
      for (const f of ["pbkdf2-valide.json", "scrypt-valide.json", "cle-compte-2.json"]) expect(sortie, f).to.match(new RegExp(`^console/fichiers-cle \\| ${echapper(f)} \\| 0 \\| 0x[0-9a-f]{40} \\| 0x[0-9a-f]{40} \\| concorde$`, "m"));
      // D_A dont le premier octet est nul (EX-9.22) : recouvré sans perte.
      expect(sortie).to.match(/^console\/requetes \| apr-c0-542-approuve-compte-1\.json \| 0 \| 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 \| 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 \| concorde$/m);
    }
  });

  it("écarts attendus d'EX-9.22 : ethers refuse s haut et accepte v = 37 et 64 octets ; eth-account accepte v = 37, v = 38, et s haut ou v ∈ {0, 1} présentés au noyau", function () {
    const s = sortieEthers();
    // R4-F37, R4-F38.
    expect(s).to.match(/^console\/reponses \| s-haut-normalisee\.json \| 0 \| refusée \| 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 \| refusee_par_la_bibliotheque$/m);
    expect(s).to.match(/^console\/reponses \| v-37\.json \| 0 \| 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 \| forme refusée par CT-3 \| acceptee_par_la_bibliotheque$/m);
    expect(s).to.match(/^console\/reponses \| longueur-64\.json \| 0 \| 0x[0-9a-f]{40} \| forme refusée par CT-3 \| acceptee_par_la_bibliotheque$/m);
    // R4-F40, R4-F41.
    const a = sortieEthAccount();
    expect(a).to.match(/^console\/reponses \| s-haut-normalisee\.json \| 0 \| 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 \| 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 \| concorde$/m);
    expect(a).to.match(/^console\/reponses \| v-37\.json \| 0 \| 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 \| forme refusée par CT-3 \| acceptee_par_la_bibliotheque$/m);
    expect(a).to.match(/^console\/reponses \| v-38\.json \| 0 \| 0x[0-9a-f]{40} \| forme refusée par CT-3 \| acceptee_par_la_bibliotheque$/m);
    expect(a).to.match(/^console\/reponses \| longueur-64\.json \| 0 \| refusée \| forme refusée par CT-3 \| concorde$/m);
    expect(a).to.match(/^console\/reponses \| v-29\.json \| 0 \| refusée \| forme refusée par CT-3 \| concorde$/m);
    expect(a).to.match(/^decisions \| invalides\/sg5-s-haut\.json \| 1 \| 0x[0-9a-f]{40} \| forme refusée par CT-3 \| acceptee_par_la_bibliotheque$/m);
    expect(a).not.to.match(/\| refusee_par_la_bibliotheque$/m);
  });

  it("rejeu de ethers/confronter_ethers.mjs : code 0, sortie égale à sorties/ethers.txt", function () {
    this.timeout(120_000);
    const r = spawnSync(process.execPath, [path.join(CONFRONTATION3, "ethers", "confronter_ethers.mjs"), path.relative(PROJECT_ROOT, CT3)], { encoding: "utf8", cwd: PROJECT_ROOT, maxBuffer: 64 * 1024 * 1024 });
    expect(r.status, r.stderr).to.equal(0);
    expect(r.stdout).to.equal(sortieEthers());
  });

  it("rejeu de eth-account/confronter_eth_account.py (interpréteur aux versions d'exigences.txt présent) : code 0, sortie égale à sorties/eth-account.txt", function () {
    this.timeout(180_000);
    const ex = exigences();
    const python = process.env.NOORTRACE_PYTHON_CONFRONTATION || "python3";
    const code = `import importlib.metadata as m, json\nout = {}\nfor p in ${JSON.stringify(ex.map(([p]) => p))}:\n    try: out[p] = m.version(p)\n    except m.PackageNotFoundError: out[p] = None\nprint(json.dumps(out))`;
    const versions = spawnSync(python, ["-I", "-c", code], { encoding: "utf8" });
    if (versions.error || versions.status !== 0) this.skip();
    const lues = JSON.parse(versions.stdout);
    if (!ex.every(([p, v]) => lues[p] === v)) this.skip();
    const r = spawnSync(python, ["-I", path.join(CONFRONTATION3, "eth-account", "confronter_eth_account.py"), CT3], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    expect(r.status, r.stdout.split("\n").slice(-4).join("\n") + r.stderr).to.equal(0);
    expect(r.stdout).to.equal(sortieEthAccount());
  });
});

// ---------------------------------------------------------------------------
// CT-7 (spec/CT-7-securite-et-conformite.md, version 0.1, EX-A.24, EX-A.25) :
// sorties publiées de spec/vecteurs/ct-7/confrontation/ceremonies/ et
// attestations/ (jamais écrites par le générateur), par ethers (celui du
// dépôt) et par eth-account 0.14.0. Les programmes n'importent rien de
// scripts/ ; ceux d'ethers et d'eth-account portent les mêmes lignes, dans le
// même ordre, avec les mêmes adresses attendues : une ligne par signature de
// chaque procès-verbal de ceremonies/, de attestations/exemple/, de chaque
// cas de attestations.json, deux par cas de croises.json, et une par
// signature de la partie attestation-perimetre.json des dossiers de ct-1 et
// de ct-6. Les programmes ethers sont toujours rejoués ; ceux d'eth-account
// le sont quand un interpréteur Python porte exactement les versions
// d'exigences.txt (NOORTRACE_PYTHON_CONFRONTATION, sinon python3).
// ---------------------------------------------------------------------------

describe("CT-7 : sorties publiées de la confrontation des signatures de procès-verbal et d'attestation par des outils tiers (EX-A.24, EX-A.25)", function () {
  const VECTEURS = path.join(PROJECT_ROOT, "spec", "vecteurs");
  const CT7 = path.join(VECTEURS, "ct-7");
  const CONFRONTATION7 = path.join(CT7, "confrontation");
  const PARTIES = ["ceremonies", "attestations"];
  const sortie7 = (partie, outil) => lire(CONFRONTATION7, partie, "sorties", `${outil}.txt`);
  const exigences7 = (partie) =>
    lire(CONFRONTATION7, partie, "exigences.txt")
      .split("\n")
      .filter((l) => /^[A-Za-z0-9_.-]+==/.test(l))
      .map((l) => l.split("=="));
  const lignes7 = (texte) => texte.split("\n").filter((l) => l !== "" && !l.startsWith("# ")).map((l) => l.split(" | "));
  const BILAN7 = /^# bilan : (\d+) signatures ; concorde (\d+), acceptee_par_la_bibliotheque (\d+), refusee_par_la_bibliotheque (\d+), discordance 0$/m;
  const arguments7 = (partie) => (partie === "ceremonies" ? ["spec/vecteurs/ct-7"] : ["spec/vecteurs/ct-7", "spec/vecteurs/ct-1", "spec/vecteurs/ct-6"]);
  const casCeremonies = () => fs.readdirSync(path.join(CT7, "ceremonies")).filter((n) => fs.existsSync(path.join(CT7, "ceremonies", n, "proces-verbal.json"))).sort();
  const dossiersAvecPartie = (famille) =>
    fs.readdirSync(path.join(VECTEURS, famille, "dossiers")).filter((n) => fs.existsSync(path.join(VECTEURS, famille, "dossiers", n, "attestation-perimetre.json"))).sort();

  it("quatre sorties publiées, aucun chemin local, aucune discordance ; en-têtes aux versions d'ethers du dépôt et d'exigences.txt ; exigences.txt égal à celui de ct-3", function () {
    const version = lireJSON(PROJECT_ROOT, "node_modules", "ethers", "package.json").version;
    const exigences3 = lire(PROJECT_ROOT, "spec", "vecteurs", "ct-3", "confrontation", "eth-account", "exigences.txt").split("\n").filter((l) => /^[A-Za-z0-9_.-]+==/.test(l));
    for (const partie of PARTIES) {
      expect(fs.readdirSync(path.join(CONFRONTATION7, partie)).sort(), partie).to.deep.equal(["LISEZMOI.md", "confronter_eth_account.py", "confronter_ethers.mjs", "exigences.txt", "sorties"]);
      expect(fs.readdirSync(path.join(CONFRONTATION7, partie, "sorties")).sort(), partie).to.deep.equal(["eth-account.txt", "ethers.txt"]);
      for (const outil of ["ethers", "eth-account"]) {
        const texte = sortie7(partie, outil);
        expect(texte, `${partie}/${outil}`).not.to.match(/\/home\/|\/tmp\/|\/root\/|[A-Z]:\\/);
        expect(texte, `${partie}/${outil}`).not.to.match(/\| discordance$/m);
        expect(texte, `${partie}/${outil}`).to.match(BILAN7);
        const [, total, ...parts] = texte.match(BILAN7).map(Number);
        expect(lignes7(texte).length, `${partie}/${outil}`).to.equal(total);
        expect(parts.reduce((a, b) => a + b, 0), `${partie}/${outil}`).to.equal(total);
      }
      const ex = exigences7(partie);
      expect(ex.map((l) => l.join("=="))).to.deep.equal(exigences3);
      const v = (p) => ex.find(([n]) => n === p)[1];
      expect(v("eth-account")).to.equal("0.14.0");
      const objet = partie === "ceremonies" ? "des procès-verbaux des vecteurs CT-7" : "d'attestation des vecteurs CT-7, CT-1 et CT-6";
      expect(sortie7(partie, "ethers").split("\n")[0]).to.equal(`# Confrontation des signatures ${objet} par ethers ${version} (verifyMessage, getBytes)`);
      expect(sortie7(partie, "eth-account").split("\n")[0]).to.equal(`# Confrontation des signatures ${objet} par eth-account ${v("eth-account")} (eth-keys ${v("eth-keys")} ; Account.recover_message, encode_defunct)`);
    }
  });

  it("les programmes n'importent rien de scripts/ ; ethers par verifyMessage(getBytes(…)), eth-account par encode_defunct(primitive=…)", function () {
    for (const partie of PARTIES) {
      const js = lire(CONFRONTATION7, partie, "confronter_ethers.mjs");
      const importsJs = js.split("\n").filter((l) => /^\s*import\b|\bimport\(|\brequire\(/.test(l));
      expect(importsJs.length).to.be.above(0);
      for (const l of importsJs) expect(l, partie).to.match(/^import [^;]+ from "(node:[a-z]+|ethers)";$/);
      expect(js).to.include("verifyMessage(");
      expect(js).to.match(/getBytes\(d\)/);
      const py = lire(CONFRONTATION7, partie, "confronter_eth_account.py");
      for (const l of py.split("\n").filter((x) => /^\s*(import|from)\s/.test(x))) expect(l, partie).to.match(/^(import (importlib\.metadata|json|os|sys)|from eth_account(\.messages)? import (Account|encode_defunct))$/);
      expect(py).to.include("encode_defunct(primitive=bytes.fromhex(d[2:]))");
      expect(py).not.to.match(/encode_defunct\(text=d|primitive=int\(/);
    }
  });

  it("ceremonies : une ligne par signature de chaque procès-verbal, mêmes lignes pour les deux outils ; signataires de attendu.json recouverts", function () {
    const e = lignes7(sortie7("ceremonies", "ethers"));
    const a = lignes7(sortie7("ceremonies", "eth-account"));
    expect(a.map((l) => [l[0], l[1], l[2], l[4]])).to.deep.equal(e.map((l) => [l[0], l[1], l[2], l[4]]));
    const attendues = [];
    for (const n of casCeremonies()) {
      const pv = JSON.parse(lire(CT7, "ceremonies", n, "proces-verbal.json"));
      const attendu = lireJSON(CT7, "ceremonies", n, "attendu.json");
      const famille = attendu.digest === null ? "ceremonies/cr1-lecture-permissive" : "ceremonies";
      pv.signatures.forEach((s, i) => attendues.push([famille, n, String(i)]));
      for (const sortie of [e, a]) {
        const adresses = sortie.filter((l) => l[1] === n && l[5] === "concorde" && l[3] === l[4]).map((l) => l[3]);
        for (const adr of attendu.signers) expect(adresses, `${n} ${adr}`).to.include(adr);
      }
    }
    expect(e.map((l) => l.slice(0, 3))).to.deep.equal(attendues);
    for (const n of casCeremonies().filter((x) => x.startsWith("valide-"))) {
      for (const sortie of [e, a]) expect(sortie.filter((l) => l[1] === n).every((l) => l[5] === "concorde"), n).to.equal(true);
    }
  });

  it("attestations : exemple, chaque cas de attestations.json, deux lignes par cas de croises.json, chaque dossier de ct-1 et de ct-6 à partie signée ; mêmes lignes pour les deux outils", function () {
    const e = lignes7(sortie7("attestations", "ethers"));
    const a = lignes7(sortie7("attestations", "eth-account"));
    expect(a.map((l) => [l[0], l[1], l[2], l[4]])).to.deep.equal(e.map((l) => [l[0], l[1], l[2], l[4]]));
    const attendues = [];
    for (const f of ["condense.json", "attestation-signee.json"]) lireJSON(CT7, "attestations", "exemple", f).signatures.forEach((s, i) => attendues.push(["attestations/exemple", f, String(i), s.address]));
    for (const c of lireJSON(CT7, "attestations", "attestations.json").cases) {
      const signee = typeof c.input.signed === "string" ? JSON.parse(c.input.signed) : c.input.signed;
      const at1 = c.expected.checks.find((x) => x.id === "AT-1").status === "reussi";
      signee.signatures.forEach((s, i) => attendues.push(["attestations/cas", c.name, String(i), at1 ? (c.expected.recovered[i] ?? "forme refusée par CT-7") : null]));
    }
    const croises = lireJSON(CT7, "attestations", "croises.json");
    for (const c of croises.cases) attendues.push(["attestations/croises", c.name, "0", croises.address], ["attestations/croises", c.name, "1", c.expected.recovered]);
    for (const famille of ["ct-1", "ct-6"]) {
      const noms = dossiersAvecPartie(famille);
      expect(noms.length, famille).to.be.at.least(4);
      for (const n of noms) {
        const partie = lireJSON(VECTEURS, famille, "dossiers", n, "attestation-perimetre.json");
        if (partie === null || typeof partie !== "object") continue;
        const at3 = lireJSON(VECTEURS, famille, "dossiers", n, "attendu.json").perimeter_checks.find((x) => x.id === "AT-3").status === "reussi";
        partie.signed.signatures.forEach((s, i) => attendues.push([`${famille}/dossiers`, n, String(i), at3 ? s.address : null]));
      }
    }
    expect(e.length).to.equal(attendues.length);
    attendues.forEach(([famille, cas, indice, adresse], k) => {
      expect(e[k].slice(0, 3), `${famille} ${cas} ${indice}`).to.deep.equal([famille, cas, indice]);
      if (adresse !== null) expect(e[k][4], `${famille} ${cas} ${indice}`).to.equal(adresse);
    });
    // Exemple de CT-7 §7.2 : comptes 1 et 2 recouverts par les deux outils.
    for (const sortie of [sortie7("attestations", "ethers"), sortie7("attestations", "eth-account")]) {
      expect(sortie).to.include("attestations/exemple | condense.json | 0 | 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 | 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 | concorde");
      expect(sortie).to.include("attestations/exemple | condense.json | 1 | 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc | 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc | concorde");
      expect(sortie).to.include("attestations/cas | invalide-at3-signature-substituee | 1 | 0x90f79bf6eb2c4f870365e785982e1f101e93b906 | 0x90f79bf6eb2c4f870365e785982e1f101e93b906 | concorde");
    }
  });

  it("écarts inscrits d'EX-A.25, seulement sur les cas invalides de forme : eth-account accepte s haut et v = 0, ethers accepte v = 0 et refuse s haut", function () {
    const ce = sortie7("ceremonies", "ethers");
    const ca = sortie7("ceremonies", "eth-account");
    expect(ce).to.match(/^ceremonies \| invalide-cr11-s-haut \| 1 \| refusée \| forme refusée par CT-7 \| concorde$/m);
    expect(ca).to.match(/^ceremonies \| invalide-cr11-s-haut \| 1 \| 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc \| forme refusée par CT-7 \| acceptee_par_la_bibliotheque$/m);
    const ae = sortie7("attestations", "ethers");
    const aa = sortie7("attestations", "eth-account");
    expect(ae).to.match(/^attestations\/cas \| invalide-at3-s-haut \| 1 \| refusée \| forme refusée par CT-7 \| concorde$/m);
    expect(aa).to.match(/^attestations\/cas \| invalide-at3-s-haut \| 1 \| 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc \| forme refusée par CT-7 \| acceptee_par_la_bibliotheque$/m);
    for (const s of [ae, aa]) expect(s).to.match(/^attestations\/cas \| invalide-at3-v-hors-domaine \| 1 \| 0x[0-9a-f]{40} \| forme refusée par CT-7 \| acceptee_par_la_bibliotheque$/m);
    for (const s of [ce, ca, ae, aa]) {
      const ecarts = s.split("\n").filter((l) => / \| acceptee_par_la_bibliotheque$/.test(l));
      for (const l of ecarts) expect(l).to.match(/ \| invalide-(cr11-s-haut|at3-s-haut|at3-v-hors-domaine) \| /);
      expect(s).not.to.match(/\| refusee_par_la_bibliotheque$/m);
    }
  });

  for (const partie of PARTIES) {
    it(`rejeu de ${partie}/confronter_ethers.mjs : code 0, sortie égale à ${partie}/sorties/ethers.txt`, function () {
      this.timeout(180_000);
      const r = spawnSync(process.execPath, [path.join(CONFRONTATION7, partie, "confronter_ethers.mjs"), ...arguments7(partie)], { encoding: "utf8", cwd: PROJECT_ROOT, maxBuffer: 64 * 1024 * 1024 });
      expect(r.status, r.stderr).to.equal(0);
      expect(r.stdout).to.equal(sortie7(partie, "ethers"));
    });

    it(`rejeu de ${partie}/confronter_eth_account.py (interpréteur aux versions d'exigences.txt présent) : code 0, sortie égale à ${partie}/sorties/eth-account.txt`, function () {
      this.timeout(180_000);
      const ex = exigences7(partie);
      const python = process.env.NOORTRACE_PYTHON_CONFRONTATION || "python3";
      const code = `import importlib.metadata as m, json\nout = {}\nfor p in ${JSON.stringify(ex.map(([p]) => p))}:\n    try: out[p] = m.version(p)\n    except m.PackageNotFoundError: out[p] = None\nprint(json.dumps(out))`;
      const versions = spawnSync(python, ["-I", "-c", code], { encoding: "utf8" });
      if (versions.error || versions.status !== 0) this.skip();
      const lues = JSON.parse(versions.stdout);
      if (!ex.every(([p, v]) => lues[p] === v)) this.skip();
      const r = spawnSync(python, ["-I", path.join(CONFRONTATION7, partie, "confronter_eth_account.py"), ...arguments7(partie)], { encoding: "utf8", cwd: PROJECT_ROOT, maxBuffer: 64 * 1024 * 1024 });
      expect(r.status, r.stdout.split("\n").slice(-4).join("\n") + r.stderr).to.equal(0);
      expect(r.stdout).to.equal(sortie7(partie, "eth-account"));
    });
  }
});
