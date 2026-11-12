// Publication préparée de l'étape 7, sans rien publier (CT-6 §14.3 et §14.4,
// CT-8 EX-3.6, EX-3.13, EX-3.14 ; CT-9 complément de TV-55, partie
// mécanique de TQ-8).
//
// - scripts/publication/preparer-version.mjs rejoue à blanc la production
//   des fichiers d'une version : deux préparations, chacune avec son cache Go
//   neuf, donnent les mêmes octets ; SHA256SUMS est exact ; l'archive de
//   déploiement est l'ustar de la recette GNU tar d'EX-13.15 ; la note et la
//   déclaration de provenance portent les empreintes préparées.
// - SHA256SUMS est signé au format minisign par une clé d'essai éphémère,
//   créée en mémoire pendant l'essai et jamais écrite dans le dépôt
//   (implémentation compatible par le module crypto de Node.js,
//   test/fixtures/publication/minisign.mjs) ; la signature est vérifiée,
//   puis refusée après chaque falsification. Si minisign est installé, il
//   vérifie la même signature.
// - .github/workflows/version.yml est relu : déclencheurs, droits,
//   épinglage des actions par SHA, image par condensé, aucune publication.
//
// Aucun accès au réseau ; tout fichier va sous NOORTRACE_TMP (ou
// os.tmpdir()) et est détruit. Sans go1.27.3 (NOORTRACE_GO_BIN, à défaut le
// PATH), les essais qui construisent sont en attente ; sans GNU tar, celui
// de la recette d'EX-13.15 aussi.

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import yaml from "js-yaml";
import { RACINE, enAttente, environnementGo, repertoireTemporaire } from "./fixtures/verification-page/outils.mjs";
import * as minisign from "./fixtures/publication/minisign.mjs";
import { ecrireUstar, decouperNom, Refus } from "../scripts/publication/preparer-version.mjs";

const SCRIPT = path.join(RACINE, "scripts", "publication", "preparer-version.mjs");
const WORKFLOW = path.join(RACINE, ".github", "workflows", "version.yml");
const VERSION = "0.1.0";
const NOMS = [
  "LICENCES-TIERCES",
  "LICENSE",
  "NOTICE",
  `noortrace-deploiement-${VERSION}.tar`,
  "noortrace-verifier-linux-amd64",
  "noortrace-verifier-linux-amd64.go-version-m.txt",
  "noortrace-verifier-linux-arm64",
  "noortrace-verifier-linux-arm64.go-version-m.txt",
];
const PRODUITS = [...NOMS, "NOTE-DE-VERSION.md", "SHA256SUMS", "provenance.intoto.json"].sort();

// Actions épinglées de version.yml : SHA de commit de l'étiquette, date du
// commit relevée sur le dépôt public de l'action (git ls-remote et git
// fetch du 2026-11-12), date d'ajout ; la règle du dépôt exige plus de deux
// semaines entre les deux.
const AJOUT = "2026-11-12";
const ACTIONS_EPINGLEES = {
  "actions/checkout": { sha: "d23441a48e516b6c34aea4fa41551a30e30af803", version: "v6.1.0", date: "2026-07-16" },
  "actions/setup-node": { sha: "249970729cb0ef3589644e2896645e5dc5ba9c38", version: "v6.5.0", date: "2026-07-13" },
  "actions/upload-artifact": { sha: "b7c566a772e6b6bfb58ed0dc250532a479d7789f", version: "v6.0.0", date: "2025-12-12" },
  "actions/download-artifact": { sha: "37930b1c2abaa49bbe596cd826c3c89aef350131", version: "v7.0.0", date: "2025-12-12" },
};
// Image de construction : index de golang:1.27.3-bookworm publié le
// 2026-10-21 (configuration linux/amd64 créée le 2026-10-21T02:16:44Z,
// GOLANG_VERSION=1.27.3).
const IMAGE = { ref: "golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5", date: "2026-10-21" };
const NODE = { version: "22.23.4", date: "2026-10-20" };

const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");
const jours = (a, b) => (Date.parse(b) - Date.parse(a)) / 86400000;

function lancer(args, env) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { cwd: RACINE, env, encoding: "utf8" });
}

function lireRepertoire(dir) {
  return new Map(fs.readdirSync(dir).sort().map((n) => [n, fs.readFileSync(path.join(dir, n))]));
}

function gnuTar() {
  const r = spawnSync("tar", ["--version"], { encoding: "utf8" });
  return r.status === 0 && /GNU tar/.test(r.stdout);
}

function teteGit() {
  const h = spawnSync("git", ["rev-parse", "HEAD"], { cwd: RACINE, encoding: "utf8" });
  const d = spawnSync("git", ["log", "-1", "--format=%ct"], { cwd: RACINE, encoding: "utf8" });
  if (h.status !== 0 || d.status !== 0) return { commit: "0".repeat(40), date: "1794475464" };
  return { commit: h.stdout.trim(), date: d.stdout.trim() };
}

describe("Étape 7 : publication préparée sans rien publier (CT-6 §14.4, CT-8 EX-3.13, EX-3.14)", function () {
  this.timeout(600000);
  const goEnv = environnementGo();
  const { commit, date } = teteGit();
  let tmp;
  let p1;
  let p2;
  let envBase;

  before(function () {
    tmp = repertoireTemporaire("noortrace-publication");
    if (goEnv === null) return;
    envBase = { ...goEnv, NOORTRACE_TMP: tmp };
    const args = ["--version", VERSION, "--commit", commit, "--date", date];
    p1 = path.join(tmp, "preparation-1");
    p2 = path.join(tmp, "preparation-2");
    for (const [sortie, cache] of [[p1, "cache-1"], [p2, "cache-2"]]) {
      const r = lancer([...args, "--sortie", sortie], { ...envBase, GOCACHE: path.join(tmp, cache) });
      if (r.status !== 0) throw new Error(`preparer-version.mjs : code ${r.status}\n${r.stderr}`);
    }
    for (const cache of ["cache-1", "cache-2"]) fs.rmSync(path.join(tmp, cache), { recursive: true, force: true });
  });

  after(function () {
    if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("TV-55, complément (étape 7) : deux préparations de la version à blanc, chacune avec son cache Go neuf, donnent les mêmes fichiers aux mêmes octets ; binaires d'un second constructeur égaux acceptés par --temoin, un octet changé refusé (code 1, rien sous --sortie)", function () {
    if (goEnv === null) return enAttente(this, "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH)");
    const a = lireRepertoire(p1);
    const b = lireRepertoire(p2);
    expect([...a.keys()]).to.deep.equal(PRODUITS);
    expect([...b.keys()]).to.deep.equal(PRODUITS);
    for (const n of PRODUITS) expect(a.get(n).equals(b.get(n)), n).to.equal(true);

    const args = ["--version", VERSION, "--commit", commit, "--date", date, "--binaires", p1];
    const accepte = path.join(tmp, "temoin-egal");
    const r = lancer([...args, "--temoin", p2, "--sortie", accepte], envBase);
    expect(r.status, r.stderr).to.equal(0);
    expect(fs.readFileSync(path.join(accepte, "SHA256SUMS")).equals(a.get("SHA256SUMS"))).to.equal(true);

    const temoin = path.join(tmp, "temoin-altere");
    fs.mkdirSync(temoin);
    for (const n of ["noortrace-verifier-linux-amd64", "noortrace-verifier-linux-arm64"]) fs.copyFileSync(path.join(p2, n), path.join(temoin, n));
    const altere = fs.readFileSync(path.join(temoin, "noortrace-verifier-linux-arm64"));
    altere[altere.length - 1] ^= 1;
    fs.writeFileSync(path.join(temoin, "noortrace-verifier-linux-arm64"), altere);
    const refuse = path.join(tmp, "temoin-refuse");
    const s = lancer([...args, "--temoin", temoin, "--sortie", refuse], envBase);
    expect(s.status).to.equal(1);
    expect(s.stderr).to.include("noortrace-verifier-linux-arm64 : constructeurs en désaccord");
    expect(fs.existsSync(refuse)).to.equal(false);
  });

  it("TV-55, complément (étape 7) : SHA256SUMS exact (une ligne « <sha256>  <nom> » par fichier, triée, recalculée ; sha256sum --strict -c rend 0) ; binaires ELF amd64 et arm64 ; go version -m de go1.27.3 avec CGO_ENABLED=0 et -trimpath ; LICENSE, NOTICE et LICENCES-TIERCES du dépôt", function () {
    if (goEnv === null) return enAttente(this, "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH)");
    const sums = fs.readFileSync(path.join(p1, "SHA256SUMS"), "utf8");
    const attendu = NOMS.map((n) => `${sha256(fs.readFileSync(path.join(p1, n)))}  ${n}\n`).join("");
    expect(sums).to.equal(attendu);
    const c = spawnSync("sha256sum", ["--strict", "-c", "SHA256SUMS"], { cwd: p1, encoding: "utf8" });
    expect(c.status, c.stdout + c.stderr).to.equal(0);
    expect(c.stdout.trim().split("\n")).to.deep.equal(NOMS.map((n) => `${n}: OK`));

    for (const [arch, machine] of [["amd64", 0x3e], ["arm64", 0xb7]]) {
      const nom = `noortrace-verifier-linux-${arch}`;
      const bin = fs.readFileSync(path.join(p1, nom));
      expect(bin.subarray(0, 4).toString("latin1")).to.equal("\x7fELF");
      expect(bin.readUInt16LE(18), nom).to.equal(machine);
      expect(fs.statSync(path.join(p1, nom)).mode & 0o777).to.equal(0o755);
      const m = fs.readFileSync(path.join(p1, `${nom}.go-version-m.txt`), "utf8");
      expect(m.split("\n")[0]).to.equal(`${nom}: go1.27.3`);
      for (const l of ["\tpath\tgithub.com/noorfinances-eng/noortrace/verificateur/cmd/noortrace-verifier", "\tdep\tgithub.com/decred/dcrd/dcrec/secp256k1/v4\tv4.4.1", "\tdep\tgolang.org/x/crypto\tv0.58.0", "\tbuild\t-trimpath=true", "\tbuild\tCGO_ENABLED=0", "\tbuild\tGOOS=linux", `\tbuild\tGOARCH=${arch}`]) {
        expect(m, `${nom} : ${l}`).to.include(l);
      }
    }
    for (const [nom, source] of [["LICENSE", "LICENSE"], ["NOTICE", "NOTICE"], ["LICENCES-TIERCES", "verificateur/LICENCES-TIERCES"]]) {
      expect(fs.readFileSync(path.join(p1, nom)).equals(fs.readFileSync(path.join(RACINE, source))), nom).to.equal(true);
    }
  });

  it("TV-55, complément (étape 7) : archive de déploiement ustar déterministe, égale octet pour octet à la recette GNU tar d'EX-13.15 sur ses fichiers extraits par tar -xkf, dont SHA256SUMS se vérifie ; découpage nom et préfixe d'un nom de 103 octets égal à GNU tar ; nom non représentable refusé", function () {
    if (!gnuTar()) return enAttente(this, "GNU tar absent");
    expect(decouperNom("a".repeat(100)).prefix.length).to.equal(0);
    expect(() => decouperNom(`d/${"b".repeat(101)}`)).to.throw(Refus, "non représentable");
    const synth = path.join(tmp, "synthese");
    const long = `${"r".repeat(60)}/${"s".repeat(30)}/${"f".repeat(11)}`;
    expect(Buffer.byteLength(long)).to.equal(103);
    fs.mkdirSync(path.join(synth, path.dirname(long)), { recursive: true });
    fs.writeFileSync(path.join(synth, long), "contenu\n");
    fs.writeFileSync(path.join(synth, "Z"), "");
    fs.writeFileSync(path.join(synth, "a.txt"), Buffer.alloc(513, 7));
    const liste = path.join(tmp, "liste-synthese.txt");
    fs.writeFileSync(liste, ["Z", "a.txt", long].join("\n") + "\n");
    const recette = (cwd, l, sortie, mtime) => spawnSync("tar", ["--format=ustar", "--no-recursion", "--owner=0", "--group=0", "--numeric-owner", "--mode=0644", `--mtime=@${mtime}`, "-cf", sortie, "-T", l], { cwd, env: { ...process.env, LC_ALL: "C" }, encoding: "utf8" });
    const gnuSynth = path.join(tmp, "synthese.tar");
    expect(recette(synth, liste, gnuSynth, 1794475464).status).to.equal(0);
    const notre = ecrireUstar([{ nom: long, octets: Buffer.from("contenu\n") }, { nom: "a.txt", octets: Buffer.alloc(513, 7) }, { nom: "Z", octets: Buffer.alloc(0) }], 1794475464);
    expect(notre.equals(fs.readFileSync(gnuSynth))).to.equal(true);

    if (goEnv === null) return enAttente(this, "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH) : archive de la préparation non produite");
    const archive = path.join(p1, `noortrace-deploiement-${VERSION}.tar`);
    const extrait = path.join(tmp, "archive-extraite");
    fs.mkdirSync(extrait);
    expect(spawnSync("tar", ["-xkf", archive, "-C", extrait]).status).to.equal(0);
    const v = spawnSync("sha256sum", ["--strict", "-c", "SHA256SUMS", "--quiet"], { cwd: extrait, encoding: "utf8" });
    expect(v.status, v.stdout + v.stderr).to.equal(0);
    for (const f of ["deploiement/compose/rapide.yaml", "deploiement/config/rapide/configuration.json", "scripts/deploiement/controle-prealable.mjs", "NOTICE", "LICENSE"]) {
      expect(fs.existsSync(path.join(extrait, f)), f).to.equal(true);
    }
    const fichiers = [];
    const parcourir = (rel) => {
      for (const e of fs.readdirSync(path.join(extrait, rel), { withFileTypes: true })) {
        const p = rel ? `${rel}/${e.name}` : e.name;
        if (e.isDirectory()) parcourir(p);
        else fichiers.push(p);
      }
    };
    parcourir("");
    fichiers.sort((x, y) => Buffer.compare(Buffer.from(x), Buffer.from(y)));
    const listeArchive = path.join(tmp, "liste-archive.txt");
    fs.writeFileSync(listeArchive, fichiers.join("\n") + "\n");
    const gnu = path.join(tmp, "gnu.tar");
    const r = recette(extrait, listeArchive, gnu, date);
    expect(r.status, r.stderr).to.equal(0);
    expect(fs.readFileSync(gnu).equals(fs.readFileSync(archive))).to.equal(true);
    expect(fs.statSync(archive).size % 10240).to.equal(0);
  });

  it("TV-55, complément (étape 7) : SHA256SUMS signé au format minisign par une clé d'essai éphémère (en mémoire, détruite) : signature vérifiée avec le commentaire de confiance de la note (version et date), puis refusée après falsification de SHA256SUMS, du commentaire de confiance, de la signature ou de la clé", function () {
    const sums = goEnv === null
      ? Buffer.from(`${"0".repeat(64)}  noortrace-verifier-linux-amd64\n`)
      : fs.readFileSync(path.join(p1, "SHA256SUMS"));
    const dateJour = new Date(Number(date) * 1000).toISOString().slice(0, 10);
    const commentaire = `noortrace ${VERSION} ${dateJour}`;
    if (goEnv !== null) expect(fs.readFileSync(path.join(p1, "NOTE-DE-VERSION.md"), "utf8")).to.include(`trusted comment: ${commentaire}\n`);
    let cle = minisign.creerCleEssai();
    const pub = minisign.textePublique(cle);
    const sig = minisign.signer(cle, sums, commentaire);
    expect(pub.split("\n")[0]).to.equal(`untrusted comment: minisign public key ${minisign.texteIdentifiant(cle.id)}`);
    expect(minisign.verifier(pub, sig, sums)).to.deep.equal({ valide: true, commentaire });

    // minisign installé : il vérifie la même signature (sinon, la seule
    // implémentation compatible est employée ; confrontation hors dépôt
    // consignée au rapport de l'étape).
    const outil = spawnSync("minisign", ["-v"], { encoding: "utf8" });
    if (outil.status === 0) {
      const d = path.join(tmp, "minisign");
      fs.mkdirSync(d);
      fs.writeFileSync(path.join(d, "SHA256SUMS"), sums);
      fs.writeFileSync(path.join(d, "cle.pub"), pub);
      fs.writeFileSync(path.join(d, "SHA256SUMS.minisig"), sig);
      expect(spawnSync("minisign", ["-Vm", "SHA256SUMS", "-p", "cle.pub"], { cwd: d }).status).to.equal(0);
      fs.writeFileSync(path.join(d, "SHA256SUMS"), Buffer.concat([sums, Buffer.from("x")]));
      expect(spawnSync("minisign", ["-Vm", "SHA256SUMS", "-p", "cle.pub"], { cwd: d }).status).to.not.equal(0);
      fs.rmSync(d, { recursive: true, force: true });
    }

    const falsifie = Buffer.from(sums);
    falsifie[0] = falsifie[0] === 0x30 ? 0x31 : 0x30;
    expect(minisign.verifier(pub, sig, falsifie)).to.deep.equal({ valide: false, raison: "signature invalide" });
    const lignes = sig.split("\n");
    const autreCommentaire = [lignes[0], lignes[1], `trusted comment: noortrace 9.9.9 ${dateJour}`, lignes[3], ""].join("\n");
    expect(minisign.verifier(pub, autreCommentaire, sums)).to.deep.equal({ valide: false, raison: "commentaire de confiance altéré" });
    const brute = Buffer.from(lignes[1], "base64");
    brute[20] ^= 0x80;
    const sigAlteree = [lignes[0], brute.toString("base64"), lignes[2], lignes[3], ""].join("\n");
    expect(minisign.verifier(pub, sigAlteree, sums).valide).to.equal(false);
    const autre = minisign.creerCleEssai();
    expect(minisign.verifier(minisign.textePublique(autre), sig, sums)).to.deep.equal({ valide: false, raison: "signature d'une autre clé (identifiant différent)" });
    const memeId = { ...autre, id: cle.id };
    expect(minisign.verifier(minisign.textePublique(memeId), sig, sums)).to.deep.equal({ valide: false, raison: "signature invalide" });
    cle = null;
  });

  it("TV-55, complément (étape 7) : note de version remplie depuis le gabarit (SHA-256 des binaires et de l'archive, go version -m, images noortrace/* de images.json non publiées, ou leur condensé par --condenses) ; provenance in-toto SLSA v1 préparée, non signée, sujets égaux aux fichiers de SHA256SUMS et à SHA256SUMS", function () {
    if (goEnv === null) return enAttente(this, "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH)");
    const note = fs.readFileSync(path.join(p1, "NOTE-DE-VERSION.md"), "utf8");
    const sums = fs.readFileSync(path.join(p1, "SHA256SUMS"), "utf8");
    expect(note).to.not.match(/\{\{|\}\}/);
    expect(note).to.include(`Commit : \`${commit}\``);
    for (const l of sums.trim().split("\n")) {
      const [h, n] = l.split("  ");
      expect(note).to.include(`| \`${n}\` | ${fs.statSync(path.join(p1, n)).size} | \`${h}\` |`);
    }
    const shaArchive = sha256(fs.readFileSync(path.join(p1, `noortrace-deploiement-${VERSION}.tar`)));
    expect(note).to.include(`echo '${shaArchive}  noortrace-deploiement-${VERSION}.tar' | sha256sum -c`);
    expect(note).to.include(fs.readFileSync(path.join(p1, "noortrace-verifier-linux-arm64.go-version-m.txt"), "utf8").trimEnd());
    const images = JSON.parse(fs.readFileSync(path.join(RACINE, "deploiement", "images", "images.json"), "utf8"));
    const noms = [...new Set(Object.values(images.services).map((s) => s.image).filter((i) => i.startsWith("noortrace/")))];
    expect(noms.length).to.be.greaterThan(0);
    for (const i of noms) expect(note).to.match(new RegExp(`\\| \`${i.replace("/", "\\/")}\` \\| \`[^\`]+\` \\| non publiée à cette version \\|`));

    const p = JSON.parse(fs.readFileSync(path.join(p1, "provenance.intoto.json"), "utf8"));
    expect(p._type).to.equal("https://in-toto.io/Statement/v1");
    expect(p.predicateType).to.equal("https://slsa.dev/provenance/v1");
    expect(p.subject).to.deep.equal([...NOMS, "SHA256SUMS"].map((n) => ({ name: n, digest: { sha256: sha256(fs.readFileSync(path.join(p1, n))) } })));
    expect(p.predicate.buildDefinition.resolvedDependencies).to.deep.equal([{ uri: `git+https://depot.invalid/noortrace@refs/tags/v${VERSION}`, digest: { gitCommit: commit } }]);
    expect(p.predicate.buildDefinition.internalParameters.noortrace).to.include({ version: VERSION, source_date_epoch: Number(date), go: "go1.27.3", image_construction: null });
    expect(JSON.stringify(p)).to.not.match(/signature|dsseEnvelope|BEGIN/i);

    const condenses = path.join(tmp, "condenses.json");
    const fictif = `sha256:${"ab".repeat(32)}`;
    fs.writeFileSync(condenses, JSON.stringify({ [noms[0]]: fictif }));
    const sortie = path.join(tmp, "avec-condenses");
    const r = lancer(["--version", VERSION, "--commit", commit, "--date", date, "--binaires", p1, "--condenses", condenses, "--image-construction", IMAGE.ref, "--sortie", sortie], envBase);
    expect(r.status, r.stderr).to.equal(0);
    const note2 = fs.readFileSync(path.join(sortie, "NOTE-DE-VERSION.md"), "utf8");
    expect(note2).to.match(new RegExp(`\\| \`${noms[0].replace("/", "\\/")}\` \\| \`[^\`]+\` \\| \`${fictif}\` \\|`));
    expect(note2).to.include(`Image de construction (CT-6 EX-14.7) : \`${IMAGE.ref}\`.`);
    expect(fs.readFileSync(path.join(sortie, "SHA256SUMS")).equals(fs.readFileSync(path.join(p1, "SHA256SUMS")))).to.equal(true);
  });

  it("TV-55, complément (étape 7) : preparer-version.mjs refuse une option manquante, invalide ou une sortie existante (code 2), une autre chaîne que go1.27.3 et --exiger-arbre-propre sur un autre commit que HEAD (code 1), sans rien laisser sous --sortie", function () {
    const base = ["--version", VERSION, "--commit", commit, "--date", date];
    const sortie = path.join(tmp, "refus");
    const env = { ...process.env, NOORTRACE_TMP: tmp };
    for (const args of [
      ["--commit", commit, "--date", date, "--sortie", sortie],
      ["--version", "v0.1", "--commit", commit, "--date", date, "--sortie", sortie],
      ["--version", VERSION, "--commit", "ABC", "--date", date, "--sortie", sortie],
      ["--version", VERSION, "--commit", commit, "--date", "-1", "--sortie", sortie],
      [...base, "--temoin", tmp, "--sortie", sortie],
      [...base, "--image-construction", "golang:1.27.3", "--sortie", sortie],
      [...base, "--inconnue", "--sortie", sortie],
      [...base, "--sortie", tmp],
    ]) {
      const r = lancer(args, env);
      expect(r.status, args.join(" ")).to.equal(2);
      expect(fs.existsSync(sortie)).to.equal(false);
    }
    const faux = path.join(tmp, "faux-go");
    fs.mkdirSync(faux);
    fs.writeFileSync(path.join(faux, "go"), "#!/bin/sh\necho go1.24.7\n", { mode: 0o755 });
    const r = lancer([...base, "--sortie", sortie], { ...env, PATH: `${faux}${path.delimiter}${process.env.PATH}` });
    expect(r.status).to.equal(1);
    expect(r.stderr).to.include("Go go1.27.3 exigé (CT-6 EX-14.3), go1.24.7 trouvé");
    expect(fs.existsSync(sortie)).to.equal(false);
    if (goEnv === null) return enAttente(this, "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH) : refus de --exiger-arbre-propre non essayé");
    const s = lancer(["--version", VERSION, "--commit", "f".repeat(40), "--date", date, "--binaires", p1, "--exiger-arbre-propre", "--sortie", sortie], envBase);
    expect(s.status).to.equal(1);
    expect(s.stderr).to.include(`≠ --commit ${"f".repeat(40)}`);
    expect(fs.existsSync(sortie)).to.equal(false);
  });

  it("TV-55 et TQ-8, complément (étape 7) : .github/workflows/version.yml ne se déclenche qu'à la main ou sur une étiquette v*, n'a que contents: read, épingle chaque action par SHA de commit d'une version publiée plus de deux semaines avant, Node.js par version exacte, l'image de construction et Go par empreinte, et ne contient aucune étape de publication, de signature ni d'attestation", function () {
    const texte = fs.readFileSync(WORKFLOW, "utf8");
    const w = yaml.load(texte);
    expect(Object.keys(w.on).sort()).to.deep.equal(["push", "workflow_dispatch"]);
    expect(w.on.push).to.deep.equal({ tags: ["v*"] });
    expect(Object.keys(w.on.workflow_dispatch)).to.deep.equal(["inputs"]);
    expect(w.permissions).to.deep.equal({ contents: "read" });
    const travaux = Object.entries(w.jobs);
    expect(travaux.map(([n]) => n)).to.deep.equal(["version", "binaires-conteneur", "binaires-hote", "preparation"]);
    const runs = [];
    const uses = [];
    for (const [nom, t] of travaux) {
      expect(t.permissions, `${nom} : permissions`).to.equal(undefined);
      expect(t["runs-on"], nom).to.equal("ubuntu-24.04");
      for (const pas of t.steps) {
        if (pas.run !== undefined) runs.push(pas.run);
        if (pas.uses !== undefined) uses.push(pas);
      }
    }
    // Épinglage des actions (CT-6 EX-14.7) et dates de publication.
    expect(uses.length).to.be.greaterThan(0);
    for (const pas of uses) {
      const m = /^([\w.-]+\/[\w.-]+)@([0-9a-f]{40})$/.exec(pas.uses);
      expect(m, pas.uses).to.not.equal(null);
      const ref = ACTIONS_EPINGLEES[m[1]];
      expect(ref, m[1]).to.not.equal(undefined);
      expect(m[2]).to.equal(ref.sha);
      expect(texte).to.include(`uses: ${pas.uses} # ${ref.version}\n`);
      expect(jours(ref.date, AJOUT), m[1]).to.be.greaterThan(14);
      if (m[1] === "actions/checkout") expect(pas.with?.["persist-credentials"], "checkout sans jeton persistant").to.equal(false);
      if (m[1] === "actions/setup-node") {
        expect(pas.with["node-version"]).to.equal(NODE.version);
        expect(pas.with).to.not.have.property("cache");
      }
    }
    expect(jours(NODE.date, AJOUT)).to.be.greaterThan(14);
    // Image de construction par condensé, la même partout.
    expect(w.jobs["binaires-conteneur"].container.image).to.equal(IMAGE.ref);
    expect(w.jobs.preparation.env.IMAGE_CONSTRUCTION).to.equal(IMAGE.ref);
    expect(jours(IMAGE.date, AJOUT)).to.be.greaterThan(14);
    // Go téléchargé seulement avec le SHA-256 publié (celui du LISEZMOI du vérificateur).
    const shaGo = /([0-9a-f]{64})  go1\.27\.3\.linux-amd64\.tar\.gz/.exec(fs.readFileSync(path.join(RACINE, "verificateur", "LISEZMOI.md"), "utf8"))[1];
    for (const r of runs.filter((x) => x.includes("curl"))) {
      expect(r).to.include(`echo "${shaGo}  go1.27.3.linux-amd64.tar.gz" | sha256sum --strict -c`);
      expect(r.indexOf("sha256sum")).to.be.lessThan(r.indexOf("tar -xzf"));
    }
    // Aucune expression dans un script (injection), aucune publication.
    for (const r of runs) expect(r, r).to.not.include("${{");
    // Les commentaires du fichier nomment ce qui viendra après validation : seules les clés et les commandes comptent.
    const sansCommentaires = texte.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
    expect(sansCommentaires).to.not.match(/secrets\.|id-token|attestations:|actions\/attest|git push|git tag|gh release|gh api|docker (push|login)|npm publish|minisign -S|softprops|upload-release|create-release|packages: write|contents: write/);
    const preparation = runs.find((r) => r.includes("preparer-version.mjs"));
    for (const o of ["--binaires", "--temoin", "--exiger-arbre-propre", "--image-construction", '--commit "$GITHUB_SHA"']) expect(preparation).to.include(o);
    expect(runs.some((r) => r.includes("npm ci --ignore-scripts"))).to.equal(true);
  });

  it("TQ-8, partie mécanique (étape 7) : chaîne de construction et de publication du binaire et de l'archive : aucune clé ni secret dans les fichiers préparés ni dans l'archive, empreintes de la note égales aux deux constructions ; les fichiers de construction des images restent à relire par une personne qui ne les a pas écrits", function () {
    if (goEnv === null) return enAttente(this, "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH)");
    const interdits = /-----BEGIN [A-Z ]*PRIVATE KEY-----|minisign encrypted secret key|untrusted comment: [^\n]*secret key/;
    for (const n of PRODUITS) {
      if (n.startsWith("noortrace-verifier-linux-") && !n.endsWith(".txt")) continue;
      expect(fs.readFileSync(path.join(p1, n), "latin1"), n).to.not.match(interdits);
    }
    const extrait = path.join(tmp, "archive-tq8");
    fs.mkdirSync(extrait);
    expect(spawnSync("tar", ["-xkf", path.join(p1, `noortrace-deploiement-${VERSION}.tar`), "-C", extrait]).status).to.equal(0);
    const trouves = [];
    const parcourir = (rel) => {
      for (const e of fs.readdirSync(path.join(extrait, rel), { withFileTypes: true })) {
        const p = rel ? `${rel}/${e.name}` : e.name;
        if (e.isDirectory()) parcourir(p);
        else if (interdits.test(fs.readFileSync(path.join(extrait, p), "latin1")) || /(^|\/)secrets\//.test(p)) trouves.push(p);
      }
    };
    parcourir("");
    expect(trouves).to.deep.equal([]);
    const note = fs.readFileSync(path.join(p1, "NOTE-DE-VERSION.md"), "utf8");
    for (const arch of ["amd64", "arm64"]) {
      const n = `noortrace-verifier-linux-${arch}`;
      const h = sha256(fs.readFileSync(path.join(p1, n)));
      expect(h).to.equal(sha256(fs.readFileSync(path.join(p2, n))));
      expect(note).to.include(`| \`linux/${arch}\` | \`${h}\` |`);
    }
  });
});
