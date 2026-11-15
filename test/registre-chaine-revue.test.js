import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// Revue de sécurité interne de l'étape 8 : chaîne du registre (chain/).
// Constats : (correctifs de l'image du nœud ni épinglés ni vérifiés :
// chain/patches/EMPREINTES et chain/scripts/verifier-correctifs.sh, appelés par
// chain/docker/Dockerfile et chain/scripts/build-noorcore.sh avant tout
// git apply, CT-4 EX-10.1 d), EX-4.12 (chain/README.md : répartition interdite
// en production, chemin de machine, GOTOOLCHAIN=auto), (exemple Compose
// du suiveur : développement seulement, condensé en production). L'image
// noortrace/noorcore:618fcef-noortrace n'est pas reconstruite (son correctif
// est absent du dépôt) : la vérification d'empreinte est prouvée sur un
// correctif témoin. Fichiers sous NOORTRACE_TMP (ou os.tmpdir()) ; le dépôt
// n'est pas modifié. NOORTRACE_RACINE désigne un autre arbre (rejeu sur une
// copie figée).

const RACINE = process.env.NOORTRACE_RACINE ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CHAIN = path.join(RACINE, "chain");
const SCRIPT = path.join(CHAIN, "scripts", "verifier-correctifs.sh");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const sha256 = (o) => crypto.createHash("sha256").update(o).digest("hex");
const lire = (f) => fs.readFileSync(f, "utf8");
const bash = (script, args, env = {}) => spawnSync("/bin/bash", [script, ...args], { encoding: "utf8", env: { ...process.env, ...env } });

let TRAVAIL;
before(function () {
  TRAVAIL = fs.mkdtempSync(path.join(TMP, "noortrace-chaine-revue-"));
});
after(function () {
  if (TRAVAIL) fs.rmSync(TRAVAIL, { recursive: true, force: true });
});

/** Répertoire de correctifs témoin : `fichiers` { nom: contenu }, EMPREINTES écrit depuis `listes` [nom] (empreintes exactes) ou donné. */
function depot(nom, fichiers, { listes = Object.keys(fichiers), empreintes = null } = {}) {
  const rep = path.join(TRAVAIL, nom);
  fs.mkdirSync(rep, { recursive: true });
  for (const [n, c] of Object.entries(fichiers)) fs.writeFileSync(path.join(rep, n), c);
  const texte = empreintes ?? `# témoin\n${listes.map((n) => `${sha256(fichiers[n] ?? "")}  ${n}`).join("\n")}\n`;
  fs.writeFileSync(path.join(rep, "EMPREINTES"), texte);
  return rep;
}

describe("Revue de sécurité de l'étape 8, CT-4 EX-10.1 (d) : correctifs du nœud épinglés par chain/patches/EMPREINTES et vérifiés avant git apply", function () {
  this.timeout(60000);

  it("chain/patches/EMPREINTES existe, n'est pas ignoré par git, et nomme 0001-noor_getCommitCertificate.patch avec le SHA-256 que chain/docker/README.md consigne ; le LISEZMOI du répertoire dit la règle", function () {
    expect(fs.existsSync(SCRIPT), "verifier-correctifs.sh présent").to.equal(true);
    const f = path.join(CHAIN, "patches", "EMPREINTES");
    expect(fs.existsSync(f), "EMPREINTES présent").to.equal(true);
    const ignore = spawnSync("git", ["check-ignore", "-q", "chain/patches/EMPREINTES"], { cwd: RACINE, encoding: "utf8" });
    expect(ignore.status, "git check-ignore rend 1 pour un fichier suivi (non ignoré)").to.equal(1);
    const lignes = lire(f).split("\n").filter((l) => l.trim() && !l.startsWith("#"));
    expect(lignes).to.deep.equal(["04d4a48b28568bb6859abdfb1778985841fc547ea47649742b3b2763dd83ae82  0001-noor_getCommitCertificate.patch"]);
    expect(lire(path.join(CHAIN, "docker", "README.md"))).to.include("04d4a48b28568bb6859abdfb1778985841fc547ea47649742b3b2763dd83ae82");
    expect(lire(path.join(CHAIN, "patches", "LISEZMOI.md"))).to.match(/EMPREINTES/);
    expect(lire(path.join(CHAIN, "patches", ".gitignore"))).to.include("!EMPREINTES");
  });

  it("verifier-correctifs.sh : témoin conforme → 0 ; empreinte différente → 1 ; fichier .patch non listé → 1 ; correctif listé absent → 1 ; aucun correctif alors qu'un est attendu → 3, et 0 seulement avec NOORTRACE_SANS_CORRECTIF=1 ; ligne mal formée → 1 ; mutant (sha256sum retiré) : l'empreinte différente passe", function () {
    const bon = depot("bon", { "0001-temoin.patch": "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n" });
    const r0 = bash(SCRIPT, [bon]);
    expect(r0.status, r0.stderr).to.equal(0);
    expect(r0.stdout).to.match(/1 correctif\(s\) vérifié\(s\)/);
    // Empreinte différente : le fichier a changé après l'épinglage.
    const change = depot("change", { "0001-temoin.patch": "contenu attendu\n" });
    fs.writeFileSync(path.join(change, "0001-temoin.patch"), "contenu modifié par un constructeur\n");
    const r1 = bash(SCRIPT, [change]);
    expect(r1.status, r1.stderr).to.equal(1);
    expect(r1.stderr).to.match(/empreinte diffère|FAILED/);
    // Fichier non listé.
    const enPlus = depot("en-plus", { "0001-temoin.patch": "a\n", "0002-inconnu.patch": "b\n" }, { listes: ["0001-temoin.patch"] });
    const r2 = bash(SCRIPT, [enPlus]);
    expect(r2.status).to.equal(1);
    expect(r2.stderr).to.include("0002-inconnu.patch");
    // Correctif listé mais absent.
    const absent = depot("absent", { "0001-temoin.patch": "a\n" });
    fs.unlinkSync(path.join(absent, "0001-temoin.patch"));
    fs.writeFileSync(path.join(absent, "0002-present.patch"), "c\n");
    const r3 = bash(SCRIPT, [absent]);
    expect(r3.status).to.equal(1);
    expect(r3.stderr).to.include("0001-temoin.patch");
    // Aucun correctif alors qu'EMPREINTES en attend : 3 ; admis seulement sur demande explicite.
    const vide = depot("vide", { "0001-temoin.patch": "a\n" });
    fs.unlinkSync(path.join(vide, "0001-temoin.patch"));
    const r4 = bash(SCRIPT, [vide]);
    expect(r4.status).to.equal(3);
    expect(r4.stderr).to.include("NOORTRACE_SANS_CORRECTIF=1");
    const r5 = bash(SCRIPT, [vide], { NOORTRACE_SANS_CORRECTIF: "1" });
    expect(r5.status, r5.stderr).to.equal(0);
    expect(r5.stderr).to.match(/AVERTISSEMENT/);
    // Ligne mal formée (nom avec répertoire).
    const malForme = depot("mal-forme", { "0001-temoin.patch": "a\n" }, { empreintes: `${sha256("a\n")}  ../0001-temoin.patch\n` });
    expect(bash(SCRIPT, [malForme]).status).to.equal(1);
    // Arguments : répertoire absent → 2.
    expect(bash(SCRIPT, [path.join(TRAVAIL, "inexistant")]).status).to.equal(2);
    // Le fichier EMPREINTES du dépôt lui-même est lisible par le script : avec le correctif absent, 3 (l'image ne se reconstruit pas ici).
    const r6 = bash(SCRIPT, [path.join(CHAIN, "patches")]);
    expect(r6.status, r6.stderr).to.equal(3);
    // Mutant : la comparaison des empreintes retirée ; le correctif modifié passe (oracle : code 1).
    const texte = lire(SCRIPT);
    const motif = `if ! (cd "$dir" && grep -Ev '^[[:space:]]*(#|$)' "$empreintes" | sha256sum --strict -c -) ; then`;
    expect(texte.split(motif), "motif unique").to.have.length(2);
    const mutant = path.join(TRAVAIL, "mutant-verifier-correctifs.sh");
    fs.writeFileSync(mutant, texte.replace(motif, "if false; then"), { mode: 0o755 });
    const rm = bash(mutant, [change]);
    expect(rm.status, "mutant : le correctif modifié est accepté (le mutant est tué)").to.not.equal(1);
  });

  it("chain/docker/Dockerfile et chain/scripts/build-noorcore.sh vérifient les correctifs (verifier-correctifs) avant tout git apply ; le contexte Docker laisse passer le script ; NOORTRACE_SANS_CORRECTIF n'est qu'un argument explicite ; mutant statique (appel retiré du Dockerfile) : l'oracle échoue", function () {
    const dockerfile = lire(path.join(CHAIN, "docker", "Dockerfile"));
    const verifie = dockerfile.indexOf("bash /usr/local/bin/verifier-correctifs /patches /patches/EMPREINTES");
    const applique = dockerfile.indexOf('git apply --check "$p"; git apply "$p"');
    expect(verifie, "Dockerfile : vérification présente").to.be.greaterThan(-1);
    expect(applique).to.be.greaterThan(-1);
    expect(verifie, "la vérification précède git apply").to.be.lessThan(applique);
    expect(dockerfile).to.include("COPY scripts/verifier-correctifs.sh /usr/local/bin/verifier-correctifs");
    expect(dockerfile).to.include("ARG NOORTRACE_SANS_CORRECTIF=0");
    expect(lire(path.join(CHAIN, "docker", "Dockerfile.dockerignore"))).to.include("!scripts/verifier-correctifs.sh");
    const build = lire(path.join(CHAIN, "scripts", "build-noorcore.sh"));
    const v2 = build.indexOf('verifier-correctifs.sh" "$PATCH_DIR" "$PATCH_DIR/EMPREINTES"');
    const a2 = build.indexOf('git -C "$SRC" apply "$p"');
    expect(v2, "build-noorcore.sh : vérification présente").to.be.greaterThan(-1);
    expect(v2).to.be.lessThan(a2);
    expect(spawnSync("/bin/bash", ["-n", path.join(CHAIN, "scripts", "build-noorcore.sh")], { encoding: "utf8" }).status).to.equal(0);
    // Mutant statique : l'appel retiré du Dockerfile ; l'oracle (vérification avant git apply) échoue.
    const mutant = dockerfile.replace("bash /usr/local/bin/verifier-correctifs /patches /patches/EMPREINTES; \\\n", "");
    expect(mutant).to.not.equal(dockerfile);
    expect(mutant.indexOf("bash /usr/local/bin/verifier-correctifs /patches /patches/EMPREINTES"), "mutant : l'oracle ne trouve plus la vérification (le mutant est tué)").to.equal(-1);
  });

  it("chain/README.md ne porte aucun chemin de machine, décrit la répartition d'EX-4.12 (quatre sites, deux validateurs par site nommés comme non admis en production) ; build-noorcore.sh force GOTOOLCHAIN=local et le README le dit ; docker-compose.yml se déclare réservé au développement et renvoie à l'emploi par condensé (EX-10.1)", function () {
    const readme = lire(path.join(CHAIN, "README.md"));
    expect(readme).to.not.match(/\/home\/[a-z]/);
    expect(readme).to.match(/quatre opérateurs et quatre sites/);
    expect(readme).to.match(/pas admis en production/);
    expect(readme).to.not.include("## Ce qui change pour un réseau prod-like à quatre validateurs sur deux sites");
    expect(readme).to.include("GOTOOLCHAIN=local");
    expect(readme).to.not.include("GOTOOLCHAIN=auto");
    const build = lire(path.join(CHAIN, "scripts", "build-noorcore.sh"));
    expect(build).to.include("export GOTOOLCHAIN=local");
    expect(build).to.not.match(/GOTOOLCHAIN=auto, la chaîne de compilation est téléchargée/);
    const compose = lire(path.join(CHAIN, "docker", "docker-compose.yml"));
    expect(compose).to.include("DÉVELOPPEMENT SEULEMENT");
    expect(compose).to.include("noortrace/noorcore@sha256:");
    expect(compose).to.include("EX-10.1");
    expect(compose).to.not.match(/rpc\.exemple\.ch/);
    for (const f of ["README.md", "docker/README.md", "docker/docker-compose.yml"]) expect(lire(path.join(CHAIN, f)), f).to.not.match(/[a-z0-9-]+\.exemple\.ch/);
  });
});
