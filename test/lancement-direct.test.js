// Garde du lancement direct des outils : un script qui ne s'exécute que s'il
// est le programme lancé compare le chemin réel de son module au chemin réel
// du programme nommé par la ligne de commande. Node.js résout les liens
// symboliques du module principal (l'URL du module porte le chemin réel)
// mais laisse à la ligne de commande le chemin tapé ; une comparaison qui ne
// résout pas ce dernier échoue dès que le chemin passe par un lien (répertoire
// temporaire lié, répertoire de version lié), et l'outil ne fait alors rien,
// n'écrit rien et rend 0 : pour un outil de contrôle, une réussite silencieuse.
//
// Forme attendue (celle de scripts/deploiement/) :
//   process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))
// ou une aide locale qui rend fs.realpathSync du chemin.
//
// (a) Aucun fichier .mjs ou .js du dépôt (hors node_modules, environnements
//     d'essai et artefacts de construction) ne compare le module au programme
//     lancé sans realpathSync.
// (b) Lancés par un chemin qui passe par un lien symbolique, des outils de
//     contrôle rendent le même code et la même sortie qu'en direct.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { creerRepertoireTemporaire } from "./aides/temporaires.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// ---------------------------------------------------------------------------
// (a) parcours du dépôt
// ---------------------------------------------------------------------------

/** Répertoires jamais parcourus, par nom (où qu'ils soient) ; les modules Go des vérificateurs indépendants n'ont aucun fichier JavaScript. */
const NOMS_EXCLUS = new Set(["node_modules", ".environnements", ".git", "hh-artifacts", "hh-cache", ".venv", "__pycache__", ".pytest_cache", "verificateur-independant"]);
/** Répertoires jamais parcourus, par chemin depuis la racine (artefacts et états locaux ignorés par git). */
const CHEMINS_EXCLUS = new Set(["deployments", "types", "data", "chain/runtime", "archive/polyscan/data"]);

function fichiersJs(rep = RACINE, sortie = []) {
  for (const e of fs.readdirSync(rep, { withFileTypes: true })) {
    const abs = path.join(rep, e.name);
    const rel = path.relative(RACINE, abs).split(path.sep).join("/");
    if (e.isDirectory()) {
      if (!NOMS_EXCLUS.has(e.name) && !CHEMINS_EXCLUS.has(rel)) fichiersJs(abs, sortie);
    } else if (e.isFile() && /\.(mjs|js)$/.test(e.name)) {
      sortie.push(rel);
    }
  }
  return sortie;
}

/**
 * Code d'une ligne, sans ses chaînes entre apostrophes ou guillemets ni ses
 * commentaires : un texte cité (le mutant d'un essai, par exemple) n'est pas
 * une garde. Le contenu des gabarits (accents graves) est gardé, puisqu'une
 * garde peut y lire la ligne de commande.
 */
export function codeSeul(ligne) {
  let sortie = "";
  let ouvert = null;
  for (let i = 0; i < ligne.length; i++) {
    const c = ligne[i];
    if (ouvert === "`") {
      if (c === "\\") {
        sortie += c + (ligne[i + 1] ?? "");
        i++;
      } else {
        sortie += c;
        if (c === "`") ouvert = null;
      }
      continue;
    }
    if (ouvert) {
      if (c === "\\") i++;
      else if (c === ouvert) {
        ouvert = null;
        sortie += c;
      }
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      ouvert = c;
      sortie += c;
      continue;
    }
    if (c === "/" && ligne[i + 1] === "/") break;
    if (c === "/" && ligne[i + 1] === "*") {
      const fin = ligne.indexOf("*/", i + 2);
      if (fin === -1) break;
      i = fin + 1;
      continue;
    }
    sortie += c;
  }
  return sortie;
}

const LIGNE_DE_COMMANDE = /\bargv\s*\[\s*1\s*\]|\bargv\.(?:slice|at)\(\s*1\s*\)/;
const MODULE = /\bimport\.meta\.(?:url|filename)\b|\bfileURLToPath\s*\(|\bpathToFileURL\s*\(/;
const EGALITE = /[=!]==?/;
const RESOLU = /\brealpathSync\b/;

/** Corps d'une fonction locale nommée (déclaration ou constante fléchée), jusqu'à la première accolade fermante en colonne 0. */
function corpsDeFonction(texte, nom) {
  const n = nom.replace(/\$/g, "\\$");
  const debut = texte.search(new RegExp(`(?:^|\\n)\\s*(?:export\\s+)?(?:function\\s+${n}\\s*\\(|const\\s+${n}\\s*=)`));
  if (debut === -1) return null;
  const fin = texte.indexOf("\n}", debut);
  return texte.slice(debut, fin === -1 ? undefined : fin);
}

/** Gardes de lancement direct sans chemin réel : [{ ligne, texte }]. */
export function gardesFautives(texte) {
  const fautives = [];
  const lignes = texte.split("\n");
  for (let n = 0; n < lignes.length; n++) {
    const brute = lignes[n];
    if (/^\s*(?:\*|\/\*)/.test(brute)) continue;
    const code = codeSeul(brute);
    if (!(LIGNE_DE_COMMANDE.test(code) && MODULE.test(code) && EGALITE.test(code))) continue;
    if (RESOLU.test(code)) continue;
    const appels = [...code.matchAll(/\b([A-Za-z_$][\w$]*)\s*\(/g)].map((m) => m[1]);
    if (appels.some((nom) => RESOLU.test(corpsDeFonction(texte, nom) ?? ""))) continue;
    fautives.push({ ligne: n + 1, texte: brute.trim() });
  }
  return fautives;
}

describe("Lancement direct des outils : la garde « ce module est le programme lancé » compare des chemins réels (liens symboliques résolus)", function () {
  this.timeout(180000);

  it("le détecteur reconnaît les formes fautives et admet la forme résolue, l'aide locale résolue et un texte cité", function () {
    const fautives = [
      "if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {",
      "if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) servir();",
      "if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) process.exitCode = principal(process.argv.slice(2));",
      "if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {",
      "if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {",
      "const principal = fileURLToPath(import.meta.url) === path.resolve(process.argv[1]); // commentaire",
    ];
    for (const f of fautives) expect(gardesFautives(f), f).to.have.length(1);
    const admises = [
      "if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) {",
      "if (process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href) {",
      "function cheminReel(p) {\n  try {\n    return fs.realpathSync(path.resolve(p));\n  } catch {\n    return null;\n  }\n}\nif (process.argv[1] && fileURLToPath(import.meta.url) === cheminReel(process.argv[1])) {",
      "const r = mutant(\"x\", \"if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {\");",
      "// if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {",
      "const { a } = JSON.parse(process.argv[1]);",
    ];
    for (const a of admises) expect(gardesFautives(a), a).to.deep.equal([]);
    // Une aide locale qui ne résout pas le chemin n'est pas admise.
    expect(gardesFautives("function cheminReel(p) {\n  return path.resolve(p);\n}\nif (process.argv[1] && fileURLToPath(import.meta.url) === cheminReel(process.argv[1])) {")).to.have.length(1);
  });

  it("(a) aucun fichier .mjs ou .js du dépôt ne compare le module au programme lancé sans realpathSync", function () {
    const fichiers = fichiersJs();
    // Le parcours atteint les outils, les paquets et les fixtures d'essai.
    for (const attendu of ["scripts/deploiement/renvois.mjs", "scripts/tests/attentes.mjs", "paquets/console/src/pages/construire.mjs", "test/fixtures/inscription/agent-essai.mjs"]) {
      expect(fichiers, attendu).to.include(attendu);
    }
    const fautes = [];
    for (const rel of fichiers) {
      for (const f of gardesFautives(fs.readFileSync(path.join(RACINE, rel), "utf8"))) fautes.push(`${rel}:${f.ligne} : ${f.texte}`);
    }
    expect(fautes, fautes.join("\n")).to.deep.equal([]);
  });

  describe("(b) lancés par un chemin qui passe par un lien symbolique, les outils de contrôle rendent le même code et la même sortie qu'en direct", function () {
    let travail; // chemin réel
    let lien; // lien symbolique vers `travail`
    let lienDepot; // lien symbolique vers la racine du dépôt

    before(function () {
      const base = fs.realpathSync(creerRepertoireTemporaire("noortrace-lancement-"));
      travail = path.join(base, "travail");
      fs.mkdirSync(travail);
      lien = path.join(base, "lien");
      fs.symlinkSync(travail, lien, "dir");
      lienDepot = path.join(base, "lien-depot");
      fs.symlinkSync(RACINE, lienDepot, "dir");
    });

    const lancer = (script, args, env = process.env) => {
      const r = spawnSync(process.execPath, [script, ...args], { cwd: travail, encoding: "utf8", env, timeout: 120000 });
      return { code: r.status, sortie: r.stdout, erreur: r.stderr };
    };
    /** Lance `rel` sous `direct` puis sous `parLien` ; exige le même résultat ; rend le résultat direct. */
    const deuxFois = (direct, parLien, rel, args, env) => {
      const a = lancer(path.join(direct, ...rel.split("/")), args, env);
      const b = lancer(path.join(parLien, ...rel.split("/")), args, env);
      expect(b, `${rel} par le lien`).to.deep.equal(a);
      return a;
    };

    it("scripts/tests/attentes.mjs sur une sortie d'essais en échec : code 1", function () {
      const fautive = path.join(travail, "sortie-fautive.txt");
      fs.writeFileSync(fautive, "  2 passing (1s)\n  1 failing\n\n  1) suite\n       essai :\n     AssertionError: x\n");
      const r = deuxFois(RACINE, lienDepot, "scripts/tests/attentes.mjs", [fautive]);
      expect(r.code, r.erreur).to.equal(1);
      expect(r.sortie).to.include("1 échec(s)");
    });

    it("scripts/tests/temporaires.mjs comparer, une entrée laissée sous le répertoire temporaire : code 1 et l'entrée nommée", function () {
      const tmp = path.join(travail, "tmp-isole");
      fs.mkdirSync(path.join(tmp, "noortrace-laisse"), { recursive: true });
      const releve = path.join(travail, "releve-vide.txt");
      fs.writeFileSync(releve, "");
      const env = { ...process.env, TMPDIR: tmp };
      delete env.NOORTRACE_TMP;
      const r = deuxFois(RACINE, lienDepot, "scripts/tests/temporaires.mjs", ["comparer", releve], env);
      expect(r.code, r.erreur).to.equal(1);
      expect(r.erreur).to.include(path.join(tmp, "noortrace-laisse"));
    });

    it("scripts/conception/figeage.mjs (vérification) sur un dépôt dont un fichier figé est modifié : code 1 et l'écart nommé", function () {
      const depot = path.join(travail, "depot-fige");
      fs.mkdirSync(path.join(depot, "spec"), { recursive: true });
      const git = spawnSync("git", ["init", "-q"], { cwd: depot, encoding: "utf8" });
      expect(git.status, git.stderr).to.equal(0);
      fs.writeFileSync(path.join(depot, "spec", "CT-1-x.md"), "a\n");
      const init = lancer(path.join(RACINE, "scripts", "conception", "figeage.mjs"), ["--initialiser", "--date", "2026-11-02", "--racine", depot]);
      expect(init.code, init.erreur).to.equal(0);
      fs.writeFileSync(path.join(depot, "spec", "CT-1-x.md"), "b\n");
      const r = deuxFois(RACINE, lienDepot, "scripts/conception/figeage.mjs", ["--racine", depot]);
      expect(r.code, r.erreur).to.equal(1);
      expect(r.sortie).to.include("[ÉCART] modifié sans consignation : spec/CT-1-x.md");
    });

    it("paquets/console/src/pages/construire.mjs sur une copie dont un module est modifié : code 1 et « fichiers périmés »", function () {
      const paquet = path.join(RACINE, "paquets", "console");
      const copie = path.join(travail, "console");
      fs.cpSync(path.join(paquet, "src"), path.join(copie, "src"), { recursive: true });
      fs.mkdirSync(path.join(copie, "node_modules", "@noble"), { recursive: true });
      const exiger = createRequire(path.join(paquet, "src", "serveur", "index.mjs"));
      for (const p of ["@noble/hashes", "@noble/curves"]) fs.symlinkSync(path.dirname(exiger.resolve(`${p}/utils.js`)), path.join(copie, "node_modules", ...p.split("/")), "dir");
      fs.writeFileSync(path.join(copie, "package.json"), JSON.stringify({ name: "copie-essai", type: "module", private: true }));
      fs.appendFileSync(path.join(copie, "src", "pages", "statique", "commun", "dom.mjs"), "\n");
      const r = deuxFois(travail, lien, "console/src/pages/construire.mjs", []);
      expect(r.code, r.erreur).to.equal(1);
      expect(r.erreur).to.include("fichiers périmés");
      expect(r.erreur).to.include("manifeste.json");
    });

    it("scripts/console/empreintes.mjs sur une copie dont console/index.html est altéré : code 1 et « périmé »", function () {
      const copie = path.join(travail, "depot-console");
      for (const rel of ["scripts/console/empreintes.mjs", "scripts/lib/console.mjs", "console/console.js", "console/index.html"]) {
        fs.mkdirSync(path.dirname(path.join(copie, rel)), { recursive: true });
        fs.copyFileSync(path.join(RACINE, rel), path.join(copie, rel));
      }
      fs.appendFileSync(path.join(copie, "console", "index.html"), "<!-- altéré -->\n");
      const r = deuxFois(travail, lien, "depot-console/scripts/console/empreintes.mjs", []);
      expect(r.code, r.erreur).to.equal(1);
      expect(r.erreur).to.include("console/index.html est périmé");
    });

    it("scripts/conformite/verifier-renvois.mjs sur le dépôt : même verdict, et un verdict écrit", function () {
      const r = deuxFois(RACINE, lienDepot, "scripts/conformite/verifier-renvois.mjs", []);
      expect(r.sortie.length + r.erreur.length).to.be.greaterThan(0);
    });
  });
});
