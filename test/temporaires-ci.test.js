// Garde des répertoires temporaires du travail `tests` de l'intégration
// continue (scripts/tests/temporaires.mjs) et libération par l'aide commune
// (test/aides/temporaires.mjs) : un fichier d'essai factice qui laisse une
// entrée d'un préfixe du dépôt (`noortrace-*`, préfixes courts des prises
// Unix, autres préfixes de PREFIXES) dans le répertoire temporaire rend la
// garde rouge ; le même répertoire créé par l'aide commune est libéré, même
// quand l'essai échoue ; chaque préfixe que le dépôt crée sous le répertoire
// temporaire est un préfixe de la garde.
// Les fichiers factices sont écrits ici, dans un répertoire temporaire, et
// joués par mocha dans un processus séparé dont le TMPDIR est neuf : ils ne
// sont jamais sous test/, où `npm test` les chargerait.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { creerRepertoireTemporaire } from "./aides/temporaires.mjs";
import { PREFIXES, estDuDepot } from "../scripts/tests/temporaires.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUTIL = path.join(RACINE, "scripts", "tests", "temporaires.mjs");
const MOCHA = path.join(RACINE, "node_modules", "mocha", "bin", "mocha.js");
const AIDE = pathToFileURL(path.join(RACINE, "test", "aides", "temporaires.mjs")).href;

/**
 * Relevé, passe mocha d'un fichier factice, comparaison, avec un TMPDIR neuf ;
 * rend `{ mocha, releve, comparer, restes }`.
 */
function passe(source) {
  const travail = creerRepertoireTemporaire("noortrace-temporaires-ci-");
  const tmp = path.join(travail, "tmp");
  fs.mkdirSync(tmp);
  const essai = path.join(travail, "factice.test.mjs");
  fs.writeFileSync(essai, source);
  const env = { ...process.env, TMPDIR: tmp };
  delete env.NOORTRACE_TMP;
  const garde = (commande) => spawnSync(process.execPath, [OUTIL, commande, path.join(travail, "releve.txt")], { encoding: "utf8", env });
  const releve = garde("releve");
  const mocha = spawnSync(process.execPath, [MOCHA, essai], { encoding: "utf8", cwd: travail, env, timeout: 60000 });
  const comparer = garde("comparer");
  return { mocha, releve, comparer, restes: fs.readdirSync(tmp).filter(estDuDepot) };
}

/** Fichiers sources examinés sous `rel` (récursif, sans node_modules ni environnements Python), d'extension `ext`. */
function sources(rel, ext) {
  const out = [];
  const parcourir = (d) => {
    let entrees;
    try {
      entrees = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entrees) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) {
        if (!["node_modules", ".environnements", "__pycache__"].includes(e.name)) parcourir(p);
      } else if (ext.some((x) => e.name.endsWith(x))) out.push(p);
    }
  };
  parcourir(path.join(RACINE, rel));
  return out;
}

/**
 * Préfixes littéraux des entrées créées directement sous le répertoire
 * temporaire : `mkdtemp` sur `path.join(<base>, <littéral>)` dont la base est
 * os.tmpdir(), NOORTRACE_TMP, TMP, tmp ou base ; appel des aides
 * `repertoireTemporaire` et `creerRepertoireTemporaire` avec un littéral ;
 * `tempfile.mkdtemp` de Python avec `prefix=<littéral>` ; chemin
 * `path.join(<base>, <gabarit>)` dont la base est os.tmpdir(), NOORTRACE_TMP
 * ou TMP et le gabarit a une partie variable (fichier au nom tiré). Partie fixe du
 * littéral seulement (avant `${`) ; rend [{ fichier, prefixe }].
 */
function prefixesCrees() {
  const js = [
    ...sources("test", [".js", ".mjs"]),
    ...fs.readdirSync(path.join(RACINE, "paquets")).flatMap((p) => sources(path.join("paquets", p, "src"), [".js", ".mjs"])),
    ...["tests", "e2e", "mesures", "deploiement", "paquet-reviseur", "publication"].flatMap((d) => sources(path.join("scripts", d), [".js", ".mjs"])),
    ...sources("demo", [".mjs"]),
  ];
  const py = sources(path.join("paquets", "sdk-python", "tests"), [".py"]);
  // Base : une expression qui rend le répertoire temporaire (os.tmpdir(), NOORTRACE_TMP), ou les noms qu'elle prend dans les essais et les aides.
  const temporaire = (base) => /os\.tmpdir\(\)|NOORTRACE_TMP/.test(base) || /^(TMP|tmp|base)$/.test(base);
  const trouves = [];
  const garder = (fichier, litteral) => {
    const fixe = litteral.split("${")[0];
    if (fixe) trouves.push({ fichier: path.relative(RACINE, fichier), prefixe: fixe });
  };
  for (const f of js) {
    const texte = fs.readFileSync(f, "utf8");
    for (const m of texte.matchAll(/mkdtemp(?:Sync)?\(\s*path\.join\(\s*([^,]+?)\s*,\s*([`"'])([^`"']*)\2/g)) if (temporaire(m[1].trim())) garder(f, m[3]);
    for (const m of texte.matchAll(/\b(?:creerR|r)epertoireTemporaire\(\s*([`"'])([^`"']*)\1/g)) garder(f, m[2]);
    for (const m of texte.matchAll(/path\.join\(\s*([^,()]+(?:\(\))?[^,()]*)\s*,\s*`([^`]*\$\{[^`]*)`/g)) if (/os\.tmpdir\(\)|NOORTRACE_TMP/.test(m[1]) || m[1].trim() === "TMP") garder(f, m[2]);
  }
  for (const f of py) for (const m of fs.readFileSync(f, "utf8").matchAll(/(?:mkdtemp|TemporaryDirectory)\([^)]*prefix=(["'])([^"']*)\1/g)) garder(f, m[2]);
  return trouves;
}

describe("scripts/tests/temporaires.mjs : garde des répertoires temporaires du travail tests ; libération par test/aides/temporaires.mjs", function () {
  this.timeout(120000);

  it("un fichier d'essai factice qui laisse un noortrace-* dans le répertoire temporaire rend la garde rouge (code 1), et l'entrée est nommée", function () {
    const r = passe([
      'import fs from "node:fs"; import os from "node:os"; import path from "node:path";',
      'describe("factice", function () { it("fuit", function () { fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-fuite-")); }); });',
      "",
    ].join("\n"));
    expect(r.releve.status, r.releve.stderr).to.equal(0);
    expect(r.mocha.status, r.mocha.stdout + r.mocha.stderr).to.equal(0);
    expect(r.restes).to.have.length(1);
    expect(r.comparer.status, r.comparer.stdout).to.equal(1);
    expect(r.comparer.stderr).to.include(`laissé par les essais : `);
    expect(r.comparer.stderr).to.include(r.restes[0]);
  });

  it("les répertoires de l'aide commune (créés au chargement, dans un « before all », dans un essai en échec) sont libérés : la garde reste verte (code 0) malgré l'échec", function () {
    const r = passe([
      `import { creerRepertoireTemporaire } from ${JSON.stringify(AIDE)};`,
      'creerRepertoireTemporaire("noortrace-factice-chargement-");',
      'describe("factice", function () {',
      '  before(function () { creerRepertoireTemporaire("noortrace-factice-avant-"); });',
      '  it("échoue", function () { creerRepertoireTemporaire("noortrace-factice-essai-"); throw new Error("échec voulu"); });',
      "});",
      'describe("factice 2", function () { it("réussit", function () { creerRepertoireTemporaire("noortrace-factice-essai2-"); }); });',
      "",
    ].join("\n"));
    expect(r.mocha.status, r.mocha.stdout + r.mocha.stderr).to.equal(1);
    expect(r.mocha.stdout).to.include("1 passing").and.include("1 failing");
    expect(r.restes).to.deep.equal([]);
    expect(r.comparer.status, r.comparer.stderr).to.equal(0);
    expect(r.comparer.stdout).to.include("aucune entrée nouvelle d'un préfixe du dépôt");
  });

  it("préfixes courts des prises Unix et autres préfixes du dépôt (ntpy-, ntrv-, ntadv-, ntpt-, nt-, noyau-, ancrage-, ct4-) : une entrée laissée rend la garde rouge (code 1) et chacune est nommée ; une entrée d'un autre préfixe n'est pas lue", function () {
    const noms = ["ntpy-", "ntrv-", "ntadv-", "ntpt-", "nt-prise-", "noyau-revue-", "ancrage-revue-file-", "ct4-export-"];
    const r = passe([
      'import fs from "node:fs"; import os from "node:os"; import path from "node:path";',
      `const NOMS = ${JSON.stringify([...noms, "autre-outil-"])};`,
      'describe("factice", function () { it("fuit", function () { for (const n of NOMS) fs.mkdtempSync(path.join(os.tmpdir(), n)); }); });',
      "",
    ].join("\n"));
    expect(r.mocha.status, r.mocha.stdout + r.mocha.stderr).to.equal(0);
    expect(r.restes).to.have.length(noms.length);
    expect(r.comparer.status, r.comparer.stdout).to.equal(1);
    for (const n of noms) expect(r.comparer.stderr).to.match(new RegExp(`laissé par les essais : \\S*/${n}`));
    expect(r.comparer.stderr).to.not.include("autre-outil-");
    expect(r.comparer.stderr).to.include(`${noms.length} entrée(s) nouvelle(s)`);
  });

  it("chaque préfixe créé directement sous le répertoire temporaire par les essais, leurs aides, les sources des paquets et les outils lancés par les essais est un préfixe de la garde", function () {
    const trouves = prefixesCrees();
    // Le relevé lit bien les créations : préfixes connus de chaque famille.
    for (const p of ["noortrace-", "nt-prise-", "ntadv-", "ntmes-", "ntpt-", "ntpy-", "ntrv-", "ntta33-", "noyau-revue-", "ancrage-revue-file-", "ct4-export-", "ct5-squat-", "ct7-plafond-", "ct8-gnutar-", "verif-go-revue-", "banc-g-", "banc-client-", "pages-console-", "validators-go-"]) {
      expect(trouves.some((t) => t.prefixe.startsWith(p)), p).to.equal(true);
    }
    expect(trouves.filter((t) => !estDuDepot(t.prefixe)).map((t) => `${t.fichier} : ${t.prefixe}`)).to.deep.equal([]);
    // Chaque préfixe de la garde sert : aucun préfixe mort.
    for (const p of PREFIXES) expect(trouves.some((t) => t.prefixe.startsWith(p)), p).to.equal(true);
  });

  it("usage incorrect ou relevé illisible : code 2", function () {
    expect(spawnSync(process.execPath, [OUTIL], { encoding: "utf8" }).status).to.equal(2);
    expect(spawnSync(process.execPath, [OUTIL, "comparer", path.join(RACINE, "absent", "releve.txt")], { encoding: "utf8" }).status).to.equal(2);
  });
});
