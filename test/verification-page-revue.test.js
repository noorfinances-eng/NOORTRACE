// Page de vérification (CT-6 §18) : corrections de la revue de sécurité
// interne (étape 8), sous Node, sans chaîne Go ni navigateur.
//
// - EX-18.7 : une archive dont un chemin a 100 000 composants
//   (393 octets de .tar.gz) figeait la page (temps quadratique) ; elle est
//   refusée en moins d'une seconde, avec la raison r_chemin_long ; bornes de
//   64 composants et 4 096 octets par chemin, en un seul endroit (archives.js).
// - CT-6 EX-18.7 : un fichier de plus de 512 Mio est refusé d'après sa taille,
//   avant toute lecture ; le parcours d'un répertoire déposé s'arrête à la
//   4 097e entrée.
// - EX-18.8 : l'arbre du travailleur est numéroté sans récursion ; un chemin
//   de 100 000 niveaux ne fait plus déborder la pile.
// - CT-6 EX-8.6 (part page) : neutraliser, seul point d'affichage des chaînes
//   venues d'une entrée, rend visibles les caractères de commande, les
//   séparateurs de ligne et les marques de direction.
// - Les libellés qui nomment une borne portent la valeur de la constante.
//
// NOORTRACE_RACINE : racine d'une copie du dépôt dont les sources sont lues
// (essais de mutants hors du dépôt) ; à défaut, le dépôt lui-même.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import zlib from "node:zlib";
import { tar, zip } from "./fixtures/verification-page/archives-essai.mjs";
import { RACINE } from "./fixtures/verification-page/outils.mjs";

const RACINE_SOURCES = process.env.NOORTRACE_RACINE ? path.resolve(process.env.NOORTRACE_RACINE) : RACINE;
const SOURCES = path.join(RACINE_SOURCES, "paquets", "verification-web", "src");
const Mio = 1024 * 1024;

/** archives.js de la page, chargé sans en changer le texte, avec ses bornes. */
function chargerArchives() {
  const source = fs.readFileSync(path.join(SOURCES, "page", "archives.js"), "utf8");
  // Un symbole absent (sources d'avant la correction) rend undefined : l'essai échoue alors par son oracle.
  const symboles = ["lireArchive", "RefusArchive", "normaliserChemin", "bornesRepertoire", "bornerChemin", "bornerTailleFichier", "compteurEntrees", "BORNES_ARCHIVE"];
  const f = new vm.Script(`(function () {\n${source}\nreturn { ${symboles.map((s) => `${s}: typeof ${s} === "undefined" ? undefined : ${s}`).join(", ")} };\n})()`, { filename: "archives.js" });
  return f.runInThisContext();
}

function libelles(fichier, nom) {
  return vm.runInNewContext(`${fs.readFileSync(path.join(SOURCES, "page", fichier), "utf8")}\n${nom};`, {});
}

/** La fonction neutraliser de interface.js, telle qu'écrite, avec sa table de caractères. */
function chargerNeutraliser() {
  const source = fs.readFileSync(path.join(SOURCES, "page", "interface.js"), "utf8");
  const debutTable = source.indexOf("const CARACTERES_NEUTRALISES = ");
  const debut = source.indexOf("function neutraliser(");
  const fin = source.indexOf("\n}\n", debut);
  // Sources sans la fonction (avant la correction) : null, et l'essai échoue par son oracle.
  if (debutTable < 0 || debut < 0 || fin < 0) return null;
  const table = source.slice(debutTable, source.indexOf("\n", debutTable));
  return vm.runInNewContext(`${table}\n${source.slice(debut, fin + 3)}\nneutraliser;`, {});
}

/** Archive .tar.gz du relecteur (CT-6 EX-18.7) : un seul fichier dont le chemin pax a `n` composants « a ». */
function archiveProfonde(n) {
  const chemin = `d/${"a/".repeat(n)}f`;
  return zlib.gzipSync(tar([{ nom: "d/dossier.json", donnees: "{}" }, { nom: "f", pax: { path: chemin }, donnees: "x" }]), { level: 9 });
}

async function refusDe(lireArchive, nom, octets) {
  try {
    const r = await lireArchive(nom, octets);
    return { admis: true, fichiers: r.fichiers.map((f) => f.chemin) };
  } catch (e) {
    if (e.name !== "RefusArchive") throw e;
    return { admis: false, raison: e.raison, parametres: e.parametres };
  }
}

describe("page de vérification, revue de sécurité : bornes des chemins et des fichiers (CT-6 EX-18.7)", function () {
  this.timeout(10 * 60 * 1000);
  const A = chargerArchives();

  it("les bornes sont des constantes nommées d'archives.js, en un seul endroit : 4 096 entrées, 256 Mio, 64 composants, 4 096 octets par chemin, 512 Mio par fichier", function () {
    expect(A.BORNES_ARCHIVE).to.deep.equal({ entrees: 4096, octets: 256 * Mio, composants_chemin: 64, octets_chemin: 4096, octets_fichier: 512 * Mio });
    expect(Object.isFrozen(A.BORNES_ARCHIVE)).to.equal(true);
    // Aucune autre source de la page n'écrit ces valeurs : interface.js n'en porte aucune.
    const interfaceJs = fs.readFileSync(path.join(SOURCES, "page", "interface.js"), "utf8");
    expect(interfaceJs).to.not.match(/\b(4096|4 096|536870912|268435456|512 \* 1024)\b/);
    expect(interfaceJs).to.include("bornerTailleFichier(");
    expect(interfaceJs).to.include("compteurEntrees(");
  });

  it("chemin d'entrée : 64 composants et 4 096 octets admis ; 65 composants ou 4 097 octets refusés (r_chemin_long) pour un chemin pax, un nom ZIP, un nom long GNU et un répertoire choisi", async function () {
    const composants = (n) => `${"a/".repeat(n - 1)}f`;
    // Dans l'archive, « d/ » ajoute un composant : 63 sous d/ = 64 au total.
    for (const [n, attendu] of [[63, true], [64, false]]) {
      const pax = await refusDe(A.lireArchive, "d.tar", tar([{ nom: "d/dossier.json", donnees: "{}" }, { nom: "f", pax: { path: `d/${composants(n)}` }, donnees: "x" }]));
      expect(pax.admis, `pax, ${n + 1} composants`).to.equal(attendu);
      if (!attendu) expect([pax.raison, pax.parametres], `pax, ${n + 1}`).to.deep.equal(["r_chemin_long", { composants: String(n + 1), octets: String(2 + 2 * (n - 1) + 1) }]);
      const z = await refusDe(A.lireArchive, "d.zip", zip([{ nom: "d/dossier.json", donnees: "{}" }, { nom: `d/${composants(n)}`, donnees: "x" }]));
      expect(z.admis, `ZIP, ${n + 1} composants`).to.equal(attendu);
      if (!attendu) expect(z.raison).to.equal("r_chemin_long");
      const gnu = await refusDe(A.lireArchive, "d.tar", tar([{ nom: "d/dossier.json", donnees: "{}" }, { nom: "f", long: `d/${composants(n)}`, magie: "gnu", donnees: "x" }]));
      expect(gnu.admis, `GNU, ${n + 1} composants`).to.equal(attendu);
    }
    // Longueur en octets UTF-8, sur un seul composant : « é » fait deux octets.
    const longueur = (octets, c = "x") => `d/${c.repeat((octets - 2) / Buffer.byteLength(c))}`;
    expect((await refusDe(A.lireArchive, "d.zip", zip([{ nom: "d/dossier.json", donnees: "{}" }, { nom: longueur(4096), donnees: "x" }]))).admis).to.equal(true);
    const trop = await refusDe(A.lireArchive, "d.zip", zip([{ nom: "d/dossier.json", donnees: "{}" }, { nom: longueur(4097), donnees: "x" }]));
    expect([trop.raison, trop.parametres]).to.deep.equal(["r_chemin_long", { composants: "2", octets: "4097" }]);
    expect((await refusDe(A.lireArchive, "d.zip", zip([{ nom: "d/dossier.json", donnees: "{}" }, { nom: longueur(4096, "é"), donnees: "x", drapeaux: 0x0800 }]))).admis).to.equal(true);
    const tropUtf8 = await refusDe(A.lireArchive, "d.zip", zip([{ nom: "d/dossier.json", donnees: "{}" }, { nom: longueur(4098, "é"), donnees: "x", drapeaux: 0x0800 }]));
    expect([tropUtf8.raison, tropUtf8.parametres]).to.deep.equal(["r_chemin_long", { composants: "2", octets: "4098" }]);
    // Un nom ZIP de 65 535 octets (le plus long qu'un en-tête permet).
    const maximal = await refusDe(A.lireArchive, "d.zip", zip([{ nom: "d/dossier.json", donnees: "{}" }, { nom: `d/${"x".repeat(65533)}`, donnees: "x" }]));
    expect(maximal.raison).to.equal("r_chemin_long");
    // La borne vaut avant la normalisation : un nom brut trop long est refusé même si « ./ » répétés le raccourciraient.
    const brut = await refusDe(A.lireArchive, "d.tar", tar([{ nom: "d/dossier.json", donnees: "{}" }, { nom: "f", pax: { path: `${"./".repeat(2100)}d/f` }, donnees: "x" }]));
    expect(brut.raison).to.equal("r_chemin_long");
    // Répertoire choisi : mêmes bornes, sur les métadonnées.
    const refusRepertoire = (liste) => {
      try {
        A.bornesRepertoire(liste);
        return null;
      } catch (e) {
        return e.raison;
      }
    };
    expect(refusRepertoire([{ chemin: composants(64), taille: 1 }])).to.equal(null);
    expect(refusRepertoire([{ chemin: composants(65), taille: 1 }])).to.equal("r_chemin_long");
    expect(refusRepertoire([{ chemin: "x".repeat(4096), taille: 1 }])).to.equal(null);
    expect(refusRepertoire([{ chemin: "x".repeat(4097), taille: 1 }])).to.equal("r_chemin_long");
  });

  it("archive hostile du relecteur (CT-6 EX-18.7) : chemin pax de 100 000 composants dans 393 octets de .tar.gz, refusée r_chemin_long en moins d'une seconde ; un million de composants, et un .tar de 32 000 composants, aussi", async function () {
    // « d/ », n fois « a/ », puis le nom du fichier : n + 2 composants.
    const cas = [
      ["d.tar.gz", archiveProfonde(100000), 100002],
      ["d.tar.gz", archiveProfonde(1000000), 1000002],
      ["d.tar", tar([{ nom: "f", pax: { path: `d/${"a/".repeat(32000)}dossier.json` }, donnees: "{}" }]), 32002],
    ];
    expect(cas[0][1].length, "taille de l'archive du relecteur").to.be.lessThan(1024);
    for (const [nom, octets, composants] of cas) {
      const t0 = process.hrtime.bigint();
      const r = await refusDe(A.lireArchive, nom, new Uint8Array(octets));
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      expect([r.raison, r.parametres.composants], `${nom}, ${composants} composants`).to.deep.equal(["r_chemin_long", String(composants)]);
      expect(ms, `${nom}, ${composants} composants : ${ms.toFixed(0)} ms`).to.be.lessThan(1000);
    }
  });

  it("la recherche des parents (conflit fichier et répertoire) reste linéaire par chemin et juste : 4 000 fichiers de 60 composants lus en moins de deux secondes ; r_conflit toujours rendu", async function () {
    const entrees = [{ nom: "d/dossier.json", donnees: "{}" }];
    for (let i = 0; i < 4000; i++) entrees.push({ nom: `f${i}`, pax: { path: `d/${"a/".repeat(59)}f${i}` }, donnees: "" });
    const t0 = process.hrtime.bigint();
    const r = await refusDe(A.lireArchive, "d.tar", new Uint8Array(tar(entrees)));
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    expect(r.admis, JSON.stringify(r)).to.equal(true);
    expect(r.fichiers).to.have.length(4001);
    expect(ms, `${ms.toFixed(0)} ms`).to.be.lessThan(2000);
    const conflit = await refusDe(A.lireArchive, "d.tar", tar([{ nom: "d/dossier.json", donnees: "{}" }, { nom: "d/a/b", donnees: "1" }, { nom: "f", pax: { path: "d/a/b/c/e" }, donnees: "2" }]));
    expect([conflit.raison, conflit.parametres]).to.deep.equal(["r_conflit", { chemin: "d/a/b" }]);
  });

  it("fichier de plus de 512 Mio (CT-6 EX-18.7) : refusé d'après sa taille, r_fichier_trop_gros, avant qu'un octet ne soit lu ; 512 Mio admis à la borne", async function () {
    const refus = (nom, taille) => {
      try {
        A.bornerTailleFichier(nom, taille);
        return null;
      } catch (e) {
        return [e.raison, e.parametres];
      }
    };
    expect(refus("d.zip", 512 * Mio)).to.equal(null);
    expect(refus("d.zip", 512 * Mio + 1)).to.deep.equal(["r_fichier_trop_gros", { nom: "d.zip" }]);
    expect(refus("d.zip", Number.NaN)).to.deep.equal(["r_fichier_trop_gros", { nom: "d.zip" }]);
    // lireArchive : la taille est contrôlée avant tout examen des octets. Un objet
    // qui n'a qu'une longueur suffit : aucun octet ne doit être touché.
    for (const nom of ["d.zip", "d.tar", "d.tar.gz", "d.tgz"]) {
      const r = await refusDe(A.lireArchive, nom, { length: 512 * Mio + 1 });
      expect([r.raison, r.parametres], nom).to.deep.equal(["r_fichier_trop_gros", { nom }]);
    }
    // L'interface borne la taille déclarée par le navigateur avant arrayBuffer(),
    // dans sa seule fonction de lecture, qui sert à l'archive, aux fichiers
    // d'un répertoire, aux ancres et aux en-têtes.
    const interfaceJs = fs.readFileSync(path.join(SOURCES, "page", "interface.js"), "utf8");
    const corps = interfaceJs.slice(interfaceJs.indexOf("async function lireFichier("), interfaceJs.indexOf("function dossierDeRepertoire("));
    expect(corps.indexOf("bornerTailleFichier(fichier.name, fichier.size)")).to.be.greaterThan(-1);
    expect(corps.indexOf("bornerTailleFichier(")).to.be.lessThan(corps.indexOf("arrayBuffer()"));
    expect(interfaceJs.match(/arrayBuffer\(\)/g)).to.have.length(1);
  });

  it("répertoire déposé (CT-6 EX-18.7) : le compteur d'entrées s'arrête à la 4 097e entrée (r_trop_entrees), répertoires comptés, et refuse un chemin de 65 composants (r_chemin_long)", function () {
    const c = A.compteurEntrees();
    for (let i = 0; i < 4096; i++) c.ajouter(i % 2 === 0 ? `f-${i}` : `r-${i}`);
    expect(() => c.ajouter("f-4097")).to.throw().with.property("raison", "r_trop_entrees");
    const d = A.compteurEntrees();
    expect(() => d.ajouter(`${"a/".repeat(63)}f`)).to.not.throw();
    expect(() => d.ajouter(`${"a/".repeat(64)}f`)).to.throw().with.property("raison", "r_chemin_long");
    // L'interface compte pendant le parcours, avant de descendre dans un sous-répertoire.
    const interfaceJs = fs.readFileSync(path.join(SOURCES, "page", "interface.js"), "utf8");
    const corps = interfaceJs.slice(interfaceJs.indexOf("async function parcourirRepertoire("), interfaceJs.indexOf("async function deposer("));
    expect(corps.indexOf("compteur.ajouter(chemin)")).to.be.greaterThan(-1);
    expect(corps.indexOf("compteur.ajouter(chemin)")).to.be.lessThan(corps.indexOf("await parcourirRepertoire(e,"));
  });

  it("libellés : r_trop_entrees, r_trop_gros, r_chemin_long et r_fichier_trop_gros nomment les valeurs des constantes, en français et en anglais ; mêmes clés ; arreter, cause_arret et cause_version_differente présents", function () {
    const fr = libelles("libelles-fr.js", "LIBELLES_FR");
    const en = libelles("libelles-en.js", "LIBELLES_EN");
    expect(Object.keys(en)).to.deep.equal(Object.keys(fr));
    const nombres = (t) => (t.match(/[0-9][0-9 ,]*[0-9]|[0-9]/g) ?? []).map((x) => Number(x.replace(/[ ,]/g, "")));
    for (const table of [fr, en]) {
      expect(nombres(table.r_trop_entrees)).to.deep.equal([A.BORNES_ARCHIVE.entrees]);
      expect(nombres(table.r_trop_gros)).to.deep.equal([A.BORNES_ARCHIVE.octets / Mio]);
      expect(nombres(table.r_chemin_long)).to.deep.equal([A.BORNES_ARCHIVE.octets_chemin, A.BORNES_ARCHIVE.composants_chemin]);
      expect(table.r_chemin_long).to.include("{composants}").and.to.include("{octets}");
      expect(nombres(table.r_fichier_trop_gros)).to.deep.equal([A.BORNES_ARCHIVE.octets_fichier / Mio]);
      expect(table.r_fichier_trop_gros).to.include("{nom}");
      for (const cle of ["arreter", "cause_arret", "cause_version_differente"]) expect(table[cle], cle).to.be.a("string").that.is.not.empty;
      expect(table.cause_version_differente).to.include("{rapport}").and.to.include("{page}");
    }
  });
});

describe("page de vérification, revue de sécurité : arbre du travailleur sans récursion (CT-6 EX-18.8)", function () {
  this.timeout(60 * 1000);

  function prelude() {
    const ctx = vm.createContext({ TextEncoder });
    vm.runInContext(`${fs.readFileSync(path.join(SOURCES, "travailleur", "prelude.js"), "utf8")}\nglobalThis.__arbre = NOORTRACE_ARBRE;`, ctx);
    return ctx;
  }

  it("un chemin de 100 000 niveaux est installé sans débordement de pile, et lstat le trouve", function () {
    const ctx = prelude();
    const octets = vm.runInContext("new Uint8Array(1)", ctx);
    const chemin = `dossier/${"a/".repeat(100000)}f`;
    ctx.__arbre.installer(vm.runInContext("x => x", ctx)([{ chemin, octets }]), []);
    let r;
    ctx.fs.lstat(chemin, (e, v) => {
      r = { e, v };
    });
    expect(r.e).to.equal(null);
    expect([r.v.size, r.v.isDirectory()]).to.deep.equal([1, false]);
  });

  it("la numérotation reste celle d'un parcours en profondeur d'abord, noms triés par octets UTF-8, parent avant enfants : couples (dev, ino) inchangés", function () {
    const ctx = prelude();
    const o = (t) => {
      const u = vm.runInContext("n => new Uint8Array(n)", ctx)(t.length);
      u.set(Buffer.from(t));
      return u;
    };
    ctx.__arbre.installer(vm.runInContext("x => x", ctx)([
      { chemin: "dossier/dossier.json", octets: o("{}") },
      { chemin: "dossier/sous/b.json", octets: o("b") },
      { chemin: "dossier/sous/a.json", octets: o("a") },
      { chemin: "dossier/é.json", octets: o("e") },
      { chemin: "dossier/Z.json", octets: o("z") },
      { chemin: "ancres.json", octets: o("[]") },
      { chemin: "entetes-bitcoin.json", octets: o("[]") },
    ]), ["dossier/vide", "dossier/sous/creux"]);
    const ino = (c) => {
      let r;
      ctx.fs.lstat(c, (e, v) => {
        r = e ? e.code : v.ino;
      });
      return r;
    };
    // Ordre attendu : / (1), /entrees (2), ancres.json (3), dossier (4), Z.json (5), dossier.json (6), sous (7),
    // a.json (8), b.json (9), creux (10), vide (11), é.json (12), entetes-bitcoin.json (13).
    expect(["/", "/entrees", "ancres.json", "dossier", "dossier/Z.json", "dossier/dossier.json", "dossier/sous", "dossier/sous/a.json", "dossier/sous/b.json", "dossier/sous/creux", "dossier/vide", "dossier/é.json", "entetes-bitcoin.json"].map(ino))
      .to.deep.equal([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);
    let noms;
    ctx.fs.readdir("dossier", (e, v) => {
      noms = v;
    });
    expect(noms).to.deep.equal(["Z.json", "dossier.json", "sous", "vide", "é.json"]);
  });
});

describe("page de vérification, revue de sécurité : neutralisation des chaînes affichées (CT-6 EX-8.6, part page)", function () {
  const neutraliser = chargerNeutraliser();

  it("retour chariot, échappement, C0, DEL, C1, U+2028, U+2029, marques et isolats de direction : rendus sous la forme visible \\u{…} ; saut de ligne, tabulation, lettres accentuées et émojis inchangés ; idempotent", function () {
    expect(neutraliser, "fonction neutraliser et table CARACTERES_NEUTRALISES de interface.js").to.be.a("function");
    const cas = [
      ["\r", "\\u{000D}"],
      ["\u001b[2K", "\\u{001B}[2K"],
      ["\u0000", "\\u{0000}"],
      ["\u0007", "\\u{0007}"],
      ["\u000b\u000c", "\\u{000B}\\u{000C}"],
      ["\u007f", "\\u{007F}"],
      ["\u0085", "\\u{0085}"],
      ["\u009b[8m", "\\u{009B}[8m"],
      [" ", "\\u{2028}"],
      [" ", "\\u{2029}"],
      ["‮", "\\u{202E}"],
      ["‪‫‬‭", "\\u{202A}\\u{202B}\\u{202C}\\u{202D}"],
      ["⁦⁧⁨⁩", "\\u{2066}\\u{2067}\\u{2068}\\u{2069}"],
      ["‎‏؜", "\\u{200E}\\u{200F}\\u{061C}"],
    ];
    for (const [entree, attendu] of cas) expect(neutraliser(`a${entree}b`), JSON.stringify(entree)).to.equal(`a${attendu}b`);
    const intact = "Résultat : VALIDE\n\t[réussi] 4 — 2026-11-05T10:00:06Z 😀 « é » 日本";
    expect(neutraliser(intact)).to.equal(intact);
    const hostile = "Résultat : VALIDE\r\u001b[2K[réussi]‮ faux ligne";
    expect(neutraliser(neutraliser(hostile))).to.equal(neutraliser(hostile));
    expect(neutraliser(hostile)).to.equal("Résultat : VALIDE\\u{000D}\\u{001B}[2K[réussi]\\u{202E} faux\\u{2028}ligne");
    expect(neutraliser(12)).to.equal("12");
  });

  it("interface.js : tout texte affiché passe par neutraliser (element et les paramètres de libelle) ; aucune autre écriture de textContent n'est faite depuis une valeur", function () {
    const source = fs.readFileSync(path.join(SOURCES, "page", "interface.js"), "utf8");
    expect(source).to.include("if (texte !== undefined) e.textContent = neutraliser(texte);");
    expect(source).to.include("Object.hasOwn(parametres, k) ? neutraliser(parametres[k]) : tout");
    // Les autres écritures de textContent ne portent que des libellés (texte fixe et paramètres neutralisés).
    const autres = [...source.matchAll(/\.textContent = ([^;]+);/g)].map((m) => m[1]).filter((v) => v !== "neutraliser(texte)");
    for (const v of autres) expect(v, v).to.match(/^(libelle\(|`\$\{libelle\(|`\$\{libelle\()/);
    expect(source).to.not.match(/innerHTML|insertAdjacentHTML|outerHTML/);
  });
});
