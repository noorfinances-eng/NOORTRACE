// Page de vérification (CT-6 §18, révision 0.6) : sources de la page, sous
// Node, sans chaîne Go ni navigateur.
//
// - Lecture des archives (EX-18.7) : chaque refus, avant toute exécution ;
//   les formes admises, dont chaque recette d'EX-18.13 appliquée à chacun des
//   190 dossiers des vecteurs, rendent exactement les fichiers du dossier.
// - Arbre du prélude (EX-18.8) : erreurs POSIX, modes, couples (dev, ino),
//   membres d'état, lecture seule, process et path.
// - Libellés : phrases fixes d'EX-18.2, EX-18.5, EX-18.7 et EX-18.9 égales
//   au texte de CT-6, mêmes clés en français et en anglais.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { spawnSync } from "node:child_process";
import { casAdmis, casDeRefus, chargerArchives } from "./fixtures/verification-page/archives-essai.mjs";
import { RACINE, dossiersVecteurs, enAttente, fichiersDe, repertoireTemporaire } from "./fixtures/verification-page/outils.mjs";
import { recettesArchives, outilsArchivesDisponibles } from "./fixtures/verification-page/recettes.mjs";

const SOURCES = path.join(RACINE, "paquets", "verification-web", "src");

/** Le texte de CT-6, blancs ramenés à une espace. */
function texteCt6() {
  return fs.readFileSync(path.join(RACINE, "spec", "CT-6-verificateur.md"), "utf8").replace(/\s+/g, " ");
}

function libelles(fichier, nom) {
  return vm.runInNewContext(`${fs.readFileSync(path.join(SOURCES, "page", fichier), "utf8")}\n${nom};`, {});
}

describe("page de vérification : lecture des archives (CT-6 EX-18.7)", function () {
  this.timeout(10 * 60 * 1000);
  const { lireArchive, RefusArchive, bornesRepertoire } = chargerArchives();

  it("chaque refus d'EX-18.7 est rendu avant toute exécution, avec sa raison", async function () {
    const cas = casDeRefus();
    const raisons = new Set();
    for (const c of cas) {
      let erreur = null;
      try {
        await lireArchive(c.fichier, new Uint8Array(c.octets));
      } catch (e) {
        erreur = e;
      }
      expect(erreur, c.titre).to.be.instanceOf(RefusArchive);
      expect(erreur.raison, `${c.titre} : ${erreur && erreur.message}`).to.equal(c.raison);
      raisons.add(c.raison);
    }
    // Chaque raison, type et défaut a son libellé dans les deux langues.
    const fr = libelles("libelles-fr.js", "LIBELLES_FR");
    const en = libelles("libelles-en.js", "LIBELLES_EN");
    for (const c of cas) {
      let e = null;
      try {
        await lireArchive(c.fichier, new Uint8Array(c.octets));
      } catch (x) {
        e = x;
      }
      for (const cle of [e.raison, e.parametres.type, e.parametres.detail].filter((k) => k !== undefined)) {
        expect(Object.hasOwn(fr, cle) && Object.hasOwn(en, cle), `${c.titre} : libellé ${cle}`).to.equal(true);
      }
    }
    // Toutes les raisons de refus d'EX-18.7 sont éprouvées.
    for (const r of ["r_forme", "r_absolu", "r_composant", "r_barre_inverse", "r_double", "r_nom_codage", "r_type", "r_trop_entrees", "r_trop_gros", "r_racine", "r_chemin_vide", "r_chiffree", "r_zip64", "r_methode"]) {
      expect(raisons.has(r), r).to.equal(true);
    }
  });

  it("répertoire choisi (révision 0.7 d'EX-18.7) : mêmes bornes, comptées sur les métadonnées avant toute lecture ; 4 097 entrées ou plus de 256 Mio refusés avec leur raison", function () {
    const refus = (liste) => {
      try {
        bornesRepertoire(liste);
      } catch (e) {
        expect(e).to.be.instanceOf(RefusArchive);
        return e.raison;
      }
      return null;
    };
    const fichiers = (n, prefixe = "") => Array.from({ length: n }, (_, k) => ({ chemin: `${prefixe}f-${k}.json`, taille: 1 }));
    expect(refus(fichiers(4096))).to.equal(null);
    expect(refus(fichiers(4097))).to.equal("r_trop_entrees");
    // Les sous-répertoires comptent : 4 095 fichiers sous a/ = 4 096 entrées ; sous a/b/, 4 097.
    expect(refus(fichiers(4095, "a/"))).to.equal(null);
    expect(refus(fichiers(4095, "a/b/"))).to.equal("r_trop_entrees");
    const Mio = 1024 * 1024;
    expect(refus([{ chemin: "dossier.json", taille: 128 * Mio }, { chemin: "pieces/p", taille: 128 * Mio }])).to.equal(null);
    expect(refus([{ chemin: "dossier.json", taille: 128 * Mio }, { chemin: "pieces/p", taille: 128 * Mio + 1 }])).to.equal("r_trop_gros");
    // L'interface applique ces bornes au répertoire avant de lire le premier fichier.
    const interfaceJs = fs.readFileSync(path.join(SOURCES, "page", "interface.js"), "utf8");
    const corps = interfaceJs.slice(interfaceJs.indexOf("function dossierDeRepertoire("), interfaceJs.indexOf("function dossierDArchive("));
    expect(corps.indexOf("bornesRepertoire(")).to.be.greaterThan(-1);
    expect(corps.indexOf("bornesRepertoire(")).to.be.lessThan(corps.indexOf("lireFichier("));
  });

  it("formes admises écrites octet par octet : ustar à préfixe, pax, nom long GNU, en-tête g, « ./ », entrée « . », ZIP à la racine", async function () {
    for (const c of casAdmis()) {
      const r = await lireArchive(c.fichier, new Uint8Array(c.octets));
      const obtenus = new Map(r.fichiers.map((f) => [f.chemin, Buffer.from(f.octets).toString("utf8")]));
      expect([...obtenus.entries()].sort(), c.titre).to.deep.equal([...c.attendus.fichiers.entries()].sort());
      expect(r.repertoires.sort(), c.titre).to.deep.equal(c.attendus.repertoires.sort());
    }
  });

  it("chaque recette d'EX-18.13, sur chacun des 190 dossiers des vecteurs, rend exactement les fichiers du dossier", async function () {
    const manque = outilsArchivesDisponibles();
    if (manque) return enAttente(this, manque);
    const dir = repertoireTemporaire("noortrace-page-recettes");
    try {
      let n = 0;
      for (const d of dossiersVecteurs()) {
        const attendus = fichiersDe(d.chemin).map((f) => [f.chemin, f.octets.toString("base64")]);
        for (const a of recettesArchives(d.chemin, dir)) {
          const r = await lireArchive(a.fichier, new Uint8Array(fs.readFileSync(a.chemin)));
          const obtenus = r.fichiers.map((f) => [f.chemin, Buffer.from(f.octets).toString("base64")]).sort();
          expect(obtenus, `${d.nom} ${a.recette}`).to.deep.equal(attendus.sort());
          expect(r.repertoires.every((x) => attendus.some(([c]) => c.startsWith(`${x}/`))), `${d.nom} ${a.recette}`).to.equal(true);
          fs.rmSync(a.chemin);
          n++;
        }
      }
      expect(n).to.equal(190 * 7);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("page de vérification : arbre présenté au programme (CT-6 EX-18.8)", function () {
  /** Le prélude seul, dans un contexte neuf ; rend { fs, process, path, arbre }. */
  function prelude() {
    const ctx = vm.createContext({ TextEncoder });
    vm.runInContext(`${fs.readFileSync(path.join(SOURCES, "travailleur", "prelude.js"), "utf8")}\nglobalThis.__arbre = NOORTRACE_ARBRE;`, ctx);
    const appel = (nom, ...args) => {
      let r;
      ctx.fs[nom](...args, (e, v) => {
        r = { e, v };
      });
      return r;
    };
    ctx.Uint8Array = vm.runInContext("Uint8Array", ctx);
    return { ctx, appel };
  }

  const octets = (t) => new Uint8Array(Buffer.from(t));

  it("constantes de Node sous Linux, répertoire de travail /entrees, identité 0, umask 0o022, chdir refusé (ENOSYS)", function () {
    const { ctx } = prelude();
    expect({ ...ctx.fs.constants }).to.deep.equal({ O_WRONLY: 1, O_RDWR: 2, O_CREAT: 64, O_EXCL: 128, O_TRUNC: 512, O_APPEND: 1024, O_DIRECTORY: 65536 });
    const p = ctx.process;
    expect([p.cwd(), p.pid, p.ppid, p.getuid(), p.getgid(), p.geteuid(), p.getegid(), p.umask(0), p.getgroups().length]).to.deep.equal(["/entrees", 1, 0, 0, 0, 0, 0, 0o022, 0]);
    expect(() => p.chdir("/")).to.throw().with.property("code", "ENOSYS");
  });

  it("path.resolve résout contre /entrees et normalise, comme Node", function () {
    const { ctx } = prelude();
    for (const [args, attendu] of [
      [["dossier"], "/entrees/dossier"],
      [["dossier/./a/../b.json"], "/entrees/dossier/b.json"],
      [["/x//y/"], "/x/y"],
      [["/a", "b", "../c"], "/a/c"],
      [[".."], "/"],
      [["../../.."], "/"],
      [[""], "/entrees"],
    ]) expect(ctx.path.resolve(...args), JSON.stringify(args)).to.equal(attendu);
    expect(ctx.path.resolve("dossier/x")).to.equal(path.posix.resolve("/entrees", "dossier/x"));
  });

  it("arbre en lecture seule : modes, tailles, couples (dev, ino) stables, membres d'état numériques, erreurs POSIX", function () {
    const { ctx, appel } = prelude();
    ctx.__arbre.installer(vm.runInContext("x => x", ctx)([
      { chemin: "dossier/dossier.json", octets: octets("{}") },
      { chemin: "dossier/sous/a.json", octets: octets("abcdef") },
      { chemin: "ancres.json", octets: octets("[]") },
    ]), ["dossier/vide"]);
    const membres = ["dev", "ino", "mode", "nlink", "uid", "gid", "rdev", "size", "blksize", "blocks", "atimeMs", "mtimeMs", "ctimeMs"];
    const s = appel("lstat", "/entrees/dossier/sous/a.json").v;
    for (const m of membres) expect(typeof s[m], m).to.equal("number");
    expect([s.mode, s.size, s.uid, s.gid, s.mtimeMs, s.isDirectory()]).to.deep.equal([0o100444, 6, 0, 0, 0, false]);
    const r = appel("stat", "dossier").v;
    expect([r.mode, r.isDirectory()]).to.deep.equal([0o040555, true]);
    // lstat et fstat rendent le même couple (dev, ino).
    const fd = appel("open", "dossier/sous/a.json", 0, 0).v;
    const f = appel("fstat", fd).v;
    expect([f.dev, f.ino]).to.deep.equal([s.dev, s.ino]);
    // Lecture séquentielle et positionnée.
    const t = new ctx.Uint8Array(4);
    expect(appel("read", fd, t, 0, 4, null).v).to.equal(4);
    expect(Buffer.from(t).toString()).to.equal("abcd");
    expect(appel("read", fd, t, 0, 4, null).v).to.equal(2);
    expect(appel("read", fd, t, 0, 4, null).v).to.equal(0);
    expect(appel("read", fd, t, 1, 2, 3).v).to.equal(2);
    expect(Buffer.from(t).toString("latin1", 1, 3)).to.equal("de");
    expect(appel("close", fd).e).to.equal(null);
    expect(appel("close", fd).e.code).to.equal("EBADF");
    expect(appel("readdir", "/entrees").v).to.deep.equal(["ancres.json", "dossier"]);
    expect(appel("readdir", "dossier").v).to.deep.equal(["dossier.json", "sous", "vide"]);
    const erreurs = {
      ENOENT: [appel("lstat", "dossier/absent.json"), appel("open", "absent", 0, 0), appel("stat", "")],
      ENOTDIR: [appel("lstat", "ancres.json/x"), appel("stat", "ancres.json/"), appel("readdir", "ancres.json"), appel("open", "ancres.json", 65536, 0)],
      EROFS: [appel("open", "nouveau", 64 | 1, 0o644), appel("open", "ancres.json", 2, 0), appel("open", "ancres.json", 1024, 0), appel("mkdir", "x", 0o755), appel("unlink", "ancres.json"), appel("rename", "a", "b"), appel("chmod", "ancres.json", 0o777), appel("utimes", "ancres.json", 0, 0)],
      ENOSYS: [appel("readlink", "ancres.json"), appel("fsync", 3)],
      EBADF: [appel("fstat", 99), appel("read", 99, new ctx.Uint8Array(1), 0, 1, null), appel("write", 0, new ctx.Uint8Array(1), 0, 1, null)],
    };
    for (const [code, liste] of Object.entries(erreurs)) for (const x of liste) expect(x.e && x.e.code, code).to.equal(code);
    const dfd = appel("open", "dossier", 0, 0).v;
    expect(appel("read", dfd, new ctx.Uint8Array(1), 0, 1, null).e.code).to.equal("EISDIR");
    // « .. » à travers un fichier : ENOTDIR, comme le noyau.
    expect(appel("lstat", "ancres.json/../dossier").e.code).to.equal("ENOTDIR");
    expect(appel("lstat", "dossier/../ancres.json").e).to.equal(null);
    // Une nouvelle installation donne les mêmes couples.
    const avant = appel("lstat", "dossier/sous/a.json").v.ino;
    ctx.__arbre.installer(vm.runInContext("x => x", ctx)([
      { chemin: "dossier/dossier.json", octets: octets("{}") },
      { chemin: "dossier/sous/a.json", octets: octets("abcdef") },
      { chemin: "ancres.json", octets: octets("[]") },
    ]), ["dossier/vide"]);
    expect(appel("lstat", "dossier/sous/a.json").v.ino).to.equal(avant);
  });

  it("sorties 1 et 2 recueillies par write et writeSync ; chemins d'entrée mal formés ou en double refusés", function () {
    const { ctx, appel } = prelude();
    ctx.__arbre.ouvrirSorties();
    expect(appel("write", 1, octets("abc"), 1, 2, null).v).to.equal(2);
    expect(ctx.fs.writeSync(2, octets("err"))).to.equal(3);
    expect(appel("write", 1, octets("x"), 0, 1, 5).e.code).to.equal("ENOSYS");
    const s = ctx.__arbre.fermerSorties();
    expect([Buffer.from(s.sortie).toString(), Buffer.from(s.erreur).toString()]).to.deep.equal(["bc", "err"]);
    const installer = (fichiers, reps = []) => () => ctx.__arbre.installer(vm.runInContext("x => x", ctx)(fichiers), reps);
    for (const chemin of ["../x", "dossier/./x", "dossier//x", "/x", "dossier/x/", ""]) {
      expect(installer([{ chemin, octets: octets("") }]), chemin).to.throw(/chemin d'entrée mal formé/);
    }
    expect(installer([{ chemin: "dossier/a", octets: octets("") }, { chemin: "dossier/a", octets: octets("") }])).to.throw(/en double/);
    expect(installer([{ chemin: "dossier/a", octets: octets("") }, { chemin: "dossier/a/b", octets: octets("") }])).to.throw(/à la fois fichier et répertoire/);
    expect(installer([{ chemin: "dossier/a", octets: octets("") }], ["dossier/a"])).to.throw(/en double/);
  });
});

describe("page de vérification : libellés (CT-6 EX-18.2, EX-18.5, EX-18.7, EX-18.9)", function () {
  const fr = libelles("libelles-fr.js", "LIBELLES_FR");
  const en = libelles("libelles-en.js", "LIBELLES_EN");

  it("mêmes clés en français et en anglais", function () {
    expect(Object.keys(en)).to.deep.equal(Object.keys(fr));
  });

  it("phrases fixes égales, mot pour mot, au texte de CT-6 §18", function () {
    const ct6 = texteCt6();
    const p = /la phrase fixe : « (Cette page .*? le binaire\.) » \(« (This page .*? the binary\.) »\)/.exec(ct6);
    expect(p, "phrase d'EX-18.2 dans CT-6").to.not.equal(null);
    expect(fr.phrase_fixe.replace("{version}", "<version>")).to.equal(p[1]);
    expect(en.phrase_fixe.replace("{version}", "<version>")).to.equal(p[2]);
    const a = /affiche « (artefact du vérificateur altéré : .*?) » \(« (verifier artefact altered: .*?) »\)/.exec(ct6);
    expect(fr.artefact_altere.replace("{calculee}", "<calculée>").replace("{attendue}", "<attendue>")).to.equal(a[1]);
    expect(en.artefact_altere.replace("{calculee}", "<computed>").replace("{attendue}", "<expected>")).to.equal(a[2]);
    expect(ct6).to.include(`la raison, « ${fr.aucun_rapport} » (« ${en.aucun_rapport} »)`);
    expect(ct6).to.include(`« ${fr.aucune_affirmation} » (« ${en.aucune_affirmation} »)`);
    expect(ct6).to.include(`affiche « ${fr.non_faite} » (« ${en.non_faite} »)`);
    // Révision 0.7 d'EX-18.9 : sens des codes affiché par la page anglaise, table mot pour mot.
    for (const code of [0, 1, 2, 3]) {
      const ligne = new RegExp(`\\| ${code} \\| ([a-z][^|]*?) \\|`).exec(ct6.slice(ct6.indexOf("Sens affiché par la page anglaise")));
      expect(ligne, `ligne ${code} de la table d'EX-18.9`).to.not.equal(null);
      expect(en[`code_${code}`], `code ${code}`).to.equal(ligne[1]);
    }
  });
});
