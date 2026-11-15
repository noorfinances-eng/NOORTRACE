// Empreinte du code en cours et image attendue (CT-7 EX-3.14, proposition
// PA-4 à CT-2 ; menace MN-25 ; CT-9 TA-25) : `empreinteCode`,
// `racineInstallation`, `lireImageAttendue`, `controlerImage`
// (paquets/enregistreur/src/empreinte-image.mjs), la commande
// `noortrace empreinte`, l'option `--image-attendue` du démon et ce que le
// démon réel consigne (ligne `startup`, ligne `image_mismatch`). Les arbres
// d'installation d'essai ont la disposition de `/opt/noortrace` dans l'image
// de référence (test/fixtures/enregistreur-adversarial/image.mjs) ; aucun
// conteneur, aucun réseau. Le mutant de TA-25 est dans
// test/adversarial.test.js.

import { expect } from "chai";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { empreinteCode, racineInstallation, lireImageAttendue, controlerImage, ErreurImageAttendue, PAQUET_EN_COURS } from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { RACINE } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationDemon, demarrer, arreter, sante, detruireMutants } from "./fixtures/enregistreur-adversarial/demon.mjs";
import { arbreInstallation, modifierUnOctet, ecrireImageAttendue } from "./fixtures/enregistreur-adversarial/image.mjs";

const IMAGE = `noortrace/enregistreur:0.1.0@sha256:${"ab".repeat(32)}`;
const sha256 = (octets) => `0x${createHash("sha256").update(octets).digest("hex")}`;

describe("enregistreur : empreinte du code en cours et image attendue (CT-7 EX-3.14, PA-4 ; MN-25)", function () {
  this.timeout(300000);
  let base;
  let publie;
  let empreintePubliee;

  before(function () {
    base = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-empreinte-image-"));
    publie = arbreInstallation(path.join(base, "publie"));
    empreintePubliee = empreinteCode({ racine: publie.racine });
  });
  after(function () {
    detruireMutants();
    if (base) fs.rmSync(base, { recursive: true, force: true });
  });

  /** Petit répertoire à trois fichiers et un lien, pour les propriétés du manifeste. */
  function petit(nom) {
    const d = path.join(base, nom);
    fs.mkdirSync(path.join(d, "b"), { recursive: true });
    fs.writeFileSync(path.join(d, "b", "y.txt"), "y\n");
    fs.writeFileSync(path.join(d, "a.txt"), "a\n");
    fs.writeFileSync(path.join(d, "b.txt"), "b\n");
    fs.symlinkSync("b/y.txt", path.join(d, "lien"));
    fs.mkdirSync(path.join(d, "vide"));
    const executable = path.join(base, `${nom}-binaire`);
    fs.writeFileSync(executable, "binaire d'essai\n");
    return { d, executable };
  }

  describe("empreinteCode : forme du manifeste", function () {
    it("manifeste : première ligne [\"node\", sha256 du binaire], puis une ligne JSON par fichier ([\"f\", chemin, sha256]) et par lien non suivi ([\"l\", chemin, cible]), triées par les octets du chemin, LF final ; aucun répertoire ; code_sha256 = SHA-256 du manifeste", function () {
      const { d, executable } = petit("forme");
      const e = empreinteCode({ racine: d, executable });
      expect(e.manifeste).to.equal(
        [
          ["node", sha256("binaire d'essai\n")],
          ["f", "a.txt", sha256("a\n")],
          ["f", "b.txt", sha256("b\n")],
          ["f", "b/y.txt", sha256("y\n")],
          ["l", "lien", "b/y.txt"],
        ].map((l) => `${JSON.stringify(l)}\n`).join(""),
      );
      expect(e.code_sha256).to.equal(sha256(e.manifeste));
      expect(e.entrees).to.equal(4);
      expect(e.racine).to.equal(fs.realpathSync(d));
      expect(empreinteCode({ racine: d, executable }).code_sha256, "deux calculs, même empreinte").to.equal(e.code_sha256);
    });

    it("tri par octets UTF-8 du chemin entier : « a-b » avant « a/b », un nom en majuscule avant les minuscules, un nom accentué après", function () {
      const d = path.join(base, "tri");
      fs.mkdirSync(path.join(d, "a"), { recursive: true });
      for (const n of ["a/b", "a-b", "Z", "é", "z"]) fs.writeFileSync(path.join(d, n), "");
      const chemins = empreinteCode({ racine: d, executable: path.join(d, "Z") }).manifeste.trim().split("\n").slice(1).map((l) => JSON.parse(l)[1]);
      expect(chemins).to.deep.equal(["Z", "a-b", "a/b", "z", "é"]);
    });

    it("l'empreinte change quand un fichier est modifié d'un octet, ajouté ou retiré, quand un lien est redirigé, quand le binaire change ; elle ne change pas pour un répertoire vide ajouté, des droits ou une date modifiés", function () {
      const { d, executable } = petit("change");
      const e0 = empreinteCode({ racine: d, executable }).code_sha256;
      const attendre = (quoi, change) => {
        const e = empreinteCode({ racine: d, executable }).code_sha256;
        if (change) expect(e, quoi).to.not.equal(e0);
        else expect(e, quoi).to.equal(e0);
      };
      fs.writeFileSync(path.join(d, "a.txt"), "a ");
      attendre("un octet modifié", true);
      fs.writeFileSync(path.join(d, "a.txt"), "a\n");
      attendre("fichier rétabli", false);
      fs.writeFileSync(path.join(d, "b", "ajout"), "");
      attendre("fichier ajouté", true);
      fs.rmSync(path.join(d, "b", "ajout"));
      fs.rmSync(path.join(d, "b.txt"));
      attendre("fichier retiré", true);
      fs.writeFileSync(path.join(d, "b.txt"), "b\n");
      fs.rmSync(path.join(d, "lien"));
      fs.symlinkSync("a.txt", path.join(d, "lien"));
      attendre("lien redirigé", true);
      fs.rmSync(path.join(d, "lien"));
      fs.symlinkSync("b/y.txt", path.join(d, "lien"));
      attendre("lien rétabli", false);
      fs.writeFileSync(executable, "autre binaire\n");
      attendre("binaire changé", true);
      fs.writeFileSync(executable, "binaire d'essai\n");
      fs.mkdirSync(path.join(d, "vide2"));
      fs.chmodSync(path.join(d, "a.txt"), 0o600);
      fs.utimesSync(path.join(d, "b.txt"), new Date(0), new Date(0));
      attendre("répertoire vide, droits, date", false);
    });

    it("un lien symbolique n'est pas suivi : sa cible hors de l'arbre n'est ni lue ni hachée ; un répertoire illisible ou un binaire absent lève ErreurImageAttendue (empreinte_impossible)", function () {
      const d = path.join(base, "liens");
      fs.mkdirSync(d);
      const dehors = path.join(base, "dehors.txt");
      fs.writeFileSync(dehors, "un\n");
      fs.symlinkSync(dehors, path.join(d, "vers-dehors"));
      const executable = path.join(d, "vers-dehors");
      const e1 = empreinteCode({ racine: d, executable }).manifeste;
      expect(e1.split("\n")[1]).to.equal(JSON.stringify(["l", "vers-dehors", dehors]));
      for (const o of [{ racine: path.join(base, "absent"), executable }, { racine: d, executable: path.join(base, "binaire-absent") }]) {
        let erreur = null;
        try {
          empreinteCode(o);
        } catch (e) {
          erreur = e;
        }
        expect(erreur).to.be.instanceOf(ErreurImageAttendue);
        expect(erreur.regle).to.equal("empreinte_impossible");
      }
    });
  });

  describe("racineInstallation", function () {
    it("dans un arbre d'installation : l'ancêtre dont node_modules/@noortrace/enregistreur désigne le paquet ; un paquet copié seul : le paquet lui-même ; le paquet du dépôt : la racine du dépôt", function () {
      expect(racineInstallation(publie.paquet)).to.equal(fs.realpathSync(publie.racine));
      const seul = path.join(base, "seul", "enregistreur");
      fs.mkdirSync(path.join(seul, "src"), { recursive: true });
      expect(racineInstallation(seul)).to.equal(fs.realpathSync(seul));
      // node_modules présent chez un ancêtre, mais qui désigne un autre paquet (disposition des mutants de CT-9 EX-10.5).
      const mutant = path.join(base, "disposition-mutant");
      fs.mkdirSync(path.join(mutant, "paquets", "enregistreur"), { recursive: true });
      fs.symlinkSync(path.join(RACINE, "node_modules"), path.join(mutant, "node_modules"));
      expect(racineInstallation(path.join(mutant, "paquets", "enregistreur"))).to.equal(fs.realpathSync(path.join(mutant, "paquets", "enregistreur")));
      expect(PAQUET_EN_COURS).to.equal(path.join(RACINE, "paquets", "enregistreur"));
      expect(racineInstallation()).to.equal(fs.realpathSync(RACINE));
    });

    it("l'arbre d'essai a la disposition de l'image de référence : paquets enregistreur, ancrage et noyau, liens node_modules/@noortrace relatifs, consignés comme liens ; son empreinte ne dépend pas de l'endroit où il est copié", function () {
      const lignes = empreintePubliee.manifeste.trim().split("\n").map((l) => JSON.parse(l));
      expect(lignes[0][0]).to.equal("node");
      for (const nom of ["enregistreur", "ancrage", "noyau"]) expect(lignes).to.deep.include(["l", `node_modules/@noortrace/${nom}`, `../../paquets/${nom}`]);
      expect(lignes.some((l) => l[0] === "f" && l[1] === "paquets/enregistreur/src/empreinte-image.mjs")).to.equal(true);
      expect(lignes.some((l) => l[0] === "f" && l[1] === "paquets/enregistreur/bin/noortrace")).to.equal(true);
      expect(lignes.filter((l) => l[0] === "x")).to.deep.equal([]);
      const copie = arbreInstallation(path.join(base, "ailleurs", "copie"));
      expect(empreinteCode({ racine: copie.racine }).code_sha256).to.equal(empreintePubliee.code_sha256);
    });
  });

  describe("lireImageAttendue : fichier monté par l'orchestrateur", function () {
    const ecrire = (nom, texte) => {
      const f = path.join(base, nom);
      fs.writeFileSync(f, texte);
      return f;
    };
    const refus = (f) => {
      try {
        lireImageAttendue(f);
      } catch (e) {
        expect(e).to.be.instanceOf(ErreurImageAttendue);
        return e.regle;
      }
      return null;
    };

    it("forme admise : { version: 0, image: <nom>[:<étiquette>]@sha256:<64 hex>, code_sha256: 0x<64 hex> } ; rend image et code_sha256", function () {
      const f = ecrireImageAttendue(path.join(base, "attendue-valide.json"), { image: IMAGE, code_sha256: `0x${"cd".repeat(32)}` });
      expect(lireImageAttendue(f)).to.deep.equal({ image: IMAGE, code_sha256: `0x${"cd".repeat(32)}` });
      expect(lireImageAttendue(ecrire("attendue-sans-etiquette.json", JSON.stringify({ version: 0, image: `noortrace/enregistreur@sha256:${"0".repeat(64)}`, code_sha256: `0x${"1".repeat(64)}` }))).image).to.equal(`noortrace/enregistreur@sha256:${"0".repeat(64)}`);
    });

    it("refus : fichier absent (fichier_illisible) ; JSON non strict, clé en double, tableau, membre en trop, membre absent, version autre que 0, image sans condensé, condensé en majuscules ou trop court, code_sha256 mal formé, fichier de plus de 4096 octets (forme_invalide)", function () {
      const bon = { version: 0, image: IMAGE, code_sha256: `0x${"cd".repeat(32)}` };
      expect(refus(path.join(base, "attendue-absente.json"))).to.equal("fichier_illisible");
      const cas = {
        "non-json": "{ version: 0 }",
        "cle-double": `{"version":0,"version":0,"image":"${IMAGE}","code_sha256":"0x${"cd".repeat(32)}"}`,
        tableau: JSON.stringify([bon]),
        "membre-en-trop": JSON.stringify({ ...bon, note: "x" }),
        "membre-absent": JSON.stringify({ version: 0, image: IMAGE }),
        version: JSON.stringify({ ...bon, version: 1 }),
        "image-sans-condense": JSON.stringify({ ...bon, image: "noortrace/enregistreur:0.1.0" }),
        "condense-majuscules": JSON.stringify({ ...bon, image: `noortrace/enregistreur:0.1.0@sha256:${"AB".repeat(32)}` }),
        "condense-court": JSON.stringify({ ...bon, image: `noortrace/enregistreur:0.1.0@sha256:${"ab".repeat(31)}` }),
        "code-majuscules": JSON.stringify({ ...bon, code_sha256: `0x${"CD".repeat(32)}` }),
        "code-sans-prefixe": JSON.stringify({ ...bon, code_sha256: "cd".repeat(32) }),
        "code-court": JSON.stringify({ ...bon, code_sha256: `0x${"cd".repeat(31)}` }),
        "code-nombre": JSON.stringify({ ...bon, code_sha256: 1 }),
        "trop-long": `${JSON.stringify(bon)}${" ".repeat(4096)}`,
      };
      for (const [nom, texte] of Object.entries(cas)) expect(refus(ecrire(`attendue-${nom}.json`, texte)), nom).to.equal("forme_invalide");
    });
  });

  describe("controlerImage : comparaison", function () {
    it("empreinte attendue égale à celle de l'arbre : image_match vrai ; arbre modifié d'un octet : image_match faux, les deux empreintes rendues ; l'image attendue est rendue telle qu'écrite", function () {
      const f = ecrireImageAttendue(path.join(base, "controle.json"), { image: IMAGE, code_sha256: empreintePubliee.code_sha256 });
      expect(controlerImage({ fichier: f, racine: publie.racine })).to.deep.equal({ image_expected: IMAGE, expected_code_sha256: empreintePubliee.code_sha256, code_sha256: empreintePubliee.code_sha256, image_match: true });
      const modifie = arbreInstallation(path.join(base, "controle-modifie"));
      modifierUnOctet(modifie, "paquets/noyau/src/index.mjs");
      const r = controlerImage({ fichier: f, racine: modifie.racine });
      expect(r.image_match).to.equal(false);
      expect(r.expected_code_sha256).to.equal(empreintePubliee.code_sha256);
      expect(r.code_sha256).to.equal(empreinteCode({ racine: modifie.racine }).code_sha256);
      expect(r.code_sha256).to.not.equal(empreintePubliee.code_sha256);
    });
  });

  describe("ligne de commande et démon réel", function () {
    let service;
    let serveur;
    let n = 0;

    before(async function () {
      service = new ServiceApprobationFactice({ org_id: "0x00", journal_id: null });
      serveur = await service.servir(0);
    });
    after(function () {
      serveur?.close();
    });

    async function configuration(arguments_) {
      const dir = path.join(base, `demon-${++n}`);
      fs.mkdirSync(dir);
      const c = await configurationDemon(dir, { approbation: serveur.address().port });
      service.org_id = c.config.recorder.org_id;
      service.journal_id = c.config.recorder.journal_id;
      c.arguments = arguments_;
      return c;
    }
    const lancerSeul = (arbre, args) => spawnSync(process.execPath, [arbre.bin("noortrace"), ...args], { encoding: "utf8", timeout: 120000 });

    it("noortrace empreinte, dans l'arbre : une ligne JSON { code_sha256, entries }, égale à celle de la bibliothèque, code 0 ; un argument en trop : usage, code 2", function () {
      const r = lancerSeul(publie, ["empreinte"]);
      expect(r.status, r.stderr).to.equal(0);
      expect(JSON.parse(r.stdout)).to.deep.equal({ code_sha256: empreintePubliee.code_sha256, entries: empreintePubliee.entrees });
      expect(r.stdout.endsWith("\n")).to.equal(true);
      const trop = lancerSeul(publie, ["empreinte", "x"]);
      expect(trop.status).to.equal(2);
      expect(trop.stderr).to.match(/^usage : noortrace --config <fichier> \[--image-attendue <fichier>\] \| noortrace validate-config <fichier> \| noortrace empreinte\n$/);
    });

    it("--image-attendue sans valeur, suivi d'une autre option ou donné deux fois, option mal écrite (--image-attendu), argument en trop, --config donné deux fois : usage, code 2 ; l'ordre des deux options est libre ; fichier absent : demarrage_refuse : image_attendue : fichier_illisible, code 2 ; fichier mal formé : forme_invalide, code 2 ; rien n'est écrit au journal d'exploitation", async function () {
      const c = await configuration([]);
      const f = path.join(c.dir, "configuration.json");
      fs.writeFileSync(f, JSON.stringify(c.config));
      const env = { ...process.env, ...c.env };
      const lancer = (args) => spawnSync(process.execPath, [publie.bin("noortrace"), ...args], { encoding: "utf8", env, timeout: 120000 });
      const bon = ecrireImageAttendue(path.join(c.dir, "image.json"), { image: IMAGE, code_sha256: empreintePubliee.code_sha256 });
      for (const args of [["--config", f, "--image-attendue"], ["--image-attendue", "--config", f], ["--config", f, "--image-attendue", bon, "--image-attendue", bon], ["--config", f, "--image-attendu", bon], ["--config", f, "--image-attendue", bon, "reste"], ["reste", "--config", f], ["--config", f, "--config", f]]) {
        const r = lancer(args);
        expect(r.status, args.join(" ")).to.equal(2);
        expect(r.stderr, args.join(" ")).to.match(/^usage : noortrace /);
      }
      // L'ordre des deux options est libre : l'option est lue, le fichier absent refuse le démarrage.
      const avant = lancer(["--image-attendue", path.join(c.dir, "absent.json"), "--config", f]);
      expect(avant.status).to.equal(2);
      expect(avant.stderr).to.include("demarrage_refuse : image_attendue : fichier_illisible : ");
      const absent = lancer(["--config", f, "--image-attendue", path.join(c.dir, "absent.json")]);
      expect(absent.status).to.equal(2);
      expect(absent.stderr).to.include("demarrage_refuse : image_attendue : fichier_illisible : ");
      const malForme = path.join(c.dir, "mal-forme.json");
      fs.writeFileSync(malForme, JSON.stringify({ version: 0, image: "noortrace/enregistreur:0.1.0", code_sha256: empreintePubliee.code_sha256 }));
      const forme = lancer(["--config", f, "--image-attendue", malForme]);
      expect(forme.status).to.equal(2);
      expect(forme.stderr).to.include("demarrage_refuse : image_attendue : forme_invalide : ");
      expect(fs.existsSync(c.config.supervision.ops_log.path)).to.equal(false);
    });

    it("démon réel sans --image-attendue : la ligne startup porte image_expected, code_sha256 et image_match nuls ; aucune ligne image_mismatch", async function () {
      const c = await configuration([]);
      const p = await demarrer(publie, c, path.join(c.dir, "configuration.json"));
      try {
        const startup = p.lignes().filter((l) => l.event === "startup");
        expect(startup).to.have.lengthOf(1);
        expect(startup[0].data).to.include({ image_expected: null, code_sha256: null, image_match: null });
        expect(startup[0].data.config_sha256).to.match(/^0x[0-9a-f]{64}$/);
        expect(p.lignes().filter((l) => l.event === "image_mismatch")).to.deep.equal([]);
      } finally {
        await arreter(p);
      }
    });

    it("démon réel de l'arbre publié avec l'image attendue : startup consigne l'image attendue, code_sha256 égal à l'empreinte publiée et image_match vrai, aucune ligne image_mismatch ; démon de l'arbre modifié d'un octet : code_sha256 différent, image_match faux, une ligne image_mismatch de niveau error (image attendue, empreinte attendue, empreinte calculée), et le démon sert quand même (/healthz ok)", async function () {
      const c1 = await configuration([]);
      c1.arguments = ["--image-attendue", ecrireImageAttendue(path.join(c1.dir, "image-attendue.json"), { image: IMAGE, code_sha256: empreintePubliee.code_sha256 })];
      const p1 = await demarrer(publie, c1, path.join(c1.dir, "configuration.json"));
      try {
        const s = p1.lignes().find((l) => l.event === "startup");
        expect(s.data).to.include({ image_expected: IMAGE, code_sha256: empreintePubliee.code_sha256, image_match: true });
        expect(p1.lignes().filter((l) => l.event === "image_mismatch")).to.deep.equal([]);
      } finally {
        await arreter(p1);
      }
      const modifie = arbreInstallation(path.join(base, "demon-modifie"));
      modifierUnOctet(modifie, "paquets/enregistreur/src/horloge.mjs");
      const empreinteModifiee = empreinteCode({ racine: modifie.racine }).code_sha256;
      expect(empreinteModifiee).to.not.equal(empreintePubliee.code_sha256);
      const c2 = await configuration([]);
      c2.arguments = ["--image-attendue", ecrireImageAttendue(path.join(c2.dir, "image-attendue.json"), { image: IMAGE, code_sha256: empreintePubliee.code_sha256 })];
      const p2 = await demarrer(modifie, c2, path.join(c2.dir, "configuration.json"));
      try {
        const s = p2.lignes().find((l) => l.event === "startup");
        expect(s.data).to.include({ image_expected: IMAGE, code_sha256: empreinteModifiee, image_match: false });
        const ecarts = p2.lignes().filter((l) => l.event === "image_mismatch");
        expect(ecarts).to.have.lengthOf(1);
        expect(ecarts[0]).to.include({ level: "error", component: "noyau" });
        expect(ecarts[0].data).to.deep.equal({ image_expected: IMAGE, expected_code_sha256: empreintePubliee.code_sha256, code_sha256: empreinteModifiee });
        expect(p2.lignes().findIndex((l) => l.event === "image_mismatch")).to.be.greaterThan(p2.lignes().findIndex((l) => l.event === "startup"));
        expect((await sante(c2.portSante)).corps.status).to.equal("ok");
      } finally {
        await arreter(p2);
      }
    });
  });
});
