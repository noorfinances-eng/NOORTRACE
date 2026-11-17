// Page de vérification (CT-6 §18) : corrections de la revue de sécurité
// interne (étape 8) dans un navigateur de chacun des trois moteurs
// (Chromium, Firefox, WebKit de Playwright 1.56.1), sur l'origine HTTPS
// fictive et sous les en-têtes d'EX-18.12 (outillage de
// test/verification-page-chromium.test.js, page d'entrée de Gecko comprise).
//
// - CT-6 EX-18.7 : l'archive hostile du relecteur (chemin pax de
//   100 000 composants, 393 octets de .tar.gz) : la page répond en moins
//   d'une seconde, refus r_chemin_long, « aucun rapport », aucun code.
// - : un fichier de 513 Mio (creux) est refusé d'après sa taille,
//   sans lecture ; un répertoire déposé de trop d'entrées, ou dont un chemin
//   est trop long, est refusé pendant le parcours, avant toute lecture.
// - CT-6 EX-18.9 : une page construite avec une autre version que l'artefact
//   affiche « vérification non faite » avec les deux versions.
// - : bouton « Arrêter » : pendant l'exécution (travailleur détruit
//   et recréé), pendant la lecture (rien d'envoyé) ; une vérification aboutit
//   ensuite.
// - CT-6 EX-8.6 (part page) : les chaînes d'un rapport, d'un énoncé, d'un
//   message d'erreur, d'une sortie d'erreur ou d'un chemin d'entrée qui
//   portent des caractères de commande, des séparateurs de ligne ou des
//   marques de direction sont affichées sous une forme visible.
//
// Chromium : en attente, avec un message, si Playwright ou Chromium manquent,
// si go1.27.3 manque ou si le binaire natif ne s'exécute pas dans /entrees ;
// sous NOORTRACE_EXIGER_CHROMIUM=1, ces conditions font échouer l'essai.
// Firefox et WebKit : la même suite quand Playwright les a, en attente sinon.
// NOORTRACE_RACINE : racine d'une copie du dépôt dont les sources de la page
// sont construites (mutants hors du dépôt) ; à défaut, le dépôt lui-même.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import zlib from "node:zlib";
import { execFileSync } from "node:child_process";
import { tar, zip } from "./fixtures/verification-page/archives-essai.mjs";
import { attendreArtefact, deplierOptions, lancer, lancerVerification, ouvrir } from "./fixtures/verification-page/navigateur.mjs";
import { RACINE, RacineNatif, VERSION, argumentsVerification, construireArtefact, construireNatif, enAttente, environnementGo, essaiRacineNatif, repertoireTemporaire, sha256 } from "./fixtures/verification-page/outils.mjs";

const EXIGER = process.env.NOORTRACE_EXIGER_CHROMIUM === "1";
const RACINE_SOURCES = process.env.NOORTRACE_RACINE ? path.resolve(process.env.NOORTRACE_RACINE) : RACINE;
const SOURCES = path.join(RACINE_SOURCES, "paquets", "verification-web", "src");
const VECTEURS = path.join(RACINE, "spec", "vecteurs");
const DOSSIER = path.join(VECTEURS, "ct-1", "dossiers", "valide-seq-7");
const Mio = 1024 * 1024;

const LIBELLES = vm.runInNewContext(`${fs.readFileSync(path.join(SOURCES, "page", "libelles-fr.js"), "utf8")}\nLIBELLES_FR;`, {});

/** Libellé rempli ; une clé absente (sources d'avant la correction) rend un texte qui ne vaut aucun affichage. */
function libelle(cle, parametres = {}) {
  if (!Object.hasOwn(LIBELLES, cle)) return `«libellé ${cle} absent»`;
  return LIBELLES[cle].replace(/\{([a-z0-9_]+)\}/g, (tout, k) => (Object.hasOwn(parametres, k) ? String(parametres[k]) : tout));
}

const refus = (raison, parametres = {}) => libelle("refus_archive", { raison: libelle(raison, parametres) });

/** Forme visible d'un caractère, celle que la page affiche. */
const visible = (c) => `\\u{${c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}}`;

/** Archive .tar.gz du relecteur (CT-6 EX-18.7) : un fichier dont le chemin pax a `n` composants « a ». */
function archiveProfonde(n) {
  return zlib.gzipSync(tar([{ nom: "d/dossier.json", donnees: "{}" }, { nom: "f", pax: { path: `d/${"a/".repeat(n)}f` }, donnees: "x" }]), { level: 9 });
}

/** construire.mjs des sources éprouvées, pour une version donnée. */
function construirePageVersion(wasm, sortie, version) {
  execFileSync(process.execPath, [path.join(SOURCES, "construire.mjs"), "--wasm", wasm, "--version", version, "--sortie", sortie], { encoding: "utf8", stdio: "pipe" });
}

/** Attend, au plus `ms`, que « Vérification en cours… » disparaisse ; ne lève pas : les assertions suivent. */
async function attendreFin(page, ms = 30000) {
  await page.waitForFunction(() => document.querySelector("#resultat-contenu .en-cours") === null, null, { timeout: ms }).catch(() => {});
}

/** Ce que la page affiche du résultat. */
async function lireResultat(page) {
  return page.evaluate(() => {
    const t = (s) => {
      const e = document.querySelector(s);
      return e === null ? null : e.textContent;
    };
    return {
      code: t("#code"),
      lisible: t("#rapport-lisible"),
      erreur: t("#sortie-erreur"),
      enonceFr: t("#enonce-fr"),
      enonceEn: t("#enonce-en"),
      message: t("#message-erreur"),
      commande: t("pre.commande"),
      aucunRapport: t(".aucun-rapport"),
      alerte: t("#resultat-contenu .alerte"),
      nonFaite: t(".non-faite"),
      cause: t("#resultat-contenu .cause"),
      dossierChoisi: t("#dossier-choisi"),
      tout: t("#resultat-contenu"),
    };
  });
}

/**
 * Travailleur de remplacement : répond à l'artefact par artefact_pret, et à
 * une vérification par `reponse` (fonction, en texte, qui rend le message),
 * ou jamais si `reponse` est null.
 */
function travailleurFactice(reponse) {
  return Buffer.from(`"use strict";
self.addEventListener("message", (ev) => {
  const m = ev.data;
  if (m.type === "artefact") self.postMessage({ type: "artefact_pret", version: ${JSON.stringify(VERSION)}, empreinte: "0x" + "0".repeat(64) });
  else if (m.type === "verifier") { const r = (${reponse ?? "() => null"})(m); if (r !== null) self.postMessage(r); }
});
`, "utf8");
}

for (const moteur of ["chromium", "firefox", "webkit"]) {
  describe(`page de vérification, revue de sécurité, dans ${moteur} (CT-6 EX-18.7, EX-18.9, EX-18.13 ; EX-8.6)`, function () {
    this.timeout(30 * 60 * 1000);
    const exige = EXIGER && moteur === "chromium";
    let navigateur = null;
    let attente = null;
    let dir;
    let construit;
    let racine;

    before(async function () {
      const env = environnementGo();
      if (env === null) {
        attente = "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH) : aucune page à servir";
        return;
      }
      const l = await lancer(moteur);
      if (!l.navigateur) {
        attente = l.raison;
        return;
      }
      navigateur = l.navigateur;
      dir = repertoireTemporaire(`noortrace-page-revue-${moteur}`);
      const wasm = path.join(dir, "wasm");
      const page = path.join(dir, "page");
      construireArtefact(wasm, env);
      construirePageVersion(wasm, page, VERSION);
      const natif = construireNatif(path.join(dir, "noortrace-verifier"), env);
      construit = { wasm, page, natif };
      const r = essaiRacineNatif(natif);
      if (r !== null) {
        attente = `binaire natif non exécutable dans /entrees (${r})`;
        return;
      }
      racine = new RacineNatif(path.join(dir, "racine"), natif);
    });

    after(async function () {
      if (navigateur) await navigateur.close();
      if (dir) fs.rmSync(dir, { recursive: true, force: true });
    });

    function pret(ctx) {
      if (attente === null) return true;
      if (exige) throw new Error(`essai ${moteur} exigé (NOORTRACE_EXIGER_CHROMIUM=1) : ${attente}`);
      enAttente(ctx, attente);
      return false;
    }

    /** Sorties du binaire natif pour valide-seq-7 sans option. */
    function natif() {
      const configuration = { ancres: false, entetes: false, exiger: null, langue: "fr", detail: false };
      racine.installer(DOSSIER, configuration);
      const args = argumentsVerification(configuration);
      return { args, sorties: [racine.executer(args), racine.executer([...args, "--json"])] };
    }

    async function ouvrirPage(options) {
      const o = await ouvrir(navigateur, construit.page, options);
      await o.page.goto("https://verification.example/index.html");
      await attendreArtefact(o.page);
      o.marquer();
      await deplierOptions(o.page);
      await o.page.click("#retirer-ancres");
      await o.page.click("#retirer-entetes");
      return o;
    }

    function ecrire(nom, octets) {
      const f = path.join(dir, `entree-${sha256(Buffer.from(nom)).slice(0, 8)}`, nom);
      fs.mkdirSync(path.dirname(f), { recursive: true });
      fs.writeFileSync(f, octets);
      return f;
    }

    it("archive hostile du relecteur (CT-6 EX-18.7) : chemin pax de 100 000 composants dans 393 octets de .tar.gz ; la page répond en moins d'une seconde avec le refus r_chemin_long, « aucun rapport », aucun code", async function () {
      if (!pret(this)) return;
      const octets = archiveProfonde(100000);
      expect(octets.length).to.be.lessThan(1024);
      const o = await ouvrirPage();
      try {
        await o.page.setInputFiles("#entree-archive", ecrire("hostile.tar.gz", octets));
        const t0 = Date.now();
        await lancerVerification(o.page);
        const ms = Date.now() - t0;
        const r = await lireResultat(o.page);
        // « d/ », 100 000 fois « a/ », « f » : 100 002 composants, 200 003 octets.
        expect(r.alerte).to.equal(refus("r_chemin_long", { composants: 100002, octets: 200003 }));
        expect(r.aucunRapport).to.equal(LIBELLES.aucun_rapport);
        expect([r.code, r.lisible, r.enonceFr, r.commande, r.nonFaite]).to.deep.equal([null, null, null, null, null]);
        expect(ms, `réponse en ${ms} ms`).to.be.lessThan(1000);
        expect(await o.page.isDisabled("#verifier")).to.equal(false);
        expect(o.requetesDepuisMarque()).to.deep.equal([]);
      } finally {
        await o.fermer();
      }
    });

    it("fichier d'archive de 513 Mio (creux) : refusé d'après sa taille déclarée, r_fichier_trop_gros, « aucun rapport » ; un .zip de 32 Mio dont un chemin fait 65 composants : r_chemin_long (CT-6 EX-18.7)", async function () {
      if (!pret(this)) return;
      const creux = ecrire("creux.tar", Buffer.alloc(0));
      fs.truncateSync(creux, 512 * Mio + 1);
      const o = await ouvrirPage();
      try {
        // Témoin de lecture : chaque appel de arrayBuffer() sur un fichier est compté (hors de la page).
        await o.page.evaluate(() => {
          globalThis.__lectures = 0;
          const originale = Blob.prototype.arrayBuffer;
          Blob.prototype.arrayBuffer = function () {
            globalThis.__lectures++;
            return originale.call(this);
          };
        });
        await o.page.setInputFiles("#entree-archive", creux);
        await lancerVerification(o.page);
        let r = await lireResultat(o.page);
        expect(r.alerte).to.equal(refus("r_fichier_trop_gros", { nom: "creux.tar" }));
        expect(r.aucunRapport).to.equal(LIBELLES.aucun_rapport);
        expect([r.code, r.lisible, r.nonFaite]).to.deep.equal([null, null, null]);
        expect(await o.page.evaluate(() => globalThis.__lectures), "le fichier de 513 Mio n'est pas lu").to.equal(0);
        // ZIP de CT-6 EX-18.7 : 32 Mio que nul en-tête ne désigne, admis sous la borne de 512 Mio ; le chemin trop long est refusé.
        const z = zip([{ nom: "d/dossier.json", donnees: Buffer.alloc(32 * Mio, 0x41), methode: 0 }, { nom: `d/${"a/".repeat(63)}f`, donnees: "x" }]);
        await o.page.setInputFiles("#entree-archive", ecrire("gap.zip", z));
        await lancerVerification(o.page);
        r = await lireResultat(o.page);
        expect(r.alerte).to.equal(refus("r_chemin_long", { composants: 65, octets: 129 }));
        expect(await o.page.evaluate(() => globalThis.__lectures), "le .zip de 32 Mio est lu une fois (témoin du compteur)").to.equal(1);
        expect(o.requetesDepuisMarque()).to.deep.equal([]);
      } finally {
        await o.fermer();
      }
    });

    it("répertoire déposé (CT-6 EX-18.7) : 10 000 entrées, le parcours s'arrête à la 4 097e sans lire un fichier de plus, refus r_trop_entrees ; un chemin de 65 composants, refus r_chemin_long avant toute lecture ; un répertoire ordinaire déposé est vérifié", async function () {
      if (!pret(this)) return;
      const o = await ouvrirPage();
      try {
        // Entrées de système de fichiers simulées derrière webkitGetAsEntry : le
        // parcours de la page (createReader, readEntries, file) est le vrai.
        const installerFaux = (forme) => o.page.evaluate((f) => {
          globalThis.__lectures = 0;
          const fichier = (nom) => ({ isDirectory: false, isFile: true, name: nom, file(ok) {
            globalThis.__lectures++;
            ok(new File(["{}"], nom));
          } });
          const repertoire = (nom, enfants) => ({ isDirectory: true, isFile: false, name: nom, createReader() {
            let lu = false;
            return { readEntries(ok) {
              if (lu) ok([]);
              else {
                lu = true;
                ok(enfants());
              }
            } };
          } });
          let racine;
          if (f === "beaucoup") {
            racine = repertoire("rep", () => Array.from({ length: 10000 }, (_, i) => fichier(`f-${i}`)));
          } else if (f === "profond") {
            const descendre = (n) => (n === 0 ? [fichier("f")] : [repertoire("a", () => descendre(n - 1))]);
            racine = repertoire("rep", () => descendre(64));
          } else {
            racine = repertoire("rep", () => [fichier("dossier.json")]);
          }
          DataTransferItem.prototype.webkitGetAsEntry = function () {
            return racine;
          };
        }, forme);
        const deposer = () => o.page.evaluate(() => {
          const dt = new DataTransfer();
          dt.items.add(new File([""], "rep"));
          document.body.dispatchEvent(new DragEvent("drop", { dataTransfer: dt, bubbles: true, cancelable: true }));
        });
        const attendreSuite = () => o.page.waitForFunction(() => document.querySelector(".aucun-rapport") !== null || document.getElementById("dossier-choisi").textContent !== "Aucun dossier choisi.", null, { timeout: 60000 });
        await installerFaux("beaucoup");
        await deposer();
        await attendreSuite();
        let r = await lireResultat(o.page);
        expect(r.alerte).to.equal(refus("r_trop_entrees"));
        expect(r.aucunRapport).to.equal(LIBELLES.aucun_rapport);
        expect(r.dossierChoisi).to.equal(LIBELLES.aucun_dossier);
        expect(await o.page.evaluate(() => globalThis.__lectures), "fichiers lus avant l'arrêt du parcours").to.equal(4096);
        await o.page.reload();
        await attendreArtefact(o.page);
        await installerFaux("profond");
        await deposer();
        await attendreSuite();
        r = await lireResultat(o.page);
        expect(r.alerte).to.equal(refus("r_chemin_long", { composants: 65, octets: 129 }));
        expect(r.dossierChoisi).to.equal(LIBELLES.aucun_dossier);
        expect(await o.page.evaluate(() => globalThis.__lectures), "fichiers lus").to.equal(0);
        // Témoin : un répertoire ordinaire déposé est choisi puis vérifié (code 1 : index « {} »).
        await o.page.reload();
        await attendreArtefact(o.page);
        await installerFaux("ordinaire");
        await deposer();
        await attendreSuite();
        r = await lireResultat(o.page);
        expect(r.dossierChoisi).to.equal(libelle("dossier_choisi_repertoire", { nom: "rep" }));
        await lancerVerification(o.page);
        r = await lireResultat(o.page);
        expect(r.code).to.match(/^Code de retour 1 /);
      } finally {
        await o.fermer();
      }
    });

    it("version de la page différente de celle du rapport (CT-6 EX-18.9, EX-18.10) : « vérification non faite » avec les deux versions, aucun rapport ni énoncé ; la page construite avec la version de l'artefact affiche le rapport", async function () {
      if (!pret(this)) return;
      const autre = path.join(dir, "page-0.1.1");
      construirePageVersion(construit.wasm, autre, "0.1.1");
      const o = await ouvrir(navigateur, autre);
      try {
        await o.page.goto("https://verification.example/index.html");
        const t = await attendreArtefact(o.page);
        expect(t).to.include("noortrace-verifier 0.1.1");
        await deplierOptions(o.page);
        await o.page.click("#retirer-ancres");
        await o.page.click("#retirer-entetes");
        await o.page.setInputFiles("#entree-repertoire", DOSSIER);
        await lancerVerification(o.page);
        const r = await lireResultat(o.page);
        expect(r.nonFaite).to.equal(LIBELLES.non_faite);
        expect(r.cause).to.equal(libelle("cause", { cause: libelle("cause_version_differente", { rapport: VERSION, page: "0.1.1" }) }));
        expect([r.code, r.lisible, r.enonceFr, r.enonceEn, r.message]).to.deep.equal([null, null, null, null, null]);
        expect(r.commande).to.equal("noortrace-verifier dossier --langue fr\nnoortrace-verifier dossier --langue fr --json");
      } finally {
        await o.fermer();
        fs.rmSync(autre, { recursive: true, force: true });
      }
      const n = natif();
      const o2 = await ouvrirPage();
      try {
        await o2.page.setInputFiles("#entree-repertoire", DOSSIER);
        await lancerVerification(o2.page);
        const r = await lireResultat(o2.page);
        expect(r.nonFaite).to.equal(null);
        expect(r.code).to.equal(libelle("code", { code: n.sorties[0].code, sens: LIBELLES[`code_${n.sorties[0].code}`] }));
      } finally {
        await o2.fermer();
      }
    });

    it("bouton « Arrêter » (CT-6 EX-18.9) : pendant l'exécution, le travailleur est détruit, « vérification non faite » avec la cause, un travailleur neuf reçoit l'artefact et la page redevient prête ; pendant la lecture, rien n'est envoyé ; une vérification aboutit ensuite", async function () {
      if (!pret(this)) return;
      // 1. Travailleur qui ne répond jamais à une vérification.
      const muet = await ouvrir(navigateur, construit.page, { remplacements: { "travailleur.js": travailleurFactice(null) } });
      try {
        await muet.page.goto("https://verification.example/index.html");
        await attendreArtefact(muet.page);
        muet.marquer();
        await deplierOptions(muet.page);
        await muet.page.click("#retirer-ancres");
        await muet.page.click("#retirer-entetes");
        await muet.page.setInputFiles("#entree-repertoire", DOSSIER);
        expect(await muet.page.isDisabled("#arreter"), "Arrêter inactif avant la vérification").to.equal(true);
        await muet.page.click("#verifier");
        await muet.page.waitForFunction(() => !document.getElementById("arreter").disabled, null, { timeout: 30000 });
        expect(await muet.page.textContent("#resultat-contenu .en-cours")).to.equal(LIBELLES.en_cours);
        await muet.page.click("#arreter");
        await attendreFin(muet.page);
        const r = await lireResultat(muet.page);
        expect(r.nonFaite, "après « Arrêter »").to.equal(LIBELLES.non_faite);
        expect(r.cause).to.equal(libelle("cause", { cause: libelle("cause_arret") }));
        expect([r.code, r.lisible, r.enonceFr, r.aucunRapport]).to.deep.equal([null, null, null, null]);
        // Un travailleur neuf a reçu l'artefact : la page redevient prête.
        await muet.page.waitForFunction(() => !document.getElementById("verifier").disabled, null, { timeout: 30000 });
        expect(await muet.page.textContent("#artefact")).to.equal(libelle("artefact_pret", { version: VERSION, empreinte: `0x${"0".repeat(64)}` }));
        expect(await muet.page.isDisabled("#arreter")).to.equal(true);
        // La seule requête depuis le chargement : travailleur.js, pour le travailleur neuf (EX-18.11, révision demandée).
        const requetes = muet.requetesDepuisMarque();
        expect(requetes.every((q) => q.url === "https://verification.example/travailleur.js" && q.methode === "GET"), JSON.stringify(requetes)).to.equal(true);
        expect(requetes.length).to.be.at.most(1);
        // Le travailleur détruit n'a plus voix : une seconde vérification repasse par le neuf, et s'arrête de même.
        await muet.page.click("#verifier");
        await muet.page.waitForFunction(() => !document.getElementById("arreter").disabled, null, { timeout: 30000 });
        await muet.page.click("#arreter");
        await attendreFin(muet.page);
        expect((await lireResultat(muet.page)).nonFaite, "second arrêt").to.equal(LIBELLES.non_faite);
        await muet.page.waitForFunction(() => !document.getElementById("verifier").disabled, null, { timeout: 30000 });
      } finally {
        await muet.fermer();
      }
      // 2. Travailleur réel : arrêt demandé pendant la lecture du dossier (avant
      //    l'envoi), puis une vérification complète, égale au binaire.
      const n = natif();
      const o = await ouvrirPage();
      try {
        await o.page.setInputFiles("#entree-repertoire", DOSSIER);
        await o.page.evaluate(() => {
          document.getElementById("verifier").click();
          document.getElementById("arreter").click();
        });
        await o.page.waitForFunction(() => document.querySelector("#resultat-contenu .en-cours") === null, null, { timeout: 60000 });
        let r = await lireResultat(o.page);
        expect(r.nonFaite).to.equal(LIBELLES.non_faite);
        expect(r.cause).to.equal(libelle("cause", { cause: libelle("cause_arret") }));
        expect(r.commande, "rien n'a été envoyé au travailleur").to.equal(null);
        expect(await o.page.textContent("#artefact")).to.equal(libelle("artefact_pret", { version: VERSION, empreinte: `0x${sha256(fs.readFileSync(path.join(construit.page, "noortrace-verifier.wasm")))}` }));
        expect(await o.page.isDisabled("#verifier")).to.equal(false);
        await lancerVerification(o.page);
        r = await lireResultat(o.page);
        expect(r.nonFaite).to.equal(null);
        expect(r.code).to.equal(libelle("code", { code: n.sorties[0].code, sens: LIBELLES[`code_${n.sorties[0].code}`] }));
        expect(r.lisible).to.equal(n.sorties[0].sortie.toString("utf8"));
        expect(o.requetesDepuisMarque()).to.deep.equal([]);
      } finally {
        await o.fermer();
      }
    });

    it("chaînes hostiles (CT-6 EX-8.6, part page) : énoncés, message d'erreur, rapport lisible, sortie d'erreur et chemin d'un refus portant retour chariot, échappement, U+2028 et marque de direction sont affichés sous la forme visible \\u{…}, sans un seul de ces caractères dans la zone de résultat", async function () {
      if (!pret(this)) return;
      const hostile = "Résultat : VALIDE\r\u001b[2K[réussi]‮ faux ligne\u0085suite";
      const attendu = `Résultat : VALIDE${visible("\r")}${visible("\u001b")}[2K[réussi]${visible("‮")} faux${visible(" ")}ligne${visible("\u0085")}suite`;
      const interdits = /[\u{0}-\u{8}\u{B}-\u{1F}\u{7F}-\u{9F}\u{61C}\u{200E}\u{200F}\u{2028}\u{2029}\u{202A}-\u{202E}\u{2066}-\u{2069}]/u;
      const reponse = (code) => `(m) => {
        const e = new TextEncoder();
        const json = ${code === 2
    ? `{ exit_code: 2, verifier: { version: ${JSON.stringify(VERSION)} }, error: { message: ${JSON.stringify(hostile)} } }`
    : `{ exit_code: 0, verifier: { version: ${JSON.stringify(VERSION)} }, statement: { fr: ${JSON.stringify(hostile)}, en: ${JSON.stringify(`en ${hostile}`)} } }`};
        return { type: "resultat", executions: [
          { arguments: ["noortrace-verifier", "dossier", "--langue", "fr"], code: ${code}, sortie: e.encode(${JSON.stringify(`rapport ${hostile}\n`)}), erreur: e.encode(${JSON.stringify(`avertissement ${hostile}`)}) },
          { arguments: ["noortrace-verifier", "dossier", "--langue", "fr", "--json"], code: ${code}, sortie: e.encode(JSON.stringify(json)), erreur: new Uint8Array(0) },
        ] };
      }`;
      for (const code of [0, 2]) {
        const o = await ouvrir(navigateur, construit.page, { remplacements: { "travailleur.js": travailleurFactice(reponse(code)) } });
        try {
          await o.page.goto("https://verification.example/index.html");
          await attendreArtefact(o.page);
          await deplierOptions(o.page);
          await o.page.click("#retirer-ancres");
          await o.page.click("#retirer-entetes");
          await o.page.setInputFiles("#entree-repertoire", DOSSIER);
          await lancerVerification(o.page);
          const r = await lireResultat(o.page);
          expect(r.nonFaite, `code ${code}`).to.equal(null);
          expect(r.lisible, `code ${code}`).to.equal(`rapport ${attendu}\n`);
          expect(r.erreur, `code ${code}`).to.equal(`avertissement ${attendu}`);
          if (code === 2) {
            expect(r.message).to.equal(attendu);
            expect(r.enonceFr).to.equal(null);
          } else {
            expect(r.enonceFr).to.equal(attendu);
            expect(r.enonceEn).to.equal(`en ${attendu}`);
          }
          expect(interdits.test(r.tout), `code ${code} : zone de résultat`).to.equal(false);
          // Chemin d'entrée hostile dans la raison d'un refus.
          const a = zip([{ nom: `/d/x${hostile}`, donnees: "{}", drapeaux: 0x0800 }]);
          await o.page.setInputFiles("#entree-archive", ecrire("hostile-chemin.zip", a));
          await lancerVerification(o.page);
          const s = await lireResultat(o.page);
          expect(s.alerte).to.equal(refus("r_absolu", { chemin: `/d/x${attendu}` }));
          expect(interdits.test(s.tout), `code ${code} : refus`).to.equal(false);
        } finally {
          await o.fermer();
        }
      }
    });
  });
}
