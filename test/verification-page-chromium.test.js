// Page de vérification (CT-6 §18, révision 0.6) dans un navigateur (EX-18.13),
// par Playwright, sur une origine HTTPS fictive servie par interception avec
// les en-têtes d'en-tetes.json (EX-18.12) ; fuseau horaire Asia/Kathmandu
// (UTC+5:45), sans effet sur le rapport.
//
// - En-têtes présents ; phrase fixe, version et empreinte ; langue anglaise.
// - Échantillon fixé (codes 0, 1, 2 et 3), chaque dossier comme répertoire et
//   sous chacune des sept recettes d'archive d'EX-18.13 : rapport lisible,
//   code, énoncés ou message d'erreur, sortie d'erreur affichés égaux à ceux
//   du binaire natif exécuté dans /entrees ; dans le moteur, octet pour octet,
//   par le travailleur de la page.
// - Chaque refus d'archive d'EX-18.7 : la raison et « aucun rapport ».
// - Aucune requête après le chargement, aucune violation de politique ;
//   stockage vide, aucun service worker, aucun cookie.
// - TA-101 : artefact altéré d'un octet sous un travailleur.js intact : non
//   compilé, aucun rapport ; le mutant du travailleur sans le contrôle de
//   l'empreinte rend un rapport (tué).
//
// Chromium : en attente, avec un message, si Playwright ou Chromium manquent,
// si go1.27.3 manque (rien à servir) ou si le binaire natif ne s'exécute pas
// dans /entrees ; sous NOORTRACE_EXIGER_CHROMIUM=1, ces mêmes conditions font
// échouer l'essai. Firefox et WebKit : la même suite quand Playwright les a,
// en attente sinon (jamais exigés ici).

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { casDeRefus, chargerArchives } from "./fixtures/verification-page/archives-essai.mjs";
import { attendreArtefact, lancer, lancerVerification, ouvrir } from "./fixtures/verification-page/navigateur.mjs";
import { ANCRES, CHAINE, RACINE, RacineNatif, VERSION, argumentsVerification, construireTout, enAttente, environnementGo, essaiRacineNatif, fichiersDe, repertoireTemporaire, sha256 } from "./fixtures/verification-page/outils.mjs";
import { outilsArchivesDisponibles, recettesArchives } from "./fixtures/verification-page/recettes.mjs";

const EXIGER = process.env.NOORTRACE_EXIGER_CHROMIUM === "1";
const VECTEURS = path.join(RACINE, "spec", "vecteurs");
const LIBELLES = vm.runInNewContext(`${fs.readFileSync(path.join(RACINE, "paquets", "verification-web", "src", "page", "libelles-fr.js"), "utf8")}\nLIBELLES_FR;`, {});
const LIBELLES_EN = vm.runInNewContext(`${fs.readFileSync(path.join(RACINE, "paquets", "verification-web", "src", "page", "libelles-en.js"), "utf8")}\nLIBELLES_EN;`, {});

// Message que Chromium 141 écrit pour la valeur d'Integrity-Policy d'EX-18.12 :
// la destination « style » n'y est pas prise en charge. Ce n'est pas une
// violation de politique ; il est relevé à part.
const AVIS_INTEGRITY_POLICY = "The Integrity-Policy destination 'style' is not supported.";

/** Échantillon fixé : au moins un dossier par code 0, 1, 2 et 3. */
const ECHANTILLON = [
  { titre: "code 0, dossier CT-1", dossier: "ct-1/dossiers/valide-seq-7", options: {}, code: 0 },
  { titre: "code 0, dossier CT-6 aux huit contrôles, ancres et chaîne", dossier: "ct-6/dossiers/valide-seq-7-complet", options: { ancres: true, entetes: true }, code: 0 },
  { titre: "code 1", dossier: "ct-1/dossiers/invalide-hash-faux", options: { langue: "en" }, code: 1 },
  { titre: "code 2", dossier: "ct-1/dossiers/illisible-index-non-json", options: {}, code: 2 },
  { titre: "code 3, --exiger 4,5,8, --detail, rapport anglais", dossier: "ct-1/dossiers/valide-seq-7", options: { exiger: [4, 5, 8], detail: true, langue: "en" }, code: 3 },
];

function libelle(table, cle, parametres = {}) {
  return table[cle].replace(/\{([a-z0-9_]+)\}/g, (tout, k) => (Object.hasOwn(parametres, k) ? String(parametres[k]) : tout));
}

/** Choisit les options de l'échantillon dans la page. */
async function choisirOptions(page, o) {
  if (o.ancres) await page.setInputFiles("#entree-ancres", ANCRES);
  else await page.click("#retirer-ancres");
  if (o.entetes) await page.setInputFiles("#entree-entetes", CHAINE);
  else await page.click("#retirer-entetes");
  for (let n = 1; n <= 8; n++) await page.setChecked(`input[name="exiger"][value="${n}"]`, (o.exiger ?? []).includes(n));
  await page.selectOption("#langue-rapport", o.langue ?? "fr");
  await page.setChecked("#detail", o.detail === true);
}

function configuration(o) {
  return { ancres: o.ancres === true, entetes: o.entetes === true, exiger: o.exiger ? o.exiger.join(",") : null, langue: o.langue ?? "fr", detail: o.detail === true };
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
      affirmation: t("#aucune-affirmation"),
      commande: t("pre.commande"),
      aucunRapport: t(".aucun-rapport"),
      alerte: t("#resultat-contenu .alerte"),
      nonFaite: t(".non-faite"),
    };
  });
}

/** Compare l'affichage au binaire natif (EX-18.9, EX-18.10). */
function comparer(affiche, natif, args, quoi) {
  const [lisible, json] = natif;
  expect(lisible.code, quoi).to.equal(json.code);
  const rapport = JSON.parse(json.sortie.toString("utf8"));
  expect(affiche.nonFaite, quoi).to.equal(null);
  expect(affiche.aucunRapport, quoi).to.equal(null);
  expect(affiche.commande, quoi).to.equal(`noortrace-verifier ${args.join(" ")}\nnoortrace-verifier ${args.join(" ")} --json`);
  expect(affiche.code, quoi).to.equal(libelle(LIBELLES, "code", { code: lisible.code, sens: LIBELLES[`code_${lisible.code}`] }));
  const sortie = lisible.sortie.toString("utf8");
  expect(affiche.lisible, quoi).to.equal(sortie === "" ? null : sortie);
  const erreur = lisible.erreur.toString("utf8");
  expect(affiche.erreur, quoi).to.equal(erreur === "" ? LIBELLES.sortie_erreur_vide : erreur);
  if (lisible.code === 2) {
    expect(affiche.message, quoi).to.equal(rapport.error.message);
    expect(affiche.affirmation, quoi).to.equal(LIBELLES.aucune_affirmation);
    expect([affiche.enonceFr, affiche.enonceEn], quoi).to.deep.equal([null, null]);
  } else {
    expect([affiche.enonceFr, affiche.enonceEn], quoi).to.deep.equal([rapport.statement.fr, rapport.statement.en]);
    expect([affiche.message, affiche.affirmation], quoi).to.deep.equal([null, null]);
  }
}

for (const moteur of ["chromium", "firefox", "webkit"]) {
  describe(`page de vérification dans ${moteur} (CT-6 EX-18.13, TE-23, TA-101)`, function () {
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
      dir = repertoireTemporaire(`noortrace-page-${moteur}`);
      construit = construireTout(dir, env);
      const r = essaiRacineNatif(construit.natif);
      if (r !== null) {
        attente = `binaire natif non exécutable dans /entrees (${r})`;
        return;
      }
      racine = new RacineNatif(path.join(dir, "racine"), construit.natif);
    });

    after(async function () {
      if (navigateur) await navigateur.close();
      if (dir) fs.rmSync(dir, { recursive: true, force: true });
    });

    /** Met l'essai en attente, ou le fait échouer sous NOORTRACE_EXIGER_CHROMIUM=1. */
    function pret(ctx) {
      if (attente === null) return true;
      if (exige) throw new Error(`essai ${moteur} exigé (NOORTRACE_EXIGER_CHROMIUM=1) : ${attente}`);
      enAttente(ctx, attente);
      return false;
    }

    /** Sorties du binaire natif pour un dossier et une configuration. */
    function natif(dossier, o) {
      racine.installer(dossier, configuration(o));
      const args = argumentsVerification(configuration(o));
      return { args, sorties: [racine.executer(args), racine.executer([...args, "--json"])] };
    }

    it("en-têtes d'EX-18.12 présents ; phrase fixe, version et empreinte de l'artefact ; page en anglais au choix", async function () {
      if (!pret(this)) return;
      const o = await ouvrir(navigateur, construit.page);
      try {
        await o.page.goto("https://verification.example/index.html");
        const artefact = await attendreArtefact(o.page);
        const empreinte = `0x${sha256(fs.readFileSync(path.join(construit.page, "noortrace-verifier.wasm")))}`;
        expect(artefact).to.equal(libelle(LIBELLES, "artefact_pret", { version: VERSION, empreinte }));
        expect(await o.page.textContent("#phrase-fixe")).to.equal(libelle(LIBELLES, "phrase_fixe", { version: VERSION }));
        const entetes = JSON.parse(fs.readFileSync(path.join(construit.page, "en-tetes.json"), "utf8"));
        for (const f of ["index.html", "page.css", "page.js", "verificateur-wasm.js", "travailleur.js"]) {
          const recus = o.reponses.get(`https://verification.example/${f}`);
          expect(recus, f).to.not.equal(undefined);
          for (const [k, v] of Object.entries(entetes[f])) {
            // WebKit (Playwright 1.56.1) rend Content-Type sans ses paramètres (« ; charset=utf-8 ») : constaté le
            // 2026-11-11 ; l'en-tête servi est celui de la table, seul son relevé par le moteur diffère.
            const attendu = moteur === "webkit" && k === "Content-Type" ? v.split(";")[0] : v;
            expect(recus[k.toLowerCase()], `${f} ${k}`).to.equal(attendu);
          }
          expect(recus).to.not.have.property("set-cookie");
          expect(recus).to.not.have.property("access-control-allow-origin");
        }
        // Exactement les cinq fichiers, une fois chacun.
        expect(o.requetes.map((r) => r.url).sort()).to.deep.equal(["index.html", "page.css", "page.js", "travailleur.js", "verificateur-wasm.js"].map((f) => `https://verification.example/${f}`));
        await o.page.click("#autre-langue");
        expect(await o.page.getAttribute("html", "lang")).to.equal("en");
        expect(await o.page.textContent("#phrase-fixe")).to.equal(libelle(LIBELLES_EN, "phrase_fixe", { version: VERSION }));
        expect(await o.page.textContent("#artefact")).to.equal(libelle(LIBELLES_EN, "artefact_pret", { version: VERSION, empreinte }));
        expect(await o.page.inputValue("#langue-rapport")).to.equal("en");
        expect(await o.page.title()).to.equal(LIBELLES_EN.titre);
        await o.page.click("#autre-langue");
        expect(await o.page.textContent("#phrase-fixe")).to.equal(libelle(LIBELLES, "phrase_fixe", { version: VERSION }));
      } finally {
        await o.fermer();
      }
    });

    for (const e of ECHANTILLON) {
      it(`échantillon, ${e.titre} : comme répertoire et sous chaque recette d'archive, rapport affiché égal à celui du binaire ; octet pour octet dans le travailleur`, async function () {
        if (!pret(this)) return;
        const manque = outilsArchivesDisponibles();
        if (manque) {
          if (exige) throw new Error(`essai exigé : ${manque}`);
          return enAttente(this, manque);
        }
        const dossier = path.join(VECTEURS, e.dossier);
        const n = natif(dossier, e.options);
        expect(n.sorties[0].code, "code du binaire").to.equal(e.code);
        const archives = recettesArchives(dossier, fs.mkdtempSync(path.join(dir, "archives-")));
        // Une copie .tgz de la dernière recette : l'autre nom de la même forme.
        const tgz = path.join(path.dirname(archives[6].chemin), "d.tgz");
        fs.copyFileSync(archives[6].chemin, tgz);
        archives.push({ recette: "tar pax | gzip -n, nommée .tgz", fichier: "d.tgz", chemin: tgz });
        const o = await ouvrir(navigateur, construit.page);
        try {
          await o.page.goto("https://verification.example/index.html");
          await attendreArtefact(o.page);
          o.marquer();
          await choisirOptions(o.page, e.options);
          // Comme répertoire.
          await o.page.setInputFiles("#entree-repertoire", dossier);
          expect(await o.page.textContent("#dossier-choisi")).to.equal(libelle(LIBELLES, "nom_dossier_repertoire", { nom: path.basename(dossier) }));
          await lancerVerification(o.page);
          comparer(await lireResultat(o.page), n.sorties, n.args, `${e.dossier} répertoire`);
          // Sous chaque recette.
          for (const a of archives) {
            const nommee = path.join(path.dirname(a.chemin), `${path.basename(a.chemin)}.d`, a.fichier);
            fs.mkdirSync(path.dirname(nommee), { recursive: true });
            fs.renameSync(a.chemin, nommee);
            await o.page.setInputFiles("#entree-archive", nommee);
            expect(await o.page.textContent("#dossier-choisi")).to.equal(libelle(LIBELLES, "nom_dossier_archive", { nom: a.fichier }));
            await lancerVerification(o.page);
            comparer(await lireResultat(o.page), n.sorties, n.args, `${e.dossier} ${a.recette}`);
          }
          // Octet pour octet, dans le moteur : le travailleur de la page reçoit
          // le même message que de la page, et ses sorties sont relevées.
          const w = o.page.workers()[0];
          const fichiers = fichiersDe(dossier).map((f) => ({ chemin: `dossier/${f.chemin}`, b64: f.octets.toString("base64") }));
          if (e.options.ancres) fichiers.push({ chemin: "ancres.json", b64: fs.readFileSync(ANCRES).toString("base64") });
          if (e.options.entetes) fichiers.push({ chemin: "entetes-bitcoin.json", b64: fs.readFileSync(CHAINE).toString("base64") });
          const resultat = await w.evaluate(({ fichiers: liste, options }) => {
            const octets = (b64) => {
              const s = atob(b64);
              const u = new Uint8Array(s.length);
              for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
              return u.buffer;
            };
            const enBase64 = (u) => {
              let s = "";
              for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
              return btoa(s);
            };
            const message = { type: "verifier", fichiers: liste.map((f) => ({ chemin: f.chemin, octets: octets(f.b64) })), repertoires: [], options };
            return new Promise((resoudre) => {
              const envoi = self.postMessage;
              self.postMessage = (m) => {
                self.postMessage = envoi;
                if (m.type !== "resultat") resoudre(m);
                else resoudre({ type: m.type, executions: m.executions.map((x) => ({ arguments: x.arguments, code: x.code, sortie: enBase64(x.sortie), erreur: enBase64(x.erreur) })) });
              };
              self.dispatchEvent(new MessageEvent("message", { data: message }));
            });
          }, { fichiers, options: configuration(e.options) });
          expect(resultat.type).to.equal("resultat");
          for (let i = 0; i < 2; i++) {
            const x = resultat.executions[i];
            expect(x.code, `exécution ${i}`).to.equal(n.sorties[i].code);
            expect(Buffer.compare(Buffer.from(x.sortie, "base64"), n.sorties[i].sortie), `sortie ${i}`).to.equal(0);
            expect(Buffer.compare(Buffer.from(x.erreur, "base64"), n.sorties[i].erreur), `erreur ${i}`).to.equal(0);
          }
          expect(o.requetesDepuisMarque()).to.deep.equal([]);
        } finally {
          await o.fermer();
        }
      });
    }

    it("chaque refus d'archive d'EX-18.7 : la raison, « aucun rapport », aucun code ; dépôt d'une archive vérifiée, de deux éléments refusé", async function () {
      if (!pret(this)) return;
      const { lireArchive } = chargerArchives();
      const o = await ouvrir(navigateur, construit.page);
      try {
        await o.page.goto("https://verification.example/index.html");
        await attendreArtefact(o.page);
        o.marquer();
        let i = 0;
        for (const c of casDeRefus()) {
          let refus = null;
          try {
            await lireArchive(c.fichier, new Uint8Array(c.octets));
          } catch (x) {
            refus = x;
          }
          const parametres = { ...refus.parametres };
          if (parametres.type !== undefined) parametres.type = libelle(LIBELLES, parametres.type, { type: parametres.code ?? "?" });
          if (parametres.detail !== undefined) parametres.detail = libelle(LIBELLES, parametres.detail, parametres);
          const attendu = libelle(LIBELLES, "refus_archive", { raison: libelle(LIBELLES, refus.raison, parametres) });
          const f = path.join(dir, `refus-${i++}`, c.fichier);
          fs.mkdirSync(path.dirname(f), { recursive: true });
          fs.writeFileSync(f, c.octets);
          await o.page.setInputFiles("#entree-archive", f);
          await lancerVerification(o.page);
          const r = await lireResultat(o.page);
          expect(r.alerte, c.titre).to.equal(attendu);
          expect(r.aucunRapport, c.titre).to.equal(LIBELLES.aucun_rapport);
          expect([r.code, r.lisible, r.enonceFr, r.commande], c.titre).to.deep.equal([null, null, null, null]);
          fs.rmSync(path.dirname(f), { recursive: true, force: true });
        }
        // Dépôt d'une archive (élément de fichier ; un répertoire déposé ne se simule pas).
        const archive = recettesArchives(path.join(VECTEURS, "ct-1/dossiers/valide-seq-7"), fs.mkdtempSync(path.join(dir, "depot-")))[0];
        const deposer = (fichiers) => o.page.evaluate((liste) => {
          const dt = new DataTransfer();
          for (const { nom, b64 } of liste) {
            const s = atob(b64);
            const u = new Uint8Array(s.length);
            for (let k = 0; k < s.length; k++) u[k] = s.charCodeAt(k);
            dt.items.add(new File([u], nom));
          }
          document.body.dispatchEvent(new DragEvent("drop", { dataTransfer: dt, bubbles: true, cancelable: true }));
        }, fichiers);
        await o.page.click("#retirer-ancres");
        await o.page.click("#retirer-entetes");
        await deposer([{ nom: "depose.zip", b64: fs.readFileSync(archive.chemin).toString("base64") }]);
        await o.page.waitForFunction(() => document.getElementById("dossier-choisi").textContent.includes("depose.zip"));
        await o.page.selectOption("#langue-rapport", "fr");
        for (let n = 1; n <= 8; n++) await o.page.setChecked(`input[name="exiger"][value="${n}"]`, false);
        await o.page.setChecked("#detail", false);
        await lancerVerification(o.page);
        const n = natif(path.join(VECTEURS, "ct-1/dossiers/valide-seq-7"), {});
        comparer(await lireResultat(o.page), n.sorties, n.args, "archive déposée");
        await deposer([{ nom: "a.zip", b64: "" }, { nom: "b.zip", b64: "" }]);
        await o.page.waitForFunction(() => document.querySelector(".aucun-rapport") !== null);
        const r = await lireResultat(o.page);
        expect(r.alerte).to.equal(libelle(LIBELLES, "refus_archive", { raison: LIBELLES.r_plusieurs }));
        expect(await o.page.isDisabled("#verifier")).to.equal(true);
        expect(o.requetesDepuisMarque()).to.deep.equal([]);
      } finally {
        await o.fermer();
      }
    });

    it("répertoire choisi de 4 097 fichiers (révision 0.7 d'EX-18.7) : refusé avant toute lecture, avec la raison des archives, « aucun rapport », aucun code", async function () {
      if (!pret(this)) return;
      const rep = path.join(dir, "repertoire-4097");
      fs.mkdirSync(rep, { recursive: true });
      fs.writeFileSync(path.join(rep, "dossier.json"), "{}");
      for (let k = 0; k < 4096; k++) fs.writeFileSync(path.join(rep, `f-${String(k).padStart(4, "0")}.json`), "{}");
      const o = await ouvrir(navigateur, construit.page);
      try {
        await o.page.goto("https://verification.example/index.html");
        await attendreArtefact(o.page);
        o.marquer();
        await o.page.setInputFiles("#entree-repertoire", rep);
        await lancerVerification(o.page);
        const r = await lireResultat(o.page);
        expect(r.alerte).to.equal(libelle(LIBELLES, "refus_archive", { raison: LIBELLES.r_trop_entrees }));
        expect(r.aucunRapport).to.equal(LIBELLES.aucun_rapport);
        expect([r.code, r.lisible, r.enonceFr, r.commande]).to.deep.equal([null, null, null, null]);
        expect(o.requetesDepuisMarque()).to.deep.equal([]);
      } finally {
        await o.fermer();
        fs.rmSync(rep, { recursive: true, force: true });
      }
    });

    it("aucune requête après le chargement, aucune violation de politique (témoin : un script en ligne ajouté est signalé) ; stockage vide, aucun service worker, aucun cookie", async function () {
      if (!pret(this)) return;
      // Témoin : le relevé voit une violation quand il y en a une.
      const html = fs.readFileSync(path.join(construit.page, "index.html"), "utf8").replace("</main>", "</main>\n<script>document.title = 'x';</script>");
      const t = await ouvrir(navigateur, construit.page, { remplacements: { "index.html": Buffer.from(html) } });
      try {
        await t.page.goto("https://verification.example/index.html");
        await attendreArtefact(t.page);
        const v = await t.violations();
        expect(v.some((x) => x.startsWith("script-src")), JSON.stringify(v)).to.equal(true);
        expect(await t.page.title()).to.not.equal("x");
      } finally {
        await t.fermer();
      }
      const o = await ouvrir(navigateur, construit.page);
      try {
        await o.page.goto("https://verification.example/index.html");
        await attendreArtefact(o.page);
        o.marquer();
        await choisirOptions(o.page, { ancres: true, entetes: true, exiger: [4, 5, 8], detail: true });
        await o.page.setInputFiles("#entree-repertoire", path.join(VECTEURS, "ct-6/dossiers/valide-seq-7-complet"));
        await lancerVerification(o.page);
        expect(await o.page.textContent("#code")).to.match(/^Code de retour 0 /);
        await o.page.waitForTimeout(2000);
        expect(o.requetesDepuisMarque(), "requêtes après le chargement").to.deep.equal([]);
        expect(o.requetes.every((r) => r.methode === "GET" && r.corps === null)).to.equal(true);
        // Gecko (Firefox de Playwright 1.56.1) demande de lui-même /favicon.ico, hors de la page : default-src 'none'
        // la bloque avant tout envoi (aucune requête relevée) et il la signale ; constaté le 2026-11-11, consigné à part
        // (CT-6 EX-18.13, révision 0.7), admis pour ce moteur et cette adresse seulement.
        const iconeGecko = (v) => moteur === "firefox" && v === "img-src https://verification.example/favicon.ico";
        const avisIconeGecko = (m) => moteur === "firefox" && m.includes("https://verification.example/favicon.ico") && m.includes("FaviconLoader.sys.mjs");
        expect((await o.violations()).filter((v) => !iconeGecko(v))).to.deep.equal([]);
        // Un moteur sans types de confiance ignore les deux dernières directives de la politique du document (CT-6
        // EX-18.12) ; Gecko le dit par un avertissement pour chacune : admis, et seulement s'il n'offre pas trustedTypes.
        const sansTypesDeConfiance = !(await o.page.evaluate(() => typeof globalThis.trustedTypes === "object" && globalThis.trustedTypes !== null));
        const directiveInconnue = (m) => sansTypesDeConfiance && /^warning : .*Content-Security-Policy: Couldn.t process unknown directive .(require-trusted-types-for|trusted-types)./.test(m);
        const autres = o.messages.filter((m) => !m.endsWith(AVIS_INTEGRITY_POLICY) && !directiveInconnue(m) && !avisIconeGecko(m));
        expect(autres, autres.join("\n")).to.deep.equal([]);
        const stockage = await o.page.evaluate(async () => ({
          local: localStorage.length,
          session: sessionStorage.length,
          cookie: document.cookie,
          bases: indexedDB.databases ? (await indexedDB.databases()).length : 0,
          caches: (await caches.keys()).length,
          serviceWorkers: navigator.serviceWorker ? (await navigator.serviceWorker.getRegistrations()).length : 0,
        }));
        expect(stockage).to.deep.equal({ local: 0, session: 0, cookie: "", bases: 0, caches: 0, serviceWorkers: 0 });
        expect(await o.contexte.cookies()).to.deep.equal([]);
      } finally {
        await o.fermer();
      }
    });

    it("« vérification non faite », sans rapport ni énoncé : compilation refusée par la politique du travailleur ; codes différents des deux exécutions (EX-18.9, EX-18.12)", async function () {
      if (!pret(this)) return;
      const entetes = JSON.parse(fs.readFileSync(path.join(construit.page, "en-tetes.json"), "utf8"));
      // 1. Politique du travailleur sans 'wasm-unsafe-eval' : celle qu'un
      //    navigateur appliquerait s'il prenait la politique du document.
      const copie = path.join(dir, "page-sans-wasm");
      fs.cpSync(construit.page, copie, { recursive: true });
      entetes["travailleur.js"]["Content-Security-Policy"] = "default-src 'none'; script-src 'self'";
      fs.writeFileSync(path.join(copie, "en-tetes.json"), JSON.stringify(entetes));
      const o = await ouvrir(navigateur, copie);
      try {
        await o.page.goto("https://verification.example/index.html");
        const t = await attendreArtefact(o.page);
        if (moteur === "webkit") {
          // WebKit (Playwright 1.56.1) compile l'artefact sous cette politique du travailleur : le refus de compilation
          // n'y est pas observable (constaté le 2026-11-11, CT-6 EX-18.13, révision 0.7) ; la page reste utilisable.
          expect(t).to.equal(libelle(LIBELLES, "artefact_pret", { version: VERSION, empreinte: `0x${sha256(fs.readFileSync(path.join(copie, "noortrace-verifier.wasm")))}` }));
        } else {
          expect(t.startsWith(`${LIBELLES.non_faite}. ${libelle(LIBELLES, "cause", { cause: "compilation refusée : " })}`), t).to.equal(true);
          await o.page.setInputFiles("#entree-repertoire", path.join(VECTEURS, "ct-1/dossiers/valide-seq-7"));
          expect(await o.page.isDisabled("#verifier")).to.equal(true);
          expect(await o.page.isHidden("#resultat")).to.equal(true);
        }
      } finally {
        await o.fermer();
        fs.rmSync(copie, { recursive: true, force: true });
      }
      // 2. Travailleur dont la seconde exécution prend un autre argument : les
      //    deux codes diffèrent (0 et 3).
      const travailleur = fs.readFileSync(path.join(construit.page, "travailleur.js"), "utf8");
      const seconde = 'executions.push(await executer([...lisible, "--json"]));';
      expect(travailleur.split(seconde)).to.have.length(2);
      const m = await ouvrir(navigateur, construit.page, { remplacements: { "travailleur.js": Buffer.from(travailleur.replace(seconde, 'executions.push(await executer([...lisible, "--json", "--exiger", "4"]));')) } });
      try {
        await m.page.goto("https://verification.example/index.html");
        await attendreArtefact(m.page);
        await m.page.setInputFiles("#entree-repertoire", path.join(VECTEURS, "ct-1/dossiers/valide-seq-7"));
        await lancerVerification(m.page);
        const r = await lireResultat(m.page);
        expect(r.nonFaite).to.equal(LIBELLES.non_faite);
        expect(await m.page.textContent("#resultat-contenu .cause")).to.equal(libelle(LIBELLES, "cause", { cause: libelle(LIBELLES, "cause_codes_differents", { code1: 0, code2: 3 }) }));
        expect([r.code, r.lisible, r.enonceFr, r.enonceEn, r.message]).to.deep.equal([null, null, null, null, null]);
      } finally {
        await m.fermer();
      }
    });

    it("TA-101 : artefact altéré d'un octet sous un travailleur.js intact, non compilé et aucun rapport ; le mutant sans le contrôle de l'empreinte rend un rapport (tué)", async function () {
      if (!pret(this)) return;
      const original = fs.readFileSync(path.join(construit.page, "noortrace-verifier.wasm"));
      const altere = Buffer.from(original);
      const repere = altere.indexOf(Buffer.from("hors ligne d'un dossier de preuve", "utf8"));
      expect(repere).to.be.above(0);
      altere[repere] = "H".charCodeAt(0);
      const wasmJs = Buffer.from(`globalThis.NOORTRACE_VERIFICATEUR_WASM = "${altere.toString("base64")}";\n`);
      const integrite = (b) => `sha384-${crypto.createHash("sha384").update(b).digest("base64")}`;
      const avant = integrite(fs.readFileSync(path.join(construit.page, "verificateur-wasm.js")));
      const indexHtml = fs.readFileSync(path.join(construit.page, "index.html"), "utf8");
      expect(indexHtml.split(avant)).to.have.length(2);
      const html = indexHtml.replace(avant, integrite(wasmJs));
      const remplacements = { "verificateur-wasm.js": wasmJs, "index.html": Buffer.from(html) };
      const attendue = `0x${sha256(original)}`;
      const calculee = `0x${sha256(altere)}`;
      const o = await ouvrir(navigateur, construit.page, { remplacements });
      try {
        await o.page.goto("https://verification.example/index.html");
        expect(await attendreArtefact(o.page)).to.equal(libelle(LIBELLES, "artefact_altere", { calculee, attendue }));
        await o.page.setInputFiles("#entree-repertoire", path.join(VECTEURS, "ct-1/dossiers/valide-seq-7"));
        expect(await o.page.isDisabled("#verifier")).to.equal(true);
        await o.page.click("#verifier", { force: true });
        await o.page.waitForTimeout(1000);
        expect(await o.page.isHidden("#resultat")).to.equal(true);
      } finally {
        await o.fermer();
      }
      // Mutant du travailleur : la comparaison à EMPREINTE_WASM retirée.
      const travailleur = fs.readFileSync(path.join(construit.page, "travailleur.js"), "utf8");
      const condition = "if (calculee !== EMPREINTE_WASM) {";
      expect(travailleur.split(condition)).to.have.length(2);
      const mutant = repertoireTemporaire("noortrace-ta101");
      try {
        fs.writeFileSync(path.join(mutant, "travailleur.js"), travailleur.replace(condition, "if (false) {"));
        const m = await ouvrir(navigateur, construit.page, { remplacements: { ...remplacements, "travailleur.js": fs.readFileSync(path.join(mutant, "travailleur.js")) } });
        try {
          await m.page.goto("https://verification.example/index.html");
          expect(await attendreArtefact(m.page)).to.equal(libelle(LIBELLES, "artefact_pret", { version: VERSION, empreinte: calculee }));
          await m.page.setInputFiles("#entree-repertoire", path.join(VECTEURS, "ct-1/dossiers/valide-seq-7"));
          await lancerVerification(m.page);
          const r = await lireResultat(m.page);
          expect(r.lisible.split("\n")[0]).to.equal("Vérification Hors ligne d'un dossier de preuve NOORTRACE (format v0, CT-1 et CT-6)");
        } finally {
          await m.fermer();
        }
      } finally {
        fs.rmSync(mutant, { recursive: true, force: true });
      }
    });
  });
}
