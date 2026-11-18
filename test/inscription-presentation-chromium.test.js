// Inscription des clients : les écrans de l'interface d'exploitant dans Chromium, par Playwright (complément du
// 2026-11-17, décision du porteur sur la présentation des écrans ; CT-4 §7.14, EX-7.16, EX-7.25, EX-7.26 ;
// paquets/inscription/INTERFACES.md 2.2). L'interface est construite par l'essai (`next build`, sans réseau
// extérieur) puis servie par son binaire, sur des données fictives écrites à la main
// (test/fixtures/inscription/donnees-fictives.mjs) : aucun agent, aucune chaîne. L'essai lit ce que l'exploitant
// voit : le texte rendu (un bloc replié fermé n'en fait pas partie), les états, les blocs repliés, le thème.
//
// Complément du 2026-11-18, décision du porteur (langage des écrans ; INTERFACES.md 2.5) : les libellés attendus
// sont ceux du langage courant ; aucun mot de la liste publiée (test/fixtures/inscription/langage.mjs) ne se lit
// au premier niveau d'un écran ; les aides de saisie de la confirmation (empreinte de la pièce calculée dans le
// navigateur, date et heure converties) n'envoient rien d'autre que ce que la route attendait déjà ; le compte
// qui envoie une demande signée se choisit, sans présélection ; un envoi resté sans réponse est la seule consigne.
//
// En attente, avec un message, si Playwright manque ou si Chromium ne se lance pas ; en échec dans ces deux cas
// quand NOORTRACE_EXIGER_CHROMIUM vaut 1.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { enAttente } from "./fixtures/ancrage-rfc3161/outils.mjs";
import { chargerPlaywright } from "./fixtures/verification-page/navigateur.mjs";
import * as O from "./fixtures/inscription/outils.mjs";
import * as I from "./fixtures/inscription/interface.mjs";
import { DEBUT_ETAPES, ajouterClientFictif, ecrireDonneesFictives, travailFictif } from "./fixtures/inscription/donnees-fictives.mjs";
import { MOTS_TECHNIQUES, motsTechniquesDans, textePremierNiveau } from "./fixtures/inscription/langage.mjs";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";

const EXIGER = process.env.NOORTRACE_EXIGER_CHROMIUM === "1";
const NOM = "operateur-1";
const MOT_DE_PASSE = "mot de passe du compte d'essai";
/** Un code brut : mots en minuscules liés par « _ » (étape, état, erreur, membre d'un document). */
const CODE_BRUT = /\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/;

describe("inscription : écrans de l'interface d'exploitant dans Chromium (complément du 2026-11-17)", function () {
  this.timeout(1200000);
  let navigateur = null;
  let indisponible = null;
  let dir;
  let web;
  let F;
  let donneesFictives;
  const ouverts = [];

  before(async function () {
    const { playwright, raison } = chargerPlaywright();
    if (!playwright) {
      indisponible = raison;
      return;
    }
    try {
      // Le champ natif de date suit la langue du navigateur, non celle du contexte : Chromium est lancé en français
      // (sous Linux, par les variables de langue de son environnement ; l'option « --lang » n'y suffit pas).
      navigateur = await playwright.chromium.launch({ env: { ...process.env, LANGUAGE: "fr_FR", LANG: "fr_FR.UTF-8", LC_ALL: "fr_FR.UTF-8" } });
    } catch (e) {
      indisponible = `Chromium ne se lance pas (${String(e.message).split("\n")[0]})`;
      return;
    }
    dir = O.repertoireTemporaire("noortrace-inscription-ecrans-");
    const donnees = path.join(dir, "donnees");
    fs.mkdirSync(donnees);
    donneesFictives = donnees;
    F = ecrireDonneesFictives(donnees);
    const b = I.construire();
    expect(b.code, b.sortie).to.equal(0);
    web = await I.lancerInterface({ dir, prise: path.join(dir, "agent.sock"), donnees, nom: NOM, motDePasse: MOT_DE_PASSE });
  });

  after(async function () {
    if (navigateur) await navigateur.close();
    if (web) await web.arreter();
  });

  beforeEach(function () {
    if (navigateur) return;
    if (EXIGER) throw new Error(`NOORTRACE_EXIGER_CHROMIUM=1 : ${indisponible}`);
    enAttente(this, `Chromium indisponible : ${indisponible}`);
  });

  afterEach(async function () {
    while (ouverts.length) await ouverts.pop().close();
  });

  /** Page neuve ; `connecte` : passe par l'écran de connexion. Rend `{ page, ecarts, aller, visible }`. */
  async function ouvrir({ largeur = 1280, hauteur = 800, connecte = true, stockage = null, fuseau = undefined } = {}) {
    const contexte = await navigateur.newContext({ viewport: { width: largeur, height: hauteur }, locale: "fr-FR", timezoneId: fuseau });
    ouverts.push(contexte);
    const ecarts = [];
    await contexte.addInitScript((valeur) => {
      document.addEventListener("securitypolicyviolation", (e) => console.error(`violation de la politique : ${e.violatedDirective} ${e.blockedURI}`));
      if (valeur !== null && !sessionStorage.getItem("essai-pose")) {
        sessionStorage.setItem("essai-pose", "1");
        localStorage.setItem("noor.theme", valeur);
      }
    }, stockage);
    const page = await contexte.newPage();
    page.on("pageerror", (e) => ecarts.push(String(e)));
    page.on("console", (m) => {
      if (m.type() === "error" && !/status of (401|503|409|400)/.test(m.text())) ecarts.push(m.text());
    });
    const aller = async (chemin) => {
      await page.goto(`${web.url}${chemin}`);
      await page.waitForLoadState("networkidle");
    };
    /** Texte rendu de la page : ce qu'on lit sans rien ouvrir. */
    const visible = () => page.evaluate(() => document.body.innerText);
    if (connecte) {
      await aller("/connexion");
      await page.fill('input[name="name"]', NOM);
      await page.fill('input[name="password"]', MOT_DE_PASSE);
      await page.click('button[type="submit"]');
      await page.waitForURL((u) => u.pathname === "/clients", { timeout: 60000 });
      await page.waitForLoadState("networkidle");
    }
    return { page, ecarts, aller, visible, contexte };
  }

  it("connexion : écran sobre, sans navigation ni session ; un refus se lit en clair ; connecté, la barre commune porte le logo NOORTRACE, « Inscription des clients », la navigation, l'identité de session en entier, la déconnexion et la bascule ; le réseau d'essai est dit", async function () {
    const { page, ecarts, aller, visible } = await ouvrir({ connecte: false });
    await aller("/connexion");
    expect(await page.locator("header.nt-barre .nt-logo-mot").innerText()).to.equal("NOORTRACE");
    expect(await page.locator("header.nt-barre .nt-outil").innerText()).to.equal("Inscription des clients");
    expect(await page.locator("header.nt-barre nav a").count(), "aucune navigation avant la connexion").to.equal(0);
    expect(await page.locator("header.nt-barre .nt-session").count()).to.equal(0);
    expect(await page.locator("h1").innerText()).to.equal("Connexion");
    for (const nom of ["name", "password"]) {
      const id = await page.locator(`input[name="${nom}"]`).getAttribute("id");
      expect(await page.locator(`label[for="${id}"]`).count(), `libellé de ${nom}`).to.equal(1);
    }
    await page.fill('input[name="name"]', NOM);
    await page.fill('input[name="password"]', "un autre mot de passe");
    await page.click('button[type="submit"]');
    await page.waitForSelector('.nt-bandeau-erreur[role="alert"]');
    expect(await page.locator('.nt-bandeau-erreur[role="alert"]').innerText()).to.contain("Nom ou mot de passe refusé.");
    await page.fill('input[name="password"]', MOT_DE_PASSE);
    await page.click('button[type="submit"]');
    await page.waitForURL((u) => u.pathname === "/clients", { timeout: 60000 });
    await page.waitForLoadState("networkidle");
    const barre = page.locator("header.nt-barre");
    expect(await barre.locator('nav a[href="/clients"]').getAttribute("aria-current")).to.equal("page");
    expect(await barre.locator('nav a[href="/clients/nouveau"]').innerText()).to.equal("Nouveau client");
    // La barre dit qui est connecté, par son nom ; l'identité de session entière reste exacte, hors du texte.
    expect(await barre.locator(".nt-session .nt-session-libelle").innerText()).to.equal("Connecté :");
    expect(await barre.locator(".nt-session [data-valeur]").innerText()).to.equal(NOM);
    expect(await barre.locator(".nt-session").getAttribute("data-identite")).to.equal(`exploitant ${NOM}`);
    expect(await barre.getByRole("button", { name: "Se déconnecter" }).count()).to.equal(1);
    expect(await barre.locator("button.nt-bascule").count()).to.equal(1);
    expect(await page.locator("[data-reseau-essai]").innerText()).to.equal("Mode essai : rien de ce que vous faites ici ne touche le registre réel.");
    expect(await visible()).to.not.match(CODE_BRUT);
    expect(ecarts).to.deep.equal([]);
  });

  it("bascule de thème : sombre par défaut, sans attribut ; un clic pose data-theme=\"clair\", change le fond et le libellé du bouton, et mémorise « noor.theme » ; le choix est repris au rechargement et d'un écran à l'autre ; une valeur étrangère retombe sur le sombre ; aucune violation de la politique", async function () {
    const { page, ecarts, aller } = await ouvrir();
    const etat = () => page.evaluate(() => ({ attribut: document.documentElement.getAttribute("data-theme"), fond: getComputedStyle(document.documentElement).backgroundColor, memoire: localStorage.getItem("noor.theme"), barre: document.querySelector('meta[name="theme-color"]')?.getAttribute("content"), libelle: document.querySelector("button.nt-bascule").getAttribute("aria-label") }));
    let e = await etat();
    expect(e).to.deep.include({ attribut: null, fond: "rgb(6, 11, 22)", memoire: null, libelle: "Passer au thème clair" });
    await page.locator("button.nt-bascule").click();
    e = await etat();
    expect(e).to.deep.include({ attribut: "clair", fond: "rgb(243, 247, 255)", memoire: "clair", barre: "#F3F7FF", libelle: "Passer au thème sombre" });
    await page.reload();
    await page.waitForLoadState("networkidle");
    expect(await etat()).to.deep.include({ attribut: "clair", fond: "rgb(243, 247, 255)", libelle: "Passer au thème sombre" });
    await aller("/clients/client-en-cours");
    expect((await etat()).attribut, "d'un écran à l'autre").to.equal("clair");
    await page.locator("button.nt-bascule").click();
    expect(await etat()).to.deep.include({ attribut: null, fond: "rgb(6, 11, 22)", memoire: "sombre", barre: "#060B16", libelle: "Passer au thème clair" });
    expect(ecarts).to.deep.equal([]);
    // Une valeur étrangère dans le stockage : jamais un troisième état.
    const autre = await ouvrir({ connecte: false, stockage: "bleu" });
    await autre.aller("/connexion");
    expect(await autre.page.evaluate(() => [document.documentElement.getAttribute("data-theme"), getComputedStyle(document.documentElement).backgroundColor])).to.deep.equal([null, "rgb(6, 11, 22)"]);
    // Le clair mémorisé est posé avant le premier affichage du corps (amorce du gabarit).
    const clair = await ouvrir({ connecte: false, stockage: "clair" });
    await clair.aller("/connexion");
    expect(await clair.page.evaluate(() => document.documentElement.getAttribute("data-theme"))).to.equal("clair");
    expect([...autre.ecarts, ...clair.ecarts]).to.deep.equal([]);
  });

  it("liste des clients : une carte par client, avec son nom, son avancement en mots (« 5 étapes sur 8 »), sa prochaine action en clair et la date de sa dernière action ; aucun code brut à lire ; l'identifiant de l'organisation reste exact dans le détail replié", async function () {
    const { page, ecarts, visible } = await ouvrir();
    const cartes = page.locator("article[data-client]");
    expect(await cartes.evaluateAll((l) => l.map((x) => x.getAttribute("data-client")))).to.deep.equal(["client-en-cours", "client-en-echec", "client-envoye", "client-inscrit", "client-neuf"]);
    const lire = async (slug) => {
      const c = page.locator(`article[data-client="${slug}"]`);
      return {
        nom: await c.locator(`a[href="/clients/${slug}"]`).first().innerText(),
        avancement: await c.locator("[data-avancement]").innerText(),
        action: await c.locator("[data-prochaine-action]").innerText(),
        code: await c.locator("[data-prochaine-action]").getAttribute("data-prochaine-action"),
        dates: await c.locator("time").evaluateAll((l) => l.map((t) => [t.getAttribute("datetime"), t.innerText])),
      };
    };
    const enCours = await lire("client-en-cours");
    expect(enCours.nom).to.equal("client-en-cours");
    expect(enCours.avancement).to.equal("5 étapes sur 8");
    expect(enCours.code).to.equal("relayer_demande");
    expect(enCours.action).to.equal("Faites signer le document par les approbateurs du client, puis envoyez-le");
    // Deux dates, chacune avec son libellé : celle du dossier, celle de la dernière action.
    expect(enCours.dates).to.deep.equal([["2026-11-12T07:55:00.000Z", "12 novembre 2026 à 07:55 UTC"], ["2026-11-12T08:10:00.000Z", "12 novembre 2026 à 08:10 UTC"]]);
    expect((await page.locator('article[data-client="client-en-cours"] [data-dates-client]').innerText()).replace(/\s+/g, " ")).to.equal("Dossier préparé le 12 novembre 2026 à 07:55 UTC. Dernière action : Préparer le document d'inscription à faire signer (réussi), le 12 novembre 2026 à 08:10 UTC.");
    expect((await lire("client-neuf")).avancement).to.equal("1 étape sur 8");
    expect((await lire("client-neuf")).code).to.equal("consigner_confirmation");
    expect((await lire("client-en-echec")).code).to.equal("conduire_etapes");
    expect((await lire("client-en-echec")).action).to.equal("Reprenez à l'étape 3");
    expect((await lire("client-neuf")).action).to.equal("Notez la confirmation du client");
    expect((await lire("client-envoye")).action).to.equal("Allez chercher la réponse du registre public pour l'étape 2");
    expect((await lire("client-inscrit")).action).to.equal("Remettez le paquet au client");
    // L'écran d'accueil dit à quoi il sert et explique le parcours une fois, en cinq lignes au plus.
    expect(await page.locator(".nt-sous-titre").innerText()).to.match(/^Cet écran montre où en est l'inscription de chaque client et ce qu'il vous reste à faire pour lui\./);
    const marche = page.locator("details[data-comment-ca-marche]");
    expect(await marche.locator("summary").innerText()).to.match(/^Comment ça marche/);
    expect(await marche.evaluate((d) => d.open)).to.equal(false);
    const lignes = await marche.locator("ol > li").count();
    expect(lignes).to.be.within(3, 5);
    expect(await page.locator("details[data-les-etapes] ol > li").count(), "les huit étapes, chacune avec son nom et sa phrase").to.equal(8);
    expect((await lire("client-inscrit")).avancement).to.equal("8 étapes sur 8");
    expect((await lire("client-inscrit")).code).to.equal("remettre_paquet");
    // L'état se lit en mots, pas par la seule couleur : une pastille avec une icône et un mot.
    expect(await page.locator('article[data-client="client-en-echec"] .nt-pastille-refus').innerText()).to.match(/À reprendre/);
    expect(await page.locator('article[data-client="client-inscrit"] .nt-pastille-succes svg.nt-icone').count()).to.be.greaterThan(0);
    expect(await visible()).to.not.match(CODE_BRUT);
    const detail = page.locator('article[data-client="client-en-cours"] details');
    expect(await detail.evaluate((d) => d.open)).to.equal(false);
    expect(await detail.evaluate((d) => d.textContent)).to.contain(F.clients["client-en-cours"].dossier.organisation.org_id);
    expect(await page.getByRole("link", { name: "Nouveau client" }).count()).to.be.greaterThan(0);
    expect(ecarts).to.deep.equal([]);
  });

  it("fiche d'un client : en haut le nom, l'état et la prochaine action avec son bouton ; puis les étapes dans l'ordre, chacune avec son libellé, la phrase qui dit ce qu'elle fait et son état en mots ; une étape en échec monte en bandeau, avec quoi faire ; aucun code brut à lire sans ouvrir un détail", async function () {
    const { page, ecarts, aller, visible } = await ouvrir();
    await aller("/clients/client-en-cours");
    expect(await page.locator("h1").innerText()).to.equal("client-en-cours");
    expect(await page.locator("[data-etat-client]").innerText()).to.equal("En cours");
    const essentiel = page.locator("section.nt-essentiel[data-prochaine-action]");
    expect(await essentiel.getAttribute("data-prochaine-action")).to.equal("relayer_demande");
    expect(await essentiel.innerText()).to.match(/Prochaine action/i);
    // Troisième lecture : le bouton dit qui envoie ; la phrase dessous, lue avec lui, dit que c'est le cas habituel.
    const envoyerSigne = essentiel.locator('form[data-commande="inscrire-cle"] button[type="submit"]');
    expect(await envoyerSigne.innerText()).to.equal("Envoyer par notre compte d'envoi");
    expect(await page.locator(`[id="${await envoyerSigne.getAttribute("aria-describedby")}"]`).innerText()).to.equal("C'est le cas habituel : notre société envoie le document signé au registre public et paie cet envoi.");
    expect(await essentiel.locator("h2").innerText()).to.equal("Faites signer le document par les approbateurs du client, puis envoyez-le");
    // La consigne dit aussi quoi avoir sous la main et ce qui se passe après le clic.
    expect(await essentiel.locator("[data-a-preparer]").innerText()).to.equal("Ensuite : Ayez sous la main : le document signé, tel que le client vous l'a rendu.");
    expect(await essentiel.locator("> [data-apres-clic]").innerText()).to.match(/^Après le clic : l'outil contrôle les signatures, puis envoie le document signé au registre public/);
    expect(await page.locator(".nt-sous-titre").innerText()).to.equal("Inscription sur le registre public, un registre que personne ne peut modifier après coup : 5 étapes sur 8 faites. L'inscription est en cours.");
    // La carte « essentiel » précède les étapes dans l'ordre de lecture.
    expect(await page.evaluate(() => Boolean(document.querySelector("section.nt-essentiel").compareDocumentPosition(document.querySelector("ol.nt-etapes")) & Node.DOCUMENT_POSITION_FOLLOWING))).to.equal(true);
    const etapes = await page.locator("ol.nt-etapes > li.nt-etape").evaluateAll((l) => l.map((x) => ({ code: x.getAttribute("data-etape"), etat: x.getAttribute("data-etat"), classes: x.className, developpee: x.getAttribute("data-developpee"), titre: x.querySelector(".nt-etape-titre").innerText.replace(/\s+/g, " ").trim(), texte: [...x.querySelectorAll(".nt-etape-texte")].map((p) => p.innerText).join(" "), ligne: x.innerText.replace(/\s+/g, " ").trim(), detail: x.querySelector("details[data-detail-etape]").textContent, hauteur: Math.round(x.getBoundingClientRect().height) })));
    expect(etapes.map((e) => e.code)).to.deep.equal(["preparation", "jeu_approbateurs", "assignation", "lecture_jeu", "approvisionnement", "inscription", "premiere_ancre", "premiere_cloture"]);
    expect(etapes.map((e) => e.etat)).to.deep.equal(["faite", "capturee", "capturee", "faite", "capturee", "a_faire", "a_faire", "a_faire"]);
    expect(etapes.map((e) => e.titre)).to.deep.equal([
      "Étape 1 : Préparer le dossier Fait le 12 novembre 2026", "Étape 2 : Enregistrer les approbateurs Fait le 12 novembre 2026", "Étape 3 : Rattacher les approbateurs au client Fait le 12 novembre 2026", "Étape 4 : Contrôler les approbateurs Fait le 12 novembre 2026",
      "Étape 5 : Alimenter le compte technique Fait le 12 novembre 2026", "Étape 6 : Inscrire l'enregistreur À faire", "Étape 7 : Déposer la première preuve de date À faire par le client", "Étape 8 : Clore la première période À faire par le client",
    ]);
    expect(etapes[1].classes).to.contain("nt-etape-faite");
    expect(etapes[5].classes).to.contain("nt-etape-a-faire");
    // Seule l'étape où l'on en est se développe : sa phrase et son état se lisent sans rien ouvrir.
    expect(etapes.map((e) => e.developpee)).to.deep.equal(["non", "non", "non", "non", "non", "oui", "non", "non"]);
    expect(etapes[5].texte).to.contain("Inscrit sur le registre public l'enregistreur du client et son compte technique.");
    expect(etapes[5].texte).to.contain("Rien n'a encore été envoyé pour cette étape.");
    // Une étape faite tient en une ligne : son nom, « Fait le … » ; sa phrase et son état sont dans son détail replié.
    expect(etapes[1].ligne).to.equal("Étape 2 : Enregistrer les approbateurs Fait le 12 novembre 2026 Détail de l'étape 2");
    expect(etapes[1].texte).to.equal("");
    expect(etapes[1].detail).to.contain("Inscrit sur le registre public la liste des approbateurs du client et le nombre d'approbations requises.");
    expect(etapes[1].detail).to.contain("L'opération est inscrite sur le registre public et sa preuve est rangée dans le dossier.");
    expect(etapes[1].detail).to.match(/Bloc\s*100/);
    expect(etapes[3].detail).to.contain("Étape faite sans rien écrire sur le registre public.");
    for (const e of etapes) expect(`${e.texte} ${e.detail}`, e.code).to.match(/[a-zé]\./);
    for (const e of etapes.filter((x) => x.developpee === "non")) expect(e.hauteur, `${e.code} : une ligne`).to.be.at.most(64);
    expect(await visible()).to.not.match(CODE_BRUT);

    // Étape en échec : pastille « Échec », bandeau d'erreur au-dessus des étapes, avec la conduite à tenir.
    await aller("/clients/client-en-echec");
    expect(await page.locator("[data-etat-client]").innerText()).to.equal("À reprendre");
    const bandeau = page.locator('.nt-bandeau-erreur[role="alert"]').first();
    expect(await bandeau.locator(".nt-bandeau-titre").innerText()).to.equal("L'étape 3 a échoué : Rattacher les approbateurs au client");
    // Ce qui s'est passé, et ce qui a été dépensé ; la marche à suivre est dans la consigne, juste dessous.
    expect(await bandeau.innerText()).to.contain("L'opération a été envoyée, mais le registre public l'a refusée, ou le contrôle fait juste après ne retrouve pas ce qui devait être inscrit. Cet envoi a coûté des crédits d'écriture.");
    expect(await page.locator(".nt-sous-titre").innerText()).to.equal("Inscription sur le registre public, un registre que personne ne peut modifier après coup : 2 étapes sur 8 faites. Une étape a échoué : reprenez-la pour continuer.");
    expect(await page.evaluate(() => Boolean(document.querySelector(".nt-bandeau-erreur").compareDocumentPosition(document.querySelector("ol.nt-etapes")) & Node.DOCUMENT_POSITION_FOLLOWING)), "le bandeau précède les étapes").to.equal(true);
    expect(await page.locator('li.nt-etape[data-etape="assignation"]').getAttribute("class")).to.contain("nt-etape-echec");
    expect(await page.locator('li.nt-etape[data-etape="assignation"] .nt-pastille-refus').innerText()).to.equal("Échec");
    expect(await page.locator("section.nt-essentiel[data-prochaine-action]").getAttribute("data-prochaine-action")).to.equal("conduire_etapes");
    expect(await page.locator('section.nt-essentiel form[data-commande="inscrire-client"] button[type="submit"]').innerText()).to.equal("Reprendre à l'étape 3");
    expect(await page.locator("section.nt-essentiel h2").innerText()).to.equal("Reprenez à l'étape 3");
    expect(await page.locator("section.nt-essentiel > [data-apres-clic]").innerText()).to.contain("Si l'étape échoue une deuxième fois, n'insistez pas : prévenez l'équipe technique.");
    expect(await visible()).to.not.match(CODE_BRUT);

    // Envoi sans reçu : « Envoyée », en cours.
    await aller("/clients/client-envoye");
    expect(await page.locator('li.nt-etape[data-etape="jeu_approbateurs"]').getAttribute("class")).to.contain("nt-etape-en-cours");
    expect(await page.locator('li.nt-etape[data-etape="jeu_approbateurs"] .nt-pastille-info').innerText()).to.equal("Envoyée");

    expect(await page.locator("[data-etat-client]").innerText()).to.equal("Réponse à aller chercher");
    // Envoi resté sans réponse : l'écran ne dit qu'une chose, aller chercher la réponse du registre public. La consigne ne parle pas de la
    // confirmation, et aucune autre action n'est proposée à côté d'elle (le même état sans aucune confirmation
    // notée est joué plus bas, dans l'essai de la seconde lecture). Le dernier travail, resté sans réponse, ne
    // monte pas en bandeau : il dirait la même chose que la consigne.
    expect(await page.locator(".nt-bandeau-erreur[data-derniere-action]").count(), "pas de bandeau à côté de la consigne").to.equal(0);
    const envoi = page.locator("section.nt-essentiel[data-prochaine-action]");
    expect(await envoi.getAttribute("data-prochaine-action")).to.equal("reprendre_envoi");
    expect(await envoi.locator("h2").innerText()).to.equal("Allez chercher la réponse du registre public pour l'étape 2");
    expect(await envoi.locator("dl.nt-faits dt").evaluate((x) => x.textContent)).to.equal("Réponse à aller chercher");
    expect((await envoi.locator("dl.nt-faits dd").innerText()).replace(/\s+/g, " ")).to.equal("celle de l'étape 2, « Enregistrer les approbateurs »");
    expect(await envoi.innerText()).to.not.match(/confirmation du client/i);
    expect(await page.locator("[data-actions-utiles]").count(), "aucune autre action proposée à côté de la consigne").to.equal(0);
    expect(await page.locator('a[href="/clients/client-envoye/confirmations"].nt-bouton').count(), "aucun bouton vers les confirmations").to.equal(0);
    // Le bouton va chercher la réponse de l'envoi connu : l'identifiant exact part tel quel, sans que la personne le
    // recopie ni ne le choisisse ; dessous, « Rien n'est renvoyé, rien n'est dépensé. » (le travail ne fait que lire).
    const reprise = envoi.locator('form[data-commande="capturer"]');
    expect(await reprise.locator("[name]").count(), "aucun champ à remplir").to.equal(0);
    expect(await reprise.locator('button[type="submit"]').innerText()).to.equal("Chercher la réponse");
    expect(await reprise.locator("[data-sous-bouton]").innerText()).to.equal("Rien n'est renvoyé, rien n'est dépensé.");
    expect(await envoi.innerText(), "aucune autre formule pour ce geste").to.not.match(/repren[a-z]* (?:cet |l'|un )?envoi/i);
    const [demandeReprise] = await Promise.all([page.waitForRequest((r) => r.url().endsWith("/api/travaux") && r.method() === "POST"), reprise.locator('button[type="submit"]').click()]);
    expect(JSON.parse(demandeReprise.postData())).to.deep.equal({ commande: "capturer", slug: "client-envoye", parametres: { envoi: F.clients["client-envoye"].dossier.steps[0].transaction_hash } });
    await page.locator('section.nt-essentiel .nt-bandeau-erreur[data-refus="agent_injoignable"]').waitFor();

    // Client neuf : la confirmation hors bande d'abord, par un lien vers son registre.
    await aller("/clients/client-neuf");
    const neuf = page.locator("section.nt-essentiel[data-prochaine-action]");
    expect(await neuf.getAttribute("data-prochaine-action")).to.equal("consigner_confirmation");
    expect(await neuf.locator('a[href="/clients/client-neuf/confirmations"]').innerText()).to.equal("Aller noter la confirmation");
    expect(await neuf.locator("h2").innerText()).to.equal("Notez la confirmation du client");
    // Ce que le client doit confirmer : le montant, le nom de l'enregistreur et l'adresse exacte du compte technique.
    const dNeuf = F.clients["client-neuf"].dossier;
    const aConfirmer = (await neuf.locator("dl.nt-faits").innerText()).replace(/\s+/g, " ");
    expect(aConfirmer).to.contain("le versement de 327 000 000 crédits d'écriture sur le compte technique de son enregistreur rec-client-neuf-01");
    expect(aConfirmer).to.contain(dNeuf.recorders[0].chain_key);
    // Ce que la personne fait confirmer, elle sait l'expliquer : ce que sont ces crédits, qui les verse, ce qu'ils
    // permettent ; et l'adresse se confirme par écrit, en entier, jamais dictée.
    expect((await neuf.locator("[data-credits-en-clair]").innerText()).replace(/\s+/g, " ")).to.equal("Les crédits d'écriture paient les écritures de l'enregistreur du client sur le registre public : chaque preuve de date, chaque clôture de période. Ils ne s'achètent pas et ne se vendent pas : c'est notre société qui les verse, depuis son compte de paiement. Le montant suit le budget d'écriture de l'enregistreur, 10 800 000 crédits par jour ; si le compte en a déjà, l'outil ne verse que la différence.");
    expect(await neuf.locator("[data-adresse-a-confirmer]").innerText()).to.equal("Ne la dictez pas : 42 caractères ne se lisent pas à voix haute sans erreur. Envoyez-la au client par écrit, par un autre moyen que cet outil, et demandez-lui de vous répondre par écrit qu'elle est bien, en entier, celle du compte technique de son enregistreur. Gardez sa réponse avec la pièce de la confirmation.");
    expect(aConfirmer).to.not.match(/à lui lire/);
    expect(await page.locator("[data-actions-utiles]").count(), "aucune autre action utile sur un client neuf").to.equal(0);

    // Client inscrit : tout est fait.
    await aller("/clients/client-inscrit");
    expect(await page.locator("[data-etat-client]").innerText()).to.equal("Inscrit");
    expect(await page.locator("ol.nt-etapes > li.nt-etape-faite").count()).to.equal(8);
    expect(ecarts).to.deep.equal([]);
  });

  it("fiche d'un client : le détail technique de chaque étape est replié à l'arrivée et garde les valeurs exactes du dossier (codes de l'étape et de l'état, objet, transaction, bloc, capture, contrat, erreur, instant) ; ouvert, elles se lisent en entier ; à l'impression les blocs fermés s'ouvrent ; la sortie d'un travail et une demande à faire signer restent exactes", async function () {
    const { page, ecarts, aller, visible } = await ouvrir();
    await aller("/clients/client-en-echec");
    const d = F.clients["client-en-echec"].dossier;
    expect(await page.locator("details").evaluateAll((l) => l.filter((x) => x.open).length), "aucun bloc ouvert à l'arrivée").to.equal(0);
    const avant = await visible();
    for (const e of d.steps) {
      const bloc = page.locator(`li.nt-etape[data-etape="${e.step}"] details[data-detail-etape]`);
      expect(await bloc.count(), e.step).to.equal(1);
      const texte = await bloc.evaluate((x) => x.textContent);
      for (const v of [e.step, e.state, e.subject, e.transaction_hash, e.block_hash, e.capture, e.contract, e.updated_at, e.error?.code, e.error?.message]) {
        if (v === null || v === undefined) continue;
        expect(texte, `${e.step} : ${v}`).to.contain(v);
        if (/^0x[0-9a-f]{64}$/.test(v)) expect(avant, `${e.step} : ${v} à lire sans ouvrir`).to.not.contain(v);
      }
    }
    // Ouvert : la valeur se lit en entier, sans débordement de la page.
    const assignation = page.locator('li.nt-etape[data-etape="assignation"] details[data-detail-etape]');
    await assignation.locator("summary").click();
    expect(await assignation.evaluate((x) => x.open)).to.equal(true);
    const apres = await visible();
    expect(apres).to.contain(d.steps[1].transaction_hash);
    expect(apres).to.contain("transaction_annulee");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).to.equal(true);
    // Impression : les blocs fermés s'ouvrent avant l'impression (un bloc fermé ne s'imprime pas), puis se referment.
    const ouverts = () => page.locator("details").evaluateAll((l) => [l.filter((x) => x.open).length, l.length]);
    const [avantImpression, total] = await ouverts();
    expect(avantImpression).to.equal(1);
    await page.evaluate(() => window.dispatchEvent(new Event("beforeprint")));
    expect(await ouverts()).to.deep.equal([total, total]);
    await page.evaluate(() => window.dispatchEvent(new Event("afterprint")));
    expect(await ouverts(), "le bloc ouvert à la main reste ouvert").to.deep.equal([1, total]);
    expect(await assignation.evaluate((x) => x.open)).to.equal(true);
    // Organisation : l'identifiant exact est dans le détail replié de l'organisation ; le réseau se lit en clair.
    const org = page.locator("details[data-detail-organisation]");
    expect(await org.evaluate((x) => x.open)).to.equal(false);
    const texteOrg = await org.evaluate((x) => x.textContent);
    for (const v of [d.organisation.org_id, d.instance.bft_chain_id, String(d.instance.evm_chain_id), d.instance.genesis_sha256, d.approvers.set_admin, ...d.approvers.members, d.recorders[0].chain_key, d.recorders[0].public_key, d.journals[0].journal_id]) expect(texteOrg, v).to.contain(v);
    // Travaux et demandes : libellés en clair, document exact au détail.
    await aller("/clients/client-en-cours");
    const travaux = page.locator("[data-travail]");
    expect(await travaux.evaluateAll((l) => l.map((x) => x.getAttribute("data-travail")))).to.deep.equal([F.travaux[2].id, F.travaux[1].id, F.travaux[0].id]);
    // L'historique est replié : sa ligne de titre dit la dernière action ; ouvert, chaque action se lit en mots.
    const historique = page.locator("details[data-historique]");
    expect(await historique.evaluate((x) => x.open)).to.equal(false);
    expect(await historique.locator("> summary").innerText()).to.match(/3 actions ; la dernière : Préparer le document d'inscription à faire signer \(réussi\)/);
    await historique.locator("> summary").click();
    const premier = travaux.first();
    expect(await premier.innerText()).to.match(/Préparer le document d'inscription à faire signer/);
    expect(await premier.innerText()).to.match(/Réussi/);
    expect(await premier.innerText()).to.match(/12 novembre 2026 à 08:10 UTC/);
    expect(JSON.parse(await premier.locator("details pre").evaluate((x) => x.textContent))).to.deep.equal(F.travaux[2].sortie);
    const demande = page.locator("[data-demande]").first();
    expect(await demande.locator(".nt-pastille").innerText()).to.equal("À faire signer par le client");
    expect(await demande.innerText()).to.contain("ses approbateurs le contrôlent et le signent avec leur propre outil");
    expect(JSON.parse(await demande.locator("details pre").evaluate((x) => x.textContent))).to.deep.equal(F.demande);
    expect(await visible()).to.not.match(CODE_BRUT);
    expect(ecarts).to.deep.equal([]);
  });

  it("confirmations hors bande et paquet : ce qui engage reste à lire sans rien ouvrir, et exact : la personne du client, le canal, l'instant exact, l'empreinte SHA-256 de la pièce en entier, l'exploitant, le travail qui a consommé la confirmation ; le SHA-256 du manifeste du paquet en entier", async function () {
    const { page, ecarts, aller, visible } = await ouvrir();
    await aller("/clients/client-en-cours/confirmations");
    const c = F.confirmations[0];
    const carte = page.locator(`[data-confirmation="${c.id}"]`);
    expect(await carte.count()).to.equal(1);
    expect(await carte.evaluate((x) => x.closest("details") === null), "hors de tout bloc replié").to.equal(true);
    const texte = await carte.innerText();
    for (const v of [c.personne_client, c.canal, c.instant, c.piece_sha256, c.exploitant, c.objet.cle_chaine, F.travaux[1].id]) expect(texte, v).to.contain(v);
    expect(await carte.locator("[data-piece]").innerText()).to.equal(c.piece_sha256);
    expect(await carte.locator(".nt-pastille").innerText()).to.equal("Déjà utilisée");
    expect(await carte.locator("h3").innerText()).to.equal("Premier versement sur le compte technique (étape 5 de l'inscription)");
    // Chaque valeur qui engage dit pourquoi on la montre.
    expect(texte).to.contain("à comparer avec celle de la pièce rangée dans le dossier du client");
    expect(texte.replace(/\s+/g, " ")).to.contain("À quoi elle a servi au versement fait pendant l'action « Faire les étapes 2 à 5 » du 12 novembre 2026 à 08:05 UTC ; elle ne peut plus servir");
    expect(await page.locator("h1").innerText()).to.equal("Confirmations du client");
    // Troisième lecture : le versement de ce client est fait, aucune confirmation n'est attendue ; l'écran le dit, et
    // le formulaire est rangé dans un bloc replié, pour ne pas noter par mégarde une confirmation qui ne s'effacerait pas.
    const aucune = page.locator("[data-aucune-attendue]");
    expect(await aucune.locator("p.nt-encart").innerText()).to.equal("Aucune confirmation n'est attendue pour ce client pour l'instant.");
    const autre = aucune.locator("details[data-autre-confirmation]");
    expect(await autre.evaluate((x) => x.open), "formulaire replié").to.equal(false);
    expect((await autre.locator("> summary").innerText()).split("\n")[0]).to.equal("Noter une autre confirmation (rare)");
    expect(await autre.locator('form[data-formulaire="confirmation"]').count()).to.equal(1);
    expect(await page.locator("[data-confirmation-attendue]").count()).to.equal(0);
    expect(texte).to.contain("dans le formulaire replié « Noter une autre confirmation (rare) », plus bas, sans rien noter : ce choix n'enregistre rien.");
    await autre.locator("> summary").click();
    // Le formulaire d'ajout : un libellé par champ, le type déclaré de chaque champ (EX-7.25).
    const lireChamps = () => page.locator('form[data-formulaire="confirmation"] [name]').evaluateAll((l) => l.map((x) => ({ nom: x.getAttribute("name"), type: x.getAttribute("data-type"), libelle: x.id ? document.querySelectorAll(`label[for="${x.id}"]`).length : 0 })));
    let champs = await lireChamps();
    expect(champs.map((x) => `${x.nom}:${x.type}`)).to.deep.equal(["operation:texte", "cle_chaine:adresse", "personne_client:texte", "canal:texte", "instant:texte", "piece_sha256:hachage"]);
    for (const x of champs) expect(x.libelle, `libellé de ${x.nom}`).to.equal(1);
    // L'objet demandé suit l'opération : pour une administration du jeu, le condensé de la demande, non la clé.
    await page.locator('form[data-formulaire="confirmation"] [name="operation"]').selectOption("administrer-jeu");
    champs = await lireChamps();
    expect(champs.map((x) => `${x.nom}:${x.type}`)).to.deep.equal(["operation:texte", "digest:hachage", "personne_client:texte", "canal:texte", "instant:texte", "piece_sha256:hachage"]);
    for (const x of champs) expect(x.libelle, `libellé de ${x.nom}`).to.equal(1);
    expect(await visible()).to.not.match(CODE_BRUT);
    // Une confirmation en réserve se dit « Disponible ».
    await aller("/clients/client-en-echec/confirmations");
    expect(await page.locator(`[data-confirmation="${F.confirmations[1].id}"]`).locator(".nt-pastille").innerText()).to.equal("Prête à servir");
    // Une confirmation prête à servir attend déjà le versement : aucune autre n'est attendue.
    expect(await page.locator("[data-aucune-attendue] details[data-autre-confirmation]").evaluate((x) => x.open)).to.equal(false);
    // Le client neuf attend la confirmation de son premier versement : le formulaire est déployé, sans la phrase.
    await aller("/clients/client-neuf/confirmations");
    expect(await page.locator("section[data-confirmation-attendue]").getAttribute("data-confirmation-attendue")).to.equal("approvisionnement");
    expect(await page.locator('section[data-confirmation-attendue] > form[data-formulaire="confirmation"]').isVisible()).to.equal(true);
    expect(await page.locator("[data-aucune-attendue]").count()).to.equal(0);
    // Paquet produit : téléchargement et empreinte du manifeste, en entier, hors de tout bloc replié.
    await aller("/clients/client-inscrit/paquet");
    const manifeste = page.locator("[data-manifeste-paquet]");
    expect(await manifeste.innerText()).to.equal(F.manifestePaquet);
    expect(await manifeste.evaluate((x) => x.closest("details") === null)).to.equal(true);
    expect(await page.locator('a[href="/api/clients/client-inscrit/paquet"]').innerText()).to.equal("Télécharger le paquet");
    // L'empreinte dit à quoi elle sert : le client la compare à celle du fichier qu'il a reçu.
    const faitPaquet = (await manifeste.locator("xpath=ancestor::div[contains(@class,'nt-fait')]").innerText()).replace(/\s+/g, " ");
    expect(faitPaquet).to.match(/^Empreinte du paquet/i);
    expect(faitPaquet).to.contain("À donner au client par un autre moyen que le paquet lui-même");
    expect(faitPaquet).to.contain("si le client retrouve la même sur le fichier qu'il a reçu, il a le bon paquet");
    // Un paquet déjà produit ne se refait pas par mégarde : son formulaire est replié, avec la raison de s'en servir.
    expect(await page.locator("details[data-produire-de-nouveau]").evaluate((x) => x.open)).to.equal(false);
    expect(JSON.parse(await page.locator("details pre").first().evaluate((x) => x.textContent))).to.deep.equal(F.travaux[4].sortie);
    expect(await visible()).to.not.match(CODE_BRUT);
    // Paquet pas encore produit : état vide dit en clair.
    await aller("/clients/client-en-cours/paquet");
    expect(await page.locator(".nt-vide").innerText()).to.match(/Aucun paquet/);
    expect(await page.locator('a[href="/api/clients/client-en-cours/paquet"]').count()).to.equal(0);
    expect(ecarts).to.deep.equal([]);
  });

  it("nouveau client : formulaire en sections courtes, un libellé et une aide par champ, exemples fictifs en .example ; une saisie refusée se dit en clair sous le champ fautif, sans recopier la valeur, et rien n'est envoyé", async function () {
    const { page, ecarts, aller, visible } = await ouvrir();
    await aller("/clients/nouveau");
    const forme = page.locator('form[data-commande="inscrire-client-preparer"]').first();
    expect(await forme.locator("fieldset legend").evaluateAll((l) => l.map((x) => x.textContent))).to.deep.equal(["Le client", "Ses approbateurs", "Son enregistreur", "Le versement sur le compte technique"]);
    // Les deux réglages dont la valeur habituelle est sûre sont rangés dans « Réglages avancés », replié.
    const avances = forme.locator("details[data-reglages-avances]");
    expect(await avances.evaluate((x) => x.open)).to.equal(false);
    expect(await avances.locator("[name]").evaluateAll((l) => l.map((x) => [x.getAttribute("name"), x.required]))).to.deep.equal([["budget_jour", false], ["tresorerie", false]]);
    const champs = await forme.locator("[name]").evaluateAll((l) => l.map((x) => ({ nom: x.getAttribute("name"), type: x.getAttribute("data-type"), libelles: x.id ? document.querySelectorAll(`label[for="${x.id}"]`).length : 0, aide: document.getElementById(`${x.id}-aide`)?.textContent ?? "", decrit: (x.getAttribute("aria-describedby") ?? "").split(" "), exemple: document.getElementById(`${x.id}-exemple`)?.textContent ?? "", fantome: x.getAttribute("placeholder"), id: x.id })));
    expect(champs.map((x) => x.nom)).to.deep.equal(["org", "journaux", "approbateurs", "seuil", "admin_jeu", "cles_enregistreur", "budget_jour", "tresorerie"]);
    for (const x of champs) {
      expect(x.libelles, `libellé de ${x.nom}`).to.equal(1);
      expect(x.aide, `aide de ${x.nom}`).to.match(/\.$/);
      // L'aide dit d'où vient l'information : le client la donne par écrit, ou le champ se laisse vide.
      expect(x.aide, `origine de ${x.nom}`).to.match(/Le client vous|Laissez vide|cliquez sur « Tirer un nom au hasard »/);
      // L'exemple s'écrit sous le champ, jamais dans le champ ; il est lu avec l'aide par les lecteurs d'écran.
      expect(x.fantome, `texte fantôme de ${x.nom}`).to.equal(null);
      expect(x.exemple, `exemple de ${x.nom}`).to.match(/^Exemple : ./);
      expect(x.decrit, x.nom).to.include.members([`${x.id}-aide`, `${x.id}-exemple`]);
    }
    expect(await forme.locator('label[for]').first().innerText()).to.equal("Nom court du client");
    expect(await page.locator(".nt-sur-titre").first().innerText()).to.match(/^Étape 1 sur 8$/i);
    expect(await page.locator("[data-avant-de-commencer]").innerText()).to.contain("il ne peut pas savoir si une adresse est bien celle du client");
    const texte = await visible();
    expect(texte).to.not.match(CODE_BRUT);
    expect(texte).to.not.match(/RG-1|RG-2|EX-[0-9]/);
    expect(await page.locator("[placeholder]").count(), "aucun texte fantôme dans un champ").to.equal(0);
    const exemples = await page.locator("[data-exemple] [data-valeur]").evaluateAll((l) => l.map((x) => x.textContent).filter(Boolean));
    expect(exemples.length).to.be.greaterThan(6);
    for (const x of exemples) for (const hote of x.match(/[a-z0-9.-]+\.[a-z]{2,}\b/g) ?? []) expect(hote, x).to.match(/\.(example|cle|json)$/);
    // Saisie refusée : dite sous le champ, en clair ; la valeur n'est pas recopiée ; aucun travail n'est remis.
    const envois = [];
    page.on("request", (r) => {
      if (r.method() === "POST") envois.push(r.url());
    });
    await forme.locator('[name="org"]').fill("Assureur Démo SA");
    await forme.locator('[name="journaux"]').fill("journal-demo");
    await forme.locator('[name="approbateurs"]').fill("0x70997970c51812dc3a010c7d01b50e0d17dc79c8");
    await forme.locator('[name="seuil"]').fill("1");
    await forme.locator('[name="admin_jeu"]').fill("0x15d34aaf54267db7d7c367839aaf71a00a2c6a65");
    await forme.locator('[name="cles_enregistreur"]').fill("[]");
    await forme.locator('button[type="submit"]').click();
    const erreur = forme.locator('p.nt-erreur[role="alert"]');
    await erreur.waitFor();
    expect(await erreur.innerText()).to.match(/^Le nom court n'a pas la bonne forme/);
    expect(await erreur.innerText()).to.not.contain("Assureur Démo SA");
    expect(await forme.locator('[name="org"]').getAttribute("aria-invalid")).to.equal("true");
    expect((await forme.locator('[name="org"]').getAttribute("aria-describedby")).split(" ")).to.include(await erreur.getAttribute("id"));
    expect(envois).to.deep.equal([]);
    expect(ecarts).to.deep.equal([]);
  });

  it("à 390 px de large comme à 1280, aucun écran ne déborde en largeur ; boutons, liens d'action, champs et titres de bloc replié font 44 px de haut au moins sur téléphone ; le focus au clavier se voit", async function () {
    const ecrans = ["/connexion", "/clients", "/clients/nouveau", "/clients/client-neuf", "/clients/client-en-cours", "/clients/client-en-echec", "/clients/client-inscrit", "/clients/client-en-cours/confirmations", "/clients/client-inscrit/paquet"];
    for (const largeur of [390, 1280]) {
      const { page, ecarts, aller } = await ouvrir({ largeur, hauteur: largeur === 390 ? 844 : 800 });
      for (const e of ecrans.slice(1)) {
        await aller(e);
        const d = await page.evaluate(() => ({ page: document.documentElement.scrollWidth, vue: document.documentElement.clientWidth }));
        expect(d.page, `${e} à ${largeur} px`).to.be.at.most(d.vue);
        if (largeur !== 390) continue;
        // Tout ouvrir, puis mesurer les cibles.
        await page.evaluate(() => document.querySelectorAll("details").forEach((x) => (x.open = true)));
        const petites = await page.evaluate(() => [...document.querySelectorAll("button, a.nt-bouton, summary, input:not([type=hidden]), select, textarea")].filter((x) => x.getClientRects().length > 0).map((x) => ({ quoi: `${x.tagName} ${(x.innerText || x.getAttribute("name") || "").slice(0, 30)}`, h: Math.round(x.getBoundingClientRect().height) })).filter((x) => x.h < 44));
        expect(petites, `${e} : cibles de moins de 44 px`).to.deep.equal([]);
        const d2 = await page.evaluate(() => ({ page: document.documentElement.scrollWidth, vue: document.documentElement.clientWidth }));
        expect(d2.page, `${e} à ${largeur} px, blocs ouverts`).to.be.at.most(d2.vue);
      }
      // Focus au clavier : un contour visible sur l'élément atteint par tabulation.
      await aller("/clients");
      await page.keyboard.press("Tab");
      const focus = await page.evaluate(() => {
        const s = getComputedStyle(document.activeElement);
        return { balise: document.activeElement.tagName, contour: s.outlineStyle, largeur: parseFloat(s.outlineWidth) };
      });
      expect(focus.balise).to.not.equal("BODY");
      expect(focus.contour).to.not.equal("none");
      expect(focus.largeur).to.be.at.least(2);
      expect(ecarts, `à ${largeur} px`).to.deep.equal([]);
    }
  });

  it("aucun mot de technicien au premier niveau : connexion, liste, nouveau client (vide et avec un refus), fiche dans chacun de ses états (étapes à lancer, confirmation à noter, demande à préparer, demande à faire signer, transaction envoyée, étape en échec, première période attendue, inscription terminée), confirmations, paquet produit et pas encore produit, client inconnu, panne de l'outil ; le détecteur voit un mot réintroduit au premier niveau, et ne confond ni un bloc replié fermé, ni une valeur venue des données", async function () {
    const plus = [
      ajouterClientFictif(donneesFictives, "essai-a-lancer", ["a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"], { confirmation: true }),
      ajouterClientFictif(donneesFictives, "essai-a-preparer", ["capturee", "capturee", "faite", "capturee", "a_faire", "a_faire", "a_faire"], { histoire: true }),
      ajouterClientFictif(donneesFictives, "essai-periode", ["capturee", "capturee", "faite", "capturee", "capturee", "a_faire", "a_faire"], { histoire: true }),
    ];
    try {
      const lus = [];
      /** Le premier niveau de l'écran affiché ne porte aucun mot de la liste. */
      const controler = async (page, ecran) => {
        const texte = await page.evaluate(textePremierNiveau);
        expect(texte.length, `${ecran} : texte lu`).to.be.greaterThan(80);
        expect(motsTechniquesDans(texte), `${ecran} : mots de technicien au premier niveau`).to.deep.equal([]);
        lus.push(ecran);
        return texte;
      };
      // Connexion : vide, puis après un refus.
      const hors = await ouvrir({ connecte: false });
      await hors.aller("/connexion");
      await controler(hors.page, "connexion");
      await hors.page.fill('input[name="name"]', NOM);
      await hors.page.fill('input[name="password"]', "un autre mot de passe");
      await hors.page.click('button[type="submit"]');
      await hors.page.waitForSelector('.nt-bandeau-erreur[role="alert"]');
      expect(await controler(hors.page, "connexion refusée")).to.contain("Vérifiez le nom du compte et les majuscules du mot de passe, puis réessayez.");
      const { page, ecarts, aller } = await ouvrir();
      await controler(page, "liste des clients");
      // Nouveau client : vide, puis avec une saisie refusée.
      await aller("/clients/nouveau");
      await controler(page, "nouveau client");
      const forme = page.locator('form[data-commande="inscrire-client-preparer"]').first();
      await forme.locator('[name="org"]').fill("Assureur Démo SA");
      await forme.locator('[name="journaux"]').fill("journal-demo");
      await forme.locator('[name="approbateurs"]').fill("0x70997970c51812dc3a010c7d01b50e0d17dc79c8");
      await forme.locator('[name="seuil"]').fill("1");
      await forme.locator('[name="admin_jeu"]').fill("0x15d34aaf54267db7d7c367839aaf71a00a2c6a65");
      await forme.locator('[name="cles_enregistreur"]').fill("[]");
      await forme.locator('button[type="submit"]').click();
      await forme.locator('p.nt-erreur[role="alert"]').waitFor();
      expect(await controler(page, "nouveau client, saisie refusée")).to.contain("Rien n'a été envoyé : un champ est à corriger, il est signalé en rouge.");
      // La fiche, dans chacun de ses états ; la prochaine action attendue prouve que l'état est le bon.
      const fiches = [
        ["essai-a-lancer", "conduire_etapes", "Lancez l'inscription sur le registre public"],
        ["client-neuf", "consigner_confirmation", "Notez la confirmation du client"],
        ["essai-a-preparer", "preparer_demande", "Préparez le document d'inscription de l'enregistreur"],
        ["client-en-cours", "relayer_demande", "Faites signer le document par les approbateurs du client, puis envoyez-le"],
        ["client-envoye", "reprendre_envoi", "Allez chercher la réponse du registre public pour l'étape 2"],
        ["client-en-echec", "conduire_etapes", "Reprenez à l'étape 3"],
        ["essai-periode", "attendre_premiere_periode", "Attendez la première preuve de date du client"],
        ["client-inscrit", "remettre_paquet", "Remettez le paquet au client"],
      ];
      for (const [slug, code, titre] of fiches) {
        await aller(`/clients/${slug}`);
        const essentiel = page.locator("section.nt-essentiel[data-prochaine-action]");
        expect(await essentiel.getAttribute("data-prochaine-action"), slug).to.equal(code);
        expect(await essentiel.locator("h2").innerText(), slug).to.equal(titre);
        const texte = await controler(page, `fiche ${slug}`);
        // Les noms qui viennent des données restent affichés tels quels, hors du texte contrôlé.
        expect(texte, slug).to.not.contain(slug);
        expect(await page.locator("h1[data-valeur]").innerText(), slug).to.equal(slug);
      }
      // Rien n'a été tenté pour « essai-a-lancer » : le bouton dit « Commencer », jamais « Reprendre ».
      await aller("/clients/essai-a-lancer");
      expect(await page.locator('section.nt-essentiel form[data-commande="inscrire-client"] button[type="submit"]').innerText()).to.equal("Commencer les étapes 2 à 5");
      expect(await page.locator("section.nt-essentiel h2").innerText()).to.not.match(/[Rr]epren/);
      // Confirmations (une notée ; aucune), paquet (produit ; pas encore produit), client inconnu.
      await aller("/clients/client-en-cours/confirmations");
      await controler(page, "confirmations");
      await aller("/clients/client-neuf/confirmations");
      expect(await controler(page, "confirmations, aucune")).to.contain("Aucune confirmation notée pour ce client.");
      await aller("/clients/client-inscrit/paquet");
      await controler(page, "paquet produit");
      await aller("/clients/client-en-cours/paquet");
      expect(await controler(page, "paquet pas encore produit")).to.contain("Le paquet ne se produit que lorsque toutes les étapes de l'inscription sont faites ; pour l'instant, 5 étapes sur 8 faites.");
      await aller("/clients/client-qui-n-existe-pas");
      expect(await controler(page, "client inconnu")).to.contain("Le client demandé n'existe pas dans l'outil, ou l'adresse de la page est mal écrite.");
      expect(await page.locator('[data-introuvable] a[href="/clients"]').innerText()).to.equal("Revenir à la liste des clients");
      // Une panne de préparation d'un écran (ici, un dossier auquel il manque un membre) : dite en clair, sans détail interne.
      const casse = path.join(donneesFictives, "clients", "essai-periode", "dossier.json");
      const entier = fs.readFileSync(casse, "utf8");
      try {
        const { recorders, ...reste } = JSON.parse(entier);
        expect(recorders).to.have.length(1);
        fs.writeFileSync(casse, JSON.stringify(reste));
        await aller("/clients/essai-periode");
        await page.waitForSelector("[data-panne]");
        expect(await controler(page, "panne de l'outil")).to.contain("L'outil n'a pas pu préparer cet écran.");
        expect(await page.locator("[data-panne]").innerText()).to.not.match(/recorders|undefined|TypeError|digest/i);
        expect(await page.locator("[data-panne]").getByRole("button", { name: "Réessayer" }).count()).to.equal(1);
      } finally {
        fs.writeFileSync(casse, entier);
      }
      expect(lus.length, "écrans et états lus").to.equal(19);
      // Les valeurs exactes n'ont pas disparu : elles sont à leur place, marquées comme des valeurs.
      await aller("/clients/client-neuf");
      const valeurs = await page.locator("[data-valeur]").evaluateAll((l) => l.filter((x) => x.getClientRects().length > 0).map((x) => x.textContent));
      expect(valeurs).to.include.members(["client-neuf", NOM, "rec-client-neuf-01", F.clients["client-neuf"].dossier.recorders[0].chain_key, "journal-client-neuf"]);

      // Le détecteur : un mot réintroduit au premier niveau est vu ; le même mot dans un bloc replié fermé ou dans
      // une valeur venue des données ne l'est pas ; dans un bloc ouvert, il l'est de nouveau.
      const propre = await page.evaluate(textePremierNiveau);
      expect(motsTechniquesDans(propre)).to.deep.equal([]);
      await page.evaluate(() => { document.querySelector("section.nt-essentiel h2").textContent = "Consigner la confirmation hors bande du client"; });
      expect(motsTechniquesDans(await page.evaluate(textePremierNiveau)).map((x) => x.mot).sort(), "mutant du titre").to.deep.equal(["consigner", "hors bande"]);
      await page.reload();
      await page.waitForLoadState("networkidle");
      await page.evaluate(() => {
        const d = document.querySelector("details[data-detail-organisation]");
        d.querySelector("dl").insertAdjacentHTML("beforeend", "<dt>clé de chaîne</dt><dd>regtest</dd>");
        const v = document.createElement("span");
        v.setAttribute("data-valeur", "");
        v.textContent = "exploitant jeu_approbateurs";
        document.querySelector("section.nt-essentiel").appendChild(v);
      });
      expect(motsTechniquesDans(await page.evaluate(textePremierNiveau)), "bloc fermé et valeur").to.deep.equal([]);
      await page.evaluate(() => { document.querySelector("details[data-detail-organisation]").open = true; });
      expect(motsTechniquesDans(await page.evaluate(textePremierNiveau)).map((x) => x.mot), "bloc ouvert").to.include.members(["clé de chaîne", "regtest"]);
      // Chaque mot de la liste publiée est reconnu par son propre motif (aucun motif mort).
      const temoins = { "oidc": "oidc", "adresse d'un site en clair dans une phrase": "voir https://idp.client.example", "chemin JSON employé comme libellé": "le champ /amount vaut", "condensé": "le condensé", "hachage": "le hachage", "hors bande": "hors bande", "clé de chaîne": "la clé de chaîne", "manifeste": "le manifeste", "ancre": "la première ancre", "RPC": "le point RPC", "nonce": "le nonce", "regtest": "regtest", "drapeau de ligne de commande": "avec --ancres", "identifiant de règle ou de contrôle": "selon EX-7.16", "renvoi à la spécification": "voir CT-4", "suite hexadécimale dans une phrase": "la clé 0x63e9559b66b5", "nom de code (mots liés par « _ »)": "état a_faire", "slug": "le slug", "jeu d'approbateurs": "le jeu d'approbateurs", "seuil": "le seuil", "exploitant": "l'exploitant", "agent (le service d'inscription)": "l'agent refuse", "relayer": "relayer la demande", "consigner": "consigner", "approvisionner": "approvisionner", "trésorerie": "la trésorerie", "clé de gouvernance": "la clé de gouvernance", "clé d'enregistreur": "la clé d'enregistreur", "transaction": "la transaction", "bloc": "au bloc 14", "capture": "sa capture", "nœud": "le nœud", "validateur": "un validateur", "gaz": "en gaz", "wei": "12 wei", "JSON": "tableau JSON", "SHA-256": "empreinte SHA-256", "hexadécimal": "chiffres hexadécimaux", "session": "votre session", "Ed25519, EVM, BFT, API": "clé Ed25519", "octet": "12 octets", "sortie de la commande": "sortie de la commande", "réseau de développement": "réseau de développement", "demande (nom : ici, « document à faire signer »)": "la demande signée" };
      expect(Object.keys(temoins).sort()).to.deep.equal(MOTS_TECHNIQUES.map((x) => x.mot).sort());
      for (const [mot, phrase] of Object.entries(temoins)) expect(motsTechniquesDans(phrase).map((x) => x.mot), phrase).to.include(mot);
      // Les mots admis ne sont pas pris pour des mots bannis.
      expect(motsTechniquesDans("Suivez sa consigne. L'agent logiciel du client. Un appel au numéro de son contrat. Elle commence par « https:// ». Heure UTC. Demandez au client. Si l'outil le demande. Il ne vous demandera jamais de secret. Le document à faire signer par le client.")).to.deep.equal([]);
      // Les seuls écarts admis : la réponse 404 de la page d'un client qui n'existe pas, et la panne provoquée ci-dessus.
      const admis = /status of (404|500)|Server Components render|React error #441/;
      expect([...hors.ecarts, ...ecarts].filter((x) => !admis.test(x))).to.deep.equal([]);
      expect(ecarts.filter((x) => /status of 404/.test(x))).to.have.length(1);
    } finally {
      for (const x of plus) x.retirer();
    }
  });

  it("aides de saisie : « Choisir la pièce » calcule dans le navigateur l'empreinte du fichier choisi, égale à celle de sha256sum, sans rien envoyer du fichier ; « Date et heure » et « Maintenant » écrivent l'instant à la forme exacte que la route accepte ; la saisie à la main reste possible ; « Tirer un nom au hasard » donne un nom court de la forme des vrais clients", async function () {
    const { lireConfirmation } = await import("../paquets/inscription/src/commun/travaux.mjs");
    const marque = `piece-fictive-${crypto.randomBytes(12).toString("hex")}`;
    const piece = path.join(dir, "compte-rendu-appel.txt");
    fs.writeFileSync(piece, `Compte rendu d'appel fictif.\n${marque}\n${"ligne de remplissage\n".repeat(2000)}`);
    const attendue = `0x${crypto.createHash("sha256").update(fs.readFileSync(piece)).digest("hex")}`;
    const outil = spawnSync("sha256sum", [piece], { encoding: "utf8" });
    expect(outil.status, outil.stderr).to.equal(0);
    expect(`0x${outil.stdout.split(" ")[0]}`, "sha256sum").to.equal(attendue);
    // Le poste est à Zurich (UTC+1 en novembre) : 10:12 à la montre vaut 09:12 en temps universel.
    const { page, ecarts, aller } = await ouvrir({ fuseau: "Europe/Zurich" });
    await aller("/clients/client-neuf/confirmations");
    const requetes = [];
    page.on("request", (r) => requetes.push({ methode: r.method(), url: r.url(), corps: r.postData() ?? "" }));
    const f = page.locator('form[data-formulaire="confirmation"]');
    // Les deux aides ne sont pas des champs envoyés : elles n'ont pas de nom, et portent le type du champ qu'elles remplissent (EX-7.25).
    expect(await f.locator("[data-aide-saisie]").evaluateAll((l) => l.map((x) => [x.getAttribute("data-aide-saisie"), x.getAttribute("name"), x.getAttribute("data-type")]))).to.deep.equal([["date", null, "texte"], ["maintenant", null, null], ["piece", null, "hachage"], ["choisir-piece", null, null]]);
    expect(await f.locator("[data-piece-choisie]").innerText()).to.equal("Le fichier ne quitte pas votre poste : l'outil calcule son empreinte ici même, sans l'envoyer.");
    const [choix] = await Promise.all([page.waitForEvent("filechooser"), f.getByRole("button", { name: "Choisir la pièce" }).click()]);
    await choix.setFiles(piece);
    await page.waitForFunction((v) => document.querySelector('form[data-formulaire="confirmation"] [name="piece_sha256"]').value === v, attendue);
    expect((await f.locator("[data-piece-choisie]").innerText()).replace(/\s+/g, " ")).to.match(/^Empreinte calculée sur votre poste pour compte-rendu-appel\.txt \(\d+ Ko\)\. Le fichier n'a pas quitté votre poste\.$/);
    expect(requetes, "aucune requête au choix du fichier").to.deep.equal([]);
    // Date et heure du poste, converties ; puis « Maintenant ». Sous le champ, l'aide dit de quelle heure il s'agit ;
    // la valeur convertie ne paraît qu'une fois la date donnée, en clair, et c'est celle du champ enregistré.
    const aideDate = f.locator(`#${await f.locator('[data-aide-saisie="date"]').getAttribute("aria-describedby")}`);
    expect(await aideDate.innerText()).to.equal("Heure de votre poste ; l'outil la convertit. Donnez la date et l'heure à votre montre, ou cliquez sur « Maintenant » si le client vient de confirmer : le champ suivant se remplit pour vous.");
    expect(await f.locator("[data-instant-converti]").count(), "rien de converti avant la saisie").to.equal(0);
    await f.locator('[data-aide-saisie="date"]').fill("2026-11-17T10:12");
    expect(await f.locator('[name="instant"]').inputValue()).to.equal("2026-11-17T09:12:00.000Z");
    // Le champ natif suit la langue du navigateur : la date choisie est toujours redite en toutes lettres, en français.
    expect(await f.locator("[data-date-en-clair]").innerText()).to.equal("Vous avez choisi : 17 novembre 2026 à 10 h 12, heure de votre poste.");
    expect(await f.locator("[data-instant-converti]").innerText()).to.equal("Converti en temps universel (UTC) : 17 novembre 2026 à 09:12 UTC. C'est cette heure, et non celle de votre poste, que l'outil enregistre et affiche partout.");
    // D'autres fuseaux, dont un à l'ouest et un décalé d'une demi-heure : la même saisie donne un autre instant, et l'écran le montre.
    for (const [fuseau, instant, clair] of [
      ["America/New_York", "2026-11-17T15:12:00.000Z", "17 novembre 2026 à 15:12 UTC"],
      ["Asia/Kolkata", "2026-11-17T04:42:00.000Z", "17 novembre 2026 à 04:42 UTC"],
      ["Pacific/Auckland", "2026-11-16T21:12:00.000Z", "16 novembre 2026 à 21:12 UTC"],
    ]) {
      const autre = await ouvrir({ fuseau });
      await autre.aller("/clients/client-neuf/confirmations");
      const g = autre.page.locator('form[data-formulaire="confirmation"]');
      await g.locator('[data-aide-saisie="date"]').fill("2026-11-17T10:12");
      expect(await g.locator('[name="instant"]').inputValue(), fuseau).to.equal(instant);
      expect(await g.locator("[data-instant-converti] strong").innerText(), fuseau).to.equal(clair);
      await ouverts.pop().close();
    }
    const avant = Date.now();
    await f.getByRole("button", { name: "Maintenant" }).click();
    const maintenant = await f.locator('[name="instant"]').inputValue();
    expect(maintenant).to.match(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/);
    expect(Date.parse(maintenant)).to.be.within(avant - 5000, Date.now() + 5000);
    expect(await f.locator('[data-aide-saisie="date"]').inputValue(), "le champ du poste suit").to.match(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}$/);
    await f.locator('[data-aide-saisie="date"]').fill("2026-11-17T10:12");
    await f.locator('[name="personne_client"]').fill("Camille Durand (personne fictive)");
    await f.locator('[name="canal"]').fill("appel au numéro du contrat");
    const reponse = page.waitForResponse((r) => r.url().endsWith("/api/clients/client-neuf/confirmations") && r.request().method() === "POST");
    // Le premier clic n'envoie rien : il affiche le récapitulatif à relire ; seul le second envoie.
    expect(await f.locator('button[type="submit"]').innerText()).to.equal("Relire avant de noter");
    await f.locator('button[type="submit"]').click();
    await f.locator("[data-relecture]").waitFor();
    expect(requetes.filter((x) => x.methode === "POST"), "rien n'est envoyé au premier clic").to.deep.equal([]);
    await f.locator("[data-relecture] button[data-noter]").click();
    const r = await reponse;
    const envoi = requetes.filter((x) => x.methode === "POST");
    expect(envoi).to.have.length(1);
    const corps = JSON.parse(envoi[0].corps);
    // Ce qui part est ce que la route attendait déjà, et rien de plus : ni le fichier, ni son nom.
    expect(Object.keys(corps).sort()).to.deep.equal(["canal", "instant", "objet", "operation", "personne_client", "piece_sha256"]);
    expect(corps).to.deep.include({ operation: "approvisionnement", instant: "2026-11-17T09:12:00.000Z", piece_sha256: attendue, personne_client: "Camille Durand (personne fictive)", canal: "appel au numéro du contrat" });
    expect(corps.objet).to.deep.equal({ org_id: F.clients["client-neuf"].dossier.organisation.org_id, cle_chaine: F.clients["client-neuf"].dossier.recorders[0].chain_key });
    for (const x of requetes) {
      expect(x.corps, x.url).to.not.contain(marque);
      expect(x.corps, x.url).to.not.contain("compte-rendu-appel");
      expect(x.corps.length, x.url).to.be.lessThan(1000);
    }
    // La route accepte cette forme : son contrôle passe (la même fonction ne lève rien), et le refus qui suit est
    // celui du service d'inscription, absent de cet essai, dit en clair ; un instant mal formé aurait rendu 400.
    expect(() => lireConfirmation(corps)).to.not.throw();
    expect(r.status()).to.equal(503);
    expect((await r.json()).error.code).to.equal("agent_injoignable");
    const refus = f.locator('.nt-bandeau-erreur[data-refus="agent_injoignable"]');
    await refus.waitFor();
    expect((await refus.locator(".nt-bandeau-titre").innerText()).replace(/\s+/g, " ")).to.equal("La confirmation n'a pas été notée. Le service d'inscription ne répond pas : votre action n'est pas partie.");
    // La saisie à la main reste possible, et contrôlée : une empreinte mal formée est refusée sous le champ, sans envoi.
    const avantSaisie = requetes.length;
    await f.locator('[name="piece_sha256"]').fill("empreinte recopiée de travers");
    await f.locator('button[type="submit"]').click();
    const erreur = f.locator('p.nt-erreur[role="alert"]');
    await erreur.waitFor();
    expect(await erreur.innerText()).to.match(/^Ce n'est pas une empreinte\./);
    expect(await erreur.innerText()).to.not.contain("recopiée");
    expect(requetes.length, "aucun envoi").to.equal(avantSaisie);
    await f.locator('[name="piece_sha256"]').fill(attendue);
    await f.locator('[name="instant"]').fill("hier vers dix heures");
    await f.locator('button[type="submit"]').click();
    await page.waitForFunction(() => /La date et l'heure n'ont pas la forme attendue/.test(document.querySelector('form[data-formulaire="confirmation"] p.nt-erreur')?.textContent ?? ""));
    expect(requetes.length, "aucun envoi").to.equal(avantSaisie);
    // Nouveau client : un nom court tiré au hasard dans la page, de la forme des vrais clients, différent à chaque tirage.
    await aller("/clients/nouveau");
    const forme = page.locator('form[data-commande="inscrire-client-preparer"]').first();
    const { slug } = await import("../paquets/inscription/src/commun/champs.mjs");
    const tires = [];
    for (let k = 0; k < 2; k++) {
      await forme.getByRole("button", { name: "Tirer un nom au hasard" }).click();
      tires.push(await forme.locator('[name="org"]').inputValue());
    }
    for (const t of tires) {
      expect(t).to.match(/^o-[0-9a-f]{32}$/);
      expect(slug("org", t, { production: true }), "forme des clients de production (CT-4 EX-6.2)").to.equal(t);
    }
    expect(tires[0]).to.not.equal(tires[1]);
    expect(ecarts).to.deep.equal([]);
  });

  it("qui envoie le document signé (troisième lecture) : aucun choix à faire, aucune case ni aucun bouton présélectionné sur aucun écran ; le bouton de la consigne dit qui envoie (« Envoyer par notre compte d'envoi », le cas habituel, dit dessous) et envoie à la route, au caractère près, ce qu'elle recevait déjà (relayeur vrai) ; l'envoi par le compte qu'une référence désigne (essais seulement) est une action rangée, avec son champ, refusé vide, qui envoie la référence seule ; de même pour un changement des approbateurs", async function () {
    const { page, ecarts, aller } = await ouvrir();
    // Aucun écran ne porte de choix à faire avant un envoi : ni case, ni bouton radio, ni bouton enfoncé, ni groupe de choix.
    for (const e of ["/clients/nouveau", "/clients/client-neuf", "/clients/client-en-cours", "/clients/client-envoye", "/clients/client-en-echec", "/clients/client-inscrit", "/clients/client-neuf/confirmations", "/clients/client-en-cours/confirmations", "/clients/client-inscrit/paquet"]) {
      await aller(e);
      await page.evaluate(() => document.querySelectorAll("details").forEach((x) => (x.open = true)));
      expect(await page.locator('input[type="radio"], input[type="checkbox"], [aria-pressed], [data-choix], input[type="hidden"][name]').count(), `${e} : aucun choix ni valeur cachée`).to.equal(0);
    }
    await aller("/clients/client-en-cours");
    const forme = page.locator('section.nt-essentiel form[data-commande="inscrire-cle"]');
    // La consigne : le document signé à coller, et un seul bouton, qui nomme notre compte d'envoi ; la phrase dessous est lue avec lui.
    expect(await forme.locator("[name]").evaluateAll((l) => l.map((x) => x.getAttribute("name")))).to.deep.equal(["demande"]);
    expect(await forme.locator("select").count(), "aucune liste où un choix serait fait d'avance").to.equal(0);
    const bouton = forme.locator('button[type="submit"]');
    expect(await forme.locator("button").count()).to.equal(1);
    expect(await bouton.innerText()).to.equal("Envoyer par notre compte d'envoi");
    expect(await bouton.evaluate((b) => b.classList.contains("nt-bouton-principal") && b.closest("details") === null)).to.equal(true);
    const dessous = forme.locator("[data-sous-bouton]");
    expect(await dessous.innerText()).to.equal("C'est le cas habituel : notre société envoie le document signé au registre public et paie cet envoi.");
    expect(await bouton.getAttribute("aria-describedby")).to.equal(await dessous.getAttribute("id"));
    expect(await bouton.evaluate((b) => Boolean(b.compareDocumentPosition(b.closest("form").querySelector("[data-sous-bouton]")) & Node.DOCUMENT_POSITION_FOLLOWING)), "la phrase est sous le bouton").to.equal(true);
    expect(await page.locator("section.nt-essentiel").innerText(), "plus de question à trancher").to.not.match(/Choisissez qui envoie|rien n'est choisi d'avance|essais seulement/);
    const envois = [];
    page.on("request", (r) => {
      if (r.method() === "POST") envois.push(r.postData());
    });
    const texteDemande = JSON.stringify(F.demande, null, 2);
    await forme.locator('[name="demande"]').fill(texteDemande);
    const [une] = await Promise.all([page.waitForRequest((r) => r.url().endsWith("/api/travaux") && r.method() === "POST"), bouton.click()]);
    // Ce que la route reçoit est ce qu'elle recevait déjà avec « Notre compte d'envoi », au caractère près : la demande, puis « relayeur : vrai ».
    expect(une.postData()).to.equal(JSON.stringify({ commande: "inscrire-cle", slug: "client-en-cours", parametres: { demande: F.demande, relayeur: true } }));
    await page.locator('section.nt-essentiel .nt-bandeau-erreur[data-refus="agent_injoignable"]').waitFor();
    // L'autre façon d'envoyer, par le compte qu'une référence désigne : rangée, avec son champ, pour les essais seulement.
    await aller("/clients/client-en-cours");
    const rares = page.locator("details[data-actions-rares]");
    await rares.locator("> summary").click();
    const variante = rares.locator('details[data-action="inscrire-cle-reference"]');
    expect(await variante.locator("> summary").innerText()).to.equal("Envoyer le document d'inscription signé par le compte désigné par une référence (essais seulement)");
    await variante.locator("> summary").click();
    const fv = variante.locator('form[data-commande="inscrire-cle"]');
    expect(await fv.locator("[name]").evaluateAll((l) => l.map((x) => [x.getAttribute("name"), x.getAttribute("data-type")]))).to.deep.equal([["demande", "document"], ["cle_chaine", "reference_cle"]]);
    expect(await fv.locator(`label[for="${await fv.locator('[name="cle_chaine"]').getAttribute("id")}"]`).innerText(), "nécessaire, elle n'est pas dite facultative").to.equal("Référence du compte technique du client");
    expect(await fv.locator('[name="cle_chaine"]').getAttribute("aria-required")).to.equal("true");
    expect(await fv.locator('button[type="submit"]').innerText()).to.equal("Envoyer par le compte désigné");
    const avant = envois.length;
    await fv.locator('[name="demande"]').fill(texteDemande);
    await fv.locator('button[type="submit"]').click();
    const erreur = fv.locator('p.nt-erreur[role="alert"]');
    await erreur.waitFor();
    expect(await erreur.innerText()).to.equal("Écrivez ici la référence que l'équipe technique vous a donnée. Si vous n'en avez pas, servez-vous du bouton « Envoyer par notre compte d'envoi ». Rien n'a été envoyé.");
    expect(envois.length, "rien ne part sans la référence").to.equal(avant);
    await fv.locator('[name="cle_chaine"]').fill("alias:compte-d-essai");
    const [deux] = await Promise.all([page.waitForRequest((r) => r.url().endsWith("/api/travaux") && r.method() === "POST"), fv.locator('button[type="submit"]').click()]);
    expect(deux.postData()).to.equal(JSON.stringify({ commande: "inscrire-cle", slug: "client-en-cours", parametres: { demande: F.demande, cle_chaine: "alias:compte-d-essai" } }));
    // Le changement des approbateurs signé : les deux mêmes façons, rangées ; ce que la route reçoit pour chacune ne change pas.
    await aller("/clients/client-en-cours");
    await page.locator("details[data-actions-rares] > summary").click();
    const changement = { version: 0, operation: "administration_jeu", digest: `0x${"cd".repeat(32)}`, signatures: [] };
    for (const [cle, plus, attendu] of [["administrer-jeu", null, { demande: changement, relayeur: true }], ["administrer-jeu-reference", "alias:compte-d-essai", { demande: changement, expediteur: "alias:compte-d-essai" }]]) {
      const d = page.locator(`details[data-actions-rares] details[data-action="${cle}"]`);
      await d.locator("> summary").click();
      const f = d.locator('form[data-commande="administrer-jeu"]');
      expect(await f.locator('button[type="submit"]').innerText(), cle).to.equal(plus ? "Envoyer par le compte désigné" : "Envoyer par notre compte d'envoi");
      await f.locator('[name="demande"]').fill(JSON.stringify(changement));
      if (plus) await f.locator('[name="expediteur"]').fill(plus);
      const [r] = await Promise.all([page.waitForRequest((x) => x.url().endsWith("/api/travaux") && x.method() === "POST"), f.locator('button[type="submit"]').click()]);
      expect(r.postData(), cle).to.equal(JSON.stringify({ commande: "administrer-jeu", slug: "client-en-cours", parametres: attendu }));
    }
    expect(ecarts).to.deep.equal([]);
  });

  it("erreurs en clair : service d'inscription indisponible, connexion finie, confirmation du client absente (la mention de CT-4 reste mot pour mot, sous sa phrase courante), action qui attend son tour, résultat pas encore connu, paquet refusé au téléchargement ; chacune dit ce qui s'est passé, ce qui a été envoyé ou dépensé, et quoi faire ; le code exact reste dans le détail replié", async function () {
    const plus = ajouterClientFictif(donneesFictives, "essai-erreurs", ["a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"], { confirmation: true });
    try {
      const { page, ecarts, aller, contexte } = await ouvrir();
      const carte = "section.nt-essentiel[data-prochaine-action]";
      const lancer = async () => {
        await aller("/clients/essai-erreurs");
        await page.locator(`${carte} form button[type="submit"]`).click();
      };
      /** Le bandeau du refus `code` : ses phrases, sans mot de technicien ; son code exact, dans le détail replié seulement. */
      const lireRefus = async (code) => {
        const b = page.locator(`.nt-bandeau-erreur[data-refus="${code}"]`).first();
        await b.waitFor();
        expect(await b.locator("details").evaluate((d) => d.open), code).to.equal(false);
        expect(await b.locator("details").evaluate((d) => d.textContent), code).to.contain(code);
        const lu = await b.evaluate((x) => {
          const c = x.cloneNode(true);
          for (const d of c.querySelectorAll("details, [data-phrase-fixee]")) d.remove();
          return [...c.querySelectorAll("p")].map((p) => p.textContent.replace(/\s+/g, " ").trim());
        });
        expect(motsTechniquesDans(lu.join("\n")), code).to.deep.equal([]);
        expect(lu.join("\n"), code).to.not.contain(code);
        return lu;
      };
      // Service d'inscription indisponible : réel dans cet essai (aucun agent ne tourne).
      await lancer();
      expect(await lireRefus("agent_injoignable")).to.deep.equal([
        "Le service d'inscription ne répond pas : votre action n'est pas partie.",
        "Rien n'a été envoyé au registre public et rien n'a été dépensé.",
        "Que faire : Attendez une minute, puis recommencez. Si le service ne répond toujours pas, prévenez l'équipe technique : il doit être redémarré.",
      ]);
      /** Joue une réponse fictive de POST /api/travaux, puis l'état fictif du travail. */
      const jouer = async (reponse, travail = null) => {
        await aller("/clients/essai-erreurs");
        await page.route("**/api/travaux", (r) => r.fulfill({ status: reponse.statut, contentType: "application/json", body: JSON.stringify(reponse.corps) }));
        if (travail) await page.route("**/api/travaux/trv-*", (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(travail) }));
        await page.locator(`${carte} form button[type="submit"]`).click();
      };
      const fin = async () => {
        await page.unroute("**/api/travaux");
        await page.unroute("**/api/travaux/trv-*");
      };
      // Confirmation absente : la phrase courante d'abord, puis la mention de CT-4 EX-7.26, mot pour mot.
      await jouer({ statut: 400, corps: { error: { code: "confirmation_absente", message: "confirmation hors bande absente : aucune confirmation pour ce compte" } } });
      const absente = await lireRefus("confirmation_absente");
      expect(absente[0]).to.equal("Rien n'a été envoyé : il manque la confirmation du client pour cette opération.");
      expect(absente[absente.length - 2]).to.equal("Que faire : Notez la confirmation du client sur l'écran « Confirmations du client », puis relancez l'action.");
      const bandeau = page.locator('.nt-bandeau-erreur[data-refus="confirmation_absente"]');
      expect(await bandeau.locator("[data-phrase-fixee]").innerText()).to.equal("Mention exacte de l'outil : « confirmation hors bande absente ».");
      expect(await bandeau.evaluate((b) => Boolean(b.querySelector(".nt-bandeau-titre").compareDocumentPosition(b.querySelector("[data-phrase-fixee]")) & Node.DOCUMENT_POSITION_FOLLOWING)), "la phrase courante précède la mention fixée").to.equal(true);
      expect(await bandeau.locator('a[href="/clients/essai-erreurs/confirmations"]').innerText()).to.equal("Ouvrir les confirmations du client");
      await fin();
      // Une action déjà en cours : la suivante attend son tour, et l'écran le dit.
      const id = `trv-${"0".repeat(30)}98`;
      const t = (plusT) => ({ id, commande: "inscrire-client", slug: "essai-erreurs", exploitant: `exploitant ${NOM}`, recu_a: "2026-11-18T09:00:00.000Z", etat: "fini", sortie: null, ...plusT });
      await jouer({ statut: 200, corps: { id } }, t({ etat: "en_attente" }));
      const attente = page.locator(`${carte} [data-etat-travail="en_attente"]`);
      await attente.waitFor();
      expect((await attente.innerText()).replace(/\s+/g, " ")).to.equal("En attente de son tour Faire les étapes 2 à 5. Le service d'inscription fait une action à la fois : celle-ci attend la fin de la précédente. Vous n'avez rien à faire.");
      expect(await page.locator(`${carte} form button[type="submit"]`).isDisabled(), "pas de second envoi pendant l'attente").to.equal(true);
      await fin();
      // Résultat pas encore connu : l'opération est partie ; on reprend l'envoi, on ne renvoie rien.
      await jouer({ statut: 200, corps: { id } }, t({ sortie: { version: 0, command: "inscrire-client", result: "incertain", exit_code: 3, checks: [], error: { code: "recu_absent", check: null, message: "aucun reçu dans le délai" }, outputs: {} } }));
      const inconnu = await lireRefus("recu_absent");
      expect(inconnu[1]).to.equal("L'opération est partie vers le registre public ; elle a pu coûter des crédits d'écriture.");
      expect(inconnu[2]).to.equal("Que faire : Ne renvoyez rien. Actualisez la fiche du client : elle vous propose d'aller chercher la réponse du registre public.");
      expect(await page.locator(`${carte} [data-etat-travail="incertain"] .nt-pastille`).innerText()).to.equal("Résultat pas encore connu");
      await fin();
      // Un code que cette version ne connaît pas : explication générale, et le code reste lisible au détail.
      await jouer({ statut: 400, corps: { error: { code: "code_futur", message: "message que cette version ne connaît pas" } } });
      expect((await lireRefus("code_futur"))[0]).to.equal("L'action n'a pas abouti, pour une raison que cet outil ne sait pas expliquer.");
      await fin();
      // Paquet refusé au téléchargement : dit sur l'écran, sans quitter la page.
      await aller("/clients/client-inscrit/paquet");
      await page.route("**/api/clients/client-inscrit/paquet", (r) => r.fulfill({ status: 409, contentType: "application/json", body: JSON.stringify({ error: { code: "paquet_fichiers", message: "fichier absent du paquet" } }) }));
      await page.locator('a[href="/api/clients/client-inscrit/paquet"]').click();
      const paquet = await lireRefus("paquet_fichiers");
      expect(paquet[0]).to.equal("Le paquet n'a pas été téléchargé. Le contrôle du paquet a refusé un fichier.");
      expect(new URL(page.url()).pathname).to.equal("/clients/client-inscrit/paquet");
      await page.unroute("**/api/clients/client-inscrit/paquet");
      // Connexion finie : réelle (les témoins sont effacés) ; la demande n'est pas partie, et le chemin du retour est donné.
      await aller("/clients/essai-erreurs");
      await contexte.clearCookies();
      await page.locator(`${carte} form button[type="submit"]`).click();
      const finie = await lireRefus("session_absente");
      expect(finie[0]).to.equal("Votre connexion à l'outil a pris fin : votre action n'est pas partie.");
      expect(await page.locator('.nt-bandeau-erreur[data-refus="session_absente"] a[href="/connexion"]').innerText()).to.equal("Se reconnecter");
      expect(ecarts).to.deep.equal([]);
    } finally {
      plus.retirer();
    }
  });

  it("états cohérents et fiche courte : un travail « réussi » dont une étape est en échec se lit « Terminé, avec une étape en échec » sur la liste comme dans l'historique, jamais « réussi » ; à 1280 sur 800, le premier écran de la fiche montre l'avancement, la consigne et son bouton ; les actions qui ne servent pas dans l'état courant sont rangées, chacune avec ce qu'elle fait et quand s'en servir", async function () {
    const reussi = travailFictif(77, { slug: "essai-contradiction", commande: "inscrire-client", recu_a: DEBUT_ETAPES });
    const plus = ajouterClientFictif(donneesFictives, "essai-contradiction", ["capturee", "echec", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"], { confirmation: true, travaux: [reussi] });
    try {
      const { page, ecarts, aller } = await ouvrir();
      const carteListe = page.locator('article[data-client="essai-contradiction"]');
      expect(await carteListe.locator(".nt-pastille-refus").innerText()).to.equal("À reprendre");
      expect((await carteListe.innerText()).replace(/\s+/g, " ")).to.contain("Dernière action : Faire les étapes 2 à 5 (terminé, avec une étape en échec), le 12 novembre 2026 à 08:05 UTC.");
      expect(await carteListe.innerText()).to.not.match(/réussi/i);
      await aller("/clients/essai-contradiction");
      const historique = page.locator("details[data-historique]");
      expect(await historique.locator("> summary").innerText()).to.contain("la dernière : Faire les étapes 2 à 5 (terminé, avec une étape en échec)");
      await historique.locator("> summary").click();
      expect(await page.locator(`[data-travail="${reussi.id}"] .nt-pastille`).innerText()).to.equal("Terminé, avec une étape en échec");
      // La sortie exacte du travail, elle, n'est pas retouchée : elle dit toujours « reussi » dans le détail.
      expect(JSON.parse(await page.locator(`[data-travail="${reussi.id}"] details pre`).evaluate((x) => x.textContent)).result).to.equal("reussi");
      expect(await page.locator("main").innerText(), "aucun « Réussi » sur la fiche d'un client à reprendre").to.not.match(/Réussi/);
      // Le premier écran de la fiche : où en est le client, quoi faire, et le bouton.
      const premier = async (slug) => {
        await aller(`/clients/${slug}`);
        return page.evaluate(() => {
          const bas = (s) => { const e = document.querySelector(s); return e ? Math.round(e.getBoundingClientRect().bottom + window.scrollY) : null; };
          return { etat: bas("[data-etat-client]"), jauge: bas("progress.ins-jauge"), titre: bas("section.nt-essentiel h2"), phrase: bas("section.nt-essentiel .ins-essentiel-texte"), bouton: bas("section.nt-essentiel .nt-bouton-principal, section.nt-essentiel a.nt-bouton"), page: document.documentElement.scrollHeight };
        });
      };
      const hauteurs = {};
      for (const slug of ["client-neuf", "client-en-echec", "client-envoye", "client-inscrit", "essai-contradiction"]) {
        const h = await premier(slug);
        hauteurs[slug] = h.page;
        for (const quoi of ["etat", "jauge", "titre", "phrase", "bouton"]) expect(h[quoi], `${slug} : ${quoi} dans le premier écran`).to.be.at.most(800);
        // Une marge sous le bouton, pour une police plus large que celle du thème (celle d'un poste qui n'a pas Inter).
        expect(h.bouton, `${slug} : bouton à 40 px au moins du bas du premier écran`).to.be.at.most(760);
      }
      // La fiche à formulaire (demande signée à coller) montre au moins l'avancement et toute la consigne.
      const cours = await premier("client-en-cours");
      for (const quoi of ["etat", "jauge", "titre", "phrase"]) expect(cours[quoi], `client-en-cours : ${quoi}`).to.be.at.most(800);
      hauteurs["client-en-cours"] = cours.page;
      // La fiche est nettement plus courte qu'à la première passe (3 000 à 3 950 px selon l'état, mesurés à 1280 px).
      for (const [slug, h] of Object.entries(hauteurs)) expect(h, `${slug} : hauteur de la fiche`).to.be.at.most(2800);
      // Actions rangées : repliées, comptées, chacune avec ce qu'elle fait et quand s'en servir ; aucune n'a disparu.
      await aller("/clients/client-en-cours");
      const rares = page.locator("details[data-actions-rares]");
      expect(await rares.evaluate((x) => x.open)).to.equal(false);
      expect(await rares.locator("> summary").innerText()).to.match(/^Actions rarement utiles/);
      const actions = await rares.locator("details[data-action]").evaluateAll((l) => l.map((x) => ({ commande: x.getAttribute("data-action"), titre: x.querySelector("summary").textContent, texte: [...x.querySelectorAll(".nt-detail-corps > p")].map((p) => p.textContent) })));
      // Troisième lecture : l'envoi d'un document signé par le compte qu'une référence désigne (essais seulement) est une action rangée, à part.
      expect(actions.map((x) => x.commande).sort()).to.deep.equal(["administrer-jeu", "administrer-jeu-reference", "approvisionner", "capturer", "condense-administration", "condense-inscription", "inscrire-cle-reference", "inscrire-client"]);
      for (const x of actions) {
        expect(x.texte[0], x.commande).to.match(/^Ce que fait cette action : .{40,}\.$/);
        expect(x.texte[1], x.commande).to.match(/^Quand s'en servir : .{20,}\.$/);
        expect(motsTechniquesDans(`${x.titre}\n${x.texte.join("\n")}`), x.commande).to.deep.equal([]);
      }
      // L'action principale de l'état (envoyer la demande signée) est en haut, pas dans les actions rangées.
      expect(await page.locator('section.nt-essentiel form[data-commande="inscrire-cle"]').count()).to.equal(1);
      expect(ecarts).to.deep.equal([]);
    } finally {
      plus.retirer();
    }
  });

  it("seconde lecture des écrans : l'outil ne se contredit pas sur ce qui a été fait (liste, historique, confirmations d'un versement fait) ; chaque date d'un client porte son libellé ; une étiquette n'a qu'un sens, et les étapes du client se disent « À faire par le client » ; le formulaire de confirmation redit ce que le client confirme et n'envoie rien avant le second clic, qui envoie le même corps ; le paquet dit ce qu'il contient et ne contient pas ; un nom tiré au hasard renvoie au fichier des clients", async function () {
    const A = "a_faire";
    const FAIT = ["capturee", "capturee", "faite", "capturee"];
    const TIRE = "o-5d0c1f7a9b3e4c2d8a6f0e1b7c9d2a4f";
    const plus = [
      ajouterClientFictif(donneesFictives, "essai-sans-rien", [A, A, A, A, A, A, A]),
      ajouterClientFictif(donneesFictives, TIRE, [A, A, A, A, A, A, A], { confirmation: true, histoire: true }),
      ajouterClientFictif(donneesFictives, "essai-verse", [...FAIT, A, A, A], { histoire: true }),
      ajouterClientFictif(donneesFictives, "essai-verse-sans-trace", [...FAIT, A, A, A]),
      ajouterClientFictif(donneesFictives, "essai-chez-le-client", [...FAIT, "capturee", A, A], { histoire: true }),
      ajouterClientFictif(donneesFictives, "essai-registre", [...FAIT, "capturee", "envoyee", A], { histoire: true }),
      ajouterClientFictif(donneesFictives, "essai-envoi-nu", ["envoyee", A, A, A, A, A, A]),
    ];
    try {
      const { page, ecarts, aller, visible } = await ouvrir({ fuseau: "Europe/Zurich" });
      const plat = (x) => x.replace(/\s+/g, " ").trim();
      const sansMotTechnique = async (ecran) => expect(motsTechniquesDans(await page.evaluate(textePremierNiveau)), ecran).to.deep.equal([]);
      const carte = (slug) => page.locator(`article[data-client="${slug}"]`);
      const dates = async (slug) => plat(await carte(slug).locator("[data-dates-client]").innerText());
      const etiquette = (slug) => carte(slug).locator(".ins-pastilles .nt-pastille").first().innerText();
      const consigne = (slug) => carte(slug).locator("[data-prochaine-action]").getAttribute("data-prochaine-action");

      // 1. Liste. Rien n'a été lancé : la carte le dit, sans contredire sa « prochaine action » ; chaque date a son libellé.
      expect(await dates("essai-sans-rien")).to.equal("Dossier préparé le 12 novembre 2026 à 07:55 UTC. Vous n'avez encore rien lancé pour ce client.");
      expect(await dates("client-neuf")).to.equal("Dossier préparé le 12 novembre 2026 à 07:55 UTC. Dernière action : Préparer le dossier (réussi), le 12 novembre 2026 à 07:55 UTC.");
      expect(await visible()).to.not.match(/Aucune action pour l'instant/i);
      // Une étiquette, un sens : agir sous « Réponse à aller chercher » ; ne rien faire sous les deux autres.
      expect([await etiquette("client-envoye"), await consigne("client-envoye")]).to.deep.equal(["Réponse à aller chercher", "reprendre_envoi"]);
      expect([await etiquette("essai-envoi-nu"), await consigne("essai-envoi-nu")]).to.deep.equal(["Réponse à aller chercher", "reprendre_envoi"]);
      expect([await etiquette("essai-registre"), await consigne("essai-registre")]).to.deep.equal(["En attente du registre", "attendre_envoi"]);
      expect([await etiquette("essai-chez-le-client"), await consigne("essai-chez-le-client")]).to.deep.equal(["En attente chez le client", "attendre_premiere_periode"]);
      expect(await visible()).to.not.match(/Envoi en attente/);
      await sansMotTechnique("liste");

      // 2. Fiches. Les confirmations : ce qui est noté, et à quoi cela a servi. Un versement fait a sa confirmation,
      // utilisée ; les données fictives de l'essai sont cohérentes ; un versement sans confirmation est dit anormal.
      const confirmations = async (slug) => {
        await aller(`/clients/${slug}`);
        const l = page.locator("[data-confirmations-notees]");
        return [await l.innerText(), await l.getAttribute("data-confirmations-notees"), await l.getAttribute("data-anomalie")];
      };
      expect(await confirmations("client-inscrit")).to.deep.equal(["1 notée, utilisée pour le versement du 12 novembre 2026", "1", null]);
      expect(await confirmations("client-en-cours")).to.deep.equal(["1 notée, utilisée pour le versement du 12 novembre 2026", "1", null]);
      expect(await confirmations("essai-verse")).to.deep.equal(["1 notée, utilisée pour le versement du 12 novembre 2026", "1", null]);
      expect(await confirmations("client-envoye")).to.deep.equal(["1 notée, prête à servir", "1", null]);
      expect(await confirmations("client-en-echec")).to.deep.equal(["1 notée, prête à servir", "1", null]);
      expect(await confirmations("client-neuf")).to.deep.equal(["aucune notée", "0", null]);
      expect(await confirmations("essai-verse-sans-trace")).to.deep.equal(["aucune notée ici, alors que le versement est fait : ce n'est pas normal, prévenez l'équipe technique", "0", "versement_sans_confirmation"]);
      await sansMotTechnique("fiche, versement sans confirmation");
      // L'historique dit ce qu'il contient : les actions lancées depuis cet outil ; pour l'état du client, il renvoie aux étapes.
      const historique = page.locator("details[data-historique]");
      expect(plat(await historique.locator("> summary").innerText())).to.equal("Historique des actions lancées depuis cet outil aucune ; ce qui est fait se lit dans les étapes, plus haut");
      expect(await page.locator("ol.nt-etapes > li.nt-etape-faite").count(), "cinq étapes faites, sans action lancée d'ici").to.equal(5);
      await historique.locator("> summary").click();
      expect(await historique.locator("[data-historique-contenu]").innerText()).to.equal("Cet historique garde les actions lancées depuis cet outil pour ce client, les plus récentes d'abord. Il ne dit pas où en est le client : cela se lit dans « Les étapes de l'inscription », plus haut.");
      expect(await historique.innerText()).to.contain("Aucune action n'a été lancée depuis cet outil pour ce client.");
      expect(await page.locator("main").innerText()).to.not.match(/aucune action pour l'instant/i);
      // La fiche date elle aussi chaque chose par son nom : le dossier préparé, et la dernière action lancée d'ici.
      await aller("/clients/client-neuf");
      expect(plat(await page.locator("details[data-historique] > summary").innerText())).to.equal("Historique des actions lancées depuis cet outil 1 action ; la dernière : Préparer le dossier (réussi), le 12 novembre 2026 à 07:55 UTC");
      expect(plat(await page.locator("#org-titre").locator("xpath=..").locator("dl").first().innerText())).to.match(/Dossier préparé le 12 novembre 2026 à 07:55 UTC$/i);
      // Envoi resté sans réponse, aucune confirmation notée : l'écran ne dit qu'une chose, reprendre cet envoi.
      await aller("/clients/essai-envoi-nu");
      const nu = page.locator("section.nt-essentiel[data-prochaine-action]");
      expect(await nu.getAttribute("data-prochaine-action")).to.equal("reprendre_envoi");
      expect(await nu.innerText()).to.not.match(/confirmation du client/i);
      expect(await page.locator("[data-actions-utiles]").count()).to.equal(0);
      expect(await page.locator("[data-etat-client]").innerText()).to.equal("Réponse à aller chercher");
      expect(await nu.locator("> [data-apres-clic]").innerText()).to.contain("l'attend, quelques minutes d'ordinaire");
      // Étapes du client : « À faire par le client », jamais « À faire » tout court ; rien à lancer d'ici.
      await aller("/clients/essai-chez-le-client");
      expect(await page.locator("[data-etat-client]").innerText()).to.equal("En attente chez le client");
      expect(await page.locator('li.nt-etape[data-etape="premiere_ancre"] .nt-pastille, li.nt-etape[data-etape="premiere_cloture"] .nt-pastille').allInnerTexts()).to.deep.equal(["À faire par le client", "À faire par le client"]);
      expect(await page.locator("section.nt-essentiel > [data-apres-clic]").innerText()).to.equal("Cette fiche se met à jour quand ces deux étapes sont enregistrées dans le dossier. Cet outil ne sait pas quand le client les fera : si la fiche n'a pas changé à votre prochaine visite, demandez au client où il en est.");
      await sansMotTechnique("fiche, en attente chez le client");
      await aller("/clients/essai-registre");
      expect(await page.locator("[data-etat-client]").innerText()).to.equal("En attente du registre");
      expect(await page.locator('li.nt-etape[data-etape="premiere_ancre"] .nt-pastille').innerText()).to.equal("Envoyée");
      expect(await page.locator('li.nt-etape[data-etape="premiere_cloture"] .nt-pastille').innerText()).to.equal("À faire par le client");
      const attente = page.locator("section.nt-essentiel[data-prochaine-action]");
      expect(await attente.locator(".ins-essentiel-texte").first().innerText()).to.equal("Cette étape se fait chez le client, avec ses propres outils : vous n'avez rien à lancer d'ici. Elle est notée « Envoyée » depuis le 12 novembre 2026 à 10:00 UTC et attend la réponse du registre public. Le client a fait sa part : si la fiche n'a pas changé à votre prochaine visite, prévenez l'équipe technique.");
      expect(await attente.locator("form").count(), "aucune action à lancer").to.equal(0);
      expect(await attente.innerText(), "aucune durée inventée").to.not.match(/[0-9]+ (?:minutes?|heures?|jours?)|quelques (?:minutes|heures|jours)|une heure/);
      await sansMotTechnique("fiche, en attente du registre");
      // Un nom tiré au hasard ne dit pas qui est le client : la fiche et le formulaire renvoient au fichier des clients.
      await aller(`/clients/${TIRE}`);
      expect(await page.locator("[data-nom-tire]").innerText()).to.equal("Ce nom ne dit pas qui est le client : notez la correspondance dans votre fichier des clients.");
      await aller("/clients/client-neuf");
      expect(await page.locator("[data-nom-tire]").count(), "un nom libre n'est pas dit « tiré au hasard »").to.equal(0);
      await aller("/clients/nouveau");
      expect(plat(await page.locator('form[data-commande="inscrire-client-preparer"]').first().locator('[data-a-retenir="org"]').innerText())).to.equal("Ce nom ne dit pas qui est le client : notez la correspondance dans votre fichier des clients.");

      // 3. Formulaire de confirmation : en haut, ce que le client confirme (le montant et le compte) ; avant l'envoi,
      // un récapitulatif à relire ; rien ne part avant le second clic, qui envoie le corps que la route recevait déjà.
      const d = F.clients["client-neuf"].dossier;
      const compte = d.recorders[0].chain_key;
      await aller("/clients/client-neuf/confirmations");
      const f = page.locator('form[data-formulaire="confirmation"]');
      const rappel = f.locator("[data-ce-que-confirme]");
      expect(await rappel.evaluate((x) => Boolean(x.compareDocumentPosition(x.closest("form").querySelector('[name="personne_client"]')) & Node.DOCUMENT_POSITION_FOLLOWING)), "avant les champs à remplir").to.equal(true);
      expect(plat(await rappel.innerText())).to.contain(`Le versement de 327 000 000 crédits d'écriture sur le compte technique de son enregistreur rec-client-neuf-01, dont l'adresse est ${compte}.`);
      expect(plat(await rappel.innerText())).to.contain("c'est notre société qui les verse, depuis son compte de paiement.");
      expect(plat(await rappel.innerText())).to.contain("L'adresse : ne la dictez pas : 42 caractères ne se lisent pas à voix haute sans erreur.");
      await f.locator('[name="operation"]').selectOption("approvisionner");
      expect(plat(await rappel.innerText())).to.contain(`Un nouveau versement, qui complète le compte jusqu'à 327 000 000 crédits d'écriture, sur le compte technique de son enregistreur rec-client-neuf-01, dont l'adresse est ${compte}.`);
      await f.locator('[name="operation"]').selectOption("administrer-jeu");
      expect(plat(await rappel.innerText())).to.contain("Le changement de la liste de ses approbateurs que décrit le document dont vous donnez l'empreinte ci-dessus, et aucun autre.");
      await f.locator('[name="operation"]').selectOption("approvisionnement");
      const envois = [];
      page.on("request", (r) => {
        if (r.method() === "POST") envois.push(JSON.parse(r.postData()));
      });
      const piece = `0x${"ab".repeat(32)}`;
      await f.locator('[name="personne_client"]').fill("Camille Durand (personne fictive)");
      await f.locator('[name="canal"]').fill("courrier signé");
      await f.locator('[data-aide-saisie="date"]').fill("2026-11-17T10:12");
      await f.locator('[name="piece_sha256"]').fill(piece);
      const relire = f.locator('button[type="submit"]');
      const relu = f.locator("[data-relecture]");
      expect(await relire.innerText()).to.equal("Relire avant de noter");
      expect(await relu.count(), "pas de récapitulatif avant le premier clic").to.equal(0);
      await relire.click();
      await relu.waitFor();
      const lignes = async () => Object.fromEntries(await relu.locator("[data-relu]").evaluateAll((l) => l.map((x) => [x.getAttribute("data-relu"), [...x.children].map((s) => s.textContent.replace(/\s+/g, " ").trim()).join(" | ")])));
      expect(await lignes()).to.deep.equal({
        objet: `le versement de 327 000 000 crédits d'écriture sur le compte technique de son enregistreur rec-client-neuf-01, adresse ${compte}`,
        personne: "Camille Durand (personne fictive)",
        moyen: "courrier signé",
        date: "17 novembre 2026 à 10 h 12, heure de votre poste | soit, en temps universel : 17 novembre 2026 à 09:12 UTC",
        piece: "empreinte saisie à la main | son empreinte commence par 0xabababab et finit par abababab",
      });
      expect(await relu.locator("h3").innerText()).to.equal("Relisez avant de noter");
      expect(await f.locator('button[type="submit"]').count(), "le premier bouton laisse la place au second").to.equal(0);
      expect(await relu.locator("button").allInnerTexts()).to.deep.equal(["C'est exact, noter la confirmation", "Corriger"]);
      expect(envois, "rien n'est envoyé au premier clic").to.deep.equal([]);
      await sansMotTechnique("confirmation, récapitulatif à relire");
      // « Corriger » referme le récapitulatif ; une retouche d'un champ l'annule aussi : on ne note que ce qu'on a relu.
      await relu.locator("button[data-corriger]").click();
      expect(await relu.count()).to.equal(0);
      await relire.click();
      await relu.waitFor();
      await f.locator('[name="canal"]').fill("appel au numéro du contrat");
      expect(await relu.count(), "une retouche annule la relecture").to.equal(0);
      expect(envois).to.deep.equal([]);
      await relire.click();
      await relu.waitFor();
      expect((await lignes()).moyen).to.equal("appel au numéro du contrat");
      // Second clic : le corps est celui que la route recevait déjà, membre pour membre.
      const [demande] = await Promise.all([page.waitForRequest((r) => r.url().endsWith("/api/clients/client-neuf/confirmations") && r.method() === "POST"), relu.locator("button[data-noter]").click()]);
      expect(JSON.parse(demande.postData())).to.deep.equal({ operation: "approvisionnement", objet: { org_id: d.organisation.org_id, cle_chaine: compte }, personne_client: "Camille Durand (personne fictive)", canal: "appel au numéro du contrat", instant: "2026-11-17T09:12:00.000Z", piece_sha256: piece });
      await f.locator('.nt-bandeau-erreur[data-refus="agent_injoignable"]').waitFor();
      expect(envois).to.have.length(1);

      // 4. Paquet : ce qu'il contient, ce qu'il ne contient pas, à qui le remettre, ce que le client vérifie.
      await aller("/clients/client-inscrit/paquet");
      const clair = page.locator("[data-paquet-en-clair]");
      expect(await clair.evaluate((x) => x.closest("details") === null), "hors de tout bloc replié").to.equal(true);
      expect(await clair.locator("dt").evaluateAll((l) => l.map((x) => x.textContent))).to.deep.equal(["Ce qu'il contient", "Ce qu'il ne contient pas", "À qui le remettre", "Ce que le client vérifie"]);
      expect(plat(await clair.locator("[data-sans-secret]").innerText())).to.equal("Aucune clé secrète et aucun mot de passe : ni les nôtres, ni ceux du client. Avant de vous le proposer, l'outil a cherché dans chaque fichier les 2 clés secrètes de notre société qui ont servi à cette inscription : il n'en a trouvé aucune.");
      expect(await clair.locator("[data-sans-secret]").getAttribute("data-sans-secret")).to.equal(String(F.travaux[4].sortie.outputs.secrets_checked.count));
      expect(await visible()).to.not.match(/n'était à chercher|Recherche de secrets/i);
      await sansMotTechnique("paquet");
      expect(ecarts).to.deep.equal([]);
    } finally {
      for (const x of plus) x.retirer();
    }
  });

  it("troisième lecture des écrans : la fiche de chaque enregistreur se colle telle quelle dans sa zone, « Ajouter une autre fiche » en ouvre une autre, une zone vide ou un texte qui n'est pas une fiche est refusé sans rien envoyer, et le corps envoyé est, au caractère près, celui de la saisie à la main ; « Copier » met dans le presse-papiers l'adresse du compte technique et chaque empreinte à comparer ou à transmettre, ou sélectionne le texte si le navigateur refuse ; sur téléphone, une adresse et une empreinte se coupent en deux moitiés égales ; chaque pas du formulaire de confirmation a sa phrase ; les heures d'une fiche suivent l'ordre des étapes", async function () {
    const { lireChamp } = await import("../paquets/inscription/src/web/composants/champs-page.js");
    const FAIT = ["capturee", "capturee", "faite", "capturee"];
    const plus = [ajouterClientFictif(donneesFictives, "essai-changement", [...FAIT, "capturee", "a_faire", "a_faire"], { histoire: true })];
    // Un document de changement des approbateurs préparé, pas encore envoyé : son empreinte se reporte sur la confirmation.
    const changement = { version: 0, operation: "administration_jeu", digest: `0x${"5e".repeat(32)}`, signatures: [], prepared_at: "2026-11-13T09:00:00.000Z" };
    fs.mkdirSync(path.join(donneesFictives, "clients", "essai-changement", "demandes"), { recursive: true });
    fs.writeFileSync(path.join(donneesFictives, "clients", "essai-changement", "demandes", `demande-administration-trv-${"0".repeat(30)}55.json`), JSON.stringify(changement, null, 2));
    try {
      const { page, ecarts, aller, contexte } = await ouvrir();
      await contexte.grantPermissions(["clipboard-read", "clipboard-write"], { origin: web.url });
      const plat = (x) => x.replace(/\s+/g, " ").trim();

      // 1. Nouveau client : une zone par fiche, collée telle quelle.
      await aller("/clients/nouveau");
      const forme = page.locator('form[data-commande="inscrire-client-preparer"]').first();
      const zones = forme.locator('[data-fiches="cles_enregistreur"] textarea[name="cles_enregistreur"]');
      expect(await zones.count()).to.equal(1);
      expect(await zones.first().getAttribute("data-type")).to.equal("liste_documents");
      expect(await forme.locator(`label[for="${await zones.first().getAttribute("id")}"]`).innerText()).to.equal("Fiche de l'enregistreur du client");
      const aide = await forme.locator(`[id="${await zones.first().getAttribute("id")}-aide"]`).innerText();
      expect(aide).to.equal("À son installation, l'enregistreur du client produit une fiche : un petit fichier de texte qui le décrit, lui et son compte technique, sans aucun secret. Le client vous envoie ce fichier. Ouvrez-le, copiez tout son contenu et collez-le ici, sans rien y ajouter ni retirer. Si le client a plusieurs enregistreurs, il vous envoie une fiche pour chacun : cliquez sur « Ajouter une autre fiche » pour chacune des suivantes.");
      expect(await page.locator("main").innerText(), "plus de crochets ni de virgules à taper").to.not.match(/crochet|séparez les fiches/);
      const envois = [];
      page.on("request", (r) => {
        if (r.method() === "POST") envois.push(r.postData());
      });
      const APP = ["0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"];
      await forme.locator('[name="org"]').fill("essai-fiches");
      await forme.locator('[name="journaux"]').fill("journal-principal");
      await forme.locator('[name="approbateurs"]').fill(APP.join("\n"));
      await forme.locator('[name="seuil"]').fill("2");
      await forme.locator('[name="admin_jeu"]').fill("0x15d34aaf54267db7d7c367839aaf71a00a2c6a65");
      const fiche = (n) => F.clients[n].dossier.recorders[0];
      const t1 = JSON.stringify(fiche("client-neuf"), null, 2);
      const t2 = `\n${JSON.stringify(fiche("client-en-cours"), null, 4)}\n\n`;
      const refus = async (zone, attendu) => {
        await forme.locator('button[type="submit"]').click();
        const e = forme.locator(`[data-zone="${zone}"] p.nt-erreur[role="alert"]`);
        await e.waitFor();
        expect(await e.innerText()).to.equal(attendu);
        expect(await zones.nth(zone).getAttribute("aria-invalid")).to.equal("true");
        expect(await page.evaluate(() => document.activeElement?.getAttribute("name"))).to.equal("cles_enregistreur");
        expect(envois, "rien n'est envoyé").to.deep.equal([]);
      };
      // Une zone vide, une liste entre crochets, un texte qui n'est pas une fiche entière : refusés, avec quoi faire.
      // La première zone vide : refusée (une liste vide n'est pas admise par la page), avec la raison.
      await refus(0, "Cette zone est vide. Collez-y tout le contenu du fichier que le client vous a envoyé pour son enregistreur, sans rien y changer. Il faut au moins une fiche : l'outil n'inscrit au registre public que les enregistreurs dont la fiche est donnée ici, et il ne pourra plus en ajouter une fois le dossier préparé.");
      await zones.first().fill("[]");
      await refus(0, "Cette zone contient une liste entre crochets « [ » et « ] », et non une seule fiche. Collez ici le contenu d'un seul fichier, tel que le client l'a envoyé ; pour une autre fiche, cliquez sur « Ajouter une autre fiche ».");
      const illisible = "Ce texte n'est pas une fiche d'enregistreur, ou il en manque une partie. Ouvrez le fichier que le client vous a envoyé, copiez tout son contenu, du premier caractère « { » au dernier « } », et collez-le ici sans rien y changer. Si le fichier ne commence pas par « { », demandez au client de vous le renvoyer.";
      await zones.first().fill(t1.slice(0, -1));
      await refus(0, illisible);
      await zones.first().fill(JSON.stringify({ key_id: "rec-client-neuf-01" }));
      await refus(0, illisible);
      expect(await forme.locator("p.nt-erreur").innerText(), "la valeur refusée n'est pas recopiée").to.not.contain("rec-client-neuf-01");
      // Une autre fiche : sa zone s'ajoute, vide ; laissée vide, elle est refusée, et peut se retirer.
      await zones.first().fill(t1);
      await forme.locator("[data-ajouter-fiche]").click();
      expect(await zones.count()).to.equal(2);
      expect(await forme.locator(`label[for="${await zones.nth(1).getAttribute("id")}"]`).innerText()).to.equal("Fiche d'un autre enregistreur du client (fiche 2)");
      await refus(1, "Cette zone est vide. Collez-y tout le contenu du fichier que le client vous a envoyé pour son enregistreur, sans rien y changer. Si vous n'avez pas d'autre fiche, cliquez sur « Retirer cette zone ».");
      await forme.locator('[data-retirer-fiche="1"]').click();
      expect(await zones.count()).to.equal(1);
      expect(await zones.first().inputValue(), "la première fiche reste").to.equal(t1);
      // Le corps est celui que donnait la saisie à la main de « [ fiche ] » dans une seule zone, au caractère près.
      const corps = (textes) => JSON.stringify({ commande: "inscrire-client-preparer", slug: "essai-fiches", parametres: { org: "essai-fiches", journaux: ["journal-principal"], approbateurs: APP, seuil: 2, admin_jeu: "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65", cles_enregistreur: lireChamp({ nom: "cles_enregistreur", type: "liste_documents" }, `[${textes.join(",")}]`).valeur } });
      const [une] = await Promise.all([page.waitForRequest((r) => r.url().endsWith("/api/travaux") && r.method() === "POST"), forme.locator('button[type="submit"]').click()]);
      expect(une.postData()).to.equal(corps([t1]));
      expect(JSON.parse(une.postData()).parametres.cles_enregistreur).to.deep.equal([fiche("client-neuf")]);
      // La route accepte cette forme ; le refus qui suit est celui du service d'inscription, absent de cet essai.
      await page.locator('.nt-bandeau-erreur[data-refus="agent_injoignable"]').waitFor();
      // Deux fiches : deux zones, dans l'ordre ; le corps est celui de « [ fiche, fiche ] ».
      await forme.locator("[data-ajouter-fiche]").click();
      await zones.nth(1).fill(t2);
      const [deux] = await Promise.all([page.waitForRequest((r) => r.url().endsWith("/api/travaux") && r.method() === "POST"), forme.locator('button[type="submit"]').click()]);
      expect(deux.postData()).to.equal(corps([t1, t2]));
      expect(JSON.parse(deux.postData()).parametres.cles_enregistreur).to.deep.equal([fiche("client-neuf"), fiche("client-en-cours")]);
      expect(motsTechniquesDans(await page.evaluate(textePremierNiveau))).to.deep.equal([]);

      // 2. Copier : l'adresse du compte technique (fiche, formulaire de confirmation, carte d'une confirmation) et chaque
      // empreinte qui se compare ou se transmet (pièce, document de changement, paquet). Rien d'autre n'est envoyé.
      const copier = async (zone, valeur, forme_) => {
        const v = zone.locator(`[data-a-copier="${forme_}"]`).first();
        expect(await v.locator("[data-valeur]").innerText()).to.equal(valeur);
        await page.evaluate(() => navigator.clipboard.writeText("vide"));
        const avant = envois.length;
        await v.locator("button[data-copier]").click();
        await page.waitForFunction((x) => navigator.clipboard.readText().then((t) => t === x), valeur);
        expect(await v.locator("[data-copie-etat]").innerText()).to.equal("Copié.");
        expect(envois.length, "la copie n'envoie rien").to.equal(avant);
        return v;
      };
      const dNeuf = F.clients["client-neuf"].dossier;
      await aller("/clients/client-neuf");
      const adresseFiche = await copier(page.locator("section.nt-essentiel"), dNeuf.recorders[0].chain_key, "adresse");
      expect(await adresseFiche.locator("button[data-copier]").innerText()).to.equal("Copier l'adresse");
      // Le navigateur refuse la copie : le texte exact est sélectionné, et la phrase dit comment le copier au clavier.
      await page.evaluate(() => { navigator.clipboard.writeText = () => Promise.reject(new Error("refusé")); });
      await adresseFiche.locator("button[data-copier]").click();
      await adresseFiche.locator("[data-copie-etat]:not(:empty)").waitFor();
      expect(await adresseFiche.locator("[data-copie-etat]").innerText()).to.equal("La copie automatique n'a pas pu se faire : le texte est sélectionné, copiez-le au clavier (Ctrl+C, ou Cmd+C sur Mac).");
      expect(await page.evaluate(() => String(window.getSelection()))).to.equal(dNeuf.recorders[0].chain_key);
      await aller("/clients/client-neuf/confirmations");
      await copier(page.locator("[data-ce-que-confirme]"), dNeuf.recorders[0].chain_key, "adresse");
      await aller("/clients/client-en-cours/confirmations");
      const carte = page.locator(`[data-confirmation="${F.confirmations[0].id}"]`);
      await copier(carte, F.confirmations[0].objet.cle_chaine, "adresse");
      expect(await (await copier(carte, F.confirmations[0].piece_sha256, "empreinte")).locator("[data-piece]").innerText()).to.equal(F.confirmations[0].piece_sha256);
      await aller("/clients/client-inscrit/paquet");
      await copier(page.locator("section.nt-essentiel"), F.manifestePaquet, "empreinte");
      await aller("/clients/essai-changement");
      const doc = page.locator('[data-demande^="demande-administration-"]');
      expect(plat(await doc.locator("[data-empreinte-document]").innerText())).to.equal(`Son empreinte, à reporter telle quelle sur la confirmation du client : ${changement.digest} Copier l'empreinte`);
      await copier(doc, changement.digest, "empreinte");
      // Ce changement préparé attend sa confirmation : le formulaire est déployé ; l'aide dit où copier l'empreinte.
      await aller("/clients/essai-changement/confirmations");
      expect(await page.locator("section[data-confirmation-attendue]").getAttribute("data-confirmation-attendue")).to.equal("administrer-jeu");
      await page.locator('form[data-formulaire="confirmation"] [name="operation"]').selectOption("administrer-jeu");
      expect(await page.locator(`[id="${await page.locator('[name="digest"]').getAttribute("id")}-aide"]`).innerText()).to.equal("L'empreinte du document que le client a confirmé. Elle est sur la fiche du client, sous « Documents à faire signer par le client », avec un bouton « Copier l'empreinte ». Collez-la ici sans la retaper : « 0x » suivi de 64 caractères.");

      // 3. Formulaire de confirmation : chaque pas a sa phrase, sous son bouton, et seulement à ce pas.
      await aller("/clients/client-neuf/confirmations");
      const f = page.locator('form[data-formulaire="confirmation"]');
      const phrases = () => f.locator("[data-phrase-du-pas]").evaluateAll((l) => l.map((x) => [x.getAttribute("data-phrase-du-pas"), x.textContent]));
      expect(await phrases()).to.deep.equal([["relire", "Ce bouton n'enregistre rien : il vous montre ce que vous allez noter."]]);
      expect(await f.locator('button[type="submit"]').getAttribute("aria-describedby")).to.equal(await f.locator('[data-phrase-du-pas="relire"]').getAttribute("id"));
      expect(await f.locator(".nt-bandeau-avertissement").innerText(), "plus de « premier bouton » à côté du bouton définitif").to.not.match(/premier bouton|n'envoie rien/);
      await f.locator('[name="personne_client"]').fill("Camille Durand (personne fictive)");
      await f.locator('[name="canal"]').fill("courrier signé");
      await f.locator('[data-aide-saisie="date"]').fill("2026-11-17T10:12");
      await f.locator('[name="piece_sha256"]').fill(`0x${"ab".repeat(32)}`);
      await f.locator('button[type="submit"]').click();
      await f.locator("[data-relecture]").waitFor();
      expect(await phrases()).to.deep.equal([["noter", "Ce bouton enregistre la confirmation. Elle ne pourra plus être effacée."]]);
      expect(await f.locator("button[data-noter]").getAttribute("aria-describedby")).to.equal(await f.locator('[data-phrase-du-pas="noter"]').getAttribute("id"));
      expect(await f.locator("button[data-noter]").evaluate((b) => Boolean(b.compareDocumentPosition(b.parentElement.querySelector('[data-phrase-du-pas="noter"]')) & Node.DOCUMENT_POSITION_FOLLOWING)), "la phrase est sous le bouton qui note").to.equal(true);
      expect(envois.filter((x) => (x ?? "").includes("personne_client")), "rien n'est noté avant le second clic").to.deep.equal([]);

      // 4. Heures : sur chaque fiche, les étapes sont datées dans leur ordre ; un même échec a une seule heure, partout.
      for (const slug of ["client-en-cours", "client-en-echec", "client-envoye", "client-inscrit", "essai-changement"]) {
        await aller(`/clients/${slug}`);
        const instants = await page.locator("ol.nt-etapes > li.nt-etape").evaluateAll((l) => l.map((x) => [...x.querySelectorAll("dt")].find((t) => t.textContent.trim() === "Instant exact")?.nextElementSibling?.textContent.trim()).filter(Boolean));
        expect(instants.length, slug).to.be.greaterThan(1);
        expect(instants, `${slug} : étapes datées dans leur ordre`).to.deep.equal([...instants].sort());
      }
      await aller("/clients/client-en-echec");
      const heureEchec = await page.locator('li.nt-etape[data-etape="assignation"] .ins-resultat time').innerText();
      expect(heureEchec).to.equal("12 novembre 2026 à 08:05 UTC");
      expect(await page.locator("details[data-historique] > summary").innerText()).to.contain(`la dernière : Faire les étapes 2 à 5 (échec), le ${heureEchec}`);
      await aller("/clients");
      expect(plat(await page.locator('article[data-client="client-en-echec"] [data-derniere-action]').innerText())).to.equal(`Dernière action : Faire les étapes 2 à 5 (échec), le ${heureEchec}.`);
      expect(ecarts).to.deep.equal([]);

      // 5. Sur téléphone : une adresse se coupe en deux moitiés de 21 caractères, une empreinte en deux de 33 ; rien ne déborde.
      const tel = await ouvrir({ largeur: 390, hauteur: 844 });
      const coupe = (loc) => loc.evaluate((e) => {
        const n = e.firstChild;
        const r = document.createRange();
        const lignes = [];
        let haut = null;
        for (let k = 0; k < n.length; k++) {
          r.setStart(n, k);
          r.setEnd(n, k + 1);
          const y = Math.round(r.getBoundingClientRect().top);
          if (y !== haut) lignes.push(0);
          haut = y;
          lignes[lignes.length - 1]++;
        }
        return lignes;
      });
      const sansDebord = () => tel.page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth);
      await tel.aller("/clients/client-neuf");
      expect(await coupe(tel.page.locator("section.nt-essentiel .ins-adresse"))).to.deep.equal([21, 21]);
      expect(await sansDebord()).to.equal(true);
      await tel.aller("/clients/client-neuf/confirmations");
      expect(await coupe(tel.page.locator("[data-ce-que-confirme] .ins-adresse"))).to.deep.equal([21, 21]);
      await tel.aller("/clients/client-en-cours/confirmations");
      expect(await coupe(tel.page.locator("[data-piece]"))).to.deep.equal([33, 33]);
      expect(await coupe(tel.page.locator(`[data-confirmation="${F.confirmations[0].id}"] .ins-adresse`))).to.deep.equal([21, 21]);
      expect(await sansDebord()).to.equal(true);
      await tel.aller("/clients/client-inscrit/paquet");
      expect(await coupe(tel.page.locator("[data-manifeste-paquet]"))).to.deep.equal([33, 33]);
      expect(await tel.page.locator("[data-manifeste-paquet]").innerText(), "la valeur reste entière").to.equal(F.manifestePaquet);
      expect(await sansDebord()).to.equal(true);
      expect(tel.ecarts).to.deep.equal([]);
    } finally {
      for (const x of plus) x.retirer();
    }
  });
});
