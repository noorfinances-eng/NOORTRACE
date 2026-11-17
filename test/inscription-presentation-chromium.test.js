// Inscription des clients : les écrans de l'interface d'exploitant dans Chromium, par Playwright (complément du
// 2026-11-17, décision du porteur sur la présentation des écrans ; CT-4 §7.14, EX-7.16, EX-7.25, EX-7.26 ;
// paquets/inscription/INTERFACES.md 2.2). L'interface est construite par l'essai (`next build`, sans réseau
// extérieur) puis servie par son binaire, sur des données fictives écrites à la main
// (test/fixtures/inscription/donnees-fictives.mjs) : aucun agent, aucune chaîne. L'essai lit ce que l'exploitant
// voit : le texte rendu (un bloc replié fermé n'en fait pas partie), les états, les blocs repliés, le thème.
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
import { ecrireDonneesFictives } from "./fixtures/inscription/donnees-fictives.mjs";

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
  const ouverts = [];

  before(async function () {
    const { playwright, raison } = chargerPlaywright();
    if (!playwright) {
      indisponible = raison;
      return;
    }
    try {
      navigateur = await playwright.chromium.launch();
    } catch (e) {
      indisponible = `Chromium ne se lance pas (${String(e.message).split("\n")[0]})`;
      return;
    }
    dir = O.repertoireTemporaire("noortrace-inscription-ecrans-");
    const donnees = path.join(dir, "donnees");
    fs.mkdirSync(donnees);
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
  async function ouvrir({ largeur = 1280, hauteur = 800, connecte = true, stockage = null } = {}) {
    const contexte = await navigateur.newContext({ viewport: { width: largeur, height: hauteur }, locale: "fr-FR" });
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
      if (m.type() === "error" && !/status of 401/.test(m.text())) ecarts.push(m.text());
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
    return { page, ecarts, aller, visible };
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
    expect(await barre.locator(".nt-session").innerText()).to.contain(`exploitant ${NOM}`);
    expect(await barre.getByRole("button", { name: "Se déconnecter" }).count()).to.equal(1);
    expect(await barre.locator("button.nt-bascule").count()).to.equal(1);
    expect(await page.locator("[data-reseau-essai]").innerText()).to.match(/Réseau d'essai/);
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
    expect(enCours.action).to.match(/Faire signer la demande/);
    expect(enCours.dates).to.deep.equal([["2026-11-12T08:10:00.000Z", "12 novembre 2026 à 08:10 UTC"]]);
    expect((await lire("client-neuf")).avancement).to.equal("1 étape sur 8");
    expect((await lire("client-neuf")).code).to.equal("consigner_confirmation");
    expect((await lire("client-en-echec")).code).to.equal("conduire_etapes");
    expect((await lire("client-en-echec")).action).to.match(/Reprendre les étapes 2 à 5/);
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
    expect(await essentiel.locator('form[data-commande="inscrire-cle"] button[type="submit"]').innerText()).to.equal("Relayer la demande signée");
    // La carte « essentiel » précède les étapes dans l'ordre de lecture.
    expect(await page.evaluate(() => Boolean(document.querySelector("section.nt-essentiel").compareDocumentPosition(document.querySelector("ol.nt-etapes")) & Node.DOCUMENT_POSITION_FOLLOWING))).to.equal(true);
    const etapes = await page.locator("ol.nt-etapes > li.nt-etape").evaluateAll((l) => l.map((x) => ({ code: x.getAttribute("data-etape"), etat: x.getAttribute("data-etat"), classes: x.className, titre: x.querySelector(".nt-etape-titre").innerText.replace(/\s+/g, " ").trim(), texte: [...x.querySelectorAll(".nt-etape-texte")].map((p) => p.innerText).join(" ") })));
    expect(etapes.map((e) => e.code)).to.deep.equal(["preparation", "jeu_approbateurs", "assignation", "lecture_jeu", "approvisionnement", "inscription", "premiere_ancre", "premiere_cloture"]);
    expect(etapes.map((e) => e.etat)).to.deep.equal(["faite", "capturee", "capturee", "faite", "capturee", "a_faire", "a_faire", "a_faire"]);
    expect(etapes.map((e) => e.titre)).to.deep.equal([
      "Étape 1 : Préparer le dossier Fait", "Étape 2 : Créer le jeu d'approbateurs Fait", "Étape 3 : Assigner le jeu à l'organisation Fait", "Étape 4 : Relire le jeu Fait",
      "Étape 5 : Approvisionner la clé de chaîne Fait", "Étape 6 : Inscrire la clé d'enregistreur À faire", "Étape 7 : Première ancre À faire", "Étape 8 : Première clôture À faire",
    ]);
    expect(etapes[1].classes).to.contain("nt-etape-faite");
    expect(etapes[5].classes).to.contain("nt-etape-a-faire");
    expect(etapes[1].texte).to.contain("Déploie sur le registre le jeu d'approbateurs du client");
    expect(etapes[1].texte).to.match(/incluse au bloc 100 et capturée/);
    expect(etapes[3].texte).to.match(/sans transaction/);
    for (const e of etapes) expect(e.texte, e.code).to.match(/[a-zé]\./);
    expect(await visible()).to.not.match(CODE_BRUT);

    // Étape en échec : pastille « Échec », bandeau d'erreur au-dessus des étapes, avec la conduite à tenir.
    await aller("/clients/client-en-echec");
    expect(await page.locator("[data-etat-client]").innerText()).to.equal("À reprendre");
    const bandeau = page.locator('.nt-bandeau-erreur[role="alert"]').first();
    expect(await bandeau.innerText()).to.match(/Assigner le jeu à l'organisation/);
    expect(await bandeau.innerText()).to.match(/relit d'abord l'état de la chaîne/);
    expect(await page.evaluate(() => Boolean(document.querySelector(".nt-bandeau-erreur").compareDocumentPosition(document.querySelector("ol.nt-etapes")) & Node.DOCUMENT_POSITION_FOLLOWING)), "le bandeau précède les étapes").to.equal(true);
    expect(await page.locator('li.nt-etape[data-etape="assignation"]').getAttribute("class")).to.contain("nt-etape-echec");
    expect(await page.locator('li.nt-etape[data-etape="assignation"] .nt-pastille-refus').innerText()).to.equal("Échec");
    expect(await page.locator("section.nt-essentiel[data-prochaine-action]").getAttribute("data-prochaine-action")).to.equal("conduire_etapes");
    expect(await page.locator('section.nt-essentiel form[data-commande="inscrire-client"] button[type="submit"]').innerText()).to.equal("Reprendre les étapes 2 à 5");
    expect(await visible()).to.not.match(CODE_BRUT);

    // Envoi sans reçu : « Envoyée », en cours.
    await aller("/clients/client-envoye");
    expect(await page.locator('li.nt-etape[data-etape="jeu_approbateurs"]').getAttribute("class")).to.contain("nt-etape-en-cours");
    expect(await page.locator('li.nt-etape[data-etape="jeu_approbateurs"] .nt-pastille-info').innerText()).to.equal("Envoyée");

    // Client neuf : la confirmation hors bande d'abord, par un lien vers son registre.
    await aller("/clients/client-neuf");
    const neuf = page.locator("section.nt-essentiel[data-prochaine-action]");
    expect(await neuf.getAttribute("data-prochaine-action")).to.equal("consigner_confirmation");
    expect(await neuf.locator('a[href="/clients/client-neuf/confirmations"]').innerText()).to.equal("Consigner la confirmation");

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
    const premier = travaux.first();
    expect(await premier.innerText()).to.match(/Préparer la demande d'inscription/);
    expect(await premier.innerText()).to.match(/Réussi/);
    expect(await premier.innerText()).to.match(/12 novembre 2026 à 08:10 UTC/);
    expect(JSON.parse(await premier.locator("details pre").evaluate((x) => x.textContent))).to.deep.equal(F.travaux[2].sortie);
    const demande = page.locator("[data-demande]").first();
    expect(await demande.innerText()).to.match(/à faire signer hors de (cette |l')application/i);
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
    expect(texte).to.match(/Consommée/);
    expect(texte).to.match(/Approvisionnement/);
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
    expect(await page.locator(`[data-confirmation="${F.confirmations[1].id}"]`).innerText()).to.match(/Disponible/);
    // Paquet produit : téléchargement et empreinte du manifeste, en entier, hors de tout bloc replié.
    await aller("/clients/client-inscrit/paquet");
    const manifeste = page.locator("[data-manifeste-paquet]");
    expect(await manifeste.innerText()).to.equal(F.manifestePaquet);
    expect(await manifeste.evaluate((x) => x.closest("details") === null)).to.equal(true);
    expect(await page.locator('a[href="/api/clients/client-inscrit/paquet"]').innerText()).to.match(/Télécharger/);
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
    expect(await forme.locator("fieldset legend").allInnerTexts()).to.deep.equal(["L'organisation", "Les approbateurs", "Les clés d'enregistreur", "Le financement"]);
    const champs = await forme.locator("[name]").evaluateAll((l) => l.map((x) => ({ nom: x.getAttribute("name"), type: x.getAttribute("data-type"), libelles: x.id ? document.querySelectorAll(`label[for="${x.id}"]`).length : 0, aide: (x.getAttribute("aria-describedby") ?? "").split(" ").filter(Boolean).map((i) => document.getElementById(i)?.innerText ?? "").join(" ") })));
    expect(champs.map((x) => x.nom)).to.deep.equal(["org", "journaux", "approbateurs", "seuil", "admin_jeu", "cles_enregistreur", "budget_jour", "tresorerie"]);
    for (const x of champs) {
      expect(x.libelles, `libellé de ${x.nom}`).to.equal(1);
      expect(x.aide, `aide de ${x.nom}`).to.match(/\.$/);
    }
    expect(await forme.locator('label[for]').first().innerText()).to.equal("Nom court de l'organisation");
    const texte = await visible();
    expect(texte).to.not.match(CODE_BRUT);
    expect(texte).to.not.match(/RG-1|RG-2|EX-[0-9]/);
    const exemples = await page.locator("[placeholder]").evaluateAll((l) => l.map((x) => x.getAttribute("placeholder")).filter(Boolean));
    expect(exemples.length).to.be.greaterThan(2);
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
});
