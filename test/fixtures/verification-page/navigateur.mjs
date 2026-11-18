// Hébergement de test de la page de vérification dans un navigateur piloté
// par Playwright (version mesurée : 1.56.1, installée sans être ajoutée à
// package.json) : origine HTTPS fictive https://verification.example, servie
// par interception des requêtes, avec les en-têtes d'en-tetes.json (EX-18.12).
// Toute requête est relevée ; une requête vers une autre adresse reçoit 404.

import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

export const ORIGINE = "https://verification.example";
/** Entrée de l'essai sous Gecko (voir ouvrir) : hors des fichiers de la page, jamais relevée. */
const ENTREE_GECKO = `${ORIGINE}/.entree-essai-gecko`;
const ENTETES_ENTREE_GECKO = { "Content-Type": "text/html; charset=utf-8", "Cross-Origin-Opener-Policy": "same-origin", "Content-Security-Policy": "default-src 'none'" };

/** Playwright, ou { raison } s'il n'est pas installé. */
export function chargerPlaywright() {
  try {
    return { playwright: createRequire(import.meta.url)("playwright") };
  } catch (e) {
    return { raison: `Playwright absent (require("playwright") : ${e.code ?? e.message})` };
  }
}

/** Lance le moteur `nom` (chromium, firefox, webkit), ou rend { raison }. */
export async function lancer(nom) {
  const { playwright, raison } = chargerPlaywright();
  if (!playwright) return { raison };
  try {
    const navigateur = await playwright[nom].launch();
    return { navigateur };
  } catch (e) {
    return { raison: `${nom} ne se lance pas : ${String(e.message).split("\n")[0]}` };
  }
}

/**
 * Ouvre la page servie depuis `repertoire` ; `remplacements` : nom → octets
 * servis à la place du fichier. Rend { page, contexte, requetes, reponses,
 * messages, marquer(), requetesDepuisMarque() }.
 */
export async function ouvrir(navigateur, repertoire, { remplacements = {}, langue = "fr-FR", fuseau = "Asia/Kathmandu" } = {}) {
  const entetes = JSON.parse(fs.readFileSync(path.join(repertoire, "en-tetes.json"), "utf8"));
  const contexte = await navigateur.newContext({ locale: langue, timezoneId: fuseau });
  const requetes = [];
  const reponses = new Map();
  const messages = [];
  contexte.on("request", (r) => {
    if (r.url() !== ENTREE_GECKO) requetes.push({ url: r.url(), methode: r.method(), corps: r.postData() });
  });
  contexte.on("response", async (r) => {
    if (r.url() === ENTREE_GECKO) return;
    try {
      reponses.set(r.url(), await r.allHeaders());
    } catch {
      // réponse déjà libérée
    }
  });
  await contexte.route("**/*", async (route) => {
    const u = new URL(route.request().url());
    const nom = u.pathname === "/" ? "index.html" : u.pathname.slice(1);
    if (u.origin !== ORIGINE || !Object.hasOwn(entetes, nom) || u.search !== "") {
      await route.fulfill({ status: 404, headers: { "Content-Type": "text/plain; charset=utf-8" }, body: "" });
      return;
    }
    const corps = Object.hasOwn(remplacements, nom) ? remplacements[nom] : fs.readFileSync(path.join(repertoire, nom));
    await route.fulfill({ status: 200, headers: entetes[nom], body: corps });
  });
  // Violations de politique signalées au document (relevé d'essai, hors de la page).
  await contexte.addInitScript(() => {
    globalThis.__violationsEssai = [];
    document.addEventListener("securitypolicyviolation", (e) => {
      globalThis.__violationsEssai.push(`${e.violatedDirective} ${e.blockedURI}`);
    });
  });
  // Gecko (Firefox 142.0.1 de Playwright 1.56.1) : la première navigation d'une page neuve, de about:blank vers un
  // document servi sous Cross-Origin-Opener-Policy: same-origin (EX-18.12), change de groupe de contextes de
  // navigation, et Playwright perd parfois le document chargé : ni DOMContentLoaded ni load ne lui parviennent, son
  // contexte d'exécution est « détruit », page.goto ne rend jamais la main (constaté le 2026-11-11 : 1 navigation sur
  // 8 à 15 sous la charge de npm test, aucune en 60 sans cet en-tête ; Chromium et WebKit non touchés ; toutes les
  // requêtes de la page servies). La page est hors de cause : la première navigation se fait donc vers une entrée de
  // même origine et de même politique d'ouverture, reprise dans une page neuve si elle se bloque (au plus deux
  // reprises, comptées dans `reprisesEntree`) ; la navigation vers index.html qui suit ne change plus de groupe.
  // Hors de ce blocage, page.goto dure de 0,7 à 1 s, seul comme sous la charge : le délai de Playwright (30 s) suffit.
  let page;
  let reprisesEntree = 0;
  await contexte.route(ENTREE_GECKO, (route) => route.fulfill({ status: 200, headers: ENTETES_ENTREE_GECKO, body: "<!DOCTYPE html><title>entrée de l'essai</title>" }));
  for (;;) {
    page = await contexte.newPage();
    if (navigateur.browserType().name() !== "firefox") break;
    try {
      await page.goto(ENTREE_GECKO, { timeout: 15000 });
      break;
    } catch (e) {
      if (!/Timeout/.test(e.message) || ++reprisesEntree > 2) throw e;
      process.stderr.write(`page de vérification, firefox : première navigation bloquée (changement de groupe de contextes), reprise ${reprisesEntree}\n`);
      await page.close();
    }
  }
  page.on("console", (m) => {
    if (m.type() === "error" || m.type() === "warning") messages.push(`${m.type()} : ${m.text()}`);
  });
  page.on("pageerror", (e) => messages.push(`erreur de page : ${e.message}`));
  if (navigateur.browserType().name() === "chromium") {
    const cdp = await contexte.newCDPSession(page);
    await cdp.send("Log.enable");
    cdp.on("Log.entryAdded", (e) => {
      if (e.entry.level === "error" || e.entry.level === "warning") messages.push(`journal ${e.entry.source} : ${e.entry.text}`);
    });
  }
  let marque = 0;
  return {
    page,
    contexte,
    reprisesEntree,
    requetes,
    reponses,
    messages,
    marquer() {
      marque = requetes.length;
    },
    requetesDepuisMarque() {
      return requetes.slice(marque);
    },
    async violations() {
      return page.evaluate(() => globalThis.__violationsEssai.slice());
    },
    async fermer() {
      await contexte.close();
    },
  };
}

/** Attend la fin du chargement de l'artefact ; rend le texte de #artefact. */
export async function attendreArtefact(page) {
  await page.waitForFunction(() => {
    const t = document.getElementById("artefact").textContent;
    return !t.startsWith("Chargement") && !t.startsWith("Loading");
  }, null, { timeout: 120000 });
  return page.textContent("#artefact");
}

/**
 * Choisit le répertoire `chemin` dans le champ `#entree-repertoire` de la page.
 *
 * Pour un répertoire, Playwright 1.56.1 envoie le choix au moteur puis pose son écoute de l'événement `input`
 * (lib/server/dom.js, `_setInputFiles` : `setInputFilePaths` part avant l'évaluation qui pose l'écoute) et attend cet
 * événement. Si le moteur l'émet avant que l'écoute soit posée, l'appel reste sans réponse jusqu'au délai alors que
 * la page a bien reçu le répertoire : vu deux fois sous WebKit en intégration continue le 2026-11-17 (30 s, puis
 * échec), sur une page plus occupée à son chargement. Cette fonction pose donc sa propre écoute avant l'appel et lui
 * donne 10 s ; au délai, elle ne continue que si son écoute a vu l'événement (le choix a eu lieu), et l'écrit sur la
 * sortie d'erreur ; sinon l'erreur de Playwright est rendue, avec ce que l'écoute a vu.
 */
export async function choisirRepertoire(page, chemin) {
  await page.evaluate(() => {
    globalThis.__choixRepertoireEssai = 0;
    document.getElementById("entree-repertoire").addEventListener("input", () => {
      globalThis.__choixRepertoireEssai += 1;
    }, { once: true });
  });
  try {
    await page.setInputFiles("#entree-repertoire", chemin, { timeout: 10000 });
  } catch (e) {
    if (!/setInputFiles: Timeout/.test(e.message)) throw e;
    const moteur = page.context().browser().browserType().name();
    const vu = await page.evaluate(() => ({
      evenements: globalThis.__choixRepertoireEssai,
      fichiers: document.getElementById("entree-repertoire").files.length,
      affiche: document.getElementById("dossier-choisi")?.textContent ?? null,
    }));
    if (vu.evenements !== 1) {
      e.message += `\nchoisirRepertoire, ${moteur} : aucun événement input vu par l'écoute de l'essai (${JSON.stringify(vu)})`;
      throw e;
    }
    process.stderr.write(`page de vérification, ${moteur} : répertoire choisi, événement input émis avant l'écoute de Playwright, appel poursuivi\n`);
  }
}

/**
 * Déplie le bloc des options de la page (fichiers facultatifs, contrôles à exiger, langue et détail du rapport y sont
 * repliés, complément du 2026-11-17 de CT-6 §18) par son titre, comme le ferait la personne ; sans effet s'il est ouvert.
 */
export async function deplierOptions(page) {
  if (!(await page.evaluate(() => document.getElementById("options").open))) await page.click("#options > summary");
  await page.waitForFunction(() => document.getElementById("options").open);
}

/** Clique « Vérifier » et attend le résultat. */
export async function lancerVerification(page) {
  await page.click("#verifier");
  await page.waitForFunction(() => {
    const r = document.getElementById("resultat");
    return !r.hidden && document.querySelector("#resultat-contenu .en-cours") === null;
  }, null, { timeout: 300000 });
}
