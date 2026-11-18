// Page de vérification (CT-6 §18, complément du 2026-11-17 : présentation des
// écrans) : le verdict mis en avant, la liste des huit contrôles, les
// avertissements et les blocs repliés.
//
// - Sources, sous Node, sans chaîne Go ni navigateur : la lecture des
//   contrôles du rapport JSON (lireControles, resumer) ne résume que ce
//   qu'elle lit exactement ; libellés des contrôles, des statuts et des
//   raisons de CT-6 §6.2 dans les deux langues ; ce que les blocs repliés du
//   gabarit contiennent ; feuille de style sans adresse, sans jeton redéfini,
//   sans préférence de couleur hors du bloc commun ; aucun stockage.
// - Dans un navigateur, sans chaîne Go : la page est construite depuis les
//   sources avec un artefact factice, et un travailleur de remplacement rend
//   des rapports écrits par l'essai (codes 0, 1, 2 et 3). Le mot du verdict
//   suit le code de retour ; l'état de chaque contrôle est celui du rapport
//   JSON ; un contrôle non exécuté n'est jamais montré réussi (deux mutants
//   tués) ; un rapport dont les contrôles ne se lisent pas n'est pas résumé ;
//   le rapport lisible, le rapport JSON et la ligne de commande sont intacts
//   dans leurs blocs repliés ; les avertissements sont hors de tout bloc
//   replié ; le thème suit le système, bascule, et ne mémorise rien.
// - De bout en bout, avec go1.27.3 : sur les dossiers des vecteurs, la liste
//   affichée est celle du rapport JSON que la page montre.
//
// NOORTRACE_RACINE : racine d'une copie du dépôt dont les sources sont lues
// (essais de mutants hors du dépôt) ; à défaut, le dépôt lui-même.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { execFileSync } from "node:child_process";
import { attendreArtefact, choisirRepertoire, deplierOptions, lancer, lancerVerification, ouvrir } from "./fixtures/verification-page/navigateur.mjs";
import { ANCRES, CHAINE, RACINE, VERSION, construireArtefact, enAttente, environnementGo, repertoireTemporaire } from "./fixtures/verification-page/outils.mjs";

const RACINE_SOURCES = process.env.NOORTRACE_RACINE ? path.resolve(process.env.NOORTRACE_RACINE) : RACINE;
const SOURCES = path.join(RACINE_SOURCES, "paquets", "verification-web", "src");
const VECTEURS = path.join(RACINE, "spec", "vecteurs");
const DOSSIER = path.join(VECTEURS, "ct-1", "dossiers", "valide-seq-7");
const HEX = `0x${"5a".repeat(32)}`;

const lire = (nom) => fs.readFileSync(path.join(SOURCES, "page", nom), "utf8");

function tables(sources = SOURCES) {
  const table = (fichier, nom) => vm.runInNewContext(`${fs.readFileSync(path.join(sources, "page", fichier), "utf8")}\n${nom};`, {});
  return { fr: table("libelles-fr.js", "LIBELLES_FR"), en: table("libelles-en.js", "LIBELLES_EN") };
}

/** Libellé rempli ; une clé absente (sources d'avant la refonte) rend un texte qui ne vaut aucun affichage. */
function libelle(table, cle, parametres = {}) {
  if (!Object.hasOwn(table, cle)) return `«libellé ${cle} absent»`;
  return table[cle].replace(/\{([a-z0-9_]+)\}/g, (tout, k) => (Object.hasOwn(parametres, k) ? String(parametres[k]) : tout));
}

/** Les fonctions de lecture du rapport JSON d'interface.js, telles qu'écrites ; null si les sources ne les ont pas. */
function chargerResume() {
  const source = lire("interface.js");
  const debut = source.indexOf("// --- Résumé tiré du rapport JSON");
  const fin = source.indexOf("// --- Affichage du résultat");
  const statuts = /^const STATUTS_CONNUS = .*$/m.exec(source);
  const raisons = /^const RAISONS_CONNUES = .*$/m.exec(source);
  if (debut < 0 || fin < debut || !statuts || !raisons) return null;
  return vm.runInNewContext(`${statuts[0]}\n${raisons[0]}\n${source.slice(debut, fin)}\n({ lireControles, resumer, controlesNonReussis, STATUTS_CONNUS, RAISONS_CONNUES });`, {});
}

/** Les raisons de non-exécution de la table de CT-6 §6.2, dans l'ordre. */
function raisonsCt6() {
  const ct6 = fs.readFileSync(path.join(RACINE, "spec", "CT-6-verificateur.md"), "utf8");
  const section = ct6.slice(ct6.indexOf("### 6.2 Raisons de non-exécution"), ct6.indexOf("### 6.3 Statut d'un contrôle"));
  return [...section.matchAll(/^\| `([a-z_]+)` \|/gm)].map((m) => m[1]);
}

/**
 * Rapport JSON écrit par l'essai, à la forme de CT-6 EX-8.7 pour ce que la
 * page en lit. `statuts` : huit statuts ; `raisons` : numéro → raison.
 */
function rapport({ code, statuts = [], raisons = {}, exiges = [], echecs = [], bloquantes = [], avertissements = [], message = null }) {
  const verifier = { name: "noortrace-verifier", implementation: "binaire_go", version: VERSION, runtime: "go1.27.3" };
  if (code === 2) return { format: "noortrace/rapport-verification", version: 0, verifier, exit_code: 2, verdict: null, error: { kind: "dossier_illisible", message, check: null } };
  return {
    format: "noortrace/rapport-verification",
    version: 0,
    verifier,
    inputs: { required_controls: exiges },
    controls: statuts.map((s, i) => ({ number: i + 1, status: s, reason: raisons[i + 1] ?? null, checks: [], anchors_used: [], summary: `résumé du contrôle ${i + 1}` })),
    failed_checks: echecs,
    blocking_unexecuted: bloquantes,
    warnings: avertissements,
    verdict: { 0: "valide", 1: "invalide", 3: "incomplet" }[code],
    exit_code: code,
    statement: { fr: `Énoncé français ${HEX} ; fin.`, en: `English statement ${HEX}; end.` },
    bound: null,
  };
}

const R = "reussi";
const N = "non_execute";
const E = "echoue";

/** Les cas de l'essai : un rapport par code, plus le « valide » borné. */
const CAS = {
  valide: { code: 0, json: rapport({ code: 0, statuts: [R, R, R, R, R, R, R, R], avertissements: [{ id: "AV-O-3", check: "O-5", detail: "réseau regtest : réseau d'essai, sans valeur probante hors des tests" }] }) },
  borne: { code: 0, json: rapport({ code: 0, statuts: [R, R, R, N, N, R, R, N], raisons: { 4: "ancre_absente", 5: "partie_absente", 8: "hors_perimetre_version" } }) },
  nonValide: { code: 1, json: rapport({ code: 1, statuts: [E, R, R, N, N, R, R, N], raisons: { 4: "prerequis_en_echec", 5: "partie_absente", 8: "ancre_absente" }, echecs: ["E-7"], bloquantes: ["T-2"] }) },
  incomplet: { code: 3, json: rapport({ code: 3, statuts: [R, R, R, N, N, R, R, N], raisons: { 4: "ancre_absente", 5: "partie_absente", 8: "ancre_absente" }, exiges: [4, 7, 8] }) },
  aucun: { code: 2, json: rapport({ code: 2, message: "dossier.json n'est pas du JSON" }), erreur: "Erreur : dossier.json n'est pas du JSON\n" },
};

const texteLisible = (cas) => (cas.code === 2 ? "" : `Vérification hors ligne (rapport de l'essai)\n  [réussi]      1  ligne   à   colonnes\nRésultat      : code ${cas.code}\n`);
const texteJson = (cas) => `${JSON.stringify(cas.json, null, 2)}\n`;

/**
 * Travailleur de remplacement : répond à l'artefact par artefact_pret, et à
 * une vérification par les deux exécutions du cas (rapport lisible, puis
 * rapport JSON), avec les arguments d'EX-18.8.
 */
function travailleurFactice(cas) {
  const donnees = { code: cas.code, lisible: texteLisible(cas), json: cas.jsonTexte ?? texteJson(cas), erreur: cas.erreur ?? "" };
  return Buffer.from(`"use strict";
const D = ${JSON.stringify(donnees)};
self.addEventListener("message", (ev) => {
  const m = ev.data;
  const e = new TextEncoder();
  if (m.type === "artefact") self.postMessage({ type: "artefact_pret", version: ${JSON.stringify(VERSION)}, empreinte: "0x" + "0".repeat(64) });
  else if (m.type === "verifier") {
    const args = ["noortrace-verifier", "dossier", "--langue", m.options.langue];
    self.postMessage({ type: "resultat", executions: [
      { arguments: args, code: D.code, sortie: e.encode(D.lisible), erreur: e.encode(D.erreur) },
      { arguments: [...args, "--json"], code: D.code, sortie: e.encode(D.json), erreur: new Uint8Array(0) },
    ] });
  }
});
`, "utf8");
}

/** Page construite depuis `sources` avec un artefact factice : aucun besoin de la chaîne Go. */
function construirePageFactice(dir, sources = SOURCES) {
  const wasm = path.join(dir, "wasm");
  fs.mkdirSync(wasm, { recursive: true });
  fs.writeFileSync(path.join(wasm, "noortrace-verifier.wasm"), Buffer.from("artefact factice de l'essai"));
  fs.writeFileSync(path.join(wasm, "wasm_exec.js"), "// fichier de soutien factice de l'essai\n");
  const page = path.join(dir, "page");
  execFileSync(process.execPath, [path.join(sources, "construire.mjs"), "--wasm", wasm, "--version", VERSION, "--sortie", page], { encoding: "utf8", stdio: "pipe" });
  return page;
}

/** Ce que la page montre du résultat : verdict, contrôles, avertissements, blocs. */
async function lireEcran(page) {
  return page.evaluate(() => {
    const t = (s) => {
      const e = document.querySelector(s);
      return e === null ? null : e.textContent;
    };
    const replie = (s) => {
      const e = document.querySelector(s);
      return e === null ? null : e.closest("details:not([open])") !== null;
    };
    const dansUnBloc = (s) => {
      const e = document.querySelector(s);
      return e === null ? null : e.closest("details") !== null;
    };
    const verdict = document.getElementById("verdict");
    return {
      mot: t("#verdict-mot"),
      variante: verdict === null ? null : [...verdict.classList].filter((c) => c.startsWith("nt-verdict-")).join(" "),
      code: t("#code"),
      tousReussis: t("#tous-reussis"),
      borne: t("#verdict-borne"),
      exiges: t("#exiges-non-reussis"),
      indisponible: t("#resume-indisponible"),
      suite: t("#verdict-suite"),
      compte: t("#compte-controles"),
      controles: [...document.querySelectorAll("#controles li")].map((li) => {
        const pastilles = [...li.querySelectorAll(".nt-pastille")];
        const raison = li.querySelector(".pv-controle-raison");
        return {
          numero: Number(li.dataset.numero),
          statut: li.dataset.statut,
          etat: pastilles[0].textContent,
          montreReussi: pastilles[0].classList.contains("nt-pastille-succes"),
          titre: li.querySelector(".nt-controle-titre").textContent,
          raison: raison === null ? null : raison.textContent,
          exige: pastilles.length > 1 ? pastilles[1].textContent : null,
        };
      }),
      pastillesReussi: document.querySelectorAll("#controles .nt-pastille-succes").length,
      avertissements: t("#avertissements"),
      avertissementsDansUnBloc: dansUnBloc("#avertissements"),
      lisible: t("#rapport-lisible"),
      json: t("#rapport-json"),
      commande: t("pre.commande"),
      erreur: t("#sortie-erreur"),
      enonceFr: t("#enonce-fr"),
      enonceEn: t("#enonce-en"),
      message: t("#message-erreur"),
      affirmation: t("#aucune-affirmation"),
      replies: { lisible: replie("#rapport-lisible"), json: replie("#rapport-json"), commande: replie("pre.commande"), enonceFr: replie("#enonce-fr"), enonceEn: replie("#enonce-en"), code: replie("#code"), mot: replie("#verdict-mot"), controles: replie("#controles") },
    };
  });
}

/**
 * Ce que la page doit montrer d'un rapport, écrit ici une seconde fois d'après
 * CT-6 §6 et §8.3 : le mot suit le code ; l'état d'un contrôle est son statut
 * dans le rapport ; seul un contrôle « reussi » est montré réussi.
 */
function attendu(cas, T) {
  const mots = { 0: ["mot_0", "nt-verdict-valide"], 1: ["mot_1", "nt-verdict-non-valide"], 2: ["mot_2", ""], 3: ["mot_3", "nt-verdict-incomplet"] };
  const r = { mot: T[mots[cas.code][0]], variante: mots[cas.code][1], code: libelle(T, "code", { code: cas.code, sens: T[`code_${cas.code}`] }) };
  if (cas.code === 2) return { ...r, controles: [], pastillesReussi: 0, tousReussis: null, borne: null, exiges: null };
  const exiges = cas.json.inputs.required_controls;
  r.controles = cas.json.controls.map((c) => ({
    numero: c.number,
    statut: c.status,
    etat: T[`statut_${c.status}`],
    montreReussi: c.status === "reussi",
    titre: `${c.number}. ${T[`controle_${c.number}`]}`,
    raison: c.status === "non_execute" ? libelle(T, "raison", { raison: T[`raison_${c.reason}`], code: c.reason }) : null,
    exige: exiges.includes(c.number) ? T.controle_exige : null,
  }));
  const nonReussis = cas.json.controls.filter((c) => c.status !== "reussi").map((c) => c.number);
  r.pastillesReussi = 8 - nonReussis.length;
  r.tousReussis = cas.code === 0 && nonReussis.length === 0 ? T.tous_reussis : null;
  r.borne = cas.code === 0 && nonReussis.length > 0 ? libelle(T, "valide_borne", { liste: nonReussis.join(", ") }) : null;
  r.exiges = cas.code === 3 ? libelle(T, "exiges_non_reussis", { liste: exiges.filter((n) => nonReussis.includes(n)).join(", ") }) : null;
  return r;
}

const garder = (ecran, cles) => Object.fromEntries(cles.map((k) => [k, ecran[k]]));
const CLES_VERDICT = ["mot", "variante", "code", "controles", "pastillesReussi", "tousReussis", "borne", "exiges"];

describe("page de vérification, présentation : sources (CT-6 §18, complément du 2026-11-17)", function () {
  it("lecture des contrôles du rapport JSON : huit contrôles numérotés, statut de CT-6 EX-6.1, raison de CT-6 §6.2 pour un contrôle non exécuté ; toute autre liste, ou une liste qui contredit le code, n'est pas résumée", function () {
    const f = chargerResume();
    expect(f, "fonctions de lecture du rapport dans interface.js").to.not.equal(null);
    expect([...f.STATUTS_CONNUS]).to.deep.equal(["reussi", "echoue", "non_execute"]);
    expect([...f.RAISONS_CONNUES]).to.deep.equal(raisonsCt6());
    const borne = CAS.borne.json;
    const lus = f.lireControles(borne, 0);
    expect(lus.map((c) => [c.numero, c.statut, c.raison])).to.deep.equal(borne.controls.map((c) => [c.number, c.status, c.reason]));
    expect([...f.controlesNonReussis(lus)]).to.deep.equal([4, 5, 8]);
    expect([...f.controlesNonReussis(f.lireControles(CAS.valide.json, 0))]).to.deep.equal([]);
    expect([...f.controlesNonReussis(f.lireControles(CAS.nonValide.json, 1))]).to.deep.equal([1, 4, 5, 8]);
    const change = (modifier) => {
      const copie = JSON.parse(JSON.stringify(borne));
      modifier(copie);
      return f.lireControles(copie, 0);
    };
    const illisibles = {
      "liste absente": (r) => delete r.controls,
      "liste qui n'est pas un tableau": (r) => (r.controls = { 1: "reussi" }),
      "sept contrôles": (r) => r.controls.pop(),
      "neuf contrôles": (r) => r.controls.push({ ...r.controls[0], number: 9 }),
      "numéros dans le désordre": (r) => r.controls.reverse(),
      "numéro en double": (r) => (r.controls[1].number = 1),
      "contrôle nul": (r) => (r.controls[2] = null),
      "statut inconnu": (r) => (r.controls[3].status = "ignore"),
      "statut absent": (r) => delete r.controls[3].status,
      "statut en capitales": (r) => (r.controls[0].status = "REUSSI"),
      "non exécuté sans raison": (r) => (r.controls[3].reason = null),
      "réussi avec une raison": (r) => (r.controls[0].reason = "partie_absente"),
      "contrôle en échec sous le code 0": (r) => {
        r.controls[0].status = "echoue";
      },
      "prérequis en échec sous le code 0": (r) => (r.controls[3].reason = "prerequis_en_echec"),
    };
    for (const [titre, modifier] of Object.entries(illisibles)) expect(change(modifier), titre).to.equal(null);
    // Sous le code 1, un contrôle en échec et un prérequis en échec se lisent.
    expect(f.lireControles(CAS.nonValide.json, 1)).to.not.equal(null);
    // Une raison que la page ne connaît pas reste une raison : le contrôle est lu non exécuté, jamais réussi.
    const inconnue = change((r) => (r.controls[3].reason = "raison_nouvelle"));
    expect([inconnue[3].statut, inconnue[3].raison]).to.deep.equal(["non_execute", "raison_nouvelle"]);
    // Résumé : contrôles exigés, vérifications en échec et bloquantes, avertissements ; illisibles, ils valent null.
    const r = f.resumer(CAS.nonValide.json, 1);
    expect([[...r.echecs], [...r.bloquantes], [...r.exiges], r.avertissements.length]).to.deep.equal([["E-7"], ["T-2"], [], 0]);
    expect(f.resumer({ ...CAS.valide.json, warnings: "aucun" }, 0).avertissements).to.equal(null);
    expect(f.resumer({ ...CAS.valide.json, warnings: [{ id: 3 }] }, 0).avertissements).to.equal(null);
    expect(f.resumer({ ...CAS.incomplet.json, inputs: { required_controls: [0, 9] } }, 3).exiges).to.equal(null);
    expect([...f.resumer(CAS.incomplet.json, 3).exiges]).to.deep.equal([4, 7, 8]);
  });

  it("libellés : nom courant des huit contrôles, statuts, raisons de CT-6 §6.2 et mots du verdict, en français et en anglais ; le sens fixé des codes reste entier", function () {
    const { fr, en } = tables();
    const cles = [...[1, 2, 3, 4, 5, 6, 7, 8].map((n) => `controle_${n}`), "statut_reussi", "statut_echoue", "statut_non_execute", ...raisonsCt6().map((r) => `raison_${r}`), "raison_inconnue", "mot_0", "mot_1", "mot_2", "mot_3", "tous_reussis", "valide_borne", "exiges_non_reussis", "resume_indisponible", "controle_exige"];
    for (const T of [fr, en]) {
      for (const cle of cles) expect(typeof T[cle] === "string" && T[cle].length > 0, cle).to.equal(true);
      // Aucun libellé de statut ou de raison non réussi ne dit « réussi ».
      for (const cle of ["statut_echoue", "statut_non_execute", ...raisonsCt6().map((r) => `raison_${r}`), "raison_inconnue"]) expect(T[cle], cle).to.not.match(/réussi|passed|valide|valid/i);
      expect(new Set([T.statut_reussi, T.statut_echoue, T.statut_non_execute]).size).to.equal(3);
      expect(new Set([T.mot_0, T.mot_1, T.mot_2, T.mot_3]).size).to.equal(4);
    }
    expect([fr.mot_0, fr.mot_1, fr.mot_2, fr.mot_3]).to.deep.equal(["Valide", "Non valide", "Aucun verdict", "Incomplet"]);
    expect([en.mot_0, en.mot_1, en.mot_2, en.mot_3]).to.deep.equal(["Valid", "Not valid", "No verdict", "Incomplete"]);
    // Le mot du verdict reprend le premier mot du sens fixé du code (table de CT-6 §8.3), sans le remplacer.
    expect(fr.code_0.startsWith("valide. ") && fr.code_1.startsWith("invalide. ") && fr.code_2.startsWith("aucun verdict. ") && fr.code_3.startsWith("incomplet. ")).to.equal(true);
    expect(fr.code).to.equal("Code de retour {code} : {sens}");
    expect(fr.valide_borne.startsWith("Valide, avec des contrôles non exécutés : {liste}")).to.equal(true);
  });

  it("gabarit : la phrase fixe, l'état du vérificateur, le choix du dossier, « Vérifier », « Arrêter » et le résultat sont hors de tout bloc replié ; seuls l'empreinte et les options sont repliées ; page.js est dans l'en-tête", function () {
    const html = lire("index.modele.html");
    const blocs = [...html.matchAll(/<details\b[^>]*>[\s\S]*?<\/details>/g)].map((m) => ({ debut: m.index, fin: m.index + m[0].length, id: /id="([^"]+)"/.exec(m[0].slice(0, m[0].indexOf(">")))?.[1] ?? null }));
    expect(blocs.map((b) => b.id)).to.deep.equal(["detail-empreinte", "options"]);
    const dansUnBloc = (id) => {
      const i = html.indexOf(`id="${id}"`);
      expect(i, id).to.be.greaterThan(-1);
      return blocs.find((b) => i > b.debut && i < b.fin)?.id ?? null;
    };
    for (const id of ["phrase-fixe", "etat-verificateur", "alerte-verificateur", "choisir-repertoire", "choisir-archive", "dossier-choisi", "verifier", "arreter", "resultat", "resultat-contenu", "autre-langue", "bascule-theme"]) {
      expect(dansUnBloc(id), id).to.equal(null);
    }
    expect(dansUnBloc("artefact")).to.equal("detail-empreinte");
    for (const id of ["entree-ancres", "retirer-ancres", "entree-entetes", "retirer-entetes", "exiger", "exiger-tous", "langue-rapport", "detail"]) expect(dansUnBloc(id), id).to.equal("options");
    // Aucun bloc n'est ouvert d'office dans le gabarit, et le résultat est masqué avant la première vérification.
    expect(html).to.not.match(/<details[^>]*\sopen\b/);
    expect(html).to.match(/<section id="resultat"[^>]*\shidden>/);
    // Chaque contrôle à exiger porte son nom courant et son numéro entre parenthèses.
    for (let n = 1; n <= 8; n++) expect(html, `contrôle ${n}`).to.include(`<input type="checkbox" name="exiger" value="${n}"><span><span data-libelle="controle_${n}">{{controle_${n}}}</span> <span class="nt-attenue">(${n})</span></span>`);
    for (const option of ["--ancres", "--entetes-bitcoin", "--exiger", "--langue", "--detail"]) expect(html, option).to.include(`(${option})`);
    expect(html.indexOf('<script src="page.js"')).to.be.lessThan(html.indexOf("</head>"));
    // Aucun style ni script en ligne, aucune image : les icônes sont des tracés dans le document.
    expect(html).to.not.match(/<style|\sstyle\s*=|<img\b|url\(/i);
    expect(html.match(/<script\b/g)).to.have.length(2);
  });

  it("feuille de style : le bloc commun en tête, puis les règles de la page, sans adresse, sans importation, sans jeton redéfini, sans préférence de couleur ni « !important » hors de l'impression", function () {
    const css = lire("page.css");
    expect(css.startsWith("/* noor-theme:debut */\n")).to.equal(true);
    const fin = css.indexOf("/* noor-theme:fin */");
    expect(fin).to.be.greaterThan(0);
    expect(css.indexOf("/* noor-theme:debut */", 1)).to.equal(-1);
    expect(css.indexOf("/* noor-theme:fin */", fin + 1)).to.equal(-1);
    expect(css).to.not.match(/url\(|@import|@font-face|expression\(/i);
    const propres = css.slice(fin + "/* noor-theme:fin */".length).replace(/\/\*[\s\S]*?\*\//g, "");
    expect(propres.length).to.be.greaterThan(0);
    expect(propres).to.not.match(/--nt-[a-z0-9-]+\s*:/);
    expect(propres).to.not.match(/prefers-color-scheme|color-scheme|data-theme|!important/);
    // Les règles de la page ne définissent aucune classe du bloc commun.
    for (const m of propres.matchAll(/(^|\})\s*([^{}@]+)\{/g)) {
      for (const selecteur of m[2].split(",")) expect(selecteur.trim(), selecteur.trim()).to.not.match(/^\.nt-/);
    }
  });

  it("interface.js : le thème suit prefers-color-scheme et ne mémorise rien ; aucun stockage, aucune requête, aucune insertion de HTML ; le verdict ne compare que le code de retour", function () {
    const source = lire("interface.js");
    expect(source).to.include('globalThis.matchMedia("(prefers-color-scheme: light)")');
    expect(source).to.not.match(/localStorage|sessionStorage|indexedDB|document\.cookie|\bcaches\b|serviceWorker|\bfetch\s*\(|XMLHttpRequest|innerHTML|outerHTML|insertAdjacentHTML/);
    // Le mot et la variante du verdict sont pris dans une table indexée par le code de retour, et nulle part ailleurs.
    expect(source).to.include('const variantes = { 0: ["valide", "bouclier"], 1: ["non-valide", "croix"], 2: [null, "question"], 3: ["incomplet", "alerte"] };');
    expect(source).to.include("libelle(`mot_${v.code}`)");
    expect(source.match(/nt-verdict-valide|"valide"/g)).to.have.length(1);
  });
});

for (const moteur of ["chromium", "firefox", "webkit"]) {
  describe(`page de vérification, présentation, dans ${moteur} (CT-6 §18, complément du 2026-11-17)`, function () {
    this.timeout(20 * 60 * 1000);
    let navigateur = null;
    let attente = null;
    let dir;
    let pageConstruite;

    before(async function () {
      const l = await lancer(moteur);
      if (!l.navigateur) {
        attente = l.raison;
        return;
      }
      navigateur = l.navigateur;
      dir = repertoireTemporaire(`noortrace-page-presentation-${moteur}`);
      pageConstruite = construirePageFactice(path.join(dir, "construite"));
    });

    after(async function () {
      if (navigateur) await navigateur.close();
      if (dir) fs.rmSync(dir, { recursive: true, force: true });
    });

    function pret(ctx) {
      if (attente === null) return true;
      enAttente(ctx, attente);
      return false;
    }

    /** Ouvre la page servie avec le travailleur du cas, choisit le dossier et vérifie ; rend l'ouverture. */
    async function verifierCas(cas, { page = pageConstruite, langue = "fr", options = {} } = {}) {
      const o = await ouvrir(navigateur, page, { remplacements: { "travailleur.js": travailleurFactice(cas) }, ...options });
      await o.page.goto("https://verification.example/index.html");
      await attendreArtefact(o.page);
      if (langue === "en") await o.page.click("#autre-langue");
      await choisirRepertoire(o.page, DOSSIER);
      await lancerVerification(o.page);
      return o;
    }

    it("le mot du verdict suit le code de retour, et l'état de chaque contrôle est celui du rapport JSON : valide, valide borné, non valide, incomplet, aucun verdict ; en français et en anglais ; un contrôle non exécuté n'est jamais montré réussi", async function () {
      if (!pret(this)) return;
      const T = tables();
      for (const langue of ["fr", "en"]) {
        for (const [nom, cas] of Object.entries(CAS)) {
          const quoi = `${nom}, ${langue}`;
          const o = await verifierCas(cas, { langue });
          try {
            const ecran = await lireEcran(o.page);
            const a = attendu(cas, T[langue]);
            expect(garder(ecran, CLES_VERDICT), quoi).to.deep.equal(garder(a, CLES_VERDICT));
            // Jamais plus de contrôles montrés réussis que le rapport n'en dit réussis.
            expect(ecran.controles.filter((c) => c.montreReussi).map((c) => c.numero), quoi).to.deep.equal(cas.code === 2 ? [] : cas.json.controls.filter((c) => c.status === "reussi").map((c) => c.number));
            // Le verdict, la phrase du code et la liste des contrôles se lisent sans rien déplier.
            expect([ecran.replies.mot, ecran.replies.code], quoi).to.deep.equal([false, false]);
            if (cas.code !== 2) {
              expect(ecran.replies.controles, quoi).to.equal(false);
              expect(await o.page.isVisible("#controles"), quoi).to.equal(true);
              // L'énoncé dans la langue de la page est déplié ; les deux énoncés sont ceux du rapport, au caractère près.
              expect([ecran.enonceFr, ecran.enonceEn], quoi).to.deep.equal([cas.json.statement.fr, cas.json.statement.en]);
              expect([ecran.replies.enonceFr, ecran.replies.enonceEn], quoi).to.deep.equal(langue === "fr" ? [false, true] : [true, false]);
              expect(ecran.affirmation, quoi).to.equal(null);
            } else {
              expect([ecran.message, ecran.affirmation, ecran.enonceFr, ecran.enonceEn], quoi).to.deep.equal([cas.json.error.message, T[langue].aucune_affirmation, null, null]);
              expect(await o.page.isVisible("#message-erreur"), quoi).to.equal(true);
            }
            expect(await o.page.isVisible("#verdict-mot"), quoi).to.equal(true);
            expect(await o.page.isVisible("#code"), quoi).to.equal(true);
            expect((await o.violations()).filter((v) => !(moteur === "firefox" && v === "img-src https://verification.example/favicon.ico")), quoi).to.deep.equal([]);
            expect(o.messages.filter((m) => m.startsWith("erreur de page")), quoi).to.deep.equal([]);
          } finally {
            await o.fermer();
          }
        }
      }
      // Code 1 : les vérifications en échec et les vérifications bloquantes du rapport sont nommées sous le verdict.
      const o = await verifierCas(CAS.nonValide);
      try {
        const ecran = await lireEcran(o.page);
        expect(ecran.suite).to.include(libelle(T.fr, "verifications_echec", { liste: "E-7" }));
        expect(ecran.suite).to.include(libelle(T.fr, "verifications_bloquantes", { liste: "T-2" }));
        expect(ecran.controles[3].raison).to.include("(prerequis_en_echec)");
      } finally {
        await o.fermer();
      }
    });

    it("mutants : « non exécuté » montré réussi, et contrôles non exécutés oubliés du verdict « valide » ; l'essai les voit (tués)", async function () {
      if (!pret(this)) return;
      const T = tables();
      const mutants = [
        { titre: "pastille « réussi » pour un contrôle non exécuté", avant: 'non_execute: ["", "tiret", "statut_non_execute"],', apres: 'non_execute: ["succes", "coche", "statut_reussi"],' },
        { titre: "seuls les contrôles en échec comptés non réussis", avant: 'return controles.filter((c) => c.statut !== "reussi").map((c) => c.numero);', apres: 'return controles.filter((c) => c.statut === "echoue").map((c) => c.numero);' },
      ];
      let n = 0;
      for (const m of mutants) {
        const copie = path.join(dir, `mutant-${n++}`);
        fs.cpSync(SOURCES, path.join(copie, "src"), { recursive: true });
        const fichier = path.join(copie, "src", "page", "interface.js");
        const source = fs.readFileSync(fichier, "utf8");
        expect(source.split(m.avant), m.titre).to.have.length(2);
        fs.writeFileSync(fichier, source.replace(m.avant, m.apres));
        const page = construirePageFactice(path.join(copie, "construite"), path.join(copie, "src"));
        const o = await verifierCas(CAS.borne, { page });
        try {
          const ecran = await lireEcran(o.page);
          const a = attendu(CAS.borne, T.fr);
          expect(garder(ecran, CLES_VERDICT), m.titre).to.not.deep.equal(garder(a, CLES_VERDICT));
          // Ce que le mutant montre de faux : plus de contrôles réussis que le rapport n'en dit, ou un « valide » sans réserve.
          expect(ecran.pastillesReussi > a.pastillesReussi || ecran.tousReussis !== null, m.titre).to.equal(true);
        } finally {
          await o.fermer();
          fs.rmSync(copie, { recursive: true, force: true });
        }
      }
    });

    it("rapport JSON dont la liste des contrôles ne se lit pas, ou contredit le code : aucune liste, « résumé indisponible », jamais « les huit contrôles ont réussi » ; le verdict, l'énoncé et les rapports restent affichés", async function () {
      if (!pret(this)) return;
      const T = tables().fr;
      const variantes = {
        "sans liste de contrôles": (r) => delete r.controls,
        "sept contrôles": (r) => r.controls.pop(),
        "statut inconnu": (r) => {
          r.controls[4].status = "inconnu";
          r.controls[4].reason = null;
        },
        "contrôle en échec sous le code 0": (r) => (r.controls[0].status = "echoue"),
        "non exécuté sans raison": (r) => (r.controls[3].reason = null),
      };
      for (const [titre, modifier] of Object.entries(variantes)) {
        const json = JSON.parse(JSON.stringify(CAS.borne.json));
        modifier(json);
        const cas = { code: 0, json };
        const o = await verifierCas(cas);
        try {
          const ecran = await lireEcran(o.page);
          expect([ecran.mot, ecran.code], titre).to.deep.equal([T.mot_0, libelle(T, "code", { code: 0, sens: T.code_0 })]);
          expect([ecran.controles, ecran.pastillesReussi, ecran.tousReussis, ecran.borne], titre).to.deep.equal([[], 0, null, null]);
          expect(ecran.indisponible, titre).to.equal(T.resume_indisponible);
          expect([ecran.enonceFr, ecran.lisible, ecran.json], titre).to.deep.equal([json.statement.fr, texteLisible(cas), texteJson(cas)]);
        } finally {
          await o.fermer();
        }
      }
    });

    it("rapport lisible, rapport JSON et ligne de commande : intacts au caractère près dans des blocs repliés, qui se déplient ; la sortie d'erreur et les avertissements du rapport montent sous le verdict, hors de tout bloc replié", async function () {
      if (!pret(this)) return;
      const T = tables().fr;
      const o = await verifierCas(CAS.valide);
      try {
        const ecran = await lireEcran(o.page);
        expect([ecran.lisible, ecran.json, ecran.commande]).to.deep.equal([texteLisible(CAS.valide), texteJson(CAS.valide), "noortrace-verifier dossier --langue fr\nnoortrace-verifier dossier --langue fr --json"]);
        expect(ecran.replies).to.include({ lisible: true, json: true, commande: true });
        for (const s of ["#rapport-lisible", "#rapport-json", "pre.commande"]) expect(await o.page.isVisible(s), s).to.equal(false);
        // Avertissement du rapport JSON : visible sans interaction, avec son identifiant et sa vérification.
        expect(ecran.avertissementsDansUnBloc).to.equal(false);
        expect(await o.page.isVisible("#avertissements")).to.equal(true);
        expect(ecran.avertissements).to.include(libelle(T, "avertissement", { detail: "réseau regtest : réseau d'essai, sans valeur probante hors des tests", id: "AV-O-3", check: "O-5" }));
        // Sortie d'erreur vide : dite vide, dans le bloc du rapport complet.
        expect(ecran.erreur).to.equal(T.sortie_erreur_vide);
        // Chaque bloc se déplie par son titre et montre le texte entier ; au clavier dans Chromium (la touche qui
        // ouvre un bloc dépend du moteur), par un clic ailleurs.
        for (const [bloc, s] of [["#detail-rapport", "#rapport-lisible"], ["#detail-json", "#rapport-json"], ["#detail-commande", "pre.commande"]]) {
          if (moteur === "chromium") {
            await o.page.focus(`${bloc} > summary`);
            await o.page.keyboard.press("Enter");
          } else await o.page.click(`${bloc} > summary`);
          await o.page.waitForFunction((x) => document.querySelector(x).open, bloc);
          expect(await o.page.isVisible(s), s).to.equal(true);
        }
        // Les blocs gardent leur état quand la langue de la page change, et les textes ne changent pas.
        await o.page.click("#autre-langue");
        const en = await lireEcran(o.page);
        expect([en.lisible, en.json, en.commande]).to.deep.equal([ecran.lisible, ecran.json, ecran.commande]);
        expect(en.replies).to.include({ lisible: false, json: false, commande: false });
        if (moteur === "chromium") {
          // Bouton « Copier » : le presse-papiers reçoit le texte affiché, tel quel.
          await o.contexte.grantPermissions(["clipboard-read", "clipboard-write"], { origin: "https://verification.example" });
          await o.page.click("#detail-json .pv-copie button");
          await o.page.waitForFunction(() => document.querySelector("#detail-json .pv-copie [role=status]").textContent !== "");
          expect(await o.page.evaluate(() => navigator.clipboard.readText())).to.equal(texteJson(CAS.valide));
        }
      } finally {
        await o.fermer();
      }
      // Sortie d'erreur non vide (code 2) : affichée entière sous le verdict, hors de tout bloc replié.
      const e = await verifierCas(CAS.aucun);
      try {
        const ecran = await lireEcran(e.page);
        expect(ecran.erreur).to.equal(CAS.aucun.erreur);
        expect(ecran.avertissementsDansUnBloc).to.equal(false);
        expect(await e.page.isVisible("#sortie-erreur")).to.equal(true);
        expect(ecran.lisible).to.equal(null);
      } finally {
        await e.fermer();
      }
      // Avertissements illisibles dans le rapport JSON : dits illisibles, sous le verdict.
      const json = { ...CAS.valide.json, warnings: [{ id: "AV-O-3" }] };
      const i = await verifierCas({ code: 0, json });
      try {
        const ecran = await lireEcran(i.page);
        expect(ecran.avertissements).to.include(T.avertissements_illisibles);
        expect(await i.page.isVisible("#avertissements")).to.equal(true);
      } finally {
        await i.fermer();
      }
    });

    it("avant la vérification : trois étapes, options repliées et résumées, « Vérifier » visible sans rien déplier ; la phrase fixe reste affichée ; l'empreinte se lit dans son bloc", async function () {
      if (!pret(this)) return;
      const T = tables().fr;
      const o = await ouvrir(navigateur, pageConstruite, { remplacements: { "travailleur.js": travailleurFactice(CAS.valide) } });
      try {
        await o.page.goto("https://verification.example/index.html");
        const artefact = await attendreArtefact(o.page);
        expect(artefact).to.equal(libelle(T, "artefact_pret", { version: VERSION, empreinte: `0x${"0".repeat(64)}` }));
        expect(await o.page.isVisible("#phrase-fixe")).to.equal(true);
        expect(await o.page.textContent("#etat-verificateur")).to.equal(T.etat_pret);
        expect(await o.page.isVisible("#artefact")).to.equal(false);
        await o.page.click("#detail-empreinte > summary");
        expect(await o.page.isVisible("#artefact")).to.equal(true);
        expect(await o.page.evaluate(() => [...document.querySelectorAll(".nt-etape-rond")].map((e) => e.textContent))).to.deep.equal(["1", "2", "3"]);
        expect(await o.page.evaluate(() => document.getElementById("options").open)).to.equal(false);
        expect(await o.page.isVisible("#verifier")).to.equal(true);
        expect(await o.page.isDisabled("#verifier")).to.equal(true);
        expect(await o.page.textContent("#aide-verifier")).to.equal(T.aide_verifier_dossier);
        expect(await o.page.textContent("#resume-options")).to.equal(T.options_aucune);
        expect(await o.page.isVisible("#entree-ancres")).to.equal(false);
        // Les options choisies se lisent dans le titre du bloc, replié ou non.
        await deplierOptions(o.page);
        await o.page.setInputFiles("#entree-ancres", ANCRES);
        await o.page.setInputFiles("#entree-entetes", CHAINE);
        for (const n of [8, 4]) await o.page.setChecked(`input[name="exiger"][value="${n}"]`, true);
        await o.page.setChecked("#detail", true);
        expect(await o.page.textContent("#nom-ancres")).to.equal(libelle(T, "fichier_choisi", { nom: path.basename(ANCRES) }));
        expect(await o.page.textContent("#resume-options")).to.equal([T.options_ancres, T.options_entetes, libelle(T, "options_exiger", { liste: "4, 8" }), T.options_detail].join(" · "));
        await o.page.click("#retirer-ancres");
        expect(await o.page.textContent("#nom-ancres")).to.equal(T.aucun_fichier);
        await o.page.click("#options > summary");
        expect(await o.page.textContent("#resume-options")).to.equal([T.options_entetes, libelle(T, "options_exiger", { liste: "4, 8" }), T.options_detail].join(" · "));
        await choisirRepertoire(o.page, DOSSIER);
        expect(await o.page.textContent("#dossier-choisi")).to.equal(libelle(T, "dossier_choisi_repertoire", { nom: path.basename(DOSSIER) }));
        expect(await o.page.isEnabled("#verifier")).to.equal(true);
        expect(await o.page.textContent("#aide-verifier")).to.equal(T.aide_verifier_pret);
      } finally {
        await o.fermer();
      }
    });

    it("thème : sombre ou clair selon le système, bascule par le bouton, libellé du bouton dans la langue de la page ; aucun choix mémorisé, aucun stockage", async function () {
      if (!pret(this)) return;
      const { fr, en } = tables();
      const etat = (page) => page.evaluate(() => ({
        theme: document.documentElement.getAttribute("data-theme"),
        libelle: document.getElementById("bascule-theme").getAttribute("aria-label"),
        barre: document.querySelector('meta[name="theme-color"]').getAttribute("content"),
        fond: getComputedStyle(document.documentElement).backgroundColor,
      }));
      const ouvrirSous = async (schema) => {
        const origine = navigateur.newContext.bind(navigateur);
        navigateur.newContext = (options = {}) => origine({ ...options, colorScheme: schema });
        try {
          const o = await ouvrir(navigateur, pageConstruite, { remplacements: { "travailleur.js": travailleurFactice(CAS.valide) } });
          // La préférence est aussi posée sur la page elle-même : sous Firefox, la page rouverte après une première
          // navigation bloquée (reprise de l'ouverture) ne recevait pas celle du contexte.
          await o.page.emulateMedia({ colorScheme: schema });
          await o.page.goto("https://verification.example/index.html");
          await attendreArtefact(o.page);
          return o;
        } finally {
          navigateur.newContext = origine;
        }
      };
      const sombre = { theme: null, libelle: fr.theme_vers_clair, barre: "#060B16", fond: "rgb(6, 11, 22)" };
      const clair = { theme: "clair", libelle: fr.theme_vers_sombre, barre: "#F3F7FF", fond: "rgb(243, 247, 255)" };
      const o = await ouvrirSous("dark");
      try {
        expect(await etat(o.page)).to.deep.equal(sombre);
        await o.page.click("#bascule-theme");
        expect(await etat(o.page)).to.deep.equal(clair);
        await o.page.click("#autre-langue");
        expect((await etat(o.page)).libelle).to.equal(en.theme_vers_sombre);
        await o.page.click("#autre-langue");
        await o.page.click("#bascule-theme");
        expect(await etat(o.page)).to.deep.equal(sombre);
        await o.page.click("#bascule-theme");
        // Aucune mémoire : la page rechargée reprend l'état du système, et le stockage est vide.
        await o.page.reload();
        await attendreArtefact(o.page);
        expect(await etat(o.page)).to.deep.equal(sombre);
        expect(await o.page.evaluate(() => [localStorage.length, sessionStorage.length, document.cookie])).to.deep.equal([0, 0, ""]);
        // Tant que la bascule n'a pas servi, la page suit un changement du système.
        await o.page.emulateMedia({ colorScheme: "light" });
        await o.page.waitForFunction(() => document.documentElement.getAttribute("data-theme") === "clair");
        await o.page.click("#bascule-theme");
        await o.page.emulateMedia({ colorScheme: "dark" });
        await o.page.emulateMedia({ colorScheme: "light" });
        expect((await etat(o.page)).theme).to.equal(null);
      } finally {
        await o.fermer();
      }
      const c = await ouvrirSous("light");
      try {
        expect(await etat(c.page)).to.deep.equal(clair);
      } finally {
        await c.fermer();
      }
    });
  });
}

describe("page de vérification, présentation, de bout en bout dans chromium (CT-6 §18, complément du 2026-11-17)", function () {
  this.timeout(30 * 60 * 1000);
  let navigateur = null;
  let attente = null;
  let dir;
  let page;

  before(async function () {
    const env = environnementGo();
    if (env === null) {
      attente = "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH) : aucune page à servir";
      return;
    }
    const l = await lancer("chromium");
    if (!l.navigateur) {
      attente = l.raison;
      return;
    }
    navigateur = l.navigateur;
    dir = repertoireTemporaire("noortrace-page-presentation-bout");
    const wasm = path.join(dir, "wasm");
    page = path.join(dir, "page");
    construireArtefact(wasm, env);
    execFileSync(process.execPath, [path.join(SOURCES, "construire.mjs"), "--wasm", wasm, "--version", VERSION, "--sortie", page], { encoding: "utf8", stdio: "pipe" });
  });

  after(async function () {
    if (navigateur) await navigateur.close();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("dossiers des vecteurs (valide aux huit contrôles, valide borné, non valide, incomplet, illisible) : le mot suit le code de retour du vérificateur, et la liste affichée est celle du rapport JSON que la page montre", async function () {
    if (attente !== null) return enAttente(this, attente);
    const T = tables().fr;
    const echantillon = [
      { titre: "valide, huit contrôles réussis", dossier: "ct-6/dossiers/valide-seq-7-complet", ancres: true, entetes: true, code: 0, nonReussis: [] },
      { titre: "valide borné, sans fichier d'ancres", dossier: "ct-6/dossiers/valide-seq-7-complet", code: 0, nonReussis: [4, 5, 8] },
      { titre: "non valide", dossier: "ct-1/dossiers/invalide-hash-faux", code: 1 },
      { titre: "incomplet, contrôles 4, 5 et 8 exigés", dossier: "ct-1/dossiers/valide-seq-7", exiger: [4, 5, 8], code: 3, nonReussis: [4, 5, 8] },
      { titre: "aucun verdict", dossier: "ct-1/dossiers/illisible-index-non-json", code: 2 },
    ];
    const o = await ouvrir(navigateur, page);
    try {
      await o.page.goto("https://verification.example/index.html");
      await attendreArtefact(o.page);
      await deplierOptions(o.page);
      for (const e of echantillon) {
        if (e.ancres) await o.page.setInputFiles("#entree-ancres", ANCRES);
        else await o.page.click("#retirer-ancres");
        if (e.entetes) await o.page.setInputFiles("#entree-entetes", CHAINE);
        else await o.page.click("#retirer-entetes");
        for (let n = 1; n <= 8; n++) await o.page.setChecked(`input[name="exiger"][value="${n}"]`, (e.exiger ?? []).includes(n));
        await choisirRepertoire(o.page, path.join(VECTEURS, e.dossier));
        await lancerVerification(o.page);
        const ecran = await lireEcran(o.page);
        const json = JSON.parse(ecran.json);
        expect(json.exit_code, e.titre).to.equal(e.code);
        const a = attendu({ code: e.code, json }, T);
        expect(garder(ecran, CLES_VERDICT), e.titre).to.deep.equal(garder(a, CLES_VERDICT));
        if (e.nonReussis) expect(ecran.controles.filter((c) => !c.montreReussi).map((c) => c.numero), e.titre).to.deep.equal(e.nonReussis);
        if (e.code === 0) expect([ecran.tousReussis !== null, ecran.borne !== null], e.titre).to.deep.equal([e.nonReussis.length === 0, e.nonReussis.length > 0]);
        // Le résumé que le vérificateur donne de chaque contrôle est repris tel quel.
        if (e.code !== 2) for (const c of json.controls) expect(await o.page.textContent(`#controles li[data-numero="${c.number}"]`), `${e.titre}, contrôle ${c.number}`).to.include(c.summary);
        // Les avertissements du rapport sont tous sous le verdict.
        for (const w of json.warnings ?? []) expect(ecran.avertissements, e.titre).to.include(w.detail);
      }
      expect((await o.violations())).to.deep.equal([]);
    } finally {
      await o.fermer();
    }
  });
});
