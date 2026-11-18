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
// - Langage (complément du 2026-11-18 de CT-6 §18) : les phrases en langage
//   courant (une par code de retour, une par avertissement, « ce que ce
//   résultat ne dit pas ») sont celles des tables de CT-6, dans les deux
//   langues ; la phrase affichée est celle du code, jamais celle d'un autre
//   (mutant vu), et un code ou un avertissement hors table n'en reçoit
//   aucune ; le texte du vérificateur reste entier sous la phrase courante ;
//   l'énoncé est rendu en membres de phrase sans qu'un caractère change, texte
//   copié compris ; après un résultat, les étapes se réduisent à une ligne et
//   la mise en garde d'EX-18.2 passe sous le résultat : le mot du verdict est
//   sur le premier écran ; aucun terme de technicien ne paraît au premier
//   niveau de lecture, en français et en anglais (liste publiée ici, mutant vu).
// - Seconde lecture (même complément, points 14 à 19) : la présentation ne
//   peut que restreindre ce que le code dit. Sous le code 0, le vert plein ne
//   reste que pour huit contrôles réussis sans avertissement ; sinon teinte
//   d'avertissement, mention fixe dans le titre et phrase de ce qui n'est pas
//   prouvé ; rapport illisible : mot seul, teinte neutre. Un avertissement
//   n'est rattaché à un contrôle que par le rapport ; une réserve en double
//   est dite une fois, tous ses textes exacts gardés. « En résumé » ne recopie
//   que des champs du rapport (valeurs égales aux champs, sur des rapports
//   écrits ici et sur ceux du vérificateur pour les dossiers des vecteurs),
//   jamais pour un contrôle non réussi ni hors des codes 0 et 3. Mutants vus,
//   sous Node et dans le navigateur.
//
// NOORTRACE_RACINE : racine d'une copie du dépôt dont les sources sont lues
// (essais de mutants hors du dépôt) ; à défaut, le dépôt lui-même.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { execFileSync } from "node:child_process";
import { attendreArtefact, choisirRepertoire, deplierOptions, lancer, lancerVerification, ouvrir, rouvrirEtapes } from "./fixtures/verification-page/navigateur.mjs";
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
  const langage = source.indexOf("// --- Langage courant");
  const debut = langage >= 0 ? langage : source.indexOf("// --- Résumé tiré du rapport JSON");
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
      teinte: verdict === null ? null : [...verdict.classList].filter((c) => c.startsWith("pv-verdict-")).join(" "),
      mention: t("#verdict-mention"),
      nonProuve: t("#non-prouve"),
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
          reserves: li.dataset.reserves ?? null,
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
/**
 * Identifiants des avertissements que le rapport rattache à un contrôle réussi, écrit ici une seconde fois : la
 * vérification que l'avertissement nomme (`check`) figure dans la liste `checks` du contrôle (CT-6 §18, point 15).
 */
function reservesAttendues(json, c) {
  if (c.status !== "reussi") return [];
  return [...new Set((json.warnings ?? []).filter((w) => typeof w.check === "string" && (c.checks ?? []).includes(w.check)).map((w) => w.id))];
}

/** La phrase de ce que les contrôles non réussis laissent sans preuve, écrite ici une seconde fois (point 14). */
function nonProuveAttendu(nonReussis, T) {
  const date = nonReussis.includes(4) && nonReussis.includes(5);
  const noms = nonReussis.filter((n) => !(date && n === 5)).map((n) => (date && n === 4 ? T.non_prouve_4_5 : T[`non_prouve_${n}`]));
  if (noms.length === 0) return null;
  if (noms.length === 1) return libelle(T, "non_prouve_un", { liste: noms[0] });
  return libelle(T, "non_prouve_plusieurs", { liste: `${noms.slice(0, -1).join(T.non_prouve_sep)}${T.non_prouve_dernier}${noms[noms.length - 1]}` });
}

function attendu(cas, T) {
  const mots = { 0: ["mot_0", "nt-verdict-valide"], 1: ["mot_1", "nt-verdict-non-valide"], 2: ["mot_2", ""], 3: ["mot_3", "nt-verdict-incomplet"] };
  const r = { mot: T[mots[cas.code][0]], variante: mots[cas.code][1], teinte: "", mention: null, nonProuve: null, code: libelle(T, "code", { code: cas.code, sens: T[`code_${cas.code}`] }) };
  if (cas.code === 2) return { ...r, controles: [], pastillesReussi: 0, tousReussis: null, borne: null, exiges: null };
  const exiges = cas.json.inputs.required_controls;
  r.controles = cas.json.controls.map((c) => {
    const reserves = reservesAttendues(cas.json, c);
    return {
      numero: c.number,
      statut: c.status,
      etat: reserves.length > 0 ? T.statut_reussi_reserve : T[`statut_${c.status}`],
      montreReussi: c.status === "reussi" && reserves.length === 0,
      titre: `${c.number}. ${T[`controle_${c.number}`]}`,
      raison: c.status === "non_execute" ? libelle(T, "raison", { raison: T[`raison_${c.reason}`], code: c.reason }) : null,
      exige: exiges.includes(c.number) ? T.controle_exige : null,
      reserves: reserves.length > 0 ? reserves.join(" ") : null,
    };
  });
  const nonReussis = cas.json.controls.filter((c) => c.status !== "reussi").map((c) => c.number);
  const avecReserve = r.controles.filter((c) => c.reserves !== null).length;
  // Sous le code 0, le vert plein ne reste que pour huit contrôles réussis sans avertissement ; sinon la teinte
  // d'avertissement et la mention fixe, et la phrase de ce qui n'est pas prouvé (point 14).
  const avertis = (cas.json.warnings ?? []).length > 0;
  if (cas.code === 0 && (nonReussis.length > 0 || avertis)) {
    r.variante = "";
    r.teinte = "pv-verdict-reserve";
    r.mention = nonReussis.length > 0 && avertis ? T.mention_les_deux : nonReussis.length > 0 ? T.mention_non_prouve : T.mention_reserves;
    r.nonProuve = nonProuveAttendu(nonReussis, T);
  }
  r.pastillesReussi = 8 - nonReussis.length - avecReserve;
  r.tousReussis = cas.code === 0 && nonReussis.length === 0 ? (avecReserve === 0 ? T.tous_reussis : libelle(T, "tous_reussis_reserve", { n: avecReserve })) : null;
  r.borne = cas.code === 0 && nonReussis.length > 0 ? libelle(T, "valide_borne", { liste: nonReussis.join(", ") }) : null;
  r.exiges = cas.code === 3 ? libelle(T, "exiges_non_reussis", { liste: exiges.filter((n) => nonReussis.includes(n)).join(", ") }) : null;
  return r;
}

const garder = (ecran, cles) => Object.fromEntries(cles.map((k) => [k, ecran[k]]));
const CLES_VERDICT = ["mot", "variante", "teinte", "mention", "nonProuve", "code", "controles", "pastillesReussi", "tousReussis", "borne", "exiges"];

// --- Langage (complément du 2026-11-18 de CT-6 §18) ------------------------------

/** Les fonctions et tables du langage courant d'interface.js, telles qu'écrites ; null si les sources ne les ont pas. */
const NOMS_LANGAGE = ["clePhraseCourante", "cleAvertissement", "cleRefusCourant", "membresEnonce", "aDesReserves", "PHRASES_COURANTES", "LIMITES", "SUITES", "presentationVerdict", "clesNonProuve", "controlesDeLAvertissement", "reservesDuControle", "grouperAvertissements", "clePieceEnCause", "PIECES_EN_CAUSE", "instantDeSecondes", "instantDeTexte", "lignesEnResume", "CONTROLE_DU_RESUME", "GABARITS_DECISION"];

/** `transformer` : changement appliqué à la source avant de l'évaluer (mutant joué sous Node) ; il doit la changer. */
function chargerLangage(transformer = null) {
  const source = lire("interface.js");
  const debut = source.indexOf("// --- Langage courant");
  const fin = source.indexOf("// --- Résumé tiré du rapport JSON");
  if (debut < 0 || fin < debut) return null;
  let section = source.slice(debut, fin);
  if (transformer !== null) {
    const mutee = transformer(section);
    expect(mutee, "le mutant change la source").to.not.equal(section);
    section = mutee;
  }
  // Un nom que les sources n'ont pas (sources d'avant ce complément) vaut null.
  return vm.runInNewContext(`${section}\n({ ${NOMS_LANGAGE.map((n) => `${n}: typeof ${n} === "undefined" ? null : ${n}`).join(", ")} });`, {});
}

const texteCt6 = () => fs.readFileSync(path.join(RACINE, "spec", "CT-6-verificateur.md"), "utf8");

/** Lignes de la table à trois colonnes de CT-6 dont la ligne d'en-tête est `entete`, qui n'y figure qu'une fois. */
function tableCt6(entete) {
  const lignes = texteCt6().split("\n");
  const places = lignes.flatMap((l, i) => (l === entete ? [i] : []));
  expect(places, `en-tête de table dans CT-6 : ${entete}`).to.have.length(1);
  expect(lignes[places[0] + 1]).to.equal("|---|---|---|");
  const r = [];
  for (let i = places[0] + 2; i < lignes.length && lignes[i].startsWith("| "); i++) {
    expect(lignes[i].endsWith(" |"), lignes[i]).to.equal(true);
    const cellules = lignes[i].slice(2, -2).split(" | ");
    expect(cellules, lignes[i]).to.have.length(3);
    r.push(cellules);
  }
  return r;
}

/** Clé du libellé d'un avertissement, écrite ici une seconde fois : « AV-O-3 » → « av_o_3 ». */
const cleAv = (id) => `av_${id.slice(3, id.lastIndexOf("-")).toLowerCase()}_${id.slice(id.lastIndexOf("-") + 1)}`;

/**
 * Termes qu'une personne qui n'a pas lu la spécification ne comprend pas : aucun ne paraît au premier niveau de
 * lecture de la page, c'est-à-dire hors des blocs repliés fermés, hors des textes exacts (attribut data-exact : texte
 * du vérificateur ou phrase fixée par CT-6, toujours précédés d'une phrase en langage courant) et hors des valeurs
 * venues des données (attribut data-valeur). La liste part des règles de rédaction des écrans et de la relecture de
 * la page par une personne étrangère au projet.
 */
const TERMES_DE_TECHNICIEN = [
  ["oidc", /\boidc\b/i],
  ["adresse d'un service en clair", /https?:\/\//i],
  ["condensé", /condens[ée]|\bdigests?\b/i],
  ["hachage", /hachage|\bhash/i],
  ["hors bande", /hors[ -]bande|out[- ]of[- ]band/i],
  ["clé de chaîne", /clé de chaîne|chain key/i],
  ["manifeste", /manifeste?s?\b/i],
  ["ancre, sans explication", /\bancres?\b|\banchors?\b/i],
  ["RPC", /\bRPC\b/],
  ["nonce", /\bnonce\b/i],
  ["regtest", /regtest/i],
  ["drapeau de ligne de commande", /(^|[\s(«“"'])--[a-z]/],
  ["identifiant de règle, de contrôle ou d'exigence", /\b(?:AV|EX|TE|TA|CT|RG)-[A-Z0-9]|\b[A-Z]{1,2}-[0-9]+\b/],
  ["suite hexadécimale", /0x[0-9a-f]{6,}|\b[0-9a-f]{16,}\b/i],
  ["nom de code d'état, d'étape ou de raison", /\b[a-z]+_[a-z_]+\b/],
  ["WebAssembly", /webassembly|\bwasm\b/i],
  ["binaire", /\bbinaires?\b|\bbinar(?:y|ies)\b/i],
  ["nom d'algorithme ou de fichier d'empreintes", /\bSHA-?[0-9]/i],
  // Le mot, pas la fin d'un nom de fichier (« .json », comme « .zip ») par laquelle une personne reconnaît une pièce.
  ["JSON", /(?<!\.)\bJSON\b/i],
  ["code de retour", /code de retour|code de sortie|exit code/i],
  ["sortie standard ou sortie d'erreur", /sortie standard|sortie d'erreur|standard (?:output|error)|\bstd(?:out|err)\b/i],
  ["travailleur", /\btravailleurs?\b|\bworkers?\b/i],
  ["répertoire", /répertoire|\bdirector(?:y|ies)\b/i],
  ["archive", /\barchives?\b/i],
  ["format d'archive ou de codage en toutes lettres", /ZIP64|\bustar\b|\bpax\b|\bGNU\b|\bCRC\b|UTF-8|\bASCII\b/],
  ["événement (à l'écran : action enregistrée)", /événement|\bevents?\b/i],
  ["seuil (à l'écran : nombre d'approbations requises)", /\bseuils?\b|\bthresholds?\b/i],
  ["quorum", /quorum/i],
  ["RFC", /\bRFC\b/],
  ["OpenTimestamps", /opentimestamps/i],
  ["non exécuté (à l'écran : non fait)", /non[- ]ex[ée]cut|\bnot run\b/i],
  ["énoncé (à l'écran : texte exact du vérificateur)", /\bénoncés?\b/i],
];

/** Termes de technicien trouvés dans des textes : « terme : texte ». */
function termesTrouves(textes) {
  const r = [];
  for (const t of textes) for (const [nom, motif] of TERMES_DE_TECHNICIEN) if (motif.test(t)) r.push(`${nom} : « ${t} »`);
  return r;
}

/**
 * Libellés qui ne sont jamais au premier niveau de lecture : phrases fixées par CT-6 §18 et textes de détail, que
 * la page pose dans un élément data-exact ou dans un bloc replié « Pour les spécialistes ». Tout autre libellé est
 * soumis à la liste des termes de technicien.
 */
const LIBELLES_EXACTS_OU_REPLIES = ["phrase_fixe", "artefact_pret", "artefact_altere", "code", "code_0", "code_1", "code_2", "code_3", "noms_choisis", "nom_dossier_repertoire", "nom_dossier_archive", "nom_ancres", "nom_entetes", "nom_interne", "commande", "sortie_erreur", "refus_archive", "avertissement", "avertissement_sans_verification"];
const estExactOuReplie = (cle) => LIBELLES_EXACTS_OU_REPLIES.includes(cle) || /^(r|i|type)_/.test(cle);

/** Éléments qui peuvent porter data-exact : la liste est fermée, pour que la marque ne serve pas à soustraire un texte à l'épreuve. */
const PORTEURS_EXACTS = ["#phrase-fixe", "#artefact", "#code", "#enonce-fr", "#enonce-en", ".pv-reserve-exacte", "#sortie-erreur", "#message-erreur", "#resultat-contenu .pv-exact > .alerte", "#resultat-contenu .pv-exact > .aucun-rapport", ".pv-resume-exact", "pre.rapport", "pre.rapport-json", "pre.commande"];

/**
 * Ce qu'une personne lit sans rien ouvrir : les textes de la page hors des blocs repliés fermés (leur titre excepté),
 * hors des éléments masqués, des textes exacts et des valeurs ; et les éléments marqués data-exact qui ne sont pas
 * dans la liste fermée des porteurs.
 */
async function premierNiveau(page) {
  return page.evaluate((porteurs) => {
    const textes = [];
    const marcheur = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = marcheur.nextNode(); n !== null; n = marcheur.nextNode()) {
      const texte = n.textContent.replace(/\s+/g, " ").trim();
      if (texte === "") continue;
      let lu = true;
      for (let a = n.parentElement; a !== null && a !== document.body; a = a.parentElement) {
        const parent = a.parentElement;
        const dansBlocFerme = parent !== null && parent.tagName === "DETAILS" && !parent.open && a.tagName !== "SUMMARY";
        if (a.hasAttribute("data-exact") || a.hasAttribute("data-valeur") || a.hidden || dansBlocFerme || getComputedStyle(a).display === "none") {
          lu = false;
          break;
        }
      }
      if (lu) textes.push(texte);
    }
    const horsListe = [...document.querySelectorAll("[data-exact]")].filter((e) => !porteurs.some((s) => e.matches(s))).map((e) => `${e.tagName.toLowerCase()}#${e.id}.${e.className}`);
    return { textes, horsListe };
  }, PORTEURS_EXACTS);
}

const HEX2 = `0x${"c3".repeat(32)}`;

/** Rapport réaliste : énoncé à plusieurs membres de phrase, résumés et avertissements dans les mots du vérificateur. */
function rapportRealiste({ code, statuts, raisons = {}, exiges = [], echecs = [], avertissements = [] }) {
  const r = rapport({ code, statuts, raisons, exiges, echecs, avertissements });
  const resumes = ["hachage canonique recalculé égal à hash", "chaîné aux voisins seq 6 et 8", `feuille 6 de l'arbre de 9 du manifeste ${HEX}`, "selon AC de test CT-6 (unité TSA de test CT-6) ; aucun statut qualifié déclaré", "bloc Bitcoin 1001 du réseau regtest, 20 confirmations (réseau d'essai)", "rec-test-01 (événement), rec-test-02 (manifeste), clés fournies par le fichier d'ancres", "apr-2201 : 2 signatures, seuil 2 sur 3 ; A-4 hors dossier", "noortrace-2124-dev : 3 validateurs sur 4 à chaque bloc"];
  r.controls.forEach((c, i) => (c.summary = resumes[i]));
  r.statement = {
    fr: `L'événement seq 7 (hachage ${HEX}) du journal ${HEX2} est bien formé, chaîné à ses voisins seq 6 et 8 et inclus dans la période close par le manifeste ${HEX} ; l'événement est signé par la clé d'enregistreur rec-test-01, clés fournies par le fichier d'ancres ; l'événement porte l'approbation de la demande ${HEX2} (ticket apr-2201 ; seuil de 2 sur 3) ; ce dossier ne prouve rien sur sa date (contrôles 4 et 5).`,
    en: `Event seq 7 (hash ${HEX}) of journal ${HEX2} is well-formed, chained to its neighbours seq 6 and 8 and included in the period closed by manifest ${HEX}; the event is signed by recorder key rec-test-01, keys supplied by the anchors file; the event carries the approval of request ${HEX2} (ticket apr-2201; threshold 2 of 3); this dossier proves nothing about its date (controls 4 and 5).`,
  };
  return r;
}

const AV_ESSAI = { id: "AV-O-3", check: "O-5", detail: "réseau regtest : réseau d'essai, sans valeur probante hors des tests" };
const AV_INSCRIPTION = { id: "AV-R-1", check: "R-10", detail: "aucune inscription de la clé du manifeste" };
const AV_HORS_TABLE = { id: "AV-Z-9", check: "Z-1", detail: "avertissement d'une version future du vérificateur" };

/** Les cas du langage : un rapport réaliste par verdict, avec et sans avertissement, dont un avertissement hors table. */
const CAS_LANGAGE = {
  valide: { code: 0, json: rapportRealiste({ code: 0, statuts: [R, R, R, R, R, R, R, R] }) },
  valideAverti: { code: 0, json: rapportRealiste({ code: 0, statuts: [R, R, R, R, R, R, R, R], avertissements: [AV_ESSAI, AV_HORS_TABLE, { ...AV_ESSAI, check: "K-9" }] }) },
  valideNonFaits: { code: 0, json: rapportRealiste({ code: 0, statuts: [R, R, R, N, N, R, R, N], raisons: { 4: "ancre_absente", 5: "partie_absente", 8: "hors_perimetre_version" } }) },
  nonValide: { code: 1, json: rapportRealiste({ code: 1, statuts: [E, R, R, N, N, R, R, N], raisons: { 4: "prerequis_en_echec", 5: "partie_absente", 8: "ancre_absente" }, echecs: ["E-7"], avertissements: [AV_INSCRIPTION] }) },
  incomplet: { code: 3, json: rapportRealiste({ code: 3, statuts: [R, R, R, N, N, R, R, N], raisons: { 4: "ancre_absente", 5: "partie_absente", 8: "ancre_absente" }, exiges: [4, 7, 8], avertissements: [AV_INSCRIPTION] }) },
  illisible: CAS.aucun,
};
/** Code de retour hors de la table de CT-6 §8.3, rendu par les deux exécutions : « vérification non faite ». */
const CAS_CODE_INCONNU = { code: 4, json: { ...rapportRealiste({ code: 0, statuts: [R, R, R, R, R, R, R, R] }), exit_code: 4 } };

// --- Seconde lecture (complément du 2026-11-18 de CT-6 §18, points 14 à 19) ---------

const AV_POINT = { id: "AV-K-1", check: "K-8", detail: "référence au registre du point déclarative : l'inclusion de l'ancre du point n'est pas prouvée" };
const DETAIL_E7 = `evenement : hash recalculé ${HEX} différent de hash ${HEX2}`;
const DETAIL_D2 = "approbations.json déclaré présent mais absent du répertoire";

/**
 * Rapport aux faits réalistes, d'après la forme du rapport d'un dossier des vecteurs (CT-6 §8.6) : vérifications de
 * chaque contrôle (`checks`), événement, période en secondes, faits des contrôles réussis.
 */
function rapportAuxFaits({ code = 0, statuts = [R, R, R, R, R, R, R, R], raisons = {}, exiges = [], echecs = [], avertissements = [], decision = "approuve" } = {}) {
  const r = rapportRealiste({ code, statuts, raisons, exiges, echecs, avertissements });
  const listes = [["E-1", "E-7"], ["C-1", "K-6"], ["M-1", "P-1", "K-1"], ["K-7", "T-1"], ["K-9", "O-5"], ["E-8", "N-3"], ["E-5", "A-3"], ["K-8", "R-10", "N-4"]];
  r.controls.forEach((c, i) => (c.checks = listes[i]));
  r.checks = [{ id: "D-2", controls: [], status: echecs.includes("D-2") ? E : R, reason: null, admitted: null, detail: DETAIL_D2 }, { id: "E-7", controls: [1], status: echecs.includes("E-7") ? E : R, reason: null, admitted: null, detail: DETAIL_E7 }];
  r.event = { seq: 7, hash: HEX, ts: "2026-11-05T09:31:48.006Z", tool: "sap.payments.create" };
  r.period = { period_start: 1793869200, period_end: 1793872800, period_hash: HEX2 };
  const ok = (n) => statuts[n - 1] === R;
  r.facts = {
    approval: ok(7) ? { decision, ticket: "apr-2201", approvers: decision === "expire" ? [] : ["0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"], required: 2, size: 3, set_source: "dossier" } : null,
    timestamp: ok(4) ? { authority: "AC de test CT-6", gen_time: "2026-11-01T00:00:05Z", upper_bound: "2026-11-01T00:00:06Z" } : null,
    bitcoin: ok(5) ? { network: "regtest", block_time: "2026-11-05T13:50:00Z", median_bound: "2026-11-05T14:50:00Z" } : null,
  };
  return r;
}

const NON_FAITS = { statuts: [R, R, R, N, N, R, R, N], raisons: { 4: "ancre_absente", 5: "partie_absente", 8: "ancre_absente" } };

/** Les cas de la seconde lecture : « Valide » plein, avec réserves, aux contrôles non faits, les deux ; décisions ; codes 1 et 3. */
const CAS_SECONDE = {
  plein: { code: 0, json: rapportAuxFaits() },
  reserves: { code: 0, json: rapportAuxFaits({ avertissements: [AV_POINT, { ...AV_ESSAI, check: "K-9" }, AV_HORS_TABLE, AV_ESSAI] }) },
  nonFaits: { code: 0, json: rapportAuxFaits(NON_FAITS) },
  // Un avertissement sur un contrôle non fait ne change pas sa ligne ; celui du contrôle 2 la change.
  lesDeux: { code: 0, json: rapportAuxFaits({ ...NON_FAITS, avertissements: [AV_ESSAI, { id: "AV-K-3", check: "K-6", detail: "voisinage non rattaché au point de contrôle" }] }) },
  seulQuatre: { code: 0, json: rapportAuxFaits({ statuts: [R, R, R, N, R, R, N, R], raisons: { 4: "ancre_absente", 7: "partie_absente" } }) },
  refuse: { code: 0, json: rapportAuxFaits({ decision: "refuse" }) },
  expire: { code: 0, json: rapportAuxFaits({ decision: "expire" }) },
  incomplet: { code: 3, json: rapportAuxFaits({ code: 3, ...NON_FAITS, exiges: [4, 8], avertissements: [AV_POINT] }) },
  nonValide: { code: 1, json: rapportAuxFaits({ code: 1, statuts: [E, R, R, N, N, R, R, N], raisons: { 4: "hors_perimetre_version", 5: "hors_perimetre_version", 8: "hors_perimetre_version" }, echecs: ["D-2", "E-7"] }) },
};

/** Instant en toutes lettres, écrit ici une seconde fois avec l'horloge du moteur : temps universel, gabarit de la langue. */
function instantAttendu(ms, T) {
  const d = new Date(ms);
  const deux = (n) => String(n).padStart(2, "0");
  return libelle(T, "instant", { jour: d.getUTCDate() === 1 ? T.jour_premier : d.getUTCDate(), mois: T[`mois_${d.getUTCMonth() + 1}`], annee: d.getUTCFullYear(), heure: deux(d.getUTCHours()), minute: deux(d.getUTCMinutes()), seconde: deux(d.getUTCSeconds()) });
}

/**
 * Les lignes « En résumé » qu'un rapport doit donner, écrites ici une seconde fois (point 17) : chaque valeur est un
 * champ du rapport ; aucune ligne hors des codes 0 et 3, ni pour un contrôle que le rapport ne dit pas réussi.
 */
function enResumeAttendu(json, code, T) {
  if (code !== 0 && code !== 3) return [];
  const ok = (n) => json.controls[n - 1].status === "reussi";
  const l = [];
  if (ok(1)) l.push(["action", libelle(T, "resume_action", { seq: json.event.seq })]);
  if (ok(1) && typeof json.event.tool === "string" && json.event.tool !== "") l.push(["outil", libelle(T, "resume_outil", { outil: json.event.tool })]);
  if (ok(3)) l.push(["periode", libelle(T, "resume_periode", { debut: instantAttendu(json.period.period_start * 1000, T), fin: instantAttendu(json.period.period_end * 1000, T) })]);
  const a = json.facts.approval;
  if (ok(7) && a) l.push(["approbation", libelle(T, { approuve: "resume_approbation", refuse: "resume_refus", expire: "resume_expiration" }[a.decision], { n: a.approvers.length, requis: a.required, taille: a.size })]);
  const t = json.facts.timestamp;
  if (ok(4) && t && t.upper_bound) l.push(["limite_autorite", libelle(T, "resume_limite_autorite", { limite: instantAttendu(Date.parse(t.upper_bound), T) })]);
  if (ok(5) && json.facts.bitcoin) l.push(["limite_bitcoin", T.resume_limite_bitcoin]);
  return l;
}

/** Ce que la page écrit des points 15 à 19 : résumé, renvois des contrôles, échecs dits, pièce en cause. */
async function lireSeconde(page) {
  return page.evaluate(() => {
    const t = (s) => (document.querySelector(s) === null ? null : document.querySelector(s).textContent);
    const avant = (a, b) => document.querySelector(a) !== null && document.querySelector(b) !== null && (document.querySelector(a).compareDocumentPosition(document.querySelector(b)) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
    return {
      enResume: [...document.querySelectorAll("#en-resume li")].map((li) => [li.dataset.ligne, li.textContent]),
      resumeFin: t("#resume-fin"),
      resumeAvantEnonce: document.querySelector("#en-resume") === null ? null : avant("#en-resume", "#enonce"),
      resumeTexte: t("#en-resume"),
      valeursDuResume: [...document.querySelectorAll("#en-resume li [data-valeur]")].map((e) => e.textContent),
      renvois: [...document.querySelectorAll("#controles .pv-controle-reserve")].map((e) => [Number(e.closest("li").dataset.numero), e.textContent, e.querySelector("a").getAttribute("href")]),
      pastillesReserve: [...document.querySelectorAll("#controles li")].filter((li) => li.querySelector(".nt-pastille").classList.contains("nt-pastille-attente")).map((li) => Number(li.dataset.numero)),
      compte: t("#compte-controles"),
      echecsControles: [...document.querySelectorAll("#controles .pv-controle-dit")].map((e) => [Number(e.closest("li").dataset.numero), e.textContent]),
      echecsVerdict: [...document.querySelectorAll("#verdict .pv-controle-dit")].map((e) => e.textContent),
      piece: t("#piece-en-cause"),
      pieceAvantMessage: document.querySelector("#piece-en-cause") === null ? null : avant("#piece-en-cause", "#message-erreur"),
      signe: document.querySelector("#verdict .nt-verdict-signe path") === null ? null : document.querySelector("#verdict .nt-verdict-signe path").getAttribute("d"),
      titre: t("#verdict-titre"),
    };
  });
}

/** Ce que la page écrit en langage courant autour du texte du vérificateur. */
async function lireLangage(page) {
  return page.evaluate(() => {
    const e = (s) => document.querySelector(s);
    const t = (s) => (e(s) === null ? null : e(s).textContent);
    const avant = (a, b) => e(a) !== null && e(b) !== null && (e(a).compareDocumentPosition(e(b)) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
    const code = e("#code");
    return {
      mot: t("#verdict-mot"),
      phrase: t("#phrase-courante"),
      phraseDansLeVerdict: e("#verdict #phrase-courante") !== null,
      reserves: t("#reserves"),
      code: t("#code"),
      introCode: code === null ? null : code.parentElement.querySelector(".pv-exact-intro").textContent,
      codeMarqueExact: code === null ? null : code.hasAttribute("data-exact"),
      codeReplie: code === null ? null : code.closest("details") !== null,
      ordre: { motPuisPhrase: avant("#verdict-mot", "#phrase-courante"), phrasePuisCode: avant("#phrase-courante", "#code"), verdictPuisReserves: avant("#verdict", "#avertissements"), reservesPuisControles: avant("#avertissements", "#controles"), controlesPuisEnonce: avant("#controles", "#enonce"), enoncePuisLimites: avant("#enonce", "#limites"), enoncePuisSuite: avant("#enonce", "#suite"), suitePuisSpecialistes: avant("#suite", "#specialistes") },
      listeReserves: [...document.querySelectorAll("#avertissements li.pv-reserve")].map((li) => {
        const courante = li.querySelector(".pv-reserve-courante");
        const exactes = [...li.querySelectorAll(".pv-reserve-exacte")];
        return {
          id: li.dataset.id,
          courante: courante === null ? null : courante.textContent,
          exactes: exactes.map((e) => e.textContent),
          intros: [...li.querySelectorAll(".pv-exact-intro")].map((e) => e.textContent),
          couranteAvantExacte: courante === null ? null : exactes.every((e) => (courante.compareDocumentPosition(e) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0),
          exacteMarquee: exactes.every((e) => e.hasAttribute("data-exact")),
        };
      }),
      reservesRepliees: e("#avertissements") === null ? null : e("#avertissements").closest("details") !== null,
      limites: [...document.querySelectorAll("#limites li")].map((li) => li.textContent),
      suite: [...document.querySelectorAll("#suite li")].map((li) => li.textContent),
      nonFaite: t(".non-faite"),
      cause: t("#resultat-contenu .cause"),
      resultat: t("#resultat"),
    };
  });
}

/**
 * Ce que la page doit écrire, d'après le complément du 2026-11-18 de CT-6 §18, écrit ici une seconde fois : la phrase
 * du code de retour ; la ligne des réserves sous un code 0 ou 3 dont le rapport porte un avertissement ; chaque
 * avertissement, sa phrase s'il est dans la table et son texte exact ; les lignes fixes des deux rubriques.
 */
function attenduLangage(cas, T) {
  const w = cas.json.warnings ?? [];
  // Une réserve de la table signalée plusieurs fois n'est dite qu'une fois, « (signalée N fois) », avec chacun de
  // ses textes exacts ; hors table, chaque avertissement reste seul (point 16).
  const groupes = [];
  for (const a of w) {
    const g = Object.hasOwn(T, cleAv(a.id)) ? groupes.find((x) => x[0].id === a.id) : undefined;
    if (g) g.push(a);
    else groupes.push([a]);
  }
  const lignes = [1, 2, 3, 4, 5].map((n) => T[`limite_${n}`]);
  return {
    mot: T[`mot_${cas.code}`],
    phrase: T[`phrase_${cas.code}`],
    phraseDansLeVerdict: true,
    reserves: (cas.code === 0 || cas.code === 3) && w.length > 0 ? T.reserves : null,
    code: libelle(T, "code", { code: cas.code, sens: T[`code_${cas.code}`] }),
    introCode: T.formule_exacte,
    codeMarqueExact: true,
    codeReplie: false,
    listeReserves: groupes.map((g) => ({
      id: g[0].id,
      courante: Object.hasOwn(T, cleAv(g[0].id)) ? `${T[cleAv(g[0].id)]}${g.length > 1 ? ` ${libelle(T, "reserve_fois", { n: g.length })}` : ""}` : null,
      exactes: g.map((a) => libelle(T, "avertissement", { detail: a.detail, id: a.id, check: a.check })),
      intros: g.map(() => T.texte_exact),
      couranteAvantExacte: Object.hasOwn(T, cleAv(g[0].id)) ? true : null,
      exacteMarquee: true,
    })),
    limites: { 0: lignes, 1: [T.limite_invalide], 2: [], 3: lignes }[cas.code],
    suite: [1, 2, 3].map((n) => T[`suite_${cas.code}_${n}`]),
  };
}
const CLES_LANGAGE = ["mot", "phrase", "phraseDansLeVerdict", "reserves", "code", "introCode", "codeMarqueExact", "codeReplie", "listeReserves", "limites", "suite"];

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
    // Complément du 2026-11-18 de CT-6 §18 (point 8) : la ligne écrite sous le code 0 quand un contrôle n'est pas réussi.
    expect(fr.valide_borne.startsWith("Contrôles qui n'ont pas pu être faits : n° {liste}")).to.equal(true);
    expect(en.valide_borne.startsWith("Controls that could not be done: no. {liste}")).to.equal(true);
    expect([fr.statut_reussi, fr.statut_echoue, fr.statut_non_execute, en.statut_reussi, en.statut_echoue, en.statut_non_execute]).to.deep.equal(["Réussi", "Échoué", "Non fait", "Passed", "Failed", "Not done"]);
  });

  it("gabarit : la phrase fixe, l'état du vérificateur, le choix du dossier, « Vérifier », « Arrêter » et le résultat sont hors de tout bloc replié ; seuls « Comment ça marche », l'empreinte et les options sont repliés ; page.js est dans l'en-tête", function () {
    const html = lire("index.modele.html");
    const blocs = [...html.matchAll(/<details\b[^>]*>[\s\S]*?<\/details>/g)].map((m) => ({ debut: m.index, fin: m.index + m[0].length, id: /id="([^"]+)"/.exec(m[0].slice(0, m[0].indexOf(">")))?.[1] ?? null }));
    // « Comment ça marche » (complément du 2026-11-18 de CT-6 §18, EX-18.2) est un bloc replié de plus : cinq lignes
    // d'explication, aucune commande. Le bloc des noms de ligne de commande est dans celui des options, à sa fin.
    expect(blocs.map((b) => b.id)).to.deep.equal(["comment", "detail-empreinte", "options"]);
    expect(html.indexOf('<details class="nt-detail pv-detail" id="options-specialistes">')).to.be.greaterThan(html.indexOf('id="detail"'));
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

  it("langage (complément du 2026-11-18) : la phrase de chaque code de retour, celle de chaque avertissement et les lignes « ce que ce résultat ne dit pas » sont, mot pour mot et dans les deux langues, celles des tables de CT-6 §18 ; chaque avertissement que CT-6 définit a sa phrase, et aucun autre", function () {
    const { fr, en } = tables();
    const f = chargerLangage();
    expect(f, "tables du langage courant dans interface.js").to.not.equal(null);
    // Table par code de retour : les quatre codes de CT-6 §8.3, dans l'ordre.
    const codes = tableCt6("| Code de retour | Phrase de la page française | Phrase de la page anglaise |");
    expect(codes.map((l) => l[0])).to.deep.equal(["0", "1", "2", "3"]);
    for (const [code, phraseFr, phraseEn] of codes) expect([fr[`phrase_${code}`], en[`phrase_${code}`]], `code ${code}`).to.deep.equal([phraseFr, phraseEn]);
    expect({ ...f.PHRASES_COURANTES }).to.deep.equal({ 0: "phrase_0", 1: "phrase_1", 2: "phrase_2", 3: "phrase_3" });
    expect(tableCt6("| Cas | Phrase de la page française | Phrase de la page anglaise |")).to.deep.equal([["vérification non faite", fr.phrase_non_faite, en.phrase_non_faite], ["refus d'un dossier", fr.phrase_refus, en.phrase_refus]]);
    // Table des avertissements : exactement les identifiants que CT-6 définit hors de la section 18.
    const ct6 = texteCt6();
    const horsSection18 = ct6.slice(0, ct6.indexOf("\n## 18. Page de vérification")) + ct6.slice(ct6.indexOf("\n## Annexe A"));
    const definis = [...new Set(horsSection18.match(/AV-[A-Z]+-[0-9]+/g))].sort();
    expect(definis).to.have.length(17);
    const avertissements = tableCt6("| Avertissement | Phrase de la page française | Phrase de la page anglaise |");
    expect(avertissements.map((l) => l[0]).sort()).to.deep.equal(definis);
    for (const [id, phraseFr, phraseEn] of avertissements) {
      expect([fr[cleAv(id)], en[cleAv(id)]], id).to.deep.equal([phraseFr, phraseEn]);
      expect([f.cleAvertissement(id, fr), f.cleAvertissement(id, en)], id).to.deep.equal([cleAv(id), cleAv(id)]);
    }
    expect(Object.keys(fr).filter((k) => k.startsWith("av_")).sort()).to.deep.equal(definis.map(cleAv).sort());
    // « Ce que ce résultat ne dit pas » : cinq lignes sous 0 et 3, une sous 1, aucune sous 2.
    const limites = tableCt6("| Code de retour | Ligne de la page française | Ligne de la page anglaise |");
    expect(limites).to.deep.equal([...[1, 2, 3, 4, 5].map((n) => ["0, 3", fr[`limite_${n}`], en[`limite_${n}`]]), ["1", fr.limite_invalide, en.limite_invalide]]);
    expect(JSON.parse(JSON.stringify(f.LIMITES))).to.deep.equal({ 0: ["limite_1", "limite_2", "limite_3", "limite_4", "limite_5"], 1: ["limite_invalide"], 3: ["limite_1", "limite_2", "limite_3", "limite_4", "limite_5"] });
    // Lignes et introductions fixées dans le texte du complément.
    const texte = ct6.replace(/\s+/g, " ");
    for (const [avant, cle] of [["la ligne fixe", "reserves"], ["introduits par", "formule_exacte"], ["introduit par", "texte_exact"], ["introduite par", "raison_exacte"], ["et introduite par", "mention_exacte"], ["La phrase qui la précède est :", "confiance_courante"], ["la garantie est dite seule :", "garantie"], ["sous l'introduction", "message_exact"], ["la page écrit", "resume_indisponible"], ["porte le bouton", "verifier_autre"]]) {
      expect(texte, cle).to.include(`${avant} « ${fr[cle]} » (« ${en[cle]} »)`);
    }
    expect(texte).to.include(`« ${fr.statut_reussi} », « ${fr.statut_echoue} » et « ${fr.statut_non_execute} » (page anglaise : « ${en.statut_reussi} », « ${en.statut_echoue} », « ${en.statut_non_execute} »)`);
    // La phrase d'un code ne dit rien de plus que le code : « valide » n'y devient ni « authentique » ni « huit
    // contrôles réussis » (CT-6 §6.4, §7.1), « invalide » n'y devient pas « faux » (§7.4), et le code 2 n'affirme rien.
    for (const T of [fr, en]) {
      expect(T.phrase_0).to.not.match(/authenti|huit contrôles|eight controls|complet\b|complete\b/i);
      expect(T.phrase_1).to.not.match(/\bfaux\b|\bfausse\b|falsifi|\bfalse\b|forge/i);
      for (const cle of ["phrase_2", "phrase_non_faite", "phrase_refus"]) expect(T[cle], cle).to.match(/ni pour ni contre|neither for nor against/);
    }
  });

  it("langage : un code de retour, un avertissement ou une raison de refus hors table ne reçoit aucune phrase courante ; les membres de phrase d'un énoncé le recomposent au caractère près", function () {
    const { fr, en } = tables();
    const f = chargerLangage();
    expect(f, "tables du langage courant dans interface.js").to.not.equal(null);
    for (const code of [0, 1, 2, 3]) expect(f.clePhraseCourante(code)).to.equal(`phrase_${code}`);
    for (const code of [4, -1, 0.5, 10, "0", "1", null, undefined, NaN, true, [0], "toString", "__proto__"]) expect(f.clePhraseCourante(code), String(code)).to.equal(null);
    for (const id of ["AV-Z-9", "AV-O-9", "AV-O-03", "av-o-3", "AV-O-3 ", " AV-O-3", "AV-O-", "AV--3", "O-3", "", "__proto__", "AV-TOSTRING-1", null, undefined, 3]) expect(f.cleAvertissement(id, fr), String(id)).to.equal(null);
    // Chaque raison de refus d'EX-18.7 a sa phrase courante dans les deux langues ; toute autre valeur n'en a pas.
    const raisons = Object.keys(fr).filter((k) => /^r_/.test(k));
    expect(raisons.length).to.equal(24);
    for (const r of raisons) {
      expect([f.cleRefusCourant(r, fr), f.cleRefusCourant(r, en)], r).to.deep.equal([`c_${r}`, `c_${r}`]);
      // Une phrase courante dit ce qui s'est passé, puis quoi faire : elle a au moins deux propositions.
      for (const T of [fr, en]) expect(T[`c_${r}`], r).to.match(/[.:] \S/);
    }
    for (const r of ["r_inconnue", "c_r_forme", "forme", "", "r_", "__proto__", "toString", null, undefined]) expect(f.cleRefusCourant(r, fr), String(r)).to.equal(null);
    // Réserves : présence d'avertissements dans le rapport, ou avertissements illisibles.
    expect([f.aDesReserves([]), f.aDesReserves([{ id: "AV-O-3" }]), f.aDesReserves(null)]).to.deep.equal([false, true, true]);
    // Membres de phrase : coupure après « ; » suivi d'une espace, rien de retiré ni d'ajouté.
    const s = CAS_LANGAGE.valideNonFaits.json.statement;
    for (const texte of [s.fr, s.en, CAS.valide.json.statement.fr, "", "sans point-virgule", "a; b; c", "a ;b;c", "; ", " ; ; ", "fin ; ", "a; b; c"]) {
      const membres = [...f.membresEnonce(texte)];
      expect(membres.join(""), JSON.stringify(texte)).to.equal(texte);
      // Chaque membre, sauf peut-être le dernier, finit par « ; » et une espace, et n'en porte pas d'autre ; aucun n'est vide, sauf pour un texte vide.
      for (const [i, m] of membres.entries()) {
        if (m === "") expect(texte, "membre vide").to.equal("");
        expect(m.indexOf("; "), JSON.stringify(m)).to.equal(i < membres.length - 1 || m.endsWith("; ") ? m.length - 2 : -1);
      }
    }
    expect([...f.membresEnonce(s.fr)]).to.have.length(5);
    // Les lignes de « Et maintenant ? » existent pour chaque code, un refus et une vérification non faite.
    expect(Object.keys(f.SUITES).sort()).to.deep.equal(["0", "1", "2", "3", "non_faite", "refus"]);
    for (const cles of Object.values(f.SUITES)) for (const cle of cles) for (const T of [fr, en]) expect(typeof T[cle] === "string" && T[cle].length > 0, cle).to.equal(true);
  });

  it("langage : aucun libellé du premier niveau de lecture ne porte un terme de technicien, en français et en anglais ; les noms de ligne de commande ne sont que dans le bloc replié des options ; la phrase fixe d'EX-18.2 est marquée texte exact", function () {
    const { fr, en } = tables();
    for (const [langue, T] of [["fr", fr], ["en", en]]) {
      const lus = Object.keys(T).filter((cle) => !estExactOuReplie(cle));
      expect(lus.length).to.be.greaterThan(200);
      expect(termesTrouves(lus.map((cle) => T[cle].replace(/\{[a-z0-9_]+\}/g, "…"))), langue).to.deep.equal([]);
    }
    // La fin d'un nom de fichier (« .json ») n'est admise au premier niveau que dans la phrase de l'étape 2 qui dit à
    // quoi reconnaître la liste des références de confiance ; le mot « JSON » reste refusé partout ailleurs.
    for (const T of [fr, en]) expect(Object.keys(T).filter((cle) => !estExactOuReplie(cle) && /\.json/i.test(T[cle]))).to.deep.equal(["aide_ancres"]);
    for (const temoin of ["le rapport JSON", "un fichier json", "Rapport JSON : voir plus bas", "tableau JSON."]) expect(termesTrouves([temoin]).map((x) => x.split(" : ")[0]), temoin).to.include("JSON");
    expect(termesTrouves(["un fichier dont le nom finit par .json."]).filter((x) => x.startsWith("JSON"))).to.deep.equal([]);
    // Témoin : la liste voit les phrases fixées d'hier, qui restent, elles, dans des éléments marqués.
    expect(termesTrouves([fr.code_0, fr.phrase_fixe, fr.r_zip64, "réseau regtest (AV-O-3, vérification O-5)", "Fichier d'ancres (--ancres)"]).length).to.be.greaterThan(8);
    const html = lire("index.modele.html");
    const debut = html.indexOf('<details class="nt-detail pv-detail" id="options-specialistes">');
    const fin = html.indexOf("</details>", debut);
    expect(debut).to.be.greaterThan(-1);
    expect((html.slice(0, debut) + html.slice(fin)).includes("(--")).to.equal(false);
    for (const option of ["--ancres", "--entetes-bitcoin", "--exiger", "--exiger tous", "--langue", "--detail"]) expect(html.slice(debut, fin), option).to.include(`<span class="nt-fixe">(${option})</span>`);
    expect(html).to.include('<span id="phrase-fixe" data-exact data-libelle="phrase_fixe">{{phrase_fixe}}</span>');
    expect(html).to.include('<p id="confiance-courante" data-libelle="confiance_courante">{{confiance_courante}}</p>');
    expect(html.indexOf('id="confiance-courante"')).to.be.lessThan(html.indexOf('id="phrase-fixe"'));
    // « Arrêter » ne paraît que pendant une vérification ; les étapes ne sont réduites qu'après un rapport.
    expect(html).to.include('id="arreter" disabled hidden');
    const source = lire("interface.js");
    expect(source).to.include('etat.reduit = etat.vue.genre === "resultat";');
  });

  it("seconde lecture (complément du 2026-11-18, points 14 et 19) : la présentation ne peut que restreindre ce que le code dit ; mention de « Valide », éléments non prouvés, pièce en cause et titres du refus sont, dans les deux langues, ceux de CT-6 §18", function () {
    const { fr, en } = tables();
    const f = chargerLangage();
    expect(f.presentationVerdict, "presentationVerdict dans interface.js").to.be.a("function");
    const lus = (statuts) => statuts.map((s, i) => ({ numero: i + 1, statut: s, verifications: [] }));
    const tous = lus([R, R, R, R, R, R, R, R]);
    const bornes = lus([R, R, R, N, N, R, R, N]);
    const av = [{ id: "AV-O-3", verification: "O-5", detail: "x" }];
    const p = (...a) => ({ ...f.presentationVerdict(...a) });
    // Sous le code 0 : le plein seulement pour huit contrôles réussis sans avertissement, lus exactement.
    expect(p(0, tous, [])).to.deep.equal({ teinte: "pleine", mention: null });
    expect(p(0, bornes, [])).to.deep.equal({ teinte: "reserve", mention: "mention_non_prouve" });
    expect(p(0, tous, av)).to.deep.equal({ teinte: "reserve", mention: "mention_reserves" });
    expect(p(0, bornes, av)).to.deep.equal({ teinte: "reserve", mention: "mention_les_deux" });
    expect(p(0, lus([R, R, R, R, R, R, E, R]), [])).to.deep.equal({ teinte: "reserve", mention: "mention_non_prouve" });
    for (const [c, a] of [[null, []], [tous, null], [null, null], [null, av]]) expect(p(0, c, a)).to.deep.equal({ teinte: "neutre", mention: null });
    // Les autres codes gardent leur présentation : aucune mention, quoi que dise le rapport.
    for (const code of [1, 2, 3]) for (const [c, a] of [[tous, []], [bornes, av], [null, null]]) expect(p(code, c, a), String(code)).to.deep.equal({ teinte: "pleine", mention: null });
    // Aucune entrée ne donne le plein à un rapport que le plein ne décrit pas : tous les cas à huit statuts de deux valeurs.
    for (let m = 0; m < 256; m++) {
      const c = lus([0, 1, 2, 3, 4, 5, 6, 7].map((i) => ((m >> i) & 1 ? N : R)));
      for (const a of [[], av]) expect(p(0, c, a).teinte === "pleine", `${m}`).to.equal(m === 0 && a.length === 0);
    }
    const mentions = tableCt6("| Cas, sous le code 0 | Mention de la page française | Mention de la page anglaise |");
    expect(mentions).to.deep.equal([["un contrôle non réussi, aucun avertissement", fr.mention_non_prouve, en.mention_non_prouve], ["huit contrôles réussis, un avertissement", fr.mention_reserves, en.mention_reserves], ["un contrôle non réussi et un avertissement", fr.mention_les_deux, en.mention_les_deux]]);
    // La mention suit le mot : elle ne le remplace pas et ne dit pas « valide » à sa place.
    for (const T of [fr, en]) for (const cle of ["mention_non_prouve", "mention_reserves", "mention_les_deux"]) expect(T[cle], cle).to.match(/^, \S/).and.not.match(/valid/i);
    // Éléments non prouvés : une clé par contrôle non réussi, la date une seule fois quand 4 et 5 manquent tous deux.
    const cles = (statuts) => [...f.clesNonProuve(lus(statuts))];
    expect(cles([R, R, R, R, R, R, R, R])).to.deep.equal([]);
    expect(cles([R, R, R, N, N, R, R, N])).to.deep.equal(["non_prouve_4_5", "non_prouve_8"]);
    expect(cles([R, R, R, N, R, R, N, R])).to.deep.equal(["non_prouve_4", "non_prouve_7"]);
    expect(cles([R, R, R, R, N, R, R, R])).to.deep.equal(["non_prouve_5"]);
    expect(cles([N, N, N, N, N, N, N, N])).to.deep.equal(["non_prouve_1", "non_prouve_2", "non_prouve_3", "non_prouve_4_5", "non_prouve_6", "non_prouve_7", "non_prouve_8"]);
    const elements = tableCt6("| Contrôle non réussi | Élément de la page française | Élément de la page anglaise |");
    expect(elements).to.deep.equal([...[1, 2, 3].map((n) => [String(n), fr[`non_prouve_${n}`], en[`non_prouve_${n}`]]), ["4 et 5", fr.non_prouve_4_5, en.non_prouve_4_5], ["4 seul", fr.non_prouve_4, en.non_prouve_4], ["5 seul", fr.non_prouve_5, en.non_prouve_5], ...[6, 7, 8].map((n) => [String(n), fr[`non_prouve_${n}`], en[`non_prouve_${n}`]])]);
    // Pièce en cause : table par type d'erreur ; un type inconnu n'a pas de phrase.
    const pieces = tableCt6("| Type de l'erreur | Phrase de la page française | Phrase de la page anglaise |");
    const attendues = [["`dossier_illisible`", "piece_dossier"], ["`ancres_inutilisables`", "piece_ancres"], ["`entree_illisible`, vérification `N-2`", "piece_entetes"], ["`entree_illisible`, autre", "piece_entree"], ["`taille_depassee`", "piece_taille"], ["`usage`", "piece_usage"], ["`schemas_illisibles`, `erreur_interne`", "piece_verificateur"]];
    expect(pieces).to.deep.equal(attendues.map(([t, cle]) => [t, fr[cle], en[cle]]));
    expect([f.clePieceEnCause("dossier_illisible", null), f.clePieceEnCause("ancres_inutilisables", "N-1"), f.clePieceEnCause("entree_illisible", "N-2"), f.clePieceEnCause("entree_illisible", null), f.clePieceEnCause("taille_depassee", null), f.clePieceEnCause("usage", null), f.clePieceEnCause("schemas_illisibles", null), f.clePieceEnCause("erreur_interne", null)]).to.deep.equal(["piece_dossier", "piece_ancres", "piece_entetes", "piece_entree", "piece_taille", "piece_usage", "piece_verificateur", "piece_verificateur"]);
    for (const genre of ["inconnu", "", "toString", "__proto__", null, undefined, 2, {}]) expect(f.clePieceEnCause(genre, null), String(genre)).to.equal(null);
    // Phrases et titres fixés dans le texte du complément.
    const texte = texteCt6().replace(/\s+/g, " ");
    for (const cle of ["non_prouve_un", "non_prouve_plusieurs", "statut_reussi_reserve", "tous_reussis_reserve", "reserve_fois", "instant", "resume_fin", "dit_echec", "mention_refus", "titre_refus", "titre_refus_repertoire", "titre_refus_choix"]) expect(texte, cle).to.include(`« ${fr[cle]} » (« ${en[cle]} »)`);
    expect(texte).to.include("la présentation ne peut que restreindre, jamais étendre, ce que le code de retour dit");
    // « Examiné », et non « vérifié », pour le dossier d'un résultat ; les mots d'un contrôle avec réserve ne sont pas ceux d'un contrôle réussi.
    for (const cle of ["dossier_verifie_repertoire", "dossier_verifie_archive"]) expect([fr[cle], en[cle]].join(" "), cle).to.match(/examiné.*examined/).and.not.match(/vérifié|verified/);
    for (const T of [fr, en]) expect(T.statut_reussi_reserve).to.not.equal(T.statut_reussi);
    // Étape 2 : d'où vient la liste des références de confiance, et à quoi on la reconnaît.
    expect(fr.aide_ancres).to.include("L'organisation qui vous a remis le dossier vous fournit cette liste avec lui ; c'est un fichier dont le nom finit par .json.").and.include("Si vous ne l'avez pas");
    expect(en.aide_ancres).to.include("The organisation that gave you the dossier provides this list with it; it is a file whose name ends in .json.").and.include("If you do not have it");
  });

  it("seconde lecture (points 15 et 16) : un avertissement n'est rattaché à un contrôle que par le rapport (sa vérification dans la liste du contrôle) ; les avertissements de même identifiant de la table forment une seule réserve, sans qu'aucun soit retiré", function () {
    const { fr } = tables();
    const f = chargerLangage();
    expect(f.controlesDeLAvertissement, "controlesDeLAvertissement dans interface.js").to.be.a("function");
    const r = chargerResume();
    const json = CAS_SECONDE.reserves.json;
    const controles = r.lireControles(json, 0);
    expect(controles.map((c) => [...c.verifications])).to.deep.equal(json.controls.map((c) => c.checks));
    const a = (id, verification) => ({ id, verification, detail: "x" });
    expect([...f.controlesDeLAvertissement(a("AV-O-3", "O-5"), controles)]).to.deep.equal([5]);
    expect([...f.controlesDeLAvertissement(a("AV-O-3", "K-9"), controles)]).to.deep.equal([5]);
    expect([...f.controlesDeLAvertissement(a("AV-K-1", "K-8"), controles)]).to.deep.equal([8]);
    // Sans vérification nommée, ou nommée d'aucun contrôle : aucun rattachement ; l'identifiant seul ne rattache rien.
    for (const v of [null, "Z-1", "", "O", "O-55", "5"]) expect([...f.controlesDeLAvertissement(a("AV-O-3", v), controles)], String(v)).to.deep.equal([]);
    // Une vérification que deux contrôles portent rattache l'avertissement aux deux.
    const deux = controles.map((c) => ({ ...c, verifications: c.numero === 2 || c.numero === 3 ? ["P-3"] : [] }));
    expect([...f.controlesDeLAvertissement(a("AV-X-1", "P-3"), deux)]).to.deep.equal([2, 3]);
    const lus = r.resumer(json, 0).avertissements;
    expect([1, 2, 3, 4, 5, 6, 7, 8].map((n) => [...f.reservesDuControle(n, controles, lus)])).to.deep.equal([[], [], [], [], ["AV-O-3"], [], [], ["AV-K-1"]]);
    expect([...f.reservesDuControle(5, controles, null)]).to.deep.equal([]);
    // Regroupement : même identifiant de la table → un groupe, à la place du premier ; hors table → seul.
    const dansLaTable = (id) => f.cleAvertissement(id, fr) !== null;
    const groupes = f.grouperAvertissements(lus, dansLaTable).map((g) => [g.id, g.elements.map((x) => x.verification)]);
    expect(groupes).to.deep.equal([["AV-K-1", ["K-8"]], ["AV-O-3", ["K-9", "O-5"]], ["AV-Z-9", ["Z-1"]]]);
    const horsTable = [a("AV-Z-9", "Z-1"), a("AV-Z-9", "Z-1"), a("AV-O-3", "O-5")];
    expect(f.grouperAvertissements(horsTable, dansLaTable).map((g) => [g.id, g.elements.length])).to.deep.equal([["AV-Z-9", 1], ["AV-Z-9", 1], ["AV-O-3", 1]]);
    // Aucun avertissement n'est perdu, quel que soit l'ordre.
    for (const liste of [lus, [...lus].reverse(), horsTable, []]) expect(f.grouperAvertissements(liste, dansLaTable).flatMap((g) => [...g.elements])).to.have.members(liste).and.have.length(liste.length);
  });

  it("seconde lecture (point 17) : « En résumé » ne recopie que des champs du rapport, dans les gabarits de CT-6 §18 ; aucune ligne hors des codes 0 et 3, ni pour un contrôle non réussi ou échoué, ni pour un champ qui ne se lit pas ; aucune empreinte ; un instant est celui du rapport, en temps universel ; mutants vus", function () {
    const { fr, en } = tables();
    const f = chargerLangage();
    expect(f.lignesEnResume, "lignesEnResume dans interface.js").to.be.a("function");
    const r = chargerResume();
    // Gabarits : ceux de la table de CT-6, dans les deux langues, avec le contrôle dont chaque ligne dépend.
    const gabarits = tableCt6("| Champ du rapport, contrôle dont la ligne dépend | Gabarit de la page française | Gabarit de la page anglaise |");
    const cles = [["`event.seq`, contrôle 1", "resume_action"], ["`event.tool`, contrôle 1", "resume_outil"], ["`period.period_start` et `period.period_end`, contrôle 3", "resume_periode"], ["`facts.approval`, décision `approuve`, contrôle 7", "resume_approbation"], ["`facts.approval`, décision `refuse`, contrôle 7", "resume_refus"], ["`facts.approval`, décision `expire`, contrôle 7", "resume_expiration"], ["`facts.timestamp.upper_bound`, contrôle 4", "resume_limite_autorite"], ["`facts.bitcoin`, contrôle 5", "resume_limite_bitcoin"]];
    expect(gabarits).to.deep.equal(cles.map(([t, cle]) => [t, fr[cle], en[cle]]));
    expect({ ...f.CONTROLE_DU_RESUME }).to.deep.equal({ action: 1, outil: 1, periode: 3, approbation: 7, limite_autorite: 4, limite_bitcoin: 5 });
    expect({ ...f.GABARITS_DECISION }).to.deep.equal({ approuve: "resume_approbation", refuse: "resume_refus", expire: "resume_expiration" });
    // Aucun gabarit ne porte d'empreinte ni de paramètre qui en recevrait une ; les bornes de la période sont dites déclarées.
    for (const T of [fr, en]) for (const [, cle] of cles) expect(T[cle], cle).to.not.match(/0x|\{hash\}|\{period_hash\}|empreinte|digest/i);
    expect(fr.resume_periode).to.include("déclarés par le journal").and.include("temps universel");
    expect(en.resume_periode).to.include("declared by the log").and.include("Universal Time");
    expect([fr.resume_fin, en.resume_fin]).to.deep.equal(["Ce résumé aide à lire ; seul le texte exact ci-dessous fait foi.", "This summary helps reading; only the exact text below is authoritative."]);
    // Instants : division entière des secondes du rapport, égale à l'horloge du moteur en temps universel ; chiffres recopiés d'un instant écrit.
    const civil = (ms) => {
      const d = new Date(ms);
      return { annee: d.getUTCFullYear(), mois: d.getUTCMonth() + 1, jour: d.getUTCDate(), heure: d.getUTCHours(), minute: d.getUTCMinutes(), seconde: d.getUTCSeconds() };
    };
    const secondes = [0, 1, 59, 86399, 86400, 951782399, 951782400, 951868800, 1793869200, 1793872800, 1798761599, 1798761600, 4102444799, 4107542400, 253402300799];
    for (let i = 0; i < 4000; i++) secondes.push((i * 2654435761 + 97 * i * i) % 253402300800);
    for (const s of secondes) expect({ ...f.instantDeSecondes(s) }, String(s)).to.deep.equal(civil(s * 1000));
    for (const s of [-1, 0.5, 253402300800, 2 ** 53, "1793869200", null, undefined, NaN, Infinity]) expect(f.instantDeSecondes(s), String(s)).to.equal(null);
    for (const texte of ["2026-11-05T10:00:06Z", "2024-02-29T23:59:59Z", "1970-01-01T00:00:00Z", "9999-12-31T23:59:59Z"]) expect({ ...f.instantDeTexte(texte) }, texte).to.deep.equal(civil(Date.parse(texte)));
    for (const texte of ["2026-11-05T10:00:06.5Z", "2026-11-05T10:00:06", "2026-11-05T10:00:06+01:00", "2026-11-05 10:00:06Z", "2026-02-29T00:00:00Z", "2026-13-01T00:00:00Z", "2026-00-10T00:00:00Z", "2026-11-31T00:00:00Z", "2026-11-05T24:00:00Z", "2026-11-05T10:60:00Z", "2026-11-05T10:00:60Z", " 2026-11-05T10:00:06Z", "", null, undefined, 1793869206]) expect(f.instantDeTexte(texte), String(texte)).to.equal(null);
    // Lignes d'un rapport : nom, gabarit, valeurs et instants égaux aux champs.
    const lignes = (g, cas, controles = r.lireControles(cas.json, cas.code)) => g.lignesEnResume(cas.json, controles, cas.code).map((l) => ({ nom: l.nom, cle: l.cle, valeurs: { ...l.valeurs }, instants: Object.fromEntries(Object.entries(l.instants).map(([k, v]) => [k, { ...v }])) }));
    const attendues = (cas) => {
      const j = cas.json;
      if (cas.code !== 0 && cas.code !== 3) return [];
      const ok = (n) => j.controls[n - 1].status === R;
      const l = [];
      if (ok(1)) l.push({ nom: "action", cle: "resume_action", valeurs: { seq: String(j.event.seq) }, instants: {} });
      if (ok(1) && typeof j.event.tool === "string" && j.event.tool !== "") l.push({ nom: "outil", cle: "resume_outil", valeurs: { outil: j.event.tool }, instants: {} });
      if (ok(3)) l.push({ nom: "periode", cle: "resume_periode", valeurs: {}, instants: { debut: civil(j.period.period_start * 1000), fin: civil(j.period.period_end * 1000) } });
      if (ok(7)) l.push({ nom: "approbation", cle: { approuve: "resume_approbation", refuse: "resume_refus", expire: "resume_expiration" }[j.facts.approval.decision], valeurs: { n: String(j.facts.approval.approvers.length), requis: String(j.facts.approval.required), taille: String(j.facts.approval.size) }, instants: {} });
      if (ok(4)) l.push({ nom: "limite_autorite", cle: "resume_limite_autorite", valeurs: {}, instants: { limite: civil(Date.parse(j.facts.timestamp.upper_bound)) } });
      if (ok(5)) l.push({ nom: "limite_bitcoin", cle: "resume_limite_bitcoin", valeurs: {}, instants: {} });
      return l;
    };
    for (const [nom, cas] of Object.entries(CAS_SECONDE)) expect(lignes(f, cas), nom).to.deep.equal(attendues(cas));
    expect(lignes(f, CAS_SECONDE.plein).map((l) => l.nom)).to.deep.equal(["action", "outil", "periode", "approbation", "limite_autorite", "limite_bitcoin"]);
    expect(lignes(f, CAS_SECONDE.nonFaits).map((l) => l.nom)).to.deep.equal(["action", "outil", "periode", "approbation"]);
    expect(lignes(f, CAS_SECONDE.nonValide)).to.deep.equal([]);
    // Aucune ligne si les contrôles ne se lisent pas, ni sous les codes 1 et 2 même avec huit contrôles réussis.
    const plein = CAS_SECONDE.plein;
    const huit = r.lireControles(plein.json, 0);
    expect(lignes(f, plein, null)).to.deep.equal([]);
    for (const code of [1, 2, 4, -1, "0", null]) expect(lignes(f, { code, json: plein.json }, huit), String(code)).to.deep.equal([]);
    // Un contrôle échoué ou non fait ôte sa ligne, même si le rapport porte encore le champ (rapport contradictoire).
    const sans = (numero, statut) => lignes(f, plein, huit.map((c) => (c.numero === numero ? { ...c, statut } : c))).map((l) => l.nom);
    for (const statut of [E, N]) {
      expect(sans(1, statut), statut).to.deep.equal(["periode", "approbation", "limite_autorite", "limite_bitcoin"]);
      expect(sans(3, statut), statut).to.deep.equal(["action", "outil", "approbation", "limite_autorite", "limite_bitcoin"]);
      expect(sans(7, statut), statut).to.deep.equal(["action", "outil", "periode", "limite_autorite", "limite_bitcoin"]);
      expect(sans(4, statut), statut).to.deep.equal(["action", "outil", "periode", "approbation", "limite_bitcoin"]);
      expect(sans(5, statut), statut).to.deep.equal(["action", "outil", "periode", "approbation", "limite_autorite"]);
    }
    // Un champ qui ne se lit pas exactement ôte sa ligne, et rien n'est inventé à sa place.
    const avec = (modifier) => {
      const json = JSON.parse(JSON.stringify(plein.json));
      modifier(json);
      return lignes(f, { code: 0, json }, huit).map((l) => l.nom);
    };
    const toutes = ["action", "outil", "periode", "approbation", "limite_autorite", "limite_bitcoin"];
    const moins = (nom) => toutes.filter((x) => x !== nom);
    for (const seq of ["7", 7.5, -1, null, undefined, 2 ** 53]) expect(avec((j) => (j.event.seq = seq)), `seq ${seq}`).to.deep.equal(moins("action"));
    expect(avec((j) => (j.event = null))).to.deep.equal(moins("action").filter((x) => x !== "outil"));
    // « Outil appelé » : le nom que le rapport donne à l'outil de l'action, recopié tel quel ; aucune ligne s'il manque, s'il
    // n'est pas une chaîne, s'il est vide, ou s'il porte un caractère que la page n'afficherait pas tel quel.
    expect(lignes(f, plein).find((l) => l.nom === "outil")).to.deep.equal({ nom: "outil", cle: "resume_outil", valeurs: { outil: plein.json.event.tool }, instants: {} });
    for (const v of [undefined, null, "", 7, ["sap.payments.create"], { nom: "x" }, "outil\u202Ecache", "deux\nlignes", "a\u0000b", "x".repeat(257)]) expect(avec((j) => (v === undefined ? delete j.event.tool : (j.event.tool = v))), `outil ${JSON.stringify(v)}`).to.deep.equal(moins("outil"));
    for (const v of ["demo__payments.create", "Envoyer un courriel", "outil-é"]) expect(avec((j) => (j.event.tool = v)), v).to.deep.equal(toutes);
    expect([fr.resume_outil, en.resume_outil]).to.deep.equal(["Outil appelé : {outil}", "Tool called: {outil}"]);
    for (const v of ["1793869200", null, -5, 1.5, 253402300800]) expect(avec((j) => (j.period.period_end = v)), `fin ${v}`).to.deep.equal(moins("periode"));
    expect(avec((j) => delete j.period)).to.deep.equal(moins("periode"));
    for (const m of [(j) => (j.facts.approval.decision = "autre"), (j) => (j.facts.approval.approvers = "deux"), (j) => (j.facts.approval.approvers = [1, 2]), (j) => (j.facts.approval.required = "2"), (j) => delete j.facts.approval.size, (j) => (j.facts.approval = null)]) expect(avec(m), String(m)).to.deep.equal(moins("approbation"));
    for (const v of [null, "2026-11-05T10:00:06.5Z", "le 5 novembre", 1793869206]) expect(avec((j) => (j.facts.timestamp.upper_bound = v)), `limite ${v}`).to.deep.equal(moins("limite_autorite"));
    expect(avec((j) => (j.facts.bitcoin = null))).to.deep.equal(moins("limite_bitcoin"));
    expect(avec((j) => delete j.facts)).to.deep.equal(["action", "outil", "periode"]);
    // Mutants, joués ici sur la source : chacun rend une ligne que l'essai refuse.
    const mutants = [
      { titre: "ligne affichée alors que son contrôle a échoué", avant: 'c.numero === CONTROLE_DU_RESUME[nom] && c.statut === "reussi");', apres: "c.numero === CONTROLE_DU_RESUME[nom]);", vu: (g) => lignes(g, plein, huit.map((c) => (c.numero === 7 ? { ...c, statut: E } : c))).some((l) => l.nom === "approbation") },
      { titre: "résumé écrit sous un code qui n'affirme rien du dossier", avant: "  if ((code !== 0 && code !== 3) || controles === null ||", apres: "  if (controles === null ||", vu: (g) => lignes(g, { code: 1, json: plein.json }, huit).length > 0 },
      { titre: "instant limite pris d'un champ qui n'est pas une borne (gen_time)", avant: "const limite = instantDeTexte(jeton.upper_bound);", apres: "const limite = instantDeTexte(jeton.upper_bound ?? jeton.gen_time);", vu: (g) => { const json = JSON.parse(JSON.stringify(plein.json)); json.facts.timestamp.upper_bound = null; return lignes(g, { code: 0, json }, huit).some((l) => l.nom === "limite_autorite"); } },
      { titre: "période décalée d'un fuseau", avant: "const debut = instantDeSecondes(periode.period_start);", apres: "const debut = instantDeSecondes(periode.period_start + 3600);", vu: (g) => JSON.stringify(lignes(g, plein)) !== JSON.stringify(attendues(plein)) },
    ];
    for (const m of mutants) {
      expect(m.vu(f), `témoin : ${m.titre}`).to.equal(false);
      const g = chargerLangage((source) => source.replace(m.avant, m.apres));
      expect(m.vu(g), `mutant vu : ${m.titre}`).to.equal(true);
    }
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
        expect(await o.page.textContent("#resume-options")).to.equal([T.options_ancres, T.options_entetes, libelle(T, "options_exiger", { liste: `4${T.liste_et}8` }), T.options_detail].join(" · "));
        await o.page.click("#retirer-ancres");
        expect(await o.page.textContent("#nom-ancres")).to.equal(T.aucun_fichier);
        await o.page.click("#options > summary");
        expect(await o.page.textContent("#resume-options")).to.equal([T.options_entetes, libelle(T, "options_exiger", { liste: `4${T.liste_et}8` }), T.options_detail].join(" · "));
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
      const attendu = { dark: sombre, light: clair };
      const oppose = { dark: "light", light: "dark" };
      const systemeVu = (page) => page.evaluate(() => (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"));
      const attendreSysteme = (page, schema) => page.waitForFunction((s) => matchMedia("(prefers-color-scheme: light)").matches === (s === "light"), schema, { timeout: 10000 });
      const attendreTheme = (page, schema) => page.waitForFunction((s) => (document.documentElement.getAttribute("data-theme") === "clair") === (s === "light"), schema, { timeout: 10000 });
      // Aucune mémoire : la page rechargée après un choix contraire au système reprend l'état du système, et le
      // stockage est vide. Le système est celui que le moteur annonce à la page. Sous Firefox, le pilote perd la
      // préférence émulée quand le rechargement d'un document servi sous Cross-Origin-Opener-Policy: same-origin
      // remplace le contexte de navigation : la page voit alors la préférence du moteur, et la suit, ce qui est son
      // comportement attendu. L'essai le constate (il ne le suppose pas), l'écrit sur la sortie d'erreur, repose la
      // préférence et exige que la page, dont la bascule n'a pas servi depuis le rechargement, la suive. Dans tous
      // les cas, l'état exigé après le rechargement est celui du système demandé, contraire au choix d'avant.
      const recharger = async (page, schema) => {
        await page.reload();
        await attendreArtefact(page);
        const vu = await systemeVu(page);
        if (vu !== schema) {
          expect(await etat(page), `rechargement, ${moteur} : le moteur annonce ${vu} et la page ne le suit pas`).to.deep.equal(attendu[vu]);
          process.stderr.write(`page de vérification, ${moteur} : préférence de couleur émulée (${schema}) perdue au rechargement, la page a vu ${vu} et l'a suivi ; préférence reposée\n`);
          await page.emulateMedia({ colorScheme: schema });
          await attendreSysteme(page, schema);
          await attendreTheme(page, schema);
        }
        expect(await etat(page), `après le rechargement, système ${schema}, choix d'avant ${oppose[schema]}`).to.deep.equal(attendu[schema]);
        expect(await page.evaluate(() => [localStorage.length, sessionStorage.length, document.cookie, window.name])).to.deep.equal([0, 0, "", ""]);
      };
      const o = await ouvrirSous("dark");
      try {
        expect(await systemeVu(o.page)).to.equal("dark");
        expect(await etat(o.page)).to.deep.equal(sombre);
        await o.page.click("#bascule-theme");
        expect(await etat(o.page)).to.deep.equal(clair);
        await o.page.click("#autre-langue");
        expect((await etat(o.page)).libelle).to.equal(en.theme_vers_sombre);
        await o.page.click("#autre-langue");
        await o.page.click("#bascule-theme");
        expect(await etat(o.page)).to.deep.equal(sombre);
        await o.page.click("#bascule-theme");
        expect(await etat(o.page)).to.deep.equal(clair);
        await recharger(o.page, "dark");
        // Tant que la bascule n'a pas servi, la page suit un changement du système.
        await o.page.emulateMedia({ colorScheme: "light" });
        await attendreTheme(o.page, "light");
        expect(await etat(o.page)).to.deep.equal(clair);
        // Dès qu'elle a servi, le choix tient contre les changements du système, tant que la page est affichée.
        await o.page.click("#bascule-theme");
        await o.page.emulateMedia({ colorScheme: "dark" });
        await attendreSysteme(o.page, "dark");
        await o.page.emulateMedia({ colorScheme: "light" });
        await attendreSysteme(o.page, "light");
        await o.page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
        expect(await etat(o.page)).to.deep.equal(sombre);
      } finally {
        await o.fermer();
      }
      const c = await ouvrirSous("light");
      try {
        expect(await systemeVu(c.page)).to.equal("light");
        expect(await etat(c.page)).to.deep.equal(clair);
        // Le même rechargement dans l'autre sens : choix « sombre » sous un système clair.
        await c.page.click("#bascule-theme");
        expect(await etat(c.page)).to.deep.equal(sombre);
        await recharger(c.page, "light");
      } finally {
        await c.fermer();
      }
    });

    it("langage (complément du 2026-11-18) : sous le mot du verdict, la phrase courante du code de retour, et d'aucun autre ; dessous, la formule exacte du vérificateur, entière ; la ligne des réserves quand le rapport porte un avertissement ; chaque avertissement en langage courant puis tel quel, et tel quel seulement hors table ; « ce que ce résultat ne dit pas » et « et maintenant ? » ; en français et en anglais", async function () {
      if (!pret(this)) return;
      const T = tables();
      for (const langue of ["fr", "en"]) {
        for (const [nom, cas] of Object.entries(CAS_LANGAGE)) {
          const quoi = `${nom}, ${langue}`;
          const o = await verifierCas(cas, { langue });
          try {
            const ecran = await lireLangage(o.page);
            expect(garder(ecran, CLES_LANGAGE), quoi).to.deep.equal(attenduLangage(cas, T[langue]));
            // La phrase d'un autre code ne paraît nulle part dans le résultat.
            for (const autre of [0, 1, 2, 3].filter((c) => c !== cas.code)) expect(ecran.resultat.includes(T[langue][`phrase_${autre}`]), `${quoi}, phrase du code ${autre}`).to.equal(false);
            // Ordre : le mot, la phrase courante, la formule exacte ; puis les réserves, les contrôles, le texte
            // exact, ce que le résultat ne dit pas, la suite, et les blocs des spécialistes.
            expect([ecran.ordre.motPuisPhrase, ecran.ordre.phrasePuisCode, ecran.ordre.suitePuisSpecialistes], quoi).to.deep.equal([true, true, true]);
            if (cas.code !== 2) expect([ecran.ordre.controlesPuisEnonce, ecran.ordre.enoncePuisLimites, ecran.ordre.enoncePuisSuite], quoi).to.deep.equal([true, true, true]);
            if ((cas.json.warnings ?? []).length > 0) {
              expect([ecran.ordre.verdictPuisReserves, ecran.ordre.reservesPuisControles, ecran.reservesRepliees], quoi).to.deep.equal([true, true, false]);
              expect(await o.page.isVisible("#avertissements"), quoi).to.equal(true);
            }
            for (const s of ["#verdict-mot", "#phrase-courante", "#code"]) expect(await o.page.isVisible(s), `${quoi} ${s}`).to.equal(true);
            // Le texte du vérificateur n'est ni modifié ni abrégé : énoncés, message d'erreur, sortie d'erreur.
            const brut = await lireEcran(o.page);
            if (cas.code !== 2) expect([brut.enonceFr, brut.enonceEn], quoi).to.deep.equal([cas.json.statement.fr, cas.json.statement.en]);
            else expect([brut.message, brut.erreur], quoi).to.deep.equal([cas.json.error.message, cas.erreur]);
            expect((await o.violations()).filter((v) => !(moteur === "firefox" && v === "img-src https://verification.example/favicon.ico")), quoi).to.deep.equal([]);
            expect(o.messages.filter((m) => m.startsWith("erreur de page")), quoi).to.deep.equal([]);
          } finally {
            await o.fermer();
          }
        }
        // Code de retour hors de la table : « vérification non faite », sa phrase à elle, et aucune phrase d'un code.
        const o = await verifierCas(CAS_CODE_INCONNU, { langue });
        try {
          const ecran = await lireLangage(o.page);
          const L = T[langue];
          expect([ecran.nonFaite, ecran.phrase, ecran.code, ecran.mot], langue).to.deep.equal([L.non_faite, L.phrase_non_faite, null, null]);
          expect(ecran.cause, langue).to.equal(libelle(L, "cause", { cause: libelle(L, "cause_code_inconnu", { code: 4 }) }));
          for (const code of [0, 1, 2, 3]) expect(ecran.resultat.includes(L[`phrase_${code}`]), `${langue}, phrase du code ${code}`).to.equal(false);
          expect(ecran.suite, langue).to.deep.equal([1, 2, 3].map((n) => L[`suite_non_faite_${n}`]));
          expect(ecran.limites, langue).to.deep.equal([]);
        } finally {
          await o.fermer();
        }
      }
    });

    it("langage, mutants : phrase d'un autre code, phrase inventée pour un avertissement hors table, réserves tues, formule exacte retirée, énoncé abrégé, terme de technicien réintroduit, marque « exact » détournée, mise en garde restée au-dessus du résultat ou retirée ; l'essai les voit (tués)", async function () {
      if (!pret(this)) return;
      const T = tables();
      const nonFaits = CAS_LANGAGE.valideNonFaits;
      const averti = CAS_LANGAGE.valideAverti;
      const langage = async (o, cas, langue) => JSON.stringify(garder(await lireLangage(o.page), CLES_LANGAGE)) === JSON.stringify(attenduLangage(cas, T[langue]));
      // La mise en garde d'EX-18.2 : sous le résultat, juste avant les blocs des spécialistes, visible, hors de tout bloc replié.
      const miseEnGarde = (o) => o.page.evaluate(() => {
        const c = document.getElementById("confiance");
        const f = document.getElementById("phrase-fixe");
        return c !== null && c.parentElement !== null && c.parentElement.id === "resultat-contenu" && c.nextElementSibling === document.getElementById("specialistes") && f.getClientRects().length > 0 && f.closest("details") === null;
      });
      const mutants = [
        { titre: "la phrase d'un autre code sous « Valide »", fichier: "interface.js", avant: 'const PHRASES_COURANTES = Object.freeze({ 0: "phrase_0", 1: "phrase_1", 2: "phrase_2", 3: "phrase_3" });', apres: 'const PHRASES_COURANTES = Object.freeze({ 0: "phrase_3", 1: "phrase_1", 2: "phrase_2", 3: "phrase_3" });', cas: nonFaits, conforme: langage },
        { titre: "une phrase inventée pour un avertissement hors table", fichier: "interface.js", avant: "  return Object.hasOwn(table, cle) ? cle : null;", apres: '  return Object.hasOwn(table, cle) ? cle : "av_o_3";', cas: averti, conforme: langage },
        { titre: "les réserves tues sous « Valide »", fichier: "interface.js", avant: "  return avertissements === null || avertissements.length > 0;", apres: "  return false;", cas: averti, conforme: langage },
        { titre: "la formule exacte du vérificateur retirée", fichier: "interface.js", avant: '  suite.append(ligneExacte("formule_exacte", code));', apres: "", cas: nonFaits, conforme: langage },
        { titre: "l'énoncé abrégé à ses deux premiers membres", fichier: "interface.js", avant: "  for (const membre of membresEnonce(String(texte))) {", apres: "  for (const membre of membresEnonce(String(texte)).slice(0, 2)) {", cas: nonFaits, conforme: async (o, cas) => (await o.page.textContent("#enonce-fr")) === cas.json.statement.fr },
        { titre: "un drapeau de ligne de commande à côté d'un libellé du résultat", fichier: "libelles-fr.js", avant: '  titre_controles: "Les huit contrôles",', apres: '  titre_controles: "Les huit contrôles (--exiger)",', cas: nonFaits, conforme: async (o) => termesTrouves((await premierNiveau(o.page)).textes).length === 0 },
        { titre: "un texte de la page marqué « exact » pour le soustraire à l'épreuve", fichier: "interface.js", avant: '  const p = element("p", "nt-verdict-phrase pv-courante", libelle(cle));', apres: '  const p = exact(element("p", "nt-verdict-phrase pv-courante", libelle(cle)));', cas: nonFaits, conforme: async (o) => (await premierNiveau(o.page)).horsListe.length === 0 },
        { titre: "la mise en garde restée au-dessus du résultat", fichier: "interface.js", avant: '  if (etat.vue !== null && etat.vue.genre !== "en_cours") etat.confianceDessous = true;\n', apres: "", cas: nonFaits, conforme: miseEnGarde },
        { titre: "la mise en garde retirée de la page après un résultat", fichier: "interface.js", avant: "      if (bandeau.nextElementSibling !== specialistes) specialistes.before(bandeau);", apres: "      bandeau.remove();", cas: nonFaits, conforme: miseEnGarde },
      ];
      // Témoin : sur les sources telles qu'elles sont, chaque oracle est satisfait.
      for (const cas of [nonFaits, averti]) {
        const o = await verifierCas(cas);
        try {
          for (const m of mutants.filter((x) => x.cas === cas)) expect(await m.conforme(o, cas, "fr"), `témoin : ${m.titre}`).to.equal(true);
        } finally {
          await o.fermer();
        }
      }
      let n = 0;
      for (const m of mutants) {
        const copie = path.join(dir, `mutant-langage-${n++}`);
        fs.cpSync(SOURCES, path.join(copie, "src"), { recursive: true });
        const fichier = path.join(copie, "src", "page", m.fichier);
        const source = fs.readFileSync(fichier, "utf8");
        expect(source.split(m.avant), m.titre).to.have.length(2);
        fs.writeFileSync(fichier, source.replace(m.avant, m.apres));
        const page = construirePageFactice(path.join(copie, "construite"), path.join(copie, "src"));
        const o = await verifierCas(m.cas, { page });
        try {
          expect(await m.conforme(o, m.cas, "fr"), `mutant vu : ${m.titre}`).to.equal(false);
        } finally {
          await o.fermer();
          fs.rmSync(copie, { recursive: true, force: true });
        }
      }
    });

    it("énoncé : chaque membre de phrase (coupure après « ; ») est un bloc à part, les empreintes en chasse fixe, sans qu'un caractère change ; le texte de l'élément, celui d'une sélection et le texte copié sont l'énoncé", async function () {
      if (!pret(this)) return;
      const f = chargerLangage();
      const cas = CAS_LANGAGE.valideNonFaits;
      for (const langue of ["fr", "en"]) {
        const o = await verifierCas(cas, { langue });
        try {
          const enonce = cas.json.statement[langue];
          const vu = await o.page.evaluate((id) => {
            const p = document.getElementById(id);
            const membres = [...p.querySelectorAll(".pv-membre")];
            const rects = membres.map((m) => m.getBoundingClientRect());
            const selection = getSelection();
            selection.selectAllChildren(p);
            const tout = selection.getRangeAt(0).cloneContents().textContent;
            const plage = document.createRange();
            plage.setStart(membres[0], 0);
            plage.setEnd(membres[1], membres[1].childNodes.length);
            const hex = [...p.querySelectorAll(".pv-hex")];
            return {
              texte: p.textContent,
              exact: p.hasAttribute("data-exact"),
              replie: p.closest("details") !== null,
              membres: membres.map((m) => m.textContent),
              enfants: [...p.children].every((e) => e.classList.contains("pv-membre")) && [...p.childNodes].every((n) => n.nodeType === Node.ELEMENT_NODE),
              blocs: membres.map((m) => getComputedStyle(m).display),
              empiles: rects.every((r, i) => i === 0 || r.top >= rects[i - 1].bottom - 0.5),
              selectionEntiere: tout,
              deuxMembres: plage.cloneContents().textContent,
              hex: hex.map((h) => h.textContent),
              chasseFixe: hex.every((h) => getComputedStyle(h).fontFamily !== getComputedStyle(p).fontFamily),
            };
          }, `enonce-${langue}`);
          const membres = [...f.membresEnonce(enonce)];
          expect(membres.length, langue).to.equal(5);
          expect(vu, langue).to.deep.equal({ texte: enonce, exact: true, replie: false, membres, enfants: true, blocs: membres.map(() => "block"), empiles: true, selectionEntiere: enonce, deuxMembres: membres[0] + membres[1], hex: enonce.match(/0x[0-9a-f]{16,}/g), chasseFixe: true });
          // L'autre langue, dans son bloc replié, est rendue de même, sans qu'un caractère change.
          const autre = langue === "fr" ? "en" : "fr";
          expect(await o.page.evaluate((id) => [...document.getElementById(id).querySelectorAll(".pv-membre")].map((m) => m.textContent).join(""), `enonce-${autre}`), langue).to.equal(cas.json.statement[autre]);
          if (moteur === "chromium") {
            // Texte copié : par le bouton, puis par une sélection de tout l'énoncé et le raccourci du clavier.
            await o.contexte.grantPermissions(["clipboard-read", "clipboard-write"], { origin: "https://verification.example" });
            await o.page.click("#enonce > .pv-copie button");
            await o.page.waitForFunction(() => document.querySelector("#enonce > .pv-copie [role=status]").textContent !== "");
            expect(await o.page.evaluate(() => navigator.clipboard.readText()), `${langue}, bouton`).to.equal(enonce);
            await o.page.evaluate(() => navigator.clipboard.writeText("presse-papiers vidé par l'essai"));
            await o.page.evaluate((id) => getSelection().selectAllChildren(document.getElementById(id)), `enonce-${langue}`);
            await o.page.keyboard.press("Control+C");
            await o.page.waitForFunction(async () => (await navigator.clipboard.readText()) !== "presse-papiers vidé par l'essai");
            expect(await o.page.evaluate(() => navigator.clipboard.readText()), `${langue}, sélection`).to.equal(enonce);
          }
        } finally {
          await o.fermer();
        }
      }
    });

    it("après un rapport, les étapes se réduisent à une ligne qui nomme le dossier vérifié ; « Vérifier un autre dossier » ou le choix d'un autre dossier les ramènent ; un refus et une vérification non faite les laissent ; le mot du verdict et sa phrase sont à l'écran sans défiler ; la phrase fixe d'EX-18.2 reste affichée", async function () {
      if (!pret(this)) return;
      const T = tables().fr;
      const etat = (page) => page.evaluate(() => {
        const vu = (id) => {
          const e = document.getElementById(id);
          return e !== null && e.getClientRects().length > 0;
        };
        const aLEcran = (id) => {
          const e = document.getElementById(id);
          if (e === null) return null;
          const r = e.getBoundingClientRect();
          return r.top >= 0 && r.bottom <= innerHeight;
        };
        return { etapes: ["choix-dossier", "options", "lancer"].map(vu), verifier: vu("verifier"), arreter: vu("arreter"), ligne: vu("dossier-verifie"), nom: document.getElementById("nom-verifie").textContent, autre: vu("verifier-autre"), phraseFixe: vu("phrase-fixe"), motALEcran: aLEcran("verdict-mot"), phraseALEcran: aLEcran("phrase-courante"), resultat: !document.getElementById("resultat").hidden };
      });
      const reduit = { etapes: [false, false, false], verifier: false, arreter: false, ligne: true, nom: libelle(T, "dossier_verifie_repertoire", { nom: path.basename(DOSSIER) }), autre: true, phraseFixe: true, motALEcran: true, phraseALEcran: true, resultat: true };
      const o = await ouvrir(navigateur, pageConstruite, { remplacements: { "travailleur.js": travailleurFactice(CAS_LANGAGE.valideAverti) } });
      try {
        await o.page.goto("https://verification.example/index.html");
        await attendreArtefact(o.page);
        // Avant toute vérification : les trois étapes, aucune ligne, « Arrêter » absent.
        expect(garder(await etat(o.page), ["etapes", "verifier", "arreter", "ligne", "autre", "phraseFixe", "resultat"])).to.deep.equal({ etapes: [true, true, true], verifier: true, arreter: false, ligne: false, autre: false, phraseFixe: true, resultat: false });
        await choisirRepertoire(o.page, DOSSIER);
        await lancerVerification(o.page);
        expect(await etat(o.page), "après un rapport").to.deep.equal(reduit);
        // « Vérifier un autre dossier » : les étapes reviennent, le résultat reste, la ligne garde le nom du dossier vérifié.
        await o.page.click("#verifier-autre");
        expect(garder(await etat(o.page), ["etapes", "verifier", "ligne", "nom", "autre", "resultat"]), "après « Vérifier un autre dossier »").to.deep.equal({ etapes: [true, true, true], verifier: true, ligne: true, nom: reduit.nom, autre: false, resultat: true });
        // Une nouvelle vérification réduit de nouveau ; le choix d'un autre dossier ramène les étapes.
        await lancerVerification(o.page);
        expect(await etat(o.page), "après un second rapport").to.deep.equal(reduit);
        await choisirRepertoire(o.page, DOSSIER);
        expect(garder(await etat(o.page), ["etapes", "verifier", "autre"]), "après le choix d'un autre dossier").to.deep.equal({ etapes: [true, true, true], verifier: true, autre: false });
        // Un refus laisse les étapes : il faut y revenir pour choisir un autre dossier. La raison en langage courant
        // précède la raison exacte, qui reste entière.
        const refuse = path.join(dir, "contrat.rar");
        fs.writeFileSync(refuse, "x");
        await o.page.setInputFiles("#entree-archive", refuse);
        await lancerVerification(o.page);
        expect(garder(await etat(o.page), ["etapes", "verifier", "ligne", "autre", "resultat"]), "après un refus").to.deep.equal({ etapes: [true, true, true], verifier: true, ligne: false, autre: false, resultat: true });
        const refus = await o.page.evaluate(() => {
          const t = (s) => (document.querySelector(s) === null ? null : document.querySelector(s).textContent);
          const exacte = document.querySelector("#resultat-contenu .alerte");
          return { titre: t("#refus-titre"), titreAvantMention: (document.getElementById("refus-titre").compareDocumentPosition(document.querySelector(".aucun-rapport")) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0, mot: t(".aucun-rapport"), phrase: t("#phrase-courante"), courant: t("#refus-courant"), exacte: exacte.textContent, intro: exacte.parentElement.querySelector(".pv-exact-intro").textContent, marquee: exacte.hasAttribute("data-exact"), ordre: (document.getElementById("refus-courant").compareDocumentPosition(exacte) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0, replie: exacte.closest("details") !== null, suite: [...document.querySelectorAll("#suite li")].map((li) => li.textContent), code: t("#code") };
        });
        expect(refus).to.deep.equal({ titre: T.titre_refus, titreAvantMention: true, mot: T.aucun_rapport, phrase: T.phrase_refus, courant: T.c_r_forme, exacte: libelle(T, "refus_archive", { raison: libelle(T, "r_forme", { nom: "contrat.rar" }) }), intro: T.raison_exacte, marquee: true, ordre: true, replie: false, suite: [T.suite_refus_1, T.suite_refus_2], code: null });
      } finally {
        await o.fermer();
      }
      // Une vérification non faite laisse aussi les étapes.
      const n = await verifierCas(CAS_CODE_INCONNU);
      try {
        expect(garder(await etat(n.page), ["etapes", "verifier", "ligne", "autre", "resultat"]), "après une vérification non faite").to.deep.equal({ etapes: [true, true, true], verifier: true, ligne: false, autre: false, resultat: true });
      } finally {
        await n.fermer();
      }
    });

    it("premier écran : après une vérification, à 1280×800 comme à 390×844, le mot du verdict et le début de sa phrase courante sont à l'écran sans défiler ; la mise en garde d'EX-18.2 est en tête à l'arrivée, puis sous le résultat, juste avant « Pour les spécialistes », entière et jamais repliée ; la garantie reste en tête", async function () {
      if (!pret(this)) return;
      const lire = (page) => page.evaluate(() => {
        const e = (id) => document.getElementById(id);
        const avant = (a, b) => (a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
        const vu = (id) => e(id) !== null && e(id).getClientRects().length > 0;
        const cadre = (id) => (e(id) === null || e(id).getClientRects().length === 0 ? null : { haut: e(id).getBoundingClientRect().top, bas: e(id).getBoundingClientRect().bottom });
        const confiance = e("confiance");
        return {
          enTete: avant(confiance, e("formulaire")) && avant(confiance, e("resultat")),
          sousLeResultat: confiance.parentElement.id === "resultat-contenu",
          justeAvantLesSpecialistes: e("specialistes") !== null && confiance.nextElementSibling === e("specialistes"),
          apresLeVerdict: e("verdict") !== null && avant(e("verdict"), confiance),
          textes: ["confiance-courante", "phrase-fixe", "artefact"].map((id) => e(id).textContent),
          visibles: ["confiance-courante", "phrase-fixe", "detail-empreinte"].map(vu),
          mentionRepliee: e("phrase-fixe").closest("details") !== null,
          garantieEnTete: vu("garantie") && avant(e("garantie"), e("resultat")) && avant(e("garantie"), confiance),
          fenetre: innerHeight,
          defilement: scrollY,
          garantie: cadre("garantie"),
          mot: cadre("verdict-mot"),
          phrase: cadre("phrase-courante"),
        };
      });
      const aLEcran = (v, quoi) => {
        expect(v.mot !== null && v.phrase !== null, quoi).to.equal(true);
        expect(v.mot.haut >= 0 && v.mot.bas <= v.fenetre, `${quoi} : mot du verdict de ${v.mot.haut} à ${v.mot.bas} dans ${v.fenetre}`).to.equal(true);
        // Le début de la phrase courante : sa première ligne, soit au moins 24 px sous son bord haut.
        expect(v.phrase.haut >= 0 && v.phrase.haut + 24 <= v.fenetre, `${quoi} : phrase courante à partir de ${v.phrase.haut} dans ${v.fenetre}`).to.equal(true);
      };
      for (const fenetre of [{ width: 1280, height: 800 }, { width: 390, height: 844 }]) {
        for (const [nom, cas] of [["valide avec avertissements", CAS_LANGAGE.valideAverti], ["non valide", CAS_LANGAGE.nonValide]]) {
          const quoi = `${nom}, ${fenetre.width}×${fenetre.height}`;
          const o = await ouvrir(navigateur, pageConstruite, { remplacements: { "travailleur.js": travailleurFactice(cas) } });
          try {
            await o.page.setViewportSize(fenetre);
            await o.page.goto("https://verification.example/index.html");
            await attendreArtefact(o.page);
            // À l'arrivée : la mise en garde est en tête, avant les étapes.
            const arrivee = await lire(o.page);
            expect(garder(arrivee, ["enTete", "sousLeResultat", "visibles", "mentionRepliee", "garantieEnTete"]), `${quoi}, à l'arrivée`).to.deep.equal({ enTete: true, sousLeResultat: false, visibles: [true, true, true], mentionRepliee: false, garantieEnTete: true });
            await choisirRepertoire(o.page, DOSSIER);
            await lancerVerification(o.page);
            // Après la vérification, telle que la page se présente : le mot et le début de la phrase sont à l'écran.
            const apres = await lire(o.page);
            aLEcran(apres, `${quoi}, après la vérification`);
            // La mise en garde est passée sous le résultat, juste avant les blocs des spécialistes : mêmes textes, visibles, non repliés.
            expect(garder(apres, ["enTete", "sousLeResultat", "justeAvantLesSpecialistes", "apresLeVerdict", "textes", "visibles", "mentionRepliee", "garantieEnTete"]), `${quoi}, après la vérification`).to.deep.equal({ enTete: false, sousLeResultat: true, justeAvantLesSpecialistes: true, apresLeVerdict: true, textes: arrivee.textes, visibles: [true, true, true], mentionRepliee: false, garantieEnTete: true });
            // Sans défiler du tout : la page remise en haut montre la garantie, le mot du verdict et le début de sa phrase.
            await o.page.evaluate(() => scrollTo(0, 0));
            const enHaut = await lire(o.page);
            expect(enHaut.defilement, quoi).to.equal(0);
            aLEcran(enHaut, `${quoi}, page en haut`);
            expect(enHaut.garantie.haut >= 0 && enHaut.garantie.bas <= enHaut.mot.haut, `${quoi} : garantie au-dessus du verdict`).to.equal(true);
            // Le changement de langue garde cette place ; « Vérifier un autre dossier » aussi (le résultat reste affiché).
            await o.page.click("#autre-langue");
            expect(garder(await lire(o.page), ["sousLeResultat", "justeAvantLesSpecialistes", "visibles"]), `${quoi}, en anglais`).to.deep.equal({ sousLeResultat: true, justeAvantLesSpecialistes: true, visibles: [true, true, true] });
            await o.page.click("#autre-langue");
            await o.page.click("#verifier-autre");
            expect(garder(await lire(o.page), ["sousLeResultat", "visibles"]), `${quoi}, étapes ramenées`).to.deep.equal({ sousLeResultat: true, visibles: [true, true, true] });
            // Un refus : la mise en garde reste sous le résultat, affichée.
            const refuse = path.join(dir, `piece-${fenetre.width}.rar`);
            fs.writeFileSync(refuse, "x");
            await o.page.setInputFiles("#entree-archive", refuse);
            await lancerVerification(o.page);
            expect(garder(await lire(o.page), ["sousLeResultat", "apresLeVerdict", "textes", "visibles", "mentionRepliee"]), `${quoi}, après un refus`).to.deep.equal({ sousLeResultat: true, apresLeVerdict: true, textes: arrivee.textes, visibles: [true, true, true], mentionRepliee: false });
          } finally {
            await o.fermer();
          }
        }
      }
    });

    it("seconde lecture (complément du 2026-11-18, points 14 à 19) : « Valide » ne garde le vert plein que pour huit contrôles réussis sans avertissement, sinon teinte d'avertissement, mention dans le titre et phrase de ce qui n'est pas prouvé ; rapport illisible : mot seul, teinte neutre ; contrôle réussi avec réserve ; réserve en double dite une fois ; « En résumé » égal aux champs du rapport ; ce qui a échoué ; pièce en cause ; en français et en anglais", async function () {
      if (!pret(this)) return;
      const T = tables();
      const BOUCLIER = "M12 3.5l7 2.5v5.5c0 4.3-2.9 7.6-7 9-4.1-1.4-7-4.7-7-9V6z";
      for (const langue of ["fr", "en"]) {
        const L = T[langue];
        for (const [nom, cas] of Object.entries(CAS_SECONDE)) {
          const quoi = `${nom}, ${langue}`;
          const o = await verifierCas(cas, { langue });
          try {
            const ecran = await lireEcran(o.page);
            const a = attendu(cas, L);
            expect(garder(ecran, CLES_VERDICT), quoi).to.deep.equal(garder(a, CLES_VERDICT));
            const lu = await lireSeconde(o.page);
            // Le titre est le mot du code, suivi de la seule mention que le rapport appelle ; le bouclier ne reste qu'au vert plein.
            expect(lu.titre, quoi).to.equal(`${a.mot}${a.mention ?? ""}`);
            expect(lu.signe === BOUCLIER, quoi).to.equal(a.variante === "nt-verdict-valide");
            if (a.nonProuve !== null) expect(await o.page.isVisible("#non-prouve"), quoi).to.equal(true);
            // Contrôles avec réserve : ceux que le rapport désigne, et eux seuls ; chacun renvoie aux réserves.
            const reserves = a.controles.filter((c) => c.reserves !== null);
            expect(lu.pastillesReserve, quoi).to.deep.equal(reserves.map((c) => c.numero));
            expect(lu.renvois, quoi).to.deep.equal(reserves.map((c) => [c.numero, libelle(L, "controle_reserve", { ids: c.reserves.split(" ").join(", "), renvoi: L.renvoi_reserves }), "#avertissements"]));
            const reussis = cas.json.controls.filter((c) => c.status === R).length;
            expect(lu.compte.startsWith(reserves.length === 0 ? libelle(L, "compte_reussis", { n: reussis }) : libelle(L, "compte_reussis_reserve", { n: reussis, m: reserves.length })), quoi).to.equal(true);
            // Réserves : une ligne par identifiant de la table, « signalée N fois », tous les textes exacts.
            expect(garder(await lireLangage(o.page), ["listeReserves"]), quoi).to.deep.equal(garder(attenduLangage(cas, L), ["listeReserves"]));
            // « En résumé » : les lignes que le rapport permet, valeurs égales à ses champs ; avant le texte exact ; aucune empreinte.
            const resume = enResumeAttendu(cas.json, cas.code, L);
            expect(lu.enResume, quoi).to.deep.equal(resume);
            // « Outil appelé » : le nom de l'outil tel que le rapport le donne, marqué comme une valeur, en chasse fixe.
            if (resume.some((l) => l[0] === "outil")) {
              const outil = await o.page.evaluate(() => {
                const v = document.querySelector('#en-resume li[data-ligne="outil"] .pv-valeur');
                return [v.textContent, v.hasAttribute("data-valeur"), getComputedStyle(v).fontFamily !== getComputedStyle(v.parentElement).fontFamily, document.querySelectorAll('#en-resume li[data-ligne="outil"] .pv-valeur').length];
              });
              expect(outil, quoi).to.deep.equal([cas.json.event.tool, true, true, 1]);
            }
            if (resume.length > 0) {
              expect([lu.resumeFin, lu.resumeAvantEnonce], quoi).to.deep.equal([L.resume_fin, true]);
              expect(lu.resumeTexte, quoi).to.not.match(/0x[0-9a-f]{8}/);
              expect(await o.page.isVisible("#en-resume"), quoi).to.equal(true);
            } else expect([lu.resumeFin, lu.resumeTexte], quoi).to.deep.equal([null, null]);
            // Ce qui a échoué (code 1) : sur la ligne du contrôle, ce que le vérificateur dit, l'identifiant à la fin ;
            // sous le verdict, la vérification en échec qu'aucun contrôle ne porte.
            if (nom === "nonValide") {
              expect(lu.echecsControles, quoi).to.deep.equal([[1, libelle(L, "dit_echec", { detail: DETAIL_E7, id: "E-7" })]]);
              expect(lu.echecsVerdict, quoi).to.deep.equal([libelle(L, "dit_echec", { detail: DETAIL_D2, id: "D-2" })]);
              expect(lu.echecsControles[0][1].endsWith("(E-7)"), quoi).to.equal(true);
            } else expect([lu.echecsControles, lu.echecsVerdict], quoi).to.deep.equal([[], []]);
            expect(o.messages.filter((m) => m.startsWith("erreur de page")), quoi).to.deep.equal([]);
          } finally {
            await o.fermer();
          }
        }
        // Ce que le cas « avec réserves » doit montrer, écrit en clair : deux contrôles avec réserve, une réserve dite deux fois.
        const o = await verifierCas(CAS_SECONDE.reserves, { langue });
        try {
          const ecran = await lireEcran(o.page);
          const langage = await lireLangage(o.page);
          expect([ecran.mention, ecran.teinte, ecran.variante, ecran.tousReussis], langue).to.deep.equal([L.mention_reserves, "pv-verdict-reserve", "", libelle(L, "tous_reussis_reserve", { n: 2 })]);
          expect(ecran.controles.map((c) => c.etat), langue).to.deep.equal([L.statut_reussi, L.statut_reussi, L.statut_reussi, L.statut_reussi, L.statut_reussi_reserve, L.statut_reussi, L.statut_reussi, L.statut_reussi_reserve]);
          expect(langage.listeReserves.map((x) => [x.id, x.exactes.length]), langue).to.deep.equal([["AV-K-1", 1], ["AV-O-3", 2], ["AV-Z-9", 1]]);
          expect(langage.listeReserves[1].courante, langue).to.equal(`${L.av_o_3} ${libelle(L, "reserve_fois", { n: 2 })}`);
        } finally {
          await o.fermer();
        }
        // Rapport qui ne se lit pas exactement, sous le code 0 : le mot seul, teinte neutre, jamais le vert plein ni une mention.
        const illisibles = {
          "contrôles illisibles": (r) => r.controls.pop(),
          "avertissements illisibles": (r) => (r.warnings = [{ id: "AV-O-3" }]),
          "contrôle en échec sous le code 0": (r) => (r.controls[0].status = E),
        };
        for (const [titre, modifier] of Object.entries(illisibles)) {
          const json = JSON.parse(JSON.stringify(CAS_SECONDE.plein.json));
          modifier(json);
          const i = await verifierCas({ code: 0, json }, { langue });
          try {
            const ecran = await lireEcran(i.page);
            const lu = await lireSeconde(i.page);
            expect([ecran.mot, ecran.variante, ecran.teinte, ecran.mention, ecran.nonProuve, lu.titre], `${titre}, ${langue}`).to.deep.equal([L.mot_0, "", "pv-verdict-neutre", null, null, L.mot_0]);
            expect(lu.signe === BOUCLIER, `${titre}, ${langue}`).to.equal(false);
            if (titre !== "avertissements illisibles") expect([ecran.indisponible, lu.enResume], `${titre}, ${langue}`).to.deep.equal([L.resume_indisponible, []]);
            else expect(ecran.avertissements, `${titre}, ${langue}`).to.include(L.avertissements_illisibles);
          } finally {
            await i.fermer();
          }
        }
        // Aucun verdict : la pièce en cause, en clair, d'après le type de l'erreur ; un type inconnu n'en reçoit pas.
        const pieces = [["dossier_illisible", null, "piece_dossier"], ["ancres_inutilisables", "N-1", "piece_ancres"], ["entree_illisible", "N-2", "piece_entetes"], ["entree_illisible", null, "piece_entree"], ["taille_depassee", null, "piece_taille"], ["usage", null, "piece_usage"], ["erreur_interne", null, "piece_verificateur"], ["type_futur", null, null]];
        for (const [kind, check, cle] of langue === "fr" ? pieces : pieces.slice(0, 3)) {
          const json = { ...CAS.aucun.json, error: { kind, message: CAS.aucun.json.error.message, check } };
          const e = await verifierCas({ ...CAS.aucun, json }, { langue });
          try {
            const lu = await lireSeconde(e.page);
            const ecran = await lireEcran(e.page);
            expect([lu.piece, lu.pieceAvantMessage], `${kind}, ${langue}`).to.deep.equal(cle === null ? [null, null] : [L[cle], true]);
            expect([ecran.mot, ecran.message, ecran.affirmation], `${kind}, ${langue}`).to.deep.equal([L.mot_2, json.error.message, L.aucune_affirmation]);
          } finally {
            await e.fermer();
          }
        }
      }
    });

    it("seconde lecture : après un refus, un titre courant précède la mention fixée « aucun rapport » ; le choix du dossier dit le refus, sans coche ni « tout est prêt » ; un autre choix l'efface", async function () {
      if (!pret(this)) return;
      const T = tables().fr;
      const o = await ouvrir(navigateur, pageConstruite, { remplacements: { "travailleur.js": travailleurFactice(CAS_SECONDE.plein) } });
      const lire = () => o.page.evaluate(() => {
        const t = (s) => (document.querySelector(s) === null ? null : document.querySelector(s).textContent);
        const choisi = document.getElementById("dossier-choisi");
        const mention = document.querySelector(".aucun-rapport");
        return { choisi: choisi.textContent, classes: choisi.className, aide: t("#aide-verifier"), titre: t("#refus-titre"), mention: mention === null ? null : mention.textContent, intro: mention === null ? null : mention.parentElement.querySelector(".pv-exact-intro").textContent, marquee: mention === null ? null : mention.hasAttribute("data-exact"), mot: t("#verdict-mot") };
      });
      try {
        await o.page.goto("https://verification.example/index.html");
        await attendreArtefact(o.page);
        const refuse = path.join(dir, "contrat-refuse.rar");
        fs.writeFileSync(refuse, "x");
        await o.page.setInputFiles("#entree-archive", refuse);
        // Avant la vérification : le fichier est choisi, rien n'est encore refusé.
        expect(garder(await lire(), ["choisi", "classes", "aide", "titre"])).to.deep.equal({ choisi: libelle(T, "dossier_choisi_archive", { nom: "contrat-refuse.rar" }), classes: "pv-choisi pv-choisi-fait", aide: T.aide_verifier_pret, titre: null });
        await lancerVerification(o.page);
        expect(await lire()).to.deep.equal({ choisi: libelle(T, "dossier_refuse_archive", { nom: "contrat-refuse.rar" }), classes: "pv-choisi pv-choisi-refuse", aide: T.aide_verifier_refus, titre: T.titre_refus, mention: T.aucun_rapport, intro: T.mention_refus, marquee: true, mot: null });
        expect(await o.page.evaluate(() => document.querySelector("#dossier-choisi svg path").getAttribute("d"))).to.not.equal("M5 12.5l4.5 4.5L19 7.5");
        // Un autre choix efface le refus de l'étape 1 ; un rapport suit, sans trace du refus.
        await choisirRepertoire(o.page, DOSSIER);
        expect(garder(await lire(), ["choisi", "classes", "aide"])).to.deep.equal({ choisi: libelle(T, "dossier_choisi_repertoire", { nom: path.basename(DOSSIER) }), classes: "pv-choisi pv-choisi-fait", aide: T.aide_verifier_pret });
        await lancerVerification(o.page);
        expect(garder(await lire(), ["titre", "mention", "mot"])).to.deep.equal({ titre: null, mention: null, mot: T.mot_0 });
        expect(await o.page.textContent("#nom-verifie")).to.equal(libelle(T, "dossier_verifie_repertoire", { nom: path.basename(DOSSIER) }));
      } finally {
        await o.fermer();
      }
    });

    it("seconde lecture, mutants : vert plein gardé avec un contrôle non fait, mention affichée sans contrôle non fait ni avertissement, rapport illisible en vert plein, contrôle resté « Réussi » sous une réserve, réserve rattachée sans que le rapport le dise, réserve en double redite, texte exact d'un doublon retiré, ligne du résumé pour un contrôle non réussi, résumé sous « Non valide », coche gardée après un refus ; l'essai les voit (tués)", async function () {
      if (!pret(this)) return;
      const T = tables().fr;
      const egal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
      const verdict = async (o, cas) => egal(garder(await lireEcran(o.page), CLES_VERDICT), garder(attendu(cas, T), CLES_VERDICT));
      const reserves = async (o, cas) => egal(garder(await lireLangage(o.page), ["listeReserves"]), garder(attenduLangage(cas, T), ["listeReserves"]));
      const resume = async (o, cas) => egal((await lireSeconde(o.page)).enResume, enResumeAttendu(cas.json, cas.code, T));
      // Rapport contradictoire : le contrôle 4 non fait, mais un instant limite encore au rapport ; la ligne ne doit pas paraître.
      const contradictoire = { code: 0, json: JSON.parse(JSON.stringify(CAS_SECONDE.nonFaits.json)) };
      contradictoire.json.facts.timestamp = { authority: "AC de test CT-6", gen_time: "2026-11-01T00:00:05Z", upper_bound: "2026-11-01T00:00:06Z" };
      const sansTimestamp = (cas) => ({ code: cas.code, json: { ...cas.json, facts: { ...cas.json.facts, timestamp: null } } });
      const illisible = { code: 0, json: { ...CAS_SECONDE.plein.json, controls: CAS_SECONDE.plein.json.controls.slice(0, 7) } };
      const neutre = async (o) => {
        const e = await lireEcran(o.page);
        return egal([e.variante, e.teinte, e.mention], ["", "pv-verdict-neutre", null]);
      };
      const mutants = [
        { titre: "vert plein gardé avec un contrôle non fait", avant: '  if (nonProuve) return { teinte: "reserve", mention: "mention_non_prouve" };\n', apres: "", cas: CAS_SECONDE.nonFaits, conforme: verdict },
        { titre: "mention affichée sans contrôle non fait ni avertissement", avant: '  if (reserves) return { teinte: "reserve", mention: "mention_reserves" };\n  return { teinte: "pleine", mention: null };', apres: '  return { teinte: "reserve", mention: "mention_reserves" };', cas: CAS_SECONDE.plein, conforme: verdict },
        { titre: "rapport illisible montré en vert plein", avant: '  if (controles === null || avertissements === null) return { teinte: "neutre", mention: null };', apres: '  if (controles === null || avertissements === null) return { teinte: "pleine", mention: null };', cas: illisible, conforme: neutre },
        { titre: "contrôle resté « Réussi » sous une réserve que le rapport lui rattache", avant: "    const [ton, nomIcone, cle] = ids.length > 0 ? PASTILLE_RESERVE : PASTILLES_STATUT[c.statut];", apres: "    const [ton, nomIcone, cle] = PASTILLES_STATUT[c.statut];", cas: CAS_SECONDE.reserves, conforme: verdict },
        { titre: "réserve rattachée à des contrôles que le rapport ne nomme pas", avant: "  return controles.filter((c) => c.verifications.includes(avertissement.verification)).map((c) => c.numero);", apres: "  return controles.map((c) => c.numero);", cas: CAS_SECONDE.reserves, conforme: verdict },
        { titre: "réserve en double redite à chaque fois", avant: "    if (g) g.elements.push(a);\n    else groupes.push(", apres: "    groupes.push(", cas: CAS_SECONDE.reserves, conforme: reserves },
        { titre: "texte exact d'une réserve en double retiré", avant: "      for (const a of g.elements) {", apres: "      for (const a of g.elements.slice(0, 1)) {", cas: CAS_SECONDE.reserves, conforme: reserves },
        { titre: "ligne du résumé affichée pour un contrôle que le rapport ne dit pas réussi", avant: 'c.numero === CONTROLE_DU_RESUME[nom] && c.statut === "reussi");', apres: "c.numero === CONTROLE_DU_RESUME[nom]);", cas: contradictoire, conforme: async (o, cas) => resume(o, sansTimestamp(cas)) },
        { titre: "résumé affiché sous « Non valide »", avant: "  if ((code !== 0 && code !== 3) || controles === null ||", apres: "  if (controles === null ||", cas: { code: 1, json: { ...CAS_SECONDE.nonValide.json, controls: CAS_SECONDE.nonValide.json.controls.map((c) => (c.number === 1 ? c : { ...c, status: R, reason: null })) } }, conforme: resume },
      ];
      // Témoin : sur les sources telles qu'elles sont, chaque oracle est satisfait.
      for (const m of mutants) {
        const o = await verifierCas(m.cas);
        try {
          expect(await m.conforme(o, m.cas), `témoin : ${m.titre}`).to.equal(true);
        } finally {
          await o.fermer();
        }
      }
      let n = 0;
      const muter = (m) => {
        const copie = path.join(dir, `mutant-seconde-${n++}`);
        fs.cpSync(SOURCES, path.join(copie, "src"), { recursive: true });
        const fichier = path.join(copie, "src", "page", "interface.js");
        const source = fs.readFileSync(fichier, "utf8");
        expect(source.split(m.avant), m.titre).to.have.length(2);
        fs.writeFileSync(fichier, source.replace(m.avant, m.apres));
        return { copie, page: construirePageFactice(path.join(copie, "construite"), path.join(copie, "src")) };
      };
      for (const m of mutants) {
        const { copie, page } = muter(m);
        const o = await verifierCas(m.cas, { page });
        try {
          expect(await m.conforme(o, m.cas), `mutant vu : ${m.titre}`).to.equal(false);
        } finally {
          await o.fermer();
          fs.rmSync(copie, { recursive: true, force: true });
        }
      }
      // Coche gardée à l'étape 1 après un refus : le fichier refusé y reste dit « choisi ».
      const m = { titre: "coche et « tout est prêt » gardés après un refus", avant: '    etat.refuse = etat.vue.genre === "refus";', apres: "    etat.refuse = false;" };
      const refuse = path.join(dir, "mutant-refuse.rar");
      fs.writeFileSync(refuse, "x");
      const apresRefus = async (page) => {
        const o = await ouvrir(navigateur, page, { remplacements: { "travailleur.js": travailleurFactice(CAS_SECONDE.plein) } });
        try {
          await o.page.goto("https://verification.example/index.html");
          await attendreArtefact(o.page);
          await o.page.setInputFiles("#entree-archive", refuse);
          await lancerVerification(o.page);
          return await o.page.evaluate(() => [document.getElementById("dossier-choisi").textContent, document.getElementById("dossier-choisi").className, document.getElementById("aide-verifier").textContent]);
        } finally {
          await o.fermer();
        }
      };
      const attenduRefus = [libelle(T, "dossier_refuse_archive", { nom: "mutant-refuse.rar" }), "pv-choisi pv-choisi-refuse", T.aide_verifier_refus];
      expect(await apresRefus(pageConstruite), `témoin : ${m.titre}`).to.deep.equal(attenduRefus);
      const { copie, page } = muter(m);
      try {
        expect(await apresRefus(page), `mutant vu : ${m.titre}`).to.not.deep.equal(attenduRefus);
      } finally {
        fs.rmSync(copie, { recursive: true, force: true });
      }
    });

    it("aucun terme de technicien au premier niveau de lecture, en français et en anglais : page vide, dossier chargé et options ouvertes, chaque verdict (valide, valide avec avertissement, valide aux contrôles non faits, non valide, incomplet, illisible), vérification non faite, refus d'un fichier ; seuls les textes exacts de la liste fermée portent la marque", async function () {
      if (!pret(this)) return;
      const constater = async (page, quoi) => {
        const lu = await premierNiveau(page);
        expect(lu.textes.length, quoi).to.be.greaterThan(10);
        expect(termesTrouves(lu.textes), quoi).to.deep.equal([]);
        expect(lu.horsListe, quoi).to.deep.equal([]);
      };
      for (const langue of ["fr", "en"]) {
        const o = await ouvrir(navigateur, pageConstruite, { remplacements: { "travailleur.js": travailleurFactice(CAS_LANGAGE.valide) } });
        try {
          await o.page.goto("https://verification.example/index.html");
          await attendreArtefact(o.page);
          if (langue === "en") await o.page.click("#autre-langue");
          await constater(o.page, `page vide, ${langue}`);
          // « Comment ça marche » ouvert : ses cinq lignes sont lues elles aussi.
          await o.page.click("#comment > summary");
          await constater(o.page, `comment ça marche, ${langue}`);
          await choisirRepertoire(o.page, DOSSIER);
          await deplierOptions(o.page);
          await o.page.setInputFiles("#entree-ancres", ANCRES);
          await o.page.setInputFiles("#entree-entetes", CHAINE);
          for (const k of [4, 5, 8]) await o.page.setChecked(`input[name="exiger"][value="${k}"]`, true);
          await constater(o.page, `dossier chargé, options ouvertes, ${langue}`);
          // Refus d'un fichier qui n'est pas un dossier de preuve.
          const refuse = path.join(dir, `releve-${langue}.rar`);
          fs.writeFileSync(refuse, "x");
          await o.page.setInputFiles("#entree-archive", refuse);
          await lancerVerification(o.page);
          await constater(o.page, `refus, ${langue}`);
        } finally {
          await o.fermer();
        }
        for (const [nom, cas] of [...Object.entries(CAS_LANGAGE), ...Object.entries(CAS_SECONDE).map(([k, v]) => [`seconde lecture, ${k}`, v]), ["vérification non faite", CAS_CODE_INCONNU]]) {
          const v = await verifierCas(cas, { langue });
          try {
            await constater(v.page, `${nom}, ${langue}`);
          } finally {
            await v.fermer();
          }
        }
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
      { titre: "valide, huit contrôles réussis", dossier: "ct-6/dossiers/valide-seq-7-complet", ancres: true, entetes: true, code: 0, nonReussis: [], resume: ["action", "outil", "periode", "approbation", "limite_autorite", "limite_bitcoin"] },
      { titre: "valide borné, sans fichier d'ancres", dossier: "ct-6/dossiers/valide-seq-7-complet", code: 0, nonReussis: [4, 5, 8], resume: ["action", "outil", "periode", "approbation"] },
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
        // Après un résultat, les étapes sont réduites à une ligne (complément du 2026-11-18) : la personne les ramène.
        await rouvrirEtapes(o.page);
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
        if (e.nonReussis) expect(ecran.controles.filter((c) => !c.montreReussi && c.reserves === null).map((c) => c.numero), e.titre).to.deep.equal(e.nonReussis);
        if (e.code === 0) expect([ecran.tousReussis !== null, ecran.borne !== null], e.titre).to.deep.equal([e.nonReussis.length === 0, e.nonReussis.length > 0]);
        // Le résumé que le vérificateur donne de chaque contrôle est repris tel quel, dans le bloc replié de la liste
        // (complément du 2026-11-18 de CT-6 §18, point 8) ; sous un contrôle échoué, il est aussi sur sa ligne.
        if (e.code !== 2) {
          for (const c of json.controls) {
            expect(await o.page.textContent(`#controles #detail-controles [data-numero="${c.number}"]`), `${e.titre}, contrôle ${c.number}`).to.equal(c.summary);
            if (c.status === "echoue") {
              // Sur la ligne d'un contrôle échoué : ce que le vérificateur dit de chaque vérification en échec qu'il
              // porte, tel quel, l'identifiant à la fin entre parenthèses (point 18) ; à défaut, son résumé.
              const dits = json.checks.filter((v) => v.status === "echoue" && c.checks.includes(v.id) && json.failed_checks.includes(v.id));
              const ligne = await o.page.textContent(`#controles li[data-numero="${c.number}"]`);
              expect(dits.length, `${e.titre}, contrôle ${c.number}`).to.be.greaterThan(0);
              for (const v of dits) expect(ligne, `${e.titre}, contrôle ${c.number}`).to.include(libelle(T, "dit_echec", { detail: v.detail, id: v.id }));
            }
          }
        }
        // Les avertissements du rapport sont tous sous le verdict.
        for (const w of json.warnings ?? []) expect(ecran.avertissements, e.titre).to.include(w.detail);
        // « En résumé » (point 17) : les lignes sont les champs du rapport que le vérificateur vient de rendre.
        const lu = await lireSeconde(o.page);
        expect(lu.enResume, e.titre).to.deep.equal(e.code === 2 ? [] : enResumeAttendu(json, e.code, T));
        if (e.resume) expect(lu.enResume.map((l) => l[0]), e.titre).to.deep.equal(e.resume);
        // Les valeurs affichées sont celles du rapport : numéro d'ordre, nombres de l'approbation, instants en toutes lettres.
        if (e.code === 0 && e.nonReussis.length === 0) {
          expect(lu.valeursDuResume, e.titre).to.deep.equal([String(json.event.seq), json.event.tool, instantAttendu(json.period.period_start * 1000, T), instantAttendu(json.period.period_end * 1000, T), String(json.facts.approval.approvers.length), String(json.facts.approval.required), String(json.facts.approval.size), instantAttendu(Date.parse(json.facts.timestamp.upper_bound), T)]);
          expect(lu.valeursDuResume[1], e.titre).to.equal("sap.payments.create");
          expect(lu.valeursDuResume[2], e.titre).to.equal("5 novembre 2026 à 09 h 00 min 00 s");
          expect(lu.valeursDuResume[7], e.titre).to.equal("5 novembre 2026 à 10 h 00 min 06 s");
        }
        if (e.code === 2) expect(lu.piece, e.titre).to.equal(T.piece_dossier);
      }
      expect((await o.violations())).to.deep.equal([]);
    } finally {
      await o.fermer();
    }
  });
});
