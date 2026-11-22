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
      sansValeur: t("#verdict-sans-valeur"),
      exigesSansValeur: t("#exiges-sans-valeur"),
      specialistes: t("#specialistes"),
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
function nonProuveAttendu(nonReussis, T, dossier = []) {
  const date = nonReussis.includes(4) && nonReussis.includes(5);
  // Cinquième lecture : un contrôle réussi avec ce que le dossier déclare lui-même a son élément, à sa place.
  const tous = [...new Set([...nonReussis, ...dossier])].sort((x, y) => x - y);
  const noms = tous.filter((n) => !(date && n === 5)).map((n) => (!nonReussis.includes(n) ? T[`non_prouve_${n}_dossier`] : date && n === 4 ? T.non_prouve_4_5 : T[`non_prouve_${n}`]));
  if (noms.length === 0) return null;
  if (noms.length === 1) return libelle(T, "non_prouve_un", { liste: noms[0] });
  return libelle(T, "non_prouve_plusieurs", { liste: `${noms.slice(0, -1).join(T.non_prouve_sep)}${T.non_prouve_dernier}${noms[noms.length - 1]}` });
}

/**
 * Clé de la phrase d'un contrôle non fait, écrite ici une seconde fois d'après la table de CT-6 §18 (point 8) : la
 * raison du rapport, le numéro du contrôle, et les pièces que la personne a ajoutées à l'étape 2.
 */
function cleRaisonAttendue(raison, numero, { ancres = false, entetes = false } = {}, horsPerimetre = null) {
  if (raison === "ancre_absente") return !ancres ? "raison_ancre_absente" : numero === 5 && entetes ? "raison_ancre_absente_liste_extrait" : "raison_ancre_absente_liste";
  if (raison === "partie_absente" && numero === 5 && !entetes) return ancres ? "raison_partie_absente_extrait" : "raison_partie_absente_liste_extrait";
  // Cinquième lecture (point 8) : une partie requise déclarée absente « hors périmètre CT-1 », ou une pièce présente.
  if (raison === "hors_perimetre_version" && horsPerimetre !== null) return PARTIES_REQUISES_ATTENDUES[numero].some((f) => horsPerimetre.includes(f)) ? "raison_hors_perimetre_absente" : "raison_hors_perimetre_forme";
  return ["partie_absente", "hors_perimetre_version", "piece_hors_dossier", "prerequis_en_echec"].includes(raison) ? `raison_${raison}` : "raison_inconnue";
}

/**
 * Cinquième lecture (CT-6 §18, point 8), écrit ici une seconde fois : les parties requises de chaque contrôle (table
 * 5.1, par leur fichier), et les fichiers que le rapport dit déclarés absents « hors périmètre CT-1 » (`absent_parts`),
 * ou null sans ce membre.
 */
const PARTIES_REQUISES_ATTENDUES = { 1: ["evenement.json"], 2: ["voisins.json"], 3: ["chemin.json", "manifeste.json", "manifeste.sig"], 4: ["jeton-rfc3161.der"], 5: ["preuve.ots"], 6: ["cles.json", "evenement.json", "voisins.json", "manifeste.sig"], 7: ["approbations.json"], 8: ["registre.json", "certificat-commit.json"] };
const horsPerimetreAttendu = (json) => (Array.isArray(json.absent_parts) ? json.absent_parts.filter((p) => p.reason === "hors périmètre CT-1").map((p) => p.file) : null);

/**
 * Quatrième lecture (CT-6 §18, point 15), écrit ici une seconde fois : les raisons courtes (clés) qui rendent un
 * contrôle réussi sans valeur de preuve, celles des avertissements AV-O-3 que le rapport lui rattache.
 */
// Complément du 2026-11-19 (CT-6 6.10) : les avertissements de pièce d'essai AV-T-5, AV-R-4, AV-N-1 et AV-N-2 s'y ajoutent.
const SANS_VALEUR_ATTENDU = { "AV-O-3": "sans_valeur_av_o_3", "AV-T-5": "sans_valeur_av_t_5", "AV-R-4": "sans_valeur_av_r_4", "AV-N-1": "sans_valeur_av_n_1", "AV-N-2": "sans_valeur_av_n_2" };
// CT-6 EX-6.25, écrit ici une seconde fois : pour chaque contrôle, les couples (avertissement, vérification) qui le
// rendent sans valeur de preuve. Levés par K-3, K-7 ou K-9, ou rattachés à un autre contrôle, ils n'y sont qu'une réserve.
const SANS_VALEUR_PAR_CONTROLE_ATTENDU = { 4: [["AV-T-5", "T-7"]], 5: [["AV-O-3", "O-5"]], 6: [["AV-N-1", "E-8"], ["AV-N-1", "P-5"]], 7: [["AV-N-2", "E-9"]], 8: [["AV-R-4", "R-4"], ["AV-N-1", "N-4"]] };
// Adresses d'approbateur d'essai, lues dans le texte de CT-6 6.10 (EX-6.23) et non dans les sources de la page.
function approbateursEssaiDuTexte() {
  const ct6 = fs.readFileSync(path.join(RACINE, "spec", "CT-6-verificateur.md"), "utf8");
  const i = ct6.indexOf("Approbateurs (comptes 0 à 19) :");
  const j = ct6.indexOf("Sortes pour lesquelles les données ne portent aucun signe sûr", i);
  expect(i, "liste des approbateurs d'essai dans CT-6 6.10").to.be.greaterThan(0);
  return [...ct6.slice(i, j).matchAll(/0x[0-9a-f]{40}\b/g)].map((m) => m[0]);
}
function sansValeurAttendu(json, numero) {
  const c = json.controls[numero - 1];
  if (c === undefined || c.status !== "reussi") return [];
  const couples = SANS_VALEUR_PAR_CONTROLE_ATTENDU[numero] ?? [];
  if (numero === 7) {
    // Règle de nombre : adresses hors de la liste d'EX-6.23 moins nombreuses que le requis ; sans ces faits, jamais.
    // `facts` ne s'emploie que sous les verdicts valide et incomplet (EX-6.13).
    if (json.verdict !== "valide" && json.verdict !== "incomplet") return [];
    const a = json.facts && json.facts.approval;
    if (!a || !Array.isArray(a.approvers) || !Number.isSafeInteger(a.required)) return [];
    const essai = approbateursEssaiDuTexte();
    if (new Set(a.approvers.map((x) => x.toLowerCase()).filter((x) => !essai.includes(x))).size >= a.required) return [];
  }
  const ids = (json.warnings ?? []).filter((w) => typeof w.check === "string" && (c.checks ?? []).includes(w.check) && couples.some(([id, v]) => w.id === id && w.check === v)).map((w) => w.id);
  return [...new Set(ids.map((id) => SANS_VALEUR_ATTENDU[id]))];
}

/**
 * Clé de la phrase « clés du dossier » d'un contrôle réussi, écrite ici une seconde fois (point 15) : sous les codes 0
 * et 3, contrôle 6 d'après la provenance des clés (`facts.recorder_keys`, et `facts.checkpoint.key_source`) et la liste
 * ajoutée à l'étape 2 ; contrôle 7 si le jeu d'approbateurs est celui du dossier.
 */
function cleDossierAttendue(cas, numero, { ancres = false } = {}) {
  const f = cas.json.facts;
  if ((cas.code !== 0 && cas.code !== 3) || !f || cas.json.controls[numero - 1].status !== "reussi") return null;
  if (numero === 7) return f.approval && f.approval.set_source === "dossier" ? "controle_approbateurs_dossier" : null;
  if (numero !== 6 || !f.recorder_keys) return null;
  const s = [f.recorder_keys.event_key_source, f.recorder_keys.manifest_key_source];
  if (f.checkpoint && ["dossier", "ancres", "registre"].includes(f.checkpoint.key_source)) s.push(f.checkpoint.key_source);
  const n = s.filter((x) => x === "dossier").length;
  return n === 0 ? null : `controle_cles_dossier_${n === s.length ? "toutes" : "partie"}${ancres ? "_liste" : ""}`;
}

function attendu(cas, T, pieces = {}) {
  const mots = { 0: ["mot_0", "nt-verdict-valide"], 1: ["mot_1", "nt-verdict-non-valide"], 2: ["mot_2", ""], 3: ["mot_3", "nt-verdict-incomplet"] };
  const r = { mot: T[mots[cas.code][0]], variante: mots[cas.code][1], teinte: "", mention: null, nonProuve: null, code: libelle(T, "code", { code: cas.code, sens: T[`code_${cas.code}`] }) };
  if (cas.code === 2) return { ...r, controles: [], pastillesReussi: 0, tousReussis: null, borne: null, exiges: null, sansValeur: null, exigesSansValeur: null };
  const exiges = cas.json.inputs.required_controls;
  const horsPerimetre = horsPerimetreAttendu(cas.json);
  r.controles = cas.json.controls.map((c) => {
    const reserves = reservesAttendues(cas.json, c);
    // Quatrième lecture (point 15) : sans valeur de preuve, puis avec ce que le dossier fournit (cinquième lecture :
    // avant la réserve), puis avec réserve.
    const sansValeur = sansValeurAttendu(cas.json, c.number);
    const dossier = cleDossierAttendue(cas, c.number, pieces);
    const etat = sansValeur.length > 0 ? libelle(T, "statut_sans_valeur", { raisons: sansValeur.map((k) => T[k]).join(", ") }) : dossier !== null ? T[{ 6: "statut_reussi_cles_dossier", 7: "statut_reussi_approbateurs_dossier" }[c.number]] : reserves.length > 0 ? T.statut_reussi_reserve : T[`statut_${c.status}`];
    return {
      numero: c.number,
      statut: c.status,
      etat,
      montreReussi: c.status === "reussi" && reserves.length === 0 && dossier === null,
      titre: `${c.number}. ${T[`controle_${c.number}`]}`,
      // Cinquième lecture (point 8) : la phrase seule ; le code de la raison est en tête des spécialistes.
      raison: c.status === "non_execute" ? libelle(T, "raison", { raison: T[cleRaisonAttendue(c.reason, c.number, pieces, horsPerimetre)] }) : null,
      exige: exiges.includes(c.number) ? T.controle_exige : null,
      reserves: reserves.length > 0 ? reserves.join(" ") : null,
    };
  });
  const nonReussis = cas.json.controls.filter((c) => c.status !== "reussi").map((c) => c.number);
  const sansValeur = cas.json.controls.filter((c) => sansValeurAttendu(cas.json, c.number).length > 0).map((c) => c.number);
  const raisons = [...new Set(sansValeur.flatMap((n) => sansValeurAttendu(cas.json, n)))].map((k) => T[k]).join(", ");
  const nonProuves = cas.json.controls.filter((c) => nonReussis.includes(c.number) || sansValeur.includes(c.number)).map((c) => c.number);
  // Cinquième lecture (point 15) : réussis avec ce que le dossier déclare lui-même ; ni réussis, ni prouvés, ni « avec réserve ».
  const dossiers = r.controles.filter((c) => c.statut === "reussi" && !sansValeur.includes(c.numero) && cleDossierAttendue(cas, c.numero, pieces) !== null).map((c) => c.numero);
  const avecReserve = r.controles.filter((c) => c.reserves !== null && !sansValeur.includes(c.numero) && !dossiers.includes(c.numero)).length;
  // Contrôles exigés sans valeur de preuve : depuis le complément du 2026-11-19 (CT-6 EX-6.25), ils rendent le code 3.
  const exigesSv = sansValeur.filter((n) => exiges.includes(n));
  // Sous le code 0, le vert plein ne reste que pour huit contrôles réussis sans avertissement ; sinon la teinte
  // d'avertissement et la mention fixe, et la phrase de ce qui n'est pas prouvé (point 14).
  const avertis = (cas.json.warnings ?? []).length > 0;
  if (cas.code === 0 && (nonReussis.length > 0 || avertis || dossiers.length > 0)) {
    const nonProuve = nonProuves.length > 0 || dossiers.length > 0;
    r.variante = "";
    r.teinte = "pv-verdict-reserve";
    r.mention = nonProuve && avertis ? T.mention_les_deux : nonProuve ? T.mention_non_prouve : T.mention_reserves;
    r.nonProuve = nonProuveAttendu(nonProuves, T, dossiers);
  }
  r.pastillesReussi = 8 - nonReussis.length - avecReserve - sansValeur.length - dossiers.length;
  let tous;
  if (sansValeur.length === 0 && dossiers.length === 0) tous = avecReserve === 0 ? T.tous_reussis : libelle(T, "tous_reussis_reserve", { n: avecReserve });
  else {
    const n = 8 - sansValeur.length - dossiers.length;
    tous = avecReserve === 0 ? libelle(T, "decompte_reussis", { n }) : libelle(T, "decompte_reussis_reserve", { n, m: avecReserve });
    if (sansValeur.length > 0) tous += T.decompte_sep + libelle(T, "decompte_sans_valeur", { k: sansValeur.length, raisons });
    if (dossiers.length > 0) tous += T.decompte_sep + libelle(T, "decompte_dossier", { j: dossiers.length });
    tous += T.decompte_fin;
  }
  r.tousReussis = cas.code === 0 && nonReussis.length === 0 ? tous : null;
  r.exigesSansValeur = cas.code === 3 && exigesSv.length > 0 ? libelle(T, "exiges_sans_valeur", { liste: exigesSv.join(", "), raisons: [...new Set(exigesSv.flatMap((n) => sansValeurAttendu(cas.json, n)))].map((k) => T[k]).join(", ") }) : null;
  r.sansValeur = (cas.code === 0 || cas.code === 3) && sansValeur.length > 0 && !(cas.code === 0 && nonReussis.length === 0) ? libelle(T, "valide_sans_valeur", { liste: sansValeur.join(", "), raisons }) : null;
  r.borne = cas.code === 0 && nonReussis.length > 0 ? libelle(T, "valide_borne", { liste: nonReussis.join(", ") }) : null;
  r.exiges = cas.code === 3 && exiges.some((n) => nonReussis.includes(n)) ? libelle(T, "exiges_non_reussis", { liste: exiges.filter((n) => nonReussis.includes(n)).join(", ") }) : null;
  return r;
}

const garder = (ecran, cles) => Object.fromEntries(cles.map((k) => [k, ecran[k]]));
const CLES_VERDICT = ["mot", "variante", "teinte", "mention", "nonProuve", "code", "controles", "pastillesReussi", "tousReussis", "borne", "exiges", "sansValeur", "exigesSansValeur"];

// --- Langage (complément du 2026-11-18 de CT-6 §18) ------------------------------

/** Les fonctions et tables du langage courant d'interface.js, telles qu'écrites ; null si les sources ne les ont pas. */
const NOMS_LANGAGE = ["SANS_VALEUR", "SANS_VALEUR_PAR_CONTROLE", "APPROBATEURS_ESSAI", "approbationSansValeur", "avertissementsSansValeur", "sansValeurDuControle", "exigesSansValeur", "numerosDuDossier", "PARTIES_REQUISES", "partiesHorsPerimetre", "clesDuDossier", "approbateursDuDossier", "clePhraseCourante", "cleAvertissement", "cleRefusCourant", "cleRaisonCourante", "membresEnonce", "aDesReserves", "PHRASES_COURANTES", "LIMITES", "SUITES", "presentationVerdict", "clesNonProuve", "controlesDeLAvertissement", "reservesDuControle", "grouperAvertissements", "clePieceEnCause", "PIECES_EN_CAUSE", "instantDeSecondes", "instantDeTexte", "lignesEnResume", "CONTROLE_DU_RESUME", "GABARITS_DECISION"];

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
const LIBELLES_EXACTS_OU_REPLIES = ["ou_empreintes", "lien_versions", "phrase_fixe", "artefact_pret", "artefact_altere", "code", "code_0", "code_1", "code_2", "code_3", "noms_choisis", "nom_dossier_repertoire", "nom_dossier_archive", "nom_ancres", "nom_entetes", "nom_interne", "commande", "sortie_erreur", "refus_archive", "avertissement", "avertissement_sans_verification"];
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
  if (ok(8) && json.facts.registry) l.push(["registre", T.resume_registre]);
  // Quatrième lecture : la ligne d'un contrôle sans valeur de preuve est remplacée, une fois, par la ligne qui le dit.
  const numeros = { action: 1, outil: 1, periode: 3, approbation: 7, limite_autorite: 4, limite_bitcoin: 5, registre: 8 };
  const r = [];
  for (const x of l) {
    const n = numeros[x[0]];
    const raisons = sansValeurAttendu(json, n);
    if (raisons.length === 0) r.push(x);
    else if (!r.some((y) => y[0] === `sans_valeur_${n}`)) r.push([`sans_valeur_${n}`, libelle(T, "resume_sans_valeur", { controle: T[`controle_${n}`], raisons: raisons.map((k) => T[k]).join(", ") })]);
  }
  return r;
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
      // Complément du 2026-11-18, troisième lecture (point 6) : la formule exacte est en tête des spécialistes, hors du cadre du verdict.
      codeEnTeteSpecialistes: code === null ? null : code.closest("#verdict") === null && code.closest("#specialistes > .pv-exact") !== null && code.closest("#specialistes > .pv-exact").previousElementSibling.matches("#specialistes > h3, #specialistes > .nt-aide"),
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
  // Complément du 2026-11-19 (CT-6 EX-6.25) : un contrôle exigé sans valeur de preuve rend le code 3 ; la phrase et la
  // suite sont celles du code, sans cas particulier.
  return {
    mot: T[`mot_${cas.code}`],
    phrase: T[`phrase_${cas.code}`],
    phraseDansLeVerdict: true,
    reserves: (cas.code === 0 || cas.code === 3) && w.length > 0 ? T.reserves : null,
    code: libelle(T, "code", { code: cas.code, sens: T[`code_${cas.code}`] }),
    introCode: T.formule_exacte,
    codeMarqueExact: true,
    codeReplie: false,
    codeEnTeteSpecialistes: true,
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
const CLES_LANGAGE = ["mot", "phrase", "phraseDansLeVerdict", "reserves", "code", "introCode", "codeMarqueExact", "codeReplie", "codeEnTeteSpecialistes", "listeReserves", "limites", "suite"];

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
    const RAISONS_PIECES = ["raison_ancre_absente_liste", "raison_ancre_absente_liste_extrait", "raison_partie_absente_extrait", "raison_partie_absente_liste_extrait"];
    const cles = [...[1, 2, 3, 4, 5, 6, 7, 8].map((n) => `controle_${n}`), "statut_reussi", "statut_echoue", "statut_non_execute", ...raisonsCt6().map((r) => `raison_${r}`), ...RAISONS_PIECES, "raison_inconnue", "mot_0", "mot_1", "mot_2", "mot_3", "tous_reussis", "valide_borne", "exiges_non_reussis", "resume_indisponible", "controle_exige"];
    for (const T of [fr, en]) {
      for (const cle of cles) expect(typeof T[cle] === "string" && T[cle].length > 0, cle).to.equal(true);
      // Aucun libellé de statut ou de raison non réussi ne dit « réussi ».
      for (const cle of ["statut_echoue", "statut_non_execute", ...raisonsCt6().map((r) => `raison_${r}`), ...RAISONS_PIECES, "raison_inconnue"]) expect(T[cle], cle).to.not.match(/réussi|passed|valide|valid/i);
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
    // Un mot, un sens dans les trois outils : ce que le registre public inscrit d'un coup est un « lot » (l'outil
    // d'inscription dit « le même lot »), jamais un « bloc » ; « bloc » ne reste que pour la chaîne Bitcoin, nommée.
    for (const [cle, texte] of Object.entries(fr)) if (/\bblocs?\b/i.test(texte)) expect(texte, cle).to.match(/\bbloc de la chaîne Bitcoin\b/);
    expect(fr.prouve_long_8).to.contain("dans des lots d'opérations signés par le nombre requis de ses validateurs");
    expect(en.prouve_long_8).to.contain("in batches of operations signed by the required number of its validators");
    // Décisions du 2026-11-19 : « nom interne » est le nom qu'une équipe donne à un client dans l'outil d'inscription ;
    // la page ne l'emploie pour rien d'autre. « inchangé » est la marque de la console d'approbation : la page ne l'emploie pas.
    for (const [cle, texte] of Object.entries(fr)) expect(texte, cle).to.not.match(/noms? internes?|inchangée?s?(?!\p{L})/iu);
    for (const [cle, texte] of Object.entries(en)) expect(texte, cle).to.not.match(/internal names?|name internal|unchanged/i);
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
    // Dix-sept, et depuis le complément du 2026-11-19 quatre de plus : AV-T-5, AV-R-4, AV-N-1, AV-N-2 (section 6.10).
    expect(definis).to.have.length(21);
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
    // Complément du 2026-11-19 : la suite réservée au contrôle exigé sans valeur de preuve sous le code 0 est retirée.
    expect(Object.keys(f.SUITES).sort()).to.deep.equal(["0", "1", "2", "3", "non_faite", "refus", "refus_piece"]);
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
    expect(mentions).to.deep.equal([["un contrôle non réussi, aucun avertissement", fr.mention_non_prouve, en.mention_non_prouve], ["huit contrôles réussis, un avertissement", fr.mention_reserves, en.mention_reserves], ["un contrôle non réussi, sans valeur de preuve ou réussi avec ce que le dossier déclare, et un avertissement", fr.mention_les_deux, en.mention_les_deux]]);
    // Complément du 2026-11-19 : la mention du contrôle exigé sans valeur de preuve est retirée, dans les deux langues.
    expect([Object.hasOwn(fr, "mention_exige_sans_valeur"), Object.hasOwn(en, "mention_exige_sans_valeur"), Object.hasOwn(fr, "phrase_0_exige_sans_valeur"), Object.hasOwn(en, "suite_exige_sans_valeur")]).to.deep.equal([false, false, false, false]);
    // La mention suit le mot : elle ne le remplace pas et ne dit pas « valide » à sa place.
    for (const T of [fr, en]) for (const cle of ["mention_non_prouve", "mention_reserves", "mention_les_deux"]) expect(T[cle], cle).to.match(/^, \S/).and.not.match(/valid/i);
    // Éléments non prouvés : une clé par contrôle non réussi, la date une seule fois quand 4 et 5 manquent tous deux.
    const cles = (statuts) => [...f.clesNonProuve(lus(statuts))];
    expect(cles([R, R, R, R, R, R, R, R])).to.deep.equal([]);
    expect(cles([R, R, R, N, N, R, R, N])).to.deep.equal(["non_prouve_4_5", "non_prouve_8"]);
    expect(cles([R, R, R, N, R, R, N, R])).to.deep.equal(["non_prouve_4", "non_prouve_7"]);
    expect(cles([R, R, R, R, N, R, R, R])).to.deep.equal(["non_prouve_5"]);
    expect(cles([N, N, N, N, N, N, N, N])).to.deep.equal(["non_prouve_1", "non_prouve_2", "non_prouve_3", "non_prouve_4_5", "non_prouve_6", "non_prouve_7", "non_prouve_8"]);
    const elements = tableCt6("| Contrôle non réussi, sans valeur de preuve, ou réussi avec ce que le dossier déclare | Élément de la page française | Élément de la page anglaise |");
    expect(elements).to.deep.equal([...[1, 2, 3].map((n) => [String(n), fr[`non_prouve_${n}`], en[`non_prouve_${n}`]]), ["4 et 5", fr.non_prouve_4_5, en.non_prouve_4_5], ["4 seul", fr.non_prouve_4, en.non_prouve_4], ["5 seul", fr.non_prouve_5, en.non_prouve_5], ...[6, 7, 8].map((n) => [String(n), fr[`non_prouve_${n}`], en[`non_prouve_${n}`]]), ["6, réussi avec les clés du dossier", fr.non_prouve_6_dossier, en.non_prouve_6_dossier], ["7, réussi avec les approbateurs du dossier", fr.non_prouve_7_dossier, en.non_prouve_7_dossier]]);
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
    // Étape 2 : d'où vient la liste des références de confiance, et à quoi on la reconnaît. Quatrième lecture : elle ne
    // vient pas « avec » le dossier (consigne de sûreté, point 3 de cette lecture).
    expect(fr.aide_ancres).to.include("C'est un fichier dont le nom finit par .json ; l'organisation qui vous a remis le dossier vous le fournit.").and.include("Si vous ne l'avez pas").and.not.include("avec lui");
    expect(en.aide_ancres).to.include("It is a file whose name ends in .json; the organisation that gave you the dossier provides it.").and.include("If you do not have it").and.not.include("with it");
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
    const cles = [["`event.seq`, contrôle 1", "resume_action"], ["`event.tool`, contrôle 1", "resume_outil"], ["`period.period_start` et `period.period_end`, contrôle 3", "resume_periode"], ["`facts.approval`, décision `approuve`, contrôle 7", "resume_approbation"], ["`facts.approval`, décision `refuse`, contrôle 7", "resume_refus"], ["`facts.approval`, décision `expire`, contrôle 7", "resume_expiration"], ["`facts.timestamp.upper_bound`, contrôle 4", "resume_limite_autorite"], ["`facts.bitcoin`, contrôle 5", "resume_limite_bitcoin"], ["`facts.registry`, contrôle 8", "resume_registre"]];
    expect(gabarits).to.deep.equal(cles.map(([t, cle]) => [t, fr[cle], en[cle]]));
    expect({ ...f.CONTROLE_DU_RESUME }).to.deep.equal({ action: 1, outil: 1, periode: 3, approbation: 7, limite_autorite: 4, limite_bitcoin: 5, registre: 8 });
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
    // Quatrième lecture : les avertissements du rapport sont passés, pour qu'une ligne sans valeur de preuve soit remplacée.
    const lignes = (g, cas, controles = r.lireControles(cas.json, cas.code)) => g.lignesEnResume(cas.json, controles, cas.code, r.resumer(cas.json, cas.code).avertissements).map((l) => ({ nom: l.nom, cle: l.cle, valeurs: { ...l.valeurs }, instants: Object.fromEntries(Object.entries(l.instants).map(([k, v]) => [k, { ...v }])), ...(l.libelles ? { libelles: JSON.parse(JSON.stringify(l.libelles)) } : {}) }));
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
      if (ok(8) && j.facts.registry) l.push({ nom: "registre", cle: "resume_registre", valeurs: {}, instants: {} });
      // Quatrième lecture : la ligne d'un contrôle sans valeur de preuve est remplacée, une fois, par la ligne qui le dit.
      const remplacees = [];
      for (const x of l) {
        const n = { action: 1, outil: 1, periode: 3, approbation: 7, limite_autorite: 4, limite_bitcoin: 5, registre: 8 }[x.nom];
        const raisons = sansValeurAttendu(j, n);
        if (raisons.length === 0) remplacees.push(x);
        else if (!remplacees.some((y) => y.nom === `sans_valeur_${n}`)) remplacees.push({ nom: `sans_valeur_${n}`, cle: "resume_sans_valeur", valeurs: {}, instants: {}, libelles: { controle: [`controle_${n}`], raisons } });
      }
      return remplacees;
    };
    for (const [nom, cas] of Object.entries(CAS_SECONDE)) expect(lignes(f, cas), nom).to.deep.equal(attendues(cas));
    expect(lignes(f, CAS_SECONDE.plein).map((l) => l.nom)).to.deep.equal(["action", "outil", "periode", "approbation", "limite_autorite", "limite_bitcoin"]);
    expect(lignes(f, CAS_SECONDE.reserves).map((l) => l.nom)).to.deep.equal(["action", "outil", "periode", "approbation", "limite_autorite", "sans_valeur_5"]);
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

  it("troisième lecture (complément du 2026-11-18, points 2, 4 et 7) : la phrase d'un contrôle non fait suit la table de CT-6 §18, d'après la raison, le contrôle et les pièces ajoutées à l'étape 2 ; chaque réserve dit sa conséquence ; une réserve signalée plusieurs fois le dit en une phrase ; la consigne de sûreté de l'étape 2 est une phrase à part ; mutants vus", function () {
    const { fr, en } = tables();
    const f = chargerLangage();
    expect(f.cleRaisonCourante, "cleRaisonCourante dans interface.js").to.be.a("function");
    // Table de CT-6 §18 (point 8) : les phrases de la page, mot pour mot, dans les deux langues et dans l'ordre.
    const cles = ["raison_ancre_absente", "raison_ancre_absente_liste", "raison_ancre_absente_liste_extrait", "raison_partie_absente_liste_extrait", "raison_partie_absente_extrait", "raison_partie_absente", "raison_hors_perimetre_absente", "raison_hors_perimetre_forme", "raison_hors_perimetre_version", "raison_piece_hors_dossier", "raison_prerequis_en_echec", "raison_inconnue"];
    const table = tableCt6("| Raison, contrôle, pièces ajoutées à l'étape 2 | Phrase de la page française | Phrase de la page anglaise |");
    expect(table.map((l) => [l[1], l[2]])).to.deep.equal(cles.map((c) => [fr[c], en[c]]));
    // Le choix de la phrase, écrit ici une seconde fois, sur toutes les raisons, tous les contrôles et toutes les pièces.
    for (const r of [...raisonsCt6(), "raison_nouvelle", "", null, undefined, "__proto__", "toString"]) {
      for (let n = 1; n <= 8; n++) for (const ancres of [false, true]) for (const entetes of [false, true]) expect(f.cleRaisonCourante(r, n, ancres, entetes), `${r}, contrôle ${n}, liste ${ancres}, extrait ${entetes}`).to.equal(cleRaisonAttendue(r, n, { ancres, entetes }));
      // Cinquième lecture : les parties déclarées absentes « hors périmètre CT-1 » distinguent les deux causes de
      // hors_perimetre_version ; sans ce membre lisible (null), la phrase les dit toutes deux.
      const parties = [[], ["jeton-rfc3161.der"], ["preuve.ots"], ["registre.json"], ["certificat-commit.json"], ["validateurs.json"], ["approbations.json"], Object.values(PARTIES_REQUISES_ATTENDUES).flat()];
      for (let n = 1; n <= 8; n++) for (const hp of parties) expect(f.cleRaisonCourante(r, n, false, false, hp), `${r}, contrôle ${n}, ${hp}`).to.equal(cleRaisonAttendue(r, n, {}, hp));
    }
    expect({ ...f.PARTIES_REQUISES }).to.deep.equal(PARTIES_REQUISES_ATTENDUES);
    // absent_parts : seule la raison exacte « hors périmètre CT-1 » (EX-4.3) compte ; un membre illisible vaut null.
    const absentes = (a) => f.partiesHorsPerimetre({ absent_parts: a });
    expect([...absentes([{ name: "preuve_ots", file: "preuve.ots", reason: "hors périmètre CT-1" }, { name: "registre", file: "registre.json", reason: "aucun registre" }, { name: "jeton_rfc3161", file: "jeton-rfc3161.der", reason: null }])]).to.deep.equal(["preuve.ots"]);
    expect([...absentes([])]).to.deep.equal([]);
    for (const a of [undefined, null, {}, [null], [{ file: 1, reason: "hors périmètre CT-1" }], [{ file: "preuve.ots", reason: 3 }], "preuve.ots"]) expect(absentes(a), JSON.stringify(a)).to.equal(null);
    expect(f.partiesHorsPerimetre({})).to.equal(null);
    // Les deux causes en mots, et ce qui ne s'y trouve pas : la pièce absente ne met pas en cause la version, la pièce
    // présente ne dit pas que le dossier a été préparé sans elle.
    expect(fr.raison_hors_perimetre_absente).to.include("le dossier a été préparé sans la pièce dont ce contrôle a besoin").and.not.include("version");
    expect(fr.raison_hors_perimetre_forme).to.include("est dans le dossier, mais sous une forme que cette version du vérificateur ne sait pas contrôler").and.not.include("préparé sans");
    expect(en.raison_hors_perimetre_absente).to.include("the dossier was prepared without the document this control needs").and.not.include("version");
    expect(en.raison_hors_perimetre_forme).to.include("is in the dossier, but in a form this version of the verifier cannot check").and.not.include("prepared without");
    // Les phrases demandées pour une liste non ajoutée et pour une liste qui ne contient pas la référence ; la raison exacte suit, entre parenthèses.
    expect(fr.raison_ancre_absente).to.equal("Non fait : vous n'avez pas ajouté la liste des références de confiance (étape 2). Demandez-la à l'organisation qui vous a remis le dossier, puis recommencez.");
    expect(fr.raison_ancre_absente_liste).to.equal("Non fait : la liste que vous avez ajoutée ne contient pas la référence qu'il faut pour ce dossier. Demandez la bonne liste à l'organisation qui vous a remis le dossier.");
    // Cinquième lecture : le code de la raison n'est plus sur la ligne du contrôle ; il est en tête des spécialistes.
    expect([fr.raison, en.raison]).to.deep.equal(["{raison}", "{raison}"]);
    for (const T of [fr, en]) {
      for (const c of cles) expect(T[c], c).to.match(/^(?:Non fait|Not done)[ ,:]/);
      // Quand la raison met en cause le dossier, la phrase ne renvoie pas à l'étape 2 : elle renvoie à l'organisation.
      // Quatrième lecture : sans dire de ne rien ajouter à l'étape 2 (la liste sert aussi au contrôle 6), elle dit que la
      // liste et l'extrait n'y changent rien.
      for (const c of ["raison_partie_absente", "raison_hors_perimetre_version", "raison_hors_perimetre_absente", "raison_hors_perimetre_forme"]) expect(T[c], c).to.match(/Ajouter la liste ou l'extrait de l'étape 2 n'y change rien|Adding the list or the extract at step 2 changes nothing/).and.match(/organisation/).and.not.match(/pas une pièce à ajouter|not a document to add/);
      // La raison non admise (CT-6 6.2) le dit en mots courants, au lieu d'un « cette raison n'est pas admise » qui ne
      // dit rien à qui n'a pas lu la spécification.
      expect(T.raison_prerequis_en_echec).to.match(/(?:Le vérificateur ne l'accepte pas comme raison de ne pas faire un contrôle|The verifier does not accept this as a reason for not doing a control)\.$/).and.not.match(/; (?:cette raison|this reason)/);
      // Chaque réserve de la table dit sa conséquence, une fois, après ce qui est signalé.
      for (const k of Object.keys(T).filter((x) => /^av_[a-z]+_[0-9]+$/.test(x))) {
        const marque = T === fr ? " Conséquence : " : " Consequence: ";
        expect(T[k].split(marque), k).to.have.length(2);
        expect(T[k].split(marque)[0], k).to.match(/[.:;] ?\S|[.]$/);
      }
      // Une réserve signalée plusieurs fois : une phrase, sans parenthèses.
      expect(T.reserve_fois).to.match(/^(?:Le vérificateur la signale|The verifier reports it) \{n\} /).and.match(/\.$/).and.not.match(/[()]/);
      // La consigne de sûreté de l'étape 2 n'est plus dans l'aide en petit.
      expect(T.aide_ancres).to.not.match(/Vérifiez d'où|Check where/);
    }
    expect([fr.consigne_ancres, en.consigne_ancres]).to.deep.equal(["Vérifiez d'où vient cette liste : c'est elle qui désigne les tiers de confiance. Cette liste doit vous parvenir par un autre moyen que le dossier lui-même (courrier, site de l'organisation, remise en main propre). Si elle vient avec le dossier, elle ne prouve rien de plus que lui.", "Check where this list comes from: it is the list that names the trusted third parties. This list must reach you by another means than the dossier itself (post, the organisation's website, delivery by hand). If it comes with the dossier, it proves nothing more than the dossier does."]);
    const html = lire("index.modele.html");
    expect(html).to.include('<p class="nt-aide" id="aide-ancres" data-libelle="aide_ancres">{{aide_ancres}}</p>\n<p class="pv-consigne" id="consigne-ancres" data-libelle="consigne_ancres">{{consigne_ancres}}</p>');
    expect(html).to.include('aria-describedby="aide-ancres consigne-ancres nom-ancres"');
    const texte = texteCt6().replace(/\s+/g, " ");
    expect(texte).to.include(`la consigne de sûreté « ${fr.consigne_ancres} » (« ${en.consigne_ancres} »)`);
    // Mutants, joués ici sur la source : chacun rend une phrase que la table refuse.
    const mutants = [
      { titre: "liste ajoutée ignorée : toujours dite non ajoutée", avant: '    if (!ancres) return "raison_ancre_absente";', apres: '    return "raison_ancre_absente";', vu: (g) => g.cleRaisonCourante("ancre_absente", 4, true, false) !== "raison_ancre_absente_liste" },
      { titre: "extrait mis en cause pour un autre contrôle que le 5", avant: '    return numero === 5 && entetes ?', apres: "    return entetes ?", vu: (g) => g.cleRaisonCourante("ancre_absente", 8, true, true) !== "raison_ancre_absente_liste" },
      { titre: "pièce absente du dossier renvoyée à l'étape 2", avant: "    if (numero === 5 && !entetes) return ancres ?", apres: "    if (!entetes) return ancres ?", vu: (g) => g.cleRaisonCourante("partie_absente", 2, true, false) !== "raison_partie_absente" },
      // Cinquième lecture : une pièce présente dite absente ; une raison approximative de l'index prise pour « hors périmètre CT-1 ».
      { titre: "pièce présente d'une forme non contrôlée dite absente du dossier", avant: '    return parties.some((f) => horsPerimetre.includes(f)) ? "raison_hors_perimetre_absente" : "raison_hors_perimetre_forme";', apres: '    return "raison_hors_perimetre_absente";', vu: (g) => g.cleRaisonCourante("hors_perimetre_version", 5, true, true, []) !== "raison_hors_perimetre_forme" },
      { titre: "raison d'absence autre que « hors périmètre CT-1 » retenue", avant: '  return a.filter((p) => p.reason === "hors périmètre CT-1").map((p) => p.file);', apres: "  return a.map((p) => p.file);", vu: (g) => g.partiesHorsPerimetre({ absent_parts: [{ name: "preuve_ots", file: "preuve.ots", reason: "en attente" }] }).length > 0 },
    ];
    for (const m of mutants) {
      expect(m.vu(f), `témoin : ${m.titre}`).to.equal(false);
      expect(m.vu(chargerLangage((source) => source.replace(m.avant, m.apres))), `mutant vu : ${m.titre}`).to.equal(true);
    }
  });
  it("décisions du 2026-11-19 (CT-6 EX-6.25, §18 point 15) : la page ne dit sans valeur de preuve que ce que le texte dit tel ; un avertissement d'essai levé par K-3, K-7 ou K-9 n'est qu'une réserve ; le contrôle 7 suit la règle de nombre, et sans faits lisibles n'est jamais dit sans valeur ; décompte, mention et contrôles exigés suivent ; mutants vus", function () {
    const f = chargerLangage();
    const r = chargerResume();
    expect(f.avertissementsSansValeur, "avertissementsSansValeur dans interface.js").to.be.a("function");
    // La liste d'EX-6.23 de la page est, mot pour mot, celle du texte.
    expect([...f.APPROBATEURS_ESSAI].sort()).to.deep.equal(approbateursEssaiDuTexte().sort());
    expect(f.APPROBATEURS_ESSAI).to.have.length(20);
    const CHECKS = { 1: ["E-1"], 2: ["C-1"], 3: ["P-5", "K-1"], 4: ["T-7", "K-7"], 5: ["O-5", "K-9"], 6: ["E-8", "P-5", "K-3", "N-3"], 7: ["E-9", "A-3"], 8: ["R-4", "N-4", "K-8"] };
    const ESSAI = ["0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"];
    const AUTRES = ["0x" + "1".repeat(40), "0x" + "2".repeat(40)];
    const lus = (approbation = null, statuts = [R, R, R, R, R, R, R, R]) => statuts.map((st, i) => ({ numero: i + 1, statut: st, verifications: CHECKS[i + 1], approbation: i === 6 ? approbation : null }));
    const av = (id, verification) => ({ id, verification, detail: "x" });
    const sv = (g, n, c, a) => [...g.sansValeurDuControle(n, c, a)];
    const huit = (g, c, a) => [1, 2, 3, 4, 5, 6, 7, 8].map((n) => sv(g, n, c, a));
    // Levés par le point de contrôle du journal : rattachés aux contrôles 4, 5 et 6 par le rapport, mais réserves seulement.
    for (const [w, n] of [[av("AV-T-5", "K-7"), 4], [av("AV-O-3", "K-9"), 5], [av("AV-N-1", "K-3"), 6]]) {
      expect(huit(f, lus(), [w]), `${w.id} de ${w.verification}`).to.deep.equal([[], [], [], [], [], [], [], []]);
      expect([...f.reservesDuControle(n, lus(), [w])], `${w.id} de ${w.verification} : réserve`).to.deep.equal([w.id]);
      expect({ ...f.presentationVerdict(0, lus(), [w]) }).to.deep.equal({ teinte: "reserve", mention: "mention_reserves" });
      expect([...f.exigesSansValeur(lus(), [w], [n])]).to.deep.equal([]);
      expect([...f.clesNonProuve(lus(), [w])]).to.deep.equal([]);
    }
    // Les couples du texte : chacun rend son contrôle, et lui seul, sans valeur de preuve.
    for (const [w, n, cle] of [[av("AV-T-5", "T-7"), 4, "sans_valeur_av_t_5"], [av("AV-O-3", "O-5"), 5, "sans_valeur_av_o_3"], [av("AV-N-1", "E-8"), 6, "sans_valeur_av_n_1"], [av("AV-N-1", "P-5"), 6, "sans_valeur_av_n_1"], [av("AV-R-4", "R-4"), 8, "sans_valeur_av_r_4"], [av("AV-N-1", "N-4"), 8, "sans_valeur_av_n_1"]]) {
      expect(huit(f, lus(), [w]), `${w.id} de ${w.verification}`).to.deep.equal([1, 2, 3, 4, 5, 6, 7, 8].map((k) => (k === n ? [cle] : [])));
    }
    // Contrôle 7, règle de nombre : approbateurs hors de la liste d'EX-6.23 moins nombreux que le requis.
    const n2 = [av("AV-N-2", "E-9")];
    const cas7 = [
      ["deux comptes d'essai, 2 requis", { approvers: ESSAI, required: 2 }, ["sans_valeur_av_n_2"]],
      ["un compte d'essai et un autre, 2 requis", { approvers: [ESSAI[0], AUTRES[0]], required: 2 }, ["sans_valeur_av_n_2"]],
      ["un compte d'essai et deux autres, 2 requis", { approvers: [ESSAI[0], ...AUTRES], required: 2 }, []],
      ["un compte d'essai et un autre, 1 requis", { approvers: [ESSAI[0], AUTRES[0]], required: 1 }, []],
      ["adresse d'essai en capitales", { approvers: [ESSAI[0].toUpperCase().replace("0X", "0x"), AUTRES[0]], required: 2 }, ["sans_valeur_av_n_2"]],
      ["une autre adresse en double ne compte qu'une fois", { approvers: [ESSAI[0], AUTRES[0], AUTRES[0]], required: 2 }, ["sans_valeur_av_n_2"]],
      ["faits absents", null, []],
    ];
    for (const [titre, a, attendu] of cas7) {
      expect(sv(f, 7, lus(a), n2), titre).to.deep.equal(attendu);
      expect([...f.exigesSansValeur(lus(a), n2, [7])], titre).to.deep.equal(attendu.length > 0 ? [7] : []);
    }
    // AV-N-2 rattaché par une autre vérification que E-9 : réserve.
    expect(sv(f, 7, lus({ approvers: ESSAI, required: 2 }), [av("AV-N-2", "A-3")])).to.deep.equal([]);
    // Lecture des faits par la page : facts.approval sous les codes 0 et 3 seulement ; forme exacte, sinon rien.
    const json = (approval) => ({ controls: [1, 2, 3, 4, 5, 6, 7, 8].map((k) => ({ number: k, status: "reussi", reason: null, summary: "", checks: CHECKS[k] })), facts: { approval } });
    const approbation = (j, code) => r.lireControles(j, code)[6].approbation;
    expect(JSON.parse(JSON.stringify(approbation(json({ approvers: ESSAI, required: 2, size: 3 }), 0)))).to.deep.equal({ approvers: ESSAI, required: 2 });
    expect(JSON.parse(JSON.stringify(approbation(json({ approvers: ESSAI, required: 2, size: 3 }), 3)))).to.deep.equal({ approvers: ESSAI, required: 2 });
    for (const [titre, a, code] of [["code 1", { approvers: ESSAI, required: 2 }, 1], ["code 2", { approvers: ESSAI, required: 2 }, 2], ["sans approbation", null, 0], ["requis absent", { approvers: ESSAI }, 0], ["requis nul", { approvers: ESSAI, required: 0 }, 0], ["adresse mal formée", { approvers: ["0x12"], required: 1 }, 0], ["approbateurs absents", { required: 2 }, 0]]) expect(approbation(json(a), code), titre).to.equal(null);
    expect(r.lireControles(json(null), 0).filter((c) => c.numero !== 7).every((c) => c.approbation === null)).to.equal(true);
    // Mutants, joués sur la source : chacun dit sans valeur ce que le texte ne dit pas tel.
    const mutants = [
      { titre: "AV-T-5 de K-7 compté pour le contrôle 4", avant: '  4: Object.freeze([["AV-T-5", "T-7"]]),', apres: '  4: Object.freeze([["AV-T-5", "T-7"], ["AV-T-5", "K-7"]]),', vu: (g) => sv(g, 4, lus(), [av("AV-T-5", "K-7")]).length > 0 },
      { titre: "AV-O-3 de K-9 compté pour le contrôle 5", avant: '  5: Object.freeze([["AV-O-3", "O-5"]]),', apres: '  5: Object.freeze([["AV-O-3", "O-5"], ["AV-O-3", "K-9"]]),', vu: (g) => sv(g, 5, lus(), [av("AV-O-3", "K-9")]).length > 0 },
      { titre: "AV-N-1 de K-3 compté pour le contrôle 6", avant: '  6: Object.freeze([["AV-N-1", "E-8"], ["AV-N-1", "P-5"]]),', apres: '  6: Object.freeze([["AV-N-1", "E-8"], ["AV-N-1", "P-5"], ["AV-N-1", "K-3"]]),', vu: (g) => sv(g, 6, lus(), [av("AV-N-1", "K-3")]).length > 0 },
      { titre: "vérification de l'avertissement ignorée (table par identifiant)", avant: "    if (couples.some(([id, v]) => a.id === id && a.verification === v) && !ids.includes(a.id)) ids.push(a.id);", apres: "    if (couples.some(([id]) => a.id === id) && !ids.includes(a.id)) ids.push(a.id);", vu: (g) => sv(g, 4, lus(), [av("AV-T-5", "K-7")]).length > 0 },
      { titre: "règle de nombre du contrôle 7 ignorée", avant: "  if (numero === 7 && !approbationSansValeur(c.approbation)) return [];\n", apres: "", vu: (g) => sv(g, 7, lus({ approvers: [ESSAI[0], ...AUTRES], required: 2 }), n2).length > 0 },
      { titre: "contrôle 7 dit sans valeur sans faits lisibles", avant: "  if (approbation === null || approbation === undefined) return false;", apres: "  if (approbation === null || approbation === undefined) return true;", vu: (g) => sv(g, 7, lus(null), n2).length > 0 },
      { titre: "adresses d'essai comparées sans la casse", avant: "approbation.approvers.map((x) => x.toLowerCase())", apres: "approbation.approvers.map((x) => x)", vu: (g) => sv(g, 7, lus({ approvers: [ESSAI[0].toUpperCase().replace("0X", "0x"), AUTRES[0]], required: 2 }), n2).length === 0 },
    ];
    for (const m of mutants) {
      expect(m.vu(f), `témoin : ${m.titre}`).to.equal(false);
      expect(m.vu(chargerLangage((source) => source.replace(m.avant, m.apres))), `mutant vu : ${m.titre}`).to.equal(true);
    }
  });

  it("quatrième lecture (complément du 2026-11-18, point 15, point 17 et étape 2) : un contrôle réussi que le rapport dit sans valeur de preuve (table de CT-6 §18) ne compte ni parmi les réussis ni comme prouvé, et « En résumé » ne le dit pas réussi ; un contrôle réussi avec les clés ou les approbateurs que le dossier déclare lui-même le dit ; la liste des références de confiance vient par un autre moyen que le dossier ; les heures du registre sont dites comparées à rien ; mutants vus", function () {
    const { fr, en } = tables();
    const f = chargerLangage();
    const r = chargerResume();
    expect(f.sansValeurDuControle, "sansValeurDuControle dans interface.js").to.be.a("function");
    // Table de CT-6 : les avertissements qui rendent un contrôle sans valeur de preuve, et leur raison courte, mot pour mot.
    const table = tableCt6("| Avertissement | Raison courte, page française | Raison courte, page anglaise |");
    expect(table).to.deep.equal(Object.entries(SANS_VALEUR_ATTENDU).map(([id, cle]) => [id, fr[cle], en[cle]]));
    expect({ ...f.SANS_VALEUR }).to.deep.equal(SANS_VALEUR_ATTENDU);
    // Complément du 2026-11-19 (CT-6 EX-6.25) : la table de la page est celle du texte, couple par couple.
    expect(JSON.parse(JSON.stringify(f.SANS_VALEUR_PAR_CONTROLE))).to.deep.equal(SANS_VALEUR_PAR_CONTROLE_ATTENDU);
    // Les avertissements que CT-6 dit « sans valeur probante » : AV-O-3 (section 10.7) et, depuis le complément du
    // 2026-11-19, les quatre de pièce d'essai (section 6.10) ; leur phrase dit qu'ils ne prouvent rien.
    const ct6 = texteCt6();
    expect([...new Set([...ct6.matchAll(/^\| (AV-[A-Z]+-[0-9]+) \|.*sans valeur probante/gm)].map((m) => m[1]))].sort()).to.deep.equal(Object.keys(SANS_VALEUR_ATTENDU).sort());
    expect(fr.av_o_3).to.include("elle ne prouve rien");
    for (const cle of ["av_t_5", "av_r_4", "av_n_1", "av_n_2"]) expect([fr[cle], en[cle]], cle).to.satisfy(([a, b]) => / ne prouve rien/.test(a) && /proves nothing/.test(b));
    const lus = (statuts, checks = {}) => statuts.map((s, i) => ({ numero: i + 1, statut: s, verifications: checks[i + 1] ?? [] }));
    const av = (id, verification) => ({ id, verification, detail: "x" });
    const VERIFS = { 4: ["T-7", "K-7"], 5: ["O-5", "K-9"], 6: ["E-8", "K-3"], 8: ["K-8", "R-4"] };
    const tous = lus([R, R, R, R, R, R, R, R], VERIFS);
    const sv = (g, n, c, a) => [...g.sansValeurDuControle(n, c, a)];
    // AV-N-1 levé par P-5 (clé du manifeste) est rattaché aux contrôles 3 et 6 : sans valeur de preuve pour le 6 seulement.
    expect([3, 6].map((n) => sv(f, n, lus([R, R, R, R, R, R, R, R], { 3: ["P-5"], 6: ["P-5"] }), [av("AV-N-1", "P-5")]))).to.deep.equal([[], ["sans_valeur_av_n_1"]]);
    expect([1, 2, 3, 4, 5, 6, 7, 8].map((n) => sv(f, n, tous, [av("AV-O-3", "O-5"), av("AV-K-1", "K-8"), av("AV-O-3", "K-9")]))).to.deep.equal([[], [], [], [], ["sans_valeur_av_o_3"], [], [], []]);
    expect([1, 2, 3, 4, 5, 6, 7, 8].map((n) => sv(f, n, tous, [av("AV-T-5", "T-7"), av("AV-N-1", "E-8"), av("AV-R-4", "R-4")]))).to.deep.equal([[], [], [], ["sans_valeur_av_t_5"], [], ["sans_valeur_av_n_1"], [], ["sans_valeur_av_r_4"]]);
    // Seul le rattachement que le rapport donne compte ; un contrôle non fait ou échoué garde sa ligne.
    for (const v of [null, "Z-1", "R-10"]) expect(sv(f, 5, tous, [av("AV-O-3", v)]), String(v)).to.deep.equal([]);
    for (const s of [N, E]) expect(sv(f, 5, lus([R, R, R, R, s, R, R, R], VERIFS), [av("AV-O-3", "O-5")]), s).to.deep.equal([]);
    expect(sv(f, 5, tous, null)).to.deep.equal([]);
    // Les seize autres avertissements de la table ne rendent jamais un contrôle sans valeur de preuve.
    const autres = Object.keys(fr).filter((k) => /^av_[a-z]+_[0-9]+$/.test(k)).map((k) => `AV-${k.slice(3, k.lastIndexOf("_")).toUpperCase()}-${k.slice(k.lastIndexOf("_") + 1)}`).filter((id) => !Object.hasOwn(SANS_VALEUR_ATTENDU, id));
    expect(autres).to.have.length(16);
    for (const id of autres) for (const n of [4, 5, 6, 8]) expect(sv(f, n, tous, [av(id, VERIFS[n][0])]), `${id}, contrôle ${n}`).to.deep.equal([]);
    // Un contrôle sans valeur de preuve compte comme non prouvé : mention et éléments non prouvés.
    expect({ ...f.presentationVerdict(0, tous, [av("AV-O-3", "O-5")]) }).to.deep.equal({ teinte: "reserve", mention: "mention_les_deux" });
    expect({ ...f.presentationVerdict(0, tous, [av("AV-K-1", "K-8")]) }).to.deep.equal({ teinte: "reserve", mention: "mention_reserves" });
    expect([...f.clesNonProuve(tous, [av("AV-O-3", "O-5")])]).to.deep.equal(["non_prouve_5"]);
    expect([...f.clesNonProuve(lus([R, R, R, N, R, R, R, N], VERIFS), [av("AV-O-3", "O-5")])]).to.deep.equal(["non_prouve_4_5", "non_prouve_8"]);
    expect([...f.clesNonProuve(tous, [av("AV-K-1", "K-8")])]).to.deep.equal([]);
    // « En résumé » : la ligne du contrôle sans valeur de preuve est remplacée par celle qui le dit ; jamais « réussie ».
    const json = CAS_SECONDE.reserves.json;
    const lignes = (g, j = json) => g.lignesEnResume(j, r.lireControles(j, 0), 0, r.resumer(j, 0).avertissements).map((l) => JSON.parse(JSON.stringify(l)));
    expect(lignes(f).map((l) => l.nom)).to.deep.equal(["action", "outil", "periode", "approbation", "limite_autorite", "sans_valeur_5"]);
    expect(lignes(f).at(-1)).to.deep.equal({ nom: "sans_valeur_5", cle: "resume_sans_valeur", valeurs: {}, instants: {}, libelles: { controle: ["controle_5"], raisons: ["sans_valeur_av_o_3"] } });
    expect([fr.resume_sans_valeur, en.resume_sans_valeur].join(" ")).to.not.match(/réussi|passed/i);
    expect([fr.statut_sans_valeur, en.statut_sans_valeur, fr.compte_sans_valeur, en.compte_sans_valeur].join(" ")).to.not.match(/réussi|passed/i);
    // La ligne du registre (point 4 de cette lecture) : elle dit, d'après CT-6 7.1, que les heures des blocs ne sont comparées à rien.
    const registre = JSON.parse(JSON.stringify(CAS_SECONDE.plein.json));
    registre.facts.registry = { chain_id: "noortrace-2124-dev", entries: [] };
    expect(lignes(f, registre).map((l) => l.nom).at(-1)).to.equal("registre");
    expect(ct6.replace(/\s+/g, " ")).to.include("Aucune heure du registre n'est comparée aux dates de la période : une heure déclarée antérieure à la période n'est pas signalée.");
    // Cinquième lecture : la ligne dit honnêtement ce que la page sait, sans mot rassurant ; elle ne calcule aucun écart.
    expect(fr.resume_registre).to.include("ne les compare pas à la période et n'en tire aucune date : un écart entre ces heures et la période, même une heure antérieure au début de la période, n'est ni signalé, ni expliqué, ni contrôlé par lui.");
    expect(en.resume_registre).to.include("does not compare them with the period and draws no date from them: a gap between these times and the period, even a time before the start of the period, is neither reported, nor explained, nor checked by it.");
    for (const T of [fr, en]) expect(T.resume_registre).to.not.match(/contredit aucun|contradicts no|peut venir|may come|horloge|clock/);
    // Clés du dossier (EX-6.8) : toutes, une partie, ou aucune ; rien hors des codes 0 et 3 (EX-6.13).
    const cles = (e, m, point) => ({ facts: { recorder_keys: { event_key_id: "rec-01", manifest_key_id: "rec-02", source: e === m ? e : "mixte", event_key_source: e, manifest_key_source: m }, checkpoint: point === undefined ? null : { key_source: point } } });
    const cas = [[["dossier", "dossier"], 0, "toutes"], [["dossier", "dossier"], 3, "toutes"], [["dossier", "registre"], 0, "partie"], [["registre", "dossier"], 0, "partie"], [["ancres", "ancres"], 0, null], [["registre", "registre"], 0, null], [["ancres", "ancres", "dossier"], 0, "partie"], [["dossier", "dossier", "ancres"], 0, "partie"], [["dossier", "dossier", "dossier"], 0, "toutes"], [["dossier", "dossier", "autre"], 0, "toutes"], [["autre", "dossier"], 0, null], [["dossier", "dossier"], 1, null], [["dossier", "dossier"], 2, null]];
    for (const [s, code, attendue] of cas) expect(f.clesDuDossier(cles(...s), code), `${s}, code ${code}`).to.equal(attendue);
    for (const j of [{}, { facts: null }, { facts: { recorder_keys: null } }, { facts: [] }]) expect(f.clesDuDossier(j, 0), JSON.stringify(j)).to.equal(null);
    const approbation = (set_source) => ({ facts: { approval: { decision: "approuve", approvers: [], required: 2, size: 3, set_source } } });
    expect([f.approbateursDuDossier(approbation("dossier"), 0), f.approbateursDuDossier(approbation("dossier"), 3), f.approbateursDuDossier(approbation("dossier"), 1), f.approbateursDuDossier(approbation("ancres"), 0), f.approbateursDuDossier({ facts: { approval: null } }, 0), f.approbateursDuDossier({}, 0)]).to.deep.equal([true, true, false, false, false, false]);
    // Les phrases : table de CT-6, mot pour mot ; celle demandée pour le contrôle 6 sans liste ; celle du contrôle 7 ne
    // renvoie pas à l'étape 2 (aucune ancre d'approbateurs en version 0, table 5.1).
    const phrases = ["controle_cles_dossier_toutes", "controle_cles_dossier_toutes_liste", "controle_cles_dossier_partie", "controle_cles_dossier_partie_liste", "controle_approbateurs_dossier"];
    expect(tableCt6("| Contrôle, provenance, liste ajoutée à l'étape 2 | Phrase de la page française | Phrase de la page anglaise |").map((l) => [l[1], l[2]])).to.deep.equal(phrases.map((c) => [fr[c], en[c]]));
    // Cinquième lecture : la phrase ne commence plus par « Réussi » ; elle dit ce qui est prouvé et ce qui ne l'est pas.
    expect(fr.controle_cles_dossier_toutes).to.equal("Le vérificateur a fait ce contrôle avec les clés que le dossier fournit lui-même : cela montre que le dossier est cohérent, pas qui l'a signé. Pour savoir qui l'a signé, ajoutez la liste des références de confiance (étape 2).");
    for (const T of [fr, en]) for (const c of [...phrases, "statut_reussi_cles_dossier", "statut_reussi_approbateurs_dossier", "compte_dossier", "decompte_dossier"]) expect(T[c], c).to.not.match(/réussi|passed/i);
    for (const T of [fr, en]) for (const c of ["statut_reussi_cles_dossier", "statut_reussi_approbateurs_dossier"]) expect(T[c], c).to.match(/Cohérent|Consistent/).and.match(/non prouvée|not proven/);
    // Un contrôle réussi avec ce que le dossier déclare compte comme non prouvé : mention et éléments ; il n'entre pas dans le plein.
    const p5 = (...a) => ({ ...f.presentationVerdict(...a) });
    expect(p5(0, tous, [], [7])).to.deep.equal({ teinte: "reserve", mention: "mention_non_prouve" });
    expect(p5(0, tous, [av("AV-K-1", "K-8")], [6, 7])).to.deep.equal({ teinte: "reserve", mention: "mention_les_deux" });
    expect(p5(0, tous, [], [])).to.deep.equal({ teinte: "pleine", mention: null });
    expect([...f.clesNonProuve(tous, [], [6, 7])]).to.deep.equal(["non_prouve_6_dossier", "non_prouve_7_dossier"]);
    expect([...f.clesNonProuve(lus([R, R, R, N, N, R, R, R], VERIFS), [], [7])]).to.deep.equal(["non_prouve_4_5", "non_prouve_7_dossier"]);
    expect([...f.clesNonProuve(tous, [av("AV-O-3", "O-5")], [7])]).to.deep.equal(["non_prouve_5", "non_prouve_7_dossier"]);
    const resumeLu = (controles, clesDossier, approbateurs) => [...f.numerosDuDossier({ controles, clesDuDossier: clesDossier, approbateursDuDossier: approbateurs })];
    expect([resumeLu(tous, "partie", true), resumeLu(tous, null, true), resumeLu(tous, "toutes", false), resumeLu(lus([R, R, R, R, R, N, N, R]), "toutes", true), resumeLu(null, "toutes", true)]).to.deep.equal([[6, 7], [7], [6], [], []]);
    // Complément du 2026-11-19 (CT-6 EX-6.25) : un contrôle exigé sans valeur de preuve rend le code 3 ; le code 0 n'a plus
    // de cas particulier, et la ligne des contrôles exigés sans valeur de preuve ne paraît que sous le code 3.
    const essai = [av("AV-O-3", "O-5")];
    expect([...f.exigesSansValeur(tous, essai, [4, 5]), ...f.exigesSansValeur(tous, essai, [4]), ...f.exigesSansValeur(tous, essai, null), ...f.exigesSansValeur(tous, [], [5]), ...f.exigesSansValeur(null, essai, [5])]).to.deep.equal([5]);
    expect(p5(0, tous, essai, [])).to.deep.equal({ teinte: "reserve", mention: "mention_les_deux" });
    expect(f.presentationVerdict.length, "presentationVerdict ne lit plus les contrôles exigés").to.equal(3);
    for (const code of [1, 3]) expect(p5(code, tous, essai, []), String(code)).to.deep.equal({ teinte: "pleine", mention: null });
    for (const T of [fr, en]) expect(T.exiges_sans_valeur).to.match(/« Incomplet »|“Incomplete”/).and.not.match(/compte comme réussis|counts them as passed/);
    for (const T of [fr, en]) expect(T.phrase_3).to.match(/pièce d'essai|test piece/);
    const s18 = ct6.slice(ct6.indexOf("\n## 18. Page de vérification"), ct6.indexOf("\n## Annexe A")).replace(/\s+/g, " ");
    expect(s18, "§18 : plus de renvoi à l'ancien 7.5").to.not.include("est satisfait par un contrôle 5 réussi");
    expect(ct6.replace(/\s+/g, " ")).to.include("`--exiger 5` sur `regtest` rend le code 3").and.not.include("`--exiger 5` est satisfait par un contrôle 5 réussi sur le réseau que déclare votre fichier d'ancres, `regtest` compris : ne déclarez");
    for (const T of [fr, en]) {
      expect(T.controle_approbateurs_dossier).to.not.match(/ajoutez|add the list/);
      for (const c of ["controle_cles_dossier_toutes_liste", "controle_cles_dossier_partie_liste"]) expect(T[c], c).to.match(/organisation/).and.not.match(/ajoutez|add the list/);
    }
    // Étape 2 : la consigne de sûreté, mot pour mot ; un seul discours : aucun libellé ne dit que la liste vient avec le
    // dossier, ni qu'elle n'est pas une pièce à ajouter.
    expect(fr.consigne_ancres).to.include("Cette liste doit vous parvenir par un autre moyen que le dossier lui-même (courrier, site de l'organisation, remise en main propre). Si elle vient avec le dossier, elle ne prouve rien de plus que lui.");
    for (const T of [fr, en]) for (const [cle, texte] of Object.entries(T)) expect(texte, cle).to.not.match(/avec lui ;|cette liste avec lui|reçu ces pièces avec le dossier|pas une pièce à ajouter|provides this list with it|received these documents with the dossier|not a document to add/);
    // Mutants, joués ici sur la source : chacun rend ce que l'essai refuse.
    const mutants = [
      { titre: "table des avertissements sans valeur de preuve vidée", avant: 'const SANS_VALEUR = Object.freeze({ "AV-O-3": "sans_valeur_av_o_3",', apres: 'const SANS_VALEUR = Object.freeze({ "AV-O-9": "sans_valeur_av_o_3",', vu: (g) => sv(g, 5, tous, [av("AV-O-3", "O-5")]).length === 0 },
      // Depuis le complément du 2026-11-19, la règle tient en deux tables (raisons courtes, couples d'EX-6.25) : le mutant
      // ajoute AV-K-1 aux deux.
      { titre: "inscription « déclarée, non prouvée » (AV-K-1) prise pour un contrôle sans valeur", avant: /(const SANS_VALEUR = Object\.freeze\(\{ )("AV-O-3"[\s\S]*?  8: Object\.freeze\(\[\["AV-R-4", "R-4"\], \["AV-N-1", "N-4"\])/, apres: '$1"AV-K-1": "sans_valeur_av_o_3", $2, ["AV-K-1", "K-8"]', vu: (g) => sv(g, 8, tous, [av("AV-K-1", "K-8")]).length > 0 },
      // Complément du 2026-11-19.
      { titre: "registre d'essai (AV-R-4) dit « avec réserve » au lieu de « sans valeur de preuve »", avant: ' "AV-R-4": "sans_valeur_av_r_4",', apres: "", vu: (g) => sv(g, 8, tous, [av("AV-R-4", "R-4")]).length === 0 },
      { titre: "contrôle sans valeur de preuve compté comme prouvé", avant: '  const non = controles.filter((c) => c.statut !== "reussi" || sansValeurDuControle(c.numero, controles, avertissements).length > 0).map((c) => c.numero);', apres: '  const non = controles.filter((c) => c.statut !== "reussi").map((c) => c.numero);', vu: (g) => g.clesNonProuve(tous, [av("AV-O-3", "O-5")]).length === 0 },
      { titre: "« réussie » gardé dans le résumé pour une preuve sans valeur", avant: "    if (raisons.length === 0) lignes.push(ligne);", apres: "    if (raisons.length >= 0) lignes.push(ligne);", vu: (g) => lignes(g).some((l) => l.nom === "limite_bitcoin") },
      { titre: "provenance des clés lue sous un code qui n'affirme rien", avant: "  if (code !== 0 && code !== 3) return null;\n  const objet", apres: "  const objet", vu: (g) => g.clesDuDossier(cles("dossier", "dossier"), 1) !== null },
      { titre: "une clé du dossier sur deux passée sous silence", avant: '  return n === 0 ? null : n === sources.length ? "toutes" : "partie";', apres: '  return n === sources.length ? "toutes" : null;', vu: (g) => g.clesDuDossier(cles("dossier", "registre"), 0) !== "partie" },
      // Cinquième lecture.
      { titre: "approbateurs déclarés par le dossier comptés comme prouvés", avant: " || duDossier.includes(c.numero));", apres: ");", vu: (g) => g.presentationVerdict(0, tous, [], [7]).teinte === "pleine" },
      { titre: "élément « identité des approbateurs » tu", avant: "      if (duDossier.includes(n)) cles.push(`non_prouve_${n}_dossier`);", apres: "", vu: (g) => g.clesNonProuve(tous, [], [7]).length === 0 },
      { titre: "contrôle exigé sans valeur de preuve oublié", avant: "  return controles.filter((c) => exiges.includes(c.numero) && sansValeurDuControle(c.numero, controles, avertissements).length > 0).map((c) => c.numero);", apres: "  return [];", vu: (g) => g.exigesSansValeur(tous, essai, [5]).length === 0 },
    ];
    for (const m of mutants) {
      expect(m.vu(f), `témoin : ${m.titre}`).to.equal(false);
      expect(m.vu(chargerLangage((source) => source.replace(m.avant, m.apres))), `mutant vu : ${m.titre}`).to.equal(true);
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

    /**
     * Ouvre la page servie avec le travailleur du cas, choisit le dossier, ajoute les pièces demandées (`pieces` :
     * { ancres, entetes }) et vérifie ; rend l'ouverture.
     */
    async function verifierCas(cas, { page = pageConstruite, langue = "fr", options = {}, pieces = {} } = {}) {
      const o = await ouvrir(navigateur, page, { remplacements: { "travailleur.js": travailleurFactice(cas) }, ...options });
      await o.page.goto("https://verification.example/index.html");
      await attendreArtefact(o.page);
      if (langue === "en") await o.page.click("#autre-langue");
      await choisirRepertoire(o.page, DOSSIER);
      if (pieces.ancres || pieces.entetes) await deplierOptions(o.page);
      if (pieces.ancres) await o.page.setInputFiles("#entree-ancres", ANCRES);
      if (pieces.entetes) await o.page.setInputFiles("#entree-entetes", CHAINE);
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
      // Code 1 : les vérifications en échec et les vérifications bloquantes du rapport sont nommées, comme la raison
      // exacte de chaque contrôle non fait, en tête de la rubrique des spécialistes, hors de tout bloc replié (complément
      // du 2026-11-18, cinquième lecture : points 8 et 12) ; ni sous le verdict ni sur la ligne du contrôle.
      const o = await verifierCas(CAS.nonValide);
      try {
        const ecran = await lireEcran(o.page);
        expect(ecran.specialistes).to.include(libelle(T.fr, "verifications_echec", { liste: "E-7" }));
        expect(ecran.specialistes).to.include(libelle(T.fr, "verifications_bloquantes", { liste: "T-2" }));
        expect(ecran.specialistes).to.include(libelle(T.fr, "raisons_exactes", { liste: "4 (prerequis_en_echec), 5 (partie_absente), 8 (ancre_absente)" }));
        expect(ecran.suite).to.not.match(/E-7|T-2/);
        expect(ecran.controles[3].raison).to.equal(T.fr.raison_prerequis_en_echec);
        expect(await o.page.evaluate(() => [...document.querySelectorAll("#specialistes .pv-references")].every((p) => p.closest("details") === null && p.getClientRects().length > 0))).to.equal(true);
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
          // Aucun rapport : la rubrique des spécialistes n'annonce ni résultat ni rapport (troisième lecture).
          expect(await o.page.evaluate(() => document.querySelector("#specialistes .nt-aide")), langue).to.equal(null);
          expect(ecran.resultat.includes(L.intro_specialistes), langue).to.equal(false);
        } finally {
          await o.fermer();
        }
      }
    });

    it("langage, mutants : phrase d'un autre code, phrase inventée pour un avertissement hors table, réserves tues, formule exacte retirée ou restée dans le cadre du verdict, énoncé abrégé, terme de technicien réintroduit, marque « exact » détournée, mise en garde restée au-dessus du résultat ou retirée ; l'essai les voit (tués)", async function () {
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
        { titre: "la formule exacte du vérificateur retirée", fichier: "interface.js", avant: "  contenu.append(rubriqueSpecialistes(blocs, { tete: formule }));", apres: "  contenu.append(rubriqueSpecialistes(blocs, { tete: null }));", cas: nonFaits, conforme: langage },
        { titre: "la formule exacte restée dans le cadre du verdict", fichier: "interface.js", avant: "  contenu.append(rubriqueSpecialistes(blocs, { tete: formule }));", apres: "  suite.append(formule);\n  contenu.append(rubriqueSpecialistes(blocs, { tete: null }));", cas: nonFaits, conforme: langage },
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
            // Contrôles avec réserve : ceux que le rapport désigne, et eux seuls ; chacun renvoie aux réserves. Quatrième
            // lecture : un contrôle sans valeur de preuve le dit d'abord, avec ses avertissements à lui ; un contrôle réussi
            // avec ce que le dossier fournit lui-même a aussi la pastille d'avertissement.
            const reserves = a.controles.filter((c) => c.reserves !== null);
            expect(lu.pastillesReserve, quoi).to.deep.equal(a.controles.filter((c) => c.statut === R && !c.montreReussi).map((c) => c.numero));
            expect(lu.renvois, quoi).to.deep.equal(reserves.flatMap((c) => {
              const ids = c.reserves.split(" ");
              return [[ids.filter((id) => id === "AV-O-3"), "controle_sans_valeur"], [ids.filter((id) => id !== "AV-O-3"), "controle_reserve"]].filter(([l]) => l.length > 0).map(([l, cle]) => [c.numero, libelle(L, cle, { ids: l.join(", "), renvoi: L.renvoi_reserves }), "#avertissements"]);
            }));
            // Cinquième lecture : le renvoi ne porte plus l'identifiant de l'avertissement (il est dans son texte exact).
            expect(lu.renvois.every(([, texte]) => !/AV-/.test(texte)), quoi).to.equal(true);
            const sansValeur = cas.json.controls.filter((c) => sansValeurAttendu(cas.json, c.number).length > 0).length;
            const dossiers = a.controles.filter((c) => c.statut === R && sansValeurAttendu(cas.json, c.numero).length === 0 && cleDossierAttendue(cas, c.numero) !== null).map((c) => c.numero);
            const reussis = cas.json.controls.filter((c) => c.status === R).length - sansValeur - dossiers.length;
            const avecReserve = reserves.filter((c) => sansValeurAttendu(cas.json, c.numero).length === 0 && !dossiers.includes(c.numero)).length;
            expect(lu.compte.startsWith(avecReserve === 0 ? libelle(L, "compte_reussis", { n: reussis }) : libelle(L, "compte_reussis_reserve", { n: reussis, m: avecReserve })), quoi).to.equal(true);
            expect(lu.compte.includes(libelle(L, "compte_sans_valeur", { n: sansValeur })), quoi).to.equal(sansValeur > 0);
            expect(lu.compte.includes(libelle(L, "compte_dossier", { n: dossiers.length })), quoi).to.equal(dossiers.length > 0);
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
        // Ce que le cas « avec réserves » doit montrer, écrit en clair : un contrôle avec réserve, un contrôle sans valeur
        // de preuve (réseau d'essai : quatrième lecture), les approbateurs du dossier, une réserve dite deux fois.
        const o = await verifierCas(CAS_SECONDE.reserves, { langue });
        try {
          const ecran = await lireEcran(o.page);
          const langage = await lireLangage(o.page);
          // Cinquième lecture : le contrôle 7 (approbateurs du dossier) n'est plus compté parmi les réussis ni prouvé.
          expect([ecran.mention, ecran.teinte, ecran.variante, ecran.tousReussis, ecran.nonProuve], langue).to.deep.equal([L.mention_les_deux, "pv-verdict-reserve", "", langue === "fr" ? "6 contrôles réussis, dont 1 avec réserve ; 1 sans valeur de preuve (réseau d'essai) ; 1 sans preuve de l'identité des signataires." : "6 controls passed, 1 of them with a reservation; 1 without evidential value (test network); 1 with no proof of the signers' identity.", libelle(L, "non_prouve_plusieurs", { liste: `${L.non_prouve_5}${L.non_prouve_dernier}${L.non_prouve_7_dossier}` })]);
          expect(ecran.controles.map((c) => c.etat), langue).to.deep.equal([L.statut_reussi, L.statut_reussi, L.statut_reussi, L.statut_reussi, libelle(L, "statut_sans_valeur", { raisons: L.sans_valeur_av_o_3 }), L.statut_reussi, L.statut_reussi_approbateurs_dossier, L.statut_reussi_reserve]);
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

    it("seconde lecture : après un refus, un titre courant précède la mention fixée « aucun rapport », placée en tête des spécialistes ; le choix du dossier dit le refus, sans coche ni « tout est prêt », et « Vérifier » est inactif ; un autre choix l'efface", async function () {
      if (!pret(this)) return;
      const T = tables().fr;
      const o = await ouvrir(navigateur, pageConstruite, { remplacements: { "travailleur.js": travailleurFactice(CAS_SECONDE.plein) } });
      const lire = () => o.page.evaluate(() => {
        const t = (s) => (document.querySelector(s) === null ? null : document.querySelector(s).textContent);
        const choisi = document.getElementById("dossier-choisi");
        const mention = document.querySelector(".aucun-rapport");
        return { choisi: choisi.textContent, classes: choisi.className, aide: t("#aide-verifier"), titre: t("#refus-titre"), mention: mention === null ? null : mention.textContent, intro: mention === null ? null : mention.parentElement.querySelector(".pv-exact-intro").textContent, marquee: mention === null ? null : mention.hasAttribute("data-exact"), mot: t("#verdict-mot"), inactif: document.getElementById("verifier").disabled, mentionEnTeteSpecialistes: mention === null ? null : mention.closest("#verdict") === null && mention.closest("details") === null && mention.parentElement.matches("#specialistes > h3 + .pv-exact") };
      });
      try {
        await o.page.goto("https://verification.example/index.html");
        await attendreArtefact(o.page);
        const refuse = path.join(dir, "contrat-refuse.rar");
        fs.writeFileSync(refuse, "x");
        await o.page.setInputFiles("#entree-archive", refuse);
        // Avant la vérification : le fichier est choisi, rien n'est encore refusé.
        expect(garder(await lire(), ["choisi", "classes", "aide", "titre", "inactif"])).to.deep.equal({ choisi: libelle(T, "dossier_choisi_archive", { nom: "contrat-refuse.rar" }), classes: "pv-choisi pv-choisi-fait", aide: T.aide_verifier_pret, titre: null, inactif: false });
        await lancerVerification(o.page);
        // Troisième lecture (points 3 et 6) : la mention fixée est en tête des spécialistes, et « Vérifier » est inactif.
        expect(await lire()).to.deep.equal({ choisi: libelle(T, "dossier_refuse_archive", { nom: "contrat-refuse.rar" }), classes: "pv-choisi pv-choisi-refuse", aide: T.aide_verifier_refus, titre: T.titre_refus, mention: T.aucun_rapport, intro: T.mention_refus, marquee: true, mot: null, inactif: true, mentionEnTeteSpecialistes: true });
        expect(await o.page.evaluate(() => document.querySelector("#dossier-choisi svg path").getAttribute("d"))).to.not.equal("M5 12.5l4.5 4.5L19 7.5");
        // Un autre choix efface le refus de l'étape 1 ; un rapport suit, sans trace du refus.
        await choisirRepertoire(o.page, DOSSIER);
        expect(garder(await lire(), ["choisi", "classes", "aide", "inactif"])).to.deep.equal({ choisi: libelle(T, "dossier_choisi_repertoire", { nom: path.basename(DOSSIER) }), classes: "pv-choisi pv-choisi-fait", aide: T.aide_verifier_pret, inactif: false });
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
      // Cinquième lecture : en version 0, le jeu d'approbateurs est toujours celui du dossier, et le contrôle 7 ne compte
      // plus comme prouvé ; le vert plein ne se voit que sur un rapport dont le jeu vient d'ailleurs (valeur que la
      // version 0 ne rend pas, lue comme toute valeur autre que « dossier »).
      const plein = { code: 0, json: JSON.parse(JSON.stringify(CAS_SECONDE.plein.json)) };
      plein.json.facts.approval.set_source = "ancres";
      const neutre = async (o) => {
        const e = await lireEcran(o.page);
        return egal([e.variante, e.teinte, e.mention], ["", "pv-verdict-neutre", null]);
      };
      const mutants = [
        { titre: "vert plein gardé avec un contrôle non fait", avant: '  if (nonProuve) return { teinte: "reserve", mention: "mention_non_prouve" };\n', apres: "", cas: CAS_SECONDE.nonFaits, conforme: verdict },
        { titre: "mention affichée sans contrôle non fait ni avertissement", avant: '  if (reserves) return { teinte: "reserve", mention: "mention_reserves" };\n  return { teinte: "pleine", mention: null };', apres: '  return { teinte: "reserve", mention: "mention_reserves" };', cas: plein, conforme: verdict },
        { titre: "rapport illisible montré en vert plein", avant: '  if (controles === null || avertissements === null) return { teinte: "neutre", mention: null };', apres: '  if (controles === null || avertissements === null) return { teinte: "pleine", mention: null };', cas: illisible, conforme: neutre },
        { titre: "contrôle resté « Réussi » sous une réserve que le rapport lui rattache", avant: "    const [ton, nomIcone, cle] = raisonsSansValeur.length > 0 ? PASTILLE_SANS_VALEUR : cleDossier !== null ? PASTILLES_DOSSIER[c.numero] : ids.length > 0 ? PASTILLE_RESERVE : PASTILLES_STATUT[c.statut];", apres: "    const [ton, nomIcone, cle] = PASTILLES_STATUT[c.statut];", cas: CAS_SECONDE.reserves, conforme: verdict },
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
      const m = { titre: "coche et « tout est prêt » gardés après un refus", avant: '    etat.refuse = etat.vue.genre === "refus" ? etat.vue.vise : null;', apres: "    etat.refuse = null;" };
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

    it("troisième lecture (points 1 et 3) : « Valide » et sa mention d'un seul tenant, à la même taille ; ce que le dossier ne prouve pas, en gras, juste dessous ; la formule exacte en tête des spécialistes, hors du cadre du verdict et jamais repliée ; en français et en anglais ; mutant vu", async function () {
      if (!pret(this)) return;
      const T = tables();
      const lireTitre = (o) => o.page.evaluate(() => {
        const e = (s) => document.querySelector(s);
        const style = (x) => { const c = getComputedStyle(x); return [c.fontSize, c.fontWeight, c.fontFamily, c.fontStyle, c.color, c.letterSpacing, c.lineHeight]; };
        const titre = e("#verdict-titre");
        const mot = e("#verdict-mot");
        const mention = e("#verdict-mention");
        const suivant = titre.nextElementSibling;
        const code = e("#code");
        return {
          titre: titre.textContent,
          enfants: [...titre.childNodes].map((n) => (n.nodeType === Node.ELEMENT_NODE ? n.id : `texte ${JSON.stringify(n.textContent)}`)),
          memeStyle: mention !== null && JSON.stringify(style(mot)) === JSON.stringify(style(mention)),
          suivant: suivant === null ? null : suivant.id,
          suivantGras: suivant === null ? null : Number(getComputedStyle(suivant).fontWeight) >= 700,
          verdict: e("#verdict").textContent,
          formule: code === null ? null : code.closest(".pv-exact").textContent,
          formuleEnTete: code !== null && code.closest("#verdict") === null && code.closest("details") === null && code.closest("#specialistes > .pv-exact") !== null && code.closest(".pv-exact").previousElementSibling.matches("#specialistes > .nt-aide") && code.closest(".pv-exact").getClientRects().length > 0,
        };
      });
      for (const langue of ["fr", "en"]) {
        const L = T[langue];
        for (const [nom, cas] of [["contrôles non faits", CAS_SECONDE.nonFaits], ["les deux", CAS_SECONDE.lesDeux], ["réserves", CAS_SECONDE.reserves], ["incomplet", CAS_SECONDE.incomplet]]) {
          const quoi = `${nom}, ${langue}`;
          const o = await verifierCas(cas, { langue });
          try {
            const a = attendu(cas, L);
            const lu = await lireTitre(o);
            const formule = `${L.formule_exacte} ${libelle(L, "code", { code: cas.code, sens: L[`code_${cas.code}`] })}`;
            expect([lu.formule, lu.formuleEnTete], quoi).to.deep.equal([formule, true]);
            // Le cadre du verdict n'est écrit qu'en langage courant : ni la formule, ni son introduction.
            expect([lu.verdict.includes(L.formule_exacte), lu.verdict.includes(L[`code_${cas.code}`])], quoi).to.deep.equal([false, false]);
            if (a.mention === null) continue;
            expect([lu.titre, lu.enfants, lu.memeStyle], quoi).to.deep.equal([`${a.mot}${a.mention}`, ["verdict-mot", "verdict-mention"], true]);
            // Juste sous le titre : ce que le dossier ne prouve pas, en gras, avant toute autre phrase ; sinon la phrase du code.
            expect([lu.suivant, lu.suivantGras], quoi).to.deep.equal(a.nonProuve !== null ? ["non-prouve", true] : ["phrase-courante", lu.suivantGras]);
          } finally {
            await o.fermer();
          }
        }
      }
      // Mutant : la mention écrite en plus petit que le mot ; l'essai le voit.
      const copie = path.join(dir, "mutant-titre");
      fs.cpSync(SOURCES, path.join(copie, "src"), { recursive: true });
      const css = path.join(copie, "src", "page", "page.css");
      const source = fs.readFileSync(css, "utf8");
      const avant = ".pv-mention {\n  font: inherit;";
      expect(source.split(avant)).to.have.length(2);
      fs.writeFileSync(css, source.replace(avant, ".pv-mention {\n  font: inherit;\n  font-size: 0.6em;"));
      const o = await verifierCas(CAS_SECONDE.nonFaits, { page: construirePageFactice(path.join(copie, "construite"), path.join(copie, "src")) });
      try {
        expect((await lireTitre(o)).memeStyle, "mutant vu : mention plus petite que le mot").to.equal(false);
      } finally {
        await o.fermer();
        fs.rmSync(copie, { recursive: true, force: true });
      }
    });

    it("troisième lecture (point 2) : un contrôle non fait dit quoi demander, d'après les pièces ajoutées à l'étape 2 (aucune, la liste, la liste et l'extrait, l'extrait seul) ; la raison exacte est en tête des spécialistes (cinquième lecture) ; aucun terme de technicien ; en français et en anglais ; mutant vu", async function () {
      if (!pret(this)) return;
      const T = tables();
      const rapports = [
        rapportAuxFaits({ statuts: [R, N, N, N, N, R, R, N], raisons: { 2: "partie_absente", 3: "hors_perimetre_version", 4: "ancre_absente", 5: "partie_absente", 8: "ancre_absente" } }),
        rapportAuxFaits({ statuts: [R, R, R, R, N, R, R, R], raisons: { 5: "ancre_absente" } }),
      ];
      const raisonsLues = (o) => o.page.evaluate(() => [...document.querySelectorAll("#controles li")].filter((li) => li.dataset.statut === "non_execute").map((li) => {
        const r = li.querySelector(".pv-controle-raison");
        return [Number(li.dataset.numero), r.textContent, [...r.querySelectorAll("[data-valeur]")].map((v) => v.textContent)];
      }));
      const raisonsExactes = (o) => o.page.evaluate(() => (document.querySelector("#raisons-exactes") === null ? null : document.querySelector("#raisons-exactes").textContent));
      for (const langue of ["fr", "en"]) {
        for (const pieces of [{}, { ancres: true }, { ancres: true, entetes: true }, { entetes: true }]) {
          for (const json of rapports) {
            const cas = { code: 0, json };
            const quoi = `${langue}, pièces ${JSON.stringify(pieces)}, contrôles non faits ${json.controls.filter((c) => c.status === N).map((c) => c.number)}`;
            const o = await verifierCas(cas, { langue, pieces });
            try {
              const a = attendu(cas, T[langue], pieces);
              // Cinquième lecture : la ligne ne porte plus le code de la raison ; il est en tête des spécialistes.
              expect(await raisonsLues(o), quoi).to.deep.equal(a.controles.filter((c) => c.statut === N).map((c) => [c.numero, c.raison, []]));
              expect(await raisonsExactes(o), quoi).to.equal(libelle(T[langue], "raisons_exactes", { liste: json.controls.filter((c) => c.status === N).map((c) => `${c.number} (${c.reason})`).join(", ") }));
              expect(termesTrouves((await premierNiveau(o.page)).textes), quoi).to.deep.equal([]);
            } finally {
              await o.fermer();
            }
          }
        }
      }
      // Mutant : la page ignore les pièces ajoutées (la liste toujours dite non ajoutée) ; l'essai le voit.
      const copie = path.join(dir, "mutant-raisons");
      fs.cpSync(SOURCES, path.join(copie, "src"), { recursive: true });
      const fichier = path.join(copie, "src", "page", "interface.js");
      const source = fs.readFileSync(fichier, "utf8");
      const avant = "numero, noms !== null && noms.ancres !== null, noms !== null && noms.entetes !== null, horsPerimetre);";
      expect(source.split(avant)).to.have.length(2);
      fs.writeFileSync(fichier, source.replace(avant, "numero, false, false, horsPerimetre);"));
      const o = await verifierCas({ code: 0, json: rapports[0] }, { page: construirePageFactice(path.join(copie, "construite"), path.join(copie, "src")), pieces: { ancres: true } });
      try {
        const a = attendu({ code: 0, json: rapports[0] }, T.fr, { ancres: true });
        expect(await raisonsLues(o), "mutant vu : pièces ignorées").to.not.deep.equal(a.controles.filter((c) => c.statut === N).map((c) => [c.numero, c.raison, []]));
      } finally {
        await o.fermer();
        fs.rmSync(copie, { recursive: true, force: true });
      }
    });

    it("quatrième lecture (point 15) : un contrôle réussi sans valeur de preuve le dit sur sa ligne, dans le décompte, sous le verdict et dans « En résumé », jamais « réussi » ; un contrôle réussi avec les clés ou les approbateurs du dossier le dit, selon la liste ajoutée à l'étape 2 ; rien de cela sous le code 1 ; en français et en anglais ; mutant vu", async function () {
      if (!pret(this)) return;
      const T = tables();
      const faits = (json, recorder_keys) => {
        const j = JSON.parse(JSON.stringify(json));
        j.facts.recorder_keys = recorder_keys;
        return j;
      };
      const cles = (e, m) => ({ event_key_id: "rec-test-01", manifest_key_id: "rec-test-02", source: e === m ? e : "mixte", event_key_source: e, manifest_key_source: m });
      const cas = {
        // Valide aux huit contrôles réussis, le 5 sur un réseau d'essai : 7 réussis, 1 sans valeur de preuve.
        sansValeur: { code: 0, json: faits(rapportAuxFaits({ avertissements: [AV_ESSAI] }), cles("ancres", "ancres")) },
        // Le 4 non fait et le 5 sans valeur : la date n'est pas prouvée du tout ; la ligne des contrôles sans valeur s'ajoute.
        borne: { code: 0, json: faits(rapportAuxFaits({ statuts: [R, R, R, N, R, R, R, N], raisons: { 4: "ancre_absente", 8: "ancre_absente" }, avertissements: [AV_ESSAI] }), cles("dossier", "dossier")) },
        partie: { code: 0, json: faits(rapportAuxFaits(), cles("registre", "dossier")) },
        incomplet: { code: 3, json: faits(rapportAuxFaits({ code: 3, ...NON_FAITS, exiges: [4] }), cles("dossier", "dossier")) },
        nonValide: { code: 1, json: faits(rapportAuxFaits({ code: 1, statuts: [E, R, R, N, N, R, R, N], raisons: { 4: "hors_perimetre_version", 5: "hors_perimetre_version", 8: "hors_perimetre_version" }, echecs: ["E-7"], avertissements: [AV_ESSAI] }), cles("dossier", "dossier")) },
      };
      const lire = (o) => o.page.evaluate(() => {
        const t = (s) => (document.querySelector(s) === null ? null : document.querySelector(s).textContent);
        return {
          lignes: [...document.querySelectorAll("#controles li")].map((li) => [Number(li.dataset.numero), li.dataset.statut, li.dataset.presentation ?? null, li.querySelector(".nt-pastille").textContent, li.querySelector(".nt-pastille").classList.contains("nt-pastille-attente"), li.querySelector(".pv-controle-dossier") === null ? null : li.querySelector(".pv-controle-dossier").textContent]),
          compte: t("#compte-controles"),
          resume: t("#en-resume"),
          tous: t("#tous-reussis"),
        };
      });
      for (const langue of ["fr", "en"]) {
        const L = T[langue];
        for (const [nom, c] of Object.entries(cas)) {
          for (const pieces of [{}, { ancres: true }]) {
            const quoi = `${nom}, ${langue}, ${JSON.stringify(pieces)}`;
            const o = await verifierCas(c, { langue, pieces });
            try {
              const a = attendu(c, L, pieces);
              const ecran = await lireEcran(o.page);
              expect(garder(ecran, CLES_VERDICT), quoi).to.deep.equal(garder(a, CLES_VERDICT));
              const lu = await lire(o);
              // Ligne par ligne : le statut du rapport reste dans data-statut ; la présentation ne fait que restreindre.
              expect(lu.lignes.map((l) => l[1]), quoi).to.deep.equal(c.json.controls.map((x) => x.status));
              expect(lu.lignes.map((l) => l[5]), quoi).to.deep.equal(c.json.controls.map((x) => { const k = cleDossierAttendue(c, x.number, pieces); return k === null ? null : L[k]; }));
              const sv = c.json.controls.filter((x) => sansValeurAttendu(c.json, x.number).length > 0).map((x) => x.number);
              expect(lu.lignes.filter((l) => l[2] === "sans_valeur").map((l) => l[0]), quoi).to.deep.equal(sv);
              for (const n of sv) expect(lu.lignes[n - 1][3], quoi).to.equal(libelle(L, "statut_sans_valeur", { raisons: L.sans_valeur_av_o_3 }));
              expect(lu.compte.includes(libelle(L, "compte_sans_valeur", { n: sv.length })), quoi).to.equal(sv.length > 0);
              // Rien ne dit « réussi » d'un contrôle sans valeur de preuve, ni dans le résumé ni dans la ligne du verdict.
              if (sv.length > 0) {
                if (lu.resume !== null) expect(lu.resume, quoi).to.include(libelle(L, "resume_sans_valeur", { controle: L.controle_5, raisons: L.sans_valeur_av_o_3 })).and.not.include(L.resume_limite_bitcoin);
                expect(lu.tous === null || !lu.tous.includes(L.tous_reussis), quoi).to.equal(true);
              }
              expect(termesTrouves((await premierNiveau(o.page)).textes), quoi).to.deep.equal([]);
            } finally {
              await o.fermer();
            }
          }
        }
        // Écrit en clair, pour le cas de la consigne. Cinquième lecture : le contrôle 7 (approbateurs du dossier) n'est
        // plus compté parmi les réussis.
        const o = await verifierCas(cas.sansValeur, { langue });
        try {
          const ecran = await lireEcran(o.page);
          expect([ecran.tousReussis, ecran.mention, ecran.nonProuve], langue).to.deep.equal([langue === "fr" ? "6 contrôles réussis ; 1 sans valeur de preuve (réseau d'essai) ; 1 sans preuve de l'identité des signataires." : "6 controls passed; 1 without evidential value (test network); 1 with no proof of the signers' identity.", L.mention_les_deux, libelle(L, "non_prouve_plusieurs", { liste: `${L.non_prouve_5}${L.non_prouve_dernier}${L.non_prouve_7_dossier}` })]);
        } finally {
          await o.fermer();
        }
        const b = await verifierCas(cas.borne, { langue });
        try {
          const ecran = await lireEcran(b.page);
          // Cinquième lecture : les contrôles 6 et 7, réussis avec les clés et les approbateurs du dossier, ont leur élément.
          expect([ecran.nonProuve, ecran.sansValeur], langue).to.deep.equal([libelle(L, "non_prouve_plusieurs", { liste: `${L.non_prouve_4_5}${L.non_prouve_sep}${L.non_prouve_6_dossier}${L.non_prouve_sep}${L.non_prouve_7_dossier}${L.non_prouve_dernier}${L.non_prouve_8}` }), libelle(L, "valide_sans_valeur", { liste: "5", raisons: L.sans_valeur_av_o_3 })]);
          if (langue === "fr") expect(ecran.nonProuve).to.equal("Ce dossier ne prouve ni sa date, ni que la signature est bien celle de l'enregistreur, ni l'identité des approbateurs, ni son inscription au registre public.");
        } finally {
          await b.fermer();
        }
      }
      // Mutant : la phrase des clés du dossier retirée de la ligne du contrôle 6 ; l'essai le voit.
      const copie = path.join(dir, "mutant-cles-dossier");
      fs.cpSync(SOURCES, path.join(copie, "src"), { recursive: true });
      const fichier = path.join(copie, "src", "page", "interface.js");
      const source = fs.readFileSync(fichier, "utf8");
      const avant = '    if (cleDossier !== null) texte.append(element("span", "pv-controle-dossier", libelle(cleDossier)));';
      expect(source.split(avant)).to.have.length(2);
      fs.writeFileSync(fichier, source.replace(avant, ""));
      const o = await verifierCas(cas.borne, { page: construirePageFactice(path.join(copie, "construite"), path.join(copie, "src")) });
      try {
        expect((await lire(o)).lignes[5][5], "mutant vu : phrase des clés du dossier retirée").to.equal(null);
      } finally {
        await o.fermer();
        fs.rmSync(copie, { recursive: true, force: true });
      }
    });

    it("décisions du 2026-11-19 (CT-6 6.10, EX-6.25, EX-18.5) : un contrôle exigé sans valeur de preuve donne « Incomplet », sans cas particulier sous le code 0, et la ligne des contrôles exigés qui reposent sur une pièce d'essai ; les deux causes de hors_perimetre_version ; aucun code interne sur la ligne d'un contrôle ni sous le verdict ; adresse des empreintes publiées, en clair et en lien ; en français et en anglais ; mutant vu", async function () {
      if (!pret(this)) return;
      const T = tables();
      // Complément du 2026-11-19 (CT-6 EX-6.25) : la preuve de date par la chaîne Bitcoin exigée, sur un réseau d'essai,
      // rend le code 3 ; sans exigence, le même rapport rend 0.
      const exige = (exiges) => ({ code: exiges.length > 0 ? 3 : 0, json: rapportAuxFaits({ code: exiges.length > 0 ? 3 : 0, avertissements: [AV_ESSAI], exiges }) });
      const cas = {
        exigeCinq: exige([4, 5]),
        exigeTous: exige([1, 2, 3, 4, 5, 6, 7, 8]),
        sansExigence: exige([]),
        // Code 3 : le 4 exigé non fait, le 5 exigé sans valeur de preuve ; les deux lignes.
        incomplet: { code: 3, json: rapportAuxFaits({ code: 3, statuts: [R, R, R, N, R, R, R, R], raisons: { 4: "ancre_absente" }, exiges: [4, 5], avertissements: [AV_ESSAI] }) },
        // EX-6.25 : levé par le point de contrôle du journal (K-7, K-9), un avertissement d'essai n'est qu'une réserve ;
        // les contrôles 4 et 5 exigés restent satisfaits (code 0), et la page ne les dit pas sans valeur de preuve.
        pointEssai: { code: 0, json: rapportAuxFaits({ code: 0, exiges: [4, 5], avertissements: [{ id: "AV-T-5", check: "K-7", detail: "autorité AC de test CT-6 : certificat d'essai, sans valeur probante hors des tests" }, { ...AV_ESSAI, check: "K-9" }] }) },
      };
      // Contrôle 7 et règle de nombre : un approbateur d'essai sur trois, deux requis (code 0, « réserve » seulement), puis
      // les deux approbateurs du dossier, tous deux comptes d'essai (code 3 sous --exiger 7).
      const avN2 = (adresse) => ({ id: "AV-N-2", check: "E-9", detail: `approbateur ${adresse} : compte d'essai publié, sans valeur probante hors des tests` });
      const septSuffit = rapportAuxFaits({ code: 0, exiges: [7], avertissements: [avN2("0x70997970c51812dc3a010c7d01b50e0d17dc79c8")] });
      septSuffit.controls[6].checks = ["E-5", "E-9", "A-3"];
      septSuffit.facts.approval.approvers = ["0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x" + "1".repeat(40), "0x" + "2".repeat(40)];
      const septEssai = rapportAuxFaits({ code: 3, exiges: [7], avertissements: [avN2("0x70997970c51812dc3a010c7d01b50e0d17dc79c8"), avN2("0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc")] });
      septEssai.controls[6].checks = ["E-5", "E-9", "A-3"];
      cas.septSuffit = { code: 0, json: septSuffit };
      cas.septEssai = { code: 3, json: septEssai };
      // Les deux causes de hors_perimetre_version (6.2), d'après absent_parts (EX-4.3).
      const absent = { code: 0, json: rapportAuxFaits({ statuts: [R, R, R, N, N, R, R, N], raisons: { 4: "hors_perimetre_version", 5: "hors_perimetre_version", 8: "hors_perimetre_version" } }) };
      absent.json.absent_parts = ["jeton-rfc3161.der", "preuve.ots", "registre.json", "certificat-commit.json", "validateurs.json"].map((file) => ({ name: file.replace(/[.-].*$/, ""), file, reason: "hors périmètre CT-1" }));
      const forme = { code: 0, json: rapportAuxFaits({ statuts: [R, R, R, R, N, R, R, R], raisons: { 5: "hors_perimetre_version" } }) };
      forme.json.absent_parts = [];
      cas.absent = absent;
      cas.forme = forme;
      const lire = (o) => o.page.evaluate(() => {
        const t = (s) => (document.querySelector(s) === null ? null : document.querySelector(s).textContent);
        return { titre: t("#verdict-titre"), verdict: t("#verdict"), lignes: [...document.querySelectorAll("#controles li.pv-controle")].map((li) => li.querySelector(".nt-controle-texte").textContent), code: t("#code") };
      });
      for (const langue of ["fr", "en"]) {
        const L = T[langue];
        for (const [nom, c] of Object.entries(cas)) {
          const quoi = `${nom}, ${langue}`;
          const o = await verifierCas(c, { langue });
          try {
            const a = attendu(c, L);
            expect(garder(await lireEcran(o.page), CLES_VERDICT), quoi).to.deep.equal(garder(a, CLES_VERDICT));
            expect(garder(await lireLangage(o.page), CLES_LANGAGE), quoi).to.deep.equal(attenduLangage(c, L));
            const lu = await lire(o);
            expect(lu.titre, quoi).to.equal(`${a.mot}${a.mention ?? ""}`);
            // La formule exacte reste celle du code que le vérificateur a rendu : la page ne change pas le code, elle restreint ce qu'elle en dit.
            expect(lu.code, quoi).to.equal(libelle(L, "code", { code: c.code, sens: L[`code_${c.code}`] }));
            // Aucun code interne sur la ligne d'un contrôle ni dans le cadre du verdict (raison, identifiant d'avertissement ou de vérification).
            for (const texte of [lu.verdict, ...lu.lignes]) expect(texte, quoi).to.not.match(/\b[a-z]+_[a-z_]+\b|\bAV-[A-Z]|\b[A-Z]{1,2}-[0-9]+\b/);
          } finally {
            await o.fermer();
          }
        }
        // Écrit en clair, pour le cas de la consigne (preuve de date par la chaîne Bitcoin exigée, réseau d'essai).
        const o = await verifierCas(cas.exigeCinq, { langue });
        try {
          const ecran = await lireEcran(o.page);
          const langage = await lireLangage(o.page);
          expect([ecran.mot, ecran.mention, ecran.exigesSansValeur, ecran.exiges, langage.phrase], langue).to.deep.equal(langue === "fr" ? ["Incomplet", null, "Contrôles que vous avez exigés et qui reposent sur une pièce d'essai : n° 5 (réseau d'essai). Ils sont sans valeur de preuve : c'est pourquoi le résultat est « Incomplet ».", null, L.phrase_3] : ["Incomplete", null, "Controls you required that rest on a test piece: no. 5 (test network). They have no evidential value: that is why the result is “Incomplete”.", null, L.phrase_3]);
          expect(await o.page.textContent("#verdict"), langue).to.not.include(langue === "fr" ? "tout contrôle que vous avez exigé a réussi" : "every control you required passed");
          // Où trouver les empreintes publiées (décision du 2026-11-19) : l'adresse en clair dans la mise en garde courante ;
          // dans le bloc replié de l'empreinte, avant la phrase qui porte l'empreinte, un lien que la personne ouvre.
          const ADRESSE = "https://github.com/noorfinances-eng/NOORTRACE/releases";
          expect(await o.page.textContent("#confiance-courante"), langue).to.equal(L.confiance_courante);
          expect(L.confiance_courante, langue).to.match(langue === "fr" ? /sur la page des versions de son dépôt \(l'adresse est dans « Pour les spécialistes : empreinte du vérificateur », ci-dessous\)/ : /on the releases page of its repository \(the address is in “For specialists: fingerprint of the verifier”, below\)/);
          await o.page.click("#detail-empreinte > summary");
          expect(await o.page.evaluate(() => { const p = document.getElementById("ou-empreintes"); return [p.textContent, p.getClientRects().length > 0, (p.compareDocumentPosition(document.getElementById("artefact")) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0]; }), langue).to.deep.equal([L.ou_empreintes, true, true]);
          expect(await o.page.evaluate(() => { const a = document.getElementById("adresse-versions"); return [a.closest("#lien-versions").textContent, a.getAttribute("href"), a.textContent, a.getAttribute("rel"), a.getAttribute("target"), a.getClientRects().length > 0, (a.compareDocumentPosition(document.getElementById("artefact")) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0]; }), langue).to.deep.equal([`${L.lien_versions} ${ADRESSE}`, ADRESSE, ADRESSE, "noopener noreferrer", "_blank", true, true]);
        } finally {
          await o.fermer();
        }
      }
      // Les deux causes, écrites en clair.
      const o = await verifierCas(cas.absent);
      try {
        expect((await lireEcran(o.page)).controles.filter((c) => c.statut === N).map((c) => c.raison)).to.deep.equal([T.fr.raison_hors_perimetre_absente, T.fr.raison_hors_perimetre_absente, T.fr.raison_hors_perimetre_absente]);
        expect(await o.page.textContent("#raisons-exactes")).to.equal(libelle(T.fr, "raisons_exactes", { liste: "4 (hors_perimetre_version), 5 (hors_perimetre_version), 8 (hors_perimetre_version)" }));
      } finally {
        await o.fermer();
      }
      // Mutant : la ligne des contrôles exigés qui reposent sur une pièce d'essai tue sous « Incomplet » ; l'essai le voit.
      const copie = path.join(dir, "mutant-exige-sans-valeur");
      fs.cpSync(SOURCES, path.join(copie, "src"), { recursive: true });
      const fichier = path.join(copie, "src", "page", "interface.js");
      const source = fs.readFileSync(fichier, "utf8");
      const avant = "      if (v.code === 3 && exigesSv.length > 0) {";
      expect(source.split(avant)).to.have.length(2);
      fs.writeFileSync(fichier, source.replace(avant, "      if (false) {"));
      const m = await verifierCas(cas.exigeCinq, { page: construirePageFactice(path.join(copie, "construite"), path.join(copie, "src")) });
      try {
        expect((await lireEcran(m.page)).exigesSansValeur, "mutant vu : contrôle exigé sans valeur de preuve tu sous « Incomplet »").to.equal(null);
      } finally {
        await m.fermer();
        fs.rmSync(copie, { recursive: true, force: true });
      }
    });

    it("troisième lecture (points 6 et 7) : après le refus d'un fichier ou d'une pièce complémentaire, « Vérifier » est inactif et l'aide dit pourquoi ; la chose refusée est dite refusée là où elle a été choisie ; un autre choix l'efface ; la consigne de sûreté de l'étape 2 est à la taille du texte courant ; mutant vu", async function () {
      if (!pret(this)) return;
      const T = tables().fr;
      const etat = (page) => page.evaluate(() => {
        const t = (s) => (document.querySelector(s) === null ? null : document.querySelector(s).textContent);
        return { inactif: document.getElementById("verifier").disabled, aide: t("#aide-verifier"), choisi: t("#dossier-choisi"), classeChoisi: document.getElementById("dossier-choisi").className, ancres: t("#nom-ancres"), classeAncres: document.getElementById("nom-ancres").className, titre: t("#refus-titre"), suite: [...document.querySelectorAll("#suite li")].map((li) => li.textContent), mention: t("#specialistes > h3 + .pv-exact > .aucun-rapport") };
      });
      const creux = path.join(dir, "troisieme", "ancres-geantes.json");
      fs.mkdirSync(path.dirname(creux), { recursive: true });
      fs.writeFileSync(creux, "");
      fs.truncateSync(creux, 512 * 1024 * 1024 + 1);
      const refuse = path.join(dir, "troisieme", "contrat.rar");
      fs.writeFileSync(refuse, "x");
      const scenario = async (page) => {
        const o = await ouvrir(navigateur, page, { remplacements: { "travailleur.js": travailleurFactice(CAS_SECONDE.plein) } });
        const vu = {};
        try {
          await o.page.goto("https://verification.example/index.html");
          await attendreArtefact(o.page);
          // Étape 2 : la consigne de sûreté, à part, à la taille du texte courant, plus grande que l'aide en petit.
          await deplierOptions(o.page);
          vu.consigne = await o.page.evaluate(() => {
            const c = document.getElementById("consigne-ancres");
            const aide = document.getElementById("aide-ancres");
            return { texte: c.textContent, taille: getComputedStyle(c).fontSize, courant: getComputedStyle(document.body).fontSize, plusGrandeQueLAide: parseFloat(getComputedStyle(c).fontSize) > parseFloat(getComputedStyle(aide).fontSize), horsDeLAide: !aide.contains(c), visible: c.getClientRects().length > 0 };
          });
          // Refus du fichier choisi : « Vérifier » inactif jusqu'au choix d'un autre dossier.
          await o.page.setInputFiles("#entree-archive", refuse);
          await lancerVerification(o.page);
          vu.refusFichier = await etat(o.page);
          await choisirRepertoire(o.page, DOSSIER);
          vu.apresChoix = await etat(o.page);
          // Refus d'une pièce complémentaire : le dossier reste choisi, la pièce est dite refusée ; « Vérifier » inactif.
          await deplierOptions(o.page);
          await o.page.setInputFiles("#entree-ancres", creux);
          await lancerVerification(o.page);
          vu.refusPiece = await etat(o.page);
          // La pièce remplacée efface le refus.
          await deplierOptions(o.page);
          await o.page.setInputFiles("#entree-ancres", ANCRES);
          vu.pieceRemplacee = await etat(o.page);
          await o.page.setInputFiles("#entree-ancres", creux);
          await lancerVerification(o.page);
          await deplierOptions(o.page);
          await o.page.click("#retirer-ancres");
          vu.pieceRetiree = await etat(o.page);
          vu.premierNiveau = termesTrouves((await premierNiveau(o.page)).textes);
          return vu;
        } finally {
          await o.fermer();
        }
      };
      const vu = await scenario(pageConstruite);
      expect(vu.consigne).to.deep.equal({ texte: T.consigne_ancres, taille: vu.consigne.courant, courant: vu.consigne.courant, plusGrandeQueLAide: true, horsDeLAide: true, visible: true });
      const choisi = libelle(T, "dossier_choisi_repertoire", { nom: path.basename(DOSSIER) });
      expect(vu.refusFichier).to.deep.equal({ inactif: true, aide: T.aide_verifier_refus, choisi: libelle(T, "dossier_refuse_archive", { nom: "contrat.rar" }), classeChoisi: "pv-choisi pv-choisi-refuse", ancres: T.aucun_fichier, classeAncres: "pv-fichier-nom", titre: T.titre_refus, suite: [T.suite_refus_1, T.suite_refus_2], mention: T.aucun_rapport });
      expect(garder(vu.apresChoix, ["inactif", "aide", "choisi", "classeChoisi"])).to.deep.equal({ inactif: false, aide: T.aide_verifier_pret, choisi, classeChoisi: "pv-choisi pv-choisi-fait" });
      expect(vu.refusPiece).to.deep.equal({ inactif: true, aide: T.aide_verifier_refus_piece, choisi, classeChoisi: "pv-choisi pv-choisi-fait", ancres: libelle(T, "fichier_refuse", { nom: "ancres-geantes.json" }), classeAncres: "pv-fichier-nom pv-fichier-refuse", titre: T.titre_refus, suite: [T.suite_refus_piece_1, T.suite_refus_piece_2], mention: T.aucun_rapport });
      expect(garder(vu.pieceRemplacee, ["inactif", "aide", "ancres", "classeAncres"])).to.deep.equal({ inactif: false, aide: T.aide_verifier_pret, ancres: libelle(T, "fichier_choisi", { nom: path.basename(ANCRES) }), classeAncres: "pv-fichier-nom pv-fichier-choisi" });
      expect(garder(vu.pieceRetiree, ["inactif", "aide", "ancres", "choisi"])).to.deep.equal({ inactif: false, aide: T.aide_verifier_pret, ancres: T.aucun_fichier, choisi });
      expect(vu.premierNiveau).to.deep.equal([]);
      // Mutant : « Vérifier » laissé actif après un refus ; l'essai le voit.
      const copie = path.join(dir, "mutant-bouton");
      fs.cpSync(SOURCES, path.join(copie, "src"), { recursive: true });
      const fichier = path.join(copie, "src", "page", "interface.js");
      const source = fs.readFileSync(fichier, "utf8");
      const avant = " && !etat.enCours && etat.refuse === null);";
      expect(source.split(avant)).to.have.length(2);
      fs.writeFileSync(fichier, source.replace(avant, " && !etat.enCours);"));
      try {
        const m = await scenario(construirePageFactice(path.join(copie, "construite"), path.join(copie, "src")));
        expect([m.refusFichier.inactif, m.refusPiece.inactif], "mutant vu : « Vérifier » actif après un refus").to.deep.equal([false, false]);
      } finally {
        fs.rmSync(copie, { recursive: true, force: true });
      }
    });

    it("barre haute : la page amène le résultat, puis l'étape 1 (« Vérifier un autre dossier »), sous la barre, d'après sa hauteur réelle, à 1280×800 et à 390×844 ; mutant vu", async function () {
      if (!pret(this)) return;
      const mesure = async (page, fenetre) => {
        const o = await ouvrir(navigateur, page, { remplacements: { "travailleur.js": travailleurFactice(CAS_SECONDE.nonFaits) } });
        try {
          await o.page.setViewportSize(fenetre);
          await o.page.goto("https://verification.example/index.html");
          await attendreArtefact(o.page);
          await choisirRepertoire(o.page, DOSSIER);
          await lancerVerification(o.page);
          const lire = (id) => o.page.evaluate((x) => {
            const b = document.querySelector(".nt-barre").getBoundingClientRect();
            const r = document.getElementById(x).getBoundingClientRect();
            return { barre: Math.max(0, b.bottom), haut: r.top, fenetre: innerHeight };
          }, id);
          const resultat = await lire("resultat");
          await o.page.click("#verifier-autre");
          await o.page.waitForFunction(() => document.getElementById("verifier-autre").hidden);
          const etape = await lire("choix-dossier");
          return { resultat, etape, focus: await o.page.evaluate(() => document.activeElement.id) };
        } finally {
          await o.fermer();
        }
      };
      const sousLaBarre = (v) => v.haut >= v.barre && v.haut < v.barre + 48;
      for (const fenetre of [{ width: 1280, height: 800 }, { width: 390, height: 844 }]) {
        const v = await mesure(pageConstruite, fenetre);
        const quoi = `${fenetre.width}×${fenetre.height} : ${JSON.stringify(v)}`;
        expect([sousLaBarre(v.resultat), sousLaBarre(v.etape), v.focus], quoi).to.deep.equal([true, true, "choisir-archive"]);
      }
      // Mutant : la hauteur de la barre n'est pas lue ; à 1280, où la barre reste collée en haut, l'étape 1 passe dessous.
      const copie = path.join(dir, "mutant-barre");
      fs.cpSync(SOURCES, path.join(copie, "src"), { recursive: true });
      const fichier = path.join(copie, "src", "page", "interface.js");
      const source = fs.readFileSync(fichier, "utf8");
      const avant = 'position === "sticky" || position === "fixed" ? barre.getBoundingClientRect().height : 0;';
      expect(source.split(avant)).to.have.length(2);
      fs.writeFileSync(fichier, source.replace(avant, "0;"));
      try {
        const v = await mesure(construirePageFactice(path.join(copie, "construite"), path.join(copie, "src")), { width: 1280, height: 800 });
        expect([sousLaBarre(v.resultat), sousLaBarre(v.etape)], `mutant vu : ${JSON.stringify(v)}`).to.deep.equal([false, false]);
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
      // Décision du 2026-11-19 : avec les pièces d'essai des vecteurs, les lignes des contrôles 4, 5, 7 et 8 disent « sans valeur de preuve ».
      { titre: "valide, huit contrôles réussis", dossier: "ct-6/dossiers/valide-seq-7-complet", ancres: true, entetes: true, code: 0, nonReussis: [], resume: ["action", "outil", "periode", "sans_valeur_7", "sans_valeur_4", "sans_valeur_5", "sans_valeur_8"], dossier6: null },
      { titre: "valide borné, sans fichier d'ancres", dossier: "ct-6/dossiers/valide-seq-7-complet", code: 0, nonReussis: [4, 5, 8], resume: ["action", "outil", "periode", "sans_valeur_7"], dossier6: "controle_cles_dossier_toutes" },
      { titre: "non valide", dossier: "ct-1/dossiers/invalide-hash-faux", code: 1 },
      { titre: "incomplet, contrôles 4, 5 et 8 exigés", dossier: "ct-1/dossiers/valide-seq-7", exiger: [4, 5, 8], code: 3, nonReussis: [4, 5, 8], dossier6: "controle_cles_dossier_toutes", raisons: "raison_hors_perimetre_absente" },
      // Décision du 2026-11-19 (CT-6 EX-6.25) : la preuve de date par la chaîne Bitcoin exigée, sur un réseau d'essai, rend
      // le code 3 ; une preuve OpenTimestamps présente, d'une forme que la version 0 ne vérifie pas.
      { titre: "incomplet, preuve de date par la chaîne Bitcoin exigée sur un réseau d'essai", dossier: "ct-6/dossiers/valide-seq-7-complet", ancres: true, entetes: true, exiger: [4, 5], code: 3, nonReussis: [], resume: ["action", "outil", "periode", "sans_valeur_7", "sans_valeur_4", "sans_valeur_5", "sans_valeur_8"], dossier6: null, phrase: "phrase_3" },
      { titre: "valide, preuve OpenTimestamps hors profil", dossier: "ct-6/dossiers/valide-o3-hors-profil-seul", ancres: true, entetes: true, code: 0, nonReussis: [5], dossier6: null, raisons: "raison_hors_perimetre_forme" },
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
        // La phrase d'un contrôle non fait dépend des pièces ajoutées à l'étape 2 (complément du 2026-11-18, point 8).
        const a = attendu({ code: e.code, json }, T, { ancres: e.ancres === true, entetes: e.entetes === true });
        expect(garder(ecran, CLES_VERDICT), e.titre).to.deep.equal(garder(a, CLES_VERDICT));
        if (e.nonReussis) expect(ecran.controles.filter((c) => c.statut !== R).map((c) => c.numero), e.titre).to.deep.equal(e.nonReussis);
        // Cinquième lecture : la phrase du verdict, et la cause de hors_perimetre_version lue dans absent_parts.
        if (e.phrase) expect((await lireLangage(o.page)).phrase, e.titre).to.equal(T[e.phrase]);
        if (e.raisons) expect(ecran.controles.filter((c) => c.statut !== R).map((c) => c.raison), e.titre).to.deep.equal(e.nonReussis.map(() => T[e.raisons]));
        // Quatrième lecture (point 15) : les clés du contrôle 6 viennent du dossier sans liste, du fichier d'ancres avec
        // elle ; le jeu d'approbateurs du contrôle 7 est toujours celui du dossier ; la phrase est sur la ligne.
        if (e.code === 0 || e.code === 3) {
          const dossiers = await o.page.evaluate(() => [6, 7].map((n) => { const s = document.querySelector(`#controles li[data-numero="${n}"] .pv-controle-dossier`); return s === null ? null : s.textContent; }));
          expect(dossiers, e.titre).to.deep.equal([e.dossier6 === null ? null : T[e.dossier6], T.controle_approbateurs_dossier]);
          expect(json.facts.recorder_keys.source, e.titre).to.equal(e.dossier6 === null ? "ancres" : "dossier");
        }
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
          // Les lignes de l'approbation et de l'autorité d'horodatage, faites avec des pièces d'essai, ne recopient plus leurs valeurs.
          expect(lu.valeursDuResume, e.titre).to.deep.equal([String(json.event.seq), json.event.tool, instantAttendu(json.period.period_start * 1000, T), instantAttendu(json.period.period_end * 1000, T)]);
          expect(lu.valeursDuResume[1], e.titre).to.equal("sap.payments.create");
          expect(lu.valeursDuResume[2], e.titre).to.equal("5 novembre 2026 à 09 h 00 min 00 s");
        }
        if (e.code === 2) expect(lu.piece, e.titre).to.equal(T.piece_dossier);
      }
      expect((await o.violations())).to.deep.equal([]);
    } finally {
      await o.fermer();
    }
  });
});
