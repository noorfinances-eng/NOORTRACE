// Interface de la page de vérification (CT-6 §18) : choix des fichiers,
// lecture des archives (archives.js), transmission au travailleur, affichage
// (EX-18.2, EX-18.5, EX-18.7, EX-18.9). Aucun HTML n'est inséré : tout texte
// passe par textContent ou par un nœud de texte, après neutralisation des
// caractères de commande (neutraliser) ; aucun stockage, aucune requête.
//
// Présentation (complément du 2026-11-17 de CT-6 §18) : le verdict, la liste
// des contrôles et les avertissements se lisent dans le code de retour et
// dans le rapport JSON du vérificateur ; la page ne calcule aucun statut. Un
// contrôle que le rapport ne dit pas « reussi » n'est jamais montré réussi,
// et un rapport dont la liste des contrôles ne se lit pas n'est pas résumé.
//
// Langage (complément du 2026-11-18 de CT-6 §18) : chaque texte du
// vérificateur, et chaque phrase que CT-6 fixe mot pour mot, reste affiché tel
// quel, dans un élément marqué data-exact ; une phrase en langage courant le
// précède. Ces phrases sont prises dans des tables indexées par le code de
// retour, par l'identifiant d'un avertissement ou par la raison d'un refus :
// hors table, aucune phrase n'est écrite. Une valeur venue des données (nom de
// fichier, code d'une raison, référence d'une vérification) est posée dans un
// élément marqué data-valeur.

const TABLES_LIBELLES = { fr: LIBELLES_FR, en: LIBELLES_EN };
const CODES_CONNUS = [0, 1, 2, 3];
const STATUTS_CONNUS = ["reussi", "echoue", "non_execute"];
const RAISONS_CONNUES = ["partie_absente", "ancre_absente", "hors_perimetre_version", "piece_hors_dossier", "prerequis_en_echec"];

const etat = {
  langue: "fr",
  langueRapportChoisie: false,
  themeChoisi: false,
  travailleur: null,
  artefactOctets: null,
  pret: false,
  artefact: { genre: "chargement" },
  dossier: null,
  ancres: null,
  entetes: null,
  enCours: false,
  arret: false,
  attente: null,
  vue: null,
  reduit: false,
  // Ce qu'un refus vise, tant qu'il est affiché : "dossier", "ancres" ou "entetes" ; null sans refus.
  refuse: null,
  confiance: null,
  confianceDessous: false,
  deplies: new Set(),
};

const $ = (id) => document.getElementById(id);

// Caractères qu'aucun texte affiché ne porte tels quels (étape 8, revue de
// sécurité, CT-6 EX-8.6 côté page) : commandes C0 sauf la tabulation et le saut de
// ligne, DEL et C1, séparateurs de ligne et de paragraphe U+2028 et U+2029,
// marques et isolats de direction (U+061C, U+200E, U+200F, U+202A à U+202E,
// U+2066 à U+2069). Chacun est remplacé par sa forme visible \u{…}.
const CARACTERES_NEUTRALISES = /[\u{0}-\u{8}\u{B}-\u{1F}\u{7F}-\u{9F}\u{61C}\u{200E}\u{200F}\u{2028}\u{2029}\u{202A}-\u{202E}\u{2066}-\u{2069}]/gu;

/**
 * Seul point par lequel passe une chaîne venue d'une entrée (rapport, énoncé,
 * message d'erreur, sortie d'erreur, nom de fichier, chemin d'entrée) avant
 * d'être affichée : la chaîne rendue ne change ni la ligne, ni le sens de
 * lecture, ni ce qui la suit.
 */
function neutraliser(texte) {
  return String(texte).replace(CARACTERES_NEUTRALISES, (c) => `\\u{${c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}}`);
}

function libelle(cle, parametres = {}) {
  const modele = TABLES_LIBELLES[etat.langue][cle];
  return modele.replace(/\{([a-z0-9_]+)\}/g, (tout, k) => (Object.hasOwn(parametres, k) ? neutraliser(parametres[k]) : tout));
}

function element(balise, classe, texte) {
  const e = document.createElement(balise);
  if (classe) e.className = classe;
  if (texte !== undefined) e.textContent = neutraliser(texte);
  return e;
}

/**
 * Écrit dans `e` le libellé `cle`. Chaque paramètre de `valeurs` est une
 * valeur venue des données : elle est posée, neutralisée, dans un élément
 * marqué data-valeur. Chaque paramètre de `textes` est un texte de la page
 * (un autre libellé), ou un nœud déjà composé. Le texte de l'ensemble est
 * celui de libelle(cle, { ...valeurs, ...textes }).
 */
function composer(e, cle, valeurs = {}, textes = {}) {
  const modele = TABLES_LIBELLES[etat.langue][cle];
  e.replaceChildren();
  let i = 0;
  for (const m of modele.matchAll(/\{([a-z0-9_]+)\}/g)) {
    const estValeur = Object.hasOwn(valeurs, m[1]);
    if (!estValeur && !Object.hasOwn(textes, m[1])) continue;
    if (m.index > i) e.append(document.createTextNode(modele.slice(i, m.index)));
    if (estValeur) {
      const v = element("span", "pv-valeur", valeurs[m[1]]);
      v.dataset.valeur = "";
      e.append(v);
    } else if (typeof textes[m[1]] === "object") e.append(textes[m[1]]);
    else e.append(document.createTextNode(neutraliser(textes[m[1]])));
    i = m.index + m[0].length;
  }
  if (i < modele.length) e.append(document.createTextNode(modele.slice(i)));
  return e;
}

/** Élément dont le texte est le libellé `cle` (voir composer). */
function elementLibelle(balise, classe, cle, valeurs, textes) {
  return composer(element(balise, classe), cle, valeurs, textes);
}

/** Marque un élément dont le texte est celui du vérificateur, ou une phrase fixée par CT-6, tel quel. */
function exact(e) {
  e.dataset.exact = "";
  return e;
}

/** Ligne en petit : une introduction en langage courant, puis le texte exact. */
function ligneExacte(cleIntro, elementExact) {
  const p = element("p", "pv-exact");
  p.append(element("span", "pv-exact-intro", libelle(cleIntro)), document.createTextNode(" "), exact(elementExact));
  return p;
}

/** Remplace le contenu d'un élément par un texte, neutralisé. */
function ecrire(e, texte) {
  e.replaceChildren(document.createTextNode(neutraliser(texte)));
}

// Icônes du thème : tracés au trait, construits élément par élément (aucun
// HTML inséré, aucune image).
const ICONES = {
  coche: [["path", { d: "M5 12.5l4.5 4.5L19 7.5" }]],
  croix: [["path", { d: "M6.5 6.5l11 11M17.5 6.5l-11 11" }]],
  sablier: [["path", { d: "M7 4h10M7 20h10M8 4c0 4.2 4 4.6 4 8s-4 3.8-4 8M16 4c0 4.2-4 4.6-4 8s4 3.8 4 8" }]],
  imprimante: [["path", { d: "M7.5 8.5v-4h9v4M7.5 16.5h-2a1.5 1.5 0 0 1-1.5-1.5v-5a1.5 1.5 0 0 1 1.5-1.5h13a1.5 1.5 0 0 1 1.5 1.5v5a1.5 1.5 0 0 1-1.5 1.5h-2" }], ["path", { d: "M7.5 13.5h9v6h-9z" }]],
  alerte: [["path", { d: "M12 4.5l8.5 14.5h-17z" }], ["path", { d: "M12 10.5v3.5M12 16.6v.3" }]],
  question: [["circle", { cx: "12", cy: "12", r: "8.5" }], ["path", { d: "M9.7 9.7a2.4 2.4 0 1 1 3.5 2.2c-.8.4-1.2 1-1.2 1.8M12 16.6v.3" }]],
  bouclier: [["path", { d: "M12 3.5l7 2.5v5.5c0 4.3-2.9 7.6-7 9-4.1-1.4-7-4.7-7-9V6z" }], ["path", { d: "M8.8 12.2l2.4 2.4 4.2-4.6" }]],
  tiret: [["path", { d: "M7 12h10" }]],
};

function icone(nom) {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("class", "nt-icone");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  for (const [balise, attributs] of ICONES[nom]) {
    const e = document.createElementNS(NS, balise);
    for (const [k, v] of Object.entries(attributs)) e.setAttribute(k, v);
    svg.append(e);
  }
  return svg;
}

/** Pastille d'état : une icône et un mot ; `ton` : succes, refus, attente, info ou rien (neutre). */
function pastille(ton, nomIcone, texte) {
  const p = element("span", ton ? `nt-pastille nt-pastille-${ton}` : "nt-pastille");
  p.append(icone(nomIcone), element("span", null, texte));
  return p;
}

const decodeur = new TextDecoder("utf-8");

// --- Thème ------------------------------------------------------------------

// Le sombre est l'état sans attribut ; le clair pose data-theme="clair" sur
// <html>. Aucun stockage (EX-18.11) : la page s'ouvre selon le système
// (prefers-color-scheme), et le choix fait par la bascule vaut pour la page
// affichée seulement.
const COULEURS_BARRE = { sombre: "#060B16", clair: "#F3F7FF" };

function requeteSystemeClair() {
  return typeof globalThis.matchMedia === "function" ? globalThis.matchMedia("(prefers-color-scheme: light)") : null;
}

function themeClair() {
  return document.documentElement.getAttribute("data-theme") === "clair";
}

function poserTheme(clair) {
  if (clair) document.documentElement.setAttribute("data-theme", "clair");
  else document.documentElement.removeAttribute("data-theme");
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", clair ? COULEURS_BARRE.clair : COULEURS_BARRE.sombre);
  afficherBascule();
}

function afficherBascule() {
  const b = $("bascule-theme");
  if (!b) return;
  const texte = libelle(themeClair() ? "theme_vers_sombre" : "theme_vers_clair");
  b.setAttribute("aria-label", texte);
  b.setAttribute("title", texte);
}

/** Posé dès le chargement du script, avant le premier affichage du corps. */
function amorcerTheme() {
  const requete = requeteSystemeClair();
  poserTheme(requete !== null && requete.matches);
  if (requete !== null && typeof requete.addEventListener === "function") {
    requete.addEventListener("change", (ev) => {
      if (!etat.themeChoisi) poserTheme(ev.matches);
    });
  }
}

// --- Langue de la page ----------------------------------------------------

function appliquerLangue() {
  document.documentElement.lang = etat.langue;
  for (const e of document.querySelectorAll("[data-libelle]")) {
    e.textContent = libelle(e.dataset.libelle, { version: VERSION_VERIFICATEUR });
  }
  const autre = $("autre-langue");
  autre.lang = etat.langue === "fr" ? "en" : "fr";
  if (!etat.langueRapportChoisie) $("langue-rapport").value = etat.langue;
  afficherBascule();
  afficherArtefact();
  afficherDossier();
  afficherEntrees();
  afficherOptions();
  afficherVue();
}

// --- Artefact ---------------------------------------------------------------

/**
 * État du vérificateur (EX-18.5). Prêt : une pastille dans l'en-tête de la
 * page, et la phrase qui porte la version et l'empreinte dans le bloc replié
 * « Empreinte du vérificateur ». Artefact altéré ou vérificateur indisponible : la phrase
 * monte dans une alerte toujours visible, et le bloc replié disparaît.
 */
function afficherArtefact() {
  const p = $("artefact");
  const a = etat.artefact;
  p.className = "";
  let marque = ["", "sablier", "artefact_chargement"];
  if (a.genre === "chargement") p.textContent = libelle("artefact_chargement");
  else if (a.genre === "pret") {
    p.textContent = libelle("artefact_pret", { version: a.version, empreinte: a.empreinte });
    marque = ["succes", "coche", "etat_pret"];
  } else if (a.genre === "altere") {
    p.className = "alerte";
    p.textContent = libelle("artefact_altere", { calculee: a.calculee, attendue: a.attendue });
    marque = ["refus", "croix", "etat_indisponible"];
  } else {
    p.className = "alerte";
    p.textContent = `${libelle("non_faite")}. ${libelle("cause", { cause: a.cause })}`;
    marque = ["refus", "croix", "etat_indisponible"];
  }
  const enAlerte = a.genre === "altere" || a.genre === "non_faite";
  const alerte = $("alerte-verificateur");
  const detail = $("detail-empreinte");
  if (alerte && detail) {
    // En alerte : la phrase en langage courant, puis le message exact ; sinon l'empreinte, dans son bloc replié.
    if (enAlerte) alerte.replaceChildren(element("p", "pv-alerte-courante", libelle(a.genre === "altere" ? "altere_courant" : "indisponible_courant")), element("p", "pv-exact-intro", libelle("message_exact")), p);
    else $("hote-artefact").append(p);
    alerte.hidden = !enAlerte;
    detail.hidden = a.genre !== "pret";
  }
  const mot = $("etat-verificateur");
  if (mot) {
    const p = pastille(marque[0], marque[1], libelle(marque[2]));
    p.classList.add("nt-pastille-grande");
    mot.replaceChildren(p);
  }
  placerConfiance();
  majBoutons();
}

/**
 * Place du bandeau de confiance (mise en garde en langage courant, phrase fixe
 * d'EX-18.2, empreinte). À l'arrivée, il est en tête, avant les étapes. Dès
 * qu'un rapport, un refus ou une vérification non faite a été affiché, il est
 * sous le résultat, juste avant « Pour les spécialistes » : le résultat vient
 * alors en premier. Il n'est jamais retiré de la page, replié ni abrégé, et
 * il revient en tête quand le vérificateur est altéré ou indisponible (son
 * alerte y est).
 */
function placerConfiance() {
  const bandeau = etat.confiance;
  const contenu = $("resultat-contenu");
  const formulaire = $("formulaire");
  const section = $("resultat");
  if (!bandeau || !contenu || !formulaire || !section) return;
  const enAlerte = etat.artefact.genre === "altere" || etat.artefact.genre === "non_faite";
  if (etat.confianceDessous && !enAlerte && !section.hidden) {
    const specialistes = $("specialistes");
    if (specialistes && specialistes.parentElement === contenu) {
      if (bandeau.nextElementSibling !== specialistes) specialistes.before(bandeau);
    } else if (contenu.lastElementChild !== bandeau) contenu.append(bandeau);
  } else if (bandeau.nextElementSibling !== formulaire) formulaire.before(bandeau);
}

let politiqueTravailleur = null;

function creerTravailleur() {
  // Types de confiance (EX-18.12) : la politique noortrace-travailleur, créée
  // une fois (la politique de contenu n'en admet pas deux du même nom) et
  // gardée pour un travailleur neuf après un arrêt, ne rend que l'adresse
  // travailleur.js ; sans types de confiance, la chaîne constante travailleur.js.
  if (globalThis.trustedTypes && typeof globalThis.trustedTypes.createPolicy === "function") {
    if (politiqueTravailleur === null) {
      politiqueTravailleur = globalThis.trustedTypes.createPolicy("noortrace-travailleur", {
        createScriptURL(valeur) {
          if (valeur === "travailleur.js") return valeur;
          throw new TypeError("adresse de travailleur refusée");
        },
      });
    }
    return new Worker(politiqueTravailleur.createScriptURL("travailleur.js"));
  }
  return new Worker("travailleur.js");
}

function decoderArtefact() {
  const b64 = globalThis.NOORTRACE_VERIFICATEUR_WASM;
  if (typeof b64 !== "string") throw new Error("verificateur-wasm.js absent");
  delete globalThis.NOORTRACE_VERIFICATEUR_WASM;
  const binaire = atob(b64);
  const octets = new Uint8Array(binaire.length);
  for (let i = 0; i < binaire.length; i++) octets[i] = binaire.charCodeAt(i);
  return octets.buffer;
}

/**
 * Crée le travailleur et lui remet une copie des octets de l'artefact, au
 * chargement et après chaque arrêt (le travailleur arrêté est détruit ; la
 * page garde les octets pour les remettre au travailleur neuf).
 */
function lancerTravailleur() {
  etat.pret = false;
  etat.artefact = { genre: "chargement" };
  afficherArtefact();
  try {
    etat.travailleur = creerTravailleur();
  } catch (e) {
    etat.travailleur = null;
    etat.artefact = { genre: "non_faite", cause: libelle("cause_travailleur", { detail: e && e.message ? e.message : String(e) }) };
    afficherArtefact();
    return;
  }
  const t = etat.travailleur;
  t.addEventListener("message", (ev) => {
    if (etat.travailleur === t) recevoir(ev.data);
  });
  t.addEventListener("error", (ev) => {
    ev.preventDefault();
    if (etat.travailleur === t) echecTravailleur(libelle("travailleur_indisponible"));
  });
  t.addEventListener("messageerror", () => {
    if (etat.travailleur === t) echecTravailleur(libelle("travailleur_indisponible"));
  });
  const octets = etat.artefactOctets.slice(0);
  t.postMessage({ type: "artefact", octets }, [octets]);
}

function demarrer() {
  try {
    etat.artefactOctets = decoderArtefact();
  } catch (e) {
    etat.artefact = { genre: "non_faite", cause: libelle("cause_travailleur", { detail: e && e.message ? e.message : String(e) }) };
    afficherArtefact();
    return;
  }
  lancerTravailleur();
}

/**
 * Arrêt d'une vérification en cours (bouton « Arrêter ») : le travailleur
 * est détruit, la page affiche « vérification non faite » avec la cause, et
 * un travailleur neuf reçoit l'artefact. Pendant la lecture du dossier, qui
 * précède l'envoi au travailleur, la demande est retenue et honorée ensuite.
 */
function arreter() {
  if (!etat.enCours || etat.arret) return;
  etat.arret = true;
  majBoutons();
  if (etat.attente === null) return;
  const a = etat.attente;
  etat.attente = null;
  if (etat.travailleur) etat.travailleur.terminate();
  etat.travailleur = null;
  a({ type: "non_faite", cause: libelle("cause_arret") });
}

function echecTravailleur(cause) {
  if (etat.attente) {
    const a = etat.attente;
    etat.attente = null;
    a({ type: "non_faite", cause });
    return;
  }
  if (!etat.pret && etat.artefact.genre === "chargement") {
    etat.artefact = { genre: "non_faite", cause };
    afficherArtefact();
  }
}

function recevoir(message) {
  if (message === null || typeof message !== "object") return;
  if (message.type === "artefact_pret") {
    etat.pret = true;
    etat.artefact = { genre: "pret", version: String(message.version), empreinte: String(message.empreinte) };
    afficherArtefact();
  } else if (message.type === "artefact_altere") {
    etat.artefact = { genre: "altere", calculee: String(message.calculee), attendue: String(message.attendue) };
    afficherArtefact();
  } else if (etat.attente) {
    const a = etat.attente;
    etat.attente = null;
    a(message);
  } else if (message.type === "non_faite" && !etat.pret) {
    etat.artefact = { genre: "non_faite", cause: String(message.cause) };
    afficherArtefact();
  }
}

// --- Choix du dossier et des entrées ---------------------------------------

function afficherDossier() {
  const p = $("dossier-choisi");
  const d = etat.dossier;
  if (d === null) {
    p.className = "pv-choisi";
    p.textContent = libelle("aucun_dossier");
  } else if (etat.refuse === "dossier") {
    // Le dossier choisi vient d'être refusé : ni coche, ni « dossier choisi ».
    p.className = "pv-choisi pv-choisi-refuse";
    p.replaceChildren(icone("alerte"), elementLibelle("span", null, d.genre === "repertoire" ? "dossier_refuse_repertoire" : "dossier_refuse_archive", { nom: d.nom }));
  } else {
    p.className = "pv-choisi pv-choisi-fait";
    p.replaceChildren(icone("coche"), elementLibelle("span", null, d.genre === "repertoire" ? "dossier_choisi_repertoire" : "dossier_choisi_archive", { nom: d.nom }));
  }
  majBoutons();
}

/** Noms des fichiers facultatifs choisis, à côté de leurs boutons ; une pièce que la vérification a refusée le dit. */
function afficherEntrees() {
  for (const [id, fichier, piece] of [["nom-ancres", etat.ancres, "ancres"], ["nom-entetes", etat.entetes, "entetes"]]) {
    const e = $(id);
    if (!e) continue;
    const refusee = fichier !== null && etat.refuse === piece;
    e.className = refusee ? "pv-fichier-nom pv-fichier-refuse" : fichier ? "pv-fichier-nom pv-fichier-choisi" : "pv-fichier-nom";
    composer(e, refusee ? "fichier_refuse" : fichier ? "fichier_choisi" : "aucun_fichier", { nom: fichier ? fichier.name : "" });
  }
  afficherOptions();
}

/** Une pièce complémentaire changée (ajoutée, remplacée ou retirée) efface le refus qui la visait. */
function changerPiece(piece, fichier) {
  etat[piece] = fichier;
  if (etat.refuse === piece) etat.refuse = null;
  afficherEntrees();
  majBoutons();
}

/** Résumé des options choisies, lisible quand le bloc des options est replié. */
function afficherOptions() {
  const resume = $("resume-options");
  if (!resume) return;
  const parties = [];
  if (etat.ancres) parties.push(libelle("options_ancres"));
  if (etat.entetes) parties.push(libelle("options_entetes"));
  const exiges = valeurExiger();
  if (exiges === "tous") parties.push(libelle("options_exiger_tous"));
  else if (exiges !== null) {
    // Un numéro seul se lirait comme un nombre de contrôles : il est suivi du nom du contrôle.
    const numeros = exiges.split(",");
    if (numeros.length === 1) parties.push(libelle("options_exiger_un", { numero: numeros[0], nom: libelle(`controle_${numeros[0]}`) }));
    else parties.push(libelle("options_exiger", { liste: `${numeros.slice(0, -1).join(", ")}${libelle("liste_et")}${numeros[numeros.length - 1]}` }));
  }
  const langue = $("langue-rapport").value === "en" ? "en" : "fr";
  if (langue !== etat.langue) parties.push(libelle("options_langue", { langue: libelle(langue === "en" ? "langue_en" : "langue_fr") }));
  if ($("detail").checked) parties.push(libelle("options_detail"));
  ecrire(resume, parties.length === 0 ? libelle("options_aucune") : parties.join(" · "));
}

function cleAideVerifier() {
  if (etat.enCours) return "aide_verifier_en_cours";
  if (etat.artefact.genre === "altere" || etat.artefact.genre === "non_faite") return "aide_verifier_indisponible";
  if (!etat.pret) return "aide_verifier_chargement";
  if (etat.dossier !== null && etat.refuse === "dossier") return "aide_verifier_refus";
  if (etat.dossier !== null && etat.refuse !== null) return "aide_verifier_refus_piece";
  return etat.dossier === null ? "aide_verifier_dossier" : "aide_verifier_pret";
}

/**
 * Après un résultat, les trois étapes se réduisent à une ligne, sous le titre
 * du résultat : le dossier vérifié et « Vérifier un autre dossier ». Elles
 * reviennent par ce bouton, ou dès qu'un autre dossier est choisi ou déposé.
 * Un refus et une vérification non faite les laissent en place : il faut y
 * revenir pour recommencer.
 */
function afficherReduction() {
  const formulaire = $("formulaire");
  const ligne = $("dossier-verifie");
  if (!formulaire || !ligne) return;
  const v = etat.vue;
  const resultat = v !== null && v.genre === "resultat";
  formulaire.classList.toggle("pv-reduit", etat.reduit && resultat);
  // L'explication du haut de page (« à quoi sert cette page », « Comment ça marche ») s'efface avec les étapes.
  const page = $("page");
  if (page) page.classList.toggle("pv-apres-resultat", etat.reduit && resultat);
  ligne.hidden = !resultat;
  if (resultat) composer($("nom-verifie"), v.noms.dossier.genre === "repertoire" ? "dossier_verifie_repertoire" : "dossier_verifie_archive", { nom: v.noms.dossier.nom });
  $("verifier-autre").hidden = !(etat.reduit && resultat);
}

function rouvrirFormulaire() {
  etat.reduit = false;
  // Un autre choix efface le refus du précédent, et la pièce complémentaire refusée n'est plus marquée.
  etat.refuse = null;
  afficherReduction();
  afficherEntrees();
}

function majBoutons() {
  const b = $("verifier");
  // Tant qu'un refus est affiché, « Vérifier » est inactif : un autre choix le rend actif (l'aide dit lequel).
  if (b) b.disabled = !(etat.pret && etat.dossier !== null && !etat.enCours && etat.refuse === null);
  const a = $("arreter");
  if (a) {
    a.disabled = !(etat.enCours && !etat.arret);
    // « Arrêter » ne paraît que pendant une vérification.
    a.hidden = !etat.enCours;
  }
  const aide = $("aide-verifier");
  if (aide) aide.textContent = libelle(cleAideVerifier());
}

/** Octets propres d'un Uint8Array (tampon exact, transférable). */
function tamponExact(octets) {
  if (octets.byteOffset === 0 && octets.byteLength === octets.buffer.byteLength) return octets.buffer;
  return octets.slice().buffer;
}

/**
 * Seule lecture d'un fichier choisi (archive, fichier d'un répertoire,
 * ancres, en-têtes) : la taille que le navigateur déclare est bornée avant
 * la lecture (EX-18.7, bornes d'archives.js).
 */
async function lireFichier(fichier) {
  bornerTailleFichier(fichier.name, fichier.size);
  try {
    return new Uint8Array(await fichier.arrayBuffer());
  } catch {
    throw new RefusArchive("r_lecture", { nom: fichier.name });
  }
}

function dossierDeRepertoire(nom, liste) {
  // liste : [{ chemin relatif au répertoire choisi, fichier }]
  return {
    genre: "repertoire",
    nom,
    async lire() {
      // Mêmes bornes qu'une archive (EX-18.7, révision 0.7), avant toute lecture.
      bornesRepertoire(liste.map(({ chemin, fichier }) => ({ chemin, taille: fichier.size })));
      const fichiers = [];
      for (const { chemin, fichier } of liste) fichiers.push({ chemin, octets: await lireFichier(fichier) });
      return { fichiers, repertoires: [] };
    },
  };
}

function dossierDArchive(fichier) {
  return {
    genre: "archive",
    nom: fichier.name,
    async lire() {
      return lireArchive(fichier.name, await lireFichier(fichier));
    },
  };
}

function choisirRepertoire(fichiersChoisis) {
  const liste = [];
  let nom = null;
  for (const f of fichiersChoisis) {
    const rel = f.webkitRelativePath || f.name;
    const i = rel.indexOf("/");
    if (i < 0) continue;
    nom = nom ?? rel.slice(0, i);
    liste.push({ chemin: rel.slice(i + 1), fichier: f });
  }
  etat.dossier = nom === null ? null : dossierDeRepertoire(nom, liste);
  rouvrirFormulaire();
  afficherDossier();
}

function lireEntreesRepertoire(lecteur) {
  return new Promise((resoudre, rejeter) => lecteur.readEntries(resoudre, rejeter));
}

/**
 * Parcours d'un répertoire déposé. Le compteur (archives.js) arrête le
 * parcours à la première entrée au-delà de la borne d'entrées, et refuse un
 * chemin trop long, avant de descendre plus loin (EX-18.7) ; le même compte
 * est refait par bornesRepertoire avant toute lecture.
 */
async function parcourirRepertoire(entree, prefixe, liste, compteur = compteurEntrees()) {
  const lecteur = entree.createReader();
  for (;;) {
    const lot = await lireEntreesRepertoire(lecteur);
    if (lot.length === 0) break;
    for (const e of lot) {
      const chemin = `${prefixe}${e.name}`;
      if (e.isDirectory) {
        compteur.ajouter(chemin);
        await parcourirRepertoire(e, `${chemin}/`, liste, compteur);
      } else if (e.isFile) {
        compteur.ajouter(chemin);
        const fichier = await new Promise((resoudre, rejeter) => e.file(resoudre, rejeter));
        liste.push({ chemin, fichier });
      }
    }
  }
}

async function deposer(ev) {
  ev.preventDefault();
  if (etat.enCours) return;
  rouvrirFormulaire();
  const elements = [];
  const items = ev.dataTransfer ? ev.dataTransfer.items : null;
  for (let i = 0; items !== null && i < items.length; i++) if (items[i].kind === "file") elements.push(items[i]);
  if (elements.length !== 1) {
    etat.dossier = null;
    afficherDossier();
    etat.vue = { genre: "refus", raison: "r_plusieurs", parametres: {}, noms: null };
    afficherVue();
    montrerResultat();
    return;
  }
  const item = elements[0];
  const entree = typeof item.webkitGetAsEntry === "function" ? item.webkitGetAsEntry() : null;
  if (entree && entree.isDirectory) {
    const liste = [];
    try {
      await parcourirRepertoire(entree, "", liste);
    } catch (e) {
      etat.dossier = null;
      afficherDossier();
      if (e instanceof RefusArchive) etat.vue = { genre: "refus", raison: e.raison, parametres: e.parametres, noms: null };
      else etat.vue = { genre: "refus", raison: "r_lecture", parametres: { nom: entree.name }, noms: null };
      afficherVue();
      montrerResultat();
      return;
    }
    etat.dossier = dossierDeRepertoire(entree.name, liste);
  } else {
    const fichier = item.getAsFile();
    if (fichier === null) return;
    etat.dossier = dossierDArchive(fichier);
  }
  afficherDossier();
}

function contraintesExiger() {
  const tous = $("exiger-tous").checked;
  for (const c of document.querySelectorAll('input[name="exiger"]')) c.disabled = tous;
  afficherOptions();
}

/** Forme canonique d'EX-8.2 : « tous », ou numéros croissants séparés par une virgule. */
function valeurExiger() {
  if ($("exiger-tous").checked) return "tous";
  const n = [...document.querySelectorAll('input[name="exiger"]')].filter((c) => c.checked).map((c) => Number(c.value));
  n.sort((a, b) => a - b);
  return n.length === 0 ? null : n.join(",");
}

// --- Vérification -------------------------------------------------------------

function demanderVerification(message, transferts) {
  return new Promise((resoudre) => {
    etat.attente = resoudre;
    etat.travailleur.postMessage(message, transferts);
  });
}

async function verifier() {
  if (!etat.pret || etat.dossier === null || etat.enCours) return;
  etat.enCours = true;
  etat.arret = false;
  majBoutons();
  etat.vue = { genre: "en_cours" };
  etat.reduit = false;
  etat.deplies.clear();
  afficherVue();
  const noms = {
    dossier: { genre: etat.dossier.genre, nom: etat.dossier.nom },
    ancres: etat.ancres ? etat.ancres.name : null,
    entetes: etat.entetes ? etat.entetes.name : null,
  };
  try {
    let contenu;
    const fichiers = [];
    // Ce qui est lu : le dossier, puis chaque pièce complémentaire ; un refus vise ce qui était lu.
    let lu = "dossier";
    try {
      contenu = await etat.dossier.lire();
      for (const f of contenu.fichiers) fichiers.push({ chemin: `dossier/${f.chemin}`, octets: tamponExact(f.octets) });
      lu = "ancres";
      if (etat.ancres) fichiers.push({ chemin: "ancres.json", octets: tamponExact(await lireFichier(etat.ancres)) });
      lu = "entetes";
      if (etat.entetes) fichiers.push({ chemin: "entetes-bitcoin.json", octets: tamponExact(await lireFichier(etat.entetes)) });
    } catch (e) {
      if (e instanceof RefusArchive) {
        etat.vue = { genre: "refus", raison: e.raison, parametres: e.parametres, noms, vise: lu };
        return;
      }
      throw e;
    }
    if (etat.arret) {
      // Arrêt demandé pendant la lecture : rien n'est envoyé au travailleur.
      etat.vue = { genre: "non_faite", cause: { cle: "cause_arret", parametres: {} }, noms };
      return;
    }
    const message = {
      type: "verifier",
      fichiers,
      repertoires: contenu.repertoires.map((r) => `dossier/${r}`),
      options: {
        ancres: etat.ancres !== null,
        entetes: etat.entetes !== null,
        exiger: valeurExiger(),
        langue: $("langue-rapport").value === "en" ? "en" : "fr",
        detail: $("detail").checked,
      },
    };
    const reponse = await demanderVerification(message, fichiers.map((f) => f.octets));
    etat.vue = interpreter(reponse, noms);
  } catch (e) {
    etat.vue = { genre: "non_faite", cause: { cle: "cause_travailleur", parametres: { detail: e && e.message ? e.message : String(e) } }, noms };
  } finally {
    etat.enCours = false;
    const arrete = etat.arret;
    etat.arret = false;
    etat.reduit = etat.vue.genre === "resultat";
    // Un refus se dit aussi là où la chose refusée a été choisie : à l'étape 1 pour le dossier, à l'étape 2 pour une pièce.
    etat.refuse = etat.vue.genre === "refus" ? etat.vue.vise : null;
    afficherDossier();
    afficherEntrees();
    afficherVue();
    montrerResultat();
    // Après un arrêt, un travailleur neuf reçoit l'artefact ; la page
    // redevient prête quand il répond.
    if (arrete && etat.travailleur === null) lancerTravailleur();
  }
}

/** Règles d'EX-18.9 : deux codes égaux, connus, et rapport JSON cohérent. */
function interpreter(reponse, noms) {
  if (reponse === null || typeof reponse !== "object" || reponse.type !== "resultat") {
    const cause = reponse && typeof reponse.cause === "string" ? reponse.cause : "?";
    return { genre: "non_faite", cause: { texte: cause }, noms };
  }
  const [lisible, json] = reponse.executions;
  const commandes = reponse.executions.map((x) => x.arguments.join(" "));
  if (lisible.code !== json.code) {
    return { genre: "non_faite", cause: { cle: "cause_codes_differents", parametres: { code1: lisible.code, code2: json.code } }, noms, commandes };
  }
  if (!CODES_CONNUS.includes(lisible.code)) {
    return { genre: "non_faite", cause: { cle: "cause_code_inconnu", parametres: { code: lisible.code } }, noms, commandes };
  }
  let rapport;
  try {
    rapport = JSON.parse(decodeur.decode(json.sortie));
  } catch {
    return { genre: "non_faite", cause: { cle: "cause_json_illisible", parametres: {} }, noms, commandes };
  }
  if (rapport === null || typeof rapport !== "object" || rapport.exit_code !== json.code) {
    return { genre: "non_faite", cause: { cle: "cause_json_incoherent", parametres: {} }, noms, commandes };
  }
  // La version que la page annonce (EX-18.2, EX-18.5) est celle du rapport
  // (bloc verifier, EX-18.10) ; sinon la page annoncerait une version que
  // le programme n'a pas.
  const versionRapport = rapport.verifier && typeof rapport.verifier.version === "string" ? rapport.verifier.version : null;
  if (versionRapport !== VERSION_VERIFICATEUR) {
    return { genre: "non_faite", cause: { cle: "cause_version_differente", parametres: { rapport: versionRapport === null ? "?" : versionRapport, page: VERSION_VERIFICATEUR } }, noms, commandes };
  }
  const vue = {
    genre: "resultat",
    noms,
    commandes,
    code: lisible.code,
    lisible: decodeur.decode(lisible.sortie),
    erreur: decodeur.decode(lisible.erreur),
    json: decodeur.decode(json.sortie),
  };
  if (lisible.code === 2) {
    const m = rapport.error && typeof rapport.error.message === "string" ? rapport.error.message : null;
    if (m === null) return { genre: "non_faite", cause: { cle: "cause_json_incoherent", parametres: {} }, noms, commandes };
    vue.messageErreur = m;
    vue.pieceEnCause = clePieceEnCause(rapport.error.kind, rapport.error.check);
  } else {
    const s = rapport.statement;
    if (!s || typeof s.fr !== "string" || typeof s.en !== "string") {
      return { genre: "non_faite", cause: { cle: "cause_json_incoherent", parametres: {} }, noms, commandes };
    }
    vue.enonceFr = s.fr;
    vue.enonceEn = s.en;
    vue.resume = resumer(rapport, lisible.code);
  }
  return vue;
}

// --- Langage courant : tables fixées (CT-6 §18, complément du 2026-11-18) -------

// Phrase en langage courant d'un code de retour : une clé par code de la table
// de CT-6 §8.3, et rien pour toute autre valeur.
const PHRASES_COURANTES = Object.freeze({ 0: "phrase_0", 1: "phrase_1", 2: "phrase_2", 3: "phrase_3" });

/** Clé de la phrase courante du code de retour `code`, ou null si le code n'est pas dans la table. */
function clePhraseCourante(code) {
  return Number.isInteger(code) && Object.hasOwn(PHRASES_COURANTES, code) ? PHRASES_COURANTES[code] : null;
}

/**
 * Clé de la phrase courante d'un avertissement du rapport (`AV-O-3` →
 * `av_o_3`), ou null si l'identifiant n'est pas dans la table des libellés :
 * la page n'écrit alors que le texte exact du vérificateur.
 */
function cleAvertissement(id, table) {
  const m = /^AV-([A-Z]{1,2})-([1-9][0-9]{0,2})$/.exec(String(id));
  if (m === null) return null;
  const cle = `av_${m[1].toLowerCase()}_${m[2]}`;
  return Object.hasOwn(table, cle) ? cle : null;
}

/** Clé de la phrase courante d'une raison de refus (`r_…` → `c_r_…`), ou null hors table. */
function cleRefusCourant(raison, table) {
  const cle = `c_${String(raison)}`;
  return /^r_[a-z0-9_]+$/.test(String(raison)) && Object.hasOwn(table, cle) ? cle : null;
}

/**
 * Clé de la phrase courante d'un contrôle non fait (table de CT-6 §18) : d'après la raison que le rapport donne, le
 * numéro du contrôle et ce que la personne a ajouté à l'étape 2 (`ancres`, `entetes` : vrai si la pièce a été
 * ajoutée). C'est un état de la page, pas un statut calculé : la raison exacte suit, entre parenthèses. Une raison
 * hors de la table reçoit la phrase « raison inconnue ».
 */
function cleRaisonCourante(raison, numero, ancres, entetes) {
  if (raison === "ancre_absente") {
    if (!ancres) return "raison_ancre_absente";
    return numero === 5 && entetes ? "raison_ancre_absente_liste_extrait" : "raison_ancre_absente_liste";
  }
  if (raison === "partie_absente") {
    if (numero === 5 && !entetes) return ancres ? "raison_partie_absente_extrait" : "raison_partie_absente_liste_extrait";
    return "raison_partie_absente";
  }
  if (raison === "hors_perimetre_version" || raison === "piece_hors_dossier" || raison === "prerequis_en_echec") return `raison_${raison}`;
  return "raison_inconnue";
}

// « Ce que ce résultat ne dit pas » et « Et maintenant ? » : lignes fixes par
// code de retour ; rien pour le code 2 dans la première liste (le vérificateur
// n'a rien examiné).
const LIMITES = Object.freeze({ 0: ["limite_1", "limite_2", "limite_3", "limite_4", "limite_5"], 1: ["limite_invalide"], 3: ["limite_1", "limite_2", "limite_3", "limite_4", "limite_5"] });
const SUITES = Object.freeze({
  0: ["suite_0_1", "suite_0_2", "suite_0_3"],
  1: ["suite_1_1", "suite_1_2", "suite_1_3"],
  2: ["suite_2_1", "suite_2_2", "suite_2_3"],
  3: ["suite_3_1", "suite_3_2", "suite_3_3"],
  non_faite: ["suite_non_faite_1", "suite_non_faite_2", "suite_non_faite_3"],
  refus: ["suite_refus_1", "suite_refus_2"],
  refus_piece: ["suite_refus_piece_1", "suite_refus_piece_2"],
});

/**
 * Membres de phrase d'un énoncé : le texte coupé après chaque « ; » suivi d'une
 * espace. Aucun caractère n'est retiré ni ajouté : la concaténation des
 * membres est le texte.
 */
function membresEnonce(texte) {
  const membres = [];
  let debut = 0;
  for (;;) {
    const i = texte.indexOf("; ", debut);
    if (i < 0) break;
    membres.push(texte.slice(debut, i + 2));
    debut = i + 2;
  }
  if (debut < texte.length || membres.length === 0) membres.push(texte.slice(debut));
  return membres;
}

/**
 * Le rapport porte-t-il des réserves ? Vrai si ses avertissements ne se lisent
 * pas (null) ou s'il en porte au moins un. Ce n'est pas un statut calculé :
 * c'est la présence d'avertissements dans le rapport.
 */
function aDesReserves(avertissements) {
  return avertissements === null || avertissements.length > 0;
}

/**
 * Présentation du verdict. Le mot vient toujours du code de retour ; la
 * présentation ne peut que restreindre ce que le code dit, jamais l'étendre.
 * Sous le code 0, la teinte pleine n'est gardée que si le rapport JSON, lu
 * exactement, donne les huit contrôles réussis et aucun avertissement. Avec
 * un contrôle non réussi ou un avertissement, la teinte est celle de
 * l'avertissement et une mention fixe suit le mot. Si le rapport ne se lit
 * pas exactement, la teinte est neutre, sans mention. Les autres codes
 * gardent leur présentation.
 */
function presentationVerdict(code, controles, avertissements) {
  if (code !== 0) return { teinte: "pleine", mention: null };
  if (controles === null || avertissements === null) return { teinte: "neutre", mention: null };
  const nonProuve = controles.some((c) => c.statut !== "reussi");
  const reserves = avertissements.length > 0;
  if (nonProuve && reserves) return { teinte: "reserve", mention: "mention_les_deux" };
  if (nonProuve) return { teinte: "reserve", mention: "mention_non_prouve" };
  if (reserves) return { teinte: "reserve", mention: "mention_reserves" };
  return { teinte: "pleine", mention: null };
}

/**
 * Ce que les contrôles non réussis laissent sans preuve, en clés de la table
 * des noms courants : la date quand ni le contrôle 4 ni le contrôle 5 n'a
 * réussi (comme le fragment F7 de l'énoncé, CT-6 §7.3), sinon une clé par
 * contrôle non réussi, dans l'ordre des numéros.
 */
function clesNonProuve(controles) {
  const non = controles.filter((c) => c.statut !== "reussi").map((c) => c.numero);
  const cles = [];
  for (const n of non) {
    if ((n === 4 || n === 5) && non.includes(4) && non.includes(5)) {
      if (n === 4) cles.push("non_prouve_4_5");
    } else cles.push(`non_prouve_${n}`);
  }
  return cles;
}

/**
 * Numéros des contrôles auxquels le rapport rattache un avertissement : ceux
 * dont la liste `checks` porte la vérification que l'avertissement nomme
 * (`check`). Sans vérification nommée, ou si aucun contrôle ne la porte,
 * l'avertissement n'est rattaché à rien : aucune ligne de contrôle ne change.
 */
function controlesDeLAvertissement(avertissement, controles) {
  if (avertissement.verification === null) return [];
  return controles.filter((c) => c.verifications.includes(avertissement.verification)).map((c) => c.numero);
}

/** Identifiants des avertissements rattachés au contrôle `numero`, chacun une fois, dans l'ordre du rapport. */
function reservesDuControle(numero, controles, avertissements) {
  const ids = [];
  for (const a of avertissements ?? []) {
    if (controlesDeLAvertissement(a, controles).includes(numero) && !ids.includes(a.id)) ids.push(a.id);
  }
  return ids;
}

/**
 * Avertissements regroupés pour l'affichage : ceux qui ont le même
 * identifiant, donc la même phrase courante, forment un seul groupe, à la
 * place du premier ; un avertissement hors de la table (`aUnePhrase` rend
 * faux) reste seul. Aucun avertissement n'est retiré : chaque groupe garde
 * tous les siens, dans l'ordre du rapport.
 */
function grouperAvertissements(avertissements, aUnePhrase) {
  const groupes = [];
  for (const a of avertissements) {
    const g = aUnePhrase(a.id) ? groupes.find((x) => x.groupe && x.id === a.id) : undefined;
    if (g) g.elements.push(a);
    else groupes.push({ id: a.id, groupe: aUnePhrase(a.id), elements: [a] });
  }
  return groupes;
}

// Phrase courante qui nomme la pièce en cause d'un rapport d'erreur (code 2),
// d'après son champ `error.kind`, et `error.check` pour une entrée à part.
const PIECES_EN_CAUSE = Object.freeze({
  dossier_illisible: "piece_dossier",
  ancres_inutilisables: "piece_ancres",
  taille_depassee: "piece_taille",
  usage: "piece_usage",
  schemas_illisibles: "piece_verificateur",
  erreur_interne: "piece_verificateur",
});

/** Clé de la phrase qui nomme la pièce en cause, ou null si le rapport d'erreur ne la nomme pas d'une façon connue. */
function clePieceEnCause(genre, verification) {
  if (genre === "entree_illisible") return verification === "N-2" ? "piece_entetes" : "piece_entree";
  return typeof genre === "string" && Object.hasOwn(PIECES_EN_CAUSE, genre) ? PIECES_EN_CAUSE[genre] : null;
}

/**
 * Jour et heure, en temps universel, d'un nombre entier de secondes comptées
 * depuis le 1er janvier 1970 ; null hors des années 1970 à 9999. Aucun fuseau
 * n'entre dans le calcul : c'est une division entière du nombre du rapport.
 */
function instantDeSecondes(secondes) {
  if (!Number.isSafeInteger(secondes) || secondes < 0 || secondes > 253402300799) return null;
  const jours = Math.floor(secondes / 86400);
  const reste = secondes - jours * 86400;
  const z = jours + 719468;
  const ere = Math.floor(z / 146097);
  const j = z - ere * 146097;
  const a = Math.floor((j - Math.floor(j / 1460) + Math.floor(j / 36524) - Math.floor(j / 146096)) / 365);
  const q = j - (365 * a + Math.floor(a / 4) - Math.floor(a / 100));
  const m = Math.floor((5 * q + 2) / 153);
  const mois = m < 10 ? m + 3 : m - 9;
  return { annee: a + ere * 400 + (mois <= 2 ? 1 : 0), mois, jour: q - Math.floor((153 * m + 2) / 5) + 1, heure: Math.floor(reste / 3600), minute: Math.floor((reste % 3600) / 60), seconde: reste % 60 };
}

/**
 * Jour et heure d'un instant du rapport écrit en temps universel, à la
 * seconde (« 2026-11-05T10:00:06Z ») ; null pour toute autre écriture, une
 * fraction de seconde comprise, ou pour un jour qui n'existe pas. Les
 * chiffres sont recopiés, rien n'est converti.
 */
function instantDeTexte(texte) {
  const m = typeof texte === "string" ? /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/.exec(texte) : null;
  if (m === null) return null;
  const [annee, mois, jour, heure, minute, seconde] = m.slice(1).map(Number);
  const bissextile = annee % 4 === 0 && (annee % 100 !== 0 || annee % 400 === 0);
  const longueurs = [31, bissextile ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (mois < 1 || mois > 12 || jour < 1 || jour > longueurs[mois - 1] || heure > 23 || minute > 59 || seconde > 59) return null;
  return { annee, mois, jour, heure, minute, seconde };
}

// « En résumé » : le contrôle dont dépend chaque ligne, et le gabarit de la
// ligne d'approbation selon la décision que le rapport donne.
const CONTROLE_DU_RESUME = Object.freeze({ action: 1, outil: 1, periode: 3, approbation: 7, limite_autorite: 4, limite_bitcoin: 5 });
const GABARITS_DECISION = Object.freeze({ approuve: "resume_approbation", refuse: "resume_refus", expire: "resume_expiration" });
// Un nom d'outil recopié tel quel : au plus 256 caractères, aucun caractère de commande, de fin de ligne ni de sens d'écriture.
const NOM_OUTIL_TEL_QUEL = /^[^\u{0}-\u{1F}\u{7F}-\u{9F}\u{61C}\u{200E}\u{200F}\u{2028}\u{2029}\u{202A}-\u{202E}\u{2066}-\u{2069}]{1,256}$/u;

/**
 * Lignes du bloc « En résumé » : des champs du rapport JSON recopiés dans des
 * gabarits fixes, et rien d'autre. Aucune ligne hors des codes 0 et 3, ni si
 * les contrôles ne se lisent pas (CT-6 EX-6.13 : `facts` ne s'emploie que
 * sous les verdicts de ces deux codes, table de CT-6 §8.3).
 * Chaque ligne ne paraît que si son champ se lit exactement et si le
 * contrôle dont elle dépend est réussi dans le rapport. Aucune empreinte.
 * Chaque ligne : { nom, cle, valeurs, instants }.
 */
function lignesEnResume(rapport, controles, code) {
  const lignes = [];
  if ((code !== 0 && code !== 3) || controles === null || rapport === null || typeof rapport !== "object") return lignes;
  const reussi = (nom) => controles.some((c) => c.numero === CONTROLE_DU_RESUME[nom] && c.statut === "reussi");
  const objet = (x) => (x !== null && typeof x === "object" && !Array.isArray(x) ? x : null);
  const entier = (x) => Number.isSafeInteger(x) && x >= 0;
  const evenement = objet(rapport.event);
  if (reussi("action") && evenement !== null && entier(evenement.seq)) lignes.push({ nom: "action", cle: "resume_action", valeurs: { seq: String(evenement.seq) }, instants: {} });
  // Le nom de l'outil de l'action, tel que le rapport le donne : recopié sans traduction, et seulement s'il
  // s'affiche tel quel (une chaîne non vide, sans caractère que la page rendrait visible ou qui changerait la ligne).
  if (reussi("outil") && evenement !== null && typeof evenement.tool === "string" && NOM_OUTIL_TEL_QUEL.test(evenement.tool)) lignes.push({ nom: "outil", cle: "resume_outil", valeurs: { outil: evenement.tool }, instants: {} });
  const periode = objet(rapport.period);
  if (reussi("periode") && periode !== null) {
    const debut = instantDeSecondes(periode.period_start);
    const fin = instantDeSecondes(periode.period_end);
    if (debut !== null && fin !== null) lignes.push({ nom: "periode", cle: "resume_periode", valeurs: {}, instants: { debut, fin } });
  }
  const faits = objet(rapport.facts) ?? {};
  const a = objet(faits.approval);
  if (reussi("approbation") && a !== null && typeof a.decision === "string" && Object.hasOwn(GABARITS_DECISION, a.decision) && Array.isArray(a.approvers) && a.approvers.every((x) => typeof x === "string") && entier(a.required) && entier(a.size)) {
    lignes.push({ nom: "approbation", cle: GABARITS_DECISION[a.decision], valeurs: { n: String(a.approvers.length), requis: String(a.required), taille: String(a.size) }, instants: {} });
  }
  const jeton = objet(faits.timestamp);
  if (reussi("limite_autorite") && jeton !== null) {
    const limite = instantDeTexte(jeton.upper_bound);
    if (limite !== null) lignes.push({ nom: "limite_autorite", cle: "resume_limite_autorite", valeurs: {}, instants: { limite } });
  }
  // Le rapport ne donne pas d'instant « au plus tard » pour la preuve par la chaîne Bitcoin : la ligne renvoie au texte exact.
  if (reussi("limite_bitcoin") && objet(faits.bitcoin) !== null) lignes.push({ nom: "limite_bitcoin", cle: "resume_limite_bitcoin", valeurs: {}, instants: {} });
  return lignes;
}

// --- Résumé tiré du rapport JSON ---------------------------------------------

/**
 * Les huit contrôles du rapport JSON (CT-6 EX-8.7, `controls`), ou null si
 * la liste ne se lit pas exactement : huit objets numérotés de 1 à 8, un
 * statut de CT-6 EX-6.1, une raison de CT-6 §6.2 pour un contrôle non exécuté
 * et aucune pour les autres. Null aussi si la liste contredit le code de
 * retour (un contrôle en échec, ou non exécuté pour un prérequis en échec,
 * sous un code 0 ou 3). La page ne corrige ni ne complète rien : une liste
 * qu'elle ne lit pas n'est pas résumée, et le rapport complet reste affiché.
 */
function lireControles(rapport, code) {
  const liste = rapport.controls;
  if (!Array.isArray(liste) || liste.length !== 8) return null;
  const controles = [];
  for (let i = 0; i < 8; i++) {
    const c = liste[i];
    if (c === null || typeof c !== "object" || c.number !== i + 1 || !STATUTS_CONNUS.includes(c.status)) return null;
    if (c.status === "non_execute" ? typeof c.reason !== "string" : c.reason !== null && c.reason !== undefined) return null;
    if ((code === 0 || code === 3) && (c.status === "echoue" || c.reason === "prerequis_en_echec")) return null;
    controles.push({ numero: c.number, statut: c.status, raison: c.status === "non_execute" ? c.reason : null, resume: typeof c.summary === "string" ? c.summary : "", verifications: listeDeChaines(c.checks) ?? [] });
  }
  return controles;
}

/** Liste de chaînes du rapport, ou null si ce n'en est pas une. */
function listeDeChaines(v) {
  return Array.isArray(v) && v.every((x) => typeof x === "string") ? v : null;
}

/**
 * Ce que la page résume d'un rapport de code 0, 1 ou 3, tiré du seul rapport
 * JSON : contrôles (ou null), contrôles exigés (`inputs.required_controls`,
 * ou null), vérifications en échec et bloquantes (EX-6.7), avertissements
 * (`warnings`, ou null s'ils ne se lisent pas), ce que le vérificateur dit de
 * chaque vérification en échec (`checks`, champ `detail`), et les lignes du
 * bloc « En résumé ».
 */
function resumer(rapport, code) {
  const exiges = rapport.inputs && Array.isArray(rapport.inputs.required_controls) && rapport.inputs.required_controls.every((n) => Number.isInteger(n) && n >= 1 && n <= 8) ? rapport.inputs.required_controls : null;
  let avertissements = [];
  if (rapport.warnings !== undefined) {
    const w = rapport.warnings;
    const lisibles = Array.isArray(w) && w.every((a) => a !== null && typeof a === "object" && typeof a.id === "string" && typeof a.detail === "string" && (a.check === null || a.check === undefined || typeof a.check === "string"));
    avertissements = lisibles ? w.map((a) => ({ id: a.id, verification: typeof a.check === "string" ? a.check : null, detail: a.detail })) : null;
  }
  const controles = lireControles(rapport, code);
  const echecs = listeDeChaines(rapport.failed_checks);
  // Ce que le vérificateur dit de chaque vérification en échec : son champ `detail`, tel quel, quand il se lit.
  const dits = [];
  for (const id of echecs ?? []) {
    const v = Array.isArray(rapport.checks) ? rapport.checks.find((x) => x !== null && typeof x === "object" && x.id === id) : undefined;
    if (v && v.status === "echoue" && typeof v.detail === "string" && v.detail !== "") dits.push({ id, detail: v.detail });
  }
  return {
    controles,
    exiges,
    echecs,
    dits,
    bloquantes: listeDeChaines(rapport.blocking_unexecuted),
    avertissements,
    enResume: lignesEnResume(rapport, controles, code),
  };
}

/** Numéros des contrôles que le rapport ne dit pas réussis. */
function controlesNonReussis(controles) {
  return controles.filter((c) => c.statut !== "reussi").map((c) => c.numero);
}

// --- Affichage du résultat ----------------------------------------------------

function blocNoms(noms) {
  const div = element("div", "noms nt-pile");
  div.append(element("p", "nt-petit", libelle("noms_choisis")));
  const ul = element("ul", "pv-liste nt-petit");
  const d = noms.dossier;
  ul.append(element("li", null, libelle(d.genre === "repertoire" ? "nom_dossier_repertoire" : "nom_dossier_archive", { nom: d.nom })));
  if (noms.ancres !== null) ul.append(element("li", null, libelle("nom_ancres", { nom: noms.ancres })));
  if (noms.entetes !== null) ul.append(element("li", null, libelle("nom_entetes", { nom: noms.entetes })));
  div.append(ul);
  return div;
}

/** Texte d'un refus d'EX-18.7 : raison (r_…), type d'entrée (type_…) et défaut (i_…) traduits. */
function texteRefus(raison, parametres) {
  const p = { ...parametres };
  if (p.type !== undefined) p.type = libelle(p.type, { type: p.code ?? "?" });
  if (p.detail !== undefined) p.detail = libelle(p.detail, p);
  return libelle("refus_archive", { raison: libelle(raison, p) });
}

/** Paragraphe de la cause d'une vérification non faite : une phrase de la page, ou le texte que le travailleur donne (valeur). */
function paragrapheCause(cause) {
  const p = element("p", "pv-verdict-fort cause");
  if (cause.texte !== undefined) return composer(p, "cause", { cause: cause.texte });
  return composer(p, "cause", {}, { cause: composer(element("span"), cause.cle, cause.parametres) });
}

/**
 * Raison d'une non-exécution en clair, d'après ce que la personne a ajouté à l'étape 2 (`noms`), puis son code exact
 * entre parenthèses (CT-6 §6.2).
 */
function elementRaison(code, numero, noms) {
  const cle = cleRaisonCourante(RAISONS_CONNUES.includes(code) ? code : null, numero, noms !== null && noms.ancres !== null, noms !== null && noms.entetes !== null);
  return elementLibelle("span", "pv-controle-raison", "raison", { code }, { raison: libelle(cle) });
}

/**
 * Bloc replié : titre, note, corps. Son état (ouvert ou non) est gardé d'un
 * affichage à l'autre de la même vérification (changement de langue).
 */
function blocReplie(id, titre, note) {
  const d = element("details", "nt-detail pv-detail");
  d.id = id;
  d.open = etat.deplies.has(id);
  const s = element("summary");
  s.append(element("span", null, titre));
  if (note) s.append(element("span", "nt-detail-note pv-detail-note", note));
  const corps = element("div", "nt-detail-corps");
  d.append(s, corps);
  d.addEventListener("toggle", () => {
    if (d.open) etat.deplies.add(id);
    else etat.deplies.delete(id);
  });
  return { bloc: d, corps };
}

/** Bouton qui copie le texte d'un élément, tel quel ; rien si le navigateur ne l'offre pas. */
function boutonCopier(pre, cle = "copier") {
  const presse = globalThis.navigator && globalThis.navigator.clipboard;
  if (!presse || typeof presse.writeText !== "function") return null;
  const ligne = element("div", "pv-copie");
  const bouton = element("button", "nt-bouton nt-bouton-petit", libelle(cle));
  bouton.type = "button";
  const suite = element("span", "nt-petit nt-attenue");
  suite.setAttribute("role", "status");
  bouton.addEventListener("click", () => {
    presse.writeText(pre.textContent).then(
      () => {
        suite.textContent = libelle("copie_faite");
      },
      () => {
        suite.textContent = libelle("copie_impossible");
      },
    );
  });
  ligne.append(bouton, suite);
  return ligne;
}

/** Bloc replié « Fichiers choisis », quand aucune ligne de commande n'est à montrer. */
function blocFichiers(noms) {
  const { bloc, corps } = blocReplie("detail-fichiers", libelle("titre_fichiers"), null);
  corps.append(blocNoms(noms));
  return bloc;
}

/**
 * Texte préformaté, tel quel (EX-18.9), avec son bouton de copie. Un texte
 * long défile dans son cadre, que le clavier atteint.
 */
function blocPre(corps, pre) {
  exact(pre).classList.add("pv-pre");
  pre.tabIndex = 0;
  pre.setAttribute("role", "group");
  pre.setAttribute("aria-label", libelle("texte_defilant"));
  const copie = boutonCopier(pre);
  if (copie) corps.append(copie);
  corps.append(pre);
}

/** Grand verdict : un signe, un mot, une phrase ; `variante` : valide, non-valide, incomplet ou null (neutre). */
function blocVerdict(variante, nomIcone) {
  const s = element("section", variante ? `nt-verdict nt-verdict-${variante}` : "nt-verdict");
  s.id = "verdict";
  const signe = element("div", "nt-verdict-signe");
  signe.append(icone(nomIcone));
  s.append(signe);
  return s;
}

/** Phrase en langage courant sous le mot du verdict. */
function phraseCourante(cle) {
  const p = element("p", "nt-verdict-phrase pv-courante", libelle(cle));
  p.id = "phrase-courante";
  return p;
}

/** Ligne d'alerte sous le verdict : ce que le verdict ne couvre pas. `valeurs` : paramètres venus du rapport. */
function ligneBorne(id, cle, valeurs = {}) {
  const p = element("p", "pv-verdict-borne");
  p.id = id;
  p.append(icone("alerte"), elementLibelle("span", null, cle, valeurs));
  return p;
}

/** Carte à titre : une rubrique du résultat. */
function carte(id, cleTitre) {
  const section = element("section", "nt-carte");
  section.id = id;
  const titre = element("div", "nt-carte-titre");
  titre.append(element("h3", null, libelle(cleTitre)));
  section.append(titre);
  return { section, titre };
}

/**
 * Copie d'une sélection faite dans l'énoncé : le presse-papiers reçoit le
 * texte choisi tel qu'il est dans l'énoncé, sans les sauts de ligne que le
 * navigateur ajouterait entre deux membres de phrase affichés l'un sous l'autre.
 */
function copierSelectionExacte(ev) {
  const selection = typeof globalThis.getSelection === "function" ? globalThis.getSelection() : null;
  if (!selection || selection.rangeCount !== 1 || !ev.clipboardData) return;
  const plage = selection.getRangeAt(0);
  const p = ev.currentTarget;
  if (!p.contains(plage.startContainer) || !p.contains(plage.endContainer)) return;
  ev.clipboardData.setData("text/plain", plage.cloneContents().textContent);
  ev.preventDefault();
}

/**
 * Énoncé du vérificateur, tel quel : chaque membre de phrase (coupure après
 * « ; ») est un bloc à part, et les empreintes hexadécimales sont en chasse
 * fixe, sans qu'un caractère change ; le texte de l'élément est l'énoncé.
 */
function paragrapheEnonce(id, langue, texte) {
  const p = exact(element("p", "enonce"));
  p.id = id;
  p.lang = langue;
  for (const membre of membresEnonce(String(texte))) {
    const bloc = element("span", "pv-membre");
    for (const morceau of membre.split(/(0x[0-9a-f]{16,})/)) {
      if (morceau === "") continue;
      if (/^0x[0-9a-f]{16,}$/.test(morceau)) bloc.append(element("span", "pv-hex", morceau));
      else bloc.append(document.createTextNode(neutraliser(morceau)));
    }
    p.append(bloc);
  }
  p.addEventListener("copy", copierSelectionExacte);
  return p;
}

const PASTILLES_STATUT = {
  reussi: ["succes", "coche", "statut_reussi"],
  echoue: ["refus", "croix", "statut_echoue"],
  non_execute: ["", "tiret", "statut_non_execute"],
};
// Contrôle réussi auquel le rapport rattache un avertissement.
const PASTILLE_RESERVE = ["attente", "alerte", "statut_reussi_reserve"];

/** Liste en mots : éléments joints par le libellé `cleSep`, le dernier par `cleDernier`. */
function listeEnMots(elements, cleSep, cleDernier) {
  if (elements.length <= 1) return elements.join("");
  return `${elements.slice(0, -1).join(libelle(cleSep))}${libelle(cleDernier)}${elements[elements.length - 1]}`;
}

/** Ce que le vérificateur dit d'une vérification en échec, tel quel, son identifiant à la fin entre parenthèses. */
function ligneEchec(dit) {
  const e = elementLibelle("span", "pv-controle-dit", "dit_echec", { detail: dit.detail, id: dit.id });
  e.dataset.verification = dit.id;
  return e;
}

/** Jour et heure en toutes lettres, d'après le gabarit `instant` de la langue de la page. */
function instantEnLettres(i) {
  const deux = (n) => String(n).padStart(2, "0");
  return libelle("instant", { jour: i.jour === 1 ? libelle("jour_premier") : String(i.jour), mois: libelle(`mois_${i.mois}`), annee: String(i.annee), heure: deux(i.heure), minute: deux(i.minute), seconde: deux(i.seconde) });
}

/**
 * Carte « En résumé », avant le texte exact : les lignes de lignesEnResume,
 * chaque valeur venue du rapport marquée comme telle, puis la phrase qui dit
 * que seul le texte exact fait foi. Rien si aucune ligne.
 */
function carteEnResume(lignes) {
  if (lignes.length === 0) return null;
  const { section } = carte("en-resume", "titre_en_resume");
  const ul = element("ul", "pv-liste pv-en-resume");
  for (const l of lignes) {
    const valeurs = { ...l.valeurs };
    for (const [nom, i] of Object.entries(l.instants)) valeurs[nom] = instantEnLettres(i);
    const li = elementLibelle("li", null, l.cle, valeurs);
    li.dataset.ligne = l.nom;
    // Le nom d'un outil est un identifiant : en chasse fixe, pour qu'il se lise caractère par caractère.
    if (l.nom === "outil") for (const v of li.querySelectorAll(".pv-valeur")) v.classList.add("pv-identifiant");
    ul.append(li);
  }
  const fin = element("p", "pv-intro", libelle("resume_fin"));
  fin.id = "resume-fin";
  section.append(ul, fin);
  return section;
}

/**
 * Carte des huit contrôles, une ligne chacun : l'état que le rapport lui
 * donne, son nom courant, ce qu'il sert à prouver. Sous un contrôle non fait,
 * sa raison en clair et son code ; sous un contrôle échoué, ce que le
 * vérificateur en dit. Le résumé que le vérificateur donne de chaque contrôle
 * est repris tel quel dans un bloc replié de la carte.
 */
function carteControles(resume, noms) {
  const { section, titre } = carte("controles", "titre_controles");
  const compte = (statut) => resume.controles.filter((c) => c.statut === statut).length;
  const reserves = new Map(resume.controles.map((c) => [c.numero, c.statut === "reussi" ? reservesDuControle(c.numero, resume.controles, resume.avertissements) : []]));
  const avecReserve = [...reserves.values()].filter((ids) => ids.length > 0).length;
  const parties = [avecReserve === 0 ? libelle("compte_reussis", { n: compte("reussi") }) : libelle("compte_reussis_reserve", { n: compte("reussi"), m: avecReserve })];
  if (compte("non_execute") > 0) parties.push(libelle("compte_non_executes", { n: compte("non_execute") }));
  if (compte("echoue") > 0) parties.push(libelle("compte_echoues", { n: compte("echoue") }));
  const note = element("span", "nt-carte-note", parties.join(" · "));
  note.id = "compte-controles";
  titre.append(note);
  // La pastille « réussi, avec réserve » est plus longue : la colonne des états s'élargit pour toute la liste.
  const ul = element("ul", avecReserve > 0 ? "nt-controles pv-controles-reserve" : "nt-controles");
  const resumes = element("div", "pv-resumes");
  for (const c of resume.controles) {
    const li = element("li", "nt-controle pv-controle");
    li.dataset.numero = String(c.numero);
    li.dataset.statut = c.statut;
    // Un contrôle réussi auquel le rapport rattache un avertissement n'est pas montré réussi sans plus : sa pastille le dit.
    const ids = reserves.get(c.numero);
    const [ton, nomIcone, cle] = ids.length > 0 ? PASTILLE_RESERVE : PASTILLES_STATUT[c.statut];
    if (ids.length > 0) li.dataset.reserves = ids.join(" ");
    const marque = element("span");
    marque.append(pastille(ton, nomIcone, libelle(cle)));
    const texte = element("div", "nt-controle-texte");
    const ligne = element("div", "pv-controle-ligne");
    const nom = `${c.numero}. ${libelle(`controle_${c.numero}`)}`;
    ligne.append(element("span", "nt-controle-titre", nom));
    if (resume.exiges !== null && resume.exiges.includes(c.numero)) ligne.append(pastille("info", "alerte", libelle("controle_exige")));
    ligne.append(element("span", "pv-controle-prouve", libelle(`prouve_${c.numero}`)));
    texte.append(ligne);
    if (c.statut === "non_execute") texte.append(elementRaison(c.raison, c.numero, noms));
    if (ids.length > 0) {
      const renvoi = element("a", null, libelle("renvoi_reserves"));
      renvoi.href = "#avertissements";
      texte.append(elementLibelle("span", "pv-controle-reserve", "controle_reserve", { ids: ids.join(", ") }, { renvoi }));
    }
    if (c.statut === "echoue") {
      texte.append(element("span", "pv-controle-echec", libelle("echec_suite")));
      // Ce que le vérificateur dit de ce qui a échoué, d'abord ; l'identifiant de la vérification à la fin, entre parenthèses.
      const dits = resume.dits.filter((d) => c.verifications.includes(d.id));
      for (const d of dits) texte.append(ligneEchec(d));
      if (dits.length === 0 && c.resume !== "") texte.append(elementLibelle("span", "pv-controle-dit", "dit_verificateur", { resume: c.resume }));
    }
    li.append(marque, texte);
    ul.append(li);
    // Dans le bloc replié : ce que le contrôle sert à prouver, en entier, puis le résumé du vérificateur, tel quel.
    const detail = element("div", "pv-resume");
    const dit = element("span", "pv-resume-exact", c.resume);
    dit.dataset.numero = String(c.numero);
    detail.append(element("p", "pv-resume-titre", nom), element("p", null, libelle(`prouve_long_${c.numero}`)), ligneExacte("texte_exact", dit));
    resumes.append(detail);
  }
  section.append(ul);
  const { bloc, corps } = blocReplie("detail-controles", libelle("titre_detail_controles"), null);
  corps.append(resumes);
  section.append(bloc);
  return section;
}

/**
 * Bandeau des réserves : chaque avertissement du rapport JSON, en langage
 * courant quand son identifiant est dans la table, puis son texte exact avec
 * son identifiant ; ensuite la sortie d'erreur si elle n'est pas vide.
 */
function bandeauAvertissements(v) {
  const avertissements = v.resume ? v.resume.avertissements : [];
  if (v.erreur === "" && avertissements !== null && avertissements.length === 0) return null;
  const bandeau = element("div", "nt-bandeau nt-bandeau-avertissement");
  bandeau.id = "avertissements";
  bandeau.append(icone("alerte"));
  const texte = element("div", "nt-bandeau-texte");
  if (avertissements === null) texte.append(element("p", "nt-bandeau-titre", libelle("avertissements_illisibles")));
  else if (avertissements.length > 0) {
    texte.append(element("p", "nt-bandeau-titre", libelle("titre_avertissements")));
    const ul = element("ul", "pv-liste pv-reserves");
    // Une réserve signalée plusieurs fois sous le même identifiant n'est dite qu'une fois en langage courant ; chacun de ses textes exacts suit.
    const table = TABLES_LIBELLES[etat.langue];
    for (const g of grouperAvertissements(avertissements, (id) => cleAvertissement(id, table) !== null)) {
      const li = element("li", "pv-reserve");
      li.dataset.id = g.id;
      li.dataset.fois = String(g.elements.length);
      const cle = cleAvertissement(g.id, table);
      if (cle !== null) {
        const courante = element("p", "pv-reserve-courante", libelle(cle));
        if (g.elements.length > 1) courante.append(document.createTextNode(" "), elementLibelle("span", "pv-reserve-fois", "reserve_fois", { n: String(g.elements.length) }));
        li.append(courante);
      }
      for (const a of g.elements) {
        const brut = a.verification === null ? libelle("avertissement_sans_verification", { detail: a.detail, id: a.id }) : libelle("avertissement", { detail: a.detail, id: a.id, check: a.verification });
        li.append(ligneExacte("texte_exact", element("span", "pv-reserve-exacte", brut)));
      }
      ul.append(li);
    }
    texte.append(ul);
  }
  if (v.erreur !== "") {
    texte.append(element("p", "nt-bandeau-titre", libelle("titre_sortie_erreur")));
    const err = exact(element("pre", "sortie-erreur nt-pre", v.erreur));
    err.id = "sortie-erreur";
    texte.append(err);
  }
  bandeau.append(texte);
  return bandeau;
}

/** Carte « Ce que ce résultat ne dit pas » : lignes fixes du code de retour ; rien hors table. */
function carteLimites(code) {
  if (!Object.hasOwn(LIMITES, code)) return null;
  const { section } = carte("limites", "titre_limites");
  section.append(element("p", "pv-intro", libelle("intro_limites")));
  const ul = element("ul", "pv-liste");
  for (const cle of LIMITES[code]) ul.append(element("li", null, libelle(cle)));
  section.append(ul);
  return section;
}

/** Carte « Et maintenant ? » : lignes fixes du code de retour, d'un refus ou d'une vérification non faite ; « Imprimer » après un rapport. */
function carteSuite(genre, imprimer) {
  if (!Object.hasOwn(SUITES, genre)) return null;
  const { section } = carte("suite", "titre_suite");
  const ul = element("ul", "pv-liste");
  for (const cle of SUITES[genre]) ul.append(element("li", null, libelle(cle)));
  section.append(ul);
  if (imprimer && typeof globalThis.print === "function") {
    const actions = element("div", "nt-actions pv-imprimer");
    const bouton = element("button", "nt-bouton");
    bouton.type = "button";
    bouton.id = "imprimer";
    bouton.append(icone("imprimante"), element("span", null, libelle("imprimer")));
    bouton.addEventListener("click", () => globalThis.print());
    actions.append(bouton);
    section.append(actions);
  }
  return section;
}

/** Bloc replié « Refaire la vérification avec le programme autonome » : fichiers choisis et ligne de commande équivalente. */
function blocCommande(v) {
  const { bloc, corps } = blocReplie("detail-commande", libelle("titre_commande"), libelle("note_commande"));
  if (v.noms) corps.append(blocNoms(v.noms));
  corps.append(element("p", "nt-petit", libelle("commande")));
  blocPre(corps, element("pre", "commande nt-pre", v.commandes.join("\n")));
  corps.append(element("p", "nt-petit nt-attenue", libelle("nom_interne")));
  return bloc;
}

/**
 * Rubrique « Pour les spécialistes » : un titre, une phrase (`cleIntro`, ou aucune), un texte exact affiché en tête
 * hors de tout bloc replié (`tete` : la formule exacte du vérificateur, ou la mention fixée pour un refus), puis les
 * blocs repliés donnés.
 */
function rubriqueSpecialistes(blocs, { cleIntro = "intro_specialistes", tete = null } = {}) {
  const section = element("section", "nt-pile pv-specialistes");
  section.id = "specialistes";
  section.append(element("h3", null, libelle("titre_specialistes")));
  if (cleIntro !== null) section.append(element("p", "nt-aide", libelle(cleIntro)));
  if (tete !== null) section.append(tete);
  section.append(...blocs);
  return section;
}

function afficherVue() {
  const contenu = $("resultat-contenu");
  const formulaire = $("formulaire");
  // Le bandeau de confiance sort du résultat avant que celui-ci soit réécrit : il n'est jamais détruit.
  if (etat.confiance && contenu && formulaire && etat.confiance.parentElement === contenu) formulaire.before(etat.confiance);
  ecrireVue();
  if (etat.vue !== null && etat.vue.genre !== "en_cours") etat.confianceDessous = true;
  placerConfiance();
}

function ecrireVue() {
  const section = $("resultat");
  const contenu = $("resultat-contenu");
  if (!section || !contenu) return;
  afficherReduction();
  contenu.replaceChildren();
  const v = etat.vue;
  if (v === null) {
    section.hidden = true;
    return;
  }
  section.hidden = false;
  if (v.genre === "en_cours") {
    const bandeau = element("div", "nt-bandeau");
    bandeau.append(icone("sablier"));
    const texte = element("div", "nt-bandeau-texte");
    texte.append(element("p", "en-cours", libelle("en_cours")));
    bandeau.append(texte);
    contenu.append(bandeau);
    return;
  }
  if (v.genre === "refus") {
    // EX-18.7 : la raison, « aucun rapport » et aucun code. La raison en langage courant précède la raison exacte.
    const verdict = blocVerdict(null, "alerte");
    // Titre courant du refus, selon ce qui est refusé : un fichier (dossier compressé ou pièce complémentaire), un
    // dossier de fichiers, ou un dépôt que la page n'a pas pu prendre.
    const piece = v.vise === "ancres" || v.vise === "entetes";
    const cleTitre = !v.noms ? "titre_refus_choix" : !piece && v.noms.dossier.genre === "repertoire" ? "titre_refus_repertoire" : "titre_refus";
    const titreRefus = element("p", "nt-verdict-mot pv-mot", libelle(cleTitre));
    titreRefus.id = "refus-titre";
    verdict.append(titreRefus, phraseCourante("phrase_refus"));
    const suite = element("div", "pv-verdict-suite");
    const cle = cleRefusCourant(v.raison, TABLES_LIBELLES[etat.langue]);
    if (cle !== null) {
      const courant = element("p", "pv-verdict-fort", libelle(cle));
      courant.id = "refus-courant";
      suite.append(courant);
    }
    suite.append(ligneExacte("raison_exacte", element("span", "alerte", texteRefus(v.raison, v.parametres))));
    verdict.append(suite);
    contenu.append(verdict, carteSuite(piece ? "refus_piece" : "refus", false));
    // EX-18.7 : la mention fixée « aucun rapport » reste affichée, hors de tout bloc replié, en tête des spécialistes.
    const mention = ligneExacte("mention_refus", element("span", "aucun-rapport", libelle("aucun_rapport")));
    mention.id = "mention-refus";
    contenu.append(rubriqueSpecialistes(v.noms ? [blocFichiers(v.noms)] : [], { cleIntro: null, tete: mention }));
    return;
  }
  if (v.genre === "non_faite") {
    // EX-18.9 : « vérification non faite » avec la cause, aucun rapport, aucun énoncé.
    const verdict = blocVerdict(null, "question");
    verdict.append(element("p", "nt-verdict-mot pv-mot alerte non-faite", libelle("non_faite")), phraseCourante("phrase_non_faite"));
    const suite = element("div", "pv-verdict-suite");
    suite.append(paragrapheCause(v.cause));
    verdict.append(suite);
    contenu.append(verdict, carteSuite("non_faite", false));
    // Aucun rapport : la rubrique ne porte que ses blocs, sans la phrase qui annonce les rapports.
    if (v.commandes) contenu.append(rubriqueSpecialistes([blocCommande(v)], { cleIntro: null }));
    else if (v.noms) contenu.append(rubriqueSpecialistes([blocFichiers(v.noms)], { cleIntro: null }));
    return;
  }

  // Verdict : le mot suit le code de retour, la phrase en langage courant aussi ; la phrase du code (table de CT-6
  // §8.3) reste entière dessous, en petit.
  const variantes = { 0: ["valide", "bouclier"], 1: ["non-valide", "croix"], 2: [null, "question"], 3: ["incomplet", "alerte"] };
  // La présentation ne peut que restreindre ce que le code dit : sous le code 0, la teinte pleine et son signe ne
  // restent que si le rapport, lu exactement, donne huit contrôles réussis et aucun avertissement.
  const presentation = presentationVerdict(v.code, v.code === 2 ? null : v.resume.controles, v.code === 2 ? null : v.resume.avertissements);
  const [variante, signe] = presentation.teinte === "pleine" ? variantes[v.code] : [null, presentation.teinte === "reserve" ? "alerte" : "question"];
  const verdict = blocVerdict(variante, signe);
  if (presentation.teinte !== "pleine") verdict.classList.add(`pv-verdict-${presentation.teinte}`);
  verdict.dataset.code = String(v.code);
  const titre = element("p", "nt-verdict-mot pv-mot");
  titre.id = "verdict-titre";
  const mot = element("span", null, libelle(`mot_${v.code}`));
  mot.id = "verdict-mot";
  titre.append(mot);
  if (presentation.mention !== null) {
    const mention = element("span", "pv-mention", libelle(presentation.mention));
    mention.id = "verdict-mention";
    titre.append(mention);
    // Le mot et sa mention se lisent d'un seul tenant, à la même taille.
    titre.classList.add("pv-titre-mention");
  }
  verdict.append(titre);
  // Juste sous le titre : ce que les contrôles non réussis laissent sans preuve, en mots.
  if (v.code === 0 && presentation.teinte === "reserve") {
    const cles = clesNonProuve(v.resume.controles);
    if (cles.length > 0) {
      const p = element("p", "pv-non-prouve", libelle(cles.length === 1 ? "non_prouve_un" : "non_prouve_plusieurs", { liste: listeEnMots(cles.map((cle) => libelle(cle)), "non_prouve_sep", "non_prouve_dernier") }));
      p.id = "non-prouve";
      verdict.append(p);
    }
  }
  const courante = clePhraseCourante(v.code);
  if (courante !== null) verdict.append(phraseCourante(courante));
  const suite = element("div", "pv-verdict-suite");
  suite.id = "verdict-suite";
  verdict.append(suite);
  contenu.append(verdict);

  if (v.code === 2) {
    const a = element("p", "aucune-affirmation pv-verdict-fort", libelle("aucune_affirmation"));
    a.id = "aucune-affirmation";
    suite.append(a);
    // La pièce en cause, en clair, quand le rapport d'erreur la nomme (son champ `kind`).
    if (v.pieceEnCause !== null) {
      const piece = element("p", "pv-verdict-fort", libelle(v.pieceEnCause));
      piece.id = "piece-en-cause";
      suite.append(piece);
    }
    const m = element("span", "message-erreur", v.messageErreur);
    m.id = "message-erreur";
    suite.append(ligneExacte("message_erreur", m));
  } else {
    const r = v.resume;
    // Réserves : la ligne paraît dès que le rapport porte un avertissement, sous un verdict qui affirme quelque chose.
    if ((v.code === 0 || v.code === 3) && aDesReserves(r.avertissements)) suite.append(ligneBorne("reserves", "reserves"));
    if (r.controles === null) suite.append(ligneBorne("resume-indisponible", "resume_indisponible"));
    else {
      const nonReussis = controlesNonReussis(r.controles);
      if (v.code === 0 && nonReussis.length === 0) {
        const avecReserve = r.controles.filter((c) => reservesDuControle(c.numero, r.controles, r.avertissements).length > 0).length;
        const p = avecReserve === 0 ? element("p", "pv-verdict-fort", libelle("tous_reussis")) : elementLibelle("p", "pv-verdict-fort", "tous_reussis_reserve", { n: String(avecReserve) });
        p.id = "tous-reussis";
        suite.append(p);
      } else if (v.code === 0) suite.append(ligneBorne("verdict-borne", "valide_borne", { liste: nonReussis.join(", ") }));
      else if (v.code === 3 && r.exiges !== null) {
        suite.append(ligneBorne("exiges-non-reussis", "exiges_non_reussis", { liste: r.exiges.filter((n) => nonReussis.includes(n)).join(", ") }));
      }
    }
    if (v.code === 1) {
      // Ce que le vérificateur dit d'une vérification en échec qu'aucun contrôle ne porte : les autres sont dites sur la ligne de leur contrôle.
      for (const d of r.dits) {
        if (r.controles !== null && r.controles.some((c) => c.statut === "echoue" && c.verifications.includes(d.id))) continue;
        suite.append(ligneEchec(d));
      }
      if (r.echecs !== null && r.echecs.length > 0) suite.append(elementLibelle("p", "pv-references", "verifications_echec", { liste: r.echecs.join(", ") }));
      if (r.bloquantes !== null && r.bloquantes.length > 0) suite.append(elementLibelle("p", "pv-references", "verifications_bloquantes", { liste: r.bloquantes.join(", ") }));
    }
  }
  // Le code et son sens (table de CT-6 §8.3), entiers et jamais repliés, en tête de « Pour les spécialistes ».
  const code = element("span", `code code-${v.code}`, libelle("code", { code: v.code, sens: libelle(`code_${v.code}`) }));
  code.id = "code";
  const formule = ligneExacte("formule_exacte", code);
  formule.id = "formule-exacte";

  // Les réserves viennent aussitôt sous le verdict : elles ne sont jamais repliées.
  const avertissements = bandeauAvertissements(v);
  if (avertissements) contenu.append(avertissements);

  if (v.code !== 2) {
    if (v.resume.controles !== null) contenu.append(carteControles(v.resume, v.noms));
    const enResume = carteEnResume(v.resume.enResume);
    if (enResume) contenu.append(enResume);
    // Énoncé dans la langue de la page, tel quel ; l'autre langue dans un bloc replié de la même carte.
    const { section: enonce } = carte("enonce", v.code === 1 ? "titre_enonce_invalide" : "titre_enonce");
    enonce.append(element("p", "pv-intro", libelle(v.code === 1 ? "intro_enonce_invalide" : "intro_enonce")));
    // L'explication des empreintes ne paraît que si l'énoncé affiché en porte.
    if (/0x[0-9a-f]{16,}/.test(etat.langue === "en" ? v.enonceEn : v.enonceFr)) enonce.append(element("p", "pv-intro", libelle("intro_empreintes")));
    const fr = paragrapheEnonce("enonce-fr", "fr", v.enonceFr);
    const en = paragrapheEnonce("enonce-en", "en", v.enonceEn);
    const [principal, autre, cleAutre] = etat.langue === "en" ? [en, fr, "enonce_fr"] : [fr, en, "enonce_en"];
    enonce.append(principal);
    const copie = boutonCopier(principal, "copier_enonce");
    if (copie) enonce.append(copie);
    const { bloc, corps } = blocReplie("detail-enonce-autre", libelle(cleAutre), null);
    bloc.classList.add("pv-enonce-autre");
    corps.append(autre);
    enonce.append(bloc);
    contenu.append(enonce);
  }
  // « Ce que ce résultat ne dit pas » et « Et maintenant ? » : côte à côte quand la place le permet.
  const duo = element("div", "pv-duo");
  const limites = v.code === 2 ? null : carteLimites(v.code);
  if (limites) duo.append(limites);
  const suiteCarte = carteSuite(v.code, true);
  if (suiteCarte) duo.append(suiteCarte);
  contenu.append(duo);

  // Pour les spécialistes : rapport complet, rapport JSON, ligne de commande, tels quels, dans des blocs repliés.
  const blocs = [];
  if (v.lisible !== "" || v.erreur === "") {
    const { bloc, corps } = blocReplie("detail-rapport", libelle("rapport_lisible"), libelle("note_rapport"));
    if (v.lisible !== "") {
      const pre = element("pre", "rapport nt-pre nt-pre-defile", v.lisible);
      pre.id = "rapport-lisible";
      blocPre(corps, pre);
    }
    if (v.erreur === "") {
      corps.append(element("p", "nt-petit", libelle("sortie_erreur")));
      const err = element("pre", "sortie-erreur nt-pre vide", libelle("sortie_erreur_vide"));
      err.id = "sortie-erreur";
      corps.append(err);
    }
    blocs.push(bloc);
  }
  const json = blocReplie("detail-json", libelle("rapport_json"), libelle("note_rapport_json"));
  const preJson = element("pre", "rapport-json nt-pre nt-pre-defile", v.json);
  preJson.id = "rapport-json";
  blocPre(json.corps, preJson);
  blocs.push(json.bloc, blocCommande(v));
  contenu.append(rubriqueSpecialistes(blocs, { tete: formule }));
}

/**
 * Amène `e` en haut de l'écran, sous la barre haute quand elle reste collée en haut : la hauteur de la barre est
 * lue à chaque fois (elle change avec la police et la largeur), et l'écart sous elle est la marge de défilement
 * que la feuille de style donne à `e`.
 */
function montrerSousLaBarre(e) {
  if (!e || typeof globalThis.scrollTo !== "function") return;
  const barre = document.querySelector(".nt-barre");
  const position = barre ? getComputedStyle(barre).position : "static";
  const dessous = position === "sticky" || position === "fixed" ? barre.getBoundingClientRect().height : 0;
  const marge = parseFloat(getComputedStyle(e).scrollMarginTop) || 0;
  globalThis.scrollTo(0, Math.max(0, e.getBoundingClientRect().top + globalThis.scrollY - dessous - marge));
}

/** Après une vérification, le résultat vient à l'écran. */
function montrerResultat() {
  const section = $("resultat");
  if (section && !section.hidden) montrerSousLaBarre(section);
}

// --- Liaisons -----------------------------------------------------------------

function lier() {
  $("autre-langue").addEventListener("click", () => {
    etat.langue = etat.langue === "fr" ? "en" : "fr";
    appliquerLangue();
  });
  $("bascule-theme").addEventListener("click", () => {
    etat.themeChoisi = true;
    poserTheme(!themeClair());
  });
  $("choisir-repertoire").addEventListener("click", () => $("entree-repertoire").click());
  $("choisir-archive").addEventListener("click", () => $("entree-archive").click());
  $("choisir-ancres").addEventListener("click", () => $("entree-ancres").click());
  $("choisir-entetes").addEventListener("click", () => $("entree-entetes").click());
  $("entree-repertoire").addEventListener("change", (ev) => {
    if (etat.enCours) return;
    choisirRepertoire(ev.target.files);
    ev.target.value = "";
  });
  $("entree-archive").addEventListener("change", (ev) => {
    if (etat.enCours) return;
    const f = ev.target.files[0];
    etat.dossier = f ? dossierDArchive(f) : null;
    ev.target.value = "";
    rouvrirFormulaire();
    afficherDossier();
  });
  $("entree-ancres").addEventListener("change", (ev) => changerPiece("ancres", ev.target.files[0] ?? null));
  $("entree-entetes").addEventListener("change", (ev) => changerPiece("entetes", ev.target.files[0] ?? null));
  $("retirer-ancres").addEventListener("click", () => {
    $("entree-ancres").value = "";
    changerPiece("ancres", null);
  });
  $("retirer-entetes").addEventListener("click", () => {
    $("entree-entetes").value = "";
    changerPiece("entetes", null);
  });
  $("exiger-tous").addEventListener("change", contraintesExiger);
  for (const c of document.querySelectorAll('input[name="exiger"]')) c.addEventListener("change", afficherOptions);
  $("detail").addEventListener("change", afficherOptions);
  $("langue-rapport").addEventListener("change", () => {
    etat.langueRapportChoisie = true;
    afficherOptions();
  });
  $("verifier").addEventListener("click", () => {
    verifier();
  });
  $("verifier-autre").addEventListener("click", () => {
    rouvrirFormulaire();
    $("choisir-archive").focus({ preventScroll: true });
    montrerSousLaBarre($("choix-dossier"));
  });
  $("arreter").addEventListener("click", () => {
    arreter();
  });
  const zone = $("zone-depot");
  document.addEventListener("dragover", (ev) => {
    ev.preventDefault();
    zone.classList.add("pv-depot-survol");
  });
  document.addEventListener("dragleave", (ev) => {
    if (ev.relatedTarget === null) zone.classList.remove("pv-depot-survol");
  });
  document.addEventListener("drop", (ev) => {
    zone.classList.remove("pv-depot-survol");
    deposer(ev);
  });
  // Un bloc replié ne s'imprime pas : le résultat s'imprime entier, puis reprend son état.
  let fermes = [];
  globalThis.addEventListener("beforeprint", () => {
    fermes = [...document.querySelectorAll("#resultat-contenu details:not([open])")];
    for (const d of fermes) d.open = true;
  });
  globalThis.addEventListener("afterprint", () => {
    for (const d of fermes) d.open = false;
    fermes = [];
  });
}

function initialiser() {
  etat.confiance = $("confiance");
  lier();
  appliquerLangue();
  demarrer();
}

// page.js est chargé dans l'en-tête : le thème est posé avant le premier
// affichage, le reste attend que le document soit lu (verificateur-wasm.js,
// en fin de corps, a alors défini l'artefact).
amorcerTheme();
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initialiser);
else initialiser();
