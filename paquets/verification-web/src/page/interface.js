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
    $(enAlerte ? "alerte-verificateur" : "hote-artefact").append(p);
    alerte.hidden = !enAlerte;
    detail.hidden = a.genre !== "pret";
  }
  const mot = $("etat-verificateur");
  if (mot) {
    const p = pastille(marque[0], marque[1], libelle(marque[2]));
    p.classList.add("nt-pastille-grande");
    mot.replaceChildren(p);
  }
  majBoutons();
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
  } else {
    p.className = "pv-choisi pv-choisi-fait";
    p.replaceChildren(icone("coche"), element("span", null, libelle(d.genre === "repertoire" ? "dossier_choisi_repertoire" : "dossier_choisi_archive", { nom: d.nom })));
  }
  majBoutons();
}

/** Noms des fichiers facultatifs choisis, à côté de leurs boutons. */
function afficherEntrees() {
  for (const [id, fichier] of [["nom-ancres", etat.ancres], ["nom-entetes", etat.entetes]]) {
    const e = $(id);
    if (!e) continue;
    e.className = fichier ? "pv-fichier-nom pv-fichier-choisi" : "pv-fichier-nom";
    e.textContent = libelle(fichier ? "fichier_choisi" : "aucun_fichier", { nom: fichier ? fichier.name : "" });
  }
  afficherOptions();
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
  else if (exiges !== null) parties.push(libelle("options_exiger", { liste: exiges.split(",").join(", ") }));
  const langue = $("langue-rapport").value === "en" ? "en" : "fr";
  if (langue !== etat.langue) parties.push(libelle("options_langue", { langue: libelle(langue === "en" ? "langue_en" : "langue_fr") }));
  if ($("detail").checked) parties.push(libelle("options_detail"));
  ecrire(resume, parties.length === 0 ? libelle("options_aucune") : parties.join(" · "));
}

function cleAideVerifier() {
  if (etat.artefact.genre === "altere" || etat.artefact.genre === "non_faite") return "aide_verifier_indisponible";
  if (!etat.pret) return "aide_verifier_chargement";
  return etat.dossier === null ? "aide_verifier_dossier" : "aide_verifier_pret";
}

function majBoutons() {
  const b = $("verifier");
  if (b) b.disabled = !(etat.pret && etat.dossier !== null && !etat.enCours);
  const a = $("arreter");
  if (a) a.disabled = !(etat.enCours && !etat.arret);
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
    try {
      contenu = await etat.dossier.lire();
      for (const f of contenu.fichiers) fichiers.push({ chemin: `dossier/${f.chemin}`, octets: tamponExact(f.octets) });
      if (etat.ancres) fichiers.push({ chemin: "ancres.json", octets: tamponExact(await lireFichier(etat.ancres)) });
      if (etat.entetes) fichiers.push({ chemin: "entetes-bitcoin.json", octets: tamponExact(await lireFichier(etat.entetes)) });
    } catch (e) {
      if (e instanceof RefusArchive) {
        etat.vue = { genre: "refus", raison: e.raison, parametres: e.parametres, noms };
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
    majBoutons();
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
    controles.push({ numero: c.number, statut: c.status, raison: c.status === "non_execute" ? c.reason : null, resume: typeof c.summary === "string" ? c.summary : "" });
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
 * (`warnings`, ou null s'ils ne se lisent pas).
 */
function resumer(rapport, code) {
  const exiges = rapport.inputs && Array.isArray(rapport.inputs.required_controls) && rapport.inputs.required_controls.every((n) => Number.isInteger(n) && n >= 1 && n <= 8) ? rapport.inputs.required_controls : null;
  let avertissements = [];
  if (rapport.warnings !== undefined) {
    const w = rapport.warnings;
    const lisibles = Array.isArray(w) && w.every((a) => a !== null && typeof a === "object" && typeof a.id === "string" && typeof a.detail === "string" && (a.check === null || a.check === undefined || typeof a.check === "string"));
    avertissements = lisibles ? w.map((a) => ({ id: a.id, verification: typeof a.check === "string" ? a.check : null, detail: a.detail })) : null;
  }
  return {
    controles: lireControles(rapport, code),
    exiges,
    echecs: listeDeChaines(rapport.failed_checks),
    bloquantes: listeDeChaines(rapport.blocking_unexecuted),
    avertissements,
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

function texteCause(cause) {
  if (cause.texte !== undefined) return cause.texte;
  return libelle(cause.cle, cause.parametres);
}

/** Raison d'une non-exécution en clair, son code entre parenthèses (CT-6 §6.2). */
function texteRaison(code) {
  return libelle("raison", { raison: libelle(RAISONS_CONNUES.includes(code) ? `raison_${code}` : "raison_inconnue"), code });
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

/** Bouton « Copier » d'un texte préformaté : le texte affiché, tel quel ; rien si le navigateur ne l'offre pas. */
function boutonCopier(pre) {
  const presse = globalThis.navigator && globalThis.navigator.clipboard;
  if (!presse || typeof presse.writeText !== "function") return null;
  const ligne = element("div", "pv-copie");
  const bouton = element("button", "nt-bouton nt-bouton-petit", libelle("copier"));
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
  pre.classList.add("pv-pre");
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

/** Ligne d'alerte sous le verdict : ce que le verdict ne couvre pas. */
function ligneBorne(id, texte) {
  const p = element("p", "pv-verdict-borne");
  p.id = id;
  p.append(icone("alerte"), element("span", null, texte));
  return p;
}

/** Énoncé du vérificateur, tel quel ; les empreintes hexadécimales sont mises en chasse fixe, sans qu'un caractère change. */
function paragrapheEnonce(id, langue, texte) {
  const p = element("p", "enonce");
  p.id = id;
  p.lang = langue;
  for (const morceau of String(texte).split(/(0x[0-9a-f]{16,})/)) {
    if (morceau === "") continue;
    if (/^0x[0-9a-f]{16,}$/.test(morceau)) p.append(element("span", "pv-hex", morceau));
    else p.append(document.createTextNode(neutraliser(morceau)));
  }
  return p;
}

const PASTILLES_STATUT = {
  reussi: ["succes", "coche", "statut_reussi"],
  echoue: ["refus", "croix", "statut_echoue"],
  non_execute: ["", "tiret", "statut_non_execute"],
};

/** Carte des huit contrôles : l'état que le rapport donne à chacun, sa raison, son résumé. */
function carteControles(resume) {
  const carte = element("section", "nt-carte");
  carte.id = "controles";
  const titre = element("div", "nt-carte-titre");
  titre.append(element("h3", null, libelle("titre_controles")));
  const compte = (statut) => resume.controles.filter((c) => c.statut === statut).length;
  const parties = [libelle("compte_reussis", { n: compte("reussi") })];
  if (compte("non_execute") > 0) parties.push(libelle("compte_non_executes", { n: compte("non_execute") }));
  if (compte("echoue") > 0) parties.push(libelle("compte_echoues", { n: compte("echoue") }));
  const note = element("span", "nt-carte-note", parties.join(" · "));
  note.id = "compte-controles";
  titre.append(note);
  const ul = element("ul", "nt-controles");
  for (const c of resume.controles) {
    const li = element("li", "nt-controle pv-controle");
    li.dataset.numero = String(c.numero);
    li.dataset.statut = c.statut;
    const [ton, nomIcone, cle] = PASTILLES_STATUT[c.statut];
    const marque = element("span");
    marque.append(pastille(ton, nomIcone, libelle(cle)));
    const texte = element("div", "nt-controle-texte");
    const ligne = element("div", "pv-controle-ligne");
    ligne.append(element("span", "nt-controle-titre", `${c.numero}. ${libelle(`controle_${c.numero}`)}`));
    if (resume.exiges !== null && resume.exiges.includes(c.numero)) ligne.append(pastille("info", "alerte", libelle("controle_exige")));
    texte.append(ligne);
    if (c.statut === "non_execute") texte.append(element("span", "pv-controle-raison", texteRaison(c.raison)));
    if (c.resume !== "") texte.append(element("span", "nt-attenue nt-petit", c.resume));
    li.append(marque, texte);
    ul.append(li);
  }
  carte.append(titre, ul);
  return carte;
}

/** Bandeau des avertissements : ceux du rapport JSON, puis la sortie d'erreur si elle n'est pas vide. */
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
    const ul = element("ul", "pv-liste");
    for (const a of avertissements) {
      ul.append(element("li", null, a.verification === null ? libelle("avertissement_sans_verification", { detail: a.detail, id: a.id }) : libelle("avertissement", { detail: a.detail, id: a.id, check: a.verification })));
    }
    texte.append(ul);
  }
  if (v.erreur !== "") {
    texte.append(element("p", "nt-bandeau-titre", libelle("titre_sortie_erreur")));
    const err = element("pre", "sortie-erreur nt-pre", v.erreur);
    err.id = "sortie-erreur";
    texte.append(err);
  }
  bandeau.append(texte);
  return bandeau;
}

/** Bloc replié « Refaire la vérification avec le binaire » : fichiers choisis et ligne de commande équivalente. */
function blocCommande(v) {
  const { bloc, corps } = blocReplie("detail-commande", libelle("titre_commande"), libelle("note_commande"));
  if (v.noms) corps.append(blocNoms(v.noms));
  corps.append(element("p", "nt-petit", libelle("commande")));
  blocPre(corps, element("pre", "commande nt-pre", v.commandes.join("\n")));
  corps.append(element("p", "nt-petit nt-attenue", libelle("nom_interne")));
  return bloc;
}

function afficherVue() {
  const section = $("resultat");
  const contenu = $("resultat-contenu");
  if (!section || !contenu) return;
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
    // EX-18.7 : la raison, « aucun rapport » et aucun code.
    const verdict = blocVerdict(null, "alerte");
    verdict.append(element("p", "nt-verdict-mot pv-mot aucun-rapport", libelle("aucun_rapport")));
    verdict.append(element("p", "nt-verdict-phrase pv-phrase alerte", texteRefus(v.raison, v.parametres)));
    const suite = element("div", "pv-verdict-suite");
    suite.append(element("p", null, libelle("refus_suite")));
    verdict.append(suite);
    contenu.append(verdict);
    if (v.noms) contenu.append(blocFichiers(v.noms));
    return;
  }
  if (v.genre === "non_faite") {
    // EX-18.9 : « vérification non faite » avec la cause, aucun rapport, aucun énoncé.
    const verdict = blocVerdict(null, "question");
    verdict.append(element("p", "nt-verdict-mot pv-mot alerte non-faite", libelle("non_faite")));
    verdict.append(element("p", "nt-verdict-phrase pv-phrase cause", libelle("cause", { cause: texteCause(v.cause) })));
    const suite = element("div", "pv-verdict-suite");
    suite.append(element("p", null, libelle("non_faite_suite")));
    verdict.append(suite);
    contenu.append(verdict);
    if (v.commandes) contenu.append(blocCommande(v));
    else if (v.noms) contenu.append(blocFichiers(v.noms));
    return;
  }

  // Verdict : le mot suit le code de retour ; la phrase du code (table de CT-6 §8.3) reste entière dessous.
  const variantes = { 0: ["valide", "bouclier"], 1: ["non-valide", "croix"], 2: [null, "question"], 3: ["incomplet", "alerte"] };
  const verdict = blocVerdict(variantes[v.code][0], variantes[v.code][1]);
  verdict.dataset.code = String(v.code);
  const mot = element("p", "nt-verdict-mot pv-mot", libelle(`mot_${v.code}`));
  mot.id = "verdict-mot";
  const code = element("p", `nt-verdict-phrase pv-phrase code code-${v.code}`, libelle("code", { code: v.code, sens: libelle(`code_${v.code}`) }));
  code.id = "code";
  const suite = element("div", "pv-verdict-suite");
  suite.id = "verdict-suite";
  verdict.append(mot, code, suite);
  contenu.append(verdict);

  if (v.code === 2) {
    const a = element("p", "aucune-affirmation pv-verdict-fort", libelle("aucune_affirmation"));
    a.id = "aucune-affirmation";
    suite.append(a);
    suite.append(element("p", "nt-petit nt-attenue", libelle("message_erreur")));
    const m = element("p", "message-erreur", v.messageErreur);
    m.id = "message-erreur";
    suite.append(m);
  } else {
    const r = v.resume;
    if (r.controles === null) suite.append(ligneBorne("resume-indisponible", libelle("resume_indisponible")));
    else {
      const nonReussis = controlesNonReussis(r.controles);
      if (v.code === 0 && nonReussis.length === 0) {
        const p = element("p", "pv-verdict-fort", libelle("tous_reussis"));
        p.id = "tous-reussis";
        suite.append(p);
      } else if (v.code === 0) suite.append(ligneBorne("verdict-borne", libelle("valide_borne", { liste: nonReussis.join(", ") })));
      else if (v.code === 3 && r.exiges !== null) {
        suite.append(ligneBorne("exiges-non-reussis", libelle("exiges_non_reussis", { liste: r.exiges.filter((n) => nonReussis.includes(n)).join(", ") })));
      }
    }
    if (v.code === 1) {
      if (r.echecs !== null && r.echecs.length > 0) suite.append(element("p", "pv-verdict-fort", libelle("verifications_echec", { liste: r.echecs.join(", ") })));
      if (r.bloquantes !== null && r.bloquantes.length > 0) suite.append(element("p", "pv-verdict-fort", libelle("verifications_bloquantes", { liste: r.bloquantes.join(", ") })));
    }
  }

  // Les avertissements montent sous le verdict : ils ne sont jamais repliés.
  const avertissements = bandeauAvertissements(v);
  if (avertissements) contenu.append(avertissements);

  if (v.code !== 2) {
    // Énoncé dans la langue de la page, tel quel ; l'autre langue dans un bloc replié de la même carte.
    const carte = element("section", "nt-carte");
    carte.id = "enonce";
    const titre = element("div", "nt-carte-titre");
    titre.append(element("h3", null, libelle(v.code === 1 ? "titre_enonce_invalide" : "titre_enonce")));
    titre.append(element("span", "nt-carte-note", libelle("note_enonce")));
    carte.append(titre);
    const fr = paragrapheEnonce("enonce-fr", "fr", v.enonceFr);
    const en = paragrapheEnonce("enonce-en", "en", v.enonceEn);
    const [principal, autre, cleAutre, champAutre] = etat.langue === "en" ? [en, fr, "enonce_fr", "statement.fr"] : [fr, en, "enonce_en", "statement.en"];
    carte.append(principal);
    const { bloc, corps } = blocReplie("detail-enonce-autre", libelle(cleAutre), champAutre);
    bloc.classList.add("pv-enonce-autre");
    corps.append(autre);
    carte.append(bloc);
    contenu.append(carte);
    if (v.resume.controles !== null) contenu.append(carteControles(v.resume));
  }

  // Rapport complet, rapport JSON, ligne de commande : tels quels, dans des blocs repliés.
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
    contenu.append(bloc);
  }
  const json = blocReplie("detail-json", libelle("rapport_json"), libelle("note_rapport_json"));
  const preJson = element("pre", "rapport-json nt-pre nt-pre-defile", v.json);
  preJson.id = "rapport-json";
  blocPre(json.corps, preJson);
  contenu.append(json.bloc);
  contenu.append(blocCommande(v));
}

/** Après une vérification, le résultat vient à l'écran. */
function montrerResultat() {
  const section = $("resultat");
  if (section && !section.hidden && typeof section.scrollIntoView === "function") section.scrollIntoView({ block: "start" });
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
    afficherDossier();
  });
  $("entree-ancres").addEventListener("change", (ev) => {
    etat.ancres = ev.target.files[0] ?? null;
    afficherEntrees();
  });
  $("entree-entetes").addEventListener("change", (ev) => {
    etat.entetes = ev.target.files[0] ?? null;
    afficherEntrees();
  });
  $("retirer-ancres").addEventListener("click", () => {
    $("entree-ancres").value = "";
    etat.ancres = null;
    afficherEntrees();
  });
  $("retirer-entetes").addEventListener("click", () => {
    $("entree-entetes").value = "";
    etat.entetes = null;
    afficherEntrees();
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
