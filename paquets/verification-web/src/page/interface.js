// Interface de la page de vérification (CT-6 §18) : choix des fichiers,
// lecture des archives (archives.js), transmission au travailleur, affichage
// (EX-18.2, EX-18.5, EX-18.7, EX-18.9). Aucun HTML n'est inséré : tout texte
// passe par textContent ; aucun stockage, aucune requête.

const TABLES_LIBELLES = { fr: LIBELLES_FR, en: LIBELLES_EN };
const CODES_CONNUS = [0, 1, 2, 3];

const etat = {
  langue: "fr",
  langueRapportChoisie: false,
  travailleur: null,
  pret: false,
  artefact: { genre: "chargement" },
  dossier: null,
  ancres: null,
  entetes: null,
  enCours: false,
  attente: null,
  vue: null,
};

const $ = (id) => document.getElementById(id);

function libelle(cle, parametres = {}) {
  const modele = TABLES_LIBELLES[etat.langue][cle];
  return modele.replace(/\{([a-z0-9_]+)\}/g, (tout, k) => (Object.hasOwn(parametres, k) ? String(parametres[k]) : tout));
}

function element(balise, classe, texte) {
  const e = document.createElement(balise);
  if (classe) e.className = classe;
  if (texte !== undefined) e.textContent = texte;
  return e;
}

const decodeur = new TextDecoder("utf-8");

// --- Langue de la page ----------------------------------------------------

function appliquerLangue() {
  document.documentElement.lang = etat.langue;
  for (const e of document.querySelectorAll("[data-libelle]")) {
    e.textContent = libelle(e.dataset.libelle, { version: VERSION_VERIFICATEUR });
  }
  const autre = $("autre-langue");
  autre.lang = etat.langue === "fr" ? "en" : "fr";
  if (!etat.langueRapportChoisie) $("langue-rapport").value = etat.langue;
  afficherArtefact();
  afficherDossier();
  afficherVue();
}

// --- Artefact ---------------------------------------------------------------

function afficherArtefact() {
  const p = $("artefact");
  const a = etat.artefact;
  p.className = "";
  if (a.genre === "chargement") p.textContent = libelle("artefact_chargement");
  else if (a.genre === "pret") p.textContent = libelle("artefact_pret", { version: a.version, empreinte: a.empreinte });
  else if (a.genre === "altere") {
    p.className = "alerte";
    p.textContent = libelle("artefact_altere", { calculee: a.calculee, attendue: a.attendue });
  } else {
    p.className = "alerte";
    p.textContent = `${libelle("non_faite")}. ${libelle("cause", { cause: a.cause })}`;
  }
  majBoutons();
}

function creerTravailleur() {
  // Types de confiance (EX-18.12) : la politique noortrace-travailleur, créée
  // une fois, ne rend que l'adresse travailleur.js ; sans types de confiance,
  // la chaîne constante travailleur.js.
  if (globalThis.trustedTypes && typeof globalThis.trustedTypes.createPolicy === "function") {
    const politique = globalThis.trustedTypes.createPolicy("noortrace-travailleur", {
      createScriptURL(valeur) {
        if (valeur === "travailleur.js") return valeur;
        throw new TypeError("adresse de travailleur refusée");
      },
    });
    return new Worker(politique.createScriptURL("travailleur.js"));
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

function demarrer() {
  let octets;
  try {
    octets = decoderArtefact();
    etat.travailleur = creerTravailleur();
  } catch (e) {
    etat.artefact = { genre: "non_faite", cause: libelle("cause_travailleur", { detail: e && e.message ? e.message : String(e) }) };
    afficherArtefact();
    return;
  }
  etat.travailleur.addEventListener("message", (ev) => recevoir(ev.data));
  etat.travailleur.addEventListener("error", (ev) => {
    ev.preventDefault();
    echecTravailleur(libelle("travailleur_indisponible"));
  });
  etat.travailleur.addEventListener("messageerror", () => echecTravailleur(libelle("travailleur_indisponible")));
  etat.travailleur.postMessage({ type: "artefact", octets }, [octets]);
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
  if (d === null) p.textContent = libelle("aucun_dossier");
  else p.textContent = libelle(d.genre === "repertoire" ? "nom_dossier_repertoire" : "nom_dossier_archive", { nom: d.nom });
  majBoutons();
}

function majBoutons() {
  const b = $("verifier");
  if (b) b.disabled = !(etat.pret && etat.dossier !== null && !etat.enCours);
}

/** Octets propres d'un Uint8Array (tampon exact, transférable). */
function tamponExact(octets) {
  if (octets.byteOffset === 0 && octets.byteLength === octets.buffer.byteLength) return octets.buffer;
  return octets.slice().buffer;
}

async function lireFichier(fichier) {
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

async function parcourirRepertoire(entree, prefixe, liste) {
  const lecteur = entree.createReader();
  for (;;) {
    const lot = await lireEntreesRepertoire(lecteur);
    if (lot.length === 0) break;
    for (const e of lot) {
      if (e.isDirectory) await parcourirRepertoire(e, `${prefixe}${e.name}/`, liste);
      else if (e.isFile) {
        const fichier = await new Promise((resoudre, rejeter) => e.file(resoudre, rejeter));
        liste.push({ chemin: `${prefixe}${e.name}`, fichier });
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
    return;
  }
  const item = elements[0];
  const entree = typeof item.webkitGetAsEntry === "function" ? item.webkitGetAsEntry() : null;
  if (entree && entree.isDirectory) {
    const liste = [];
    try {
      await parcourirRepertoire(entree, "", liste);
    } catch {
      etat.vue = { genre: "refus", raison: "r_lecture", parametres: { nom: entree.name }, noms: null };
      afficherVue();
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
  majBoutons();
  etat.vue = { genre: "en_cours" };
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
    majBoutons();
    afficherVue();
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
  const vue = {
    genre: "resultat",
    noms,
    commandes,
    code: lisible.code,
    lisible: decodeur.decode(lisible.sortie),
    erreur: decodeur.decode(lisible.erreur),
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
  }
  return vue;
}

// --- Affichage du résultat ----------------------------------------------------

function blocNoms(noms) {
  const div = element("div", "noms");
  div.append(element("p", null, libelle("noms_choisis")));
  const ul = element("ul");
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
    contenu.append(element("p", "en-cours", libelle("en_cours")));
    return;
  }
  if (v.noms) contenu.append(blocNoms(v.noms));
  if (v.genre === "refus") {
    contenu.append(element("p", "alerte", texteRefus(v.raison, v.parametres)));
    contenu.append(element("p", "aucun-rapport", libelle("aucun_rapport")));
    return;
  }
  if (v.commandes) {
    contenu.append(element("p", null, libelle("commande")));
    contenu.append(element("pre", "commande", v.commandes.join("\n")));
  }
  if (v.genre === "non_faite") {
    contenu.append(element("p", "alerte non-faite", libelle("non_faite")));
    contenu.append(element("p", "cause", libelle("cause", { cause: texteCause(v.cause) })));
    return;
  }
  const code = element("p", `code code-${v.code}`, libelle("code", { code: v.code, sens: libelle(`code_${v.code}`) }));
  code.id = "code";
  contenu.append(code);
  if (v.lisible !== "") {
    contenu.append(element("p", null, libelle("rapport_lisible")));
    const pre = element("pre", "rapport", v.lisible);
    pre.id = "rapport-lisible";
    contenu.append(pre);
  }
  if (v.code === 2) {
    contenu.append(element("p", null, libelle("message_erreur")));
    const m = element("p", "message-erreur", v.messageErreur);
    m.id = "message-erreur";
    contenu.append(m);
    const a = element("p", "aucune-affirmation", libelle("aucune_affirmation"));
    a.id = "aucune-affirmation";
    contenu.append(a);
  } else {
    contenu.append(element("p", null, libelle("enonce_fr")));
    const fr = element("p", "enonce", v.enonceFr);
    fr.id = "enonce-fr";
    fr.lang = "fr";
    contenu.append(fr);
    contenu.append(element("p", null, libelle("enonce_en")));
    const en = element("p", "enonce", v.enonceEn);
    en.id = "enonce-en";
    en.lang = "en";
    contenu.append(en);
  }
  contenu.append(element("p", null, libelle("sortie_erreur")));
  const err = element("pre", "sortie-erreur", v.erreur === "" ? libelle("sortie_erreur_vide") : v.erreur);
  err.id = "sortie-erreur";
  if (v.erreur === "") err.classList.add("vide");
  contenu.append(err);
}

// --- Liaisons -----------------------------------------------------------------

function lier() {
  $("autre-langue").addEventListener("click", () => {
    etat.langue = etat.langue === "fr" ? "en" : "fr";
    appliquerLangue();
  });
  $("choisir-repertoire").addEventListener("click", () => $("entree-repertoire").click());
  $("choisir-archive").addEventListener("click", () => $("entree-archive").click());
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
  });
  $("entree-entetes").addEventListener("change", (ev) => {
    etat.entetes = ev.target.files[0] ?? null;
  });
  $("retirer-ancres").addEventListener("click", () => {
    $("entree-ancres").value = "";
    etat.ancres = null;
  });
  $("retirer-entetes").addEventListener("click", () => {
    $("entree-entetes").value = "";
    etat.entetes = null;
  });
  $("exiger-tous").addEventListener("change", contraintesExiger);
  $("langue-rapport").addEventListener("change", () => {
    etat.langueRapportChoisie = true;
  });
  $("verifier").addEventListener("click", () => {
    verifier();
  });
  document.addEventListener("dragover", (ev) => ev.preventDefault());
  document.addEventListener("drop", (ev) => {
    deposer(ev);
  });
}

lier();
appliquerLangue();
demarrer();
