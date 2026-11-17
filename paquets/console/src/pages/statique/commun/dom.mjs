// Construction du DOM des écrans (CT-3 EX-13.33 point 8, EX-13.34 point 4 ;
// contrat de l'étape 6, 3.2) : uniquement par `document.createElement`, la
// propriété `textContent`, `setAttribute` et l'ajout d'enfants. Aucun
// `innerHTML`, aucun gestionnaire en ligne : les événements passent par
// `addEventListener`. Un texte venu du service ou du portefeuille n'est jamais
// interprété comme du HTML.
//
// Les icônes sont des SVG en ligne que le générateur a écrits dans l'écran,
// dans des gabarits `<template id="icone-<nom>">` : `icone()` clone le
// gabarit (`cloneNode`), sans analyser de texte. Une icône est un décor
// (`aria-hidden`) : le mot à côté porte le sens.
//
// Les classes `nt-…` sont celles du thème commun (`console.css`, entre les
// repères `noor-theme`).

/**
 * Crée un élément.
 * @param {string} nom
 * @param {{classe?: string, texte?: string, attributs?: Record<string, string>, surClic?: (e: Event) => void}} [options]
 * @param {...(Node|string|null|undefined|false)} enfants une chaîne devient un `<span>` dont `textContent` est la chaîne
 * @returns {HTMLElement}
 */
export function el(nom, options = {}, ...enfants) {
  const n = document.createElement(nom);
  if (options.classe) n.setAttribute("class", options.classe);
  if (options.attributs) {
    for (const [k, v] of Object.entries(options.attributs)) {
      if (v === null || v === undefined || v === false) continue;
      n.setAttribute(k, v === true ? "" : String(v));
    }
  }
  if (options.texte !== undefined) n.textContent = options.texte;
  if (options.surClic) n.addEventListener("click", options.surClic);
  ajouter(n, ...enfants);
  return n;
}

/** Ajoute des enfants ; une chaîne devient un `<span>` de ce texte. */
export function ajouter(parent, ...enfants) {
  for (const e of enfants.flat()) {
    if (e === null || e === undefined || e === false) continue;
    parent.appendChild(typeof e === "string" ? texte(e) : e);
  }
  return parent;
}

/** Un `<span>` dont `textContent` est le texte. */
export function texte(t, classe) {
  const s = document.createElement("span");
  if (classe) s.setAttribute("class", classe);
  s.textContent = t;
  return s;
}

/** Retire tous les enfants d'un nœud. */
export function vider(n) {
  n.replaceChildren();
  return n;
}

/** Remplace le contenu d'un nœud. */
export function remplacer(n, ...enfants) {
  vider(n);
  return ajouter(n, ...enfants);
}

/**
 * Une icône du thème : clone du gabarit `icone-<nom>` de l'écran, ou `null`
 * si l'écran ne le porte pas (l'écran reste lisible : chaque icône
 * accompagne un mot).
 * @param {string} nom nom d'une icône de `icones.mjs`, ou `logo`
 * @param {string} [classe] classe ajoutée à celle du gabarit
 * @returns {Element|null}
 */
export function icone(nom, classe) {
  const gabarit = document.getElementById(`icone-${nom}`);
  if (gabarit === null || !gabarit.content || gabarit.content.firstElementChild === null) return null;
  const svg = gabarit.content.firstElementChild.cloneNode(true);
  if (classe) svg.setAttribute("class", `${svg.getAttribute("class") ?? ""} ${classe}`.trim());
  return svg;
}

/**
 * Un bouton ; `actif` faux le rend inactif. `genre` : `principal`, `danger`,
 * `discret`, `choix` (les deux boutons de décision, de même poids), ou rien
 * (bouton secondaire) ; `petit` ; `icone` : nom d'une icône placée avant le
 * libellé.
 */
export function bouton(libelle, surClic, { actif = true, genre = null, petit = false, icone: nomIcone = null, classe = null } = {}) {
  const classes = ["nt-bouton"];
  if (genre) classes.push(`nt-bouton-${genre}`);
  if (petit) classes.push("nt-bouton-petit");
  if (classe) classes.push(classe);
  const b = el("button", { classe: classes.join(" "), attributs: { type: "button", disabled: !actif } }, nomIcone ? icone(nomIcone) : null);
  b.appendChild(document.createTextNode(libelle));
  if (surClic) b.addEventListener("click", surClic);
  return b;
}

/** Un groupe de boutons. */
export function actions(...boutons) {
  return el("div", { classe: "nt-actions" }, ...boutons);
}

/** Une liste de définitions `<dl>` à partir de couples [terme, valeur]. */
export function definitions(couples, classe = "nt-definitions") {
  const dl = el("dl", { classe });
  for (const [terme, valeur] of couples) {
    ajouter(dl, el("dt", { texte: terme }), el("dd", {}, valeur));
  }
  return dl;
}

/** Une valeur à chasse fixe. */
export function code(t, classe = "nt-fixe") {
  return el("code", { classe, texte: t });
}

// Icône d'un bandeau selon son genre.
const ICONE_BANDEAU = Object.freeze({ info: "info", succes: "coche", alerte: "alerte", erreur: "alerte" });
const CLASSE_BANDEAU = Object.freeze({ info: "nt-bandeau", succes: "nt-bandeau nt-bandeau-succes", alerte: "nt-bandeau nt-bandeau-avertissement", erreur: "nt-bandeau nt-bandeau-erreur" });

/**
 * Un bandeau : message d'état (`role="status"` : `info`, `succes`) ou
 * d'alerte (`role="alert"` : `alerte`, `erreur`). Le genre se lit par
 * l'icône et par le texte, jamais par la seule couleur.
 */
export function message(genre, ...enfants) {
  return el(
    "div",
    { classe: CLASSE_BANDEAU[genre] ?? CLASSE_BANDEAU.info, attributs: { role: genre === "info" || genre === "succes" ? "status" : "alert" } },
    icone(ICONE_BANDEAU[genre] ?? "info"),
    el("div", { classe: "nt-bandeau-texte" }, ...enfants),
  );
}

/** Une note : même forme qu'un bandeau, sans annonce aux lecteurs d'écran (`role="note"`). */
export function note(genre, ...enfants) {
  const n = message(genre, ...enfants);
  n.setAttribute("role", "note");
  return n;
}

/**
 * Pastille d'état : un mot et une icône. `genre` : `attente`, `succes`,
 * `refus`, `info`, ou `neutre` ; `telQuel` : le libellé est rendu sans
 * capitale ajoutée.
 */
export function pastille(genre, libelle, nomIcone, { grande = false, attributs = {}, telQuel = false } = {}) {
  const classes = ["nt-pastille"];
  if (genre && genre !== "neutre") classes.push(`nt-pastille-${genre}`);
  if (grande) classes.push("nt-pastille-grande");
  // Le libellé garde son texte ; la feuille de style lui donne une capitale initiale, sauf `telQuel` (une valeur signée).
  return el("span", { classe: classes.join(" "), attributs }, nomIcone ? icone(nomIcone) : null, el("span", { classe: telQuel ? null : "capitale", texte: libelle }));
}

/**
 * Marque d'un champ : un rectangle, pour ne pas la confondre avec un état.
 * `genre` : `verifie`, `non-verifiable`, `different`, ou rien (marque
 * déclarative).
 */
export function marque(genre, libelle, nomIcone, attributs = {}) {
  const m = el("span", { classe: genre ? `nt-marque nt-marque-${genre}` : "nt-marque", attributs }, nomIcone ? icone(nomIcone) : null);
  m.appendChild(document.createTextNode(libelle));
  return m;
}

/** Un bloc replié, ouvert sur demande ; `noteTitre` : précision à droite du titre. */
export function detail(titre, noteTitre, ...enfants) {
  const resume = el("summary", {});
  resume.appendChild(document.createTextNode(titre));
  if (noteTitre) resume.appendChild(el("span", { classe: "nt-detail-note", texte: noteTitre }));
  return el("details", { classe: "nt-detail" }, resume, el("div", { classe: "nt-detail-corps" }, ...enfants));
}
