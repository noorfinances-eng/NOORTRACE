// Construction du DOM des écrans (CT-3 EX-13.33 point 8, EX-13.34 point 4 ;
// contrat de l'étape 6, 3.2) : uniquement par `document.createElement`, la
// propriété `textContent`, `setAttribute` et l'ajout d'enfants. Aucun
// `innerHTML`, aucun gestionnaire en ligne : les événements passent par
// `addEventListener`. Un texte venu du service ou du portefeuille n'est jamais
// interprété comme du HTML.

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

/** Un bouton ; `actif` faux le rend inactif. */
export function bouton(libelle, surClic, { actif = true, classe = "bouton" } = {}) {
  const b = el("button", { classe, texte: libelle, attributs: { type: "button", disabled: !actif } });
  if (surClic) b.addEventListener("click", surClic);
  return b;
}

/** Une liste de définitions `<dl>` à partir de couples [terme, valeur]. */
export function definitions(couples, classe = "definitions") {
  const dl = el("dl", { classe });
  for (const [terme, valeur] of couples) {
    ajouter(dl, el("dt", { texte: terme }), el("dd", {}, valeur));
  }
  return dl;
}

/** Une valeur à chasse fixe. */
export function code(t, classe = "fixe") {
  return el("code", { classe, texte: t });
}

/**
 * Un message d'état (`role="status"`) ou d'alerte (`role="alert"`), selon le
 * genre : `info`, `alerte`, `erreur`.
 */
export function message(genre, ...enfants) {
  return el("div", { classe: `message message-${genre}`, attributs: { role: genre === "info" ? "status" : "alert" } }, ...enfants);
}
