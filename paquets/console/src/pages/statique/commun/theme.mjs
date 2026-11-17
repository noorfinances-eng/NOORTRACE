// Thème des écrans (CT-3 13.1 : « servi comme fichier avec son intégrité,
// sans script en ligne » ; contrat du paquet, 3.2) : deux états, sombre et
// clair. Le sombre est l'état sans attribut sur `<html>` ; le clair pose
// `data-theme="clair"`. Ce module est le premier module de chaque écran : il
// pose l'état avant que le module d'entrée ne construise la page, et son
// élément `<script>` porte `blocking="render"` : le premier affichage
// l'attend, pour qu'un poste réglé en clair n'entrevoie pas le fond sombre.
//
// Aucun stockage : ni `localStorage`, ni `sessionStorage`, ni témoin. L'état
// initial est celui que demande le système (`prefers-color-scheme` : clair
// s'il le demande, sombre sinon) et suit ses changements ; la bascule de la
// barre vaut pour la page affichée seulement, et se perd au chargement
// suivant.

const CLAIR = "clair";
// Couleur de la barre du navigateur : le fond de chaque état.
const COULEUR = Object.freeze({ sombre: "#060B16", clair: "#F3F7FF" });
const racine = document.documentElement;

// Vrai dès que la personne a basculé elle-même : le système n'est plus suivi.
let choisi = false;
const rappels = [];

/** Vrai si l'état affiché est le clair. */
export function estClair() {
  return racine.getAttribute("data-theme") === CLAIR;
}

function poser(clair) {
  if (clair) racine.setAttribute("data-theme", CLAIR);
  else racine.removeAttribute("data-theme");
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta !== null) meta.setAttribute("content", clair ? COULEUR.clair : COULEUR.sombre);
  for (const f of [...rappels]) f(clair);
}

/** Bascule l'état, pour la page affichée seulement ; rend vrai si le nouvel état est le clair. */
export function basculerTheme() {
  choisi = true;
  poser(!estClair());
  return estClair();
}

/** Appelle `f(clair)` à chaque changement d'état. */
export function surTheme(f) {
  rappels.push(f);
}

// État initial : celui du système, lu sans confiance.
let media = null;
try {
  media = window.matchMedia("(prefers-color-scheme: light)");
} catch {
  media = null;
}
poser(media !== null && media.matches === true);
if (media !== null && typeof media.addEventListener === "function") {
  media.addEventListener("change", (e) => {
    if (!choisi) poser(e.matches === true);
  });
}
