// Thème d'affichage de l'interface d'exploitant (complément du 2026-11-17, décision du porteur sur la présentation
// des écrans) : deux états, « sombre » (l'état sans attribut sur <html>, rendu sans script) et « clair »
// (`data-theme="clair"`). Le choix se mémorise dans le navigateur (`localStorage`, clé `noor.theme`, comme les
// hubs NOORCHAIN) : ce n'est ni une clé, ni une référence, ni une donnée d'un client. Toute autre valeur que
// « clair » retombe sur le sombre : jamais un troisième état. Module pur, sous essais.

export const THEME_SOMBRE = "sombre";
export const THEME_CLAIR = "clair";
export const CLE_THEME = "noor.theme";

/** Couleur de la barre du système (`meta[name="theme-color"]`) pour chaque état. */
export const COULEUR_BARRE = Object.freeze({ sombre: "#060B16", clair: "#F3F7FF" });

/** Toute valeur qui n'est pas exactement « clair » vaut « sombre ». */
export function normaliseTheme(valeur) {
  return valeur === THEME_CLAIR ? THEME_CLAIR : THEME_SOMBRE;
}

/** L'autre état. */
export function prochainTheme(valeur) {
  return normaliseTheme(valeur) === THEME_CLAIR ? THEME_SOMBRE : THEME_CLAIR;
}

/** Libellé du bouton de bascule dans l'état donné : il dit ce que le clic fera. */
export function libelleBascule(valeur) {
  return normaliseTheme(valeur) === THEME_CLAIR ? "Passer au thème sombre" : "Passer au thème clair";
}

/**
 * Amorce posée dans l'en-tête du gabarit, en script à nonce (la politique de sécurité du contenu l'admet) : elle
 * pose l'état clair mémorisé avant le premier affichage du corps. Tout échec (stockage refusé) laisse le sombre.
 */
export const AMORCE_THEME = `try{if(localStorage.getItem("${CLE_THEME}")==="${THEME_CLAIR}"){document.documentElement.setAttribute("data-theme","${THEME_CLAIR}")}}catch(e){}`;
