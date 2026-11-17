"use client";
// Bascule de thème (complément du 2026-11-17) : inverse l'état du document (sombre sans attribut, clair par
// data-theme="clair" sur <html>), repeint la barre du système et mémorise le choix dans le navigateur
// (lib/theme.mjs). Le libellé du bouton dit ce que le clic fera. Un stockage refusé n'empêche rien : le choix vaut
// alors pour la page affichée.

import { useEffect, useState } from "react";
import Icone from "./Icone.js";
import { CLE_THEME, COULEUR_BARRE, THEME_CLAIR, THEME_SOMBRE, libelleBascule, normaliseTheme, prochainTheme } from "../lib/theme.mjs";

function appliquer(theme) {
  const racine = document.documentElement;
  if (theme === THEME_CLAIR) racine.setAttribute("data-theme", THEME_CLAIR);
  else racine.removeAttribute("data-theme");
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", COULEUR_BARRE[theme]);
}

export default function BasculeTheme() {
  const [theme, setTheme] = useState(THEME_SOMBRE);
  // L'amorce du gabarit a déjà posé l'attribut : la bascule lit l'état du document, puis repeint la barre.
  useEffect(() => {
    const courant = normaliseTheme(document.documentElement.getAttribute("data-theme"));
    appliquer(courant);
    setTheme(courant);
  }, []);
  const basculer = () => {
    const suivant = prochainTheme(theme);
    appliquer(suivant);
    try {
      window.localStorage.setItem(CLE_THEME, suivant);
    } catch {
      // stockage refusé : le choix vaut pour cette page seulement
    }
    setTheme(suivant);
  };
  const libelle = libelleBascule(theme);
  return (
    <button type="button" className="nt-bascule nt-sans-impression" onClick={basculer} aria-label={libelle} title={libelle}>
      <Icone nom="soleil" className="nt-icone-soleil" />
      <Icone nom="lune" className="nt-icone-lune" />
    </button>
  );
}
