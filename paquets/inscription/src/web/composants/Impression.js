"use client";
// Impression : un bloc replié fermé ne s'imprime pas. Avant l'impression, les blocs fermés sont ouverts, pour que
// la page imprimée porte les valeurs exactes ; après, ils sont refermés. Rien d'autre ne change.

import { useEffect } from "react";

export default function Impression() {
  useEffect(() => {
    const MARQUE = "data-ouvert-pour-impression";
    const ouvrir = () => {
      for (const d of document.querySelectorAll("details:not([open])")) {
        d.setAttribute(MARQUE, "");
        d.open = true;
      }
    };
    const refermer = () => {
      for (const d of document.querySelectorAll(`details[${MARQUE}]`)) {
        d.removeAttribute(MARQUE);
        d.open = false;
      }
    };
    window.addEventListener("beforeprint", ouvrir);
    window.addEventListener("afterprint", refermer);
    return () => {
      window.removeEventListener("beforeprint", ouvrir);
      window.removeEventListener("afterprint", refermer);
    };
  }, []);
  return null;
}
