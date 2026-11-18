"use client";
// Bouton qui copie un texte exact dans le presse-papiers (complément du 2026-11-18, décision du porteur sur le
// langage des écrans) : la demande à remettre aux approbateurs du client se copie telle quelle, sans la
// sélectionner à la main. Rien n'est envoyé. Si le navigateur refuse, la consigne dit comment faire autrement.

import { useState } from "react";

export default function CopierTexte({ texte, libelle = "Copier", ...attributs }) {
  const [etat, setEtat] = useState("");
  const copier = async () => {
    try {
      await navigator.clipboard.writeText(texte);
      setEtat("Copié : collez-le dans votre message au client.");
    } catch {
      setEtat("La copie n'a pas pu se faire : ouvrez « Texte exact du document », sélectionnez tout le texte et copiez-le.");
    }
  };
  return (
    <span className="ins-copier">
      <button type="button" className="nt-bouton nt-bouton-petit nt-sans-impression" onClick={copier} {...attributs}>{libelle}</button>
      <span className={etat ? "nt-attenue nt-petit" : "nt-masque"} role="status">{etat}</span>
    </span>
  );
}
