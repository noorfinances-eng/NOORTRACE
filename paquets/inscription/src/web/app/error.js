"use client";
// Écran d'une panne de l'outil (complément du 2026-11-18, décision du porteur sur le langage des écrans) : un
// écran qui ne peut pas être préparé le dit en clair, avec quoi faire. Aucun détail interne n'est affiché.

import Icone from "../composants/Icone.js";

export default function Panne({ reset }) {
  return (
    <main className="nt-page nt-page-etroite">
      <div className="nt-vide" data-panne="">
        <Icone nom="alerte" />
        <h1 className="nt-vide-titre">L'outil n'a pas pu préparer cet écran.</h1>
        <p className="nt-vide-texte">Ce n'est pas de votre fait, et cet affichage n'a rien modifié. Réessayez ; si le problème revient, prévenez l'équipe technique en lui disant sur quel écran vous étiez.</p>
        <div className="nt-actions">
          <button type="button" className="nt-bouton nt-bouton-principal" onClick={() => reset()}>Réessayer</button>
          <a className="nt-bouton" href="/clients">Revenir à la liste des clients</a>
        </div>
      </div>
    </main>
  );
}
