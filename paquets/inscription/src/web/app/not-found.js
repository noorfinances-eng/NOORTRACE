// Page introuvable (complément du 2026-11-18, décision du porteur sur le langage des écrans) : un client qui
// n'existe pas, ou une adresse mal écrite, se dit en clair, avec le chemin du retour.

import Icone from "../composants/Icone.js";

export default function Introuvable() {
  return (
    <main className="nt-page nt-page-etroite">
      <div className="nt-vide" data-introuvable="">
        <Icone nom="question" />
        <h1 className="nt-vide-titre">Cette page n'existe pas.</h1>
        <p className="nt-vide-texte">Le client demandé n'existe pas dans l'outil, ou l'adresse de la page est mal écrite. Rien n'a été modifié.</p>
        <a className="nt-bouton nt-bouton-principal" href="/clients">Revenir à la liste des clients</a>
      </div>
    </main>
  );
}
