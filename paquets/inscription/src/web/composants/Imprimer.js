"use client";
// Bouton « Imprimer cette page » (fiche de contrôle des adresses des approbateurs, complément du 2026-11-25) : il
// n'ouvre que la boîte d'impression du navigateur ; rien n'est envoyé, rien n'est gardé. Il ne s'imprime pas lui-même.

export default function Imprimer({ libelle = "Imprimer cette page" }) {
  return <button type="button" className="nt-bouton nt-sans-impression" onClick={() => window.print()} data-imprimer="">{libelle}</button>;
}
