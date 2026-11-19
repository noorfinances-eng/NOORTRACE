// Ce que sont les crédits d'écriture (complément du 2026-11-18, décision du porteur sur le langage des écrans ;
// cinquième lecture des écrans) : un bloc replié, « Qu'est-ce qu'un crédit d'écriture ? », placé juste après le
// premier texte de l'écran qui les nomme, une fois par écran au plus. Ce n'est pas ce qui engage : le montant d'un
// versement et le compte qui le reçoit restent écrits, à leur place, sans rien ouvrir. `versement` : la phrase sur
// ce que permet le versement du compte technique s'y ajoute. Aucun état, aucun script : le composant sert aux pages
// du serveur comme aux formulaires de la page.

import { CREDITS_EN_CLAIR, CREDITS_QUESTION } from "../lib/parcours.mjs";

export default function CreditsEnClair({ versement = null, classe = "" }) {
  return (
    <details className={["ins-detail ins-credits", classe].filter(Boolean).join(" ")} data-credits-en-clair="">
      <summary>{CREDITS_QUESTION}</summary>
      <p className="ins-detail-corps">{CREDITS_EN_CLAIR}{versement ? ` ${versement}` : ""}</p>
    </details>
  );
}
