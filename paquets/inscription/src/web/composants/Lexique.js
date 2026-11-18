// Lexique replié, au bas de chaque écran (complément du 2026-11-18, décision du porteur sur le langage des
// écrans) : chaque mot de l'outil avec son explication en une demi-phrase. Les écrans expliquent déjà, dans leur
// texte, les mots dont ils se servent d'abord ; le lexique les réunit tous.

import { LEXIQUE } from "../lib/parcours.mjs";

export default function Lexique() {
  return (
    <details className="nt-detail nt-sans-impression" data-lexique="">
      <summary>Les mots de cet outil<span className="nt-detail-note">{LEXIQUE.length} mots expliqués</span></summary>
      <dl className="nt-detail-corps nt-definitions">
        {LEXIQUE.map((x) => (
          <div className="ins-contenu" key={x.terme}>
            <dt>{x.terme}</dt>
            <dd>{x.explication}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}
