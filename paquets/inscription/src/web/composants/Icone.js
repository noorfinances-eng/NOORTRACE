// Icônes du thème NOORTRACE (complément du 2026-11-17) : SVG écrits dans le HTML, tracés au trait dans une vue
// de 24 sur 24, sans image ni ressource externe. Une icône accompagne toujours un mot : elle est cachée aux
// lecteurs d'écran. Composant sans état, rendu par le serveur comme par la page.

const TRACES = {
  coche: [["path",{"d":"M5 12.5l4.5 4.5L19 7.5"}]],
  croix: [["path",{"d":"M6.5 6.5l11 11M17.5 6.5l-11 11"}]],
  horloge: [["circle",{"cx":"12","cy":"12","r":"8.5"}],["path",{"d":"M12 7.5V12l3 2"}]],
  sablier: [["path",{"d":"M7 4h10M7 20h10M8 4c0 4.2 4 4.6 4 8s-4 3.8-4 8M16 4c0 4.2-4 4.6-4 8s4 3.8 4 8"}]],
  info: [["circle",{"cx":"12","cy":"12","r":"8.5"}],["path",{"d":"M12 11v5.5M12 7.7v.3"}]],
  alerte: [["path",{"d":"M12 4.5l8.5 14.5h-17z"}],["path",{"d":"M12 10.5v3.5M12 16.6v.3"}]],
  question: [["circle",{"cx":"12","cy":"12","r":"8.5"}],["path",{"d":"M9.7 9.7a2.4 2.4 0 1 1 3.5 2.2c-.8.4-1.2 1-1.2 1.8M12 16.6v.3"}]],
  different: [["path",{"d":"M6 9.5h12M6 14.5h12M15.5 5.5l-7 13"}]],
  bouclier: [["path",{"d":"M12 3.5l7 2.5v5.5c0 4.3-2.9 7.6-7 9-4.1-1.4-7-4.7-7-9V6z"}],["path",{"d":"M8.8 12.2l2.4 2.4 4.2-4.6"}]],
  tiret: [["path",{"d":"M7 12h10"}]],
  point: [["circle",{"cx":"12","cy":"12","r":"3.4"}]],
  retour: [["path",{"d":"M10 6l-6 6 6 6M4 12h16"}]],
  dossier: [["path",{"d":"M3.5 8a2 2 0 0 1 2-2h4l2 2.5h7a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"}]],
  cadenas: [["rect",{"x":"5.5","y":"10.5","width":"13","height":"9","rx":"2"}],["path",{"d":"M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5"}]],
  boite: [["path",{"d":"M4 13.5l2.2-7.2A1.8 1.8 0 0 1 7.9 5h8.2a1.8 1.8 0 0 1 1.7 1.3L20 13.5V17a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"}],["path",{"d":"M4 13.5h4.5l1 2h5l1-2H20"}]],
  soleil: [["circle",{"cx":"12","cy":"12","r":"4.2"}],["path",{"d":"M12 2.8v2.4M12 18.8v2.4M21.2 12h-2.4M5.2 12H2.8M18.5 5.5l-1.7 1.7M7.2 16.8l-1.7 1.7M18.5 18.5l-1.7-1.7M7.2 7.2L5.5 5.5"}]],
  lune: [["path",{"d":"M20 14.2A8.3 8.3 0 0 1 9.8 4a8.3 8.3 0 1 0 10.2 10.2z"}]],
};

/** Icônes pleines (remplies, sans trait). */
const PLEINES = new Set(["point"]);

/** Noms des icônes. */
export const ICONES = Object.freeze(Object.keys(TRACES));

/** Une icône du thème ; un nom inconnu rend le point d'interrogation. */
export default function Icone({ nom, className = "" }) {
  const traces = TRACES[nom] ?? TRACES.question;
  const classes = ["nt-icone", PLEINES.has(nom) ? "nt-icone-pleine" : "", className].filter(Boolean).join(" ");
  return (
    <svg className={classes} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      {traces.map(([Element, attributs], k) => <Element key={k} {...attributs} />)}
    </svg>
  );
}

/** Le signe du logo NOORTRACE : un cadre arrondi et la lettre N en deux traits. */
export function SigneLogo() {
  return (
    <svg className="nt-logo-signe" viewBox="0 0 28 28" aria-hidden="true" focusable="false">
      <rect className="nt-logo-cadre" x="2.5" y="2.5" width="23" height="23" rx="6.5" />
      <path className="nt-logo-trait-1" d="M9 19.5v-11" />
      <path className="nt-logo-trait-2" d="M9 8.5l10 11v-11" />
    </svg>
  );
}
