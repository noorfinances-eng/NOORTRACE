// Barre haute commune aux écrans (complément du 2026-11-17) : le mot NOORTRACE et le nom de l'outil, la
// navigation, la personne connectée, la déconnexion et la bascule de thème. Sans session (écran de connexion), ni
// navigation ni nom. Complément du 2026-11-18 (langage des écrans) : « Connecté : » suivi du nom du compte, tel
// quel ; l'identité de session entière (INTERFACES.md 1) reste lisible dans l'info-bulle et l'attribut
// `data-identite`.

import { SigneLogo } from "./Icone.js";
import BasculeTheme from "./BasculeTheme.js";
import Deconnexion from "./Deconnexion.js";
import Navigation from "./Navigation.js";
import Valeur from "./Valeur.js";

export default function Barre({ nom, identite }) {
  return (
    <header className="nt-barre">
      <div className="nt-barre-dedans">
        <a className="nt-logo" href={identite ? "/clients" : "/connexion"}>
          <SigneLogo />
          <span className="nt-logo-texte">
            <span className="nt-logo-mot">NOOR<span className="nt-logo-accent">TRACE</span></span>
            <span className="nt-outil">Inscription des clients</span>
          </span>
        </a>
        {identite ? <Navigation /> : null}
        {identite ? (
          <div className="nt-barre-fin">
            <p className="nt-session" title={`Identité de session : ${identite}`} data-identite={identite}><span className="nt-session-libelle">Connecté :</span> <Valeur>{nom}</Valeur></p>
            <Deconnexion />
          </div>
        ) : null}
        <div className="nt-barre-outils"><BasculeTheme /></div>
      </div>
    </header>
  );
}
