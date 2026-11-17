// Barre haute commune aux écrans (complément du 2026-11-17) : le mot NOORTRACE et le nom de l'outil, la
// navigation, l'identité de la session en entier, la déconnexion et la bascule de thème. Sans session (écran de
// connexion), ni navigation ni identité.

import { SigneLogo } from "./Icone.js";
import BasculeTheme from "./BasculeTheme.js";
import Deconnexion from "./Deconnexion.js";
import Navigation from "./Navigation.js";

export default function Barre({ identite }) {
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
            <p className="nt-session"><span className="nt-session-libelle">Session</span><span className="nt-fixe">{identite}</span></p>
            <Deconnexion />
          </div>
        ) : null}
        <div className="nt-barre-outils"><BasculeTheme /></div>
      </div>
    </header>
  );
}
