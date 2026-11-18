// /connexion : nom et mot de passe du compte de la personne qui inscrit les clients (route publique,
// INTERFACES.md 2.1). Langage : complément du 2026-11-18, décision du porteur (langage des écrans).

import Connexion from "../../composants/Connexion.js";

export const dynamic = "force-dynamic";

export default function PageConnexion() {
  return (
    <main className="nt-page nt-page-etroite">
      <header className="nt-entete">
        <div className="nt-entete-texte">
          <p className="nt-sur-titre">Inscription des clients</p>
          <h1>Connexion</h1>
          <p className="nt-sous-titre">Cet outil sert à notre équipe pour inscrire un nouveau client sur le registre public : un registre que personne ne peut modifier après coup. Entrez le nom et le mot de passe de votre compte.</p>
        </div>
      </header>
      <section className="nt-carte" aria-label="Connexion">
        <Connexion />
      </section>
      <p className="nt-attenue nt-petit">Vous étiez connecté et l'outil vous ramène ici ? Votre connexion a pris fin : elle dure huit heures au plus. Reconnectez-vous ; rien de ce qui était fait n'est perdu.</p>
    </main>
  );
}
