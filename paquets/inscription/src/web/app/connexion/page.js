// /connexion : nom et mot de passe du compte d'exploitant (route publique, INTERFACES.md 2.1).

import Connexion from "../../composants/Connexion.js";

export const dynamic = "force-dynamic";

export default function PageConnexion() {
  return (
    <main className="nt-page nt-page-etroite">
      <header className="nt-entete">
        <div className="nt-entete-texte">
          <p className="nt-sur-titre">Inscription des clients</p>
          <h1>Connexion</h1>
          <p className="nt-sous-titre">Cet outil sert à l'exploitant du registre pour inscrire un client. Entrez le nom et le mot de passe de votre compte.</p>
        </div>
      </header>
      <section className="nt-carte" aria-label="Connexion">
        <Connexion />
      </section>
    </main>
  );
}
