// /connexion : nom et mot de passe du compte d'exploitant (route publique, INTERFACES.md 2.1).

import Connexion from "../../composants/Connexion.js";

export const dynamic = "force-dynamic";

export default function PageConnexion() {
  return (
    <>
      <h1>Connexion</h1>
      <Connexion />
    </>
  );
}
