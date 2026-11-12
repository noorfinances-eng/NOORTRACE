// Aides des pages : session exigée (le mandataire l'a contrôlée ; la page la relit et renvoie à /connexion sinon).

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { COOKIE, configuration, session } from "./serveur.mjs";

/** Session de la page, ou renvoi à /connexion. */
export async function exigerSession() {
  const c = await cookies();
  const s = session(c.get(COOKIE)?.value);
  if (!s) redirect("/connexion");
  return s;
}

/** Nature déclarée par la configuration de l'interface (affichage seulement : l'agent tranche). */
export function nature() {
  return configuration().nature;
}
