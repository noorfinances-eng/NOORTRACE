// POST /api/deconnexion {} : ferme la session (204).

import { cookieDe, enteteCookie, fermerSession } from "../../../lib/serveur.mjs";
import { corps, erreur, json, sessionDe } from "../../../lib/routes.mjs";

export const dynamic = "force-dynamic";

export async function POST(requete) {
  if (!sessionDe(requete)) return erreur(401, "session_absente", "session absente ou expirée");
  const c = await corps(requete);
  if (c.reponse) return c.reponse;
  if (!c.valeur || typeof c.valeur !== "object" || Array.isArray(c.valeur) || Object.keys(c.valeur).length !== 0) return erreur(400, "requete_invalide", "{} attendu");
  fermerSession(cookieDe(requete.headers.get("cookie")));
  return json(204, null, { "set-cookie": enteteCookie("", { effacer: true }) });
}
