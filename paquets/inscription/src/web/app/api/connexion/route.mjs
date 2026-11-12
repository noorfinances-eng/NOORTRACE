// POST /api/connexion { name, password } : ouvre une session (204), 401
// identifiants refusés, 429 essai trop tôt (verrou progressif, INTERFACES.md 1).

import { connecter, cookieDe, enteteCookie, fermerSession } from "../../../lib/serveur.mjs";
import { corps, erreur, json } from "../../../lib/routes.mjs";

export const dynamic = "force-dynamic";

export async function POST(requete) {
  const c = await corps(requete);
  if (c.reponse) return c.reponse;
  const v = c.valeur;
  if (!v || typeof v !== "object" || Array.isArray(v) || Object.keys(v).sort().join(",") !== "name,password" || typeof v.name !== "string" || typeof v.password !== "string" || v.name.length > 255 || v.password.length > 1024) {
    return erreur(400, "requete_invalide", "{ name, password } attendu");
  }
  const r = await connecter(v.name, v.password);
  if (r.statut === 429) return erreur(429, r.code, "trop d'échecs récents : réessayer plus tard", { retry_after_s: r.retry_after_s });
  if (r.statut === 401) return erreur(401, r.code, "nom ou mot de passe refusé");
  // Un succès détruit la session que portait la requête, s'il y en avait une.
  fermerSession(cookieDe(requete.headers.get("cookie")));
  return json(204, null, { "set-cookie": enteteCookie(r.session) });
}
