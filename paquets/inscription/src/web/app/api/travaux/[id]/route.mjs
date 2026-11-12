// GET /api/travaux/<id> : l'enregistrement du travail ($defs/travail, INTERFACES.md 3.3).

import { travail } from "../../../../lib/donnees.mjs";
import { erreur, json, sessionDe } from "../../../../lib/routes.mjs";

export const dynamic = "force-dynamic";

export async function GET(requete, { params }) {
  if (!sessionDe(requete)) return erreur(401, "session_absente", "session absente ou expirée");
  const { id } = await params;
  const t = travail(id);
  if (!t) return erreur(404, "travail_inconnu", "travail inconnu");
  return json(200, t);
}
