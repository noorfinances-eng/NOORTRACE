// GET /api/clients : clients connus, état de chaque étape (EX-7.16), dernier travail.

import { clients } from "../../../lib/donnees.mjs";
import { erreur, json, sessionDe } from "../../../lib/routes.mjs";

export const dynamic = "force-dynamic";

export async function GET(requete) {
  if (!sessionDe(requete)) return erreur(401, "session_absente", "session absente ou expirée");
  return json(200, { clients: clients() });
}
