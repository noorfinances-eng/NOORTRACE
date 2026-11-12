// POST /api/clients/<slug>/confirmations : remet une confirmation hors bande à l'agent (EX-7.26), au nom de
// l'exploitant de la session ; GET : le registre des confirmations du client.

import { remettreConfirmation, ErreurAgent } from "../../../../../../agent/client.mjs";
import { ErreurChamp } from "../../../../../../commun/champs.mjs";
import { lireConfirmation } from "../../../../../../commun/travaux.mjs";
import { client, confirmations } from "../../../../../lib/donnees.mjs";
import { configuration } from "../../../../../lib/serveur.mjs";
import { corps, erreur, json, sessionDe } from "../../../../../lib/routes.mjs";

export const dynamic = "force-dynamic";

export async function GET(requete, { params }) {
  if (!sessionDe(requete)) return erreur(401, "session_absente", "session absente ou expirée");
  const { slug } = await params;
  if (!client(slug)) return erreur(404, "client_inconnu", "client inconnu");
  return json(200, { confirmations: confirmations(slug) });
}

export async function POST(requete, { params }) {
  const s = sessionDe(requete);
  if (!s) return erreur(401, "session_absente", "session absente ou expirée");
  const { slug } = await params;
  const c = client(slug);
  if (!c) return erreur(404, "client_inconnu", "client inconnu");
  const b = await corps(requete);
  if (b.reponse) return b.reponse;
  let confirmation;
  try {
    confirmation = lireConfirmation(b.valeur);
  } catch (e) {
    if (e instanceof ErreurChamp) return erreur(400, e.code, e.message);
    throw e;
  }
  if (confirmation.objet.org_id !== c.dossier.organisation.org_id) return erreur(400, "requete_invalide", "objet.org_id n'est pas celui du client");
  let r;
  try {
    r = await remettreConfirmation(configuration().prise, s.identite, confirmation);
  } catch (e) {
    if (e instanceof ErreurAgent) return erreur(503, "agent_injoignable", "l'agent ne répond pas");
    throw e;
  }
  if (!r.accepte) return erreur(400, r.code, r.message);
  return json(200, { id: r.id });
}
