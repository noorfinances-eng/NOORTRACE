// POST /api/clients/<slug>/notes : remet à l'agent une note interne sur le client (CT-4 EX-7.23, complément du
// 2026-11-19, décision du porteur sur le suivi interne des clients ; INTERFACES.md 2.6) : son nom interne, la remise
// de son paquet, ou la correction d'une remise, au nom de l'exploitant de la session. Corps `{ sorte, … }`, sans
// l'organisation : la route la prend du dossier du client. Rend { id }, 400 (forme, ou refus de l'agent), 404, 503.
// Une note ne part jamais vers le registre public ; aucune valeur refusée n'est recopiée.

import { remettreNote, ErreurAgent } from "../../../../../../agent/client.mjs";
import { ErreurChamp } from "../../../../../../commun/champs.mjs";
import { lireCorpsNote } from "../../../../../../commun/notes.mjs";
import { client } from "../../../../../lib/donnees.mjs";
import { configuration } from "../../../../../lib/serveur.mjs";
import { corps, erreur, json, sessionDe } from "../../../../../lib/routes.mjs";

export const dynamic = "force-dynamic";

export async function POST(requete, { params }) {
  const s = sessionDe(requete);
  if (!s) return erreur(401, "session_absente", "session absente ou expirée");
  const { slug } = await params;
  const c = client(slug);
  if (!c) return erreur(404, "client_inconnu", "client inconnu");
  const b = await corps(requete);
  if (b.reponse) return b.reponse;
  let note;
  try {
    note = lireCorpsNote(b.valeur);
  } catch (e) {
    if (e instanceof ErreurChamp) return erreur(400, e.code, e.message);
    throw e;
  }
  let r;
  try {
    r = await remettreNote(configuration().prise, s.identite, { sorte: note.sorte, org_id: c.dossier.organisation.org_id, ...note });
  } catch (e) {
    if (e instanceof ErreurAgent) return erreur(503, "agent_injoignable", "l'agent ne répond pas");
    throw e;
  }
  if (!r.accepte) return erreur(400, r.code, r.message);
  return json(200, { id: r.id });
}
