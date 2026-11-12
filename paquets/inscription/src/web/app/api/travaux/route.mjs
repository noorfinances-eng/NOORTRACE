// POST /api/travaux : un travail typé (INTERFACES.md 3.3), sans identité ; contrôlé champ par champ
// (src/commun/travaux.mjs), puis remis à l'agent avec l'identité de la session. Rend { id }, 400 (forme ou refus de
// l'agent, dont « confirmation hors bande absente »), 503 (agent injoignable). Aucune valeur refusée n'est recopiée.

import { remettreTravail, ErreurAgent } from "../../../../agent/client.mjs";
import { ErreurChamp } from "../../../../commun/champs.mjs";
import { lireTravail } from "../../../../commun/travaux.mjs";
import { configuration } from "../../../lib/serveur.mjs";
import { corps, erreur, json, sessionDe } from "../../../lib/routes.mjs";

export const dynamic = "force-dynamic";

export async function POST(requete) {
  const s = sessionDe(requete);
  if (!s) return erreur(401, "session_absente", "session absente ou expirée");
  const b = await corps(requete);
  if (b.reponse) return b.reponse;
  let travail;
  try {
    travail = lireTravail(b.valeur, { production: configuration().nature === "production" });
  } catch (e) {
    if (e instanceof ErreurChamp) return erreur(400, e.code, e.message);
    throw e;
  }
  let r;
  try {
    r = await remettreTravail(configuration().prise, s.identite, travail);
  } catch (e) {
    if (e instanceof ErreurAgent) return erreur(503, "agent_injoignable", "l'agent ne répond pas");
    throw e;
  }
  if (!r.accepte) return erreur(400, r.code, r.code === "confirmation_absente" ? `confirmation hors bande absente : ${r.message}` : r.message);
  return json(200, { id: r.id });
}
