// GET /api/clients/<slug> : dossier, travaux et sorties du client, demandes de signature préparées et relayées.

import { client } from "../../../../lib/donnees.mjs";
import { erreur, json, sessionDe } from "../../../../lib/routes.mjs";

export const dynamic = "force-dynamic";

export async function GET(requete, { params }) {
  if (!sessionDe(requete)) return erreur(401, "session_absente", "session absente ou expirée");
  const { slug } = await params;
  const c = client(slug);
  if (!c) return erreur(404, "client_inconnu", "client inconnu");
  return json(200, { slug: c.slug, dossier: c.dossier, travaux: c.travaux, demandes: c.demandes, periodes: c.periodes, parties: c.parties, paquet: { present: c.paquet.present, dernier: c.paquet.dernier } });
}
