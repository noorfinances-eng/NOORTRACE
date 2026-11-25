// GET /api/clients/<slug> : dossier, travaux et sorties du client, demandes de signature préparées et relayées ; complément
// du 2026-11-25 (CT-4 EX-7.9, EX-7.8) : les frais de l'instance que l'agent applique (`frais`, ou null) et l'empreinte de la
// fiche de contrôle des adresses des approbateurs (`fiche.sha256`), avec le dossier qui donne déjà le montant et la
// consommation prévue.

import { client } from "../../../../lib/donnees.mjs";
import { erreur, json, sessionDe } from "../../../../lib/routes.mjs";

export const dynamic = "force-dynamic";

export async function GET(requete, { params }) {
  if (!sessionDe(requete)) return erreur(401, "session_absente", "session absente ou expirée");
  const { slug } = await params;
  const c = client(slug);
  if (!c) return erreur(404, "client_inconnu", "client inconnu");
  return json(200, { slug: c.slug, dossier: c.dossier, travaux: c.travaux, demandes: c.demandes, periodes: c.periodes, parties: c.parties, paquet: { present: c.paquet.present, dernier: c.paquet.dernier }, frais: c.frais, fiche: c.fiche });
}
