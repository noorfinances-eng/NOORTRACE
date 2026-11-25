// GET /api/clients/<slug>/fiche-controle : la fiche de contrôle des adresses des approbateurs du client (CT-4 EX-7.8,
// complément du 2026-11-25, décision du porteur sur l'outil d'inscription ; INTERFACES.md 2.3, 2.7), en fichier
// texte canonique (UTF-8, une ligne par élément, sauts de ligne `\n`), produit à la demande depuis le dossier et les
// noms des approbateurs notés (note interne `noms_approbateurs`) :
// le même dossier donne les mêmes octets, dont le SHA-256 est l'empreinte que la confirmation du client cite. Route de
// lecture seulement ; rien ne part vers l'agent ni vers le registre public.

import { nomFichierFiche, octetsFiche } from "../../../../../../commun/fiche-controle.mjs";
import { client } from "../../../../../lib/donnees.mjs";
import { erreur, sessionDe } from "../../../../../lib/routes.mjs";

export const dynamic = "force-dynamic";

export async function GET(requete, { params }) {
  if (!sessionDe(requete)) return erreur(401, "session_absente", "session absente ou expirée");
  const { slug } = await params;
  const c = client(slug);
  if (!c) return erreur(404, "client_inconnu", "client inconnu");
  const octets = octetsFiche(c.dossier, c.fiche.noms);
  return new Response(octets, { status: 200, headers: { "content-type": "text/plain; charset=utf-8", "content-disposition": `attachment; filename="${nomFichierFiche(slug)}"`, "content-length": String(octets.length), "cache-control": "no-store" } });
}
