// GET /api/clients/<slug>/paquet : archive `tar` (POSIX ustar) du dernier paquet produit, produite à la demande, après
// le contrôle d'EX-7.22 (INTERFACES.md 4.2) ; le registre des confirmations n'y entre pas. Un paquet qui ne passe pas le
// contrôle rend 409 avec la sortie de `paquet-client controler` (EX-7.30).

import { sortieControle } from "../../../../../../commun/paquet.mjs";
import { etatPaquet } from "../../../../../lib/donnees.mjs";
import { archiver } from "../../../../../lib/tar.mjs";
import { erreur, sessionDe } from "../../../../../lib/routes.mjs";

export const dynamic = "force-dynamic";

export async function GET(requete, { params }) {
  if (!sessionDe(requete)) return erreur(401, "session_absente", "session absente ou expirée");
  const { slug } = await params;
  const p = etatPaquet(slug);
  if (!p || !p.present) return erreur(404, "paquet_absent", "aucun paquet produit pour ce client");
  const controle = sortieControle(p.repertoire);
  if (controle.result !== "reussi") return erreur(409, controle.error.code, controle.error.message, { sortie: controle });
  const octets = archiver(p.repertoire);
  return new Response(octets, { status: 200, headers: { "content-type": "application/x-tar", "content-disposition": `attachment; filename="paquet-client-${slug}.tar"`, "content-length": String(octets.length), "cache-control": "no-store" } });
}
