// Gabarit des pages de l'interface d'exploitant (CT-4 §7.14) : aucune ressource d'une autre origine.
//
// Présentation (complément du 2026-11-17, décision du porteur sur la présentation des écrans) : thème commun des
// écrans NOORTRACE (globals.css), barre haute commune, deux états d'affichage. L'état sombre est celui du document
// sans attribut ; l'état clair mémorisé par le navigateur est posé avant le premier affichage par une amorce de
// quelques octets, en script à nonce : la politique de sécurité du contenu (proxy.mjs) n'est pas assouplie.
//
// Langage (complément du 2026-11-18, décision du porteur sur le langage des écrans) : la barre dit qui est
// connecté ; hors production, un bandeau dit en clair que l'on est en mode essai ; le pied de page dit ce que
// l'outil ne demande jamais et dans quelle heure il affiche les dates.

import "./globals.css";
import { cookies, headers } from "next/headers";
import Barre from "../composants/Barre.js";
import Impression from "../composants/Impression.js";
import { COOKIE, configuration, session } from "../lib/serveur.mjs";
import { AMORCE_THEME, COULEUR_BARRE } from "../lib/theme.mjs";

export const metadata = {
  title: "Inscription des clients · NOORTRACE",
  description: "Outil de notre équipe pour inscrire un client sur le registre public",
};

export const viewport = { width: "device-width", initialScale: 1, themeColor: COULEUR_BARRE.sombre };

export const dynamic = "force-dynamic";

/** Le registre de cette interface est-il un réseau d'essai ? (affichage seulement : l'agent tranche) */
function reseauEssai() {
  try {
    return configuration().nature !== "production";
  } catch {
    return false;
  }
}

export default async function Racine({ children }) {
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  const s = session((await cookies()).get(COOKIE)?.value);
  return (
    <html lang="fr" suppressHydrationWarning>
      <head>
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: AMORCE_THEME }} />
      </head>
      <body>
        <Barre nom={s?.nom ?? null} identite={s?.identite ?? null} />
        {s && reseauEssai() ? (
          <p className="ins-reseau" data-reseau-essai>
            <strong>Mode essai :</strong> rien de ce que vous faites ici ne touche le registre réel.
          </p>
        ) : null}
        {children}
        <Impression />
        <footer className="nt-pied">
          NOORTRACE · Inscription des clients. Aucune clé secrète de signature n'est demandée dans cet outil : seulement des adresses et des documents publics. Les heures affichées sont en temps universel (UTC), pas à l'heure de votre montre.
        </footer>
      </body>
    </html>
  );
}
