// Gabarit des pages de l'interface d'exploitant (CT-4 §7.14) : aucune ressource d'une autre origine.
//
// Présentation (complément du 2026-11-17, décision du porteur sur la présentation des écrans) : thème commun des
// écrans NOORTRACE (globals.css), barre haute commune, deux états d'affichage. L'état sombre est celui du document
// sans attribut ; l'état clair mémorisé par le navigateur est posé avant le premier affichage par une amorce de
// quelques octets, en script à nonce : la politique de sécurité du contenu (proxy.mjs) n'est pas assouplie.

import "./globals.css";
import { cookies, headers } from "next/headers";
import Barre from "../composants/Barre.js";
import Impression from "../composants/Impression.js";
import { COOKIE, configuration, session } from "../lib/serveur.mjs";
import { AMORCE_THEME, COULEUR_BARRE } from "../lib/theme.mjs";

export const metadata = {
  title: "Inscription des clients · NOORTRACE",
  description: "Application d'exploitant : inscription des clients au registre (CT-4 §7.14)",
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
        <Barre identite={s?.identite ?? null} />
        {s && reseauEssai() ? (
          <p className="ins-reseau" data-reseau-essai>
            <strong>Réseau d'essai.</strong> Rien de ce qui se fait ici ne vaut pour le registre de production.
          </p>
        ) : null}
        {children}
        <Impression />
        <footer className="nt-pied">NOORTRACE · Inscription des clients au registre. Aucune clé ne se saisit dans cet outil.</footer>
      </body>
    </html>
  );
}
