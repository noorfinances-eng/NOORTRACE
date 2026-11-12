// Gabarit des pages de l'interface d'exploitant (CT-4 §7.14) : aucune ressource d'une autre origine.

import "./globals.css";

export const metadata = {
  title: "Inscription des clients",
  description: "Application d'exploitant : inscription des clients au registre (CT-4 §7.14)",
};

export const dynamic = "force-dynamic";

export default function Racine({ children }) {
  return (
    <html lang="fr">
      <body>
        <header>
          <strong>Inscription des clients</strong>
          <nav>
            <a href="/clients">Clients</a> · <a href="/clients/nouveau">Nouveau client</a>
          </nav>
        </header>
        <main>{children}</main>
      </body>
    </html>
  );
}
