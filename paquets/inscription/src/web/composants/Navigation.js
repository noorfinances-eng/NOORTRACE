"use client";
// Navigation de la barre haute : l'écran courant est marqué (aria-current="page").

import { usePathname } from "next/navigation";

export default function Navigation() {
  const chemin = usePathname() ?? "";
  const nouveau = chemin === "/clients/nouveau";
  const clients = chemin.startsWith("/clients") && !nouveau;
  return (
    <nav aria-label="Écrans de l'outil">
      <ul className="nt-nav">
        <li><a href="/clients" aria-current={clients ? "page" : undefined}>Clients</a></li>
        <li><a href="/clients/nouveau" aria-current={nouveau ? "page" : undefined}>Nouveau client</a></li>
      </ul>
    </nav>
  );
}
