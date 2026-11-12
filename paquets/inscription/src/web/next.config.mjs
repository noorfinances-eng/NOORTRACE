// Configuration Next.js de l'interface d'exploitant (INTERFACES.md 2) :
// optimisation des images désactivée (la route d'optimisation n'est pas
// servie), aucun en-tête permissif (la politique de sécurité du contenu et les
// en-têtes de sécurité sont posés par proxy.mjs à chaque réponse), extensions
// des pages et des routes `.js` et `.mjs`. Les modules de src/commun/ et
// src/agent/client.mjs sont importés hors du répertoire du projet : la racine
// de traçage et celle de Turbopack sont la racine du dépôt, où sont les
// dépendances de l'espace de travail ; aucun module n'est copié. Le corps
// qu'un mandataire (`proxy`) de Next retient avant la route est borné à
// `CORPS_MAX` + 1 octets (au-delà, Next le tronque et la route rend 413) au
// lieu des 10 Mio par défaut.

import path from "node:path";
import { fileURLToPath } from "node:url";
import { CORPS_MAX } from "./lib/bornes.mjs";

const ICI = path.dirname(fileURLToPath(import.meta.url));
const RACINE = path.resolve(ICI, "..", "..", "..", "..");

/** @type {import("next").NextConfig} */
const configuration = {
  pageExtensions: ["js", "mjs"],
  images: { unoptimized: true },
  poweredByHeader: false,
  reactStrictMode: true,
  outputFileTracingRoot: RACINE,
  turbopack: { root: RACINE },
  experimental: { proxyClientMaxBodySize: CORPS_MAX + 1 },
};

export default configuration;
