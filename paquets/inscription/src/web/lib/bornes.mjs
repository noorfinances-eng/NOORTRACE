// Bornes des requêtes de l'interface (INTERFACES.md 2.3), sans dépendance :
// partagées par les routes (lib/routes.mjs), la configuration de Next
// (next.config.mjs) et le serveur de l'interface
// (bin/noortrace-inscription-web).

/** Taille maximale d'un corps de requête (une demande signée tient en moins de 64 Kio). */
export const CORPS_MAX = 256 * 1024;

/** Délai d'une requête entière, corps compris (un envoi lent ne tient pas une connexion au-delà). */
export const DELAI_REQUETE_MS = 60000;
