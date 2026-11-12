// Outils communs du serveur de console (CT-3 13.20, 13.21) : base64url
// strict, instants (CT-1 §3), comparaison en temps constant, journal du
// serveur (une ligne JSON par événement sur la sortie d'erreur, contrat 2.13),
// erreur de démarrage (code de sortie 1).

import crypto from "node:crypto";
import tls from "node:tls";

/**
 * Autorités du magasin du système (CT-3 EX-13.42, EX-13.45 : « le magasin du
 * système »), et non la liste intégrée de Node : passées explicitement comme
 * `ca` à chaque requête HTTPS qui n'a ni autorité configurée ni agent
 * d'essai. Lues à chaque appel (Node garde sa propre copie).
 * @returns {string[]}
 */
export const magasinSysteme = () => tls.getCACertificates("system");

/** Erreur qui arrête le démarrage du serveur (code de sortie 1). */
export class ErreurDemarrage extends Error {
  /**
   * @param {string} message texte sans valeur secrète
   * @param {{rapport?: object, pointeur?: string}} [details]
   */
  constructor(message, details = {}) {
    super(message);
    this.name = "ErreurDemarrage";
    this.rapport = details.rapport ?? null;
    this.pointeur = details.pointeur ?? null;
  }
}

const BASE64URL = /^[A-Za-z0-9_-]*$/;

/** Octets en base64url sans remplissage. */
export const b64u = (octets) => Buffer.from(octets).toString("base64url");

/**
 * Décode un base64url sans remplissage, canonique (le réencodage rend le même
 * texte) ; `null` sinon.
 * @param {string} texte
 * @returns {Buffer|null}
 */
export function deB64u(texte) {
  if (typeof texte !== "string" || !BASE64URL.test(texte) || texte.length % 4 === 1) return null;
  const o = Buffer.from(texte, "base64url");
  return o.toString("base64url") === texte ? o : null;
}

/** Instant CT-1 §3 (`AAAA-MM-JJTHH:MM:SS.mmmZ`) d'un nombre de millisecondes. */
export const horodatage = (ms) => new Date(ms).toISOString();

/** Égalité de deux suites d'octets en temps constant (la longueur n'est pas secrète). */
export function egauxTempsConstant(a, b) {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  if (x.length !== y.length) {
    crypto.timingSafeEqual(x, x);
    return false;
  }
  return crypto.timingSafeEqual(x, y);
}

/**
 * Journal du serveur : `{ "ts", "event", "data" }` sur la sortie d'erreur.
 * Les appelants n'y mettent jamais un jeton, un secret, une valeur de cookie,
 * un mot de passe, un code d'autorisation ni un corps.
 * @param {() => number} horloge
 * @returns {(event: string, data?: object) => void}
 */
export function creerJournal(horloge) {
  return (event, data = {}) => {
    process.stderr.write(JSON.stringify({ ts: horodatage(horloge()), event, data }) + "\n");
  };
}

/** Retire les blancs ASCII de tête et de fin (espace, tabulation, fins de ligne). */
export function retirerBlancs(texte) {
  return texte.replace(/^[\t\n\v\f\r ]+|[\t\n\v\f\r ]+$/g, "");
}

/**
 * Blocs PEM d'un type donné, dans l'ordre du texte.
 * @param {string} texte
 * @param {string} type par exemple `CERTIFICATE`
 * @returns {string[]}
 */
export function blocsPem(texte, type) {
  const motif = new RegExp(`-----BEGIN ${type}-----\\r?\\n[\\s\\S]*?-----END ${type}-----`, "g");
  return [...texte.matchAll(motif)].map((m) => m[0] + "\n");
}

/** Motif d'un identifiant de ticket (EX-7.1, EX-13.43). */
const TICKET = /^apr-[0-9a-z]+(-[0-9a-z]+)*$/;

/** Vrai pour un segment `<ticket>` admis sous `/tickets/` (motif, 5 à 128 caractères). */
export const estTicket = (s) => typeof s === "string" && s.length >= 5 && s.length <= 128 && TICKET.test(s);

/**
 * Chemin `retour` retenu (EX-13.43) : un chemin d'écran de la table, `/tickets`
 * sinon ; aucune redirection ouverte.
 * @param {unknown} retour
 * @returns {string}
 */
export function retourRetenu(retour) {
  if (retour === "/tickets" || retour === "/inscription" || retour === "/annuaire") return retour;
  if (typeof retour === "string" && retour.startsWith("/tickets/") && estTicket(retour.slice(9))) return retour;
  return "/tickets";
}
