// Identité de session (CT-3 EX-13.7, EX-12.13) : chaîne canonique
// « oidc <iss> <sub> » ou « utilisateur <domaine> <nom> », trois jetons
// d'ASCII imprimable sans espace séparés par une espace, au plus 256
// caractères ; motif `$defs/identite_session` d'annuaire-approbateurs-v0
// (l'émetteur `iss` est une URL https sans « ? » ni « # »). Comparée octet
// pour octet ; jamais un courriel, un nom affiché ni `preferred_username`.

import { ErreurConsole } from "./erreurs.mjs";

const MOTIF_IDENTITE = /^(oidc https:\/\/[!-"$->@-~]+ [!-~]{1,255}|utilisateur [!-~]{1,128} [!-~]{1,255})$/;
const LONGUEUR_MAX = 256;

/**
 * Vrai pour une identité de session canonique (EX-13.7).
 * @param {unknown} valeur
 * @returns {boolean}
 */
export function estIdentiteCanonique(valeur) {
  return typeof valeur === "string" && valeur.length >= 1 && valeur.length <= LONGUEUR_MAX && MOTIF_IDENTITE.test(valeur);
}

/**
 * Analyse une identité de session canonique.
 * @param {string} texte
 * @returns {{systeme: "oidc", iss: string, sub: string}|{systeme: "utilisateur", domaine: string, nom: string}}
 * @throws {ErreurConsole} `identite_invalide`
 */
export function analyserIdentite(texte) {
  if (typeof texte !== "string") throw new TypeError("analyserIdentite : chaine attendue");
  if (!estIdentiteCanonique(texte)) throw new ErreurConsole("identite_invalide", "identite de session hors de la forme canonique (EX-13.7)");
  const [systeme, a, b] = texte.split(" ");
  return systeme === "oidc" ? { systeme: "oidc", iss: a, sub: b } : { systeme: "utilisateur", domaine: a, nom: b };
}

/**
 * Forme canonique d'une identité donnée par ses champs (forme rendue par
 * `analyserIdentite`, sans autre membre).
 * @param {{systeme: string, iss?: string, sub?: string, domaine?: string, nom?: string}} champs
 * @returns {string}
 * @throws {ErreurConsole} `identite_invalide`
 */
export function identiteCanonique(champs) {
  if (champs === null || typeof champs !== "object" || Array.isArray(champs)) {
    throw new TypeError("identiteCanonique : objet attendu");
  }
  const cles = Object.keys(champs).sort().join(",");
  let texte = null;
  if (champs.systeme === "oidc" && cles === "iss,sub,systeme" && typeof champs.iss === "string" && typeof champs.sub === "string") {
    texte = `oidc ${champs.iss} ${champs.sub}`;
  } else if (
    champs.systeme === "utilisateur" &&
    cles === "domaine,nom,systeme" &&
    typeof champs.domaine === "string" &&
    typeof champs.nom === "string"
  ) {
    texte = `utilisateur ${champs.domaine} ${champs.nom}`;
  }
  if (texte === null || !estIdentiteCanonique(texte)) {
    throw new ErreurConsole("identite_invalide", "champs d'identite hors de la forme canonique (EX-13.7)");
  }
  return texte;
}
