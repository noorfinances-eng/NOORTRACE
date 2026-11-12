// Libellés des écrans de la console (contrat de l'étape 6, 3.6 ; CT-3
// EX-13.29, EX-13.33 point 8) : chaque texte affiché vient d'une table
// `{ cle: texte }` de /statique/libelles/, choisie selon la langue du document
// (`document.documentElement.lang`). La table française est la table de
// repli ; une autre langue s'ajoute par un fichier `<langue>.mjs` de mêmes
// clés, sans autre changement de code (le générateur la nomme dans la carte
// d'importation). Un texte à paramètres porte `{nom}`, remplacé par
// `String(valeurs.nom)`.

import fr from "../libelles/fr.mjs";

const langue = document.documentElement.lang;
let table = fr;
if (langue !== "fr" && /^[a-z]{2,3}$/.test(langue)) {
  try {
    table = (await import(`../libelles/${langue}.mjs`)).default;
  } catch {
    table = fr;
  }
}

/**
 * Texte de la clé, paramètres remplacés ; la clé elle-même si la table ne la
 * porte pas (l'essai des pages exige que chaque clé employée existe).
 * @param {string} cle
 * @param {Record<string, unknown>} [valeurs]
 * @returns {string}
 */
export function t(cle, valeurs = {}) {
  const modele = Object.prototype.hasOwnProperty.call(table, cle) ? table[cle] : cle;
  return modele.replace(/\{([a-z_]+)\}/g, (tout, nom) => (Object.prototype.hasOwnProperty.call(valeurs, nom) ? String(valeurs[nom]) : tout));
}

/** Vrai si la table porte la clé. */
export function aCle(cle) {
  return Object.prototype.hasOwnProperty.call(table, cle);
}

/**
 * Texte d'un code suivi du code entre parenthèses (EX-13.29) : la première
 * clé présente parmi les préfixes donnés, dans l'ordre.
 * @param {string} code
 * @param {string[]} prefixes par exemple `["inscription.", "console."]`
 * @returns {string}
 */
export function texteCode(code, prefixes) {
  for (const p of prefixes) {
    if (aCle(p + code)) return `${t(p + code)} (${code})`;
  }
  return `${t("erreur.inconnue")} (${code})`;
}
