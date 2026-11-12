// Erreur de la bibliothèque de la console (contrat de l'étape 6, 0.4) :
// un refus qui n'est pas rendu dans la valeur de retour lève `ErreurConsole`,
// de membre `code` (valeur de `$defs/code_console` de console-approbation-v0,
// de `$defs/code_erreur_annuaire` d'annuaire-approbateurs-v0, ou
// `identite_invalide`, CT-3 EX-13.7) et de membre `detail` (texte ASCII, sans
// valeur secrète). Une erreur de programmation (paramètre d'un autre type)
// lève `TypeError`.

/** Erreur de domaine de la bibliothèque. */
export class ErreurConsole extends Error {
  /**
   * @param {string} code
   * @param {string} [detail]
   */
  constructor(code, detail) {
    if (typeof code !== "string" || code === "") throw new TypeError("ErreurConsole : code attendu");
    if (detail !== undefined && typeof detail !== "string") throw new TypeError("ErreurConsole : detail doit etre une chaine");
    const texte = detail === undefined ? code : detail;
    super(texte);
    this.name = "ErreurConsole";
    this.code = code;
    this.detail = texte;
  }
}

/**
 * Lève une erreur de programmation.
 * @param {string} message
 * @returns {never}
 */
export function erreurType(message) {
  throw new TypeError(message);
}
