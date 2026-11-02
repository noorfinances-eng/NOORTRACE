// Copies WORM (CT-2 §12.6), en interface seulement dans ce lot. Quand
// `storage.seal.worm` est configuré, chaque segment fermé, chaque manifeste et
// sa signature, la série des points de chaque période close et, avec
// `copy_pieces`, les pièces sont copiés vers le support après fermeture, sous
// la clé `<prefix>` + chemin relatif de 12.1 (EX-12.16), écriture
// conditionnelle à l'absence de l'objet ; une copie en échec est réessayée
// par la supervision et ne bloque jamais un appel (14.2). Le registre des
// copies (EX-12.29), le contrôle du verrou (EX-12.33), le relevé (EX-17.6) et
// le gel juridique (12.11) relèvent du lot WORM.

/**
 * Clé d'objet WORM d'un fichier du journal (EX-12.16) : le préfixe concaténé
 * tel quel au chemin relatif de 12.1, sans séparateur ajouté.
 * @param {string} prefixe `storage.seal.worm.prefix`
 * @param {string} cheminRelatif chemin relatif au répertoire du journal, séparateur `/`
 * @returns {string}
 */
export function cleObjetWorm(prefixe, cheminRelatif) {
  return `${prefixe}${cheminRelatif}`;
}

/**
 * Interface d'un support WORM vu de l'écrivain.
 * @abstract
 */
export class SupportWorm {
  /**
   * Copie un fichier fermé ; jamais d'écrasement (If-None-Match: *).
   * @param {{cle: string, chemin: string, nature: "segment"|"manifeste"|"signature"|"points"|"piece"}} demande
   * @returns {Promise<{version_id: string|null}>}
   */
  async copier(demande) {
    void demande;
    return { version_id: null };
  }
}

/** Support absent (`storage.seal.worm: null`) : aucune copie. */
export class SupportWormAbsent extends SupportWorm {}

/** Support qui garde les demandes en mémoire (tests). */
export class SupportWormMemoire extends SupportWorm {
  constructor() {
    super();
    this.copies = [];
  }

  async copier(demande) {
    this.copies.push(demande);
    return { version_id: null };
  }
}
