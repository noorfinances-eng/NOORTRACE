// Erreurs du cœur de l'enregistreur. Une erreur porte la raison de la
// matrice de CT-2 §14.2 (`stockage`, `cle`, `bail`, `horloge`, `attente`,
// `approbation`, `redaction`, `bail_non_detenu`) et le code JSON-RPC que le
// frontal rendra (table de CT-2 §4.4 : -31010 avant relais, -31017 après
// relais, EX-4.46). Le cœur ne rend jamais lui-même de réponse à l'hôte : il
// lève ces erreurs, et le frontal les traduit (EX-14.5).

/** Raisons de mode dégradé de CT-2 §14.2 et EX-17.1. */
export const RAISONS_DEGRADE = Object.freeze(["stockage", "cle", "bail", "horloge", "attente", "approbation"]);

/** Erreur du cœur que le frontal rend à l'hôte (code et raison fixes). */
export class ErreurEnregistreur extends Error {
  /**
   * @param {string} raison raison de la matrice de 14.2 (data.reason)
   * @param {string} message texte français, sans donnée du client
   * @param {{code?: number, cause?: unknown, donnees?: object}} [options]
   */
  constructor(raison, message, options = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "ErreurEnregistreur";
    this.raison = raison;
    this.code = options.code ?? -31010;
    this.donnees = options.donnees ?? {};
  }
}

/** Erreur d'une configuration refusée au démarrage (EX-15.4, code de retour 2). */
export class ErreurConfiguration extends Error {
  /**
   * @param {{pointeur: string, regle: string, valeur?: unknown, secret?: boolean}[]} erreurs
   * @param {{pointeur: string, regle: string}[]} [avertissements]
   */
  constructor(erreurs, avertissements = []) {
    super(`configuration invalide : ${erreurs.length} erreur(s)`);
    this.name = "ErreurConfiguration";
    this.erreurs = erreurs;
    this.avertissements = avertissements;
  }
}

/**
 * Bogue de l'enregistreur : un événement construit qui ne valide pas (EX-7.1).
 * Il n'est jamais signé ; l'appel entre en mode dégradé.
 */
export class ErreurConstruction extends Error {
  /**
   * @param {string} message
   * @param {string[]} ecarts
   */
  constructor(message, ecarts) {
    super(message);
    this.name = "ErreurConstruction";
    this.ecarts = ecarts;
  }
}
