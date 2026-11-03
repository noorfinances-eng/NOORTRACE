// Quotas par connexion d'hôte (CT-2 EX-4.47) : requêtes en cours, octets de
// pièces écrits, octets reçus et temps de capture par minute glissante de
// l'horloge monotone. Un dépassement refuse la requête au pas 1 de 4.4 par
// -31013 (`data.direction: "quota"`), sans relais ni pièce.

const MINUTE = 60000;

class Fenetre {
  constructor() {
    this.entrees = [];
    this.somme = 0;
  }

  purger(t) {
    while (this.entrees.length && this.entrees[0][0] <= t - MINUTE) this.somme -= this.entrees.shift()[1];
  }

  ajouter(t, n) {
    this.purger(t);
    this.entrees.push([t, n]);
    this.somme += n;
  }

  total(t) {
    this.purger(t);
    return this.somme;
  }
}

export class QuotasHote {
  /** @param {{max_concurrent: number, piece_bytes_per_minute: number, received_bytes_per_minute: number, redaction_ms_per_minute: number}} quota */
  constructor(quota) {
    this.quota = quota;
    this.enCours = 0;
    this.recus = new Fenetre();
    this.pieces = new Fenetre();
    this.capture = new Fenetre();
  }

  /** Octets reçus (comptés même pour une requête refusée). */
  recevoir(t, octets) {
    this.recus.ajouter(t, octets);
  }

  /**
   * Quota atteint avant l'analyse de la requête (4.4 pas 1) : octets reçus
   * ou temps de capture, les deux seuls qui ne dépendent pas de ce que la
   * requête demande ; null sinon.
   * @param {number} t
   * @returns {object|null} `data` de -31013
   */
  depasseAvantAnalyse(t) {
    const q = this.quota;
    if (this.recus.total(t) > q.received_bytes_per_minute) return { limit_bytes: q.received_bytes_per_minute, direction: "quota" };
    if (this.capture.total(t) >= q.redaction_ms_per_minute) return { limit_ms: q.redaction_ms_per_minute, direction: "quota" };
    return null;
  }

  /**
   * Quota atteint au pas 1, ou null.
   * @param {number} t
   * @param {{appel: boolean}} o `appel` : la requête est un `tools/call`
   * @returns {object|null} `data` de -31013
   */
  depasse(t, o = { appel: true }) {
    const q = this.quota;
    if (this.recus.total(t) > q.received_bytes_per_minute) return { limit_bytes: q.received_bytes_per_minute, direction: "quota" };
    if (!o.appel) return null;
    if (this.enCours >= q.max_concurrent) return { limit_requests: q.max_concurrent, direction: "quota" };
    if (this.pieces.total(t) >= q.piece_bytes_per_minute) return { limit_bytes: q.piece_bytes_per_minute, direction: "quota" };
    if (this.capture.total(t) >= q.redaction_ms_per_minute) return { limit_ms: q.redaction_ms_per_minute, direction: "quota" };
    return null;
  }

  /** Octets de pièces écrits pour l'hôte. */
  piece(t, octets) {
    this.pieces.ajouter(t, octets);
  }

  /** Temps de capture consommé (analyse, rédaction, sérialisation). */
  tempsCapture(t, ms) {
    if (ms > 0) this.capture.ajouter(t, ms);
  }
}
