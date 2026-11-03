// Erreurs du SDK TypeScript de NOORTRACE (CT-2 EX-6.12) : toutes dérivent de
// `ErreurNoortrace`. Une décision `a_approuver` ou `refuse` n'est pas une
// erreur du protocole (EX-6.4) : seule `appelOutil` la change en exception
// (`AppelNonAutorise`), pour qu'aucun code appelant ne l'exécute par mégarde.

/** Toute erreur du SDK ; pour un code JSON-RPC non nommé ci-dessous : `code`, `message`, `data`. */
export class ErreurNoortrace extends Error {
  /**
   * @param {string} message
   * @param {{code?: number|null, data?: unknown}} [o]
   */
  constructor(message, o = {}) {
    super(message);
    this.name = "ErreurNoortrace";
    this.code = o.code ?? null;
    this.data = o.data ?? null;
  }
}

/** Prise injoignable, connexion coupée, délai écoulé ; `envoyee` : la requête a été écrite sur la prise. */
export class ErreurNoortraceIndisponible extends ErreurNoortrace {
  /** @param {string} message @param {boolean} envoyee */
  constructor(message, envoyee) {
    super(message);
    this.name = "ErreurNoortraceIndisponible";
    this.envoyee = envoyee === true;
  }
}

/** -31010 : `raison` (`data.reason`). */
export class ErreurNoortraceDegrade extends ErreurNoortrace {
  constructor(message, data) {
    super(message, { code: -31010, data });
    this.name = "ErreurNoortraceDegrade";
    this.raison = data?.reason ?? null;
  }
}

/** -31013 : `direction`, `limite` (octets, requêtes ou millisecondes). */
export class ErreurNoortraceLimite extends ErreurNoortrace {
  constructor(message, data) {
    super(message, { code: -31013, data });
    this.name = "ErreurNoortraceLimite";
    this.direction = data?.direction ?? null;
    this.limite = data?.limit_bytes ?? data?.limit_requests ?? data?.limit_ms ?? null;
  }
}

/** -31017 (`finAppel` après une panne du démon, 14.2) : `intent_id`. */
export class ErreurNoortraceNonDurable extends ErreurNoortrace {
  constructor(message, data) {
    super(message, { code: -31017, data });
    this.name = "ErreurNoortraceNonDurable";
    this.intent_id = data?.intent_id ?? null;
  }
}

/** -32602 : `raison` (`data.reason`). */
export class ErreurNoortraceEntreeInvalide extends ErreurNoortrace {
  constructor(message, data) {
    super(message, { code: -32602, data });
    this.name = "ErreurNoortraceEntreeInvalide";
    this.raison = data?.reason ?? null;
  }
}

/** Configuration du client invalide (EX-6.10 : chemin de prise de plus de 103 octets, …). */
export class ErreurNoortraceConfiguration extends ErreurNoortrace {
  constructor(message) {
    super(message);
    this.name = "ErreurNoortraceConfiguration";
  }
}

/**
 * Texte du résultat d'outil d'EX-4.49 (EX-6.12 : `texte`).
 * @param {string|null} ticket
 * @param {string|null} etat
 * @returns {string}
 */
export function texteNonAutorise(ticket, etat) {
  return ticket === null ? "noortrace: appel refuse par la politique" : `noortrace: appel soumis a approbation ; ticket=${ticket} ; state=${etat}`;
}

/** `decision` autre que `autorise` dans `appelOutil` : `decision`, `ticket`, `ticket_state`, `texte`. */
export class AppelNonAutorise extends ErreurNoortrace {
  /** @param {{decision: string, ticket: string|null, ticket_state: string|null}} d */
  constructor(d) {
    const texte = texteNonAutorise(d.ticket ?? null, d.ticket_state ?? null);
    super(texte);
    this.name = "AppelNonAutorise";
    this.decision = d.decision;
    this.ticket = d.ticket ?? null;
    this.ticket_state = d.ticket_state ?? null;
    this.texte = texte;
  }
}

/**
 * Erreur du SDK pour un objet `error` JSON-RPC rendu par le démon (EX-6.12).
 * @param {{code: number, message: string, data?: unknown}} e
 * @returns {ErreurNoortrace}
 */
export function erreurDepuisReponse(e) {
  const data = e?.data ?? null;
  const message = typeof e?.message === "string" ? e.message : "noortrace: erreur";
  switch (e?.code) {
    case -31010:
      return new ErreurNoortraceDegrade(message, data);
    case -31013:
      return new ErreurNoortraceLimite(message, data);
    case -31017:
      return new ErreurNoortraceNonDurable(message, data);
    case -32602:
      return new ErreurNoortraceEntreeInvalide(message, data);
    default:
      return new ErreurNoortrace(message, { code: typeof e?.code === "number" ? e.code : null, data });
  }
}
