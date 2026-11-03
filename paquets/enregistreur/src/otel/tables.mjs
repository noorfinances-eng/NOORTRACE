// Tables en mémoire de l'ingestion OpenTelemetry (CT-2 EX-6.33, EX-6.34) :
// table des doublons (clé alias, trace_id, span_id ; fenêtre
// `otel.dedup_window_ms` ; au plus 1 000 000 de clés, les plus anciennes
// sortant les premières) et registre de recouvrement (appels d'outils et
// échanges scellés par le frontal MCP, le frontal modèle et le SDK, par
// groupe d'hôte, pendant `otel.overlap_window_ms`). Ni l'une ni l'autre n'est
// persistante ni reconstruite au redémarrage (EX-6.33, EX-6.39).

/** Nombre maximal de clés de la table des doublons (EX-6.33). */
export const CLES_MAX = 1000000;

export class TableDoublons {
  /**
   * @param {{fenetreMs: number, max?: number, surSortie?: (n: number) => void}} o
   */
  constructor(o) {
    this.fenetreMs = o.fenetreMs;
    this.max = o.max ?? CLES_MAX;
    this.surSortie = o.surSortie ?? (() => {});
    /** @type {Map<string, {at: number, empreinte: string}>} */
    this.cles = new Map();
  }

  static cle(alias, trace_id, span_id) {
    return `${alias}\u0000${trace_id}\u0000${span_id}`;
  }

  _purger(t) {
    for (const [k, v] of this.cles) {
      if (v.at >= t - this.fenetreMs) break;
      this.cles.delete(k);
    }
  }

  /** Entrée d'une clé dans la fenêtre, ou undefined. */
  chercher(cle, t) {
    this._purger(t);
    return this.cles.get(cle);
  }

  /** Inscrit une clé scellée ou écartée comme recouvrement, avec l'empreinte de N(S). */
  inscrire(cle, empreinte, t) {
    this._purger(t);
    this.cles.delete(cle);
    this.cles.set(cle, { at: t, empreinte });
    let sorties = 0;
    while (this.cles.size > this.max) {
      this.cles.delete(this.cles.keys().next().value);
      sorties++;
    }
    if (sorties) this.surSortie(sorties);
  }
}

export class RegistreRecouvrement {
  /** @param {{fenetreMs: number}} o */
  constructor(o) {
    this.fenetreMs = o.fenetreMs;
    /** @type {{genre: "appel"|"echange", host_group: string, nom: string|null, modele: string|null, t: number, seq: number, apparie: boolean}[]} */
    this.entrees = [];
  }

  _purger(t) {
    const limite = t - this.fenetreMs;
    while (this.entrees.length && this.entrees[0].t < limite) this.entrees.shift();
  }

  /**
   * Inscrit un acte scellé par un chemin plus fort (EX-6.34).
   * @param {{genre: "appel"|"echange", host_group: string, nom?: string|null, modele?: string|null, t: number, seq: number}} x
   */
  inscrire(x) {
    this._purger(x.t);
    this.entrees.push({ genre: x.genre, host_group: x.host_group, nom: x.nom ?? null, modele: x.modele ?? null, t: x.t, seq: x.seq, apparie: false });
    this.entrees.sort((a, b) => a.t - b.t);
  }

  /**
   * Apparie un span au plus ancien acte non apparié de son groupe, inscrit
   * dans `[t − fenêtre, t]`, de même nom (outil) ou de même modèle (inférence).
   * @param {{genre: "appel"|"echange", host_group: string, nom?: string, modele?: string, t: number}} q
   * @returns {number|null} `seq` de l'acte apparié
   */
  apparier(q) {
    this._purger(q.t);
    for (const e of this.entrees) {
      if (e.apparie || e.genre !== q.genre || e.host_group !== q.host_group) continue;
      if (e.t < q.t - this.fenetreMs || e.t > q.t) continue;
      if (q.genre === "appel" ? e.nom !== q.nom : e.modele !== q.modele) continue;
      e.apparie = true;
      return e.seq;
    }
    return null;
  }
}
