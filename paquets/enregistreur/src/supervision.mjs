// Supervision (CT-2 §17) : santé (`GET /healthz`, `/readyz`), métriques au
// format texte Prometheus (`GET /metrics`), pour ce qui touche le cœur :
// écrivain (`noortrace_events_total`, `noortrace_fsync_duration_ms`,
// `noortrace_fsync_group_size`, `noortrace_segment_bytes`,
// `noortrace_pending_events`), clé (`noortrace_sign_duration_ms`,
// contrôle `health()` du signataire), bail (`noortrace_lease_epoch`), mode
// dégradé (`noortrace_degraded{reason}`), horloge (`noortrace_clock_skew_ms`).
// Aucune étiquette ne porte un argument, un nom d'utilisateur, un ticket ou un
// nom d'hôte de client (17.2).

import http from "node:http";

const BORNES_DEFAUT = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000];

function cleEtiquettes(etiquettes) {
  const noms = Object.keys(etiquettes).sort();
  return noms.map((n) => `${n}="${String(etiquettes[n]).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`).join(",");
}

/** Registre de métriques en mémoire, exposé au format texte Prometheus. */
export class Metriques {
  constructor() {
    /** @type {Map<string, {type: string, series: Map<string, any>, bornes?: number[]}>} */
    this.familles = new Map();
  }

  famille(nom, type, bornes) {
    let f = this.familles.get(nom);
    if (!f) {
      f = { type, series: new Map(), bornes };
      this.familles.set(nom, f);
    }
    return f;
  }

  /** Incrémente un compteur. */
  compter(nom, etiquettes = {}, n = 1) {
    const f = this.famille(nom, "counter");
    const c = cleEtiquettes(etiquettes);
    f.series.set(c, (f.series.get(c) ?? 0) + n);
  }

  /** Fixe une jauge. */
  jauge(nom, etiquettes = {}, valeur) {
    this.famille(nom, "gauge").series.set(cleEtiquettes(etiquettes), valeur);
  }

  /** Observe une valeur d'histogramme. */
  observer(nom, etiquettes = {}, valeur, bornes = BORNES_DEFAUT) {
    const f = this.famille(nom, "histogram", bornes);
    const c = cleEtiquettes(etiquettes);
    let s = f.series.get(c);
    if (!s) {
      s = { compte: 0, somme: 0, seaux: f.bornes.map(() => 0) };
      f.series.set(c, s);
    }
    s.compte++;
    s.somme += valeur;
    f.bornes.forEach((b, k) => {
      if (valeur <= b) s.seaux[k]++;
    });
  }

  /** Valeur d'un compteur ou d'une jauge (tests, santé). */
  valeur(nom, etiquettes = {}) {
    const f = this.familles.get(nom);
    if (!f) return undefined;
    const s = f.series.get(cleEtiquettes(etiquettes));
    return typeof s === "object" && s !== null ? s.compte : s;
  }

  /** Exposition texte Prometheus. */
  exposer() {
    const lignes = [];
    for (const nom of [...this.familles.keys()].sort()) {
      const f = this.familles.get(nom);
      lignes.push(`# TYPE ${nom} ${f.type}`);
      for (const [c, v] of f.series) {
        const e = c ? `{${c}}` : "";
        if (f.type !== "histogram") {
          lignes.push(`${nom}${e} ${v}`);
          continue;
        }
        f.bornes.forEach((b, k) => lignes.push(`${nom}_bucket{${c ? c + "," : ""}le="${b}"} ${v.seaux[k]}`));
        lignes.push(`${nom}_bucket{${c ? c + "," : ""}le="+Inf"} ${v.compte}`);
        lignes.push(`${nom}_sum${e} ${v.somme}`);
        lignes.push(`${nom}_count${e} ${v.compte}`);
      }
    }
    return lignes.join("\n") + "\n";
  }
}

/**
 * Corps de `GET /healthz` (EX-17.1) d'après l'état du cœur.
 * @param {{bailDetenu: boolean, passive?: boolean, raisons: string[], depuis: string|null, cleIndisponible: boolean}} etat
 * @returns {{statut: number, corps: object}}
 */
export function sante(etat) {
  if (etat.passive) return { statut: 200, corps: { status: "standby" } };
  if (!etat.bailDetenu || etat.cleIndisponible) {
    const raisons = [...etat.raisons];
    if (!etat.bailDetenu && !raisons.includes("bail")) raisons.push("bail");
    if (etat.cleIndisponible && !raisons.includes("cle")) raisons.push("cle");
    return { statut: 503, corps: { status: "down", reasons: raisons } };
  }
  if (etat.raisons.length) return { statut: 200, corps: { status: "degraded", reasons: etat.raisons, since: etat.depuis } };
  return { statut: 200, corps: { status: "ok" } };
}

/**
 * Serveur de supervision sur `supervision.health_listen` (local par défaut).
 * @param {{adresse: string, port: number, etat: () => object, pret: () => boolean, metriques: Metriques|null}} p
 * @returns {Promise<http.Server>}
 */
export function servirSupervision(p) {
  const serveur = http.createServer((req, res) => {
    if (req.method !== "GET") {
      res.writeHead(405).end();
      return;
    }
    if (req.url === "/healthz") {
      const { statut, corps } = sante(p.etat());
      res.writeHead(statut, { "content-type": "application/json" }).end(JSON.stringify(corps));
    } else if (req.url === "/readyz") {
      res.writeHead(p.pret() ? 200 : 503).end();
    } else if (req.url === "/metrics" && p.metriques) {
      res.writeHead(200, { "content-type": "text/plain; version=0.0.4" }).end(p.metriques.exposer());
    } else {
      res.writeHead(404).end();
    }
  });
  return new Promise((resolve, reject) => {
    serveur.once("error", reject);
    serveur.listen(p.port, p.adresse, () => resolve(serveur));
  });
}
