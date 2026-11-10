// Client JSON-RPC vers un ou plusieurs validateurs du registre (CT-4 §8.6,
// EX-8.15 : une transaction est soumise, en mêmes octets, à chaque point ;
// CT-4 §9.4 : les réponses sont conservées telles que reçues, octets de la
// réponse HTTP complète). Le transport est injectable ; l'implémentation par
// défaut emploie `fetch` de Node.js avec un délai borné et un corps de
// réponse borné. Aucune horloge n'est lue ici : les attentes sont celles de
// l'appelant (`attendre` injecté, règle 2 d'INTERFACES.md).
//
// Les points sont des adresses `http://127.0.0.1:<port>` sur le réseau de
// développement ; en production, `https://` ou `http://` vers la boucle
// locale seulement (CT-4 EX-7.1, OP-2). Aucun jeton ni secret n'est écrit
// dans un index de capture : `node.rpc` est l'adresse sans identifiants.

import { depasseProfondeur } from "@noortrace/noyau";
import { utf8Octets, utf8Texte } from "./octets.mjs";

/** Taille maximale d'une réponse JSON-RPC lue (16 Mio : certificat d'un bloc plein, marge comprise). */
export const TAILLE_REPONSE_MAX = 16 * 1024 * 1024;
/** Profondeur JSON admise (CT-6 EX-4.13). */
export const PROFONDEUR_JSON = 128;

/** Erreur de transport ou de forme d'une réponse JSON-RPC (le nœud n'a pas répondu en JSON-RPC). */
export class ErreurRpc extends Error {
  constructor(code, message, point) {
    super(message);
    this.name = "ErreurRpc";
    this.code = code;
    this.point = point;
  }
}

/**
 * Transport HTTP par défaut : `POST` d'un corps JSON, réponse lue jusqu'à
 * `tailleMax` octets, délai `delaiMs`. Rend `{ status, octets }` ; lève
 * `ErreurRpc("noeud_injoignable")` sur une panne de réseau ou un délai.
 */
export function transportHttp({ fetch = globalThis.fetch } = {}) {
  if (typeof fetch !== "function") throw new TypeError("fetch indisponible");
  return async function envoyer({ url, octets, delaiMs, tailleMax }) {
    let reponse;
    try {
      reponse = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: octets,
        signal: AbortSignal.timeout(delaiMs),
        redirect: "error",
      });
    } catch (e) {
      throw new ErreurRpc("noeud_injoignable", `${url} : ${e?.name === "TimeoutError" ? "délai dépassé" : "injoignable"}`, url);
    }
    const lecteur = reponse.body?.getReader?.();
    const morceaux = [];
    let total = 0;
    if (lecteur) {
      for (;;) {
        const { done, value } = await lecteur.read();
        if (done) break;
        total += value.length;
        if (total > tailleMax) {
          await lecteur.cancel().catch(() => {});
          throw new ErreurRpc("noeud_injoignable", `${url} : réponse au-delà de ${tailleMax} octets`, url);
        }
        morceaux.push(value);
      }
    } else {
      const b = new Uint8Array(await reponse.arrayBuffer());
      if (b.length > tailleMax) throw new ErreurRpc("noeud_injoignable", `${url} : réponse au-delà de ${tailleMax} octets`, url);
      morceaux.push(b);
    }
    const corps = new Uint8Array(total);
    let k = 0;
    for (const m of morceaux) {
      corps.set(m, k);
      k += m.length;
    }
    return { status: reponse.status, octets: corps };
  };
}

/** Lit une réponse JSON-RPC (octets) : `{ json, erreur, resultat }` ; lève `ErreurRpc` si ce n'est pas du JSON-RPC. */
export function lireReponseRpc(octets, point, id) {
  const texte = utf8Texte(octets);
  if (texte === null) throw new ErreurRpc("noeud_injoignable", `${point} : réponse non UTF-8`, point);
  let json;
  try {
    json = JSON.parse(texte);
  } catch {
    throw new ErreurRpc("noeud_injoignable", `${point} : réponse qui n'est pas du JSON`, point);
  }
  if (!json || typeof json !== "object" || Array.isArray(json) || depasseProfondeur(json, PROFONDEUR_JSON)) {
    throw new ErreurRpc("noeud_injoignable", `${point} : réponse JSON-RPC mal formée`, point);
  }
  if (json.jsonrpc !== "2.0" || (id !== undefined && json.id !== id)) throw new ErreurRpc("noeud_injoignable", `${point} : réponse JSON-RPC mal formée`, point);
  if ("error" in json && json.error !== null) {
    const e = json.error;
    if (!e || typeof e !== "object") throw new ErreurRpc("noeud_injoignable", `${point} : erreur JSON-RPC mal formée`, point);
    return { json, erreur: { code: typeof e.code === "number" ? e.code : null, message: typeof e.message === "string" ? e.message : "" }, resultat: undefined };
  }
  if (!("result" in json)) throw new ErreurRpc("noeud_injoignable", `${point} : réponse JSON-RPC sans result`, point);
  return { json, erreur: null, resultat: json.result };
}

/**
 * Client vers une liste de points. `appeler` interroge un point (le premier
 * par défaut) ; `appelerTous` envoie les mêmes octets à chacun et rend les
 * réponses de tous, panne comprise (EX-8.15, EX-8.16).
 */
export class ClientRpc {
  #points;
  #transport;
  #delaiMs;
  #tailleMax;
  #identifiants;
  #compteur;

  /**
   * @param {{points: string[], transport?: Function, delaiMs?: number, tailleMax?: number, identifiants?: Record<string,string>}} options
   *   `identifiants` : identifiant de validateur déclaré derrière chaque point (`node.validator_id` de l'index).
   */
  constructor({ points, transport = null, delaiMs = 10000, tailleMax = TAILLE_REPONSE_MAX, identifiants = {} }) {
    if (!Array.isArray(points) || points.length === 0 || !points.every((p) => typeof p === "string" && /^https?:\/\/[^\s/]+(\/.*)?$/.test(p))) {
      throw new TypeError("points JSON-RPC : au moins une adresse http(s) attendue");
    }
    for (const p of points) if (/\/\/[^/]*@/.test(p)) throw new TypeError("point JSON-RPC : aucun identifiant dans l'adresse");
    this.#points = [...points];
    this.#transport = transport ?? transportHttp();
    this.#delaiMs = delaiMs;
    this.#tailleMax = tailleMax;
    this.#identifiants = { ...identifiants };
    this.#compteur = 0;
  }

  /** Les points, dans l'ordre. */
  points() {
    return [...this.#points];
  }

  /** Identifiant de validateur déclaré pour un point, ou null. */
  validateurDe(point) {
    return this.#identifiants[point] ?? null;
  }

  /** Octets d'une requête JSON-RPC (déterministes pour un identifiant donné). */
  static requete(methode, params, id) {
    return utf8Octets(JSON.stringify({ jsonrpc: "2.0", id, method: methode, params }));
  }

  /**
   * Appelle `methode` sur un point ; rend `{ point, octets, json, erreur,
   * resultat }`. Lève `ErreurRpc` si le point est injoignable ou ne parle pas
   * JSON-RPC ; une erreur JSON-RPC du nœud est rendue, non levée.
   */
  async appeler(methode, params = [], { point = this.#points[0], id = ++this.#compteur } = {}) {
    const requete = ClientRpc.requete(methode, params, id);
    const { status, octets } = await this.#transport({ url: point, octets: requete, delaiMs: this.#delaiMs, tailleMax: this.#tailleMax });
    if (status !== 200) throw new ErreurRpc("noeud_injoignable", `${point} : HTTP ${status}`, point);
    const lue = lireReponseRpc(octets, point, id);
    return { point, octets, ...lue };
  }

  /**
   * Appelle `methode` avec les mêmes octets sur chaque point ; rend, par
   * point, `{ point, octets, json, erreur, resultat }` ou `{ point, panne }`.
   */
  async appelerTous(methode, params = []) {
    const id = ++this.#compteur;
    const requete = ClientRpc.requete(methode, params, id);
    const sorties = [];
    for (const point of this.#points) {
      try {
        const { status, octets } = await this.#transport({ url: point, octets: requete, delaiMs: this.#delaiMs, tailleMax: this.#tailleMax });
        if (status !== 200) throw new ErreurRpc("noeud_injoignable", `${point} : HTTP ${status}`, point);
        sorties.push({ point, octets, ...lireReponseRpc(octets, point, id) });
      } catch (e) {
        if (e instanceof ErreurRpc) sorties.push({ point, panne: e });
        else throw e;
      }
    }
    return sorties;
  }

  /**
   * Appelle `methode` sur le premier point qui répond en JSON-RPC (panne
   * ignorée) ; lève `ErreurRpc("noeud_injoignable")` si aucun ne répond.
   */
  async appelerPremier(methode, params = []) {
    let derniere = null;
    for (const point of this.#points) {
      try {
        return await this.appeler(methode, params, { point });
      } catch (e) {
        if (!(e instanceof ErreurRpc)) throw e;
        derniere = e;
      }
    }
    throw derniere ?? new ErreurRpc("noeud_injoignable", "aucun point", null);
  }
}

/**
 * Client sur un seul point, pour une capture ou une lecture auprès d'un
 * validateur donné.
 */
export function clientSurPoint(client, point) {
  return {
    point,
    appeler: (methode, params, options = {}) => client.appeler(methode, params, { ...options, point }),
    validateurDe: () => client.validateurDe(point),
  };
}
