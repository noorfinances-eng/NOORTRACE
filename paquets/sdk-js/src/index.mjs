// SDK TypeScript/JavaScript de NOORTRACE (CT-2 6.5, EX-6.9 à EX-6.15) :
// `ClientNoortrace` enveloppe les méthodes `noortrace/sdk/*` de 6.2 sans en
// ajouter, sans paramètre ajouté, et sans changer ni les résultats ni leur
// sémantique. Le SDK ne capture rien et ne calcule rien : pas de hachage, pas
// de signature, pas d'écriture de journal (EX-6.1) ; il remet au démon ce que
// l'agent déclare. Il n'est un chemin de capture acceptable qu'avec un
// pare-feu de sortie (EX-6.2).

import fs from "node:fs";
import { performance } from "node:perf_hooks";
import { Buffer } from "node:buffer";
import { Connexion } from "./connexion.mjs";
import {
  ErreurNoortrace, ErreurNoortraceIndisponible, ErreurNoortraceDegrade, ErreurNoortraceLimite, ErreurNoortraceNonDurable,
  ErreurNoortraceEntreeInvalide, ErreurNoortraceConfiguration, AppelNonAutorise, texteNonAutorise,
} from "./erreurs.mjs";

export {
  ErreurNoortrace, ErreurNoortraceIndisponible, ErreurNoortraceDegrade, ErreurNoortraceLimite, ErreurNoortraceNonDurable,
  ErreurNoortraceEntreeInvalide, ErreurNoortraceConfiguration, AppelNonAutorise, texteNonAutorise,
};

/** Prise par défaut (EX-6.10). */
export const PRISE_DEFAUT = "/run/noortrace/sdk.sock";
/** Longueur maximale du chemin d'une prise Unix, en octets (EX-6.10). */
export const CHEMIN_PRISE_MAX = 103;
/** Borne de la tentative de `fermer` à la sortie du processus (EX-6.11 (4)). */
export const FERMER_A_LA_SORTIE_MS = 2000;

const M = (nom) => `noortrace/sdk/${nom}`;

/** Clients qui ont ouvert une session : `fermer` à la sortie du processus (EX-6.11 (4)). */
const CLIENTS_OUVERTS = new Set();
const SORTIE = { armee: false };

/** Membre « session » interne de `Debut` (non énuméré : `Debut` porte exactement quatre membres, EX-6.9). */
const SESSION_DU_DEBUT = new WeakMap();

/**
 * Délai avant la tentative n + 1 de la reprise de connexion (EX-6.13) :
 * `min(0,5 × 2^n, 8) × (1 − 0,25 × u)` secondes, u uniforme dans [0, 1[.
 * @param {number} n
 * @param {number} [u]
 * @returns {number} millisecondes
 */
export function delaiReprise(n, u = Math.random()) {
  return Math.min(0.5 * 2 ** n, 8) * (1 - 0.25 * u) * 1000;
}

/**
 * Valeur JSON rendue sans perte par `JSON.stringify` (EX-6.9) : sans
 * `undefined`, fonction, symbole, BigInt ni nombre non fini ; objets simples
 * et tableaux, récursivement.
 * @param {unknown} v
 * @returns {boolean}
 */
export function estValeurJson(v, vus = new Set()) {
  if (v === null || typeof v === "string" || typeof v === "boolean") return true;
  if (typeof v === "number") return Number.isFinite(v);
  if (typeof v !== "object") return false;
  if (vus.has(v)) return false;
  vus.add(v);
  try {
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i++) if (!(i in v) || !estValeurJson(v[i], vus)) return false;
      return true;
    }
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) return false;
    if (Object.getOwnPropertySymbols(v).length) return false;
    for (const k of Object.keys(v)) if (!estValeurJson(v[k], vus)) return false;
    return true;
  } finally {
    vus.delete(v);
  }
}

/** Nom du type d'une valeur (EX-6.9 : `noortrace_sdk_non_json`). */
export function nomDuType(v) {
  if (v === null) return "null";
  if (typeof v === "object") return v.constructor?.name ?? "Object";
  if (typeof v === "function") return "Function";
  return typeof v;
}

/** Nom de la classe d'une exception (EX-6.9 : `noortrace_sdk_exception`), jamais son message. */
export function nomDeClasse(e) {
  if (e !== null && typeof e === "object") return e.constructor?.name ?? "Object";
  return typeof e;
}

function analyserTcp(tcp) {
  const r = /^(\[[0-9A-Fa-f:]+\]|[^:\s]+):([0-9]{1,5})$/.exec(tcp ?? "");
  if (!r || Number(r[2]) < 1 || Number(r[2]) > 65535) throw new ErreurNoortraceConfiguration("noortrace: adresse TCP invalide (hote:port attendu)");
  return { hote: r[1].replace(/^\[|\]$/g, ""), port: Number(r[2]) };
}

export class ClientNoortrace {
  /**
   * Client du démon (EX-6.9, EX-6.10). La connexion est ouverte au premier appel.
   * @param {{socket?: string|null, tcp?: string|null, jeton?: string|null, delaiMs?: number, reprises?: number,
   *   surIndisponibiliteLecture?: "bloquer"|"executer"}} [o]
   */
  constructor(o = {}) {
    const env = process.env;
    const delaiMs = o.delaiMs ?? 30000;
    const reprises = o.reprises ?? 2;
    const sur = o.surIndisponibiliteLecture ?? "bloquer";
    if (!(typeof delaiMs === "number" && Number.isFinite(delaiMs) && delaiMs > 0)) throw new ErreurNoortraceConfiguration("noortrace: delaiMs invalide");
    if (!Number.isInteger(reprises) || reprises < 0) throw new ErreurNoortraceConfiguration("noortrace: reprises invalide");
    if (sur !== "bloquer" && sur !== "executer") throw new ErreurNoortraceConfiguration("noortrace: surIndisponibiliteLecture invalide");
    if (o.socket && o.tcp) throw new ErreurNoortraceConfiguration("noortrace: socket et tcp exclusifs");
    // Adresse (EX-6.10) : paramètres du constructeur, puis environnement, puis la prise par défaut.
    let socket = o.socket ?? null;
    let tcp = o.tcp ?? null;
    let jeton = o.jeton ?? null;
    if (!socket && !tcp) {
      if (env.NOORTRACE_SDK_SOCKET) socket = env.NOORTRACE_SDK_SOCKET;
      else if (env.NOORTRACE_SDK_TCP) tcp = env.NOORTRACE_SDK_TCP;
      else socket = PRISE_DEFAUT;
    }
    if (jeton === null && env.NOORTRACE_SDK_TOKEN) jeton = env.NOORTRACE_SDK_TOKEN;
    let tlsOptions = null;
    if (tcp) {
      const t = analyserTcp(tcp);
      if (env.NOORTRACE_SDK_TLS_CERT || env.NOORTRACE_SDK_TLS_KEY || env.NOORTRACE_SDK_TLS_CA) {
        if (!env.NOORTRACE_SDK_TLS_CERT || !env.NOORTRACE_SDK_TLS_KEY) throw new ErreurNoortraceConfiguration("noortrace: mTLS exige NOORTRACE_SDK_TLS_CERT et NOORTRACE_SDK_TLS_KEY");
        try {
          const lire = (f) => (f ? fs.readFileSync(f) : undefined);
          tlsOptions = { ca: lire(env.NOORTRACE_SDK_TLS_CA), cert: lire(env.NOORTRACE_SDK_TLS_CERT), key: lire(env.NOORTRACE_SDK_TLS_KEY) };
        } catch {
          throw new ErreurNoortraceConfiguration("noortrace: fichier mTLS illisible");
        }
      } else if (!jeton) {
        throw new ErreurNoortraceConfiguration("noortrace: une prise TCP exige un jeton ou mTLS (EX-4.39)");
      }
      this._adresse = { socket: null, tcp: t, jeton: tlsOptions ? null : jeton, tls: tlsOptions };
    } else {
      if (typeof socket !== "string" || socket.length === 0) throw new ErreurNoortraceConfiguration("noortrace: chemin de prise invalide");
      // EX-6.10 : au plus 103 octets ; un chemin plus long joindrait une autre prise.
      if (Buffer.byteLength(socket, "utf8") > CHEMIN_PRISE_MAX) throw new ErreurNoortraceConfiguration("noortrace: chemin de prise de plus de 103 octets");
      this._adresse = { socket, tcp: null, jeton: null, tls: null };
    }
    this.delaiMs = delaiMs;
    this.reprises = reprises;
    this.surIndisponibiliteLecture = sur;
    this._connexion = null;
    this._generation = 0;
    this._sessions = new Set();
    this._etablissement = null;
  }

  /** Client configuré par l'environnement seul (EX-6.10). */
  static depuisEnvironnement() {
    return new ClientNoortrace({});
  }

  /**
   * Connexion vivante, établie au besoin par **une** tentative ; une connexion
   * perdue ouvre une génération nouvelle. Les reprises et leurs délais sont
   * comptés par l'appelant (`_ouvrirSession`) : au plus `1 + reprises`
   * tentatives d'établissement en tout (EX-6.13).
   * @returns {Promise<Connexion>}
   */
  async _connexionVive() {
    if (this._connexion && !this._connexion.perdue) return this._connexion;
    if (this._etablissement) return this._etablissement;
    this._etablissement = (async () => {
      const c = new Connexion(this._adresse);
      await c.ouvrir(this.delaiMs);
      this._connexion = c;
      this._generation++;
      return c;
    })();
    try {
      return await this._etablissement;
    } finally {
      this._etablissement = null;
    }
  }

  /** Une génération de connexion est-elle toujours vivante ? */
  _vivante(generation) {
    return this._connexion !== null && !this._connexion.perdue && this._generation === generation;
  }

  /**
   * Ouvre une session (6.2 `ouvrir`) ; la connexion et `ouvrir` sont retentés
   * ensemble, en au plus `1 + reprises` tentatives séparées par
   * `delaiReprise(n)` (EX-6.13) : une tentative établit la connexion si
   * besoin, puis envoie `ouvrir`.
   */
  async _ouvrirSession(run_id, on_behalf_of) {
    let derniere;
    for (let n = 0; n <= this.reprises; n++) {
      if (n > 0) await new Promise((r) => setTimeout(r, delaiReprise(n - 1)));
      try {
        const c = await this._connexionVive();
        const generation = this._generation;
        const r = await c.appeler(M("ouvrir"), { run_id, on_behalf_of }, this.delaiMs);
        return { r, generation };
      } catch (e) {
        if (!(e instanceof ErreurNoortraceIndisponible)) throw e;
        derniere = e;
      }
    }
    throw derniere;
  }

  /**
   * `noortrace/sdk/ouvrir` (EX-6.9).
   * @param {{runId?: string|null, onBehalfOf?: string|null}} [o]
   * @returns {Promise<Session>}
   */
  async ouvrir(o = {}) {
    const s = new Session(this, o.runId ?? null, o.onBehalfOf ?? null);
    await s._ouvrir();
    this._sessions.add(s);
    this._armerSortie();
    return s;
  }

  /** EX-6.11 (4) : à la sortie du processus, `fermer` est tenté, borné à 2 s. */
  _armerSortie() {
    CLIENTS_OUVERTS.add(this);
    if (SORTIE.armee) return;
    SORTIE.armee = true;
    process.once("beforeExit", () => {
      const ouvertes = [...CLIENTS_OUVERTS].flatMap((c) => [...c._sessions]);
      if (!ouvertes.length) return;
      const borne = new Promise((r) => {
        const t = setTimeout(r, FERMER_A_LA_SORTIE_MS);
        t.unref?.();
      });
      Promise.race([Promise.allSettled(ouvertes.map((s) => s.fermer())), borne]).finally(() => {
        for (const c of CLIENTS_OUVERTS) c._connexion?.fermer();
      });
    });
  }
}

export class Session {
  /** @param {ClientNoortrace} client */
  constructor(client, run_id, on_behalf_of) {
    this._client = client;
    this._run_id = run_id;
    this._on_behalf_of = on_behalf_of;
    this._id = null;
    this._generation = 0;
    this._contextes = new Set();
    this._contextesPerdus = new Set();
    this._close = false;
  }

  async _ouvrir() {
    const { r, generation } = await this._client._ouvrirSession(this._run_id, this._on_behalf_of);
    this._id = r.session;
    this._generation = generation;
    this._reponseOuvrir = r;
  }

  /**
   * Session vivante : après une connexion perdue, une nouvelle session est
   * ouverte (même `run_id`, même `on_behalf_of`), que l'objet désigne désormais ;
   * les références de contexte de la session perdue ne valent plus (EX-6.13).
   */
  async _assurer() {
    if (this._close) throw new ErreurNoortraceEntreeInvalide("noortrace: session fermee", { reason: "session_inconnue" });
    if (this._client._vivante(this._generation)) return;
    for (const s of this._contextes) this._contextesPerdus.add(s);
    this._contextes.clear();
    await this._ouvrir();
  }

  async _appeler(methode, params) {
    await this._assurer();
    if (!this._client._vivante(this._generation)) throw new ErreurNoortraceIndisponible("noortrace: connexion perdue", false);
    return this._client._connexion.appeler(M(methode), params, this._client.delaiMs);
  }

  /**
   * `noortrace/sdk/declarerContexte` (EX-6.9).
   * @param {{kind: "document"|"donnees"|"memoire"|"autre", octets: Uint8Array|string, mediaType?: string|null}} p
   * @returns {Promise<{sha256: string, length: number, redacted: boolean}>}
   */
  async declarerContexte(p) {
    const octets = typeof p.octets === "string" ? Buffer.from(p.octets, "utf8") : Buffer.from(p.octets.buffer ?? p.octets, p.octets.byteOffset ?? 0, p.octets.byteLength ?? p.octets.length);
    await this._assurer();
    const r = await this._appeler("declarerContexte", { session: this._id, kind: p.kind, media_type: p.mediaType ?? null, bytes_base64: octets.toString("base64") });
    this._contextes.add(r.sha256);
    return { sha256: r.sha256, length: r.length, redacted: r.redacted };
  }

  /**
   * `noortrace/sdk/debutAppel` (EX-6.9) : la décision et, pour `ecriture`,
   * l'intention durable (EX-6.3).
   * @param {{tool: string, arguments: unknown, classe?: "lecture"|"ecriture"|null, contexte?: string[], intent?: string|null, effects?: object[]|null}} p
   * @returns {Promise<{call: string|null, decision: string, ticket: string|null, ticket_state: string|null}>}
   */
  async debutAppel(p) {
    await this._assurer();
    const contexte = p.contexte ?? [];
    // EX-6.13 : une référence de la session perdue lève sans rien envoyer.
    for (const s of contexte) {
      if (this._contextesPerdus.has(s) && !this._contextes.has(s)) throw new ErreurNoortraceEntreeInvalide("noortrace: reference de contexte d'une session perdue", { reason: "context_session_perdue" });
    }
    const generation = this._generation;
    const r = await this._appeler("debutAppel", {
      session: this._id,
      tool: p.tool,
      arguments: p.arguments === undefined ? null : p.arguments,
      class: p.classe ?? null,
      context: contexte,
      intent: p.intent ?? null,
      effects: p.effects ?? null,
    });
    const debut = { call: r.call, decision: r.decision, ticket: r.ticket, ticket_state: r.ticket_state };
    SESSION_DU_DEBUT.set(debut, { session: this, generation });
    return debut;
  }

  /**
   * `noortrace/sdk/finAppel` (EX-6.9) : l'événement durable.
   * @param {{call: string|null}} debut résultat de `debutAppel`
   * @param {{resultat?: unknown, isError: boolean, durationMs: number}} p
   * @returns {Promise<{seq: number|null, hash: string|null}>}
   */
  async finAppel(debut, p) {
    const lien = SESSION_DU_DEBUT.get(debut);
    // EX-6.13 : un finAppel dont la session a été perdue avant son envoi n'est pas envoyé.
    if (lien && (lien.session !== this || !this._client._vivante(lien.generation) || this._generation !== lien.generation)) {
      throw new ErreurNoortraceIndisponible("noortrace: session perdue avant finAppel", false);
    }
    if (!this._client._vivante(this._generation)) throw new ErreurNoortraceIndisponible("noortrace: connexion perdue", false);
    const r = await this._client._connexion.appeler(
      M("finAppel"),
      { call: debut?.call ?? null, result: p.resultat === undefined ? null : p.resultat, is_error: p.isError, duration_ms: p.durationMs },
      this._client.delaiMs,
    );
    return { seq: r.seq, hash: r.hash };
  }

  /**
   * `debutAppel`, exécution de `fonction`, `finAppel` (EX-6.9, seule méthode
   * composée) : le résultat de `fonction`, rendu après l'événement durable.
   * @template T
   * @param {{tool: string, arguments: unknown, classe?: "lecture"|"ecriture"|null, contexte?: string[], intent?: string|null, effects?: object[]|null}} p
   * @param {(args: unknown) => T|Promise<T>} fonction
   * @returns {Promise<T>}
   */
  async appelOutil(p, fonction) {
    let debut;
    try {
      debut = await this.debutAppel(p);
    } catch (e) {
      // EX-6.15 : un outil d'écriture n'est jamais exécuté ; une lecture seulement avec « executer », sans événement.
      if ((p.classe ?? "ecriture") === "lecture" && this._client.surIndisponibiliteLecture === "executer") {
        process.stderr.write(`noortrace-sdk: debutAppel en echec (${nomDeClasse(e)}) ; outil de lecture ${p.tool} execute sans evenement\n`);
        return fonction(p.arguments);
      }
      throw e;
    }
    if (debut.decision !== "autorise") throw new AppelNonAutorise(debut);
    const t0 = performance.now();
    let valeur;
    try {
      valeur = await fonction(p.arguments);
    } catch (e) {
      const durationMs = Math.max(0, Math.floor(performance.now() - t0));
      // Le message de l'exception n'est jamais transmis : seul le nom de sa classe.
      await this.finAppel(debut, { resultat: { noortrace_sdk_exception: nomDeClasse(e) }, isError: true, durationMs });
      throw e;
    }
    const durationMs = Math.max(0, Math.floor(performance.now() - t0));
    const resultat = estValeurJson(valeur) ? valeur : { noortrace_sdk_non_json: nomDuType(valeur) };
    await this.finAppel(debut, { resultat, isError: false, durationMs });
    return valeur;
  }

  /**
   * `noortrace/sdk/echangeModele` (EX-6.9) : l'événement durable.
   * @param {{format: string, providerLabel: string, request: unknown, response: unknown, status?: number|null, durationMs: number, isError: boolean}} p
   * @returns {Promise<{seq: number|null, hash: string|null}>}
   */
  async echangeModele(p) {
    await this._assurer();
    const r = await this._appeler("echangeModele", {
      session: this._id,
      format: p.format,
      provider_label: p.providerLabel,
      request: p.request,
      response: p.response,
      status: p.status ?? null,
      duration_ms: p.durationMs,
      is_error: p.isError,
    });
    return { seq: r.seq, hash: r.hash };
  }

  /**
   * `noortrace/sdk/fermer` (EX-6.9), dans un `finally`.
   * @returns {Promise<object>}
   */
  async fermer() {
    if (this._close) return {};
    this._client._sessions.delete(this);
    if (!this._client._vivante(this._generation)) {
      this._close = true;
      return {};
    }
    const r = await this._client._connexion.appeler(M("fermer"), { session: this._id }, this._client.delaiMs);
    this._close = true;
    return r;
  }
}
