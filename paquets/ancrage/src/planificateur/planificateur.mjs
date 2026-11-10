// Planificateur d'ancrage de CT-5 §8 : machine à états déterministe, à
// horloge injectée et sans réseau (EX-8.13). Il reçoit les entrées de
// `$defs/evenement_entree` (démarrage, point admis, période close, tic,
// réponses des prestataires et des calendriers, inclusions et échecs du
// registre, objets durables relus, arrêt) et rend les actions de
// `$defs/action_attendue` dans l'ordre où les règles les produisent (EX-8.16) ;
// la file est faite de `$defs/demande` (EX-8.2, EX-8.3). Il ne fait aucun
// appel réseau, ne lit aucun fichier et ne vérifie aucun jeton : les
// résultats lui sont remis (EX-8.6, EX-8.8 à EX-8.11) et il en tire les
// transitions. Deux entrées de même instant sont traitées dans l'ordre de la
// liste ; une action produite à l'instant d'une entrée porte cet instant.
//
// Révision 0.6 de CT-5 : chaque ligne écrite porte au plus 32 tentatives et
// `attempts_total` (EX-8.5, règle 7 ; `fenetrer`), le rang d'une tentative
// nouvelle est `attempts_total + 1` (EX-8.12) ; la ligne
// `checkpoint_countersigned` porte `d_admission_s` et compte `d_attente_s`
// depuis l'admission du point (EX-3.5, 8.9). Les lignes `anchor_retry`,
// `anchor_fallback` et `anchor_response_rejected` portent le rang `n`
// (`attempt`) et l'`attempt_id` de leur tentative (EX-8.15).

import { DOC_TYPE_POINT, decoderHorodatage, ecrireHorodatage, empreinteAncre, keccak256, octetsVersHex, utf8 } from "@noortrace/noyau";
import { ID_SCHEMA_PLANIFICATEUR, REGISTRE_ANCRAGE, validerProjection } from "./configuration.mjs";
import { ETATS_FINAUX, FENETRE_TENTATIVES, estFinale, totalTentatives, trierDemandes, validerLigneDemande } from "./file.mjs";
import { construireRequete, nonceEntier, nonceHex } from "./requete-der.mjs";
// Table unique des attentes de reprise après une erreur HTTP transitoire (EX-8.9 révisée ; R-C-1 à R-C-3) : le lot A
// la possède, le planificateur l'appelle, pour que le client et la file ne divergent jamais.
import { attenteTransitoire, bornerRetryAfter } from "../rfc3161/classement.mjs";

/** `docType` de l'ancre d'une période (CT-4 §6.4 : keccak256 du libellé). */
export const DOC_TYPE_PERIODE = octetsVersHex(keccak256(utf8("noortrace/periode/v0")));

/** Les six sortes de demandes (EX-8.2). */
export const SORTES = Object.freeze(["jeton_periode", "jeton_point", "ots_periode", "ots_point", "ancre_registre_periode", "ancre_registre_point"]);

/** Codes HTTP transitoires d'EX-5.12. */
const HTTP_TRANSITOIRES = new Set([408, 429, 500, 502, 503, 504]);
/** `PKIFailureInfo` permanents et transitoires d'EX-5.12. */
const ECHECS_PERMANENTS = new Set(["badAlg", "badRequest", "badDataFormat", "unacceptedPolicy", "unacceptedExtension", "addInfoNotAvailable"]);
const ECHECS_TRANSITOIRES = new Set(["timeNotAvailable", "systemFailure"]);
/** Types de contenu admis en réponse (EX-5.5). */
const TYPES_REPONSE = new Set(["application/timestamp-reply", "application/timestamp-response"]);
/** Corps maximal d'une réponse (EX-5.5). */
const CORPS_MAX = 131072;
/** Vérifications T- exigées à l'acquisition (EX-5.10, étape 6). */
const VERIFICATIONS_T = ["T-1", "T-2", "T-3", "T-4", "T-5", "T-6", "T-7", "T-8", "T-9"];
/** Taille représentée d'un index de capture quand l'entrée ne la porte pas (annexe A.2). */
export const TAILLE_CAPTURE_REPRESENTEE = 4096;
/** Cadence quotidienne de mise à niveau après `give_up_after_s` (EX-8.11). */
const JOUR_S = 86400;

const REF_ENTREE = `${ID_SCHEMA_PLANIFICATEUR}#/$defs/evenement_entree`;
/** Codes d'échec d'une ancre qu'aucun nœud n'a admise (EX-9.5 : aucune transaction en mempool, aucun nonce consommé). */
const CODES_ANCRE_NON_ADMISE = Object.freeze(["noeud_injoignable", "transaction_refusee", "registre_absent", "exception_client", "reprise_impossible"]);

const ms = (h) => {
  const v = decoderHorodatage(h);
  if (v === null) throw new TypeError(`horodatage invalide : ${String(h)}`);
  return v;
};
/** Secondes entières tronquées d'une durée en millisecondes. */
const sEntieres = (dms) => Math.trunc(dms / 1000);
/** `gen_time` du schéma (secondes, décimales facultatives) en millisecondes. */
const msGenTime = (g) => {
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d{1,3})?Z$/.exec(g);
  if (!m) throw new TypeError(`gen_time invalide : ${String(g)}`);
  const frac = (m[2] ?? ".000").slice(1).padEnd(3, "0");
  return ms(`${m[1]}.${frac}Z`);
};
const trierNombres = (a) => [...a].sort((x, y) => x - y);
const cle = (org, journal, periodStart) => `${org}|${journal}|${periodStart}`;
const comparerDemandes = (a, b) => (a.created_at < b.created_at ? -1 : a.created_at > b.created_at ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

/**
 * Erreur d'entrée du planificateur (forme hors schéma, demande inconnue).
 * `code` vaut `entree_non_conforme` pour une entrée refusée par le schéma, avec
 * `chemin` (pointeur JSON de l'écart) : le composant en fait une entrée d'échec
 * conforme (R-F-1).
 */
export class ErreurPlanificateur extends Error {
  constructor(message, { code = null, chemin = null } = {}) {
    super(message);
    this.name = "ErreurPlanificateur";
    this.code = code;
    this.chemin = chemin;
  }
}

/** Pointeur JSON d'un message d'écart du validateur de schéma (`/data/x : ...`). */
function cheminEcart(message) {
  const m = /^(\/[^ ]*)/.exec(String(message ?? ""));
  return m ? m[1] : "";
}

/**
 * Source de nonces par défaut : `aleatoire(n)` du système ; un tirage nul du
 * nonce RFC 3161 est rejoué (EX-5.3).
 * @param {(n: number) => Uint8Array} aleatoire
 */
export function noncesAleatoires(aleatoire) {
  if (typeof aleatoire !== "function") throw new TypeError("aleatoire(n) attendu");
  return {
    rfc3161() {
      for (let i = 0; i < 64; i++) {
        const o = aleatoire(8);
        if (!(o instanceof Uint8Array) || o.length !== 8) throw new TypeError("aleatoire(8) : 8 octets attendus");
        let n = 0n;
        for (const x of o) n = (n << 8n) | BigInt(x);
        if (n !== 0n) return n;
      }
      throw new Error("générateur aléatoire défaillant : 64 tirages nuls");
    },
    ots() {
      const o = aleatoire(16);
      if (!(o instanceof Uint8Array) || o.length !== 16) throw new TypeError("aleatoire(16) : 16 octets attendus");
      return o;
    },
    gigue(max) {
      if (max === 0) return 0;
      const o = aleatoire(4);
      let v = 0;
      for (const x of o) v = v * 256 + x;
      return v % (max + 1);
    },
  };
}

/**
 * Planificateur d'une projection de configuration (EX-8.2).
 */
export class Planificateur {
  /**
   * @param {object} projection `$defs/configuration`
   * @param {{maintenant?: () => number, aleatoire?: (n: number) => Uint8Array, gigues?: number[],
   *   nonces?: {rfc3161: (p: object) => bigint|string, ots: (p: object) => Uint8Array, gigue?: (max: number) => number},
   *   file?: {ecrire: (d: object) => unknown}|null, sansRegistre?: boolean, fileInitiale?: object[]}} [options]
   */
  constructor(projection, options = {}) {
    const v = validerProjection(projection);
    if (!v.valide) throw new ErreurPlanificateur(`projection non conforme : ${v.erreurs[0]}`);
    this.config = structuredClone(projection);
    this.maintenant = options.maintenant ?? null;
    this.gigues = Array.isArray(options.gigues) ? [...options.gigues] : null;
    this.nonces = options.nonces ?? (options.aleatoire ? noncesAleatoires(options.aleatoire) : null);
    this.fileDurable = options.file ?? null;
    this.sansRegistre = options.sansRegistre === true;
    /** @type {Map<string, object>} demandes par id */
    this.demandes = new Map();
    /** @type {Map<string, object>} état interne par id (jamais écrit) */
    this.interne = new Map();
    /** @type {Map<string, object>} périodes connues */
    this.periodes = new Map();
    this.timers = [];
    this.seqTimer = 0;
    this.now = null;
    this.tDemarrage = null;
    this.demarre = false;
    this.actions = [];
    this.dernierEnvoi = new Map(); // prestataire → ms du dernier envoi
    this.compteurs = { ecritures: 0 };
    /** Tentative reprise par une action `programmer` (rang et `attempt_id`, pour la ligne `anchor_retry` du composant ; EX-8.15). */
    this.tentativesActions = new WeakMap();
    if (Array.isArray(options.fileInitiale)) for (const d of options.fileInitiale) this.chargerDemande(d);
    this.nT = 3600 / this.config.rfc3161.checkpoints.interval_s;
  }

  // ----- accès -----

  /** Demandes de la file, rangées par `created_at` puis `id` (comme `queue_after`). */
  file() {
    return trierDemandes([...this.demandes.values()]).map((d) => structuredClone(d));
  }

  /** Échéances d'une période connue (EX-4.2), avec leur état. */
  echeances(periodStart, org_id = null, journal_id = null) {
    const p = this.periodeDe(org_id, journal_id, periodStart, false);
    const cT = this.config.rfc3161.checkpoints.interval_s;
    const liste = [];
    for (let k = 1; k <= this.nT - 1; k++) {
      const e = p?.echeances.get(k) ?? null;
      liste.push({ k, at: ecrireHorodatage((periodStart + k * cT) * 1000), state: e ? e.state : "a_venir", request_id: e?.request ?? null });
    }
    return liste;
  }

  /** Nombre de demandes actives (non finales), règle 4 d'EX-8.5. */
  actives() {
    let n = 0;
    for (const d of this.demandes.values()) if (!estFinale(d)) n++;
    return n;
  }

  /**
   * Traite une entrée et rend les actions produites, dans l'ordre.
   * @param {object} entree `$defs/evenement_entree`
   * @returns {object[]} `$defs/action_attendue`
   */
  traiter(entree) {
    const v = REGISTRE_ANCRAGE.valider(REF_ENTREE, entree);
    if (!v.valide) throw new ErreurPlanificateur(`entrée non conforme : ${v.erreurs[0]}`, { code: "entree_non_conforme", chemin: cheminEcart(v.erreurs[0]) });
    const t = ms(entree.t);
    if (this.now !== null && t < this.now) throw new ErreurPlanificateur(`entrée antérieure à l'horloge du planificateur (${entree.t} < ${ecrireHorodatage(this.now)})`);
    if (!this.demarre && entree.type !== "demarrage") throw new ErreurPlanificateur("la première entrée est le démarrage");
    this.actions = [];
    if (entree.type === "demarrage") this.demarrer(t);
    else this.avancer(t);
    this.now = t;
    switch (entree.type) {
      case "demarrage":
        break;
      case "tic":
        break;
      case "point_produit":
        this.pointProduit(entree.data);
        break;
      case "periode_close":
        this.periodeClose(entree.data);
        break;
      case "reponse_rfc3161":
        this.reponseRfc3161(entree.data);
        break;
      case "reponse_ots":
        this.reponseOts(entree.data);
        break;
      case "inclusion_registre":
        this.inclusionRegistre(entree.data);
        break;
      case "echec_registre":
        this.echecRegistre(entree.data);
        break;
      case "stockage_relu":
        this.stockageRelu(entree.data);
        break;
      case "arret":
        this.emettre("journaliser", null, { event: "anchoring_stopped", queue_entries: this.demandes.size });
        break;
      default:
        throw new ErreurPlanificateur(`type d'entrée inconnu : ${entree.type}`);
    }
    // Les programmations immédiates (408, démarrage) prennent effet au même instant.
    if (entree.type !== "arret") this.avancer(t);
    return this.actions;
  }

  /** Tic à l'horloge injectée `maintenant` (composant temps réel). */
  tic() {
    if (!this.maintenant) throw new ErreurPlanificateur("aucune horloge injectée");
    return this.traiter({ t: ecrireHorodatage(this.maintenant()), type: "tic", data: {} });
  }

  /** Préambule commun des entrées hors schéma (`relever`, `revoquer`) : horloge avancée à `t`, actions vidées. */
  #entreeHorsSchema(t, requestId) {
    if (!this.demarre) throw new ErreurPlanificateur("la première entrée est le démarrage");
    const tMs = ms(t);
    if (this.now !== null && tMs < this.now) throw new ErreurPlanificateur(`entrée antérieure à l'horloge du planificateur (${t} < ${ecrireHorodatage(this.now)})`);
    this.actions = [];
    this.avancer(tMs);
    this.now = tMs;
    const req = this.demandes.get(requestId) ?? null;
    return { tMs, req };
  }

  /**
   * EX-5.9 (retrait de `qualified`, aucune entrée du schéma ne le porte) :
   * une demande `jeton_periode` ouverte chez le prestataire part aussi au
   * secours, comme sur une erreur permanente du principal (EX-5.7, EX-8.8).
   * Rend les actions produites ; une demande close ou déjà relevée ne produit
   * qu'une ligne `anchor_duplicate_ignored`.
   * @param {string} requestId
   * @param {{t: string, reason?: string}} p `t` : horodatage de l'horloge injectée
   */
  relever(requestId, { t, reason = "qualification_retiree" }) {
    const { req } = this.#entreeHorsSchema(t, requestId);
    if (!req || !req.kind.startsWith("jeton_")) {
      this.emettre("journaliser", requestId, { event: "anchor_duplicate_ignored", reason: "demande_inconnue" });
      return this.actions;
    }
    const i = this.interneDe(req.id);
    const { prestataire: secours } = this.releveDe(req);
    if (estFinale(req) || !secours || i.releve || i.epuises.has(secours.id) || i.revoques.has(secours.id)) {
      this.emettre("journaliser", req.id, { event: "anchor_duplicate_ignored", state: req.state, reason: "releve_sans_objet" });
      return this.actions;
    }
    this.annulerTimers(req.id, ["releve"]);
    i.releve = true;
    this.emettre("releve", req.id, { provider: secours.id });
    this.journaliserTentative(req, { event: "anchor_fallback", to: secours.id, reason }, this.derniereTentative(req));
    if (req.state === "envoyee" || req.state === "a_reprendre") {
      if (req.state === "a_reprendre") this.ecrire(req, "a_envoyer");
      this.envoyerRfc3161(req, secours.id);
    } else {
      // `a_envoyer` ou `attente_registre` : la relève suit la première tentative (envoi parallèle).
      i.releveImmediate = true;
    }
    this.avancer(this.now);
    return this.actions;
  }

  /**
   * EX-5.10 étape 10, EX-8.3 (révision 0.2 ; aucune entrée du schéma ne le
   * porte) : une révocation constatée après coup marque la tentative promue
   * `echec_permanente` (`revoque`), passe la demande `obtenue → a_reprendre`
   * et la fait repartir au secours (ou au prestataire désigné, au pas
   * `retry.max_ms`, quand il n'y a pas de secours). Rend les actions.
   * @param {string} requestId
   * @param {{t: string, provider: string}} p
   */
  revoquer(requestId, { t, provider }) {
    const { req } = this.#entreeHorsSchema(t, requestId);
    if (!req || !req.kind.startsWith("jeton_") || req.state !== "obtenue") {
      this.emettre("journaliser", requestId, { event: "anchor_duplicate_ignored", reason: req ? "demande_non_obtenue" : "demande_inconnue", state: req?.state ?? null });
      return this.actions;
    }
    const i = this.interneDe(req.id);
    const a = req.attempts.find((x) => x.outcome === "obtenue" && x.provider === provider) ?? this.derniereTentative(req);
    if (a) {
      a.outcome = "echec_permanente";
      a.error_code = "revoque";
      a.detail = "certificat de l'unite revoque apres genTime (T-10)";
      a.next_at = null;
    }
    req.result = null;
    this.emettre("alerter", req.id, { code: "revoque", severity: "critique" });
    this.journaliserTentative(req, { event: "anchor_response_rejected", error_code: "revoque", attempt: a?.n ?? null, provider: provider ?? null, kept: true }, a);
    i.epuises.add(provider);
    i.revoques.add(provider); // lecture H1-b : après une révocation, l'alternance d'EX-8.9 ne revient jamais à ce prestataire
    const { prestataire: secours } = this.releveDe(req);
    if (secours && secours.id !== provider && !i.epuises.has(secours.id)) {
      i.releve = true;
      this.ecrire(req, "a_reprendre");
      this.emettre("releve", req.id, { provider: secours.id });
      this.journaliserTentative(req, { event: "anchor_fallback", to: secours.id, reason: "revoque" }, a);
      this.envoyerRfc3161(req, secours.id);
    } else {
      const at = this.now + this.config.rfc3161.retry.max_ms;
      if (a) a.next_at = this.horodatage(at);
      req.due_at = this.horodatage(at);
      this.journaliserTentative(req, { event: "anchor_retry", kind: req.kind, mode: "reprise", error_code: "revoque" }, a);
      this.ecrire(req, "a_reprendre");
      this.programmer(req, at, "backoff", "reprise", { provider: null });
    }
    this.avancer(this.now);
    return this.actions;
  }

  /**
   * Rechargement de la configuration (EX-4.9 : la projection validée remplace
   * l'ancienne ; les demandes et minuteries en cours sont conservées).
   * @param {object} projection `$defs/configuration`
   */
  reconfigurer(projection) {
    const v = validerProjection(projection);
    if (!v.valide) throw new ErreurPlanificateur(`projection non conforme : ${v.erreurs[0]}`);
    this.config = structuredClone(projection);
    this.nT = 3600 / this.config.rfc3161.checkpoints.interval_s;
  }

  // ----- outils -----

  emettre(action, request_id, detail) {
    const a = { t: ecrireHorodatage(this.now), action, request_id, detail };
    this.actions.push(a);
    return a;
  }

  /**
   * Ligne `anchor_retry`, `anchor_fallback` ou `anchor_response_rejected` :
   * elle porte le rang `n` de sa tentative (`attempt`) et son `attempt_id`
   * (EX-8.15, révision 0.6), de sorte que l'historique des tentatives sorties
   * de la fenêtre de la file (EX-8.5, règle 7) se lit au journal ;
   * `attempt_id` est nul pour un rang qui ne désigne aucune tentative.
   */
  journaliserTentative(req, detail, tentative) {
    const n = typeof tentative === "number" ? tentative : tentative?.n ?? null;
    const existe = req && Number.isSafeInteger(n) && n >= 1 && n <= totalTentatives(req);
    return this.emettre("journaliser", req?.id ?? null, { ...detail, attempt: Number.isSafeInteger(n) ? n : null, attempt_id: existe ? this.correlation(req, n) : null });
  }

  associerTentative(action, req, tentative) {
    if (!req) return;
    const n = typeof tentative === "number" ? tentative : tentative?.n ?? null;
    if (!Number.isSafeInteger(n) || n < 1) return;
    this.tentativesActions.set(action, { n, attempt_id: this.correlation(req, n) });
  }

  /**
   * Tentative reprise par une action `programmer` : `{n, attempt_id}`, ou
   * null (la ligne `anchor_retry` que le composant consigne, EX-8.15).
   * @param {object} action
   */
  tentativeDe(action) {
    return this.tentativesActions.get(action) ?? null;
  }

  horodatage(msValeur) {
    return ecrireHorodatage(msValeur);
  }

  interneDe(id) {
    let i = this.interne.get(id);
    if (!i) {
      i = {
        epuises: new Set(), revoques: new Set(), releve: false, releveImmediate: false, alerteRegistre: false, alerteAttente: false, inclusionLate: 0, repli: false, nonceOts: null, soumisA: null, giveUp: false, http408: new Set(), relevable: null, epuisementAlerte: false,
        // Révision 0.6 : instant d'admission du point (EX-3.5), premier envoi de la demande, et ce que la mémoire garde
        // des tentatives sorties de la fenêtre de 32 (EX-8.5, règle 7) pour les attentes de reprise d'EX-8.9.
        // `inconnues` : tentatives sorties de la fenêtre avant un redémarrage, dont la mémoire ne sait rien.
        admisA: null, premierEnvoi: null, horsFenetre: { transitoires: 0, consecutifs: new Map(), admiseParNoeud: false, inconnues: 0, nonces: new Map() },
      };
      this.interne.set(id, i);
    }
    return i;
  }

  prestataire(role) {
    return this.config.rfc3161.providers.find((p) => p.role === role) ?? null;
  }

  prestataireParId(id) {
    return this.config.rfc3161.providers.find((p) => p.id === id) ?? null;
  }

  periodeDe(org_id, journal_id, periodStart, creer = true) {
    const k = cle(org_id, journal_id, periodStart);
    let p = this.periodes.get(k);
    if (!p && creer) {
      p = {
        org_id,
        journal_id,
        period_start: periodStart,
        echeances: new Map(),
        echeancesActives: false,
        close: false,
        periodHash: null,
        dernierPoint: null,
        dernierTs: null,
        manquantSignale: false,
        baseAncre: 0,
        points: new Map(),
      };
      this.periodes.set(k, p);
    }
    return p ?? null;
  }

  /** Active la liste des échéances d'une période : celles déjà atteintes sont ouvertes sans action. */
  activerEcheances(p) {
    if (p.echeancesActives) return;
    p.echeancesActives = true;
    const cT = this.config.rfc3161.checkpoints.interval_s;
    for (let k = 1; k <= this.nT - 1; k++) {
      const at = (p.period_start + k * cT) * 1000;
      if (!p.echeances.has(k) && at <= this.now) p.echeances.set(k, { state: "ouverte", request: null });
    }
  }

  gigue() {
    const max = this.config.rfc3161.retry.jitter_ms;
    if (this.gigues) return this.gigues.length ? this.gigues.shift() : 0;
    if (this.nonces?.gigue) return this.nonces.gigue(max);
    return 0;
  }

  programmer(req, at, raison, type, donnees = {}) {
    const action = this.emettre("programmer", req.id, { next_at: this.horodatage(at), reason: raison });
    this.associerTentative(action, req, this.derniereTentative(req));
    this.timers.push({ at, id: req.id, type, seq: this.seqTimer++, ...donnees });
  }

  annulerTimers(id, types = null) {
    this.timers = this.timers.filter((t) => !(t.id === id && (types === null || types.includes(t.type))));
  }

  ecrire(req, state) {
    req.state = state;
    if (ETATS_FINAUX.includes(state)) req.due_at = null;
    this.fenetrer(req);
    this.emettre("ecrire_file", req.id, { state });
    if (this.fileDurable) this.fileDurable.ecrire(structuredClone(req));
    this.compteurs.ecritures += 1;
  }

  nouvelleDemande(kind, sujet, deadlines = []) {
    const id = `${kind}:${sujet.hash}`;
    const existante = this.demandes.get(id);
    if (existante) {
      this.emettre("journaliser", id, { event: "anchor_duplicate_ignored", state: existante.state });
      return null;
    }
    const d = {
      version: 0,
      id,
      kind,
      subject: { kind: sujet.kind, org_id: sujet.org_id, journal_id: sujet.journal_id, period_start: sujet.period_start, hash: sujet.hash, tree_size: sujet.tree_size, declared_at: sujet.declared_at },
      deadlines: trierNombres(deadlines),
      state: "a_envoyer",
      created_at: this.horodatage(this.now),
      due_at: null,
      attempts: [],
      attempts_total: 0,
      result: null,
      replaced_by: null,
    };
    this.demandes.set(id, d);
    this.interneDe(id);
    return d;
  }

  chargerDemande(d) {
    // Lecture des lignes d'avant la révision 0.6 (EX-8.5, règle 7) : sans `attempts_total`, plus de 32 tentatives admises.
    const v = validerLigneDemande(d);
    if (!v.valide) throw new ErreurPlanificateur(`demande de la file non conforme : ${v.erreurs[0]}`);
    this.demandes.set(d.id, structuredClone(d));
    this.interneDe(d.id).horsFenetre.inconnues = Math.max(0, totalTentatives(d) - d.attempts.length);
  }

  demandesTriees() {
    return [...this.demandes.values()].sort(comparerDemandes);
  }

  indiceFile(id) {
    const tri = this.demandesTriees();
    return tri.findIndex((d) => d.id === id);
  }

  correlation(req, n) {
    return `${req.kind}:${req.subject.hash.slice(2, 18)}:${n}`;
  }

  /**
   * Fenêtre de 32 tentatives (EX-8.5, règle 7 ; révision 0.6), appliquée à
   * chaque ligne écrite : les tentatives `en_cours` toujours, puis les plus
   * récentes jusqu'à 32, rangées par `n` croissant ; `attempts_total` toujours
   * écrit, `n` jamais renuméroté. Ce que la mémoire garde des tentatives
   * sorties (échecs transitoires consécutifs par prestataire, admission d'une
   * transaction par un nœud) sert aux attentes d'EX-8.9 et à EX-9.5.
   */
  fenetrer(req) {
    req.attempts_total = totalTentatives(req);
    if (req.attempts.length <= FENETRE_TENTATIVES) return;
    const enCours = req.attempts.filter((a) => a.outcome === "en_cours");
    const autres = req.attempts.filter((a) => a.outcome !== "en_cours").sort((a, b) => b.n - a.n).slice(0, Math.max(0, FENETRE_TENTATIVES - enCours.length));
    const gardees = new Set([...enCours, ...autres]);
    const sorties = req.attempts.filter((a) => !gardees.has(a)).sort((a, b) => a.n - b.n);
    const h = this.interneDe(req.id).horsFenetre;
    for (const a of sorties) {
      const transitoire = a.outcome === "echec_transitoire" || a.outcome === "reponse_tardive";
      if (a.outcome === "echec_transitoire") h.transitoires += 1;
      const cle = a.provider ?? "";
      h.consecutifs.set(cle, transitoire ? (h.consecutifs.get(cle) ?? 0) + 1 : 0);
      if (a.outcome === "obtenue" || !CODES_ANCRE_NON_ADMISE.includes(a.error_code)) h.admiseParNoeud = true;
      // Nonce d'une requête RFC 3161 sortie de la fenêtre : une réponse tardive se rapporte encore à sa requête.
      if (a.nonce) h.nonces.set(a.n, a.nonce);
    }
    req.attempts = [...gardees].sort((a, b) => a.n - b.n);
  }

  nouvelleTentative(req, { provider = null, nonce = null, detail }) {
    const n = totalTentatives(req) + 1;
    req.attempts_total = n;
    const a = {
      n,
      provider,
      started_at: this.horodatage(this.now),
      nonce,
      correlation_id: this.correlation(req, n),
      outcome: "en_cours",
      error_code: null,
      http_status: null,
      pki_status: null,
      failure_info: null,
      retry_after_s: null,
      next_at: null,
      detail,
    };
    req.attempts.push(a);
    if (n === 1) this.interneDe(req.id).premierEnvoi = this.now;
    return a;
  }

  derniereTentative(req, provider = undefined) {
    for (let i = req.attempts.length - 1; i >= 0; i--) {
      if (provider === undefined || req.attempts[i].provider === provider) return req.attempts[i];
    }
    return null;
  }

  // ----- horloge et timers -----

  /** Fait avancer l'horloge jusqu'à `t` en déclenchant, dans l'ordre, ce qui échoit. */
  avancer(t) {
    for (;;) {
      const prochain = this.prochainEvenement(t);
      if (!prochain) break;
      this.now = prochain.at;
      prochain.declencher();
    }
    this.now = t;
  }

  prochainEvenement(limite) {
    let meilleur = null;
    const candidat = (at, rang, ordre, declencher) => {
      if (at > limite) return;
      if (!meilleur || at < meilleur.at || (at === meilleur.at && (rang < meilleur.rang || (rang === meilleur.rang && ordre < meilleur.ordre)))) {
        meilleur = { at, rang, ordre, declencher };
      }
    };
    const cT = this.config.rfc3161.checkpoints.interval_s;
    const cK = this.config.checkpoint_interval_s;
    for (const p of this.periodes.values()) {
      if (p.echeancesActives) {
        for (let k = 1; k <= this.nT - 1; k++) {
          if (p.echeances.has(k)) continue;
          const at = (p.period_start + k * cT) * 1000;
          candidat(at, 0, p.period_start * 100 + k, () => {
            p.echeances.set(k, { state: "ouverte", request: null });
            this.emettre("echeance", null, { k, state: "ouverte" });
          });
          break;
        }
      }
      // Alerte `point_manquant` (EX-4.1, 8.9, révision 0.4) : le délai de `2 × c_K` court depuis le
      // `checkpoint_ts` déclaré du dernier point admis, non depuis son admission ni depuis le
      // démarrage : un point relu longtemps après sa production (saut d'horloge, arrêt) lève
      // l'alerte dès sa relecture, à l'instant où elle était due. Le point de clôture
      // (`checkpoint_ts ≥ period_end`) n'arme aucune minuterie, ni une période close.
      if (!p.close && p.dernierTs !== null && !p.manquantSignale && p.dernierTs < (p.period_start + 3600) * 1000) {
        const base = p.dernierTs;
        const at = base + 2 * cK * 1000;
        candidat(at, 1, p.period_start, () => {
          p.manquantSignale = true;
          this.emettre("journaliser", null, { event: "point_manquant", last_checkpoint_ts: this.horodatage(p.dernierTs), gap_s: sEntieres(at - base) });
          this.emettre("alerter", null, { code: "point_manquant", severity: "majeure" });
        });
      }
    }
    if (this.timers.length) {
      const tri = this.demandesTriees();
      const indice = new Map(tri.map((d, i) => [d.id, i]));
      for (const tm of this.timers) {
        candidat(tm.at, 2, (indice.get(tm.id) ?? 1e9) * 1e6 + tm.seq, () => {
          this.timers = this.timers.filter((x) => x !== tm);
          this.declencherTimer(tm);
        });
      }
    }
    return meilleur;
  }

  declencherTimer(tm) {
    const req = this.demandes.get(tm.id);
    if (!req || estFinale(req)) return;
    switch (tm.type) {
      case "attente_registre":
        this.examinerAttenteRegistre(req);
        break;
      case "reprise":
        if (req.state === "a_reprendre" || req.state === "a_envoyer") this.envoyerRfc3161(req, tm.provider);
        break;
      case "prestataire":
        if (req.state !== "envoyee" || tm.force) this.envoyerRfc3161(req, tm.provider, true);
        break;
      case "releve":
        this.releverParDelai(req);
        break;
      case "recu":
        this.recuAbsent(req);
        break;
      case "mise_a_niveau":
        this.lancerMiseANiveau(req);
        break;
      case "reprise_ots":
        if (req.state === "a_reprendre") this.soumettreOts(req);
        break;
      case "repli_cloture":
        this.repliCloture(req);
        break;
      case "reprise_registre":
        this.reprendreRegistre(req);
        break;
      default:
        break;
    }
  }

  // ----- démarrage et reprise (EX-8.12) -----

  demarrer(t) {
    if (this.demarre) throw new ErreurPlanificateur("démarrage déjà fait");
    this.demarre = true;
    this.now = t;
    this.tDemarrage = t;
    this.emettre("journaliser", null, { event: "anchoring_started", queue_entries: this.demandes.size });
    // Périodes connues par la file : échéances tenues par les demandes de points.
    for (const d of this.demandesTriees()) {
      const s = d.subject;
      const p = this.periodeDe(s.org_id, s.journal_id, s.period_start);
      if (s.kind === "periode") p.close = true;
      if (d.kind === "ancre_registre_point" && d.state !== "refusee" && d.state !== "remplacee") p.baseAncre = Math.max(p.baseAncre, s.tree_size);
      if (s.kind === "point") p.points.set(s.hash, { hash: s.hash, tree_size: s.tree_size, checkpoint_ts: ms(s.declared_at) });
    }
    for (const d of this.demandesTriees()) {
      if (d.kind !== "jeton_point") continue;
      const p = this.periodeDe(d.subject.org_id, d.subject.journal_id, d.subject.period_start);
      this.activerEcheances(p);
      if (d.state === "obtenue") for (const k of d.deadlines) p.echeances.set(k, { state: "satisfaite", request: d.id });
      else if (!estFinale(d)) for (const k of d.deadlines) p.echeances.set(k, { state: "ouverte", request: d.id });
      if (d.deadlines.length === 0 && d.kind === "jeton_point") this.interneDe(d.id).repli = true;
      // EX-3.5 (révision 0.6) : la demande d'un point est créée à son admission ; relue de la file, elle garde
      // l'instant de cette admission (`created_at`). Un point relu du stockage au démarrage (`stockage_relu`) est
      // admis à l'instant de sa relecture, auquel sa demande est créée.
      this.interneDe(d.id).admisA = ms(d.created_at);
    }
    for (const p of this.periodes.values()) if (p.points.size) this.activerEcheances(p);
    // Transitions de reprise, dans l'ordre de la file.
    for (const d of this.demandesTriees()) {
      if (estFinale(d)) continue;
      const i = this.interneDe(d.id);
      if (d.kind.startsWith("ancre_registre_")) {
        if (d.state === "envoyee") {
          this.journaliserTentative(d, { event: "anchor_retry", kind: d.kind, mode: "renvoi" }, this.derniereTentative(d));
          this.emettre("envoyer_registre", d.id, { fingerprint: this.empreinte(d), doc_type: this.docType(d) });
          this.timers.push({ at: this.now + this.config.registry.inclusion_alert_s * 1000, id: d.id, type: "recu", seq: this.seqTimer++ });
        } else if (d.state === "a_reprendre") {
          if (d.due_at) this.timers.push({ at: Math.max(ms(d.due_at), this.now), id: d.id, type: "reprise_registre", seq: this.seqTimer++ });
        }
      } else if (d.kind.startsWith("jeton_")) {
        if (d.state === "attente_registre") {
          this.programmer(d, this.now, "attente_registre", "attente_registre");
        } else if (d.state === "envoyee") {
          for (const a of d.attempts) {
            if (a.outcome !== "en_cours") continue;
            a.outcome = "echec_transitoire";
            a.error_code = "redemarrage";
            a.detail = "redemarrage : reponse non recue";
            a.next_at = this.horodatage(this.now);
          }
          d.due_at = this.horodatage(this.now);
          this.ecrire(d, "a_reprendre");
          const fournisseurs = [...new Set(d.attempts.filter((a) => a.error_code === "redemarrage").map((a) => a.provider))];
          for (const f of fournisseurs.length ? fournisseurs : [null]) this.programmer(d, this.now, "immediat", "reprise", { provider: f });
        } else if (d.state === "a_reprendre") {
          const dernier = this.derniereTentative(d);
          const at = d.due_at ? ms(d.due_at) : this.now;
          this.timers.push({ at, id: d.id, type: "reprise", seq: this.seqTimer++, provider: dernier?.provider ?? null });
        }
        // La relève par délai n'est pas réarmée depuis d'anciennes tentatives : elle
        // l'est à la prochaine tentative (trace file-pleine).
        if (d.attempts.length) this.interneDe(d.id).releve = d.attempts.some((a) => a.provider === this.releveDe(d).prestataire?.id);
      } else if (d.kind.startsWith("ots_")) {
        if (d.state === "en_attente") {
          const at = Math.max(d.due_at ? ms(d.due_at) : this.now, this.now);
          i.soumisA = d.result ? ms(d.result.obtained_at) : this.now;
          d.due_at = this.horodatage(at);
          this.programmer(d, at, "mise_a_niveau", "mise_a_niveau");
        } else if (d.state === "envoyee" || d.state === "a_reprendre") {
          d.due_at = this.horodatage(this.now);
          if (d.state === "envoyee") this.ecrire(d, "a_reprendre");
          this.programmer(d, d.state === "a_reprendre" && d.due_at ? Math.max(ms(d.due_at), this.now) : this.now, "immediat", "reprise_ots");
        }
      }
    }
    // Demandes encore à envoyer (file interrompue entre l'écriture et l'envoi).
    for (const d of this.demandesTriees()) {
      if (d.state !== "a_envoyer") continue;
      if (d.kind.startsWith("ancre_registre_")) this.dispatcherRegistre(d);
      else if (d.kind.startsWith("ots_")) this.soumettreOts(d);
      else this.envoyerRfc3161(d, null);
    }
  }

  // ----- point admis (EX-8.4, règle 3 ; EX-4.3, EX-4.6, EX-6.1) -----

  pointProduit(data, reconstruction = null) {
    // Règle 2 d'EX-8.5 : un point déjà connu (même empreinte) ne crée aucune demande nouvelle ; chaque demande existante est signalée.
    const connues = ["ancre_registre_point", "jeton_point"].map((k) => this.demandes.get(`${k}:${data.checkpoint_hash}`)).filter(Boolean);
    if (connues.length) {
      for (const d of connues) this.emettre("journaliser", d.id, { event: "anchor_duplicate_ignored", state: d.state });
      return { creees: 0 };
    }
    const p = this.periodeDe(data.org_id, data.journal_id, data.period_start);
    const ts = ms(data.checkpoint_ts);
    p.dernierTs = ts;
    p.manquantSignale = false;
    // Instant d'admission (EX-3.5, révision 0.6) : celui de l'entrée `point_produit`, que le composant date sur
    // l'horloge de l'enregistreur après les vérifications d'EX-4.1 (AN-3) ; pour un point relu au démarrage
    // (`stockage_relu`), l'instant de sa relecture.
    p.dernierPoint = { hash: data.checkpoint_hash, tree_size: data.tree_size, checkpoint_ts: ts, declared_at: data.checkpoint_ts, admisA: this.now };
    p.points.set(data.checkpoint_hash, { hash: data.checkpoint_hash, tree_size: data.tree_size, checkpoint_ts: ts });
    this.activerEcheances(p);
    const sujet = { kind: "point", org_id: data.org_id, journal_id: data.journal_id, period_start: data.period_start, hash: data.checkpoint_hash, tree_size: data.tree_size, declared_at: data.checkpoint_ts };
    const compte = { creees: 0 };

    // Règle 4 d'EX-8.5 : file pleine, aucune demande de point.
    const actives = this.actives();
    if (actives >= this.config.queue.max_pending) {
      this.emettre("journaliser", null, { event: "anchor_queue_full", tree_size: data.tree_size, active: actives, max_pending: this.config.queue.max_pending });
      this.emettre("alerter", null, { code: "file_pleine", severity: "critique" });
      return compte;
    }

    // 1. Ancre au registre (EX-4.6, EX-9.3, EX-9.5).
    const regle = this.config.registry.checkpoints;
    if (regle !== "aucun" && (regle === "tous" || data.tree_size > p.baseAncre)) {
      const ancre = this.nouvelleDemande("ancre_registre_point", sujet);
      if (ancre) {
        compte.creees += 1;
        p.baseAncre = Math.max(p.baseAncre, data.tree_size);
        this.ecrire(ancre, "a_envoyer");
        for (const autre of this.demandesTriees()) {
          if (autre.kind !== "ancre_registre_point" || autre.id === ancre.id || !this.ancreEncoreAEnvoyer(autre)) continue;
          if (autre.subject.org_id !== sujet.org_id || autre.subject.journal_id !== sujet.journal_id || autre.subject.period_start !== sujet.period_start) continue;
          this.annulerTimers(autre.id);
          this.emettre("remplacer", autre.id, { replaced_by: ancre.id });
          autre.replaced_by = ancre.id;
          this.ecrire(autre, "remplacee");
          this.emettre("journaliser", autre.id, { event: "anchor_replaced", replaced_by: ancre.id });
        }
        this.dispatcherRegistre(ancre);
      }
    } else {
      this.emettre("journaliser", null, { event: "checkpoint_not_anchored", reason: regle === "aucun" ? "registre_aucun" : "aucun_nouvel_evenement", tree_size: data.tree_size });
    }

    // 2. Échéances (EX-4.3, EX-8.4 règle 1).
    const selection = [];
    if (p.echeancesActives) {
      for (const [k, e] of p.echeances) if (e.state === "ouverte" && e.request === null && (p.period_start + k * this.config.rfc3161.checkpoints.interval_s) * 1000 <= ts) selection.push(k);
    }
    selection.sort((a, b) => a - b);
    let jeton = null;
    if (selection.length && !this.demandes.has(`jeton_point:${data.checkpoint_hash}`)) {
      const base = this.dernierContresigne(p);
      const role = this.config.rfc3161.checkpoints.provider_role;
      if (role === "aucun") {
        // Points non contresignés (hors production, EX-4.9) : les échéances sont closes sans requête.
        for (const k of selection) {
          p.echeances.set(k, { state: "sans_objet", request: null });
          this.emettre("echeance", null, { k, state: "sans_objet" });
        }
        this.emettre("journaliser", null, { event: "deadline_sans_objet", reason: "prestataire_aucun", deadlines: selection, tree_size: data.tree_size });
      } else if (this.config.rfc3161.checkpoints.countersign_idle || data.tree_size > base) {
        const id = `jeton_point:${data.checkpoint_hash}`;
        for (const k of selection) this.emettre("echeance", id, { k, state: "ouverte" });
        jeton = this.nouvelleDemande("jeton_point", sujet, selection);
        this.interneDe(id).admisA = this.now;
        compte.creees += 1;
        for (const k of selection) p.echeances.set(k, { state: "ouverte", request: id });
        this.ecrireJetonPointInitial(jeton);
      } else {
        for (const k of selection) {
          p.echeances.set(k, { state: "sans_objet", request: null });
          this.emettre("echeance", null, { k, state: "sans_objet" });
        }
        this.emettre("journaliser", null, { event: "deadline_sans_objet", reason: "aucun_nouvel_evenement", deadlines: selection, tree_size: data.tree_size });
      }
    }

    // 3. Preuve OpenTimestamps du point médian (EX-6.1).
    const o = this.config.opentimestamps;
    if (o.enabled && o.checkpoint === "mi_periode" && this.nT > 1) {
      const km = Math.ceil(this.nT / 2);
      if (selection.includes(km)) {
        const ots = this.nouvelleDemande("ots_point", sujet, []);
        if (ots) {
          compte.creees += 1;
          this.ecrire(ots, "a_envoyer");
          this.soumettreOts(ots);
        }
      }
    }

    // 4. Requête RFC 3161 qui n'attend aucune ancre.
    if (jeton && jeton.state === "a_envoyer") this.envoyerRfc3161(jeton, null);
    void reconstruction;
    return compte;
  }

  /**
   * EX-9.5 : une ancre de point « encore à envoyer » est une demande `a_envoyer`,
   * ou une demande `a_reprendre` dont aucune tentative n'a été admise par un
   * nœud (registre injoignable ou transaction refusée partout : aucune
   * transaction en mempool, aucun nonce consommé) ; une ancre dont une
   * transaction est partie (`recu_absent`) suit la reprise de CT-4 §8.6.
   */
  ancreEncoreAEnvoyer(d) {
    if (d.state === "a_envoyer") return true;
    if (d.state !== "a_reprendre") return false;
    // Révision 0.6 : les tentatives sorties de la fenêtre de 32 comptent aussi ; inconnues (relues après un
    // redémarrage), l'ancre n'est pas tenue pour « encore à envoyer » : une transaction a pu partir (CT-4 §8.6).
    const h = this.interneDe(d.id).horsFenetre;
    if (h.admiseParNoeud || h.inconnues > 0) return false;
    return d.attempts.every((a) => a.outcome !== "obtenue" && CODES_ANCRE_NON_ADMISE.includes(a.error_code));
  }

  /** Dernier point contresigné de la période : plus grand tree_size dont le jeton est obtenu ou la demande active (EX-4.3). */
  dernierContresigne(p) {
    let base = 0;
    for (const d of this.demandes.values()) {
      if (d.kind !== "jeton_point" || d.subject.org_id !== p.org_id || d.subject.journal_id !== p.journal_id || d.subject.period_start !== p.period_start) continue;
      if (d.state === "obtenue" || !estFinale(d)) base = Math.max(base, d.subject.tree_size);
    }
    return base;
  }

  /** Première écriture d'un jeton de point : attente de l'ancre du registre (EX-8.4, règle 3) ou envoi direct. */
  ecrireJetonPointInitial(jeton) {
    const ancre = this.demandes.get(`ancre_registre_point:${jeton.subject.hash}`);
    if (ancre && (ancre.state === "a_envoyer" || ancre.state === "envoyee" || ancre.state === "a_reprendre")) {
      const at = ms(jeton.created_at) + this.config.registry.squat_wait_s * 1000;
      jeton.due_at = this.horodatage(at);
      this.ecrire(jeton, "attente_registre");
      this.programmer(jeton, at, "attente_registre", "attente_registre");
    } else {
      this.ecrire(jeton, "a_envoyer");
    }
  }

  // ----- clôture (EX-8.4, règle 2) -----

  periodeClose(data, reconstruction = null) {
    const p = this.periodeDe(data.org_id, data.journal_id, data.period_start);
    p.close = true;
    p.periodHash = data.period_hash;
    const sujet = { kind: "periode", org_id: data.org_id, journal_id: data.journal_id, period_start: data.period_start, hash: data.period_hash, tree_size: null, declared_at: data.generated_at };
    const creees = [];
    const ancre = this.demandes.has(`ancre_registre_periode:${data.period_hash}`) ? null : this.nouvelleDemande("ancre_registre_periode", sujet);
    const jeton = this.demandes.has(`jeton_periode:${data.period_hash}`) ? null : this.nouvelleDemande("jeton_periode", sujet);
    const ots = !this.config.opentimestamps.enabled || this.demandes.has(`ots_periode:${data.period_hash}`) ? null : this.nouvelleDemande("ots_periode", sujet);
    if (ancre) {
      this.ecrire(ancre, "a_envoyer");
      creees.push(ancre);
    }
    if (jeton) {
      if (this.sansRegistre) this.ecrire(jeton, "a_envoyer");
      else {
        jeton.due_at = this.horodatage(this.now + this.config.registry.inclusion_alert_s * 1000);
        this.ecrire(jeton, "attente_registre");
      }
      creees.push(jeton);
    }
    if (ots) {
      this.ecrire(ots, "a_envoyer");
      creees.push(ots);
    }
    for (const d of creees) {
      if (d.kind === "ancre_registre_periode") this.dispatcherRegistre(d);
      else if (d.kind === "jeton_periode") {
        if (d.state === "attente_registre") this.programmer(d, this.now + this.config.registry.inclusion_alert_s * 1000, "attente_registre", "attente_registre");
        else this.envoyerRfc3161(d, null);
      } else this.soumettreOts(d);
    }
    if (jeton && !this.sansRegistre && reconstruction === null) {
      this.timers.push({ at: this.now + this.config.registry.squat_wait_s * 1000, id: jeton.id, type: "repli_cloture", seq: this.seqTimer++ });
    }
    return creees.length;
  }

  /** Repli de clôture (EX-4.2, EX-8.4 règle 2) : jeton du point de clôture quand le registre tarde. */
  repliCloture(jetonPeriode) {
    if (jetonPeriode.state !== "attente_registre") return;
    const s = jetonPeriode.subject;
    const p = this.periodeDe(s.org_id, s.journal_id, s.period_start, false);
    const point = p?.dernierPoint ?? null;
    if (!point) return;
    if (this.demandes.has(`jeton_point:${point.hash}`)) return;
    if (point.tree_size <= this.dernierContresigne(p)) return;
    if (this.config.rfc3161.checkpoints.provider_role === "aucun") return;
    this.emettre("journaliser", `jeton_point:${point.hash}`, { event: "checkpoint_closing_fallback", tree_size: point.tree_size, period_request: jetonPeriode.id, squat_wait_s: this.config.registry.squat_wait_s });
    const sujet = { kind: "point", org_id: s.org_id, journal_id: s.journal_id, period_start: s.period_start, hash: point.hash, tree_size: point.tree_size, declared_at: point.declared_at };
    const jeton = this.nouvelleDemande("jeton_point", sujet, []);
    if (!jeton) return;
    this.interneDe(jeton.id).repli = true;
    this.interneDe(jeton.id).admisA = point.admisA ?? this.now;
    this.ecrireJetonPointInitial(jeton);
    if (jeton.state === "a_envoyer") this.envoyerRfc3161(jeton, null);
  }

  // ----- registre (EX-8.10, EX-9.4 à EX-9.7) -----

  empreinte(d) {
    return empreinteAncre(d.subject.org_id, d.subject.journal_id, d.subject.hash);
  }

  docType(d) {
    return d.subject.kind === "periode" ? DOC_TYPE_PERIODE : DOC_TYPE_POINT;
  }

  /** Une ancre de la même clé de chaîne attend-elle son reçu (EX-9.4) ? */
  registreOccupe(d) {
    for (const autre of this.demandes.values()) {
      if (autre.id === d.id || !autre.kind.startsWith("ancre_registre_") || autre.state !== "envoyee") continue;
      if (autre.subject.org_id === d.subject.org_id && autre.subject.journal_id === d.subject.journal_id) return true;
    }
    return false;
  }

  dispatcherRegistre(d) {
    if (this.registreOccupe(d)) {
      // Programmée sans minuterie : elle part au reçu (ou au refus) de l'ancre en vol (EX-9.4).
      this.emettre("programmer", d.id, { next_at: this.horodatage(this.now), reason: "attente_nonce" });
      return;
    }
    this.nouvelleTentative(d, { detail: "transaction envoyee" });
    this.ecrire(d, "envoyee");
    this.emettre("envoyer_registre", d.id, { fingerprint: this.empreinte(d), doc_type: this.docType(d) });
    this.timers.push({ at: this.now + this.config.registry.inclusion_alert_s * 1000, id: d.id, type: "recu", seq: this.seqTimer++ });
  }

  /**
   * Envoie la prochaine ancre à envoyer de la même clé : périodes d'abord, puis points par checkpoint_ts (EX-8.7, EX-9.4).
   * Une ancre `a_reprendre` dont l'échéance est passée est candidate au même titre : sa minuterie de reprise a pu tomber
   * pendant l'envoi d'une autre ancre (attente_nonce), elle part alors au reçu de celle-ci, au lieu d'attendre sans fin.
   */
  dispatcherRegistreSuivant(org_id, journal_id) {
    const candidates = this.demandesTriees().filter(
      (d) =>
        d.kind.startsWith("ancre_registre_") &&
        (d.state === "a_envoyer" || (d.state === "a_reprendre" && d.due_at !== null && ms(d.due_at) <= this.now)) &&
        d.subject.org_id === org_id &&
        d.subject.journal_id === journal_id,
    );
    if (!candidates.length) return;
    candidates.sort((a, b) => {
      if (a.subject.kind !== b.subject.kind) return a.subject.kind === "periode" ? -1 : 1;
      if (a.subject.kind === "periode") return a.subject.period_start - b.subject.period_start;
      return ms(a.subject.declared_at) - ms(b.subject.declared_at) || comparerDemandes(a, b);
    });
    this.dispatcherRegistre(candidates[0]);
  }

  recuAbsent(d) {
    if (d.state !== "envoyee") return;
    const i = this.interneDe(d.id);
    const a = this.derniereTentative(d);
    const delai = this.config.registry.inclusion_alert_s;
    if (a && a.outcome === "en_cours") {
      a.outcome = "echec_transitoire";
      a.error_code = "recu_absent";
      a.detail = `aucun recu en ${delai} s`;
      a.next_at = this.horodatage(this.now);
    }
    i.inclusionLate += 1;
    this.emettre("alerter", d.id, { code: "inclusion_late", severity: i.inclusionLate === 1 ? "mineure" : "majeure" });
    this.nouvelleTentative(d, { detail: "transaction envoyee" });
    this.ecrire(d, "envoyee");
    this.emettre("envoyer_registre", d.id, { fingerprint: this.empreinte(d), doc_type: this.docType(d) });
    this.timers.push({ at: this.now + delai * 1000, id: d.id, type: "recu", seq: this.seqTimer++ });
  }

  inclusionRegistre(data) {
    const d = this.demandes.get(data.request_id);
    if (!d || !d.kind.startsWith("ancre_registre_")) {
      this.emettre("journaliser", data.request_id, { event: "anchor_duplicate_ignored", reason: "demande_inconnue" });
      return;
    }
    if (estFinale(d)) {
      this.emettre("journaliser", d.id, { event: "anchor_duplicate_ignored", state: d.state });
      return;
    }
    const i = this.interneDe(d.id);
    this.annulerTimers(d.id, ["recu", "reprise_registre"]);
    let a = this.derniereTentative(d);
    if (!a || a.outcome !== "en_cours") a = this.nouvelleTentative(d, { detail: "transaction envoyee" });
    a.outcome = "obtenue";
    a.error_code = null;
    a.next_at = null;
    a.detail = `ancre incluse au bloc ${data.block_number}`;
    const taille = Number.isSafeInteger(data.capture_size) ? data.capture_size : TAILLE_CAPTURE_REPRESENTEE;
    d.result = { sha256: data.capture_sha256, size: taille, provider: null, obtained_at: this.horodatage(this.now), bound: null };
    this.emettre("stocker", d.id, { sha256: data.capture_sha256, size: taille, bound: null });
    this.ecrire(d, "obtenue");
    // Inclusion tardive constatée au reçu : délai depuis la création de la demande (trace bascule-epoque).
    const dInclusion = this.now - ms(d.created_at);
    if (dInclusion > this.config.registry.inclusion_alert_s * 1000 && i.inclusionLate === 0) {
      i.inclusionLate += 1;
      this.emettre("alerter", d.id, { code: "inclusion_late", severity: "mineure" });
    }
    // Le jeton du même sujet qui attendait l'inclusion part (EX-4.7, EX-8.4).
    const jeton = this.demandes.get(`${d.subject.kind === "periode" ? "jeton_periode" : "jeton_point"}:${d.subject.hash}`);
    if (jeton && jeton.state === "attente_registre") {
      this.annulerTimers(jeton.id, ["attente_registre"]);
      this.envoyerRfc3161(jeton, null);
    }
    this.dispatcherRegistreSuivant(d.subject.org_id, d.subject.journal_id);
  }

  echecRegistre(data) {
    const d = this.demandes.get(data.request_id);
    if (!d || !d.kind.startsWith("ancre_registre_")) {
      this.emettre("journaliser", data.request_id, { event: "anchor_duplicate_ignored", reason: "demande_inconnue" });
      return;
    }
    if (estFinale(d)) {
      this.emettre("journaliser", d.id, { event: "anchor_duplicate_ignored", state: d.state });
      return;
    }
    this.annulerTimers(d.id, ["recu", "reprise_registre"]);
    const a = this.derniereTentative(d) ?? this.nouvelleTentative(d, { detail: "transaction envoyee" });
    const code = data.code;
    const permanent = code === "empreinte_squattee" || code.startsWith("refus_");
    if (code === "empreinte_squattee") {
      a.outcome = "echec_permanente";
      a.error_code = code;
      a.detail = "empreinte deja ancree par un tiers";
      a.next_at = null;
      this.ecrire(d, "refusee");
      this.emettre("alerter", d.id, { code: "empreinte_squattee", severity: "critique" });
      this.emettre("journaliser", d.id, { event: "anchor_refused", error_code: code });
    } else if (permanent && d.subject.kind === "point") {
      a.outcome = "echec_permanente";
      a.error_code = code;
      a.detail = `registre : ${code}`;
      a.next_at = null;
      this.ecrire(d, "refusee");
      this.emettre("alerter", d.id, { code: "prestataires_epuises", severity: "majeure" });
      this.emettre("journaliser", d.id, { event: "anchor_refused", error_code: code });
    } else {
      // Transitoire (recu_absent, noeud_injoignable…) ou refus d'une ancre de période, jamais abandonnée (EX-4.5).
      a.outcome = permanent ? "echec_permanente" : "echec_transitoire";
      a.error_code = code;
      a.detail = `registre : ${code}`;
      const r = this.config.rfc3161.retry;
      // Toutes les tentatives d'une ancre non finale ont échoué : celles sorties de la fenêtre comptent (EX-8.5, règle 7).
      const k = d.attempts.filter((x) => x.outcome !== "obtenue").length + Math.max(0, totalTentatives(d) - d.attempts.length);
      const dAttente = permanent ? r.max_ms : Math.min(r.max_ms, r.initial_ms * r.factor ** Math.max(0, k - 1)) + this.gigue();
      const at = this.now + dAttente;
      a.next_at = this.horodatage(at);
      d.due_at = a.next_at;
      this.journaliserTentative(d, { event: "anchor_retry", kind: d.kind, mode: "reprise", error_code: code }, a);
      this.ecrire(d, "a_reprendre");
      this.programmer(d, at, "backoff", "reprise_registre");
    }
    // Le jeton du même point qui attendait cette ancre part sans attendre (EX-9.7) ; la clé est libre.
    const jeton = this.demandes.get(`${d.subject.kind === "periode" ? "jeton_periode" : "jeton_point"}:${d.subject.hash}`);
    if (jeton && jeton.state === "attente_registre" && d.state === "refusee" && d.subject.kind === "point") {
      this.annulerTimers(jeton.id, ["attente_registre"]);
      this.envoyerRfc3161(jeton, null);
    }
    this.dispatcherRegistreSuivant(d.subject.org_id, d.subject.journal_id);
  }

  /** Timer `reprise_registre` : renvoi d'une ancre `a_reprendre`. */
  reprendreRegistre(d) {
    if (d.state !== "a_reprendre") return;
    this.dispatcherRegistre(d);
  }

  /** Examen d'une demande `attente_registre` à son échéance (EX-8.4 règles 2 et 3, EX-9.6). */
  examinerAttenteRegistre(req) {
    if (req.state !== "attente_registre") return;
    const ancre = this.demandes.get(`${req.subject.kind === "periode" ? "ancre_registre_periode" : "ancre_registre_point"}:${req.subject.hash}`);
    if (ancre && ancre.state === "obtenue") {
      this.envoyerRfc3161(req, null);
      return;
    }
    if (req.kind === "jeton_point") {
      const limite = ms(req.created_at) + this.config.registry.squat_wait_s * 1000;
      if (!ancre || ancre.state === "refusee" || this.now >= limite) {
        if (ancre && ancre.state !== "refusee") {
          this.emettre("journaliser", req.id, { event: "ordre_ancres_non_respecte", tree_size: req.subject.tree_size, squat_wait_s: this.config.registry.squat_wait_s });
        }
        this.envoyerRfc3161(req, null);
      } else {
        req.due_at = this.horodatage(limite);
        this.programmer(req, limite, "attente_registre", "attente_registre");
      }
      return;
    }
    // jeton_periode : jamais sans l'inclusion (CT-4 EX-8.4) ; supervision.
    const i = this.interneDe(req.id);
    const age = sEntieres(this.now - ms(req.created_at));
    const alerte = this.config.registry.inclusion_alert_s;
    if (age >= alerte) {
      this.emettre("journaliser", req.id, { event: "registry_pending", age_s: age });
      if (!i.alerteRegistre) {
        i.alerteRegistre = true;
        this.emettre("alerter", req.id, { code: "registry_pending", severity: "majeure" });
      }
    }
    if (age >= this.config.queue.anchor_pending_alert_s && !i.alerteAttente) {
      i.alerteAttente = true;
      this.emettre("journaliser", req.id, { event: "anchor_pending", age_s: age });
      this.emettre("alerter", req.id, { code: "anchor_pending", severity: "majeure" });
    }
    const at = this.now + alerte * 1000;
    req.due_at = this.horodatage(at);
    this.programmer(req, at, "attente_registre", "attente_registre");
  }

  // ----- RFC 3161 : envoi, relève, reprise (EX-8.6 à EX-8.9) -----

  /** Prestataire désigné et délai de relève d'une demande de jeton (EX-5.6, EX-5.7). */
  releveDe(req) {
    const r = this.config.rfc3161;
    if (req.kind === "jeton_periode") return { prestataire: this.prestataire("secours"), delai: r.manifest.fallback_after_s };
    if (r.checkpoints.provider_role === "principal") return { prestataire: this.prestataire("secours"), delai: r.checkpoints.fallback_after_s };
    return { prestataire: null, delai: null };
  }

  /** Prestataire de la série principale d'une demande. */
  prestatairePrincipal(req) {
    if (req.kind === "jeton_periode") return this.prestataire("principal");
    const role = this.config.rfc3161.checkpoints.provider_role;
    return role === "aucun" ? null : this.prestataire(role);
  }

  /** Prestataire de la prochaine tentative : série demandée, ou alternance après épuisement (EX-8.8, EX-8.9). */
  choisirPrestataire(req, demande) {
    const i = this.interneDe(req.id);
    const principal = this.prestatairePrincipal(req);
    const secours = this.releveDe(req).prestataire;
    let candidats = [principal, secours].filter(Boolean);
    // Lecture H1-b : un prestataire dont le certificat d'unité est révoqué (T-10, EX-5.10 étape 10) ne reçoit plus de
    // requête tant qu'un autre candidat existe ; seul, il reste le dernier recours (EX-8.3 : reprise au pas retry.max_ms).
    const nonRevoques = candidats.filter((c) => !i.revoques.has(c.id));
    if (nonRevoques.length) candidats = nonRevoques;
    if (candidats.length && candidats.every((c) => i.epuises.has(c.id))) {
      // Alternance au pas retry.max_ms : l'autre que celui de la dernière tentative.
      const dernier = this.derniereTentative(req);
      if (candidats.length === 1) return candidats[0];
      return dernier && dernier.provider === candidats[0].id ? candidats[1] : candidats[0];
    }
    if (demande) {
      const p = this.prestataireParId(demande);
      if (p && !i.epuises.has(p.id) && candidats.some((c) => c.id === p.id)) return p;
    }
    if (principal && !i.epuises.has(principal.id) && candidats.some((c) => c.id === principal.id)) return principal;
    if (secours && i.releve && !i.epuises.has(secours.id) && candidats.some((c) => c.id === secours.id)) return secours;
    return candidats[0] ?? principal ?? secours;
  }

  /**
   * Envoie la requête d'une demande de jeton à son prestataire : ligne `envoyee`
   * (nonce et attempt_id) avant l'action d'envoi (EX-8.5, règle 1).
   * @param {object} req
   * @param {string|null} prestataireDemande id du prestataire de la série à poursuivre
   * @param {boolean} [depuisAttente] déclenchement par le timer `prestataire`
   */
  envoyerRfc3161(req, prestataireDemande, depuisAttente = false) {
    if (estFinale(req)) return;
    const p = this.choisirPrestataire(req, prestataireDemande);
    if (!p) return;
    const i = this.interneDe(req.id);
    // Une tentative est déjà en cours chez ce prestataire : rien à envoyer.
    if (req.attempts.some((a) => a.provider === p.id && a.outcome === "en_cours")) return;
    // min_interval_ms du prestataire, toutes demandes confondues (EX-8.7).
    const dernierEnvoi = this.dernierEnvoi.get(p.id);
    if (dernierEnvoi !== undefined && p.min_interval_ms > 0 && this.now < dernierEnvoi + p.min_interval_ms) {
      const at = dernierEnvoi + p.min_interval_ms;
      // Lecture H1-c : `due_at` (informatif) dit l'instant de l'envoi retenu par `min_interval_ms` (EX-8.7).
      req.due_at = this.horodatage(at);
      this.programmer(req, at, "backoff", "prestataire", { provider: p.id, force: true });
      return;
    }
    void depuisAttente;
    const nonce = this.nonceRfc3161(req, totalTentatives(req) + 1);
    const nonceH = nonceHex(nonceEntier(nonce));
    const requete = construireRequete({ imprint: req.subject.hash, nonce: nonceH, policy_oid: p.policy_oid });
    this.nouvelleTentative(req, { provider: p.id, nonce: nonceH, detail: "requete envoyee" });
    req.due_at = null;
    this.ecrire(req, "envoyee");
    this.emettre("envoyer_rfc3161", req.id, {
      provider: p.id,
      attempt: req.attempts_total,
      digest: req.subject.hash,
      nonce: nonceH,
      policy_oid: p.policy_oid,
      request_sha256: requete.sha256,
      request_size: requete.taille,
    });
    this.dernierEnvoi.set(p.id, this.now);
    // Relève par délai : armée à la première tentative chez le prestataire désigné (EX-8.8).
    if (i.relevable === null) {
      const { prestataire: secours, delai } = this.releveDe(req);
      i.relevable = Boolean(secours);
      if (secours && p.id !== secours.id && !i.releveImmediate) this.timers.push({ at: this.now + delai * 1000, id: req.id, type: "releve", seq: this.seqTimer++ });
    }
    // Relève demandée avant le premier envoi (EX-5.9 : qualification retirée) : le secours est sollicité en parallèle.
    if (i.releveImmediate) {
      i.releveImmediate = false;
      const { prestataire: secours } = this.releveDe(req);
      if (secours && p.id !== secours.id && !i.epuises.has(secours.id)) this.envoyerRfc3161(req, secours.id);
    }
  }

  nonceRfc3161(req, n) {
    if (!this.nonces) throw new ErreurPlanificateur("aucune source de nonces injectée (aleatoire ou nonces)");
    return this.nonces.rfc3161({ kind: req.kind, hash: req.subject.hash, n, org_id: req.subject.org_id, journal_id: req.subject.journal_id, period_start: req.subject.period_start, subjectKind: req.subject.kind });
  }

  /** Relève par délai (EX-8.8) : la demande part aussi au secours. */
  releverParDelai(req) {
    if (estFinale(req)) return;
    const i = this.interneDe(req.id);
    const { prestataire: secours } = this.releveDe(req);
    if (!secours || i.releve || i.epuises.has(secours.id) || i.revoques.has(secours.id)) return;
    i.releve = true;
    this.emettre("releve", req.id, { provider: secours.id });
    this.journaliserTentative(req, { event: "anchor_fallback", to: secours.id, reason: "delai" }, this.derniereTentative(req));
    this.envoyerRfc3161(req, secours.id);
  }

  /**
   * Attente de reprise d'EX-8.9 après un échec transitoire chez `p` : la table
   * unique `attenteTransitoire` du lot A (R-C-2) ; `Retry-After` borné à
   * `[initial_ms, max_ms]` sur 429 et 503 seulement (R-C-1, R-C-3) ; premier
   * 408 immédiat une fois par prestataire ; la gigue s'ajoute au seul `backoff`.
   */
  attenteReprise(req, p, data, codeHttp) {
    const r = this.config.rfc3161.retry;
    const i = this.interneDe(req.id);
    let k = 0;
    let rompu = false;
    for (let j = req.attempts.length - 1; j >= 0; j--) {
      const a = req.attempts[j];
      if (a.provider !== p.id) continue;
      if (a.outcome === "echec_transitoire" || a.outcome === "reponse_tardive") k += 1;
      else {
        rompu = true;
        break;
      }
    }
    // Révision 0.6 : la série se poursuit dans les tentatives sorties de la fenêtre de 32 (EX-8.5, règle 7) ; au-delà
    // de 21 échecs l'attente est de toute façon `retry.max_ms` (bornes du schéma : facteur ≥ 2, initial_ms ≥ 100).
    if (!rompu) k += i.horsFenetre.consecutifs.get(p.id) ?? 0;
    const premier408 = codeHttp === 408 && !i.http408.has(p.id);
    if (codeHttp === 408) i.http408.add(p.id);
    const a = attenteTransitoire({ httpStatus: codeHttp, retryAfterS: bornerRetryAfter(data.retry_after_s ?? null), retry: r, k: Math.max(1, k), premier408 });
    return { d: a.raison === "backoff" ? a.attenteMs + this.gigue() : a.attenteMs, raison: a.raison };
  }

  /** Échecs transitoires d'une demande sortis de la fenêtre de 32 (mémoire ; inconnus d'une file relue comptés transitoires). */
  transitoiresHorsFenetre(req) {
    const h = this.interneDe(req.id).horsFenetre;
    return h.transitoires + h.inconnues;
  }

  /** Classement d'une réponse RFC 3161 (EX-5.10 étapes 1 à 8, EX-5.12), sans vérifier de jeton. */
  classer(req, attempt, data) {
    const fr = this.config.rfc3161.freshness;
    const permanente = (code, detail) => ({ issue: "echec_permanente", classe: "permanente", code, detail });
    const transitoire = (code, detail) => ({ issue: "echec_transitoire", classe: "transitoire", code, detail });
    if (data.transport === "erreur_transport") return transitoire("erreur_transport", "erreur de transport");
    if (data.transport === "delai") return transitoire("delai", "delai de reponse depasse");
    const statut = data.http_status;
    if (statut !== 200) {
      const code = `http_${statut}`;
      if (HTTP_TRANSITOIRES.has(statut)) {
        const ra = data.retry_after_s !== null && data.retry_after_s !== undefined ? ` ; Retry-After ${data.retry_after_s} s` : "";
        return transitoire(code, `http ${statut}${ra}`);
      }
      return permanente(code, `http ${statut}`);
    }
    if (typeof data.content_type === "string" && !TYPES_REPONSE.has(data.content_type.split(";")[0].trim().toLowerCase())) {
      return permanente("type_contenu", `Content-Type ${data.content_type} non admis`);
    }
    if (Number.isSafeInteger(data.body_size) && data.body_size > CORPS_MAX) return permanente("taille", `corps de ${data.body_size} octets, au plus ${CORPS_MAX}`);
    const pki = data.pki_status;
    if (pki === null || pki === undefined) return permanente("reponse_illisible", "TimeStampResp illisible");
    if (pki === 2) {
      const fi = data.failure_info;
      if (fi && ECHECS_PERMANENTS.has(fi)) return permanente(`echec_${fi}`, `PKIStatus 2 (rejection) ; ${fi}`);
      if (fi && ECHECS_TRANSITOIRES.has(fi)) return transitoire(`echec_${fi}`, `PKIStatus 2 (rejection) ; ${fi}`);
      return permanente("statut_2", "PKIStatus 2 (rejection)");
    }
    if (pki === 3) return transitoire("statut_3", "PKIStatus 3 (waiting)");
    if (pki === 4 || pki === 5) return { ...permanente(`statut_${pki}`, `PKIStatus ${pki} (revocation)`), revocation: true };
    if (pki !== 0 && pki !== 1) return permanente(`statut_${pki}`, `PKIStatus ${pki} inconnu`);
    if (data.token_sha256 === null || data.token_sha256 === undefined) return permanente("reponse_illisible", "TimeStampToken absent");
    if (data.imprint_matches !== true) return permanente("empreinte_differente", "messageImprint different de l'empreinte demandee");
    if (data.nonce_in_response === null || data.nonce_in_response === undefined) return permanente("nonce_absent", "nonce absent du TSTInfo");
    if (data.nonce_in_response !== attempt.nonce) return permanente("nonce_different", "nonce du TSTInfo different de celui de la requete");
    if (data.policy_check === "politique_differente") return permanente("politique_differente", "politique differente de reqPolicy");
    if (data.policy_check === "politique_refusee") return permanente("politique_refusee", "politique hors de accepted_policies");
    const manquante = VERIFICATIONS_T.find((t) => !data.checks_passed.includes(t));
    if (manquante) return permanente(`verification_${manquante}`, `verification ${manquante} en echec`);
    const envoi = ms(attempt.started_at);
    const delai = this.now - envoi;
    const avertissements = [];
    const genTime = msGenTime(data.gen_time);
    if (Math.abs(genTime - envoi) > fr.clock_tolerance_s * 1000) avertissements.push("horloge_suspecte");
    if (delai > fr.max_response_delay_s * 1000) {
      let tardives = 0;
      for (let j = req.attempts.length - 1; j >= 0; j--) {
        if (req.attempts[j] === attempt) continue;
        if (req.attempts[j].outcome === "reponse_tardive") tardives += 1;
        else break;
      }
      if (tardives < 2) return { issue: "reponse_tardive", classe: "transitoire", code: "reponse_tardive", detail: `reponse recue ${sEntieres(delai)} s apres l'envoi`, valable: true };
      avertissements.push("reponse_tardive");
    }
    return { issue: "obtenue", avertissements, valable: true };
  }

  reponseRfc3161(data) {
    const req = this.demandes.get(data.request_id);
    if (!req || !req.kind.startsWith("jeton_")) {
      this.emettre("journaliser", data.request_id, { event: "anchor_response_rejected", error_code: "demande_inconnue", attempt: data.attempt, provider: null, kept: false });
      return;
    }
    const attempt = req.attempts.find((a) => a.n === data.attempt) ?? null;
    const jeton = data.token_sha256 !== null && data.token_sha256 !== undefined;
    const borneValable = (a) => (a && jeton && data.gen_time && data.imprint_matches === true && data.nonce_in_response === a.nonce && (data.policy_check ?? "conforme") === "conforme" && VERIFICATIONS_T.every((t) => data.checks_passed.includes(t))
      ? this.horodatage(msGenTime(data.gen_time) + (data.accuracy_s ?? 0) * 1000)
      : null);
    if (estFinale(req) || !attempt || attempt.outcome !== "en_cours") {
      // Réponse à une demande close ou à une tentative remplacée : conservée comme pièce, jamais promue (EX-5.8, EX-5.11, EX-8.5).
      // Révision 0.6 : une tentative sortie de la fenêtre de 32 (rang au plus `attempts_total`) se traite comme une
      // tentative qui n'est plus en cours (EX-8.5, règle 7) : conservée, non promue.
      const sortie = !attempt && Number.isSafeInteger(data.attempt) && data.attempt >= 1 && data.attempt <= totalTentatives(req);
      const horsFenetre = sortie ? { n: data.attempt, nonce: this.interneDe(req.id).horsFenetre.nonces.get(data.attempt) ?? null } : null;
      if (jeton) this.emettre("stocker", req.id, { sha256: data.token_sha256, size: data.token_size, bound: borneValable(attempt ?? (horsFenetre?.nonce ? horsFenetre : null)) });
      const code = !attempt && !sortie ? "tentative_inconnue" : estFinale(req) ? "demande_close" : "tentative_close";
      this.journaliserTentative(req, { event: "anchor_response_rejected", error_code: code, attempt: data.attempt, provider: attempt?.provider ?? null, kept: jeton }, attempt ?? (sortie ? data.attempt : null));
      return;
    }
    const p = this.prestataireParId(attempt.provider);
    const i = this.interneDe(req.id);
    const verdict = this.classer(req, attempt, data);
    attempt.http_status = data.http_status;
    attempt.pki_status = data.pki_status;
    attempt.failure_info = data.failure_info;
    attempt.retry_after_s = bornerRetryAfter(data.retry_after_s ?? null); // borne du schéma (R-C-1)
    if (jeton) this.emettre("stocker", req.id, { sha256: data.token_sha256, size: data.token_size, bound: verdict.valable ? borneValable(attempt) : null });

    if (verdict.issue === "obtenue") {
      this.promouvoir(req, attempt, data, verdict.avertissements);
      return;
    }
    attempt.outcome = verdict.issue;
    attempt.error_code = verdict.code;
    attempt.detail = verdict.detail;
    this.emettre("rejeter_reponse", req.id, { error_code: verdict.code, class: verdict.classe });
    this.journaliserTentative(req, { event: "anchor_response_rejected", error_code: verdict.code, attempt: attempt.n, provider: attempt.provider }, attempt);
    if (verdict.revocation) this.emettre("alerter", req.id, { code: "revoque", severity: "critique" });

    if (verdict.classe === "transitoire") {
      const { d, raison } = this.attenteReprise(req, p, data, data.http_status);
      const at = this.now + d;
      attempt.next_at = this.horodatage(at);
      req.due_at = attempt.next_at;
      this.ecrire(req, "a_reprendre");
      this.programmer(req, at, raison, "reprise", { provider: p.id });
      return;
    }
    this.apresPermanente(req, attempt, p, verdict.code);
  }

  /**
   * Suite d'une erreur permanente d'une demande de jeton chez `p` (EX-5.12,
   * EX-8.8) : relève immédiate au secours, ou épuisement (reprise au pas
   * `retry.max_ms` pour un `jeton_periode`, `refusee` pour un `jeton_point`).
   */
  apresPermanente(req, attempt, p, code) {
    const i = this.interneDe(req.id);
    // Permanente : relève immédiate, ou épuisement (EX-8.8).
    i.epuises.add(p.id);
    const { prestataire: secours } = this.releveDe(req);
    const principal = this.prestatairePrincipal(req);
    const candidats = [principal, secours].filter(Boolean);
    const restants = candidats.filter((c) => !i.epuises.has(c.id));
    if (restants.length && secours && p.id !== secours.id && !i.releve) {
      // Première erreur permanente chez le principal : relève sans réexpédition (EX-5.12, EX-8.3).
      this.annulerTimers(req.id, ["releve"]);
      i.releve = true;
      this.ecrire(req, "a_envoyer");
      this.emettre("releve", req.id, { provider: secours.id });
      this.journaliserTentative(req, { event: "anchor_fallback", to: secours.id, reason: code }, attempt);
      this.envoyerRfc3161(req, secours.id);
      return;
    }
    if (restants.length) {
      // L'autre série reste active : rien de plus pour celle-ci.
      return;
    }
    this.annulerTimers(req.id, ["releve"]);
    if (req.kind === "jeton_periode") {
      if (!i.epuisementAlerte) {
        i.epuisementAlerte = true;
        this.emettre("alerter", req.id, { code: "prestataires_epuises", severity: "critique" });
      }
      const at = this.now + this.config.rfc3161.retry.max_ms;
      attempt.next_at = this.horodatage(at);
      req.due_at = attempt.next_at;
      this.ecrire(req, "a_reprendre");
      this.programmer(req, at, "backoff", "reprise", { provider: null });
      return;
    }
    this.ecrire(req, "refusee");
    this.emettre("alerter", req.id, { code: "prestataires_epuises", severity: "majeure" });
    this.emettre("journaliser", req.id, { event: "anchor_refused", error_code: code, provider: p.id });
    this.rendreEcheances(req);
  }

  /**
   * Entrée hors schéma (règle 1 d'INTERFACES.md ; correction R-F-1) : le
   * résultat d'un client refusé par le schéma du planificateur devient une
   * issue d'échec conforme, pour qu'aucune demande ne reste `envoyee` sans
   * issue. `code` : `entree_non_conforme` ; `detail` : pointeur JSON de
   * l'écart. Jeton RFC 3161 : tentative `echec_permanente` puis la conduite
   * d'une erreur permanente (relève, épuisement) ; OpenTimestamps : tentative
   * `echec_transitoire`, soumission rejouée au pas de `retry` ou mise à niveau
   * reprogrammée ; registre : traité comme un `echec_registre` de ce code.
   * Rend les actions produites.
   * @param {string} requestId
   * @param {{t: string, attempt?: number|null, code?: string, detail?: string}} p
   */
  rejeter(requestId, { t, attempt = null, code = "entree_non_conforme", detail = "" }) {
    const { req } = this.#entreeHorsSchema(t, requestId);
    const texte = String(detail ?? "").slice(0, 200);
    if (!req) {
      this.emettre("journaliser", requestId, { event: "anchor_response_rejected", error_code: code, attempt, provider: null, kept: false, detail: texte });
      return this.actions;
    }
    if (req.kind.startsWith("ancre_registre_")) {
      this.echecRegistre({ request_id: req.id, code });
      this.avancer(this.now);
      return this.actions;
    }
    if (estFinale(req)) {
      this.emettre("journaliser", req.id, { event: "anchor_response_rejected", error_code: "demande_close", attempt, provider: null, kept: false });
      return this.actions;
    }
    // Révision 0.6 : une tentative désignée qui est sortie de la fenêtre n'est plus en cours (EX-8.5, règle 7).
    const a = attempt !== null ? req.attempts.find((x) => x.n === attempt) ?? null : this.derniereTentative(req);
    if (!a || a.outcome !== "en_cours") {
      this.journaliserTentative(req, { event: "anchor_response_rejected", error_code: "tentative_close", attempt, provider: a?.provider ?? null, kept: false }, a ?? attempt);
      return this.actions;
    }
    if (req.kind.startsWith("jeton_")) {
      const p = this.prestataireParId(a.provider);
      a.outcome = "echec_permanente";
      a.error_code = code;
      a.detail = `reponse hors schema : ${texte}`.slice(0, 1024);
      a.next_at = null;
      this.emettre("rejeter_reponse", req.id, { error_code: code, class: "permanente" });
      this.journaliserTentative(req, { event: "anchor_response_rejected", error_code: code, attempt: a.n, provider: a.provider, detail: texte }, a);
      if (p) this.apresPermanente(req, a, p, code);
      else {
        // Prestataire retiré de la configuration : la demande repart au pas retry.max_ms chez le prestataire désigné.
        const at = this.now + this.config.rfc3161.retry.max_ms;
        a.next_at = this.horodatage(at);
        req.due_at = a.next_at;
        this.ecrire(req, "a_reprendre");
        this.programmer(req, at, "backoff", "reprise", { provider: null });
      }
      this.avancer(this.now);
      return this.actions;
    }
    // ots_* : la soumission ou la mise à niveau est rejouée (EX-8.11), jamais abandonnée.
    const r = this.config.rfc3161.retry;
    a.outcome = "echec_transitoire";
    a.error_code = code;
    a.detail = `reponse hors schema : ${texte}`.slice(0, 1024);
    this.emettre("rejeter_reponse", req.id, { error_code: code, class: "transitoire" });
    this.journaliserTentative(req, { event: "anchor_response_rejected", error_code: code, attempt: a.n, provider: null, detail: texte }, a);
    if (req.state === "en_attente") {
      const at = this.now + Math.max(60, this.config.opentimestamps.upgrade.interval_s) * 1000;
      a.next_at = this.horodatage(at);
      req.due_at = a.next_at;
      this.ecrire(req, "en_attente");
      this.programmer(req, at, "mise_a_niveau", "mise_a_niveau");
    } else {
      const k = req.attempts.filter((x) => x.outcome === "echec_transitoire").length + this.transitoiresHorsFenetre(req);
      const at = this.now + Math.min(r.max_ms, r.initial_ms * r.factor ** Math.max(0, k - 1)) + this.gigue();
      a.next_at = this.horodatage(at);
      req.due_at = a.next_at;
      this.ecrire(req, "a_reprendre");
      this.programmer(req, at, "backoff", "reprise_ots");
    }
    this.avancer(this.now);
    return this.actions;
  }

  /** Une demande refusée rend ses échéances, qui redeviennent ouvertes (EX-4.3, EX-8.4 règle 1). */
  rendreEcheances(req) {
    const p = this.periodeDe(req.subject.org_id, req.subject.journal_id, req.subject.period_start, false);
    if (!p) return;
    for (const k of req.deadlines) {
      const e = p.echeances.get(k);
      if (e && e.request === req.id && e.state === "ouverte") p.echeances.set(k, { state: "ouverte", request: null });
    }
  }

  /** Jeton promu (EX-5.8, EX-5.10 étape 9) : résultat, échéances, journal, remplacements (EX-4.4). */
  promouvoir(req, attempt, data, avertissements) {
    const borne = msGenTime(data.gen_time) + (data.accuracy_s ?? 0) * 1000;
    attempt.outcome = "obtenue";
    attempt.error_code = null;
    attempt.next_at = null;
    attempt.detail = `granted ; T-1 a T-9 reussies${avertissements.map((a) => ` ; avertissement ${a}`).join("")}`;
    req.result = { sha256: data.token_sha256, size: data.token_size, provider: attempt.provider, obtained_at: this.horodatage(this.now), bound: this.horodatage(borne) };
    this.annulerTimers(req.id);
    this.ecrire(req, "obtenue");
    const p = this.periodeDe(req.subject.org_id, req.subject.journal_id, req.subject.period_start);
    const i0 = this.interneDe(req.id);
    // Premier envoi de la demande : gardé en mémoire depuis la tentative de rang 1 ; pour une demande relue dont la
    // tentative de rang 1 est sortie de la fenêtre de 32 (EX-8.5, règle 7), la plus ancienne tentative de la ligne.
    const premiere = req.attempts.find((x) => x.n === 1) ?? req.attempts.reduce((m, x) => (m === null || x.n < m.n ? x : m), null);
    const premierEnvoi = i0.premierEnvoi ?? ms(premiere.started_at);
    const envoiPromu = ms(attempt.started_at);
    const alertes = avertissements.map((a) => ({ code: a === "reponse_tardive" ? "reponse_tardive_promue" : a, severity: "mineure" }));
    if (req.kind === "jeton_point") {
      for (const k of req.deadlines) {
        p.echeances.set(k, { state: "satisfaite", request: req.id });
        this.emettre("echeance", req.id, { k, state: "satisfaite" });
      }
      const i = this.interneDe(req.id);
      const origine = req.deadlines.length ? (p.period_start + Math.max(...req.deadlines) * this.config.rfc3161.checkpoints.interval_s) * 1000 : (p.period_start + 3600) * 1000;
      // Cinq instants tronqués à la seconde depuis D_k (depuis period_end pour le repli) : checkpoint_ts, admission,
      // premier envoi, envoi de la tentative promue, genTime + précision ; chaque composante est la différence avec
      // le précédent, leur somme est d_jeton_s (EX-3.5, 8.9 ; révision 0.6).
      const admission = i.admisA ?? this.tDemarrage ?? ms(req.created_at);
      const t0 = sEntieres(ms(req.subject.declared_at) - origine);
      const tA = sEntieres(admission - origine);
      const t1 = sEntieres(premierEnvoi - origine);
      const t2 = sEntieres(envoiPromu - origine);
      const t3 = sEntieres(borne - origine);
      const ligne = {
        event: "checkpoint_countersigned",
        tree_size: req.subject.tree_size,
        provider: attempt.provider,
        deadlines: req.deadlines,
        d_jeton_s: t3,
        d_point_s: t0,
        d_admission_s: tA - t0,
        d_attente_s: t1 - tA,
        d_releve_s: t2 - t1,
        d_tsa_s: t3 - t2,
      };
      if (avertissements.length) ligne.warnings = avertissements;
      if (i.repli) ligne.closing_fallback = true;
      this.emettre("journaliser", req.id, ligne);
      for (const a of alertes) this.emettre("alerter", req.id, a);
      // Alertes de 8.9 sur le jeton d'un point (AN-2) : `jeton_anterieur_au_point` quand
      // `genTime + précision < checkpoint_ts − clock_tolerance_s` (point antidaté ou horloge de
      // l'enregistreur en avance, majeure) ; `contresignature_tardive` quand
      // `genTime + précision − checkpoint_ts > c_T` (mineure ; trace point-manquant-saut-horloge).
      const tsPoint = ms(req.subject.declared_at);
      if (borne < tsPoint - this.config.rfc3161.freshness.clock_tolerance_s * 1000) this.emettre("alerter", req.id, { code: "jeton_anterieur_au_point", severity: "majeure" });
      if (borne - tsPoint > this.config.rfc3161.checkpoints.interval_s * 1000) this.emettre("alerter", req.id, { code: "contresignature_tardive", severity: "mineure" });
      if (req.deadlines.length) this.remplacerAnterieures(p, req, borne, Math.min(...req.deadlines));
      return;
    }
    // jeton_periode : la n_T-ième échéance.
    this.emettre("echeance", req.id, { k: this.nT, state: "satisfaite" });
    const ligne = { event: "period_timestamped", provider: attempt.provider, d_jeton_s: sEntieres(borne - (p.period_start + 3600) * 1000) };
    if (avertissements.length) ligne.warnings = avertissements;
    this.emettre("journaliser", req.id, ligne);
    for (const a of alertes) this.emettre("alerter", req.id, a);
    this.remplacerAnterieures(p, req, borne, Infinity);
    this.timers = this.timers.filter((t) => !(t.type === "repli_cloture" && t.id === req.id));
  }

  /** EX-4.4 : les demandes de points servant des échéances antérieures passent `remplacee`, les échéances ouvertes aussi. */
  remplacerAnterieures(p, parReq, borne, kLimite) {
    const roleExterieur = this.config.rfc3161.checkpoints.provider_role !== "interne";
    for (const d of this.demandesTriees()) {
      if (d.kind !== "jeton_point" || d.id === parReq.id || estFinale(d)) continue;
      if (d.subject.org_id !== p.org_id || d.subject.journal_id !== p.journal_id || d.subject.period_start !== p.period_start) continue;
      const i = this.interneDe(d.id);
      if (d.deadlines.length === 0) {
        if (parReq.kind !== "jeton_periode") continue;
        this.emettre("remplacer", d.id, { replaced_by: parReq.id });
        d.replaced_by = parReq.id;
        this.annulerTimers(d.id);
        this.ecrire(d, "remplacee");
        this.emettre("journaliser", d.id, { event: "anchor_replaced", replaced_by: parReq.id });
        continue;
      }
      if (Math.max(...d.deadlines) >= kLimite) continue;
      void i;
      this.emettre("remplacer", d.id, { replaced_by: parReq.id });
      d.replaced_by = parReq.id;
      this.annulerTimers(d.id);
      this.ecrire(d, "remplacee");
      for (const k of d.deadlines) {
        p.echeances.set(k, { state: "remplacee", request: d.id });
        this.emettre("echeance", d.id, { k, state: "remplacee" });
      }
      const dMin = (p.period_start + Math.min(...d.deadlines) * this.config.rfc3161.checkpoints.interval_s) * 1000;
      this.emettre("journaliser", d.id, { event: "checkpoint_anchor_late", tree_size: d.subject.tree_size, deadlines: d.deadlines, replaced_by: parReq.id, window_s: sEntieres(borne - dMin) });
      this.emettre("alerter", d.id, { code: "checkpoint_anchor_late", severity: roleExterieur ? "majeure" : "mineure" });
    }
    for (const [k, e] of [...p.echeances.entries()].sort((a, b) => a[0] - b[0])) {
      if (e.state === "ouverte" && e.request === null && k < kLimite) {
        p.echeances.set(k, { state: "remplacee", request: null });
        this.emettre("echeance", null, { k, state: "remplacee" });
      }
    }
  }

  // ----- OpenTimestamps (EX-8.11) -----

  soumettreOts(req) {
    if (estFinale(req)) return;
    const i = this.interneDe(req.id);
    if (!i.nonceOts) {
      if (!this.nonces) throw new ErreurPlanificateur("aucune source de nonces injectée (aleatoire ou nonces)");
      const n = this.nonces.ots({ kind: req.kind, hash: req.subject.hash, org_id: req.subject.org_id, journal_id: req.subject.journal_id, period_start: req.subject.period_start, subjectKind: req.subject.kind });
      if (!(n instanceof Uint8Array) || n.length !== 16) throw new ErreurPlanificateur("nonce OpenTimestamps : 16 octets attendus");
      i.nonceOts = octetsVersHex(n);
    }
    this.nouvelleTentative(req, { detail: "soumission envoyee" });
    req.due_at = null;
    this.ecrire(req, "envoyee");
    this.emettre("soumettre_ots", req.id, { digest: req.subject.hash, nonce: i.nonceOts, calendars: [...this.config.opentimestamps.calendars] });
  }

  lancerMiseANiveau(req) {
    if (req.state !== "en_attente") return;
    this.nouvelleTentative(req, { detail: "mise a niveau demandee" });
    this.ecrire(req, "en_attente");
    this.emettre("mettre_a_niveau_ots", req.id, { attempt: req.attempts_total });
  }

  reponseOts(data) {
    const req = this.demandes.get(data.request_id);
    if (!req || !req.kind.startsWith("ots_")) {
      this.emettre("journaliser", data.request_id, { event: "anchor_response_rejected", error_code: "demande_inconnue", attempt: null, provider: null, kept: false });
      return;
    }
    if (estFinale(req)) {
      this.journaliserTentative(req, { event: "anchor_response_rejected", error_code: "demande_close", attempt: totalTentatives(req), provider: null, kept: data.proof_sha256 !== null }, totalTentatives(req));
      return;
    }
    const i = this.interneDe(req.id);
    const o = this.config.opentimestamps;
    const attempt = this.derniereTentative(req);
    if (!attempt || attempt.outcome !== "en_cours") {
      this.journaliserTentative(req, { event: "anchor_response_rejected", error_code: "tentative_close", attempt: totalTentatives(req), provider: null, kept: data.proof_sha256 !== null }, totalTentatives(req));
      return;
    }
    const preuve = data.proof_sha256 !== null && data.proof_sha256 !== undefined;
    if (data.attestation === "complete" && preuve) {
      attempt.outcome = "obtenue";
      attempt.error_code = null;
      attempt.next_at = null;
      attempt.detail = req.state === "en_attente" ? "mise a niveau : attestation Bitcoin" : `${data.calendars_answered} calendriers ; attestation Bitcoin`;
      req.result = { sha256: data.proof_sha256, size: data.proof_size, provider: null, obtained_at: this.horodatage(this.now), bound: null };
      this.annulerTimers(req.id);
      this.emettre("stocker", req.id, { sha256: data.proof_sha256, size: data.proof_size, bound: null });
      this.ecrire(req, "complete");
      this.emettre("journaliser", req.id, { event: "ots_complete", reexport: true });
      return;
    }
    if (req.state === "envoyee") {
      // Réponse à la soumission (EX-6.2 (4)).
      if (data.attestation === "en_attente" && preuve && data.calendars_answered >= o.min_responses) {
        const at = this.now + o.upgrade.first_after_s * 1000;
        attempt.outcome = "obtenue";
        attempt.error_code = null;
        attempt.next_at = this.horodatage(at);
        attempt.detail = `${data.calendars_answered} calendriers ; attestation en attente`;
        req.result = { sha256: data.proof_sha256, size: data.proof_size, provider: null, obtained_at: this.horodatage(this.now), bound: null };
        req.due_at = attempt.next_at;
        i.soumisA = this.now;
        this.emettre("stocker", req.id, { sha256: data.proof_sha256, size: data.proof_size, bound: null });
        this.ecrire(req, "en_attente");
        this.programmer(req, at, "mise_a_niveau", "mise_a_niveau");
        return;
      }
      // Trop peu de calendriers : la soumission est rejouée avec le même engagement.
      attempt.outcome = "echec_transitoire";
      attempt.error_code = "calendriers_insuffisants";
      attempt.detail = `${data.calendars_answered} calendrier(s) ; au moins ${o.min_responses} attendus`;
      const r = this.config.rfc3161.retry;
      const k = req.attempts.filter((a) => a.outcome === "echec_transitoire").length + this.transitoiresHorsFenetre(req);
      const at = this.now + Math.min(r.max_ms, r.initial_ms * r.factor ** Math.max(0, k - 1)) + this.gigue();
      attempt.next_at = this.horodatage(at);
      req.due_at = attempt.next_at;
      this.emettre("rejeter_reponse", req.id, { error_code: "calendriers_insuffisants", class: "transitoire" });
      this.journaliserTentative(req, { event: "anchor_response_rejected", error_code: "calendriers_insuffisants", attempt: attempt.n, provider: null }, attempt);
      this.ecrire(req, "a_reprendre");
      this.programmer(req, at, "backoff", "reprise_ots");
      return;
    }
    // Mise à niveau sans attestation Bitcoin (404) : en_attente, nouvelle tentative interval_s plus tard (≥ 60 s).
    const depuis = this.now - (i.soumisA ?? ms(req.created_at));
    let intervalle = Math.max(60, o.upgrade.interval_s);
    if (depuis >= o.upgrade.give_up_after_s * 1000) {
      if (!i.giveUp) {
        i.giveUp = true;
        this.emettre("alerter", req.id, { code: "ots_give_up", severity: "majeure" });
      }
      intervalle = JOUR_S;
    }
    const at = this.now + intervalle * 1000;
    attempt.outcome = "echec_transitoire";
    attempt.error_code = "en_attente";
    attempt.detail = "mise a niveau : engagement en attente";
    attempt.next_at = this.horodatage(at);
    req.due_at = attempt.next_at;
    this.ecrire(req, "en_attente");
    this.programmer(req, at, "mise_a_niveau", "mise_a_niveau");
  }

  // ----- reconstruction (EX-8.12) -----

  stockageRelu(data) {
    let recreees = 0;
    let periodesTouchees = 0;
    let pointsTouches = 0;
    for (const per of data.periods) {
      const avant = this.demandes.size;
      this.periodeClose(per, { reconstruction: true });
      const n = this.demandes.size - avant;
      if (n > 0) {
        recreees += n;
        periodesTouchees += 1;
      }
    }
    const parPeriode = new Map();
    for (const c of data.checkpoints) {
      const k = cle(c.org_id, c.journal_id, c.period_start);
      const courant = parPeriode.get(k);
      if (!courant || ms(c.checkpoint_ts) > ms(courant.checkpoint_ts) || (ms(c.checkpoint_ts) === ms(courant.checkpoint_ts) && c.tree_size > courant.tree_size)) parPeriode.set(k, c);
    }
    for (const c of parPeriode.values()) {
      const p = this.periodeDe(c.org_id, c.journal_id, c.period_start);
      const close = p.close || data.periods.some((x) => x.org_id === c.org_id && x.journal_id === c.journal_id && x.period_start === c.period_start);
      if (close) continue;
      const aDemande = [...this.demandes.values()].some((d) => d.subject.hash === c.checkpoint_hash);
      if (aDemande) continue;
      const avant = this.demandes.size;
      this.pointProduit(c, { reconstruction: true });
      const n = this.demandes.size - avant;
      recreees += n;
      pointsTouches += 1;
    }
    this.emettre("journaliser", null, { event: "anchoring_queue_rebuilt", recreated: recreees, periods: periodesTouchees, checkpoints: pointsTouches });
    if (recreees > 0) this.emettre("alerter", null, { code: "file_perdue", severity: "critique" });
  }
}

/**
 * Crée un planificateur (EX-8.13) : `traiter(entree)` rend les actions dans
 * l'ordre où les règles les produisent, `file()` la file (rangée par
 * `created_at` puis `id`), `echeances(periodStart)` la table des échéances.
 * @param {object} projection `$defs/configuration`
 * @param {object} [options] voir `Planificateur`
 * @returns {Planificateur}
 */
export function creerPlanificateur(projection, options = {}) {
  return new Planificateur(projection, options);
}
