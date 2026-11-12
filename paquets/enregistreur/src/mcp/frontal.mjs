// Frontal MCP du démon `noortrace` (CT-2 §4) : serveur MCP pour l'hôte,
// client MCP pour chaque serveur d'outils. Il agrège `tools/list` (4.3),
// relaie `tools/call` dans l'ordre des pas 1 à 14 de 4.4 (EX-4.19), rend les
// erreurs de la table de 4.4 et les résultats d'EX-4.49, applique les quotas
// par connexion d'hôte (EX-4.47) et la matrice de panne de 14.2 pour ce qui
// le concerne. Il ne scelle rien lui-même : pièces, événements, intentions et
// vérifications d'approbation sont faits par le cœur (INTERFACES.md, a).
//
// Les transports (connecteur stdio, Streamable HTTP) remettent au frontal le
// texte reçu et une session ; le frontal rend le texte de la réponse.

import { randomBytes } from "node:crypto";
import { sha256Hex, utf8, ecrireHorodatage } from "@noortrace/noyau";
import { ErreurEnregistreur, ErreurConstruction } from "../erreurs.mjs";
import { pieceJson, pieceDefinitionOutil, pieceListeAnnoncee, pieceErreurJsonRpc } from "../pieces.mjs";
import { partielAppelOutil } from "../capture.mjs";
import { evaluerEffets } from "../effets.mjs";
import { macRelais } from "../approbations.mjs";
import { VERSION_ENREGISTREUR } from "../coeur.mjs";
import {
  analyserTexte, decoderUtf8Strict, membre, valeurDe, compacter, premierNombreNonRepresentable, typeJson, recomposerObjet, ErreurTexteJson,
} from "./json-texte.mjs";
import {
  CODES, IDENTITE_TEXTE, VERSION_MODERNE, VERSIONS_HERITEES, VERSIONS_SUPPORTEES, reponseErreur, reponseErreurTexte, reponseResultat,
  resultatEnregistreur, notification, erreurIssue, MESSAGES,
} from "./messages.mjs";
import { agreger, paginer, entetesParametres } from "./agregation.mjs";
import { ConnexionStdio, ConnexionHttp, ErreurConnexionAmont, valeurEnteteParametre } from "./amont.mjs";
import { QuotasHote } from "./quotas.mjs";
import { resoudreDelegation } from "./delegation.mjs";

const REFERENCES_SANS_KIND = (p) => p.referenceContexte("autre");

/** Lignes d'exploitation qu'un hôte déclenche sans requête (réponses, notifications) : au plus tant par seconde (lecture 159). */
export const LIGNES_HOTE_PAR_SECONDE = 20;
/** Enregistrements de continuation MRTR gardés au plus (EX-4.21 ; lecture 159). */
export const CONTINUATIONS_MAX = 10000;

/**
 * Clé d'un `id` JSON-RPC par sa valeur (un `requestId` d'annulation désigne
 * la requête de même valeur, quelle que soit son écriture : échappements
 * d'une chaîne, écriture d'un nombre).
 * @param {string} texte
 * @param {object} noeud noeud `chaine` ou `nombre`
 * @returns {string}
 */
export function cleIdJson(texte, noeud) {
  if (noeud.t === "chaine") return "s:" + noeud.valeur;
  const brut = texte.slice(noeud.d, noeud.f);
  return "n:" + (/^-?(0|[1-9][0-9]*)$/.test(brut) ? BigInt(brut).toString() : String(Number(brut)));
}

/** Session d'une connexion d'hôte (processus connecteur, identité HTTP, session héritée). */
export class SessionHote {
  /**
   * @param {{hote: object, identite: object, transport: "stdio"|"http", emettre?: (texte: string) => void, idSession?: string}} p
   */
  constructor(p) {
    this.hote = p.hote;
    this.identite = p.identite ?? {};
    this.transport = p.transport;
    this.emettre = p.emettre ?? (() => {});
    this.idSession = p.idSession ?? `s-${randomBytes(16).toString("hex")}`;
    this.ere = null;
    this.version = null;
    this.initialisee = false;
    /** Liste servie au dernier parcours complet (EX-4.45). */
    this.liste = null;
    this.instantanes = new Map();
    this.compteurInstantane = 0;
    /** Requêtes en cours : clé de l'id (`cleIdJson`) → contrôle. */
    this.enCours = new Map();
    /** Fenêtre des lignes d'exploitation déclenchées par l'hôte sans requête (lecture 159). */
    this.lignesHote = { debut: -Infinity, n: 0, comptees: 0 };
    this.ecouteListe = false;
    /** Flux `subscriptions/listen` ouvert par un hôte moderne (EX-4.15, lecture 173) : `{ id, emettre, filtre }`. */
    this.ecoute = null;
    this.fermee = false;
  }

  /** Identité portée par un jeton (EX-4.14 : `cacheScope: "private"`). */
  get parJeton() {
    return Boolean(this.identite.jeton || this.identite.oauth_subject);
  }
}

/** Erreur rendue à l'hôte : texte de la réponse déjà formé. */
class Rendu {
  constructor(texte) {
    this.texte = texte;
  }
}

export class FrontalMcp {
  /**
   * @param {object} o
   * @param {import("../coeur.mjs").Coeur} o.coeur
   * @param {object} [o.redacteur] `{ rediger(valeur, {portee, tool_announced}), detecte?(texte) }` (section e)
   * @param {object} [o.correlateur] `{ correler({...}) }` (5.6, frontal modèle)
   * @param {Function} [o.lanceur] lanceur des serveurs stdio (tests)
   * @param {{planifier: Function, annuler: Function}} [o.minuteur]
   * @param {Map<string, Uint8Array>} [o.secrets] secrets résolus par pointeur
   * @param {Object<string, number>} [o.compteursAmont] compteur initial des identifiants amont par alias (rejeu des vecteurs)
   */
  constructor(o) {
    this.coeur = o.coeur;
    this.redacteur = o.redacteur ?? null;
    this.correlateur = o.correlateur ?? null;
    this.lanceur = o.lanceur ?? null;
    this.minuteur = o.minuteur ?? {
      planifier: (ms, f) => {
        const t = setTimeout(f, ms);
        t.unref?.();
        return t;
      },
      annuler: (t) => clearTimeout(t),
    };
    this.secrets = o.secrets ?? this.coeur.secrets ?? new Map();
    this.connexions = new Map();
    /** Dernière liste reçue avec succès de chaque serveur (EX-4.18). */
    this.listes = new Map();
    this.injoignables = new Set();
    this.agregat = { annonces: [], rejets: [], parNom: new Map() };
    this.sessions = new Set();
    this.quotas = new Map();
    this.continuations = new Map();
    this.retentions = new Map();
    this.progressions = new Map();
    this.compteurProgression = 0;
    this.relectures = new Map();
    /** Appels relayés en vol (notifications du serveur, EX-4.27). */
    this.appelsEnVol = new Set();
    for (const [alias, serveur] of Object.entries(this.config.policy.servers ?? {})) {
      const Classe = serveur.transport.type === "stdio" ? ConnexionStdio : ConnexionHttp;
      const c = new Classe({ alias, serveur, frontal: this, lanceur: this.lanceur, compteurInitial: o.compteursAmont?.[alias] ?? 0 });
      c.on("notification", (n) => this._notificationAmont(c, n));
      this.connexions.set(alias, c);
    }
  }

  get config() {
    return this.coeur.config;
  }

  get journal() {
    return this.coeur.journal;
  }

  get metriques() {
    return this.coeur.metriques;
  }

  monotone() {
    return this.coeur.horlogeBrute.monotone();
  }

  murale() {
    return this.coeur.horlogeBrute.murale();
  }

  planifier(ms, f) {
    return this.minuteur.planifier(ms, f);
  }

  annulerMinuteur(t) {
    if (t !== undefined && t !== null) this.minuteur.annuler(t);
  }

  // ---------------------------------------------------------------- démarrage

  /**
   * Inscrit au journal d'exploitation la commande de chaque serveur stdio
   * (EX-3.4), branche la rétention et la santé dans le cœur, et lit la liste
   * de chaque serveur (4.3).
   */
  async demarrer() {
    for (const [alias, c] of this.connexions) {
      if (c instanceof ConnexionStdio) this.journal.consigner("info", "frontal_mcp", "stdio_server_command", { server: alias, command: c.commande() });
    }
    this.coeur.brancherRetention?.({
      retient: (ticket) => this.retentions.has(ticket),
      decidee: (ticket, evenement) => this._decisionRetenue(ticket, evenement),
    });
    this.coeur.brancherSante?.(() => [...this.injoignables].sort().map((a) => `serveur:${a}`));
    // La raison de santé `serveur:<alias>` est aussi une raison de la jauge du
    // mode dégradé (EX-14.11, alerte de §17.4 « mineure pour serveur:* ») :
    // série posée à 0 pour chaque serveur, 1 tant qu'il est injoignable.
    for (const alias of this.connexions.keys()) this.metriques.jauge("noortrace_degraded", { reason: `serveur:${alias}` }, this.injoignables.has(alias) ? 1 : 0);
    // Première lecture des listes : l'agrégat de départ n'est pas un changement
    // de définition (EX-4.16 compare ensuite à lui).
    this.demarrage = true;
    try {
      await Promise.all([...this.connexions.keys()].map((a) => this.rafraichir(a)));
    } finally {
      this.demarrage = false;
    }
  }

  /**
   * Arrêt (4.2, « Arrêt ») : les appels en vol sont attendus jusqu'à
   * `drain_timeout_ms`, puis les connexions amont fermées dans l'ordre de 4.2.
   */
  async arreter() {
    for (const r of this.retentions.values()) this.annulerMinuteur(r.minuteur);
    for (const t of this.relectures.values()) this.annulerMinuteur(t.minuteur);
    const limite = Date.now() + (this.config.mcp.drain_timeout_ms ?? 0);
    while (this.appelsEnVol.size && Date.now() < limite) await new Promise((r) => setTimeout(r, 20));
    if (this.appelsEnVol.size) this.journal.consigner("warning", "frontal_mcp", "drain_timeout", { calls: this.appelsEnVol.size });
    await Promise.all([...this.connexions.values()].map((c) => c.fermer().catch(() => {})));
  }

  /** Normalisations des connexions d'hôte configurées (EX-4.11 règle 3). */
  normalisations() {
    const vues = new Map();
    for (const h of this.config.mcp.hosts ?? []) {
      const n = { template: h.tool_name_template, sanitize: h.tool_name_sanitize };
      vues.set(JSON.stringify(n), n);
    }
    return [...vues.values()];
  }

  /**
   * Relit la liste d'un serveur (4.3) ; un serveur injoignable est omis
   * (EX-4.18) et sa dernière liste reçue avec succès reste celle de la
   * résolution.
   * @param {string} alias
   */
  async rafraichir(alias) {
    const c = this.connexions.get(alias);
    try {
      await c.assurer("{}");
      const l = await c.lister();
      this.chargerListe(alias, l.tools, { ttlMs: l.ttlMs, cacheScope: l.cacheScope, ere: c.ere });
      this.injoignables.delete(alias);
      this.metriques.jauge("noortrace_degraded", { reason: `serveur:${alias}` }, 0);
    } catch (e) {
      if (!this.injoignables.has(alias)) this.journal.consigner("warning", "frontal_mcp", "upstream_unreachable", { server: alias, reason: e?.raison ?? "erreur" });
      this.injoignables.add(alias);
      this.metriques.jauge("noortrace_degraded", { reason: `serveur:${alias}` }, 1);
      this.metriques.compter("noortrace_upstream_errors_total", { server: alias, kind: "injoignable" });
      this.recalculer();
    }
  }

  /**
   * Remplace la dernière liste reçue avec succès d'un serveur et recalcule
   * l'agrégat.
   * @param {string} alias
   * @param {object[]} tools objets Tool reçus
   * @param {{ttlMs?: number|null, cacheScope?: string|null, ere?: string|null}} [m]
   */
  chargerListe(alias, tools, m = {}) {
    this.listes.set(alias, { tools, ttlMs: m.ttlMs ?? null, cacheScope: m.cacheScope ?? null, ere: m.ere ?? "moderne" });
    this.recalculer();
  }

  /** Agrégat (EX-4.11), empreintes (EX-4.16), `charger` (EX-4.15, EX-7.15), `list_changed`. */
  recalculer() {
    const serveurs = [...this.listes.entries()].map(([alias, l]) => ({ alias, tools: l.tools }));
    const r = agreger({ serveurs, prefixe: this.config.tools.prefix, normalisations: this.normalisations(), configServeurs: this.config.policy.servers });
    const avant = this.agregat;
    for (const x of r.rejets) {
      const deja = avant.rejets.some((y) => y.server_alias === x.server_alias && y.original === x.original && y.reason === x.reason);
      if (!deja) {
        this.journal.consigner("warning", "frontal_mcp", "tool_rejected", { server: x.server_alias, tool_original: x.original, reason: x.reason });
        this.metriques.compter("noortrace_tools_rejected_total", { server: x.server_alias, reason: x.reason });
      }
    }
    const parNom = new Map(r.annonces.map((a) => [a.announced, a]));
    const noms = new Set([...avant.parNom.keys(), ...parNom.keys()]);
    for (const nom of noms) {
      const a = avant.parNom.get(nom)?.definition_sha256 ?? null;
      const b = parNom.get(nom)?.definition_sha256 ?? null;
      if (a !== b && avant.annonces.length && !this.demarrage) {
        const serveur = (parNom.get(nom) ?? avant.parNom.get(nom)).server_alias;
        this.journal.consigner("warning", "frontal_mcp", "tool_definition_changed", { server: serveur, tool_announced: nom, old_sha256: a, new_sha256: b });
        this.metriques.compter("noortrace_tool_definition_changes_total", { server: serveur });
      }
    }
    const change = avant.annonces.length !== r.annonces.length || r.annonces.some((x) => avant.parNom.get(x.announced)?.definition_sha256 !== x.definition_sha256);
    this.agregat = { annonces: r.annonces, rejets: r.rejets, parNom };
    const parServeur = new Map();
    for (const x of r.annonces) parServeur.set(x.server_alias, (parServeur.get(x.server_alias) ?? 0) + 1);
    for (const alias of this.connexions.keys()) this.metriques.jauge("noortrace_tools_announced", { server: alias }, parServeur.get(alias) ?? 0);
    if (change) {
      this.coeur.definirOutils(
        r.annonces.map((x) => ({ tool_announced: x.announced, tool_original: x.original, server_alias: x.server_alias, class: x.class, effects: this.config.policy.servers?.[x.server_alias]?.tools?.[x.original]?.effects ?? null })),
      );
      if (avant.annonces.length) this._notifierListeChangee();
    }
  }

  _notifierListeChangee() {
    for (const s of this.sessions) {
      if (s.fermee) continue;
      // Hôte moderne : sur son flux subscriptions/listen, marqué de l'id de la souscription (lecture 173).
      if (s.ecoute?.filtre.toolsListChanged) s.ecoute.emettre(notification("notifications/tools/list_changed", `{"_meta":{"io.modelcontextprotocol/subscriptionId":${s.ecoute.id}}}`));
      else if (s.ere === "heritee" || s.ecouteListe) s.emettre(notification("notifications/tools/list_changed", null));
    }
  }

  /**
   * `subscriptions/listen` d'un hôte moderne (EX-4.15 ; lecture 173) : le
   * premier message du flux est `notifications/subscriptions/acknowledged`,
   * qui porte les types de notification que le frontal honore (seul
   * `toolsListChanged` : le frontal ne relaie ni ressources ni prompts,
   * EX-4.25) et l'id de la requête ; le flux reste ouvert jusqu'à
   * l'annulation par l'hôte (`notifications/cancelled`, fermeture du flux
   * HTTP) ou la fin de la session. Des paramètres sans `notifications`
   * rendent -32602, jamais le silence.
   */
  _ecouter(session, m) {
    const filtre = membre(m.params, "notifications");
    if (!filtre || filtre.t !== "objet") throw new Rendu(reponseErreur(m.idBrut, -32602, { reason: "notifications_requis" }));
    const demande = valeurDe(filtre);
    const honore = demande.toolsListChanged === true ? { toolsListChanged: true } : {};
    const emettre = m.canal?.notifier ?? session.emettre;
    const ecoute = { id: m.idBrut, emettre, filtre: honore };
    session.ecoute = ecoute;
    this.journal.consigner("info", "frontal_mcp", "host_subscription_opened", { tools_list_changed: honore.toolsListChanged === true }, { host: session.hote.id, request_id: m.idBrut });
    emettre(notification("notifications/subscriptions/acknowledged", `{"notifications":${JSON.stringify(honore)},"_meta":{"io.modelcontextprotocol/subscriptionId":${m.idBrut}}}`));
    return new Promise((resoudre) => {
      const fin = () => {
        if (session.ecoute === ecoute) session.ecoute = null;
        if (session.enCours.get(m.cleId) === controle) session.enCours.delete(m.cleId);
        resoudre(null);
      };
      const controle = { annuler: fin };
      if (!session.enCours.has(m.cleId)) session.enCours.set(m.cleId, controle);
      m.canal?.annulation?.then?.(fin);
      ecoute.fin = fin;
    });
  }

  /** `notifications/tools/list_changed` d'un serveur : relecture fusionnée (EX-4.15). */
  _listeChangee(alias) {
    const min = this.config.tools.list_changed_min_interval_ms;
    const r = this.relectures.get(alias) ?? { derniere: -Infinity, minuteur: null, fusionnees: 0 };
    this.relectures.set(alias, r);
    if (r.minuteur !== null) {
      r.fusionnees++;
      return;
    }
    const t = this.monotone();
    const attente = Math.max(0, r.derniere + min - t);
    r.minuteur = this.planifier(attente, async () => {
      r.minuteur = null;
      r.derniere = this.monotone();
      if (r.fusionnees) this.journal.consigner("info", "frontal_mcp", "list_changed_merged", { server: alias, count: r.fusionnees });
      r.fusionnees = 0;
      await this.rafraichir(alias);
    });
  }

  _notificationAmont(c, n) {
    if (n.methode === "notifications/tools/list_changed") return this._listeChangee(c.alias);
    if (n.methode === "notifications/progress") {
      const jeton = n.objet?.params?.progressToken;
      const p = typeof jeton === "string" ? this.progressions.get(jeton) : null;
      if (!p) return;
      const params = membre(n.noeud, "params");
      const texte = recomposerObjet(n.texte, params, { remplacer: new Map([["progressToken", p.jetonBrut]]) });
      p.emettre(notification("notifications/progress", texte));
      p.compte.n++;
      return;
    }
    if (n.methode === "notifications/message") {
      // Relayée telle quelle à l'hôte de l'appel concerné (EX-4.27), quand il
      // n'y en a qu'un en vol vers ce serveur ; sinon consignée seulement.
      const appels = [...this.appelsEnVol.values()].filter((a) => a.alias === c.alias);
      if (appels.length === 1) {
        (appels[0].m.canal?.notifier ?? appels[0].session.emettre)(compacter(n.texte, n.noeud));
        appels[0].compteNotifications.n++;
      } else {
        this.journal.consigner("info", "frontal_mcp", "server_message_not_relayed", { server: c.alias });
      }
    }
  }

  // ---------------------------------------------------------------- sessions

  /**
   * Ouvre une session d'hôte.
   * @param {{hote: object, identite?: object, transport: "stdio"|"http", emettre?: Function}} p
   * @returns {SessionHote}
   */
  ouvrirSession(p) {
    const s = new SessionHote(p);
    this.sessions.add(s);
    if (!this.quotas.has(p.hote.id)) this.quotas.set(p.hote.id, new QuotasHote(p.hote.quota));
    return s;
  }

  fermerSession(s) {
    s.fermee = true;
    this.sessions.delete(s);
    s.ecoute?.fin?.();
    // Ses continuations MRTR ne peuvent plus servir (EX-4.21 : même connexion d'hôte).
    for (const [k, c] of this.continuations) if (c.session === s) this.continuations.delete(k);
  }

  /** Quotas d'une connexion d'hôte (EX-4.47). */
  quotasHote(hote) {
    let q = this.quotas.get(hote.id);
    if (!q) {
      q = new QuotasHote(hote.quota);
      this.quotas.set(hote.id, q);
    }
    return q;
  }

  /**
   * Octets reçus d'une connexion d'hôte, comptés par son transport dès leur
   * lecture, avant toute analyse (4.4 pas 1 : « les octets reçus sont comptés
   * même pour une requête refusée » ; EX-4.47).
   * @param {object} hote entrée de `mcp.hosts`
   * @param {number} octets
   */
  compterRecus(hote, octets) {
    this.quotasHote(hote).recevoir(this.monotone(), octets);
  }

  /** Temps d'analyse consommé par un transport pour une connexion d'hôte (EX-4.47). */
  compterCapture(hote, ms) {
    this.quotasHote(hote).tempsCapture(this.monotone(), ms);
  }

  /**
   * Contrôle du quota avant l'analyse (4.4 pas 1, EX-4.47) : octets reçus ou
   * temps de capture atteints → texte de la réponse -31013, `id: null` (la
   * requête n'est pas analysée, son `id` n'est pas connu ; lecture 160),
   * consigné ; null sinon. En mode observation (EX-14.16), rien n'est refusé ici : le
   * contrôle qui suit l'analyse consigne le blocage évité.
   * @param {object} hote
   * @returns {string|null}
   */
  refusAvantAnalyse(hote) {
    if (this.coeur.politique?.observation) return null;
    const q = this.quotasHote(hote).depasseAvantAnalyse(this.monotone());
    if (!q) return null;
    this.journal.consigner("warning", "frontal_mcp", "call_blocked", { code: CODES.TAILLE, reason: "quota", ...q }, { host: hote.id });
    this._compterBlocage(CODES.TAILLE, "quota", null);
    return reponseErreur(null, CODES.TAILLE, q);
  }

  /**
   * Ligne d'exploitation qu'un hôte déclenche sans requête (réponse ignorée,
   * notification) : au plus LIGNES_HOTE_PAR_SECONDE par connexion, les autres
   * comptées et consignées en une ligne (lecture 159).
   */
  _consignerParHote(session, niveau, evenement, data) {
    const f = session.lignesHote;
    const t = this.monotone();
    if (t - f.debut >= 1000) {
      if (f.comptees) this.journal.consigner("info", "frontal_mcp", "host_lines_dropped", { lines: f.comptees }, { host: session.hote.id });
      f.debut = t;
      f.n = 0;
      f.comptees = 0;
    }
    if (f.n >= LIGNES_HOTE_PAR_SECONDE) {
      f.comptees++;
      return;
    }
    f.n++;
    this.journal.consigner(niveau, "frontal_mcp", evenement, data, { host: session.hote.id });
  }

  /** Entrée de connexion d'hôte d'une identité (EX-7.3) ; null : refusée. */
  hotePour(match) {
    for (const h of this.config.mcp.hosts ?? []) {
      if (match.peer_user !== undefined && h.match.peer_user === match.peer_user) return h;
      if (match.static_token !== undefined && h.match.static_token === match.static_token) return h;
      if (match.oauth_subject !== undefined && h.match.oauth_subject === match.oauth_subject) return h;
    }
    return null;
  }

  // ---------------------------------------------------------------- réception (4.4 pas 1)

  /**
   * Traite un message reçu d'un hôte et rend le texte de la réponse (ou null
   * pour une notification).
   * @param {SessionHote} session
   * @param {Uint8Array|string} entree octets reçus (ligne sans LF, ou corps POST)
   * @param {{cadre?: "ligne"|"corps", canal?: {notifier?: Function, annulation?: Promise<number>}}} [o]
   * @returns {Promise<string|null>}
   */
  async recevoir(session, entree, o = {}) {
    const octets = typeof entree === "string" ? utf8(entree) : entree;
    const quotas = this.quotasHote(session.hote);
    // 4.4 pas 1 : octets comptés (par le transport, `compte`, ou ici), puis
    // quota d'octets et de temps de capture contrôlé avant toute analyse.
    if (!o.compte) quotas.recevoir(this.monotone(), octets.length);
    const avant = this.refusAvantAnalyse(session.hote);
    if (avant !== null) return avant;
    const t_recu = this.monotone();
    if (o.cadre !== "corps" && octets.includes(13)) return reponseErreur(null, -32700, { reason: "cr_dans_la_ligne" });
    const lim = this.config.limits;
    if (octets.length > lim.request_max_bytes) {
      this.journal.consigner("warning", "frontal_mcp", "request_too_large", { length: octets.length }, { host: session.hote.id });
      this._compterBlocage(CODES.TAILLE, "requete", null);
      return reponseErreur(null, CODES.TAILLE, { limit_bytes: lim.request_max_bytes, direction: "requete" });
    }
    let texte;
    let noeud;
    try {
      texte = decoderUtf8Strict(octets);
      noeud = analyserTexte(texte, { profondeurMax: lim.json_max_depth, membresMax: lim.json_max_members });
    } catch (e) {
      if (!(e instanceof ErreurTexteJson)) throw e;
      // EX-4.47 : le temps d'analyse d'une requête refusée est compté.
      quotas.tempsCapture(t_recu, this.monotone() - t_recu);
      if (e.raison === "non_canonisable") return reponseErreur(null, -32602, { reason: "arguments_non_canonisables" });
      return reponseErreur(null, -32700, { reason: e.raison === "syntaxe" ? "json_invalide" : e.raison });
    }
    const dureeAnalyse = this.monotone() - t_recu;
    // Compté pour les requêtes suivantes, après le contrôle de quota de celle-ci
    // quand elle y arrive, et même si elle est refusée avant (EX-4.47).
    let analyseComptee = false;
    const compterAnalyse = () => {
      if (!analyseComptee) quotas.tempsCapture(t_recu, dureeAnalyse);
      analyseComptee = true;
    };
    try {
      return await this._recevoirAnalysee(session, o, { texte, noeud, t_recu, dureeAnalyse, quotas, compterAnalyse });
    } finally {
      compterAnalyse();
    }
  }

  async _recevoirAnalysee(session, o, { texte, noeud, t_recu, dureeAnalyse, quotas, compterAnalyse }) {
    if (noeud.t === "tableau") return reponseErreur(null, -32600, { reason: "lot_non_pris_en_charge" });
    if (noeud.t !== "objet") return reponseErreur(null, -32600);
    const id = membre(noeud, "id");
    const idValide = id && (id.t === "chaine" || id.t === "nombre");
    const idBrut = idValide ? texte.slice(id.d, id.f) : null;
    const methode = membre(noeud, "method");
    const jsonrpc = membre(noeud, "jsonrpc");
    if (jsonrpc?.t !== "chaine" || jsonrpc.valeur !== "2.0") return reponseErreur(idBrut, -32600);
    if (!methode) {
      // Réponse de l'hôte (aucune requête serveur→client n'est relayée) : ignorée.
      this._consignerParHote(session, "info", "host_response_ignored", {});
      return null;
    }
    if (methode.t !== "chaine" || (id && !idValide)) return reponseErreur(idBrut, -32600);
    const params = membre(noeud, "params");
    if (params && params.t !== "objet") return reponseErreur(idBrut, -32602);
    const m = { texte, noeud, idBrut, cleId: idValide ? cleIdJson(texte, id) : null, methode: methode.valeur, params, t_recu, dureeAnalyse, cadre: o.cadre ?? "ligne", canal: o.canal ?? {} };
    if (!idBrut) {
      this._notificationHote(session, m);
      return null;
    }
    const appel = m.methode === "tools/call";
    const q = quotas.depasse(t_recu, { appel });
    if (q && this.coeur.politique?.observation) {
      // Mode observation (EX-14.16) : un quota d'hôte ne bloque pas ; consigné et compté.
      this.coeur.politique.consignerBlocageEvite({ would: "quota", raison: "quota", host: session.hote.id, request_id: idBrut });
    } else if (q) {
      this.journal.consigner("warning", "frontal_mcp", "call_blocked", { code: CODES.TAILLE, reason: "quota", ...q }, { host: session.hote.id, request_id: idBrut });
      this._compterBlocage(CODES.TAILLE, "quota", null);
      return reponseErreur(idBrut, CODES.TAILLE, q);
    }
    compterAnalyse();
    try {
      return await this._requete(session, m);
    } catch (e) {
      if (e instanceof Rendu) return e.texte;
      throw e;
    }
  }

  _notificationHote(session, m) {
    if (m.methode === "notifications/initialized") {
      if (session.ere === "heritee") session.initialisee = true;
      return;
    }
    if (m.methode === "notifications/cancelled") {
      const rid = membre(m.params, "requestId");
      if (!rid || (rid.t !== "chaine" && rid.t !== "nombre")) return;
      session.enCours.get(cleIdJson(m.texte, rid))?.annuler();
      return;
    }
    this._consignerParHote(session, "debug", "host_notification", { method: m.methode });
  }

  /**
   * Ère d'une requête (EX-4.4, EX-4.5) : session héritée initialisée, ou
   * `_meta` moderne complet. Rend `true` pour une requête moderne.
   */
  _ere(session, m) {
    if (session.ere === "heritee") {
      if (!session.initialisee && m.methode !== "ping" && m.methode !== "initialize") throw new Rendu(reponseErreur(m.idBrut, -32600, { reason: "non_initialise" }));
      return false;
    }
    const meta = membre(m.params, "_meta");
    const v = membre(meta, "io.modelcontextprotocol/protocolVersion");
    const caps = membre(meta, "io.modelcontextprotocol/clientCapabilities");
    if (!v || v.t !== "chaine" || !caps || caps.t !== "objet") {
      // Statut HTTP de ce refus (EX-4.37) : indiqué au transport, jamais lu dans le texte.
      m.canal.statutHttp = 400;
      throw new Rendu(reponseErreur(m.idBrut, -32602, { reason: "meta_requis" }));
    }
    if (v.valeur !== VERSION_MODERNE) {
      throw new Rendu(reponseErreur(m.idBrut, -32022, { supported: [...VERSIONS_SUPPORTEES], requested: v.valeur }));
    }
    session.ere = session.ere ?? "moderne";
    return true;
  }

  async _requete(session, m) {
    if (m.methode === "initialize" && session.ere !== "moderne") return this._initialiser(session, m);
    const moderne = this._ere(session, m);
    switch (m.methode) {
      case "ping":
        if (moderne) break;
        return reponseResultat(m.idBrut, "{}");
      case "server/discover":
        return reponseResultat(
          m.idBrut,
          `{"resultType":"complete","supportedVersions":${JSON.stringify(VERSIONS_SUPPORTEES)},"capabilities":${this._capacites()},"serverInfo":${IDENTITE_TEXTE},"_meta":{"io.modelcontextprotocol/serverInfo":${IDENTITE_TEXTE}}}`,
        );
      case "subscriptions/listen":
        if (!moderne) break;
        return this._ecouter(session, m);
      case "tools/list":
        return this._listerOutils(session, m, moderne);
      case "tools/call":
        return this._appel(session, m, moderne);
      default:
        break;
    }
    if (/^(resources|prompts|completion)\//.test(m.methode) || m.methode === "logging/setLevel") {
      this.journal.consigner("info", "frontal_mcp", "relay_out_of_chain_refused", { method: m.methode }, { host: session.hote.id, request_id: m.idBrut });
    }
    // Méthode inconnue du frontal : 404 en HTTP (EX-4.35), indiqué au transport.
    m.canal.statutHttp = 404;
    return reponseErreur(m.idBrut, -32601);
  }

  _capacites() {
    return `{"tools":{"listChanged":true}}`;
  }

  /** `initialize` d'un hôte hérité (EX-4.5). */
  _initialiser(session, m) {
    const v = membre(m.params, "protocolVersion");
    const demandee = v?.t === "chaine" ? v.valeur : null;
    const version = VERSIONS_HERITEES.includes(demandee) ? demandee : VERSIONS_HERITEES[0];
    session.ere = "heritee";
    session.version = version;
    session.initialisee = false;
    const caps = membre(m.params, "capabilities");
    session.capacitesHeritees = caps?.t === "objet" ? caps : null;
    session.texteCapacites = caps?.t === "objet" ? m.texte : null;
    return reponseResultat(m.idBrut, `{"protocolVersion":${JSON.stringify(version)},"capabilities":${this._capacites()},"serverInfo":${IDENTITE_TEXTE}}`);
  }

  // ---------------------------------------------------------------- tools/list (EX-4.13, EX-4.14, EX-4.45)

  /** Liste servie à une session : sans les serveurs injoignables, sans les rejets HTTP. */
  _annoncesServies(session) {
    return this.agregat.annonces.filter((a) => !this.injoignables.has(a.server_alias) && (session.transport !== "http" || a.http_admis));
  }

  _listerOutils(session, m, moderne) {
    const c = membre(m.params, "cursor");
    let n;
    let debut;
    let instantane;
    if (!c) {
      n = ++session.compteurInstantane;
      instantane = this._annoncesServies(session);
      session.instantanes.set(n, instantane);
      if (session.instantanes.size > 8) session.instantanes.delete(session.instantanes.keys().next().value);
      debut = 0;
    } else {
      const r = c.t === "chaine" ? /^c-([0-9]{1,9})-([0-9]{1,9})$/.exec(c.valeur) : null;
      instantane = r ? session.instantanes.get(Number(r[1])) : null;
      if (!instantane || Number(r[2]) % this.config.tools.page_size !== 0 || Number(r[2]) >= Math.max(instantane.length, 1)) {
        return reponseErreur(m.idBrut, -32602, { reason: "curseur_invalide" });
      }
      n = Number(r[1]);
      debut = Number(r[2]);
    }
    const taille = this.config.tools.page_size;
    const page = instantane.slice(debut, debut + taille);
    const suite = debut + taille < instantane.length ? `c-${n}-${debut + taille}` : null;
    if (suite === null) session.liste = { annonces: instantane, parNom: new Map(instantane.map((a) => [a.announced, a])) };
    const outils = "[" + page.map((a) => JSON.stringify(a.definition)).join(",") + "]";
    const curseur = suite === null ? "" : `,"nextCursor":${JSON.stringify(suite)}`;
    if (!moderne) return reponseResultat(m.idBrut, `{"tools":${outils}${curseur}}`);
    // EX-4.14 : plus petit ttlMs des serveurs modernes de la page ; le
    // défaut si un serveur hérité (ou sans ttlMs) y figure, ou page vide.
    const listes = [...new Set(page.map((a) => a.server_alias))].map((a) => this.listes.get(a));
    const defaut = this.config.tools.default_ttl_ms;
    const ttl = listes.length === 0 || listes.some((l) => l.ere !== "moderne" || l.ttlMs === null) ? defaut : Math.min(...listes.map((l) => l.ttlMs));
    const prive = session.parJeton || listes.some((l) => l.cacheScope === "private");
    return reponseResultat(
      m.idBrut,
      `{"resultType":"complete","tools":${outils}${curseur},"ttlMs":${ttl},"cacheScope":${JSON.stringify(prive ? "private" : "public")},"_meta":{"io.modelcontextprotocol/serverInfo":${IDENTITE_TEXTE}}}`,
    );
  }

  // ---------------------------------------------------------------- tools/call (4.4)

  _compterBlocage(code, raison, classe) {
    this.metriques.compter("noortrace_calls_blocked_total", { code: String(code), reason: raison ?? "", class: classe ?? "" });
  }

  /** -31010 (14.2) : rendu, consigné (`call_blocked`, EX-14.7) et compté. */
  _bloque(ctx, raison) {
    this.journal.consigner(
      "warning",
      "frontal_mcp",
      "call_blocked",
      { code: CODES.BLOQUE, reason: raison, server: ctx.alias ?? null, tool_announced: ctx.nom ?? null, class: ctx.classe ?? null },
      { host: ctx.session.hote.id, request_id: ctx.m.idBrut },
    );
    this._compterBlocage(CODES.BLOQUE, raison, ctx.classe);
    return new Rendu(reponseErreur(ctx.m.idBrut, CODES.BLOQUE, { reason: raison }));
  }

  /**
   * Rédacteur (section e) : celui passé au frontal, à défaut le crochet
   * `redaction` du cœur s'il rédige les pièces (`redigerArguments`,
   * `redigerResultat`). Sans rédacteur, les pièces sont écrites telles
   * quelles, et le fait est consigné une fois.
   */
  _redacteur() {
    const r = this.redacteur ?? this.coeur.o?.redaction ?? null;
    return typeof r?.redigerArguments === "function" ? r : null;
  }

  /**
   * Pièce rédigée d'une valeur (4.4 pas 4 et 12) : `{ piece, valeurRedigee, nonRedigeable }`
   * (`nonRedigeable` : raison d'EX-8.7 règle 3, ou null).
   */
  async _redigerPiece(valeur, portee, ctx) {
    const r = this._redacteur();
    if (!r) {
      if (!this.sansRedacteur) {
        this.sansRedacteur = true;
        this.journal.consigner("warning", "redaction", "redaction_absente", {});
      }
      return { piece: pieceJson(valeur), valeurRedigee: valeur, nonRedigeable: null };
    }
    const o = { outil: ctx.nom, alias: ctx.alias, id: ctx.m.idBrut, host: ctx.session.hote.id };
    const x = portee === "arguments" ? await r.redigerArguments(valeur, o) : await r.redigerResultat(valeur, o);
    const nonRedigeable = x.non_redigeable ?? null;
    return { piece: x.piece, valeurRedigee: nonRedigeable ? null : x.valeur ?? null, nonRedigeable };
  }

  /** `run_id` déclaré admis par les détecteurs de la politique (EX-7.2). */
  async _runIdAdmis(v) {
    const r = this.redacteur ?? this.coeur.o?.redaction ?? null;
    if (typeof r?.admettreRunId === "function") return (await r.admettreRunId(v)) === true;
    return true;
  }

  async _ecrirePieces(ctx, pieces) {
    for (const p of pieces) {
      await this.coeur.ecrirePiece(p);
      this.quotas.get(ctx.session.hote.id).piece(this.monotone(), p.octets.length);
      this.metriques.compter("noortrace_pieces_bytes_total", { scope: p === ctx.pieceArguments ? "arguments" : p === ctx.pieceResultat ? "resultat" : "contexte" }, p.octets.length);
    }
  }

  /** Délai d'un outil (EX-4.22). */
  delaiOutil(alias, original) {
    const s = this.config.policy.servers?.[alias];
    return (original !== null ? s?.tools?.[original]?.timeout_ms : null) ?? s?.timeout_ms ?? this.config.tools.default_timeout_ms;
  }

  /** Comportement en mode dégradé d'un outil (EX-14.2). */
  _comportement(alias, original, classe) {
    const f = this.config.policy.servers?.[alias]?.tools?.[original]?.failure;
    if (f) return f;
    return classe === "ecriture" ? "bloquant" : this.config.policy.failure?.lecture ?? "passant";
  }

  /** Environnement d'un serveur stdio : `env` de la configuration, secrets résolus (EX-4.40). */
  environnementServeur(alias) {
    const t = this.config.policy.servers[alias].transport;
    const env = { PATH: process.env.PATH ?? "/usr/bin:/bin" };
    for (const [k, v] of Object.entries(t.env ?? {})) {
      if (typeof v === "string") env[k] = v;
      else {
        const s = this.secrets.get(`/policy/servers/${alias}/transport/env/${k}`);
        if (s) env[k] = Buffer.from(s).toString("utf8");
      }
    }
    return env;
  }

  /** En-têtes statiques d'un serveur HTTP, secrets résolus (EX-4.40, EX-4.41). */
  entetesServeur(alias) {
    const t = this.config.policy.servers[alias].transport;
    const h = {};
    for (const [k, v] of Object.entries(t.headers ?? {})) {
      if (typeof v === "string") h[k] = v;
      else {
        const s = this.secrets.get(`/policy/servers/${alias}/transport/headers/${k.replace(/~/g, "~0").replace(/\//g, "~1")}`);
        if (s) h[k] = Buffer.from(s).toString("utf8");
      }
    }
    return h;
  }

  /** Capacités déclarées au serveur (EX-4.7, EX-4.28) : intersection avec ce qui est relayable. */
  _capacitesAmont(alias, texte, caps) {
    if (!caps || caps.t !== "objet") return "{}";
    const g = this.config.relay.server_requests;
    const s = this.config.policy.servers?.[alias]?.relay ?? g;
    const admis = { sampling: s.sampling, elicitation: s.elicitation, roots: s.roots };
    const membres = caps.membres.filter((x) => admis[x.cle] === true).map((x) => texte.slice(x.kd, x.kf) + ":" + compacter(texte, x.v));
    return "{" + membres.join(",") + "}";
  }

  /**
   * `_meta` relayé au serveur (4.4 pas 9, EX-4.7) : clés
   * `io.modelcontextprotocol/*` réécrites, `progressToken` remplacé par un
   * jeton propre, autres clés relayées telles quelles.
   */
  _metaAmont(ctx, connexion, capsTexte) {
    const meta = membre(ctx.m.params, "_meta");
    const t = ctx.m.texte;
    const remplacer = new Map([
      ["io.modelcontextprotocol/protocolVersion", JSON.stringify(connexion.version)],
      ["io.modelcontextprotocol/clientCapabilities", capsTexte],
      ["io.modelcontextprotocol/clientInfo", IDENTITE_TEXTE],
    ]);
    const pt = membre(meta, "progressToken");
    if (pt && (pt.t === "chaine" || pt.t === "nombre")) {
      const jeton = `p-${String(++this.compteurProgression).padStart(12, "0")}`;
      ctx.progression = jeton;
      this.progressions.set(jeton, { emettre: ctx.m.canal?.notifier ?? ctx.session.emettre, jetonBrut: t.slice(pt.d, pt.f), alias: ctx.alias, compte: ctx.compteNotifications });
      remplacer.set("progressToken", JSON.stringify(jeton));
    }
    const presentes = new Set(meta?.t === "objet" ? meta.membres.map((x) => x.cle) : []);
    const fin = [];
    for (const k of ["io.modelcontextprotocol/protocolVersion", "io.modelcontextprotocol/clientCapabilities", "io.modelcontextprotocol/clientInfo"]) {
      if (!presentes.has(k)) fin.push([k, remplacer.get(k)]);
    }
    if (meta?.t === "objet") return recomposerObjet(t, meta, { remplacer, ajouterEnFin: fin });
    return "{" + fin.map(([k, v]) => JSON.stringify(k) + ":" + v).join(",") + "}";
  }

  /** Message amont du pas 9. */
  _messageAmont(ctx, connexion, idAmont) {
    const t = ctx.m.texte;
    const p = ctx.m.params;
    const parties = [`"name":${JSON.stringify(ctx.original)}`];
    if (ctx.argumentsNoeud) parties.push(`"arguments":${compacter(t, ctx.argumentsNoeud)}`);
    for (const k of ["inputResponses", "requestState"]) {
      const x = membre(p, k);
      if (x) parties.push(`${JSON.stringify(k)}:${compacter(t, x)}`);
    }
    for (const x of p.membres) {
      if (["name", "arguments", "inputResponses", "requestState", "_meta"].includes(x.cle)) continue;
      parties.push(t.slice(x.kd, x.kf) + ":" + compacter(t, x.v));
    }
    parties.push(`"_meta":${this._metaAmont(ctx, connexion, ctx.capsAmont)}`);
    return `{"jsonrpc":"2.0","id":${JSON.stringify(idAmont)},"method":"tools/call","params":{${parties.join(",")}}}`;
  }

  /** En-têtes `Mcp-Param-*` construits d'après la définition courante (EX-4.35). */
  _parametresEntetes(ctx) {
    const r = {};
    for (const { propriete, entete } of entetesParametres(ctx.annonce.definition)) {
      if (ctx.argumentsClair && typeof ctx.argumentsClair === "object" && propriete in ctx.argumentsClair) {
        const v = valeurEnteteParametre(ctx.argumentsClair[propriete]);
        if (v !== null && typeof entete === "string") r[entete] = v;
      }
    }
    return r;
  }

  /**
   * `tools/call` : pas 1 (fin) à 14 de 4.4.
   * @param {SessionHote} session
   * @param {object} m
   * @param {boolean} moderne
   */
  async _appel(session, m, moderne) {
    const ctx = { session, m, moderne, compteNotifications: { n: 0 } };
    const quotas = this.quotas.get(session.hote.id);
    quotas.enCours++;
    let annule = false;
    const controle = {
      annuler: () => {
        annule = true;
        ctx.annulerAmont?.();
      },
    };
    // Un id déjà en cours garde son contrôle (« MUST NOT » réutiliser un id en cours, R1).
    const proprietaire = !session.enCours.has(m.cleId);
    if (proprietaire) session.enCours.set(m.cleId, controle);
    // HTTP moderne : la fermeture du flux de réponse vaut annulation (EX-4.23,
    // EX-4.36), dès sa survenue, avant comme pendant le relais.
    m.canal?.annulation?.then?.(() => controle.annuler());
    try {
      return await this._appelPas(ctx, () => annule);
    } catch (e) {
      if (e instanceof Rendu) return e.texte;
      throw e;
    } finally {
      quotas.enCours--;
      if (proprietaire && session.enCours.get(m.cleId) === controle) session.enCours.delete(m.cleId);
      if (ctx.progression) this.progressions.delete(ctx.progression);
    }
  }

  async _appelPas(ctx, estAnnule) {
    const { session, m } = ctx;
    const t = m.texte;
    // Pas 1 (fin) : nom, arguments exactement représentables (EX-4.44).
    const nomNoeud = membre(m.params, "name");
    if (!nomNoeud || nomNoeud.t !== "chaine") throw new Rendu(reponseErreur(m.idBrut, -32602));
    const nom = nomNoeud.valeur;
    ctx.nom = nom;
    const argsNoeud = membre(m.params, "arguments");
    if (argsNoeud && argsNoeud.t !== "objet") throw new Rendu(reponseErreur(m.idBrut, -32602, { reason: "arguments_non_objet" }));
    if (argsNoeud && premierNombreNonRepresentable(t, argsNoeud) !== null) throw new Rendu(reponseErreur(m.idBrut, -32602, { reason: "nombre_non_representable" }));
    ctx.argumentsNoeud = argsNoeud ?? null;
    ctx.argumentsClair = argsNoeud ? valeurDe(argsNoeud) : {};

    // Pas 2 : résolution sur la dernière liste reçue avec succès (EX-4.18).
    const annonce = this.agregat.parNom.get(nom);
    if (!annonce || (session.transport === "http" && !annonce.http_admis)) {
      const k = nom.indexOf("__");
      const alias = this.config.tools.prefix && k > 0 ? nom.slice(0, k) : null;
      if (alias && this.connexions.has(alias) && !this.listes.has(alias)) throw new Rendu(reponseErreur(m.idBrut, CODES.INJOIGNABLE, { server: alias }));
      throw new Rendu(reponseErreurTexte(m.idBrut, `{"code":-32602,"message":${JSON.stringify(`Unknown tool: ${nom}`)}}`));
    }
    ctx.annonce = annonce;
    ctx.alias = annonce.server_alias;
    ctx.original = annonce.original;
    ctx.classe = annonce.class;
    const connexion = this.connexions.get(ctx.alias);
    ctx.connexion = connexion;
    const meta = membre(m.params, "_meta");
    const capsHote = ctx.moderne ? membre(meta, "io.modelcontextprotocol/clientCapabilities") : session.capacitesHeritees;
    const texteCaps = ctx.moderne ? t : session.texteCapacites;
    ctx.capsAmont = this._capacitesAmont(ctx.alias, texteCaps, capsHote);

    // Pièces de contexte (EX-4.45, EX-7.7).
    const servie = session.liste?.parNom.get(nom) ?? null;
    let listeServie = session.liste?.annonces ?? null;
    if (!servie) {
      this.journal.consigner("info", "frontal_mcp", "definition_non_servie", { server: ctx.alias, tool_announced: nom }, { host: session.hote.id, request_id: m.idBrut });
      listeServie = this._annoncesServies(session);
    }
    const contexte = [];
    if (this.config.tools.definition_in_context) {
      contexte.push(pieceDefinitionOutil((servie ?? annonce).definition));
      if (servie && servie.definition_sha256 !== annonce.definition_sha256) contexte.push(pieceDefinitionOutil(annonce.definition));
    }
    if (this.config.tools.list_in_context) contexte.push(pieceListeAnnoncee(listeServie.map((a) => a.definition)));
    ctx.piecesContexte = contexte;

    // Délégation (7.2, EX-7.2) et corrélation (5.6).
    const declaree = valeurDe(meta ?? { t: "objet", membres: [] })["noortrace/delegation"];
    const runDeclare = declaree && typeof declaree === "object" && typeof declaree.run_id === "string" ? declaree.run_id : null;
    const runRefuse = runDeclare !== null && session.hote.accept_declared_delegation === true && !(await this._runIdAdmis(runDeclare));
    const delegation = resoudreDelegation({
      hote: session.hote,
      identite: session.identite,
      declaree,
      sessionHeritee: session.ere === "heritee" ? session.idSession : null,
      detecte: () => runRefuse,
      refus: (champ, raison, longueur) =>
        this.journal.consigner("warning", "frontal_mcp", "delegation_refused", { component: "frontal_mcp", field: champ, reason: raison, length: longueur }, { host: session.hote.id, request_id: m.idBrut }),
    });
    if (delegation.launched_by === null) throw this._bloque(ctx, "approbation");
    if (declaree !== undefined && session.hote.accept_declared_delegation) {
      this.journal.consigner("info", "frontal_mcp", "delegation_declared", { fields: Object.keys(declaree ?? {}).filter((k) => k === "run_id" || k === "on_behalf_of") }, { host: session.hote.id, request_id: m.idBrut });
    }
    ctx.delegation = delegation;
    const hoteCapture = { id: session.hote.id, launched_by: delegation.launched_by, on_behalf_of: session.hote.on_behalf_of ?? null, scope: session.hote.scope };

    // Continuation MRTR (EX-4.21) : héritage sans nouvel appel au service.
    // Enregistrement gardé par ce processus, à défaut reconstruit par le cœur
    // depuis la ligne `continuation` d'un appel approuvé (reprise, bascule) :
    // celui-ci n'a plus de connexion d'hôte, et RL-2 compare la délégation de
    // la ré-émission à celle de la `retenue`.
    const rs = membre(m.params, "requestState");
    let herite = null;
    if (rs) {
      const shaRs = sha256Hex(utf8(compacter(t, rs)));
      ctx.shaRequestState = shaRs;
      const c = this.continuations.get(shaRs) ?? this._continuationReconstruite(shaRs);
      const mac = macRelais(this.coeur.cleMac, ctx.argumentsClair);
      if (c && !c.servie && (c.session === session || c.session === null) && c.tool === nom && c.mac === mac) {
        c.servie = true;
        herite = c;
        // Servie une fois : retirée (une ré-émission rejouée repasse par le pas 3).
        this.continuations.delete(shaRs);
      }
      this.journal.consigner("info", "frontal_mcp", "mrtr_reemission", { request_state_sha256: shaRs, inherited: herite !== null }, { host: session.hote.id, request_id: m.idBrut });
    }

    let correlation = null;
    if (!herite && this.correlateur) {
      correlation = (await this.correlateur.correler({ host: session.hote, host_group: session.hote.host_group, run_id: delegation.run_id, tool_announced: nom, arguments: ctx.argumentsClair, t_recu: m.t_recu })) ?? null;
      this.journal.consigner("info", "frontal_mcp", "correlation", { seq: correlation?.seq ?? "aucun" }, { host: session.hote.id, request_id: m.idBrut });
    }
    const intent = herite ? herite.intent : correlation?.intent ?? null;
    const code = herite ? herite.code : { model: correlation?.code?.model ?? null, prompt_version: correlation?.code?.prompt_version ?? null };

    // Pas 3 : politique (EX-7.4) par le moteur de politique (INTERFACES.md,
    // section d) : matrice de 14.2 pour le service, mode observation (EX-4.51).
    let reponse;
    const moteur = this.coeur.politique;
    ctx.blocagesEvites = [];
    if (herite) {
      // Une continuation d'un appel approuvé est relayée sous le ticket : RL-1
      // à RL-4, RL-3 en mode continuation, au pas 7 (EX-4.21 condition 4, EX-7.21).
      reponse = herite.policy.ticket === null
        ? { rule: herite.policy.rule, decision: herite.policy.decision, ticket: null, ticket_state: null, approval: null, approver_set: null }
        : { rule: herite.policy.rule, decision: "autorise", ticket: herite.policy.ticket, ticket_state: "approuve", approval: herite.approval, approver_set: null };
    } else {
      try {
        const issue = await moteur.evaluerAppel({
          tool_announced: nom,
          tool_original: ctx.original,
          server_alias: ctx.alias,
          arguments: ctx.argumentsClair,
          class: ctx.classe,
          delegation,
          intent,  // chaîne, référence ou null : le moteur forme le membre d'EX-7.4
          code: { model: code.model, prompt_version: code.prompt_version, policy_version: this.coeur.versionPolitique, recorder: VERSION_ENREGISTREUR },
          context: contexte.map(REFERENCES_SANS_KIND),
        }, { nom, classe: ctx.classe, alias: ctx.alias, host: session.hote.id, request_id: m.idBrut });
        reponse = issue.reponse;
        ctx.observation = issue.observation;
        if (issue.observation?.bloquerait) ctx.blocagesEvites.push(issue.observation.bloquerait);
      } catch (e) {
        if (!(e instanceof ErreurEnregistreur)) throw e;
        throw this._bloque(ctx, e.raison ?? "approbation");
      }
    }
    ctx.reponse = reponse;
    const classeEffective = moteur.classeEffective(reponse, ctx.classe);
    ctx.classeEffective = classeEffective;
    const relaieOuRetient = reponse.decision === "autorise" || reponse.ticket_state === "nouveau";
    const susceptible = ctx.classe === "ecriture" || this.coeur.susceptible(nom);

    // Pas 7 (anticipé) : le stockage décide entre écriture des pièces et attente (14.5).
    const panne = this._etatPanne(ctx.alias, ctx.original, classeEffective);
    let passantObservation = false;
    // `bail_non_detenu` et `journal_clos` (EX-19.4) bloquent aussi en mode observation.
    if (panne.bloque && ctx.observation && panne.bloque !== "bail_non_detenu" && panne.bloque !== "journal_clos") {
      // Mode observation (EX-14.16) : relayé, événement mis en attente.
      ctx.blocagesEvites.push(panne.bloque);
      passantObservation = true;
    } else if (panne.bloque && (relaieOuRetient || reponse.decision === "refuse" || reponse.ticket_state === "en_attente")) {
      if (reponse.ticket_state !== "en_attente") throw this._bloque(ctx, panne.bloque);
    }
    let passant = passantObservation || (panne.passant === true && reponse.decision === "autorise" && reponse.ticket_state === null);

    // Pas 4 : pièce « arguments » rédigée (EX-10.23 pour la borne de temps).
    const t0 = this.monotone();
    const pa = await this._redigerPiece(ctx.argumentsClair, "arguments", ctx);
    this.quotas.get(session.hote.id).tempsCapture(this.monotone(), this.monotone() - t0);
    // EX-10.23 opération 1 : arguments non rédigeables d'une écriture ou d'un outil susceptible.
    if (pa.nonRedigeable === "budget_redaction" && susceptible && relaieOuRetient) {
      // Mode observation (EX-14.16) : la pièce non rédigeable est relayée comme pour une lecture.
      if (!ctx.observation) throw this._bloque(ctx, "redaction");
      ctx.blocagesEvites.push("redaction");
    }
    ctx.pieceArguments = pa.piece;
    ctx.argumentsRediges = pa.valeurRedigee;
    ctx.sourceNonRedigeable = pa.nonRedigeable !== null;
    // Pièces du pas 4 ; une ré-émission en attente n'en écrit pas, sauf celle
    // que le mode `retenir` retient (EX-4.50) : sa retenue peut finir en relais
    // ou en événement `refusee`, qui les citent.
    const retenueEnAttente = reponse.ticket_state === "en_attente" && moteur.mode === "retenir" && !this.retentions.has(reponse.ticket);
    if (!passant && (reponse.ticket_state !== "en_attente" || retenueEnAttente)) {
      try {
        await this._ecrirePieces(ctx, [pa.piece, ...contexte]);
      } catch (e) {
        if (!(e instanceof ErreurEnregistreur)) throw e;
        if (ctx.observation) {
          // Mode observation (EX-14.16) : pièces gardées avec l'événement en attente.
          ctx.blocagesEvites.push(e.raison);
        } else {
          // Panne constatée par cette écriture (14.2, colonne L ; EX-14.8) : une
          // lecture passante sans ticket est relayée, ses pièces gardées en mémoire
          // avec l'événement en attente ; sinon bloquée par la panne constatée.
          const apres = this._etatPanne(ctx.alias, ctx.original, classeEffective);
          if (!(apres.passant === true && reponse.decision === "autorise" && reponse.ticket_state === null)) throw this._bloque(ctx, apres.bloque ?? e.raison);
        }
        passant = true;
      }
    }
    const capture = {
      host: hoteCapture,
      delegation,
      tool_announced: nom,
      tool_original: ctx.original,
      server_alias: ctx.alias,
      class: ctx.classe,
      arguments: pa.piece.reference,
      context: contexte.map(REFERENCES_SANS_KIND),
      intent,
      code,
    };
    ctx.capture = capture;
    // Une annulation par l'hôte arrête l'appel avant tout relais ; un refus est
    // tout de même scellé (4.4 pas 5 : « Chaque tentative refusée est un
    // événement », EX-14.3), sans réponse rendue.
    if (estAnnule() && reponse.decision !== "refuse") return null;

    // Pas 5 : refus.
    if (reponse.decision === "refuse") {
      try {
        await this.coeur.scellerRefus(capture, reponse);
      } catch (e) {
        if (e instanceof ErreurEnregistreur || e instanceof ErreurConstruction) throw this._bloque(ctx, e.raison ?? "stockage");
        throw e;
      }
      if (estAnnule()) return null;
      if (reponse.ticket_state === null) return reponseResultat(m.idBrut, resultatEnregistreur({ moderne: ctx.moderne }));
      return this._signal(ctx, reponse.ticket, reponse.ticket_state);
    }

    // Pas 6 : ticket nouveau ou en attente (jamais en mode observation : aucun ticket).
    const mode = moteur.mode;
    if (reponse.ticket_state === "nouveau") {
      try {
        await this.coeur.scellerRetenue(capture, reponse, ctx.argumentsClair);
      } catch (e) {
        if (e instanceof ErreurEnregistreur || e instanceof ErreurConstruction) throw this._bloque(ctx, e.raison ?? "stockage");
        throw e;
      }
      if (mode === "retenir" && !this.retentions.has(reponse.ticket)) return this._retenir(ctx, reponse.ticket);
      return this._signal(ctx, reponse.ticket, "en_attente");
    }
    if (reponse.ticket_state === "en_attente") {
      this.journal.consigner("info", "politique", "approval_pending", { server: ctx.alias, tool_announced: nom }, { host: session.hote.id, request_id: m.idBrut });
      if (mode === "retenir" && !this.retentions.has(reponse.ticket)) return this._retenir(ctx, reponse.ticket);
      return this._signal(ctx, reponse.ticket, "en_attente");
    }
    if (reponse.decision !== "autorise") throw this._bloque(ctx, "approbation");

    // Pas 7 à 14 : relais.
    if (herite) ctx.herite = herite;
    return this._relayer(ctx, { passant, estAnnule });
  }

  /**
   * Enregistrement de continuation reconstruit par le cœur (EX-4.21 : reprise
   * ou bascule), sans connexion d'hôte ; null sinon.
   * @param {string} sha
   */
  _continuationReconstruite(sha) {
    const r = this.coeur.continuationReconstruite?.(sha) ?? null;
    if (!r) return null;
    const e = r.evenement;
    return {
      session: null,
      tool: e.execution.tool,
      mac: r.mac,
      policy: e.policy,
      approval: e.approval,
      intent: e.intent,
      code: { model: e.code.model, prompt_version: e.code.prompt_version },
      servie: false,
    };
  }

  /** Panne au pas 7 (14.2) : `{ bloque: raison }`, `{ passant: true }` ou `{}`. */
  _etatPanne(alias, original, classeEffective) {
    const c = this.coeur;
    if (!c.bailDetenu) return { bloque: "bail_non_detenu" };
    // Journal terminé par la clôture anticipée (EX-19.4) : -31010 journal_clos.
    if (c.journalClos) return { bloque: "journal_clos" };
    const r = c.degrade.raisons();
    for (const x of ["cle", "bail", "horloge"]) if (r.includes(x)) return { bloque: x };
    if (r.includes("stockage") || c.intervention) {
      if (classeEffective === "ecriture" || this._comportement(alias, original, classeEffective) === "bloquant") return { bloque: "stockage" };
      // Bornes d'EX-14.9, contrôlées avant le relais : au-delà, la lecture passante devient bloquante.
      if (r.includes("attente") || c.attenteBornee()) return { bloque: "attente" };
      return { passant: true };
    }
    if (r.includes("attente") && classeEffective !== "ecriture") return { bloque: "attente" };
    return {};
  }

  /** Signal d'approbation (EX-4.49). */
  _signal(ctx, ticket, state) {
    this.metriques.compter("noortrace_approval_signals_total", { state });
    return reponseResultat(ctx.m.idBrut, resultatEnregistreur({ moderne: ctx.moderne, approbation: { ticket, state } }));
  }

  // ---------------------------------------------------------------- mode retenir (EX-4.50)

  _retenir(ctx, ticket) {
    return new Promise((resoudre) => {
      const r = { ctx, ticket, resoudre, minuteur: null };
      r.minuteur = this.planifier(this.config.policy.approval.hold_timeout_ms, () => {
        if (this.retentions.get(ticket) !== r) return;
        this.retentions.delete(ticket);
        resoudre(this._signal(ctx, ticket, "en_attente"));
      });
      // Annulation par l'hôte (EX-4.23) : la requête retenue prend fin, sans
      // réponse ; la première ré-émission reconnue qui suit pourra être retenue.
      ctx.annulerAmont = () => {
        if (this.retentions.get(ticket) !== r) return;
        this.retentions.delete(ticket);
        this.annulerMinuteur(r.minuteur);
        this.journal.consigner("info", "politique", "approval_hold_cancelled", {}, { host: ctx.session.hote.id, request_id: ctx.m.idBrut });
        resoudre(null);
      };
      this.retentions.set(ticket, r);
      this.journal.consigner("info", "politique", "approval_held", { hold_timeout_ms: this.config.policy.approval.hold_timeout_ms }, { host: ctx.session.hote.id, request_id: ctx.m.idBrut });
    });
  }

  async _decisionRetenue(ticket, evenement) {
    const r = this.retentions.get(ticket);
    if (!r) return;
    this.retentions.delete(ticket);
    this.annulerMinuteur(r.minuteur);
    r.ctx.annulerAmont = null;
    const d = evenement.approval.decision;
    try {
      if (d === "approuve") {
        r.ctx.reponse = { rule: null, decision: "autorise", ticket, ticket_state: "approuve", approval: evenement.approval, approver_set: null };
        r.ctx.classeEffective = "ecriture";
        r.resoudre(await this._relayer(r.ctx, { passant: false, estAnnule: () => false }));
        return;
      }
      await this.coeur.scellerRefus(r.ctx.capture, { rule: null, decision: "refuse", ticket, ticket_state: d, approval: evenement.approval, approver_set: null });
      r.resoudre(this._signal(r.ctx, ticket, d));
    } catch (e) {
      if (e instanceof Rendu) return r.resoudre(e.texte);
      if (e instanceof ErreurEnregistreur) return r.resoudre(reponseErreur(r.ctx.m.idBrut, CODES.BLOQUE, { reason: e.raison }));
      r.resoudre(reponseErreur(r.ctx.m.idBrut, CODES.BLOQUE, { reason: "approbation" }));
    }
  }

  // ---------------------------------------------------------------- relais (pas 7 à 14)

  async _relayer(ctx, o) {
    const { session, m } = ctx;
    const connexion = ctx.connexion;
    const timeout_ms = this.delaiOutil(ctx.alias, ctx.original);
    ctx.timeout_ms = timeout_ms;
    // Pas 7 : connexion établie avant l'intention (sinon -31014 sans événement).
    try {
      await connexion.assurer(ctx.capsAmont);
    } catch (e) {
      if (!(e instanceof ErreurConnexionAmont)) throw e;
      this.journal.consigner("warning", "frontal_mcp", "upstream_unreachable", { server: ctx.alias, reason: e.raison }, { host: session.hote.id, request_id: m.idBrut });
      this.metriques.compter("noortrace_upstream_errors_total", { server: ctx.alias, kind: "injoignable" });
      throw new Rendu(reponseErreur(m.idBrut, CODES.INJOIGNABLE, { server: ctx.alias }));
    }
    if (ctx.moderne === false && connexion.ere === null) throw new Rendu(reponseErreur(m.idBrut, CODES.INJOIGNABLE, { server: ctx.alias }));
    const idAmont = connexion.prochainId();
    // Pas 7 et 8 : RL-1 à RL-4 et intention durable (cœur).
    let relais = null;
    if (!o.passant) {
      const sousTicket = ctx.herite && ctx.herite.policy.ticket !== null;
      // Continuation sous ticket : aucune réponse d'evaluer à comparer (RL-1).
      const reponse = !ctx.herite
        ? ctx.reponse
        : sousTicket
          ? { ...ctx.reponse, approval: null }
          : { rule: ctx.herite.policy.rule, decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null };
      try {
        relais = await this.coeur.preparerRelais(ctx.capture, {
          reponse, argumentsEnClair: ctx.argumentsClair, upstream_id: idAmont, timeout_ms, continuation: sousTicket ? ctx.shaRequestState : null,
        });
      } catch (e) {
        if (!(e instanceof ErreurEnregistreur || e instanceof ErreurConstruction)) throw e;
        if (!ctx.observation) throw this._bloque(ctx, e.raison ?? "stockage");
        // Mode observation (EX-4.51, EX-14.16) : une précondition du pas 7 qui échoue rend l'appel passant.
        ctx.blocagesEvites.push(e.raison ?? "stockage");
        o.passant = true;
        relais = null;
      }
      // Sous ticket, `policy` et `approval` sont ceux que le cœur a vérifiés (RL-1, EX-7.12).
      if (relais && ctx.herite && !sousTicket) relais.fixe = { policy: ctx.herite.policy, approval: ctx.herite.approval };
    }
    // Pas 9 : envoi.
    const texteAmont = this._messageAmont(ctx, connexion, idAmont);
    const attente = connexion.attendre(idAmont);
    this.appelsEnVol.add(ctx);
    if (connexion instanceof ConnexionHttp) connexion.envoyerAppel(idAmont, texteAmont, { nom: ctx.original, parametres: this._parametresEntetes(ctx) });
    else connexion.envoyerRequete(texteAmont, { id: idAmont });
    const t_envoi = this.monotone();
    // Pas 10 et 11 : notifications en vol, réponse, délai, annulation.
    let minuteur;
    let annulationHote = null;
    const issue = await Promise.race([
      attente,
      new Promise((res) => {
        minuteur = this.planifier(timeout_ms, () => res({ issue: "delai" }));
      }),
      new Promise((res) => {
        ctx.annulerAmont = () => res({ issue: "annulation" });
        if (o.estAnnule()) res({ issue: "annulation" });
        ctx.m.canal?.annulation?.then?.(() => res({ issue: "annulation" }));
      }),
    ]);
    this.annulerMinuteur(minuteur);
    this.appelsEnVol.delete(ctx);
    ctx.annulerAmont = null;
    let t_reponse;
    let resultat;
    let objetErreurHote = null;
    let texteResultatHote = null;
    let is_error = true;
    let resultatRedige = null;
    let sourceNonRedigeable = ctx.sourceNonRedigeable;
    switch (issue.issue) {
      case "delai": {
        t_reponse = t_envoi + timeout_ms;
        connexion.annuler(idAmont, MESSAGES[CODES.DELAI]);
        this.journal.consigner("warning", "frontal_mcp", "upstream_timeout", { server: ctx.alias, timeout_ms }, { host: session.hote.id, request_id: m.idBrut });
        this.metriques.compter("noortrace_upstream_errors_total", { server: ctx.alias, kind: "delai" });
        const err = erreurIssue(CODES.DELAI, { timeout_ms });
        resultat = pieceErreurJsonRpc(err);
        objetErreurHote = JSON.stringify(err);
        break;
      }
      case "annulation": {
        connexion.annuler(idAmont, MESSAGES[CODES.ANNULE]);
        t_reponse = this.monotone();
        annulationHote = true;
        const err = erreurIssue(CODES.ANNULE);
        resultat = pieceErreurJsonRpc(err);
        objetErreurHote = JSON.stringify(err);
        break;
      }
      case "perte": {
        t_reponse = issue.t;
        this.journal.consigner("warning", "frontal_mcp", "upstream_unreachable", { server: ctx.alias, reason: "perte" }, { host: session.hote.id, request_id: m.idBrut });
        this.metriques.compter("noortrace_upstream_errors_total", { server: ctx.alias, kind: "injoignable" });
        const err = erreurIssue(CODES.INJOIGNABLE, { server: ctx.alias });
        resultat = pieceErreurJsonRpc(err);
        objetErreurHote = JSON.stringify(err);
        break;
      }
      case "taille": {
        t_reponse = issue.t;
        connexion.terminerAppel(idAmont);
        const err = erreurIssue(CODES.TAILLE, { limit_bytes: issue.limite, direction: "reponse" });
        resultat = pieceErreurJsonRpc(err);
        objetErreurHote = JSON.stringify(err);
        break;
      }
      default: {
        t_reponse = issue.t;
        connexion.terminerAppel(idAmont);
        const r = await this._resultatRecu(ctx, issue);
        resultat = r.piece;
        resultatRedige = r.valeurRedigee;
        is_error = r.is_error;
        objetErreurHote = r.erreurHote;
        texteResultatHote = r.resultatHote;
        sourceNonRedigeable = sourceNonRedigeable || r.nonRedigeable !== null;
      }
    }
    const duration_ms = Math.max(0, Math.floor(t_reponse - t_envoi));
    ctx.pieceResultat = resultat;
    this.metriques.observer("noortrace_upstream_latency_ms", { server: ctx.alias }, duration_ms);
    // Pas 12 et 13 : pièce « résultat » et événement durable.
    let evenement = null;
    if (o.passant) {
      this._mettreEnAttente(ctx, { resultat, resultatRedige, duration_ms, is_error, sourceNonRedigeable });
    } else {
      try {
        evenement = await this.coeur.terminerRelais(relais, { resultat, resultatRedige, argumentsRediges: ctx.argumentsRediges, duration_ms, is_error, sourceNonRedigeable });
      } catch (e) {
        if (!(e instanceof ErreurEnregistreur)) throw e;
        if (ctx.observation) {
          // Mode observation (EX-14.16) : la réponse reçue est rendue, jamais -31017 ;
          // l'événement est en attente (14.5), ou perdu au-delà des bornes.
          if (e.code !== CODES.NON_DURABLE) this.coeur.politique.consignerPerte(e.raison ?? "attente", 1, { host: session.hote.id, request_id: m.idBrut });
          ctx.blocagesEvites.push(e.raison ?? "stockage");
          evenement = null;
        } else {
          this.journal.consigner("error", "frontal_mcp", "call_blocked", { code: CODES.NON_DURABLE, reason: e.raison }, { host: session.hote.id, request_id: m.idBrut });
          this._compterBlocage(CODES.NON_DURABLE, e.raison, ctx.classe);
          return reponseErreur(m.idBrut, CODES.NON_DURABLE, { intent_id: relais?.intention?.intent_id ?? null, reason: e.raison });
        }
      }
      // Continuation MRTR (EX-4.21) : enregistrement gardé avant le pas 14 ;
      // pour un appel qui porte l'approbation d'un ticket, ligne `continuation`
      // écrite et synchronisée d'abord (EX-12.23), faute de quoi aucun
      // enregistrement n'est gardé et la ré-émission repasse par le pas 3.
      const rsNoeud = issue.issue === "reponse" && evenement ? membre(membre(issue.noeud, "result"), "requestState") : null;
      const ticket = evenement?.policy?.ticket ?? null;
      if (rsNoeud && (ticket === null || (evenement.approval?.ticket === ticket && evenement.approval.decision === "approuve"))) {
        const sha = sha256Hex(utf8(compacter(issue.texte, rsNoeud)));
        let garde = true;
        if (ticket !== null) {
          try {
            await this.coeur.inscrireContinuation(evenement, sha);
          } catch (e) {
            if (!(e instanceof ErreurEnregistreur)) throw e;
            garde = false;
            this.journal.consigner("error", "frontal_mcp", "mrtr_continuation_unrecorded", { request_state_sha256: sha, reason: e.raison ?? null }, { seq: evenement.seq, host: session.hote.id });
          }
        }
        if (garde) {
          if (this.continuations.size >= CONTINUATIONS_MAX) this.continuations.delete(this.continuations.keys().next().value);
          this.continuations.delete(sha);
          this.continuations.set(sha, {
            session,
            tool: ctx.nom,
            mac: macRelais(this.coeur.cleMac, ctx.argumentsClair),
            policy: ticket === null ? { rule: evenement.policy.rule, decision: evenement.policy.decision, ticket: null } : evenement.policy,
            approval: evenement.approval,
            intent: evenement.intent,
            code: { model: evenement.code.model, prompt_version: evenement.code.prompt_version },
            servie: false,
          });
          this.journal.consigner("info", "frontal_mcp", "mrtr_continuation", { request_state_sha256: sha }, { seq: evenement.seq, host: session.hote.id });
        }
      }
    }
    this.journal.consigner(
      "info",
      "frontal_mcp",
      "tool_call_relayed",
      {
        server: ctx.alias,
        tool_original: ctx.original,
        tool_announced: ctx.nom,
        upstream_id: idAmont,
        intent_id: relais?.intention?.intent_id ?? null,
        arguments_sha256: ctx.pieceArguments.sha256,
        result_sha256: resultat.sha256,
        duration_ms,
        is_error,
        notifications: ctx.compteNotifications.n,
        ticket: evenement?.policy?.ticket ?? null,
        pending: o.passant === true,
      },
      { seq: evenement?.seq ?? null, host: session.hote.id, request_id: m.idBrut },
    );
    const ajoute = Math.max(0, this.monotone() - m.t_recu - duration_ms);
    this.metriques.observer("noortrace_relay_latency_ms", { path: "mcp", class: ctx.classe }, ajoute);
    // Mode observation (EX-14.14, EX-17.8) : marque comptée ; chaque blocage
    // qu'un mode bloquant aurait opposé est consigné, avec le seq de
    // l'événement (null s'il est en attente).
    if (ctx.observation) {
      const moteur = this.coeur.politique;
      moteur.compterMarque(ctx.observation.would);
      for (const raison of [...new Set(ctx.blocagesEvites ?? [])]) {
        moteur.consignerBlocageEvite({ would: ctx.observation.would, raison, alias: ctx.alias, nom: ctx.nom, classe: ctx.classe, seq: evenement?.seq ?? null, host: session.hote.id, request_id: m.idBrut });
      }
    }
    // Pas 14 : réponse à l'hôte.
    if (annulationHote) return null;
    if (objetErreurHote !== null) return reponseErreurTexte(m.idBrut, objetErreurHote);
    return reponseResultat(m.idBrut, texteResultatHote);
  }

  /** Lecture passante en mode dégradé « stockage » (EX-14.8) : événement en attente. */
  _mettreEnAttente(ctx, r) {
    const a = ctx.capture;
    const { effets } = evaluerEffets({
      gabarit: this.config.policy.servers?.[ctx.alias]?.tools?.[ctx.original]?.effects ?? null,
      classe: ctx.classe,
      alias: ctx.alias,
      nomOrigine: ctx.original,
      arguments: ctx.argumentsRediges,
      resultat: r.resultatRedige,
      sourceNonRedigeable: r.sourceNonRedigeable,
      executerExtract: this.coeur.o?.redaction?.executerExtract,
    });
    const partiel = partielAppelOutil({
      delegation: a.delegation,
      code: { model: a.code.model, prompt_version: a.code.prompt_version, policy_version: this.coeur.versionPolitique, recorder: VERSION_ENREGISTREUR },
      intent: a.intent,
      tool: a.tool_announced,
      arguments: a.arguments,
      context: a.context,
      nomRedaction: this.coeur.nomRedaction,
      policy: { rule: ctx.reponse.rule ?? null, decision: "autorise", ticket: null },
      approval: null,
      status: "executee",
      result: r.resultat.reference,
      duration_ms: r.duration_ms,
      is_error: r.is_error,
      effects: effets,
    });
    try {
      const captured_at = this.coeur.politique?.instantCapture() ?? this.murale();
      const id = this.coeur.mettreEnAttente(partiel, [ctx.pieceArguments, ...ctx.piecesContexte, r.resultat], { captured_at, host: ctx.session.hote.id, genre: "appel" });
      this.journal.consigner("warning", "frontal_mcp", "call_passthrough_pending", { pending_id: id, server: ctx.alias }, { host: ctx.session.hote.id, request_id: ctx.m.idBrut });
    } catch (e) {
      if (!(e instanceof ErreurEnregistreur)) throw e;
      if (ctx.observation) this.coeur.politique.consignerPerte(e.raison ?? "attente", 1, { host: ctx.session.hote.id, request_id: ctx.m.idBrut });
      else this.journal.consigner("error", "frontal_mcp", "event_lost", { reason: e.raison }, { host: ctx.session.hote.id, request_id: ctx.m.idBrut });
    }
  }

  /**
   * Pas 12 et 14 pour une réponse reçue : pièce « résultat » (rédigée), et
   * texte rendu à l'hôte (octets reçus, deux réécritures).
   */
  async _resultatRecu(ctx, issue) {
    const t = issue.texte;
    const res = membre(issue.noeud, "result");
    const err = membre(issue.noeud, "error");
    if (err && !res) {
      const valeur = valeurDe(err);
      const p = await this._redigerPiece({ noortrace_jsonrpc_error: valeur }, "resultat", ctx);
      this.metriques.compter("noortrace_upstream_errors_total", { server: ctx.alias, kind: "jsonrpc" });
      return { piece: p.piece, valeurRedigee: p.valeurRedigee, nonRedigeable: p.nonRedigeable, is_error: true, erreurHote: compacter(t, err), resultatHote: null };
    }
    if (!res || res.t !== "objet") {
      const e = { code: -32603, message: "noortrace: resultat amont invalide", data: { result_type: res ? typeJson(res) : "null" } };
      return { piece: pieceErreurJsonRpc(e), valeurRedigee: null, nonRedigeable: null, is_error: true, erreurHote: JSON.stringify(e), resultatHote: null };
    }
    const valeur = valeurDe(res);
    const t0 = this.monotone();
    const p = await this._redigerPiece(valeur, "resultat", ctx);
    this.quotas.get(ctx.session.hote.id).tempsCapture(this.monotone(), this.monotone() - t0);
    const is_error = valeur.isError === true;
    const rt = membre(res, "resultType");
    const type = rt?.t === "chaine" ? rt.valeur : null;
    // Résultat non relayable (EX-4.8, différences d'ère) : -31016.
    let erreurHote = null;
    if (type !== null && type !== "complete" && type !== "input_required") erreurHote = JSON.stringify(erreurIssueNonRelayable("resultType"));
    else if (type === "input_required" && !ctx.moderne) erreurHote = JSON.stringify(erreurIssueNonRelayable("input_required"));
    else if (type === "input_required" && !this._demandesAdmises(ctx, valeur)) erreurHote = JSON.stringify(erreurIssueNonRelayable("inputRequests"));
    if (erreurHote !== null) {
      this.journal.consigner("warning", "frontal_mcp", "result_not_relayable", { server: ctx.alias, result_type: type }, { host: ctx.session.hote.id, request_id: ctx.m.idBrut });
      return { piece: p.piece, valeurRedigee: p.valeurRedigee, nonRedigeable: p.nonRedigeable, is_error, erreurHote, resultatHote: null };
    }
    const meta = membre(res, "_meta");
    const remplacer = new Map();
    const fin = [];
    const metaTexte =
      meta?.t === "objet"
        ? recomposerObjet(t, meta, {
            remplacer: new Map([["io.modelcontextprotocol/serverInfo", IDENTITE_TEXTE]]),
            ajouterEnFin: membre(meta, "io.modelcontextprotocol/serverInfo") ? [] : [["io.modelcontextprotocol/serverInfo", IDENTITE_TEXTE]],
          })
        : `{"io.modelcontextprotocol/serverInfo":${IDENTITE_TEXTE}}`;
    if (meta) remplacer.set("_meta", metaTexte);
    else fin.push(["_meta", metaTexte]);
    const tete = ctx.moderne && !rt ? [["resultType", '"complete"']] : [];
    const resultatHote = recomposerObjet(t, res, { remplacer, ajouterEnTete: tete, ajouterEnFin: fin });
    return { piece: p.piece, valeurRedigee: p.valeurRedigee, nonRedigeable: p.nonRedigeable, is_error, erreurHote: null, resultatHote };
  }

  /** `inputRequests` déclarées par l'hôte et relayables pour ce serveur (EX-4.28). */
  _demandesAdmises(ctx, valeur) {
    const demandes = valeur.inputRequests;
    if (!demandes || typeof demandes !== "object") return true;
    const caps = JSON.parse(ctx.capsAmont);
    const parMethode = { "sampling/createMessage": "sampling", "elicitation/create": "elicitation", "roots/list": "roots" };
    return Object.values(demandes).every((d) => {
      const k = parMethode[d?.method];
      return k !== undefined && k in caps;
    });
  }
}

function erreurIssueNonRelayable(quoi) {
  return { code: CODES.NON_RELAYABLE, message: MESSAGES[CODES.NON_RELAYABLE], data: { what: quoi } };
}

/** Horodatage d'un instant (tests, journal). */
export const horodatage = ecrireHorodatage;
