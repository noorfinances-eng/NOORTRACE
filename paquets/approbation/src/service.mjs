// Service d'approbation (CT-3 §12) : méthodes du noyau (`charger`,
// `evaluer`, `ouvrir`, `decisions`, `acquitter`, `consommer`, `expiration`),
// canal de la console complet (EX-12.13 : `tickets`, `consulter`, `voter`,
// `recuser`, `retirer`, `annuaire` et les méthodes de l'annuaire), état
// (`GET /v0/etat`, EX-12.12), minuteurs, lecture et surveillance du jeu,
// persistance avant toute réponse (EX-7.22, EX-12.17) et reprise (EX-7.23),
// notifications formées après la persistance de ce qui les cause (13.19).
//
// Toutes les entrées et les opérations de l'annuaire passent, une à une, par
// une file unique : la machine (ou le module d'annuaire) traite la requête,
// l'enregistrement est écrit et synchronisé, puis seulement la réponse est
// rendue (ou la remise livrée), et la notification formée. Le service ne
// détient aucune clé du journal ni d'approbateur, n'écrit aucun événement et
// ne signe rien (EX-3.3, EX-12.3). Les règles de l'annuaire sont celles du
// module d'annuaire de la console (`annuaire.mjs`), jamais réécrites ici.

import { ecrireHorodatage, hacherEvenement, verifierPiece, decoderBase64Canonique } from "@noortrace/noyau";
import { ErreurService } from "./erreurs.mjs";
import { validerPolitique, avertissementsPolitique } from "./politique.mjs";
import { candidats } from "./evaluation.mjs";
import { verifierRemise, condenseA } from "./signatures.mjs";
import { IDS, registreSchemas } from "./schema.mjs";
import {
  EtatAnnuaire, annuaireVide, annuaireDeSession, controleCanal, estIdentiteCanonique, adresseActive,
} from "./annuaire.mjs";
import { cloner, comparerChaines } from "./json.mjs";
import { infoCanal, membresAjoutes, reponseTickets, vueTicket } from "./vues.mjs";
import { SuiviPlafond } from "./notifications.mjs";

const HEX32 = /^0x[0-9a-f]{64}$/;
const objet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const memesCles = (o, cles) => objet(o) && Object.keys(o).length === cles.length && cles.every((k) => Object.prototype.hasOwnProperty.call(o, k));
const invalide = (message) => new ErreurService("requete_invalide", {}, message);

/** Méthodes du canal du noyau (12.2 à 12.6). */
export const METHODES_NOYAU = Object.freeze(["charger", "evaluer", "ouvrir", "decisions", "acquitter", "consommer", "expiration"]);
/** Méthodes du canal de la console (table d'EX-12.13). */
export const METHODES_CONSOLE = Object.freeze([
  "tickets", "consulter", "voter", "recuser", "retirer", "annuaire", "preparer_inscription", "inscrire", "valider",
  "revoquer", "desactiver", "reactiver", "lier_demandeur", "delier_demandeur",
]);
/** Méthodes du canal de la console qui forment une entrée de 7.4. */
export const METHODES_ENTREES_CONSOLE = Object.freeze(["voter", "recuser", "retirer"]);

/** `$defs` de la requête de chaque méthode du canal de la console (EX-12.13). */
export const REQUETES_CONSOLE = Object.freeze({
  tickets: [IDS.consoleService, "requete_tickets"],
  consulter: [IDS.consoleApprobation, "requete_consulter"],
  voter: [IDS.consoleApprobation, "requete_voter"],
  recuser: [IDS.consoleService, "requete_recuser"],
  retirer: [IDS.consoleService, "requete_retirer"],
  annuaire: [IDS.consoleService, "requete_annuaire"],
  preparer_inscription: [IDS.consoleService, "requete_preparer_inscription"],
  inscrire: [IDS.consoleService, "requete_inscrire"],
  valider: [IDS.consoleService, "requete_valider"],
  revoquer: [IDS.consoleService, "requete_revoquer"],
  desactiver: [IDS.consoleService, "requete_entree"],
  reactiver: [IDS.consoleService, "requete_entree"],
  lier_demandeur: [IDS.consoleService, "requete_demandeur"],
  delier_demandeur: [IDS.consoleService, "requete_demandeur"],
});

/** Types d'événements de la machine qui causent une notification (13.19). */
const CAUSES = new Set(["notification", "seuil_inatteignable", "plafond_atteint"]);

/** Empreinte abrégée d'un condensé (EX-9.18) : 8 chiffres, U+2026, 8 chiffres. */
export const empreinte = (D) => `${D.slice(2, 10)}\u2026${D.slice(-8)}`;

/** Le service d'approbation. */
export class ServiceApprobation {
  /**
   * @param {{config: object, machine: import("./tickets.mjs").Machine, magasin: import("./persistance.mjs").MagasinEtat|null,
   *   supervision: import("./supervision.mjs").Supervision, lecteur?: import("./lecteur-jeu.mjs").LecteurJeu|null,
   *   annuaire?: EtatAnnuaire|null, notifications?: import("./notifications.mjs").Notificateur|null,
   *   horloge?: () => number, tirerNonce?: () => string|undefined, minuterie?: boolean}} p
   *   `tirerNonce` : nonce imposé à `preparer_inscription` (essais seulement ; absent, le
   *   module d'annuaire le tire au hasard) ; `minuterie: false` : périodes du plafond closes
   *   par `tic()` seulement (horloge injectée des essais)
   */
  constructor(p) {
    this.config = p.config;
    this.machine = p.machine;
    this.magasin = p.magasin;
    this.supervision = p.supervision;
    this.lecteur = p.lecteur ?? null;
    this.annuaire = p.annuaire ?? new EtatAnnuaire({
      document: annuaireVide({
        org: p.config.org, org_id: p.config.org_id, console_origin: p.config.console_origin,
        registration_ttl_ms: p.config.registration_ttl_ms, administrators: p.config.administrators,
      }),
      defis: [],
      persiste: false,
    });
    this.notifications = p.notifications ?? null;
    this.horloge = p.horloge ?? Date.now;
    this.tirerNonce = p.tirerNonce ?? (() => undefined);
    this.plafond = new SuiviPlafond({
      horloge: this.horloge, journal: (type, d) => this.supervision.consigner(type, d), minuterie: p.minuterie !== false,
    });
    /** Causes de notification de l'entrée en cours, formées après sa persistance (EX-13.39). */
    this.causes = [];
    const amont = this.machine.evenement;
    this.machine.evenement = (type, detail) => {
      amont(type, detail);
      if (CAUSES.has(type)) this.causes.push({ type, detail: cloner(detail) });
    };
    this.file = Promise.resolve();
    /** remise_id → instant au plus tôt de sa prochaine présentation */
    this.prochaines = new Map();
    this.attentes = new Set();
    this.minuteur = null;
    this.minuteurLecture = null;
    this.lectureEnCours = null;
    /** Dernière hauteur vue par jeu épinglé lu (EX-8.5). */
    this.dernieresHauteurs = new Map();
    this.derniereTentative = 0;
    this.setReadAt = null;
    this.arrete = false;
  }

  // -------------------------------------------------------------- file unique

  /** Exécute une tâche dans la file ; la tâche suivante attend sa fin. */
  #executer(tache) {
    const r = this.file.then(tache);
    this.file = r.catch(() => {});
    return r;
  }

  #maintenant() {
    const t = this.horloge();
    const d = this.machine.dernierAt;
    return d !== null && t < d ? d : t; // horloge qui recule : jamais d'instant antérieur à la dernière entrée
  }

  /**
   * Traite une entrée de 7.4, persiste, puis rend le résultat.
   * @param {string} kind
   * @param {object} data
   * @param {object} [options]
   */
  async #entree(kind, data, options) {
    if (this.arrete) throw new ErreurService("requete_invalide", {}, "service arrete");
    const at = ecrireHorodatage(this.#maintenant());
    const r = this.machine.entree({ kind, at, data }, options);
    await this.#persister();
    for (const remise of r.remises) this.supervision.consigner("remise_calculee", { ticket: remise.ticket, remise_id: remise.remise_id, decision: remise.approval.decision });
    this.#notifierCauses();
    this.#apres();
    if (!r.accepted) throw new ErreurService(r.reason, r.data ?? {});
    return r.response;
  }

  /**
   * Rend durable l'état changé par l'entrée (EX-7.22). Un enregistrement porte
   * toujours l'état général (dont l'instant de la dernière entrée) ; une entrée
   * sans effet n'écrit rien. Après un échec d'écriture, le magasin refuse les
   * ajouts : l'état complet en mémoire est alors recopié (`reprendre`) avant
   * toute réponse, de sorte que rien de ce que la machine a changé ne devient
   * visible sans être durable, et qu'aucun changement n'est perdu.
   */
  async #persister(annuaire = {}) {
    const m = this.machine.prendreModifications();
    if (!this.magasin) return;
    if (this.magasin.enPanne) {
      await this.magasin.reprendre(this.etatComplet());
      this.supervision.consigner("reprise", { kind: "etat_recopie" });
      return;
    }
    const enr = {};
    if (m.versions) enr.versions = this.machine.versionsChargees();
    if (m.tickets.size) enr.tickets = [...m.tickets].map((id) => this.machine.ticketPersiste(this.machine.tickets.get(id)));
    if (m.fenetres) enr.fenetres = this.machine.copieFenetres();
    // annuaire et défis (EX-13.38) : documents entiers, écrits à chaque changement
    if (annuaire.annuaire) enr.annuaire = annuaire.annuaire;
    if (annuaire.defis) enr.defis = annuaire.defis;
    if (!m.meta && Object.keys(enr).length === 0) return;
    enr.meta = this.machine.meta();
    try {
      await this.magasin.ajouter(enr);
      if (this.magasin.aCompacter) await this.magasin.compacter(this.etatComplet());
    } catch (e) {
      this.supervision.consigner("erreur", { kind: "persistance", code: e?.code ?? null, message: e?.message ?? null });
      throw e;
    }
  }

  /** Après chaque entrée : minuteurs, remises en attente, lecture du jeu. */
  #apres() {
    this.#planifierMinuteur();
    this.#reveiller();
    if (this.#lectureNecessaire()) this.#lireBientot(0);
  }

  #planifierMinuteur() {
    clearTimeout(this.minuteur);
    if (this.arrete) return;
    const prochain = this.machine.prochainMinuteur();
    if (prochain === null) return;
    const delai = Math.max(0, Math.min(prochain - this.horloge(), 2 ** 31 - 1));
    this.minuteur = setTimeout(() => {
      this.#executer(() => this.#entree("horloge", {})).catch((e) => this.supervision.consigner("erreur", { kind: "minuteur", message: e.message }));
    }, delai);
    this.minuteur.unref?.();
  }

  // -------------------------------------------------------------- charger (12.2)

  /** @param {object} corps */
  charger(corps) {
    return this.#executer(async () => {
      const cles = ["org_id", "journal_id", "environment", "policy_version", "policy_sha256", "approval", "tools", "requesters"];
      if (!memesCles(corps, cles)) throw invalide("membres de charger");
      if (corps.org_id !== this.config.org_id || corps.journal_id !== this.config.journal_id) throw invalide("journal différent de celui du service");
      if (corps.environment !== "production" && corps.environment !== "developpement") throw invalide("environment");
      if (typeof corps.policy_version !== "string" || corps.policy_version.length < 1 || [...corps.policy_version].length > 128) throw invalide("policy_version");
      if (!HEX32.test(corps.policy_sha256)) throw invalide("policy_sha256");
      const a = corps.approval;
      if (!memesCles(a, ["rules", "mode", "hold_timeout_ms", "expire_after_ms", "timeout_ms"])) throw invalide("approval sans service");
      if (!["erreur", "retenir", "observation"].includes(a.mode)) throw invalide("approval.mode");
      for (const k of ["hold_timeout_ms", "expire_after_ms", "timeout_ms"]) {
        if (!Number.isInteger(a[k]) || a[k] < 0 || a[k] > 86400000) throw invalide(`approval.${k}`);
      }
      if (a.expire_after_ms < 1) throw invalide("approval.expire_after_ms");
      if (!Array.isArray(corps.tools) || !corps.tools.every((t) => memesCles(t, ["tool_announced", "tool_original", "server_alias", "class", "effects"]) &&
        typeof t.tool_announced === "string" && /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(t.tool_announced))) {
        throw invalide("tools");
      }
      if (!Array.isArray(corps.requesters) || !corps.requesters.every((x) => typeof x === "string")) throw invalide("requesters");
      const existante = this.machine.version(corps.policy_version);
      if (existante && existante.policy_sha256 !== corps.policy_sha256) throw invalide("version déjà chargée avec une autre empreinte");
      // EX-12.5 : EX-4.2 et EX-8.2 ; toutes les erreurs dans data.errors
      const erreurs = validerPolitique(a.rules, { environment: corps.environment, expire_after_ms: a.expire_after_ms });
      if (erreurs.length) {
        this.supervision.consigner("politique_invalide", { policy_version: corps.policy_version, errors: erreurs });
        throw new ErreurService("politique_invalide", { errors: erreurs });
      }
      const L = corps.tools.map((t) => t.tool_announced);
      for (const w of avertissementsPolitique(a.rules, { outils: L, requesters: corps.requesters })) {
        this.supervision.consigner("avertissement_politique", { policy_version: corps.policy_version, ...w });
      }
      // EX-10.10, EX-7.13 : chaque after_ms d'escalade est inférieur à E ; une étape au-delà ne part jamais
      const tardives = (this.config.escalation ?? []).filter((x) => x.after_ms >= a.expire_after_ms).map((x) => x.after_ms);
      if (tardives.length) {
        this.supervision.consigner("avertissement", { kind: "escalade_apres_echeance", policy_version: corps.policy_version, expire_after_ms: a.expire_after_ms, after_ms: tardives });
      }
      if (a.rules.approver_set.source === "registre" && !this.lecteur) {
        this.supervision.consigner("alerte", { kind: "jeu_registre_sans_rpc", policy_version: corps.policy_version });
      }
      const approval_candidates = candidats(a.rules, L).sort(comparerChaines);
      this.machine.ajouterVersion({
        policy_version: corps.policy_version,
        policy_sha256: corps.policy_sha256,
        environment: corps.environment,
        approval: cloner(a),
        tools: cloner(corps.tools),
        requesters: [...corps.requesters],
        approval_candidates,
      });
      await this.#entree("charger", { policy_version: corps.policy_version });
      this.supervision.consigner("charger", { policy_version: corps.policy_version, policy_sha256: corps.policy_sha256, mode: a.mode, approval_candidates });
      return { policy_version: corps.policy_version, policy_sha256: corps.policy_sha256, approval_candidates };
    });
  }

  // -------------------------------------------------------------- evaluer (12.3)

  /** @param {object} corps requête de CT-2 EX-7.4 */
  evaluer(corps) {
    return this.#executer(async () => {
      const cles = ["tool_announced", "tool_original", "server_alias", "arguments", "class", "delegation", "intent", "code", "context"];
      if (!memesCles(corps, cles) || !registreSchemas().estValide(`${IDS.ticket}#/$defs/requete_evaluer`, corps)) throw invalide("requete evaluer");
      const r = await this.#entree("evaluer", { request: corps });
      this.supervision.compter(`evaluations_${r.decision}`);
      return r;
    });
  }

  // -------------------------------------------------------------- ouvrir (12.4)

  /** @param {object} corps */
  ouvrir(corps) {
    return this.#executer(async () => {
      const cles = ["ticket", "request_hash", "request_seq", "request_ts", "request_event", "arguments_piece"];
      if (!memesCles(corps, cles)) throw invalide("membres d'ouvrir");
      const ev = corps.request_event;
      // L'événement est celui que le noyau a scellé : sa forme, son hachage et
      // la pièce « arguments » sont contrôlés avant d'être gardés pour la console (EX-9.6).
      if (!registreSchemas().estValide(IDS.evenement, ev)) throw invalide("request_event");
      let hash;
      try {
        hash = hacherEvenement(ev);
      } catch {
        throw invalide("request_event");
      }
      if (hash !== corps.request_hash || ev.hash !== corps.request_hash || ev.seq !== corps.request_seq || ev.ts !== corps.request_ts ||
        ev.policy?.ticket !== corps.ticket || ev.execution?.status !== "retenue") {
        throw invalide("request_event différent de la demande remise");
      }
      const ref = ev.execution.arguments;
      if (corps.arguments_piece === null) {
        if (ref?.value === undefined) throw invalide("arguments_piece nulle pour une référence sans valeur en ligne");
      } else {
        const octets = decoderBase64Canonique(corps.arguments_piece, this.config.body_max_bytes);
        if (!octets || !verifierPiece(ref, octets)) throw invalide("arguments_piece");
      }
      return this.#entree("ouvrir", corps);
    });
  }

  // -------------------------------------------------------------- decisions (12.5)

  #livrables(maintenant) {
    return this.machine.remisesCourantes().filter((x) => (this.prochaines.get(x.remise.remise_id) ?? 0) <= maintenant);
  }

  #reveiller() {
    for (const a of [...this.attentes]) a();
  }

  /** Contrôle SG d'une remise avant livraison : défaut du service consigné (EX-9.11, T16). */
  #autoControle(remise, maintenant) {
    const t = this.machine.tickets.get(remise.ticket);
    if (!t || t.request.request_hash === null || t.request.request_ts === null) return;
    const sep = this.machine.version(t.request.policy_version)?.approval?.rules?.separation ?? { self_approval: "permise", identities: [] };
    const v = verifierRemise(remise, {
      org_id: this.machine.org_id,
      journal_id: this.machine.journal_id,
      retained: [{ seq: t.request.request_seq, ticket: t.ticket, hash: t.request.request_hash, ts: t.request.request_ts, launched_by: t.request.delegation.launched_by }],
      decided: [],
      expire_after_ms: t.expire_after_ms,
      separation: sep,
      write_at: ecrireHorodatage(maintenant),
    });
    if (v.result !== "scelle") this.supervision.consigner("alerte", { kind: "remise_non_conforme", ticket: remise.ticket, remise_id: remise.remise_id, check: v.check, reason: v.reason });
  }

  /**
   * Attente longue (EX-12.8) : rend dès qu'une remise est prête, ou au terme
   * de `wait_ms` une liste vide. Une remise livrée est re-présentée après
   * `remise_representation_ms` sans acquittement, ou `timeout_ms` après un
   * acquittement `temporaire` (T12).
   * @param {{wait_ms: number}} corps
   */
  async decisions(corps) {
    if (!memesCles(corps, ["wait_ms"]) || !Number.isInteger(corps.wait_ms) || corps.wait_ms < 0 || corps.wait_ms > 25000) throw invalide("wait_ms");
    const fin = this.horloge() + corps.wait_ms;
    for (;;) {
      const remises = await this.#executer(async () => {
        // EX-7.22 : une remise n'est livrée que durable ; après un échec d'écriture,
        // l'état complet est d'abord recopié, sinon rien n'est livré.
        if (this.magasin?.enPanne) {
          try {
            await this.magasin.reprendre(this.machine.exporter());
          } catch {
            return [];
          }
        }
        const maintenant = this.horloge();
        const l = this.#livrables(maintenant);
        for (const x of l) {
          this.prochaines.set(x.remise.remise_id, maintenant + this.config.remise_representation_ms);
          this.#autoControle(x.remise, maintenant);
          this.supervision.consigner("remise_livree", { ticket: x.remise.ticket, remise_id: x.remise.remise_id });
        }
        return l.map((x) => x.remise);
      });
      if (remises.length || this.arrete) return { remises };
      const reste = fin - this.horloge();
      if (reste <= 0) return { remises: [] };
      const prochaine = Math.min(
        ...this.machine.remisesCourantes().map((x) => this.prochaines.get(x.remise.remise_id) ?? 0).filter((t) => t > this.horloge()),
        fin,
      );
      await new Promise((resoudre) => {
        const fini = () => {
          clearTimeout(minuteur);
          this.attentes.delete(fini);
          resoudre();
        };
        const minuteur = setTimeout(fini, Math.max(1, Math.min(reste, prochaine - this.horloge())));
        this.attentes.add(fini);
      });
    }
  }

  // -------------------------------------------------------------- acquitter, consommer, expiration (12.5, 12.6)

  /** @param {object} corps */
  acquitter(corps) {
    return this.#executer(async () => {
      if (!memesCles(corps, ["remise_id", "ticket", "result", "reason", "seq", "hash", "at", "decision", "held", "approval"])) throw invalide("membres d'acquitter");
      const r = await this.#entree("acquitter", corps);
      if (corps.result === "temporaire") {
        // T12 : re-présentée au plus tôt timeout_ms plus tard
        const t = this.machine.tickets.get(corps.ticket);
        const timeout = this.machine.version(t.request.policy_version)?.approval?.timeout_ms ?? 2000;
        this.prochaines.set(corps.remise_id, this.horloge() + timeout);
      } else {
        this.prochaines.delete(corps.remise_id);
      }
      this.supervision.consigner("acquitter", { ticket: corps.ticket, remise_id: corps.remise_id, result: corps.result, reason: corps.reason, state: r.state });
      return r;
    });
  }

  /** @param {object} corps */
  consommer(corps) {
    return this.#executer(async () => {
      if (!memesCles(corps, ["ticket", "seq", "hash"])) throw invalide("membres de consommer");
      const r = await this.#entree("consommer", corps);
      this.supervision.consigner("consommer", { ticket: corps.ticket, state: r.state });
      return r;
    });
  }

  /** @param {object} corps */
  expiration(corps) {
    return this.#executer(async () => {
      if (!memesCles(corps, ["ticket", "seq", "hash", "at", "approval"])) throw invalide("membres d'expiration");
      const r = await this.#entree("expiration", corps);
      this.supervision.consigner("expiration", { ticket: corps.ticket, state: r.state });
      return r;
    });
  }

  // -------------------------------------------------------------- canal de la console (12.9)

  /**
   * Méthode du canal de la console (EX-12.13) : forme du corps
   * (`requete_invalide`), identité de session canonique (`identite_invalide`),
   * puis les refus de la méthode dans l'ordre de sa règle. Le contrôle de
   * l'identité de session des méthodes de ticket est celui de `controleCanal`,
   * fait avant que l'entrée soit formée : un refus ne laisse aucune trace dans
   * le ticket (EX-12.13, EX-12.19).
   * @param {string} methode
   * @param {object} corps
   */
  console(methode, corps) {
    return this.#executer(async () => {
      if (this.arrete) throw new ErreurService("requete_invalide", {}, "service arrete");
      const def = REQUETES_CONSOLE[methode];
      if (!def) throw invalide("methode hors du canal de la console");
      if (!registreSchemas().estValide(`${def[0]}#/$defs/${def[1]}`, corps)) throw invalide(`corps de ${methode}`);
      if (!estIdentiteCanonique(corps.session_identity)) throw new ErreurService("identite_invalide");
      switch (methode) {
        case "tickets": return this.#tickets(corps);
        case "consulter": return this.#consulter(corps);
        case "annuaire": return annuaireDeSession(this.annuaire.document, corps.session_identity);
        case "voter":
        case "recuser":
        case "retirer": return this.#entreeConsole(methode, corps);
        default: return this.#operationAnnuaire(methode, corps);
      }
    });
  }

  #refusCanal(methode, ticket, reason) {
    this.supervision.consigner("canal_console_refus", { methode, ticket: typeof ticket === "string" ? ticket : null, reason });
    return new ErreurService(reason);
  }

  /** Refus de `consulter` appliqué à un ticket (EX-12.14 : points 1 à 3, puis `ticket_non_ouvert`). */
  #controleConsulter(methode, ticket, session) {
    const refus = controleCanal(this.annuaire.document, "consulter", { ticket, session_identity: session }, infoCanal(this.machine, ticket));
    if (refus) throw this.#refusCanal(methode, ticket, refus);
    const t = this.machine.tickets.get(ticket);
    if (t.state === "reserve") throw this.#refusCanal(methode, ticket, "ticket_non_ouvert");
    return t;
  }

  /** `tickets` (EX-12.14, EX-12.21). */
  #tickets(corps) {
    const refus = controleCanal(this.annuaire.document, "tickets", corps, null);
    if (refus) throw this.#refusCanal("tickets", null, refus);
    if (corps.related_to !== undefined) this.#controleConsulter("tickets", corps.related_to, corps.session_identity);
    return reponseTickets({
      machine: this.machine, annuaire: this.annuaire.document, session: corps.session_identity, relatedTo: corps.related_to,
      maintenant: this.#maintenant(),
    });
  }

  /**
   * `consulter` (EX-12.14, EX-12.15). Un ticket dont les arguments sont
   * effacés (EX-7.24 : `consomme`, `clos`, `abandonne`, ou expiré sans
   * événement `retenue`) n'a plus de vue : `ticket_clos_aux_votes`.
   */
  #consulter(corps) {
    const t = this.#controleConsulter("consulter", corps.ticket, corps.session_identity);
    if (t.request.retained_event === null || t.request.arguments === null) throw this.#refusCanal("consulter", corps.ticket, "ticket_clos_aux_votes");
    return vueTicket({ machine: this.machine, annuaire: this.annuaire.document, ticket: t, bodyMax: this.config.body_max_bytes });
  }

  /** `voter`, `recuser`, `retirer` : entrée de 7.4 après le contrôle du canal (EX-12.16, EX-12.19). */
  async #entreeConsole(methode, corps) {
    const refus = controleCanal(this.annuaire.document, methode, corps, infoCanal(this.machine, corps.ticket));
    if (refus) throw this.#refusCanal(methode, corps.ticket, refus);
    await this.#entree(methode, corps);
    const t = this.machine.tickets.get(corps.ticket);
    if (methode === "voter") {
      // EX-13.3, EX-13.40 : vote_inscrit, formé après la persistance du vote
      const D = condenseA({ decision: corps.decision, ticket: t.ticket, request_hash: t.request.request_hash, org_id: this.machine.org_id, journal_id: this.machine.journal_id });
      const vote = t.votes.at(-1);
      this.#notifier("vote_inscrit", {
        entries: this.#entreesDesAdresses([corps.approver]), roles: [], ticket: t,
        details: { approver: corps.approver, decision: corps.decision, digest: empreinte(D), at: vote.at },
      });
    }
    return { ticket: t.ticket, state: t.state };
  }

  /**
   * Méthode qui modifie l'annuaire ou ses défis (EX-13.13, EX-13.15,
   * EX-13.17) : le module d'annuaire décide ; l'annuaire et les défis changés
   * sont persistés avec fsync avant la réponse (EX-12.17), y compris le défi
   * marqué présenté d'une inscription refusée (EX-13.15, pas 4) ; une
   * opération refusée est consignée avec sa raison.
   */
  async #operationAnnuaire(methode, corps) {
    const at = ecrireHorodatage(this.#maintenant());
    const nonce = methode === "preparer_inscription" ? this.tirerNonce() : undefined;
    const r = this.annuaire.calculer(methode, corps, at, nonce === undefined ? {} : { nonce });
    if (r.annuaireChange || r.defisChanges) {
      const persiste = this.annuaire.persiste || r.annuaireChange;
      const document = r.annuaireChange ? r.annuaire : this.annuaire.document;
      this.annuaire.adopter({ annuaire: document, defis: r.defis, persiste });
      await this.#persister(persiste ? { annuaire: document, defis: r.defis } : { defis: r.defis });
    }
    if (!r.accepted) {
      this.supervision.consigner("operation_annuaire_refusee", { methode, reason: r.reason, entry: typeof corps.entry === "string" ? corps.entry : null });
      throw new ErreurService(r.reason, typeof corps.entry === "string" ? { entry: corps.entry } : {});
    }
    if (methode !== "preparer_inscription") {
      const op = r.annuaire.operations.at(-1);
      const e = r.annuaire.entries.find((x) => x.id === op.entry);
      this.supervision.consigner("operation_annuaire", { methode, entry: op.entry, revision: r.annuaire.revision });
      // EX-13.3, EX-13.40 : operation_annuaire, à l'entrée visée, après la persistance
      this.#notifier("operation_annuaire", {
        entries: [op.entry], roles: [], ticket: null,
        details: { op: op.op, entry: op.entry, address: op.address, revision: r.annuaire.revision, at: op.at, by_self: e?.session_identity === op.by },
      });
    }
    return r.response;
  }

  // -------------------------------------------------------------- notifications (13.19)

  /** Entrées actives dont l'adresse active est l'une de `adresses` (EX-13.40). */
  #entreesDesAdresses(adresses) {
    const voulues = new Set(adresses);
    return this.annuaire.document.entries.filter((e) => e.active && voulues.has(adresseActive(e))).map((e) => e.id);
  }

  /**
   * Forme une notification (EX-13.40) : `ticket` est le document du ticket,
   * ou null pour une opération de l'annuaire et `plafond_atteint`.
   */
  #notifier(kind, { entries, roles, ticket, details, lien = true }) {
    if (!this.notifications) return;
    const id = ticket?.ticket ?? null;
    this.notifications.notifier({
      kind, entries, roles, ticket: id, tool: ticket?.request.tool_announced ?? null, deadline: ticket?.deadline ?? null,
      link: lien ? this.notifications.lien(id) : null, details,
    });
  }

  /** Forme les notifications causées par l'entrée qui vient d'être persistée (EX-13.39). */
  #notifierCauses() {
    const causes = this.causes;
    this.causes = [];
    for (const { type, detail } of causes) {
      try {
        if (type === "plafond_atteint") {
          if (this.plafond.refus(detail.launched_by)) {
            this.#notifier("plafond_atteint", { entries: [], roles: ["administrateur"], ticket: null, lien: false, details: { max_open_tickets: detail.max_open_tickets } });
          }
          continue;
        }
        const t = this.machine.tickets.get(detail.ticket);
        if (!t) continue;
        if (type === "seuil_inatteignable") {
          this.#notifier("seuil_inatteignable", {
            entries: [], roles: ["administrateur_jeu", "administrateur"], ticket: t,
            details: { eligible_count: detail.eligible, effective_required: detail.effective_required },
          });
        } else if (detail.kind === "ouverture") {
          this.#notifier("ouverture", { entries: this.#entreesDesAdresses(detail.approvers), roles: [], ticket: t, details: null });
        } else if (detail.kind === "nouveau_gel") {
          this.#notifier("nouveau_gel", {
            entries: this.#entreesDesAdresses(detail.approvers), roles: [], ticket: t,
            details: { added_members: membresAjoutes(t), effective_required: t.effective_required },
          });
        } else if (detail.kind === "escalade") {
          let entries = [];
          let roles = [];
          if (detail.notify === "jeu") entries = this.#entreesDesAdresses(detail.approvers);
          else if (detail.notify === "administrateur") roles = ["administrateur_jeu"];
          else {
            const lb = t.request.delegation.launched_by;
            entries = this.annuaire.document.entries.filter((e) => e.active && e.requester_identities.includes(lb)).map((e) => e.id);
          }
          this.#notifier("escalade", { entries, roles, ticket: t, details: null });
        }
      } catch (e) {
        this.supervision.consigner("erreur", { kind: "notification", message: e.message });
      }
    }
  }

  // -------------------------------------------------------------- jeu d'approbateurs (8.1 à 8.3)

  /** Jeu épinglé `registre` d'une version (`approver_set` de sa politique), ou null. */
  #jeuEpingle(pv) {
    const p = pv ? this.machine.version(pv)?.approval?.rules?.approver_set : null;
    return p?.source === "registre" ? p : null;
  }

  /**
   * Jeux à lire (EX-8.1, EX-8.3, EX-7.21) : le jeu épinglé de la version en
   * vigueur (jeu de repli) et celui de la version de chaque ticket en collecte,
   * un par (chain_id, registry, set).
   * @returns {Map<string, {pol: object, vigueur: boolean, tickets: object[]}>}
   */
  #cibles() {
    const cibles = new Map();
    const ajouter = (pol) => {
      if (!pol) return null;
      const k = `${pol.chain_id}|${pol.registry.toLowerCase()}|${pol.set.toLowerCase()}`;
      if (!cibles.has(k)) cibles.set(k, { pol, vigueur: false, tickets: [] });
      return cibles.get(k);
    };
    const v = ajouter(this.#jeuEpingle(this.machine.enVigueur));
    if (v) v.vigueur = true;
    for (const t of this.#ticketsOuverts()) ajouter(this.#jeuEpingle(t.request.policy_version))?.tickets.push(t);
    return cibles;
  }

  /** Une lecture complète de ce jeu est-elle nécessaire (repli absent, ticket non figé, en vérification ou réassigné) ? */
  #cibleALire(c) {
    if (c.vigueur && !this.machine.pret(this.machine.enVigueur)) return true;
    return c.tickets.some((t) => t.approver_set === null || t.state === "verification" || t.set_reassigned);
  }

  #lectureNecessaire() {
    if (!this.lecteur) return false;
    for (const c of this.#cibles().values()) if (this.#cibleALire(c)) return true;
    return false;
  }

  #ticketsOuverts() {
    return [...this.machine.tickets.values()].filter((t) => ["ouvert", "seuil_atteint", "verification"].includes(t.state));
  }

  #lireBientot(delai) {
    if (this.arrete || !this.lecteur) return;
    if (this.lectureEnCours) {
      this.relire = true;
      return;
    }
    clearTimeout(this.minuteurLecture);
    this.minuteurLecture = setTimeout(() => this.#sonder(true), delai);
    this.minuteurLecture.unref?.();
  }

  /**
   * Sondage des jeux (EX-8.4, EX-8.5) : pour chaque jeu épinglé à suivre,
   * lecture complète quand elle est nécessaire, sinon recherche des changements
   * depuis la dernière hauteur vue ; puis nouveau sondage après
   * `set_poll_interval_ms`.
   */
  async #sonder(force = false) {
    if (this.arrete || !this.lecteur) return;
    this.lectureEnCours = (async () => {
      for (const [k, c] of this.#cibles()) {
        if (this.arrete) return;
        try {
          await this.#sonderCible(k, c, force);
        } catch (e) {
          this.supervision.consigner("erreur", { kind: "lecture_jeu", message: e.message });
        }
      }
    })();
    await this.lectureEnCours;
    this.lectureEnCours = null;
    if (this.arrete) return;
    if (this.relire) {
      this.relire = false;
      return this.#lireBientot(0);
    }
    clearTimeout(this.minuteurLecture);
    this.minuteurLecture = setTimeout(() => this.#sonder(false), this.config.set_poll_interval_ms);
    this.minuteurLecture.unref?.();
  }

  async #sonderCible(k, c, force) {
    const pol = c.pol;
    let lire = force || this.#cibleALire(c);
    if (!lire) {
      // EX-8.5 : journaux de l'organisation au registre et du jeu épinglé
      try {
        const H = await this.lecteur.hauteur();
        const derniere = this.dernieresHauteurs.get(k) ?? null;
        if (derniere !== null) lire = await this.lecteur.changements(pol, pol.set, derniere, H);
        else lire = true;
        if (!lire) this.dernieresHauteurs.set(k, H);
      } catch {
        lire = true;
      }
    }
    if (!lire) return;
    const precedents = new Set();
    for (const t of this.machine.tickets.values()) for (const m of t.approver_set?.members ?? []) precedents.add(m);
    for (const v of this.machine.versions.values()) for (const i of v.approval.rules.separation.identities) for (const a of i.addresses) precedents.add(a);
    const repli = this.machine.repli(this.machine.enVigueur);
    for (const m of repli?.members ?? []) precedents.add(m);
    // EX-8.7 : la lecture est datée de son début ; une lecture partie avant le
    // calcul d'une décision ne la confirme pas (T8).
    const debut = this.#maintenant();
    const r = await this.lecteur.lire(pol, precedents);
    const lecture = { debut, cible: { chain_id: pol.chain_id, registry: pol.registry, set: pol.set } };
    await this.#executer(async () => {
      if (this.arrete) return;
      await this.#entree("jeu_lu", r, { lecture }).catch(() => {});
    });
    if (r.status === "lu" && r.jeu.set === pol.set.toLowerCase()) {
      this.setReadAt = ecrireHorodatage(this.horloge());
      this.dernieresHauteurs.set(k, r.jeu.height);
    }
    this.supervision.consigner("lecture_jeu", { status: r.status, cause: r.cause, height: r.jeu?.height ?? null, set: r.jeu?.set ?? null, pinned: pol.set });
  }

  /**
   * Déclenche les minuteurs échus à l'instant de l'horloge du service : entrée
   * `horloge` de la machine, périodes du plafond closes, tentatives de
   * notification échues.
   */
  async tic() {
    const r = await this.#executer(() => this.#entree("horloge", {}));
    this.plafond.cloturer();
    this.notifications?.traiter();
    return r;
  }

  /** État complet à persister (EX-7.23) : documents de la machine, annuaire et défis (EX-13.38). */
  etatComplet() {
    return { ...this.machine.exporter(), ...this.annuaire.exporter() };
  }

  // -------------------------------------------------------------- état (EX-12.12)

  /** `{ ready, set_read_at, open_tickets }` */
  etat() {
    const pv = this.machine.enVigueur;
    return { ready: pv !== null && this.machine.pret(pv), set_read_at: this.setReadAt, open_tickets: this.machine.ticketsOuverts() };
  }

  // -------------------------------------------------------------- cycle de vie

  /**
   * Démarre : déclenche les minuteurs échus pendant l'arrêt (EX-7.23), relit
   * le jeu des tickets ouverts, re-présente les remises non acquittées.
   */
  async demarrer() {
    await this.#executer(() => this.#entree("horloge", {}));
    this.#sonder(this.#lectureNecessaire() || this.#ticketsOuverts().length > 0);
    this.supervision.consigner("demarrage_service", {
      tickets: this.machine.tickets.size, open_tickets: this.machine.ticketsOuverts(), remises: this.machine.remisesCourantes().length,
      en_vigueur: this.machine.enVigueur,
    });
  }

  async arreter() {
    this.arrete = true;
    clearTimeout(this.minuteur);
    clearTimeout(this.minuteurLecture);
    this.#reveiller();
    await this.lectureEnCours?.catch(() => {});
    await this.file.catch(() => {});
    this.plafond.arreter();
    await this.notifications?.arreter();
    await this.supervision.vider();
    await this.magasin?.fermer();
  }
}
