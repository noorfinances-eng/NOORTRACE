// Service d'approbation (CT-3 §12) : méthodes du noyau (`charger`,
// `evaluer`, `ouvrir`, `decisions`, `acquitter`, `consommer`, `expiration`),
// entrées de la console (`voter`, `recuser`, `retirer`, 7.4), état
// (`GET /v0/etat`, EX-12.12), minuteurs, lecture et surveillance du jeu,
// persistance avant toute réponse (EX-7.22) et reprise (EX-7.23).
//
// Toutes les entrées passent, une à une, par une file unique : la machine
// traite l'entrée, l'enregistrement est écrit et synchronisé, puis seulement
// la réponse est rendue (ou la remise livrée). Le service ne détient aucune
// clé du journal ni d'approbateur, n'écrit aucun événement et ne signe rien
// (EX-3.3, EX-12.3).

import { ecrireHorodatage, hacherEvenement, verifierPiece, decoderBase64Canonique } from "@noortrace/noyau";
import { ErreurService } from "./erreurs.mjs";
import { validerPolitique, avertissementsPolitique } from "./politique.mjs";
import { candidats } from "./evaluation.mjs";
import { verifierRemise, condenseA } from "./signatures.mjs";
import { IDS, registreSchemas } from "./schema.mjs";
import { Annuaire, controleCanal, identiteCanonique } from "./annuaire.mjs";
import { cloner, comparerChaines } from "./json.mjs";

const HEX32 = /^0x[0-9a-f]{64}$/;
const objet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const memesCles = (o, cles) => objet(o) && Object.keys(o).length === cles.length && cles.every((k) => Object.prototype.hasOwnProperty.call(o, k));
const invalide = (message) => new ErreurService("requete_invalide", {}, message);

/** Méthodes du canal du noyau (12.2 à 12.6). */
export const METHODES_NOYAU = Object.freeze(["charger", "evaluer", "ouvrir", "decisions", "acquitter", "consommer", "expiration"]);
/** Méthodes du canal de la console servies à l'étape 4 (entrées de 7.4). */
export const METHODES_CONSOLE = Object.freeze(["voter", "recuser", "retirer"]);
/** Méthodes du canal de la console de l'étape 6 (12.9), non servies ici. */
export const METHODES_CONSOLE_ETAPE_6 = Object.freeze([
  "tickets", "consulter", "annuaire", "preparer_inscription", "inscrire", "valider", "revoquer", "desactiver",
  "reactiver", "lier_demandeur", "delier_demandeur",
]);

/** Le service d'approbation. */
export class ServiceApprobation {
  /**
   * @param {{config: object, machine: import("./tickets.mjs").Machine, magasin: import("./persistance.mjs").MagasinEtat|null,
   *   supervision: import("./supervision.mjs").Supervision, lecteur?: import("./lecteur-jeu.mjs").LecteurJeu|null,
   *   annuaire?: Annuaire|null, horloge?: () => number}} p
   */
  constructor(p) {
    this.config = p.config;
    this.machine = p.machine;
    this.magasin = p.magasin;
    this.supervision = p.supervision;
    this.lecteur = p.lecteur ?? null;
    this.annuaire = p.annuaire ?? Annuaire.vide(p.config.org_id, p.config.administrators);
    this.horloge = p.horloge ?? Date.now;
    this.file = Promise.resolve();
    /** remise_id → instant au plus tôt de sa prochaine présentation */
    this.prochaines = new Map();
    this.attentes = new Set();
    this.minuteur = null;
    this.minuteurLecture = null;
    this.lectureEnCours = null;
    this.derniereHauteur = null;
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
    this.#apres();
    if (!r.accepted) throw new ErreurService(r.reason, r.data ?? {});
    return r.response;
  }

  async #persister() {
    const m = this.machine.prendreModifications();
    if (!this.magasin) return;
    const enr = {};
    if (m.meta) enr.meta = this.machine.meta();
    if (m.versions) enr.versions = this.machine.versionsChargees();
    if (m.tickets.size) enr.tickets = [...m.tickets].map((id) => this.machine.tickets.get(id));
    if (m.fenetres) enr.fenetres = this.machine.copieFenetres();
    if (Object.keys(enr).length === 0) return;
    await this.magasin.ajouter(enr);
    if (this.magasin.aCompacter) await this.magasin.compacter(this.machine.exporter());
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

  // -------------------------------------------------------------- canal de la console : voter, recuser, retirer (EX-12.13, EX-12.16, EX-12.19)

  #infoTicket(id) {
    const t = typeof id === "string" ? this.machine.tickets.get(id) : undefined;
    return t ? { launched_by: t.request.delegation.launched_by, eligible: t.eligible } : null;
  }

  /**
   * Méthode du canal de la console qui forme une entrée de 7.4. Le contrôle de
   * l'identité de session est fait avant l'entrée : un refus ne laisse aucune
   * trace dans le ticket.
   * @param {"voter"|"recuser"|"retirer"} methode
   * @param {object} corps
   */
  console(methode, corps) {
    return this.#executer(async () => {
      const formes = {
        voter: ["ticket", "approver", "decision", "signature", "reason", "session_identity"],
        recuser: ["ticket", "approver", "session_identity"],
        retirer: ["ticket", "by", "reason", "session_identity"],
      };
      if (!formes[methode] || !memesCles(corps, formes[methode])) throw invalide(`membres de ${methode}`);
      if (!identiteCanonique(corps.session_identity)) throw new ErreurService("identite_invalide");
      const refus = controleCanal(this.annuaire, methode, corps, this.#infoTicket(corps.ticket));
      if (refus) {
        this.supervision.consigner("canal_console_refus", { methode, ticket: typeof corps.ticket === "string" ? corps.ticket : null, reason: refus });
        throw new ErreurService(refus);
      }
      await this.#entree(methode, corps);
      const t = this.machine.tickets.get(corps.ticket);
      if (methode === "voter") {
        // EX-13.3 : notification du vote inscrit, sans identité de personne
        const D = condenseA({ decision: corps.decision, ticket: t.ticket, request_hash: t.request.request_hash, org_id: this.machine.org_id, journal_id: this.machine.journal_id });
        const empreinte = `${D.slice(2, 10)}\u2026${D.slice(-8)}`; // empreinte abrégée d'EX-9.18
        const vote = t.votes.at(-1);
        this.supervision.notifier({ kind: "vote_inscrit", ticket: t.ticket, decision: corps.decision, approver: corps.approver, digest: empreinte, at: vote?.at ?? null });
      }
      return { ticket: t.ticket, state: t.state };
    });
  }

  // -------------------------------------------------------------- jeu d'approbateurs (8.1 à 8.3)

  #politiqueVigueur() {
    const v = this.machine.enVigueur ? this.machine.version(this.machine.enVigueur) : null;
    return v?.approval?.rules?.approver_set ?? null;
  }

  #lectureNecessaire() {
    const pol = this.#politiqueVigueur();
    if (!this.lecteur || !pol || pol.source !== "registre") return false;
    if (!this.machine.pret(this.machine.enVigueur)) return true;
    for (const t of this.machine.tickets.values()) {
      if (!["ouvert", "seuil_atteint", "verification"].includes(t.state)) continue;
      if (t.approver_set === null || t.state === "verification" || t.set_reassigned) return true;
    }
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
   * Sondage du jeu (EX-8.4, EX-8.5) : lecture complète quand elle est
   * nécessaire (jeu de repli absent, ticket non figé ou en vérification),
   * sinon recherche des changements depuis la dernière hauteur vue ; puis
   * nouveau sondage après `set_poll_interval_ms`.
   */
  async #sonder(force = false) {
    if (this.arrete || !this.lecteur) return;
    const pol = this.#politiqueVigueur();
    this.lectureEnCours = (async () => {
      try {
        if (!pol || pol.source !== "registre") return;
        let lire = force || this.#lectureNecessaire();
        if (!lire) {
          // EX-8.5 : journaux de l'organisation au registre et du jeu épinglé (figé ou de repli)
          try {
            const H = await this.lecteur.hauteur();
            const fige = this.#ticketsOuverts().find((t) => t.approver_set)?.approver_set?.set ?? pol.set;
            if (this.derniereHauteur !== null) lire = await this.lecteur.changements(pol, fige, this.derniereHauteur, H);
            else lire = true;
            if (!lire) this.derniereHauteur = H;
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
        const r = await this.lecteur.lire(pol, precedents);
        await this.#executer(async () => {
          if (this.arrete) return;
          await this.#entree("jeu_lu", r).catch(() => {});
        });
        if (r.status === "lu" && r.jeu.set === pol.set) {
          this.setReadAt = ecrireHorodatage(this.horloge());
          this.derniereHauteur = r.jeu.height;
        }
        this.supervision.consigner("lecture_jeu", { status: r.status, cause: r.cause, height: r.jeu?.height ?? null, set: r.jeu?.set ?? null });
      } catch (e) {
        this.supervision.consigner("erreur", { kind: "lecture_jeu", message: e.message });
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

  /** Déclenche les minuteurs échus à l'instant de l'horloge du service (entrée `horloge`). */
  tic() {
    return this.#executer(() => this.#entree("horloge", {}));
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
    await this.supervision.vider();
    await this.magasin?.fermer();
  }
}
