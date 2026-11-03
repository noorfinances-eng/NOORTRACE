// Machine à états des tickets (CT-3 §7, §8.2 à §8.4, §10) : rapprochement,
// réservation, ouverture, gel et nouveau gel du jeu, votes, récusations,
// retraits, décompte et fenêtre de contestation, remises, acquittements,
// consommation, expiration par le noyau, minuteurs, fenêtres ouvertes.
//
// La machine est déterministe : elle ne lit aucune horloge ; chaque entrée
// porte son instant `at` (horloge du service), et les minuteurs échus avant
// une entrée sont déclenchés d'abord, dans l'ordre d'EX-7.7. Elle n'écrit
// rien : après chaque entrée, `prendreModifications()` dit ce qui a changé
// (tickets, fenêtres, état général), que le service persiste avant de rendre
// la réponse (EX-7.22). Elle se reconstruit de ses seuls documents
// (`exporter`, `Machine.restaurer`, EX-7.23).
//
// Un ticket est le document `ticket-v0` (`$defs/ticket`) ; une fenêtre est
// `$defs/fenetre_ouverte`. Les entrées sont celles de `$defs/entree`
// (annexe A.6) ; le service y ajoute, pour `ouvrir`, `request_event` et
// `arguments_piece` (12.4).

import { randomBytes } from "node:crypto";
import { decoderHorodatage, ecrireHorodatage } from "@noortrace/noyau";
import { IDS, registreSchemas } from "./schema.mjs";
import { cloner, egaliteJson, jcsIntegral, longueurPointsDeCode } from "./json.mjs";
import { evaluer as evaluerPolitique, fenetreDeMarque, finFenetre } from "./evaluation.mjs";
import { adresseDuVote, normaliserSignature } from "./signatures.mjs";
import { jeuDeclare, jeuStatique, jeuxEgaux } from "./jeux.mjs";
import { ErreurService } from "./erreurs.mjs";

const H = (ms) => ecrireHorodatage(ms);
const T = (s) => decoderHorodatage(s);

/** États où un ticket recueille les votes (EX-9.10). */
export const ETATS_COLLECTE = Object.freeze(["ouvert", "seuil_atteint", "verification"]);
/** États non décidés, comptés par le plafond d'EX-14.1. */
export const ETATS_NON_DECIDES = Object.freeze(["reserve", "ouvert", "seuil_atteint", "verification", "a_remettre"]);
/** États terminaux (7.3). */
export const ETATS_TERMINAUX = Object.freeze(["consomme", "clos", "abandonne"]);

// Ordre des minuteurs à instant égal (EX-7.7).
const ORDRE_MINUTEURS = ["echeance", "fin_contestation", "fin_reservation", "fin_reconnaissance", "escalade", "fin_fenetre"];

/** Raisons fixes d'une décision `expire` (EX-7.11). */
export const RAISONS_EXPIRE = Object.freeze({
  abandon: "reservation abandonnee avant l'ouverture",
  retrait: "echeance avancee par retrait",
  caduque: "decision non scellee avant l'echeance",
  illisible: "echeance atteinte, jeu d'approbateurs illisible",
  reassigne: "echeance atteinte, jeu reassigne",
  inatteignable: "echeance atteinte, seuil inatteignable",
  objection: "echeance atteinte, objection non levee",
  contestation: "echeance atteinte pendant la fenetre de contestation",
  autre: "echeance atteinte sans decision",
});

const ALPHABET32 = "abcdefghijklmnopqrstuvwxyz234567";

/**
 * Identifiant aléatoire de 65 bits (EX-7.1) : `apr-` suivi de 13 caractères
 * en base 32 minuscule.
 */
export function identifiantAleatoire() {
  const o = randomBytes(9);
  let x = BigInt("0x" + o.toString("hex")) & ((1n << 65n) - 1n);
  let s = "";
  for (let k = 0; k < 13; k++) {
    s = ALPHABET32[Number(x & 31n)] + s;
    x >>= 5n;
  }
  return `apr-${s}`;
}

/**
 * Clé de rapprochement d'une demande (EX-7.3) : chaque membre comparé octet
 * pour octet ; les arguments par leur JCS intégral. Gardée en mémoire
 * seulement (EX-7.24 : ni hachage ni condensé des arguments persisté).
 */
export function cleRapprochement(org_id, journal_id, d) {
  return JSON.stringify([
    org_id, journal_id, d.code.policy_version, d.tool_announced, jcsIntegral(d.arguments),
    d.delegation.launched_by, d.delegation.on_behalf_of, d.delegation.scope,
  ]);
}

function trierFenetres(f) {
  return f.sort((a, b) => (a.ticket < b.ticket ? -1 : a.ticket > b.ticket ? 1 : 0));
}

/**
 * Forme d'une entrée : `$defs/entree` de ticket-v0 ; le service y ajoute,
 * pour `evaluer`, une requête sans `evaluation` (calculée par la machine) et,
 * pour `ouvrir`, `request_event` et `arguments_piece` de 12.4.
 * @param {unknown} e
 */
export function entreeConforme(e) {
  if (e === null || typeof e !== "object" || Array.isArray(e)) return false;
  const reg = registreSchemas();
  const d = e.data;
  if (d === null || typeof d !== "object" || Array.isArray(d)) return false;
  if (e.kind === "evaluer") {
    const cles = Object.keys(e).sort().join(",") === "at,data,kind";
    const permis = Object.keys(d).every((k) => k === "request" || k === "evaluation");
    return cles && permis && typeof e.at === "string" && reg.estValide(`${IDS.ticket}#/$defs/requete_evaluer`, d.request) &&
      (d.evaluation === undefined || reg.estValide(`${IDS.ticket}#/$defs/evaluation`, d.evaluation));
  }
  if (e.kind === "ouvrir" && ("request_event" in d || "arguments_piece" in d)) {
    const { request_event: ev, arguments_piece: piece, ...reste } = d;
    if (ev !== undefined && (ev === null || typeof ev !== "object" || Array.isArray(ev))) return false;
    if (piece !== undefined && piece !== null && (typeof piece !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(piece))) return false;
    return reg.estValide(`${IDS.ticket}#/$defs/entree`, { kind: e.kind, at: e.at, data: reste });
  }
  return reg.estValide(`${IDS.ticket}#/$defs/entree`, e);
}

/**
 * Machine à états du service.
 */
export class Machine {
  /**
   * @param {{org_id: string, journal_id: string, identifiants?: {mode: "compteur"|"epoque"|"aleatoire", epoque?: string},
   *   max_open_tickets?: number, escalation?: {after_ms: number, notify: string}[], administrators?: string[],
   *   evenement?: (type: string, detail: object) => void}} p
   *   `evenement` : journal du service, notifications et alertes (hors chaîne, sans arguments)
   */
  constructor(p) {
    this.org_id = p.org_id;
    this.journal_id = p.journal_id;
    this.identifiants = p.identifiants ?? { mode: "aleatoire" };
    this.max_open_tickets = p.max_open_tickets ?? 20;
    this.escalation = p.escalation ?? [];
    this.administrators = p.administrators ?? [];
    this.evenement = p.evenement ?? (() => {});
    /** @type {Map<string, object>} versions chargées */
    this.versions = new Map();
    /** @type {string|null} */
    this.enVigueur = null;
    /** @type {Map<string, object>} jeu de repli par jeu épinglé (EX-8.3) */
    this.replis = new Map();
    this.compteur = 0;
    /** @type {Map<string, object>} */
    this.tickets = new Map();
    /** @type {object[]} */
    this.fenetres = [];
    /** @type {Map<string, string>} clé de rapprochement → ticket actif */
    this.cles = new Map();
    this.dernierAt = null;
    this.#reinitModifs();
    /** Remises calculées pendant l'entrée en cours, dans l'ordre (annexe A.6). */
    this.remisesDuPas = [];
  }

  #reinitModifs() {
    this.modifs = { tickets: new Set(), fenetres: false, meta: false, versions: false };
  }

  /** Ce qui a changé depuis le dernier appel (à persister, EX-7.22). */
  prendreModifications() {
    const m = this.modifs;
    this.#reinitModifs();
    return m;
  }

  // -------------------------------------------------------------- versions

  /**
   * Ajoute une version chargée.
   * @param {{policy_version: string, policy_sha256?: string|null, environment?: string,
   *   approval: {rules: object, mode?: string, expire_after_ms: number, timeout_ms?: number, hold_timeout_ms?: number},
   *   tools?: object[], requesters?: string[], approval_candidates?: string[]}} v
   */
  ajouterVersion(v) {
    this.versions.set(v.policy_version, cloner(v));
    this.modifs.versions = true;
  }

  /** Version chargée, ou null. */
  version(pv) {
    return this.versions.get(pv) ?? null;
  }

  /** Fixe la version en vigueur ; un changement ferme toutes les fenêtres (EX-4.12, EX-7.7). */
  fixerEnVigueur(pv) {
    if (this.enVigueur !== pv) {
      if (this.enVigueur !== null && this.fenetres.length) {
        for (const w of this.fenetres) this.evenement("fenetre_fermee", { ticket: w.ticket, cause: "changement_de_version" });
        this.fenetres = [];
        this.modifs.fenetres = true;
      }
      this.enVigueur = pv;
      this.modifs.meta = true;
    }
  }

  /** Jeu épinglé (`approver_set` de la politique) d'une version. */
  #politiqueJeu(pv) {
    return this.versions.get(pv)?.approval?.rules?.approver_set ?? null;
  }

  #politiqueSeparation(pv) {
    return this.versions.get(pv)?.approval?.rules?.separation ?? { self_approval: "permise", identities: [] };
  }

  /** Jeu de repli d'une version de jeu `registre`, ou null (EX-8.3). */
  repli(pv) {
    const pol = this.#politiqueJeu(pv);
    if (!pol || pol.source !== "registre") return null;
    return this.replis.get(pol.set) ?? null;
  }

  /** La version a-t-elle un jeu exploitable (statique, ou repli lu) ? EX-8.3. */
  pret(pv) {
    const pol = this.#politiqueJeu(pv);
    if (!pol) return false;
    return pol.source === "statique" || this.replis.has(pol.set);
  }

  /** Jeu déclaré d'une réponse `nouveau` (EX-12.6) : statique, ou repli courant. */
  jeuNouveau(pv) {
    const pol = this.#politiqueJeu(pv);
    if (pol.source === "statique") return jeuDeclare(jeuStatique(pol), pol, pv, null, false);
    const r = this.replis.get(pol.set);
    return r ? jeuDeclare(r, pol, pv, { height: r.height, block_hash: r.block_hash }, true) : null;
  }

  // -------------------------------------------------------------- entrées

  /**
   * Traite une entrée de 7.4 (`{ kind, at, data }`), après les minuteurs échus.
   * @param {{kind: string, at: string, data: object}} entree
   * @param {{evaluation?: object, lecture?: {debut: number, cible: {chain_id: number, registry: string, set: string}}}} [options]
   *   `lecture` (entrée `jeu_lu` du service) : instant où la lecture a commencé et jeu épinglé
   *   contre lequel elle a été faite (EX-8.1) ; sans lui (traces de l'annexe A.6), la
   *   lecture vaut pour chaque ticket et date de l'instant de l'entrée
   * @returns {{accepted: boolean, reason: string|null, data: object|null, response: object|null, remises: object[]}}
   */
  entree(entree, options = {}) {
    this.remisesDuPas = [];
    if (!entreeConforme(entree) || T(entree.at) === null) {
      return this.#refus(null, entree, "requete_invalide");
    }
    let at = T(entree.at);
    if (this.dernierAt !== null && at < this.dernierAt) at = this.dernierAt; // horloge qui recule : jamais d'entrée dans le passé
    this.avancer(at);
    // L'instant de la dernière entrée n'est persisté qu'avec un enregistrement
    // qui a un effet (le service joint l'état général à tout enregistrement) :
    // une entrée sans effet ne coûte aucune écriture (EX-7.20).
    this.dernierAt = at;
    const d = entree.data;
    try {
      switch (entree.kind) {
        case "charger": return this.#ok(this.#charger(at, d));
        case "evaluer": return this.#ok(this.#evaluer(at, d, options));
        case "ouvrir": return this.#ok(this.#ouvrir(at, d));
        case "jeu_lu": this.#jeuLu(at, d, options.lecture ?? null); return this.#ok(null);
        case "voter": this.#voter(at, d); return this.#ok(null);
        case "recuser": this.#recuser(at, d); return this.#ok(null);
        case "retirer": this.#retirer(at, d); return this.#ok(null);
        case "horloge": return this.#ok(null);
        case "acquitter": return this.#ok(this.#acquitter(at, d));
        case "consommer": return this.#ok(this.#consommer(at, d));
        case "expiration": return this.#ok(this.#expiration(at, d));
        default: return this.#refus(null, entree, "requete_invalide");
      }
    } catch (e) {
      if (e instanceof ErreurService) return { accepted: false, reason: e.code, data: e.data, response: null, remises: this.remisesDuPas };
      throw e;
    }
  }

  #ok(response) {
    return { accepted: true, reason: null, data: null, response, remises: this.remisesDuPas };
  }

  #refus(_t, _e, reason, data = {}) {
    return { accepted: false, reason, data, response: null, remises: this.remisesDuPas };
  }

  /** Refuse une entrée propre à un ticket : inscrite dans la trace du ticket (EX-7.8). */
  #refuser(t, at, input, data, reason, extra = {}) {
    if (t) {
      this.#inscrire(t, at, input, t.state, t.state, false, reason, data);
    }
    throw new ErreurService(reason, extra);
  }

  #inscrire(t, at, input, from, to, accepted, reason, data) {
    t.transitions.push({ at: H(at), input, from, to, accepted, reason, data: data === undefined ? null : cloner(data) });
    this.modifs.tickets.add(t.ticket);
  }

  #etat(t, at, input, vers, data) {
    const de = t.state;
    t.state = vers;
    this.#inscrire(t, at, input, de, vers, true, null, data);
    if (ETATS_TERMINAUX.includes(vers)) this.#effacer(t);
    this.#indexer(t);
  }

  /** Efface les arguments en clair d'un ticket terminé (EX-7.24). */
  #effacer(t) {
    t.request.arguments = null;
    t.request.retained_event = null;
    t.request.arguments_piece = null;
    if (t.opening) t.opening.scope.values = null;
  }

  #actif(t) {
    if (t.key_released) return false;
    if (ETATS_NON_DECIDES.includes(t.state)) return true;
    return ["approuve", "refuse", "expire"].includes(t.state);
  }

  #indexer(t) {
    for (const [c, id] of this.cles) if (id === t.ticket && !this.#actif(t)) this.cles.delete(c);
  }

  // -------------------------------------------------------------- minuteurs (7.6, EX-7.7)

  /** Minuteurs d'un ticket : [{ type, instant }]. */
  #minuteursTicket(t) {
    const m = [];
    if (t.state === "reserve") m.push({ type: "fin_reservation", instant: T(t.reserved_at) + t.expire_after_ms });
    if (ETATS_COLLECTE.includes(t.state)) {
      m.push({ type: "echeance", instant: T(t.deadline) });
      if (t.state === "seuil_atteint" && t.contest_end) m.push({ type: "fin_contestation", instant: T(t.contest_end) });
      if (t.escalations < this.escalation.length && t.request.request_ts) {
        m.push({ type: "escalade", instant: T(t.request.request_ts) + this.escalation[t.escalations].after_ms });
      }
    }
    if (t.state === "a_remettre" && t.deadline && t.current_remise) {
      const r = this.#remiseCourante(t);
      if (r && r.approval.decision !== "expire") m.push({ type: "echeance", instant: T(t.deadline) });
    }
    if (["approuve", "refuse", "expire"].includes(t.state) && t.recognize_until) {
      m.push({ type: "fin_reconnaissance", instant: T(t.recognize_until) });
    }
    return m;
  }

  /** Prochain minuteur échu au plus tard à `at`, dans l'ordre d'EX-7.7, ou null. */
  #prochain(at) {
    let meilleur = null;
    const plusTot = (c) =>
      !meilleur ||
      c.instant < meilleur.instant ||
      (c.instant === meilleur.instant &&
        (ORDRE_MINUTEURS.indexOf(c.type) < ORDRE_MINUTEURS.indexOf(meilleur.type) ||
          (c.type === meilleur.type && c.id < meilleur.id)));
    for (const t of this.tickets.values()) {
      if (ETATS_TERMINAUX.includes(t.state)) continue;
      for (const m of this.#minuteursTicket(t)) {
        const c = { ...m, id: t.ticket };
        if (c.instant <= at && plusTot(c)) meilleur = c;
      }
    }
    for (const w of this.fenetres) {
      const c = { type: "fin_fenetre", instant: T(w.end), id: w.ticket };
      if (c.instant <= at && plusTot(c)) meilleur = c;
    }
    return meilleur;
  }

  /** Instant du prochain minuteur (pour la planification du service), ou null. */
  prochainMinuteur() {
    const m = this.#prochain(Number.MAX_SAFE_INTEGER);
    return m ? m.instant : null;
  }

  /** Déclenche tous les minuteurs échus au plus tard à `at`. */
  avancer(at) {
    for (let n = 0; n < 1e6; n++) {
      const m = this.#prochain(at);
      if (!m) return;
      this.#declencher(m);
    }
    throw new Error("minuteurs : boucle sans fin");
  }

  #declencher(m) {
    if (m.type === "fin_fenetre") {
      this.fenetres = this.fenetres.filter((w) => !(w.ticket === m.id && T(w.end) === m.instant));
      this.modifs.fenetres = true;
      this.evenement("fenetre_fermee", { ticket: m.id, cause: "fin" });
      return;
    }
    const t = this.tickets.get(m.id);
    const at = m.instant;
    switch (m.type) {
      case "fin_reservation":
        t.key_released = true;
        this.#etat(t, at, "fin_reservation", "abandonne", null);
        break;
      case "echeance":
        if (t.state === "a_remettre") {
          // T13 : décision approuve ou refuse caduque, remplacée par expire
          this.#remettreExpire(t, at, RAISONS_EXPIRE.caduque, "echeance");
        } else {
          // T9
          this.#remettreExpire(t, at, this.#raisonEcheance(t), "echeance");
        }
        break;
      case "fin_contestation":
        // T7
        t.contest_end = null;
        t.computed_decision = { decision: "approuve", at: H(at) };
        this.#etat(t, at, "fin_contestation", "verification", null);
        this.#confirmationImmediate(t, at);
        break;
      case "fin_reconnaissance": {
        // T19
        if (t.state === "approuve" && t.consumed === null) {
          this.evenement("approbation_non_consommee", { ticket: t.ticket, served: t.served_at !== null });
        }
        this.#etat(t, at, "fin_reconnaissance", "clos", null);
        break;
      }
      case "escalade": {
        const etape = this.escalation[t.escalations];
        t.escalations += 1;
        this.#inscrire(t, at, "escalade", t.state, t.state, true, null, { notify: etape.notify });
        const votants = new Set(t.votes.filter((v) => v.status === "courant").map((v) => v.approver));
        this.evenement("notification", {
          kind: "escalade",
          ticket: t.ticket,
          tool: t.request.tool_announced,
          deadline: t.deadline,
          notify: etape.notify,
          approvers: etape.notify === "jeu" ? t.eligible.filter((a) => !votants.has(a)) : [],
          requester: etape.notify === "demandeur" ? t.request.delegation.launched_by : null,
        });
        break;
      }
      default:
        throw new Error(`minuteur inconnu : ${m.type}`);
    }
  }

  // -------------------------------------------------------------- charger

  #charger(at, d) {
    if (!this.versions.has(d.policy_version)) throw new ErreurService("politique_inconnue");
    this.fixerEnVigueur(d.policy_version);
    void at;
    return { policy_version: d.policy_version };
  }

  // -------------------------------------------------------------- evaluer (EX-7.6, EX-7.16, T1, T21)

  #evaluer(at, data, options) {
    const d = data.request;
    const v = this.versions.get(d.code.policy_version);
    if (!v) throw new ErreurService("politique_inconnue");
    if (v.approval.mode === "observation") {
      // EX-11.12 : EVALUER sans effet, ni rapprochement, ni ticket, ni consommation
      const e = data.evaluation ?? evaluerPolitique(v.approval.rules, d, this.fenetres, at);
      this.evenement("evaluation_observation", { policy_version: d.code.policy_version, rule: e.rule, decision: e.decision });
      return { rule: e.rule, decision: e.decision, ticket: null, ticket_state: null, approval: null, approver_set: null };
    }
    if (!this.pret(d.code.policy_version)) throw new ErreurService("non_pret");
    const cle = cleRapprochement(this.org_id, this.journal_id, d);
    const id = this.cles.get(cle);
    if (id !== undefined) {
      const t = this.tickets.get(id);
      if (this.#actif(t)) return this.#reemission(t, at);
      this.cles.delete(cle);
    }
    const e = options.evaluation ?? data.evaluation ?? evaluerPolitique(v.approval.rules, d, this.fenetres, at);
    if (e.decision === "a_approuver") {
      const n = [...this.tickets.values()].filter(
        (t) => ETATS_NON_DECIDES.includes(t.state) && t.request.delegation.launched_by === d.delegation.launched_by,
      ).length;
      if (n >= this.max_open_tickets) {
        this.evenement("plafond_atteint", { launched_by: d.delegation.launched_by, max_open_tickets: this.max_open_tickets });
        throw new ErreurService("plafond_atteint");
      }
      const t = this.#creer(at, d, e, v);
      this.cles.set(cle, t.ticket);
      return {
        rule: e.rule, decision: "a_approuver", ticket: t.ticket, ticket_state: "nouveau", approval: null,
        approver_set: this.jeuNouveau(d.code.policy_version),
      };
    }
    if (e.decision === "autorise") {
      const f = e.fenetre ?? fenetreDeMarque(e.rule)?.ticket ?? null;
      if (f !== null) this.#consommerFenetre(f);
    }
    return { rule: e.rule, decision: e.decision, ticket: null, ticket_state: null, approval: null, approver_set: null };
  }

  /** Consomme une unité de la fenêtre ouverte par `ticket` (EX-5.5) ; la retire épuisée (EX-5.6). */
  #consommerFenetre(ticket) {
    const w = this.fenetres.find((x) => x.ticket === ticket);
    if (!w) return;
    w.remaining -= 1;
    if (w.remaining <= 0) {
      this.fenetres = this.fenetres.filter((x) => x !== w);
      this.evenement("fenetre_fermee", { ticket, cause: "epuisee" });
    }
    this.modifs.fenetres = true;
  }

  #prochainIdentifiant() {
    if (this.identifiants.mode === "aleatoire") {
      let id;
      do id = identifiantAleatoire();
      while (this.tickets.has(id));
      return id;
    }
    this.compteur += 1;
    this.modifs.meta = true;
    const n = String(this.compteur).padStart(4, "0");
    return this.identifiants.mode === "epoque" ? `apr-${this.identifiants.epoque}-${n}` : `apr-${n}`;
  }

  #creer(at, d, e, v) {
    const pv = d.code.policy_version;
    const sep = this.#politiqueSeparation(pv);
    const id = sep.identities.find((x) => x.launched_by === d.delegation.launched_by);
    const t = {
      version: 0,
      ticket: this.#prochainIdentifiant(),
      org_id: this.org_id,
      journal_id: this.journal_id,
      state: "reserve",
      request: {
        tool_announced: d.tool_announced,
        tool_original: d.tool_original,
        server_alias: d.server_alias,
        class: d.class,
        delegation: cloner(d.delegation),
        arguments: cloner(d.arguments),
        rule: e.rule,
        policy_version: pv,
        request_hash: null,
        request_seq: null,
        request_ts: null,
        retained_event: null,
        arguments_piece: null,
      },
      key_released: false,
      reserved_at: H(at),
      deadline: null,
      expire_after_ms: v.approval.expire_after_ms,
      contest_ms: e.contest_ms ?? 0,
      opening: e.opening ? cloner(e.opening) : null,
      self_approval: sep.self_approval,
      requester_addresses: id ? [...id.addresses] : [],
      approver_set: null,
      effective_required: null,
      confirmation: null,
      set_reassigned: false,
      eligible: [],
      recused: [],
      votes: [],
      contest_end: null,
      computed_decision: null,
      remises: [],
      current_remise: null,
      sealed: null,
      served_at: null,
      consumed: null,
      recognize_until: null,
      escalations: 0,
      transitions: [],
    };
    this.tickets.set(t.ticket, t);
    this.#inscrire(t, at, "evaluer", null, "reserve", true, null, null);
    if (sep.self_approval === "interdite" && !id) {
      // EX-10.5 : séparation vide pour ce demandeur, signalée à la création
      this.evenement("separation_non_verifiable", { ticket: t.ticket, launched_by: d.delegation.launched_by });
    }
    return t;
  }

  #reemission(t, at) {
    const rule = t.request.rule;
    switch (t.state) {
      case "reserve":
        return { rule, decision: "a_approuver", ticket: t.ticket, ticket_state: "nouveau", approval: null, approver_set: this.jeuNouveau(t.request.policy_version) };
      case "approuve":
        if (t.served_at === null) {
          // T21 : approbation servie une fois, persistée avant la réponse
          t.served_at = H(at);
          this.#inscrire(t, at, "evaluer", "approuve", "approuve", true, null, null);
          return { rule, decision: "autorise", ticket: t.ticket, ticket_state: "approuve", approval: cloner(t.sealed.approval), approver_set: null };
        }
        return { rule, decision: "a_approuver", ticket: t.ticket, ticket_state: "en_attente", approval: null, approver_set: null };
      case "refuse":
      case "expire":
        return { rule, decision: "refuse", ticket: t.ticket, ticket_state: t.state, approval: cloner(t.sealed.approval), approver_set: null };
      default:
        return { rule, decision: "a_approuver", ticket: t.ticket, ticket_state: "en_attente", approval: null, approver_set: null };
    }
  }

  // -------------------------------------------------------------- ouvrir (T2, T4)

  #ouvrir(at, d) {
    const t = this.tickets.get(d.ticket);
    if (!t) throw new ErreurService("ticket_inconnu");
    const donnees = { ticket: d.ticket, request_hash: d.request_hash, request_seq: d.request_seq, request_ts: d.request_ts };
    const reponse = () => ({ ticket: t.ticket, state: t.state, deadline: t.deadline });
    if (t.request.request_hash !== null) {
      if (t.request.request_hash === d.request_hash) return reponse(); // EX-7.20
      this.#refuser(t, at, "ouvrir", donnees, "ticket_deja_ouvert", { request_hash: t.request.request_hash });
    }
    if (!(t.state === "reserve" || t.state === "abandonne") || T(d.request_ts) > at) {
      this.#refuser(t, at, "ouvrir", donnees, "requete_invalide");
    }
    t.request.request_hash = d.request_hash;
    t.request.request_seq = d.request_seq;
    t.request.request_ts = d.request_ts;
    t.deadline = H(T(d.request_ts) + t.expire_after_ms);
    if (t.state === "abandonne") {
      // T4 : ouvrir tardif ; décision expire sur le jeu de repli ; la clé n'est pas reprise
      this.#remettreExpire(t, at, RAISONS_EXPIRE.abandon, "ouvrir", donnees);
      return reponse();
    }
    // T2
    if (d.request_event !== undefined) t.request.retained_event = cloner(d.request_event);
    if (d.arguments_piece !== undefined) t.request.arguments_piece = d.arguments_piece;
    this.#etat(t, at, "ouvrir", "ouvert", donnees);
    const pol = this.#politiqueJeu(t.request.policy_version);
    // jeu statique figé aussitôt ; jeu registre : lecture demandée (8.2), notification au gel
    if (pol.source === "statique") this.#figer(t, jeuStatique(pol), at, null);
    else this.evenement("lecture_jeu_demandee", { ticket: t.ticket });
    return reponse();
  }

  // -------------------------------------------------------------- jeu (T5, T8, 8.2, 8.3)

  #eligibles(t) {
    if (!t.approver_set) return [];
    const exclus = new Set(t.recused);
    if (t.self_approval === "interdite") for (const a of t.requester_addresses) exclus.add(a);
    return t.approver_set.members.filter((m) => !exclus.has(m));
  }

  /** Gel ou nouveau gel du jeu (EX-8.4, EX-8.6). */
  #figer(t, jeu, at, donnees) {
    const avant = t.approver_set;
    t.approver_set = cloner(jeu);
    t.effective_required = Math.max(t.effective_required ?? 0, jeu.threshold.required);
    t.confirmation = jeu.height === null ? null : { height: jeu.height, block_hash: jeu.block_hash };
    const eligAvant = t.eligible.length;
    t.eligible = this.#eligibles(t);
    const ajoutes = avant ? jeu.members.filter((m) => !avant.members.includes(m)) : [];
    if (avant) {
      // votes des adresses qui ne sont plus membres : écartés (hors_jeu)
      for (const v of t.votes) {
        if (v.status === "courant" && !jeu.members.includes(v.approver)) {
          v.status = "ecarte";
          v.cause = "hors_jeu";
        }
      }
    }
    if (donnees) this.#inscrire(t, at, "jeu_lu", t.state, t.state, true, null, { ...donnees, added_members: ajoutes });
    else this.modifs.tickets.add(t.ticket);
    if (!avant) {
      // EX-7.12 : notification des membres éligibles du jeu figé, sans les arguments
      this.evenement("notification", {
        kind: "ouverture", ticket: t.ticket, tool: t.request.tool_announced, deadline: t.deadline, approvers: [...t.eligible],
      });
    }
    if (ajoutes.length) this.evenement("notification", { kind: "membres_ajoutes", ticket: t.ticket, added_members: ajoutes, approvers: [...t.eligible] });
    if (t.eligible.length < t.effective_required && (eligAvant >= t.effective_required || !avant)) {
      this.evenement("seuil_inatteignable", { ticket: t.ticket, eligible: t.eligible.length, effective_required: t.effective_required });
    }
    if (avant) {
      if (t.state === "seuil_atteint") {
        // le nouveau gel annule la fenêtre de contestation (EX-8.6)
        t.contest_end = null;
        this.#etat(t, at, "jeu_lu", "ouvert", null);
      }
      this.#decompter(t, at, "jeu_lu");
    }
  }

  #jeuLu(at, d, lecture) {
    // Une lecture est faite contre un jeu épinglé (EX-8.1 : chaîne, registre, jeu) ; elle ne
    // vaut que pour les tickets dont la version épingle ce jeu (EX-7.21 : un ticket garde
    // le jeu de sa version), et pour le repli si la version en vigueur l'épingle.
    const cible = lecture?.cible ?? null;
    const memeCible = (pol) =>
      cible === null ||
      (pol.chain_id === cible.chain_id && pol.registry.toLowerCase() === cible.registry.toLowerCase() && pol.set.toLowerCase() === cible.set.toLowerCase());
    // Instant de la lecture : celui où elle a commencé (EX-8.7 : « lecture faite après
    // l'instant où la décision a été calculée ») ; à défaut, celui de l'entrée.
    const instantLecture = lecture?.debut ?? at;
    // jeu de repli : dernière lecture réussie du jeu épinglé de la version en vigueur (EX-8.3)
    const polVigueur = this.enVigueur ? this.#politiqueJeu(this.enVigueur) : null;
    if (d.status === "lu" && polVigueur?.source === "registre" && memeCible(polVigueur) && d.jeu.set === polVigueur.set) {
      this.replis.set(polVigueur.set, cloner(d.jeu));
      this.modifs.meta = true;
    }
    const ids = [...this.tickets.values()].filter((t) => ETATS_COLLECTE.includes(t.state)).map((t) => t.ticket).sort();
    for (const id of ids) {
      const t = this.tickets.get(id);
      const pol = this.#politiqueJeu(t.request.policy_version);
      if (!pol || pol.source !== "registre" || !memeCible(pol)) continue;
      const donnees = { status: d.status, jeu: d.jeu, cause: d.cause };
      if (d.status === "illisible" || d.jeu.set !== pol.set) {
        if (d.cause === "jeu_non_attendu" || d.status === "lu") t.set_reassigned = true;
        this.#inscrire(t, at, "jeu_lu", t.state, t.state, true, null, donnees);
        continue;
      }
      t.set_reassigned = false;
      if (t.approver_set === null) {
        this.#figer(t, d.jeu, at, donnees);
      } else if (!jeuxEgaux(t.approver_set, d.jeu)) {
        this.#figer(t, d.jeu, at, donnees);
      } else {
        t.confirmation = { height: d.jeu.height, block_hash: d.jeu.block_hash };
        this.#inscrire(t, at, "jeu_lu", t.state, t.state, true, null, donnees);
        if (t.state === "verification" && instantLecture >= T(t.computed_decision.at)) this.#remettreDecision(t, at, "jeu_lu");
      }
    }
  }

  /** Confirmation immédiate d'un jeu statique (EX-8.7) : T8 suit l'entrée en verification. */
  #confirmationImmediate(t, at) {
    const pol = this.#politiqueJeu(t.request.policy_version);
    if (t.state === "verification" && pol?.source === "statique") this.#remettreDecision(t, at, "jeu_lu");
  }

  // -------------------------------------------------------------- votes (T6, EX-9.10, EX-7.26)

  #ticketPourVote(at, d, input) {
    const t = this.tickets.get(d.ticket);
    if (!t) throw new ErreurService("ticket_inconnu");
    if (t.state === "reserve") this.#refuser(t, at, input, d, "ticket_non_ouvert");
    if (!ETATS_COLLECTE.includes(t.state)) this.#refuser(t, at, input, d, "ticket_clos_aux_votes");
    if (t.approver_set === null) this.#refuser(t, at, input, d, "jeu_non_fige");
    return t;
  }

  #voter(at, d) {
    const t = this.#ticketPourVote(at, d, "voter");
    const sig = normaliserSignature(d.signature);
    const champs = { decision: d.decision, ticket: t.ticket, request_hash: t.request.request_hash, org_id: this.org_id, journal_id: this.journal_id };
    if (sig === null || adresseDuVote(champs, sig) !== d.approver) this.#refuser(t, at, "voter", d, "signature_invalide");
    if (!t.approver_set.members.includes(d.approver)) this.#refuser(t, at, "voter", d, "hors_jeu");
    if (t.self_approval === "interdite" && t.requester_addresses.includes(d.approver)) this.#refuser(t, at, "voter", d, "auto_approbation");
    if (t.recused.includes(d.approver)) this.#refuser(t, at, "voter", d, "recuse");
    if (d.reason !== null && longueurPointsDeCode(d.reason) > 1024) this.#refuser(t, at, "voter", d, "motif_trop_long");
    const courant = t.votes.find((v) => v.approver === d.approver && v.status === "courant");
    if (courant && courant.decision === d.decision) this.#refuser(t, at, "voter", d, "vote_identique");
    if (courant) courant.status = "remplace";
    if (d.decision === "approuve") {
      // un vote approuve de son auteur lève son objection (EX-10.8)
      for (const v of t.votes) if (v.approver === d.approver && v.objection && v.objection.lifted_at === null) v.objection.lifted_at = H(at);
    }
    t.votes.push({
      at: H(at),
      approver: d.approver,
      decision: d.decision,
      signature: sig,
      reason: d.reason,
      session_identity: d.session_identity,
      status: "courant",
      cause: null,
      objection: d.decision === "refuse" && t.contest_ms > 0 ? { lifted_at: null } : null,
    });
    this.#inscrire(t, at, "voter", t.state, t.state, true, null, { ...d, signature: sig });
    this.evenement("vote_inscrit", { ticket: t.ticket, approver: d.approver, decision: d.decision });
    this.#decompter(t, at, "voter");
  }

  #recuser(at, d) {
    const t = this.#ticketPourVote(at, d, "recuser");
    if (!t.approver_set.members.includes(d.approver)) this.#refuser(t, at, "recuser", d, "hors_jeu");
    if (t.self_approval === "interdite" && t.requester_addresses.includes(d.approver)) this.#refuser(t, at, "recuser", d, "auto_approbation");
    if (t.recused.includes(d.approver)) this.#refuser(t, at, "recuser", d, "recuse");
    t.recused.push(d.approver);
    const eligAvant = t.eligible.length;
    t.eligible = this.#eligibles(t);
    for (const v of t.votes) {
      if (v.approver === d.approver && v.status === "courant" && v.decision === "approuve") {
        v.status = "ecarte";
        v.cause = "recuse";
      }
    }
    this.#inscrire(t, at, "recuser", t.state, t.state, true, null, d);
    if (eligAvant >= t.effective_required && t.eligible.length < t.effective_required) {
      this.evenement("seuil_inatteignable", { ticket: t.ticket, eligible: t.eligible.length, effective_required: t.effective_required });
    }
    this.#decompter(t, at, "recuser");
  }

  #retirer(at, d) {
    const t = this.tickets.get(d.ticket);
    if (!t) throw new ErreurService("ticket_inconnu");
    if (t.state === "reserve") this.#refuser(t, at, "retirer", d, "ticket_non_ouvert");
    if (!ETATS_COLLECTE.includes(t.state)) this.#refuser(t, at, "retirer", d, "ticket_clos_aux_votes");
    if (d.by !== t.request.delegation.launched_by && !this.administrators.includes(d.by)) {
      this.#refuser(t, at, "retirer", d, "retrait_non_autorise");
    }
    // T10 : échéance avancée, décision expire ; le motif libre reste dans la trace
    t.deadline = H(at);
    this.#remettreExpire(t, at, RAISONS_EXPIRE.retrait, "retirer", d);
  }

  // -------------------------------------------------------------- décompte (EX-7.27)

  #decompter(t, at, input) {
    if (!ETATS_COLLECTE.includes(t.state) || t.approver_set === null) return;
    const membres = new Set(t.approver_set.members);
    const elig = new Set(t.eligible);
    const recuses = new Set(t.recused);
    const courants = t.votes.filter((v) => v.status === "courant" && membres.has(v.approver));
    const a = courants.filter((v) => v.decision === "approuve" && elig.has(v.approver)).length;
    const r = courants.filter((v) => v.decision === "refuse" && (elig.has(v.approver) || recuses.has(v.approver))).length;
    const seuil = t.effective_required;
    const C = t.contest_ms;
    const O = t.votes.some((v) => v.objection && v.objection.lifted_at === null);
    const verifier = (decision) => {
      if (t.state === "verification" && t.computed_decision?.decision === decision) return;
      t.contest_end = null;
      t.computed_decision = { decision, at: H(at) };
      this.#etat(t, at, input, "verification", null);
      this.#confirmationImmediate(t, at);
    };
    if (r >= seuil) return verifier("refuse");
    if (a >= seuil && C === 0) return verifier("approuve");
    if (a >= seuil && C > 0 && !O) {
      if (t.state === "seuil_atteint") return;
      if (t.state === "verification" && t.computed_decision?.decision === "approuve") return;
      t.computed_decision = null;
      t.contest_end = H(at + C);
      this.#etat(t, at, input, "seuil_atteint", null);
      return;
    }
    if (t.state !== "ouvert") {
      t.contest_end = null;
      t.computed_decision = null;
      this.#etat(t, at, input, "ouvert", null);
    }
  }

  // -------------------------------------------------------------- remises (T8, T9, T10, T13, T4 ; 12.5)

  #remiseCourante(t) {
    return t.remises.find((x) => x.remise.remise_id === t.current_remise)?.remise ?? null;
  }

  #presenter(t, at, approval, jeuRemise, input, donnees) {
    const n = t.remises.length + 1;
    const remise = { remise_id: `${t.ticket}/${n}`, ticket: t.ticket, approval, approver_set: jeuRemise };
    t.remises.push({ remise, computed_at: H(at) });
    t.current_remise = remise.remise_id;
    t.computed_decision = null;
    t.contest_end = null;
    if (t.state === "a_remettre") this.#inscrire(t, at, input, "a_remettre", "a_remettre", true, null, donnees);
    else this.#etat(t, at, input, "a_remettre", donnees);
    this.remisesDuPas.push(cloner(remise));
  }

  /** T8 : remise de la décision calculée, jeu confirmé (EX-7.28, EX-8.7). */
  #remettreDecision(t, at, input) {
    const decision = t.computed_decision.decision;
    const seuil = t.effective_required;
    const elig = new Set(t.eligible);
    const recuses = new Set(t.recused);
    const comptes = t.votes.filter(
      (v) => v.status === "courant" && v.decision === decision && t.approver_set.members.includes(v.approver) &&
        (elig.has(v.approver) || (decision === "refuse" && recuses.has(v.approver))),
    );
    const retenus = comptes.slice(0, seuil);
    const pv = t.request.policy_version;
    const pol = this.#politiqueJeu(pv);
    const jeu = jeuDeclare(t.approver_set, pol, pv, t.confirmation, false);
    const approval = {
      decision,
      ticket: t.ticket,
      request_hash: t.request.request_hash,
      threshold: cloner(t.approver_set.threshold),
      approvers: retenus.map((v) => v.approver),
      signatures: retenus.map((v) => v.signature),
      reason: retenus[seuil - 1]?.reason ?? null,
    };
    this.#presenter(t, at, approval, jeu, input, null);
  }

  /** Remise `expire` (T4, T9, T10, T13) : jeu figé et dernière confirmation, ou repli. */
  #remettreExpire(t, at, raison, input, donnees) {
    const pv = t.request.policy_version;
    const pol = this.#politiqueJeu(pv);
    let jeu;
    if (t.approver_set) jeu = jeuDeclare(t.approver_set, pol, pv, t.confirmation, false);
    else if (pol.source === "statique") jeu = jeuDeclare(jeuStatique(pol), pol, pv, null, false);
    else {
      const r = this.replis.get(pol.set);
      jeu = r ? jeuDeclare(r, pol, pv, { height: r.height, block_hash: r.block_hash }, true) : null;
    }
    if (!jeu) {
      // aucun jeu à déclarer : le noyau expirera seul avec le jeu de la réponse nouveau (EX-12.11)
      this.evenement("alerte", { kind: "expire_sans_jeu", ticket: t.ticket });
      t.current_remise = null;
      if (t.state !== "a_remettre") this.#etat(t, at, input, "a_remettre", donnees ?? null);
      return;
    }
    const approval = {
      decision: "expire",
      ticket: t.ticket,
      request_hash: t.request.request_hash,
      threshold: cloner(jeu.threshold),
      approvers: [],
      signatures: [],
      reason: raison,
    };
    this.#presenter(t, at, approval, jeu, input, donnees ?? null);
  }

  /** Cause d'une expiration à l'échéance (EX-7.11), par ordre de priorité. */
  #raisonEcheance(t) {
    if (t.approver_set === null) return RAISONS_EXPIRE.illisible;
    if (t.set_reassigned) return RAISONS_EXPIRE.reassigne;
    if (t.eligible.length < t.effective_required) return RAISONS_EXPIRE.inatteignable;
    if (t.votes.some((v) => v.objection && v.objection.lifted_at === null)) return RAISONS_EXPIRE.objection;
    if (t.state === "seuil_atteint") return RAISONS_EXPIRE.contestation;
    return RAISONS_EXPIRE.autre;
  }

  // -------------------------------------------------------------- acquitter (T11 à T16, T20)

  #acquitter(at, d) {
    const t = this.tickets.get(d.ticket);
    if (!t) throw new ErreurService("ticket_inconnu");
    const reponse = () => ({ ticket: t.ticket, state: t.state });
    const deja = t.transitions.some((x) => x.input === "acquitter" && x.accepted && egaliteJson(x.data, d));
    if (deja) return reponse(); // EX-7.20
    const presentee = t.remises.find((x) => x.remise.remise_id === d.remise_id)?.remise ?? null;
    const courante = t.state === "a_remettre" && t.current_remise === d.remise_id;
    const E = t.expire_after_ms;
    const approvalConforme = (a, decision) =>
      a !== null && a.ticket === t.ticket && a.decision === decision && a.at === d.at;
    if (d.result === "scelle") {
      if (
        t.state !== "a_remettre" || !presentee || d.decision !== presentee.approval.decision ||
        !approvalConforme(d.approval, d.decision) || d.approval.request_hash !== presentee.approval.request_hash ||
        d.seq === null || d.hash === null || d.at === null || d.held === null
      ) {
        this.#refuser(t, at, "acquitter", d, "requete_invalide");
      }
      // T11
      t.sealed = { decision: d.decision, seq: d.seq, hash: d.hash, at: d.at, approval: cloner(d.approval) };
      t.current_remise = null;
      t.recognize_until = H(T(d.at) + E);
      if (d.decision === "approuve" && d.held === true) t.served_at = H(at);
      this.#etat(t, at, "acquitter", d.decision, d);
      if (d.decision === "approuve" && t.opening) this.#ouvrirFenetre(t, at, d.at);
      return reponse();
    }
    if (!courante) {
      // remise qui n'est plus la remise courante : sans effet (7.5)
      this.#inscrire(t, at, "acquitter", t.state, t.state, true, null, d);
      return reponse();
    }
    if (d.result === "temporaire") {
      // T12 : re-présentation au plus tôt timeout_ms plus tard (planifiée par le service)
      this.#inscrire(t, at, "acquitter", t.state, t.state, true, null, d);
      return reponse();
    }
    // result refuse
    if (d.reason === "ticket_deja_decide") {
      if (d.approval === null || !approvalConforme(d.approval, d.decision) || d.seq === null || d.hash === null) {
        this.#refuser(t, at, "acquitter", d, "requete_invalide");
      }
      if (d.approval.request_hash === t.request.request_hash) {
        // T14 : alignement sur le noyau, seul scelleur
        t.sealed = { decision: d.decision, seq: d.seq, hash: d.hash, at: d.at, approval: cloner(d.approval) };
        t.current_remise = null;
        t.recognize_until = H(T(d.at) + E);
        this.#etat(t, at, "acquitter", d.decision, d);
      } else {
        // T20 : décision d'une autre demande sous le même identifiant
        t.current_remise = null;
        t.key_released = true;
        this.evenement("alerte", { kind: "identifiant_en_collision", ticket: t.ticket });
        this.#etat(t, at, "acquitter", "clos", d);
      }
      return reponse();
    }
    if (d.reason === "echeance_depassee") {
      // T15 : la remise expire de T13 sera présentée
      this.#inscrire(t, at, "acquitter", t.state, t.state, true, null, d);
      return reponse();
    }
    // T16 : défaut du service
    this.evenement("alerte", { kind: "remise_refusee", ticket: t.ticket, remise_id: d.remise_id, reason: d.reason });
    const remise = this.#remiseCourante(t);
    t.current_remise = null;
    if (d.reason === "ticket_inconnu") {
      t.key_released = true;
      this.#etat(t, at, "acquitter", "abandonne", d);
      return reponse();
    }
    if (remise.approval.decision === "expire") {
      this.#inscrire(t, at, "acquitter", t.state, t.state, true, null, d);
      return reponse();
    }
    for (const v of t.votes) {
      if (v.status === "courant" && remise.approval.approvers.includes(v.approver) && v.decision === remise.approval.decision) {
        v.status = "ecarte";
        v.cause = "remise_refusee";
      }
    }
    this.#etat(t, at, "acquitter", "ouvert", d);
    this.#decompter(t, at, "acquitter");
    return reponse();
  }

  /** Ouverture de la fenêtre d'un ticket ouvrant à l'acquittement du scellement (EX-5.4, T11). */
  #ouvrirFenetre(t, at, approvalAt) {
    const o = t.opening;
    if (o.scope.policy_version !== this.enVigueur) return;
    const end = finFenetre(approvalAt, o.duration_ms);
    if (!(T(end) > at)) return;
    this.fenetres = this.fenetres.filter((w) => !egaliteJson(w.scope, o.scope));
    this.fenetres.push({ scope: cloner(o.scope), start: approvalAt, end, remaining: o.max_calls, ticket: t.ticket });
    trierFenetres(this.fenetres);
    this.modifs.fenetres = true;
    this.evenement("fenetre_ouverte", { ticket: t.ticket, start: approvalAt, end, max_calls: o.max_calls });
  }

  // -------------------------------------------------------------- consommer (T18, T22)

  #consommer(at, d) {
    const t = this.tickets.get(d.ticket);
    if (!t) throw new ErreurService("ticket_inconnu");
    const donnees = { seq: d.seq, hash: d.hash };
    if (t.consumed !== null) {
      if (egaliteJson(t.consumed, donnees)) return { ticket: t.ticket, state: t.state }; // EX-7.20
      this.#refuser(t, at, "consommer", d, "requete_invalide");
    }
    if (t.state === "approuve") {
      t.consumed = donnees;
      this.#etat(t, at, "consommer", "consomme", d);
      return { ticket: t.ticket, state: "consomme" };
    }
    if (t.state === "clos" && t.served_at !== null && t.sealed?.decision === "approuve") {
      // T22 : consommation tardive
      t.consumed = donnees;
      this.#inscrire(t, at, "consommer", "clos", "clos", true, null, d);
      this.evenement("alerte", { kind: "consommation_tardive", ticket: t.ticket });
      return { ticket: t.ticket, state: "clos" };
    }
    this.#refuser(t, at, "consommer", d, "requete_invalide");
  }

  // -------------------------------------------------------------- expiration par le noyau (T17)

  #expiration(at, d) {
    const t = this.tickets.get(d.ticket);
    if (!t) throw new ErreurService("ticket_inconnu");
    const a = d.approval;
    if (t.sealed !== null) {
      const meme = t.sealed.decision === "expire" && t.sealed.seq === d.seq && t.sealed.hash === d.hash && t.sealed.at === d.at &&
        egaliteJson(t.sealed.approval, a);
      if (meme) return { ticket: t.ticket, state: t.state }; // EX-7.20
      this.#refuser(t, at, "expiration", d, "requete_invalide");
    }
    const admis = ["reserve", "ouvert", "seuil_atteint", "verification", "a_remettre", "abandonne"];
    if (
      !admis.includes(t.state) || a.ticket !== t.ticket || a.decision !== "expire" || a.at !== d.at ||
      (t.request.request_hash !== null && a.request_hash !== t.request.request_hash)
    ) {
      this.#refuser(t, at, "expiration", d, "requete_invalide");
    }
    if (t.request.request_hash === null) t.request.request_hash = a.request_hash;
    t.sealed = { decision: "expire", seq: d.seq, hash: d.hash, at: d.at, approval: cloner(a) };
    t.current_remise = null;
    t.computed_decision = null;
    t.contest_end = null;
    t.recognize_until = H(T(d.at) + t.expire_after_ms);
    this.#etat(t, at, "expiration", "expire", d);
    return { ticket: t.ticket, state: "expire" };
  }

  // -------------------------------------------------------------- vues

  /** États des tickets connus (annexe A.6). */
  etats() {
    const r = {};
    for (const id of [...this.tickets.keys()].sort()) r[id] = this.tickets.get(id).state;
    return r;
  }

  /** Copie des fenêtres ouvertes, triées par ticket. */
  copieFenetres() {
    return trierFenetres(cloner(this.fenetres));
  }

  /** Remises à livrer : tickets en a_remettre avec une remise courante, dans l'ordre de leur calcul. */
  remisesCourantes() {
    const r = [];
    for (const t of this.tickets.values()) {
      if (t.state !== "a_remettre" || !t.current_remise) continue;
      const x = t.remises.find((y) => y.remise.remise_id === t.current_remise);
      if (x) r.push({ remise: cloner(x.remise), computed_at: x.computed_at });
    }
    return r.sort((a, b) => T(a.computed_at) - T(b.computed_at) || (a.remise.ticket < b.remise.ticket ? -1 : 1));
  }

  /** Nombre de tickets non décidés (EX-12.12). */
  ticketsOuverts() {
    return [...this.tickets.values()].filter((t) => ETATS_NON_DECIDES.includes(t.state)).length;
  }

  // -------------------------------------------------------------- persistance (EX-7.22, EX-7.23)

  /** Versions chargées, persistées à part (elles ne changent qu'à `charger`). */
  versionsChargees() {
    return [...this.versions.values()].map(cloner);
  }

  /** État général persisté (hors versions, tickets et fenêtres). */
  meta() {
    return {
      en_vigueur: this.enVigueur,
      replis: [...this.replis.entries()].map(([set, jeu]) => ({ set, jeu: cloner(jeu) })),
      compteur: this.compteur,
      identifiants: cloner(this.identifiants),
      dernier_at: this.dernierAt === null ? null : H(this.dernierAt),
    };
  }

  /** Documents persistés : état général, tickets (`ticket-v0`), fenêtres. */
  exporter() {
    return { meta: this.meta(), versions: this.versionsChargees(), tickets: [...this.tickets.values()].map(cloner), fenetres: this.copieFenetres() };
  }

  /**
   * Reconstruit une machine de ses seuls documents (EX-7.23) : la clé de
   * rapprochement est recalculée des arguments en clair des tickets actifs.
   * @param {ConstructorParameters<typeof Machine>[0]} p
   * @param {{meta: object, versions: object[], tickets: object[], fenetres: object[]}} docs
   */
  static restaurer(p, docs) {
    const m = new Machine(p);
    const meta = docs.meta;
    if (meta) {
      m.enVigueur = meta.en_vigueur ?? null;
      for (const { set, jeu } of meta.replis ?? []) m.replis.set(set, cloner(jeu));
      m.compteur = meta.compteur ?? 0;
      if (meta.identifiants && p.identifiants === undefined) m.identifiants = cloner(meta.identifiants);
      m.dernierAt = meta.dernier_at ? T(meta.dernier_at) : null;
    }
    for (const v of docs.versions ?? []) m.versions.set(v.policy_version, cloner(v));
    for (const t of docs.tickets ?? []) m.tickets.set(t.ticket, cloner(t));
    m.fenetres = trierFenetres(cloner(docs.fenetres ?? []));
    for (const t of m.tickets.values()) {
      if (!m.#actif(t) || t.request.arguments === null) continue;
      const d = { ...t.request, code: { policy_version: t.request.policy_version } };
      m.cles.set(cleRapprochement(m.org_id, m.journal_id, d), t.ticket);
    }
    m.#reinitModifs();
    return m;
  }
}
