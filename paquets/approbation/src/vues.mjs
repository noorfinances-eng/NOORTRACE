// Ce que le canal de la console sert en lecture (CT-3 12.9) : vue d'un
// ticket (`consulter`, EX-12.14, EX-12.15 ; `$defs/vue_ticket` de
// `console-approbation-v0`), liste des tickets (`tickets`, EX-12.14,
// EX-12.21 ; `$defs/reponse_tickets` de `console-service-v0`), informations
// de ticket du contrôle du canal (`controleCanal`), effets prévus (gabarit de
// CT-2 EX-7.6 évalué avant l'exécution, avec `unresolved`).
//
// Tout vient des documents `ticket-v0` de la machine, de la version de
// politique chargée du ticket et de l'annuaire ; rien n'est gardé à part.

import { decoderHorodatage, ecrireHorodatage, decoderBase64Canonique } from "@noortrace/noyau";
import { condenseA } from "./signatures.mjs";
import { jeuDeclare, jeuStatique } from "./jeux.mjs";
import { cloner, comparerChaines, jcsIntegral, lireJsonStrict } from "./json.mjs";
import { ETATS_NON_DECIDES } from "./tickets.mjs";
import { entreeActive, adresseActive } from "./annuaire.mjs";

const T = (s) => decoderHorodatage(s);
const H = (ms) => ecrireHorodatage(ms);

/** Nombre maximal de tickets de `related` (EX-12.21). */
export const RELATED_MAX = 20;

/**
 * Membres que le contrôle de `consulter` tient pour éligibles (EX-12.14) :
 * `eligible` du ticket après le gel ; avant le gel, les membres du jeu de
 * repli de sa version (jeu statique de la politique pour une source
 * `statique`), hors adresses du demandeur sous `interdite` (10.1).
 * @param {import("./tickets.mjs").Machine} machine
 * @param {object} t ticket
 */
export function eligiblesPourLecture(machine, t) {
  if (t.approver_set !== null) return [...t.eligible];
  const pol = machine.version(t.request.policy_version)?.approval?.rules?.approver_set ?? null;
  let membres = [];
  if (pol?.source === "statique") membres = jeuStatique(pol).members;
  else if (pol?.source === "registre") membres = machine.repli(t.request.policy_version)?.members ?? [];
  const exclus = t.self_approval === "interdite" ? new Set(t.requester_addresses) : new Set();
  return membres.filter((m) => !exclus.has(m));
}

/**
 * Ticket vu par `controleCanal` : `{ launched_by, eligible }`, ou null pour
 * un ticket inconnu de l'organisation.
 */
export function infoCanal(machine, id) {
  const t = typeof id === "string" ? machine.tickets.get(id) : undefined;
  return t ? { launched_by: t.request.delegation.launched_by, eligible: eligiblesPourLecture(machine, t) } : null;
}

/**
 * La session voit-elle le ticket dans `tickets` (EX-12.14) : administrateur,
 * adresse active de son entrée active éligible, ou alias de demandeur de son
 * entrée égal au `launched_by` du ticket ?
 */
export function ticketVisible(machine, annuaire, session, t) {
  if (annuaire.administrators.includes(session)) return true;
  const e = entreeActive(annuaire, session);
  if (e === null) return false;
  const a = adresseActive(e);
  if (a !== null && eligiblesPourLecture(machine, t).includes(a)) return true;
  return e.requester_identities.includes(t.request.delegation.launched_by);
}

/** Membres du jeu figé courant absents du premier jeu figé du ticket (EX-8.6, EX-12.14, EX-13.40). */
export function membresAjoutes(t) {
  if (t.approver_set === null) return [];
  const gel = t.transitions.find((x) => x.input === "jeu_lu" && x.accepted && x.data && Array.isArray(x.data.added_members) && x.data.jeu);
  if (!gel) return [];
  const premiers = new Set(gel.data.jeu.members.map((m) => m.toLowerCase()));
  return t.approver_set.members.filter((m) => !premiers.has(m)).sort();
}

/** État de la fenêtre de contestation (`contest` de la vue, EX-10.9, EX-12.14, EX-12.21). */
export function etatContestation(t) {
  const objections = t.votes
    .filter((v) => v.objection && v.objection.lifted_at === null)
    .map((v) => ({ approver: v.approver, at: v.at }));
  // Dernier instant où le seuil peut être atteint pour que la fenêtre finisse
  // avant l'échéance : échéance − contest_ms − 1 ms (l'échéance passe avant la
  // fin de fenêtre au même instant, EX-7.7, EX-10.9).
  const last = t.contest_ms > 0 && t.deadline !== null ? H(T(t.deadline) - t.contest_ms - 1) : null;
  return { window_end: t.contest_end, objections, last_threshold_at: last };
}

/** Votes courants comptés (`votes_approuve`, `votes_refuse`, EX-7.27). */
function compter(t, decision) {
  return t.votes.filter((v) => v.status === "courant" && v.decision === decision).length;
}

/** Ligne d'un ticket de `reponse_tickets` (EX-12.14, EX-12.21). */
export function ligneTicket(t) {
  return {
    ticket: t.ticket,
    state: t.state,
    tool_announced: t.request.tool_announced,
    launched_by: t.request.delegation.launched_by,
    deadline: t.deadline,
    votes_approuve: compter(t, "approuve"),
    votes_refuse: compter(t, "refuse"),
    effective_required: t.effective_required,
    contest_ms: t.contest_ms,
    contest: etatContestation(t),
  };
}

/**
 * Réponse de `tickets` (EX-12.14, EX-12.21), contrôles faits par l'appelant.
 * Tickets non décidés (`reserve` à `a_remettre`, EX-14.1) que la session
 * voit, triés par identifiant ; avec `related_to`, `related`.
 * @param {{machine: object, annuaire: object, session: string, relatedTo?: string, maintenant: number}} p
 */
export function reponseTickets(p) {
  const tickets = [...p.machine.tickets.values()]
    .filter((t) => ETATS_NON_DECIDES.includes(t.state) && ticketVisible(p.machine, p.annuaire, p.session, t))
    .sort((a, b) => comparerChaines(a.ticket, b.ticket))
    .map(ligneTicket);
  const r = { tickets };
  if (p.relatedTo !== undefined) {
    const ref = p.machine.tickets.get(p.relatedTo);
    const depuis = p.maintenant - ref.expire_after_ms;
    r.related = [...p.machine.tickets.values()]
      .filter((t) => t.sealed !== null && (t.sealed.approval.decision === "refuse" || t.sealed.approval.decision === "expire") &&
        t.request.delegation.launched_by === ref.request.delegation.launched_by &&
        t.request.tool_announced === ref.request.tool_announced &&
        T(t.sealed.approval.at) > depuis)
      .sort((a, b) => comparerChaines(b.sealed.approval.at, a.sealed.approval.at) || comparerChaines(a.ticket, b.ticket))
      .slice(0, RELATED_MAX)
      .map((t) => ({ ticket: t.ticket, decision: t.sealed.approval.decision, decided_at: t.sealed.approval.at, reason: t.sealed.approval.reason }));
  }
  return r;
}

// ---------------------------------------------------------------- effets prévus

const MOTIF_MONTANT = /^-?(0|[1-9][0-9]*)(\.[0-9]{1,8})?$/;
const MOTIF_DEVISE = /^[A-Z]{3}$/;
const estPointeur = (v) => typeof v === "string" && /^\/(arguments|result)(\/|$)/.test(v);

function resoudrePointeur(racine, pointeur) {
  let v = racine;
  for (const brut of pointeur.slice(1).split("/")) {
    const jeton = brut.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(v)) {
      if (!/^(0|[1-9][0-9]*)$/.test(jeton) || Number(jeton) >= v.length) return { trouve: false };
      v = v[Number(jeton)];
    } else if (v !== null && typeof v === "object" && Object.prototype.hasOwnProperty.call(v, jeton)) {
      v = v[jeton];
    } else {
      return { trouve: false };
    }
  }
  return { trouve: true, valeur: v };
}

const tronquer = (s, max) => {
  const p = Array.from(s);
  return p.length > max ? p.slice(0, max).join("") : s;
};

/**
 * Effets prévus de la vue (EX-12.14) : gabarit de l'outil (CT-2 EX-7.6)
 * évalué sur les valeurs rédigées des arguments (pas 1 d'EX-7.6) ; un membre
 * dont le pointeur désigne le résultat reste `null` et est listé dans
 * `unresolved` ; un effet dont un pointeur vers les arguments ne se résout
 * pas, ou invalide au pas 4, est omis. Sans gabarit : effet par défaut d'une
 * écriture, aucun pour une lecture (EX-7.6, (2) et (3)).
 * @param {{effects: object[]|null}|null} outil outil du message `charger`
 * @param {object} requete `request` du ticket
 * @param {unknown} argumentsRediges valeur JSON de la pièce « arguments »
 */
export function effetsPrevus(outil, requete, argumentsRediges) {
  const gabarit = outil?.effects ?? null;
  if (!gabarit) {
    return requete.class === "ecriture"
      ? [{ system: requete.server_alias, action: "ecriture", object: requete.tool_original, amount: null, currency: null, unresolved: [] }]
      : [];
  }
  const racine = { arguments: argumentsRediges };
  const effets = [];
  for (const g of gabarit) {
    const unresolved = [];
    let omis = false;
    const valeur = (membre, champ) => {
      if (champ === null || champ === undefined) return null;
      if (!estPointeur(champ)) return champ;
      if (champ.startsWith("/result")) {
        unresolved.push({ member: membre, pointer: champ });
        return null;
      }
      const r = resoudrePointeur(racine, champ);
      if (!r.trouve || r.valeur === null || r.valeur === undefined) {
        omis = true;
        return null;
      }
      return typeof r.valeur === "string" ? r.valeur : jcsIntegral(r.valeur);
    };
    let objet = valeur("object", g.object);
    const amount = valeur("amount", g.amount);
    const currency = valeur("currency", g.currency);
    if (omis) continue;
    const objetNonResolu = unresolved.some((u) => u.member === "object");
    if (!objetNonResolu) {
      if (objet === null) continue;
      if (g.extract !== null && g.extract !== undefined) {
        let m = null;
        try {
          m = new RegExp(g.extract, "u").exec(objet);
        } catch {
          continue;
        }
        if (!m) continue;
        objet = m.length > 1 && m[1] !== undefined ? m[1] : m[0];
      }
      objet = tronquer(objet, 512);
      if (objet.length === 0) continue;
    }
    const system = tronquer(String(g.system ?? ""), 128);
    const nr = (m) => unresolved.some((u) => u.member === m);
    if (system.length === 0) continue;
    if (!nr("amount") && amount !== null && !MOTIF_MONTANT.test(amount)) continue;
    if (!nr("currency") && currency !== null && !MOTIF_DEVISE.test(currency)) continue;
    // un couple montant/devise dont un seul membre est nul est invalide, sauf membre connu après exécution
    if (!nr("amount") && !nr("currency") && (amount === null) !== (currency === null)) continue;
    effets.push({ system, action: g.action, object: objet, amount, currency, unresolved });
  }
  return effets;
}

/** Valeur rédigée des arguments : pièce en base64, ou valeur en ligne de la référence (12.4). */
function argumentsRediges(t, bodyMax) {
  const ref = t.request.retained_event?.execution?.arguments;
  if (t.request.arguments_piece === null) return ref?.value;
  const octets = decoderBase64Canonique(t.request.arguments_piece, bodyMax);
  return octets ? lireJsonStrict(octets) : undefined;
}

/** Règle retenue (EX-12.14) : nom lu dans `policy.rule` avant sa marque (6.4). */
function regleDuTicket(version, t) {
  const rule = t.request.rule;
  const k = rule.lastIndexOf(" [");
  const nom = k >= 0 && rule.endsWith("]") ? rule.slice(0, k) : rule;
  const P = version?.approval?.rules ?? null;
  const r = P?.rules?.find((x) => x.name === nom) ?? (P?.default?.name === nom ? P.default : null);
  return {
    policy_rule: rule,
    name: nom,
    description: r?.description ?? null,
    level: r?.level ?? "revue",
    contest_ms: t.contest_ms,
    regle: r,
  };
}

/**
 * Vue d'un ticket (EX-12.14, EX-12.15), contrôles faits par l'appelant.
 * @param {{machine: object, annuaire: object, ticket: object, bodyMax: number}} p
 */
export function vueTicket(p) {
  const { machine, annuaire, ticket: t } = p;
  const version = machine.version(t.request.policy_version);
  const { regle, ...rule } = regleDuTicket(version, t);
  const ev = t.request.retained_event;
  // intention de la requête evaluer, gardée avec les arguments, jamais tirée
  // de l'événement retenue (EX-7.24, EX-12.14, révision 0.6)
  const intent = machine.intention(t.ticket);
  const outil = version?.tools?.find((x) => x.tool_announced === t.request.tool_announced) ?? null;
  let rediges;
  try {
    rediges = argumentsRediges(t, p.bodyMax);
  } catch {
    rediges = undefined;
  }
  const effects = effetsPrevus(outil, t.request, rediges);
  const sep = version?.approval?.rules?.separation ?? { self_approval: t.self_approval, identities: [] };
  const lb = t.request.delegation.launched_by;
  const annuaireDemandeur = [];
  for (const e of annuaire.entries) {
    if (!e.requester_identities.includes(lb)) continue;
    for (const a of e.addresses) if (a.state === "active") annuaireDemandeur.push(a.address);
  }
  let opening = null;
  if (t.opening) {
    const pointeurs = regle?.window?.same_arguments ?? [];
    const valeurs = t.opening.scope.values ?? [];
    opening = {
      tool: t.opening.scope.tool,
      when: regle ? cloner(regle.when) : null,
      same_arguments: pointeurs.map((pointer, k) => ({ pointer, value: valeurs[k] })),
      max_calls: t.opening.max_calls,
      duration_ms: t.opening.duration_ms,
    };
  }
  const D = (decision) => condenseA({ decision, ticket: t.ticket, request_hash: t.request.request_hash, org_id: machine.org_id, journal_id: machine.journal_id });
  return {
    version: 0,
    ticket: t.ticket,
    state: t.state,
    org_id: machine.org_id,
    journal_id: machine.journal_id,
    request_hash: t.request.request_hash,
    request: {
      tool_announced: t.request.tool_announced,
      tool_original: t.request.tool_original,
      server_alias: t.request.server_alias,
      class: t.request.class,
      arguments: cloner(t.request.arguments),
      intent,
      delegation: cloner(t.request.delegation),
      policy_version: t.request.policy_version,
    },
    retained_event: cloner(ev),
    arguments_piece: t.request.arguments_piece,
    rule,
    opening,
    effects,
    deadline: t.deadline,
    contest: etatContestation(t),
    approver_set: t.approver_set === null
      ? null
      : jeuDeclare(t.approver_set, null, t.request.policy_version, t.confirmation, false),
    effective_required: t.effective_required,
    added_members: membresAjoutes(t),
    eligible: eligiblesPourLecture(machine, t),
    votes: t.votes.filter((v) => v.status === "courant").map((v) => ({ approver: v.approver, decision: v.decision, reason: v.reason, at: v.at })),
    separation: {
      self_approval: t.self_approval,
      requester_declared: sep.identities.some((x) => x.launched_by === lb),
      requester_addresses: [...t.requester_addresses],
      requester_directory_addresses: [...new Set(annuaireDemandeur)].sort(),
    },
    digests: { approuve: D("approuve"), refuse: D("refuse") },
  };
}
