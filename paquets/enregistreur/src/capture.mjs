// Construction de l'événement CT-1 depuis la capture (CT-2 §7). Les frontaux
// préparent les pièces et remettent au noyau un événement **partiel** : les
// huit champs de CT-1 §5.3 (delegation, code, intent, policy, approval,
// execution, effects, context). L'écrivain unique fixe l'enveloppe (version,
// seq, ts, org_id, journal_id, recorder_key_id, prev_hash), complète ce qui
// dépend de `ts` (approval.at d'une décision, EX-7.11 ; annonce de rotation,
// EX-11.15), valide (EX-7.1), hache et fait signer (EX-7.8).
//
// Ce module fixe, sorte par sorte, d'où vient chaque champ (tables de 7.2) :
// appel d'outil (relayé, retenu, refusé, reprise), échange de modèle,
// décision d'approbation, rotation de clé, politique.

import {
  NOMS_RESERVES, CLES_EVENEMENT, champsEvenementRotation, controlerEvenement, creerReferenceEnLigne, objetApprobation,
} from "@noortrace/noyau";
import { ErreurConstruction } from "./erreurs.mjs";

/** Délégation des événements du journal sur lui-même (CT-1 §5.3, annexe A). */
export const DELEGATION_JOURNAL = Object.freeze({
  launched_by: "noortrace-enregistreur",
  on_behalf_of: null,
  scope: "journal:administration",
  run_id: null,
});

/** Clés de l'événement partiel, dans l'ordre de CT-1 §5.1. */
export const CLES_PARTIEL = Object.freeze(["delegation", "code", "intent", "policy", "approval", "execution", "effects", "context"]);

/**
 * Dit si une valeur est une référence (CT-1 §5.4).
 * @param {unknown} v
 */
function estReference(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v) && "sha256" in v && "length" in v && "redacted" in v;
}

/**
 * `policy.redaction` (EX-10.20, CT-1 E-4) : le nom de la version des règles
 * de rédaction si au moins une référence de l'événement a `redacted: true`,
 * sinon null.
 * @param {object} partiel
 * @param {string|null} nomRedaction `policy.redaction.name` en vigueur
 * @returns {string|null}
 */
export function redactionDe(partiel, nomRedaction) {
  const refs = [];
  if (estReference(partiel.intent)) refs.push(partiel.intent);
  if (estReference(partiel.execution?.arguments)) refs.push(partiel.execution.arguments);
  if (estReference(partiel.execution?.result)) refs.push(partiel.execution.result);
  for (const c of partiel.context ?? []) if (estReference(c)) refs.push(c);
  return refs.some((r) => r.redacted === true) ? nomRedaction ?? null : null;
}

function code(p, policyVersion, recorder) {
  return { model: p?.model ?? null, prompt_version: p?.prompt_version ?? null, policy_version: policyVersion, recorder };
}

/**
 * Appel d'outil (frontal MCP, SDK, OpenTelemetry) : événement partiel.
 * @param {{delegation: object, code: {model: string|null, prompt_version: string|null, policy_version: string, recorder: string},
 *   intent: string|object|null, policy: {rule: string|null, decision: string, ticket: string|null},
 *   approval: object|null, tool: string, arguments: object, status: "executee"|"retenue"|"refusee",
 *   result?: object|null, duration_ms?: number|null, is_error?: boolean|null, effects?: object[], context?: object[],
 *   nomRedaction: string|null}} c
 * @returns {object}
 */
export function partielAppelOutil(c) {
  const executee = c.status === "executee";
  const partiel = {
    delegation: { ...c.delegation },
    code: code(c.code, c.code.policy_version, c.code.recorder),
    intent: c.intent ?? null,
    policy: { rule: c.policy.rule ?? null, decision: c.policy.decision, ticket: c.policy.ticket ?? null, redaction: null },
    approval: c.approval ?? null,
    execution: {
      tool: c.tool,
      arguments: c.arguments,
      status: c.status,
      result: executee ? c.result : null,
      duration_ms: executee ? c.duration_ms : null,
      is_error: executee ? c.is_error : null,
    },
    effects: executee ? (c.effects ?? []) : [],
    context: c.context ?? [],
  };
  partiel.policy.redaction = redactionDe(partiel, c.nomRedaction);
  return partiel;
}

/**
 * Appel relayé ou refus d'un ticket décidé : reprise, clé pour clé, de
 * l'événement `retenue` du ticket (EX-7.12) : `policy.decision`
 * (`a_approuver`), `policy.rule`, `policy.ticket`, `intent`, `code.model`,
 * `code.prompt_version` ; `approval` est l'objet de la décision scellée par le
 * noyau ; `code.policy_version` est la version en vigueur au relais.
 * @param {object} retenue événement `retenue` scellé
 * @param {object} decision événement de décision scellé
 * @returns {{policy: object, intent: unknown, code: {model: string|null, prompt_version: string|null}, approval: object}}
 */
export function repriseDeRetenue(retenue, decision) {
  return {
    policy: { rule: retenue.policy.rule, decision: retenue.policy.decision, ticket: retenue.policy.ticket },
    intent: retenue.intent,
    code: { model: retenue.code.model, prompt_version: retenue.code.prompt_version },
    approval: decision.approval,
  };
}

/**
 * Échange de modèle (`noortrace.modele.echange`) : toujours `executee`,
 * `policy.decision: "sans_objet"` (7.2, 9.1).
 * @param {{delegation: object, code: object, intent: string|object|null, requete: object, reponse: object,
 *   duration_ms: number, is_error: boolean, context?: object[], nomRedaction: string|null}} c
 * @returns {object}
 */
export function partielEchange(c) {
  const partiel = {
    delegation: { ...c.delegation },
    code: code(c.code, c.code.policy_version, c.code.recorder),
    intent: c.intent ?? null,
    policy: { rule: null, decision: "sans_objet", ticket: null, redaction: null },
    approval: null,
    execution: {
      tool: NOMS_RESERVES.ECHANGE,
      arguments: c.requete,
      status: "executee",
      result: c.reponse,
      duration_ms: c.duration_ms,
      is_error: c.is_error,
    },
    effects: [],
    context: c.context ?? [],
  };
  partiel.policy.redaction = redactionDe(partiel, c.nomRedaction);
  return partiel;
}

/**
 * Événement de politique (`noortrace.journal.politique`, 9.1, EX-15.6).
 * @param {{policy_version: string, policy_sha256: string, recorder: string}} p
 * @returns {object}
 */
export function partielPolitique(p) {
  return {
    delegation: { ...DELEGATION_JOURNAL },
    code: { model: null, prompt_version: null, policy_version: p.policy_version, recorder: p.recorder },
    intent: null,
    policy: { rule: null, decision: "sans_objet", ticket: null, redaction: null },
    approval: null,
    execution: {
      tool: NOMS_RESERVES.POLITIQUE,
      arguments: creerReferenceEnLigne({ policy_version: p.policy_version, policy_sha256: p.policy_sha256 }),
      status: "executee",
      result: null,
      duration_ms: null,
      is_error: null,
    },
    effects: [{ system: "noortrace", action: "ecriture", object: `politique:${p.policy_version}`, amount: null, currency: null }],
    context: [],
  };
}

/**
 * Décision d'approbation (`noortrace.approbation.decision`, 9.1, EX-7.19) :
 * `approval` de la remise (sans `at`, que l'écrivain pose, EX-7.11) ;
 * `arguments` : référence en ligne à A (CT-1 §6.3). La délégation et
 * `code.model`, `code.prompt_version` sont ceux de l'appel retenu (7.2 ;
 * lecture consignée dans le LISEZMOI pour la délégation).
 * @param {{retenue: object, approval: object, policy_version: string, recorder: string,
 *   org_id: string, journal_id: string}} p `approval` sans `at`
 * @returns {object}
 */
export function partielDecision(p) {
  const a = p.approval;
  const approval = {
    decision: a.decision,
    ticket: a.ticket,
    request_hash: a.request_hash,
    threshold: { required: a.threshold.required, size: a.threshold.size },
    approvers: [...a.approvers],
    signatures: [...a.signatures],
    at: null,
    reason: a.reason ?? null,
  };
  const A = objetApprobation({ approval, org_id: p.org_id, journal_id: p.journal_id });
  return {
    delegation: { ...p.retenue.delegation },
    code: { model: p.retenue.code.model, prompt_version: p.retenue.code.prompt_version, policy_version: p.policy_version, recorder: p.recorder },
    intent: null,
    policy: { rule: null, decision: "sans_objet", ticket: a.ticket, redaction: null },
    approval,
    execution: {
      tool: NOMS_RESERVES.DECISION,
      arguments: creerReferenceEnLigne(A),
      status: "executee",
      result: null,
      duration_ms: null,
      is_error: null,
    },
    effects: [],
    context: [],
  };
}

/**
 * Rotation de clé (`noortrace.journal.rotation-cle`, CT-1 §8, EX-11.15) :
 * l'annonce dépend de `ts` (`valid_from = ts`) ; l'écrivain la complète.
 * @param {object} annonce les sept clés de CT-1 §8
 * @param {{policy_version: string, recorder: string}} p
 * @returns {object}
 */
export function partielRotation(annonce, p) {
  const { execution, effects } = champsEvenementRotation(annonce);
  return {
    delegation: { ...DELEGATION_JOURNAL },
    code: { model: null, prompt_version: null, policy_version: p.policy_version, recorder: p.recorder },
    intent: null,
    policy: { rule: null, decision: "sans_objet", ticket: null, redaction: null },
    approval: null,
    execution,
    effects,
    context: [],
  };
}

/**
 * Complète l'enveloppe d'un événement partiel (7.2, « Enveloppe ») dans
 * l'ordre des dix-sept clés de CT-1 §5.1, sans `hash` ni `sig`.
 * @param {object} partiel
 * @param {{seq: number, ts: string, org_id: string, journal_id: string, recorder_key_id: string, prev_hash: string}} e
 * @returns {object}
 */
export function envelopper(partiel, e) {
  return {
    version: 0,
    seq: e.seq,
    ts: e.ts,
    org_id: e.org_id,
    journal_id: e.journal_id,
    recorder_key_id: e.recorder_key_id,
    prev_hash: e.prev_hash,
    delegation: partiel.delegation,
    code: partiel.code,
    intent: partiel.intent,
    policy: partiel.policy,
    approval: partiel.approval,
    execution: partiel.execution,
    effects: partiel.effects,
    context: partiel.context,
  };
}

const SIG_PROVISOIRE = "0x" + "00".repeat(64);

/**
 * Validation d'EX-7.1 avant signature : schéma d'événement et contrôles E-1
 * à E-7 de CT-1 §11.4 (la signature, E-8 et suivants, n'existe pas encore).
 * @param {object} evenement sans `sig`, avec `hash`
 * @throws {ErreurConstruction}
 */
export function validerAvantSignature(evenement) {
  const essai = { ...evenement, sig: evenement.sig ?? SIG_PROVISOIRE };
  const { controles } = controlerEvenement(essai, {});
  const ecarts = [];
  for (const id of ["E-1", "E-2", "E-3", "E-4", "E-5", "E-6", "E-7"]) {
    const c = controles[id];
    if (c.statut !== "reussi") ecarts.push(`${id} : ${(c.details?.length ? c.details : [c.raison]).join(" ; ")}`);
  }
  for (const cle of CLES_EVENEMENT) if (!(cle in essai)) ecarts.push(`clé ${cle} absente`);
  if (ecarts.length) throw new ErreurConstruction("événement construit invalide (EX-7.1)", ecarts);
}
