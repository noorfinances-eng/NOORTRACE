// Journal sur lui-même (CT-2 §9.1) : ce qui déclenche les quatre événements
// réservés. Le premier événement de tout journal est un
// `noortrace.journal.politique` (EX-9.1) ; un changement de l'ensemble de
// politique en produit un avant le premier événement qui porte la nouvelle
// version (EX-9.2, EX-15.4 pas 6, EX-15.5) ; une rotation est produite avant
// la clôture de la période où la clé courante expire (EX-9.3, EX-11.15) ; une
// décision `expire` est scellée par le noyau seul à l'échéance plus
// `timeout_ms` (EX-9.4). Rien d'autre (démarrage, arrêt, clôture, mode
// dégradé) n'est un événement : c'est le journal d'exploitation (9.2).

import { decoderHorodatage } from "@noortrace/noyau";
import { E_MAX_MS } from "./approbations.mjs";

/**
 * Faut-il annoncer l'ensemble de politique chargé (EX-9.2, EX-15.4 pas 6) ?
 * @param {{dernierePolitique: object|null, politiques: Map<string, string>}} index
 * @param {{policy_version: string, policy_sha256: string}} empreinte
 * @returns {{annoncer: boolean, refus: string|null}}
 *   `refus` : la version n'a pas changé alors que l'empreinte a changé (EX-10.21)
 */
export function decisionPolitique(index, empreinte) {
  const d = index.dernierePolitique;
  if (!d) return { annoncer: true, refus: null };
  if (d.policy_sha256 === empreinte.policy_sha256) return { annoncer: false, refus: null };
  if (d.policy_version === empreinte.policy_version) {
    return { annoncer: false, refus: "policy.version inchangée alors que l'ensemble de politique a changé (EX-10.21)" };
  }
  if (index.politiques.has(empreinte.policy_version) && index.politiques.get(empreinte.policy_version) !== empreinte.policy_sha256) {
    return { annoncer: false, refus: "policy.version déjà annoncée avec une autre empreinte (EX-10.21)" };
  }
  return { annoncer: true, refus: null };
}

/**
 * Rotation planifiée due (EX-11.15) : `planned_every_days` écoulés depuis
 * l'entrée en vigueur de la clé courante.
 * @param {{planned_every_days: number|null, next_key_id: string|null}} rotation
 * @param {number|null} depuis entrée en vigueur de la clé courante, ms
 * @param {number} maintenant ms
 * @returns {boolean}
 */
export function rotationDue(rotation, depuis, maintenant) {
  if (!rotation?.planned_every_days || !rotation.next_key_id || depuis === null) return false;
  return maintenant - depuis >= rotation.planned_every_days * 86400000;
}

/**
 * Échéance d'expiration par le noyau seul (EX-9.4) : `request_ts + E +
 * timeout_ms`, E étant l'`expire_after_ms` de la version de la `retenue`.
 * Politique de cette version introuvable (E null) : la borne de E (CT-3 7.6,
 * 86 400 000 ms), jamais antérieure à l'échéance réelle ; le ticket reçoit
 * ainsi toujours une décision (CT-3 EX-7.25), sans être expiré avant son
 * échéance (LISEZMOI, Lectures).
 * @param {object} retenue
 * @param {number|null} E
 * @param {number} timeoutMs
 * @returns {number} ms
 */
export function echeanceExpiration(retenue, E, timeoutMs) {
  return decoderHorodatage(retenue.ts) + (E ?? E_MAX_MS) + timeoutMs;
}
