// Délégation d'un appel reçu par le frontal MCP (CT-2 §7.2, EX-7.2, EX-7.3).
// `launched_by` et `scope` viennent de l'entrée de connexion d'hôte et de son
// identité (`${peer_user}`, `${oauth_subject}`), jamais de l'hôte ;
// `on_behalf_of` et `run_id` déclarés dans `_meta["noortrace/delegation"]`
// ne sont admis que si l'entrée l'accepte, et bornés avant d'entrer dans la
// chaîne : `on_behalf_of` octet pour octet dans `allowed_on_behalf_of`,
// `run_id` au motif d'EX-7.2 et sans correspondance d'un détecteur de texte
// de la politique de rédaction (crochet du lot de rédaction). Un refus est
// consigné (`delegation_refused`) sans la valeur.

/** Motif d'un `run_id` déclaré (EX-7.2). */
const MOTIF_RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

/**
 * `launched_by` d'une entrée : valeur fixe, ou gabarit résolu par l'identité.
 * @param {string} gabarit
 * @param {{peer_user?: string|null, oauth_subject?: string|null}} identite
 * @returns {string|null}
 */
export function lanceurDe(gabarit, identite) {
  if (gabarit === "${peer_user}") return identite.peer_user ?? null;
  if (gabarit === "${oauth_subject}") return identite.oauth_subject ?? null;
  return gabarit;
}

/**
 * Délégation de 7.2 pour une requête d'hôte.
 * @param {object} p
 * @param {object} p.hote entrée de `mcp.hosts`
 * @param {object} p.identite identité de la connexion (utilisateur du pair, sujet OAuth)
 * @param {unknown} p.declaree valeur de `_meta["noortrace/delegation"]` ou undefined
 * @param {string|null} p.sessionHeritee identifiant de session d'un hôte hérité, ou null
 * @param {(texte: string) => boolean} [p.detecte] détecteurs de texte de la politique de rédaction
 * @param {(champ: string, raison: string, longueur: number) => void} [p.refus]
 * @returns {{launched_by: string, on_behalf_of: string|null, scope: string, run_id: string|null}}
 */
export function resoudreDelegation(p) {
  const h = p.hote;
  const d = p.declaree !== null && typeof p.declaree === "object" && !Array.isArray(p.declaree) ? p.declaree : {};
  const refus = p.refus ?? (() => {});
  let on_behalf_of = h.on_behalf_of ?? null;
  let run_id = null;
  if (h.accept_declared_delegation === true) {
    if ("on_behalf_of" in d) {
      const v = d.on_behalf_of;
      if (typeof v === "string" && (h.allowed_on_behalf_of ?? []).includes(v)) on_behalf_of = v;
      else refus("on_behalf_of", "hors_liste", typeof v === "string" ? v.length : 0);
    }
    if ("run_id" in d) {
      const v = d.run_id;
      if (typeof v !== "string" || !MOTIF_RUN_ID.test(v)) refus("run_id", "motif", typeof v === "string" ? v.length : 0);
      else if (p.detecte && p.detecte(v)) refus("run_id", "detecteur", v.length);
      else run_id = v;
    }
  }
  if (run_id === null && p.sessionHeritee) run_id = p.sessionHeritee;
  const launched_by = lanceurDe(h.launched_by, p.identite ?? {});
  return { launched_by, on_behalf_of, scope: h.scope, run_id };
}
