// Frontal modèle dans le démon (CT-2 §3.4, §5.1, EX-5.1) : registre de
// corrélation (5.6), offert au frontal MCP et au SDK, et le transport du mode
// configuré : passerelle (`model.listen`), serveur ICAP (`model.icap`) ou
// récepteur du miroir (`model.mirror.socket`) ; rien en mode `desactive`.
// Démarré après le cœur (EX-15.4 pas 7), arrêté avant lui (13.5).

import { PasserelleModele } from "./passerelle.mjs";
import { ServeurIcap } from "./icap.mjs";
import { RecepteurMiroir } from "./miroir.mjs";
import { MoteurEchanges } from "./echange.mjs";
import { RegistreCorrelation } from "./correlation.mjs";

/**
 * Démarre le frontal modèle du démon.
 * @param {import("../coeur.mjs").Coeur} coeur
 * @param {Map<string, Uint8Array>} secrets
 * @param {{redacteur?: object, chargerJwks?: () => Promise<object>}} [o]
 * @returns {Promise<{correlateur: RegistreCorrelation|null, passerelle: PasserelleModele|null, icap: ServeurIcap|null,
 *   miroir: RecepteurMiroir|null, arreter: () => Promise<void>}>}
 */
export async function demarrerFrontalModele(coeur, secrets, o = {}) {
  const m = coeur.config.model;
  const vide = { correlateur: null, passerelle: null, icap: null, miroir: null, async arreter() {} };
  if (m.mode === "desactive") return vide;
  const correlateur = new RegistreCorrelation({
    fenetreMs: m.correlation_window_ms,
    monotone: () => coeur.horlogeBrute.monotone(),
    ecrirePiece: (p) => coeur.ecrirePiece(p),
    origine: (nom) => origineAnnoncee(coeur.config, nom),
    journal: coeur.journal,
  });
  const moteur = new MoteurEchanges({ coeur, redacteur: o.redacteur, registre: correlateur });
  if (m.mode === "passerelle") {
    const passerelle = new PasserelleModele({ coeur, secrets, moteur, chargerJwks: o.chargerJwks });
    await passerelle.ecouter();
    const a = passerelle.adresse();
    coeur.journal.consigner("info", "frontal_modele", "model_gateway_listening", { address: a ? `${a.address}:${a.port}` : null, routes: (coeur.config.policy.model?.routes ?? []).length });
    return { ...vide, correlateur, passerelle, arreter: () => passerelle.arreter() };
  }
  if (m.mode === "icap") {
    const icap = new ServeurIcap({ coeur, moteur });
    await icap.ecouter();
    const [a, t] = icap.adresses();
    coeur.journal.consigner("info", "frontal_modele", "model_icap_listening", { address: `${a.address}:${a.port}`, tls_address: t ? `${t.address}:${t.port}` : null, services: ["/noortrace/reqmod", "/noortrace/respmod"] });
    return { ...vide, correlateur, icap, arreter: () => icap.arreter() };
  }
  if (m.mode === "miroir") {
    const miroir = new RecepteurMiroir({ coeur, moteur });
    await miroir.ecouter();
    coeur.journal.consigner("info", "frontal_modele", "model_mirror_listening", { socket: m.mirror.socket });
    return { ...vide, correlateur, miroir, arreter: () => miroir.arreter() };
  }
  throw new Error(`mode ${m.mode} du frontal modèle inconnu (EX-5.1)`);
}

/**
 * Alias et nom d'origine d'un nom annoncé (EX-4.10), pour le gabarit
 * `tool_name_template` (EX-5.22) : `<alias>__<nom>`, ou le nom d'origine sans
 * préfixe quand `tools.prefix` est désactivé avec un seul serveur.
 * @param {object} config
 * @param {string} nom
 */
export function origineAnnoncee(config, nom) {
  const serveurs = Object.keys(config.policy?.servers ?? {});
  if (config.tools?.prefix === false && serveurs.length === 1) return { alias: serveurs[0], nom };
  const k = nom.indexOf("__");
  return k > 0 ? { alias: nom.slice(0, k), nom: nom.slice(k + 2) } : { alias: serveurs[0] ?? "", nom };
}
