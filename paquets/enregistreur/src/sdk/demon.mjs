// Point d'entrée SDK dans le démon (CT-2 §3.4, §6) : frontal et prise
// (`sdk.socket`, `sdk.tcp_listen`), démarrés après le cœur (EX-15.4 pas 7),
// arrêtés avant lui. Un appel resté ouvert à l'arrêt du démon est repris par
// la relecture du journal d'intention au démarrage suivant (EX-12.15).

import { FrontalSdk } from "./frontal.mjs";
import { ServeurSdk } from "./prise.mjs";

/**
 * Jetons statiques des prises TCP du SDK : ceux de `mcp.http.static_tokens`
 * (lecture du LISEZMOI), identifiant → octets.
 * @param {object} config
 * @param {Map<string, Uint8Array>} secrets
 */
export function jetonsSdk(config, secrets) {
  const m = new Map();
  (config.mcp?.http?.static_tokens ?? []).forEach((t, k) => {
    const s = secrets.get(`/mcp/http/static_tokens/${k}/token`);
    if (s) m.set(t.id, s);
  });
  return m;
}

/**
 * Démarre le point d'entrée SDK, si `sdk.enabled`.
 * @param {import("../coeur.mjs").Coeur} coeur
 * @param {Map<string, Uint8Array>} secrets
 * @param {{redacteur?: object, correlateur?: object|null}} [o]
 * @returns {Promise<{frontal: FrontalSdk|null, serveur: ServeurSdk|null, arreter: () => Promise<void>}>}
 */
export async function demarrerSdk(coeur, secrets, o = {}) {
  const s = coeur.config.sdk;
  if (!s?.enabled) return { frontal: null, serveur: null, async arreter() {} };
  const frontal = new FrontalSdk({ coeur, redacteur: o.redacteur, correlateur: o.correlateur ?? null });
  const serveur = new ServeurSdk({ frontal, socket: s.socket, tcp: s.tcp_listen, jetons: jetonsSdk(coeur.config, secrets) });
  await serveur.ecouter();
  const a = serveur.adresseTcp();
  coeur.journal.consigner("info", "sdk", "sdk_listening", { socket: s.socket ?? null, address: a ? `${a.address}:${a.port}` : null, hosts: (s.hosts ?? []).length });
  return {
    frontal,
    serveur,
    async arreter() {
      frontal.arreter();
      await serveur.fermer();
    },
  };
}
