// Frontal MCP dans le démon (CT-2 §3.4) : frontal, prise des connecteurs
// stdio (`mcp.socket`, `mcp.connector_tcp`) et Streamable HTTP (`mcp.http`),
// démarrés après le cœur (EX-15.4 pas 7) et arrêtés avant lui (4.2, « Arrêt »).

import { FrontalMcp } from "./frontal.mjs";
import { ServeurConnecteurs } from "./hote-stdio.mjs";
import { ServeurHttpMcp } from "./hote-http.mjs";

/**
 * Jetons statiques résolus (EX-4.39) : identifiant → octets.
 * @param {object} config
 * @param {Map<string, Uint8Array>} secrets
 */
export function jetonsStatiques(config, secrets) {
  const m = new Map();
  (config.mcp.http?.static_tokens ?? []).forEach((t, k) => {
    const s = secrets.get(`/mcp/http/static_tokens/${k}/token`);
    if (s) m.set(t.id, s);
  });
  return m;
}

/**
 * Démarre le frontal MCP du démon.
 * @param {import("../coeur.mjs").Coeur} coeur
 * @param {Map<string, Uint8Array>} secrets
 * @param {object} [o] options du frontal (rédacteur, corrélateur)
 * @returns {Promise<{frontal: FrontalMcp, connecteurs: ServeurConnecteurs, http: ServeurHttpMcp|null, arreter: () => Promise<void>}>}
 */
export async function demarrerFrontalMcp(coeur, secrets, o = {}) {
  const config = coeur.config;
  const frontal = new FrontalMcp({ coeur, secrets, ...o });
  await frontal.demarrer();
  const jetons = jetonsStatiques(config, secrets);
  const connecteurs = new ServeurConnecteurs({ frontal, socket: config.mcp.socket, tcp: config.mcp.connector_tcp, jetons });
  let http = null;
  let ecoute = false;
  try {
    await connecteurs.ecouter();
    ecoute = true;
    if (config.mcp.http) {
      http = new ServeurHttpMcp({ frontal, jetons });
      await http.ecouter();
    }
  } catch (e) {
    // Refus du démarrage (prise refusée, adresse prise) : les serveurs d'outils
    // déjà lancés par le frontal sont arrêtés, sans quoi leurs processus
    // gardaient le démon vivant après `demarrage_refuse` (étape 7).
    if (ecoute) await connecteurs.fermer().catch(() => {});
    await frontal.arreter().catch(() => {});
    throw e;
  }
  return {
    frontal,
    connecteurs,
    http,
    async arreter() {
      await http?.fermer();
      await connecteurs.fermer();
      await frontal.arreter();
    },
  };
}
