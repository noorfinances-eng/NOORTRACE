// Agent de test du banc « client fictif » : un hôte MCP qui joint le frontal
// HTTP de l'enregistreur (CT-2 §4, Streamable HTTP, `mcp.http`, jeton
// statique de la connexion d'hôte `cursor-postes` du modèle de production),
// comme le ferait le client MCP d'un poste (CT-2 §19.5). Aucune dépendance :
// `fetch` de Node.js. Les réponses en `text/event-stream` sont lues jusqu'au
// message qui porte l'identifiant de la requête.

import * as N from "@noortrace/noyau";

const VERSION_PROTOCOLE = "2025-06-18";

/** Lit une réponse JSON-RPC (JSON ou flux SSE) d'identifiant `id`. */
async function lireReponse(rep, id) {
  const type = rep.headers.get("content-type") ?? "";
  const texte = await rep.text();
  if (type.startsWith("text/event-stream")) {
    for (const bloc of texte.split(/\r?\n\r?\n/)) {
      const donnees = bloc.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n");
      if (!donnees) continue;
      const m = JSON.parse(donnees);
      if (m.id === id) return m;
    }
    throw new Error(`flux SSE sans réponse à la requête ${id}`);
  }
  if (!texte) return null;
  return JSON.parse(texte);
}

/**
 * Ouvre une session MCP auprès de `url` avec le jeton `jeton`.
 * @param {{url: string, jeton: string, nomClient?: string}} o
 */
export async function ouvrirSession({ url, jeton, nomClient = "agent-banc-client-fictif" }) {
  let session = null;
  let suivant = 1;
  const entetes = () => ({
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    authorization: `Bearer ${jeton}`,
    ...(session ? { "mcp-session-id": session, "mcp-protocol-version": VERSION_PROTOCOLE } : {}),
  });
  const requete = async (method, params) => {
    const id = suivant++;
    const rep = await fetch(url, { method: "POST", headers: entetes(), body: JSON.stringify({ jsonrpc: "2.0", id, method, params }) });
    if (!session) session = rep.headers.get("mcp-session-id");
    if (rep.status >= 400) throw new Error(`${method} : HTTP ${rep.status} ${await rep.text()}`);
    return lireReponse(rep, id);
  };
  const init = await requete("initialize", { protocolVersion: VERSION_PROTOCOLE, capabilities: {}, clientInfo: { name: nomClient, version: "0.1.0" } });
  if (init?.error) throw new Error(`initialize : ${JSON.stringify(init.error)}`);
  const notif = await fetch(url, { method: "POST", headers: entetes(), body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) });
  await notif.text();
  return {
    session: () => session,
    initialisation: init,
    requete,
    liste: () => requete("tools/list", {}),
    appeler: (name, args) => requete("tools/call", { name, arguments: args }),
  };
}

/** Condensé d'approbation D_A (CT-1 §6.3) d'un vote, en hexadécimal. */
export function condenseApprobation({ decision, journalId, orgId, requestHash, ticket }) {
  return N.octetsVersHex(N.condenseApprobation({ decision, journal_id: journalId, org_id: orgId, request_hash: requestHash, ticket }));
}
