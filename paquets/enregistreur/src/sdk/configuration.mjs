// Règles du pas 3 d'EX-15.4 propres au point d'entrée SDK (CT-2 EX-6.6,
// EX-6.24, EX-7.3, EX-4.39), ajoutées par `validerConfiguration(octets, {
// reglesSupplementaires: [controleSdk] })` au démarrage, au rechargement et
// par `validate-config` :
//   - `alias` non nul et distinct de tout alias de serveur dans `sdk.hosts`,
//     nul ailleurs (`mcp.hosts`, `model.hosts`) ; alias du SDK uniques ;
//   - au moins une connexion d'hôte quand le SDK est activé (EX-7.3), et une
//     prise (`sdk.socket` ou `sdk.tcp_listen`) ;
//   - une entrée de `sdk.hosts` s'identifie par l'utilisateur du pair (prise
//     Unix) ou par un jeton statique (prise TCP, EX-4.39) : un jeton désigne
//     un `id` de `mcp.http.static_tokens` (lecture du LISEZMOI), au plus une
//     entrée du SDK par jeton ; `${oauth_subject}` n'a pas de sens ici ;
//   - `sdk.tcp_listen.client_auth: "mtls"` exige `sdk.tcp_listen.tls` : le
//     certificat client est vérifié par la poignée de main TLS, contre
//     l'autorité qui suit le certificat du démon dans `tls.cert_file`, et
//     rattaché à l'entrée dont `match.peer_user` est son nom commun
//     (lecture 113) ;
//   - `allowed_on_behalf_of` non vide seulement avec `accept_declared_delegation` ;
//   - `policy.sdk.aliases`, s'il est présent, est exactement l'ensemble des
//     alias de `sdk.hosts` ; absent avec `sdk.enabled` : avertissement (EX-6.24).

import { erreursPriseTcp } from "../mcp/prise-tcp.mjs";

/**
 * @param {object} c configuration (validée contre le schéma)
 * @returns {{erreurs: object[], avertissements: object[]}}
 */
export function controleSdk(c) {
  const erreurs = [];
  const avertissements = [];
  const err = (pointeur, regle, valeur) => erreurs.push({ pointeur, regle, valeur });
  const avert = (pointeur, regle) => avertissements.push({ pointeur, regle });
  const sdk = c.sdk ?? { enabled: false, hosts: [] };
  const serveurs = new Set(Object.keys(c.policy?.servers ?? {}));
  const jetons = new Set((c.mcp?.http?.static_tokens ?? []).map((t) => t.id));

  // `alias` nul hors de sdk.hosts (EX-15.4 pas 3, EX-6.6).
  for (const [membre, liste] of [["mcp", c.mcp?.hosts], ["model", c.model?.hosts]]) {
    (liste ?? []).forEach((h, k) => {
      if (h.alias !== null && h.alias !== undefined) err(`/${membre}/hosts/${k}/alias`, "alias réservé aux entrées de sdk.hosts (EX-6.6)", h.alias);
    });
  }

  const vus = new Set();
  const jetonsVus = new Set();
  (sdk.hosts ?? []).forEach((h, k) => {
    const ici = `/sdk/hosts/${k}`;
    if (h.alias === null || h.alias === undefined) err(`${ici}/alias`, "alias non nul exigé dans sdk.hosts (EX-6.6)", null);
    else {
      if (h.alias === "noortrace") err(`${ici}/alias`, "alias réservé (EX-4.9)", h.alias);
      if (serveurs.has(h.alias)) err(`${ici}/alias`, "alias du SDK égal à un alias de serveur (EX-6.6)", h.alias);
      if (vus.has(h.alias)) err(`${ici}/alias`, "alias du SDK en double", h.alias);
      vus.add(h.alias);
    }
    if (h.match?.oauth_subject !== undefined || h.match?.source_addresses !== undefined) err(`${ici}/match`, "le SDK s'identifie par l'utilisateur du pair ou par un jeton statique (EX-6.1, EX-4.39)", null);
    if (typeof h.match?.static_token === "string") {
      if (!jetons.has(h.match.static_token)) err(`${ici}/match/static_token`, "jeton statique inconnu", h.match.static_token);
      if (jetonsVus.has(h.match.static_token)) err(`${ici}/match/static_token`, "jeton référencé par deux connexions du même frontal", h.match.static_token);
      jetonsVus.add(h.match.static_token);
    }
    if (h.launched_by === "${oauth_subject}") err(`${ici}/launched_by`, "${oauth_subject} sans objet pour le SDK", h.launched_by);
    if (h.launched_by === "${peer_user}" && h.match?.peer_user === undefined) err(`${ici}/launched_by`, "${peer_user} exige une entrée match.peer_user", h.launched_by);
    if ((h.allowed_on_behalf_of ?? []).length && h.accept_declared_delegation !== true) err(`${ici}/allowed_on_behalf_of`, "allowed_on_behalf_of non vide seulement avec accept_declared_delegation", h.id);
  });

  if (sdk.enabled === true) {
    if (!(sdk.hosts ?? []).length) err("/sdk/hosts", "au moins une connexion d'hôte quand le SDK est activé (EX-7.3)", []);
    if (!sdk.socket && !sdk.tcp_listen) err("/sdk", "sdk.socket ou sdk.tcp_listen exigé quand le SDK est activé (EX-6.1)", null);
    erreurs.push(...erreursPriseTcp(sdk.tcp_listen, "/sdk/tcp_listen"));
    if (!c.policy?.sdk) avert("/policy/sdk", "policy.sdk.aliases absent alors que le SDK est activé (EX-6.24)");
  }

  // EX-6.24 : alias annoncés dans la chaîne.
  if (c.policy?.sdk) {
    const annonces = [...new Set(c.policy.sdk.aliases ?? [])].sort();
    const attendus = [...new Set((sdk.hosts ?? []).map((h) => h.alias).filter((a) => typeof a === "string"))].sort();
    if (annonces.join("\n") !== attendus.join("\n")) err("/policy/sdk/aliases", "différent de l'ensemble des alias de sdk.hosts (EX-6.24)", c.policy.sdk.aliases);
  }
  return { erreurs, avertissements };
}
