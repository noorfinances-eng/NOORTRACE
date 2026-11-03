// Règles du pas 3 d'EX-15.4 propres à l'ingestion OpenTelemetry (révision
// 0.5 ; CT-2 EX-6.23, EX-6.34, EX-6.37, EX-6.40), ajoutées par
// `validerConfiguration(octets, { reglesSupplementaires: [controleOtel] })` :
// `otel`, s'il est présent avec `enabled: true` : chaque entrée de
// `otel.hosts` a un `match.static_token` qui désigne un `id` de
// `otel.static_tokens` (chaque jeton référencé par une seule entrée), un
// `alias` non nul, unique, distinct de tout alias de `policy.servers` et de
// `sdk.hosts`, et égal à une clé de `policy.otel.sources`, chaque clé ayant une
// entrée ; `launched_by` ne contient pas `${` ; `allowed_on_behalf_of` est
// vide ; en production, `otel.tls` non nul hors adresse de bouclage ;
// avertissements pour `overlap: "conserver"` et pour `encodings` sans
// `protobuf`. (`policy.otel` exigé avec `otel.enabled` et l'avertissement de
// `policy.otel` sans `otel` activé sont des règles du cœur.)

/**
 * `otel.listen` est-il une adresse de bouclage (`127.0.0.0/8`, `[::1]`) ?
 * @param {string} listen
 */
export function adresseBouclage(listen) {
  const hote = listen.split(/:(?=[0-9]+$)/)[0].replace(/^\[|\]$/g, "");
  return /^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(hote) || hote === "::1";
}

/**
 * @param {object} c configuration (validée contre le schéma)
 * @returns {{erreurs: object[], avertissements: object[]}}
 */
export function controleOtel(c) {
  const erreurs = [];
  const avertissements = [];
  const err = (pointeur, regle, valeur) => erreurs.push({ pointeur, regle, valeur });
  const avert = (pointeur, regle) => avertissements.push({ pointeur, regle });
  const o = c.otel;
  if (!o || o.enabled !== true) return { erreurs, avertissements };
  const serveurs = new Set(Object.keys(c.policy?.servers ?? {}));
  const aliasSdk = new Set((c.sdk?.hosts ?? []).map((h) => h.alias).filter((a) => typeof a === "string"));
  const sources = c.policy?.otel?.sources ?? {};
  const jetons = new Set((o.static_tokens ?? []).map((t) => t.id));
  const jetonsVus = new Set();
  const aliasVus = new Set();
  if (!(o.hosts ?? []).length) err("/otel/hosts", "au moins une source quand otel.enabled vaut true (EX-7.3)", []);
  (o.hosts ?? []).forEach((h, k) => {
    const ici = `/otel/hosts/${k}`;
    const id = h.match?.static_token;
    if (typeof id !== "string") err(`${ici}/match`, "une source s'identifie par match.static_token (EX-6.37)", null);
    else {
      if (!jetons.has(id)) err(`${ici}/match/static_token`, "jeton inconnu de otel.static_tokens (EX-6.37)", id);
      if (jetonsVus.has(id)) err(`${ici}/match/static_token`, "jeton référencé par deux sources", id);
      jetonsVus.add(id);
    }
    if (h.alias === null || h.alias === undefined) err(`${ici}/alias`, "alias non nul exigé pour une source (EX-6.37)", null);
    else {
      if (aliasVus.has(h.alias)) err(`${ici}/alias`, "alias de source en double", h.alias);
      aliasVus.add(h.alias);
      if (h.alias === "noortrace") err(`${ici}/alias`, "alias réservé (EX-4.9)", h.alias);
      if (serveurs.has(h.alias)) err(`${ici}/alias`, "alias de source égal à un alias de serveur (EX-6.37)", h.alias);
      if (aliasSdk.has(h.alias)) err(`${ici}/alias`, "alias de source égal à un alias du SDK (EX-6.37)", h.alias);
      if (!Object.prototype.hasOwnProperty.call(sources, h.alias)) err(`${ici}/alias`, "alias sans entrée de policy.otel.sources (EX-6.23)", h.alias);
    }
    if (typeof h.launched_by === "string" && h.launched_by.includes("${")) err(`${ici}/launched_by`, "valeur fixe exigée pour une source (EX-6.37)", h.launched_by);
    if ((h.allowed_on_behalf_of ?? []).length) err(`${ici}/allowed_on_behalf_of`, "vide exigé pour une source (EX-6.37)", h.allowed_on_behalf_of);
  });
  for (const [alias, s] of Object.entries(sources)) {
    if (!aliasVus.has(alias)) err(`/policy/otel/sources/${alias}`, "source sans entrée de otel.hosts (EX-6.23)", alias);
    if (s.overlap === "conserver") avert(`/policy/otel/sources/${alias}/overlap`, "conserver : un acte journalisé par un chemin plus fort aura aussi l'événement du span (EX-6.34)");
  }
  if (!o.encodings.includes("protobuf")) avert("/otel/encodings", "sans protobuf : les SDK OpenTelemetry exportent en http/protobuf par défaut (EX-6.27)");
  if (c.recorder?.environment === "production" && o.tls === null && !adresseBouclage(o.listen)) {
    err("/otel/tls", "TLS exigé en production hors adresse de bouclage (EX-6.40)", null);
  }
  return { erreurs, avertissements };
}
