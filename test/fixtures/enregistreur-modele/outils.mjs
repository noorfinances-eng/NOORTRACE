// Outils communs aux tests du frontal modèle (test/enregistreur-modele-*) :
// configuration de développement dont les routes visent le fournisseur
// simulé sur 127.0.0.1, connexions d'hôte de la passerelle et du mandataire
// MCP d'un même groupe, cœur démarré sur une horloge qui suit le temps réel
// et qu'on peut avancer (clôture de période), politique pii-v1 des vecteurs.
// Jetons et clés fictifs.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Coeur, Redacteur, validerConfiguration, resoudreSecrets, controleRedaction, controleModele } from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { configurationDev, VECTEURS_CT2 } from "../enregistreur-coeur/outils.mjs";

export const ICI = path.dirname(fileURLToPath(import.meta.url));
export const AGENT = path.join(ICI, "agent.mjs");
export const SERVEUR_OUTILS = path.join(ICI, "serveur-outils.mjs");

/** Jetons fictifs des connexions d'hôte. */
export const JETON_MODELE = "jeton-passerelle-de-test-0001";
export const JETON_MCP = "jeton-mcp-de-test-0001";

/** Politique de rédaction des vecteurs (pii-v1). */
export function politiquePii() {
  return JSON.parse(fs.readFileSync(path.join(VECTEURS_CT2, "redaction", "politique-pii-v1.json"), "utf8"));
}

function hote(id, jeton, groupe) {
  return {
    id,
    match: { static_token: jeton },
    launched_by: "agent-modele",
    scope: "sinistres:lecture",
    on_behalf_of: "service-sinistres",
    accept_declared_delegation: true,
    allowed_on_behalf_of: ["service-sinistres"],
    tool_name_template: "{tool_announced}",
    tool_name_sanitize: true,
    prompt_version_name: null,
    host_group: groupe,
    quota: { max_concurrent: 32, piece_bytes_per_minute: 268435456, received_bytes_per_minute: 268435456, redaction_ms_per_minute: 30000 },
    alias: null,
  };
}

/** Routes du fournisseur simulé, une par format et par variante des vecteurs. */
export function routesSimulees(url) {
  const r = (path_, format, label, o = {}) => ({
    path: path_,
    format,
    upstream: url,
    provider_label: label,
    credentials: o.credentials ?? "propre",
    secret: (o.credentials ?? "propre") === "propre" ? { env: "NOORTRACE_TEST_CLE_FOURNISSEUR" } : null,
    auth_header: o.auth ?? (format === "gemini" ? "x-goog-api-key" : "x-api-key"),
    passthrough: o.passthrough ?? [],
    ...(o.extra ?? {}),
  });
  return [
    r("/v1/messages", "anthropic-messages", "anthropic", { passthrough: [{ method: "POST", path: "/v1/messages/count_tokens" }, { method: "GET", path: "/v1/models" }] }),
    r("/anthropic/v1/messages", "anthropic-messages", "bedrock-mantle"),
    r("/v1/chat/completions", "openai-chat", "openai", { credentials: "relayer", auth: "authorization-bearer" }),
    r("/v1/responses", "openai-responses", "openai", { auth: "authorization-bearer" }),
    r("/v1beta/models", "gemini", "gemini"),
    r("/v1/models", "gemini", "gemini"),
  ];
}

/**
 * Configuration de développement du frontal modèle.
 * @param {string} dir
 * @param {string} url URL du fournisseur simulé
 * @param {{mcp?: boolean, delais?: object, model?: object, failure?: object}} [o]
 */
export function configurationModele(dir, url, o = {}) {
  const { config, env } = configurationDev(dir, { mcp: o.mcp === true, modele: true });
  config.model = {
    ...config.model,
    hosts: [hote("agent-modele", "agent-modele", "agent-modele")],
    static_tokens: [{ id: "agent-modele", token: { env: "NOORTRACE_TEST_JETON_MODELE" } }],
    forward_headers: ["x-trace-*"],
    strip_headers: ["x-a-retirer"],
    prompt_in_request: "reference",
    prompt_system: "redige",
    connect_timeout_ms: 2000,
    first_byte_timeout_ms: 3000,
    idle_timeout_ms: 3000,
    correlation_window_ms: 600000,
    ...(o.delais ?? {}),
    ...(o.model ?? {}),
  };
  config.policy.model = { routes: routesSimulees(url) };
  config.policy.redaction = politiquePii();
  if (o.failure) config.policy.failure = { ...config.policy.failure, ...o.failure };
  env.NOORTRACE_TEST_JETON_MODELE = JETON_MODELE;
  env.NOORTRACE_TEST_CLE_FOURNISSEUR = "cle-fournisseur-fictive-de-test";
  if (o.mcp) {
    config.mcp.http = { listen: "127.0.0.1:0", path: "/mcp", allowed_origins: [], tls: null, oauth: null, static_tokens: [{ id: "agent-mcp", token: { env: "NOORTRACE_TEST_JETON_MCP" } }] };
    config.mcp.hosts = [hote("agent-mcp", "agent-mcp", "agent-modele")];
    config.mcp.connector_tcp = null;
    config.policy.servers = {
      demo: {
        transport: { type: "stdio", command: [process.execPath, SERVEUR_OUTILS], cwd: null, env: {}, sandbox: null, user: null, integrity: null },
        protocol: "legacy",
        class_default: "lecture",
        timeout_ms: 10000,
        tools: {
          "claims.get": { class: "lecture", timeout_ms: null, effects: null, failure: null },
          "payments.create": { class: "ecriture", timeout_ms: null, effects: null, failure: null },
        },
        uri_prefixes: [],
        relay: null,
      },
    };
    env.NOORTRACE_TEST_JETON_MCP = JETON_MCP;
  }
  return { config, env };
}

/** Connexion d'hôte des modes icap et miroir : par l'adresse source (EX-5.8 point 3). */
export function hoteParAdresse(id = "agent-adresse", plages = ["127.0.0.0/8", "::1/128"]) {
  const h = hote(id, "inutilise", "agent-modele");
  h.match = { source_addresses: plages };
  h.accept_declared_delegation = true;
  return h;
}

/** Configuration du mode icap (EX-5.3) : services sur 127.0.0.1:0, mandataires admis par adresse. */
export function configurationIcap(dir, url, o = {}) {
  const c = configurationModele(dir, url, o);
  c.config.model.mode = "icap";
  c.config.model.listen = null;
  c.config.model.hosts = [hoteParAdresse()];
  c.config.model.static_tokens = [];
  c.config.model.icap = { listen: "127.0.0.1:0", tls_listen: null, client_ca: null, allowed_sources: ["127.0.0.1/32"], client_address_header: "X-Client-IP", ...(o.icap ?? {}) };
  return c;
}

/** Configuration du mode miroir (EX-5.6) : prise de l'adaptateur sous le répertoire du test. */
export function configurationMiroir(dir, url, o = {}) {
  const c = configurationModele(dir, url, o);
  c.config.model.mode = "miroir";
  c.config.model.listen = null;
  c.config.model.hosts = [hoteParAdresse()];
  c.config.model.static_tokens = [];
  c.config.model.mirror = { socket: path.join(dir, "prise", "miroir.sock") };
  return c;
}

/** Valide une configuration (pas 1 à 4 d'EX-15.4) et rend config et secrets. */
export function valider(config, env) {
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)), { reglesSupplementaires: [controleRedaction, controleModele] });
  if (v.erreurs.length) throw new Error(`configuration de test invalide : ${JSON.stringify(v.erreurs)}`);
  const s = resoudreSecrets(v.config, { env });
  if (s.erreurs.length) throw new Error(`secrets de test : ${JSON.stringify(s.erreurs)}`);
  return { config: v.config, secrets: s.secrets };
}

/**
 * Horloge qui suit le temps réel depuis un instant mural donné, et qu'on peut
 * avancer (murale et monotone ensemble) pour clore une période.
 * @param {number} debut instant mural initial, ms UNIX
 */
export function horlogeAvancable(debut) {
  const hr = () => Number(process.hrtime.bigint() / 1000000n);
  const h0 = hr();
  let decalage = 0;
  return {
    murale: () => debut + (hr() - h0) + decalage,
    monotone: () => hr() + decalage,
    avancer(ms) {
      decalage += ms;
    },
  };
}

/**
 * Démarre un cœur de test (service d'approbation factice qui autorise tout,
 * rédacteur pii-v1 dans le fil appelant).
 */
export async function demarrerCoeur(config, secrets, o = {}) {
  const service = o.service === null ? null : new ServiceApprobationFactice({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id });
  const redaction = new Redacteur({ politique: config.policy.redaction, fils: o.fils ?? 0 });
  const coeur = await Coeur.demarrer({ config, secrets, horloge: o.horloge, service, redaction, nonce: o.nonce });
  return { coeur, service, redaction };
}
