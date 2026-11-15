#!/usr/bin/env node
// Banc des scénarios d'intégration de CT-9 TI-4 à TI-11 (EX-8.2) : le démon
// réel `bin/noortrace` lancé comme processus avec la **configuration de
// démonstration** (`demo/configuration-demo.json`, CT-2 §19.1) ramenée à
// l'hôte de construction, et les deux services que la démonstration isole
// derrière l'enregistreur, servis dans ce processus :
//   - le serveur d'outils `outils-demo` de la démonstration (Streamable HTTP,
//     ère 2026-07-28, `conteneurs/outils-demo/outils-demo.mjs`), serveur `demo`
//     de la politique ;
//   - le simulateur de l'API Messages `modele-demo` (CT-2 §19.3, EX-19.2,
//     `conteneurs/modele-demo/modele-demo.mjs`) derrière la route
//     `/v1/messages`, et, pour les SDK et cadres dont le format n'est pas
//     l'API Messages (§19.5.4, §19.5.5, §19.5.7 à §19.5.10), le simulateur des
//     formats `simulateur-formats.mjs` (même scénario de §19.2) derrière les
//     routes `/v1/chat/completions`, `/v1/responses` et `/v1beta/models` de
//     15.3, ajoutées à la politique de démonstration.
// Ce qui change par rapport au conteneur : les chemins (prises, stockage,
// clé, journal d'exploitation, exports), les adresses d'écoute (boucle locale,
// ports libres), le registre (désactivé : aucune chaîne sur l'hôte ; les
// contrôles 4 et 5 du vérificateur ne s'exécutent alors pas, comme dans la
// démonstration hors ligne), le service d'approbation (le service simulé de
// CT-3 §12 des essais, en HTTP, qui joue aussi `approbateur-demo` : il signe la
// décision avec les comptes Hardhat 1 et 2 dès que le ticket est ouvert), le
// point d'entrée SDK (activé, alias `agent-py`, pour les outils locaux que les
// adaptateurs de 6.6 déclarent) et l'ingestion OpenTelemetry (membre `otel`
// de l'exemple de 15.3, pour TI-11).
//
// NOORTRACE_INTEGRATION_LITELLM : exécutable `litellm` (extra `proxy`) ;
// NOORTRACE_INTEGRATION_MANDATAIRE : `derriere` (agent → passerelle →
// mandataire LiteLLM → simulateur, CT-2 EX-6.22 topologie 1) ou `devant`
// (agent → mandataire LiteLLM → passerelle → simulateur, topologie 2).
//
// Il écrit une ligne JSON `{"pret": true, …}` (adresses, jetons, répertoire),
// puis lit des commandes JSON, une par ligne, et répond par une ligne JSON :
//   {"cmd": "arreter"} | {"cmd": "tuer"} | {"cmd": "demarrer"}
//   {"cmd": "evenements"}                 événements du journal (segments)
//   {"cmd": "exploitation", "event": e}   lignes du journal d'exploitation
//   {"cmd": "requetes"}                   requêtes reçues par les simulateurs (modele-demo et formats)
//   {"cmd": "usage"}                      relevé d'usage par empreinte de clé des deux simulateurs
//   {"cmd": "appels_outils"}              nombre de tools/call reçus par outils-demo
//   {"cmd": "approbations"}               tickets décidés par l'approbateur automatique
//   {"cmd": "pieces", "sha256": [...]}    octets (UTF-8) des pièces du journal
//   {"cmd": "cloturer"}                   `noortrace-ctl close-period --now` (CT-2 EX-19.4)
//   {"cmd": "exporter", "seq": n}         `noortrace-ctl dossier exporter --seq n --vers <exports>/dossier-seq-n`
//   {"cmd": "verifier", "dossier": d}     vérificateur JavaScript de référence et binaire Go, sans réseau (unshare -rn)
// À la fermeture de son entrée, il arrête tout et retire son répertoire.
// Importé sans être lancé, il ne fait rien.

import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const ICI = path.dirname(fileURLToPath(import.meta.url));
export const RACINE = path.resolve(ICI, "..", "..", "..");
/** Valeurs de démonstration publiques de `demo/compose.yaml` (sans valeur). */
export const JETON_HOTE = "demo-jeton-hote-agent-demo";
export const JETON_PASSERELLE = "demo-jeton-passerelle-agent-demo";
export const CLE_MODELE = "demo-cle-de-la-passerelle-vers-modele-demo";
export const CLE_MAC_RELAIS = "000000000000000000000000000000000000000000000000000000006d616364";
export const JETON_APPROBATION = "jeton-noyau-integration";
export const JETON_OTEL = "jeton-otel-integration-agent-sinistres";
export const CLE_MANDATAIRE = "sk-noortrace-integration-mandataire-2b7e1516";
/** Clé que le mandataire LiteLLM présente au simulateur quand il est derrière la passerelle (topologie 1) : fictive, sans valeur. */
export const CLE_FOURNISSEUR_MANDATAIRE = "cle-fournisseur-fictive-integration";
export const ALIAS_SDK = "agent-py";
export const BIN_CTL = path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace-ctl");
export const VERIFICATEUR_JS = path.join(RACINE, "scripts", "verify", "dossier.mjs");

function portLibre() {
  return new Promise((resoudre, rejeter) => {
    const s = net.createServer();
    s.once("error", rejeter);
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => resoudre(p));
    });
  });
}

const ESSAIS_PORTS = 5;

/**
 * Décision du service simulé, lue sur les arguments comme les règles de la
 * politique `demo-2026-12` (demo/configuration-demo.json) : lectures
 * autorisées, paiement hors CHF refusé, paiement de 0 à 5000 CHF autorisé,
 * au-delà soumis aux approbateurs ; un outil local déclaré par le SDK (alias
 * `agent-py`, hors de la démonstration) : `*approuver*` soumis, sinon autorisé.
 */
export function deciderDemo(r) {
  const nom = r.tool_announced ?? "";
  if (nom === "demo__claims.get" || nom === "demo__claims.search") return { decision: "autorise", rule: "lecture autorisee" };
  if (nom === "demo__payments.create") {
    const a = r.arguments ?? {};
    if (a.currency === undefined && a.amount === undefined) return { decision: "a_approuver", rule: "montant > 5000" };
    if (a.currency !== "CHF") return { decision: "refuse", rule: "paiement hors CHF" };
    if (Number(a.amount) > 0 && Number(a.amount) <= 5000) return { decision: "autorise", rule: "paiement <= 5000 CHF" };
    return { decision: "a_approuver", rule: "montant > 5000" };
  }
  if (nom.startsWith(`${ALIAS_SDK}__`)) return nom.includes("approuver") ? { decision: "a_approuver", rule: "revue des essais" } : { decision: "autorise", rule: "lecture autorisee" };
  return { decision: "a_approuver", rule: "defaut : revue" };
}

/** Vérificateur Go de CT-6 : NOORTRACE_VERIFIER_BIN, ou verificateur/dist/, ou null. */
export function binaireGo() {
  for (const c of [process.env.NOORTRACE_VERIFIER_BIN, path.join(RACINE, "verificateur", "dist", "noortrace-verifier-linux-amd64")]) if (c && fs.existsSync(c)) return c;
  return null;
}

/** `unshare -rn` est-il utilisable (espace de noms réseau sans privilège) ? */
export function unshareDisponible() {
  const r = spawnSync("unshare", ["-rn", "true"], { encoding: "utf8", timeout: 10000 });
  return r.status === 0;
}

/**
 * Lance un vérificateur sur un dossier, sans réseau quand `unshare -rn` est
 * disponible ; rend `{ code, rapport, stderr, sans_reseau }`.
 */
export function verifierDossier(commande, dossier, o = {}) {
  const sansReseau = o.sansReseau ?? unshareDisponible();
  const args = [...commande, dossier, "--json", ...(o.ancres ? ["--ancres", o.ancres] : [])];
  const r = sansReseau ? spawnSync("unshare", ["-rn", ...args], { cwd: RACINE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 120000 }) : spawnSync(args[0], args.slice(1), { cwd: RACINE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 120000 });
  let rapport = null;
  try {
    rapport = JSON.parse(r.stdout);
  } catch {
    rapport = null;
  }
  return { code: r.status, rapport, stderr: (r.stderr ?? "").slice(0, 4000), sans_reseau: sansReseau };
}

async function principal() {
  const { ServiceSimule } = await import("../enregistreur-politique/outils.mjs");
  const { configurationExemple, repertoireTemporaire } = await import("../enregistreur-coeur/outils.mjs");
  const { creerServeur: creerOutilsDemo } = await import(pathToFileURL(path.join(RACINE, "conteneurs", "outils-demo", "outils-demo.mjs")).href);
  const { creerServeur: creerModeleDemo } = await import(pathToFileURL(path.join(RACINE, "conteneurs", "modele-demo", "modele-demo.mjs")).href);
  const { SimulateurFormats } = await import("./simulateur-formats.mjs");
  const { lireEvenements, validerConfiguration } = await import("@noortrace/enregistreur");
  const BIN_NOORTRACE = path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace");

  const dir = repertoireTemporaire("noortrace-integration-");
  for (const d of ["p", "cles", "stockage", "bail", "exports"]) fs.mkdirSync(path.join(dir, d), { recursive: true, mode: 0o700 });
  const ecrire = (o) => process.stdout.write(JSON.stringify(o) + "\n");

  // Services de la démonstration, dans ce processus.
  const outils = creerOutilsDemo();
  await new Promise((r) => outils.serveur.listen(0, "127.0.0.1", r));
  const urlOutils = `http://127.0.0.1:${outils.serveur.address().port}`;
  const modeleDemo = creerModeleDemo();
  await new Promise((r) => modeleDemo.serveur.listen(0, "127.0.0.1", r));
  const urlModeleDemo = `http://127.0.0.1:${modeleDemo.serveur.address().port}`;
  const formats = await new SimulateurFormats().demarrer();

  // Configuration de démonstration (CT-2 §19.1), ramenée à l'hôte.
  const config = JSON.parse(fs.readFileSync(path.join(RACINE, "demo", "configuration-demo.json"), "utf8"));
  const exemple = configurationExemple();
  fs.copyFileSync(path.join(RACINE, "demo", "cle-rec-test-01.pem"), path.join(dir, "cles", "rec-test-01.pem"));
  fs.chmodSync(path.join(dir, "cles", "rec-test-01.pem"), 0o600);
  config.recorder.instance_id = "enregistreur-integration-1";
  let portMcp = await portLibre();
  let portModele = await portLibre();
  config.mcp.socket = path.join(dir, "p", "mcp.sock");
  config.mcp.http.listen = `127.0.0.1:${portMcp}`;
  config.model.listen = `127.0.0.1:${portModele}`;
  config.sdk = {
    enabled: true,
    socket: path.join(dir, "p", "sdk.sock"),
    tcp_listen: null,
    hosts: [
      {
        id: ALIAS_SDK,
        match: { peer_user: os.userInfo().username },
        launched_by: "${peer_user}",
        scope: "sinistres:lecture,paiement",
        on_behalf_of: null,
        accept_declared_delegation: true,
        allowed_on_behalf_of: ["service-sinistres"],
        tool_name_template: "{tool_announced}",
        tool_name_sanitize: false,
        prompt_version_name: null,
        host_group: "demo",
        quota: { max_concurrent: 32, piece_bytes_per_minute: 268435456, received_bytes_per_minute: 268435456, redaction_ms_per_minute: 30000 },
        alias: ALIAS_SDK,
      },
    ],
  };
  config.policy.sdk = { aliases: [ALIAS_SDK] };
  config.signer.backend.path = path.join(dir, "cles", "rec-test-01.pem");
  config.storage.root = path.join(dir, "stockage");
  config.storage.min_free_bytes = 1024;
  config.lease.store.path = path.join(dir, "bail", "verrou");
  config.anchoring = { registry: { enabled: false, rpc_url: null, chain_key: null, next_chain_key: null }, rfc3161: { enabled: false, url: null }, opentimestamps: { enabled: false, calendars: [] }, ancrage: null };
  config.supervision.health_listen = "127.0.0.1:0";
  config.supervision.ops_log.path = path.join(dir, "exploitation.ndjson");
  config.supervision.ops_log.level = "debug";
  config.exports_dir = path.join(dir, "exports");
  config.policy.servers.demo.transport.url = `${urlOutils}/mcp`;
  // Ingestion OpenTelemetry (CT-2 6.8.15, exemple de 15.3), groupe d'hôte de la démonstration.
  config.otel = { ...exemple.otel, listen: "127.0.0.1:0", tls: null, static_tokens: [{ id: "otel-agent-sinistres", token: { env: "NOORTRACE_INTEGRATION_JETON_OTEL" } }] };
  config.otel.hosts = exemple.otel.hosts.map((h) => ({ ...h, host_group: "demo" }));
  // Borne facultative d'EX-6.40 (6), posée pour que TI-11 éprouve le 413 (CT-9 TI-11, pas 1).
  config.otel.spans_per_request = 16;
  config.policy.otel = exemple.policy.otel;

  // Service d'approbation simulé (CT-3 §12), qui joue aussi approbateur-demo.
  class ServiceDemo extends ServiceSimule {
    constructor(p) {
      super(p);
      this.automatique = true;
      this.delaiApprobationMs = 300;
      this.decides = [];
    }

    async ouvrir(r) {
      const x = await super.ouvrir(r);
      if (this.automatique) {
        setTimeout(() => {
          const t = this.tickets.get(r.ticket);
          if (!t || t.etat !== "ouvert") return;
          // Comptes Hardhat 1 et 2 (CT-2 §19.2 pas 6), seuil 2 sur 3.
          this.decider_ticket(r.ticket, { signataires: [0, 1] });
          this.decides.push({ ticket: r.ticket, decision: "approuve", approvers: [0, 1] });
        }, this.delaiApprobationMs).unref?.();
      }
      return x;
    }
  }
  const service = new ServiceDemo({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id, decider: deciderDemo, jeton: JETON_APPROBATION });
  await service.servirHttp(0);
  config.policy.approval.service = { url: `http://127.0.0.1:${service.serveurHttp.address().port}`, socket: null, token: { env: "NOORTRACE_INTEGRATION_JETON_APPROBATION" }, peer_user: null };

  // Mandataire LiteLLM (CT-2 EX-6.22), au choix de l'environnement.
  const topologie = process.env.NOORTRACE_INTEGRATION_MANDATAIRE ?? null;
  const litellm = process.env.NOORTRACE_INTEGRATION_LITELLM ?? null;
  if (topologie && !litellm) throw new Error("NOORTRACE_INTEGRATION_MANDATAIRE sans NOORTRACE_INTEGRATION_LITELLM");
  let mandataire = null;
  let urlMandataire = null;
  async function lancerMandataire(apiBase, apiKey) {
    const fichier = path.join(dir, "litellm-mandataire.yaml");
    fs.writeFileSync(fichier, `model_list:\n  - model_name: modele-demo-1\n    litellm_params:\n      model: openai/modele-demo-1\n      api_base: ${apiBase}\n      api_key: ${apiKey}\n`);
    process.on("exit", () => mandataire?.kill("SIGKILL"));
    for (let essai = 1; ; essai++) {
      const port = await portLibre();
      let erreurs = "";
      mandataire = spawn(litellm, ["--config", fichier, "--host", "127.0.0.1", "--port", String(port)], {
        env: { ...process.env, LITELLM_MASTER_KEY: CLE_MANDATAIRE, LITELLM_LOG: "ERROR" },
        stdio: ["ignore", "ignore", "pipe"],
      });
      const m = mandataire;
      m.stderr.on("data", (x) => (erreurs = (erreurs + x.toString("utf8")).slice(-20000)));
      const ferme = new Promise((r) => m.once("close", () => r()));
      const url = `http://127.0.0.1:${port}`;
      const fin = Date.now() + 180000;
      let pret = false;
      for (;;) {
        pret = await new Promise((r) => {
          const q = http.get(`${url}/health/liveliness`, (res) => {
            res.resume();
            r(res.statusCode === 200);
          });
          q.on("error", () => r(false));
        });
        if (pret || m.exitCode !== null || Date.now() > fin) break;
        await new Promise((r) => setTimeout(r, 250));
      }
      if (pret) return url;
      if (m.exitCode !== null) await ferme;
      if (m.exitCode !== null && essai < ESSAIS_PORTS && /address already in use|EADDRINUSE|Errno 98/i.test(erreurs)) continue;
      m.kill("SIGKILL");
      throw new Error(`mandataire LiteLLM non demarre : ${erreurs.slice(-2000)}`);
    }
  }
  let amontChat = formats.url;
  let secretChat = CLE_MODELE;
  if (topologie === "derriere") {
    urlMandataire = await lancerMandataire(`${formats.url}/v1`, CLE_FOURNISSEUR_MANDATAIRE);
    amontChat = urlMandataire;
    secretChat = CLE_MANDATAIRE;
  }
  // Routes de 15.3 : celle de la démonstration (API Messages, modele-demo), puis les formats de §19.5.
  config.policy.model.routes = [
    { path: "/v1/messages", format: "anthropic-messages", upstream: urlModeleDemo, provider_label: "demo", credentials: "propre", secret: { env: "NOORTRACE_DEMO_CLE_MODELE" }, auth_header: "x-api-key", passthrough: [] },
    { path: "/v1/chat/completions", format: "openai-chat", upstream: amontChat, provider_label: "openai", credentials: "propre", secret: { env: "NOORTRACE_INTEGRATION_CLE_CHAT" }, auth_header: "authorization-bearer", passthrough: [] },
    { path: "/v1/responses", format: "openai-responses", upstream: formats.url, provider_label: "openai", credentials: "propre", secret: { env: "NOORTRACE_DEMO_CLE_MODELE" }, auth_header: "authorization-bearer", passthrough: [] },
    { path: "/v1beta/models", format: "gemini", upstream: formats.url, provider_label: "gemini", credentials: "propre", secret: { env: "NOORTRACE_DEMO_CLE_MODELE" }, auth_header: "x-goog-api-key", provider_mcp: "refuser", passthrough: [] },
  ];

  const env = {
    NOORTRACE_DEMO_JETON_HOTE: JETON_HOTE,
    NOORTRACE_DEMO_JETON_PASSERELLE: JETON_PASSERELLE,
    NOORTRACE_DEMO_CLE_MODELE: CLE_MODELE,
    NOORTRACE_DEMO_CLE_MAC_RELAIS: CLE_MAC_RELAIS,
    NOORTRACE_INTEGRATION_JETON_APPROBATION: JETON_APPROBATION,
    NOORTRACE_INTEGRATION_JETON_OTEL: JETON_OTEL,
    NOORTRACE_INTEGRATION_CLE_CHAT: secretChat,
  };
  const fichierConfig = path.join(dir, "configuration.json");
  const ecrireConfig = () => fs.writeFileSync(fichierConfig, JSON.stringify(config, null, 2));
  ecrireConfig();
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)));
  if (v.erreurs.length) throw new Error(`configuration du banc invalide : ${JSON.stringify(v.erreurs)}`);
  const envDemon = { ...process.env, ...env };
  const repertoireJournal = () => path.join(config.storage.root, config.recorder.org_id.replace(/^0x/, ""), config.recorder.journal_id.replace(/^0x/, ""));

  let demon = null;
  let sortieDemon = "";
  const lignesExploitation = () => {
    try {
      return fs.readFileSync(config.supervision.ops_log.path, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    } catch {
      return [];
    }
  };
  let publie = false;
  let adresses = null;
  async function demarrer() {
    for (let essai = 1; ; essai++) {
      const r = await demarrerUneFois();
      if (r.adresses) {
        publie = true;
        adresses = r.adresses;
        return r.adresses;
      }
      if (essai >= ESSAIS_PORTS) throw new Error(`demon non demarre (adresse prise) : ${sortieDemon}`);
      if (!publie) {
        portMcp = await portLibre();
        portModele = await portLibre();
        config.mcp.http.listen = `127.0.0.1:${portMcp}`;
        config.model.listen = `127.0.0.1:${portModele}`;
        ecrireConfig();
      } else {
        await new Promise((x) => setTimeout(x, 500));
      }
    }
  }
  async function demarrerUneFois() {
    const avant = lignesExploitation().length;
    const debutSortie = sortieDemon.length;
    demon = spawn(process.execPath, [BIN_NOORTRACE, "--config", fichierConfig], { cwd: RACINE, env: envDemon, stdio: ["ignore", "pipe", "pipe"] });
    const d = demon;
    const ferme = new Promise((r) => d.once("close", () => r()));
    d.stdout.on("data", (x) => (sortieDemon += x.toString("utf8")));
    d.stderr.on("data", (x) => (sortieDemon += x.toString("utf8")));
    const fin = Date.now() + 60000;
    for (;;) {
      const lignes = lignesExploitation().slice(avant);
      const passerelle = lignes.find((l) => l.event === "model_gateway_listening");
      const sdk = lignes.find((l) => l.event === "sdk_listening");
      const otel = lignes.find((l) => l.event === "otel_listening");
      if (passerelle && sdk && otel && /demon demarre/.test(sortieDemon.slice(debutSortie))) {
        while (!service.versions.has(config.policy.version) && Date.now() < fin) await new Promise((r) => setTimeout(r, 20));
        return { adresses: { passerelle: `http://${passerelle.data?.address}`, otel: `http://${otel.data?.address}${config.otel.path}` } };
      }
      if (d.exitCode !== null) {
        await ferme;
        if (/EADDRINUSE/.test(sortieDemon.slice(debutSortie))) return { adresseOccupee: true };
        throw new Error(`demon non demarre : ${sortieDemon}`);
      }
      if (Date.now() > fin) throw new Error(`demon non demarre : ${sortieDemon}`);
      await new Promise((r) => setTimeout(r, 25));
    }
  }
  async function arreter(signal = "SIGTERM") {
    const d = demon;
    demon = null;
    if (!d || d.exitCode !== null) return;
    const fini = new Promise((r) => d.once("exit", r));
    d.kill(signal);
    await fini;
  }

  await demarrer();
  if (topologie === "devant") urlMandataire = await lancerMandataire(`${adresses.passerelle}/v1`, JETON_PASSERELLE);

  ecrire({
    pret: true,
    dir,
    configuration: fichierConfig,
    racine: RACINE,
    socket_sdk: config.sdk.socket,
    alias_sdk: ALIAS_SDK,
    mcp_url: `http://127.0.0.1:${portMcp}/mcp`,
    mcp_jeton: JETON_HOTE,
    passerelle_url: adresses.passerelle,
    passerelle_jeton: JETON_PASSERELLE,
    otel_url: adresses.otel,
    otel_jeton: JETON_OTEL,
    mandataire_url: urlMandataire,
    mandataire_cle: urlMandataire ? CLE_MANDATAIRE : null,
    topologie,
    outils_url: urlOutils,
    modele_demo_url: urlModeleDemo,
    formats_url: formats.url,
    service_url: config.policy.approval.service.url,
    exports: config.exports_dir,
    journal: repertoireJournal(),
    org_id: config.recorder.org_id,
    journal_id: config.recorder.journal_id,
    policy_version: config.policy.version,
    go: binaireGo(),
    unshare: unshareDisponible(),
  });

  /** Exécute noortrace-ctl et attend la ligne de réponse du journal d'exploitation. */
  function ctl(args) {
    const r = spawnSync(process.execPath, [BIN_CTL, ...args, "--configuration", fichierConfig], { cwd: RACINE, env: envDemon, encoding: "utf8", timeout: 180000 });
    return { code: r.status, stdout: (r.stdout ?? "").slice(-4000), stderr: (r.stderr ?? "").slice(-4000) };
  }

  const lecteur = readline.createInterface({ input: process.stdin });
  let file = Promise.resolve();
  lecteur.on("line", (ligne) => {
    file = file.then(async () => {
      let m;
      try {
        m = JSON.parse(ligne);
      } catch {
        return ecrire({ erreur: "ligne illisible" });
      }
      try {
        switch (m.cmd) {
          case "arreter":
            await arreter();
            return ecrire({ ok: true });
          case "tuer":
            await arreter("SIGKILL");
            return ecrire({ ok: true });
          case "demarrer":
            await demarrer();
            return ecrire({ ok: true });
          case "evenements":
            return ecrire({ ok: true, evenements: await lireEvenements(repertoireJournal()) });
          case "exploitation":
            return ecrire({ ok: true, lignes: lignesExploitation().filter((l) => !m.event || l.event === m.event) });
          case "requetes":
            return ecrire({ ok: true, formats: formats.requetes.map((r) => ({ n: r.n, cible: r.cible, format: r.format, etape: r.etape, reemission: r.reemission, etat: r.etat, corps: r.corps, entetes: r.entetes })) });
          case "usage": {
            const u = (map) => [...map.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, n]) => ({ key_sha256_16: k.split(" ")[0], route: k.split(" ")[1], requests: n }));
            return ecrire({ ok: true, modele_demo: u(modeleDemo.usage), formats: u(formats.usage) });
          }
          case "appels_outils":
            return ecrire({ ok: true, appels: outils.etat.appels, paiements: outils.etat.paiements });
          case "approbations":
            return ecrire({ ok: true, decides: service.decides, automatique: service.automatique });
          case "approbateur":
            service.automatique = m.automatique !== false;
            return ecrire({ ok: true, automatique: service.automatique });
          case "pieces": {
            const racine = path.join(repertoireJournal(), "pieces");
            const lire = (sha) => {
              const h = String(sha).replace(/^0x/, "");
              for (const c of [path.join(racine, h), path.join(racine, h.slice(0, 2), h), path.join(racine, h.slice(0, 2), h.slice(2, 4), h)]) if (fs.existsSync(c)) return fs.readFileSync(c, "utf8");
              const trouve = fs.readdirSync(racine, { recursive: true }).find((f) => path.basename(f) === h || path.basename(f).startsWith(h));
              return trouve ? fs.readFileSync(path.join(racine, trouve), "utf8") : null;
            };
            return ecrire({ ok: true, pieces: Object.fromEntries((m.sha256 ?? []).map((s) => [s, lire(s)])) });
          }
          case "cloturer": {
            const r = ctl(["close-period", "--now"]);
            const l = lignesExploitation().filter((x) => ["period_closed_early", "period_close_refused"].includes(x.event)).at(-1) ?? null;
            return ecrire({ ok: true, ...r, ligne: l });
          }
          case "exporter": {
            const destination = path.join(config.exports_dir, `dossier-seq-${m.seq}`);
            const r = ctl(["dossier", "exporter", "--seq", String(m.seq), "--vers", destination]);
            const l = lignesExploitation().filter((x) => ["dossier_exported", "dossier_export_refused"].includes(x.event)).at(-1) ?? null;
            return ecrire({ ok: true, ...r, destination, ligne: l });
          }
          case "verifier": {
            const js = verifierDossier([process.execPath, VERIFICATEUR_JS], m.dossier, { ancres: m.ancres });
            const bin = binaireGo();
            const go = bin ? verifierDossier([bin], m.dossier, { ancres: m.ancres }) : null;
            return ecrire({ ok: true, js, go });
          }
          default:
            return ecrire({ erreur: `commande inconnue : ${m.cmd}` });
        }
      } catch (e) {
        return ecrire({ erreur: String(e?.stack ?? e).slice(0, 4000), sortie_demon: sortieDemon.slice(-4000) });
      }
    });
  });
  lecteur.on("close", async () => {
    await file.catch(() => {});
    await arreter();
    service.liberer();
    service.serveurHttp?.close();
    outils.serveur.closeAllConnections?.();
    outils.serveur.close();
    modeleDemo.serveur.closeAllConnections?.();
    modeleDemo.serveur.close();
    await formats.arreter();
    mandataire?.kill("SIGTERM");
    if (!process.env.NOORTRACE_ESSAI_GARDER) fs.rmSync(dir, { recursive: true, force: true });
    process.exit(0);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  principal().catch((e) => {
    process.stdout.write(JSON.stringify({ pret: false, erreur: String(e?.stack ?? e) }) + "\n");
    process.exit(2);
  });
}
