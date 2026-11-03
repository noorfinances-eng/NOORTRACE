#!/usr/bin/env node
// Banc d'essai du SDK Python et des adaptateurs de cadres (CT-2 6.4 à 6.6) :
// le démon réel `bin/noortrace` lancé comme processus, avec
//   - le point d'entrée SDK sur une prise Unix (entrée de `sdk.hosts` de
//     l'utilisateur courant, alias `agent-py`, `policy.sdk.aliases`) ;
//   - le frontal MCP en Streamable HTTP (jeton statique de test) devant le
//     vrai serveur d'outils stdio de test (`../enregistreur-mcp/serveur-outils.mjs`,
//     alias `demo`, noms annoncés `demo__claims_get`, … : `tool_name_sanitize`) ;
//   - le service d'approbation simulé de `../enregistreur-politique/outils.mjs`
//     servi en HTTP (CT-3 §12.1), dont la décision d'un outil du SDK suit son
//     nom : `*approuver*` → `a_approuver`, `*refuser*` → `refuse`, sinon
//     `autorise` ;
//   - la passerelle de modèle devant le fournisseur simulé de
//     `../enregistreur-modele/fournisseur.mjs` (route `/v1/chat/completions`,
//     format `openai-chat`), pour les agents dont le modèle passe par la
//     passerelle (`modele="passerelle"`, EX-6.17).
//
// NOORTRACE_ESSAI_MANDATAIRE : exécutable `litellm` (extra `proxy`) ; la
// passerelle a alors pour amont un mandataire LiteLLM devant le fournisseur
// simulé (EX-6.22, disposition (a)).
// NOORTRACE_ESSAI_POLITIQUE (`pii-v1`, `pii-pseudo-test`) : politique de
// rédaction et options de la passerelle des vecteurs de l'annexe B.
//
// Il écrit une ligne JSON `{"pret": true, …}` (adresses, jetons, répertoire),
// puis lit des commandes JSON, une par ligne, sur son entrée standard et
// répond par une ligne JSON :
//   {"cmd": "arreter"}            arrêt du démon (SIGTERM), le banc reste ;
//   {"cmd": "tuer"}               arrêt brutal du démon (SIGKILL) ;
//   {"cmd": "demarrer"}           relance du démon sur le même stockage ;
//   {"cmd": "evenements"}         événements du journal (lecture des segments) ;
//   {"cmd": "exploitation", "event": "<nom>"}   lignes du journal d'exploitation ;
//   {"cmd": "scenario", "reponses": [<corps>…]} réponses suivantes du fournisseur simulé ;
//   {"cmd": "verifier", "seq": <n>, "dossier": "<rép.>"}
//        copie du stockage (démon arrêté puis relancé), clôture de la période
//        sur la copie par un cœur relancé une heure plus tard, journal vérifié
//        par `N.verifierJournal`, dossier de l'événement `seq` exporté et
//        vérifié par le noyau et, si go1.27.3 est présent (NOORTRACE_GO_BIN, à
//        défaut PATH), par le binaire Go `noortrace-verifier`.
// À la fermeture de son entrée, il arrête tout et retire son répertoire.
// Importé sans être lancé (le chargeur des tests lit les fichiers .mjs), il ne fait rien.

import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { spawn, spawnSync, execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const ICI = path.dirname(fileURLToPath(import.meta.url));
export const ALIAS_SDK = "agent-py";
export const JETON_MCP = "jeton-mcp-essai-sdk-python-0001";
export const JETON_MODELE = "jeton-passerelle-essai-sdk-python-0001";

/** Port TCP libre sur 127.0.0.1. */
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

/** Décision du service simulé pour une demande (CT-3 §12, réponse d'`evaluer`). */
export function deciderBanc(r) {
  const nom = r.tool_announced ?? "";
  if (nom.includes("approuver")) return { decision: "a_approuver", rule: "revue des essais" };
  if (nom.includes("refuser")) return { decision: "refuse", rule: "refus des essais" };
  return { decision: "autorise", rule: "defaut : autorise" };
}

/** go1.27.3 et le binaire `noortrace-verifier` construit, ou null. */
function construireVerificateur(racine, dir) {
  const dirGo = process.env.NOORTRACE_GO_BIN ?? null;
  const env = { ...process.env, GOFLAGS: "-mod=vendor", GOTOOLCHAIN: "local" };
  if (dirGo) env.PATH = `${dirGo}${path.delimiter}${env.PATH}`;
  const v = spawnSync("go", ["version"], { env, encoding: "utf8" });
  if (v.status !== 0 || !/go1\.27\.3 /.test(v.stdout)) return null;
  const sortie = path.join(dir, "noortrace-verifier");
  if (!fs.existsSync(sortie)) execFileSync(path.join(racine, "verificateur", "scripts", "construire.sh"), ["-o", sortie], { env, cwd: path.join(racine, "verificateur"), stdio: "pipe" });
  return sortie;
}

async function principal() {
  const { configurationDev, repertoireTemporaire, secretsDev, RACINE, BIN_NOORTRACE, VECTEURS_CT2 } = await import("../enregistreur-coeur/outils.mjs");
  const { ServiceSimule, politiqueApprobationTest } = await import("../enregistreur-politique/outils.mjs");
  const { FournisseurSimule } = await import("../enregistreur-modele/fournisseur.mjs");
  const { Coeur, HorlogeReglable, lireEvenements, validerConfiguration } = await import("@noortrace/enregistreur");
  const N = await import("@noortrace/noyau");
  const { verifierRepertoireDossier } = await import("@noortrace/noyau/dossier-fichiers");

  const dir = repertoireTemporaire("noortrace-sdkpy-");
  const ecrire = (o) => process.stdout.write(JSON.stringify(o) + "\n");

  // Fournisseur simulé et service d'approbation simulé (dans ce processus).
  const fournisseur = await new FournisseurSimule({ pauseMs: 1 }).demarrer();
  const { config: base, env } = configurationDev(dir, {
    mcp: true,
    modele: true,
    sdk: {
      hosts: [
        {
          id: "agent-py",
          match: { peer_user: os.userInfo().username },
          launched_by: "${peer_user}",
          scope: "sinistres:lecture,paiement",
          on_behalf_of: null,
          accept_declared_delegation: true,
          allowed_on_behalf_of: ["service-sinistres"],
          tool_name_template: "{tool_announced}",
          tool_name_sanitize: false,
          prompt_version_name: null,
          host_group: "agent-sinistres",
          quota: { max_concurrent: 32, piece_bytes_per_minute: 268435456, received_bytes_per_minute: 268435456, redaction_ms_per_minute: 30000 },
          alias: ALIAS_SDK,
        },
      ],
    },
  });
  const config = base;
  const service = new ServiceSimule({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id, decider: deciderBanc });
  await service.servirHttp(0);
  const portService = service.serveurHttp.address().port;
  const portMcp = await portLibre();
  // Ports fixés pour la durée du banc : le démon relancé garde les mêmes adresses.
  const portModele = await portLibre();

  // Prises sous un chemin court (EX-6.10 : au plus 103 octets).
  config.sdk.socket = path.join(dir, "p", "sdk.sock");
  config.mcp.socket = path.join(dir, "p", "mcp.sock");
  config.mcp.http = { listen: `127.0.0.1:${portMcp}`, path: "/mcp", allowed_origins: [], tls: null, oauth: null, static_tokens: [{ id: "agent-mcp", token: { env: "NOORTRACE_ESSAI_JETON_MCP" } }] };
  config.mcp.hosts = [
    {
      id: "agent-mcp",
      match: { static_token: "agent-mcp" },
      launched_by: "agent-sinistres",
      scope: "sinistres:lecture,paiement",
      on_behalf_of: null,
      accept_declared_delegation: true,
      allowed_on_behalf_of: ["service-sinistres"],
      tool_name_template: "{tool_announced}",
      tool_name_sanitize: true,
      prompt_version_name: null,
      host_group: "agent-sinistres",
      quota: { max_concurrent: 32, piece_bytes_per_minute: 268435456, received_bytes_per_minute: 268435456, redaction_ms_per_minute: 30000 },
      alias: null,
    },
  ];
  config.mcp.connector_tcp = null;
  config.policy.servers = {
    demo: {
      transport: { type: "stdio", command: [process.execPath, path.join(ICI, "..", "enregistreur-mcp", "serveur-outils.mjs")], cwd: null, env: {}, sandbox: null, user: null, integrity: null },
      protocol: "auto",
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
  // Passerelle : route openai-chat vers le fournisseur simulé, jeton statique de l'agent.
  config.model.listen = `127.0.0.1:${portModele}`;
  config.model.hosts = [
    {
      id: "agent-modele",
      match: { static_token: "agent-modele" },
      launched_by: "agent-sinistres",
      scope: "sinistres:lecture",
      on_behalf_of: null,
      accept_declared_delegation: true,
      allowed_on_behalf_of: ["service-sinistres"],
      tool_name_template: "{tool_announced}",
      tool_name_sanitize: true,
      prompt_version_name: null,
      host_group: "agent-sinistres",
      quota: { max_concurrent: 32, piece_bytes_per_minute: 268435456, received_bytes_per_minute: 268435456, redaction_ms_per_minute: 30000 },
      alias: null,
    },
  ];
  config.model.static_tokens = [{ id: "agent-modele", token: { env: "NOORTRACE_ESSAI_JETON_MODELE" } }];
  // EX-6.22, disposition (a) : agent → passerelle → mandataire LiteLLM → fournisseur simulé.
  // NOORTRACE_ESSAI_MANDATAIRE : exécutable `litellm` de l'environnement du mandataire ;
  // la route de la passerelle a alors pour amont l'URL du mandataire, et le secret de la
  // route est la clé maîtresse du mandataire (jeton de test, sans valeur).
  let amont = fournisseur.url;
  let mandataire = null;
  const CLE_MANDATAIRE = "sk-noortrace-essai-mandataire-7f3a9c2e5b1d8f4a";
  if (process.env.NOORTRACE_ESSAI_MANDATAIRE) {
    const portMandataire = await portLibre();
    const fichier = path.join(dir, "litellm-mandataire.yaml");
    fs.writeFileSync(fichier, `model_list:\n  - model_name: modele-chat\n    litellm_params:\n      model: openai/modele-chat\n      api_base: ${fournisseur.url}/v1\n      api_key: cle-fournisseur-fictive-essai\n`);
    mandataire = spawn(process.env.NOORTRACE_ESSAI_MANDATAIRE, ["--config", fichier, "--host", "127.0.0.1", "--port", String(portMandataire)], {
      env: { ...process.env, LITELLM_MASTER_KEY: CLE_MANDATAIRE, LITELLM_LOG: "ERROR" },
      stdio: ["ignore", "ignore", "ignore"],
    });
    process.on("exit", () => mandataire?.kill("SIGKILL"));
    amont = `http://127.0.0.1:${portMandataire}`;
    const fin = Date.now() + 120000;
    for (;;) {
      const pret = await new Promise((r) => {
        const q = http.get(`${amont}/health/liveliness`, (res) => {
          res.resume();
          r(res.statusCode === 200);
        });
        q.on("error", () => r(false));
      });
      if (pret) break;
      if (mandataire.exitCode !== null || Date.now() > fin) throw new Error("mandataire LiteLLM non demarre");
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  config.policy.model = {
    routes: [
      { path: "/v1/chat/completions", format: "openai-chat", upstream: amont, provider_label: "openai", credentials: "propre", secret: { env: "NOORTRACE_ESSAI_CLE_FOURNISSEUR" }, auth_header: "authorization-bearer", passthrough: [] },
    ],
  };
  config.policy.version = "essai-sdk-python-1";
  config.policy.approval.rules = politiqueApprobationTest();
  config.policy.approval.mode = "erreur";
  config.policy.approval.timeout_ms = 2000;
  // EX-18.8 : en HTTP, le noyau s'authentifie auprès du service par un jeton.
  config.policy.approval.service = { url: `http://127.0.0.1:${portService}`, socket: null, token: { env: "NOORTRACE_ESSAI_JETON_APPROBATION" }, peer_user: null };
  config.policy.failure.approval_service = { ecriture: "bloquant", lecture: "passant" };
  config.supervision.ops_log.level = "debug";
  if (config.otel) config.otel.enabled = false;
  // Rejeu des vecteurs de l'annexe B par le SDK Python (EX-6.5) : politique de
  // rédaction des vecteurs (`pii-v1` ou `pii-pseudo-test`, B.3) et options de
  // la passerelle des cas `pieces-modele` (`prompt_in_request: "reference"`,
  // `prompt_system: "redige"`), choisies par NOORTRACE_ESSAI_POLITIQUE.
  const politique = process.env.NOORTRACE_ESSAI_POLITIQUE ?? null;
  if (politique) {
    const fichiers = { "pii-v1": "politique-pii-v1.json", "pii-pseudo-test": "politique-pseudonyme-test.json" };
    if (!fichiers[politique]) throw new Error(`politique de vecteurs inconnue : ${politique}`);
    config.policy.redaction = JSON.parse(fs.readFileSync(path.join(VECTEURS_CT2, "redaction", fichiers[politique]), "utf8"));
    config.policy.version = `essai-sdk-python-${politique}`;
    config.model.prompt_in_request = "reference";
    config.model.prompt_system = "redige";
    // Clé de pseudonymisation de test (INDEX.md des vecteurs CT-2), sans valeur.
    env.NOORTRACE_VECTEURS_CLE_PSEUDO = "139011dc372b3ce979a162b0dee18753e67e1477ea4db3c55f929829c2ca3808";
  }
  env.NOORTRACE_ESSAI_JETON_MCP = JETON_MCP;
  env.NOORTRACE_ESSAI_JETON_APPROBATION = "jeton-noyau-essai";
  env.NOORTRACE_ESSAI_JETON_MODELE = JETON_MODELE;
  env.NOORTRACE_ESSAI_CLE_FOURNISSEUR = mandataire ? CLE_MANDATAIRE : "cle-fournisseur-fictive-essai";

  const fichierConfig = path.join(dir, "configuration.json");
  fs.writeFileSync(fichierConfig, JSON.stringify(config, null, 2));
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)));
  if (v.erreurs.length) throw new Error(`configuration du banc invalide : ${JSON.stringify(v.erreurs)}`);
  const envDemon = { ...process.env, ...env };
  const repertoireJournal = () => {
    const org = config.recorder.org_id.replace(/^0x/, "");
    const jid = config.recorder.journal_id.replace(/^0x/, "");
    return path.join(config.storage.root, org, jid);
  };

  let demon = null;
  let sortieDemon = "";
  const lignesExploitation = () => {
    try {
      return fs.readFileSync(config.supervision.ops_log.path, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    } catch {
      return [];
    }
  };
  async function demarrer() {
    const avant = lignesExploitation().length;
    demon = spawn(process.execPath, [BIN_NOORTRACE, "--config", fichierConfig], { env: envDemon, stdio: ["ignore", "pipe", "pipe"] });
    const d = demon;
    d.stdout.on("data", (x) => (sortieDemon += x.toString("utf8")));
    d.stderr.on("data", (x) => (sortieDemon += x.toString("utf8")));
    const fin = Date.now() + 30000;
    for (;;) {
      const lignes = lignesExploitation().slice(avant);
      const passerelle = lignes.find((l) => l.event === "model_gateway_listening");
      const sdk = lignes.find((l) => l.event === "sdk_listening");
      if (passerelle && sdk && /demon demarre/.test(sortieDemon)) {
        // Le service simulé a reçu `charger` (EX-7.15) avant le premier appel.
        while (!service.versions.has(config.policy.version) && Date.now() < fin) await new Promise((r) => setTimeout(r, 20));
        return { passerelle: `http://${passerelle.data?.address}` };
      }
      if (d.exitCode !== null || Date.now() > fin) throw new Error(`demon non demarre : ${sortieDemon}`);
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

  const adresses = await demarrer();
  ecrire({
    pret: true,
    dir,
    socket: config.sdk.socket,
    alias: ALIAS_SDK,
    mcp_url: `http://127.0.0.1:${portMcp}/mcp`,
    mcp_jeton: JETON_MCP,
    passerelle_url: adresses.passerelle,
    passerelle_jeton: JETON_MODELE,
    mandataire_url: mandataire ? amont : null,
    journal: repertoireJournal(),
    intentions: path.join(repertoireJournal(), "intentions"),
  });

  let verifications = 0;
  async function verifier(seq, destination) {
    // Copie du stockage, démon arrêté (segments complets), puis démon relancé :
    // la période est close sur la copie seulement, par un cœur relancé une
    // heure plus tard (horloge réglable), sans toucher à l'horloge du journal vivant.
    await arreter();
    const copie = path.join(dir, `verification-${++verifications}`);
    fs.cpSync(config.storage.root, path.join(copie, "stockage"), { recursive: true });
    // Le verrou du bail et son époque suivent la copie (EX-13.5 : époque supérieure aux segments).
    fs.cpSync(path.dirname(config.lease.store.path), path.join(copie, "bail"), { recursive: true });
    await demarrer();
    const org = config.recorder.org_id.replace(/^0x/, "");
    const jid = config.recorder.journal_id.replace(/^0x/, "");
    const repCopie = path.join(copie, "stockage", org, jid);
    const evts0 = await lireEvenements(repCopie);
    const dernier = evts0[evts0.length - 1];
    const t = N.decoderHorodatage(dernier.ts);
    const debutSuivante = (Math.floor(t / 3600000) + 1) * 3600000 + 2000;
    const horloge = new HorlogeReglable(debutSuivante);
    const c = {
      ...config,
      storage: { ...config.storage, root: path.join(copie, "stockage") },
      lease: { ...config.lease, store: { type: "file", path: path.join(copie, "bail", "verrou") } },
      supervision: { ...config.supervision, health_listen: "127.0.0.1:0", ops_log: { ...config.supervision.ops_log, path: path.join(copie, "exploitation.ndjson") } },
      mcp: { ...config.mcp, enabled: false },
      sdk: { ...config.sdk, enabled: false },
      model: { ...config.model, mode: "desactive" },
    };
    Object.assign(process.env, env);
    const coeur = await Coeur.demarrer({ config: validerConfiguration(new TextEncoder().encode(JSON.stringify(c))).config, secrets: secretsDev(), horloge, service: null });
    await coeur.tic();
    fs.rmSync(destination, { recursive: true, force: true });
    await coeur.exporterDossier(seq, destination);
    const evts = await lireEvenements(repCopie);
    await coeur.arreter();
    const cles = JSON.parse(fs.readFileSync(path.join(destination, "cles.json"), "utf8"));
    const journal = N.verifierJournal(evts, cles);
    const dossier = verifierRepertoireDossier(destination);
    let go = null;
    const bin = construireVerificateur(RACINE, dir);
    if (bin) {
      const r = spawnSync(bin, [destination, "--json"], { encoding: "utf8" });
      let rapport = null;
      try {
        rapport = JSON.parse(r.stdout);
      } catch {
        rapport = null;
      }
      go = { status: r.status, verdict: rapport?.verdict ?? null, failed_checks: rapport?.failed_checks ?? null, controls: rapport?.controls?.map((x) => [x.number, x.status, x.reason ?? null]) ?? null, stderr: r.stderr.slice(0, 2000) };
    }
    return { journal: { valide: journal.valide, diagnostics: journal.diagnostics?.slice(0, 20) ?? null, evenements: evts.length }, dossier: { verdict: dossier.verdict, controles_en_echec: dossier.controles_en_echec }, go };
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
          case "scenario":
            for (const corps of m.reponses ?? []) {
              const octets = JSON.stringify(corps);
              fournisseur.prochaine({ statut: 200, entetes: { "content-type": "application/json", "request-id": "req_essai" }, morceaux: [octets] });
            }
            return ecrire({ ok: true });
          case "requetes_fournisseur":
            return ecrire({ ok: true, requetes: fournisseur.requetes.map((r) => ({ cible: r.cible, corps: r.corps })) });
          case "verifier":
            return ecrire({ ok: true, ...(await verifier(m.seq, m.dossier)) });
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
    await fournisseur.arreter();
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
