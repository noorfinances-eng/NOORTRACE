// Outils des essais de bout en bout des scénarios et des pannes (CT-9 §10.5
// TA-103 à TA-107, TA-96 ; TE-8, TE-9, TE-16 ; TM-36, TM-37) :
//
//   - démonstration de référence (CT-2 §19) lancée par étapes, avec des
//     fichiers de surcharge Compose (demo/pannes/), attaques jouées depuis la
//     position de l'agent, exports et vérification par les deux vérificateurs
//     de CT-6, lecture et écriture des volumes, flux réseau observés ;
//   - horloge pilotable d'un processus Node.js par libfaketime (CT-9 TA-105,
//     précondition : « libfaketime par LD_PRELOAD sur le processus Node, hors
//     binaires Go ») : bibliothèque du paquet Debian 12 `libfaketime`
//     0.9.10-2.1, à empreinte fixée, jamais dans le dépôt, désignée par
//     NOORTRACE_LIBFAKETIME ; sans elle, les essais qui en dépendent sont en
//     attente, condition nommée (CT-9 EX-3.11) ;
//   - mutants des paquets @noortrace/enregistreur et @noortrace/ancrage tels
//     que l'image les porte (CT-9 EX-10.5, EX-10.6) : copie des sources
//     extraites de l'image, un remplacement exact et unique, montée dans le
//     conteneur à la place des sources de l'image ;
//   - rapports de mesure au format $defs/rapport_mesure (CT-9 EX-11.11), hors
//     système de référence : counts_for_targets faux, met null.
//
// Importé sans être lancé, ce module ne fait rien.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { pathToFileURL } from "node:url";
import { Composition, DEMO, RACINE, docker, etatDocker, portLibre, repertoireTemporaire, pause } from "../demonstration/outils.mjs";
import { materielTls } from "../ancrage-composant/outils.mjs";

export { Composition, DEMO, RACINE, docker, etatDocker, portLibre, repertoireTemporaire, pause };

export const PANNES = path.join(DEMO, "pannes");
export const CONFIG_DEMO = JSON.parse(fs.readFileSync(path.join(DEMO, "configuration-demo.json"), "utf8"));
export const ANCRES_DEMO = path.join(DEMO, "ancres-demo.json");
export const IMAGE_ENREGISTREUR = "noortrace/enregistreur:0.1.0";
export const IMAGE_TSA = "noortrace/tsa-interne:0.1.0";

/** Marque un essai « en attente » en nommant sa condition (CT-9 EX-3.11). */
export function enAttente(ctx, condition) {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
}

export const sha256Fichier = (f) => createHash("sha256").update(fs.readFileSync(f)).digest("hex");

// ---------------------------------------------------------------------------
// libfaketime (CT-9 TA-105, CT-8 RB-6, CT-2 §14.2 lignes « Horloge »)
// ---------------------------------------------------------------------------

/**
 * Bibliothèque libfaketime admise : celle du paquet Debian 12
 * `libfaketime_0.9.10-2.1_amd64.deb` (pool/main/f/faketime, publié le
 * 13 août 2022, SHA-256 du paquet dans l'index `Packages` de bookworm), dont
 * `usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1` est extrait. Le
 * téléchargement n'est jamais fait par un essai : la bibliothèque est désignée
 * par NOORTRACE_LIBFAKETIME et son SHA-256 est contrôlé.
 */
export const LIBFAKETIME = Object.freeze({
  variable: "NOORTRACE_LIBFAKETIME",
  paquet: "libfaketime_0.9.10-2.1_amd64.deb",
  sha256_paquet: "b09481e7690680966005330c3f907bba4b5eefc35e1faaea4783cc55655d1150",
  sha256_bibliotheque: "45c4822a7516e9c41ec1b5498b0f08665ba4877330e9e9573c1213d16d6629a0",
  condition: "bibliothèque libfaketime 0.9.10-2.1 (Debian 12, libfaketime.so.1 à SHA-256 45c4822a…6629a0) absente : variable NOORTRACE_LIBFAKETIME",
});

/** La bibliothèque libfaketime à l'empreinte fixée est-elle désignée ? `{ ok, chemin, condition }`. */
export function libfaketime() {
  const chemin = process.env[LIBFAKETIME.variable];
  if (!chemin || !fs.existsSync(chemin)) return { ok: false, chemin: null, condition: LIBFAKETIME.condition };
  const empreinte = sha256Fichier(chemin);
  if (empreinte !== LIBFAKETIME.sha256_bibliotheque) return { ok: false, chemin, condition: `${LIBFAKETIME.condition} ; empreinte lue ${empreinte.slice(0, 8)}…` };
  return { ok: true, chemin, condition: null };
}

/**
 * Horloge murale pilotable d'un processus Node.js préchargé par libfaketime :
 * le décalage est lu dans un fichier à chaque appel (FAKETIME_NO_CACHE), les
 * horloges monotones ne sont pas touchées (DONT_FAKE_MONOTONIC) : c'est la
 * manipulation de l'horloge murale seule, celle que CT-2 EX-7.9 et EX-7.13
 * détectent contre l'horloge monotone.
 */
export class HorlogePilotable {
  /**
   * @param {string} dir répertoire (créé) où le fichier du décalage est écrit
   * @param {string} bibliotheque chemin de libfaketime.so.1 sur l'hôte
   */
  constructor(dir, bibliotheque) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
    this.dir = dir;
    this.fichier = path.join(dir, "decalage.txt");
    this.bibliotheque = path.join(dir, "libfaketime.so.1");
    fs.copyFileSync(bibliotheque, this.bibliotheque);
    fs.chmodSync(this.bibliotheque, 0o644);
    this.placer(0);
  }

  /** Place le décalage de l'horloge murale, en secondes (négatif : recul). */
  placer(secondes) {
    this.decalage = secondes;
    fs.writeFileSync(this.fichier, `${secondes >= 0 ? "+" : "-"}${Math.abs(secondes)}\n`, { mode: 0o644 });
    fs.chmodSync(this.fichier, 0o644);
  }

  /** Variables d'environnement du processus piloté ; `racine` : où le répertoire est monté (défaut : l'hôte). */
  env(racine = this.dir) {
    return { LD_PRELOAD: path.join(racine, "libfaketime.so.1"), FAKETIME_TIMESTAMP_FILE: path.join(racine, "decalage.txt"), FAKETIME_NO_CACHE: "1", DONT_FAKE_MONOTONIC: "1" };
  }
}

// ---------------------------------------------------------------------------
// Vérification d'un dossier par les deux vérificateurs de CT-6 (boîte noire)
// ---------------------------------------------------------------------------

/** Vérificateur Go de CT-6 (`NOORTRACE_VERIFIER_BIN`, `NOORTRACE_GO_BIN`, ou `verificateur/dist/`), ou null. */
export function binaireGo() {
  for (const c of [process.env.NOORTRACE_VERIFIER_BIN, process.env.NOORTRACE_GO_BIN, path.join(RACINE, "verificateur", "dist", "noortrace-verifier-linux-amd64")]) if (c && fs.existsSync(c) && fs.statSync(c).isFile()) return c;
  return null;
}

export const CONDITION_GO = "vérificateur Go de CT-6 (NOORTRACE_VERIFIER_BIN, NOORTRACE_GO_BIN ou verificateur/dist/noortrace-verifier-linux-amd64)";

function lancerVerificateur(commande, args) {
  const r = spawnSync(commande, args, { cwd: RACINE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  let rapport = null;
  try {
    rapport = r.stdout ? JSON.parse(r.stdout) : null;
  } catch {
    rapport = null;
  }
  return { code: r.status, rapport, stderr: r.stderr };
}

/**
 * Vérifie un dossier par le vérificateur JavaScript de référence et par le
 * binaire Go (`go` null sans binaire) ; `ancres` : fichier d'ancres du
 * réviseur, ou null. Rend aussi `memes` : mêmes codes, verdicts, statuts des
 * vérifications et énoncé (CT-6 §6.5), ou null sans binaire.
 */
export function verifierDeux(dossier, { ancres = null } = {}) {
  const args = [dossier, "--json", ...(ancres ? ["--ancres", ancres] : [])];
  const js = lancerVerificateur(process.execPath, [path.join(RACINE, "scripts", "verify", "dossier.mjs"), ...args]);
  const bin = binaireGo();
  const go = bin ? lancerVerificateur(bin, args) : null;
  const statuts = (r) => Object.fromEntries((r?.rapport?.checks ?? []).map((x) => [x.id, x.status]));
  const memes = go
    ? js.code === go.code && js.rapport?.verdict === go.rapport?.verdict && JSON.stringify(statuts(js)) === JSON.stringify(statuts(go)) && JSON.stringify(js.rapport?.statement) === JSON.stringify(go.rapport?.statement)
    : null;
  return { js, go, memes, bin };
}

/** Statuts des vérifications d'un rapport : { id: status }. */
export const statutsDe = (rapport) => Object.fromEntries((rapport?.checks ?? []).map((x) => [x.id, x.status]));

// ---------------------------------------------------------------------------
// Démonstration de référence par étapes, avec surcharges (demo/pannes/)
// ---------------------------------------------------------------------------

/**
 * Composition de la démonstration lue avec des fichiers de surcharge (dans
 * l'ordre, après demo/compose.yaml) et des variables d'environnement
 * supplémentaires (sources des montages liés propres au passage).
 */
export class CompositionPannes extends Composition {
  /** @param {{nom: string, port: number, surcharges?: string[], env?: Record<string, string>}} o */
  constructor(o) {
    super(o);
    this.surcharges = o.surcharges ?? [];
    this.envSupplementaire = o.env ?? {};
  }

  base(fichier = this.fichier) {
    return ["compose", "-p", this.nom, "--project-directory", DEMO, "-f", fichier, ...this.surcharges.flatMap((s) => ["-f", s])];
  }

  dc(args, o = {}) {
    return super.dc(args, { ...o, env: { ...this.envSupplementaire, ...(o.env ?? {}) } });
  }

  /** `up --detach --no-deps` d'un service (sans relancer ses dépendances terminées). */
  lancerSeul(service, options = []) {
    const r = this.dc(["up", "--detach", "--no-deps", ...options, service], { timeout: 420000 });
    if (r.status !== 0) throw new Error(`docker compose up ${service} en échec (code ${r.status}) :\n${r.stderr.split("\n").slice(-25).join("\n")}`);
    return r;
  }

  /**
   * Recrée le conteneur de l'enregistreur (nouvelle configuration, sources mutées, horloge) puis les services qui
   * partagent son espace réseau (serveurs RFC 3161 des surcharges), que Compose ne recrée pas de lui-même.
   */
  recreerEnregistreur() {
    this.lancerSeul("enregistreur", ["--force-recreate"]);
    const services = this.dc(["config", "--services"], { timeout: 60000 }).stdout.split("\n").filter((s) => /^horodatage-(principal|secours|decalee)$/.test(s));
    for (const s of services) this.lancerSeul(s, ["--force-recreate"]);
  }

  /** `docker compose exec -T <service> <commande…>` : { code, stdout, stderr }. */
  exec(service, commande, o = {}) {
    const r = this.dc(["exec", "-T", ...(o.user ? ["--user", o.user] : []), service, ...commande], { timeout: o.timeout ?? 120000 });
    return { code: r.status, stdout: r.stdout, stderr: r.stderr };
  }

  /** `noortrace-ctl` dans le conteneur de l'enregistreur (même espace de processus : le signal atteint le démon). */
  ctl(args, o = {}) {
    const r = this.exec("enregistreur", ["/usr/local/bin/noortrace-ctl", ...args, "--configuration", "/etc/noortrace/configuration.json"], o);
    let reponse = null;
    try {
      reponse = JSON.parse(r.stdout.trim().split("\n").at(-1));
    } catch {
      reponse = null;
    }
    return { ...r, reponse };
  }

  /** Programme Node.js lancé sous le compte 0, sans réseau, un volume du projet monté en écriture sous /v. */
  ecrireVolume(volume, script, montages = []) {
    const args = ["run", "--rm", "--network", "none", "--user", "0:0", "-v", `${this.ressource(volume)}:/v`];
    for (const [source, cible] of montages) args.push("-v", `${source}:${cible}`);
    const r = docker([...args, "--entrypoint", "/usr/local/bin/node", IMAGE_ENREGISTREUR, "-e", script]);
    if (r.status !== 0) throw new Error(`écriture du volume ${volume} en échec : ${r.stderr}`);
    return r.stdout;
  }

  /** Répertoire du journal de la démonstration sous storage.root (CT-2 EX-12.1). */
  repertoireJournal(config = CONFIG_DEMO) {
    return `${config.recorder.org_id.slice(2)}/${config.recorder.journal_id.slice(2)}`;
  }

  /** Points de contrôle du journal (volume `journal`, répertoire points/), dans l'ordre des fichiers puis des lignes. */
  points(config = CONFIG_DEMO) {
    const texte = this.lireVolume("journal", `const fs=require("fs");const d="/v/${this.repertoireJournal(config)}/points";if(!fs.existsSync(d))process.exit(0);for(const f of fs.readdirSync(d).sort()){for(const l of fs.readFileSync(d+"/"+f,"utf8").split("\\n").filter(Boolean))console.log(l)}`);
    return texte.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  }

  /** Manifestes signés du journal : [{ nom, manifeste, signature }]. */
  manifestes(config = CONFIG_DEMO) {
    const texte = this.lireVolume("journal", `const fs=require("fs");const d="/v/${this.repertoireJournal(config)}/manifestes";if(!fs.existsSync(d))process.exit(0);for(const f of fs.readdirSync(d).sort().filter((n)=>n.endsWith(".json")))console.log(JSON.stringify({nom:f,manifeste:JSON.parse(fs.readFileSync(d+"/"+f,"utf8")),signature:fs.existsSync(d+"/"+f.replace(/\\.json$/,".sig"))?JSON.parse(fs.readFileSync(d+"/"+f.replace(/\\.json$/,".sig"),"utf8")):null}))`);
    return texte.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  }

  /** Noms des segments du journal, dans l'ordre. */
  segments(config = CONFIG_DEMO) {
    return JSON.parse(this.lireVolume("journal", `const fs=require("fs");console.log(JSON.stringify(fs.readdirSync("/v/${this.repertoireJournal(config)}/segments").sort()))`).trim().split("\n").at(-1));
  }

  /**
   * Un `tools/call` (ou une autre méthode MCP) envoyé au frontal de l'enregistreur depuis la position de l'agent :
   * conteneur éphémère de l'image `agent-demo` sur ses réseaux, avec son jeton (ère 2026-07-28, mêmes en-têtes que
   * l'agent de la démonstration). `corps` : objet JSON-RPC, ou texte brut (clés en double, nombres bruts).
   * Rend { http, json, texte }.
   */
  mcp(corps, o = {}) {
    const methode = typeof corps === "string" ? (o.methode ?? "tools/call") : corps.method;
    const nom = typeof corps === "string" ? o.nom ?? null : corps.params?.name ?? null;
    const script = `
      const corps = ${typeof corps === "string" ? JSON.stringify(corps) : JSON.stringify(JSON.stringify(corps))};
      const entetes = { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Bearer " + process.env.NOORTRACE_MCP_TOKEN, "mcp-protocol-version": "2026-07-28", "mcp-method": ${JSON.stringify(methode)} };
      ${nom ? `entetes["mcp-name"] = ${JSON.stringify(nom)};` : ""}
      fetch(process.env.NOORTRACE_MCP_URL, { method: "POST", headers: entetes, body: corps }).then(async (r) => {
        const texte = await r.text();
        let json = null;
        try { const d = texte.startsWith("event:") || texte.startsWith("data:") ? texte.split("\\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).replace(/^ /, "")).pop() : texte; json = JSON.parse(d); } catch {}
        console.log(JSON.stringify({ http: r.status, json, texte: json ? null : texte.slice(0, 500) }));
      }, (e) => { console.log(JSON.stringify({ http: 0, json: null, texte: String(e.cause?.code ?? e.message) })); });`;
    const r = this.executer("agent-demo", script, o);
    if (r.code !== 0) throw new Error(`appel MCP depuis la position de l'agent en échec : ${r.stdout}${r.stderr}`);
    return JSON.parse(r.stdout.trim().split("\n").at(-1));
  }

  /** `tools/call` d'un outil avec ses arguments, métadonnées de l'agent de la démonstration (run_id) ; `meta` les complète. */
  appel(nom, args, o = {}) {
    const id = `pannes-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
    const _meta = {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientCapabilities": {},
      "io.modelcontextprotocol/clientInfo": { name: "agent-demo", version: "0.1.0" },
      "noortrace/delegation": { run_id: "run-demo-0001" },
      ...(o.meta ?? {}),
    };
    return this.mcp({ jsonrpc: "2.0", id, method: "tools/call", params: { name: nom, arguments: args, _meta } }, o);
  }

  /** Compteur des `tools/call` reçus par le serveur d'outils, lu depuis son propre réseau. */
  appelsOutils() {
    const r = this.executer("outils-demo", 'fetch("http://outils-demo:8000/sante").then((r)=>r.text()).then((t)=>console.log(t))');
    return JSON.parse(r.stdout.trim().split("\n").at(-1)).appels;
  }

  /**
   * Exporte le dossier d'un événement par `noortrace-ctl dossier exporter` dans le conteneur de l'enregistreur, vers
   * `dossiers/<nom>` du volume des exports, puis le copie sur l'hôte. Rend { reponse, dossier } (chemin de l'hôte).
   */
  exporterDossier(seq, nom, destination) {
    const r = this.ctl(["dossier", "exporter", "--seq", String(seq), "--vers", `/var/lib/noortrace-exports/pannes-${nom}`]);
    if (r.code !== 0 || r.reponse?.event !== "dossier_exported") return { reponse: r.reponse, refus: `${r.stdout}${r.stderr}`, dossier: null };
    return { reponse: r.reponse, refus: null, dossier: this.extraire("exports", `pannes-${nom}`, path.join(destination, nom)) };
  }

  /**
   * Connexions TCP établies d'un service, lues dans /proc/net/tcp et tcp6 de son conteneur : [{ local, distant }],
   * adresses « ip:port ». Un service arrêté rend [].
   */
  connexions(service) {
    const id = this.conteneur(service);
    if (!id || docker(["inspect", "--format", "{{.State.Running}}", id]).stdout.trim() !== "true") return [];
    const script = `
      const fs = require("fs");
      const ip4 = (h) => h.match(/../g).reverse().map((x) => parseInt(x, 16)).join(".");
      const ip6 = (h) => { const m = h.match(/.{8}/g).map((w) => w.match(/../g).reverse().join("")); const t = m.join(""); if (t.startsWith("0000000000000000" + "0000ffff")) return ip4(m[3].match(/../g).map((x) => x).join("")); return t.replace(/(.{4})/g, "$1:").slice(0, -1); };
      const lire = (f, v6) => { try { return fs.readFileSync(f, "utf8").split("\\n").slice(1).filter(Boolean).map((l) => l.trim().split(/\\s+/)).filter((c) => c[3] === "01").map((c) => { const [la, lp] = c[1].split(":"); const [da, dp] = c[2].split(":"); const a = v6 ? ip6 : ip4; return { local: a(la) + ":" + parseInt(lp, 16), distant: a(da) + ":" + parseInt(dp, 16) }; }); } catch { return []; } };
      console.log(JSON.stringify([...lire("/proc/net/tcp", false), ...lire("/proc/net/tcp6", true)]));`;
    const r = docker(["exec", id, "/usr/local/bin/node", "-e", script], { timeout: 30000 });
    if (r.status !== 0) return [];
    return JSON.parse(r.stdout.trim().split("\n").at(-1));
  }

  /** Adresses IP (toutes) → nom de service, pour les conteneurs en marche du projet. */
  adresses() {
    const table = new Map();
    const ids = this.dc(["ps", "-q"], { timeout: 60000 }).stdout.trim().split("\n").filter(Boolean);
    for (const id of ids) {
      const i = JSON.parse(docker(["inspect", id]).stdout)[0];
      const service = i.Config.Labels["com.docker.compose.service"];
      for (const r of Object.values(i.NetworkSettings.Networks ?? {})) if (r.IPAddress) table.set(r.IPAddress, service);
    }
    return table;
  }
}

/**
 * Flux réseau de la table de CT-8 §5.1 observables dans la démonstration de
 * référence : (service source, service destination, port) → FL-. Le serveur
 * RFC 3161 interne des surcharges partage l'espace réseau de l'enregistreur
 * (boucle locale, FL-21).
 */
export const FLUX_DEMO = Object.freeze([
  { fl: "FL-2", source: "agent-demo", destination: "enregistreur", port: 8300, raison: "frontal MCP en Streamable HTTP" },
  { fl: "FL-3", source: "agent-demo", destination: "enregistreur", port: 8400, raison: "passerelle du modèle" },
  { fl: "FL-6", source: "enregistreur", destination: "enregistreur", port: 8500, raison: "sonde de santé (boucle locale)" },
  { fl: "FL-6", source: "approbation", destination: "approbation", port: 8601, raison: "état du service d'approbation (boucle locale)" },
  { fl: "FL-7", source: "enregistreur", destination: "outils-demo", port: 8000, raison: "relais des appels d'outils" },
  { fl: "FL-8", source: "enregistreur", destination: "modele-demo", port: 8080, raison: "relais des échanges de modèle" },
  { fl: "FL-19", source: "enregistreur", destination: "registre-dev", port: 8545, raison: "inscription, ancres, clôtures" },
  { fl: "FL-21", source: "enregistreur", destination: "enregistreur", port: 2020, raison: "serveur RFC 3161 interne (boucle locale)" },
  { fl: "FL-21", source: "enregistreur", destination: "enregistreur", port: 2021, raison: "serveur RFC 3161 interne de secours (boucle locale)" },
  { fl: "FL-21", source: "enregistreur", destination: "enregistreur", port: 2022, raison: "serveur RFC 3161 interne à horloge décalée (boucle locale)" },
]);

/**
 * Flux hors table admis par CT-8 EX-5.1 : le poste de l'exploitant n'est pas un hôte NOORTRACE ; `approbateur-demo`
 * tient dans la démonstration la place de l'outil du registre de l'exploitant (CT-4 §7, inscription et demande de
 * clôture signées au seuil) et `registre-dev` celle de quatre validateurs dans un conteneur (consensus entre eux sur
 * la boucle locale, hors du périmètre du client).
 */
export const FLUX_HORS_TABLE_ADMIS = Object.freeze([
  { source: "approbateur-demo", destination: "registre-dev", port: 8545, motif: "poste de l'exploitant du registre (CT-8 EX-5.1, dernier alinéa ; CT-4 §7)" },
  { source: "registre-dev", destination: "registre-dev", port: null, motif: "consensus des quatre validateurs du conteneur registre-dev (CT-4), hors du périmètre du client" },
]);

/**
 * Relève les connexions TCP établies de tous les services en marche et les classe : FL- de la table, hors table admis,
 * ou écart. Rend { observes: [{ source, destination, port, fl|null, motif|null }], ecarts: [...] }.
 */
export function releverFlux(c) {
  const adresses = c.adresses();
  const services = [...new Set(adresses.values())];
  const vus = new Map();
  for (const service of services) {
    for (const x of c.connexions(service)) {
      const [ipL, portL] = x.local.split(":");
      const [ipD, portD] = x.distant.split(":");
      // Un côté « serveur » (port d'écoute connu) est la destination ; l'autre la source.
      const portsServeurs = new Set([...FLUX_DEMO.map((f) => f.port), 8545]);
      let source;
      let destination;
      let port;
      if (portsServeurs.has(Number(portD))) [source, destination, port] = [service, ipD === "127.0.0.1" ? service : adresses.get(ipD) ?? ipD, Number(portD)];
      else if (portsServeurs.has(Number(portL))) [source, destination, port] = [ipD === "127.0.0.1" ? service : adresses.get(ipD) ?? ipD, service, Number(portL)];
      else [source, destination, port] = [service, ipD === "127.0.0.1" ? service : adresses.get(ipD) ?? ipD, Number(portD)];
      const cle = `${source}>${destination}:${port}`;
      if (vus.has(cle)) continue;
      const declare = FLUX_DEMO.find((f) => f.source === source && f.destination === destination && f.port === port);
      let admis = FLUX_HORS_TABLE_ADMIS.find((f) => f.source === source && f.destination === destination && (f.port === null || f.port === port))?.motif ?? null;
      // registre-dev tient la place des validateurs et de l'outil du registre de l'exploitant : ses flux internes et entrants
      // ne sont pas des flux FL- d'un hôte NOORTRACE du périmètre du client (CT-8 EX-5.1, dernier alinéa ; CT-4 §7, §10).
      if (!declare && !admis && (source === "registre-dev" || destination === "registre-dev")) admis = "registre-dev (validateurs et outil du registre de l'exploitant) hors du périmètre du client (CT-8 EX-5.1 ; CT-4)";
      vus.set(cle, { source, destination, port, fl: declare?.fl ?? null, motif: declare ? declare.raison : admis });
    }
  }
  const observes = [...vus.values()].sort((a, b) => `${a.source}${a.destination}${a.port}`.localeCompare(`${b.source}${b.destination}${b.port}`));
  return { observes, ecarts: observes.filter((o) => o.fl === null && o.motif === null) };
}

// ---------------------------------------------------------------------------
// Mutants des paquets portés par l'image (CT-9 EX-10.5, EX-10.6), montés dans le conteneur
// ---------------------------------------------------------------------------

/**
 * Copie les sources d'un paquet telles que l'image de l'enregistreur les porte (`docker cp` depuis un conteneur créé,
 * jamais lancé) dans `destination`, puis applique chaque remplacement ; la chaîne retirée doit apparaître exactement
 * une fois dans le fichier copié. Rend le répertoire des sources mutées, à monter à la place de
 * `/opt/noortrace/paquets/<paquet>/src` (variable d'environnement de la surcharge Compose).
 * @param {"enregistreur"|"ancrage"} paquet
 */
export function mutantImage(paquet, destination, remplacements, image = IMAGE_ENREGISTREUR) {
  const cree = docker(["create", image]);
  if (cree.status !== 0) throw new Error(`docker create ${image} : ${cree.stderr}`);
  const id = cree.stdout.trim();
  try {
    fs.mkdirSync(destination, { recursive: true });
    const cp = docker(["cp", `${id}:/opt/noortrace/paquets/${paquet}/src/.`, destination]);
    if (cp.status !== 0) throw new Error(`docker cp des sources de ${paquet} : ${cp.stderr}`);
  } finally {
    docker(["rm", id]);
  }
  for (const r of remplacements) {
    const f = path.join(destination, r.fichier);
    const texte = fs.readFileSync(f, "utf8");
    const n = texte.split(r.ancien).length - 1;
    if (n !== 1) throw new Error(`mutant de ${paquet} : « ${r.ancien} » trouvé ${n} fois dans ${r.fichier} (sources de l'image)`);
    fs.writeFileSync(f, texte.replace(r.ancien, () => r.nouveau));
  }
  // Lisible par le compte du démon dans le conteneur (10001).
  for (const f of fs.readdirSync(destination, { recursive: true })) fs.chmodSync(path.join(destination, f), fs.statSync(path.join(destination, f)).isDirectory() ? 0o755 : 0o644);
  return destination;
}

/** Sources d'un paquet de l'image, non modifiées (référence montée au même endroit que le mutant, pour comparer à armes égales). */
export const referenceImage = (paquet, destination, image = IMAGE_ENREGISTREUR) => mutantImage(paquet, destination, [], image);

// ---------------------------------------------------------------------------
// Rapports de mesure (CT-9 EX-11.11), hors système de référence
// ---------------------------------------------------------------------------

/** Relevé de la machine (`$defs/systeme`), `reference` faux ; `disque` : { type, fsync }. */
export async function releverSysteme(disque = { type: "virtuel", fsync: null }) {
  const { systeme } = await import("../../../scripts/deploiement/mesure-supervision.mjs");
  return systeme(disque);
}

/** Commit du dépôt (HEAD) et nombre de chemins modifiés dans l'arbre de travail. */
export function depot() {
  const c = spawnSync("git", ["rev-parse", "HEAD"], { cwd: RACINE, encoding: "utf8" });
  const s = spawnSync("git", ["status", "--porcelain"], { cwd: RACINE, encoding: "utf8" });
  return { commit: c.status === 0 ? c.stdout.trim() : "0".repeat(40), modifies: s.status === 0 ? s.stdout.split("\n").filter((l) => l.trim() !== "").length : null };
}

/** Version de CT-9 (en-tête de spec/CT-9-plan-de-tests.md : « Version 0.n »), ou « 0.9 » si elle ne se lit pas. */
export function versionCt9() {
  const texte = fs.readFileSync(path.join(RACINE, "spec", "CT-9-plan-de-tests.md"), "utf8").slice(0, 4000);
  return texte.match(/[Vv]ersion\s+\*{0,2}(0\.[0-9]+)/)?.[1] ?? "0.9";
}

/** Une ligne de résultat (`$defs/resultat_mesure`) à valeur unique, `met` null, hors système de référence. */
export function ligneMesure({ name, test_id, unit, value, target = null, conditions = [], samples = null, text_value = null }) {
  const nombres = (samples ?? []).filter((x) => typeof x === "number").sort((a, b) => a - b);
  const rang = (p) => (nombres.length ? nombres[Math.min(nombres.length - 1, Math.max(0, Math.ceil((p / 100) * nombres.length) - 1))] : null);
  return {
    name, test_id, unit, n: samples ? samples.length : value === null ? 0 : 1, connections: null, samples: samples ?? null, samples_sha256: null,
    value, p50: nombres.length ? rang(50) : null, p95: nombres.length ? rang(95) : null, p99: nombres.length ? rang(99) : null,
    min: nombres.length ? nombres[0] : null, max: nombres.length ? nombres.at(-1) : null, mean: nombres.length ? Math.round((nombres.reduce((a, b) => a + b, 0) / nombres.length) * 1000) / 1000 : null,
    text_value, target, met: null, conditions, excluded_reason: "hors_systeme_de_reference",
  };
}

/** Écrit un rapport de mesure conforme à `$defs/rapport_mesure`, `counts_for_targets` faux ; rend le document. */
export async function ecrireRapportMesure(chemin, { results, notes, clock = "monotone", measured_at = new Date(), disque }) {
  const d = depot();
  const rapport = {
    version: 0,
    kind: "rapport-mesure",
    date: measured_at.toISOString().slice(0, 10),
    measured_at: measured_at.toISOString().replace(/\.[0-9]{3}Z$/, "Z"),
    commit: d.commit,
    spec_version: versionCt9(),
    system: await releverSysteme(disque),
    method: { warmup: 0, repetitions: 1, percentile_method: "plus_proche_rang", clock, pair_with_without: false, samples_published: results.some((r) => Array.isArray(r.samples) && r.samples.length) },
    configuration_sha256: null,
    counts_for_targets: false,
    results,
    notes: `${notes} ; mesure hors du système de référence de la porte 2 (CT-9 EX-11.2) : valeurs indicatives, met null ; arbre de travail : ${d.modifies ?? "?"} chemin(s) modifié(s) ou nouveau(x) (git status --porcelain)`,
  };
  fs.mkdirSync(path.dirname(chemin), { recursive: true });
  fs.writeFileSync(chemin, `${JSON.stringify(rapport, null, 2)}\n`);
  return rapport;
}

/** Valide un document contre `$defs/rapport_mesure` du schéma `plan-de-tests-v0` par le validateur du dépôt (scripts/lib/journal.mjs, boîte noire, comme scripts/tests/mesures.mjs) ; rend la liste des erreurs. */
export async function erreursRapportMesure(rapport) {
  const { validerSchema } = await import(pathToFileURL(path.join(RACINE, "scripts", "lib", "journal.mjs")).href);
  const plan = JSON.parse(fs.readFileSync(path.join(RACINE, "spec", "schemas", "plan-de-tests-v0.schema.json"), "utf8"));
  const erreurs = validerSchema(rapport, { $ref: `${plan.$id}#/$defs/rapport_mesure` }, { registre: { [plan.$id]: plan } });
  return (Array.isArray(erreurs) ? erreurs : []).map((e) => (typeof e === "string" ? e : `${e.chemin ?? ""} ${e.message ?? JSON.stringify(e)}`));
}

/** Chronomètre : `debut()` puis `fin()` rend les secondes écoulées (horloge monotone), arrondies au centième. */
export function chronometre() {
  let t0 = null;
  return {
    debut: () => (t0 = performance.now()),
    fin: () => Math.round((performance.now() - t0) / 10) / 100,
  };
}

/** Attend qu'une condition (éventuellement asynchrone) rende une valeur vraie ; rend cette valeur, ou null à l'échéance. */
export async function jusqua(delaiMs, condition, pasMs = 500) {
  const fin = Date.now() + delaiMs;
  for (;;) {
    const v = await condition();
    if (v) return v;
    if (Date.now() > fin) return null;
    await pause(pasMs);
  }
}

export const ICI = path.dirname(fileURLToPath(import.meta.url));
export const tmpRacine = () => process.env.NOORTRACE_TMP ?? os.tmpdir();

// ---------------------------------------------------------------------------
// Prestataires RFC 3161 internes des surcharges (demo/pannes/compose.prestataires.yaml)
// ---------------------------------------------------------------------------

export const POLITIQUE_TEST = "1.3.6.1.4.1.99999.1.1";
export const PRESTATAIRES = Object.freeze({ principal: 2020, secours: 2021, decalee: 2022 });

/** Un seul certificat PEM, tel quel. */
function unPem(texte, quoi) {
  const m = texte.match(/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----\n?/g);
  if (!m || m.length !== 1) throw new Error(`${quoi} : un seul bloc PEM attendu, ${m ? m.length : 0} lu(s)`);
  return m[0].endsWith("\n") ? m[0] : `${m[0]}\n`;
}

/**
 * Crée l'autorité de chaque serveur RFC 3161 interne nommé (pas IR-2 de CT-8 : `horodatage-init-<nom> init`, puis
 * `ac`), et rend { nom: { pem, url } }. La composition doit lire compose.prestataires.yaml.
 */
export function preparerPrestataires(c, noms, travail) {
  const r = {};
  if (travail) {
    // Matériel TLS d'essai du secours (autorité, serveur pour 127.0.0.1, client), lisible par les comptes des conteneurs.
    const tls = path.join(travail, "tls");
    fs.mkdirSync(tls, { recursive: true, mode: 0o755 });
    const m = materielTls(path.join(travail, "tls-source"));
    if (!m) throw new Error("matériel TLS d'essai : openssl requis");
    fs.writeFileSync(path.join(tls, "ca.pem"), m.ca, { mode: 0o644 });
    fs.writeFileSync(path.join(tls, "serveur.key"), m.serveur.cle, { mode: 0o644 });
    fs.writeFileSync(path.join(tls, "serveur.pem"), m.serveur.certificat, { mode: 0o644 });
    fs.writeFileSync(path.join(tls, "client.pem"), m.client, { mode: 0o400 });
    for (const f of fs.readdirSync(tls)) fs.chmodSync(path.join(tls, f), f === "client.pem" ? 0o400 : 0o644);
    // Le certificat client est un secret du démon (CT-2 EX-15.3 : fichier 0400 lisible du seul démon, compte 10001 de l'image).
    try {
      fs.chownSync(path.join(tls, "client.pem"), 10001, 10001);
    } catch {
      // sans le superutilisateur : le démon ne pourra pas le lire, ce que l'essai constate (secret_non_resolu)
    }
    fs.chmodSync(tls, 0o755);
  }
  for (const nom of noms) {
    const port = PRESTATAIRES[nom];
    const init = c.dc(["--profile", "outils", "run", "--rm", "-T", "--no-deps", `horodatage-init-${nom}`, "init", "--repertoire", "/var/lib/noortrace-tsa", "--politique", POLITIQUE_TEST, "--crl-url", `http://127.0.0.1:${port}/crl.pem`, "--algorithme", "p-256"], { timeout: 180000 });
    if (init.status !== 0 && !/existe|exist/i.test(init.stderr + init.stdout)) throw new Error(`horodatage-init-${nom} init : code ${init.status}\n${init.stderr.slice(-800)}`);
    const ac = c.dc(["--profile", "outils", "run", "--rm", "-T", "--no-deps", `horodatage-init-${nom}`, "ac", "--repertoire", "/var/lib/noortrace-tsa"], { timeout: 180000 });
    if (ac.status !== 0) throw new Error(`horodatage-init-${nom} ac : code ${ac.status}\n${ac.stderr.slice(-800)}`);
    r[nom] = { pem: unPem(ac.stdout, `certificat de l'AC ${nom}`), url: `http://127.0.0.1:${port}/`, port };
  }
  return r;
}

/**
 * Prestataire RFC 3161 du document `ancrage-v0` pour un serveur interne préparé (forme de demo/ancrage-demo.json) ;
 * le secours est servi en TLS mutuel (CT-5 EX-5.5) : https et certificat client (secret monté par la surcharge).
 */
export function prestataireInterne(nom, role, autorite) {
  const tls = nom === "secours";
  return {
    id: `tsa-${nom}`, role, url: tls ? `https://127.0.0.1:${autorite.port}/` : autorite.url,
    auth: tls ? { method: "certificat_client", secret: { file: "/etc/noortrace-pannes/tls/client.pem" } } : { method: "aucune", secret: null },
    hash: "sha256", policy_oid: POLITIQUE_TEST, accepted_policies: [POLITIQUE_TEST],
    anchor_certificates: [autorite.pem], qualified: null, min_interval_ms: 0, request_timeout_ms: 5000, correlation_header: null,
    source: `scénarios de bout en bout (CT-9 §10.5) : serveur RFC 3161 interne non qualifié (CT-5 §7) du service horodatage-${nom} de demo/pannes/compose.prestataires.yaml, joint sur la boucle locale de l'espace réseau de l'enregistreur ; autorité créée dans son volume au début du passage, sans valeur hors de la démonstration`,
  };
}

/** Document `ancrage-v0` du passage : celui de la démonstration de référence, prestataires et surcharges remplacés. */
export function documentAncragePannes(prestataires, surcharges = {}) {
  const doc = JSON.parse(fs.readFileSync(path.join(DEMO, "ancrage-demo.json"), "utf8"));
  doc.rfc3161.providers = prestataires;
  const fusionner = (base, s) => {
    for (const [k, v] of Object.entries(s)) {
      if (v !== null && typeof v === "object" && !Array.isArray(v) && base[k] && typeof base[k] === "object" && !Array.isArray(base[k])) fusionner(base[k], v);
      else base[k] = v;
    }
  };
  fusionner(doc, surcharges);
  return doc;
}

/** Écrit configuration-pannes.json et ancrage-pannes.json dans le répertoire du passage (compose.configuration.yaml). */
export function ecrireConfigurationPannes(travail, { configuration = CONFIG_DEMO, ancrage }) {
  fs.mkdirSync(travail, { recursive: true, mode: 0o755 });
  for (const [nom, doc] of [["configuration-pannes.json", configuration], ["ancrage-pannes.json", ancrage]]) {
    fs.writeFileSync(path.join(travail, nom), `${JSON.stringify(doc, null, 2)}\n`, { mode: 0o644 });
    fs.chmodSync(path.join(travail, nom), 0o644);
  }
  fs.chmodSync(travail, 0o755);
}
