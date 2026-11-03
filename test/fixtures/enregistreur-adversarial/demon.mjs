// Outils des tests adversariaux de CT-9 joués sur le démon de l'étape 4
// (test/adversarial.test.js, describe « démon de l'étape 4 ») : fabrique de
// mutants du paquet @noortrace/enregistreur (CT-9 EX-10.5), configuration
// d'un démon réel tirée de l'exemple de CT-2 §15.3 (classe D, magasin de bail
// `file`, frontal MCP en Streamable HTTP à jetons statiques, serveur d'outils
// stdio de test, service d'approbation simulé joint en HTTP), lancement de
// `bin/noortrace --config` depuis le paquet du dépôt ou depuis un mutant, et
// client JSON-RPC minimal de l'ère héritée.
//
// Un mutant est une copie de paquets/enregistreur (src, bin, schemas,
// package.json) dans un répertoire temporaire, où node_modules est un lien
// symbolique vers celui du dépôt ; chaque remplacement nomme la chaîne
// retirée, qui doit apparaître exactement une fois dans le fichier copié
// (ou au moins une fois avec `tous`). Le dépôt n'est jamais modifié.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import net from "node:net";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { RACINE } from "../enregistreur-coeur/outils.mjs";
import { configurationHa, adresseOccupee, remplacerPort, santeBornee, ESSAIS_PORTS } from "../enregistreur-ha/outils.mjs";

export const PAQUET = path.join(RACINE, "paquets", "enregistreur");
export const SERVEUR_OUTILS = path.join(path.dirname(fileURLToPath(import.meta.url)), "serveur-outils.mjs");

/** Paquet du dépôt (la référence) : { racine, paquet, bin(nom), importer(rel) }. */
export const REFERENCE = Object.freeze({
  racine: RACINE,
  paquet: PAQUET,
  bin: (nom = "noortrace") => path.join(PAQUET, "bin", nom),
  importer: (rel) => import(pathToFileURL(path.join(PAQUET, "src", rel)).href),
});

const MUTANTS = [];

/**
 * Mutant du paquet @noortrace/enregistreur (CT-9 EX-10.5).
 * @param {string} nom
 * @param {{fichier: string, ancien: string, nouveau: string, tous?: boolean}[]} remplacements
 *   `fichier` relatif à paquets/enregistreur/src
 * @param {string} [tmp]
 */
export function mutantPaquet(nom, remplacements, tmp = process.env.NOORTRACE_TMP ?? os.tmpdir()) {
  const racine = fs.mkdtempSync(path.join(tmp, `noortrace-mutant-demon-${nom}-`));
  MUTANTS.push(racine);
  const paquet = path.join(racine, "paquets", "enregistreur");
  fs.mkdirSync(paquet, { recursive: true });
  for (const d of ["src", "bin", "schemas"]) fs.cpSync(path.join(PAQUET, d), path.join(paquet, d), { recursive: true });
  fs.copyFileSync(path.join(PAQUET, "package.json"), path.join(paquet, "package.json"));
  fs.symlinkSync(path.join(RACINE, "node_modules"), path.join(racine, "node_modules"));
  for (const r of remplacements) {
    const f = path.join(paquet, "src", r.fichier);
    const texte = fs.readFileSync(f, "utf8");
    const n = texte.split(r.ancien).length - 1;
    if (r.tous ? n < 1 : n !== 1) throw new Error(`mutant ${nom} : « ${r.ancien} » trouvé ${n} fois dans ${r.fichier}`);
    fs.writeFileSync(f, r.tous ? texte.split(r.ancien).join(r.nouveau) : texte.replace(r.ancien, () => r.nouveau));
  }
  return {
    racine,
    paquet,
    bin: (b = "noortrace") => path.join(paquet, "bin", b),
    importer: (rel) => import(pathToFileURL(path.join(paquet, "src", rel)).href),
  };
}

/** Détruit les mutants fabriqués et les répertoires des prises. */
export function detruireMutants() {
  for (const r of MUTANTS.splice(0)) fs.rmSync(r, { recursive: true, force: true });
}

/**
 * Port TCP libre de la boucle locale, au moment de l'appel seulement : il
 * peut être pris avant que le démon ne l'ouvre ; `demarrer` relance alors le
 * démon sur d'autres ports (EADDRINUSE, au plus ESSAIS_PORTS essais).
 */
export function portLibre() {
  return new Promise((res, rej) => {
    const s = http.createServer();
    s.once("error", rej);
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
}

/** Attend qu'une condition (éventuellement asynchrone) soit vraie. */
export async function attendre(cond, delaiMs = 30000, pasMs = 50) {
  const limite = Date.now() + delaiMs;
  for (;;) {
    if (await cond()) return;
    if (Date.now() > limite) throw new Error(`condition non atteinte en ${delaiMs} ms`);
    await new Promise((r) => setTimeout(r, pasMs));
  }
}

/**
 * Configuration d'un démon réel : celle des tests de haute disponibilité
 * (configurationHa : classe D, frontal MCP Streamable HTTP, service
 * d'approbation simulé joint en HTTP), magasin de bail `file`, sans WORM,
 * serveur d'outils stdio `demo` de ce répertoire (lire, ecrire, ecrire_lent,
 * changer, sonder) ; `modifier(config, env)` ajuste.
 * @returns {Promise<{config: object, env: object, dir: string, journal: string, portSante: number, portHttp: number}>}
 */
export async function configurationDemon(dir, o) {
  const portHttp = await portLibre();
  const portSante = await portLibre();
  const x = configurationHa(dir, {
    instance: o.instance ?? "inst-adv",
    journal_id: o.journal_id,
    store: { type: "file", path: path.join(dir, "bail", "verrou") },
    approbation: o.approbation,
    portHttp,
    portSante,
    segment_max_bytes: o.segment_max_bytes,
  });
  // Prise Unix du frontal sous un répertoire court du système : le chemin d'une
  // prise est borné (108 octets), et NOORTRACE_TMP peut être long.
  const prises = fs.mkdtempSync(path.join(os.tmpdir(), "ntadv-"));
  MUTANTS.push(prises);
  x.config.mcp.socket = path.join(prises, "mcp.sock");
  const demo = x.config.policy.servers.demo;
  demo.transport.command = [process.execPath, SERVEUR_OUTILS];
  demo.tools.changer = { class: "lecture", timeout_ms: null, effects: null, failure: null };
  demo.tools.sonder = { class: "lecture", timeout_ms: null, effects: null, failure: null };
  if (o.modifier) await o.modifier(x.config, x.env);
  return { ...x, dir, journal: repertoireJournal(x.config), portSante, portHttp, ports: [portHttp] };
}

/** Répertoire du journal d'une configuration (12.1 : `<root>/<org>/<journal>`). */
export function repertoireJournal(config) {
  return path.join(config.storage.root, config.recorder.org_id.slice(2), config.recorder.journal_id.slice(2));
}

/**
 * Complète une configuration du frontal modèle (fixtures du frontal modèle :
 * configurationModele, configurationIcap) pour un démon réel : santé et
 * frontal sur des ports libres connus.
 */
export async function demonModele(dir, c, mode) {
  const portSante = await portLibre();
  const port = await portLibre();
  c.config.supervision.health_listen = `127.0.0.1:${portSante}`;
  if (mode === "icap") c.config.model.icap.listen = `127.0.0.1:${port}`;
  else c.config.model.listen = `127.0.0.1:${port}`;
  return { ...c, dir, journal: repertoireJournal(c.config), portSante, port, ports: [], ligneEcoute: mode === "icap" ? "model_icap_listening" : "model_gateway_listening" };
}

/**
 * Démon réel `bin/noortrace --config` d'un paquet (référence ou mutant).
 * @returns {import("node:child_process").ChildProcess & {sortie: string, fin: Promise<object>, lignes: () => object[]}}
 */
export function lancer(paquet, c, fichier) {
  fs.writeFileSync(fichier, JSON.stringify(c.config));
  const p = spawn(process.execPath, [paquet.bin("noortrace"), "--config", fichier], { env: { ...process.env, ...c.env }, stdio: ["ignore", "pipe", "pipe"] });
  p.sortie = "";
  p.stdout.on("data", (d) => (p.sortie += d));
  p.stderr.on("data", (d) => (p.sortie += d));
  p.fin = new Promise((r) => p.on("exit", (code, signal) => r({ code, signal })));
  // Fin des flux de sortie (après `exit`) : la sortie d'erreur est alors complète.
  p.ferme = new Promise((r) => p.on("close", () => r()));
  const ops = c.config.supervision.ops_log.path;
  p.lignes = () => (fs.existsSync(ops) ? fs.readFileSync(ops, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
  return p;
}

/** Corps de `GET /healthz` (EX-17.1), ou null. */
export function sante(port) {
  return new Promise((res) => {
    const r = http.get({ host: "127.0.0.1", port, path: "/healthz" }, (x) => {
      const m = [];
      x.on("data", (k) => m.push(k));
      x.on("end", () => {
        try {
          res({ statut: x.statusCode, corps: JSON.parse(Buffer.concat(m).toString("utf8") || "null") });
        } catch {
          res(null);
        }
      });
    });
    r.on("error", () => res(null));
  });
}

/** Le port TCP accepte-t-il une connexion ? */
export function ecoute(port) {
  return new Promise((res) => {
    const s = net.connect({ host: "127.0.0.1", port }, () => {
      s.destroy();
      res(true);
    });
    s.on("error", () => res(false));
  });
}

/**
 * Lance un démon et attend sa santé `ok` (ou l'état demandé), puis que
 * chaque port de `c.ports` (défaut : celui du frontal MCP HTTP) écoute, et
 * que la ligne `c.ligneEcoute` du journal d'exploitation soit écrite : les
 * frontaux s'ouvrent après la sonde de santé. Un port que la sonde ne doit
 * pas toucher (ICAP : une connexion d'une source non admise est consignée)
 * est attendu par sa ligne seulement.
 */
export async function demarrer(paquet, c, fichier, etat = "ok", delaiMs = 60000) {
  for (let essai = 1; ; essai++) {
    const p = lancer(paquet, c, fichier);
    // Un démon arrêté ne répondra plus : l'attente cesse aussitôt.
    const vivant = (f) => async () => {
      if (p.exitCode !== null || p.signalCode !== null) throw new Error(`démon arrêté (${p.exitCode ?? p.signalCode})`);
      return f();
    };
    try {
      // Le port peut être tenu par un autre processus qui ne répond pas en HTTP : sonde bornée.
      await attendre(vivant(async () => (await santeBornee(c.portSante))?.corps?.status === etat), delaiMs);
      for (const port of c.ports ?? [c.portHttp]) await attendre(vivant(() => ecoute(port)), delaiMs);
      if (c.ligneEcoute) await attendre(vivant(() => p.lignes().some((l) => l.event === c.ligneEcoute)), delaiMs);
      return p;
    } catch (e) {
      if (p.exitCode !== null || p.signalCode !== null) await p.ferme;
      // Port choisi libre, puis pris par un autre processus avant l'ouverture
      // par le démon (EADDRINUSE) : nouveaux ports, configuration réécrite par
      // `lancer`, nouvel essai, au plus ESSAIS_PORTS.
      if (essai < ESSAIS_PORTS && adresseOccupee(p)) {
        await reattribuerPorts(c);
        continue;
      }
      p.kill("SIGKILL");
      throw new Error(`${e.message} ; démon : ${p.sortie.slice(-3000)}`);
    }
  }
}

/**
 * Nouveaux ports libres pour les adresses d'écoute d'une configuration de
 * démon (`portSante`, `portHttp`, `port`, `ports`) : chaque ancien port est
 * remplacé dans `c.config` et dans les champs de `c`.
 */
async function reattribuerPorts(c) {
  const anciens = new Set([c.portSante, c.portHttp, c.port, ...(c.ports ?? [])].filter((x) => Number.isInteger(x) && x > 0));
  const table = new Map();
  for (const ancien of anciens) {
    const nouveau = await portLibre();
    remplacerPort(c.config, ancien, nouveau);
    table.set(ancien, nouveau);
  }
  for (const champ of ["portSante", "portHttp", "port"]) if (table.has(c[champ])) c[champ] = table.get(c[champ]);
  if (c.ports) c.ports = c.ports.map((x) => table.get(x) ?? x);
}

/**
 * Processus enfants d'un processus (lecture de /proc) : [{ pid, commande }].
 * Sert à trouver l'auxiliaire `flock(1)` qui tient le bail `file` d'un démon
 * (bail.mjs) : le tuer rend le verrou, comme une instance isolée qui cesse de
 * renouveler (13.4 pas 2).
 */
export function enfants(pid) {
  const r = [];
  for (const x of fs.readdirSync("/proc")) {
    if (!/^[0-9]+$/.test(x)) continue;
    try {
      const stat = fs.readFileSync(`/proc/${x}/stat`, "utf8");
      const ppid = stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1];
      if (ppid === String(pid)) r.push({ pid: Number(x), commande: fs.readFileSync(`/proc/${x}/cmdline`, "utf8").split("\0").filter(Boolean) });
    } catch {
      // processus terminé entre la liste et la lecture
    }
  }
  return r;
}

/** Tue l'auxiliaire `flock(1)` du bail `file` d'un démon ; rend son pid. */
export function tuerAuxiliaireBail(demon) {
  const aux = enfants(demon.pid).find((e) => e.commande[0] === "flock");
  if (!aux) throw new Error("auxiliaire flock(1) du bail introuvable");
  process.kill(aux.pid, "SIGKILL");
  return aux.pid;
}

/** Arrête un démon (SIGTERM, puis SIGKILL après 10 s). */
export async function arreter(p) {
  if (!p || p.exitCode !== null || p.signalCode !== null) return;
  p.kill("SIGTERM");
  const t = setTimeout(() => p.kill("SIGKILL"), 10000);
  await p.fin;
  clearTimeout(t);
}

/**
 * Requête JSON-RPC POST au point MCP du démon ; `jeton` null : aucun en-tête
 * d'autorisation. Rend { statut, entetes, corps (objet JSON ou null), session }.
 */
export function poster(port, corps, o = {}) {
  return new Promise((res, rej) => {
    const entetes = { "content-type": "application/json", accept: "application/json, text/event-stream" };
    if (o.jeton) entetes.authorization = `Bearer ${o.jeton}`;
    if (o.session) entetes["mcp-session-id"] = o.session;
    const req = http.request({ host: "127.0.0.1", port, path: "/mcp", method: "POST", headers: entetes }, (r) => {
      const m = [];
      r.on("data", (k) => m.push(k));
      r.on("end", () => {
        let texte = Buffer.concat(m).toString("utf8");
        if (String(r.headers["content-type"]).startsWith("text/event-stream")) texte = texte.split("\n").filter((l) => l.startsWith("data: ")).at(-1)?.slice(6) ?? "";
        let json = null;
        try {
          json = texte ? JSON.parse(texte) : null;
        } catch {
          json = null;
        }
        res({ statut: r.statusCode, entetes: r.headers, corps: json, session: r.headers["mcp-session-id"] ?? null });
      });
    });
    req.on("error", rej);
    req.end(JSON.stringify(corps));
  });
}

/**
 * Hôte de l'ère héritée sur Streamable HTTP : `initialize` puis
 * `notifications/initialized`, puis `tools/call` ; rend la réponse HTTP de
 * l'appel, avec l'identifiant de session reçu à `initialize`. `jeton` null :
 * aucune autorisation sur aucune requête.
 */
export async function appelerOutil(port, jeton, nom, args, o = {}) {
  const ini = await poster(port, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "hote-adversarial", version: "1.0.0" } } }, { jeton });
  if (ini.statut !== 200) return ini;
  await poster(port, { jsonrpc: "2.0", method: "notifications/initialized" }, { jeton, session: ini.session });
  const params = { name: nom, arguments: args };
  if (o.meta) params._meta = o.meta;
  return { ...(await poster(port, { jsonrpc: "2.0", id: 2, method: "tools/call", params }, { jeton, session: ini.session })), session: ini.session };
}
