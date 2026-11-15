// Outils des essais d'intégration (test/integrations.test.js, CT-9 TI-4 à
// TI-11) : pilote du banc (`banc.mjs`) lancé comme processus et commandé par
// lignes JSON ; lancement d'un agent sous `strace -f -e trace=connect`, qui
// relève chaque connexion sortante de l'hôte (TI-4 à TI-10, pas 3 :
// « Relever les connexions sortantes de l'hôte pendant le scénario ») ;
// interpréteurs des environnements Python ; lecture de la trace que chaque
// agent écrit sur sa sortie standard (ligne `noortrace-agent {…}`).

import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ICI = path.dirname(fileURLToPath(import.meta.url));
export const RACINE = path.resolve(ICI, "..", "..", "..");
export const BANC = path.join(ICI, "banc.mjs");
export const AGENTS = path.join(ICI, "agents");
export const ENVS = path.join(RACINE, "paquets", "sdk-python", ".environnements");
export const PREPARER = "test/fixtures/integrations/environnements.sh preparer";
export const PREPARER_ADAPTATEURS = "paquets/sdk-python/outils/environnements.sh preparer";

/** Interpréteur Python d'un environnement, ou null. */
export function interpreteur(nom) {
  const p = path.join(ENVS, nom, "bin", "python");
  return fs.existsSync(p) ? p : null;
}

/** Exécutable d'un environnement (`litellm`), ou null. */
export function executable(nom, prog) {
  const p = path.join(ENVS, nom, "bin", prog);
  return fs.existsSync(p) ? p : null;
}

/** `strace` est-il présent ? */
export function straceDisponible() {
  return spawnSync("strace", ["-V"], { encoding: "utf8", timeout: 10000 }).status === 0;
}

/**
 * Lance le banc et rend son pilote.
 * @param {object} [env] variables supplémentaires (mandataire LiteLLM)
 */
export async function lancerBanc(env = {}) {
  const p = spawn(process.execPath, [BANC], { cwd: RACINE, env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
  let erreurs = "";
  p.stderr.on("data", (x) => (erreurs = (erreurs + x.toString("utf8")).slice(-20000)));
  const lignes = readline.createInterface({ input: p.stdout });
  const attente = [];
  const recues = [];
  lignes.on("line", (l) => {
    const a = attente.shift();
    if (a) a(l);
    else recues.push(l);
  });
  const suivante = () => (recues.length ? Promise.resolve(recues.shift()) : new Promise((r) => attente.push(r)));
  const info = JSON.parse(await suivante());
  if (!info.pret) throw new Error(`banc non pret : ${JSON.stringify(info)}\n${erreurs}`);
  let file = Promise.resolve();
  const commande = (m) => {
    const r = file.then(async () => {
      p.stdin.write(JSON.stringify(m) + "\n");
      const x = JSON.parse(await suivante());
      if (x.erreur) throw new Error(`banc : ${x.erreur}`);
      return x;
    });
    file = r.catch(() => {});
    return r;
  };
  return {
    info,
    commande,
    evenements: async () => (await commande({ cmd: "evenements" })).evenements,
    exploitation: async (event) => (await commande({ cmd: "exploitation", event })).lignes,
    erreurs: () => erreurs,
    async fermer() {
      p.stdin.end();
      await new Promise((r) => (p.exitCode !== null ? r() : p.once("exit", r)));
    },
  };
}

/**
 * Connexions sortantes relevées par strace : `connect(…)` vers AF_INET ou
 * AF_INET6, dédoublonnées, sous la forme `adresse:port`.
 */
export function connexionsRelevees(trace) {
  const vues = new Set();
  for (const l of trace.split("\n")) {
    if (!/\bconnect\(/.test(l)) continue;
    const v4 = /sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)/.exec(l);
    if (v4) {
      vues.add(`${v4[2]}:${v4[1]}`);
      continue;
    }
    const v6 = /sa_family=AF_INET6,\s*sin6_port=htons\((\d+)\),.*inet_pton\(AF_INET6,\s*"([^"]+)"/.exec(l);
    if (v6) vues.add(`[${v6[2]}]:${v6[1]}`);
  }
  return [...vues].sort();
}

/**
 * Lance un agent (programme et arguments) sous `strace -f -e trace=connect`,
 * avec un délai ; rend `{ code, signal, stdout, stderr, connexions, trace }`
 * où `trace` est la ligne `noortrace-agent {…}` analysée (ou null).
 * @param {{commande: string[], env?: object, cwd?: string, delaiMs?: number, strace?: boolean, fichierTrace: string}} o
 */
export function lancerAgent(o) {
  const avecStrace = o.strace !== false;
  const args = avecStrace ? ["-f", "-e", "trace=connect", "-s", "256", "-o", o.fichierTrace, "--", ...o.commande] : o.commande;
  // Aucun mandataire HTTP hérité de l'environnement : une connexion que l'agent
  // tenterait hors de l'enregistreur part alors directement vers sa cible et
  // apparaît telle quelle dans le relevé (au lieu de se cacher derrière un mandataire local).
  const env = { ...process.env, PYTHONDONTWRITEBYTECODE: "1", PYTHONUNBUFFERED: "1", ...(o.env ?? {}) };
  for (const v of ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]) delete env[v];
  // Une valeur `undefined` retire la variable (héritée de l'environnement de l'essai).
  for (const [k, v] of Object.entries(env)) if (v === undefined) delete env[k];
  const r = spawnSync(avecStrace ? "strace" : args[0], avecStrace ? args : args.slice(1), {
    cwd: o.cwd ?? RACINE,
    env,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    timeout: o.delaiMs ?? 300000,
  });
  const stdout = r.stdout ?? "";
  const ligne = stdout.split("\n").find((l) => l.startsWith("noortrace-agent "));
  let trace = null;
  try {
    trace = ligne ? JSON.parse(ligne.slice("noortrace-agent ".length)) : null;
  } catch {
    trace = null;
  }
  const brut = avecStrace && fs.existsSync(o.fichierTrace) ? fs.readFileSync(o.fichierTrace, "utf8") : "";
  return { code: r.status, signal: r.signal, stdout, stderr: r.stderr ?? "", connexions: connexionsRelevees(brut), trace, erreur: r.error ?? null };
}

/** Adresse `hôte:port` d'une URL. */
export function adresseDe(url) {
  const u = new URL(url);
  return `${u.hostname}:${u.port}`;
}

/** Attend qu'une condition soit vraie (au plus `ms`), sinon rend la dernière valeur. */
export async function attendre(condition, ms = 10000, pas = 50) {
  const fin = Date.now() + ms;
  for (;;) {
    const v = await condition();
    if (v || Date.now() > fin) return v;
    await new Promise((r) => setTimeout(r, pas));
  }
}
