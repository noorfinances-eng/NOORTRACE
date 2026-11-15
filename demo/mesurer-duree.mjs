#!/usr/bin/env node
// Mesure de la durée de la démonstration de référence (CT-9 TM-43 ; CT-2
// EX-19.1 : moins de deux minutes). Outil de la personne qui mesure ; jamais
// lancé par la suite d'essais.
//
//   node demo/mesurer-duree.mjs --sortie <rapport.json> [--echauffement 3]
//        [--repetitions 10] [--projet noortrace-demo-mesure] [--port 8500] [--reference]
//
// Une répétition : `docker compose down --volumes`, puis la commande unique
// en mode détaché (`up --detach`), puis `docker compose wait verificateur`,
// qui bloque jusqu'à la fin de ce service ; la sortie du service est lue par
// `docker compose logs`. Les images sont déjà dans le magasin local.
//
// Grandeur de la ligne `demonstration_duree` : la durée IMPRIMÉE par le
// service verificateur (« Durée totale : <s>,<ms> s » : du démarrage de son
// processus à l'impression, horloge monotone de ce processus), en secondes.
// Recoupement publié dans `conditions`, jamais comparé à la cible : la durée
// murale de l'outil, du lancement de la commande unique à la fin du service
// verificateur, et le code de retour de chaque répétition.
//
// Une répétition qui imprime une durée est un échantillon quel que soit son
// code de retour (CT-9 EX-11.4) ; une répétition sans durée imprimée n'en est
// pas un. Sous dix échantillons, la ligne porte `echantillon_insuffisant`.
// Hors du système de référence de CT-9 EX-11.1 (sans --reference), le rapport
// porte `counts_for_targets` faux et la ligne `met` nul (EX-11.2) : il éprouve
// l'outil et la forme du rapport, il ne juge pas la cible.
//
// Codes : 0 rapport écrit ; 1 échec (Docker, images, composition) ; 2 usage.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEMO = path.join(RACINE, "demo");
export const CIBLE_S = 120;

/** Durée imprimée par le vérificateur, en secondes, ou null (« Durée totale : 41,237 s »). */
export function dureeImprimee(sortie) {
  const m = /^ {2}Durée totale : ([0-9]+),([0-9]{3}) s$/m.exec(sortie);
  return m ? Number(`${m[1]}.${m[2]}`) : null;
}

const commande = (c, args) => {
  try {
    return execFileSync(c, args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
};

/** Relevé de la machine (`$defs/systeme` de plan-de-tests-v0). */
export function systeme(reference) {
  const lireFichier = (f) => {
    try {
      return fs.readFileSync(f, "utf8");
    } catch {
      return "";
    }
  };
  const osRelease = Object.fromEntries(lireFichier("/etc/os-release").split("\n").filter((l) => l.includes("=")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).replace(/^"|"$/g, "")]));
  const aslr = lireFichier("/proc/sys/kernel/randomize_va_space").trim();
  const go = commande("go", ["version"]);
  const python = commande("python3", ["--version"]);
  const hyperviseur = /^flags\s*:.*\bhypervisor\b/m.test(lireFichier("/proc/cpuinfo"));
  return {
    reference,
    cpu: os.cpus()[0]?.model ?? "inconnu",
    cores: os.cpus().length,
    memory_bytes: os.totalmem(),
    disk: { type: reference ? "inconnu" : "virtuel", fsync: null },
    os: osRelease.PRETTY_NAME ?? `${os.type()} ${os.release()}`,
    kernel: os.release(),
    node: process.version,
    go: go ? /go[0-9.]+/.exec(go)?.[0] ?? null : null,
    python: python ? python.replace(/^Python /, "") : null,
    cpu_scaling: fs.existsSync("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") ? "actif" : "inconnu",
    aslr: aslr === "0" ? "inactif" : aslr ? "actif" : "inconnu",
    load_avg_1m: Math.round(os.loadavg()[0] * 100) / 100,
    virtualized: hyperviseur ? true : null,
  };
}

/**
 * Rapport de mesure (`$defs/rapport_mesure`) d'une campagne. `repetitions` :
 * `[{ imprimee_s|null, murale_s, code }]`, échauffement exclu.
 */
export function rapport({ repetitions, echauffement, demandees, reference, commit, mesureA, configuration, images }) {
  const echantillons = repetitions.filter((r) => r.imprimee_s !== null).map((r) => r.imprimee_s);
  const suffisant = echantillons.length >= 10 && echauffement >= 3;
  const compte = reference && suffisant;
  const max = echantillons.length ? Math.max(...echantillons) : null;
  const tri = [...echantillons].sort((a, b) => a - b);
  const rang = (p) => (tri.length ? tri[Math.max(0, Math.ceil((p / 100) * tri.length) - 1)] : null);
  const arrondi = (x) => (x === null ? null : Math.round(x * 1000) / 1000);
  const ecarts = repetitions.filter((r) => r.imprimee_s !== null).map((r) => arrondi(r.murale_s - r.imprimee_s));
  return {
    version: 0,
    kind: "rapport-mesure",
    date: mesureA.slice(0, 10),
    measured_at: mesureA,
    commit,
    spec_version: "0.10",
    system: systeme(reference),
    method: { warmup: echauffement, repetitions: demandees, percentile_method: "plus_proche_rang", clock: "monotone", pair_with_without: false, samples_published: true },
    configuration_sha256: createHash("sha256").update(JSON.stringify(configuration)).digest("hex"),
    counts_for_targets: compte,
    results: [
      {
        name: "demonstration_duree", test_id: "TM-43", unit: "s", n: echantillons.length || null, connections: null,
        samples: echantillons, samples_sha256: null, value: null, p50: rang(50), p95: rang(95), p99: rang(99),
        min: echantillons.length ? Math.min(...echantillons) : null, max, mean: echantillons.length ? arrondi(echantillons.reduce((a, b) => a + b, 0) / echantillons.length) : null,
        text_value: null, target: CIBLE_S, met: compte && max !== null ? max < CIBLE_S : null,
        conditions: [
          "images déjà dans le magasin local ; sans clé d'API ni accès à Internet (réseaux de la composition internes)",
          "durée imprimée par le service verificateur : origine au démarrage de son processus, fin à l'impression du résultat, horloge monotone de ce processus, secondes à trois décimales (CT-2 EX-19.1 ; PD-25)",
          "commande unique : docker compose up --detach, terminée par docker compose wait verificateur ; un nouveau journal à chaque répétition (docker compose down --volumes)",
          `recoupement, non comparé à la cible : durée murale de l'outil, du lancement de la commande unique à la fin de verificateur, en secondes : ${repetitions.map((r) => arrondi(r.murale_s)).join(", ")}`,
          `écart durée murale moins durée imprimée, par répétition, en secondes : ${ecarts.join(", ") || "aucun échantillon"} (création des conteneurs et des réseaux avant le démarrage du processus verificateur, et fin du conteneur après l'impression)`,
          `codes de retour de verificateur par répétition : ${repetitions.map((r) => (r.code === null ? "aucun" : r.code)).join(", ")}`,
          `images : ${images.join(", ")}`,
        ],
        excluded_reason: compte ? null : !reference ? "hors_systeme_de_reference" : "echantillon_insuffisant",
      },
    ],
    notes: `TM-43 (CT-2 EX-19.1) : démonstration de référence, ${echauffement} exécution(s) d'échauffement puis ${demandees} répétition(s) demandée(s), ${echantillons.length} échantillon(s). ${reference ? "Système déclaré de référence par l'opérateur de la mesure." : "Hors du système de référence de CT-9 EX-11.1 : le rapport ne compte pour aucune cible."} Configuration (configuration_sha256) : ${JSON.stringify(configuration)}.`,
  };
}

const USAGE = "usage : demo/mesurer-duree.mjs --sortie <rapport.json> [--echauffement <n>] [--repetitions <n>] [--projet <nom>] [--port <n>] [--reference]";

export function principal(argv, io = {}) {
  const err = io.stderr ?? process.stderr;
  let o;
  try {
    o = parseArgs({ args: argv, options: { sortie: { type: "string" }, echauffement: { type: "string", default: "3" }, repetitions: { type: "string", default: "10" }, projet: { type: "string", default: "noortrace-demo-mesure" }, port: { type: "string", default: "8500" }, reference: { type: "boolean", default: false } }, strict: true, allowPositionals: false }).values;
  } catch (e) {
    err.write(`${e.message}\n${USAGE}\n`);
    return 2;
  }
  const echauffement = Number(o.echauffement);
  const demandees = Number(o.repetitions);
  if (!o.sortie || !Number.isInteger(echauffement) || echauffement < 0 || !Number.isInteger(demandees) || demandees < 1 || !/^[0-9]{1,5}$/.test(o.port) || !/^[a-z0-9][a-z0-9_-]*$/.test(o.projet)) {
    err.write(`${USAGE}\n`);
    return 2;
  }
  const dc = (args, timeout = 420000) => spawnSync("docker", ["compose", "-p", o.projet, "--project-directory", DEMO, "-f", path.join(DEMO, "compose.yaml"), ...args], { encoding: "utf8", timeout, maxBuffer: 64 * 1024 * 1024, env: { ...process.env, NOORTRACE_DEMO_PORT_SANTE: o.port } });
  const images = dc(["config", "--images"]);
  if (images.status !== 0) {
    err.write(`docker compose config en échec : ${images.stderr}\n`);
    return 1;
  }
  const liste = [...new Set(images.stdout.trim().split("\n"))].sort();
  const condenses = [];
  for (const i of liste) {
    const r = spawnSync("docker", ["image", "inspect", "--format", "{{.Id}}", i], { encoding: "utf8" });
    if (r.status !== 0) {
      err.write(`image ${i} absente du magasin local\n`);
      return 1;
    }
    condenses.push(`${i}@${r.stdout.trim()}`);
  }
  const une = (k, total, nature) => {
    dc(["down", "--volumes", "--remove-orphans", "--timeout", "5"]);
    const t0 = process.hrtime.bigint();
    const up = dc(["up", "--detach", "--quiet-pull"]);
    const attente = up.status === 0 ? dc(["wait", "verificateur"], 300000) : null;
    const murale = Number(process.hrtime.bigint() - t0) / 1e9;
    const sortie = dc(["logs", "--no-log-prefix", "--no-color", "verificateur"], 60000).stdout;
    // `docker compose wait` écrit « container "…" exited with status code <n> » et rend <n> comme code.
    const m = attente ? /exited with status code ([0-9]+)/.exec(attente.stdout) : null;
    const code = m ? Number(m[1]) : attente && attente.status !== null ? attente.status : null;
    const r = { imprimee_s: dureeImprimee(sortie), murale_s: murale, code };
    err.write(`${nature} ${k}/${total} : durée imprimée ${r.imprimee_s ?? "absente"} s, murale ${murale.toFixed(3)} s, code ${code ?? "aucun"}\n`);
    return r;
  };
  const mesureA = new Date().toISOString().replace(/\.[0-9]{3}Z$/, "Z");
  let repetitions = [];
  try {
    for (let k = 1; k <= echauffement; k++) une(k, echauffement, "échauffement");
    for (let k = 1; k <= demandees; k++) repetitions.push(une(k, demandees, "répétition"));
  } finally {
    dc(["down", "--volumes", "--remove-orphans", "--timeout", "5"]);
  }
  const commit = commande("git", ["-C", RACINE, "rev-parse", "HEAD"]) ?? "0".repeat(40);
  const doc = rapport({
    repetitions, echauffement, demandees, reference: o.reference, commit, mesureA, images: condenses,
    configuration: { outil: "demo/mesurer-duree.mjs", composition_sha256: createHash("sha256").update(fs.readFileSync(path.join(DEMO, "compose.yaml"))).digest("hex"), echauffement, repetitions: demandees, images: condenses },
  });
  fs.mkdirSync(path.dirname(path.resolve(o.sortie)), { recursive: true });
  fs.writeFileSync(o.sortie, `${JSON.stringify(doc, null, 2)}\n`);
  err.write(`rapport écrit : ${o.sortie} (${doc.results[0].n ?? 0} échantillon(s), max ${doc.results[0].max ?? "absent"} s, counts_for_targets ${doc.counts_for_targets})\n`);
  return 0;
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = principal(process.argv.slice(2));
