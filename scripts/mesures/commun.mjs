// Outils communs aux campagnes de mesure de CT-9 §11 (scripts/mesures/) :
// relevé de la machine (`system`, EX-11.1, EX-11.2), percentiles au plus
// proche rang (EX-11.4), lignes et rapport au format `$defs/rapport_mesure`
// (EX-11.11), validation par l'outil publié de CT-9 (boîte noire).
//
// Rien ici ne décide d'une cible : `met` n'est calculé que si le rapport
// compte pour les cibles, c'est-à-dire sur le système de référence, avec
// `fdatasync` actif et hors disque en mémoire (EX-11.2) ; ailleurs chaque
// ligne porte `met` null et sa raison.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const RACINE = fileURLToPath(new URL("../../", import.meta.url));
export const CATALOGUE = path.join(RACINE, "spec", "vecteurs", "ct-9", "catalogue.json");
export const UNITES = Object.freeze(["ms", "s", "min", "octets", "evenements_par_s", "blocs_par_s", "nombre", "booleen", "ratio", "texte"]);
export const TYPES_DISQUE = Object.freeze(["nvme", "ssd", "hdd", "virtuel", "memoire", "inconnu"]);

export const sha256Hex = (octets) => createHash("sha256").update(octets).digest("hex");
export const arrondi3 = (x) => (x === null || x === undefined ? null : Math.round(x * 1000) / 1000);
export const lireJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));

/**
 * Percentile au plus proche rang (EX-11.4) : la valeur de rang
 * `ceil(p / 100 × N)` de la série triée, N ≥ 1, 0 < p ≤ 100.
 */
export function plusProcheRang(valeurs, p) {
  if (!Array.isArray(valeurs) || valeurs.length === 0) throw new RangeError("série vide");
  if (!(p > 0 && p <= 100)) throw new RangeError("percentile hors de ]0, 100]");
  const tri = Float64Array.from(valeurs).sort();
  return tri[Math.max(1, Math.ceil((p / 100) * tri.length)) - 1];
}

/** Agrégats d'une série (EX-11.4), arrondis au millième de l'unité. */
export function agreger(valeurs) {
  if (!valeurs.length) return { n: null, p50: null, p95: null, p99: null, min: null, max: null, mean: null };
  let min = Infinity;
  let max = -Infinity;
  let somme = 0;
  for (const v of valeurs) {
    if (v < min) min = v;
    if (v > max) max = v;
    somme += v;
  }
  return { n: valeurs.length, p50: arrondi3(plusProcheRang(valeurs, 50)), p95: arrondi3(plusProcheRang(valeurs, 95)), p99: arrondi3(plusProcheRang(valeurs, 99)), min: arrondi3(min), max: arrondi3(max), mean: arrondi3(somme / valeurs.length) };
}

/** Le plus petit échantillon qui porte un percentile au plus proche rang sans le confondre avec le maximum (EX-11.3). */
export const effectifMinimal = (p) => Math.ceil(100 / (100 - p));

const lire = (f) => {
  try {
    return fs.readFileSync(f, "utf8");
  } catch {
    return null;
  }
};

/** Moyenne de charge sur une minute, lue dans /proc/loadavg (null ailleurs que sous Linux). */
export function charge1m() {
  const t = lire("/proc/loadavg");
  const v = t === null ? NaN : Number(t.split(" ")[0]);
  return Number.isFinite(v) ? v : null;
}

/** Les trois moyennes de charge, en texte, pour `conditions` et `notes`. */
export function chargeTexte() {
  const t = lire("/proc/loadavg");
  return t === null ? "moyenne de charge illisible" : `moyenne de charge ${t.split(" ").slice(0, 3).join(", ")} (1, 5 et 15 min)`;
}

/** Type du disque qui porte `chemin` : `memoire` pour tmpfs et ramfs, sinon `rota` de /sys/block (0 : ssd ou nvme ; 1 : hdd), `virtuel` pour un disque virtio, `inconnu` sinon. */
export function typeDisque(chemin) {
  const df = spawnSync("df", ["--output=source,fstype", chemin], { encoding: "utf8" });
  if (df.status !== 0) return "inconnu";
  const [source, fstype] = df.stdout.trim().split("\n").pop().trim().split(/\s+/);
  if (fstype === "tmpfs" || fstype === "ramfs") return "memoire";
  const nom = path.basename(source ?? "");
  if (/^nvme/.test(nom)) return "nvme";
  if (/^vd/.test(nom)) return "virtuel";
  const disque = nom.replace(/p?[0-9]+$/, "");
  const rota = lire(`/sys/block/${disque}/queue/rotational`)?.trim();
  if (rota === "0") return "ssd";
  if (rota === "1") return "hdd";
  return "inconnu";
}

/**
 * Relevé de la machine (`$defs/systeme`). `reference` n'est vrai que si
 * l'opérateur le déclare (`--systeme-de-reference`) ; `disque.type` est celui
 * que l'opérateur déclare, sinon celui que `typeDisque` trouve pour le
 * répertoire de la mesure ; `fsync` est vrai quand `fdatasync` est actif
 * (jamais désactivé par le harnais), null quand la mesure n'écrit rien.
 */
export function systeme({ reference = false, repertoire = null, disque = null, fsync = true, go = null, python = null } = {}) {
  const version = (cmd, args, re) => {
    const r = spawnSync(cmd, args, { encoding: "utf8", env: { ...process.env, GOTOOLCHAIN: "local" } });
    if (r.status !== 0) return null;
    return (r.stdout + r.stderr).match(re)?.[1] ?? null;
  };
  const osRelease = lire("/etc/os-release");
  const aslr = lire("/proc/sys/kernel/randomize_va_space")?.trim() ?? null;
  const gouverneur = lire("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")?.trim() ?? null;
  const virt = spawnSync("systemd-detect-virt", [], { encoding: "utf8" });
  const hyperviseur = /^flags\s*:.*\bhypervisor\b/m.test(lire("/proc/cpuinfo") ?? "");
  return {
    reference,
    cpu: os.cpus()[0]?.model?.trim() || "inconnu",
    cores: os.cpus().length,
    memory_bytes: os.totalmem(),
    disk: { type: disque ?? (repertoire ? typeDisque(repertoire) : "inconnu"), fsync },
    os: osRelease?.match(/^PRETTY_NAME="?([^"\n]+)"?/m)?.[1] ?? `${os.type()} ${os.release()}`,
    kernel: os.release(),
    node: process.version,
    go: go ?? version("go", ["env", "GOVERSION"], /(go[0-9.]+)/),
    python: python ?? version("python3", ["--version"], /Python ([0-9.]+)/),
    cpu_scaling: gouverneur ? (gouverneur === "performance" ? "inactif" : "actif") : "inconnu",
    aslr: aslr === null ? "inconnu" : aslr === "0" ? "inactif" : "actif",
    load_avg_1m: charge1m(),
    virtualized: virt.status === 0 ? virt.stdout.trim() !== "none" : hyperviseur ? true : null,
  };
}

/** Commit du dépôt lu (40 chiffres hexadécimaux) ; lève si git ne le donne pas. */
export function commitDepot(racine = RACINE) {
  const r = spawnSync("git", ["-C", racine, "rev-parse", "HEAD"], { encoding: "utf8" });
  const c = r.status === 0 ? r.stdout.trim() : "";
  if (!/^[0-9a-f]{40}$/.test(c)) throw new Error("commit du dépôt illisible (git rev-parse HEAD)");
  return c;
}

/** L'arbre de travail diffère-t-il du commit ? (dit dans `notes` : le commit éprouvé n'est exact que sur un arbre propre.) */
export function arbreModifie(racine = RACINE) {
  const r = spawnSync("git", ["-C", racine, "status", "--porcelain"], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim().length > 0 : null;
}

/** Entrée TM- du catalogue (cible, unité, mode de comparaison, nom de la ligne principale). */
export function entreeCatalogue(id, catalogue = lireJson(CATALOGUE)) {
  const t = catalogue.tests.find((x) => x.id === id);
  if (!t || t.level !== "TM") throw new Error(`${id} n'est pas une entrée TM- du catalogue`);
  return t;
}

/**
 * Le rapport compte-t-il pour les cibles (EX-11.2) ? Rend { compte, raison }.
 * `raison` est la valeur d'`excluded_reason` des lignes quand il ne compte pas.
 */
export function comptePourLesCibles(sys) {
  if (sys.disk.type === "memoire") return { compte: false, raison: "disque_memoire" };
  if (sys.disk.fsync === false) return { compte: false, raison: "fsync_desactive" };
  if (!sys.reference) return { compte: false, raison: "hors_systeme_de_reference" };
  return { compte: true, raison: null };
}

/**
 * Compare une ligne à la cible de son entrée (EX-11.14). Rend un booléen, ou
 * null quand l'entrée n'a pas de cible, que la valeur manque ou que le mode
 * n'est pas une comparaison numérique.
 */
export function comparer(mesure, l) {
  const c = mesure.target;
  const nb = (x) => typeof x === "number";
  switch (mesure.comparison) {
    case "p50_et_p99_au_plus": return nb(l.p50) && nb(l.p99) && c && nb(c.p50) && nb(c.p99) ? l.p50 <= c.p50 && l.p99 <= c.p99 : null;
    case "p99_au_plus": return nb(l.p99) && nb(c) ? l.p99 <= c : null;
    case "p95_au_plus": return nb(l.p95) && nb(c) ? l.p95 <= c : null;
    case "p50_au_plus": return nb(l.p50) && nb(c) ? l.p50 <= c : null;
    case "au_plus": return nb(c) ? (nb(l.max) ? l.max <= c : nb(l.value) ? l.value <= c : null) : null;
    case "strictement_inferieur": return nb(c) ? (nb(l.max) ? l.max < c : nb(l.value) ? l.value < c : null) : null;
    case "au_moins": return nb(l.value) && nb(c) ? l.value >= c : null;
    default: return null;
  }
}

/**
 * Une ligne de `results[]` (`$defs/resultat_mesure`). `serie` : échantillons
 * dans l'unité, dans l'ordre de collecte, échauffement exclu ; publiés dans la
 * ligne (`samples`) jusqu'à `echantillonsMax`, à part au-delà, avec leur
 * SHA-256 (`samples_sha256` : celui du texte JSON de la série, un tableau de
 * nombres sans espace, que `publierEchantillons` écrit dans
 * `fichierEchantillons` quand il est donné). `percentiles` faux
 * pour une taille (EX-11.4 : `max` et `mean`). `principale` : la ligne porte
 * le `result_name` de son entrée et se compare à sa cible ; une ligne
 * supplémentaire (EX-11.11) n'a ni cible ni `met`.
 */
export function ligne({ name, test_id, unit, serie = null, value = null, text_value = null, n = null, connections = null, percentiles = true, conditions = [], principale = true, exclue = null, compte, catalogue, echantillonsMax = 512, fichierEchantillons = null }) {
  const t = entreeCatalogue(test_id, catalogue);
  if (!UNITES.includes(unit)) throw new Error(`unité ${unit} hors de la liste d'EX-11.6`);
  const a = serie ? agreger(serie) : null;
  const publies = serie && serie.length <= echantillonsMax;
  if (serie && !publies && fichierEchantillons) publierEchantillons(fichierEchantillons, serie);
  const l = {
    name, test_id, unit,
    n: serie ? a.n : n,
    connections,
    samples: serie && publies ? serie.map(arrondi3) : null,
    samples_sha256: serie && !publies ? sha256Hex(JSON.stringify(serie.map(arrondi3))) : null,
    value: value === null ? null : arrondi3(value),
    p50: serie && percentiles ? a.p50 : null,
    p95: serie && percentiles && a.n >= effectifMinimal(95) ? a.p95 : null,
    p99: serie && percentiles && a.n >= effectifMinimal(99) ? a.p99 : null,
    min: serie ? a.min : null,
    max: serie ? a.max : null,
    mean: serie ? a.mean : null,
    text_value,
    target: principale ? t.measure.target : null,
    met: null,
    conditions,
    excluded_reason: null,
  };
  const sansCible = !principale || t.measure.comparison === "aucune_cible" || t.measure.target === null;
  if (!compte.compte) l.excluded_reason = exclue ?? compte.raison;
  else if (exclue) l.excluded_reason = exclue;
  else if (sansCible) l.excluded_reason = "aucune_cible";
  else {
    l.met = comparer(t.measure, l);
    if (l.met === null) l.excluded_reason = "echantillon_insuffisant";
  }
  return l;
}

/** Écrit les échantillons d'une ligne à part (EX-11.4) ; rend le SHA-256 du fichier, égal au `samples_sha256` de la ligne. */
export function publierEchantillons(fichier, serie) {
  const texte = JSON.stringify(serie.map(arrondi3));
  fs.writeFileSync(fichier, texte);
  return sha256Hex(texte);
}

/**
 * Assemble un rapport `$defs/rapport_mesure`. `spec_version` est lu dans le
 * catalogue (version de CT-9) ; `measured_at` est l'instant d'écriture.
 */
export function rapportMesure({ sys, compte = comptePourLesCibles(sys), methode, configurationSha256 = null, results, notes = [], maintenant = new Date(), racine = RACINE, catalogue = lireJson(CATALOGUE) }) {
  const iso = maintenant.toISOString();
  const r = {
    version: 0,
    kind: "rapport-mesure",
    date: iso.slice(0, 10),
    measured_at: iso.replace(/\.[0-9]{3}Z$/, "Z"),
    commit: commitDepot(racine),
    spec_version: catalogue.spec_version,
    system: sys,
    method: { warmup: methode.warmup, repetitions: methode.repetitions, percentile_method: "plus_proche_rang", clock: methode.clock, pair_with_without: methode.pair_with_without === true, samples_published: methode.samples_published !== false },
    configuration_sha256: configurationSha256,
    counts_for_targets: compte.compte,
    results,
  };
  if (notes.length) r.notes = notes.join(" ");
  return r;
}

/**
 * Valide un rapport par l'outil publié de CT-9 (`scripts/tests/mesures.mjs`,
 * boîte noire) sur une racine temporaire où il est posé à côté des rapports
 * publiés ; rend { code, texte }. Rien n'est écrit dans le dépôt.
 */
export function validerRapport(cheminRapport, nomPublie = path.basename(cheminRapport), racine = RACINE) {
  if (!/^rapport-.*\.json$/.test(nomPublie)) throw new Error("un rapport de mesure se nomme rapport-<AAAA-MM-JJ>-<etiquette>.json (EX-11.11)");
  const T = fs.mkdtempSync(path.join(process.env.NOORTRACE_TMP || os.tmpdir(), "noortrace-mesure-validation-"));
  try {
    fs.mkdirSync(path.join(T, "spec", "vecteurs", "ct-9"), { recursive: true });
    fs.symlinkSync(path.join(racine, "spec", "schemas"), path.join(T, "spec", "schemas"));
    for (const n of fs.readdirSync(path.join(racine, "spec", "vecteurs"))) if (n !== "ct-9") fs.symlinkSync(path.join(racine, "spec", "vecteurs", n), path.join(T, "spec", "vecteurs", n));
    const ct9 = path.join(racine, "spec", "vecteurs", "ct-9");
    for (const n of fs.readdirSync(ct9)) if (n !== "mesures") fs.symlinkSync(path.join(ct9, n), path.join(T, "spec", "vecteurs", "ct-9", n));
    const mesures = path.join(T, "spec", "vecteurs", "ct-9", "mesures");
    fs.mkdirSync(mesures);
    for (const n of fs.readdirSync(path.join(ct9, "mesures"))) if (n !== nomPublie) fs.symlinkSync(path.join(ct9, "mesures", n), path.join(mesures, n));
    fs.copyFileSync(cheminRapport, path.join(mesures, nomPublie));
    const r = spawnSync(process.execPath, [path.join(racine, "scripts", "tests", "mesures.mjs"), "--racine", T, "--json"], { cwd: racine, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    let ecarts = null;
    try {
      ecarts = JSON.parse(r.stdout).errors ?? null;
    } catch {
      ecarts = null;
    }
    return { code: r.status, texte: `${r.stdout ?? ""}${r.stderr ?? ""}`, ecarts };
  } finally {
    fs.rmSync(T, { recursive: true, force: true });
  }
}

/** Écrit un rapport après l'avoir fait valider (EX-11.11) ; lève, sans rien laisser, si l'outil de CT-9 le refuse. */
export function ecrireRapportValide(chemin, rapport) {
  const provisoire = `${chemin}.provisoire`;
  fs.mkdirSync(path.dirname(chemin), { recursive: true });
  fs.writeFileSync(provisoire, JSON.stringify(rapport, null, 2) + "\n");
  let v;
  try {
    v = validerRapport(provisoire, path.basename(chemin));
  } catch (e) {
    fs.rmSync(provisoire, { force: true });
    throw e;
  }
  if (v.code !== 0) {
    fs.rmSync(provisoire, { force: true });
    const detail = Array.isArray(v.ecarts) && v.ecarts.length ? v.ecarts.join("\n") : v.texte.slice(-3000);
    throw new Error(`rapport refusé par scripts/tests/mesures.mjs (code ${v.code}) :\n${detail}`);
  }
  fs.renameSync(provisoire, chemin);
  return v;
}
