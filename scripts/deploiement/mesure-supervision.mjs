#!/usr/bin/env node
// Campagnes de mesure de la supervision en marche (CT-9 §11 ; entrées TM-34 et
// TM-35 du catalogue), sur une installation locale : collecteur Prometheus
// 3.5.0 (scripts/deploiement/collecteur.mjs), règles de référence de CT-8 §10.4
// à §10.7, extracteur des journaux et sonde de référence. Aucune horloge n'est
// manipulée (EX-11.5) : les durées sont attendues en temps réel. Rien ne joint
// un réseau public. Hors du système de référence de la porte 2, les rapports
// portent `counts_for_targets` faux et `met` null (EX-11.2).
//
//   node scripts/deploiement/mesure-supervision.mjs tm-34 --travail <répertoire neuf> --sortie-rapport <fichier>
//       [--duree-nominale-s 3600] [--cadence 50] [--connexions 16] [--stockage <répertoire>] [--marge-mio 256]
//       [--disque nvme|ssd|hdd|virtuel|memoire|inconnu] [--registre <port RPC>,<port des métriques>]
//       [--scenarios stockage,quota,serveur,registre,definition] [--prometheus <binaire>] [--note <texte>]…
//     TM-34 : démon réel de l'enregistreur sous la charge à cadence fixe de
//     l'hôte de test (EX-11.9), fenêtre nominale, puis scénarios provoqués un à
//     un. Faux positif : une règle déclenchée pendant la fenêtre nominale. Faux
//     négatif : une règle attendue d'un scénario qui ne se déclenche pas dans
//     sa fenêtre. Une ligne par règle dont l'expression est une comparaison à
//     un seuil : valeur extrême du membre comparé pendant la fenêtre nominale,
//     et valeur atteinte dans le scénario qui l'attend. Le seuil
//     storage.min_free_bytes du démon vaut l'espace libre au montage moins
//     --marge-mio : la marge doit dépasser ce que la fenêtre nominale écrit
//     (environ 2 Kio par appel), et le système de fichiers de --stockage ne
//     doit servir à rien d'autre, sans quoi l'espace libre passe sous le seuil
//     hors de tout scénario.
//
//   node scripts/deploiement/mesure-supervision.mjs tm-35 relever --rpc <cible>=<url>… --duree-s <n> --sortie <fichier.ndjson>
//     Relève chaque seconde, à cadence fixe, eth_getBlockTransactionCountByNumber("pending")
//     de chaque point RPC (la lecture de la sonde de référence, CT-8 EX-10.7) ;
//     une ligne JSON par relevé. Aucune transaction n'est soumise.
//
//   node scripts/deploiement/mesure-supervision.mjs tm-35 rapport --echantillons <fichier.ndjson> --debut <instant> --fin <instant>
//       --txpool-max-pending <n> --source-m <texte> --charge <texte> --sortie-rapport <fichier>
//       [--collecteur <url>] [--note <texte>]…
//     TM-35 : rapport du relevé sur la fenêtre [début, fin] ; `<M>` est la
//     moitié de --txpool-max-pending, dont --source-m dit d'où la valeur est lue.
//
// Codes : 0 rapport écrit (que les cibles soient tenues ou non) ; 1 échec de
// la campagne ; 2 usage ; 3 binaire Prometheus 3.5.0 absent.

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import yaml from "js-yaml";
import { binairePrometheus, ClientCollecteur } from "./collecteur.mjs";
import { monterSupervision, demonterSupervision, jouerProvocation, PROVOCATIONS, lireSupervision } from "../../test/fixtures/supervision-collecteur/montage.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const CATALOGUE = path.join(RACINE, "spec", "vecteurs", "ct-9", "catalogue.json");

class Usage extends Error {}
class Echec extends Error {}

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (m) => process.stderr.write(`mesure-supervision ${new Date().toISOString()} : ${m}\n`);
const ecrireJson = (f, o) => fs.writeFileSync(f, `${JSON.stringify(o, null, 2)}\n`);
const sha256 = (octets) => crypto.createHash("sha256").update(octets).digest("hex");

/** Machine de la mesure (`$defs/systeme`) : jamais déclarée système de référence par cet outil. */
export function systeme(disque) {
  const lire = (f) => {
    try {
      return fs.readFileSync(f, "utf8");
    } catch {
      return null;
    }
  };
  const version = (cmd, args, re) => {
    const r = spawnSync(cmd, args, { encoding: "utf8", env: { ...process.env, GOTOOLCHAIN: "local" } });
    if (r.error || r.status !== 0) return null;
    return (r.stdout + r.stderr).match(re)?.[1] ?? null;
  };
  const osRelease = lire("/etc/os-release");
  const aslr = lire("/proc/sys/kernel/randomize_va_space")?.trim() ?? null;
  const gouverneur = lire("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")?.trim() ?? null;
  const virt = lire("/proc/cpuinfo")?.match(/^flags\s*:.*\bhypervisor\b/m) ? true : lire("/proc/cpuinfo") === null ? null : false;
  return {
    reference: false,
    cpu: os.cpus()[0]?.model?.trim() || "inconnu",
    cores: os.cpus().length,
    memory_bytes: os.totalmem(),
    disk: disque,
    os: osRelease?.match(/^PRETTY_NAME="?([^"\n]+)"?/m)?.[1] ?? `${os.type()} ${os.release()}`,
    kernel: os.release(),
    node: process.version,
    go: version("go", ["env", "GOVERSION"], /(go[0-9.]+)/),
    python: version("python3", ["--version"], /Python ([0-9.]+)/),
    cpu_scaling: gouverneur ? (gouverneur === "performance" ? "inactif" : "actif") : "inconnu",
    aslr: aslr === null ? "inconnu" : aslr === "0" ? "inactif" : "actif",
    load_avg_1m: Math.round(os.loadavg()[0] * 100) / 100,
    virtualized: virt,
  };
}

/** Commit éprouvé et état de l'arbre de travail. */
function depot() {
  const c = spawnSync("git", ["rev-parse", "HEAD"], { cwd: RACINE, encoding: "utf8" });
  const s = spawnSync("git", ["status", "--porcelain"], { cwd: RACINE, encoding: "utf8" });
  if (c.status !== 0 || !/^[0-9a-f]{40}$/.test(c.stdout.trim())) throw new Echec("commit du dépôt illisible (git rev-parse HEAD)");
  const modifies = s.status === 0 ? s.stdout.split("\n").filter((l) => l.trim() !== "").length : null;
  return { commit: c.stdout.trim(), modifies };
}

function entreeCatalogue(id) {
  const c = JSON.parse(fs.readFileSync(CATALOGUE, "utf8"));
  const e = c.tests.find((t) => t.id === id);
  if (!e?.measure) throw new Echec(`entrée ${id} absente du catalogue`);
  return { version: c.spec_version, mesure: e.measure };
}

/** Ligne de résultat (`$defs/resultat_mesure`), hors système de référence : `met` null. */
function ligne(o) {
  return {
    name: o.name, test_id: o.test_id, unit: o.unit, n: o.n ?? null, connections: o.connections ?? null,
    samples: o.samples ?? null, samples_sha256: o.samples_sha256 ?? null,
    value: o.value ?? null, p50: null, p95: null, p99: null, min: o.min ?? null, max: o.max ?? null, mean: o.mean ?? null,
    text_value: o.text_value ?? null, target: o.target ?? null, met: null, conditions: o.conditions, excluded_reason: "hors_systeme_de_reference",
  };
}

function rapport({ entree, disque, methode, configurationSha256, lignes, notes }) {
  const d = depot();
  const maintenant = new Date();
  const toutes = [...notes];
  if (d.modifies) toutes.push(`arbre de travail non propre à la mesure : ${d.modifies} chemin(s) modifié(s) ou nouveau(x) (git status --porcelain)`);
  return {
    version: 0,
    kind: "rapport-mesure",
    date: maintenant.toISOString().slice(0, 10),
    measured_at: maintenant.toISOString().replace(/\.[0-9]{3}Z$/, "Z"),
    commit: d.commit,
    spec_version: entree.version,
    system: systeme(disque),
    method: { warmup: entree.mesure.warmup, repetitions: entree.mesure.repetitions, percentile_method: "plus_proche_rang", clock: methode.clock, pair_with_without: false, samples_published: methode.samples_published },
    configuration_sha256: configurationSha256,
    counts_for_targets: false,
    results: lignes,
    notes: toutes.join(" ; "),
  };
}

/** Forme « première occurrence » d'EX-10.6 d'une règle simple : branche de gauche, série, fenêtre, comparateur et seuil répétés. */
const RE_PREMIERE_OCCURRENCE = /^\(((?:increase|rate)\((\S+?)\[([0-9]+[smhdwy])\]\) (>=?) ([0-9]+))\) or \(\(\2 unless \2 offset ([0-9]+[smhdwy])\) (>=?) ([0-9]+)\)$/;

/**
 * Membre comparé et seuil d'une expression de règle de la forme
 * `<membre> <comparateur> <nombre>`, sans `and`, `or` ni `unless` au niveau
 * supérieur ; null pour toute autre forme (dont un seuil écrit en produit).
 * La forme « première occurrence » d'une règle simple (CT-8 EX-10.6 :
 * `(<membre> OP n) or ((x unless x offset w) OP n)`) rend le membre et le seuil
 * de sa branche de gauche, qui est la règle de la table.
 * @returns {{membre: string, comparateur: string, seuil: number}|null}
 */
export function membreCompare(expr) {
  const po = RE_PREMIERE_OCCURRENCE.exec(expr.trim());
  if (po && po[3] === po[6] && po[4] === po[7] && po[5] === po[8]) return membreCompare(po[1]);
  const m = /^([\s\S]*\S)\s*(>=|<=|==|!=|>|<)\s*(-?[0-9]+(?:\.[0-9]+)?(?:e[+-]?[0-9]+)?)\s*$/.exec(expr.trim());
  if (!m) return null;
  let profondeur = 0;
  let chaine = null;
  const g = m[1];
  for (let k = 0; k < g.length; k++) {
    const c = g[k];
    if (chaine) {
      if (c === "\\") k++;
      else if (c === chaine) chaine = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") chaine = c;
    else if ("([{".includes(c)) profondeur++;
    else if (")]}".includes(c)) profondeur--;
    else if (profondeur === 0 && /^\s(and|or|unless)\s/.test(g.slice(k, k + 8))) return null;
    if (profondeur < 0) return null;
  }
  if (profondeur !== 0 || chaine) return null;
  return { membre: g, comparateur: m[2], seuil: Number(m[3]) };
}

/** Valeurs extrêmes du membre comparé d'une règle sur une fenêtre close à `finS`. */
async function extremes(collecteur, membre, finS, dureeS, pasS) {
  const fenetre = `[${dureeS}s:${pasS}s]`;
  try {
    const maxs = await collecteur.requete(`max_over_time((${membre})${fenetre})`, finS);
    const mins = await collecteur.requete(`min_over_time((${membre})${fenetre})`, finS);
    if (!maxs.length) return { series: 0, max: null, min: null, erreur: null };
    return { series: maxs.length, max: Math.max(...maxs.map((x) => x.valeur)), min: Math.min(...mins.map((x) => x.valeur)), erreur: null };
  } catch (e) {
    return { series: 0, max: null, min: null, erreur: e.message };
  }
}

const fini = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);

async function campagneTm34(o) {
  const b = binairePrometheus({ chemin: o.prometheus });
  if (!b.ok) {
    process.stderr.write(`Condition absente : ${b.condition}\n`);
    return 3;
  }
  if (fs.existsSync(o.travail) && fs.readdirSync(o.travail).length) throw new Usage("--travail : répertoire neuf ou vide attendu");
  const entree = entreeCatalogue("TM-34");
  const scenarios = o.scenarios;
  for (const sc of scenarios) if (!PROVOCATIONS[sc]) throw new Usage(`--scenarios : ${sc} inconnu (${Object.keys(PROVOCATIONS).join(", ")})`);
  if (scenarios.includes("registre") && !o.registre) throw new Usage("--scenarios registre exige --registre <port RPC>,<port des métriques>");
  if (scenarios.includes("definition") && scenarios.at(-1) !== "definition") throw new Usage("--scenarios : definition se joue en dernier (règle à fenêtre d'une heure, sans attente de résolution)");
  log(`TM-34 : montage sous ${o.travail} ; cadence ${o.cadence} appels/s sur ${o.connexions} connexions ; fenêtre nominale ${o.dureeNominaleS} s ; scénarios ${scenarios.join(", ") || "aucun"}`);
  let s;
  try {
    s = await monterSupervision(o.travail, { cadence: o.cadence, connexions: o.connexions, stockage: o.stockage, margeOctets: o.margeMio * 1024 * 1024, registre: o.registre, gardeLatences: false });
  } catch (e) {
    throw new Echec(`montage impossible : ${e.message}`);
  }
  const brut = { outil: "scripts/deploiement/mesure-supervision.mjs tm-34", prometheus: { version: b.version, sha256: b.sha256 }, cadence: o.cadence, connexions: o.connexions, intervalle_s: s.collecteur.intervalleS, nominal: null, scenarios: [] };
  let code = 0;
  // Interruption (SIGTERM, SIGINT) : tout ce que la campagne a lancé est arrêté, aucun rapport n'est écrit.
  const interrompre = async () => {
    log("campagne interrompue : arrêt du montage, aucun rapport écrit");
    await demonterSupervision(s);
    process.exit(1);
  };
  process.once("SIGTERM", interrompre);
  process.once("SIGINT", interrompre);
  try {
    const c = s.collecteur;
    // L'API de Prometheus 3.5.0 rend les groupes de règles triés par nom (noortrace-ancrage, noortrace-enregistreur…),
    // non dans l'ordre du fichier : les lignes du rapport suivent l'ordre du fichier de règles chargé, celui des tables
    // de CT-8 §10.4 à §10.7.
    const ordre = yaml.load(fs.readFileSync(c.fichierRegles, "utf8")).groups.flatMap((g) => g.rules.map((r) => r.alert));
    const regles = (await c.regles()).sort((a, b) => ordre.indexOf(a.nom) - ordre.indexOf(b.nom));
    brut.regles = regles.length;
    // Amorce : deux intervalles d'évaluation avant la charge, pour que chaque cible soit collectée une fois.
    await pause(2 * c.intervalleS * 1000);
    brut.cibles = await c.cibles();
    s.hote.demarrer();
    await pause(2 * c.intervalleS * 1000);
    const debut = Math.floor(Date.now() / 1000);
    log(`fenêtre nominale ouverte (${new Date(debut * 1000).toISOString()})`);
    const tDebut = performance.now();
    while (performance.now() - tDebut < o.dureeNominaleS * 1000) {
      await pause(Math.min(60000, o.dureeNominaleS * 1000 - (performance.now() - tDebut) + 1));
      const actives = (await c.alertes()).filter((a) => a.etat === "firing").map((a) => a.nom);
      log(`nominal ${Math.round((performance.now() - tDebut) / 1000)} s : ${s.hote.envoyes} appels envoyés, ${s.hote.erreurs} en erreur ; alertes déclenchées : ${actives.join(", ") || "aucune"}`);
    }
    const fin = Math.ceil(Date.now() / 1000);
    const pas = Math.min(5, c.intervalleS);
    const tr = await c.transitions(debut, fin, pas);
    const fauxPositifs = [...tr].filter(([, v]) => v.transitions > 0 || v.declenchee_au_debut).map(([nom, v]) => ({ regle: nom, transitions: v.transitions, declenchee_au_debut: v.declenchee_au_debut, gravites: v.gravites }));
    const parRegle = [];
    for (const r of regles) {
      const mc = membreCompare(r.expr);
      parRegle.push({ regle: r.nom, expr: r.expr, for_s: r.for_s, compare: mc, nominal: mc ? await extremes(c, mc.membre, fin, fin - debut, c.intervalleS) : null });
    }
    brut.nominal = {
      debut_s: debut, fin_s: fin, appels_envoyes: s.hote.envoyes, appels_en_erreur: s.hote.erreurs, codes: Object.fromEntries(s.hote.codes),
      ecritures: { ...s.hote.ecritures, codes: Object.fromEntries(s.hote.ecritures.codes) }, listes: s.hote.listes, faux_positifs: fauxPositifs,
      sante: (await lireSupervision(s.m, "/healthz")).texte, cibles: await c.cibles(), regles_en_erreur: (await c.regles()).filter((r) => r.sante !== "ok").map((r) => ({ regle: r.nom, erreur: r.erreur })),
    };
    log(`fenêtre nominale close : ${fauxPositifs.length} règle(s) déclenchée(s) en nominal`);
    for (const sc of scenarios) {
      const compte = await jouerProvocation(s, sc, log);
      for (const a of compte.attendues) {
        const mc = membreCompare(regles.find((r) => r.nom === a.regle).expr);
        a.atteint = mc ? await extremes(c, mc.membre, compte.fenetre.fin_s, compte.fenetre.fin_s - compte.fenetre.debut_s, c.intervalleS) : null;
      }
      brut.scenarios.push(compte);
    }
    const fauxNegatifs = brut.scenarios.flatMap((x) => x.attendues.filter((a) => a.transitions === 0).map((a) => ({ scenario: x.provocation, regle: a.regle })));
    const configurationSha256 = sha256(fs.readFileSync(s.m.chemin));
    const communes = [
      `hôte de test à cadence fixe (EX-11.9) : ${o.cadence} appels de lecture par seconde sur ${o.connexions} connexions, un appel d'écriture par seconde, un tools/list toutes les 5 s ; serveur d'outils nul`,
      `storage.min_free_bytes = ${s.m.config.storage.min_free_bytes} (espace libre au montage moins ${o.margeMio} Mio)`,
      `collecteur Prometheus ${b.version}, ${regles.length} règles de référence régénérées depuis la configuration du montage (scripts/deploiement/regles.mjs --configuration, CT-8 EX-10.6 ; pending_max_ms ${s.m.config.policy.failure.pending_max_ms}), intervalle de collecte et d'évaluation ${c.intervalleS} s`,
      `cibles collectées : ${brut.cibles.map((t) => `${t.job} (${t.sante})`).join(", ")} ; exportateur de nœud absent : aucune métrique node_*`,
    ];
    const joues = brut.scenarios.map((x) => `${x.provocation} (${x.runbook})`).join(", ") || "aucun";
    const rejoues = [...new Set(brut.scenarios.map((x) => x.runbook).filter((r) => r !== "aucun"))].sort();
    const nonRejoues = ["RB-1", "RB-2", "RB-3", "RB-4", "RB-5", "RB-6", "RB-7", "RB-8"].filter((r) => !rejoues.includes(r));
    const lignes = [
      ligne({ name: entree.mesure.result_name, test_id: "TM-34", unit: entree.mesure.unit, n: regles.length, connections: o.connexions, value: fauxPositifs.length, target: entree.mesure.target, conditions: [
        `fenêtre nominale de ${fin - debut} s (cible de l'entrée : une heure)`, ...communes,
        `règles déclenchées en nominal : ${fauxPositifs.map((x) => `${x.regle} (${x.transitions} transition(s)${x.declenchee_au_debut ? ", déclenchée au début" : ""})`).join(", ") || "aucune"}`,
      ] }),
      ligne({ name: "supervision_faux_negatifs", test_id: "TM-34", unit: entree.mesure.unit, n: brut.scenarios.reduce((k, x) => k + x.attendues.length, 0) || null, connections: o.connexions, value: brut.scenarios.length ? fauxNegatifs.length : null, target: entree.mesure.target, conditions: [
        `scénarios joués : ${joues}`,
        `runbooks rejoués par ces scénarios : ${rejoues.join(", ") || "aucun"} ; non rejoués sur ce montage : ${nonRejoues.join(", ") || "aucun"}`,
        ...communes,
        `règles attendues non déclenchées : ${fauxNegatifs.map((x) => `${x.regle} (${x.scenario})`).join(", ") || "aucune"}`,
      ] }),
    ];
    for (const r of parRegle) {
      const suffixe = r.regle.replace(/^noortrace_/, "");
      if (!r.compare) {
        lignes.push(ligne({ name: `supervision_nominal_${suffixe}`, test_id: "TM-34", unit: entree.mesure.unit, conditions: [`règle ${r.regle} : ${r.expr}`, "expression composée, ou comparée à autre chose qu'un nombre : aucun membre comparé à un seuil littéral unique, valeur non relevée"] }));
        continue;
      }
      const n = r.nominal;
      lignes.push(ligne({ name: `supervision_nominal_${suffixe}`, test_id: "TM-34", unit: entree.mesure.unit, n: n.series || null, max: fini(n.max), min: fini(n.min), target: r.compare.seuil, conditions: [
        `règle ${r.regle} : ${r.expr}${r.for_s ? ` pendant ${r.for_s} s` : ""}`,
        `membre comparé (${r.compare.comparateur} ${r.compare.seuil}), dans son unité : ${r.compare.membre}`,
        n.erreur ? `requête en erreur : ${n.erreur}` : n.series ? `extrêmes sur la fenêtre nominale, ${n.series} série(s), un point par intervalle d'évaluation` : "aucune série dans ce montage pendant la fenêtre nominale",
      ] }));
    }
    for (const x of brut.scenarios) {
      for (const a of x.attendues) {
        const mc = membreCompare(regles.find((r) => r.nom === a.regle).expr);
        lignes.push(ligne({ name: `supervision_scenario_${x.provocation}_${a.regle.replace(/^noortrace_/, "")}`, test_id: "TM-34", unit: entree.mesure.unit, n: a.atteint?.series || null, max: fini(a.atteint?.max), min: fini(a.atteint?.min), value: a.transitions, target: mc?.seuil ?? null, conditions: [
          `scénario ${x.provocation} (${x.runbook}) : ${x.geste}`,
          `règle attendue ${a.regle} (${a.gravite}) : ${a.cause}`,
          `value : transitions vers l'état déclenché sur la fenêtre du scénario (${x.fenetre.fin_s - x.fenetre.debut_s} s) ; ${a.levee ? `levée ${a.apres_s} s après la provocation, gravité relevée ${a.gravite_relevee}` : `non levée en ${a.delai_s} s`}`,
          mc ? `max et min : extrêmes du membre comparé (${mc.comparateur} ${mc.seuil}) sur la fenêtre du scénario : ${mc.membre}` : "expression composée : membre non relevé",
        ] }));
      }
    }
    const notes = [
      "mesure hors du système de référence de la porte 2 (EX-11.2) : valeurs indicatives",
      `TM-34 : faux positif = règle déclenchée pendant la fenêtre nominale ; faux négatif = règle attendue d'un scénario sans transition vers l'état déclenché dans sa fenêtre ; règles en dehors des listes attendues pendant les scénarios : ${brut.scenarios.flatMap((x) => x.hors_liste.map((h) => `${h.regle} (${x.provocation})`)).join(", ") || "aucune"}`,
      ...o.notes,
    ];
    const r = rapport({ entree, disque: o.disque, methode: { clock: "sans_objet", samples_published: false }, configurationSha256, lignes, notes });
    ecrireJson(path.join(o.travail, "campagne.json"), brut);
    ecrireJson(o.sortieRapport, r);
    log(`rapport écrit : ${o.sortieRapport} ; faux positifs ${fauxPositifs.length}, faux négatifs ${brut.scenarios.length ? fauxNegatifs.length : "non mesurés"}`);
  } catch (e) {
    ecrireJson(path.join(o.travail, "campagne-interrompue.json"), { ...brut, erreur: String(e?.stack ?? e) });
    log(`échec : ${e?.message ?? e}`);
    code = 1;
  } finally {
    process.removeListener("SIGTERM", interrompre);
    process.removeListener("SIGINT", interrompre);
    const codeDemon = await demonterSupervision(s);
    log(`démon arrêté (code ${codeDemon})`);
  }
  return code;
}

/**
 * Instants prévus des relevés de TM-35, un par seconde à partir de `debut`
 * (horloge monotone, ms) : `dureeS` relevés exactement. Le nombre de relevés
 * se compte en entiers : comparer `debut + n × 1000 − debut` à la durée en
 * virgule flottante en ferait un de trop pour certaines valeurs de `debut`
 * (par exemple 100.743336 : (debut + 4000) − debut = 3999.9999999999995).
 * @param {number} debut
 * @param {number} dureeS
 * @returns {number[]}
 */
export function instantsReleves(debut, dureeS) {
  return Array.from({ length: dureeS }, (_, n) => debut + n * 1000);
}

async function releverTm35(o) {
  const debut = performance.now();
  let n = 0;
  const lire = async (url) => {
    try {
      const rep = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getBlockTransactionCountByNumber", params: ["pending"] }), signal: AbortSignal.timeout(900) });
      const j = await rep.json();
      return typeof j.result === "string" && /^0x[0-9a-f]+$/.test(j.result) ? Number(BigInt(j.result)) : null;
    } catch {
      return null;
    }
  };
  log(`TM-35 : relevé de ${o.dureeS} s sur ${Object.keys(o.rpc).join(", ")}`);
  for (const prevu of instantsReleves(debut, o.dureeS)) {
    const attente = prevu - performance.now();
    if (attente > 0) await pause(attente);
    n++;
    const mempool = {};
    await Promise.all(Object.entries(o.rpc).map(async ([cible, url]) => {
      mempool[cible] = await lire(url);
    }));
    fs.appendFileSync(o.sortie, JSON.stringify({ t: new Date().toISOString(), mono_ms: Math.round(performance.now() - debut), prevu_ms: (n - 1) * 1000, mempool }) + "\n");
  }
  log(`${n} relevés écrits dans ${o.sortie}`);
  return 0;
}

async function rapportTm35(o) {
  const entree = entreeCatalogue("TM-35");
  const brutes = fs.readFileSync(o.echantillons);
  const lignesLues = brutes.toString("utf8").split("\n").filter((l) => l.trim() !== "").map((l) => JSON.parse(l));
  const dans = lignesLues.filter((l) => Date.parse(l.t) >= o.debut && Date.parse(l.t) < o.fin);
  if (!dans.length) throw new Echec("aucun relevé dans la fenêtre [--debut, --fin[");
  const cibles = [...new Set(dans.flatMap((l) => Object.keys(l.mempool)))].sort();
  const parCible = Object.fromEntries(cibles.map((c) => [c, dans.map((l) => l.mempool[c]).filter((v) => v !== null && v !== undefined)]));
  // Un échantillon par relevé : la plus grande file lue sur les points RPC à cet instant.
  const samples = dans.map((l) => Object.values(l.mempool).filter((v) => v !== null && v !== undefined)).filter((v) => v.length).map((v) => Math.max(...v));
  const sansReponse = dans.length - samples.length;
  const m = o.txpoolMaxPending / 2;
  const moyenne = (v) => Math.round((v.reduce((a, x) => a + x, 0) / v.length) * 1000) / 1000;
  const fenetre = `fenêtre du ${new Date(o.debut).toISOString()} au ${new Date(o.fin).toISOString()} (${Math.round((o.fin - o.debut) / 1000)} s)`;
  const communes = [
    o.charge,
    `\`<M>\` = ${m} : moitié de -txpool-max-pending = ${o.txpoolMaxPending} ; ${o.sourceM}`,
    `${fenetre} ; un relevé par seconde à cadence fixe de eth_getBlockTransactionCountByNumber("pending") sur ${cibles.length} point(s) RPC (${cibles.join(", ")}) ; ${sansReponse} relevé(s) sans aucune réponse`,
  ];
  const lignes = [
    ligne({ name: entree.mesure.result_name, test_id: "TM-35", unit: entree.mesure.unit, n: samples.length, samples: null, samples_sha256: sha256(brutes), max: Math.max(...samples), min: Math.min(...samples), mean: moyenne(samples), target: m, conditions: [
      ...communes,
      "échantillon : à chaque relevé, la plus grande file lue sur les points RPC ; échantillons bruts publiés à part (samples_sha256 : SHA-256 du fichier des relevés)",
    ] }),
  ];
  for (const c of cibles) {
    const v = parCible[c];
    lignes.push(ligne({ name: `mempool_max_${c.replace(/[^a-z0-9]+/g, "_")}`, test_id: "TM-35", unit: entree.mesure.unit, n: v.length || null, max: v.length ? Math.max(...v) : null, min: v.length ? Math.min(...v) : null, mean: v.length ? moyenne(v) : null, target: m, conditions: [`point RPC ${c}`, ...communes] }));
  }
  if (o.collecteur) {
    const c = new ClientCollecteur(o.collecteur);
    const finS = Math.floor(o.fin / 1000);
    const dureeS = Math.round((o.fin - o.debut) / 1000);
    const maxs = await c.requete(`max_over_time(noortrace_registre_mempool[${dureeS}s])`, finS);
    const comptes = await c.requete(`count_over_time(noortrace_registre_mempool[${dureeS}s])`, finS);
    const tr = await c.transitions(Math.floor(o.debut / 1000), finS, 5);
    lignes.push(ligne({ name: "mempool_max_collecteur", test_id: "TM-35", unit: entree.mesure.unit, n: comptes.reduce((a, x) => a + x.valeur, 0) || null, max: maxs.length ? Math.max(...maxs.map((x) => x.valeur)) : null, target: m, conditions: [
      "jauge noortrace_registre_mempool de la sonde de référence (scripts/deploiement/sonde.mjs, passage de 15 s), collectée par Prometheus : max_over_time sur la fenêtre, toutes cibles",
      `règle noortrace_registre_mempool (seuil de référence du fichier de règles) : ${tr.get("noortrace_registre_mempool")?.transitions ?? 0} transition(s) vers l'état déclenché sur la fenêtre`,
      ...communes,
    ] }));
  }
  const notes = ["mesure hors du système de référence de la porte 2 (EX-11.2) : valeurs indicatives", ...o.notes];
  ecrireJson(o.sortieRapport, rapport({ entree, disque: { type: "virtuel", fsync: null }, methode: { clock: "sans_objet", samples_published: false }, configurationSha256: null, lignes, notes }));
  log(`rapport écrit : ${o.sortieRapport} ; max observé ${Math.max(...samples)}, <M> = ${m}`);
  return 0;
}

const USAGE = [
  "Usage : node scripts/deploiement/mesure-supervision.mjs tm-34 --travail <répertoire neuf> --sortie-rapport <fichier> [--duree-nominale-s 3600] [--cadence 50] [--connexions 16]",
  "          [--stockage <répertoire>] [--marge-mio 256] [--disque nvme|ssd|hdd|virtuel|memoire|inconnu] [--registre <port RPC>,<port des métriques>] [--scenarios <liste>] [--prometheus <binaire>] [--note <texte>]…",
  "        node scripts/deploiement/mesure-supervision.mjs tm-35 relever --rpc <cible>=<url>… --duree-s <n> --sortie <fichier.ndjson>",
  "        node scripts/deploiement/mesure-supervision.mjs tm-35 rapport --echantillons <fichier.ndjson> --debut <instant> --fin <instant> --txpool-max-pending <n>",
  "          --source-m <texte> --charge <texte> --sortie-rapport <fichier> [--collecteur <url>] [--note <texte>]…",
].join("\n");

const entier = (v, nom, min, max) => {
  if (!/^[0-9]{1,9}$/.test(v ?? "") || Number(v) < min || Number(v) > max) throw new Usage(`--${nom} : entier de ${min} à ${max} attendu`);
  return Number(v);
};

export async function principal(argv) {
  try {
    if (argv[0] === "tm-34") {
      const o = parseArgs({ args: argv.slice(1), strict: true, allowPositionals: false, options: {
        travail: { type: "string" }, "sortie-rapport": { type: "string" }, "duree-nominale-s": { type: "string" }, cadence: { type: "string" }, connexions: { type: "string" },
        stockage: { type: "string" }, "marge-mio": { type: "string" }, disque: { type: "string" }, registre: { type: "string" }, scenarios: { type: "string" }, prometheus: { type: "string" }, note: { type: "string", multiple: true },
      } }).values;
      if (!o.travail || !o["sortie-rapport"]) throw new Usage("--travail et --sortie-rapport attendus");
      const disque = o.disque ?? "inconnu";
      if (!["nvme", "ssd", "hdd", "virtuel", "memoire", "inconnu"].includes(disque)) throw new Usage("--disque : nvme, ssd, hdd, virtuel, memoire ou inconnu");
      let registre = null;
      if (o.registre !== undefined) {
        const m = /^([0-9]{1,5}),([0-9]{1,5})$/.exec(o.registre);
        if (!m) throw new Usage("--registre : <port RPC>,<port des métriques> attendu");
        registre = { rpc: Number(m[1]), metriques: Number(m[2]) };
      }
      return await campagneTm34({
        travail: path.resolve(o.travail), sortieRapport: path.resolve(o["sortie-rapport"]), dureeNominaleS: entier(o["duree-nominale-s"] ?? "3600", "duree-nominale-s", 30, 86400),
        cadence: entier(o.cadence ?? "50", "cadence", 1, 2000), connexions: entier(o.connexions ?? "16", "connexions", 1, 64), stockage: o.stockage ? path.resolve(o.stockage) : undefined, margeMio: entier(o["marge-mio"] ?? "256", "marge-mio", 1, 1048576),
        disque: { type: disque, fsync: disque === "memoire" ? false : true }, registre, scenarios: (o.scenarios ?? "").split(",").filter(Boolean), prometheus: o.prometheus, notes: o.note ?? [],
      });
    }
    if (argv[0] === "tm-35" && argv[1] === "relever") {
      const o = parseArgs({ args: argv.slice(2), strict: true, allowPositionals: false, options: { rpc: { type: "string", multiple: true }, "duree-s": { type: "string" }, sortie: { type: "string" } } }).values;
      if (!o.rpc?.length || !o.sortie) throw new Usage("--rpc et --sortie attendus");
      const rpc = Object.fromEntries(o.rpc.map((x) => {
        const k = x.indexOf("=");
        if (k < 1 || !/^http:\/\/127\.0\.0\.1:[0-9]{1,5}\/?$/.test(x.slice(k + 1))) throw new Usage(`--rpc : <cible>=http://127.0.0.1:<port> attendu (${x})`);
        return [x.slice(0, k), x.slice(k + 1)];
      }));
      return await releverTm35({ rpc, dureeS: entier(o["duree-s"], "duree-s", 1, 86400), sortie: path.resolve(o.sortie) });
    }
    if (argv[0] === "tm-35" && argv[1] === "rapport") {
      const o = parseArgs({ args: argv.slice(2), strict: true, allowPositionals: false, options: {
        echantillons: { type: "string" }, debut: { type: "string" }, fin: { type: "string" }, "txpool-max-pending": { type: "string" }, "source-m": { type: "string" }, charge: { type: "string" },
        "sortie-rapport": { type: "string" }, collecteur: { type: "string" }, note: { type: "string", multiple: true },
      } }).values;
      for (const k of ["echantillons", "debut", "fin", "txpool-max-pending", "source-m", "charge", "sortie-rapport"]) if (!o[k]) throw new Usage(`--${k} attendu`);
      const debut = Date.parse(o.debut);
      const fin = Date.parse(o.fin);
      if (!Number.isFinite(debut) || !Number.isFinite(fin) || fin <= debut) throw new Usage("--debut et --fin : instants ISO 8601, fin après début");
      const max = entier(o["txpool-max-pending"], "txpool-max-pending", 2, 100000000);
      if (max % 2) throw new Usage("--txpool-max-pending : nombre pair attendu (<M> en est la moitié)");
      return await rapportTm35({ echantillons: o.echantillons, debut, fin, txpoolMaxPending: max, sourceM: o["source-m"], charge: o.charge, sortieRapport: path.resolve(o["sortie-rapport"]), collecteur: o.collecteur ?? null, notes: o.note ?? [] });
    }
    throw new Usage(argv.length ? `commande inconnue : ${argv.slice(0, 2).join(" ")}` : "commande attendue");
  } catch (e) {
    const usage = e instanceof Usage || (typeof e?.code === "string" && e.code.startsWith("ERR_PARSE_ARGS"));
    if (!usage && !(e instanceof Echec)) throw e;
    process.stderr.write(`Erreur : ${e.message}\n${usage ? USAGE + "\n" : ""}`);
    return usage ? 2 : 1;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = await principal(process.argv.slice(2));
