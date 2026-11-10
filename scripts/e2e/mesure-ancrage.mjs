#!/usr/bin/env node
// Campagne de mesures de l'étape 5 (CT-9 §11 ; entrées TM-11 à TM-14,
// TM-17 à TM-19, TM-30, TM-41, TM-42 du catalogue) : le démon `noortrace` réel,
// avec le composant d'ancrage de CT-5 branché (`anchoring.ancrage`), contre le
// réseau de développement noorcore (quatre validateurs, lancé s'il ne tourne
// pas, arrêté à la fin s'il a été lancé ici), le serveur RFC 3161 interne de
// référence du paquet d'ancrage comme `principal` qualifié d'exemple (CT-5 EX-7.4 : admis
// pour TM-13 et TM-19) et un second serveur interne comme prestataire des
// points, deux calendriers OpenTimestamps factices à chaîne regtest, une
// charge d'événements à cadence fixe (EX-11.9) pendant une période complète
// d'une heure, en temps réel (aucune horloge manipulée pendant la mesure,
// EX-11.5 ; délais lus sur l'horloge de l'enregistreur).
//
//   node scripts/e2e/mesure-ancrage.mjs collecter --parcours <sortie de npm run e2e:registre>
//        --configuration defaut|porte2 --sortie <répertoire> [--evenements-par-s 1] [--garder-reseau]
//        [--verificateur-go <binaire>] [--journal-du-parcours]
//   node scripts/e2e/mesure-ancrage.mjs complements --sortie <répertoire> [--reseau-public]
//   node scripts/e2e/mesure-ancrage.mjs rapport --collecte <répertoire> [--collecte <répertoire>] [--complements <répertoire>]
//        [--p6 <rapport TM-16>] --sortie-rapport <fichier> [--sortie <répertoire>] [--note <texte>]…
//
// `collecter` : une configuration (`defaut` : c_K 60 s, c_T 300 s, points
// chez le serveur interne ; `porte2` : c_K 60 s, c_T 60 s, points chez le
// principal, cas `cadence-une-minute-principal` de CT-5 §12.3), le démon
// démarré avant une heure pleine, la charge jusqu'à la fin de la première
// période complète, puis la clôture, les trois ancres de la racine, la mise à
// niveau des preuves par les calendriers factices, l'export du dossier de
// chaque événement de la période et sa vérification par le vérificateur
// JavaScript de référence (boîte noire). Il écrit sous `--sortie` les données
// brutes (journal d'exploitation, file durable, acquisitions, série, dossiers
// témoins, rapports de vérification) et `collecte.json`.
// `complements` : les mesures qui n'exigent pas le réseau (TM-17 à l'horloge
// réglable du composant, TM-18 sur le serveur interne, TM-30 sur les
// calendriers factices et, avec `--reseau-public`, la taille des preuves en
// attente des calendriers publics). `rapport` : le rapport de mesure conforme
// à `plan-de-tests-v0#/$defs/rapport_mesure`, validé avant d'être écrit.
//
// Rien n'est écrit dans le dépôt, sauf le rapport au chemin `--sortie-rapport`
// que l'ingénieur de la campagne choisit (EX-11.11). Codes : 0 ; 1 échec ; 2
// préalable absent ou usage.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { spawn, spawnSync } from "node:child_process";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";
import * as N from "@noortrace/noyau";
import { lireFiles, constaterCadence } from "@noortrace/ancrage/planificateur";
import { DepotAncres, lireJeton } from "@noortrace/ancrage/rfc3161";
import { DepotOts, attestationsEnAttente, hauteursAttestees, lireOts } from "@noortrace/ancrage/ots";
import { RACINE, assurerReseau, arreterReseau, dormir } from "./reseau-dev.mjs";
import {
  lireParcours, inscrireJournal, monterDemonReseauReel, Demon, fichierAncres, pointDeControleBitcoin, portLibre,
} from "../../test/fixtures/enregistreur-ancrage/outils.mjs";

const VERIFICATEUR_JS = path.join(RACINE, "scripts", "verify", "dossier.mjs");
const SCHEMA = path.join(RACINE, "spec", "schemas", "plan-de-tests-v0.schema.json");
const CATALOGUE = path.join(RACINE, "spec", "vecteurs", "ct-9", "catalogue.json");
const HEURE_MS = 3600000;

class Echec extends Error {
  constructor(message, code = 1) {
    super(message);
    this.code = code;
  }
}

const lireJson = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const ecrireJson = (f, o) => fs.writeFileSync(f, `${JSON.stringify(o, null, 2)}\n`);
const log = (m) => process.stderr.write(`mesure-ancrage ${new Date().toISOString()} : ${m}\n`);

/** État de l'arbre de travail à la collecte : propre, ou nombre de chemins modifiés ou nouveaux (`git status --porcelain`). */
function etatArbre() {
  const r = spawnSync("git", ["status", "--porcelain"], { cwd: RACINE, encoding: "utf8" });
  if (r.status !== 0) return null;
  const n = r.stdout.split("\n").filter((l) => l.trim() !== "").length;
  return { propre: n === 0, chemins_modifies: n };
}

/** Configurations mesurées : paramètres du document `ancrage-v0` et de l'enregistreur. */
export const CONFIGURATIONS = Object.freeze({
  defaut: { c_K: 60, c_T: 300, provider_role: "interne", description: "configuration par défaut de CT-5 §4 : c_K = 60 s, c_T = 300 s, points chez le serveur interne (EX-7.4), clôture chez le principal qualifié d'exemple" },
  porte2: { c_K: 60, c_T: 60, provider_role: "principal", description: "configuration de la porte 2 : c_K = 60 s, c_T = 60 s, points chez le principal (cas cadence-une-minute-principal de CT-5 §12.3)" },
});

// ----------------------------------------------------------------- outils

/** Percentile par la méthode du plus proche rang (CT-9 EX-11.4) sur des nombres. */
export function plusProcheRang(valeurs, p) {
  if (!valeurs.length) return null;
  const tri = [...valeurs].sort((a, b) => a - b);
  const rang = Math.max(1, Math.ceil((p / 100) * tri.length));
  return tri[rang - 1];
}

/** Agrégats d'une série : n, p50, p95, p99, min, max, mean (arrondis à trois décimales). */
export function agreger(valeurs) {
  const r3 = (x) => (x === null ? null : Math.round(x * 1000) / 1000);
  if (!valeurs.length) return { n: null, p50: null, p95: null, p99: null, min: null, max: null, mean: null };
  return {
    n: valeurs.length,
    p50: r3(plusProcheRang(valeurs, 50)),
    p95: r3(plusProcheRang(valeurs, 95)),
    p99: r3(plusProcheRang(valeurs, 99)),
    min: r3(Math.min(...valeurs)),
    max: r3(Math.max(...valeurs)),
    mean: r3(valeurs.reduce((a, x) => a + x, 0) / valeurs.length),
  };
}

const getTexte = (port, chemin) => new Promise((res, rej) => {
  http.get({ host: "127.0.0.1", port, path: chemin }, (r) => {
    let t = "";
    r.on("data", (d) => (t += d));
    r.on("end", () => res({ statut: r.statusCode, corps: t }));
  }).on("error", rej);
});

/** Lance le vérificateur JavaScript de référence (boîte noire) et rend son rapport JSON. */
function verifierJsAsync(repertoire, { ancres, entetes }) {
  return new Promise((resolve) => {
    const args = [VERIFICATEUR_JS, repertoire, "--json", "--ancres", ancres, ...(entetes && fs.existsSync(entetes) ? ["--entetes-bitcoin", entetes] : [])];
    const p = spawn(process.execPath, args, { cwd: RACINE, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", (code) => {
      let rapport = null;
      try {
        rapport = out ? JSON.parse(out) : null;
      } catch {
        rapport = null;
      }
      resolve({ code, rapport, stderr: err });
    });
  });
}

/** Machine de la mesure (CT-9 §11.3, `$defs/systeme`) : cette machine n'est pas le système de référence. */
export function systeme() {
  const lire = (f) => {
    try {
      return fs.readFileSync(f, "utf8");
    } catch {
      return null;
    }
  };
  const version = (cmd, args, re) => {
    const r = spawnSync(cmd, args, { encoding: "utf8", env: { ...process.env, GOTOOLCHAIN: "local" } });
    if (r.status !== 0) return null;
    return (r.stdout + r.stderr).match(re)?.[1] ?? null;
  };
  const osRelease = lire("/etc/os-release");
  const aslr = lire("/proc/sys/kernel/randomize_va_space")?.trim() ?? null;
  const gouverneur = lire("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")?.trim() ?? null;
  const cpuinfo = lire("/proc/cpuinfo") ?? "";
  const virt = spawnSync("systemd-detect-virt", [], { encoding: "utf8" });
  return {
    reference: false,
    cpu: os.cpus()[0]?.model?.trim() || "inconnu",
    cores: os.cpus().length,
    memory_bytes: os.totalmem(),
    // Disque virtuel (ext4 sur /dev/vda d'une machine virtuelle) ; `fdatasync` est appelé par l'écrivain (CT-2 §12.3) et
    // n'a pas été désactivé, mais son honneur par le support virtuel n'est pas établi : `fsync` vrai au sens « actif ».
    disk: { type: "virtuel", fsync: true },
    os: osRelease?.match(/^PRETTY_NAME="?([^"\n]+)"?/m)?.[1] ?? `${os.type()} ${os.release()}`,
    kernel: os.release(),
    node: process.version,
    go: version("go", ["env", "GOVERSION"], /(go[0-9.]+)/),
    python: version("python3", ["--version"], /Python ([0-9.]+)/),
    cpu_scaling: gouverneur ? (gouverneur === "performance" ? "inactif" : "actif") : "inconnu",
    aslr: aslr === null ? "inconnu" : aslr === "0" ? "inactif" : "actif",
    load_avg_1m: Math.round(os.loadavg()[0] * 100) / 100,
    virtualized: virt.status === 0 ? virt.stdout.trim() !== "none" : /\bhypervisor\b/.test(cpuinfo) ? true : null,
  };
}

/** Journal en mémoire des serveurs RFC 3161 internes (lignes `tsa_*`, dont `tsa_clock_offset_ms`). */
function journalTsa() {
  const lignes = [];
  return { lignes, consigner(niveau, evenement, data = {}) { lignes.push({ at: new Date().toISOString(), level: niveau, event: evenement, data }); } };
}

/** Déclaration de qualification de test du principal (forme `qualification` d'ancres-confiance-v0, CT-6 EX-9.17), sans valeur. */
export const QUALIFICATION_TEST = Object.freeze({ framework: "eidas", valid_from: "2026-01-01T00:00:00.000Z", valid_to: null, source: "déclaration de test de la campagne de mesures de l'étape 5 pour le serveur interne de référence, sans valeur : aucun prestataire qualifié réel" });

/** Fichier d'ancres du réviseur de la campagne, écrit sous `sortie` ; rend son chemin. */
function ecrireAncresReviseur({ sortie, m, parcours }) {
  const ancres = path.join(sortie, "ancres-reviseur.json");
  fichierAncres({
    chemin: ancres, montage: m, bitcoin: pointDeControleBitcoin(m, 1000), qualifiedPrincipal: QUALIFICATION_TEST,
    preparedAt: `${new Date().toISOString().slice(0, 19)}.000Z`,
    recorders: [{ org_id: parcours.orgId, journal_id: parcours.journalId, key_id: parcours.recorder.key_id, public_key: N.octetsVersHex(parcours.clePublique), chain_key: parcours.cleChaine.adresse(), source: "journal inscrit au registre pour la campagne (organisation du parcours de référence)" }],
  });
  return ancres;
}

/** Copie les données brutes du démon (journal d'exploitation, file, acquisitions, série, manifeste, journal des serveurs internes). */
function copierDonnees({ sortie, m, P, tsa, evenements, depot }) {
  const donnees = path.join(sortie, "donnees");
  fs.mkdirSync(donnees, { recursive: true });
  fs.copyFileSync(m.config.supervision.ops_log.path, path.join(donnees, "exploitation.ndjson"));
  const relue = lireFiles(m.documentAncrage.queue.path);
  for (const f of relue.fichiers) fs.copyFileSync(path.join(m.documentAncrage.queue.path, f), path.join(donnees, f));
  for (const f of ["acquisitions.ndjson", "entetes-bitcoin.json"]) if (fs.existsSync(path.join(depot.repertoire(P), f))) fs.copyFileSync(path.join(depot.repertoire(P), f), path.join(donnees, f));
  for (const [de, a] of [[path.join(m.repertoire, "points", `periode-${P}.ndjson`), `points-periode-${P}.ndjson`], [path.join(m.repertoire, "manifestes", `periode-${P}.json`), `manifeste-periode-${P}.json`]]) if (fs.existsSync(de)) fs.copyFileSync(de, path.join(donnees, a));
  fs.writeFileSync(path.join(donnees, "tsa-journal.ndjson"), tsa.lignes.map((l) => JSON.stringify(l)).join("\n") + "\n");
  ecrireJson(path.join(donnees, "evenements.json"), evenements);
  return donnees;
}

// ----------------------------------------------------------------- collecte

export async function collecter(o) {
  const conf = CONFIGURATIONS[o.configuration];
  if (!conf) throw new Echec("--configuration defaut|porte2 attendu", 2);
  if (!o.parcours || !fs.existsSync(path.join(o.parcours, "cles", "cle-chaine-rec-demo-01.cle"))) throw new Echec("--parcours : sortie d'un `npm run e2e:registre -- --garder-reseau --sortie <répertoire>` attendue", 2);
  const sortie = path.resolve(o.sortie);
  fs.mkdirSync(sortie, { recursive: true });
  const travail = path.join(sortie, "travail");
  fs.mkdirSync(travail, { recursive: true });
  const evParS = Number(o["evenements-par-s"] ?? 1);
  if (!(evParS > 0 && evParS <= 10)) throw new Echec("--evenements-par-s : nombre de 0,1 à 10", 2);
  const reseau = assurerReseau({ journal: process.stderr });
  let demon = null;
  let m = null;
  let reussi = false;
  const debut = new Date();
  try {
    // Journal mesuré : par défaut un journal neuf inscrit sous l'organisation du parcours (clé de chaîne propre : deux
    // campagnes peuvent tourner en parallèle sans se disputer les nonces ; première période sans continuité à tenir) ;
    // `--journal-du-parcours` reprend le journal que le parcours a inscrit.
    const base = lireParcours(o.parcours);
    const parcours = o["journal-du-parcours"] ? base : inscrireJournal({ parcours: base, travail, etiquette: `mesure-${o.configuration}-${Date.now()}` });
    if (parcours.condition) throw new Echec(parcours.condition, 2);
    if (parcours.neuf) log(`journal neuf inscrit au registre : ${parcours.journalId} (clé de chaîne ${parcours.cleChaine.adresse()})`);
    const tsa = journalTsa();
    m = await monterDemonReseauReel({
      travail, parcours, baseMs: Date.now(), cK: conf.c_K, journalTsa: tsa,
      surchargesAncrage: {
        rfc3161: { manifest: { fallback_after_s: 300 }, checkpoints: { interval_s: conf.c_T, provider_role: conf.provider_role, fallback_after_s: 120 } },
        registry: { checkpoints: "nouveaux_evenements", squat_wait_s: 5, inclusion_alert_s: 60 },
        opentimestamps: { upgrade: { first_after_s: 60, interval_s: 60, give_up_after_s: 3600 } },
        queue: { max_pending: 1000 },
      },
      surchargesConfig: (c) => {
        c.supervision.metrics = true;
      },
    });
    if (m.condition) throw new Echec(m.condition, 2);
    ecrireJson(path.join(sortie, "configuration-ancrage.json"), m.documentAncrage);
    fs.copyFileSync(m.cheminConfig, path.join(sortie, "configuration-enregistreur.json"));
    demon = new Demon(m);
    const d0 = await demon.demarrer();
    await demon.attendre((l) => l.some((x) => x.event === "anchoring_attached"), 60000, "anchoring_attached");
    log(`démon démarré (pid ${d0.pid}, époque ${d0.epoque}) ; configuration ${o.configuration} : ${conf.description}`);
    const portSante = Number(m.config.supervision.health_listen.split(":").pop());
    // Le fichier d'ancres du réviseur est éprouvé tout de suite sur un dossier des vecteurs (boîte noire) : un fichier
    // inutilisable serait découvert avant la période mesurée, pas après.
    {
      const essai = await verifierJsAsync(path.join(RACINE, "spec", "vecteurs", "ct-6", "dossiers", "valide-point-de-controle-complet"), { ancres: ecrireAncresReviseur({ sortie, m, parcours }), entetes: null });
      if (essai.rapport?.error?.message && /ancres/.test(essai.rapport.error.message)) throw new Echec(`fichier d'ancres du réviseur refusé par le vérificateur : ${essai.rapport.error.message}`, 2);
      log(`fichier d'ancres du réviseur accepté par le vérificateur (code ${essai.code} sur un dossier des vecteurs, attendu : refus des ancres de ce dossier, pas du fichier)`);
    }
    // Période complète mesurée : la première heure pleine qui suit le démarrage (la période courante, entamée, ne compte pas).
    const maintenant = Date.now();
    const essaiS = o["essai-charge-s"] ? Number(o["essai-charge-s"]) : null;
    const P = essaiS ? Math.floor(maintenant / HEURE_MS) * 3600 : (Math.floor(maintenant / HEURE_MS) + 1) * 3600;
    const finP = essaiS ? maintenant + essaiS * 1000 : (P + 3600) * 1000;
    log(`période mesurée : ${P} (${new Date(P * 1000).toISOString()} → ${new Date(finP).toISOString()}) ; charge ${evParS} événement(s)/s à cadence fixe dès maintenant`);
    // Charge à cadence fixe (EX-11.9) : l'instant prévu de l'envoi est noté, les réponses lentes ne retardent pas les suivantes.
    const evenements = [];
    const pasMs = Math.round(1000 / evParS);
    const t0 = Date.now() + 1000;
    const enVol = [];
    let k = 0;
    for (;;) {
      const prevu = t0 + k * pasMs;
      if (prevu >= finP + 500) break;
      const attente = prevu - Date.now();
      if (attente > 0) await dormir(attente);
      const n = k + 1;
      const envoi = Date.now();
      const p = demon.evenement(n).then((e) => evenements.push({ n, seq: e.seq, ts: e.ts, hash: e.hash, prevu_ms: prevu, envoi_ms: envoi, retour_ms: Date.now() }), (e) => evenements.push({ n, erreur: String(e?.message ?? e), prevu_ms: prevu, envoi_ms: envoi }));
      enVol.push(p);
      if (enVol.length > 64) {
        await enVol.shift();
      }
      k += 1;
      if (k % 600 === 0) log(`${k} événements émis (${evenements.filter((e) => e.seq).length} scellés)`);
    }
    await Promise.all(enVol);
    evenements.sort((a, b) => a.n - b.n);
    const erreurs = evenements.filter((e) => !e.seq);
    log(`charge terminée : ${evenements.length} émis, ${erreurs.length} en erreur`);
    if (essaiS) {
      // Essai court de la collecte (option non documentée) : données brutes écrites, pas de clôture attendue.
      await dormir(5000);
      const donneesEssai = path.join(sortie, "donnees");
      fs.mkdirSync(donneesEssai, { recursive: true });
      fs.copyFileSync(m.config.supervision.ops_log.path, path.join(donneesEssai, "exploitation.ndjson"));
      ecrireJson(path.join(donneesEssai, "evenements.json"), evenements);
      ecrireJson(path.join(donneesEssai, "file.json"), lireFiles(m.documentAncrage.queue.path).demandes);
      log(`essai court terminé : ${evenements.filter((e) => e.seq).length} événements scellés`);
      return { essai: true };
    }
    // Clôture de la période mesurée et ses ancres (le démon continue dans la période suivante) : états lus dans la file durable
    // (les lignes `period_timestamped`, `ots_submitted`, `ots_complete` portent le `request_id`, la file porte la période).
    await demon.attendre((l) => l.some((x) => x.event === "period_closed" && x.data.period_start === P), 120000, `period_closed ${P}`);
    const demandesP = () => lireFiles(m.documentAncrage.queue.path).demandes.filter((d) => d.subject.period_start === P);
    const attendreFile = async (predicat, delaiMs, description) => {
      const limite = Date.now() + delaiMs;
      for (;;) {
        const d = demandesP();
        if (predicat(d)) return d;
        if (Date.now() > limite) throw new Echec(`${description} non atteint en ${delaiMs} ms ; états : ${JSON.stringify(d.map((x) => [x.kind, x.state]))}`);
        await dormir(2000);
      }
    };
    await attendreFile((d) => d.some((x) => x.kind === "jeton_periode" && x.state === "obtenue"), 600000, "jeton_periode obtenue");
    await attendreFile((d) => d.filter((x) => (x.kind === "ots_periode" || x.kind === "ots_point") && (x.state === "en_attente" || x.state === "complete")).length >= 2, 300000, "ots_periode et ots_point soumis");
    // Ancres des points de la période toutes à un état final (obtenue, remplacee).
    await attendreFile((d) => d.filter((x) => x.kind === "ancre_registre_point" && !["obtenue", "remplacee", "refusee", "sans_objet"].includes(x.state)).length === 0, 300000, "ancres des points à un état final");
    await demon.attendre((l) => l.some((x) => (x.event === "period_submitted" || x.event === "period_close_delegated" || x.event === "registry_pending") && x.data.period_start === P), 300000, "clôture déléguée ou relayée");
    // Mise à niveau OpenTimestamps : les calendriers factices rendent le chemin complet (chaîne regtest, EX-6.9).
    m.calendriers.completer(1010);
    await attendreFile((d) => d.filter((x) => (x.kind === "ots_periode" || x.kind === "ots_point") && x.state === "complete").length >= 2, 300000, "ots_periode et ots_point complete");
    await demon.attendre((l) => l.some((x) => x.event === "bitcoin_headers_written" && x.data.period_start === P), 120000, "entetes-bitcoin.json");
    const metriques = await getTexte(portSante, "/metrics");
    fs.writeFileSync(path.join(sortie, "metriques.txt"), metriques.corps);
    const depot = DepotAncres.ouvrir({ racine: m.config.storage.root, orgId: m.config.recorder.org_id, journalId: m.config.recorder.journal_id });
    copierDonnees({ sortie, m, P, tsa, evenements, depot });
    log("données brutes de la période copiées (avant les exports)");
    // Fichier d'ancres du réviseur : autorités internes de test (le principal déclaré qualifié par une déclaration de test, forme
    // `qualification` d'ancres-confiance-v0, CT-6 EX-9.17 : condition de TM-14), chaîne regtest, registre du réseau.
    const ancres = ecrireAncresReviseur({ sortie, m, parcours });
    // Export du dossier de chaque événement de la période et vérification par le vérificateur JavaScript (trois à la fois).
    const dansP = evenements.filter((e) => e.seq && N.decoderHorodatage(e.ts) >= P * 1000 && N.decoderHorodatage(e.ts) < finP);
    log(`${dansP.length} événements dans la période ; export et vérification des dossiers…`);
    const repDossiers = path.join(sortie, "dossiers");
    fs.mkdirSync(repDossiers, { recursive: true });
    const verifications = [];
    const file = [];
    let entetes = null;
    const traiter = async (e, index) => {
      const dest = path.join(repDossiers, `seq-${e.seq}`);
      const r = await demon.exporter(e.seq, dest);
      if (entetes === null && fs.existsSync(path.join(dest, "entetes-bitcoin.json"))) entetes = path.join(sortie, "entetes-bitcoin.json");
      if (entetes && !fs.existsSync(entetes) && fs.existsSync(path.join(dest, "entetes-bitcoin.json"))) fs.copyFileSync(path.join(dest, "entetes-bitcoin.json"), entetes);
      const v = await verifierJsAsync(dest, { ancres, entetes: entetes ?? path.join(dest, "entetes-bitcoin.json") });
      const rap = v.rapport && Array.isArray(v.rapport.controls) && Array.isArray(v.rapport.checks) ? v.rapport : null;
      const controles = rap ? Object.fromEntries(rap.controls.map((c) => [c.number, c.status])) : null;
      const checks = rap ? Object.fromEntries(rap.checks.map((c) => [c.id, c.status])) : null;
      const partie = fs.existsSync(path.join(dest, "points-de-controle.json")) ? lireJson(path.join(dest, "points-de-controle.json")) : null;
      verifications.push({
        seq: e.seq, ts: e.ts, code: v.code, verdict: rap?.verdict ?? null, controles, checks,
        rewrite_window_ms: rap?.facts?.checkpoint?.rewrite_window_ms ?? null, rewrite_window_end: rap?.facts?.checkpoint?.rewrite_window_end ?? null,
        checkpoint_ts: partie?.checkpoint?.checkpoint_ts ?? null, tree_size: partie?.checkpoint?.tree_size ?? null, leaf_index: fs.existsSync(path.join(dest, "chemin.json")) ? lireJson(path.join(dest, "chemin.json")).leaf_index : null,
        parts_present: r.parts.filter((p) => p.present).map((p) => p.name), statement_fr: rap?.statement?.fr ?? null,
        erreur: rap ? null : (v.rapport?.error?.message ?? v.stderr.slice(0, 300)),
      });
      if (!rap || rap.verdict !== "valide") fs.writeFileSync(path.join(sortie, `verification-seq-${e.seq}.stderr.txt`), v.stderr);
      // Dossiers témoins gardés : le premier et le dernier de la période ; les autres sont supprimés après vérification (place disque).
      if (index !== 0 && index !== dansP.length - 1) fs.rmSync(dest, { recursive: true, force: true });
      else fs.writeFileSync(path.join(dest, "verification-js.json"), JSON.stringify(rap, null, 2));
    };
    const lots = 3;
    let erreurExports = null;
    for (let i = 0; i < dansP.length && !erreurExports; i += lots) {
      await Promise.all(dansP.slice(i, i + lots).map((e, j) => traiter(e, i + j).catch((err) => { erreurExports = `seq ${e.seq} : ${String(err?.message ?? err)}`; })));
      if ((i / lots) % 100 === 0 && i) log(`${i} dossiers vérifiés`);
    }
    if (erreurExports) log(`exports interrompus : ${erreurExports} (les données brutes de la période sont copiées)`);
    verifications.sort((a, b) => a.seq - b.seq);
    // Vérificateur Go sur le dossier témoin du premier événement, pour la parité de l'énoncé.
    let go = null;
    const bin = o["verificateur-go"] ?? process.env.NOORTRACE_VERIFIER_BIN ?? null;
    if (bin && fs.existsSync(bin) && dansP.length) {
      const dest = path.join(repDossiers, `seq-${dansP[0].seq}`);
      const r = spawnSync(bin, [dest, "--json", "--ancres", ancres, ...(fs.existsSync(path.join(dest, "entetes-bitcoin.json")) ? ["--entetes-bitcoin", path.join(dest, "entetes-bitcoin.json")] : [])], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
      const rap = r.stdout ? JSON.parse(r.stdout) : null;
      go = { code: r.status, verdict: rap?.verdict ?? null, statement_fr: rap?.statement?.fr ?? null, identique: rap?.statement?.fr === verifications[0]?.statement_fr };
    }
    // Données brutes de la période, second passage (journal d'exploitation complet).
    const donnees = copierDonnees({ sortie, m, P, tsa, evenements, depot });
    ecrireJson(path.join(donnees, "verifications.json"), verifications);
    // Preuves OpenTimestamps de la période (tailles pour TM-30 : preuves mises à niveau par les calendriers factices).
    const depotOts = DepotOts.ouvrir({ racine: m.config.storage.root, orgId: m.config.recorder.org_id, journalId: m.config.recorder.journal_id });
    const preuves = fs.readdirSync(path.join(depot.repertoire(P), "ots")).filter((n) => n.endsWith(".ots")).map((n) => {
      const octets = new Uint8Array(fs.readFileSync(path.join(depot.repertoire(P), "ots", n)));
      let enAttente = null;
      let hauteurs = null;
      try {
        const lu = lireOts(octets);
        enAttente = attestationsEnAttente(lu.arbre, lu.empreinte).length;
        hauteurs = hauteursAttestees(lu.arbre);
      } catch {
        enAttente = null;
      }
      return { fichier: n, octets: octets.length, attestations_en_attente: enAttente, hauteurs_attestees: hauteurs === null ? null : Array.isArray(hauteurs) ? hauteurs.length : hauteurs };
    });
    void depotOts;
    // Jetons de la période (TM-19 : accuracy de chaque jeton émis par les serveurs internes).
    const acquisitions = depot.dernieresAcquisitions(P).enregistrements.filter((e) => e.outcome === "obtenue");
    const jetons = acquisitions.map((e) => {
      const j = lireJeton(new Uint8Array(fs.readFileSync(path.join(depot.repertoire(P), e.files.token))));
      const acc = j.tstInfo.accuracy;
      const accuracyS = acc === null ? null : Number(acc.seconds ?? 0n) + (Number(acc.millis ?? 0n) + Number(acc.micros ?? 0n) / 1000) / 1000;
      return { attempt_id: e.attempt_id, provider: e.provider_id, object: e.object, serial: j.tstInfo.serialNumberHex, gen_time: e.gen_time, upper_bound: e.upper_bound, accuracy_s: accuracyS, sent_at: e.sent_at, received_at: e.received_at };
    });
    const fin = await demon.arreter();
    log(`démon arrêté (code ${fin.code})`);
    demon = null;
    const collecte = {
      version: 0, kind: "collecte-mesure-ancrage", configuration: o.configuration, parametres: conf, period_start: P,
      debut: debut.toISOString(), fin: new Date().toISOString(), evenements_par_s: evParS, commit: spawnSync("git", ["rev-parse", "HEAD"], { cwd: RACINE, encoding: "utf8" }).stdout.trim(),
      arbre: etatArbre(),
      reseau: { deja_debout: reseau.deja_debout, demarre_ici: reseau.demarre }, parcours: { repertoire: o.parcours, org_id: parcours.orgId, journal_id: parcours.journalId, chain_key: parcours.cleChaine.adresse(), journal_neuf: parcours.neuf === true },
      evenements: { emis: evenements.length, en_erreur: erreurs.length, dans_la_periode: dansP.length, dossiers_verifies: verifications.filter((v) => v.verdict !== null).length, exports_erreur: erreurExports },
      go, preuves, jetons, systeme: systeme(),
    };
    ecrireJson(path.join(sortie, "collecte.json"), collecte);
    log(`collecte écrite : ${path.join(sortie, "collecte.json")}`);
    reussi = erreurExports === null;
    return collecte;
  } finally {
    if (demon?.p) await demon.arreter().catch(() => {});
    await m?.fermer?.().catch(() => {});
    if (reseau?.demarre && !o["garder-reseau"]) {
      log("arrêt du réseau démarré par la mesure…");
      arreterReseau({ journal: process.stderr });
    }
    // Le stockage du démon (segments, pièces, dépôts) n'est supprimé qu'après une collecte complète : sinon il reste sous
    // travail/enregistreur pour être relu.
    if (reussi) fs.rmSync(path.join(travail, "enregistreur"), { recursive: true, force: true });
    else log(`stockage du démon conservé : ${path.join(travail, "enregistreur")}`);
  }
}

// ----------------------------------------------------------------- point d'entrée

export async function principal(argv) {
  const action = argv[0];
  const { values: o } = parseArgs({
    args: argv.slice(1), strict: true,
    options: {
      parcours: { type: "string" }, configuration: { type: "string" }, sortie: { type: "string" }, "evenements-par-s": { type: "string" }, "garder-reseau": { type: "boolean" },
      "verificateur-go": { type: "string" }, "reseau-public": { type: "boolean" }, "essai-charge-s": { type: "string" }, "journal-du-parcours": { type: "boolean" }, collecte: { type: "string", multiple: true }, complements: { type: "string" }, p6: { type: "string" }, "sortie-rapport": { type: "string" },
      note: { type: "string", multiple: true },
    },
  });
  if (action === "collecter") {
    if (!o.sortie) throw new Echec("--sortie attendu", 2);
    await collecter(o);
    return 0;
  }
  if (action === "complements") {
    const { complements } = await import("./mesure-ancrage-complements.mjs");
    if (!o.sortie) throw new Echec("--sortie attendu", 2);
    await complements({ sortie: o.sortie, reseauPublic: o["reseau-public"] === true, log });
    return 0;
  }
  if (action === "rapport") {
    const { rapport } = await import("./mesure-ancrage-rapport.mjs");
    if (!o["sortie-rapport"] || !o.collecte?.length) throw new Echec("--collecte <répertoire> (au moins un) et --sortie-rapport <fichier> attendus", 2);
    await rapport({ collectes: o.collecte, complements: o.complements ?? null, p6: o.p6 ?? null, sortieRapport: o["sortie-rapport"], sortie: o.sortie ?? null, notesOperateur: o.note ?? [], schema: SCHEMA, catalogue: CATALOGUE, log });
    return 0;
  }
  throw new Echec("usage : node scripts/e2e/mesure-ancrage.mjs collecter|complements|rapport …", 2);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  principal(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (err) => {
      process.stderr.write(`mesure-ancrage : ${err?.stack ?? err?.message ?? err}\n`);
      process.exitCode = err instanceof Echec ? err.code : 1;
    },
  );
}

export { Echec, lireJson, ecrireJson, log, portLibre };
