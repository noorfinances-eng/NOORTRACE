// TM-16 de CT-9 : mesure de la propriété P-6 de CT-5 (§3.6, §5.5 ; CT-2
// EX-12.16, EX-12.17) sur le support WORM réel des tests du lot WORM : un
// service S3 à Object Lock (LocalStack, image épinglée par condensé, lancée
// dans Docker, derrière un mandataire TLS), bucket verrouillé par
// l'exploitant (rétention par défaut COMPLIANCE, EX-12.30).
//
// Une période est close par le cœur du démon, qui copie ses fichiers vers le
// support (EX-12.16). Puis, pour chaque fichier de `points/`, de
// `ancres/periode-*/` et de `manifestes/` (manifeste et sa signature), la
// mesure lit par l'API du support, indépendamment du registre des copies de
// l'écrivain : la liste des versions de la clé (`ListObjectVersions`), le
// contenu de chaque version (`GET` avec `versionId`, SHA-256 recalculé), son
// mode de verrou et sa date de rétention (`HEAD` avec `versionId` :
// `x-amz-object-lock-mode`, `x-amz-object-lock-retain-until-date`). Un
// fichier est conforme s'il a une version au même SHA-256, en mode
// `COMPLIANCE` (sans contournement par aucun rôle du client), dont l'échéance
// n'est pas antérieure à sa date de création sur le support plus
// `365 × storage.retention.events_years` jours, moins la tolérance d'une heure
// d'EX-12.33. La ligne `p6_copie_worm` du rapport (CT-9 §11.3, plan-de-tests-
// v0#/$defs/rapport_mesure) compte les fichiers non conformes.
//
// Le rapport est validé contre le schéma ; s'il est demandé
// (NOORTRACE_RAPPORT_TM16=<fichier>), il est écrit dans ce fichier : c'est
// ainsi que l'ingénieur de la campagne produit le rapport publié sous
// spec/vecteurs/ct-9/mesures/ (EX-11.11). Hors du système de référence de
// CT-9 §11.1, la ligne ne compte pour aucune cible (`counts_for_targets`
// faux, `met` null).
// Sans Docker, le test est mis en attente et son titre nomme la condition.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import {
  Coeur, validerConfiguration, resoudreSecrets, supportWormDepuisConfiguration, controleWorm, OperationsS3, identifiantsS3, lireEcheance, lireRegistres,
} from "@noortrace/enregistreur";
import { configurationDev, repertoireTemporaire, RACINE, SPEC } from "./fixtures/enregistreur-coeur/outils.mjs";
import {
  IMAGES, dockerDisponible, demarrerS3, arreterTout, certificats, mandataireTls, creerBucketVerrouille, identifiantsRole, fichierSecret,
} from "./fixtures/enregistreur-worm/outils.mjs";

const RAPIDE = [20, 20, 20];
const PREFIXE = "journal-p6/";
const RETAIN_DAYS = 4018;
/** Horloge réelle décalée (murale et monotone ensemble). */
const horloge = (decalage) => ({ murale: () => Date.now() + decalage, monotone: () => performance.now() + 1e7 + decalage });
/** Décalage qui place l'horloge dans l'heure suivante, de moins d'une heure (tolérance d'EX-12.33). */
const versHeureSuivante = () => 3600000 - (Date.now() % 3600000) + 2000;

/** Fichiers mesurés (relatifs au répertoire du journal) : points, ancres/periode-<P> et manifestes. */
function fichiersMesures(repertoire) {
  const sous = (rel) => {
    const abs = path.join(repertoire, rel);
    if (!fs.existsSync(abs)) return [];
    return fs.readdirSync(abs, { recursive: true }).map((f) => path.posix.join(rel, String(f).split(path.sep).join("/"))).filter((f) => fs.statSync(path.join(repertoire, f)).isFile());
  };
  const ancres = fs.existsSync(path.join(repertoire, "ancres")) ? fs.readdirSync(path.join(repertoire, "ancres")).filter((d) => /^periode-[0-9]{10}$/.test(d)).flatMap((d) => sous(`ancres/${d}`)) : [];
  return { points: sous("points"), ancres, manifestes: sous("manifestes").filter((f) => /^manifestes\/periode-[0-9]{10}\.(json|sig)$/.test(f)) };
}

/**
 * Mesure P-6 par l'API du support. `lireLocal(rel)` rend les octets de
 * l'original. Rend une ligne par fichier : { fichier, conforme, raison, versions }.
 */
async function mesurerP6({ ops, fichiers, lireLocal, eventsYears }) {
  const lignes = [];
  for (const rel of fichiers) {
    const cle = `${PREFIXE}${rel}`;
    const attendu = N.sha256Hex(new Uint8Array(lireLocal(rel)));
    const liste = await ops.listerVersions(cle);
    const versions = liste.versions.filter((v) => v.key === cle && !v.delete_marker);
    let raison = versions.length ? null : "aucune_version";
    let conforme = false;
    const lues = [];
    for (const v of versions) {
      const e = await ops.empreinte(cle, v.version_id);
      const h = await ops.etat(cle, v.version_id);
      const mode = h.entetes["x-amz-object-lock-mode"] ?? null;
      const echeance = lireEcheance(h.entetes["x-amz-object-lock-retain-until-date"] ?? null);
      const creation = lireEcheance(e.last_modified);
      const minimum = creation === null ? null : creation + eventsYears * 365 * 86400000 - 3600000;
      const r = e.sha256 !== attendu ? "sha256_different" : mode !== "COMPLIANCE" ? "mode_non_conforme" : echeance === null || minimum === null ? "echeance_illisible" : echeance < minimum ? "retention_plus_courte" : null;
      lues.push({ version_id: v.version_id, sha256: e.sha256, mode, retain_until: echeance === null ? null : new Date(echeance).toISOString(), raison: r });
      if (r === null) conforme = true;
      else raison = raison ?? r;
    }
    lignes.push({ fichier: rel, conforme, raison: conforme ? null : raison, versions: lues });
  }
  return lignes;
}

/** Machine de la mesure (CT-9 §11.3, `$defs/systeme`) ; hors système de référence. */
function systeme() {
  const lire = (cmd, args) => {
    const r = spawnSync(cmd, args, { encoding: "utf8" });
    return r.status === 0 ? `${r.stdout}${r.stderr}`.trim() : null;
  };
  const os_ = (fs.readFileSync("/etc/os-release", "utf8").match(/^PRETTY_NAME="?([^"\n]+)"?$/m) ?? [])[1] ?? os.type();
  const aslr = fs.existsSync("/proc/sys/kernel/randomize_va_space") ? (fs.readFileSync("/proc/sys/kernel/randomize_va_space", "utf8").trim() === "0" ? "inactif" : "actif") : "inconnu";
  const virt = lire("systemd-detect-virt", []);
  const goV = (lire("go", ["version"]) ?? "").match(/go[0-9]+\.[0-9]+(\.[0-9]+)?/)?.[0] ?? null;
  const pyV = (lire("python3", ["--version"]) ?? "").match(/[0-9]+\.[0-9]+\.[0-9]+/)?.[0] ?? null;
  return {
    reference: false,
    cpu: os.cpus()[0]?.model ?? "inconnu",
    cores: os.cpus().length,
    memory_bytes: os.totalmem(),
    disk: { type: "virtuel", fsync: null },
    os: os_,
    kernel: os.release(),
    node: process.version,
    go: goV,
    python: pyV,
    cpu_scaling: "inconnu",
    aslr,
    load_avg_1m: Math.round(os.loadavg()[0] * 100) / 100,
    virtualized: virt === null ? true : virt !== "none",
  };
}

describe("TM-16 — P-6 de CT-5 mesurée sur le support WORM réel (S3 à Object Lock en conteneur) : copie conforme des points, des ancres et des manifestes", function () {
  this.timeout(600000);
  const docker = dockerDisponible([IMAGES.s3]);
  let dir;
  let tls;
  let prox;

  before(async function () {
    if (!docker.ok) return;
    dir = repertoireTemporaire("noortrace-worm-p6-");
    const s3 = await demarrerS3(`noortrace-test-worm-p6-${process.pid}`);
    tls = certificats(path.join(dir, "tls"));
    prox = await mandataireTls(tls, { port: s3.port });
  });

  after(async function () {
    await prox?.fermer();
    arreterTout();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("TM-16 : une période close copiée sur le support ; chaque fichier de points/, d'ancres/periode-*/ et de manifestes/ lu par l'API du support (version au même SHA-256, mode COMPLIANCE, rétention au moins égale à celle des événements) ; rapport conforme à plan-de-tests-v0#/$defs/rapport_mesure, ligne p6_copie_worm à 0 fichier non conforme", async function () {
    if (!docker.ok) {
      this.test.title += ` — en attente : ${docker.condition}`;
      this.skip();
    }
    const debut = new Date();
    const bucket = `noortrace-p6-${process.pid}`;
    await creerBucketVerrouille(prox.origine, bucket, { ca: tls.caPem, jours: RETAIN_DAYS, mode: "COMPLIANCE" });
    const d = path.join(dir, "journal");
    const { config: brute, env } = configurationDev(d, { journal_id: N.octetsVersHex(N.keccak256(N.utf8(`journal-p6-${process.pid}`))) });
    brute.storage.seal.worm = {
      type: "s3-object-lock", bucket, prefix: PREFIXE, mode: "compliance", retain_days: RETAIN_DAYS,
      credentials: { file: fichierSecret(path.join(d, "secrets", "worm-ecrivain"), identifiantsRole("ecrivain")) },
      endpoint: prox.origine, region: null, legal_hold_on_write: false, lock_audit_interval_days: 30, copy_pieces: false,
    };
    const octetsConfig = new TextEncoder().encode(JSON.stringify(brute));
    const v = validerConfiguration(octetsConfig, { reglesSupplementaires: [controleWorm] });
    expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
    const s = resoudreSecrets(v.config, { env });
    expect(s.erreurs).to.deep.equal([]);
    // Période close : événement de politique dans l'heure courante, clôture dans l'heure suivante, copies vidées.
    const wormA = supportWormDepuisConfiguration(v.config, s.secrets, { tls: { ca: tls.caPem }, delais: RAPIDE });
    const a = await Coeur.demarrer({ config: v.config, secrets: s.secrets, worm: wormA, horloge: horloge(0) });
    const P = Math.floor(a.horlogeBrute.murale() / 3600000) * 3600;
    await a.arreter();
    const wormB = supportWormDepuisConfiguration(v.config, s.secrets, { tls: { ca: tls.caPem }, delais: RAPIDE });
    const b = await Coeur.demarrer({ config: v.config, secrets: s.secrets, worm: wormB, horloge: horloge(versHeureSuivante()) });
    let mesure;
    let rep;
    try {
      await b.tic();
      await wormB.vider();
      rep = b.repertoire;
      const p10 = String(P).padStart(10, "0");
      const f = fichiersMesures(rep);
      expect(f.points).to.include(`points/periode-${p10}.ndjson`);
      expect(f.manifestes).to.include.members([`manifestes/periode-${p10}.json`, `manifestes/periode-${p10}.sig`]);
      const tous = [...f.points, ...f.ancres, ...f.manifestes];
      // Lecture par l'API du support, avec les identifiants du rôle Lecteur (EX-12.36), indépendamment du registre des copies.
      const ops = new OperationsS3({ worm: v.config.storage.seal.worm, identifiants: identifiantsS3(new TextEncoder().encode(identifiantsRole("lecteur"))), tls: { ca: tls.caPem }, delais: RAPIDE });
      const eventsYears = v.config.storage.retention.events_years;
      const lireLocal = (rel) => fs.readFileSync(path.join(rep, rel));
      const lignes = await mesurerP6({ ops, fichiers: tous, lireLocal, eventsYears });
      // Sensibilité de la mesure : un original qui diffère de sa copie est compté (sha256_different).
      const altere = await mesurerP6({ ops, fichiers: [f.manifestes[0]], lireLocal: (rel) => Buffer.concat([lireLocal(rel), Buffer.from(" ")]), eventsYears });
      expect(altere.map((l) => [l.conforme, l.raison])).to.deep.equal([[false, "sha256_different"]]);
      const registre = (await lireRegistres(path.join(rep, "worm"))).map((x) => x.ligne.key);
      mesure = { lignes, f, eventsYears, p10, registre, ancresAbsent: !fs.existsSync(path.join(rep, "ancres")) };
    } finally {
      await b.arreter();
    }
    const { lignes, f, eventsYears } = mesure;
    // Aucun composant d'ancrage avant l'étape 5 : le démon n'écrit pas ancres/ (CT-5 §5.5) ; la part « ancres » de P-6 est vide.
    expect(mesure.ancresAbsent).to.equal(true);
    expect(f.ancres).to.deep.equal([]);
    const nonConformes = lignes.filter((l) => !l.conforme);
    expect(nonConformes, JSON.stringify(nonConformes)).to.deep.equal([]);
    expect(lignes.every((l) => l.versions.length === 1 && l.versions[0].mode === "COMPLIANCE")).to.equal(true);
    // Chaque fichier mesuré a sa ligne au registre des copies de l'écrivain (EX-12.29), sous le même chemin.
    for (const l of lignes) expect(mesure.registre).to.include(`${PREFIXE}${l.fichier}`);

    // Rapport de mesure (CT-9 §11.3).
    const catalogue = JSON.parse(fs.readFileSync(path.join(SPEC, "vecteurs", "ct-9", "catalogue.json"), "utf8"));
    const entree = catalogue.tests.find((t) => t.id === "TM-16");
    const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: RACINE, encoding: "utf8" }).trim();
    const modifie = execFileSync("git", ["status", "--porcelain"], { cwd: RACINE, encoding: "utf8" }).trim() !== "";
    const instant = `${debut.toISOString().slice(0, 19)}Z`;
    const detail = lignes.map((l) => `${l.fichier} : ${l.conforme ? "conforme" : `non conforme (${l.raison})`}, ${l.versions.map((x) => `version ${x.version_id}, sha256 ${x.sha256}, mode ${x.mode}, échéance ${x.retain_until}`).join(" ; ")}`).join(". ");
    const rapport = {
      version: 0,
      kind: "rapport-mesure",
      date: instant.slice(0, 10),
      measured_at: instant,
      commit,
      spec_version: catalogue.spec_version,
      system: systeme(),
      method: { warmup: entree.measure.warmup, repetitions: entree.measure.repetitions, percentile_method: "plus_proche_rang", clock: "sans_objet", pair_with_without: false, samples_published: false },
      configuration_sha256: N.sha256Hex(octetsConfig).slice(2),
      counts_for_targets: false,
      results: [
        {
          name: entree.measure.result_name,
          test_id: "TM-16",
          unit: entree.measure.unit,
          n: lignes.length,
          connections: null,
          samples: null,
          samples_sha256: null,
          value: nonConformes.length,
          p50: null,
          p95: null,
          p99: null,
          min: null,
          max: null,
          mean: null,
          text_value: null,
          target: entree.measure.target,
          met: null,
          conditions: [
            `API du support : S3 à Object Lock de LocalStack 4.0 (image ${IMAGES.s3}), en conteneur Docker, derrière un mandataire TLS ; bucket créé avec Object Lock et rétention par défaut COMPLIANCE de ${RETAIN_DAYS} jours (EX-12.30)`,
            `une période close par le cœur du démon (paquets/enregistreur) : ${f.points.length} fichier(s) de points, ${f.ancres.length} fichier(s) d'ancres (aucun composant d'ancrage avant l'étape 5 : ancres/ absent), ${f.manifestes.length} fichier(s) de manifestes (manifeste et signature)`,
            "par fichier : ListObjectVersions sur la clé <prefix> + chemin relatif de 12.1, GET de chaque version avec versionId (SHA-256 recalculé), HEAD avec versionId (x-amz-object-lock-mode, x-amz-object-lock-retain-until-date), identifiants du rôle Lecteur",
            `conforme : une version au même SHA-256, mode COMPLIANCE, échéance au moins égale à sa date de création sur le support plus 365 × events_years (${eventsYears}) jours, moins une heure (tolérance d'EX-12.33)`,
          ],
          excluded_reason: "hors_systeme_de_reference",
        },
      ],
      notes: `TM-16 (CT-5 P-6, §5.5 ; CT-2 EX-12.16, EX-12.17). Relevé par l'API du support, une exécution (EX-11.10). ${detail}. Mesure faite hors du système de référence de CT-9 §11.1 (machine virtuelle, disque virtuel, support émulé en conteneur) : elle ne compte pour aucune cible. Commit : ${commit}${modifie ? ", arbre de travail modifié (lot non encore commité)" : ""}.`,
    };
    const schema = JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", "plan-de-tests-v0.schema.json"), "utf8"));
    const { validerSchema } = await import("../scripts/lib/journal.mjs");
    expect(validerSchema(rapport, schema, { fragment: "#/$defs/rapport_mesure" })).to.deep.equal([]);
    expect(rapport.results[0].value).to.equal(0);
    if (process.env.NOORTRACE_RAPPORT_TM16) fs.writeFileSync(process.env.NOORTRACE_RAPPORT_TM16, `${JSON.stringify(rapport, null, 2)}\n`);
  });
});
