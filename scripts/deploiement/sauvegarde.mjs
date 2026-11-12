#!/usr/bin/env node
// Sauvegarde d'un journal (CT-8 §11.2, EX-11.2 à EX-11.4 ; chemin A de 11.4,
// pas 2 et 3) : archive au format déterministe de 13.4 et procès-verbal
// `sauvegarde` (schéma proces-verbal-exploitation-v0, 11.9).
//
//   node scripts/deploiement/sauvegarde.mjs creer --journal <répertoire du journal> --cles <cles.json> \
//     --archive <archive.tar à créer> --pv <procès-verbal.json à créer> --id pv-AAAA-MM-JJ-NNN \
//     --executant <identité> [--temoin <identité>] --motif <texte> --source <désignation> \
//     --destination <désignation> [--support-source volume_local|volume_bloc|autre] [--date <horodatage>] [--json]
//   node scripts/deploiement/sauvegarde.mjs verifier --archive <archive.tar> --pv <procès-verbal.json> [--json]
//   node scripts/deploiement/sauvegarde.mjs extraire --archive <archive.tar> --pv <procès-verbal.json> --vers <répertoire neuf> [--json]
//
// `creer` lit chaque fichier ordinaire du répertoire du journal une seule
// fois (refus d'un lien, d'un fichier spécial, d'un composant `secrets` ou
// d'une clé privée : EX-11.1, point 2 ; PV-10), garde d'un fichier `.ndjson`
// en cours d'écriture le préfixe qui finit à sa dernière fin de ligne (noté
// dans `observations`), écrit l'archive (date commune : `started_at`), la
// relit et en contrôle la forme, l'extrait dans un répertoire temporaire
// neuf, y exécute verifier-journal.mjs (EX-11.7) puis proces-verbal.mjs
// verifier --racine (PV-1 à PV-10), et n'écrit le procès-verbal, avec le
// rapport du vérificateur à côté (`<pv>.verification-journal.json`, dont le
// SHA-256 est `verification.report_sha256`), que si tout réussit.
// `verifier` contrôle la forme de l'archive (EX-13.13, EX-13.14) et chaque
// fichier contre le procès-verbal (longueur, SHA-256 : EX-11.4, PV-4, PV-7).
// `extraire` fait ce contrôle puis écrit les fichiers dans un répertoire neuf
// (0700, fichiers 0600 : EX-11.4 ; le chemin A, pas 6, en fixe ensuite le
// propriétaire) et imprime la plus haute époque des noms de segments, à
// consigner au procès-verbal `restauration` (pas 6).
// Codes : 0 fait (ou conforme) ; 1 contenu refusé, archive non conforme ou
// vérification en échec (rien n'est écrit par creer) ; 2 usage.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { messageOptions, texteJSON } from "../lib/deploiement.mjs";
import { inventaire, ecrireArchive, lireArchive, extraire, epoqueMaxSegments, sha256, ErreurSauvegarde } from "../lib/sauvegarde.mjs";

const ICI = path.dirname(fileURLToPath(import.meta.url));
const VERSION = "0.1.0";

const USAGE = [
  "Usage : node scripts/deploiement/sauvegarde.mjs creer --journal <répertoire> --cles <cles.json> --archive <archive.tar> --pv <pv.json> --id pv-AAAA-MM-JJ-NNN --executant <identité> [--temoin <identité>] --motif <texte> --source <désignation> --destination <désignation> [--support-source volume_local|volume_bloc|autre] [--date <horodatage>] [--json]",
  "        node scripts/deploiement/sauvegarde.mjs verifier --archive <archive.tar> --pv <pv.json> [--json]",
  "        node scripts/deploiement/sauvegarde.mjs extraire --archive <archive.tar> --pv <pv.json> --vers <répertoire neuf> [--json]",
].join("\n");

const OPTIONS = {
  journal: { type: "string" }, cles: { type: "string" }, archive: { type: "string" }, pv: { type: "string" }, id: { type: "string" },
  executant: { type: "string" }, temoin: { type: "string" }, motif: { type: "string" }, source: { type: "string" }, destination: { type: "string" },
  "support-source": { type: "string" }, date: { type: "string" }, vers: { type: "string" }, json: { type: "boolean" },
};
const REQUISES = {
  creer: ["journal", "cles", "archive", "pv", "id", "executant", "motif", "source", "destination"],
  verifier: ["archive", "pv"],
  extraire: ["archive", "pv", "vers"],
};
const PERMISES = {
  creer: [...REQUISES.creer, "temoin", "support-source", "date", "json"],
  verifier: [...REQUISES.verifier, "json"],
  extraire: [...REQUISES.extraire, "json"],
};
const RE_HORODATAGE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
const RE_ID = /^pv-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{3}$/;

class ErreurUsage extends Error {}

function analyser(argv) {
  const [sous, ...reste] = argv;
  const o = parseArgs({ args: reste, strict: true, allowPositionals: false, options: OPTIONS }).values;
  if (!Object.hasOwn(REQUISES, sous ?? "")) throw new ErreurUsage(sous === undefined ? "sous-commande requise (creer, verifier, extraire)" : sous.startsWith("-") ? `option inconnue : ${sous}` : `sous-commande inconnue : ${sous}`);
  for (const k of REQUISES[sous]) if (o[k] === undefined) throw new ErreurUsage(`option --${k} requise`);
  for (const k of Object.keys(o)) if (!PERMISES[sous].includes(k)) throw new ErreurUsage(`option --${k} sans objet pour ${sous}`);
  if (o.date !== undefined && !RE_HORODATAGE.test(o.date)) throw new ErreurUsage("--date : horodatage AAAA-MM-JJTHH:MM:SS.mmmZ attendu");
  if (o.id !== undefined && !RE_ID.test(o.id)) throw new ErreurUsage("--id : pv-AAAA-MM-JJ-NNN attendu");
  if (o["support-source"] !== undefined && !["volume_local", "volume_bloc", "autre"].includes(o["support-source"])) throw new ErreurUsage("--support-source : volume_local, volume_bloc ou autre");
  if (o.temoin !== undefined && o.temoin === o.executant) throw new ErreurUsage("--temoin : identité distincte de l'exécutant attendue (PV-5)");
  return { sous, o };
}

const horodatage = (ms) => new Date(ms).toISOString();

function lancerOutil(nom, args) {
  return spawnSync(process.execPath, [path.join(ICI, nom), ...args], { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
}

/** Contrôle d'une archive contre un procès-verbal `sauvegarde` : liste d'écarts (vide si conforme). */
export function controlerArchive(octetsArchive, pv) {
  const lu = lireArchive(octetsArchive);
  const ecarts = [...lu.erreurs];
  if (pv?.kind !== "sauvegarde") ecarts.push(`procès-verbal de sorte ${JSON.stringify(pv?.kind)} : sauvegarde attendue`);
  const attendus = new Map((pv?.files ?? []).map((f) => [f.path, f]));
  const presents = new Set();
  for (const f of lu.fichiers) {
    presents.add(f.path);
    const a = attendus.get(f.path);
    if (!a) {
      ecarts.push(`${f.path} : présent dans l'archive, absent du procès-verbal`);
      continue;
    }
    if (a.length !== f.length) ecarts.push(`${f.path} : longueur ${f.length} au lieu de ${a.length}`);
    const s = a.sha256_destination ?? a.sha256_source;
    if (s !== f.sha256) ecarts.push(`${f.path} : SHA-256 ${f.sha256} au lieu de ${s}`);
  }
  for (const p of attendus.keys()) if (!presents.has(p)) ecarts.push(`${p} : listé au procès-verbal, absent de l'archive`);
  if (lu.mtime !== null && typeof pv?.started_at === "string" && lu.mtime !== Math.floor(Date.parse(pv.started_at) / 1000)) ecarts.push(`date des entrées ${lu.mtime} différente de started_at (${pv.started_at})`);
  return { ecarts, fichiers: lu.fichiers };
}

function creer(o, sortie) {
  const debut = o.date !== undefined ? Date.parse(o.date) : Math.floor(Date.now() / 1000) * 1000;
  const started_at = horodatage(debut);
  for (const [k, v] of [["archive", o.archive], ["pv", o.pv]]) if (fs.existsSync(v)) throw new ErreurUsage(`--${k} : ${v} existe déjà`);
  const rapportChemin = `${o.pv}.verification-journal.json`;
  if (fs.existsSync(rapportChemin)) throw new ErreurUsage(`${rapportChemin} existe déjà`);
  if (!fs.statSync(o.journal, { throwIfNoEntry: false })?.isDirectory()) throw new ErreurUsage(`--journal : ${o.journal} n'est pas un répertoire`);
  const identite = JSON.parse(fs.readFileSync(path.join(o.journal, "journal.json"), "utf8"));
  const { fichiers, tronques } = inventaire(o.journal);
  const octets = ecrireArchive(fichiers, Math.floor(debut / 1000));
  const travail = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-sauvegarde-"));
  try {
    // Relecture de l'archive écrite : forme, puis chaque fichier contre la source (EX-11.4).
    fs.writeFileSync(o.archive, octets, { flag: "wx", mode: 0o600 });
    const relue = lireArchive(fs.readFileSync(o.archive));
    if (relue.erreurs.length) throw new ErreurSauvegarde(`archive relue non conforme : ${relue.erreurs.join(" ; ")}`);
    const source = new Map(fichiers.map((f) => [f.path, f]));
    const lignes = relue.fichiers.map((f) => {
      const s = source.get(f.path);
      return { path: f.path, length: s.octets.length, sha256_source: sha256(s.octets), sha256_destination: f.sha256 };
    });
    for (const l of lignes) if (l.sha256_source !== l.sha256_destination) throw new ErreurSauvegarde(`${l.path} : SHA-256 relu différent de la source`);
    const racine = path.join(travail, "journal");
    extraire(relue.fichiers, racine);
    const vj = lancerOutil("verifier-journal.mjs", [racine, "--cles", o.cles, "--json"]);
    if (vj.status !== 0 && vj.status !== 1) throw new ErreurSauvegarde(`verifier-journal.mjs : code ${vj.status} ${vj.stderr.trim()}`);
    const rapport = JSON.parse(vj.stdout);
    if (rapport.verdict !== "valide") throw new ErreurSauvegarde(`verifier-journal.mjs rend ${rapport.verdict} sur l'archive : ${JSON.stringify(rapport.errors).slice(0, 2000)}`);
    const periodes = (rapport.manifests ?? []).filter((m) => m.verdict === "valide").map((m) => m.period_start);
    const observations = tronques.length
      ? `fichiers en cours d'écriture, gardés jusqu'à leur dernière fin de ligne : ${tronques.map((t) => `${t.path} (${t.retenu} octets sur ${t.length})`).join(", ")}`
      : null;
    const pv = {
      version: 0,
      kind: "sauvegarde",
      id: o.id,
      org_id: identite.org_id,
      journal_id: identite.journal_id,
      started_at,
      finished_at: horodatage(Math.max(debut, Math.floor(Date.now() / 1000) * 1000)),
      operators: [{ identity: o.executant, role: "executant" }, ...(o.temoin !== undefined ? [{ identity: o.temoin, role: "temoin" }] : [])],
      reason: o.motif,
      source: { medium: o["support-source"] ?? "volume_local", locator: o.source },
      destination: { medium: "archive_sauvegarde", locator: o.destination },
      files: lignes,
      totals: { files: lignes.length, bytes: lignes.reduce((s, l) => s + l.length, 0) },
      verification: {
        tool: `verifier-journal ${VERSION} (CT-8 EX-11.7), par sauvegarde.mjs ${VERSION}`,
        command: "node scripts/deploiement/verifier-journal.mjs . --cles cles.json --json (sur l'archive extraite)",
        result: "valide",
        report_sha256: sha256(Buffer.from(vj.stdout, "utf8")),
      },
      continuity: { last_seq: rapport.last_seq, last_hash: rapport.last_hash, last_period_start: periodes.length ? Math.max(...periodes) : null },
      retention: null,
      mode_change: null,
      observations,
    };
    const cheminPv = path.join(travail, "pv.json");
    fs.writeFileSync(cheminPv, texteJSON(pv));
    const verif = lancerOutil("proces-verbal.mjs", ["verifier", cheminPv, "--racine", racine, "--cles", o.cles, "--json"]);
    if (verif.status !== 0) throw new ErreurSauvegarde(`proces-verbal.mjs verifier rend le code ${verif.status} : ${verif.stdout.trim().slice(0, 2000)} ${verif.stderr.trim()}`);
    fs.writeFileSync(rapportChemin, vj.stdout, { flag: "wx" });
    fs.writeFileSync(o.pv, texteJSON(pv), { flag: "wx" });
    if (o.json) sortie.write(texteJSON(pv));
    else sortie.write(`sauvegarde ${pv.id} : ${pv.totals.files} fichiers, ${pv.totals.bytes} octets ; archive ${sha256(octets)} (${octets.length} octets) ; dernier seq ${pv.continuity.last_seq} ; PV-1 à PV-10 réussies\n`);
    return 0;
  } catch (err) {
    fs.rmSync(o.archive, { force: true });
    throw err;
  } finally {
    fs.rmSync(travail, { recursive: true, force: true });
  }
}

function lirePv(chemin) {
  try {
    return JSON.parse(fs.readFileSync(chemin, "utf8"));
  } catch (err) {
    throw new ErreurUsage(`--pv : ${chemin} illisible (${err.message})`);
  }
}

function lireOctets(chemin) {
  try {
    return fs.readFileSync(chemin);
  } catch (err) {
    throw new ErreurUsage(`--archive : ${chemin} illisible (${err.message})`);
  }
}

function verifierOuExtraire(sous, o, sortie) {
  const pv = lirePv(o.pv);
  const { ecarts, fichiers } = controlerArchive(lireOctets(o.archive), pv);
  if (sous === "verifier" || ecarts.length) {
    const r = { verdict: ecarts.length ? "non_conforme" : "conforme", files: fichiers.length, errors: ecarts };
    sortie.write(o.json ? texteJSON(r) : `${r.verdict} : ${fichiers.length} fichiers${ecarts.length ? `\n${ecarts.map((e) => `  ${e}`).join("\n")}` : ""}\n`);
    return ecarts.length ? 1 : 0;
  }
  if (!fs.existsSync(path.dirname(path.resolve(o.vers)))) throw new ErreurUsage(`--vers : le parent de ${o.vers} n'existe pas`);
  extraire(fichiers, o.vers);
  const r = { verdict: "extrait", files: fichiers.length, bytes: fichiers.reduce((s, f) => s + f.length, 0), highest_segment_epoch: epoqueMaxSegments(fichiers.map((f) => f.path)), errors: [] };
  sortie.write(o.json ? texteJSON(r) : `extrait : ${r.files} fichiers, ${r.bytes} octets sous ${o.vers} ; époque la plus haute des segments : ${r.highest_segment_epoch}\n`);
  return 0;
}

export function principal(argv, { stdout = process.stdout, stderr = process.stderr } = {}) {
  let a;
  try {
    a = analyser(argv);
  } catch (err) {
    stderr.write(`Erreur : ${err instanceof ErreurUsage ? err.message : messageOptions(err)}\n${USAGE}\n`);
    return 2;
  }
  try {
    return a.sous === "creer" ? creer(a.o, stdout) : verifierOuExtraire(a.sous, a.o, stdout);
  } catch (err) {
    if (err instanceof ErreurUsage) {
      stderr.write(`Erreur : ${err.message}\n`);
      return 2;
    }
    if (err instanceof ErreurSauvegarde) {
      stderr.write(`Refus : ${err.message}\n`);
      return 1;
    }
    stderr.write(`Erreur : ${err.message}\n`);
    return 2;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = principal(process.argv.slice(2));
