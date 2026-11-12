#!/usr/bin/env node
// Banc « client fictif » hors réseau public (étape 7) : installation
// complète de production IC-1 à IC-18 (CT-8 §8.3), chronométrée pas par pas,
// sur l'hôte de construction (décision D-9), avec les substituts locaux de
// l'inventaire de l'étape 7 (section 2.3), les vraies images `noortrace/*`
// (chargées par `docker load` depuis l'archive `docker save`, ou déjà
// présentes) et le vrai `deploiement/compose/production.yaml` de l'archive de
// déploiement, plus un fichier de surcharge du banc qui ne fait que trois
// choses : noms `.example` des substituts (`extra_hosts`), résolution externe
// coupée (`dns: 127.0.0.1`), autorité TLS du banc (fichier monté, variables
// `NODE_EXTRA_CA_CERTS` et `SSL_CERT_FILE`) et point d'accès KMS du banc
// (`AWS_ENDPOINT_URL_KMS`).
//
//   node scripts/deploiement/banc-client-fictif.mjs --travail <répertoire neuf> --ip-interne <adresse>
//        [--org organisation-exemple] [--images <archive docker save>] [--arreter-apres IC-n] [--garder]
//
// Organisation : `organisation-exemple` (slug neuf au registre : le réseau de
// développement garde les inscriptions ; `--org` en donne un autre). Adresse
// interne : une adresse RFC 5737 portée par une interface de l'hôte (ou
// 127.0.0.1) ; tous les substituts y écoutent, et `production.yaml` y publie
// ses ports (NOORTRACE_IP_INTERNE). Aucun réseau public : les noms du banc sont
// résolus par le fichier des hôtes (bloc marqué, retiré à la fin) et par
// `extra_hosts` ; les conteneurs n'ont aucune résolution externe.
//
// Attentes : la clôture de l'heure (CT-8 IC-15) est attendue réellement, sur
// l'horloge du système : `close-period --now` n'est admise qu'en développement
// (CT-2 EX-19.4), et CT-9 EX-11.5 interdit toute horloge manipulée pendant une
// mesure. IC-16 et IC-17 se font pendant cette attente, comme CT-8 le prévoit.
//
// Sorties sous --travail : `pv/` (procès-verbal d'installation de CT-8 EX-8.3,
// clos par IC-18), `banc/proces-verbal-banc.json` (chaque pas, chaque commande,
// durées), `banc/mesures.json` (rapport de mesure de CT-9 §11.3 : `ic_1` à
// `ic_18`, `ic_attente_cloture`, `ic_total`), `banc/dossier-ic15/` (copie du
// premier dossier) et `banc/verificateurs/` (sorties exactes des
// vérificateurs). Codes : 0 installation menée et dossier valide ; 1 un pas a
// échoué ; 2 usage ; 3 condition du banc absente (Docker, images, réseau 2124).

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import * as N from "@noortrace/noyau";
import { AccesS3, requeteS3ConfigurationVerrou, requeteS3LireConfiguration, lireConfigurationVerrou, lireEvenements } from "@noortrace/enregistreur";
import { crlVersPem } from "@noortrace/ancrage";
import { publierCrl } from "@noortrace/ancrage/serveur-interne";
import {
  NOMS, PORTS, IMAGE_LOCALSTACK, pki, mandataireTls, serveurCrl, prestataireRfc3161, calendriers, recepteurWebhook, fournisseurOidc, localStack, attendre,
} from "../../test/fixtures/banc-client/substituts.mjs";
import { inscrireOrganisation, inscrireCleJournal, compte } from "../../test/fixtures/banc-client/prealables.mjs";
import { clesJournal, envelopper, procesVerbal } from "../../test/fixtures/banc-client/ceremonie.mjs";
import { ouvrirSession } from "../../test/fixtures/banc-client/agent-http.mjs";
import { Personne, inscrireAdresse, validerAdresse, voter } from "../../test/fixtures/exploitation-console/parcours/navigateur.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const USAGE = "Usage : node scripts/deploiement/banc-client-fictif.mjs --travail <répertoire neuf> --ip-interne <adresse> [--org <slug>] [--images <archive docker save>] [--arreter-apres IC-n] [--garder]";

/** Images `noortrace/*` de production.yaml (étiquette 0.1.0) et du relais. */
export const IMAGES_BANC = Object.freeze([
  "noortrace/enregistreur:0.1.0", "noortrace/attributs:0.1.0", "noortrace/approbation:0.1.0", "noortrace/console:0.1.0", "noortrace/pont-stdio:0.1.0", "noortrace/verificateur:0.1.0",
  "noortrace/noorcore:618fcef-noortrace",
]);
const POINT_RPC_LOCAL = "http://127.0.0.1:8645";
const CHAIN_BFT = "noortrace-2124-dev";
const REGION = "eu-central-2";
const KEY_ID = "rec-banc-01";
const NOM_JOURNAL = "journal-sinistres";
const MARQUE_HOTES = "# noortrace banc client fictif (étape 7)";

/**
 * Serveurs d'outils du modèle de production que le client fictif n'a pas :
 * tous sauf `fichiers`, servi par le pont. Leurs noms sont lus dans le modèle,
 * jamais écrits ici.
 */
function serveursRetires(B) {
  const modele = JSON.parse(fs.readFileSync(path.join(B.dep, "config", "modele-production", "configuration.json"), "utf8"));
  return Object.keys(modele.policy.servers).filter((a) => a !== "fichiers");
}
const SECRET_INUTILISE = "secret inutilisé par le banc (aucune route, aucun serveur, aucun bail en base) ; présent parce que production.yaml le déclare";

/** Budgets de CT-8 §8.3 (minutes). */
export const BUDGETS_IC = Object.freeze({
  "IC-1": 15, "IC-2": 45, "IC-3": 30, "IC-4": 5, "IC-5": 10, "IC-6": 15, "IC-7": 60, "IC-8": 25, "IC-9": 40, "IC-10": 15,
  "IC-11": 40, "IC-12": 30, "IC-13": 35, "IC-14": 15, "IC-15": 20, "IC-16": 20, "IC-17": 25, "IC-18": 5,
});

// ---------------------------------------------------------------- outils

const iso = (ms = Date.now()) => new Date(ms).toISOString();
const sha256 = (o) => crypto.createHash("sha256").update(o).digest("hex");
const sha256Fichier = (f) => sha256(fs.readFileSync(f));
const jeton = () => crypto.randomBytes(32).toString("hex");

/** Processus asynchrone (la boucle d'événements continue de servir les substituts). */
export function executer(commande, args, { cwd = RACINE, env = process.env, entree = null, delaiMs = 900000 } = {}) {
  return new Promise((resolve) => {
    const debut = performance.now();
    const p = spawn(commande, args, { cwd, env, stdio: [entree === null ? "ignore" : "pipe", "pipe", "pipe"] });
    const out = [];
    const err = [];
    p.stdout.on("data", (d) => out.push(d));
    p.stderr.on("data", (d) => err.push(d));
    if (entree !== null) p.stdin.end(entree);
    const minuterie = setTimeout(() => p.kill("SIGKILL"), delaiMs);
    p.on("error", (e) => err.push(Buffer.from(String(e.message))));
    p.on("close", (code) => {
      clearTimeout(minuterie);
      resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), duree_ms: Math.round(performance.now() - debut) });
    });
  });
}

/** Conditions du banc : rend la liste des conditions absentes (vide si le banc peut tourner). */
export async function conditionsBanc({ ipInterne = null } = {}) {
  const manque = [];
  const d = spawnSync("docker", ["info", "--format", "{{.ServerVersion}}"], { encoding: "utf8" });
  if (d.status !== 0) return ["Docker absent ou démon dockerd injoignable"];
  const c = spawnSync("docker", ["compose", "version"], { encoding: "utf8" });
  if (c.status !== 0) manque.push("greffon docker compose absent");
  for (const i of [...IMAGES_BANC, IMAGE_LOCALSTACK]) {
    if (spawnSync("docker", ["image", "inspect", i], { encoding: "utf8" }).status !== 0) manque.push(`image ${i} absente (étape 7 : docker load de noortrace-images-0.1.0.tar ; images d'essai)`);
  }
  try {
    const r = await fetch(POINT_RPC_LOCAL, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }), signal: AbortSignal.timeout(3000) });
    const j = await r.json();
    if (j.result !== "0x84c") manque.push("réseau de développement 2124 absent (eth_chainId ≠ 0x84c ; bash chain/scripts/dev-net.sh start)");
  } catch {
    manque.push("réseau de développement 2124 absent (bash chain/scripts/dev-net.sh start)");
  }
  if (!fs.existsSync(path.join(RACINE, "deployments", "noorcore.json"))) manque.push("deployments/noorcore.json absent (contrats du registre non déployés)");
  if (spawnSync("openssl", ["version"], { encoding: "utf8" }).status !== 0) manque.push("openssl absent");
  try {
    createRequire(import.meta.url)("playwright");
  } catch {
    manque.push("playwright absent (Chromium : console)");
  }
  const bin = process.env.NOORTRACE_VERIFIER_BIN;
  if (!bin || !fs.existsSync(bin)) manque.push("binaire noortrace-verifier absent (NOORTRACE_VERIFIER_BIN)");
  if (ipInterne && !Object.values(os.networkInterfaces()).flat().some((i) => i.address === ipInterne)) manque.push(`adresse interne ${ipInterne} portée par aucune interface de l'hôte`);
  return manque;
}

/** Adresse RFC 5737 portée par une interface de l'hôte, sinon 127.0.0.1. */
export function adresseInterneParDefaut() {
  const rfc5737 = /^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+$/;
  return Object.values(os.networkInterfaces()).flat().find((i) => i.family === "IPv4" && rfc5737.test(i.address))?.address ?? "127.0.0.1";
}

/** Environnement sans mandataire (le navigateur joint la console du banc directement, jamais par un mandataire de sortie). */
function sansMandataire() {
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (/^(https?|all|no)_proxy$/i.test(k)) delete env[k];
  return env;
}

/** Espace libre (octets) sous un chemin. */
function libre(chemin) {
  const s = fs.statfsSync(chemin);
  return s.bavail * s.bsize;
}

// ---------------------------------------------------------------- procès-verbal du banc

class ProcesVerbalBanc {
  constructor(dir) {
    this.dir = dir;
    this.pas = [];
    this.debut = null;
    this.fichier = path.join(dir, "proces-verbal-banc.json");
    this.journal = path.join(dir, "proces-verbal-banc.ndjson");
  }

  ligne(o) {
    fs.appendFileSync(this.journal, `${JSON.stringify({ at: iso(), ...o })}\n`);
  }

  /**
   * Un pas chronométré : début et fin sur l'horloge murale, durée sur
   * l'horloge monotone (CT-9 EX-11.5 : procédure, horloge murale au
   * procès-verbal ; la durée monotone est la même grandeur sans saut).
   */
  async executer(id, objet, { budget = null, compte = true } = {}, fn) {
    const p = { id, objet, budget_min: budget, compte, debut: iso(), fin: null, duree_s: null, resultat: null, commandes: [], verifications: [], ecarts: [], fichiers: [], erreur: null };
    this.pas.push(p);
    this.ligne({ evenement: "debut", pas: id, objet });
    process.stderr.write(`[${p.debut}] ${id} — ${objet}\n`);
    const t0 = performance.now();
    try {
      await fn(p);
      p.resultat = p.ecarts.length ? "reussi_avec_ecarts" : "reussi";
    } catch (e) {
      p.resultat = "echoue";
      p.erreur = String(e.stack ?? e.message ?? e);
      throw e;
    } finally {
      p.fin = iso();
      p.duree_s = Math.round((performance.now() - t0) / 100) / 10;
      this.ligne({ evenement: "fin", pas: id, resultat: p.resultat, duree_s: p.duree_s });
      process.stderr.write(`[${p.fin}] ${id} : ${p.resultat} en ${p.duree_s} s${p.erreur ? ` — ${p.erreur.split("\n")[0]}` : ""}\n`);
      this.ecrire();
    }
    return p;
  }

  ecrire(extra = {}) {
    fs.writeFileSync(this.fichier, `${JSON.stringify({ version: 0, kind: "proces-verbal-banc-client-fictif", pas: this.pas, ...extra }, null, 2)}\n`);
  }
}

/** Commande au procès-verbal du banc ; lève si le code n'est pas admis. */
async function cmd(p, affichage, commande, args, o = {}) {
  const r = await executer(commande, args, o);
  const admis = o.codes ?? [0];
  p.commandes.push({ commande: affichage, code: r.code, duree_ms: r.duree_ms, ...(o.garderSortie ? { sortie: r.stdout.slice(0, 4000) } : {}) });
  if (!admis.includes(r.code)) throw new Error(`${affichage} : code ${r.code}\n${r.stdout.slice(-2000)}\n${r.stderr.slice(-2000)}`);
  return r;
}

function verifier(p, quoi, ok, detail = null) {
  p.verifications.push({ quoi, ok: Boolean(ok), detail });
  if (!ok) throw new Error(`vérification en échec : ${quoi}${detail ? ` (${typeof detail === "string" ? detail : JSON.stringify(detail)})` : ""}`);
}

function ecart(p, texte) {
  p.ecarts.push(texte);
}

function ecrirePv(B, p, nom, contenu) {
  const f = path.join(B.pv, nom);
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, contenu);
  p.fichiers.push(nom);
  return f;
}

// ---------------------------------------------------------------- banc

function ecrireSecret(B, nom, contenu, uid) {
  const f = path.join(B.dep, "secrets", nom);
  fs.writeFileSync(f, contenu, { mode: 0o400 });
  fs.chmodSync(f, 0o400);
  fs.chownSync(f, uid, uid);
  return f;
}

function surchargeBanc(B) {
  const hotes = Object.values(NOMS).filter((n) => n !== NOMS.modeleInterdit).map((n) => `${n}:${B.ip}`);
  const commun = (env) => ({
    extra_hosts: hotes,
    dns: ["127.0.0.1"],
    environment: { NODE_EXTRA_CA_CERTS: "/run/banc/autorite.pem", SSL_CERT_FILE: "/run/banc/autorite.pem", ...env },
    volumes: [{ type: "bind", source: B.autoriteFichier, target: "/run/banc/autorite.pem", read_only: true, bind: { create_host_path: false } }],
  });
  const doc = {
    services: {
      enregistreur: commun({ AWS_ENDPOINT_URL_KMS: B.sub.ls.origineKms }),
      approbation: commun({}),
      console: commun({}),
    },
  };
  // YAML est un sur-ensemble de JSON : le fichier de surcharge est écrit en JSON.
  fs.writeFileSync(B.surcharge, `${JSON.stringify(doc, null, 2)}\n`);
}

function dcArgs(B, args) {
  return ["compose", "--project-directory", ".", "-f", "compose/production.yaml", "-f", B.surcharge, ...args];
}

async function dc(B, p, args, o = {}) {
  const affichage = `$DC ${args.join(" ")}`;
  return cmd(p, affichage, "docker", dcArgs(B, args), { cwd: B.dep, env: B.envDc, ...o });
}

function volume(nom) {
  const r = spawnSync("docker", ["volume", "inspect", "-f", "{{ .Mountpoint }}", `noortrace_${nom}`], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`volume noortrace_${nom} introuvable`);
  return r.stdout.trim();
}

function lignesExploitation() {
  const f = path.join(volume("exploitation"), "exploitation.ndjson");
  if (!fs.existsSync(f)) return [];
  return fs.readFileSync(f, "utf8").split("\n").filter((l) => l.startsWith("{")).map((l) => {
    try {
      return JSON.parse(l);
    } catch {
      return null;
    }
  }).filter(Boolean);
}

function repertoireJournal(B) {
  return path.join(volume("journal"), B.orgId.slice(2), B.journalId.slice(2));
}

// ---------------------------------------------------------------- préalables (EX-8.2)

async function prealables(B, pvb) {
  await pvb.executer("P-1", "Substituts locaux du banc (inventaire §2.3) et noms internes", { compte: false }, async (p) => {
    B.pki = pki(path.join(B.travail, "substituts", "pki"), B.ip);
    B.autoriteFichier = path.join(B.travail, "substituts", "autorite.pem");
    fs.writeFileSync(B.autoriteFichier, B.pki.ca, { mode: 0o644 });
    // Noms internes de l'hôte (préalable « noms DNS internes », EX-8.2).
    const hotes = fs.readFileSync("/etc/hosts", "utf8");
    if (!hotes.includes(MARQUE_HOTES)) {
      const bloc = [MARQUE_HOTES, ...Object.values(NOMS).filter((n) => n !== NOMS.modeleInterdit).map((n) => `${B.ip} ${n}`), `${MARQUE_HOTES} (fin)`].join("\n");
      fs.appendFileSync("/etc/hosts", `\n${bloc}\n`);
      B.hotesModifies = true;
    }
    p.commandes.push({ commande: `bloc « ${MARQUE_HOTES} » ajouté au fichier des hôtes`, code: 0, duree_ms: 0 });
    const s = path.join(B.travail, "substituts");
    B.sub = {};
    B.sub.crl = await serveurCrl({ hote: B.ip, port: PORTS.crl });
    B.sub.principal = await prestataireRfc3161({ nom: "qtsa-principal", role: "principal", hote: B.ip, port: PORTS.tsaPrincipal, nomDns: NOMS.tsaPrincipal, dir: s, crl: B.sub.crl, pkiBanc: B.pki, secret: "/run/secrets/tsa-principal", politique: "1.3.6.1.4.1.99999.3.1" });
    B.sub.secours = await prestataireRfc3161({ nom: "qtsa-secours", role: "secours", hote: B.ip, port: PORTS.tsaSecours, nomDns: NOMS.tsaSecours, dir: s, crl: B.sub.crl, pkiBanc: B.pki, secret: "/run/secrets/tsa-secours", politique: "1.3.6.1.4.1.99999.4.1" });
    B.sub.calendriers = await calendriers({ hote: B.ip, pkiBanc: B.pki, fichierEntetes: path.join(s, "entetes-regtest.json") });
    B.cleWebhook = jeton();
    B.sub.webhook = await recepteurWebhook({ hote: B.ip, port: PORTS.webhook, pkiBanc: B.pki, cle: B.cleWebhook });
    B.secretOidc = jeton();
    B.sub.oidc = await fournisseurOidc({ hote: B.ip, pkiBanc: B.pki, clientId: "noortrace-console", secret: B.secretOidc });
    B.sub.ls = await localStack({ nom: `noortrace-banc-localstack-${process.pid}`, hote: B.ip, pkiBanc: B.pki });
    B.sub.rpc = await mandataireTls({ hote: B.ip, port: PORTS.rpc, pkiBanc: B.pki, cible: { port: 8645 } });
    B.origineRpc = `https://${NOMS.rpc}:${PORTS.rpc}`;
    B.identite = (sujet) => `oidc ${B.sub.oidc.issuer} ${sujet}`;
    B.origineConsole = `https://${NOMS.console}:8700`;
    // Répertoire servi par le pont (montage lié de production.yaml).
    if (!fs.existsSync("/srv/noortrace-outils/fichiers")) {
      fs.mkdirSync("/srv/noortrace-outils/fichiers", { recursive: true });
      B.srvCree = true;
    }
    fs.chownSync("/srv/noortrace-outils/fichiers", 10101, 10101);
    fs.chmodSync("/srv/noortrace-outils/fichiers", 0o750);
    p.verifications.push({ quoi: "substituts à l'écoute", ok: true, detail: { ip: B.ip, issuer: B.sub.oidc.issuer, kms: B.sub.ls.origineKms, s3: B.sub.ls.origineS3, rpc: B.origineRpc, calendriers: B.sub.calendriers.uris } });
  });

  await pvb.executer("P-2", "Registre : organisation inscrite, jeu d'approbateurs déployé, assigné et lu, paquet client remis (CT-4 §7, §7.13)", { compte: false }, async (p) => {
    const r = await inscrireOrganisation({ travail: path.join(B.travail, "poste"), slug: B.org, consoleOrigin: B.origineConsole, administrateurs: [B.identite("admin-1")], journal: (t) => p.commandes.push({ commande: t, code: 0, duree_ms: null }) });
    B.client = r;
    B.orgId = r.orgId;
    verifier(p, "paquet client contrôlé (EX-7.22)", r.paquet.controle.valide, r.paquet.controle.ecarts);
    verifier(p, "jeu lu au registre", r.paquet.jeu.source === "registre", r.paquet.jeu);
  });

  await pvb.executer("P-3", "Archive de déploiement et note de version (images : condensés de la construction double)", { compte: false }, async (p) => {
    const dir = path.join(B.travail, "construction", "archive");
    await cmd(p, "node scripts/deploiement/construire-archive.mjs --sortie <construction>/archive", process.execPath, [path.join(RACINE, "scripts", "deploiement", "construire-archive.mjs"), "--sortie", dir]);
    B.archive = path.join(B.travail, "construction", "noortrace-deploiement-0.1.0.tar");
    await cmd(p, "tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@1794475464 -cf noortrace-deploiement-0.1.0.tar -C archive .", "tar", ["--sort=name", "--owner=0", "--group=0", "--numeric-owner", "--mtime=@1794475464", "-cf", B.archive, "-C", dir, "."]);
    B.noteArchiveSha256 = sha256Fichier(B.archive);
    const condenses = JSON.parse(fs.readFileSync(B.condensesFichier, "utf8"));
    B.condenses = Object.fromEntries(Object.values(condenses.images).map((i) => [`${i.image}:${i.tag}`, i.condense]));
    const noor = spawnSync("docker", ["image", "inspect", "-f", "{{.Id}}", "noortrace/noorcore:618fcef-noortrace"], { encoding: "utf8" }).stdout.trim();
    B.condenses["noortrace/noorcore:618fcef-noortrace"] = noor;
    fs.writeFileSync(path.join(B.travail, "construction", "note-de-version.json"), `${JSON.stringify({ archive_sha256: B.noteArchiveSha256, images: B.condenses }, null, 2)}\n`);
    p.verifications.push({ quoi: "note de version du banc", ok: true, detail: { archive_sha256: B.noteArchiveSha256, images: B.condenses } });
  });
}

// ---------------------------------------------------------------- IC-1 à IC-18

const DIMENSIONNEMENT = (rotate, garder) => ({
  version: 0,
  hours_per_year: 8760,
  coefficients: {},
  journals: [{
    id: "sinistres",
    count: 1,
    activity: { agents: 2, events_per_hour: 2, active_hours: 2920, peak_factor: 4, event_bytes: 2560, piece_bytes_per_event: 6144, pieces_per_event: 2, write_share: 0.1, ops_log_bytes_per_event: 512 },
    storage: {
      events_years: 10, local_days: 4018, pieces_days: 4018, segment_max_bytes: 16777216, min_free_bytes: 268435456, pending_max_bytes: 67108864,
      ops_log: { rotate_max_bytes: rotate, keep_files: garder }, fsync: { group_max_events: 64, group_max_wait_ms: 5 },
      worm: { retain_days: 4018, copies: 1, pieces_in_worm: false, ops_log_in_worm: false },
    },
    anchoring: { checkpoint_interval_s: 60, rfc3161_interval_s: 300, a: 0, r: 0, provider_role: "principal", registry_checkpoints: "nouveaux_evenements", ots_checkpoint: "aucun", retention_years: 10, crl_per_token: 2, crl_bytes: 833, acquisition_bytes: 2048 },
    memory: { max_concurrent: 32, request_max_bytes: 16777216, response_max_bytes: 16777216, base_bytes: null },
  }],
});

async function ic1(B, p) {
  fs.mkdirSync(B.pv, { recursive: true, mode: 0o700 });
  fs.chmodSync(B.pv, 0o700);
  p.commandes.push({ commande: 'install -d -m 0700 "$PV"', code: 0, duree_ms: 0 });
  // Poste de l'exploitant : archive vérifiée comme à IR-1, outils de cette copie.
  const poste = path.join(B.travail, "poste", "noortrace");
  fs.mkdirSync(poste, { recursive: true });
  const r = await cmd(p, "sha256sum noortrace-deploiement-0.1.0.tar (comparé à la note de version)", "sha256sum", [B.archive]);
  verifier(p, "SHA-256 de l'archive égal à la note", r.stdout.split(" ")[0] === B.noteArchiveSha256);
  await cmd(p, "tar -xkf noortrace-deploiement-0.1.0.tar -C noortrace", "tar", ["-xkf", B.archive, "-C", poste]);
  await cmd(p, "(cd noortrace && sha256sum --strict -c SHA256SUMS --quiet)", "sha256sum", ["--strict", "-c", "SHA256SUMS", "--quiet"], { cwd: poste });
  ecrirePv(B, p, "IC-1-choix.txt", [
    "Topologie (EX-3.4) : sur site, un hôte, une instance (banc client fictif, environnement de construction ; D-9).",
    `Organisation : ${B.org} (${B.orgId}) ; journal : ${NOM_JOURNAL}.`,
    "Support WORM : S3 à verrouillage d'objets en mode conformité (simulateur LocalStack du banc), rétention par défaut 4018 jours.",
    "CLE-1 (enregistreur, Ed25519) : classe C, graine enveloppée par AWS KMS (simulé). CLE-2 (clé de chaîne, secp256k1) : classe C, scalaire enveloppé par AWS KMS (simulé).",
    "Magasin de bail : file (une instance), sur le volume de storage.root.",
    "EX-3.12 : volume local de l'hôte, sans réplication synchrone (perte de l'hôte : reprise par le chemin B depuis les copies WORM).",
    "Prestataires RFC 3161 : principal et secours du banc (serveur interne de paquets/ancrage, TLS mutuel, statut qualifié déclaratif d'exemple).",
    "Calendriers OpenTimestamps : deux calendriers factices du banc. Registre : réseau de développement 2124.",
    "Déclaration d'IP-13 : cache d'écriture du disque virtuel de l'environnement de construction déclaré protégé pour le banc (source : aucune fiche ; déclaration du banc, sans valeur hors du banc).",
    "",
  ].join("\n"));
  const entrees = path.join(poste, "deploiement", "dimensionnement.json");
  fs.writeFileSync(entrees, `${JSON.stringify(DIMENSIONNEMENT(B.opsLog.rotate, B.opsLog.garder), null, 2)}\n`);
  const d = await cmd(p, "node ../scripts/deploiement/dimensionner.mjs --entrees dimensionnement.json --json > IC-1-dimensionnement.json", process.execPath, ["../scripts/deploiement/dimensionner.mjs", "--entrees", "dimensionnement.json", "--json"], { cwd: path.join(poste, "deploiement") });
  B.dimensionnement = ecrirePv(B, p, "IC-1-dimensionnement.json", d.stdout);
  const j = JSON.parse(d.stdout);
  verifier(p, "dimensionnement valide", j.valid === true, j.errors ?? null);
  ecart(p, `Entrées du dimensionnement : client fictif réduit (2 agents, 2 événements par heure, journal d'exploitation 4 Mio × 4) ; D_l = 4018 jours (CT-8 IC-1) ; hypothèses de 9.5 non mesurées (f_pic, b_o, n_crl, b_crl, b_acq) notées comme hypothèses ; local_bytes = ${j.totals?.local_bytes ?? j.journals?.[0]?.local_bytes} octets, très au-delà du disque du banc (IP-3 échouera)`);
}

async function ic2(B, p) {
  const r = await cmd(p, 'sudo bash deploiement/hote/preparer-hote.sh --simulation --stockage /var/lib/docker --declaration-cache "<déclaration du banc>" --pv "$PV"', "bash", ["deploiement/hote/preparer-hote.sh", "--simulation", "--stockage", "/var/lib/docker", "--declaration-cache", "cache d'écriture déclaré protégé pour le banc (disque virtuel de l'environnement de construction ; sans fiche)", "--pv", B.pv], { cwd: path.join(B.travail, "poste", "noortrace"), codes: [0, 3, 4], garderSortie: true });
  ecrirePv(B, p, "IC-2-simulation.txt", `code ${r.code}\n${r.stdout}${r.stderr}`);
  if (r.code !== 0) ecart(p, `preparer-hote.sh --simulation rend ${r.code} : l'environnement de construction n'est pas une machine vierge (D-9) ; le script n'est pas exécuté pour de bon (paquets du système par FL-31, réseau public)`);
  ecart(p, "preparer-hote.sh est lancé depuis la copie de l'archive du poste (IC-1) : à IC-2, l'archive n'est pas encore sur l'hôte (IC-4)");
  for (const [nom, c, a] of [["docker-version", "docker", ["version"]], ["compose-version", "docker", ["compose", "version"]], ["node-version", "node", ["--version"]]]) {
    const x = await cmd(p, `${c} ${a.join(" ")}`, c, a);
    ecrirePv(B, p, `IC-2-${nom}.txt`, x.stdout);
  }
  verifier(p, "node --version rend v22.", /^v22\./.test(process.version));
  const ch = await executer("chronyc", ["tracking"]);
  p.commandes.push({ commande: "chronyc tracking", code: ch.code, duree_ms: ch.duree_ms });
  ecrirePv(B, p, "IC-2-chronyc.txt", `code ${ch.code}\n${ch.stdout}${ch.stderr}`);
  if (ch.code !== 0) ecart(p, "chronyc absent de l'environnement de construction (pas de systemd, pas de chrony) : la vérification « chronyc tracking » d'IC-2 ne peut pas être faite ; IP-5 sera non exécutée (outil_absent)");
}

async function ic3(B, p) {
  const regles = [
    "# Règles de sortie du banc client fictif (substitut de l'export du pare-feu, EX-5.2).",
    "# Aucun pare-feu d'équipement : la sortie des conteneurs est coupée par la résolution (dns 127.0.0.1)",
    "# et seuls les noms suivants sont résolus, vers l'adresse interne de l'hôte de banc :",
    ...Object.values(NOMS).filter((n) => n !== NOMS.modeleInterdit).map((n) => `autoriser ${n} -> ${B.ip}`),
    "refuser * (aucune autre résolution, aucun nom public)",
    "réseaux internes de production.yaml : outils, console (internal: true)",
    "",
  ].join("\n");
  const f = path.join(B.travail, "hote", "regles-sortie-banc.txt");
  fs.writeFileSync(f, regles);
  B.reglesSha256 = sha256(regles);
  ecrirePv(B, p, "IC-3-regles.sha256", `${B.reglesSha256}  regles-sortie-banc.txt\n`);
  const r = await cmd(p, "docker run --rm --dns 127.0.0.1 --entrypoint /usr/local/bin/node noortrace/enregistreur:0.1.0 -e <résolution de modele.fournisseur-interdit.example>", "docker", ["run", "--rm", "--dns", "127.0.0.1", "--entrypoint", "/usr/local/bin/node", "noortrace/enregistreur:0.1.0", "-e", `require("node:dns").lookup(${JSON.stringify(NOMS.modeleInterdit)},(e)=>{console.log(e?e.code:"resolu");process.exit(e?3:0)})`], { codes: [3] });
  ecrirePv(B, p, "IC-3-essai-refus.txt", `destination ${NOMS.modeleInterdit} depuis un conteneur du banc : ${r.stdout.trim()} (code ${r.code})\n`);
  verifier(p, "une destination non déclarée n'est pas joignable depuis un conteneur (refus par la résolution)", r.code === 3);
  ecart(p, "Pas de pare-feu d'équipement ni de journal du pare-feu (règle 4 d'EX-5.2) : la coupure du banc est la résolution des noms ; une adresse IP littérale n'est pas refusée par le banc");
}

async function ic4(B, p) {
  fs.mkdirSync(B.racine, { recursive: true });
  const copie = path.join(B.travail, "hote", "noortrace-deploiement-0.1.0.tar");
  fs.copyFileSync(B.archive, copie);
  const r1 = await cmd(p, "echo '<SHA-256 de la note>  noortrace-deploiement-0.1.0.tar' | sha256sum -c", "sha256sum", ["-c"], { cwd: path.dirname(copie), entree: `${B.noteArchiveSha256}  noortrace-deploiement-0.1.0.tar\n` });
  await cmd(p, "tar -xkf noortrace-deploiement-0.1.0.tar -C noortrace", "tar", ["-xkf", copie, "-C", B.racine]);
  const r2 = await cmd(p, "(cd .. && sha256sum --strict -c SHA256SUMS --quiet)", "sha256sum", ["--strict", "-c", "SHA256SUMS", "--quiet"], { cwd: B.racine });
  ecrirePv(B, p, "IC-4-archive.txt", `${r1.stdout}${r2.stdout}(SHA256SUMS : aucune ligne, code ${r2.code})\n`);
}

async function controle(B, p, nom, args) {
  const r = await cmd(p, `sudo "$(command -v node)" ../scripts/deploiement/controle-prealable.mjs ${args.join(" ")} --json > "$PV"/${nom}`, process.execPath, ["../scripts/deploiement/controle-prealable.mjs", ...args, "--json"], { cwd: B.dep, codes: [0, 1], env: { ...sansMandataire(), SSL_CERT_FILE: B.autoriteFichier } });
  ecrirePv(B, p, nom, r.stdout);
  const rapport = JSON.parse(r.stdout);
  const nonReussies = rapport.checks.filter((c) => c.status !== "reussi").map((c) => ({ id: c.id, status: c.status, reason: c.reason }));
  p.verifications.push({ quoi: `verdict du contrôle préalable (${nom})`, ok: rapport.verdict !== "non_pret", detail: { verdict: rapport.verdict, non_reussies: nonReussies } });
  const bloquantes = rapport.checks.filter((c) => c.blocking && c.status !== "reussi" && c.status !== "avertissement");
  const portsIc11 = (c) => c.id === "IP-6" && c.reason === "port_occupe" && (c.measured?.busy ?? []).every((b) => [8601, 8700].includes(b.port)) && nom.startsWith("IC-14");
  const admises = bloquantes.filter((c) => (c.id === "IP-5" && c.reason === "outil_absent") || c.id === "IP-3" || portsIc11(c));
  for (const c of admises) {
    if (c.id === "IP-6") {
      ecart(p, `${nom} : IP-6 port_occupe sur ${JSON.stringify(c.measured.busy)} : ports publiés par approbation et console, démarrés à IC-11 comme CT-8 l'ordonne (contradiction de CT-8 entre IC-11 et IC-14)`);
      continue;
    }
    ecart(p, c.id === "IP-5"
      ? `${nom} : IP-5 non exécutée (outil_absent : ni chronyc, ni timedatectl synchronisé, dans l'environnement de construction) ; verdict ${rapport.verdict}`
      : `${nom} : IP-3 ${c.status} (${c.reason}) : espace libre du disque de l'environnement de construction (${JSON.stringify(c.measured)}) sous local_bytes du dimensionnement (${JSON.stringify(c.expected)}) ; verdict ${rapport.verdict}`);
  }
  const autres = bloquantes.filter((c) => !admises.includes(c));
  if (autres.length) throw new Error(`contrôle préalable ${nom} : ${JSON.stringify(autres.map((c) => ({ id: c.id, status: c.status, reason: c.reason, measured: c.measured })))}`);
  return rapport;
}

async function ic5(B, p) {
  B.controleIc5 = await controle(B, p, "IC-5-controle.json", ["--profil", "production", "--seulement", "IP-1,IP-2,IP-4,IP-5,IP-6,IP-11,IP-13", "--declare", "cache-protege", "--compose", "compose/production.yaml", "--ip-interne", B.ip, "--stockage", "/var/lib/docker"]);
}

async function ic6(B, p) {
  const f = path.join(B.dep, "compose", "production.yaml");
  let texte = fs.readFileSync(f, "utf8");
  for (const [ref, condense] of Object.entries(B.condenses)) {
    const avant = `image: ${ref}\n`;
    if (!texte.includes(avant)) throw new Error(`production.yaml : ligne « ${avant.trim()} » absente`);
    texte = texte.replace(avant, `image: ${ref}@${condense}\n`);
  }
  fs.writeFileSync(f, texte);
  p.commandes.push({ commande: "compose/production.yaml : chaque image complétée par le condensé de la note de version", code: 0, duree_ms: 0 });
  const r = await cmd(p, 'node ../scripts/deploiement/verifier-conteneurs.mjs compose/production.yaml --images images/images.json --json > "$PV"/IC-6-conteneurs.json', process.execPath, ["../scripts/deploiement/verifier-conteneurs.mjs", "compose/production.yaml", "--images", "images/images.json", "--json"], { cwd: B.dep, codes: [0, 1] });
  ecrirePv(B, p, "IC-6-conteneurs.json", r.stdout);
  const j = JSON.parse(r.stdout);
  const fichier = Array.isArray(j.files) ? j.files[0] : j;
  verifier(p, "verdict conforme et toutes les images par condensé", (fichier.verdict ?? j.verdict) === "conforme" && (fichier.all_images_by_digest ?? j.all_images_by_digest) === true, j);
  if (B.imagesTar && fs.existsSync(B.imagesTar)) {
    await cmd(p, "docker load -i noortrace-images-0.1.0.tar (au lieu de $DC pull : aucune image publiée, D-3)", "docker", ["load", "-i", B.imagesTar]);
  } else {
    ecart(p, "archive docker save absente : images déjà présentes dans le magasin local (aucune image publiée, D-3)");
  }
  for (const [ref, condense] of Object.entries(B.condenses)) {
    const x = await cmd(p, `docker image inspect ${ref}@${condense}`, "docker", ["image", "inspect", "-f", "{{.Id}}", `${ref}@${condense}`]);
    verifier(p, `${ref}@${condense.slice(0, 19)}… présente`, x.stdout.trim() === condense, x.stdout.trim());
  }
  ecart(p, "$DC pull remplacé par docker load : aucune image n'est publiée (D-3) ; le registre de conteneurs (FL-29) n'est pas éprouvé");
  ecrirePv(B, p, "IC-6-conteneurs.sha256", `${sha256Fichier(f)}  compose/production.yaml\n`);
}

async function ic7(B, p) {
  const debut = new Date();
  B.indiceCles = 3000000 + (Math.floor(Date.now() / 1000) % 100000000) * 4;
  B.cles = clesJournal(B.indiceCles);
  // journal_id = keccak256(utf8(nom)) (CT-4 §6.3, journalIdOf).
  B.journalId = N.octetsVersHex(N.keccak256(N.utf8(NOM_JOURNAL)));
  B.identiteAws = "[default]\naws_access_key_id = banc-enregistreur\naws_secret_access_key = banc-enregistreur-secret\n";
  const env = { AWS_ACCESS_KEY_ID: "banc-officiant", AWS_SECRET_ACCESS_KEY: "banc-officiant-secret" };
  // Le poste de cérémonie joint le KMS par son origine locale (le magasin d'autorités du poste n'a pas l'autorité du banc).
  B.enveloppes = await envelopper({ origineKms: B.sub.ls.locale, region: REGION, env, orgId: B.orgId, journalId: B.journalId, keyId: KEY_ID, cles: B.cles });
  verifier(p, "condensé d'essai signé par la clé de chaîne : adresse recouvrée égale à l'adresse déclarée (CT-7 §5.4, pas 6)", B.enveloppes.adresseRecouvree === B.cles.chaine.adresse, { recouvree: B.enveloppes.adresseRecouvree, declaree: B.cles.chaine.adresse });
  const journalPoste = [
    `clé KMS d'enveloppe : ${B.enveloppes.arn}`,
    `CLE-1 ${KEY_ID} : clé publique ${N.octetsVersHex(B.cles.clePublique)}`,
    `CLE-2 : adresse ${B.cles.chaine.adresse}`,
    `condensé d'essai ${B.enveloppes.condenseEssai} ; adresse recouvrée ${B.enveloppes.adresseRecouvree}`,
    "",
  ].join("\n");
  const ceremonie = await procesVerbal({
    dir: path.join(B.travail, "poste", "ceremonie"), org: B.org, orgId: B.orgId, keyId: KEY_ID, cles: B.cles, debut, fin: new Date(), journalPoste,
    condenser: async (fichier) => {
      const r = await cmd(p, "npm run verify:ceremonie -- <procès-verbal> --condense", process.execPath, [path.join(RACINE, "scripts", "verify", "ceremonie.mjs"), fichier, "--condense"]);
      return r.stdout.trim().split("\n")[0].trim();
    },
  });
  const v = await cmd(p, "npm run verify:ceremonie -- proces-verbal-ceremonie.json", process.execPath, [path.join(RACINE, "scripts", "verify", "ceremonie.mjs"), ceremonie.fichier], { codes: [0, 1, 2] });
  ecrirePv(B, p, "IC-7-ceremonie.json", fs.readFileSync(ceremonie.fichier));
  ecrirePv(B, p, "IC-7-ceremonie.sha256", `${sha256Fichier(ceremonie.fichier)}  IC-7-ceremonie.json\n`);
  ecrirePv(B, p, "IC-7-verification.txt", `code ${v.code}\n${v.stdout}${v.stderr}`);
  verifier(p, "npm run verify:ceremonie rend 0 (CR-1 à CR-12)", v.code === 0, v.stdout.slice(-1500) + v.stderr.slice(-500));
  ecart(p, "Cérémonie jouée par le harnais (participants : comptes d'essai 5, 6 et 7 du mnémonique public), sans personne ni poste hors ligne réels");
}

async function ic8(B, p) {
  const s = path.join(B.dep, "secrets");
  fs.mkdirSync(s, { mode: 0o700 });
  fs.chmodSync(s, 0o700);
  p.commandes.push({ commande: "install -d -m 0700 secrets", code: 0, duree_ms: 0 });
  B.jetons = { hoteAgents: jeton(), pont: jeton(), noyau: jeton(), console: jeton(), rpc: jeton() };
  const E = 10001;
  ecrireSecret(B, "cle-mac-relais", jeton(), E);
  ecrireSecret(B, "acces-signataire", B.enveloppes.graineScellee, E);
  ecrireSecret(B, "cle-chaine", B.enveloppes.chaineScellee, E);
  ecrireSecret(B, "identite-aws", B.identiteAws, E);
  ecrireSecret(B, "worm-ecrivain", JSON.stringify({ access_key_id: "banc-ecrivain", secret_access_key: "banc-ecrivain-secret" }), E);
  ecrireSecret(B, "jeton-hote-agents", B.jetons.hoteAgents, E);
  ecrireSecret(B, "jeton-hote-otel", jeton(), E);
  ecrireSecret(B, "jeton-passerelle", jeton(), E);
  ecrireSecret(B, "jeton-noyau-vers-service-enregistreur", B.jetons.noyau, E);
  ecrireSecret(B, "tsa-principal", B.pki.clientPem, E);
  ecrireSecret(B, "tsa-secours", B.pki.clientPem, E);
  ecrireSecret(B, "tls-enregistreur-certificat", B.pki.cert, E);
  ecrireSecret(B, "tls-enregistreur-cle", B.pki.key, E);
  ecrireSecret(B, "identifiant-outil-fichiers", `Bearer ${B.jetons.pont}`, E);
  const outilsRetires = serveursRetires(B).map((a) => `identifiant-outil-${a}`);
  for (const n of ["dsn-bail", "cle-fournisseur-anthropic", "cle-fournisseur-openai", "cle-fournisseur-gemini", ...outilsRetires]) ecrireSecret(B, n, jeton(), E);
  ecart(p, `secrets dsn-bail, cle-fournisseur-*, ${outilsRetires.join(", ")} : ${SECRET_INUTILISE}`);
  const A = 10002;
  ecrireSecret(B, "cle-stockage-approbation", jeton(), A);
  ecrireSecret(B, "jeton-noyau-vers-service", B.jetons.noyau, A);
  ecrireSecret(B, "jeton-console-vers-service-approbation", B.jetons.console, A);
  ecrireSecret(B, "rpc-registre", B.jetons.rpc, A);
  ecrireSecret(B, "notification-webhook", B.cleWebhook, A);
  ecrireSecret(B, "tls-approbation", B.pki.serveurPem, A);
  const C = 10003;
  ecrireSecret(B, "jeton-console-vers-service-console", B.jetons.console, C);
  ecrireSecret(B, "oidc-client", B.secretOidc, C);
  ecrireSecret(B, "tls-console", B.pki.serveurPem, C);
  ecrireSecret(B, "tls-autorite-approbation", B.pki.ca, C);
  ecrireSecret(B, "jeton-pont-fichiers", B.jetons.pont, 10101);
  const r = await cmd(p, "sudo stat -c '%a %u %n' secrets/*", "bash", ["-c", "stat -c '%a %u %n' secrets/*"], { cwd: B.dep });
  ecrirePv(B, p, "IC-8-secrets.txt", r.stdout);
  verifier(p, "chaque secret en 400, propriété du compte de son service", r.stdout.trim().split("\n").every((l) => l.startsWith("400 ")));
}

async function ic9(B, p) {
  B.bucket = "noortrace-banc-worm";
  const admin = new AccesS3({ endpoint: B.sub.ls.origineS3, region: REGION, bucket: B.bucket, identifiants: { access_key_id: "banc-administrateur", secret_access_key: "banc-administrateur-secret" }, tls: { ca: B.pki.ca } });
  const corpsCreation = Buffer.from(`<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>${REGION}</LocationConstraint></CreateBucketConfiguration>`, "utf8");
  const r1 = await admin.envoyer({ method: "PUT", target: "/", headers: [["x-amz-bucket-object-lock-enabled", "true"]], body: corpsCreation });
  p.commandes.push({ commande: `S3 PUT /${B.bucket} (x-amz-bucket-object-lock-enabled: true), administrateur du compte`, code: r1.statut, duree_ms: null });
  verifier(p, "conteneur créé avec verrouillage d'objets", r1.statut === 200, `${r1.statut} ${r1.corps ? Buffer.from(r1.corps).toString("utf8").slice(0, 400) : ""}`);
  const r2 = await admin.envoyer(requeteS3ConfigurationVerrou(4018, "COMPLIANCE"));
  p.commandes.push({ commande: "S3 PUT /?object-lock (COMPLIANCE, 4018 jours)", code: r2.statut, duree_ms: null });
  verifier(p, "rétention par défaut posée", r2.statut === 200, r2.statut);
  const roles = ["ecrivain", "gardien-pose", "gardien-levee", "lecteur", "administrateur"];
  for (const role of roles) {
    ecrirePv(B, p, `IC-9-politiques/${role}.json`, `${JSON.stringify({ role, identite: `banc-${role}`, note: "simulateur S3 du banc : les politiques d'accès ne sont pas appliquées (LocalStack) ; identités distinctes par rôle seulement" }, null, 2)}\n`);
  }
  const lecteur = new AccesS3({ endpoint: B.sub.ls.origineS3, region: REGION, bucket: B.bucket, identifiants: { access_key_id: "banc-lecteur", secret_access_key: "banc-lecteur-secret" }, tls: { ca: B.pki.ca } });
  const r3 = await lecteur.envoyer(requeteS3LireConfiguration());
  const conf = lireConfigurationVerrou(r3.corps);
  ecrirePv(B, p, "IC-9-verrou-lecteur.json", `${JSON.stringify(conf, null, 2)}\n`);
  verifier(p, "le Lecteur relit la rétention par défaut (COMPLIANCE, 4018 jours)", conf.mode === "COMPLIANCE" && conf.days === 4018, conf);
  ecart(p, "Simulateur S3 (LocalStack) : les cinq rôles d'EX-8.4 sont des identités distinctes, mais aucune politique IAM n'est appliquée ni vérifiable (inventaire §2.3, TI-15 et TM-39 rattachés ailleurs) ; aucun second exploitant ; pas de journal d'accès aux objets");
}

async function ic10(B, p) {
  ecrirePv(B, p, "IC-10-bail.txt", "Magasin de bail : file (/var/lib/noortrace/bail, volume journal), une instance ; lease.fencing nul (admis avec file, CT-2 EX-15.4).\n");
  p.verifications.push({ quoi: "magasin file sur le volume de storage.root ; aucune connexion à vérifier", ok: true, detail: null });
}

async function ic11(B, p, ctx) {
  const prod = path.join(B.dep, "config", "production");
  fs.mkdirSync(prod, { recursive: true });
  const { version, ...gabarit } = B.client.paquet.gabarit;
  const approbation = {
    version, environment: "production", ...gabarit, journal_id: B.journalId,
    state_dir: "/var/lib/noortrace-approbation",
    storage_key: { file: "/run/secrets/cle-stockage-approbation" },
    noyau: { socket: "/run/noortrace/approbation.sock", socket_mode: "0660", tcp: null, tls: null, token: { file: "/run/secrets/jeton-noyau-vers-service" } },
    console: { socket: null, tcp: { host: "0.0.0.0", port: 8600 }, tls: { cert: { file: "/run/secrets/tls-approbation" }, key: { file: "/run/secrets/tls-approbation" }, client_ca: null }, token: { file: "/run/secrets/jeton-console-vers-service-approbation" }, annuaire: null },
    etat: { host: "0.0.0.0", port: 8601 },
    tickets: { epoch: null },
    max_open_tickets: 20,
    escalation: [{ after_ms: 900000, notify: "jeu" }, { after_ms: 2700000, notify: "administrateur" }],
    set_poll_interval_ms: 10000,
    registration_ttl_ms: 600000,
    rpc: { url: B.origineRpc, validator: "client", token: { file: "/run/secrets/rpc-registre" }, timeout_ms: 5000, logs_from_block: 0 },
    notifications: { url: B.sub.webhook.url, key: { file: "/run/secrets/notification-webhook" }, ca: null, timeout_ms: 10000 },
    remise_representation_ms: 30000,
    body_max_bytes: 16777216,
  };
  const consoleConf = {
    version: 0, environment: "production", console_origin: B.origineConsole,
    listen: { host: "0.0.0.0", port: 8700 },
    tls: { cert: { file: "/run/secrets/tls-console" }, key: { file: "/run/secrets/tls-console" } },
    service: { url: "https://approbation:8600", socket: null, token: { file: "/run/secrets/jeton-console-vers-service-console" }, ca: { file: "/run/secrets/tls-autorite-approbation" }, client_cert: null, client_key: null },
    identity: { kind: "oidc", issuer: B.sub.oidc.issuer, client_id: "noortrace-console", client_secret: { file: "/run/secrets/oidc-client" }, id_token_signing_alg_values: ["RS256"], cache_s: 3600 },
    reauth_max_age_s: 900, service_timeout_ms: 10000, delai_signature_ms: 300000, session_max_age_s: 28800, walletconnect: null,
  };
  for (const [nom, doc, uid] of [["approbation.json", approbation, 10002], ["console.json", consoleConf, 10003]]) {
    const f = path.join(prod, nom);
    fs.writeFileSync(f, `${JSON.stringify(doc, null, 2)}\n`, { mode: 0o400 });
    fs.chownSync(f, uid, uid);
    fs.chmodSync(f, 0o400);
  }
  p.commandes.push({ commande: "config/production/approbation.json et console.json écrits ; sudo chown 10002:10002 / 10003:10003 ; sudo chmod 0400", code: 0, duree_ms: 0 });
  const va = await dc(B, p, ["run", "--rm", "--no-deps", "approbation", "valider-configuration", "/etc/noortrace-approbation/configuration.json"], { codes: [0, 1] });
  ecrirePv(B, p, "IC-11-valider-approbation.json", va.stdout);
  verifier(p, "approbation : {\"valide\":true,\"errors\":[]}", va.code === 0, va.stdout + va.stderr.slice(-800));
  const vc = await dc(B, p, ["run", "--rm", "--no-deps", "console", "valider-configuration", "/etc/noortrace-console/configuration.json"], { codes: [0, 1] });
  ecrirePv(B, p, "IC-11-valider-console.json", vc.stdout);
  verifier(p, "console : {\"valide\":true,\"errors\":[]}", vc.code === 0, vc.stdout + vc.stderr.slice(-800));
  await dc(B, p, ["up", "-d", "approbation", "console"]);
  await attendre(async () => {
    const r = await executer("docker", dcArgs(B, ["ps", "--format", "json"]), { cwd: B.dep, env: B.envDc });
    const etats = r.stdout.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
    return ["approbation", "console"].every((s) => etats.find((e) => e.Service === s)?.Health === "healthy");
  }, 180000, "approbation et console healthy", 2000);
  p.verifications.push({ quoi: "$DC ps : approbation et console healthy", ok: true, detail: null });
  const sonde = await dc(B, p, ["exec", "-T", "console", "noortrace-console", "sonde"], { codes: [0, 1] });
  ecrirePv(B, p, "IC-11-sonde-console.txt", `code ${sonde.code}\n${sonde.stdout}${sonde.stderr}`);
  verifier(p, "noortrace-console sonde rend 0 (ready, service_reachable, identity_ready)", sonde.code === 0, sonde.stdout + sonde.stderr);
  const etat = await (await fetch("http://127.0.0.1:8601/v0/etat")).json();
  p.commandes.push({ commande: "curl -s http://127.0.0.1:8601/v0/etat", code: 0, duree_ms: null });
  if (!(etat.ready === true && etat.set_read_at)) ecart(p, `/v0/etat avant le démarrage du démon : ${JSON.stringify(etat)} ; le service ne lit le jeu qu'après le chargement de la politique par le démon (charger) : vérification reportée à IC-15`);
  ecrirePv(B, p, "IC-11-etat.json", `${JSON.stringify(etat, null, 2)}\n`);
  const sante = await executer("curl", ["-sS", "-k", "--noproxy", "*", "-m", "10", "--resolve", `${NOMS.console}:8700:${B.ip}`, `${B.origineConsole}/v0/sante`]);
  ecrirePv(B, p, "IC-11-sante-console.txt", `code ${sante.code}\n${sante.stdout}${sante.stderr}`);
  // Annuaire (CT-3 §13.4 à §13.8) : chaque approbateur inscrit son adresse par preuve de possession, l'administrateur la valide.
  const navigateur = await ctx.chromium();
  const personne = async (sujet, comptes) => {
    const x = await new Personne({ navigateur, fournisseur: B.sub.oidc.fournisseur, origine: B.origineConsole, sujet, comptes }).ouvrir();
    ctx.personnes.push(x);
    return x;
  };
  B.ap1 = await personne("approbateur-1", [1]);
  B.ap2 = await personne("approbateur-2", [2]);
  B.admin = await personne("admin-1", []);
  await inscrireAdresse(B.ap1, compte(1).adresse);
  await inscrireAdresse(B.ap2, compte(2).adresse);
  await validerAdresse(B.admin, compte(1).adresse);
  await validerAdresse(B.admin, compte(2).adresse);
  p.commandes.push({ commande: "console (Chromium) : approbateur-1 et approbateur-2 inscrivent leur adresse (portefeuille d'essai), admin-1 les valide", code: 0, duree_ms: null });
  const notif = await attendre(() => B.sub.webhook.recues.find((n) => n.signature_valide), 60000, "première notification livrée (HMAC vérifié)", 1000);
  ecrirePv(B, p, "IC-11-notification.json", `${JSON.stringify({ at: notif.at, kind: notif.document?.kind ?? null, signature_valide: notif.signature_valide }, null, 2)}\n`);
  ecart(p, "Empreintes de la page de la console non comparées à une note de version (CT-7 EX-3.9) : aucune note publiée (D-3)");
}

async function ic12(B, p) {
  const hote = { mcpServers: { noortrace: { type: "http", url: `http://${B.ip}:8300/mcp`, headers: { Authorization: "Bearer <contenu de secrets/jeton-hote-agents>" } } } };
  ecrirePv(B, p, "IC-12-hote-cursor-postes.json", `${JSON.stringify(hote, null, 2)}\n`);
  ecart(p, "Une seule connexion d'hôte éprouvée (cursor-postes, jeton statique sur le frontal HTTP) ; routes du frontal modèle retirées (aucun fournisseur de modèle pour le client fictif) ; pas de mode ICAP");
}

async function ic13(B, p) {
  const prod = path.join(B.dep, "config", "production");
  const doc = {
    version: 0,
    checkpoint_interval_s: 60,
    rfc3161: {
      providers: [B.sub.principal.prestataire, B.sub.secours.prestataire],
      manifest: { fallback_after_s: 300 },
      checkpoints: { interval_s: 300, provider_role: "principal", fallback_after_s: 120, countersign_idle: false },
      freshness: { max_response_delay_s: 60, clock_tolerance_s: 120 },
      retry: { initial_ms: 5000, factor: 2, max_ms: 300000, jitter_ms: 250 },
      retention_years: 10,
      crl_capture: { enabled: true, delay_s: 0 },
    },
    registry: { checkpoints: "nouveaux_evenements", squat_wait_s: 5, inclusion_alert_s: 60 },
    opentimestamps: {
      enabled: true, calendars: B.sub.calendriers.uris, min_responses: 2, timeout_ms: 5000, checkpoint: "aucun",
      upgrade: { whitelist: B.sub.calendriers.uris, first_after_s: 21600, interval_s: 1800, give_up_after_s: 1209600 },
      headers_source: { type: "fichier", network: "mainnet", path: "/var/lib/noortrace/bitcoin/entetes-bitcoin.json" },
    },
    queue: { path: "/var/lib/noortrace/ancrage", max_pending: 100000, anchor_pending_alert_s: 7200, compact_bytes: 16777216 },
  };
  B.ancrage = path.join(prod, "ancrage.json");
  fs.writeFileSync(B.ancrage, `${JSON.stringify(doc, null, 2)}\n`, { mode: 0o444 });
  const deploiement = JSON.parse(fs.readFileSync(path.join(RACINE, "deployments", "noorcore.json"), "utf8"));
  const instance = {
    version: 0, bft_chain_id: CHAIN_BFT, evm_chain_id: 2124,
    contracts: Object.entries({ AttestationRegistry: B.client.contrats.attestation_registry, PeriodRegistry: B.client.contrats.period_registry, RecorderRegistry: B.client.contrats.recorder_registry }).map(([name, address]) => ({ name, address })),
    fees: { gas_limit: 3000000, gas_limit_max: 16777216 },
    validator_sets: [{ from_height: 1, to_height: null, validators: B.client.validators, source: "validators.json du réseau de développement, clés publiques seulement" }],
    source: `réseau de développement 2124 (deployments/noorcore.json du ${deploiement.date ?? "dépôt"}, chain/runtime/validators.json) : manifeste d'instance du banc`,
  };
  fs.writeFileSync(path.join(prod, "instance-registre.json"), `${JSON.stringify(instance, null, 2)}\n`, { mode: 0o444 });
  // Inscription de la clé de l'enregistreur et de la clé de chaîne (CT-4 §8.7).
  const rep = path.join(B.travail, "poste", "inscription-journal");
  fs.mkdirSync(rep, { recursive: true, mode: 0o700 });
  const scalaire = path.join(rep, "cle-chaine.cle");
  fs.writeFileSync(scalaire, `${N.octetsVersHex(B.cles.chaine.octets).slice(2)}\n`, { mode: 0o600 });
  try {
    const r = await inscrireCleJournal({ rep, orgId: B.orgId, journalId: B.journalId, adresseChaine: B.cles.chaine.adresse, fichierScalaire: scalaire, clePubliqueEd25519: N.octetsVersHex(B.cles.clePublique) });
    for (const s of r.sorties) p.commandes.push({ commande: s.commande, code: s.code, duree_ms: null, result: s.result });
    ecrirePv(B, p, "IC-13-inscription.json", `${JSON.stringify(r.sorties, null, 2)}\n`);
    B.demandeInscription = r.demande;
  } finally {
    fs.rmSync(scalaire, { force: true });
  }
  ecart(p, "Le scalaire de la clé de chaîne est donné en clair à l'outil du registre le temps de l'inscription (fichier: admis sur le réseau de développement seulement, CT-4 EX-7.3), puis effacé");
  const copie = path.join(B.travail, "poste", "ancrage-copie.json");
  fs.copyFileSync(B.ancrage, copie);
  const v = await cmd(p, "node paquets/ancrage/bin/noortrace-ancrage configuration <copie de ancrage.json> --profil production --checkpoint-interval 60 (au lieu de npx --yes ajv-cli@5, écart E-9)", process.execPath, [path.join(RACINE, "paquets", "ancrage", "bin", "noortrace-ancrage"), "configuration", copie, "--profil", "production", "--checkpoint-interval", "60"], { codes: [0, 1] });
  ecrirePv(B, p, "IC-13-ancrage-validation.txt", `code ${v.code}\n${v.stdout}${v.stderr}`);
  verifier(p, "ancrage.json conforme à ancrage-v0 et à AN-1 (profil production)", v.code === 0, v.stdout + v.stderr);
  ecart(p, "Statut qualifié des prestataires non établi depuis une liste de confiance (TP-2) : objet qualified déclaratif d'exemple");
}

async function ic14(B, p) {
  const modele = JSON.parse(fs.readFileSync(path.join(B.dep, "config", "modele-production", "configuration.json"), "utf8"));
  const c = structuredClone(modele);
  c.recorder = { ...c.recorder, instance_id: "enregistreur-banc-1", org_id: B.orgId, journal_id: B.journalId, environment: "production" };
  c.signer = {
    ...c.signer, class: "C", key_id: KEY_ID,
    backend: { type: "envelope", sealed_seed_file: "/run/secrets/acces-signataire", wrap: { type: "aws-kms", key_arn: B.enveloppes.arn, region: REGION } },
    rotation: { planned_every_days: 365, next_key_id: null },
  };
  c.storage.min_free_bytes = 268435456;
  c.storage.segment_max_bytes = 16777216;
  c.storage.seal.worm = { ...c.storage.seal.worm, bucket: B.bucket, prefix: "journal-sinistres/", endpoint: B.sub.ls.origineS3, region: REGION };
  c.lease = { store: { type: "file", path: "/var/lib/noortrace/bail" }, ttl_ms: 10000, renew_ms: 3000, acquire_wait_ms: 30000, fencing: null };
  c.anchoring.registry = { ...c.anchoring.registry, rpc_url: B.origineRpc, chain_key: { ...c.anchoring.registry.chain_key, address: B.cles.chaine.adresse } };
  c.anchoring.opentimestamps = { enabled: true, calendars: B.sub.calendriers.uris };
  c.supervision.ops_log = { ...c.supervision.ops_log, rotate_max_bytes: B.opsLog.rotate, keep_files: B.opsLog.garder };
  const retires = serveursRetires(B);
  for (const a of retires) {
    delete c.policy.servers[a];
    c.policy.approval.rules.rules = c.policy.approval.rules.rules.filter((r) => !r.tools.some((t) => t.startsWith(`${a}__`)));
  }
  c.policy.approval.rules.approver_set = structuredClone(B.client.paquet.jeu);
  c.policy.model.routes = [];
  B.configuration = path.join(B.dep, "config", "production", "configuration.json");
  fs.writeFileSync(B.configuration, `${JSON.stringify(c, null, 2)}\n`, { mode: 0o400 });
  fs.chownSync(B.configuration, 10001, 10001);
  fs.chmodSync(B.configuration, 0o400);
  p.commandes.push({ commande: "config/production/configuration.json écrite depuis le modèle ; sudo chown 10001:10001 ; sudo chmod 0400", code: 0, duree_ms: 0 });
  ecart(p, `Valeurs du client fictif : serveur ${retires.join(", ")} retiré (et ses règles), routes du frontal modèle retirées, journal d'exploitation et seuils de stockage réduits au disque du banc, bail file, signataire de classe C (AWS KMS simulé)`);
  const v = await dc(B, p, ["run", "--rm", "--no-deps", "enregistreur", "validate-config", "/etc/noortrace/configuration.json"], { codes: [0, 1, 2] });
  ecrirePv(B, p, "IC-14-validate-config.txt", `code ${v.code}\n${v.stdout}${v.stderr}`);
  verifier(p, "validate-config sans erreur (code 0)", v.code === 0, v.stdout.slice(-1500) + v.stderr.slice(-1500));
  B.controleIc14 = await controle(B, p, "IC-14-controle.json", [
    "--profil", "production", "--configuration", "config/production/configuration.json", "--ancrage", "config/production/ancrage.json", "--compose", "compose/production.yaml",
    "--images", "images/images.json", "--secrets", "secrets", "--stockage", "/var/lib/docker", "--dimensionnement", B.dimensionnement, "--ip-interne", B.ip, "--declare", "cache-protege",
  ]);
}

/** IC-15, première partie : démarrage, appel soumis à approbation, décision signée par la console, appel relayé. */
async function ic15a(B, p) {
  await dc(B, p, ["up", "-d"]);
  await attendre(async () => {
    const r = await executer("docker", dcArgs(B, ["ps", "--format", "json"]), { cwd: B.dep, env: B.envDc });
    const etats = r.stdout.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const mauvais = etats.filter((e) => e.State !== "running");
    if (mauvais.length) throw new Error(`service arrêté : ${mauvais.map((e) => `${e.Service} ${e.Status}`).join(", ")}`);
    return ["enregistreur", "approbation", "console", "pont-fichiers"].every((s) => etats.find((e) => e.Service === s)?.Health === "healthy");
  }, 300000, "services healthy", 3000).catch(async (e) => {
    const l = await executer("docker", dcArgs(B, ["logs", "--tail", "60", "enregistreur"]), { cwd: B.dep, env: B.envDc });
    throw new Error(`${e.message}\n${l.stdout.slice(-4000)}${l.stderr.slice(-4000)}`);
  });
  const etatService = await attendre(async () => {
    const j = await (await fetch("http://127.0.0.1:8601/v0/etat")).json();
    return j.ready === true && j.set_read_at ? j : null;
  }, 180000, "service d'approbation : ready et set_read_at (IC-11, reporté)", 2000);
  ecrirePv(B, p, "IC-15-etat-service.json", `${JSON.stringify(etatService, null, 2)}\n`);
  const ready = await fetch("http://127.0.0.1:8500/readyz");
  verifier(p, "/readyz rend 200", ready.status === 200, ready.status);
  const lignes = lignesExploitation();
  const verrou = lignes.find((l) => l.event === "worm_lock_config_check");
  ecrirePv(B, p, "IC-15-worm-lock-config-check.json", `${JSON.stringify(verrou ?? null, null, 2)}\n`);
  verifier(p, "première ligne worm_lock_config_check conforme", verrou && (verrou.data?.conforme === true || verrou.data?.verdict === "conforme" || verrou.level === "info"), verrou);
  // L'agent (hôte cursor-postes) appelle un outil d'écriture : règle par défaut « revue ».
  const agent = await ouvrirSession({ url: `http://${B.ip}:8300/mcp`, jeton: B.jetons.hoteAgents });
  const liste = await agent.liste();
  const outils = (liste.result?.tools ?? []).map((t) => t.name);
  verifier(p, "l'outil fichiers__write_file est annoncé à l'agent", outils.includes("fichiers__write_file"), outils);
  const args = { path: "/srv/pieces/rapport-sinistre-2026-001.txt", content: "Rapport de sinistre 2026-001 (client fictif du banc).\n" };
  const r1 = await agent.appeler("fichiers__write_file", args);
  const signal = r1.result?._meta?.["noortrace/approval"];
  verifier(p, "appel retenu : signal en_attente et ticket", signal?.state === "en_attente" && signal.ticket, r1);
  B.ticket = signal.ticket;
  const retenue = await attendre(async () => (await lireEvenements(repertoireJournal(B))).find((e) => e.execution?.status === "retenue" && e.policy?.ticket === B.ticket), 30000, "événement retenue");
  B.requestHash = retenue.hash;
  for (const personne of [B.ap1, B.ap2]) {
    const v = await voter(personne, B.ticket, { decision: "approuve", motif: "Rapport conforme au dossier de sinistre" });
    verifier(p, `${personne.sujet} : vote_inscrit`, v.resultat === "vote_inscrit", v);
  }
  p.commandes.push({ commande: "console (Chromium) : approbateur-1 et approbateur-2 ouvrent /tickets/<ticket> et signent « approuve » (personal_sign du portefeuille d'essai)", code: 0, duree_ms: null });
  const decision = await attendre(async () => (await lireEvenements(repertoireJournal(B))).find((e) => e.execution?.tool === "noortrace.approbation.decision" && e.policy?.ticket === B.ticket), 60000, "décision scellée");
  verifier(p, "décision au seuil scellée (approuve, deux signatures)", decision.approval?.decision === "approuve" && decision.approval.approvers?.length === 2, decision.approval);
  const r2 = await agent.appeler("fichiers__write_file", args);
  verifier(p, "ré-émission relayée au pont (isError faux)", r2.result && r2.result.isError !== true, r2);
  const executee = await attendre(async () => (await lireEvenements(repertoireJournal(B))).find((e) => e.execution?.tool === "fichiers__write_file" && e.execution?.status === "executee" && e.approval?.ticket === B.ticket), 30000, "appel exécuté portant l'approbation");
  B.executee = { seq: executee.seq, ts: executee.ts, hash: executee.hash };
  verifier(p, "fichier écrit par le pont dans /srv/noortrace-outils/fichiers", fs.existsSync("/srv/noortrace-outils/fichiers/rapport-sinistre-2026-001.txt"));
  ecrirePv(B, p, "IC-15-appel.json", `${JSON.stringify({ ticket: B.ticket, request_hash: B.requestHash, executee: B.executee, decision: { seq: decision.seq, approvers: decision.approval.approvers } }, null, 2)}\n`);
}

/** Attente de la clôture de l'heure, de l'inclusion de l'ancre et du jeton (IC-15) ; demande de clôture au seuil déposée ; `period_submitted`. */
async function attenteCloture(B, p) {
  const debutPeriode = Math.floor(Date.parse(B.executee.ts) / 3600000) * 3600;
  B.periodStart = debutPeriode;
  p.verifications.push({ quoi: "période de l'appel", ok: true, detail: { period_start: iso(debutPeriode * 1000), fin_attendue: iso((debutPeriode + 3600) * 1000) } });
  const ferme = await attendre(() => lignesExploitation().find((l) => l.event === "period_closed" && l.data?.period_start === debutPeriode), 3 * 3600000, "period_closed", 5000);
  const periodHash = ferme.data.period_hash;
  await attendre(() => lignesExploitation().find((l) => l.event === "period_timestamped" && l.data?.request_id === `jeton_periode:${periodHash}`), 1800000, "jeton RFC 3161 de la période", 5000);
  await attendre(() => lignesExploitation().find((l) => l.event === "period_close_delegated" && l.data?.period_start === debutPeriode), 1800000, "ancre de la période incluse (period_close_delegated)", 5000);
  // Demande de clôture (CT-4 §7.7, operation « cloture ») signée au seuil par les approbateurs 1 et 2, déposée dans le répertoire du registre du journal.
  const manifeste = JSON.parse(fs.readFileSync(path.join(repertoireJournal(B), "manifestes", `periode-${debutPeriode}.json`), "utf8"));
  if (N.hacherManifeste(manifeste) !== periodHash) throw new Error("manifeste de la période : hachage différent de period_closed");
  const { demandeClotureParcours } = await import("../../test/fixtures/enregistreur-ancrage/outils.mjs");
  const demande = demandeClotureParcours({ manifeste, parcours: { contrats: B.client.contrats, approbateurs: B.client.approbateurs, seuil: 2, inscription: B.demandeInscription }, preparedAt: iso() });
  const f = path.join(repertoireJournal(B), "registre", `demande-cloture-${periodHash}.json`);
  fs.writeFileSync(f, `${JSON.stringify(demande, null, 2)}\n`, { mode: 0o600 });
  fs.chownSync(f, 10001, 10001);
  p.commandes.push({ commande: "demande de clôture signée par les approbateurs 1 et 2, déposée sous <journal>/registre/demande-cloture-<period_hash>.json (compte 10001, 0600)", code: 0, duree_ms: null });
  await attendre(() => lignesExploitation().find((l) => l.event === "period_submitted" && l.data?.period_start === debutPeriode), 1800000, "period_submitted", 5000);
  B.periodHash = periodHash;
}

function fichierAncres(B) {
  // Statut qualifié d'IC-13 (objet `qualified` d'ancrage-v0, liste de confiance) traduit dans la forme `qualification` d'ancres-confiance-v0.
  const autorite = (s) => ({
    name: `AC ${s.nom} (banc)`, certificate: s.init.acPem, intermediates: [], accepted_policies: [s.prestataire.policy_oid],
    qualified: { framework: s.prestataire.qualified.framework, valid_from: s.prestataire.qualified.trusted_list.issue_date, valid_to: null, source: `liste de confiance ${s.prestataire.qualified.trusted_list.territory}, séquence ${s.prestataire.qualified.trusted_list.sequence_number} (statut déclaratif d'exemple du banc, IC-13)` },
    source: `prestataire ${s.nom} du banc client fictif, établi à IC-13`,
  });
  const crls = [B.sub.principal, B.sub.secours].map((s) => crlVersPem(publierCrl({ repertoire: s.repertoire, horloge: { murale: () => Date.now() }, revoques: [] }).octets));
  return {
    version: 0,
    label: `Ancres du premier dossier (IC-15) de ${B.org}`,
    prepared_by: "exploitant du banc client fictif",
    prepared_at: iso(),
    tsa_authorities: [autorite(B.sub.principal), autorite(B.sub.secours)],
    revocation: { crls, statements: [] },
    bitcoin: null,
    registry: {
      chain_id: CHAIN_BFT,
      contracts: B.client.contrats,
      validator_sets: [{ from_height: 1, to_height: null, validators: B.client.validators, source: "validators.json du réseau de développement 2124, lu à IC-13" }],
      source: "registre du réseau de développement 2124, lu à IC-13",
    },
    recorders: [{ org_id: B.orgId, journal_id: B.journalId, key_id: KEY_ID, public_key: N.octetsVersHex(B.cles.clePublique), chain_key: B.cles.chaine.adresse, source: "clé d'enregistreur et clé de chaîne inscrites au registre à IC-13" }],
  };
}

/** IC-15, seconde partie : export du dossier de l'appel approuvé et vérification. */
async function ic15b(B, p) {
  const ex = await dc(B, p, ["exec", "-T", "enregistreur", "noortrace-ctl", "dossier", "exporter", "--ticket", B.ticket, "--vers", "/var/lib/noortrace-exports/ic-15"], { codes: [0, 1, 2, 4] });
  ecrirePv(B, p, "IC-15-export.txt", `code ${ex.code}\n${ex.stdout}${ex.stderr}`);
  verifier(p, "export : code 0 et ligne dossier_exported", ex.code === 0 && ex.stdout.includes("dossier_exported"), ex.stdout + ex.stderr);
  const ancres = fichierAncres(B);
  const fa = path.join(B.travail, "poste", "ancres-ic15.json");
  fs.writeFileSync(fa, `${JSON.stringify(ancres, null, 2)}\n`);
  const exportsVol = volume("exports");
  await cmd(p, `sudo install -o 10001 -g 10005 -m 0640 ancres.json "$(docker volume inspect -f '{{ .Mountpoint }}' noortrace_exports)/ancres-ic15.json"`, "install", ["-o", "10001", "-g", "10005", "-m", "0640", fa, path.join(exportsVol, "ancres-ic15.json")]);
  const dossier = path.join(exportsVol, "ic-15");
  const entetes = fs.existsSync(path.join(dossier, "entetes-bitcoin.json")) ? ["--entetes-bitcoin", "/var/lib/noortrace-exports/ic-15/entetes-bitcoin.json"] : [];
  const vc = await dc(B, p, ["--profile", "outils", "run", "--rm", "verificateur", "/var/lib/noortrace-exports/ic-15", "--ancres", "/var/lib/noortrace-exports/ancres-ic15.json", ...entetes, "--exiger", "7", "--json"], { codes: [0, 1, 2, 3] });
  const sortie = path.join(B.bancDir, "verificateurs");
  fs.mkdirSync(sortie, { recursive: true });
  fs.writeFileSync(path.join(sortie, "verificateur-conteneur.json"), vc.stdout);
  ecrirePv(B, p, "IC-15-verificateur.json", vc.stdout);
  const rc = JSON.parse(vc.stdout);
  const ctl = (rap) => Object.fromEntries(rap.controls.map((x) => [x.number, x.status]));
  verifier(p, "vérificateur (image noortrace/verificateur, --exiger 7) : valide, code 0, contrôles 4 et 8 réussis", vc.code === 0 && rc.verdict === "valide" && ctl(rc)[4] === "reussi" && ctl(rc)[8] === "reussi" && ctl(rc)[7] === "reussi", { code: vc.code, verdict: rc.verdict, controles: ctl(rc) });
  // Copie du dossier hors du volume, puis les deux vérificateurs de l'hôte.
  B.dossierCopie = path.join(B.bancDir, "dossier-ic15");
  fs.cpSync(dossier, B.dossierCopie, { recursive: true });
  fs.copyFileSync(fa, path.join(B.bancDir, "ancres-ic15.json"));
  const go = await cmd(p, "noortrace-verifier <dossier> --ancres ancres-ic15.json --exiger 7 --json", process.env.NOORTRACE_VERIFIER_BIN, [B.dossierCopie, "--ancres", fa, "--exiger", "7", "--json"], { codes: [0, 1, 2, 3] });
  fs.writeFileSync(path.join(sortie, "noortrace-verifier.json"), go.stdout);
  fs.writeFileSync(path.join(sortie, "noortrace-verifier.code"), `${go.code}\n`);
  const js = await cmd(p, "npm run verify:dossier -- <dossier> --ancres ancres-ic15.json --exiger 7 --json", "npm", ["run", "-s", "verify:dossier", "--", B.dossierCopie, "--ancres", fa, "--exiger", "7", "--json"], { cwd: RACINE, codes: [0, 1, 2, 3] });
  fs.writeFileSync(path.join(sortie, "verify-dossier.json"), js.stdout);
  fs.writeFileSync(path.join(sortie, "verify-dossier.code"), `${js.code}\n`);
  for (const [nom, r] of [["noortrace-verifier", go], ["npm run verify:dossier", js]]) {
    const rap = JSON.parse(r.stdout);
    verifier(p, `${nom} --exiger 7 : code 0, valide, contrôles 4, 7 et 8 réussis`, r.code === 0 && rap.verdict === "valide" && ctl(rap)[4] === "reussi" && ctl(rap)[7] === "reussi" && ctl(rap)[8] === "reussi", { code: r.code, verdict: rap.verdict, controles: ctl(rap) });
  }
  // TM-29 (relevé, sans la charge de TM-3) : consommation des services en marche.
  const stats = spawnSync("docker", ["stats", "--no-stream", "--format", "{{json .}}"], { encoding: "utf8" }).stdout.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)).filter((x) => x.Name.startsWith("noortrace-"));
  const du = Object.fromEntries(["journal", "exploitation", "exports", "approbation-etat"].map((v) => [v, Number(spawnSync("du", ["-sb", volume(v)], { encoding: "utf8" }).stdout.split("\t")[0])]));
  B.consommation = { at: iso(), load_avg: os.loadavg(), services: stats.map((x) => ({ nom: x.Name, cpu: x.CPUPerc, memoire: x.MemUsage })), volumes_octets: du };
  fs.writeFileSync(path.join(B.bancDir, "consommation.json"), `${JSON.stringify(B.consommation, null, 2)}\n`);
  const liste = spawnSync("bash", ["-c", "find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum"], { cwd: B.dossierCopie, encoding: "utf8" }).stdout;
  fs.writeFileSync(path.join(B.bancDir, "dossier-ic15.sha256"), liste);
  B.dossierSha256 = sha256(liste);
}

async function ic16(B, p) {
  const exploitation = path.join(B.travail, "hote", "exploitation");
  const env = {
    ...sansMandataire(), NOORTRACE_IP_INTERNE: B.ip, NOORCORE_CHAIN_ID: CHAIN_BFT, NOORCORE_EVM_CHAIN_ID: "2124", NOORCORE_LEADER_RPC: B.envDc.NOORCORE_LEADER_RPC, NOORTRACE_RACINE: B.racine, NOORTRACE_EXPLOITATION: exploitation, NOORTRACE_INSTANCE: "enregistreur-banc-1",
    NOORTRACE_STOCKAGE: "/var/lib/docker", NOORTRACE_DIMENSIONNEMENT: B.dimensionnement, SSL_CERT_FILE: B.autoriteFichier,
  };
  const res = {};
  for (const t of ["TP-6", "TP-8"]) {
    const r = await executer("bash", [path.join(B.racine, "deploiement", "taches", "executer-tache.sh"), t], { cwd: B.racine, env });
    p.commandes.push({ commande: `deploiement/taches/executer-tache.sh ${t}`, code: r.code, duree_ms: r.duree_ms });
    res[t] = { code: r.code, sortie: (r.stdout + r.stderr).slice(-1500) };
  }
  ecrirePv(B, p, "IC-16-taches.json", `${JSON.stringify(res, null, 2)}\n`);
  const journalTaches = path.join(exploitation, "taches", "taches.ndjson");
  if (fs.existsSync(journalTaches)) ecrirePv(B, p, "IC-16-journal-taches.ndjson", fs.readFileSync(journalTaches));
  if (res["TP-6"].code !== 0) ecart(p, `TP-6 : code ${res["TP-6"].code}`);
  if (res["TP-8"].code !== 0) ecart(p, `TP-8 (contrôle préalable rejoué, services en marche) : code ${res["TP-8"].code} — ${res["TP-8"].sortie.split("\n").slice(-3).join(" ")}`);
  ecart(p, "Minuteurs systemd non posés (poser-taches.sh) : l'environnement de construction n'a pas systemd ; TP-1 sans objet (support en mode conformité), TP-2, TP-3, TP-5 commandes du client, TP-4 sans gel posé, TP-7 annuel : non exécutées");
  const rg = await cmd(p, "node scripts/deploiement/regles.mjs --configuration config/production/configuration.json --ancrage config/production/ancrage.json > IC-16-regles.yml", process.execPath, [path.join(RACINE, "scripts", "deploiement", "regles.mjs"), "--configuration", B.configuration, "--ancrage", B.ancrage], { codes: [0, 1, 2] });
  ecrirePv(B, p, "IC-16-regles.yml", rg.stdout);
  if (rg.code !== 0) ecart(p, `regles.mjs : code ${rg.code} ${rg.stderr.slice(-300)}`);
  ecart(p, "Aucune supervision branchée (D-5 : fichiers de référence seulement) ; sauvegarde (SAUVEGARDE) non posée");
}

async function ic17(B, p) {
  const dir = path.join(B.travail, "poste", "attestation");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const gab = await cmd(p, "npm run conformite:attestation -- gabarit", process.execPath, [path.join(RACINE, "scripts", "conformite", "attestation.mjs"), "gabarit"]);
  const a = JSON.parse(gab.stdout);
  const maintenant = Date.now();
  a.org = { org_id: B.orgId, slug: B.org, name: "Organisation exemple (client fictif du banc)" };
  a.journals = [{ journal_id: B.journalId, name: NOM_JOURNAL }];
  a.validity = { from: iso(maintenant - 3600000), until: iso(maintenant + 180 * 86400000) };
  a.issued_at = iso(maintenant);
  a.prepared_by = { identity: B.identite("admin-1"), function: "administrateur du client fictif" };
  a.agents = [{ agent_id: "agent-poste-1", journal_id: B.journalId, host: "poste-banc", framework: "client MCP (agent de test du banc)", capture_channels: ["mandataire_mcp"], notes: null }];
  a.tools_via_proxy_only = [{ server_alias: "fichiers", tools: ["*"], enforcement: "réseau outils interne de production.yaml : le pont n'est joignable que par l'enregistreur" }];
  a.egress = { default_policy: "refus_par_defaut", rules_sha256: `0x${B.reglesSha256}`, rules_format: "règles du banc (résolution des noms)", summary: "Seuls les noms des substituts du banc sont résolus ; aucune autre sortie.", allowed_destinations: [{ name: "registre, horodatage, KMS, S3", via: "enregistreur", description: "substituts du banc" }] };
  a.gateway_credentials = [];
  a.not_captured = [];
  a.signatories = [1, 2].map((i) => ({ name: `Approbateur ${i}`, function: "approbateur", address: compte(i).adresse }));
  const fa = path.join(dir, "attestation.json");
  fs.writeFileSync(fa, `${JSON.stringify(a, null, 2)}\n`);
  await cmd(p, "npm run conformite:attestation -- condenser attestation.json", process.execPath, [path.join(RACINE, "scripts", "conformite", "attestation.mjs"), "condenser", fa]);
  const sigs = [];
  for (const i of [1, 2]) {
    const cle = path.join(dir, `cle-${i}.hex`);
    fs.writeFileSync(cle, `${N.octetsVersHex(compte(i).cle)}\n`, { mode: 0o600 });
    const s = await cmd(p, `npm run conformite:attestation -- signer attestation.json --cle fichier:<clé de l'approbateur ${i}> --oui`, process.execPath, [path.join(RACINE, "scripts", "conformite", "attestation.mjs"), "signer", fa, "--cle", `fichier:${cle}`, "--oui"]);
    fs.rmSync(cle);
    const fs1 = path.join(dir, `signature-${i}.json`);
    // La commande imprime l'attestation lisible, puis la signature en JSON (dernier objet de la sortie).
    fs.writeFileSync(fs1, s.stdout.slice(s.stdout.lastIndexOf("\n{") + 1));
    sigs.push(fs1);
  }
  const as = await cmd(p, "npm run conformite:attestation -- assembler attestation.json signature-1.json signature-2.json", process.execPath, [path.join(RACINE, "scripts", "conformite", "attestation.mjs"), "assembler", fa, ...sigs]);
  const signee = path.join(dir, "attestation-signee.json");
  fs.writeFileSync(signee, as.stdout);
  const jeu = path.join(dir, "jeu.json");
  fs.writeFileSync(jeu, `${JSON.stringify({ threshold: { required: 2, size: 3 }, members: B.client.membres, source: "jeu d'approbateurs de l'organisation, lu au registre (paquet client)" }, null, 2)}\n`);
  const v = await cmd(p, "npm run conformite:attestation -- verifier attestation-signee.json --jeu jeu.json", process.execPath, [path.join(RACINE, "scripts", "conformite", "attestation.mjs"), "verifier", signee, "--jeu", jeu], { codes: [0, 1, 2] });
  ecrirePv(B, p, "IC-17-attestation-signee.json", fs.readFileSync(signee));
  ecrirePv(B, p, "IC-17-verification.txt", `code ${v.code}\n${v.stdout}${v.stderr}`);
  verifier(p, "conformite:attestation verifier rend 0 (AT-1 à AT-4)", v.code === 0, v.stdout + v.stderr);
  ecart(p, "Attestation non inscrite au journal : policy.perimeter (PA-8) n'existe pas dans le schéma de configuration ; AT-6 non exécutable");
}

async function ic18(B, p) {
  ecrirePv(B, p, "IC-18-fermeture.txt", "FL-29 (registre de conteneurs), FL-30 (archive) et FL-31 (paquets du système) : jamais ouverts sur le banc (aucun réseau public) ; rien à fermer.\n");
  await cmd(p, 'cd "$PV" && find . -type f ! -name IC-18-liste.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > IC-18-liste.sha256', "bash", ["-c", "find . -type f ! -name IC-18-liste.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > IC-18-liste.sha256"], { cwd: B.pv });
  const c = await cmd(p, "sha256sum --strict -c IC-18-liste.sha256", "sha256sum", ["--strict", "-c", "IC-18-liste.sha256", "--quiet"], { cwd: B.pv });
  verifier(p, "sha256sum --strict -c IC-18-liste.sha256 rend 0", c.code === 0);
  B.pvSha256 = sha256Fichier(path.join(B.pv, "IC-18-liste.sha256"));
}

// ---------------------------------------------------------------- mesures (CT-9 §11.3)

function systeme() {
  const lire = (f) => {
    try {
      return fs.readFileSync(f, "utf8");
    } catch {
      return "";
    }
  };
  const osr = Object.fromEntries(lire("/etc/os-release").split("\n").filter((l) => l.includes("=")).map((l) => [l.split("=")[0], l.split("=").slice(1).join("=").replace(/^"|"$/g, "")]));
  const go = spawnSync("go", ["version"], { encoding: "utf8" });
  const py = spawnSync("python3", ["--version"], { encoding: "utf8" });
  const aslr = lire("/proc/sys/kernel/randomize_va_space").trim();
  return {
    reference: false,
    cpu: os.cpus()[0]?.model ?? "inconnu",
    cores: os.availableParallelism(),
    memory_bytes: os.totalmem(),
    disk: { type: "virtuel", fsync: true },
    os: osr.PRETTY_NAME ?? os.type(),
    kernel: os.release(),
    node: process.version,
    go: go.status === 0 ? go.stdout.trim() : null,
    python: py.status === 0 ? py.stdout.trim() : null,
    cpu_scaling: "inconnu",
    aslr: aslr === "0" ? "inactif" : aslr ? "actif" : "inconnu",
    load_avg_1m: os.loadavg()[0],
    virtualized: true,
  };
}

function mesures(B, pvb) {
  const ligne = (name, test_id, unit, value, target, conditions) => ({
    name, test_id, unit, n: value === null ? null : 1, value, p50: null, p95: null, p99: null, min: null, max: null, mean: null, text_value: null,
    target, met: null, conditions, excluded_reason: "hors_systeme_de_reference",
  });
  const cond = ["banc client fictif de l'étape 7 : environnement de construction, substituts locaux de l'inventaire §2.3", "harnais automatique (aucun ingénieur extérieur ; D-7)", "horloge murale, une exécution"];
  const res = [];
  for (const id of Object.keys(BUDGETS_IC)) {
    const p = pvb.pas.find((x) => x.id === id);
    res.push(ligne(id.toLowerCase().replace("-", "_"), "TM-22", "min", p?.duree_s != null ? Math.round(p.duree_s / 0.06) / 1000 : null, BUDGETS_IC[id], cond));
  }
  const attente = pvb.pas.find((x) => x.id === "IC-15 (attente)");
  res.push(ligne("ic_attente_cloture", "TM-22", "min", attente ? Math.round(attente.duree_s / 0.06) / 1000 : null, null, [...cond, "attente réelle de la clôture de l'heure, de l'inclusion de l'ancre et du jeton (IC-16 et IC-17 faits pendant l'attente)"]));
  res.push(ligne("ic_total", "TM-22", "min", B.totalMin ?? null, 480, [...cond, "du premier instant d'IC-1 au dernier d'IC-18, attente comprise"]));
  return {
    version: 0, kind: "rapport-mesure", date: iso().slice(0, 10), measured_at: iso(B.debutIc), commit: spawnSync("git", ["rev-parse", "HEAD"], { cwd: RACINE, encoding: "utf8" }).stdout.trim() || "0".repeat(40),
    spec_version: "0.8", system: systeme(),
    method: { warmup: 0, repetitions: 1, percentile_method: "plus_proche_rang", clock: "murale", pair_with_without: false, samples_published: false },
    configuration_sha256: B.configuration && fs.existsSync(B.configuration) ? `0x${sha256Fichier(B.configuration)}` : null,
    counts_for_targets: false, results: res,
    notes: "Mesure du banc client fictif hors du système de référence (CT-9 EX-11.2) : publiée, ne compte pas pour les cibles. Arbre de travail non commité (commit de base indiqué).",
  };
}

// ---------------------------------------------------------------- nettoyage

async function nettoyer(B, ctx, { pile = true } = {}) {
  for (const x of ctx.personnes) await x.fermer().catch(() => {});
  if (ctx.navigateur) await ctx.navigateur.close().catch(() => {});
  if (pile && B.dep && fs.existsSync(path.join(B.dep, "compose"))) {
    // Le compagnon des attributs pose « a » et « i » sur le journal : retirés avant la suppression du volume.
    await executer("docker", dcArgs(B, ["--profile", "outils", "--profile", "relais", "stop"]), { cwd: B.dep, env: B.envDc });
    const j = spawnSync("docker", ["volume", "inspect", "-f", "{{ .Mountpoint }}", "noortrace_journal"], { encoding: "utf8" });
    if (j.status === 0) await executer("chattr", ["-R", "-i", "-a", j.stdout.trim()]);
    await executer("docker", dcArgs(B, ["--profile", "outils", "--profile", "relais", "down", "-v", "--remove-orphans"]), { cwd: B.dep, env: B.envDc });
  }
  for (const s of Object.values(B.sub ?? {})) await s?.fermer?.().catch(() => {});
  if (B.hotesModifies) {
    const t = fs.readFileSync("/etc/hosts", "utf8");
    const debut = t.indexOf(`\n${MARQUE_HOTES}\n`);
    const fin = t.indexOf(`${MARQUE_HOTES} (fin)\n`);
    if (debut >= 0 && fin > debut) fs.writeFileSync("/etc/hosts", t.slice(0, debut) + t.slice(fin + `${MARQUE_HOTES} (fin)\n`.length));
  }
  if (B.srvCree && pile) fs.rmSync("/srv/noortrace-outils", { recursive: true, force: true });
  if (B.client?.baseAgent) fs.rmSync(B.client.baseAgent, { recursive: true, force: true });
}

// ---------------------------------------------------------------- principal

export async function principal(argv) {
  let o;
  try {
    o = parseArgs({ args: argv, strict: true, options: { travail: { type: "string" }, "ip-interne": { type: "string" }, org: { type: "string" }, images: { type: "string" }, "arreter-apres": { type: "string" }, garder: { type: "boolean" }, condenses: { type: "string" } } }).values;
    if (!o.travail) throw new Error("--travail requis");
    if (fs.existsSync(o.travail)) throw new Error(`${o.travail} existe déjà`);
  } catch (e) {
    process.stderr.write(`Erreur : ${e.message}\n${USAGE}\n`);
    return 2;
  }
  const ip = o["ip-interne"] ?? adresseInterneParDefaut();
  const manque = await conditionsBanc({ ipInterne: ip });
  if (manque.length) {
    process.stderr.write(`Conditions du banc absentes :\n- ${manque.join("\n- ")}\n`);
    return 3;
  }
  if (libre("/var/lib/docker") < 1.2e9) {
    process.stderr.write(`Espace libre insuffisant sous /var/lib/docker (${Math.round(libre("/var/lib/docker") / 1e6)} Mo, 1 200 Mo au moins)\n`);
    return 3;
  }
  const travail = path.resolve(o.travail);
  fs.mkdirSync(travail, { recursive: true, mode: 0o700 });
  const B = {
    travail, ip, org: o.org ?? "organisation-exemple",
    racine: path.join(travail, "hote", "noortrace"),
    pv: path.join(travail, "pv"),
    bancDir: path.join(travail, "banc"),
    surcharge: path.join(travail, "hote", "banc-surcharge.yaml"),
    imagesTar: o.images ?? null,
    condensesFichier: o.condenses ?? (o.images ? path.join(path.dirname(o.images), "condenses.json") : null),
    opsLog: { rotate: 4194304, garder: 4 },
    sub: {},
  };
  if (!B.condensesFichier || !fs.existsSync(B.condensesFichier)) {
    process.stderr.write("Erreur : relevé des condensés (condenses.json de la construction double) introuvable : --images <archive> à côté de condenses.json, ou --condenses <fichier>\n");
    return 2;
  }
  B.dep = path.join(B.racine, "deploiement");
  B.envDc = { ...process.env, NOORTRACE_IP_INTERNE: ip, NOORCORE_CHAIN_ID: CHAIN_BFT, NOORCORE_EVM_CHAIN_ID: "2124", NOORCORE_LEADER_RPC: `https://${NOMS.rpc}:${PORTS.rpc}` };
  fs.mkdirSync(B.bancDir, { recursive: true });
  fs.mkdirSync(path.join(travail, "hote"), { recursive: true });
  const pvb = new ProcesVerbalBanc(B.bancDir);
  const ctx = {
    personnes: [],
    navigateur: null,
    async chromium() {
      if (!this.navigateur) this.navigateur = await createRequire(import.meta.url)("playwright").chromium.launch({ args: [`--host-resolver-rules=MAP *.example ${ip}`], env: sansMandataire() });
      return this.navigateur;
    },
  };
  let code = 0;
  const arret = o["arreter-apres"] ?? null;
  const disque = { avant: libre("/var/lib/docker") };
  try {
    await prealables(B, pvb);
    surchargeBanc(B);
    B.debutIc = Date.now();
    const pas = [
      ["IC-1", "Ouvrir le procès-verbal ; fixer la topologie ; dimensionner", ic1],
      ["IC-2", "Préparer l'hôte (simulation sur l'environnement de construction)", ic2],
      ["IC-3", "Pare-feu et DNS (règles du banc) ; exporter les règles", ic3],
      ["IC-4", "Obtenir et vérifier l'archive", ic4],
      ["IC-5", "Contrôle préalable du système", ic5],
      ["IC-6", "Épingler les images par condensé", ic6],
      ["IC-7", "Cérémonie des clés CLE-1 et CLE-2", ic7],
      ["IC-8", "Secrets de service", ic8],
      ["IC-9", "Support WORM", ic9],
      ["IC-10", "Bail et volume", ic10],
      ["IC-11", "Service d'approbation et console", (b, p) => ic11(b, p, ctx)],
      ["IC-12", "Raccords de capture", ic12],
      ["IC-13", "Ancrage et registre", ic13],
      ["IC-14", "Configuration et contrôle préalable final", ic14],
    ];
    let stop = false;
    for (const [id, objet, fn] of pas) {
      await pvb.executer(id, objet, { budget: BUDGETS_IC[id] }, (p) => fn(B, p));
      if (disque.min === undefined || libre("/var/lib/docker") < disque.min) disque.min = libre("/var/lib/docker");
      if (libre("/var/lib/docker") < 1e9) throw new Error(`espace libre sous 1 Go (${Math.round(libre("/var/lib/docker") / 1e6)} Mo) : arrêt du banc`);
      if (arret === id) {
        stop = true;
        break;
      }
    }
    if (!stop) {
      const a = await pvb.executer("IC-15", "Démarrage, appel soumis à approbation, décision signée par la console (première partie)", { budget: BUDGETS_IC["IC-15"] }, (p) => ic15a(B, p));
      const attente = pvb.executer("IC-15 (attente)", "Attente de la clôture de l'heure, de l'inclusion de l'ancre et du jeton RFC 3161 ; demande de clôture au seuil", { compte: false }, (p) => attenteCloture(B, p));
      attente.catch(() => {});
      await pvb.executer("IC-16", "Tâches planifiées, supervision, sauvegarde (pendant l'attente)", { budget: BUDGETS_IC["IC-16"] }, (p) => ic16(B, p));
      await pvb.executer("IC-17", "Attestation de périmètre (pendant l'attente)", { budget: BUDGETS_IC["IC-17"] }, (p) => ic17(B, p));
      await attente;
      const b = await pvb.executer("IC-15 (fin)", "Export du premier dossier et vérification", { compte: false }, (p) => ic15b(B, p));
      // Durée d'IC-15 : travail de l'exploitant (première partie et fin), sans l'attente (CT-8 IC-15).
      a.duree_s = Math.round((a.duree_s + b.duree_s) * 10) / 10;
      a.fin = b.fin;
      a.parties = ["IC-15", "IC-15 (fin)"];
      await pvb.executer("IC-18", "Clore le procès-verbal", { budget: BUDGETS_IC["IC-18"] }, (p) => ic18(B, p));
      B.totalMin = Math.round((Date.now() - B.debutIc) / 60) / 1000;
    }
  } catch (e) {
    code = 1;
    process.stderr.write(`Banc arrêté : ${e.message}\n`);
  } finally {
    const m = mesures(B, pvb);
    fs.writeFileSync(path.join(B.bancDir, "mesures.json"), `${JSON.stringify(m, null, 2)}\n`);
    disque.apres_installation = libre("/var/lib/docker");
    pvb.ecrire({
      organisation: { slug: B.org, org_id: B.orgId ?? null, journal_id: B.journalId ?? null }, ip_interne: ip,
      debut_ic: B.debutIc ? iso(B.debutIc) : null, total_min: B.totalMin ?? null, dossier_sha256: B.dossierSha256 ?? null, pv_liste_sha256: B.pvSha256 ?? null,
      ticket: B.ticket ?? null, executee: B.executee ?? null, period_start: B.periodStart ?? null, period_hash: B.periodHash ?? null,
      systeme: systeme(), disque,
    });
    await nettoyer(B, ctx, { pile: !o.garder });
  }
  process.stdout.write(`${JSON.stringify({ code, total_min: B.totalMin ?? null, dossier_sha256: B.dossierSha256 ?? null, proces_verbal: pvb.fichier, mesures: path.join(B.bancDir, "mesures.json") })}\n`);
  return code;
}

if (process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href) {
  principal(process.argv.slice(2)).then((c) => process.exit(c), (e) => {
    process.stderr.write(`${e.stack ?? e}\n`);
    process.exit(1);
  });
}
