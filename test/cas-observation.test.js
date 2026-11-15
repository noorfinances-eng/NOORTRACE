// Mode observation de bout en bout sur l'installation rapide (CT-9 TE-10 ;
// CT-8 §7, §12 ; CT-2 EX-14.13 à EX-14.17 ; CT-3 EX-11.11 à EX-11.15), avec
// Docker : l'installation rapide de CT-8 (`deploiement/compose/rapide.yaml`
// du dépôt, pas IR-2 à IR-6 rejoués comme à l'étape 7 : secrets, autorité du
// serveur RFC 3161 interne, configuration de référence en mode observation,
// réseaux rendus internes, serveur d'outils factice des essais sur le réseau
// interne), puis :
//
//   1. un agent (client MCP minimal dans l'espace réseau de l'enregistreur)
//      joue des appels : tous relayés, aucun signal d'approbation, chaque
//      événement porte la marque d'observation (EX-12.6) ;
//   2. le service d'approbation est coupé pendant des appels : relayés sans
//      retard d'une décision, marque « inconnu », `approval_service_unavailable`
//      (EX-14.15) ;
//   3. le stockage est coupé pendant des appels (attribut immuable posé sur le
//      segment courant : l'écriture suivante échoue, CT-2 EX-12.8) : appels
//      relayés, événement en attente, puis, la borne `pending_max_ms` passée,
//      appel perdu et compté (`event_lost`, `noortrace_events_lost_total`,
//      EX-12.3, EX-12.14) ; stockage rendu : reprise, `pending_flushed` ;
//   4. rapport d'observation (`rapport-observation.mjs`, EX-12.10) égal au
//      recompte fait ici depuis les événements ;
//   5. passage au mode bloquant (12.6, pas 3 à 5) : configuration récrite en
//      place, validée dans le conteneur, `noortrace-ctl reload`, événement de
//      politique, `noortrace_observation_mode` à 0, appel de test retenu avec
//      le signal d'approbation ; le retour à l'observation est refusé tant que
//      la retenue n'a pas de décision (`tickets_ouverts`, EX-12.13).
//
// Banc : `policy.failure.pending_max_ms` est abaissé à 15 000 ms dans la
// configuration de l'installation (300 000 par défaut), pour que la perte se
// produise pendant l'essai ; rien d'autre ne change par rapport à IR-3, hors
// l'autorité TLS du serveur d'outils factice. En attente, condition nommée,
// sans démon Docker, sans les images, sans openssl ou sans chattr. Aucun essai
// ne joint un réseau public.

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { RACINE, docker, enAttente, pause } from "./fixtures/demonstration/outils.mjs";
import { attendre } from "./fixtures/cas/outils.mjs";

const VERSION = "0.1.0";
const IMAGES = ["enregistreur", "approbation", "tsa-interne"].map((n) => `noortrace/${n}:${VERSION}`);
const CLIENT = path.join(RACINE, "test", "fixtures", "cas", "client-mcp.mjs");
const OUTIL = "outils__read_file";
const PENDING_MAX_MS = 15000;
const MARQUE = / \[observation (autorise|a_approuver|refuse|inconnu)\]$/;

function etat() {
  const info = docker(["info", "--format", "{{.ServerVersion}}"], { timeout: 20000 });
  if (info.status !== 0) return { ok: false, condition: "démon Docker injoignable (docker info)" };
  const manquantes = IMAGES.filter((i) => docker(["image", "inspect", "--format", "{{.Id}}", i], { timeout: 20000 }).status !== 0);
  if (manquantes.length) return { ok: false, condition: `image(s) absente(s) du magasin local : ${manquantes.join(", ")} (node scripts/deploiement/construire-images.mjs)` };
  if (spawnSync("openssl", ["version"], { stdio: "pipe" }).status !== 0) return { ok: false, condition: "openssl absent (certificats du serveur d'outils factice)" };
  if (spawnSync("chattr", ["-V"], { stdio: "pipe" }).status !== 0 && !fs.existsSync("/usr/bin/chattr")) return { ok: false, condition: "chattr absent (coupure du stockage par l'attribut immuable)" };
  if ((process.getuid?.() ?? 1) !== 0) return { ok: false, condition: "essai hors du compte root : l'attribut immuable et la réécriture de la configuration possédée par le compte 10001 exigent root sur l'hôte" };
  return { ok: true };
}

describe("CT-9 TE-10 : mode observation de bout en bout sur l'installation rapide (CT-8 §7, §12) : capture sans blocage, service d'approbation puis stockage coupés pendant des appels, rapport d'observation, passage au mode bloquant", function () {
  this.timeout(1500000);
  const s = { attente: null, nettoyage: [] };

  const dc = (args, o = {}) => docker(["compose", ...s.projet, ...args], { timeout: o.timeout ?? 300000 });
  const dcOk = (args, o) => {
    const r = dc(args, o);
    if (r.status !== 0) throw new Error(`docker compose ${args.join(" ")} : code ${r.status} : ${r.stderr}`);
    return r.stdout;
  };
  const exec = (svc, args) => dc(["exec", "-T", svc, ...args]);
  /** Programme Node.js dans l'espace réseau de l'enregistreur (image de l'enregistreur, compte sans privilège). */
  const noeud = (args, montages = []) => {
    const r = docker(["run", "--rm", "--network", `container:${s.idEnregistreur}`, "--user", "65534:65534", ...montages.flatMap(([a, b]) => ["-v", `${a}:${b}:ro`]), "--entrypoint", "/usr/local/bin/node", `noortrace/enregistreur:${VERSION}`, ...args], { timeout: 120000 });
    if (r.status !== 0) throw new Error(`programme dans l'espace réseau de l'enregistreur : code ${r.status} : ${r.stderr}`);
    return r.stdout;
  };
  /** Appels d'outil de l'agent : une ligne JSON par appel. */
  const appeler = (appels, pauseMs = 0) => noeud(["/client/client-mcp.mjs", "http://127.0.0.1:8300/mcp", "/client/jeton-hote", JSON.stringify(appels), String(pauseMs)], [[CLIENT, "/client/client-mcp.mjs"], [path.join(s.T, "jeton-hote"), "/client/jeton-hote"]]).trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const metriques = () => noeud(["-e", 'fetch("http://127.0.0.1:8500/metrics").then((r) => r.text()).then((t) => process.stdout.write(t))']);
  const metrique = (texte, nom, etiquettes = "") => {
    const m = new RegExp(`^${nom}${etiquettes ? `\\{[^}]*${etiquettes}[^}]*\\}` : ""} ([0-9.e+]+)$`, "m").exec(texte);
    return m ? Number(m[1]) : null;
  };
  const journalOps = () => exec("enregistreur", ["/usr/local/bin/node", "-e", 'const fs=require("fs");for(const f of fs.readdirSync("/var/log/noortrace").filter((n)=>n.endsWith(".ndjson")))process.stdout.write(fs.readFileSync("/var/log/noortrace/"+f,"utf8"))']).stdout.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  /** Événements du journal (segments), lus dans le volume par un conteneur sans réseau. */
  const evenements = () => {
    const r = docker(["run", "--rm", "--network", "none", "--user", "0:0", "-v", `${s.volumeJournal}:/v:ro`, "--entrypoint", "/usr/local/bin/node", `noortrace/enregistreur:${VERSION}`, "-e", `const fs=require("fs");const d="/v/${s.repJournal}/segments";for(const f of fs.readdirSync(d).sort()){const l=fs.readFileSync(d+"/"+f,"utf8").split("\\n").filter(Boolean);for(const x of l.slice(1))console.log(x)}`]);
    if (r.status !== 0) throw new Error(`lecture des segments : ${r.stderr}`);
    return r.stdout.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  };
  const appelsOutil = (ev) => ev.filter((e) => e.execution?.tool === OUTIL);

  before(async function () {
    this.timeout(600000);
    const e = etat();
    if (!e.ok) {
      s.attente = e.condition;
      return;
    }
    const T = fs.mkdtempSync(path.join(process.env.NOORTRACE_TMP ?? os.tmpdir(), "noortrace-observation-"));
    s.T = T;
    fs.cpSync(path.join(RACINE, "deploiement", "compose"), path.join(T, "compose"), { recursive: true });
    fs.mkdirSync(path.join(T, "config", "rapide"), { recursive: true });
    // Serveur d'outils factice des essais de l'étape 7 (TLS, nom de la configuration de référence), sur le réseau interne.
    const outils = path.join(T, "outils");
    fs.mkdirSync(outils);
    for (const f of ["serveur-outils.mjs"]) fs.copyFileSync(path.join(RACINE, "test", "fixtures", "installation-rapide", f), path.join(outils, f));
    const ossl = (args) => {
      const r = spawnSync("openssl", args, { cwd: outils, encoding: "utf8" });
      if (r.status !== 0) throw new Error(`openssl ${args.join(" ")} : ${r.stderr}`);
    };
    ossl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.cle.pem", "-out", "ca.pem", "-days", "2", "-subj", "/CN=AC de l'essai du serveur d'outils"]);
    ossl(["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "cle.pem", "-out", "req.pem", "-subj", "/CN=outils.interne.example"]);
    fs.writeFileSync(path.join(outils, "ext.cnf"), "subjectAltName=DNS:outils.interne.example\nextendedKeyUsage=serverAuth\n");
    ossl(["x509", "-req", "-in", "req.pem", "-CA", "ca.pem", "-CAkey", "ca.cle.pem", "-CAcreateserial", "-out", "certificat.pem", "-days", "2", "-extfile", "ext.cnf"]);
    for (const f of fs.readdirSync(outils)) fs.chmodSync(path.join(outils, f), 0o444);
    fs.writeFileSync(path.join(T, "sans-sortie.yaml"), "networks:\n  hotes:\n    internal: true\n  sortie:\n    internal: true\n");
    fs.writeFileSync(path.join(T, "outils.yaml"), `services:\n  enregistreur:\n    volumes:\n      - type: bind\n        source: ${outils}/ca.pem\n        target: /etc/noortrace/outils-ca.pem\n        read_only: true\n  outils-factice:\n    image: noortrace/enregistreur:${VERSION}\n    entrypoint: ["/usr/local/bin/node", "/outils/serveur-outils.mjs", "/outils/cle.pem", "/outils/certificat.pem", "443"]\n    user: "65534:65534"\n    read_only: true\n    volumes:\n      - type: bind\n        source: ${outils}\n        target: /outils\n        read_only: true\n    networks:\n      sortie:\n        aliases:\n          - outils.interne.example\n`);
    s.nom = `noortrace-observation-${process.pid}`;
    s.projet = ["-p", s.nom, "--project-directory", T, "-f", path.join(T, "compose", "rapide.yaml"), "-f", path.join(T, "sans-sortie.yaml"), "-f", path.join(T, "outils.yaml")];
    // IR-2 : secrets, autorité du serveur interne.
    const secrets = path.join(T, "secrets");
    fs.mkdirSync(secrets, { mode: 0o700 });
    fs.writeFileSync(path.join(secrets, "cle-enregistreur"), crypto.generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "der" }), { mode: 0o400 });
    s.jetonHote = crypto.randomBytes(32).toString("hex");
    for (const n of ["cle-mac-relais", "jeton-hote", "jeton-passerelle", "cle-stockage-approbation"]) fs.writeFileSync(path.join(secrets, n), n === "jeton-hote" ? s.jetonHote : crypto.randomBytes(32).toString("hex"), { mode: 0o400 });
    fs.writeFileSync(path.join(T, "jeton-hote"), s.jetonHote, { mode: 0o444 });
    const init = dcOk(["--profile", "outils", "run", "--rm", "-T", "horodatage-init", "init", "--repertoire", "/var/lib/noortrace-tsa", "--politique", "1.3.6.1.4.1.99999.1.1", "--crl-url", "http://127.0.0.1:2020/crl.pem", "--algorithme", "p-256"]);
    if (!init.includes("autorité créée")) throw new Error(`horodatage-init : ${init}`);
    const acPem = dcOk(["--profile", "outils", "run", "--rm", "-T", "horodatage-init", "ac", "--repertoire", "/var/lib/noortrace-tsa"]);
    const ficAc = path.join(T, "config", "rapide", "ac-horodatage.pem");
    fs.writeFileSync(ficAc, acPem);
    // IR-3 : configuration de référence (mode observation) et document d'ancrage par configurer-rapide ; configuration du service.
    s.cheminConfig = path.join(T, "config", "rapide", "configuration.json");
    const ir3 = spawnSync(process.execPath, [path.join(RACINE, "scripts", "deploiement", "configurer-rapide.mjs"), "--org", "organisation-exemple", "--journal", "journal-observation", "--serveur-outils", "https://outils.interne.example/mcp", "--sortie", s.cheminConfig, "--ac-horodatage", ficAc, "--sortie-ancrage", path.join(T, "config", "rapide", "ancrage.json")], { encoding: "utf8", cwd: T });
    if (ir3.status !== 0) throw new Error(`configurer-rapide : ${ir3.stderr}`);
    const conf = JSON.parse(fs.readFileSync(s.cheminConfig, "utf8"));
    conf.policy.servers.outils.transport.tls = { ca_file: "/etc/noortrace/outils-ca.pem", cert_file: null, key_file: null };
    conf.policy.failure.pending_max_ms = PENDING_MAX_MS;
    s.config = conf;
    s.repJournal = `${conf.recorder.org_id.slice(2)}/${conf.recorder.journal_id.slice(2)}`;
    s.versionObservation = conf.policy.version;
    s.ecrireConfig = (c) => {
      fs.chmodSync(s.cheminConfig, 0o600);
      fs.writeFileSync(s.cheminConfig, `${JSON.stringify(c, null, 2)}\n`);
      fs.chmodSync(s.cheminConfig, 0o400);
      fs.chownSync(s.cheminConfig, 10001, 10001);
    };
    s.ecrireConfig(conf);
    const approbation = { version: 0, environment: "developpement", org: "organisation-exemple", org_id: conf.recorder.org_id, journal_id: conf.recorder.journal_id, state_dir: "/var/lib/noortrace-approbation", storage_key: { file: "/run/secrets/cle-stockage-approbation" }, noyau: { socket: "/run/noortrace/approbation.sock", socket_mode: "0660", tcp: null, tls: null, token: null }, console: null, etat: { host: "127.0.0.1", port: 8601 }, administrators: ["utilisateur console.invalid administrateur"], console_origin: "https://console.invalid", notifications: null, rpc: null };
    const cheminApprobation = path.join(T, "config", "rapide", "approbation.json");
    fs.writeFileSync(cheminApprobation, `${JSON.stringify(approbation, null, 2)}\n`, { mode: 0o400 });
    for (const [f, [u, g]] of Object.entries({ "secrets/cle-enregistreur": [10001, 10001], "secrets/cle-mac-relais": [10001, 10001], "secrets/jeton-hote": [10001, 10001], "secrets/jeton-passerelle": [10001, 10001], "secrets/cle-stockage-approbation": [10002, 10002], "config/rapide/approbation.json": [10002, 10002] })) fs.chownSync(path.join(T, f), u, g);
    // IR-5 : validation par le démon et par le service.
    s.ir5 = { demon: dc(["run", "--rm", "--no-deps", "enregistreur", "validate-config", "/etc/noortrace/configuration.json"]), service: dc(["run", "--rm", "--no-deps", "approbation", "valider-configuration", "/etc/noortrace-approbation/configuration.json"]) };
    // IR-6 : démarrage.
    dcOk(["up", "-d"]);
    const sante = () => Object.fromEntries(dc(["ps", "--format", "{{.Service}}={{.Health}}"]).stdout.trim().split("\n").map((l) => l.split("=")));
    let h = {};
    const debut = Date.now();
    while (Date.now() - debut < 180000) {
      h = sante();
      if (h.enregistreur === "healthy" && h.approbation === "healthy" && h.horodatage === "healthy") break;
      await pause(2000);
    }
    if (!(h.enregistreur === "healthy" && h.approbation === "healthy" && h.horodatage === "healthy")) throw new Error(`installation rapide non saine : ${JSON.stringify(h)}\n${dc(["logs", "--tail", "30"]).stdout}`);
    s.idEnregistreur = dc(["ps", "-q", "enregistreur"]).stdout.trim();
    s.volumeJournal = `${s.nom}_journal`;
    s.pointDeMontage = docker(["volume", "inspect", "--format", "{{.Mountpoint}}", s.volumeJournal]).stdout.trim();
  });

  after(function () {
    this.timeout(300000);
    if (!s.projet) return;
    if (process.env.NOORTRACE_GARDER_CAS === "1") {
      fs.writeFileSync(path.join(s.T, "journal-enregistreur.log"), dc(["logs", "--no-log-prefix", "enregistreur"]).stdout);
      return;
    }
    // Un attribut immuable resté posé empêcherait la suppression du volume.
    for (const f of s.nettoyage) spawnSync("chattr", ["-i", f], { stdio: "pipe" });
    dc(["down", "--volumes", "--remove-orphans", "--timeout", "5"], { timeout: 180000 });
    fs.rmSync(s.T, { recursive: true, force: true });
  });

  function pret(ctx) {
    if (s.attente) {
      enAttente(ctx, s.attente);
      return false;
    }
    return true;
  }

  it("TE-10, précondition (IR-5, IR-6) : la configuration de référence de l'installation rapide valide avec l'avertissement du mode observation (CT-2 EX-15.8) ; enregistreur, service d'approbation et serveur interne sains ; noortrace_observation_mode vaut 1 ; aucun appel bloqué", function () {
    if (!pret(this)) return;
    expect(s.ir5.demon.status, s.ir5.demon.stderr).to.equal(0);
    expect(s.ir5.demon.stdout + s.ir5.demon.stderr).to.match(/observation/);
    expect(s.ir5.service.status).to.equal(0);
    expect(s.versionObservation).to.match(/-observation$/);
    expect(s.config.policy.approval.mode).to.equal("observation");
    const m = metriques();
    expect(metrique(m, "noortrace_observation_mode")).to.equal(1);
    expect(journalOps().find((l) => l.event === "startup")).to.not.equal(undefined);
  });

  it("TE-10, pas 1 : trois appels de l'agent par le frontal MCP : tous relayés (résultat du serveur d'outils), aucun signal d'approbation, aucun ticket ; trois événements executee, policy autorise, ticket null, approval null, règle « defaut : revue [observation a_approuver] » (EX-12.6) ; trois lignes observation_would_block ; noortrace_calls_blocked_total n'a pas augmenté", async function () {
    if (!pret(this)) return;
    const r = appeler([1, 2, 3].map((i) => ({ name: OUTIL, arguments: { path: `/dossier/piece-${i}.txt` } })));
    expect(r.map((x) => [x.status, x.is_error, x.approval, x.error])).to.deep.equal([1, 2, 3].map(() => [200, false, null, null]));
    for (const x of r) expect(x.text).to.match(/^contenu factice de /);
    const ev = await attendre(() => {
      const e = appelsOutil(evenements());
      return e.length >= 3 ? e : null;
    }, 30000, "trois événements d'appel");
    for (const e of ev) {
      expect(e.execution.status).to.equal("executee");
      expect(e.policy).to.deep.include({ decision: "autorise", ticket: null, rule: "defaut : revue [observation a_approuver]" });
      expect(e.approval).to.equal(null);
      expect(e.code.policy_version).to.equal(s.versionObservation);
    }
    const bloques = journalOps().filter((l) => l.event === "observation_would_block");
    expect(bloques.length).to.be.at.least(3);
    expect(bloques.map((l) => l.data.would)).to.include("a_approuver");
    const m = metriques();
    expect(metrique(m, "noortrace_observation_mode")).to.equal(1);
    expect(metrique(m, "noortrace_calls_blocked_total") ?? 0).to.equal(0);
    s.apres1 = appelsOutil(evenements()).length;
  });

  it("TE-10, pas 1 (service d'approbation coupé) : le service d'approbation arrêté pendant deux appels : relayés sans refus ni signal, en moins de quatre secondes chacun (délai d'évaluation, EX-12.5), règle « evaluation impossible [observation inconnu] », approval_service_unavailable au journal d'exploitation (EX-14.15) ; service redémarré sain", async function () {
    if (!pret(this)) return;
    dcOk(["stop", "approbation"]);
    const r = appeler([4, 5].map((i) => ({ name: OUTIL, arguments: { path: `/dossier/piece-${i}.txt` } })));
    expect(r.map((x) => [x.status, x.is_error, x.approval])).to.deep.equal([[200, false, null], [200, false, null]]);
    for (const x of r) expect(x.ms, `durée ${x.ms} ms`).to.be.below(4000);
    const ev = await attendre(() => {
      const e = appelsOutil(evenements());
      return e.length >= s.apres1 + 2 ? e : null;
    }, 30000, "deux événements de plus");
    for (const e of ev.slice(-2)) expect(e.policy).to.deep.include({ decision: "autorise", ticket: null, rule: "evaluation impossible [observation inconnu]" });
    expect(journalOps().filter((l) => l.event === "approval_service_unavailable").length).to.be.at.least(1);
    dcOk(["start", "approbation"]);
    await attendre(() => dc(["ps", "--format", "{{.Service}}={{.Health}}"]).stdout.includes("approbation=healthy"), 60000, "service d'approbation sain");
    s.apres2 = appelsOutil(evenements()).length;
  });

  it(`TE-10, pas 1 (stockage coupé) : attribut immuable posé sur le segment courant et sur le répertoire des segments (l'écriture échoue, aucun segment neuf ne s'ouvre) : l'appel suivant est relayé (aucun refus), l'écriture échoue (storage_unavailable, degraded_enter stockage, call_executed_not_durable : son événement attend) ; l'appel d'après, sous la panne connue, est relayé et son événement attend (call_passthrough_pending) ; ${PENDING_MAX_MS} ms plus tard, l'appel suivant est relayé et son événement perdu et compté (pending_limit_reached, event_lost, noortrace_events_lost_total, EX-12.3, EX-12.14) ; attribut retiré : reprise (degraded_exit), événements en attente scellés (pending_flushed), aucun trou de seq, autant d'événements d'appel que d'appels moins les pertes comptées`, async function () {
    if (!pret(this)) return;
    const segments = path.join(s.pointDeMontage, s.repJournal, "segments");
    const courant = path.join(segments, fs.readdirSync(segments).filter((n) => n.endsWith(".ndjson")).sort().at(-1));
    // Le fichier seul ne suffit pas : à la panne, le démon ferme le segment et en ouvre un neuf (CT-2 EX-12.8, EX-14.11),
    // et la panne cesse en une seconde (constaté) ; le répertoire immuable interdit le segment neuf, et la panne dure.
    s.nettoyage.push(courant, segments);
    for (const f of [courant, segments]) {
      const r0 = spawnSync("chattr", ["+i", f], { encoding: "utf8" });
      expect(r0.status, r0.stderr).to.equal(0);
    }
    const pertes = () => journalOps().filter((l) => l.event === "event_lost").reduce((n, l) => n + (l.data.count ?? 1), 0);
    try {
      // A : l'écriture échoue sur cet appel ; l'appel est relayé quand même (EX-14.16).
      const a = appeler([{ name: OUTIL, arguments: { path: "/dossier/piece-6.txt" } }]);
      expect(a.map((x) => [x.status, x.is_error, x.approval])).to.deep.equal([[200, false, null]]);
      await attendre(() => journalOps().some((l) => l.event === "degraded_enter" && l.data.reason === "stockage"), 20000, "degraded_enter stockage");
      expect(journalOps().filter((l) => l.event === "storage_unavailable").length).to.be.at.least(1);
      expect(journalOps().filter((l) => l.event === "call_executed_not_durable").length).to.be.at.least(1);
      // B : la panne est connue avant le relais : passant, événement en attente (14.5).
      const b = appeler([{ name: OUTIL, arguments: { path: "/dossier/piece-7.txt" } }]);
      expect(b.map((x) => [x.status, x.is_error, x.approval])).to.deep.equal([[200, false, null]]);
      await attendre(() => journalOps().some((l) => l.event === "call_passthrough_pending"), 20000, "call_passthrough_pending");
      const pertesAvant = pertes();
      await pause(PENDING_MAX_MS + 1000);
      // C : la borne pending_max_ms est passée : relayé, événement perdu et compté.
      const c = appeler([{ name: OUTIL, arguments: { path: "/dossier/piece-8.txt" } }]);
      expect(c.map((x) => [x.status, x.is_error, x.approval])).to.deep.equal([[200, false, null]]);
      await attendre(() => pertes() > pertesAvant, 20000, "event_lost");
      expect(journalOps().some((l) => l.event === "pending_limit_reached" && l.data.limit === "pending_max_ms")).to.equal(true);
      const m = metriques();
      const total = journalOps().filter((l) => l.event === "event_lost").map((l) => metrique(m, "noortrace_events_lost_total", `reason="${l.data.reason}"`) ?? 0).reduce((x, y) => Math.max(x, y), 0);
      expect(total).to.be.at.least(1);
      expect(metrique(m, "noortrace_observation_mode")).to.equal(1);
    } finally {
      for (const f of [segments, courant]) spawnSync("chattr", ["-i", f], { stdio: "pipe" });
    }
    await attendre(() => journalOps().some((l) => l.event === "degraded_exit" && l.data.reason === "stockage"), 120000, "degraded_exit stockage");
    await attendre(() => journalOps().some((l) => l.event === "pending_flushed"), 60000, "pending_flushed");
    const ev = await attendre(() => {
      const e = evenements();
      return appelsOutil(e).length >= s.apres2 + 3 - pertes() ? e : null;
    }, 60000, "événements en attente scellés");
    expect(ev.map((e) => e.seq)).to.deep.equal(ev.map((_, i) => i + 1));
    expect(appelsOutil(ev).length).to.equal(s.apres2 + 3 - pertes());
    expect(pertes()).to.be.at.least(1);
    s.pertes = pertes();
    s.apresCoupures = appelsOutil(ev).length;
  });

  it("TE-10, pas 1 (rapport) : rapport-observation.mjs sur une copie du journal : rapport-observation-v0 égal au recompte fait ici depuis les événements (versions, règles sans marque, décisions, seq hors autorise, totaux, observed) ; aucune anomalie OB-1, OB-2 ; code 0", function () {
    if (!pret(this)) return;
    const copie = path.join(s.T, "journal-copie");
    fs.mkdirSync(copie);
    const cp = docker(["run", "--rm", "--network", "none", "--user", "0:0", "-v", `${s.volumeJournal}:/v:ro`, "-v", `${copie}:/c`, "--entrypoint", "/usr/local/bin/node", `noortrace/enregistreur:${VERSION}`, "-e", `require("fs").cpSync("/v/${s.repJournal}", "/c", { recursive: true })`]);
    expect(cp.status, cp.stderr).to.equal(0);
    const r = spawnSync(process.execPath, [path.join(RACINE, "scripts", "deploiement", "rapport-observation.mjs"), copie, "--json"], { cwd: RACINE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    expect(r.status, r.stderr + r.stdout).to.equal(0);
    const rapport = JSON.parse(r.stdout);
    const ev = evenements();
    const appels = ev.filter((e) => e.execution?.tool && !String(e.execution.tool).startsWith("noortrace."));
    const lignes = new Map();
    const totaux = { autorise: 0, a_approuver: 0, refuse: 0, inconnu: 0 };
    let observes = 0;
    for (const e of appels) {
      const m = MARQUE.exec(e.policy.rule);
      if (!m) continue;
      observes += 1;
      totaux[m[1]] += 1;
      const k = `${e.code.policy_version}\u0000${e.policy.rule.slice(0, m.index)}\u0000${m[1]}`;
      const l = lignes.get(k) ?? { policy_version: e.code.policy_version, rule: e.policy.rule.slice(0, m.index), would: m[1], count: 0, seqs: [] };
      l.count += 1;
      if (m[1] !== "autorise") l.seqs.push(e.seq);
      lignes.set(k, l);
    }
    expect(rapport).to.include({ version: 0, org_id: s.config.recorder.org_id, journal_id: s.config.recorder.journal_id, first_seq: ev[0].seq, last_seq: ev.at(-1).seq, events: ev.length, tool_calls: appels.length, observed: observes });
    expect(rapport.totals).to.deep.equal(totaux);
    const trier = (x) => [...x].sort((a, b) => `${a.policy_version} ${a.rule} ${a.would}`.localeCompare(`${b.policy_version} ${b.rule} ${b.would}`));
    expect(trier(rapport.rows)).to.deep.equal(trier([...lignes.values()]));
    expect(rapport.anomalies).to.deep.equal([]);
    expect(observes).to.equal(s.apresCoupures);
    expect(totaux.inconnu).to.equal(2);
    expect(rapport.tool_calls + s.pertes).to.equal(3 + 2 + 3);
    s.rapport = rapport;
  });

  it("TE-10, passage au mode bloquant (CT-8 EX-12.11, pas 3 à 5) : configuration récrite en place avec mode erreur, une version nouvelle sans suffixe et une règle de test a_approuver sur l'outil de lecture ; validate-config dans le conteneur : code 0 ; noortrace-ctl reload : config_reloaded puis événement noortrace.journal.politique ; noortrace_observation_mode vaut 0 et le rapport sur les événements qui suivent a observed à 0 ; l'appel de test reçoit le signal d'approbation (en_attente, ticket) et un événement retenue ; le retour au mode observation est refusé tant que la retenue n'a pas de décision (config_reload_rejected, tickets_ouverts, EX-12.13)", async function () {
    if (!pret(this)) return;
    const bloquante = structuredClone(s.config);
    bloquante.policy.version = "rapide-2026-11-13-erreur";
    bloquante.policy.approval.mode = "erreur";
    bloquante.policy.approval.rules.rules = [{ name: "regle de test : lecture en revue", description: "Pas 5a d'EX-12.11 : un appel d'un outil de lecture sans effet est soumis a approbation pour verifier le mode bloquant.", tools: [OUTIL], when: null, level: "revue", decision: null, window: null, contest_ms: 0 }];
    s.ecrireConfig(bloquante);
    const v = dc(["run", "--rm", "--no-deps", "enregistreur", "validate-config", "/etc/noortrace/configuration.json"]);
    expect(v.status, v.stdout + v.stderr).to.equal(0);
    expect(v.stdout + v.stderr).to.not.include("mode observation : aucun appel ne sera bloque");
    // Les comptes du jeu de l'installation rapide sont des comptes de test (7.3) : l'avertissement approbateurs_de_test reste, et le texte le dit (pas 2).
    expect(v.stdout + v.stderr).to.include("approbateurs_de_test");
    const avant = evenements().length;
    const reload = exec("enregistreur", ["/usr/local/bin/noortrace-ctl", "reload"]);
    expect(reload.status, reload.stdout + reload.stderr).to.equal(0);
    const ligne = JSON.parse(reload.stdout.trim().split("\n").at(-1));
    expect(ligne.event).to.equal("config_reloaded");
    expect(ligne.data).to.include({ policy_version: "rapide-2026-11-13-erreur" });
    const politique = await attendre(() => evenements().find((e) => e.execution?.tool === "noortrace.journal.politique" && e.code.policy_version === "rapide-2026-11-13-erreur"), 30000, "événement de politique");
    expect(politique.seq).to.be.above(avant);
    s.seqPolitique = politique.seq;
    expect(metrique(metriques(), "noortrace_observation_mode")).to.equal(0);
    // 5c : l'appel de test est retenu.
    const r = appeler([{ name: OUTIL, arguments: { path: "/dossier/piece-test.txt" } }]);
    expect(r[0].status).to.equal(200);
    expect(r[0].is_error).to.equal(true);
    expect(r[0].approval).to.include({ state: "en_attente" });
    expect(r[0].approval.ticket).to.match(/^apr-/);
    s.ticket = r[0].approval.ticket;
    const retenue = await attendre(() => evenements().find((e) => e.execution?.status === "retenue" && e.policy.ticket === s.ticket), 30000, "événement retenue");
    expect(retenue.policy).to.include({ decision: "a_approuver", rule: "regle de test : lecture en revue" });
    expect(retenue.code.policy_version).to.equal("rapide-2026-11-13-erreur");
    // 5b : le rapport sur les événements qui suivent l'événement de politique a observed à 0.
    const suite = path.join(s.T, "evenements-apres-passage.ndjson");
    fs.writeFileSync(suite, evenements().filter((e) => e.seq > s.seqPolitique).map((e) => JSON.stringify(e)).join("\n") + "\n");
    const rap = spawnSync(process.execPath, [path.join(RACINE, "scripts", "deploiement", "rapport-observation.mjs"), suite, "--json"], { cwd: RACINE, encoding: "utf8" });
    expect(rap.status, rap.stderr).to.equal(0);
    expect(JSON.parse(rap.stdout).observed).to.equal(0);
    // EX-12.13 : retour à l'observation refusé tant que la retenue n'a pas de décision.
    const retour = structuredClone(s.config);
    retour.policy.version = "rapide-2026-11-13-observation";
    s.ecrireConfig(retour);
    const v2 = dc(["run", "--rm", "--no-deps", "enregistreur", "validate-config", "/etc/noortrace/configuration.json"]);
    expect(v2.status, v2.stdout + v2.stderr).to.equal(0);
    const reload2 = exec("enregistreur", ["/usr/local/bin/noortrace-ctl", "reload"]);
    expect(reload2.status).to.not.equal(0);
    const ligne2 = JSON.parse(reload2.stdout.trim().split("\n").at(-1));
    expect(ligne2.event).to.equal("config_reload_rejected");
    expect(JSON.stringify(ligne2.data)).to.include("tickets_ouverts");
    expect(metrique(metriques(), "noortrace_observation_mode")).to.equal(0);
    expect(journalOps().filter((l) => l.event === "config_reload_rejected").length).to.be.at.least(1);
  });
});
