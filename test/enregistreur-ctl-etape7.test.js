// Étape 7 : commandes de `noortrace-ctl` que CT-8 emploie sans que
// CT-2 les fixe (PD-2 ; décision D-11 : exigences de construction) :
//
// - `noortrace-ctl sonde --url <url>` : sonde du conteneur `enregistreur` des
//   deux fichiers Compose (CT-8 §4.4, CO-12 : forme `CMD`, image sans
//   interpréteur de commandes) ; code 0 sur une réponse 200, 1 sinon (délai
//   écoulé compris) ; URL `http:` de boucle locale écrite en clair ; délai
//   total de 2 500 ms, sous le `timeout` de 3 s des sondes ;
// - `noortrace-ctl etat` : `GET /healthz`, `/readyz` et l'époque du bail
//   (`noortrace_lease_epoch`) du démon en marche (CT-8 EX-10.14, RB-1, RB-2,
//   11.4) ; muet (code 4) sans démon ;
// - `noortrace-ctl close-period --now` : clôture anticipée (CT-2 EX-19.4,
//   CT-8 IR-8), développement seulement ; elle termine le journal (tout
//   nouvel appel refusé, `-31010` `journal_clos`, mode observation compris,
//   et encore après un redémarrage) ; refusée en production par la commande
//   (code 1, sans demande ni signal) et par le démon (`period_close_refused`,
//   `production`).
//
// Le magasin de bail `file` sans `/bin/sh` ni `cat` (images sans interpréteur) est
// éprouvé ici sur son auxiliaire, et par les suites du bail et de la haute
// disponibilité (TE-11, TA-19), rejouées sans changement.
//
// CT-9 n'a aucune entrée TA- pour ces commandes (recherche du 2026-11-12 dans
// spec/vecteurs/ct-9/catalogue.json) : aucun mutant ici.

import { expect } from "chai";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import yaml from "js-yaml";
import { Coeur, ErreurEnregistreur, HorlogeReglable, validerConfiguration, pieceJson } from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { configurationDev, secretsDev, RACINE } from "./fixtures/enregistreur-coeur/outils.mjs";
import { ctl, BIN_CTL, VERIFICATEUR_JS, attendre, pause } from "./fixtures/enregistreur-export/outils.mjs";
import { REFERENCE, configurationDemon, demarrer, arreter, appelerOutil, enfants, repertoireJournal, portLibre } from "./fixtures/enregistreur-adversarial/demon.mjs";
import { argumentsSonde, DELAI_SONDE_MS } from "../paquets/enregistreur/src/ctl-sante.mjs";
import { SCRIPT_AUXILIAIRE } from "../paquets/enregistreur/src/bail.mjs";

const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const COMPOSE = path.join(RACINE, "deploiement", "compose");

/** Serveur HTTP d'essai sur 127.0.0.1 ; `gerer(req, res)`. */
async function serveur(gerer) {
  const s = http.createServer(gerer);
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  return { s, port: s.address().port, fermer: () => new Promise((r) => { s.closeAllConnections?.(); s.close(() => r()); }) };
}

/** Sondes `noortrace-ctl` des fichiers Compose : [{ fichier, service, test }]. */
function sondesCompose() {
  const r = [];
  for (const f of ["rapide.yaml", "production.yaml"]) {
    const doc = yaml.load(fs.readFileSync(path.join(COMPOSE, f), "utf8"));
    for (const [service, s] of Object.entries(doc.services)) {
      const t = s.healthcheck?.test;
      if (Array.isArray(t) && t[1] === "/usr/local/bin/noortrace-ctl") r.push({ fichier: f, service, test: t, timeout: s.healthcheck.timeout });
    }
  }
  return r;
}

describe("étape 7 — noortrace-ctl sonde --url (CT-8 §4.4, CO-12 ; PD-2) : sonde des fichiers Compose, sans interpréteur", function () {
  this.timeout(60000);

  it("appel exact des fichiers Compose : rapide.yaml et production.yaml sondent `enregistreur` par [\"CMD\", \"/usr/local/bin/noortrace-ctl\", \"sonde\", \"--url\", \"http://127.0.0.1:8500/readyz\"], timeout 3s ; la commande admet cette URL et son délai total (2 500 ms) est sous le timeout", function () {
    const s = sondesCompose();
    expect(s.map((x) => `${x.fichier}:${x.service}`)).to.deep.equal(["rapide.yaml:enregistreur", "production.yaml:enregistreur"]);
    for (const x of s) {
      expect(x.test).to.deep.equal(["CMD", "/usr/local/bin/noortrace-ctl", "sonde", "--url", "http://127.0.0.1:8500/readyz"]);
      expect(x.timeout).to.equal("3s");
      const a = argumentsSonde(x.test.slice(3));
      expect(a.erreur, x.fichier).to.equal(undefined);
      expect(a.url.href).to.equal("http://127.0.0.1:8500/readyz");
    }
    expect(DELAI_SONDE_MS).to.be.below(3000);
  });

  it("nominal : réponse 200 → code 0 et « 200 » sur la sortie standard ; 503 (démon pas prêt) → code 1 et le statut sur la sortie d'erreur ; aucune redirection suivie (302 → code 1)", async function () {
    let statut = 200;
    const vus = [];
    const x = await serveur((req, res) => {
      vus.push(`${req.method} ${req.url}`);
      if (statut === 302) res.writeHead(302, { location: "/readyz-ailleurs" }).end();
      else res.writeHead(statut).end();
    });
    try {
      const ok = await ctl(["sonde", "--url", `http://127.0.0.1:${x.port}/readyz`]);
      expect(ok.code, ok.stderr).to.equal(0);
      expect(ok.stdout).to.equal("200\n");
      expect(ok.stderr).to.equal("");
      statut = 503;
      const pasPret = await ctl(["sonde", "--url", `http://127.0.0.1:${x.port}/readyz`]);
      expect(pasPret.code).to.equal(1);
      expect(pasPret.stdout).to.equal("");
      expect(pasPret.stderr).to.equal("noortrace-ctl sonde : statut 503\n");
      statut = 302;
      const redirige = await ctl(["sonde", "--url", `http://127.0.0.1:${x.port}/readyz`]);
      expect(redirige.code).to.equal(1);
      expect(vus).to.deep.equal(["GET /readyz", "GET /readyz", "GET /readyz"]);
    } finally {
      await x.fermer();
    }
  });

  it("URL non locale refusée sans connexion (192.0.2.1, nom localhost, 0.0.0.0, https, identifiants) ; usage incorrect : code 1, jamais 2 (réservé par le moteur de conteneurs)", async function () {
    let connexions = 0;
    const x = await serveur((req, res) => {
      connexions++;
      res.writeHead(200).end();
    });
    try {
      const cas = [
        ["http://192.0.2.1:8500/readyz", "adresse de boucle locale attendue (127.0.0.0/8 ou [::1]) : 192.0.2.1"],
        [`http://localhost:${x.port}/readyz`, "adresse de boucle locale attendue (127.0.0.0/8 ou [::1]) : localhost"],
        ["http://0.0.0.0:8500/readyz", "adresse de boucle locale attendue (127.0.0.0/8 ou [::1]) : 0.0.0.0"],
        ["http://203.0.113.7/readyz", "adresse de boucle locale attendue (127.0.0.0/8 ou [::1]) : 203.0.113.7"],
        [`https://127.0.0.1:${x.port}/readyz`, "url http attendue (écoute de supervision locale, sans TLS)"],
        [`http://a:b@127.0.0.1:${x.port}/readyz`, "url sans identifiants attendue"],
        ["pas une url", "url invalide"],
      ];
      for (const [url, raison] of cas) {
        const t0 = Date.now();
        const r = await ctl(["sonde", "--url", url]);
        expect(r.code, url).to.equal(1);
        expect(r.stderr, url).to.equal(`noortrace-ctl sonde : ${raison}\n`);
        expect(Date.now() - t0, `${url} : refus sans attendre le délai`).to.be.below(DELAI_SONDE_MS);
      }
      for (const args of [[], ["--url"], ["--url", `http://127.0.0.1:${x.port}/`, "--url", "x"], ["--adresse", `http://127.0.0.1:${x.port}/`]]) {
        const r = await ctl(["sonde", ...args]);
        expect(r.code, args.join(" ")).to.equal(1);
        expect(r.stderr).to.equal("noortrace-ctl sonde : usage : noortrace-ctl sonde --url <url>\n");
      }
      expect(connexions, "aucune connexion pour une URL refusée").to.equal(0);
      expect(argumentsSonde(["--url", "http://[::1]:8500/readyz"]).url.hostname).to.equal("[::1]");
      expect(argumentsSonde(["--url", "http://127.0.0.2:8500/readyz"]).url.hostname).to.equal("127.0.0.2");
    } finally {
      await x.fermer();
    }
  });

  it("sans service : connexion refusée → code 1 aussitôt ; service muet (connexion acceptée, aucune réponse) → code 1 au délai de 2 500 ms, sous le timeout de 3 s des sondes", async function () {
    const libre = await portLibre();
    const refuse = await ctl(["sonde", "--url", `http://127.0.0.1:${libre}/readyz`]);
    expect(refuse.code).to.equal(1);
    expect(refuse.stderr).to.equal("noortrace-ctl sonde : connexion : ECONNREFUSED\n");
    const prises = new Set();
    const muet = net.createServer((c) => prises.add(c));
    await new Promise((r) => muet.listen(0, "127.0.0.1", r));
    try {
      const t0 = Date.now();
      const r = await ctl(["sonde", "--url", `http://127.0.0.1:${muet.address().port}/readyz`]);
      const duree = Date.now() - t0;
      expect(r.code).to.equal(1);
      expect(r.stderr).to.equal("noortrace-ctl sonde : délai écoulé\n");
      expect(duree).to.be.at.least(DELAI_SONDE_MS);
      expect(duree, "processus compris, sous le timeout de 3 s").to.be.below(3000);
    } finally {
      for (const c of prises) c.destroy();
      await new Promise((r) => muet.close(r));
    }
  });

  it("sans interpréteur de commandes : la commande, lancée sans shell avec un PATH vide (ni /bin/sh, ni programme auxiliaire joignable), sonde et rend 0 ; elle ne lance aucun processus", async function () {
    const x = await serveur((req, res) => res.writeHead(200).end());
    try {
      // Processus asynchrone : le serveur d'essai tourne dans ce processus.
      const p = spawn(process.execPath, [BIN_CTL, "sonde", "--url", `http://127.0.0.1:${x.port}/readyz`], { env: { PATH: "" }, shell: false, cwd: TMP, stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      p.stdout.on("data", (d) => (stdout += d));
      p.stderr.on("data", (d) => (stderr += d));
      const code = await new Promise((r) => p.on("exit", r));
      expect(code, stderr).to.equal(0);
      expect(stdout).to.equal("200\n");
    } finally {
      await x.fermer();
    }
    const source = fs.readFileSync(path.join(RACINE, "paquets", "enregistreur", "src", "ctl-sante.mjs"), "utf8");
    expect(source).to.not.match(/child_process/);
  });
});

describe("étape 7 — bail `file` sans /bin/sh ni cat (images sans interpréteur ; CT-2 13.2, EX-13.10)", function () {
  this.timeout(60000);

  it("l'auxiliaire est flock(1) qui exécute Node.js directement (--close, sans -c ni SHELL) ; le tuer libère le verrou ; un second détenteur est refusé tant qu'il vit", async function () {
    const { MagasinBailFichier } = await REFERENCE.importer("bail.mjs");
    const dir = fs.mkdtempSync(path.join(TMP, "noortrace-etape7-bail-"));
    try {
      const chemin = path.join(dir, "verrou");
      const a = new MagasinBailFichier(chemin);
      expect(await a.acquerir()).to.equal(1);
      const [aux] = enfants(process.pid).filter((e) => e.pid === a.auxiliaire.pid);
      expect(aux.commande.slice(0, 6)).to.deep.equal(["flock", "--exclusive", "--nonblock", "--close", "--conflict-exit-code", "75"]);
      expect(aux.commande.slice(6)).to.deep.equal([chemin, process.execPath, "-e", SCRIPT_AUXILIAIRE]);
      expect(aux.commande).to.not.include("-c");
      const [commande] = enfants(aux.pid);
      expect(commande.commande[0]).to.equal(process.execPath);
      const b = new MagasinBailFichier(chemin);
      let err = null;
      try {
        await b.acquerir();
      } catch (e) {
        err = e;
      }
      expect(err).to.be.instanceOf(ErreurEnregistreur);
      expect(err.raison).to.equal("bail_non_detenu");
      // Auxiliaire tué (instance isolée, 13.4 pas 2) : le verrou est rendu, le bail n'est plus valide.
      process.kill(aux.pid, "SIGKILL");
      await attendre(() => a.valide() === false, 5000, "bail invalide après la mort de l'auxiliaire");
      expect(await b.acquerir()).to.equal(2);
      await b.liberer();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("étape 7 — noortrace-ctl etat et close-period --now sur le démon réel (CT-8 EX-10.14, IR-8 ; CT-2 EX-19.4)", function () {
  this.timeout(300000);
  let base;
  let service;
  let serveurService;
  let c;
  let fichier;
  let demon;

  before(async function () {
    base = fs.mkdtempSync(path.join(TMP, "noortrace-etape7-ctl-"));
    service = new ServiceApprobationFactice({ org_id: "0x00", journal_id: null });
    serveurService = await service.servir(0);
    c = await configurationDemon(base, {
      approbation: serveurService.address().port,
      modifier: (config) => {
        // Installation rapide (CT-8 §7) : mode observation, développement, métriques servies.
        config.policy.approval.mode = "observation";
        config.policy.version = `${config.policy.version}-observation`;
        config.supervision.metrics = true;
        config.exports_dir = path.join(base, "exports");
      },
    });
    fs.mkdirSync(c.config.exports_dir);
    service.org_id = c.config.recorder.org_id;
    service.journal_id = c.config.recorder.journal_id;
    fichier = path.join(base, "configuration.json");
    expect(c.config.recorder.environment).to.equal("developpement");
    demon = await demarrer(REFERENCE, c, fichier);
  });

  after(async function () {
    await arreter(demon).catch(() => {});
    serveurService?.close();
    if (base) fs.rmSync(base, { recursive: true, force: true });
  });

  const opts = () => ({ env: c.env });

  it("etat nominal : une ligne { pid, configuration, health_listen, status ok, reasons [], healthz 200, readyz 200, lease_epoch 1 }, code 0 ; sonde du démon (sa /readyz) : code 0", async function () {
    const r = await ctl(["etat", "--configuration", fichier], opts());
    expect(r.code, r.stderr).to.equal(0);
    expect(r.ligne).to.deep.equal({ pid: demon.pid, configuration: fs.realpathSync(fichier), health_listen: c.config.supervision.health_listen, status: "ok", reasons: [], since: null, healthz: 200, readyz: 200, lease_epoch: 1 });
    const s = await ctl(["sonde", "--url", `http://127.0.0.1:${c.portSante}/readyz`]);
    expect(s.code, s.stderr).to.equal(0);
  });

  it("close-period --now nominal (IR-8) : code 0, ligne period_closed_early (request_id) ; manifeste signé de la période courante, generated_at avant period_end ; dossier exporté par --dernier et vérifié ; le journal est terminé : appels de lecture et d'écriture refusés -31010 journal_clos en mode observation, nouvelle clôture refusée (journal_clos, code 1), rotation d'urgence refusée", async function () {
    const lu = await appelerOutil(c.portHttp, c.env.NOORTRACE_TEST_JETON_HOTE, "demo__lire", { id: "E7-1" });
    expect(lu.corps?.error, JSON.stringify(lu.corps)).to.equal(undefined);
    const r = await ctl(["close-period", "--now", "--configuration", fichier], opts());
    expect(r.code, r.stderr).to.equal(0);
    expect(r.stderr).to.equal("");
    expect(r.ligne).to.deep.include({ pid: demon.pid, event: "period_closed_early" });
    const d = r.ligne.data;
    expect(Object.keys(d)).to.deep.equal(["period_start", "period_end", "count", "period_hash", "generated_at"]);
    expect(d.period_end).to.equal(d.period_start + 3600);
    // Au moins la politique et la lecture, sauf si l'heure pleine est passée entre la lecture et la clôture.
    expect(Number.isSafeInteger(d.count) && d.count >= 0).to.equal(true);
    expect(Date.parse(d.generated_at)).to.be.below(d.period_end * 1000);
    const ligne = demon.lignes().find((l) => l.event === "period_closed_early");
    expect(ligne).to.include({ level: "info", component: "cloture" });
    expect(ligne.request_id).to.match(/^[0-9a-f]{32}$/);
    const nom = `periode-${String(d.period_start).padStart(10, "0")}`;
    const manifeste = JSON.parse(fs.readFileSync(path.join(repertoireJournal(c.config), "manifestes", `${nom}.json`), "utf8"));
    expect(manifeste).to.include({ period_start: d.period_start, period_end: d.period_end, count: d.count, generated_at: d.generated_at });
    expect(fs.existsSync(path.join(repertoireJournal(c.config), "manifestes", `${nom}.sig`))).to.equal(true);
    // Premier dossier (IR-8) : export de l'événement de plus grand seq dont la période est close, puis vérification.
    const destination = path.join(c.config.exports_dir, "premier");
    const ex = await ctl(["dossier", "exporter", "--dernier", "--vers", destination, "--configuration", fichier], opts());
    expect(ex.code, ex.stderr).to.equal(0);
    expect(ex.ligne.event).to.equal("dossier_exported");
    const v = spawnSync(process.execPath, [VERIFICATEUR_JS, destination, "--json"], { cwd: RACINE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    const rapport = JSON.parse(v.stdout);
    for (const n of [1, 2, 3]) expect(rapport.controls.find((x) => x.number === n)?.status, `contrôle ${n} : ${v.stdout.slice(0, 2000)}`).to.equal("reussi");
    // Journal terminé (EX-19.4), mode observation compris.
    for (const [outil, args] of [["demo__lire", { id: "E7-2" }], ["demo__ecrire", { id: "E7-3", valeur: 1 }]]) {
      const x = await appelerOutil(c.portHttp, c.env.NOORTRACE_TEST_JETON_HOTE, outil, args);
      expect(x.corps?.error?.code, `${outil} : ${JSON.stringify(x.corps)}`).to.equal(-31010);
      expect(x.corps.error.data.reason).to.equal("journal_clos");
    }
    const encore = await ctl(["close-period", "--now", "--configuration", fichier], opts());
    expect(encore.code).to.equal(1);
    expect(encore.ligne).to.deep.include({ event: "period_close_refused", data: { raison: "journal_clos", environment: "developpement", reasons: [] } });
    expect(encore.stderr).to.equal("noortrace-ctl close-period : le journal est déjà clos par une clôture anticipée : un nouveau journal est nécessaire (docker compose down -v, puis up)\n");
    const rot = await ctl(["cle", "rotation-urgence", "--configuration", fichier], opts());
    expect(rot.code).to.equal(1);
    expect(rot.ligne.data).to.deep.include({ raison: "journal_clos" });
    const manifestes = fs.readdirSync(path.join(repertoireJournal(c.config), "manifestes")).filter((n) => n.endsWith(".json")).sort();
    expect(manifestes.at(-1), "aucune clôture après la clôture anticipée").to.equal(`${nom}.json`);
  });

  it("redémarrage après la clôture anticipée : le journal reste terminé (dernier manifeste à generated_at < period_end) ; etat rend ok et époque 2 ; appel refusé -31010 journal_clos", async function () {
    await arreter(demon);
    const muet = await ctl(["etat", "--configuration", fichier], opts());
    expect(muet.code, "aucun démon : muet").to.equal(4);
    expect(muet.stderr).to.contain("(muet)");
    const sonde = await ctl(["sonde", "--url", `http://127.0.0.1:${c.portSante}/readyz`]);
    expect(sonde.code, "démon arrêté : sonde en échec").to.equal(1);
    demon = await demarrer(REFERENCE, c, fichier);
    const e = await ctl(["etat", "--configuration", fichier], opts());
    expect(e.code, e.stderr).to.equal(0);
    expect(e.ligne).to.deep.include({ status: "ok", readyz: 200, lease_epoch: 2 });
    const x = await appelerOutil(c.portHttp, c.env.NOORTRACE_TEST_JETON_HOTE, "demo__lire", { id: "E7-4" });
    expect(x.corps?.error?.code, JSON.stringify(x.corps)).to.equal(-31010);
    expect(x.corps.error.data.reason).to.equal("journal_clos");
  });

  it("etat : délai dépassé sur une écoute de supervision muette → code 4 (muet), la ligne du démon sans statut ; usage incorrect → code 2", async function () {
    const r = await ctl(["etat", "--configuration", fichier, "--delai-ms", "0"], opts());
    expect(r.code).to.equal(4);
    expect(r.ligne).to.deep.include({ pid: demon.pid, status: null, healthz: null });
    expect(r.stderr).to.match(/muet sur 127\.0\.0\.1:[0-9]+ \(délai écoulé\)/);
    for (const args of [["--configuration"], ["--delai-ms", "-1"], ["--autre", "x"]]) {
      const u = await ctl(["etat", ...args], opts());
      expect(u.code, args.join(" ")).to.equal(2);
    }
  });
});

describe("étape 7 — close-period --now refusée en production (CT-2 EX-19.4, CT-8 IR-8)", function () {
  this.timeout(60000);

  it("commande : un démon dont recorder.environment vaut production → code 1, message, aucune demande écrite, aucun signal envoyé", async function () {
    const dir = fs.mkdtempSync(path.join(TMP, "noortrace-etape7-prod-"));
    // Processus qui se présente comme le démon (`noortrace --config <fichier>`) et consigne tout SIGURG reçu.
    const config = { recorder: { environment: "production" }, supervision: { ops_log: { path: path.join(dir, "exploitation.ndjson") } } };
    const cheminConfig = path.join(dir, "configuration.json");
    fs.writeFileSync(cheminConfig, JSON.stringify(config));
    const temoin = path.join(dir, "signaux");
    const faux = spawn(process.execPath, ["-e", `process.on("SIGURG",()=>require("fs").appendFileSync(${JSON.stringify(temoin)},"SIGURG\\n"));setInterval(()=>{},1000);process.stdout.write("pret\\n")`, "noortrace", "--config", cheminConfig], { cwd: dir, stdio: ["ignore", "pipe", "ignore"] });
    try {
      await new Promise((r) => faux.stdout.once("data", r));
      const r = await ctl(["close-period", "--now", "--configuration", cheminConfig]);
      expect(r.code).to.equal(1);
      expect(r.ligne).to.deep.equal({ pid: faux.pid, configuration: fs.realpathSync(cheminConfig), event: null, data: null });
      expect(r.stderr).to.equal("noortrace-ctl close-period : refusée : la clôture anticipée n'est admise qu'en développement (CT-2 EX-19.4) ; recorder.environment vaut \"production\" ; rien n'est demandé au démon\n");
      await pause(300);
      expect(fs.existsSync(`${config.supervision.ops_log.path}.rotation-urgence`), "aucune demande").to.equal(false);
      expect(fs.existsSync(temoin), "aucun signal").to.equal(false);
      const u = await ctl(["close-period", "--configuration", cheminConfig]);
      expect(u.code, "sans --now : usage").to.equal(2);
    } finally {
      faux.kill("SIGKILL");
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("démon : la demande cloture-anticipee d'un démon de production est refusée sans rien clore (period_close_refused, raison production, request_id de la demande)", async function () {
    const lignes = [];
    let clos = false;
    const coeur = {
      config: { recorder: { environment: "production" } },
      journal: { consigner: (level, component, event, data, ctx) => lignes.push({ level, component, event, data, ...ctx }) },
      ecrivain: { cloreMaintenant: async () => { clos = true; } },
      passif: false,
      bailDetenu: true,
    };
    const r = await Coeur.prototype.clotureAnticipee.call(coeur, { request_id: "ab".repeat(16) });
    expect(r).to.deep.equal({ accepte: false, raison: "production" });
    expect(clos).to.equal(false);
    expect(lignes).to.deep.equal([{ level: "warning", component: "cloture", event: "period_close_refused", data: { raison: "production", environment: "production", reasons: [] }, seq: null, request_id: "ab".repeat(16) }]);
  });
});

describe("étape 7 — clôture anticipée dans le cœur, à horloge réglable (CT-2 EX-19.4, CT-1 P-3)", function () {
  this.timeout(60000);
  const DELEGATION = { launched_by: "agent", on_behalf_of: null, scope: "s", run_id: null };

  async function echange(coeur, n) {
    const p = pieceJson({ n });
    await coeur.ecrirePiece(p);
    return coeur.scellerEchange({ delegation: DELEGATION, code: { model: null, prompt_version: null }, intent: null, requete: p.reference, reponse: p.reference, duration_ms: 1, is_error: false });
  }

  it("période close à l'instant (generated_at < period_end), journal terminé : échange et pièce refusés -31010 journal_clos ; aucune clôture ni aucun point aux heures suivantes ; après redémarrage, toujours terminé", async function () {
    const dir = fs.mkdtempSync(path.join(TMP, "noortrace-etape7-coeur-"));
    try {
      const { config } = configurationDev(dir);
      const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)));
      expect(v.erreurs).to.deep.equal([]);
      const h = new HorlogeReglable(Date.UTC(2026, 10, 12, 10, 20, 0));
      let coeur = await Coeur.demarrer({ config: v.config, secrets: secretsDev(), horloge: h });
      try {
        const e = await echange(coeur, 1);
        const r = await coeur.clotureAnticipee({ request_id: "cd".repeat(16) });
        expect(r.accepte).to.equal(true);
        expect(r.periode).to.deep.include({ period_start: Date.UTC(2026, 10, 12, 10) / 1000, period_end: Date.UTC(2026, 10, 12, 11) / 1000, generated_at: "2026-11-12T10:20:00.000Z" });
        expect(r.periode.count).to.equal(e.seq);
        expect(coeur.journalClos).to.equal(true);
        let err = null;
        try {
          await echange(coeur, 2);
        } catch (x) {
          err = x;
        }
        expect(err).to.be.instanceOf(ErreurEnregistreur);
        expect(err.raison).to.equal("journal_clos");
        expect(err.code).to.equal(-31010);
        h.avancer(3 * 3600000);
        await coeur.ecrivain.tic();
        const rep = path.join(v.config.storage.root, v.config.recorder.org_id.slice(2), v.config.recorder.journal_id.slice(2));
        expect(fs.readdirSync(path.join(rep, "manifestes")).filter((n) => n.endsWith(".json"))).to.have.length(1);
        expect((await coeur.clotureAnticipee()).raison).to.equal("journal_clos");
      } finally {
        await coeur.arreter();
      }
      coeur = await Coeur.demarrer({ config: v.config, secrets: secretsDev(), horloge: h });
      try {
        expect(coeur.journalClos).to.equal(true);
        let err = null;
        try {
          await echange(coeur, 3);
        } catch (x) {
          err = x;
        }
        expect(err?.raison).to.equal("journal_clos");
      } finally {
        await coeur.arreter();
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("journal sans événement : l'écrivain refuse journal_vide (raison rendue par la commande) sans rien clore ; un journal clos à l'heure pleine (generated_at ≥ period_end) n'est pas terminé", async function () {
    const { Ecrivain } = await REFERENCE.importer("ecrivain.mjs");
    const sansPeriode = Object.assign(Object.create(Ecrivain.prototype), {
      clos: false, periode: null, segment: {}, degrade: { actif: () => false }, horloge: { murale: () => Date.UTC(2026, 10, 12, 10, 20), controlerAvance: () => true },
    });
    let err = null;
    try {
      await sansPeriode._cloreAnticipee();
    } catch (x) {
      err = x;
    }
    expect(err?.raison).to.equal("journal_vide");
    expect(sansPeriode.clos).to.equal(false);
    const dir = fs.mkdtempSync(path.join(TMP, "noortrace-etape7-heure-"));
    try {
      const { config } = configurationDev(dir);
      const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)));
      const h = new HorlogeReglable(Date.UTC(2026, 10, 12, 10, 20, 0));
      let coeur = await Coeur.demarrer({ config: v.config, secrets: secretsDev(), horloge: h });
      try {
        await echange(coeur, 1);
        h.avancer(3600000);
        await coeur.ecrivain.tic();
        expect(coeur.journalClos).to.equal(false);
        expect((await echange(coeur, 2)).seq).to.be.above(1);
      } finally {
        await coeur.arreter();
      }
      coeur = await Coeur.demarrer({ config: v.config, secrets: secretsDev(), horloge: h });
      try {
        expect(coeur.journalClos, "clôture à l'heure pleine : journal non terminé au redémarrage").to.equal(false);
        await echange(coeur, 3);
      } finally {
        await coeur.arreter();
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
