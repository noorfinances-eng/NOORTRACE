// TI-19 de CT-9 : mode ICAP, raccord à un mandataire d'interception réel
// (CT-2 §19.6, EX-5.3 à EX-5.5, EX-5.8 ; CT-8 EX-5.4). Squid 6.13 construit
// avec OpenSSL (paquet Debian `squid-openssl` à version exacte, image du
// Dockerfile de test/fixtures/enregistreur-modele/squid, base épinglée par
// condensé) déchiffre par ssl-bump le trafic d'un client de test vers le
// fournisseur simulé servi en HTTPS sous `api.fournisseur.example`, et parle
// ICAP (REQMOD et RESPMOD, `icap_send_client_ip`) au démon réel
// `bin/noortrace --config` en mode `icap`. Le lien ICAP est en clair
// (127.0.0.1) et relevé par un relais qui garde les octets de chaque sens.
//
//   1. Référence : le même échange de modèle hors flux (échange n° 1 de CT-2
//      §19.2, `POST /v1/messages`) joué par la passerelle d'un démon réel en
//      mode `passerelle`, route vers le même nom, avec `X-Noortrace-Token` et
//      `X-Noortrace-Run-Id`.
//   2. Le même échange par Squid et ICAP, l'hôte non reconfiguré n'envoyant
//      aucun en-tête `X-Noortrace-*` ; il est rattaché par son adresse
//      (`source_addresses`, en-tête `X-Client-IP` posé par Squid).
//   3. Adresse d'hôte hors de `model.hosts` : entrée `inconnu` déclarée, puis
//      sans elle (blocage en REQMOD).
//   4. Client ICAP hors d'`allowed_sources` : refusé.
//   5. Une instance du cœur clôt la période à l'heure suivante ; le journal
//      est accepté par le noyau ; les dossiers de l'échange en passerelle et
//      de l'échange par ICAP sont valides pour le noyau ET pour le binaire Go
//      `noortrace-verifier` (go1.27.3, NOORTRACE_GO_BIN ; sans lui, cette
//      dernière vérification est en attente).
// Les démons écoutent sur le port 0 et leurs adresses réelles sont lues dans
// leur journal d'exploitation (`model_gateway_listening`,
// `model_icap_listening`). Le démon résout `*.example` vers 127.0.0.1 par un
// module chargé à son lancement (`--import`), Squid par `--add-host`.
// Sans Docker (ou sans l'image), ou sans openssl, tout est en attente et le
// titre nomme la condition.

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import * as N from "@noortrace/noyau";
import { verifierRepertoireDossier } from "@noortrace/noyau/dossier-fichiers";
import { Coeur, ServeurIcap, lireEvenements } from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { RACINE, BIN_NOORTRACE, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationModele, configurationIcap, hoteParAdresse, valider, demarrerCoeur, JETON_MODELE } from "./fixtures/enregistreur-modele/outils.mjs";
import { FournisseurSimule } from "./fixtures/enregistreur-modele/fournisseur.mjs";
import {
  VERSION_SQUID, RESOLUTION_EXAMPLE, NOM_FOURNISSEUR, imageSquid, opensslDisponible, autorites, lancerSquid, arreterSquid, relaisIcap, appelParSquid,
} from "./fixtures/enregistreur-modele/squid/squid.mjs";

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const OUTIL_ECHANGE = "noortrace.modele.echange";
const RUN_ID = "run-ti19-0001";
/** Échange n° 1 de CT-2 §19.2 (hors flux) : le modèle simulé demande un outil. */
const MSG = {
  model: "modele-demo-1",
  max_tokens: 256,
  system: "Agent de démonstration : consulter le sinistre avant de répondre.",
  messages: [{ role: "user", content: "Où en est le sinistre 2026-81044 ?" }],
  tools: [{ name: "demo__claims_get", description: "Lire un sinistre", input_schema: { type: "object", properties: { claim_id: { type: "string" } }, required: ["claim_id"] } }],
};
const ENTETES = { "content-type": "application/json", "anthropic-version": "2023-06-01", "accept-encoding": "identity" };

/** Construit noortrace-verifier avec go1.27.3 (GOFLAGS limité à cette commande), ou rend null. */
function construireVerificateur(dir) {
  const dirGo = process.env.NOORTRACE_GO_BIN ?? null;
  const env = { ...process.env, GOTOOLCHAIN: "local" };
  if (dirGo) env.PATH = `${dirGo}${path.delimiter}${env.PATH}`;
  const v = spawnSync("go", ["version"], { env, encoding: "utf8" });
  if (v.status !== 0 || !/go1\.27\.3 /.test(v.stdout)) return null;
  const sortie = path.join(dir, "noortrace-verifier");
  execFileSync(path.join(RACINE, "verificateur", "scripts", "construire.sh"), ["-o", sortie], { env: { ...env, GOFLAGS: "-mod=vendor" }, cwd: path.join(RACINE, "verificateur"), stdio: "pipe" });
  return sortie;
}

/** Horloge réelle décalée dans l'heure suivante, de moins d'une heure. */
function horlogeHeureSuivante() {
  const d = 3600000 - (Date.now() % 3600000) + 3000;
  return { murale: () => Date.now() + d, monotone: () => performance.now() + 1e7 + d };
}

const lignesOps = (f) => (fs.existsSync(f) ? fs.readFileSync(f, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);

/** POST HTTP vers la passerelle du démon ; rend { statut, entetes, corps }. */
function posterPasserelle(port, chemin, entetes, corps) {
  return new Promise((res, rej) => {
    const q = http.request({ host: "127.0.0.1", port, path: chemin, method: "POST", headers: entetes }, (x) => {
      const m = [];
      x.on("data", (k) => m.push(k));
      x.on("end", () => res({ statut: x.statusCode, entetes: x.headers, corps: Buffer.concat(m) }));
    });
    q.on("error", rej);
    q.end(corps);
  });
}

describe("TI-19 — mode ICAP : raccord à un mandataire Squid réel (ssl-bump, REQMOD et RESPMOD) ; échange comparé à la passerelle ; sources ICAP admises et refusées ; adresse d'hôte inconnue ; dossiers vérifiés par les deux vérificateurs", function () {
  this.timeout(900000);
  let cond = { ok: true, condition: null };
  let dir;
  let cles;
  let fournisseur;
  let serveurTls;
  let portFournisseur;
  let service;
  let serveurService;
  let relais;
  let bin = null;
  const demons = new Set();
  const conteneurs = new Set();
  const ev = { phases: {} };

  /** Démon réel `bin/noortrace --config` ; attend la ligne d'écoute du frontal modèle et rend son adresse réelle. */
  async function lancerDemon(nom, config, env) {
    const fichier = path.join(dir, `${nom}.json`);
    fs.writeFileSync(fichier, JSON.stringify(config));
    const ops = config.supervision.ops_log.path;
    const p = spawn(process.execPath, [BIN_NOORTRACE, "--config", fichier], {
      env: {
        ...process.env,
        ...env,
        // Confiance dans l'autorité du fournisseur simulé ; `*.example` → 127.0.0.1.
        NODE_EXTRA_CA_CERTS: cles.caFournisseur,
        NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ""} --import=${pathToFileURL(RESOLUTION_EXAMPLE).href}`.trim(),
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    demons.add(p);
    p.sortie = "";
    p.stdout.on("data", (d) => (p.sortie += d));
    p.stderr.on("data", (d) => (p.sortie += d));
    p.fin = new Promise((r) => p.on("exit", (code, signal) => r({ code, signal })));
    p.lignes = () => lignesOps(ops);
    const attendue = config.model.mode === "icap" ? "model_icap_listening" : "model_gateway_listening";
    const limite = Date.now() + 60000;
    for (;;) {
      const l = p.lignes().find((x) => x.event === attendue);
      if (l && /demon demarre/.test(p.sortie)) {
        p.port = Number(l.data.address.split(":").at(-1));
        return p;
      }
      if (p.exitCode !== null || Date.now() > limite) {
        p.kill("SIGKILL");
        throw new Error(`démon ${nom} non démarré : ${p.sortie.slice(-3000)}`);
      }
      await pause(50);
    }
  }

  async function arreterDemon(p) {
    if (!p || p.exitCode !== null || p.signalCode !== null) return null;
    p.kill("SIGTERM");
    const t = setTimeout(() => p.kill("SIGKILL"), 10000);
    const fin = await p.fin;
    clearTimeout(t);
    demons.delete(p);
    return fin;
  }

  /** Configuration validée d'un démon ; même journal, même stockage, même bail pour toutes. */
  function configuration(nom, mode, modifier = () => {}) {
    const url = `https://${NOM_FOURNISSEUR}:${portFournisseur}`;
    const c = mode === "icap" ? configurationIcap(dir, url) : configurationModele(dir, url);
    c.config.recorder.instance_id = `inst-${nom}`;
    c.config.supervision.ops_log.path = path.join(dir, `exploitation-${nom}.ndjson`);
    c.config.policy.approval.service = { url: `http://127.0.0.1:${serveurService.address().port}`, socket: null, token: { env: "NOORTRACE_TEST_JETON_APPROBATION" }, peer_user: null };
    c.env.NOORTRACE_TEST_JETON_APPROBATION = "jeton-approbation-de-test";
    modifier(c.config);
    const { config, secrets } = valider(c.config, c.env);
    return { config, env: c.env, secrets };
  }

  /** Une phase ICAP : démon en mode icap, relais visé, Squid lancé, échange par Squid ; tout est arrêté ensuite. */
  async function phaseIcap(nom, modifier) {
    const { config, env } = configuration(nom, "icap", modifier);
    const d = await lancerDemon(nom, config, env);
    relais.viser(d.port);
    const marque = relais.marque();
    const nomSquid = `noortrace-test-ti19-squid-${process.pid}-${nom}`;
    conteneurs.add(nomSquid);
    const avant = fournisseur.requetes.length;
    let reponse;
    let squid;
    try {
      squid = await lancerSquid(nomSquid, cles.dir, relais.port);
      fournisseur.compteur = 0;
      reponse = await appelParSquid(squid.port, { port: portFournisseur, chemin: "/v1/messages", entetes: { ...ENTETES, "x-api-key": "cle-agent-fictive-de-test" }, corps: JSON.stringify(MSG), ca: cles.interception });
      await pause(500);
    } finally {
      ev.phases[nom] = { journalSquid: squid?.journal() ?? null };
      arreterSquid(nomSquid);
      conteneurs.delete(nomSquid);
    }
    const fin = await arreterDemon(d);
    Object.assign(ev.phases[nom], { reponse, fin, lignes: d.lignes(), icap: relais.messages(marque), requetesFournisseur: fournisseur.requetes.slice(avant), sortie: d.sortie });
    return ev.phases[nom];
  }

  before(async function () {
    if (!opensslDisponible()) {
      cond = { ok: false, condition: "openssl absent" };
      return;
    }
    cond = imageSquid();
    if (!cond.ok) return;
    dir = repertoireTemporaire("noortrace-ti19-");
    cles = autorites(path.join(dir, "squid"));
    // Fournisseur simulé servi en HTTPS sous api.fournisseur.example.
    fournisseur = new FournisseurSimule({ pauseMs: 2 });
    serveurTls = https.createServer({ key: fs.readFileSync(cles.fournisseurCle), cert: fs.readFileSync(cles.fournisseur) }, (req, res) => fournisseur._servir(req, res).catch(() => res.destroy()));
    await new Promise((r) => serveurTls.listen(0, "127.0.0.1", r));
    portFournisseur = serveurTls.address().port;
    service = new ServiceApprobationFactice({ org_id: "0x00", journal_id: null });
    serveurService = await service.servir(0);
    relais = await relaisIcap();
    bin = construireVerificateur(dir);

    // 1. Référence : la passerelle d'un démon réel, route vers le même nom.
    {
      const { config, env } = configuration("passerelle", "passerelle");
      service.org_id = config.recorder.org_id;
      service.journal_id = config.recorder.journal_id;
      ev.repertoire = path.join(config.storage.root, config.recorder.org_id.slice(2), config.recorder.journal_id.slice(2));
      const d = await lancerDemon("passerelle", config, env);
      fournisseur.compteur = 0;
      const avant = fournisseur.requetes.length;
      ev.passerelle = await posterPasserelle(d.port, "/v1/messages", { ...ENTETES, "x-noortrace-token": JETON_MODELE, "x-noortrace-run-id": RUN_ID }, JSON.stringify(MSG));
      await pause(500);
      ev.passerelleFin = await arreterDemon(d);
      ev.passerelleLignes = d.lignes();
      ev.passerelleRequetes = fournisseur.requetes.slice(avant);
      ev.evtsPasserelle = await lireEvenements(ev.repertoire);
    }
    // 2. Le même échange par Squid et ICAP (hôte rattaché par son adresse).
    await phaseIcap("icap");
    ev.evtsIcap = await lireEvenements(ev.repertoire);
    // 3. Adresse d'hôte hors de model.hosts : entrée « inconnu » déclarée, puis sans elle.
    const ailleurs = (c) => {
      c.model.hosts = [hoteParAdresse("agent-adresse", ["198.51.100.0/24"])];
    };
    await phaseIcap("inconnu", (c) => {
      ailleurs(c);
      // Forme du `match` de l'entrée « inconnu » (non fixée par CT-2 EX-5.8, PD-26) : une plage
      // d'adresses qui ne contient pas le client ; c'est l'`id` qui la désigne.
      c.model.hosts.push({ ...hoteParAdresse("inconnu", ["192.0.2.0/24"]), launched_by: "hote-inconnu", host_group: "inconnu" });
    });
    ev.evtsInconnu = await lireEvenements(ev.repertoire);
    await phaseIcap("bloque", ailleurs);
    ev.evtsBloque = await lireEvenements(ev.repertoire);
    // 4. Client ICAP hors d'allowed_sources.
    await phaseIcap("source", (c) => {
      c.model.icap.allowed_sources = ["192.0.2.0/24"];
    });
    ev.evtsSource = await lireEvenements(ev.repertoire);
    // 5. Clôture de la période à l'heure suivante par une instance du cœur.
    const k = configuration("cloture", "passerelle");
    ev.C = await Coeur.demarrer({ config: k.config, secrets: k.secrets, horloge: horlogeHeureSuivante() });
    await ev.C.tic();
    ev.evts = await lireEvenements(ev.repertoire);
  });

  after(async function () {
    for (const n of conteneurs) arreterSquid(n);
    for (const p of demons) p.kill("SIGKILL");
    await ev.C?.arreter();
    await relais?.fermer();
    serveurService?.close();
    if (serveurTls) {
      serveurTls.closeAllConnections?.();
      await new Promise((r) => serveurTls.close(() => r()));
    }
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  beforeEach(function () {
    if (!cond.ok) {
      this.currentTest.title += ` — en attente : ${cond.condition}`;
      this.skip();
    }
  });

  const echanges = (evts) => evts.filter((e) => e.execution.tool === OUTIL_ECHANGE);
  const nouveaux = (avant, apres) => echanges(apres).filter((e) => !avant.some((x) => x.seq === e.seq));
  const ref = (r) => ({ sha256: r.sha256, length: r.length, redacted: r.redacted });
  /** Messages ICAP d'une phase, requête et réponse appariées dans l'ordre de chaque connexion. */
  const transactions = (phase) => phase.icap.flatMap((c) => c.requetes.map((q, k) => ({ requete: q, reponse: c.reponses[k] ?? null })));

  it("chaque échange produit un événement ; égalité, entre la passerelle (référence) et Squid par ICAP, de code.model, code.prompt_version, des pièces « requête » et « réponse » (sha256, length, redacted) et d'execution.is_error ; écarts consignés : run_id nul en ICAP, hôte rattaché par source_addresses (X-Client-IP de Squid), même groupe d'hôte", function () {
    expect(ev.passerelle.statut, ev.passerelle.corps.toString("utf8")).to.equal(200);
    const icap = ev.phases.icap;
    expect(icap.reponse.statut, icap.reponse.corps.toString("utf8")).to.equal(200);
    // L'agent reçoit la même réponse du fournisseur dans les deux modes, qui a reçu le même corps.
    expect(JSON.parse(icap.reponse.corps.toString("utf8"))).to.deep.equal(JSON.parse(ev.passerelle.corps.toString("utf8")));
    expect(ev.passerelleRequetes).to.have.length(1);
    expect(icap.requetesFournisseur).to.have.length(1);
    expect(icap.requetesFournisseur[0].brut.equals(ev.passerelleRequetes[0].brut)).to.equal(true);
    // Aucun jeton ni run_id noortrace ne part chez le fournisseur ; en ICAP, la requête adaptée porte X-Noortrace-Exchange (EX-5.4).
    expect(Object.keys(ev.passerelleRequetes[0].entetes).filter((k) => k.startsWith("x-noortrace-"))).to.deep.equal([]);
    expect(Object.keys(icap.requetesFournisseur[0].entetes).filter((k) => k.startsWith("x-noortrace-"))).to.deep.equal(["x-noortrace-exchange"]);
    const [eP] = echanges(ev.evtsPasserelle);
    expect(echanges(ev.evtsPasserelle)).to.have.length(1);
    const nI = nouveaux(ev.evtsPasserelle, ev.evtsIcap);
    expect(nI).to.have.length(1);
    const eI = nI[0];
    expect(eI.code.model).to.equal(eP.code.model);
    expect(eI.code.prompt_version).to.equal(eP.code.prompt_version);
    expect(ref(eI.execution.arguments)).to.deep.equal(ref(eP.execution.arguments));
    expect(ref(eI.execution.result)).to.deep.equal(ref(eP.execution.result));
    expect(eI.execution.is_error).to.equal(eP.execution.is_error);
    expect(eP.execution.is_error).to.equal(false);
    expect(eP.code.model).to.equal(`anthropic/${MSG.model}`);
    // Écarts attendus (EX-3.4 de CT-9) : run_id déclaré en passerelle seulement ; même délégation sinon.
    expect(eP.delegation.run_id).to.equal(RUN_ID);
    expect(eI.delegation).to.deep.equal({ ...eP.delegation, run_id: null });
    const hote = (lignes) => lignes.filter((l) => l.event === "model_exchange_relayed").map((l) => l.host);
    expect(hote(ev.passerelleLignes)).to.deep.equal(["agent-modele"]);
    expect(hote(icap.lignes)).to.deep.equal(["agent-adresse"]);
    for (const p of [ev.passerelleFin, icap.fin]) expect(p).to.deep.equal({ code: 0, signal: null });
  });

  it(`lien ICAP relevé (Squid ${VERSION_SQUID}) : OPTIONS avec Methods, ISTag et Encapsulated: null-body=0 ; ISTag sur toute réponse ; aucune réponse 204 en REQMOD ni en RESPMOD ; X-Client-IP posé ; la requête encapsulée par RESPMOD porte le X-Noortrace-Exchange émis en REQMOD (corrélation sans heuristique, EX-5.4)`, function () {
    const toutes = Object.values(ev.phases).flatMap(transactions);
    expect(toutes.length).to.be.greaterThan(0);
    for (const t of toutes) {
      expect(t.reponse, t.requete.icap.premiere).to.not.equal(null);
      expect(t.reponse.entetes.istag, t.reponse.premiere).to.match(/^"noortrace-[0-9.]+"$/);
    }
    for (const t of toutes.filter((x) => x.requete.methode === "OPTIONS" && x.reponse.statut === 200)) {
      const service = t.requete.icap.premiere.includes("/noortrace/reqmod") ? "REQMOD" : "RESPMOD";
      expect(t.reponse.entetes).to.include({ methods: service, encapsulated: "null-body=0" });
    }
    for (const t of toutes.filter((x) => x.requete.methode !== "OPTIONS")) expect(t.reponse.statut, t.requete.methode).to.not.equal(204);
    const icap = transactions(ev.phases.icap);
    expect(icap.filter((t) => t.requete.methode === "OPTIONS").map((t) => t.reponse.statut)).to.deep.equal([200, 200]);
    const reqmod = icap.filter((t) => t.requete.methode === "REQMOD");
    const respmod = icap.filter((t) => t.requete.methode === "RESPMOD");
    expect(reqmod).to.have.length(1);
    expect(respmod).to.have.length(1);
    expect(reqmod[0].reponse.statut).to.equal(200);
    expect(reqmod[0].reponse.entetes.encapsulated).to.match(/^req-hdr=0, req-body=[0-9]+$/);
    expect(respmod[0].reponse.statut).to.equal(200);
    expect(respmod[0].reponse.entetes.encapsulated).to.match(/^res-hdr=0, res-body=[0-9]+$/);
    expect(reqmod[0].requete.icap.entetes["x-client-ip"]).to.equal("127.0.0.1");
    // L'hôte non reconfiguré n'envoie aucun en-tête X-Noortrace-* (CT-2 EX-5.8).
    expect(Object.keys(reqmod[0].requete.reqHdr.entetes).filter((k) => k.startsWith("x-noortrace-"))).to.deep.equal([]);
    const echangeRespmod = respmod[0].requete.reqHdr?.entetes["x-noortrace-exchange"];
    expect(echangeRespmod).to.match(/^[0-9a-f]{32}\.[0-9a-f]{32}$/);
    expect(echangeRespmod).to.equal(ev.phases.icap.requetesFournisseur[0].entetes["x-noortrace-exchange"]);
    const evenementsOps = ev.phases.icap.lignes.map((l) => l.event);
    expect(evenementsOps.filter((e) => ["icap_correlation_heuristique", "icap_requete_inconnue", "icap_respmod_non_capture", "model_route_not_found"].includes(e))).to.deep.equal([]);
  });

  it("adresse d'hôte hors de model.hosts (CT-2 EX-5.8) : rattachée à l'entrée « inconnu » déclarée (forme du match consignée : source_addresses d'une plage qui ne contient pas le client) — un événement ; sans elle, bloquée en REQMOD par une réponse HTTP encapsulée — aucun événement, rien chez le fournisseur, ligne consignée", function () {
    const inc = ev.phases.inconnu;
    expect(inc.reponse.statut).to.equal(200);
    const n = nouveaux(ev.evtsIcap, ev.evtsInconnu);
    expect(n).to.have.length(1);
    expect(n[0].delegation).to.include({ launched_by: "hote-inconnu", run_id: null });
    expect(inc.lignes.filter((l) => l.event === "model_exchange_relayed").map((l) => l.host)).to.deep.equal(["inconnu"]);
    const bl = ev.phases.bloque;
    expect(nouveaux(ev.evtsInconnu, ev.evtsBloque)).to.deep.equal([]);
    expect(bl.requetesFournisseur).to.deep.equal([]);
    const reqmod = transactions(bl).filter((t) => t.requete.methode === "REQMOD");
    expect(reqmod).to.have.length(1);
    expect(reqmod[0].reponse.statut).to.equal(200);
    expect(reqmod[0].reponse.entetes.encapsulated).to.match(/^res-hdr=0, res-body=[0-9]+$/);
    expect(transactions(bl).filter((t) => t.requete.methode === "RESPMOD")).to.deep.equal([]);
    // Statut encapsulé et ligne non fixés par CT-2 (PD-26) : ceux du démon, consignés, et rendus à l'agent par Squid.
    const ligne = bl.lignes.filter((l) => l.event === "auth_failed");
    expect(ligne).to.have.length(1);
    expect(ligne[0].data).to.include({ transport: "icap", reason: "hote_inconnu" });
    expect(bl.reponse.statut).to.equal(ligne[0].data.status);
    expect(bl.fin).to.deep.equal({ code: 0, signal: null });
  });

  it("client ICAP hors d'allowed_sources (CT-2 EX-5.3) : Squid refusé (403, ISTag), aucun événement, rien chez le fournisseur, l'agent reçoit l'erreur de Squid, ligne consignée ; le démon s'arrête proprement (la connexion refusée ne le retient pas)", function () {
    const so = ev.phases.source;
    expect(nouveaux(ev.evtsBloque, ev.evtsSource)).to.deep.equal([]);
    expect(so.requetesFournisseur).to.deep.equal([]);
    const t = transactions(so);
    expect(t.length).to.be.greaterThan(0);
    for (const x of t) expect(x.reponse.statut, x.requete.icap.premiere).to.equal(403);
    expect(t.filter((x) => x.requete.methode !== "OPTIONS")).to.deep.equal([]);
    expect(so.reponse.statut).to.be.at.least(500);
    const l = so.lignes.filter((x) => x.event === "auth_failed");
    expect(l.length).to.be.at.least(1);
    for (const x of l) expect(x.data).to.deep.equal({ transport: "icap", reason: "client_icap_refuse" });
    expect(so.fin).to.deep.equal({ code: 0, signal: null });
  });

  it("période close à l'heure suivante : journal accepté par le noyau ; dossiers de l'échange en passerelle et de l'échange par ICAP valides pour le noyau ET pour le binaire Go (go1.27.3)", async function () {
    const [eP] = echanges(ev.evtsPasserelle);
    const [eI] = nouveaux(ev.evtsPasserelle, ev.evtsIcap);
    expect(ev.evts.map((e) => e.seq)).to.deep.equal(ev.evts.map((_, k) => k + 1));
    const dossiers = [];
    for (const [nom, e] of [["passerelle", eP], ["icap", eI]]) {
      const d = path.join(dir, `dossier-${nom}`);
      await ev.C.exporterDossier(e.seq, d);
      if (nom === "passerelle") {
        const cles = JSON.parse(fs.readFileSync(path.join(d, "cles.json"), "utf8"));
        const j = N.verifierJournal(ev.evts, cles);
        expect(j.valide, JSON.stringify(j.diagnostics)).to.equal(true);
      }
      const r = verifierRepertoireDossier(d);
      expect(r.verdict, `${nom} : ${JSON.stringify(r.controles_en_echec)}`).to.equal("valide");
      dossiers.push(d);
    }
    if (!bin) {
      this.test.title += " — binaire Go en attente : go1.27.3 introuvable (NOORTRACE_GO_BIN)";
      this.skip();
    }
    for (const d of dossiers) {
      const r = spawnSync(bin, [d, "--json"], { encoding: "utf8" });
      expect(r.status, r.stdout + r.stderr).to.equal(0);
      const rapport = JSON.parse(r.stdout);
      expect(rapport.verdict).to.equal("valide");
      expect(rapport.failed_checks).to.deep.equal([]);
    }
  });
});

describe("TI-19, défaut révélé : client ICAP refusé qui garde sa moitié de connexion ouverte (CT-2 EX-5.3) — le serveur ICAP détruit la prise après le 403 et s'arrête sans attendre le délai de drain", function () {
  this.timeout(60000);
  let dir;
  let coeur;
  let serveur;

  before(async function () {
    dir = repertoireTemporaire("noortrace-ti19-refus-");
    const c = configurationIcap(dir, "http://127.0.0.1:9", { icap: { allowed_sources: ["192.0.2.0/24"] } });
    c.config.mcp.drain_timeout_ms = 10000;
    const { config, secrets } = valider(c.config, c.env);
    ({ coeur } = await demarrerCoeur(config, secrets));
    serveur = new ServeurIcap({ coeur, config });
    await serveur.ecouter();
  });

  after(async function () {
    await coeur?.arreter();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("403 avec ISTag, prise fermée par le serveur alors que le client garde son côté ouvert ; arrêt du serveur en moins d'une seconde", async function () {
    const client = net.connect({ host: "127.0.0.1", port: serveur.adresses()[0].port, allowHalfOpen: true });
    let recu = "";
    client.on("data", (d) => (recu += d));
    await new Promise((r) => client.once("connect", r));
    client.write("OPTIONS icap://127.0.0.1/noortrace/reqmod ICAP/1.0\r\nEncapsulated: null-body=0\r\n\r\n");
    await new Promise((r) => client.once("end", r));
    expect(recu.split("\r\n")[0]).to.equal("ICAP/1.0 403 Forbidden");
    expect(recu).to.match(/\r\nISTag: "noortrace-[0-9.]+"\r\n/);
    await pause(300);
    expect(serveur.prises.size, "prise du client refusé encore ouverte côté serveur").to.equal(0);
    const t0 = Date.now();
    await serveur.arreter();
    expect(Date.now() - t0).to.be.below(1000);
    client.destroy();
  });
});
