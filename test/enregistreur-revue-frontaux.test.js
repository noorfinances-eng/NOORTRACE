// Revue de sécurité interne de l'étape 8 (enregistreur : frontaux MCP et
// SDK, prises, commandes). Chaque `it` nomme l'exigence ou le défaut qu'il reproduit ;
// chaque essai échoue sur le code d'avant la correction et passe après.
//
//     progression d'un serveur relayée au seul hôte qui a appelé ce serveur
//   EX-4.11   exception à l'envoi amont : appel terminé en perte, jamais laissé en vol ; en-tête Mcp-Param-* invalide jamais construit
//   EX-4.21   enregistrement de continuation pour un résultat `input_required` seulement
//   EX-4.47    sortie de la raison `serveur:<alias>` consignée (`upstream_reachable`, EX-14.7)
//   EX-16.2   `tool_call_relayed` porte t_recu_ms, t_envoi_ms, t_reponse_ms, t_fdatasync_ms (CT-2 EX-16.2 pas 4)
//      prise locale : jamais supprimée à l'arrêt, chemin tenu par un autre compte refusé au démarrage,
//             propriétaire de la prise vérifié par le connecteur et le SDK
//   EX-18.3    délai d'identification et borne des connexions non identifiées sur les prises
//      preuve par fichier refusée quand l'instant de création n'est pas disponible
//      fichier de demande de noortrace-ctl : propriétaire contrôlé
//   CT-7 MN-99    répertoire temporaire d'un export : propriétaire contrôlé dans tout environnement

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import http from "node:http";
import path from "node:path";
import { PassThrough } from "node:stream";
import * as N from "@noortrace/noyau";
import * as E from "@noortrace/enregistreur";
import { ClientNoortrace, ErreurNoortraceIndisponible } from "noortrace-sdk";
import { repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationMcp, serveurStdio, hoteDemo, RedacteurTest, ServiceFixe, AUTORISE, EnfantFactice, laisserTourner } from "./fixtures/enregistreur-mcp/outils.mjs";
// Espaces de noms : les fonctions nouvelles manquent dans le code d'avant la correction (rejeu), chaque essai échoue alors par son oracle.
import * as DD from "../paquets/enregistreur/src/demandes-demon.mjs";
import * as ED from "../paquets/enregistreur/src/export-dossier.mjs";
const { preleverFichierDemande } = DD;
const controlerRepertoireTemporaire = ED.controlerRepertoireTemporaire ?? (() => undefined);

const { Coeur, HorlogeReglable, FrontalMcp, validerConfiguration, lireEvenements, ServeurConnecteurs, ServeurSdk, executerConnecteur, verifierPreuveFichier } = E;

const META = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} };
const ligne = (o) => JSON.stringify(o);
const appel = (id, nom, args, meta = META, extra = {}) => ligne({ jsonrpc: "2.0", id, method: "tools/call", params: { name: nom, arguments: args, ...extra, _meta: meta } });
const OUTIL = (n, lecture = true) => [{ name: n, description: n, inputSchema: { type: "object" }, annotations: { readOnlyHint: lecture } }];
/** Un compte qui n'est ni le démon ni root : `nobody` (65534) ; les essais de propriétaire exigent le compte 0. */
const UID_AUTRE = 65534;
const estRoot = typeof process.getuid === "function" && process.getuid() === 0;

/**
 * Banc du frontal MCP (cœur réel, serveurs stdio factices), repris des essais
 * du frontal : `servers`, `outils` par alias, `hosts`, `repondre(m, enfant, alias)`.
 */
async function banc(o = {}) {
  const dir = repertoireTemporaire("noortrace-revue-frontaux-");
  const servers = o.servers ?? { demo: serveurStdio(["/opt/mcp/demo"], { protocol: "2026-07-28" }) };
  const outils = o.outils ?? { demo: OUTIL("claims.get") };
  const { config: brute } = configurationMcp(dir, { servers, hosts: o.hosts, limits: o.limits });
  if (o.ajuster) o.ajuster(brute);
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(brute)));
  expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
  const horloge = new HorlogeReglable(N.decoderHorodatage("2026-11-10T10:20:00.000Z"));
  const service = new ServiceFixe(() => AUTORISE, []);
  const coeur = await Coeur.demarrer({ config: v.config, secrets: secretsDev(), horloge, service });
  const enfants = {};
  const ecrit = [];
  const alias = Object.keys(servers);
  let ordre = 0;
  const repondre = o.repondre ?? ((m) => ({ content: [{ type: "text", text: `ok ${m.params.name}` }], isError: false }));
  const lanceur = () => {
    const nom = alias[ordre++] ?? `x${ordre}`;
    const e = new EnfantFactice((l, enfant) => {
      ecrit.push({ serveur: nom, ligne: l });
      const m = JSON.parse(l);
      if (m.id === undefined) return;
      let r;
      if (m.method === "server/discover") r = { result: { supportedVersions: ["2026-07-28"] } };
      else if (m.method === "tools/list") r = { result: { tools: outils[nom] ?? [], ttlMs: 60000 } };
      else if (m.method === "subscriptions/listen") r = null;
      else {
        const x = repondre(m, enfant, nom);
        r = x === null || x === undefined ? null : x.error || x.result !== undefined ? x : { result: x };
      }
      if (r) setImmediate(() => enfant.repondre(JSON.stringify({ jsonrpc: "2.0", id: m.id, ...r })));
    });
    enfants[nom] = e;
    return e;
  };
  const frontal = new FrontalMcp({ coeur, redacteur: new RedacteurTest(), lanceur });
  for (const a of alias) frontal.chargerListe(a, outils[a] ?? [], { ttlMs: 60000, ere: "moderne" });
  const sessions = v.config.mcp.hosts.map((hote) => {
    const emis = [];
    const session = frontal.ouvrirSession({ hote, identite: { peer_user: hote.match.peer_user }, transport: "stdio", emettre: (x) => emis.push(x) });
    return { hote, session, emis, recevoir: async (texte) => { const r = await frontal.recevoir(session, texte); return r === null ? null : JSON.parse(r); } };
  });
  const evenements = async () => (await lireEvenements(coeur.repertoire)).filter((e) => !e.execution.tool.startsWith("noortrace."));
  const fermer = async () => {
    await frontal.arreter();
    await coeur.arreter();
    fs.rmSync(dir, { recursive: true, force: true });
  };
  return { dir, config: v.config, coeur, frontal, sessions, enfants, ecrit, evenements, fermer, lignes: (ev) => coeur.journal.trouver(ev) };
}

// Attend qu'une condition soit vraie, au plus `ms` millisecondes : un délai fixe
// ne suffit pas sur une machine chargée (relais, écriture durable de l'intention).
async function attendreQue(cond, description, ms = 10000) {
  const limite = Date.now() + ms;
  for (;;) {
    const v = cond();
    if (v) return v;
    if (Date.now() > limite) throw new Error(`${description} : non atteint en ${ms} ms`);
    await laisserTourner(10);
  }
}

describe("enregistreur, revue (étape 8) : frontaux, prises et commandes", function () {
  this.timeout(60000);

  describe("notifications de progression d'un serveur d'outils", function () {
    it("une notifications/progress du serveur « meteo » dont le jeton est celui d'un appel en vol vers « banque » n'est pas relayée à l'hôte (server_progress_refused) ; celle du serveur appelé l'est", async function () {
      const b = await banc({
        servers: { banque: serveurStdio(["/opt/mcp/banque"], { protocol: "2026-07-28" }), meteo: serveurStdio(["/opt/mcp/meteo"], { protocol: "2026-07-28" }) },
        outils: { banque: OUTIL("lire"), meteo: OUTIL("prevoir") },
        hosts: [hoteDemo({ id: "hote-victime", match: { peer_user: "victime" }, launched_by: "victime" }), hoteDemo({ id: "hote-autre", match: { peer_user: "autre" }, launched_by: "autre" })],
        repondre: (m, enfant, nom) => (nom === "banque" ? null : { content: [{ type: "text", text: "ok" }], isError: false }),
      });
      try {
        const [victime, autre] = b.sessions;
        const enVol = victime.recevoir(appel(1, "banque__lire", {}, { ...META, progressToken: "jeton-de-la-victime" }));
        const relaye = await attendreQue(() => b.ecrit.filter((x) => x.serveur === "banque").map((x) => JSON.parse(x.ligne)).find((m) => m.method === "tools/call"), "appel relayé au serveur « banque »");
        const jetonAmont = relaye.params._meta.progressToken;
        await autre.recevoir(appel(7, "meteo__prevoir", {}));
        // Le serveur « meteo » devine le jeton amont de l'appel de la victime.
        b.enfants.meteo.repondre(ligne({ jsonrpc: "2.0", method: "notifications/progress", params: { progressToken: jetonAmont, progress: 1, total: 2, message: "TEXTE CHOISI PAR LE SERVEUR METEO" } }));
        await attendreQue(() => b.lignes("server_progress_refused").length > 0, "refus server_progress_refused consigné");
        expect(victime.emis.filter((x) => x.includes("notifications/progress"))).to.deep.equal([]);
        const refus = b.lignes("server_progress_refused");
        expect(refus).to.have.length(1);
        expect(refus[0].data).to.include({ server: "meteo", token_server: "banque" });
        // Le serveur appelé, lui, est relayé, avec le jeton de l'hôte.
        b.enfants.banque.repondre(ligne({ jsonrpc: "2.0", method: "notifications/progress", params: { progressToken: jetonAmont, progress: 1, total: 2 } }));
        await attendreQue(() => victime.emis.some((x) => x.includes("notifications/progress")), "progression du serveur appelé relayée à l'hôte");
        const relayees = victime.emis.filter((x) => x.includes("notifications/progress")).map((x) => JSON.parse(x));
        expect(relayees).to.have.length(1);
        expect(relayees[0].params.progressToken).to.equal("jeton-de-la-victime");
        b.enfants.banque.repondre(ligne({ jsonrpc: "2.0", id: relaye.id, result: { resultType: "complete", content: [], isError: false } }));
        const r = await enVol;
        expect(r.result.isError).to.equal(false);
      } finally {
        await b.fermer();
      }
    });
  });

  describe("CT-2 EX-4.11 : exception à l'envoi vers un serveur d'outils HTTP", function () {
    it("un outil dont une propriété porte un x-mcp-header invalide, appelé par un hôte stdio : aucune exception ni en-tête Mcp-Param-* construit (un nom valide donne le sien) ; une exception synchrone de l'envoi termine l'appel en perte (-31014, upstream_send_failed, événement scellé is_error), rien ne reste en vol et l'arrêt est immédiat", async function () {
      const recus = [];
      const serveur = http.createServer((req, res) => {
        let c = "";
        req.on("data", (d) => (c += d));
        req.on("end", () => {
          recus.push({ corps: c, entetes: req.headers });
          let m = null;
          try {
            m = JSON.parse(c);
          } catch {
            m = null;
          }
          if (!m || m.id === undefined) return res.writeHead(202).end();
          res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { resultType: "complete", content: [{ type: "text", text: "paye" }], isError: false } }));
        });
      });
      await new Promise((r) => serveur.listen(0, "127.0.0.1", r));
      const url = `http://127.0.0.1:${serveur.address().port}/mcp`;
      const OUTILS = [
        { name: "payer", description: "ecriture", inputSchema: { type: "object", properties: { compte: { type: "string", "x-mcp-header": "Compte Client" } } }, annotations: { readOnlyHint: false } },
        { name: "virer", description: "ecriture", inputSchema: { type: "object", properties: { compte: { type: "string", "x-mcp-header": "X-Compte" } } }, annotations: { readOnlyHint: false } },
      ];
      const b = await banc({
        servers: { web: { transport: { type: "http", url, headers: {}, oauth: null, tls: null }, protocol: "2026-07-28", class_default: null, timeout_ms: null, tools: {}, uri_prefixes: [], relay: null } },
        outils: { web: OUTILS },
      });
      try {
        const [h] = b.sessions;
        // (1) nom d'en-tête invalide : aucun en-tête construit, l'appel aboutit.
        const r1 = await h.recevoir(appel(2, "web__payer", { compte: "CH-1" }));
        expect(r1.result?.isError, JSON.stringify(r1)).to.equal(false);
        const envoi1 = recus.find((x) => x.corps.includes('"web__payer"') || x.corps.includes('"payer"'));
        expect(envoi1, "tools/call parti").to.be.an("object");
        expect(Object.keys(envoi1.entetes).filter((k) => k.startsWith("mcp-param-"))).to.deep.equal([]);
        // Nom valide : l'en-tête part (EX-4.35).
        const r2 = await h.recevoir(appel(3, "web__virer", { compte: "CH-2" }));
        expect(r2.result?.isError, JSON.stringify(r2)).to.equal(false);
        const envoi2 = recus.find((x) => x.corps.includes('"virer"'));
        expect(envoi2.entetes["mcp-param-x-compte"]).to.equal("CH-2");
        // (2) exception synchrone de l'envoi (prise fermée) après l'intention durable.
        const cx = b.frontal.connexions.get("web");
        cx.envoyerAppel = () => {
          throw Object.assign(new Error("write EPIPE"), { code: "EPIPE" });
        };
        const r3 = await h.recevoir(appel(4, "web__payer", { compte: "CH-3" }));
        expect(r3.error?.code, JSON.stringify(r3)).to.equal(-31014);
        await attendreQue(() => b.frontal.appelsEnVol.size === 0 && cx.enVol.size === 0 && b.lignes("upstream_send_failed").length > 0, "appel en vol retiré et upstream_send_failed consigné");
        expect(b.frontal.appelsEnVol.size, "aucun appel en vol").to.equal(0);
        expect(cx.enVol.size, "aucune attente amont").to.equal(0);
        const l = b.lignes("upstream_send_failed");
        expect(l).to.have.length(1);
        expect(l[0].data).to.include({ server: "web", code: "EPIPE" });
        const ev = await b.evenements();
        expect(ev.map((e) => [e.execution.tool, e.execution.status, e.execution.is_error])).to.deep.equal([["web__payer", "executee", false], ["web__virer", "executee", false], ["web__payer", "executee", true]]);
        const t0 = Date.now();
        await b.frontal.arreter();
        expect(Date.now() - t0, "l'arrêt n'attend pas drain_timeout_ms").to.be.below(2000);
      } finally {
        await b.coeur.arreter();
        fs.rmSync(b.dir, { recursive: true, force: true });
        serveur.close();
      }
    });
  });

  describe("CT-2 EX-4.21 : enregistrement de continuation MRTR", function () {
    it("un résultat complete (ou sans resultType) qui porte un requestState ne donne aucun enregistrement de continuation ; un résultat input_required en donne un", async function () {
      let forme = "complete";
      const b = await banc({
        outils: { demo: OUTIL("claims.get") },
        repondre: () => ({ ...(forme === null ? {} : { resultType: forme }), content: [{ type: "text", text: "suite" }], isError: false, requestState: { etape: 1 } }),
      });
      try {
        const [h] = b.sessions;
        for (const f of ["complete", null]) {
          forme = f;
          const r = await h.recevoir(appel(f === null ? 2 : 1, "demo__claims.get", { a: 1 }));
          expect(r.result.isError).to.equal(false);
        }
        expect(b.lignes("mrtr_continuation"), "aucune continuation pour complete ni sans resultType").to.deep.equal([]);
        expect(b.frontal.continuations.size).to.equal(0);
        forme = "input_required";
        const r = await h.recevoir(appel(3, "demo__claims.get", { a: 1 }));
        expect(r.result.resultType).to.equal("input_required");
        expect(b.lignes("mrtr_continuation")).to.have.length(1);
        expect(b.frontal.continuations.size).to.equal(1);
      } finally {
        await b.fermer();
      }
    });
  });

  describe("CT-2 EX-4.47 et EX-16.2 : lignes du journal d'exploitation du frontal MCP", function () {
    it("CT-2 EX-4.47 : le retour d'un serveur d'outils injoignable est consigné (upstream_reachable), comme son entrée (EX-14.7), et la jauge noortrace_degraded retombe à 0", async function () {
      const b = await banc();
      try {
        b.frontal.injoignables.add("demo");
        b.coeur.metriques.jauge("noortrace_degraded", { reason: "serveur:demo" }, 1);
        await b.frontal.rafraichir("demo");
        const l = b.lignes("upstream_reachable");
        expect(l).to.have.length(1);
        expect(l[0].data).to.deep.equal({ server: "demo" });
        expect(b.frontal.injoignables.has("demo")).to.equal(false);
        expect(b.coeur.metriques.valeur("noortrace_degraded", { reason: "serveur:demo" })).to.equal(0);
        // Serveur déjà joignable : aucune ligne nouvelle.
        await b.frontal.rafraichir("demo");
        expect(b.lignes("upstream_reachable")).to.have.length(1);
      } finally {
        await b.fermer();
      }
    });

    it("CT-2 EX-16.2 pas 4 : tool_call_relayed porte t_recu_ms ≤ t_envoi_ms ≤ t_reponse_ms et t_fdatasync_ms (instant du fdatasync qui a rendu l'événement durable) ; l'horloge monotone du système a trois décimales", async function () {
      const b = await banc();
      try {
        const [h] = b.sessions;
        const r = await h.recevoir(appel(1, "demo__claims.get", { a: 1 }));
        expect(r.result.isError).to.equal(false);
        const l = b.lignes("tool_call_relayed");
        expect(l).to.have.length(1);
        const d = l[0].data;
        for (const k of ["t_recu_ms", "t_envoi_ms", "t_reponse_ms", "t_fdatasync_ms"]) expect(d[k], k).to.be.a("number");
        expect(d.t_recu_ms).to.be.at.most(d.t_envoi_ms);
        expect(d.t_envoi_ms).to.be.at.most(d.t_reponse_ms);
        expect(d.t_fdatasync_ms).to.be.at.least(d.t_recu_ms);
        expect(d.duration_ms).to.equal(Math.floor(d.t_reponse_ms - d.t_envoi_ms));
        // L'horloge monotone du système : millisecondes à la microseconde près.
        const lectures = Array.from({ length: 200 }, () => E.HORLOGE_SYSTEME.monotone());
        expect(lectures.some((x) => !Number.isInteger(x)), "trois décimales").to.equal(true);
        // Exact quelle que soit la durée de marche : x vient d'un entier de microsecondes divisé par 1000, l'arrondi au millième le redonne.
        expect(lectures.every((x) => Math.round(x * 1000) / 1000 === x), "au plus trois décimales").to.equal(true);
      } finally {
        await b.fermer();
      }
    });
  });

  /** Frontal factice des prises : journal en mémoire, un hôte par jeton ou par compte. */
  function frontalFactice(o = {}) {
    const lignes = [];
    const hote = { id: "hote-a", match: { static_token: "jeton-a", peer_user: os.userInfo().username } };
    return {
      lignes,
      journal: { consigner: (...a) => lignes.push({ level: a[0], event: a[2], data: a[3] }), abonner: () => () => {} },
      monotone: () => Number(process.hrtime.bigint() / 1000000n),
      hotePour: (m) => (m.static_token === "jeton-a" || m.peer_user === hote.match.peer_user ? hote : null),
      config: { limits: { line_max_bytes: 65536 } },
      ouvrirSession: () => ({}), fermerSession: () => {}, compterRecus: () => {},
      ouvrirConnexion: () => ({}), fermerConnexion: async () => {},
      ...o,
    };
  }

  describe("usurpation d'une prise locale par un membre du groupe des prises", function () {
    it("le chemin des prises des connecteurs et du SDK reste tenu par le démon après l'arrêt (fichier 0600 du démon : un autre compte ne peut ni le retirer ni lier sa prise au même chemin ; un client y lit prise_non_prise) ; le démon le retire au démarrage suivant", async function () {
      const dir = repertoireTemporaire("noortrace-revue-prise-");
      try {
        for (const [Classe, nom] of [[ServeurConnecteurs, "mcp.sock"], [ServeurSdk, "sdk.sock"]]) {
          const socket = path.join(dir, "p", nom);
          const s = new Classe({ frontal: frontalFactice(), socket });
          await s.ecouter();
          expect(fs.lstatSync(socket).isSocket()).to.equal(true);
          await s.fermer();
          expect(fs.existsSync(socket), `${Classe.name} : le chemin reste tenu à l'arrêt`).to.equal(true);
          expect(fs.lstatSync(socket).mode & 0o777).to.equal(0o600);
          expect(E.controlerProprietairePrise(socket, null)).to.equal("prise_non_prise");
          // Un bind au même chemin échoue tant que le fichier est là.
          const intrus = net.createServer();
          const e = await new Promise((res) => intrus.once("error", res).listen(socket));
          expect(e.code).to.equal("EADDRINUSE");
          // Redémarrage sur le même chemin : la prise du démon est retirée et remplacée.
          const s2 = new Classe({ frontal: frontalFactice(), socket });
          await s2.ecouter();
          const c = net.createConnection(socket);
          await new Promise((res, rej) => c.once("connect", res).once("error", rej));
          c.destroy();
          await s2.fermer();
        }
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it("un chemin de prise tenu par un fichier d'un autre compte fait refuser le démarrage (ErreurPriseTenue, prise_tenue_par_autre_compte), jamais une erreur avalée ; le connecteur et le SDK refusent une prise d'un autre compte (prise_autre_compte) et l'admettent quand NOORTRACE_*_PROPRIETAIRE nomme ce compte", async function () {
      if (!estRoot) {
        this.test.title += " [en attente : compte 0 requis pour chown]";
        return this.skip();
      }
      const dir = repertoireTemporaire("noortrace-revue-prise-");
      try {
        // (a) le démon : fichier d'un autre compte au chemin de la prise.
        for (const Classe of [ServeurConnecteurs, ServeurSdk]) {
          const socket = path.join(dir, "p", `${Classe.name}.sock`);
          fs.mkdirSync(path.dirname(socket), { recursive: true, mode: 0o1770 });
          fs.writeFileSync(socket, "");
          fs.chownSync(socket, UID_AUTRE, UID_AUTRE);
          const s = new Classe({ frontal: frontalFactice(), socket });
          let erreur = null;
          try {
            await s.ecouter();
          } catch (e) {
            erreur = e;
          }
          expect(erreur, `${Classe.name} : refus`).to.be.instanceOf(E.ErreurPriseTenue);
          expect(erreur.code).to.equal("prise_tenue_par_autre_compte");
          expect(erreur.uid).to.equal(UID_AUTRE);
          expect(fs.existsSync(socket), "le fichier de l'autre compte n'est pas supprimé").to.equal(true);
          await s.fermer();
        }
        // (b) les clients : une prise réelle dont le propriétaire est un autre compte.
        const socket = path.join(dir, "q", "sdk.sock");
        fs.mkdirSync(path.dirname(socket), { recursive: true, mode: 0o1770 });
        const faux = net.createServer((c) => c.write(JSON.stringify({ noortrace_identite: "acceptee" }) + "\n"));
        await new Promise((r) => faux.listen(socket, r));
        fs.chownSync(socket, UID_AUTRE, UID_AUTRE);
        try {
          expect(E.controlerProprietairePrise(socket, null)).to.equal("prise_autre_compte");
          expect(E.controlerProprietairePrise(socket, UID_AUTRE)).to.equal(null);
          expect(E.controlerProprietairePrise(socket, String(UID_AUTRE))).to.equal(null);
          expect(E.controlerProprietairePrise(socket, "nobody")).to.equal(null);
          expect(E.controlerProprietairePrise(socket, "compte-inexistant-noortrace")).to.equal("proprietaire_inconnu");
          expect(E.controlerProprietairePrise(path.join(dir, "absente.sock"), null)).to.equal("prise_absente");
          // Connecteur : refus avant toute connexion, code 1, message qui nomme la raison.
          const erreur = new PassThrough();
          let texte = "";
          erreur.on("data", (d) => (texte += d));
          const entree = new PassThrough();
          const code = await executerConnecteur({ socket, entree, sortie: new PassThrough(), erreur });
          expect(code).to.equal(1);
          expect(texte).to.include("prise_autre_compte");
          // Avec le compte attendu : la connexion s'établit (identité acceptée, fin d'entrée : code 0).
          const entree2 = new PassThrough();
          const fini = executerConnecteur({ socket, proprietaire: String(UID_AUTRE), entree: entree2, sortie: new PassThrough(), erreur: new PassThrough() });
          await new Promise((r) => setTimeout(r, 150));
          entree2.end();
          expect(await fini).to.equal(0);
          // SDK JavaScript : refus avant connexion, raison nommée ; admis avec `proprietaire`.
          const client = new ClientNoortrace({ socket, delaiMs: 2000, reprises: 0 });
          let e1 = null;
          try {
            await client._connexionVive();
          } catch (e) {
            e1 = e;
          }
          expect(e1).to.be.instanceOf(ErreurNoortraceIndisponible);
          expect(e1.message).to.include("prise_autre_compte");
          const client2 = new ClientNoortrace({ socket, delaiMs: 2000, reprises: 0, proprietaire: UID_AUTRE });
          const cx = await client2._connexionVive();
          expect(cx.perdue).to.equal(false);
          cx.fermer();
        } finally {
          await new Promise((r) => faux.close(() => r()));
        }
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });

  describe("CT-2 EX-18.3 : délai d'identification et borne des connexions non identifiées", function () {
    it("prise Unix du SDK et prise TCP des connecteurs : au-delà de la borne, une connexion muette de plus est refusée (connexions_non_identifiees) ; les connexions muettes sont détruites au délai (delai_identification) ; une connexion qui s'identifie ensuite est servie", async function () {
      const dir = repertoireTemporaire("noortrace-revue-garde-");
      try {
        const identification = { delaiMs: 400, max: 2 };
        // Prise Unix du SDK.
        const socket = path.join(dir, "p", "sdk.sock");
        const f = frontalFactice();
        const sdk = new ServeurSdk({ frontal: f, socket, identification });
        await sdk.ecouter();
        const muettes = [];
        const instantsFermeture = [];
        const t0 = Date.now();
        for (let k = 0; k < 3; k++) {
          const c = net.createConnection(socket);
          c.on("error", () => {});
          c.resume(); // une prise lue détecte la fermeture par le démon
          instantsFermeture.push(new Promise((r) => c.once("close", () => r(Date.now()))));
          await new Promise((res, rej) => c.once("connect", res).once("error", rej));
          muettes.push(c);
        }
        const fermees = Promise.all(instantsFermeture);
        await new Promise((r) => setTimeout(r, 100));
        expect(f.lignes.filter((l) => l.event === "auth_failed" && l.data.reason === "connexions_non_identifiees")).to.have.length(1);
        const instants = await fermees;
        expect(instants[2] - t0, "troisième connexion refusée aussitôt").to.be.below(250);
        for (const t of instants.slice(0, 2)) expect(t - t0).to.be.within(350, 1500);
        expect(f.lignes.filter((l) => l.event === "auth_failed" && l.data.reason === "delai_identification")).to.have.length(2);
        // Après le délai, une connexion qui remet sa preuve est servie.
        const d = await new Promise((res, rej) => {
          const c = net.createConnection(socket);
          let t = "";
          c.on("data", (x) => {
            t += x;
            const m = JSON.parse(t.split("\n")[0]);
            if (m.noortrace_defi) {
              fs.closeSync(fs.openSync(path.join(path.dirname(socket), ".noortrace-defi-" + m.noortrace_defi), "wx", 0o600));
              c.write(JSON.stringify({ noortrace_preuve: m.noortrace_defi }) + "\n");
              t = "";
            } else {
              c.destroy();
              res(m);
            }
          });
          c.once("error", rej);
        });
        expect(d).to.deep.equal({ noortrace_identite: "acceptee" });
        await sdk.fermer();
        // Prise TCP des connecteurs (jeton).
        const g = frontalFactice();
        const tcp = new ServeurConnecteurs({ frontal: g, tcp: { listen: "127.0.0.1:0", client_auth: "jeton", tls: null }, jetons: new Map([["jeton-a", new Uint8Array(Buffer.from("0123456789abcdef"))]]), identification });
        await tcp.ecouter();
        const { port } = tcp.adresseTcp();
        const closes = [];
        for (let k = 0; k < 3; k++) {
          const c = net.createConnection(port, "127.0.0.1");
          c.on("error", () => {});
          c.resume();
          closes.push(new Promise((r) => c.once("close", r)));
          await new Promise((res, rej) => c.once("connect", res).once("error", rej));
        }
        await Promise.all(closes);
        expect(g.lignes.filter((l) => l.event === "auth_failed" && l.data.reason === "connexions_non_identifiees")).to.have.length(1);
        expect(g.lignes.filter((l) => l.event === "auth_failed" && l.data.reason === "delai_identification")).to.have.length(2);
        const rep = await new Promise((res, rej) => {
          const c = net.createConnection(port, "127.0.0.1", () => c.write(JSON.stringify({ noortrace_token: "0123456789abcdef" }) + "\n"));
          c.once("data", (x) => {
            c.destroy();
            res(x.toString().trim());
          });
          c.once("error", rej);
        });
        expect(rep).to.equal(JSON.stringify({ noortrace_identite: "acceptee" }));
        expect(tcp.garde.enCours.size, "connexion identifiée : plus comptée").to.equal(0);
        expect(E.DELAI_IDENTIFICATION_MS).to.equal(5000);
        expect(E.CONNEXIONS_NON_IDENTIFIEES_MAX).to.equal(64);
        await tcp.fermer();
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });

  describe("preuve par fichier sans instant de création", function () {
    it("un fichier de preuve dont birthtimeMs vaut 0 est refusé (preuve, instant_creation_indisponible) au lieu d'être admis sans contrôle d'antériorité ; un fichier daté est admis ; le démon sonde le répertoire au démarrage", async function () {
      const dir = repertoireTemporaire("noortrace-revue-preuve-");
      try {
        const socket = path.join(dir, "p", "mcp.sock");
        fs.mkdirSync(path.dirname(socket), { recursive: true, mode: 0o1770 });
        const defi = "ab".repeat(16);
        const fichier = path.join(path.dirname(socket), E.PREFIXE_DEFI + defi);
        const creer = () => fs.closeSync(fs.openSync(fichier, "wx", 0o600));
        creer();
        const sansInstant = (p) => Object.assign(fs.lstatSync(p), { birthtimeMs: 0 });
        const r = verifierPreuveFichier(socket, defi, Date.now(), { lstat: sansInstant });
        expect(r).to.deep.equal({ refus: "preuve", detail: "instant_creation_indisponible" });
        expect(fs.existsSync(fichier), "le fichier de preuve est consommé").to.equal(false);
        creer();
        const ok = verifierPreuveFichier(socket, defi, Date.now());
        expect(ok.utilisateur).to.equal(os.userInfo().username);
        creer();
        const ancien = (p) => Object.assign(fs.lstatSync(p), { birthtimeMs: Date.now() - 60000 });
        expect(verifierPreuveFichier(socket, defi, Date.now(), { lstat: ancien })).to.deep.equal({ refus: "preuve" });
        expect(E.instantCreationDisponible(path.dirname(socket))).to.equal(true);
        expect(fs.readdirSync(path.dirname(socket)).filter((n) => n.startsWith(".noortrace-sonde-"))).to.deep.equal([]);
        // Le démon sonde au démarrage : aucune ligne quand l'instant est disponible.
        const f = frontalFactice();
        const s = new ServeurConnecteurs({ frontal: f, socket });
        await s.ecouter();
        await s.fermer();
        expect(f.lignes.filter((l) => l.event === "proof_birthtime_unavailable")).to.deep.equal([]);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });

  describe("CT-7 MN-99 : fichiers d'un autre compte (demande de noortrace-ctl, répertoire temporaire d'un export)", function () {
    it("un fichier de demande dont le propriétaire n'est pas le compte du démon n'est pas lu (octets null, raison proprietaire) et est supprimé ; un fichier du démon est lu", function () {
      if (!estRoot) {
        this.test.title += " [en attente : compte 0 requis pour chown]";
        return this.skip();
      }
      const dir = repertoireTemporaire("noortrace-revue-demande-");
      try {
        const f = path.join(dir, "demande.json");
        fs.writeFileSync(f, JSON.stringify({ demande: "rotation-urgence", at: "2026-11-10T10:00:00.000Z" }));
        fs.chownSync(f, UID_AUTRE, UID_AUTRE);
        const r = preleverFichierDemande(f);
        expect(r.octets).to.equal(null);
        expect(r.raison).to.equal("proprietaire");
        expect(r.nonSupprime).to.equal(null);
        expect(fs.existsSync(f)).to.equal(false);
        fs.writeFileSync(f, JSON.stringify({ demande: "rotation-urgence", at: "2026-11-10T10:00:00.000Z" }));
        const ok = preleverFichierDemande(f);
        expect(ok.raison).to.equal(null);
        expect(Buffer.from(ok.octets).toString("utf8")).to.include("rotation-urgence");
        expect(preleverFichierDemande(f)).to.deep.equal({ absent: true });
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it("CT-7 MN-99 : le répertoire temporaire ouvert par l'export doit appartenir au compte effectif du démon et n'être accessible qu'à lui, dans tout environnement (proprietaire, mode, non_dossier)", function () {
      const dir = repertoireTemporaire("noortrace-revue-export-");
      try {
        const temp = path.join(dir, ".noortrace-partiel-" + "0".repeat(32));
        fs.mkdirSync(temp, { mode: 0o700 });
        const st = fs.statSync(temp);
        const euid = typeof process.geteuid === "function" ? process.geteuid() : null;
        expect(controlerRepertoireTemporaire(st, euid)).to.equal(null);
        expect(controlerRepertoireTemporaire(Object.assign(fs.statSync(temp), { uid: UID_AUTRE }), euid)).to.equal("proprietaire");
        fs.chmodSync(temp, 0o750);
        expect(controlerRepertoireTemporaire(fs.statSync(temp), euid)).to.equal("mode");
        fs.chmodSync(temp, 0o2700);
        expect(controlerRepertoireTemporaire(fs.statSync(temp), euid), "bit setgid admis").to.equal(null);
        fs.writeFileSync(path.join(dir, "f"), "");
        expect(controlerRepertoireTemporaire(fs.statSync(path.join(dir, "f")), euid)).to.equal("non_dossier");
        // La règle est appliquée par l'export dans tout environnement : le texte du module le dit.
        const source = fs.readFileSync(new URL("../paquets/enregistreur/src/export-dossier.mjs", import.meta.url), "utf8");
        expect(source).to.match(/controlerRepertoireTemporaire\(fs\.fstatSync\(fdTemp\)/);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });
});
