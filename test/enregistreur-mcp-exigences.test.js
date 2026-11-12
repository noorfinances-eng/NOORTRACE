// Frontal MCP (CT-2 §4, §7.2, §14.1 à §14.3, EX-17.2) : exigences EX-
// testées en réussite et en échec, et entrées hostiles. Banc : cœur réel
// (stockage sous os.tmpdir()), frontal réel, serveur d'outils stdio factice
// à réponses programmées, service d'approbation de test ; les transports
// (prise des connecteurs, TCP à jeton, Streamable HTTP, OAuth) sont exercés
// par de vraies connexions locales.

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { spawn } from "node:child_process";
import { generateKeyPairSync, sign as signer } from "node:crypto";
import * as N from "@noortrace/noyau";
import {
  Coeur, HorlogeReglable, FrontalMcp, ServeurConnecteurs, ServeurHttpMcp, ConnexionHttp, validerConfiguration, reglesHorsSchema, lireEvenements,
  ErreurEnregistreur, analyserTexte, compacter, nombreRepresentable, ErreurTexteJson, decoderUtf8Strict, objetErreur, resultatEnregistreur,
  verifierJwt, executerConnecteur, resoudreDelegation, QuotasHote, agreger, LecteurSse, signataireDepuisConfiguration,
} from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { repertoireTemporaire, secretsDev, RACINE } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationMcp, hoteDemo, serveurStdio, reglageOutil, RedacteurTest, ServiceFixe, AUTORISE, EnfantFactice, laisserTourner } from "./fixtures/enregistreur-mcp/outils.mjs";

const META = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} };
const OUTILS = [
  { name: "claims.get", description: "Lire", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } },
  { name: "payments.create", description: "Ecrire", inputSchema: { type: "object" }, annotations: { readOnlyHint: false } },
  { name: "slow.op", description: "Lent", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } },
];
const ms = (x) => N.decoderHorodatage(x);
const ligne = (o) => JSON.stringify(o);
const appel = (id, nom, args, meta = META, extra = {}) => ligne({ jsonrpc: "2.0", id, method: "tools/call", params: { name: nom, arguments: args, ...extra, _meta: meta } });

/**
 * Banc : cœur, frontal, enfant stdio factice qui répond par `repondre(message)`
 * (objet `result`, `{ error }`, `null` : pas de réponse).
 */
async function banc(o = {}) {
  // `o.dir` : journal d'un banc fermé, repris par un nouveau cœur (redémarrage).
  const dir = o.dir ?? repertoireTemporaire("noortrace-mcp-ex-");
  const servers = o.servers ?? {
    demo: serveurStdio(["/opt/mcp/demo"], { protocol: o.protocole ?? "2026-07-28", tools: o.reglages ?? {}, class_default: o.class_default ?? null, relay: o.relay ?? null }),
  };
  const { config: brute } = configurationMcp(dir, { servers, hosts: o.hosts, mode: o.mode, tools: o.tools, limits: o.limits });
  if (o.ajuster) o.ajuster(brute);
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(brute)));
  expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
  const horloge = o.horloge ?? new HorlogeReglable(ms("2026-11-10T10:20:00.000Z"));
  const service = o.service ?? new ServiceFixe(o.evaluer ?? (() => AUTORISE), o.candidats ?? []);
  // `o.signataire(config, secrets)` : backend de signature fourni par l'essai (sinon celui de la configuration).
  const signataire = o.signataire ? await o.signataire(v.config, secretsDev()) : undefined;
  const coeur = await Coeur.demarrer({ config: v.config, secrets: secretsDev(), horloge, service, signataire });
  const enfants = [];
  const ecrit = [];
  const repondre = o.repondre ?? ((m) => ({ content: [{ type: "text", text: `ok ${m.params.name}` }], isError: false }));
  const lanceur = () => {
    if (o.lancementImpossible) throw Object.assign(new Error("absent"), { code: "ENOENT" });
    const e = new EnfantFactice((l, enfant) => {
      ecrit.push(l);
      const m = JSON.parse(l);
      if (m.id === undefined) return;
      let r;
      if (m.method === "server/discover") r = o.discover ? o.discover(m) : { result: { supportedVersions: ["2026-07-28"] } };
      else if (m.method === "initialize") r = { result: { protocolVersion: "2025-11-25", capabilities: {}, serverInfo: { name: "x", version: "1" } } };
      else if (m.method === "tools/list") r = { result: { tools: o.outils ?? OUTILS, ttlMs: 60000 } };
      else if (m.method === "subscriptions/listen") r = null;
      else {
        const x = repondre(m, enfant);
        r = x === null || x === undefined ? null : x.error || x.result !== undefined ? x : { result: x };
      }
      if (r) setImmediate(() => enfant.repondre(JSON.stringify({ jsonrpc: "2.0", id: m.id, ...r })));
    });
    enfants.push(e);
    return e;
  };
  const redacteur = o.redacteur ?? new RedacteurTest();
  const frontal = new FrontalMcp({ coeur, redacteur, lanceur, ...o.frontal });
  if (o.demarrer) await frontal.demarrer();
  else frontal.chargerListe("demo", o.outils ?? OUTILS, { ttlMs: 60000, cacheScope: o.cacheScope ?? null, ere: "moderne" });
  const hote = v.config.mcp.hosts[0];
  const emis = [];
  const session = frontal.ouvrirSession({ hote, identite: { peer_user: "agent-demo" }, transport: o.transport ?? "stdio", emettre: (x) => emis.push(x) });
  const recevoir = async (texte, opt) => {
    const r = await frontal.recevoir(session, texte, opt);
    return r === null ? null : JSON.parse(r);
  };
  const evenements = async () => (await lireEvenements(coeur.repertoire)).filter((e) => !e.execution.tool.startsWith("noortrace."));
  const fermer = async () => {
    await frontal.arreter();
    await coeur.arreter();
  };
  return { dir, config: v.config, coeur, frontal, session, recevoir, evenements, ecrit, emis, enfants, horloge, service, redacteur, fermer, hote };
}

describe("enregistreur, frontal MCP : exigences de §4, §7.2, §14 (réussite et échec)", function () {
  this.timeout(60000);

  describe("4.2 cycle de vie et négociation (EX-4.3 à EX-4.8)", function () {
    it("EX-4.3 : server/discover rend les quatre révisions ; un lot reçoit une seule erreur -32600 sans relais", async function () {
      const b = await banc();
      const d = await b.recevoir(ligne({ jsonrpc: "2.0", id: 1, method: "server/discover", params: { _meta: META } }));
      expect(d.result.supportedVersions).to.deep.equal(["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"]);
      const l = await b.recevoir(`[${appel(2, "demo__claims.get", {})}]`);
      expect(l).to.deep.equal({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request", data: { reason: "lot_non_pris_en_charge" } } });
      expect(b.ecrit).to.deep.equal([]);
      await b.fermer();
    });

    it("EX-4.4 : _meta requis (-32602), version non supportée (-32022, data.supported), serverInfo dans chaque résultat", async function () {
      const b = await banc();
      expect((await b.recevoir(appel(1, "demo__claims.get", {}, {}))).error).to.deep.equal({ code: -32602, message: "Invalid params", data: { reason: "meta_requis" } });
      const v = await b.recevoir(appel(2, "demo__claims.get", {}, { ...META, "io.modelcontextprotocol/protocolVersion": "2099-01-01" }));
      expect(v.error.code).to.equal(-32022);
      expect(v.error.data.supported).to.include("2026-07-28");
      const ok = await b.recevoir(appel(3, "demo__claims.get", {}));
      expect(ok.result._meta["io.modelcontextprotocol/serverInfo"]).to.deep.equal({ name: "noortrace-enregistreur", version: "0.1.0" });
      const liste = await b.recevoir(ligne({ jsonrpc: "2.0", id: 4, method: "tools/list", params: { _meta: META } }));
      expect(liste.result._meta["io.modelcontextprotocol/serverInfo"].name).to.equal("noortrace-enregistreur");
      await b.fermer();
    });

    it("EX-4.5 : hôte hérité, version inconnue → 2025-11-25 ; rien d'autre que ping avant initialized ; ping → {}", async function () {
      const b = await banc();
      const i = await b.recevoir(ligne({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-01-01", capabilities: {}, clientInfo: { name: "h", version: "1" } } }));
      expect(i.result.protocolVersion).to.equal("2025-11-25");
      expect(i.result.capabilities).to.deep.equal({ tools: { listChanged: true } });
      expect((await b.recevoir(ligne({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }))).error.code).to.equal(-32600);
      expect((await b.recevoir(ligne({ jsonrpc: "2.0", id: 3, method: "ping" }))).result).to.deep.equal({});
      await b.recevoir(ligne({ jsonrpc: "2.0", method: "notifications/initialized" }));
      expect(Object.keys((await b.recevoir(ligne({ jsonrpc: "2.0", id: 4, method: "tools/list", params: {} }))).result)).to.deep.equal(["tools"]);
      await b.fermer();
    });

    it("EX-4.6 : sonde server/discover → moderne ; erreur non moderne → initialize ; -32022 → connexion impossible (-31014, sans événement)", async function () {
      const b = await banc({ protocole: "auto" });
      expect((await b.recevoir(appel(1, "demo__claims.get", {}))).result.isError).to.equal(false);
      expect(JSON.parse(b.ecrit[0]).method).to.equal("server/discover");
      expect(JSON.parse(b.ecrit[1]).method).to.equal("subscriptions/listen");
      await b.fermer();
      const h = await banc({ protocole: "auto", discover: () => ({ error: { code: -32000, message: "x" } }) });
      expect((await h.recevoir(appel(1, "demo__claims.get", {}))).result.isError).to.equal(false);
      expect(h.ecrit.map((l) => JSON.parse(l).method)).to.deep.equal(["server/discover", "initialize", "notifications/initialized", "tools/call"]);
      expect(JSON.parse(h.ecrit[3]).params._meta["io.modelcontextprotocol/protocolVersion"]).to.equal("2025-11-25");
      await h.fermer();
      const m = await banc({ protocole: "auto", discover: () => ({ error: { code: -32022, message: "Unsupported protocol version" } }) });
      expect((await m.recevoir(appel(1, "demo__claims.get", {}))).error).to.deep.equal({ code: -31014, message: "noortrace: serveur d'outils injoignable", data: { server: "demo" } });
      expect(await m.evenements()).to.deep.equal([]);
      await m.fermer();
    });

    it("EX-4.7, EX-4.28 : _meta réécrit vers le serveur ; capacités : intersection avec le relais autorisé", async function () {
      const b = await banc({ relay: { sampling: false, elicitation: true, roots: false } });
      await b.recevoir(appel(1, "demo__claims.get", {}, { ...META, "io.modelcontextprotocol/clientCapabilities": { sampling: {}, elicitation: {}, roots: {}, experimental: {} }, "io.modelcontextprotocol/clientInfo": { name: "hote", version: "9" }, autre: 1 }));
      const m = JSON.parse(b.ecrit.at(-1)).params._meta;
      expect(m).to.deep.equal({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": { elicitation: {} },
        "io.modelcontextprotocol/clientInfo": { name: "noortrace-enregistreur", version: "0.1.0" },
        autre: 1,
      });
      await b.fermer();
    });
  });

  describe("4.3 agrégation (EX-4.9 à EX-4.18)", function () {
    it("EX-4.9 : l'alias `noortrace` est refusé à la configuration", function () {
      const dir = repertoireTemporaire("noortrace-mcp-ex-");
      const { config } = configurationMcp(dir, { servers: { noortrace: serveurStdio(["/x"]) } });
      expect(reglesHorsSchema(config).erreurs.map((e) => e.pointeur)).to.include("/policy/servers/noortrace");
    });

    it("EX-4.2, EX-4.11 : un outil `noortrace.*` n'est jamais annoncé ni appelable ; rejet consigné (tool_rejected)", async function () {
      const b = await banc({ outils: [...OUTILS, { name: "noortrace.journal.politique", inputSchema: { type: "object" } }] });
      const l = await b.recevoir(ligne({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: META } }));
      expect(l.result.tools.map((t) => t.name)).to.not.include("demo__noortrace.journal.politique");
      expect((await b.recevoir(appel(2, "demo__noortrace.journal.politique", {}))).error).to.deep.equal({ code: -32602, message: "Unknown tool: demo__noortrace.journal.politique" });
      expect(b.coeur.journal.trouver("tool_rejected").map((x) => x.data.reason)).to.include("nom_reserve");
      await b.fermer();
    });

    it("EX-4.11 règle 4 : une propriété x-mcp-header invalide retire l'outil de la liste servie en HTTP seulement", async function () {
      const outils = [...OUTILS, { name: "h.bad", inputSchema: { type: "object", properties: { a: { type: "object", "x-mcp-header": "A B" } } } }];
      const http = await banc({ outils, transport: "http" });
      const l = await http.recevoir(ligne({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: META } }));
      expect(l.result.tools.map((t) => t.name)).to.not.include("demo__h.bad");
      await http.fermer();
      const stdio = await banc({ outils });
      const l2 = await stdio.recevoir(ligne({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: META } }));
      expect(l2.result.tools.map((t) => t.name)).to.include("demo__h.bad");
      await stdio.fermer();
    });

    it("EX-4.13 : pagination propre (curseur opaque, ordre), curseur invalide -32602 ; la liste servie est celle du parcours complet", async function () {
      const outils = Array.from({ length: 5 }, (_, k) => ({ name: `t${k}`, inputSchema: { type: "object" }, annotations: { readOnlyHint: true } }));
      const b = await banc({ outils, tools: { page_size: 2 } });
      const p1 = await b.recevoir(ligne({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: META } }));
      expect(p1.result.tools.map((t) => t.name)).to.deep.equal(["demo__t0", "demo__t1"]);
      const p2 = await b.recevoir(ligne({ jsonrpc: "2.0", id: 2, method: "tools/list", params: { cursor: p1.result.nextCursor, _meta: META } }));
      const p3 = await b.recevoir(ligne({ jsonrpc: "2.0", id: 3, method: "tools/list", params: { cursor: p2.result.nextCursor, _meta: META } }));
      expect(p3.result.tools.map((t) => t.name)).to.deep.equal(["demo__t4"]);
      expect(p3.result).to.not.have.property("nextCursor");
      expect(b.session.liste.annonces.length).to.equal(5);
      expect((await b.recevoir(ligne({ jsonrpc: "2.0", id: 4, method: "tools/list", params: { cursor: "c-99-0", _meta: META } }))).error).to.deep.equal({ code: -32602, message: "Invalid params", data: { reason: "curseur_invalide" } });
      await b.fermer();
    });

    it("EX-4.13 : un serveur au-delà de tools_list_max_items est traité comme injoignable (liste_trop_longue)", async function () {
      const outils = Array.from({ length: 3 }, (_, k) => ({ name: `t${k}`, inputSchema: { type: "object" } }));
      const b = await banc({ outils, demarrer: true, limits: { tools_list_max_items: 2 } });
      expect(b.frontal.injoignables.has("demo")).to.equal(true);
      expect(b.coeur.journal.trouver("upstream_unreachable")[0].data.reason).to.equal("liste_trop_longue");
      await b.fermer();
    });

    // Étape 7 : la raison `serveur:<alias>` de la santé
    // (EX-17.1) n'était pas dans `noortrace_degraded` : l'alerte « Mode dégradé,
    // mineure pour serveur:* » de CT-2 §17.4 (CT-8 noortrace_mode_degrade_serveur)
    // ne pouvait pas se déclencher.
    it("EX-14.11, EX-17.1, §17.4 : un serveur injoignable met noortrace_degraded{reason=\"serveur:<alias>\"} à 1 (série posée à 0 au démarrage), comme la raison de santé ; revenu, la jauge repasse à 0", async function () {
      const outils = Array.from({ length: 3 }, (_, k) => ({ name: `t${k}`, inputSchema: { type: "object" } }));
      const b = await banc({ outils, demarrer: true, limits: { tools_list_max_items: 2 } });
      const jauge = () => b.coeur.metriques.valeur("noortrace_degraded", { reason: "serveur:demo" });
      expect(b.frontal.injoignables.has("demo")).to.equal(true);
      expect(b.coeur.raisonsFrontal()).to.deep.equal(["serveur:demo"]);
      expect(jauge()).to.equal(1);
      expect(b.coeur.metriques.exposer()).to.include('noortrace_degraded{reason="serveur:demo"} 1');
      b.coeur.config.limits.tools_list_max_items = 10;
      await b.frontal.rafraichir("demo");
      expect(b.frontal.injoignables.has("demo")).to.equal(false);
      expect(jauge()).to.equal(0);
      await b.fermer();
    });

    it("EX-4.14 : cacheScope public sans jeton ni serveur `private` ; ttlMs du serveur moderne", async function () {
      const b = await banc();
      const l = await b.recevoir(ligne({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: META } }));
      expect([l.result.ttlMs, l.result.cacheScope]).to.deep.equal([60000, "public"]);
      await b.fermer();
    });

    it("EX-4.15, EX-4.16 : list_changed du serveur → relecture fusionnée, `charger`, notification à l'hôte qui écoute ; empreinte consignée", async function () {
      const b = await banc({ demarrer: true, tools: { list_changed_min_interval_ms: 50 } });
      b.frontal.recevoir(b.session, ligne({ jsonrpc: "2.0", id: "ecoute", method: "subscriptions/listen", params: { notifications: { toolsListChanged: true }, _meta: META } }));
      // Accusé, premier message du flux (révision 2026-07-28, lecture 173).
      expect(b.emis[0]).to.equal('{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"notifications":{"toolsListChanged":true},"_meta":{"io.modelcontextprotocol/subscriptionId":"ecoute"}}}');
      const chargers = b.service.messages.filter((m) => m.methode === "charger").length;
      const enfant = b.enfants[0];
      OUTILS[0].description = "Lire, description changee";
      try {
        for (let k = 0; k < 3; k++) enfant.repondre(ligne({ jsonrpc: "2.0", method: "notifications/tools/list_changed" }));
        await new Promise((r) => setTimeout(r, 200));
        await laisserTourner(20);
      } finally {
        OUTILS[0].description = "Lire";
      }
      expect(b.ecrit.filter((l) => JSON.parse(l).method === "tools/list").length).to.equal(2);
      expect(b.coeur.journal.trouver("list_changed_merged")[0].data.count).to.equal(2);
      expect(b.service.messages.filter((m) => m.methode === "charger").length).to.equal(chargers + 1);
      expect(b.emis).to.include('{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":"ecoute"}}}');
      const d = b.coeur.journal.trouver("tool_definition_changed").at(-1);
      expect(d.data.tool_announced).to.equal("demo__claims.get");
      expect(d.data.old_sha256).to.not.equal(d.data.new_sha256);
      await b.fermer();
    });

    it("EX-4.17, EX-14.1 : classe : configuration de l'outil, puis du serveur, puis readOnlyHint, à défaut ecriture", function () {
      const outils = [{ name: "a", annotations: { readOnlyHint: true } }, { name: "b", annotations: { readOnlyHint: true } }, { name: "c" }, { name: "d", annotations: { readOnlyHint: false } }];
      const cfg = { demo: { tools: { a: { class: "ecriture" } } } };
      const r = agreger({ serveurs: [{ alias: "demo", tools: outils }], prefixe: true, configServeurs: cfg });
      expect(r.annonces.map((x) => x.class)).to.deep.equal(["ecriture", "lecture", "ecriture", "ecriture"]);
      const r2 = agreger({ serveurs: [{ alias: "demo", tools: outils }], prefixe: true, configServeurs: { demo: { class_default: "lecture", tools: {} } } });
      expect(r2.annonces.map((x) => x.class)).to.deep.equal(["lecture", "lecture", "lecture", "lecture"]);
    });

    it("EX-4.18 : serveur injoignable omis de la liste, santé `serveur:<alias>`, appel → -31014 sans événement", async function () {
      const b = await banc({ demarrer: true, lancementImpossible: true });
      const l = await b.recevoir(ligne({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: META } }));
      expect(l.result.tools).to.deep.equal([]);
      expect(b.coeur.sante().corps).to.deep.include({ status: "degraded", reasons: ["serveur:demo"] });
      expect((await b.recevoir(appel(2, "demo__claims.get", {}))).error.code).to.equal(-31014);
      expect(await b.evenements()).to.deep.equal([]);
      expect(b.coeur.degrade.enModeDegrade, "le cœur n'est pas en mode dégradé").to.equal(false);
      await b.fermer();
    });
  });

  describe("4.4 relais de tools/call (EX-4.19 à EX-4.24, EX-4.43 à EX-4.48)", function () {
    it("EX-4.19 : la pièce « arguments » et l'intention sont durables avant le relais ; l'événement avant la réponse", async function () {
      let constat = null;
      const b = await banc({
        repondre: (m) => {
          const fichier = b.coeur.pieces.chemin(N.sha256Hex(N.utf8(JSON.stringify({ claim_id: "1" }))));
          const intentions = fs.readdirSync(path.join(b.coeur.repertoire, "intentions"));
          constat = { piece: fs.existsSync(fichier), intention: intentions.some((f) => fs.readFileSync(path.join(b.coeur.repertoire, "intentions", f), "utf8").includes(m.id)) };
          return { content: [], isError: false };
        },
      });
      const r = await b.recevoir(appel(1, "demo__payments.create", { claim_id: "1" }));
      expect(constat).to.deep.equal({ piece: true, intention: true });
      const evts = await b.evenements();
      expect(evts.length).to.equal(1);
      expect(r.result.isError).to.equal(false);
      await b.fermer();
    });

    it("EX-4.44 : nombres non représentables refusés (id recopié), forme décimale identique admise", function () {
      for (const x of ["0.75", "1.0", "1e3", "-0", "0.1", "123456789012345680000", "1E-7"]) expect(nombreRepresentable(x), x).to.equal(true);
      for (const x of ["12345678901234567890", "0.10000000000000000001", "1e-400", "9007199254740993"]) expect(nombreRepresentable(x), x).to.equal(false);
    });

    it("EX-4.43 : blancs retirés hors des chaînes seulement (CR, LF, tabulation dans une chaîne échappée conservés)", function () {
      const t = '{ "a" :\t[ 1 ,\r\n 2 ] , "b" : "x \\n\\t y" }';
      expect(compacter(t, analyserTexte(t))).to.equal('{"a":[1,2],"b":"x \\n\\t y"}');
    });

    it("entrées hostiles : JSON non strict, clé en double, substitut isolé, BOM, UTF-8 invalide, profondeur et membres → -32700, sans pièce ni relais", async function () {
      const b = await banc({ limits: { json_max_depth: 8, json_max_members: 4 } });
      const cas = [
        ['{"jsonrpc":"2.0","id":1,"method":"tools/call",}', "json_invalide"],
        ['{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/call"}', "cle_double"],
        ['{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"\\ud800"}}', "substitut_isole"],
        ["﻿" + appel(1, "demo__claims.get", {}), "bom"],
        [appel(1, "demo__claims.get", { a: [[[[[[[[[1]]]]]]]]] }), "profondeur"],
        [appel(1, "demo__claims.get", { a: 1, b: 2, c: 3, d: 4, e: 5 }), "membres"],
        ['{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x\u0001"}}', "json_invalide"],
      ];
      for (const [texte, raison] of cas) {
        const r = await b.recevoir(texte);
        expect(r.error, raison).to.deep.equal({ code: -32700, message: "Parse error", data: { reason: raison } });
      }
      const utf8 = await b.recevoir(new Uint8Array([0x7b, 0xff, 0x7d]));
      expect(utf8.error.data.reason).to.equal("utf8");
      expect((await b.recevoir('{"jsonrpc":"1.0","id":1,"method":"tools/call"}')).error.code).to.equal(-32600);
      expect((await b.recevoir('"texte"')).error.code).to.equal(-32600);
      expect((await b.recevoir(appel(9, "demo__claims.get", [1]))).error).to.deep.equal({ code: -32602, message: "Invalid params", data: { reason: "arguments_non_objet" } });
      expect(b.ecrit).to.deep.equal([]);
      expect(await b.evenements()).to.deep.equal([]);
      expect(() => decoderUtf8Strict(new Uint8Array([0xc3]))).to.throw(ErreurTexteJson);
      await b.fermer();
    });

    it("entrées hostiles : requête au-delà de request_max_bytes → -31013 (requete), sans pièce ; `_meta` piégé relayé tel quel mais jamais journalisé", async function () {
      const b = await banc({ limits: { request_max_bytes: 1024 } });
      const r = await b.recevoir(appel(1, "demo__claims.get", { x: "a".repeat(2000) }));
      expect(r.error).to.deep.equal({ code: -31013, message: "noortrace: taille maximale depassee", data: { limit_bytes: 1024, direction: "requete" } });
      expect(b.ecrit).to.deep.equal([]);
      await b.fermer();
    });

    it("EX-4.21 : continuation MRTR sans ticket : héritage une seule fois, avec les mêmes arguments en clair", async function () {
      let n = 0;
      const b = await banc({ repondre: () => (++n === 1 ? { resultType: "input_required", inputRequests: {}, requestState: "etat-1" } : { content: [], isError: false }) });
      await b.recevoir(appel(1, "demo__payments.create", { a: 1 }));
      const evaluer = () => b.service.messages.filter((m) => m.methode === "evaluer").length;
      expect(evaluer()).to.equal(1);
      await b.recevoir(appel(2, "demo__payments.create", { a: 1 }, META, { requestState: "etat-1", inputResponses: {} }));
      expect(evaluer(), "héritage : pas de nouvel evaluer").to.equal(1);
      expect(JSON.parse(b.ecrit.at(-1)).params.requestState).to.equal("etat-1");
      await b.recevoir(appel(3, "demo__payments.create", { a: 1 }, META, { requestState: "etat-1", inputResponses: {} }));
      expect(evaluer(), "requestState déjà servi : repasse par le pas 3").to.equal(2);
      n = 0;
      await b.recevoir(appel(4, "demo__payments.create", { a: 1 }));
      await b.recevoir(appel(5, "demo__payments.create", { a: 2 }, META, { requestState: "etat-1", inputResponses: {} }));
      expect(evaluer(), "autres arguments : repasse par le pas 3").to.equal(4);
      expect((await b.evenements()).length).to.equal(5);
      await b.fermer();
    });

    // Continuation MRTR d'un appel approuvé (EX-4.21, EX-12.23, EX-7.21) : banc
    // en mode `erreur`, ticket ouvert, décision `approuve` scellée, ré-émission
    // approuvée relayée dont le résultat est `input_required`.
    const RS = "etat-approuve-1";
    const shaRs = N.sha256Hex(N.utf8(JSON.stringify(RS)));
    const ARGS = { claim_id: "4242" };
    const lignesApprobations = (b) => {
      const d = path.join(b.coeur.repertoire, "approbations");
      return fs.readdirSync(d).filter((n) => n.startsWith("approbations-")).sort()
        .flatMap((n) => fs.readFileSync(path.join(d, n), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)));
    };
    async function appelApprouveInputRequired(o = {}) {
      const service = o.service ?? new ServiceApprobationFactice({ org_id: "0x" + "00".repeat(32), journal_id: "0x" + "00".repeat(32), decider: (q) => (q.tool_announced === "demo__payments.create" ? { decision: "a_approuver", rule: "revue" } : { decision: "autorise", rule: null }) });
      let relais = 0;
      const b = await banc({ service, repondre: () => (++relais === 1 ? { resultType: "input_required", inputRequests: {}, requestState: RS } : { content: [{ type: "text", text: "paye" }], isError: false }) });
      service.org_id = b.config.recorder.org_id;
      service.journal_id = b.config.recorder.journal_id;
      const signal = await b.recevoir(appel(1, "demo__payments.create", ARGS));
      const { ticket } = signal.result._meta["noortrace/approval"];
      // `ouvrir` part sans être attendu (EX-7.18) : attendre que le service l'ait reçu.
      for (let k = 0; k < 500 && !service.tickets.get(ticket)?.request; k++) await laisserTourner(10);
      service.decider_ticket(ticket);
      expect((await b.coeur.traiterRemises())[0]).to.deep.include({ result: "scelle" });
      const r = await b.recevoir(appel(2, "demo__payments.create", ARGS));
      expect(r.result.resultType, JSON.stringify(r)).to.equal("input_required");
      return { b, service, ticket };
    }
    const compter = (service, methode) => service.messages.filter((m) => m.methode === methode).length;

    it("EX-4.21, EX-12.23, EX-7.21 : continuation MRTR d'un appel approuvé : ligne continuation (ticket, seq et hash de l'executee, sha256 du requestState) avant la réponse ; la ré-émission hérite sans evaluer (même policy, même approval, aucun consommer), ligne continuation_consommee ; rejouée ou sous d'autres arguments, elle repasse par le pas 3 et l'approbation déjà servie ne la couvre pas (-31010 approbation, RL-3)", async function () {
      const { b, service, ticket } = await appelApprouveInputRequired();
      try {
        const [, premier] = await b.evenements();
        expect(premier.execution.status).to.equal("executee");
        const cont = lignesApprobations(b).filter((l) => l.kind === "continuation");
        expect(cont, "ligne continuation écrite avant la réponse (pas 14)").to.deep.equal([{ kind: "continuation", ticket, seq: premier.seq, hash: premier.hash, request_state_sha256: shaRs }]);
        const evaluer = compter(service, "evaluer");
        expect(compter(service, "consommer"), "consommer du premier relais").to.equal(1);
        const r3 = await b.recevoir(appel(3, "demo__payments.create", ARGS, META, { requestState: RS, inputResponses: {} }));
        expect(r3.result?.isError, JSON.stringify(r3)).to.equal(false);
        expect(compter(service, "evaluer"), "héritage : aucun nouvel evaluer").to.equal(evaluer);
        expect(JSON.parse(b.ecrit.at(-1)).params.requestState).to.equal(RS);
        const evts = await b.evenements();
        expect(evts.map((e) => e.execution.status)).to.deep.equal(["retenue", "executee", "executee"]);
        const suite = evts[2];
        expect(suite.policy, "policy héritée").to.deep.equal(premier.policy);
        expect(suite.approval, "approval héritée").to.deep.equal(premier.approval);
        expect(suite.intent).to.deep.equal(premier.intent);
        expect(suite.code.model).to.equal(premier.code.model);
        await laisserTourner(20);
        expect(compter(service, "consommer"), "une continuation ne donne pas de consommer (EX-7.20)").to.equal(1);
        expect(lignesApprobations(b).filter((l) => l.kind === "continuation_consommee")).to.deep.equal([{ kind: "continuation_consommee", ticket, request_state_sha256: shaRs }]);
        // Rejouée : pas 3 ; le service rend approuve, RL-3 refuse un second relais.
        const r4 = await b.recevoir(appel(4, "demo__payments.create", ARGS, META, { requestState: RS, inputResponses: {} }));
        expect(r4.error, JSON.stringify(r4)).to.deep.include({ code: -31010 });
        expect(r4.error.data).to.deep.equal({ reason: "approbation" });
        expect(compter(service, "evaluer")).to.equal(evaluer + 1);
        expect(b.coeur.journal.trouver("approval_relay_refused").at(-1).data).to.deep.equal({ check: "RL-3" });
        expect((await b.evenements()).length, "aucun événement pour un relais refusé").to.equal(3);
      } finally {
        await b.fermer();
      }
    });

    it("EX-4.21 : continuation d'un appel approuvé sous d'autres arguments (MAC différent) : pas d'héritage, pas 3 (autre demande, signal en_attente), jamais un relais sous l'approbation ; la ligne continuation reste inemployée", async function () {
      const { b, service } = await appelApprouveInputRequired();
      try {
        const evaluer = compter(service, "evaluer");
        const r = await b.recevoir(appel(3, "demo__payments.create", { claim_id: "4243" }, META, { requestState: RS, inputResponses: {} }));
        expect(compter(service, "evaluer"), "pas 3").to.equal(evaluer + 1);
        // Autres arguments : une autre demande, ticket nouveau, signal en_attente ; jamais un relais sous l'approbation.
        expect(r.result?._meta?.["noortrace/approval"]?.state, JSON.stringify(r)).to.equal("en_attente");
        expect(lignesApprobations(b).filter((l) => l.kind === "continuation_consommee")).to.deep.equal([]);
        expect((await b.evenements()).filter((e) => e.execution.status === "executee")).to.have.length(1);
      } finally {
        await b.fermer();
      }
    });

    it("EX-4.21 : après un redémarrage, l'enregistrement de continuation d'un appel approuvé se reconstruit depuis la ligne continuation, l'événement executee et la ligne mac de la retenue : la ré-émission hérite (aucun evaluer, même approval, ligne continuation_consommee), une seule fois", async function () {
      const { b, service, ticket } = await appelApprouveInputRequired();
      await b.fermer();
      const b2 = await banc({ dir: b.dir, service, horloge: b.horloge, repondre: () => ({ content: [{ type: "text", text: "paye" }], isError: false }) });
      try {
        expect(b2.frontal.continuations.size, "aucun enregistrement en mémoire").to.equal(0);
        const evaluer = compter(service, "evaluer");
        const r = await b2.recevoir(appel(3, "demo__payments.create", ARGS, META, { requestState: RS, inputResponses: {} }));
        expect(r.result?.isError, JSON.stringify(r)).to.equal(false);
        expect(compter(service, "evaluer"), "héritage sans evaluer").to.equal(evaluer);
        const evts = await b2.evenements();
        expect(evts.map((e) => e.execution.status)).to.deep.equal(["retenue", "executee", "executee"]);
        expect(evts[2].approval).to.deep.equal(evts[1].approval);
        expect(evts[2].policy).to.deep.equal(evts[1].policy);
        await laisserTourner(20);
        expect(service.messages.filter((m) => m.methode === "consommer" && m.corps.seq === evts[2].seq), "aucun consommer pour la continuation").to.deep.equal([]);
        expect(lignesApprobations(b2).filter((l) => l.kind === "continuation_consommee")).to.deep.equal([{ kind: "continuation_consommee", ticket, request_state_sha256: shaRs }]);
        const r2 = await b2.recevoir(appel(4, "demo__payments.create", ARGS, META, { requestState: RS, inputResponses: {} }));
        expect(r2.error?.data, JSON.stringify(r2)).to.deep.equal({ reason: "approbation" });
        expect((await b2.evenements()).length).to.equal(3);
      } finally {
        await b2.fermer();
      }
    });

    it("EX-4.23 : annulation par l'hôte (stdio) relayée au serveur ; événement -31012 ; aucune réponse rendue", async function () {
      const b = await banc({ repondre: () => null });
      const p = b.frontal.recevoir(b.session, appel("a-1", "demo__slow.op", {}));
      // Annulation pendant le relais : attendre que l'appel soit parti vers le serveur (borné).
      for (let k = 0; k < 500 && !b.ecrit.some((l) => JSON.parse(l).method === "tools/call"); k++) await laisserTourner(10);
      await b.recevoir(ligne({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: "a-1" } }));
      expect(await p).to.equal(null);
      const annul = JSON.parse(b.ecrit.at(-1));
      expect(annul).to.deep.include({ method: "notifications/cancelled" });
      expect(annul.params.requestId).to.match(/^e-[0-9]{12}$/);
      const [e] = await b.evenements();
      expect(e.execution.is_error).to.equal(true);
      expect(Buffer.from(await b.coeur.pieces.lire(e.execution.result.sha256)).toString()).to.equal('{"noortrace_jsonrpc_error":{"code":-31012,"message":"noortrace: appel annule par l\'hote"}}');
      await b.fermer();
    });

    it("EX-4.24 : l'enregistreur n'émet que les codes de la table de 4.4, les codes JSON-RPC standard et -32020 à -32022", function () {
      for (const c of [-31010, -31011, -31012, -31013, -31014, -31016, -31017, -32700, -32600, -32601, -32602, -32603, -32020, -32022]) expect(() => objetErreur(c)).to.not.throw();
      for (const c of [-31015, -32000, -32001, -32002, -32042, -32050, 404, 500]) expect(() => objetErreur(c), String(c)).to.throw(RangeError);
    });

    it("EX-4.33, EX-4.48 : le serveur meurt pendant l'appel → -31014 et événement ; relance au prochain appel", async function () {
      let premier = true;
      const b = await banc({
        repondre: (m, enfant) => {
          if (premier) {
            premier = false;
            setImmediate(() => enfant.finDeFichier());
            return null;
          }
          return { content: [], isError: false };
        },
      });
      const r = await b.recevoir(appel(1, "demo__claims.get", {}));
      expect(r.error.code).to.equal(-31014);
      expect((await b.evenements())[0].execution.is_error).to.equal(true);
      b.horloge.avancer(2000);
      const r2 = await b.recevoir(appel(2, "demo__claims.get", {}));
      expect(r2.result.isError).to.equal(false);
      expect(b.enfants.length).to.equal(2);
      await b.fermer();
    });

    it("EX-4.31 (amont) : ligne avec CR, JSON non strict ou lot du serveur ignorés et consignés (invalid_line) ; l'appel finit par délai", async function () {
      const b = await banc({
        reglages: { "claims.get": reglageOutil({ timeout_ms: 200 }) },
        repondre: (m, enfant) => {
          setImmediate(() => {
            enfant.repondre(`{"jsonrpc":"2.0","id":"${m.id}",\r"result":{}}`);
            enfant.repondre(`[{"jsonrpc":"2.0","id":"${m.id}","result":{}}]`);
          });
          return null;
        },
      });
      const r = await b.recevoir(appel(1, "demo__claims.get", {}));
      expect(r.error.code).to.equal(-31011);
      expect(b.coeur.journal.trouver("invalid_line").map((l) => l.data.reason)).to.deep.equal(["cr", "lot"]);
      await b.fermer();
    });

    it("EX-4.46 : panne du stockage après relais → -31017 avec intent_id, événement gardé en attente", async function () {
      const b = await banc();
      const ecrire = b.coeur.pieces.ecrire.bind(b.coeur.pieces);
      b.redacteur.redigerResultat = async (v) => {
        b.coeur.pieces.ecrire = async () => {
          throw new ErreurEnregistreur("stockage", "noortrace: stockage indisponible");
        };
        return { piece: (await import("@noortrace/enregistreur")).pieceJson(v), valeur: v, redacted: false, non_redigeable: null };
      };
      const r = await b.recevoir(appel(1, "demo__payments.create", { claim_id: "x" }));
      expect(r.error.code).to.equal(-31017);
      expect(r.error.message).to.equal("noortrace: appel execute, evenement non durable");
      expect(r.error.data.intent_id).to.match(/^i-[0-9]{20}-[0-9]{12}$/);
      expect(r.error.data.reason).to.equal("stockage");
      expect(b.coeur.attente.length).to.equal(1);
      b.coeur.pieces.ecrire = ecrire;
      await b.fermer();
    });

    it("EX-4.47 : quotas par connexion d'hôte : requêtes en cours, octets reçus (requêtes refusées comprises)", async function () {
      const quota = { max_concurrent: 1, piece_bytes_per_minute: 268435456, received_bytes_per_minute: 4000, redaction_ms_per_minute: 30000 };
      const b = await banc({ hosts: [hoteDemo({ quota })], repondre: () => null, reglages: { "slow.op": reglageOutil({ timeout_ms: 300 }) } });
      const lent = b.recevoir(appel(1, "demo__slow.op", {}));
      await laisserTourner(20);
      expect((await b.recevoir(appel(2, "demo__claims.get", {}))).error).to.deep.equal({ code: -31013, message: "noortrace: taille maximale depassee", data: { limit_requests: 1, direction: "quota" } });
      await lent;
      expect((await b.recevoir(appel(3, "demo__claims.get", { x: "y".repeat(4000) }))).error.data).to.deep.equal({ limit_bytes: 4000, direction: "quota" });
      expect(b.coeur.metriques.exposer()).to.match(/noortrace_calls_blocked_total\{class="",code="-31013",reason="quota"\} 2/);
      const q = new QuotasHote({ max_concurrent: 5, piece_bytes_per_minute: 10, received_bytes_per_minute: 1e9, redaction_ms_per_minute: 5 });
      q.piece(0, 10);
      expect(q.depasse(1000)).to.deep.equal({ limit_bytes: 10, direction: "quota" });
      expect(q.depasse(61001)).to.equal(null);
      q.tempsCapture(70000, 6);
      expect(q.depasse(70001)).to.deep.equal({ limit_ms: 5, direction: "quota" });
      await b.fermer();
    });

    it("EX-4.45 : sans liste servie, la définition et la liste courantes en tiennent lieu (definition_non_servie) ; context retirable", async function () {
      const b = await banc();
      await b.recevoir(appel(1, "demo__claims.get", {}));
      expect(b.coeur.journal.trouver("definition_non_servie").length).to.equal(1);
      expect((await b.evenements())[0].context.length).to.equal(2);
      await b.fermer();
      const c = await banc({ tools: { definition_in_context: false, list_in_context: false } });
      await c.recevoir(appel(1, "demo__claims.get", {}));
      expect((await c.evenements())[0].context).to.deep.equal([]);
      await c.fermer();
    });

    it("4.4 pas 4, EX-10.23 : arguments non rédigeables d'une écriture → -31010 `redaction`, sans relais ni événement ; d'une lecture : relayée", async function () {
      const redacteur = new RedacteurTest({ budgetDepasse: (portee) => portee === "arguments" });
      const b = await banc({ redacteur });
      expect((await b.recevoir(appel(1, "demo__payments.create", { a: 1 }))).error).to.deep.equal({ code: -31010, message: "noortrace: appel bloque, enregistreur en mode degrade", data: { reason: "redaction" } });
      expect(b.ecrit).to.deep.equal([]);
      expect((await b.recevoir(appel(2, "demo__claims.get", { a: 1 }))).result.isError).to.equal(false);
      const [e] = await b.evenements();
      expect(e.execution.arguments.redacted).to.equal(true);
      expect(e.policy.redaction).to.equal(b.config.policy.redaction.name);
      await b.fermer();
    });
  });

  describe("approbation au pas 3 à 7 (EX-4.49, EX-4.50, EX-7.16, 14.2)", function () {
    it("EX-4.49 : signal d'un ticket refusé ou expiré (`state` de ticket_state) ; refus sans ticket : texte fixe", function () {
      expect(resultatEnregistreur({ moderne: true, approbation: { ticket: "apr-1", state: "expire" } })).to.equal(
        '{"resultType":"complete","content":[{"type":"text","text":"noortrace: appel soumis a approbation ; ticket=apr-1 ; state=expire"}],"isError":true,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"noortrace-enregistreur","version":"0.1.0"},"noortrace/approval":{"ticket":"apr-1","state":"expire"}}}',
      );
      expect(resultatEnregistreur({ moderne: false })).to.equal('{"content":[{"type":"text","text":"noortrace: appel refuse par la politique"}],"isError":true,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"noortrace-enregistreur","version":"0.1.0"}}}');
    });

    it("14.2 : service d'approbation indisponible : écriture et outil susceptible bloqués (-31010 approbation) ; autre lecture passante, decision autorise, rule null", async function () {
      const b = await banc({ evaluer: () => Promise.reject(new Error("panne")), candidats: ["demo__slow.op"] });
      b.coeur.definirOutils(b.frontal.agregat.annonces.map((x) => ({ tool_announced: x.announced, tool_original: x.original, server_alias: x.server_alias, class: x.class, effects: null })));
      await laisserTourner(10);
      expect((await b.recevoir(appel(1, "demo__payments.create", {}))).error.data).to.deep.equal({ reason: "approbation" });
      expect((await b.recevoir(appel(2, "demo__slow.op", {}))).error.data).to.deep.equal({ reason: "approbation" });
      expect((await b.recevoir(appel(3, "demo__claims.get", {}))).result.isError).to.equal(false);
      const [e] = await b.evenements();
      expect(e.policy).to.deep.include({ decision: "autorise", rule: null, ticket: null });
      expect(b.coeur.journal.trouver("call_blocked").length).to.equal(2);
      await b.fermer();
    });

    it("EX-7.16 : réponse d'evaluer hors des combinaisons → -31010 approbation, jamais un relais", async function () {
      const b = await banc({ evaluer: () => ({ rule: null, decision: "autorise", ticket: "t-1", ticket_state: null, approval: null, approver_set: null }) });
      expect((await b.recevoir(appel(1, "demo__payments.create", {}))).error.data.reason).to.equal("approbation");
      expect(b.ecrit).to.deep.equal([]);
      await b.fermer();
    });

    it("EX-4.50 : mode retenir : la requête est retenue jusqu'à la décision approuvée (acquitter held), puis relayée ; délai de rétention → en_attente", async function () {
      const dirS = { org_id: null };
      const b = await banc({
        mode: "retenir",
        ajuster: (c) => {
          dirS.org_id = c.recorder.org_id;
          dirS.journal_id = c.recorder.journal_id;
          c.policy.approval.hold_timeout_ms = 2000;
        },
        service: new ServiceApprobationFactice({ org_id: "0x" + "00".repeat(32), journal_id: "0x" + "00".repeat(32), decider: (q) => (q.tool_announced === "demo__payments.create" ? { decision: "a_approuver", rule: "revue" } : { decision: "autorise", rule: null }) }),
      });
      b.service.org_id = b.config.recorder.org_id;
      b.service.journal_id = b.config.recorder.journal_id;
      b.coeur.brancherRetention({ retient: (t) => b.frontal.retentions.has(t), decidee: (t, e) => b.frontal._decisionRetenue(t, e) });
      const p = b.frontal.recevoir(b.session, appel(1, "demo__payments.create", { claim_id: "7" }));
      // La retenue est scellée (fsync compris) avant la rétention : attendue, bornée, plutôt qu'un délai fixe.
      // `ouvrir` part sans être attendu (EX-7.18) : attendre aussi que le service l'ait reçu.
      const ouvert = () => [...b.frontal.retentions.keys()].some((t) => b.service.tickets.get(t)?.request);
      for (let k = 0; k < 500 && !ouvert(); k++) await laisserTourner(10);
      const [ticket] = [...b.frontal.retentions.keys()];
      expect(ticket).to.match(/^apr-test-/);
      b.service.decider_ticket(ticket);
      const acq = await b.coeur.traiterRemises();
      expect(acq[0]).to.deep.include({ result: "scelle", held: true });
      const r = JSON.parse(await p);
      expect(r.result.isError).to.equal(false);
      const evts = await b.evenements();
      expect(evts.map((e) => e.execution.status)).to.deep.equal(["retenue", "executee"]);
      expect(evts[1].approval.decision).to.equal("approuve");
      // Délai de rétention : signal en_attente.
      const p2 = b.frontal.recevoir(b.session, appel(2, "demo__payments.create", { claim_id: "8" }));
      const r2 = JSON.parse(await p2);
      expect(r2.result._meta["noortrace/approval"].state).to.equal("en_attente");
      await b.fermer();
    });

    it("14.2, EX-14.6, EX-14.8 : mode dégradé « stockage » : lecture passante relayée, réponse normale, événement en attente ; écriture bloquée ; « clé » bloque tout", async function () {
      const b = await banc();
      b.coeur.degrade.entrer("stockage");
      const lecture = await b.recevoir(appel(1, "demo__claims.get", {}));
      expect(lecture.result.isError).to.equal(false);
      expect(b.coeur.attente.length).to.equal(1);
      expect(b.coeur.journal.trouver("call_passthrough_pending").length).to.equal(1);
      expect((await b.recevoir(appel(2, "demo__payments.create", {}))).error.data).to.deep.equal({ reason: "stockage" });
      b.coeur.degrade.sortir("stockage");
      await b.coeur.viderAttente();
      expect((await b.evenements()).length).to.equal(1);
      b.coeur.degrade.entrer("cle");
      expect((await b.recevoir(appel(3, "demo__claims.get", {}))).error.data).to.deep.equal({ reason: "cle" });
      b.coeur.degrade.sortir("cle");
      await b.fermer();
    });

    it("14.2 « clé indisponible » (détection : appel au signataire, EX-11.18 `sign`) : l'échec de la signature d'un point de contrôle ou d'une clôture de période met le démon en mode dégradé « clé » (degraded_enter, jauge noortrace_degraded à 1, santé down) ; l'appel suivant est bloqué avant le relais (-31010, raison cle), jamais relayé puis rendu -31017 ; sortie par health() et signature de test, l'événement en attente scellé (EX-14.10, EX-14.11)", async function () {
      // Backend dont `sign` échoue sur commande ; `health()` répond toujours `ok`
      // et n'est appelé qu'une fois par heure : seule la signature révèle la panne.
      const panne = { active: false };
      const b = await banc({
        ajuster: (c) => (c.signer.health_interval_ms = 3600000),
        signataire: async (config, secrets) => {
          const reel = await signataireDepuisConfiguration(config, secrets);
          return new Proxy(reel, {
            get(cible, cle) {
              if (cle === "signer" && panne.active) return async () => { throw new Error("backend de signature arrêté"); };
              const v = cible[cle];
              return typeof v === "function" ? v.bind(cible) : v;
            },
          });
        },
      });
      const h = b.horloge;
      const jauge = () => b.coeur.metriques.valeur("noortrace_degraded", { reason: "cle" });
      const entrees = () => b.coeur.journal.trouver("degraded_enter").filter((l) => l.data?.reason === "cle").length;
      const relayes = () => b.ecrit.filter((l) => JSON.parse(l).method === "tools/call").length;
      try {
        expect((await b.recevoir(appel(1, "demo__payments.create", { claim_id: "1" }))).result.isError).to.equal(false);
        // (a) Point de contrôle aligné (10:21:00) signé pendant la panne.
        panne.active = true;
        h.aller(ms("2026-11-10T10:21:00.300Z"));
        await b.coeur.tic();
        expect(b.coeur.journal.trouver("signer_unavailable").length, "signer_unavailable consigné").to.be.at.least(1);
        expect(b.coeur.degrade.actif("cle"), "mode « clé » après l'échec du point de contrôle").to.equal(true);
        expect(entrees()).to.equal(1);
        expect(jauge()).to.equal(1);
        expect(b.coeur.sante().corps.status).to.equal("down");
        const avant = relayes();
        const r2 = await b.recevoir(appel(2, "demo__payments.create", { claim_id: "2" }));
        expect(r2.error, JSON.stringify(r2)).to.deep.include({ code: -31010, message: "noortrace: appel bloque, enregistreur en mode degrade" });
        expect(r2.error.data).to.deep.equal({ reason: "cle" });
        expect(relayes(), "aucun relais en mode « clé »").to.equal(avant);
        panne.active = false;
        await b.coeur.tic();
        expect(b.coeur.degrade.actif("cle"), "sortie : health() et signature de test (EX-14.11)").to.equal(false);
        expect(jauge()).to.equal(0);
        // (b) Clôture de la période de 10 h exigée par un appel relayé à 11:00:05.
        panne.active = true;
        h.aller(ms("2026-11-10T11:00:05.000Z"));
        const r3 = await b.recevoir(appel(3, "demo__payments.create", { claim_id: "3" }));
        expect(r3.error, JSON.stringify(r3)).to.deep.include({ code: -31017 });
        expect(r3.error.data.reason).to.equal("cle");
        expect(b.coeur.degrade.actif("cle"), "mode « clé » après l'échec de la clôture").to.equal(true);
        expect(entrees()).to.equal(2);
        expect(jauge()).to.equal(1);
        const avant4 = relayes();
        const r4 = await b.recevoir(appel(4, "demo__claims.get", {}));
        expect(r4.error, JSON.stringify(r4)).to.deep.include({ code: -31010 });
        expect(r4.error.data).to.deep.equal({ reason: "cle" });
        expect(relayes(), "lecture non relayée non plus (« clé » bloque tout)").to.equal(avant4);
        expect(b.coeur.attente.length).to.equal(1);
        panne.active = false;
        await b.coeur.tic();
        expect(b.coeur.degrade.actif("cle")).to.equal(false);
        expect(b.coeur.attente.length, "événement en attente scellé à la sortie (EX-14.10)").to.equal(0);
        const evts = await b.evenements();
        // Appels 1 et 3 scellés ; 2 et 4, bloqués avant le relais, n'ont aucun événement.
        expect(evts.map((e) => e.execution.status)).to.deep.equal(["executee", "executee"]);
      } finally {
        panne.active = false;
        await b.fermer();
      }
    });
  });

  describe("§7.2 délégation (EX-7.2, EX-7.3)", function () {
    it("EX-7.2 : on_behalf_of admis seulement dans la liste ; run_id au motif et sans détecteur ; refus consigné sans la valeur", function () {
      const hote = { ...hoteDemo(), allowed_on_behalf_of: ["service-a"], launched_by: "${peer_user}" };
      const refus = [];
      const ok = resoudreDelegation({ hote, identite: { peer_user: "u1" }, declaree: { on_behalf_of: "service-a", run_id: "run-1" }, refus: (...x) => refus.push(x) });
      expect(ok).to.deep.equal({ launched_by: "u1", on_behalf_of: "service-a", scope: hote.scope, run_id: "run-1" });
      const ko = resoudreDelegation({ hote, identite: { peer_user: "u1" }, declaree: { on_behalf_of: "pirate", run_id: "a b" }, refus: (...x) => refus.push(x) });
      expect(ko).to.deep.equal({ launched_by: "u1", on_behalf_of: "service-sinistres", scope: hote.scope, run_id: null });
      const det = resoudreDelegation({ hote, identite: {}, declaree: { run_id: "run-jean.dupont" }, detecte: () => true, refus: (...x) => refus.push(x), sessionHeritee: "s-1" });
      expect(det.run_id).to.equal("s-1");
      expect(refus).to.deep.equal([["on_behalf_of", "hors_liste", 6], ["run_id", "motif", 3], ["run_id", "detecteur", 15]]);
      const sans = resoudreDelegation({ hote: { ...hote, accept_declared_delegation: false }, identite: { peer_user: "u" }, declaree: { run_id: "run-2", on_behalf_of: "service-a" } });
      expect(sans).to.deep.include({ run_id: null, on_behalf_of: "service-sinistres" });
    });

    it("EX-7.2 : le détecteur du rédacteur refuse un run_id ; ligne delegation_refused sans la valeur", async function () {
      const b = await banc({ redacteur: new RedacteurTest({ runIdRefuse: (v) => v.includes("dupont") }) });
      await b.recevoir(appel(1, "demo__claims.get", {}, { ...META, "noortrace/delegation": { run_id: "run-dupont" } }));
      const [e] = await b.evenements();
      expect(e.delegation.run_id).to.equal(null);
      const l = b.coeur.journal.trouver("delegation_refused")[0];
      expect(l.data).to.deep.equal({ component: "frontal_mcp", field: "run_id", reason: "detecteur", length: 10 });
      expect(JSON.stringify(b.coeur.journal.lignes)).to.not.include("run-dupont");
      await b.fermer();
    });
  });

  describe("4.7 et 4.8 transports et authentification (EX-4.31 à EX-4.42, EX-7.3)", function () {
    it("EX-4.39, EX-7.3 : prise Unix : utilisateur prouvé par fichier, connecteur relaie ; utilisateur sans entrée refusé ; CR rejeté par le connecteur", async function () {
      const moi = os.userInfo().username;
      const b = await banc({ hosts: [hoteDemo({ match: { peer_user: moi }, launched_by: "${peer_user}" })] });
      const s = new ServeurConnecteurs({ frontal: b.frontal, socket: b.config.mcp.socket });
      await s.ecouter();
      const sortie = [];
      const entree = new (await import("node:stream")).PassThrough();
      const fin = executerConnecteur({ socket: b.config.mcp.socket, entree, sortie: { write: (x) => sortie.push(String(x)) }, erreur: { write: () => {} } });
      await new Promise((r) => setTimeout(r, 150));
      entree.write(appel(1, "demo__claims.get", {}) + "\n");
      entree.write('{"a":1}\r\n');
      entree.write("Content-Length: 12\n");
      await new Promise((r) => setTimeout(r, 300));
      entree.end();
      expect(await fin).to.equal(0);
      const lignes = sortie.join("").trim().split("\n").map((x) => JSON.parse(x));
      expect(lignes.find((x) => x.id === 1).result.isError).to.equal(false);
      expect(lignes.find((x) => x.id === null).error.data.reason).to.equal("cr_dans_la_ligne");
      expect((await b.evenements())[0].delegation.launched_by).to.equal(moi);
      expect(fs.readdirSync(path.dirname(b.config.mcp.socket)).filter((f) => f.startsWith(".noortrace-defi-"))).to.deep.equal([]);
      await s.fermer();
      await b.fermer();
      // Utilisateur sans entrée de mcp.hosts : connexion refusée.
      const c = await banc({ hosts: [hoteDemo({ match: { peer_user: "personne-xyz" } })] });
      const s2 = new ServeurConnecteurs({ frontal: c.frontal, socket: c.config.mcp.socket });
      await s2.ecouter();
      const code = await executerConnecteur({ socket: c.config.mcp.socket, entree: new (await import("node:stream")).PassThrough(), sortie: { write: () => {} }, erreur: { write: () => {} } });
      expect(code).to.equal(1);
      expect(c.coeur.journal.trouver("auth_failed")[0].data.reason).to.equal("hote_inconnu");
      await s2.fermer();
      await c.fermer();
    });

    it("EX-4.39 : prise Unix : un défi sans fichier, ou un fichier lié, est refusé", async function () {
      const moi = os.userInfo().username;
      const b = await banc({ hosts: [hoteDemo({ match: { peer_user: moi } })] });
      const s = new ServeurConnecteurs({ frontal: b.frontal, socket: b.config.mcp.socket });
      await s.ecouter();
      for (const mode of ["sans_fichier", "lien"]) {
        const c = net.createConnection(b.config.mcp.socket);
        const ferme = new Promise((r) => c.on("close", r));
        c.once("data", (d) => {
          const defi = JSON.parse(String(d)).noortrace_defi;
          if (mode === "lien") {
            const cible = path.join(b.dir, "cible");
            fs.writeFileSync(cible, "");
            fs.linkSync(cible, path.join(path.dirname(b.config.mcp.socket), `.noortrace-defi-${defi}`));
          }
          c.write(JSON.stringify({ noortrace_preuve: defi }) + "\n");
        });
        await ferme;
      }
      expect(b.coeur.journal.trouver("auth_failed").map((l) => l.data.reason)).to.deep.equal(["preuve", "preuve"]);
      await s.fermer();
      await b.fermer();
    });

    it("EX-4.39 : prise TCP : première ligne {noortrace_token}, comparée en temps constant ; jeton faux refusé ; ligne trop longue -31013 puis reprise", async function () {
      const b = await banc({
        hosts: [hoteDemo({ match: { static_token: "poste" } })],
        limits: { line_max_bytes: 2048 },
        ajuster: (c) => (c.mcp.http = { listen: "127.0.0.1:0", path: "/mcp", allowed_origins: [], tls: null, oauth: null, static_tokens: [{ id: "poste", token: { env: "X" } }] }),
      });
      const s = new ServeurConnecteurs({ frontal: b.frontal, tcp: { listen: "127.0.0.1:0", client_auth: "jeton", tls: null }, jetons: new Map([["poste", N.utf8("jeton-secret")]]) });
      await s.ecouter();
      const { port } = s.adresseTcp();
      const parler = (jeton, lignes) =>
        new Promise((res) => {
          const c = net.createConnection(port, "127.0.0.1");
          let recu = "";
          c.on("data", (d) => {
            recu += d;
            if (recu.includes("acceptee")) {
              for (const l of lignes) c.write(l + "\n");
              lignes.length = 0;
              setTimeout(() => c.end(), 300);
            }
          });
          c.on("close", () => res(recu));
          c.write(JSON.stringify({ noortrace_token: jeton }) + "\n");
        });
      const bon = await parler("jeton-secret", [appel(1, "demo__claims.get", { x: "z".repeat(3000) }), appel(2, "demo__claims.get", {})]);
      // Les lignes `noortrace_journal` vont à la sortie d'erreur du connecteur (EX-9.7, lecture 145).
      const toutes = bon.trim().split("\n").map((x) => JSON.parse(x));
      expect(toutes.filter((x) => x.noortrace_journal).map((x) => x.noortrace_journal.event)).to.deep.equal(["request_too_large"]);
      const lignes = toutes.filter((x) => !x.noortrace_journal);
      expect(lignes[1].error).to.deep.equal({ code: -31013, message: "noortrace: taille maximale depassee", data: { limit_bytes: 2048, direction: "requete" } });
      expect(lignes[2].id).to.equal(2);
      expect(await parler("mauvais", [])).to.equal("");
      await s.fermer();
      await b.fermer();
    });

    it("EX-4.34 à EX-4.37 : Streamable HTTP : jeton exigé, Origin, 405, en-têtes comparés, Accept, notification 202, méthode inconnue 404, SSE, session héritée", async function () {
      const b = await banc({
        hosts: [hoteDemo({ match: { static_token: "poste" } })],
        ajuster: (c) => (c.mcp.http = { listen: "127.0.0.1:0", path: "/mcp", allowed_origins: ["http://127.0.0.1"], tls: null, oauth: null, static_tokens: [{ id: "poste", token: { env: "X" } }] }),
        repondre: (m, enfant) => {
          const jeton = m.params._meta.progressToken;
          if (jeton) enfant.repondre(ligne({ jsonrpc: "2.0", method: "notifications/progress", params: { progressToken: jeton, progress: 1 } }));
          return { content: [], isError: false };
        },
      });
      const s = new ServeurHttpMcp({ frontal: b.frontal, jetons: new Map([["poste", N.utf8("jeton-http")]]) });
      await s.ecouter();
      const { port } = s.adresse();
      const req = (methode, corps, entetes = {}) =>
        new Promise((res) => {
          const r = http.request({ host: "127.0.0.1", port, path: "/mcp", method: methode, headers: { authorization: "Bearer jeton-http", "content-type": "application/json", accept: "application/json, text/event-stream", ...entetes } }, (x) => {
            const m = [];
            x.on("data", (c) => m.push(c));
            x.on("end", () => res({ statut: x.statusCode, entetes: x.headers, corps: Buffer.concat(m).toString() }));
          });
          r.end(corps);
        });
      const corps = appel(1, "demo__claims.get", {});
      const h = { "mcp-protocol-version": "2026-07-28", "mcp-method": "tools/call", "mcp-name": "demo__claims.get" };
      expect((await req("POST", corps, h)).statut).to.equal(200);
      expect((await req("POST", corps, { ...h, authorization: "Bearer x" })).statut).to.equal(401);
      expect((await req("POST", corps, { ...h, origin: "http://evil.example" })).statut).to.equal(403);
      expect((await req("POST", corps, { ...h, origin: "http://127.0.0.1" })).statut).to.equal(200);
      expect((await req("GET", undefined, {})).statut).to.equal(405);
      expect((await req("DELETE", undefined, {})).statut).to.equal(405);
      const ecart = await req("POST", corps, { ...h, "mcp-protocol-version": "2025-11-25" });
      expect([ecart.statut, JSON.parse(ecart.corps).error.code]).to.deep.equal([400, -32020]);
      const ecart2 = await req("POST", corps, { ...h, "mcp-method": "tools/list" });
      expect(JSON.parse(ecart2.corps).error.code).to.equal(-32020);
      expect((await req("POST", corps, { ...h, accept: "application/json" })).statut).to.equal(406);
      expect((await req("POST", ligne({ jsonrpc: "2.0", method: "notifications/x", params: { _meta: META } }), { ...h, "mcp-method": "notifications/x" })).statut).to.equal(202);
      const inconnue = await req("POST", ligne({ jsonrpc: "2.0", id: 5, method: "inconnue/x", params: { _meta: META } }), { ...h, "mcp-method": "inconnue/x" });
      expect([inconnue.statut, JSON.parse(inconnue.corps).error.code]).to.deep.equal([404, -32601]);
      // Notification de progression : réponse en SSE, sans tampon (EX-4.36).
      const sse = await req("POST", appel(6, "demo__claims.get", {}, { ...META, progressToken: 9 }), h);
      expect(sse.entetes["content-type"]).to.equal("text/event-stream");
      expect(sse.entetes["x-accel-buffering"]).to.equal("no");
      const evts = sse.corps.split("\n\n").filter(Boolean).map((x) => JSON.parse(x.replace(/^data: /, "")));
      expect(evts[0]).to.deep.equal({ jsonrpc: "2.0", method: "notifications/progress", params: { progressToken: 9, progress: 1 } });
      expect(evts[1].id).to.equal(6);
      // Ère héritée : session frappée par initialize, exigée ensuite, DELETE.
      const init = await req("POST", ligne({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "h", version: "1" } } }));
      const id = init.entetes["mcp-session-id"];
      expect(id).to.match(/^[0-9a-f]{32}$/);
      expect((await req("POST", ligne({ jsonrpc: "2.0", method: "notifications/initialized" }), { "mcp-session-id": id })).statut).to.equal(202);
      const l = await req("POST", ligne({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }), { "mcp-session-id": id });
      expect(Object.keys(JSON.parse(l.corps).result)).to.deep.equal(["tools"]);
      expect((await req("POST", ligne({ jsonrpc: "2.0", id: 3, method: "tools/list", params: {} }))).statut).to.equal(400);
      expect((await req("POST", ligne({ jsonrpc: "2.0", id: 3, method: "tools/list", params: {} }), { "mcp-session-id": "inconnue" })).statut).to.equal(404);
      expect((await req("DELETE", undefined, { "mcp-session-id": id })).statut).to.equal(200);
      expect((await req("POST", ligne({ jsonrpc: "2.0", id: 4, method: "tools/list", params: {} }), { "mcp-session-id": id })).statut).to.equal(404);
      // Aucun en-tête d'authentification journalisé (EX-4.41).
      expect(JSON.stringify(b.coeur.journal.lignes)).to.not.include("jeton-http");
      await s.fermer();
      await b.fermer();
    });

    it("EX-4.39 : jeton OAuth : signature, audience, émetteur, expiration, portée (401 / 403), métadonnées de ressource protégée", async function () {
      const { publicKey, privateKey } = generateKeyPairSync("ed25519");
      const jwk = { ...publicKey.export({ format: "jwk" }), kid: "k1" };
      const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
      const jwt = (charge) => {
        const e = b64({ alg: "EdDSA", kid: "k1" });
        const c = b64(charge);
        return `${e}.${c}.${signer(null, Buffer.from(`${e}.${c}`), privateKey).toString("base64url")}`;
      };
      const o = { jwks: { keys: [jwk] }, resource: "https://noortrace.local/mcp", issuers: ["https://as.local"], scopes: ["mcp"], maintenant: Date.now() };
      const base = { aud: o.resource, iss: "https://as.local", sub: "alice", scope: "mcp autre", exp: Math.floor(Date.now() / 1000) + 600 };
      expect(verifierJwt(jwt(base), o)).to.deep.equal({ sub: "alice" });
      const statut = (c) => {
        try {
          verifierJwt(jwt(c), o);
          return 200;
        } catch (e) {
          return [e.statut, e.raison];
        }
      };
      expect(statut({ ...base, aud: "https://autre" })).to.deep.equal([401, "audience"]);
      expect(statut({ ...base, iss: "https://x" })).to.deep.equal([401, "emetteur"]);
      expect(statut({ ...base, exp: 1 })).to.deep.equal([401, "expire"]);
      expect(statut({ ...base, scope: "autre" })).to.deep.equal([403, "portee"]);
      const falsifie = jwt(base).replace(/\.[^.]+$/, ".AAAA");
      expect(() => verifierJwt(falsifie, o)).to.throw("signature");
      // Serveur HTTP avec OAuth : 401 avec WWW-Authenticate et métadonnées.
      const b = await banc({
        hosts: [hoteDemo({ match: { oauth_subject: "alice" }, launched_by: "${oauth_subject}" })],
        ajuster: (c) => (c.mcp.http = { listen: "127.0.0.1:0", path: "/mcp", allowed_origins: [], tls: null, oauth: { resource: o.resource, authorization_servers: o.issuers, jwks_uri: "https://as.local/jwks", required_scopes: ["mcp"] }, static_tokens: [] }),
      });
      const s = new ServeurHttpMcp({ frontal: b.frontal, chargerJwks: async () => o.jwks });
      await s.ecouter();
      const { port } = s.adresse();
      const get = (p, h = {}) =>
        new Promise((res) => http.get({ host: "127.0.0.1", port, path: p, headers: h }, (x) => {
          const m = [];
          x.on("data", (c) => m.push(c));
          x.on("end", () => res({ statut: x.statusCode, entetes: x.headers, corps: Buffer.concat(m).toString() }));
        }));
      const meta = await get("/.well-known/oauth-protected-resource/mcp");
      expect(JSON.parse(meta.corps)).to.deep.include({ resource: o.resource, authorization_servers: o.issuers });
      const sans = await get("/mcp");
      expect(sans.statut).to.equal(401);
      expect(sans.entetes["www-authenticate"]).to.equal('Bearer resource_metadata="https://noortrace.local/.well-known/oauth-protected-resource/mcp", scope="mcp"');
      const r = await new Promise((res) => {
        const jeton = jwt({ ...base, exp: Math.floor(b.horloge.murale() / 1000) + 600 });
        const q = http.request({ host: "127.0.0.1", port, path: "/mcp", method: "POST", headers: { authorization: `Bearer ${jeton}`, accept: "application/json, text/event-stream", "mcp-protocol-version": "2026-07-28", "mcp-method": "tools/call", "mcp-name": "demo__claims.get" } }, (x) => {
          const m = [];
          x.on("data", (c) => m.push(c));
          x.on("end", () => res(Buffer.concat(m).toString()));
        });
        q.end(appel(1, "demo__claims.get", {}));
      });
      expect(JSON.parse(r).result.isError).to.equal(false);
      expect((await b.evenements())[0].delegation.launched_by).to.equal("alice");
      await s.fermer();
      await b.fermer();
    });

    it("EX-4.35, EX-4.40, EX-4.41 : vers un serveur HTTP, seuls les en-têtes construits par le frontal partent (aucun de l'hôte)", async function () {
      const recus = [];
      const amont = http.createServer((req, res) => {
        const m = [];
        req.on("data", (c) => m.push(c));
        req.on("end", () => {
          const corps = JSON.parse(Buffer.concat(m).toString());
          recus.push({ entetes: req.headers, corps });
          if (corps.id === undefined) return res.writeHead(202).end();
          const result = corps.method === "server/discover" ? { supportedVersions: ["2026-07-28"] } : corps.method === "tools/list" ? { tools: [{ name: "q", inputSchema: { type: "object", properties: { region: { type: "string", "x-mcp-header": "Region" } } } }] } : { content: [], isError: false };
          res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: corps.id, result }));
        });
      });
      await new Promise((r) => amont.listen(0, "127.0.0.1", r));
      const url = `http://127.0.0.1:${amont.address().port}/mcp`;
      const b = await banc({
        servers: { web: { transport: { type: "http", url, headers: { "X-Cle": { env: "NOORTRACE_TEST_CLE_WEB" } }, oauth: null, tls: null }, protocol: "auto", class_default: "lecture", timeout_ms: null, tools: {}, uri_prefixes: [], relay: null } },
        demarrer: true,
        frontal: { secrets: new Map([...secretsDev(), ["/policy/servers/web/transport/headers/X-Cle", N.utf8("cle-propre")]]) },
      });
      const r = await b.recevoir(appel(1, "web__q", { region: "Genève" }, { ...META, authorization: "x" }));
      expect(r.result.isError).to.equal(false);
      const call = recus.find((x) => x.corps.method === "tools/call");
      expect(call.entetes["mcp-method"]).to.equal("tools/call");
      expect(call.entetes["mcp-name"]).to.equal("q");
      expect(call.entetes["mcp-param-region"]).to.equal(`=?base64?${Buffer.from("Genève").toString("base64")}?=`);
      expect(call.entetes["x-cle"]).to.equal("cle-propre");
      expect(Object.keys(call.entetes).sort()).to.deep.equal(["accept", "connection", "content-length", "content-type", "host", "mcp-method", "mcp-name", "mcp-param-region", "mcp-protocol-version", "x-cle"]);
      expect(b.frontal.connexions.get("web")).to.be.instanceOf(ConnexionHttp);
      await b.fermer();
      await new Promise((x) => amont.close(x));
    });
  });

  describe("EX-17.2 journal d'exploitation", function () {
    it("tool_call_relayed (sha256, durée, upstream_id, intent_id), call_blocked, approval_pending ; jamais d'argument ni de résultat", async function () {
      let etat = "nouveau";
      const b = await banc({
        evaluer: (q) =>
          q.tool_announced === "demo__payments.create"
            ? { rule: "r", decision: "a_approuver", ticket: "apr-x-1", ticket_state: etat, approval: null, approver_set: etat === "nouveau" ? { threshold: { required: 1, size: 1 }, members: ["0x70997970c51812dc3a010c7d01b50e0d17dc79c8"], source: "jeu statique de test" } : null }
            : AUTORISE,
      });
      await b.recevoir(appel(1, "demo__claims.get", { secret: "valeur-sensible-1" }));
      await b.recevoir(appel(2, "demo__payments.create", { secret: "valeur-sensible-2" }));
      etat = "en_attente";
      const s = await b.recevoir(appel(3, "demo__payments.create", { secret: "valeur-sensible-2" }));
      expect(s.result._meta["noortrace/approval"]).to.deep.equal({ ticket: "apr-x-1", state: "en_attente" });
      const r = b.coeur.journal.trouver("tool_call_relayed")[0];
      expect(r.component).to.equal("frontal_mcp");
      expect(r.seq).to.be.a("number");
      expect(r.host).to.equal("agent-demo");
      expect(r.request_id).to.equal("1");
      expect(Object.keys(r.data)).to.include.members(["server", "tool_original", "tool_announced", "upstream_id", "intent_id", "arguments_sha256", "result_sha256", "duration_ms", "is_error"]);
      expect(b.coeur.journal.trouver("approval_pending").length).to.equal(1);
      expect(JSON.stringify(b.coeur.journal.lignes)).to.not.match(/valeur-sensible/);
      await b.fermer();
    });
  });

  // Défauts démontrés par la relecture adversariale B des frontaux : chaque
  // essai de la relecture devient un cas de non-régression.
  describe("relecture B : non-régression des transports et du relais MCP", function () {
    const pause = (x) => new Promise((r) => setTimeout(r, x));
    const httpCfg = (c) => (c.mcp.http = { listen: "127.0.0.1:0", path: "/mcp", allowed_origins: [], tls: null, oauth: null, static_tokens: [{ id: "poste", token: { env: "X" } }] });
    const H = { "mcp-protocol-version": "2026-07-28", "mcp-method": "tools/call", "mcp-name": "demo__claims.get" };
    const hoteHttp = (o = {}) => hoteDemo({ match: { static_token: "poste" }, ...o });

    /** Serveur Streamable HTTP du banc et requêtes sur une connexion `keep-alive` unique (ou l'agent donné). */
    async function serveurHttp(b, jeton = "jeton-http") {
      const s = new ServeurHttpMcp({ frontal: b.frontal, jetons: new Map([["poste", N.utf8(jeton)]]) });
      await s.ecouter();
      const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
      const req = (corps, entetes = {}, o = {}) =>
        new Promise((res) => {
          const r = http.request(
            { agent: o.agent ?? agent, host: "127.0.0.1", port: s.adresse().port, path: "/mcp", method: o.methode ?? "POST", headers: { authorization: `Bearer ${o.jeton ?? jeton}`, "content-type": "application/json", accept: "application/json, text/event-stream", ...entetes } },
            (x) => {
              const m = [];
              x.on("data", (c) => m.push(c));
              x.on("end", () => res({ statut: x.statusCode, entetes: x.headers, corps: Buffer.concat(m).toString() }));
            },
          );
          r.on("error", () => res({ statut: null, corps: "" }));
          r.end(corps);
        });
      return { s, req, agent, fermer: async () => (agent.destroy(), await s.fermer()) };
    }

    /** Connexion brute à la prise Unix : `fichier(chemin, défi)` crée la preuve ; rend vrai si l'identité est acceptée. */
    const preuveBrute = (socket, fichier = (f) => fs.closeSync(fs.openSync(f, "wx", 0o600))) =>
      new Promise((res) => {
        const c = net.createConnection(socket);
        let recu = "";
        c.on("data", (d) => {
          recu += d;
          const m = JSON.parse(String(d).split("\n")[0]);
          if (m.noortrace_defi) {
            fichier(path.join(path.dirname(socket), `.noortrace-defi-${m.noortrace_defi}`), m.noortrace_defi);
            c.write(JSON.stringify({ noortrace_preuve: m.noortrace_defi }) + "\n");
          } else if (m.noortrace_identite) c.end();
        });
        c.on("error", () => {});
        c.on("close", () => res(recu.includes("acceptee")));
      });

    it("R-B-1 (EX-4.35, EX-4.20, 4.4 pas 14) : statut HTTP décidé par le code que le frontal produit, jamais par le texte de la réponse", async function () {
      const b = await banc({
        hosts: [hoteHttp()],
        ajuster: httpCfg,
        repondre: (m) => (m.params.arguments.amont ? { error: { code: -32601, message: "Method not found" } } : { content: [{ type: "text", text: "ok" }], structuredContent: m.params.arguments, isError: false }),
      });
      const h = await serveurHttp(b);
      // Résultat d'outil réussi dont le contenu structuré porte {"error":{"code":-32601,…}} : 200, événement executee.
      const r = await h.req(appel(1, "demo__claims.get", { error: { code: -32601, message: "x" } }), H);
      expect([r.statut, JSON.parse(r.corps).result.isError]).to.deep.equal([200, false]);
      expect((await b.evenements()).at(-1).execution.status).to.equal("executee");
      // Erreur -32601 d'un serveur d'outils, relayée (pas 14) : 200.
      const amont = await h.req(appel(2, "demo__claims.get", { amont: true }), H);
      expect([amont.statut, JSON.parse(amont.corps).error.code]).to.deep.equal([200, -32601]);
      // Méthode inconnue du frontal : 404 ; _meta incomplet : 400 meta_requis.
      const inconnue = await h.req(ligne({ jsonrpc: "2.0", id: 3, method: "inconnue/x", params: { _meta: META } }), { ...H, "mcp-method": "inconnue/x" });
      expect([inconnue.statut, JSON.parse(inconnue.corps).error.code]).to.deep.equal([404, -32601]);
      const incomplet = await h.req(ligne({ jsonrpc: "2.0", id: 4, method: "tools/list", params: { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } } }), { ...H, "mcp-method": "tools/list" });
      expect([incomplet.statut, JSON.parse(incomplet.corps).error.data.reason]).to.deep.equal([400, "meta_requis"]);
      await h.fermer();
      await b.fermer();
    });

    it("R-B-2 (EX-4.39, EX-18.1) : répertoire de la prise inscriptible par d'autres sans bit collant refusé au démarrage et à chaque preuve ; fichier antérieur au défi refusé", async function () {
      const moi = os.userInfo().username;
      const b = await banc({ hosts: [hoteDemo({ match: { peer_user: moi } })] });
      const dir = path.dirname(b.config.mcp.socket);
      fs.mkdirSync(dir, { recursive: true });
      fs.chmodSync(dir, 0o777);
      const s = new ServeurConnecteurs({ frontal: b.frontal, socket: b.config.mcp.socket });
      let refus = null;
      await s.ecouter().catch((e) => (refus = e));
      expect(refus?.message).to.match(/répertoire de la prise.*repertoire_inscriptible/);
      await s.fermer();
      // Bit collant : admis ; un répertoire créé par le démon reçoit le mode 1770.
      fs.chmodSync(dir, 0o1777);
      const s2 = new ServeurConnecteurs({ frontal: b.frontal, socket: b.config.mcp.socket });
      await s2.ecouter();
      expect(await preuveBrute(b.config.mcp.socket)).to.equal(true);
      // Le répertoire devient inscriptible sans bit collant après le démarrage : chaque preuve est refusée.
      fs.chmodSync(dir, 0o770);
      fs.chmodSync(dir, 0o777);
      expect(await preuveBrute(b.config.mcp.socket)).to.equal(false);
      expect(b.coeur.journal.trouver("auth_failed").at(-1).data).to.deep.include({ reason: "repertoire_prise", detail: "repertoire_inscriptible" });
      fs.chmodSync(dir, 0o1777);
      // Un fichier du bon propriétaire mais créé avant le défi, puis renommé : refusé (preuve non transférable).
      const ancien = path.join(b.dir, "ancien");
      fs.writeFileSync(ancien, "");
      await pause(1200);
      expect(await preuveBrute(b.config.mcp.socket, (f) => fs.renameSync(ancien, f))).to.equal(false);
      expect(b.coeur.journal.trouver("auth_failed").at(-1).data.reason).to.equal("preuve");
      expect(await preuveBrute(b.config.mcp.socket)).to.equal(true);
      await s2.fermer();
      await b.fermer();
      // Répertoire absent : créé par le démon, mode 1770.
      const c = await banc({ hosts: [hoteDemo({ match: { peer_user: moi } })] });
      const s3 = new ServeurConnecteurs({ frontal: c.frontal, socket: c.config.mcp.socket });
      await s3.ecouter();
      expect(fs.statSync(path.dirname(c.config.mcp.socket)).mode & 0o7777).to.equal(0o1770);
      await s3.fermer();
      await c.fermer();
    });

    it("R-B-2 (EX-4.39, EX-7.3) : deux utilisateurs réels, répertoire à bit collant : un pair ne peut pas renommer la preuve d'un autre", async function () {
      if (process.getuid?.() !== 0) this.skip();
      const b = await banc({
        hosts: [
          hoteDemo({ id: "agent-alice", match: { peer_user: "nobody" }, launched_by: "${peer_user}" }),
          hoteDemo({ id: "agent-mallory", match: { peer_user: "daemon" }, launched_by: "${peer_user}" }),
        ],
      });
      const prise = b.config.mcp.socket;
      const s = new ServeurConnecteurs({ frontal: b.frontal, socket: prise });
      await s.ecouter();
      fs.chmodSync(b.dir, 0o711);
      fs.chmodSync(path.dirname(prise), 0o1777);
      fs.chmodSync(prise, 0o666);
      const client = (utilisateur, code) =>
        new Promise((res) => {
          const p = spawn("runuser", ["-u", utilisateur, "--", process.execPath, "-e", code, prise], { stdio: ["ignore", "pipe", "pipe"] });
          let o = "";
          p.stdout.on("data", (x) => (o += x));
          p.stderr.on("data", (x) => (o += x));
          p.on("close", () => res(o.trim()));
        });
      // Alice crée sa preuve et tarde à l'annoncer ; Mallory tente de renommer le fichier d'Alice sous le nom de son propre défi.
      const alice = client("nobody", `
const net=require("net"),fs=require("fs"),path=require("path");const s=process.argv[1];const c=net.createConnection(s);
c.once("data",(d)=>{const defi=JSON.parse(String(d)).noortrace_defi;fs.closeSync(fs.openSync(path.join(path.dirname(s),".noortrace-defi-"+defi),"wx",0o600));
setTimeout(()=>{c.write(JSON.stringify({noortrace_preuve:defi})+"\\n");},1500);});
c.on("data",(d)=>{if(String(d).includes("acceptee")){console.log("alice: acceptee");c.end();}});setTimeout(()=>process.exit(0),2500);`);
      await pause(400);
      const mallory = client("daemon", `
const net=require("net"),fs=require("fs"),path=require("path");const s=process.argv[1];const dir=path.dirname(s);const c=net.createConnection(s);
c.on("data",(d)=>{const m=JSON.parse(String(d).split("\\n")[0]);
 if(m.noortrace_defi){const autre=fs.readdirSync(dir).find((n)=>n.startsWith(".noortrace-defi-")&&!n.endsWith(m.noortrace_defi));
  try{fs.renameSync(path.join(dir,autre),path.join(dir,".noortrace-defi-"+m.noortrace_defi));console.log("mallory: renomme");}catch(e){console.log("mallory: "+e.code);}
  c.write(JSON.stringify({noortrace_preuve:m.noortrace_defi})+"\\n");}
 else if(m.noortrace_identite){console.log("mallory: acceptee");c.end();}});
c.on("close",()=>console.log("mallory: fermee"));`);
      expect(await mallory).to.equal("mallory: EPERM\nmallory: fermee");
      expect(await alice).to.equal("alice: acceptee");
      const journal = b.coeur.journal.lignes.filter((l) => ["host_connected", "auth_failed"].includes(l.event)).map((l) => [l.event, l.host ?? null, l.data.reason ?? null]);
      expect(journal).to.deep.equal([["auth_failed", null, "preuve"], ["host_connected", "agent-alice", null]]);
      await s.fermer();
      await b.fermer();
    });

    it("R-B-3 (EX-18.3) : échecs de jeton limités par identifiant de jeton et par connexion (prise TCP des connecteurs, Streamable HTTP) ; un jeton valide sur une autre connexion passe", async function () {
      const b = await banc({ hosts: [hoteHttp()], ajuster: httpCfg });
      const tcp = new ServeurConnecteurs({ frontal: b.frontal, tcp: { listen: "127.0.0.1:0", client_auth: "jeton", tls: null }, jetons: new Map([["poste", N.utf8("jeton-valide")]]) });
      await tcp.ecouter();
      const essai = (jeton) =>
        new Promise((res) => {
          const c = net.createConnection(tcp.adresseTcp().port, "127.0.0.1");
          let r = "";
          c.on("data", (d) => {
            r += d;
            if (r.includes("acceptee")) c.end();
          });
          c.on("error", () => {});
          c.on("close", () => res(r.includes("acceptee")));
          c.write(JSON.stringify({ noortrace_token: jeton }) + "\n");
        });
      for (let k = 0; k < 12; k++) expect(await essai("faux-jeton")).to.equal(false);
      expect(await essai("jeton-valide")).to.equal(true);
      const tcpRaisons = b.coeur.journal.trouver("auth_failed").map((l) => l.data.reason);
      expect(tcpRaisons).to.deep.equal([...Array(10).fill("jeton"), "jeton_limite", "jeton_limite"]);
      // Streamable HTTP : dix échecs sur une connexion keep-alive, puis refus de ce jeton et de cette connexion.
      const h = await serveurHttp(b, "jeton-valide");
      const statuts = [];
      for (let k = 0; k < 11; k++) statuts.push((await h.req(appel(1, "demo__claims.get", {}), H, { jeton: "faux-jeton" })).statut);
      expect(statuts).to.deep.equal(Array(11).fill(401));
      expect((await h.req(appel(2, "demo__claims.get", {}), H)).statut, "même connexion : refusée 60 s").to.equal(401);
      const autre = new http.Agent({ keepAlive: false });
      expect((await h.req(appel(3, "demo__claims.get", {}), H, { agent: autre })).statut, "jeton valide, autre connexion").to.equal(200);
      expect((await h.req(appel(4, "demo__claims.get", {}), H, { agent: autre, jeton: "faux-jeton" })).statut).to.equal(401);
      const raisons = b.coeur.journal.trouver("auth_failed").filter((l) => l.data.transport === "http").map((l) => l.data.reason);
      expect(raisons).to.deep.equal([...Array(10).fill("jeton_inconnu"), "jeton_limite", "jeton_limite", "jeton_limite"]);
      await h.fermer();
      await tcp.fermer();
      await b.fermer();
    });

    it("R-B-6 (4.4 pas 1, EX-4.47) : quota contrôlé avant l'analyse ; corps refusés en HTTP, lignes trop longues et temps d'analyse des refus comptés", async function () {
      const Q = { max_concurrent: 32, piece_bytes_per_minute: 268435456, received_bytes_per_minute: 2000, redaction_ms_per_minute: 30000 };
      // (a) quota d'octets atteint : une requête invalide est refusée par -31013 sans être analysée (id inconnu : null).
      const a = await banc({ hosts: [hoteDemo({ quota: Q })] });
      expect((await a.recevoir(appel(1, "demo__claims.get", { x: "a".repeat(1500) }))).result.isError).to.equal(false);
      const tronque = appel(2, "demo__claims.get", { x: "a".repeat(600) }).slice(0, -1);
      expect(await a.recevoir(tronque)).to.deep.equal({ jsonrpc: "2.0", id: null, error: { code: -31013, message: "noortrace: taille maximale depassee", data: { limit_bytes: 2000, direction: "quota" } } });
      await a.fermer();
      // (d) le temps d'analyse d'une requête refusée est compté (horloge monotone qui avance à chaque lecture).
      class HorlogeQuiAvance extends HorlogeReglable {
        monotone() {
          this.mono += 1;
          return this.mono;
        }
      }
      const d = await banc({ horloge: new HorlogeQuiAvance(ms("2026-11-10T10:20:00.000Z")) });
      for (const x of ["{", "[1]", '{"jsonrpc":"1.0","id":1,"method":"x"}']) await d.recevoir(x);
      expect(d.frontal.quotas.get("agent-demo").capture.total(d.frontal.monotone())).to.be.greaterThan(0);
      await d.fermer();
      // (b) corps refusés par le transport HTTP avant le frontal (400 -32020, 406, 400 meta_requis, 413) : comptés.
      const b = await banc({ hosts: [hoteHttp({ quota: { ...Q, received_bytes_per_minute: 1000000 } })], ajuster: httpCfg, limits: { request_max_bytes: 100000 } });
      const h = await serveurHttp(b);
      const corps = appel(1, "demo__claims.get", { x: "a".repeat(5000) });
      expect((await h.req(corps, { ...H, "mcp-method": "tools/list" })).statut).to.equal(400);
      expect((await h.req(corps, { ...H, accept: "application/json" })).statut).to.equal(406);
      expect((await h.req(ligne({ jsonrpc: "2.0", id: 2, method: "tools/list", params: { x: "a".repeat(5000) } }))).statut).to.equal(400);
      expect((await h.req("a".repeat(150000), H)).statut).to.equal(413);
      const recus = () => b.frontal.quotas.get("agent-demo").recus.total(b.frontal.monotone());
      expect(recus()).to.be.at.least(3 * 5000 + 100000);
      // Au-delà du quota, un corps invalide est refusé par -31013 avant toute analyse.
      for (let k = 0; k < 9; k++) await h.req("a".repeat(99000), H);
      const q = await h.req("{", H);
      expect([q.statut, JSON.parse(q.corps)]).to.deep.equal([200, { jsonrpc: "2.0", id: null, error: { code: -31013, message: "noortrace: taille maximale depassee", data: { limit_bytes: 1000000, direction: "quota" } } }]);
      await h.fermer();
      await b.fermer();
      // (c) lignes au-delà de line_max_bytes sur la prise des connecteurs : comptées.
      const c = await banc({ hosts: [hoteHttp({ quota: { ...Q, received_bytes_per_minute: 200000 } })], limits: { line_max_bytes: 70000 }, ajuster: httpCfg });
      const s = new ServeurConnecteurs({ frontal: c.frontal, tcp: { listen: "127.0.0.1:0", client_auth: "jeton", tls: null }, jetons: new Map([["poste", N.utf8("j")]]) });
      await s.ecouter();
      const recu = await new Promise((res) => {
        const x = net.createConnection(s.adresseTcp().port, "127.0.0.1");
        let r = "";
        let envoye = false;
        x.on("data", (z) => {
          r += z;
          if (!envoye && r.includes("acceptee")) {
            envoye = true;
            for (let k = 0; k < 5; k++) x.write("x".repeat(100000) + "\n");
            x.write(appel(9, "demo__claims.get", {}) + "\n");
            setTimeout(() => x.end(), 500);
          }
        });
        x.on("close", () => res(r));
        x.write(JSON.stringify({ noortrace_token: "j" }) + "\n");
      });
      const lignes = recu.trim().split("\n").slice(1).map((l) => JSON.parse(l));
      expect(lignes.filter((l) => l.error?.data?.direction === "requete")).to.have.length(5);
      expect(lignes.at(-1).error.data).to.deep.equal({ limit_bytes: 200000, direction: "quota" });
      expect(c.frontal.quotas.get("agent-demo").recus.total(c.frontal.monotone())).to.be.at.least(500000);
      await s.fermer();
      await c.fermer();
    });

    it("R-B-8 (EX-4.23, EX-4.36) : en HTTP moderne, la fermeture du flux avant le relais empêche le relais", async function () {
      const b = await banc({ evaluer: () => new Promise((r) => setTimeout(() => r(AUTORISE), 300)), hosts: [hoteHttp()], ajuster: httpCfg });
      const h = await serveurHttp(b);
      const r = http.request({ host: "127.0.0.1", port: h.s.adresse().port, path: "/mcp", method: "POST", headers: { authorization: "Bearer jeton-http", "content-type": "application/json", accept: "application/json, text/event-stream", ...H, "mcp-name": "demo__payments.create" } });
      r.on("error", () => {});
      r.end(appel(1, "demo__payments.create", { montant: "10.00" }));
      await pause(80);
      r.destroy();
      await pause(700);
      expect(b.ecrit.filter((l) => JSON.parse(l).method === "tools/call")).to.deep.equal([]);
      expect(await b.evenements()).to.deep.equal([]);
      await h.fermer();
      await b.fermer();
    });

    it("R-B-9 (4.4 pas 5, EX-14.3) : une tentative refusée puis annulée par l'hôte est un événement refusee", async function () {
      const REFUS = { rule: "interdit", decision: "refuse", ticket: null, ticket_state: null, approval: null, approver_set: null };
      const b = await banc({ evaluer: () => new Promise((r) => setTimeout(() => r(REFUS), 200)) });
      const p = b.recevoir(appel(2, "demo__payments.create", { montant: "99999.00" }));
      await pause(50);
      await b.recevoir(ligne({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 2 } }));
      expect(await p).to.equal(null);
      expect((await b.evenements()).map((e) => e.execution.status)).to.deep.equal(["refusee"]);
      await b.fermer();
    });

    it("R-B-10 (EX-4.34) et sessions héritées : Mcp-Session-Id ignoré en ère moderne ; sessions héritées bornées par identité", async function () {
      const b = await banc({ hosts: [hoteHttp()], ajuster: httpCfg });
      const h = await serveurHttp(b);
      expect((await h.req(appel(1, "demo__claims.get", {}), { ...H, "mcp-session-id": "abc" })).statut).to.equal(200);
      expect((await h.req(undefined, { "mcp-session-id": "abc", "mcp-protocol-version": "2026-07-28" }, { methode: "GET" })).statut).to.equal(405);
      expect((await h.req(ligne({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }), { "mcp-session-id": "abc" })).statut).to.equal(404);
      const init = ligne({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "h", version: "1" } } });
      const premiere = (await h.req(init)).entetes["mcp-session-id"];
      const avant = b.frontal.sessions.size;
      for (let k = 0; k < 100; k++) await h.req(init);
      expect(h.s.heritees.size).to.equal(64);
      expect(b.frontal.sessions.size).to.be.at.most(avant + 63);
      // La plus ancienne a été terminée : 404, l'hôte réinitialise (EX-4.37).
      expect((await h.req(ligne({ jsonrpc: "2.0", id: 3, method: "ping" }), { "mcp-session-id": premiere })).statut).to.equal(404);
      await h.fermer();
      await b.fermer();
    });

    it("R-B-11 (EX-18.1) : mcp.socket en mode 0660 dès sa création, quel que soit le masque du processus", async function () {
      for (const masque of [0o022, 0o000]) {
        const ancien = process.umask(masque);
        try {
          const b = await banc();
          const s = new ServeurConnecteurs({ frontal: b.frontal, socket: b.config.mcp.socket });
          await s.ecouter();
          expect(fs.statSync(b.config.mcp.socket).mode & 0o777, `umask ${masque.toString(8)}`).to.equal(0o660);
          await s.fermer();
          await b.fermer();
        } finally {
          process.umask(ancien);
        }
      }
    });

    it("R-B-12 (EX-9.7) : les lignes warning et error de la connexion d'hôte d'un connecteur sont copiées sur sa sortie d'erreur, et elles seules", async function () {
      const moi = os.userInfo().username;
      const b = await banc({ hosts: [hoteDemo({ match: { peer_user: moi }, launched_by: "${peer_user}" })] });
      const s = new ServeurConnecteurs({ frontal: b.frontal, socket: b.config.mcp.socket });
      await s.ecouter();
      const { PassThrough } = await import("node:stream");
      const lancer = () => {
        const x = { sortie: [], erreur: [], entree: new PassThrough() };
        x.fin = executerConnecteur({ socket: b.config.mcp.socket, entree: x.entree, sortie: { write: (y) => x.sortie.push(String(y)) }, erreur: { write: (y) => x.erreur.push(String(y)) } });
        return x;
      };
      const un = lancer();
      const deux = lancer();
      const attendre = async (f) => {
        for (let k = 0; k < 1000 && !f(); k++) await pause(10);
      };
      // Les deux connecteurs identifiés (deux host_connected), puis la réponse rendue au premier.
      await attendre(() => b.coeur.journal.trouver("host_connected").length === 2);
      un.entree.write(appel(1, "demo__claims.get", {}, { ...META, "noortrace/delegation": { run_id: "a b" } }) + "\n");
      await attendre(() => un.sortie.join("").includes('"id":1'));
      // Une ligne du même hôte écrite hors de toute requête de ce connecteur, une ligne du démon : jamais copiées.
      b.coeur.journal.consigner("warning", "frontal_mcp", "essai_hors_connexion", {}, { host: "agent-demo" });
      b.coeur.journal.consigner("error", "noyau", "essai_demon", {});
      await pause(50);
      un.entree.end();
      deux.entree.end();
      await un.fin;
      await deux.fin;
      const copiees = un.erreur.join("").trim().split("\n").map((l) => JSON.parse(l));
      expect(copiees.map((l) => [l.level, l.event, l.host])).to.deep.equal([["warning", "delegation_refused", "agent-demo"]]);
      expect(copiees[0]).to.deep.equal(b.coeur.journal.trouver("delegation_refused")[0]);
      expect(deux.erreur).to.deep.equal([]);
      expect(un.sortie.join("").trim().split("\n").map((l) => JSON.parse(l).jsonrpc)).to.deep.equal(["2.0"]);
      await s.fermer();
      await b.fermer();
    });

    it("R-B-13 (EX-4.36, EX-4.32) : un CRLF coupé entre deux lectures SSE est une seule fin de ligne ; une ligne de stderr coupée est une ligne", async function () {
      const flux = 'data: {"jsonrpc":"2.0","id":"e-000000000001",\r\ndata: "result":{"content":[],"isError":false}}\r\n\r\n';
      for (const coupe of [null, flux.indexOf("\r") + 1, flux.lastIndexOf("\r")]) {
        const recus = [];
        const l = new LecteurSse((x) => recus.push(x));
        if (coupe === null) l.pousser(flux);
        else {
          l.pousser(flux.slice(0, coupe));
          l.pousser(flux.slice(coupe));
        }
        l.finir();
        expect(recus.map((x) => JSON.parse(x).id), `coupe ${coupe}`).to.deep.equal(["e-000000000001"]);
      }
      const donnees = [];
      const fin = new LecteurSse((x) => donnees.push(x));
      fin.pousser("data: a\r");
      fin.finir();
      expect(donnees).to.deep.equal(["a"]);
      // Sortie d'erreur d'un serveur stdio : ligne coupée en deux lectures.
      const b = await banc();
      await b.recevoir(appel(1, "demo__claims.get", {}));
      const enfant = b.enfants[0];
      enfant.stderr.emit("data", Buffer.from("premiere moi"));
      enfant.stderr.emit("data", Buffer.from("tie\nseconde\n"));
      const lignes = b.coeur.journal.trouver("child_stderr").map((l) => l.data.sha256);
      expect(lignes).to.deep.equal([N.sha256Hex(N.utf8("premiere moitie")), N.sha256Hex(N.utf8("seconde"))]);
      await b.fermer();
    });

    it("subscriptions/listen (EX-4.15 ; lot SDK Python) : accusé rendu ; client réel @langchain/mcp-adapters 2.0.1 en mode « auto », en Streamable HTTP et par le connecteur stdio", async function () {
      const { MCPAdapter } = await import("@langchain/mcp-adapters");
      const essayer = async (b, serveur) => {
        const mcp = new MCPAdapter({ mcpServers: { nt: serveur }, prefixToolNameWithServerName: false });
        try {
          const outils = await mcp.listTools();
          expect(outils.map((t) => t.name)).to.include("demo__claims.get");
          expect(await outils.find((t) => t.name === "demo__claims.get").invoke({})).to.equal("ok claims.get");
        } finally {
          await mcp.close?.();
        }
        expect(b.coeur.journal.trouver("host_subscription_opened").at(-1).data).to.deep.equal({ tools_list_changed: true });
      };
      const b = await banc({ hosts: [hoteHttp()], ajuster: httpCfg });
      const h = await serveurHttp(b);
      await essayer(b, { url: `http://127.0.0.1:${h.s.adresse().port}/mcp`, mode: "auto", headers: { Authorization: "Bearer jeton-http" } });
      // Paramètres sans `notifications` : -32602, jamais le silence.
      const r = await h.req(ligne({ jsonrpc: "2.0", id: "l", method: "subscriptions/listen", params: { toolsListChanged: true, _meta: META } }), { ...H, "mcp-method": "subscriptions/listen" });
      expect(JSON.parse(r.corps).error).to.deep.equal({ code: -32602, message: "Invalid params", data: { reason: "notifications_requis" } });
      await h.fermer();
      await b.fermer();
      const c = await banc({ hosts: [hoteDemo({ match: { peer_user: os.userInfo().username } })] });
      const s = new ServeurConnecteurs({ frontal: c.frontal, socket: c.config.mcp.socket });
      await s.ecouter();
      await essayer(c, { transport: "stdio", command: process.execPath, args: [path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace-connecteur"), "--socket", c.config.mcp.socket], mode: "auto" });
      await s.fermer();
      await c.fermer();
    });

    it("soupçons : Mcp-Param-* décodé avant comparaison ; alg lié au type de clé ; JWKS borné ; continuations purgées ; journal non inondable ; id d'annulation comparé par valeur", async function () {
      // Mcp-Param-* (EX-4.35) : la sentinelle base64 est décodée, puis comparée à la valeur de l'argument.
      const outils = [{ name: "q", inputSchema: { type: "object", properties: { region: { type: "string", "x-mcp-header": "Region" } } }, annotations: { readOnlyHint: true } }];
      const b = await banc({ hosts: [hoteHttp()], ajuster: httpCfg, outils });
      const h = await serveurHttp(b);
      const Hq = { ...H, "mcp-name": "demo__q" };
      const b64 = (x) => `=?base64?${Buffer.from(x).toString("base64")}?=`;
      expect((await h.req(appel(1, "demo__q", { region: "Paris" }), { ...Hq, "mcp-param-region": b64("Paris") })).statut).to.equal(200);
      expect((await h.req(appel(2, "demo__q", { region: "Genève" }), { ...Hq, "mcp-param-region": b64("Genève") })).statut).to.equal(200);
      expect((await h.req(appel(3, "demo__q", { region: "Paris" }), { ...Hq, "mcp-param-region": b64("Lyon") })).statut).to.equal(400);
      expect((await h.req(appel(4, "demo__q", { region: "Paris" }), { ...Hq, "mcp-param-region": "Lyon" })).statut).to.equal(400);
      // Journal non inondable par l'hôte : réponses et notifications consignées au plus 20 fois par seconde, le reste compté.
      for (let k = 0; k < 100; k++) await b.recevoir(ligne({ jsonrpc: "2.0", id: k, result: {} }));
      expect(b.coeur.journal.trouver("host_response_ignored")).to.have.length(20);
      b.horloge.avancer(1000);
      await b.recevoir(ligne({ jsonrpc: "2.0", id: 1, result: {} }));
      expect(b.coeur.journal.trouver("host_lines_dropped").at(-1).data).to.deep.equal({ lines: 80 });
      await h.fermer();
      await b.fermer();
      // alg lié au type de la clé (RFC 8725 §3.1) : un RS256 présenté comme ES256 est refusé.
      const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const jwk = { ...publicKey.export({ format: "jwk" }), kid: "r1" };
      const enc = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
      const o = { jwks: { keys: [jwk] }, resource: "https://noortrace.local/mcp", issuers: ["https://as.local"], scopes: [], maintenant: Date.now() };
      const charge = enc({ aud: o.resource, iss: "https://as.local", sub: "alice", exp: Math.floor(Date.now() / 1000) + 600 });
      const signe = (alg) => {
        const e = enc({ alg, kid: "r1" });
        return `${e}.${charge}.${signer("sha256", Buffer.from(`${e}.${charge}`), privateKey).toString("base64url")}`;
      };
      expect(verifierJwt(signe("RS256"), o)).to.deep.equal({ sub: "alice" });
      expect(() => verifierJwt(signe("ES256"), o)).to.throw("signature");
      // JWKS : délai et taille bornés, une seule lecture en vol.
      let lectures = 0;
      const lent = http.createServer((req, res) => {
        lectures++;
        if (req.url === "/gros") res.end("x".repeat(2 * 1024 * 1024));
        else if (req.url === "/ok") res.end(JSON.stringify({ keys: [] }));
      });
      await new Promise((r) => lent.listen(0, "127.0.0.1", r));
      const base = `http://127.0.0.1:${lent.address().port}`;
      const { chargeurJwksHttps } = await import("@noortrace/enregistreur");
      const rejet = (p) => p.then(() => "resolu", (e) => e.message);
      expect(await rejet(chargeurJwksHttps(`${base}/muet`, { requete: http.get, delaiMs: 200 })())).to.match(/délai/);
      expect(await rejet(chargeurJwksHttps(`${base}/gros`, { requete: http.get })())).to.match(/taille/);
      lectures = 0;
      const charger = chargeurJwksHttps(`${base}/ok`, { requete: http.get });
      expect(await Promise.all([charger(), charger(), charger()])).to.deep.equal([{ keys: [] }, { keys: [] }, { keys: [] }]);
      expect(lectures).to.equal(1);
      lent.closeAllConnections();
      await new Promise((r) => lent.close(r));
      // Continuations MRTR (EX-4.21) : une continuation servie est retirée ; celles d'une session fermée aussi.
      let n = 0;
      const m = await banc({ repondre: () => (++n % 2 === 1 ? { resultType: "input_required", inputRequests: {}, requestState: `etat-${n}` } : { content: [], isError: false }) });
      await m.recevoir(appel(1, "demo__payments.create", { a: 1 }));
      expect(m.frontal.continuations.size).to.equal(1);
      await m.recevoir(appel(2, "demo__payments.create", { a: 1 }, META, { requestState: "etat-1", inputResponses: {} }));
      expect(m.frontal.continuations.size).to.equal(0);
      await m.recevoir(appel(3, "demo__payments.create", { a: 1 }));
      expect(m.frontal.continuations.size).to.equal(1);
      m.frontal.fermerSession(m.session);
      expect(m.frontal.continuations.size).to.equal(0);
      await m.fermer();
      // Annulation : requestId comparé par valeur JSON (échappements, écriture du nombre).
      const a = await banc({ repondre: () => null, reglages: { "slow.op": reglageOutil({ timeout_ms: 1000 }) } });
      const p1 = a.frontal.recevoir(a.session, appel("a-1", "demo__slow.op", {}));
      const p2 = a.frontal.recevoir(a.session, appel(7, "demo__slow.op", {}));
      await laisserTourner(20);
      await a.recevoir('{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"\\u0061-1"}}');
      await a.recevoir('{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7.0}}');
      expect([await p1, await p2]).to.deep.equal([null, null]);
      await a.fermer();
    });
  });
});
