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
import { generateKeyPairSync, sign as signer } from "node:crypto";
import * as N from "@noortrace/noyau";
import {
  Coeur, HorlogeReglable, FrontalMcp, ServeurConnecteurs, ServeurHttpMcp, ConnexionHttp, validerConfiguration, reglesHorsSchema, lireEvenements,
  ErreurEnregistreur, analyserTexte, compacter, nombreRepresentable, ErreurTexteJson, decoderUtf8Strict, objetErreur, resultatEnregistreur,
  verifierJwt, executerConnecteur, resoudreDelegation, QuotasHote, agreger,
} from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";
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
  const dir = repertoireTemporaire("noortrace-mcp-ex-");
  const servers = o.servers ?? {
    demo: serveurStdio(["/opt/mcp/demo"], { protocol: o.protocole ?? "2026-07-28", tools: o.reglages ?? {}, class_default: o.class_default ?? null, relay: o.relay ?? null }),
  };
  const { config: brute } = configurationMcp(dir, { servers, hosts: o.hosts, mode: o.mode, tools: o.tools, limits: o.limits });
  if (o.ajuster) o.ajuster(brute);
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(brute)));
  expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
  const horloge = new HorlogeReglable(ms("2026-11-10T10:20:00.000Z"));
  const service = o.service ?? new ServiceFixe(o.evaluer ?? (() => AUTORISE), o.candidats ?? []);
  const coeur = await Coeur.demarrer({ config: v.config, secrets: secretsDev(), horloge, service });
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

    it("EX-4.14 : cacheScope public sans jeton ni serveur `private` ; ttlMs du serveur moderne", async function () {
      const b = await banc();
      const l = await b.recevoir(ligne({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: META } }));
      expect([l.result.ttlMs, l.result.cacheScope]).to.deep.equal([60000, "public"]);
      await b.fermer();
    });

    it("EX-4.15, EX-4.16 : list_changed du serveur → relecture fusionnée, `charger`, notification à l'hôte qui écoute ; empreinte consignée", async function () {
      const b = await banc({ demarrer: true, tools: { list_changed_min_interval_ms: 50 } });
      b.session.ecouteListe = true;
      b.frontal.recevoir(b.session, ligne({ jsonrpc: "2.0", id: "ecoute", method: "subscriptions/listen", params: { toolsListChanged: true, _meta: META } }));
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
      expect(b.emis).to.include('{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}');
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

    it("EX-4.23 : annulation par l'hôte (stdio) relayée au serveur ; événement -31012 ; aucune réponse rendue", async function () {
      const b = await banc({ repondre: () => null });
      const p = b.frontal.recevoir(b.session, appel("a-1", "demo__slow.op", {}));
      await laisserTourner(20);
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
      await laisserTourner(30);
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
      const lignes = bon.trim().split("\n").map((x) => JSON.parse(x));
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
});
