// Revue de sécurité interne de l'étape 8 (enregistreur : frontaux,
// télémétrie, haute disponibilité) : bornes de mémoire et de temps sur les
// entrées (cause structurante S-1). Chaque `it` nomme l'exigence ou le défaut qu'il reproduit ;
// chaque essai échoue sur le code d'avant la correction et passe après.
//
//    contrôle EX-4.44 des nombres en temps linéaire
//   CT-2 EX-17.2, CT-2 EX-4.47   chaînes recopiées et bornées au journal d'exploitation, `id` JSON-RPC borné,
//                      tampon en mémoire borné en octets, quota opposé à finAppel/fermer inconnus
//              appels ouverts et sessions bornés par connexion du SDK
//               LecteurSse en temps linéaire
//   CT-2 EX-6.28, CT-2 EX-15.1   ingestion OTLP : ressource partagée, éléments comptés pendant le décodage
//              quotas OTLP comptés pendant la lecture du corps
//               limitation OTLP : un refus pendant la limitation ne compte pas contre le jeton valide
//   EX-15.4   client PostgreSQL du magasin de bail : trames hostiles, serveur non authentifié
//   S-1 (nœuds JSON)   nombre total de nœuds d'un texte JSON borné

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import http from "node:http";
import path from "node:path";
import { spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
// Import par espace de noms : les constantes nouvelles (bornes.mjs) manquent dans
// le code d'avant la correction, et chaque essai doit alors échouer par son oracle,
// non au chargement du fichier (rejeu avant et après la correction).
import * as E from "@noortrace/enregistreur";

const {
  Coeur, HorlogeReglable, FrontalMcp, FrontalSdk, JournalExploitation, validerConfiguration, lireEvenements,
  analyserTexte, membre, premierNombreNonRepresentable, nombreRepresentable, LecteurSse, ErreurTexteJson,
  IngestionOtel, ServeurOtel, champLen, ConnexionPg, analyserDsn, MagasinBailPostgresql,
} = E;
const ID_JSONRPC_MAX = E.ID_JSONRPC_MAX ?? 256;
const CHAINE_JOURNAL_MAX = E.CHAINE_JOURNAL_MAX ?? 256;
const NOEUDS_JSON_MAX = E.NOEUDS_JSON_MAX;
const SESSIONS_SDK_PAR_CONNEXION_MAX = E.SESSIONS_SDK_PAR_CONNEXION_MAX ?? 1024;
import { repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationMcp, serveurStdio, RedacteurTest, ServiceFixe, AUTORISE, EnfantFactice } from "./fixtures/enregistreur-mcp/outils.mjs";
import { demarrerDemonSdk, hoteSdk, priseBrute } from "./fixtures/enregistreur-sdk/outils.mjs";

const META = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} };
const ligne = (o) => JSON.stringify(o);
const appel = (id, nom, args, meta = META) => ligne({ jsonrpc: "2.0", id, method: "tools/call", params: { name: nom, arguments: args, _meta: meta } });
const OUTILS = [{ name: "claims.get", description: "Lire", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } }];
const chrono = () => Number(process.hrtime.bigint() / 1000000n);

/** Banc du frontal MCP (cœur réel, serveur stdio factice), repris des essais du frontal. */
async function banc(o = {}) {
  const dir = repertoireTemporaire("noortrace-revue-bornes-");
  const servers = { demo: serveurStdio(["/opt/mcp/demo"], { protocol: "2026-07-28" }) };
  const { config: brute } = configurationMcp(dir, { servers, hosts: o.hosts, limits: o.limits });
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(brute)));
  expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
  const horloge = new HorlogeReglable(N.decoderHorodatage("2026-11-10T10:20:00.000Z"));
  const service = new ServiceFixe(() => AUTORISE, []);
  const coeur = await Coeur.demarrer({ config: v.config, secrets: secretsDev(), horloge, service });
  const lanceur = () =>
    new EnfantFactice((l, enfant) => {
      const m = JSON.parse(l);
      if (m.id === undefined) return;
      let r;
      if (m.method === "server/discover") r = { result: { supportedVersions: ["2026-07-28"] } };
      else if (m.method === "tools/list") r = { result: { tools: OUTILS, ttlMs: 60000 } };
      else if (m.method === "subscriptions/listen") r = null;
      else r = { result: { content: [{ type: "text", text: "ok" }], isError: false } };
      if (r) setImmediate(() => enfant.repondre(JSON.stringify({ jsonrpc: "2.0", id: m.id, ...r })));
    });
  const frontal = new FrontalMcp({ coeur, redacteur: new RedacteurTest(), lanceur });
  frontal.chargerListe("demo", OUTILS, { ttlMs: 60000, ere: "moderne" });
  const hote = v.config.mcp.hosts[0];
  const emis = [];
  const session = frontal.ouvrirSession({ hote, identite: { peer_user: "agent-demo" }, transport: "stdio", emettre: (x) => emis.push(x) });
  const recevoir = async (texte) => {
    const r = await frontal.recevoir(session, texte);
    return r === null ? null : JSON.parse(r);
  };
  const fermer = async () => {
    await frontal.arreter();
    await coeur.arreter();
    fs.rmSync(dir, { recursive: true, force: true });
  };
  return { dir, config: v.config, coeur, frontal, session, recevoir, emis, hote, evenements: () => lireEvenements(coeur.repertoire), fermer };
}

describe("enregistreur, revue (étape 8) : bornes de mémoire et de temps sur les entrées (S-1)", function () {
  this.timeout(120000);

  describe("contrôle des nombres d'EX-4.44 en temps linéaire", function () {
    it("un littéral « 0.1, 160 000 zéros, 1 » est jugé en moins d'une seconde (quadratique : vingt secondes), et le verdict ne change pas", function () {
      const n = 160000;
      const litteral = "0.1" + "0".repeat(n) + "1";
      const texte = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"a":${litteral}}}}`;
      const noeud = analyserTexte(texte, { profondeurMax: 128, membresMax: 100000 });
      const args = membre(membre(noeud, "params"), "arguments");
      const t0 = chrono();
      const r = premierNombreNonRepresentable(texte, args);
      const duree = chrono() - t0;
      expect(r, "le littéral n'est pas exactement représentable : refusé").to.equal(litteral);
      expect(duree, `durée ${duree} ms`).to.be.below(1000);
      // Verdicts inchangés sur des littéraux ordinaires.
      for (const ok of ["0.1", "1e2", "100", "-0", "1.5", "123456789012345680000", "0.000001"]) expect(nombreRepresentable(ok), ok).to.equal(true);
      for (const ko of ["0.10000000000000001", "100.000000000000000001", "9007199254740993"]) expect(nombreRepresentable(ko), ko).to.equal(false);
      expect(nombreRepresentable("1" + "0".repeat(300))).to.equal(true);
      expect(nombreRepresentable("1" + "0".repeat(50000)), "au-delà de la double précision : refusé").to.equal(false);
    });
  });

  describe("S-1 : nombre total de nœuds d'un texte JSON", function () {
    it("un texte de deux millions de valeurs réparties dans des tableaux sous la borne par conteneur est refusé (raison noeuds) avant d'être matérialisé", function () {
      const tableau = "[" + Array(10000).fill("0").join(",") + "]";
      const texte = "[" + Array(201).fill(tableau).join(",") + "]";
      expect(NOEUDS_JSON_MAX).to.equal(1000000);
      let erreur = null;
      try {
        analyserTexte(texte, { profondeurMax: 128, membresMax: 100000 });
      } catch (e) {
        erreur = e;
      }
      expect(erreur).to.be.instanceOf(ErreurTexteJson);
      expect(erreur.raison).to.equal("noeuds");
      // Sous la borne, le même texte s'analyse.
      const petit = "[" + Array(50).fill(tableau).join(",") + "]";
      expect(analyserTexte(petit, { profondeurMax: 128, membresMax: 100000 }).elements.length).to.equal(50);
    });
  });

  describe("CT-2 EX-17.2, CT-2 EX-4.47 : journal d'exploitation, chaînes recopiées et bornées, tampon en octets", function () {
    it("request_id, host et les chaînes de data au-delà de 256 caractères sont tronqués avec leur longueur, à tout niveau ; une chaîne courte est gardée telle quelle", function () {
      const j = new JournalExploitation({ chemin: null });
      const long = "x".repeat(5000);
      j.consigner("info", "frontal_mcp", "essai", { method: long, imbrique: { liste: [long, "court"], n: 3 }, court: "abc" }, { host: "hote-a", request_id: long });
      const l = j.lignes[0];
      expect(l.request_id).to.have.length.below(CHAINE_JOURNAL_MAX + 20);
      expect(l.request_id.endsWith("…[5000]")).to.equal(true);
      expect(l.data.method.endsWith("…[5000]")).to.equal(true);
      expect(l.data.imbrique.liste[0].endsWith("…[5000]")).to.equal(true);
      expect(l.data.imbrique.liste[1]).to.equal("court");
      expect(l.data.imbrique.n).to.equal(3);
      expect(l.data.court).to.equal("abc");
      expect(l.host).to.equal("hote-a");
    });

    it("les lignes gardées en mémoire sont bornées en octets (16 Mio par défaut) et non seulement en nombre : 10 000 lignes de 10 Kio n'en retiennent pas 100 Mio", function () {
      const j = new JournalExploitation({ chemin: null, enMemoire: 10000 });
      const donnee = { liste: Array.from({ length: 50 }, (_, k) => `valeur-${k}-` + "y".repeat(180)) };
      for (let k = 0; k < 10000; k++) j.consigner("info", "sdk", "essai", donnee);
      expect(j.octetsMemoire).to.be.at.most(16 * 1048576);
      expect(j.lignes.length).to.be.below(10000);
      expect(j.lignes.length).to.be.above(100);
      // La ligne la plus récente est toujours gardée.
      expect(j.lignes.at(-1).event).to.equal("essai");
    });

    it("une ligne consignée ne retient pas le texte de la requête dont ses chaînes sont tirées (tranche V8) : 60 requêtes de 1 Mio refusées retiennent moins de 20 Mio", async function () {
      if (typeof globalThis.gc !== "function") {
        // Mesure du tas : lancée avec --expose-gc ; sans lui, la propriété se vérifie par la forme des chaînes.
        const j = new JournalExploitation({ chemin: null });
        const texte = `{"jsonrpc":"2.0","id":"${"A".repeat(1048576)}"}`;
        const noeud = analyserTexte(texte, {});
        const id = membre(noeud, "id");
        j.consigner("info", "sdk", "essai", { method: texte.slice(id.d, id.f).slice(0, 100) }, { request_id: texte.slice(id.d, id.f) });
        expect(j.lignes[0].request_id.length).to.be.below(300);
        expect(j.lignes[0].data.method.length).to.equal(100);
        return;
      }
      const j = new JournalExploitation({ chemin: null });
      globalThis.gc();
      const avant = process.memoryUsage().heapUsed;
      for (let k = 0; k < 60; k++) {
        const texte = `{"jsonrpc":"2.0","id":"${"A".repeat(1048576)}","k":${k}}`;
        const noeud = analyserTexte(texte, {});
        const id = membre(noeud, "id");
        j.consigner("info", "sdk", "essai", { method: texte.slice(id.d, id.f).slice(0, 100) }, { request_id: texte.slice(id.d, id.f) });
      }
      globalThis.gc();
      const apres = process.memoryUsage().heapUsed;
      expect(apres - avant, `retenu ${Math.round((apres - avant) / 1048576)} Mio`).to.be.below(20 * 1048576);
    });

    it("frontal MCP : un id JSON-RPC de plus de 256 caractères est refusé par -32600 (id_trop_long, id null) avant toute analyse de la méthode ; la ligne consignée ne porte pas l'id", async function () {
      const b = await banc();
      try {
        const long = "B".repeat(ID_JSONRPC_MAX + 1);
        const r = await b.recevoir(ligne({ jsonrpc: "2.0", id: long, method: "tools/call", params: { name: "demo__claims.get", arguments: {}, _meta: META } }));
        expect(r.id).to.equal(null);
        expect(r.error.code).to.equal(-32600);
        expect(r.error.data.reason).to.equal("id_trop_long");
        const l = b.coeur.journal.trouver("request_id_too_long");
        expect(l).to.have.length(1);
        // Longueur du texte de l'id, guillemets compris.
        expect(l[0].data.length).to.equal(ID_JSONRPC_MAX + 3);
        expect(JSON.stringify(b.coeur.journal.lignes)).to.not.include(long);
        // Un id de 256 caractères passe et est renvoyé tel quel.
        const juste = "C".repeat(ID_JSONRPC_MAX - 2);
        const ok = await b.recevoir(appel(juste, "demo__claims.get", {}));
        expect(ok.id).to.equal(juste);
        expect(ok.result.isError).to.equal(false);
      } finally {
        await b.fermer();
      }
    });
  });

  describe("CT-2 EX-4.47 : point d'entrée SDK, id borné, quota opposé à finAppel/fermer inconnus, appels ouverts et sessions bornés", function () {
    function frontalSdkSeul(quota) {
      const journal = new JournalExploitation({ chemin: null });
      const hote = { id: "agent-sdk", alias: "sdk-a", host_group: "g", quota, launched_by: "a", scope: "s" };
      const coeur = {
        config: { sdk: { hosts: [hote] }, limits: { json_max_depth: 128, json_max_members: 100000, line_max_bytes: 16842752, piece_max_bytes: 16777216 }, policy: {} },
        journal, metriques: { compter() {}, observer() {} }, horlogeBrute: { monotone: chrono, murale: () => Date.now() },
        bailDetenu: true, politique: { observation: false }, o: { redaction: { redigerPiece() {} } },
      };
      const f = new FrontalSdk({ coeur });
      const cx = f.ouvrirConnexion({ hote, identite: { peer_user: "agent", transport: "unix" } });
      return { f, cx, journal, hote };
    }

    it("un id de plus de 256 caractères est refusé par -32600 (id null) sans ligne qui le porte ; finAppel d'un call inconnu est soumis au quota d'octets reçus (-31013 une fois le quota atteint)", async function () {
      const { f, cx, journal } = frontalSdkSeul({ max_concurrent: 8, piece_bytes_per_minute: 268435456, received_bytes_per_minute: 1048576, redaction_ms_per_minute: 30000 });
      const long = Buffer.from(`{"jsonrpc":"2.0","id":"${"A".repeat(4096)}","method":"noortrace/sdk/finAppel","params":{"call":"c-inconnu","is_error":false,"duration_ms":1}}`);
      const r1 = JSON.parse(await f.recevoir(cx, new Uint8Array(long)));
      expect(r1.id).to.equal(null);
      expect(r1.error.code).to.equal(-32600);
      expect(r1.error.data.reason).to.equal("id_trop_long");
      expect(JSON.stringify(journal.lignes)).to.not.include("AAAAAAAAAAAAAAAA");
      // Quota d'octets reçus (1 Mio par minute) opposé à finAppel pour un call inconnu.
      const bourre = Buffer.from(`{"jsonrpc":"2.0","id":7,"method":"noortrace/sdk/finAppel","params":{"call":"c-inconnu","is_error":false,"duration_ms":1,"result":"${"r".repeat(300000)}"}}`);
      const codes = [];
      for (let k = 0; k < 6; k++) codes.push(JSON.parse(await f.recevoir(cx, new Uint8Array(bourre))).error.code);
      expect(codes.slice(0, 3)).to.deep.equal([-32602, -32602, -32602]);
      expect(codes).to.include(-31013);
    });

    it("notification_ignored et sdk_input_refused sont bornées à 20 lignes par connexion et par seconde, le reste compté (host_lines_dropped)", async function () {
      const { f, cx, journal } = frontalSdkSeul({ max_concurrent: 8, piece_bytes_per_minute: 268435456, received_bytes_per_minute: 268435456, redaction_ms_per_minute: 30000 });
      const notif = new Uint8Array(Buffer.from('{"jsonrpc":"2.0","method":"noortrace/sdk/x"}'));
      for (let k = 0; k < 100; k++) await f.recevoir(cx, notif);
      expect(journal.trouver("notification_ignored")).to.have.length(20);
      await new Promise((r) => setTimeout(r, 1050));
      await f.recevoir(cx, notif);
      const d = journal.trouver("host_lines_dropped");
      expect(d).to.have.length(1);
      expect(d[0].data.lines).to.equal(80);
    });

    it("CT-2 EX-4.47 : au-delà de quota.max_concurrent appels ouverts (debutAppel sans finAppel), debutAppel rend -31013 limit_requests ; un finAppel rend la place", async function () {
      const d = await demarrerDemonSdk({ hotes: [hoteSdk({ quota: { max_concurrent: 2 } })], decider: () => ({ decision: "autorise" }) });
      try {
        const p = await priseBrute(d.config.sdk.socket);
        const o = await p.appel("ouvrir", { run_id: null, on_behalf_of: null });
        const s = o.result.session;
        const a1 = await p.appel("debutAppel", { session: s, tool: "lire", arguments: { k: 1 }, class: "lecture" }, 2);
        const a2 = await p.appel("debutAppel", { session: s, tool: "lire", arguments: { k: 2 }, class: "lecture" }, 3);
        expect(a1.result.call).to.be.a("string");
        expect(a2.result.call).to.be.a("string");
        const a3 = await p.appel("debutAppel", { session: s, tool: "lire", arguments: { k: 3 }, class: "lecture" }, 4);
        expect(a3.error.code).to.equal(-31013);
        expect(a3.error.data.limit_requests).to.equal(2);
        expect(d.lignes("call_blocked").some((l) => l.data.open_calls === 2)).to.equal(true);
        const fin = await p.appel("finAppel", { call: a1.result.call, result: null, is_error: false, duration_ms: 1 }, 5);
        expect(fin.result).to.be.an("object");
        const a4 = await p.appel("debutAppel", { session: s, tool: "lire", arguments: { k: 4 }, class: "lecture" }, 6);
        expect(a4.result.call).to.be.a("string");
        p.fermer();
      } finally {
        await d.arreter();
      }
    });

    it("CT-2 EX-4.47 : les sessions ouvertes par une connexion sont bornées (SESSIONS_SDK_PAR_CONNEXION_MAX), au-delà -31013", async function () {
      const { f, cx } = frontalSdkSeul({ max_concurrent: 8, piece_bytes_per_minute: 268435456, received_bytes_per_minute: 268435456, redaction_ms_per_minute: 30000 });
      // Connexion dont la table des sessions est pleine : la borne s'applique avant toute ouverture.
      for (let k = 0; k < SESSIONS_SDK_PAR_CONNEXION_MAX; k++) cx.sessions.set(`s-${k}`, { id: `s-${k}`, close: false, appels: new Map() });
      f.coeur.org_id = "0x" + "0".repeat(64);
      f.coeur.journal_id = "0x" + "1".repeat(64);
      f.coeur.versionPolitique = "v";
      const r = JSON.parse(await f.recevoir(cx, new Uint8Array(Buffer.from('{"jsonrpc":"2.0","id":1,"method":"noortrace/sdk/ouvrir","params":{"run_id":null,"on_behalf_of":null}}'))));
      expect(r.error.code).to.equal(-31013);
      expect(r.error.data.limit_sessions).to.equal(SESSIONS_SDK_PAR_CONNEXION_MAX);
    });
  });

  describe("LecteurSse en temps linéaire", function () {
    it("16 Mio sans fin de ligne en morceaux de 16 Kio sont lus en moins de deux secondes (quadratique : plus de dix) ; les lignes et un CRLF coupé entre deux morceaux restent lus", function () {
      const l = new LecteurSse(() => {});
      const morceau = "a".repeat(16384);
      const t0 = chrono();
      for (let k = 0; k < (16 * 1048576) / 16384; k++) l.pousser(morceau);
      const duree = chrono() - t0;
      expect(duree, `${duree} ms`).to.be.below(2000);
      const recu = [];
      const m = new LecteurSse((d) => recu.push(d));
      m.pousser("data: un\r");
      m.pousser("\ndata: deux\n\nevent: x\ndata: tr");
      m.pousser("ois\n\n: commentaire\ndata: quatre");
      m.finir();
      expect(recu).to.deep.equal(["un\ndeux", "trois", "quatre"]);
    });
  });

  describe("ingestion OpenTelemetry : CT-2 EX-6.28, CT-2 EX-15.1", function () {
    const jeton = "j".repeat(32);
    function configOtel(o = {}) {
      return {
        limits: { json_max_depth: 128, json_max_members: 100000, piece_max_bytes: 16777216 },
        model: { prompt_in_request: "inline", prompt_system: "hash" },
        policy: { otel: { sources: { src: { ingest: ["inference", "outil"], overlap: "ignorer", class_default: null, tools: {} } } } },
        otel: {
          listen: "127.0.0.1:0", tls: null, path: "/v1/traces", encodings: ["protobuf", "json"], max_body_bytes: 67108864, dedup_window_ms: 3600000, overlap_window_ms: 600000, retry_after_s: 5,
          ...(o.spans_per_request ? { spans_per_request: o.spans_per_request } : {}),
          hosts: [{ id: "h", alias: "src", host_group: "g", match: { static_token: "t" }, quota: { max_concurrent: o.max_concurrent ?? 8, piece_bytes_per_minute: 268435456, received_bytes_per_minute: o.received ?? 268435456, redaction_ms_per_minute: 30000 } }],
        },
      };
    }
    function ingestion(config, o = {}) {
      const journal = new JournalExploitation({ chemin: null });
      let t = 0;
      const ing = new IngestionOtel({
        config: () => config, journal, metriques: { compter() {}, observer() {} }, redacteur: null, jetons: new Map([["t", new Uint8Array(Buffer.from(jeton))]]),
        monotone: o.monotone ?? (() => chrono()), ecrirePiece: async () => ({}), sceller: async () => ({ seq: 1, ts: "2026-11-10T10:00:00.000Z" }), panne: () => null,
        version: () => ({ policy_version: "v", recorder: "r", nomRedaction: null }),
      });
      return { ing, journal, avance: (ms) => (t += ms), t: () => t };
    }
    const lon = (n) => { const o = []; let x = n; do { let b = x & 0x7f; x = Math.floor(x / 128); if (x) b |= 0x80; o.push(b); } while (x); return Buffer.from(o); };
    const len = (num, b) => Buffer.concat([Buffer.from([(num << 3) | 2]), lon(b.length), b]);
    const prejuger = (ing, type, connexion = 1, j = jeton) => ing.prejuger({ methode: "POST", cible: "/v1/traces", entetes: { "content-type": type, "x-noortrace-token": j }, connexion });

    it("CT-2 EX-6.28 : une ressource de 1 Mio et 200 spans vides (corps de 1 Mio) n'occupent pas 200 fois la ressource : le tas croît de moins de 48 Mio (avant : 212 Mio), statut 200", async function () {
      const { ing } = ingestion(configOtel({ spans_per_request: 10000 }));
      const chaine = Buffer.alloc(1048576, 0x61);
      const anyValue = len(1, chaine);
      const kv = Buffer.concat([len(1, Buffer.from("k")), len(2, anyValue)]);
      const resource = len(1, kv);
      const nSpans = 200;
      const spans = Buffer.alloc(nSpans * 2);
      for (let i = 0; i < nSpans; i++) { spans[2 * i] = (2 << 3) | 2; spans[2 * i + 1] = 0; }
      const corps = len(1, Buffer.concat([len(1, resource), len(2, spans)]));
      const pre = await prejuger(ing, "application/x-protobuf");
      expect(pre.suite, JSON.stringify(pre.refus)).to.be.an("object");
      globalThis.gc?.();
      const avant = process.memoryUsage().heapUsed;
      const issue = await ing.traiter(pre.suite, new Uint8Array(corps), corps.length);
      const pendant = process.memoryUsage().heapUsed - avant;
      expect(issue.statut).to.equal(200);
      expect(issue.etat.spans).to.equal(nSpans);
      expect(pendant, `tas +${Math.round(pendant / 1048576)} Mio`).to.be.below(48 * 1048576);
      expect(champLen).to.be.a("function");
    });

    it("CT-2 EX-15.1, CT-2 EX-6.28 : 4 Mio de resource_spans vides en protobuf (deux millions d'éléments) sont refusés par 413 elements_par_requete pendant le décodage, sans matérialiser la suite ; même budget en JSON", async function () {
      const { ing } = ingestion(configOtel());
      const corps = Buffer.alloc(4 * 1048576);
      for (let i = 0; i < corps.length; i += 2) { corps[i] = (1 << 3) | 2; corps[i + 1] = 0; }
      const pre = await prejuger(ing, "application/x-protobuf");
      globalThis.gc?.();
      const avant = process.memoryUsage().heapUsed;
      const t0 = chrono();
      const issue = await ing.traiter(pre.suite, new Uint8Array(corps), corps.length);
      const duree = chrono() - t0;
      const pendant = process.memoryUsage().heapUsed - avant;
      expect(issue.statut).to.equal(413);
      expect(issue.raison).to.equal("elements_par_requete");
      expect(duree, `${duree} ms`).to.be.below(5000);
      // Avant : 414 Mio de tas pour 4 Mio reçus ; après : le décodage s'arrête au budget.
      expect(pendant, `tas +${Math.round(pendant / 1048576)} Mio`).to.be.below(160 * 1048576);
      // 150 × 100 × 100 spans vides : chaque conteneur sous json_max_members, 1,5 million de nœuds en tout.
      const scope = `{"spans":[${Array(100).fill("{}").join(",")}]}`;
      const rs = `{"scopeSpans":[${Array(100).fill(scope).join(",")}]}`;
      const json = Buffer.from(`{"resourceSpans":[${Array(150).fill(rs).join(",")}]}`);
      const pre2 = await prejuger(ing, "application/json", 2);
      const issue2 = await ing.traiter(pre2.suite, new Uint8Array(json), json.length);
      expect(issue2.statut).to.equal(413);
      expect(issue2.raison).to.equal("elements_par_requete");
      // Sous le budget, un lot ordinaire passe.
      const petit = Buffer.from(`{"resourceSpans":[{"scopeSpans":[{"spans":[${Array(100).fill("{}").join(",")}]}]}]}`);
      const pre3 = await prejuger(ing, "application/json", 3);
      const issue3 = await ing.traiter(pre3.suite, new Uint8Array(petit), petit.length);
      expect(issue3.statut).to.equal(200);
      expect(issue3.etat.spans).to.equal(100);
    });

    it("CT-2 EX-6.28 : un texte d'entier de plus de vingt chiffres (startTimeUnixNano) est refusé sans conversion BigInt du texte entier", async function () {
      const { ing } = ingestion(configOtel());
      const corps = Buffer.from(`{"resourceSpans":[{"scopeSpans":[{"spans":[{"startTimeUnixNano":"${"9".repeat(8000000)}"}]}]}]}`);
      const pre = await prejuger(ing, "application/json");
      const t0 = chrono();
      const issue = await ing.traiter(pre.suite, new Uint8Array(corps), corps.length);
      const duree = chrono() - t0;
      expect(issue.statut).to.equal(400);
      expect(issue.detail).to.equal("fixed64:startTimeUnixNano");
      // Avant : `BigInt` du texte entier (environ 1 s par 4 millions de chiffres) ; après : refus sur la longueur.
      expect(duree, `${duree} ms`).to.be.below(400);
    });

    it("CT-2 EX-6.28 : une requête admise compte parmi celles en cours dès prejuger, et ses octets au quota pendant la lecture : avec max_concurrent 1, une seconde requête simultanée reçoit 429 ; avec max_concurrent 2, les octets d'un corps encore ouvert comptent déjà contre la requête suivante", async function () {
      const config = configOtel({ max_concurrent: 1, received: 1048576 });
      const { ing } = ingestion(config);
      const journal = { consigner() {} };
      const srv = new ServeurOtel({ ingestion: ing, config: () => config, journal });
      await srv.ecouter();
      const port = srv.adresse().port;
      const ouvrir = (taille) => {
        const r = http.request({ host: "127.0.0.1", port, path: "/v1/traces", method: "POST", headers: { "content-type": "application/json", "x-noortrace-token": jeton, "content-length": String(taille) } });
        const statut = new Promise((res) => {
          r.on("response", (x) => { x.resume(); res(x.statusCode); });
          r.on("error", () => res(null));
        });
        return { r, statut };
      };
      try {
        const a = ouvrir(2 * 1048576 + 2);
        a.r.write(Buffer.alloc(512 * 1024, 0x20));
        await new Promise((x) => setTimeout(x, 150));
        const b = ouvrir(64);
        b.r.write(Buffer.alloc(32, 0x20));
        const sb = await Promise.race([b.statut, new Promise((x) => setTimeout(() => x("silence"), 2000))]);
        expect(sb, "seconde requête de la source pendant la première : 429").to.equal(429);
        a.r.destroy();
        b.r.destroy();
      } finally {
        await srv.fermer();
      }
      // Octets comptés pendant la lecture : un corps ouvert de 1,2 Mio épuise le quota d'octets (1 Mio) pour la requête suivante.
      const config2 = configOtel({ max_concurrent: 2, received: 1048576 });
      const { ing: ing2 } = ingestion(config2);
      const srv2 = new ServeurOtel({ ingestion: ing2, config: () => config2, journal });
      await srv2.ecouter();
      const port2 = srv2.adresse().port;
      const ouvrir2 = (taille) => {
        const r = http.request({ host: "127.0.0.1", port: port2, path: "/v1/traces", method: "POST", headers: { "content-type": "application/json", "x-noortrace-token": jeton, "content-length": String(taille) } });
        const statut = new Promise((res) => {
          r.on("response", (x) => { x.resume(); res(x.statusCode); });
          r.on("error", () => res(null));
        });
        return { r, statut };
      };
      try {
        const a = ouvrir2(4 * 1048576);
        a.r.write(Buffer.alloc(1228800, 0x20));
        await new Promise((x) => setTimeout(x, 200));
        const b = ouvrir2(2);
        b.r.end("{}");
        const sb = await Promise.race([b.statut, new Promise((x) => setTimeout(() => x("silence"), 2000))]);
        expect(sb, "quota d'octets atteint par un corps encore en lecture : 429").to.equal(429);
        a.r.destroy();
      } finally {
        await srv2.fermer();
      }
    });

    it("dix échecs d'un tiers sur une connexion partagée bloquent la connexion ; les requêtes du jeton valide qui la suivent ne comptent pas d'échec contre ce jeton, admis sur une connexion neuve", async function () {
      let t = 0;
      const { ing } = ingestion(configOtel(), { monotone: () => t });
      const statut = async (j, connexion) => { const r = await prejuger(ing, "application/json", connexion, j); if (r.suite) ing.liberer(r.suite); return r.refus ? r.refus.statut : 200; };
      expect(await statut(jeton, 2)).to.equal(200);
      for (let i = 0; i < 10; i++) { t += 100; await statut(`faux-${i}`, 1); }
      const sur1 = [];
      for (let i = 0; i < 10; i++) { t += 100; sur1.push(await statut(jeton, 1)); }
      expect(sur1.every((s) => s === 401), "connexion 1 bloquée par les échecs du tiers").to.equal(true);
      t += 100;
      expect(await statut(jeton, 2), "jeton valide sur une connexion neuve : jamais refusé à cause des échecs d'un autre (EX-18.3)").to.equal(200);
    });
  });

  describe("CT-2 EX-15.4 : client PostgreSQL du magasin de bail", function () {
    const msg = (type, corps) => { const b = Buffer.alloc(5 + corps.length); b.write(type, 0, "latin1"); b.writeInt32BE(4 + corps.length, 1); corps.copy(b, 5); return b; };
    const i32 = (n) => { const b = Buffer.alloc(4); b.writeInt32BE(n); return b; };
    const i16 = (n) => { const b = Buffer.alloc(2); b.writeInt16BE(n); return b; };
    const authOk = msg("R", i32(0));
    const pret = msg("Z", Buffer.from("I"));
    const serveur = (surConnexion) => new Promise((res) => { const s = net.createServer(surConnexion); s.listen(0, "127.0.0.1", () => res(s)); });

    it("une ErrorResponse sans octet nul final et une longueur de message négative ne figent pas le fil : ouvrir() rejette en moins de trois secondes (essai dans un processus enfant, tué à dix secondes)", function () {
      const script = `
import net from "node:net";
import { ConnexionPg, analyserDsn } from "@noortrace/enregistreur";
const msg = (type, corps) => { const b = Buffer.alloc(5 + corps.length); b.write(type, 0, "latin1"); b.writeInt32BE(4 + corps.length, 1); corps.copy(b, 5); return b; };
const i32 = (n) => { const b = Buffer.alloc(4); b.writeInt32BE(n); return b; };
const cas = process.argv[1];
const s = net.createServer((c) => c.once("data", () => {
  if (cas === "erreur") c.write(msg("E", Buffer.from("Mabc")));
  else c.write(Buffer.concat([msg("R", i32(0)), Buffer.from("N"), i32(-1)]));
}));
await new Promise((r) => s.listen(0, "127.0.0.1", r));
const cx = new ConnexionPg(analyserDsn("postgresql://u@127.0.0.1:" + s.address().port + "/b"), { delaiMs: 1500 });
const t0 = Date.now();
try { await cx.ouvrir(); console.log(JSON.stringify({ cas, issue: "ouverte", ms: Date.now() - t0 })); }
catch (e) { console.log(JSON.stringify({ cas, issue: "erreur", message: e.message, ms: Date.now() - t0 })); }
s.close(); process.exit(0);`;
      for (const cas of ["erreur", "longueur"]) {
        const r = spawnSync(process.execPath, ["--input-type=module", "-e", script, cas], { cwd: path.dirname(new URL(import.meta.url).pathname), encoding: "utf8", timeout: 10000 });
        expect(r.signal, `cas ${cas} : processus tué (fil figé) ; sortie : ${r.stdout} ${r.stderr}`).to.equal(null);
        const sortie = JSON.parse(r.stdout.trim().split("\n").at(-1));
        expect(sortie.issue).to.equal("erreur");
        expect(sortie.ms).to.be.below(3000);
      }
    });

    it("un serveur qui demande 2 147 483 647 itérations SCRAM est refusé ; une connexion acceptée puis muette (SSLRequest sans réponse) fait rejeter ouvrir() au délai", async function () {
      const s = await serveur((c) => {
        let etape = 0;
        c.on("data", (d) => {
          if (etape === 0) { etape = 1; c.write(msg("R", Buffer.concat([i32(10), Buffer.from("SCRAM-SHA-256\0\0")]))); return; }
          if (etape === 1) {
            etape = 2;
            const nonce = /r=([^,]+)/.exec(d.subarray(5).toString("utf8"))[1];
            c.write(msg("R", Buffer.concat([i32(11), Buffer.from(`r=${nonce}serveur,s=${Buffer.from("sel-du-serveur").toString("base64")},i=2147483647`)])));
          }
        });
      });
      try {
        const cx = new ConnexionPg(analyserDsn(`postgresql://u:p@127.0.0.1:${s.address().port}/b`), { delaiMs: 2000 });
        let erreur = null;
        try { await cx.ouvrir(); } catch (e) { erreur = e; }
        expect(erreur?.message).to.match(/itérations refusé/);
        cx.detruire();
      } finally {
        s.close();
      }
      const muet = await serveur(() => {});
      try {
        const cx = new ConnexionPg(analyserDsn(`postgresql://u:p@127.0.0.1:${muet.address().port}/b?sslmode=verify-full`), { delaiMs: 800 });
        const t0 = Date.now();
        let erreur = null;
        try { await cx.ouvrir(); } catch (e) { erreur = e; }
        expect(erreur, "ouvrir() rejette").to.be.an("error");
        expect(Date.now() - t0).to.be.below(3000);
      } finally {
        muet.close();
      }
    });

    it("CT-2 EX-15.4 : avec un mot de passe dans le DSN, le mot de passe en clair et MD5 sont refusés hors d'un canal TLS vérifié, et AuthenticationOk sans SCRAM achevé est refusé : un faux serveur n'obtient ni le mot de passe ni le bail", async function () {
      let recu = null;
      const clair = await serveur((c) => {
        let n = 0;
        c.on("data", (d) => {
          n++;
          if (n === 1) c.write(msg("R", i32(3)));
          else { recu = d.subarray(5, d.length - 1).toString("utf8"); c.write(Buffer.concat([authOk, pret])); }
        });
      });
      try {
        const cx = new ConnexionPg(analyserDsn(`postgresql://noortrace:MOT-DE-PASSE-DU-BAIL@127.0.0.1:${clair.address().port}/bail`), { delaiMs: 2000 });
        let erreur = null;
        try { await cx.ouvrir(); } catch (e) { erreur = e; }
        expect(erreur?.message).to.match(/en clair refusée/);
        expect(recu, "le mot de passe n'est pas parti").to.equal(null);
        cx.detruire();
      } finally {
        clair.close();
      }
      const sansAuth = await serveur((c) => {
        let demarre = false;
        c.on("data", (d) => {
          if (!demarre) { demarre = true; c.write(Buffer.concat([authOk, pret])); return; }
          const texte = d.toString("latin1");
          const l = msg("D", Buffer.concat([i16(1), i32(3), Buffer.from("999")]));
          const fin = texte.includes("RETURNING epoch") ? Buffer.concat([l, msg("C", Buffer.from("UPDATE 1\0"))]) : msg("C", Buffer.from("UPDATE 1\0"));
          c.write(Buffer.concat([msg("1", Buffer.alloc(0)), msg("2", Buffer.alloc(0)), fin, pret]));
        });
      });
      try {
        const m = new MagasinBailPostgresql({ instance: "instance-b", org_id: "0xorg", journal_id: "0xjournal", ttl_ms: 10000, renew_ms: 3000, acquire_wait_ms: 1500, dsn: `postgresql://noortrace:MOT-DE-PASSE-DU-BAIL@127.0.0.1:${sansAuth.address().port}/bail`, table: "noortrace_lease" });
        let epoque = null;
        let erreur = null;
        try { epoque = await m.acquerir(); } catch (e) { erreur = e; }
        expect(epoque, "aucun bail accordé par un pair non authentifié").to.equal(null);
        expect(erreur).to.be.an("error");
        try { m.perdre?.(); m._fermer?.(); } catch { /* déjà fermé */ }
      } finally {
        sansAuth.close();
      }
      // Sans mot de passe (mode trust), AuthenticationOk reste admis hors production : le DSN ne porte aucun secret.
      const trust = await serveur((c) => c.once("data", () => c.write(Buffer.concat([authOk, pret]))));
      try {
        const cx = new ConnexionPg(analyserDsn(`postgresql://u@127.0.0.1:${trust.address().port}/b`), { delaiMs: 2000 });
        await cx.ouvrir();
        cx.detruire();
      } finally {
        trust.close();
      }
    });
  });
});
