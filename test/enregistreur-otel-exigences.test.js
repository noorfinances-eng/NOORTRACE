// Exigences de l'ingestion OpenTelemetry (CT-2 §6.8, EX-6.23 à EX-6.41,
// EX-15.4 pas 3 pour `otel`), en réussite et en échec, et entrées hostiles :
// lots OTLP envoyés en HTTP au point d'entrée réel d'un démon en processus
// (cœur, rédacteur pii-v1, écrivain unique), JSON et protobuf. Écrit d'après
// le seul texte de CT-2.

import { expect } from "chai";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import { spawnSync } from "node:child_process";
import path from "node:path";
import zlib from "node:zlib";
import {
  controleOtel, validerConfiguration, pieceDeclarationSource, TableDoublons, decoderProtobuf, decoderJson, ErreurDecodage, analyserJsonIntegral,
} from "@noortrace/enregistreur";
import { ClientNoortrace } from "noortrace-sdk";
import { configurationDev, configurationExemple, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { demarrerDemonOtel, lot, span, spanOutil, spanInference, encoderProtobuf, identifiants } from "./fixtures/enregistreur-otel/outils.mjs";

async function avec(o, f) {
  const d = await demarrerDemonOtel(o);
  try {
    return await f(d);
  } finally {
    await d.arreter();
  }
}

const BORNES = { profondeurMax: 128, membresMax: 100000 };
const lirePiece = async (d, sha) => Buffer.from(await d.coeur.pieces.lire(sha)).toString("utf8");

describe("enregistreur, ingestion OpenTelemetry : exigences (§6.8)", function () {
  this.timeout(60000);

  describe("EX-6.23 : sources annoncées dans la chaîne", function () {
    it("policy.otel est dans l'ensemble de politique annoncé ; la pièce de déclaration de source ne dépend que de l'alias et ouvre le context", async function () {
      await avec({}, async (d) => {
        const r = await d.envoyer({ corps: lot([spanOutil("dossier.lire")]) });
        expect(r.statut).to.equal(200);
        const evts = await d.evenements();
        const pol = JSON.parse(await lirePiece(d, evts[0].execution.arguments.value.policy_sha256));
        expect(pol.otel.sources["otel-sinistres"].ingest).to.deep.equal(["inference", "outil"]);
        const e = evts.at(-1);
        const source = pieceDeclarationSource("otel", "otel-sinistres");
        expect(source.octets.length).to.equal(66);
        expect(e.context[0]).to.deep.equal(source.referenceContexte("autre"));
        expect(e.policy).to.deep.equal({ rule: null, decision: "autorise", ticket: null, redaction: null });
        expect(e.execution.tool).to.equal("otel-sinistres__dossier.lire");
      });
    });
  });

  describe("EX-6.25 : versions épinglées", function () {
    it("policy.otel.semconv est la constante 1.41.1 ; un span qui emploie d'autres noms est ignoré (hors_genai), jamais un événement invalide", async function () {
      const c = configurationExemple();
      c.policy.otel.semconv = "1.42.0";
      expect(validerConfiguration(new TextEncoder().encode(JSON.stringify(c))).pas).to.equal(2);
      await avec({}, async (d) => {
        const avant = (await d.evenements()).length;
        const r = await d.envoyer({ corps: lot([span({ attributs: { "gen_ai.operation": "chat" } })]) });
        expect(r.statut).to.equal(200);
        expect((await d.evenements()).length).to.equal(avant);
        expect(d.coeur.metriques.valeur("noortrace_otel_spans_total", { source: "otel-sinistres", issue: "ignore", reason: "hors_genai" })).to.equal(1);
      });
    });
  });

  describe("EX-6.26, EX-6.27 : point d'entrée, types de contenu, réponses, ordre des décisions", function () {
    it("POST sur le chemin exact ; 404 pour /v1/metrics et /v1/logs ; 405 avec Allow ; chaîne de requête ignorée et notée, jamais sa valeur ; 415 pour gRPC", async function () {
      await avec({}, async (d) => {
        expect((await d.envoyer({ chemin: "/v1/metrics" })).statut).to.equal(404);
        expect((await d.envoyer({ chemin: "/v1/logs" })).statut).to.equal(404);
        const r = await d.envoyer({ methode: "PUT" });
        expect(r.statut).to.equal(405);
        expect(r.entetes.allow).to.equal("POST");
        expect(r.json).to.deep.equal({ message: "noortrace: methode non admise" });
        const q = await d.envoyer({ chemin: "/v1/traces?secret=valeur-cachee", corps: lot([]) });
        expect(q.statut).to.equal(200);
        const l = d.lignes("otel_request").at(-1);
        expect(l.data.query_string).to.equal(true);
        expect(JSON.stringify(d.coeur.journal.lignes)).to.not.contain("valeur-cachee");
        expect((await d.envoyer({ type: "application/grpc" })).statut).to.equal(415);
      });
    });

    it("réponse au type de contenu de la requête : {} ou corps protobuf vide ; refus en JSON ou en Status protobuf ; ordre (c) jeton avant (f) type", async function () {
      await avec({}, async (d) => {
        const ok = await d.envoyer({ type: "application/x-protobuf", corps: encoderProtobuf(lot([])) });
        expect(ok.statut).to.equal(200);
        expect(ok.entetes["content-type"]).to.equal("application/x-protobuf");
        expect(ok.corps.length).to.equal(0);
        const non = await d.envoyer({ type: "application/x-protobuf", corps: Buffer.from([0x08]) });
        expect(non.statut).to.equal(400);
        expect(non.corps.toString("hex")).to.equal("12" + Buffer.from("noortrace: corps OTLP non decodable").length.toString(16) + Buffer.from("noortrace: corps OTLP non decodable").toString("hex"));
        const r = await d.envoyer({ jeton: null, type: "text/plain" });
        expect(r.statut).to.equal(401);
        expect(r.entetes["content-type"]).to.equal("application/json");
        expect(d.lignes("auth_failed").length).to.be.greaterThan(0);
      });
    });
  });

  describe("EX-6.28 : compression, bornes, quotas", function () {
    it("gzip accepté ; autre codage 415 ; bombe gzip arrêtée à la borne (413) ; corps reçu au-delà (413)", async function () {
      await avec({ modifier: (c) => (c.otel.max_body_bytes = 4096) }, async (d) => {
        const g = await d.envoyer({ codage: "gzip", corps: zlib.gzipSync(Buffer.from(JSON.stringify(lot([spanOutil("a.b")])))) });
        expect(g.statut).to.equal(200);
        expect((await d.envoyer({ codage: "br", corps: "{}" })).statut).to.equal(415);
        // Bombe : moins de 4 096 octets reçus, 3 Mio une fois décomprimés.
        const bombe = zlib.gzipSync(Buffer.alloc(3 * 1024 * 1024, 0x20), { level: 9 });
        expect(bombe.length).to.be.lessThan(4096);
        const b = await d.envoyer({ codage: "gzip", corps: bombe });
        expect(b.statut).to.equal(413);
        expect(d.lignes("otel_refused").at(-1).data.reason).to.equal("taille_decomprimee");
        expect((await d.envoyer({ corps: Buffer.alloc(5000, 0x20) })).statut).to.equal(413);
        expect((await d.envoyer({ codage: "gzip", corps: Buffer.from("pas du gzip") })).statut).to.equal(400);
      });
    });

    it("spans_per_request : 413 sans rien sceller ; events_per_minute : 429 avec Retry-After, spans déjà scellés gardés, le lot renvoyé donne des doublons", async function () {
      await avec({ modifier: (c) => Object.assign(c.otel, { spans_per_request: 3, events_per_minute: 2 }) }, async (d) => {
        const avant = (await d.evenements()).length;
        const trop = await d.envoyer({ corps: lot([spanOutil("a"), spanOutil("b"), spanOutil("c"), spanOutil("d")]) });
        expect(trop.statut).to.equal(413);
        expect((await d.evenements()).length).to.equal(avant);
        const l = lot([spanOutil("a"), spanOutil("b"), spanOutil("c")]);
        const r = await d.envoyer({ corps: l });
        expect(r.statut).to.equal(429);
        expect(r.entetes["retry-after"]).to.equal("5");
        expect((await d.evenements()).length).to.equal(avant + 2);
        const r2 = await d.envoyer({ corps: l });
        expect(r2.statut).to.equal(429);
        expect(d.lignes("otel_request").at(-1).data.issues.doublon).to.equal(2);
        expect(d.lignes("otel_refused").map((x) => x.data.reason)).to.include("evenements_par_minute");
      });
    });

    it("quotas de l'entrée (EX-4.47) : octets reçus et requêtes en cours, 429 ; min_free_bytes : 503 volume_ingestion", async function () {
      await avec({ modifier: (c) => (c.otel.hosts[0].quota.received_bytes_per_minute = 2048) }, async (d) => {
        expect((await d.envoyer({ corps: lot([spanOutil("a", { attributs: { "x.remplissage": "y".repeat(2100) } })]) })).statut).to.equal(200);
        const r = await d.envoyer({ corps: lot([]) });
        expect(r.statut).to.equal(429);
        expect(r.json).to.deep.equal({ message: "noortrace: quota de la source atteint" });
      });
      await avec({ modifier: (c) => (c.otel.min_free_bytes = 1024 ** 5) }, async (d) => {
        const r = await d.envoyer({ corps: lot([]) });
        expect(r.statut).to.equal(503);
        expect(r.entetes["retry-after"]).to.equal("5");
        expect(d.lignes("otel_refused").at(-1).data.reason).to.equal("volume_ingestion");
      });
    });

    it("profondeur et membres des arrayValue et kvlistValue bornés dans les deux encodages : 400", async function () {
      let v = { stringValue: "x" };
      for (let k = 0; k < 10; k++) v = { arrayValue: { values: [v] } };
      const l = lot([span({})]);
      l.resourceSpans[0].scopeSpans[0].spans[0].attributes.push({ key: "profond", value: v });
      expect(() => decoderJson(Buffer.from(JSON.stringify(l)), { profondeurMax: 8, membresMax: 100 })).to.throw(ErreurDecodage);
      expect(() => decoderProtobuf(encoderProtobuf(l), { profondeurMax: 8, membresMax: 100 })).to.throw(ErreurDecodage);
      expect(() => decoderProtobuf(encoderProtobuf(l), BORNES)).to.not.throw();
      const m = lot([span({ attributs: Object.fromEntries(Array.from({ length: 20 }, (_, k) => [`a${k}`, "v"])) })]);
      expect(() => decoderProtobuf(encoderProtobuf(m), { profondeurMax: 8, membresMax: 10 })).to.throw(ErreurDecodage);
      await avec({ modifier: (c) => (c.limits.json_max_depth = 8) }, async (d) => {
        expect((await d.envoyer({ corps: l })).statut).to.equal(400);
        expect((await d.envoyer({ type: "application/x-protobuf", corps: encoderProtobuf(l) })).statut).to.equal(400);
      });
    });

    it("priorité : un événement de span n'est remis à l'écrivain que si aucun événement d'un autre frontal n'attend", async function () {
      await avec({}, async (d) => {
        const c = d.coeur;
        const { pieceJson, partielEchange } = await import("@noortrace/enregistreur");
        const p = pieceJson({ q: 1 });
        await c.ecrirePiece(p);
        const delegation = { launched_by: "x", on_behalf_of: null, scope: "s", run_id: null };
        const echange = () => c.scellerEchange({ delegation, code: { model: null, prompt_version: null }, intent: null, requete: p.reference, reponse: p.reference, duration_ms: 0, is_error: false, context: [] });
        const partiel = partielEchange({ delegation, code: { model: null, prompt_version: null, policy_version: c.versionPolitique, recorder: "0.1.0" }, intent: null, requete: p.reference, reponse: p.reference, duration_ms: 0, is_error: false, context: [], nomRedaction: null });
        const a1 = echange();
        const a2 = echange();
        const bas = c.scellerPartiel(partiel, { priorite: "basse" });
        const a3 = echange();
        const [r1, r2, rb, r3] = await Promise.all([a1, a2, bas, a3]);
        expect(rb.seq).to.be.greaterThan(Math.max(r1.seq, r2.seq, r3.seq));
      });
    });
  });

  describe("EX-6.29, EX-6.30 : décodage", function () {
    it("JSON : AnyValue à deux membres, identifiant de longueur impaire, bytesValue invalide, champ message non objet : 400 ; null vaut absent ; champs inconnus ignorés", function () {
      const base = () => lot([span({})]);
      const l1 = base();
      l1.resourceSpans[0].scopeSpans[0].spans[0].attributes.push({ key: "a", value: { stringValue: "x", boolValue: true } });
      expect(() => decoderJson(Buffer.from(JSON.stringify(l1)), BORNES)).to.throw(ErreurDecodage);
      const l2 = base();
      l2.resourceSpans[0].scopeSpans[0].spans[0].traceId = "abc";
      expect(() => decoderJson(Buffer.from(JSON.stringify(l2)), BORNES)).to.throw(ErreurDecodage);
      const l3 = base();
      l3.resourceSpans[0].scopeSpans[0].spans[0].attributes.push({ key: "b", value: { bytesValue: "!!" } });
      expect(() => decoderJson(Buffer.from(JSON.stringify(l3)), BORNES)).to.throw(ErreurDecodage);
      const l4 = base();
      l4.resourceSpans[0].scopeSpans[0].spans[0].status = "OK";
      expect(() => decoderJson(Buffer.from(JSON.stringify(l4)), BORNES)).to.throw(ErreurDecodage);
      const l5 = base();
      Object.assign(l5.resourceSpans[0].scopeSpans[0].spans[0], { traceState: null, inconnu: { x: 1 }, parent_span_id: "zz" });
      expect(() => decoderJson(Buffer.from(JSON.stringify(l5)), BORNES)).to.not.throw();
      expect(() => decoderJson(Buffer.from("﻿{}"), BORNES)).to.throw(ErreurDecodage);
    });

    it("protobuf : type de fil 3 ou 6, étiquette 0, varint de onze octets, longueur au-delà, bool 2, UTF-8 invalide, oneof double : 400 ; champ inconnu sauté", function () {
      const bon = [...encoderProtobuf(lot([span({})]))];
      expect(() => decoderProtobuf(new Uint8Array([...bon, (99 << 3) | 0, 1]), BORNES)).to.not.throw();
      for (const mauvais of [
        [(1 << 3) | 3],
        [(1 << 3) | 6],
        [0, 0],
        [(1 << 3) | 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
        [(1 << 3) | 2, 0x7f, 0x01],
        [(1 << 3) | 0, 1],
      ]) {
        expect(() => decoderProtobuf(new Uint8Array(mauvais), BORNES), JSON.stringify(mauvais)).to.throw(ErreurDecodage);
      }
      const attr = (valeur) => encoderProtobuf({ resourceSpans: [{ resource: { attributes: [{ key: "k", value: valeur }] }, scopeSpans: [] }] });
      const b = [...attr({ boolValue: true })];
      b[b.length - 1] = 2;
      expect(() => decoderProtobuf(new Uint8Array(b), BORNES)).to.throw(ErreurDecodage);
      const s = [...attr({ stringValue: "é" })];
      s[s.length - 1] = 0xff;
      expect(() => decoderProtobuf(new Uint8Array(s), BORNES)).to.throw(ErreurDecodage);
      // Deux membres du oneof d'AnyValue.
      const kvDouble = [0x0a, 0x01, 0x6b, 0x12, 0x05, 0x0a, 0x01, 0x78, 0x10, 0x01];
      const res = [0x0a, kvDouble.length, ...kvDouble];
      const rs = [0x0a, res.length, ...res];
      expect(() => decoderProtobuf(new Uint8Array([0x0a, rs.length, ...rs]), BORNES)).to.throw(ErreurDecodage);
    });

    it("un corps protobuf et un corps JSON qui portent les mêmes valeurs donnent les mêmes événements (EX-6.30, EX-6.31)", async function () {
      await avec({}, async (d) => {
        const ids = identifiants();
        const sp = spanOutil("dossier.ecrire", { ids, attributs: { "gen_ai.tool.call.arguments": '{"note":"ok"}' } });
        await d.envoyer({ corps: lot([sp]) });
        const a = (await d.evenements()).at(-1);
        const d2 = await demarrerDemonOtel({});
        try {
          await d2.envoyer({ type: "application/x-protobuf", corps: encoderProtobuf(lot([sp])) });
          const b = (await d2.evenements()).at(-1);
          expect(b.execution.arguments).to.deep.equal(a.execution.arguments);
          expect(b.context).to.deep.equal(a.context);
        } finally {
          await d2.arreter();
        }
      });
    });
  });

  describe("EX-6.31 à EX-6.34 : normalisation, classification, doublons, recouvrement", function () {
    it("clé en double : la première gardée, comptée (otel_cle_double) ; span ignoré : rien stocké, rien de son contenu au journal ; span rejeté : identifiants consignés", async function () {
      await avec({}, async (d) => {
        const sp = spanOutil("a.b");
        sp.attributes.push({ key: "gen_ai.tool.name", value: { stringValue: "autre" } });
        const ign = span({ nom: "nom-secret-du-span", attributs: { "http.url": "https://secret.exemple/x" } });
        const rej = spanOutil("c.d", { ids: { traceId: "0".repeat(32), spanId: "1".repeat(16) } });
        const pieces = () => (fs.existsSync(path.join(d.coeur.repertoire, "pieces")) ? fs.readdirSync(path.join(d.coeur.repertoire, "pieces"), { recursive: true }).length : 0);
        const avant = pieces();
        const r = await d.envoyer({ corps: lot([sp, ign, rej]) });
        expect(r.json).to.deep.equal({ partialSuccess: { rejectedSpans: "1", errorMessage: "noortrace: 1 span(s) rejete(s), identifiants invalides" } });
        expect((await d.evenements()).at(-1).execution.tool).to.equal("otel-sinistres__a.b");
        expect(d.lignes("otel_cle_double")[0].data.count).to.equal(1);
        const texte = JSON.stringify(d.coeur.journal.lignes);
        expect(texte).to.not.contain("nom-secret-du-span");
        expect(texte).to.not.contain("secret.exemple");
        expect(d.lignes("otel_span_rejected")[0].data).to.deep.equal({ trace_id: "0".repeat(32), span_id: "1".repeat(16), reason: "identifiants_invalides" });
        expect(pieces() - avant).to.be.greaterThan(0);
      });
    });

    it("doublons dans la fenêtre : aucun second événement ; contenu différent : otel_span_conflict et noortrace_otel_conflicts_total ; table bornée, sortie comptée", async function () {
      await avec({}, async (d) => {
        const ids = identifiants();
        const l = lot([spanOutil("a.b", { ids })]);
        await d.envoyer({ corps: l });
        const n = (await d.evenements()).length;
        await d.envoyer({ corps: l });
        expect((await d.evenements()).length).to.equal(n);
        await d.envoyer({ corps: lot([spanOutil("a.b", { ids, attributs: { "x.autre": "contenu" } })]) });
        expect((await d.evenements()).length).to.equal(n);
        expect(d.lignes("otel_span_conflict")).to.have.length(1);
        expect(d.coeur.metriques.valeur("noortrace_otel_conflicts_total", { source: "otel-sinistres" })).to.equal(1);
      });
      const sorties = [];
      const t = new TableDoublons({ fenetreMs: 1000, max: 2, surSortie: (k) => sorties.push(k) });
      t.inscrire("a", "x", 0);
      t.inscrire("b", "x", 1);
      t.inscrire("c", "x", 2);
      expect(sorties).to.deep.equal([1]);
      expect(t.chercher("a", 3)).to.equal(undefined);
      expect(t.chercher("c", 3)).to.not.equal(undefined);
      expect(t.chercher("c", 5000)).to.equal(undefined);
    });

    it("recouvrement : un span d'outil qui décrit un appel du SDK du même groupe est écarté (otel_span_overlap, seq) ; d'un échange déclaré aussi ; overlap conserver : scellé", async function () {
      await avec({ sdk: true }, async (d) => {
        const s = await new ClientNoortrace({ socket: d.config.sdk.socket }).ouvrir({});
        const debut = await s.debutAppel({ tool: "dossier.lire", arguments: { id: 1 }, classe: "lecture" });
        const fin = await s.finAppel(debut, { resultat: null, isError: false, durationMs: 1 });
        const ech = await s.echangeModele({ format: "autre", providerLabel: "local", request: { model: "modele-x" }, response: {}, status: 200, durationMs: 1, isError: false });
        await s.fermer();
        const n = (await d.evenements()).length;
        const r = await d.envoyer({ corps: lot([spanOutil("dossier.lire"), spanInference("modele-x"), spanOutil("dossier.lire")]) });
        expect(r.statut).to.equal(200);
        const recouvrements = d.lignes("otel_span_overlap").map((l) => l.data.seq);
        expect(recouvrements).to.deep.equal([fin.seq, ech.seq]);
        // Le second span du même nom ne trouve plus d'appel non apparié : scellé.
        expect((await d.evenements()).length).to.equal(n + 1);
      });
      await avec(
        {
          sdk: true,
          modifier: (c) => (c.policy.otel.sources["otel-sinistres"].overlap = "conserver"),
        },
        async (d) => {
          const s = await new ClientNoortrace({ socket: d.config.sdk.socket }).ouvrir({});
          const debut = await s.debutAppel({ tool: "dossier.lire", arguments: {}, classe: "lecture" });
          await s.finAppel(debut, { resultat: null, isError: false, durationMs: 1 });
          await s.fermer();
          const n = (await d.evenements()).length;
          await d.envoyer({ corps: lot([spanOutil("dossier.lire")]) });
          expect((await d.evenements()).length).to.equal(n + 1);
          expect(d.lignes("otel_span_overlap")).to.have.length(0);
        },
      );
    });
    it("recouvrement (lecture 125) : un appel et un échange du SDK mis en attente (14.5) puis scellés démon en marche entrent au registre ; le span qui les décrit est apparié, pas de double capture", async function () {
      await avec({ sdk: true, modifier: (c) => (c.policy.failure.modele = "passant") }, async (d) => {
        const s = await new ClientNoortrace({ socket: d.config.sdk.socket }).ouvrir({});
        d.coeur.degrade.entrer("stockage");
        const debut = await s.debutAppel({ tool: "dossier.lire", arguments: { id: 2 }, classe: "lecture" });
        expect(await s.finAppel(debut, { resultat: null, isError: false, durationMs: 1 })).to.deep.equal({ seq: null, hash: null });
        expect(await s.echangeModele({ format: "autre", providerLabel: "local", request: { model: "modele-y" }, response: {}, status: 200, durationMs: 1, isError: false })).to.deep.equal({ seq: null, hash: null });
        expect(d.coeur.attente).to.have.length(2);
        d.coeur.degrade.sortir("stockage");
        await d.coeur.viderAttente();
        const scelles = (await d.evenements()).slice(-2);
        expect(scelles.map((e) => e.execution.tool)).to.deep.equal(["agent-local__dossier.lire", "noortrace.modele.echange"]);
        await s.fermer();
        const n = (await d.evenements()).length;
        const r = await d.envoyer({ corps: lot([spanOutil("dossier.lire"), spanInference("modele-y")]) });
        expect(r.statut).to.equal(200);
        expect(d.lignes("otel_span_overlap").map((l) => l.data.seq)).to.deep.equal(scelles.map((e) => e.seq));
        expect((await d.evenements()).length).to.equal(n);
      });
    });
  });

  describe("EX-6.35, EX-6.36 : pièces et champs", function () {
    it("pièce au-delà de limits.piece_max_bytes : forme taille, otel_piece_too_large, réponse 200 ; rédaction au-delà de la borne : pièce non rédigeable, événement scellé", async function () {
      await avec({ modifier: (c) => (c.limits.piece_max_bytes = 1024) }, async (d) => {
        const r = await d.envoyer({ corps: lot([spanOutil("a.b", { attributs: { "gen_ai.tool.call.result": "z".repeat(3000) } })]) });
        expect(r.statut).to.equal(200);
        const e = (await d.evenements()).at(-1);
        expect(JSON.parse(await lirePiece(d, e.execution.result.sha256))).to.deep.equal({ noortrace_non_redigeable: { content_type: null, length: 3002, reason: "taille" } });
        expect(d.lignes("otel_piece_too_large")[0].data.piece).to.equal("result");
      });
      await avec({ modifier: (c) => (c.limits.redaction_budget_ms = 1) }, async (d) => {
        const texte = Array.from({ length: 30000 }, (_, k) => `x${k}@exemple-${k}.ch`).join(" ");
        const r = await d.envoyer({ corps: lot([spanOutil("a.b", { attributs: { "gen_ai.tool.call.arguments": texte } })]) });
        expect(r.statut).to.equal(200);
        const e = (await d.evenements()).at(-1);
        expect(JSON.parse(await lirePiece(d, e.execution.arguments.sha256)).noortrace_non_redigeable.reason).to.equal("budget_redaction");
        expect(e.execution.arguments.redacted).to.equal(true);
      });
    });

    it("ts de l'écrivain, jamais du span ; durée déclarée ; is_error ; run_id déclaré admis ou refusé ; nom invalide", async function () {
      await avec({}, async (d) => {
        const r = await d.envoyer({
          corps: lot([
            spanOutil("sap__payments.create", { debut: "1000000000000000000", fin: "1000000000123900000", statut: 2, attributs: { "gen_ai.conversation.id": "conv-1" } }),
            spanInference("m", { attributs: { "gen_ai.conversation.id": "jean@exemple.ch", "error.type": "timeout" } }),
          ]),
        });
        expect(r.statut).to.equal(200);
        const [o, i] = (await d.evenements()).slice(-2);
        expect(o.execution.tool).to.equal("otel-sinistres__nom-invalide");
        expect(o.execution.duration_ms).to.equal(123);
        expect(o.execution.is_error).to.equal(true);
        expect(o.ts.startsWith("2001")).to.equal(false);
        expect(o.delegation.run_id).to.equal("conv-1");
        expect(o.effects).to.deep.equal([{ system: "otel-sinistres", action: "ecriture", object: "nom-invalide", amount: null, currency: null }]);
        const env = JSON.parse(await lirePiece(d, o.context[1].sha256));
        expect(env.attributes["gen_ai.tool.name"]).to.equal("sap__payments.create");
        expect(i.execution.is_error).to.equal(true);
        expect(i.delegation.run_id).to.equal(null);
        expect(d.lignes("delegation_refused").at(-1).data).to.deep.include({ component: "otel", field: "run_id", reason: "motif" });
        expect(i.policy.decision).to.equal("sans_objet");
      });
    });
  });

  describe("EX-6.37 : sources et authentification", function () {
    it("X-Noortrace-Token ou Authorization: Bearer ; jeton faux : 401, auth_failed, jamais le jeton ; limité par identifiant de jeton (EX-18.3)", async function () {
      await avec({}, async (d) => {
        expect((await d.envoyer({ jeton: null, entetes: { authorization: `Bearer ${d.jeton}` }, corps: lot([]) })).statut).to.equal(200);
        for (let k = 0; k < 10; k++) expect((await d.envoyer({ jeton: "faux-jeton-xyz", corps: lot([]) })).statut).to.equal(401);
        expect(JSON.stringify(d.coeur.journal.lignes)).to.not.contain("faux-jeton-xyz");
        expect(JSON.stringify(d.coeur.journal.lignes)).to.not.contain(d.jeton);
        // Le jeton valide n'est jamais refusé à cause des échecs d'un autre (connexions distinctes).
        expect((await d.envoyer({ corps: lot([]), agent: new http.Agent({ keepAlive: false }) })).statut).to.equal(200);
        expect(d.coeur.metriques.valeur("noortrace_otel_requests_total", { source: "", status: "401" })).to.equal(10);
      });
    });
  });

  describe("EX-6.38, EX-6.39 : ordre, réponse, pannes", function () {
    it("événements dans l'ordre du document, durables avant la réponse 200", async function () {
      await avec({}, async (d) => {
        const noms = ["un.a", "deux.b", "trois.c"];
        const l = lot(noms.map((n) => spanOutil(n)));
        await d.envoyer({ corps: l });
        expect((await d.evenements()).slice(-3).map((e) => e.execution.tool)).to.deep.equal(noms.map((n) => `otel-sinistres__${n}`));
      });
    });

    it("mode dégradé (stockage, clé, horloge, bail) : 503 avec Retry-After, aucun événement en attente ; service d'approbation indisponible : sans effet", async function () {
      await avec({}, async (d) => {
        for (const raison of ["stockage", "cle", "horloge"]) {
          d.coeur.degrade.entrer(raison);
          const r = await d.envoyer({ corps: lot([spanOutil("a.b")]) });
          expect(r.statut, raison).to.equal(503);
          expect(r.entetes["retry-after"]).to.equal("5");
          expect(d.coeur.attente).to.have.length(0);
          expect(d.lignes("otel_refused").at(-1).data.reason).to.equal(raison);
          d.coeur.degrade.sortir(raison);
        }
        d.coeur.bailDetenu = false;
        expect((await d.envoyer({ corps: lot([]) })).statut).to.equal(503);
        d.coeur.bailDetenu = true;
        d.coeur.degrade.entrer("approbation");
        expect((await d.envoyer({ corps: lot([spanOutil("a.b")]) })).statut).to.equal(200);
        d.coeur.degrade.sortir("approbation");
      });
    });
  });

  describe("EX-6.40 : sécurité", function () {
    it("une source ne produit que des noms de préfixe <son alias>__ ; aucune URL d'un span n'est visitée", async function () {
      let visites = 0;
      const espion = http.createServer((req, res) => (visites++, res.end()));
      await new Promise((r) => espion.listen(0, "127.0.0.1", r));
      try {
        await avec({}, async (d) => {
          const url = `http://127.0.0.1:${espion.address().port}/schema`;
          const l = lot([spanOutil("noortrace.journal.politique", { attributs: { "server.address": url } }), spanOutil("agent-local__x")]);
          l.resourceSpans[0].schemaUrl = url;
          await d.envoyer({ corps: l });
          for (const e of (await d.evenements()).slice(-2)) expect(e.execution.tool).to.equal("otel-sinistres__nom-invalide");
        });
        expect(visites).to.equal(0);
      } finally {
        await new Promise((r) => espion.close(r));
      }
    });

    it("validation (EX-15.4 pas 3) : jeton, alias, sources, launched_by, allowed_on_behalf_of, TLS hors bouclage en production ; avertissements", function () {
      const base = () => configurationDev(repertoireTemporaire("noortrace-otel-cfg-")).config;
      const valider = (c) => validerConfiguration(new TextEncoder().encode(JSON.stringify(c)), { reglesSupplementaires: [controleOtel] });
      expect(valider(base()).erreurs).to.deep.equal([]);
      const cas = [
        [(c) => (c.otel.hosts[0].match = { static_token: "inconnu" }), "/otel/hosts/0/match/static_token"],
        [(c) => (c.otel.hosts[0].alias = null), "/otel/hosts/0/alias"],
        [(c) => (c.otel.hosts[0].alias = "sap"), "/otel/hosts/0/alias"],
        [(c) => (c.otel.hosts[0].launched_by = "${peer_user}"), "/otel/hosts/0/launched_by"],
        [(c) => (c.otel.hosts[0].allowed_on_behalf_of = ["x"]), "/otel/hosts/0/allowed_on_behalf_of"],
        [(c) => (c.policy.otel.sources.autre = { ingest: ["outil"], overlap: "ignorer", class_default: null, tools: {} }), "/policy/otel/sources/autre"],
        [(c) => ((c.recorder.environment = "production"), (c.otel.listen = "otel.exemple:4318")), "/otel/tls"],
      ];
      for (const [f, p] of cas) {
        const c = base();
        f(c);
        expect(controleOtel(c).erreurs.map((e) => e.pointeur), p).to.include(p);
      }
      const c = base();
      c.otel.encodings = ["json"];
      c.policy.otel.sources["otel-sinistres"].overlap = "conserver";
      expect(controleOtel(c).avertissements.map((a) => a.pointeur)).to.deep.equal(["/policy/otel/sources/otel-sinistres/overlap", "/otel/encodings"]);
    });
  });

  describe("EX-6.40 (1) : TLS du point d'entrée", function () {
    it("otel.tls : OTLP/HTTPS avec un certificat généré à l'exécution, TLS 1.2 au moins ; TLS 1.1 refusé", async function () {
      const dirTls = repertoireTemporaire("noortrace-otel-tls-");
      const cert = path.join(dirTls, "cert.pem");
      const cle = path.join(dirTls, "cle.pem");
      const r0 = spawnSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", cle, "-out", cert], { encoding: "utf8" });
      if (r0.status !== 0) this.skip();
      await avec({ modifier: (c) => (c.otel.tls = { cert_file: cert, key_file: cle }) }, async (d) => {
        const envoyerTls = (o = {}) =>
          new Promise((resoudre, rejeter) => {
            const corps = Buffer.from(JSON.stringify(lot([spanOutil("a.b")])));
            const req = https.request(
              { host: "127.0.0.1", port: d.adresse.port, method: "POST", path: "/v1/traces", ca: fs.readFileSync(cert), headers: { "content-type": "application/json", "x-noortrace-token": d.jeton, "content-length": corps.length }, ...o },
              (res) => (res.resume(), res.on("end", () => resoudre(res.statusCode))),
            );
            req.on("error", rejeter);
            req.end(corps);
          });
        expect(await envoyerTls()).to.equal(200);
        let refus = null;
        try {
          await envoyerTls({ maxVersion: "TLSv1.1", minVersion: "TLSv1.1", ciphers: "DEFAULT@SECLEVEL=0" });
        } catch (e) {
          refus = e;
        }
        expect(refus).to.not.equal(null);
      });
    });
  });

  describe("EX-6.41 : supervision", function () {
    it("otel_request pour toute requête, refusée comprise ; métriques des requêtes, des spans par issue et raison, du retard", async function () {
      await avec({}, async (d) => {
        await d.envoyer({ chemin: "/x" });
        await d.envoyer({ corps: lot([spanOutil("a.b", { fin: "1794307799000000000" }), span({ attributs: { "gen_ai.operation.name": "embeddings" } })]) });
        const l = d.lignes("otel_request");
        expect(l.map((x) => x.data.status)).to.deep.equal([404, 200]);
        expect(l[1].data.issues).to.deep.equal({ scelle: 1, ignore: 1, doublon: 0, recouvrement: 0, rejete: 0 });
        expect(l[1].data.reasons).to.deep.equal({ operation_non_retenue: 1 });
        const m = d.coeur.metriques;
        expect(m.valeur("noortrace_otel_requests_total", { source: "otel-sinistres", status: "200" })).to.equal(1);
        expect(m.valeur("noortrace_otel_spans_total", { source: "otel-sinistres", issue: "scelle", reason: "" })).to.equal(1);
        expect(m.valeur("noortrace_otel_reception_lag_ms", { source: "otel-sinistres" })).to.equal(1);
        expect(m.exposer()).to.contain("noortrace_otel_reception_lag_ms_bucket");
        expect(analyserJsonIntegral(JSON.stringify(l[1].data)).spans).to.equal(2);
      });
    });
  });
});
