import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { keccak256, toUtf8Bytes } from "ethers";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as C from "../scripts/lib/capture.mjs";
import * as AP from "../scripts/lib/approbation.mjs";
import * as OT from "../scripts/lib/otel.mjs";
import * as W from "../scripts/lib/worm.mjs";
import { coutAgent, relevesParAn } from "../scripts/lib/cout-agent.mjs";

// RÉVISION 0.5 DE CT-2 (spec/CT-2-enregistreur.md, version 0.5) : API Gemini à
// la passerelle et format gemini du SDK (EX-5.28 à EX-5.36, EX-6.8),
// ingestion OpenTelemetry (6.8, EX-6.25 à EX-6.41), copies WORM et gel
// juridique (12.6, 12.11, EX-12.29 à EX-12.41), coût annuel par agent (16.4,
// EX-16.4 à EX-16.6), contrôles de démarrage ajoutés (EX-15.4 pas 3). Les
// références sont scripts/lib/capture.mjs, otel.mjs, worm.mjs et
// cout-agent.mjs ; les vecteurs pieces-modele/gemini-*, otel/, worm/ et
// cout-agent/ de spec/vecteurs/ct-2 sont rejoués un par un, et les valeurs
// imprimées dans la spécification sont recalculées depuis son texte.

const SPEC = path.join(PROJECT_ROOT, "spec");
const VECTEURS = path.join(SPEC, "vecteurs", "ct-2");
const lireSchema = (n) => JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", `${n}-v0.schema.json`), "utf8"));
const SCHEMAS = J.registreSchemas(["evenement", "manifeste", "dossier", "politique-redaction", "politique-approbation", "ticket", "configuration-enregistreur", "worm", "cout-agent"].map(lireSchema));
const ID_CONFIG = C.ID_SCHEMA_CONFIGURATION;
const ID_WORM = "https://noortrace.example/schemas/v0/worm.schema.json";
const ID_COUT = "https://noortrace.example/schemas/v0/cout-agent.schema.json";
const lireJSON = (...p) => C.analyserJSONIntegral(fs.readFileSync(path.join(VECTEURS, ...p)));
const existe = (...p) => fs.existsSync(path.join(VECTEURS, ...p));
const MD = fs.readFileSync(path.join(SPEC, "CT-2-enregistreur.md"), "utf8");
/** Les blocs JSON annotés `<!-- schema: marque -->` de CT-2, texte exact. */
const blocs = (marque) => [...MD.matchAll(new RegExp(`<!-- schema: ${marque} -->\\n\`\`\`json\\n([\\s\\S]*?)\\n\`\`\``, "g"))].map((m) => m[1]);
const section = (debut, fin) => MD.slice(MD.indexOf(debut), MD.indexOf(fin, MD.indexOf(debut)));
const CONFIG = C.analyserJSONIntegral(blocs("configuration-enregistreur")[0]);
const PII = C.chargerPolitique(lireJSON("redaction", "politique-pii-v1.json"), { schemas: SCHEMAS });
const CLE_01 = J.cleEd25519DepuisGraine(J.sha256(Buffer.from("noortrace/vecteurs/v0/cle-enregistreur/rec-test-01", "utf8")));
const ORG_ID = keccak256(toUtf8Bytes("assureur-demo"));
const JOURNAL_ID = keccak256(toUtf8Bytes("journal-demo"));
const avecOctets = (p) => (p ? { ...p.reference, bytes: Buffer.from(p.octets).toString("utf8") } : null);
const jcs = (v) => J.canonicaliserJCSIntegral(v);

// ---------------------------------------------------------------------------
describe("CT-2 révision 0.5 : Gemini à la passerelle et format gemini du SDK (EX-5.28 à EX-5.36, EX-6.8)", function () {
  const ROUTES = [{ path: "/v1beta/models", format: "gemini", provider_label: "gemini" }, { path: "/v1/models", format: "gemini", provider_label: "gemini" }];
  const corpsJSON = (o) => Buffer.from(JSON.stringify(o), "utf8");
  const reponseOK = { status: 200, content_type: "application/json; charset=UTF-8", corps: corpsJSON({ candidates: [{ content: { parts: [{ text: "ok" }], role: "model" }, finishReason: "STOP", index: 0 }], modelVersion: "gemini-exemple-001" }) };
  const requeteOK = { corps: corpsJSON({ contents: [{ role: "user", parts: [{ text: "Statut ?" }] }] }), content_type: "application/json" };

  it("pieces-modele/gemini-* : les 30 cas de l'annexe B.5 rejoués (route, segment, refus et corps exact, cible amont, pièces, forme consolidée, code.model, intent, appels)", function () {
    const cas = fs.readdirSync(path.join(VECTEURS, "pieces-modele")).filter((n) => n.startsWith("gemini-")).sort();
    expect(cas).to.have.length(30);
    for (const nom of cas) {
      const at = lireJSON("pieces-modele", nom, "attendu.json");
      const options = { politique: PII, prompt_in_request: at.options.prompt_in_request, prompt_system: at.options.prompt_system };
      let r;
      if (at.via === "sdk") {
        // EX-6.8, B.5 : statut et is_error déclarés lus dans echange-sdk.json, jamais dans attendu.json.
        const declare = lireJSON("pieces-modele", nom, "echange-sdk.json");
        expect([declare.format, declare.provider_label, declare.status], nom).to.deep.equal(["gemini", at.provider_label, at.status]);
        r = C.echangeModeleSDKGemini({ provider_label: declare.provider_label, request: lireJSON("pieces-modele", nom, "requete.json"), response: lireJSON("pieces-modele", nom, "reponse-morceaux.json"), status: declare.status, is_error: declare.is_error, ...options });
        expect([at.request_line, at.model_segment, at.upstream_target, r.removed_members], nom).to.deep.equal([null, null, null, at.removed_members]);
      } else {
        const ligne = lireJSON("pieces-modele", nom, "requete-ligne.json");
        expect(ligne, nom).to.deep.equal(at.request_line);
        const brut = existe("pieces-modele", nom, "requete.brut");
        const corps = fs.readFileSync(path.join(VECTEURS, "pieces-modele", nom, brut ? "requete.brut" : "requete.json"));
        let reponse = null;
        if (existe("pieces-modele", nom, "reponse-entetes.json")) {
          const e = lireJSON("pieces-modele", nom, "reponse-entetes.json");
          const flux = existe("pieces-modele", nom, "reponse.sse");
          reponse = { status: e.status, content_type: e["content-type"], corps: fs.readFileSync(path.join(VECTEURS, "pieces-modele", nom, flux ? "reponse.sse" : "reponse.json")) };
          if (flux && nom !== "gemini-flux-crlf-data-final") expect(fs.readFileSync(path.join(VECTEURS, "pieces-modele", nom, "reponse.sse"), "utf8"), nom).to.not.include("\r");
        }
        r = C.echangeGemini({ method: ligne.method, target: ligne.target, routes: ROUTES, hote_connu: ligne.host_known !== false, requete: { corps, content_type: "application/json" }, reponse, ...options });
        expect([r.model_segment, r.refus ? null : r.upstream_target], nom).to.deep.equal([at.model_segment, at.upstream_target]);
        expect(r.route ? r.route.path : null, nom).to.equal(at.route);
      }
      if (at.refused) {
        expect({ status: r.refus.status, reason: r.refus.raison, body: r.refus.corps, content_type: r.refus.content_type }, nom).to.deep.equal(at.refused);
        // Corps de refus : octets compacts dans l'ordre code, message, status (EX-5.30).
        if (r.refus.corps) expect(JSON.stringify(r.refus.corps), nom).to.equal(jcs(at.refused.body));
        expect([at.pieces, existe("pieces-modele", nom, "reponse-entetes.json")], nom).to.deep.equal([null, false]);
        continue;
      }
      expect(jcs(r.consolidated), `${nom} : forme consolidée`).to.equal(jcs(at.consolidated));
      expect({ request: avecOctets(r.pieces.requete), response: avecOctets(r.pieces.reponse), system_prompt: avecOctets(r.pieces.prompt_systeme), intent: avecOctets(r.pieces.intention) }, `${nom} : pièces`).to.deep.equal(at.pieces);
      expect([r.code_model, r.prompt_version, r.intent, r.is_error, r.incomplete], nom).to.deep.equal([at.code_model, at.prompt_version, at.intent, at.is_error, at.incomplete]);
      expect(jcs(r.tool_calls), `${nom} : appels`).to.equal(jcs(at.tool_calls));
    }
  });

  it("EX-5.28 : routeGemini (préfixe, segment, suffixe littéral) ; cibleAmontGemini reconstruite", function () {
    const ok = C.routeGemini("/v1beta/models/gemini-2.0-flash:streamGenerateContent", ROUTES);
    expect([ok.route.path, ok.segment, ok.methode]).to.deep.equal(["/v1beta/models", "gemini-2.0-flash", "streamGenerateContent"]);
    expect(C.cibleAmontGemini(ok.route, ok.segment, ok.methode)).to.equal("/v1beta/models/gemini-2.0-flash:streamGenerateContent?alt=sse");
    expect(C.cibleAmontGemini(ok.route, ok.segment, "generateContent")).to.equal("/v1beta/models/gemini-2.0-flash:generateContent");
    for (const chemin of ["/v1beta/tunedModels/m:generateContent", "/v1beta/models/gemini-exemple%3AgenerateContent", "/v1beta/models/Gemini-Exemple:generateContent", "/v1beta/models/a/b:generateContent", "/v1beta/models/gemini-exemple:countTokens", "/v1beta/models/:generateContent", "/v1/projects/p/locations/l/publishers/google/models/m:generateContent", "/"]) {
      expect(C.routeGemini(chemin, ROUTES), chemin).to.equal(null);
    }
    expect(C.routeGemini("/v1beta/models/" + "a".repeat(128) + ":generateContent", ROUTES).segment).to.have.length(128);
    expect(C.routeGemini("/v1beta/models/" + "a".repeat(129) + ":generateContent", ROUTES)).to.equal(null);
    // EX-5.2 : %3A n'est pas décodé (réservé), %2F refusé, les non réservés décodés.
    expect(C.normaliserChemin("/v1beta/models/m%3AgenerateContent").chemin).to.equal("/v1beta/models/m%3AgenerateContent");
    expect(C.normaliserChemin("/v1beta/models/m%2Fx:generateContent").refus).to.equal("chemin_invalide");
    expect(C.normaliserChemin("/v1beta/%6Dodels/m:generateContent").chemin).to.equal("/v1beta/models/m:generateContent");
    expect(C.normaliserChemin("/v1beta//models").refus).to.equal("chemin_invalide");
    expect(C.normaliserChemin("/v1beta/../models").refus).to.equal("chemin_invalide");
    const r = C.echangeGemini({ method: "GET", target: "/v1beta/models/gemini-exemple:generateContent", routes: ROUTES, requete: requeteOK, reponse: reponseOK, politique: PII });
    expect([r.refus.status, r.refus.raison, r.journal[0].event]).to.deep.equal([404, "route_inconnue", "model_route_not_found"]);
  });

  it("EX-5.29 : examinerRequeteGemini, ordre des raisons ; noms consignés, jamais les valeurs", function () {
    const ex = (m, q) => C.examinerRequeteGemini(m, q);
    expect(ex("generateContent", null).ok).to.equal(true);
    expect(ex("generateContent", "").ok).to.equal(true);
    expect(ex("generateContent", "alt=json").ok).to.equal(true);
    expect(ex("streamGenerateContent", "alt=sse").ok).to.equal(true);
    expect(ex("streamGenerateContent", "alt=%73se").ok).to.equal(true);
    expect(ex("generateContent", "alt=sse").refus.raison).to.equal("parametre_non_admis");
    expect(ex("generateContent", "alt=proto").refus.raison).to.equal("parametre_non_admis");
    expect(ex("generateContent", "alt=json&alt=json").refus.raison).to.equal("parametre_non_admis");
    expect(ex("streamGenerateContent", "alt=sse&alt=sse").refus.raison).to.equal("parametre_non_admis");
    expect(ex("streamGenerateContent", "alt=sse&x=1").refus.raison).to.equal("parametre_non_admis");
    expect(ex("streamGenerateContent", null).refus.raison).to.equal("flux_sans_sse");
    expect(ex("streamGenerateContent", "alt=json").refus.raison).to.equal("flux_sans_sse");
    // `key` d'abord, même vide, même avant flux_sans_sse.
    expect(ex("streamGenerateContent", "key").refus.raison).to.equal("cle_dans_url");
    expect(ex("streamGenerateContent", "x=1&k%65y=secret").refus).to.deep.equal({ status: 400, raison: "cle_dans_url", noms: ["x", "key"] });
    const r = C.echangeGemini({ method: "POST", target: "/v1beta/models/gemini-exemple:generateContent?key=valeur-secrete", routes: ROUTES, requete: requeteOK, reponse: reponseOK, politique: PII });
    expect(JSON.stringify(r.journal)).to.not.include("valeur-secrete");
    expect(r.journal[0]).to.deep.equal({ event: "model_request_refused", data: { route: "/v1beta/models", reason: "cle_dans_url", names: ["key"] } });
  });

  it("EX-5.30 : corps d'erreur AIP-193 de la passerelle, octets exacts de la table, Content-Type selon la méthode", function () {
    const table = [...section("**EX-5.30**", "**EX-5.31**").matchAll(/^\| `(\d{3})` \| ([^|]+) \| `(\{"error".*\})` \|$/gm)].map((m) => [Number(m[1]), m[3]]);
    expect(table).to.have.length(11);
    const raisons = ["corps_non_analysable", "cle_dans_url", "flux_sans_sse", "parametre_non_admis", "serveurs_mcp_fournisseur", "cache_fournisseur", "hote_inconnu", "taille", "content_encoding", "mode_degrade", "delai"];
    raisons.forEach((raison, i) => {
      const corps = C.corpsErreurGemini(raison);
      expect([corps.error.code, JSON.stringify(corps)], raison).to.deep.equal(table[i]);
    });
    expect(C.contentTypeRefusGemini("generateContent", false)).to.equal("application/json; charset=UTF-8");
    expect(C.contentTypeRefusGemini("streamGenerateContent", false)).to.equal("application/json; charset=UTF-8");
    expect(C.contentTypeRefusGemini("streamGenerateContent", true)).to.equal("text/event-stream");
    // 415 et 413 sur une route gemini (EX-5.7 point 1, EX-5.33).
    const gz = C.echangeGemini({ method: "POST", target: "/v1beta/models/m:streamGenerateContent?alt=sse", routes: ROUTES, requete: { ...requeteOK, content_encoding: "gzip" }, reponse: reponseOK, politique: PII });
    expect([gz.refus.status, gz.refus.raison, gz.refus.content_type, gz.refus.corps.error.status]).to.deep.equal([415, "content_encoding", "text/event-stream", "INVALID_ARGUMENT"]);
    const grand = C.echangeGemini({ method: "POST", target: "/v1beta/models/m:generateContent", routes: ROUTES, requete: requeteOK, reponse: reponseOK, politique: PII, requestMaxBytes: 10 });
    expect([grand.refus.status, grand.refus.raison, grand.refus.corps.error.code]).to.deep.equal([413, "taille", 413]);
  });

  it("EX-5.31 : corps d'erreur amont analysé quel que soit le Content-Type ; jamais d'analyseur SSE au-delà de 400", function () {
    const md = section("**EX-5.31**", "**EX-5.32**");
    const exemple = JSON.parse(/```json\n([\s\S]*?)\n```/.exec(md)[1]);
    const r = C.echangeModele({ format: "gemini", provider_label: "gemini", segment: "gemini-exemple", requete: requeteOK, reponse: { status: 400, content_type: "text/event-stream", corps: Buffer.from(JSON.stringify(exemple.noortrace_http_error.body, null, 2)) }, politique: null });
    expect(r.pieces.reponse.valeur).to.deep.equal(exemple);
    expect([r.is_error, r.consolidated, r.code_model]).to.deep.equal([true, null, "gemini/gemini-exemple"]);
    // Corps non JSON : la règle de 5.3.1 pas 7 telle quelle (chaîne).
    const t = C.echangeModele({ format: "gemini", provider_label: "gemini", segment: "m", requete: requeteOK, reponse: { status: 503, content_type: "text/html", corps: Buffer.from("<html>panne</html>") } });
    expect(t.pieces.reponse.valeur.noortrace_http_error.body).to.equal("<html>panne</html>");
    // Pour les autres formats, un corps JSON reçu sous un type non JSON reste une chaîne (inchangé).
    const a = C.echangeModele({ format: "anthropic-messages", provider_label: "anthropic", requete: { corps: corpsJSON({ model: "m", max_tokens: 1, messages: [] }) }, reponse: { status: 400, content_type: "text/plain", corps: Buffer.from('{"a":1}') } });
    expect(a.pieces.reponse.valeur.noortrace_http_error.body).to.equal('{"a":1}');
  });

  it("EX-5.32 : mcpServers refusés sous refuser (défaut), relayés et consignés sous relayer, notés seulement pour le SDK ; null et [] ne comptent pas", function () {
    const avec = (mcp) => ({ corps: corpsJSON({ contents: [], tools: [{ mcpServers: mcp }] }), content_type: "application/json" });
    expect(C.serveursMcpFournisseur({ tools: [{ mcpServers: null }, { mcpServers: [] }, { functionDeclarations: [] }] })).to.equal(0);
    const refus = C.echangeGemini({ method: "POST", target: "/v1beta/models/m:generateContent", routes: ROUTES, requete: avec([{ name: "s", streamableHttpTransport: { url: "https://mcp.exemple.invalid/x" } }]), reponse: reponseOK, politique: PII });
    expect([refus.refus.status, refus.refus.raison]).to.deep.equal([400, "serveurs_mcp_fournisseur"]);
    expect(JSON.stringify(refus.journal)).to.not.include("mcp.exemple.invalid");
    const relais = C.echangeGemini({ method: "POST", target: "/v1beta/models/m:generateContent", routes: [{ ...ROUTES[0], provider_mcp: "relayer" }], requete: avec([{ name: "s" }, { name: "t" }]), reponse: reponseOK, politique: PII });
    expect(relais.refus).to.equal(undefined);
    expect(relais.journal).to.deep.include({ event: "provider_mcp_bypass", data: { route: "/v1beta/models", entries: 2 } });
    const sdk = C.echangeModeleSDKGemini({ provider_label: "gemini", request: { contents: [], tools: [{ mcpServers: [{ name: "s" }] }] }, response: { candidates: [] }, status: 200, politique: PII });
    expect(sdk.journal).to.deep.include({ event: "provider_mcp_bypass", data: { entries: 1 } });
  });

  it("EX-5.33 : bornes de taille pour tous les formats (413 au format du fournisseur ; réponse au-delà : capture arrêtée)", function () {
    const m = C.echangeModele({ format: "anthropic-messages", provider_label: "a", requete: { corps: Buffer.alloc(20, 0x20) }, reponse: null, requestMaxBytes: 10 });
    expect([m.refus.status, JSON.stringify(m.refus.corps)]).to.deep.equal([413, '{"type":"error","error":{"type":"noortrace_taille","message":"noortrace: corps de requete trop grand"}}']);
    const o = C.echangeModele({ format: "openai-chat", provider_label: "o", requete: { corps: Buffer.alloc(20, 0x20) }, reponse: null, requestMaxBytes: 10 });
    expect(JSON.stringify(o.refus.corps)).to.equal('{"error":{"message":"noortrace: corps de requete trop grand","type":"invalid_request_error","param":null,"code":"noortrace_taille"}}');
    expect(m.journal[0]).to.deep.equal({ event: "model_request_refused", data: { reason: "taille", length: 20, content_type: null } });
    const hors = C.echangeModele({ format: "gemini", provider_label: "gemini", segment: "m", requete: requeteOK, reponse: reponseOK, responseMaxBytes: 10, politique: PII });
    expect([hors.pieces.reponse.valeur, hors.is_error]).to.deep.equal([{ noortrace_non_redigeable: { content_type: "application/json; charset=UTF-8", length: reponseOK.corps.length, reason: "taille" } }, true]);
    expect(hors.journal).to.deep.include({ event: "model_response_truncated", data: { received_bytes: reponseOK.corps.length } });
    const flux = Buffer.from(`data: ${JSON.stringify({ candidates: [{ content: { parts: [{ text: "a" }] } }] })}\n\ndata: ${JSON.stringify({ candidates: [{ finishReason: "STOP" }] })}\n\n`);
    const coupe = C.echangeModele({ format: "gemini", provider_label: "gemini", segment: "m", requete: requeteOK, reponse: { status: 200, content_type: "text/event-stream", corps: flux }, responseMaxBytes: flux.indexOf("\n\n") + 2 });
    expect([coupe.consolidated.noortrace_flux_incomplet, coupe.is_error, coupe.incomplete]).to.deep.equal([true, true, true]);
    // Capture arrêtée à la borne (EX-5.33) : le finishReason du second événement n'est pas lu, la pièce ne contient pas la suite.
    expect(coupe.consolidated.candidates[0].finishReason).to.equal(undefined);
    expect(coupe.pieces.reponse.octets.toString("utf8")).to.not.include("STOP");
    // Un flux Anthropic terminé avant la borne mais tronqué reste marqué incomplet.
    const sse = Buffer.from('event: message_start\ndata: {"type":"message_start","message":{"model":"m","content":[]}}\n\nevent: message_stop\ndata: {"type":"message_stop"}\n\n: fin\n\n');
    const a = C.echangeModele({ format: "anthropic-messages", provider_label: "a", requete: { corps: corpsJSON({ model: "m", max_tokens: 1, messages: [] }) }, reponse: { status: 200, content_type: "text/event-stream", corps: sse }, responseMaxBytes: sse.length - 4 });
    expect([a.consolidated.noortrace_flux_incomplet, a.is_error]).to.deep.equal([true, true]);
  });

  it("EX-5.34 : data final sans ligne vide distribué pour gemini seulement, compté ; une dernière ligne sans fin de ligne est d'abord lue (comme le SDK Python)", function () {
    const brut = Buffer.from('data: {"a":1}\n\ndata: {"b":2}\n');
    expect(C.analyserSSE(brut).evenements.map((e) => e.data)).to.deep.equal(['{"a":1}']);
    const g = C.analyserSSE(brut, { distribuerDataFinal: true });
    expect([g.evenements.map((e) => e.data), g.dataFinal]).to.deep.equal([['{"a":1}', '{"b":2}'], 1]);
    // Dernière ligne sans fin de ligne : lue, puis le tampon distribué ; sans distribuerDataFinal (autres formats), abandonnée.
    expect(C.analyserSSE(Buffer.from('data: {"a":1}\n\ndata: {"b":2}'), { distribuerDataFinal: true }).evenements.map((e) => e.data)).to.deep.equal(['{"a":1}', '{"b":2}']);
    expect(C.analyserSSE(Buffer.from('data: {"a":1}\n\ndata: {"b":2}')).evenements.map((e) => e.data)).to.deep.equal(['{"a":1}']);
    expect(C.analyserSSE(Buffer.from('data: {"a":1}\r\ndata: {"b"'), { distribuerDataFinal: true }).evenements.map((e) => e.data)).to.deep.equal(['{"a":1}\n{"b"']);
    const c = C.consoliderFlux("gemini", Buffer.from(`data: ${JSON.stringify({ candidates: [{ content: { parts: [{ text: "x" }] }, finishReason: "STOP" }] })}\r\n`));
    expect([c.dataFinal, c.is_error, c.forme.candidates[0].content.parts]).to.deep.equal([1, false, [{ text: "x" }]]);
    const r = C.echangeModele({ format: "gemini", provider_label: "gemini", segment: "m", requete: requeteOK, reponse: { status: 200, content_type: "text/event-stream", corps: Buffer.from(`data: ${JSON.stringify({ candidates: [{ content: { parts: [{ text: "x" }] }, finishReason: "STOP" }] })}`) } });
    expect(r.journal.some((l) => l.event === "sse_data_final_sans_ligne_vide")).to.equal(true);
    expect([r.is_error, r.incomplete, r.intent]).to.deep.equal([false, false, "x"]);
  });

  it("EX-5.35 : consoliderGemini (index, parts, content, morceau d'erreur, promptFeedback, aucun morceau)", function () {
    const d = (o) => ({ data: typeof o === "string" ? o : JSON.stringify(o) });
    const fin = { candidates: [{ finishReason: "STOP" }] };
    const g = (...evs) => C.consoliderGemini(evs);
    // Index chaîne "0" ignoré, compté ; 2^53 + 2 ignoré ; 2^53 + 1 se lit 2^53 en double précision (JCS intégral) et est admis.
    let c = g(d({ candidates: [{ index: "0", content: { parts: [{ text: "x" }] } }] }), d(fin));
    expect([c.ignores, c.forme.candidates.length, c.forme.candidates[0].content.parts]).to.deep.equal([1, 1, []]);
    c = g(d('{"candidates":[{"index":9007199254740994,"finishReason":"STOP"}]}'));
    expect([c.ignores, c.forme.candidates, c.incomplet]).to.deep.equal([1, undefined, true]);
    c = g(d('{"candidates":[{"index":9007199254740993,"finishReason":"STOP"}]}'));
    expect(c.forme.candidates[0].index).to.equal(2 ** 53);
    c = g(d({ candidates: [{ index: -1, finishReason: "STOP" }, { index: 1.5 }] }));
    expect(c.ignores).to.equal(2);
    // parts non tableau, content non objet, élément de parts non objet : ignorés et comptés.
    c = g(d({ candidates: [{ content: { parts: { text: "x" }, role: "model" } }, { content: "texte" }, { content: { parts: ["a", { text: "b" }] } }] }), d(fin));
    expect([c.ignores, c.forme.candidates[0].content]).to.deep.equal([3, { parts: [{ text: "b" }], role: "model" }]);
    // Candidats créés dans l'ordre de première apparition ; autres membres remplacés ; membres de premier niveau : le dernier l'emporte.
    c = g(d({ candidates: [{ index: 1, content: { parts: [{ text: "u" }] } }], modelVersion: "a" }), d({ candidates: [{ content: { parts: [{ text: "z" }] }, finishReason: "STOP" }], modelVersion: "b", responseId: "r" }));
    expect([c.forme.candidates.map((k) => k.index), c.forme.modelVersion, c.forme.responseId, c.is_error]).to.deep.equal([[1, 0], "b", "r", false]);
    expect(C.extraireIntention("gemini", c.forme)).to.equal("u");
    // Morceau d'erreur en premier : forme réduite ; ce qui suit est ignoré.
    c = g(d({ error: { code: 503, message: "x", status: "UNAVAILABLE" } }), d(fin));
    expect([c.forme, c.is_error, c.ignores]).to.deep.equal([{ noortrace_erreur_flux: { code: 503, message: "x", status: "UNAVAILABLE" } }, true, 1]);
    // promptFeedback seul : fin normale ; sans rien : incomplet ; aucun morceau valide : pas de forme.
    c = g(d({ promptFeedback: { blockReason: "SAFETY" } }));
    expect([c.forme.noortrace_flux_incomplet, c.is_error, c.forme.candidates]).to.deep.equal([undefined, false, undefined]);
    c = g(d({ usageMetadata: { totalTokenCount: 1 } }));
    expect([c.forme.noortrace_flux_incomplet, c.is_error]).to.deep.equal([true, true]);
    expect(g(d("pas du json"), d("[1]")).forme).to.equal(null);
    // finishReason vide : non terminé ; corps coupé : incomplet malgré finishReason.
    expect(g(d({ candidates: [{ finishReason: "" }] })).incomplet).to.equal(true);
    expect(C.consoliderGemini([d(fin)], { finNormale: false }).incomplet).to.equal(true);
  });

  it("5.4.5 : l'exemple (transcription et forme consolidée) est recalculé à l'identique, avec ses valeurs tirées", function () {
    const sec = section("#### 5.4.5 Gemini", "**EX-5.18**");
    const transcription = /```text\n([\s\S]*?)```/.exec(sec)[1];
    const forme = JSON.parse(/Forme consolidée[\s\S]*?```json\n([\s\S]*?)\n```/.exec(sec)[1]);
    const c = C.consoliderFlux("gemini", Buffer.from(transcription, "utf8"));
    expect(jcs(c.forme)).to.equal(jcs(forme));
    expect([c.is_error, c.dataFinal]).to.deep.equal([false, 0]);
    expect(C.extraireIntention("gemini", c.forme)).to.equal("Je consulte le sinistre 2026-81044.");
    expect(C.extraireAppelsOutils("gemini", c.forme)).to.deep.equal([{ id: null, name: "demo__claims_get", arguments: { claim_id: "2026-81044" }, position: 2 }]);
    expect(C.codeModeleGemini("gemini", c.forme, "gemini-exemple").code_model).to.equal("gemini/gemini-exemple-001");
    const premier = transcription.split("\n\n")[0] + "\n\n";
    expect(C.consoliderFlux("gemini", Buffer.from(premier)).forme.noortrace_flux_incomplet).to.equal(true);
  });

  it("5.5, EX-8.5 : prompt système, remplacement et rédaction en place limités à systemInstruction.parts ; intent sans séparateur hors thought", function () {
    const corps = { contents: [], systemInstruction: { role: "system", parts: [{ text: "A" }, { inlineData: { data: "AA==" } }, { text: "B" }] } };
    expect(C.extrairePromptSysteme("gemini", corps)).to.equal("A\nB");
    expect(C.remplacerPromptSysteme("gemini", corps).systemInstruction).to.deep.equal({ role: "system", parts: [{ text: "[REDIGE:prompt-systeme]" }] });
    expect(C.extrairePromptSysteme("gemini", { contents: [], systemInstruction: "texte" })).to.equal(null);
    expect(C.remplacerPromptSysteme("gemini", { contents: [], systemInstruction: { parts: "x" } }).systemInstruction).to.deep.equal({ parts: "x" });
    expect(C.redigerPromptEnPlace("gemini", { contents: [], systemInstruction: { parts: [{ text: "écrire à a.b@exemple.ch" }] } }, PII).systemInstruction.parts[0].text).to.equal("écrire à [REDIGE:email]");
    expect(C.requeteDeForme("gemini", { contents: [] })).to.equal(true);
    expect(C.requeteDeForme("gemini", { contents: {} })).to.equal(false);
    const rep = { candidates: [{ content: { parts: [{ text: "pensée", thought: true }, { text: "Bon" }, { text: "jour" }, { functionCall: { name: "f" } }, { text: "après" }] } }] };
    expect(C.extraireIntention("gemini", rep)).to.equal("Bonjourapres".replace("apres", "après"));
    expect(C.texteAvantAppel("gemini", rep, 3)).to.equal("Bonjour");
    expect(C.extraireAppelsOutils("gemini", rep)).to.deep.equal([{ id: null, name: "f", arguments: {}, position: 3 }]);
    expect(C.extraireIntention("gemini", { candidates: [{ content: { parts: [{ text: "" }] } }] })).to.equal(null);
  });

  it("EX-5.36 : code.model = modelVersion, sinon segment s'il passe les détecteurs de la politique (contrôle d'EX-7.2), sinon null ; jamais le membre model du corps", function () {
    expect(C.codeModeleGemini("gemini", { modelVersion: "v-1" }, "s").code_model).to.equal("gemini/v-1");
    expect(C.codeModeleGemini("gemini", { modelVersion: "" }, "s").code_model).to.equal("gemini/s");
    expect(C.codeModeleGemini("gemini", null, "m-4111111111111111", { politique: PII })).to.deep.equal({ code_model: null, segment_refuse: true });
    expect(C.codeModeleGemini("gemini", null, "m-4111111111111111", { politique: null }).code_model).to.equal("gemini/m-4111111111111111");
    expect(C.codeModeleGemini("x".repeat(32), { modelVersion: "y".repeat(300) }, null).code_model).to.have.length(256);
    const r = C.echangeGemini({ method: "POST", target: "/v1beta/models/m-4111111111111111:generateContent", routes: ROUTES, requete: { corps: corpsJSON({ model: "models/autre", contents: [] }) }, reponse: { status: 500, content_type: "application/json", corps: corpsJSON({ error: { code: 500 } }) }, politique: PII });
    expect([r.code_model, r.segment_refuse]).to.deep.equal([null, true]);
    expect(JSON.stringify(r.journal)).to.not.include("4111111111111111");
    const s = C.echangeGemini({ method: "POST", target: "/v1beta/models/m:generateContent", routes: ROUTES, requete: { corps: corpsJSON({ model: "models/autre", contents: [] }) }, reponse: { status: 200, content_type: "application/json", corps: corpsJSON({ candidates: [] }) }, politique: PII });
    expect(s.code_model).to.equal("gemini/m");
  });

  it("EX-5.22 : corrélation Gemini sur args objet ({} si absent), un args non objet ne correspond jamais, une part functionCall consommée une fois", function () {
    const forme = { candidates: [{ content: { parts: [{ text: "Je regarde." }, { functionCall: { name: "demo__claims_get" } }, { functionCall: { name: "demo__claims_get", args: "{}" } }, { functionCall: { name: "demo__claims_get", args: { claim_id: "1" } } }] } }] };
    const ech = [{ seq: 4, t: 1000, run_id: null, groupe: "g", format: "gemini", forme, forme_redigee: forme }];
    const appel = (args) => ({ tool_announced: "demo__claims_get", arguments: args, t_recu: 1500, run_id: null, groupe: "g" });
    const a = C.correler(appel({}), ech);
    expect([a.echange.seq, a.appel.position, a.texte]).to.deep.equal([4, 1, "Je regarde."]);
    expect(C.correler(appel({}), ech).echange).to.equal(null);
    expect(C.correler(appel({ claim_id: "1" }), ech).appel.position).to.equal(3);
  });

  it("EX-6.8 : echangeModele du SDK au format gemini (objet, tableau, tableau vide, statut ≥ 400, membres du SDK retirés, repli de code.model sur request.model)", function () {
    const sdk = (response, extra = {}) => C.echangeModeleSDKGemini({ provider_label: "gemini", request: { model: "models/gemini-exemple", contents: [{ role: "user", parts: [{ text: "x" }] }] }, response, status: 200, politique: PII, ...extra });
    const objet = sdk({ candidates: [{ content: { parts: [{ text: "ok" }] }, finishReason: "STOP" }], sdkHttpResponse: { headers: {} }, parsed: null, automaticFunctionCallingHistory: [] });
    expect([objet.removed_members, objet.consolidated, objet.code_model, objet.intent, objet.is_error]).to.deep.equal([["sdkHttpResponse", "automaticFunctionCallingHistory", "parsed"], null, "gemini/gemini-exemple", "ok", false]);
    expect(objet.journal.filter((l) => l.event === "sdk_member_removed").map((l) => l.data.member)).to.deep.equal(["sdkHttpResponse", "automaticFunctionCallingHistory", "parsed"]);
    const vide = sdk([]);
    expect([vide.consolidated, vide.is_error, vide.incomplete]).to.deep.equal([{ noortrace_flux_incomplet: true }, true, true]);
    const erreur = sdk({ error: { code: 429, message: "quota", status: "RESOURCE_EXHAUSTED" } }, { status: 429 });
    expect([erreur.pieces.reponse.valeur, erreur.is_error, erreur.code_model]).to.deep.equal([{ noortrace_http_error: { status: 429, content_type: null, body: { error: { code: 429, message: "quota", status: "RESOURCE_EXHAUSTED" } } } }, true, "gemini/gemini-exemple"]);
    const sansModele = C.echangeModeleSDKGemini({ provider_label: "gemini", request: { model: "models/Avec Espace", contents: [] }, response: { candidates: [] }, status: 200 });
    expect(sansModele.code_model).to.equal(null);
    // L'exemple de paramètres d'EX-6.8.
    const p = JSON.parse(/```json\n([\s\S]*?)\n```/.exec(section("**EX-6.8**", "### 6.3 Limites"))[1]);
    const ex = C.echangeModeleSDKGemini({ provider_label: p.provider_label, request: p.request, response: p.response, status: p.status, is_error: p.is_error, politique: PII });
    expect([ex.intent, ex.code_model, ex.is_error, ex.consolidated.candidates[0].content.parts.length]).to.deep.equal(["Je consulte le sinistre.", "gemini/gemini-exemple-001", false, 2]);
  });

  it("schéma de configuration : model_route gemini (bloc annoté de 15.3), auth_header imposé, provider_mcp réservé à gemini ; mots-clés dans le sous-ensemble appliqué", function () {
    const config = SCHEMAS[ID_CONFIG];
    const route = C.analyserJSONIntegral(blocs("configuration-enregistreur/model_route")[0]);
    expect(J.validerSchema(route, config, { registre: SCHEMAS, fragment: "#/$defs/model_route" })).to.deep.equal([]);
    const avecRoute = C.copieJSON(CONFIG);
    avecRoute.policy.model.routes = avecRoute.policy.model.routes.filter((r) => r.format !== "gemini").concat([route]);
    expect(J.validerSchema(avecRoute, config, { registre: SCHEMAS })).to.deep.equal([]);
    expect(J.validerSchema({ ...route, auth_header: "x-api-key" }, config, { registre: SCHEMAS, fragment: "#/$defs/model_route" })).to.not.deep.equal([]);
    const anthropic = CONFIG.policy.model.routes.find((r) => r.format === "anthropic-messages");
    expect(J.validerSchema({ ...anthropic, provider_mcp: "refuser" }, config, { registre: SCHEMAS, fragment: "#/$defs/model_route" })).to.not.deep.equal([]);
    expect(J.validerSchema(anthropic, config, { registre: SCHEMAS, fragment: "#/$defs/model_route" })).to.deep.equal([]);
    for (const id of [ID_CONFIG, ID_WORM, ID_COUT]) expect(J.motsClesHorsSousEnsemble(SCHEMAS[id]), id).to.deep.equal([]);
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 révision 0.5 : contrôles de démarrage ajoutés (EX-15.4 pas 3 : otel, policy.sdk, routes gemini, support WORM)", function () {
  const controle = (mutation) => {
    const c = C.copieJSON(CONFIG);
    mutation(c);
    return C.controlesConfigurationRevision05(c);
  };
  const erreurs = (m) => controle(m).erreurs.join(" | ");

  it("l'exemple de 15.3 passe les contrôles sans erreur ni avertissement, y compris par AP.controlesConfiguration", function () {
    expect(C.controlesConfigurationRevision05(CONFIG)).to.deep.equal({ erreurs: [], avertissements: [] });
    expect(AP.controlesConfiguration(CONFIG, { schemas: SCHEMAS })).to.deep.equal({ erreurs: [], avertissements: [] });
  });

  it("un cas refusé par règle (otel, policy.otel, policy.sdk, routes, WORM) et les avertissements nommés", function () {
    expect(erreurs((c) => delete c.policy.otel)).to.include("/policy/otel : membre obligatoire");
    expect(erreurs((c) => (c.otel.hosts[0].match.static_token = "inconnu"))).to.include("/otel/hosts/0/match/static_token");
    expect(erreurs((c) => c.otel.hosts.push({ ...c.otel.hosts[0], id: "bis" }))).to.include("jeton déjà référencé");
    expect(erreurs((c) => (c.otel.hosts[0].alias = null))).to.include("/otel/hosts/0/alias : alias non nul");
    expect(erreurs((c) => (c.otel.hosts[0].alias = "sap"))).to.include("distinct des alias de serveurs");
    expect(erreurs((c) => (c.policy.otel.sources = { autre: c.policy.otel.sources["otel-sinistres"] }))).to.include("doit être une clé de policy.otel.sources");
    expect(erreurs((c) => (c.policy.otel.sources.orpheline = c.policy.otel.sources["otel-sinistres"]))).to.include("/policy/otel/sources/orpheline : aucune entrée");
    expect(erreurs((c) => (c.otel.hosts[0].launched_by = "${peer_user}"))).to.include("valeur fixe exigée");
    expect(erreurs((c) => (c.otel.hosts[0].allowed_on_behalf_of = ["x"]))).to.include("doit être vide");
    expect(erreurs((c) => (c.otel.listen = "0.0.0.0:4318"))).to.include("/otel/tls");
    expect(erreurs((c) => (c.otel.listen = "[::1]:4318"))).to.equal("");
    expect(controle((c) => (c.policy.otel.sources["otel-sinistres"].overlap = "conserver")).avertissements.join()).to.include("conserver");
    expect(controle((c) => (c.otel.encodings = ["json"])).avertissements.join()).to.include("/otel/encodings");
    expect(controle((c) => (c.otel.enabled = false)).avertissements).to.deep.equal(["/policy/otel : présent sans otel activé (EX-15.4)"]);
    expect(erreurs((c) => (c.policy.sdk = { aliases: ["agent-local"] }))).to.include("/policy/sdk/aliases");
    expect(controle((c) => (c.sdk.enabled = true)).avertissements.join()).to.include("/policy/sdk : absent");
    const routeGemini = (c) => c.policy.model.routes.find((r) => r.format === "gemini");
    expect(erreurs((c) => (routeGemini(c).path = "/v1beta/modeles"))).to.include("se termine par /models");
    expect(controle((c) => (routeGemini(c).path = "/v2/models")).avertissements.join()).to.include("ni /v1beta/models ni /v1/models");
    expect(controle((c) => (routeGemini(c).provider_mcp = "relayer")).avertissements.join()).to.include("route /v1beta/models");
    expect(erreurs((c) => (c.policy.model.routes[0].provider_mcp = "refuser"))).to.include("réservé aux routes gemini");
    expect(erreurs((c) => c.policy.model.routes.push({ ...c.policy.model.routes[0] }))).to.include("chemin en double");
    expect(erreurs((c) => (c.storage.seal.worm.mode = "governance"))).to.include("compliance exigé en production");
    expect(erreurs((c) => Object.assign(c.storage.seal.worm, { type: "azure-immutable-blob", endpoint: null }))).to.include("obligatoire pour azure-immutable-blob");
    expect(erreurs((c) => Object.assign(c.storage.seal.worm, { type: "gcs-object-retention", endpoint: "https://stockage.exemple" }))).to.include("doit être nul pour gcs-object-retention");
    expect(erreurs((c) => Object.assign(c.storage.seal.worm, { type: "gcs-object-retention", legal_hold_on_write: true }))).to.include("seulement avec s3-object-lock");
    expect(erreurs((c) => (c.storage.seal.worm.legal_hold_on_write = true))).to.include("refusé en production");
    expect(erreurs((c) => Object.assign(c.storage.seal.worm, { type: "gcs-object-retention", endpoint: null }))).to.include("n'est pas admis en production");
    // EX-15.4 pas 3 : retain_days ≥ 365 × events_years, avertissement sous 365 × (events_years + 1).
    expect(erreurs((c) => (c.storage.seal.worm.retain_days = 30))).to.include("/storage/seal/worm/retain_days : au moins 365 × events_years = 3650 jours");
    expect(erreurs((c) => (c.storage.seal.worm.retain_days = 3649))).to.include("/storage/seal/worm/retain_days");
    expect(controle((c) => (c.storage.seal.worm.retain_days = 3650)).avertissements.join()).to.include("inférieur à 365 × (events_years + 1) = 4015 jours");
    expect(controle((c) => (c.storage.retention.events_years = 11)).avertissements.join()).to.include("4380 jours");
    // EX-5.32, EX-15.4 : provider_cache et passthrough de création de cache ou de téléversement.
    expect(controle((c) => (routeGemini(c).provider_cache = "relayer")).avertissements.join()).to.include("/provider_cache");
    expect(erreurs((c) => (routeGemini(c).passthrough = [{ method: "POST", path: "/v1beta/cachedContents" }]))).to.include("création de contenu en cache");
    expect(erreurs((c) => (routeGemini(c).passthrough = [{ method: "POST", path: "/upload/v1beta/files" }]))).to.include("création de contenu en cache");
    expect(erreurs((c) => (routeGemini(c).passthrough = [{ method: "GET", path: "/v1beta/cachedContents" }]))).to.equal("");
    expect(erreurs((c) => (c.policy.model.routes[0].provider_cache = "refuser"))).to.include("réservé aux routes gemini");
    expect(controle((c) => (c.storage.seal.worm.credentials = c.policy.model.routes[0].secret)).avertissements.join()).to.include("/storage/seal/worm/credentials : même référence que /policy/model/routes/0/secret");
  });

  it("schéma : fragment worm de 15.3 valide ; Azure sans endpoint, GCS avec endpoint non nul ou legal_hold_on_write refusés", function () {
    const config = SCHEMAS[ID_CONFIG];
    const fragment = C.analyserJSONIntegral(blocs("configuration-enregistreur/worm")[0]);
    expect(J.validerSchema(fragment, config, { registre: SCHEMAS, fragment: "#/$defs/worm" })).to.deep.equal([]);
    const c = C.copieJSON(CONFIG);
    c.storage.seal.worm = fragment;
    expect(J.validerSchema(c, config, { registre: SCHEMAS })).to.deep.equal([]);
    const v = (w) => J.validerSchema(w, config, { registre: SCHEMAS, fragment: "#/$defs/worm" });
    expect(v({ ...fragment, type: "azure-immutable-blob", endpoint: null })).to.not.deep.equal([]);
    expect(v({ ...fragment, type: "gcs-object-retention", endpoint: "https://stockage.exemple", legal_hold_on_write: false })).to.not.deep.equal([]);
    expect(v({ ...fragment, type: "gcs-object-retention", endpoint: null, legal_hold_on_write: true })).to.not.deep.equal([]);
    expect(v({ ...fragment, type: "gcs-object-retention", endpoint: null, legal_hold_on_write: false })).to.deep.equal([]);
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 révision 0.5 : ingestion OpenTelemetry (6.8, EX-6.25 à EX-6.41)", function () {
  this.timeout(120_000);
  const CAS = fs.readdirSync(path.join(VECTEURS, "otel")).sort();
  /** Rejoue un cas otel/ : rend le résultat de traiterRequete, les événements scellés et l'attendu. */
  function rejouer(nom) {
    const source = lireJSON("otel", nom, "source.json");
    const entetes = lireJSON("otel", nom, "requete-entetes.json");
    const fichier = ["requete.json", "requete.pb", "requete.brut"].find((f) => existe("otel", nom, f));
    const tR = J.msHorodatage(source.t_reception);
    const doublons = new OT.TableDoublons({ fenetreMs: source.options.dedup_window_ms });
    for (const s of source.seen) doublons.ajouter(OT.TableDoublons.cle(source.alias, s.trace_id, s.span_id), J.msHorodatage(s.at));
    const recouvrement = new OT.RegistreRecouvrement(source.recorded.map((e) => ({ ...e, t: J.msHorodatage(e.t) })), { fenetreMs: source.options.overlap_window_ms });
    const politique = { "pii-v1": PII }[source.redaction];
    const r = OT.traiterRequete({ methode: entetes.method, chemin: entetes.path, entetes, corps: fs.readFileSync(path.join(VECTEURS, "otel", nom, fichier)) }, { source: { alias: source.alias, host: source.host, policy_source: source.policy_source, policy_version: source.policy_version }, jeton: source.host.id, options: source.options, politique, t_reception: tR, doublons, recouvrement });
    const evenements = OT.scellerPartiels(r.partiels, { ...source.chain, org_id: ORG_ID, journal_id: JOURNAL_ID, recorder_key_id: "rec-test-01", cle: CLE_01.clePrivee });
    return { r, evenements, at: lireJSON("otel", nom, "attendu.json"), source };
  }
  const piecesDe = (s) => (s.pieces === null ? null : s.sorte === "outil" ? { source: avecOctets(s.pieces.source), envelope: avecOctets(s.pieces.envelope), arguments: avecOctets(s.pieces.arguments), result: avecOctets(s.pieces.result), system_prompt: null, intent: null } : { source: avecOctets(s.pieces.source), envelope: avecOctets(s.pieces.envelope), request: avecOctets(s.pieces.request), response: avecOctets(s.pieces.response), system_prompt: avecOctets(s.pieces.system_prompt), intent: avecOctets(s.pieces.intent) });

  it("otel/ : les 48 cas de l'annexe B.8 rejoués (statut, réponse octet pour octet, issues, formes normalisées, pièces, événements, chaîne, E-1 à E-11, lag_ms)", function () {
    expect(CAS).to.have.length(48);
    const cles = { "rec-test-01": CLE_01.clePublique };
    for (const nom of CAS) {
      const { r, evenements, at, source } = rejouer(nom);
      expect([r.status, r.contentType, r.retryAfter, r.rejetes, r.compteurs], nom).to.deep.equal([at.status, at.response.content_type, at.response.retry_after, at.rejected_spans, at.counts]);
      if (at.response.body_hex !== undefined) expect(r.corps.toString("hex"), nom).to.equal(at.response.body_hex);
      else expect(r.corps.toString("utf8"), nom).to.equal(JSON.stringify(at.response.body_json));
      expect(r.spans.length, nom).to.equal(at.spans.length);
      let e = 0;
      r.spans.forEach((s, i) => {
        const a = at.spans[i];
        expect([s.path, s.trace_id, s.span_id, s.issue, s.overlap_seq], `${nom} #${i}`).to.deep.equal([a.path, a.trace_id, a.span_id, a.issue, a.overlap_seq]);
        expect(s.issue === "ignore" || s.issue === "rejete" ? s.reason : null, `${nom} #${i} raison`).to.equal(a.reason);
        expect(jcs(s.normalized), `${nom} #${i} forme normalisée`).to.equal(jcs(a.normalized));
        expect(piecesDe(s), `${nom} #${i} pièces`).to.deep.equal(a.pieces);
        const ev = s.issue === "scelle" ? evenements[e++] : null;
        expect(J.canonicaliserJCS(ev), `${nom} #${i} événement`).to.equal(J.canonicaliserJCS(a.event));
        expect(ev ? OT.retardReception(ev.ts, s.normalized) : null, `${nom} #${i} lag_ms`).to.equal(a.lag_ms);
        if (ev) {
          expect(Object.entries(J.controlesEvenement(ev, { schemas: SCHEMAS, cles })).filter(([, x]) => x.ok === false), `${nom} #${i} E-1 à E-11`).to.deep.equal([]);
          expect(J.validerSchema(ev, SCHEMAS[J.ID_SCHEMA_EVENEMENT], { registre: SCHEMAS }), nom).to.deep.equal([]);
          expect(J.verifierSignatureEvenement(ev, CLE_01.clePublique), nom).to.equal(true);
          // EX-6.36 : ts de l'écrivain (chain.ts), jamais un horodatage du span ; contexte de deux références, la déclaration de source en tête.
          expect(ev.ts, nom).to.equal(source.chain.ts[e - 1]);
          expect([ev.context.length, ev.context[0].sha256], nom).to.deep.equal([2, OT.pieceDeclarationSource(source.alias).reference.sha256]);
          expect(ev.execution.tool === J.OUTIL_MODELE || ev.execution.tool.startsWith(`${source.alias}__`), nom).to.equal(true);
          expect(ev.policy.decision, nom).to.equal(ev.execution.tool === J.OUTIL_MODELE ? "sans_objet" : "autorise");
        }
      });
      // Chaîne propre au cas (annexe B.8) : seq consécutifs depuis seq_start, prev_hash du premier = celui de source.json, puis le hash du précédent.
      evenements.forEach((ev, k) => {
        expect([ev.seq, ev.prev_hash], `${nom} chaîne`).to.deep.equal([source.chain.seq_start + k, k === 0 ? source.chain.prev_hash : evenements[k - 1].hash]);
        expect(J.verifierHachageEvenement(ev), nom).to.equal(true);
      });
      // CT-1 C-1 à C-3 sans filtre : aucun fragment ne commence à seq 1, que C-2 réserve au prev_hash nul.
      if (evenements.length) {
        expect(evenements[0].seq, nom).to.be.greaterThan(1);
        expect(J.verifierChaine(evenements, { clesPubliques: cles }).diagnostics, nom).to.deep.equal([]);
      }
      // EX-6.35 : les horodatages et identifiants de la pièce d'enveloppe restent lisibles, même quand ils passent Luhn.
      at.spans.forEach((a, i) => {
        if (!a.pieces) return;
        const env = JSON.parse(a.pieces.envelope.bytes);
        for (const k of ["trace_id", "span_id", "parent_span_id", "start_time_unix_nano", "end_time_unix_nano", "flags", "kind"]) expect(env[k], `${nom} #${i} enveloppe ${k}`).to.equal(a.normalized[k]);
      });
    }
  });

  it("6.8.16 : l'exemple calculé du texte de CT-2 (deux événements, huit pièces de la table) est égal aux vecteurs JSON et protobuf", function () {
    const sec = section("#### 6.8.16 Exemple calculé", "## 7. Construction");
    const evenements = [...sec.matchAll(/<!-- schema: evenement -->\n```json\n([\s\S]*?)\n```/g)].map((m) => JSON.parse(m[1]));
    const table = [...sec.matchAll(/^\| [^|]+ \| `(0x[0-9a-f]{64})` \| ([0-9]+) \| `(true|false)` \| (?:`([^`]+)`|—) \| `(.*)` \|$/gm)];
    expect([evenements.length, table.length]).to.deep.equal([2, 8]);
    expect(Buffer.from(/```json\n([\s\S]*?)\n```/.exec(sec)[1] + "\n", "utf8").equals(fs.readFileSync(path.join(VECTEURS, "otel", "json-exemple-6-8-16", "requete.json")))).to.equal(true);
    for (const nom of ["json-exemple-6-8-16", "pb-exemple-6-8-16"]) {
      const at = lireJSON("otel", nom, "attendu.json");
      expect(J.canonicaliserJCS(at.spans.map((s) => s.event)), nom).to.equal(J.canonicaliserJCS(evenements));
      const pieces = at.spans.flatMap((s) => Object.values(s.pieces)).filter(Boolean);
      for (const [, sha, length, redacted, media, bytes] of table) {
        const p = pieces.find((x) => x.sha256 === sha);
        expect([p.length, p.redacted, p.media_type ?? null, p.bytes], sha).to.deep.equal([Number(length), redacted === "true", media ?? null, bytes]);
        expect(J.sha256(Buffer.from(bytes, "utf8")), sha).to.equal(sha);
      }
    }
    expect(OT.pieceDeclarationSource("otel-sinistres").octets.length).to.equal(66);
  });

  it("paires JSON / protobuf : mêmes formes normalisées, pièces et événements ; l'encodeur redonne les octets de requete.pb", function () {
    for (const [j, p] of [["json-exemple-6-8-16", "pb-exemple-6-8-16"], ["json-identifiants-invalides", "pb-identifiants-invalides"]]) {
      const a = lireJSON("otel", j, "attendu.json");
      const b = lireJSON("otel", p, "attendu.json");
      expect(jcs(b.spans.map((s) => [s.normalized, s.pieces, s.event])), p).to.equal(jcs(a.spans.map((s) => [s.normalized, s.pieces, s.event])));
      const logique = OT.decoderJSON(fs.readFileSync(path.join(VECTEURS, "otel", j, "requete.json")));
      expect(OT.encoderProtobuf(logique).equals(fs.readFileSync(path.join(VECTEURS, "otel", p, "requete.pb"))), p).to.equal(true);
      const relu = OT.decoderProtobuf(fs.readFileSync(path.join(VECTEURS, "otel", p, "requete.pb")));
      const sansPresence = (v) => JSON.stringify(v, (k, x) => (k === "keyPresent" ? undefined : typeof x === "bigint" ? x.toString() : x));
      expect(sansPresence(relu), p).to.equal(sansPresence(logique));
    }
  });

  it("EX-6.29 : décodage JSON strict (nombres sur leur texte, hexadécimal, énumérations en nombre, oneof, base64, bornes)", function () {
    const span = (s) => Buffer.from(JSON.stringify({ resourceSpans: [{ scopeSpans: [{ spans: [{ traceId: "5b8efff798038103d269b633813fc60c", spanId: "eee19b7ec3c1b174", name: "n", ...s }] }] }] }));
    const ok = (s) => OT.decoderJSON(span(s)).resourceSpans[0].scopeSpans[0].spans[0];
    const ko = (s) => expect(() => OT.decoderJSON(span(s)), JSON.stringify(s)).to.throw(OT.ErreurOTLP);
    expect(ok({ startTimeUnixNano: "18446744073709551615" }).startTimeUnixNano).to.equal(2n ** 64n - 1n);
    ko({ startTimeUnixNano: "18446744073709551616" });
    ko({ startTimeUnixNano: "-1" });
    ko({ startTimeUnixNano: "01" });
    ko({ kind: "SPAN_KIND_CLIENT" });
    ko({ kind: "1" });
    ko({ status: { code: "STATUS_CODE_ERROR" } });
    expect(ok({ droppedAttributesCount: "7" }).droppedAttributesCount).to.equal(7);
    ko({ droppedAttributesCount: 4294967296 });
    ko({ traceId: "5b8" });
    ko({ name: 5 });
    ko({ attributes: {} });
    ko({ status: [] });
    const attr = (value) => ok({ attributes: [{ key: "k", value }] }).attributes[0].value;
    expect(attr({ intValue: "-9223372036854775808" }).value).to.equal(-(2n ** 63n));
    expect(() => attr({ intValue: "9223372036854775808" })).to.throw(OT.ErreurOTLP);
    expect(() => attr({ stringValue: "a", intValue: 1 })).to.throw(OT.ErreurOTLP);
    expect(() => attr({ stringValue: "a", stringValueStrindex: 1 })).to.throw(OT.ErreurOTLP);
    expect(attr({ stringValue: "a", intValue: null }).value).to.equal("a");
    expect(attr({ bytesValue: "_-8" }).value).to.deep.equal(Buffer.from([0xff, 0xef]));
    expect(() => attr({ bytesValue: "a" })).to.throw(OT.ErreurOTLP);
    expect(() => attr({ doubleValue: "nan" })).to.throw(OT.ErreurOTLP);
    expect(() => OT.decoderJSON(Buffer.from('{"resourceSpans":[{"scopeSpans":[{"spans":[{"attributes":[{"key":"k","value":{"doubleValue":1e400}}]}]}]}]}'))).to.throw(OT.ErreurOTLP);
    expect(() => OT.decoderJSON(Buffer.from('{"resourceSpans":[],"resourceSpans":[]}'))).to.throw(OT.ErreurOTLP);
    expect(() => OT.decoderJSON(Buffer.from("﻿{}"))).to.throw(OT.ErreurOTLP);
    const profond = (n) => (n === 0 ? { stringValue: "x" } : { arrayValue: { values: [profond(n - 1)] } });
    expect(() => OT.decoderJSON(span({ attributes: [{ key: "k", value: profond(5) }] }), { profondeurMax: 4 })).to.throw(OT.ErreurOTLP);
  });

  it("EX-6.30 : décodage protobuf écrit à la main (types de fil, étiquette 0, varint, champ en double, oneof, UTF-8, booléen)", function () {
    const pb = (hex) => () => OT.decoderProtobuf(Buffer.from(hex, "hex"));
    expect(pb("")().resourceSpans).to.deep.equal([]);
    expect(pb("0b")).to.throw(OT.ErreurOTLP); // type de fil 3
    expect(pb("0c")).to.throw(OT.ErreurOTLP); // type de fil 4
    expect(pb("0000")).to.throw(OT.ErreurOTLP); // étiquette 0
    expect(pb("08ffffffffffffffffff01")).to.throw(OT.ErreurOTLP); // varint de onze octets
    expect(pb("0a05")).to.throw(OT.ErreurOTLP); // longueur au-delà
    expect(pb("08")).to.throw(OT.ErreurOTLP); // champ 1 en varint (attendu LEN)
    expect(pb("a00601")().resourceSpans).to.deep.equal([]); // champ inconnu sauté
    const kv = (valeur) => Buffer.concat([Buffer.from("0a016b12", "hex"), Buffer.from([valeur.length]), valeur]);
    const enveloppe = (k) => {
      const span = Buffer.concat([Buffer.from("4a", "hex"), Buffer.from([k.length]), k]);
      const ss = Buffer.concat([Buffer.from("12", "hex"), Buffer.from([span.length]), span]);
      const rs = Buffer.concat([Buffer.from("12", "hex"), Buffer.from([ss.length]), ss]);
      return Buffer.concat([Buffer.from("0a", "hex"), Buffer.from([rs.length]), rs]);
    };
    const attr = (valeur) => OT.decoderProtobuf(enveloppe(kv(valeur))).resourceSpans[0].scopeSpans[0].spans[0].attributes[0].value;
    expect(attr(Buffer.from("0a0161", "hex"))).to.deep.equal({ type: "string", value: "a" });
    expect(attr(Buffer.from("18ffffffffffffffffff01", "hex"))).to.deep.equal({ type: "int", value: -1n });
    expect(() => attr(Buffer.from("0a01611001", "hex"))).to.throw(OT.ErreurOTLP); // deux membres du oneof
    expect(() => attr(Buffer.from("1002", "hex"))).to.throw(OT.ErreurOTLP); // bool_value 2
    expect(() => attr(Buffer.from("0a01ff", "hex"))).to.throw(OT.ErreurOTLP); // UTF-8 invalide
    expect(() => attr(Buffer.from("0a01610a0162", "hex"))).to.throw(OT.ErreurOTLP); // champ non répété en double
  });

  it("EX-6.31 à EX-6.34 : V et A (première occurrence, contenus en chaîne JSON), classification, doublons (fenêtre, taille), recouvrement (plus ancien non apparié)", function () {
    expect(OT.valeurAnyValue({ type: "int", value: 2n ** 53n - 1n })).to.equal(2 ** 53 - 1);
    expect(OT.valeurAnyValue({ type: "int", value: -(2n ** 53n) })).to.equal("-9007199254740992");
    expect(OT.valeurAnyValue({ type: "double", value: -0 })).to.equal(0);
    expect(OT.valeurAnyValue({ type: "double", value: Infinity })).to.equal("Infinity");
    expect(OT.valeurAnyValue({ type: "bytes", value: Buffer.from([1, 2]) })).to.equal("AQI=");
    expect(OT.valeurAnyValue(null)).to.equal(null);
    const compte = { doubles: 0 };
    const a = OT.attributs([{ key: "gen_ai.tool.call.arguments", value: { type: "string", value: '{"a":1.50}' } }, { key: "autre", value: { type: "string", value: '{"a":1}' } }, { key: "autre", value: { type: "string", value: "x" } }, { key: null, value: { type: "string", value: "y" } }], compte);
    expect([a.valeur, compte.doubles]).to.deep.equal([{ "gen_ai.tool.call.arguments": { a: 1.5 }, autre: '{"a":1}' }, 1]);
    const N = (attributes, ids = {}) => ({ trace_id: "5b8efff798038103d269b633813fc60c", span_id: "eee19b7ec3c1b174", parent_span_id: null, attributes, ...ids });
    const P = { ingest: ["inference", "outil"] };
    expect(OT.classer(N({}), P)).to.deep.equal({ sorte: null, issue: "ignore", raison: "hors_genai" });
    expect(OT.classer(N({ "gen_ai.operation.name": "retrieval" }), P).raison).to.equal("operation_non_retenue");
    expect(OT.classer(N({ "gen_ai.operation.name": "text_completion" }), { ingest: ["outil"] }).raison).to.equal("sorte_desactivee");
    expect(OT.classer(N({ "mcp.method.name": "tools/call" }), P)).to.deep.equal({ sorte: "outil", issue: "retenu", raison: null });
    expect(OT.classer(N({ "gen_ai.operation.name": "chat" }, { parent_span_id: "0000000000000000" }), P).issue).to.equal("rejete");
    expect(OT.classer(N({ "gen_ai.operation.name": "chat" }, { span_id: "eee19b7ec3c1b17" }), P).issue).to.equal("rejete");
    const t = new OT.TableDoublons({ fenetreMs: 1000, max: 2 });
    t.ajouter("a", 0);
    t.ajouter("b", 10);
    t.ajouter("c", 20);
    expect([t.sorties, t.contient("a", 20), t.contient("b", 20), t.contient("b", 1011)]).to.deep.equal([1, false, true, false]);
    const reg = new OT.RegistreRecouvrement([{ kind: "appel_outil", host_group: "g", seen_name: "x", t: 100, seq: 2 }, { kind: "appel_outil", host_group: "g", seen_name: "x", t: 50, seq: 1 }, { kind: "echange_modele", host_group: "g", model: "x", t: 60, seq: 3 }], { fenetreMs: 100 });
    expect(reg.apparier({ host_group: "g", sorte: "outil", nom: "x", t: 120 }).seq).to.equal(1);
    expect(reg.apparier({ host_group: "g", sorte: "outil", nom: "x", t: 120 }).seq).to.equal(2);
    expect(reg.apparier({ host_group: "g", sorte: "outil", nom: "x", t: 120 })).to.equal(null);
    expect(reg.apparier({ host_group: "h", sorte: "inference", nom: "x", t: 120 })).to.equal(null);
    expect(reg.apparier({ host_group: "g", sorte: "inference", nom: "x", t: 200 })).to.equal(null);
  });

  it("EX-6.35, EX-6.36 : nom d'outil, durée, erreur, run_id, fournisseur ; aucune clé ni valeur nouvelle de CT-1", function () {
    expect(OT.nomOutil("otel-sinistres", "paiement.creer").tool).to.equal("otel-sinistres__paiement.creer");
    for (const n of ["", "a__b", "noortrace.x", "a b", "x".repeat(120)]) expect(OT.nomOutil("otel-sinistres", n).tool, n).to.equal("otel-sinistres__nom-invalide");
    expect(OT.nomDeclare({ attributes: {}, name: "execute_tool f" })).to.equal("f");
    const d = (a, b) => OT.dureeSpan({ start_time_unix_nano: a, end_time_unix_nano: b });
    expect([d("1000000", "3999999"), d("0", "5000000"), d("5000000", "1000000"), d("1", "18446744073709551615")]).to.deep.equal([2, 0, 0, 18446744073709]);
    expect(OT.erreurSpan({ status: { code: 2 }, attributes: {} })).to.equal(true);
    expect(OT.erreurSpan({ status: { code: 1 }, attributes: { "error.type": "" } })).to.equal(false);
    const hote = { accept_declared_delegation: true };
    expect(OT.runIdSpan({ attributes: { "gen_ai.conversation.id": "conv-1" } }, hote, PII)).to.equal("conv-1");
    expect(OT.runIdSpan({ attributes: { "gen_ai.conversation.id": "conv-1" } }, { accept_declared_delegation: false }, PII)).to.equal(null);
    expect(OT.runIdSpan({ attributes: { "gen_ai.conversation.id": "m-4111111111111111" } }, hote, PII)).to.equal(null);
    expect(OT.fournisseurSpan({ request: { valeur: { "gen_ai.provider.name": "x_ai" } } })).to.equal("x_ai");
    expect(OT.fournisseurSpan({ request: { valeur: { "gen_ai.provider.name": 5, "gen_ai.system": "openai" } } })).to.equal("inconnu");
    // Toutes les valeurs des événements des vecteurs sont des valeurs existantes de CT-1 (schéma evenement-v0 inchangé).
    for (const nom of CAS) for (const s of lireJSON("otel", nom, "attendu.json").spans) if (s.event) expect(Object.keys(s.event), nom).to.deep.equal(J.CLES_EVENEMENT);
  });

  it("EX-6.26 à EX-6.28 : chemin (404), méthode (405, Allow), authentification (401), quota (429) et mode dégradé (503) avec Retry-After, type et codage (415), bornes (413) ; corps de réponse exacts", function () {
    const ctx = { source: { alias: "s", host: { host_group: "g", launched_by: "l", scope: "x" }, policy_source: { ingest: ["outil"] }, policy_version: "v" }, jeton: "j", options: { retry_after_s: 7 }, t_reception: 0 };
    const req = (extra = {}, e = {}) => OT.traiterRequete({ methode: "POST", chemin: "/v1/traces", entetes: { "content-type": "application/json", token_id: "j", ...e }, corps: Buffer.from('{"resourceSpans":[]}'), ...extra }, ctx);
    expect(req().status).to.equal(200);
    expect(req({ chemin: "/v1/metrics" }).status).to.equal(404);
    expect(req({ chemin: "/v1/traces?x=1" }).status).to.equal(200);
    const m = req({ methode: "GET" });
    expect([m.status, m.allow, m.corps.toString()]).to.deep.equal([405, "POST", '{"message":"noortrace: methode non admise"}']);
    expect(req({}, { token_id: "autre" }).status).to.equal(401);
    const q = OT.traiterRequete({ methode: "POST", chemin: "/v1/traces", entetes: { "content-type": "application/x-protobuf", token_id: "j" }, corps: Buffer.alloc(0) }, { ...ctx, quota: true });
    expect([q.status, q.retryAfter, q.contentType, q.corps.toString("hex")]).to.deep.equal([429, 7, "application/x-protobuf", "12" + Buffer.byteLength(OT.TEXTES_REFUS[429]).toString(16) + Buffer.from(OT.TEXTES_REFUS[429]).toString("hex")]);
    const deg = OT.traiterRequete({ methode: "POST", chemin: "/v1/traces", entetes: { "content-type": "application/json", token_id: "j" }, corps: Buffer.alloc(0) }, { ...ctx, degrade: "stockage" });
    expect([deg.status, deg.retryAfter, deg.partiels]).to.deep.equal([503, 7, []]);
    expect(req({ corps: Buffer.alloc(0) }, { "content-type": "Application/X-Protobuf; charset=x" }).status).to.equal(200);
    expect(OT.traiterRequete({ methode: "POST", chemin: "/v1/traces", entetes: { "content-type": "application/x-protobuf", token_id: "j" }, corps: Buffer.alloc(0) }, { ...ctx, options: { encodings: ["json"] } }).status).to.equal(415);
    expect(req({}, { "content-encoding": "br" }).status).to.equal(415);
    expect(req({ corps: zlib.gzipSync(Buffer.from("pas du json")) }, { "content-encoding": "gzip" }).status).to.equal(400);
    expect(req({ corps: Buffer.from("pas du gzip") }, { "content-encoding": "gzip" }).status).to.equal(400);
    const message = Buffer.from("noortrace: 300 span(s) rejete(s), identifiants invalides");
    const interne = Buffer.concat([Buffer.from("08ac0212", "hex"), Buffer.from([message.length]), message]);
    expect(OT.corpsReponse("protobuf", { rejetes: 300 }).toString("hex")).to.equal("0a" + interne.length.toString(16) + interne.toString("hex"));
    expect(OT.corpsReponse("json", { rejetes: 300 }).toString()).to.equal('{"partialSuccess":{"rejectedSpans":"300","errorMessage":"noortrace: 300 span(s) rejete(s), identifiants invalides"}}');
    expect(OT.corpsReponse("json", { rejetes: 0 }).toString()).to.equal("{}");
  });

  it("blocs annotés de 6.8.15 (otel, otel_policy, sdk_policy) valides ; 15.3 les porte ; policy.otel.semconv = 1.41.1", function () {
    const config = SCHEMAS[ID_CONFIG];
    for (const def of ["otel", "otel_policy", "sdk_policy"]) {
      const [texte] = blocs(`configuration-enregistreur/${def}`);
      expect(J.validerSchema(JSON.parse(texte), config, { registre: SCHEMAS, fragment: `#/$defs/${def}` }), def).to.deep.equal([]);
    }
    const c = C.copieJSON(CONFIG);
    c.policy.sdk = JSON.parse(blocs("configuration-enregistreur/sdk_policy")[0]);
    expect(J.validerSchema(c, config, { registre: SCHEMAS })).to.deep.equal([]);
    expect(jcs(CONFIG.otel)).to.equal(jcs(JSON.parse(blocs("configuration-enregistreur/otel")[0])));
    expect([CONFIG.policy.otel.semconv, OT.SEMCONV]).to.deep.equal(["1.41.1", "1.41.1"]);
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 révision 0.5 : copies WORM et gel juridique (12.6, 12.11, EX-12.29 à EX-12.41)", function () {
  const FAMILLES = { "requetes.json": "worm/requetes", "etats.json": "worm/etats", "perimetres.json": "worm/perimetres", "gardes.json": "worm/gardes" };

  it("worm/*.json : chaque fichier valide contre worm-v0, chaque cas rejoué par worm.mjs à l'identique", function () {
    for (const [fichier, family] of Object.entries(FAMILLES)) {
      const doc = lireJSON("worm", fichier);
      expect([doc.version, doc.family], fichier).to.deep.equal([0, family]);
      expect(J.validerSchema(doc, SCHEMAS[ID_WORM], { registre: SCHEMAS }), fichier).to.deep.equal([]);
      for (const c of doc.cases) {
        let obtenu;
        if (family === "worm/requetes") obtenu = W.requeteDeCas(c.input);
        else if (family === "worm/etats") obtenu = W.etatVerrou(c.input);
        else if (family === "worm/perimetres") {
          const { objects, objects_sha256, count, anomalies } = W.perimetreGel(c.input);
          obtenu = { objects, objects_sha256, count, anomalies };
        } else obtenu = W.verifierGarde(c.input.records);
        expect(jcs(obtenu), `${fichier} ${c.id}`).to.equal(jcs(c.expected));
      }
    }
  });

  it("EX-12.39 : Content-MD5 recalculé par node:crypto, valeurs imprimées dans la spécification, longueurs 128, 129, 273, 22, 23", function () {
    const md5 = (s) => crypto.createHash("md5").update(Buffer.from(s, "utf8")).digest("base64");
    for (const c of lireJSON("worm", "requetes.json").cases) {
      const h = Object.fromEntries(c.expected.headers);
      if (h["Content-MD5"] !== undefined) expect(h["Content-MD5"], c.id).to.equal(md5(c.expected.body_utf8));
      if (c.expected.body_utf8 !== null) expect([Buffer.byteLength(c.expected.body_utf8), J.sha256(Buffer.from(c.expected.body_utf8, "utf8"))], c.id).to.deep.equal([c.expected.body_length, c.expected.body_sha256]);
      const noms = c.expected.headers.map(([n]) => n.toLowerCase());
      expect(noms, c.id).to.deep.equal([...noms].sort());
      expect(noms.some((n) => ["host", "date", "authorization", "x-amz-date", "x-ms-date"].includes(n)), c.id).to.equal(false);
    }
    const sec = section("**EX-12.39**", "**EX-12.40**");
    for (const v of ["PabGSMHFuZL/pMW6ZUAWbQ==", "dUbasAU9gptvOryKx8wHGQ==", "MrEn2+g7Ii+EumTicoW97w=="]) expect(sec).to.include(v);
    const P = "journal-demo/segments/seg-0000000000000001-00000000000000000001.ndjson";
    const pose = W.requeteGelS3({ cle: P, versionId: "3/L4kqtJl40Nr8X8gdRQBpUMLUo", gel: true });
    const exemple = /```text\n(PUT [^\n]+) HTTP\/1\.1\nContent-Length: (\d+)\nContent-MD5: (\S+)\n\n(.*)\n```/.exec(sec);
    expect([`PUT ${pose.target}`, pose.headers[0][1], pose.headers[1][1], pose.body_utf8]).to.deep.equal([exemple[1], exemple[2], exemple[3], exemple[4]]);
    expect([W.corpsGelS3(true).length, W.corpsGelS3(false).length, W.corpsConfigurationVerrouS3(4018).length]).to.deep.equal([128, 129, 273]);
    expect(W.requeteGelS3({ cle: P, versionId: "v", gel: false }).headers[1][1]).to.equal("dUbasAU9gptvOryKx8wHGQ==");
    expect(W.requeteConfigurationVerrouS3(4018).headers[1][1]).to.equal("MrEn2+g7Ii+EumTicoW97w==");
    expect(sec).to.include(W.requeteGelAzure({ conteneur: "noortrace-demo-worm", blob: P, versionId: "2026-11-10T11:00:05.1234567Z", gel: true }).target);
  });

  it("EX-12.39 : encodage RFC 3986 (« / » gardé dans la clé S3 et Azure, encodé ailleurs et dans le nom GCS), hexadécimal en majuscules", function () {
    expect(W.requeteGelS3({ cle: "journal démo/pièce.json", versionId: "a+b/c=", gel: true }).target).to.equal("/journal%20d%C3%A9mo/pi%C3%A8ce.json?legal-hold&versionId=a%2Bb%2Fc%3D");
    expect(W.encoderSegment("A-Za-z0-9._~", false)).to.equal("A-Za-z0-9._~");
    expect(W.encoderSegment("a/b:é", true)).to.equal("a/b%3A%C3%A9");
    expect(W.requeteGelGcs({ bucket: "b", nom: "p/q r", generation: "17", gel: true }).target).to.equal("/storage/v1/b/b/o/p%2Fq%20r?generation=17");
    expect(W.requeteListeS3({ prefix: "p/", keyMarker: null, versionIdMarker: null }).target).to.equal("/?versions&max-keys=1000&prefix=p%2F");
    expect(W.requeteCopieS3({ cle: "k", octets: Buffer.from("x"), gelALEcriture: true }).headers.map(([n]) => n)).to.deep.equal(["Content-Length", "Content-MD5", "If-None-Match", "x-amz-object-lock-legal-hold"]);
  });

  it("EX-12.33 : lecture des échéances (RFC 3339, IMF-fixdate), ordre des raisons, notes", function () {
    expect(J.horodatage(W.lireEcheance("2037-11-10T11:00:05Z"))).to.equal("2037-11-10T11:00:05.000Z");
    expect(J.horodatage(W.lireEcheance("2037-11-10T12:00:05.9999+01:00"))).to.equal("2037-11-10T11:00:05.999Z");
    expect(J.horodatage(W.lireEcheance("Tue, 10 Nov 2037 11:00:05 GMT"))).to.equal("2037-11-10T11:00:05.000Z");
    for (const v of ["2037-02-30T00:00:00Z", "2037-11-10 11:00:05Z", "2037-11-10T24:00:00Z", "Tue, 10 Nov 2037 11:00:05 UTC", "", null]) expect(W.lireEcheance(v), String(v)).to.equal(null);
    const e = W.etatVerrou({ type: "s3-object-lock", headers: { "x-amz-object-lock-mode": "GOVERNANCE", "x-amz-object-lock-retain-until-date": "x" }, json: null, expected_lock: { retain_until_min: "2030-01-01T00:00:00.000Z", hold: true } });
    expect([e.reasons, e.notes, e.verdict]).to.deep.equal([["mode_non_conforme", "date_illisible", "gel_absent"], ["jamais_gele"], "non_conforme"]);
    expect(W.etatVerrou({ type: "s3-object-lock", headers: { "x-amz-object-lock-mode": "GOVERNANCE", "x-amz-object-lock-retain-until-date": "2031-01-01T00:00:00Z" }, json: null, expected_lock: { retain_until_min: "2030-01-01T00:00:00.000Z", hold: null } }, { mode: "governance" }).verdict).to.equal("conforme");
    expect(W.echeanceMinimale("2026-11-10T11:00:05.412Z", 4018)).to.equal("2037-11-10T10:00:05.412Z");
    const { ligne, texte } = W.ligneCopie({ key: "k", version_id: "v", octets: Buffer.from("abc"), copied_at: "2026-11-10T11:00:05.412Z", lock: e });
    expect(J.validerSchema(ligne, SCHEMAS[ID_WORM], { registre: SCHEMAS, fragment: "#/$defs/ligne_copie" })).to.deep.equal([]);
    expect(texte.endsWith("\n") && JSON.parse(texte).length === 3).to.equal(true);
  });

  it("EX-12.35 : l'exemple (six objets, 673 octets, empreinte) recalculé depuis le texte de 12.11 ; tri par octets UTF-8", function () {
    const sec = section("**EX-12.35**", "**EX-12.36**");
    const lignes = /```text\n([\s\S]*?)\n```/.exec(sec)[1];
    expect(sec).to.include("0x0a24b97a14bf984ea5e8864e940ef45a5aad5eb8a1be9ec176affbe37a41083c");
    const versions = lignes.split("\n").map((l) => ({ ...JSON.parse(l), is_latest: true, delete_marker: false })).reverse();
    const r = W.perimetreGel({ prefix: "journal-demo/", from: 1794304800, to: 1794304800, manifests: [{ period_start: 1794304800, first_seq: 1, last_seq: 8 }], versions, pieces: null });
    expect([r.texte, Buffer.byteLength(r.texte), r.objects_sha256, r.count]).to.deep.equal([lignes + "\n", 673, "0x0a24b97a14bf984ea5e8864e940ef45a5aad5eb8a1be9ec176affbe37a41083c", 6]);
    expect(() => W.perimetreGel({ prefix: "", from: 1, to: 3600, manifests: [], versions: [] })).to.throw(RangeError);
    const tri = W.perimetreGel({ prefix: "", from: 0, to: 0, manifests: [], versions: [{ key: "ancres/periode-0000000000/é", version_id: "1", is_latest: true, delete_marker: false }, { key: "ancres/periode-0000000000/z", version_id: "2", is_latest: true, delete_marker: false }] });
    expect(tri.objects.map((o) => o.key)).to.deep.equal(["ancres/periode-0000000000/z", "ancres/periode-0000000000/é"]);
  });

  it("EX-12.37 : les empreintes des enregistrements imprimées en 12.11 recalculées depuis les blocs 0001-pose et 0004-levee", function () {
    const [pose, levee] = blocs("worm/enregistrement_gel").map((t) => C.analyserJSONIntegral(t));
    expect([W.empreinteEnregistrement(pose), W.octetsEnregistrement(pose).length]).to.deep.equal(["0x4b88f9b3b618a27835988b98bb3e146e99177e370eb6cd3af219a7ba4634eb1a", 811]);
    expect(W.empreinteEnregistrement(levee)).to.equal("0x3543164e9f59156aeff461bcaf1334a5a678a98fa239f1162f6df970bf0e8482");
    expect(levee.request_sha256).to.equal("0xe9d87eb97309d57d4d2241d12b8d3debe220a9d782fd541b92299eecc30c3af7");
    const valide = lireJSON("worm", "gardes.json").cases.find((c) => c.id === "suite-valide");
    expect(jcs(valide.input.records[0])).to.equal(jcs(pose));
    expect(jcs(valide.input.records[3])).to.equal(jcs(levee));
    expect(valide.expected.record_sha256).to.deep.equal(["0x4b88f9b3b618a27835988b98bb3e146e99177e370eb6cd3af219a7ba4634eb1a", "0xb7d1457d111588b55d7d235d313a6d6aabb32ff6c82e75c82c351beed67cc744", "0xe9d87eb97309d57d4d2241d12b8d3debe220a9d782fd541b92299eecc30c3af7", "0x3543164e9f59156aeff461bcaf1334a5a678a98fa239f1162f6df970bf0e8482", "0x1fa25acb0f9f78211f2abdbbd2217233f4b134a69534e2975fc3828dfe892c05"]);
    expect(W.cleEnregistrement("journal-demo/", pose)).to.equal("journal-demo/gels/gel-20261201T090000Z-5f0c2a1e/0001-pose.json");
  });

  it("EX-12.38 : chaque code de la règle de garde provoqué par une mutation minimale de la suite valide", function () {
    const base = lireJSON("worm", "gardes.json").cases.find((c) => c.id === "suite-valide").input.records;
    expect(W.verifierGarde(base).valid).to.equal(true);
    /** Rechaîne une suite (prev_sha256 et request_sha256 des levées sur la dernière demande) après une mutation. */
    const rechainer = (suite) => {
      const out = [];
      let demande = null;
      suite.forEach((r, i) => {
        const o = { ...r, n: i + 1, prev_sha256: i === 0 ? null : W.empreinteEnregistrement(out[i - 1]) };
        if (o.kind === "levee" && r.request_sha256 !== "fixe") o.request_sha256 = demande;
        out.push(o);
        if (o.kind === "demande_levee") demande = W.empreinteEnregistrement(o);
      });
      return out;
    };
    const codes = (suite) => W.verifierGarde(suite).errors;
    const muter = (i, champs) => rechainer(base.map((r, k) => (k === i ? { ...r, ...champs } : r)));
    expect(codes(base.map((r, k) => (k === 2 ? { ...r, prev_sha256: "0x" + "00".repeat(32) } : r)))).to.deep.include({ n: 3, code: "chaine_rompue" });
    expect(codes(base.map((r, k) => (k === 1 ? { ...r, gel_id: "gel-20261201T090000Z-00000000" } : r)))).to.deep.include({ n: 2, code: "chaine_rompue" });
    expect(codes(rechainer(base.slice(1)))).to.deep.include({ n: 1, code: "premier_non_pose" });
    expect(codes(muter(1, { kind: "demande_levee", results: null }))).to.deep.include({ n: 2, code: "ordre_invalide" });
    expect(codes(muter(4, { at: "2037-03-16T14:29:59.999Z" }))).to.deep.equal([{ n: 5, code: "ordre_invalide" }]);
    expect(codes(muter(3, { actor: base[2].actor }))).to.deep.equal([{ n: 4, code: "meme_identite" }]);
    expect(codes(muter(3, { request_sha256: "fixe" }).map((r) => (r.request_sha256 === "fixe" ? { ...r, request_sha256: W.empreinteEnregistrement(base[0]) } : r)))).to.deep.include({ n: 4, code: "demande_inconnue" });
    const expiree = muter(3, { at: "2037-03-22T08:00:00.001Z" });
    expect(codes(expiree.map((r, k) => (k === 4 ? { ...r, at: "2037-03-22T08:00:01.000Z" } : r)))).to.deep.include({ n: 4, code: "demande_expiree" });
    const septJours = rechainer(base.map((r, k) => (k === 3 ? { ...r, at: "2037-03-22T08:00:00.000Z" } : k === 4 ? { ...r, at: "2037-03-22T08:00:01.000Z" } : r)));
    expect(W.verifierGarde(septJours).valid).to.equal(true);
    expect(codes(rechainer([...base, { ...base[3] }]))).to.deep.include({ n: 6, code: "levee_en_double" });
    expect(codes(muter(2, { objects: { ...base[2].objects, count: 5 } }))).to.deep.equal([{ n: 3, code: "objets_differents" }]);
    expect(codes(muter(2, { periods: { from: base[0].periods.from, to: base[0].periods.to + 3600 } }))).to.deep.equal([{ n: 3, code: "periode_differente" }]);
    expect(W.DELAI_LEVEE_MS).to.equal(604800000);
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 révision 0.5 : coût annuel par agent (16.4, EX-16.4 à EX-16.6)", function () {
  it("cout-agent/cas.json : valide contre cout-agent-v0, neuf cas rejoués à l'identique ; C_anc relu dans les vecteurs de CT-5", function () {
    const doc = lireJSON("cout-agent", "cas.json");
    expect(J.validerSchema(doc, SCHEMAS[ID_COUT], { registre: SCHEMAS })).to.deep.equal([]);
    expect(doc.cases.map((c) => c.id)).to.deep.equal(["reference", "sans-worm", "pieces-dans-le-worm", "taille-minimale-facturable", "gel-juridique", "segments-scindes", "agent-inactif", "un-agent-par-journal", "pieces-purgees"]);
    for (const c of doc.cases) expect(coutAgent(c.input), c.id).to.deep.equal(c.expected);
    const ct5 = JSON.parse(fs.readFileSync(path.join(SPEC, "vecteurs", "ct-5", "cout", "cout.json"), "utf8")).cases.find((c) => c.id === "defaut-second-rang-a1");
    for (const c of doc.cases) expect(c.input.anchoring_cost_per_journal, c.id).to.equal(ct5.expected.cost_per_journal);
  });

  it("les totaux de la table de 16.4 et les valeurs de l'exemple de référence sont ceux de la formule", function () {
    const sec = section("### 16.4 Coût annuel par agent", "## 17. Supervision");
    const lignes = [...sec.matchAll(/^\| `([a-z-]+)` \| [^|]+ \| ([0-9 ]+(?:,[0-9]+)?) \|$/gm)].map((m) => [m[1], Number(m[2].replace(/ /g, "").replace(",", "."))]);
    expect(lignes).to.have.length(9);
    const doc = lireJSON("cout-agent", "cas.json");
    for (const [id, total] of lignes) expect(doc.cases.find((c) => c.id === id).expected.cost.total, id).to.equal(total);
    const ref = doc.cases[0].expected;
    expect([ref.events_per_year, ref.event_bytes_per_year, ref.segments_per_year, ref.journal_objects_per_year, ref.worm_objects_per_year, ref.cost.local_storage, ref.cost.worm_storage, ref.cost.write_requests, ref.cost.read_requests, ref.cost.network, ref.cost.anchoring, ref.cost.total, ref.cost_journal_total]).to.deep.equal([350400, 897024000, 292, 35040, 35332, 16.223, 10.374, 4, 47.38, 0.094, 2803.2, 2881.27, 28812.701]);
    expect(relevesParAn(30)).to.equal(365 / 30);
  });

  it("contrôles d'entrée : entiers, A ≥ 1, S ≥ 1024, 0 ≤ g ≤ 1 ; worm null annule les termes WORM", function () {
    const base = lireJSON("cout-agent", "cas.json").cases[0].input;
    expect(() => coutAgent({ ...base, agents_per_journal: 0 })).to.throw(RangeError);
    expect(() => coutAgent({ ...base, segment_max_bytes: 1023 })).to.throw(RangeError);
    expect(() => coutAgent({ ...base, active_hours_per_year: 2.5 })).to.throw(TypeError);
    expect(() => coutAgent({ ...base, worm: { ...base.worm, legal_hold_fraction: 1.5 } })).to.throw(RangeError);
    expect(() => coutAgent({ ...base, prices: { ...base.prices, egress_gib: Number.NaN } })).to.throw(TypeError);
    const sans = coutAgent({ ...base, worm: null });
    expect([sans.worm_objects_per_year, sans.worm_billable_bytes_per_year, sans.cost.worm_storage, sans.cost.legal_hold, sans.cost.write_requests, sans.cost.read_requests, sans.cost.network]).to.deep.equal([0, 0, 0, 0, 0, 0, 0]);
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 révision 0.5, relecture : corrections de comportement sans vecteur dédié", function () {
  this.timeout(120_000);
  const SRC = lireJSON("otel", "json-exemple-6-8-16", "source.json");
  const CORPS = fs.readFileSync(path.join(VECTEURS, "otel", "json-exemple-6-8-16", "requete.json"));
  const DOC = JSON.parse(CORPS.toString("utf8"));
  const SPANS = DOC.resourceSpans[0].scopeSpans[0].spans;
  const avecSpans = (spans) => {
    const d = JSON.parse(JSON.stringify(DOC));
    d.resourceSpans[0].scopeSpans[0].spans = spans;
    return Buffer.from(JSON.stringify(d), "utf8");
  };
  const ctx = (extra = {}) => ({ source: { alias: SRC.alias, host: SRC.host, policy_source: SRC.policy_source, policy_version: SRC.policy_version }, jeton: SRC.host.id, options: SRC.options, politique: PII, t_reception: J.msHorodatage(SRC.t_reception), ...extra });
  const envoyer = ({ methode = "POST", chemin = "/v1/traces", entetes = {}, corps = CORPS } = {}, extra = {}) => OT.traiterRequete({ methode, chemin, entetes: { "content-type": "application/json", token_id: SRC.host.id, ...entetes }, corps }, ctx(extra));
  const evenements = (r) => r.journal.map((l) => l.event);

  it("EX-6.27 : ordre des décisions chemin, méthode, jeton, quota, mode dégradé, type ; un refus est consigné par otel_request avec query_string", function () {
    expect(envoyer({ methode: "GET", chemin: "/v1/%2e%2e/traces", entetes: { token_id: "faux", "content-type": "text/plain" } }).status).to.equal(404);
    const m = envoyer({ methode: "GET", chemin: "/v1/traces?x=1", entetes: { token_id: "faux", "content-type": "text/plain" } });
    expect([m.status, evenements(m)]).to.deep.equal([405, ["otel_refused", "otel_request"]]);
    expect(m.journal[1].data).to.deep.include({ query_string: true, status: 405, content_type: "text/plain", received_bytes: CORPS.length, decoded_bytes: null });
    expect(envoyer({ entetes: { token_id: "faux", "content-type": "text/plain" } }, { quota: true }).status).to.equal(401);
    expect(envoyer({ entetes: { "content-type": "text/plain" } }, { quota: true, degrade: "stockage" }).status).to.equal(429);
    expect(envoyer({ entetes: { "content-type": "text/plain" } }, { degrade: "stockage" }).status).to.equal(503);
    expect(envoyer({ entetes: { "content-type": "text/plain" } }).status).to.equal(415);
    const ok = envoyer({ chemin: "/v1/traces?x=1" });
    expect([ok.status, ok.journal.at(-1).data.query_string, ok.journal.at(-1).data.spans]).to.deep.equal([200, true, 2]);
  });

  it("EX-6.28 : spans_per_request dépassé → 413 sans rien sceller ; events_per_minute atteint → 429, les spans déjà scellés restent", function () {
    const t = envoyer({}, { options: { ...SRC.options, spans_per_request: 1 } });
    expect([t.status, t.partiels.length, t.corps.toString(), t.journal[0].data.reason]).to.deep.equal([413, 0, '{"message":"noortrace: corps OTLP trop grand"}', "spans_par_requete"]);
    expect(envoyer({}, { options: { ...SRC.options, spans_per_request: 2 } }).status).to.equal(200);
    const q = envoyer({}, { evenements_restants: 1 });
    expect([q.status, q.partiels.length, q.retryAfter, q.journal[0].data.reason]).to.deep.equal([429, 1, 5, "evenements_par_minute"]);
    expect(envoyer({}, { evenements_restants: 2 }).partiels).to.have.length(2);
  });

  it("EX-6.33 : un span rejoué avec un autre contenu est un doublon signalé (otel_span_conflict) ; otel_dedup_evicted ne compte que les sorties de la requête", function () {
    const c = envoyer({ corps: avecSpans([SPANS[0], { ...SPANS[0], name: "chat autre" }]) });
    expect([c.status, c.compteurs.scelle, c.compteurs.doublon]).to.deep.equal([200, 1, 1]);
    const conflit = c.journal.find((l) => l.event === "otel_span_conflict");
    expect(conflit.data).to.include({ trace_id: SPANS[0].traceId.toLowerCase(), span_id: SPANS[0].spanId.toLowerCase() });
    expect(conflit.data.sha256_connu).to.not.equal(conflit.data.sha256_recu);
    expect(evenements(envoyer({ corps: avecSpans([SPANS[0], SPANS[0]]) }))).to.deep.equal(["otel_request"]);
    const table = new OT.TableDoublons({ fenetreMs: 3600000 });
    envoyer({}, { doublons: table });
    expect(evenements(envoyer({ corps: avecSpans([{ ...SPANS[1], name: "x" }]) }, { doublons: table }))).to.deep.equal(["otel_span_conflict", "otel_request"]);
    const petite = new OT.TableDoublons({ fenetreMs: 3600000, max: 1 });
    petite.ajouter("y", 0);
    petite.ajouter("z", 0);
    expect(petite.sorties).to.equal(1);
    // « z », hors fenêtre, est purgé sans sortie ; le second span fait sortir le premier : une sortie dans cette requête, deux au total.
    expect(envoyer({}, { doublons: petite }).journal.filter((l) => l.event === "otel_dedup_evicted")).to.deep.equal([{ event: "otel_dedup_evicted", data: { count: 1 } }]);
    expect(petite.sorties).to.equal(2);
  });

  it("EX-6.31 : une clé en double dans un kvlist est comptée comme dans attributes (première occurrence gardée)", function () {
    const compte = { doubles: 0 };
    const v = OT.valeurAnyValue({ type: "kvlist", value: [{ key: "a", value: { type: "string", value: "1" } }, { key: "a", value: { type: "string", value: "2" } }] }, compte);
    expect([v, compte.doubles]).to.deep.equal([{ a: "1" }, 1]);
  });

  it("EX-6.26 : borne de 413 sur les octets reçus, puis décomprimés ; gzip égal à la borne admis ; IDENTITY sans compression", function () {
    const g = zlib.gzipSync(CORPS);
    const borne = (n, codage, corps) => envoyer({ entetes: { "content-encoding": codage }, corps }, { options: { ...SRC.options, max_body_bytes: n } });
    expect(borne(CORPS.length, "gzip", g).status).to.equal(200);
    const d = borne(CORPS.length - 1, "gzip", g);
    expect([d.status, d.journal[0].data.reason]).to.deep.equal([413, "taille_decomprimee"]);
    expect(borne(g.length - 1, "gzip", g).journal[0].data.reason).to.equal("taille");
    expect(borne(CORPS.length, "IDENTITY", CORPS).status).to.equal(200);
    expect(borne(CORPS.length - 1, "IDENTITY", CORPS).status).to.equal(413);
  });

  it("EX-6.35 : prompt en ligne, rédaction au-delà du budget → pièce « requête » non rédigeable (budget_redaction)", function () {
    const lente = C.chargerPolitique({ version: 0, name: "budget-v1", pseudonym_key: null, named_patterns: { m: { pattern: "[0-9]+$" } }, rules: [{ id: "r-motif", scopes: ["prompt_systeme"], tools: "*", detectors: [{ type: "regex", name: "m" }], action: { kind: "remplacer" } }] }, { schemas: SCHEMAS });
    const s = lireJSON("otel", "json-inference-prompt-inline", "source.json");
    const lg = OT.decoderJSON(fs.readFileSync(path.join(VECTEURS, "otel", "json-inference-prompt-inline", "requete.json")));
    const N = OT.formeNormalisee(lg.resourceSpans[0], lg.resourceSpans[0].scopeSpans[0], lg.resourceSpans[0].scopeSpans[0].spans[0]);
    N.attributes["gen_ai.system_instructions"] = [{ type: "text", content: "1".repeat(80000) + "x" }];
    const notes = [];
    const p = OT.piecesSpan(N, "inference", { source: { alias: s.alias, host: s.host, policy_source: s.policy_source }, options: { ...s.options, prompt_in_request: "inline" }, politique: lente, budgetMs: 50, onDepassement: (n) => notes.push(n) });
    expect(p.request.nonRedigeable).to.equal("budget_redaction");
    expect(p.request.reference).to.include({ redacted: true });
    expect(notes.length).to.be.above(0);
  });

  it("EX-5.22 : l'échange interposé est préféré à l'échange déclaré par le SDK ; à défaut, la corrélation au SDK est signalée", function () {
    const forme = { content: [{ type: "tool_use", id: "t1", name: "lire", input: { a: 1 } }] };
    const echange = (channel, t, seq) => ({ groupe: "g", channel, format: "anthropic-messages", forme: JSON.parse(JSON.stringify(forme)), t, seq });
    const appel = { groupe: "g", tool_announced: "lire", arguments: { a: 1 }, t_recu: 100 };
    const sdk = echange("sdk", 90, 2);
    const passerelle = echange("passerelle", 80, 1);
    const r = C.correler(appel, [sdk, passerelle]);
    expect([r.echange, r.declaree]).to.deep.equal([passerelle, false]);
    const r2 = C.correler({ ...appel }, [echange("sdk", 90, 2)]);
    expect(r2.declaree).to.equal(true);
    expect(C.correler({ ...appel, tool_announced: "autre" }, [sdk])).to.deep.equal({ echange: null, appel: null, texte: null, texteClair: null });
    const d = C.pieceDeclarationCanal("sdk", "sdk-a");
    expect(Buffer.from(d.octets).toString("utf8")).to.equal('{"noortrace_capture":{"channel":"sdk","source":"sdk-a"}}');
    expect(Buffer.from(OT.pieceDeclarationSource("otel-a").octets).toString("utf8")).to.equal('{"noortrace_capture":{"channel":"otel","source":"otel-a"}}');
  });

  it("table de 6.2 : la classe configurée prime, une classe déclarée ne peut que la renforcer", function () {
    expect(C.classeEffectiveSDK({ declaree: "lecture", configuree: "ecriture" })).to.deep.equal({ classe: "ecriture", refusee: true });
    expect(C.classeEffectiveSDK({ declaree: "ecriture", configuree: "lecture" })).to.deep.equal({ classe: "ecriture", refusee: false });
    expect(C.classeEffectiveSDK({ declaree: null, configuree: "lecture" })).to.deep.equal({ classe: "lecture", refusee: false });
    expect(C.classeEffectiveSDK({ declaree: "lecture" })).to.deep.equal({ classe: "lecture", refusee: false });
    expect(C.classeEffectiveSDK({})).to.deep.equal({ classe: "ecriture", refusee: false });
  });

  it("EX-5.29 : noms de paramètres consignés sans valeur ni nom inconnu ; EX-5.32 : cachedContent détecté", function () {
    expect(C.nomsConsignes(["key", "alt", "cachedContent", "é"])).to.deep.equal(["key", "alt", "[autre:13]", "[autre:2]"]);
    expect(C.cacheFournisseur({ contents: [] })).to.not.be.ok;
    expect(C.cacheFournisseur({ cachedContent: "cachedContents/x" })).to.be.ok;
  });

  it("EX-12.33 : une valeur de gel hors de la table est illisible, jamais lue comme off ; EX-12.38 : suite vide, at illisible", function () {
    const s3 = W.etatVerrou({ type: "s3-object-lock", headers: { "x-amz-object-lock-mode": "COMPLIANCE", "x-amz-object-lock-retain-until-date": "2040-01-01T00:00:00Z", "x-amz-object-lock-legal-hold": "on" }, expected_lock: { retain_until_min: "2030-01-01T00:00:00.000Z", hold: false } });
    expect([s3.legal_hold, s3.verdict, s3.reasons]).to.deep.equal(["illisible", "non_conforme", ["gel_illisible"]]);
    const gcs = W.etatVerrou({ type: "gcs-object-retention", json: { retention: { mode: "Locked", retainUntilTime: "2040-01-01T00:00:00Z" }, temporaryHold: "true" }, expected_lock: { retain_until_min: "2030-01-01T00:00:00.000Z", hold: true } });
    expect([gcs.legal_hold, gcs.reasons]).to.deep.equal(["illisible", ["gel_illisible"]]);
    expect(W.verifierGarde([])).to.deep.equal({ valid: false, record_sha256: [], errors: [{ n: 1, code: "premier_non_pose" }] });
    const gardes = lireJSON("worm", "gardes.json");
    const valide = gardes.cases.find((c) => c.expected.valid === true);
    const suite = JSON.parse(JSON.stringify(valide.input.records));
    suite[0].at = "16/03/2037";
    expect(W.verifierGarde(suite).errors.filter((e) => e.n === 1).map((e) => e.code)).to.include("ordre_invalide");
  });

  it("EX-12.40 : une version couverte par un autre gel actif n'est pas levée", function () {
    const r = W.versionsALever([{ key: "a", version_id: "1" }, { key: "b", version_id: "1" }, { key: "c", version_id: "2" }], [{ gel_id: "g2", objects: [{ key: "b", version_id: "1" }] }, { gel_id: "g3", objects: [{ key: "b", version_id: "1" }, { key: "c", version_id: "2" }] }]);
    expect(r).to.deep.equal({ lever: [{ key: "a", version_id: "1" }], conserver: [{ key: "b", version_id: "1", gel_id: "g2" }, { key: "c", version_id: "2", gel_id: "g3" }] });
    const levees = lireJSON("worm", "levees.json");
    for (const c of levees.cases) {
      const v = W.versionsALever(c.input.objects, c.input.other_holds);
      expect({ lift: v.lever, keep: v.conserver }, c.id).to.deep.equal(c.expected);
    }
  });
});
