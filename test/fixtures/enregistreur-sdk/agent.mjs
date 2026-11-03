// Agent Node.js de démonstration pour le parcours du SDK (test
// enregistreur-sdk-parcours) : il exécute lui-même ses outils et les
// déclare au démon `noortrace` par le SDK `noortrace-sdk` (CT-2 6.2, 6.5),
// déclare un échange de modèle (EX-6.8), et exporte des spans au point
// d'entrée OTLP/HTTP du démon (6.8, 6.8.15) de deux façons : par
// l'exportateur officiel OTLP/HTTP du SDK OpenTelemetry JavaScript
// (`@opentelemetry/exporter-trace-otlp-http`, JSON, configuré par
// OTEL_EXPORTER_OTLP_TRACES_ENDPOINT et OTEL_EXPORTER_OTLP_TRACES_HEADERS),
// et par un exportateur minimal en protobuf (`http/protobuf`).
// Il écrit ses étapes en lignes JSON sur sa sortie standard et lit sur son
// entrée le signal du test (« vote » rendu).
//
// Environnement : NOORTRACE_SDK_SOCKET (prise du démon), NOORTRACE_ESSAI_INTENTIONS
// (répertoire du journal d'intention, pour constater l'intention durable avant
// l'exécution), OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, OTEL_EXPORTER_OTLP_TRACES_HEADERS.

import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import readline from "node:readline";
import { pathToFileURL } from "node:url";
import { ClientNoortrace } from "noortrace-sdk";
import { encoderProtobuf, lot, spanOutil, spanInference } from "../enregistreur-otel/lots.mjs";

const ecrire = (o) => process.stdout.write(JSON.stringify(o) + "\n");

/** L'intention de l'appel `call` est-elle sur disque (EX-12.12) ? */
function intentionDurable(call) {
  const dir = process.env.NOORTRACE_ESSAI_INTENTIONS;
  return fs.readdirSync(dir).some((n) => fs.readFileSync(path.join(dir, n), "utf8").split("\n").some((l) => l && JSON.parse(l).upstream_id === call));
}

/** Exportateur OTLP/HTTP minimal (protobuf, en-têtes de OTEL_EXPORTER_OTLP_TRACES_HEADERS). */
function exporter(spans) {
  const url = new URL(process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT);
  const entetes = Object.fromEntries(process.env.OTEL_EXPORTER_OTLP_TRACES_HEADERS.split(",").map((p) => p.split("=").map((x) => decodeURIComponent(x.trim()))));
  const corps = Buffer.from(encoderProtobuf(lot(spans)));
  return new Promise((resoudre, rejeter) => {
    const req = http.request({ host: url.hostname, port: url.port, path: url.pathname, method: "POST", headers: { "content-type": "application/x-protobuf", "content-length": corps.length, ...entetes } }, (res) => {
      const m = [];
      res.on("data", (x) => m.push(x));
      res.on("end", () => resoudre({ statut: res.statusCode, corps: Buffer.concat(m).toString("hex") }));
    });
    req.on("error", rejeter);
    req.end(corps);
  });
}

/**
 * Exportateur officiel : traceur du SDK OpenTelemetry JavaScript, spans
 * d'inférence et d'outil aux attributs `gen_ai.*`, exportés par
 * `OTLPTraceExporter` (OTLP/HTTP JSON, adresse et en-têtes lus dans
 * l'environnement par l'exportateur lui-même).
 */
async function exporterOfficiel() {
  const { BasicTracerProvider, SimpleSpanProcessor, InMemorySpanExporter } = await import("@opentelemetry/sdk-trace-base");
  const { OTLPTraceExporter } = await import("@opentelemetry/exporter-trace-otlp-http");
  const { SpanKind, SpanStatusCode } = await import("@opentelemetry/api");
  const memoire = new InMemorySpanExporter();
  const fournisseur = new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(memoire)] });
  const traceur = fournisseur.getTracer("agent-sinistres", "1.0.0");
  const inference = traceur.startSpan("chat modele-officiel-1", {
    kind: SpanKind.CLIENT,
    attributes: {
      "gen_ai.operation.name": "chat",
      "gen_ai.provider.name": "openai",
      "gen_ai.request.model": "modele-officiel-1",
      "gen_ai.response.model": "modele-officiel-1",
      "gen_ai.output.messages": JSON.stringify([{ role: "assistant", parts: [{ type: "text", content: "J'archive le dossier." }] }]),
    },
  });
  inference.setStatus({ code: SpanStatusCode.OK });
  inference.end();
  const outil = traceur.startSpan("execute_tool archiver_dossier", {
    kind: SpanKind.INTERNAL,
    attributes: { "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "archiver_dossier", "gen_ai.tool.call.arguments": '{"dossier":"2026-77812"}', "gen_ai.tool.call.result": '{"archive":true}' },
  });
  outil.end();
  await fournisseur.forceFlush();
  const spans = memoire.getFinishedSpans();
  const exportateur = new OTLPTraceExporter();
  const r = await new Promise((resoudre) => exportateur.export(spans, resoudre));
  await exportateur.shutdown();
  await fournisseur.shutdown();
  return { code: r.code, erreur: r.error ? String(r.error.message ?? r.error) : null, spans: spans.length };
}

/** Parcours de l'agent ; lancé seulement comme programme (le chargeur de tests lit aussi ce fichier). */
async function principal() {
  const lignes = readline.createInterface({ input: process.stdin });
  const attenteLigne = () => new Promise((r) => lignes.once("line", r));
  const client = ClientNoortrace.depuisEnvironnement();
  const session = await client.ouvrir({ runId: "run-parcours-0001", onBehalfOf: null });
  try {
    // Contexte déclaré (8.2, EX-7.7).
    const ref = await session.declarerContexte({ kind: "document", octets: "Dossier du sinistre 2026-77812 ; assuré jean.exemple@assureur-demo.example", mediaType: "text/plain" });
    ecrire({ etape: "contexte", ref });

    // Appel de lecture : exécuté après « autorise ».
    const lu = await session.appelOutil({ tool: "lire_sinistre", arguments: { sinistre: "2026-77812" }, classe: "lecture", contexte: [ref.sha256] }, async (a) => ({ sinistre: a.sinistre, statut: "ouvert" }));
    ecrire({ etape: "lecture", resultat: lu });

    // Appel d'écriture : l'intention est durable avant le retour de debutAppel (EX-6.3, EX-12.12).
    const d = await session.debutAppel({ tool: "ecrire_note", arguments: { sinistre: "2026-77812", note: "pieces recues" }, classe: "ecriture", intent: "Noter la réception des pièces" });
    const durable = intentionDurable(d.call);
    const t0 = performance.now();
    const resultat = { note: "N-1" };
    const fin = await session.finAppel(d, { resultat, isError: false, durationMs: Math.floor(performance.now() - t0) });
    ecrire({ etape: "ecriture", decision: d.decision, intention_durable_avant_execution: durable, fin });

    // Appel refusé par la politique (refusee).
    const refus = await session.debutAppel({ tool: "supprimer_dossier", arguments: { sinistre: "2026-77812" }, classe: "ecriture" });
    ecrire({ etape: "refus", debut: refus });

    // Appel soumis à approbation : retenue, votes signés au vrai service, puis relais approuvé.
    const args = { sinistre: "2026-77812", montant: "7400.00", devise: "CHF" };
    const n = await session.debutAppel({ tool: "preparer_paiement", arguments: args, classe: "ecriture" });
    ecrire({ etape: "retenue", debut: n });
    await attenteLigne();
    let ok = null;
    for (let k = 0; k < 200; k++) {
      ok = await session.debutAppel({ tool: "preparer_paiement", arguments: args, classe: "ecriture" });
      if (ok.decision === "autorise") break;
      await new Promise((r) => setTimeout(r, 100));
    }
    const durableApprouve = ok.call ? intentionDurable(ok.call) : false;
    const finApprouve = await session.finAppel(ok, { resultat: { paiement: "PAY-2026-55120" }, isError: false, durationMs: 33 });
    ecrire({ etape: "approuve", debut: ok, intention_durable_avant_execution: durableApprouve, fin: finApprouve });

    // Échange de modèle déclaré (EX-6.8), format gemini, réponse en morceaux.
    const echange = await session.echangeModele({
      format: "gemini",
      providerLabel: "gemini",
      request: { model: "models/gemini-exemple", contents: [{ role: "user", parts: [{ text: "Ouvre le sinistre 2026-81044." }] }], systemInstruction: { parts: [{ text: "Tu es l'agent sinistres." }] } },
      response: [
        { candidates: [{ content: { role: "model", parts: [{ text: "Je consulte " }] } }], modelVersion: "gemini-exemple-001" },
        { candidates: [{ content: { role: "model", parts: [{ text: "le sinistre." }] }, finishReason: "STOP" }], modelVersion: "gemini-exemple-001", sdkHttpResponse: { headers: {} } },
      ],
      status: 200,
      durationMs: 812,
      isError: false,
    });
    ecrire({ etape: "echange", scelle: echange });

    // Exportateur minimal en protobuf : un span d'inférence et un span d'outil, après coup.
    const otlp = await exporter([
      spanInference("modele-otel-1", { attributs: { "gen_ai.output.messages": JSON.stringify([{ role: "assistant", parts: [{ type: "text", content: "Je classe le dossier." }] }]) } }),
      spanOutil("classer_dossier", { attributs: { "gen_ai.tool.call.arguments": '{"dossier":"2026-77812"}', "gen_ai.tool.call.result": '{"ok":true}' } }),
    ]);
    ecrire({ etape: "otel", reponse: otlp });

    // Exportateur officiel OTLP/HTTP du SDK OpenTelemetry JavaScript.
    ecrire({ etape: "otel_officiel", resultat: await exporterOfficiel() });

    // Fermeture avec un appel d'écriture resté ouvert : événement de reprise (EX-12.15).
    const ouvert = await session.debutAppel({ tool: "ecrire_note", arguments: { sinistre: "2026-77812", note: "agent interrompu" }, classe: "ecriture" });
    ecrire({ etape: "ouvert", debut: ouvert });
  } finally {
    await session.fermer();
    ecrire({ etape: "fermee" });
    lignes.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await principal();
