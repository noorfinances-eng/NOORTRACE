#!/usr/bin/env node
// Agent instrumenté OpenTelemetry du scénario d'intégration CT-9 TI-11, en
// JavaScript : `@opentelemetry/sdk-trace-base` 2.12.0 et
// `@opentelemetry/exporter-trace-otlp-http` 0.223.0 (OTLP/HTTP **JSON**, les
// paquets du verrou du dépôt ; CT-2 §19.5.11 nomme `@opentelemetry/sdk-node`
// 0.300.0 et `exporter-trace-otlp-proto` 0.300.0, absents du verrou). Il est
// configuré par le seul environnement de CT-2 6.8.15
// (`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_TRACES_HEADERS`,
// `OTEL_TRACES_SAMPLER=always_on`, `OTEL_EXPORTER_OTLP_TRACES_TIMEOUT` en
// millisecondes), ce que ce fichier d'intégration dit « à tester en phase 2 ».
// Il émet les spans GenAI du scénario de CT-2 §19.2 (trois inférences, deux
// outils), force l'export et écrit sa trace.
//
//   otel_agent.mjs  (variables : OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, OTEL_EXPORTER_OTLP_TRACES_HEADERS, AGENT_PREFIXE)
//
// Lancé seulement comme programme : Hardhat charge tout fichier JavaScript de test/ (fixtures comprises) ;
// chargé ainsi, l'agent ne crée ni fournisseur de traces global ni export (aucune connexion).

import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const require = createRequire(path.join(RACINE, "package.json"));
const { trace, SpanStatusCode } = require("@opentelemetry/api");
const { BasicTracerProvider, BatchSpanProcessor, AlwaysOnSampler } = require("@opentelemetry/sdk-trace-base");
const { OTLPTraceExporter } = require("@opentelemetry/exporter-trace-otlp-http");
const { resourceFromAttributes } = require("@opentelemetry/resources");

const MODELE = "modele-demo-1";
const SYSTEME = "Tu es l'agent sinistres de l'assureur de démonstration. Contact interne : support@assureur-demo.example (jamais communiqué).";
const DEMANDE = "Traite le sinistre 2026-81044.";
const ARGS_LECTURE = { claim_id: "2026-81044" };
const ARGS_ECRITURE = { claim_id: "2026-81044", amount: "7400.00", currency: "CHF", beneficiary_iban: "CH93 0076 2011 6238 5295 7" };
const RESULTAT_LECTURE = "Sinistre 2026-81044 : collision du 2026-11-02, dommages 7400.00 CHF, assuré joignable à j.dupont@assure.example ou au +41 44 123 45 67";
const RESULTAT_ECRITURE = { payment_id: "PAY-2026-90417" };
const prefixe = process.env.AGENT_PREFIXE ?? "js";

async function principal() {
  // L'exportateur lit l'adresse, les en-têtes et le délai dans l'environnement (6.8.15) : rien n'est passé ici.
  const exportateur = new OTLPTraceExporter();
  const fournisseur = new BasicTracerProvider({
    sampler: new AlwaysOnSampler(),
    resource: resourceFromAttributes({ "service.name": "agent-sinistres", "service.version": "0.1.0" }),
    spanProcessors: [new BatchSpanProcessor(exportateur)],
  });
  trace.setGlobalTracerProvider(fournisseur);
  const traceur = trace.getTracer("agent-sinistres.instrumentation", "1.0.0");
  const t = { sdk: `@opentelemetry/sdk-trace-base ${require("@opentelemetry/sdk-trace-base/package.json").version} ; @opentelemetry/exporter-trace-otlp-http ${require("@opentelemetry/exporter-trace-otlp-http/package.json").version}`, echanges: [], appels: [], fin: null, notes: { url: exportateur.url ?? process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT } };

  function inference(n, demande, parent) {
    const s = traceur.startSpan(`chat ${MODELE}`, undefined, parent);
    s.setAttributes({
      "gen_ai.operation.name": "chat", "gen_ai.provider.name": "anthropic", "gen_ai.request.model": MODELE, "gen_ai.response.model": MODELE,
      "gen_ai.response.id": `msg_otel_${prefixe}_${String(n).padStart(4, "0")}`, "gen_ai.usage.input_tokens": 512 + 100 * n, "gen_ai.usage.output_tokens": 48,
      "gen_ai.conversation.id": `conv-otel-${prefixe}-0001`,
      "gen_ai.system_instructions": JSON.stringify([{ type: "text", content: SYSTEME }]),
      "gen_ai.input.messages": JSON.stringify([{ role: "user", parts: [{ type: "text", content: DEMANDE }] }]),
      "gen_ai.output.messages": JSON.stringify([{ role: "assistant", parts: [{ type: "text", content: demande ? "Je consulte le dossier." : MODELE }, ...(demande ? [{ type: "tool_call", id: `toolu_otel_${prefixe}_${n}`, name: demande, arguments: demande.includes("claims") ? ARGS_LECTURE : ARGS_ECRITURE }] : [])], finish_reason: demande ? "tool_use" : "stop" }]),
    });
    s.setStatus({ code: SpanStatusCode.OK });
    s.end();
    t.echanges.push({ format: "otel", flux: false, modele: MODELE, demandes: demande ? [demande] : [] });
  }

  function outil(n, nom, args, resultat, parent) {
    const s = traceur.startSpan(`execute_tool ${nom}`, undefined, parent);
    s.setAttributes({ "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": nom, "gen_ai.tool.type": "function", "gen_ai.tool.call.id": `toolu_otel_${prefixe}_${n}`, "gen_ai.tool.call.arguments": JSON.stringify(args), "gen_ai.tool.call.result": JSON.stringify(resultat) });
    s.setStatus({ code: SpanStatusCode.OK });
    s.end();
    t.appels.push({ outil: nom, nom_modele: nom, arguments: args, resultat: JSON.stringify(resultat), is_error: false, emissions: 1, tickets: [], structured: null });
  }

  const { context } = require("@opentelemetry/api");
  const racine = traceur.startSpan("invoke_agent agent-sinistres");
  racine.setAttributes({ "gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "agent-sinistres" });
  const ctx = trace.setSpan(context.active(), racine);
  inference(1, "claims.get", ctx);
  outil(1, "claims.get", ARGS_LECTURE, RESULTAT_LECTURE, ctx);
  inference(2, "payments.create", ctx);
  outil(2, "payments.create", ARGS_ECRITURE, RESULTAT_ECRITURE, ctx);
  inference(3, null, ctx);
  racine.end();
  await fournisseur.forceFlush();
  await fournisseur.shutdown();
  t.fin = "export forcé";
  process.stdout.write(`agent : spans exportés en OTLP/HTTP JSON vers ${t.notes.url}\n`);
  process.stdout.write(`noortrace-agent ${JSON.stringify(t)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await principal();
