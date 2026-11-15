"""Agent instrumenté OpenTelemetry du scénario d'intégration CT-9 TI-11
(CT-2 §19.5.11, 6.8.15) : SDK ``opentelemetry-sdk`` 1.45.1 et exportateur
``opentelemetry-exporter-otlp-proto-http`` 1.45.1 (OTLP/HTTP **protobuf**),
``TracerProvider(sampler=ALWAYS_ON)``, ``BatchSpanProcessor(OTLPSpanExporter(
endpoint=<démon>/v1/traces, headers={"x-noortrace-token": …}, timeout=30))``,
le code même de 19.5.11. L'agent émet les spans des conventions GenAI du
scénario de CT-2 §19.2 (trois inférences ``chat``, un ``execute_tool`` par
appel d'outil, contenu enregistré : ``gen_ai.tool.call.arguments`` et
``.result``), force l'export, et écrit les octets exacts de la requête OTLP
envoyée dans le fichier ``AGENT_OCTETS`` (l'essai la rejoue telle quelle :
doublon, EX-6.32).

Variables : NOORTRACE_OTEL_URL (adresse complète, ``/v1/traces`` compris),
NOORTRACE_OTEL_TOKEN, AGENT_OCTETS, AGENT_PREFIXE_TRACE (identifiants).
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import commun  # noqa: E402,F401

from opentelemetry import trace  # noqa: E402
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # noqa: E402
from opentelemetry.sdk.resources import Resource  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import BatchSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.sampling import ALWAYS_ON  # noqa: E402
from opentelemetry.sdk.version import __version__ as version_sdk  # noqa: E402

from commun import MODELE, Trace, dire, rapporter_echec  # noqa: E402

ARGS_LECTURE = {"claim_id": "2026-81044"}
ARGS_ECRITURE = {"claim_id": "2026-81044", "amount": "7400.00", "currency": "CHF", "beneficiary_iban": "CH93 0076 2011 6238 5295 7"}
RESULTAT_LECTURE = "Sinistre 2026-81044 : collision du 2026-11-02, dommages 7400.00 CHF, assuré joignable à j.dupont@assure.example ou au +41 44 123 45 67"
RESULTAT_ECRITURE = {"payment_id": "PAY-2026-90417"}


ENVOIS: list = []


def observer(exportateur: OTLPSpanExporter) -> OTLPSpanExporter:
    """Garde les octets de chaque requête que l'exportateur de 19.5.11 envoie
    (``export`` sérialise les spans puis les remet à son client HTTP)."""
    client = exportateur._client  # noqa: SLF001
    original = client.export

    def export(donnees, *a, **k):  # noqa: ANN001
        ENVOIS.append(bytes(donnees))
        return original(donnees, *a, **k)

    client.export = export
    return exportateur


def principal() -> int:
    url = os.environ["NOORTRACE_OTEL_URL"]
    jeton = os.environ["NOORTRACE_OTEL_TOKEN"]
    sortie = os.environ.get("AGENT_OCTETS")
    t = Trace(sdk=f"opentelemetry-sdk {version_sdk}")
    fournisseur = TracerProvider(sampler=ALWAYS_ON, resource=Resource.create({"service.name": "agent-sinistres", "service.version": "0.1.0"}))
    exportateur = observer(OTLPSpanExporter(endpoint=url, headers={"x-noortrace-token": jeton}, timeout=30))
    fournisseur.add_span_processor(BatchSpanProcessor(exportateur))
    trace.set_tracer_provider(fournisseur)
    traceur = trace.get_tracer("agent-sinistres.instrumentation", "1.0.0")

    def inference(n: int, demande: str | None) -> None:
        with traceur.start_as_current_span(f"chat {MODELE}") as s:
            s.set_attribute("gen_ai.operation.name", "chat")
            s.set_attribute("gen_ai.provider.name", "anthropic")
            s.set_attribute("gen_ai.request.model", MODELE)
            s.set_attribute("gen_ai.response.model", MODELE)
            s.set_attribute("gen_ai.response.id", f"msg_otel_{n:04d}")
            s.set_attribute("gen_ai.usage.input_tokens", 512 + 100 * n)
            s.set_attribute("gen_ai.usage.output_tokens", 48)
            s.set_attribute("gen_ai.response.finish_reasons", ["tool_use" if demande else "stop"])
            s.set_attribute("gen_ai.conversation.id", "conv-otel-0001")
            s.set_attribute("gen_ai.system_instructions", json.dumps([{"type": "text", "content": commun.SYSTEME}], ensure_ascii=False))
            s.set_attribute("gen_ai.input.messages", json.dumps([{"role": "user", "parts": [{"type": "text", "content": commun.DEMANDE}]}], ensure_ascii=False))
            parts = [{"type": "text", "content": "Je consulte le dossier." if demande else commun.MODELE}]
            if demande:
                parts.append({"type": "tool_call", "id": f"toolu_otel_{n:04d}", "name": demande, "arguments": ARGS_LECTURE if "claims" in demande else ARGS_ECRITURE})
            s.set_attribute("gen_ai.output.messages", json.dumps([{"role": "assistant", "parts": parts, "finish_reason": "tool_use" if demande else "stop"}], ensure_ascii=False))
            t.echange(format="otel", flux=False, modele=MODELE, demandes=[demande] if demande else [])

    def outil(n: int, nom: str, args: dict, resultat, erreur: bool = False) -> None:
        with traceur.start_as_current_span(f"execute_tool {nom}") as s:
            s.set_attribute("gen_ai.operation.name", "execute_tool")
            s.set_attribute("gen_ai.tool.name", nom)
            s.set_attribute("gen_ai.tool.type", "function")
            s.set_attribute("gen_ai.tool.call.id", f"toolu_otel_{n:04d}")
            s.set_attribute("gen_ai.tool.call.arguments", json.dumps(args, ensure_ascii=False))
            s.set_attribute("gen_ai.tool.call.result", json.dumps(resultat, ensure_ascii=False))
            if erreur:
                s.set_attribute("error.type", "approval_pending")
                s.set_status(trace.StatusCode.ERROR, "en attente d'approbation")
            t.appels.append(commun.Appel(outil=nom, nom_modele=nom, arguments=args, resultat=json.dumps(resultat, ensure_ascii=False), is_error=erreur, emissions=1))

    with traceur.start_as_current_span("invoke_agent agent-sinistres") as racine:
        racine.set_attribute("gen_ai.operation.name", "invoke_agent")
        racine.set_attribute("gen_ai.agent.name", "agent-sinistres")
        inference(1, "claims.get")
        outil(1, "claims.get", ARGS_LECTURE, RESULTAT_LECTURE)
        inference(2, "payments.create")
        outil(2, "payments.create", ARGS_ECRITURE, RESULTAT_ECRITURE)
        inference(3, None)
    ok = fournisseur.force_flush(30000)
    fournisseur.shutdown()
    t.fin = "export forcé" if ok else "export incomplet"
    t.notes["envois"] = len(ENVOIS)
    t.notes["octets"] = [len(x) for x in ENVOIS]
    if sortie and ENVOIS:
        with open(sortie, "wb") as f:
            f.write(ENVOIS[0])
        t.notes["fichier_octets"] = sortie
    dire(f"spans exportés en {len(ENVOIS)} requête(s) OTLP/HTTP protobuf vers {url}")
    t.imprimer()
    return 0 if ok and ENVOIS else 1


if __name__ == "__main__":
    try:
        code = principal()
    except BaseException as e:  # noqa: BLE001
        rapporter_echec(e)
        code = 1
    sys.exit(code)
