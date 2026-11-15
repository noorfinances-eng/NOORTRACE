"""Agent du scénario d'intégration CT-9 TI-8 : équipage CrewAI 1.15.30 (CT-2
§19.5.8, EX-6.21) dont le modèle passe par la passerelle (``LLM(model=
"openai/…", base_url=…, api_key=…)``, fournisseur natif OpenAI, route
``/v1/chat/completions``), dont les outils MCP viennent du frontal par
``mcps=[MCPServerHTTP(url, headers, cache_tools_list=True)]`` et dont un outil
local (``@tool calculer_franchise``) est déclaré par l'adaptateur CrewAI de
CT-2 6.6 : crochets ``before_tool_call`` et ``after_tool_call`` enregistrés en
dernier (``installer()``), outil enveloppé (``envelopper``). Scénario de CT-2
§19.2 avec l'outil local entre la lecture et l'écriture ; le cadre mène la
boucle, le modèle simulé redemande l'appel soumis à approbation jusqu'à la
décision. Un outil issu de ``mcps`` passe aussi par les crochets : l'adaptateur
le reconnaît et l'ignore (EX-6.17, EX-19.5). Les appels sont relevés par le
bus d'événements de CrewAI (``ToolUsageFinishedEvent``).

Variables : NOORTRACE_MCP_URL, NOORTRACE_MCP_TOKEN, NOORTRACE_GATEWAY_URL,
NOORTRACE_GATEWAY_TOKEN, NOORTRACE_SDK_SOCKET, NOORTRACE_RUN_ID, PYTHONPATH.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import commun  # noqa: E402,F401  (chemin du SDK Python du dépôt)
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")

import crewai  # noqa: E402
from crewai import LLM, Agent, Crew, Task  # noqa: E402
from crewai.events import crewai_event_bus  # noqa: E402
from crewai.events.types.tool_usage_events import ToolUsageErrorEvent, ToolUsageFinishedEvent  # noqa: E402
from crewai.mcp import MCPServerHTTP  # noqa: E402
from crewai.tools import tool  # noqa: E402

from noortrace_sdk import ClientNoortrace  # noqa: E402
from noortrace_sdk.adaptateurs.crewai import AdaptateurCrewAI  # noqa: E402

from commun import DEMANDE, MODELE, SYSTEME, Appel, Trace, configuration, dire, rapporter_echec  # noqa: E402

LOCAL = []


@tool("calculer_franchise")
def calculer_franchise(claim_id: str, amount: str) -> str:
    """Calcule la franchise applicable à un sinistre (outil local de lecture)."""
    LOCAL.append({"claim_id": claim_id, "amount": amount})
    return f"franchise de 500.00 CHF sur {amount} CHF pour le sinistre {claim_id}"


def principal() -> int:
    cfg = configuration()
    trace = Trace(sdk=f"crewai {crewai.__version__}")
    vus = []

    @crewai_event_bus.on(ToolUsageFinishedEvent)
    def _fini(source, event):
        vus.append(("fini", event.tool_name, event.tool_args, event.output))

    @crewai_event_bus.on(ToolUsageErrorEvent)
    def _erreur(source, event):
        vus.append(("erreur", event.tool_name, event.tool_args, str(getattr(event, "error", ""))))

    llm = LLM(model=f"openai/{MODELE}", base_url=f"{cfg.passerelle_url}/v1", api_key=cfg.passerelle_jeton, temperature=0)
    trace.notes["fonctions_natives"] = bool(llm.supports_function_calling())
    with ClientNoortrace(socket=cfg.sdk_socket, delai_s=30).ouvrir(run_id=cfg.run_id) as session:
        adapt = AdaptateurCrewAI(session, classes={"calculer_franchise": "lecture"}).installer()
        try:
            mcp = MCPServerHTTP(url=cfg.mcp_url, headers={"Authorization": f"Bearer {cfg.mcp_jeton}"}, cache_tools_list=True)
            agent = Agent(role="Gestionnaire de sinistres", goal="Traiter les sinistres de démonstration", backstory=SYSTEME, llm=llm, tools=adapt.envelopper([calculer_franchise]), mcps=[mcp], verbose=False, max_iter=20)
            tache = Task(description=DEMANDE, expected_output="Un compte rendu du règlement.", agent=agent)
            sortie = Crew(agents=[agent], tasks=[tache], verbose=False).kickoff()
        finally:
            adapt.desinstaller()
    trace.fin = str(sortie)
    for genre, nom, args, texte in vus:
        a = args if isinstance(args, dict) else {}
        if isinstance(args, str):
            try:
                a = json.loads(args)
            except Exception:  # noqa: BLE001
                a = {"input": args}
        t = texte if isinstance(texte, str) else json.dumps(texte, ensure_ascii=False)
        meme = next((x for x in trace.appels if x.outil == nom and x.arguments == a), None)
        if "state=en_attente" in t:
            if meme is None:
                meme = Appel(outil=nom, nom_modele=nom, arguments=a)
                trace.appels.append(meme)
            meme.emissions += 1
            meme.tickets.append(t.split("ticket=")[1].split(" ")[0])
            continue
        if meme is None:
            meme = Appel(outil=nom, nom_modele=nom, arguments=a)
            trace.appels.append(meme)
        meme.emissions += 1
        meme.resultat = t
        meme.is_error = genre == "erreur"
    trace.echanges = [{"format": "openai-chat", "flux": False, "modele": None, "demandes": []}]
    trace.notes["local"] = LOCAL
    dire(f"équipage (fin) : {trace.fin}")
    trace.imprimer()
    return 0


if __name__ == "__main__":
    try:
        code = principal()
    except BaseException as e:  # noqa: BLE001
        rapporter_echec(e)
        code = 1
    sys.exit(code)
