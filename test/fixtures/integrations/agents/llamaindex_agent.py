"""Agent du scénario d'intégration CT-9 TI-9 : ``FunctionAgent`` de
``llama-index-core`` 0.14.25 (CT-2 §19.5.9) dont le modèle passe par la
passerelle (``OpenAI(api_base=…)`` de ``llama-index-llms-openai`` 0.8.3, route
``/v1/chat/completions``), dont les outils MCP viennent du frontal par
``McpToolSpec(BasicMCPClient(url, headers=…))`` (``llama-index-tools-mcp``
0.6.0) et dont un outil local (``FunctionTool`` ``calculer_franchise``) est
enveloppé par l'adaptateur LlamaIndex de CT-2 6.6 (``envelopper``). Scénario
de CT-2 §19.2 avec l'outil local entre la lecture et l'écriture ; le cadre
mène la boucle, le modèle simulé redemande l'appel soumis à approbation
jusqu'à la décision. Les outils issus de ``McpToolSpec`` ne sont pas
enveloppés (EX-6.17, EX-19.5). Les appels sont relevés par les événements
``ToolCallResult`` du flux de l'agent.

Variables : NOORTRACE_MCP_URL, NOORTRACE_MCP_TOKEN, NOORTRACE_GATEWAY_URL,
NOORTRACE_GATEWAY_TOKEN, NOORTRACE_SDK_SOCKET, NOORTRACE_RUN_ID, PYTHONPATH.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import commun  # noqa: E402,F401  (chemin du SDK Python du dépôt)

import llama_index.core  # noqa: E402
from llama_index.core.agent.workflow import AgentStream, FunctionAgent, ToolCallResult  # noqa: E402
from llama_index.core.base.llms.types import LLMMetadata  # noqa: E402
from llama_index.core.tools import FunctionTool  # noqa: E402
from llama_index.llms.openai import OpenAI  # noqa: E402
from llama_index.tools.mcp import BasicMCPClient, McpToolSpec  # noqa: E402

from noortrace_sdk import ClientNoortraceAsync  # noqa: E402
from noortrace_sdk.adaptateurs.llamaindex import AdaptateurLlamaIndex  # noqa: E402

from commun import DEMANDE, MODELE, SYSTEME, Appel, Trace, assainir, configuration, dire, rapporter_echec  # noqa: E402

LOCAL = []


class OpenAIPasserelle(OpenAI):
    """``OpenAI`` de LlamaIndex pour un modèle que sa table ne nomme pas (le simulateur) :
    les métadonnées sont données ici, le reste (``api_base`` → ``base_url``, appels de
    fonctions) est celui du paquet 0.8.3."""

    @property
    def metadata(self) -> LLMMetadata:  # noqa: D401
        return LLMMetadata(context_window=128000, num_output=1024, is_chat_model=True, is_function_calling_model=True, model_name=self.model)


def calculer_franchise(claim_id: str, amount: str) -> str:
    """Calcule la franchise applicable à un sinistre (outil local de lecture)."""
    LOCAL.append({"claim_id": claim_id, "amount": amount})
    return f"franchise de 500.00 CHF sur {amount} CHF pour le sinistre {claim_id}"


async def principal() -> int:
    cfg = configuration()
    trace = Trace(sdk=f"llama-index-core {llama_index.core.__version__}")
    llm = OpenAIPasserelle(model=MODELE, api_base=f"{cfg.passerelle_url}/v1", api_key=cfg.passerelle_jeton, default_headers={"X-Noortrace-Run-Id": cfg.run_id}, max_retries=0, timeout=120)
    client = ClientNoortraceAsync(socket=cfg.sdk_socket, delai_s=30)
    async with client.ouvrir(run_id=cfg.run_id) as session:
        adapt = AdaptateurLlamaIndex(session, classes={"calculer_franchise": "lecture"})
        mcp = BasicMCPClient(cfg.mcp_url, headers={"Authorization": f"Bearer {cfg.mcp_jeton}"})
        outils_mcp = await McpToolSpec(client=mcp).to_tool_list_async()
        dire(f"outils MCP du frontal : {', '.join(t.metadata.name for t in outils_mcp)}")
        # Le client OpenAI de LlamaIndex assainit les noms qu'il déclare au modèle (le motif
        # d'OpenAI exclut le point) mais FunctionAgent cherche l'outil sous son nom d'origine :
        # l'hôte déclare donc chaque outil MCP sous son nom assaini (EX-4.12, tool_name_sanitize
        # de la connexion d'hôte) ; l'appel MCP garde le nom annoncé (fermeture de McpToolSpec).
        from dataclasses import replace

        for t in outils_mcp:
            t._metadata = replace(t.metadata, name=assainir(t.metadata.name))  # noqa: SLF001
        local = FunctionTool.from_defaults(fn=calculer_franchise, name="calculer_franchise")
        agent = FunctionAgent(tools=[*outils_mcp, *adapt.envelopper([local])], llm=llm, system_prompt=SYSTEME)
        handler = agent.run(DEMANDE, max_iterations=40)
        appels = []
        async for ev in handler.stream_events():
            if isinstance(ev, ToolCallResult):
                sortie = ev.tool_output
                texte = sortie.content if hasattr(sortie, "content") else str(sortie)
                raw = getattr(sortie, "raw_output", None)
                if "state=en_attente" in texte:
                    appels.append(("signal", ev.tool_name, dict(ev.tool_kwargs), texte))
                    continue
                appels.append(("resultat", ev.tool_name, dict(ev.tool_kwargs), texte, getattr(sortie, "is_error", False), raw))
        resultat = await handler
        trace.fin = str(resultat)
    for a in appels:
        if a[0] == "signal":
            continue
        _, nom, args, texte, is_error, raw = a
        ta = Appel(outil=nom, nom_modele=nom, arguments=args, resultat=texte, is_error=bool(is_error), emissions=1)
        ta.emissions += sum(1 for s in appels if s[0] == "signal" and s[1] == nom and s[2] == args)
        ta.tickets = [s[3].split("ticket=")[1].split(" ")[0] for s in appels if s[0] == "signal" and s[1] == nom and s[2] == args]
        trace.appels.append(ta)
    trace.echanges = [{"format": "openai-chat", "flux": False, "modele": None, "demandes": []}]
    trace.notes["local"] = LOCAL
    dire(f"modèle (fin de tour) : {trace.fin}")
    trace.imprimer()
    return 0


if __name__ == "__main__":
    try:
        code = asyncio.run(principal())
    except BaseException as e:  # noqa: BLE001
        rapporter_echec(e)
        code = 1
    sys.exit(code)
