"""Agent du scénario d'intégration CT-9 TI-7 : agent LangChain 1.4.7 /
LangGraph 1.2.17 (``create_agent``, CT-2 §19.5.5) dont le modèle passe par la
passerelle (``ChatOpenAI(base_url=…)`` de ``langchain-openai``, en flux), dont
les outils MCP viennent du frontal par ``langchain.mcp.MCPAdapter`` (client
``fastmcp``), et dont un outil local (``calculer_franchise``, fonction ``@tool``)
est déclaré par l'intergiciel ``MiddlewareNoortrace`` de CT-2 6.6
(``wrap_tool_call``), passé en dernier de la liste ``middleware``. Le scénario
est celui de CT-2 §19.2, l'outil local appelé entre la lecture et l'écriture
(le modèle simulé le demande dès qu'il est déclaré) ; le cadre mène la boucle,
le modèle simulé redemande l'appel soumis à approbation jusqu'à la décision.
Règle de non-double capture (EX-6.17, EX-19.5) : les outils issus de
``langchain.mcp`` portent la marque de leur origine et ne sont pas déclarés.

Variables : NOORTRACE_MCP_URL, NOORTRACE_MCP_TOKEN, NOORTRACE_GATEWAY_URL,
NOORTRACE_GATEWAY_TOKEN, NOORTRACE_SDK_SOCKET, NOORTRACE_RUN_ID, PYTHONPATH
(``paquets/sdk-python/src``).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import commun  # noqa: E402,F401  (chemin du SDK Python du dépôt)

import langchain  # noqa: E402
from fastmcp import Client  # noqa: E402
from langchain.agents import create_agent  # noqa: E402
from langchain.mcp import MCPAdapter  # noqa: E402
from langchain.tools import tool  # noqa: E402
from langchain_openai import ChatOpenAI  # noqa: E402

from noortrace_sdk import ClientNoortraceAsync  # noqa: E402
from noortrace_sdk.adaptateurs.langchain import MiddlewareNoortrace  # noqa: E402

from commun import DEMANDE, MODELE, SYSTEME, Appel, Trace, configuration, dire, rapporter_echec  # noqa: E402

LOCAL = []


@tool
def calculer_franchise(claim_id: str, amount: str) -> str:
    """Calcule la franchise applicable à un sinistre (outil local de lecture)."""
    LOCAL.append({"claim_id": claim_id, "amount": amount})
    return f"franchise de 500.00 CHF sur {amount} CHF pour le sinistre {claim_id}"


async def principal() -> int:
    cfg = configuration()
    trace = Trace(sdk=f"langchain {langchain.__version__}")
    modele = ChatOpenAI(model=MODELE, base_url=f"{cfg.passerelle_url}/v1", api_key=cfg.passerelle_jeton, default_headers={"X-Noortrace-Run-Id": cfg.run_id}, max_retries=0, streaming=True, timeout=120)
    client = ClientNoortraceAsync(socket=cfg.sdk_socket, delai_s=30)
    async with client.ouvrir(run_id=cfg.run_id) as session, MCPAdapter(Client(cfg.mcp_url, auth=cfg.mcp_jeton)) as mcp:
        outils_mcp = await mcp.list_tools()
        dire(f"outils MCP du frontal : {', '.join(t.name for t in outils_mcp)}")
        mw = MiddlewareNoortrace(session, classes={"calculer_franchise": "lecture"})
        agent = create_agent(modele, [*outils_mcp, calculer_franchise], system_prompt=SYSTEME, middleware=[mw])
        r = await agent.ainvoke({"messages": [("user", DEMANDE)]}, config={"recursion_limit": 40})
    messages = r["messages"]
    en_cours = {}
    signaux = []
    for m in messages:
        t = m.type if hasattr(m, "type") else None
        if t == "ai":
            demandes = [tc["name"] for tc in (m.tool_calls or [])]
            trace.echange(format="openai-chat", flux=True, modele=(m.response_metadata or {}).get("model_name") or (m.response_metadata or {}).get("model"), demandes=demandes)
            for tc in m.tool_calls or []:
                en_cours[tc["id"]] = (tc["name"], tc["args"])
            if not demandes:
                trace.fin = m.content if isinstance(m.content, str) else json.dumps(m.content, ensure_ascii=False)
        elif t == "tool" and m.tool_call_id in en_cours:
            nom, args = en_cours.pop(m.tool_call_id)
            texte = m.content if isinstance(m.content, str) else json.dumps(m.content, ensure_ascii=False)
            if "state=en_attente" in texte:
                signaux.append((nom, args, texte.split("ticket=")[1].split(" ")[0]))
                continue
            a = Appel(outil=nom, nom_modele=nom, arguments=args, resultat=texte, is_error=getattr(m, "status", None) == "error", emissions=1)
            # Les émissions précédentes du même appel, soumises à approbation, sont réunies à celle qui a abouti.
            for s_nom, s_args, ticket in [x for x in signaux if x[0] == nom and x[1] == args]:
                a.emissions += 1
                a.tickets.append(ticket)
            signaux = [x for x in signaux if not (x[0] == nom and x[1] == args)]
            trace.appels.append(a)
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
