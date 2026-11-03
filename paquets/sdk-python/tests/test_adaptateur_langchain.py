"""Adaptateur LangChain et LangGraph (CT-2 6.6) : les cinq essais obligatoires
d'EX-6.20 et un agent réel ``create_agent`` (``langchain`` 1.4.7,
``langgraph`` 1.2.17) qui appelle un outil local et un outil MCP passé par le
frontal MCP du démon réel. Le modèle est le modèle factice de LangChain
(``GenericFakeChatModel``), qui rejoue un scénario d'appels d'outils et note
ce qu'il reçoit."""

from __future__ import annotations

import asyncio
import time
import warnings
from typing import Any, List

import pytest

from conftest import EspionAsync, Espion, evenements_outil, exiger, verifier_parcours

exiger("langchain.agents")
warnings.filterwarnings("ignore", message=".*langchain.mcp.*")

from langchain.agents import create_agent  # noqa: E402
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel  # noqa: E402
from langchain_core.messages import AIMessage, ToolMessage  # noqa: E402
from langchain_core.tools import tool  # noqa: E402
from langgraph.prebuilt import ToolNode  # noqa: E402

from noortrace_sdk import ClientNoortrace, ClientNoortraceAsync  # noqa: E402
from noortrace_sdk.adaptateurs import TEXTE_ENTREE_INVALIDE, TEXTE_INJOIGNABLE  # noqa: E402
from noortrace_sdk.adaptateurs.langchain import MiddlewareNoortrace  # noqa: E402

ALIAS = "agent-py"


class ModeleScenario(GenericFakeChatModel):
    """Modèle factice : rejoue ses messages, note chaque liste de messages reçue."""

    vus: List[Any] = []

    def bind_tools(self, tools: Any, **kwargs: Any) -> "ModeleScenario":
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):  # type: ignore[override]
        self.vus.append(list(messages))
        return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)


def modele(*appels: tuple) -> ModeleScenario:
    """Scénario : un message par appel d'outil (nom, arguments), puis une conclusion."""
    messages = [AIMessage(content="", tool_calls=[{"name": n, "args": a, "id": f"call_{k}", "type": "tool_call"}]) for k, (n, a) in enumerate(appels)]
    return ModeleScenario(messages=iter(messages + [AIMessage(content="fin")]), vus=[])


def recu_par_le_modele(m: ModeleScenario, id_: str) -> ToolMessage:
    """``ToolMessage`` de l'appel ``id_`` tel que le modèle l'a reçu."""
    for liste in m.vus:
        for x in liste:
            if isinstance(x, ToolMessage) and x.tool_call_id == id_:
                return x
    raise AssertionError(f"aucun ToolMessage {id_} reçu par le modèle")


class Trace:
    """Outils de test qui notent leur instant de départ (horloge monotone)."""

    def __init__(self) -> None:
        self.departs: List[tuple] = []

    def outils(self):
        trace = self

        @tool
        def preparer_paiement(sinistre: str, montant: str, devise: str) -> dict:
            """Prépare un ordre de paiement (outil local d'écriture)."""
            trace.departs.append(("preparer_paiement", time.monotonic()))
            return {"ordre": f"ORD-{sinistre}", "montant": montant, "devise": devise}

        @tool
        def approuver_paiement(montant: str) -> str:
            """Paiement soumis à approbation."""
            trace.departs.append(("approuver_paiement", time.monotonic()))
            return "paye"

        @tool
        def lire_sinistre(sinistre: str) -> str:
            """Lit un sinistre (outil local de lecture)."""
            trace.departs.append(("lire_sinistre", time.monotonic()))
            return f"sinistre {sinistre} ouvert"

        return [preparer_paiement, approuver_paiement, lire_sinistre]


ARGS = {"sinistre": "2026-77812", "montant": "7400.00", "devise": "CHF"}


def executer_agent(session, m, outils, intergiciel=None):
    intergiciel = intergiciel or MiddlewareNoortrace(session, classes={"preparer_paiement": "ecriture", "lire_sinistre": "lecture"})
    agent = create_agent(m, outils, middleware=[intergiciel])
    return agent


# ---------------------------------------------------------------- EX-6.20 (i) à (v)


def test_i_demon_arrete_ecriture_non_executee(banc):
    trace = Trace()

    async def principal():
        client = ClientNoortraceAsync(socket=banc.socket, delai_s=2, reprises=0)
        session = await client.ouvrir(run_id="run-lc-i")
        m = modele(("preparer_paiement", ARGS))
        agent = executer_agent(session, m, trace.outils())
        banc.arreter()
        try:
            await agent.ainvoke({"messages": [("user", "Traite le sinistre 2026-77812.")]})
        finally:
            banc.demarrer()
        return m

    m = asyncio.run(principal())
    assert trace.departs == []
    r = recu_par_le_modele(m, "call_0")
    assert r.content == TEXTE_INJOIGNABLE == "noortrace: enregistreur injoignable" and r.status == "error"


def test_ii_a_approuver_signal_exact(banc):
    trace = Trace()

    async def principal():
        client = ClientNoortraceAsync(socket=banc.socket, delai_s=10)
        async with client.ouvrir(run_id="run-lc-ii") as session:
            espion = EspionAsync(session)
            m = modele(("approuver_paiement", {"montant": "9100.00"}))
            await executer_agent(espion, m, trace.outils()).ainvoke({"messages": [("user", "Paie.")]})
            return m, espion

    m, espion = asyncio.run(principal())
    assert trace.departs == []
    d = espion.debuts[0]
    assert d.decision == "a_approuver" and d.ticket_state == "nouveau"
    r = recu_par_le_modele(m, "call_0")
    assert r.content == f"noortrace: appel soumis a approbation ; ticket={d.ticket} ; state=nouveau" and r.status == "error"
    assert [e["execution"]["status"] for e in evenements_outil(banc.evenements(), f"{ALIAS}__approuver_paiement")] == ["retenue"]


def test_iii_debut_appel_precede_l_outil(banc):
    trace = Trace()

    async def principal():
        client = ClientNoortraceAsync(socket=banc.socket, delai_s=10)
        async with client.ouvrir(run_id="run-lc-iii") as session:
            espion = EspionAsync(session)
            await executer_agent(espion, modele(("preparer_paiement", ARGS)), trace.outils()).ainvoke({"messages": [("user", "x")]})
            return espion

    espion = asyncio.run(principal())
    assert len(trace.departs) == 1 and len(espion.reponses) == 1
    assert espion.reponses[0] <= trace.departs[0][1]


def test_iv_agent_reel_outil_local_et_outil_mcp_un_evenement_par_appel(banc):
    from fastmcp import Client
    from langchain.mcp import MCPAdapter

    trace = Trace()
    avant = banc.evenements()

    async def principal():
        client = ClientNoortraceAsync(socket=banc.socket, delai_s=10)
        async with client.ouvrir(run_id="run-lc-iv") as session, \
                MCPAdapter(Client(banc.info["mcp_url"], auth=banc.info["mcp_jeton"])) as mcp:
            outils_mcp = await mcp.list_tools()
            outils = [*trace.outils(), *outils_mcp]
            m = modele(("preparer_paiement", ARGS), ("demo__claims.get", {"claim_id": "2026-77812"}), ("lire_sinistre", {"sinistre": "2026-77812"}))
            agent = create_agent(m, outils, middleware=[MiddlewareNoortrace(session, classes={"preparer_paiement": "ecriture", "lire_sinistre": "lecture"})])
            await agent.ainvoke({"messages": [("user", "Traite le sinistre 2026-77812.")]})
            return m

    m = asyncio.run(principal())
    assert [n for n, _ in trace.departs] == ["preparer_paiement", "lire_sinistre"]
    assert "Sinistre 2026-77812 : ouvert" in str(recu_par_le_modele(m, "call_1").content)
    nouveaux = banc.evenements()[len(avant):]
    outils = [e["execution"]["tool"] for e in nouveaux if not e["execution"]["tool"].startswith("noortrace.")]
    assert sorted(outils) == sorted([f"{ALIAS}__preparer_paiement", "demo__claims.get", f"{ALIAS}__lire_sinistre"])
    local = evenements_outil(nouveaux, f"{ALIAS}__preparer_paiement")[0]
    assert local["execution"]["status"] == "executee" and local["execution"]["is_error"] is False
    assert local["delegation"]["run_id"] == "run-lc-iv"
    verifier_parcours(banc, local["seq"], "langchain")


def test_v_exception_de_l_adaptateur_outil_non_execute(banc, monkeypatch):
    trace = Trace()

    def panne(self, request):
        raise RuntimeError("exception injectee dans l'adaptateur")

    async def principal():
        client = ClientNoortraceAsync(socket=banc.socket, delai_s=10)
        async with client.ouvrir(run_id="run-lc-v") as session:
            m1 = modele(("preparer_paiement", ARGS))
            monkeypatch.setattr(MiddlewareNoortrace, "_preparer", panne)
            await executer_agent(session, m1, trace.outils()).ainvoke({"messages": [("user", "x")]})
            monkeypatch.undo()
            m2 = modele(("lire_sinistre", {"sinistre": "1"}))
            monkeypatch.setattr(MiddlewareNoortrace, "_laisser_passer", panne)
            await executer_agent(session, m2, trace.outils()).ainvoke({"messages": [("user", "x")]})
            monkeypatch.undo()
            return m1, m2

    m1, m2 = asyncio.run(principal())
    assert trace.departs == []
    assert recu_par_le_modele(m1, "call_0").content == TEXTE_INJOIGNABLE
    assert recu_par_le_modele(m2, "call_0").content == TEXTE_INJOIGNABLE


# ---------------------------------------------------------------- compléments


def test_chemin_synchrone_toolnode_et_nom_hors_motif(banc):
    trace = Trace()
    client = ClientNoortrace(socket=banc.socket, delai_s=10)
    with client.ouvrir(run_id="run-lc-sync") as session:
        mw = MiddlewareNoortrace(session, classes={"lire_sinistre": "lecture"})
        m = modele(("lire_sinistre", {"sinistre": "9"}))
        create_agent(m, trace.outils(), middleware=[mw]).invoke({"messages": [("user", "x")]})
        assert recu_par_le_modele(m, "call_0").content == "sinistre 9 ouvert"
        # Sans create_agent : ToolNode(wrap_tool_call=…, awrap_tool_call=…).
        noeud = ToolNode(trace.outils(), wrap_tool_call=mw.wrap_tool_call, awrap_tool_call=mw.awrap_tool_call)
        from langgraph.graph import END, START, MessagesState, StateGraph

        g = StateGraph(MessagesState)
        g.add_node("outils", noeud)
        g.add_edge(START, "outils")
        g.add_edge("outils", END)
        sortie = g.compile().invoke({"messages": [AIMessage(content="", tool_calls=[{"name": "lire_sinistre", "args": {"sinistre": "10"}, "id": "t1", "type": "tool_call"}])]})
        assert sortie["messages"][-1].content == "sinistre 10 ouvert"

        @tool("outil__double")
        def outil_double() -> str:
            """Nom hors du motif de 6.2."""
            trace.departs.append(("double", time.monotonic()))
            return "x"

        m2 = modele(("outil__double", {}))
        create_agent(m2, [outil_double], middleware=[mw]).invoke({"messages": [("user", "x")]})
        assert recu_par_le_modele(m2, "call_0").content == TEXTE_ENTREE_INVALIDE
    assert all(n != "double" for n, _ in trace.departs)
    evts = banc.evenements()
    assert len([e for e in evts if e["execution"]["tool"] == f"{ALIAS}__lire_sinistre" and e["delegation"]["run_id"] == "run-lc-sync"]) == 2


def test_ignorer_et_echanges_declares(banc):
    trace = Trace()
    avant = banc.evenements()

    async def principal():
        client = ClientNoortraceAsync(socket=banc.socket, delai_s=10)
        async with client.ouvrir(run_id="run-lc-declarer") as session:
            mw = MiddlewareNoortrace(session, classes={"lire_sinistre": "lecture"}, modele="declarer", ignorer=["lire_sinistre"])
            m = modele(("lire_sinistre", {"sinistre": "5"}))
            await create_agent(m, trace.outils(), middleware=[mw]).ainvoke({"messages": [("user", "x")]}, config={"callbacks": mw.rappels})
            await mw.rappels[0].file.vide()
            return mw

    mw = asyncio.run(principal())
    nouveaux = banc.evenements()[len(avant):]
    # Outil ignoré : exécuté, non déclaré (EX-6.17 (b)) ; deux échanges déclarés (format autre).
    assert [n for n, _ in trace.departs] == ["lire_sinistre"]
    assert evenements_outil(nouveaux, f"{ALIAS}__lire_sinistre") == []
    echanges = evenements_outil(nouveaux, "noortrace.modele.echange")
    assert len(echanges) == 2 and mw.rappels[0].file.echanges_perdus == 0
    assert all(len(e["context"]) >= 1 for e in echanges)
