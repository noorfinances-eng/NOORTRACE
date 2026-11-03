"""Adaptateur LlamaIndex (CT-2 6.6) : les cinq essais obligatoires d'EX-6.20 et
un agent réel ``FunctionAgent`` (``llama-index-core`` 0.14.25) qui appelle un
outil local enveloppé et un outil MCP de ``McpToolSpec``
(``llama-index-tools-mcp`` 0.6.0) passé par le frontal MCP du démon réel. Le
modèle est le modèle factice du cadre (``MockFunctionCallingLLM``), muni d'un
générateur de réponses qui rejoue un scénario d'appels d'outils et note ce
qu'il reçoit."""

from __future__ import annotations

import asyncio
import time
from typing import Any, List

import pytest

from conftest import EspionAsync, evenements_outil, exiger, verifier_parcours

exiger("llama_index.core")

from llama_index.core.agent.workflow import FunctionAgent  # noqa: E402
from llama_index.core.base.llms.types import ChatMessage, MessageRole, ToolCallBlock  # noqa: E402
from llama_index.core.llms.mock import MockFunctionCallingLLM  # noqa: E402
from llama_index.core.tools import FunctionTool  # noqa: E402

from noortrace_sdk import ClientNoortrace, ClientNoortraceAsync  # noqa: E402
from noortrace_sdk.adaptateurs import TEXTE_INJOIGNABLE  # noqa: E402
from noortrace_sdk.adaptateurs.llamaindex import AdaptateurLlamaIndex, OutilNoortrace, est_outil_mcp  # noqa: E402

ALIAS = "agent-py"
ARGS = {"sinistre": "2026-77812", "montant": "7400.00", "devise": "CHF"}


class Scenario:
    """Générateur de réponses du modèle factice : un appel d'outil par tour, puis une conclusion."""

    def __init__(self, appels: List[tuple]) -> None:
        self.appels = list(appels)
        self.vus: List[list] = []

    def __call__(self, messages, **kwargs):
        self.vus.append(list(messages))
        tour = len([m for m in messages if m.role == MessageRole.TOOL])
        if tour < len(self.appels):
            nom, args = self.appels[tour]
            return ChatMessage(role=MessageRole.ASSISTANT, blocks=[ToolCallBlock(tool_call_id=f"call_{tour}", tool_name=nom, tool_kwargs=args)])
        return ChatMessage(role=MessageRole.ASSISTANT, content="fini")

    def recu(self, tour: int) -> str:
        for liste in self.vus:
            outils = [m for m in liste if m.role == MessageRole.TOOL]
            if len(outils) > tour:
                return outils[tour].content
        raise AssertionError("résultat non reçu par le modèle")


class Trace:
    def __init__(self) -> None:
        self.departs: List[tuple] = []

    def outils(self):
        trace = self

        def preparer_paiement(sinistre: str, montant: str, devise: str) -> dict:
            """Prépare un ordre de paiement (outil local d'écriture)."""
            trace.departs.append(("preparer_paiement", time.monotonic()))
            return {"ordre": f"ORD-{sinistre}"}

        def approuver_paiement(montant: str) -> str:
            """Paiement soumis à approbation."""
            trace.departs.append(("approuver_paiement", time.monotonic()))
            return "paye"

        async def lire_sinistre(sinistre: str) -> str:
            """Lit un sinistre."""
            trace.departs.append(("lire_sinistre", time.monotonic()))
            return f"sinistre {sinistre} ouvert"

        return [FunctionTool.from_defaults(fn=preparer_paiement), FunctionTool.from_defaults(fn=approuver_paiement),
                FunctionTool.from_defaults(async_fn=lire_sinistre, name="lire_sinistre")]


def adaptateur(session, **k):
    return AdaptateurLlamaIndex(session, classes={"preparer_paiement": "ecriture", "lire_sinistre": "lecture"}, **k)


async def lancer(adapt, scenario, outils, extra=()):
    agent = FunctionAgent(tools=[*adapt.envelopper(outils), *extra], llm=MockFunctionCallingLLM(response_generator=scenario), system_prompt="Essai.")
    return await agent.run(user_msg="Traite le sinistre 2026-77812.")


def test_i_demon_arrete_ecriture_non_executee(banc):
    trace = Trace()
    sc = Scenario([("preparer_paiement", ARGS)])

    async def principal():
        session = await ClientNoortraceAsync(socket=banc.socket, delai_s=2, reprises=0).ouvrir(run_id="run-li-i")
        banc.arreter()
        try:
            await lancer(adaptateur(session), sc, trace.outils())
        finally:
            banc.demarrer()

    asyncio.run(principal())
    assert trace.departs == []
    assert sc.recu(0) == TEXTE_INJOIGNABLE


def test_ii_a_approuver_signal_exact(banc):
    trace = Trace()
    sc = Scenario([("approuver_paiement", {"montant": "9100.00"})])

    async def principal():
        async with ClientNoortraceAsync(socket=banc.socket, delai_s=10).ouvrir(run_id="run-li-ii") as session:
            espion = EspionAsync(session)
            await lancer(adaptateur(espion), sc, trace.outils())
            return espion

    espion = asyncio.run(principal())
    assert trace.departs == []
    d = espion.debuts[0]
    assert d.decision == "a_approuver" and d.ticket_state == "nouveau"
    assert sc.recu(0) == f"noortrace: appel soumis a approbation ; ticket={d.ticket} ; state=nouveau"


def test_iii_debut_appel_precede_l_outil(banc):
    trace = Trace()

    async def principal():
        async with ClientNoortraceAsync(socket=banc.socket, delai_s=10).ouvrir(run_id="run-li-iii") as session:
            espion = EspionAsync(session)
            await lancer(adaptateur(espion), Scenario([("preparer_paiement", ARGS)]), trace.outils())
            return espion

    espion = asyncio.run(principal())
    assert len(trace.departs) == 1 and len(espion.reponses) == 1
    assert espion.reponses[0] <= trace.departs[0][1]


def test_iv_agent_reel_outil_local_et_outil_mcp_un_evenement_par_appel(banc):
    from llama_index.tools.mcp import BasicMCPClient, McpToolSpec

    trace = Trace()
    sc = Scenario([("preparer_paiement", ARGS), ("demo__claims.get", {"claim_id": "2026-77812"}), ("lire_sinistre", {"sinistre": "2026-77812"})])
    avant = banc.evenements()

    async def principal():
        async with ClientNoortraceAsync(socket=banc.socket, delai_s=10).ouvrir(run_id="run-li-iv") as session:
            client = BasicMCPClient(banc.info["mcp_url"], headers={"Authorization": f"Bearer {banc.info['mcp_jeton']}"})
            outils_mcp = await McpToolSpec(client=client).to_tool_list_async()
            assert all(est_outil_mcp(o) for o in outils_mcp)
            a = adaptateur(session)
            # Même passés à l'adaptateur, les outils MCP ne sont pas enveloppés (EX-6.17).
            assert not any(isinstance(o, OutilNoortrace) for o in a.envelopper(outils_mcp))
            await lancer(a, sc, trace.outils(), extra=outils_mcp)

    asyncio.run(principal())
    assert [n for n, _ in trace.departs] == ["preparer_paiement", "lire_sinistre"]
    assert "Sinistre 2026-77812 : ouvert" in sc.recu(1)
    nouveaux = banc.evenements()[len(avant):]
    outils = [e["execution"]["tool"] for e in nouveaux if not e["execution"]["tool"].startswith("noortrace.")]
    assert sorted(outils) == sorted([f"{ALIAS}__preparer_paiement", "demo__claims.get", f"{ALIAS}__lire_sinistre"])
    local = evenements_outil(nouveaux, f"{ALIAS}__preparer_paiement")[0]
    assert local["execution"]["status"] == "executee" and local["execution"]["is_error"] is False
    verifier_parcours(banc, local["seq"], "llamaindex")


def test_v_exception_de_l_adaptateur_outil_non_execute(banc, monkeypatch):
    trace = Trace()
    sc = Scenario([("preparer_paiement", ARGS)])

    def panne(self, args, kwargs):
        raise RuntimeError("exception injectee dans l'adaptateur")

    async def principal():
        async with ClientNoortraceAsync(socket=banc.socket, delai_s=10).ouvrir(run_id="run-li-v") as session:
            monkeypatch.setattr(OutilNoortrace, "_preparer", panne)
            await lancer(adaptateur(session), sc, trace.outils())

    asyncio.run(principal())
    assert trace.departs == []
    assert sc.recu(0) == TEXTE_INJOIGNABLE


def test_appel_synchrone_et_echanges_declares(banc):
    trace = Trace()
    with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-li-sync") as session:
        a = adaptateur(session)
        outil = a.envelopper(trace.outils())[0]
        sortie = outil.call(**ARGS)
        assert sortie.raw_output == {"ordre": "ORD-2026-77812"} and not sortie.is_error
    avant = banc.evenements()

    async def principal():
        async with ClientNoortraceAsync(socket=banc.socket, delai_s=10).ouvrir(run_id="run-li-declarer") as session:
            a = adaptateur(session, modele="declarer", ignorer=["lire_sinistre"])
            try:
                await lancer(a, Scenario([("lire_sinistre", {"sinistre": "7"})]), trace.outils())
                await a.gestionnaire.file.vide()
                return a.gestionnaire.file.echanges_perdus
            finally:
                a.retirer()

    perdus = asyncio.run(principal())
    nouveaux = banc.evenements()[len(avant):]
    assert perdus == 0
    assert evenements_outil(nouveaux, f"{ALIAS}__lire_sinistre") == []
    assert len(evenements_outil(nouveaux, "noortrace.modele.echange")) == 2
