"""Adaptateur du SDK Agents d'OpenAI, Python (CT-2 6.6) : les cinq essais
obligatoires d'EX-6.20 et un agent réel ``Runner.run`` (``openai-agents``
0.24.0) dont le modèle passe par la passerelle du démon réel
(``OpenAIChatCompletionsModel`` sur ``/v1/chat/completions``, fournisseur
simulé, ``modele="passerelle"``), qui appelle un outil de fonction local et
un outil MCP de ``mcp_servers`` passé par le frontal MCP. Pour les essais (i) à
(iii) et (v), le modèle est un ``Model`` de test (le démon arrêté arrêterait
aussi la passerelle)."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, List

import pytest

from conftest import EspionAsync, evenements_outil, exiger, verifier_parcours

exiger("agents")

from agents import Agent, ModelResponse, Runner, Usage, function_tool, set_trace_processors, set_tracing_disabled  # noqa: E402
from agents.models.interface import Model  # noqa: E402
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText  # noqa: E402

from noortrace_sdk import ClientNoortrace, ClientNoortraceAsync  # noqa: E402
from noortrace_sdk.adaptateurs import TEXTE_INJOIGNABLE  # noqa: E402
from noortrace_sdk.adaptateurs.openai_agents import AdaptateurAgentsOpenAI, analyser_arguments  # noqa: E402

ALIAS = "agent-py"
ARGS = {"sinistre": "2026-77812", "montant": "7400.00", "devise": "CHF"}
set_tracing_disabled(True)


class ModeleScenario(Model):
    """``Model`` de test : un appel d'outil par tour, puis un message final ; note ses entrées."""

    def __init__(self, appels: List[tuple]) -> None:
        self.appels = list(appels)
        self.vus: List[Any] = []

    async def get_response(self, system_instructions, input, model_settings, tools, output_schema, handoffs, tracing, **k):  # noqa: A002
        self.vus.append(input if isinstance(input, str) else list(input))
        sorties = [x for x in (input if isinstance(input, list) else []) if isinstance(x, dict) and x.get("type") == "function_call_output"]
        tour = len(sorties)
        if tour < len(self.appels):
            nom, args = self.appels[tour]
            out = [ResponseFunctionToolCall(arguments=json.dumps(args), call_id=f"call_{tour}", name=nom, type="function_call", id=f"fc_{tour}", status="completed")]
        else:
            out = [ResponseOutputMessage(id="msg_f", role="assistant", status="completed", type="message", content=[ResponseOutputText(text="fini", type="output_text", annotations=[])])]
        return ModelResponse(output=out, usage=Usage(), response_id=None)

    def stream_response(self, *a, **k):
        raise NotImplementedError

    def recu(self, tour: int) -> str:
        for entree in self.vus:
            sorties = [x for x in (entree if isinstance(entree, list) else []) if isinstance(x, dict) and x.get("type") == "function_call_output"]
            if len(sorties) > tour:
                return sorties[tour]["output"]
        raise AssertionError("résultat non reçu par le modèle")


class Trace:
    def __init__(self) -> None:
        self.departs: List[tuple] = []

    def outils(self):
        trace = self

        @function_tool
        def preparer_paiement(sinistre: str, montant: str, devise: str) -> str:
            """Prépare un ordre de paiement (outil local d'écriture)."""
            trace.departs.append(("preparer_paiement", time.monotonic()))
            return f"ORD-{sinistre}"

        @function_tool
        def approuver_paiement(montant: str) -> str:
            """Paiement soumis à approbation."""
            trace.departs.append(("approuver_paiement", time.monotonic()))
            return "paye"

        @function_tool
        async def lire_sinistre(sinistre: str) -> str:
            """Lit un sinistre."""
            trace.departs.append(("lire_sinistre", time.monotonic()))
            return f"sinistre {sinistre} ouvert"

        return [preparer_paiement, approuver_paiement, lire_sinistre]


def adaptateur(session, **k):
    return AdaptateurAgentsOpenAI(session, classes={"preparer_paiement": "ecriture", "lire_sinistre": "lecture"}, **k)


async def lancer(adapt, modele, outils, mcp_servers=()):
    agent = adapt.envelopper_agent(Agent(name="agent-sinistres", instructions="Essai.", tools=outils, mcp_servers=list(mcp_servers), model=modele))
    return await Runner.run(agent, "Traite le sinistre 2026-77812.")


def test_i_demon_arrete_ecriture_non_executee(banc):
    trace = Trace()
    m = ModeleScenario([("preparer_paiement", ARGS)])

    async def principal():
        session = await ClientNoortraceAsync(socket=banc.socket, delai_s=2, reprises=0).ouvrir(run_id="run-oa-i")
        banc.arreter()
        try:
            await lancer(adaptateur(session), m, trace.outils())
        finally:
            banc.demarrer()

    asyncio.run(principal())
    assert trace.departs == []
    assert m.recu(0) == TEXTE_INJOIGNABLE


def test_ii_a_approuver_signal_exact(banc):
    trace = Trace()
    m = ModeleScenario([("approuver_paiement", {"montant": "9100.00"})])

    async def principal():
        async with ClientNoortraceAsync(socket=banc.socket, delai_s=10).ouvrir(run_id="run-oa-ii") as session:
            espion = EspionAsync(session)
            await lancer(adaptateur(espion), m, trace.outils())
            return espion

    espion = asyncio.run(principal())
    assert trace.departs == []
    d = espion.debuts[0]
    assert d.decision == "a_approuver" and d.ticket_state == "nouveau"
    assert m.recu(0) == f"noortrace: appel soumis a approbation ; ticket={d.ticket} ; state=nouveau"


def test_iii_debut_appel_precede_l_outil(banc):
    trace = Trace()

    async def principal():
        async with ClientNoortraceAsync(socket=banc.socket, delai_s=10).ouvrir(run_id="run-oa-iii") as session:
            espion = EspionAsync(session)
            await lancer(adaptateur(espion), ModeleScenario([("preparer_paiement", ARGS)]), trace.outils())
            return espion

    espion = asyncio.run(principal())
    assert len(trace.departs) == 1 and len(espion.reponses) == 1
    assert espion.reponses[0] <= trace.departs[0][1]


def chat(n: int, nom: str, args: dict) -> dict:
    return {"id": f"chatcmpl-essai-{n}", "object": "chat.completion", "created": 1794306000, "model": "modele-chat",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": None, "tool_calls": [{"id": f"call_{n}", "type": "function", "function": {"name": nom, "arguments": json.dumps(args)}}]}, "finish_reason": "tool_calls"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}


FIN = {"id": "chatcmpl-essai-fin", "object": "chat.completion", "created": 1794306000, "model": "modele-chat",
       "choices": [{"index": 0, "message": {"role": "assistant", "content": "fini"}, "finish_reason": "stop"}],
       "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}


def test_iv_agent_reel_passerelle_outil_local_et_outil_mcp_un_evenement_par_appel(banc):
    from agents import OpenAIChatCompletionsModel
    from agents.mcp import MCPServerStreamableHttp
    from openai import AsyncOpenAI

    trace = Trace()
    banc.commande(cmd="scenario", reponses=[chat(0, "preparer_paiement", ARGS), chat(1, "demo__claims.get", {"claim_id": "2026-77812"}),
                                            chat(2, "lire_sinistre", {"sinistre": "2026-77812"}), FIN])
    avant = banc.evenements()
    n_requetes = len(banc.commande(cmd="requetes_fournisseur")["requetes"])

    async def principal():
        async with ClientNoortraceAsync(socket=banc.socket, delai_s=10).ouvrir(run_id="run-oa-iv") as session, \
                MCPServerStreamableHttp(name="noortrace", params={"url": banc.info["mcp_url"], "headers": {"Authorization": f"Bearer {banc.info['mcp_jeton']}"}, "timeout": 10}, cache_tools_list=True) as serveur:
            modele = OpenAIChatCompletionsModel(model="modele-chat", openai_client=AsyncOpenAI(base_url=banc.info["passerelle_url"] + "/v1", api_key=banc.info["passerelle_jeton"], max_retries=0))
            r = await lancer(adaptateur(session), modele, trace.outils(), mcp_servers=[serveur])
            return r.final_output

    assert asyncio.run(principal()) == "fini"
    assert [n for n, _ in trace.departs] == ["preparer_paiement", "lire_sinistre"]
    requetes = banc.commande(cmd="requetes_fournisseur")["requetes"][n_requetes:]
    outils_recus = [m["content"] for m in requetes[-1]["corps"]["messages"] if m.get("role") == "tool"]
    assert outils_recus[0] == "ORD-2026-77812" and "Sinistre 2026-77812 : ouvert" in json.dumps(outils_recus[1], ensure_ascii=False)
    # L'événement d'un échange relayé est scellé après le relais de la réponse (5.3.1) : attente bornée.
    fin = time.monotonic() + 10
    while True:
        nouveaux = banc.evenements()[len(avant):]
        if len(evenements_outil(nouveaux, "noortrace.modele.echange")) >= 4 or time.monotonic() > fin:
            break
        time.sleep(0.05)
    outils = [e["execution"]["tool"] for e in nouveaux if not e["execution"]["tool"].startswith("noortrace.")]
    assert sorted(outils) == sorted([f"{ALIAS}__preparer_paiement", "demo__claims.get", f"{ALIAS}__lire_sinistre"])
    # Quatre échanges de modèle, journalisés par la passerelle (EX-6.17 : modele="passerelle"), context vide.
    echanges = evenements_outil(nouveaux, "noortrace.modele.echange")
    assert len(echanges) == 4 and all(e["context"] == [] for e in echanges)
    local = evenements_outil(nouveaux, f"{ALIAS}__preparer_paiement")[0]
    assert local["execution"]["status"] == "executee"
    verifier_parcours(banc, local["seq"], "openai-agents")


def test_v_exception_de_l_adaptateur_outil_non_execute(banc, monkeypatch):
    trace = Trace()
    m = ModeleScenario([("preparer_paiement", ARGS)])

    def panne(self, outil, texte):
        raise RuntimeError("exception injectee dans l'adaptateur")

    async def principal():
        async with ClientNoortraceAsync(socket=banc.socket, delai_s=10).ouvrir(run_id="run-oa-v") as session:
            monkeypatch.setattr(AdaptateurAgentsOpenAI, "_preparer", panne)
            await lancer(adaptateur(session), m, trace.outils())

    asyncio.run(principal())
    assert trace.departs == []
    assert m.recu(0) == TEXTE_INJOIGNABLE


def test_session_synchrone_arguments_et_echanges_declares(banc):
    """Session du client synchrone (appels par ``asyncio.to_thread``) et processeur de traces
    (``modele="declarer"``) : le modèle de l'essai passe aussi par la passerelle, pour que
    ses spans de génération existent ; chaque échange a alors deux événements (celui de la
    passerelle, ``context`` vide, et la déclaration, ``context[0]`` du SDK), ce qu'une
    intégration réelle évite (EX-6.17 : ``declarer`` seulement hors passerelle)."""
    from agents import OpenAIChatCompletionsModel
    from openai import AsyncOpenAI

    assert analyser_arguments('{"a": 1}') == {"a": 1}
    assert analyser_arguments("pas du json") == "pas du json"
    assert analyser_arguments('{"a": NaN}') == '{"a": NaN}'
    trace = Trace()
    banc.commande(cmd="scenario", reponses=[chat(0, "lire_sinistre", {"sinistre": "8"}), FIN])
    avant = banc.evenements()
    with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-oa-sync") as session:
        a = adaptateur(session, modele="declarer")
        set_trace_processors([a.processeur])
        set_tracing_disabled(False)
        try:
            modele = OpenAIChatCompletionsModel(model="modele-chat", openai_client=AsyncOpenAI(base_url=banc.info["passerelle_url"] + "/v1", api_key=banc.info["passerelle_jeton"], max_retries=0))
            asyncio.run(lancer(a, modele, trace.outils()))
        finally:
            set_tracing_disabled(True)
            set_trace_processors([])
        assert a.processeur.file.vide(10)
    fin = time.monotonic() + 10
    while True:
        nouveaux = banc.evenements()[len(avant):]
        echanges = evenements_outil(nouveaux, "noortrace.modele.echange")
        if len(echanges) >= 4 or time.monotonic() > fin:
            break
        time.sleep(0.05)
    assert [n for n, _ in trace.departs] == ["lire_sinistre"]
    assert len(evenements_outil(nouveaux, f"{ALIAS}__lire_sinistre")) == 1
    assert a.processeur.file.echanges_perdus == 0
    declares = [e for e in echanges if e["context"]]
    assert len(declares) == 2 and len(echanges) == 4
    assert all(e["code"]["model"] == "openai/modele-chat" for e in declares)
