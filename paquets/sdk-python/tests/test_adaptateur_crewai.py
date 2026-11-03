"""Adaptateur CrewAI (CT-2 6.6, EX-6.21 ; LISEZMOI, lecture 168) : les cinq
essais obligatoires d'EX-6.20 et un agent réel ``Crew(...).kickoff()``
(``crewai`` 1.15.30) qui appelle un outil local et un outil MCP passé par le
frontal MCP du démon réel (``mcps=[MCPServerHTTP(...)]``), sur le chemin
natif (modèle à appels de fonctions) ; puis, sur les deux chemins (natif et
« ReAct »), exactement un événement par exécution réelle : réexécution d'un
outil qui a levé une exception, appel répété (``task_repeated_usage``),
``max_usage_count`` atteint, cache de l'équipage, ``is_error``. Les modèles
sont des ``BaseLLM`` de test qui rejouent un scénario et notent ce qu'ils
reçoivent ; ils émettent les événements de modèle de CrewAI."""

from __future__ import annotations

import json
import os
import time
from typing import Any, List

import pytest

from conftest import Espion, evenements_outil, exiger, verifier_parcours

os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
exiger("crewai")

from crewai import Agent, Crew, Task  # noqa: E402
from crewai.events.types.llm_events import LLMCallType  # noqa: E402
from crewai.hooks.tool_hooks import register_before_tool_call_hook, unregister_before_tool_call_hook  # noqa: E402
from crewai.tools import BaseTool  # noqa: E402
from crewai.llms.base_llm import BaseLLM  # noqa: E402
from crewai.mcp import MCPServerHTTP  # noqa: E402
from crewai.tools import tool  # noqa: E402

from noortrace_sdk import ClientNoortrace  # noqa: E402
from noortrace_sdk.adaptateurs import TEXTE_INJOIGNABLE  # noqa: E402
from noortrace_sdk.adaptateurs.crewai import AdaptateurCrewAI  # noqa: E402

ALIAS = "agent-py"
ARGS = {"sinistre": "2026-77812", "montant": "7400.00", "devise": "CHF"}


class LLMScenario(BaseLLM):
    """Modèle de test : un appel d'outil natif par tour, puis la réponse finale."""

    def __init__(self, appels: List[tuple], **k: Any) -> None:
        super().__init__(model="scenario/modele-crewai", **k)
        object.__setattr__(self, "_appels", list(appels))
        object.__setattr__(self, "vus", [])

    def supports_function_calling(self) -> bool:
        return True

    def call(self, messages, tools=None, callbacks=None, available_functions=None, from_task=None, from_agent=None, response_model=None):
        self.vus.append(list(messages))
        self._emit_call_started_event(messages=messages, tools=tools, from_task=from_task, from_agent=from_agent)
        noms = [t.get("function", {}).get("name") for t in (tools or [])]
        tour = len([m for m in messages if m.get("role") == "tool"])
        if tour < len(self._appels):
            nom, args = self._appels[tour]
            if callable(nom):
                nom = nom(noms)
            r: Any = [{"id": f"call_{tour}", "type": "function", "function": {"name": nom, "arguments": json.dumps(args)}}]
        else:
            r = "fini"
        self._emit_call_completed_event(response=r if isinstance(r, str) else json.dumps(r), call_type=LLMCallType.LLM_CALL, from_task=from_task, from_agent=from_agent, messages=messages)
        return r

    def recu(self, tour: int) -> str:
        """Contenu du résultat d'outil du tour ``tour`` tel que le modèle l'a reçu."""
        for liste in self.vus:
            outils = [m for m in liste if m.get("role") == "tool"]
            if len(outils) > tour:
                return outils[tour]["content"]
        raise AssertionError("résultat non reçu par le modèle")


class Trace:
    def __init__(self) -> None:
        self.departs: List[tuple] = []

    def outils(self):
        trace = self

        @tool("preparer_paiement")
        def preparer_paiement(sinistre: str, montant: str, devise: str) -> str:
            """Prépare un ordre de paiement (outil local d'écriture)."""
            trace.departs.append(("preparer_paiement", time.monotonic(), dict(sinistre=sinistre, montant=montant, devise=devise)))
            return f"ORD-{sinistre}"

        @tool("approuver_paiement")
        def approuver_paiement(montant: str) -> str:
            """Paiement soumis à approbation."""
            trace.departs.append(("approuver_paiement", time.monotonic(), None))
            return "paye"

        @tool("lire_sinistre")
        def lire_sinistre(sinistre: str) -> str:
            """Lit un sinistre."""
            trace.departs.append(("lire_sinistre", time.monotonic(), None))
            return f"sinistre {sinistre} ouvert"

        return [preparer_paiement, approuver_paiement, lire_sinistre]


def lancer(llm, outils, mcps=None, cache=False):
    agent = Agent(role="Gestionnaire de sinistres", goal="Traiter les sinistres", backstory="Essai.", llm=llm, tools=outils, mcps=mcps or [], verbose=False)
    tache = Task(description="Traite le sinistre 2026-77812.", expected_output="Un compte rendu.", agent=agent)
    return Crew(agents=[agent], tasks=[tache], cache=cache).kickoff()


class LLMReAct(BaseLLM):
    """Modèle de test sans appels de fonctions : chemin « ReAct » de CrewAI
    (``Action:`` / ``Action Input:``, puis ``Final Answer:``) ; note les observations reçues."""

    def __init__(self, actions: List[tuple], **k: Any) -> None:
        super().__init__(model="scenario/modele-react", **k)
        object.__setattr__(self, "_actions", list(actions))
        object.__setattr__(self, "vus", [])
        object.__setattr__(self, "_base", None)

    def supports_function_calling(self) -> bool:
        return False

    def call(self, messages, tools=None, callbacks=None, available_functions=None, from_task=None, from_agent=None, response_model=None):
        texte = json.dumps(messages, ensure_ascii=False)
        if self._base is None:
            object.__setattr__(self, "_base", texte.count("Observation:"))
        self.vus.append(list(messages))
        tour = texte.count("Observation:") - self._base
        if tour < len(self._actions):
            nom, args = self._actions[tour]
            return f"Thought: j'appelle l'outil\nAction: {nom}\nAction Input: {json.dumps(args)}"
        return "Thought: I now know the final answer\nFinal Answer: fini"

    def recu(self) -> str:
        """Tout ce que le modèle a reçu, en un texte."""
        return json.dumps(self.vus, ensure_ascii=False)


@pytest.fixture
def installe():
    adaptateurs = []

    def installer(session, **k):
        k.setdefault("classes", {"preparer_paiement": "ecriture", "lire_sinistre": "lecture"})
        a = AdaptateurCrewAI(session, **k).installer()
        adaptateurs.append(a)
        return a

    yield installer
    for a in adaptateurs:
        a.desinstaller()


def executions(banc, avant, nom):
    """Événements d'un outil du SDK depuis ``avant``."""
    return evenements_outil(banc.evenements()[len(avant):], f"{ALIAS}__{nom}")


def test_i_demon_arrete_ecriture_non_executee(banc, installe):
    trace = Trace()
    session = ClientNoortrace(socket=banc.socket, delai_s=2, reprises=0).ouvrir(run_id="run-crew-i")
    a = installe(session)
    llm = LLMScenario([("preparer_paiement", ARGS)])
    banc.arreter()
    try:
        lancer(llm, a.envelopper(trace.outils()))
    finally:
        banc.demarrer()
    assert trace.departs == []
    assert llm.recu(0) == TEXTE_INJOIGNABLE


def test_ii_a_approuver_signal_exact(banc, installe):
    trace = Trace()
    with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-crew-ii") as session:
        espion = Espion(session)
        a = installe(espion)
        llm = LLMScenario([("approuver_paiement", {"montant": "9100.00"})])
        lancer(llm, a.envelopper(trace.outils()))
    assert trace.departs == []
    d = espion.debuts[0]
    assert d.decision == "a_approuver" and d.ticket_state == "nouveau"
    assert llm.recu(0) == f"noortrace: appel soumis a approbation ; ticket={d.ticket} ; state=nouveau"


def test_iii_debut_appel_precede_l_outil(banc, installe):
    trace = Trace()
    with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-crew-iii") as session:
        espion = Espion(session)
        a = installe(espion)
        lancer(LLMScenario([("preparer_paiement", ARGS)]), a.envelopper(trace.outils()))
    assert len(trace.departs) == 1 and len(espion.reponses) == 1
    assert espion.reponses[0] <= trace.departs[0][1]


def test_iv_agent_reel_outil_local_et_outil_mcp_un_evenement_par_appel(banc, installe):
    trace = Trace()
    avant = banc.evenements()
    with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-crew-iv") as session:
        a = installe(session)
        mcp = MCPServerHTTP(url=banc.info["mcp_url"], headers={"Authorization": f"Bearer {banc.info['mcp_jeton']}"}, cache_tools_list=True)
        claims = lambda noms: next(n for n in noms if n.endswith("demo_claims_get"))  # noqa: E731
        llm = LLMScenario([("preparer_paiement", ARGS), (claims, {"claim_id": "2026-77812"}), ("lire_sinistre", {"sinistre": "2026-77812"})])
        lancer(llm, a.envelopper(trace.outils()), mcps=[mcp])
    assert [d[0] for d in trace.departs] == ["preparer_paiement", "lire_sinistre"]
    assert llm.recu(1) == "Sinistre 2026-77812 : ouvert"
    nouveaux = banc.evenements()[len(avant):]
    outils = [e["execution"]["tool"] for e in nouveaux if not e["execution"]["tool"].startswith("noortrace.")]
    assert sorted(outils) == sorted([f"{ALIAS}__preparer_paiement", "demo__claims.get", f"{ALIAS}__lire_sinistre"])
    local = evenements_outil(nouveaux, f"{ALIAS}__preparer_paiement")[0]
    assert local["execution"]["status"] == "executee" and local["execution"]["is_error"] is False
    verifier_parcours(banc, local["seq"], "crewai")


def test_v_exception_de_l_adaptateur_outil_non_execute(banc, installe, monkeypatch):
    trace = Trace()
    with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-crew-v") as session:
        a = installe(session)

        def panne(self, nom, args, kwargs):
            raise RuntimeError("exception injectee dans l'adaptateur")

        monkeypatch.setattr(AdaptateurCrewAI, "_preparer", panne)
        llm = LLMScenario([("preparer_paiement", ARGS)])
        lancer(llm, a.envelopper(trace.outils()))
        llm2 = LLMReAct([("lire_sinistre", {"sinistre": "3"})])
        lancer(llm2, a.envelopper(trace.outils()))
        monkeypatch.undo()
    assert trace.departs == []
    assert llm.recu(0) == TEXTE_INJOIGNABLE and TEXTE_INJOIGNABLE in llm2.recu()


# ---------------------------------------------------------------- compléments


def test_ordre_des_crochets_et_entree_modifiee(banc, installe):
    """EX-6.21 : enregistré après un crochet qui modifie ``tool_input`` en place,
    l'adaptateur déclare les arguments modifiés ; un crochet qui lève est avalé par CrewAI."""
    trace = Trace()

    def modifier(context):
        if context.tool_name == "preparer_paiement":
            context.tool_input["montant"] = "100.00"
        return None

    def defaillant(context):
        raise ValueError("crochet defaillant")

    register_before_tool_call_hook(modifier)
    register_before_tool_call_hook(defaillant)
    try:
        avant = banc.evenements()
        with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-crew-ordre") as session:
            a = installe(session)
            lancer(LLMScenario([("preparer_paiement", ARGS)]), a.envelopper(trace.outils()))
    finally:
        unregister_before_tool_call_hook(modifier)
        unregister_before_tool_call_hook(defaillant)
    assert trace.departs[0][2]["montant"] == "100.00"
    e = evenements_outil(banc.evenements()[len(avant):], f"{ALIAS}__preparer_paiement")[0]
    from conftest import RACINE  # noqa: F401
    h = e["execution"]["arguments"]["sha256"][2:]
    from pathlib import Path
    args = json.loads(Path(banc.info["journal"], "pieces", h[:2], h).read_bytes())
    assert args["montant"] == "100.00"


def test_echanges_declares(banc, installe):
    trace = Trace()
    avant = banc.evenements()
    with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-crew-declarer") as session:
        a = installe(session, modele="declarer")
        lancer(LLMScenario([("lire_sinistre", {"sinistre": "4"})]), a.envelopper(trace.outils()))
        assert a.ecouteur.file.vide(10)
        assert a.ecouteur.file.echanges_perdus == 0
    nouveaux = banc.evenements()[len(avant):]
    echanges = evenements_outil(nouveaux, "noortrace.modele.echange")
    assert len(echanges) == 2 and all(e["code"]["model"] == "scenario/modele-crewai" for e in echanges)


# ---------------------------------------------------------------- un événement par exécution réelle (EX-6.17, EX-6.18)


class Fragile:
    """Outil d'écriture qui lève une exception aux ``echecs`` premières exécutions."""

    def __init__(self, echecs: int) -> None:
        self.echecs = echecs
        self.executions = 0

    def outil(self):
        f = self

        @tool("ecrire_note")
        def ecrire_note(sinistre: str, note: str) -> str:
            """Écrit une note au dossier (outil local d'écriture)."""
            f.executions += 1
            if f.executions <= f.echecs:
                raise ValueError("panne passagere")
            return f"note-{f.executions}"

        return ecrire_note


def test_react_reexecutions_un_evenement_par_execution_et_is_error(banc, installe):
    """Chemin « ReAct » : ToolUsage réexécute un outil qui a levé une exception
    (crewai/tools/tool_usage.py) ; chaque exécution réelle a son événement, celles qui
    ont levé portent is_error vrai et la forme noortrace_sdk_exception."""
    f = Fragile(2)
    avant = banc.evenements()
    with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-crew-react") as session:
        a = installe(session, classes={"ecrire_note": "ecriture"})
        lancer(LLMReAct([("ecrire_note", {"sinistre": "1", "note": "pieces"})]), a.envelopper([f.outil()]))
    evts = executions(banc, avant, "ecrire_note")
    assert f.executions == 3 and len(evts) == 3
    assert [e["execution"]["is_error"] for e in evts] == [True, True, False]
    h = evts[0]["execution"]["result"]["sha256"][2:]
    from pathlib import Path
    assert json.loads(Path(banc.info["journal"], "pieces", h[:2], h).read_bytes()) == {"noortrace_sdk_exception": "ValueError"}


def test_natif_exception_is_error(banc, installe):
    f = Fragile(1)
    avant = banc.evenements()
    with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-crew-natif-erreur") as session:
        a = installe(session, classes={"ecrire_note": "ecriture"})
        llm = LLMScenario([("ecrire_note", {"sinistre": "2", "note": "x"}), ("ecrire_note", {"sinistre": "2", "note": "y"})])
        lancer(llm, a.envelopper([f.outil()]))
    evts = executions(banc, avant, "ecrire_note")
    assert f.executions == 2 and [e["execution"]["is_error"] for e in evts] == [True, False]
    assert llm.recu(0).startswith("Error executing tool: ")


def test_react_appel_repete_sans_execution_sans_evenement(banc, installe):
    """task_repeated_usage : CrewAI rend un texte sans exécuter l'outil ; aucun événement."""
    f = Fragile(0)
    avant = banc.evenements()
    with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-crew-repete") as session:
        a = installe(session, classes={"ecrire_note": "ecriture"})
        args = {"sinistre": "3", "note": "meme"}
        lancer(LLMReAct([("ecrire_note", args), ("ecrire_note", args)]), a.envelopper([f.outil()]))
    assert f.executions == 1 and len(executions(banc, avant, "ecrire_note")) == 1


def test_natif_max_usage_et_cache_sans_execution_sans_evenement(banc, installe):
    """max_usage_count atteint et résultat servi par le cache de l'équipage : l'outil n'est
    pas exécuté, aucun événement (ni d'intention, ni de reprise)."""
    f = Fragile(0)
    avant = banc.evenements()
    with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-crew-limite") as session:
        a = installe(session, classes={"ecrire_note": "ecriture"})
        outil = a.envelopper([f.outil()])[0]
        outil.max_usage_count = 1
        lancer(LLMScenario([("ecrire_note", {"sinistre": "4", "note": "a"}), ("ecrire_note", {"sinistre": "4", "note": "b"})]), [outil])
        assert f.executions == 1
        g = Fragile(0)
        args = {"sinistre": "5", "note": "c"}
        lancer(LLMScenario([("ecrire_note", args), ("ecrire_note", args)]), a.envelopper([g.outil()]), cache=True)
        assert g.executions == 1
    evts = executions(banc, avant, "ecrire_note")
    assert len(evts) == 2 and all(e["execution"]["status"] == "executee" for e in evts)
    # Aucune intention restée ouverte : la fermeture de la session ne produit aucune reprise.
    assert len(executions(banc, avant, "ecrire_note")) == 2


def test_react_demon_arrete_et_approbation(banc, installe):
    """Chemin « ReAct » : démon arrêté, outil d'écriture non exécuté et texte reçu ;
    a_approuver, signal exact reçu."""
    f = Fragile(0)
    session = ClientNoortrace(socket=banc.socket, delai_s=2, reprises=0).ouvrir(run_id="run-crew-react-i")
    a = installe(session, classes={"ecrire_note": "ecriture"})
    llm = LLMReAct([("ecrire_note", {"sinistre": "6", "note": "x"})])
    banc.arreter()
    try:
        lancer(llm, a.envelopper([f.outil()]))
    finally:
        banc.demarrer()
    assert f.executions == 0 and TEXTE_INJOIGNABLE in llm.recu()
    trace = Trace()
    with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-crew-react-ii") as s2:
        espion = Espion(s2)
        b2 = installe(espion)
        llm2 = LLMReAct([("approuver_paiement", {"montant": "9300.00"})])
        lancer(llm2, b2.envelopper(trace.outils()))
    d = espion.debuts[0]
    assert trace.departs == [] and d.decision == "a_approuver"
    assert f"noortrace: appel soumis a approbation ; ticket={d.ticket} ; state=nouveau" in llm2.recu()
