"""Adaptateur LiteLLM, bibliothèque (CT-2 6.6 ; ``litellm`` 1.106.4).

LiteLLM n'exécute pas d'outil (R12 conséquence 7) : l'adaptateur n'a qu'un
point d'observation (``CustomLogger``), et un agent bâti sur
``litellm.completion`` exécute lui-même ses outils locaux — chemin du SDK
appelé directement (6.1), par ``appel_outil`` ; ses outils MCP passent par le
frontal MCP. Les cinq essais d'EX-6.20 sont lus pour cet agent (LISEZMOI,
lecture 160) : (i) à (iii) portent sur ``appel_outil`` dans la boucle de
l'agent ; (iv) est l'agent réel, modèle par la passerelle (``api_base``,
``modele="passerelle"``) ; (v) injecte une exception dans le code de
l'adaptateur (le ``CustomLogger``) et dans ``debut_appel``. Le modèle des
essais (i) à (iii) et (v) est le modèle factice de LiteLLM
(``mock_response``, ``mock_tool_calls``)."""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict, List

import pytest

from conftest import evenements_outil, exiger, verifier_parcours

litellm = exiger("litellm")

from noortrace_sdk import ClientNoortrace  # noqa: E402
from noortrace_sdk.adaptateurs import TEXTE_INJOIGNABLE, texte_avant_execution  # noqa: E402
from noortrace_sdk.adaptateurs.litellm import GestionnaireLiteLLM  # noqa: E402

ALIAS = "agent-py"
ARGS = {"sinistre": "2026-77812", "montant": "7400.00", "devise": "CHF"}
CLASSES = {"preparer_paiement": "ecriture", "lire_sinistre": "lecture", "approuver_paiement": None}


class ClientMcp:
    """Client Streamable HTTP minimal (ère héritée : ``initialize``, ``notifications/initialized``, ``tools/call``)."""

    def __init__(self, url: str, jeton: str) -> None:
        import httpx

        self.url = url
        self.h = {"Authorization": f"Bearer {jeton}", "Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        r = httpx.post(url, headers=self.h, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "agent-litellm", "version": "0.1.0"}}})
        self.h = {**self.h, "MCP-Protocol-Version": "2025-11-25"}
        if r.headers.get("mcp-session-id"):
            self.h["Mcp-Session-Id"] = r.headers["mcp-session-id"]
        httpx.post(url, headers=self.h, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.n = 1

    def appeler(self, nom: str, args: dict) -> str:
        import httpx

        self.n += 1
        r = httpx.post(self.url, headers=self.h, json={"jsonrpc": "2.0", "id": self.n, "method": "tools/call", "params": {"name": nom, "arguments": args}}).json()
        return "".join(c.get("text", "") for c in r["result"]["content"])


def agent(session, completion: Callable[[List[dict]], Any], outils: Dict[str, Callable], mcp: ClientMcp = None, tours: int = 4) -> List[List[dict]]:
    """Boucle d'agent sur LiteLLM : le modèle demande des outils ; les outils locaux passent par
    ``appel_outil`` (texte d'EX-6.19 rendu au modèle s'ils ne sont pas exécutés), les outils MCP
    par le frontal MCP. Rend les listes de messages envoyées au modèle."""
    messages: List[dict] = [{"role": "user", "content": "Traite le sinistre 2026-77812."}]
    envoyes = []
    for _ in range(tours):
        envoyes.append(json.loads(json.dumps(messages)))
        r = completion(messages)
        msg = r.choices[0].message
        if not msg.tool_calls:
            break
        messages.append({"role": "assistant", "content": msg.content, "tool_calls": [{"id": t.id, "type": "function", "function": {"name": t.function.name, "arguments": t.function.arguments}} for t in msg.tool_calls]})
        for t in msg.tool_calls:
            args = json.loads(t.function.arguments)
            if t.function.name.startswith("demo__"):
                contenu = mcp.appeler(t.function.name, args)
            else:
                try:
                    contenu = json.dumps(session.appel_outil(t.function.name, args, outils[t.function.name], classe=CLASSES.get(t.function.name)))
                except Exception as e:  # noqa: BLE001 - les outils de l'essai ne lèvent jamais : erreur avant l'exécution
                    contenu = texte_avant_execution(e)
            messages.append({"role": "tool", "tool_call_id": t.id, "content": contenu})
    return envoyes


def factice(appels: List[tuple]) -> Callable[[List[dict]], Any]:
    """Modèle factice de LiteLLM : un appel d'outil par tour (``mock_tool_calls``), puis une réponse."""
    def completion(messages):
        tour = len([m for m in messages if m["role"] == "tool"])
        if tour < len(appels):
            nom, args = appels[tour]
            return litellm.completion(model="openai/modele-chat", messages=messages, mock_tool_calls=[{"id": f"call_{tour}", "type": "function", "function": {"name": nom, "arguments": json.dumps(args)}}])
        return litellm.completion(model="openai/modele-chat", messages=messages, mock_response="fini")
    return completion


def recu(envoyes: List[List[dict]], tour: int) -> str:
    for m in envoyes:
        outils = [x for x in m if x["role"] == "tool"]
        if len(outils) > tour:
            return outils[tour]["content"]
    raise AssertionError("résultat non reçu par le modèle")


class Espion:
    """Note, sur la session même, l'instant où ``debut_appel`` a répondu (``appel_outil``
    appelle la méthode de l'instance)."""

    def __init__(self, session) -> None:
        self.session = session
        self.reponses: List[float] = []
        self.debuts: List[Any] = []
        reel = session.debut_appel

        def debut_appel(*a, **k):
            r = reel(*a, **k)
            self.reponses.append(time.monotonic())
            self.debuts.append(r)
            return r

        session.debut_appel = debut_appel


class Trace:
    def __init__(self) -> None:
        self.departs: List[tuple] = []

    def outils(self) -> Dict[str, Callable]:
        def preparer_paiement(sinistre, montant, devise):
            self.departs.append(("preparer_paiement", time.monotonic()))
            return {"ordre": f"ORD-{sinistre}"}

        def approuver_paiement(montant):
            self.departs.append(("approuver_paiement", time.monotonic()))
            return "paye"

        def lire_sinistre(sinistre):
            self.departs.append(("lire_sinistre", time.monotonic()))
            return f"sinistre {sinistre} ouvert"

        return {"preparer_paiement": preparer_paiement, "approuver_paiement": approuver_paiement, "lire_sinistre": lire_sinistre}


@pytest.fixture(autouse=True)
def rappels_vides():
    """LiteLLM recopie ``litellm.callbacks`` dans ses listes internes : toutes sont vidées après chaque essai."""
    litellm.logging_callback_manager._reset_all_callbacks()
    yield
    litellm.logging_callback_manager._reset_all_callbacks()


def test_i_demon_arrete_ecriture_non_executee(banc):
    trace = Trace()
    session = ClientNoortrace(socket=banc.socket, delai_s=2, reprises=0).ouvrir(run_id="run-ll-i")
    g = GestionnaireLiteLLM(session)
    litellm.callbacks = [g]
    banc.arreter()
    try:
        envoyes = agent(session, factice([("preparer_paiement", ARGS)]), trace.outils())
    finally:
        banc.demarrer()
    assert trace.departs == []
    assert recu(envoyes, 0) == TEXTE_INJOIGNABLE
    # Le point d'observation n'a ni bloqué ni fait échouer l'agent ; les échanges restés en
    # tête de file (requête non écrite) sont remis après la reprise de connexion (EX-6.13).
    assert len(envoyes) == 2
    fin = time.monotonic() + 30
    while True:
        assert g.file.vide(30) and g.file.echanges_perdus == 0
        remis = [e for e in evenements_outil(banc.evenements(), "noortrace.modele.echange") if e["delegation"]["run_id"] == "run-ll-i"]
        if len(remis) >= 2 or time.monotonic() > fin:
            break
        time.sleep(0.05)
    assert len(remis) == 2 and all(len(e["context"]) >= 1 for e in remis)


def test_ii_a_approuver_signal_exact(banc):
    trace = Trace()
    with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-ll-ii") as session:
        espion = Espion(session)
        envoyes = agent(session, factice([("approuver_paiement", {"montant": "9100.00"})]), trace.outils())
    assert trace.departs == []
    d = espion.debuts[0]
    assert d.decision == "a_approuver" and d.ticket_state == "nouveau"
    assert recu(envoyes, 0) == f"noortrace: appel soumis a approbation ; ticket={d.ticket} ; state=nouveau"


def test_iii_debut_appel_precede_l_outil(banc):
    trace = Trace()
    with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-ll-iii") as session:
        espion = Espion(session)
        agent(session, factice([("preparer_paiement", ARGS)]), trace.outils())
    assert len(trace.departs) == 1 and len(espion.reponses) == 1
    assert espion.reponses[0] <= trace.departs[0][1]


def chat(n: int, nom: str, args: dict) -> dict:
    return {"id": f"chatcmpl-ll-{n}", "object": "chat.completion", "created": 1794306000, "model": "modele-chat",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": None, "tool_calls": [{"id": f"call_{n}", "type": "function", "function": {"name": nom, "arguments": json.dumps(args)}}]}, "finish_reason": "tool_calls"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}


FIN = {"id": "chatcmpl-ll-fin", "object": "chat.completion", "created": 1794306000, "model": "modele-chat",
       "choices": [{"index": 0, "message": {"role": "assistant", "content": "fini"}, "finish_reason": "stop"}],
       "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}


def test_iv_agent_reel_passerelle_outil_local_et_outil_mcp_un_evenement_par_appel(banc):
    trace = Trace()
    banc.commande(cmd="scenario", reponses=[chat(0, "preparer_paiement", ARGS), chat(1, "demo__claims.get", {"claim_id": "2026-77812"}), FIN])
    avant = banc.evenements()

    def completion(messages):
        return litellm.completion(model="openai/modele-chat", api_base=banc.info["passerelle_url"] + "/v1", api_key=banc.info["passerelle_jeton"], messages=messages, num_retries=0)

    with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-ll-iv") as session:
        envoyes = agent(session, completion, trace.outils(), mcp=ClientMcp(banc.info["mcp_url"], banc.info["mcp_jeton"]))
    assert [n for n, _ in trace.departs] == ["preparer_paiement"]
    assert recu(envoyes, 1) == "Sinistre 2026-77812 : ouvert"
    fin = time.monotonic() + 10
    while True:
        nouveaux = banc.evenements()[len(avant):]
        if len(evenements_outil(nouveaux, "noortrace.modele.echange")) >= 3 or time.monotonic() > fin:
            break
        time.sleep(0.05)
    outils = [e["execution"]["tool"] for e in nouveaux if not e["execution"]["tool"].startswith("noortrace.")]
    assert sorted(outils) == sorted([f"{ALIAS}__preparer_paiement", "demo__claims.get"])
    echanges = evenements_outil(nouveaux, "noortrace.modele.echange")
    assert len(echanges) == 3 and all(e["context"] == [] for e in echanges)
    local = evenements_outil(nouveaux, f"{ALIAS}__preparer_paiement")[0]
    verifier_parcours(banc, local["seq"], "litellm")


def test_v_exception_de_l_adaptateur_et_de_debut_appel(banc, monkeypatch):
    trace = Trace()
    avant = banc.evenements()
    with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-ll-v") as session:
        g = GestionnaireLiteLLM(session)
        litellm.callbacks = [g]

        def panne(*a, **k):
            raise RuntimeError("exception injectee dans l'adaptateur")

        # Exception dans le code de l'adaptateur (point d'observation) : l'agent n'en voit rien.
        monkeypatch.setattr(GestionnaireLiteLLM, "_requete", staticmethod(panne))
        agent(session, factice([("lire_sinistre", {"sinistre": "1"})]), trace.outils())
        monkeypatch.undo()
        # Exception dans debut_appel : l'outil n'est jamais exécuté.
        monkeypatch.setattr(session, "debut_appel", panne)
        envoyes = agent(session, factice([("preparer_paiement", ARGS)]), trace.outils())
        monkeypatch.undo()
        g.file.vide(10)
    assert [n for n, _ in trace.departs] == ["lire_sinistre"]
    assert recu(envoyes, 0) == TEXTE_INJOIGNABLE
    assert evenements_outil(banc.evenements()[len(avant):], f"{ALIAS}__preparer_paiement") == []


def test_echanges_declares_hors_passerelle(banc):
    avant = banc.evenements()
    with ClientNoortrace(socket=banc.socket, delai_s=10).ouvrir(run_id="run-ll-declarer") as session:
        g = GestionnaireLiteLLM(session)
        litellm.callbacks = [g]
        r = litellm.completion(model="openai/modele-local", messages=[{"role": "user", "content": "Bonjour"}], mock_response="Bonjour, sinistre ouvert.")
        assert r.choices[0].message.content == "Bonjour, sinistre ouvert."
        with pytest.raises(Exception):
            litellm.completion(model="openai/modele-local", messages=[{"role": "user", "content": "x"}], mock_response=litellm.exceptions.RateLimitError("trop", "openai", "modele-local"))
        # LiteLLM peut appeler ses gestionnaires depuis un groupe de fils, après le retour de
        # completion : attente bornée des deux échanges, puis de la file.
        fin = time.monotonic() + 15
        while True:
            assert g.file.vide(10)
            echanges = evenements_outil(banc.evenements()[len(avant):], "noortrace.modele.echange")
            if len(echanges) >= 2 or time.monotonic() > fin:
                break
            time.sleep(0.05)
        assert g.file.echanges_perdus == 0
    assert len(echanges) == 2 and all(len(e["context"]) >= 1 for e in echanges)
    # Les gestionnaires appelés depuis un groupe de fils peuvent sceller les deux
    # échanges dans l'un ou l'autre ordre : chacun est cherché par son issue.
    reussi = [e for e in echanges if e["execution"]["is_error"] is False]
    echoue = [e for e in echanges if e["execution"]["is_error"] is True]
    assert len(reussi) == 1 and len(echoue) == 1
    assert reussi[0]["code"]["model"] == "openai/modele-local"
