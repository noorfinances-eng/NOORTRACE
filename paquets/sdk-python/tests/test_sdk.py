"""Essais du SDK Python (CT-2 6.5, EX-6.9 à EX-6.15) contre le démon réel
``bin/noortrace`` (banc Node.js), et, pour le seul protocole côté client
(cadrage, ``id``, codes d'erreur, délais, requête jamais renvoyée, jeton
TCP, sortie du processus), contre un démon simulé."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import os
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from pathlib import Path

import pytest

from conftest import evenements_outil
from demon_simule import DemonSimule, reponses_nominales

from noortrace_sdk import (
    AppelNonAutorise,
    ClientNoortrace,
    ClientNoortraceAsync,
    Debut,
    NoortraceConfiguration,
    NoortraceDegrade,
    NoortraceEntreeInvalide,
    NoortraceErreur,
    NoortraceIndisponible,
    NoortraceLimite,
    NoortraceNonDurable,
    Reference,
    Scelle,
)
from noortrace_sdk._commun import delai_reprise, est_valeur_json

ALIAS = "agent-py"


def piece(banc, ref: dict):
    """Octets d'une pièce stockée par le démon (adressage par ``sha256``)."""
    h = ref["sha256"][2:]
    return json.loads(Path(banc.info["journal"], "pieces", h[:2], h).read_bytes())


def intention_durable(banc, call: str) -> bool:
    """L'intention de l'appel ``call`` est-elle sur disque (EX-12.12) ?"""
    d = Path(banc.info["intentions"])
    for f in d.iterdir():
        for l in f.read_text().splitlines():
            if l and json.loads(l).get("upstream_id") == call:
                return True
    return False


@pytest.fixture
def dossier_court():
    d = tempfile.mkdtemp(prefix="ntpy-")
    yield d


# ---------------------------------------------------------------- interface de 6.5 (EX-6.9)


def test_interface_synchrone_complete(banc):
    client = ClientNoortrace(socket=banc.socket, delai_s=10)
    with client.ouvrir(run_id="run-sdkpy-0001", on_behalf_of="service-sinistres") as session:
        assert session.reponse_ouvrir["session"].startswith("s-")
        ref = session.declarer_contexte("document", "Dossier du sinistre 2026-77812", media_type="text/plain")
        assert isinstance(ref, Reference) and ref.length == len("Dossier du sinistre 2026-77812".encode())
        ref2 = session.declarer_contexte("donnees", b"\x00\x01binaire")
        assert ref2.sha256.startswith("0x")
        debut = session.debut_appel("lire_sinistre", {"sinistre": "2026-77812"}, classe="lecture", contexte=[ref.sha256])
        assert isinstance(debut, Debut)
        assert [f.name for f in dataclasses.fields(Debut)] == ["call", "decision", "ticket", "ticket_state"]
        assert debut.decision == "autorise" and debut.call is not None and debut.ticket is None and debut.ticket_state is None
        scelle = session.fin_appel(debut, {"statut": "ouvert"}, False, 4)
        assert isinstance(scelle, Scelle) and isinstance(scelle.seq, int) and scelle.hash.startswith("0x")
        # Écriture : l'intention est durable quand debut_appel rend (EX-6.3).
        d = session.debut_appel("ecrire_note", {"note": "pieces recues"}, classe="ecriture", intent="Noter la reception")
        assert d.decision == "autorise" and intention_durable(banc, d.call)
        session.fin_appel(d, {"note": "N-1"}, False, 2)
        s3 = session.echange_modele("autre", "local", {"model": "modele-local-1", "messages": []}, {"texte": "fin"}, 200, 12, False)
        assert isinstance(s3.seq, int)
    evts = banc.evenements()
    lu = evenements_outil(evts, f"{ALIAS}__lire_sinistre")[-1]
    assert lu["execution"]["status"] == "executee" and lu["seq"] == scelle.seq and lu["hash"] == scelle.hash
    assert lu["delegation"]["run_id"] == "run-sdkpy-0001" and lu["delegation"]["on_behalf_of"] == "service-sinistres"
    assert piece(banc, lu["execution"]["result"]) == {"statut": "ouvert"}
    assert lu["execution"]["duration_ms"] == 4
    note = evenements_outil(evts, f"{ALIAS}__ecrire_note")[-1]
    assert note["code"]["prompt_version"] is None
    echange = [e for e in evts if e["execution"]["tool"] == "noortrace.modele.echange"][-1]
    assert echange["seq"] == s3.seq and echange["code"]["model"] == "local/modele-local-1"
    # EX-7.7 : pièce de déclaration de source du SDK en context[0].
    assert echange["context"][0]["sha256"].startswith("0x")


def test_appel_outil_resultats_et_exceptions(banc):
    client = ClientNoortrace(socket=banc.socket, delai_s=10)
    with client.ouvrir(run_id="run-sdkpy-0002") as session:
        vus = []
        assert session.appel_outil("lire_x", {"a": 1, "b": "z"}, lambda a, b: (vus.append((a, b)), {"a": a})[1], classe="lecture") == {"a": 1}
        assert vus == [(1, "z")]
        # Valeur non JSON (EX-6.9) : forme noortrace_sdk_non_json, la valeur est rendue à l'appelant.
        objet = object()
        assert session.appel_outil("lire_objet", {}, lambda: objet, classe="lecture") is objet
        assert session.appel_outil("lire_tuple", {}, lambda: (1, 2), classe="lecture") == (1, 2)
        assert session.appel_outil("lire_nan", {}, lambda: [float("nan")], classe="lecture")

        class ErreurSecrete(Exception):
            pass

        with pytest.raises(ErreurSecrete):
            session.appel_outil("ecrire_y", {"v": 1}, lambda v: (_ for _ in ()).throw(ErreurSecrete("secret IBAN CH93")), classe="ecriture")
        # Décisions autres qu'autorise (EX-6.12) : AppelNonAutorise, fonction jamais exécutée.
        executee = []
        with pytest.raises(AppelNonAutorise) as e1:
            session.appel_outil("approuver_paiement", {"montant": "7400.00"}, lambda montant: executee.append(1))
        assert e1.value.decision == "a_approuver" and e1.value.ticket_state == "nouveau"
        assert e1.value.texte == f"noortrace: appel soumis a approbation ; ticket={e1.value.ticket} ; state=nouveau"
        with pytest.raises(AppelNonAutorise) as e2:
            session.appel_outil("approuver_paiement", {"montant": "7400.00"}, lambda montant: executee.append(1))
        assert e2.value.ticket_state == "en_attente" and e2.value.ticket == e1.value.ticket
        with pytest.raises(AppelNonAutorise) as e3:
            session.appel_outil("refuser_virement", {}, lambda: executee.append(1))
        assert e3.value.decision == "refuse" and e3.value.ticket is None
        assert e3.value.texte == "noortrace: appel refuse par la politique"
        assert executee == []
        # debut_appel rend la décision sans lever (EX-6.4).
        d = session.debut_appel("refuser_virement", {})
        assert (d.call, d.decision) == (None, "refuse")
    evts = banc.evenements()
    assert piece(banc, evenements_outil(evts, f"{ALIAS}__lire_objet")[-1]["execution"]["result"]) == {"noortrace_sdk_non_json": "object"}
    assert piece(banc, evenements_outil(evts, f"{ALIAS}__lire_tuple")[-1]["execution"]["result"]) == {"noortrace_sdk_non_json": "tuple"}
    assert piece(banc, evenements_outil(evts, f"{ALIAS}__lire_nan")[-1]["execution"]["result"]) == {"noortrace_sdk_non_json": "list"}
    y = evenements_outil(evts, f"{ALIAS}__ecrire_y")[-1]
    assert y["execution"]["is_error"] is True
    assert piece(banc, y["execution"]["result"]) == {"noortrace_sdk_exception": "ErreurSecrete"}
    # Le message de l'exception n'est jamais transmis.
    brut = Path(banc.info["journal"], "pieces", y["execution"]["result"]["sha256"][2:4], y["execution"]["result"]["sha256"][2:]).read_text()
    assert "secret" not in brut and "CH93" not in brut
    assert [e["execution"]["status"] for e in evenements_outil(evts, f"{ALIAS}__approuver_paiement")] == ["retenue"]
    assert {e["execution"]["status"] for e in evenements_outil(evts, f"{ALIAS}__refuser_virement")} == {"refusee"}


def test_entrees_invalides_et_configuration(banc, dossier_court):
    client = ClientNoortrace(socket=banc.socket, delai_s=10)
    with client.ouvrir() as session:
        for tool, raison in (("a__b", "tool_double_soulignement"), ("noortrace.x", "tool_reserve"), ("-x", "tool_hors_motif")):
            with pytest.raises(NoortraceEntreeInvalide) as e:
                session.debut_appel(tool, {})
            assert e.value.raison == raison and e.value.code == -32602
        with pytest.raises(NoortraceEntreeInvalide):
            session.debut_appel("lire", {}, contexte=["0x" + "ab" * 32])
        with pytest.raises(NoortraceEntreeInvalide) as e:
            session.debut_appel("lire", {"x": object()})
        assert e.value.raison == "valeur_non_json"
        # Un finAppel sans debutAppel connu est refusé (EX-6.3).
        with pytest.raises(NoortraceEntreeInvalide):
            session.fin_appel(Debut("c-inconnu", "autorise", None, None), None, False, 0)
    # Configuration (EX-6.10, EX-6.12).
    long = "/" + "x" * 103
    with pytest.raises(NoortraceConfiguration):
        ClientNoortrace(socket=long)
    ClientNoortrace(socket="/" + "x" * 102)
    with pytest.raises(NoortraceConfiguration):
        ClientNoortrace(socket="/a", tcp="127.0.0.1:1")
    with pytest.raises(NoortraceConfiguration):
        ClientNoortrace(tcp="127.0.0.1:9")
    with pytest.raises(NoortraceConfiguration):
        ClientNoortrace(tcp="127.0.0.1", jeton="j")
    with pytest.raises(NoortraceConfiguration):
        ClientNoortrace(socket="/a", delai_s=0)
    with pytest.raises(NoortraceConfiguration):
        ClientNoortrace(socket="/a", reprises=-1)
    with pytest.raises(NoortraceConfiguration):
        ClientNoortrace(socket="/a", sur_indisponibilite_lecture="toujours")
    assert issubclass(NoortraceConfiguration, NoortraceErreur) and issubclass(AppelNonAutorise, NoortraceErreur)


def test_adresse_par_environnement(monkeypatch, dossier_court):
    for v in ("NOORTRACE_SDK_SOCKET", "NOORTRACE_SDK_TCP", "NOORTRACE_SDK_TOKEN", "NOORTRACE_SDK_TLS_CA", "NOORTRACE_SDK_TLS_CERT", "NOORTRACE_SDK_TLS_KEY"):
        monkeypatch.delenv(v, raising=False)
    assert ClientNoortrace.depuis_environnement()._adresse.socket == "/run/noortrace/sdk.sock"
    monkeypatch.setenv("NOORTRACE_SDK_SOCKET", "/run/essai/une.sock")
    assert ClientNoortrace.depuis_environnement()._adresse.socket == "/run/essai/une.sock"
    # Les paramètres du constructeur priment.
    assert ClientNoortrace(socket="/run/essai/autre.sock")._adresse.socket == "/run/essai/autre.sock"
    monkeypatch.delenv("NOORTRACE_SDK_SOCKET")
    monkeypatch.setenv("NOORTRACE_SDK_TCP", "127.0.0.1:7000")
    with pytest.raises(NoortraceConfiguration):
        ClientNoortrace.depuis_environnement()
    monkeypatch.setenv("NOORTRACE_SDK_TOKEN", "jeton")
    a = ClientNoortrace.depuis_environnement()._adresse
    assert (a.hote, a.port, a.jeton, a.tls) == ("127.0.0.1", 7000, "jeton", None)
    monkeypatch.setenv("NOORTRACE_SDK_TLS_CA", "/inexistant/ca.pem")
    with pytest.raises(NoortraceConfiguration):
        ClientNoortrace.depuis_environnement()
    monkeypatch.setenv("NOORTRACE_SDK_TLS_CERT", "/inexistant/c.pem")
    monkeypatch.setenv("NOORTRACE_SDK_TLS_KEY", "/inexistant/k.pem")
    with pytest.raises(NoortraceConfiguration):
        ClientNoortrace.depuis_environnement()


# ---------------------------------------------------------------- protocole côté client (démon simulé)


def test_cadrage_ids_et_jeton_tcp(dossier_court):
    d = DemonSimule(dossier_court, reponses_nominales(), tcp=True, jeton="jeton-essai")
    try:
        client = ClientNoortrace(tcp=d.adresse, jeton="jeton-essai", delai_s=5)
        s = client.ouvrir(run_id="r")
        s.appel_outil("lire", {"a": 1}, lambda a: a, classe="lecture")
        s.fermer()
        # Première ligne : le jeton (EX-6.10) ; puis une ligne JSON-RPC 2.0 par message, LF final.
        assert json.loads(d.lignes_brutes[0]) == {"noortrace_token": "jeton-essai"}
        assert all(l.endswith(b"\n") and l.count(b"\n") == 1 for l in d.lignes_brutes)
        assert [m["id"] for m in d.recues] == [1, 2, 3, 4]
        assert all(m["jsonrpc"] == "2.0" for m in d.recues)
        assert d.methodes() == ["ouvrir", "debutAppel", "finAppel", "fermer"]
        assert set(d.recues[1]["params"]) == {"session", "tool", "arguments", "class", "context", "intent", "effects"}
        assert set(d.recues[2]["params"]) == {"call", "result", "is_error", "duration_ms"}
    finally:
        d.fermer()


@pytest.mark.parametrize("code,classe,attrs", [
    (-31010, NoortraceDegrade, {"raison": "stockage"}),
    (-31013, NoortraceLimite, {"direction": "requete", "limite": 1024}),
    (-31017, NoortraceNonDurable, {"intent_id": "i-1"}),
    (-32602, NoortraceEntreeInvalide, {"raison": "tool_hors_motif"}),
    (-32603, NoortraceErreur, {"code": -32603}),
])
def test_erreurs_par_code(dossier_court, code, classe, attrs):
    data = {"reason": attrs.get("raison"), "direction": "requete", "limit_bytes": 1024, "intent_id": "i-1"}

    def repondre(m, p, i):
        if m == "debutAppel":
            return {"error": {"code": code, "message": "noortrace: message fixe", "data": data}}
        return reponses_nominales()(m, p, i)

    d = DemonSimule(dossier_court, repondre)
    try:
        s = ClientNoortrace(socket=d.socket_path, delai_s=5).ouvrir()
        with pytest.raises(classe) as e:
            s.debut_appel("ecrire", {})
        assert type(e.value) is classe
        for k, v in attrs.items():
            assert getattr(e.value, k) == v
        assert e.value.message == "noortrace: message fixe"
    finally:
        d.fermer()


def test_delai_et_requete_jamais_renvoyee(dossier_court):
    def repondre(m, p, i):
        if m == "debutAppel":
            return None  # le démon ne répond jamais
        return reponses_nominales()(m, p, i)

    d = DemonSimule(dossier_court, repondre)
    try:
        client = ClientNoortrace(socket=d.socket_path, delai_s=0.5)
        s = client.ouvrir()
        executee = []
        t0 = time.monotonic()
        with pytest.raises(NoortraceIndisponible) as e:
            s.appel_outil("ecrire", {}, lambda: executee.append(1))
        assert 0.45 <= time.monotonic() - t0 < 3
        assert e.value.envoyee is True and executee == []
        assert d.methodes().count("debutAppel") == 1  # jamais renvoyée (EX-6.13)
    finally:
        d.fermer()


def test_connexion_perdue_puis_reprise_simulee(dossier_court):
    d = DemonSimule(dossier_court, reponses_nominales())
    try:
        client = ClientNoortrace(socket=d.socket_path, delai_s=5, reprises=2)
        s = client.ouvrir(run_id="run-r", on_behalf_of="obo")
        ref = s.declarer_contexte("document", "x")
        debut = s.debut_appel("ecrire", {})
        d.couper_tout()
        time.sleep(0.2)
        # finAppel d'une session perdue : jamais envoyé (EX-6.13).
        n = len(d.recues)
        with pytest.raises(NoortraceIndisponible) as e:
            s.fin_appel(debut, None, False, 1)
        assert e.value.envoyee is False and len(d.recues) == n
        # Référence de la session perdue : levée sans rien envoyer… après la nouvelle session.
        with pytest.raises(NoortraceEntreeInvalide) as e2:
            s.debut_appel("lire", {}, contexte=[ref.sha256])
        assert e2.value.raison == "context_session_perdue"
        assert d.connexions == 2
        ouvertures = [m for m in d.recues if m["method"].endswith("ouvrir")]
        assert [o["params"] for o in ouvertures] == [{"run_id": "run-r", "on_behalf_of": "obo"}] * 2
        assert ouvertures[1]["id"] == 1  # id recommencent à 1 sur la connexion nouvelle
        assert d.recues[-1]["method"].endswith("ouvrir")
    finally:
        d.fermer()


def test_demon_injoignable_et_reprises(dossier_court, caplog):
    chemin = os.path.join(dossier_court, "absente.sock")
    client = ClientNoortrace(socket=chemin, delai_s=1, reprises=2)
    t0 = time.monotonic()
    with pytest.raises(NoortraceIndisponible) as e:
        client.ouvrir()
    duree = time.monotonic() - t0
    # Deux attentes : n = 0 et n = 1, soit au moins 0,5·0,75 + 1·0,75 s.
    assert e.value.envoyee is False and 1.1 <= duree < 3.5
    assert delai_reprise(0, 0) == 0.5 and delai_reprise(1, 0) == 1.0 and delai_reprise(10, 0) == 8.0
    assert delai_reprise(3, 0.999999) == pytest.approx(4 * 0.75, rel=1e-3)


def test_demon_arrete_ecriture_jamais_executee_lecture_selon_reglage(banc, caplog):
    client = ClientNoortrace(socket=banc.socket, delai_s=2, reprises=0)
    session = client.ouvrir(run_id="run-sdkpy-arret")
    c2 = ClientNoortrace(socket=banc.socket, delai_s=2, reprises=0, sur_indisponibilite_lecture="executer")
    s2 = c2.ouvrir(run_id="run-sdkpy-arret-2")
    banc.arreter()
    try:
        executee = []
        with pytest.raises(NoortraceIndisponible):
            session.appel_outil("ecrire_z", {}, lambda: executee.append("ecriture"), classe="ecriture")
        with pytest.raises(NoortraceIndisponible):
            session.appel_outil("ecrire_z", {}, lambda: executee.append("defaut"))
        with pytest.raises(NoortraceIndisponible):
            session.appel_outil("lire_z", {}, lambda: executee.append("lecture-bloquer"), classe="lecture")
        assert executee == []
        with caplog.at_level(logging.WARNING, logger="noortrace_sdk"):
            # EX-6.15 : lecture exécutée sans aucun événement, notée au journal du SDK.
            assert s2.appel_outil("lire_z", {"q": 1}, lambda q: q * 2, classe="lecture") == 2
            with pytest.raises(NoortraceIndisponible):
                s2.appel_outil("ecrire_z", {}, lambda: executee.append("ecriture-executer"), classe="ecriture")
            with pytest.raises(NoortraceIndisponible):
                s2.appel_outil("sans_classe", {}, lambda: executee.append("defaut-executer"))
        assert executee == []
        assert any("execute sans evenement" in r.getMessage() for r in caplog.records)
    finally:
        banc.demarrer()
    assert evenements_outil(banc.evenements(), f"{ALIAS}__lire_z") == []


def test_reprise_apres_arret_du_demon(banc):
    client = ClientNoortrace(socket=banc.socket, delai_s=5, reprises=3)
    session = client.ouvrir(run_id="run-sdkpy-reprise", on_behalf_of="service-sinistres")
    premier = session.reponse_ouvrir["session"]
    ref = session.declarer_contexte("document", "avant la coupure")
    debut = session.debut_appel("ecrire_ordre", {"ordre": "O-1"}, classe="ecriture")
    banc.tuer()
    banc.demarrer()
    # finAppel de la session perdue : jamais envoyé.
    with pytest.raises(NoortraceIndisponible) as e:
        session.fin_appel(debut, {"ok": True}, False, 1)
    assert e.value.envoyee is False
    # Premier appel suivant : connexion et session nouvelles, mêmes run_id et on_behalf_of.
    assert session.appel_outil("lire_apres", {}, lambda: "ok", classe="lecture") == "ok"
    assert session.reponse_ouvrir["session"] != premier
    with pytest.raises(NoortraceEntreeInvalide):
        session.debut_appel("lire_apres", {}, contexte=[ref.sha256])
    session.fermer()
    evts = banc.evenements()
    reprise = evenements_outil(evts, f"{ALIAS}__ecrire_ordre")
    assert len(reprise) == 1 and reprise[0]["execution"]["is_error"] is True
    assert reprise[0]["delegation"]["run_id"] == "run-sdkpy-reprise"
    apres = evenements_outil(evts, f"{ALIAS}__lire_apres")[-1]
    assert apres["delegation"]["run_id"] == "run-sdkpy-reprise" and apres["delegation"]["on_behalf_of"] == "service-sinistres"


def test_fils_partages(banc):
    client = ClientNoortrace(socket=banc.socket, delai_s=20)
    session = client.ouvrir(run_id="run-sdkpy-fils")
    erreurs = []
    resultats = []

    def travail(k):
        try:
            for j in range(5):
                resultats.append(session.appel_outil("lire_fil", {"k": k, "j": j}, lambda k, j: k * 10 + j, classe="lecture"))
        except Exception as e:  # noqa: BLE001
            erreurs.append(e)

    fils = [threading.Thread(target=travail, args=(k,)) for k in range(8)]
    for f in fils:
        f.start()
    for f in fils:
        f.join()
    session.fermer()
    assert erreurs == [] and sorted(resultats) == sorted(k * 10 + j for k in range(8) for j in range(5))
    assert client._generation == 1  # une seule connexion (EX-6.14)


def test_fork_nouvelle_connexion(banc):
    if not hasattr(os, "fork"):
        pytest.skip("os.fork absent")
    client = ClientNoortrace(socket=banc.socket, delai_s=10)
    session = client.ouvrir(run_id="run-sdkpy-fork")
    parent = session.reponse_ouvrir["session"]
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:  # enfant
        os.close(r)
        code = 0
        try:
            session.appel_outil("lire_enfant", {}, lambda: 1, classe="lecture")
            os.write(w, json.dumps({"session": session.reponse_ouvrir["session"], "gen": client._generation}).encode())
        except BaseException as e:  # noqa: BLE001
            os.write(w, json.dumps({"erreur": repr(e)}).encode())
            code = 1
        finally:
            os.close(w)
            os._exit(code)
    os.close(w)
    os.waitpid(pid, 0)
    sortie = json.loads(os.read(r, 4096))
    os.close(r)
    assert "erreur" not in sortie and sortie["session"] != parent
    # Le parent garde sa connexion et sa session.
    session.appel_outil("lire_parent", {}, lambda: 1, classe="lecture")
    assert session.reponse_ouvrir["session"] == parent
    session.fermer()


def test_sortie_du_processus_fermer_borne(dossier_court):
    recues = []

    def repondre(m, p, i):
        recues.append(m)
        if m == "fermer":
            return None  # jamais de réponse : la sortie n'attend que 2 s
        return reponses_nominales()(m, p, i)

    d = DemonSimule(dossier_court, repondre)
    try:
        src = str(Path(__file__).resolve().parents[1] / "src")
        script = textwrap.dedent(f"""
            import sys; sys.path.insert(0, {src!r})
            from noortrace_sdk import ClientNoortrace
            s = ClientNoortrace(socket={d.socket_path!r}, delai_s=30).ouvrir(run_id="r")
        """)
        t0 = time.monotonic()
        subprocess.run([sys.executable, "-c", script], check=True, timeout=30)
        duree = time.monotonic() - t0
        time.sleep(0.2)
        assert "fermer" in recues and duree < 6
    finally:
        d.fermer()


# ---------------------------------------------------------------- client asynchrone


def test_client_asynchrone(banc):
    async def principal():
        client = ClientNoortraceAsync(socket=banc.socket, delai_s=10)
        async with client.ouvrir(run_id="run-sdkpy-async") as session:
            ref = await session.declarer_contexte("memoire", "note de memoire")
            assert await session.appel_outil("lire_async", {"x": 2}, lambda x: x + 1, classe="lecture", contexte=[ref.sha256]) == 3

            async def ecrire(v):
                await asyncio.sleep(0)
                return {"v": v}

            assert await session.appel_outil("ecrire_async", {"v": 5}, ecrire) == {"v": 5}
            with pytest.raises(AppelNonAutorise):
                await session.appel_outil("approuver_async", {}, lambda: 1)
            r = await session.echange_modele("autre", "local", {"model": "m"}, {"ok": 1}, None, 3, False)
            assert isinstance(r.seq, int)
            # En parallèle sur une connexion.
            vals = await asyncio.gather(*[session.appel_outil("lire_async", {"x": k}, lambda x: x, classe="lecture") for k in range(10)])
            assert vals == list(range(10))
        s2 = await client.ouvrir()  # attendu plutôt qu'employé par async with
        await s2.fermer()
        return client

    client = asyncio.run(principal())
    # EX-6.14 : employé depuis une autre boucle, NoortraceConfiguration.
    async def autre_boucle():
        await client.ouvrir()

    with pytest.raises(NoortraceConfiguration):
        asyncio.run(autre_boucle())
    evts = banc.evenements()
    assert evenements_outil(evts, f"{ALIAS}__ecrire_async")[-1]["execution"]["status"] == "executee"


def test_client_asynchrone_demon_arrete_et_reprise(banc):
    async def principal():
        client = ClientNoortraceAsync(socket=banc.socket, delai_s=2, reprises=0)
        s = await client.ouvrir(run_id="run-sdkpy-async-arret")
        premier = s.reponse_ouvrir["session"]
        banc.tuer()
        executee = []
        with pytest.raises(NoortraceIndisponible):
            await s.appel_outil("ecrire_a", {}, lambda: executee.append(1))
        assert executee == []
        banc.demarrer()
        assert await s.appel_outil("lire_a", {}, lambda: "ok", classe="lecture") == "ok"
        assert s.reponse_ouvrir["session"] != premier
        await s.fermer()

    asyncio.run(principal())


def test_valeurs_json():
    assert est_valeur_json({"a": [1, 2.5, True, None, "x"]})
    assert not est_valeur_json({"a": float("inf")})
    assert not est_valeur_json({1: "cle entiere"})
    assert not est_valeur_json((1, 2))
    cycle = []
    cycle.append(cycle)
    assert not est_valeur_json(cycle)


# ---------------------------------------------------------------- file des échanges observés (EX-6.11 (3))


def test_file_des_echanges_bornee_jamais_renvoyee(dossier_court, caplog):
    from noortrace_sdk.adaptateurs import FileEchanges, FileEchangesAsync

    def repondre(m, p, i):
        if m == "echangeModele":
            return None  # requête écrite, jamais de réponse
        return reponses_nominales()(m, p, i)

    d = DemonSimule(dossier_court, repondre)
    try:
        session = ClientNoortrace(socket=d.socket_path, delai_s=0.3).ouvrir()
        f = FileEchanges(session, file_max=2)
        with caplog.at_level(logging.WARNING, logger="noortrace_sdk"):
            t0 = time.monotonic()
            acceptes = [f.ajouter("autre", "local", {"model": "m"}, {"k": k}, None, 1, False) for k in range(5)]
            assert time.monotonic() - t0 < 0.2  # ajouter n'attend jamais
            assert f.vide(10)
        assert acceptes == [True, True, False, False, False]  # file pleine : l'échange le plus récent est abandonné
        assert f.echanges_perdus == 5
        recus = d.methodes().count("echangeModele")
        assert recus == acceptes.count(True)  # écrite sans réponse : jamais renvoyée (EX-6.13)
        assert any("file des echanges pleine" in r.getMessage() for r in caplog.records)

        async def asynchrone():
            s = await ClientNoortraceAsync(socket=d.socket_path, delai_s=0.3).ouvrir()
            fa = FileEchangesAsync(s, file_max=1)
            assert fa.ajouter("autre", "local", {}, {}, None, 1, False) is True
            assert fa.ajouter("autre", "local", {}, {}, None, 1, False) is False
            await fa.vide()
            return fa.echanges_perdus

        assert asyncio.run(asynchrone()) == 2
    finally:
        d.fermer()
