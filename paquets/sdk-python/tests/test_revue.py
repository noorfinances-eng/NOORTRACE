"""Revue de sécurité interne de l'étape 8 : SDK Python (CT-2 EX-6.10,
usurpation d'une prise locale côté client, substitut isolé). Contre le
démon simulé seulement (``demon_simule.py``) : aucun banc Node.js.

- Substitut isolé : une chaîne à substitut isolé n'est pas une valeur JSON ; ``appel_outil``
  déclare le résultat sous la forme ``noortrace_sdk_non_json`` et l'événement est
  durable ; ``ligne_jsonrpc`` lève ``NoortraceEntreeInvalide`` (``valeur_non_json``),
  jamais ``UnicodeEncodeError`` ; les motifs sont ancrés par ``fullmatch``.
- CT-2 EX-6.10 : une prise TCP hors de la boucle locale n'est admise qu'en mTLS.
- Usurpation d'une prise locale : la prise Unix doit appartenir au compte attendu du démon (``proprietaire``,
  ``NOORTRACE_SDK_PROPRIETAIRE``) ; sans compte attendu, au compte du processus ou au compte 0.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import tempfile

import pytest

from demon_simule import DemonSimule, reponses_nominales

from noortrace_sdk import ClientNoortrace, ClientNoortraceAsync, NoortraceConfiguration, NoortraceEntreeInvalide, NoortraceIndisponible
import noortrace_sdk._commun as commun
from noortrace_sdk._commun import defi_valide, est_valeur_json, ligne_jsonrpc, resoudre_adresse, resultat_declare
from noortrace_sdk.adaptateurs import intercepter, nom_declarable

# Fonctions nouvelles : absentes du code d'avant la correction (rejeu), chaque essai échoue alors par son oracle.
controler_proprietaire_prise = getattr(commun, "controler_proprietaire_prise", lambda *a: "fonction_absente")
est_adresse_de_bouclage = getattr(commun, "est_adresse_de_bouclage", lambda h: None)

UID_AUTRE = 65534  # nobody


@pytest.fixture
def dossier_court():
    d = tempfile.mkdtemp(prefix="ntrv-")
    yield d
    # Libéré après l'essai, échec compris (pytest joue la suite du générateur dans tous les cas).
    shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------- substitut isolé


def test_substitut_isole_valeur_non_json_et_motifs_ancres(dossier_court):
    surrogate = "fichier-\udcff.txt"  # forme surrogateescape d'os.listdir
    assert est_valeur_json(surrogate) is False
    assert est_valeur_json({"nom": surrogate}) is False
    assert est_valeur_json({surrogate: 1}) is False
    assert est_valeur_json("texte ordinaire é") is True
    assert resultat_declare(surrogate) == {"noortrace_sdk_non_json": "str"}
    assert resultat_declare([surrogate]) == {"noortrace_sdk_non_json": "list"}
    with pytest.raises(NoortraceEntreeInvalide) as e:
        ligne_jsonrpc(1, "finAppel", {"result": surrogate})
    assert e.value.data == {"reason": "valeur_non_json"}
    # Motifs ancrés : un saut de ligne final n'est ni un nom déclarable ni un défi.
    assert nom_declarable("outil") is True
    assert nom_declarable("outil\n") is False
    assert defi_valide({"noortrace_defi": "0" * 32}) == "0" * 32
    assert defi_valide({"noortrace_defi": "0" * 32 + "\n"}) is None
    # Contre le démon simulé : l'outil exécuté est déclaré, l'événement est durable.
    d = DemonSimule(dossier_court, reponses_nominales())
    try:
        client = ClientNoortrace(socket=d.socket_path, delai_s=5)
        with client.ouvrir(run_id="r") as s:
            assert s.appel_outil("lister", {}, lambda: surrogate, classe="lecture") == surrogate
            # Un argument non représentable : NoortraceEntreeInvalide avant tout envoi, l'outil n'est pas exécuté.
            executes = []
            with pytest.raises(NoortraceEntreeInvalide):
                s.appel_outil("lire", {"nom": surrogate}, lambda nom: executes.append(nom), classe="lecture")
            assert executes == []
            # Point d'interception des adaptateurs : même forme déclarée, aucune exception brute.
            issue = intercepter(s, lambda: ("lister2", {}, "lecture"), lambda: surrogate, lambda v: (resultat_declare(v), False))
            assert issue.executee is True and issue.texte is None and issue.valeur == surrogate
        fins = [m for m in d.recues if m["method"] == "noortrace/sdk/finAppel"]
        assert [m["params"]["result"] for m in fins] == [{"noortrace_sdk_non_json": "str"}, {"noortrace_sdk_non_json": "str"}]
        assert all(m["params"]["is_error"] is False for m in fins)
        assert [m["method"] for m in d.recues if m["method"] == "noortrace/sdk/debutAppel"].count("noortrace/sdk/debutAppel") == 2
    finally:
        d.fermer()


# ---------------------------------------------------------------- CT-2 EX-6.10


def test_prise_tcp_hors_boucle_locale_exige_mtls(dossier_court):
    assert est_adresse_de_bouclage("127.0.0.1") and est_adresse_de_bouclage("localhost") and est_adresse_de_bouclage("::1")
    assert not est_adresse_de_bouclage("hote.example") and not est_adresse_de_bouclage("192.0.2.5")
    a = resoudre_adresse(None, "127.0.0.1:8611", "jeton", env={})
    assert (a.hote, a.port, a.jeton) == ("127.0.0.1", 8611, "jeton")
    with pytest.raises(NoortraceConfiguration) as e:
        resoudre_adresse(None, "hote.example:8611", "jeton", env={})
    assert "mTLS" in str(e.value) and "en clair" in str(e.value)
    with pytest.raises(NoortraceConfiguration):
        ClientNoortrace(tcp="192.0.2.5:8611", jeton="jeton")
    with pytest.raises(NoortraceConfiguration):
        resoudre_adresse(None, None, None, env={"NOORTRACE_SDK_TCP": "hote.example:8611", "NOORTRACE_SDK_TOKEN": "jeton"})
    # En mTLS, un hôte distant est admis : le jeton ne part pas.
    cle, cert = os.path.join(dossier_court, "c.key"), os.path.join(dossier_court, "c.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", cle, "-out", cert, "-subj", "/CN=agent", "-days", "2"],
                   check=True, capture_output=True)
    m = resoudre_adresse(None, "hote.example:8611", None, env={"NOORTRACE_SDK_TLS_CERT": cert, "NOORTRACE_SDK_TLS_KEY": cle})
    assert m.hote == "hote.example" and m.jeton is None and m.tls is not None


# ---------------------------------------------------------------- prise usurpée (côté client)


def test_proprietaire_de_la_prise_unix(dossier_court):
    d = DemonSimule(dossier_court, reponses_nominales())
    try:
        assert controler_proprietaire_prise(d.socket_path, None) is None
        assert controler_proprietaire_prise(os.path.join(dossier_court, "absente.sock"), None) == "prise_absente"
        fichier = os.path.join(dossier_court, "fichier")
        open(fichier, "w").close()
        assert controler_proprietaire_prise(fichier, None) == "prise_non_prise"
        assert controler_proprietaire_prise(d.socket_path, "compte-inexistant-noortrace") == "proprietaire_inconnu"
        assert controler_proprietaire_prise(d.socket_path, os.getuid()) is None
        assert controler_proprietaire_prise(d.socket_path, str(os.getuid())) is None
        if os.getuid() != 0:
            pytest.skip("compte 0 requis pour chown (ressource absente)")
        os.chown(d.socket_path, UID_AUTRE, UID_AUTRE)
        assert controler_proprietaire_prise(d.socket_path, None) == "prise_autre_compte"
        assert controler_proprietaire_prise(d.socket_path, "nobody") is None
        # Client synchrone : refus avant tout envoi.
        with pytest.raises(NoortraceIndisponible) as e:
            ClientNoortrace(socket=d.socket_path, delai_s=5, reprises=0).ouvrir(run_id="r")
        assert "prise_autre_compte" in str(e.value) and d.connexions == 0
        # Compte attendu nommé : admis (paramètre, puis variable d'environnement).
        with ClientNoortrace(socket=d.socket_path, delai_s=5, proprietaire=str(UID_AUTRE)).ouvrir(run_id="r") as s:
            s.appel_outil("lire", {"a": 1}, lambda a: a, classe="lecture")
        assert d.connexions == 1
        a = resoudre_adresse(d.socket_path, None, None, env={"NOORTRACE_SDK_PROPRIETAIRE": "nobody"})
        assert a.proprietaire == "nobody" and controler_proprietaire_prise(a.socket, a.proprietaire) is None

        # Client asynchrone : même règle.
        async def asynchrone():
            with pytest.raises(NoortraceIndisponible) as e2:
                async with ClientNoortraceAsync(socket=d.socket_path, delai_s=5, reprises=0).ouvrir(run_id="r"):
                    pass
            assert "prise_autre_compte" in str(e2.value)
            async with ClientNoortraceAsync(socket=d.socket_path, delai_s=5, proprietaire=UID_AUTRE).ouvrir(run_id="r") as s2:
                await s2.debut_appel("lire", {"a": 1}, classe="lecture")

        asyncio.run(asynchrone())
        assert d.connexions == 2
    finally:
        d.fermer()
