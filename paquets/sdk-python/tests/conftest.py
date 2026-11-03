"""Montage des essais du SDK Python : le banc Node.js (démon réel ``bin/noortrace``,
service d'approbation simulé, serveur d'outils MCP de test, fournisseur de
modèle simulé), piloté par lignes JSON (``test/fixtures/enregistreur-sdk-python/banc.mjs``).

Variables : ``NOORTRACE_NODE`` (exécutable Node.js, défaut ``node``),
``NOORTRACE_ESSAI_EXIGER`` (un cadre absent fait échouer l'essai au lieu de
le sauter : la suite mocha la pose, l'environnement étant présent),
``NOORTRACE_GO_BIN`` (répertoire de go1.27.3, pour le binaire Go).
"""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

RACINE = Path(__file__).resolve().parents[3]
BANC = RACINE / "test" / "fixtures" / "enregistreur-sdk-python" / "banc.mjs"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def exiger(module: str) -> Any:
    """Importe un cadre ; absent, l'essai est sauté, sauf sous ``NOORTRACE_ESSAI_EXIGER`` où il échoue."""
    if os.environ.get("NOORTRACE_ESSAI_EXIGER"):
        return importlib.import_module(module)
    return pytest.importorskip(module)


class Banc:
    """Démon réel et services simulés, dans un processus Node.js."""

    def __init__(self, politique: Optional[str] = None, mandataire: Optional[str] = None) -> None:
        node = os.environ.get("NOORTRACE_NODE", "node")
        env = dict(os.environ)
        if politique:
            env["NOORTRACE_ESSAI_POLITIQUE"] = politique
        if mandataire:
            env["NOORTRACE_ESSAI_MANDATAIRE"] = mandataire
        self.processus = subprocess.Popen([node, str(BANC)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=None, text=True, cwd=str(RACINE), bufsize=1, env=env)
        ligne = self.processus.stdout.readline()
        info = json.loads(ligne) if ligne else {"pret": False, "erreur": "banc muet"}
        if not info.get("pret"):
            raise RuntimeError(f"banc non pret : {info}")
        self.info: Dict[str, Any] = info
        self._verrou = threading.Lock()

    @property
    def socket(self) -> str:
        return self.info["socket"]

    def commande(self, **m: Any) -> Dict[str, Any]:
        with self._verrou:
            self.processus.stdin.write(json.dumps(m) + "\n")
            self.processus.stdin.flush()
            r = json.loads(self.processus.stdout.readline())
        if "erreur" in r:
            raise RuntimeError(f"banc : {r}")
        return r

    def evenements(self) -> List[dict]:
        return self.commande(cmd="evenements")["evenements"]

    def exploitation(self, evenement: Optional[str] = None) -> List[dict]:
        return self.commande(cmd="exploitation", event=evenement)["lignes"]

    def arreter(self) -> None:
        self.commande(cmd="arreter")

    def tuer(self) -> None:
        self.commande(cmd="tuer")

    def demarrer(self) -> None:
        self.commande(cmd="demarrer")

    def verifier(self, seq: int, dossier: str) -> Dict[str, Any]:
        return self.commande(cmd="verifier", seq=seq, dossier=dossier)

    def fermer(self) -> None:
        try:
            self.processus.stdin.close()
        except OSError:
            pass
        try:
            self.processus.wait(60)
        except subprocess.TimeoutExpired:
            self.processus.kill()


@pytest.fixture(scope="module")
def banc():
    b = Banc()
    yield b
    b.fermer()


def evenements_outil(evenements: List[dict], nom: str) -> List[dict]:
    """Événements d'un nom d'outil."""
    return [e for e in evenements if e["execution"]["tool"] == nom]


def verifier_parcours(banc: Banc, seq: int, nom: str) -> Dict[str, Any]:
    """Journal accepté par ``N.verifierJournal`` ; dossier de ``seq`` valide pour le
    noyau et, si go1.27.3 est présent, pour le binaire Go."""
    dossier = os.path.join(banc.info["dir"], f"dossier-{nom}")
    r = banc.verifier(seq, dossier)
    assert r["journal"]["valide"], r["journal"]
    assert r["dossier"]["verdict"] == "valide", r["dossier"]
    if os.environ.get("NOORTRACE_ESSAI_EXIGER_GO") and r["go"] is None:
        raise AssertionError("go1.27.3 exige mais absent")
    if r["go"] is not None:
        assert r["go"]["status"] == 0 and r["go"]["verdict"] == "valide" and r["go"]["failed_checks"] == [], r["go"]
        statuts = {c[0]: c[1] for c in r["go"]["controls"]}
        for i in (1, 2, 3, 6):
            assert statuts[i] == "reussi", r["go"]
    print(f"\nnoortrace-parcours {nom} : journal {r['journal']['evenements']} evenements valide ; dossier noyau {r['dossier']['verdict']} ; "
          f"binaire Go {'absent' if r['go'] is None else r['go']['verdict']}")
    return r


class Espion:
    """Session qui note l'instant (horloge monotone) où ``debut_appel`` a répondu (EX-6.20 (iii))."""

    def __init__(self, session: Any) -> None:
        self._session = session
        self._client = getattr(session, "_client", None)
        self.reponses: List[float] = []
        self.debuts: List[Any] = []

    def __getattr__(self, nom: str) -> Any:
        return getattr(self._session, nom)

    def debut_appel(self, *a: Any, **k: Any) -> Any:
        r = self._session.debut_appel(*a, **k)
        self.reponses.append(time.monotonic())
        self.debuts.append(r)
        return r


class EspionAsync(Espion):
    async def debut_appel(self, *a: Any, **k: Any) -> Any:  # type: ignore[override]
        r = await self._session.debut_appel(*a, **k)
        self.reponses.append(time.monotonic())
        self.debuts.append(r)
        return r

    async def fin_appel(self, *a: Any, **k: Any) -> Any:
        return await self._session.fin_appel(*a, **k)

    async def echange_modele(self, *a: Any, **k: Any) -> Any:
        return await self._session.echange_modele(*a, **k)
