"""Revue de sécurité interne de l'étape 8 : adaptateur CrewAI, constat
CT-2 EX-6.21 : une sous-classe de ``BaseTool`` qui
définit sa propre ``_arun`` et que le cadre appelle par ``arun`` (chemin
asynchrone natif) est interceptée comme ``_run`` : un ``debut_appel`` et un
``fin_appel`` par exécution réelle, sur les deux chemins. Session factice
synchrone (aucun banc) : l'adaptateur appelle la session par ``asyncio.to_thread``."""

from __future__ import annotations

import asyncio
import os
from typing import Any, List

import pytest

from conftest import exiger

os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
exiger("crewai")

from crewai.tools import BaseTool  # noqa: E402

from noortrace_sdk.adaptateurs.crewai import AdaptateurCrewAI  # noqa: E402
from noortrace_sdk.objets import Debut, Scelle  # noqa: E402


class SessionFactice:
    """Session synchrone : note chaque debut_appel / fin_appel."""

    def __init__(self) -> None:
        self.debuts: List[tuple] = []
        self.fins: List[tuple] = []

    def debut_appel(self, nom: str, arguments: Any, classe: Any = None, **k: Any) -> Debut:
        self.debuts.append((nom, arguments, classe))
        return Debut(call=f"c-{len(self.debuts)}", decision="autorise", ticket=None, ticket_state=None)

    def fin_appel(self, debut: Debut, resultat: Any, is_error: bool, duration_ms: int) -> Scelle:
        self.fins.append((debut.call, resultat, is_error))
        return Scelle(seq=len(self.fins), hash="0x" + "00" * 32)


class OutilAsynchrone(BaseTool):
    name: str = "lire_sinistre"
    description: str = "lecture d'un sinistre"

    def _run(self, sinistre: str) -> str:
        return f"sync {sinistre}"

    async def _arun(self, sinistre: str) -> str:
        return f"async {sinistre}"


class OutilSynchroneSeul(BaseTool):
    name: str = "lire_note"
    description: str = "lecture d'une note"

    def _run(self, note: str) -> str:
        return f"sync {note}"


def test_outil_asynchrone_natif_intercepte_sur_arun_et_run():
    session = SessionFactice()
    adaptateur = AdaptateurCrewAI(session, classes={"lire_sinistre": "lecture", "lire_note": "lecture"})
    copie = adaptateur.envelopper_outil(OutilAsynchrone())
    assert copie is not None
    # Chemin asynchrone natif (BaseTool.arun -> _arun) : intercepté.
    valeur = asyncio.run(copie.arun(sinistre="2026-77812"))
    assert valeur == "async 2026-77812"
    assert session.debuts == [("lire_sinistre", {"sinistre": "2026-77812"}, "lecture")]
    assert session.fins == [("c-1", "async 2026-77812", False)]
    # Chemin synchrone (BaseTool.run -> _run) : intercepté de même, un événement par exécution.
    assert copie.run(sinistre="2026-77813") == "sync 2026-77813"
    assert len(session.debuts) == 2 and len(session.fins) == 2
    assert session.fins[-1] == ("c-2", "sync 2026-77813", False)
    # L'original n'est pas modifié.
    assert OutilAsynchrone()._run(sinistre="x") == "sync x" and len(session.debuts) == 2
    # Une sous-classe sans _arun propre garde la _arun par défaut de BaseTool (qui lève) : rien d'enveloppé en plus.
    copie2 = adaptateur.envelopper_outil(OutilSynchroneSeul())
    assert "_arun" not in copie2.__dict__
    assert copie2.run(note="n") == "sync n" and len(session.fins) == 3
    with pytest.raises(NotImplementedError):
        asyncio.run(copie2.arun(note="n"))
    assert len(session.debuts) == 3
