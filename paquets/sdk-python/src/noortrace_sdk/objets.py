"""Objets rendus par le SDK (CT-2 EX-6.9).

``Debut`` porte exactement les quatre membres du résultat de ``debutAppel``
(``call``, ``decision``, ``ticket``, ``ticket_state``) ; ``Scelle`` porte
``seq`` et ``hash`` ; ``Reference`` porte ``sha256``, ``length``,
``redacted``. Les noms sont ceux de 6.2.

``Debut`` est comparé par identité (``eq=False``) : le SDK y rattache, hors
de ses membres, la session et la connexion qui l'ont rendu (EX-6.13 : un
``fin_appel`` dont la session a été perdue avant son envoi n'est pas
envoyé).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True, eq=False)
class Debut:
    """Résultat de ``debut_appel`` : la décision et, pour ``autorise``, l'appel."""

    call: Optional[str]
    decision: str
    ticket: Optional[str]
    ticket_state: Optional[str]


@dataclass(frozen=True)
class Scelle:
    """Événement durable : ``seq`` et ``hash`` (``None`` pour un événement en attente du mode dégradé, 14.5)."""

    seq: Optional[int]
    hash: Optional[str]


@dataclass(frozen=True)
class Reference:
    """Référence de la pièce stockée par ``declarer_contexte``."""

    sha256: str
    length: int
    redacted: bool
