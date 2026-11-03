"""Erreurs du SDK Python de NOORTRACE (CT-2 EX-6.12).

Toutes dérivent de ``NoortraceErreur``. Une décision ``a_approuver`` ou
``refuse`` n'est pas une erreur du protocole (EX-6.4) : seule
``appel_outil`` la change en exception (``AppelNonAutorise``), pour qu'aucun
code appelant ne l'exécute par mégarde.
"""

from __future__ import annotations

from typing import Any, Optional


class NoortraceErreur(Exception):
    """Toute erreur du SDK ; pour un code JSON-RPC non nommé ci-dessous : ``code``, ``message``, ``data``."""

    def __init__(self, message: str, code: Optional[int] = None, data: Any = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.data = data


class NoortraceIndisponible(NoortraceErreur):
    """Prise injoignable, connexion coupée, délai ``delai_s`` écoulé.

    ``envoyee`` : vrai si la requête a été écrite sur la prise (EX-6.13 : une
    requête écrite n'est jamais renvoyée).
    """

    def __init__(self, message: str, envoyee: bool) -> None:
        super().__init__(message)
        self.envoyee = envoyee is True


class NoortraceDegrade(NoortraceErreur):
    """-31010 : ``raison`` (``data.reason``)."""

    def __init__(self, message: str, data: Any = None) -> None:
        super().__init__(message, -31010, data)
        self.raison = data.get("reason") if isinstance(data, dict) else None


class NoortraceLimite(NoortraceErreur):
    """-31013 : ``direction``, et ``limite`` (octets, requêtes ou millisecondes)."""

    def __init__(self, message: str, data: Any = None) -> None:
        super().__init__(message, -31013, data)
        d = data if isinstance(data, dict) else {}
        self.direction = d.get("direction")
        limite = None
        for cle in ("limit_bytes", "limit_requests", "limit_ms"):
            if d.get(cle) is not None:
                limite = d[cle]
                break
        self.limite = limite


class NoortraceNonDurable(NoortraceErreur):
    """-31017 (``finAppel`` après une panne du démon, 14.2) : ``intent_id``."""

    def __init__(self, message: str, data: Any = None) -> None:
        super().__init__(message, -31017, data)
        self.intent_id = data.get("intent_id") if isinstance(data, dict) else None


class NoortraceEntreeInvalide(NoortraceErreur):
    """-32602 : ``raison`` (``data.reason``)."""

    def __init__(self, message: str, data: Any = None) -> None:
        super().__init__(message, -32602, data)
        self.raison = data.get("reason") if isinstance(data, dict) else None


class NoortraceConfiguration(NoortraceErreur):
    """Configuration du client invalide (EX-6.10 : chemin de prise de plus de 103 octets, …)."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


def texte_non_autorise(ticket: Optional[str], etat: Optional[str]) -> str:
    """Texte du résultat d'outil d'EX-4.49 (EX-6.12 : ``texte``)."""
    if ticket is None:
        return "noortrace: appel refuse par la politique"
    return f"noortrace: appel soumis a approbation ; ticket={ticket} ; state={etat}"


class AppelNonAutorise(NoortraceErreur):
    """``decision`` autre que ``autorise`` dans ``appel_outil`` : ``decision``, ``ticket``, ``ticket_state``, ``texte``."""

    def __init__(self, decision: str, ticket: Optional[str], ticket_state: Optional[str]) -> None:
        texte = texte_non_autorise(ticket, ticket_state)
        super().__init__(texte)
        self.decision = decision
        self.ticket = ticket
        self.ticket_state = ticket_state
        self.texte = texte


def erreur_depuis_reponse(e: Any) -> NoortraceErreur:
    """Erreur du SDK pour un objet ``error`` JSON-RPC rendu par le démon (EX-6.12)."""
    e = e if isinstance(e, dict) else {}
    data = e.get("data")
    message = e.get("message") if isinstance(e.get("message"), str) else "noortrace: erreur"
    code = e.get("code")
    if code == -31010:
        return NoortraceDegrade(message, data)
    if code == -31013:
        return NoortraceLimite(message, data)
    if code == -31017:
        return NoortraceNonDurable(message, data)
    if code == -32602:
        return NoortraceEntreeInvalide(message, data)
    return NoortraceErreur(message, code if isinstance(code, int) and not isinstance(code, bool) else None, data)
