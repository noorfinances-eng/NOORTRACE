"""SDK Python de NOORTRACE (CT-2 6.5, EX-6.9) : distribution ``noortrace-sdk``, module ``noortrace_sdk``.

Il enveloppe les six méthodes ``noortrace/sdk/*`` du démon ``noortrace``
(6.2) sans en ajouter, sans paramètre ajouté, et sans changer ni les
résultats ni leur sémantique (6.5). Il ne capture rien et ne calcule rien
(EX-6.1). **Il n'est un chemin de capture acceptable qu'avec un pare-feu de
sortie qui interdit au processus de l'agent de joindre les serveurs d'outils
et les fournisseurs de modèle autrement que par l'enregistreur (EX-6.2).**
"""

from .client import ClientNoortrace, Session
from .client_async import ClientNoortraceAsync, SessionAsync
from .erreurs import (
    AppelNonAutorise,
    NoortraceConfiguration,
    NoortraceDegrade,
    NoortraceEntreeInvalide,
    NoortraceErreur,
    NoortraceIndisponible,
    NoortraceLimite,
    NoortraceNonDurable,
)
from .objets import Debut, Reference, Scelle

__version__ = "0.1.0"

__all__ = [
    "ClientNoortrace",
    "ClientNoortraceAsync",
    "Session",
    "SessionAsync",
    "Debut",
    "Scelle",
    "Reference",
    "NoortraceErreur",
    "NoortraceIndisponible",
    "NoortraceDegrade",
    "NoortraceLimite",
    "NoortraceNonDurable",
    "NoortraceEntreeInvalide",
    "NoortraceConfiguration",
    "AppelNonAutorise",
]
