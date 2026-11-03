"""Client synchrone du SDK Python de NOORTRACE (CT-2 6.5, EX-6.9 à EX-6.15).

``ClientNoortrace`` enveloppe les méthodes ``noortrace/sdk/*`` de 6.2 sans en
ajouter, sans paramètre ajouté, et sans changer ni les résultats ni leur
sémantique. Le SDK ne capture rien et ne calcule rien : pas de hachage, pas
de signature, pas d'écriture de journal (EX-6.1) ; il remet au démon ce que
l'agent déclare. Il n'est un chemin de capture acceptable qu'avec un
pare-feu de sortie (EX-6.2).

Le client peut être partagé entre fils (EX-6.14) : une connexion, des
écritures sérialisées par un verrou, un fil lecteur qui remet chaque réponse
au fil qui attend son ``id``. Après ``os.fork()``, l'enfant ne réutilise
jamais la prise du parent : l'identifiant de processus est comparé à chaque
appel, et une connexion et une session nouvelles sont ouvertes.
"""

from __future__ import annotations

import atexit
import base64
import math
import os
import threading
import time
import weakref
from typing import Any, Callable, Dict, Iterable, Optional

from ._commun import (
    FERMER_A_LA_SORTIE_S,
    delai_reprise,
    journal,
    nom_de_classe,
    octets_de,
    params_debut,
    params_echange,
    resoudre_adresse,
    resultat_declare,
    verifier_reglages,
)
from ._connexion import Connexion
from .erreurs import (
    AppelNonAutorise,
    NoortraceEntreeInvalide,
    NoortraceIndisponible,
)
from .objets import Debut, Reference, Scelle

#: Session et génération de connexion de chaque ``Debut`` rendu (hors de ses quatre membres, EX-6.9).
_LIENS: "weakref.WeakKeyDictionary[Debut, tuple]" = weakref.WeakKeyDictionary()

#: Clients qui ont ouvert une session : ``fermer`` à la sortie du processus (EX-6.11 (4)).
_CLIENTS: "weakref.WeakSet[ClientNoortrace]" = weakref.WeakSet()
_SORTIE = {"armee": False}


def _duree_ms(t0: float) -> int:
    """Durée sur l'horloge monotone, en millisecondes entières (EX-6.9)."""
    return max(0, math.floor((time.monotonic() - t0) * 1000))


def _fermer_a_la_sortie() -> None:
    """EX-6.11 (4) : à la sortie du processus, ``fermer`` est tenté, borné à 2 s."""
    sessions = [s for c in list(_CLIENTS) for s in list(c._sessions)]
    if not sessions:
        return

    def fermer_tout() -> None:
        for s in sessions:
            try:
                s._fermer_borne(FERMER_A_LA_SORTIE_S)
            except Exception:  # noqa: BLE001 - la sortie n'est jamais retardée ni empêchée
                pass

    f = threading.Thread(target=fermer_tout, name="noortrace-sdk-sortie", daemon=True)
    f.start()
    f.join(FERMER_A_LA_SORTIE_S)
    for c in list(_CLIENTS):
        con = c._connexion
        if con is not None and c._pid == os.getpid():
            con.fermer()


class ClientNoortrace:
    """Client du démon (EX-6.9, EX-6.10). La connexion est ouverte au premier appel."""

    def __init__(self, socket: Optional[str] = None, tcp: Optional[str] = None, jeton: Optional[str] = None,
                 delai_s: float = 30.0, reprises: int = 2, sur_indisponibilite_lecture: str = "bloquer") -> None:
        verifier_reglages(delai_s, reprises, sur_indisponibilite_lecture)
        self._adresse = resoudre_adresse(socket, tcp, jeton)
        self.delai_s = float(delai_s)
        self.reprises = reprises
        self.sur_indisponibilite_lecture = sur_indisponibilite_lecture
        self._connexion: Optional[Connexion] = None
        self._generation = 0
        self._pid = os.getpid()
        self._verrou = threading.RLock()
        self._sessions: "weakref.WeakSet[Session]" = weakref.WeakSet()

    @classmethod
    def depuis_environnement(cls) -> "ClientNoortrace":
        """Client configuré par l'environnement seul (EX-6.10)."""
        return cls()

    # ------------------------------------------------------------ connexion

    def _verifier_processus(self) -> None:
        """EX-6.14 : après ``os.fork()``, la prise du parent n'est jamais réutilisée.

        Dans l'enfant, les verrous sont recréés sans être pris (un fil du parent
        pouvait les détenir au moment du ``fork``)."""
        if self._pid == os.getpid():
            return
        self._pid = os.getpid()
        self._verrou = threading.RLock()
        for s in list(self._sessions):
            s._verrou = threading.RLock()
        if self._connexion is not None:
            self._connexion.abandonner()
        self._connexion = None
        self._generation += 1

    def _vivante(self, generation: int) -> bool:
        """Une génération de connexion est-elle toujours vivante ?"""
        self._verifier_processus()
        c = self._connexion
        return c is not None and not c.perdue and self._generation == generation

    def _connexion_une_tentative(self) -> tuple:
        """Connexion vivante, ou une tentative d'établissement ; rend (connexion, génération)."""
        with self._verrou:
            c = self._connexion
            if c is not None and not c.perdue:
                return c, self._generation
            c = Connexion(self._adresse)
            c.ouvrir(self.delai_s)
            self._connexion = c
            self._generation += 1
            return c, self._generation

    def _ouvrir_session(self, run_id: Optional[str], on_behalf_of: Optional[str]) -> tuple:
        """``ouvrir`` de 6.2 ; l'établissement de la connexion et ``ouvrir`` sont retentés
        (EX-6.13) : au plus ``1 + reprises`` tentatives, séparées par ``delai_reprise``."""
        self._verifier_processus()
        derniere: Optional[BaseException] = None
        for n in range(self.reprises + 1):
            if n > 0:
                time.sleep(delai_reprise(n - 1))
            try:
                c, generation = self._connexion_une_tentative()
                r = c.appeler("ouvrir", {"run_id": run_id, "on_behalf_of": on_behalf_of}, self.delai_s)
                return r, generation
            except NoortraceIndisponible as e:
                derniere = e
        assert derniere is not None
        raise derniere

    def _armer_sortie(self) -> None:
        _CLIENTS.add(self)
        if not _SORTIE["armee"]:
            _SORTIE["armee"] = True
            atexit.register(_fermer_a_la_sortie)

    # ------------------------------------------------------------ sessions

    def ouvrir(self, run_id: Optional[str] = None, on_behalf_of: Optional[str] = None) -> "Session":
        """``noortrace/sdk/ouvrir`` (EX-6.9) ; la session s'emploie aussi par ``with``."""
        s = Session(self, run_id, on_behalf_of)
        s._ouvrir()
        self._sessions.add(s)
        self._armer_sortie()
        return s


class Session:
    """Session SDK ; après une connexion perdue, l'objet désigne une session nouvelle
    de mêmes ``run_id`` et ``on_behalf_of`` (EX-6.13)."""

    def __init__(self, client: ClientNoortrace, run_id: Optional[str], on_behalf_of: Optional[str]) -> None:
        self._client = client
        self._run_id = run_id
        self._on_behalf_of = on_behalf_of
        self._id: Optional[str] = None
        self._generation = 0
        self._contextes: set = set()
        self._contextes_perdus: set = set()
        self._close = False
        self._verrou = threading.RLock()
        self.reponse_ouvrir: Optional[Dict[str, Any]] = None

    def _ouvrir(self) -> None:
        r, generation = self._client._ouvrir_session(self._run_id, self._on_behalf_of)
        self._id = r["session"]
        self._generation = generation
        self.reponse_ouvrir = r

    def _assurer(self) -> None:
        """Session vivante ; sinon une session nouvelle, et les références de la
        session perdue ne valent plus (EX-6.13)."""
        if self._close:
            raise NoortraceEntreeInvalide("noortrace: session fermee", {"reason": "session_inconnue"})
        with self._verrou:
            if self._client._vivante(self._generation):
                return
            self._contextes_perdus.update(self._contextes)
            self._contextes.clear()
            self._ouvrir()

    def _appeler(self, nom: str, construire: Callable[[str], dict]) -> Any:
        self._assurer()
        generation = self._generation
        if not self._client._vivante(generation):
            raise NoortraceIndisponible("noortrace: connexion perdue", False)
        c = self._client._connexion
        assert c is not None and self._id is not None
        return c.appeler(nom, construire(self._id), self._client.delai_s)

    # ------------------------------------------------------------ méthodes de 6.2

    def declarer_contexte(self, kind: str, octets: Any, media_type: Optional[str] = None) -> Reference:
        """``noortrace/sdk/declarerContexte`` (EX-6.9) : la référence de la pièce stockée."""
        donnees = base64.b64encode(octets_de(octets)).decode("ascii")
        r = self._appeler("declarerContexte", lambda s: {"session": s, "kind": kind, "media_type": media_type, "bytes_base64": donnees})
        self._contextes.add(r["sha256"])
        return Reference(sha256=r["sha256"], length=r["length"], redacted=r["redacted"])

    def debut_appel(self, tool: str, arguments: Any, classe: Optional[str] = None, contexte: Iterable[str] = (),
                    intent: Optional[str] = None, effects: Optional[list] = None) -> Debut:
        """``noortrace/sdk/debutAppel`` (EX-6.9) : la décision et, pour ``ecriture``,
        l'intention durable (EX-6.3)."""
        self._assurer()
        contexte = list(contexte or ())
        # EX-6.13 : une référence de la session perdue lève sans rien envoyer.
        for s in contexte:
            if s in self._contextes_perdus and s not in self._contextes:
                raise NoortraceEntreeInvalide("noortrace: reference de contexte d'une session perdue",
                                              {"reason": "context_session_perdue"})
        generation = self._generation
        r = self._appeler("debutAppel", lambda s: params_debut(s, tool, arguments, classe, contexte, intent, effects))
        debut = Debut(call=r.get("call"), decision=r.get("decision"), ticket=r.get("ticket"), ticket_state=r.get("ticket_state"))
        _LIENS[debut] = (weakref.ref(self), generation)
        return debut

    def fin_appel(self, debut: Debut, resultat: Any, is_error: bool, duration_ms: int) -> Scelle:
        """``noortrace/sdk/finAppel`` (EX-6.9) : l'événement durable."""
        lien = _LIENS.get(debut)
        if lien is not None:
            session, generation = lien[0](), lien[1]
            # EX-6.13 : un finAppel dont la session a été perdue avant son envoi n'est pas envoyé.
            if session is not self or not self._client._vivante(generation) or self._generation != generation:
                raise NoortraceIndisponible("noortrace: session perdue avant finAppel", False)
        if not self._client._vivante(self._generation):
            raise NoortraceIndisponible("noortrace: connexion perdue", False)
        c = self._client._connexion
        assert c is not None
        r = c.appeler("finAppel", {"call": getattr(debut, "call", None), "result": resultat, "is_error": is_error,
                                   "duration_ms": duration_ms}, self._client.delai_s)
        return Scelle(seq=r.get("seq"), hash=r.get("hash"))

    def appel_outil(self, tool: str, arguments: Any, fonction: Callable[..., Any], classe: Optional[str] = None,
                    contexte: Iterable[str] = (), intent: Optional[str] = None, effects: Optional[list] = None) -> Any:
        """``debut_appel``, ``fonction(**arguments)``, ``fin_appel`` (EX-6.9, seule méthode
        composée) : le résultat de ``fonction``, rendu après l'événement durable."""
        try:
            debut = self.debut_appel(tool, arguments, classe=classe, contexte=contexte, intent=intent, effects=effects)
        except Exception as e:
            # EX-6.15 : un outil d'écriture n'est jamais exécuté ; une lecture seulement avec « executer », sans événement.
            if (classe or "ecriture") == "lecture" and self._client.sur_indisponibilite_lecture == "executer":
                journal.warning("noortrace-sdk: debutAppel en echec (%s) ; outil de lecture %s execute sans evenement",
                                nom_de_classe(e), tool)
                return fonction(**arguments)
            raise
        if debut.decision != "autorise":
            raise AppelNonAutorise(debut.decision, debut.ticket, debut.ticket_state)
        t0 = time.monotonic()
        try:
            valeur = fonction(**arguments)
        except Exception as e:
            # Le message de l'exception n'est jamais transmis : seul le nom de sa classe.
            self.fin_appel(debut, {"noortrace_sdk_exception": nom_de_classe(e)}, True, _duree_ms(t0))
            raise
        duree = _duree_ms(t0)
        self.fin_appel(debut, resultat_declare(valeur), False, duree)
        return valeur

    def echange_modele(self, format: str, provider_label: str, request: Any, response: Any, status: Optional[int],
                       duration_ms: int, is_error: bool) -> Scelle:
        """``noortrace/sdk/echangeModele`` (EX-6.9) : l'événement durable."""
        r = self._appeler("echangeModele", lambda s: params_echange(s, format, provider_label, request, response, status,
                                                                     duration_ms, is_error))
        return Scelle(seq=r.get("seq"), hash=r.get("hash"))

    def fermer(self) -> Dict[str, Any]:
        """``noortrace/sdk/fermer`` (EX-6.9)."""
        return self._fermer_borne(self._client.delai_s)

    def _fermer_borne(self, delai_s: float) -> Dict[str, Any]:
        if self._close:
            return {}
        self._client._sessions.discard(self)
        if not self._client._vivante(self._generation):
            self._close = True
            return {}
        c = self._client._connexion
        assert c is not None
        r = c.appeler("fermer", {"session": self._id}, delai_s)
        self._close = True
        return r if isinstance(r, dict) else {}

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, type_, valeur, trace) -> None:
        try:
            self.fermer()
        except Exception:
            # Une erreur de fermeture ne masque pas celle du corps du bloc.
            if valeur is None:
                raise
            journal.warning("noortrace-sdk: fermer en echec apres une exception du bloc")
