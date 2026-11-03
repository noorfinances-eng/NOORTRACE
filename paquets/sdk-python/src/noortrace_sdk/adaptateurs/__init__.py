"""Outils communs aux adaptateurs de cadres d'agents (CT-2 6.6).

Ce module n'ajoute rien à l'interface publique d'EX-6.9 (client et
session) : c'est l'outil des adaptateurs.

- **Points d'interception** (EX-6.16) : ``intercepter`` et
  ``intercepter_async`` appellent ``debut_appel``, n'exécutent l'outil que
  pour ``autorise``, mesurent ``duration_ms`` sur l'horloge monotone,
  appellent ``fin_appel`` et disent ce que le modèle reçoit (EX-6.19).
  Toute exception levée avant l'exécution, qu'elle vienne du SDK ou du code
  de l'adaptateur, laisse l'outil non exécuté (EX-6.15, EX-6.20 (v)).
- **Points d'observation** : ``FileEchanges`` (fil de fond) et
  ``FileEchangesAsync`` (tâche de fond), la file bornée d'EX-6.11 (3), qui
  ne sert qu'à ``echange_modele``, jamais à un appel d'outil.
- **Textes** rendus au modèle quand l'outil n'est pas exécuté (EX-6.19).

Les modules ``noortrace_sdk.adaptateurs.<cadre>`` importent leur cadre ; ce
module n'importe aucun cadre.
"""

from __future__ import annotations

import asyncio
import collections
import inspect
import math
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Iterable, Optional, Tuple

from .._commun import delai_reprise, est_valeur_json, journal, nom_de_classe, nom_du_type
from ..erreurs import (
    AppelNonAutorise,
    NoortraceDegrade,
    NoortraceEntreeInvalide,
    NoortraceIndisponible,
    NoortraceLimite,
    texte_non_autorise,
)

#: Textes fixes d'EX-6.19 (ASCII, français sans accent).
TEXTE_DEGRADE = "noortrace: appel bloque, enregistreur en mode degrade"
TEXTE_INJOIGNABLE = "noortrace: enregistreur injoignable"
TEXTE_LIMITE = "noortrace: taille maximale depassee"
TEXTE_ENTREE_INVALIDE = "noortrace: appel refuse, entree invalide"
TEXTE_NON_DURABLE = "noortrace: appel execute, evenement non durable"

#: Motif d'un nom d'outil de CT-1 (``$defs/nom_outil``), 128 caractères au plus.
_MOTIF_NOM_OUTIL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")

#: Valeurs admises de ``modele`` (EX-6.17).
MODELES = ("passerelle", "declarer")


def nom_declarable(nom: Any) -> bool:
    """Le nom respecte-t-il le motif de 6.2 (motif de CT-1, sans ``__``, hors ``noortrace.``) ? (EX-6.18)"""
    return isinstance(nom, str) and bool(_MOTIF_NOM_OUTIL.match(nom)) and "__" not in nom and not nom.startswith("noortrace.")


def texte_avant_execution(e: BaseException) -> str:
    """Texte rendu au modèle quand ``debut_appel`` n'a pas autorisé l'outil (EX-6.19).

    Les cinq textes d'EX-6.19 ; une erreur du protocole d'un autre code, ou
    une exception du code de l'adaptateur, reçoit celui de
    ``NoortraceIndisponible`` (LISEZMOI, lecture 151)."""
    if isinstance(e, AppelNonAutorise):
        return e.texte
    if isinstance(e, NoortraceDegrade):
        return TEXTE_DEGRADE
    if isinstance(e, NoortraceLimite):
        return TEXTE_LIMITE
    if isinstance(e, NoortraceEntreeInvalide):
        return TEXTE_ENTREE_INVALIDE
    return TEXTE_INJOIGNABLE


def valeur_declaree(v: Any) -> Any:
    """Valeur JSON déclarée (EX-6.9) : la valeur, ou ``{"noortrace_sdk_non_json": "<type>"}``."""
    return v if est_valeur_json(v) else {"noortrace_sdk_non_json": nom_du_type(v)}


def verifier_reglages(classes: Any, modele: Any, ignorer: Any) -> Tuple[dict, str, frozenset]:
    """Réglages communs des adaptateurs : ``classes``, ``modele``, ``ignorer`` (EX-6.17, EX-6.18)."""
    classes = dict(classes or {})
    for k, v in classes.items():
        if not isinstance(k, str) or v not in ("lecture", "ecriture"):
            raise ValueError("noortrace: classes attend {nom: 'lecture' ou 'ecriture'}")
    if modele not in MODELES:
        raise ValueError("noortrace: modele vaut 'passerelle' ou 'declarer'")
    return classes, modele, frozenset(ignorer or ())


def _duree_ms(t0: float) -> int:
    return max(0, math.floor((time.monotonic() - t0) * 1000))


@dataclass
class Issue:
    """Issue d'une interception : l'outil a-t-il été exécuté, que rend-on au modèle ?

    ``texte`` non nul : le cadre rend un résultat d'erreur d'outil portant ce
    texte (EX-6.19), à la place de ``valeur`` quand l'outil a été exécuté
    (``fin_appel`` en échec : « evenement non durable »)."""

    executee: bool
    texte: Optional[str] = None
    valeur: Any = None
    t_autorise: Optional[float] = None


def _lecture_sans_evenement(session: Any, classe: Optional[str]) -> bool:
    """EX-6.15 : lecture exécutée sans événement seulement avec ``executer``."""
    client = getattr(session, "_client", None)
    return classe == "lecture" and getattr(client, "sur_indisponibilite_lecture", "bloquer") == "executer"


def intercepter(session: Any, preparer: Callable[[], Tuple[str, Any, Optional[str]]], executer: Callable[[], Any],
                declarer: Callable[[Any], Tuple[Any, bool]]) -> Issue:
    """Point d'interception synchrone (EX-6.16, EX-6.18, EX-6.19).

    ``preparer()`` rend ``(nom, arguments, classe)`` ; ``executer()`` exécute
    l'outil ; ``declarer(valeur)`` rend ``(resultat, is_error)`` à déclarer à
    ``fin_appel``. Une exception de l'outil est déclarée par la forme
    ``noortrace_sdk_exception`` puis relancée."""
    classe: Optional[str] = None
    nom = "?"
    try:
        nom, arguments, classe = preparer()
        if not nom_declarable(nom):
            return Issue(False, TEXTE_ENTREE_INVALIDE)
        debut = session.debut_appel(nom, arguments, classe=classe)
    except Exception as e:  # noqa: BLE001 - EX-6.15 : rien n'est exécuté
        if not isinstance(e, NoortraceEntreeInvalide) and _lecture_sans_evenement(session, classe):
            journal.warning("noortrace-sdk: debutAppel en echec (%s) ; outil de lecture %s execute sans evenement", nom_de_classe(e), nom)
            return Issue(True, None, executer())
        return Issue(False, texte_avant_execution(e))
    if debut.decision != "autorise":
        return Issue(False, texte_non_autorise(debut.ticket, debut.ticket_state))
    t_autorise = time.monotonic()
    t0 = time.monotonic()
    try:
        valeur = executer()
    except Exception as exc:
        try:
            session.fin_appel(debut, {"noortrace_sdk_exception": nom_de_classe(exc)}, True, _duree_ms(t0))
        except Exception:  # noqa: BLE001
            return Issue(True, TEXTE_NON_DURABLE, None, t_autorise)
        raise
    duree = _duree_ms(t0)
    try:
        resultat, is_error = declarer(valeur)
        session.fin_appel(debut, resultat, bool(is_error), duree)
    except Exception:  # noqa: BLE001 - EX-6.19 : l'appel a eu lieu, l'événement n'est pas durable
        return Issue(True, TEXTE_NON_DURABLE, valeur, t_autorise)
    return Issue(True, None, valeur, t_autorise)


async def intercepter_async(session: Any, preparer: Callable[[], Tuple[str, Any, Optional[str]]],
                            executer: Callable[[], Awaitable[Any]], declarer: Callable[[Any], Tuple[Any, bool]]) -> Issue:
    """Point d'interception asynchrone (même contrat qu'``intercepter`` ; session du client asynchrone, EX-6.14)."""
    classe: Optional[str] = None
    nom = "?"
    try:
        nom, arguments, classe = preparer()
        if not nom_declarable(nom):
            return Issue(False, TEXTE_ENTREE_INVALIDE)
        debut = session.debut_appel(nom, arguments, classe=classe)
        if inspect.isawaitable(debut):
            debut = await debut
    except Exception as e:  # noqa: BLE001
        if not isinstance(e, NoortraceEntreeInvalide) and _lecture_sans_evenement(session, classe):
            journal.warning("noortrace-sdk: debutAppel en echec (%s) ; outil de lecture %s execute sans evenement", nom_de_classe(e), nom)
            return Issue(True, None, await executer())
        return Issue(False, texte_avant_execution(e))
    if debut.decision != "autorise":
        return Issue(False, texte_non_autorise(debut.ticket, debut.ticket_state))
    t_autorise = time.monotonic()
    t0 = time.monotonic()

    async def fin(resultat: Any, is_error: bool, duree: int) -> None:
        r = session.fin_appel(debut, resultat, is_error, duree)
        if inspect.isawaitable(r):
            await r

    try:
        valeur = await executer()
    except Exception as exc:
        try:
            await fin({"noortrace_sdk_exception": nom_de_classe(exc)}, True, _duree_ms(t0))
        except Exception:  # noqa: BLE001
            return Issue(True, TEXTE_NON_DURABLE, None, t_autorise)
        raise
    duree = _duree_ms(t0)
    try:
        resultat, is_error = declarer(valeur)
        await fin(resultat, bool(is_error), duree)
    except Exception:  # noqa: BLE001
        return Issue(True, TEXTE_NON_DURABLE, valeur, t_autorise)
    return Issue(True, None, valeur, t_autorise)


# ---------------------------------------------------------------- file des échanges observés


class FileEchanges:
    """File bornée des échanges de modèle observés (EX-6.11 (3)), vidée par un unique fil de fond.

    ``ajouter`` ne bloque ni ne lève ; file pleine, l'échange le plus récent est
    abandonné, compté (``echanges_perdus``) et noté au journaliseur
    ``noortrace_sdk``. Un échange que le fil ne peut pas remettre parce que le
    démon est injoignable reste en tête tant que sa requête n'a pas été écrite
    (``envoyee`` faux) et il est retenté après la reprise de connexion
    (EX-6.13) ; un échange écrit sans réponse est abandonné et compté."""

    def __init__(self, session: Any, file_max: int = 1000) -> None:
        self.session = session
        self.file_max = file_max
        self.echanges_perdus = 0
        self._file: "collections.deque[dict]" = collections.deque()
        self._condition = threading.Condition()
        self._fil: Optional[threading.Thread] = None
        self._occupe = False

    def ajouter(self, format: str, provider_label: str, request: Any, response: Any, status: Optional[int],
                duration_ms: int, is_error: bool) -> bool:
        """Met un échange en file, sans jamais attendre ni lever (EX-6.11 (3))."""
        try:
            with self._condition:
                if len(self._file) >= self.file_max:
                    self.echanges_perdus += 1
                    journal.warning("noortrace-sdk: file des echanges pleine (%d) ; echange abandonne, %d perdu(s)",
                                    self.file_max, self.echanges_perdus)
                    return False
                self._file.append({"format": format, "provider_label": provider_label, "request": request,
                                   "response": response, "status": status, "duration_ms": duration_ms, "is_error": is_error})
                if self._fil is None or not self._fil.is_alive():
                    self._fil = threading.Thread(target=self._vider, name="noortrace-sdk-echanges", daemon=True)
                    self._fil.start()
                self._condition.notify_all()
                return True
        except Exception:  # noqa: BLE001 - une erreur de la file n'atteint jamais l'agent
            return False

    def vide(self, delai_s: Optional[float] = None) -> bool:
        """Attend que la file soit vide (arrêt, essais) ; rend vrai si elle l'est."""
        fin = None if delai_s is None else time.monotonic() + delai_s
        with self._condition:
            while self._file or self._occupe:
                reste = None if fin is None else fin - time.monotonic()
                if reste is not None and reste <= 0:
                    return False
                self._condition.wait(reste if reste is not None else 0.1)
            return True

    def _vider(self) -> None:
        n = 0
        while True:
            with self._condition:
                if not self._file:
                    self._occupe = False
                    self._condition.notify_all()
                    return
                p = self._file[0]
                self._occupe = True
            try:
                self.session.echange_modele(**p)
                with self._condition:
                    self._file.popleft()
                n = 0
            except NoortraceIndisponible as e:
                if not e.envoyee:
                    # Démon injoignable avant l'écriture : l'échange reste en tête (EX-6.13).
                    time.sleep(delai_reprise(min(n, 4)))
                    n += 1
                    continue
                self._perdu(e)
            except Exception as e:  # noqa: BLE001
                self._perdu(e)

    def _perdu(self, e: BaseException) -> None:
        with self._condition:
            if self._file:
                self._file.popleft()
            self.echanges_perdus += 1
        journal.warning("noortrace-sdk: echange non remis (%s) ; %d perdu(s)", nom_de_classe(e), self.echanges_perdus)


class FileEchangesAsync:
    """File bornée des échanges observés pour une session du client asynchrone (EX-6.11 (3)),
    vidée par une unique tâche de fond dans la boucle de la session. ``ajouter``
    peut être appelée depuis un autre fil (gestionnaires exécutés en tâche de fond)."""

    def __init__(self, session: Any, file_max: int = 1000) -> None:
        self.session = session
        self.file_max = file_max
        self.echanges_perdus = 0
        self._file: "collections.deque[dict]" = collections.deque()
        self._tache: Optional[asyncio.Task] = None
        self._boucle: Optional[asyncio.AbstractEventLoop] = None
        self._verrou = threading.Lock()

    def _boucle_session(self) -> Optional[asyncio.AbstractEventLoop]:
        if self._boucle is None:
            self._boucle = getattr(getattr(self.session, "_client", None), "_boucle", None)
        return self._boucle

    def ajouter(self, format: str, provider_label: str, request: Any, response: Any, status: Optional[int],
                duration_ms: int, is_error: bool) -> bool:
        """Met un échange en file, sans jamais attendre ni lever (EX-6.11 (3))."""
        try:
            p = {"format": format, "provider_label": provider_label, "request": request, "response": response,
                 "status": status, "duration_ms": duration_ms, "is_error": is_error}
            with self._verrou:
                if len(self._file) >= self.file_max:
                    self.echanges_perdus += 1
                    journal.warning("noortrace-sdk: file des echanges pleine (%d) ; echange abandonne, %d perdu(s)",
                                    self.file_max, self.echanges_perdus)
                    return False
                self._file.append(p)
            boucle = self._boucle_session()
            try:
                courante = asyncio.get_running_loop()
            except RuntimeError:
                courante = None
            if boucle is None:
                boucle = courante
                self._boucle = boucle
            if boucle is None:
                return True
            if courante is boucle:
                self._lancer()
            else:
                boucle.call_soon_threadsafe(self._lancer)
            return True
        except Exception:  # noqa: BLE001
            return False

    def _lancer(self) -> None:
        if self._tache is None or self._tache.done():
            self._tache = asyncio.get_running_loop().create_task(self._vider())

    async def vide(self) -> None:
        """Attend que la file soit vide (arrêt, essais)."""
        while True:
            t = self._tache
            if t is None or t.done():
                if not self._file:
                    return
                self._lancer()
                t = self._tache
            await asyncio.shield(t)

    async def _vider(self) -> None:
        n = 0
        while True:
            with self._verrou:
                if not self._file:
                    return
                p = self._file[0]
            try:
                await self.session.echange_modele(**p)
                with self._verrou:
                    self._file.popleft()
                n = 0
            except NoortraceIndisponible as e:
                if not e.envoyee:
                    await asyncio.sleep(delai_reprise(min(n, 4)))
                    n += 1
                    continue
                self._perdu(e)
            except Exception as e:  # noqa: BLE001
                self._perdu(e)

    def _perdu(self, e: BaseException) -> None:
        with self._verrou:
            if self._file:
                self._file.popleft()
            self.echanges_perdus += 1
        journal.warning("noortrace-sdk: echange non remis (%s) ; %d perdu(s)", nom_de_classe(e), self.echanges_perdus)


def file_pour(session: Any, file_max: int = 1000) -> Any:
    """File des échanges adaptée à la session (client synchrone ou asynchrone)."""
    return FileEchangesAsync(session, file_max) if inspect.iscoroutinefunction(getattr(session, "echange_modele", None)) else FileEchanges(session, file_max)


def etiquette(texte: Any, defaut: str = "local") -> str:
    """``provider_label`` au motif de ``$defs/model_route/provider_label`` (``^[a-z0-9][a-z0-9.-]{0,31}$``)."""
    if not isinstance(texte, str):
        return defaut
    t = re.sub(r"[^a-z0-9.-]+", "-", texte.lower()).strip("-.")
    t = t[:32].rstrip("-.")
    return t if t and re.match(r"^[a-z0-9]", t) else defaut


__all__ = [
    "TEXTE_DEGRADE",
    "TEXTE_INJOIGNABLE",
    "TEXTE_LIMITE",
    "TEXTE_ENTREE_INVALIDE",
    "TEXTE_NON_DURABLE",
    "FileEchanges",
    "FileEchangesAsync",
    "Issue",
    "intercepter",
    "intercepter_async",
    "nom_declarable",
    "texte_avant_execution",
    "valeur_declaree",
    "etiquette",
    "file_pour",
]
