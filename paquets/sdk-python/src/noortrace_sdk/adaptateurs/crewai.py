"""Adaptateur CrewAI (CT-2 6.6, ligne « CrewAI 1.15.30 », EX-6.21 ; LISEZMOI, lectures 154, 155 et 168).

Point d'interception : **l'enveloppe de l'outil local** (famille d'EX-6.16,
« l'enveloppe d'un outil »), à la place des crochets globaux
``before_tool_call`` / ``after_tool_call`` de la table de 6.6 : dans CrewAI
1.15.30, un crochet ``before`` ne précède pas toujours une exécution, ni une
seule (cache, ``max_usage_count``, ``task_repeated_usage``, réexécution d'un
outil qui a levé une exception entre un seul ``before`` et un seul ``after``),
et un ``debut_appel`` d'écriture sans exécution donnerait un événement de
reprise « exécuté » (EX-12.15). L'enveloppe est la fonction que les deux
chemins d'exécution de CrewAI appellent pour chaque exécution réelle :
``Tool.func`` (outil de ``@tool``) ou ``BaseTool._run`` (sous-classe), que
``BaseTool.run`` (chemin natif, ``available_functions``) et
``CrewStructuredTool.invoke`` (chemin « ReAct », ``func=self._run``)
appellent, après les contrôles d'usage et le cache.

``AdaptateurCrewAI(session, classes, modele, ignorer).envelopper(outils)``
rend des copies des outils locaux ; pour chaque exécution réelle :
``debut_appel`` (nom vu par le modèle : ``sanitize_tool_name``, arguments
après la validation du cadre et toute modification par un crochet
``before``), l'outil seulement pour ``autorise``, ``fin_appel`` avec la valeur
rendue par l'outil, ``is_error`` vrai si l'outil a levé une exception (puis
relancée, CrewAI la traite). Outil non exécuté : la chaîne du texte
d'EX-6.19, rendue à CrewAI comme résultat de l'outil, que le modèle reçoit.

- Outil MCP (EX-6.17) : ``MCPNativeTool`` et ``MCPToolWrapper`` ne sont pas
  enveloppés (les outils de ``mcps`` ne passent d'ailleurs pas par
  ``envelopper``), ni un nom de ``ignorer``.
- Échanges de modèle (``modele="declarer"``) : ``installer()`` enregistre un
  écouteur ``BaseEventListener`` sur ``LLMCallStartedEvent`` /
  ``LLMCallCompletedEvent`` (point d'observation, file d'EX-6.11 (3)).
- Client synchrone : CrewAI appelle ses outils synchrones depuis des fils ;
  un outil asynchrone est enveloppé par une coroutine qui appelle la session
  par ``asyncio.to_thread``.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from typing import Any, Dict, Iterable, List, Optional

from crewai.events import BaseEventListener, LLMCallCompletedEvent, LLMCallStartedEvent
from crewai.tools.base_tool import BaseTool, Tool
from crewai.tools.mcp_native_tool import MCPNativeTool
from crewai.tools.mcp_tool_wrapper import MCPToolWrapper
from crewai.utilities.string_utils import sanitize_tool_name

from . import FileEchanges, etiquette, intercepter, intercepter_async, valeur_declaree, verifier_reglages
from ..erreurs import NoortraceConfiguration


class _SessionEnFil:
    """Session du client synchrone appelée depuis une coroutine (EX-6.14)."""

    def __init__(self, session: Any) -> None:
        self._session = session
        self._client = getattr(session, "_client", None)

    async def debut_appel(self, *a: Any, **k: Any) -> Any:
        return await asyncio.to_thread(self._session.debut_appel, *a, **k)

    async def fin_appel(self, *a: Any, **k: Any) -> Any:
        return await asyncio.to_thread(self._session.fin_appel, *a, **k)


def _arguments(args: tuple, kwargs: dict) -> Any:
    """Arguments déclarés : les arguments nommés ; une entrée positionnelle sous ``input``."""
    if not args:
        return dict(kwargs)
    return {"input": args[0] if len(args) == 1 else list(args), **kwargs}


class AdaptateurCrewAI:
    """``AdaptateurCrewAI(session, classes={nom: "lecture" ou "ecriture"},
    modele="passerelle" (défaut) ou "declarer", ignorer=[noms])`` ;
    ``envelopper_outil(outil)``, ``envelopper(outils)``, ``installer()``."""

    def __init__(self, session: Any, classes: Optional[Dict[str, str]] = None, modele: str = "passerelle",
                 ignorer: Iterable[str] = ()) -> None:
        if inspect.iscoroutinefunction(getattr(session, "debut_appel", None)):
            # Outils synchrones appelés depuis des fils de CrewAI : client synchrone (EX-6.14).
            raise NoortraceConfiguration("noortrace: CrewAI exige une session du client synchrone (EX-6.14)")
        self.session = session
        self.classes, self.modele, self.ignorer = verifier_reglages(classes, modele, ignorer)
        self.ecouteur: Optional[EcouteurEchangesNoortrace] = None

    def installer(self) -> "AdaptateurCrewAI":
        """Avec ``modele="declarer"``, enregistre l'écouteur des échanges de modèle."""
        if self.modele == "declarer" and self.ecouteur is None:
            self.ecouteur = EcouteurEchangesNoortrace(self.session)
        return self

    def desinstaller(self) -> None:
        if self.ecouteur is not None:
            self.ecouteur.desactiver()

    def _preparer(self, nom: str, args: tuple, kwargs: dict) -> tuple:
        return nom, _arguments(args, kwargs), self.classes.get(nom)

    def _envelopper_fonction(self, nom: str, origine: Any) -> Any:
        adaptateur = self
        declarer = lambda v: (valeur_declaree(v), False)  # noqa: E731

        if inspect.iscoroutinefunction(origine):
            async def enveloppe_async(*args: Any, **kwargs: Any) -> Any:
                async def executer() -> Any:
                    return await origine(*args, **kwargs)

                issue = await intercepter_async(_SessionEnFil(adaptateur.session), lambda: adaptateur._preparer(nom, args, kwargs),
                                                executer, declarer)
                return issue.texte if issue.texte is not None else issue.valeur

            enveloppe_async._noortrace = True  # type: ignore[attr-defined]
            return enveloppe_async

        def enveloppe(*args: Any, **kwargs: Any) -> Any:
            issue = intercepter(adaptateur.session, lambda: adaptateur._preparer(nom, args, kwargs),
                                lambda: origine(*args, **kwargs), declarer)
            return issue.texte if issue.texte is not None else issue.valeur

        enveloppe._noortrace = True  # type: ignore[attr-defined]
        return enveloppe

    def envelopper_outil(self, outil: Any) -> Any:
        """Copie de l'outil local dont la fonction d'exécution est enveloppée ; un outil
        MCP, déjà enveloppé ou nommé dans ``ignorer`` est rendu tel quel."""
        if not isinstance(outil, BaseTool) or isinstance(outil, (MCPNativeTool, MCPToolWrapper)):
            return outil
        if outil.name in self.ignorer or getattr(getattr(outil, "func", None), "_noortrace", False) \
                or getattr(outil.__dict__.get("_run"), "_noortrace", False):
            return outil
        nom = sanitize_tool_name(outil.name)
        copie = outil.model_copy()
        if isinstance(copie, Tool):
            object.__setattr__(copie, "func", self._envelopper_fonction(nom, copie.func))
        else:
            # Méthode d'instance : prime sur ``_run`` de la classe (BaseTool.run, to_structured_tool).
            object.__setattr__(copie, "_run", self._envelopper_fonction(nom, outil._run))
        return copie

    def envelopper(self, outils: Iterable[Any]) -> List[Any]:
        return [self.envelopper_outil(o) for o in outils]


class EcouteurEchangesNoortrace(BaseEventListener):
    """Écouteur des échanges de modèle de CrewAI (``LLMCallStartedEvent`` pour l'instant
    de départ, ``LLMCallCompletedEvent`` pour l'échange), point d'observation :
    file d'EX-6.11 (3), format ``autre``. Une erreur n'atteint jamais l'agent."""

    def __init__(self, session: Any, file_max: int = 1000) -> None:
        self.file = FileEchanges(session, file_max)
        self._debuts: Dict[str, float] = {}
        self._actif = True
        super().__init__()

    def desactiver(self) -> None:
        self._actif = False

    def setup_listeners(self, crewai_event_bus: Any) -> None:
        @crewai_event_bus.on(LLMCallStartedEvent)
        def _debut(source: Any, event: Any) -> None:
            try:
                self._debuts[event.call_id] = time.monotonic()
            except Exception:  # noqa: BLE001
                pass

        @crewai_event_bus.on(LLMCallCompletedEvent)
        def _fin(source: Any, event: Any) -> None:
            if not self._actif:
                return
            try:
                t0 = self._debuts.pop(event.call_id, time.monotonic())
                modele = event.model if isinstance(event.model, str) else None
                fournisseur = modele.split("/", 1)[0] if modele and "/" in modele else "local"
                requete: Dict[str, Any] = {"messages": valeur_declaree(event.messages)}
                if modele:
                    requete = {"model": modele.split("/", 1)[-1], **requete}
                self.file.ajouter("autre", etiquette(fournisseur), requete, valeur_declaree(event.response), None,
                                  max(0, int((time.monotonic() - t0) * 1000)), False)
            except Exception:  # noqa: BLE001
                pass


__all__ = ["AdaptateurCrewAI", "EcouteurEchangesNoortrace"]
