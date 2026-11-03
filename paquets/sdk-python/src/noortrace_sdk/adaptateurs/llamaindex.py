"""Adaptateur LlamaIndex (CT-2 6.6, ligne « LlamaIndex (``llama-index-core`` 0.14.25) »).

L'instrumentation de LlamaIndex n'a aucun point d'interception (ses
gestionnaires avalent leurs exceptions) : l'adaptateur **enveloppe chaque
outil** local par ``envelopper_outil(outil) -> AsyncBaseTool``, dont ``call``
et ``acall`` appellent ``debut_appel``, l'outil d'origine, puis ``fin_appel``
(``llama_index/core/tools/types.py``) ; l'agent par flux appelle
``tool.acall(**tool_input)`` (``agent/workflow/base_agent.py``).

- Outil non exécuté : ``ToolOutput(blocks=[texte], tool_name, raw_input,
  raw_output=None, is_error=True)`` (EX-6.19).
- Déclaré à ``fin_appel`` : ``raw_output`` du ``ToolOutput`` d'origine,
  ``is_error`` du ``ToolOutput``.
- Outils MCP (EX-6.17) : l'intégration n'enveloppe que les outils locaux
  qu'elle énumère ; ``envelopper_outil`` rend en outre tel quel un outil
  construit par ``McpToolSpec`` (fonction du module ``llama_index.tools.mcp``,
  LISEZMOI, lecture 157) ou nommé dans ``ignorer``.
- Échanges de modèle (``modele="declarer"``) : gestionnaire d'événements sur
  ``LLMChatStartEvent`` (requête) et ``LLMChatEndEvent`` (réponse), enregistré
  par ``get_dispatcher().add_event_handler`` ; point d'observation, file
  d'EX-6.11 (3), format ``autre``.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from typing import Any, Dict, Iterable, List, Optional

from llama_index.core.base.llms.types import TextBlock
from llama_index.core.instrumentation import get_dispatcher
from llama_index.core.instrumentation.event_handlers import BaseEventHandler
from llama_index.core.instrumentation.events.llm import LLMChatEndEvent, LLMChatStartEvent
from llama_index.core.tools.types import AsyncBaseTool, BaseTool, ToolMetadata, ToolOutput, adapt_to_async_tool

from . import etiquette, file_pour, intercepter, intercepter_async, valeur_declaree, verifier_reglages
from ..erreurs import NoortraceConfiguration

#: Module des fonctions des outils construits par ``McpToolSpec`` (``llama-index-tools-mcp`` 0.6.0).
MODULE_MCP = "llama_index.tools.mcp"


def _est_async(session: Any) -> bool:
    return inspect.iscoroutinefunction(getattr(session, "debut_appel", None))


def est_outil_mcp(outil: Any) -> bool:
    """Outil construit par ``McpToolSpec.to_tool_list(_async)`` : sa fonction est une
    fermeture définie dans ``llama_index.tools.mcp.base`` (``_create_tool_fn``)."""
    for nom in ("_async_fn", "_fn"):
        f = getattr(outil, nom, None)
        module = getattr(f, "__module__", "") or ""
        if module == MODULE_MCP or module.startswith(MODULE_MCP + "."):
            return True
    return False


class _SessionEnFil:
    """Session du client synchrone employée depuis ``acall`` : appels par ``asyncio.to_thread`` (EX-6.14)."""

    def __init__(self, session: Any) -> None:
        self._session = session
        self._client = getattr(session, "_client", None)

    async def debut_appel(self, *a: Any, **k: Any) -> Any:
        return await asyncio.to_thread(self._session.debut_appel, *a, **k)

    async def fin_appel(self, *a: Any, **k: Any) -> Any:
        return await asyncio.to_thread(self._session.fin_appel, *a, **k)


class OutilNoortrace(AsyncBaseTool):
    """Outil enveloppé : point d'interception de LlamaIndex (EX-6.16)."""

    def __init__(self, adaptateur: "AdaptateurLlamaIndex", outil: BaseTool) -> None:
        self._adaptateur = adaptateur
        self.outil_origine = outil

    @property
    def metadata(self) -> ToolMetadata:
        return self.outil_origine.metadata

    def _preparer(self, args: tuple, kwargs: dict) -> tuple:
        nom = self.metadata.get_name()
        arguments: Any = dict(kwargs)
        if args:
            # Ancienne forme ``__call__(input)`` : l'entrée positionnelle sous la clé ``input``.
            arguments = {"input": args[0] if len(args) == 1 else list(args), **arguments}
        return nom, arguments, self._adaptateur.classes.get(nom)

    @staticmethod
    def _declarer(sortie: Any) -> tuple:
        if isinstance(sortie, ToolOutput):
            return valeur_declaree(sortie.raw_output), bool(sortie.is_error)
        return valeur_declaree(sortie), False

    def _erreur(self, texte: str, args: tuple, kwargs: dict) -> ToolOutput:
        return ToolOutput(blocks=[TextBlock(text=texte)], tool_name=self.metadata.get_name(),
                          raw_input={"args": list(args), "kwargs": dict(kwargs)}, raw_output=None, is_error=True)

    def call(self, *args: Any, **kwargs: Any) -> ToolOutput:
        session = self._adaptateur.session
        if _est_async(session):
            raise NoortraceConfiguration("noortrace: session du client asynchrone sur un chemin synchrone (EX-6.14)")
        issue = intercepter(session, lambda: self._preparer(args, kwargs), lambda: self.outil_origine(*args, **kwargs), self._declarer)
        return self._erreur(issue.texte, args, kwargs) if issue.texte is not None else issue.valeur

    async def acall(self, *args: Any, **kwargs: Any) -> ToolOutput:
        session = self._adaptateur.session
        session = session if _est_async(session) else _SessionEnFil(session)
        origine = adapt_to_async_tool(self.outil_origine)

        async def executer() -> Any:
            return await origine.acall(*args, **kwargs)

        issue = await intercepter_async(session, lambda: self._preparer(args, kwargs), executer, self._declarer)
        return self._erreur(issue.texte, args, kwargs) if issue.texte is not None else issue.valeur


class AdaptateurLlamaIndex:
    """``AdaptateurLlamaIndex(session, classes={nom: "lecture" ou "ecriture"},
    modele="passerelle" (défaut) ou "declarer", ignorer=[noms])`` ;
    ``envelopper_outil(outil)``, ``envelopper(outils)``."""

    def __init__(self, session: Any, classes: Optional[Dict[str, str]] = None, modele: str = "passerelle",
                 ignorer: Iterable[str] = ()) -> None:
        self.session = session
        self.classes, self.modele, self.ignorer = verifier_reglages(classes, modele, ignorer)
        self.gestionnaire: Optional[GestionnaireEchangesNoortrace] = None
        if self.modele == "declarer":
            self.gestionnaire = GestionnaireEchangesNoortrace.creer(session)
            get_dispatcher().add_event_handler(self.gestionnaire)

    def envelopper_outil(self, outil: BaseTool) -> BaseTool:
        """Outil local enveloppé (``AsyncBaseTool``) ; un outil MCP ou ignoré est rendu tel quel (EX-6.17)."""
        if isinstance(outil, OutilNoortrace):
            return outil
        nom = outil.metadata.get_name()
        if nom in self.ignorer or est_outil_mcp(outil):
            return outil
        return OutilNoortrace(self, outil)

    def envelopper(self, outils: Iterable[BaseTool]) -> List[BaseTool]:
        return [self.envelopper_outil(o) for o in outils]

    def retirer(self) -> None:
        """Retire le gestionnaire d'événements du répartiteur racine."""
        if self.gestionnaire is not None:
            d = get_dispatcher()
            d.event_handlers = [h for h in d.event_handlers if h is not self.gestionnaire]
            self.gestionnaire = None


class GestionnaireEchangesNoortrace(BaseEventHandler):
    """Gestionnaire d'événements de LlamaIndex : ``LLMChatStartEvent`` (requête,
    instant de départ) et ``LLMChatEndEvent`` (réponse) d'un même span ; l'échange
    est mis dans la file d'EX-6.11 (3), format ``autre``."""

    @classmethod
    def class_name(cls) -> str:
        return "GestionnaireEchangesNoortrace"

    @classmethod
    def creer(cls, session: Any, file_max: int = 1000) -> "GestionnaireEchangesNoortrace":
        g = cls()
        object.__setattr__(g, "_file", file_pour(session, file_max))
        object.__setattr__(g, "_debuts", {})
        return g

    @property
    def file(self) -> Any:
        return self._file

    def handle(self, event: Any, **kwargs: Any) -> Any:
        try:
            if isinstance(event, LLMChatStartEvent):
                d = event.model_dict or {}
                requete: Dict[str, Any] = {"messages": [m.model_dump(mode="json") for m in event.messages]}
                if isinstance(d.get("model"), str):
                    requete = {"model": d["model"], **requete}
                self._debuts[event.span_id] = (time.monotonic(), etiquette(d.get("class_name")), valeur_declaree(requete))
            elif isinstance(event, LLMChatEndEvent):
                t0, label, requete = self._debuts.pop(event.span_id, (time.monotonic(), "local", {}))
                reponse = event.response.model_dump(mode="json") if event.response is not None else None
                self._file.ajouter("autre", label, requete, valeur_declaree(reponse), None,
                                   max(0, int((time.monotonic() - t0) * 1000)), False)
        except Exception:  # noqa: BLE001 - une erreur n'atteint jamais l'agent
            pass
        return None


__all__ = ["AdaptateurLlamaIndex", "OutilNoortrace", "GestionnaireEchangesNoortrace", "est_outil_mcp"]
