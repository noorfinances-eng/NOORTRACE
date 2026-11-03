"""Adaptateur LangChain et LangGraph (CT-2 6.6, ligne « LangChain 1.4.7 et LangGraph 1.2.17 »).

Point d'interception : l'intergiciel ``MiddlewareNoortrace(AgentMiddleware)``
définit ``wrap_tool_call(request, handler)`` et ``awrap_tool_call``
(``langchain/agents/middleware/types.py``), passé **en dernier** à
``create_agent(model, tools, middleware=[…])`` ; sans ``create_agent``,
``ToolNode(tools, wrap_tool_call=m.wrap_tool_call, awrap_tool_call=m.awrap_tool_call)``.

- Déclaré à ``debut_appel`` : ``request.tool_call["name"]`` et
  ``request.tool_call["args"]`` (les arguments du modèle, sans les arguments
  injectés, EX-6.18), la classe de ``classes`` ou ``None``.
- Outil non exécuté : ``ToolMessage(content=<texte>, tool_call_id=request.tool_call["id"], status="error")``,
  sans appeler ``handler`` (EX-6.19).
- Déclaré à ``fin_appel`` : ``content`` du ``ToolMessage`` rendu par
  ``handler``, ``is_error`` = ``status == "error"`` ; un ``Command`` de
  LangGraph : ``{"noortrace_sdk_non_json": "Command"}``.
- Outil MCP (EX-6.17) : ``request.tool.metadata`` porte la clé ``mcp``
  (outil converti par ``langchain.mcp``) ; sinon, liste ``ignorer``.
- Échanges de modèle (``modele="declarer"`` seulement, EX-6.17) : le
  gestionnaire de rappels ``m.rappels`` (``on_chat_model_start`` et
  ``on_llm_start`` pour la requête, ``on_llm_end`` pour la réponse), format
  ``autre``, point d'observation (file d'EX-6.11 (3)) ; à passer dans
  ``config={"callbacks": m.rappels}`` (LISEZMOI, lecture 152).
"""

from __future__ import annotations

import asyncio
import inspect
import time
from typing import Any, Awaitable, Callable, Dict, Iterable, Optional
from uuid import UUID

from langchain.agents.middleware import AgentMiddleware
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import ToolMessage, messages_to_dict

from . import Issue, etiquette, file_pour, intercepter, intercepter_async, valeur_declaree, verifier_reglages
from ..erreurs import NoortraceConfiguration


def _est_async(session: Any) -> bool:
    return inspect.iscoroutinefunction(getattr(session, "debut_appel", None))


class _SessionEnFil:
    """Session du client synchrone employée depuis une coroutine : chaque appel
    passe par ``asyncio.to_thread`` pour ne pas bloquer la boucle (EX-6.14)."""

    def __init__(self, session: Any) -> None:
        self._session = session
        self._client = getattr(session, "_client", None)

    async def debut_appel(self, *a: Any, **k: Any) -> Any:
        return await asyncio.to_thread(self._session.debut_appel, *a, **k)

    async def fin_appel(self, *a: Any, **k: Any) -> Any:
        return await asyncio.to_thread(self._session.fin_appel, *a, **k)


class MiddlewareNoortrace(AgentMiddleware):
    """Intergiciel NOORTRACE : ``MiddlewareNoortrace(session, classes={nom: "lecture" ou "ecriture"},
    modele="passerelle" (défaut) ou "declarer", ignorer=[noms])``."""

    def __init__(self, session: Any, classes: Optional[Dict[str, str]] = None, modele: str = "passerelle",
                 ignorer: Iterable[str] = ()) -> None:
        super().__init__()
        self.session = session
        self.classes, self.modele, self.ignorer = verifier_reglages(classes, modele, ignorer)
        self.rappels = [GestionnaireEchangesNoortrace(session)] if self.modele == "declarer" else []

    @property
    def name(self) -> str:
        return "MiddlewareNoortrace"

    # ------------------------------------------------------------ point d'interception

    def _laisser_passer(self, request: Any) -> bool:
        """EX-6.17 : outil MCP (clé ``mcp`` des métadonnées) ou nommé dans ``ignorer``."""
        nom = request.tool_call.get("name")
        if nom in self.ignorer:
            return True
        meta = getattr(request.tool, "metadata", None) if request.tool is not None else None
        return isinstance(meta, dict) and "mcp" in meta

    def _preparer(self, request: Any) -> tuple:
        nom = request.tool_call["name"]
        return nom, request.tool_call.get("args", {}), self.classes.get(nom)

    @staticmethod
    def _declarer(resultat: Any) -> tuple:
        if isinstance(resultat, ToolMessage):
            return valeur_declaree(resultat.content), resultat.status == "error"
        return {"noortrace_sdk_non_json": type(resultat).__name__}, False

    @staticmethod
    def _erreur(request: Any, texte: str) -> ToolMessage:
        return ToolMessage(content=texte, tool_call_id=request.tool_call["id"], status="error")

    def _rendre(self, request: Any, issue: Issue) -> Any:
        if issue.texte is not None:
            return self._erreur(request, issue.texte)
        return issue.valeur

    def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        if _est_async(self.session):
            raise NoortraceConfiguration("noortrace: session du client asynchrone sur un chemin synchrone (EX-6.14)")
        try:
            passer = self._laisser_passer(request)
        except Exception:  # noqa: BLE001 - EX-6.20 (v) : l'outil n'est pas exécuté
            from . import TEXTE_INJOIGNABLE
            return self._erreur(request, TEXTE_INJOIGNABLE)
        if passer:
            return handler(request)
        issue = intercepter(self.session, lambda: self._preparer(request), lambda: handler(request), self._declarer)
        return self._rendre(request, issue)

    async def awrap_tool_call(self, request: Any, handler: Callable[[Any], Awaitable[Any]]) -> Any:
        try:
            passer = self._laisser_passer(request)
        except Exception:  # noqa: BLE001
            from . import TEXTE_INJOIGNABLE
            return self._erreur(request, TEXTE_INJOIGNABLE)
        if passer:
            return await handler(request)
        session = self.session if _est_async(self.session) else _SessionEnFil(self.session)

        async def executer() -> Any:
            return await handler(request)

        issue = await intercepter_async(session, lambda: self._preparer(request), executer, self._declarer)
        return self._rendre(request, issue)


# ---------------------------------------------------------------- point d'observation


def _json(v: Any) -> Any:
    """Représentation JSON d'un objet de LangChain (``model_dump(mode="json")`` s'il existe)."""
    if hasattr(v, "model_dump"):
        try:
            v = v.model_dump(mode="json")
        except Exception:  # noqa: BLE001
            pass
    return valeur_declaree(v)


class GestionnaireEchangesNoortrace(BaseCallbackHandler):
    """Rappels de modèle (R12-F6) : requête vue par ``on_chat_model_start`` ou
    ``on_llm_start``, réponse par ``on_llm_end`` ; l'échange est mis dans la file
    d'EX-6.11 (3), format ``autre`` (6.6, « Échanges de modèle observés par
    ``on_llm_end`` »). Une erreur n'atteint jamais l'agent."""

    raise_error = False

    def __init__(self, session: Any, file_max: int = 1000) -> None:
        super().__init__()
        self.file = file_pour(session, file_max)
        self._debuts: Dict[UUID, tuple] = {}

    @staticmethod
    def _modele(serialized: Any, kwargs: dict) -> tuple:
        params = kwargs.get("invocation_params") or {}
        modele = params.get("model") or params.get("model_name")
        if not isinstance(modele, str):
            k = (serialized or {}).get("kwargs") or {}
            modele = k.get("model") or k.get("model_name")
        return (modele if isinstance(modele, str) else None), etiquette(params.get("_type"))

    def on_chat_model_start(self, serialized: Any, messages: Any, *, run_id: UUID, **kwargs: Any) -> None:
        try:
            modele, label = self._modele(serialized, kwargs)
            requete: Dict[str, Any] = {"messages": [messages_to_dict(m) for m in messages]}
            if modele is not None:
                requete = {"model": modele, **requete}
            self._debuts[run_id] = (time.monotonic(), label, valeur_declaree(requete))
        except Exception:  # noqa: BLE001
            pass

    def on_llm_start(self, serialized: Any, prompts: Any, *, run_id: UUID, **kwargs: Any) -> None:
        try:
            modele, label = self._modele(serialized, kwargs)
            requete: Dict[str, Any] = {"prompts": list(prompts)}
            if modele is not None:
                requete = {"model": modele, **requete}
            self._debuts[run_id] = (time.monotonic(), label, valeur_declaree(requete))
        except Exception:  # noqa: BLE001
            pass

    def on_llm_end(self, response: Any, *, run_id: UUID, **kwargs: Any) -> None:
        try:
            t0, label, requete = self._debuts.pop(run_id, (time.monotonic(), "local", {}))
            duree = max(0, int((time.monotonic() - t0) * 1000))
            self.file.ajouter("autre", label, requete, _json(response), None, duree, False)
        except Exception:  # noqa: BLE001 - une erreur de la file n'atteint jamais l'agent
            pass


__all__ = ["MiddlewareNoortrace", "GestionnaireEchangesNoortrace"]
