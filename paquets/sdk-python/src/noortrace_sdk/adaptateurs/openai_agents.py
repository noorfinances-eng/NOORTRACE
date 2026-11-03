"""Adaptateur du SDK Agents d'OpenAI, Python (CT-2 6.6, ligne « SDK Agents d'OpenAI 0.24.0 (Python) »).

Point d'interception : pour chaque ``FunctionTool`` local, l'adaptateur
remplace ``on_invoke_tool`` — la fonction qui reçoit le contexte et « the
arguments from the LLM, as a JSON string » (``agents/tool.py``) — par une
enveloppe : analyse JSON stricte de la chaîne (une chaîne qui n'est pas du
JSON est déclarée telle quelle), ``debut_appel``, fonction d'origine,
``fin_appel``. ``needs_approval`` et ``on_tool_start`` ne sont pas employés.

- Outil non exécuté : la chaîne du texte d'EX-6.19, valeur rendue par
  ``on_invoke_tool``.
- Déclaré à ``fin_appel`` : les arguments analysés ; la valeur rendue par la
  fonction d'origine.
- Outils MCP (EX-6.17) : les outils de ``mcp_servers`` ne sont pas dans
  ``agent.tools`` (réunis seulement à l'exécution par ``get_all_tools``) et ne
  sont pas enveloppés ; un nom de ``ignorer`` non plus.
- Échanges de modèle (``modele="declarer"``) : ``TracingProcessor.on_span_end``
  sur ``GenerationSpanData`` et ``ResponseSpanData``, jamais ``on_span_start``
  (l'entrée n'y est pas encore posée) ; un span sans entrée ni sortie
  (``trace_include_sensitive_data`` faux) n'est pas déclaré ; point
  d'observation, file d'EX-6.11 (3), format ``autre``. À enregistrer par
  ``add_trace_processor(adaptateur.processeur)``.
"""

from __future__ import annotations

import asyncio
import copy
import inspect
import json
import time
from typing import Any, Dict, Iterable, List, Optional

from agents import Agent, FunctionTool
from agents.tracing import TracingProcessor
from agents.tracing.span_data import GenerationSpanData, ResponseSpanData

from . import file_pour, intercepter_async, valeur_declaree, verifier_reglages


def _est_async(session: Any) -> bool:
    return inspect.iscoroutinefunction(getattr(session, "debut_appel", None))


class _SessionEnFil:
    """Session du client synchrone employée depuis ``on_invoke_tool`` (coroutine) : ``asyncio.to_thread`` (EX-6.14)."""

    def __init__(self, session: Any) -> None:
        self._session = session
        self._client = getattr(session, "_client", None)

    async def debut_appel(self, *a: Any, **k: Any) -> Any:
        return await asyncio.to_thread(self._session.debut_appel, *a, **k)

    async def fin_appel(self, *a: Any, **k: Any) -> Any:
        return await asyncio.to_thread(self._session.fin_appel, *a, **k)


def _refuser_constante(nom: str) -> Any:
    raise ValueError(f"constante non JSON : {nom}")


def analyser_arguments(texte: Any) -> Any:
    """Analyse JSON stricte (``NaN``, ``Infinity`` refusés) ; une chaîne qui n'est pas
    du JSON est déclarée telle quelle (6.6)."""
    if not isinstance(texte, str):
        return valeur_declaree(texte)
    try:
        return json.loads(texte, parse_constant=_refuser_constante)
    except ValueError:
        return texte


class AdaptateurAgentsOpenAI:
    """``AdaptateurAgentsOpenAI(session, classes={nom: "lecture" ou "ecriture"},
    modele="passerelle" (défaut) ou "declarer", ignorer=[noms])`` ;
    ``envelopper_outil(outil)``, ``envelopper(outils)``, ``envelopper_agent(agent)``,
    ``processeur`` (``modele="declarer"``)."""

    def __init__(self, session: Any, classes: Optional[Dict[str, str]] = None, modele: str = "passerelle",
                 ignorer: Iterable[str] = ()) -> None:
        self.session = session
        self.classes, self.modele, self.ignorer = verifier_reglages(classes, modele, ignorer)
        self.processeur: Optional[ProcesseurEchangesNoortrace] = ProcesseurEchangesNoortrace(session) if self.modele == "declarer" else None

    def _preparer(self, outil: FunctionTool, texte: Any) -> tuple:
        return outil.name, analyser_arguments(texte), self.classes.get(outil.name)

    def envelopper_outil(self, outil: Any) -> Any:
        """``FunctionTool`` local dont ``on_invoke_tool`` est enveloppé (copie) ; tout autre
        outil, ou un nom de ``ignorer``, est rendu tel quel."""
        if not isinstance(outil, FunctionTool) or outil.name in self.ignorer or getattr(outil.on_invoke_tool, "_noortrace", False):
            return outil
        origine = outil.on_invoke_tool
        adaptateur = self

        async def on_invoke_tool(ctx: Any, texte: str) -> Any:
            session = adaptateur.session if _est_async(adaptateur.session) else _SessionEnFil(adaptateur.session)

            async def executer() -> Any:
                r = origine(ctx, texte)
                return (await r) if inspect.isawaitable(r) else r

            issue = await intercepter_async(session, lambda: adaptateur._preparer(outil, texte), executer,
                                            lambda v: (valeur_declaree(v), False))
            return issue.texte if issue.texte is not None else issue.valeur

        on_invoke_tool._noortrace = True  # type: ignore[attr-defined]
        nouveau = copy.copy(outil)
        nouveau.on_invoke_tool = on_invoke_tool
        return nouveau

    def envelopper(self, outils: Iterable[Any]) -> List[Any]:
        return [self.envelopper_outil(o) for o in outils]

    def envelopper_agent(self, agent: Agent) -> Agent:
        """Copie de l'agent dont les ``FunctionTool`` de ``agent.tools`` sont enveloppés ;
        ``mcp_servers`` n'est pas touché (EX-6.17)."""
        return agent.clone(tools=self.envelopper(agent.tools))


class ProcesseurEchangesNoortrace(TracingProcessor):
    """Processeur de traces : ``on_span_end`` des spans ``GenerationSpanData`` et
    ``ResponseSpanData`` ; l'échange est mis dans la file d'EX-6.11 (3). Une
    erreur n'atteint jamais l'agent (et le SDK Agents journalise sans propager
    celles d'un processeur)."""

    def __init__(self, session: Any, file_max: int = 1000) -> None:
        self.file = file_pour(session, file_max)

    def on_trace_start(self, trace: Any) -> None:
        return None

    def on_trace_end(self, trace: Any) -> None:
        return None

    def on_span_start(self, span: Any) -> None:
        return None

    @staticmethod
    def _duree(span: Any) -> int:
        try:
            from datetime import datetime

            debut = datetime.fromisoformat(span.started_at)
            fin = datetime.fromisoformat(span.ended_at)
            return max(0, int((fin - debut).total_seconds() * 1000))
        except Exception:  # noqa: BLE001
            return 0

    def on_span_end(self, span: Any) -> None:
        try:
            d = span.span_data
            if isinstance(d, GenerationSpanData):
                if d.input is None and d.output is None:
                    return
                requete: Dict[str, Any] = {"input": valeur_declaree(d.input), "model_config": valeur_declaree(d.model_config)}
                if isinstance(d.model, str):
                    requete = {"model": d.model, **requete}
                reponse = {"output": valeur_declaree(d.output), "usage": valeur_declaree(d.usage)}
            elif isinstance(d, ResponseSpanData):
                if d.input is None and d.response is None:
                    return
                corps = d.response.model_dump(mode="json") if d.response is not None else None
                requete = {"input": valeur_declaree(d.input)}
                modele = getattr(d.response, "model", None)
                if isinstance(modele, str):
                    requete = {"model": modele, **requete}
                reponse = valeur_declaree(corps)
            else:
                return
            erreur = getattr(span, "error", None) is not None
            self.file.ajouter("autre", "openai", requete, reponse, None, self._duree(span), erreur)
        except Exception:  # noqa: BLE001
            pass

    def shutdown(self) -> None:
        return None

    def force_flush(self) -> None:
        return None


__all__ = ["AdaptateurAgentsOpenAI", "ProcesseurEchangesNoortrace", "analyser_arguments"]
