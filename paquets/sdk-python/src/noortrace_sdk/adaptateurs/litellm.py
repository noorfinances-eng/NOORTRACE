"""Adaptateur LiteLLM, bibliothèque (CT-2 6.6, ligne « LiteLLM 1.106.4 (Python, bibliothèque) »).

LiteLLM n'exécute pas d'outil en bibliothèque (R12 conséquence 7) : aucun
point d'interception. Le seul point d'accroche est un **point
d'observation**, pour un échange qui ne passe pas par la passerelle
(``modele="declarer"`` : modèle local, fournisseur sans route) :
``CustomLogger.async_log_success_event`` et ``async_log_failure_event``
(``litellm/integrations/custom_logger.py``), enregistré par
``litellm.callbacks = [gestionnaire]``. Jamais ``log_pre_api_call`` pour
bloquer : une exception y est avalée et l'appel continue.

Un appel synchrone ``litellm.completion`` ne passe que par les gestionnaires
synchrones (``litellm_core_utils/litellm_logging.py``, routage des
gestionnaires de succès) : le gestionnaire définit aussi ``log_success_event``
et ``log_failure_event``, au même effet (LISEZMOI, lecture 159).

L'échange est mis dans la file d'EX-6.11 (3), format ``autre`` : ``request``
est le corps envoyé au fournisseur tel que LiteLLM le consigne
(``additional_args.complete_input_dict``), à défaut ``model`` et
``messages`` ; ``response`` la réponse (``model_dump``) ; un échec est
déclaré ``{"noortrace_sdk_exception": "<classe>"}``, ``is_error`` vrai,
``status`` le statut HTTP de l'exception s'il est connu ; jamais son message.

En mandataire, l'adaptateur ne sert pas : la disposition recommandée place
la passerelle devant le mandataire (EX-6.22, LISEZMOI).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from litellm.integrations.custom_logger import CustomLogger

from . import etiquette, file_pour, valeur_declaree


def _json(v: Any) -> Any:
    if hasattr(v, "model_dump"):
        try:
            v = v.model_dump(mode="json")
        except Exception:  # noqa: BLE001
            try:
                v = v.model_dump()
            except Exception:  # noqa: BLE001
                pass
    return valeur_declaree(v)


def _duree_ms(debut: Any, fin: Any) -> int:
    try:
        return max(0, int((fin - debut).total_seconds() * 1000))
    except Exception:  # noqa: BLE001
        return 0


class GestionnaireLiteLLM(CustomLogger):
    """Gestionnaire de rappels de LiteLLM : ``GestionnaireLiteLLM(session)`` ; à poser par
    ``litellm.callbacks = [gestionnaire]`` pour un échange hors passerelle seulement
    (EX-6.17, ``modele="declarer"``). Une erreur n'atteint jamais l'agent."""

    def __init__(self, session: Any, file_max: int = 1000) -> None:
        super().__init__()
        self.file = file_pour(session, file_max)

    @staticmethod
    def _requete(kwargs: Dict[str, Any]) -> Any:
        extra = kwargs.get("additional_args") or {}
        corps = extra.get("complete_input_dict") if isinstance(extra, dict) else None
        if isinstance(corps, dict) and corps:
            requete = dict(corps)
            if "model" not in requete and isinstance(kwargs.get("model"), str):
                requete["model"] = kwargs["model"]
            return valeur_declaree(requete)
        requete = {"messages": valeur_declaree(kwargs.get("messages"))}
        if isinstance(kwargs.get("model"), str):
            requete = {"model": kwargs["model"], **requete}
        return requete

    def _succes(self, kwargs: Dict[str, Any], reponse: Any, debut: Any, fin: Any) -> None:
        try:
            self.file.ajouter("autre", etiquette(kwargs.get("custom_llm_provider")), self._requete(kwargs), _json(reponse),
                              None, _duree_ms(debut, fin), False)
        except Exception:  # noqa: BLE001
            pass

    def _echec(self, kwargs: Dict[str, Any], reponse: Any, debut: Any, fin: Any) -> None:
        try:
            exc = kwargs.get("exception")
            statut: Optional[int] = getattr(exc, "status_code", None)
            if isinstance(statut, bool) or not isinstance(statut, int):
                statut = None
            corps = {"noortrace_sdk_exception": type(exc).__name__} if exc is not None else _json(reponse)
            self.file.ajouter("autre", etiquette(kwargs.get("custom_llm_provider")), self._requete(kwargs), corps,
                              statut, _duree_ms(debut, fin), True)
        except Exception:  # noqa: BLE001
            pass

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):  # noqa: D401
        self._succes(kwargs, response_obj, start_time, end_time)

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        self._echec(kwargs, response_obj, start_time, end_time)

    def log_success_event(self, kwargs, response_obj, start_time, end_time):
        self._succes(kwargs, response_obj, start_time, end_time)

    def log_failure_event(self, kwargs, response_obj, start_time, end_time):
        self._echec(kwargs, response_obj, start_time, end_time)


__all__ = ["GestionnaireLiteLLM"]
