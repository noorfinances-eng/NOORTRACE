"""Agent du scénario d'intégration CT-9 TI-10 : LiteLLM 1.106.4 en
bibliothèque (``litellm.completion(model="openai/…", api_base=…)``, CT-2
§19.5.10), vers la passerelle (``--cible passerelle``, route
``/v1/chat/completions``), ou vers un mandataire LiteLLM placé devant la
passerelle (``--cible mandataire``, EX-6.22 topologie 2 : la clé est la clé
maîtresse du mandataire, qui présente lui-même le jeton de la passerelle).
Scénario de CT-2 §19.2 : trois échanges (le deuxième en flux, consolidé par
``litellm.stream_chunk_builder``), outils par le frontal MCP (client sans
état de ``commun.py`` : l'environnement de LiteLLM n'a pas de client MCP),
noms assainis pour le modèle. Puis, en bibliothèque seulement, le rappel
``CustomLogger`` de l'adaptateur (``GestionnaireLiteLLM``, CT-2 6.6) déclare
un échange qui **ne passe pas** par la passerelle (modèle local simulé par
``mock_response``), ``modele="declarer"`` (EX-6.17 (c)).

Variables : NOORTRACE_MCP_URL, NOORTRACE_MCP_TOKEN, NOORTRACE_GATEWAY_URL,
NOORTRACE_GATEWAY_TOKEN, NOORTRACE_MANDATAIRE_URL, NOORTRACE_MANDATAIRE_CLE,
NOORTRACE_SDK_SOCKET, NOORTRACE_RUN_ID, PYTHONPATH (``paquets/sdk-python/src``).
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import commun  # noqa: E402,F401  (chemin du SDK Python du dépôt)

import litellm  # noqa: E402

from commun import DEMANDE, MODELE, SYSTEME, Appel, ClientMcpSansEtat, Trace, appeler_avec_approbation, assainir, configuration, dire, rapporter_echec, schema_entree, texte_resultat  # noqa: E402


def principal(cible: str) -> int:
    cfg = configuration()
    trace = Trace(sdk=f"litellm {importlib.metadata.version('litellm')}")
    litellm.suppress_debug_info = True
    litellm.telemetry = False
    if cible == "mandataire":
        api_base, api_key = cfg.mandataire_url, cfg.mandataire_cle
    else:
        api_base, api_key = f"{cfg.passerelle_url}/v1", cfg.passerelle_jeton
    trace.notes["cible"] = cible
    trace.notes["api_base"] = api_base
    mcp = ClientMcpSansEtat(cfg.mcp_url, cfg.mcp_jeton, cfg.run_id, "agent-litellm")
    liste = mcp.lister()
    annonces = [t["name"] for t in liste]
    annonce_de = {assainir(n): n for n in annonces}
    outils = [{"type": "function", "function": {"name": assainir(t["name"]), "description": t.get("description", ""), "parameters": schema_entree(t)}} for t in liste]
    dire(f"outils annoncés par l'enregistreur : {', '.join(annonces)}")
    messages = [{"role": "system", "content": SYSTEME}, {"role": "user", "content": DEMANDE}]
    for echange in range(1, 13):
        flux = echange == 2
        communs = dict(model=f"openai/{MODELE}", api_base=api_base, api_key=api_key, messages=messages, tools=outils, num_retries=0, timeout=120, extra_headers={"X-Noortrace-Run-Id": cfg.run_id})
        if flux:
            morceaux = list(litellm.completion(stream=True, stream_options={"include_usage": True}, **communs))
            r = litellm.stream_chunk_builder(morceaux, messages=messages)
        else:
            r = litellm.completion(**communs)
        message = r.choices[0].message
        appels = list(message.tool_calls or [])
        trace.echange(format="openai-chat", flux=flux, modele=r.model, demandes=[a.function.name for a in appels])
        if not appels:
            trace.fin = message.content
            dire(f"modèle (fin de tour) : {trace.fin}")
            break
        dire(f"modèle ({'flux SSE' if flux else 'hors flux'}) : demande {', '.join(a.function.name for a in appels)}")
        messages.append({"role": "assistant", "content": message.content, "tool_calls": [a.model_dump() for a in appels]})
        for a in appels:
            outil = annonce_de.get(a.function.name)
            if outil is None:
                raise RuntimeError(f"le modèle demande un outil que l'enregistreur n'annonce pas : {a.function.name}")
            args = json.loads(a.function.arguments)
            ta = Appel(outil=outil, nom_modele=a.function.name, arguments=args)
            trace.appels.append(ta)
            res = appeler_avec_approbation(lambda: mcp.appeler(outil, dict(args)), ta, cfg.pause_s, cfg.attente_max_s)
            dire(f"{outil} : {'résultat en erreur' if ta.is_error else 'résultat reçu'} après {ta.emissions} émission(s)")
            messages.append({"role": "tool", "tool_call_id": a.id, "content": texte_resultat(res)})
    else:
        raise RuntimeError("le tour n'est pas clos après 12 échanges")
    if cible == "passerelle" and cfg.sdk_socket:
        # Rappel CustomLogger : un échange hors passerelle, déclaré par le SDK (EX-6.17 (c)).
        import threading

        from noortrace_sdk import ClientNoortrace
        from noortrace_sdk.adaptateurs.litellm import GestionnaireLiteLLM

        class GestionnaireObserve(GestionnaireLiteLLM):
            """Le gestionnaire de l'adaptateur, qui signale en plus le passage du rappel (LiteLLM l'appelle
            depuis un groupe de fils, après le retour de ``completion``) : la session reste ouverte jusque-là."""

            def __init__(self, session):
                super().__init__(session)
                self.vu = threading.Event()

            def _succes(self, *a, **k):
                super()._succes(*a, **k)
                self.vu.set()

        with ClientNoortrace(socket=cfg.sdk_socket, delai_s=30).ouvrir(run_id=cfg.run_id) as session:
            g = GestionnaireObserve(session)
            litellm.callbacks = [g]
            r = litellm.completion(model="openai/modele-local", messages=[{"role": "user", "content": "Résume le sinistre 2026-81044."}], mock_response="Sinistre 2026-81044 : collision, règlement proposé.")
            rappel = g.vu.wait(20)
            vide = g.file.vide(10)
            trace.notes["declare"] = {"modele": "openai/modele-local", "reponse": r.choices[0].message.content, "rappel": rappel, "file_vide": vide, "echanges_perdus": g.file.echanges_perdus}
            litellm.callbacks = []
    trace.imprimer()
    return 0


if __name__ == "__main__":
    cible = sys.argv[sys.argv.index("--cible") + 1] if "--cible" in sys.argv else "passerelle"
    try:
        code = principal(cible)
    except BaseException as e:  # noqa: BLE001
        rapporter_echec(e)
        code = 1
    sys.exit(code)
