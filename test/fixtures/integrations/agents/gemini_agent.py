"""Agent du scénario d'intégration CT-9 TI-6 : SDK officiel de Gemini pour
Python (``google-genai`` 2.33.0, CT-2 §19.5.7) vers la route ``gemini`` de la
passerelle (``/v1beta/models/<modèle>:generateContent`` et
``:streamGenerateContent?alt=sse``, jeton de l'hôte dans ``x-goog-api-key``,
EX-5.28), par les deux voies de 19.5.7 : « sans changer le code »
(``GOOGLE_GEMINI_BASE_URL`` et ``GEMINI_API_KEY`` dans l'environnement,
``GOOGLE_API_KEY`` absente) pour le premier échange, « dans le code »
(``genai.Client(api_key=…, http_options=HttpOptions(base_url=…, headers=
{"X-Noortrace-Run-Id": …}))``) pour les suivants, dont le deuxième en flux
(``generate_content_stream``). L'appel automatique de fonctions est désactivé
(EX-19.6) : chaque ``functionCall`` reçu est exécuté par le frontal MCP
(``tools/call`` du nom annoncé, arguments = ``args`` sans modification,
EX-5.22), avec le client MCP de référence (``mcp`` 2.3.0). Les fonctions sont
déclarées au modèle sous le nom annoncé (Gemini admet le point).

Variables : NOORTRACE_MCP_URL, NOORTRACE_MCP_TOKEN, GOOGLE_GEMINI_BASE_URL,
GEMINI_API_KEY (= jeton de la passerelle), NOORTRACE_GATEWAY_URL,
NOORTRACE_GATEWAY_TOKEN, NOORTRACE_RUN_ID.
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import commun  # noqa: E402,F401  (chemin du SDK Python du dépôt)

from google import genai  # noqa: E402
from google.genai import types  # noqa: E402

from commun import DEMANDE, rapporter_echec, MODELE, SYSTEME, Appel, Trace, appeler_avec_approbation_async, session_mcp, configuration, dire, schema_entree, texte_resultat  # noqa: E402


def declarations(outils) -> types.Tool:
    return types.Tool(function_declarations=[types.FunctionDeclaration(name=t.name, description=t.description or "", parameters_json_schema=schema_entree(t)) for t in outils])


async def principal() -> int:
    cfg = configuration()
    trace = Trace(sdk=f"google-genai {genai.__version__}")
    if "GOOGLE_API_KEY" in os.environ:
        raise RuntimeError("GOOGLE_API_KEY doit être absente (19.5.7 : lue avant GEMINI_API_KEY)")
    # Voie « sans changer le code » : URL de base et clé dans l'environnement.
    client_env = genai.Client()
    # Voie « dans le code » : HttpOptions, avec le run_id déclaré.
    client_code = genai.Client(api_key=cfg.passerelle_jeton, http_options=types.HttpOptions(base_url=cfg.passerelle_url, headers={"X-Noortrace-Run-Id": cfg.run_id}))
    async with session_mcp(cfg) as session:
        if True:
            liste = await session.list_tools()
            annonces = [t.name for t in liste.tools]
            dire(f"outils annoncés par l'enregistreur : {', '.join(annonces)}")
            config = types.GenerateContentConfig(
                system_instruction=SYSTEME,
                tools=[declarations(liste.tools)],
                automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
            )
            historique = [types.Content(role="user", parts=[types.Part(text=DEMANDE)])]
            for echange in range(1, 13):
                flux_sse = echange == 2
                client = client_env if echange == 1 else client_code
                voie = "environnement" if echange == 1 else "code"
                if flux_sse:
                    parts, texte = [], ""
                    version_modele = None
                    async for morceau in await client.aio.models.generate_content_stream(model=MODELE, contents=historique, config=config):
                        version_modele = morceau.model_version or version_modele
                        for p in morceau.candidates[0].content.parts or []:
                            if p.text:
                                texte += p.text
                            if p.function_call is not None:
                                parts.append(p)
                    contenu = types.Content(role="model", parts=([types.Part(text=texte)] if texte else []) + parts)
                else:
                    reponse = await client.aio.models.generate_content(model=MODELE, contents=historique, config=config)
                    contenu = reponse.candidates[0].content
                    version_modele = reponse.model_version
                appels = [p for p in (contenu.parts or []) if p.function_call is not None]
                trace.echange(format="gemini", flux=flux_sse, voie=voie, modele=version_modele, demandes=[p.function_call.name for p in appels])
                # Le tour du modèle qui porte les functionCall précède leurs réponses (19.5.7).
                historique.append(contenu)
                if not appels:
                    trace.fin = "".join(p.text or "" for p in (contenu.parts or []))
                    dire(f"modèle (fin de tour) : {trace.fin}")
                    break
                dire(f"modèle ({'flux SSE' if flux_sse else 'hors flux'}, voie {voie}) : demande {', '.join(p.function_call.name for p in appels)}")
                reponses = []
                for p in appels:
                    nom = p.function_call.name
                    if nom not in annonces:
                        raise RuntimeError(f"le modèle demande un outil que l'enregistreur n'annonce pas : {nom}")
                    args = dict(p.function_call.args or {})
                    ta = Appel(outil=nom, nom_modele=nom, arguments=args)
                    trace.appels.append(ta)
                    r = await appeler_avec_approbation_async(lambda: session.call_tool(nom, dict(args), meta={"noortrace/delegation": {"run_id": cfg.run_id}}), ta, cfg.pause_s, cfg.attente_max_s)
                    dire(f"{nom} : {'résultat en erreur' if ta.is_error else 'résultat reçu'} après {ta.emissions} émission(s)")
                    reponses.append(types.Part(function_response=types.FunctionResponse(name=nom, response={"error": texte_resultat(r)} if ta.is_error else {"result": texte_resultat(r)})))
                historique.append(types.Content(role="user", parts=reponses))
            else:
                raise RuntimeError("le tour n'est pas clos après 12 échanges")
    trace.imprimer()
    return 0


if __name__ == "__main__":
    try:
        code = asyncio.run(principal())
    except BaseException as e:  # noqa: BLE001
        rapporter_echec(e)
        code = 1
    sys.exit(code)
