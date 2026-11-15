"""Agent du scénario d'intégration CT-9 TI-4 : SDK officiel d'Anthropic pour
Python (``anthropic`` 2.3.0, CT-2 §6.4) dirigé vers la passerelle par
``ANTHROPIC_BASE_URL``, le jeton statique de la connexion d'hôte dans
``ANTHROPIC_API_KEY`` (CT-2 §19.5.2 : la route ``/v1/messages`` de la
démonstration est en ``credentials: "propre"``, ``auth_header: "x-api-key"``),
et ``X-Noortrace-Run-Id`` posé en en-tête par défaut (``ANTHROPIC_CUSTOM_HEADERS``
de 19.5.2 fait de même) ; outils par le frontal MCP avec le client MCP de
référence (``mcp`` 2.3.0, Streamable HTTP, ère 2026-07-28). Il joue le
scénario de CT-2 §19.2 : échange de modèle hors flux, ``claims.get``, échange
en flux SSE (``messages.stream``), ``payments.create`` retenu puis redemandé
après la décision, échange de clôture. Les outils sont déclarés au modèle sous
leur nom assaini (EX-4.12 : l'API Messages refuse le point) ; ``tools/call``
porte le nom annoncé.

Variables : NOORTRACE_MCP_URL, NOORTRACE_MCP_TOKEN, ANTHROPIC_BASE_URL,
ANTHROPIC_API_KEY (= jeton de la passerelle), NOORTRACE_RUN_ID ;
AGENT_JETON_ENTETE=x-noortrace-token : porte en plus le jeton dans
``X-Noortrace-Token`` (pour une route qui lirait un autre en-tête que
``x-api-key``).
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import commun  # noqa: E402,F401  (chemin du SDK Python du dépôt)

import anthropic  # noqa: E402

from commun import DEMANDE, rapporter_echec, MODELE, SYSTEME, Appel, Trace, appeler_avec_approbation_async, session_mcp, assainir, configuration, dire, schema_entree, texte_resultat  # noqa: E402


async def principal() -> int:
    cfg = configuration()
    trace = Trace(sdk=f"anthropic {anthropic.__version__}")
    entetes = {"X-Noortrace-Run-Id": cfg.run_id}
    if os.environ.get("AGENT_JETON_ENTETE") == "x-noortrace-token":
        entetes["X-Noortrace-Token"] = os.environ.get("NOORTRACE_GATEWAY_TOKEN", "")
    # URL de base et clé lues dans l'environnement par le SDK (ANTHROPIC_BASE_URL, ANTHROPIC_API_KEY).
    client = anthropic.AsyncAnthropic(default_headers=entetes, max_retries=0, timeout=120)
    trace.notes["base_url"] = str(client.base_url)
    trace.notes["entetes_auth"] = dict(client.auth_headers) if hasattr(client, "auth_headers") else None
    async with session_mcp(cfg) as session:
        if True:
            liste = await session.list_tools()
            annonces = [t.name for t in liste.tools]
            outils = [{"name": assainir(t.name), "description": t.description or "", "input_schema": schema_entree(t)} for t in liste.tools]
            dire(f"outils annoncés par l'enregistreur : {', '.join(annonces)}")
            annonce_de = {assainir(n): n for n in annonces}
            messages = [{"role": "user", "content": DEMANDE}]
            for echange in range(1, 13):
                flux_sse = echange == 2
                if flux_sse:
                    async with client.messages.stream(model=MODELE, max_tokens=1024, system=SYSTEME, messages=messages, tools=outils) as s:
                        message = await s.get_final_message()
                else:
                    message = await client.messages.create(model=MODELE, max_tokens=1024, system=SYSTEME, messages=messages, tools=outils)
                appels = [b for b in message.content if b.type == "tool_use"]
                trace.echange(format="anthropic-messages", flux=flux_sse, modele=message.model, id=message.id, stop_reason=message.stop_reason, demandes=[a.name for a in appels])
                if not appels:
                    trace.fin = "".join(b.text for b in message.content if b.type == "text")
                    dire(f"modèle (fin de tour) : {trace.fin}")
                    break
                dire(f"modèle ({'flux SSE' if flux_sse else 'hors flux'}) : demande {', '.join(a.name for a in appels)}")
                resultats = []
                for a in appels:
                    outil = annonce_de.get(a.name)
                    if outil is None:
                        raise RuntimeError(f"le modèle demande un outil que l'enregistreur n'annonce pas : {a.name}")
                    ta = Appel(outil=outil, nom_modele=a.name, arguments=dict(a.input))
                    trace.appels.append(ta)
                    r = await appeler_avec_approbation_async(lambda: session.call_tool(outil, dict(a.input), meta={"noortrace/delegation": {"run_id": cfg.run_id}}), ta, cfg.pause_s, cfg.attente_max_s)
                    dire(f"{outil} : {'résultat en erreur' if ta.is_error else 'résultat reçu'} après {ta.emissions} émission(s)")
                    bloc = {"type": "tool_result", "tool_use_id": a.id, "content": texte_resultat(r)}
                    if ta.is_error:
                        bloc["is_error"] = True
                    resultats.append(bloc)
                messages.append({"role": "assistant", "content": [b.model_dump(exclude_none=True) for b in message.content]})
                messages.append({"role": "user", "content": resultats})
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
