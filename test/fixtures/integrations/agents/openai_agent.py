"""Agent du scénario d'intégration CT-9 TI-5 : SDK officiel d'OpenAI pour
Python (``openai``, dépendance du verrou d'``openai-agents`` 0.24.0) et SDK
Agents d'OpenAI (``openai-agents`` 0.24.0, CT-2 §19.5.4) vers la passerelle,
en trois parties, chacune le scénario de CT-2 §19.2 :

- ``chat`` : Chat Completions (``/v1/chat/completions``), hors flux, en flux,
  hors flux ; outils par le client MCP de référence (``mcp`` 2.3.0), noms
  assainis pour le modèle (le motif des noms de fonction d'OpenAI exclut le
  point), ``tools/call`` du nom annoncé ;
- ``responses`` : Responses (``/v1/responses``), de même (deuxième échange en
  flux : ``stream=True``, réponse finale lue dans ``response.completed``) ;
- ``agents`` : ``Agent(mcp_servers=[MCPServerStreamableHttp(…)])`` et
  ``Runner.run`` (CT-2 §19.5.4), client OpenAI par défaut dirigé vers la
  passerelle (``set_default_openai_client``), API Responses par défaut ; le
  SDK Agents mène la boucle (les outils MCP ne sont pas enveloppés, EX-6.17),
  le modèle simulé redemande l'appel soumis à approbation jusqu'à la décision.

Variables : NOORTRACE_MCP_URL, NOORTRACE_MCP_TOKEN, OPENAI_BASE_URL
(= passerelle + /v1), OPENAI_API_KEY (= jeton de la passerelle),
NOORTRACE_RUN_ID, AGENT_PARTIES (``chat,responses,agents`` par défaut).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import commun  # noqa: E402,F401  (chemin du SDK Python du dépôt)

import openai  # noqa: E402

from commun import DEMANDE, MODELE, SYSTEME, Appel, Trace, appeler_avec_approbation_async, assainir, configuration, dire, rapporter_echec, schema_entree, session_mcp, texte_resultat  # noqa: E402


def outils_chat(liste):
    return [{"type": "function", "function": {"name": assainir(t.name), "description": t.description or "", "parameters": schema_entree(t)}} for t in liste]


def outils_responses(liste):
    return [{"type": "function", "name": assainir(t.name), "description": t.description or "", "parameters": schema_entree(t)} for t in liste]


async def executer(session, trace, cfg, annonce_de, nom_modele, arguments):
    outil = annonce_de.get(nom_modele)
    if outil is None:
        raise RuntimeError(f"le modèle demande un outil que l'enregistreur n'annonce pas : {nom_modele}")
    ta = Appel(outil=outil, nom_modele=nom_modele, arguments=arguments)
    trace.appels.append(ta)
    r = await appeler_avec_approbation_async(lambda: session.call_tool(outil, dict(arguments), meta={"noortrace/delegation": {"run_id": cfg.run_id}}), ta, cfg.pause_s, cfg.attente_max_s)
    dire(f"{outil} : {'résultat en erreur' if ta.is_error else 'résultat reçu'} après {ta.emissions} émission(s)")
    return texte_resultat(r), ta.is_error


async def partie_chat(client, session, trace, cfg, liste, annonce_de):
    outils = outils_chat(liste)
    messages = [{"role": "system", "content": SYSTEME}, {"role": "user", "content": DEMANDE}]
    for echange in range(1, 13):
        flux = echange == 2
        if flux:
            morceaux = []
            async for m in await client.chat.completions.create(model=MODELE, messages=messages, tools=outils, stream=True, stream_options={"include_usage": True}):
                morceaux.append(m)
            message = consolider_chat(morceaux)
            modele = next((m.model for m in morceaux if m.model), None)
        else:
            r = await client.chat.completions.create(model=MODELE, messages=messages, tools=outils)
            message = r.choices[0].message.model_dump(exclude_none=True)
            modele = r.model
        appels = message.get("tool_calls") or []
        trace.echange(partie="chat", format="openai-chat", flux=flux, modele=modele, demandes=[a["function"]["name"] for a in appels])
        if not appels:
            trace.fin = message.get("content")
            dire(f"modèle (fin de tour, chat) : {trace.fin}")
            return
        dire(f"modèle (chat, {'flux SSE' if flux else 'hors flux'}) : demande {', '.join(a['function']['name'] for a in appels)}")
        messages.append({"role": "assistant", "content": message.get("content"), "tool_calls": appels})
        for a in appels:
            texte, _ = await executer(session, trace, cfg, annonce_de, a["function"]["name"], json.loads(a["function"]["arguments"]))
            messages.append({"role": "tool", "tool_call_id": a["id"], "content": texte})
    raise RuntimeError("chat : le tour n'est pas clos après 12 échanges")


def consolider_chat(morceaux):
    """Message consolidé d'un flux Chat Completions (texte et appels d'outils par index), comme un SDK le fait."""
    contenu = ""
    appels = {}
    for m in morceaux:
        for c in m.choices:
            d = c.delta
            if d.content:
                contenu += d.content
            for tc in d.tool_calls or []:
                a = appels.setdefault(tc.index, {"id": None, "type": "function", "function": {"name": "", "arguments": ""}})
                if tc.id:
                    a["id"] = tc.id
                if tc.function and tc.function.name:
                    a["function"]["name"] += tc.function.name
                if tc.function and tc.function.arguments:
                    a["function"]["arguments"] += tc.function.arguments
    return {"role": "assistant", "content": contenu or None, **({"tool_calls": [appels[k] for k in sorted(appels)]} if appels else {})}


async def partie_responses(client, session, trace, cfg, liste, annonce_de):
    outils = outils_responses(liste)
    entree = [{"role": "user", "content": DEMANDE}]
    for echange in range(1, 13):
        flux = echange == 2
        if flux:
            reponse = None
            async for ev in await client.responses.create(model=MODELE, instructions=SYSTEME, input=entree, tools=outils, stream=True):
                if ev.type == "response.completed":
                    reponse = ev.response
            if reponse is None:
                raise RuntimeError("responses : flux sans response.completed")
        else:
            reponse = await client.responses.create(model=MODELE, instructions=SYSTEME, input=entree, tools=outils)
        appels = [it for it in reponse.output if it.type == "function_call"]
        trace.echange(partie="responses", format="openai-responses", flux=flux, modele=reponse.model, demandes=[a.name for a in appels])
        if not appels:
            trace.fin = reponse.output_text
            dire(f"modèle (fin de tour, responses) : {trace.fin}")
            return
        dire(f"modèle (responses, {'flux SSE' if flux else 'hors flux'}) : demande {', '.join(a.name for a in appels)}")
        for it in reponse.output:
            entree.append(it.model_dump(exclude_none=True))
        for a in appels:
            texte, _ = await executer(session, trace, cfg, annonce_de, a.name, json.loads(a.arguments))
            entree.append({"type": "function_call_output", "call_id": a.call_id, "output": texte})
    raise RuntimeError("responses : le tour n'est pas clos après 12 échanges")


async def partie_agents(client, trace, cfg):
    from agents import Agent, Runner, set_default_openai_client, set_tracing_disabled
    from agents.mcp import MCPServerStreamableHttp

    set_tracing_disabled(True)
    set_default_openai_client(client)
    async with MCPServerStreamableHttp(name="noortrace", params={"url": cfg.mcp_url, "headers": {"Authorization": f"Bearer {cfg.mcp_jeton}"}, "timeout": 30}, cache_tools_list=True) as serveur:
        agent = Agent(name="agent-sinistres", instructions=SYSTEME, mcp_servers=[serveur], model=MODELE)
        r = await Runner.run(agent, DEMANDE, max_turns=12)
    # Appels relevés dans les éléments du résultat ; un appel redemandé après le signal d'approbation
    # (même outil, mêmes arguments) est réuni à l'émission qui a abouti.
    appels = {}
    ordre = []
    for it in r.new_items:
        t = type(it).__name__
        if t == "ToolCallItem":
            brut = it.raw_item
            cid = getattr(brut, "call_id", None)
            appels[cid] = Appel(outil=getattr(brut, "name", None), nom_modele=getattr(brut, "name", None), arguments=json.loads(getattr(brut, "arguments", "{}") or "{}"), emissions=1)
            ordre.append(cid)
        elif t == "ToolCallOutputItem":
            brut = it.raw_item
            cid = brut.get("call_id") if isinstance(brut, dict) else getattr(brut, "call_id", None)
            if cid in appels:
                sortie = brut.get("output") if isinstance(brut, dict) else getattr(brut, "output", None)
                appels[cid].resultat = sortie if isinstance(sortie, str) else json.dumps(sortie, ensure_ascii=False)
        elif t == "MessageOutputItem":
            trace.echange(partie="agents", format="openai-responses", flux=False, modele=None, demandes=[])
    signaux = []
    for cid in ordre:
        a = appels[cid]
        if "state=en_attente" in a.resultat:
            signaux.append(a)
            continue
        for s_ in [x for x in signaux if x.outil == a.outil and x.arguments == a.arguments]:
            a.emissions += s_.emissions
            a.tickets.append(s_.resultat.split("ticket=")[1].split(" ")[0])
        signaux = [x for x in signaux if not (x.outil == a.outil and x.arguments == a.arguments)]
        trace.appels.append(a)
    trace.fin = r.final_output if isinstance(r.final_output, str) else str(r.final_output)
    dire(f"modèle (fin de tour, agents) : {trace.fin}")


async def principal() -> int:
    cfg = configuration()
    parties = os.environ.get("AGENT_PARTIES", "chat,responses,agents").split(",")
    trace = Trace(sdk=f"openai {openai.__version__}")
    try:
        import agents

        trace.sdk += f" ; openai-agents {agents.__version__}" if hasattr(agents, "__version__") else " ; openai-agents"
    except Exception:  # noqa: BLE001
        pass
    # URL de base et clé lues dans l'environnement par le SDK (OPENAI_BASE_URL, OPENAI_API_KEY).
    client = openai.AsyncOpenAI(default_headers={"X-Noortrace-Run-Id": cfg.run_id}, max_retries=0, timeout=120)
    trace.notes["base_url"] = str(client.base_url)
    async with session_mcp(cfg) as session:
        liste = (await session.list_tools()).tools
        annonces = [t.name for t in liste]
        annonce_de = {assainir(n): n for n in annonces}
        dire(f"outils annoncés par l'enregistreur : {', '.join(annonces)}")
        if "chat" in parties:
            await partie_chat(client, session, trace, cfg, liste, annonce_de)
        if "responses" in parties:
            await partie_responses(client, session, trace, cfg, liste, annonce_de)
    if "agents" in parties:
        await partie_agents(client, trace, cfg)
    trace.notes["parties"] = parties
    trace.imprimer()
    return 0


if __name__ == "__main__":
    try:
        code = asyncio.run(principal())
    except BaseException as e:  # noqa: BLE001
        rapporter_echec(e)
        code = 1
    sys.exit(code)
