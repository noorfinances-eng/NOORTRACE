# noortrace-sdk — SDK Python de NOORTRACE

**Le SDK n'est un chemin de capture acceptable qu'avec un pare-feu de sortie
qui interdit au processus de l'agent de joindre les serveurs d'outils et les
fournisseurs de modèle autrement que par l'enregistreur (CT-2 EX-6.2).** Un
agent qui peut atteindre ses cibles directement peut n'appeler le SDK que pour
ce qu'il veut montrer : ce qu'il déclare est une déclaration (CT-2 6.3, 6.7),
de rang plus faible que ce que voient le frontal MCP et la passerelle.

Distribution `noortrace-sdk`, module `noortrace_sdk` (CT-2 EX-6.9), Python
3.10 ou plus (EX-6.5), **sans dépendance d'exécution** (bibliothèque standard
seule : prises, fils, `asyncio`, `ssl`, `json`). Il enveloppe les six méthodes
`noortrace/sdk/*` du démon `noortrace` (6.2) sans en ajouter, sans ajouter de
paramètre et sans changer ni les résultats ni leur sémantique (6.5). Il ne
capture rien et ne calcule rien : ni hachage, ni signature, ni écriture de
journal (EX-6.1) ; le démon fait tout le reste. Il se comporte comme le SDK
JavaScript `noortrace-sdk` (`paquets/sdk-js`) là où CT-2 ne les distingue pas
(lectures 146 et 147 pour les deux écarts relevés).

Les adaptateurs de cadres d'agents (6.6) sont dans
`noortrace_sdk.adaptateurs.<cadre>` : LangChain et LangGraph, CrewAI,
LlamaIndex, SDK Agents d'OpenAI, LiteLLM. Les cadres ne sont pas des
dépendances : chaque module n'importe son cadre qu'à son propre import.

## Employer le SDK

```python
from noortrace_sdk import ClientNoortrace, AppelNonAutorise

client = ClientNoortrace.depuis_environnement()          # NOORTRACE_SDK_SOCKET, …
with client.ouvrir(run_id="run-2026-11-10-0007", on_behalf_of=None) as session:
    ref = session.declarer_contexte("document", "…", media_type="text/plain")
    try:
        ordre = session.appel_outil(
            "preparer_paiement", {"sinistre": "2026-77812", "montant": "7400.00"},
            preparer_paiement,                             # exécutée seulement après « autorise » et l'intention durable
            classe="ecriture", contexte=[ref.sha256])
    except AppelNonAutorise as e:
        print(e.texte)                                     # « noortrace: appel soumis a approbation ; ticket=… ; state=… »
    session.echange_modele("autre", "local", requete, reponse, 200, 812, False)
```

Client asynchrone : `ClientNoortraceAsync`, mêmes noms, méthodes `async` ;
`client.ouvrir(…)` s'attend (`await`) ou s'emploie par `async with`.

| Python | Méthode de 6.2 | L'appelant attend |
|---|---|---|
| `ClientNoortrace(socket=None, tcp=None, jeton=None, delai_s=30.0, reprises=2, sur_indisponibilite_lecture="bloquer")`, `ClientNoortrace.depuis_environnement()` | aucune (connexion au premier appel) | rien |
| `client.ouvrir(run_id=None, on_behalf_of=None) -> Session` | `ouvrir` | la session |
| `session.declarer_contexte(kind, octets, media_type=None) -> Reference` | `declarerContexte` | `sha256`, `length`, `redacted` |
| `session.debut_appel(tool, arguments, classe=None, contexte=(), intent=None, effects=None) -> Debut` | `debutAppel` | `call`, `decision`, `ticket`, `ticket_state` et, pour `ecriture`, l'intention durable |
| `session.fin_appel(debut, resultat, is_error, duration_ms) -> Scelle` | `finAppel` | `seq`, `hash`, l'événement durable |
| `session.appel_outil(tool, arguments, fonction, classe=None, contexte=(), intent=None, effects=None)` | `debutAppel`, `fonction(**arguments)`, `finAppel` | le résultat de `fonction`, après l'événement durable |
| `session.echange_modele(format, provider_label, request, response, status, duration_ms, is_error) -> Scelle` | `echangeModele` | `seq`, `hash` |
| `session.fermer()` ; `with client.ouvrir(…) as session:` | `fermer` | `{}` |

`Debut`, `Scelle` et `Reference` sont des classes de données figées, aux
membres de 6.2 ; `Scelle(seq=None, hash=None)` : événement en attente du mode
dégradé (14.5, lecture 114 du démon).

## Connexion (EX-6.10)

Adresse, dans cet ordre : paramètres du constructeur ; variables
`NOORTRACE_SDK_SOCKET` (prise Unix), `NOORTRACE_SDK_TCP` (`hôte:port`),
`NOORTRACE_SDK_TOKEN` (jeton de la prise TCP), `NOORTRACE_SDK_TLS_CA`,
`NOORTRACE_SDK_TLS_CERT`, `NOORTRACE_SDK_TLS_KEY` (mTLS) ; à défaut
`/run/noortrace/sdk.sock`. Un chemin de prise de plus de 103 octets est refusé
à la construction (`NoortraceConfiguration`). Sur une prise Unix, le démon lit
l'utilisateur du processus par une preuve de propriété de fichier (le SDK crée
en exclusion `<répertoire de la prise>/.noortrace-defi-<défi>`, lecture 112 du
démon) ; sur une prise TCP, la première ligne est `{"noortrace_token":
"<jeton>"}`, sauf en mTLS. Une ligne JSON-RPC 2.0 par message, `\n` final ;
`id` entiers croissants à partir de 1 sur chaque connexion.

## Erreurs (EX-6.12)

Toutes dérivent de `NoortraceErreur` (`code`, `message`, `data`) :
`NoortraceIndisponible` (`envoyee`), `NoortraceDegrade` (`raison`),
`NoortraceLimite` (`direction`, `limite`), `NoortraceNonDurable`
(`intent_id`), `NoortraceEntreeInvalide` (`raison`), `NoortraceConfiguration`,
`AppelNonAutorise` (`decision`, `ticket`, `ticket_state`, `texte`).

## Ce qui bloque l'agent et ce qui ne le bloque jamais (EX-6.11, EX-6.15)

Chaque méthode attend la réponse du démon, au plus `delai_s` ; aucune n'est
mise en file. `appel_outil` n'exécute jamais `fonction` avant `autorise` ; si
`debut_appel` échoue, un outil `ecriture` (la classe par défaut) n'est jamais
exécuté, et un outil déclaré `lecture` ne l'est qu'avec
`sur_indisponibilite_lecture="executer"`, sans aucun événement (noté au
journaliseur `noortrace_sdk`). Seul `echange_modele` appelé depuis un point
d'observation d'un adaptateur passe par une file
(`noortrace_sdk.adaptateurs.FileEchanges`, fil de fond, ou `FileEchangesAsync`,
tâche de fond) : bornée (`file_max`, défaut 1 000), l'échange le plus récent
abandonné et compté (`echanges_perdus`) quand elle est pleine ; une erreur de
la file n'atteint jamais l'agent. À la sortie du processus, le client
synchrone tente `fermer`, borné à 2 s (`atexit`).

## Reprise (EX-6.13), fils et asynchrone (EX-6.14)

Une connexion perdue clôt la session côté démon, qui scelle les événements de
reprise des appels d'écriture ou approuvés restés ouverts. Au premier appel
qui suit, le SDK rouvre la connexion et une session de mêmes `run_id` et
`on_behalf_of` (au plus `1 + reprises` tentatives, séparées de
`min(0,5 × 2^n, 8) × (1 − 0,25 × u)` s), que l'objet `Session` désigne
désormais. Une requête déjà écrite n'est jamais renvoyée ; un `fin_appel` dont
la session a été perdue avant son envoi n'est pas envoyé ; une référence de
contexte de la session perdue lève `NoortraceEntreeInvalide` sans rien envoyer.

Le client synchrone se partage entre fils : une connexion, écritures sous
verrou, un fil lecteur qui remet chaque réponse au fil qui attend son `id`.
Le client asynchrone appartient à sa boucle d'événements
(`asyncio.open_unix_connection`) ; employé depuis une autre boucle, il lève
`NoortraceConfiguration`. Après `os.fork()`, l'enfant ouvre une connexion et
une session nouvelles sans toucher à la prise du parent.

## Adaptateurs de cadres (6.6)

Un adaptateur n'appelle `debut_appel` et `fin_appel` que depuis un **point
d'interception** (EX-6.16) ; un **point d'observation** ne sert qu'aux
échanges de modèle, et seulement avec `modele="declarer"` (EX-6.17 (c)) : par
défaut (`modele="passerelle"`), l'URL de base du modèle est dirigée vers la
passerelle (19.5), qui journalise l'échange. Un outil MCP reconnu, ou nommé
dans `ignorer`, n'est jamais déclaré : il passe par le frontal MCP (EX-6.17).
Chaque adaptateur prend `classes={"<nom>": "lecture" ou "ecriture"}`
(EX-6.18) et rend au cadre, quand l'outil n'est pas exécuté, un **résultat
d'erreur d'outil** portant le texte d'EX-6.19 (`noortrace: enregistreur
injoignable`, `noortrace: appel bloque, enregistreur en mode degrade`,
`noortrace: taille maximale depassee`, `noortrace: appel refuse, entree
invalide`, le `texte` d'`AppelNonAutorise`, et, après l'exécution,
`noortrace: appel execute, evenement non durable`).

| Cadre (version essayée) | Accroche | Point d'interception | Outil MCP | Échanges de modèle (`modele="declarer"`) |
|---|---|---|---|---|
| LangChain 1.4.7, LangGraph 1.2.17 (`langgraph-prebuilt` 1.1.1, `langchain-core` 1.7.0) | `noortrace_sdk.adaptateurs.langchain.MiddlewareNoortrace(session, classes, modele, ignorer)`, **dernier** de `create_agent(…, middleware=[…])` ; sans `create_agent`, `ToolNode(tools, wrap_tool_call=m.wrap_tool_call, awrap_tool_call=m.awrap_tool_call)` | `wrap_tool_call` / `awrap_tool_call` ; erreur : `ToolMessage(content=<texte>, tool_call_id=…, status="error")` | clé `mcp` de `request.tool.metadata` (`langchain.mcp`), sinon `ignorer` | `config={"callbacks": m.rappels}` : `on_chat_model_start` / `on_llm_start` puis `on_llm_end`, format `autre` |
| CrewAI 1.15.30 | `a = noortrace_sdk.adaptateurs.crewai.AdaptateurCrewAI(session, classes, modele, ignorer)` ; `Agent(tools=a.envelopper(outils_locaux), mcps=[…])` ; `a.installer()` pour `modele="declarer"` | **enveloppe de l'outil local** (`Tool.func` ou `BaseTool._run`), à la place des crochets de la table (lecture 168, « À corriger dans CT-2 ») : un événement par exécution réelle, sur les chemins natif et « ReAct » ; outil non exécuté : la chaîne d'EX-6.19 rendue comme résultat de l'outil ; déclaré : la valeur rendue, `is_error` vrai si l'outil a levé | outils de `mcps` non enveloppés ; `MCPNativeTool`, `MCPToolWrapper` et `ignorer` rendus tels quels | écouteur `BaseEventListener` sur `LLMCallStartedEvent` / `LLMCallCompletedEvent`, format `autre` |
| LlamaIndex (`llama-index-core` 0.14.25 ; `llama-index-tools-mcp` 0.6.0) | `noortrace_sdk.adaptateurs.llamaindex.AdaptateurLlamaIndex(session, classes, modele, ignorer).envelopper_outil(outil)` (ou `envelopper(outils)`) | `call` / `acall` de l'outil enveloppé ; erreur : `ToolOutput(blocks=[texte], …, raw_output=None, is_error=True)` | outils locaux énumérés seulement ; un outil de `McpToolSpec` est rendu tel quel (lecture 157), sinon `ignorer` | gestionnaire `get_dispatcher().add_event_handler` sur `LLMChatStartEvent` / `LLMChatEndEvent`, format `autre` |
| SDK Agents d'OpenAI 0.24.0 | `noortrace_sdk.adaptateurs.openai_agents.AdaptateurAgentsOpenAI(session, classes, modele, ignorer).envelopper_agent(agent)` (ou `envelopper(outils)`) | `on_invoke_tool` de chaque `FunctionTool` local, enveloppé (arguments : analyse JSON stricte, sinon la chaîne) ; erreur : la chaîne du texte | outils de `mcp_servers` non enveloppés | `add_trace_processor(a.processeur)` : `on_span_end` des spans de génération et de réponse, format `autre` |
| LiteLLM 1.106.4 (bibliothèque) | `litellm.callbacks = [noortrace_sdk.adaptateurs.litellm.GestionnaireLiteLLM(session)]`, pour un échange hors passerelle seulement | aucun (LiteLLM n'exécute pas d'outil) : les outils d'un agent bâti sur LiteLLM passent par `appel_outil` | — | `async_log_success_event`, `async_log_failure_event` (et leurs pendants synchrones, lecture 159), format `autre` |

Ce que chaque adaptateur ne capture pas est dit dans la table de 6.6 ; les
lectures 152 à 160 et 168 y ajoutent ce que la lecture du code publié a montré.

### LiteLLM en mandataire (EX-6.22)

Aucun code d'adaptateur ne sert en mandataire ; deux dispositions :
(a) **recommandée** : agent → passerelle de l'enregistreur → mandataire
LiteLLM → fournisseurs ; la route de la passerelle a pour `upstream` l'URL du
mandataire et pour format celui de l'agent ; l'enregistreur voit la requête de
l'agent, sous la délégation de l'agent ; le pare-feu interdit à l'agent de
joindre le mandataire directement. (b) agent → mandataire → passerelle
(`api_base` des modèles du mandataire) : l'enregistreur voit les requêtes du
mandataire (forme non lue, NV-R12-5), sous une seule connexion d'hôte ; la
corrélation de 5.6 ne distingue plus les agents. La disposition (b) n'est
admise que si la documentation d'intégration le dit (essai de la disposition
(a) : lecture 169). Les crochets
`async_pre_call_hook` du mandataire ne sont pas employés en version 0.

## Environnements d'essai

Chaque cadre est essayé à la version exacte de la table de 6.6, dans un
environnement isolé créé par `uv` à partir d'un fichier de verrou versionné
(versions exactes et empreintes SHA-256 de toutes les dépendances,
résolution universelle pour Python 3.10 et plus) :

| Environnement | Python | Verrou | Contenu direct |
|---|---|---|---|
| `essais-py310`, `essais-py313` | 3.10, 3.13 | `verrous/requirements-essais.txt` | `pytest==9.1.1` |
| `langchain` | 3.12 | `verrous/requirements-langchain.txt` | `langchain[mcp]==1.4.7`, `langchain-core==1.7.0`, `langgraph==1.2.17`, `langgraph-prebuilt==1.1.1` |
| `crewai` | 3.12 | `verrous/requirements-crewai.txt` | `crewai==1.15.30` |
| `llamaindex` | 3.12 | `verrous/requirements-llamaindex.txt` | `llama-index-core==0.14.25`, `llama-index-tools-mcp==0.6.0` |
| `openai-agents` | 3.12 | `verrous/requirements-openai-agents.txt` | `openai-agents==0.24.0` |
| `litellm` | 3.12 | `verrous/requirements-litellm.txt` | `litellm==1.106.4` |
| `litellm-mandataire` | 3.12 | `verrous/requirements-litellm-mandataire.txt` | `litellm[proxy]==1.106.4` (EX-6.22) |

Les cadres ne cohabitent pas dans un seul environnement (`crewai` 1.15.30
exige `mcp<2` et `openai<3` ; `openai-agents` 0.24.0 exige `openai>=3` ;
`llama-index-tools-mcp` 0.6.0 exige `mcp>=2`).

```sh
paquets/sdk-python/outils/environnements.sh preparer          # tous, sous paquets/sdk-python/.environnements/ (ignoré par git)
paquets/sdk-python/outils/environnements.sh verrouiller crewai # régénère un verrou depuis verrous/crewai.in
```

Les essais pytest (`paquets/sdk-python/tests/`) s'exécutent contre le démon
réel `bin/noortrace`, lancé par le banc Node.js
`test/fixtures/enregistreur-sdk-python/banc.mjs` (point d'entrée SDK, frontal
MCP en Streamable HTTP devant le serveur d'outils de test, service
d'approbation simulé, passerelle devant le fournisseur simulé) ; un démon
simulé (`tests/demon_simule.py`) ne sert qu'au protocole côté client ;
`tests/test_vecteurs.py` rejoue les vecteurs de l'annexe B (lecture 167).
Depuis
la racine du dépôt, la suite mocha `test/enregistreur-sdk-python.test.js` les
lance tous (le SDK seul sous 3.10 et 3.13, chaque adaptateur dans son
environnement) et met en attente, avec un titre qui nomme la condition, tout
essai dont l'environnement manque ; `test/enregistreur-sdk-adaptateurs.test.js`
essaie les adaptateurs JavaScript. Directement :

```sh
cd paquets/sdk-python
NOORTRACE_ESSAI_EXIGER=1 .environnements/essais-py310/bin/python -m pytest tests/test_sdk.py
NOORTRACE_ESSAI_EXIGER=1 NOORTRACE_GO_BIN=<répertoire de go1.27.3> .environnements/crewai/bin/python -m pytest -s tests/test_adaptateur_crewai.py
```

## Lectures

Passages que le texte ne tranche pas, avec la lecture retenue, et lectures du
code publié des cadres aux versions de la table de 6.6 (numérotées à la suite
des lectures du LISEZMOI de `@noortrace/enregistreur`, qui s'arrêtent à 143).

144. **Boucle du client asynchrone** (EX-6.14 : « appartient à la boucle
     d'événements qui l'a créé » ; exemple de 6.6 :
     `ClientNoortraceAsync.depuis_environnement()` au niveau du module, hors
     de toute boucle). Lecture : créé dans une boucle, le client lui
     appartient ; créé hors de toute boucle, il appartient à la boucle de son
     premier appel ; ensuite, toute autre boucle lève `NoortraceConfiguration`.
145. **Valeur non JSON dans les paramètres** (EX-6.9 ne règle que le résultat
     de `fonction` ; 6.2 : « valeur JSON »). Lecture : un argument, un
     `request` ou une `response` que JSON ne représente pas (objet quelconque,
     nombre non fini) n'est jamais envoyé : `NoortraceEntreeInvalide`, raison
     `valeur_non_json`, avant l'écriture (aucun `id` consommé). Un `tuple`
     est sérialisé en tableau ; seul le résultat d'`appel_outil` suit la règle
     d'EX-6.9 (`tuple` → `{"noortrace_sdk_non_json": "tuple"}`).
146. **Nombre de tentatives de reprise** (EX-6.13 : « en au plus `1 +
     reprises` tentatives […], puis ouvre une nouvelle session » ; « Seuls
     l'établissement de la connexion et `ouvrir` sont retentés »). Lecture :
     une tentative est l'établissement de la connexion suivi d'`ouvrir` ; il y
     en a au plus `1 + reprises` en tout, séparées par le délai d'EX-6.13. Le
     SDK JavaScript publié imbrique deux boucles (`_ouvrirSession` retente
     `_connexionVive`, qui fait elle-même `1 + reprises` tentatives), soit
     jusqu'à `(1 + reprises)²` connexions : écart au texte, signalé au rapport
     du lot ; ce lot ne change pas l'interface ni le client JavaScript.
147. **Jeton sur TLS** (lecture 113 du démon : « avec `tls` posé, la ligne de
     jeton passe sur TLS » ; EX-6.10 ne nomme `NOORTRACE_SDK_TLS_*` que pour
     le mTLS). Lecture, comme le SDK JavaScript : le client parle TLS
     seulement en mTLS (certificat et clé exigés, autorité facultative) ; une
     prise TCP à jeton est jointe en clair. Une prise `tcp_listen` à jeton
     avec `tls` n'est pas jointe par les SDK de la version 0.
148. **Sortie du processus, client asynchrone** (EX-6.11 (4)). À la sortie,
     la boucle d'`asyncio.run` est close : aucune coroutine ne peut plus y
     s'exécuter. Lecture : le client synchrone tente `fermer` par `atexit`,
     borné à 2 s ; le client asynchrone ferme par `async with` (ou
     `fermer()`), et, à défaut, la perte de la connexion clôt la session côté
     démon (EX-6.13), comme pour le SDK JavaScript (sa lecture 5).
149. **Exception de `fonction`, puis échec de `fin_appel`** (EX-6.9 : « puis
     relance l'exception »). Lecture, comme le SDK JavaScript (sa lecture 4) :
     l'erreur du SDK est levée, l'agent devant savoir que l'événement n'est
     pas durable ; sinon l'exception de `fonction` est relancée. Seules les
     exceptions dérivées d'`Exception` sont déclarées ; une
     `BaseException` (`KeyboardInterrupt`, annulation `asyncio`) traverse
     sans `fin_appel`, et le démon scelle la reprise d'un appel d'écriture à
     la clôture de la session (EX-12.15).
150. **`sur_indisponibilite_lecture` dans les adaptateurs** (EX-6.11 (2) : un
     outil n'est jamais exécuté par un adaptateur avant `autorise` ; EX-6.15 :
     « la classe est celle que le code appelant déclare, sinon celle de la
     configuration de l'adaptateur » pour le réglage `executer`). Lecture :
     EX-6.15 est l'exception d'EX-6.11 (2) ; un adaptateur exécute sans
     événement un outil que `classes` dit `lecture` seulement si le client de
     la session porte `sur_indisponibilite_lecture="executer"` et que
     `debut_appel` a échoué autrement que par `NoortraceEntreeInvalide`.
151. **Texte d'une erreur hors des cinq classes d'EX-6.19** (EX-6.15 : « ou
     toute autre erreur » ; EX-6.19 nomme cinq textes ; EX-6.20 (v) :
     exception injectée dans le code de l'adaptateur). Lecture : un
     `NoortraceErreur` d'un autre code et toute exception levée avant
     l'exécution, y compris dans le code de l'adaptateur, rendent au modèle
     `noortrace: enregistreur injoignable` (l'appel n'a pas pu être déclaré) ;
     aucun texte nouveau n'est créé. L'outil n'est jamais exécuté.
152. **LangChain : forme de `request` d'un échange observé** (6.6 : « la
     forme de `request` est à écrire en phase 2 ») . Lecture : `{"model":
     <invocation_params.model ou model_name, à défaut kwargs du sérialisé>,
     "messages": [messages_to_dict(liste)…]}` vue par `on_chat_model_start`
     (ou `{"model", "prompts"}` par `on_llm_start`), `response` =
     `LLMResult.model_dump(mode="json")`, `provider_label` tiré de
     `invocation_params._type` au motif de `provider_label` (à défaut
     `local`), `duration_ms` entre le départ et `on_llm_end` d'un même
     `run_id`, `status` nul. La table ne dit pas comment le gestionnaire
     atteint le cadre : il est offert par `MiddlewareNoortrace.rappels`, à
     passer dans `config={"callbacks": …}`.
153. **LangChain : lignes lues** (`langchain` 1.4.7). `wrap_tool_call` et
     `awrap_tool_call` : `langchain/agents/middleware/types.py` L674-L766
     (« first defined = outermost », L683) ; `create_agent(model, tools, *,
     …, middleware=…)` : `langchain/agents/factory.py` L824-L870 (surcharges) ;
     `ToolCallRequest` (`tool_call`, `tool`, `state`, `runtime`) et appel de
     l'enveloppe : `langgraph-prebuilt` 1.1.1, `langgraph/prebuilt/tool_node.py`
     L141-L157, L1031-L1088 ; une exception de l'enveloppe est convertie par
     `handle_tool_errors` ou propagée (L1073-L1088) : l'adaptateur n'en lève
     jamais ; `ToolMessage.status` : `langchain_core/messages/tool.py` L81 ;
     métadonnées `mcp` : `langchain/mcp/tools.py` L183-L209 et L302. Un outil
     de `langchain.mcp` n'a que `coroutine` (L283, L300) : l'agent doit être
     appelé de façon asynchrone (`ainvoke`).
154. **CrewAI : chemins d'exécution des outils lus** (`crewai` 1.15.30 ;
     « Chemin d'appel « ReAct » de CrewAI : non lu »). Chemin natif (modèle à
     appels de fonctions) : `crewai/agents/agent_executor.py`
     `_execute_single_native_tool_call` L2118, crochet `before` L2218, texte
     de blocage L2237, appel `tool_func(**args_dict)` (L2243, `tool_func` =
     `BaseTool.run`, `crewai/utilities/agent_utils.py` L303),
     `Error executing tool: ` L2264, crochet `after` L2308 ; même structure
     dans `crewai/utilities/agent_utils.py` L1567, L1585, L1591, L1609, L1647
     (cité par la table). Chemin « ReAct » (modèle sans appels de fonctions) :
     `crewai/utilities/tool_utils.py` `aexecute_tool_and_check_finality` L35
     et `execute_tool_and_check_finality` L200 ; crochet `before` L123 et L286
     (blocage : crochet `after` avec le texte `Tool execution blocked by
     hook. Tool: <nom>`, L124-L142), puis `ToolUsage.ause` L145 / `use`
     L308, crochet `after`. Dans ce chemin, `ToolUsage`
     (`crewai/tools/tool_usage.py`) réexécute l'outil après une exception,
     jusqu'à `_max_parsing_attempts` fois (L110, L479, L736, L756), entre un
     seul crochet `before` et un seul crochet `after` ; il peut rendre le
     texte `task_repeated_usage` sans exécuter l'outil (L254-L262) ; son texte
     d'erreur est `I encountered an error while trying to use the tool…`
     (`crewai/translations/en.json` L53), qui ne commence pas par `Error
     executing tool: `. Dans le chemin natif, `max_usage_reached` (L2167,
     L2240) et le cache de l'équipage (L2220-L2232) empêchent l'exécution
     après un crochet `before`. Les deux chemins appellent la fonction de
     l'outil par `BaseTool.run` → `_run` / `Tool.func`
     (`crewai/tools/base_tool.py` L326-L343, L532-L566 ; `_claim_usage`
     avant) ou `CrewStructuredTool.invoke` → `func` = `BaseTool._run`
     (`crewai/tools/structured_tool.py` L424-L443 ; `base_tool.py`
     L405-L421) : c'est le seul point qui voit chaque exécution réelle, et
     seulement elle (lecture 168).
155. **CrewAI : nom déclaré et outils MCP**. Le modèle voit
     `sanitize_tool_name(outil.name)` (`crewai/utilities/string_utils.py`
     L26 ; `agent_utils.py` L290-L303) : c'est le nom déclaré (EX-6.18). Les
     outils de `mcps` apparaissent au modèle sous un nom dérivé de l'URL
     (`mcp_127_0_0_1_<port>_mcp_demo_claims_get` dans l'essai), ne passent pas
     par `envelopper`, et `envelopper_outil` rend tel quel un `MCPNativeTool`
     ou un `MCPToolWrapper` qu'on lui passerait.
156. **CrewAI : échanges observés**. `LLMCallCompletedEvent` porte
     `messages`, `response`, `model` et `call_id`
     (`crewai/events/types/llm_events.py` L90-L99, L9-L13) ; l'instant de
     départ vient de `LLMCallStartedEvent` du même `call_id`. Lecture :
     `request` = `{"model": <partie de model après le premier « / »>,
     "messages": …}`, `provider_label` = partie avant ce « / » (à défaut
     `local`), `response` = `response` de l'événement.
157. **LlamaIndex : marque MCP** (table : « aucune marque MCP lue »). Lecture
     de `llama-index-tools-mcp` 0.6.0 : `McpToolSpec._create_tool_fn`
     (`llama_index/tools/mcp/base.py` L106-L113) crée la fonction
     `async_tool_fn` du module `llama_index.tools.mcp.base`, passée à
     `FunctionTool.from_defaults(async_fn=…)` (L163-L170) ; les métadonnées
     n'ont que nom, description et schéma. `envelopper_outil` rend tel quel un
     outil dont la fonction vient de ce module, en plus des outils locaux
     énumérés par l'intégration et de `ignorer`. Limite lue : l'agent par flux
     n'injecte le contexte d'un `FunctionTool` à `requires_context` que si
     l'outil est un `FunctionTool` (`agent/workflow/base_agent.py` L366-L372 : `isinstance(tool, FunctionTool)`) :
     un tel outil, enveloppé, perd son contexte. Une entrée positionnelle de
     l'ancienne forme `__call__(input)` est déclarée sous la clé `input`.
158. **SDK Agents d'OpenAI (Python) : lignes lues** (`openai-agents`
     0.24.0). `FunctionTool.on_invoke_tool` : `agents/tool.py` L455-L482 (`on_invoke_tool`, L469) ;
     l'outil enveloppé est une copie (`copy.copy`) dont `on_invoke_tool` est
     remplacé, l'outil d'origine n'est pas modifié ; outils hébergés
     (`FileSearchTool` L815, `WebSearchTool` L853, `ComputerTool` L908,
     `HostedMCPTool` L1158, `CodeInterpreterTool` L1189,
     `ImageGenerationTool` L1254, `LocalShellTool` L1297) : ce ne sont pas des
     `FunctionTool`, ils ne sont ni enveloppés ni déclarés. La fonction
     d'origine produite par `@function_tool` convertit elle-même une
     exception de l'outil en message d'erreur (`failure_error_function`) :
     la valeur déclarée est ce message, `is_error` faux (la table : « la
     valeur rendue par la fonction d'origine »). Échanges observés :
     `GenerationSpanData` (`input`, `output`, `model`, `model_config`,
     `usage`) et `ResponseSpanData` (`response`, `input`)
     (`agents/tracing/span_data.py` L169-L195, L212-L230) ; lecture :
     format `autre`, `provider_label` `openai`, durée entre `started_at` et
     `ended_at`, `is_error` si le span porte une erreur ; un span sans entrée
     ni sortie n'est pas déclaré.
159. **LiteLLM : gestionnaires synchrones** (table : `async_log_success_event`
     et `async_log_failure_event`). Lecture du code : pour un appel
     synchrone `litellm.completion`, LiteLLM n'appelle que les gestionnaires
     synchrones (`litellm/litellm_core_utils/litellm_logging.py` L2217-L2226 :
     `sync_sdk` → `success_handler`) ; le gestionnaire définit donc aussi
     `log_success_event` et `log_failure_event`, au même effet. `request` est
     `additional_args.complete_input_dict` (le corps envoyé) s'il existe,
     sinon `{"model", "messages"}` ; un échec est déclaré
     `{"noortrace_sdk_exception": "<classe>"}`, `is_error` vrai, `status` le
     `status_code` de l'exception s'il est entier ; jamais son message.
     LiteLLM recopie `litellm.callbacks` dans ses listes internes : le
     retirer exige `litellm.logging_callback_manager`.
160. **Essais d'EX-6.20 pour LiteLLM** (EX-6.20 : « Tests obligatoires de
     chaque adaptateur » ; table : LiteLLM n'a aucun point d'interception, ses
     colonnes d'erreur et de résultat sont « — »). Lecture : les cinq essais
     sont lus pour un agent bâti sur `litellm.completion` dont les outils
     locaux passent par `appel_outil` (le SDK appelé directement, 6.1) et le
     modèle par le modèle factice de LiteLLM (`mock_response`,
     `mock_tool_calls`) ou par la passerelle ; (v) injecte l'exception dans le
     code de l'adaptateur (`GestionnaireLiteLLM`), qui n'atteint pas l'agent,
     et dans `debut_appel`, qui empêche l'exécution. L'essai (i) montre aussi
     un échange resté en tête de file pendant l'arrêt du démon puis remis
     après la reprise (EX-6.11 (3), EX-6.13).
161. **Modèle simulé des essais d'adaptateurs** (demande du lot : fournisseur
     simulé, ou modèle factice du cadre). Lecture : `GenericFakeChatModel`
     (LangChain, `bind_tools` rendu identique), `MockFunctionCallingLLM`
     (LlamaIndex), `mock_response` (LiteLLM) ; CrewAI et le SDK Agents n'en
     offrent pas d'utilisable pour des appels d'outils : un `BaseLLM` et un
     `Model` de test, d'une dizaine de lignes, rejouent le scénario ; l'agent
     réel du SDK Agents et celui de LiteLLM passent en outre par la passerelle
     devant le fournisseur simulé.

167. **Vecteurs de l'annexe B rejoués par le SDK** (EX-6.5 : « ses tests
     vérifient que le démon rend les références attendues » ;
     `tests/test_vecteurs.py`, démon réel muni de la politique des vecteurs).
     Lecture : `redaction/cas.json`, politiques `pii-v1` (59 cas) et
     `pii-pseudo-test` (6 cas), par la méthode du SDK qui écrit la pièce de
     la portée (`debut_appel` pour `arguments`, `fin_appel` pour `resultat`,
     `declarer_contexte` pour `contexte`, `echange_modele` au format
     `anthropic-messages` pour `requete`, `reponse` et `prompt_systeme`, la
     pièce « prompt système » étant citée par son `sha256` dans
     `code.prompt_version`) ; les 8 cas de `pii-regles-test` ne sont pas
     rejoués : leurs règles visent par sélecteur des noms du frontal MCP
     (`demo__payments.create`, `mail__send`, …), qu'un nom d'outil du SDK
     (`<alias>__<tool>`, EX-6.6) ne peut pas porter. `pieces-modele` : les deux
     cas `gemini-sdk-*` (pièces, `code.model`, `prompt_version`, `is_error`,
     membre retiré consigné). `pieces-mcp/appels` : les 17 cas non refusés ;
     la pièce « arguments » vient des arguments de la requête de
     `hote.jsonl` ; la pièce « résultat », pour un résultat du serveur, est
     déclarée depuis ses octets attendus (rédaction idempotente, EX-10.14) ;
     les formes `noortrace_*` que le frontal construit lui-même ne sont pas
     déclarables par un SDK et ne sont pas rejouées.

168. **CrewAI : un événement par exécution réelle — À corriger dans CT-2**
     (EX-6.17 et EX-6.18 : un appel déclaré est l'exécution de l'outil, son
     résultat la valeur rendue ; table de 6.6, ligne CrewAI : point
     d'interception par les crochets `before_tool_call`/`after_tool_call`,
     résultat déclaré `context.tool_result`, `is_error` par le préfixe
     `Error executing tool: ` ; EX-6.21). Les crochets ne bornent pas les
     exécutions (lecture 154) : (1) chemin « ReAct », un outil qui lève est
     réexécuté jusqu'à trois fois entre un seul `before` et un seul `after` ;
     (2) `task_repeated_usage`, `max_usage_count` atteint et le cache
     suivent un `before` qui a autorisé sans exécuter l'outil : un
     `debut_appel` d'écriture y écrit une intention que le démon reprend,
     faute de `fin_appel`, en événement « exécuté, résultat inconnu »
     (EX-12.15), et un `fin_appel` au crochet `after` déclarerait une
     exécution qui n'a pas eu lieu ; (3) le texte d'erreur du chemin
     « ReAct » ne porte pas le préfixe, d'où `is_error` faux. Aucune lecture
     de la ligne CrewAI de la table ne donne exactement un événement par
     exécution. Lecture retenue, pour tenir EX-6.17, EX-6.18 et EX-6.20 :
     le point d'interception de CrewAI est l'**enveloppe de l'outil local**
     (famille d'EX-6.16 « l'enveloppe d'un outil (LlamaIndex, …) »),
     `AdaptateurCrewAI.envelopper(outils)`, qui enveloppe `Tool.func` ou
     `BaseTool._run` d'une copie de l'outil : `debut_appel` juste avant chaque
     exécution réelle, `fin_appel` juste après, avec la valeur rendue par
     l'outil (et non la chaîne `context.tool_result`, que l'enveloppe ne voit
     pas) et `is_error` vrai si l'outil a levé une exception, sur les deux
     chemins ; aucun appel déclaré sans exécution ; outil non exécuté : la
     chaîne d'EX-6.19 est rendue à CrewAI comme résultat de l'outil (le modèle
     la reçoit comme observation), et non par `HookAborted`. Les crochets
     globaux ne sont plus employés ; `Crew(cache=False)` n'est plus requis
     (un résultat servi par le cache ne produit aucun événement). Les arguments
     déclarés sont ceux que CrewAI passe à la fonction : après sa validation
     et après toute modification en place par un crochet `before` (essai
     `test_ordre_des_crochets_et_entree_modifiee`). Essais :
     `test_react_reexecutions_un_evenement_par_execution_et_is_error` (trois
     exécutions, trois événements, `is_error` vrai, vrai, faux),
     `test_natif_exception_is_error`,
     `test_react_appel_repete_sans_execution_sans_evenement`,
     `test_natif_max_usage_et_cache_sans_execution_sans_evenement`,
     `test_react_demon_arrete_et_approbation`. À corriger dans CT-2 : la ligne
     CrewAI de la table de 6.6 et EX-6.21 (point d'interception, résultat
     déclaré, règle d'`is_error`, appariement par pile, `Crew(cache=False)`)
     devraient désigner l'enveloppe de l'outil.
169. **LiteLLM en mandataire, essai de la disposition (a)** (EX-6.22).
     `tests/test_mandataire_litellm.py`, dans l'environnement
     `litellm-mandataire` (`litellm[proxy]==1.106.4`) : le banc lance le
     mandataire (`litellm --config`, clé maîtresse de test, modèle
     `openai/modele-chat` d'`api_base` le fournisseur simulé) et donne à la
     route `/v1/chat/completions` de la passerelle l'URL du mandataire pour
     amont, son secret étant la clé maîtresse. Constat : un échange, requête
     de l'agent sous la délégation de l'agent (`launched_by` de sa connexion
     d'hôte, `run_id` de `X-Noortrace-Run-Id`), réponse rendue par LiteLLM ;
     le fournisseur reçoit la requête émise par LiteLLM. La disposition (b)
     n'est pas essayée.

## Dépendances

Aucune dépendance d'exécution. Essais : `pytest==9.1.1` et les cadres aux
versions de la table, épinglés avec leurs empreintes dans `verrous/`.
