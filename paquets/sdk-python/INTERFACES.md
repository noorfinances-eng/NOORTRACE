# Interfaces de noortrace-sdk (Python)

Ce document s'adresse à qui raccorde un agent Python et aux auteurs
d'adaptateurs de cadres (CT-2 6.6). Avec CT-2 6.2 et 6.5, il suffit.

## Interface publique (EX-6.9), et seulement elle

```python
from noortrace_sdk import (ClientNoortrace, ClientNoortraceAsync, Session, SessionAsync, Debut, Scelle, Reference,
    NoortraceErreur, NoortraceIndisponible, NoortraceDegrade, NoortraceLimite, NoortraceNonDurable,
    NoortraceEntreeInvalide, NoortraceConfiguration, AppelNonAutorise)

ClientNoortrace(socket=None, tcp=None, jeton=None, delai_s=30.0, reprises=2, sur_indisponibilite_lecture="bloquer")
ClientNoortrace.depuis_environnement()
client.ouvrir(run_id=None, on_behalf_of=None) -> Session                      # aussi : with client.ouvrir(…) as session
session.declarer_contexte(kind, octets, media_type=None) -> Reference          # octets : bytes ou str (UTF-8)
session.debut_appel(tool, arguments, classe=None, contexte=(), intent=None, effects=None) -> Debut
session.fin_appel(debut, resultat, is_error, duration_ms) -> Scelle
session.appel_outil(tool, arguments, fonction, classe=None, contexte=(), intent=None, effects=None)
session.echange_modele(format, provider_label, request, response, status, duration_ms, is_error) -> Scelle
session.fermer() -> dict

ClientNoortraceAsync(…mêmes paramètres…) ; ClientNoortraceAsync.depuis_environnement()
await client.ouvrir(…) -> SessionAsync ; async with client.ouvrir(…) as session: …
await session.declarer_contexte(…) ; await session.debut_appel(…) ; await session.fin_appel(…)
await session.appel_outil(…, fonction)        # fonction synchrone, ou rendant un objet attendable
await session.echange_modele(…) ; await session.fermer()
```

- Paramètres : noms et valeurs de 6.2, sauf `classe`, `contexte`, `resultat`
  (`class`, `context`, `result`) ; aucun paramètre ni méthode ajouté au
  protocole.
- `Debut(call, decision, ticket, ticket_state)`, `Scelle(seq, hash)`,
  `Reference(sha256, length, redacted)` : classes de données figées.
  `Scelle(None, None)` : événement en attente du mode dégradé (14.5).
- `appel_outil` : `AppelNonAutorise` sans exécuter `fonction` pour toute
  décision autre que `autorise` ; durée sur l'horloge monotone autour de
  `fonction(**arguments)` ; résultat non JSON déclaré
  `{"noortrace_sdk_non_json": "<type>"}` ; exception de `fonction` déclarée
  `{"noortrace_sdk_exception": "<classe>"}`, `is_error` vrai, puis relancée ;
  son message n'est jamais transmis.
- Journaliseur : `noortrace_sdk` (lecture sans événement d'EX-6.15, file des
  échanges d'EX-6.11 (3)).

## Pour les adaptateurs (6.6) : `noortrace_sdk.adaptateurs`

```python
from noortrace_sdk.adaptateurs import (FileEchanges, FileEchangesAsync, intercepter, intercepter_async, Issue,
    texte_avant_execution, nom_declarable, valeur_declaree, etiquette, file_pour,
    TEXTE_DEGRADE, TEXTE_INJOIGNABLE, TEXTE_LIMITE, TEXTE_ENTREE_INVALIDE, TEXTE_NON_DURABLE)

file = FileEchanges(session, file_max=1000)        # client synchrone : un fil de fond
file = FileEchangesAsync(session, file_max=1000)   # client asynchrone : une tâche de la boucle de la session ; ajouter() depuis tout fil
file.ajouter(format, provider_label, request, response, status, duration_ms, is_error) -> bool   # ne bloque ni ne lève
file.echanges_perdus ; file.vide(delai_s=None) (FileEchanges) ; await file.vide() (FileEchangesAsync)

issue = intercepter(session, preparer, executer, declarer)              # point d'interception synchrone
issue = await intercepter_async(session, preparer, executer, declarer)  # asynchrone
# preparer() -> (nom, arguments, classe) ; executer() -> valeur ; declarer(valeur) -> (resultat, is_error)
# issue.executee, issue.texte (texte d'EX-6.19 à rendre au modèle, ou None), issue.valeur
```

Un adaptateur n'appelle `debut_appel` et `fin_appel` que depuis un point
d'interception (EX-6.16) ; la file ne sert qu'aux échanges de modèle observés,
jamais à un appel d'outil (EX-6.11).

## Adaptateurs livrés

```python
from noortrace_sdk.adaptateurs.langchain import MiddlewareNoortrace, GestionnaireEchangesNoortrace
m = MiddlewareNoortrace(session, classes={"preparer_paiement": "ecriture"}, modele="passerelle", ignorer=[])
create_agent(model, tools, middleware=[…, m])                 # en dernier ; m.rappels avec modele="declarer"

from noortrace_sdk.adaptateurs.crewai import AdaptateurCrewAI, EcouteurEchangesNoortrace
a = AdaptateurCrewAI(session, classes=…, modele=…, ignorer=…)
Agent(…, tools=a.envelopper(outils_locaux), mcps=[…])                       # a.envelopper_outil(outil) ; a.installer() (modele="declarer")

from noortrace_sdk.adaptateurs.llamaindex import AdaptateurLlamaIndex, OutilNoortrace, est_outil_mcp
a = AdaptateurLlamaIndex(session, classes=…, modele=…, ignorer=…)
FunctionAgent(tools=a.envelopper(outils_locaux) + outils_mcp, llm=…)        # a.envelopper_outil(outil) ; a.retirer()

from noortrace_sdk.adaptateurs.openai_agents import AdaptateurAgentsOpenAI, ProcesseurEchangesNoortrace, analyser_arguments
a = AdaptateurAgentsOpenAI(session, classes=…, modele=…, ignorer=…)
agent = a.envelopper_agent(Agent(…, tools=[…], mcp_servers=[…]))           # a.envelopper(outils) ; add_trace_processor(a.processeur)

from noortrace_sdk.adaptateurs.litellm import GestionnaireLiteLLM
litellm.callbacks = [GestionnaireLiteLLM(session)]                          # échanges hors passerelle seulement
```

Chaque adaptateur prend une session du client synchrone ou asynchrone ; sur
un chemin asynchrone, une session synchrone est appelée par
`asyncio.to_thread` (EX-6.14) ; une session asynchrone sur un chemin
synchrone lève `NoortraceConfiguration`. CrewAI (outils appelés depuis des
fils) exige une session du client synchrone (`NoortraceConfiguration` à la
construction) ;
LiteLLM accepte l'une ou l'autre pour sa file.
