# noortrace-sdk — SDK TypeScript/JavaScript de NOORTRACE

**Le SDK n'est un chemin de capture acceptable qu'avec un pare-feu de sortie
qui interdit au processus de l'agent de joindre les serveurs d'outils et les
fournisseurs de modèle autrement que par l'enregistreur (CT-2 EX-6.2).** Un
agent qui peut atteindre ses cibles directement peut n'appeler le SDK que pour
ce qu'il veut montrer : ce qu'il déclare est une déclaration (CT-2 6.3, 6.7),
de rang plus faible que ce que voient le frontal MCP et la passerelle.

Paquet npm `noortrace-sdk` (module ECMAScript, types inclus, Node.js 22 ou
plus, CT-2 EX-6.5, EX-6.9), sans dépendance d'exécution. Il enveloppe les six
méthodes `noortrace/sdk/*` du démon `noortrace` (CT-2 6.2) sans en ajouter, sans
ajouter de paramètre et sans changer ni les résultats ni leur sémantique
(6.5). Il ne capture rien et ne calcule rien : ni hachage, ni signature, ni
écriture de journal (EX-6.1) ; le démon fait tout le reste.

## Employer le SDK

```js
import { ClientNoortrace, AppelNonAutorise } from "noortrace-sdk";

const client = ClientNoortrace.depuisEnvironnement();      // NOORTRACE_SDK_SOCKET, …
const session = await client.ouvrir({ runId: "run-2026-11-10-0007", onBehalfOf: null });
try {
  const ref = await session.declarerContexte({ kind: "document", octets: "…", mediaType: "text/plain" });
  const resultat = await session.appelOutil(
    { tool: "preparer_paiement", arguments: { sinistre: "2026-77812", montant: "7400.00" }, classe: "ecriture", contexte: [ref.sha256] },
    async (args) => preparerPaiement(args),               // exécutée seulement après « autorise » et l'intention durable
  );
  await session.echangeModele({ format: "autre", providerLabel: "local", request, response, status: 200, durationMs: 812, isError: false });
} catch (e) {
  if (e instanceof AppelNonAutorise) console.log(e.texte);  // « noortrace: appel soumis a approbation ; ticket=… ; state=… »
  else throw e;
} finally {
  await session.fermer();
}
```

| Méthode | Méthode de 6.2 | L'appelant attend |
|---|---|---|
| `new ClientNoortrace({ socket, tcp, jeton, delaiMs = 30000, reprises = 2, surIndisponibiliteLecture = "bloquer" })`, `ClientNoortrace.depuisEnvironnement()` | aucune (connexion au premier appel) | rien |
| `client.ouvrir({ runId, onBehalfOf })` | `ouvrir` | la session |
| `session.declarerContexte({ kind, octets, mediaType })` | `declarerContexte` | `{ sha256, length, redacted }` |
| `session.debutAppel({ tool, arguments, classe, contexte, intent, effects })` | `debutAppel` | `{ call, decision, ticket, ticket_state }` et, pour `ecriture`, l'intention durable |
| `session.finAppel(debut, { resultat, isError, durationMs })` | `finAppel` | `{ seq, hash }`, l'événement durable |
| `session.appelOutil({ … }, fonction)` | `debutAppel`, `fonction(arguments)`, `finAppel` | le résultat de `fonction`, après l'événement durable |
| `session.echangeModele({ format, providerLabel, request, response, status, durationMs, isError })` | `echangeModele` | `{ seq, hash }` |
| `session.fermer()` (dans un `finally`) | `fermer` | `{}` |

## Connexion (EX-6.10)

Adresse, dans cet ordre : paramètres du constructeur ; variables
`NOORTRACE_SDK_SOCKET` (prise Unix), `NOORTRACE_SDK_TCP` (`hôte:port`),
`NOORTRACE_SDK_TOKEN` (jeton de la prise TCP), `NOORTRACE_SDK_TLS_CA`,
`NOORTRACE_SDK_TLS_CERT`, `NOORTRACE_SDK_TLS_KEY` (mTLS) ; à défaut
`/run/noortrace/sdk.sock`. Un chemin de prise de plus de 103 octets est refusé
à la construction (`ErreurNoortraceConfiguration`). Sur une prise Unix, le
démon lit l'utilisateur du processus par une preuve de propriété de fichier
(le SDK crée en exclusion `<répertoire de la prise>/.noortrace-defi-<défi>`) ;
sur une prise TCP, la première ligne est `{"noortrace_token": "<jeton>"}`,
sauf en mTLS. Une ligne JSON-RPC 2.0 par message ; `id` entiers croissants à
partir de 1 sur chaque connexion.

## Erreurs (EX-6.12)

Toutes dérivent de `ErreurNoortrace` : `ErreurNoortraceIndisponible`
(`envoyee`), `ErreurNoortraceDegrade` (`raison`), `ErreurNoortraceLimite`
(`direction`, `limite`), `ErreurNoortraceNonDurable` (`intent_id`),
`ErreurNoortraceEntreeInvalide` (`raison`), `ErreurNoortraceConfiguration`,
`AppelNonAutorise` (`decision`, `ticket`, `ticket_state`, `texte`) ; tout autre
code : `ErreurNoortrace` (`code`, `message`, `data`).

## Ce qui bloque l'agent et ce qui ne le bloque jamais (EX-6.11, EX-6.15)

Chaque méthode attend la réponse du démon, au plus `delaiMs` ; aucune n'est
mise en file. `appelOutil` n'exécute jamais `fonction` avant `autorise` ; si
`debutAppel` échoue, un outil `ecriture` (la classe par défaut) n'est jamais
exécuté, et un outil `lecture` ne l'est qu'avec `surIndisponibiliteLecture:
"executer"`, sans aucun événement (noté sur la sortie d'erreur). À la sortie du
processus, `fermer` est tenté, borné à 2 s.

`noortrace-sdk/adaptateurs` offre `FileEchanges`, la file bornée des échanges
de modèle observés par un adaptateur de cadre (EX-6.11 (3)) : file pleine,
l'échange le plus récent est abandonné et compté (`echangesPerdus`) ; une
erreur de la file n'atteint jamais l'agent. Il offre aussi le point
d'interception commun (`intercepter`) et les textes d'EX-6.19.

## Adaptateurs de cadres (6.6)

| Cadre (version essayée) | Module | Accroche | Point d'interception | Outil MCP | Échanges (`modele: "declarer"`) |
|---|---|---|---|---|---|
| LangChain 1.5.19 (`@langchain/core` 1.3.0, `@langchain/mcp-adapters` 2.0.1) | `noortrace-sdk/adaptateurs/langchain` | `middlewareNoortrace(session, { classes, modele, ignorer })`, **dernier** de `createAgent({ middleware: [...] })` | `wrapToolCall` ; outil non exécuté : `ToolMessage({ content: <texte>, tool_call_id, status: "error" })` sans appeler `handler` ; déclaré : `content` du `ToolMessage` rendu, `isError` = `status === "error"` | liste `ignorer` (aucune marque d'origine MCP, lecture 163) | `{ callbacks: middleware.rappels }` : `handleChatModelStart` / `handleLLMStart`, `handleLLMEnd`, format `autre` |
| SDK Agents d'OpenAI 0.21.0 (TypeScript) | `noortrace-sdk/adaptateurs/openai-agents` | `const a = adaptateurAgentsOpenAI(session, { classes, modele, ignorer })` ; `tool({ name, …, execute: a.envelopperExecution(name, execute) })` | `envelopperExecution` ; outil non exécuté : la chaîne du texte ; déclaré : les arguments, la valeur rendue par `execute` | outils de `mcpServers` non enveloppés | `addTraceProcessor(a.processeur)` : `onSpanEnd` des spans `generation` et `response`, format `autre` |

Un adaptateur n'appelle `debutAppel` et `finAppel` que depuis son point
d'interception ; toute exception levée avant l'exécution, du SDK ou de son
propre code, laisse l'outil non exécuté et rend au modèle un résultat d'erreur
d'outil (EX-6.16, EX-6.19, EX-6.20 (v)). Les essais :
`test/enregistreur-sdk-adaptateurs.test.js` (cinq essais d'EX-6.20 par
adaptateur, agent réel avec un outil local et un outil MCP par le frontal,
journal et dossier vérifiés, contre le démon réel `bin/noortrace`).

## Reprise (EX-6.13)

Une connexion perdue clôt la session côté démon (qui scelle les événements de
reprise des appels d'écriture ou approuvés restés ouverts). Au premier appel
qui suit, le SDK rouvre la connexion (au plus `1 + reprises` tentatives,
séparées de `min(0,5 × 2^n, 8) × (1 − 0,25 × u)` s) et une nouvelle session de
mêmes `runId` et `onBehalfOf`, que l'objet `Session` désigne désormais. Une
requête déjà écrite n'est jamais renvoyée ; un `finAppel` dont la session a
été perdue avant son envoi n'est pas envoyé ; une référence de contexte de la
session perdue lève `ErreurNoortraceEntreeInvalide` sans rien envoyer.

## Lectures

Passages que le texte ne tranche pas, avec la lecture retenue (les lectures
côté démon sont au LISEZMOI de `@noortrace/enregistreur`).

1. **Nom du paquet.** CT-2 EX-6.9 nomme le paquet npm `noortrace-sdk` ; le
   paquet porte ce nom (et non un nom à portée), dans le répertoire
   `paquets/sdk-js/` de l'espace de travail.
2. **Noms des membres rendus.** EX-6.9 met en camelCase les *paramètres* en
   TypeScript ; `Debut` « porte exactement les quatre membres du résultat de
   `debutAppel` » : les objets rendus (`Debut`, `Scelle`, `Reference`) et les
   attributs des erreurs gardent les noms de 6.2 et d'EX-6.12 (`ticket_state`,
   `intent_id`).
3. **mTLS.** Le constructeur n'a pas de paramètre de certificat (table
   d'EX-6.9) : le mTLS ne vient que de l'environnement (EX-6.10) ; il exige le
   certificat et la clé, l'autorité étant facultative.
4. **Exception de `fonction` puis échec de `finAppel`.** EX-6.9 : `finAppel`
   avec la forme `noortrace_sdk_exception`, « puis relance l'exception ».
   Lecture : si `finAppel` échoue aussi, l'erreur du SDK est levée (l'agent
   doit savoir que l'événement n'est pas durable) ; sinon l'exception de
   `fonction` est relancée.
5. **Sortie du processus** (EX-6.11 (4)). Node.js n'exécute pas de code
   asynchrone dans `exit` : `fermer` est tenté sur `beforeExit` (quand la
   boucle d'événements se vide), borné à 2 s ; la prise ne retient pas le
   processus quand aucune requête n'est en cours. Une sortie par
   `process.exit()` ou un signal ne laisse pas cette chance : le démon clôt la
   session à la perte de la connexion (EX-6.13).
6. **`fork`** (EX-6.14) concerne le client Python : un processus Node.js ne
   duplique pas ses prises ; chaque `Worker` crée son propre client.
7. **File des échanges** (EX-6.11 (3)) : elle n'est pas dans l'interface
   publique d'EX-6.9 (aucune méthode ajoutée à la session) ; elle est offerte
   aux adaptateurs de cadres (6.6, lot suivant) par `noortrace-sdk/adaptateurs`.

### Lectures du lot des adaptateurs

Numérotées à la suite des lectures du LISEZMOI de `@noortrace/enregistreur`
(jusqu'à 143) et du SDK Python (`paquets/sdk-python/LISEZMOI.md`, 144 à 161 et 167 à 169) ;
les lectures 151 (texte d'une erreur hors des cinq classes d'EX-6.19 :
`noortrace: enregistreur injoignable`) et 150 (`surIndisponibiliteLecture`
dans un adaptateur) valent aussi pour les adaptateurs JavaScript.

162. **Modules des adaptateurs JavaScript** (EX-6.9 ne nomme que le paquet
     `noortrace-sdk` ; 6.6 nomme le module Python
     `noortrace_sdk.adaptateurs.langchain`). Lecture : un sous-chemin par
     cadre, `noortrace-sdk/adaptateurs/langchain` et
     `noortrace-sdk/adaptateurs/openai-agents`, chargés seulement par
     l'intégration qui les importe ; l'interface publique d'EX-6.9 ne change
     pas. L'adaptateur LangChain importe `langchain` (`createMiddleware`,
     `ToolMessage`) et `@langchain/core` (`BaseCallbackHandler`) : ce sont des
     dépendances pairs **facultatives** du paquet, aux versions essayées
     (1.5.19 et 1.3.0) ; l'adaptateur du SDK Agents n'importe rien du cadre.
163. **LangChain JavaScript : interface lue** (table : « le reste de
     l'interface n'est pas lu », « Résultat d'outil d'erreur du cadre (non
     lu) », « non lu (`@langchain/mcp-adapters` 2.0.1) »). `langchain`
     1.5.19 : `wrapToolCall` (`dist/agents/middleware/types.d.ts` L352),
     `ToolCallRequest` (`toolCall`, `tool`, `state`, `runtime`, L75-L113),
     `ToolCallHandler` rendant `ToolMessage | Command` (L114, L119) ;
     `createMiddleware` (`dist/agents/middleware.js` L57-L73) ; composition,
     le premier de la liste étant la couche la plus externe
     (`dist/agents/utils.js` L304-L317) ; le `ToolNode` du cadre convertit une
     erreur d'outil en `new ToolMessage({ …, status: "error" })`
     (`dist/agents/nodes/ToolNode.js` L32-L45) : c'est la forme rendue par
     l'adaptateur. `@langchain/mcp-adapters` 2.0.1 : un outil MCP est un
     `DynamicStructuredTool` dont les métadonnées ne portent que
     `{ annotations }` (`dist/tools.js` L207-L212), aucune marque d'origine :
     seule la liste `ignorer` évite la double capture (EX-6.17 (b)). Constat
     de l'essai : en mode « auto », `MCPAdapter` ouvre l'ère 2026-07-28 et
     attend l'accusé de `subscriptions/listen`, que le frontal MCP du démon
     ne rend pas (`SdkError: subscriptions/listen ack timed out`,
     `@modelcontextprotocol/client`) ; l'essai emploie `mode: "legacy"`.
     Signalé au rapport du lot (frontal MCP, hors de ce lot).
164. **LangChain JavaScript : échanges observés**. Comme la lecture 152 du
     SDK Python : `request` = `{ model, messages }` vu par
     `handleChatModelStart` (ou `{ model, prompts }` par `handleLLMStart`),
     `response` = le `LLMResult` sérialisé, `providerLabel` tiré de
     `invocation_params._type`, durée entre le départ et `handleLLMEnd` du
     même `runId` ; le gestionnaire ne pose pas `awaitHandlers` : il
     s'exécute en tâche de fond (R12-F14), point d'observation.
165. **SDK Agents d'OpenAI TypeScript : nom déclaré** (EX-6.18 : « le nom
     que le cadre donne à l'outil et que le modèle voit »). `tool({ name })`
     normalise le nom par `toFunctionToolName` (`@openai/agents-core`
     0.21.0, `dist/tool.mjs` L689-L690, `dist/utils/tools.mjs` L23-L33 :
     tout caractère hors `[a-zA-Z0-9]` devient `_`), et le nom d'un outil MCP
     vu par le modèle est normalisé de même (essai : `demo__claims.get`
     devient `demo__claims_get`, le frontal journalisant le nom annoncé).
     Lecture : l'adaptateur déclare le nom de l'appel
     (`details.toolCall.name`, `ToolCallDetails`, `dist/tool.d.ts` L62-L72),
     à défaut le nom passé à `envelopperExecution`. `execute` reçoit les
     arguments déjà analysés par le cadre (`dist/tool.d.ts` L649, L656) ; une
     chaîne (outil sans schéma) est analysée en JSON strict, sinon déclarée
     telle quelle, comme en Python.
166. **SDK Agents d'OpenAI TypeScript : échanges observés**. Spans
     `generation` (`input`, `output`, `model`, `model_config`, `usage`) et
     `response` (`_input`, `_response`) (`dist/tracing/spans.d.ts` L46-L72).
     Lecture : format `autre`, `providerLabel` `openai`, durée entre
     `startedAt` et `endedAt`, `isError` si le span porte une erreur ; un span
     sans entrée ni sortie n'est pas déclaré.

## Tests

Depuis la racine du dépôt : `test/enregistreur-sdk-client.test.js` (EX-6.9 à
EX-6.15 contre un démon en processus et des démons simulés),
`test/enregistreur-sdk-exigences.test.js`,
`test/enregistreur-sdk-vecteurs.test.js` et
`test/enregistreur-sdk-parcours.test.js` (agent Node.js réel contre le démon
réel `bin/noortrace`) ; `test/enregistreur-sdk-adaptateurs.test.js`
(adaptateurs de cadres).
