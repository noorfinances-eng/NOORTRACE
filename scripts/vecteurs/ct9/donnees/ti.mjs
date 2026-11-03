// Source de données du catalogue CT-9 : entrées TI- (section 8), telles
// qu'elles sont imprimées dans spec/vecteurs/ct-9/catalogue.json.

export const TI = [
  {
    "id": "TI-1",
    "level": "TI",
    "title": "Export OpenTelemetry GenAI d'un événement (CT-1 §12.1) validé par le registre des conventions",
    "specs": [
      "CT-1",
      "CT-2"
    ],
    "covers": [
      "CT-1 §12.1",
      "CT-2 EX-6.25"
    ],
    "preconditions": [
      "Exportateur de la phase 2 (CT-1 §12 : « aucune des trois correspondances n'est implémentée en v0 ») ; version du registre `gen_ai` épinglée (CT-2 EX-6.25 : `semantic-conventions` v1.41.1 ; registre courant sans version, R11-F40) ; outil `weaver registry live-check` à version épinglée (R11-F42 : v0.28.0)."
    ],
    "steps": [
      "Exporter les événements de `ct-2/evenements/journal-demo/` en spans OTLP ; les soumettre à `weaver registry live-check` contre le registre épinglé.",
      "Vérifier la table de CT-1 §12.1 attribut par attribut : `gen_ai.operation.name`, `gen_ai.tool.name`, `gen_ai.request.model`, `gen_ai.provider.name`, `gen_ai.conversation.id`, `enduser.id`, `error.type`, préfixe `noortrace.*`.",
      "Vérifier qu'aucun span ne porte `gen_ai.tool.call.arguments` ni `gen_ai.tool.call.result` (contenus non exportés) et que `start`, `end` suivent `ts` et `duration_ms`."
    ],
    "oracle": "Rapport `live-check` sans ligne `violation` (code 0) ; chaque attribut de la table présent avec la valeur dérivée de l'événement ; contenus absents ; `gen_ai.system`, retiré du registre courant (R11-F41), n'est émis que si la version épinglée le définit.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Aucun exportateur n'existe ; le registre GenAI courant n'a aucune version publiée (R11-F40) : la version à épingler est fixée par la révision de CT-2 EX-6.25 (proposition PD- de CT-9)."
    },
    "threats": []
  },
  {
    "id": "TI-2",
    "level": "TI",
    "title": "Export au format du projet IETF « agent audit trail » (CT-1 §12.2) relu par un vérificateur du projet",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 §12.2"
    ],
    "preconditions": [
      "Exportateur de la phase 2 ; version du projet fixée (draft-sharif-agent-audit-trail-09 au 2026-11-01, R11-F46) ; le préfixe de domaine du hachage exposé comme paramètre de profil (CT-1 §12.2, « à négocier »)."
    ],
    "steps": [
      "Exporter le journal des vecteurs de CT-1 en enregistrements du projet ; recalculer `prev_hash = hex(SHA-256(JCS(record)))` avec et sans le préfixe de domaine ; vérifier la signature selon `sig_alg`."
    ],
    "oracle": "Avec le paramètre de profil, la chaîne est acceptée par un vérificateur du projet ; sans lui, elle est refusée, ce qui est consigné comme écart connu (premier `prev_hash` nul dans le projet, zéro dans CT-1 ; Ed25519 optionnel, ES256 par défaut ; R11-F47).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Aucun exportateur ; projet individuel non adopté par l'IETF (R11-F46)."
    },
    "threats": []
  },
  {
    "id": "TI-3",
    "level": "TI",
    "title": "Protocole MCP réel : client de référence (stdio et Streamable HTTP, ère moderne) à travers le frontal",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-3.1",
      "CT-2 EX-3.2",
      "CT-2 EX-3.3",
      "CT-2 EX-3.4",
      "CT-2 EX-3.5",
      "CT-2 EX-3.6",
      "CT-2 EX-4.1",
      "CT-2 EX-4.2",
      "CT-2 EX-4.3",
      "CT-2 EX-4.4",
      "CT-2 EX-4.5",
      "CT-2 EX-4.6",
      "CT-2 EX-4.7",
      "CT-2 EX-4.8",
      "CT-2 EX-4.9",
      "CT-2 EX-4.10",
      "CT-2 EX-4.25",
      "CT-2 EX-4.26",
      "CT-2 EX-4.27",
      "CT-2 EX-4.28",
      "CT-2 EX-4.29",
      "CT-2 EX-4.30",
      "CT-2 EX-4.31",
      "CT-2 EX-4.32",
      "CT-2 EX-4.33",
      "CT-2 EX-4.34",
      "CT-2 EX-4.35",
      "CT-2 EX-4.36",
      "CT-2 EX-4.37",
      "CT-2 EX-4.38",
      "CT-2 EX-4.39",
      "CT-2 EX-4.40",
      "CT-2 EX-4.41",
      "CT-2 EX-4.42",
      "CT-2 §4.2",
      "CT-2 §4.7",
      "CT-2 §4.8"
    ],
    "preconditions": [
      "Enregistreur de l'étape 4 : démon réel `bin/noortrace --config`, connecteur `noortrace-connecteur` ; politique de rédaction `pii-v1` de l'exemple de CT-2 §15.3.",
      "Client MCP de référence de l'ère de CT-2 §0.3 : `@modelcontextprotocol/client` 2.4.0 (SDK TypeScript v2 de la révision 2026-07-28, dépendance de `@langchain/mcp-adapters` 2.0.1 fixée par `package-lock.json`), ère moderne épinglée (`versionNegotiation: { mode: { pin: \"2026-07-28\" } }`).",
      "Serveur d'outils de test au contrat d'`outils-demo` (CT-2 §19.1 : `claims.get`, `claims.search`, `payments.create`, données fictives), qui rejoue les octets des vecteurs `pieces-mcp/appels` (`test/fixtures/enregistreur-mcp-reference/outils-demo.mjs`, transport stdio comme les serveurs des vecteurs ; l'image `outils-demo` en Streamable HTTP est un livrable de la démonstration, étape 8), et le serveur hérité `archives` des mêmes vecteurs ; service d'approbation simulé qui autorise."
    ],
    "steps": [
      "Négocier la version, lister, appeler `claims.get`, `claims.search`, `payments.create` par stdio (connecteur) puis par Streamable HTTP (jeton statique) ; authentifier une connexion d'hôte (sans jeton, jeton faux) ; couper le serveur en cours d'appel (`payments.create` du vecteur `injoignable`)."
    ],
    "oracle": "Version négociée 2026-07-28 ; chaque appel produit l'événement attendu : pièces arguments, résultat, définition servie et liste annoncée égales, octet pour octet, à celles d'`attendu.json` du vecteur `pieces-mcp/appels` qui joue le même appel (`blancs-non-significatifs`, `arguments-non-entiers`, `execute-ecriture` sauf sa liste annoncée, servie sans le serveur `archives`, `injoignable`) ; événements attribués à la connexion d'hôte de chaque transport ; requête non authentifiée refusée (401, auth_failed, aucun événement) ; serveur coupé : erreur -31014 rendue à l'hôte et consignée (upstream_unreachable, raison perte), l'événement est celui du vecteur `injoignable` (résultat d'erreur), aucun événement forgé.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur-mcp-client-reference.test.js",
          "describe": "TI-3 — protocole MCP réel : client de référence @modelcontextprotocol/client (stdio et Streamable HTTP, ère moderne) à travers le frontal du démon",
          "it": "client de référence (@modelcontextprotocol/client 2.4.0) en stdio par le connecteur, ère 2026-07-28 : tools/list, puis claims.get, claims.search et payments.create ; chaque appel rendu à l'hôte et scellé avec les pièces du vecteur pieces-mcp qui joue le même appel"
        },
        {
          "file": "test/enregistreur-mcp-client-reference.test.js",
          "describe": "TI-3 — protocole MCP réel : client de référence @modelcontextprotocol/client (stdio et Streamable HTTP, ère moderne) à travers le frontal du démon",
          "it": "client de référence en Streamable HTTP, jeton statique, ère 2026-07-28 : mêmes appels, mêmes pièces ; événements attribués à la connexion d'hôte HTTP"
        },
        {
          "file": "test/enregistreur-mcp-client-reference.test.js",
          "describe": "TI-3 — protocole MCP réel : client de référence @modelcontextprotocol/client (stdio et Streamable HTTP, ère moderne) à travers le frontal du démon",
          "it": "requête non authentifiée (sans jeton, puis jeton faux) : refusée par 401, une ligne auth_failed chacune, aucun événement"
        },
        {
          "file": "test/enregistreur-mcp-client-reference.test.js",
          "describe": "TI-3 — protocole MCP réel : client de référence @modelcontextprotocol/client (stdio et Streamable HTTP, ère moderne) à travers le frontal du démon",
          "it": "serveur d'outils coupé en cours d'appel (payments.create du vecteur injoignable) : -31014 rendu à l'hôte et consigné ; l'événement est celui du vecteur (résultat d'erreur), aucun succès forgé"
        }
      ]
    },
    "threats": [
      "MN-1",
      "MN-8",
      "MN-9"
    ]
  },
  {
    "id": "TI-4",
    "level": "TI",
    "title": "Intégration Anthropic : SDK officiel avec `ANTHROPIC_BASE_URL` vers la passerelle (hors flux et flux)",
    "specs": [
      "CT-2",
      "CT-1"
    ],
    "covers": [
      "CT-2 §5.4.2",
      "CT-2 §19.5",
      "CT-2 EX-5.1",
      "CT-2 EX-5.2",
      "CT-2 EX-5.4",
      "CT-2 EX-5.5",
      "CT-2 EX-5.6",
      "CT-2 EX-5.7",
      "CT-2 EX-5.9",
      "CT-2 EX-5.10"
    ],
    "preconditions": [
      "Enregistreur de la phase 2 (étape 4) lancé avec la configuration de démonstration (CT-2 §19.1) ; fournisseur de modèle simulé (CT-2 §19.3) ; réseau de l'hôte isolé : seul l'enregistreur est joignable.",
      "Fichier d'intégration de CT-2 §19.5 pour cet hôte, à la version épinglée par CT-2 §6.4."
    ],
    "steps": [
      "Lancer le SDK Anthropic (CT-2 §19.5) avec le fichier d'intégration ; jouer le scénario de CT-2 §19.2 (lecture, écriture approuvée, échange de modèle).",
      "Clore la période (commande d'exploitation) ; exporter le dossier de chaque appel ; vérifier par le vérificateur de CT-6 (JavaScript et Go) sans réseau.",
      "Relever les connexions sortantes de l'hôte pendant le scénario."
    ],
    "oracle": "Un événement par appel et par échange, accepté par le vérificateur (code 0) ; pièces égales aux octets vus par l'hôte ; aucune connexion de l'hôte vers le serveur d'outils ni vers le fournisseur hors de l'enregistreur ; aucune clé réelle.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Passerelle non construite (étape 4) ; fichiers d'intégration marqués « à tester en phase 2 » (CT-2 §19)."
    },
    "threats": []
  },
  {
    "id": "TI-5",
    "level": "TI",
    "title": "Intégration OpenAI : Chat Completions et Responses par le SDK officiel vers la passerelle",
    "specs": [
      "CT-2",
      "CT-1"
    ],
    "covers": [
      "CT-2 §5.4.3",
      "CT-2 §5.4.4",
      "CT-2 EX-5.12",
      "CT-2 EX-5.13",
      "CT-2 EX-5.14",
      "CT-2 EX-5.15"
    ],
    "preconditions": [
      "Enregistreur de la phase 2 (étape 4) lancé avec la configuration de démonstration (CT-2 §19.1) ; fournisseur de modèle simulé (CT-2 §19.3) ; réseau de l'hôte isolé : seul l'enregistreur est joignable.",
      "Fichier d'intégration de CT-2 §19.5 pour cet hôte, à la version épinglée par CT-2 §6.4."
    ],
    "steps": [
      "Lancer le SDK OpenAI et le SDK Agents d'OpenAI (CT-2 §19.5, §6.6) avec le fichier d'intégration ; jouer le scénario de CT-2 §19.2 (lecture, écriture approuvée, échange de modèle).",
      "Clore la période (commande d'exploitation) ; exporter le dossier de chaque appel ; vérifier par le vérificateur de CT-6 (JavaScript et Go) sans réseau.",
      "Relever les connexions sortantes de l'hôte pendant le scénario."
    ],
    "oracle": "Un événement par appel et par échange, accepté par le vérificateur (code 0) ; pièces égales aux octets vus par l'hôte ; aucune connexion de l'hôte vers le serveur d'outils ni vers le fournisseur hors de l'enregistreur ; aucune clé réelle.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Passerelle non construite."
    },
    "threats": []
  },
  {
    "id": "TI-6",
    "level": "TI",
    "title": "Intégration Gemini : `google-genai` vers la passerelle (route `gemini`, `x-goog-api-key`)",
    "specs": [
      "CT-2",
      "CT-1"
    ],
    "covers": [
      "CT-2 EX-19.6",
      "CT-2 EX-5.28",
      "CT-2 EX-5.32",
      "CT-2 EX-5.34",
      "CT-2 EX-5.36"
    ],
    "preconditions": [
      "Enregistreur de la phase 2 (étape 4) lancé avec la configuration de démonstration (CT-2 §19.1) ; fournisseur de modèle simulé (CT-2 §19.3) ; réseau de l'hôte isolé : seul l'enregistreur est joignable.",
      "Fichier d'intégration de CT-2 §19.5 pour cet hôte, à la version épinglée par CT-2 §6.4."
    ],
    "steps": [
      "Lancer `google-genai` 2.33.0 (CT-2 §19.5.7, EX-19.6) avec le fichier d'intégration ; jouer le scénario de CT-2 §19.2 (lecture, écriture approuvée, échange de modèle).",
      "Clore la période (commande d'exploitation) ; exporter le dossier de chaque appel ; vérifier par le vérificateur de CT-6 (JavaScript et Go) sans réseau.",
      "Relever les connexions sortantes de l'hôte pendant le scénario."
    ],
    "oracle": "Un événement par appel et par échange, accepté par le vérificateur (code 0) ; pièces égales aux octets vus par l'hôte ; aucune connexion de l'hôte vers le serveur d'outils ni vers le fournisseur hors de l'enregistreur ; aucune clé réelle.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Passerelle non construite ; la confrontation `ct-2/confrontation/gemini/` n'exerce que les octets des vecteurs."
    },
    "threats": []
  },
  {
    "id": "TI-7",
    "level": "TI",
    "title": "Intégration LangChain et LangGraph : intergiciel `MiddlewareNoortrace`, `wrap_tool_call`",
    "specs": [
      "CT-2",
      "CT-1"
    ],
    "covers": [
      "CT-2 EX-6.19",
      "CT-2 EX-6.20",
      "CT-2 EX-6.9",
      "CT-2 EX-6.10",
      "CT-2 EX-6.11",
      "CT-2 EX-6.12",
      "CT-2 EX-6.13",
      "CT-2 EX-6.14",
      "CT-2 EX-6.15",
      "CT-2 EX-6.16",
      "CT-2 EX-6.17",
      "CT-2 EX-6.18",
      "CT-2 §6.6"
    ],
    "preconditions": [
      "Enregistreur de la phase 2 (étape 4) lancé avec la configuration de démonstration (CT-2 §19.1) ; fournisseur de modèle simulé (CT-2 §19.3) ; réseau de l'hôte isolé : seul l'enregistreur est joignable.",
      "Fichier d'intégration de CT-2 §19.5 pour cet hôte, à la version épinglée par CT-2 §6.4."
    ],
    "steps": [
      "Lancer un agent LangGraph 1.2.17 avec l'adaptateur Python (CT-2 §6.6, §19.5) avec le fichier d'intégration ; jouer le scénario de CT-2 §19.2 (lecture, écriture approuvée, échange de modèle).",
      "Clore la période (commande d'exploitation) ; exporter le dossier de chaque appel ; vérifier par le vérificateur de CT-6 (JavaScript et Go) sans réseau.",
      "Relever les connexions sortantes de l'hôte pendant le scénario."
    ],
    "oracle": "Un événement par appel et par échange, accepté par le vérificateur (code 0) ; pièces égales aux octets vus par l'hôte ; aucune connexion de l'hôte vers le serveur d'outils ni vers le fournisseur hors de l'enregistreur ; aucune clé réelle.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "SDK Python et adaptateurs non construits (étape 4)."
    },
    "threats": []
  },
  {
    "id": "TI-8",
    "level": "TI",
    "title": "Intégration CrewAI : crochets `before_tool_call` et `after_tool_call` enregistrés en dernier",
    "specs": [
      "CT-2",
      "CT-1"
    ],
    "covers": [
      "CT-2 EX-6.21"
    ],
    "preconditions": [
      "Enregistreur de la phase 2 (étape 4) lancé avec la configuration de démonstration (CT-2 §19.1) ; fournisseur de modèle simulé (CT-2 §19.3) ; réseau de l'hôte isolé : seul l'enregistreur est joignable.",
      "Fichier d'intégration de CT-2 §19.5 pour cet hôte, à la version épinglée par CT-2 §6.4."
    ],
    "steps": [
      "Lancer un équipage CrewAI 1.15.30 (CT-2 EX-6.21, §19.5.8) avec le fichier d'intégration ; jouer le scénario de CT-2 §19.2 (lecture, écriture approuvée, échange de modèle).",
      "Clore la période (commande d'exploitation) ; exporter le dossier de chaque appel ; vérifier par le vérificateur de CT-6 (JavaScript et Go) sans réseau.",
      "Relever les connexions sortantes de l'hôte pendant le scénario."
    ],
    "oracle": "Un événement par appel et par échange, accepté par le vérificateur (code 0) ; pièces égales aux octets vus par l'hôte ; aucune connexion de l'hôte vers le serveur d'outils ni vers le fournisseur hors de l'enregistreur ; aucune clé réelle.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Adaptateur non construit ; CrewAI avale les exceptions des crochets (CT-2 EX-6.21) : l'oracle exige le refus avant l'outil, jamais une exception."
    },
    "threats": []
  },
  {
    "id": "TI-9",
    "level": "TI",
    "title": "Intégration LlamaIndex : enveloppe de chaque outil",
    "specs": [
      "CT-2",
      "CT-1"
    ],
    "covers": [
      "CT-2 §6.6",
      "CT-2 EX-6.23"
    ],
    "preconditions": [
      "Enregistreur de la phase 2 (étape 4) lancé avec la configuration de démonstration (CT-2 §19.1) ; fournisseur de modèle simulé (CT-2 §19.3) ; réseau de l'hôte isolé : seul l'enregistreur est joignable.",
      "Fichier d'intégration de CT-2 §19.5 pour cet hôte, à la version épinglée par CT-2 §6.4."
    ],
    "steps": [
      "Lancer un agent `llama-index-core` 0.14.25 (CT-2 §6.6, §19.5.9) avec le fichier d'intégration ; jouer le scénario de CT-2 §19.2 (lecture, écriture approuvée, échange de modèle).",
      "Clore la période (commande d'exploitation) ; exporter le dossier de chaque appel ; vérifier par le vérificateur de CT-6 (JavaScript et Go) sans réseau.",
      "Relever les connexions sortantes de l'hôte pendant le scénario."
    ],
    "oracle": "Un événement par appel et par échange, accepté par le vérificateur (code 0) ; pièces égales aux octets vus par l'hôte ; aucune connexion de l'hôte vers le serveur d'outils ni vers le fournisseur hors de l'enregistreur ; aucune clé réelle.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Adaptateur non construit."
    },
    "threats": []
  },
  {
    "id": "TI-10",
    "level": "TI",
    "title": "Intégration LiteLLM : `CustomLogger` en bibliothèque et LiteLLM en mandataire devant la passerelle",
    "specs": [
      "CT-2",
      "CT-1"
    ],
    "covers": [
      "CT-2 EX-6.22",
      "CT-2 EX-6.24"
    ],
    "preconditions": [
      "Enregistreur de la phase 2 (étape 4) lancé avec la configuration de démonstration (CT-2 §19.1) ; fournisseur de modèle simulé (CT-2 §19.3) ; réseau de l'hôte isolé : seul l'enregistreur est joignable.",
      "Fichier d'intégration de CT-2 §19.5 pour cet hôte, à la version épinglée par CT-2 §6.4."
    ],
    "steps": [
      "Lancer LiteLLM 1.106.4 dans ses deux dispositions (CT-2 EX-6.22, §19.5.10) avec le fichier d'intégration ; jouer le scénario de CT-2 §19.2 (lecture, écriture approuvée, échange de modèle).",
      "Clore la période (commande d'exploitation) ; exporter le dossier de chaque appel ; vérifier par le vérificateur de CT-6 (JavaScript et Go) sans réseau.",
      "Relever les connexions sortantes de l'hôte pendant le scénario."
    ],
    "oracle": "Un événement par appel et par échange, accepté par le vérificateur (code 0) ; pièces égales aux octets vus par l'hôte ; aucune connexion de l'hôte vers le serveur d'outils ni vers le fournisseur hors de l'enregistreur ; aucune clé réelle.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Adaptateur et passerelle non construits."
    },
    "threats": []
  },
  {
    "id": "TI-11",
    "level": "TI",
    "title": "Intégration OpenTelemetry : agent instrumenté par un SDK OpenTelemetry vers le point d'entrée OTLP de l'enregistreur",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 §6.8",
      "CT-2 EX-6.37",
      "CT-2 EX-6.38",
      "CT-2 EX-6.39",
      "CT-2 EX-6.40",
      "CT-2 EX-6.41"
    ],
    "preconditions": [
      "Enregistreur de l'étape 4 avec `otel` activé ; agent instrumenté par le SDK OpenTelemetry d'un langage de CT-2 §6.4, exportateur OTLP/HTTP (JSON puis protobuf) ; jeton de source."
    ],
    "steps": [
      "Émettre les spans du scénario de démonstration ; rejouer la même requête (doublon) ; dépasser `spans_per_request` ; envoyer sans jeton."
    ],
    "oracle": "Événements déclaratifs de rang CT-2 §6.7 acceptés par le vérificateur ; doublon signalé ; 413 et 401 exacts ; formes normalisées égales à celles que `otel/` des vecteurs donne pour les mêmes octets.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Point d'entrée OTLP non construit ; `otel.mjs` et les 48 cas des vecteurs (TV-) couvrent la bibliothèque seule."
    },
    "threats": [
      "MN-15",
      "MN-16"
    ]
  },
  {
    "id": "TI-12",
    "level": "TI",
    "title": "Requêtes OTLP confrontées à `opentelemetry-proto` et réponses `ExportTraceServiceResponse` exactes",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-6.29",
      "CT-2 EX-6.30",
      "CT-2 §B.8"
    ],
    "preconditions": [
      "Sorties publiées de `ct-2/confrontation/otel/` ; `opentelemetry-proto` 1.45.1 et `protobuf` 7.36.2 pour le rejeu."
    ],
    "steps": [
      "Décoder chaque `requete.pb` des vecteurs par la bibliothèque officielle ; comparer aux formes JSON ; réencoder."
    ],
    "oracle": "Mêmes octets, même forme normalisée que l'implémentation de référence.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/confrontation.test.js",
          "describe": "CT-2 : sorties publiées de la confrontation par des outils tiers (annexes B.5 et B.8)",
          "it": "otel.txt (opentelemetry-proto 1.45.1, protobuf 7.36.2) : chaque cas, SHA-256 des requêtes égaux aux fichiers, identifiants de chaque span"
        },
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : ingestion OpenTelemetry (6.8, EX-6.25 à EX-6.41)",
          "it": "paires JSON / protobuf : mêmes formes normalisées, pièces et événements ; l'encodeur redonne les octets de requete.pb"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/confrontation.test.js"
    },
    "threats": []
  },
  {
    "id": "TI-13",
    "level": "TI",
    "title": "SDK Python et TypeScript : interface publique, versions de langage, aucune exception vers l'agent",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-6.1",
      "CT-2 EX-6.2",
      "CT-2 EX-6.3",
      "CT-2 EX-6.4",
      "CT-2 EX-6.6",
      "CT-2 EX-6.7",
      "CT-2 EX-6.5",
      "CT-2 §6.5"
    ],
    "preconditions": [
      "SDK de l'étape 4 : `noortrace-sdk` JavaScript (paquets/sdk-js) sous Node.js 22 (v22.22.0 au 2026-11-03) et Python (paquets/sdk-python) sous Python 3.10 (3.10.20) et 3.13 (3.13.16), environnements `essais-py310` et `essais-py313` créés par `uv` depuis les verrous versionnés (`paquets/sdk-python/outils/environnements.sh preparer`) ; un environnement absent met son exécution en attente et le titre nomme la condition (EX-3.11).",
      "Démon réel du banc du SDK Python (`test/fixtures/enregistreur-sdk-python/banc.mjs` : point d'entrée SDK sur prise Unix, service d'approbation simulé qui rend a_approuver pour un outil `*approuver*` et refuse pour `*refuser*`), neuf pour chaque langage ; démon muet qui fait la preuve d'identité puis ne répond plus."
    ],
    "steps": [
      "Jouer le même scénario dans chaque langage (`test/fixtures/enregistreur-sdk-langages/scenario.mjs`, `scenario.py`) : ouvrir, declarer_contexte, debut_appel et fin_appel, appel_outil d'écriture, debut_appel soumis à approbation puis refusé, appel_outil refusé, echange_modele, fermer.",
      "Couper l'enregistreur après l'ouverture d'une session (appel_outil d'écriture, puis ouvrir) ; dépasser delai_s sur le démon muet.",
      "Comparer les sorties normalisées et les événements des trois exécutions ; vérifier le journal et le dossier d'un événement de chacune."
    ],
    "oracle": "Événements conformes (journal accepté par le noyau, dossier valide pour le noyau et pour le binaire Go si go1.27.3 est présent) et de mêmes pièces dans les deux langages ; chaque issue de politique rend le résultat de la table de CT-2 EX-6.7 sans exception (EX-6.4) ; une panne de l'enregistreur rend l'exception d'EX-6.12 (`NoortraceIndisponible` / `ErreurNoortraceIndisponible`, `envoyee` faux démon arrêté, vrai au-delà de delai_s) et l'outil d'écriture n'est jamais exécuté (EX-6.15) ; sorties normalisées identiques dans les deux langages.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur-sdk-langages.test.js",
          "describe": "TI-13 — SDK Python et TypeScript : interface publique de CT-2 6.5, Python 3.10 et 3.13 et Node.js 22, issues de politique sans exception, panne de l'enregistreur, comportement identique dans les deux langages",
          "it": "SDK JavaScript (Node.js 22) : chaque fonction de l'interface publique ; issues de politique de la table d'EX-6.7 rendues sans exception par debutAppel ; démon arrêté : ErreurNoortraceIndisponible, outil d'écriture jamais exécuté ; démon muet au-delà de delai_s : ErreurNoortraceIndisponible, requête écrite ; événements conformes (journal et dossier vérifiés)"
        },
        {
          "file": "test/enregistreur-sdk-langages.test.js",
          "describe": "TI-13 — SDK Python et TypeScript : interface publique de CT-2 6.5, Python 3.10 et 3.13 et Node.js 22, issues de politique sans exception, panne de l'enregistreur, comportement identique dans les deux langages",
          "it": "SDK Python 3.10 : mêmes sorties normalisées que le SDK JavaScript, étape par étape (interface publique, issues de politique, démon arrêté puis muet), mêmes événements (outils, statuts, décisions, pièces) ; événements conformes (journal et dossier vérifiés)"
        },
        {
          "file": "test/enregistreur-sdk-langages.test.js",
          "describe": "TI-13 — SDK Python et TypeScript : interface publique de CT-2 6.5, Python 3.10 et 3.13 et Node.js 22, issues de politique sans exception, panne de l'enregistreur, comportement identique dans les deux langages",
          "it": "SDK Python 3.13 : mêmes sorties normalisées que le SDK JavaScript, étape par étape (interface publique, issues de politique, démon arrêté puis muet), mêmes événements (outils, statuts, décisions, pièces) ; événements conformes (journal et dossier vérifiés)"
        }
      ]
    },
    "threats": []
  },
  {
    "id": "TI-14",
    "level": "TI",
    "title": "Canal réel noyau ↔ service d'approbation et console ↔ service : authentification, `evaluer`, `GET /v0/etat`, sessions",
    "specs": [
      "CT-3",
      "CT-2"
    ],
    "covers": [
      "CT-3 EX-12.1",
      "CT-3 EX-12.2",
      "CT-3 EX-12.3",
      "CT-3 EX-12.4",
      "CT-3 EX-12.7",
      "CT-3 EX-12.8",
      "CT-3 EX-12.9",
      "CT-3 EX-12.10",
      "CT-3 EX-12.11",
      "CT-3 EX-12.12",
      "CT-3 EX-12.13",
      "CT-3 EX-12.15",
      "CT-3 EX-12.18",
      "CT-2 EX-7.4",
      "CT-2 EX-7.5"
    ],
    "preconditions": [
      "Service d'approbation et serveur de console de l'étape 6 ; enregistreur de l'étape 4 ; jetons ou certificats du canal (CT-7 CLE-23)."
    ],
    "steps": [
      "Évaluer, retenir, voter, remettre, acquitter, consommer sur le réseau ; couper le canal ; présenter un jeton faux ; relancer le service depuis ses documents persistés."
    ],
    "oracle": "Sept combinaisons d'`evaluer` et refus des autres (CT-3 EX-12.6) ; canal non authentifié refusé ; mêmes sorties après reprise (TK-12).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 6,
      "blocking": "Service non construit ; seule la partie calculable est testée (TU-)."
    },
    "threats": [
      "MN-51",
      "MN-77"
    ]
  },
  {
    "id": "TI-15",
    "level": "TI",
    "title": "Supports WORM réels (S3, Azure, GCS) : requêtes exactes, verrou, rétention, journal d'accès",
    "specs": [
      "CT-2",
      "CT-8"
    ],
    "covers": [
      "CT-2 EX-12.29",
      "CT-2 EX-12.30",
      "CT-2 EX-12.31",
      "CT-2 EX-12.32",
      "CT-2 EX-18.9",
      "CT-8 EX-11.19",
      "CT-8 EX-11.6"
    ],
    "preconditions": [
      "Comptes de test sur chaque support, hors du dépôt (références de secret) ; enregistreur de l'étape 4."
    ],
    "steps": [
      "Copier une période ; poser et lever un gel ; tenter une suppression avec chaque rôle du client ; relever le journal d'accès du support et son format."
    ],
    "oracle": "Version dont le SHA-256 égale l'original ; mode et date de rétention rendus par l'API ; suppression refusée pour tout rôle ; journal d'accès disponible et au format relevé (CT-8 §15 : « CT-9 les établit »).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Aucun support réel n'est configuré ; `worm/` des vecteurs fixe les octets des requêtes seulement."
    },
    "threats": [
      "MN-27",
      "MN-28",
      "MN-29"
    ]
  },
  {
    "id": "TI-16",
    "level": "TI",
    "title": "Prestataires RFC 3161 et calendriers OpenTimestamps réels : fiche de prestataire, `min_interval_ms`, qualification",
    "specs": [
      "CT-5"
    ],
    "covers": [
      "CT-5 EX-11.1",
      "CT-5 EX-11.2",
      "CT-5 EX-11.3",
      "CT-5 EX-11.4",
      "CT-5 EX-11.5",
      "CT-5 AN-7",
      "CT-5 AN-12",
      "CT-5 AN-14",
      "CT-5 AN-15",
      "CT-5 AN-54",
      "CT-5 AN-55",
      "CT-5 AN-56",
      "CT-5 AN-57",
      "CT-5 AN-58",
      "CT-5 EX-5.2",
      "CT-5 EX-5.4",
      "CT-5 EX-5.5",
      "CT-5 EX-5.6",
      "CT-5 EX-5.8",
      "CT-5 EX-5.9",
      "CT-5 EX-5.14",
      "CT-5 EX-5.15",
      "CT-5 EX-5.16",
      "CT-5 EX-6.8",
      "CT-5 EX-6.9",
      "CT-5 EX-6.10"
    ],
    "preconditions": [
      "Composant d'ancrage de l'étape 5 ; accès à un prestataire de test et à deux calendriers ; aucun prix dans le dépôt."
    ],
    "steps": [
      "Acquérir un jeton et une preuve `.ots` pour une racine ; retirer la qualification du principal dans la configuration sans recharger (CT-5 EX-5.9) ; respecter `min_interval_ms` ; relire la fiche de prestataire."
    ],
    "oracle": "Jeton accepté par T-1 à T-10 ; relève de la clôture par le secours qualifié tant que la configuration n'est pas rechargée (test « à écrire » de CT-5 §14) ; aucune requête sous `min_interval_ms`.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 5,
      "blocking": "Composant d'ancrage non construit ; le planificateur à horloge injectée (TV-) ne parle à aucun prestataire."
    },
    "threats": [
      "MN-62",
      "MN-76"
    ]
  },
  {
    "id": "TI-17",
    "level": "TI",
    "title": "Serveur RFC 3161 interne : AN-22 à AN-31 vérifiées sur un jeton émis, épreuve de redémarrage (AN-26)",
    "specs": [
      "CT-5"
    ],
    "covers": [
      "CT-5 EX-7.1",
      "CT-5 EX-7.2",
      "CT-5 EX-7.3",
      "CT-5 EX-7.4",
      "CT-5 AN-22",
      "CT-5 AN-23",
      "CT-5 AN-24",
      "CT-5 AN-25",
      "CT-5 AN-26",
      "CT-5 AN-27",
      "CT-5 AN-28",
      "CT-5 AN-29",
      "CT-5 AN-30",
      "CT-5 AN-31",
      "CT-7 CLE-10"
    ],
    "preconditions": [
      "Serveur interne de l'étape 5 (optionnel, CT-5 §7) ; client RFC 3161 du composant d'ancrage."
    ],
    "steps": [
      "Émettre un jeton ; l'évaluer par T-1 à T-10 ; redémarrer le serveur ; émettre un second jeton ; demander un condensé non SHA-2, une politique autre que la privée."
    ],
    "oracle": "EKU critique et unique, `ESSCertIDv2` SHA-256, nonce repris, `serialNumber` strictement croissant à travers le redémarrage, `badAlg` et `unacceptedPolicy` rendus, journal des jetons hors du serveur.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 5,
      "blocking": "Serveur non construit (CT-5 §7.2 : « vérifiées par CT-9 sur un jeton émis »)."
    },
    "threats": [
      "MN-42"
    ]
  },
  {
    "id": "TI-18",
    "level": "TI",
    "title": "Nœud noorcore et certificat de commit : JSON-RPC `noor_getCommitCertificate`, parité Go/JavaScript, confrontation go-ethereum",
    "specs": [
      "CT-4",
      "CT-6"
    ],
    "covers": [
      "CT-4 §9",
      "CT-6 EX-11.1",
      "CT-6 EX-11.2",
      "CT-6 EX-11.3",
      "CT-6 EX-11.4",
      "CT-6 EX-11.6",
      "CT-6 EX-11.7",
      "CT-6 EX-11.10",
      "CT-6 EX-11.11",
      "CT-6 EX-11.12",
      "CT-6 EX-11.13",
      "CT-6 EX-11.14",
      "CT-6 EX-11.15",
      "CT-6 EX-11.16",
      "CT-6 EX-11.17",
      "CT-6 EX-11.18",
      "CT-6 EX-11.19",
      "CT-6 EX-11.23",
      "CT-6 EX-11.24",
      "CT-6 EX-11.20",
      "CT-6 EX-11.21",
      "CT-6 EX-11.25"
    ],
    "preconditions": [
      "Fixtures du réseau de développement (`test/fixtures/certificat-commit/`) ; sorties publiées `ct-6/confrontation/registre/`."
    ],
    "steps": [
      "Décoder la fixture par le décodeur JavaScript ; comparer aux sorties du Go de noorcore et de go-ethereum."
    ],
    "oracle": "Même certificat, mêmes validateurs, même hachage de bloc.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/certificatCommit.test.js",
          "describe": "Certificat de commit — parité avec le décodeur du nœud (vecteurs « lignes » et « fichiers » du Go)"
        },
        {
          "file": "test/certificatCommit.test.js",
          "describe": "Certificat de commit — fixture du réseau de développement (test/fixtures/certificat-commit)"
        },
        {
          "file": "test/confrontation.test.js",
          "describe": "CT-6 : sorties publiées de la confrontation par des outils tiers (annexe A.8)",
          "it": "registre-certificats.txt : chaque certificat de la capture vérifié par certificat-commit.mjs (VALIDE, code 0), chemins relatifs"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/certificatCommit.test.js"
    },
    "threats": [
      "MN-55"
    ]
  },
  {
    "id": "TI-19",
    "level": "TI",
    "title": "Mode ICAP : raccord à un mandataire existant, sources admises",
    "specs": [
      "CT-2",
      "CT-8"
    ],
    "covers": [
      "CT-2 §19.6",
      "CT-2 EX-5.3",
      "CT-2 EX-5.8",
      "CT-8 EX-5.4"
    ],
    "preconditions": [
      "Enregistreur de l'étape 4 : démons réels `bin/noortrace --config` sur un même journal, en mode `passerelle` (référence) puis en mode `icap` ; mandataire d'interception Squid 6.13, paquet Debian `squid-openssl` 6.13-2+deb13u3 (OpenSSL, ssl-bump ; CT-2 §19.6 : seul équipement dont la configuration a été lue), image construite par `test/fixtures/enregistreur-modele/squid/Dockerfile` (base `debian:trixie-slim` épinglée par condensé, paquets lus dans l'instantané daté de l'archive Debian), réseau de l'hôte ; services ICAP REQMOD et RESPMOD (`reqmod_precache`, `respmod_precache`, `bypass=off`), `icap_send_client_ip on` (`client_address_header: \"X-Client-IP\"`), adaptation limitée à la destination du fournisseur hors tunnel CONNECT, ssl-bump (peek puis bump) avec une autorité d'interception de test créée par le harnais (rôle de CT-7 CLE-27 : clé hors de NOORTRACE, tenue par le client en production ; CLE-27 nomme la clé, il ne dit pas comment en fabriquer une pour l'épreuve).",
      "Montage : simulateur de fournisseur servi en HTTPS sous `api.fournisseur.example` (autorité de test), joint par Squid (résolution par `--add-host`) et, en mode passerelle, par une route de l'enregistreur pour ce même nom (le démon le résout vers 127.0.0.1 par un module de test chargé à son lancement, `--import`) ; lien ICAP en clair (`icap://127.0.0.1`) restreint par `allowed_sources` (CT-2 EX-5.3), relevé par un relais qui garde les octets de chaque sens (`ISTag`, statuts, requête encapsulée par RESPMOD) ; démons à l'écoute sur le port 0, adresses réelles lues dans leur journal d'exploitation. Docker et `openssl` requis, sinon les cas sont en attente et leur titre nomme la condition ; binaire Go `noortrace-verifier` construit avec go1.27.3 (NOORTRACE_GO_BIN)."
    ],
    "steps": [
      "Jouer le même échange de modèle hors flux (échange n° 1 de CT-2 §19.2) deux fois, par le même client de test, qui envoie `Accept-Encoding: identity` dans les deux modes (en ICAP, l'enregistreur ne pose pas cet en-tête : la requête qu'il rend est l'originale augmentée de `X-Noortrace-Exchange`, CT-2 EX-5.4 ; en passerelle, il le pose lui-même, CT-2 EX-5.9) : par la passerelle (référence), la requête portant `X-Noortrace-Run-Id`, et par le mandataire ICAP, l'hôte non reconfiguré n'envoyant aucun en-tête `X-Noortrace-*` (CT-2 EX-5.8) ; comparer les deux événements. Le flux SSE (échange n° 2 de CT-2 §19.2 : relais sans tampon en passerelle, RESPMOD par morceaux) est hors de TI-19.",
      "Présenter un client ICAP hors d'`allowed_sources` (CT-2 EX-5.3) et une adresse d'hôte hors de `model.hosts` (CT-2 EX-5.8)."
    ],
    "oracle": "Égalité, événement à événement avec l'échange joué en mode passerelle, de `code.model`, `code.prompt_version`, des `sha256`, `length` et `redacted` des pièces « requête » et « réponse » (références de CT-1 §5.4) et de `execution.is_error`, comparé par égalité entre les deux modes, sa règle restant celle de CT-2 §5.3.1 (statut du fournisseur et corps non JSON compris) ; écarts attendus et consignés (EX-3.4) : `delegation.run_id` nul en ICAP, l'hôte non reconfiguré n'ayant déclaré aucun `run_id` (aucune assertion n'exige `null` pour un `run_id` déclaré par en-tête en ICAP : CT-2 EX-5.8 traite l'en-tête `X-Noortrace-Run-Id` dans tous les modes), hôte rattaché par `source_addresses` (en-tête `client_address_header`), corrélation par groupe d'hôte seulement (CT-2 EX-5.8, §5.6). ICAP (CT-2 EX-5.3) : réponse OPTIONS avec `Methods`, `ISTag` et `Encapsulated: null-body=0`, `ISTag` sur toute réponse, aucune réponse `204` en REQMOD ni en RESPMOD (CT-2 EX-5.4, EX-5.5 ; la permission `Allow: 204` ou Preview qu'EX-5.3 rappelle est celle de la RFC 3507, qu'aucun des deux services n'exerce) ; un client ICAP hors d'`allowed_sources` est refusé sans événement, avec une ligne consignée ; une adresse d'hôte hors de `model.hosts` est rattachée à l'entrée « inconnu » si la configuration en déclare une, sinon bloquée en REQMOD (CT-2 EX-5.8). Écarts connus, consignés (EX-3.4) : statut ICAP du refus d'un client et nom de la ligne du journal d'exploitation non fixés par CT-2 EX-17.2 ; statut encapsulé et ligne du journal du blocage d'une adresse d'hôte inconnue en REQMOD non fixés, CT-2 EX-5.4 n'énumérant pas ce troisième cas (PD-26) ; forme du `match` de l'entrée « inconnu » non fixée par CT-2 EX-5.8 : la forme employée par le montage est consignée (PD-26) ; présence de `X-Noortrace-Exchange` dans la requête encapsulée par RESPMOD (CT-2 EX-5.4) : constatée sur Squid 6.13 (`squid-openssl` 6.13-2+deb13u3), qui encapsule en RESPMOD l'en-tête de la requête adaptée par REQMOD ; la corrélation se fait par ce MAC, sans heuristique (aucune ligne `icap_correlation_heuristique` ni `icap_requete_inconnue`). Formes consignées du démon : client ICAP refusé, `403` avec `ISTag` et ligne `auth_failed` (`transport: \"icap\"`, `reason: \"client_icap_refuse\"`), l'agent recevant l'erreur de Squid ; adresse d'hôte inconnue sans entrée « inconnu », réponse HTTP encapsulée `401` (`res-hdr`) et ligne `auth_failed` (`reason: \"hote_inconnu\"`, `status: 401`) ; entrée « inconnu » du montage : `match: { source_addresses: [plage qui ne contient pas le client] }`, l'`id` la désignant. Défaut révélé par l'épreuve et corrigé (CT-2 EX-5.3) : une connexion de client ICAP refusée restait ouverte tant que le pair gardait son côté, et retenait l'arrêt du démon jusqu'au délai de drain.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur-modele-squid.test.js",
          "describe": "TI-19 — mode ICAP : raccord à un mandataire Squid réel (ssl-bump, REQMOD et RESPMOD) ; échange comparé à la passerelle ; sources ICAP admises et refusées ; adresse d'hôte inconnue ; dossiers vérifiés par les deux vérificateurs",
          "it": "chaque échange produit un événement ; égalité, entre la passerelle (référence) et Squid par ICAP, de code.model, code.prompt_version, des pièces « requête » et « réponse » (sha256, length, redacted) et d'execution.is_error ; écarts consignés : run_id nul en ICAP, hôte rattaché par source_addresses (X-Client-IP de Squid), même groupe d'hôte"
        },
        {
          "file": "test/enregistreur-modele-squid.test.js",
          "describe": "TI-19 — mode ICAP : raccord à un mandataire Squid réel (ssl-bump, REQMOD et RESPMOD) ; échange comparé à la passerelle ; sources ICAP admises et refusées ; adresse d'hôte inconnue ; dossiers vérifiés par les deux vérificateurs",
          "it": "adresse d'hôte hors de model.hosts (CT-2 EX-5.8) : rattachée à l'entrée « inconnu » déclarée (forme du match consignée : source_addresses d'une plage qui ne contient pas le client) — un événement ; sans elle, bloquée en REQMOD par une réponse HTTP encapsulée — aucun événement, rien chez le fournisseur, ligne consignée"
        },
        {
          "file": "test/enregistreur-modele-squid.test.js",
          "describe": "TI-19 — mode ICAP : raccord à un mandataire Squid réel (ssl-bump, REQMOD et RESPMOD) ; échange comparé à la passerelle ; sources ICAP admises et refusées ; adresse d'hôte inconnue ; dossiers vérifiés par les deux vérificateurs",
          "it": "client ICAP hors d'allowed_sources (CT-2 EX-5.3) : Squid refusé (403, ISTag), aucun événement, rien chez le fournisseur, l'agent reçoit l'erreur de Squid, ligne consignée ; le démon s'arrête proprement (la connexion refusée ne le retient pas)"
        },
        {
          "file": "test/enregistreur-modele-squid.test.js",
          "describe": "TI-19 — mode ICAP : raccord à un mandataire Squid réel (ssl-bump, REQMOD et RESPMOD) ; échange comparé à la passerelle ; sources ICAP admises et refusées ; adresse d'hôte inconnue ; dossiers vérifiés par les deux vérificateurs",
          "it": "période close à l'heure suivante : journal accepté par le noyau ; dossiers de l'échange en passerelle et de l'échange par ICAP valides pour le noyau ET pour le binaire Go (go1.27.3)"
        },
        {
          "file": "test/enregistreur-modele-squid.test.js",
          "describe": "TI-19, défaut révélé : client ICAP refusé qui garde sa moitié de connexion ouverte (CT-2 EX-5.3) — le serveur ICAP détruit la prise après le 403 et s'arrête sans attendre le délai de drain"
        }
      ]
    },
    "threats": [
      "MN-12"
    ]
  },
  {
    "id": "TI-20",
    "level": "TI",
    "title": "Export des pièces d'un dossier vers un paquet réviseur lu par des outils tiers (GNU tar, `tarfile`)",
    "specs": [
      "CT-8",
      "CT-6"
    ],
    "covers": [
      "CT-8 EX-13.3",
      "CT-8 EX-13.14",
      "CT-8 EX-13.16",
      "CT-6 EX-14.8"
    ],
    "preconditions": [
      "Paquets des vecteurs `ct-8/paquets/` ; GNU tar et Python 3.12 ou 3.13."
    ],
    "steps": [
      "Lire chaque archive par `tar -t`, `tarfile` (filtre `data`) et la lecture brute des blocs ; comparer."
    ],
    "oracle": "Mêmes entrées, tailles et SHA-256 ; aucune entrée refusée par le filtre `data`.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/confrontation.test.js",
          "describe": "CT-8 : sorties publiées de la confrontation des paquets réviseurs par GNU tar et tarfile (EX-A.32 à EX-A.35)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/confrontation.test.js"
    },
    "threats": []
  }
];
