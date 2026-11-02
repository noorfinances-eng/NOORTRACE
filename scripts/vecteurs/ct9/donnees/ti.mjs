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
      "Enregistreur de l'étape 4 ; client MCP de référence de l'ère de CT-2 §0.3 ; serveur d'outils de démonstration (`outils-demo`, CT-2 §19.1)."
    ],
    "steps": [
      "Négocier la version, lister, appeler `claims.get`, `claims.search`, `payments.create` par stdio puis par Streamable HTTP ; authentifier une connexion d'hôte ; couper le serveur en cours d'appel."
    ],
    "oracle": "Chaque appel produit l'événement attendu (comparé par `pieces-mcp/` sur les mêmes octets) ; requête non authentifiée refusée ; serveur coupé : erreur -3101x consignée et aucun événement forgé.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 4,
      "blocking": "Le démon n'est pas construit ; seules les bibliothèques existent (TU-, TV-)."
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
      "SDK de l'étape 4 ; interpréteurs Python 3.10 et 3.13, Node.js 22 (CT-2 §6.4)."
    ],
    "steps": [
      "Exercer chaque fonction de l'interface publique de CT-2 §6.5 contre un enregistreur de test ; couper l'enregistreur ; dépasser `delai_s`."
    ],
    "oracle": "Événements conformes ; une panne de l'enregistreur rend le résultat de la table de CT-2 EX-6.7 sans exception ; comportement identique dans les deux langages.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 4,
      "blocking": "SDK non construits (CT-2 §6, « à tester en phase 2 »)."
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
      "Enregistreur de l'étape 4 en mode ICAP ; mandataire d'interception Squid (CT-2 §19.6 : seul équipement dont la configuration a été lue), services ICAP REQMOD et RESPMOD et interception TLS en place, version exacte consignée à la livraison de l'étape 4 (EX-3.4) ; autorité d'interception de test créée par le harnais pour le mandataire (rôle de CT-7 CLE-27 : clé hors de NOORTRACE, tenue par le client en production ; CLE-27 nomme la clé, il ne dit pas comment en fabriquer une pour l'épreuve). Montage : simulateur de fournisseur servi en HTTPS sous un nom de domaine `.example`, joint par le mandataire et, en mode passerelle, par une route de l'enregistreur pour ce même nom ; lien ICAP en clair (`icap://`, port 1344) restreint par `allowed_sources` (CT-2 EX-5.3), sur lequel se relève `ISTag` de chaque réponse ICAP."
    ],
    "steps": [
      "Jouer le même échange de modèle hors flux (échange n° 1 de CT-2 §19.2) deux fois, par le même client de test, qui envoie `Accept-Encoding: identity` dans les deux modes (en ICAP, l'enregistreur ne pose pas cet en-tête : la requête qu'il rend est l'originale augmentée de `X-Noortrace-Exchange`, CT-2 EX-5.4 ; en passerelle, il le pose lui-même, CT-2 EX-5.9) : par la passerelle (référence), la requête portant `X-Noortrace-Run-Id`, et par le mandataire ICAP, l'hôte non reconfiguré n'envoyant aucun en-tête `X-Noortrace-*` (CT-2 EX-5.8) ; comparer les deux événements. Le flux SSE (échange n° 2 de CT-2 §19.2 : relais sans tampon en passerelle, RESPMOD par morceaux) est hors de TI-19.",
      "Présenter un client ICAP hors d'`allowed_sources` (CT-2 EX-5.3) et une adresse d'hôte hors de `model.hosts` (CT-2 EX-5.8)."
    ],
    "oracle": "Égalité, événement à événement avec l'échange joué en mode passerelle, de `code.model`, `code.prompt_version`, des `sha256`, `length` et `redacted` des pièces « requête » et « réponse » (références de CT-1 §5.4) et de `execution.is_error`, comparé par égalité entre les deux modes, sa règle restant celle de CT-2 §5.3.1 (statut du fournisseur et corps non JSON compris) ; écarts attendus et consignés (EX-3.4) : `delegation.run_id` nul en ICAP, l'hôte non reconfiguré n'ayant déclaré aucun `run_id` (aucune assertion n'exige `null` pour un `run_id` déclaré par en-tête en ICAP : CT-2 EX-5.8 traite l'en-tête `X-Noortrace-Run-Id` dans tous les modes), hôte rattaché par `source_addresses` (en-tête `client_address_header`), corrélation par groupe d'hôte seulement (CT-2 EX-5.8, §5.6). ICAP (CT-2 EX-5.3) : réponse OPTIONS avec `Methods`, `ISTag` et `Encapsulated: null-body=0`, `ISTag` sur toute réponse, aucune réponse `204` en REQMOD ni en RESPMOD (CT-2 EX-5.4, EX-5.5 ; la permission `Allow: 204` ou Preview qu'EX-5.3 rappelle est celle de la RFC 3507, qu'aucun des deux services n'exerce) ; un client ICAP hors d'`allowed_sources` est refusé sans événement, avec une ligne consignée ; une adresse d'hôte hors de `model.hosts` est rattachée à l'entrée « inconnu » si la configuration en déclare une, sinon bloquée en REQMOD (CT-2 EX-5.8). Écarts connus, consignés (EX-3.4) : statut ICAP du refus d'un client et nom de la ligne du journal d'exploitation non fixés par CT-2 EX-17.2 ; statut encapsulé et ligne du journal du blocage d'une adresse d'hôte inconnue en REQMOD non fixés, CT-2 EX-5.4 n'énumérant pas ce troisième cas (PD-26) ; forme du `match` de l'entrée « inconnu » non fixée par CT-2 EX-5.8 : la forme employée par le montage est consignée (PD-26) ; présence de `X-Noortrace-Exchange` dans la requête encapsulée par RESPMOD vérifiée sur Squid en phase 2 (CT-2 EX-5.4), à défaut corrélation heuristique et pièce « requête » `{\"noortrace_requete_inconnue\": true}`, consignée.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 4,
      "blocking": "CT-2 §19.6 : « à tester en phase 2 » ; CT-8 §5.3 : « épreuve de CT-9 »."
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
