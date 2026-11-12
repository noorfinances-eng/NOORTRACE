// Source de données du catalogue CT-9 : entrées TV- (section 7), telles
// qu'elles sont imprimées dans spec/vecteurs/ct-9/catalogue.json.

export const TV = [
  {
    "id": "TV-1",
    "level": "TV",
    "title": "`ct-1/cles/` : clés de test dérivées des graines",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 §13"
    ],
    "preconditions": [
      "Vecteurs `ct-1/cles` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Dériver chaque clé depuis sa graine documentée ; comparer à `cles-test.json` et aux `cles.json` des dossiers."
    ],
    "oracle": "Égalité des dérivations.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : Ed25519 (RFC 8032)",
          "it": "dérive les clés de test de la section 13 depuis les graines documentées"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-2",
    "level": "TV",
    "title": "`ct-1/jcs/cas-limites.json` : forme canonique ou refus",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 E-2"
    ],
    "preconditions": [
      "Vecteurs `ct-1/jcs` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Canonicaliser chaque entrée du fichier."
    ],
    "oracle": "Octets égaux à la forme attendue, ou refus quand l'attendu est `null`.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : forme canonique JCS v0 (RFC 8785 restreinte aux entiers)",
          "it": "rejoue jcs/cas-limites.json : forme canonique attendue, ou refus"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": [
      "MN-4"
    ]
  },
  {
    "id": "TV-3",
    "level": "TV",
    "title": "`ct-1/journal-valide/` et les cinq journaux altérés : contrôles de la table 7.2",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 C-1",
      "CT-1 C-2",
      "CT-1 C-3",
      "CT-1 E-1",
      "CT-1 E-2",
      "CT-1 E-3",
      "CT-1 E-4",
      "CT-1 E-5",
      "CT-1 E-6",
      "CT-1 E-7",
      "CT-1 E-8",
      "CT-1 E-9",
      "CT-1 E-10",
      "CT-1 E-11"
    ],
    "preconditions": [
      "Vecteurs `ct-1/journal-*` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Vérifier le journal valide ; vérifier chaque journal altéré (supprimé, modifié, inséré, inséré sans clé, réordonné)."
    ],
    "oracle": "Hachages égaux à `attendu.json` ; diagnostic nommé égal à celui du vecteur.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : chaînage",
          "it": "le journal valide des vecteurs passe, et ses hachages sont ceux de attendu.json"
        },
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : chaînage",
          "it": "suppression, modification, insertion, réordonnancement : diagnostics nommés des vecteurs"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": [
      "MN-17",
      "MN-74"
    ]
  },
  {
    "id": "TV-4",
    "level": "TV",
    "title": "`ct-1/merkle/arbres.json` : racines et preuves d'inclusion",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 M-1",
      "CT-1 M-2",
      "CT-1 M-3"
    ],
    "preconditions": [
      "Vecteurs `ct-1/merkle` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Recalculer la racine et chaque preuve des arbres de 0, 1, 2, 3, 5, 8, 12 et 1000 feuilles."
    ],
    "oracle": "Égalité des racines ; chaque preuve acceptée.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : arbre de Merkle RFC 6962 et preuves d'inclusion",
          "it": "rejoue merkle/arbres.json : racines et preuves des arbres de 0, 1, 2, 3, 12 et 1000 feuilles"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-5",
    "level": "TV",
    "title": "`ct-1/merkle/coherence.json` et `ct-1/points-de-controle/` : preuves de cohérence, séries valides et invalides",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 K-1",
      "CT-1 K-2",
      "CT-1 K-3",
      "CT-1 K-4",
      "CT-1 K-5",
      "CT-1 K-6"
    ],
    "preconditions": [
      "Vecteurs `ct-1/points-de-controle` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Recalculer chaque preuve de cohérence nœud pour nœud et le verdict de chaque sonde ; rejouer chaque série de points."
    ],
    "oracle": "Égalité ; une série invalide échoue à la règle que son nom annonce.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : preuve de cohérence RFC 9162 §2.1.4 et points de contrôle (révision 0.3)",
          "it": "rejoue merkle/coherence.json : preuves recalculées nœud pour nœud et verdict de chaque sonde"
        },
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : preuve de cohérence RFC 9162 §2.1.4 et points de contrôle (révision 0.3)",
          "it": "rejoue points-de-controle/attendu.json : séries valides (hash, forme canonique, chaînage, signature, cohérence) et séries invalides (mêmes erreurs)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": [
      "MN-74"
    ]
  },
  {
    "id": "TV-6",
    "level": "TV",
    "title": "`ct-1/manifestes/` : trois périodes consécutives et un manifeste discontinu",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 P-1",
      "CT-1 P-2",
      "CT-1 P-3",
      "CT-1 P-4",
      "CT-1 P-5"
    ],
    "preconditions": [
      "Vecteurs `ct-1/manifestes` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Recalculer `periodHash`, signatures, `PeriodMeta`, `anchorFingerprint`, continuité ; soumettre le manifeste discontinu."
    ],
    "oracle": "Égalité ; P-5 en échec sur le discontinu.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : manifeste de période",
          "it": "rejoue manifestes/ : periodHash, signatures, PeriodMeta, anchorFingerprint, continuité, manifeste discontinu"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-7",
    "level": "TV",
    "title": "`ct-1/dossiers/` : le dossier valide et chaque dossier invalide, par la bibliothèque et par le vérificateur de CT-6",
    "specs": [
      "CT-1",
      "CT-6"
    ],
    "covers": [
      "CT-1 D-1",
      "CT-1 D-2",
      "CT-1 A-1",
      "CT-1 A-2",
      "CT-1 A-3",
      "CT-1 A-4",
      "CT-1 AT-1",
      "CT-1 AT-2",
      "CT-1 AT-3",
      "CT-1 AT-4",
      "CT-1 AT-5",
      "CT-1 AT-6",
      "CT-1 AT-7",
      "CT-6 V-7",
      "CT-6 EX-6.14",
      "CT-7 EX-A.10",
      "CT-7 EX-A.11",
      "CT-6 EX-4.16",
      "CT-6 EX-5.13",
      "CT-6 EX-5.16",
      "CT-6 EX-5.17",
      "CT-6 EX-5.18",
      "CT-6 EX-5.19"
    ],
    "preconditions": [
      "Vecteurs `ct-1/dossiers` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Vérifier chacun des quatre-vingt-dix-sept dossiers (soixante-dix des versions 0.2 à 0.4 de CT-1, dix-huit de sa révision 0.5 et neuf de ses compléments) par `journal.mjs` puis par le vérificateur de CT-6 (`verifierDossierComplet`, et `scripts/verify/dossier.mjs` pour l'entrée inutilisable `illisible-index-non-json`, code 2), sans ancres et avec `ancres-test.json`.",
      "Les dossiers de la révision 0.5 de CT-1 éprouvent dans le vérificateur de CT-6 les lectures que sa révision 0.4 reprend : codage, profondeur et forme canonique (EX-4.16 : `invalide-marque-ordre-octets`, `invalide-utf8-voisins`, `invalide-profondeur-129`, `valide-profondeur-128`, `invalide-substitut-octets`) ; voisin, `approval` ou `execution.tool` qui n'est pas ce que le schéma attend (EX-5.13 : `invalide-voisin-absent`, `invalide-voisin-nombre`, `invalide-demande-non-objet`, `invalide-approval-nombre`, `invalide-outil-nombre`) ; A-1 à A-3 (EX-5.16 : `invalide-a1-autre-raison`, `invalide-approbations-declaree-manquante`) ; règle exacte de E-3 (EX-5.17 : `invalide-appel-sans-approbation`, `invalide-decision-effets`, `invalide-demande-effets`) ; A-4 (EX-5.18 : `invalide-demande-non-objet`) ; E-5 et E-9 (EX-5.19 : `invalide-signature-en-trop`, `invalide-approval-nombre`)."
    ],
    "oracle": "Contrôles en échec et code de retour égaux à `attendu.json` de chaque dossier ; statuts des AT- égaux à `perimeter_checks` ; pour l'entrée inutilisable, code 2 et `error_kind` égal à l'attendu.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : dossier de preuve",
          "it": "rejoue dossiers/ : le dossier valide et chaque dossier invalide donnent exactement les contrôles attendus"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : compatibilité avec les dossiers de CT-1 (EX-6.14, V-7)",
          "it": "les soixante-dix dossiers (quarante de la version 0.2, dix de la révision 0.3 et vingt de la révision 0.4), sans ancres et avec ancres-test.json : même code et mêmes vérifications en échec ; 4, 5, 8 hors_perimetre_version ; N-3 jamais en échec ; K-1 à K-9 seulement avec la partie points-de-controle.json, AT-1 à AT-7 seulement avec la partie attestation-perimetre.json"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : compatibilité avec les dossiers de CT-1 (EX-6.14, V-7)",
          "it": "révision 0.5 de CT-1 : les dix-huit dossiers nouveaux, mêmes exigences que les soixante-dix (invalide-raison-blancs : contrôle 4 partie_absente, sa raison n'étant pas « hors périmètre CT-1 »)"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : compatibilité avec les dossiers de CT-1 (EX-6.14, V-7)",
          "it": "révision 0.5 de CT-1, compléments : les neuf dossiers des passages tranchés après l'alignement, mêmes exigences ; illisible-index-non-json en code 2 (dossier_illisible)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": [
      "MN-74",
      "MN-79",
      "MN-80",
      "MN-82",
      "MN-84",
      "MN-86",
      "MN-89",
      "MN-90",
      "MN-91"
    ]
  },
  {
    "id": "TV-8",
    "level": "TV",
    "title": "Génération déterministe de `spec/vecteurs/ct-1`",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 §13"
    ],
    "preconditions": [
      "Générateur `scripts/vecteurs/generer-ct1.mjs` au commit éprouvé."
    ],
    "steps": [
      "Régénérer dans un répertoire vide ; comparer fichier par fichier."
    ],
    "oracle": "Mêmes octets que le dépôt, aucun fichier de plus.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : génération déterministe des vecteurs",
          "it": "rejouer scripts/vecteurs/generer-ct1.mjs produit exactement les mêmes fichiers que spec/vecteurs/ct-1"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-9",
    "level": "TV",
    "title": "Vérificateur Go indépendant de CT-1 : zéro discordance sur `spec/vecteurs/ct-1`",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 E-1",
      "CT-1 E-2",
      "CT-1 E-3",
      "CT-1 E-4",
      "CT-1 E-5",
      "CT-1 E-6",
      "CT-1 E-7",
      "CT-1 E-8",
      "CT-1 E-9",
      "CT-1 E-10",
      "CT-1 E-11",
      "CT-1 C-1",
      "CT-1 C-2",
      "CT-1 C-3",
      "CT-1 M-1",
      "CT-1 M-2",
      "CT-1 M-3",
      "CT-1 P-1",
      "CT-1 P-2",
      "CT-1 P-3",
      "CT-1 P-4",
      "CT-1 P-5",
      "CT-1 A-1",
      "CT-1 A-2",
      "CT-1 A-3",
      "CT-1 A-4",
      "CT-1 K-1",
      "CT-1 K-2",
      "CT-1 K-3",
      "CT-1 K-4",
      "CT-1 K-5",
      "CT-1 K-6",
      "CT-1 AT-1",
      "CT-1 AT-2",
      "CT-1 AT-3",
      "CT-1 AT-4",
      "CT-1 AT-5",
      "CT-1 AT-6",
      "CT-1 AT-7"
    ],
    "preconditions": [
      "Go 1.24 (version du `go.mod` du module) ; module `spec/vecteurs/ct-1/verificateur-independant` écrit depuis le seul texte de la spécification, sans lire le code JavaScript."
    ],
    "steps": [
      "`gofmt -l .` vide ; `go vet ./...` ; `go test ./...` ; `go run . ..` depuis le répertoire du module."
    ],
    "oracle": "« 0 discordance » et code 0 ; toute valeur attendue des vecteurs est recalculée et égale.",
    "status": {
      "state": "executable",
      "ci_steps": [
        "clean-room Go verifier against the CT-1 JavaScript vectors"
      ],
      "command": "cd spec/vecteurs/ct-1/verificateur-independant && gofmt -l . && go vet ./... && go test ./... && go run . .."
    },
    "threats": [
      "MN-66"
    ]
  },
  {
    "id": "TV-10",
    "level": "TV",
    "title": "`ct-2/jcs-integral/cas.json`",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-8.1",
      "CT-2 EX-8.2"
    ],
    "preconditions": [
      "Vecteurs `ct-2/jcs-integral` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Canonicaliser chaque cas."
    ],
    "oracle": "Forme canonique égale, ou refus.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : vecteurs spec/vecteurs/ct-2, rejoués",
          "it": "jcs-integral/cas.json : chaque forme canonique, ou le refus"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur.test.js"
    },
    "threats": [
      "MN-4"
    ]
  },
  {
    "id": "TV-11",
    "level": "TV",
    "title": "`ct-2/redaction/` : politiques, motifs, pièces rédigées, idempotence",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-10.1",
      "CT-2 EX-10.2",
      "CT-2 EX-10.3",
      "CT-2 EX-10.4",
      "CT-2 EX-10.5",
      "CT-2 EX-10.6",
      "CT-2 EX-10.7",
      "CT-2 EX-10.8",
      "CT-2 EX-10.9",
      "CT-2 EX-10.10",
      "CT-2 EX-10.11",
      "CT-2 EX-10.12",
      "CT-2 EX-10.13",
      "CT-2 EX-10.14",
      "CT-2 EX-10.15",
      "CT-2 EX-10.16",
      "CT-2 EX-10.17",
      "CT-2 EX-10.18",
      "CT-2 EX-10.19",
      "CT-2 EX-10.20",
      "CT-2 EX-10.21",
      "CT-2 EX-10.22",
      "CT-2 EX-10.23",
      "CT-2 EX-10.24"
    ],
    "preconditions": [
      "Vecteurs `ct-2/redaction` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Rejouer la politique `pii-v1` octet pour octet, chaque pièce rédigée et ses correspondances ; réappliquer la politique à la pièce rédigée."
    ],
    "oracle": "Égalité ; la seconde application ne change aucun octet (CT-2 §10.4, renvoi TC- de la ligne 6880).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : vecteurs spec/vecteurs/ct-2, rejoués",
          "it": "redaction/ : politique pii-v1 octet pour octet, chaque pièce rédigée, ses correspondances, l'idempotence"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-12",
    "level": "TV",
    "title": "`ct-2/pieces-mcp/` : appels relayés ou refusés, agrégation de `tools/list`",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 §4.3",
      "CT-2 §4.4",
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
      "CT-2 EX-4.11",
      "CT-2 EX-4.12",
      "CT-2 EX-4.13",
      "CT-2 EX-4.14",
      "CT-2 EX-4.15",
      "CT-2 EX-4.16",
      "CT-2 EX-4.17",
      "CT-2 EX-4.18",
      "CT-2 EX-4.19",
      "CT-2 EX-4.20",
      "CT-2 EX-4.21",
      "CT-2 EX-4.22",
      "CT-2 EX-4.23",
      "CT-2 EX-4.24",
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
      "CT-2 EX-4.42",
      "CT-2 EX-4.43",
      "CT-2 EX-4.44",
      "CT-2 EX-4.45",
      "CT-2 EX-4.46",
      "CT-2 EX-4.47",
      "CT-2 EX-4.48",
      "CT-2 EX-4.49",
      "CT-2 EX-4.50",
      "CT-2 EX-4.51"
    ],
    "preconditions": [
      "Vecteurs `ct-2/pieces-mcp` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Rejouer chaque cas d'`appels/` (liste servie, refus au pas 1, pièces, contexte, lignes relayées et rendues, durées, erreurs) et d'`agregation/`."
    ],
    "oracle": "Égalité avec `attendu.json` de chaque cas, octets des lignes compris.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : vecteurs spec/vecteurs/ct-2, rejoués",
          "it": "pieces-mcp/appels : liste servie, refus au pas 1, pièces, contexte, lignes relayées et rendues, durées, erreurs"
        },
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : vecteurs spec/vecteurs/ct-2, rejoués",
          "it": "pieces-mcp/agregation : noms annoncés, rejets, classes, empreintes des définitions, pages ; préfixe désactivé"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur.test.js"
    },
    "threats": [
      "MN-7"
    ]
  },
  {
    "id": "TV-13",
    "level": "TV",
    "title": "`ct-2/pieces-modele/` : Anthropic, OpenAI Chat Completions et Responses, Gemini",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 §5.3",
      "CT-2 §5.4",
      "CT-2 EX-5.1",
      "CT-2 EX-5.2",
      "CT-2 EX-5.4",
      "CT-2 EX-5.5",
      "CT-2 EX-5.6",
      "CT-2 EX-5.7",
      "CT-2 EX-5.9",
      "CT-2 EX-5.10",
      "CT-2 EX-5.11",
      "CT-2 EX-5.12",
      "CT-2 EX-5.13",
      "CT-2 EX-5.14",
      "CT-2 EX-5.15",
      "CT-2 EX-5.16",
      "CT-2 EX-5.17",
      "CT-2 EX-5.18",
      "CT-2 EX-5.19",
      "CT-2 EX-5.20",
      "CT-2 EX-5.21",
      "CT-2 EX-5.22",
      "CT-2 EX-5.23",
      "CT-2 EX-5.24",
      "CT-2 EX-5.25",
      "CT-2 EX-5.26",
      "CT-2 EX-5.27",
      "CT-2 EX-5.28",
      "CT-2 EX-5.29",
      "CT-2 EX-5.30",
      "CT-2 EX-5.31",
      "CT-2 EX-5.32",
      "CT-2 EX-5.33",
      "CT-2 EX-5.34",
      "CT-2 EX-5.35",
      "CT-2 EX-5.36"
    ],
    "preconditions": [
      "Vecteurs `ct-2/pieces-modele` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Rejouer chaque cas : forme consolidée, pièces, `code.model`, `prompt_version`, intention, appels d'outils, refus ; les 30 cas `gemini-*`."
    ],
    "oracle": "Égalité avec `attendu.json`.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : vecteurs spec/vecteurs/ct-2, rejoués",
          "it": "pieces-modele : formes consolidées, pièces, code.model, prompt_version, intention, appels d'outils, refus"
        },
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : Gemini à la passerelle et format gemini du SDK (EX-5.28 à EX-5.36, EX-6.8)",
          "it": "pieces-modele/gemini-* : les 30 cas de l'annexe B.5 rejoués (route, segment, refus et corps exact, cible amont, pièces, forme consolidée, code.model, intent, appels)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur.test.js"
    },
    "threats": [
      "MN-11",
      "MN-13"
    ]
  },
  {
    "id": "TV-14",
    "level": "TV",
    "title": "`ct-2/otel/` : 48 cas d'ingestion OTLP en JSON et en protobuf",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-6.25",
      "CT-2 EX-6.26",
      "CT-2 EX-6.27",
      "CT-2 EX-6.28",
      "CT-2 EX-6.29",
      "CT-2 EX-6.30",
      "CT-2 EX-6.31",
      "CT-2 EX-6.32",
      "CT-2 EX-6.33",
      "CT-2 EX-6.34",
      "CT-2 EX-6.35",
      "CT-2 EX-6.36",
      "CT-2 EX-6.37",
      "CT-2 EX-6.38",
      "CT-2 EX-6.39",
      "CT-2 EX-6.40",
      "CT-2 EX-6.41"
    ],
    "preconditions": [
      "Vecteurs `ct-2/otel` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Rejouer chaque cas : statut, réponse, `issues`, formes normalisées, pièces, événements, chaîne, E-1 à E-11, `lag_ms` ; paires JSON/protobuf."
    ],
    "oracle": "Égalité octet pour octet des réponses et des formes.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : ingestion OpenTelemetry (6.8, EX-6.25 à EX-6.41)",
          "it": "otel/ : les 48 cas de l'annexe B.8 rejoués (statut, réponse octet pour octet, issues, formes normalisées, pièces, événements, chaîne, E-1 à E-11, lag_ms)"
        },
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : ingestion OpenTelemetry (6.8, EX-6.25 à EX-6.41)",
          "it": "paires JSON / protobuf : mêmes formes normalisées, pièces et événements ; l'encodeur redonne les octets de requete.pb"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur-r05.test.js"
    },
    "threats": [
      "MN-15",
      "MN-16"
    ]
  },
  {
    "id": "TV-15",
    "level": "TV",
    "title": "`ct-2/worm/` : requêtes, états, périmètres, gardes, levées",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-12.29",
      "CT-2 EX-12.30",
      "CT-2 EX-12.31",
      "CT-2 EX-12.32",
      "CT-2 EX-12.33",
      "CT-2 EX-12.34",
      "CT-2 EX-12.35",
      "CT-2 EX-12.36",
      "CT-2 EX-12.37",
      "CT-2 EX-12.38",
      "CT-2 EX-12.39",
      "CT-2 EX-12.40",
      "CT-2 EX-12.41"
    ],
    "preconditions": [
      "Vecteurs `ct-2/worm` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Valider chaque fichier contre `worm-v0` ; rejouer chaque cas par `worm.mjs`."
    ],
    "oracle": "Égalité.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : copies WORM et gel juridique (12.6, 12.11, EX-12.29 à EX-12.41)",
          "it": "worm/*.json : chaque fichier valide contre worm-v0, chaque cas rejoué par worm.mjs à l'identique"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur-r05.test.js"
    },
    "threats": [
      "MN-27",
      "MN-28"
    ]
  },
  {
    "id": "TV-16",
    "level": "TV",
    "title": "`ct-2/cout-agent/cas.json` : neuf cas de la formule",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-16.4",
      "CT-2 EX-16.5",
      "CT-2 EX-16.6"
    ],
    "preconditions": [
      "Vecteurs `ct-2/cout-agent` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Valider contre `cout-agent-v0` ; rejouer les neuf cas ; relire `C_anc` dans les vecteurs de CT-5."
    ],
    "oracle": "Égalité ; aucun prix réel.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : coût annuel par agent (16.4, EX-16.4 à EX-16.6)",
          "it": "cout-agent/cas.json : valide contre cout-agent-v0, neuf cas rejoués à l'identique ; C_anc relu dans les vecteurs de CT-5"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur-r05.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-17",
    "level": "TV",
    "title": "`ct-2/evenements/journal-demo/` : chaîne, pièces, politique, intention, segment, dossier de seq 7",
    "specs": [
      "CT-2",
      "CT-1"
    ],
    "covers": [
      "CT-2 EX-7.1",
      "CT-2 EX-7.2",
      "CT-2 EX-7.3",
      "CT-2 EX-7.4",
      "CT-2 EX-7.5",
      "CT-2 EX-7.6",
      "CT-2 EX-7.7",
      "CT-2 EX-7.8",
      "CT-2 EX-7.9",
      "CT-2 EX-7.13",
      "CT-2 EX-7.10",
      "CT-2 EX-7.11",
      "CT-2 EX-7.12",
      "CT-2 EX-9.1",
      "CT-2 EX-9.2",
      "CT-2 EX-9.8",
      "CT-2 EX-9.3",
      "CT-2 EX-9.4",
      "CT-2 EX-9.5",
      "CT-2 EX-9.6",
      "CT-2 EX-9.7",
      "CT-2 EX-12.1",
      "CT-2 EX-12.2",
      "CT-2 EX-12.3",
      "CT-1 E-1",
      "CT-1 E-2",
      "CT-1 E-3",
      "CT-1 E-4",
      "CT-1 E-5",
      "CT-1 E-6",
      "CT-1 E-7",
      "CT-1 E-8",
      "CT-1 E-9",
      "CT-1 E-10",
      "CT-1 E-11"
    ],
    "preconditions": [
      "Vecteurs `ct-2/evenements` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Rejouer la courte exécution de la démonstration avec les clés de test de CT-1 ; vérifier `dossier-seq-7` par `verifierDossier` et par `scripts/verify/dossier.mjs`."
    ],
    "oracle": "Chaîne, attendus, pièces, segment et intentions égaux ; dossier valide, code 0.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : vecteurs spec/vecteurs/ct-2, rejoués",
          "it": "evenements/journal-demo : chaîne, attendus, pièces, politique, intention, segment ; arguments de seq 7 = pieces-mcp"
        },
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : vecteurs spec/vecteurs/ct-2, rejoués",
          "it": "evenements/journal-demo/dossier-seq-7 : dossier CT-1 valide par verifierDossier et par scripts/verify/dossier.mjs (code 0)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur.test.js"
    },
    "threats": [
      "MN-23"
    ]
  },
  {
    "id": "TV-18",
    "level": "TV",
    "title": "Génération déterministe de `spec/vecteurs/ct-2`",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 §B"
    ],
    "preconditions": [
      "Générateur `scripts/vecteurs/generer-ct2.mjs` au commit éprouvé."
    ],
    "steps": [
      "Régénérer ; comparer."
    ],
    "oracle": "Mêmes fichiers, mêmes octets.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : vecteurs spec/vecteurs/ct-2, rejoués",
          "it": "rejouer scripts/vecteurs/generer-ct2.mjs produit exactement les mêmes fichiers que spec/vecteurs/ct-2"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-19",
    "level": "TV",
    "title": "Vérificateur Go indépendant de CT-2 : zéro discordance sur `spec/vecteurs/ct-2`",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-8.1",
      "CT-2 EX-8.2",
      "CT-2 EX-8.3",
      "CT-2 EX-8.4",
      "CT-2 EX-8.5",
      "CT-2 EX-8.6",
      "CT-2 EX-8.7",
      "CT-2 EX-8.8",
      "CT-2 EX-8.9",
      "CT-2 EX-8.10",
      "CT-2 EX-8.11",
      "CT-2 EX-6.25",
      "CT-2 EX-6.26",
      "CT-2 EX-6.27",
      "CT-2 EX-6.28",
      "CT-2 EX-6.29",
      "CT-2 EX-6.30",
      "CT-2 EX-6.31",
      "CT-2 EX-6.32",
      "CT-2 EX-6.33",
      "CT-2 EX-6.34",
      "CT-2 EX-6.35",
      "CT-2 EX-6.36",
      "CT-2 EX-6.37",
      "CT-2 EX-6.38",
      "CT-2 EX-6.39",
      "CT-2 EX-6.40",
      "CT-2 EX-6.41",
      "CT-2 EX-12.29",
      "CT-2 EX-12.30",
      "CT-2 EX-12.31",
      "CT-2 EX-12.32",
      "CT-2 EX-12.33",
      "CT-2 EX-12.34",
      "CT-2 EX-12.35",
      "CT-2 EX-12.36",
      "CT-2 EX-12.37",
      "CT-2 EX-12.38",
      "CT-2 EX-12.39",
      "CT-2 EX-12.40",
      "CT-2 EX-12.41",
      "CT-2 EX-16.4",
      "CT-2 EX-16.5",
      "CT-2 EX-16.6",
      "CT-2 EX-4.20"
    ],
    "preconditions": [
      "Go 1.24 (version du `go.mod` du module) ; module `spec/vecteurs/ct-2/verificateur-independant` écrit depuis le seul texte de la spécification, sans lire le code JavaScript."
    ],
    "steps": [
      "`gofmt -l .` vide ; `go vet ./...` ; `go test ./...` ; `go run . ..` depuis le répertoire du module."
    ],
    "oracle": "« 0 discordance » et code 0 ; toute valeur attendue des vecteurs est recalculée et égale.",
    "status": {
      "state": "executable",
      "ci_steps": [
        "clean-room Go verifier against the CT-2 JavaScript vectors"
      ],
      "command": "cd spec/vecteurs/ct-2/verificateur-independant && gofmt -l . && go vet ./... && go test ./... && go run . .."
    },
    "threats": [
      "MN-66"
    ]
  },
  {
    "id": "TV-20",
    "level": "TV",
    "title": "Confrontation tierce de `ct-2` : google-genai 2.33.0 et opentelemetry-proto 1.45.1",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 §B.5",
      "CT-2 §B.8",
      "CT-2 EX-6.29",
      "CT-2 EX-6.30"
    ],
    "preconditions": [
      "Sorties publiées sous `spec/vecteurs/ct-2/confrontation/sorties/` ; interpréteur Python aux versions d'`exigences.txt` pour le rejeu (sinon le rejeu est en attente, R10-F30)."
    ],
    "steps": [
      "Vérifier que les sorties portent sur les vecteurs du dépôt (SHA-256) ; rejouer les programmes quand l'interpréteur est présent."
    ],
    "oracle": "Aucune discordance ; sortie égale à la sortie publiée.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/confrontation.test.js",
          "describe": "CT-2 : sorties publiées de la confrontation par des outils tiers (annexes B.5 et B.8)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/confrontation.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-21",
    "level": "TV",
    "title": "`ct-3/politiques/`, `politiques-invalides/`, `evaluation/`, `candidats/` : AP-1 à AP-17",
    "specs": [
      "CT-3"
    ],
    "covers": [
      "CT-3 AP-1",
      "CT-3 AP-2",
      "CT-3 AP-3",
      "CT-3 AP-4",
      "CT-3 AP-5",
      "CT-3 AP-6",
      "CT-3 AP-7",
      "CT-3 AP-8",
      "CT-3 AP-9",
      "CT-3 AP-10",
      "CT-3 AP-11",
      "CT-3 AP-12",
      "CT-3 AP-13",
      "CT-3 AP-14",
      "CT-3 AP-15",
      "CT-3 AP-16",
      "CT-3 AP-17",
      "CT-3 EX-A.1",
      "CT-3 EX-A.2",
      "CT-3 EX-A.3"
    ],
    "preconditions": [
      "Vecteurs `ct-3/politiques, evaluation, candidats` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Valider chaque politique ; refuser chaque politique invalide avec la liste complète triée ; évaluer chaque cas ; calculer les candidats."
    ],
    "oracle": "Listes d'erreurs, `rule`, `decision`, `opening`, fenêtres et candidats égaux aux attendus.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : validation de la politique (EX-4.2, EX-8.2, AP-1 à AP-4)",
          "it": "politiques-invalides : chaque document donne exactement la liste complète attendue, triée"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : validation de la politique (EX-4.2, EX-8.2, AP-1 à AP-4)",
          "it": "politiques/ : chaque politique valide passe, schéma et règles d'EX-4.2 ; substitut isolé lu tel quel"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : évaluation (sections 4 à 6, AP-5 à AP-17)",
          "it": "evaluation/ : chaque cas rend exactement rule, decision, opening et l'état des fenêtres attendus"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : outils susceptibles d'approbation (EX-4.11, AP-16)",
          "it": "candidats/ : CANDIDATS(P, L) rend la liste attendue"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/approbation.test.js"
    },
    "threats": [
      "MN-3"
    ]
  },
  {
    "id": "TV-22",
    "level": "TV",
    "title": "`ct-3/acceptation/` rejoué par l'implémentation de référence : dix décisions, matériel sans attendu (CT-3 EX-A.4, EX-A.5)",
    "specs": [
      "CT-3"
    ],
    "covers": [
      "CT-3 EX-A.4",
      "CT-3 EX-A.5"
    ],
    "preconditions": [
      "Vecteurs `ct-3/acceptation` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Vérifier que le répertoire remis ne contient aucun attendu ; évaluer les dix cas avec `politique.json`."
    ],
    "oracle": "Les dix décisions égales à `acceptation-attendu.json` ; les contraintes d'EX-A.4 tenues. L'épreuve humaine des trois relecteurs est un TR-.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : épreuve d'acceptation (annexe A.5, EX-A.4, EX-A.5)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/approbation.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-23",
    "level": "TV",
    "title": "`ct-3/tickets/` : traces de cycle de vie, TK-1 à TK-13",
    "specs": [
      "CT-3"
    ],
    "covers": [
      "CT-3 TK-1",
      "CT-3 TK-2",
      "CT-3 TK-3",
      "CT-3 TK-4",
      "CT-3 TK-5",
      "CT-3 TK-6",
      "CT-3 TK-7",
      "CT-3 TK-8",
      "CT-3 TK-9",
      "CT-3 TK-10",
      "CT-3 TK-11",
      "CT-3 TK-12",
      "CT-3 TK-13",
      "CT-3 EX-A.6",
      "CT-3 EX-A.7"
    ],
    "preconditions": [
      "Vecteurs `ct-3/tickets` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Rejouer chaque trace sur un service vide, pas à pas ; reprendre depuis l'état persisté après chaque pas."
    ],
    "oracle": "Chaque attendu de la trace ; mêmes sorties après reprise ; TK-1 à TK-13 tous visés.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : tickets (section 7, TK-1 à TK-13)",
          "it": "les traces de l'annexe A.7 sont présentes, conformes à $defs/trace, et TK-1 à TK-13 sont tous visés"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : tickets (section 7, TK-1 à TK-13)",
          "it": "chaque trace rejouée sur un service vide redonne chaque attendu, pas à pas (EX-7.9, EX-A.6)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/approbation.test.js"
    },
    "threats": [
      "MN-5",
      "MN-6",
      "MN-38",
      "MN-50"
    ]
  },
  {
    "id": "TV-24",
    "level": "TV",
    "title": "`ct-3/decisions/` et `ct-3/signatures/normalisation.json` : remises acceptées et refusées, SG-1 à SG-7",
    "specs": [
      "CT-3"
    ],
    "covers": [
      "CT-3 SG-1",
      "CT-3 SG-2",
      "CT-3 SG-3",
      "CT-3 SG-4",
      "CT-3 SG-5",
      "CT-3 SG-6",
      "CT-3 SG-7",
      "CT-3 EX-A.8",
      "CT-3 EX-9.3"
    ],
    "preconditions": [
      "Vecteurs `ct-3/decisions, signatures` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Soumettre chaque remise au noyau ; normaliser chaque forme de signature."
    ],
    "oracle": "Résultat et raison attendus dans l'ordre de SG-1 à SG-7 ; même adresse recouvrée.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : remises et signatures (section 9, SG-1 à SG-7, annexe A.7 et A.8)",
          "it": "decisions/ : chaque remise reçoit le résultat et la raison attendus, dans l'ordre de SG-1 à SG-7"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : remises et signatures (section 9, SG-1 à SG-7, annexe A.7 et A.8)",
          "it": "A.8 : normalisation d'EX-9.3 ; chaque forme normalisée recouvre la même adresse que la forme d'entrée"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/approbation.test.js"
    },
    "threats": [
      "MN-44",
      "MN-48",
      "MN-49"
    ]
  },
  {
    "id": "TV-25",
    "level": "TV",
    "title": "`ct-3/annuaire/` : annuaires, messages, inscriptions, domaines, traces, contrôles, exports (AN-1 à AN-10)",
    "specs": [
      "CT-3"
    ],
    "covers": [
      "CT-3 AN-1",
      "CT-3 AN-2",
      "CT-3 AN-3",
      "CT-3 AN-4",
      "CT-3 AN-5",
      "CT-3 AN-6",
      "CT-3 AN-7",
      "CT-3 AN-8",
      "CT-3 AN-9",
      "CT-3 AN-10",
      "CT-3 EX-A.12",
      "CT-3 EX-A.13",
      "CT-3 EX-A.14",
      "CT-3 EX-A.15",
      "CT-3 EX-A.16"
    ],
    "preconditions": [
      "Vecteurs `ct-3/annuaire` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Rejouer chaque fichier par `console.mjs`."
    ],
    "oracle": "Sort, raison, réponse, `revision`, état résumé, écarts d'export égaux aux attendus.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/console.test.js",
          "describe": "CT-3 0.3 : annuaire/ rejoué par console.mjs (AN-1 à AN-10)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/console.test.js"
    },
    "threats": [
      "MN-47"
    ]
  },
  {
    "id": "TV-26",
    "level": "TV",
    "title": "`ct-3/console/` : modèles, requêtes, réponses, découverte, fichiers de clé (CS-1 à CS-9) ; matériel de l'épreuve de lecture",
    "specs": [
      "CT-3"
    ],
    "covers": [
      "CT-3 CS-1",
      "CT-3 CS-2",
      "CT-3 CS-3",
      "CT-3 CS-4",
      "CT-3 CS-5",
      "CT-3 CS-6",
      "CT-3 CS-7",
      "CT-3 CS-8",
      "CT-3 CS-9",
      "CT-3 EX-A.17"
    ],
    "preconditions": [
      "Vecteurs `ct-3/console` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Rejouer chaque cas par `console.mjs` ; vérifier que le répertoire de l'épreuve de lecture ne contient que la consigne et le gabarit et que la grille cite des règles de CT-3."
    ],
    "oracle": "Égalité avec les attendus ; grille à part. L'épreuve humaine est un TR-.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/console.test.js",
          "describe": "CT-3 0.3 : console/ rejoué par console.mjs (CS-1 à CS-9)"
        },
        {
          "file": "test/console.test.js",
          "describe": "CT-3 0.3 : vecteurs annuaire/ et console/ (EX-A.12 à EX-A.17)",
          "it": "EX-A.17 : le répertoire remis aux lecteurs ne contient que la consigne et le gabarit ; la grille cite des règles de CT-3 et couvre chaque question"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/console.test.js"
    },
    "threats": [
      "MN-45",
      "MN-46"
    ]
  },
  {
    "id": "TV-27",
    "level": "TV",
    "title": "Génération déterministe de `spec/vecteurs/ct-3`",
    "specs": [
      "CT-3"
    ],
    "covers": [
      "CT-3 EX-A.1",
      "CT-3 EX-A.2",
      "CT-3 EX-A.3",
      "CT-3 EX-A.11"
    ],
    "preconditions": [
      "Générateur `scripts/vecteurs/generer-ct3.mjs` au commit éprouvé."
    ],
    "steps": [
      "Deux générations dans des répertoires vides ; comparaison au dépôt."
    ],
    "oracle": "Mêmes octets ; `verificateur-independant/` et `confrontation/` jamais écrits.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : génération déterministe des vecteurs (EX-A.1, EX-A.2, EX-A.3)"
        },
        {
          "file": "test/console.test.js",
          "describe": "CT-3 0.3 : vecteurs annuaire/ et console/ (EX-A.12 à EX-A.17)",
          "it": "régénérés dans un répertoire temporaire : mêmes octets que spec/vecteurs/ct-3 pour annuaire/, console/ et l'épreuve de lecture ; deux générations identiques"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/approbation.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-28",
    "level": "TV",
    "title": "Vérificateur Go indépendant de CT-3 : zéro discordance sur `spec/vecteurs/ct-3`",
    "specs": [
      "CT-3"
    ],
    "covers": [
      "CT-3 EX-A.10",
      "CT-3 AP-1",
      "CT-3 AP-2",
      "CT-3 AP-3",
      "CT-3 AP-4",
      "CT-3 AP-5",
      "CT-3 AP-6",
      "CT-3 AP-7",
      "CT-3 AP-8",
      "CT-3 AP-9",
      "CT-3 AP-10",
      "CT-3 AP-11",
      "CT-3 AP-12",
      "CT-3 AP-13",
      "CT-3 AP-14",
      "CT-3 AP-15",
      "CT-3 AP-16",
      "CT-3 AP-17",
      "CT-3 TK-1",
      "CT-3 TK-2",
      "CT-3 TK-3",
      "CT-3 TK-4",
      "CT-3 TK-5",
      "CT-3 TK-6",
      "CT-3 TK-7",
      "CT-3 TK-8",
      "CT-3 TK-9",
      "CT-3 TK-10",
      "CT-3 TK-11",
      "CT-3 TK-12",
      "CT-3 TK-13",
      "CT-3 SG-1",
      "CT-3 SG-2",
      "CT-3 SG-3",
      "CT-3 SG-4",
      "CT-3 SG-5",
      "CT-3 SG-6",
      "CT-3 SG-7",
      "CT-3 AN-1",
      "CT-3 AN-2",
      "CT-3 AN-3",
      "CT-3 AN-4",
      "CT-3 AN-5",
      "CT-3 AN-6",
      "CT-3 AN-7",
      "CT-3 AN-8",
      "CT-3 AN-9",
      "CT-3 AN-10",
      "CT-3 CS-1",
      "CT-3 CS-2",
      "CT-3 CS-3",
      "CT-3 CS-4",
      "CT-3 CS-5",
      "CT-3 CS-6",
      "CT-3 CS-7",
      "CT-3 CS-8",
      "CT-3 CS-9",
      "CT-3 EX-A.9"
    ],
    "preconditions": [
      "Go 1.24 (version du `go.mod` du module) ; module `spec/vecteurs/ct-3/verificateur-independant` écrit depuis le seul texte de la spécification, sans lire le code JavaScript."
    ],
    "steps": [
      "`gofmt -l .` vide ; `go vet ./...` ; `go test ./...` ; `go run . ..` depuis le répertoire du module."
    ],
    "oracle": "« 0 discordance » et code 0 ; toute valeur attendue des vecteurs est recalculée et égale.",
    "status": {
      "state": "executable",
      "ci_steps": [
        "vérificateur Go indépendant contre les vecteurs CT-3"
      ],
      "command": "cd spec/vecteurs/ct-3/verificateur-independant && gofmt -l . && go vet ./... && go test ./... && go run . .."
    },
    "threats": [
      "MN-66"
    ]
  },
  {
    "id": "TV-29",
    "level": "TV",
    "title": "Confrontation tierce de `ct-3` : signatures par ethers 6 et eth-account 0.14.0",
    "specs": [
      "CT-3"
    ],
    "covers": [
      "CT-3 EX-A.18",
      "CT-3 EX-A.19",
      "CT-3 EX-9.22"
    ],
    "preconditions": [
      "Sorties publiées sous `spec/vecteurs/ct-3/confrontation/sorties/`."
    ],
    "steps": [
      "Vérifier que les sorties portent sur les vecteurs ; rejouer `confronter_ethers.mjs` ; rejouer `confronter_eth_account.py` si l'interpréteur est présent."
    ],
    "oracle": "Aucune discordance hors des écarts inscrits d'EX-9.22.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/confrontation.test.js",
          "describe": "CT-3 : sorties publiées de la confrontation des signatures par des outils tiers (EX-A.18)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/confrontation.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-30",
    "level": "TV",
    "title": "`ct-4/identifiants.json`, `doctypes.json`, `empreintes.json` : RG-1 à RG-4",
    "specs": [
      "CT-4"
    ],
    "covers": [
      "CT-4 RG-1",
      "CT-4 RG-2",
      "CT-4 RG-3",
      "CT-4 RG-4"
    ],
    "preconditions": [
      "Vecteurs `ct-4` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Rejouer chaque cas admis et refusé."
    ],
    "oracle": "`org_id`, `journal_id`, `docType`, empreinte, ou `echoue`.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — vecteurs spec/vecteurs/ct-4",
          "it": "identifiants, doctypes et empreintes : RG-1 à RG-4 rejoués"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/registreCt4.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-31",
    "level": "TV",
    "title": "`ct-4/condenses.json` : RG-5 à RG-13",
    "specs": [
      "CT-4"
    ],
    "covers": [
      "CT-4 RG-5",
      "CT-4 RG-6",
      "CT-4 RG-7",
      "CT-4 RG-8",
      "CT-4 RG-9",
      "CT-4 RG-10",
      "CT-4 RG-11",
      "CT-4 RG-12",
      "CT-4 RG-13"
    ],
    "preconditions": [
      "Vecteurs `ct-4/condenses` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Recalculer les six condensés, le hachage signé, les signatures ; soumettre les signatures refusées."
    ],
    "oracle": "Égalité ; préimages aux longueurs de 6.6.2.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — vecteurs spec/vecteurs/ct-4",
          "it": "condenses : RG-5 à RG-13 rejoués, préimages aux longueurs de 6.6.2"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/registreCt4.test.js"
    },
    "threats": [
      "MN-57"
    ]
  },
  {
    "id": "TV-32",
    "level": "TV",
    "title": "`ct-4/appels.json` et `transactions.json` : RG-14, RG-15, confrontation à ethers et à la capture",
    "specs": [
      "CT-4"
    ],
    "covers": [
      "CT-4 RG-14",
      "CT-4 RG-15",
      "CT-4 EX-A.4"
    ],
    "preconditions": [
      "Vecteurs `ct-4/appels, transactions` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Recalculer les données d'appel et les transactions brutes ; comparer à l'encodeur d'ethers et aux transactions réelles de la capture de CT-6."
    ],
    "oracle": "Mêmes octets, même hachage que le reçu ; RG-15 `echoue` sur les seuls champs de frais.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — vecteurs spec/vecteurs/ct-4",
          "it": "appels : RG-14 rejoué et confronté à l'encodeur d'ethers (ABI de compilation) et aux transactions réelles de la capture"
        },
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — vecteurs spec/vecteurs/ct-4",
          "it": "transactions : RG-15 rejoué ; sérialisation confrontée à ethers ; transactions de la capture redonnées octet pour octet (EX-A.4)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/registreCt4.test.js"
    },
    "threats": [
      "MN-72"
    ]
  },
  {
    "id": "TV-33",
    "level": "TV",
    "title": "`ct-4/manifestes/` : RG-16 à RG-20, ancre `registry` dérivée",
    "specs": [
      "CT-4"
    ],
    "covers": [
      "CT-4 RG-16",
      "CT-4 RG-17",
      "CT-4 RG-18",
      "CT-4 RG-19",
      "CT-4 RG-20"
    ],
    "preconditions": [
      "Vecteurs `ct-4/manifestes` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Vérifier chaque manifeste valide et refusé ; dériver l'ancre ; vérifier les preuves de déploiement synthétiques."
    ],
    "oracle": "Verdict RG- et ancre égaux à `manifestes.json`.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — vecteurs spec/vecteurs/ct-4",
          "it": "manifestes : RG-16 à RG-20 rejoués, ancre registry dérivée ; preuves de déploiement synthétiques vérifiées"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/registreCt4.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-34",
    "level": "TV",
    "title": "`ct-4/demandes/` et `ct-4/inscription/` : schéma, OP-4, OP-6, OP-7",
    "specs": [
      "CT-4"
    ],
    "covers": [
      "CT-4 OP-4",
      "CT-4 OP-6",
      "CT-4 OP-7"
    ],
    "preconditions": [
      "Vecteurs `ct-4/demandes, inscription` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Vérifier chaque demande et chaque dossier."
    ],
    "oracle": "`valide` ou refus nommé, égal aux fichiers de verdict.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — vecteurs spec/vecteurs/ct-4",
          "it": "demandes et dossiers : schéma, OP-4, OP-6 et OP-7 rejoués"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/registreCt4.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-35",
    "level": "TV",
    "title": "`ct-4/capture/` : CP-2 à CP-6, export des parties",
    "specs": [
      "CT-4",
      "CT-6"
    ],
    "covers": [
      "CT-4 CP-2",
      "CT-4 CP-3",
      "CT-4 CP-4",
      "CT-4 CP-5",
      "CT-4 CP-6",
      "CT-4 EX-9.8",
      "CT-4 EX-9.9",
      "CT-4 EX-9.10"
    ],
    "preconditions": [
      "Vecteurs `ct-4/capture` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Rejouer les variantes ; exporter les parties de la période 1."
    ],
    "oracle": "Verdicts CP- égaux ; export égal à `spec/vecteurs/ct-6/registre/periode-1`.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — vecteurs spec/vecteurs/ct-4",
          "it": "capture : CP-2 à CP-6 rejoués ; export des parties égal à spec/vecteurs/ct-6/registre/periode-1 (EX-9.8 à EX-9.10)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/registreCt4.test.js"
    },
    "threats": [
      "MN-56"
    ]
  },
  {
    "id": "TV-36",
    "level": "TV",
    "title": "Complétude des familles de `ct-4` : chaque RG-, OP- hors ligne et CP- a un cas réussi et un cas en échec ; exemples annotés",
    "specs": [
      "CT-4"
    ],
    "covers": [
      "CT-4 EX-A.3",
      "CT-4 RG-1",
      "CT-4 RG-2",
      "CT-4 RG-3",
      "CT-4 RG-4",
      "CT-4 RG-5",
      "CT-4 RG-6",
      "CT-4 RG-7",
      "CT-4 RG-8",
      "CT-4 RG-9",
      "CT-4 RG-10",
      "CT-4 RG-11",
      "CT-4 RG-12",
      "CT-4 RG-13",
      "CT-4 RG-14",
      "CT-4 RG-15",
      "CT-4 RG-16",
      "CT-4 RG-17",
      "CT-4 RG-18",
      "CT-4 RG-19",
      "CT-4 RG-20"
    ],
    "preconditions": [
      "Vecteurs `ct-4` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Lire chaque fichier de famille ; compter les cas par vérification ; valider les exemples annotés."
    ],
    "oracle": "Au moins un cas réussi et un en échec par vérification ; exemples de 7.7, 7.10 et 9.4 présents dans les vecteurs.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — vecteurs spec/vecteurs/ct-4",
          "it": "chaque fichier de famille est conforme à fichier_vecteurs et chaque RG-, OP- hors ligne et CP- a un cas réussi et un cas en échec (EX-A.3)"
        },
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — vecteurs spec/vecteurs/ct-4",
          "it": "les exemples annotés de CT-4 sont conformes à leurs schémas ; ceux de 7.7, 7.10 et 9.4 sont dans les vecteurs"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/registreCt4.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-37",
    "level": "TV",
    "title": "Génération déterministe de `spec/vecteurs/ct-4`",
    "specs": [
      "CT-4"
    ],
    "covers": [
      "CT-4 EX-A.1",
      "CT-4 EX-A.2",
      "CT-4 EX-A.7"
    ],
    "preconditions": [
      "Générateur `scripts/vecteurs/generer-ct4.mjs` au commit éprouvé."
    ],
    "steps": [
      "Régénérer dans un répertoire temporaire ; refuser une racine étrangère."
    ],
    "oracle": "Mêmes octets ; `verificateur-independant/` jamais effacé.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — vecteurs spec/vecteurs/ct-4",
          "it": "la régénération dans un répertoire temporaire redonne les mêmes octets (EX-A.1)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/registreCt4.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-38",
    "level": "TV",
    "title": "Vérificateur Go indépendant de CT-4 : zéro discordance sur `spec/vecteurs/ct-4`",
    "specs": [
      "CT-4"
    ],
    "covers": [
      "CT-4 RG-1",
      "CT-4 RG-2",
      "CT-4 RG-3",
      "CT-4 RG-4",
      "CT-4 RG-5",
      "CT-4 RG-6",
      "CT-4 RG-7",
      "CT-4 RG-8",
      "CT-4 RG-9",
      "CT-4 RG-10",
      "CT-4 RG-11",
      "CT-4 RG-12",
      "CT-4 RG-13",
      "CT-4 RG-14",
      "CT-4 RG-15",
      "CT-4 RG-16",
      "CT-4 RG-17",
      "CT-4 RG-18",
      "CT-4 RG-19",
      "CT-4 RG-20",
      "CT-4 CP-1",
      "CT-4 CP-2",
      "CT-4 CP-3",
      "CT-4 CP-4",
      "CT-4 CP-5",
      "CT-4 CP-6",
      "CT-4 OP-4",
      "CT-4 OP-6",
      "CT-4 OP-7",
      "CT-4 EX-A.5"
    ],
    "preconditions": [
      "Go 1.24 (version du `go.mod` du module) ; module `spec/vecteurs/ct-4/verificateur-independant` écrit depuis le seul texte de la spécification, sans lire le code JavaScript."
    ],
    "steps": [
      "`gofmt -l .` vide ; `go vet ./...` ; `go test ./...` ; `go run . ..` depuis le répertoire du module."
    ],
    "oracle": "« 0 discordance » et code 0 ; toute valeur attendue des vecteurs est recalculée et égale.",
    "status": {
      "state": "executable",
      "ci_steps": [
        "vérificateur Go indépendant contre les vecteurs CT-4"
      ],
      "command": "cd spec/vecteurs/ct-4/verificateur-independant && gofmt -l . && go vet ./... && go test ./... && go run . .."
    },
    "threats": [
      "MN-66"
    ]
  },
  {
    "id": "TV-39",
    "level": "TV",
    "title": "`ct-5/requetes/` : `TimeStampReq` DER exacte, nonce, refus",
    "specs": [
      "CT-5"
    ],
    "covers": [
      "CT-5 EX-5.1",
      "CT-5 EX-5.3",
      "CT-5 AN-5",
      "CT-5 AN-6"
    ],
    "preconditions": [
      "Vecteurs `ct-5/requetes` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Reconstruire chaque requête depuis l'empreinte, l'étiquette du nonce et la politique ; relire ; rejouer `refusees.json`."
    ],
    "oracle": "Octets égaux ; chaque refus avec la règle et le message publiés.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : famille requetes (EX-5.1, EX-5.3, AN-5, AN-6)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/ancrage.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-40",
    "level": "TV",
    "title": "`ct-5/reponses/` : classement des réponses de l'autorité de test",
    "specs": [
      "CT-5"
    ],
    "covers": [
      "CT-5 EX-5.10",
      "CT-5 EX-5.11",
      "CT-5 EX-5.12",
      "CT-5 EX-5.13",
      "CT-5 EX-8.9",
      "CT-5 AN-8",
      "CT-5 AN-9",
      "CT-5 AN-10",
      "CT-5 AN-11"
    ],
    "preconditions": [
      "Vecteurs `ct-5/reponses` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Classer chaque réponse : `issue`, code, classe, avertissements, champs du TSTInfo, jeton extrait, attente de reprise."
    ],
    "oracle": "Égalité avec `reponses.json`.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : famille reponses (EX-5.10 à EX-5.12, EX-8.9, AN-8 à AN-11)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/ancrage.test.js"
    },
    "threats": [
      "MN-60",
      "MN-76"
    ]
  },
  {
    "id": "TV-41",
    "level": "TV",
    "title": "`ct-5/ots/` : fichiers `.ots` reconstruits, mise à niveau",
    "specs": [
      "CT-5"
    ],
    "covers": [
      "CT-5 EX-6.2",
      "CT-5 EX-6.3",
      "CT-5 EX-6.4",
      "CT-5 EX-6.5",
      "CT-5 EX-6.6",
      "CT-5 EX-6.7",
      "CT-5 EX-8.11",
      "CT-5 AN-16",
      "CT-5 AN-17",
      "CT-5 AN-18",
      "CT-5 AN-19"
    ],
    "preconditions": [
      "Vecteurs `ct-5/ots` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Reconstruire chaque `.ots` octet pour octet ; appliquer `mise-a-niveau.json`."
    ],
    "oracle": "Égalité ; état `en_attente` → `complete`.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : famille ots (EX-6.2 à EX-6.7, EX-8.11, AN-17 à AN-19)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/ancrage.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-42",
    "level": "TV",
    "title": "`ct-5/planification/` et `ct-5/reprise/` : vingt et une traces du planificateur, files avant et après",
    "specs": [
      "CT-5"
    ],
    "covers": [
      "CT-5 EX-4.1",
      "CT-5 EX-4.2",
      "CT-5 EX-4.3",
      "CT-5 EX-4.4",
      "CT-5 EX-4.5",
      "CT-5 EX-4.6",
      "CT-5 EX-4.7",
      "CT-5 EX-5.7",
      "CT-5 EX-5.10",
      "CT-5 EX-5.11",
      "CT-5 EX-5.12",
      "CT-5 EX-6.1",
      "CT-5 EX-8.3",
      "CT-5 EX-8.4",
      "CT-5 EX-8.5",
      "CT-5 EX-8.6",
      "CT-5 EX-8.7",
      "CT-5 EX-8.8",
      "CT-5 EX-8.9",
      "CT-5 EX-8.10",
      "CT-5 EX-8.11",
      "CT-5 EX-8.12",
      "CT-5 EX-8.13",
      "CT-5 EX-8.14",
      "CT-5 EX-8.15",
      "CT-5 EX-8.16",
      "CT-5 EX-9.5",
      "CT-5 AN-2",
      "CT-5 AN-4",
      "CT-5 AN-12",
      "CT-5 AN-13",
      "CT-5 AN-32",
      "CT-5 AN-33",
      "CT-5 AN-34",
      "CT-5 AN-35",
      "CT-5 AN-36",
      "CT-5 AN-37",
      "CT-5 AN-38",
      "CT-5 AN-39",
      "CT-5 AN-40",
      "CT-5 AN-41",
      "CT-5 AN-42",
      "CT-5 AN-43",
      "CT-5 EX-A.6"
    ],
    "preconditions": [
      "Vecteurs `ct-5/planification, reprise` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Rejouer chaque trace par `rejouerTrace` ; vérifier la ligne `envoyee` avant l'envoi ; relire et rejouer chaque file avant."
    ],
    "oracle": "Actions et file finale égales ; `request_sha256` recalculés ; files finales égales.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : familles planification et reprise (EX-8.12, EX-8.16, EX-A.6)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/ancrage.test.js"
    },
    "threats": [
      "MN-60",
      "MN-62",
      "MN-63",
      "MN-64",
      "MN-76"
    ]
  },
  {
    "id": "TV-43",
    "level": "TV",
    "title": "`ct-5/cout/` et `ct-5/completude/` : onze cas de coût, six cas de complétude",
    "specs": [
      "CT-5"
    ],
    "covers": [
      "CT-5 EX-12.1",
      "CT-5 EX-12.2",
      "CT-5 EX-10.7",
      "CT-5 AN-59",
      "CT-5 AN-61",
      "CT-5 EX-4.11"
    ],
    "preconditions": [
      "Vecteurs `ct-5/cout, completude` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Reproduire chaque cas."
    ],
    "oracle": "Six grandeurs par cas de coût ; `complete`, `orphans`, `out_of_order` égaux.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : comptages et coût (EX-4.11, section 12)",
          "it": "les onze cas de cout.json sont reproduits par la formule de coût, et leurs N_q, N_s, N_a et C_j sont ceux de la table imprimée de 12.3"
        },
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : série des points, échéances, admission et complétude au registre (AN-2, AN-3, AN-61)",
          "it": "completude/ : chaque cas est reproduit par verifierCompletudeRegistre (AN-61) ; la série réécrite laisse deux ancres orphelines ; la série de la période suivante doit être servie"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/ancrage.test.js"
    },
    "threats": [
      "MN-17"
    ]
  },
  {
    "id": "TV-44",
    "level": "TV",
    "title": "Vecteurs de CT-1 et de CT-6 inchangés par CT-5 ; aucun secret, prix ni adresse dans `ct-5`",
    "specs": [
      "CT-5"
    ],
    "covers": [
      "CT-5 EX-A.6",
      "CT-5 AN-43",
      "CT-5 AN-60"
    ],
    "preconditions": [
      "Vecteurs `ct-5` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Vérifier les quarante dossiers de CT-1 et les cinquante de CT-6 ; parcourir les fichiers de données."
    ],
    "oracle": "Mêmes verdicts ; aucune chaîne interdite.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : les dossiers de CT-1 et de CT-6 gardent leur verdict ; aucun secret, prix ni adresse dans spec/vecteurs/ct-5 (EX-A.6)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/ancrage.test.js"
    },
    "threats": [
      "MN-41"
    ]
  },
  {
    "id": "TV-45",
    "level": "TV",
    "title": "Génération déterministe de `spec/vecteurs/ct-5`",
    "specs": [
      "CT-5"
    ],
    "covers": [
      "CT-5 EX-A.1",
      "CT-5 EX-A.2",
      "CT-5 EX-A.3",
      "CT-5 EX-A.4"
    ],
    "preconditions": [
      "Générateur `scripts/vecteurs/generer-ct5.mjs` au commit éprouvé."
    ],
    "steps": [
      "Régénérer dans un répertoire vide."
    ],
    "oracle": "Mêmes octets (`verificateur-independant/` et `confrontation/` exceptés).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : génération déterministe de spec/vecteurs/ct-5 (EX-A.1, EX-A.6)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/ancrage.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-46",
    "level": "TV",
    "title": "Vérificateur Go indépendant de CT-5 : zéro discordance sur `spec/vecteurs/ct-5`",
    "specs": [
      "CT-5"
    ],
    "covers": [
      "CT-5 EX-A.5",
      "CT-5 EX-5.1",
      "CT-5 AN-5",
      "CT-5 AN-6",
      "CT-5 AN-8",
      "CT-5 AN-9",
      "CT-5 AN-10",
      "CT-5 AN-11",
      "CT-5 AN-17",
      "CT-5 AN-18",
      "CT-5 AN-19",
      "CT-5 AN-42",
      "CT-5 AN-59",
      "CT-5 AN-61"
    ],
    "preconditions": [
      "Go 1.24 (version du `go.mod` du module) ; module `spec/vecteurs/ct-5/verificateur-independant` écrit depuis le seul texte de la spécification, sans lire le code JavaScript."
    ],
    "steps": [
      "`gofmt -l .` vide ; `go vet ./...` ; `go test ./...` ; `go run . ..` depuis le répertoire du module."
    ],
    "oracle": "« 0 discordance » et code 0 ; toute valeur attendue des vecteurs est recalculée et égale.",
    "status": {
      "state": "executable",
      "ci_steps": [
        "vérificateur Go indépendant contre les vecteurs CT-5"
      ],
      "command": "cd spec/vecteurs/ct-5/verificateur-independant && gofmt -l . && go vet ./... && go test ./... && go run . .."
    },
    "threats": [
      "MN-66"
    ]
  },
  {
    "id": "TV-47",
    "level": "TV",
    "title": "Confrontation tierce de `ct-5` : openssl, python-opentimestamps, transparency-dev/merkle",
    "specs": [
      "CT-5",
      "CT-1"
    ],
    "covers": [
      "CT-5 EX-A.7",
      "CT-1 §10.7"
    ],
    "preconditions": [
      "Sorties publiées sous `spec/vecteurs/ct-5/confrontation/sorties/` ; `openssl`, `python3`, Go et le module tiers dans le cache pour le rejeu."
    ],
    "steps": [
      "Vérifier les sorties ; rejouer `confronter_requetes.py`, `confronter_reponses.py`, `confrontation/coherence` quand les outils sont présents."
    ],
    "oracle": "Aucune discordance ; sorties égales.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/confrontation.test.js",
          "describe": "CT-5 : sorties publiées de la confrontation par des outils tiers (annexe A.6)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/confrontation.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-48",
    "level": "TV",
    "title": "`ct-6/rfc3161/` : jetons, clés, CRL, statuts T-1 à T-11, confrontation à `openssl ts -verify`",
    "specs": [
      "CT-6"
    ],
    "covers": [
      "CT-6 T-1",
      "CT-6 T-2",
      "CT-6 T-3",
      "CT-6 T-4",
      "CT-6 T-5",
      "CT-6 T-6",
      "CT-6 T-7",
      "CT-6 T-8",
      "CT-6 T-9",
      "CT-6 T-10",
      "CT-6 T-11",
      "CT-6 EX-9.19",
      "CT-6 EX-9.20",
      "CT-6 EX-A.4",
      "CT-6 EX-A.5",
      "CT-6 EX-A.22",
      "CT-6 EX-A.25"
    ],
    "preconditions": [
      "Vecteurs `ct-6/rfc3161` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Vérifier les SHA-256 ; rejouer chaque cas d'`attendu.json` (quarante et un, dont les quinze des jetons de la révision 0.4 de CT-6, EX-A.22 : `sid` introuvable, jeton sans certificat, clés RSA de 8200 et 8192 bits, exposant 2³¹ + 1, intermédiaire de 8200 bits, algorithme inconnu, clé Ed25519 rattachée ou non, numéro de série de 168 bits, et les deux de la révision 0.5, EX-A.25 : `t1-cle-longueur-non-minimale` et `t1-extension-mal-formee`) ; une variante par vérification ; `openssl ts -verify` sur les jetons valides et sur deux cas refusés.",
      "Révision 0.5 de CT-6 (EX-A.25) : les deux jetons rendent T-1 `echoue` (détail nommant la `RSAPublicKey` ou `keyUsage`), T-2 à T-11 `prerequis_en_echec` ; `tsa-cle-longueur-non-minimale.pem` et `tsa-extension-mal-formee.pem` sont illisibles selon §9.3 et refusés comme ancre (N-1)."
    ],
    "oracle": "Statuts, avertissements, faits, résumé et proposition égaux ; `Verification: OK` d'openssl où attendu.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/horodatage.test.js",
          "describe": "CT-6 contrôle 4 : vecteurs spec/vecteurs/ct-6/rfc3161 (annexe A.3)"
        },
        {
          "file": "test/horodatage.test.js",
          "describe": "CT-6 contrôle 4 : confrontation à openssl ts -verify (annexe A.3)"
        },
        {
          "file": "test/horodatage.test.js",
          "describe": "CT-6 révision 0.5 : lecture du SubjectPublicKeyInfo et des extensions connues selon §9.3 (EX-9.4, EX-9.7)",
          "it": "vecteurs t1-cle-longueur-non-minimale et t1-extension-mal-formee (EX-A.25) : T-1 nomme la RSAPublicKey ou keyUsage ; les certificats sont refusés comme ancre (N-1)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/horodatage.test.js"
    },
    "threats": [
      "MN-61"
    ]
  },
  {
    "id": "TV-49",
    "level": "TV",
    "title": "`ct-6/ots/` : en-têtes synthétiques, preuves, statuts O-1 à O-7",
    "specs": [
      "CT-6"
    ],
    "covers": [
      "CT-6 O-1",
      "CT-6 O-2",
      "CT-6 O-3",
      "CT-6 O-4",
      "CT-6 O-5",
      "CT-6 O-6",
      "CT-6 O-7",
      "CT-6 EX-10.14",
      "CT-6 EX-10.15",
      "CT-6 EX-A.6",
      "CT-6 EX-A.7",
      "CT-6 EX-4.5",
      "CT-6 EX-A.26"
    ],
    "preconditions": [
      "Vecteurs `ct-6/ots` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Vérifier les SHA-256 ; rejouer chaque cas ; une variante par vérification ; cas sans en-têtes, `periodHash` incalculable, opération hors profil, attestation hors des en-têtes.",
      "Révision 0.5 de CT-6 (EX-A.26) : `preuves/o1-attestation-en-double.ots` (vingt et unième cas d'`attendu.json`) rend O-1 `echoue` (raison `doublon` dans le détail), O-2 à O-7 `prerequis_en_echec`, contrôle 5 `echoue`, aucune attestation relevée ; `python_opentimestamps.parsing` vaut `acceptee_en_ecrasant`."
    ],
    "oracle": "Statuts, avertissements et faits égaux à `attendu.json`.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/ots.test.js",
          "describe": "CT-6 contrôle 5 : vecteurs spec/vecteurs/ct-6/ots (annexe A.4)"
        },
        {
          "file": "test/ots.test.js",
          "describe": "CT-6 contrôle 5 : format .ots (§10.2, EX-10.2)",
          "it": "forme canonique d'un nœud (révision 0.5) : deux attestations identiques ou deux opérations identiques sous un même nœud rendent le fichier illisible (doublon) ; des branches sœurs distinctes sont lues"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/ots.test.js"
    },
    "threats": [
      "MN-70"
    ]
  },
  {
    "id": "TV-50",
    "level": "TV",
    "title": "`ct-6/registre/` : parties dérivées de la capture, variantes, R-1 à R-10 et N-4",
    "specs": [
      "CT-6"
    ],
    "covers": [
      "CT-6 R-1",
      "CT-6 R-2",
      "CT-6 R-3",
      "CT-6 R-4",
      "CT-6 R-5",
      "CT-6 R-6",
      "CT-6 R-7",
      "CT-6 R-8",
      "CT-6 R-9",
      "CT-6 R-10",
      "CT-6 N-4",
      "CT-6 EX-A.8",
      "CT-6 EX-A.9",
      "CT-6 EX-A.10",
      "CT-6 EX-A.11",
      "CT-6 EX-A.15"
    ],
    "preconditions": [
      "Vecteurs `ct-6/registre` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Vérifier chaque jeu de parties et chaque variante ; relire la capture (sept transactions, ancre de point)."
    ],
    "oracle": "Statuts, avertissements, faits et énoncé égaux ; une seule vérification visée en échec par variante.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/registre.test.js",
          "describe": "CT-6 contrôle 8 : rejeu des vecteurs spec/vecteurs/ct-6/registre"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/registre.test.js"
    },
    "threats": [
      "MN-34",
      "MN-54",
      "MN-59",
      "MN-67",
      "MN-71"
    ]
  },
  {
    "id": "TV-51",
    "level": "TV",
    "title": "`ct-6/ancres/` : fichiers d'ancres de test conformes à `ancres-confiance-v0`",
    "specs": [
      "CT-6"
    ],
    "covers": [
      "CT-6 N-1",
      "CT-6 N-2",
      "CT-6 N-3",
      "CT-6 EX-12.1",
      "CT-6 EX-12.2",
      "CT-6 EX-12.3",
      "CT-6 EX-12.4",
      "CT-6 EX-12.5",
      "CT-6 EX-12.6",
      "CT-6 EX-A.12"
    ],
    "preconditions": [
      "Vecteurs `ct-6/ancres` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Valider chaque fichier et fragment d'ancres ; contrôler les PEM, versions, noms, dates."
    ],
    "oracle": "Conformes ; défauts nommés par N-1 à N-3.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/horodatage.test.js",
          "describe": "CT-6 contrôle 4 : ancres d'horodatage (N-1, EX-12.2)"
        },
        {
          "file": "test/ots.test.js",
          "describe": "CT-6 contrôle 5 : vecteurs spec/vecteurs/ct-6/ots (annexe A.4)",
          "it": "en-têtes, ancre bitcoin et faits du contrôle 5 suivent les schémas entetes-bitcoin-v0, ancres-confiance-v0 et rapport-verification-v0"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/horodatage.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-52",
    "level": "TV",
    "title": "`ct-6/dossiers/` : dossiers complets, verdicts, énoncés, V-1 à V-10 (rapport comparé à `attendu.json`)",
    "specs": [
      "CT-6",
      "CT-1"
    ],
    "covers": [
      "CT-6 V-1",
      "CT-6 V-2",
      "CT-6 V-3",
      "CT-6 V-4",
      "CT-6 V-5",
      "CT-6 V-6",
      "CT-6 V-7",
      "CT-6 V-8",
      "CT-6 V-9",
      "CT-6 V-10",
      "CT-1 K-7",
      "CT-1 K-8",
      "CT-1 K-9",
      "CT-6 AT-6",
      "CT-6 AT-7",
      "CT-6 AT-1",
      "CT-6 AT-2",
      "CT-6 AT-3",
      "CT-6 AT-4",
      "CT-6 AT-5",
      "CT-6 AV-AT-1",
      "CT-6 AV-AT-2",
      "CT-6 AV-AT-3",
      "CT-6 AV-K-2",
      "CT-6 AV-K-4",
      "CT-6 AV-K-1",
      "CT-6 AV-K-3",
      "CT-6 EX-5.1",
      "CT-6 EX-5.2",
      "CT-6 EX-5.3",
      "CT-6 EX-5.4",
      "CT-6 EX-5.5",
      "CT-6 EX-5.6",
      "CT-6 EX-5.7",
      "CT-6 EX-5.8",
      "CT-6 EX-5.9",
      "CT-6 EX-5.10",
      "CT-6 EX-5.11",
      "CT-6 EX-5.12",
      "CT-6 EX-6.1",
      "CT-6 EX-6.2",
      "CT-6 EX-6.3",
      "CT-6 EX-6.4",
      "CT-6 EX-6.5",
      "CT-6 EX-6.6",
      "CT-6 EX-6.7",
      "CT-6 EX-6.8",
      "CT-6 EX-6.16",
      "CT-6 EX-6.19",
      "CT-6 EX-6.9",
      "CT-6 EX-6.10",
      "CT-6 EX-6.11",
      "CT-6 EX-6.12",
      "CT-6 EX-6.13",
      "CT-6 EX-6.15",
      "CT-6 EX-6.17",
      "CT-6 EX-6.20",
      "CT-6 EX-6.14",
      "CT-6 EX-6.18",
      "CT-6 EX-6.21",
      "CT-6 EX-7.3",
      "CT-6 EX-8.1",
      "CT-6 EX-8.2",
      "CT-6 EX-8.3",
      "CT-6 EX-8.4",
      "CT-6 EX-8.5",
      "CT-6 EX-8.6",
      "CT-6 EX-8.7",
      "CT-6 EX-8.8",
      "CT-6 EX-8.9",
      "CT-6 EX-8.10",
      "CT-6 EX-8.11",
      "CT-6 EX-4.6",
      "CT-6 EX-4.7",
      "CT-6 EX-4.11",
      "CT-6 EX-4.12",
      "CT-6 EX-4.13",
      "CT-6 EX-4.15",
      "CT-6 EX-3.2",
      "CT-6 EX-3.3",
      "CT-6 EX-7.1",
      "CT-6 EX-7.2",
      "CT-7 EX-8.10",
      "CT-7 EX-8.17",
      "CT-6 EX-13.4",
      "CT-6 EX-13.5",
      "CT-6 EX-15.1",
      "CT-6 EX-15.2",
      "CT-6 EX-A.13",
      "CT-6 EX-A.14",
      "CT-6 EX-A.15",
      "CT-6 EX-A.16",
      "CT-6 EX-A.17",
      "CT-6 EX-A.18",
      "CT-6 EX-A.19",
      "CT-6 EX-A.20",
      "CT-6 EX-A.21",
      "CT-6 K-1",
      "CT-6 K-6",
      "CT-6 EX-4.16",
      "CT-6 EX-4.17",
      "CT-6 EX-5.14",
      "CT-6 EX-5.15",
      "CT-6 EX-5.20",
      "CT-6 EX-6.22",
      "CT-6 EX-A.23",
      "CT-6 EX-A.24"
    ],
    "preconditions": [
      "Vecteurs `ct-6/dossiers` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Lancer `scripts/verify/dossier.mjs` sur chaque dossier, en français et en anglais, avec et sans `--json` ; comparer deux exécutions ; reconstruire l'énoncé fragment par fragment ; vérifier V-10 sur chaque dossier avec la partie d'attestation ; aucun « prouvé » sur le périmètre.",
      "Révision 0.4 de CT-6 : les seize dossiers d'EX-A.23 et les deux d'EX-A.24 sont rejoués comme les autres, `--exiger 4` compris (`exit_code_exiger_4`) ; événement prouvé inexploitable (EX-5.14, EX-5.15) : D-1, P-1, T-2, O-2, R-9 et R-10 non exécutées (`prerequis_en_echec`), contrôles 4, 5 et 8 non exécutés, N-4 absente, `event`, `org_id` et `journal_id` nuls (EX-6.22) ; entrées éprouvées sur une copie de `valide-seq-7-complet` : partie imbriquée au-delà de 128 niveaux (EX-4.16, point 3), `dossier.json` sans forme canonique (E-2, EX-5.20) ou contraire à son schéma (D-1), lien symbolique pour `dossier.json`, une partie, `--ancres`, `--entetes-bitcoin`, `--second-manifeste` ou une pièce (EX-4.17)."
    ],
    "oracle": "Code, vérifications en échec, statuts, non-exécutions, avertissements, énoncé et borne égaux à `attendu.json` ; rapports JSON identiques octet pour octet (V-8).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : dossiers complets de spec/vecteurs/ct-6 par la ligne de commande"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : énoncé du dossier complet reconstruit fragment par fragment (EX-6.8, V-5)"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : entrées inutilisables (code 2) et limites"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : pièces fournies à part et second manifeste (EX-4.6, EX-4.7)"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : règles précisées par la revue"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 révision 0.3 : attestation de périmètre (section 5.5, EX-6.19 à EX-6.21, V-10)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/verificateur.test.js"
    },
    "threats": [
      "MN-17",
      "MN-61",
      "MN-68",
      "MN-69",
      "MN-78",
      "MN-85",
      "MN-98"
    ]
  },
  {
    "id": "TV-53",
    "level": "TV",
    "title": "Génération déterministe de `spec/vecteurs/ct-6` (dossiers, rfc3161, ots, registre)",
    "specs": [
      "CT-6"
    ],
    "covers": [
      "CT-6 EX-A.1",
      "CT-6 EX-A.2",
      "CT-6 EX-A.3"
    ],
    "preconditions": [
      "Générateurs `scripts/vecteurs/generer-ct6.mjs` et `scripts/vecteurs/ct6/*` au commit éprouvé."
    ],
    "steps": [
      "Régénérer chaque famille dans un répertoire vide."
    ],
    "oracle": "Mêmes octets que le dépôt (entrées de capture exceptées).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : génération déterministe de spec/vecteurs/ct-6"
        },
        {
          "file": "test/horodatage.test.js",
          "describe": "CT-6 contrôle 4 : génération déterministe des vecteurs rfc3161"
        },
        {
          "file": "test/ots.test.js",
          "describe": "CT-6 contrôle 5 : génération déterministe des vecteurs ots"
        },
        {
          "file": "test/registre.test.js",
          "describe": "CT-6 contrôle 8 : rejeu des vecteurs spec/vecteurs/ct-6/registre",
          "it": "le générateur reproduit octet pour octet chaque fichier de registre/ (hors capture/), et rien d'autre"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/verificateur.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-54",
    "level": "TV",
    "title": "Confrontation tierce de `ct-6` : openssl, python-opentimestamps, go-ethereum et noorcore",
    "specs": [
      "CT-6"
    ],
    "covers": [
      "CT-6 EX-A.17",
      "CT-6 EX-A.18",
      "CT-6 EX-A.19",
      "CT-6 EX-A.20",
      "CT-6 EX-A.25",
      "CT-6 EX-A.26"
    ],
    "preconditions": [
      "Sorties publiées sous `spec/vecteurs/ct-6/confrontation/sorties/` ; la confrontation du registre n'est pas rejouée en CI (copie de noorchain-core exigée)."
    ],
    "steps": [
      "Vérifier que chaque sortie porte sur les vecteurs du dépôt ; rejouer `confronter_rfc3161.py` quand `python3` et `openssl` sont présents.",
      "Révision 0.5 de CT-6 : les sorties republiées portent les vecteurs d'EX-A.25 (`Verification: OK` d'`openssl ts -verify` pour `t1-cle-longueur-non-minimale.der`, `certificate verify error` pour `t1-extension-mal-formee.der` ; longueur non minimale relevée par `openssl asn1parse`, extension indécodable par `openssl x509 -purpose`) et d'EX-A.26 (`o1-attestation-en-double.ots` lue `acceptee_en_ecrasant` par python-opentimestamps, concordante avec l'attendu)."
    ],
    "oracle": "Aucune discordance.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/confrontation.test.js",
          "describe": "CT-6 : sorties publiées de la confrontation par des outils tiers (annexe A.8)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/confrontation.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-55",
    "level": "TV",
    "title": "Vérificateur Go indépendant de CT-6 (binaire de CT-6 §14) : zéro discordance sur `ct-6/dossiers`",
    "specs": [
      "CT-6"
    ],
    "covers": [
      "CT-6 EX-14.1",
      "CT-6 EX-14.2",
      "CT-6 EX-14.3",
      "CT-6 EX-14.4",
      "CT-6 EX-14.5",
      "CT-6 EX-14.6",
      "CT-6 EX-14.7",
      "CT-6 EX-14.8",
      "CT-6 EX-14.9",
      "CT-6 EX-14.10",
      "CT-6 EX-14.11",
      "CT-6 EX-4.16",
      "CT-6 EX-4.17",
      "CT-6 EX-5.13",
      "CT-6 EX-5.14",
      "CT-6 EX-5.15",
      "CT-6 EX-5.16",
      "CT-6 EX-5.17",
      "CT-6 EX-5.18",
      "CT-6 EX-5.19",
      "CT-6 EX-5.20",
      "CT-6 EX-6.22",
      "CT-6 EX-9.23",
      "CT-6 EX-9.24",
      "CT-6 EX-A.22",
      "CT-6 EX-A.23",
      "CT-6 EX-A.24",
      "CT-6 EX-A.25",
      "CT-6 EX-A.26"
    ],
    "preconditions": [
      "Module Go `verificateur/` (binaire `noortrace-verifier`), écrit depuis le seul texte de CT-6, étape 2 du plan (CT-6 §14 : « le binaire est construit en phase 2 ») ; Go 1.27.3, dépendances vendorisées."
    ],
    "steps": [
      "`go test ./...` dans `verificateur/` : chaque dossier de `spec/vecteurs/ct-1/dossiers` et de `spec/vecteurs/ct-6/dossiers` rejoué ; code, `failed_checks`, statuts, raisons, avertissements, énoncé et borne comparés à son `attendu.json` ; chaque jeton de `spec/vecteurs/ct-6/rfc3161/attendu.json` rejoué, ceux d'EX-A.22 et d'EX-A.25 compris ; chaque preuve de `spec/vecteurs/ct-6/ots/attendu.json` rejouée, celle d'EX-A.26 comprise.",
      "Le même `go test ./...` exécute les tests des règles de la révision 0.4 de CT-6 et de la révision 0.5 de CT-1 : `moteur/revision04_test.go` (codage, profondeur et forme canonique d'EX-4.16 ; événement prouvé inexploitable d'EX-5.15 ; désignation membre par membre d'EX-6.22 ; EX-9.24 de bout en bout), `moteur/ordinaire_unix_test.go` (lien symbolique et tube nommé, EX-4.17), `horodatage/revision04_test.go` (bornes RSA d'EX-9.23, clé hors de la version 0 d'EX-9.24), `dossier/revision05_test.go` et `dossier/correctifs_test.go` (EX-5.13, EX-5.14, EX-5.16 à EX-5.20) ; pour la révision 0.5 de CT-6, `horodatage/revision05_test.go` (certificats et jetons d'EX-A.25 illisibles selon §9.3, T-1 en échec) et `ots/format_test.go` (`TestFormatDoublon` : doublon sous un même nœud, vecteur d'EX-A.26).",
      "Construire deux fois par la recette d'EX-14.6 dans des répertoires et des caches différents ; comparer les SHA-256.",
      "Appliquer les quatre preuves d'absence de réseau d'EX-14.5 (`verificateur/scripts/verifier-sans-reseau.sh`)."
    ],
    "oracle": "Zéro discordance ; mêmes verdicts que l'implémentation JavaScript sur les mêmes entrées ; deux binaires aux mêmes octets ; les quatre preuves réussies.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/publication-etape7.test.js",
          "describe": "Étape 7 : publication préparée sans rien publier (CT-6 §14.4, CT-8 EX-3.13, EX-3.14)",
          "it": "TV-55, complément (étape 7) : deux préparations de la version à blanc, chacune avec son cache Go neuf, donnent les mêmes fichiers aux mêmes octets ; binaires d'un second constructeur égaux acceptés par --temoin, un octet changé refusé (code 1, rien sous --sortie)"
        },
        {
          "file": "test/publication-etape7.test.js",
          "describe": "Étape 7 : publication préparée sans rien publier (CT-6 §14.4, CT-8 EX-3.13, EX-3.14)",
          "it": "TV-55, complément (étape 7) : SHA256SUMS exact (une ligne « <sha256>  <nom> » par fichier, triée, recalculée ; sha256sum --strict -c rend 0) ; binaires ELF amd64 et arm64 ; go version -m de go1.27.3 avec CGO_ENABLED=0 et -trimpath ; LICENSE, NOTICE et LICENCES-TIERCES du dépôt"
        },
        {
          "file": "test/publication-etape7.test.js",
          "describe": "Étape 7 : publication préparée sans rien publier (CT-6 §14.4, CT-8 EX-3.13, EX-3.14)",
          "it": "TV-55, complément (étape 7) : archive de déploiement ustar déterministe, égale octet pour octet à la recette GNU tar d'EX-13.15 sur ses fichiers extraits par tar -xkf, dont SHA256SUMS se vérifie ; découpage nom et préfixe d'un nom de 103 octets égal à GNU tar ; nom non représentable refusé"
        },
        {
          "file": "test/publication-etape7.test.js",
          "describe": "Étape 7 : publication préparée sans rien publier (CT-6 §14.4, CT-8 EX-3.13, EX-3.14)",
          "it": "TV-55, complément (étape 7) : SHA256SUMS signé au format minisign par une clé d'essai éphémère (en mémoire, détruite) : signature vérifiée avec le commentaire de confiance de la note (version et date), puis refusée après falsification de SHA256SUMS, du commentaire de confiance, de la signature ou de la clé"
        },
        {
          "file": "test/publication-etape7.test.js",
          "describe": "Étape 7 : publication préparée sans rien publier (CT-6 §14.4, CT-8 EX-3.13, EX-3.14)",
          "it": "TV-55, complément (étape 7) : note de version remplie depuis le gabarit (SHA-256 des binaires et de l'archive, go version -m, images noortrace/* de images.json non publiées, ou leur condensé par --condenses) ; provenance in-toto SLSA v1 préparée, non signée, sujets égaux aux fichiers de SHA256SUMS et à SHA256SUMS"
        },
        {
          "file": "test/publication-etape7.test.js",
          "describe": "Étape 7 : publication préparée sans rien publier (CT-6 §14.4, CT-8 EX-3.13, EX-3.14)",
          "it": "TV-55, complément (étape 7) : preparer-version.mjs refuse une option manquante, invalide ou une sortie existante (code 2), une autre chaîne que go1.27.3 et --exiger-arbre-propre sur un autre commit que HEAD (code 1), sans rien laisser sous --sortie"
        },
        {
          "file": "test/publication-etape7.test.js",
          "describe": "Étape 7 : publication préparée sans rien publier (CT-6 §14.4, CT-8 EX-3.13, EX-3.14)",
          "it": "TV-55 et TQ-8, complément (étape 7) : .github/workflows/version.yml ne se déclenche qu'à la main ou sur une étiquette v*, n'a que contents: read, épingle chaque action par SHA de commit d'une version publiée plus de deux semaines avant, Node.js par version exacte, l'image de construction et Go par empreinte, et ne contient aucune étape de publication, de signature ni d'attestation"
        }
      ],
      "ci_steps": [
        "binaire vérificateur Go, gofmt, vet et rejeu des dossiers CT-1 et CT-6 (zéro discordance)",
        "binaire vérificateur Go, deux constructions reproductibles aux mêmes octets (CT-6 EX-14.6, EX-14.8)",
        "binaire vérificateur Go, preuves d'absence de réseau (CT-6 EX-14.5)",
        "version préparée à blanc, deux préparations aux mêmes octets (TV-55, TQ-8), aucun essai en attente"
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/publication-etape7.test.js && cd verificateur && go test ./...",
      "complement": {
        "phase2_step": 8,
        "blocking": "Signature minisign réelle de `SHA256SUMS` et publication d'une version (CT-6 EX-14.9) : la préparation de l'étape 7 écrit binaires, `go version -m`, `SHA256SUMS`, `LICENCES-TIERCES`, `NOTICE`, archive, note de version et provenance non signée, sans rien publier ; la signature, l'attestation de provenance signée et la publication attendent la décision du porteur sur la clé minisign et son accord de publication (lancement, étape 8)."
      }
    },
    "threats": [
      "MN-66"
    ]
  },
  {
    "id": "TV-56",
    "level": "TV",
    "title": "`ct-7/menaces.json`, tables 3.2 à 3.5 et vérificateur de renvois : RV-1 à RV-9, table TR- de CT-7",
    "specs": [
      "CT-7"
    ],
    "covers": [
      "CT-7 RV-1",
      "CT-7 RV-2",
      "CT-7 RV-3",
      "CT-7 RV-4",
      "CT-7 RV-5",
      "CT-7 RV-6",
      "CT-7 RV-7",
      "CT-7 RV-8",
      "CT-7 RV-9",
      "CT-7 TR-1",
      "CT-7 TR-2",
      "CT-7 TR-3",
      "CT-7 TR-4",
      "CT-7 TR-5",
      "CT-7 TR-6",
      "CT-7 TR-7",
      "CT-7 TR-8",
      "CT-7 TR-9",
      "CT-7 TR-10",
      "CT-7 TR-11",
      "CT-7 TR-12",
      "CT-7 TR-13",
      "CT-7 TR-14",
      "CT-7 TR-15",
      "CT-7 TR-16",
      "CT-7 TR-17",
      "CT-7 TR-18",
      "CT-7 TR-19",
      "CT-7 TR-20",
      "CT-7 TR-21",
      "CT-7 TR-22",
      "CT-7 TR-23",
      "CT-7 TR-24",
      "CT-7 TR-25",
      "CT-7 TR-26",
      "CT-7 TR-27",
      "CT-7 TR-28",
      "CT-7 TR-29",
      "CT-7 TR-30",
      "CT-7 TR-31",
      "CT-7 TR-32",
      "CT-7 TR-33",
      "CT-7 TR-34",
      "CT-7 TR-35",
      "CT-7 TR-36",
      "CT-7 TR-37",
      "CT-7 TR-38",
      "CT-7 TR-39",
      "CT-7 TR-40",
      "CT-7 TR-41",
      "CT-7 TR-42",
      "CT-7 TR-43",
      "CT-7 TR-44",
      "CT-7 TR-45",
      "CT-7 TR-46",
      "CT-7 TR-47",
      "CT-7 TR-48",
      "CT-7 TR-49",
      "CT-7 TR-50",
      "CT-7 TR-51",
      "CT-7 TR-52",
      "CT-7 TR-53",
      "CT-7 TR-54",
      "CT-7 TR-55",
      "CT-7 TR-56",
      "CT-7 TR-57",
      "CT-7 TR-58",
      "CT-7 TR-59",
      "CT-7 TR-60",
      "CT-7 TR-61",
      "CT-7 TR-62",
      "CT-7 TR-63",
      "CT-7 TR-64",
      "CT-7 TR-65",
      "CT-7 TR-66",
      "CT-7 TR-67",
      "CT-7 TR-68",
      "CT-7 TR-69",
      "CT-7 TR-70",
      "CT-7 TR-71",
      "CT-7 TR-72",
      "CT-7 TR-73",
      "CT-7 TR-74",
      "CT-7 TR-75",
      "CT-7 TR-76",
      "CT-7 TR-77",
      "CT-7 TR-78",
      "CT-7 TR-79",
      "CT-7 TR-80",
      "CT-7 TR-81",
      "CT-7 TR-82",
      "CT-7 TR-83",
      "CT-7 TR-84",
      "CT-7 TR-85",
      "CT-7 TR-86",
      "CT-7 TR-87",
      "CT-7 TR-88",
      "CT-7 TR-89",
      "CT-7 TR-90",
      "CT-7 TR-91",
      "CT-7 TR-92",
      "CT-7 TR-93",
      "CT-7 TR-94",
      "CT-7 TR-95",
      "CT-7 TR-96",
      "CT-7 TR-97",
      "CT-7 TR-98",
      "CT-7 TR-99",
      "CT-7 TR-100",
      "CT-7 TR-101",
      "CT-7 EX-0.1",
      "CT-7 EX-3.1",
      "CT-7 EX-3.2",
      "CT-7 EX-A.4",
      "CT-7 EX-A.5",
      "CT-7 EX-A.18",
      "CT-7 EX-A.19"
    ],
    "preconditions": [
      "Vecteurs `ct-7/menaces.json` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Comparer `menaces.json` au schéma et à ce que `construireMenaces` tire des tables ; reconstruire la table 3.4 ; lancer `verifier-renvois.mjs` ; altérer des copies en mémoire ; vérifier que chaque vecteur nommé par la colonne « Test de CT-9 » existe."
    ],
    "oracle": "Égalité octet pour octet ; code 0 ; chaque altération fait échouer la RV- visée ; 101 lignes TR- pour autant d'occurrences.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : modèle de menace et vérificateur de renvois (EX-3.1, EX-A.4, EX-A.18)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/securite.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-57",
    "level": "TV",
    "title": "`ct-7/ceremonies/` : procès-verbaux valides et invalides, CR-1 à CR-12, commande `ceremonie.mjs`",
    "specs": [
      "CT-7"
    ],
    "covers": [
      "CT-7 CR-1",
      "CT-7 CR-2",
      "CT-7 CR-3",
      "CT-7 CR-4",
      "CT-7 CR-5",
      "CT-7 CR-6",
      "CT-7 CR-7",
      "CT-7 CR-8",
      "CT-7 CR-9",
      "CT-7 CR-10",
      "CT-7 CR-11",
      "CT-7 CR-12",
      "CT-7 EX-5.8",
      "CT-7 EX-5.10",
      "CT-7 EX-A.6",
      "CT-7 EX-A.16",
      "CT-7 EX-A.19"
    ],
    "preconditions": [
      "Vecteurs `ct-7/ceremonies` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "`verifierCeremonie` sur chaque cas ; `scripts/verify/ceremonie.mjs` (`--json`, `--condense`) ; CR-11 sur une signature à `s` haut."
    ],
    "oracle": "`attendu.json` exact ; chaque cas invalide échoue à la vérification que son nom annonce ; codes 0, 1, 2.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : vecteurs ceremonies/ (annexe A.4, EX-A.6, EX-A.19)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/securite.test.js"
    },
    "threats": [
      "MN-32",
      "MN-36",
      "MN-37",
      "MN-39",
      "MN-92",
      "MN-94"
    ]
  },
  {
    "id": "TV-58",
    "level": "TV",
    "title": "`ct-7/attestations/` : exemple, 18 cas hors dossier, signatures croisées, outil de référence",
    "specs": [
      "CT-7"
    ],
    "covers": [
      "CT-7 EX-A.8",
      "CT-7 EX-A.9",
      "CT-7 EX-A.17",
      "CT-7 EX-7.7",
      "CT-7 EX-7.10",
      "CT-7 EX-7.11",
      "CT-7 EX-7.12",
      "CT-7 EX-7.13",
      "CT-7 EX-7.14",
      "CT-7 EX-7.15",
      "CT-7 EX-7.16",
      "CT-7 EX-7.17"
    ],
    "preconditions": [
      "Vecteurs `ct-7/attestations` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Rejouer `exemple/`, `attestations.json`, `croises.json` ; `condenser` et `verifier --forme` de l'outil."
    ],
    "oracle": "`digest`, adresses, statuts AT-1 à AT-4, `retained` égaux ; chaque signature croisée refusée ; adresse IPv4 dans `host` refusée.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : vecteurs attestations/ et outil de référence (EX-A.8, EX-A.9, EX-A.17)"
        },
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : partie attestation au-delà du plafond de lecture (CT-6 EX-4.15, MN-89)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/securite.test.js"
    },
    "threats": [
      "MN-81",
      "MN-83",
      "MN-87",
      "MN-89"
    ]
  },
  {
    "id": "TV-59",
    "level": "TV",
    "title": "`ct-7/matrice-conformite.json` et `ct-7/matrice/invalides/` : MX-1 à MX-9, tables 8.2, 8.4, 8.9 et clauses cellule par cellule",
    "specs": [
      "CT-7"
    ],
    "covers": [
      "CT-7 MX-1",
      "CT-7 MX-2",
      "CT-7 MX-3",
      "CT-7 MX-4",
      "CT-7 MX-5",
      "CT-7 MX-6",
      "CT-7 MX-7",
      "CT-7 MX-8",
      "CT-7 MX-9",
      "CT-7 MC-1",
      "CT-7 MC-2",
      "CT-7 MC-3",
      "CT-7 MC-4",
      "CT-7 MC-5",
      "CT-7 MC-6",
      "CT-7 MC-7",
      "CT-7 MC-8",
      "CT-7 MC-9",
      "CT-7 MC-10",
      "CT-7 MC-11",
      "CT-7 MC-12",
      "CT-7 MC-13",
      "CT-7 MC-14",
      "CT-7 MC-15",
      "CT-7 MC-16",
      "CT-7 MC-17",
      "CT-7 MC-18",
      "CT-7 MC-19",
      "CT-7 MC-20",
      "CT-7 MC-21",
      "CT-7 MC-22",
      "CT-7 MC-23",
      "CT-7 MC-24",
      "CT-7 MC-25",
      "CT-7 MC-26",
      "CT-7 MC-27",
      "CT-7 MC-28",
      "CT-7 MC-29",
      "CT-7 MC-30",
      "CT-7 MC-31",
      "CT-7 MC-32",
      "CT-7 MC-33",
      "CT-7 MC-34",
      "CT-7 MC-35",
      "CT-7 MC-36",
      "CT-7 MC-37",
      "CT-7 MC-38",
      "CT-7 MC-39",
      "CT-7 MC-40",
      "CT-7 MC-41",
      "CT-7 MC-42",
      "CT-7 MC-43",
      "CT-7 MC-44",
      "CT-7 MC-45",
      "CT-7 MC-46",
      "CT-7 MC-47",
      "CT-7 MC-48",
      "CT-7 MC-49",
      "CT-7 MC-50",
      "CT-7 MC-51",
      "CT-7 MC-52",
      "CT-7 MC-53",
      "CT-7 MC-54",
      "CT-7 MC-55",
      "CT-7 MC-56",
      "CT-7 MC-57",
      "CT-7 MC-58",
      "CT-7 T-1",
      "CT-7 T-2",
      "CT-7 T-3",
      "CT-7 T-4",
      "CT-7 T-5",
      "CT-7 T-6",
      "CT-7 T-7",
      "CT-7 T-8",
      "CT-7 T-9",
      "CT-7 T-10",
      "CT-7 L-1",
      "CT-7 L-2",
      "CT-7 L-3",
      "CT-7 L-4",
      "CT-7 L-5",
      "CT-7 L-6",
      "CT-7 L-7",
      "CT-7 L-8",
      "CT-7 L-9",
      "CT-7 L-10",
      "CT-7 EX-8.1",
      "CT-7 EX-8.2",
      "CT-7 EX-8.3",
      "CT-7 EX-8.4",
      "CT-7 EX-8.5",
      "CT-7 EX-8.6",
      "CT-7 EX-8.7",
      "CT-7 EX-8.8",
      "CT-7 EX-8.19",
      "CT-7 EX-8.20",
      "CT-7 EX-A.13",
      "CT-7 EX-A.14",
      "CT-7 EX-A.20"
    ],
    "preconditions": [
      "Vecteurs `ct-7/matrice` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "MX-1 à MX-9 sur le fichier publié ; chaque cas invalide ; statut dérivé ; garde du vocabulaire ; grille de l'épreuve de conformité recalculée depuis le fichier."
    ],
    "oracle": "Égalité des tables du texte et du fichier (MX-8) ; chaque cas invalide échoue exactement aux MX- d'`attendu.json` ; aucune phrase « est conforme » affirmative.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/conformite.test.js",
          "describe": "CT-7 : matrice de conformité (section 8, annexe A.8, EX-A.20)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/conformite.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-60",
    "level": "TV",
    "title": "`ct-7/cles-de-test.json` : clés publiques et adresses recalculées",
    "specs": [
      "CT-7"
    ],
    "covers": [
      "CT-7 EX-4.10",
      "CT-7 EX-A.7",
      "CT-7 CLE-28"
    ],
    "preconditions": [
      "Vecteurs `ct-7/cles-de-test.json` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Recalculer chaque clé publique et adresse depuis les fichiers des vecteurs."
    ],
    "oracle": "Égalité ; aucune clé privée réelle.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : modèle de menace et vérificateur de renvois (EX-3.1, EX-A.4, EX-A.18)",
          "it": "cles-de-test.json (EX-4.10, EX-A.7) : clés publiques et adresses recalculées depuis les fichiers des vecteurs ; ni la clé de l'enregistreur ni les comptes des cérémonies n'y manquent"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/securite.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-61",
    "level": "TV",
    "title": "Génération déterministe de `spec/vecteurs/ct-7` ; grilles des épreuves à part des consignes",
    "specs": [
      "CT-7"
    ],
    "covers": [
      "CT-7 EX-A.1",
      "CT-7 EX-A.2",
      "CT-7 EX-A.3",
      "CT-7 EX-A.12",
      "CT-7 EX-A.27",
      "CT-7 EX-A.28",
      "CT-7 EX-A.29",
      "CT-7 EX-A.30",
      "CT-7 EX-A.31"
    ],
    "preconditions": [
      "Générateur `scripts/vecteurs/generer-ct7.mjs` au commit éprouvé."
    ],
    "steps": [
      "Deux générations en mémoire ; vérifier que les grilles `acceptation-*-attendu.json` sont hors des répertoires remis."
    ],
    "oracle": "Identiques et égales au dépôt ; grilles à part.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : générateur scripts/vecteurs/generer-ct7.mjs (EX-A.1, EX-A.2, EX-A.3)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/securite.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-62",
    "level": "TV",
    "title": "Vérificateur Go indépendant de CT-7 : zéro discordance sur `spec/vecteurs/ct-7`",
    "specs": [
      "CT-7"
    ],
    "covers": [
      "CT-7 CR-1",
      "CT-7 CR-2",
      "CT-7 CR-3",
      "CT-7 CR-4",
      "CT-7 CR-5",
      "CT-7 CR-6",
      "CT-7 CR-7",
      "CT-7 CR-8",
      "CT-7 CR-9",
      "CT-7 CR-10",
      "CT-7 CR-11",
      "CT-7 CR-12",
      "CT-7 AT-1",
      "CT-7 AT-2",
      "CT-7 AT-3",
      "CT-7 AT-4",
      "CT-7 AT-5",
      "CT-7 AT-6",
      "CT-7 AT-7",
      "CT-7 MX-1",
      "CT-7 MX-2",
      "CT-7 MX-3",
      "CT-7 MX-5",
      "CT-7 MX-9",
      "CT-7 EX-A.21",
      "CT-7 EX-A.22",
      "CT-7 EX-A.23"
    ],
    "preconditions": [
      "Go 1.24 (version du `go.mod` du module) ; module `spec/vecteurs/ct-7/verificateur-independant` écrit depuis le seul texte de la spécification, sans lire le code JavaScript."
    ],
    "steps": [
      "`gofmt -l .` vide ; `go vet ./...` ; `go test ./...` ; `go run . ..` depuis le répertoire du module.",
      "Parité JS/Go du condensé D_P de l'exemple (CT-7 EX-A.21, test cité de test/plan-de-tests.test.js) : même première ligne de scripts/conformite/attestation.mjs condenser et de go run . condenser."
    ],
    "oracle": "« 0 discordance » et code 0 ; toute valeur attendue des vecteurs est recalculée et égale ; le D_P de l'exemple par l'outil JS égale celui du module Go (en attente sans go).",
    "status": {
      "state": "executable",
      "ci_steps": [
        "vérificateur Go indépendant contre les vecteurs CT-7"
      ],
      "command": "cd spec/vecteurs/ct-7/verificateur-independant && gofmt -l . && go vet ./... && go test ./... && go run . .. && cd ../../../.. && npx hardhat --config hardhat.config.mjs test test/plan-de-tests.test.js",
      "tests": [
        {
          "file": "test/plan-de-tests.test.js",
          "describe": "CT-9 : confrontation tierce et vérificateur Go indépendant (annexe A.10, A.11, EX-A.17, EX-A.18)",
          "it": "parité JS/Go du condensé D_P (CT-7 EX-A.21) : scripts/conformite/attestation.mjs condenser et go run . condenser du module ct-7 rendent la même première ligne sur l'exemple de ct-7/attestations, égale à condense.json (en attente sans go)"
        }
      ]
    },
    "threats": [
      "MN-66",
      "MN-97"
    ]
  },
  {
    "id": "TV-63",
    "level": "TV",
    "title": "Confrontation tierce de `ct-7` : signatures des procès-verbaux et des attestations par ethers et eth-account",
    "specs": [
      "CT-7"
    ],
    "covers": [
      "CT-7 EX-A.24",
      "CT-7 EX-A.25",
      "CT-7 EX-A.26"
    ],
    "preconditions": [
      "Sorties publiées sous `spec/vecteurs/ct-7/confrontation/`."
    ],
    "steps": [
      "Vérifier les sorties ; rejouer les programmes quand les interpréteurs sont présents."
    ],
    "oracle": "Aucune discordance hors des écarts inscrits d'EX-A.25.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/confrontation.test.js",
          "describe": "CT-7 : sorties publiées de la confrontation des signatures de procès-verbal et d'attestation par des outils tiers (EX-A.24, EX-A.25)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/confrontation.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-64",
    "level": "TV",
    "title": "`ct-8/conteneurs/` : 36 cas, CO-1 à CO-14",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 CO-1",
      "CT-8 CO-2",
      "CT-8 CO-3",
      "CT-8 CO-4",
      "CT-8 CO-5",
      "CT-8 CO-6",
      "CT-8 CO-7",
      "CT-8 CO-8",
      "CT-8 CO-9",
      "CT-8 CO-10",
      "CT-8 CO-11",
      "CT-8 CO-12",
      "CT-8 CO-13",
      "CT-8 CO-14",
      "CT-8 EX-A.4",
      "CT-8 EX-A.5"
    ],
    "preconditions": [
      "Vecteurs `ct-8/conteneurs` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Rejouer chaque cas par `verifierConteneurs` et par l'outil (`--json`)."
    ],
    "oracle": "Attendu et code 0 ou 1 ; un seul échec par cas invalide.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/deploiement.test.js",
          "describe": "CT-8 annexe A.3 : famille conteneurs/"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/deploiement.test.js"
    },
    "threats": [
      "MN-22"
    ]
  },
  {
    "id": "TV-65",
    "level": "TV",
    "title": "`ct-8/controle-prealable/` : 33 cas, IP-1 à IP-13, collecte réelle sans réseau",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 IP-1",
      "CT-8 IP-2",
      "CT-8 IP-3",
      "CT-8 IP-4",
      "CT-8 IP-5",
      "CT-8 IP-6",
      "CT-8 IP-7",
      "CT-8 IP-8",
      "CT-8 IP-9",
      "CT-8 IP-10",
      "CT-8 IP-11",
      "CT-8 IP-12",
      "CT-8 IP-13",
      "CT-8 EX-6.1",
      "CT-8 EX-6.2",
      "CT-8 EX-6.3",
      "CT-8 EX-6.4",
      "CT-8 EX-6.5",
      "CT-8 EX-6.6",
      "CT-8 FL-7",
      "CT-8 FL-8",
      "CT-8 FL-18",
      "CT-8 EX-A.6",
      "CT-8 EX-A.7"
    ],
    "preconditions": [
      "Vecteurs `ct-8/controle-prealable` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Rejouer chaque cas par `controle-prealable.mjs --observations` ; exemple de 6.3 ; collecte réelle sur la machine des tests sans destination réseau."
    ],
    "oracle": "Sortie égale à `attendu`, code d'EX-6.3 ; observations et rapport conformes au schéma.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/deploiement.test.js",
          "describe": "CT-8 §6 et annexe A.4 : contrôle préalable"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/deploiement.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-66",
    "level": "TV",
    "title": "`ct-8/dimensionnement/` : 16 cas, DM-1 à DM-22, tables 9.5, 9.6 et valeurs de CT-8 EX-14.2",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 DM-1",
      "CT-8 DM-2",
      "CT-8 DM-3",
      "CT-8 DM-4",
      "CT-8 DM-5",
      "CT-8 DM-6",
      "CT-8 DM-7",
      "CT-8 DM-8",
      "CT-8 DM-9",
      "CT-8 DM-10",
      "CT-8 DM-11",
      "CT-8 DM-12",
      "CT-8 DM-13",
      "CT-8 DM-14",
      "CT-8 DM-15",
      "CT-8 DM-16",
      "CT-8 DM-17",
      "CT-8 DM-18",
      "CT-8 DM-19",
      "CT-8 DM-20",
      "CT-8 DM-21",
      "CT-8 DM-22",
      "CT-8 EX-9.1",
      "CT-8 EX-9.2",
      "CT-8 EX-9.3",
      "CT-8 EX-9.4",
      "CT-8 EX-14.2",
      "CT-8 EX-A.8",
      "CT-8 EX-A.9"
    ],
    "preconditions": [
      "Vecteurs `ct-8/dimensionnement` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "`dimensionner` sur chaque cas ; recalcul des tables ; refus d'EX-9.3 ; coefficients remplacés ; mesures de 9.2 rejouées sur les vecteurs, `b_cap` relu dans le rapport de mesure de TM-31."
    ],
    "oracle": "Égalité exacte à l'octet ; `b_pt = 682`, `b_man = 916`, `b_tsr_sup = 9` recalculés sur les vecteurs ; `b_cap = 123 761` relu dans le rapport de TM-31 (`mesures/rapport-2026-11-02-capture-bloc-plein.json` : ligne `b_cap_bloc_plein`, trois échantillons de 109 479 octets, soit en-tête 5 846, certificat 32 587 et 64 reçus 71 046, plus 14 282 octets d'index relevés dans `notes`), égal à la constante du calculateur ; fichiers les plus grands de `ct-6/registre/capture/`, blocs d'une transaction : en-tête 1 498, certificat 7 782, reçu 1 816 (celui d'une clôture, réserve de CT-8 §9.2).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/deploiement.test.js",
          "describe": "CT-8 §9 et annexe A.5 : dimensionnement"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/deploiement.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-67",
    "level": "TV",
    "title": "Table de traçabilité de CT-8 : `renvois.mjs`, TC-1 à TC-115",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 TC-1",
      "CT-8 TC-2",
      "CT-8 TC-3",
      "CT-8 TC-4",
      "CT-8 TC-5",
      "CT-8 TC-6",
      "CT-8 TC-7",
      "CT-8 TC-8",
      "CT-8 TC-9",
      "CT-8 TC-10",
      "CT-8 TC-11",
      "CT-8 TC-12",
      "CT-8 TC-13",
      "CT-8 TC-14",
      "CT-8 TC-15",
      "CT-8 TC-16",
      "CT-8 TC-17",
      "CT-8 TC-18",
      "CT-8 TC-19",
      "CT-8 TC-20",
      "CT-8 TC-21",
      "CT-8 TC-22",
      "CT-8 TC-23",
      "CT-8 TC-24",
      "CT-8 TC-25",
      "CT-8 TC-26",
      "CT-8 TC-27",
      "CT-8 TC-28",
      "CT-8 TC-29",
      "CT-8 TC-30",
      "CT-8 TC-31",
      "CT-8 TC-32",
      "CT-8 TC-33",
      "CT-8 TC-34",
      "CT-8 TC-35",
      "CT-8 TC-36",
      "CT-8 TC-37",
      "CT-8 TC-38",
      "CT-8 TC-39",
      "CT-8 TC-40",
      "CT-8 TC-41",
      "CT-8 TC-42",
      "CT-8 TC-43",
      "CT-8 TC-44",
      "CT-8 TC-45",
      "CT-8 TC-46",
      "CT-8 TC-47",
      "CT-8 TC-48",
      "CT-8 TC-49",
      "CT-8 TC-50",
      "CT-8 TC-51",
      "CT-8 TC-52",
      "CT-8 TC-53",
      "CT-8 TC-54",
      "CT-8 TC-55",
      "CT-8 TC-56",
      "CT-8 TC-57",
      "CT-8 TC-58",
      "CT-8 TC-59",
      "CT-8 TC-60",
      "CT-8 TC-61",
      "CT-8 TC-62",
      "CT-8 TC-63",
      "CT-8 TC-64",
      "CT-8 TC-65",
      "CT-8 TC-66",
      "CT-8 TC-67",
      "CT-8 TC-68",
      "CT-8 TC-69",
      "CT-8 TC-70",
      "CT-8 TC-71",
      "CT-8 TC-72",
      "CT-8 TC-73",
      "CT-8 TC-74",
      "CT-8 TC-75",
      "CT-8 TC-76",
      "CT-8 TC-77",
      "CT-8 TC-78",
      "CT-8 TC-79",
      "CT-8 TC-80",
      "CT-8 TC-81",
      "CT-8 TC-82",
      "CT-8 TC-83",
      "CT-8 TC-84",
      "CT-8 TC-85",
      "CT-8 TC-86",
      "CT-8 TC-87",
      "CT-8 TC-88",
      "CT-8 TC-89",
      "CT-8 TC-90",
      "CT-8 TC-91",
      "CT-8 TC-92",
      "CT-8 TC-93",
      "CT-8 TC-94",
      "CT-8 TC-95",
      "CT-8 TC-96",
      "CT-8 TC-97",
      "CT-8 TC-98",
      "CT-8 TC-99",
      "CT-8 TC-100",
      "CT-8 TC-101",
      "CT-8 TC-102",
      "CT-8 TC-103",
      "CT-8 TC-104",
      "CT-8 TC-105",
      "CT-8 TC-106",
      "CT-8 TC-107",
      "CT-8 TC-108",
      "CT-8 TC-109",
      "CT-8 TC-110",
      "CT-8 TC-111",
      "CT-8 TC-112",
      "CT-8 TC-113",
      "CT-8 TC-114",
      "CT-8 TC-115",
      "CT-8 EX-0.1",
      "CT-8 EX-0.2",
      "CT-8 EX-A.2",
      "CT-8 EX-A.3"
    ],
    "preconditions": [
      "Spécifications `spec/*.md` au commit éprouvé."
    ],
    "steps": [
      "`npm run deploiement:renvois` ; identifiants cités vérifiés."
    ],
    "oracle": "Chaque occurrence de « CT-8 » a sa ligne, TC- consécutifs, code 0.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/deploiement.test.js",
          "describe": "CT-8 §0.2 et annexe A.2 : renvois vers CT-8"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/deploiement.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-68",
    "level": "TV",
    "title": "Chaînes interdites dans `deploiement/` et `spec/vecteurs/ct-8/`",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 EX-A.17"
    ],
    "preconditions": [
      "Arbre du dépôt au commit éprouvé."
    ],
    "steps": [
      "Parcourir les fichiers."
    ],
    "oracle": "Aucun chemin personnel ou temporaire, aucune adresse IPv4 hors des plages admises, aucun condensé réel.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/deploiement.test.js",
          "describe": "CT-8 EX-A.17 : chaînes interdites dans deploiement/ et spec/vecteurs/ct-8/"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/deploiement.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-69",
    "level": "TV",
    "title": "`ct-8/observation/` : marques, correspondance avec CT-3, journal d'exemple, rapport, OB-1 à OB-6",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 OB-1",
      "CT-8 OB-2",
      "CT-8 OB-3",
      "CT-8 OB-4",
      "CT-8 OB-5",
      "CT-8 OB-6",
      "CT-8 EX-12.1",
      "CT-8 EX-12.3",
      "CT-8 EX-12.4",
      "CT-8 EX-12.5",
      "CT-8 EX-12.6",
      "CT-8 EX-12.7",
      "CT-8 EX-12.8",
      "CT-8 EX-12.9",
      "CT-8 EX-12.10",
      "CT-8 EX-12.11",
      "CT-8 EX-12.12",
      "CT-8 EX-12.13",
      "CT-8 EX-12.14",
      "CT-8 EX-12.15",
      "CT-8 EX-12.16",
      "CT-8 EX-A.10",
      "CT-8 EX-A.11",
      "CT-8 EX-A.12",
      "CT-8 EX-A.13"
    ],
    "preconditions": [
      "Vecteurs `ct-8/observation` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Reproduire le journal d'exemple (10 086 octets) ; OB-1 sur `marques.json` ; OB-6 sur `correspondance.json` ; `rapport-observation.mjs` sur le journal et les cas invalides ; dossiers de seq 1 et 3 vérifiés par CT-6."
    ],
    "oracle": "SHA-256 et rapport égaux à EX-A.8 ; anomalies attendues ; dossiers valides.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/exploitation.test.js",
          "describe": "CT-8 §12 et annexe A.8 : famille observation/"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/exploitation.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-70",
    "level": "TV",
    "title": "`ct-8/journaux/`, `proces-verbaux/`, `consultations/` : vérification de journal, PV-1 à PV-10, CA-1 à CA-6, runbooks SV-8",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 PV-1",
      "CT-8 PV-2",
      "CT-8 PV-3",
      "CT-8 PV-4",
      "CT-8 PV-5",
      "CT-8 PV-6",
      "CT-8 PV-7",
      "CT-8 PV-8",
      "CT-8 PV-9",
      "CT-8 PV-10",
      "CT-8 CA-1",
      "CT-8 CA-2",
      "CT-8 CA-3",
      "CT-8 CA-4",
      "CT-8 CA-5",
      "CT-8 CA-6",
      "CT-8 SV-8",
      "CT-8 EX-11.7",
      "CT-8 EX-11.18",
      "CT-8 EX-11.20",
      "CT-8 EX-10.13",
      "CT-8 EX-10.14",
      "CT-8 EX-A.14",
      "CT-8 EX-A.15",
      "CT-7 EX-8.15"
    ],
    "preconditions": [
      "Vecteurs `ct-8/journaux, proces-verbaux, consultations` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "`verifier-journal.mjs`, `proces-verbal.mjs verifier`, `consultations.mjs verifier` sur chaque cas ; CA-5 avec les enregistrements bruts ; sept rubriques de chaque runbook."
    ],
    "oracle": "Rapport et code attendus (0 valide, 1 invalide) ; un cas invalide par vérification.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/exploitation.test.js",
          "describe": "CT-8 §11 et annexe A.9 : journaux/, proces-verbaux/, consultations/"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/exploitation.test.js"
    },
    "threats": [
      "MN-96"
    ]
  },
  {
    "id": "TV-71",
    "level": "TV",
    "title": "`ct-8/paquets/` : dix-sept cas de `cas.json`, deux constructions identiques, recette GNU tar",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 PR-1",
      "CT-8 PR-2",
      "CT-8 PR-3",
      "CT-8 PR-4",
      "CT-8 PR-5",
      "CT-8 PR-6",
      "CT-8 PR-7",
      "CT-8 PR-8",
      "CT-8 PR-9",
      "CT-8 PR-10",
      "CT-8 PR-11",
      "CT-8 PR-12",
      "CT-8 AV-PR-1",
      "CT-8 AV-PR-2",
      "CT-8 AV-PR-3",
      "CT-8 AV-PR-4",
      "CT-8 EX-13.15",
      "CT-8 EX-A.18",
      "CT-8 EX-A.19",
      "CT-8 EX-A.20",
      "CT-8 EX-A.29",
      "CT-8 EX-A.30",
      "CT-8 EX-A.31",
      "CT-8 EX-A.32",
      "CT-8 EX-A.33",
      "CT-8 EX-A.34",
      "CT-8 EX-A.35"
    ],
    "preconditions": [
      "Vecteurs `ct-8/paquets` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Rejouer chaque cas par l'outil ; construire `valide.tar` deux fois ; recette GNU tar d'EX-13.15 ; comparer le manifeste à l'exemple annoté de 13.3 ; en CI, paquet complet construit deux fois puis vérifié par sa copie jointe sous `unshare -n env -i`."
    ],
    "oracle": "Code, état, statuts PR- et codes des dossiers égaux à `cas.json` ; archives identiques ; code 0 de la copie jointe.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/paquet-reviseur.test.js",
          "describe": "CT-8 : paquet réviseur, vecteurs de la famille paquets (annexe A.10, EX-A.19)"
        }
      ],
      "ci_steps": [
        "paquet réviseur complet, construit deux fois, vérifié par le dépôt puis par sa copie jointe hors réseau"
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/paquet-reviseur.test.js"
    },
    "threats": [
      "MN-78"
    ]
  },
  {
    "id": "TV-72",
    "level": "TV",
    "title": "Matériel des épreuves de CT-8 §14 présent et cohérent : consignes, grilles, entrées de dimensionnement",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 EX-14.1",
      "CT-8 EX-14.2",
      "CT-8 EX-14.11",
      "CT-8 EX-A.1"
    ],
    "preconditions": [
      "Vecteurs `ct-8/acceptation-*` présents au commit éprouvé, régénérés sans différence (TV- de génération déterministe de la même famille).",
      "`npm ci` fait ; aucun réseau."
    ],
    "steps": [
      "Vérifier la présence des consignes et des grilles ; recalculer les totaux de la grille depuis `entrees-dimensionnement.json`."
    ],
    "oracle": "Fichiers présents ; totaux égaux. La conduite des épreuves est un TR-.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/exploitation.test.js",
          "describe": "CT-8 §14 et annexe A.9 : matériel des épreuves"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/exploitation.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-73",
    "level": "TV",
    "title": "Génération déterministe de `spec/vecteurs/ct-8`",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 EX-A.1",
      "CT-8 EX-A.2",
      "CT-8 EX-A.3",
      "CT-8 EX-A.10",
      "CT-8 EX-A.25",
      "CT-8 EX-A.26",
      "CT-8 EX-A.28"
    ],
    "preconditions": [
      "Générateur `scripts/vecteurs/generer-ct8.mjs` au commit éprouvé."
    ],
    "steps": [
      "Deux générations dans des répertoires neufs."
    ],
    "oracle": "Mêmes octets que le dépôt.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/deploiement.test.js",
          "describe": "CT-8 EX-A.1 : générateur des familles de déploiement"
        },
        {
          "file": "test/paquet-reviseur.test.js",
          "describe": "CT-8 : paquet réviseur, vecteurs de la famille paquets (annexe A.10, EX-A.19)",
          "it": "le générateur, rejoué dans un répertoire neuf, écrit les mêmes octets que les vecteurs publiés (EX-A.10)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/deploiement.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-74",
    "level": "TV",
    "title": "Vérificateur Go indépendant de CT-8 : zéro discordance sur `spec/vecteurs/ct-8`",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 DM-1",
      "CT-8 DM-2",
      "CT-8 DM-3",
      "CT-8 DM-4",
      "CT-8 DM-5",
      "CT-8 DM-6",
      "CT-8 DM-7",
      "CT-8 DM-8",
      "CT-8 DM-9",
      "CT-8 DM-10",
      "CT-8 DM-11",
      "CT-8 DM-12",
      "CT-8 DM-13",
      "CT-8 DM-14",
      "CT-8 DM-15",
      "CT-8 DM-16",
      "CT-8 DM-17",
      "CT-8 DM-18",
      "CT-8 DM-19",
      "CT-8 DM-20",
      "CT-8 DM-21",
      "CT-8 DM-22",
      "CT-8 IP-1",
      "CT-8 IP-2",
      "CT-8 IP-3",
      "CT-8 IP-4",
      "CT-8 IP-5",
      "CT-8 IP-6",
      "CT-8 IP-7",
      "CT-8 IP-8",
      "CT-8 IP-9",
      "CT-8 IP-10",
      "CT-8 IP-11",
      "CT-8 IP-12",
      "CT-8 IP-13",
      "CT-8 PV-1",
      "CT-8 PV-2",
      "CT-8 PV-3",
      "CT-8 PV-4",
      "CT-8 PV-5",
      "CT-8 PV-6",
      "CT-8 PV-7",
      "CT-8 PV-8",
      "CT-8 PV-9",
      "CT-8 PV-10",
      "CT-8 CA-1",
      "CT-8 CA-2",
      "CT-8 CA-3",
      "CT-8 CA-4",
      "CT-8 CA-6",
      "CT-8 PR-1",
      "CT-8 PR-2",
      "CT-8 PR-3",
      "CT-8 PR-4",
      "CT-8 PR-5",
      "CT-8 PR-6",
      "CT-8 PR-7",
      "CT-8 PR-8",
      "CT-8 PR-9",
      "CT-8 OB-1",
      "CT-8 OB-2",
      "CT-8 OB-3",
      "CT-8 OB-4",
      "CT-8 EX-A.21",
      "CT-8 EX-A.22",
      "CT-8 EX-A.23",
      "CT-8 EX-A.24"
    ],
    "preconditions": [
      "Go 1.24 (version du `go.mod` du module) ; module `spec/vecteurs/ct-8/verificateur-independant` écrit depuis le seul texte de la spécification, sans lire le code JavaScript."
    ],
    "steps": [
      "`gofmt -l .` vide ; `go vet ./...` ; `go test ./...` ; `go run . ..` depuis le répertoire du module."
    ],
    "oracle": "« 0 discordance » et code 0 ; toute valeur attendue des vecteurs est recalculée et égale.",
    "status": {
      "state": "executable",
      "ci_steps": [
        "vérificateur Go indépendant contre les vecteurs CT-8"
      ],
      "command": "cd spec/vecteurs/ct-8/verificateur-independant && gofmt -l . && go vet ./... && go test ./... && go run . .."
    },
    "threats": [
      "MN-66"
    ]
  },
  {
    "id": "TV-75",
    "level": "TV",
    "title": "Confrontation tierce de `ct-8` : GNU tar, `sha256sum`, `jq`, `tarfile` de Python",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 EX-A.30",
      "CT-8 EX-A.31",
      "CT-8 EX-A.32",
      "CT-8 EX-A.33",
      "CT-8 EX-A.34",
      "CT-8 EX-A.35",
      "CT-8 EX-A.36"
    ],
    "preconditions": [
      "Sorties publiées sous `spec/vecteurs/ct-8/confrontation/`."
    ],
    "steps": [
      "Vérifier les sorties ; rejouer `confronter_gnutar.sh`, `confronter_tarfile.py`, `confronter_sha256sum.sh`, `confronter_consultations.py` quand les outils sont présents."
    ],
    "oracle": "Aucune discordance.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/confrontation.test.js",
          "describe": "CT-8 : sorties publiées de la confrontation des paquets réviseurs par GNU tar et tarfile (EX-A.32 à EX-A.35)"
        },
        {
          "file": "test/confrontation.test.js",
          "describe": "CT-8 : sorties publiées de la confrontation de l'exploitation par sha256sum, jq et Python (EX-A.30)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/confrontation.test.js"
    },
    "threats": []
  },
  {
    "id": "TV-76",
    "level": "TV",
    "title": "`ct-8/supervision/` : SV-1 à SV-7, règles d'alerte, extracteur, tableau de bord",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 SV-1",
      "CT-8 SV-2",
      "CT-8 SV-3",
      "CT-8 SV-4",
      "CT-8 SV-5",
      "CT-8 SV-6",
      "CT-8 SV-7",
      "CT-8 EX-10.10",
      "CT-8 EX-10.11",
      "CT-8 EX-A.27"
    ],
    "preconditions": [
      "Fichiers `deploiement/observabilite/`, `extraire-journaux.mjs`, `regles.mjs`, `sonde.mjs` et la famille `supervision/` (CT-8 §10, livrés à l'étape 7) ; `promtool` 3.5.0 de l'archive officielle de Prometheus à SHA-256 fixé (CT-8 EX-10.10), fourni par l'intégration continue (`NOORTRACE_PROMTOOL`) ; sans lui, l'essai `promtool` est en attente, condition nommée (EX-3.11)."
    ],
    "steps": [
      "Rejouer l'extracteur sur `supervision/journaux/` ; régénérer le fichier de règles ; `promtool check rules` puis `promtool test rules` (archive de Prometheus d'EX-10.10 au SHA-256 fixé)."
    ],
    "oracle": "Sorties égales aux vecteurs ; chaque alerte prescrite présente ; `promtool` code 0.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/deploiement-supervision.test.js",
          "describe": "CT-8 §10.3 : extracteur des journaux (SV-5, EX-10.5)",
          "it": "TV-76 : supervision/ — l'extracteur rejoué sur journaux/ rend attendu.prom (SV-5), regles.mjs rend le fichier du dépôt et regles-attendues.yml (SV-6), chaque alerte prescrite a sa règle (SV-1)"
        },
        {
          "file": "test/deploiement-supervision.test.js",
          "describe": "CT-8 §10.10, EX-A.27 : promtool 3.5.0 (confrontation tierce, EX-A.31)",
          "it": "TV-76, EX-10.10 : promtool check rules sur regles-noortrace.yml puis promtool test rules sur tests-regles.yml, code 0"
        },
        {
          "file": "test/deploiement-supervision.test.js",
          "describe": "CT-8 §10.4 à §10.7 : règles d'alerte de référence (SV-1 à SV-4)"
        },
        {
          "file": "test/deploiement-supervision.test.js",
          "describe": "CT-8 EX-10.6 : générateur des règles (SV-6)"
        },
        {
          "file": "test/deploiement-supervision.test.js",
          "describe": "CT-8 §10.8, EX-10.4 : tableau de bord et collecte de référence (SV-7)"
        }
      ],
      "ci_steps": [
        "promtool 3.5.0 (CT-8 EX-10.10, EX-A.27), règles d'alerte de référence vérifiées et testées"
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/deploiement-supervision.test.js"
    },
    "threats": [
      "MN-29"
    ]
  }
];
