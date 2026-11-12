// Source de données du catalogue CT-9 : entrées TQ- (section 13), telles
// qu'elles sont imprimées dans spec/vecteurs/ct-9/catalogue.json.

export const TQ = [
  {
    "id": "TQ-1",
    "level": "TQ",
    "title": "Revue de code de l'enregistreur : frontal MCP, passerelle, SDK et ingestion, écrivain et stockage, WORM, clés (CT-7 §3.2 ; CT-2 §18)",
    "specs": [
      "CT-7",
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-18.1",
      "CT-2 EX-18.2",
      "CT-2 EX-18.3",
      "CT-2 EX-18.4",
      "CT-2 EX-18.5",
      "CT-2 EX-18.9",
      "CT-2 EX-18.6",
      "CT-2 EX-18.7",
      "CT-2 EX-18.8",
      "CT-2 EX-11.1",
      "CT-2 EX-11.2",
      "CT-2 EX-11.3",
      "CT-2 EX-11.4",
      "CT-2 EX-11.5",
      "CT-2 EX-11.6",
      "CT-2 EX-11.7",
      "CT-2 EX-11.8",
      "CT-2 EX-11.9",
      "CT-2 EX-11.10",
      "CT-2 EX-11.11",
      "CT-2 EX-11.12",
      "CT-2 EX-11.13",
      "CT-2 EX-11.14",
      "CT-2 EX-11.19",
      "CT-2 EX-11.15",
      "CT-2 EX-11.16",
      "CT-2 EX-11.17",
      "CT-2 EX-11.18",
      "CT-7 EX-3.3",
      "CT-7 EX-3.4",
      "CT-7 EX-3.5",
      "CT-7 EX-3.6",
      "CT-7 EX-3.7",
      "CT-7 EX-3.8",
      "CT-7 EX-3.9",
      "CT-7 EX-3.10",
      "CT-7 EX-3.11",
      "CT-7 EX-3.12",
      "CT-7 EX-3.13",
      "CT-7 EX-3.14",
      "CT-7 EX-3.15",
      "CT-2 EX-4.39",
      "CT-2 EX-4.40",
      "CT-2 EX-4.41",
      "CT-2 EX-5.3",
      "CT-2 EX-5.8",
      "CT-2 EX-3.2"
    ],
    "preconditions": [
      "Code du composant au commit éprouvé ; relecteur qui n'a pas écrit le code ; modèle de menace `menaces.json` et catalogue CT-9 sous la main."
    ],
    "steps": [
      "Pour chaque menace du composant (colonne `component` de `menaces.json`), localiser la réponse dans le code (fichier, fonction) et le TA- qui la tue.",
      "Relire chaque limite de confiance de CT-7 §3.2 : validation des entrées, secrets jamais journalisés, erreurs sans exception vers l'appelant.",
      "Consigner la grille remplie et les écarts (fichier, ligne, menace, décision)."
    ],
    "oracle": "Grille complète : zéro menace du composant sans réponse localisée, zéro réponse sans TA- qui échoue quand elle est retirée ; tout écart devient une correction tracée ou un risque accepté nommé, borné, attribué (CT-7 §3.5).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "CT-7 §10 : « aucune revue n'a été faite pour cette version » ; le démon de l'étape 4 n'existe pas ; les bibliothèques `scripts/lib/capture.mjs`, `journal.mjs`, `otel.mjs`, `worm.mjs` peuvent être relues dès maintenant selon la même grille."
    },
    "threats": [
      "MN-1",
      "MN-2",
      "MN-7",
      "MN-8",
      "MN-9",
      "MN-10",
      "MN-11",
      "MN-12",
      "MN-13",
      "MN-14",
      "MN-15",
      "MN-16",
      "MN-17",
      "MN-18",
      "MN-19",
      "MN-20",
      "MN-21",
      "MN-22",
      "MN-23",
      "MN-24",
      "MN-25",
      "MN-26",
      "MN-27",
      "MN-28",
      "MN-29",
      "MN-30",
      "MN-31",
      "MN-33",
      "MN-43",
      "MN-99"
    ],
    "review": {
      "components": [
        "hote_agent",
        "mandataire_mcp",
        "passerelle_modele",
        "sdk_otel",
        "ecrivain_stockage",
        "worm_gel",
        "cles"
      ],
      "scope": [
        "scripts/lib/capture.mjs",
        "scripts/lib/journal.mjs",
        "scripts/lib/otel.mjs",
        "scripts/lib/worm.mjs",
        "démon de la phase 2 (étape 4)"
      ],
      "grid": [
        "Chaque MN- du composant a sa réponse localisée (fichier, fonction).",
        "Chaque entrée venue d'une limite de confiance de CT-7 §3.2 est validée avant usage.",
        "Aucun secret de l'inventaire CLE- n'est écrit dans un journal, une erreur ou une pièce.",
        "Surface d'écoute et surface sortante égales à CT-2 EX-18.1 et EX-18.2.",
        "Aucune relance autonome vers un fournisseur (CT-2 §5.7)."
      ]
    }
  },
  {
    "id": "TQ-2",
    "level": "TQ",
    "title": "Revue de code du service d'approbation et de la console (CT-7 §3.2 `approbation_console` ; CT-3 §14)",
    "specs": [
      "CT-7",
      "CT-3"
    ],
    "covers": [
      "CT-3 EX-14.2",
      "CT-3 EX-3.2",
      "CT-3 EX-3.3",
      "CT-3 EX-3.4"
    ],
    "preconditions": [
      "Code du composant au commit éprouvé ; relecteur qui n'a pas écrit le code ; modèle de menace `menaces.json` et catalogue CT-9 sous la main."
    ],
    "steps": [
      "Pour chaque menace du composant (colonne `component` de `menaces.json`), localiser la réponse dans le code (fichier, fonction) et le TA- qui la tue.",
      "Relire chaque limite de confiance de CT-7 §3.2 : validation des entrées, secrets jamais journalisés, erreurs sans exception vers l'appelant.",
      "Consigner la grille remplie et les écarts (fichier, ligne, menace, décision)."
    ],
    "oracle": "Grille complète : zéro menace du composant sans réponse localisée, zéro réponse sans TA- qui échoue quand elle est retirée ; tout écart devient une correction tracée ou un risque accepté nommé, borné, attribué (CT-7 §3.5).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Service et console d'exploitation non construits ; `scripts/lib/approbation.mjs`, `scripts/lib/console.mjs` et `console/` relus dès maintenant."
    },
    "threats": [
      "MN-35",
      "MN-44",
      "MN-45",
      "MN-46",
      "MN-47",
      "MN-48",
      "MN-49",
      "MN-50",
      "MN-51",
      "MN-52",
      "MN-100"
    ],
    "review": {
      "components": [
        "approbation_console"
      ],
      "scope": [
        "scripts/lib/approbation.mjs",
        "scripts/lib/console.mjs",
        "console/",
        "service et console de la phase 2 (étape 6)"
      ],
      "grid": [
        "Aucune clé d'approbateur dans le service (CT-3 EX-3.3, EX-3.4).",
        "Réponses du service traitées comme non signées par le noyau ; remises vérifiées par SG-1 à SG-7 seulement.",
        "Console : aucune importation, aucun `eval`, aucun `innerHTML`, intégrité des scripts (CT-3 EX-13.31 à EX-13.35).",
        "Chaque MN- du composant localisée et tuée par son TA-."
      ]
    }
  },
  {
    "id": "TQ-3",
    "level": "TQ",
    "title": "Revue de code du registre et de l'exploitant : contrats, outil de référence, image du nœud, publication (CT-7 §3.2 `registre`, `exploitant` ; CT-4 §12)",
    "specs": [
      "CT-7",
      "CT-4"
    ],
    "covers": [
      "CT-4 §12",
      "CT-7 EX-8.9"
    ],
    "preconditions": [
      "Code du composant au commit éprouvé ; relecteur qui n'a pas écrit le code ; modèle de menace `menaces.json` et catalogue CT-9 sous la main."
    ],
    "steps": [
      "Pour chaque menace du composant (colonne `component` de `menaces.json`), localiser la réponse dans le code (fichier, fonction) et le TA- qui la tue.",
      "Relire chaque limite de confiance de CT-7 §3.2 : validation des entrées, secrets jamais journalisés, erreurs sans exception vers l'appelant.",
      "Consigner la grille remplie et les écarts (fichier, ligne, menace, décision)."
    ],
    "oracle": "Grille complète : zéro menace du composant sans réponse localisée, zéro réponse sans TA- qui échoue quand elle est retirée ; tout écart devient une correction tracée ou un risque accepté nommé, borné, attribué (CT-7 §3.5).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Revue non faite ; les contrats et `scripts/registre/noortrace-registre.mjs` sont relisibles dès maintenant."
    },
    "threats": [
      "MN-53",
      "MN-54",
      "MN-55",
      "MN-56",
      "MN-57",
      "MN-58",
      "MN-59",
      "MN-71",
      "MN-72",
      "MN-73",
      "MN-97"
    ],
    "review": {
      "components": [
        "registre",
        "exploitant"
      ],
      "scope": [
        "contracts/",
        "scripts/registre/noortrace-registre.mjs",
        "scripts/lib/conventions-registre.mjs",
        "chain/docker/"
      ],
      "grid": [
        "Aucun outil ne s'appuie sur `finalized`, `safe` ni `eth_subscribe` (CT-4 EX-4.14, EX-5.11).",
        "Chaque envoi écrit avant soumission (CT-4 EX-7.5) ; aucune valeur secrète dans le dossier remis (EX-7.12).",
        "Images de base épinglées par condensé (CT-8 PD-8).",
        "Chaque MN- du composant localisée et tuée par son TA-."
      ]
    }
  },
  {
    "id": "TQ-4",
    "level": "TQ",
    "title": "Revue de code du composant d'ancrage (CT-7 §3.2 `ancrage` ; CT-5 §13)",
    "specs": [
      "CT-7",
      "CT-5"
    ],
    "covers": [
      "CT-5 EX-13.1",
      "CT-5 AN-43"
    ],
    "preconditions": [
      "Code du composant au commit éprouvé ; relecteur qui n'a pas écrit le code ; modèle de menace `menaces.json` et catalogue CT-9 sous la main."
    ],
    "steps": [
      "Pour chaque menace du composant (colonne `component` de `menaces.json`), localiser la réponse dans le code (fichier, fonction) et le TA- qui la tue.",
      "Relire chaque limite de confiance de CT-7 §3.2 : validation des entrées, secrets jamais journalisés, erreurs sans exception vers l'appelant.",
      "Consigner la grille remplie et les écarts (fichier, ligne, menace, décision)."
    ],
    "oracle": "Grille complète : zéro menace du composant sans réponse localisée, zéro réponse sans TA- qui échoue quand elle est retirée ; tout écart devient une correction tracée ou un risque accepté nommé, borné, attribué (CT-7 §3.5).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Composant non construit ; `scripts/lib/ancrage.mjs` relisible dès maintenant."
    },
    "threats": [
      "MN-60",
      "MN-61",
      "MN-62",
      "MN-63",
      "MN-64",
      "MN-65",
      "MN-76"
    ],
    "review": {
      "components": [
        "ancrage"
      ],
      "scope": [
        "scripts/lib/ancrage.mjs",
        "composant d'ancrage de la phase 2 (étape 5)"
      ],
      "grid": [
        "Aucune clé Ed25519 ni clé de chaîne dans le composant (CT-7 §3.2).",
        "Aucun secret dans la file ni le journal (CT-5 AN-43).",
        "Ligne `envoyee` écrite avant tout envoi (AN-32).",
        "Chaque MN- du composant localisée et tuée par son TA-."
      ]
    }
  },
  {
    "id": "TQ-5",
    "level": "TQ",
    "title": "Revue de code du vérificateur et indépendance des vérificateurs Go (CT-7 §3.2 `verificateur` ; CT-6 §15)",
    "specs": [
      "CT-7",
      "CT-6",
      "CT-5"
    ],
    "covers": [
      "CT-6 EX-15.1",
      "CT-6 EX-15.2",
      "CT-6 EX-15.3",
      "CT-6 EX-3.1",
      "CT-6 EX-3.4",
      "CT-6 EX-3.5",
      "CT-6 EX-3.6",
      "CT-6 EX-3.7",
      "CT-6 EX-3.8",
      "CT-5 EX-A.5",
      "CT-7 EX-8.11"
    ],
    "preconditions": [
      "Code du composant au commit éprouvé ; relecteur qui n'a pas écrit le code ; modèle de menace `menaces.json` et catalogue CT-9 sous la main."
    ],
    "steps": [
      "Pour chaque menace du composant (colonne `component` de `menaces.json`), localiser la réponse dans le code (fichier, fonction) et le TA- qui la tue.",
      "Relire chaque limite de confiance de CT-7 §3.2 : validation des entrées, secrets jamais journalisés, erreurs sans exception vers l'appelant.",
      "Consigner la grille remplie et les écarts (fichier, ligne, menace, décision).",
      "Relire chaque module `verificateur-independant/` : aucune importation ni recopie du code JavaScript ; pour `ct-5`, relecture à l'aveugle de la partie que son README déclare non écrite à l'aveugle (R10-F35)."
    ],
    "oracle": "Grille complète : zéro menace du composant sans réponse localisée, zéro réponse sans TA- qui échoue quand elle est retirée ; tout écart devient une correction tracée ou un risque accepté nommé, borné, attribué (CT-7 §3.5). Pour les modules Go : attestation écrite du relecteur que le code ne reprend rien du JavaScript, ou retrait de la mention « indépendant » du README.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Revue non faite ; `scripts/lib/verificateur.mjs`, `horodatage.mjs`, `ots.mjs`, `registre.mjs`, `scripts/verify/dossier.mjs` et les sept modules Go relisibles dès maintenant."
    },
    "threats": [
      "MN-66",
      "MN-67",
      "MN-68",
      "MN-69",
      "MN-70",
      "MN-78",
      "MN-79",
      "MN-80",
      "MN-81",
      "MN-83",
      "MN-89",
      "MN-101"
    ],
    "review": {
      "components": [
        "verificateur"
      ],
      "scope": [
        "scripts/lib/verificateur.mjs",
        "scripts/lib/horodatage.mjs",
        "scripts/lib/ots.mjs",
        "scripts/lib/registre.mjs",
        "scripts/verify/dossier.mjs",
        "spec/vecteurs/ct-*/verificateur-independant/"
      ],
      "grid": [
        "Lecture bornée de chaque entrée (CT-6 EX-4.11, EX-4.13, EX-4.15) ; jamais une exception, toujours un statut (EX-15.2).",
        "Aucun accès réseau ; déterminisme (EX-3.2, EX-3.3).",
        "Aucun texte du rapport n'applique « prouvé », « vérifié » ou « conforme » au périmètre (CT-6 EX-7.3).",
        "Modules Go : bibliothèque standard seule, aucun fichier JavaScript lu ni recopié."
      ]
    }
  },
  {
    "id": "TQ-6",
    "level": "TQ",
    "title": "Revue des fichiers de déploiement et de la configuration de l'administrateur du client (CT-7 §3.2 `administrateur_client`, `reseau` ; CT-8 §3, §5)",
    "specs": [
      "CT-7",
      "CT-8"
    ],
    "covers": [
      "CT-8 EX-5.1",
      "CT-8 EX-5.2",
      "CT-8 EX-5.3",
      "CT-8 EX-5.4",
      "CT-8 EX-5.6",
      "CT-8 EX-5.7"
    ],
    "preconditions": [
      "Code du composant au commit éprouvé ; relecteur qui n'a pas écrit le code ; modèle de menace `menaces.json` et catalogue CT-9 sous la main."
    ],
    "steps": [
      "Pour chaque menace du composant (colonne `component` de `menaces.json`), localiser la réponse dans le code (fichier, fonction) et le TA- qui la tue.",
      "Relire chaque limite de confiance de CT-7 §3.2 : validation des entrées, secrets jamais journalisés, erreurs sans exception vers l'appelant.",
      "Consigner la grille remplie et les écarts (fichier, ligne, menace, décision)."
    ],
    "oracle": "Grille complète : zéro menace du composant sans réponse localisée, zéro réponse sans TA- qui échoue quand elle est retirée ; tout écart devient une correction tracée ou un risque accepté nommé, borné, attribué (CT-7 §3.5).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Revue non faite ; `deploiement/` relisible dès maintenant (vérifications CO- déjà exécutées)."
    },
    "threats": [
      "MN-74",
      "MN-75",
      "MN-77",
      "MN-82",
      "MN-84",
      "MN-85",
      "MN-86",
      "MN-87",
      "MN-88",
      "MN-90",
      "MN-91",
      "MN-96",
      "MN-98",
      "MN-102"
    ],
    "review": {
      "components": [
        "administrateur_client",
        "reseau"
      ],
      "scope": [
        "deploiement/compose/",
        "deploiement/config/",
        "deploiement/images/images.json"
      ],
      "grid": [
        "TLS ou prise locale authentifiée partout où un secret ou une décision circule (CT-7 §3.2).",
        "Aucun port publié hors de ceux de CT-8 §3 ; flux égaux à FL-1 à FL-31.",
        "Aucune adresse réelle, aucun secret dans le dépôt (CT-8 EX-A.17).",
        "Chaque MN- du composant localisée et tuée par son TA-."
      ]
    }
  },
  {
    "id": "TQ-7",
    "level": "TQ",
    "title": "Inventaire des clés et des secrets à jour : chaque clé ou secret introduit par une révision a sa ligne CLE- (CT-7 §4.1)",
    "specs": [
      "CT-7"
    ],
    "covers": [
      "CT-7 CLE-1",
      "CT-7 CLE-2",
      "CT-7 CLE-3",
      "CT-7 CLE-4",
      "CT-7 CLE-5",
      "CT-7 CLE-6",
      "CT-7 CLE-7",
      "CT-7 CLE-8",
      "CT-7 CLE-9",
      "CT-7 CLE-10",
      "CT-7 CLE-11",
      "CT-7 CLE-12",
      "CT-7 CLE-13",
      "CT-7 CLE-14",
      "CT-7 CLE-15",
      "CT-7 CLE-16",
      "CT-7 CLE-17",
      "CT-7 CLE-18",
      "CT-7 CLE-19",
      "CT-7 CLE-20",
      "CT-7 CLE-21",
      "CT-7 CLE-22",
      "CT-7 CLE-23",
      "CT-7 CLE-24",
      "CT-7 CLE-25",
      "CT-7 CLE-26",
      "CT-7 CLE-27",
      "CT-7 CLE-28",
      "CT-7 CLE-29",
      "CT-7 CLE-30",
      "CT-7 CLE-31",
      "CT-7 CLE-32",
      "CT-7 CLE-33",
      "CT-7 CLE-34",
      "CT-7 CLE-35",
      "CT-7 CLE-36",
      "CT-7 EX-4.1",
      "CT-7 EX-4.2",
      "CT-7 EX-4.3",
      "CT-7 EX-4.4",
      "CT-7 EX-4.5",
      "CT-7 EX-4.6",
      "CT-7 EX-4.7",
      "CT-7 EX-4.8",
      "CT-7 EX-4.9",
      "CT-7 EX-4.10"
    ],
    "preconditions": [
      "Texte de CT-1 à CT-8 au commit éprouvé ; table CT-7 §4.2."
    ],
    "steps": [
      "Relever chaque mention de clé, jeton, mot de passe, certificat, identifiant d'accès dans les huit spécifications ; la rapprocher d'une ligne CLE- ; vérifier classe admise (4.3), période et sauvegarde (4.4), conduite sur compromission (4.6)."
    ],
    "oracle": "Zéro clé ou secret sans ligne CLE- ; zéro ligne CLE- sans usage dans une spécification ; classes conformes à 4.3.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Revue de texte réalisable dès maintenant, non faite ; CT-7 §4.1 : « la revue de CT-9 le contrôle »."
    },
    "threats": [
      "MN-30",
      "MN-31",
      "MN-39",
      "MN-43"
    ],
    "review": {
      "components": [
        "cles"
      ],
      "scope": [
        "spec/CT-1-evenements-et-formats.md à spec/CT-8-deploiement-et-exploitation.md",
        "spec/CT-7-securite-et-conformite.md §4.2"
      ],
      "grid": [
        "Chaque clé ou secret nommé par une spécification a sa ligne CLE-.",
        "Chaque ligne CLE- cite une spécification qui l'emploie.",
        "Classe de garde admise pour l'usage et l'environnement (4.3).",
        "Conduite sur compromission écrite pour chaque clé de signature (4.6)."
      ]
    }
  },
  {
    "id": "TQ-8",
    "level": "TQ",
    "title": "Revue de la chaîne de construction et de publication des images : version publiée malveillante (RA-22, CT-8 §3.6)",
    "specs": [
      "CT-7",
      "CT-8"
    ],
    "covers": [
      "CT-7 EX-3.9",
      "CT-7 EX-3.14",
      "CT-8 EX-3.13",
      "CT-8 EX-3.14",
      "CT-8 EX-3.15"
    ],
    "preconditions": [
      "Fichiers de construction des images ; journal de la CI ; deux constructions indépendantes (TE- construction)."
    ],
    "steps": [
      "Relire les fichiers de construction : sources épinglées par condensé, aucune étape qui télécharge sans vérification, aucune clé embarquée ; comparer la provenance publiée aux constructions indépendantes."
    ],
    "oracle": "Chaque entrée de construction épinglée ; empreintes publiées égales aux deux constructions ; écart = RA-22 réalisé, à traiter avant publication.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Rattaché à l'étape 8 : revue humaine par une personne qui n'a pas écrit le code (EX-13.1) des fichiers de construction des images (`conteneurs/`), du script de construction double et du travail de version ; la partie mécanique est éprouvée à l'étape 7 par test/publication-etape7.test.js (binaire et archive : entrées épinglées, aucune clé, empreintes de la note égales aux deux constructions) et par la construction double des images."
    },
    "threats": [
      "MN-25"
    ],
    "review": {
      "components": [
        "exploitant",
        "ecrivain_stockage"
      ],
      "scope": [
        "fichiers de construction des images noortrace/*",
        ".github/workflows/ci.yml",
        ".github/workflows/version.yml",
        "scripts/publication/",
        "conteneurs/",
        "scripts/deploiement/construire-images.mjs"
      ],
      "grid": [
        "Sources et images de base épinglées par condensé.",
        "Construction reproductible : deux constructions, mêmes condensés.",
        "Aucune clé ni secret dans une image.",
        "Empreintes publiées égales aux constructions."
      ]
    }
  }
];
