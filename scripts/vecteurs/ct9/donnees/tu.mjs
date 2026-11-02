// Source de données du catalogue CT-9 : entrées TU- (section 6), telles
// qu'elles sont imprimées dans spec/vecteurs/ct-9/catalogue.json.

export const TU = [
  {
    "id": "TU-1",
    "level": "TU",
    "title": "JCS v0 : forme canonique restreinte aux entiers (CT-1 §4)",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 E-2",
      "CT-1 §4"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/journal.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Canonicaliser les cas limites de la section 4, les exemples de la RFC 8785 (§3.2.3, tri par unités UTF-16) et les événements des vecteurs.",
      "Soumettre à l'analyseur strict `412.0`, `1e3`, un entier hors intervalle, une clé en double, un substitut isolé, une marque d'ordre d'octets."
    ],
    "oracle": "Octets de la forme canonique égaux à ceux imprimés par CT-1 §4 et par la RFC 8785 ; chaque entrée invalide refusée (E-2) ; égalité avec `JSON.stringify` après tri récursif des clés.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : forme canonique JCS v0 (RFC 8785 restreinte aux entiers)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": [
      "MN-4"
    ]
  },
  {
    "id": "TU-2",
    "level": "TU",
    "title": "Ed25519 (RFC 8032) et dérivation des clés de test (CT-1 §6.2, §13)",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 §6.2",
      "CT-1 §13"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/journal.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Rejouer TEST 1, 2 et 3 de la RFC 8032 §7.1.",
      "Soumettre une signature altérée, un `S` non réduit, une clé de petit ordre, des longueurs fausses.",
      "Dériver les clés de test depuis les graines de CT-1 §13."
    ],
    "oracle": "Clé publique, signature et verdict égaux aux vecteurs de la RFC ; chaque entrée fautive refusée ; clés dérivées égales à `cles/cles-test.json`.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : Ed25519 (RFC 8032)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": []
  },
  {
    "id": "TU-3",
    "level": "TU",
    "title": "Événement : hachage, signature, approbation, rotation, pièces (CT-1 §5 à §8)",
    "specs": [
      "CT-1"
    ],
    "covers": [
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
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/journal.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Reproduire l'exemple de référence de l'annexe A valeur par valeur.",
      "Recalculer `JCS(A)`, `D_A`, les signatures EIP-191 des comptes Hardhat 1 et 2 et leur recouvrement.",
      "Sceller un événement, le modifier d'un octet, demander les contrôles."
    ],
    "oracle": "Valeurs égales à l'annexe A ; toute modification détectée ; `controlesEvenement` nomme exactement le contrôle en échec parmi E-3 à E-11.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : événements, hachage, signature, approbation, rotation"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": [
      "MN-84",
      "MN-90"
    ]
  },
  {
    "id": "TU-4",
    "level": "TU",
    "title": "Chaînage : `seq`, `prev_hash`, diagnostics nommés (CT-1 §7)",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 C-1",
      "CT-1 C-2",
      "CT-1 C-3"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/journal.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Reconstruire le journal des vecteurs depuis ses corps.",
      "Supprimer, modifier, insérer, réordonner un événement ; faire décroître `ts` ; changer de journal, de clé, d'origine ; rompre après rescellement."
    ],
    "oracle": "Hachages égaux à `attendu.json` ; chaque altération produit le diagnostic nommé par la table 7.2.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : chaînage"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": [
      "MN-17"
    ]
  },
  {
    "id": "TU-5",
    "level": "TU",
    "title": "Arbre de Merkle RFC 6962, preuves d'inclusion, période vide (CT-1 §9)",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 M-1",
      "CT-1 M-2",
      "CT-1 M-3",
      "CT-1 P-4"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/journal.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Calculer les racines et chemins d'audit des vecteurs de Certificate Transparency (1 à 8 feuilles) et vérifier RFC 9162 pour tout (m, n) ≤ 8.",
      "Calculer la racine de la période vide et l'exemple de §9.4."
    ],
    "oracle": "Racines et chemins égaux aux vecteurs CT ; racine nulle pour la période vide, distincte de `SHA-256(\"\")` ; valeurs de §9.4 reproduites.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : arbre de Merkle RFC 6962 et preuves d'inclusion"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": []
  },
  {
    "id": "TU-6",
    "level": "TU",
    "title": "Preuve de cohérence RFC 9162 §2.1.4 et points de contrôle (CT-1 §10.5 à §10.8)",
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
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/journal.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Calculer PROOF(m, D[n]) pour toute paire 1 ≤ m ≤ n ≤ 64 et des sondes refusées.",
      "Construire K1 à K6 de §10.8 ; vérifier hachage, forme canonique, signature, chaînage.",
      "Exécuter `choisirPointCouvrant` sur les rangs de CT-5 EX-10.2."
    ],
    "oracle": "Preuves acceptées, sondes refusées (dont (5, 6), (9, 10), (10, 11)) ; valeurs de §10.8 et de §11.1 égales ; ordre des points couvrants conforme.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : preuve de cohérence RFC 9162 §2.1.4 et points de contrôle (révision 0.3)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": [
      "MN-74"
    ]
  },
  {
    "id": "TU-7",
    "level": "TU",
    "title": "Manifeste de période : `periodHash`, signature, continuité, `anchorFingerprint` (CT-1 §10.1 à §10.4)",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 P-1",
      "CT-1 P-5"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/journal.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Construire le manifeste de l'exemple de §10 ; vérifier la période vide et la continuité.",
      "Appeler `verifierManifeste` et `verifierContinuiteManifestes` sur des manifestes altérés."
    ],
    "oracle": "Valeurs de §10 reproduites ; chaque erreur nommée par la fonction.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : manifeste de période"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": []
  },
  {
    "id": "TU-8",
    "level": "TU",
    "title": "Validation contre les schémas JSON de CT-1 (`validerSchema`)",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 D-1",
      "CT-1 E-1"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/journal.mjs` et `spec/schemas/*.schema.json` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Valider les exemples de la spécification ; soumettre membre inconnu, motif, énumération, `oneOf`, `prefixItems` fautifs.",
      "Valider 20 000 adresses distinctes dans `approver_set.members`."
    ],
    "oracle": "Exemples acceptés, écarts refusés ; `uniqueItems` en moins de deux secondes.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : validation contre les schémas JSON"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": []
  },
  {
    "id": "TU-9",
    "level": "TU",
    "title": "Dossier de preuve par la bibliothèque : assemblage, index, contrôles D-, P-, A- (CT-1 §11)",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 D-2",
      "CT-1 P-2",
      "CT-1 P-3",
      "CT-1 A-1",
      "CT-1 A-2",
      "CT-1 A-3",
      "CT-1 A-4",
      "CT-1 E-8"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/journal.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Assembler le dossier de référence de §11.1 ; réduire une partie à `null` ; retirer `approbations.json` avec raison ; soumettre une entrée qui n'est pas un dossier.",
      "Vérifier P-3 sur un voisin hors intervalle et A-2 sur l'ordre décision/appel."
    ],
    "oracle": "Index identique et SHA-256 des douze parties ; un seul contrôle en échec par altération ; entrée non-dossier inutilisable, pas invalide.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : dossier de preuve"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": []
  },
  {
    "id": "TU-10",
    "level": "TU",
    "title": "Partie `attestation-perimetre.json` par la bibliothèque, AT-1 à AT-7 (CT-1 révision 0.4)",
    "specs": [
      "CT-1",
      "CT-7"
    ],
    "covers": [
      "CT-1 AT-1",
      "CT-1 AT-2",
      "CT-1 AT-3",
      "CT-1 AT-4",
      "CT-1 AT-5",
      "CT-1 AT-6",
      "CT-1 AT-7",
      "CT-7 §7.2"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/journal.mjs` et `scripts/lib/securite.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Vérifier que `P_P` est la même chaîne dans CT-1 §11.2, annexe B et CT-7 §7.2.",
      "Construire la partie de l'exemple annoté (5 443 octets) ; rejouer l'inscription de CT-7 §7.5.",
      "Soumettre une partie inexploitable, un document de politique à doublon, un `ts` hors validité."
    ],
    "oracle": "SHA-256 déclarés reproduits ; chaque AT- rend le statut attendu sans changer le verdict.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 révision 0.4 : partie attestation-perimetre.json, AT-1 à AT-7"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": [
      "MN-79",
      "MN-80",
      "MN-82",
      "MN-86",
      "MN-89",
      "MN-91"
    ]
  },
  {
    "id": "TU-11",
    "level": "TU",
    "title": "Ligne de commande `scripts/verify/dossier.mjs` : codes 0, 1, 2 (CT-1 §11.4)",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 §11.4"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/verify/dossier.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Lancer l'outil sur le dossier valide, sur chaque dossier invalide, sur une partie `null`, sur une entrée absente ou illisible, avec une option inconnue."
    ],
    "oracle": "Codes 0, 1, 1, 2 ; rapport lisible et JSON ; contrôle attendu en échec, index jamais repris d'une partie inexploitable.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : ligne de commande scripts/verify/dossier.mjs"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/journal.test.js"
    },
    "threats": []
  },
  {
    "id": "TU-12",
    "level": "TU",
    "title": "Propriétés aléatoires du noyau : canonicalisation, hachage, chaînage, Merkle, signature",
    "specs": [
      "CT-1"
    ],
    "covers": [
      "CT-1 E-2",
      "CT-1 E-7",
      "CT-1 C-2",
      "CT-1 M-2",
      "CT-1 K-5"
    ],
    "preconditions": [
      "`fast-check` épinglé à version exacte dans `package.json` et le fichier de verrouillage (R11-F16 : 4.10.2 au 2026-11-01).",
      "Graine constante écrite dans le test, jamais `Date.now()` ; `numRuns` fixé (200) ; `randomType` `xorshift128plus` écrit ; aucune limite de temps (`skipAllAfterTimeLimit`, `interruptAfterTimeLimit`, `timeout` absents)."
    ],
    "steps": [
      "Propriété 1 : pour tout objet JSON à entiers sûrs, `jcs(parse(jcs(x))) = jcs(x)`.",
      "Propriété 2 : pour tout événement scellé et toute mutation d'un octet du corps, E-7 échoue ou la mutation est hors du corps.",
      "Propriété 3 : pour tout journal de n ≤ 64 événements et toute transposition, C-2 échoue.",
      "Propriété 4 : pour tout arbre de n ≤ 1024 feuilles et toute feuille, la preuve d'inclusion est acceptée et toute preuve altérée refusée ; pour tout m ≤ n ≤ 64, la preuve de cohérence est acceptée.",
      "Propriété 5 : signature puis vérification Ed25519 sur des messages de 0 à 4096 octets."
    ],
    "oracle": "Chaque propriété tient sur ses `numRuns` exécutions ; un échec est consigné par son couple `seed`/`path` et rejoué tel quel (R11-F18) avant toute correction.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 1,
      "blocking": "`fast-check` n'est pas une dépendance du dépôt (R11-F7) ; l'ajout se fait avec la bibliothèque noyau de l'étape 1."
    },
    "threats": [
      "MN-4",
      "MN-17"
    ]
  },
  {
    "id": "TU-13",
    "level": "TU",
    "title": "Primitives de la console confrontées à `node:crypto`, `@noble/*` et `ethers` (CT-3 EX-13.32)",
    "specs": [
      "CT-3"
    ],
    "covers": [
      "CT-3 EX-13.32"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/console.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "SHA-256, HMAC, Keccak-256 sur des longueurs autour des blocs ; PBKDF2, scrypt, AES-128-CTR ; secp256k1 (RFC 6979, s bas, recouvrement) ; EIP-191 ; JCS v0 sur tous les événements de CT-1."
    ],
    "oracle": "Égalité octet pour octet avec les bibliothèques de référence ; déterminisme du générateur de primitives.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/console-primitives.test.js",
          "describe": "CT-3 0.3 : primitives de scripts/lib/console.mjs confrontées à node:crypto, @noble/hashes, @noble/curves et ethers (EX-13.32)"
        },
        {
          "file": "test/console.test.js",
          "describe": "CT-3 0.3 : primitives de console.mjs contre node:crypto, ethers et journal.mjs (EX-13.32)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/console-primitives.test.js"
    },
    "threats": [
      "MN-52"
    ]
  },
  {
    "id": "TU-14",
    "level": "TU",
    "title": "Lecteur DER borné du vérificateur (CT-6 §9.3)",
    "specs": [
      "CT-6"
    ],
    "covers": [
      "CT-6 EX-9.4",
      "CT-6 §9.3"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/horodatage.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Soumettre longueur indéfinie, longueur non minimale, étiquette ≥ 31, octet en trop, BOOLEAN hors 00/ff, profondeur 33, OID non minimal, `genTime` mal formé."
    ],
    "oracle": "Chaque forme fautive refusée sans exception ; profondeur 32 acceptée ; aller-retour OID exact.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/horodatage.test.js",
          "describe": "CT-6 contrôle 4 : lecteur DER borné (§9.3, EX-9.4)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/horodatage.test.js"
    },
    "threats": [
      "MN-68"
    ]
  },
  {
    "id": "TU-15",
    "level": "TU",
    "title": "Jeton RFC 3161 construit en mémoire : T-1 à T-11, N-1, AV-T- (CT-6 §9, §12.2, §15.2)",
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
      "CT-6 N-1",
      "CT-6 AV-T-1",
      "CT-6 AV-T-2",
      "CT-6 AV-T-3",
      "CT-6 AV-T-4",
      "CT-6 EX-9.2",
      "CT-6 EX-9.7",
      "CT-6 EX-9.11",
      "CT-6 EX-9.12",
      "CT-6 EX-9.13",
      "CT-6 EX-9.15",
      "CT-6 EX-9.16",
      "CT-6 EX-9.19",
      "CT-6 EX-9.20",
      "CT-6 EX-9.21",
      "CT-6 EX-12.2",
      "CT-6 EX-15.2",
      "CT-6 EX-9.1",
      "CT-6 EX-9.3",
      "CT-6 EX-9.4",
      "CT-6 EX-9.5",
      "CT-6 EX-9.6",
      "CT-6 EX-9.8",
      "CT-6 EX-9.9",
      "CT-6 EX-9.10",
      "CT-6 EX-9.14",
      "CT-6 EX-9.17",
      "CT-6 EX-9.18",
      "CT-6 EX-9.22"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/horodatage.mjs` et les clés de test de `spec/vecteurs/ct-6/rfc3161/cles/` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Construire des jetons qui violent une seule vérification à la fois (structure, empreinte, ESS, certificat, algorithme, signature, chemin, EKU, TSTInfo, révocation, qualification).",
      "Soumettre des CRL antérieures, mal signées, d'un autre émetteur ; des ancres fautives à `controlerAncresTsa`.",
      "Fuzzing déterministe du jeton."
    ],
    "oracle": "Une seule vérification en échec par cas, les autres réussies ou non exécutées pour la raison attendue ; jamais une exception ; avertissements AV-T- sans effet sur le verdict.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/horodatage.test.js",
          "describe": "CT-6 contrôle 4 : T-1, structure du jeton (EX-9.7)"
        },
        {
          "file": "test/horodatage.test.js",
          "describe": "CT-6 contrôle 4 : T-2 à T-6"
        },
        {
          "file": "test/horodatage.test.js",
          "describe": "CT-6 contrôle 4 : T-7 à T-9"
        },
        {
          "file": "test/horodatage.test.js",
          "describe": "CT-6 contrôle 4 : T-10, révocation (EX-9.16)"
        },
        {
          "file": "test/horodatage.test.js",
          "describe": "CT-6 contrôle 4 : ancres d'horodatage (N-1, EX-12.2)"
        },
        {
          "file": "test/horodatage.test.js",
          "describe": "CT-6 contrôle 4 : règles précisées par la revue"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/horodatage.test.js"
    },
    "threats": [
      "MN-61",
      "MN-68"
    ]
  },
  {
    "id": "TU-16",
    "level": "TU",
    "title": "Format `.ots`, en-têtes Bitcoin, O-1 à O-7 construits en mémoire (CT-6 §10, §15.2)",
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
      "CT-6 N-2",
      "CT-6 AV-O-1",
      "CT-6 AV-O-2",
      "CT-6 AV-O-3",
      "CT-6 EX-10.2",
      "CT-6 EX-10.7",
      "CT-6 EX-10.8",
      "CT-6 EX-10.9",
      "CT-6 EX-10.12",
      "CT-6 EX-15.2",
      "CT-6 EX-10.1",
      "CT-6 EX-10.3",
      "CT-6 EX-10.4",
      "CT-6 EX-10.5",
      "CT-6 EX-10.6",
      "CT-6 EX-10.10",
      "CT-6 EX-10.11",
      "CT-6 EX-10.13",
      "CT-6 EX-10.14",
      "CT-6 EX-10.15",
      "CT-6 EX-10.16"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/ots.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Varuint LEB128, en-tête magique, opérations inconnues, chemin de 256 opérations, attestations.",
      "En-tête réel du bloc 358391, `SetCompact`/`GetCompact`, réajustement de difficulté, chaîne de test.",
      "Fuzzing déterministe des preuves."
    ],
    "oracle": "Chaque forme fautive illisible ; valeurs de §10.3 reproduites ; `evaluerPreuve` ne rend que des statuts.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/ots.test.js",
          "describe": "CT-6 contrôle 5 : format .ots (§10.2, EX-10.2)"
        },
        {
          "file": "test/ots.test.js",
          "describe": "CT-6 contrôle 5 : en-têtes Bitcoin (§10.3, EX-10.9)"
        },
        {
          "file": "test/ots.test.js",
          "describe": "CT-6 contrôle 5 : règles précisées par la revue"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/ots.test.js"
    },
    "threats": [
      "MN-70"
    ]
  },
  {
    "id": "TU-17",
    "level": "TU",
    "title": "Registre : RLP, hachage BFT, reçus, journaux, parties, R-1 à R-10 et N-4 construits en mémoire (CT-6 §11)",
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
      "CT-6 R-11",
      "CT-6 N-4",
      "CT-6 N-1",
      "CT-6 AV-R-1",
      "CT-6 AV-R-2",
      "CT-6 AV-R-3",
      "CT-6 EX-11.5",
      "CT-6 EX-11.9",
      "CT-6 EX-11.22",
      "CT-6 EX-12.4",
      "CT-6 EX-8.3",
      "CT-6 EX-4.3",
      "CT-6 EX-5.6",
      "CT-6 EX-5.4"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/registre.mjs` et la capture `spec/vecteurs/ct-6/registre/capture/` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "RLP contre `encodeRlp` d'ethers ; `BFTBlockHash` du bloc 8316 ; bloom, racine des reçus, trie ; décodage des journaux.",
      "Altérer un champ engagé, un reçu, un jeu, une clé ; retirer les ancres ; rendre `periodHash` incalculable."
    ],
    "oracle": "Valeurs de la spécification reproduites ; une seule vérification visée en échec par altération, les dépendantes non exécutées avec la raison attendue.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/registre.test.js",
          "describe": "CT-6 contrôle 8 : constantes, RLP, hachage BFT du bloc"
        },
        {
          "file": "test/registre.test.js",
          "describe": "CT-6 contrôle 8 : reçus, bloom et racine des reçus (EX-11.5)"
        },
        {
          "file": "test/registre.test.js",
          "describe": "CT-6 contrôle 8 : journaux d'événements (EX-11.9)"
        },
        {
          "file": "test/registre.test.js",
          "describe": "CT-6 contrôle 8 : lecture des parties et ancre registry"
        },
        {
          "file": "test/registre.test.js",
          "describe": "CT-6 contrôle 8 : vérifications R-1 à R-10 et N-4"
        },
        {
          "file": "test/registre.test.js",
          "describe": "CT-6 contrôle 8 : règles précisées par la revue"
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
    "id": "TU-18",
    "level": "TU",
    "title": "Certificat de commit : parité du décodeur JavaScript avec le code Go de noorcore (CT-4 §9, CT-6 §11)",
    "specs": [
      "CT-4",
      "CT-6"
    ],
    "covers": [
      "CT-4 §9",
      "CT-4 EX-9.1",
      "CT-4 EX-9.2",
      "CT-4 EX-9.3",
      "CT-4 EX-9.4",
      "CT-4 EX-9.5",
      "CT-4 EX-9.6",
      "CT-4 EX-9.7",
      "CT-4 EX-9.8",
      "CT-4 EX-9.9",
      "CT-4 EX-9.10",
      "CT-4 EX-9.11",
      "CT-4 EX-9.12",
      "CT-4 EX-9.13",
      "CT-4 EX-9.14",
      "CT-6 §11"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/certificat-commit.mjs` et `test/fixtures/certificat-commit/` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Décoder les vecteurs « lignes » et « fichiers » produits par le Go ; altérer les vecteurs synthétiques ; exercer la ligne de commande avec un nœud JSON-RPC simulé."
    ],
    "oracle": "Même décodage que le Go ; chaque altération refusée ; codes de sortie de la commande.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/certificatCommit.test.js",
          "describe": "Certificat de commit — parité avec le code Go"
        },
        {
          "file": "test/certificatCommit.test.js",
          "describe": "Certificat de commit — vecteurs synthétiques et altérations"
        },
        {
          "file": "test/certificatCommit.test.js",
          "describe": "Certificat de commit — ligne de commande"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/certificatCommit.test.js"
    },
    "threats": [
      "MN-55"
    ]
  },
  {
    "id": "TU-19",
    "level": "TU",
    "title": "Contrats du registre : `PeriodRegistry`, `RecorderRegistry`, signatures à seuil, déploiement (CT-4 §5)",
    "specs": [
      "CT-4"
    ],
    "covers": [
      "CT-4 §5"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; réseau Hardhat en mémoire (compilation des contrats)."
    ],
    "steps": [
      "Exécuter les suites des contrats sur le réseau Hardhat en mémoire ; déployer par `deploy-noortrace.mjs`."
    ],
    "oracle": "Chaque assertion des suites ; adresses et événements attendus.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/periodRegistry.test.js",
          "describe": "PeriodRegistry"
        },
        {
          "file": "test/recorderRegistry.test.js",
          "describe": "RecorderRegistry"
        },
        {
          "file": "test/thresholdSignatures.test.js",
          "describe": "ThresholdSignatures"
        },
        {
          "file": "test/deploy.test.js",
          "describe": "Déploiement de NOORTRACE"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/periodRegistry.test.js test/recorderRegistry.test.js test/thresholdSignatures.test.js test/deploy.test.js"
    },
    "threats": [
      "MN-53",
      "MN-73"
    ]
  },
  {
    "id": "TU-20",
    "level": "TU",
    "title": "JCS intégral (RFC 8785 tel quel) et étendue des valeurs relayées (CT-2 §8.1, EX-4.20)",
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
      "CT-2 EX-4.20"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/capture.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Table des nombres de l'annexe B de la RFC 8785 ; exemple §3.2.2 ; tri par unités UTF-16 ; table de CT-2 §8.1 ; étendue de chaque valeur dans le texte reçu."
    ],
    "oracle": "Octets égaux à la RFC et à la table de §8.1 ; NaN, Infinity, substituts isolés, clés en double refusés.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : JCS intégral (RFC 8785, CT-2 §8.1)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur.test.js"
    },
    "threats": [
      "MN-4"
    ]
  },
  {
    "id": "TU-21",
    "level": "TU",
    "title": "Détecteurs exacts, politique de rédaction, motifs et budget (CT-2 §10)",
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
      "CT-2 EX-10.23",
      "CT-2 EX-10.24",
      "CT-2 EX-10.19",
      "CT-2 EX-10.20",
      "CT-2 EX-10.21",
      "CT-2 EX-10.22",
      "CT-7 EX-8.14",
      "CT-7 EX-8.18"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/capture.mjs` et la politique `pii-v1` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "IBAN, AVS, carte, adresse électronique, téléphone, faux positifs évités.",
      "Rédaction au point fixe, idempotence, pointeurs RFC 6901, `redacted` ; motifs à retour arrière exponentiel refusés ; budget de rédaction et pièce « non rédigeable » ; `extract` compilé comme motif nommé."
    ],
    "oracle": "Détections et refus attendus ; empreintes de §10.6 et de §15.3 ; comportement sous budget conforme à EX-10.23.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : détecteurs exacts (§10.3)"
        },
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : politique de rédaction (§10)"
        },
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 révision 0.3 : contrôle des motifs et budget de rédaction (EX-10.6, EX-10.23, EX-7.6)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur.test.js"
    },
    "threats": []
  },
  {
    "id": "TU-22",
    "level": "TU",
    "title": "Analyseur SSE et formes consolidées des flux Anthropic, Chat Completions, Responses (CT-2 §5.4)",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 §5.4",
      "CT-2 EX-5.22",
      "CT-2 EX-5.27",
      "CT-2 EX-5.11"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/capture.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Champs, commentaires, `data` multilignes, CRLF/LF/CR, découpage arbitraire des octets.",
      "Flux coupés, erreurs en flux, deltas inconnus, fin sans `[DONE]`."
    ],
    "oracle": "Résultat indépendant du découpage ; formes consolidées égales aux formes attendues construites dans le test.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : analyseur SSE (§5.4.1)"
        },
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : formes consolidées des flux (§5.4.2 à 5.4.4)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur.test.js"
    },
    "threats": []
  },
  {
    "id": "TU-23",
    "level": "TU",
    "title": "Frontal MCP en bibliothèque : agrégation de `tools/list`, lecture d'une requête d'hôte, codes d'erreur, quotas (CT-2 §4.3, §4.4)",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-4.20",
      "CT-2 EX-4.21",
      "CT-2 EX-4.24",
      "CT-2 EX-4.43",
      "CT-2 EX-4.44",
      "CT-2 EX-4.45",
      "CT-2 EX-4.47",
      "CT-2 EX-4.49",
      "CT-2 EX-5.22",
      "CT-2 EX-5.27",
      "CT-2 §4.3",
      "CT-2 §4.4"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/capture.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Préfixe `alias__`, rejets, classes, pagination, collisions ; nombres et blancs d'une requête ; contexte d'un appel ; codes -31010 à -31017 ; signal d'approbation de l'annexe A ; quotas par connexion d'hôte."
    ],
    "oracle": "Valeurs construites dans le test et octets de l'annexe A (359 octets pour le signal).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : agrégation de tools/list et nommage (§4.3)"
        },
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : lecture d'une requête d'hôte, blancs, nombres, contexte (4.4 pas 1, EX-4.43 à EX-4.45)"
        },
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 révision 0.3 : codes d'erreur et résultats rendus par l'enregistreur (4.4, EX-4.24, EX-4.49)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur.test.js"
    },
    "threats": [
      "MN-7"
    ]
  },
  {
    "id": "TU-24",
    "level": "TU",
    "title": "Construction des événements, écrivain, segment, journal d'intention, reprise, horloge (CT-2 §7, §9, §12)",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-7.1",
      "CT-2 EX-7.6",
      "CT-2 EX-7.9",
      "CT-2 EX-7.13",
      "CT-2 §7.4",
      "CT-2 §9",
      "CT-2 §12.2",
      "CT-2 §12.4",
      "CT-2 §12.5"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/capture.mjs` et `scripts/lib/journal.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Construire chaque sorte d'événement ; `ts = max(lu, précédent)` sous le seuil ; recul au-delà de `clock.max_backstep_ms` : mode dégradé horloge (EX-7.9) ; exception de l'événement en attente, daté par `captured_at` (EX-14.10) ; saut d'horloge au-delà de `max_forward_ms` (EX-7.13) ; événement invalide non signé ; segment tronqué ou corrompu ; intention sans levée ; gabarits d'effets ; corrélation appel/échange ; annexe A recalculée."
    ],
    "oracle": "Chaque sorte valide contre CT-1 et passe E-1 à E-11 ; seq 2, 3 et 4 rescellés égaux octet pour octet aux événements imprimés ; reprise déterministe ; recul au-delà du seuil et saut en avant : erreur de mode dégradé de raison `horloge` ; événement en attente : `ts = max(captured_at, précédent)`.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : construction des événements, écrivain, segment, intention, reprise (§7, §9, §12)"
        },
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : annexe A recalculée (relais de tools/call, pièces, événements)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur.test.js"
    },
    "threats": [
      "MN-10",
      "MN-20",
      "MN-21"
    ]
  },
  {
    "id": "TU-25",
    "level": "TU",
    "title": "Configuration et contrôles de démarrage (CT-2 §15, EX-7.15)",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-15.1",
      "CT-2 EX-15.2",
      "CT-2 EX-15.3",
      "CT-2 EX-15.4",
      "CT-2 EX-15.5",
      "CT-2 EX-15.6",
      "CT-2 EX-15.8",
      "CT-2 EX-15.7",
      "CT-2 EX-7.15"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/capture.mjs` et les schémas de configuration présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Valider les blocs annotés de CT-2 ; passer l'exemple de §15.3 aux contrôles de démarrage ; refuser un cas par règle (otel, policy.sdk, routes gemini, WORM, classe D) ; `charger` de l'exemple."
    ],
    "oracle": "Exemple accepté sans erreur ni avertissement ; chaque règle refusée avec son message ; `requesters` égaux aux `launched_by` configurés.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : schémas de configuration et de politique (validerSchema)"
        },
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 révision 0.3 : configuration (15.3, EX-15.4 pas 2 à 4, EX-7.15)"
        },
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : contrôles de démarrage ajoutés (EX-15.4 pas 3 : otel, policy.sdk, routes gemini, support WORM)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur.test.js"
    },
    "threats": [
      "MN-2",
      "MN-11",
      "MN-13",
      "MN-14",
      "MN-30",
      "MN-43"
    ]
  },
  {
    "id": "TU-26",
    "level": "TU",
    "title": "Passerelle Gemini et format `gemini` du SDK, règles en bibliothèque (CT-2 §5.4.5, EX-5.28 à EX-5.36, EX-6.8)",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-5.28",
      "CT-2 EX-5.29",
      "CT-2 EX-5.30",
      "CT-2 EX-5.31",
      "CT-2 EX-5.32",
      "CT-2 EX-5.33",
      "CT-2 EX-5.34",
      "CT-2 EX-5.35",
      "CT-2 EX-5.36",
      "CT-2 EX-6.8",
      "CT-2 EX-5.22",
      "CT-2 EX-8.5"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/capture.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Route, segment, examen de la requête, corps d'erreur AIP-193, `mcpServers`, bornes de taille, `data` final, consolidation, `code.model`, corrélation, `echangeModele` du SDK, schéma `model_route`."
    ],
    "oracle": "Octets exacts des tables et de l'exemple de §5.4.5 ; raisons dans l'ordre ; noms consignés, jamais les valeurs.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : Gemini à la passerelle et format gemini du SDK (EX-5.28 à EX-5.36, EX-6.8)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur-r05.test.js"
    },
    "threats": [
      "MN-11",
      "MN-13"
    ]
  },
  {
    "id": "TU-27",
    "level": "TU",
    "title": "Ingestion OpenTelemetry en bibliothèque : décodage, classement, doublons, refus (CT-2 §6.8)",
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
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/otel.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Décodage JSON strict et protobuf écrit à la main ; V et A ; classification ; doublons ; nom d'outil, durée, erreur, `run_id` ; 404, 405, 401, 429, 503, 413 ; ordre des décisions ; `otel_span_conflict`."
    ],
    "oracle": "Formes normalisées, pièces et événements égaux à l'exemple de 6.8.16 ; réponses OTLP octet pour octet ; compteurs attendus.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : ingestion OpenTelemetry (6.8, EX-6.25 à EX-6.41)"
        },
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5, relecture : corrections de comportement sans vecteur dédié"
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
    "id": "TU-28",
    "level": "TU",
    "title": "Copies WORM et gel juridique en bibliothèque (CT-2 §12.6, §12.11)",
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
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/worm.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Content-MD5, encodage RFC 3986, lecture des échéances, empreintes des enregistrements, règle de garde par mutation minimale, levée sous un autre gel actif."
    ],
    "oracle": "Valeurs imprimées par la spécification ; chaque code de la règle de garde provoqué ; version couverte jamais levée.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : copies WORM et gel juridique (12.6, 12.11, EX-12.29 à EX-12.41)"
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
    "id": "TU-29",
    "level": "TU",
    "title": "Coût annuel par agent : formule et contrôles d'entrée (CT-2 §16.4)",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-16.4",
      "CT-2 EX-16.5",
      "CT-2 EX-16.6"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/cout-agent.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Totaux de la table de 16.4 et exemple de référence ; entiers, `A ≥ 1`, `S ≥ 1024`, `0 ≤ g ≤ 1`, `worm` nul."
    ],
    "oracle": "Valeurs de la formule ; chaque entrée hors domaine refusée ; aucun prix réel.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : coût annuel par agent (16.4, EX-16.4 à EX-16.6)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur-r05.test.js"
    },
    "threats": []
  },
  {
    "id": "TU-30",
    "level": "TU",
    "title": "Politique d'approbation : validation, évaluation, candidats, exemples de la spécification (CT-3 §3 à §6, §8.2)",
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
      "CT-3 EX-4.1",
      "CT-3 EX-4.2",
      "CT-3 EX-4.3",
      "CT-3 EX-4.4",
      "CT-3 EX-4.5",
      "CT-3 EX-4.6",
      "CT-3 EX-4.7",
      "CT-3 EX-4.8",
      "CT-3 EX-4.9",
      "CT-3 EX-4.10",
      "CT-3 EX-4.11",
      "CT-3 EX-4.12",
      "CT-3 EX-4.13",
      "CT-3 EX-4.14",
      "CT-3 EX-5.1",
      "CT-3 EX-5.2",
      "CT-3 EX-5.3",
      "CT-3 EX-5.4",
      "CT-3 EX-5.5",
      "CT-3 EX-5.6",
      "CT-3 EX-5.7",
      "CT-3 EX-5.8",
      "CT-3 EX-5.9",
      "CT-3 EX-5.10",
      "CT-3 EX-6.1",
      "CT-3 EX-6.2",
      "CT-3 EX-6.3",
      "CT-3 EX-6.4",
      "CT-3 EX-6.8",
      "CT-3 EX-6.5",
      "CT-3 EX-6.6",
      "CT-3 EX-6.7",
      "CT-3 EX-3.5",
      "CT-3 EX-8.2",
      "CT-3 EX-9.7",
      "CT-3 EX-11.8",
      "CT-3 EX-12.5"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/approbation.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Documents refusés avec la liste triée des erreurs ; bornes d'EX-4.2 ; pointeurs RFC 6901 ; entiers exacts ; tables de Kleene ; sélecteurs ; rang et ordre ; indépendance de l'ordre des membres ; évaluation sans effet ; forme de `policy.rule` ; chaîne d'un million de caractères ; `CANDIDATS(P, L)`."
    ],
    "oracle": "`rule`, `decision`, `opening` et fenêtres égaux aux valeurs construites ; chaque AP- a au moins un cas ; évaluation linéaire.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : schémas et exemples de la spécification"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : validation de la politique (EX-4.2, EX-8.2, AP-1 à AP-4)"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : évaluation (sections 4 à 6, AP-5 à AP-17)"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : outils susceptibles d'approbation (EX-4.11, AP-16)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/approbation.test.js"
    },
    "threats": [
      "MN-3"
    ]
  },
  {
    "id": "TU-31",
    "level": "TU",
    "title": "Tickets, remises, jeu d'approbateurs, mandataire en attente et échanges noyau ↔ service (CT-3 §7 à §12, §14 ; CT-2 §7.5)",
    "specs": [
      "CT-3",
      "CT-2"
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
      "CT-3 SG-1",
      "CT-3 SG-2",
      "CT-3 SG-3",
      "CT-3 SG-4",
      "CT-3 SG-5",
      "CT-3 SG-6",
      "CT-3 SG-7",
      "CT-3 EX-7.1",
      "CT-3 EX-7.2",
      "CT-3 EX-7.3",
      "CT-3 EX-7.4",
      "CT-3 EX-7.5",
      "CT-3 EX-7.6",
      "CT-3 EX-7.7",
      "CT-3 EX-7.8",
      "CT-3 EX-7.9",
      "CT-3 EX-7.10",
      "CT-3 EX-7.11",
      "CT-3 EX-7.12",
      "CT-3 EX-7.13",
      "CT-3 EX-7.14",
      "CT-3 EX-7.15",
      "CT-3 EX-7.16",
      "CT-3 EX-7.17",
      "CT-3 EX-7.18",
      "CT-3 EX-7.19",
      "CT-3 EX-7.20",
      "CT-3 EX-7.21",
      "CT-3 EX-7.22",
      "CT-3 EX-7.23",
      "CT-3 EX-7.24",
      "CT-3 EX-7.25",
      "CT-3 EX-7.26",
      "CT-3 EX-7.27",
      "CT-3 EX-7.28",
      "CT-3 EX-7.29",
      "CT-3 EX-8.1",
      "CT-3 EX-8.2",
      "CT-3 EX-8.3",
      "CT-3 EX-8.4",
      "CT-3 EX-8.5",
      "CT-3 EX-8.6",
      "CT-3 EX-8.7",
      "CT-3 EX-8.8",
      "CT-3 EX-8.9",
      "CT-3 EX-8.10",
      "CT-3 EX-8.11",
      "CT-3 EX-9.1",
      "CT-3 EX-9.2",
      "CT-3 EX-9.3",
      "CT-3 EX-9.4",
      "CT-3 EX-9.5",
      "CT-3 EX-9.6",
      "CT-3 EX-9.7",
      "CT-3 EX-9.8",
      "CT-3 EX-9.9",
      "CT-3 EX-9.10",
      "CT-3 EX-9.11",
      "CT-3 EX-9.12",
      "CT-3 EX-9.13",
      "CT-3 EX-9.14",
      "CT-3 EX-9.15",
      "CT-3 EX-9.16",
      "CT-3 EX-9.17",
      "CT-3 EX-9.18",
      "CT-3 EX-9.19",
      "CT-3 EX-9.20",
      "CT-3 EX-9.21",
      "CT-3 EX-9.22",
      "CT-3 EX-10.1",
      "CT-3 EX-10.2",
      "CT-3 EX-10.3",
      "CT-3 EX-10.4",
      "CT-3 EX-10.5",
      "CT-3 EX-10.6",
      "CT-3 EX-10.7",
      "CT-3 EX-10.8",
      "CT-3 EX-10.9",
      "CT-3 EX-10.10",
      "CT-3 EX-10.11",
      "CT-3 EX-11.1",
      "CT-3 EX-11.2",
      "CT-3 EX-11.3",
      "CT-3 EX-11.4",
      "CT-3 EX-11.5",
      "CT-3 EX-11.6",
      "CT-3 EX-11.7",
      "CT-3 EX-11.8",
      "CT-3 EX-11.9",
      "CT-3 EX-11.10",
      "CT-3 EX-11.11",
      "CT-3 EX-11.12",
      "CT-3 EX-11.13",
      "CT-3 EX-11.14",
      "CT-3 EX-11.15",
      "CT-3 EX-12.6",
      "CT-3 EX-14.1",
      "CT-3 EX-3.1",
      "CT-2 EX-7.14",
      "CT-2 EX-7.15",
      "CT-2 EX-7.16",
      "CT-2 EX-7.17",
      "CT-2 EX-7.18",
      "CT-2 EX-7.19",
      "CT-2 EX-7.20",
      "CT-2 EX-7.21",
      "CT-2 EX-7.22",
      "CT-2 EX-9.4",
      "CT-2 EX-10.24",
      "CT-2 EX-12.23",
      "CT-2 EX-4.21",
      "CT-2 EX-4.50",
      "CT-2 EX-6.7",
      "CT-2 RL-1",
      "CT-2 RL-2",
      "CT-2 RL-3",
      "CT-2 RL-4",
      "CT-2 SG-1",
      "CT-2 SG-2",
      "CT-2 SG-3",
      "CT-2 SG-4",
      "CT-2 SG-5",
      "CT-2 SG-6",
      "CT-2 SG-7"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/approbation.mjs` et `scripts/lib/capture.mjs` ; réseau Hardhat en mémoire pour le `CuratorSet` réel présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Reprise depuis l'état persisté après chaque pas ; identifiants et époques ; sept combinaisons d'`evaluer` ; remises à `t` signatures ; échéances et raisons ; effacement des arguments ; escalade ; fenêtres ; ordre des raisons de refus ; jeu lu dans un `CuratorSet` réel, surveillance du gel ; modes `erreur` et `retenir` ; MAC de relais, RL-1 à RL-4, continuation MRTR, expiration par le noyau, motif rédigé, fichiers des approbations, SG-7."
    ],
    "oracle": "Sorties égales aux valeurs construites dans le test et aux octets de la spécification ; un échec par vérification RL-/SG- ; le service repris rend les mêmes sorties.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : tickets (section 7, TK-1 à TK-13)"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : remises et signatures (section 9, SG-1 à SG-7, annexe A.7 et A.8)"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : jeu d'approbateurs lu dans un CuratorSet réel (section 8, réseau Hardhat en mémoire)"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : comportement du mandataire pendant l'attente (section 11, décision ouverte 4)"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-2 §7.5 : échanges du noyau avec le service, partie calculable (EX-7.14 à EX-7.22, EX-9.4, EX-10.24, EX-12.23)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/approbation.test.js"
    },
    "threats": [
      "MN-5",
      "MN-6",
      "MN-38",
      "MN-44",
      "MN-48",
      "MN-49",
      "MN-50"
    ]
  },
  {
    "id": "TU-32",
    "level": "TU",
    "title": "Console de référence en bibliothèque : annuaire, modèle d'affichage, requêtes, réponses, découverte, fichiers de clé, propriétés statiques (CT-3 §9, §12.9, §13)",
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
      "CT-3 CS-1",
      "CT-3 CS-2",
      "CT-3 CS-3",
      "CT-3 CS-4",
      "CT-3 CS-5",
      "CT-3 CS-6",
      "CT-3 CS-7",
      "CT-3 CS-8",
      "CT-3 CS-9",
      "CT-3 EX-13.1",
      "CT-3 EX-13.2",
      "CT-3 EX-13.3",
      "CT-3 EX-13.4",
      "CT-3 EX-13.5",
      "CT-3 EX-13.6",
      "CT-3 EX-13.7",
      "CT-3 EX-13.8",
      "CT-3 EX-13.9",
      "CT-3 EX-13.10",
      "CT-3 EX-13.11",
      "CT-3 EX-13.12",
      "CT-3 EX-13.13",
      "CT-3 EX-13.14",
      "CT-3 EX-13.15",
      "CT-3 EX-13.16",
      "CT-3 EX-13.17",
      "CT-3 EX-13.37",
      "CT-3 EX-13.18",
      "CT-3 EX-13.19",
      "CT-3 EX-13.20",
      "CT-3 EX-13.21",
      "CT-3 EX-13.22",
      "CT-3 EX-13.23",
      "CT-3 EX-13.24",
      "CT-3 EX-13.25",
      "CT-3 EX-13.26",
      "CT-3 EX-13.27",
      "CT-3 EX-13.28",
      "CT-3 EX-13.29",
      "CT-3 EX-13.30",
      "CT-3 EX-13.31",
      "CT-3 EX-13.32",
      "CT-3 EX-13.33",
      "CT-3 EX-13.34",
      "CT-3 EX-13.35",
      "CT-3 EX-9.15",
      "CT-3 EX-9.16",
      "CT-3 EX-9.17",
      "CT-3 EX-9.18",
      "CT-3 EX-9.19",
      "CT-3 EX-9.20",
      "CT-3 EX-9.21",
      "CT-3 EX-9.22",
      "CT-3 EX-9.4",
      "CT-3 EX-12.14",
      "CT-3 EX-12.16",
      "CT-3 EX-12.17",
      "CT-3 EX-12.19"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/console.mjs` et `console/` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Messages d'inscription et condensés EIP-191 ; identité canonique ; inscriptions ; domaines ; traces d'opérations ; contrôles de vote et de canal ; exports ; modèle d'affichage ; requête `personal_sign` ; réponses ; annonces EIP-6963 ; fichiers de clé ; propriétés statiques (aucune importation, `eval`, réseau, `innerHTML`, intégrité sha384)."
    ],
    "oracle": "Valeurs construites dans le test et octets de la spécification (13.5, 13.6, 13.10, 13.15) ; chaque raison dans l'ordre fixé.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/console.test.js",
          "describe": "CT-3 0.3 : annuaire/ rejoué par console.mjs (AN-1 à AN-10)"
        },
        {
          "file": "test/console.test.js",
          "describe": "CT-3 0.3 : exemples de la spécification et vecteurs (13.5, 13.6, 13.10, 13.15)"
        },
        {
          "file": "test/console.test.js",
          "describe": "CT-3 0.3 : console/ rejoué par console.mjs (CS-1 à CS-9)"
        },
        {
          "file": "test/console.test.js",
          "describe": "CT-3 0.3 : bibliothèque et page de référence, propriétés statiques (EX-13.31 à EX-13.35)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/console.test.js"
    },
    "threats": [
      "MN-35",
      "MN-45",
      "MN-46",
      "MN-47",
      "MN-52"
    ]
  },
  {
    "id": "TU-33",
    "level": "TU",
    "title": "Console de référence dans Chromium : parcours nominal, refus, délai, changement de ticket, annuaire, comptes, inscription, politique du contenu (CT-3 EX-13.36)",
    "specs": [
      "CT-3"
    ],
    "covers": [
      "CT-3 EX-13.36",
      "CT-3 EX-13.30",
      "CT-3 EX-13.21",
      "CT-3 EX-13.23",
      "CT-3 EX-13.35",
      "CT-3 EX-9.17",
      "CT-3 EX-9.21"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé ; Playwright 1.56.1 et Chromium installés hors de `package.json` (job `console-chromium` de la CI) ; `NOORTRACE_EXIGER_CHROMIUM=1` pour interdire la mise en attente."
    ],
    "steps": [
      "Charger la page avec un portefeuille simulé ; jouer les scénarios : nominal, 4001, mauvaise adresse, empreinte divergente, formes de signature, délai, changement de ticket, annuaire, comptes, inscription, aucun portefeuille, en-têtes de politique du contenu."
    ],
    "oracle": "Requêtes `personal_sign` et votes exacts ; aucun envoi dans les cas de refus ; en-têtes exacts ; aucun test Chromium en attente.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/console.test.js",
          "describe": "CT-3 0.3 : console de référence dans Chromium (EX-13.36)"
        }
      ],
      "command": "NOORTRACE_EXIGER_CHROMIUM=1 npx hardhat --config hardhat.config.mjs test test/console.test.js"
    },
    "threats": [
      "MN-35",
      "MN-45",
      "MN-46",
      "MN-52"
    ]
  },
  {
    "id": "TU-34",
    "level": "TU",
    "title": "Mode observation en bibliothèque : `evaluerObservation`, marque, relais, configuration (CT-3 révision 0.4, CT-2 révision 0.6)",
    "specs": [
      "CT-3",
      "CT-2",
      "CT-8"
    ],
    "covers": [
      "CT-3 EX-11.12",
      "CT-3 EX-11.13",
      "CT-3 EX-12.20",
      "CT-3 EX-6.8",
      "CT-3 EX-11.11",
      "CT-3 EX-11.14",
      "CT-3 EX-11.15",
      "CT-2 EX-14.13",
      "CT-2 EX-14.14",
      "CT-2 EX-14.15",
      "CT-2 EX-14.16",
      "CT-2 EX-14.17",
      "CT-2 EX-15.8",
      "CT-2 EX-17.8",
      "CT-2 EX-4.51",
      "CT-2 EX-7.23",
      "CT-8 EX-12.2",
      "CT-8 §12.6"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/approbation.mjs`, `scripts/lib/capture.mjs`, `scripts/lib/exploitation.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Évaluer chaque cas de `evaluation/assureur.json` en observation ; fenêtre ouverte non décomptée ; bloc d'EX-12.20 ; `regleObservation`, `actionMandataire` ; événement `executee` conforme à CT-1 ; schéma étendu ; empreinte de l'ensemble de politique ; avertissement fixe d'EX-15.8 ; refus d'entrée en observation ; suffixe, nom réservé, 998 caractères, `approbateurs_de_test`."
    ],
    "oracle": "Règle et décision d'`evaluer` sans ticket ni fenêtre consommée ; textes et empreintes égaux à CT-2, CT-3 et CT-8 EX-12.2.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/observation.test.js",
          "describe": "CT-3 révision 0.4 : evaluerObservation (EX-11.12, EX-11.13, EX-12.20)"
        },
        {
          "file": "test/observation.test.js",
          "describe": "CT-3 EX-6.8 et CT-2 EX-14.14, EX-14.15 : marque d'observation et relais"
        },
        {
          "file": "test/observation.test.js",
          "describe": "CT-2 révision 0.6 : configuration du mode observation (EX-15.8, EX-11.15 de CT-3)"
        },
        {
          "file": "test/exploitation.test.js",
          "describe": "CT-2 0.6 et CT-3 0.4 : règles du mode observation (suffixe, nom réservé, longueur, approbateurs de test)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/observation.test.js"
    },
    "threats": []
  },
  {
    "id": "TU-35",
    "level": "TU",
    "title": "Registre CT-4 : exigences vérifiables hors ligne, outil de référence hors ligne, parcours sur le réseau Hardhat en mémoire, capture derrière un pont synthétique (CT-4 §3 à §9)",
    "specs": [
      "CT-4",
      "CT-6"
    ],
    "covers": [
      "CT-4 OP-1",
      "CT-4 OP-2",
      "CT-4 OP-3",
      "CT-4 OP-4",
      "CT-4 OP-5",
      "CT-4 OP-6",
      "CT-4 OP-7",
      "CT-4 OP-8",
      "CT-4 OP-9",
      "CT-4 OP-10",
      "CT-4 OP-11",
      "CT-4 OP-12",
      "CT-4 CP-1",
      "CT-4 CP-2",
      "CT-4 CP-3",
      "CT-4 CP-4",
      "CT-4 CP-5",
      "CT-4 CP-6",
      "CT-4 RG-18",
      "CT-4 EX-3.3",
      "CT-4 EX-4.1",
      "CT-4 EX-4.2",
      "CT-4 EX-4.3",
      "CT-4 EX-4.6",
      "CT-4 EX-4.7",
      "CT-4 EX-4.14",
      "CT-4 EX-4.15",
      "CT-4 EX-4.17",
      "CT-4 EX-4.19",
      "CT-4 EX-4.28",
      "CT-4 EX-5.1",
      "CT-4 EX-5.3",
      "CT-4 EX-5.6",
      "CT-4 EX-5.7",
      "CT-4 EX-5.10",
      "CT-4 EX-5.11",
      "CT-4 EX-6.1",
      "CT-4 EX-7.1",
      "CT-4 EX-7.2",
      "CT-4 EX-7.3",
      "CT-4 EX-7.4",
      "CT-4 EX-7.5",
      "CT-4 EX-7.6",
      "CT-4 EX-7.7",
      "CT-4 EX-7.8",
      "CT-4 EX-7.16",
      "CT-4 EX-7.9",
      "CT-4 EX-7.10",
      "CT-4 EX-7.11",
      "CT-4 EX-7.12",
      "CT-4 EX-7.17",
      "CT-4 EX-7.13",
      "CT-4 EX-7.14",
      "CT-4 EX-7.15",
      "CT-4 EX-8.1",
      "CT-4 EX-8.2",
      "CT-4 EX-8.3",
      "CT-4 EX-8.4",
      "CT-4 EX-8.5",
      "CT-4 EX-8.19",
      "CT-4 EX-8.6",
      "CT-4 EX-8.7",
      "CT-4 EX-8.8",
      "CT-4 EX-8.9",
      "CT-4 EX-8.10",
      "CT-4 EX-8.11",
      "CT-4 EX-8.12",
      "CT-4 EX-8.21",
      "CT-4 EX-8.13",
      "CT-4 EX-8.14",
      "CT-4 EX-8.15",
      "CT-4 EX-8.16",
      "CT-4 EX-8.17",
      "CT-4 EX-8.20",
      "CT-4 EX-8.18",
      "CT-4 EX-A.2",
      "CT-4 EX-A.6",
      "CT-6 EX-11.8"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé ; réseau Hardhat en mémoire (31337) ; aucun binaire noorcore."
    ],
    "steps": [
      "Parcours de la section 7 (client inscrit, clé inscrite, racine ancrée, période close, reprise sans renvoi) ; révocation, administration du jeu, réassignation, approvisionnement ; un refus par OP-1 à OP-12 ; `signer`, `exporter`, `verifier`, `publier-jeu` hors ligne ; capture avec un pont synthétique, CP-1 à CP-6, reprise d'une étape `envoyee` sans renvoi."
    ],
    "oracle": "Chaque étape `capturee` ou `faite`, `result` conforme ; `verifier` rend R-1 à R-10 ; export des parties égal à `spec/vecteurs/ct-6/registre/periode-1` ; codes d'EX-7.4.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — exigences vérifiables hors ligne"
        },
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — outil de référence hors ligne (signer, exporter, verifier, publier-jeu)"
        },
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — outil de référence sur le réseau Hardhat en mémoire (31337, --sans-capture)"
        },
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — capture derrière un pont synthétique (CP-1 à CP-6, 9.3, 8.6, EX-7.16, EX-8.18 ; EX-A.6)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/registreCt4.test.js"
    },
    "threats": [
      "MN-40",
      "MN-53",
      "MN-56",
      "MN-57",
      "MN-72",
      "MN-73"
    ]
  },
  {
    "id": "TU-36",
    "level": "TU",
    "title": "Planificateur d'ancrage en bibliothèque : comptages, coût, série des points, admission, complétude (CT-5 §3, §4, §10.3, §12)",
    "specs": [
      "CT-5"
    ],
    "covers": [
      "CT-5 EX-4.11",
      "CT-5 EX-12.1",
      "CT-5 EX-12.2",
      "CT-5 AN-2",
      "CT-5 AN-3",
      "CT-5 AN-4",
      "CT-5 AN-59",
      "CT-5 AN-60",
      "CT-5 AN-61",
      "CT-5 EX-10.7",
      "CT-5 EX-4.1",
      "CT-5 EX-4.2",
      "CT-5 EX-4.3",
      "CT-5 EX-4.9",
      "CT-5 AN-1"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/ancrage.mjs` (horloge injectée, aucun réseau) présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "`compterJetons` sur la table de 4.6 ; formule de coût ; `tableEcheances` avec un jeton refusé ; `constaterCadence` et alerte `point_manquant` ; `admettrePoint` ; `verifierCompletudeRegistre` ; AN-1 sur la configuration."
    ],
    "oracle": "Comptages et coûts égaux aux tables ; alertes et refus exactement ceux que la règle nomme.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : comptages et coût (EX-4.11, section 12)"
        },
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : série des points, échéances, admission et complétude au registre (AN-2, AN-3, AN-61)"
        },
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : schémas ancrage-v0 et planificateur-ancrage-v0 (EX-4.8, EX-8.16, EX-A.3)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/ancrage.test.js"
    },
    "threats": [
      "MN-41",
      "MN-63",
      "MN-65"
    ]
  },
  {
    "id": "TU-37",
    "level": "TU",
    "title": "Attestation de périmètre et procès-verbal de cérémonie en bibliothèque : condensés, signatures, séparation des domaines, AT-1 à AT-4 (CT-7 §5.7, §5.8, §7.2, §7.7)",
    "specs": [
      "CT-7"
    ],
    "covers": [
      "CT-7 EX-7.7",
      "CT-7 EX-7.16",
      "CT-7 EX-5.7",
      "CT-7 EX-5.8",
      "CT-7 EX-A.15",
      "CT-7 AT-1",
      "CT-7 AT-2",
      "CT-7 AT-3",
      "CT-7 AT-4",
      "CT-7 AT-5",
      "CT-7 AT-6",
      "CT-7 AT-7",
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
      "CT-7 §4.3",
      "CT-7 §4.4"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/securite.mjs` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "`P_P`, `JCS(P)` de 3 201 octets, `D_P`, `M`, signatures des comptes 1 et 2 ; `P_C`, `JCS(V)` de 4 748 octets, `D_C` ; séparation des domaines contre tous les préfixes de CT-1, CT-3 et `P_P`/`P_C` ; AT-1 à AT-4 hors dossier ; tables 4.3, 4.4 et CR-5 lues dans le texte."
    ],
    "oracle": "Valeurs égales à §7.2 et §5.10 ; `verifyMessage` recouvre chaque signataire ; une AT- non exécutée porte `prerequis_en_echec`.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : attestation de périmètre, condensé et signature (§7.1, §7.2)"
        },
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : vérifications AT-1 à AT-4 hors dossier (EX-7.16, cas de la table d'EX-A.8)"
        },
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : procès-verbal de cérémonie, exemple de §5.10 (EX-5.7)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/securite.test.js"
    },
    "threats": [
      "MN-32",
      "MN-36",
      "MN-37",
      "MN-39",
      "MN-81",
      "MN-83",
      "MN-92",
      "MN-94"
    ]
  },
  {
    "id": "TU-38",
    "level": "TU",
    "title": "Bibliothèques du déploiement et de l'exploitation : fichiers de conteneur, configuration rapide, archive autonome, outils donnés dès maintenant, configuration modèle de production (CT-8 §3.6, §4, §7.3, §8, §10.14)",
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
      "CT-8 EX-3.6",
      "CT-8 EX-4.1",
      "CT-8 EX-4.2",
      "CT-8 EX-4.3",
      "CT-8 EX-4.4",
      "CT-8 §7.3",
      "CT-8 IR-3",
      "CT-8 IR-4",
      "CT-8 IC-5",
      "CT-8 EX-10.14",
      "CT-8 EX-10.13",
      "CT-8 SV-8",
      "CT-8 EX-A.16",
      "CT-8 EX-A.17"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/deploiement.mjs`, `scripts/lib/exploitation.mjs`, `deploiement/` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "CO-1 à CO-14 sur `deploiement/compose/*.yaml`, SHA-256 égaux à 4.2 et 4.3 ; bloc de 4.1 égal à `images.json` ; configuration rapide reproduite à l'octet ; archive de déploiement suffisante aux outils d'IR-3, IR-4 et IC-5 ; outils d'EX-10.14 présents ; sept rubriques de chaque runbook ; configuration modèle de production."
    ],
    "oracle": "Égalités octet pour octet avec les blocs de CT-8 ; codes 0, 1 et 2 attendus.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/deploiement.test.js",
          "describe": "CT-8 §4 : fichiers de conteneur de référence"
        },
        {
          "file": "test/deploiement.test.js",
          "describe": "CT-8 §7.3 : configuration de l'installation rapide"
        },
        {
          "file": "test/deploiement.test.js",
          "describe": "CT-8 EX-3.6 : archive de déploiement autonome"
        },
        {
          "file": "test/exploitation.test.js",
          "describe": "CT-8 §8 : configuration modèle de production"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/deploiement.test.js"
    },
    "threats": [
      "MN-22",
      "MN-25"
    ]
  },
  {
    "id": "TU-39",
    "level": "TU",
    "title": "Outil du paquet réviseur : vérification, construction, instructions, corrections (CT-8 §13.5 à §13.11)",
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
      "CT-8 EX-13.1",
      "CT-8 EX-13.2",
      "CT-8 EX-13.3",
      "CT-8 EX-13.4",
      "CT-8 EX-13.5",
      "CT-8 EX-13.6",
      "CT-8 EX-13.7",
      "CT-8 EX-13.8",
      "CT-8 EX-13.9",
      "CT-8 EX-13.10",
      "CT-8 EX-13.11",
      "CT-8 EX-13.12",
      "CT-8 EX-13.13",
      "CT-8 EX-13.14",
      "CT-8 EX-13.15",
      "CT-8 EX-13.16",
      "CT-8 EX-13.17",
      "CT-8 EX-13.18",
      "CT-8 EX-13.19",
      "CT-8 EX-13.20",
      "CT-8 EX-13.21",
      "CT-8 EX-13.22",
      "CT-8 EX-13.23",
      "CT-8 EX-13.24",
      "CT-8 EX-13.25",
      "CT-8 EX-13.26",
      "CT-8 EX-13.27",
      "CT-8 EX-13.28",
      "CT-8 EX-13.29",
      "CT-8 EX-13.30",
      "CT-8 EX-13.31",
      "CT-8 EX-13.32",
      "CT-8 EX-13.33",
      "CT-8 EX-13.34",
      "CT-8 EX-13.35",
      "CT-8 EX-13.36",
      "CT-8 EX-13.37",
      "CT-8 EX-13.38",
      "CT-8 EX-12.9"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; `scripts/lib/paquet.mjs`, `scripts/paquet-reviseur/` présent.",
      "Aucun réseau, aucun conteneur, aucun binaire noorcore."
    ],
    "steps": [
      "Erreurs d'usage, archive absente, gzip, PR-1, PR-3, PR-7, PR-9 chacune seule, découpage GNU tar, PR-10, `--conserver`, paquet complet et PR-11, marque d'observation, `package.json` d'ethers ; construction : refus en code 2 ; instructions égales aux blocs de 13.11 et de même structure ; aucun « prouvé » sur le périmètre ni sur les ancres."
    ],
    "oracle": "Codes 0, 2, 4 et statuts PR- attendus ; octets égaux aux blocs de CT-8 ; résumés sans caractère de contrôle.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/paquet-reviseur.test.js",
          "describe": "CT-8 : outil de vérification du paquet réviseur, cas des tests (13.7, 13.8, EX-A.19)"
        },
        {
          "file": "test/paquet-reviseur.test.js",
          "describe": "CT-8 : outil de construction du paquet réviseur (13.5)"
        },
        {
          "file": "test/paquet-reviseur.test.js",
          "describe": "CT-8 : instructions au réviseur et textes des résumés (13.10, 13.11, EX-A.20)"
        },
        {
          "file": "test/paquet-reviseur.test.js",
          "describe": "CT-8 : corrections du paquet réviseur (découpage GNU tar, dates, casse, terminal, extraction, langues, copie jointe)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/paquet-reviseur.test.js"
    },
    "threats": [
      "MN-78"
    ]
  }
];
