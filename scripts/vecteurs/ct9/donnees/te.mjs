// Source de données du catalogue CT-9 : entrées TE- (section 9), telles
// qu'elles sont imprimées dans spec/vecteurs/ct-9/catalogue.json.

export const TE = [
  {
    "id": "TE-1",
    "level": "TE",
    "title": "Cas de démonstration « assurance » : agent de souscription et de tarification, de la capture au dossier vérifié",
    "specs": [
      "CT-2",
      "CT-3",
      "CT-4",
      "CT-5",
      "CT-6",
      "CT-8"
    ],
    "covers": [
      "CT-2 EX-19.1",
      "CT-2 EX-19.2",
      "CT-2 EX-19.3",
      "CT-3 EX-14.2",
      "CT-6 EX-14.2",
      "CT-8 EX-13.1"
    ],
    "preconditions": [
      "Phase 2 jusqu'à l'étape 8 : enregistreur, service d'approbation, composant d'ancrage, console, registre de développement (`chain/scripts/dev-net.sh start`), paquets de CT-8 ; machine de test du système de référence de CT-9 (section des mesures).",
      "Données fictives seulement ; clés de test ; aucun prix ; `docker compose` disponible sur la machine de test (indisponible sur la machine de rédaction)."
    ],
    "steps": [
      "Lancer l'agent scénarisé (dossier de souscription fictif : lecture, recherche, écriture `payments.create` soumise à approbation, échange de modèle).",
      "Approuver depuis la console avec deux comptes de test ; laisser le point de contrôle et l'ancre de période se produire ; clore la période.",
      "Exporter le dossier de l'écriture approuvée et un paquet réviseur ; vérifier sur une autre machine, sans réseau, par le vérificateur JavaScript et par le binaire Go ; vérifier le paquet en une commande."
    ],
    "oracle": "Dossier valide (code 0) avec les contrôles 1 à 8 réussis, A-1 à A-4 exécutés, point couvrant ancré ; verdict et énoncé identiques entre les deux vérificateurs ; paquet : code 0, PR-1 à PR-12 réussies ; la décision, son auteur et son instant sont dans le journal (CT-1 §5).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Cas construit à l'étape 8 du plan avec des données fictives ; composants non construits."
    },
    "threats": [
      "MN-1",
      "MN-18",
      "MN-22"
    ]
  },
  {
    "id": "TE-2",
    "level": "TE",
    "title": "Cas de démonstration « administration » : agent qui instruit des demandes de prestations publiques",
    "specs": [
      "CT-2",
      "CT-3",
      "CT-4",
      "CT-5",
      "CT-6",
      "CT-8"
    ],
    "covers": [
      "CT-2 EX-19.1",
      "CT-3 EX-14.2",
      "CT-6 EX-14.2",
      "CT-8 EX-13.1"
    ],
    "preconditions": [
      "Phase 2 jusqu'à l'étape 8 : enregistreur, service d'approbation, composant d'ancrage, console, registre de développement (`chain/scripts/dev-net.sh start`), paquets de CT-8 ; machine de test du système de référence de CT-9 (section des mesures).",
      "Données fictives seulement ; clés de test ; aucun prix ; `docker compose` disponible sur la machine de test (indisponible sur la machine de rédaction)."
    ],
    "steps": [
      "Même parcours que le cas « assurance » avec un outil d'écriture `decision.notify` soumis à approbation et un refus signé.",
      "Exporter le dossier du refus et celui d'un appel autorisé ; vérifier hors ligne."
    ],
    "oracle": "Comme le cas « assurance » ; le dossier du refus porte `approval.decision = refuse` et l'appel n'a pas été relayé (aucun événement `executee` pour l'appel refusé).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Cas construit à l'étape 8 ; composants non construits."
    },
    "threats": [
      "MN-1",
      "MN-44"
    ]
  },
  {
    "id": "TE-3",
    "level": "TE",
    "title": "Démonstration de référence en une commande : `docker compose up`, moins de deux minutes, verdict imprimé (CT-2 §19)",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-19.1",
      "CT-2 EX-19.2",
      "CT-2 EX-19.3",
      "CT-2 EX-19.4",
      "CT-2 EX-19.5"
    ],
    "preconditions": [
      "`demo/compose.yaml` et les six images de CT-2 §19.1 construites ; portable du système de référence sans accès à Internet autre que le téléchargement des images."
    ],
    "steps": [
      "`docker compose up` ; attendre la fin du service `verificateur` ; relever la sortie attendue de CT-2 §19.4 et la durée imprimée.",
      "Vérifier que `agent-demo` ne joint que l'enregistreur (réseaux Compose)."
    ],
    "oracle": "Sortie égale à CT-2 §19.4 ; durée < 120 s ; aucune connexion de l'agent hors du réseau `hotes` ; aucune clé réelle, aucun prix.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Images non construites ; Docker indisponible sur la machine de rédaction."
    },
    "threats": [
      "MN-1",
      "MN-22"
    ]
  },
  {
    "id": "TE-4",
    "level": "TE",
    "title": "Parcours CT-4 §7 sur le réseau de développement noorcore : client inscrit, racine ancrée, période close, certificats capturés",
    "specs": [
      "CT-4",
      "CT-6"
    ],
    "covers": [
      "CT-4 EX-4.4",
      "CT-4 EX-4.5",
      "CT-4 EX-4.8",
      "CT-4 EX-4.9",
      "CT-4 EX-4.10",
      "CT-4 EX-4.11",
      "CT-4 EX-4.12",
      "CT-4 EX-4.13",
      "CT-4 EX-4.16",
      "CT-4 EX-4.18",
      "CT-4 EX-4.20",
      "CT-4 EX-4.21",
      "CT-4 EX-4.22",
      "CT-4 EX-4.23",
      "CT-4 EX-4.24",
      "CT-4 EX-4.25",
      "CT-4 EX-4.26",
      "CT-4 EX-4.27",
      "CT-4 EX-6.1",
      "CT-4 EX-6.2",
      "CT-4 EX-6.3",
      "CT-4 EX-6.4",
      "CT-4 EX-6.5",
      "CT-4 EX-6.6",
      "CT-4 EX-6.7",
      "CT-4 EX-6.8",
      "CT-4 EX-6.9",
      "CT-4 EX-6.10",
      "CT-4 EX-6.11",
      "CT-4 EX-6.12",
      "CT-4 EX-6.13",
      "CT-4 EX-6.14",
      "CT-4 EX-6.15",
      "CT-4 EX-6.16",
      "CT-4 EX-6.17",
      "CT-4 EX-6.18",
      "CT-4 EX-6.19",
      "CT-4 EX-6.20",
      "CT-4 EX-6.21",
      "CT-4 EX-6.22",
      "CT-4 EX-6.23",
      "CT-4 EX-10.1",
      "CT-4 EX-10.2",
      "CT-4 EX-10.3",
      "CT-4 EX-10.8",
      "CT-4 EX-10.9",
      "CT-4 EX-10.4",
      "CT-4 EX-10.5",
      "CT-4 EX-10.6",
      "CT-4 EX-10.7",
      "CT-4 EX-11.1",
      "CT-4 EX-3.1",
      "CT-4 EX-3.2",
      "CT-4 EX-5.2",
      "CT-4 EX-5.4",
      "CT-4 EX-5.5",
      "CT-4 EX-5.8",
      "CT-4 EX-5.9",
      "CT-4 EX-5.12",
      "CT-4 EX-A.8"
    ],
    "preconditions": [
      "Binaire `chain/runtime/bin/noorcore` portant `noor_getCommitCertificate` (construit avec le correctif, hors dépôt public) et binaire `noortrace-verifier` de l'étape 2 ; hors CI (aucune étape de la CI n'exécute noorcore, CT-5 EX-A.7) : sans eux, le cas est mis en attente et son titre nomme la condition (EX-3.11)."
    ],
    "steps": [
      "`npm run e2e:registre` (`scripts/e2e/parcours-registre.mjs`) : démarrer le réseau de développement s'il ne tourne pas, déployer les contrats, exécuter 7.4 à 7.9 avec l'outil de référence pour un client fictif au slug neuf ; capturer chaque certificat ; `verifier` ; `certificat-commit.mjs` sur chaque certificat ; exporter `registre.json`, `certificat-commit.json`, `validateurs.json` et le fichier d'ancres ; faire rendre le contrôle 8 par `scripts/verify/dossier.mjs` et par `noortrace-verifier` ; arrêter ce qui a été démarré ; verdict JSON."
    ],
    "oracle": "`exit_code` 0 partout ; étapes `capturee` ou `faite` ; R-1 à R-10 `reussi` ; code 0 de `certificat-commit.mjs` sur les six certificats (CT-4 EX-7.15). L'épreuve humaine à l'aveugle est un TR-.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/registre-dev.test.js",
          "describe": "TE-4 — parcours du registre sur le réseau de développement noorcore (CT-4 §7 ; contrôle 8 par les deux vérificateurs)",
          "it": "client fictif inscrit, racine ancrée, période close, six certificats capturés et valides ; contrôle 8 réussi par scripts/verify/dossier.mjs et par le binaire Go"
        }
      ],
      "command": "npm run e2e:registre"
    },
    "threats": [
      "MN-55",
      "MN-58"
    ]
  },
  {
    "id": "TE-5",
    "level": "TE",
    "title": "De l'événement au dossier vérifié sur les vecteurs : `journal-demo` de CT-2, export des parties du registre, vérificateur de CT-6",
    "specs": [
      "CT-2",
      "CT-4",
      "CT-6"
    ],
    "covers": [
      "CT-2 EX-12.1",
      "CT-4 EX-9.8",
      "CT-6 EX-6.14",
      "CT-6 EX-8.4"
    ],
    "preconditions": [
      "Vecteurs `ct-2/evenements/journal-demo/dossier-seq-7`, `ct-4/capture/`, `ct-6/dossiers/` au commit éprouvé."
    ],
    "steps": [
      "Vérifier `dossier-seq-7` par la bibliothèque et la ligne de commande ; exporter les parties de la période 1 depuis les captures de CT-4 ; vérifier le dossier complet de CT-6 avec les ancres de test."
    ],
    "oracle": "Code 0 ; parties exportées égales à `ct-6/registre/periode-1` ; verdict « valide » du dossier complet.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : vecteurs spec/vecteurs/ct-2, rejoués",
          "it": "evenements/journal-demo/dossier-seq-7 : dossier CT-1 valide par verifierDossier et par scripts/verify/dossier.mjs (code 0)"
        },
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — vecteurs spec/vecteurs/ct-4",
          "it": "capture : CP-2 à CP-6 rejoués ; export des parties égal à spec/vecteurs/ct-6/registre/periode-1 (EX-9.8 à EX-9.10)"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : dossiers complets de spec/vecteurs/ct-6 par la ligne de commande",
          "it": "chaque dossier rend le code, les vérifications en échec, les statuts, les non-exécutions, les avertissements, l'énoncé et la borne de son attendu.json (V-1 à V-5)"
        }
      ],
      "command": "npx hardhat --config hardhat.config.mjs test test/verificateur.test.js"
    },
    "threats": [
      "MN-23"
    ]
  },
  {
    "id": "TE-6",
    "level": "TE",
    "title": "Installation rapide IR-1 à IR-8 sur un hôte neuf, premier dossier vérifié",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 IR-1",
      "CT-8 IR-2",
      "CT-8 IR-3",
      "CT-8 IR-4",
      "CT-8 IR-5",
      "CT-8 IR-6",
      "CT-8 IR-7",
      "CT-8 IR-8",
      "CT-8 EX-7.1",
      "CT-8 EX-7.2",
      "CT-8 EX-7.3",
      "CT-8 EX-7.4",
      "CT-8 EX-3.6"
    ],
    "preconditions": [
      "Archive de déploiement 0.1 construite ; hôte du système de référence avec moteur de conteneurs ; images construites et épinglées."
    ],
    "steps": [
      "Suivre IR-1 à IR-8 à la lettre, sans autre document ; chronométrer chaque pas (mesure TM-) ; vérifier le premier dossier."
    ],
    "oracle": "Chaque résultat attendu d'IR-n observé ; contrôle préalable `pret` ; dossier d'IR-8 valide (code 0) ; somme des durées publiée, atteinte ou non (900 s cible).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Enregistreur non construit ; CT-8 §15 : « ni l'installation rapide ni l'installation complète n'ont été exécutées »."
    },
    "threats": [
      "MN-14"
    ]
  },
  {
    "id": "TE-7",
    "level": "TE",
    "title": "Installation complète IC-1 à IC-18 sur une machine vierge, en moins d'une journée, avec le seul document",
    "specs": [
      "CT-8",
      "CT-7"
    ],
    "covers": [
      "CT-8 IC-1",
      "CT-8 IC-2",
      "CT-8 IC-3",
      "CT-8 IC-4",
      "CT-8 IC-5",
      "CT-8 IC-6",
      "CT-8 IC-7",
      "CT-8 IC-8",
      "CT-8 IC-9",
      "CT-8 IC-10",
      "CT-8 IC-11",
      "CT-8 IC-12",
      "CT-8 IC-13",
      "CT-8 IC-14",
      "CT-8 IC-15",
      "CT-8 IC-16",
      "CT-8 IC-17",
      "CT-8 IC-18",
      "CT-8 EX-8.2",
      "CT-8 EX-8.3",
      "CT-8 EX-8.4",
      "CT-8 EX-8.5",
      "CT-8 EX-8.6",
      "CT-8 EX-8.7",
      "CT-8 EX-3.1",
      "CT-8 EX-3.2",
      "CT-8 EX-3.3",
      "CT-8 EX-3.4",
      "CT-8 EX-3.5",
      "CT-8 EX-3.7",
      "CT-8 EX-3.8",
      "CT-8 EX-3.9",
      "CT-8 EX-3.10",
      "CT-8 EX-3.11",
      "CT-8 EX-3.12",
      "CT-8 EX-3.13",
      "CT-8 EX-3.14",
      "CT-8 EX-3.15",
      "CT-8 TP-1",
      "CT-8 TP-2",
      "CT-8 TP-3",
      "CT-8 TP-4",
      "CT-8 TP-5",
      "CT-8 TP-6",
      "CT-8 TP-7",
      "CT-8 TP-8",
      "CT-7 EX-5.1",
      "CT-7 EX-5.2",
      "CT-7 EX-5.3",
      "CT-7 EX-5.4",
      "CT-7 EX-5.5",
      "CT-7 EX-5.6",
      "CT-7 EX-5.9",
      "CT-7 EX-5.11",
      "CT-7 EX-5.12",
      "CT-7 EX-7.1",
      "CT-7 EX-7.2",
      "CT-7 EX-7.3",
      "CT-7 EX-7.4",
      "CT-7 EX-7.5",
      "CT-7 EX-7.6",
      "CT-7 EX-7.8",
      "CT-7 EX-7.9"
    ],
    "preconditions": [
      "Machine vierge du système de référence ; ingénieur d'exploitation extérieur au projet ; archive 0.1 ; script de préparation de l'hôte (IC-2) livré."
    ],
    "steps": [
      "Suivre IC-1 à IC-18 ; conduire la cérémonie de CT-7 §5.4 (IC-7) ; produire l'attestation (IC-17) ; poser les tâches planifiées TP-1 à TP-8 ; clore le procès-verbal.",
      "Relever les durées, l'attente d'IC-16 et IC-17 à part, le nombre d'informations manquantes (EX-8.1, mesure TM-)."
    ],
    "oracle": "Contrôle préalable final `pret` ; premier dossier valide (IC-15) ; procès-verbal de cérémonie vérifié (CR-1 à CR-12) ; attestation inscrite (AT-6) ; chaque tâche planifiée présente ; durée totale publiée.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Composants non construits ; script de préparation absent de l'archive 0.1 (CT-8 §15)."
    },
    "threats": [
      "MN-14",
      "MN-33",
      "MN-88"
    ]
  },
  {
    "id": "TE-8",
    "level": "TE",
    "title": "Flux réseau FL-1 à FL-31 observés sur le déploiement de test et runbooks RB-1 à RB-8 rejoués",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 FL-1",
      "CT-8 FL-2",
      "CT-8 FL-3",
      "CT-8 FL-4",
      "CT-8 FL-5",
      "CT-8 FL-6",
      "CT-8 FL-7",
      "CT-8 FL-8",
      "CT-8 FL-9",
      "CT-8 FL-10",
      "CT-8 FL-11",
      "CT-8 FL-12",
      "CT-8 FL-13",
      "CT-8 FL-14",
      "CT-8 FL-15",
      "CT-8 FL-16",
      "CT-8 FL-17",
      "CT-8 FL-18",
      "CT-8 FL-19",
      "CT-8 FL-20",
      "CT-8 FL-21",
      "CT-8 FL-22",
      "CT-8 FL-23",
      "CT-8 FL-24",
      "CT-8 FL-25",
      "CT-8 FL-26",
      "CT-8 FL-27",
      "CT-8 FL-28",
      "CT-8 FL-29",
      "CT-8 FL-30",
      "CT-8 FL-31",
      "CT-8 RB-1",
      "CT-8 RB-2",
      "CT-8 RB-3",
      "CT-8 RB-4",
      "CT-8 RB-5",
      "CT-8 RB-6",
      "CT-8 RB-7",
      "CT-8 RB-8",
      "CT-8 EX-5.1",
      "CT-8 EX-5.2",
      "CT-8 EX-5.3",
      "CT-8 EX-5.4",
      "CT-8 EX-5.5",
      "CT-8 EX-5.6",
      "CT-8 EX-5.7",
      "CT-8 EX-10.1",
      "CT-8 EX-10.2",
      "CT-8 EX-10.3",
      "CT-8 EX-10.4",
      "CT-8 EX-10.5",
      "CT-8 EX-10.6",
      "CT-8 EX-10.7",
      "CT-8 EX-10.8",
      "CT-8 EX-10.9",
      "CT-8 EX-10.12",
      "CT-8 EX-10.15",
      "CT-8 EX-10.16",
      "CT-8 EX-10.17",
      "CT-8 EX-10.18",
      "CT-8 EX-10.19",
      "CT-8 EX-10.20",
      "CT-8 EX-10.21",
      "CT-8 EX-10.22",
      "CT-8 EX-10.23"
    ],
    "preconditions": [
      "Déploiement de production de test (TE- installation complète) ; relevé du pare-feu ; supervision livrée (lot suivant)."
    ],
    "steps": [
      "Relever chaque flux ouvert et chaque flux fermé pendant le scénario de démonstration ; provoquer chaque incident de RB-1 à RB-8 (écrivain arrêté, bail perdu, ancrage dégradé, prestataire injoignable, perte d'une copie WORM, saut d'horloge, RPC injoignable, suspicion de compromission) et dérouler le runbook."
    ],
    "oracle": "Seuls les flux FL- déclarés sont observés ; chaque runbook mène à l'état « rétabli » qu'il décrit sans supprimer, tronquer ni réécrire un fichier du journal ; l'après-incident nomme le test de CT-9 qui couvre la correction (CT-8 §10.11).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Déploiement et supervision non construits."
    },
    "threats": [
      "MN-29",
      "MN-75",
      "MN-96"
    ]
  },
  {
    "id": "TE-9",
    "level": "TE",
    "title": "Sauvegarde et reprise : chemins A, B et C, continuité de la chaîne, procès-verbaux",
    "specs": [
      "CT-8",
      "CT-2"
    ],
    "covers": [
      "CT-8 EX-11.1",
      "CT-8 EX-11.2",
      "CT-8 EX-11.3",
      "CT-8 EX-11.4",
      "CT-8 EX-11.5",
      "CT-8 EX-11.8",
      "CT-8 EX-11.9",
      "CT-8 EX-11.10",
      "CT-8 EX-11.11",
      "CT-8 EX-11.12",
      "CT-8 EX-11.13",
      "CT-8 EX-11.14",
      "CT-8 EX-11.15",
      "CT-8 EX-11.16",
      "CT-8 EX-11.17",
      "CT-8 EX-11.21",
      "CT-8 EX-11.22",
      "CT-8 EX-11.23",
      "CT-8 EX-11.24",
      "CT-2 EX-12.16",
      "CT-2 EX-12.17",
      "CT-7 EX-8.12",
      "CT-7 EX-8.13",
      "CT-7 EX-8.16"
    ],
    "preconditions": [
      "Déploiement de test avec copies WORM ; archive de sauvegarde ; procès-verbaux de la chaîne d'outil."
    ],
    "steps": [
      "Sauvegarder ; détruire le volume ; restaurer par le chemin A, puis B, puis C sur trois copies du déploiement ; vérifier la continuité de la chaîne et les procès-verbaux par `proces-verbal.mjs verifier`."
    ],
    "oracle": "Après chaque chemin, le vérificateur accepte un dossier qui chevauche la reprise ; PV-1 à PV-10 réussies ; les durées sont publiées (mesure TM-37 : RPO et RTO par composant, cadence de sauvegarde ; rapport de mesure, jamais la consignation), aucune n'est inventée.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Composants non construits ; CT-8 §15 : aucun outil de sauvegarde."
    },
    "threats": [
      "MN-19",
      "MN-26"
    ]
  },
  {
    "id": "TE-10",
    "level": "TE",
    "title": "Mode observation de bout en bout : capture sans blocage, rapport d'observation, passage au mode bloquant",
    "specs": [
      "CT-8",
      "CT-2",
      "CT-3"
    ],
    "covers": [
      "CT-8 EX-12.2",
      "CT-2 EX-14.13",
      "CT-2 EX-14.14",
      "CT-2 EX-14.15",
      "CT-2 EX-14.16",
      "CT-2 EX-14.17",
      "CT-3 EX-11.11",
      "CT-3 EX-11.12",
      "CT-3 EX-11.13",
      "CT-3 EX-11.14",
      "CT-3 EX-11.15"
    ],
    "preconditions": [
      "Installation rapide (mode observation) ; agent de démonstration."
    ],
    "steps": [
      "Jouer le scénario ; couper le service d'approbation puis le stockage pendant des appels ; produire le rapport d'observation ; passer au mode bloquant (CT-8 §12.6)."
    ],
    "oracle": "Aucun appel relayable bloqué ni retardé par une décision ; appels perdus comptés (EX-12.3, EX-12.14) ; rapport égal à ce que `rapport-observation.mjs` tire du journal ; passage refusé tant qu'une retenue n'a pas de décision.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Composants non construits ; les bibliothèques sont couvertes par TU-/TV-."
    },
    "threats": []
  },
  {
    "id": "TE-11",
    "level": "TE",
    "title": "Haute disponibilité à écrivain unique : bascule du bail, pertes admises, jeton de clôture (CT-2 §13)",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-13.1",
      "CT-2 EX-13.2",
      "CT-2 EX-13.3",
      "CT-2 EX-13.4",
      "CT-2 EX-13.5",
      "CT-2 EX-13.6",
      "CT-2 EX-13.10",
      "CT-2 EX-13.7",
      "CT-2 EX-13.8",
      "CT-2 EX-13.9",
      "CT-2 EX-12.4",
      "CT-2 EX-12.5",
      "CT-2 EX-12.6",
      "CT-2 EX-12.7",
      "CT-2 EX-12.8",
      "CT-2 EX-12.9",
      "CT-2 EX-12.10",
      "CT-2 EX-12.11",
      "CT-2 EX-12.12",
      "CT-2 EX-12.13",
      "CT-2 EX-12.22",
      "CT-2 EX-12.14",
      "CT-2 EX-12.15",
      "CT-2 EX-12.18",
      "CT-2 EX-12.19",
      "CT-2 EX-12.20",
      "CT-2 EX-12.21",
      "CT-2 EX-12.23",
      "CT-2 EX-12.24",
      "CT-2 EX-12.25",
      "CT-2 EX-12.26",
      "CT-2 EX-12.27",
      "CT-2 EX-12.28"
    ],
    "preconditions": [
      "Deux démons réels `bin/noortrace --config` (étape 4) sur le même journal ; magasin de bail `file` puis `etcd` 3.5 de test (image épinglée par condensé, en conteneur Docker) ; serveur d'outils de test qui journalise ses exécutions ; binaire Go `noortrace-verifier` (go1.27.3) pour la vérification des dossiers."
    ],
    "steps": [
      "Couper l'instance titulaire de son bail pendant une écriture en vol (`file` : auxiliaire flock(1) tué ; `etcd` : instance figée au-delà de lease.ttl_ms) ; mesurer la bascule ; tenter une écriture par l'ancienne instance ; relire les segments et le journal d'intention ; clore la période et vérifier les dossiers d'un événement de chaque instance."
    ],
    "oracle": "Une seule chaîne continue ; écriture de l'ancienne instance refusée par l'époque (aucun fichier qu'elle ouvre sous son époque après la prise du bail par l'autre, EX-13.5 (1)) ; pertes dans les bornes de CT-2 §13.5 (l'écriture en vol n'a qu'un événement, de reprise ; EX-4.46) ; dossiers valides pour les deux vérificateurs.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur-ha-bascule.test.js",
          "describe": "TE-11 — haute disponibilité à écrivain unique : bascule du bail (magasin file puis etcd), pertes admises, jeton de clôture ; dossiers vérifiés par les deux vérificateurs",
          "it": "A sert et B attend : chaque appel de A répondu ; B passif (santé standby, -31010 bail_non_detenu)"
        },
        {
          "file": "test/enregistreur-ha-bascule.test.js",
          "describe": "TE-11 — haute disponibilité à écrivain unique : bascule du bail (magasin file puis etcd), pertes admises, jeton de clôture ; dossiers vérifiés par les deux vérificateurs",
          "it": "bascule mesurée de la coupure de A à la santé ok de B, au plus lease.ttl_ms + lease.renew_ms + 10 s ; B prend le bail avec une époque plus grande et produit l'événement de reprise de l'intention en vol"
        },
        {
          "file": "test/enregistreur-ha-bascule.test.js",
          "describe": "TE-11 — haute disponibilité à écrivain unique : bascule du bail (magasin file puis etcd), pertes admises, jeton de clôture ; dossiers vérifiés par les deux vérificateurs",
          "it": "écriture de l'ancienne instance refusée par l'époque : -31010, ligne lease_lost ; l'écriture en vol n'est pas rendue comme acquise par A ; aucune fourche"
        },
        {
          "file": "test/enregistreur-ha-bascule.test.js",
          "describe": "TE-11 — haute disponibilité à écrivain unique : bascule du bail (magasin file puis etcd), pertes admises, jeton de clôture ; dossiers vérifiés par les deux vérificateurs",
          "it": "relecture des segments et du journal d'intention : une seule chaîne continue (seq et prev_hash), aucun événement d'époque inférieure après la première époque de B, segments d'époques croissantes ; l'intention de l'écriture en vol est levée par son événement de reprise"
        },
        {
          "file": "test/enregistreur-ha-bascule.test.js",
          "describe": "TE-11 — haute disponibilité à écrivain unique : bascule du bail (magasin file puis etcd), pertes admises, jeton de clôture ; dossiers vérifiés par les deux vérificateurs",
          "it": "pertes dans les bornes de CT-2 §13.5 : chaque appel répondu par A ou par B a son événement ; l'écriture en vol, exécutée une fois côté serveur, a son événement de reprise"
        },
        {
          "file": "test/enregistreur-ha-bascule.test.js",
          "describe": "TE-11 — haute disponibilité à écrivain unique : bascule du bail (magasin file puis etcd), pertes admises, jeton de clôture ; dossiers vérifiés par les deux vérificateurs",
          "it": "ancienne instance : aucun fichier d'attente ouvert sous une époque inférieure à celle de B après sa prise du bail (EX-13.5 (1)) ; une fois la période close, l'écriture en vol n'a qu'un événement, celui de reprise (EX-4.46 : l'événement en attente est scellé à la place de l'événement de reprise, jamais en plus ; 13.5)"
        },
        {
          "file": "test/enregistreur-ha-bascule.test.js",
          "describe": "TE-11 — haute disponibilité à écrivain unique : bascule du bail (magasin file puis etcd), pertes admises, jeton de clôture ; dossiers vérifiés par les deux vérificateurs",
          "it": "période close à l'heure suivante : journal accepté par le noyau ; dossiers d'un événement écrit par A et d'un événement écrit par B valides pour le noyau ET pour le binaire Go (go1.27.3)"
        }
      ]
    },
    "threats": [
      "MN-19",
      "MN-26"
    ]
  },
  {
    "id": "TE-12",
    "level": "TE",
    "title": "Ancrage complet d'une racine : point de contrôle, ancre au registre, jeton RFC 3161, preuve OpenTimestamps, dossier vérifié hors ligne",
    "specs": [
      "CT-5",
      "CT-6",
      "CT-1"
    ],
    "covers": [
      "CT-5 EX-9.1",
      "CT-5 EX-9.2",
      "CT-5 EX-9.3",
      "CT-5 EX-9.4",
      "CT-5 EX-9.5",
      "CT-5 EX-9.6",
      "CT-5 EX-9.7",
      "CT-5 EX-9.8",
      "CT-5 EX-9.9",
      "CT-5 EX-10.1",
      "CT-5 EX-10.2",
      "CT-5 EX-10.3",
      "CT-5 EX-10.4",
      "CT-5 EX-10.5",
      "CT-5 EX-10.6",
      "CT-5 AN-44",
      "CT-5 AN-45",
      "CT-5 AN-46",
      "CT-5 AN-47",
      "CT-5 AN-48",
      "CT-5 AN-49",
      "CT-5 AN-50",
      "CT-5 AN-51",
      "CT-5 AN-52",
      "CT-5 AN-53",
      "CT-5 AN-20",
      "CT-5 AN-21",
      "CT-5 EX-3.1",
      "CT-5 EX-3.2",
      "CT-5 EX-3.3",
      "CT-5 EX-3.4",
      "CT-5 EX-3.5",
      "CT-5 EX-4.8",
      "CT-5 EX-4.10",
      "CT-5 EX-4.12",
      "CT-5 EX-4.13",
      "CT-5 EX-8.1",
      "CT-5 EX-8.2",
      "CT-6 EX-13.1",
      "CT-6 EX-13.2",
      "CT-6 EX-13.3",
      "CT-6 EX-13.12",
      "CT-6 EX-13.6",
      "CT-6 EX-13.7",
      "CT-6 EX-13.13",
      "CT-6 EX-13.8",
      "CT-6 EX-13.9",
      "CT-6 EX-13.10",
      "CT-6 EX-13.11",
      "CT-6 EX-13.14",
      "CT-6 EX-13.15",
      "CT-6 EX-13.16",
      "CT-6 EX-13.17",
      "CT-6 EX-13.18",
      "CT-6 EX-13.19",
      "CT-6 EX-4.1",
      "CT-6 EX-4.2",
      "CT-6 EX-4.4",
      "CT-6 EX-4.8",
      "CT-6 EX-4.9",
      "CT-6 EX-4.10",
      "CT-6 EX-4.14",
      "CT-1 §10.9"
    ],
    "preconditions": [
      "Démon `noortrace` réel (processus enfant) de l'enregistreur (étape 4) avec le composant d'ancrage de l'étape 5 branché (`anchoring.ancrage`, document `ancrage-v0` validé, secrets résolus, clé de chaîne de classe D) ; vérificateur JavaScript de référence (`scripts/verify/dossier.mjs`, boîte noire) et binaire Go de CT-6 (go1.27.3), même fichier d'ancres.",
      "Variante hors réseau public : serveurs RFC 3161 internes de référence du paquet d'ancrage (points en HTTP local, principal en TLS mutuel avec un `qualified` d'exemple), calendriers OpenTimestamps factices en TLS (chaîne regtest), nœud noorcore factice en JSON-RPC, horloge hybride à cadence réduite admise par le schéma (`checkpoint_interval_s` 10).",
      "Variante sur le réseau de développement réel : quatre validateurs noorcore (`chain/scripts/dev-net.sh`), client inscrit par le parcours de référence (`npm run e2e:registre`) ; en attente quand le réseau n'est pas debout, et son cas des calendriers publics hors `NOORTRACE_RESEAU_PUBLIC=1`, condition nommée dans le titre (EX-3.11) ; `unshare -n` pour la vérification sans réseau."
    ],
    "steps": [
      "Laisser une période recevoir ses points (remis au composant, ancrés au registre), un point contresigné et soumis aux calendriers à l'échéance médiane, et ses trois ancres de clôture (ancre au registre incluse et capturée, jeton du principal, preuve OpenTimestamps) ; relayer la clôture `submitPeriod` après la demande signée des approbateurs.",
      "Exporter le dossier d'un événement avec `points-de-controle.json`, avant puis après la mise à niveau OpenTimestamps ; le vérifier par les deux vérificateurs, sans réseau (`unshare -n`) sur le réseau de développement.",
      "`noortrace-ctl ancrage` (état, métriques, retrait de qualification) et `noortrace-ctl reload` ; arrêt propre."
    ],
    "oracle": "Contrôles 4, 5 et 8 et K-7 à K-9 réussis après la mise à niveau (avant elle : contrôle 5 et K-9 non exécutés, preuve en attente) ; P-5 de CT-5 tenue (aucun réseau) ; énoncé du vérificateur conforme à CT-6 §7.9 (fragment FK), même verdict et même énoncé entre les deux vérificateurs ; le dossier antérieur est inchangé et un réexport est dû (CT-5 EX-10.5) ; file durable à états finaux à l'arrêt.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur-ancrage-parcours.test.js",
          "describe": "enregistreur + ancrage (lot F2), TE-12 hors réseau public : démon réel, trois ancres sur la racine, dossier vérifié hors ligne par les deux vérificateurs"
        },
        {
          "file": "test/enregistreur-ancrage-parcours.test.js",
          "describe": "enregistreur + ancrage (lot F2), TE-12 sur le réseau de développement réel : démon réel, ancres des points et de la période incluses sur noorcore, clôture submitPeriod relayée, dossier vérifié sans réseau par les deux vérificateurs (CT-4 §7.4, §8.2, §8.6, §9.4 ; CT-5 P-5 ; CT-6 §7.9)"
        }
      ]
    },
    "threats": [
      "MN-17",
      "MN-24"
    ]
  },
  {
    "id": "TE-13",
    "level": "TE",
    "title": "Console : un approbateur s'inscrit, signe une décision depuis son portefeuille, le dossier exporté passe le vérificateur",
    "specs": [
      "CT-3",
      "CT-6"
    ],
    "covers": [
      "CT-3 EX-13.1",
      "CT-3 EX-13.2",
      "CT-3 EX-13.3",
      "CT-3 EX-13.4",
      "CT-3 EX-13.5",
      "CT-3 EX-13.6",
      "CT-3 EX-13.8",
      "CT-3 EX-13.11",
      "CT-3 EX-13.14",
      "CT-3 EX-13.20",
      "CT-3 EX-13.25",
      "CT-3 EX-13.26",
      "CT-3 EX-13.27",
      "CT-3 EX-14.2"
    ],
    "preconditions": [
      "Console et service de l'étape 6 ; portefeuille de test ; enregistreur de l'étape 4."
    ],
    "steps": [
      "Inscrire un approbateur par preuve de possession ; soumettre un appel à approuver ; signer depuis la console ; exporter le dossier."
    ],
    "oracle": "Inscription acceptée (AN-3) ; `approbations.json` porte la signature recouvrée à l'adresse inscrite ; dossier valide avec A-1 à A-4 réussis.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 6,
      "blocking": "Console d'exploitation et service non construits ; seule la console de référence existe (TU-)."
    },
    "threats": [
      "MN-35",
      "MN-51"
    ]
  },
  {
    "id": "TE-14",
    "level": "TE",
    "title": "Journal de l'enregistreur sur lui-même : JS-1 à JS-12 observés sur le démon",
    "specs": [
      "CT-7",
      "CT-2"
    ],
    "covers": [
      "CT-7 JS-1",
      "CT-7 JS-2",
      "CT-7 JS-3",
      "CT-7 JS-4",
      "CT-7 JS-5",
      "CT-7 JS-6",
      "CT-7 JS-7",
      "CT-7 JS-8",
      "CT-7 JS-9",
      "CT-7 JS-10",
      "CT-7 JS-11",
      "CT-7 JS-12",
      "CT-7 EX-6.1",
      "CT-7 EX-6.2",
      "CT-7 EX-6.3",
      "CT-2 EX-17.1",
      "CT-2 EX-17.2",
      "CT-2 EX-17.3",
      "CT-2 EX-17.4"
    ],
    "preconditions": [
      "Démon `noortrace` réel (processus enfant) de l'étape 4 avec son journal d'exploitation et le composant d'ancrage de l'étape 5 branché (registre factice coupable pour JS-11) ; `noortrace-ctl`.",
      "Pour JS-9 et JS-10 : support WORM S3 à Object Lock de LocalStack en conteneur Docker (image épinglée par condensé), derrière un mandataire TLS, bucket verrouillé en COMPLIANCE ; sans Docker, ces cas sont en attente (EX-3.11)."
    ],
    "steps": [
      "Provoquer chaque situation de la table de CT-7 §6.1 (démarrage, arrêt, bail, rotation de la clé de l'enregistreur, rotation de la clé de chaîne, politique, configuration, saut d'horloge, gel, perte WORM, ancrage dégradé, attestation) ; relire la chaîne et le journal d'exploitation.",
      "Forcer la rotation du journal d'exploitation par `supervision.ops_log.rotate_max_bytes`, puis simuler un disque plein pendant le relais."
    ],
    "oracle": "Chaque situation produit l'événement ou la ligne que la table nomme (« porté » ou « aucun » selon la colonne) ; aucun secret dans les lignes, la file durable ni `acquisitions.ndjson`. JS-5 : aucun événement ne porte la rotation de la clé de chaîne, et la rotation d'urgence est refusée (`registre_non_branche`) ; la révocation et l'inscription au registre que la table nomme pour JS-5 sont le complément. Rotation : au plus `keep_files` fichiers conservés ; disque plein : chaque ligne non écrite incrémente `noortrace_ops_log_dropped_total` d'une unité et le relais continue (CT-2 EX-9.7, EX-17.4).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur-journal-soi.test.js",
          "describe": "TE-14 : journal de l'enregistreur sur lui-même, JS-1 à JS-12 de CT-7 §6.1 observés sur le démon réel (CT-2 EX-17.1 à EX-17.4, EX-18.6 ; CT-7 EX-6.1 à EX-6.3)"
        },
        {
          "file": "test/enregistreur-journal-soi.test.js",
          "describe": "TE-14 : rotation du journal d'exploitation par supervision.ops_log.rotate_max_bytes et keep_files (EX-9.7, EX-17.4) sur un démon réel"
        },
        {
          "file": "test/enregistreur-journal-soi.test.js",
          "describe": "TE-14 (JS-9, JS-10) et complément TM-16 sur le support WORM réel (S3 à Object Lock en conteneur) : worm_legal_hold_observed, worm_copy_failed puis reprise, copie conforme d'ancres/"
        }
      ],
      "complement": {
        "phase2_step": 7,
        "blocking": "JS-5, colonne du journal : rotation d'urgence de la clé de chaîne relayée au registre (révocation et nouvelle inscription signées par les approbateurs au seuil, CT-4 §7, CT-2 EX-11.16, EX-11.19 point 4) ; le démon de l'étape 5 la refuse en le nommant (`registre_non_branche`, lecture 202 du LISEZMOI de `paquets/enregistreur`), reste rattaché, comme la clé de chaîne des classes A à C, à l'étape 7 (paquets et exploitation)."
      }
    },
    "threats": [
      "MN-18",
      "MN-96"
    ]
  },
  {
    "id": "TE-15",
    "level": "TE",
    "title": "Construction des images de référence : reproductibilité, `docker inspect`, volume nommé, compagnon d'immuabilité",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 EX-4.4",
      "CT-8 EX-3.13",
      "CT-8 EX-3.14",
      "CT-8 EX-3.15",
      "CT-8 EX-3.9"
    ],
    "preconditions": [
      "Fichiers de conteneur de référence ; hôte de test avec moteur de conteneurs ; deux constructions à des instants différents."
    ],
    "steps": [
      "Construire chaque image deux fois ; comparer les condensés ; `docker compose up` ; relever `docker inspect` (compte, racine en lecture seule, sondes) ; copier le répertoire de l'image dans un volume nommé neuf ; vérifier le compagnon (`CAP_FOWNER`, ouverture en lecture)."
    ],
    "oracle": "Condensés égaux ; chaque propriété de la description `images.json` observée ; propriétaire et mode recopiés ; attribut immuable posé.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Aucune image construite (CT-8 §3.6, §15) ; Docker indisponible ici."
    },
    "threats": [
      "MN-22",
      "MN-25"
    ]
  },
  {
    "id": "TE-16",
    "level": "TE",
    "title": "Matrice des pannes de CT-2 §14 rejouée sur le démon : classification des outils, ce qui est rendu à l'hôte, ce qui est journalisé, mode dégradé",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-14.1",
      "CT-2 EX-14.2",
      "CT-2 EX-14.3",
      "CT-2 EX-14.4",
      "CT-2 EX-14.5",
      "CT-2 EX-14.6",
      "CT-2 EX-14.7",
      "CT-2 EX-14.8",
      "CT-2 EX-14.9",
      "CT-2 EX-14.10",
      "CT-2 EX-14.11",
      "CT-2 EX-14.12",
      "CT-2 EX-14.18"
    ],
    "preconditions": [
      "Enregistreur `paquets/enregistreur` (étape 4) : démon réel `bin/noortrace --config` et son cœur monté en cours de processus avec des dépendances coupables (stockage, signataire, bail, horloge, service d'approbation simulé, serveur d'outils et fournisseur simulés) ; composant d'ancrage de l'étape 5 branché et support WORM S3 à Object Lock en conteneur pour les lignes « Ancrage », « Registre » et « Support WORM ».",
      "Ligne « clé indisponible » rejouée sur le démon réel en configuration de production avec un signataire de classe B (Vault Transit réel en conteneur, suspendu puis repris) : démon lancé par le superutilisateur et Docker exigés, sinon les cas sont en attente, condition nommée (EX-3.11) ; le travail « parcours-superutilisateur » de `ci.yml` les joue sans attente."
    ],
    "steps": [
      "Pour chaque ligne de la matrice de CT-2 §14.2, couper la dépendance pendant un appel de lecture puis d'écriture ; relever ce qui est rendu à l'hôte, ce qui est journalisé et les événements en attente ; rétablir la dépendance.",
      "Clôturer et exporter le dossier d'un événement scellé après chaque rétablissement ; le vérifier par les deux vérificateurs de CT-6."
    ],
    "oracle": "Comportement égal, ligne par ligne, à la matrice de §14.2 (colonnes E, L et M, rendu à l'hôte, raison, journal d'exploitation) ; événements en attente rejoués à l'identique ; aucun appel d'écriture relayé sans événement durable. Lignes éprouvées par les essais cités : « Stockage indisponible », « Clé indisponible » et « Panne après relais » (démon réel, signataire de classe B suspendu), « Serveur d'outils injoignable », « Délai du serveur d'outils » (dossiers acceptés par le binaire Go), « Fournisseur de modèle », les cinq lignes du service d'approbation et des décisions, « Rédaction au-delà de la borne de temps », « Ancrage » et « Ancrage des points », « Support WORM », « Registre », les deux lignes d'horloge, « Mémoire » (quotas, -31013 et 503), « Bail perdu », « Bail non détenu », les deux lignes de configuration. Les TA- des scénarios « l'enregistreur tombe » et « un prestataire est injoignable » retirent la réponse de chaque ligne.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur-signataires-parcours.test.js",
          "describe": "CT-9 TE-16, ligne « clé indisponible » de la matrice de CT-2 §14.2 (et « panne après relais »), rejouée sur le démon réel : Vault suspendu pendant une lecture puis une écriture, puis rétabli"
        },
        {
          "file": "test/enregistreur-mcp-exigences.test.js",
          "describe": "approbation au pas 3 à 7 (EX-4.49, EX-4.50, EX-7.16, 14.2)",
          "it": "14.2, EX-14.6, EX-14.8 : mode dégradé « stockage » : lecture passante relayée, réponse normale, événement en attente ; écriture bloquée ; « clé » bloque tout"
        },
        {
          "file": "test/enregistreur-coeur-reprise.test.js",
          "describe": "enregistreur, cœur : non-régression de la relecture A (stockage, reprise, bail)",
          "it": "R-A-3 (EX-12.8) : fdatasync en erreur (EIO) pour un groupe de trois événements → refusés, segment tronqué à la dernière ligne synchronisée, la chaîne reprend sans eux"
        },
        {
          "file": "test/enregistreur-modele-exigences.test.js",
          "describe": "§14 (colonne M), EX-14.16, §13.5 : pannes et arrêt",
          "it": "stockage indisponible avec failure.modele passant : relayé, pièces gardées en mémoire, événement en attente ; bloquant sinon"
        },
        {
          "file": "test/enregistreur-modele-exigences.test.js",
          "describe": "§14 (colonne M), EX-14.16, §13.5 : pannes et arrêt",
          "it": "mode dégradé « clé » : 503 au format de la route, rien n'est relayé, call_blocked compté"
        },
        {
          "file": "test/enregistreur-mcp-exigences.test.js",
          "describe": "4.4 relais de tools/call (EX-4.19 à EX-4.24, EX-4.43 à EX-4.48)",
          "it": "EX-4.46 : panne du stockage après relais → -31017 avec intent_id, événement gardé en attente"
        },
        {
          "file": "test/enregistreur-mcp-exigences.test.js",
          "describe": "4.4 relais de tools/call (EX-4.19 à EX-4.24, EX-4.43 à EX-4.48)",
          "it": "EX-4.33, EX-4.48 : le serveur meurt pendant l'appel → -31014 et événement ; relance au prochain appel"
        },
        {
          "file": "test/enregistreur-mcp-exigences.test.js",
          "describe": "4.3 agrégation (EX-4.9 à EX-4.18)",
          "it": "EX-4.18 : serveur injoignable omis de la liste, santé `serveur:<alias>`, appel → -31014 sans événement"
        },
        {
          "file": "test/enregistreur-mcp-parcours.test.js",
          "describe": "enregistreur, frontal MCP : parcours de bout en bout (hôtes, connecteur, serveurs stdio, journal vérifié)",
          "it": "l'hôte reçoit la liste agrégée, les résultats relayés, le signal d'approbation, les erreurs de la table de 4.4"
        },
        {
          "file": "test/enregistreur-mcp-parcours.test.js",
          "describe": "enregistreur, frontal MCP : parcours de bout en bout (hôtes, connecteur, serveurs stdio, journal vérifié)",
          "it": "chaque appel a produit un événement scellé ; délégation, politique, approbation et effets conformes (7.2)"
        },
        {
          "file": "test/enregistreur-mcp-parcours.test.js",
          "describe": "enregistreur, frontal MCP : parcours de bout en bout (hôtes, connecteur, serveurs stdio, journal vérifié)",
          "it": "le dossier de chaque appel est accepté par le binaire Go noortrace-verifier (go1.27.3)"
        },
        {
          "file": "test/enregistreur-modele-exigences.test.js",
          "describe": "EX-5.24 : délais du fournisseur",
          "it": "connexion impossible : 504 au format de la route, événement is_error, pièce noortrace_timeout phase connexion"
        },
        {
          "file": "test/enregistreur-modele-exigences.test.js",
          "describe": "EX-5.24 : délais du fournisseur",
          "it": "premier octet au-delà du délai : 504 ; silence au-delà d'idle_timeout_ms pendant un flux : flux clos, forme incomplète"
        },
        {
          "file": "test/enregistreur-mcp-exigences.test.js",
          "describe": "approbation au pas 3 à 7 (EX-4.49, EX-4.50, EX-7.16, 14.2)",
          "it": "14.2 : service d'approbation indisponible : écriture et outil susceptible bloqués (-31010 approbation) ; autre lecture passante, decision autorise, rule null"
        },
        {
          "file": "test/enregistreur-politique-exigences.test.js",
          "describe": "pas 3 : evaluer, charger et matrice de 14.2 (service d'approbation)",
          "it": "14.2, service indisponible, colonne E : une écriture est bloquée (-31010, approbation), sans pièce d'événement ni intention"
        },
        {
          "file": "test/enregistreur-politique-exigences.test.js",
          "describe": "pas 3 : evaluer, charger et matrice de 14.2 (service d'approbation)",
          "it": "EX-7.4 : sans réponse dans policy.approval.timeout_ms (service muet), indisponibilité : -31010 en moins de 3 s"
        },
        {
          "file": "test/enregistreur-politique-exigences.test.js",
          "describe": "pas 3 : evaluer, charger et matrice de 14.2 (service d'approbation)",
          "it": "EX-7.16 : réponse hors des combinaisons (membre manquant, ticket incohérent, rule nulle, jeu absent ou inexploitable, approval non scellé) : -31010, approval_response_invalid"
        },
        {
          "file": "test/enregistreur-politique-exigences.test.js",
          "describe": "14.2 : lectures susceptibles, lectures bloquantes, avant le premier charger",
          "it": "failure.approval_service.lecture bloquant : une lecture non susceptible est bloquée pendant l'indisponibilité"
        },
        {
          "file": "test/enregistreur-politique-exigences.test.js",
          "describe": "pas 5 et 6, mode erreur (EX-4.49, EX-7.12, EX-7.17 à EX-7.22, EX-12.23, CT-3 EX-11.3)",
          "it": "RL-3 : un service compromis qui sert de nouveau l'approbation consommée : -31010 approbation, approval_relay_refused, aucune intention"
        },
        {
          "file": "test/enregistreur-politique-exigences.test.js",
          "describe": "pas 5 et 6, mode erreur (EX-4.49, EX-7.12, EX-7.17 à EX-7.22, EX-12.23, CT-3 EX-11.3)",
          "it": "EX-7.17 : la retenue d'un ticket déjà décidé n'est pas scellée : -31010, identifiant_en_collision"
        },
        {
          "file": "test/enregistreur-sdk-exigences.test.js",
          "describe": "EX-6.4, EX-6.7 : approbation par le SDK (table d'EX-6.7)",
          "it": "EX-6.7, EX-10.23 : pièce « arguments » au-delà de la borne de temps : -31010 redaction pour une écriture, avant l'intention"
        },
        {
          "file": "test/enregistreur-coeur-approbations.test.js",
          "describe": "enregistreur, cœur : interface du service d'approbation (§7.5)",
          "it": "remises refusées : SG-2 (ticket inconnu), SG-5 (signature), SG-6 (seuil), SG-7 (auto-approbation), SG-3 (déjà décidé)"
        },
        {
          "file": "test/enregistreur-politique-exigences.test.js",
          "describe": "mode dégradé et entrées hostiles (14.2, EX-7.5, EX-7.19, EX-9.4)",
          "it": "décision pour un ticket inconnu (SG-2) et remise rejouée (SG-3, avec la décision scellée) : refusées, rien n'est scellé"
        },
        {
          "file": "test/enregistreur-politique-exigences.test.js",
          "describe": "pas 5 et 6, mode erreur (EX-4.49, EX-7.12, EX-7.17 à EX-7.22, EX-12.23, CT-3 EX-11.3)",
          "it": "ré-émission en attente : aucun événement, approval_pending, signal en_attente (CT-3 EX-7.19)"
        },
        {
          "file": "test/enregistreur-mcp-exigences.test.js",
          "describe": "approbation au pas 3 à 7 (EX-4.49, EX-4.50, EX-7.16, 14.2)",
          "it": "EX-4.50 : mode retenir : la requête est retenue jusqu'à la décision approuvée (acquitter held), puis relayée ; délai de rétention → en_attente"
        },
        {
          "file": "test/enregistreur-politique-exigences.test.js",
          "describe": "mode dégradé et entrées hostiles (14.2, EX-7.5, EX-7.19, EX-9.4)",
          "it": "décision remise pendant un mode dégradé : acquitter temporaire, rien n'est inscrit ; ré-émission en_attente ; scellée à la représentation, après la sortie"
        },
        {
          "file": "test/enregistreur-politique-exigences.test.js",
          "describe": "mode dégradé et entrées hostiles (14.2, EX-7.5, EX-7.19, EX-9.4)",
          "it": "expiration atteinte pendant un mode dégradé : différée (approval_expired_deferred), scellée à la sortie ; ré-émission : signal expire"
        },
        {
          "file": "test/enregistreur-ancrage-exigences.test.js",
          "describe": "enregistreur + ancrage (lot F2) : période rejouée à l'horloge réglable (EX-4.12, AN-43, TA-62, EX-4.9), copie WORM d'ancres/ et de la file (EX-5.15, EX-8.14, TM-16), rotation d'urgence",
          "it": "le composant est attaché après l'écrivain (anchoring_attached, contexte depuis le stockage) ; EX-4.12 : avec un prestataire qui ne répond jamais, le tic qui produit et remet un point rend la main sans attendre le réseau"
        },
        {
          "file": "test/enregistreur-journal-soi.test.js",
          "describe": "TE-14 : journal de l'enregistreur sur lui-même, JS-1 à JS-12 de CT-7 §6.1 observés sur le démon réel (CT-2 EX-17.1 à EX-17.4, EX-18.6 ; CT-7 EX-6.1 à EX-6.3)"
        },
        {
          "file": "test/enregistreur-worm-exigences.test.js",
          "describe": "copies de l'écrivain (EX-12.16, EX-12.17, EX-12.29, EX-12.30, EX-12.32, EX-12.33)",
          "it": "panne du support (14.2 « Support WORM ») : copie en échec consignée, jamais bloquante ; le balayage de la supervision la réessaie (EX-12.16) et met à jour noortrace_worm_copy_pending"
        },
        {
          "file": "test/enregistreur-journal-soi.test.js",
          "describe": "TE-14 (JS-9, JS-10) et complément TM-16 sur le support WORM réel (S3 à Object Lock en conteneur) : worm_legal_hold_observed, worm_copy_failed puis reprise, copie conforme d'ancres/",
          "it": "JS-10 perte d'une copie WORM : support coupé (partition TCP entre le démon et le support) pendant la clôture → worm_copy_failed (injoignable) ; support rétabli → le balayage de la supervision copie ce qui manque, noortrace_worm_copy_pending retombe"
        },
        {
          "file": "test/enregistreur-coeur-config.test.js",
          "describe": "horloge (EX-7.9, EX-7.13, 14.2)"
        },
        {
          "file": "test/enregistreur-coeur-config.test.js",
          "describe": "horloge au tic (R-A-2, EX-7.13, EX-12.24)",
          "it": "saut en avant détecté par le tic lui-même (aucun scellement entre-temps) : mode dégradé « horloge », clock_forward_jump, rien n'est clos"
        },
        {
          "file": "test/enregistreur-modele-securite.test.js",
          "describe": "EX-4.47 : quotas de la connexion d'hôte sur la passerelle",
          "it": "requêtes en cours (max_concurrent) : la seconde, pendant un flux, est bloquée (503) ; l'échange suivant passe"
        },
        {
          "file": "test/enregistreur-mcp-exigences.test.js",
          "describe": "4.4 relais de tools/call (EX-4.19 à EX-4.24, EX-4.43 à EX-4.48)",
          "it": "entrées hostiles : requête au-delà de request_max_bytes → -31013 (requete), sans pièce ; `_meta` piégé relayé tel quel mais jamais journalisé"
        },
        {
          "file": "test/enregistreur-ha-exigences.test.js",
          "describe": "cœur et magasin réseau (EX-13.1, EX-13.5, EX-13.6, EX-13.9, EX-13.10, 13.4)",
          "it": "EX-13.6, 14.2 « Bail perdu » : le bail repris par une autre instance → renouvellement refusé, lease_lost, mode dégradé « bail » : écritures et lectures bloquées (raison bail), santé down"
        },
        {
          "file": "test/enregistreur-ha-exigences.test.js",
          "describe": "cœur et magasin réseau (EX-13.1, EX-13.5, EX-13.6, EX-13.9, EX-13.10, 13.4)",
          "it": "EX-13.10 (2) : bail perdu pendant une écriture — repris après le contrôle d'avant fdatasync : la revérification après fdatasync échoue, lease_lost_after_write avec le seq, l'événement n'est pas rendu comme acquis"
        },
        {
          "file": "test/enregistreur-ha-exigences.test.js",
          "describe": "cœur et magasin réseau (EX-13.1, EX-13.5, EX-13.6, EX-13.9, EX-13.10, 13.4)",
          "it": "13.4 pas 1, EX-17.1, 14.2 « Bail non détenu » : instance passive — lease_standby, santé standby, /readyz 503, -31010 bail_non_detenu sans parler au service d'approbation ; elle prend le bail quand l'active le rend, avec une époque plus grande"
        },
        {
          "file": "test/enregistreur-coeur-config.test.js",
          "describe": "démon bin/noortrace",
          "it": "refuse une configuration invalide : code 2, rapport sur stderr, rien n'est ouvert"
        },
        {
          "file": "test/enregistreur-ancrage-parcours.test.js",
          "describe": "enregistreur + ancrage (lot F2), TE-12 hors réseau public : démon réel, trois ancres sur la racine, dossier vérifié hors ligne par les deux vérificateurs",
          "it": "noortrace-ctl ancrage etat | metriques | retirer-qualification <id> (SIGURG et demande écrite, réponse au journal) ; noortrace-ctl reload recharge le document ancrage-v0 avec la politique (EX-4.9) ; un rechargement d'un document invalide est refusé sans changer l'ancien"
        },
        {
          "file": "test/enregistreur-coeur-attente-bornes.test.js",
          "describe": "enregistreur, CT-2 §14.2 lignes « Mémoire » et « Disque presque plein » sur le chemin du relais (EX-14.9, EX-14.10)",
          "it": "CT-2 §14.2 ligne « Mémoire », EX-14.9 : ${b.nom} atteinte → la lecture suivante est refusée (-31010, reason attente), pending_limit_reached, mode dégradé attente ; EX-14.10 : stockage revenu, file scellée, sortie du mode attente"
        },
        {
          "file": "test/enregistreur-coeur-attente-bornes.test.js",
          "describe": "enregistreur, CT-2 §14.2 lignes « Mémoire » et « Disque presque plein » sur le chemin du relais (EX-14.9, EX-14.10)",
          "it": "CT-2 §14.2 ligne « Mémoire », EX-14.9 : ${b.nom} atteinte → l'échange suivant est bloqué (503 noortrace_degrade, non relayé), pending_limit_reached, mode dégradé attente ; EX-14.10 : stockage revenu, file scellée, sortie du mode attente"
        },
        {
          "file": "test/enregistreur-coeur-attente-bornes.test.js",
          "describe": "enregistreur, CT-2 §14.2 lignes « Mémoire » et « Disque presque plein » sur le chemin du relais (EX-14.9, EX-14.10)",
          "it": "CT-2 §14.2 ligne « Disque presque plein », colonne E : écriture -31010 reason stockage sans relais, ligne disk_low (octets libres) ; puis espace libre au-dessus de min_free_bytes (nouveau cœur, le rechargement étant refusé) : régime normal"
        },
        {
          "file": "test/enregistreur-coeur-attente-bornes.test.js",
          "describe": "enregistreur, CT-2 §14.2 lignes « Mémoire » et « Disque presque plein » sur le chemin du relais (EX-14.9, EX-14.10)",
          "it": "CT-2 §14.2 ligne « Disque presque plein », colonne M « comme le stockage indisponible » : échange de modèle bloqué (503 noortrace_degrade), ligne disk_low"
        }
      ],
      "complement": {
        "phase2_step": 8,
        "blocking": "Partie non écrite, possible dès maintenant sur le dépôt (EX-3.10) : le rejeu de la matrice entière sur le démon réel, ligne par ligne, chaque ligne finie par un dossier vérifié par les deux vérificateurs de CT-6 (EX-3.5) — seules « Clé indisponible » et « Panne après relais » sont rejouées ainsi (essai TE-16 de test/enregistreur-signataires-parcours.test.js), les autres lignes sont éprouvées une à une par les essais du paquet, le plus souvent sur le cœur en cours de processus et sans dossier vérifié ; les lignes « Disque presque plein » (`storage.min_free_bytes`, `disk_low`, -31010 `stockage`) et « Mémoire » (bornes `pending_max_events`, `pending_max_ms` et `limits.pending_max_bytes`, `pending_limit_reached`, -31010 `attente`) sont éprouvées sur le chemin du relais par test/enregistreur-coeur-attente-bornes.test.js, sur le cœur en cours de processus et sans dossier vérifié. Étape 8 (tests de bout en bout). Les versions 0.2 à 0.4 rattachaient l'entrée à l'étape 4, faute de signataires des classes A à C (livrés à l'étape 4) et du composant d'ancrage (livré à l'étape 5)."
      }
    },
    "threats": [
      "MN-10",
      "MN-21",
      "MN-26",
      "MN-33"
    ]
  },
  {
    "id": "TE-17",
    "level": "TE",
    "title": "Supervision en charge : alertes prescrites levées sur incident, métriques `noortrace_*`, dossier produit sous charge vérifié",
    "specs": [
      "CT-2",
      "CT-5",
      "CT-8"
    ],
    "covers": [
      "CT-2 §17.4",
      "CT-2 EX-17.5",
      "CT-2 EX-17.6",
      "CT-2 EX-17.7",
      "CT-2 EX-17.8",
      "CT-5 §8.9"
    ],
    "preconditions": [
      "Déploiement de test avec supervision (CT-8 §10, lot suivant) : enregistreur, extracteur et collecteur Prometheus chargé des règles de CT-8 §10.4 à §10.7 ; les deux vérificateurs de CT-6. Les seuils et échéances du déploiement de test (`pending_max_ms`, `min_free_bytes`, `queue.anchor_pending_alert_s`, …) sont abaissés, dans les bornes de leur schéma, pour que chaque condition provocable tienne dans la fenêtre de charge ; le fichier de règles est alors régénéré par la commande de CT-8 EX-10.6 (`node scripts/deploiement/regles.mjs`, livrée avec la supervision) et les valeurs employées sont consignées dans le rapport d'exécution ; une condition dont l'échéance ne peut pas être abaissée assez est marquée non provoquée.",
      "Hôte de test à cadence fixe du harnais de TM-3 (EX-11.9) ; cadence (appels par seconde) et durée de la fenêtre de charge fixées à l'étape 7 et consignées dans le rapport d'exécution.",
      "Intervalle d'évaluation des règles : celui de `deploiement/observabilite/prometheus.yml` (CT-8 EX-10.4 ; fichier du lot suivant de CT-8) au commit éprouvé, consigné dans le rapport d'exécution ; une règle est comptée déclenchée une fois par transition de l'état inactif à l'état déclenché de ses séries `ALERTS` sur la fenêtre d'observation de la provocation, après sa clause `for`, toutes étiquettes confondues : une règle dont l'expression garde des étiquettes (`instance`, `reason`, `path`…) a une série `ALERTS` par jeu d'étiquettes, et elle compte une transition quand l'ensemble de ses séries passe d'aucune série à l'état déclenché (`firing`) à au moins une ; les transitions simultanées de plusieurs séries d'une même règle comptent une ; une série déjà déclenchée au début de la fenêtre compte zéro ; chaque provocation est maintenue au moins `for` plus deux intervalles d'évaluation, puis levée. La fenêtre d'observation s'entend par provocation : de l'application de la provocation à la résolution, après sa levée, de ses règles attendues ; chaque règle attendue d'une provocation y compte exactement une transition ; une règle commune à plusieurs provocations (`noortrace_appels_bloques` : stockage, quota, rédaction) compte une transition par provocation ; une règle à fenêtre longue (`increase(…[1h])`, `[1d]`) encore déclenchée au début d'une provocation suivante ne peut pas y être attendue : les provocations qui la partagent se jouent après sa résolution, ou dans des fenêtres de charge distinctes consignées dans le rapport d'exécution ; compter une transition par règle sur toute la fenêtre de charge ferait échouer une implémentation correcte."
    ],
    "steps": [
      "Pendant la fenêtre de charge, provoquer chaque condition d'alerte de CT-2 §17.4, de CT-2 EX-17.8 et de CT-5 §8.9 provocable sur le déploiement de test ; une condition qui exige une ressource absente du déploiement (support WORM, source OpenTelemetry, seconde instance, rétention de quatorze jours, réglage de l'horloge système, que la section 16 exclut) est marquée non provoquée dans le rapport d'exécution, qui en consigne la liste ; relever chaque règle déclenchée et sa gravité ; lire `/healthz`, `/readyz` et `/metrics` du démon.",
      "Exporter le dossier d'un appel d'écriture relayé pendant la fenêtre de charge (CT-1 §11) et le vérifier par les deux vérificateurs de CT-6."
    ],
    "oracle": "Unité de comptage : la règle d'alerte de CT-8 §10.4 à §10.7 identifiée par son étiquette `exigence`. Pour chaque condition provoquée, la règle de cette condition (étiquette nommant la prescription : CT-2 §17.4, CT-2 EX-17.8, CT-5 §8.9 ; une règle par condition d'une ligne à « ou », CT-8 EX-10.1) passe à l'état déclenché exactement une fois pendant la fenêtre d'observation ; les autres règles de la même prescription ne sont attendues que si leur condition est provoquée et restent silencieuses sinon ; une condition est provoquée quand elle survient pendant la fenêtre par l'effet d'une provocation, directement ou par cascade (stockage indisponible, puis appels bloqués et événements en attente ; prestataire coupé, puis ancre en retard) ; les règles attendues d'une provocation sont celles de la condition provoquée et de ses conséquences, nommées dans le rapport d'exécution avant la provocation ; une règle qui se déclenche hors de cette liste est un échec ; la liste peut nommer toute règle de CT-8 §10.4 à §10.7, celles du registre (`noortrace_registre_*`, CT-4) comprises, que la condition entraîne, chaque conséquence y étant inscrite avant la provocation avec la chaîne causale qui la justifie ; une conséquence non justifiée est un défaut du rapport, relu par l'examinateur ; les deux exemples de cascade ci-dessus ne sont pas limitatifs ; deux règles levées par une même cause (« Mode dégradé » `horloge` et « Horloge ») comptent chacune une fois, cet exemple illustrant le comptage sans exiger la provocation de l'horloge ; les trois alertes du registre des gels : une seule alerte critique par cause (CT-2 EX-17.7), clause jouée seulement si un support WORM est monté ; sinon ses conditions figurent dans la liste des conditions non provoquées et la clause n'est pas jouée. La gravité relevée (étiquette `severity` de la règle déclenchée) doit égaler celle de la table de CT-8 §10.4 à §10.7, qui fait foi (CT-8 EX-10.1) ; une gravité différente est un échec (le fichier de règles ne suit pas sa table, ce que TV-76 éprouve aussi sans les composants) ; un écart entre la table de CT-8 et la prescription de CT-2 §17.4 ou de CT-5 §8.9 est consigné, non jugé par le test. Chaque métrique de la table CT-2 §17.2 et de CT-5 EX-8.15 est présente avec exactement ses étiquettes : « présente » signifie déclarée par son nom dans l'exposition `/metrics` du démon (ligne `# TYPE` ; un histogramme par ses séries `_bucket`, `_sum` et `_count`, avec l'étiquette `le`), lue sur le démon et non chez le collecteur, qui ajoute `instance` et `job` ; les séries d'étiquettes exigées sont celles que le montage de test crée ; une métrique d'une fonction absente du montage (WORM, OpenTelemetry) est déclarée mais peut n'avoir aucune série (le compte de CT-8 §10.2 est à aligner sur la table de CT-2 : PD-27). Le dossier exporté sous charge : code 0 des deux vérificateurs, énoncé identique.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Supervision à produire (CT-8 §10, lot suivant)."
    },
    "threats": [
      "MN-29"
    ]
  }
];
