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
      "Binaire `chain/runtime/bin/noorcore` ; `chain/scripts/dev-net.sh start` ; `deployments/noorcore.json` ; slug neuf ; hors CI (aucune étape de la CI n'exécute noorcore, CT-5 EX-A.7)."
    ],
    "steps": [
      "Exécuter 7.4 à 7.9 avec l'outil de référence ; capturer chaque certificat ; `verifier` ; `certificat-commit.mjs` sur chaque certificat ; `chain/scripts/dev-net.sh stop`."
    ],
    "oracle": "`exit_code` 0 partout ; étapes `capturee` ou `faite` ; R-1 à R-10 `reussi` ; code 0 de `certificat-commit.mjs` sur les six certificats (CT-4 EX-7.15). L'épreuve humaine à l'aveugle est un TR-.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 3,
      "blocking": "Exécuté hors de `npm test` ; aucun describe/it ni étape de CI ne le porte (R10-NV4) : à écrire comme script d'épreuve `scripts/e2e/` rejouable, verdict JSON."
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
      "Deux instances de l'enregistreur sur le même journal ; magasin de bail `file` puis `etcd` de test."
    ],
    "steps": [
      "Couper l'instance titulaire ; mesurer la bascule ; tenter une écriture par l'ancienne instance ; relire les segments et le journal d'intention."
    ],
    "oracle": "Une seule chaîne continue ; écriture de l'ancienne instance refusée par l'époque ; pertes dans les bornes de CT-2 §13.5.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 4,
      "blocking": "Démon non construit."
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
      "Enregistreur et composant d'ancrage (étapes 4 et 5) ; réseau de développement ; prestataire de test et calendriers."
    ],
    "steps": [
      "Laisser une période recevoir ses points, ses ancres de point et ses trois ancres de clôture ; exporter le dossier avec `points-de-controle.json` ; vérifier sans réseau (`unshare -n`)."
    ],
    "oracle": "Contrôles 4, 5 et 8 et K-7 à K-9 réussis ; P-5 de CT-5 tenue (aucun réseau) ; énoncé du vérificateur conforme à CT-6 §7.9.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 5,
      "blocking": "Composant d'ancrage non construit ; « une racine reçoit ses trois ancres » est le critère de l'étape 5."
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
      "Démon de l'étape 4 avec journal d'exploitation."
    ],
    "steps": [
      "Provoquer chaque situation de la table de CT-7 §6.1 (démarrage, arrêt, bail, rotation, politique, configuration, saut d'horloge, gel, perte WORM, ancrage dégradé, attestation).",
      "Forcer la rotation du journal d'exploitation par `supervision.ops_log.rotate_max_bytes`, puis simuler un disque plein pendant le relais."
    ],
    "oracle": "Chaque situation produit l'événement ou la ligne que la table nomme (« porté » ou « aucun » selon la colonne) ; aucun secret dans les lignes. Rotation : au plus `keep_files` fichiers conservés ; disque plein : chaque ligne non écrite incrémente `noortrace_ops_log_dropped_total` d'une unité et le relais continue (CT-2 EX-9.7, EX-17.4).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 4,
      "blocking": "Démon non construit ; CT-7 §6.2 et §6.3 restent des propositions PA- à CT-2 et CT-1."
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
      "CT-2 EX-14.12"
    ],
    "preconditions": [
      "Démon de l'étape 4 ; hôte de test ; serveur d'outils et fournisseur simulés dont on peut couper chaque dépendance (stockage, signataire, bail, horloge, service d'approbation, ancrage)."
    ],
    "steps": [
      "Pour chaque ligne de la matrice de CT-2 §14.2, couper la dépendance pendant un appel de lecture puis d'écriture ; relever ce qui est rendu à l'hôte, ce qui est journalisé et les événements en attente ; rétablir la dépendance."
    ],
    "oracle": "Comportement égal, ligne par ligne, à la matrice de §14.2 ; événements en attente rejoués à l'identique ; aucun appel d'écriture relayé sans événement durable. Les TA- des scénarios « l'enregistreur tombe » et « un prestataire est injoignable » retirent la réponse de chaque ligne.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 4,
      "blocking": "Démon non construit ; les bibliothèques ne portent pas la matrice entière."
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
