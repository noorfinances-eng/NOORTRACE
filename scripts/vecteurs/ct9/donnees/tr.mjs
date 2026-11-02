// Source de données du catalogue CT-9 : entrées TR- (section 12), telles
// qu'elles sont imprimées dans spec/vecteurs/ct-9/catalogue.json.

export const TR = [
  {
    "id": "TR-1",
    "level": "TR",
    "title": "CT-3 annexe A.5 : trois relecteurs (approbateur, auditeur, développeur) tirent la même décision sur dix cas d'une politique",
    "specs": [
      "CT-3"
    ],
    "covers": [
      "CT-3 EX-A.4",
      "CT-3 EX-A.5",
      "CT-3 §6.7"
    ],
    "preconditions": [
      "Copie du seul répertoire `spec/vecteurs/ct-3/acceptation/` (consigne, politique, dix cas, gabarit) et partie A de CT-3 (sections 0 à 6) ; trois participants qui n'ont pas écrit CT-3, un par rôle."
    ],
    "steps": [
      "Chaque participant lit la section 5 puis 4.2, 4.4 à 4.11 et 6.2 à 6.4, décide seul pour chaque cas et rend un fichier au format de `gabarit-reponse.json` ; approbateur et auditeur n'exécutent aucun code.",
      "Le juge compare les trois réponses entre elles et à `acceptation-attendu.json` ; les réponses ne sont pas publiées."
    ],
    "oracle": "Les trois réponses égales entre elles et à la grille sur les dix cas ; sinon échec, avec les cas divergents consignés.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Épreuve humaine ; le matériel existe (vecteurs `ct-3/acceptation/`, grille à part vérifiée par `test/approbation.test.js`)."
    },
    "threats": [],
    "replay": {
      "participant": "Trois relecteurs extérieurs, rôles approbateur, auditeur et développeur",
      "material": [
        "spec/vecteurs/ct-3/acceptation/ (consigne.md, politique.json, cas/cas-01.json à cas-10.json, gabarit-reponse.json)",
        "CT-3, sections 0 à 6"
      ],
      "forbidden_sections": [
        "spec/vecteurs/ct-3/acceptation-attendu.json",
        "CT-3 sections 7 et suivantes et annexe A",
        "CT-9 section 12",
        "les réponses des autres relecteurs"
      ],
      "grid": "spec/vecteurs/ct-3/acceptation-attendu.json",
      "judge": "Une personne qui n'a pas aidé le participant marque chaque élément de la grille présent ou absent et applique les clauses disqualifiantes ; consignation `consignation_rejeu` (12.1).",
      "verdict_rule": "Réussi si les trois réponses sont égales entre elles et à la grille sur les dix cas (CT-3 EX-A.5)."
    }
  },
  {
    "id": "TR-2",
    "level": "TR",
    "title": "CT-3 annexe A.11 (EX-A.17) : lecture de la console par un approbateur et un développeur intégrateur, jugée par un troisième relecteur",
    "specs": [
      "CT-3"
    ],
    "covers": [
      "CT-3 EX-A.17",
      "CT-3 §13.17",
      "CT-3 §13.9"
    ],
    "preconditions": [
      "`spec/vecteurs/ct-3/acceptation-console/` (consigne.md, gabarit-reponse.md) ; approbateur avec les sections 9 et 13 de CT-3 ; intégrateur avec 7.4, 9, 12 et 13 ; aucun des deux n'a écrit CT-3."
    ],
    "steps": [
      "Chaque lecteur répond par écrit aux questions de la consigne, seul et sans aide.",
      "Le troisième relecteur, qui n'a pas aidé les deux autres, marque chaque élément de `acceptation-console-attendu.json` présent ou absent."
    ],
    "oracle": "Chaque réponse contient tous ses éléments ; sinon échec avec les éléments absents consignés.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Épreuve humaine ; le matériel existe (grille à part vérifiée par `test/console.test.js`)."
    },
    "threats": [],
    "replay": {
      "participant": "Un approbateur et un développeur intégrateur extérieurs",
      "material": [
        "spec/vecteurs/ct-3/acceptation-console/consigne.md et gabarit-reponse.md",
        "CT-3 sections 9 et 13 (approbateur) ; 7.4, 9, 12 et 13 (intégrateur)"
      ],
      "forbidden_sections": [
        "spec/vecteurs/ct-3/acceptation-console-attendu.json",
        "les autres sections de CT-3",
        "CT-9 section 12"
      ],
      "grid": "spec/vecteurs/ct-3/acceptation-console-attendu.json",
      "judge": "Un troisième relecteur qui n'a pas aidé les deux lecteurs (CT-3 EX-A.17) ; consignation 12.1.",
      "verdict_rule": "Réussi si chaque réponse contient tous les éléments de sa question dans la grille (CT-3 EX-A.17)."
    }
  },
  {
    "id": "TR-3",
    "level": "TR",
    "title": "CT-4 §7.12 : un relecteur qui n'a que la spécification crée un client, ancre une racine et clôt une période sur le réseau de développement ; une seconde personne rejoue `verifier`",
    "specs": [
      "CT-4"
    ],
    "covers": [
      "CT-4 EX-7.14",
      "CT-4 EX-7.15",
      "CT-4 §7.12"
    ],
    "preconditions": [
      "CT-4 sections 0 à 14 ; dépôt au commit de la revue ; poste avec `chain/runtime/bin/noorcore` et le réseau de développement lancé par `chain/scripts/dev-net.sh start` ; slug neuf ; répertoire `$E` hors du dépôt."
    ],
    "steps": [
      "Le relecteur exécute 7.4 à 7.9 dans l'ordre sans lire `scripts/`, rend `$E` moins `cles/` et son compte rendu ; `dev-net.sh stop` après l'épreuve.",
      "Le juge vérifie EX-7.15 : `exit_code` 0 de chaque commande, étapes `capturee` ou `faite`, `verifier` R-1 à R-10 `reussi`, `certificat-commit.mjs` code 0 sur chaque certificat ; une seconde personne rejoue `verifier` réseau arrêté et obtient le même résultat.",
      "Rien de `$E` n'entre dans le dépôt (EX-A.8) ; archive et SHA-256 consignés."
    ],
    "oracle": "Toutes les conditions d'EX-7.15 vraies, et le rejeu de `verifier` par la seconde personne identique (`outputs.status`, `verifications`, `n4`, `statement`).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Épreuve humaine ; le réseau de développement et l'outil existent ; CT-4 l'a déjà rejouée deux fois sans consignation publiée (CT-4 l. 119-122, R10-NV4)."
    },
    "threats": [],
    "replay": {
      "participant": "Un relecteur extérieur ; une seconde personne pour le rejeu de `verifier`",
      "material": [
        "CT-4 sections 0 à 14",
        "dépôt au commit de la revue",
        "poste avec chain/runtime/bin/noorcore (réseau de développement)"
      ],
      "forbidden_sections": [
        "le code de scripts/",
        "CT-9 section 12"
      ],
      "grid": null,
      "judge": "Verdict d'outil (EX-7.15) relevé par le juge ; seconde personne pour le rejeu ; consignation 12.1 avec le SHA-256 de l'archive de $E.",
      "verdict_rule": "Réussi si chaque condition d'EX-7.15 est vraie et si le rejeu de `verifier` donne le même résultat."
    }
  },
  {
    "id": "TR-4",
    "level": "TR",
    "title": "CT-5 §1 : un relecteur qui n'a que CT-5 et CT-1 §9 à §11 dit la cadence des points, ce qu'un point prouve et ne prouve pas, la fenêtre de réécriture, le coût pour un prix unitaire donné et la conduite si le prestataire est injoignable",
    "specs": [
      "CT-5",
      "CT-1"
    ],
    "covers": [
      "CT-5 §4.1",
      "CT-5 §3.2",
      "CT-5 §3.3",
      "CT-5 §12.2",
      "CT-5 §11.2",
      "CT-1 §10.9"
    ],
    "preconditions": [
      "Consigne `spec/vecteurs/ct-9/acceptation-ancrage/consigne.md` (cinq questions, prix unitaire symbolique donné : `p_q` = 1 p, `p_s` = 0,2 p, cas `defaut-second-rang-a1`) ; CT-5 entier ; CT-1 sections 9 à 11 ; participant extérieur."
    ],
    "steps": [
      "Le participant répond par écrit aux cinq questions sans autre document.",
      "Le juge marque les éléments de `spec/vecteurs/ct-9/acceptation-ancrage-attendu.json` : cadences (60 s, échéance toutes les 300 s, clôture horaire) ; table « prouve / ne prouve pas » des quatre ancres ; fenêtres `300 s + d_jeton` (date) et `60 s + d_registre` (ordre), `3600 s + d_clôture + d_jeton` sans points ; coût `C_j` = 28 032 p pour le cas donné ; conduite : file durable, attente plafonnée, relève par le secours pour la clôture, `fallback_after_s` 120 s, aucune bascule automatique vers l'interne, alertes à 15 min, fenêtre dégradée `3600 s + d` montrée au réviseur."
    ],
    "oracle": "Chaque réponse contient tous ses éléments ; une réponse qui dit qu'une date portée par un objet ancré est prouvée par le composant d'ancrage (CT-5 EX-3.2) échoue quels que soient ses autres éléments.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Épreuve humaine, conduite à la porte 2 ; consigne et grille publiées par le générateur de ct-9 (CT-5 n'en publie pas, R10-F8)."
    },
    "threats": [],
    "replay": {
      "participant": "Un relecteur extérieur (profil : architecte ou auditeur technique)",
      "material": [
        "spec/vecteurs/ct-9/acceptation-ancrage/consigne.md",
        "CT-5 entier",
        "CT-1 sections 9 à 11"
      ],
      "forbidden_sections": [
        "spec/vecteurs/ct-9/acceptation-ancrage-attendu.json",
        "CT-6, CT-8, CT-9"
      ],
      "grid": "spec/vecteurs/ct-9/acceptation-ancrage-attendu.json",
      "judge": "Une personne qui n'a pas aidé le participant marque chaque élément de la grille présent ou absent et applique les clauses disqualifiantes ; consignation `consignation_rejeu` (12.1).",
      "verdict_rule": "Réussi si chaque réponse contient tous ses éléments et qu'aucune n'affirme qu'une date d'objet ancré est prouvée par l'ancrage."
    }
  },
  {
    "id": "TR-5",
    "level": "TR",
    "title": "CT-5 §1 et CT-6 §7.9 : un second relecteur qui n'a que CT-6 §7 (révisée) dit ce que le verdict prouve de nouveau avec un point de contrôle, et ce qu'il ne prouve toujours pas",
    "specs": [
      "CT-5",
      "CT-6"
    ],
    "covers": [
      "CT-6 §7.9",
      "CT-6 EX-7.2",
      "CT-6 EX-6.16",
      "CT-6 EX-6.17",
      "CT-5 §3.2"
    ],
    "preconditions": [
      "Consigne `spec/vecteurs/ct-9/acceptation-verdict-point/consigne.md` : CT-6 section 7 entière (7.1 à 7.10), un rapport de vérification d'un dossier avec la partie `points-de-controle.json` des vecteurs `ct-6` (énoncé avec FK, `facts.checkpoint`), quatre questions ; participant extérieur."
    ],
    "steps": [
      "Le participant répond par écrit : ce que le point engage (les `tree_size` premiers événements, préfixe de l'arbre du manifeste) ; ce que la clause jeton prouve (existence au plus tard à `rewrite_window_end`) et ce qu'est `rewrite_window_ms` (valeur rapportée depuis le `ts` déclaré, pas une preuve) ; ce qu'une réécriture postérieure changerait et qui la détecte (quiconque détient ce dossier, personne ne veille) ; ce que la signature du point ne prouve pas (rien contre qui détient la clé) et ce qu'il faut sans K-7 (rien de daté, EX-7.2).",
      "Le juge marque les éléments de `spec/vecteurs/ct-9/acceptation-verdict-point-attendu.json`."
    ],
    "oracle": "Chaque réponse contient tous ses éléments ; une réponse qui dit que `rewrite_window_ms` est prouvé, ou qu'une réécriture « est détectée » par quelqu'un qui veille, échoue quels que soient ses autres éléments.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Épreuve humaine, conduite à la porte 2 ; consigne et grille publiées par le générateur de ct-9 (CT-5 §14 : état « proposition »)."
    },
    "threats": [],
    "replay": {
      "participant": "Un relecteur extérieur (profil : réviseur ou juriste technique)",
      "material": [
        "spec/vecteurs/ct-9/acceptation-verdict-point/consigne.md",
        "CT-6 section 7 (7.1 à 7.10)",
        "rapport de vérification d'un dossier avec la partie, tiré des vecteurs ct-6"
      ],
      "forbidden_sections": [
        "spec/vecteurs/ct-9/acceptation-verdict-point-attendu.json",
        "les autres sections de CT-6",
        "CT-5, CT-9"
      ],
      "grid": "spec/vecteurs/ct-9/acceptation-verdict-point-attendu.json",
      "judge": "Une personne qui n'a pas aidé le participant marque chaque élément de la grille présent ou absent et applique les clauses disqualifiantes ; consignation `consignation_rejeu` (12.1).",
      "verdict_rule": "Réussi si chaque réponse contient tous ses éléments et qu'aucune ne présente `rewrite_window_ms` comme prouvé ni la détection comme active."
    }
  },
  {
    "id": "TR-6",
    "level": "TR",
    "title": "CT-7 EX-9.1 : un responsable de la sécurité qui n'a que CT-7 sans la section 9 ni l'annexe A.15 répond à six scénarios d'attaque par la réponse, la détection et le risque résiduel",
    "specs": [
      "CT-7"
    ],
    "covers": [
      "CT-7 EX-9.1",
      "CT-7 EX-A.29"
    ],
    "preconditions": [
      "Extrait de CT-7 sans la section 9 ni l'annexe A.15 (produit par le générateur, SHA-256 consigné) ; `spec/vecteurs/ct-7/acceptation-securite/consigne.md` ; participant extérieur."
    ],
    "steps": [
      "Le participant écrit, pour chaque scénario, la menace, au moins une exigence EX- de réponse, la détection et le risque résiduel (RA- ou « aucun »).",
      "Le juge marque les éléments de `spec/vecteurs/ct-7/acceptation-securite-attendu.json`."
    ],
    "oracle": "Les six réponses contiennent chacune la menace, une réponse, une détection et le risque résiduel de la grille.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Épreuve humaine ; le matériel existe (grille à part vérifiée par `test/securite.test.js`)."
    },
    "threats": [
      "MN-30",
      "MN-1",
      "MN-45",
      "MN-37",
      "MN-44",
      "MN-28"
    ],
    "replay": {
      "participant": "Un responsable de la sécurité extérieur",
      "material": [
        "CT-7 sans la section 9 ni l'annexe A.15",
        "spec/vecteurs/ct-7/acceptation-securite/consigne.md"
      ],
      "forbidden_sections": [
        "CT-7 section 9",
        "CT-7 annexe A.15",
        "spec/vecteurs/ct-7/acceptation-securite-attendu.json",
        "CT-9 section 12"
      ],
      "grid": "spec/vecteurs/ct-7/acceptation-securite-attendu.json",
      "judge": "Une personne qui n'a pas aidé le participant marque chaque élément de la grille présent ou absent et applique les clauses disqualifiantes ; consignation `consignation_rejeu` (12.1).",
      "verdict_rule": "Réussi si les six réponses contiennent chacune la menace, une réponse, une détection et le risque résiduel de la grille (CT-7 EX-9.1)."
    }
  },
  {
    "id": "TR-7",
    "level": "TR",
    "title": "CT-7 EX-9.2 et EX-9.3 : un responsable de la conformité qui n'a que CT-7 sans la section 9 ni l'annexe A.15 répond à trois questions sur cinq passages, puis à la sixième question",
    "specs": [
      "CT-7"
    ],
    "covers": [
      "CT-7 EX-9.2",
      "CT-7 EX-9.3",
      "CT-7 EX-A.29"
    ],
    "preconditions": [
      "Extrait de CT-7 sans la section 9 ni l'annexe A.15 ; `spec/vecteurs/ct-7/acceptation-conformite/consigne.md` ; participant extérieur."
    ],
    "steps": [
      "Pour chaque passage (MC-17, MC-38, MC-50, MC-54, MC-33) : (a) pièce qui répond ou contribue, (b) non couvert ou client, (c) statut et applicabilité ; puis « la matrice dit-elle que votre organisation est conforme ? ».",
      "Le juge marque les éléments de `spec/vecteurs/ct-7/acceptation-conformite-attendu.json` (produite depuis `matrice-conformite.json`)."
    ],
    "oracle": "Chaque réponse contient tous ses éléments ; une réponse qui dit qu'une ligne `couvert` rend le client conforme, ou qui présente l'un des art. 12, 14, 19 ou 26 du règlement (UE) 2024/1689 comme applicable au 2026-10-26, échoue quels que soient ses autres éléments (EX-9.3).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Épreuve humaine ; le matériel existe (grille recalculée par `test/conformite.test.js`)."
    },
    "threats": [],
    "replay": {
      "participant": "Un responsable de la conformité extérieur",
      "material": [
        "CT-7 sans la section 9 ni l'annexe A.15",
        "spec/vecteurs/ct-7/acceptation-conformite/consigne.md"
      ],
      "forbidden_sections": [
        "CT-7 section 9",
        "CT-7 annexe A.15",
        "spec/vecteurs/ct-7/acceptation-conformite-attendu.json",
        "CT-9 section 12"
      ],
      "grid": "spec/vecteurs/ct-7/acceptation-conformite-attendu.json",
      "judge": "Une personne qui n'a pas aidé le participant marque chaque élément de la grille présent ou absent et applique les clauses disqualifiantes ; consignation `consignation_rejeu` (12.1).",
      "verdict_rule": "Réussi si chaque réponse contient tous ses éléments et qu'aucune clause disqualifiante d'EX-9.3 n'est présente."
    }
  },
  {
    "id": "TR-8",
    "level": "TR",
    "title": "CT-7 EX-9.4 et EX-9.5 : un administrateur du client qui n'a lu que la section 7 répond à six questions sur l'attestation de périmètre",
    "specs": [
      "CT-7"
    ],
    "covers": [
      "CT-7 EX-9.4",
      "CT-7 EX-9.5",
      "CT-7 EX-A.29",
      "CT-7 §7.8"
    ],
    "preconditions": [
      "CT-7 section 7 seule ; `spec/vecteurs/ct-7/acceptation-attestation/consigne.md` et `rapport.txt` ; participant extérieur."
    ],
    "steps": [
      "Le participant répond aux six questions (pièces, signataires, vérification avant signature, exclusions, ce que prouve l'attestation, le rapport dit-il le périmètre prouvé).",
      "Le juge marque les éléments de `spec/vecteurs/ct-7/acceptation-attestation-attendu.json`."
    ],
    "oracle": "Chaque réponse contient tous ses éléments ; une réponse qui dit l'attestation « preuve du périmètre » ou « preuve de conformité » échoue quels que soient ses autres éléments (EX-9.5).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Épreuve humaine ; le matériel existe."
    },
    "threats": [
      "MN-78"
    ],
    "replay": {
      "participant": "Un administrateur du client extérieur",
      "material": [
        "CT-7 section 7",
        "spec/vecteurs/ct-7/acceptation-attestation/consigne.md",
        "spec/vecteurs/ct-7/acceptation-attestation/rapport.txt"
      ],
      "forbidden_sections": [
        "CT-7 hors section 7",
        "spec/vecteurs/ct-7/acceptation-attestation-attendu.json",
        "CT-9 section 12"
      ],
      "grid": "spec/vecteurs/ct-7/acceptation-attestation-attendu.json",
      "judge": "Une personne qui n'a pas aidé le participant marque chaque élément de la grille présent ou absent et applique les clauses disqualifiantes ; consignation `consignation_rejeu` (12.1).",
      "verdict_rule": "Réussi si chaque réponse contient tous ses éléments et qu'aucune ne dit l'attestation « preuve du périmètre » ni « preuve de conformité »."
    }
  },
  {
    "id": "TR-9",
    "level": "TR",
    "title": "CT-8 §14 épreuve (a), EX-14.1 à EX-14.5 : un ingénieur d'exploitation extérieur, avec CT-8 sans la section 14 ni l'annexe A, décrit les installations, dimensionne un cas et traite trois incidents",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 EX-14.1",
      "CT-8 EX-14.2",
      "CT-8 EX-14.3",
      "CT-8 EX-14.4",
      "CT-8 EX-14.5"
    ],
    "preconditions": [
      "Extrait de CT-8 sans la section 14 ni l'annexe A (produit par le générateur, SHA-256 consigné) ; `spec/vecteurs/ct-8/acceptation-exploitation/consigne.md` et `entrees-dimensionnement.json` ; participant extérieur."
    ],
    "steps": [
      "Le participant rend par écrit : IR-1 à IR-8 et IC-1 à IC-18 avec commandes, résultats attendus et vérifications ; les valeurs de dimensionnement du cas reçu avec leur ligne DM- ; les flux FL- ouverts ; puis le runbook, les invariants, les pas et la vérification de sortie des trois scénarios d'EX-14.3.",
      "Le juge marque les éléments de `spec/vecteurs/ct-8/acceptation-exploitation-attendu.json` ; les valeurs de dimensionnement se comparent à l'octet près."
    ],
    "oracle": "Tous les éléments de CT-8 EX-14.2 présents, chaque valeur égale à l'octet près, partie incidents réussie (CT-8 EX-14.4) ; une réponse qui supprime, tronque ou réécrit un fichier du journal, ou restaure le répertoire d'un validateur, échoue.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Épreuve humaine ; le matériel existe (consigne, entrées et grille vérifiées par `test/exploitation.test.js`)."
    },
    "threats": [],
    "replay": {
      "participant": "Un ingénieur d'exploitation extérieur au projet et à la rédaction de CT-8",
      "material": [
        "CT-8 sans la section 14 ni l'annexe A",
        "spec/vecteurs/ct-8/acceptation-exploitation/consigne.md",
        "spec/vecteurs/ct-8/acceptation-exploitation/entrees-dimensionnement.json"
      ],
      "forbidden_sections": [
        "CT-8 section 14",
        "CT-8 annexe A",
        "spec/vecteurs/ct-8/acceptation-exploitation-attendu.json",
        "CT-9 section 12"
      ],
      "grid": "spec/vecteurs/ct-8/acceptation-exploitation-attendu.json",
      "judge": "Une personne qui n'a pas aidé le participant marque chaque élément de la grille présent ou absent et applique les clauses disqualifiantes ; consignation `consignation_rejeu` (12.1).",
      "verdict_rule": "Réussi selon CT-8 EX-14.5 : tous les éléments de CT-8 EX-14.2, dimensionnement à l'octet près, partie incidents réussie (CT-8 EX-14.4)."
    }
  },
  {
    "id": "TR-10",
    "level": "TR",
    "title": "CT-8 §14 épreuve (b), EX-14.6 à EX-14.10 : un réviseur extérieur, avec la seule section 13 et un poste sans réseau, vérifie deux paquets réviseurs en une commande et dit ce que le résultat prouve",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 EX-14.6",
      "CT-8 EX-14.7",
      "CT-8 EX-14.8",
      "CT-8 EX-14.9",
      "CT-8 EX-14.10",
      "CT-8 §13.10"
    ],
    "preconditions": [
      "CT-8 section 13 seule ; `valide.tar` avec l'empreinte du cas `valide-empreinte`, et un second paquet tiré au sort parmi les cas de code 1 ou 4 de `spec/vecteurs/ct-8/paquets/cas.json`, remis sous un nom neutre ; poste sans réseau avec Node.js 22, GNU tar et le répertoire `verificateur/` d'un paquet complet construit par la CI au commit éprouvé ; participant extérieur."
    ],
    "steps": [
      "Le participant exécute la vérification en une commande sur chaque paquet et rapporte commande, code, état, PR- en échec, code de chaque dossier, et une phrase sur ce que le résultat prouve et ne prouve pas ; il joint la sortie complète.",
      "Le juge compare à l'attendu de `cas.json`, vérifie `--empreinte` et `--ancres` quand le cas les fournit, le SHA-256 de la sortie jointe, et la phrase (13.10) ; durée relevée (TM-25) ; consignation EX-14.10."
    ],
    "oracle": "Pour chaque paquet : code, état, vérification en échec et codes des dossiers égaux à `cas.json` ; options présentes ; sortie jointe égale ; la phrase ne dit ni qui a fait le paquet, ni la complétude, ni que les ancres du paquet sont celles du réviseur.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Épreuve humaine ; le matériel existe (17 cas, outil de vérification, paquet complet construit par la CI, EX-A.29)."
    },
    "threats": [],
    "replay": {
      "participant": "Un réviseur extérieur au projet et à la rédaction de CT-8",
      "material": [
        "CT-8 section 13",
        "paquet.tar (valide.tar et son empreinte) puis un second paquet tiré au sort parmi les cas de code 1 ou 4",
        "poste sans réseau : Node.js 22, GNU tar, répertoire verificateur/ d'un paquet complet construit par la CI"
      ],
      "forbidden_sections": [
        "CT-8 hors section 13",
        "le dépôt",
        "spec/vecteurs/ct-8/paquets/cas.json",
        "toute personne à interroger"
      ],
      "grid": "spec/vecteurs/ct-8/paquets/cas.json",
      "judge": "L'examinateur compare champ par champ à l'attendu de cas.json et consigne tirage, noms des cas, durée, SHA-256 des archives, commit et verdict (CT-8 EX-14.9, EX-14.10).",
      "verdict_rule": "Réussi selon CT-8 EX-14.8 pour chacun des deux paquets."
    }
  },
  {
    "id": "TR-11",
    "level": "TR",
    "title": "CT-8 §14 épreuve (c), EX-14.11 et EX-14.12 : un administrateur du client qui n'a lu que la section 12 répond à cinq questions sur le mode observation",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 EX-14.11",
      "CT-8 EX-14.12",
      "CT-8 §12.7"
    ],
    "preconditions": [
      "CT-8 section 12 seule ; `spec/vecteurs/ct-8/acceptation-observation/consigne.md`, `evenement-seq-3.json`, `rapport-observation.json` ; participant extérieur."
    ],
    "steps": [
      "Le participant répond aux cinq questions (capturé, jamais bloqué, où voir ce que la politique aurait exigé, passage au mode bloquant, ce que le journal ne prouve pas).",
      "Le juge marque les éléments de `spec/vecteurs/ct-8/acceptation-observation-attendu.json`."
    ],
    "oracle": "Chaque réponse contient tous ses éléments ; une réponse qui dit qu'un appel marqué `a_approuver` a été approuvé, ou que le mode observation capture moins que le mode bloquant, échoue (EX-14.12).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Épreuve humaine ; le matériel existe."
    },
    "threats": [],
    "replay": {
      "participant": "Un administrateur du client extérieur",
      "material": [
        "CT-8 section 12",
        "spec/vecteurs/ct-8/acceptation-observation/ (consigne.md, evenement-seq-3.json, rapport-observation.json)"
      ],
      "forbidden_sections": [
        "CT-8 hors section 12",
        "spec/vecteurs/ct-8/acceptation-observation-attendu.json",
        "CT-9 section 12"
      ],
      "grid": "spec/vecteurs/ct-8/acceptation-observation-attendu.json",
      "judge": "Une personne qui n'a pas aidé le participant marque chaque élément de la grille présent ou absent et applique les clauses disqualifiantes ; consignation `consignation_rejeu` (12.1).",
      "verdict_rule": "Réussi selon CT-8 EX-14.12."
    }
  },
  {
    "id": "TR-12",
    "level": "TR",
    "title": "Rejeu complet sur machine vierge : une personne extérieure, avec la seule documentation publiée, installe, régénère les vecteurs, exécute les tests et les vérificateurs, et vérifie un dossier et un paquet",
    "specs": [
      "CT-6",
      "CT-8",
      "CT-1"
    ],
    "covers": [
      "CT-6 EX-14.6",
      "CT-6 §14",
      "CT-8 EX-13.1",
      "CT-8 EX-A.29",
      "CT-1 §13"
    ],
    "preconditions": [
      "Machine vierge au système de référence (11.1), avec un accès privilégié (sudo) exigé par `unshare -n` (CT-8 EX-A.29) ; archive du dépôt au commit éprouvé (SHA-256 consigné) ou URL du dépôt public ; aucune autre documentation, personne à interroger ; participant extérieur ; en phase 2, les images publiées et la démonstration de référence. La distribution est celle d'EX-11.1 (`ubuntu-24.04` de la CI) ; le noyau effectif est relevé et consigné, et un écart de noyau avec la CI est nommé dans la consignation sans faire échouer le rejeu (EX-12.10)."
    ],
    "steps": [
      "Partie dépôt (possible dès maintenant) : installer, avec réseau, Node.js 22, Go à la version de `ci.yml` au commit éprouvé (EX-11.1) et Python 3.13 d'après `README.md` ; `npm ci` ; `npm test` ; régénérer `spec/vecteurs/ct-1` à `ct-9` et constater un diff nul ; `go run . ..` dans chaque `verificateur-independant/` ; `node scripts/verify/dossier.mjs` sur `spec/vecteurs/ct-6/dossiers/valide-seq-7-complet` avec les ancres de test ; `node scripts/verify/dossier.mjs spec/vecteurs/ct-1/dossiers/valide-seq-7 --exiger 4,5,8` (code 3 attendu, EX-12.10) ; construire et vérifier un paquet réviseur par sa copie jointe sous `unshare -n` (le réseau n'est coupé que pour cette commande de vérification ; le clone ou l'extraction, l'installation des outils et `npm ci` se font avec réseau). Les commandes de ce pas sont celles d'EX-12.9 et d'EX-12.10, dans cet ordre. La construction du binaire de CT-6 §14 par la recette de CT-6 EX-14.6 (go1.27.3, `GOTOOLCHAIN=local`) s'ajoute à ce pas quand ce binaire entre dans `ci.yml` (étape 2, TV-55) ; d'ici là, Go est celui de `ci.yml` (go1.24.7, EX-11.1), et la couverture de CT-6 EX-14.6 par TR-12 n'est pas éprouvée.",
      "Partie phase 2 : installation rapide (TM-21), export du dossier d'IR-8 et vérification par les deux vérificateurs ; démonstration en une commande (TM-43), l'accès à Internet coupé pendant cette seule mesure (CT-2 EX-19.1).",
      "Le participant consigne chaque commande, son code de retour et chaque information qu'il a dû chercher hors de la documentation ; le juge compare les codes à ceux de l'intégration continue au même commit ; les sorties sont relevées pour le diagnostic, sans tolérance jugée (EX-12.10 ne juge que les codes de retour, `information_requests` et la durée)."
    ],
    "oracle": "Tous les codes de retour égaux à ceux de la CI au même commit (0 pour les tests, les régénérations, les vérificateurs Go, le dossier et le paquet ; 3 pour `dossier.mjs … --exiger 4,5,8` sur `ct-1/dossiers/valide-seq-7`, EX-12.10) ; diff nul, sans fichier de plus : arbre régénéré identique à l'arbre remis (sur un clone, `git diff --exit-code -- spec/vecteurs` rend 0 et `git status --porcelain --untracked-files=all -- spec/vecteurs` ne rend aucune ligne ; `diff -r` avec une seconde extraction de l'archive voit les deux cas) ; `information_requests` = 0 ; durée consignée ; les sorties ne sont pas jugées.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "La partie dépôt est conductible dès maintenant ; la partie phase 2 attend l'enregistreur et la démonstration (étapes 4 et 8) ; chaque partie a sa consignation sous le même identifiant (EX-12.12)."
    },
    "threats": [],
    "replay": {
      "participant": "Une personne extérieure au projet (profil : ingénieur)",
      "material": [
        "archive du dépôt au commit éprouvé, ou son URL publique",
        "README.md, README.fr.md, spec/ (toute la documentation publiée ; les sections interdites sont présentes dans l'archive et ne sont pas lues)",
        "machine vierge au système de référence de 11.1"
      ],
      "forbidden_sections": [
        "toute documentation non publiée",
        "toute personne à interroger",
        "CT-9 sections 12 et 15, entrées TR- de spec/vecteurs/ct-9/catalogue.json et d'INDEX.md : présentes dans l'archive remise, non lues (EX-12.3) ; la liste des commandes à exécuter est celle de README.md et de la consigne"
      ],
      "grid": null,
      "judge": "Le juge compare chaque code de retour consigné à celui de l'intégration continue au même commit ; les sorties consignées servent au diagnostic, sans tolérance jugée (EX-12.10) ; consignation 12.1.",
      "verdict_rule": "Réussi si chaque code de retour égale celui de la CI, si `information_requests` est nul et si le dossier et le paquet sont vérifiés par la copie jointe hors réseau."
    }
  },
  {
    "id": "TR-13",
    "level": "TR",
    "title": "CT-9 épreuve (a) : un testeur qui n'a que CT-9 et la spécification visée écrit, pour cinq entrées « à écrire » tirées au sort, les préconditions, les étapes et l'oracle en code ou pseudo-code exécutable, sans contredire le catalogue",
    "specs": [
      "CT-1",
      "CT-2",
      "CT-3",
      "CT-4",
      "CT-5",
      "CT-6",
      "CT-7",
      "CT-8"
    ],
    "covers": [],
    "preconditions": [
      "CT-9 (sans la section 15) et, pour chaque entrée tirée, la spécification qu'elle vise ; `spec/vecteurs/ct-9/acceptation-plan/consigne.md` ; tirage de cinq entrées `a_ecrire` hors TR-13 à TR-15 consigné par le juge ; participant extérieur."
    ],
    "steps": [
      "Le participant écrit, par entrée, un fichier de test (mocha ou pseudo-code structuré) avec préconditions, étapes et oracle.",
      "Le juge compare au catalogue : chaque précondition, étape et oracle de l'entrée a une contrepartie exécutable (entrée concrète, comparaison, valeur ou fichier), aucune assertion ne contredit l'oracle ni les sources citées ; la grille est l'entrée elle-même et les exigences qu'elle cite (exception écrite d'EX-12.3 : pour TR-13, l'entrée est à la fois matériel et grille)."
    ],
    "oracle": "Zéro contradiction sur les cinq entrées ; une assertion qui inverse l'oracle d'une entrée est disqualifiante ; une réponse qui reprend le texte des préconditions, des étapes ou de l'oracle sans entrée concrète ni comparaison exécutable échoue.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Épreuve humaine de CT-9, conduite à la porte 2 ; consigne publiée (`spec/vecteurs/ct-9/acceptation-plan/consigne.md`), grille : l'entrée tirée."
    },
    "threats": [],
    "replay": {
      "participant": "Un testeur extérieur au projet",
      "material": [
        "CT-9 sans la section 15",
        "les identifiants des cinq entrées tirées, remis par le juge ; les spécifications que ces entrées visent (membre `specs`) et, de toute autre spécification que leurs préconditions, pas, oracle ou bloc propre nomment, les sections citées",
        "spec/vecteurs/ct-9/acceptation-plan/consigne.md",
        "spec/vecteurs/ct-9/catalogue.json"
      ],
      "forbidden_sections": [
        "CT-9 section 15",
        "test/*.test.js du dépôt"
      ],
      "grid": "spec/vecteurs/ct-9/catalogue.json",
      "judge": "Le juge, qui n'a pas aidé le participant, compare chaque fichier rendu à l'entrée du catalogue (préconditions, étapes, oracle) ; consignation 12.1.",
      "verdict_rule": "Réussi si les cinq fichiers rendus ont, pour chaque précondition, étape et oracle de leur entrée, une contrepartie exécutable et ne contredisent aucun oracle ; une réponse qui reprend le texte de l'entrée sans entrée concrète ni comparaison exécutable échoue."
    }
  },
  {
    "id": "TR-14",
    "level": "TR",
    "title": "CT-9 épreuve (b) : un relecteur de la porte 2 qui n'a que CT-9 dit ce que le passage de la porte 2 prouve et ne prouve pas, et quel critère du plan chaque famille de tests sert",
    "specs": [
      "CT-1",
      "CT-2",
      "CT-3",
      "CT-4",
      "CT-5",
      "CT-6",
      "CT-7",
      "CT-8"
    ],
    "covers": [],
    "preconditions": [
      "CT-9 sans la section 15 ; `spec/vecteurs/ct-9/acceptation-porte-2/consigne.md` (trois questions) ; participant extérieur."
    ],
    "steps": [
      "Le participant écrit : pour chaque critère « continuer si », les entrées qui le servent et le verdict calculable ; ce que la porte 2 ne mesure pas ; pour chaque famille TU- à TQ-, le critère du plan qu'elle sert.",
      "Le juge marque les éléments de `spec/vecteurs/ct-9/acceptation-porte-2-attendu.json`, produits par le générateur depuis la section 14 et la table des niveaux."
    ],
    "oracle": "Chaque réponse contient tous ses éléments ; une réponse qui dit que la porte 2 prouve la conformité d'un client, la preuve du périmètre ou la robustesse hors du modèle de menace échoue quels que soient ses autres éléments.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Épreuve humaine de CT-9, conduite à la porte 2 ; consigne et grille publiées par le générateur de ct-9."
    },
    "threats": [],
    "replay": {
      "participant": "Un relecteur extérieur de la porte 2",
      "material": [
        "CT-9 sans la section 15",
        "spec/vecteurs/ct-9/acceptation-porte-2/consigne.md"
      ],
      "forbidden_sections": [
        "CT-9 section 15",
        "spec/vecteurs/ct-9/acceptation-porte-2-attendu.json",
        "le plan de projet interne"
      ],
      "grid": "spec/vecteurs/ct-9/acceptation-porte-2-attendu.json",
      "judge": "Une personne qui n'a pas aidé le participant marque chaque élément de la grille présent ou absent et applique les clauses disqualifiantes ; consignation `consignation_rejeu` (12.1).",
      "verdict_rule": "Réussi si chaque réponse contient tous ses éléments et qu'aucune clause disqualifiante n'est présente."
    }
  },
  {
    "id": "TR-15",
    "level": "TR",
    "title": "CT-9 épreuve (c) : un développeur qui n'a que CT-9 ajoute au catalogue un test pour une exigence donnée en suivant les seules règles de CT-9, et l'outil de couverture l'accepte",
    "specs": [
      "CT-1",
      "CT-2",
      "CT-3",
      "CT-4",
      "CT-5",
      "CT-6",
      "CT-7",
      "CT-8"
    ],
    "covers": [],
    "preconditions": [
      "CT-9 sans la section 15 ; dépôt au commit éprouvé ; une exigence EX- désignée par le juge (consignée) ; `spec/vecteurs/ct-9/acceptation-plan/consigne.md` ; participant extérieur."
    ],
    "steps": [
      "Le participant ajoute une entrée à la source de données du générateur, régénère le catalogue et lance `node scripts/tests/couverture.mjs`, sans puis avec `--strict`. L'entrée est `a_ecrire` (EX-3.10 : étape qui livre son objet et ce qui bloque ; étape 8 pour un test possible dès maintenant mais non écrit), ou `executable` si le participant écrit aussi le test qu'elle cite : le diff de `test/*.test.js` fait alors partie de la réponse, et la règle (d) relit ses titres.",
      "Le juge relève le code de retour de l'outil et vérifie que l'entrée nomme l'exigence dans `covers`, a un identifiant unique de la bonne famille, un état conforme (EX-3.10), et que la table du texte régénérée lui correspond."
    ],
    "oracle": "Code 0 de l'outil de couverture avec l'entrée ajoutée, sans et avec `--strict`, comme la CI (EX-12.5) ; exigence couverte : l'exigence, préfixée de sa spécification, figure dans `covers` (règle (a)) ; aucune autre entrée modifiée. La qualité du test (contrepartie exécutable, test plus fin au sens de 5.1) n'est pas jugée par cette épreuve, qui éprouve que les règles de CT-9 suffisent à produire une entrée acceptée ; la contrepartie exécutable est ce que juge l'épreuve (a) (TR-13).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Épreuve humaine de CT-9, conduite à la porte 2 ; consigne publiée, outil de couverture livré (`scripts/tests/couverture.mjs`)."
    },
    "threats": [],
    "replay": {
      "participant": "Un développeur extérieur au projet",
      "material": [
        "CT-9 sans la section 15",
        "dépôt au commit éprouvé",
        "spec/vecteurs/ct-9/acceptation-plan/consigne.md"
      ],
      "forbidden_sections": [
        "CT-9 section 15",
        "toute aide d'un auteur de CT-9"
      ],
      "grid": null,
      "judge": "Verdict d'outil (`scripts/tests/couverture.mjs`, code 0 sans et avec `--strict`) relevé par le juge, qui vérifie aussi que seule l'entrée ajoutée a changé ; consignation 12.1.",
      "verdict_rule": "Réussi si l'outil de couverture rend 0, sans et avec `--strict`, avec l'entrée ajoutée, qui couvre l'exigence désignée (exigence préfixée de sa spécification dans `covers`), et si aucune autre entrée n'a changé."
    }
  }
];
