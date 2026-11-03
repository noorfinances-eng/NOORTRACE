// Source de données du catalogue CT-9 : entrées TA- (section 10). Pour TA-1 à
// TA-98, seuls les membres propres sont ici ; menace, composant, `covers`,
// `threat_test_text` et risque accepté viennent de spec/vecteurs/ct-7/menaces.json
// (EX-10.2). Les cinq scénarios du plan (10.5) composent des TA-.

export const TA = [
  {
    "id": "TA-1",
    "preconditions": [
      "Démonstration de référence de CT-2 §19 (docker compose : agent, enregistreur, serveur d'outils HTTP, simulateur de modèle) construite et lancée ; phase 2, étape 8.",
      "Journal du pare-feu de l'hôte de démonstration lisible par le test."
    ],
    "steps": [
      "Lancer la démonstration et attendre l'événement seq 1.",
      "Exécuter dans le conteneur de l'agent : connexion TCP au port du serveur d'outils (nom de service de la composition).",
      "Relever le code de retour de la connexion et le journal du pare-feu.",
      "Rejouer après retrait de la règle de sortie."
    ],
    "oracle": "Avec la règle : code de retour non nul et une ligne de refus datée dans le journal du pare-feu ; sans la règle : connexion établie. Le test compare ces deux observations.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Démonstration de référence et tests de bout en bout : phase 2, étape 8."
    },
    "response_removed": {
      "what": "Règle de sortie du pare-feu : seul le mandataire joint le serveur d'outils HTTP (CT-2 EX-4.1, §4.9)",
      "how": "Retirer, dans la composition de la démonstration, la règle de réseau qui isole le conteneur de l'agent du réseau des serveurs d'outils",
      "where": "deploiement (composition docker compose de CT-2 §19.1)"
    },
    "attack": "Depuis le conteneur de l'agent, ouvrir une connexion TCP directe vers le serveur d'outils HTTP de la démonstration, sans passer par le mandataire.",
    "expected_with_response": "La connexion échoue (refus ou délai) ; une ligne du journal du pare-feu la nomme (CT-2 §4.9, point 5) ; le journal NOORTRACE ne porte aucun événement.",
    "expected_without_response": "La connexion aboutit et l'outil répond ; aucun événement n'existe ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-2",
    "preconditions": [
      "Démon réel `bin/noortrace --config` du paquet `paquets/enregistreur` (étape 4) et son mutant (copie du paquet, EX-10.5) ; configuration de développement tirée de l'exemple de CT-2 §15.3 (classe D, magasin de bail `file`, frontal MCP en Streamable HTTP à jetons statiques, serveur d'outils stdio de test `test/fixtures/enregistreur-adversarial/serveur-outils.mjs`, service d'approbation simulé joint en HTTP).",
      "Deux connexions d'hôte HTTP : `agent-demo` (`accept_declared_delegation` vrai, `allowed_on_behalf_of` = [`service-sinistres`], `on_behalf_of` configuré `service-sinistres`) et `agent-demo-b` (`accept_declared_delegation` faux)."
    ],
    "steps": [
      "Envoyer, sur chacune des deux connexions, un tools/call dont _meta[\"noortrace/delegation\"] = { launched_by: « u.autre@assureur-demo.example », on_behalf_of: « service-autre », run_id: « run-ta2-0001 » }.",
      "Lire delegation des deux événements scellés et les lignes delegation_refused du journal d'exploitation.",
      "Fabriquer le mutant (copie de paquets/enregistreur avec le remplacement nommé) et rejouer."
    ],
    "oracle": "delegation.launched_by égal au launched_by configuré de chaque connexion ; sur `agent-demo`, run_id déclaré admis (motif d'EX-7.2) et on_behalf_of hors de allowed_on_behalf_of remplacé par celui de la configuration, refus consigné (delegation_refused, champ on_behalf_of, raison hors_liste, longueur, jamais la valeur) ; sur `agent-demo-b`, on_behalf_of de la configuration et run_id = identifiant de session MCP de l'hôte hérité (table de CT-2 §7.2) ; le mutant scelle le launched_by de l'hôte.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables sur le démon de l'étape 4 (mutants du paquet @noortrace/enregistreur, CT-7 EX-3.2)",
          "it": "TA-2 (MN-2) : démon réel : un tools/call dont _meta[\\\"noortrace/delegation\\\"] déclare launched_by, on_behalf_of hors liste et run_id, sur une connexion configurée pour agent-demo : launched_by de la configuration, run_id admis, on_behalf_of remplacé (delegation_refused) ; sans délégation admise : run_id de session ; mutant qui recopie le launched_by déclaré (tué)"
        }
      ]
    },
    "response_removed": {
      "what": "launched_by tiré de la configuration de la connexion d'hôte, jamais de l'hôte (CT-2 EX-7.2, EX-7.3)",
      "how": "Faire prendre à resoudreDelegation la valeur launched_by déclarée par l'hôte dans _meta[\"noortrace/delegation\"] à la place de celle de la configuration",
      "where": "paquets/enregistreur/src/mcp/delegation.mjs (resoudreDelegation)"
    },
    "attack": "Un appel tools/call dont _meta[\"noortrace/delegation\"] déclare launched_by « u.autre@assureur-demo.example » et on_behalf_of « service-autre », reçu sur une connexion d'hôte configurée pour « agent-demo ».",
    "expected_with_response": "L'événement scellé porte delegation.launched_by = « agent-demo » (configuration) ; seuls run_id et on_behalf_of peuvent venir de l'hôte (EX-7.2), l'on_behalf_of déclaré hors liste est remplacé et son refus consigné (delegation_refused) ; un launched_by déclaré est ignoré sans ligne propre (CT-2 EX-17.2 ne nomme delegation_refused que pour run_id et on_behalf_of).",
    "expected_without_response": "L'événement porte launched_by « u.autre@assureur-demo.example » ; le test échoue.",
    "execution": "phase_2",
    "notes": "Au 2026-11-01, scripts/lib/capture.mjs ne lisait nulle part _meta[\"noortrace/delegation\"] (grep : 0 occurrence ; PD-12) ; le démon de l'étape 4 code EX-7.2 (paquets/enregistreur/src/mcp/delegation.mjs, appelé par mcp/frontal.mjs) : le test porte sur lui. La version 0.1 de l'entrée attendait une ligne delegation_refused pour un launched_by déclaré, ce que CT-2 EX-17.2 ne prévoit pas ; corrigé en 0.2."
  },
  {
    "id": "TA-3",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "decision et rule du cas égalent l'attendu du vecteur ; le mutant rend autorise.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-3 (MN-3) : evaluation/niveaux.json, cas fenetre-epuisee : une fenêtre au plafond max_calls atteint rend a_approuver ; mutant qui ignore remaining : autorise (tué)"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : évaluation (sections 4 à 6, AP-5 à AP-17)",
          "it": "evaluation/ : chaque cas rend exactement rule, decision, opening et l'état des fenêtres attendus"
        }
      ]
    },
    "response_removed": {
      "what": "Plafond max_calls d'une fenêtre d'approbation (CT-3 EX-5.2, EX-5.5)",
      "how": "Retirer la condition w.remaining >= 1 de la recherche d'une fenêtre couvrante",
      "where": "scripts/lib/approbation.mjs (fenêtre couvrante, EX-5.5)"
    },
    "attack": "Troisième appel de 3 000 CHF sous une fenêtre dont les deux unités sont consommées (cas fenetre-epuisee de evaluation/niveaux.json).",
    "expected_with_response": "evaluer rend a_approuver sur la règle « fenetre moyenne » : l'appel est retenu.",
    "expected_without_response": "evaluer rend autorise ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-4",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "Refus attendu par le vecteur (canonical null) et code -32602 ; le mutant rend une forme canonique et aucune erreur.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-4 (MN-4) : jcs-integral ct1-4-cle-en-double est refusé, et un argument décimal non représentable en double (1.00000000000000001) est refusé au relais (-32602 nombre_non_representable) ; mutants sans ces contrôles : la clé en double est canonisée et la requête est relayée (tués)"
        },
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : vecteurs spec/vecteurs/ct-2, rejoués",
          "it": "jcs-integral/cas.json : chaque forme canonique, ou le refus"
        }
      ]
    },
    "response_removed": {
      "what": "Analyse stricte : clé en double refusée, nombre non représentable refusé (CT-2 EX-4.43, EX-4.44)",
      "how": "Neutraliser le contrôle des clés en double de l'analyseur JSON intégral et le contrôle nombre_non_representable de lireRequeteHote",
      "where": "scripts/lib/capture.mjs"
    },
    "attack": "Cas ct1-4-cle-en-double de jcs-integral/cas.json ; requête tools/call dont un argument vaut 1.00000000000000001.",
    "expected_with_response": "jcsIntegralDuTexte lève ErreurFormat ; lireRequeteHote rend -32602 nombre_non_representable.",
    "expected_without_response": "La clé en double est canonisée (dernière valeur gagnante) et la requête est relayée avec un nombre que la politique lit autrement que le serveur ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-5",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "rejouerTrace redonne chaque attendu pas à pas ; le mutant diverge au pas 13. Les vérifications RL-2 et RL-3 (verifierRelais, MAC des arguments) restent à éprouver par un mutant de verifierRelais sur les vecteurs ct-2 (complément, étape 8).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-5 (MN-5) : tickets/consommation-tardive.json : un consommer hors de l'état approuve est refusé (requete_invalide, pas 13) ; mutant sans ce refus : la trace diverge (tué)"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : tickets (section 7, TK-1 à TK-13)",
          "it": "chaque trace rejouée sur un service vide redonne chaque attendu, pas à pas (EX-7.9, EX-A.6)"
        }
      ],
      "complement": {
        "phase2_step": 8,
        "blocking": "Mutant de verifierRelais (RL-2, RL-3, CT-2 EX-7.21) à ajouter à test/adversarial.test.js sur les vecteurs ct-2 ; possible dès maintenant sur le dépôt, dû au plus tard à l'étape 8."
      }
    },
    "response_removed": {
      "what": "Consommation unique d'une approbation et délai de reconnaissance (CT-3 EX-7.17, EX-7.18) ; RL-1 à RL-4 côté enregistreur (CT-2 EX-7.21)",
      "how": "Retirer le refus requete_invalide d'un consommer hors de l'état approuve",
      "where": "scripts/lib/approbation.mjs (ServiceApprobation.consommer)"
    },
    "attack": "Trace tickets/consommation-tardive.json : un second consommer sur un ticket clos (pas 13) ; trace retenir-double-reemission.json : ré-émission après consommation.",
    "expected_with_response": "Le service refuse (requete_invalide) et la ré-émission ouvre un ticket neuf (apr-0002) au lieu de resservir l'approbation.",
    "expected_without_response": "Le consommer tardif est accepté : la trace diverge au pas 13 ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-6",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "Égalité pas à pas avec la trace ; divergence au pas 4 pour le mutant.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-6 (MN-6) : tickets/plafond.json : la demande au-delà de max_open_tickets reçoit plafond_atteint (pas 4) ; mutant sans plafond : la trace diverge (tué)"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : tickets (section 7, TK-1 à TK-13)",
          "it": "chaque trace rejouée sur un service vide redonne chaque attendu, pas à pas (EX-7.9, EX-A.6)"
        }
      ]
    },
    "response_removed": {
      "what": "Plafond de tickets ouverts par demandeur (CT-3 EX-14.1)",
      "how": "Retirer le refus plafond_atteint",
      "where": "scripts/lib/approbation.mjs (ServiceApprobation, ouverture d'un ticket)"
    },
    "attack": "Trace tickets/plafond.json : troisième demande à approuver du même launched_by avec max_open_tickets = 2 (pas 4).",
    "expected_with_response": "Réponse accepted false, reason plafond_atteint, aucun ticket créé.",
    "expected_without_response": "Un ticket apr-0003 est créé au pas 4 ; la trace diverge ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-7",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22.",
      "Démon réel `bin/noortrace --config` du paquet `paquets/enregistreur` (étape 4) et son mutant (copie du paquet, EX-10.5) ; configuration de développement tirée de l'exemple de CT-2 §15.3 (classe D, magasin de bail `file`, frontal MCP en Streamable HTTP à jetons statiques, serveur d'outils stdio de test `test/fixtures/enregistreur-adversarial/serveur-outils.mjs`, service d'approbation simulé joint en HTTP)."
    ],
    "steps": [
      "Rejouer pieces-mcp/agregation sur agregerOutils de la bibliothèque de référence, puis sur le mutant sans l'espace réservé.",
      "Démon réel : tools/list ; appel de l'outil lire ; description de lire changée côté serveur (notifications/tools/list_changed) ; tools/list à nouveau ; appel de lire ; lire le journal d'exploitation et les pièces ; rejouer sur le mutant du paquet sans l'empreinte comparée des définitions."
    ],
    "oracle": "rejected du vecteur égal à l'attendu, le mutant de la bibliothèque annonce l'outil réservé ; démon : ligne tool_definition_changed (ancienne et nouvelle empreintes égales aux pièces de définition du contexte des deux appels) et pièce de la nouvelle définition, de SHA-256 différent, stockée ; le mutant du paquet ne consigne rien.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-7 (MN-7, partie exécutable ; la partie « définition changée entre deux tools/list » exige un serveur vivant, phase 2, étape 4) : pieces-mcp/agregation : un outil noortrace.* annoncé par un serveur est rejeté (nom_reserve) ; mutant sans l'espace réservé : il est annoncé (tué)"
        },
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : vecteurs spec/vecteurs/ct-2, rejoués",
          "it": "pieces-mcp/agregation : noms annoncés, rejets, classes, empreintes des définitions, pages ; préfixe désactivé"
        },
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables sur le démon de l'étape 4 (mutants du paquet @noortrace/enregistreur, CT-7 EX-3.2)",
          "it": "TA-7 (MN-7, partie phase 2 sur le démon de l'étape 4) : description de lire changée côté serveur entre deux tools/list : ligne tool_definition_changed (ancienne et nouvelle empreintes) et pièce de la nouvelle définition, de SHA-256 différent, au contexte de l'appel suivant ; mutant sans l'empreinte comparée : aucune ligne (tué)"
        }
      ]
    },
    "response_removed": {
      "what": "Espace noortrace.* réservé, aucun outil propre annoncé (CT-2 EX-4.2, CT-1 E-3) ; empreinte de chaque définition et pièce de définition (CT-2 EX-4.16, EX-4.45)",
      "how": "Retirer le rejet nom_reserve d'agregerOutils ; sur le démon, retirer la comparaison des empreintes des définitions (la condition de tool_definition_changed devient false)",
      "where": "scripts/lib/capture.mjs (agregerOutils) ; paquets/enregistreur/src/mcp/frontal.mjs (recalculer)"
    },
    "attack": "Un serveur d'outils annonce noortrace.journal.politique (vecteur pieces-mcp/agregation) ; un serveur de test change la description d'un outil entre deux tools/list du démon.",
    "expected_with_response": "L'outil réservé est rejeté (nom_reserve) ; sur le démon, la ligne tool_definition_changed et la nouvelle pièce de définition existent.",
    "expected_without_response": "L'outil noortrace.* est annoncé à l'hôte (un événement réservé peut être forgé) ; sur le démon, rien n'est consigné ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-8",
    "preconditions": [
      "Démon réel `bin/noortrace --config` du paquet `paquets/enregistreur` (étape 4) et son mutant (copie du paquet, EX-10.5) ; configuration de développement tirée de l'exemple de CT-2 §15.3 (classe D, magasin de bail `file`, frontal MCP en Streamable HTTP à jetons statiques, serveur d'outils stdio de test `test/fixtures/enregistreur-adversarial/serveur-outils.mjs`, service d'approbation simulé joint en HTTP).",
      "Deux connexions d'hôte configurées avec des jetons distincts."
    ],
    "steps": [
      "POST tools/call sans en-tête d'autorisation ; relever le statut et le journal d'exploitation.",
      "Même appel avec un jeton de 32 octets aléatoires.",
      "Même appel avec le jeton de l'hôte B ; lire delegation de l'événement.",
      "Fabriquer le mutant (copie de paquets/enregistreur avec les remplacements nommés) et rejouer."
    ],
    "oracle": "Statuts 401, lignes auth_failed (raisons absent et jeton_inconnu), aucun événement pour les deux premiers appels ; événement du troisième attribué à l'hôte B ; avec le mutant, l'appel sans jeton est relayé et un événement est écrit.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables sur le démon de l'étape 4 (mutants du paquet @noortrace/enregistreur, CT-7 EX-3.2)",
          "it": "TA-8 (MN-8) : démon réel, frontal MCP Streamable HTTP, deux connexions d'hôte à jetons distincts : tools/call sans autorisation puis avec un jeton de 32 octets aléatoires : 401, deux lignes auth_failed, aucun événement ; avec le jeton de l'hôte B : événement attribué à l'hôte B ; mutant sans la vérification du jeton : l'appel sans jeton est relayé et un événement est écrit (tué)"
        }
      ]
    },
    "response_removed": {
      "what": "Authentification de tout appelant HTTP, comparaison en temps constant, prise locale 0660 (CT-2 EX-18.3, EX-4.39, EX-18.1)",
      "how": "Désactiver la vérification du jeton d'hôte : le refus d'un en-tête absent est retiré et la comparaison du jeton est posée vraie",
      "where": "paquets/enregistreur/src/mcp/hote-http.mjs (_authentifier)"
    },
    "attack": "Connexion HTTP au point de terminaison MCP sans jeton, puis avec un jeton faux, puis avec le jeton d'un autre hôte.",
    "expected_with_response": "Les deux premières sont refusées (401) et consignées (ligne auth_failed) ; la troisième est journalisée sous l'identité du jeton présenté, jamais sous une autre.",
    "expected_without_response": "L'appel sans jeton est relayé et un événement est écrit ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-9",
    "preconditions": [
      "Démon réel `bin/noortrace --config` du paquet `paquets/enregistreur` (étape 4) et son mutant (copie du paquet, EX-10.5) ; configuration de développement tirée de l'exemple de CT-2 §15.3 (classe D, magasin de bail `file`, frontal MCP en Streamable HTTP à jetons statiques, serveur d'outils stdio de test `test/fixtures/enregistreur-adversarial/serveur-outils.mjs`, service d'approbation simulé joint en HTTP).",
      "Démon lancé par le superutilisateur, pour qu'il puisse changer d'utilisateur (EX-3.5) ; sinon, le test est mis en attente et son titre le dit (EX-3.11).",
      "Serveur stdio de test (outil « sonder ») lancé sous l'utilisateur `nobody` (transport.user) ; secret relay_mac_key dans un fichier 0400 (EX-15.3)."
    ],
    "steps": [
      "Configurer le serveur de test en stdio sous l'utilisateur nobody.",
      "Appeler l'outil « sonder » qui tente de lire le fichier du secret relay_mac_key et d'écrire sous storage.root, et rend les codes errno et son uid.",
      "Lire le résultat de l'outil et le contenu de storage.root ; rejouer sur le mutant du paquet."
    ],
    "oracle": "Les deux accès rendent EACCES, uid 65534 ; aucun fichier nouveau sous storage.root ; avec le mutant (serveur lancé sous l'utilisateur du démon), les deux accès réussissent.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables sur le démon de l'étape 4 (mutants du paquet @noortrace/enregistreur, CT-7 EX-3.2)",
          "it": "TA-9 (MN-9) : démon réel lancé par le superutilisateur, serveur stdio configuré sous l'utilisateur nobody : l'outil sonder tente de lire le fichier du secret relay_mac_key (0400) et d'écrire sous storage.root ; les deux accès rendent EACCES et aucun fichier n'apparaît sous storage.root ; mutant qui lance le serveur sous l'utilisateur du démon : les deux accès réussissent (tué)"
        }
      ]
    },
    "response_removed": {
      "what": "Utilisateur distinct, bac à sable et environnement réduit des serveurs stdio (CT-2 EX-3.4, EX-3.5, EX-18.4) ; secrets en fichiers 0400 (EX-15.3)",
      "how": "Lancer le serveur stdio sous l'utilisateur du démon (le changement d'utilisateur devient false)",
      "where": "paquets/enregistreur/src/mcp/amont.mjs (lancement des serveurs stdio)"
    },
    "attack": "Un serveur stdio de test tente de lire le fichier du secret relay_mac_key et d'écrire un fichier sous storage.root.",
    "expected_with_response": "Les deux accès échouent (EACCES).",
    "expected_without_response": "Lecture et écriture réussissent ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-10",
    "preconditions": [
      "Bibliothèques de référence du dépôt (partie sur reprise()).",
      "Démon réel `bin/noortrace --config` du paquet `paquets/enregistreur` (étape 4) et son mutant (copie du paquet, EX-10.5) ; configuration de développement tirée de l'exemple de CT-2 §15.3 (classe D, magasin de bail `file`, frontal MCP en Streamable HTTP à jetons statiques, serveur d'outils stdio de test `test/fixtures/enregistreur-adversarial/serveur-outils.mjs`, service d'approbation simulé joint en HTTP).",
      "Serveur d'outils de test qui journalise chaque exécution (`--executions`)."
    ],
    "steps": [
      "Appeler un outil de classe ecriture (ecrire_lent) ; dès que le serveur a reçu l'appel (pas 9), tuer le démon (SIGKILL) avant le scellement.",
      "Redémarrer ; lire le segment, le journal d'intention et le journal d'exploitation.",
      "Comparer au journal du serveur d'outils.",
      "Démon réel : perte du bail pendant le relais d'une écriture (auxiliaire flock(1) tué) ; lire la réponse de l'hôte.",
      "Fabriquer le mutant (copie de paquets/enregistreur sans intention durable avant relais) et rejouer le premier pas."
    ],
    "oracle": "Un événement de reprise (execution.status executee, is_error vrai, duration_ms 0, intent_recovered) par intention ouverte, autant que d'exécutions constatées côté serveur ; code -31017 (data.reason bail, intent_id) reçu par l'hôte quand la panne survient après le relais, le démon vivant (EX-4.46) ; avec le mutant, aucun événement pour l'écriture exécutée. Le test existant sur reprise() couvre la bibliothèque de référence.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : construction des événements, écrivain, segment, intention, reprise (§7, §9, §12)",
          "it": "journal d'intention : intention sans levée → événement de reprise valide ; événement durable → levée implicite (EX-12.14)"
        },
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables sur le démon de l'étape 4 (mutants du paquet @noortrace/enregistreur, CT-7 EX-3.2)",
          "it": "TA-10 (MN-10, partie phase 2 sur le démon de l'étape 4) : écriture relayée puis démon tué avant le scellement : au redémarrage, un événement de reprise par intention ouverte, autant que d'exécutions côté serveur ; bail perdu après le relais : -31017 à l'hôte ; mutant sans intention durable avant relais : aucun événement (tué)"
        }
      ]
    },
    "response_removed": {
      "what": "Intention durable avant relais et reprise des intentions (CT-2 EX-4.19, EX-12.12, EX-12.14) ; code -31017 (EX-4.46)",
      "how": "Bibliothèque : retirer la levée implicite et la reprise de reprise() ; démon : retirer l'intention durable écrite avant le relais d'une écriture (la condition devient false)",
      "where": "scripts/lib/capture.mjs (reprise) ; paquets/enregistreur/src/coeur.mjs (relais en deux temps)"
    },
    "attack": "Démon tué après le relais d'un appel de classe ecriture, avant son scellement ; redémarrage. Bail perdu pendant un relais.",
    "expected_with_response": "Au redémarrage, une intention sans levée produit un événement de reprise (execution.status executee, is_error vrai, pièce de reprise) ; une panne après le relais, le démon vivant, rend -31017 à l'hôte.",
    "expected_without_response": "Aucun événement n'existe pour l'écriture exécutée ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-11",
    "preconditions": [
      "Schéma de configuration du dépôt (partie existante).",
      "Démon réel `bin/noortrace --config` (étape 4) en mode passerelle et son mutant (copie du paquet, EX-10.5) ; configuration du frontal modèle des tests (`test/fixtures/enregistreur-modele/outils.mjs`) : route /v1/messages en credentials propre, auth_header x-api-key, secret résolu par référence d'environnement.",
      "Fournisseur simulé de CT-2 §19.3 qui garde les en-têtes reçus (`test/fixtures/enregistreur-modele/fournisseur.mjs`)."
    ],
    "steps": [
      "Envoyer une requête d'échange identifiée par X-Noortrace-Token et portant dans x-api-key une clé de l'hôte marquée.",
      "Lire les en-têtes reçus par le simulateur et chercher la clé marquée dans chaque fichier écrit (stockage, pièces, segments, journal d'exploitation).",
      "Fabriquer le mutant (copie de paquets/enregistreur avec le remplacement nommé) et rejouer."
    ],
    "oracle": "L'en-tête reçu par le simulateur est celui de la configuration (référence de secret résolue) ; la valeur de l'hôte n'apparaît dans aucun fichier écrit ; avec le mutant, la clé de l'hôte arrive au simulateur. Le schéma impose auth_header et la forme de credentials (test existant).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : Gemini à la passerelle et format gemini du SDK (EX-5.28 à EX-5.36, EX-6.8)",
          "it": "schéma de configuration : model_route gemini (bloc annoté de 15.3), auth_header imposé, provider_mcp réservé à gemini ; mots-clés dans le sous-ensemble appliqué"
        },
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables sur le démon de l'étape 4 (mutants du paquet @noortrace/enregistreur, CT-7 EX-3.2)",
          "it": "TA-11 (MN-11, partie phase 2 sur le démon de l'étape 4) : passerelle, route en credentials propre : la clé marquée que l'hôte met dans x-api-key n'arrive pas au fournisseur simulé, qui reçoit celle de la configuration, et n'est dans aucun fichier écrit ; mutant qui relaie l'en-tête de l'hôte : sa clé traverse (tué)"
        }
      ]
    },
    "response_removed": {
      "what": "Clé du fournisseur tenue par la passerelle seule en mode propre (CT-2 EX-5.8) ; pare-feu de sortie (§4.9, EX-6.2)",
      "how": "Faire relayer l'en-tête d'autorisation de l'hôte au lieu de le remplacer (la condition credentials propre de l'échange devient false)",
      "where": "paquets/enregistreur/src/modele/passerelle.mjs (envoi au fournisseur) ; schéma de configuration (auth_header, credentials propre)"
    },
    "attack": "Requête de l'hôte vers la passerelle portant sa propre clé de fournisseur dans l'en-tête d'autorisation, sur une route credentials: propre.",
    "expected_with_response": "La requête amont porte la clé de la passerelle ; la clé de l'hôte n'apparaît ni en amont ni dans les pièces ni dans le journal d'exploitation.",
    "expected_without_response": "La clé de l'hôte traverse ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-12",
    "preconditions": [
      "Démon réel `bin/noortrace --config` (étape 4) en mode icap et son mutant (copie du paquet, EX-10.5) ; configuration du frontal modèle des tests (`configurationIcap`).",
      "Mode icap configuré avec allowed_sources = [203.0.113.5/32] ; client ICAP de test (`test/fixtures/enregistreur-modele/client-icap.mjs`) sur la boucle locale : le banc ne peut pas prendre une adresse de la plage de documentation."
    ],
    "steps": [
      "Émettre un REQMOD puis un RESPMOD depuis une adresse absente d'allowed_sources (127.0.0.1).",
      "Lire la réponse ICAP, le journal d'exploitation et les événements.",
      "Fabriquer le mutant (copie de paquets/enregistreur avec le remplacement nommé) et rejouer."
    ],
    "oracle": "Refus 403 consigné (auth_failed, transport icap, raison client_icap_refuse) ; aucun échange écrit ; avec le mutant, REQMOD et RESPMOD rendent 200 et un événement noortrace.modele.echange est écrit.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables sur le démon de l'étape 4 (mutants du paquet @noortrace/enregistreur, CT-7 EX-3.2)",
          "it": "TA-12 (MN-12) : démon réel en mode icap, allowed_sources = [203.0.113.5/32] : REQMOD puis RESPMOD depuis une adresse absente (127.0.0.1) : 403 consigné (auth_failed, client_icap_refuse), aucun échange écrit ; mutant sans l'authentification des clients ICAP : un échange est écrit à partir de la transaction fabriquée (tué)"
        }
      ]
    },
    "response_removed": {
      "what": "Clients ICAP authentifiés (mTLS ou allowed_sources), l'un des deux exigé en production (CT-2 EX-5.3 ; CT-7 EX-3.15)",
      "how": "Retirer le refus d'un client ICAP non admis (la condition devient false)",
      "where": "paquets/enregistreur/src/modele/icap.mjs (_connexion) ; configuration"
    },
    "attack": "Transaction REQMOD puis RESPMOD envoyée depuis une adresse absente de allowed_sources (127.0.0.1, boucle locale du banc), sans certificat client.",
    "expected_with_response": "La transaction est refusée et consignée (source inconnue) ; aucun échange de modèle n'est écrit.",
    "expected_without_response": "Un événement noortrace.modele.echange est écrit à partir d'une transaction fabriquée ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-13",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "r.refus.raison égal à l'attendu ; le mutant ne refuse pas.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-13 (MN-13) : pieces-modele/gemini-refus-mcp-fournisseur : une requête qui déclare un serveur MCP au fournisseur est refusée (serveurs_mcp_fournisseur) ; mutant sans le refus : elle part (tué)"
        },
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : Gemini à la passerelle et format gemini du SDK (EX-5.28 à EX-5.36, EX-6.8)",
          "it": "pieces-modele/gemini-* : les 30 cas de l'annexe B.5 rejoués (route, segment, refus et corps exact, cible amont, pièces, forme consolidée, code.model, intent, appels)"
        },
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : Gemini à la passerelle et format gemini du SDK (EX-5.28 à EX-5.36, EX-6.8)",
          "it": "EX-5.32 : mcpServers refusés sous refuser (défaut), relayés et consignés sous relayer, notés seulement pour le SDK ; null et [] ne comptent pas"
        }
      ]
    },
    "response_removed": {
      "what": "Refus d'une requête qui déclare des serveurs MCP au fournisseur, sauf relayer (CT-2 EX-5.32)",
      "how": "Retirer le refus serveurs_mcp_fournisseur",
      "where": "scripts/lib/capture.mjs (echangeModele, branche gemini)"
    },
    "attack": "Vecteur pieces-modele/gemini-refus-mcp-fournisseur : requête generateContent avec tools[].mcpServers.",
    "expected_with_response": "Refus 400 serveurs_mcp_fournisseur, ligne model_request_refused, rien n'est relayé.",
    "expected_without_response": "La requête part vers le fournisseur ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-14",
    "preconditions": [
      "Partie phase 2 : Démonstration de référence de CT-2 §19 (docker compose : agent, enregistreur, serveur d'outils HTTP, simulateur de modèle) construite et lancée ; phase 2, étape 8."
    ],
    "steps": [
      "Partie phase 2 : lire la configuration effective au démarrage (ligne startup) et le capture_channels de l'attestation."
    ],
    "oracle": "Partie exécutable : erreur de schéma sur /model/mode, aucune avec le schéma mutant. Partie phase 2 : startup.model.mode = passerelle et attestation.agents[].capture_channels contient passerelle.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-14 (MN-14, partie exécutable ; la démonstration en mode passerelle est de phase 2, étape 4) : le schéma de configuration refuse un model.mode inconnu ; schéma mutant sans l'énumération : accepté (tué)"
        }
      ],
      "complement": {
        "phase2_step": 8,
        "blocking": "Partie à écrire : démonstration de référence de CT-2 §19 (docker compose), livrée à l'étape 8 ; la version 0.1 rattachait à tort ce complément à l'étape 4, alors que ses préconditions nomment l'étape 8."
      }
    },
    "response_removed": {
      "what": "Rang de chaque mode écrit et contrôlé (CT-2 §5.1, EX-5.1, EX-5.6) ; mode déclaré dans l'attestation (CT-7 §7)",
      "how": "Retirer l'énumération model.mode du schéma de configuration ; en phase 2, lancer la démonstration dans un autre mode que passerelle",
      "where": "spec/schemas/configuration-enregistreur-v0.schema.json ; démonstration"
    },
    "attack": "Configuration avec model.mode = inconnu ; démonstration lancée en mode miroir.",
    "expected_with_response": "La validation refuse /model/mode ; la démonstration tourne en mode passerelle et l'attestation de périmètre de la démonstration déclare passerelle.",
    "expected_without_response": "Le mode inconnu est accepté ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-15",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "nomOutil rend le nom préfixé ; les 48 cas otel/ portent des noms préfixés (test existant) ; le mutant rend le nom nu.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-15 et TA-16 (MN-15, MN-16) : nomOutil préfixe toujours l'alias de la source et remplace par nom-invalide un nom qui porte « __ » ou noortrace. (vecteur otel/json-outil-nom-invalide) ; mutants sans préfixe ou sans la règle « __ » : un nom d'une autre source passe (tués)"
        },
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : ingestion OpenTelemetry (6.8, EX-6.25 à EX-6.41)",
          "it": "otel/ : les 48 cas de l'annexe B.8 rejoués (statut, réponse octet pour octet, issues, formes normalisées, pièces, événements, chaîne, E-1 à E-11, lag_ms)"
        }
      ]
    },
    "response_removed": {
      "what": "Rang de preuve écrit et alias annoncés dans la chaîne ; événement déclaratif reconnaissable au préfixe <alias>__ (CT-2 §6.7, EX-6.24, EX-6.1)",
      "how": "Retirer le préfixe d'alias du nom d'outil construit",
      "where": "scripts/lib/otel.mjs (nomOutil)"
    },
    "attack": "Span déclaré par une source d'alias otel-sinistres pour l'outil creer.",
    "expected_with_response": "L'événement porte tool = otel-sinistres__creer : le lecteur reconnaît le chemin déclaratif.",
    "expected_without_response": "L'événement porte creer, indiscernable d'un appel capturé par le mandataire ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-16",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "nomOutil rend nom-invalide ; l'attendu du vecteur porte otel-sinistres__nom-invalide ; le mutant rend le nom composé.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-15 et TA-16 (MN-15, MN-16) : nomOutil préfixe toujours l'alias de la source et remplace par nom-invalide un nom qui porte « __ » ou noortrace. (vecteur otel/json-outil-nom-invalide) ; mutants sans préfixe ou sans la règle « __ » : un nom d'une autre source passe (tués)"
        },
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : ingestion OpenTelemetry (6.8, EX-6.25 à EX-6.41)",
          "it": "otel/ : les 48 cas de l'annexe B.8 rejoués (statut, réponse octet pour octet, issues, formes normalisées, pièces, événements, chaîne, E-1 à E-11, lag_ms)"
        }
      ]
    },
    "response_removed": {
      "what": "Noms limités au préfixe de la source, sources authentifiées, bornes (CT-2 EX-6.37, EX-6.40, EX-6.28, EX-4.47)",
      "how": "Retirer la règle qui refuse « __ » dans le nom déclaré",
      "where": "scripts/lib/otel.mjs (nomOutil)"
    },
    "attack": "Span d'une source otel-sinistres qui déclare l'outil paiement__creer (nom d'un autre alias) ; vecteur otel/json-outil-nom-invalide.",
    "expected_with_response": "Le nom devient otel-sinistres__nom-invalide ; le span est scellé sous le nom invalide, jamais sous l'alias d'un autre.",
    "expected_without_response": "L'événement porte otel-sinistres__paiement__creer, qui usurpe un autre alias ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-17",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "attendu.json de chaque dossier ; les mutants partagés avec TA-61 et TA-69 font disparaître K-7 et K-8 des échecs (it « TA-17 et TA-61 … », « TA-17 et TA-69 … »).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-17 et TA-61 (MN-17, MN-61) : invalide-t2-jeton-autre-manifeste (T-2), invalide-o2-preuve-autre-manifeste (O-2) et invalide-k7-jeton-autre-empreinte (K-7, par T-2 sur checkpoint_hash) échouent ; mutants qui ne comparent plus l'empreinte recalculée : ils passent (tués)"
        },
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-17 et TA-69 (MN-17, MN-69) : invalide-r6-entete-modifie, invalide-r7-recu-falsifie, invalide-r9-cloture-autre-periode, invalide-r11-ancre-de-periode et invalide-k8-empreinte échouent chacun à la vérification nommée ; un mutant par vérification la pose réussie : elle disparaît des échecs (tués)"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : dossiers complets de spec/vecteurs/ct-6 par la ligne de commande",
          "it": "chaque dossier rend le code, les vérifications en échec, les statuts, les non-exécutions, les avertissements, l'énoncé et la borne de son attendu.json (V-1 à V-5)"
        }
      ]
    },
    "response_removed": {
      "what": "Points de contrôle contresignés et ancrés (CT-2 EX-12.24, CT-1 §10.9, CT-5 EX-4.3) ; K-7 à K-9 au vérificateur (CT-6 §5.4)",
      "how": "Ne plus comparer l'empreinte recalculée du point (T-2 sur checkpoint_hash dans horodatage.mjs : K-7 n'échoue plus) ou ne plus poser K-8 en échec (verificateur.mjs) : l'ancre du point n'est plus vérifiée ; mutants de TA-61 et TA-69, partagés",
      "where": "scripts/lib/verificateur.mjs, horodatage.mjs"
    },
    "attack": "Dossiers invalide-k7-jeton-autre-empreinte et invalide-k8-empreinte de ct-6 : l'ancre du point couvre une autre empreinte, comme après réécriture et nouvelle signature des événements couverts.",
    "expected_with_response": "K-7 ou K-8 échoue, le dossier est invalide (code 1).",
    "expected_without_response": "Le dossier réécrit passe ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-18",
    "preconditions": [
      "Démonstration de référence de CT-2 §19 (docker compose : agent, enregistreur, serveur d'outils HTTP, simulateur de modèle) construite et lancée ; phase 2, étape 8.",
      "Compteur de requêtes par clé exposé par le simulateur (CT-2 §19.3)."
    ],
    "steps": [
      "Jouer la séquence de 19.2 ; relever n événements et n requêtes.",
      "Envoyer une requête directe au simulateur avec la clé de la passerelle.",
      "Exécuter le rapprochement."
    ],
    "oracle": "Écart de 1 rapporté avec la clé et la route ; aucun écart sans la requête directe. RA-16 borne ce que le rapprochement ne voit pas.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Démonstration de référence et tests de bout en bout : phase 2, étape 8."
    },
    "response_removed": {
      "what": "Rapprochement de l'usage des fournisseurs, clé par clé (CT-7 EX-3.8)",
      "how": "Ne pas exécuter le rapprochement",
      "where": "procédure du client (CT-7 EX-3.8) ; outil de rapprochement de la démonstration"
    },
    "attack": "Dans la démonstration, un échange de modèle envoyé au simulateur avec la clé de la passerelle, mais hors de l'enregistreur (processus de test).",
    "expected_with_response": "Le compte de requêtes déclaré par le simulateur pour la clé excède d'une unité le nombre d'événements noortrace.modele.echange de la route ; l'écart est rapporté.",
    "expected_without_response": "L'écart passe inaperçu ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-19",
    "preconditions": [
      "Deux démons réels `bin/noortrace --config` (étape 4), instances inst-a et inst-b, sur le même storage.root et le même magasin de bail `file` de l'installation rapide, et le mutant du paquet (EX-10.5) ; configuration des tests adversariaux du démon."
    ],
    "steps": [
      "Démarrer A ; faire écrire A ; démarrer B (passif) ; couper A de son bail en tuant l'auxiliaire flock(1) qui tient le verrou (instance isolée, 13.4 pas 2) ; attendre que B prenne le bail ; faire écrire B puis A.",
      "Relire les segments et le journal d'exploitation de A.",
      "Fabriquer le mutant (bail `file` toujours tenu pour valide) et rejouer."
    ],
    "oracle": "B prend le bail avec l'époque 2 et écrit ; l'écriture de A est refusée (-31010) et lease_lost consigné ; aucun événement de A après l'époque de B ; relecture des segments sans fourche (seq et prev_hash continus, aucun seq en double) ; avec le mutant, A écrit après l'époque de B et la chaîne fourche.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables sur le démon de l'étape 4 (mutants du paquet @noortrace/enregistreur, CT-7 EX-3.2)",
          "it": "TA-19 (MN-19) : deux démons sur le même journal et le même bail file : A écrit, perd son verrou (flock(1) tué), B prend le bail (époque 2) ; A, appelé, refuse (-31010, lease_lost) ; aucun événement de A après l'époque de B, chaîne sans fourche ; mutant dont le bail file se dit toujours valide : A écrit, fourche (tué)"
        }
      ]
    },
    "response_removed": {
      "what": "Bail, époque, jeton de clôture vérifié par le stockage, contrôle après écriture (CT-2 EX-13.1, EX-13.4 à EX-13.6, EX-13.10)",
      "how": "Faire tenir le bail `file` pour toujours valide (valide() rend vrai) : l'écrivain ne constate plus la perte du verrou (EX-13.6) et ajoute au segment déjà ouvert, que le jeton de clôture d'EX-13.5 (1) ne contrôle qu'à l'ouverture",
      "where": "paquets/enregistreur/src/bail.mjs (MagasinBailFichier.valide)"
    },
    "attack": "Deux démons sur le même journal ; le second acquiert le bail avec une époque supérieure après la perte du verrou du premier ; le premier tente une écriture.",
    "expected_with_response": "L'écriture du premier est refusée (-31010, lease_lost) ; une seule suite existe.",
    "expected_without_response": "Les deux écrivent : fourche ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-20",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "Nombre d'événements, drapeau tronque et corrompu nul comparés entre référence et mutant.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-20 (MN-20) : evenements/journal-demo/segment.ndjson privé de sa fin de ligne finale : la relecture tronque à la dernière ligne complète (tronque vrai) ; mutant qui lit une ligne non terminée : il l'accepte (tué)"
        }
      ]
    },
    "response_removed": {
      "what": "Relecture et troncature d'une fin incomplète ; mode dégradé stockage (CT-2 EX-12.8, EX-12.10, EX-12.11)",
      "how": "Faire lire une dernière ligne sans fin de ligne comme une ligne complète",
      "where": "scripts/lib/capture.mjs (relireSegment)"
    },
    "attack": "Segment journal-demo privé de son dernier octet de fin de ligne (écriture interrompue).",
    "expected_with_response": "relireSegment rend tronque = vrai et n − 1 événements : la ligne non durable est écartée.",
    "expected_without_response": "La ligne non terminée est acceptée (n événements, tronque faux) ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-21",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "ErreurModeDegrade raison horloge pour la référence ; ts fausse scellée pour le mutant. La partie CT-5 (genTime contre l'horloge locale) est TA-60.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-21 (MN-21) : l'écrivain bloque (mode dégradé horloge) un recul au-delà de max_backstep_ms et un saut en avant au-delà de max_forward_ms mesuré contre l'horloge monotone ; mutant sans ces deux contrôles : les événements sont scellés à la date fausse (tué)"
        },
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : construction des événements, écrivain, segment, intention, reprise (§7, §9, §12)",
          "it": "ts = max(lu, précédent) sous le seuil ; mode dégradé horloge au-delà ; exception de l'événement en attente (EX-7.9, EX-14.10)"
        },
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : construction des événements, écrivain, segment, intention, reprise (§7, §9, §12)",
          "it": "saut de l'horloge murale en avant au-delà de max_forward_ms, mesuré contre l'horloge monotone : mode dégradé horloge (EX-7.13)"
        }
      ]
    },
    "response_removed": {
      "what": "ts non décroissant et blocage sur saut en avant (CT-2 EX-7.10, EX-7.13 ; CT-1 §5.2)",
      "how": "Retirer les deux contrôles de l'horloge de l'écrivain",
      "where": "scripts/lib/capture.mjs (Ecrivain.horodater)"
    },
    "attack": "Recul de l'horloge murale au-delà de max_backstep_ms ; saut en avant de 3 min contre 1 s d'horloge monotone.",
    "expected_with_response": "Mode dégradé « horloge » dans les deux cas : aucun événement scellé à la date fausse.",
    "expected_without_response": "Les événements sont scellés à la date reculée ou sautée ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-22",
    "preconditions": [
      "Démonstration de référence de CT-2 §19 (docker compose : agent, enregistreur, serveur d'outils HTTP, simulateur de modèle) construite et lancée ; phase 2, étape 8."
    ],
    "steps": [
      "Exécuter dans le conteneur de l'agent un listage du chemin de storage.root.",
      "Rejouer après ajout du volume dans la composition."
    ],
    "oracle": "Code de retour non nul (chemin absent) avec la composition de référence ; listage réussi avec le volume monté.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Démonstration de référence et tests de bout en bout : phase 2, étape 8."
    },
    "response_removed": {
      "what": "Aucun droit de l'hôte ni de l'agent sur storage.root (CT-2 EX-3.2, EX-18.5)",
      "how": "Monter le volume du journal dans le conteneur de l'agent",
      "where": "deploiement (volumes de la démonstration)"
    },
    "attack": "Depuis le conteneur de l'agent, lister storage.root et ouvrir un segment.",
    "expected_with_response": "Le chemin n'existe pas dans le conteneur de l'agent ; aucune lecture possible.",
    "expected_without_response": "Le listage réussit ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-23",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur le vecteur publié (test cité).",
      "Régénérer les vecteurs par le générateur nommé et comparer au dépôt (git diff --exit-code en CI) : la réponse retirée dans le générateur changerait le vecteur et la comparaison échouerait."
    ],
    "oracle": "Oracle sur le vecteur evenements/journal-demo/evenements.json (ordre des seq) ; le mutant est un changement de générateur, observé par git diff --exit-code en CI.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-23 (MN-23, oracle sur le vecteur) : evenements/journal-demo : chaque version de politique employée est annoncée par un événement noortrace.journal.politique de seq inférieur à son premier usage ; la réponse retirée serait un générateur qui n'émet plus cet événement, et le vecteur régénéré différerait (CI : git diff)"
        },
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : vecteurs spec/vecteurs/ct-2, rejoués",
          "it": "evenements/journal-demo : chaîne, attendus, pièces, politique, intention, segment ; arguments de seq 7 = pieces-mcp"
        }
      ]
    },
    "response_removed": {
      "what": "Toute version de politique annoncée dans la chaîne avant usage (CT-2 EX-9.1, EX-9.2, EX-8.11)",
      "how": "Faire taire l'événement noortrace.journal.politique du générateur de journal-demo",
      "where": "générateur scripts/vecteurs/generer-ct2.mjs (le vecteur régénéré diffère : git diff en CI)"
    },
    "attack": "Rechargement d'une politique sans annonce.",
    "expected_with_response": "Chaque policy_version employée est annoncée par un événement de politique de seq inférieur ou égal à son premier usage.",
    "expected_without_response": "Le vecteur journal-demo ne porte plus l'annonce ; la régénération diffère du dépôt ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-24",
    "preconditions": [
      "Coffre des originaux du démon (CT-2 EX-10.22 ; `CoffreOriginaux` de paquets/enregistreur/src/coffre.mjs, étape 4) et son mutant (copie du paquet, EX-10.5). Outil de lecture : `dechiffrer`, qui reçoit les identités de l'appelant (lecture 26 du LISEZMOI du paquet) ; aucune commande d'exploitation n'est livrée."
    ],
    "steps": [
      "Déposer un original chiffré ; demander un déchiffrement avec la seule demande ; puis avec une approbation de la même identité ; puis avec une seconde identité autorisée.",
      "Lire le registre des accès, hors du coffre ; rejouer sur le mutant du paquet."
    ],
    "oracle": "Deux refus (seconde_approbation_absente, approbateur_identique_au_demandeur), un succès qui rend l'original, trois lignes du registre ; avec le mutant, l'original est rendu au demandeur seul.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables sur le démon de l'étape 4 (mutants du paquet @noortrace/enregistreur, CT-7 EX-3.2)",
          "it": "TA-24 (MN-24) : coffre des originaux à clé propre (CoffreOriginaux.dechiffrer du paquet) : demande seule, puis approbation de la même identité, puis d'une seconde identité autorisée : deux refus, un succès, trois lignes au registre des accès ; mutant sans seconde approbation : l'original est rendu au demandeur seul (tué)"
        }
      ]
    },
    "response_removed": {
      "what": "Coffre chiffré à clé propre ; déchiffrement à deux personnes consigné (CT-2 EX-10.22, CT-7 EX-3.11)",
      "how": "Retirer l'exigence d'une seconde approbation (les quatre conditions sur l'approbation deviennent false)",
      "where": "paquets/enregistreur/src/coffre.mjs (CoffreOriginaux.dechiffrer)"
    },
    "attack": "Demande de déchiffrement d'un original par une seule identité, puis avec l'approbation de la même identité.",
    "expected_with_response": "Refus dans les deux cas ; déchiffrement seulement avec une seconde approbation d'une identité distincte ; ligne du registre des accès.",
    "expected_without_response": "Déchiffrement obtenu seul ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-25",
    "preconditions": [
      "Images construites de façon reproductible (CT-8 §3.6, phase 2, étape 7) ; empreintes publiées."
    ],
    "steps": [
      "Lancer l'image publiée ; lire la ligne startup.",
      "Lancer l'image modifiée ; comparer."
    ],
    "oracle": "Empreinte consignée égale à la publiée pour la première ; écart signalé pour la seconde.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Paquets, observabilité et runbooks non construits : phase 2, étape 7."
    },
    "response_removed": {
      "what": "Surfaces d'écoute exhaustives, moindre privilège (CT-2 EX-18.1, EX-18.2, EX-18.4, EX-18.7) ; version et empreinte de l'image consignées (EX-18.6, CT-7 EX-3.14)",
      "how": "Retirer la comparaison de l'empreinte de l'image à la version publiée",
      "where": "démarrage du démon (PA-4) ; procédure CT-7 EX-3.14"
    },
    "attack": "Image reconstruite localement avec un octet modifié, lancée à la place de la version publiée.",
    "expected_with_response": "Le démarrage consigne l'empreinte de l'image et code.recorder ; la comparaison à la version publiée signale l'écart.",
    "expected_without_response": "L'image modifiée tourne sans signal ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-26",
    "preconditions": [
      "Démon réel `bin/noortrace --config` du paquet `paquets/enregistreur` (étape 4) et son mutant (copie du paquet, EX-10.5) ; configuration de développement tirée de l'exemple de CT-2 §15.3 (classe D, magasin de bail `file`, frontal MCP en Streamable HTTP à jetons statiques, serveur d'outils stdio de test `test/fixtures/enregistreur-adversarial/serveur-outils.mjs`, service d'approbation simulé joint en HTTP).",
      "checkpoint_interval_s = 10 ; série des points lue par constaterCadence de scripts/lib/ancrage.mjs (CT-5 AN-2)."
    ],
    "steps": [
      "Démarrer le démon, attendre un point, l'arrêter puis le relancer ; attendre deux points ; lire le journal d'exploitation et la chaîne.",
      "Lire la série des points qui chevauche le redémarrage (constaterCadence, CT-5 AN-2) ; rejouer sur le mutant du paquet."
    ],
    "oracle": "Ligne startup du redémarrage présente avec l'époque du nouveau bail (2 ; EX-17.2 ne met `instance_id` dans `data` que dans un déploiement à plusieurs instances, celui-ci n'en a qu'une) ; la série des points qui chevauche le redémarrage ne porte aucun trou supérieur à c_K + 1 s (preuve de vie) ; la trace ct-5/planification/redemarrage-reprise.json couvre déjà la reprise du planificateur (TA-64) ; avec le mutant, aucune ligne startup. La partie « annonce de reprise » dépend de PA-1 (CT-7) : non applicable tant que CT-2 ne l'a pas adoptée (section 14).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables sur le démon de l'étape 4 (mutants du paquet @noortrace/enregistreur, CT-7 EX-3.2)",
          "it": "TA-26 (MN-26, partie non conditionnée par PA-1) : démon réel, points de contrôle toutes les 10 s : arrêt puis redémarrage ; la ligne startup du redémarrage est écrite avec l'époque du nouveau bail, et la série des points qui chevauche le redémarrage n'a aucun trou supérieur à c_K + 1 s (constaterCadence, CT-5 AN-2) ; mutant sans la ligne startup : aucune ligne au redémarrage (tué)"
        }
      ],
      "depends_on": [
        "PA-1"
      ]
    },
    "response_removed": {
      "what": "Points de contrôle à chaque instant aligné (preuve de vie, CT-2 EX-12.24) ; lignes startup, lease_acquired, lease_lost (EX-17.2) ; annonce de reprise (CT-7 PA-1)",
      "how": "Retirer la ligne startup du journal d'exploitation (l'appel devient vide)",
      "where": "paquets/enregistreur/src/coeur.mjs (pas 7 du démarrage) ; émission des points aux instants alignés (CT-2 EX-12.24)"
    },
    "attack": "Arrêt puis redémarrage du démon.",
    "expected_with_response": "Une ligne startup datée ; après adoption de PA-1, un événement d'annonce de reprise dans la chaîne.",
    "expected_without_response": "Aucune ligne ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-27",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "Verdicts des cas worm/etats.json ; le mutant rend conforme.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-27 (MN-27) : worm/etats.json s3-sans-mode et s3-mode-governance rendent non_conforme ; mutant sans le contrôle du mode de verrou : conforme (tué)"
        },
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : copies WORM et gel juridique (12.6, 12.11, EX-12.29 à EX-12.41)",
          "it": "worm/*.json : chaque fichier valide contre worm-v0, chaque cas rejoué par worm.mjs à l'identique"
        }
      ]
    },
    "response_removed": {
      "what": "Rétention par défaut en mode Compliance, contrôle du verrou (CT-2 EX-12.30, EX-12.32, EX-12.33)",
      "how": "Retirer le contrôle du mode de verrou (mode_absent, mode_non_conforme)",
      "where": "scripts/lib/worm.mjs (etatVerrou)"
    },
    "attack": "Versions lues sans mode de verrou (s3-sans-mode) ou en mode Governance (s3-mode-governance).",
    "expected_with_response": "Verdict non_conforme avec la raison attendue.",
    "expected_without_response": "Verdict conforme ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-28",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "Résultat de verifierGarde comparé à l'attendu ; le mutant rend valid.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-28 (MN-28) : worm/gardes.json meme-identite : une levée accordée par l'identité qui l'a demandée est refusée ; mutant sans la règle de garde : valide (tué)"
        },
        {
          "file": "test/enregistreur-r05.test.js",
          "describe": "CT-2 révision 0.5 : copies WORM et gel juridique (12.6, 12.11, EX-12.29 à EX-12.41)",
          "it": "worm/*.json : chaque fichier valide contre worm-v0, chaque cas rejoué par worm.mjs à l'identique"
        }
      ]
    },
    "response_removed": {
      "what": "Règle de garde de la levée par deux personnes (CT-2 EX-12.37, EX-12.38)",
      "how": "Retirer la règle meme_identite",
      "where": "scripts/lib/worm.mjs (verifierGarde)"
    },
    "attack": "Cas worm/gardes.json meme-identite : levée accordée par l'identité qui l'a demandée.",
    "expected_with_response": "valid faux, erreur meme_identite.",
    "expected_without_response": "valid vrai ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-29",
    "preconditions": [
      "Démon de l'enregistreur construit (phase 2, étape 4), configuration de l'installation rapide (CT-8 §7.3).",
      "Supervision de CT-8 §10 livrée (phase 2, étape 7) ; horloge de test accélérable ou attente réelle."
    ],
    "steps": [
      "Fermer le support ; forcer la fermeture d'un segment ; attendre l'échéance.",
      "Lire la métrique et l'alerte."
    ],
    "oracle": "Métrique ≥ 1 et alerte levée à l'échéance ; retour à 0 après réouverture.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Paquets, observabilité et runbooks non construits : phase 2, étape 7."
    },
    "response_removed": {
      "what": "Copie de chaque segment fermé, comparaison horaire (CT-2 EX-12.16, EX-12.18, EX-17.5)",
      "how": "Retirer la comparaison horaire du fil de supervision",
      "where": "démon (fil de supervision) ; règles d'alerte de CT-8 §10"
    },
    "attack": "Support WORM rendu injoignable (point de terminaison fermé) pendant une heure et un segment fermé.",
    "expected_with_response": "noortrace_worm_copy_pending monte ; l'alerte « Copie WORM en retard » part après une heure.",
    "expected_without_response": "Aucune alerte ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-30",
    "preconditions": [
      "Démon `paquets/enregistreur` (étape 4) et son mutant (copie du paquet, EX-10.5) ; configuration modèle de production `deploiement/config/modele-production/configuration.json`."
    ],
    "steps": [
      "Charger la configuration modèle ; poser signer.class = D ; exécuter `noortrace validate-config` (pas 1 à 3 d'EX-15.4, contrôles du démarrage) avec recorder.environment = production, puis developpement.",
      "Vérifier qu'une erreur nomme /signer/class en production et aucune en developpement.",
      "Fabriquer le mutant (copie de paquets/enregistreur avec le remplacement nommé) et rejouer en production."
    ],
    "oracle": "Code 2 et erreur « /signer/class : classe D refusée en production (EX-11.8) » en production, aucune erreur sur /signer/class en developpement ; le mutant n'en rend aucune en production.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables sur le démon de l'étape 4 (mutants du paquet @noortrace/enregistreur, CT-7 EX-3.2)",
          "it": "TA-30 (MN-30) : configuration modèle de production (deploiement/config/modele-production) posée à signer.class = D : noortrace validate-config rend le code 2 et une erreur sur /signer/class en production, aucune en developpement ; mutant sans le refus de la classe D en production : aucune erreur sur /signer/class (tué)"
        }
      ]
    },
    "response_removed": {
      "what": "Classe D refusée en production (CT-2 EX-11.8) ; non-exportabilité, mémoire protégée (EX-11.5, EX-18.7)",
      "how": "Retirer le refus de signer.class = D quand recorder.environment = production (la condition devient false)",
      "where": "paquets/enregistreur/src/configuration.mjs (reglesHorsSchema)"
    },
    "attack": "Configuration de production (modèle deploiement/config/modele-production) avec signer.class = D.",
    "expected_with_response": "Les contrôles de démarrage refusent la configuration (code 2, erreur nommant /signer/class).",
    "expected_without_response": "Aucune erreur sur /signer/class : la validation laisserait démarrer le démon ; le test échoue.",
    "execution": "phase_2",
    "notes": "Au 2026-11-01, aucun contrôle de la classe de garde n'existait dans controlesConfiguration ni controlesConfigurationRevision05 de la bibliothèque de référence (PD-12) ; le démon de l'étape 4 code EX-11.8 (paquets/enregistreur/src/configuration.mjs et, au démarrage, signataires.mjs) : le test porte sur la validation du démon."
  },
  {
    "id": "TA-31",
    "preconditions": [
      "Backend de signature de test avec journal d'audit (phase 2, étape 4) ; outil de rapprochement."
    ],
    "steps": [
      "Produire n objets signés ; faire signer un objet hors écrivain par le même backend.",
      "Exécuter le rapprochement sur l'intervalle."
    ],
    "oracle": "Écart de 1 rapporté ; 0 sans la signature externe.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables sur le démon de l'étape 4 (mutants du paquet @noortrace/enregistreur, CT-7 EX-3.2)",
          "it": "TA-31 (MN-31) : Vault Transit à journal d'audit ; le démon produit n objets signés ; noortrace-ctl cle rapprocher sur l'intervalle : écart 0, code 0 ; une signature hors écrivain par le même backend et la même identité d'usage : écart 1, code 3 (incident, CT-7 4.6) ; mutant qui n'exécute plus la comparaison : écart 0 malgré la signature externe (tué)"
        }
      ]
    },
    "response_removed": {
      "what": "Rapprochement mensuel des appels de signature avec les objets signés (CT-7 EX-3.7) ; identité d'usage seule (CT-2 EX-11.4, EX-11.3)",
      "how": "Ne pas exécuter le rapprochement (l'écart rendu est toujours nul)",
      "where": "paquets/enregistreur/src/signataires/rapprochement.mjs (rapprocher) ; outil noortrace-ctl cle rapprocher"
    },
    "attack": "Journal d'audit d'un backend de test (service de signature de classe B : Vault Transit, audit file ; SoftHSM2 n'a pas de journal d'audit) qui compte une signature de plus que les objets signés sur l'intervalle.",
    "expected_with_response": "Le rapprochement rend un écart de +1 : incident de compromission (CT-7 §4.6).",
    "expected_without_response": "L'écart passe ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-32",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "failed contient CR-2 ; le mutant ne la contient plus.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-32 (MN-32) : invalide-cr2-un-seul-participant échoue à CR-2 ; mutant securite.mjs sans aucune faute CR-2 : CR-2 disparaît des échecs (tué)"
        },
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : vecteurs ceremonies/ (annexe A.4, EX-A.6, EX-A.19)",
          "it": "verifierCeremonie rend exactement attendu.json pour chaque cas ; chaque cas invalide échoue à la vérification que son nom annonce"
        }
      ]
    },
    "response_removed": {
      "what": "Cérémonie à deux personnes au moins pour toute opération d'administration (CT-7 EX-5.1, EX-5.2) ; CR-2",
      "how": "Neutraliser toutes les fautes CR-2 (participants)",
      "where": "scripts/lib/securite.mjs (verifierCeremonie)"
    },
    "attack": "Procès-verbal invalide-cr2-un-seul-participant.",
    "expected_with_response": "CR-2 en échec, verdict invalide.",
    "expected_without_response": "CR-2 réussit ; le test échoue (le verdict reste invalide par CR-4, ce que le test ne compte pas comme réponse).",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-33",
    "preconditions": [
      "Démon de l'enregistreur construit (phase 2, étape 4) ; configuration de l'installation rapide (CT-8 §7.3) modifiée pour le test : `policy.approval.mode` = `erreur` et `policy.version` sans suffixe `-observation` (CT-2 EX-15.8), parce qu'en mode observation, celui de la configuration rapide, un appel est relayé dans tout mode dégradé et `-31010` de raison `cle` n'est jamais rendu (CT-2 EX-14.16, EX-14.17 : seul `-31010` de raison `bail_non_detenu` l'est).",
      "Signataire de classe A ou B (CT-2 §11.2 ; EX-11.18 : signataire hors du démon) sur un backend de test arrêtable (par exemple un service de signature de classe B comme le `vault-transit` de CT-8 §8), à la place de la classe D de la configuration rapide (fichier `/run/secrets/cle-enregistreur`, fonction du démon sur la graine en mémoire : rien à arrêter)."
    ],
    "steps": [
      "Arrêter le backend ; appeler un outil ; lire la réponse de l'hôte, le journal d'exploitation et le segment."
    ],
    "oracle": "Code `-31010` de raison `cle` rendu à l'hôte (CT-2 §14.2) ; alerte : la condition de CT-2 §17.4 observée sur la jauge `noortrace_degraded{reason=\"cle\"}` == 1 pendant plus de 60 s et, si un collecteur est présent, la règle `noortrace_mode_degrade_critique` de CT-8 §10.4 en état déclenché (le collecteur n'est pas une précondition de TA-33 ; il l'est de TE-17) ; aucun nouvel événement dans le segment pendant la panne. L'oracle ne lit pas `/healthz` : CT-2 EX-14.11 et EX-17.1 divergent sur son état en mode « clé » (PD-30) ; un test qui admet les deux états est conforme.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables sur le démon de l'étape 4 (mutants du paquet @noortrace/enregistreur, CT-7 EX-3.2)",
          "it": "TA-33 (MN-33) : installation rapide modifiée (mode erreur, version sans -observation, signataire vault-transit) ; backend arrêté sans reprise : -31010 de raison cle rendu à l'hôte, jauge noortrace_degraded de raison cle à 1 plus de 60 s, aucun nouvel événement dans le segment ; mutant où l'écrivain continue sans signature : un événement est écrit pendant la panne (tué)"
        }
      ]
    },
    "response_removed": {
      "what": "Mode dégradé « clé » bloquant sur signataire injoignable sans reprise (CT-2 §17.4) ; rupture de journal (EX-11.16)",
      "how": "Faire continuer l'écrivain sans signature (signature nulle quand le signataire échoue, health() sans effet)",
      "where": "paquets/enregistreur/src/ecrivain.mjs (signature de l'événement) ; paquets/enregistreur/src/coeur.mjs (_santeSignataire)"
    },
    "attack": "Backend de signature arrêté pendant la capture.",
    "expected_with_response": "Le démon passe en mode dégradé « clé » : -31010 rendu à l'hôte, alerte critique, aucun événement non signé.",
    "expected_without_response": "Des événements sans signature valide sont écrits ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-34",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "attendu.json ; mutant sans R-10 dans failed_checks.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-34 (MN-34) : invalide-r10-inscription-cle-inconnue échoue à R-10 ; mutant qui pose R-10 réussie : R-10 disparaît des échecs (tué)"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : dossiers complets de spec/vecteurs/ct-6 par la ligne de commande",
          "it": "chaque dossier rend le code, les vérifications en échec, les statuts, les non-exécutions, les avertissements, l'énoncé et la borne de son attendu.json (V-1 à V-5)"
        }
      ]
    },
    "response_removed": {
      "what": "Le contrôle 8 écarte les ancres d'une clé révoquée ou non inscrite pour la clé du manifeste (CT-6 R-10) ; provision bornée (CT-4 EX-4.20, EX-8.18)",
      "how": "Poser R-10 réussie",
      "where": "scripts/lib/registre.mjs"
    },
    "attack": "Dossier invalide-r10-inscription-cle-inconnue : émetteur de l'ancre sans inscription pour la clé du manifeste.",
    "expected_with_response": "R-10 en échec, code 1.",
    "expected_without_response": "R-10 absente des échecs ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-35",
    "preconditions": [
      "console/ du dépôt ; Chromium et Playwright pour la partie dynamique (CT-3 EX-13.36)."
    ],
    "steps": [
      "Lire statiquement console/*.js et index.html : aucune occurrence de type=\"file\", de fichiers-cle ni de keystore.",
      "Dans Chromium, compter les éléments input[type=file] : zéro."
    ],
    "oracle": "Zéro occurrence et zéro élément ; le test existant couvre « sans autre méthode de signature ».",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Possible dès maintenant sur les vecteurs et les bibliothèques du dépôt ; non écrit dans ce lot ; dû au plus tard à l'étape 8 (tests adversariaux)."
    },
    "response_removed": {
      "what": "La clé de l'approbateur naît chez lui ; parcours par fichier seulement permis, absent de la page de référence (CT-3 EX-3.4, EX-13.1, EX-13.28, EX-13.31)",
      "how": "Ajouter à la page de référence un champ de fichier de clé",
      "where": "console/ (page de référence)"
    },
    "attack": "Un déploiement de la console livre une page qui propose d'importer un fichier de clé chiffré.",
    "expected_with_response": "La page de référence ne contient ni champ de fichier (type=\"file\"), ni appel à la bibliothèque des fichiers-cle, ni chaîne « keystore » ; le test Chromium ne trouve aucun tel élément.",
    "expected_without_response": "Le parcours apparaît ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-36",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "failed contient CR-2 ; le mutant non.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-36 (MN-36) : invalide-cr2-adresse-en-double échoue à CR-2 ; mutant sans la règle « adresses de participants en double » : CR-2 passe (tué)"
        },
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : vecteurs ceremonies/ (annexe A.4, EX-A.6, EX-A.19)",
          "it": "verifierCeremonie rend exactement attendu.json pour chaque cas ; chaque cas invalide échoue à la vérification que son nom annonce"
        }
      ]
    },
    "response_removed": {
      "what": "« Une personne, une clé » (CT-3 EX-8.11, EX-13.10 ; CT-4 EX-7.8) ; CR-8, CR-11, CR-2 adresses distinctes",
      "how": "Retirer la règle CR-2 des adresses en double",
      "where": "scripts/lib/securite.mjs"
    },
    "attack": "Procès-verbal invalide-cr2-adresse-en-double : deux membres déclarent la même adresse.",
    "expected_with_response": "CR-2 en échec.",
    "expected_without_response": "CR-2 réussit ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-37",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "failed contient CR-6 ; le mutant non ; la table CLASSES_ADMISES_PRODUCTION.gouvernance exclut D.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-37 et TA-42 (MN-37, MN-42) : invalide-cr6-classe-d-en-production échoue à CR-6 ; la table CLASSES_ADMISES_PRODUCTION exclut D pour gouvernance et tsa_interne ; mutant sans la règle de classe en production : CR-6 passe (tué)"
        },
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : vecteurs ceremonies/ (annexe A.4, EX-A.6, EX-A.19)",
          "it": "verifierCeremonie rend exactement attendu.json pour chaque cas ; chaque cas invalide échoue à la vérification que son nom annonce"
        }
      ]
    },
    "response_removed": {
      "what": "Clé de gouvernance en classe A à C, jamais D (CT-4 EX-8.21, CT-7 EX-4.2) ; CR-6",
      "how": "Retirer la règle de classe en production",
      "where": "scripts/lib/securite.mjs"
    },
    "attack": "Procès-verbal invalide-cr6-classe-d-en-production.",
    "expected_with_response": "CR-6 en échec.",
    "expected_without_response": "CR-6 réussit ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-38",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "Égalité pas à pas ; le mutant diverge au pas 10 (expiration « jeu reassigne »).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-38 (MN-38) : tickets/jeu-reassigne.json : le ticket expire avec la raison « jeu reassigne » ; mutant qui ne marque plus la réassignation : la trace diverge au pas 10 (tué)"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : tickets (section 7, TK-1 à TK-13)",
          "it": "chaque trace rejouée sur un service vide redonne chaque attendu, pas à pas (EX-7.9, EX-A.6)"
        }
      ]
    },
    "response_removed": {
      "what": "Jeu épinglé par la politique (CT-3 EX-8.1, EX-8.6) ; garde matérielle de la clé de l'exploitant (CT-4 EX-5.4)",
      "how": "Ne plus marquer la réassignation du jeu",
      "where": "scripts/lib/approbation.mjs (lecture du jeu)"
    },
    "attack": "Trace tickets/jeu-reassigne.json : le registre désigne un autre jeu pendant la vérification.",
    "expected_with_response": "Lecture illisible (jeu_non_attendu), vote hors_jeu refusé, ticket expiré avec la raison « jeu reassigne ».",
    "expected_without_response": "La trace diverge (raison d'expiration différente) ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-39",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "failed contient CR-7 ; SAUVEGARDE_PAR_USAGE.validateur = aucune ; le mutant passe. Un cas de vecteur « validateur avec sauvegarde » est proposé (PD-9).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-39 (MN-39) : invalide-cr7-sauvegarde-enregistreur échoue à CR-7 ; SAUVEGARDE_PAR_USAGE.validateur vaut aucune ; mutant sans la règle « aucune sauvegarde » : CR-7 passe (tué)"
        },
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : vecteurs ceremonies/ (annexe A.4, EX-A.6, EX-A.19)",
          "it": "verifierCeremonie rend exactement attendu.json pour chaque cas ; chaque cas invalide échoue à la vérification que son nom annonce"
        }
      ]
    },
    "response_removed": {
      "what": "Aucune sauvegarde ni réplication de la clé de validateur (CT-4 EX-10.7, EX-10.9 ; CT-7 EX-4.4) ; CR-7",
      "how": "Retirer la règle « aucune sauvegarde » de CR-7",
      "where": "scripts/lib/securite.mjs"
    },
    "attack": "Procès-verbal invalide-cr7-sauvegarde-enregistreur (clé d'enregistreur avec sauvegarde) ; la table SAUVEGARDE_PAR_USAGE donne la même règle pour validateur.",
    "expected_with_response": "CR-7 en échec.",
    "expected_without_response": "CR-7 réussit ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-40",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "attendreRefus avec check OP-5 dans le test existant ; le mutant de l'outil est le complément (étape 8).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — outil de référence sur le réseau Hardhat en mémoire (31337, --sans-capture)",
          "it": "révocation, administration du jeu, réassignation et approvisionnement"
        }
      ],
      "complement": {
        "phase2_step": 8,
        "blocking": "Mutant de l'outil scripts/registre/noortrace-registre.mjs (contrôle du destinataire d'approvisionner, OP-5) à ajouter à test/adversarial.test.js ; possible dès maintenant (fabrique étendue à scripts/registre, EX-10.5), dû au plus tard à l'étape 8."
      }
    },
    "response_removed": {
      "what": "Destinataires admis et plafond quotidien de l'approvisionnement (CT-4 EX-8.20)",
      "how": "Retirer le contrôle du destinataire dans l'outil de référence (approvisionner)",
      "where": "scripts/registre/noortrace-registre.mjs"
    },
    "attack": "approvisionner --vers une adresse aléatoire hors d'EX-8.20 (test existant, Hardhat en mémoire).",
    "expected_with_response": "Refus OP-5 ; aucune transaction.",
    "expected_without_response": "Transfert envoyé ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-41",
    "preconditions": [
      "Composant de la phase 2 qui résout des références de secrets (enregistreur, étape 4 ; composant d'ancrage, étape 5 ; CT-5 EX-4.8, AN-43) ; prestataire RFC 3161 de test exigeant une authentification ; configuration dont `providers[principal].auth` porte une référence de secret (`env`, `file` ou `vault`) dont la valeur résolue est une chaîne marqueur injectée par le test."
    ],
    "steps": [
      "Démarrer le composant ; laisser partir une requête RFC 3161 authentifiée vers le prestataire de test.",
      "Relire la file durable, les traces et le journal d'exploitation ; chercher la chaîne marqueur.",
      "Mutant : un `journaliser` ou une mise en file qui recopie la valeur résolue du secret."
    ],
    "oracle": "Le marqueur n'apparaît dans aucun fichier (file, traces, journal) ; le mutant l'y fait apparaître et le test échoue. Le planificateur de référence ne manipule aucun secret en version 0 (la projection `planificateur-ancrage-v0` exclut les secrets) : il n'y a rien à retirer aujourd'hui ; l'hygiène des vecteurs `ct-5` est TV-44.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 5,
      "blocking": "Le test porte sur une requête RFC 3161 authentifiée vers un prestataire (providers[principal].auth, CT-5 EX-4.8, AN-43) : seul le composant d'ancrage de l'étape 5 en émet ; le démon de l'étape 4 résout ses propres références de secrets mais ne parle à aucun prestataire d'horodatage. La version 0.1 rattachait à tort l'entrée à l'étape 4."
    },
    "response_removed": {
      "what": "Secrets par référence, jamais dans la file, les traces ni le journal (CT-5 EX-4.8, AN-43)",
      "how": "Journaliser ou mettre en file la valeur résolue d'une référence de secret au lieu de la référence",
      "where": "composant de la phase 2 qui résout les références de secrets (enregistreur, étape 4 ; composant d'ancrage, étape 5)"
    },
    "attack": "Un planificateur qui consigne la valeur de l'identifiant d'accès au prestataire dans la file, une trace ou le journal.",
    "expected_with_response": "Aucun fichier ne contient la valeur du secret : seule la référence (`env`, `file`, `vault`) y figure.",
    "expected_without_response": "La valeur marqueur apparaît dans la file ou le journal ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-42",
    "preconditions": [
      "Cas de vecteur « invalide-cr6-tsa-interne-classe-d » à ajouter (PD-9) ; d'ici là, le mutant est tué sur invalide-cr6-classe-d-en-production et la table est vérifiée."
    ],
    "steps": [
      "Ajouter le cas au générateur generer-ct7.mjs ; rejouer sec272."
    ],
    "oracle": "CLASSES_ADMISES_PRODUCTION.tsa_interne exclut D ; failed contient CR-6 sur le cas.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-37 et TA-42 (MN-37, MN-42) : invalide-cr6-classe-d-en-production échoue à CR-6 ; la table CLASSES_ADMISES_PRODUCTION exclut D pour gouvernance et tsa_interne ; mutant sans la règle de classe en production : CR-6 passe (tué)"
        },
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : vecteurs ceremonies/ (annexe A.4, EX-A.6, EX-A.19)",
          "it": "verifierCeremonie rend exactement attendu.json pour chaque cas ; chaque cas invalide échoue à la vérification que son nom annonce"
        }
      ],
      "complement": {
        "phase2_step": 8,
        "blocking": "Partie à écrire : Possible dès maintenant sur les vecteurs et les bibliothèques du dépôt ; non écrit dans ce lot ; dû au plus tard à l'étape 8 (tests adversariaux)."
      }
    },
    "response_removed": {
      "what": "Clé du serveur RFC 3161 interne hors de l'hôte, classe A à C (CT-5 EX-7.3) ; CR-6",
      "how": "Retirer la règle de classe en production",
      "where": "scripts/lib/securite.mjs"
    },
    "attack": "Procès-verbal de création d'une clé tsa_interne en classe D pour la production.",
    "expected_with_response": "CR-6 en échec.",
    "expected_without_response": "CR-6 réussit ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-43",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Partie dépôt à écrire : vérifier que le journal d'exploitation des vecteurs ne porte aucune valeur de secret (EX-17.3) ; partie phase 2 : même oracle sur le journal du démon."
    ],
    "oracle": "Erreur de schéma présente, absente avec le schéma mutant.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-43 (MN-43, partie exécutable) : le schéma refuse une valeur littérale là où une référence de secret est attendue (model.static_tokens[0].token) ; schéma mutant dont la définition secret_reference admet n'importe quelle forme : accepté (tué)"
        }
      ],
      "complement": {
        "phase2_step": 8,
        "blocking": "Partie à écrire : Possible dès maintenant sur les vecteurs et les bibliothèques du dépôt ; non écrit dans ce lot ; dû au plus tard à l'étape 8 (tests adversariaux)."
      }
    },
    "response_removed": {
      "what": "Références de secrets, fichiers 0400, jamais écrits ni journalisés (CT-2 EX-15.3, EX-18.4, EX-17.3)",
      "how": "Admettre n'importe quelle forme pour secret_reference dans le schéma",
      "where": "spec/schemas/configuration-enregistreur-v0.schema.json ($defs/secret_reference) ; démon (EX-17.3) en phase 2"
    },
    "attack": "Configuration où model.static_tokens[0].token est une chaîne littérale.",
    "expected_with_response": "Le schéma refuse /model/static_tokens/0/token.",
    "expected_without_response": "Accepté ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-44",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "result et reason égaux à expected ; divergence du mutant.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-44 (MN-44) : decisions/ : les remises à signature invalide (SG-5) ou à approbateur hors du jeu (SG-6) sont refusées ; mutants sans SG-5 ou sans SG-6 : au moins une de ces remises est scellée ou refusée pour une autre raison (tués)"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : remises et signatures (section 9, SG-1 à SG-7, annexe A.7 et A.8)",
          "it": "decisions/ : chaque remise reçoit le résultat et la raison attendus, dans l'ordre de SG-1 à SG-7"
        }
      ]
    },
    "response_removed": {
      "what": "Vérification de toute remise par le noyau : SG-5 signatures, SG-6 jeu (CT-2 EX-7.5 ; CT-3 SG-5, SG-6)",
      "how": "Retirer SG-5 (signature invalide) ou SG-6 (approbateur hors jeu)",
      "where": "scripts/lib/approbation.mjs (verifierRemise)"
    },
    "attack": "Remises decisions/invalides à signature invalide ou à approbateur hors du jeu remis.",
    "expected_with_response": "Refus avec la raison attendue.",
    "expected_without_response": "Au moins une remise est scellée ou refusée pour une autre raison ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-45",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "outcome du cas ; le mutant accepte.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-45 (MN-45) : console/reponses : une réponse du portefeuille qui ne recouvre pas l'adresse de l'approbateur sur le D_A de la console n'aboutit à aucun vote (adresse_differente) ; mutant sans la comparaison : accepte (tué)"
        },
        {
          "file": "test/console.test.js",
          "describe": "CT-3 0.3 : console/ rejoué par console.mjs (CS-1 à CS-9)",
          "it": "CS-6, CS-7 (EX-9.21, EX-13.29, EX-12.16) : reponses/ — verdict, signature normalisée, adresse recouvrée et vote construit"
        }
      ]
    },
    "response_removed": {
      "what": "Console qui recalcule D_A et recouvre l'adresse sur son propre condensé (CT-3 EX-9.6, EX-9.17, EX-9.21)",
      "how": "Retirer la comparaison de l'adresse recouvrée",
      "where": "scripts/lib/console.mjs (verifierSignature)"
    },
    "attack": "Réponse du portefeuille qui ne recouvre pas l'adresse de l'approbateur sur le D_A de la console (cas console/reponses adresse_differente).",
    "expected_with_response": "Aucun vote n'est construit (refus adresse_differente).",
    "expected_without_response": "Un vote part ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-46",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "decouvrir égal à l'attendu de chaque cas ; au moins un cas diverge pour le mutant.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-46 (MN-46) : console/decouverte : deux annonces de même uuid par des objets différents sont exclues toutes deux ; mutant sans l'exclusion : un portefeuille est retenu et au moins un cas diverge (tué)"
        },
        {
          "file": "test/console.test.js",
          "describe": "CT-3 0.3 : console/ rejoué par console.mjs (CS-1 à CS-9)",
          "it": "CS-8 (EX-13.22) : decouverte/ — validation des annonces, réannonce, uuid en double, ordre, aucun choix"
        }
      ]
    },
    "response_removed": {
      "what": "Aucun choix implicite, doublons d'uuid exclus (CT-3 EX-13.22)",
      "how": "Retirer l'exclusion des deux annonces de même uuid",
      "where": "scripts/lib/console.mjs (Decouverte)"
    },
    "attack": "Deux annonces EIP-6963 de même uuid par deux objets.",
    "expected_with_response": "Les deux sont écartées, aucun portefeuille choisi.",
    "expected_without_response": "Un portefeuille est retenu ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-47",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "Égalité pas à pas ; divergence au pas 3 pour le mutant.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-47 (MN-47) : annuaire/traces/confiscation.json : une adresse déjà attribuée n'est jamais réattribuée (adresse_deja_attribuee, pas 3 et 5) ; mutant sans ce refus : la trace diverge (tué)"
        },
        {
          "file": "test/console.test.js",
          "describe": "CT-3 0.3 : annuaire/ rejoué par console.mjs (AN-1 à AN-10)",
          "it": "AN-6, AN-7 (EX-13.10, EX-13.17, EX-12.17) : chaque trace rejouée redonne sort, raison, réponse, revision et état résumé, pas à pas"
        }
      ]
    },
    "response_removed": {
      "what": "Adresse jamais réattribuée, preuve de possession nommant l'identité, nonce unique (CT-3 EX-13.10, EX-13.13, EX-13.15)",
      "how": "Retirer le refus adresse_deja_attribuee",
      "where": "scripts/lib/console.mjs (annuaire)"
    },
    "attack": "Trace annuaire/traces/confiscation.json : une identité prépare l'inscription d'une adresse déjà attribuée, puis après révocation.",
    "expected_with_response": "Refus adresse_deja_attribuee aux pas 3 et 5.",
    "expected_without_response": "L'adresse est confisquée ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-48",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "result, reason, check ; le mutant scelle.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-48 (MN-48) : decisions/invalides sg7-auto-approbation : la remise signée par le demandeur est refusée par SG-7 ; mutant sans SG-7 : scellée (tué)"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : remises et signatures (section 9, SG-1 à SG-7, annexe A.7 et A.8)",
          "it": "decisions/ : chaque remise reçoit le résultat et la raison attendus, dans l'ordre de SG-1 à SG-7"
        }
      ]
    },
    "response_removed": {
      "what": "Séparation du demandeur vérifiée par le noyau (CT-3 EX-10.2, SG-7) ; seuil d'adresses distinctes (CT-1 A-3)",
      "how": "Retirer SG-7",
      "where": "scripts/lib/approbation.mjs (verifierRemise)"
    },
    "attack": "Remise sg7-auto-approbation signée par l'adresse déclarée du demandeur.",
    "expected_with_response": "Refus auto_approbation (SG-7).",
    "expected_without_response": "Scellée ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-49",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "Résultats de normaliserSignature contre expected.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-49 (MN-49) : signatures/normalisation.json : chaque forme refusée l'est par le noyau (r, s hors de ]0, n[, v hors de {0, 1, 27, 28}) ; mutant qui délègue ces contrôles : au moins une forme refusée est normalisée (tué)"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : remises et signatures (section 9, SG-1 à SG-7, annexe A.7 et A.8)",
          "it": "A.8 : normalisation d'EX-9.3 ; chaque forme normalisée recouvre la même adresse que la forme d'entrée"
        }
      ]
    },
    "response_removed": {
      "what": "Normalisation et refus des formes non canoniques par le noyau, sans déléguer à une bibliothèque (CT-3 EX-9.3, EX-9.22, SG-5)",
      "how": "Retirer les refus r, s hors de ]0, n[ et v hors domaine",
      "where": "scripts/lib/approbation.mjs (normaliserSignature)"
    },
    "attack": "Formes refusées de signatures/normalisation.json (r-nul, s-egal-n, v-29, …).",
    "expected_with_response": "Chaque forme refusée rend signature null.",
    "expected_without_response": "Au moins quatre formes refusées sont normalisées ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-50",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "Égalité pas à pas ; le mutant diverge aux pas 6 et 8 (seuil effectif abaissé).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-50 (MN-50) : tickets/jeu-seuil-abaisse.json : le seuil effectif ne baisse jamais pendant la vie du ticket ; mutant qui suit la baisse : la trace diverge aux pas 6 et 8 (tué)"
        },
        {
          "file": "test/approbation.test.js",
          "describe": "CT-3 : tickets (section 7, TK-1 à TK-13)",
          "it": "chaque trace rejouée sur un service vide redonne chaque attendu, pas à pas (EX-7.9, EX-A.6)"
        }
      ]
    },
    "response_removed": {
      "what": "Seuil effectif qui ne baisse jamais, membres ajoutés signalés (CT-3 EX-8.5 à EX-8.7)",
      "how": "Faire suivre le seuil au jeu relu",
      "where": "scripts/lib/approbation.mjs (geler)"
    },
    "attack": "Trace tickets/jeu-seuil-abaisse.json : seuil ramené à 1 pendant l'attente.",
    "expected_with_response": "Le ticket exige toujours 2 signatures.",
    "expected_without_response": "La trace diverge ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-51",
    "preconditions": [
      "Service d'approbation construit (phase 2, étape 6), avec la forme de la déclaration de son point RPC (réglage « point RPC de la chaîne du registre » de la configuration du service, CT-3 EX-10.10) fixée par l'étape 6 : schéma proposé par CT-8 PD-7, ou à défaut celui que livre l'étape 6."
    ],
    "steps": [
      "Valider une configuration de production avec un RPC non déclaré ; puis avec un RPC déclaré validateur du client ; puis avec un RPC déclaré validateur partenaire."
    ],
    "oracle": "Refus puis deux acceptations. Refus : code de retour non nul de la validation, avec une erreur qui nomme le point RPC (forme du rapport de CT-2 EX-15.4, par analogie ; commande fixée à l'étape 6). Acceptation : code 0, pour un RPC déclaré validateur du client comme pour un RPC déclaré validateur partenaire (CT-7 EX-3.10). La règle ne vaut qu'en production (CT-7 EX-3.10 : « En production ») : ce test ne juge aucune configuration hors production. Écarts connus, consignés : le lieu de la validation (au démarrage du service, ou à `charger`, qui transmet `environment`, CT-3 §12.2) et la raison du refus (aucune raison de CT-3 §12.8 ne nomme un point RPC non déclaré) ne sont pas fixés par CT-3.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 6,
      "blocking": "Service d'approbation et console non construits : phase 2, étape 6. La règle éprouvée est CT-7 EX-3.10 ; la forme de la déclaration du point RPC (CT-8 PD-7, ou à défaut la livraison de l'étape 6) est fixée par l'étape 6 ; aucun `status.depends_on` : la règle n'est pas conditionnée par la proposition."
    },
    "response_removed": {
      "what": "Jeu lu auprès d'un validateur du client ou partenaire (CT-3 EX-8.2 ; CT-7 EX-3.10)",
      "how": "Retirer, dans la validation de la configuration du service, le contrôle du point RPC déclaré",
      "where": "service d'approbation (configuration, CT-8 PD-7)"
    },
    "attack": "Configuration de production dont le point RPC est un nœud quelconque non déclaré validateur du client ni d'un partenaire.",
    "expected_with_response": "La validation refuse la configuration en production.",
    "expected_without_response": "Acceptée ; le service figerait un jeu inventé ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-52",
    "preconditions": [
      "console/ du dépôt ; Chromium (EX-13.36)."
    ],
    "steps": [
      "Lire la configuration par défaut de la page ; dans Chromium, vérifier l'absence des éléments du parcours c."
    ],
    "oracle": "Drapeau par défaut faux et zéro élément.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Possible dès maintenant sur les vecteurs et les bibliothèques du dépôt ; non écrit dans ce lot ; dû au plus tard à l'étape 8 (tests adversariaux)."
    },
    "response_removed": {
      "what": "Parcours c (relais de portefeuille) désactivé par défaut, échéance bornée, code jamais journalisé (CT-3 EX-13.27)",
      "how": "Activer le parcours c dans la configuration par défaut de la console de référence",
      "where": "console/ (configuration par défaut)"
    },
    "attack": "Console déployée sans réglage explicite.",
    "expected_with_response": "Aucun élément ni code du parcours c n'est offert sans activation.",
    "expected_without_response": "Le parcours apparaît ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-53",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "attendreRefus et request_sha256 dans le test existant ; le mutant de l'outil est le complément (étape 8).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — outil de référence sur le réseau Hardhat en mémoire (31337, --sans-capture)",
          "it": "révocation, administration du jeu, réassignation et approvisionnement"
        }
      ],
      "complement": {
        "phase2_step": 8,
        "blocking": "Mutant de l'outil scripts/registre/noortrace-registre.mjs (comparaison d'admin() et exigence de --demande dans reassigner) à ajouter à test/adversarial.test.js ; possible dès maintenant, dû au plus tard à l'étape 8."
      }
    },
    "response_removed": {
      "what": "Réassignation sur demande écrite consignée, jeu administré par la même clé de gouvernance (CT-4 EX-8.10) ; OP-5",
      "how": "Retirer la comparaison d'admin() et l'exigence de --demande",
      "where": "scripts/registre/noortrace-registre.mjs (reassigner)"
    },
    "attack": "reassigner vers un jeu dont admin() diffère ; sans --demande (test existant).",
    "expected_with_response": "Refus OP-5 jeu_invalide ; refus usage sans demande ; succès avec le bon jeu, SHA-256 de la demande consigné.",
    "expected_without_response": "La réassignation part ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-54",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "attendu.json ; mutant sans R-2 dans failed_checks.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-54 (MN-54) : invalide-r2-jeu-substitue échoue à R-2 (quorum sur le jeu du réviseur) ; mutant qui pose R-2 réussie : R-2 disparaît des échecs (tué)"
        },
        {
          "file": "test/registre.test.js",
          "describe": "CT-6 contrôle 8 : vérifications R-1 à R-10 et N-4",
          "it": "R-2 : jeu de l'ancre qui ne couvre pas la hauteur (ancre_absente, R-5 suit) ; jeu substitué (échec, R-5 prerequis_en_echec) ; le certificat forgé est pourtant valide pour son propre jeu"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : dossiers complets de spec/vecteurs/ct-6 par la ligne de commande",
          "it": "chaque dossier rend le code, les vérifications en échec, les statuts, les non-exécutions, les avertissements, l'énoncé et la borne de son attendu.json (V-1 à V-5)"
        }
      ]
    },
    "response_removed": {
      "what": "Quorum calculé sur le jeu du réviseur (CT-6 R-2) ; au plus f validateurs par opérateur (CT-4 EX-4.12)",
      "how": "Poser R-2 réussie",
      "where": "scripts/lib/registre.mjs"
    },
    "attack": "Dossier invalide-r2-jeu-substitue : certificat valide pour son propre jeu, pas pour celui de l'ancre.",
    "expected_with_response": "R-2 en échec, code 1.",
    "expected_without_response": "R-2 passe ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-55",
    "preconditions": [
      "Réseau de développement lancé par chain/scripts/dev-net.sh start (exécution réelle, hors npm test ; la CI n'exécute jamais noorcore, CT-5 EX-A.7)."
    ],
    "steps": [
      "Lancer le réseau ; soumettre les transactions parasites ; soumettre une ancre par l'outil de référence ; mesurer le délai d'inclusion ; arrêter le réseau (dev-net.sh stop)."
    ],
    "oracle": "Délai d'inclusion dans la borne de SU-2 et refus des parasites ; comparaison avec et sans la garde.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Possible dès maintenant sur les vecteurs et les bibliothèques du dépôt ; non écrit dans ce lot ; dû au plus tard à l'étape 8 (tests adversariaux)."
    },
    "response_removed": {
      "what": "Garde d'admission par client, RPC des validateurs fermés (CT-4 EX-10.8, EX-10.3, EX-8.15)",
      "how": "Retirer la garde d'admission du relais RPC du réseau de développement",
      "where": "chain/ (configuration du réseau de développement)"
    },
    "attack": "Transactions à 1 wei de frais soumises en nombre depuis un expéditeur sans provision ; épreuve SU-2 de CT-4 §11.2 rejouée.",
    "expected_with_response": "Les transactions non prêtes sont refusées à l'admission ; les ancres et clôtures obtiennent leur reçu dans le délai de SU-2.",
    "expected_without_response": "La mempool se remplit ; le délai de SU-2 est dépassé ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-56",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "Statut et code de CP-4 par cas.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-56 (MN-56) : capture/capture.json cp4-autre-jeu, cp4-valset-hash-index et cp4-certificat-autre-bloc sont refusés par CP-4 (certificat_invalide) ; mutant sans les contrôles CP-4 : CP-4 réussit (tué)"
        },
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — vecteurs spec/vecteurs/ct-4",
          "it": "capture : CP-2 à CP-6 rejoués ; export des parties égal à spec/vecteurs/ct-6/registre/periode-1 (EX-9.8 à EX-9.10)"
        }
      ]
    },
    "response_removed": {
      "what": "Certificat vérifié contre le jeu du manifeste avant d'être tenu pour capturé (CT-4 CP-1, CP-4)",
      "how": "Neutraliser tous les contrôles CP-4",
      "where": "scripts/lib/conventions-registre.mjs (verifierCapture)"
    },
    "attack": "Cas cp4-autre-jeu, cp4-valset-hash-index, cp4-certificat-autre-bloc de capture/capture.json.",
    "expected_with_response": "CP-4 echoue, code certificat_invalide.",
    "expected_without_response": "CP-4 reussi ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-57",
    "preconditions": [
      "Bibliothèque conventions-registre.mjs ; clés de test de ct-3/constantes.json."
    ],
    "steps": [
      "Construire le condensé d'inscription pour org B et le signer ; vérifier le jeu de signatures sous org A par verifierJeuSignatures.",
      "Rejouer avec un mutant de la bibliothèque qui retire org_id de la préimage, côté signataire et côté vérificateur."
    ],
    "oracle": "Refus signataire_different avec la référence ; acceptation avec le mutant appliqué des deux côtés. Les cas register-digest-autre-contrat et period-digest-autre-chaine du vecteur condenses.json couvrent déjà chain_id et contract (test existant).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Possible dès maintenant sur les vecteurs et les bibliothèques du dépôt ; non écrit dans ce lot ; dû au plus tard à l'étape 8 (tests adversariaux)."
    },
    "response_removed": {
      "what": "Identifiant EVM, adresse, étiquette et org_id dans chaque condensé (CT-4 EX-4.8, §6.6) ; RG-6 à RG-11, RG-13",
      "how": "Retirer org_id de la préimage du condensé d'inscription",
      "where": "scripts/lib/conventions-registre.mjs (condenseInscription)"
    },
    "attack": "Demande d'inscription signée par les membres du jeu de l'organisation B, rejouée pour l'organisation A.",
    "expected_with_response": "RG-13 refuse : le condensé recalculé pour A diffère de celui signé pour B (signataire_different).",
    "expected_without_response": "Si org_id sortait du condensé, la même signature vaudrait pour A ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-58",
    "preconditions": [
      "Bibliothèque ancrage.mjs ; forme des traces planificateur-ancrage-v0."
    ],
    "steps": [
      "Écrire la trace (entrées : demarrage, point_produit, periode_close, echec_registre code empreinte_squattee) et ses actions attendues ; l'ajouter au générateur generer-ct5.mjs (PD-10).",
      "Rejouer par verifierTrace ; rejouer sur le mutant."
    ],
    "oracle": "Écarts nuls pour la référence ; écarts non nuls pour le mutant.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Possible dès maintenant sur les vecteurs et les bibliothèques du dépôt ; non écrit dans ce lot ; dû au plus tard à l'étape 8 (tests adversariaux)."
    },
    "response_removed": {
      "what": "Ancre du registre envoyée avant la requête d'horodatage, aucun nouvel essai après empreinte_squattee, incident consigné (CT-4 EX-8.4, EX-8.6 ; CT-5 EX-4.7, EX-9.6, EX-9.7)",
      "how": "Retirer le passage en refusee et l'alerte dans echecRegistre",
      "where": "scripts/lib/ancrage.mjs (echecRegistre)"
    },
    "attack": "Trace du planificateur avec une entrée echec_registre de code empreinte_squattee pour l'ancre de période.",
    "expected_with_response": "Demande en état refusee, alerte critique empreinte_squattee, ligne anchor_refused, aucune nouvelle tentative ; la requête RFC 3161 part après l'envoi de l'ancre.",
    "expected_without_response": "Nouvel essai ou absence d'alerte ; la trace diverge ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-59",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "attendu.json ; mutant.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-59 (MN-59) : invalide-r8-autre-contrat échoue à R-8 ; mutant qui pose R-8 réussie : R-8 disparaît des échecs (tué)"
        },
        {
          "file": "test/registre.test.js",
          "describe": "CT-6 contrôle 8 : vérifications R-1 à R-10 et N-4",
          "it": "R-8 : journal émis par un autre contrat que celui de l'ancre pour le rôle"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : dossiers complets de spec/vecteurs/ct-6 par la ligne de commande",
          "it": "chaque dossier rend le code, les vérifications en échec, les statuts, les non-exécutions, les avertissements, l'énoncé et la borne de son attendu.json (V-1 à V-5)"
        }
      ]
    },
    "response_removed": {
      "what": "Adresse du contrat comparée à l'ancre (CT-6 R-8) ; aucune mise à niveau en place (CT-4 EX-5.9, EX-5.10)",
      "how": "Poser R-8 réussie",
      "where": "scripts/lib/registre.mjs"
    },
    "attack": "Dossier invalide-r8-autre-contrat.",
    "expected_with_response": "R-8 en échec.",
    "expected_without_response": "R-8 passe ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-60",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "verifierTrace vide pour la référence ; le mutant diverge au pas 28 (ligne horloge_suspecte attendue). Le rapport du vérificateur ne dit que « au plus tard » (TA-78 et T-11 pour la partie CT-6).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-60 (MN-60) : planification/horloge-suspecte.json : un jeton dont genTime s'écarte de l'envoi au-delà de clock_tolerance_s est promu et marqué horloge_suspecte ; mutant sans le marquage : la trace diverge au pas 28 (tué)"
        },
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : familles planification et reprise (EX-8.12, EX-8.16, EX-A.6)",
          "it": "chaque trace est reproduite à l'identique par rejouerTrace (actions et file finale)"
        }
      ]
    },
    "response_removed": {
      "what": "Contrôle de genTime à l'acquisition qui marque le jeton sans le refuser (CT-5 EX-5.11)",
      "how": "Retirer le marquage horloge_suspecte",
      "where": "scripts/lib/ancrage.mjs (planificateur, réponse RFC 3161)"
    },
    "attack": "Trace planification/horloge-suspecte.json : genTime hors de clock_tolerance_s.",
    "expected_with_response": "Jeton promu et marqué horloge_suspecte, alerte mineure.",
    "expected_without_response": "La trace diverge ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-61",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "attendu.json de chaque dossier ; mutants.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-17 et TA-61 (MN-17, MN-61) : invalide-t2-jeton-autre-manifeste (T-2), invalide-o2-preuve-autre-manifeste (O-2) et invalide-k7-jeton-autre-empreinte (K-7, par T-2 sur checkpoint_hash) échouent ; mutants qui ne comparent plus l'empreinte recalculée : ils passent (tués)"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : dossiers complets de spec/vecteurs/ct-6 par la ligne de commande",
          "it": "chaque dossier rend le code, les vérifications en échec, les statuts, les non-exécutions, les avertissements, l'énoncé et la borne de son attendu.json (V-1 à V-5)"
        }
      ]
    },
    "response_removed": {
      "what": "Égalité stricte de l'empreinte recalculée : T-2, O-2 (et T-5, T-7, O-4, O-5), K-7 et K-9 pour un point (CT-6, CT-1 K-7, K-9)",
      "how": "Retirer la comparaison de l'empreinte dans T-2 et O-2",
      "where": "scripts/lib/horodatage.mjs, scripts/lib/ots.mjs"
    },
    "attack": "Dossiers invalide-t2-jeton-autre-manifeste, invalide-o2-preuve-autre-manifeste, invalide-k7-jeton-autre-empreinte.",
    "expected_with_response": "T-2, O-2, K-7 en échec.",
    "expected_without_response": "Ils passent ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-62",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "verifierTrace vide pour la référence ; le mutant diverge au pas 47 (journaliser anchor_fallback attendu, ecrire_file obtenu) ; le test éprouve le mécanisme, pas l'existence d'un secours utilisable (CT-5 EX-11.3).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-62 (MN-62, partie exécutable ; le retrait de la relève elle-même est le complément) : planification/principal-injoignable.json : la relève par le secours configuré est consignée (anchor_fallback) ; le test éprouve le mécanisme, pas l'existence d'un secours utilisable (CT-5 EX-11.3) ; mutant sans la consignation de la relève : la trace diverge au pas 47 (tué)"
        },
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : familles planification et reprise (EX-8.12, EX-8.16, EX-A.6)",
          "it": "chaque trace est reproduite à l'identique par rejouerTrace (actions et file finale)"
        }
      ],
      "complement": {
        "phase2_step": 5,
        "blocking": "Le retrait de la relève elle-même (`this.relever`) sur `principal-injoignable.json` épuise les gigues injectées de la trace figée et lève avant l'oracle (EX-10.6) : mutant à poser sur le composant d'ancrage de l'étape 5 (ou sur une trace ad hoc de la bibliothèque) ; le texte de test de MN-62 (« si la relève est retirée ») est à aligner (PD-24). La version 0.1 rattachait à tort ce complément à l'étape 4 : la relève est le fait du composant d'ancrage."
      }
    },
    "response_removed": {
      "what": "Relève par le secours et file durable (CT-5 EX-5.7, EX-8.5) ; deux calendriers, min_responses (EX-4.9, EX-6.6, EX-8.11)",
      "how": "Retirer la consignation anchor_fallback de la relève (détection) ; le retrait de la relève elle-même (appel relever) sur la trace figée épuise les gigues injectées et lève avant l'oracle (mutant mal posé, EX-10.6) : complément, PD-24",
      "where": "scripts/lib/ancrage.mjs (relever)"
    },
    "attack": "Trace planification/principal-injoignable.json.",
    "expected_with_response": "Rejets consignés et relève vers qtsa-secours.",
    "expected_without_response": "La trace diverge ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-63",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "verifierTrace vide pour la référence ; le mutant diverge au pas 3 (alerter point_manquant attendu, echeance obtenu) ; constaterCadence sur une série creuse (test existant).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-63 (MN-63) : planification/point-manquant.json : l'absence de point admis au-delà de 2 × c_K lève l'alerte point_manquant ; mutant sans l'alerte : la trace diverge au pas 3 (tué)"
        },
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : familles planification et reprise (EX-8.12, EX-8.16, EX-A.6)",
          "it": "chaque trace est reproduite à l'identique par rejouerTrace (actions et file finale)"
        },
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : série des points, échéances, admission et complétude au registre (AN-2, AN-3, AN-61)",
          "it": "constaterCadence (AN-2, alerte point_manquant) : la série publiée est conforme ; une série creuse (09:00, 09:59, clôture) porte un écart de 3540 s"
        }
      ]
    },
    "response_removed": {
      "what": "Alerte point_manquant quand aucun point n'est admis pendant plus de 2 × c_K (CT-5 EX-8.15, §8.9)",
      "how": "Retirer l'alerte",
      "where": "scripts/lib/ancrage.mjs"
    },
    "attack": "Trace planification/point-manquant.json.",
    "expected_with_response": "Alerte majeure point_manquant.",
    "expected_without_response": "La trace diverge ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-64",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "verifierTrace vide pour la référence ; le mutant sans reconstruction diverge dès le pas 1 (ecrire_file attendu, journaliser obtenu) et sur la file finale ; le mutant sans l'alerte diverge au pas 17 (alerter file_perdue attendu, stocker obtenu).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-64 (MN-64) : planification/file-perdue.json : les demandes manquantes sont recréées au démarrage et l'alerte file_perdue est levée ; mutant sans la reconstruction : la trace diverge dès le pas 1 et sur la file finale ; mutant sans l'alerte : la trace diverge au pas 17 (tués)"
        },
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : familles planification et reprise (EX-8.12, EX-8.16, EX-A.6)",
          "it": "chaque trace est reproduite à l'identique par rejouerTrace (actions et file finale)"
        }
      ]
    },
    "response_removed": {
      "what": "Reconstruction de la file au démarrage, alerte file_perdue (CT-5 EX-8.5, EX-8.12, EX-8.14)",
      "how": "Retirer la recréation des demandes manquantes (appels periodeClose et pointProduit de reconstruire) ; second mutant : retirer l'alerte file_perdue (détection)",
      "where": "scripts/lib/ancrage.mjs (reconstruire)"
    },
    "attack": "Trace planification/file-perdue.json.",
    "expected_with_response": "Demandes recréées (anchoring_queue_rebuilt, recreated > 0) et alerte critique file_perdue.",
    "expected_without_response": "La trace diverge ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-65",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "verifierConfiguration.violations.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-65 (MN-65) : verifierConfiguration (AN-1, règle 4) refuse en production un principal sans statut qualified ; mutant sans la règle 4 pour le principal : accepté (tué)"
        }
      ]
    },
    "response_removed": {
      "what": "Statut qualifié établi sur la liste de confiance, jamais sur une déclaration (CT-5 EX-5.9 ; AN-1 règle 4)",
      "how": "Retirer la règle 4 pour le principal",
      "where": "scripts/lib/ancrage.mjs (verifierConfiguration)"
    },
    "attack": "Configuration de production dont le principal n'a pas de statut qualified.",
    "expected_with_response": "Violation de la règle 4.",
    "expected_without_response": "Acceptée ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-66",
    "preconditions": [
      "Job vecteurs de ci.yml (étapes « clean-room Go verifier against the CT-1 JavaScript vectors », « … CT-2 … », « vérificateur Go indépendant contre les vecteurs CT-3 », CT-4, CT-5, CT-7, CT-8) ; en local, Go 1.24."
    ],
    "steps": [
      "Exécuter go run . .. dans chaque module Go (les sept étapes citées du job vecteurs de ci.yml) ; code 0 attendu.",
      "Rejouer confrontation/coherence (test cité de test/confrontation.test.js) : code 0, aucune discordance."
    ],
    "oracle": "Code 0 de chaque module Go et de la confrontation ; une discordance fait échouer l'étape. Le binaire reproductible et le module Go de CT-6 sont de phase 2, étape 2 (RA-57, complément).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/confrontation.test.js",
          "describe": "CT-5 : sorties publiées de la confrontation par des outils tiers (annexe A.6)",
          "it": "rejeu de confrontation/coherence (go présent et module tiers déjà dans le cache local) : code 0, aucune discordance"
        }
      ],
      "ci_steps": [
        "clean-room Go verifier against the CT-1 JavaScript vectors",
        "clean-room Go verifier against the CT-2 JavaScript vectors",
        "vérificateur Go indépendant contre les vecteurs CT-3",
        "vérificateur Go indépendant contre les vecteurs CT-4",
        "vérificateur Go indépendant contre les vecteurs CT-5",
        "vérificateur Go indépendant contre les vecteurs CT-7",
        "vérificateur Go indépendant contre les vecteurs CT-8",
        "binaire vérificateur Go, gofmt, vet et rejeu des dossiers CT-1 et CT-6 (zéro discordance)",
        "binaire vérificateur Go, deux constructions reproductibles aux mêmes octets (CT-6 EX-14.6, EX-14.8)"
      ],
      "complement": {
        "phase2_step": 8,
        "blocking": "Binaire reproductible et module Go de CT-6 livrés à l'étape 2 (TV-55, deux étapes de CI citées) ; reste un mutant JavaScript confronté au binaire, à ajouter à test/adversarial.test.js avec les tests adversariaux de l'étape 8."
      }
    },
    "response_removed": {
      "what": "Vérificateurs indépendants confrontés sur les vecteurs (CT-6 §3.1) ; binaire reproductible (EX-14.6, EX-14.8)",
      "how": "Retirer de l'intégration continue l'exécution des vérificateurs Go (les sept étapes go run . .. citées)",
      "where": ".github/workflows/ci.yml, job vecteurs"
    },
    "attack": "Une implémentation de référence qui dit « valide » à tort sur un vecteur.",
    "expected_with_response": "Les sept modules Go (ct-1 à ct-5, ct-7, ct-8) rendent « 0 discordance » et le code 0 sur leurs vecteurs ; toute divergence fait échouer le job ; ct-6 n'a pas de module Go (TV-55, étape 2).",
    "expected_without_response": "La divergence n'est pas vue ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-67",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "attendu.json ; mutant.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-67 (MN-67) : invalide-n3-cle-enregistreur échoue à N-3 ; mutant qui ne compare plus cles.json aux enregistreurs du fichier d'ancres : N-3 passe (tué)"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : dossiers complets de spec/vecteurs/ct-6 par la ligne de commande",
          "it": "chaque dossier rend le code, les vérifications en échec, les statuts, les non-exécutions, les avertissements, l'énoncé et la borne de son attendu.json (V-1 à V-5)"
        }
      ]
    },
    "response_removed": {
      "what": "Aucune ancre tirée du dossier ; clés d'enregistreur comparées au fichier d'ancres (CT-6 EX-3.3, EX-3.4, EX-12.1, N-3)",
      "how": "Retirer la comparaison des clés de cles.json aux recorders de l'ancre",
      "where": "scripts/lib/verificateur.mjs"
    },
    "attack": "Dossier invalide-n3-cle-enregistreur.",
    "expected_with_response": "N-3 en échec.",
    "expected_without_response": "N-3 passe ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-68",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "attendu.json ; mutant du lecteur DER (T-1). Le mutant du lecteur .ots (O-1) est le complément (étape 8).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-68 (MN-68) : invalide-t1-octet-en-trop échoue à T-1 ; mutant dont le lecteur DER tolère des octets après la fin de la structure : T-1 passe (tué)"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : dossiers complets de spec/vecteurs/ct-6 par la ligne de commande",
          "it": "chaque dossier rend le code, les vérifications en échec, les statuts, les non-exécutions, les avertissements, l'énoncé et la borne de son attendu.json (V-1 à V-5)"
        }
      ],
      "complement": {
        "phase2_step": 8,
        "blocking": "Mutant du lecteur .ots (O-1, octet en trop) à ajouter à test/adversarial.test.js ; possible dès maintenant, dû au plus tard à l'étape 8."
      }
    },
    "response_removed": {
      "what": "Lecture DER stricte, bornes, aucun octet en trop (CT-6 EX-15.1 à EX-15.3 ; T-1, O-1)",
      "how": "Tolérer des octets après la fin de la structure DER",
      "where": "scripts/lib/horodatage.mjs (lireDER)"
    },
    "attack": "Dossier invalide-t1-octet-en-trop (et invalide-o1-octet-en-trop, couvert par le test existant).",
    "expected_with_response": "T-1 en échec.",
    "expected_without_response": "T-1 passe ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-69",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "attendu.json de chaque dossier ; un mutant par vérification.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-17 et TA-69 (MN-17, MN-69) : invalide-r6-entete-modifie, invalide-r7-recu-falsifie, invalide-r9-cloture-autre-periode, invalide-r11-ancre-de-periode et invalide-k8-empreinte échouent chacun à la vérification nommée ; un mutant par vérification la pose réussie : elle disparaît des échecs (tués)"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : dossiers complets de spec/vecteurs/ct-6 par la ligne de commande",
          "it": "chaque dossier rend le code, les vérifications en échec, les statuts, les non-exécutions, les avertissements, l'énoncé et la borne de son attendu.json (V-1 à V-5)"
        }
      ]
    },
    "response_removed": {
      "what": "Recalcul de tout contre les ancres du réviseur : R-4, R-6, R-7, R-8, R-9, R-11 ; K-1, K-4, K-5, K-8 (CT-6, CT-1)",
      "how": "Poser chaque vérification réussie, une à la fois",
      "where": "scripts/lib/registre.mjs, scripts/lib/verificateur.mjs"
    },
    "attack": "Dossiers invalide-r6-entete-modifie, invalide-r7-recu-falsifie, invalide-r9-cloture-autre-periode, invalide-r11-ancre-de-periode, invalide-k8-empreinte (R-4 : TA-71 ; K-4 : TA-74).",
    "expected_with_response": "La vérification nommée échoue.",
    "expected_without_response": "Elle disparaît des échecs ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-70",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "attendu.json ; mutant.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-70 (MN-70) : invalide-o5-chaine-sans-travail échoue à O-5 ; mutant qui ne recalcule plus la preuve de travail au-dessus du point de contrôle : O-5 passe (tué)"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : dossiers complets de spec/vecteurs/ct-6 par la ligne de commande",
          "it": "chaque dossier rend le code, les vérifications en échec, les statuts, les non-exécutions, les avertissements, l'énoncé et la borne de son attendu.json (V-1 à V-5)"
        }
      ]
    },
    "response_removed": {
      "what": "Travail recalculé au-dessus du point de contrôle du réviseur, profondeur minimale (CT-6 O-5, EX-10.9)",
      "how": "Retirer la vérification de la preuve de travail",
      "where": "scripts/lib/ots.mjs"
    },
    "attack": "Dossier invalide-o5-chaine-sans-travail.",
    "expected_with_response": "O-5 en échec.",
    "expected_without_response": "O-5 passe ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-71",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "attendu.json ; mutant.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-71 (MN-71) : invalide-r4-autre-chaine échoue à R-4 ; mutant qui pose R-4 réussie : R-4 disparaît des échecs (tué)"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : dossiers complets de spec/vecteurs/ct-6 par la ligne de commande",
          "it": "chaque dossier rend le code, les vérifications en échec, les statuts, les non-exécutions, les avertissements, l'énoncé et la borne de son attendu.json (V-1 à V-5)"
        }
      ]
    },
    "response_removed": {
      "what": "Identifiant de chaîne de l'ancre comparé (CT-6 R-4) ; manifeste en révisions publiées et recoupement (CT-4 EX-4.25, RG-19 ; CT-6 §12.5)",
      "how": "Poser R-4 réussie",
      "where": "scripts/lib/registre.mjs"
    },
    "attack": "Dossier invalide-r4-autre-chaine.",
    "expected_with_response": "R-4 en échec.",
    "expected_without_response": "R-4 passe ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-72",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur le vecteur publié (test cité).",
      "Régénérer les vecteurs par le générateur nommé et comparer au dépôt (git diff --exit-code en CI) : la réponse retirée dans le générateur changerait le vecteur et la comparaison échouerait."
    ],
    "oracle": "Oracle structurel sur transactions.json.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-72 (MN-72, oracle sur le vecteur) : transactions.json : chaque appel de contrat porte un sélecteur de la table de CT-4 §6.7.1 et des arguments alignés sur 32 octets, avec une valeur nulle ; le seul transfert de valeur (approvisionnement) n'a pas de données et le seul déploiement n'a pas de destinataire ; aucun champ de contenu n'est transporté"
        },
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — vecteurs spec/vecteurs/ct-4",
          "it": "transactions : RG-15 rejoué ; sérialisation confrontée à ethers ; transactions de la capture redonnées octet pour octet (EX-A.4)"
        }
      ]
    },
    "response_removed": {
      "what": "Seules des empreintes de 32 octets, des clés publiques et des identifiants sont écrits au registre (CT-4 §3.4 ; CT-5 §13)",
      "how": "Faire écrire un champ de contenu dans une transaction du générateur",
      "where": "générateur generer-ct4.mjs (le vecteur régénéré diffère)"
    },
    "attack": "Transaction qui porterait un contenu d'événement.",
    "expected_with_response": "Chaque appel de contrat des vecteurs porte un sélecteur de CT-4 §6.7.1 et des mots de 32 octets ; aucun autre champ.",
    "expected_without_response": "Un champ apparaît ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-73",
    "preconditions": [
      "Hardhat en mémoire (test existant)."
    ],
    "steps": [
      "Ajouter au test existant ou à adversarial.test.js : administrer-jeu sans --confirmer refusé."
    ],
    "oracle": "attendreRefus et request_sha256.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/registreCt4.test.js",
          "describe": "CT-4 — outil de référence sur le réseau Hardhat en mémoire (31337, --sans-capture)",
          "it": "révocation, administration du jeu, réassignation et approvisionnement"
        }
      ],
      "complement": {
        "phase2_step": 8,
        "blocking": "Partie à écrire : Possible dès maintenant sur les vecteurs et les bibliothèques du dépôt ; non écrit dans ce lot ; dû au plus tard à l'étape 8 (tests adversariaux)."
      }
    },
    "response_removed": {
      "what": "Relais et approvisionnement sur confirmation hors bande consignée (CT-4 EX-8.21) ; demande consignée (CT-7 EX-5.1)",
      "how": "Retirer l'exigence de --confirmer / --demande",
      "where": "scripts/registre/noortrace-registre.mjs (reassigner, administrer-jeu)"
    },
    "attack": "reassigner sans --demande ou avec une confirmation nulle (test existant : refus usage) ; administrer-jeu sans référence de confirmation (à écrire).",
    "expected_with_response": "Refus ; request_sha256 consigné quand la demande est fournie.",
    "expected_without_response": "Relais sans trace ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-74",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "attendu.json ; mutant.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-74 (MN-74) : invalide-k4-point-trop-court (ct-1) échoue à K-4 ; mutant qui pose K-4 réussie : le dossier devient valide (tué)"
        },
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : dossier de preuve",
          "it": "rejoue dossiers/ : le dossier valide et chaque dossier invalide donnent exactement les contrôles attendus"
        }
      ]
    },
    "response_removed": {
      "what": "Couverture de l'événement par le point (CT-1 K-4) ; série des points publiée (CT-5 §10.2) ; ancres extérieures (CT-6 §3.4)",
      "how": "Poser K-4 réussie",
      "where": "scripts/lib/journal.mjs"
    },
    "attack": "Dossier ct-1 invalide-k4-point-trop-court : point embarqué qui ne couvre pas l'événement.",
    "expected_with_response": "K-4 en échec, dossier invalide.",
    "expected_without_response": "Dossier valide ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-75",
    "preconditions": [
      "Support WORM de test S3 ou compatible (verrou d'objet, versions) ; sur Azure et GCS, une version présente sur le support mais absente des deux registres n'est pas vue par le relevé en version 0 (CT-2 EX-17.6) ; rôle Lecteur configuré ; tâche de relecture et extracteur livrés (phase 2, étape 7)."
    ],
    "steps": [
      "Poser un gel ; passer une version à off ; couper les alertes du démon : neutraliser, comme l'attaquant de CT-7 MN-75 (administrateur du client), les règles dont la source est le démon, celles de CT-8 §10.4 (règles de l'enregistreur), dont `noortrace_gel_non_pose` (condition « Gel non posé sur une version d'un gel actif », CT-2 §17.4), par un moyen que le test choisit et consigne (silence posé dans le système d'alerte, ou retrait des règles, par nom de règle ou par étiquette `component` de CT-8 EX-10.2) ; la règle de la jauge `noortrace_releve_externe_ok`, alimentée par la relecture du Lecteur hors du démon (CT-8 EX-10.9), reste hors de ce périmètre : CT-8 ne fixe pas son étiquette `component`, que le test relève et consigne, et un silence par étiquette n'est admis que s'il ne la couvre pas ; lancer la relecture."
    ],
    "oracle": "`noortrace_releve_externe_ok{check=\"registre_gels\"}` vaut 0 après la relecture et la règle critique de CT-8 EX-10.9 se déclenche, les règles du démon étant coupées ; `noortrace-ctl worm gel etat` sous les identifiants du Lecteur rend un code non nul et nomme la version `off` du gel actif (condition « Gel non posé sur une version d'un gel actif », CT-2 §17.4). Écart connu : sortie et code de retour exacts de la commande non fixés par CT-2 EX-12.40 (PD-26).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Paquets, observabilité et runbooks non construits : phase 2, étape 7."
    },
    "response_removed": {
      "what": "Relecture du registre des gels par un rôle Lecteur hors du démon (CT-2 EX-17.7, EX-18.9) ; métriques publiques (EX-17.1)",
      "how": "Faire faire la relecture par le démon seul",
      "where": "tâche d'exploitation hors du démon (CT-8 §11.12)"
    },
    "attack": "Version d'un gel actif passée à off sur le support, démon dont les alertes sont coupées.",
    "expected_with_response": "La relecture quotidienne du Lecteur (CT-8 §11.12) met `noortrace_releve_externe_ok{check=\"registre_gels\"}` à 0, alertée en critique (CT-8 EX-10.9), pour la condition « Gel non posé sur une version d'un gel actif » ; la commande du Lecteur rend un code non nul.",
    "expected_without_response": "La jauge reste à 1 ou n'existe pas, aucune alerte hors du démon ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-76",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "verifierTrace vide pour la référence ; le mutant diverge au pas 44 (rejeter_reponse attendu, ecrire_file obtenu).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-76 (MN-76) : planification/reponse-tardive.json : une réponse reçue au-delà de max_response_delay_s est classée reponse_tardive ; mutant sans le contrôle de fraîcheur : la trace diverge au pas 44 (tué)"
        },
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : familles planification et reprise (EX-8.12, EX-8.16, EX-A.6)",
          "it": "chaque trace est reproduite à l'identique par rejouerTrace (actions et file finale)"
        }
      ]
    },
    "response_removed": {
      "what": "Réponses tardives rejetées (CT-5 EX-5.11) ; TLS vérifié, nonce (EX-5.5, EX-6.2)",
      "how": "Retirer le contrôle de fraîcheur",
      "where": "scripts/lib/ancrage.mjs"
    },
    "attack": "Trace planification/reponse-tardive.json.",
    "expected_with_response": "reponse_tardive, nouvel essai.",
    "expected_without_response": "Promue ; la trace diverge ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-77",
    "preconditions": [
      "Démon de l'enregistreur construit (phase 2, étape 4), configuration de l'installation rapide (CT-8 §7.3).",
      "Service d'approbation construit (phase 2, étape 6) ; faux service de test."
    ],
    "steps": [
      "Pointer le démon vers le faux service sans mTLS ni jeton ; soumettre un appel à approuver."
    ],
    "oracle": "Ligne approval_response_invalid, appel non relayé.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 6,
      "blocking": "Service d'approbation et console non construits : phase 2, étape 6."
    },
    "response_removed": {
      "what": "Canal du service authentifié (CT-3 EX-12.2 ; CT-2 EX-18.8, EX-18.3)",
      "how": "Accepter une réponse du service sur un canal non authentifié",
      "where": "démon (client du service d'approbation)"
    },
    "attack": "Un processus tiers répond à la place du service sur un canal non authentifié.",
    "expected_with_response": "La réponse est traitée comme une indisponibilité (approval_response_invalid, mode d'attente).",
    "expected_without_response": "La réponse est appliquée ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-78",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "statement.fr ; test existant sur tous les rapports des vecteurs.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-78 (MN-78) : l'énoncé de valide-seq-7-complet-attestation dit le périmètre « déclaré, non prouvé » ; mutant qui écrit « vérifié » : l'énoncé applique « vérifié » au périmètre (tué)"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 révision 0.3 : attestation de périmètre (section 5.5, EX-6.19 à EX-6.21, V-10)",
          "it": "EX-7.3 de CT-6, EX-7.18 point 3 de CT-7 : aucun texte des rapports n'applique « prouvé », « vérifié » ou « conforme » au périmètre ; le seul verbe est « déclaré »"
        }
      ]
    },
    "response_removed": {
      "what": "Périmètre rapporté « déclaré, non prouvé », jamais compté parmi ce que le dossier prouve (CT-7 EX-7.1, EX-7.17 ; CT-6 EX-6.19, EX-7.3)",
      "how": "Écrire « vérifié » dans le fragment FP",
      "where": "scripts/lib/verificateur.mjs (fragmentPerimetre)"
    },
    "attack": "Énoncé du dossier valide-seq-7-complet-attestation.",
    "expected_with_response": "FP dit « déclaré, non prouvé ».",
    "expected_without_response": "FP dit « vérifié » ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-79",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "perimeter_checks et perimeter_retained.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-79 et TA-80 (MN-79, MN-80) : valide-at5-autre-journal et valide-at5-hors-validite font échouer AT-5 et l'attestation n'est pas retenue ; mutant qui pose toujours AT-5 réussie : attestation retenue (tué)"
        },
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : dossier de preuve",
          "it": "rejoue dossiers/ : le dossier valide et chaque dossier invalide donnent exactement les contrôles attendus"
        }
      ]
    },
    "response_removed": {
      "what": "org_id et journal_id de l'attestation comparés à l'événement prouvé (CT-1 AT-5 ; CT-7 EX-7.16)",
      "how": "Poser AT-5 réussie",
      "where": "scripts/lib/securite.mjs"
    },
    "attack": "Dossier valide-at5-autre-journal.",
    "expected_with_response": "AT-5 en échec, attestation non retenue, AV-AT-1.",
    "expected_without_response": "Retenue ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-80",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "perimeter_checks et perimeter_retained.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-79 et TA-80 (MN-79, MN-80) : valide-at5-autre-journal et valide-at5-hors-validite font échouer AT-5 et l'attestation n'est pas retenue ; mutant qui pose toujours AT-5 réussie : attestation retenue (tué)"
        },
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : dossier de preuve",
          "it": "rejoue dossiers/ : le dossier valide et chaque dossier invalide donnent exactement les contrôles attendus"
        }
      ]
    },
    "response_removed": {
      "what": "ts de l'événement dans validity (CT-1 AT-5) ; renouvellement avant validity.until (CT-7 EX-7.5)",
      "how": "Poser AT-5 réussie",
      "where": "scripts/lib/securite.mjs"
    },
    "attack": "Dossier valide-at5-hors-validite.",
    "expected_with_response": "AT-5 en échec.",
    "expected_without_response": "Retenue ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-81",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "checks AT-3 par cas.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-81 (MN-81) : chaque cas invalide-at3-* de attestations.json échoue à AT-3 ; s-haut et v-hors-domaine restent refusés par le contrôle de forme, fait avant tout recouvrement (CT-7 EX-7.6) ; mutant qui ne compare plus l'adresse recouvrée à l'adresse déclarée : la signature substituée passe (tué)"
        },
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : vecteurs attestations/ et outil de référence (EX-A.8, EX-A.9, EX-A.17)",
          "it": "attestations.json est conforme à #/$defs/fichier_vecteurs, porte les 18 cas d'EX-A.8, et chaque cas est rejoué à l'identique par verifierAttestation"
        }
      ]
    },
    "response_removed": {
      "what": "Signature canonique recouvrée sur M et égale à l'adresse déclarée (CT-1 AT-3 ; CT-7 EX-7.6) ; AT-4",
      "how": "Retirer la comparaison de l'adresse recouvrée",
      "where": "scripts/lib/securite.mjs (verifierAT1aAT4)"
    },
    "attack": "Cas invalide-at3-signature-substituee ; s-haut et v-hors-domaine restent refusés par la forme.",
    "expected_with_response": "AT-3 en échec.",
    "expected_without_response": "La signature substituée passe ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-82",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "warnings du rapport.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-82 (MN-82) : valide-at4-jeu-different porte AV-AT-2 ; mutant sans l'avertissement : aucun avertissement (tué)"
        },
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : dossier de preuve",
          "it": "rejoue dossiers/ : le dossier valide et chaque dossier invalide donnent exactement les contrôles attendus"
        }
      ]
    },
    "response_removed": {
      "what": "Avertissement AV-AT-2 quand le jeu déclaré diffère de approbations.json (CT-6 §5.5) ; set_source dans l'énoncé (CT-7 EX-7.17)",
      "how": "Retirer AV-AT-2",
      "where": "scripts/lib/securite.mjs"
    },
    "attack": "Dossier valide-at4-jeu-different.",
    "expected_with_response": "AV-AT-2 présent.",
    "expected_without_response": "Absent ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-83",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "checks[2] et recovered[0] par cas.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-83 (MN-83) : chaque signature croisée de croises.json présentée comme attestation échoue à AT-3 (D_P recalculé depuis le fichier, préfixe propre) ; mutant qui accepte l'adresse déclarée sans recouvrement : la signature croisée passe (tué)"
        },
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : vecteurs attestations/ et outil de référence (EX-A.8, EX-A.9, EX-A.17)",
          "it": "croises.json (EX-7.7, EX-A.9) : chaque signature croisée du compte 1 est refusée, et l'adresse recouvrée sur le mauvais message est celle que le fichier donne"
        }
      ]
    },
    "response_removed": {
      "what": "Préfixe propre P_P et Keccak-256, D_P recalculé depuis le fichier (CT-7 EX-7.7, EX-7.8)",
      "how": "Accepter l'adresse déclarée sans recouvrement sur M",
      "where": "scripts/lib/securite.mjs"
    },
    "attack": "Signatures croisées de croises.json présentées comme attestation (D_A d'une décision, texte d'inscription, D_C, periodDigest).",
    "expected_with_response": "AT-3 en échec, adresse recouvrée égale à celle du fichier.",
    "expected_without_response": "Passe ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-84",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "perimeter_checks.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-84 (MN-84) : valide-at6-inscription-signature-fausse fait échouer AT-6 ; mutant qui ne vérifie plus la signature E-8 de l'inscription : AT-6 réussit (tué)"
        },
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : dossier de preuve",
          "it": "rejoue dossiers/ : le dossier valide et chaque dossier invalide donnent exactement les contrôles attendus"
        }
      ]
    },
    "response_removed": {
      "what": "Signature de l'inscription vérifiée sous la clé de l'événement prouvé (CT-1 AT-6 ; CT-7 EX-7.10)",
      "how": "Ne plus vérifier E-8 de l'inscription",
      "where": "scripts/lib/securite.mjs"
    },
    "attack": "Dossier valide-at6-inscription-signature-fausse.",
    "expected_with_response": "AT-6 en échec.",
    "expected_without_response": "Réussit ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-85",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "statement.fr.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-85 et TA-98 (MN-85, MN-98) : sans inscription, le fragment FP porte la clause fixe « non inscrite au journal (ni sa date ni son rang ne sont établis) » (ct-1 valide-seq-7-attestation-sans-inscription, ct-6 valide-seq-7-complet-attestation-non-retenue exclu car non retenue) ; mutant qui annonce une inscription : la clause disparaît (tué)"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 révision 0.3 : attestation de périmètre (section 5.5, EX-6.19 à EX-6.21, V-10)",
          "it": "FP de l'exemple d'EX-6.19 (français et anglais) et ligne lisible « Périmètre » (EX-8.10) ; AT- en échec « (sans effet sur le verdict) »"
        }
      ]
    },
    "response_removed": {
      "what": "Sans inscription, AT-6 et AT-7 non exécutées et clause fixe de FP (CT-7 EX-7.12 ; CT-6 EX-6.19)",
      "how": "Annoncer une inscription dans FP",
      "where": "scripts/lib/verificateur.mjs (fragmentPerimetre)"
    },
    "attack": "Dossier valide-seq-7-attestation-sans-inscription.",
    "expected_with_response": "FP porte « non inscrite au journal (ni sa date ni son rang ne sont établis) ».",
    "expected_without_response": "La clause disparaît ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-86",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "perimeter_checks.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-86 (MN-86) : valide-at6-inscription-posterieure fait échouer AT-6 ; mutant sans la comparaison des seq et des ts : AT-6 réussit (tué)"
        },
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : dossier de preuve",
          "it": "rejoue dossiers/ : le dossier valide et chaque dossier invalide donnent exactement les contrôles attendus"
        }
      ]
    },
    "response_removed": {
      "what": "seq et ts de l'inscription au plus ceux de l'événement prouvé (CT-1 AT-6 ; CT-7 EX-7.13)",
      "how": "Retirer les deux comparaisons",
      "where": "scripts/lib/securite.mjs"
    },
    "attack": "Dossier valide-at6-inscription-posterieure.",
    "expected_with_response": "AT-6 en échec.",
    "expected_without_response": "Réussit ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-87",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "erreurs de controlerDeclaration ; outil verifier --forme (test existant).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-87 (MN-87) : controlerDeclaration refuse une adresse IPv4 de documentation (192.0.2.10) dans host ; mutant sans le contrôle des membres sans adresse IP : aucune erreur (tué)"
        },
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : vecteurs attestations/ et outil de référence (EX-A.8, EX-A.9, EX-A.17)",
          "it": "outil de référence : condenser donne D_P ; verifier --forme refuse une adresse IPv4 dans host (MN-87) et une sortie directe sans not_captured, et rappelle un not_captured vide ; verifier --jeu retient l'exemple"
        }
      ]
    },
    "response_removed": {
      "what": "Ni secret, ni adresse IP, ni règles de sortie dans l'attestation (CT-7 EX-7.3)",
      "how": "Retirer le contrôle des membres sans adresse IP",
      "where": "scripts/lib/securite.mjs (controlerDeclaration)"
    },
    "attack": "host = 192.0.2.10 dans l'attestation de l'exemple.",
    "expected_with_response": "Erreur « adresse IP refusée ».",
    "expected_without_response": "Acceptée ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-88",
    "preconditions": [
      "PA-10 adoptée par CT-2 ; Démon de l'enregistreur construit (phase 2, étape 4), configuration de l'installation rapide (CT-8 §7.3)."
    ],
    "steps": [
      "Configurer un hôte absent de l'attestation ; démarrer ; appeler ; lire le journal d'exploitation."
    ],
    "oracle": "Ligne présente.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 4,
      "blocking": "PA-10 non adoptée par CT-2 : la consigne perimeter_unlisted_host n'est pas une exigence de CT-2 0.6, et le démon de l'étape 4 ne l'écrit pas (aucune occurrence dans paquets/enregistreur/src) ; le test s'écrit sur ce démon après l'adoption.",
      "depends_on": [
        "PA-10"
      ]
    },
    "response_removed": {
      "what": "Nouvelle attestation dès qu'un élément change (CT-7 EX-7.5) ; consigne perimeter_unlisted_host et métrique d'échéance (PA-10, PA-11)",
      "how": "Retirer la consigne",
      "where": "démon (après adoption de PA-10 par CT-2)"
    },
    "attack": "Connexion d'hôte dont l'alias manque à l'inventaire de l'attestation en vigueur.",
    "expected_with_response": "Ligne perimeter_unlisted_host au démarrage et à chaque appel de l'hôte.",
    "expected_without_response": "Rien ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-89",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "verdict et failed_checks.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-89 (MN-89) : valide-at1-taille (ct-1) et valide-seq-7-complet-attestation-non-retenue (ct-6) gardent le verdict valide avec une AT- en échec ; mutant qui compte les AT- dans failed_checks : verdict invalide (tué)"
        },
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : dossier de preuve",
          "it": "rejoue dossiers/ : le dossier valide et chaque dossier invalide donnent exactement les contrôles attendus"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 révision 0.3 : attestation de périmètre (section 5.5, EX-6.19 à EX-6.21, V-10)",
          "it": "V-10 : chaque dossier qui porte la partie a le code, le verdict, failed_checks (hors D-2), blocking_unexecuted, les statuts des huit contrôles et la borne du même dossier privé de la partie (EX-A.20)"
        }
      ]
    },
    "response_removed": {
      "what": "Limites de taille de la partie et aucune AT- sans effet sur le verdict (CT-6 EX-4.15, EX-5.11, V-10)",
      "how": "Compter les AT- dans failed_checks",
      "where": "scripts/lib/verificateur.mjs"
    },
    "attack": "Dossiers valide-at1-taille et valide-seq-7-complet-attestation-non-retenue : AT- en échec.",
    "expected_with_response": "Verdict valide.",
    "expected_without_response": "Invalide ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-90",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "perimeter_checks.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-90 (MN-90) : valide-at6-cle-non-ancree laisse AT-6 non exécutée (ancre_absente) ; mutant sans la comparaison de la clé de l'inscription à celle de l'événement prouvé : AT-6 réussit (tué)"
        },
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : dossier de preuve",
          "it": "rejoue dossiers/ : le dossier valide et chaque dossier invalide donnent exactement les contrôles attendus"
        }
      ]
    },
    "response_removed": {
      "what": "AT-6 non exécutée (ancre_absente) quand la clé de l'inscription n'est pas celle de l'événement prouvé (CT-1 AT-6 ; CT-6 EX-5.12, EX-6.19)",
      "how": "Retirer la comparaison des clés",
      "where": "scripts/lib/securite.mjs"
    },
    "attack": "Dossier valide-at6-cle-non-ancree.",
    "expected_with_response": "AT-6 non_execute ancre_absente, AT-7 non exécutée.",
    "expected_without_response": "AT-6 réussit ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-91",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "statement.fr.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-91 (MN-91) : valide-at7-nom-reannonce fait réussir AT-7 et FP ne dit que « de même nom » ; mutant qui affirme la vigueur de l'attestation : FP dit « en vigueur » (tué)"
        },
        {
          "file": "test/journal.test.js",
          "describe": "CT-1 : dossier de preuve",
          "it": "rejoue dossiers/ : le dossier valide et chaque dossier invalide donnent exactement les contrôles attendus"
        }
      ]
    },
    "response_removed": {
      "what": "AT-7 ne compare que des noms ; FP dit « de même nom », jamais la vigueur (CT-1 AT-7 ; CT-6 EX-6.19)",
      "how": "Faire dire « en vigueur » à FP",
      "where": "scripts/lib/verificateur.mjs"
    },
    "attack": "Dossier valide-at7-nom-reannonce.",
    "expected_with_response": "FP : « de même nom ».",
    "expected_without_response": "FP : « en vigueur » ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-92",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "failed ; la condition d'EX-5.10 est couverte par le test existant sec331.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-92 (MN-92) : invalide-cr4-temoin-auditeur-seul échoue à CR-4 ; mutant où l'auditeur peut remplacer le témoin : CR-4 passe (tué)"
        },
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : vecteurs ceremonies/ (annexe A.4, EX-A.6, EX-A.19)",
          "it": "verifierCeremonie rend exactement attendu.json pour chaque cas ; chaque cas invalide échoue à la vérification que son nom annonce"
        },
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : vecteurs ceremonies/ (annexe A.4, EX-A.6, EX-A.19)",
          "it": "EX-5.10 : la clé d'enregistreur et la clé de chaîne d'un procès-verbal vérifié sont celles de la ligne recorders du fichier d'ancres de test de ct-6 pour rec-test-01"
        }
      ]
    },
    "response_removed": {
      "what": "Témoin distinct de l'exécutant à chaque étape, l'auditeur s'ajoutant sans le remplacer (CR-4 ; CT-7 EX-5.9, EX-5.2) ; ancre du réviseur sous la condition d'EX-5.10",
      "how": "Retirer la règle du témoin",
      "where": "scripts/lib/securite.mjs"
    },
    "attack": "Cas invalide-cr4-temoin-auditeur-seul.",
    "expected_with_response": "CR-4 en échec.",
    "expected_without_response": "Passe ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-93",
    "preconditions": [
      "Cas de vecteur « valide-production-sans-ancre » à ajouter (PD-9)."
    ],
    "steps": [
      "Ajouter la réserve au rapport de verifierCeremonie ; rejouer le cas."
    ],
    "oracle": "Réserve présente dans le rapport.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Réponse non codée dans l'implémentation de référence (voir `notes`, PD-13) et cas de vecteur « valide-production-sans-ancre » absent (PD-9) : test possible sur le dépôt sans composant de la phase 2, donc rattaché à l'étape 8 (EX-3.10). La version 0.1 le rattachait à tort à l'étape 4 : la vérification des procès-verbaux de cérémonie n'est pas un livrable de l'enregistreur."
    },
    "response_removed": {
      "what": "D_C ancré par un jeton RFC 3161 joint ou une inscription au registre en production (CT-7 EX-5.11) ; recoupement avec l'inscription (EX-5.10)",
      "how": "Accepter un procès-verbal de production sans ancre de D_C sans réserve",
      "where": "scripts/lib/securite.mjs (verifierCeremonie), scripts/verify/ceremonie.mjs"
    },
    "attack": "Procès-verbal de production valide, sans ancre de D_C.",
    "expected_with_response": "Le rapport signale « daté par déclaration seulement » (réserve, sans changer le verdict).",
    "expected_without_response": "Accepté sans réserve ; le test échoue.",
    "execution": "vecteurs_et_depot",
    "notes": "Au 2026-11-01, verifierCeremonie ne lit aucune ancre de D_C (grep « anchor », « ancre » dans la partie cérémonie : aucune) : la réserve d'EX-5.11 n'est pas codée ; mutant survivant aujourd'hui."
  },
  {
    "id": "TA-94",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "failed.",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-94 (MN-94) : invalide-cr12-restauration-sans-detenteur échoue à CR-12 ; mutant sans le compte des détenteurs de part : CR-12 passe (tué)"
        },
        {
          "file": "test/securite.test.js",
          "describe": "CT-7 : vecteurs ceremonies/ (annexe A.4, EX-A.6, EX-A.19)",
          "it": "verifierCeremonie rend exactement attendu.json pour chaque cas ; chaque cas invalide échoue à la vérification que son nom annonce"
        }
      ]
    },
    "response_removed": {
      "what": "CR-12 : restauration avec purpose_details k, n et au moins k détenteurs de part (CT-7 EX-5.9, EX-5.5)",
      "how": "Retirer le compte des détenteurs",
      "where": "scripts/lib/securite.mjs"
    },
    "attack": "Cas invalide-cr12-restauration-sans-detenteur.",
    "expected_with_response": "CR-12 en échec.",
    "expected_without_response": "Passe ; le test échoue.",
    "execution": "vecteurs_et_depot"
  },
  {
    "id": "TA-95",
    "preconditions": [
      "Répétition de cérémonie de la porte 2 avec un témoin qui ignore le scénario ; CR-7 n'y voit rien (deux identifiants distincts)."
    ],
    "steps": [
      "Jouer la remise des parts avec un figurant sous deux noms ; relever findings du procès-verbal."
    ],
    "oracle": "Un constat du témoin nomme la coïncidence.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Épreuve de procédure humaine, conduite à la répétition de cérémonie de la porte 2 (phase 2, étape 8)."
    },
    "response_removed": {
      "what": "Le témoin constate l'identité distincte de chaque détenteur de part et le consigne (CT-7 EX-5.2, §5.9)",
      "how": "Omettre le constat du témoin",
      "where": "procédure de cérémonie (répétition de la porte 2)"
    },
    "attack": "Cérémonie de sauvegarde où la même personne reçoit deux parts sous deux noms.",
    "expected_with_response": "Le témoin relève la coïncidence dans findings ; la cérémonie est reprise.",
    "expected_without_response": "Rien ne le relève ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-96",
    "preconditions": [
      "Démonstration de référence de CT-2 §19 (docker compose : agent, enregistreur, serveur d'outils HTTP, simulateur de modèle) construite et lancée ; phase 2, étape 8.",
      "Copie WORM du journal d'exploitation (CT-8 EX-11.22) sur le support de test."
    ],
    "steps": [
      "Faire tourner un fichier du journal ; attendre la copie ; effacer une ligne du fichier local ; comparer."
    ],
    "oracle": "Écart détecté entre local et copie.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Démonstration de référence et tests de bout en bout : phase 2, étape 8."
    },
    "response_removed": {
      "what": "Changements de policy annoncés dans la chaîne (CT-2 EX-9.2) ; copie WORM des fichiers tournés du journal d'exploitation (PA-18)",
      "how": "Ne pas copier le journal d'exploitation",
      "where": "tâche d'exploitation (CT-8 EX-11.22)"
    },
    "attack": "Effacement d'une ligne du journal d'exploitation de la démonstration après copie.",
    "expected_with_response": "La comparaison à la copie WORM montre la discontinuité.",
    "expected_without_response": "Inaperçue ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-97",
    "preconditions": [
      "Répétition de cérémonie de la porte 2 (comme TA-95) : signataire, outil de référence (`scripts/conformite/attestation.mjs condenser`), second outil indépendant (`go run . condenser` du module Go de `ct-7`)."
    ],
    "steps": [
      "Remettre au signataire un outil de référence altéré (copie de `scripts/lib/securite.mjs` dont `PREFIXE_ATTESTATION` vaut `…/v1`) et le second outil intact.",
      "Observer la procédure de signature : recalcul de D_P par le second outil, comparaison groupe par groupe (CT-7 EX-5.8, EX-7.8), décision."
    ],
    "oracle": "Avec la comparaison : écart constaté, signature refusée ; sans elle : la signature est produite sur le D_P de l'outil altéré. La parité JS/Go des deux outils sur l'exemple est éprouvée dès maintenant par TV-62 (test de `test/plan-de-tests.test.js`, en attente sans `go`).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Épreuve de procédure humaine (répétition de cérémonie de la porte 2, comme TA-95) : la réponse est une obligation du signataire, non un code ; la parité JS/Go est déjà testée (TV-62)."
    },
    "response_removed": {
      "what": "Comparaison du condensé à un second outil indépendant (CT-7 EX-5.8, EX-7.8, EX-A.21)",
      "how": "Le signataire omet le recalcul de D_P par le second outil et la comparaison groupe par groupe (CT-7 EX-5.8, EX-7.8)",
      "where": "procédure de signature, répétition de cérémonie de la porte 2"
    },
    "attack": "Outil de référence altéré qui affiche un autre D_P (préfixe de condensé changé).",
    "expected_with_response": "Écart constaté groupe par groupe ; signature refusée.",
    "expected_without_response": "La signature est produite sur le D_P de l'outil altéré ; AT-2 chez le réviseur le détecte après coup ; le test échoue.",
    "execution": "phase_2"
  },
  {
    "id": "TA-98",
    "preconditions": [
      "Vecteurs et bibliothèques de référence du dépôt au commit éprouvé ; Node.js 22."
    ],
    "steps": [
      "Rejouer l'oracle sur la bibliothèque de référence.",
      "Fabriquer le mutant (copie de scripts/ avec le remplacement nommé) et rejouer.",
      "Comparer : la référence rend l'attendu des vecteurs, le mutant ne le rend plus."
    ],
    "oracle": "statement.fr. Le texte de MN-98 cite valide-seq-7-complet-attestation : ce dossier porte une inscription ; la clause s'observe sur un dossier sans inscription (PD-11).",
    "status": {
      "state": "executable",
      "tests": [
        {
          "file": "test/adversarial.test.js",
          "describe": "CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)",
          "it": "TA-85 et TA-98 (MN-85, MN-98) : sans inscription, le fragment FP porte la clause fixe « non inscrite au journal (ni sa date ni son rang ne sont établis) » (ct-1 valide-seq-7-attestation-sans-inscription, ct-6 valide-seq-7-complet-attestation-non-retenue exclu car non retenue) ; mutant qui annonce une inscription : la clause disparaît (tué)"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : dossiers complets de spec/vecteurs/ct-6 par la ligne de commande",
          "it": "chaque dossier rend le code, les vérifications en échec, les statuts, les non-exécutions, les avertissements, l'énoncé et la borne de son attendu.json (V-1 à V-5)"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 révision 0.3 : attestation de périmètre (section 5.5, EX-6.19 à EX-6.21, V-10)",
          "it": "FP de l'exemple d'EX-6.19 (français et anglais) et ligne lisible « Périmètre » (EX-8.10) ; AT- en échec « (sans effet sur le verdict) »"
        }
      ]
    },
    "response_removed": {
      "what": "Inscription exigée dès que possible (CT-7 EX-7.5) ; clause fixe de FP (CT-6 EX-6.19)",
      "how": "Annoncer une inscription dans FP",
      "where": "scripts/lib/verificateur.mjs"
    },
    "attack": "Dossier sans inscription (valide-seq-7-attestation-sans-inscription de ct-1 ; le dossier ct-6 valide-seq-7-complet-attestation porte, lui, une inscription seq 12).",
    "expected_with_response": "Clause « non inscrite au journal (ni sa date ni son rang ne sont établis) ».",
    "expected_without_response": "Disparaît ; le test échoue.",
    "execution": "vecteurs_et_depot"
  }
];

export const SCENARIOS = [
  {
    "id": "TA-99",
    "scenario": "l'agent supprime ou réécrit",
    "composition": [
      "TA-1",
      "TA-2",
      "TA-3",
      "TA-4",
      "TA-5",
      "TA-6",
      "TA-7",
      "TA-9",
      "TA-15",
      "TA-22"
    ],
    "attack": "L'agent (ou l'hôte) tente d'agir hors du mandataire, de se faire passer pour un autre demandeur, de fractionner, de faire lire une valeur et exécuter une autre, de rejouer une approbation, d'inonder les approbateurs, d'annoncer un outil réservé, et d'atteindre le journal.",
    "preconditions": [
      "Démonstration de référence de CT-2 §19 (docker compose : agent, enregistreur, serveur d'outils HTTP, simulateur de modèle) construite et lancée ; phase 2, étape 8."
    ],
    "steps": [
      "Jouer les attaques de TA-1, TA-2, TA-3, TA-4, TA-5, TA-6, TA-7, TA-9, TA-15 et TA-22 dans la démonstration.",
      "Exporter le dossier de chaque appel retenu ; vérifier hors ligne."
    ],
    "oracle": "Chaque tentative est refusée ou journalisée comme le dit son TA- ; aucun événement n'est absent ni réécrit : le vérificateur accepte les dossiers et la série des points est continue. Borne (risques acceptés des tests composés) : RA-1, RA-2, RA-3, RA-4, RA-5, RA-6, RA-8, RA-13, RA-19.",
    "phase2_step": 8,
    "expected_without_response": "Une tentative de l'agent aboutit sans refus ni journalisation (connexion directe au serveur d'outils, fractionnement sous le plafond, approbation rejouée, outil réservé annoncé) : le test composé concerné et le scénario échouent."
  },
  {
    "id": "TA-100",
    "scenario": "l'opérateur réécrit après coup",
    "composition": [
      "TA-17",
      "TA-18",
      "TA-19",
      "TA-23",
      "TA-26",
      "TA-27",
      "TA-28",
      "TA-74",
      "TA-84",
      "TA-85",
      "TA-86",
      "TA-96"
    ],
    "attack": "Celui qui tient l'enregistreur réécrit des événements couverts ou non par un point ancré, remplace la politique sans annonce, redémarre sans trace, choisit ce qu'il exporte, antidate une attestation, efface le journal d'exploitation, écrit une seconde version d'un segment copié ou lève un gel seul.",
    "preconditions": [
      "Démonstration de référence de CT-2 §19 (docker compose : agent, enregistreur, serveur d'outils HTTP, simulateur de modèle) construite et lancée ; phase 2, étape 8.",
      "Accès d'administrateur au volume du journal de la démonstration."
    ],
    "steps": [
      "Réécrire un événement couvert par un point ancré et le signer de nouveau ; exporter.",
      "Tenter la fourche (deux écrivains) ; remplacer la politique sans annonce ; redémarrer ; effacer une ligne du journal d'exploitation ; écrire une seconde version d'un segment copié sur le support WORM ; lever un gel par la seule identité qui l'a posé.",
      "Vérifier chaque dossier avec les ancres du réviseur et la série des points."
    ],
    "oracle": "K-7 ou K-8 échoue sur l'événement réécrit ; la fourche est refusée ; l'absence d'annonce et le redémarrage sont visibles (événement de politique, ligne startup, point manquant) ; l'effacement est détecté par la copie WORM ; la seconde version du segment copié est non_conforme et la levée par la même identité est refusée (meme_identite). Borne (risques acceptés des tests composés) : RA-15, RA-16, RA-17, RA-20, RA-23, RA-24, RA-63, RA-66, RA-71, RA-72, RA-80 : ce qui n'est couvert par aucun point ancré, l'acte jamais journalisé et la rétention du support au-delà de ce que son API rend ne sont pas détectés.",
    "phase2_step": 8,
    "expected_without_response": "Un événement réécrit couvert par un point passe le vérificateur, ou une seconde version d'un segment copié est acceptée sans alerte, ou un gel est levé par qui l'a posé : le test composé concerné et le scénario échouent."
  },
  {
    "id": "TA-101",
    "scenario": "l'horloge est manipulée",
    "composition": [
      "TA-21",
      "TA-60",
      "TA-76",
      "TA-93"
    ],
    "attack": "Recul ou saut de l'horloge de l'enregistreur, jeton antidaté ou postdaté, réponse tardive, cérémonie antidatée.",
    "preconditions": [
      "Démon de l'enregistreur construit (phase 2, étape 4), configuration de l'installation rapide (CT-8 §7.3).",
      "Horloge du conteneur de l'enregistreur pilotable (libfaketime par LD_PRELOAD sur le processus Node, hors binaires Go ; ou horloge injectée des bibliothèques)."
    ],
    "steps": [
      "Reculer puis avancer l'horloge au-delà des seuils pendant la capture.",
      "Servir un jeton RFC 3161 à genTime décalé par le simulateur ; servir une réponse tardive."
    ],
    "oracle": "Mode dégradé horloge, AV-K-2 ou AV-K-4 au rapport, horloge_suspecte et reponse_tardive consignés ; les dates des événements restent bornées par les contresignatures extérieures. Non testé : une horloge fausse mais cohérente dans la tolérance (RA-18, RA-54).",
    "phase2_step": 8,
    "expected_without_response": "Un événement est scellé à une date reculée ou avancée sans mode dégradé, ou un jeton à genTime décalé est promu sans horloge_suspecte, ou une réponse tardive est acceptée : le test composé concerné et le scénario échouent."
  },
  {
    "id": "TA-102",
    "scenario": "l'enregistreur tombe",
    "composition": [
      "TA-10",
      "TA-19",
      "TA-20",
      "TA-26",
      "TA-29",
      "TA-33",
      "TA-64"
    ],
    "attack": "Panne du démon après relais, segment tronqué, redémarrage, bascule mal faite (deux instances actives), copie WORM impossible, signataire injoignable, file d'ancrage perdue.",
    "preconditions": [
      "Démon de l'enregistreur construit (phase 2, étape 4), configuration de l'installation rapide (CT-8 §7.3).",
      "Points d'injection de panne du démon (tests de la phase 2)."
    ],
    "steps": [
      "Tuer le démon après le pas 9 ; tronquer le dernier segment ; redémarrer ; provoquer une bascule avec l'ancienne instance encore active (bail, époque, jeton de clôture).",
      "Couper le support WORM ; arrêter le backend de signature ; effacer la file d'ancrage ; redémarrer."
    ],
    "oracle": "Événement de reprise, troncature à la dernière ligne complète, ligne startup, un seul écrivain accepté après la bascule (l'ancienne instance est refusée), alertes WORM et clé, file reconstruite avec alerte file_perdue ; aucun événement non signé ni perdu sans trace. Borne (risques acceptés des tests composés) : RA-9, RA-17, RA-25, RA-29, RA-66, RA-67.",
    "phase2_step": 8,
    "expected_without_response": "Deux écrivains actifs écrivent dans la même période, ou un segment tronqué est relu comme complet, ou la file perdue n'est pas reconstruite : le test composé concerné et le scénario échouent."
  },
  {
    "id": "TA-103",
    "scenario": "un prestataire est injoignable",
    "composition": [
      "TA-55",
      "TA-58",
      "TA-62",
      "TA-63",
      "TA-76"
    ],
    "attack": "Prestataire RFC 3161 principal injoignable, registre saturé ou empreinte squattée, calendriers OpenTimestamps absents, réponses tardives.",
    "preconditions": [
      "Démon de l'enregistreur construit (phase 2, étape 4), configuration de l'installation rapide (CT-8 §7.3).",
      "Composant d'ancrage construit (phase 2, étape 5) ; simulateurs de prestataires coupables."
    ],
    "steps": [
      "Couper le principal ; mesurer la relève et la fenêtre de date (CT-5 P-3) ; couper aussi le secours.",
      "Saturer la mempool du réseau de développement ; faire squatter une empreinte."
    ],
    "oracle": "Relève consignée, alertes prestataire_injoignable et ancre en retard aux échéances de CT-5 §8.9, empreinte_squattee sans nouvel essai, aucun blocage de la capture (CT-2 §14.2) ; la fenêtre de réécriture mesurée (CT-5 §3.3) est rapportée dans TM-42 (`w_date_porte_2`, `w_date_defaut`) et TM-13 (`d_jeton`). Borne (risques acceptés des tests composés) : RA-50, RA-52, RA-55, RA-56, RA-65.",
    "phase2_step": 8,
    "expected_without_response": "La relève n'est pas consignée, ou une alerte prestataire_injoignable ou ancre en retard manque à son échéance, ou l'empreinte squattée est réessayée, ou la capture se bloque : le test composé concerné et le scénario échouent."
  }
];
