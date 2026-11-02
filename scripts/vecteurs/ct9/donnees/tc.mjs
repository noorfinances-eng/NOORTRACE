// Source de données du catalogue CT-9 : réponses aux occurrences de « CT-9 »
// dans spec/*.md (0.2), dans l'ordre des fichiers puis des lignes ; le
// générateur relit les occurrences et exige la même clé à chaque rang.

export const TC_REPONSES = [
  {
    "key": "CT-1 §12",
    "delegated": "Tests d'interopérabilité des trois correspondances d'export (OTel GenAI, projet IETF, SCITT) ; « aucune n'est implémentée en v0 ».",
    "response": "§8 (TI- d'export, à écrire, étape 8) ; SCITT : justification NC- hors version 0 (§5.3) ; proposition PD- sur RFC 9942 (§17.2)."
  },
  {
    "key": "CT-2 §0.1",
    "delegated": "Rattachement des tests aux identifiants EX-.",
    "response": "§5.1, règle (a) ; membre `covers` de chaque entrée (§4.1)."
  },
  {
    "key": "CT-2 §1",
    "delegated": "Périmètre : les tests sont hors de CT-2.",
    "response": "Ce document."
  },
  {
    "key": "CT-2 §1",
    "delegated": "Lit les EX-, les vecteurs (annexe B), la méthode de mesure (16) ; fixe les tests.",
    "response": "§7 (TV- de `ct-2`), §6 (TU- de CT-2), §11 (TM- de CT-2 §16)."
  },
  {
    "key": "CT-2 §10.4",
    "delegated": "Réappliquer la politique à une pièce stockée : égalité des octets (idempotence).",
    "response": "TV- `ct-2/redaction/` (§7), oracle « la seconde application ne change aucun octet »."
  },
  {
    "key": "CT-2 §15.6",
    "delegated": "Règles de configuration que le schéma n'exprime pas : tests de CT-9.",
    "response": "TU- configuration et contrôles de démarrage (§6) ; TV- `ct-2/pieces-*` ; TE- installation (§9) pour la commande du démon."
  },
  {
    "key": "CT-2 §16.2",
    "delegated": "Seuil de régression des mesures de performance, à décider par CT-9.",
    "response": "§11.4 : seuil de régression EX-11.15 ; proposition PD- à CT-2 EX-16.2 pas 7 (§17.2)."
  },
  {
    "key": "CT-2 §21",
    "delegated": "« Les tests » hors de CT-2.",
    "response": "Ce document."
  },
  {
    "key": "CT-3 §0",
    "delegated": "Rattachement aux EX-.",
    "response": "§5.1, règle (a)."
  },
  {
    "key": "CT-3 §1",
    "delegated": "Périmètre.",
    "response": "Ce document."
  },
  {
    "key": "CT-3 §1",
    "delegated": "EX-, AP-, TK-, SG-, AN-, CS-, vecteurs `ct-3`, épreuve à trois relecteurs, épreuve de lecture de la console.",
    "response": "TR-1 (A.5, trois relecteurs) et TR-2 (A.11, console) en §12 ; EX-, AP-, TK-, SG-, AN-, CS- et vecteurs ct-3 : TU-, TV- (§6, §7)."
  },
  {
    "key": "CT-3 §7.12",
    "delegated": "Rattachement des TK-1 à TK-13 aux tests.",
    "response": "TV- `ct-3/tickets/` et TU- tickets (§6, §7) : `covers` CT-3 TK-1 à TK-13."
  },
  {
    "key": "CT-4 §0",
    "delegated": "Rattachement aux EX-.",
    "response": "§5.1, règle (a)."
  },
  {
    "key": "CT-4 §1",
    "delegated": "Périmètre.",
    "response": "Ce document."
  },
  {
    "key": "CT-4 §1",
    "delegated": "EX-, RG-, vecteurs `ct-4`, épreuve d'acceptation sur le réseau de développement.",
    "response": "TR-3 (§7.12, relecteur sur le réseau de développement) en §12 ; EX-, RG- et vecteurs ct-4 : TV- (§7), TE- (§9)."
  },
  {
    "key": "CT-5 §0",
    "delegated": "Rattachement aux EX-.",
    "response": "§5.1, règle (a)."
  },
  {
    "key": "CT-5 §1",
    "delegated": "Périmètre.",
    "response": "Ce document."
  },
  {
    "key": "CT-5 §1",
    "delegated": "EX-, AN-, vecteurs `ct-5`, épreuve à l'aveugle à deux relecteurs.",
    "response": "TR-4 (relecteur CT-5 et CT-1 §9 à §11) et TR-5 (second relecteur, CT-6 §7) en §12 ; consigne et grille sous spec/vecteurs/ct-9/ (EX-12.7) ; EX-, AN- et vecteurs ct-5 : TV- (§7)."
  },
  {
    "key": "CT-5 §3.6",
    "delegated": "Mesures P-1 à P-6 sur le réseau de développement et sur les vecteurs.",
    "response": "TM-10 à TM-16 (P-1 à P-6) en §11 : sur les vecteurs (TM-10, TM-15 exécutables), sur le réseau de développement (TM-11 à TM-14, à écrire, étape 5) et sur le support WORM (TM-16, à écrire, étape 4)."
  },
  {
    "key": "CT-5 §5.3",
    "delegated": "Test à écrire : relève par le secours qualifié après retrait de `qualified` (EX-5.9).",
    "response": "TI- prestataires réels (§8), étape 5 ; oracle « relève de la clôture tant que la configuration n'est pas rechargée »."
  },
  {
    "key": "CT-5 §7.2",
    "delegated": "AN-24 à AN-32 du serveur interne vérifiées sur un jeton émis.",
    "response": "TM-18 (AN-26) et TM-19 (AN-24) en §11 pour les exigences mesurables sur un jeton émis ; AN-22, AN-23, AN-25, AN-27 à AN-31 : TI- prestataires et serveur interne (§8)."
  },
  {
    "key": "CT-5 §7.2",
    "delegated": "Épreuve de redémarrage du serveur interne (AN-26).",
    "response": "TM-18 (AN-26, épreuve de redémarrage du serveur interne) et TM-19 (AN-24) en §11."
  },
  {
    "key": "CT-5 §14",
    "delegated": "Même test que la ligne 1120.",
    "response": "TM-10 à TM-17 (P-1 à P-6, mesures en charge) en §11 ; TR-4 et TR-5 en §12 ; l'état « proposition » est levé par ce document."
  },
  {
    "key": "CT-5 §14",
    "delegated": "Tests EX- et AN-1 à AN-61, mesures P-1 à P-6, épreuve à l'aveugle.",
    "response": "§6, §7, §8, §11, §12 ; état « proposition » levé par ce document."
  },
  {
    "key": "CT-6 §0",
    "delegated": "Rattachement aux EX-.",
    "response": "§5.1, règle (a)."
  },
  {
    "key": "CT-6 §1",
    "delegated": "EX-, T-, O-, R-, N-, V-, vecteurs `ct-6`.",
    "response": "§6 (TU- jeton, preuve, registre), §7 (TV- de `ct-6`, dont V-1 à V-10)."
  },
  {
    "key": "CT-6 §6.9",
    "delegated": "Exécution des V- par comparaison du rapport à `attendu.json`.",
    "response": "TV- `ct-6/dossiers/` (§7) : oracle = rapport comparé à `attendu.json`."
  },
  {
    "key": "CT-7 §0.1",
    "delegated": "Rattachement aux EX-.",
    "response": "§5.1, règle (a)."
  },
  {
    "key": "CT-7 §0.2",
    "delegated": "Revue de code de l'enregistreur, périmètre fixé par CT-7 (3.2, 3.4).",
    "response": "§13 (TQ- enregistreur)."
  },
  {
    "key": "CT-7 §0.3",
    "delegated": "Ce que l'auteur de CT-9 lit dans CT-7.",
    "response": "Ce document ; annexe A."
  },
  {
    "key": "CT-7 §1",
    "delegated": "Un test par menace.",
    "response": "§10 : un TA- par menace, TA-1 à TA-98, même numéro que la menace (EX-10.1) ; cinq scénarios TA-99 à TA-103 (§10.5)."
  },
  {
    "key": "CT-7 §1",
    "delegated": "Revue de code.",
    "response": "§13 (TQ-)."
  },
  {
    "key": "CT-7 §1",
    "delegated": "Colonne « Test de CT-9 » de 3.4.",
    "response": "TR-6, TR-7, TR-8 (les trois épreuves de la section 9) en §12 ; un TA- par menace (§10, table 10.4 imprimée depuis `catalogue.json`) ; CR-, AT-, RV-, MX- et vecteurs ct-7 : TV- (§7), TU- (§6)."
  },
  {
    "key": "CT-7 §1",
    "delegated": "Colonne « Test de CT-9 » de 3.4.",
    "response": "TR-6, TR-7, TR-8 (les trois épreuves de la section 9) en §12 ; un TA- par menace (§10, table 10.4 imprimée depuis `catalogue.json`) ; CR-, AT-, RV-, MX- et vecteurs ct-7 : TV- (§7), TU- (§6)."
  },
  {
    "key": "CT-7 §3.1",
    "delegated": "Le test que CT-9 doit écrire (colonnes de 3.4).",
    "response": "EX-10.2 : le membre `threat_test_text` de chaque TA- est la cellule « Test de CT-9 » de 3.4 ; l'oracle du TA- la précise."
  },
  {
    "key": "CT-7 §3.1",
    "delegated": "Critère : le test échoue si la réponse est retirée.",
    "response": "EX-10.1, EX-10.3 : réponse retirée nommée (`response_removed`), mutant tué ; §10.8 pour les mutants exécutés le 2026-11-01."
  },
  {
    "key": "CT-7 §3.4",
    "delegated": "Préfixe fixe de la colonne.",
    "response": "EX-10.2 : `threat_test_text` commence par ce préfixe fixe (contrôlé par le schéma)."
  },
  {
    "key": "CT-7 §3.4",
    "delegated": "Les tests de MN-22 et MN-9 valent pour l'agent.",
    "response": "TA-22 et TA-9 (phase 2, étapes 8 et 4) ; scénario TA-99 (§10.5)."
  },
  {
    "key": "CT-7 §3.4",
    "delegated": "En-tête de la table 3.4.",
    "response": "§10 ; index des TA- par menace (annexe A)."
  },
  {
    "key": "CT-7 §3.8",
    "delegated": "Cellule « Test de CT-9 » = membre `test` privé du préfixe.",
    "response": "EX-10.2 : le catalogue lit `menaces.json`, jamais la table du texte ; l'outil de couverture compare `threat_test_text` au membre `test`."
  },
  {
    "key": "CT-7 §4.1",
    "delegated": "Inventaire CLE- à jour, contrôlé par la revue de CT-9.",
    "response": "TQ- inventaire des clés (§13)."
  },
  {
    "key": "CT-7 §7.9",
    "delegated": "Parité de l'attestation : exigences mesurées par CT-9 (EX-7.18).",
    "response": "TM-20 (EX-7.18, six points constatés sur les vecteurs, exécutable) en §11."
  },
  {
    "key": "CT-7 §7.9",
    "delegated": "Test sur tous les rapports des vecteurs : aucun « prouvé » appliqué au périmètre.",
    "response": "TV- `ct-6/dossiers/` (§7), exécutable : `test/verificateur.test.js`, it « EX-7.3 de CT-6, EX-7.18 point 3 de CT-7 : aucun texte des rapports n'applique « prouvé », … »."
  },
  {
    "key": "CT-7 §7.10",
    "delegated": "Tests des menaces de l'attestation MN-78 à MN-91, MN-98.",
    "response": "TA-78 à TA-91 et TA-98 (§10.4) : tous exécutables sauf TA-88 (phase 2, étape 4, après PA-10)."
  },
  {
    "key": "CT-7 §10",
    "delegated": "Revue de code, non faite.",
    "response": "§13 (TQ-), état « à écrire », étape 8."
  },
  {
    "key": "CT-7 §A.11",
    "delegated": "Menaces reliées à un test déjà possible (vecteurs de CT-1 à CT-6).",
    "response": "§10.4 : état « exécutable » avec le fichier et le titre exact du test du dépôt (règle de couverture (d), EX-5.4)."
  },
  {
    "key": "CT-7 §A.11",
    "delegated": "Les autres tests sont écrits par CT-9.",
    "response": "§10.4 : états « à écrire » (étape de la phase 2 et blocage nommés) ou « exécutable » avec complément à écrire ; chaque entrée a ses préconditions, ses pas et son oracle."
  },
  {
    "key": "CT-8 « en-tête »",
    "delegated": "Convention « à mesurer (CT-9, porte 2) ».",
    "response": "§11 : chaque cible « à mesurer (CT-9, porte 2) » a sa ligne TM-21 à TM-40 avec cible, source et seuil d'échec ; colonne mesure vide en 0.1 (EX-11.16)."
  },
  {
    "key": "CT-8 « en-tête »",
    "delegated": "Critère du plan (moins d'une journée) mesuré à la porte 2.",
    "response": "TM-22 (durée de chaque pas IC-1 à IC-18, durée totale, attente relevée à part) et TM-23 (informations manquantes)."
  },
  {
    "key": "CT-8 « en-tête »",
    "delegated": "Ce que CT-9 chronomètre (EX-8.1).",
    "response": "TM- EX-8.1 (§11)."
  },
  {
    "key": "CT-8 §0.1",
    "delegated": "Rattachement aux EX-.",
    "response": "§5.1, règle (a)."
  },
  {
    "key": "CT-8 §0.1",
    "delegated": "Convention « cible ».",
    "response": "§2 (terminologie) et §11.4 : une cible devient une mesure par un rapport de mesure (EX-11.11) sur le système de référence (EX-11.1)."
  },
  {
    "key": "CT-8 §0.2",
    "delegated": "Ordre d'écriture (traçabilité TC-104 de CT-8).",
    "response": "Ce document ; aucune réponse attendue."
  },
  {
    "key": "CT-8 §0.3",
    "delegated": "Ce que l'auteur de CT-9 lit dans CT-8.",
    "response": "Ce document ; annexe A."
  },
  {
    "key": "CT-8 §1",
    "delegated": "Périmètre.",
    "response": "Ce document."
  },
  {
    "key": "CT-8 §1",
    "delegated": "Onze familles, budgets, cibles, vecteurs `ct-8`, épreuves §14.",
    "response": "Mesures de la porte 2 : TM-21 à TM-40 (§11) ; épreuves de §14 : TR-9, TR-10, TR-11 (§12) ; EX-, CO-, IP-, IR-, IC-, DM-, SV-, PV-, CA-, OB-, PR- et vecteurs ct-8 : TV- (§7), TE- (§9)."
  },
  {
    "key": "CT-8 §2",
    "delegated": "Budget de temps chronométré par CT-9.",
    "response": "TM-21 (IR-1 à IR-8) et TM-22 (IC-1 à IC-18) : chaque pas chronométré contre son budget, la somme contre la cible (EX-11.3, méthode `chronometre`)."
  },
  {
    "key": "CT-8 §3.3",
    "delegated": "Épreuve de construction : volume nommé neuf.",
    "response": "TE- construction des images (§9), étape 7."
  },
  {
    "key": "CT-8 §3.4",
    "delegated": "Cible : pose de l'attribut immuable sous 60 s.",
    "response": "TM-26 (compagnon : pose des attributs ≤ 60 s)."
  },
  {
    "key": "CT-8 §3.4",
    "delegated": "Épreuve de construction : compagnon, ouverture en lecture.",
    "response": "TE- construction des images (§9)."
  },
  {
    "key": "CT-8 §3.5",
    "delegated": "Cible : TTL DNS ≤ 30 s.",
    "response": "TM-27 (TTL DNS du répartiteur ≤ 30 s)."
  },
  {
    "key": "CT-8 §3.6",
    "delegated": "Mesure : égalité de deux constructions des images.",
    "response": "TM-28 (égalité des condensés de deux constructions)."
  },
  {
    "key": "CT-8 §3.6",
    "delegated": "Revue de code et RA-22.",
    "response": "TQ- chaîne de construction et de publication (§13)."
  },
  {
    "key": "CT-8 §4.4",
    "delegated": "Épreuves de construction : images, `docker compose up`, `docker inspect`.",
    "response": "TE- construction des images (§9)."
  },
  {
    "key": "CT-8 §5.3",
    "delegated": "Épreuve d'intégration ICAP.",
    "response": "TI- mode ICAP (§8), étape 4."
  },
  {
    "key": "CT-8 §6.2",
    "delegated": "Seuils « cible » du contrôle préalable.",
    "response": "TM-29 (seuils cibles IP-2, IP-3 confrontés à la consommation observée)."
  },
  {
    "key": "CT-8 §7.1",
    "delegated": "Chronométrage IR-1 à IR-8 (900 s).",
    "response": "TM-21 (900 s, pas par pas, chaque durée publiée atteinte ou non) ; TR-9 ; critère de la porte 2 « installation par une personne extérieure en 15 min » (§14)."
  },
  {
    "key": "CT-8 §7.2",
    "delegated": "Mesure : taille des images téléchargées.",
    "response": "TM-24 (taille des images et durée du téléchargement, relevées à part du budget d'IR-6)."
  },
  {
    "key": "CT-8 §8.1",
    "delegated": "Titre « Durée et ce que CT-9 mesure ».",
    "response": "§11 : TM-22, TM-23 ; TE- d'A pour les verdicts du contrôle préalable final et du premier dossier."
  },
  {
    "key": "CT-8 §8.1",
    "delegated": "Le système de référence est fixé par CT-9.",
    "response": "EX-11.1 (système de référence fixé en §11.1) ; TM-22 (durées), TM-23 (informations manquantes) ; verdicts IC-14 et IC-15 : TE-."
  },
  {
    "key": "CT-8 §8.1",
    "delegated": "Le système de référence est fixé par CT-9.",
    "response": "EX-11.1 (système de référence fixé en §11.1) ; TM-22 (durées), TM-23 (informations manquantes) ; verdicts IC-14 et IC-15 : TE-."
  },
  {
    "key": "CT-8 §8.3",
    "delegated": "Coefficients `f_pic`, `b_o`, `n_crl`, `b_crl` avant les mesures.",
    "response": "TM-33 (f_pic, b_o, b_acq, b_crl, n_crl) et TM-9 (m_0) ; IC-1 refait après mesure."
  },
  {
    "key": "CT-8 §8.3",
    "delegated": "Script de préparation de l'hôte éprouvé sur le système de référence.",
    "response": "Le script de préparation de l'hôte est éprouvé pendant TM-22 (IC-2) sur le système de référence d'EX-11.1 ; TE- (§9)."
  },
  {
    "key": "CT-8 §8.3",
    "delegated": "Attente d'IC-16 et IC-17 relevée à part.",
    "response": "TM-22 : ligne `ic_attente_cloture` relevée à part, dans la durée totale, hors de la durée du pas IC-15."
  },
  {
    "key": "CT-8 §8.3",
    "delegated": "Durées reportées pour CT-9 (procès-verbal IC-18).",
    "response": "TM-22 : les durées du procès-verbal d'IC-18 sont la source des lignes `ic_1` à `ic_18` et `ic_total`."
  },
  {
    "key": "CT-8 §9",
    "delegated": "Débit et latence de CT-2 §16.1 à mesurer.",
    "response": "TM-1 à TM-4 (cibles de CT-2 §16.1) en §11."
  },
  {
    "key": "CT-8 §9.2",
    "delegated": "Coefficients sans source : « à mesurer (CT-9) ».",
    "response": "TM-30 à TM-33 (coefficients marqués « à mesurer (CT-9) ») et TM-9 (m_0)."
  },
  {
    "key": "CT-8 §9.2",
    "delegated": "`b_ots` preuve mise à niveau.",
    "response": "TM-30 (octets d'une preuve .ots mise à niveau)."
  },
  {
    "key": "CT-8 §9.2",
    "delegated": "`b_cap` bloc plein.",
    "response": "TM-31 (octets de la capture d'une transaction d'un bloc plein)."
  },
  {
    "key": "CT-8 §9.2",
    "delegated": "`blocs_par_s` en production.",
    "response": "TM-32 (blocs_par_s sur l'instance de production)."
  },
  {
    "key": "CT-8 §9.2",
    "delegated": "Six coefficients à mesurer.",
    "response": "TM-30 à TM-33 (b_ots, b_cap, blocs_par_s, f_pic, b_o, b_acq, b_crl, n_crl) et TM-9 (m_0)."
  },
  {
    "key": "CT-8 §9.3",
    "delegated": "`m_0` à mesurer.",
    "response": "TM-9 (mémoire sous charge comparée à M_tamp)."
  },
  {
    "key": "CT-8 §9.3",
    "delegated": "Mesure de la mémoire au-delà de `M_tamp`.",
    "response": "TM- mémoire (§11)."
  },
  {
    "key": "CT-8 §10",
    "delegated": "Seuils d'alerte cibles.",
    "response": "TM-34 (seuils d'alerte cibles : faux positifs et faux négatifs)."
  },
  {
    "key": "CT-8 §10.6",
    "delegated": "Seuil mempool `<M>`.",
    "response": "TM-35 (seuil <M> de la mempool)."
  },
  {
    "key": "CT-8 §10.11",
    "delegated": "Durées des runbooks non mesurées.",
    "response": "TM-36 (durées de RB-1 à RB-8, publiées sans cible)."
  },
  {
    "key": "CT-8 §10.11",
    "delegated": "Un test de CT-9 par correction d'incident.",
    "response": "§3.2 (règle d'ajout d'une entrée) ; TE- runbooks (§9), oracle."
  },
  {
    "key": "CT-8 §11",
    "delegated": "RPO et RTO cibles.",
    "response": "TM-37 (RPO et RTO par composant, exercices de restauration)."
  },
  {
    "key": "CT-8 §11.2",
    "delegated": "Fréquence de sauvegarde de l'état du service (15 min).",
    "response": "TM-37 : ligne `sauvegarde_etat_service_cadence` (cible 15 min)."
  },
  {
    "key": "CT-8 §11.3",
    "delegated": "Table RPO/RTO : cibles à mesurer.",
    "response": "TM-37 (table d'EX-11.5, toutes les cibles sauf la borne du bail)."
  },
  {
    "key": "CT-8 §11.10",
    "delegated": "Journal d'accès des supports WORM : disponibilité et format vérifiés en CT-9.",
    "response": "TM-39 (journal d'accès du support WORM : disponibilité et format par fournisseur)."
  },
  {
    "key": "CT-8 §12.2",
    "delegated": "Latence en mode observation.",
    "response": "TM-38 (latence ajoutée en mode observation, paire avec et sans)."
  },
  {
    "key": "CT-8 §12.2",
    "delegated": "Durée d'écriture lente, cible de CT-2 §16.1.",
    "response": "TM-38 : ligne `observation_ecriture` (durée d'écriture, cible de CT-2 §16.1)."
  },
  {
    "key": "CT-8 §13.1",
    "delegated": "Parité du paquet réviseur mesurée par CT-9 (EX-13.1).",
    "response": "TM-25 (point 7) en §11 ; points 1 à 6 : TV- ct-8/paquets/ (§7) et TR-10 (§12)."
  },
  {
    "key": "CT-8 §13.1",
    "delegated": "Temps du réviseur < 30 min.",
    "response": "TM-25 (temps du réviseur < 30 min), relevé pendant TR-10."
  },
  {
    "key": "CT-8 §14",
    "delegated": "Conduite des trois épreuves de CT-8 §14.",
    "response": "TR-9, TR-10, TR-11 en §12, conduites selon le protocole commun de 12.1."
  },
  {
    "key": "CT-8 §14.2",
    "delegated": "Durée de l'épreuve (b), mesure de CT-9.",
    "response": "EX-12.4 : consignation `consignation_rejeu` (schéma, §12.1), CT-8 EX-14.10 généralisée à toutes les épreuves TR-."
  },
  {
    "key": "CT-8 §14.2",
    "delegated": "Consignation EX-14.10 par CT-9.",
    "response": "§12.1 (protocole commun) : consignation champ par champ."
  },
  {
    "key": "CT-8 §15",
    "delegated": "Conformité des images à leur description : épreuve de construction.",
    "response": "TE- construction des images (§9)."
  },
  {
    "key": "CT-8 §15",
    "delegated": "Script de préparation éprouvé sur le système de référence.",
    "response": "EX-11.1 : système de référence de la porte 2 fixé en §11.1."
  },
  {
    "key": "CT-8 §15",
    "delegated": "Système de référence fixé par CT-9.",
    "response": "§11.1."
  },
  {
    "key": "CT-8 §15",
    "delegated": "Cibles des sections 10 à 12 à mesurer.",
    "response": "TM-37 (RPO, RTO, restauration), TM-38 (latence en observation), TM-35 (mempool) en §11."
  },
  {
    "key": "CT-8 §15",
    "delegated": "Journal d'accès des supports : CT-9 l'établit.",
    "response": "TM-39 (journal d'accès par fournisseur) établit la source `journal_acces_support` avant que CT-8 EX-11.19 la tienne pour acquise."
  },
  {
    "key": "CT-8 §15",
    "delegated": "Budgets IR et IC à mesurer.",
    "response": "TM-21 (900 s) et TM-22 (450 min, 480 avec la réserve) en §11 ; porte 2 en §14."
  },
  {
    "key": "CT-8 §B.2",
    "delegated": "Ordre des champs de `chronyc -c tracking` à relever.",
    "response": "TM-40 (ordre des champs de chronyc -c tracking relevé sur chrony 4.6)."
  },
  {
    "key": "CT-8 §B.4",
    "delegated": "Latence en observation.",
    "response": "TM-38 (latence en observation)."
  },
  {
    "key": "CT-8 §B.5",
    "delegated": "Temps du réviseur.",
    "response": "TM-25 (temps du réviseur)."
  },
  {
    "key": "`spec/README.md` « Spécifications »",
    "delegated": "Ligne d'état de CT-9 dans la table des spécifications (version 0.1, contenu, revue pour la porte 1).",
    "response": "Ce document (en-tête) ; rien n'est délégué."
  },
  {
    "key": "`spec/README.md` « Spécifications »",
    "delegated": "Ligne d'état de CT-9 dans la table des spécifications (version 0.1, contenu, revue pour la porte 1).",
    "response": "Ce document (en-tête) ; rien n'est délégué."
  },
  {
    "key": "`spec/README.md` « Spécifications »",
    "delegated": "Ordre d'écriture des neuf spécifications : CT-9 en dernier.",
    "response": "Ce document, dernière spécification de la phase 1 ; rien n'est délégué."
  },
  {
    "key": "`spec/README.md` « Schémas (`schemas/`) »",
    "delegated": "Description du schéma `plan-de-tests-v0` : catalogue, rapport de couverture, rapport de mesure, consignation.",
    "response": "§4.2 (schéma), §5.4 (rapport de couverture), §11.3 (rapport de mesure), §12.1 (consignation) ; annexe A.2."
  },
  {
    "key": "`spec/README.md` « Schémas (`schemas/`) »",
    "delegated": "Description du schéma `plan-de-tests-v0` : catalogue, rapport de couverture, rapport de mesure, consignation.",
    "response": "§4.2 (schéma), §5.4 (rapport de couverture), §11.3 (rapport de mesure), §12.1 (consignation) ; annexe A.2."
  },
  {
    "key": "`spec/README.md` « Schémas (`schemas/`) »",
    "delegated": "Description du schéma `plan-de-tests-v0` : catalogue, rapport de couverture, rapport de mesure, consignation.",
    "response": "§4.2 (schéma), §5.4 (rapport de couverture), §11.3 (rapport de mesure), §12.1 (consignation) ; annexe A.2."
  },
  {
    "key": "`spec/README.md` « Schémas (`schemas/`) »",
    "delegated": "Description du schéma `plan-de-tests-v0` : catalogue, rapport de couverture, rapport de mesure, consignation.",
    "response": "§4.2 (schéma), §5.4 (rapport de couverture), §11.3 (rapport de mesure), §12.1 (consignation) ; annexe A.2."
  },
  {
    "key": "`spec/README.md` « CT-9 (`vecteurs/ct-9/`) »",
    "delegated": "Titre de la section des vecteurs `ct-9/`.",
    "response": "Annexe A.1 (disposition de `spec/vecteurs/ct-9/`)."
  },
  {
    "key": "`spec/README.md` « CT-9 (`vecteurs/ct-9/`) »",
    "delegated": "Renvoi à l'annexe A pour la disposition des vecteurs.",
    "response": "Annexe A.1 ; générateur et déterminisme : EX-A.1."
  },
  {
    "key": "`spec/README.md` « CT-9 (`vecteurs/ct-9/`) »",
    "delegated": "Renvoi à l'annexe A pour la disposition des vecteurs.",
    "response": "Annexe A.1 ; générateur et déterminisme : EX-A.1."
  }
];
