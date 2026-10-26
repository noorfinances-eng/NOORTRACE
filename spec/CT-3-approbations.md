# CT-3 — Approbations

Version 0.3, 2026-10-26. Spécification normative, soumise à la revue de la
porte 1 du plan de projet (document interne). La version 0.3 dit comment une
personne nommée, authentifiée par le système d'identité du client, approuve
depuis sa session, la signature restant faite par sa propre clé ; la version
0.2 alignait CT-3 sur la version 0.3 de CT-2 ; la fin de la section 0 dit ce
que chacune change. Elle met en œuvre la section « Approbation : avant
l'action, pas après » de l'[architecture cible](../ARCHITECTURE.md). Elle
s'appuie sur les formats v0 de [CT-1](CT-1-evenements-et-formats.md) sans
les modifier, sur le point d'appel de [CT-2](CT-2-enregistreur.md) (version
0.3, qui applique l'alignement de la section 15) sans créer de code
d'erreur, et laisse [CT-6](CT-6-verificateur.md) inchangé. Elle clôt la
décision ouverte 4 de l'architecture (sections 11 et 15).

La spécification a deux parties. La **partie A** (sections 0 à 6) dit qui
agit, ce qui est signé et journalisé, comment une règle s'écrit, ce que
valent les trois niveaux et comment une demande s'évalue. Un approbateur, un
auditeur ou un développeur peut s'y arrêter : elle suffit pour tirer d'une
règle la décision qu'elle donne. La **partie B** (sections 7 à 16 et
annexes) dit comment un ticket vit, d'où viennent le jeu d'approbateurs et
le seuil, ce que l'approbateur voit avant de signer, comment s'appliquent la
séparation des tâches et la fenêtre de contestation, ce que fait le
mandataire pendant l'attente, quels messages le service échange avec le
noyau et la console, ce que la console doit faire (identité de session,
annuaire des approbateurs, inscription, parcours de signature, console de
référence), et comment les vecteurs sont disposés.
L'annexe B donne les sources primaires des faits externes.

## 0. En-tête et conventions

Les mots DOIT, NE DOIT PAS, DEVRAIT et PEUT ont le sens de la RFC 2119, comme
dans CT-1, CT-2 et CT-6.

Chaque règle normative porte un identifiant **EX-<section>.<n>** (EX-4.6 :
sixième règle de la section 4), stable, auquel le plan de tests (CT-9)
attache ses tests. Les identifiants sont numérotés dans l'ordre du texte à
l'intérieur de chaque section de premier niveau, sous-sections comprises.
Une règle ajoutée par une révision reçoit le numéro qui suit le plus grand de
sa section ; aucun numéro n'est réattribué ; une règle retirée garde son
numéro, marqué « retiré ».

Les vérifications élémentaires portent l'identifiant de leur famille :

| Famille | Objet | Définie par |
|---|---|---|
| AP- | Validation et évaluation de la politique d'approbation | sections 4 à 6 (table en 4.15) |
| TK- | Cycle de vie du ticket : rapprochement, transitions, minuteurs, votes, décompte, jeu, remise, consommation, fenêtres | sections 7, 8 et 10 (table en 7.12) |
| SG- | Vérification d'une remise par le noyau avant scellement | 9.4 (table d'EX-9.11) |
| AN- | Identité de session, message d'inscription, vérification d'une inscription, opérations de l'annuaire, contrôles de la console avant un vote, vérification d'un annuaire exporté | section 13 (table en 13.16) |
| CS- | Contrôles de la console avant et après la signature : événement retenu, pièce, arguments, condensés, éligibilité, requête `personal_sign`, réponse du portefeuille, vote, découverte des portefeuilles, fichier de clé | 9.6, 9.7, 13.10 à 13.14 (table en A.11) |
| E-5, E-9, A-1 à A-4 | Forme, signatures et seuil d'une décision | CT-1 §11.4, reprises sans changement (CT-2 EX-7.5, contrôle 7 de CT-6) ; SG-5 et SG-6 les appliquent à une remise |

Les clés JSON sont en anglais ; les valeurs énumérées sont en français, sans
accent (`automatique`, `fenetre`, `revue`, `egal`, `strictement_superieur`,
`interdite`), comme dans CT-1. Les encodages sont ceux de CT-1 §3. Les trois
valeurs de vérité de la section 4 s'écrivent VRAI, FAUX et INDETERMINE.

« Le service » désigne toute implémentation conforme du service
d'approbation. L'implémentation de référence JavaScript
`scripts/lib/approbation.mjs` et le vérificateur Go indépendant de
`spec/vecteurs/ct-3/verificateur-independant` rendent, sur les mêmes entrées,
les mêmes sorties (section 6).

Les faits externes (pratiques d'approbation, textes officiels, moteurs de
politique, portefeuilles, identité, protocole MCP) viennent de cinq notes de
recherche du lot CT-3, internes et non publiées, chacune relue sur les
sources primaires qu'elle cite : R1 (code et spécifications du dépôt,
contrats, console des curateurs), R2 (protocoles et signature), R3
(contrôle humain et pratiques), relues le 2026-10-23 ; R4 (portefeuilles :
EIP-1193, EIP-6963, `personal_sign`, portefeuilles matériels, WalletConnect
v2, fichiers de clé chiffrés, bibliothèques de vérification) et R5
(identité, annuaire et page de signature : OpenID Connect, NIST
SP 800-63B-4, ERC-4361, SCIM, WebAuthn, politique de sécurité du contenu),
relues le 2026-10-26. Chaque fait porte le renvoi du fait dans sa
note (« R2-F67 », « R3-F75 ») ou d'un point non vérifié (« R1-NV3 »,
« R2 NV-4 »). L'annexe B donne, pour chaque renvoi, l'objet du fait, les
sources primaires publiques et leur date. Ce qui n'a pas pu être vérifié est
écrit « non vérifié ».

Lecture : la partie A suffit pour tirer d'une règle la décision qu'elle
donne. Un approbateur ou un auditeur lit d'abord la section 5 (les niveaux),
puis, pour décider d'une demande, 4.2, 4.4 à 4.11 et 6.2 à 6.4 (sélection,
pointeurs, types, comparaisons exactes, chaînes, prédicats, logique à trois
valeurs, ordre des règles, algorithme, issues et chaîne `policy.rule`) ; un
développeur lit les sections 4 et 6 en entier. Pour la console, un
approbateur lit 13.17, qui en résume les pas, puis les consignes
d'EX-9.20 ; le reste des sections 9 et 13 s'adresse à l'intégrateur et à
l'administrateur. Un développeur qui intègre la console lit 7.4, 9, 12 et 13
(13.9 et 13.18 donnent les messages échangés). C'est une indication de
lecture, non une règle.

**Révisions.** La version 0.1 est datée du 2026-10-23. La version 0.2, de la
même date, aligne CT-3 sur la version 0.3 de CT-2, qui adopte chaque
proposition de CT-3 §15.2 : le signal d'approbation est un résultat d'outil
`isError: true` et non plus l'erreur `-32015` (section 11) ; la remise est
vérifiée par SG-1 à SG-7, SG-7 étant la séparation des tâches vérifiée par
le noyau (EX-9.11, EX-9.12, 12.8) ; `charger` porte `requesters` (12.2) ;
une réponse d'`evaluer` a ses six membres dans un ordre quelconque et un jeu
exploitable pour `nouveau` (EX-12.6), dont le noyau tire seul une expiration
conforme à A-3 de CT-1 (EX-12.11) ; un `consommer` reçu après la fin du délai
de reconnaissance d'une approbation servie est admis sans changer l'état
(transition T22, EX-7.8, EX-12.10) ; une continuation MRTR n'hérite d'une
décision qu'avec les mêmes arguments en clair et un `requestState` à usage
unique (3.2, EX-11.10, 14.2, 14.5, 14.7) ; une liste blanche est `egal` ou
`dans` sous un nombre impair de `none` (EX-4.14) ; la conduite de l'agent
après un refus par la politique (EX-11.9).

- Règles ajoutées : aucune ; transition ajoutée : T22 (7.5).
- Règles modifiées : EX-4.1, EX-4.11, EX-4.13, EX-4.14, EX-7.2, EX-7.8,
  EX-7.16, EX-8.9, EX-9.11, EX-9.12, EX-9.14, EX-11.2 à EX-11.10, EX-12.6,
  EX-12.9 à EX-12.11, EX-14.1, EX-A.7, EX-A.8 ; sections 1, 3.2, 3.5, 4.12,
  6.1, 7.1, 7.4 à 7.6, 7.9, 8.4, 9.4, 9.5, 10.4, 10.5, 12.2 à 12.8, 14.2,
  14.5 à 14.7, 15.1, 15.2 ; annexes A.6, A.7 et B (les lignes de CT-2 citées
  sont celles de sa version 0.2).
- Règles retirées : aucune.
- Schémas : `ticket-v0` admet `SG-7` dans `$defs/cas_remise`, dont le
  contexte porte `separation` et le `launched_by` des `retenue` ;
  descriptions alignées dans `politique-approbation-v0`. Vecteurs
  `spec/vecteurs/ct-3` : cas SG-7 de `decisions/` (le cas
  `separation-non-verifiee-par-le-noyau` devient
  `invalides/sg7-auto-approbation.json`), trace
  `tickets/consommation-tardive.json`.

La version 0.3, du 2026-10-26, donne la parité sur l'approbation par une
personne nommée sans rien céder de la signature par l'approbateur : une
personne authentifiée par le système d'identité du client approuve depuis
sa session ; la signature reste faite par sa propre clé, dans son
portefeuille, jamais par un serveur (EX-3.4, EX-13.1), au seuil du jeu figé,
et reste vérifiable hors ligne (contrôle 7 de CT-6). Elle ajoute :
l'identité de session canonique et la réauthentification (13.3) ;
l'annuaire des approbateurs de l'organisation, qui lie une identité à ses
adresses, une personne n'ayant qu'une adresse active (13.4) ; l'inscription
d'une adresse par preuve de possession, message texte lisible signé en
`personal_sign`, distinct de tout vote, validé par un autre administrateur,
puis la rotation et la révocation (13.5, 13.6) ; les contrôles de la
console à chaque action et ce qu'un réviseur peut recouper d'un annuaire
exporté, déclaratif (13.7, 13.8) ; quatre parcours de signature décrits du
premier octet au dernier, avec chaque panne et sa réponse (13.9 à 13.14) ;
le contrôle local avant la signature, où la console recalcule `A`, `JCS(A)`
et `D_A` et refuse de faire signer si le service a calculé autre chose, et
après la signature, où elle recouvre l'adresse et normalise (9.6, 9.7) ; le
canal de la console vers le service, dont le service refuse le vote d'une
adresse qui n'est pas celle de la session (12.9) ; une console de référence
(13.15) ; les familles de vecteurs `annuaire/` et `console/`, une épreuve de
lecture de la console et une confrontation tierce des signatures (annexes
A.10 et A.11). Les formats de CT-1 v0 (objet `A`, `D_A`, EIP-191 version
`0x45`, événements) ne changent pas : l'objet signé d'un vote reste `A`, et
aucun autre message n'est signé pour un vote. CT-2 et CT-6 ne changent pas ;
les clés d'accès (WebAuthn) restent hors de la version 0 (section 16).

- Règles ajoutées : EX-9.15 à EX-9.22 (9.6, 9.7) ; EX-12.13 à EX-12.19
  (12.9, dont EX-12.19 : contrôle d'un retrait sur le canal de la console) ;
  EX-13.7 à EX-13.36 (13.3 à 13.15) et EX-13.37 (13.6 : recopie du réglage
  `administrators`) ; EX-A.12 à EX-A.19 (A.10, A.11).
  Familles de vérifications nouvelles : AN- (table en 13.16) et CS- (table en
  A.11).
- Règles modifiées : EX-7.15 (le demandeur qui retire est la session dont
  l'entrée active de l'annuaire porte `launched_by` parmi ses alias de
  demandeur ; le service le contrôle sur le canal, EX-12.19), EX-8.1 (pas 5 :
  adresses de l'annuaire), EX-9.3 (justification seulement), EX-9.6, EX-9.8,
  EX-9.9 (condensés du registre de CT-4 signés par la même adresse ; risque
  d'une signature obtenue hors de la console), EX-10.5 et EX-13.2 (le refus
  par la console, fondé sur l'annuaire, passe de DEVRAIT à DOIT), EX-12.4
  (méthodes du canal de la console), EX-13.1 (parcours d), EX-13.3 (contenu
  de la notification d'un vote inscrit), EX-13.4 (rendue mesurable par
  EX-13.35), EX-A.1, EX-A.3, EX-A.9 à EX-A.11 ; sections 0, 1, 2, 3.1, 3.3,
  3.4, 3.5, 7.4 (données des entrées `voter`, `recuser` et `retirer`), 8.6,
  9.3, 10.3, 10.5, 12.7, 12.8, 13 (introduction et 13.1), 14.2, 14.7, 15.2,
  16 ; annexes A.3 et B.
- Règles retirées : aucune ; aucun numéro réattribué.
- Schémas : nouveaux, `console-approbation-v0` (vue du ticket, vote, modèle
  d'affichage, requête de signature, fichier de clé, formats des vecteurs
  `console/`), `annuaire-approbateurs-v0` (annuaire, preuves, opérations,
  formats des vecteurs `annuaire/`) et `console-service-v0` (autres
  méthodes du canal de la console, dont `session` et `retirer` avec
  `session_identity`) ; `ticket-v0` : `$defs/raison` admet
  `session_non_autorisee`, et l'entrée `retirer` admet un membre
  `session_identity` facultatif (extensions compatibles : les traces
  existantes restent valides) ; `politique-approbation-v0` inchangé.
- Vecteurs `spec/vecteurs/ct-3` : familles nouvelles `annuaire/` et
  `console/`, épreuve `acceptation-console/`, confrontation `confrontation/` ;
  aucun vecteur existant ne change, hors `INDEX.md`, qui liste les familles
  nouvelles ; le vérificateur Go est étendu à ces familles (A.9).
- Le texte fixe aussi ce que les vecteurs tranchaient et que la première
  rédaction taisait : le rejeu d'un annuaire exporté (EX-13.19, point 6), les
  contrôles sautés après `evenement_invalide` et `jeu_non_fige` et l'affichage
  des arguments dans ce cas (EX-9.15), le motif d'une révocation par
  remplacement ou désactivation (EX-13.17), le moment de l'avertissement
  `derivation_faible` (EX-13.28, point 9), l'avertissement `condense_utf8`
  sans décision (EX-9.19), l'identifiant d'une entrée créée dans les vecteurs
  (A.10) et les indices écartés d'une annonce en double (EX-13.22).
- Clarifications, sans changement de règle, de schéma ni de vecteur :
  EX-9.15 (intention portée par une référence, cas où
  `adresse_non_attribuee` est atteint, séparation face à une console non
  conforme), EX-9.19, EX-9.20 (portée de la table des portefeuilles lus),
  EX-12.17 (document réduit d'une session ordinaire, `revision` simple
  indicateur de changement), EX-13.2, EX-13.5, EX-13.7 (`identite_invalide`
  à la console, sans modèle d'affichage), EX-13.9 (`administrators`),
  EX-13.18 (lecture du pas 7, correspondance avec EX-9.15), EX-13.26,
  EX-13.30 (signature jetée), EX-13.33 (`reauth_max_age_s` de la réponse
  `session`), EX-A.17 ; sections 0 (lecture), 9 (introduction), 13.5, 13.9
  (ordre des choix, écouteur EIP-6963, trois lectures), 13.17 (lexique,
  inscription, vote, ce que l'organisation dit, parcours) et 13.18
  (lectures, parcours c, renvois hors des sections 7.4, 9, 12 et 13).
- Points fermés avant la livraison de la révision 0.3 (même date), sans
  changer les formats de CT-1 v0 ni les vecteurs de CT-1, CT-2, CT-4, CT-5 et
  CT-6 :
  1. ordre des refus de `consulter` et de `tickets` sur le canal : session
     hors de l'organisation (`session_non_autorisee`), puis ticket inconnu
     (`ticket_inconnu`), puis session qui ne peut pas voir les arguments
     (`session_non_autorisee`) (EX-12.14, dernier alinéa d'EX-12.19 ;
     `controleCanal` traite `tickets` et un ticket nul ; douze cas de
     `annuaire/controles-canal.json`) ;
  2. effet dont un pointeur vers le résultat n'est pas résolu avant
     l'exécution : membre `unresolved` de la vue, valeur `null`, affiché
     « connu après exécution » (EX-12.14, EX-9.4 ; `$defs/effet_vue` de
     `console-approbation-v0`, `$defs/effect` de CT-1 inchangé ; cas
     `console/modeles/effet-connu-apres-execution.json`) ;
  3. la recopie d'un nouveau réglage `administrators` est une opération de
     l'annuaire, `changer_administrateurs`, rejouée par EX-13.19, point 6
     (EX-13.37, nouvelle ; EX-13.9, EX-13.19 modifiées ; trois cas de
     `annuaire/exports/`) ;
  4. intention portée par une référence : `intent_status` du modèle
     d'affichage et marque « non vérifiable par la console » (EX-9.4,
     EX-9.15, contrôle 4, EX-9.20, point 1 ; cas
     `console/modeles/intention-par-reference.json`) ;
  5. consignes de l'écran de signature de la page de référence reprises
     d'EX-9.20 tel qu'il est écrit, condition d'origine comprise
     (`console/console.js`, intégrités de `console/index.html` recalculées
     par `node scripts/console/empreintes.mjs --ecrire`) ;
  6. introduction de 12.9 : la méthode `session` a pour requête l'objet
     vide, qui ne porte pas d'identité ;
  7. CT-4 révision 0.4, textuelle : la console de CT-3 ne fait signer aucun
     condensé du registre, et l'outil prévu est nommé (15.2) ;
  8. test Chromium exécuté par l'intégration continue, sans saut possible
     sous `NOORTRACE_EXIGER_CHROMIUM=1` (EX-13.36, EX-A.9, EX-A.11, 15.2) ;
  9. canal auxiliaire temporel de la signature locale du parcours d (14.9) ;
  10. test différentiel permanent des primitives de la bibliothèque
     (`test/console-primitives.test.js`, EX-A.9).

  Règles modifiées par ces points : EX-9.4, EX-9.15, EX-9.20, EX-12.14,
  EX-12.19, EX-13.9, EX-13.19, EX-13.32 (table), EX-13.36, EX-A.9, EX-A.11,
  EX-A.13, EX-A.15 ; sections 12.9 (introduction), 13.6, 13.16 (AN-9,
  AN-10), 13.17 (« Voter », pas 1), 14.9, 15.2 et A.11 (CS-2). Schémas :
  `console-approbation-v0` (`$defs/effet_vue`, qui remplace `$defs/effet`
  dans la vue et le modèle ; `intent_status` du modèle),
  `annuaire-approbateurs-v0` (opération `changer_administrateurs`, membre `administrators` de chaque opération,
  nul hors d'elle, `entry` nul et `by` `configuration` pour elle,
  `$defs/liste_administrateurs` ; `fichier_controles_canal` admet `tickets`,
  un ticket nul et `ticket_inconnu`). Vecteurs de `annuaire/` et de
  `console/` régénérés en conséquence (membre `administrators` nul dans les
  opérations des annuaires et des exports, `unresolved` et `intent_status`
  dans les modèles) ; sorties publiées de la confrontation régénérées pour
  les trois exports nouveaux ; vérificateur Go étendu.

## 1. Objet, périmètre et relations

CT-3 fixe, pour la version 0 des approbations :

1. le modèle : acteurs, flux, ce qui est signé, ce qui est journalisé,
   adversaires (section 3) ;
2. le langage de règles : document `politique-approbation-v0`, sélection
   de l'outil, prédicats typés sur les arguments, comparaisons exactes,
   combinaisons, règle par défaut, outils susceptibles d'approbation,
   versions (section 4) ;
3. les trois niveaux, automatique, fenêtre et revue, et la fenêtre de
   contestation, leur projection sur les valeurs de CT-1 et ce que chacun
   prouve dans un dossier (section 5) ;
4. l'algorithme d'évaluation et sa sortie (section 6) ;
5. le ticket : états, transitions, délais, escalade, annulation,
   ré-émission reconnue, idempotence, persistance (section 7) ;
6. le jeu d'approbateurs et le seuil (section 8) ;
7. la signature et l'affichage (section 9) ;
8. la séparation des tâches et la fenêtre de contestation (section 10) ;
9. le comportement du mandataire pendant l'attente, qui clôt la décision
   ouverte 4 (section 11) ;
10. l'interface du service d'approbation et le canal de la console
    (section 12), la console : identité de session, annuaire des
    approbateurs, inscription par preuve de possession, parcours de
    signature, pannes, console de référence (section 13), la sûreté
    (section 14) ;
11. la fermeture de la décision ouverte 4 et l'alignement avec le dépôt
    (section 15), ce que la version ne couvre pas (section 16), les vecteurs
    (annexe A) et les sources (annexe B).

Hors périmètre : le format des événements, du dossier et de l'objet signé
(CT-1, inchangé) ; l'enregistreur, ses codes d'erreur et sa matrice de panne
(CT-2) ; le registre et ses preuves (CT-4) ; les ancres (CT-5) ; le
vérificateur (CT-6, inchangé) ; la cérémonie des clés d'approbateur et la
revue de sécurité (CT-7) ; l'exploitation du service et de la console
(CT-8) ; le plan de tests (CT-9) ; toute qualification juridique d'un
système client au regard d'un texte (R3, point non vérifié « qualification
de NOORTRACE ou de ses clients »).

Ce que la version 0 livre :

| Élément | Livré |
|---|---|
| Cette spécification ; les schémas `spec/schemas/politique-approbation-v0.schema.json` (section 4) et `spec/schemas/ticket-v0.schema.json` (trace du ticket, remise, formats des vecteurs : sections 7 et 12, annexe A) | avec CT-3 |
| L'implémentation de référence `scripts/lib/approbation.mjs` : validation de la politique, évaluation, outils susceptibles d'approbation, machine à états du ticket, construction et vérification de la décision | avec CT-3 |
| Le générateur `scripts/vecteurs/generer-ct3.mjs`, les vecteurs `spec/vecteurs/ct-3` (annexe A), `test/approbation.test.js`, le script `npm run vecteurs:ct3`, l'intégration continue | avec CT-3 |
| Le vérificateur Go indépendant `spec/vecteurs/ct-3/verificateur-independant` | avec CT-3 |
| Les schémas `spec/schemas/console-approbation-v0.schema.json` (vue du ticket, vote, modèle d'affichage, requête de signature, fichier de clé, formats des vecteurs `console/`), `spec/schemas/annuaire-approbateurs-v0.schema.json` (annuaire, preuves, opérations, formats des vecteurs `annuaire/`) et `spec/schemas/console-service-v0.schema.json` (autres méthodes du canal de la console) | avec CT-3 0.3 |
| La console de référence : bibliothèque sans interface ni dépendance `scripts/lib/console.mjs`, page minimale `console/`, test de bout en bout dans Chromium (13.15) | avec CT-3 0.3 |
| Les familles de vecteurs `spec/vecteurs/ct-3/annuaire/` et `spec/vecteurs/ct-3/console/`, l'épreuve `acceptation-console/` et la confrontation tierce `spec/vecteurs/ct-3/confrontation/` (annexes A.10 et A.11) | avec CT-3 0.3 |
| Le service d'approbation en processus | phase 2 du plan (section 12) |
| La console d'exploitation (serveur de console, authentification par le système d'identité du client, notifications) | phase 2 du plan (section 13) ; la console de référence en fixe le comportement côté navigateur |

Relations avec les autres spécifications :

| Spécification | Ce que CT-3 en reprend | Ce que CT-3 lui fournit |
|---|---|---|
| CT-1 | `policy` et `approval` (§5.3), l'objet `A` et sa signature EIP-191 (§6.3), `approbations.json` (§11.2), E-5, E-9, A-1 à A-4 : tels quels ; EIP-191 version `0x45` aussi pour le message d'inscription (13.5), sur un texte qui n'est jamais `D_A` | La syntaxe de `policy.rule` (6.4) ; la sémantique des règles et des tickets que CT-1 §15 renvoie à CT-3 ; la source du jeu déclaré (section 8) ; les champs signés supplémentaires, comme propositions pour une version 1 (section 16) |
| CT-2 | Le point d'appel avant relais (§4.4 pas 3 à 8, EX-7.4), les échanges du noyau avec le service (§7.5), la vérification avant scellement (SG-1 à SG-7, EX-7.5), les vérifications de relais (RL-1 à RL-4, EX-7.21), `approval.at` (EX-7.11), l'appel relayé et le `refusee` d'un ticket décidé (EX-7.12), le signal d'approbation, résultat `isError` qui porte `ticket` et `state` (EX-4.49), `policy.approval` (`mode`, `hold_timeout_ms`, `expire_after_ms`, `timeout_ms`, `service`), la matrice de panne (§14.2), les arguments en double précision exacte (EX-4.44) ; `delegation.launched_by` tiré de la configuration (`${oauth_subject}`), que l'alias de demandeur de l'annuaire rapproche de l'identité de session (13.3, 13.4) | Le contenu de `/policy/approval/rules` (4.1) ; la réponse au pas 3 (6.1) ; la liste des outils susceptibles d'approbation (4.12) ; le service, son interface et la remise des décisions (section 12) ; le mode d'attente par défaut (section 11) |
| CT-4 | `CuratorSetRegistry` et `CuratorSet`, lus sans écriture | La console de CT-3 ne fait pas signer les condensés du registre, qui se signent hors d'elle, et le risque d'une même adresse pour les deux usages (EX-9.9, EX-9.18, 15.2) ; ce qu'un registre pourrait un jour prouver d'une décision (section 16) |
| CT-6 | Le contrôle 7 et la provenance « déclaré par le dossier » du jeu (CT-6 EX-3.6), inchangés | Ce que chaque niveau prouve (5.7) ; ce qu'un futur contrôle pourrait recouper : réévaluation de la règle (6.8), séparation des tâches (section 10), jeu au registre (section 8) ; ce qu'un réviseur recoupe d'un annuaire exporté, déclaratif, qui ne remplace jamais le jeu du dossier (13.8) |
| CT-7 | — | La surface du service et de la console (3.5, section 14) ; la garde des clés d'approbateur (EX-3.4, sections 9 et 13) ; l'inscription des membres du jeu, une personne et une clé (8.6, 13.4) ; la publication des empreintes de la page de la console (EX-13.35) |
| CT-8 | — | La console d'exploitation, son serveur et son authentification par le système d'identité du client (13.3, 13.15) |
| CT-9 | — | Les identifiants EX-, AP-, TK-, SG-, AN- et CS-, les vecteurs `spec/vecteurs/ct-3`, l'épreuve d'acceptation à trois relecteurs et l'épreuve de lecture de la console (annexe A) |

## 2. Terminologie

Les termes de CT-1 §2 et de CT-2 §2 gardent leur sens (approbateur, journal,
événement, pièce, dossier, enregistreur, hôte, agent, frontal MCP, noyau,
nom annoncé, connexion d'hôte, ensemble de politique, service
d'approbation). S'y ajoutent :

| Terme | Définition |
|---|---|
| Demande | Un appel d'outil que le noyau soumet au service avant relais (CT-2 EX-7.4) : nom annoncé, arguments en clair, délégation, et les autres membres que CT-2 transmet. |
| Ré-émission | Nouvelle requête `tools/call` de l'hôte que le service rattache à une demande antérieure et à son ticket, selon la section 7. |
| Politique d'approbation | Le document `politique-approbation-v0`, membre `/policy/approval/rules` de l'ensemble de politique (4.1). |
| Règle | Élément de `rules` : un nom, des outils, une condition, un niveau (4.2). |
| Règle par défaut | Le membre `default` : il décide quand aucune règle ne s'applique (4.11). |
| Condition | Arbre de prédicats et de combinaisons `all`, `any`, `none` ; elle vaut VRAI, FAUX ou INDETERMINE (4.10). |
| Prédicat | Test d'une valeur des arguments désignée par un pointeur JSON (4.9). |
| Niveau | `automatique`, `fenetre` ou `revue` : la part que prend un humain à la décision (section 5). |
| Issue | Ce qu'une règle donne pour une demande : un rang, une décision CT-1, une marque (6.3). |
| Ticket | Objet du service qui suit une demande `a_approuver` jusqu'à sa décision ; son identifiant est `policy.ticket` (section 7). |
| Vote | Signature EIP-191 d'un approbateur sur l'objet `A` de CT-1 §6.3, pour `approuve` ou pour `refuse` (sections 7 et 9). |
| Décision | L'objet `approval` de CT-1 §5.3 que le noyau scelle : `approuve`, `refuse` ou `expire`. |
| Jeu d'approbateurs | Les membres et le seuil du `CuratorSet` de l'organisation, lus et figés à l'ouverture du ticket, figés de nouveau s'ils changent pendant l'attente, et reconfirmés avant la remise d'une décision (section 8). |
| Seuil | `threshold = { required, size }` : signatures requises sur la taille du jeu (CT-1 §5.3). |
| Demandeur | L'identité `delegation.launched_by` de la demande (CT-1 §5.3), qui vient de la configuration de la connexion d'hôte et non de l'hôte (CT-2 EX-7.2). |
| Administrateur du jeu | Le détenteur de la clé `admin` du `CuratorSet` : il ajoute et retire des membres et fixe le seuil (R1-F71, R1-F72). |
| Administrateur du registre | Le détenteur de la clé `admin` du `CuratorSetRegistry` : par `setCuratorSet`, il désigne le jeu de chaque organisation et peut le réassigner (R1-F74). Il est extérieur à l'organisation. |
| Jeu épinglé | L'adresse du `CuratorSet` qu'une politique `registre` attend (`approver_set.set`, 4.2) : une lecture d'un autre jeu est illisible (EX-8.1). |
| Seuil effectif | Le nombre de signatures qu'une décision `approuve` ou `refuse` d'un ticket porte : le plus grand `required` des jeux figés pour ce ticket (EX-8.6). |
| Fenêtre | Autorisation bornée dans le temps et en nombre d'appels, ouverte par une décision `approuve` sur une demande d'une règle de niveau `fenetre` (5.3). |
| Fenêtre de contestation | Délai `contest_ms` entre l'atteinte du seuil d'approbation et la remise de la décision, pendant lequel un membre éligible du jeu figé peut s'opposer (5.6, section 10). |
| Objection | Quand `contest_ms > 0`, un vote `refuse` accepté (EX-9.10) d'un membre éligible du jeu figé, reçu pendant la collecte ; seul un vote `approuve` de son auteur la lève (EX-10.7, EX-10.8). |
| Escalade | Notification supplémentaire, quand un ticket attend, des membres du jeu qui n'ont pas voté, de l'administrateur du jeu ou du demandeur ; elle ne change ni le jeu, ni le seuil, ni l'échéance (7.7). |
| Outils susceptibles d'approbation | Les noms annoncés pour lesquels l'évaluation peut rendre autre chose que `autorise`, quels que soient les arguments (4.12). |
| Instant d'évaluation | `t` : l'instant où le service reçoit la demande, sur son horloge, en UTC à la milliseconde (6.1). |
| Console | L'interface où les approbateurs voient les demandes et signent (section 13). |
| Portefeuille | Le logiciel ou l'appareil qui détient la clé secp256k1 d'un approbateur et signe pour lui : extension de navigateur, portefeuille matériel, application mobile, ou la page elle-même pour un fichier de clé chiffré qu'elle lit localement (13.9). |
| Fournisseur | L'objet EIP-1193 par lequel la page parle à un portefeuille (`request`, événements) ; la console le traite comme contrôlé par un adversaire (R4-F4). |
| Parcours de signature | Suite exacte des messages entre la page, le portefeuille et le service qui produit un vote : a) portefeuille de navigateur, b) portefeuille matériel par un portefeuille de navigateur, c) portefeuille mobile par WalletConnect v2, d) fichier de clé chiffré (13.9). |
| Vue du ticket | Ce que le service sert à la console par `consulter` (12.9) : la demande, l'événement `retenue`, la pièce « arguments », la règle, le jeu figé, les votes et les condensés `D_A` calculés par le service. |
| Condensé EIP-191 `H` | `keccak256(0x19 ‖ "Ethereum Signed Message:\n32" ‖ D_A)` : ce que le portefeuille signe en fait, et ce que certains appareils montrent sous « Message hash » (R4-F23). |
| Empreinte abrégée | Les 8 premiers et les 8 derniers chiffres hexadécimaux d'une valeur de 32 octets, séparés par U+2026 (EX-9.18), que l'approbateur compare à l'écran de son portefeuille. |
| Réviseur | Celui qui vérifie un dossier ou un journal après coup, comme dans CT-6. |
| Identité de session | L'identité sous laquelle le système d'identité du client a authentifié la personne qui utilise la console, sous sa forme canonique d'EX-13.7 (`oidc <iss> <sub>` ou `utilisateur <domaine> <nom>`). |
| Annuaire des approbateurs | Document `annuaire-approbateurs-v0` que le service tient pour une organisation : une entrée par personne nommée, ses adresses et leurs preuves de possession, ses alias de demandeur, et les opérations acceptées (13.4). |
| Entrée | Élément de l'annuaire pour une personne : identifiant stable `apb-…`, identité de session, état administratif, alias de demandeur, adresses (13.4). |
| Inscription | Rattachement d'une adresse à une entrée, sur preuve de possession, en attente de validation par un administrateur (13.5). |
| Message d'inscription | Texte ASCII, signé en `personal_sign` par l'adresse inscrite, qui nomme l'origine de la console, l'organisation, l'identité, l'adresse, les instants et un nonce (EX-13.12). Il n'est jamais un vote. |
| Preuve de possession | Le message d'inscription et sa signature, gardés dans l'entrée (EX-13.15). |
| Serveur de console | Le serveur qui sert la page de la console, authentifie la personne par le système d'identité du client et relaie les méthodes du canal de la console vers le service (12.9, 13.3). |
| Console de référence | La bibliothèque `scripts/lib/console.mjs`, la page `console/` et leur test dans Chromium (13.15). |

## 3. Modèle

### 3.1 Acteurs

| Acteur | Rôle | Détient | Confiance |
|---|---|---|---|
| Agent et hôte | Émettent les appels d'outils. | Rien de l'enregistreur. | Aucune : tout ce qu'ils envoient est une donnée d'attaquant (CT-2 §3.3). |
| Mandataire (frontal MCP) | Relaie les appels, applique le mode d'attente (section 11). | — | Partie de l'enregistreur. |
| Noyau de l'enregistreur | Scelle les événements ; vérifie toute décision avant de la sceller (CT-2 EX-7.5). | L'usage de la clé du journal (CT-2 §11). | Pleine. |
| Service d'approbation | Évalue la politique, tient les tickets et les fenêtres, lit le jeu d'approbateurs, recueille les votes, remet les décisions. | La politique, l'état des tickets ; aucune clé de signature (EX-3.3). | Canal authentifié (CT-2 EX-18.8) ; ses réponses `autorise` et `refuse` ne sont pas signées. |
| Console | Montre la demande, fait signer, transmet le vote, la récusation et le retrait (sections 9 et 13). | Aucune clé d'approbateur (EX-3.4) ; ses identifiants sur le canal vers le service (EX-12.4). | Non fiable pour l'approbateur : parades de la section 9. Une récusation et un retrait ne sont pas signés en v0 (EX-10.4, section 16). |
| Approbateurs | Votent sur l'objet `A`. | Chacun sa clé secp256k1, membre du `CuratorSet` (CT-1 §2). | Individuellement non fiables ; la décision exige le seuil. |
| Portefeuille de l'approbateur | Montre le condensé à signer et signe `D_A` avec la clé de l'approbateur (13.9). | La clé, seul. | Celle de l'approbateur, qui le choisit ; son écran, s'il est celui d'un appareil, est le seul que l'ordinateur ne contrôle pas (13.11). Son fournisseur dans la page est traité comme adverse (R4-F4) : la console vérifie ce qu'il rend (9.7). |
| Administrateurs de l'annuaire (`administrators`) | Valident les inscriptions, révoquent une adresse, désactivent ou réactivent une entrée, lient un alias de demandeur (13.6) ; retirent un ticket (EX-7.15). | Une identité de session listée dans `administrators` (10.3) ; aucune clé d'approbateur. | Leurs opérations sont déclaratives et inscrites dans l'annuaire ; elles ne changent ni le jeu figé ni le seuil d'un ticket (EX-12.18). Un administrateur ne valide jamais sa propre adresse (EX-13.17). |
| Administrateur du jeu | Gère le `CuratorSet` de l'organisation. | La clé `admin` du contrat (R1-F72). | Hors de l'enregistreur ; ses changements sont publics sur la chaîne (R1-F69). Un seuil abaissé pendant l'attente ne réduit pas le nombre de signatures exigé (EX-8.6). |
| Administrateur du registre | Désigne le jeu de chaque organisation (`setCuratorSet`, R1-F74). | La clé `admin` du `CuratorSetRegistry`, une seule clé. | Hors de l'organisation et de l'enregistreur ; une réassignation est publique (`CuratorSetAssigned`) ; la politique épingle le jeu attendu, si bien qu'un jeu réassigné ne décide d'aucun ticket (EX-8.1, EX-8.6). |
| Exploitant du nœud RPC | Sert les lectures du jeu au service (EX-8.1). | Le nœud que configure le service (10.3). | Aucune preuve d'état en v0 (R1-F80) : parade organisationnelle (14.4). |
| Opérateur | Exploite l'enregistreur et le service, écrit la politique. | La configuration. | Adversaire de CT-6 §3.4 ; ses changements de politique sont journalisés (CT-2 EX-9.1). |

### 3.2 Flux nominal

1. L'hôte envoie `tools/call` ; le mandataire le lit et résout le nom
   annoncé (CT-2 §4.4 pas 1 et 2).
2. Le noyau soumet la demande au service (CT-2 EX-7.4, pas 3).
3. Le service reconnaît, le cas échéant, une ré-émission (section 7) ;
   sinon il évalue la politique (section 6) et, pour la décision
   `a_approuver`, crée un ticket (section 7). Il répond dans
   `/policy/approval/timeout_ms`.
4. `autorise` : le noyau écrit la pièce « arguments » et relaie (pas 4, 7 à
   14). `refuse` : événement `refusee` et résultat `isError: true` rendu à
   l'hôte (pas 5, EX-11.8).
5. `a_approuver` : le noyau scelle l'événement `retenue`, dont le `hash`
   devient le `request_hash` du ticket, et remet ce hachage au service
   (pas 6, section 12). Le service lit le jeu d'approbateurs et le seuil et
   les fige dans le ticket (section 8), puis notifie la console
   (section 13) ; il surveille ensuite le jeu et le fige de nouveau s'il
   change (8.3).
6. Le mandataire applique le mode d'attente (section 11).
7. Chaque approbateur voit la demande (sections 9 et 13) et signe l'objet `A`
   de CT-1 §6.3 avec sa propre clé ; la console transmet le vote ; le service
   le vérifie (section 9) et applique la séparation des tâches (section 10).
8. Au seuil, après la fenêtre de contestation s'il y en a une (5.6) et la
   confirmation du jeu (EX-8.7), le service remet la décision au noyau ; le
   noyau la vérifie (CT-2 EX-7.5), la scelle (`noortrace.approbation.decision`,
   `approval.at = ts`, CT-2 EX-7.11) et en accuse réception (section 12). Une
   décision `approuve` d'un ticket ouvrant, créé par une règle de niveau
   `fenetre`, ouvre une fenêtre (5.3).
9. L'appel approuvé est relayé : la requête retenue (mode `retenir`) ou la
   ré-émission reconnue (mode `erreur`) porte l'objet `approval` (CT-2
   EX-7.12).
10. Sans décision scellée avant l'échéance du ticket (`ts` de l'événement
    `retenue` plus `/policy/approval/expire_after_ms`, EX-7.10), la décision
    est `expire`, scellée de même (CT-2 EX-9.4, section 7).

Une ré-émission MRTR (continuation d'un résultat `input_required` relayé)
hérite de l'évaluation de l'appel d'origine, et le service n'est pas rappelé,
seulement si ses arguments en clair sont ceux de l'appel d'origine (MAC de
relais), si son `requestState` n'a pas encore servi et, sous un ticket
approuvé, si les vérifications de relais passent (CT-2 EX-4.21, EX-7.21) ;
sinon elle repasse par l'évaluation, et une approbation déjà servie ne la
couvre pas (EX-7.17).

**EX-3.1** Le service NE DOIT PAS rendre `autorise` pour une demande liée à
un ticket tant que le noyau n'a pas accusé réception du scellement d'une
décision `approuve` pour ce ticket (section 12). Aucun appel qu'une règle
soumet à approbation n'est relayé avant la décision signée au seuil.

**EX-3.2** Aucun délai, aucune escalade, aucune fenêtre de contestation et
aucun changement de politique ne produit une décision `approuve` sans les
signatures au seuil. Un délai écoulé sans décision donne `expire`, c'est-à-dire
un refus journalisé (CT-1 §5.3). CT-3 n'a pas d'approbation implicite à
l'échéance, à la différence de l'exemple documenté de ServiceNow (R3-F115,
R3-F119) ; les autres produits lus font expirer la demande, échouent,
sautent l'étape ou annulent à l'échéance (R3-F78, R3-F88, R3-F103, R3-F110,
R3-F113).

**EX-3.3** Le service NE DOIT détenir ni la clé du journal (CT-2 EX-7.4) ni
aucune clé d'approbateur. Il ne signe rien.

**EX-3.4** La clé d'un approbateur n'est détenue que par lui. Ni le service,
ni le serveur de la console, ni l'enregistreur ne signent pour un
approbateur. La console des curateurs de noorchain-core signe aujourd'hui
côté serveur pour les curateurs, avec des clés gardées par le serveur
(R1-F83, R1-F84) : reprise telle quelle, elle viderait le contrôle 7 de son
sens (section 13).

**EX-3.5** De la demande, l'évaluation ne lit que le nom annoncé, les
arguments en clair et `delegation.launched_by` (section 6). Elle ne lit ni
l'intention, ni le code, ni le contexte, ni la classe de l'outil, ni une
valeur de délégation que l'hôte déclare (`run_id`, `on_behalf_of`, CT-2
EX-7.2).

### 3.3 Ce qui est signé

| Objet | Signé par | Forme | Vérifié par |
|---|---|---|---|
| `A = { decision, journal_id, org_id, request_hash, ticket }` | Chaque approbateur, pour son vote | EIP-191 sur `D_A` (CT-1 §6.3) | Le service à la réception (section 9), le noyau avant scellement (CT-2 EX-7.5), le vérificateur (E-9) |
| Message d'inscription (EX-13.12) | L'adresse inscrite, une fois, à l'inscription | EIP-191 version `0x45` sur les octets ASCII du texte (`personal_sign`), jamais sur `D_A` | Le service à la réception (EX-13.15), le réviseur sur l'annuaire exporté (EX-13.19) |
| Chaque événement | L'enregistreur | Ed25519 (CT-1 §6.2) | Le vérificateur (E-8) |
| Réponse du service (`autorise`, `a_approuver`, `refuse`, outils susceptibles) | Personne | — | Canal authentifié (CT-2 EX-18.8) |
| Politique d'approbation | Personne ; son empreinte entre dans l'événement de politique | `policy_sha256` sur l'ensemble de politique en JCS intégral (CT-2 EX-10.21) | Le réviseur qui détient la pièce (CT-2 EX-8.11) |

`threshold`, `approvers`, `at` et `reason` ne sont pas signés par les
approbateurs ; ils sont attestés par la signature de l'enregistreur (CT-1
§5.3). Le message d'inscription n'est pas un vote et un vote n'est pas une
inscription : leurs préimages EIP-191 diffèrent toujours (EX-13.16). Aucune
autre signature d'approbateur n'existe en version 0. L'approbateur signe
toujours dans son portefeuille (13.9) : un serveur ne signe ni un vote ni
une inscription (EX-3.4, EX-13.1). L'objet `A` ne porte ni échéance, ni
outil, ni fenêtre : une signature d'approbation lie une demande exacte et
rien d'autre (R1-F8, R3-F122).

### 3.4 Ce qui est journalisé

| Fait | Où | Forme |
|---|---|---|
| Politique en vigueur | Chaîne | `noortrace.journal.politique`, avant tout événement de la nouvelle version (CT-2 EX-9.1) |
| Évaluation d'un appel | Chaîne | `policy.rule`, `policy.decision`, `policy.ticket` de l'événement de l'appel (6.2) |
| Demande soumise à approbation | Chaîne | Événement `retenue` ; son `hash` est `request_hash` |
| Décision | Chaîne | Événement `noortrace.approbation.decision` |
| Appel relayé après approbation | Chaîne | Événement `executee` qui recopie `approval` (CT-2 EX-7.12) |
| Appel refusé | Chaîne | Événement `refusee` |
| Appel couvert par une fenêtre | Chaîne | Événement `executee`, `policy.decision` `autorise`, marque de fenêtre dans `policy.rule` (5.3) |
| Votes individuels, objections, notifications, escalades, lectures du jeu, ouvertures et fermetures de fenêtre | Journal du service | Hors chaîne (sections 7, 8 et 10) |
| Inscriptions, validations, révocations, désactivations, alias de demandeur | Annuaire du service (`operations`) | Hors chaîne, en ajout seul (13.6) ; exportable au réviseur, déclaratif (EX-13.19) |
| Attente, report d'une décision, expiration en mode dégradé | Journal d'exploitation de l'enregistreur | `approval_pending`, `approval_deferred`, `approval_expired_deferred` (CT-2 §14.2) |

Un vote qui n'atteint pas le seuil, une objection, une escalade
n'apparaissent pas dans la chaîne en version 0 : seule la décision finale y
entre, avec ses signatures.

### 3.5 Adversaires

| Adversaire | Ce qu'on lui suppose | Ce que CT-3 empêche ou rend visible | Ce qui reste possible |
|---|---|---|---|
| **Agent** (et hôte) | Il choisit l'outil et les arguments, répète, fractionne, forge `_meta` et sa délégation déclarée (CT-2 §3.3). | Contourner le mandataire : pare-feu (CT-2 §4.1). Échapper à une règle par un argument absent ou mal typé : la condition vaut INDETERMINE et une règle restrictive s'applique quand même (6.3). Profiter de la fenêtre d'un autre demandeur ou d'un autre outil : la portée tient au `launched_by` de la configuration et à l'outil annoncé (EX-5.2). Modifier un appel approuvé : `request_hash` lie la décision à l'outil et aux arguments exacts (CT-1 §5.3). | Fractionner un montant en appels sous le seuil d'une règle : un langage qui évalue un appel à la fois ne l'empêche pas ; le plafond `max_calls` d'une fenêtre ne borne que les appels qu'elle couvre (14.1). Choisir un outil qu'aucune règle ne nomme : la règle par défaut décide (4.11). Inonder le service de demandes (section 14). |
| **Opérateur** | Il écrit la politique et exploite l'enregistreur et le service. | Changer la politique sans trace : chaque version est annoncée dans la chaîne avant usage, avec son empreinte (CT-2 EX-9.1, EX-10.21). Ouvrir une fenêtre sans approbation : une fenêtre ne s'ouvre que par une décision signée au seuil (5.3). Fabriquer une approbation : il n'a pas les clés des approbateurs (EX-3.4, contrôle 7). | Assouplir la politique, ajouter une règle automatique d'urgence : visible, non empêché (5.2). Faire tourner un service qui dit `autorise` à tort : visible à la réévaluation, quand les pièces la permettent (6.8). Substituer le jeu d'approbateurs (sections 8 et 14). |
| **Administrateur du registre** | Il réassigne, par `setCuratorSet`, le jeu de l'organisation à un jeu qu'il contrôle (R1-F74). | Faire décider un ticket par le jeu réassigné : la politique épingle le jeu attendu (`approver_set.set`) ; une lecture d'un autre jeu est illisible (`jeu_non_attendu`), le ticket ne se fige pas sur lui, n'atteint pas la confirmation et expire (« echeance atteinte, jeu reassigne », EX-8.1, EX-8.6). Adopter un autre jeu exige une nouvelle version de politique, journalisée (EX-4.12). | Bloquer les approbations de l'organisation jusqu'à cette nouvelle version (déni de service, public sur la chaîne). |
| **Administrateur du jeu** | Il ajoute ou retire des membres et change le seuil pendant l'attente. | Réduire le nombre de signatures d'un ticket en attente : le seuil effectif ne baisse jamais (EX-8.6). Un membre ajouté après l'ouverture est signalé à la console et dans la trace (EX-8.6). | Ajouter des membres qu'il contrôle, qui votent ensuite au seuil : signalé, non empêché. |
| **Exploitant du nœud RPC** | Il sert au service un état faux du registre et du jeu. | — | Faire figer un jeu inventé : aucune preuve d'état en v0 (R1-F80) ; parade organisationnelle (14.4). |
| **Approbateur malveillant** | Il signe ce qu'il veut avec sa clé. | Décider seul : il faut `required` signatures d'adresses distinctes (CT-1 A-3). Approuver sa propre demande, si la séparation l'interdit (section 10). | Une collusion d'au moins `required` membres décide ce qu'elle veut ; la décision est signée, donc attribuable (contrôle 7). |
| **Approbateur contraint** | On le force à signer. | — | La version 0 n'a pas de signal de contrainte ; la fenêtre de contestation laisse à un autre membre le temps de s'opposer (5.6). |
| **Console compromise** | Elle affiche une demande et fait signer autre chose ; elle émet sur le canal console → service avec des identifiants valides (EX-12.4). | Une signature vaut pour une seule demande retenue, celle de `request_hash` (CT-1 §6.3) ; la console recalcule `D_A` et l'affiche en entier (section 9). Effacer un refus par une récusation forgée : la récusation retire le vote `approuve` du membre, jamais son vote `refuse`, qui reste compté (EX-10.4). | Faire signer une autre demande réellement retenue sans que l'approbateur s'en aperçoive, si son portefeuille n'affiche que 32 octets en hexadécimal (R2-F53 à R2-F56, section 9). Faire signer `approuve` à qui voulait refuser la même demande : les deux objets `A` ne diffèrent que par `decision` (9.3) ; seule la notification de chaque vote inscrit par un canal indépendant (EX-13.3) le rend visible, et un outil hors ligne de recalcul de `D_A`, que la version 0 ne livre pas (section 16). Faire signer, présenté comme un vote, un condensé du registre de CT-4 (`registerDigest`, `revokeDigest`, `periodDigest`), que la même adresse signe sous la même forme : rien ne le distingue sur l'écran du portefeuille, aucun vote n'est inscrit et aucune notification de vote ne part (9.3, EX-9.9). Dans le parcours d, lire le mot de passe et la clé déchiffrée (EX-13.28). Ne pas transmettre un refus, forger une récusation ou un retrait : non signés en v0 (section 16). |
| **Extension ou fournisseur malveillant** dans le navigateur de l'approbateur | Il s'annonce comme portefeuille (EIP-6963), imite le nom et l'icône d'un autre (R4-F6), ou s'interpose entre la page et le portefeuille et change le message à signer. | Se faire choisir sans action de l'approbateur : aucun choix implicite, doublons d'`uuid` écartés (EX-13.22). Faire passer la signature d'un autre condensé pour un vote sur la demande affichée : la console recouvre l'adresse sur son propre `D_A` (EX-9.21) ; l'écran du portefeuille montre le condensé réellement signé, que l'approbateur compare à l'empreinte de la console (EX-9.20). | Obtenir, d'un approbateur qui ne compare pas, la signature d'un autre `D_A` réellement retenu, puis la faire transmettre par une console compromise (9.3). Bloquer ou retarder la signature. |
| **Service d'approbation compromis** | Il répond ce qu'il veut, sauf des signatures. | Une décision `approuve` sans signatures valides au seuil du jeu que le service déclare : refusée par le noyau (CT-2 EX-7.5). S'aligner sur la décision scellée d'une autre demande sous un identifiant réattribué : T14 n'aligne que sur la même demande (`request_hash`), sinon T20 clôt le ticket (12.5). Afficher à l'approbateur d'autres arguments que ceux de la demande retenue : la console vérifie l'événement `retenue` et la pièce « arguments » (EX-9.6). Rendre une réponse hors des sept combinaisons d'EX-12.6 : le noyau la traite comme une indisponibilité. Blanchir une approbation, en faisant relayer sous une décision `approuve` scellée un autre appel ou le même deux fois : le noyau compare l'appel relayé à la demande retenue, MAC à clé des arguments en clair compris, et refuse un second relais (RL-1 à RL-4, CT-2 EX-7.21). Faire compter la signature du demandeur : le noyau vérifie la séparation déclarée (SG-7, CT-2 EX-7.5). | Rendre `autorise` pour un appel que la politique soumet à approbation : la réponse n'est pas signée (CT-2 EX-18.8) ; visible à la réévaluation (6.8). Bloquer ou retarder. Annoncer un jeu d'approbateurs qui n'est pas celui du registre (sections 8 et 14). Substituer une valeur rédigée dans l'affichage (14.5). Ignorer la fenêtre de contestation (EX-9.12). |

## 4. Langage de règles

Une règle est un outil plus des prédicats sur ses arguments, comme le dit
l'architecture. Elle s'écrit en JSON validé par un schéma, pas dans un
langage textuel à analyser : deux implémentations indépendantes, l'une en
JavaScript et l'autre en Go, l'évaluent à l'identique sans grammaire à
partager, et sont confrontées sur les mêmes vecteurs (annexe A), comme
Cedar confronte sa sémantique formelle à son implémentation par des tests
différentiels (R2-F69).

### 4.1 Place du document

**EX-4.1** Le membre `/policy/approval/rules` de l'ensemble de politique (CT-2
§15.1 ; CT-2 le valide sans l'évaluer, CT-2 EX-15.4) DOIT être un document
`politique-approbation-v0` et rien d'autre. Il est haché avec l'ensemble (CT-2
EX-10.21) ; le changer exige une nouvelle `policy.version` et produit un
événement `noortrace.journal.politique` (4.13). Les réglages d'attente et de
délai (`mode`, `hold_timeout_ms`, `expire_after_ms`, `timeout_ms`, `service`)
restent les membres de `/policy/approval` que CT-2 définit.

Le schéma de configuration de CT-2 désigne ce membre par un `$ref` vers
`politique-approbation-v0`, et l'exemple de CT-2 §15.3 porte, depuis la
version 0.3 de CT-2, un document conforme. Le vecteur
`spec/vecteurs/ct-2/evenements/journal-demo/politique.json`, antérieur à
CT-3, garde sous `rules` un tableau illustratif, marqué « syntaxe CT-3,
opaque pour CT-2 », qui n'est pas un document `politique-approbation-v0` : il
reste figé, parce que le changer changerait les événements du vecteur, et il
est validé hors de ce membre (CT-2 annexe B.6).

### 4.2 Forme du document

Schéma : `spec/schemas/politique-approbation-v0.schema.json` (`$id`
`https://noortrace.example/schemas/v0/politique-approbation.schema.json`,
JSON Schema 2020-12, `additionalProperties: false` à tous les niveaux). Comme
dans CT-1, la forme d'un objet est fixe : une clé sans objet est présente,
à `null`.

| Membre | Contenu | Section |
|---|---|---|
| `version` | Constante `0` : version du format. | 4.13 |
| `default` | Règle par défaut : `name`, `description`, `level` (`automatique` ou `revue`), `decision`, `contest_ms`. | 4.11 |
| `rules` | Règles, de 0 à 1 024, dans l'ordre du document ; l'ordre désigne la règle retenue entre issues de même rang (EX-4.9). | 4.4 à 4.11 |
| `approver_set` | Source du jeu d'approbateurs : `registre` (identifiant de chaîne, adresse du `CuratorSetRegistry`, adresse `set` du `CuratorSet` épinglé) ou `statique` (membres et seuil écrits, `set` nul, hors production). | 8 |
| `separation` | Auto-approbation `interdite` ou `permise` ; identités de demandeurs et adresses qu'elles détiennent. | 10 |

Une règle :

| Membre | Type | Rôle |
|---|---|---|
| `name` | Chaîne de 1 à 256 caractères, sans `[` ni `]`, sans caractère de contrôle (U+0000 à U+001F, U+007F à U+009F), sans espace en tête ni en fin | Nom unique ; écrit dans `policy.rule` (6.4). |
| `description` | Chaîne de 1 à 1 024 caractères, ou `null` | Montrée aux approbateurs (section 13) ; sans effet sur l'évaluation. |
| `tools` | 1 à 256 sélecteurs distincts | Outils visés (4.4). |
| `when` | Condition, ou `null` | `null` : la règle vaut pour tout appel des outils visés (4.10). |
| `level` | `automatique`, `fenetre`, `revue` | Section 5. |
| `decision` | `autorise` ou `refuse` pour `automatique` ; `null` sinon | 5.2. |
| `window` | `{ "duration_ms", "max_calls", "same_arguments" }` pour `fenetre` ; `null` sinon | 5.3. |
| `contest_ms` | Entier de 0 à 86 400 000 pour `fenetre` et `revue` ; `null` pour `automatique` | 5.6. |

**EX-4.2** Au chargement d'un ensemble de politique, le service DOIT valider
le document contre le schéma et vérifier les règles que le schéma n'exprime
pas :

1. les noms sont uniques dans le document, règle par défaut comprise ;
2. un pointeur a au plus 32 jetons (4.5) ;
3. une condition a au plus 8 niveaux d'imbrication (un prédicat seul est au
   niveau 1, chaque `all`, `any` ou `none` ajoute un niveau) et une règle au
   plus 64 prédicats ;
4. toute chaîne du document est une suite de points de code bien formée,
   sans substitut isolé (CT-1 §4, règle 3) ;
5. un même `launched_by` n'apparaît qu'une fois dans
   `separation.identities` ;
6. `contest_ms`, pour chaque règle et pour la règle par défaut, est
   inférieur à `/policy/approval/expire_after_ms` (5.6) ;
7. les règles propres à `approver_set` (EX-8.2), dont le refus d'un jeu
   `statique` en production, selon `recorder.environment` que transmet le
   message `charger` (12.2).

Le schéma est vérifié d'abord : un document non conforme donne exactement
une erreur `{ "code": "schema", "pointer": null }` et aucune autre ; les
points 1 à 7 ne sont vérifiés que sur un document conforme, dont la
structure est alors connue. Pour un document conforme, le service rapporte
toutes les erreurs des points 1 à 7, pas seulement la première, chacune
avec un code de `$defs/code_erreur_politique` de `ticket-v0` et le pointeur
JSON du membre fautif, triées comme l'annexe A.4 le fixe. Le point 4 vaut
pour la validation hors protocole (commande de validation de l'enregistreur,
CT-2 §15.6, ou validation du membre extrait ci-dessous) : sur le canal du
service, un message `charger` dont le texte porte un substitut isolé n'est
pas du JSON strict et reçoit `requete_invalide` (EX-12.1), avant toute
validation de la politique. Un document invalide n'est jamais appliqué : le
service refuse l'ensemble de politique (`politique_invalide`, 12.2) et aucune
demande n'est évaluée sous ce document. Tant que CT-2 n'a pas obtenu la
liste des outils susceptibles d'approbation, il tient tout outil pour
susceptible (CT-2 EX-7.4) et le traite, service indisponible, comme bloquant
(CT-2 §14.2) : un document refusé bloque les appels, il ne les laisse jamais
passer.

La partie « schéma » se reproduit hors du service, sur le membre extrait :

```bash
npx --yes ajv-cli@5 validate --spec=draft2020 --strict=true \
  -s spec/schemas/politique-approbation-v0.schema.json -d politique-approbation.json
```

### 4.3 Exemple complet

La politique d'un assureur, reprise du scénario de référence de CT-1
annexe A et des vecteurs CT-1 (journal `journal-sinistres`). Les règles qui
figurent dans ces vecteurs y portent exactement leur chaîne `policy.rule`,
et les arguments de `sap.payments.create` sont ceux de CT-2 annexe A
(pas 1). L'argument `recipient_role` de `mail.send` et les outils
`crm.claims.delete` et `sap.payments.list` sont fictifs. La politique
valide contre le schéma (commande de 4.2) ; ses issues sont calculées en
6.7.

<!-- schema: politique-approbation -->
```json
{
  "version": 0,
  "default": {
    "name": "defaut : revue",
    "description": "Tout appel qu'aucune règle ne couvre est soumis aux approbateurs.",
    "level": "revue",
    "decision": null,
    "contest_ms": 0
  },
  "rules": [
    {
      "name": "outil crm.claims.get : lecture autorisee",
      "description": null,
      "tools": [ "crm.claims.get" ],
      "when": null,
      "level": "automatique",
      "decision": "autorise",
      "window": null,
      "contest_ms": null
    },
    {
      "name": "outil documents.search : lecture autorisee",
      "description": null,
      "tools": [ "documents.search" ],
      "when": null,
      "level": "automatique",
      "decision": "autorise",
      "window": null,
      "contest_ms": null
    },
    {
      "name": "outil mail.send : envoi autorise vers l'assure",
      "description": "Courriel à l'assuré du dossier ; tout autre destinataire relève de la règle par défaut.",
      "tools": [ "mail.send" ],
      "when": { "path": "/arguments/recipient_role", "op": "egal", "value": "assure" },
      "level": "automatique",
      "decision": "autorise",
      "window": null,
      "contest_ms": null
    },
    {
      "name": "paiement hors CHF",
      "description": "Les paiements de sinistre se font en francs suisses.",
      "tools": [ "sap.payments.create" ],
      "when": { "none": [ { "path": "/arguments/currency", "op": "egal", "value": "CHF" } ] },
      "level": "automatique",
      "decision": "refuse",
      "window": null,
      "contest_ms": null
    },
    {
      "name": "beneficiaire hors liste blanche",
      "description": null,
      "tools": [ "sap.payments.create" ],
      "when": {
        "none": [
          { "path": "/arguments/beneficiary_iban", "op": "dans", "value": [ "CH9300762011623852957", "CH5604835012345678009" ] }
        ]
      },
      "level": "automatique",
      "decision": "refuse",
      "window": null,
      "contest_ms": null
    },
    {
      "name": "paiement <= 1000 CHF",
      "description": null,
      "tools": [ "sap.payments.create" ],
      "when": {
        "all": [
          { "path": "/arguments/currency", "op": "egal", "value": "CHF" },
          { "path": "/arguments/amount", "op": "strictement_superieur", "value": "0" },
          { "path": "/arguments/amount", "op": "inferieur_ou_egal", "value": "1000" }
        ]
      },
      "level": "automatique",
      "decision": "autorise",
      "window": null,
      "contest_ms": null
    },
    {
      "name": "paiement de 1000 a 5000 CHF",
      "description": "Une approbation ouvre, pour le même demandeur et le même bénéficiaire, une fenêtre de 8 heures et 20 paiements.",
      "tools": [ "sap.payments.create" ],
      "when": {
        "all": [
          { "path": "/arguments/currency", "op": "egal", "value": "CHF" },
          { "path": "/arguments/amount", "op": "strictement_superieur", "value": "1000" },
          { "path": "/arguments/amount", "op": "inferieur_ou_egal", "value": "5000" }
        ]
      },
      "level": "fenetre",
      "decision": null,
      "window": { "duration_ms": 28800000, "max_calls": 20, "same_arguments": [ "/arguments/beneficiary_iban" ] },
      "contest_ms": 0
    },
    {
      "name": "paiement > 5000 CHF",
      "description": "Chaque paiement est approuvé au seuil du jeu d'approbateurs.",
      "tools": [ "sap.payments.create" ],
      "when": {
        "all": [
          { "path": "/arguments/currency", "op": "egal", "value": "CHF" },
          { "path": "/arguments/amount", "op": "strictement_superieur", "value": "5000" }
        ]
      },
      "level": "revue",
      "decision": null,
      "window": null,
      "contest_ms": 0
    },
    {
      "name": "suppression de sinistre",
      "description": "Toute suppression attend 15 minutes après le seuil : un autre approbateur peut s'y opposer.",
      "tools": [ "crm.claims.delete" ],
      "when": null,
      "level": "revue",
      "decision": null,
      "window": null,
      "contest_ms": 900000
    }
  ],
  "approver_set": {
    "source": "registre",
    "chain_id": 2124,
    "registry": "0x172076e0166d1f9cc711c77adf8488051744980c",
    "set": "0x35312352c0065a3fc46ce14dba05df3fcee9fbc2",
    "members": null,
    "threshold": null
  },
  "separation": {
    "self_approval": "interdite",
    "identities": [
      { "launched_by": "u.martin@assureur-demo.example", "addresses": [ "0x90f79bf6eb2c4f870365e785982e1f101e93b906" ] }
    ]
  }
}
```

`chain_id` et `registry` sont ceux du réseau de développement
(`deployments/noorcore.json`). `set`, le jeu épinglé (EX-8.1), est l'adresse
synthétique du jeu de test 1 des vecteurs (A.2) : `deployments/noorcore.json`
ne déploie aucun `CuratorSet` pour `assureur-demo` ; une politique réelle y
écrit l'adresse du jeu de l'organisation. Les noms d'outils sont ceux des
vecteurs de CT-1 : un seul serveur d'outils, préfixe désactivé
(`tools.prefix: false`, CT-2 EX-4.10). Avec plusieurs serveurs, le nom
annoncé porte l'alias en préfixe (`sap__payments.create`) et la politique
l'écrit ainsi, comme celle de l'épreuve d'acceptation (A.5). Le demandeur
`u.martin@…` détient l'adresse du compte Hardhat 3 : il ne compte pas comme
approbateur de ses propres
demandes (section 10), et les décisions de référence de CT-1 sont signées
par les comptes Hardhat 1 et 2.

### 4.4 Sélection de l'outil

**EX-4.3** Un sélecteur est soit un nom annoncé exact, au motif de CT-1
(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`), soit un préfixe de ce motif suivi
d'un seul `*` final, soit `*` seul. Le nom annoncé est celui de CT-2 EX-4.10
(`<alias>__<nom d'origine>`, ou le nom d'origine quand le préfixe est
désactivé) et celui de `execution.tool`. Une règle sélectionne une demande
si l'un de ses sélecteurs vaut : un nom exact égal au nom annoncé, octet pour
octet, casse comprise ; un préfixe `p*` dont `p` est un préfixe du nom
annoncé (`*` seul : tout nom). Aucun autre joker n'existe.

Un alias de serveur ne contient pas de trait bas (CT-2 EX-4.9) : `sap__*`
désigne exactement les outils du serveur `sap`. Le joker final est le seul
motif du langage ; il se teste en temps linéaire (comparaison de préfixe) ;
le `like` de Cedar n'admet de même que le joker `*` (R2-F70).

### 4.5 Pointeurs

Une condition lit les arguments par un pointeur JSON (RFC 6901) appliqué à
la racine `R = { "arguments": A }`, où `A` est la valeur en clair des
arguments que le noyau transmet (`{}` quand la requête n'en porte pas, CT-2
§8.2). Un pointeur commence donc par `/arguments`.

**EX-4.4** Résolution d'un pointeur `p` sur `R` :

1. `p` est découpé sur `/` après son premier caractère ; chaque jeton est
   décodé en remplaçant `~1` par `/`, puis `~0` par `~`, dans cet ordre
   (RFC 6901 §4) ;
2. on part de `x = R` et, pour chaque jeton `j` dans l'ordre :
   - si `x` est un objet qui a un membre de nom `j` (égalité des suites de
     points de code), `x` devient ce membre ;
   - sinon, si `x` est un tableau, que `j` est `0` ou s'écrit
     `[1-9][0-9]{0,8}`, et que sa valeur est inférieure à la longueur du
     tableau, `x` devient cet élément ;
   - sinon le pointeur est **non résolu** ;
3. si tous les jetons ont été consommés, le pointeur est **résolu** et
   désigne `x`.

Un jeton `-`, un indice à zéro de tête (`01`), un indice de plus de 9
chiffres, un membre absent, un pas à travers une chaîne, un nombre, un
booléen ou `null` rendent le pointeur non résolu. Un pointeur qui désigne
`null` est résolu.

### 4.6 Types et valeurs

**EX-4.5** Une valeur résolue a l'un des types de JSON : chaîne, nombre,
booléen, `null`, objet, tableau. Pour les comparaisons numériques, une
valeur est **numérique** si et seulement si :

- c'est un nombre JSON dont la valeur mathématique est un entier de
  `[-(2^53-1), 2^53-1]` ; ou
- c'est une chaîne qui respecte la grammaire décimale de 4.7.

Toute autre valeur n'est pas numérique : un nombre JSON non entier (`7400.5`),
un entier hors de l'intervalle, une chaîne hors grammaire (`"7,400.00"`,
`"1e3"`, `" 12"`). Il n'y a aucune conversion implicite entre types : une
chaîne n'est jamais comparée à un booléen, un nombre jamais à une chaîne par
`egal`.

Le noyau ne transmet que des arguments dont chaque nombre a la même valeur
décimale exacte que sa forme JCS intégral (CT-2 EX-4.44) : la valeur vue par
la politique est celle sur laquelle le serveur agit. Une implémentation
JavaScript teste `Number.isInteger(x)` et `Math.abs(x) <= 2^53-1` sur le
nombre analysé ; une implémentation Go lit le texte du nombre sans passer
par `float64` (`json.Number`, `math/big`) et teste la même valeur. Les deux
lectures concordent sous cette précondition.

### 4.7 Comparaisons numériques exactes

**EX-4.6** Grammaire décimale, pour les arguments en chaîne comme pour les
littéraux de la politique :

```text
D = ^-?(0|[1-9][0-9]{0,29})(\.[0-9]{1,18})?$
```

Au plus 30 chiffres avant le point et 18 après ; pas de signe `+`, pas
d'exposant, pas de zéro de tête, pas de `.5` ni de `5.`, pas de séparateur,
pas d'espace. `-0` et `-0.00` valent zéro. Un littéral de la politique est
toujours une chaîne `D`, jamais un nombre JSON.

Une valeur numérique est représentée par un couple `(m, e)` d'entiers
exacts : pour un nombre JSON entier, `m` est sa valeur et `e = 0` ; pour une
chaîne `D`, `e` est le nombre de chiffres après le point (0 sans point) et
`m` l'entier formé des chiffres sans le point, avec le signe. Comparer
`(m1, e1)` et `(m2, e2)`, c'est comparer les entiers `m1 × 10^(E − e1)` et
`m2 × 10^(E − e2)`, avec `E = max(e1, e2)`. Le calcul se fait en entiers de
précision arbitraire (`BigInt` en JavaScript, `math/big` en Go) ; il ne
passe jamais par un flottant, ni par `Number()`, ni par l'ordre des chaînes.
Ainsi `"5000.00"` est numériquement égal à `"5000"` et à `5000`, et
`"5000.000000000000000001"` est strictement supérieur à `"5000"`.

Motifs : un flottant ne compare pas exactement (`0.1 + 0.2 === 0.3` est faux
en JavaScript), `JSON.parse("9007199254740993")` rend `9007199254740992`,
`"10.00" < "9.00"` est vrai dans l'ordre des chaînes, et `Number("1e3")`,
`Number("0x10")`, `Number("")` rendent 1000, 16 et 0 (R2-F89). La
comparaison d'entiers mis à la même échelle donne les résultats exacts
attendus (R2-F90). Cedar a un type `decimal` limité à quatre décimales, sur
un entier de 64 bits (R2-F71, R2-F72) ; CEL n'a pas de décimal (R2-F73). JSON
ne garantit l'accord des implémentations que pour les entiers de
`[-(2^53)+1, (2^53)-1]` (R2-F85), et JCS recommande d'écrire en chaînes les
nombres qui exigent plus de précision, en observant que des montants ne
reposeraient pas sur des flottants (R2-F86). Les montants de CT-1 sont déjà
des chaînes décimales (CT-1 §3) ; `D` contient tout montant de CT-1 qui a au
plus 30 chiffres avant le point (CT-1 en admet au plus huit après).

### 4.8 Chaînes et booléens

**EX-4.7** Deux chaînes sont égales si elles ont la même suite de points de
code. Aucune normalisation Unicode (NFC, NFD) n'est appliquée et la casse
compte, comme dans CT-1 §4 : `"CHF"` n'est pas égal à `"chf"`, et `é`
précomposé n'est pas égal à `e` suivi de U+0301. Un préfixe et un suffixe se
testent sur les points de code. Pour des chaînes bien formées, l'égalité et
les préfixes en unités UTF-16 (JavaScript) et en octets UTF-8 (Go) donnent
le même résultat. Deux booléens sont égaux s'ils ont la même valeur.

### 4.9 Prédicats

Un prédicat est l'objet `{ "path", "op", "value" }`. Il vaut toujours VRAI,
FAUX ou INDETERMINE :

| `op` | `value` | VRAI si la valeur désignée… | INDETERMINE si |
|---|---|---|---|
| `existe` | `null` | …existe : le pointeur est résolu (même vers `null`). Sinon FAUX. | jamais |
| `egal` | chaîne (≤ 1 024) ou booléen | …est du même type que `value` et lui est égale (4.8). Sinon FAUX. | non résolu, ou d'un autre type que `value` |
| `dans` | tableau de 1 à 1 024 chaînes distinctes | …est une chaîne égale à l'un des éléments. Sinon FAUX. | non résolu, ou pas une chaîne |
| `commence_par` | chaîne (1 à 1 024) | …est une chaîne qui commence par `value`. Sinon FAUX. | non résolu, ou pas une chaîne |
| `finit_par` | chaîne (1 à 1 024) | …est une chaîne qui finit par `value`. Sinon FAUX. | non résolu, ou pas une chaîne |
| `egal_numerique` | chaîne `D` | …est numérique et égale à `value` (4.7). Sinon FAUX. | non résolu, ou pas numérique |
| `strictement_superieur` | chaîne `D` | …est numérique et `> value`. Sinon FAUX. | idem |
| `superieur_ou_egal` | chaîne `D` | …est numérique et `≥ value`. Sinon FAUX. | idem |
| `strictement_inferieur` | chaîne `D` | …est numérique et `< value`. Sinon FAUX. | idem |
| `inferieur_ou_egal` | chaîne `D` | …est numérique et `≤ value`. Sinon FAUX. | idem |

Les noms des opérateurs numériques disent « strictement » ou « ou égal » :
aucun ne laisse au lecteur le choix entre comparaison stricte et large.

Un argument absent ou mal typé n'est donc ni « vrai » ni « faux » pour un
prédicat de comparaison : il est INDETERMINE, et la section 6 dit ce qu'il
advient de la règle. Seul `existe` teste l'absence. AWS IAM tient une clé
absente pour une non-correspondance (R2-F76) ; Cedar ignore une politique en
erreur, au risque qu'un `forbid` ne bloque pas, ce que sa propre
documentation signale (R2-F67, R2-F68). Ni l'un ni l'autre ne convient à un
garde-fou de paiement : un appel ne doit pas échapper à une règle restrictive
en omettant ou en déformant un argument.

### 4.10 Combinaisons et logique à trois valeurs

Une condition est un prédicat ou une combinaison : `{ "all": [ … ] }`,
`{ "any": [ … ] }`, `{ "none": [ … ] }`, chacune de 1 à 64 conditions.

**EX-4.8** Valeurs des combinaisons :

| Combinaison | VRAI si | FAUX si | INDETERMINE sinon |
|---|---|---|---|
| `all` (toutes) | tous les éléments valent VRAI | un élément au moins vaut FAUX | aucun FAUX, un INDETERMINE au moins |
| `any` (l'une) | un élément au moins vaut VRAI | tous les éléments valent FAUX | aucun VRAI, un INDETERMINE au moins |
| `none` (aucune) | tous les éléments valent FAUX | un élément au moins vaut VRAI | aucun VRAI, un INDETERMINE au moins |

C'est la logique à trois valeurs de Kleene : `none` est la négation de
`any`, et la négation d'INDETERMINE est INDETERMINE. Le résultat ne dépend
pas de l'ordre des éléments ; une implémentation PEUT s'arrêter dès qu'il
est acquis, puisqu'un prédicat n'a pas d'effet. CEL rend de même `&&` et `||`
commutatifs en absorbant une erreur quand l'autre opérande décide (R2-F74).

Pour qu'un argument facultatif ne rende pas une règle INDETERMINE, l'auteur
le garde par `existe` : `{ "all": [ { "path": "/arguments/priority", "op":
"existe", "value": null }, { "path": "/arguments/priority", "op": "egal",
"value": "haute" } ] }` vaut FAUX, et non INDETERMINE, quand `priority` est
absent.

### 4.11 Règles, ordre et règle par défaut

**EX-4.9** Une règle s'applique à une demande si elle la sélectionne (4.4)
et que sa condition n'est pas FAUX ; ce qu'elle donne alors dépend de son
niveau et de la valeur de sa condition (6.3). Toutes les règles qui
sélectionnent la demande sont évaluées. La décision est celle de l'issue de
plus haut rang. Parmi les issues de même rang, l'ordre du document désigne
la règle retenue `r* = P.rules[i*]`, la première (6.2). De `r*` seule
viennent :

- le nom et la marque écrits dans `policy.rule` ;
- le `contest_ms` du ticket créé ;
- au rang 3, le caractère ouvrant du ticket (marque vide), sa portée `K` et
  sa fenêtre (`duration_ms`, `max_calls`) ;
- au rang 2, la fenêtre consommée.

La décision rendue (`autorise`, `a_approuver` ou `refuse`) est donc
indépendante de l'ordre des règles, comme dans Cedar, où un `forbid`
l'emporte sur un `permit` (R2-F67, R2-F69), et dans AWS IAM, où un refus
explicite l'emporte (R2-F76) ; le sort du ticket ne l'est pas : fenêtre de
contestation, fenêtre ouverte, unité consommée (vecteurs `ordre.json` et
`ordre-inverse.json`, AP-12).

**EX-4.10** La règle par défaut est explicite et obligatoire. Elle décide
quand **aucune** règle ne s'applique, et seulement alors. Ses niveaux
possibles sont `automatique` (avec `autorise` ou `refuse`) et `revue`. Elle
n'a pas de condition. OPA emploie de même une valeur `default` quand aucune
règle n'est définie (R2-F75) ; Cedar et IAM refusent par défaut (R2-F67,
R2-F76). CT-3 laisse le client choisir la valeur, mais l'oblige à l'écrire.
La règle par défaut DEVRAIT être de niveau `revue` ; `autorise` ne convient
qu'à une politique dont les règles énumèrent tout ce qui doit être retenu ou
refusé.

### 4.12 Outils susceptibles d'approbation

Au chargement de l'ensemble de politique, et à chaque changement de la liste
agrégée des outils (message `charger`, 12.2), le noyau envoie la liste `L`
des noms annoncés et reçoit ceux « qu'une règle peut soumettre à approbation,
quels que soient leurs arguments » (CT-2 EX-7.4) ; pendant une
indisponibilité du service, ces outils sont bloquants, les autres lectures
passantes (CT-2 §14.2).

**EX-4.11** La liste rendue est `CANDIDATS(P, L)` : les noms de `L`, dans
l'ordre de `L`, sans doublon (première occurrence), pour lesquels l'une des
deux conditions vaut :

1. une règle qui sélectionne le nom a le niveau `fenetre` ou `revue`, ou le
   niveau `automatique` avec la décision `refuse` ;
2. la règle par défaut n'est pas (`automatique`, `autorise`) **et** aucune
   règle à `when` nul ne sélectionne le nom.

La condition 2 dit que la règle par défaut peut décider : elle le peut
tant qu'aucune règle inconditionnelle ne s'applique toujours au nom. Le
calcul ne lit ni les arguments ni l'état : il se refait à chaque message
`charger`. Il peut rendre un outil que, dans les faits, aucun argument ne
retiendrait (condition jamais vraie) : la liste est un sur-ensemble sûr.
Entre un changement de la liste agrégée et la réponse au `charger` qui le
suit, un nom absent de la liste `L` du dernier `charger` réussi est tenu
pour susceptible d'approbation (bloquant pendant une indisponibilité) : la
liste rendue ne vaut que pour les noms qu'elle a reçus (CT-2 EX-7.4,
EX-7.15).

CT-3 y range aussi les outils qu'une règle peut **refuser**. Pour CT-2, la
conséquence est la même que pour un outil à approuver : bloquant pendant une
indisponibilité. C'est la seule lecture qui ne laisse pas passer, pendant
une panne du service, une lecture que la politique refuserait (« la décision
ne peut pas être devinée », CT-2 §14.2).

Pour l'exemple de 4.3 et `L` = `crm.claims.get`, `crm.claims.delete`,
`documents.search`, `mail.send`, `sap.payments.create`, `sap.payments.list`,
la liste est `crm.claims.delete`, `mail.send`, `sap.payments.create`,
`sap.payments.list`. `mail.send` y est parce que sa règle est
conditionnelle et que la règle par défaut est `revue` ; `crm.claims.get`
n'y est pas parce qu'une règle inconditionnelle l'autorise toujours.

### 4.13 Versions de la politique

**EX-4.12** Le document n'a pas de nom propre : l'instance est nommée par
`policy.version` de l'ensemble (`code.policy_version`, CT-2 EX-10.21) et
identifiée par `policy_sha256`. Un nom de règle n'est unique que dans une
version : le couple (`code.policy_version`, nom) désigne une règle. Une
nouvelle version s'applique à toute demande dont le pas 3 de CT-2 §4.4
commence après le scellement de son événement de politique ; les demandes
déjà en cours finissent avec l'ancienne (CT-2 EX-15.5). Toute entrée en
vigueur d'une nouvelle version **ferme toutes les fenêtres** (5.3). Le sort
des tickets ouverts sous l'ancienne version est fixé par EX-7.21.

`version: 0` est la version du format. Un format différent prendra la
valeur `1`, avec son propre schéma ; un service v1 continue d'accepter v0.

### 4.14 Ce que le langage n'a pas, et pourquoi

**EX-4.13** Le langage n'a ni expression régulière, ni flottant, ni
arithmétique, ni quantificateur sur les éléments d'un tableau, ni agrégat
sur plusieurs appels, ni accès à une donnée extérieure à la demande, à
l'instant d'évaluation et à l'état des fenêtres. Une évaluation termine
toujours, en un temps borné par la taille de la politique et des arguments
(6.6).

Pas d'expression régulière : le moteur natif de JavaScript procède par retour
arrière et peut exploser exponentiellement (R2-F79) ; mesuré sur Node v22.22.0,
`/^(a+)+$/` prend 472,6 ms pour 26 caractères et quadruple tous les deux
caractères (R2-F80) ; le moteur linéaire de V8 reste expérimental (R2-F79,
R2-F80), alors que le paquet `regexp` de Go et RE2 sont linéaires (R2-F78,
R2-F82) : deux implémentations n'auraient pas la même complexité. Le
sous-ensemble « interopérable » des motifs de JSON Schema contient lui-même des
motifs dangereux (R2-F81), et la borne de temps que CT-2 prévoit pour la
rédaction (EX-10.23) donne une sortie sûre à la rédaction, pas à une décision :
à l'échéance, une politique devrait refuser (R2-F83, R2-F84). CT-2 version 0.3
a ajouté à son sous-ensemble des règles de structure et de taille, qui écartent
les formes exponentielles connues, et applique la borne de temps à tout ce que
ses motifs examinent (CT-2 EX-10.6, EX-10.23) ; un retour arrière polynomial
reste possible en ECMAScript, et la borne reste nécessaire. Les besoins
courants (devise, liste blanche, préfixe d'un compte, domaine d'une adresse)
s'écrivent avec `egal`, `dans`, `commence_par` et `finit_par`, qui se testent
en temps linéaire.

**EX-4.14** À la validation, le service DEVRAIT avertir, sans refuser :

- d'un sélecteur qui ne désigne aucun nom de la liste `L` reçue (un outil peut
  apparaître plus tard) ;
- d'un pointeur qui désigne un chemin qu'une règle `champ` de portée
  `arguments` rédige ou supprime (CT-2 §10.3.8) : la réévaluation de 6.8 ne
  pourra pas conclure pour ce prédicat ;
- d'une règle `fenetre` à plusieurs sélecteurs ou à joker (chaque outil a
  sa propre portée, EX-5.2, mais l'approbateur doit voir lesquels sa
  décision couvre, EX-9.4), dont `same_arguments` est vide ou dont `when`
  est nul (la fenêtre couvre alors toute valeur que la condition admet) ;
- d'un prédicat `egal` ou `dans` placé sous un nombre pair (zéro compris)
  de `none` dans la condition d'une règle `automatique` `refuse` (liste
  d'exclusion) : une liste d'exclusion à égalité exacte laisse passer une
  autre écriture de la même valeur (4.8). Sous un nombre impair de `none`, le
  prédicat forme une liste blanche (`none` sur `egal` ou `dans`), qui ne
  laisse rien passer d'autre que les valeurs écrites, et n'est pas signalé ;
- d'un demandeur configuré (`launched_by` fixe que le noyau transmet dans
  `requesters` de `charger`, 12.2) sans entrée dans `separation.identities`
  quand `self_approval` vaut
  `interdite` : la séparation des tâches ne peut pas être vérifiée pour lui
  (10.5).

Ces avertissements sont des diagnostics : ils ne changent ni la validation
ni l'évaluation, et leur texte n'est pas fixé par CT-3.

### 4.15 Vérifications d'évaluation

Chaque vérification a ses vecteurs dans `spec/vecteurs/ct-3` (annexe A.4).

| Id | Vérification | Règle |
|---|---|---|
| AP-1 | Un document non conforme au schéma est refusé avec exactement une erreur `schema` (pointeur nul), aucune autre règle n'étant vérifiée. | EX-4.2 |
| AP-2 | Deux règles de même nom, ou une règle du nom de la règle par défaut : refus. | EX-4.2 (1) |
| AP-3 | Un pointeur de plus de 32 jetons, une condition de plus de 8 niveaux, une règle de plus de 64 prédicats : refus. | EX-4.2 (2, 3) |
| AP-4 | Une chaîne du document avec un substitut isolé, un `launched_by` en double, `contest_ms ≥ expire_after_ms`, un jeu `statique` dont `threshold.size` diffère du nombre de `members` ou dont `required > size`, un jeu `statique` chargé avec `environment` = `production` : refus. | EX-4.2 (4 à 7), EX-8.2 |
| AP-5 | Sélection : nom exact, casse comprise ; préfixe `p*` ; `*` seul ; aucun autre joker. | EX-4.3 |
| AP-6 | Résolution des pointeurs : membres, indices, échappements `~0` et `~1`, `-`, `01`, indice hors limites, pas à travers un scalaire, membre `null`. | EX-4.4 |
| AP-7 | Typage numérique : entier JSON sûr ; chaîne `D` ; nombre non entier, entier hors intervalle, chaîne hors grammaire : non numérique. | EX-4.5, EX-4.6 |
| AP-8 | Comparaisons exactes : échelles différentes, négatifs, `-0`, égalité de `"5000"`, `"5000.00"` et `5000`, dix-huit décimales. | EX-4.6 |
| AP-9 | Chaînes et booléens : égalité sans normalisation, casse, `dans`, `commence_par`, `finit_par`, `egal` sur un booléen, type différent : INDETERMINE. | EX-4.7, table de 4.9 |
| AP-10 | Logique à trois valeurs : tables de `all`, `any`, `none` ; résultat indépendant de l'ordre des éléments. | EX-4.8 |
| AP-11 | Issue d'une règle selon son niveau et la valeur de sa condition (table 6.3). | EX-6.2, EX-6.3 |
| AP-12 | Combinaison : rang maximal ; à rang égal, première règle du document, dont viennent le nom, `contest_ms`, la fenêtre ouverte ou consommée, la décision restant la même dans l'autre ordre ; règle par défaut si aucune règle ne s'applique, et seulement alors. | EX-4.9, EX-4.10, EX-6.1 |
| AP-13 | Forme exacte de `policy.rule` : nom seul, marque ` [indetermine]`, marque ` [fenetre <ticket> <fin>]`. | EX-6.4 |
| AP-14 | Fenêtre : ouverture à `approval.at`, portée (outil, demandeur, `same_arguments`), bornes `[debut, fin)`, décompte, remplacement d'une fenêtre de même portée ; une fenêtre d'un outil ne couvre pas un autre outil de la même règle. | EX-5.2, EX-5.4, EX-5.5 |
| AP-15 | Fenêtre : aucune ouverture sous INDETERMINE ni après `refuse` ou `expire` ; fermeture et retrait à `fin`, à `max_calls`, au changement de `policy_version`. | EX-5.3, EX-5.6 |
| AP-16 | Outils susceptibles d'approbation : conditions 1 et 2, ordre de `L`, doublons. | EX-4.11 |
| AP-17 | Déterminisme : mêmes entrées, même sortie, quel que soit l'ordre des membres des objets, dans les arguments comme dans le document. | EX-6.6 |

## 5. Les trois niveaux

### 5.1 Vue d'ensemble

Le niveau d'une règle dit quand un humain intervient. L'architecture
n'admet que trois sorties d'évaluation (`autorise`, `a_approuver`, `refuse`)
et trois décisions humaines (`approuve`, `refuse`, `expire`) ; chaque niveau
s'y projette sans valeur nouvelle et sans relâcher le principe : un appel
soumis à approbation n'est jamais relayé avant la décision signée au seuil.

| Niveau | Qui décide de cet appel | Quand un humain intervient | Recherche |
|---|---|---|---|
| `automatique` | La règle seule : `autorise` ou `refuse` | En écrivant la politique, avant ; jamais pour l'appel | Refus explicite prioritaire et refus par défaut (R2-F67, R2-F76) |
| `fenetre` | La règle, sous une fenêtre ouverte par une décision humaine au seuil | Une fois pour la demande qui ouvre la fenêtre, puis plus pendant sa durée | Autorisations bornées dans le temps (R3-F69, R3-F72 à R3-F77, R3-F83) |
| `revue` | Les approbateurs, au seuil, pour cet appel exact | À chaque appel, avant le relais | Double autorisation, quatre yeux (R3-F9, R3-F55, R3-F56, R3-F59) ; autorisation d'une requête précise (R3-F93 à R3-F95) |

### 5.2 Automatique

**EX-5.1** Une règle `automatique` décide seule. Avec `decision: "autorise"`,
l'appel est relayé : `policy.decision = "autorise"`, `policy.ticket = null`,
`approval = null`. Avec `decision: "refuse"`, il ne l'est pas : événement
`refusee`, `policy.decision = "refuse"`, `policy.ticket = null`,
`approval = null`. `policy.rule` porte le nom de la règle (6.4).

Le contrôle humain du niveau automatique est la politique elle-même : elle
est écrite à l'avance, son empreinte entre dans la chaîne avant tout appel
qu'elle décide (CT-2 EX-9.1), et sa décision se recalcule (6.8). C'est aussi
la seule forme qu'un accès d'urgence peut prendre en version 0 : une règle
`automatique` à `autorise` ajoutée par un changement de politique et retirée
par un autre. NIST admet qu'une activation d'urgence contourne
l'autorisation normale, mais demande une désactivation automatique au bout
d'un délai défini (R3-F68, R3-F69) ; Microsoft demande une alerte à chaque
usage et une revue a posteriori (R3-F82), AWS un journal de toutes les
tentatives et des alertes (R3-F91). En version 0, la
règle d'urgence est visible dans la chaîne mais n'expire pas d'elle-même :
une échéance de règle est une proposition pour une version 1 (section 16).

### 5.3 Fenêtre

Une règle `fenetre` traite la première demande d'une portée comme une revue,
puis, une fois cette demande approuvée au seuil, autorise sans nouvelle
approbation les demandes suivantes de la même portée, pendant une durée et
pour un nombre d'appels bornés.

Ce niveau reprend les autorisations bornées dans le temps des systèmes
d'accès privilégié : Microsoft Entra PIM distingue l'attribution
« éligible » de l'activation, que l'on peut soumettre à approbation, pour une
durée de 1 à 24 heures (R3-F72 à R3-F77) ; Google Cloud PAM accorde un rôle
pour une durée maximale et le retire à son terme (R3-F83) ; NIST demande la
désactivation automatique des comptes temporaires au bout d'un délai défini
(R3-F69). HashiCorp Vault fait le contraire, et c'est le niveau `revue` :
ses groupes de contrôle autorisent une requête précise, pas une portée
(R3-F93, R3-F94). GitHub peut écarter, et GitLab écarte par défaut, une
approbation quand le contenu approuvé change (R3-F104, R3-F108) : de même,
une fenêtre ne couvre que la règle, l'outil, le demandeur et les valeurs
désignées de la demande approuvée.

L'objet signé `A` de la version 0 lie une seule demande (`request_hash`) et
ne porte ni durée ni portée (R1-F8, R3-F122). Un appel couvert par une
fenêtre ne peut donc pas porter l'objet `approval` de la demande ouvrante :
le contrôle 7 dirait de cet appel qu'il a été approuvé, alors que les
approbateurs ne l'ont pas vu. Il est `autorise`, et `policy.rule` nomme le
ticket qui a ouvert la fenêtre. Un tel appel n'est pas soumis à approbation :
la politique l'autorise parce qu'une décision signée au seuil, antérieure et
journalisée, a ouvert la fenêtre ; le principe de l'architecture tient.

**EX-5.2** La **portée** d'une demande `d` pour une règle `fenetre` `r` est
la clé `K = (policy_version en vigueur, r.name, d.tool_announced,
d.delegation.launched_by, v_1, …, v_n)`, où `v_i` est la chaîne que désigne
dans `d` le `i`-ième pointeur de `r.window.same_arguments`. L'outil annoncé
fait partie de la portée : la fenêtre ouverte par l'approbation d'un outil
d'une règle à plusieurs sélecteurs ne couvre aucun autre outil de cette
règle (`scope.tool` de `$defs/portee`, ticket-v0). Si l'un de ces pointeurs
n'est pas résolu ou ne désigne pas une chaîne, la portée est indéterminée et la
condition de `r` est combinée par `all` avec INDETERMINE (6.2). Le demandeur
fait toujours partie de la portée : il vient de la configuration de la
connexion d'hôte, jamais d'une valeur déclarée par l'hôte (CT-2 EX-7.2).

**EX-5.3** **Ticket ouvrant.** Une demande dont l'issue retenue est celle
d'une règle `fenetre` au rang 3 avec une condition VRAI (6.3) crée un ticket
**ouvrant**, qui mémorise sa portée `K`. Une issue de rang 3 avec une
condition INDETERMINE crée un ticket non ouvrant. La demande ouvrante suit
le cycle de la revue (5.4) : `a_approuver`, ticket, décision, appel relayé
avec `approval`.

**EX-5.4** **Ouverture.** Quand le noyau accuse réception du scellement
d'une décision `approuve` d'un ticket ouvrant (section 12), et si la
`policy_version` en vigueur est encore celle de `K`, le service ouvre la
fenêtre `W(K)` : `debut = approval.at` de la décision scellée ; `fin = debut
+ window.duration_ms` ; `restant = window.max_calls` ; `ticket` =
l'identifiant du ticket. Une fenêtre `W(K)` déjà ouverte est remplacée. Une
fenêtre dont `fin` n'est pas postérieure à l'instant de l'acquittement
n'est pas ouverte. Une décision `refuse` ou `expire` n'ouvre rien. L'appel
ouvrant est relayé comme tout appel approuvé (CT-2 EX-7.12) et ne compte
pas dans `restant`. Pour un ticket ouvrant, la console DOIT montrer, avant
le vote, ce que la décision ouvrira : l'outil couvert, et lui seul ; la
condition `when` rendue lisible ; chaque pointeur de `same_arguments` avec
sa valeur ; « au plus `max_calls` appels, chacun satisfaisant la condition,
jusqu'à `approval.at` + `duration_ms` » (sections 9 et 13).

**EX-5.5** **Usage.** `W(K)` couvre la demande `d` à l'instant `t` si la
règle de `K` sélectionne `d` avec une condition VRAI, si la portée de `d`
est `K` (même outil annoncé compris), si `debut ≤ t < fin` et si
`restant ≥ 1`. L'issue de la règle est
alors `autorise` au rang 2, avec la marque ` [fenetre <ticket> <fin>]`
(6.4). Si cette issue est celle que l'évaluation retient (6.2), `restant`
diminue de 1 ; sinon la fenêtre n'est pas consommée.

**EX-5.6** **Fermeture.** `W(K)` ne couvre plus rien dès que `t ≥ fin`, que
`restant = 0`, qu'une autre `policy_version` entre en vigueur (EX-4.12), ou
que le service a perdu son état : une fenêtre que le service ne retrouve pas
à la reprise est fermée (EX-7.23). Une fenêtre fermée est retirée de l'état
du service, avec les valeurs en clair de sa portée (EX-7.24) : à `fin`, par
un minuteur (EX-7.7), à la consommation de sa dernière unité, et à l'entrée
en vigueur d'une autre version. Rien d'autre ne la ferme en version 0 ; la
fermeture anticipée passe par un changement de politique, journalisé. Ce
changement suspend d'un coup toutes les autorisations en cours : il peut
contribuer à une procédure d'arrêt comparable à celle de l'art. 14 § 4 e) du
règlement (UE) 2024/1689, et à la suspension de son art. 26 § 5 (R3-F8,
R3-F21), ce qui n'est pas un avis de conformité. Ces articles s'appliquent
aux systèmes à haut risque de l'annexe III à partir du 2 décembre 2027 : le
règlement (UE) 2026/1744 a reporté l'application du chapitre III, sections 1
à 3, sans modifier les art. 14 et 26 (R3-F26 à R3-F28).

`debut` vient de l'horloge de l'enregistreur (`approval.at`), `t` de celle
du service : un écart entre les deux horloges déplace d'autant la fin
effective de la fenêtre. Le service DEVRAIT donc employer la même source de
temps que l'enregistreur (CT-2 EX-7.10), et le réviseur ne conclut sur `fin`
qu'à cet écart près (6.8).

`window.duration_ms` est borné à 24 heures, la borne haute de l'activation
PIM (R3-F75) et celle des délais de CT-2 ; `max_calls` à 10 000.

### 5.4 Revue

**EX-5.7** Une règle `revue` soumet chaque demande qu'elle retient aux
approbateurs : `policy.decision = "a_approuver"`, un ticket, l'événement
`retenue`, puis une décision `approuve`, `refuse` ou `expire` au seuil du jeu
figé dans le ticket (section 8). Un appel n'est relayé qu'après une décision
`approuve` scellée (EX-3.1). Ni une règle (le seuil est celui du
`CuratorSet`, CT-1 §5.3), ni une escalade (EX-7.13), ni un réglage du
service (EX-10.11) ne peut abaisser le seuil d'un ticket ; seul un
changement du `CuratorSet` lui-même, visible sur la chaîne, change le jeu et
le seuil d'un ticket en attente (EX-8.6).

La revue est la double autorisation du NIST, qui exige l'accord de deux
personnes autorisées avant l'exécution (AC-3(2), CM-5(4), R3-F55, R3-F56) et
interdit le changement avant les approbations requises (CM-3(1), R3-F59) ;
elle a la forme de la « vérification et confirmation distinctes de cette
identification par au moins deux personnes physiques » que l'art. 14 § 5 du
règlement sur l'IA exige pour les systèmes qu'il vise (R3-F9 à R3-F11), sans
que CT-3 dise si un système client en relève (section 1). Le considérant 73
admet que l'une de ces personnes soit celle qui fait fonctionner le système et
que l'enregistrement automatique des vérifications dans les journaux puisse
suffire (R3-F12) : c'est ce que fait la décision scellée, et c'est pourquoi
l'auto-approbation est un réglage (section 10) plutôt qu'une interdiction
absolue. Un seuil de deux ou plus sur des adresses distinctes réalise la
double autorisation ; deux adresses ne prouvent pas deux personnes, d'où
l'exigence d'une clé par personne (section 8).

### 5.5 Projection sur CT-1

**EX-5.8** Chaque niveau n'emploie que les valeurs de CT-1, dans ces
combinaisons et nulle autre :

| Niveau, cas | Événement | `execution.status` | `policy.decision` | `policy.ticket` | `approval` |
|---|---|---|---|---|---|
| `automatique`, `autorise` | Appel | `executee` | `autorise` | `null` | `null` |
| `automatique`, `refuse` | Appel | `refusee` | `refuse` | `null` | `null` |
| `fenetre`, appel couvert | Appel | `executee` | `autorise` | `null` | `null` |
| `fenetre` (demande ouvrante) et `revue` | Demande | `retenue` | `a_approuver` | ticket | `null` |
| idem | Décision | `executee` | `sans_objet` | ticket | `approuve`, `refuse` ou `expire` |
| idem, après `approuve` | Appel relayé | `executee` | `a_approuver` (repris de la demande, CT-2 EX-7.12) | ticket | l'objet de la décision |
| idem, après `refuse` ou `expire` : ré-émission reconnue, ou fin de la requête retenue | Appel refusé | `refusee` | `a_approuver` (repris de la demande, EX-7.18, EX-11.5) | ticket | l'objet de la décision |
| Règle par défaut | Comme `automatique` ou `revue`, selon son niveau | — | — | — | — |

### 5.6 Fenêtre de contestation

La fenêtre de contestation est un délai entre l'instant où le seuil
d'approbation est atteint et la remise de la décision `approuve`. Pendant ce
délai, un membre éligible du jeu figé peut s'opposer ; un refus reçu avant
que le seuil soit atteint vaut déjà opposition. Elle s'applique aux tickets des
règles `revue` et `fenetre` (et de la règle par défaut `revue`) dont
`contest_ms` est positif.

**EX-5.9** Pour un ticket dont la règle a `contest_ms > 0`, le service NE
DOIT PAS remettre au noyau une décision `approuve` avant la fin d'une
fenêtre de contestation sans objection :

1. la fenêtre s'ouvre à l'instant `s`, sur l'horloge du service, où le seuil
   de votes `approuve` comptés est atteint (sections 7 et 10), et dure
   `contest_ms` ;
2. une **objection** est un vote `refuse` accepté (EX-9.10) d'un membre
   éligible du jeu figé du ticket, reçu pendant la collecte (`ouvert`,
   `seuil_atteint` ou `verification`), avant ou pendant la fenêtre ; elle
   reste inscrite, avec son auteur et son instant, tant que son auteur ne
   vote pas `approuve` (EX-10.8) : ni une récusation, ni un nouveau gel, ni
   un vote d'un autre membre ne la lève ;
3. sans objection, et si le seuil est resté atteint pendant toute la
   fenêtre, la décision `approuve` est calculée à `s + contest_ms` et remise
   au plus tôt à cet instant, après la confirmation du jeu (EX-8.7) ; si les
   approbations passent sous le seuil pendant la fenêtre, celle-ci est
   annulée, et une nouvelle fenêtre complète s'ouvre quand le seuil est de
   nouveau atteint (EX-7.27) ;
4. une objection annule la fenêtre, ou l'empêche de s'ouvrir si elle
   précède le seuil, et suspend la remise ; le ticket reste ouvert. Si toutes
   les objections sont retirées par leurs auteurs, chacune remplacée par un vote
   `approuve` selon la règle de vote d'EX-7.26, et que le seuil est atteint, une
   nouvelle fenêtre complète s'ouvre à cet instant. Sinon le ticket finit en
   `refuse` si le seuil de votes `refuse` est atteint (CT-1 A-3), ou en `expire`
   à son échéance.

Avec `contest_ms = 0`, il n'y a pas de fenêtre : les votes se comptent selon
le décompte d'EX-7.27.

**EX-5.10** `contest_ms` DOIT être inférieur à
`/policy/approval/expire_after_ms` (EX-4.2) : une fenêtre de contestation
qui finit après l'échéance du ticket le ferait expirer.

La fenêtre de contestation n'ajoute aucune valeur aux formats : la chaîne ne
reçoit que la décision finale, et une objection n'y laisse pas de trace en
version 0 (3.4). Elle ne relâche pas le principe : elle ne fait que retarder
une approbation.

Ce n'est pas le droit de contester du RGPD. L'art. 22 § 3 et le
considérant 71 donnent à la personne concernée par une décision
automatisée, dans les cas de l'art. 22 § 2, points a) et c), après la
décision, le droit d'obtenir une intervention humaine, d'exprimer son point
de vue et de contester la décision (R3-F31, R3-F32) ; selon les lignes
directrices WP251rev.01 (p. 21 et 27), endossées par le Comité européen de
la protection des données, le réexamen doit être fait par une personne qui
a l'autorité de changer la décision (R3-F35, R3-F37, R3-F38). La LPD donne le
droit de faire valoir son point de vue et d'exiger une revue par une personne
physique, sans employer le mot « contester » (R3-F42, R3-F46). Le droit
d'opposition de l'art. 21 du RGPD est encore un autre droit (R3-F33). La fenêtre
de contestation est un contrôle interne, avant l'action, comparable au retrait
d'une demande en attente par le demandeur chez Google Cloud PAM (fonction en
préversion, R3-F85) ou au refus d'un seul approbateur qui clôt une demande
(R3-F87, fonction en préversion ; R3-F112). Elle rejoint la possibilité que
l'art. 14 § 4 d) du règlement sur l'IA donne aux personnes chargées du
contrôle de décider de ne pas utiliser la sortie d'un système (R3-F7) ; ce
rapprochement n'est pas un avis de conformité. Le dossier peut documenter qu'une
personne est intervenue avant l'action ; il ne remplace pas la procédure de
réexamen d'une décision contestée, qui appartient au client. La règle de vote et
le décompte sont en 7.11 ; les objections, ce qui est journalisé et ce qui est
vérifiable, en section 10.

### 5.7 Ce que chaque niveau prouve dans un dossier

Le dossier est celui de CT-1 §11 ; les phrases sont celles de CT-6 (§6.5,
§7). « Hors CT-6 v0 » désigne ce qu'un réviseur établit avec des pièces ou
des événements que le dossier n'emporte pas, sans que le vérificateur le
contrôle.

| Niveau, événement prouvé | Contrôle 7 (CT-6) | Ce que le réviseur établit en plus, hors CT-6 v0 | Ce qui n'est pas prouvé |
|---|---|---|---|
| `automatique`, appel `autorise` ou `refusee` | Non exécuté, raison admise « aucune approbation liée » | Avec la pièce de l'ensemble de politique et la pièce « arguments » : la règle donne bien cette décision (6.8) | Qu'un humain a vu l'appel : aucun ne l'a vu. Que le service a évalué la politique : seule la réévaluation le montre |
| `fenetre`, appel couvert | Non exécuté, même raison | Avec le dossier de la décision du ticket ouvrant nommé par `policy.rule` : des approbateurs ont signé la demande ouvrante, au seuil déclaré, à `approval.at`. Avec la politique : `fin = approval.at + duration_ms`. Avec l'événement `retenue` du ticket : même demandeur et même outil (`execution.tool`). Avec le journal : nombre d'appels couverts | Que les approbateurs ont vu cet appel : ils ne l'ont pas vu. Que `t < fin` exactement : `ts` de l'appel est postérieur à `t` (6.8) |
| `revue` et demande ouvrante, appel relayé | Exécuté : les adresses nommées ont signé `A` pour cette demande exacte (`request_hash`, A-4 si la demande est un voisin), en nombre au moins égal au seuil du jeu déclaré | Avec la politique et l'événement `retenue` : la séparation des tâches (section 10) et une décision scellée avant l'échéance, `approval.at < ts + E` (EX-7.10, 10.5) | Que le jeu déclaré est celui du registre (CT-6 EX-3.6, section 8) ; que les approbateurs ont lu ce qu'ils signaient (CT-6 §7) ; que la fenêtre de contestation a été respectée |
| `revue`, décision `refuse` ou `expire` | Exécuté : « porte un refus signé par … » ou « porte une demande d'approbation expirée sans signature » | — | Pourquoi personne n'a décidé, pour `expire` |

## 6. Évaluation

### 6.1 Entrées et sortie

Le service évalue une demande `d` reçue au pas 3 de CT-2 §4.4. Il lit, et
ne lit que (EX-3.5) :

| Entrée | Source |
|---|---|
| `P` | La politique d'approbation de l'ensemble en vigueur, valide (EX-4.2) |
| `d.tool_announced` | Nom annoncé (CT-2 EX-7.4) |
| `d.arguments` | Arguments en clair, valeur JSON analysée (CT-2 EX-7.4, EX-4.44) |
| `d.delegation.launched_by` | Demandeur (CT-1 §5.3, CT-2 EX-7.2) |
| `t` | Instant de réception de la demande, horloge du service, UTC, milliseconde |
| `F` | Les fenêtres ouvertes (5.3) |

La sortie d'`EVALUER` est `{ "rule", "decision", "ticket" }`, dans les
formes de CT-1 §5.3 : `rule` est la chaîne de 6.4, `decision` est
`autorise`, `a_approuver` ou `refuse`, `ticket` est l'identifiant du ticket
créé pour `a_approuver`, `null` sinon. Pour une ré-émission reconnue, la
section 7 fixe la réponse ; celle d'un ticket décidé `approuve` est
`autorise` avec, en plus, l'objet `approval` de la décision scellée, que le
noyau compare à la sienne et recopie (CT-2 §4.4 pas 3, EX-7.12, EX-7.21). La
forme exacte des messages est en section 12 ; la réponse à `evaluer`, que
CT-2 EX-7.4 reçoit, porte en plus `ticket_state`, `approval` et
`approver_set` (12.3).

**EX-6.1** Pour une demande qui n'est pas une ré-émission reconnue
(EX-7.6), le service DOIT rendre exactement le résultat de l'algorithme
`EVALUER` de 6.2, avec la règle d'issue de 6.3 et la chaîne de 6.4. Les
erreurs de 12.8 (`non_pret`, `politique_inconnue`, `plafond_atteint`) ne
sont pas des décisions : aucun ticket n'est créé, et le noyau les traite
comme une indisponibilité du service (12.3, EX-14.1).

### 6.2 Algorithme

Fonctions de la section 4 : `SELECTIONNE` (EX-4.3), `RESOUDRE` (EX-4.4),
`PREDICAT` (table 4.9, avec `NUMERIQUE` et `COMPARER` de EX-4.5 et EX-4.6),
`VALEUR` (récursion sur `all`, `any`, `none`, EX-4.8). `ET` est le `all` de
EX-4.8 à deux éléments.

```text
EVALUER(P, d, F, t) :
  R := { "arguments": d.arguments }
  C := liste vide                                   # issues candidates
  pour i de 0 à |P.rules| − 1, dans l'ordre du document :
      r := P.rules[i]
      si SELECTIONNE(r.tools, d.tool_announced) est faux : passer à la règle suivante
      v := VRAI si r.when = null, sinon VALEUR(r.when, R)
      si r.level = "fenetre" :
          v := ET(v, VRAI si la portée de d pour r est déterminée, sinon INDETERMINE)   # EX-5.2
      si v = FAUX : passer à la règle suivante
      (k, x, m) := ISSUE(r, v, d, F, t)             # table 6.3
      si k > 0 : ajouter (k, i, x, m) à C
  si C est vide :                                   # règle par défaut, EX-4.10
      nom := P.default.name
      x := P.default.decision si P.default.level = "automatique", "a_approuver" sinon
      ouvrant := faux
  sinon :
      k* := le plus grand k de C
      (k*, i*, x*, m*) := l'élément de C de rang k* dont i est le plus petit
      nom := P.rules[i*].name ‖ m*
      x := x*
      ouvrant := (k* = 3 et m* est vide)            # EX-5.3
      si k* = 2 : consommer la fenêtre qui a donné cette issue      # EX-5.5
  ticket := null
  si x = "a_approuver" :                            # T1 de 7.5
      c := P.default.contest_ms si C est vide, P.rules[i*].contest_ms sinon
      o := si ouvrant : { la portée K de d pour r* = P.rules[i*] (EX-5.2),
           r*.window.duration_ms, r*.window.max_calls } ; null sinon  # EX-5.3
      ticket := créer un ticket avec la règle nom, c et o (section 7)
  rendre { "rule": nom, "decision": x, "ticket": ticket }
```

`‖` est la concaténation de chaînes. Hors la consommation d'une fenêtre et
la création d'un ticket, aucune ligne n'a d'effet (6.5). `c` et `o` vont au
ticket créé et ne sont pas rendus au noyau ; avec `rule` et `decision`, ils
forment l'objet `$defs/evaluation` de `ticket-v0` (`contest_ms`, `opening`)
que les traces de l'annexe A.6 donnent à l'entrée `evaluer`, et les cas
d'évaluation de l'annexe A.4 attendent `contest_ms` et `opening`. Entre des
issues de même rang, `i*` désigne la règle d'où viennent le nom, `c`, `o`
et la fenêtre consommée (EX-4.9).

### 6.3 Issue d'une règle

**EX-6.2** `ISSUE(r, v, d, F, t)` rend un rang `k`, une décision `x` et une
marque `m` :

| Niveau et décision de `r` | `v` = VRAI | `v` = INDETERMINE |
|---|---|---|
| `automatique`, `autorise` | `(1, autorise, "")` | `(0)` : la règle ne s'applique pas |
| `automatique`, `refuse` | `(5, refuse, "")` | `(5, refuse, " [indetermine]")` |
| `fenetre` | si une fenêtre `W(K)` couvre `d` à `t` (EX-5.5) : `(2, autorise, " [fenetre <ticket> <fin>]")` ; sinon `(3, a_approuver, "")` | `(3, a_approuver, " [indetermine]")` |
| `revue` | `(4, a_approuver, "")` | `(4, a_approuver, " [indetermine]")` |

Les rangs ordonnent les issues de la moins restrictive à la plus
restrictive : autorisation par règle (1), autorisation sous fenêtre (2),
approbation qui ouvrira une fenêtre (3), revue (4), refus (5). Une
autorisation sous fenêtre est plus restrictive qu'une autorisation simple
parce qu'elle exige une fenêtre ouverte ; une revue l'emporte sur une
approbation ouvrante parce que la demande que retient une règle `revue` ne
doit pas ouvrir de fenêtre.

**EX-6.3** Une condition INDETERMINE ne rend jamais une décision moins
restrictive que la même condition VRAI : une règle `automatique` à
`autorise` ne s'applique pas, une règle restrictive s'applique avec sa
décision, et une règle `fenetre` ne peut ni employer ni ouvrir de fenêtre.
C'est l'échec vers la restriction : l'inverse du « skip on error » de Cedar,
dont la documentation reconnaît qu'il peut empêcher un `forbid` de bloquer
(R2-F68).

### 6.4 La chaîne `policy.rule`

**EX-6.4** `policy.rule` est le nom de la règle retenue, suivi de sa marque :

| Cas | `policy.rule` | Exemple |
|---|---|---|
| Condition VRAI, hors fenêtre ouverte | `<nom>` | `paiement > 5000 CHF` |
| Condition INDETERMINE | `<nom> [indetermine]` | `paiement > 5000 CHF [indetermine]` |
| Appel couvert par une fenêtre | `<nom> [fenetre <ticket> <fin>]` | `paiement de 1000 a 5000 CHF [fenetre apr-3001 2026-11-05T16:00:00.000Z]` |
| Règle par défaut | `<nom de la règle par défaut>` | `defaut : revue` |

`<ticket>` est l'identifiant du ticket ouvrant, `<fin>` l'instant `fin` au
format de CT-1 §3 (RFC 3339, UTC, trois décimales, `Z`). Un nom ne contient
pas de crochet et ne finit pas par une espace (4.2), et l'identifiant d'un
ticket ne contient ni espace ni crochet (EX-7.1) : la marque se retrouve
sans ambiguïté après la dernière occurrence de ` [`. La longueur reste sous
les 1 024 caractères de CT-1 (256 pour le nom, au plus 164 pour la marque).

Les noms de CT-1 (`paiement > 5000 CHF`, `beneficiaire hors liste blanche`,
`outil mail.send : envoi autorise vers l'assure`) sont des noms valides : la
chaîne `policy.rule` des vecteurs CT-1 et CT-2 a déjà la forme d'une règle
retenue avec une condition VRAI.

### 6.5 Effets de l'évaluation

**EX-6.5** L'évaluation a deux effets, et deux seulement : consommer une
unité de la fenêtre dont l'issue est retenue (rang 2, EX-5.5), et créer un
ticket pour une décision `a_approuver` (section 7). Une fenêtre épuisée
reste dans la copie que rend `EVALUER`, avec `restant = 0` ; c'est le
service qui la retire ensuite de son état (EX-5.6). Une issue candidate qui
n'est pas retenue ne consomme rien. Une unité consommée l'est même si le
noyau ne relaie pas l'appel ensuite (mode dégradé, CT-2 §14) : une fenêtre
autorise donc **au plus** `max_calls` appels.

### 6.6 Déterminisme et bornes

**EX-6.6** Le résultat d'`EVALUER` ne dépend que de `P`,
`d.tool_announced`, `d.arguments`, `d.delegation.launched_by`, `F` et `t`.
Il ne dépend ni de l'ordre des membres d'un objet des arguments ou du
document, ni de la plateforme, ni de la langue, ni d'un flottant, ni de
l'ordre d'itération d'une table de hachage. Deux implémentations conformes
rendent, sur les mêmes entrées, la même chaîne `rule` et la même
`decision`.

**EX-6.7** Une évaluation lit au plus 1 024 règles, 64 prédicats par règle,
1 024 éléments par `dans`, et résout des pointeurs d'au plus 32 jetons ;
chaque comparaison porte sur des chaînes d'au plus 1 024 caractères pour
les littéraux, et sur des décimaux d'au plus 48 chiffres. Son coût est
linéaire en la taille de la politique et des valeurs lues. Le service DOIT
répondre dans `/policy/approval/timeout_ms` (CT-2 EX-7.4) ; au-delà, CT-2
applique sa matrice de panne.

### 6.7 Cas limites

Issues de la politique de 4.3, pour le demandeur `u.martin@…`, avec des
arguments complets (`currency` `"CHF"`, `beneficiary_iban`
`"CH9300762011623852957"`, de la liste blanche) sauf mention contraire. La
fenêtre `apr-3001` de la règle `paiement de 1000 a 5000 CHF` est ouverte pour
ce demandeur et ce bénéficiaire de `2026-11-05T08:00:00.000Z` à
`2026-11-05T16:00:00.000Z`, avec 20 appels restants, quand la ligne le dit ;
`t = 2026-11-05T10:00:00.000Z`.

| Outil, arguments | Ce qui joue | `decision` | `policy.rule` |
|---|---|---|---|
| `crm.claims.get`, `{ "claim_id": "2026-77812" }` | règle inconditionnelle, rang 1 | `autorise` | `outil crm.claims.get : lecture autorisee` |
| `sap.payments.create`, `amount` `"7400.00"` | `paiement > 5000 CHF` VRAI, rang 4 | `a_approuver` | `paiement > 5000 CHF` |
| idem, `beneficiary_iban` hors liste | refus VRAI, rang 5, l'emporte | `refuse` | `beneficiaire hors liste blanche` |
| `amount` `"800"` | rang 1 | `autorise` | `paiement <= 1000 CHF` |
| `amount` `"2500.00"`, pas de fenêtre | `fenetre` VRAI sans fenêtre, rang 3, ticket ouvrant | `a_approuver` | `paiement de 1000 a 5000 CHF` |
| `amount` `"2500.00"`, fenêtre ouverte | rang 2 ; 19 appels restants | `autorise` | `paiement de 1000 a 5000 CHF [fenetre apr-3001 2026-11-05T16:00:00.000Z]` |
| idem, `beneficiary_iban` `"CH5604835012345678009"` | autre portée, rang 3 | `a_approuver` | `paiement de 1000 a 5000 CHF` |
| `amount` `"5000.00"` | `≤ 5000` VRAI, `> 5000` FAUX, rang 3 | `a_approuver` | `paiement de 1000 a 5000 CHF` |
| `amount` `"5000.000000000000000001"` | `> 5000` VRAI, rang 4 | `a_approuver` | `paiement > 5000 CHF` |
| `amount` `7400` (nombre JSON) | entier, numérique, rang 4 | `a_approuver` | `paiement > 5000 CHF` |
| `amount` `7400.5` (nombre JSON) | non numérique : les trois règles de montant sont INDETERMINE ; l'autorisation ne s'applique pas ; rang 4 | `a_approuver` | `paiement > 5000 CHF [indetermine]` |
| `amount` `"7,400.00"` | hors grammaire, même cas | `a_approuver` | `paiement > 5000 CHF [indetermine]` |
| `amount` absent | même cas | `a_approuver` | `paiement > 5000 CHF [indetermine]` |
| `currency` absent | `none` d'un INDETERMINE : refus INDETERMINE, rang 5 | `refuse` | `paiement hors CHF [indetermine]` |
| `currency` `"chf"` | casse : `egal` FAUX, `none` VRAI | `refuse` | `paiement hors CHF` |
| `amount` `"2500.00"`, `beneficiary_iban` absent, fenêtre ouverte | liste blanche INDETERMINE, rang 5 | `refuse` | `beneficiaire hors liste blanche [indetermine]` |
| `amount` `"0"` ou `"-0"` | aucune règle ne s'applique (`> 0` FAUX, `> 1000` FAUX) | `a_approuver` | `defaut : revue` |
| `mail.send`, `{ "recipient_role": "assure" }` | rang 1 | `autorise` | `outil mail.send : envoi autorise vers l'assure` |
| `mail.send`, `recipient_role` `"garage"` ou absent | FAUX ou INDETERMINE : l'autorisation ne s'applique pas | `a_approuver` | `defaut : revue` |
| `sap.payments.list` | aucune règle ne le sélectionne | `a_approuver` | `defaut : revue` |
| `SAP.payments.create` | la casse du nom compte : aucune règle | `a_approuver` | `defaut : revue` |
| `crm.claims.delete` | `revue` inconditionnelle, `contest_ms` 900 000 | `a_approuver` | `suppression de sinistre` |

L'épreuve d'acceptation (annexe A.5, répertoire `acceptation/`) applique cette
section à une même politique et à dix demandes ; les décisions attendues sont
dans un fichier que les relecteurs ne voient pas.

### 6.8 Réévaluation par un réviseur

L'évaluation est une fonction déterministe d'entrées que le client conserve.
Un réviseur qui détient la pièce de l'ensemble de politique (stockée sous
`policy_sha256` de l'événement de politique qui annonce `code.policy_version`,
CT-2 EX-8.11) et la pièce « arguments » d'un appel peut refaire l'évaluation
d'une règle `automatique` ou `revue`, avec `R = { "arguments": valeur de la
pièce }`. Les nombres de la pièce sont ceux que la politique a vus (CT-2
EX-4.44, EX-8.2). La pièce est rédigée : la réévaluation ne conclut que si
aucun pointeur lu ne désigne une chaîne qui contient un jeton de rédaction
(`[REDIGE:…]`, `[PSEUDO:…]`, CT-2 §10.2.3) ni un chemin qu'une règle
`supprimer` retire. Dans l'exemple, la liste blanche porte sur
`beneficiary_iban`, que `pii-v1` rédige : sa réévaluation ne conclut pas,
celle des montants conclut.

Pour une règle `fenetre`, il faut aussi l'état : la décision du ticket
ouvrant (son `approval.at`), la politique (`duration_ms`, `max_calls`), les
appels déjà couverts, et l'événement `retenue` du ticket ouvrant, dont
`execution.tool` et `delegation.launched_by` doivent être ceux de l'appel
couvert (même portée, EX-5.2). `ts` de l'appel est postérieur à `t` : un appel
évalué juste avant `fin` peut porter un `ts` juste après. Le réviseur conclut
donc sur `debut ≤ ts` et sur le nombre d'appels ; il ne conclut sur `fin` qu'à
l'écart entre évaluation et scellement près.

Cette réévaluation n'est pas un contrôle de CT-6 v0 ; un contrôle qui la
ferait est une proposition (section 16).

## 7. Ticket

Le ticket est l'objet du service d'approbation qui suit une demande
`a_approuver`, depuis le pas 3 de CT-2 §4.4 jusqu'à sa décision et à sa
consommation (section 2). Il n'est pas un format de CT-1 : son identifiant
entre dans `policy.ticket` et `approval.ticket` (CT-1 §5.3) ; tout le reste
vit dans le service, hors chaîne, sous la forme du document `ticket-v0`
(`spec/schemas/ticket-v0.schema.json`). Le service tient aussi les fenêtres
ouvertes par les tickets ouvrants (5.3) ; la section 7 dit comment elles
s'ouvrent et se conservent, la section 5 ce qu'elles autorisent.

### 7.1 Identifiant

**EX-7.1** L'identifiant d'un ticket est une chaîne de 5 à 128 caractères qui
respecte `^apr-[0-9a-z]+(-[0-9a-z]+)*$` : ni espace ni crochet, ce que la
marque de fenêtre de `policy.rule` exige (6.4). Il est attribué par le
service quand l'évaluation crée le ticket (6.2), unique dans le journal
(`org_id`, `journal_id`) pendant toute la vie du journal, et jamais
réattribué, même à un ticket abandonné. L'unicité DOIT tenir après une perte
totale de l'état du service : l'identifiant porte au moins 64 bits aléatoires
(par exemple `apr-` suivi de 13 caractères en base 32 minuscule), ou un
préfixe d'époque conservé hors du service et changé à chaque reconstruction
(`apr-<époque>-<compteur>`). Un compteur qui repart de zéro après une perte
d'état est interdit : un identifiant réattribué pourrait nommer la décision
scellée d'une autre demande (T20, 12.5). Les tickets des vecteurs de CT-1 et
CT-2 (`apr-1192`, `apr-2201`, `apr-demo-0001`) respectent ce motif.

**EX-7.2** L'identifiant NE DOIT PAS être dérivé des arguments ni d'aucune
donnée de la demande : il est rendu à l'agent (texte et
`_meta["noortrace/approval"]` du signal d'approbation, CT-2 EX-4.49, section
11), écrit dans la chaîne et dans les notifications. Sa forme est
libre au-delà du motif et d'EX-7.1 ; les traces de l'annexe A, qui partent
d'un service vide sans perte d'état, emploient un compteur décimal sans
époque.

### 7.2 Clé de rapprochement et ordre de traitement

Une demande qui revient (même appel ré-émis par l'agent en mode `erreur`,
ou après la fin d'une requête retenue) ne porte pas de ticket : dans les
vecteurs de CT-2, la ré-émission a le même nom, les mêmes arguments et la
même délégation que la demande, sans ticket (R1-F95). Le service la
reconnaît par une clé.

**EX-7.3** La **clé de rapprochement** d'une demande est le n-uplet
(`org_id`, `journal_id`, `code.policy_version`, `tool_announced`, octets JCS
intégral (CT-2 §8.1) des `arguments` en clair, `delegation.launched_by`,
`delegation.on_behalf_of`, `delegation.scope`). Deux demandes ont la même
clé si et seulement si chaque membre est égal octet pour octet.

**EX-7.4** `run_id`, `intent`, `context`, `class` et les autres membres de
`code` ne font pas partie de la clé : `run_id` change d'une exécution de
l'agent à l'autre et est déclaratif (CT-2 EX-7.2), l'intention et le
contexte viennent du modèle. `code.policy_version` en fait partie : une
demande évaluée sous une autre version de politique est une nouvelle
demande, de même qu'une nouvelle version ferme toutes les fenêtres
(EX-4.12). Une différence d'arguments, aussi petite soit-elle, fait une autre
demande : une approbation ne passe jamais à des arguments modifiés, comme
GitHub écarte une approbation dont le diff a changé et GitLab la retire par
défaut (R3-F104,
https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches ;
R3-F108,
https://docs.gitlab.com/user/project/merge_requests/approvals/settings/).

**EX-7.5** Un ticket est **actif** dans les états `reserve`, `ouvert`,
`seuil_atteint`, `verification` et `a_remettre`, et dans les états
`approuve`, `refuse` et `expire` tant que court son délai de reconnaissance
(7.6). À tout instant, au plus un ticket actif a une clé donnée.

**EX-7.6** Pour chaque requête `evaluer` (12.3), le service cherche d'abord
un ticket actif de même clé. S'il en trouve un, la demande est une
**ré-émission reconnue** de ce ticket et sa réponse est celle de la table
d'EX-7.16, sans évaluation de la politique. Sinon, il évalue la demande par
l'algorithme `EVALUER` de la section 6 (EX-6.1), qui crée un ticket pour une
décision `a_approuver` (T1). C'est l'ordre de 3.2, pas 3.

### 7.3 États

| État | Sens | Réponse à une ré-émission reconnue (`ticket_state`, 12.3) | Terminal |
|---|---|---|---|
| `reserve` | Ticket créé par l'évaluation ; l'événement `retenue` n'a pas encore été remis (`ouvrir`, 12.4). | `nouveau` (EX-7.19) | non |
| `ouvert` | Événement `retenue` remis ; collecte des votes sur le jeu figé (section 8). | `en_attente` | non |
| `seuil_atteint` | Approbations au seuil effectif, sans objection en cours, fenêtre de contestation en cours (5.6, 10.2). | `en_attente` | non |
| `verification` | Décision `approuve` ou `refuse` calculée ; jeu à reconfirmer avant la remise (8.3). | `en_attente` | non |
| `a_remettre` | Décision remise au noyau, acquittement attendu (12.5). | `en_attente` | non |
| `approuve` | Décision `approuve` scellée par le noyau. | `approuve` à la première requête (approbation servie, T21), puis `en_attente` jusqu'à `consommer` (EX-7.17) | non |
| `refuse` | Décision `refuse` scellée. | `refuse` | non |
| `expire` | Décision `expire` scellée. | `expire` | non |
| `consomme` | Approbation consommée par un appel relayé. | aucune : nouvelle demande | oui |
| `clos` | Délai de reconnaissance écoulé après la décision, ou identifiant en collision (T20). | aucune : nouvelle demande | oui |
| `abandonne` | Créé, jamais ouvert pendant son délai de réservation. | aucune : nouvelle demande | oui, sauf un `ouvrir` tardif (T4) |

Un ticket garde, de sa création, la règle retenue (`policy.rule`, 6.4), son
délai de contestation `contest_ms` (celui de la règle retenue, ou de la
règle par défaut) et, pour un ticket ouvrant, sa portée `K` et la fenêtre
qu'il ouvrira (`duration_ms`, `max_calls`, EX-5.3).

### 7.4 Entrées

Le service est une machine à états : un ticket ne change que sur l'une des
entrées suivantes, chacune datée d'un instant `at` (horodatage de CT-1 §3,
horloge du service). La colonne « Données » suit `$defs/entree` de
`ticket-v0`, qui fait foi : toute entrée propre à un ticket (`ouvrir`,
`voter`, `recuser`, `retirer`, `acquitter`, `consommer`, `expiration`) porte
aussi `ticket`.

| Entrée | Émetteur | Données | Section |
|---|---|---|---|
| `charger` | noyau | `policy_version` de l'ensemble chargé (le message complet de 12.2 porte aussi le document et la liste des outils ; une trace de l'annexe A.6 ne porte que `policy_version`) | 12.2 |
| `evaluer` | noyau, pas 3 | requête de CT-2 EX-7.4 ; pour une demande non reconnue, la sortie d'`EVALUER` (règle, décision, et pour `a_approuver` : `contest_ms`, ouvrant ou non, portée et fenêtre) | 6.2, 7.2, 12.3 |
| `ouvrir` | noyau, pas 6 | `request_hash`, `request_seq`, `request_ts` de l'événement `retenue` ; l'événement lui-même (`request_event`) et les octets de la pièce « arguments » (`arguments_piece`), pour la console (EX-9.6) | 12.4 |
| `jeu_lu` | lecteur de chaîne du service | résultat d'une lecture du jeu, `lu` ou `illisible` | 8.1 |
| `voter` | console | `ticket`, `approver`, `decision` (`approuve` ou `refuse`), `signature`, `reason`, `session_identity` | 9.4, 7.11 |
| `recuser` | console | `ticket`, `approver`, `session_identity` | 10.1 |
| `retirer` | console (demandeur, ou administrateur de l'annuaire, `administrators` de la configuration du service, 10.3) | `ticket`, `by`, `reason` ; `session_identity` facultatif dans la trace, exigé sur le canal de la console (EX-12.19) | 7.8 |
| `horloge` | horloge du service | — | 7.6 |
| `acquitter` | noyau | `remise_id`, `result` (`scelle`, `temporaire`, `refuse`), `reason`, et pour `scelle` ou `ticket_deja_decide` : `decision`, `seq`, `hash`, `at`, l'objet `approval` scellé ; pour `scelle`, `held` (requête retenue que le noyau va relayer) | 12.5 |
| `consommer` | noyau | `seq`, `hash` de l'appel relayé | 12.6 |
| `expiration` | noyau | `seq`, `hash`, `at` et l'objet `approval` d'une décision `expire` scellée par le noyau seul (CT-2 EX-9.4) | 12.6 |

**EX-7.7** Les entrées sont traitées une à une, dans l'ordre de leur `at`,
puis dans l'ordre d'arrivée à instant égal. **Avant** de traiter une entrée
d'instant `t`, le service déclenche les minuteurs échus (instant ≤ `t`) de
tous les tickets et des fenêtres, par instant croissant ; à instant égal,
dans cet ordre : échéance (7.6), fin de fenêtre de contestation (10.2),
échéance de réservation, fin du délai de reconnaissance, escalade (7.7), fin
d'une fenêtre ouverte (EX-5.6) ; puis par ordre croissant d'identifiant de
ticket (pour une fenêtre, celui du ticket qui l'a ouverte). Une entrée d'instant
égal à l'échéance arrive donc après elle : un vote à l'échéance est tardif. Une
entrée `jeu_lu` vaut pour chaque ticket en `ouvert`, `seuil_atteint` ou
`verification`, dans l'ordre croissant de leurs identifiants, et met à jour le
jeu de repli (EX-8.3) ; `horloge` ne fait que déclencher les minuteurs ;
`charger` ne change aucun ticket : il fixe la version en vigueur et, si elle
change, ferme toutes les fenêtres (EX-4.12).

**EX-7.8** Une entrée refusée (garde fausse dans la table 7.5) ne change ni
l'état ni les votes ; le refus et sa raison sont inscrits dans la trace du
ticket (`transitions`) et rendus à l'émetteur, avec l'une des raisons de la
table 12.8. Une entrée mal formée (hors de `$defs/entree`) est refusée
(`requete_invalide`) avant tout effet. Une entrée bien formée qu'aucune
ligne de la table 7.5 n'admet dans l'état du ticket, et pour laquelle la
table 12.8 ne nomme pas de raison propre, est refusée avec
`requete_invalide` : `ouvrir` dont `request_ts` est postérieur à `at`,
`consommer` hors `approuve` et hors T22 (ticket `clos` dont l'approbation a
été servie et n'est pas consommée), `acquitter` `scelle` d'une remise inconnue,
`acquitter` ou `expiration` sur un ticket décidé avec d'autres données que
celles de la décision scellée.

### 7.5 Transitions

Notations : `E` = `/policy/approval/expire_after_ms` (CT-2 §15.1) ; `C` =
`contest_ms` du ticket (5.6) ; `décompte` = la règle d'EX-7.27, appliquée à
l'instant de l'entrée.

| N° | De | Entrée ou minuteur | Garde | Vers | Effet |
|---|---|---|---|---|---|
| T1 | — | `evaluer` | demande non reconnue (EX-7.6), sortie `a_approuver` d'`EVALUER`, plafond d'EX-14.1 non atteint | `reserve` | identifiant attribué ; règle, `contest_ms`, portée et fenêtre d'un ticket ouvrant figés ; `reserved_at = at` ; échéance de réservation `at + E` |
| T2 | `reserve` | `ouvrir` | `request_hash` du ticket inconnu ; `request_hash` de 32 octets, `request_ts ≤ at` | `ouvert` | `request_hash`, `request_seq`, `request_ts` inscrits ; événement `retenue` et pièce « arguments » gardés pour la console (EX-9.6) ; **échéance** `request_ts + E` ; lecture du jeu demandée (8.2) ; notification (7.7) ; jeu `statique` figé aussitôt (EX-8.4) |
| T3 | `reserve` | échéance de réservation | — | `abandonne` | aucun événement de chaîne ; la clé est libérée |
| T4 | `abandonne` | `ouvrir` | idem T2 | `a_remettre` | `ouvrir` tardif (reprise du noyau après une longue panne, 7.10) : décision `expire` sur le jeu de repli (EX-8.4), raison d'EX-7.11 ; la clé n'est pas reprise |
| T5 | `ouvert`, `seuil_atteint`, `verification` | `jeu_lu` | — | inchangé, ou selon le décompte | `illisible` : inscrite ; cause `jeu_non_attendu` (autre jeu que le jeu épinglé, y compris une lecture `lu` d'un autre jeu, EX-8.1) : `set_reassigned` vrai, aucun gel ; `lu` du jeu épinglé : `set_reassigned` faux, puis : premier `lu` : jeu figé, seuil effectif, éligibles calculés (8.2, 10.1) ; `lu` différent du jeu figé : depuis `seuil_atteint`, retour en `ouvert` (fenêtre annulée), nouveau gel, seuil effectif = le plus grand des `required` figés, membres ajoutés signalés, votes hors jeu écartés, décompte (8.3) ; `lu` égal : confirmation inscrite (T8) |
| T6 | `ouvert`, `seuil_atteint`, `verification` | `voter` ou `recuser` | `voter` : EX-9.10 ; `recuser` : membre éligible du jeu figé | selon le décompte | vote enregistré, vote précédent du même approbateur remplacé (EX-7.26) ; objection inscrite ou levée (EX-10.7, EX-10.8) ; ou membre récusé : son vote `approuve` courant retiré, son vote `refuse` maintenu et compté, son objection maintenue (EX-10.4) |
| T7 | `seuil_atteint` | fin de la fenêtre de contestation (`s + C`) | — | `verification` | décision `approuve` calculée (EX-7.27, EX-5.9) |
| T8 | `verification` | `jeu_lu` | lecture `lu`, égale au jeu figé, d'instant ≥ l'entrée en `verification` | `a_remettre` | remise construite (12.5) : les `effective_required` premiers votes comptés, `approval.threshold` du jeu confirmé, `source` de 8.4 |
| T9 | `ouvert`, `seuil_atteint`, `verification` | échéance | — | `a_remettre` | décision `expire` (EX-7.11) |
| T10 | `ouvert`, `seuil_atteint`, `verification` | `retirer` | `by` autorisé (EX-7.15) | `a_remettre` | échéance avancée à `at` ; décision `expire` |
| T11 | `a_remettre` | `acquitter` `scelle` | `remise_id` d'une remise présentée pour ce ticket ; `decision` celle de cette remise ; `approval` de ce ticket, de cette décision, de `at`, du `request_hash` de la remise | état de la décision de cette remise | `sealed = { decision, seq, hash, at, approval }`, `approval` tel que reçu ; fin de reconnaissance `at + E` ; décision `approuve` et `held` vrai : `served_at = at` (EX-7.17) ; pour un ticket ouvrant, décision `approuve`, `policy_version` encore en vigueur, fin postérieure à l'acquittement : ouverture de la fenêtre (EX-5.4) |
| T12 | `a_remettre` | `acquitter` `temporaire` | `remise_id` courant | `a_remettre` | remise re-présentée au plus tôt `timeout_ms` plus tard (12.5) |
| T13 | `a_remettre` | échéance | décision en remise `approuve` ou `refuse` | `a_remettre` | décision caduque, remplacée par `expire` (EX-7.10) ; nouvelle remise, `remise_id` suivant |
| T14 | `a_remettre` | `acquitter` `refuse`, `ticket_deja_decide` | `remise_id` courant ; `approval` de ce ticket, de cette décision et de `at` ; `approval.request_hash` égal à celui du ticket | état de la décision scellée que donne l'acquittement | alignement sur le noyau, seul scelleur : `sealed` avec l'`approval` reçu |
| T15 | `a_remettre` | `acquitter` `refuse`, `echeance_depassee` | — | `a_remettre` | sans autre effet : la remise `expire` de T13 est présentée |
| T16 | `a_remettre` | `acquitter` `refuse`, autre raison | `remise_id` courant | `ouvert` ; `a_remettre` sans remise courante pour une remise `expire` ; `abandonne` pour `ticket_inconnu` | la remise cesse d'être courante ; alerte d'exploitation (défaut du service). Remise `approuve` ou `refuse` : les votes courants de ses `approvers` sont écartés (cause `remise_refusee`), puis décompte. Remise `expire` : aucune nouvelle remise, le noyau scelle `expire` seul (12.6). `ticket_inconnu` : clé libérée |
| T17 | `reserve`, `ouvert`, `seuil_atteint`, `verification`, `a_remettre`, `abandonne` | `expiration` | `approval` de ce ticket, `decision` `expire`, de `at` ; `approval.request_hash` égal à celui du ticket, s'il est connu | `expire` | alignement sur le noyau (CT-2 EX-9.4, 12.6) : `sealed` avec l'`approval` reçu ; `request_hash` inscrit s'il était inconnu ; la clé d'un ticket abandonné n'est pas reprise |
| T18 | `approuve` | `consommer` | — | `consomme` | `consumed = { seq, hash }` |
| T19 | `approuve`, `refuse`, `expire` | fin de reconnaissance | — | `clos` | `approuve` non consommé : consigné (`approbation_non_consommee`) |
| T20 | `a_remettre` | `acquitter` `refuse`, `ticket_deja_decide` | `remise_id` courant ; `approval` de ce ticket, de cette décision et de `at` ; `approval.request_hash` différent de celui du ticket | `clos` | aucun alignement : la décision scellée est celle d'une autre demande sous le même identifiant ; alerte `identifiant_en_collision` ; aucune réponse servie ; une ré-émission est une nouvelle demande |
| T21 | `approuve` | `evaluer` (ré-émission reconnue) | approbation non servie (`served_at` nul) | `approuve` | `served_at = at`, persisté avant la réponse `autorise` (EX-7.17, EX-7.22) |
| T22 | `clos` | `consommer` | approbation servie (`served_at` non nul) et non consommée (`consumed` nul) | `clos` | **consommation tardive** : `consumed = { seq, hash }`, inscrit dans la trace ; alerte `consommation_tardive` ; réponse `{ ticket, state: "clos" }`. Le relais d'une approbation servie peut être scellé après la fin du délai de reconnaissance (appel long, événement en attente scellé à la sortie d'un mode dégradé, événement de reprise, CT-2 EX-7.20) : le service, qui a consigné `approbation_non_consommee` à T19 sans savoir qu'un `consommer` viendrait, en garde la trace |

Un `acquitter` d'une remise qui n'est plus la remise courante, autre que
`scelle`, est accepté sans effet ; un `acquitter` identique à un `acquitter`
déjà accepté pour ce ticket, un `consommer` (y compris après T22), un
`ouvrir` (même `request_hash`) ou une `expiration` répétés sont sans effet
et rendent l'état courant (EX-7.20).

**EX-7.9** Une implémentation conforme DOIT réaliser exactement les
transitions de la table 7.5 et aucune autre ; toute entrée hors table est
refusée (EX-7.8). Les vecteurs `tickets/` de l'annexe A rejouent ces
transitions entrée par entrée (vérifications TK-, 7.12).

### 7.6 Délais

| Délai | Origine | Valeur | À son terme |
|---|---|---|---|
| Réponse du service | `/policy/approval/timeout_ms` (CT-2 EX-7.4) | défaut de CT-2 : 2 000 ms | le noyau traite le service comme indisponible (CT-2 §14.2) |
| Échéance de réservation | `reserved_at + E` | — | `abandonne` (T3) |
| **Échéance** du ticket | `request_ts + E` (`ts` de l'événement `retenue`) | `E` ≤ 86 400 000 ms (schéma de CT-2, R1-F54) | décision `expire` (T9) |
| Fenêtre de contestation | `contest_ms` de la règle (5.6) | `0 ≤ C < E` (EX-4.2) | remise de l'approbation sans objection (T7) |
| Reconnaissance après la décision | `at` du scellement + `E` | — | `clos` (T19) |
| Fenêtre ouverte | `approval.at` + `window.duration_ms` | ≤ 24 heures (5.3) | retirée (EX-5.6) |
| Escalade | étapes de la configuration du service (7.7) | chacune `< E` | notification |
| Expiration de repli du noyau | échéance + `timeout_ms` | — | le noyau scelle `expire` seul (12.6) |
| Requête retenue (mode `retenir`) | `/policy/approval/hold_timeout_ms` | sous le délai de l'hôte (section 11) | signal d'approbation `state: "en_attente"` (CT-2 EX-4.49) ; le ticket continue |

**EX-7.10** L'échéance d'un ticket DOIT être `request_ts + E`, où
`request_ts` est le `ts` de l'événement `retenue` remis par `ouvrir` et `E`
l'`expire_after_ms` de la version de politique du ticket
(`code.policy_version` de cet événement), de sorte que le service, le noyau
et un réviseur la calculent à l'identique. Une décision `approuve` ou
`refuse` n'est valable que si le noyau la scelle **avant** l'échéance :
`approval.at`, que le noyau pose à l'écriture (CT-2 EX-7.11), est
strictement antérieur à l'échéance (SG-4, 9.4) ; à l'échéance, sans décision
scellée, le ticket expire. Une décision `approuve` ou `refuse` dont le
service n'a pas reçu le scellement à l'échéance (mode dégradé du noyau, T12)
devient caduque et est remplacée par `expire` (T13) ; si le noyau l'a
scellée avant l'échéance, c'est elle qui tient (T11), le noyau étant le seul
scelleur. Le délai écoulé ne vaut jamais approbation (EX-3.2). Le délai de
reconnaissance après la décision est `E` lui aussi : CT-3 n'ajoute pas de
réglage, et une approbation ne se consomme pas plus de 24 heures après son
scellement.

Justification. La borne de 24 heures est celle du schéma de CT-2
(`$defs/ms`, R1-F54) ; c'est aussi l'ordre de grandeur des produits qui
bornent l'attente d'une approbation : Microsoft Entra PIM et Google Cloud PAM
laissent 24 heures aux approbateurs (R3-F78,
https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-approval-workflow ;
R3-F88, https://cloud.google.com/iam/docs/pam-approve-deny-grants), puis font
expirer la demande ; GitHub attend jusqu'à 30 jours (R3-F103,
https://docs.github.com/en/actions/reference/limits) ; sans réponse en sept
jours, AWS CodePipeline rend « the result is the same as an action
failing », comme pour un rejet (R3-F113,
https://docs.aws.amazon.com/codepipeline/latest/userguide/approvals.html).
ServiceNow permet au contraire d'approuver automatiquement à l'échéance
(R3-F115, R3-F119,
https://www.servicenow.com/docs/api/khub/maps/QG7EzyJSIJf6bo5K1OVTbw/topics/s9vS_wC22WEjISzOnNTykA/content) :
c'est ce que le principe de l'architecture interdit (« délai écoulé sans
décision : refus ») et ce que CT-1 fixe (`expire`, « refus journalisé »,
R1-F7).

**EX-7.11** La cause d'une décision `expire` est inscrite dans
`approval.reason` par l'une de ces chaînes fixes (ASCII, sans accent), dans
cet ordre de priorité quand plusieurs s'appliquent :

| Cause | `reason` |
|---|---|
| Ouverture d'un ticket abandonné (T4) | `reservation abandonnee avant l'ouverture` |
| Retrait (T10) | `echeance avancee par retrait` |
| Décision caduque (T13) | `decision non scellee avant l'echeance` |
| Jeu jamais figé (8.2) | `echeance atteinte, jeu d'approbateurs illisible` |
| Dernière lecture : un autre jeu que le jeu épinglé (`set_reassigned`, EX-8.6) | `echeance atteinte, jeu reassigne` |
| Moins de membres éligibles que le seuil effectif (EX-7.29) | `echeance atteinte, seuil inatteignable` |
| Objection non levée (EX-10.7) | `echeance atteinte, objection non levee` |
| Fenêtre de contestation en cours (`seuil_atteint`) | `echeance atteinte pendant la fenetre de contestation` |
| Autre | `echeance atteinte sans decision` |

Le motif libre d'un retrait n'entre pas dans la chaîne ; il reste dans la
trace du ticket.

### 7.7 Notification et escalade

**EX-7.12** À l'ouverture (T2), le service notifie les membres éligibles du
jeu figé (10.1) par les canaux de la console (section 13). Une notification
ne porte que l'identifiant du ticket, le nom annoncé de l'outil, l'échéance
et un lien vers la console ; jamais les arguments.

**EX-7.13** Une **escalade** est une étape de notification supplémentaire,
fixée par la configuration du service (`after_ms` et cible), déclenchée à
`request_ts + after_ms` si le ticket n'est pas décidé, vers les membres
éligibles qui n'ont pas voté, l'administrateur du jeu ou le demandeur
(contacts de la configuration du service). Une escalade NE DOIT changer ni le
jeu, ni le seuil, ni l'échéance (EX-3.2, EX-5.7) : changer qui peut approuver
est un changement du `CuratorSet`, visible sur la chaîne (8.3), ou un
changement de politique, journalisé (CT-2 EX-9.1). Elle n'entre pas dans la
décision et n'est pas dans l'ensemble de politique.

Justification. Pour ses processus d'accès d'urgence, AWS demande des
approbateurs secondaires quand les premiers sont indisponibles, et une
escalade qui remonte la hiérarchie jusqu'à approbation, ce que CT-3 ne
reprend pas (R3-F90,
https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_permissions_emergency_process.html),
et NIST SP 800-53 CM-3(1)(c) de signaler les demandes restées sans décision
après un délai (R3-F59,
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf).
Dans CT-3, les approbateurs secondaires sont des membres du même jeu : le
seuil reste celui du contrat. Une escalade automatique vers d'autres
approbateurs n'est documentée dans aucune des pages lues pour Entra PIM,
Google Cloud PAM, GitHub, GitLab, Azure Pipelines et CodePipeline (R3,
section 2 ; non vérifié ailleurs dans leur documentation).

### 7.8 Annulation et retrait

**EX-7.14** L'annulation par l'hôte d'une requête retenue (stdio :
`notifications/cancelled` ; HTTP : fermeture du flux, que le serveur DOIT
traiter comme une annulation, R2-F11,
https://github.com/modelcontextprotocol/modelcontextprotocol/blob/80041ab0a139a8f4fb3adbc99f7ae9113ea59671/docs/specification/2026-07-28/basic/patterns/cancellation.mdx#L7-L43)
met fin à la requête, pas au ticket : le ticket reste ouvert, et la
ré-émission de la demande est reconnue (7.9). La révision 2026-07-28 impose
d'ailleurs au client de ré-émettre une requête dont le flux est rompu
(R2-F5, même dépôt, `changelog.mdx` L28). Le service n'est pas informé de
l'annulation en version 0 : aucun message ne la lui transmet, et la console
ne peut pas la signaler ; un message d'annulation du noyau vers le service
est une proposition (section 16).

**EX-7.15** Un **retrait** clôt un ticket non décidé : seuls le demandeur
et un administrateur de l'annuaire (`administrators` de la configuration du
service, 10.3) PEUVENT retirer. Le demandeur est la session dont l'entrée
active de l'annuaire porte le `launched_by` du ticket parmi ses alias de
demandeur (`requester_identities`, 13.4) ; `by` vaut alors ce `launched_by`.
Un administrateur retire avec `by` égal à son identité de session. Le
service contrôle l'une ou l'autre condition sur le canal de la console,
avant de former l'entrée (EX-12.19) ; la machine à états n'admet ensuite
qu'un `by` égal à `launched_by` ou présent dans `administrators` (T10,
`retrait_non_autorise`) ; l'échéance est avancée à l'instant du retrait et la
décision est `expire` avec la raison fixe d'EX-7.11. CT-1 v0 n'a pas de valeur
« retiré » : un retrait est une expiration avancée, que seul `reason` (attesté
par l'enregistreur, non signé) distingue dans un dossier. Google Cloud PAM admet
de même le retrait d'une demande en attente par le demandeur (fonction en
préversion, R3-F85, https://cloud.google.com/iam/docs/pam-overview). Une valeur
signée de retrait est une proposition pour une version 1 (section 16).

### 7.9 Ré-émission reconnue et idempotence

**EX-7.16** Pour une requête `evaluer`, le service rend (12.3) :

| Ticket actif de même clé (EX-7.6) | `decision`, `ticket_state`, `approval` | `rule` | Ce que fait le noyau (section 11) |
|---|---|---|---|
| aucun ; `EVALUER` rend `autorise` | `autorise`, `null`, `null` | celle d'`EVALUER` | relais, `policy.decision = "autorise"` |
| aucun ; `EVALUER` rend `refuse` | `refuse`, `null`, `null` | celle d'`EVALUER` | événement `refusee`, résultat `isError: true` (EX-11.8) |
| aucun ; `EVALUER` rend `a_approuver` (nouveau ticket, T1) | `a_approuver`, `nouveau`, `null` | celle d'`EVALUER` | événement `retenue`, puis `ouvrir` |
| `reserve` | `a_approuver`, `nouveau`, `null` ; **même** ticket | celle du ticket | événement `retenue`, puis `ouvrir` (idempotent, 12.4) |
| `ouvert`, `seuil_atteint`, `verification`, `a_remettre` | `a_approuver`, `en_attente`, `null` ; même ticket | celle du ticket | aucun événement ; signal d'approbation, `state: "en_attente"` |
| `approuve`, approbation non servie (T21) | `autorise`, `approuve`, objet `approval` scellé | celle du ticket | vérifications RL-1 à RL-4 (CT-2 EX-7.21), relais selon CT-2 EX-7.12, puis `consommer` |
| `approuve`, approbation déjà servie | `a_approuver`, `en_attente`, `null` | celle du ticket | aucun événement ; signal d'approbation, `state: "en_attente"` (EX-7.17) |
| `refuse` ou `expire` | `refuse`, `refuse` ou `expire`, objet `approval` scellé | celle du ticket | événement `refusee` qui reprend la `policy` de l'événement `retenue` et porte `approval` ; signal d'approbation de même `state` |

Le membre `approver_set` de la réponse est non nul pour `nouveau` seulement
(EX-12.6) ; `approval` n'est non nul que pour une décision scellée du même
ticket.

**EX-7.17** La consommation est atomique : un ticket `approuve` autorise
**un** relais. Le service DOIT rendre `ticket_state: "approuve"` à une seule
requête par ticket, et marquer l'approbation servie (`served_at`, T21)
avant de répondre. Une approbation est aussi servie dès son scellement quand
le noyau annonce, par `held` vrai dans `acquitter` `scelle`, qu'il tient la
requête retenue et va la relayer (mode `retenir`, EX-11.5, T11). Une requête
de même clé reçue après le service d'une approbation et avant l'acquittement
du relais par `consommer` reçoit `en_attente`, et une requête reçue après
`consomme` est une nouvelle demande. Deux appels identiques voulus par
l'agent (deux paiements égaux) demandent donc deux approbations successives,
sauf si une fenêtre (5.3) couvre le second. Si le relais d'une approbation
servie échoue avant tout événement, la version 0 n'a pas de message pour la
libérer : ses ré-émissions reçoivent `en_attente` jusqu'à la fin du délai de
reconnaissance (`clos`, T19), puis sont de nouvelles demandes ; un message
de libération du noyau vers le service est une proposition (section 16).

**EX-7.18** Une ré-émission reconnue d'un ticket `refuse` ou `expire`
reçoit le refus scellé tant que court le délai de reconnaissance : l'agent
ne peut pas rouvrir aussitôt une demande refusée en la répétant à
l'identique. Une variation des arguments, même cosmétique, fait une autre
demande, évaluée de nouveau et soumise de nouveau aux approbateurs (14.7).
Chaque ré-émission ainsi refusée est un événement `refusee` (une tentative,
comme CT-2 EX-14.3 le veut pour les essais) ; c'est la forme que les vecteurs de
CT-6 publient déjà (`valide-decision-refusee`, `valide-decision-expiree` :
seq 7 `refusee` portant l'`approval` de la décision, R1-F66).

**EX-7.19** Une ré-émission reconnue d'un ticket en attente ne produit
**aucun** événement : l'événement `retenue` du ticket suffit à prouver la
demande, et un agent qui réessaie toutes les secondes ne doit pas remplir le
journal. Le noyau consigne `approval_pending` dans le journal
d'exploitation (CT-2 §14.2). Une ré-émission d'un ticket `reserve` reçoit
`nouveau` et le même identifiant : c'est le cas où le premier événement
`retenue` n'a pas pu être scellé (mode dégradé, CT-2 §14) ; si deux
événements `retenue` ont été scellés malgré tout (course), le second
`ouvrir` est refusé (`ticket_deja_ouvert`) et le ticket garde le premier
`request_hash` (A-4 de CT-1 identifie la demande par son hachage, R1-F20).

**EX-7.20** Le service DOIT être idempotent : une requête `evaluer` répétée
à l'identique (nouvelle tentative du noyau après un délai) est une
ré-émission reconnue et ne crée pas de second ticket ; `ouvrir` (même
`request_hash`), `acquitter` (mêmes données qu'un `acquitter` déjà accepté
pour ce ticket), `consommer` et `expiration` (mêmes `seq`, `hash` et
`approval`) répétés sont sans effet et rendent l'état courant du ticket ; un
`ouvrir` répété rend donc aussi son échéance.

**EX-7.21** Un changement de politique pendant la vie d'un ticket (CT-2
EX-15.5) ne change ni la règle, ni `contest_ms`, ni la portée, ni le jeu
figés du ticket, qui suit sa vie jusqu'à sa décision et son délai de
reconnaissance. Mais une demande évaluée sous la nouvelle version n'a pas la
même clé (EX-7.3) : elle est évaluée par la nouvelle politique, et une
approbation acquise sous l'ancienne n'est plus consommée que par la requête
retenue en mode `retenir`, qui finit sous l'ancienne politique (CT-2
EX-15.5 ; EX-11.5 de CT-3). Une fenêtre ne s'ouvre pas si la version a changé
avant le scellement (EX-5.4), et toutes les fenêtres se ferment au changement
(EX-4.12).

### 7.10 Persistance et reprise

**EX-7.22** Le service DOIT persister, avec `fsync` (ou l'équivalent
durable de son stockage), chaque transition d'un ticket et chaque
changement d'une fenêtre **avant** d'en rendre l'effet visible : le ticket
créé avant de répondre `nouveau`, l'unité de fenêtre consommée (EX-6.5)
avant de répondre `autorise`, l'approbation servie (`served_at`, T21) avant
de répondre `autorise` à une ré-émission, un vote avant de l'acquitter à la
console, une remise avant de la livrer au noyau, un acquittement et
l'ouverture d'une fenêtre avant de répondre au noyau, le retrait d'une
fenêtre fermée (EX-5.6). La trace persistée d'un ticket est le document
`ticket-v0` (`$defs/ticket`) : tout l'état du ticket y est, y compris le
seuil effectif, la dernière confirmation du jeu, la décision calculée et son
instant, toutes les remises présentées, la remise courante, l'objet
`approval` scellé, l'approbation servie, la clé libérée, les récusés et les
escalades déclenchées ; `transitions` (avec les données de chaque entrée,
sans arguments en clair) et `votes` sont en ajout seul. Une fenêtre est
l'objet `$defs/fenetre_ouverte` du même schéma.

**EX-7.23** À la reprise, le service relit ses documents `ticket-v0`, ses
fenêtres, la version en vigueur et les versions chargées, son jeu de repli
et son compteur d'identifiants (avec son époque, EX-7.1), et rien d'autre ;
il reprend les minuteurs depuis leurs instants absolus, inscrits dans les
documents (les minuteurs échus pendant l'arrêt se déclenchent aussitôt,
dans l'ordre d'EX-7.7), relit le jeu des tickets ouverts (8.3), et
re-présente les remises non acquittées. Une fenêtre qu'il ne retrouve pas
est fermée (EX-5.6) ; il n'en recrée aucune. Un service repris depuis ces
seuls documents DOIT donner, pour toute suite d'entrées, les mêmes sorties
que le service qui ne s'est pas arrêté (TK-12) ; les transitions d'un
document s'enchaînent et mènent à son état.

**EX-7.24** Les arguments en clair d'un ticket ne sont conservés que tant
qu'il est actif (affichage à la console, clé de rapprochement), chiffrés au
repos par le service. Ils sont effacés au passage en `consomme`, `clos` ou
`abandonne` (T3, T16, T18, T19, T20), avec l'événement `retenue` et la pièce
« arguments » gardés pour la console (EX-9.6) : `request.arguments`,
`request.retained_event` et `request.arguments_piece` deviennent `null`
dans `ticket-v0`, et, pour un ticket ouvrant, `opening.scope.values`
devient `null` ; `opening` garde le reste de la portée, la durée et le
nombre d'appels, de sorte qu'un ticket ouvrant effacé reste distinct d'un
ticket non ouvrant (`opening: null`). Le schéma l'exige (`$defs/ticket`).
La trace sans arguments
est conservée aussi longtemps que le journal (CT-2 §12.7) : elle porte les
votes, les refus de vote et leurs raisons, les récusations, les objections,
les retraits et les lectures du jeu, que la chaîne ne porte pas (10.4).
Comme le journal (CT-2 EX-10.2), elle NE DOIT contenir ni hachage ni
condensé sans clé des arguments en clair. La valeur d'une portée de fenêtre
(EX-5.2) est une donnée des arguments : dans le ticket, elle est effacée
avec les arguments ; dans la fenêtre (`$defs/fenetre_ouverte`), elle
disparaît avec la fenêtre, retirée à sa fermeture (EX-5.6).

**EX-7.25** Au redémarrage du noyau, les événements `retenue` dont le
ticket n'a pas de décision dans le journal DOIVENT être remis de nouveau
par `ouvrir` (idempotent, T2, T4) ; un `ouvrir` refusé avec `ticket_inconnu`
(service qui a perdu son état) conduit le noyau à sceller lui-même `expire`
à l'échéance (12.6). Tout ticket ouvert reçoit ainsi exactement une
décision.

### 7.11 Votes et décompte

**EX-7.26** **Règle de vote.** Chaque membre éligible (10.1) du jeu figé a au
plus un vote courant par ticket, `approuve` ou `refuse`. Un nouveau vote du
même approbateur remplace le précédent tant que la décision n'est pas remise
(états `ouvert`, `seuil_atteint`, `verification`) ; c'est la règle de
curators-hub, « a new decision replaces this curator's prior vote » (R1-F84,
`lib/validation.ts` L396-L399 de noorchain-core, dépôt privé, lu le
2026-10-23). Pour retirer son approbation, l'approbateur vote `refuse` ; pour
lever son objection (10.2), il vote `approuve`. Le vote remplacé reste dans
la trace du ticket, marqué comme tel ; l'instant d'acceptation d'un vote
courant est celui de son dernier remplacement.

**EX-7.27** **Décompte.** Après chaque entrée qui change les votes, le jeu,
les éligibles ou les objections (T5, T6, T16), le service compte `a` votes
courants `approuve` des membres éligibles du jeu figé et `r` votes courants
`refuse` des membres éligibles et des membres récusés du jeu figé
(EX-10.4) ; `t` est le **seuil effectif** du ticket, le plus grand
`required` des jeux figés pour lui (EX-8.6), `C` le `contest_ms` du ticket
et `O` l'ensemble des objections non levées (EX-10.7) :

| Condition, évaluée dans cet ordre | Résultat |
|---|---|
| `r ≥ t` | décision `refuse` : état `verification` |
| `a ≥ t` et `C = 0` | décision `approuve` : état `verification` |
| `a ≥ t`, `C > 0` et `O` vide | état inchangé en `seuil_atteint`, ou en `verification` avec la décision `approuve` ; sinon `seuil_atteint`, et la fenêtre de contestation s'ouvre à cet instant `s` (EX-5.9, 1) |
| sinon | état `ouvert` ; une fenêtre de contestation en cours est annulée |

Un décompte qui rend la décision déjà calculée laisse l'état et son instant
d'entrée inchangés : une approbation de plus ne recommence pas une fenêtre
en cours. Une fenêtre annulée parce que `a` est passé sous `t`, qu'une
objection est arrivée ou qu'un nouveau gel l'a annulée (EX-8.6) ne reprend
pas : quand la condition revient, une nouvelle fenêtre complète s'ouvre
(EX-5.9, 4). À la fin de la fenêtre
(T7), la décision `approuve` est calculée.

Le refus l'emporte quand les deux seuils sont atteints, comme le refus
explicite d'AWS IAM l'emporte sur une autorisation (R2-F76,
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html)
et `forbid` sur `permit` chez Cedar (R2-F67,
https://github.com/cedar-policy/cedar-docs/blob/3a37098eba6e02e716949cfc92b889b38db25602/docs/collections/_auth/authorization.md#L38-L58).
Le décompte s'arrête au seuil, comme `ThresholdSignatures` (R1-F75).

**EX-7.28** La remise porte exactement `t` signatures, `t` étant le seuil
effectif : les `t` premiers votes comptés de la décision (EX-7.27), dans
l'ordre où le service les a acceptés (EX-9.10) ; `approvers[i]` et
`signatures[i]` se correspondent (E-5). `approval.threshold` et
`approver_set.threshold` restent le seuil lu à la confirmation (T8), comme
CT-1 §5.3 le veut : quand le seuil a baissé pendant l'attente, la remise
porte plus de `required` signatures, ce qu'A-3 et SG-6 admettent (« au
moins »). `reason` est le motif du `t`-ième (EX-9.14). Remettre `t` signatures
et non toutes borne la taille de l'événement (176 octets par couple, CT-2
EX-11.7, R1-F50) et rend la remise déterministe.

**EX-7.29** Si le nombre de membres éligibles devient inférieur au seuil
effectif `t`, le
ticket ne peut plus être décidé par des votes : le service le signale à la
console et aux contacts d'escalade (EX-7.13), et le ticket expire à son
échéance (raison `echeance atteinte, seuil inatteignable`), sauf retrait.

### 7.12 Vérifications TK-

Vérifications du cycle de vie, servies par les vecteurs `tickets/` de
l'annexe A et rattachées par CT-9 à ses tests :

| Id | Vérification |
|---|---|
| TK-1 | Identifiant conforme et unique dans le journal (EX-7.1, EX-7.2). |
| TK-2 | Clé de rapprochement : même clé, même ticket ; un membre de la clé différent, dont `code.policy_version`, une nouvelle demande (EX-7.3 à EX-7.6). |
| TK-3 | Chaque entrée produit l'état attendu ; une entrée hors table est refusée sans changement (EX-7.8, EX-7.9). |
| TK-4 | Minuteurs déclenchés avant l'entrée de même instant, dans l'ordre d'EX-7.7. |
| TK-5 | Vote : forme, normalisation, recouvrement, appartenance au jeu figé, éligibilité, remplacement (EX-7.26, EX-9.3, EX-9.10, 10.1). |
| TK-6 | Décompte, objections (y compris un refus antérieur au seuil) et fenêtre de contestation, seuil inatteignable (EX-7.27, EX-7.29, 10.2). |
| TK-7 | Gel du jeu épinglé, nouveau gel au changement, seuil effectif, réassignation à un autre jeu (`jeu_non_attendu`), confirmation avant la remise (8.2, 8.3). |
| TK-8 | Contenu de la remise : `approvers` dans l'ordre d'acceptation, exactement le seuil effectif de signatures, `reason`, `threshold`, `approver_set` et sa `source` (EX-7.28, 8.4, 12.5). |
| TK-9 | Réponse à une ré-émission selon l'état ; acquittements et expirations du noyau, y compris répétés (EX-7.16 à EX-7.20, T11 à T17, T20). |
| TK-10 | Consommation unique, approbation servie une fois, y compris en mode `retenir` (EX-7.17, T21). |
| TK-11 | Séparation des tâches et récusation, refus d'un récusé maintenu, ordre des raisons de refus d'un vote (10.1, EX-9.10). |
| TK-12 | Un service repris depuis ses seuls documents persistés donne les mêmes sorties (EX-7.22, EX-7.23). |
| TK-13 | Ouverture d'une fenêtre à l'acquittement du scellement d'une décision `approuve` d'un ticket ouvrant, et seulement alors (T11, EX-5.4). |

## 8. Jeu d'approbateurs et seuil

CT-1 lit le seuil « dans le `CuratorSet` de l'organisation au moment de la
décision » (CT-1 §5.3, R1-F7) et déclare le jeu dans `approbations.json`
avec une `source` libre (CT-1 §11.2, R1-F16). La politique dit où le lire
(`approver_set`, 4.2) : `registre`, le `CuratorSetRegistry` d'adresse
`registry` sur la chaîne `chain_id`, pour l'`org_id` du journal, qui doit
désigner le jeu épinglé `set` ; ou `statique`, un jeu écrit dans la
politique. CT-3 fixe ici comment le service
le lit, quand il le fige et ce qui arrive s'il change.

### 8.1 Lecture

Les contrats sont ceux du dépôt, identiques à ceux de noorchain-core
(R1-F73) : `CuratorSetRegistry.curatorSetOf(orgId)` rend l'adresse du jeu
d'une organisation, ou l'adresse nulle (R1-F74) ; `CuratorSet` n'expose que
`isCurator`, `getThreshold` et `getCuratorCount`, sans liste des membres, qui
ne se reconstituent que par les événements `CuratorAdded` et
`CuratorRemoved` (R1-F69, R1-F70) ; le seuil vérifie `1 ≤ t ≤ n` (R1-F71).

**EX-8.1** Avec `approver_set.source = "registre"`, une lecture du jeu se
fait **à une hauteur** `H` unique, dans cet ordre, par le point RPC que fixe
la configuration du service :

1. `eth_chainId` doit valoir `approver_set.chain_id`, sinon lecture
   `illisible` (`chaine_differente`) ; `eth_blockNumber` donne `H` ;
   `eth_getBlockByNumber(H)` donne le hachage de bloc `b` ;
2. `curatorSetOf(orgId)` du registre `approver_set.registry`, à la hauteur
   `H` (`eth_call` avec le paramètre de bloc `H`), donne `S` ; `S` nul : lecture
   `illisible` (`organisation_sans_jeu`) ; `S` différent du jeu épinglé
   `approver_set.set` (comparaison en minuscules) : lecture `illisible`
   (`jeu_non_attendu`) ;
3. `eth_getCode(S, H)` non vide ; sinon `illisible` (`jeu_sans_code`) : avant
   le déploiement, `eth_call` rend `0x` sans erreur (R1-F81) ;
4. `getThreshold()` et `getCuratorCount()` à `H` donnent `t` et `n` ;
   `1 ≤ t ≤ n` ; sinon `illisible` (`seuil_incoherent`) ;
5. les membres : les adresses connues du service (adresses de l'annuaire
   des approbateurs, actives ou non, 13.4 ; adresses de
   `separation.identities` ; membres de ses lectures précédentes) pour
   lesquelles `isCurator(adresse)` vaut `true` à `H` ; si leur nombre est `n`,
   ce sont exactement les membres (un ensemble de `n` adresses membres parmi `n`
   membres est le jeu) ; sinon, le service reconstitue la liste par les journaux
   `CuratorAdded` et `CuratorRemoved` de `S` jusqu'à `H`, par tranches d'au plus
   16 384 blocs (borne de `eth_getLogs` de noorcore, R1-F79), et la recoupe par
   `isCurator` à `H` et par `n` ; sans égalité : `illisible`
   (`membres_non_reconstitues`) ;
6. les adresses sont écrites en minuscules (CT-1 §3 ; les journaux et les
   fichiers de déploiement rendent la casse EIP-55, R1-F81) et triées par
   ordre croissant de leur écriture hexadécimale.

Une hauteur au-dessus de la tête ou dont l'état ne s'ouvre pas est refusée
par noorcore avec `-32000`, sans substitution d'un autre état (R1-F78) : la
lecture est alors `illisible` (`etat_indisponible`) et réessayée. Le
comportement sur un état élagué n'a pas été provoqué (R1-NV4, non vérifié).

**EX-8.2** Avec `approver_set.source = "statique"`, le jeu est
`approver_set.members` (en minuscules, trié) et `approver_set.threshold` de
la politique, sans lecture de chaîne : `chain_id`, `registry`, `set`,
`height` et `block_hash` du jeu valent `null`. Au chargement, le service
vérifie, en plus du schéma, les règles propres à `approver_set` (EX-4.2,
point 7), et refuse l'ensemble (`politique_invalide`, 12.2) si l'une
manque :

1. pour `statique`, `threshold.size` est égal au nombre de `members`, et
   `required ≤ size` ;
2. pour `statique`, l'ensemble n'est pas chargé en production
   (`recorder.environment` de CT-2 §15.1 égal à `production`, transmis par
   `charger`, 12.2) : un jeu écrit par l'opérateur n'est pas celui de
   l'organisation ;
3. pour `registre`, rien de plus : `chain_id` et le jeu épinglé `set` sont
   contrôlés à chaque lecture (EX-8.1, pas 1 et 2).

Le résultat d'une lecture `lu` est l'objet `jeu` de `ticket-v0` :
`{ "chain_id", "registry", "set", "height", "block_hash", "threshold": {
"required": t, "size": n }, "members" }`. Ces lectures ne sont pas
prouvées : noorcore n'a pas `eth_getProof` et `eth_call` est servi par le
meneur seul (R1-F78, R1-F80). Le service croit le nœud qu'il interroge ; le
client DEVRAIT l'interroger par un validateur qu'il opère ou un validateur
partenaire (architecture, « Instance dédiée »).

**EX-8.3** Avec un jeu `registre`, le service NE DOIT PAS répondre à
`evaluer` tant qu'il n'a pas réussi une première lecture du jeu de son
organisation (réponse `non_pret`, 12.8, que le noyau traite comme une
indisponibilité, CT-2 §14.2). Il garde la dernière lecture réussie du jeu
épinglé de la version en vigueur comme **jeu de repli** (EX-8.4, EX-8.8) ;
une lecture `illisible`, dont `jeu_non_attendu`, ne le change pas.

### 8.2 Instant de lecture et gel

**EX-8.4** À l'ouverture d'un ticket (T2), le service lit le jeu à la
tête (EX-8.1) et le **fige** dans le ticket (`approver_set` de `ticket-v0`,
dont `height` est la hauteur de gel) ; un jeu `statique` est figé aussitôt
(EX-8.2). Les votes ne sont acceptés qu'après le gel (raison `jeu_non_fige`,
12.8). Si la lecture échoue, le service la réessaie au plus
toutes les `set_poll_interval_ms` (configuration du service, défaut
10 000) jusqu'à l'échéance ; un ticket jamais figé expire avec la raison
`echeance atteinte, jeu d'approbateurs illisible` et porte le jeu de repli,
dont la `source` le dit (8.4).

Justification. Figer à l'ouverture donne aux approbateurs un seuil et une
liste stables pendant l'attente, comme Azure Pipelines fige la liste des
approbateurs au début des vérifications (R3-F111,
https://learn.microsoft.com/en-us/azure/devops/pipelines/process/approvals?view=azure-devops).
Lire à l'ouverture, et non au pas 3, garde la réponse d'`evaluer` dans son
délai de 2 secondes (CT-2 EX-7.4) : l'appel au registre n'est pas sur le
chemin de l'agent.

### 8.3 Changement pendant l'attente

`CuratorSetRegistry` permet à son administrateur, une seule clé extérieure à
l'organisation, de réassigner le jeu d'une organisation, par exemple pour
remplacer un jeu compromis (R1-F74), et `CuratorSet` permet à son
administrateur d'ajouter ou retirer un membre et de changer le seuil
(R1-F71). Un jeu figé peut donc cesser d'être celui de l'organisation
pendant qu'un ticket attend.

**EX-8.5** Pendant la vie d'un ticket ouvert, le service surveille les
journaux `CuratorSetAssigned` de l'organisation sur le registre et
`CuratorAdded`, `CuratorRemoved`, `ThresholdUpdated` du jeu figé, depuis la
hauteur de gel, par sondage (noorcore n'a pas `eth_subscribe`, R1-F79),
au plus toutes les `set_poll_interval_ms`. Tout changement constaté donne
une nouvelle lecture (EX-8.1).

**EX-8.6** Une lecture `lu` du jeu épinglé différente du jeu figé (`t`,
`n` ou membres) **re-fige** le ticket sur la nouvelle lecture : un ticket en
`seuil_atteint` revient en `ouvert`, ce qui annule sa fenêtre de
contestation ; les votes des adresses qui ne sont plus membres sont écartés
(`hors_jeu`) ; le **seuil effectif** du ticket devient le plus grand des
`required` figés pour lui et ne baisse donc jamais ; les membres ajoutés
depuis l'ouverture sont signalés à la console et dans la trace ; puis le
décompte (EX-7.27) est refait à l'instant de la lecture : si `a ≥ t`,
`C > 0` et `O` est vide, une nouvelle fenêtre complète s'ouvre à cet
instant ; un ticket en `verification` dont le décompte rend la même
décision garde son état et l'instant de son entrée. Les objections non
levées demeurent (EX-10.8). Le changement est inscrit dans la trace du
ticket et notifié aux membres éligibles. Un seuil abaissé par
l'administrateur du jeu ne réduit pas le nombre de signatures exigé ; la
remise porte alors le seuil lu à la confirmation et plus de signatures que
lui (EX-7.28).

Une lecture d'un autre jeu que le jeu épinglé (réassignation par
l'administrateur du registre) ne re-fige **jamais** le ticket : elle est
`illisible` (`jeu_non_attendu`, EX-8.1), le ticket est marqué
(`set_reassigned`) jusqu'à une lecture réussie du jeu épinglé, aucune
confirmation n'est possible (EX-8.7) et, sans elle, le ticket expire à son
échéance avec la raison `echeance atteinte, jeu reassigne` (EX-7.11). Le
nouveau jeu n'est adopté que par une nouvelle version de politique qui
l'épingle, journalisée (EX-4.12) : la rotation d'un jeu compromis reste
possible, mais une seule clé ne fait décider aucun ticket par un jeu
qu'elle choisit.

**EX-8.7** Avant de remettre une décision `approuve` ou `refuse`, le service
DOIT confirmer le jeu par une lecture faite **après** l'instant où la
décision a été calculée (état `verification`, T8) : cette lecture doit être
égale au jeu figé et chaque signataire doit y être membre. C'est ainsi que
le seuil inscrit dans la décision est « lu au moment de la décision »
(CT-1 §5.3) tout en restant celui que les approbateurs ont vu. Une décision
`expire` ne demande pas de confirmation : elle n'autorise rien. Un jeu
`statique` ne change pas pendant la vie d'un ticket, qui garde sa version de
politique (EX-7.21) : sa confirmation est acquise et T8 suit aussitôt
l'entrée en `verification`.

Justification. Garder les signatures d'un jeu remplacé parce qu'il était
figé à l'ouverture laisserait un jeu compromis approuver les tickets en
cours, alors que la réassignation existe précisément pour l'écarter
(R1-F74) ; adopter le jeu réassigné laisserait l'administrateur du registre,
une seule clé, faire approuver n'importe quel ticket. L'épinglage fait
expirer les tickets en cours : c'est le seul choix qui ne donne la décision
ni à l'un ni à l'autre. Le contrat lui-même relit le seuil au moment de la
transaction pour une clôture de période (`_requireThreshold`, R1-F76).

### 8.4 Source déclarée

**EX-8.8** Le service remet le jeu d'une décision (`approver_set`, 12.5)
avec une `source` de la forme exacte :

```text
CuratorSet c=<chain_id> r=<registre> s=<jeu> h=<hauteur de gel>..<hauteur de confirmation> b=<hachage du bloc de confirmation>[ repli]
```

où `<chain_id>` et les hauteurs sont des entiers décimaux d'au plus 20
chiffres, les adresses et le hachage en hexadécimal minuscule `0x` (CT-1
§3), et ` repli` est présent seulement pour le jeu de repli d'EX-8.4. Motif
de contrôle :
`^CuratorSet c=[0-9]{1,20} r=0x[0-9a-f]{40} s=0x[0-9a-f]{40} h=[0-9]{1,20}\.\.[0-9]{1,20} b=0x[0-9a-f]{64}( repli)?$`.
La plus longue forme fait 243 caractères, sous la borne de 256 de CT-1
(R1-F26). Pour une décision `expire`, la hauteur de confirmation est celle
de la dernière confirmation du jeu figé (son gel, ou la dernière lecture qui
lui était égale) ; pour le jeu de repli, les deux hauteurs sont celle de sa
lecture. Un jeu `statique` a la `source`
`jeu statique de la politique <policy_version>` (motif
`^jeu statique de la politique .{1,128}$`, au plus 157 caractères), où
`<policy_version>` est la version de l'ensemble de politique du ticket.

**EX-8.9** `members` est la liste triée d'EX-8.1, `threshold` est `{
"required": t, "size": n }` de la même lecture, celle de la confirmation
(et non le seuil effectif d'EX-8.6) ; ce sont les valeurs que A-3 compare
(CT-1 §11.4). Le noyau conserve `approver_set` avec la décision
scellée, hors chaîne, pour l'exportateur de dossier, qui l'écrit tel quel
dans `approbations.json` (CT-2 EX-12.23).

Exemple (valeurs synthétiques des vecteurs, annexe A.2) :

```text
CuratorSet c=2124 r=0xff7a89fa58a8ffa1173eb70799d7c184bf4d7fe1 s=0x35312352c0065a3fc46ce14dba05df3fcee9fbc2 h=1200..1214 b=0xbbdda14682d88cba1356b88a3fa30ecf233920d3a15f4caf97dcff023d21fbca
```

(registre, jeu 1 et bloc 1214 de l'annexe A.2 : 20 premiers octets de
`SHA-256(UTF-8("noortrace/vecteurs/ct3/registre"))` et de
`SHA-256(UTF-8("noortrace/vecteurs/ct3/jeu/1"))`, et
`SHA-256(UTF-8("noortrace/vecteurs/ct3/bloc/1214"))`.)

### 8.5 Ce que le réviseur peut recouper

| Ce que dit le dossier | Ce que le réviseur peut faire | Ce que cela établit |
|---|---|---|
| `approver_set.source` : chaîne, registre, jeu, hauteurs, hachage de bloc | Relire `curatorSetOf`, `getThreshold`, `getCuratorCount` et `isCurator` à la hauteur de confirmation, par un nœud qu'il croit (validateur partenaire, le sien) | Que le jeu déclaré était celui de l'organisation à cette hauteur, **selon ce nœud** : l'état n'est pas prouvé (R1-F80) |
| Hachage du bloc de confirmation | Le comparer au certificat de commit de ce bloc (`noor_getCommitCertificate`), vérifié contre le jeu de validateurs comme au contrôle 8 de CT-6 | Que ce bloc existe dans la chaîne certifiée, pas l'état qui y est lu |
| `approval.at` et `ts` de la demande (si elle est voisine) | Comparer la date de la hauteur de confirmation aux instants du journal | Une cohérence de dates, déclarative des deux côtés |

**EX-8.10** CT-6 ne change pas : le contrôle 7 garde la provenance « déclaré
par le dossier » (CT-6 EX-3.6, R1-F59), et l'énoncé dit « seuil de … du jeu
déclaré par le dossier » (R1-F61). La comparaison du jeu déclaré à une ancre
ou à une preuve d'état est hors de cette version (section 16).

### 8.6 Une personne, une clé

**EX-8.11** Chaque membre du jeu DOIT être la clé d'une seule personne
physique, et une personne ne DOIT tenir qu'une clé du jeu : deux adresses ne
prouvent pas deux personnes (5.4), et le seuil ne réalise la double
autorisation qu'à cette condition (AC-3(2), R3-F55). C'est une obligation de
l'organisation, tenue à l'inscription des membres par l'administrateur du
jeu (cérémonie, CT-7) ; rien ne la vérifie en version 0, ni dans le service
ni dans un dossier.

L'annuaire des approbateurs (13.4) applique cette règle du côté de
l'organisation, sans la prouver : une adresse n'appartient qu'à une
entrée et n'est jamais attribuée à une autre personne, une entrée n'a
qu'une adresse active, et la validation d'une nouvelle adresse révoque la
précédente (EX-13.10) ; la console refuse de faire voter une adresse qui
n'est pas l'adresse active de la session (EX-13.18), et le service la
refuse sur le canal de la console (EX-12.16). Deux comptes du
système d'identité du client tenus par la même personne restent
indiscernables : c'est à l'organisation, à l'inscription des membres du
jeu, de l'empêcher (CT-7). Rien de l'annuaire n'entre dans le jeu figé ni
dans le dossier : le contrôle 7 compte toujours des adresses distinctes du
jeu déclaré.

## 9. Signature et affichage

Lecture : l'approbateur lit les consignes d'EX-9.20 et le pas à pas de
13.17 ; le reste de cette section s'adresse à l'intégrateur et à
l'administrateur, comme le dit la section 0. C'est une indication de
lecture, non une règle.

### 9.1 Ce qui est signé

L'objet signé est celui de CT-1 §6.3, sans changement :
`A = { decision, journal_id, org_id, request_hash, ticket }`, condensé
`D_A = SHA-256(P_A ‖ JCS(A))` avec `P_A = "noortrace/approbation/v0\n"`, puis
`personal_sign` EIP-191 version `0x45` sur les 32 octets de `D_A` (R1-F11).
L'implémentation de référence est celle de `scripts/lib/journal.mjs`
(`objetApprobation`, `condenseApprobation`, `condenseEIP191Approbation`,
`signerApprobation`, `verifierSignatureApprobation`, R1-F27). EIP-191 garantit
qu'un tel message n'est jamais une transaction (octet `0x19`, R2-F44,
https://github.com/ethereum/ERCs/blob/6b7a48ffa791e30ceee94d869b5eae9521fe158f/ERCS/erc-191.md#L29-L55).

**EX-9.1** Un approbateur vote `approuve` en signant `A` avec `decision =
"approuve"`, `refuse` en signant `A` avec `decision = "refuse"` ; les deux
condensés ne diffèrent que par `decision` (R1-F66). Un vote est la signature
de l'un des deux ; il n'existe pas de signature pour `expire`.

**EX-9.2** `threshold`, `approvers`, `at` et `reason` ne sont pas signés par
les approbateurs (CT-1 §5.3, R1-F8) ; ils sont attestés par la signature de
l'enregistreur. Aucune échéance n'est signée : une signature sur `A` reste
valable sans limite de temps (R1-C24), et seuls le cycle de vie du ticket
(échéance, décision unique, consommation unique) et la vérification du
noyau (SG-3, SG-4) bornent son usage.

**EX-9.3** Une signature est remise sous la forme `r ‖ s ‖ v` de 65 octets,
`v ∈ {27, 28}`, `s` dans la moitié basse de l'ordre (E-9 de CT-1). À la
réception d'un vote, le service DOIT d'abord **normaliser** la signature,
sans la clé : `r` et `s` doivent être dans `[1, n − 1]`, sinon la signature
est refusée (`signature_invalide`) avant toute normalisation ; `v ∈ {0, 1}`
devient `v + 27` ; un `s` dans la moitié haute devient `n − s` et `v` est
inversé (27 ↔ 28). Les deux formes recouvrent la
même adresse (R2-F64,
https://github.com/ethereum/EIPs/blob/f1bcca1b56ee91fe115d2a8d8fd731fd6ca38bb3/EIPS/eip-2.md ;
mesure sur le vecteur de CT-1, R2-F65). ethers et les deux branches de signature
du micrologiciel de Trezor produisent un `s` bas : trezor-crypto (R2-F66) et
secp256k1-zkp, qui passe par `secp256k1_ecdsa_sign_recoverable` de libsecp256k1,
dont la signature est toujours en forme `s` bas (R4-F26, qui lève R2 NV-6) ;
Trezor rend `v = 27 + recid` (R4-F25). Le SDK publié de Ledger ramène `s` dans
la moitié basse, et l'application Ethereum n'emploie pas le drapeau qui l'en
dispense (R4-F24), mais que le système de l'appareil exécute ce code n'est pas
vérifié (R4 NV-2 : R2 NV-5 est réduit, pas levé) ; l'application rend
`v = 27 + parité` (R4-F22). Le porte-clés Ledger de MetaMask ramène à 27 ou 28
un `v ∈ {0, 1}` que l'appareil rendrait, selon un commentaire de son code
(R4-F21) ; ce cas n'est pas reproduit par le code de l'application lue (R4
NV-2), et R2 NV-7 reste ouvert pour les autres portefeuilles. Toute autre valeur
de `v` est refusée (`signature_invalide`). Le noyau, lui, ne normalise pas : il
refuse une forme non canonique (SG-5), comme le vérificateur et le contrat
(R2-F63).

### 9.2 Ce que l'approbateur voit avant de signer

Le règlement (UE) 2024/1689 demande, pour les systèmes à haut risque, que les
personnes chargées du contrôle humain puissent comprendre le système,
« interpréter correctement les sorties », avoir conscience du biais
d'automatisation et décider d'« ignorer, remplacer ou inverser » une sortie
(art. 14 § 4 a) à d), R3-F4 à R3-F7,
http://publications.europa.eu/resource/celex/32024R1689) ; le groupe de
travail « Article 29 » tient pour nulle une intervention humaine de façade,
qui doit être « meaningful, rather than just a token gesture » et confiée à
quelqu'un qui peut changer la décision (WP251rev.01 p. 21, R3-F36, R3-F37,
https://ec.europa.eu/newsroom/article29/redirection/document/49826). La
spécification MCP demande aussi de montrer les entrées d'un outil avant son
appel (R2-F9,
https://github.com/modelcontextprotocol/modelcontextprotocol/blob/80041ab0a139a8f4fb3adbc99f7ae9113ea59671/docs/specification/2026-07-28/server/tools.mdx).
Ces textes ne disent pas que NOORTRACE ou ses clients y sont soumis (R3,
section 2 : qualification non vérifiée) ; ils inspirent ce que la console
montre.

**EX-9.4** Avant toute signature, la console (section 13) DOIT afficher, sur
un même écran, les éléments suivants :

| Élément | D'où il vient | Lié à la signature |
|---|---|---|
| Outil : nom annoncé, nom d'origine, alias du serveur, classe | requête `evaluer` | par `request_hash` (l'événement `retenue` porte `execution.tool`) |
| Arguments en clair, champ par champ, chacun vérifié contre la pièce « arguments » (EX-9.6) ; un champ que la politique de rédaction remplace ou supprime dans la pièce est marqué « non vérifiable par la console » | requête `evaluer` (le service les garde tant que le ticket est actif, EX-7.24) ; pièce remise par `ouvrir` (12.4) | par `request_hash`, à travers la pièce **rédigée** : le clair n'est pas dans la chaîne |
| Effets déclarés prévus : le gabarit d'effets de l'outil (CT-2 EX-7.6) évalué sur les arguments ; un membre que l'effet liste dans `unresolved` (pointeur vers le résultat, non résolu avant l'exécution, valeur `null` dans la vue) est affiché « connu après exécution », avec son pointeur | membre `effects` de la vue (EX-12.14), que le service a évalué sur les gabarits reçus par `charger` (12.2) ; la console l'affiche tel quel, déclaratif | non |
| Règle déclenchée (`policy.rule`), sa description et son niveau (section 5), délai de contestation | politique, évaluation | `policy.rule` par `request_hash` |
| Pour un ticket ouvrant (5.3) : l'outil couvert, et lui seul ; la condition `when` rendue lisible ; chaque pointeur de `same_arguments` et sa valeur ; « au plus `max_calls` appels, chacun satisfaisant la condition, jusqu'à `approval.at` + `duration_ms` » | politique, ticket | non (EX-5.4) |
| Intention de l'agent, marquée « déclarée par l'agent, non vérifiée » ; quand l'événement `retenue` la porte par une référence, marquée « non vérifiable par la console » (contrôle 4 d'EX-9.15 ; `intent_status` du modèle d'affichage) | requête `evaluer` | par `request_hash` (par la pièce de l'intention quand l'événement la porte par une référence) |
| Délégation : `launched_by` et `scope` marqués « configuration de la connexion d'hôte » ; `on_behalf_of` et `run_id` marqués « déclaré par l'hôte, non vérifié » (CT-2 EX-7.2) ; sous `self_approval` `interdite`, un demandeur sans entrée dans `separation.identities` porte le bandeau « séparation non vérifiable pour ce demandeur » (10.5) | requête `evaluer` | par `request_hash` |
| Ticket, `org_id`, `journal_id` | service | **signés** (champs de `A`) |
| `request_hash` en entier, et l'événement `retenue` (seq, `ts`) dont la console a recalculé le hachage (CT-1 §6.1) | journal, par le service | **signé** |
| Décision choisie (`approuve` ou `refuse`), sans choix présélectionné | approbateur | **signée** |
| `D_A` en entier (64 chiffres hexadécimaux), calculé par la console | calcul local (EX-9.6) | c'est le condensé signé |
| Échéance et temps restant ; délai de contestation, fin de la fenêtre en cours, objections, et dernier instant où le seuil doit être atteint (10.2, EX-10.9) | service | non |
| Jeu figé : seuil `t` sur `n`, membres, votes déjà exprimés et leur motif, source (8.4) | service | non |
| Motif (facultatif) | approbateur | non : attesté par l'enregistreur |

**EX-9.5** La console NE DOIT présenter aucune décision par défaut ni aucune
recommandation de l'agent comme décisive (biais d'automatisation, art. 14
§ 4 b), R3-F5). Refuser DOIT demander le même nombre d'actions
qu'approuver.

### 9.3 Signature à l'aveugle : risque et parades

En v0, l'approbateur signe 32 octets binaires. Le code de MetaMask affiche un
message `personal_sign` de 32 octets en hexadécimal (R2-F53,
https://github.com/MetaMask/metamask-extension/blob/6b7ca07f635cbe04dad1040ff532623c629e531b/ui/helpers/utils/util.js#L830-L841),
l'application Ethereum de Ledger affiche en hexadécimal tout message qui
contient un octet non imprimable, sous l'intitulé « Message », sans passer par
le réglage « blind signing » (R2-F54,
https://github.com/LedgerHQ/app-ethereum/blob/f7985b427841ace20795b548905ababf6a5b17a4/src/features/sign_message/cmd_sign_message.c#L165-L191),
Trezor affiche `hex(…)` ce qui n'est pas de l'UTF-8 (R2-F55,
https://github.com/trezor/trezor-firmware/blob/30d30b37751c2d8e75da5746e18864948095f5db/core/src/apps/common/signverify.py#L31-L35),
et `D_A` n'est ni de l'UTF-8 valide ni de l'ASCII imprimable (R2-F56). La
documentation de MetaMask déconseille d'afficher ainsi des données
binaires, « because the user wouldn't be able to understand what they're
agreeing to » (R2-F51, https://docs.metamask.io/wallet/how-to/sign-data), et
MetaMask a décidé d'abandonner `eth_sign` pour ce risque d'hameçonnage (MIP-3,
statut « Accepted ») et la déclare dépréciée (R2-F51, R2-F59,
https://github.com/MetaMask/metamask-improvement-proposals/blob/d05c7248bf914e07828fd55815d4c232d83d4d6f/MIPs/mip-3.md) ;
`eth_sign` est absent de l'intergiciel de signature de MetaMask, un test de
bout en bout de son extension attend une erreur « méthode introuvable », et
Rabby le refuse (R4-F14, R4-F16, R4-F18) ; que la version publiée de
l'extension en soit dépourvue n'est pas vérifié (R4 NV-5). La révision
courante du code de MetaMask montre toujours un message de 32 octets en
hexadécimal, avec un bouton de copie (R4-F15), et Rabby fait de même pour des
octets qui ne sont pas de l'UTF-8 (R4-F18). L'écran du portefeuille ne dit
donc rien de la demande : il montre un condensé. Le rendu réel d'un tel défi
n'a été observé ni dans une extension ni sur un appareil : seul le code a été
lu (R1-NV2, R4 NV-1) ; celui des portefeuilles mobiles connectés par
WalletConnect n'est pas vérifié (R2 NV-8, R4 NV-4). Ce que chaque
portefeuille lu montre, et ce que l'approbateur y compare, est en 9.6
(EX-9.20).

**EX-9.6** La console DOIT construire `A` à partir des champs affichés, vérifiés
contre l'événement `retenue` (a à c ci-dessous), calculer `D_A` elle-même
(SHA-256 de `P_A ‖ JCS(A)`), et non le recevoir du serveur : le service lui sert
aussi ses propres condensés (`digests`, 12.9), qu'elle compare aux siens et ne
fait jamais signer (EX-9.17) ; afficher `D_A` en entier et son empreinte abrégée
(EX-9.18) ; et demander à l'approbateur de le comparer à celui que montre son
portefeuille (EX-9.20). Elle DOIT aussi vérifier ce qu'elle affiche contre la
demande retenue, avec l'événement `retenue` et la pièce « arguments » que le
noyau remet par `ouvrir` (12.4) et que le service lui sert :

a) recalculer le hachage de l'événement `retenue` (CT-1 §6.1) et l'égaler
   à `request_hash` ;
b) vérifier le `sha256` et la `length` de la pièce contre
   `execution.arguments` de cet événement, ou lire la valeur en ligne
   (`value`) ;
c) égaler à l'événement chaque élément affiché que la table d'EX-9.4 dit
   lié par `request_hash` : outil et `execution.tool`, `policy.rule`,
   `policy.ticket` et le ticket, `intent`, `delegation` (`launched_by`,
   `on_behalf_of`, `scope`, `run_id`), `org_id` et `journal_id` ;
d) comparer chaque argument affiché, pointeur par pointeur, à la pièce :
   égalité de valeur JSON exigée quand la valeur de la pièce ne contient
   aucun jeton `[REDIGE:…]` ni `[PSEUDO:…]` ; une valeur à jeton, ou un
   chemin absent de la pièce (règle `supprimer`), est affiché « non
   vérifiable par la console » ; un chemin présent dans la pièce et absent
   de l'affichage, ou toute autre différence, bloque la signature.

Tout écart en a) à d) bloque la signature. Ce contrôle ne couvre pas une
valeur rédigée : un service compromis peut substituer, dans l'affichage, un
champ que la pièce rédige (14.5).

**EX-9.7** La console DOIT passer `D_A` au portefeuille en **octets** : ethers
`signMessage(getBytes(D_A))`, viem `signMessage({ message: { raw: D_A } })`
(R1-F89, https://viem.sh/docs/accounts/local/signMessage ; R1-F90). Passée
à ethers ou à viem comme chaîne `"0x…"`, la valeur est encodée par la
bibliothèque en ses 66 caractères UTF-8 (R1-F89, R1-F90) : la mesure sur
`D_A` de CT-1 donne `0xadf18ec9…1da2d` en octets et `0xcde38bdf…1060f` en
chaîne (R2-F47) ; la signature ne recouvre pas l'approbateur et le service
la refuse (`signature_invalide`, vecteur `decisions/` de l'annexe A). Le
paramètre de `personal_sign` lui-même est la donnée en hexadécimal, que le
portefeuille décode en octets (R1-F91, R2-F61) : le piège est dans la
bibliothèque, pas dans le portefeuille.

**EX-9.8** Avant d'envoyer un vote, la console DOIT recouvrer l'adresse de la
signature sur `D_A` et l'égaler à l'adresse choisie par l'approbateur, selon
la procédure d'EX-9.21.

**EX-9.9** L'adresse d'un approbateur DEVRAIT être réservée aux opérations
NOORTRACE de son organisation : les votes, signés dans la console, et les
opérations du registre au seuil de CT-4 (`registerDigest`, `revokeDigest`,
`periodDigest`), signées hors de la console par un outil qui recalcule les
champs de la demande et les montre en clair (CT-4 EX-7.10) ; la console de
CT-3 ne fait jamais signer un condensé du registre (EX-13.16, point 3).
L'approbateur NE DEVRAIT signer un condensé de 32 octets que dans la console
ou dans cet outil. Un portefeuille matériel DEVRAIT être employé (la clé ne
quitte pas l'appareil).

**Signature obtenue hors de la console.** Une signature de `D_A` obtenue
hors de la console est un vote valable au sens de CT-1 (SG-5, contrôle 7 de
CT-6), et aucune échéance signée ne la borne (EX-9.2) : seuls le cycle de
vie du ticket et SG-3, SG-4 en limitent l'usage. Le service ne l'inscrit que
si elle lui parvient par le canal authentifié de la console, au nom d'une
session dont l'adresse active est le signataire (EX-12.16), et tant que le
ticket accepte des votes (EX-9.10) ; elle ne compte dans une décision
scellée qu'avant l'échéance (SG-4). Elle ne devient donc un vote que si
l'attaquant tient aussi l'un de ces éléments : la page de la console, le
serveur de console ou un autre émetteur du canal (EX-12.4), la session de
l'approbateur, ou le service d'approbation lui-même, qui peut la placer dans
une remise que le noyau ne juge que sur ses signatures (SG-5, EX-9.12). Un
site tiers qui présente `D_A` d'un ticket en attente comme « un message à
signer » obtient une telle signature, et le portefeuille ne permet pas de
s'en apercevoir : c'est le vrai `D_A`.

**Entre protocoles.** La même adresse signe, sous la même forme
(`personal_sign` sur 32 octets, préimage de 60 octets), les votes et les
condensés du registre de CT-4, et rien ne les distingue sur l'écran du
portefeuille. Une console compromise, ou un site tiers, qui présente un
condensé du registre comme un vote obtient une signature que le registre
accepte au seuil, sans qu'aucun vote soit inscrit ni notifié (EX-13.3) ; une
demande complète au seuil reste relayable par quiconque la détient (CT-4
EX-8.19). Ce qui le borne : la comparaison de l'empreinte (EX-9.18, EX-9.20),
le seuil, et la surveillance par l'organisation des événements du registre
(`RecorderRegistered`, `PeriodSubmitted`), suivie d'une révocation (CT-4). Une
séparation de domaine au portefeuille, par des données typées EIP-712 dont le
domaine diffère selon l'usage, est une piste pour une version 1 (section 16).

Ce que ces parades ne couvrent pas : une console compromise peut afficher une
demande et faire signer le `D_A` d'une autre, puisque l'approbateur ne voit
sur son portefeuille qu'un condensé ; elle peut aussi faire signer
`approuve` à qui a choisi `refuse` sur la même demande, les deux objets `A`
ne différant que par `decision` (EX-9.1). Pour les objections et les revues
de montant élevé, l'approbateur DEVRAIT comparer les huit groupes
(EX-9.18) ; un outil hors ligne indépendant de la console, qui recalculerait
`D_A` pour un second contrôle, n'est pas livré par la version 0 (section 16).
CT-3 ne fixe pas de seuil de « montant élevé » : en version 0, l'organisation
le dit à ses approbateurs, et comparer les huit groupes reste possible pour
toute demande. Le service DEVRAIT notifier à l'approbateur, par un canal
indépendant de la console, chaque vote inscrit en son nom, avec le ticket, la
décision et l'empreinte du `D_A` signé (EX-13.3) ; c'est la limite du format
v0 (CT-6 : rien ne prouve que l'approbateur a lu ce qu'il approuvait,
R1-F62). Les
remèdes changent l'objet signé et relèvent d'une version 1 (section 16) :
données typées EIP-712 (R2-F48,
https://github.com/ethereum/EIPs/blob/f1bcca1b56ee91fe115d2a8d8fd731fd6ca38bb3/EIPS/eip-712.md),
dont l'affichage chez Ledger exige encore un réglage ou un descripteur
(R2-F58, R2-F60, R2 NV-10), ou texte lisible `personal_sign` en ASCII
imprimable seulement, qu'un accent ferait afficher en hexadécimal par Ledger
(R2-F54), comme le message texte des décisions de curateur de curators-hub
(R1-F84).

### 9.4 Vérification par le service puis par le noyau

**EX-9.10** Le service accepte un vote (T6) si et seulement si, dans cet
ordre (la première raison qui s'applique est rendue, table 12.8) : le ticket
existe (`ticket_inconnu`) ; il n'est pas en `reserve` (`ticket_non_ouvert`) ;
il est en `ouvert`, `seuil_atteint` ou `verification`
(`ticket_clos_aux_votes`) ;
le jeu est figé (`jeu_non_fige`) ; la signature normalisée (EX-9.3) recouvre,
sur `D_A` de `A` construit avec la décision du vote et le ticket, une adresse
égale à `approver` (`signature_invalide`) ; `approver` est membre du jeu
figé (`hors_jeu`) ; il est éligible (10.1 : `auto_approbation`, `recuse`) ;
le motif fait au plus 1 024 caractères (`motif_trop_long`) ; le vote porte
une autre décision que le vote courant du même approbateur (sinon
`vote_identique`, sans effet, EX-7.20) : un vote de même décision et d'un
autre motif est identique. Un vote à deux défauts reçoit la première raison
de cet ordre (trace `ordre-des-raisons-de-vote` de l'annexe A.6).

**EX-9.11** Le noyau vérifie chaque remise avant de la sceller (CT-2 EX-7.5),
par les vérifications SG- ci-dessous, dans cet ordre ; un échec refuse la
remise (`acquitter` `refuse`, 12.5) avec la raison de la première
vérification en échec, et la décision n'est jamais scellée. À l'intérieur
d'une vérification, les raisons sont essayées dans l'ordre où la dernière
colonne les donne. Seule
l'indisponibilité du noyau (mode dégradé, CT-2 §14.2) donne un refus
`temporaire`.

| Id | Vérification | Raison de refus |
|---|---|---|
| SG-1 | La remise a la forme de `ticket-v0` (`$defs/remise`) : `approval` sans `at`, `approval.ticket` égal au ticket de la remise, `remise_id` de la forme `<ticket>/<n>` pour ce ticket, `approver_set` dont la `source` respecte EX-8.8 (forme seulement : le noyau ne compare pas `c=`, `r=` ni `s=` à la politique, 14.4) | `remise_mal_formee` |
| SG-2 | Un événement `retenue` du journal porte `policy.ticket = ticket`, et l'un d'eux a pour `hash` `request_hash` | `ticket_inconnu`, `request_hash_different` |
| SG-3 | Aucune décision n'est scellée pour ce ticket | `ticket_deja_decide` (la réponse donne la décision scellée) |
| SG-4 | Pour `approuve` et `refuse` : l'instant d'écriture de la décision, qui sera `approval.at` (CT-2 EX-7.11), est strictement antérieur à l'échéance `request_ts + E` (EX-7.10 ; `request_ts` est le `ts` de l'événement `retenue` dont le `hash` est `request_hash`) | `echeance_depassee` |
| SG-5 | E-5 et E-9 de CT-1 : même longueur, chaque signature canonique recouvre `approvers[i]` sur `D_A` du `A` de la remise, avec l'`org_id` et le `journal_id` du journal | `signature_invalide` |
| SG-6 | A-3 de CT-1 : approbateurs distincts, membres de `approver_set.members`, `threshold` égal à `approver_set.threshold`, `required ≤ size` et `size` égal au nombre de membres (sinon `seuil_different_du_jeu`), aucun approbateur pour `expire`, au moins `required` pour `approuve` et `refuse` | `approbateur_double`, `approbateur_hors_jeu`, `seuil_different_du_jeu`, `expire_avec_signatures`, `seuil_non_atteint` |
| SG-7 | Séparation des tâches : quand la politique d'approbation de la version de l'événement `retenue` (son `code.policy_version`) a `separation.self_approval: "interdite"`, aucune adresse de `approvers` n'est une adresse du demandeur, c'est-à-dire de l'entrée de `separation.identities` dont `launched_by` est égal, octet pour octet, au `delegation.launched_by` de cet événement (EX-10.1, EX-10.2) | `auto_approbation` |

**EX-9.12** Le noyau ne vérifie pas la fenêtre de contestation : il ne
voit pas les votes, qui restent dans le service (section 10), et une remise
qui la viole n'est pas détectée par SG-1 à SG-7. C'est l'une des raisons
pour lesquelles le canal entre le noyau et le service est authentifié
(12.1). La séparation des tâches, elle, est vérifiée par le noyau (SG-7) :
il a la politique d'approbation de chaque version, pièce de l'ensemble de
politique, et l'événement `retenue`. SG-7, proposée par la section 15, est
adoptée par CT-2 version 0.3 (CT-2 EX-7.5) ; une remise d'un service
conforme ne l'échoue jamais, puisque le service écarte déjà ces votes
(EX-10.2), et elle ne voit que les adresses que la politique déclare
(EX-10.5).

### 9.5 Refus et motif

**EX-9.13** Une décision `refuse` exige `required` signatures de refus (A-3
de CT-1, « mêmes règles », R1-F20), et le seuil effectif d'EX-8.6. Avec un
jeu de deux sur trois, un seul refus ne fait pas une décision `refuse` :
quand `contest_ms > 0`, il est une objection, avant comme pendant la
fenêtre, et empêche l'approbation tant que son auteur ne la lève pas
(10.2) ; sinon il est compté (EX-7.27).

**EX-9.14** `reason` est le motif du vote qui a complété le seuil (le
`t`-ième dans l'ordre d'acceptation, `t` étant le seuil effectif, EX-7.28),
ou `null` s'il n'en a pas ; pour `expire`, la chaîne fixe d'EX-7.11. Le
motif est une valeur en ligne, dans la chaîne signée, qui ne peut pas être
purgée : la console DOIT avertir qu'il ne doit contenir aucune donnée
personnelle, et le noyau DEVRAIT lui appliquer les détecteurs de texte de la
politique de rédaction avant de le sceller, comme aux autres valeurs en ligne
(CT-2 EX-10.2) ; CT-2 version 0.3 en fait une obligation du noyau (CT-2
EX-10.24).

### 9.6 Contrôle local avant la signature

La console ne croit le service sur rien de ce qui entre dans la signature.
Elle reçoit de lui la vue du ticket (`consulter`, 12.9) : la demande en
clair, l'événement `retenue` tel que le noyau l'a scellé, la pièce
« arguments » rédigée, la règle, le jeu figé, les votes, et les condensés
`D_A` que le service a calculés pour les deux décisions. Elle recalcule
elle-même tout ce qui est lié à la signature, compare, et ne demande une
signature que si tout concorde. Les condensés du service ne servent qu'à ce
contrôle croisé : une console qui ferait signer la valeur du service
signerait ce qu'un service compromis lui dicte.

**EX-9.15** **Contrôles avant la signature.** Avant de demander une
signature, la console DOIT appliquer les contrôles suivants, dans cet ordre,
à une vue reçue par une requête `consulter` envoyée **après** que
l'approbateur a choisi sa décision et son adresse (une vue antérieure ne sert
qu'à l'affichage ; 13.9 dit les trois lectures de la vue et de l'annuaire).
Chaque contrôle en échec ajoute sa raison
(`$defs/code_console` de `console-approbation-v0`) à la liste `blocking` du
modèle d'affichage, dans l'ordre des contrôles ; la console ne demande de
signature que si la liste est vide (`signable`).

1. `state` est `ouvert`, `seuil_atteint` ou `verification` :
   `ticket_clos_aux_votes` sinon.
2. L'événement `retenue` : `execution.status` vaut `retenue`,
   `policy.decision` vaut `a_approuver`, `policy.ticket` est le ticket, et
   son hachage recalculé (CT-1 §6.1 : SHA-256 de `P_H ‖ JCS(E')`, `E'`
   l'événement sans `hash` ni `sig`) est égal à son `hash` et au
   `request_hash` de la vue : `evenement_invalide` sinon. En cas d'échec, les
   contrôles 3 à 6 ne sont pas faits : la console ne forme pas `A` sur un
   événement qu'elle n'a pas vérifié, le modèle n'a pas de condensés
   (`digests` nul), et chaque argument est affiché « non vérifiable par la
   console » (`non_verifiable`).
3. La pièce « arguments » (EX-9.6 b) : si `arguments_piece` n'est pas nul,
   ses octets décodés (base64 de la RFC 4648 §4) ont le `sha256` et la
   `length` de la référence `execution.arguments` de l'événement, et forment
   un texte JSON strict en UTF-8 (CT-2 §4.4 pas 1) ; s'il est nul, la
   référence porte une valeur en ligne `value` qui la vérifie (CT-1 §5.4) :
   `piece_invalide` sinon. En cas d'échec, le contrôle 5 n'est pas fait et
   chaque argument est affiché « non vérifiable par la console ».
4. Les champs liés (EX-9.6 c) : `execution.tool` est égal à
   `request.tool_announced`, `policy.rule` à `rule.policy_rule`, `org_id` et
   `journal_id` de l'événement à ceux de la vue, chacun des quatre membres de
   `delegation` (`launched_by`, `on_behalf_of`, `scope`, `run_id`) à celui de
   la requête, et `intent` à celui de la requête quand l'événement le porte
   en chaîne : `champ_different` sinon. Quand l'événement porte l'intention
   par une référence, la console l'affiche « non vérifiable par la
   console », sans bloquer. L'intention est portée par une référence quand
   le membre `intent` de `retained_event` est un objet (forme `reference` de
   CT-1) et non une chaîne ; la référence se lit dans l'événement retenu de
   la vue, et non dans `request`. La vue ne porte pas la pièce de
   l'intention : la console n'en vérifie donc ni le `sha256` ni la `length`,
   et affiche `request.intent` « non vérifiable par la console », au lieu de
   « déclarée par l'agent, non vérifiée ». Le modèle d'affichage le dit par
   son membre `intent_status` : `reference_non_verifiable` quand le membre
   `intent` de l'événement retenu est un objet, `en_clair` sinon (chaîne ou
   `null`) ; cas `console/modeles/intention-par-reference.json` (A.11).
5. Les arguments, feuille par feuille (EX-9.16) :
   `argument_different` si une feuille diffère, puis
   `argument_absent_de_l_affichage` si un chemin de la pièce manque à
   l'affichage.
6. Les condensés (EX-9.17) : `empreinte_divergente` si l'un des deux
   `D_A` de la console diffère de celui du service.
7. Le jeu est figé (`approver_set` non nul) : `jeu_non_fige` sinon ; en cas
   d'échec, les contrôles 10 et 11 ne sont pas faits (le contrôle 9 l'est).
8. L'approbateur a choisi `approuve` ou `refuse`, sans choix présélectionné
   (EX-9.5) : `decision_absente` sinon.
9. L'adresse choisie est l'adresse active que l'annuaire attribue à la
   session (EX-13.2, EX-13.18) : `identite_inconnue` si l'identité de
   session n'a pas d'entrée, `identite_desactivee` si son entrée est
   inactive, `adresse_non_attribuee` si l'adresse n'est pas l'adresse active
   de l'entrée ; en cas d'échec, les contrôles 10 et 11 ne sont pas faits.
10. L'adresse est membre du jeu figé : `hors_jeu` sinon ; en cas d'échec, le
    contrôle 11 n'est pas fait.
11. L'adresse est éligible (`eligible` de la vue, 10.1) : sinon
    `auto_approbation` si elle est une adresse du demandeur sous
    `self_approval: "interdite"`, `recuse` dans les autres cas.
12. L'identité de session n'est pas celle du demandeur quand
    `self_approval` vaut `interdite`, c'est-à-dire que le `launched_by` du
    ticket n'est pas dans `requester_identities` de son entrée (13.4,
    EX-10.5, EX-13.2) : `session_du_demandeur` sinon.
13. Le motif fait au plus 1 024 caractères, comptés en points de code
    (EX-9.10) : `motif_trop_long` sinon.

Les contrôles 7, 10, 11 et 13 répètent ceux que le service fait au vote
(EX-9.10), et le contrôle 9 celui du canal (EX-12.16) : la console les fait
d'abord pour ne pas demander une signature inutile, qui resterait valable
sans limite de temps (EX-9.2). Le contrôle 12 n'est fait que par la console.
Les contrôles 7, 9, 10 et 12 sont ceux d'EX-13.18, dans le même ordre.

Avec un service conforme, `consulter` ne rend la vue qu'à une session dont
l'entrée est active et dont l'adresse active est un membre éligible du jeu
figé, ou à un administrateur (EX-12.14) : toute autre session reçoit
`session_non_autorisee` dès `consulter` (13.14). Les raisons
`identite_inconnue`, `identite_desactivee`, `hors_jeu`, `auto_approbation` et
`recuse` n'apparaissent alors que pour un administrateur, pour une adresse
choisie autre que l'adresse active, pour un changement survenu entre deux
lectures, ou face à un service non conforme : la console les contrôle quand
même, en défense en profondeur. Avec une page conforme à EX-13.23,
l'adresse choisie pour un vote est l'adresse active lue dans l'annuaire à la
lecture précédente ; `adresse_non_attribuee` n'apparaît alors que dans deux
cas : l'annuaire relu après le choix (13.9, pas 3 ou 7) n'attribue plus
cette adresse, parce qu'elle a été révoquée ou remplacée par la validation
d'une autre (EX-13.17) ; ou une console laisse choisir une autre adresse. Le
contrôle reste exigé en défense en profondeur (cas
`console/modeles/adresse-non-attribuee.json`, A.11). Pour une inscription,
l'adresse choisie est l'un des comptes exposés (EX-13.23).
`session_du_demandeur` reste atteignable quand l'adresse active du demandeur
est éligible, c'est-à-dire quand la politique ne la déclare pas pour lui
(`separation_incomplete`). Face à une console non conforme, la séparation
n'est donc garantie que pour les adresses que la politique déclare pour le
demandeur, dont le service refuse les votes (`auto_approbation`, EX-9.10) et
que le noyau vérifie (SG-7) : le contrôle 12 ne protège qu'avec une console
conforme, et l'avertissement `separation_incomplete` signale que la
politique est à compléter (EX-10.5).

Le modèle porte aussi des avertissements, affichés sans bloquer, dans cet
ordre : `condense_utf8` (EX-9.19) ; `separation_non_verifiable`, bandeau
d'un demandeur sans entrée dans `separation.identities` (EX-9.4, 10.5) ;
`membres_ajoutes`, membres ajoutés au jeu par un nouveau gel (EX-8.6) ;
`separation_incomplete`, adresse que l'annuaire attribue au demandeur et
que la politique ne déclare pas pour lui (EX-13.18).

**EX-9.16** **Arguments, feuille par feuille.** Les **feuilles** d'une
valeur JSON sont définies ainsi : un nombre, une chaîne, un booléen, `null`,
un objet sans membre et un tableau vide sont une feuille, de pointeur vide ;
les feuilles d'un objet sont celles de ses membres, dans l'ordre JCS des noms
(unités UTF-16, CT-1 §4), le pointeur de chacune étant précédé de `/` et du
nom échappé (`~` en `~0`, puis `/` en `~1`, RFC 6901) ; les feuilles d'un
tableau sont celles de ses éléments, dans l'ordre, précédées de `/` et de
l'indice décimal. Les pointeurs partent de la racine des arguments
(`/amount`, et non `/arguments/amount` comme dans une politique). Pour
chaque feuille `p` des arguments en clair, la console résout `p` dans la
valeur de la pièce, selon les pas 1 et 2 d'EX-4.4 appliqués à cette valeur :

| Résultat | État de la feuille |
|---|---|
| `p` non résolu (chemin supprimé par la rédaction, ou passage par une valeur rédigée) | `non_verifiable` |
| `p` résolu vers une chaîne qui contient `[REDIGE:` ou `[PSEUDO:` | `non_verifiable` |
| `p` résolu vers une valeur JSON égale (CT-1 : chaînes égales point de code par point de code, nombres égaux en valeur, objets égaux membre par membre sans égard à l'ordre) | `verifie` |
| autre valeur | `different`, et `argument_different` dans `blocking` |

Puis, pour chaque feuille `q` de la pièce, la console résout `q` dans les
arguments en clair ; un `q` non résolu ajoute
`argument_absent_de_l_affichage`. La console affiche chaque feuille avec sa
valeur et son état, `non_verifiable` sous la mention « non vérifiable par la
console » (EX-9.4).

Exemple : la vue de 12.9 (ticket `apr-2201`) porte en clair `amount`
`"12500.00"`, `beneficiary_iban` `"CH9300762011623852957"` (valeur choisie
pour l'exemple), `claim_id` `"2026-81044"` et `currency` `"CHF"` ; la pièce
de CT-1 porte `"beneficiary_iban":"[REDIGE:iban]"`. Les feuilles sont, dans
l'ordre : `/amount` `verifie`, `/beneficiary_iban` `non_verifiable`,
`/claim_id` `verifie`, `/currency` `verifie`. Avec `amount` `"21500.00"` en
clair, `/amount` devient `different` et `blocking` vaut
`["argument_different"]`.

**EX-9.17** **Formation de `A` et contrôle croisé.** Dès que le contrôle 2
passe (événement vérifié), que les contrôles 3 et 4 passent ou non, la
console forme, pour chaque décision `d` de {`approuve`, `refuse`} :

```text
A_d   = { "decision": d, "journal_id": journal_id de l'événement, "org_id": org_id de l'événement,
          "request_hash": hachage recalculé de l'événement, "ticket": policy.ticket de l'événement }
D_d   = SHA-256( "noortrace/approbation/v0\n" ‖ JCS(A_d) )
H_d   = keccak256( 0x19 ‖ "Ethereum Signed Message:\n32" ‖ D_d )
```

et compare `D_approuve` et `D_refuse` aux membres `approuve` et `refuse` de
`digests` de la vue. Sur un écart, l'un ou l'autre, la console NE DOIT PAS
demander de signature, NE DOIT PAS proposer de signer la valeur du service,
affiche les deux empreintes abrégées (la sienne et celle du service) avec la
mention « le service a calculé un autre condensé que la console : aucune
signature n'est demandée », et DEVRAIT le signaler au contact administrateur
de l'organisation (10.3) : un service qui calcule un autre `D_A` que celui de
l'événement retenu est défaillant ou compromis. La comparaison porte sur les
deux décisions : un service qui ne fausse que l'une est découvert avant que
l'approbateur ne change d'avis.

Exemple, ticket `apr-2201` des vecteurs de CT-1 (seq 5, journal
`0x41c2…5164`) :

```text
JCS(A_approuve) = {"decision":"approuve","journal_id":"0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","request_hash":"0x22a54600beeb4674976033c5a21740dfe45a1886ff1f69082b5c18141efd122d","ticket":"apr-2201"}
D_approuve      = 0xa57cbdad280b5cb2e9f6ee87b85d8bc05e76a5966377e7d58046519464f7df7c
H_approuve      = 0xe9f3d8812e1fc736cd7957efb20093bfb3655c6568fc56e6133b2cc41d2cf6ea
D_refuse        = 0xd2cace7b1eded2643785e99e2f5316ee6cb4fad6ea468426d30d76538ccab300
H_refuse        = 0xde5123ed1281dbf3fa4f923b14c96db3481c460e7ed324b2943fffbec2f04811
```

`A_approuve` est, clé pour clé, la valeur en ligne de l'événement de décision
seq 6 de ces vecteurs, et les signatures des comptes 1 et 2 sur
`D_approuve` sont celles de son `approval` (exemple de remise de 12.5).

**EX-9.18** **Empreinte abrégée et affichage stable.** Pour une valeur `X`
de 32 octets, soit `x` ses 64 chiffres hexadécimaux en minuscules, sans
`0x` :

```text
empreinte(X) = x[0..8] ‖ "…" ‖ x[56..64]         17 caractères ; « … » est U+2026
groupes(X)   = x[0..8] " " x[8..16] " " … " " x[56..64]   8 groupes de 8, séparés par une espace
```

`x[a..b]` désigne les éléments d'indice `a` inclus à `b` exclu ; toute
tranche de CT-3 s'écrit ainsi (13.13 : `DK[16..32]` est formé des 16 derniers
octets de `DK`).

Sur l'écran de signature, pour la décision choisie, la console DOIT afficher
dans une police à chasse fixe, sans couper un groupe : `D_A` en entier, avec
`0x` ; `groupes(D_A)` ; `empreinte(D_A)`, en caractères plus grands, sous
l'intitulé « empreinte du condensé à signer » ; puis, séparé et sous
l'intitulé « condensé EIP-191, montré par certains appareils sous « Message
hash » », `empreinte(H)` et `groupes(H)`. Elle n'emploie aucune autre
abréviation de ces valeurs (pas d'autre longueur, pas de troncature à
droite seule). Toute console, la bibliothèque de référence et les vecteurs
appliquent la même fonction : l'empreinte d'un condensé est la même partout.
Exemple : `empreinte(D_approuve)` = `a57cbdad…64f7df7c`,
`groupes(D_approuve)` =
`a57cbdad 280b5cb2 e9f6ee87 b85d8bc0 5e76a596 6377e7d5 80465194 64f7df7c`,
`empreinte(H_approuve)` = `e9f3d881…1d2cf6ea`, `empreinte(D_refuse)` =
`d2cace7b…8ccab300`.

L'empreinte compare 16 chiffres, soit 64 bits. Pour qu'un autre condensé
partage les deux extrémités de celui qu'affiche une console honnête, il
faudrait l'événement `retenue` d'une autre demande dont le `D_A` les partage ;
chaque essai est un événement scellé par l'enregistreur, qui porte son `seq`,
son `ts` et le hachage du précédent : on ne peut pas en chercher hors ligne
parmi les `D_A`. Cet argument ne vaut que si la clé ne signe que des `D_A`.
La même adresse signe aussi les condensés du registre de CT-4 (EX-9.9), dont
`registerDigest` contient deux champs libres pour l'attaquant (la clé de
chaîne et la clé Ed25519 de 32 octets) : un attaquant peut y chercher hors
ligne, en environ 2^64 essais et sans aucun événement scellé, un condensé du
registre dont l'empreinte égale celle d'un `D_A` légitime. Contre cette
recherche, comparer les huit groupes est la seule parade. Pour une objection
ou une revue de montant élevé, l'approbateur DEVRAIT comparer les huit
groupes (EX-9.9) ; CT-3 ne fixe pas de seuil de montant élevé.

**EX-9.19** **Condensé qui est de l'UTF-8.** Si les 32 octets du `D_A` de
la décision choisie forment de l'UTF-8 valide (RFC 3629), la console DOIT
afficher l'avertissement `condense_utf8` : « certains portefeuilles
afficheront ce condensé comme du texte ; comparez-le sur un appareil qui
l'affiche en hexadécimal ». MetaMask (composant de confirmation lu), Rabby
et Trezor montrent en texte un message qui est de l'UTF-8 valide (R4-F15,
R4-F18, R4-F25, R2-F55), alors qu'une autre fonction de MetaMask garde
l'hexadécimal pour 32 octets (R4-F15) : lequel joue n'est pas vérifié ;
l'application Ethereum de Ledger montre en hexadécimal tout message qui
contient un octet non imprimable (R2-F54). La probabilité qu'une
chaîne de 32 octets soit de l'UTF-8 valide est d'environ 1,0 × 10⁻⁸
(R4-F19) ; aucun `D_A` des vecteurs ne l'est. L'avertissement ne dépend que
du `D_A` de la décision choisie : sans décision choisie, ou sans condensés
(contrôle 2 d'EX-9.15 en échec), il n'est pas porté. Si le seul portefeuille
de l'approbateur montre du texte au lieu des 64 chiffres, EX-9.20, point 5,
s'applique : il refuse dans le portefeuille, puis vote avec un autre
portefeuille qui détient la même clé et montre les 64 chiffres, depuis une
page rechargée ; si aucun ne détient la clé, il inscrit une autre adresse
(13.17, « Changer de clé »). Le cas est rare : environ une fois sur cent
millions (R4-F19).

**EX-9.20** **Ce que l'approbateur vérifie avant de signer, et ce qu'il
fait si l'empreinte diffère.** La console DOIT afficher, sur l'écran de
signature, les consignes suivantes, et l'approbateur DEVRAIT les suivre :

1. Lire la demande (EX-9.4) : outil, chaque argument et sa marque
   (« vérifié », « non vérifiable par la console », dont 13.17, « Voter »,
   pas 1, dit le sens), effets prévus (« connu après exécution » pour une
   valeur tirée du résultat), règle, délégation, intention marquée
   « déclarée par l'agent, non vérifiée », ou « non vérifiable par la
   console » quand l'événement la porte par une référence, jeu et votes.
2. Choisir sa décision et son adresse ; la console affiche alors
   l'empreinte du condensé de cette décision, et elle seule.
3. Sur l'écran du portefeuille, retrouver les 64 chiffres hexadécimaux du
   message (avec ou sans `0x`, ou entre `hex(` et `)`) et comparer les 8
   premiers et les 8 derniers à l'empreinte affichée sous l'intitulé
   « empreinte du condensé à signer » ; pour une objection ou un montant
   élevé (CT-3 n'en fixe pas le seuil : l'organisation le dit), comparer les
   huit groupes. Sur un appareil qui montre aussi « Message hash », comparer
   cette valeur à l'empreinte affichée à part, sous l'intitulé « condensé
   EIP-191, montré par certains appareils sous « Message hash » » (`H`), et
   jamais à l'empreinte du condensé à signer (`D_A`).
4. Si tout concorde, confirmer dans le portefeuille.
5. Si l'empreinte diffère, ou si le portefeuille montre autre chose qu'un
   message (une transaction, des données typées) : refuser dans le
   portefeuille, ne pas réessayer depuis cette page, et prévenir
   l'administrateur de l'organisation par un autre canal que la console
   (13.17). Si le portefeuille ne montre pas les 64 chiffres en hexadécimal,
   en entier : refuser dans le portefeuille et ne pas voter avec ce
   portefeuille ; voter avec un portefeuille qui détient la même clé et
   montre les 64 chiffres (un autre portefeuille de navigateur de la table
   ci-dessous, ou l'appareil matériel qui porte la clé, par un portefeuille
   de navigateur : parcours a ou b, EX-13.20), depuis une page de console
   rechargée ; si aucun ne détient la clé, inscrire une autre adresse (13.17,
   « Changer de clé »). Refuser dans le portefeuille n'est pas voter
   `refuse` : aucun vote n'est envoyé (13.14). Pour s'opposer à la demande,
   l'approbateur signe la décision `refuse`, depuis une console saine : la
   console de l'organisation ouverte à son origine (`console_origin`,
   EX-13.14), sur un autre poste ou dans un autre profil de navigateur sans
   extension que celui où l'écart est apparu, ou après que l'administrateur
   prévenu a écarté la cause. La concordance des empreintes ne prouve pas
   qu'une console est saine (dernier alinéa de cette règle). Tant que
   l'approbateur n'a pas signé `refuse`, son opposition ne compte pas : les
   autres membres peuvent encore atteindre le seuil `approuve` (EX-7.27) ;
   sans décision scellée avant l'échéance, le ticket expire, et un délai
   écoulé ne vaut jamais approbation (EX-7.10, EX-3.2).
6. Si la console affiche elle-même `empreinte_divergente` : il n'y a rien à
   signer ; prévenir l'administrateur.
7. Après le vote, si l'organisation a mis en place la notification
   indépendante (EX-13.3), vérifier qu'elle annonce le vote inscrit en son
   nom avec le ticket, la décision choisie et l'empreinte affichée. Si elle
   nomme un autre ticket, une autre décision ou une autre empreinte, ou si
   elle n'arrive pas dans le délai que l'organisation a fixé, prévenir
   l'administrateur par un autre canal ; tant que le ticket accepte des votes
   (`ouvert`, `seuil_atteint`, `verification`, EX-9.10), signer la décision
   voulue sur le ticket concerné depuis une console saine, ce qui remplace le
   vote (EX-7.26) ; une décision déjà scellée ne s'annule pas (SG-3).

Ce que montrent les portefeuilles lus, pour un `personal_sign` de 32 octets
(code lu ; le rendu à l'écran, la pagination et la troncature n'ont pas été
observés, R4 NV-1) :

| Portefeuille | Ce qui est à l'écran | Où comparer | Source |
|---|---|---|---|
| MetaMask, extension | ligne « message » : la donnée reçue, `0x` et 64 chiffres minuscules, avec un bouton de copie | les 64 chiffres | R4-F15, R2-F53 |
| Rabby | la donnée reçue, `0x` et 64 chiffres, quand les octets ne sont pas de l'UTF-8 | les 64 chiffres | R4-F18 |
| Ledger, application Ethereum (par un portefeuille de navigateur) | écran « Review message », paire « Message » en hexadécimal ; paire « Message hash » = `H` si le réglage « Transaction hash » est activé ; aucun réglage « blind signing » requis | « Message » avec l'empreinte de `D_A` ; « Message hash » avec celle de `H` | R4-F23, R2-F54 |
| Trezor, micrologiciel « core » (par un portefeuille de navigateur) | `hex(` suivi des 64 chiffres sans `0x`, puis `)` | les 64 chiffres | R4-F25, R2-F55 |
| Fenêtre de Trezor Connect sur l'ordinateur | décodage en texte du message (R4-F27) ; son rendu pour 32 octets binaires n'est pas vérifié | ne pas s'y fier : comparer sur l'appareil | R4-F27 |
| Portefeuille mobile (WalletConnect) | non vérifié | refuser s'il ne montre pas les 64 chiffres | R4 NV-4, R2 NV-8 |
| Trezor Model One, autres portefeuilles | non lus | idem | R4 NV-3, R4 NV-10 |

Cette table dit où chercher les 64 chiffres d'après le code des
portefeuilles ; elle est indicative. Ce qui protège l'approbateur n'en
dépend pas : si l'écran de son portefeuille ne montre pas les 64 chiffres en
hexadécimal, en entier, il refuse et applique le point 5. La console n'en
dépend pas non plus : sur l'écran de signature, elle affiche toujours `D_A`
en entier, `groupes(D_A)`, `empreinte(D_A)`, `empreinte(H)` et `groupes(H)`
(EX-9.18) et, s'il y a lieu, l'avertissement `condense_utf8` (EX-9.19). Ce
que l'approbateur voit réellement reste non vérifié (R4 NV-1), et le point 5
couvre tout écran qui ne montre pas les 64 chiffres.

Ce que la comparaison couvre : un fournisseur ou une extension qui
changerait le message entre la page et le portefeuille (14.9). Ce qu'elle ne
couvre pas : une console compromise, qui affiche l'empreinte de ce qu'elle
fait signer (9.3) ; seule la notification indépendante (EX-13.3) le rend
visible, un outil hors ligne indépendant n'étant pas livré par la version 0
(section 16) ; et un condensé du registre de CT-4 dont l'attaquant a cherché
hors ligne les extrémités, contre lequel seule la comparaison des huit
groupes vaut (EX-9.18).

### 9.7 Contrôle local après la signature

**EX-9.21** **Vérification de la réponse et construction du vote.** Quand
le portefeuille rend une réponse à une requête de signature que la console a
envoyée pour un couple (`D_A`, adresse choisie), la console DOIT, avant tout
envoi au service :

1. si la promesse est rompue, appliquer la table des pannes (13.14) ; si elle
   est tenue avec autre chose qu'une chaîne `^0x[0-9a-fA-F]*$`, refuser
   (`reponse_invalide`) ;
2. écrire la chaîne en minuscules et exiger exactement 65 octets
   (132 caractères avec `0x`) : `signature_invalide` sinon, y compris pour
   une signature compacte de 64 octets (EIP-2098), qu'ethers accepte
   (R4-F37, R4-F38) ;
3. lire `r` (octets 0 à 31), `s` (32 à 63) et `v` (octet 64) ; exiger `r` et
   `s` dans `[1, n − 1]`, `n` l'ordre de secp256k1 : `signature_invalide`
   sinon ;
4. exiger `v ∈ {0, 1, 27, 28}` : `signature_invalide` sinon, y compris pour
   `v = 37` ou `38` (forme EIP-155), qu'ethers et eth-account acceptent
   (R4-F38, R4-F41) ;
5. normaliser comme EX-9.3 : `v ∈ {0, 1}` devient `v + 27` ; un `s` de la
   moitié haute devient `n − s` et `v` est inversé (27 ↔ 28) ;
6. recouvrer la clé publique `Q` depuis `H` (EX-9.17), `r`, `s` et
   l'identifiant de recouvrement `v − 27` ; un recouvrement impossible donne
   `signature_invalide` ;
7. calculer l'adresse, les 20 derniers octets de `keccak256(X ‖ Y)`, `X` et
   `Y` les coordonnées de `Q` sur 32 octets chacune, en minuscules ; si elle
   diffère de l'adresse choisie, refuser (`adresse_differente`), sans
   envoyer de vote ;
8. construire le vote, la requête `voter` de 12.9 :
   `{ "ticket", "approver", "decision", "signature", "reason",
   "session_identity" }`, avec le ticket du `A` signé, l'adresse choisie, la
   décision choisie, la signature **normalisée** et le motif saisi ; si
   l'approbateur a ouvert un autre ticket depuis la demande de signature, ne
   rien envoyer (EX-13.21). Construire un seul vote par signature et
   l'envoyer ; sans réponse, le renvoyer à l'identique (12.7, EX-13.29) ;
   ne jamais en construire un autre sans nouvelle signature (EX-12.16).

Le service refait EX-9.3 et EX-9.10 à la réception : la console ne le
remplace pas, elle évite d'envoyer en son nom une signature qui ne vaut pas
ce que l'approbateur a vu. Exemple (signature du compte 1 sur
`D_approuve`, ticket `apr-2201`) : la réponse
`0x6e8fb398cce443d4b4343245ac27679e1e460c1c441c0115a21055ec4f1dba09a770c4ec4f338561f271e0dfecc15f53f0bff32e1fc2794f85647391f249ff741c`,
de `s` haut et `v = 28`, est normalisée en
`0x6e8fb398cce443d4b4343245ac27679e1e460c1c441c0115a21055ec4f1dba09588f3b13b0cc7a9e0d8e1f20133ea0aac9eee9b88f8626ec3a6deafaddec41cd1b`,
qui recouvre `0x70997970c51812dc3a010c7d01b50e0d17dc79c8` ; la même
signature avec `v = 0x25` (37) est refusée ; une signature du compte 1 sur
la chaîne `"0xa57c…df7c"` (66 octets UTF-8) recouvre, sur `H`,
`0x58047c881cfdadf1b8d785b79b29c5cc784ede6e` : `adresse_differente`.

<!-- schema: console-approbation/cas_reponse -->
```json
{
  "version": 0,
  "id": "s-haut-normalisee",
  "description": "Signature du compte 1 sur D_A (apr-2201, approuve) rendue avec s dans la moitié haute et v = 28 : la console la ramène à s bas et v = 27, recouvre le compte 1 et envoie la forme normalisée.",
  "checks": [ "CS-6", "CS-7" ],
  "input": {
    "a": {
      "decision": "approuve",
      "journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
      "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
      "request_hash": "0x22a54600beeb4674976033c5a21740dfe45a1886ff1f69082b5c18141efd122d",
      "ticket": "apr-2201"
    },
    "approver": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
    "reason": "Constat et facture concordants",
    "session_identity": "oidc https://idp.assureur-demo.example approbateur-1",
    "response": {
      "result": "0x6e8fb398cce443d4b4343245ac27679e1e460c1c441c0115a21055ec4f1dba09a770c4ec4f338561f271e0dfecc15f53f0bff32e1fc2794f85647391f249ff741c"
    }
  },
  "expected": {
    "outcome": "accepte",
    "reason": null,
    "signature": "0x6e8fb398cce443d4b4343245ac27679e1e460c1c441c0115a21055ec4f1dba09588f3b13b0cc7a9e0d8e1f20133ea0aac9eee9b88f8626ec3a6deafaddec41cd1b",
    "recovered": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
    "vote": {
      "ticket": "apr-2201",
      "approver": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
      "decision": "approuve",
      "signature": "0x6e8fb398cce443d4b4343245ac27679e1e460c1c441c0115a21055ec4f1dba09588f3b13b0cc7a9e0d8e1f20133ea0aac9eee9b88f8626ec3a6deafaddec41cd1b",
      "reason": "Constat et facture concordants",
      "session_identity": "oidc https://idp.assureur-demo.example approbateur-1"
    }
  }
}
```

**EX-9.22** **Ne pas déléguer la forme à une bibliothèque.** Tout
programme qui vérifie la signature d'un vote (console, service, noyau, outil
hors ligne, script de confrontation) DOIT contrôler lui-même la forme
(65 octets ; `r` et `s` dans `[1, n − 1]` ; `v ∈ {0, 1, 27, 28}` pour qui
normalise, comme la console et le service ; `v ∈ {27, 28}` et `s ≤ n/2`
pour qui ne normalise pas, comme le noyau et le vérificateur) **avant**
d'appeler une bibliothèque, et DOIT lui passer `D_A` en octets (EX-9.7). Les
bibliothèques lues ne suffisent pas : ethers 6.17.0 accepte `v` = 0, 1 ou au
moins 35 et une signature compacte de 64 octets, et son accesseur refuse un
`s` haut (R4-F37, R4-F38) ; eth-account 0.14.0 accepte `v` au moins 35 et un
`s` haut (R4-F40, R4-F41) ; `@metamask/eth-sig-util` 9.0.0 accepte un `s`
haut (R4-F17). En Python, `encode_defunct(hexstr=D_A)` ou
`encode_defunct(primitive=<octets>)` signe les 32 octets ;
`encode_defunct(text="0x…")` signe 66 octets, et un entier passé en
`primitive` perd ses octets nuls de tête (R4-F41) : les vecteurs comprennent
un `D_A` dont le premier octet est nul (A.11).

## 10. Séparation des tâches et fenêtre de contestation

La règle de vote et le décompte sont en 7.11. Cette section dit qui ne
compte pas pour un ticket (séparation des tâches, récusation), comment une
objection retient une approbation (fenêtre de contestation, 5.6), où se
trouvent les réglages, ce qui est journalisé et ce qu'un réviseur peut en
établir.

### 10.1 Séparation des tâches

La séparation des tâches (NIST SP 800-53 AC-5, R3-F50, R3-F51) et la double
autorisation (AC-3(2) : deux personnes autorisées, « two-person control »,
R3-F55,
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf) se
traduisent par un seuil `t ≥ 2` de signatures indépendantes, que la v0 permet
déjà, **et** par l'exclusion du demandeur. Microsoft Entra PIM et Google Cloud
PAM interdisent d'approuver sa propre demande (R3-F79,
https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-approval-workflow ;
R3-F88, https://cloud.google.com/iam/docs/pam-approve-deny-grants), GitLab par
défaut (R3-F107, R3-F109,
https://docs.gitlab.com/ci/environments/deployment_approvals/), GitHub et Azure
Pipelines en option (R3-F98,
https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments ;
R3-F110). Le considérant 73 du règlement (UE) 2024/1689 admet au contraire que
la personne qui fait fonctionner le système soit l'une des deux personnes de
l'art. 14 § 5 (R3-F12,
http://publications.europa.eu/resource/celex/32024R1689) : l'exclusion est donc
un réglage de la politique, `separation.self_approval` (4.2), `interdite` ou
`permise` ; l'exemple de 4.3 l'interdit.

**EX-10.1** Le **demandeur** d'un ticket est `delegation.launched_by` de la
requête `evaluer` qui l'a créé (T1), qui vient de la configuration de la
connexion d'hôte et jamais de l'hôte (CT-2 EX-7.2). Les **adresses du
demandeur** sont les `addresses` de l'entrée de `separation.identities` dont
`launched_by` est égal au demandeur, octet pour octet et sans normalisation
(comme les chaînes de 4.8), ou l'ensemble vide s'il n'y en a pas. La
politique lue est celle de la version sous laquelle le ticket a été créé
(EX-7.21).

**EX-10.2** Un membre du jeu figé est **inéligible** pour un ticket, et ses
votes y sont refusés, dans les cas suivants et dans eux seuls :

| Cas | Réglage | Raison de refus (12.8) |
|---|---|---|
| son adresse est une adresse du demandeur | `self_approval: "interdite"` | `auto_approbation` |
| il s'est récusé pour ce ticket (`recuser`, EX-10.4) | toujours | `recuse` |

Avec `self_approval: "permise"`, l'adresse du demandeur vote comme celle de
tout autre membre ; la décision la nomme dans `approvers`, ce qui la rend
visible au réviseur (10.5).

**EX-10.3** Les éligibles sont calculés au gel du jeu (8.2) et à chaque
nouveau gel (8.3) ; leur liste figure dans la trace du ticket
(`eligible`). Un vote déjà accepté d'un membre devenu inéligible est écarté
et le décompte refait (EX-7.27), sauf le vote `refuse` d'un membre du jeu
figé qui s'est récusé : il reste courant et compté (EX-10.4).

**EX-10.4** Une **récusation** (`recuser`, conflit d'intérêts déclaré,
comme la récusation de curators-hub, R1-F84 et `lib/validation.ts` de
noorchain-core) rend le membre inéligible pour ce ticket seulement et ne
peut pas être annulée. Elle retire son vote `approuve` courant ; son vote
`refuse` courant reste compté dans `r` (EX-7.27), et son objection
demeure (EX-10.8). Elle ne peut donc qu'empêcher une approbation, jamais en
produire une, ni effacer un refus. Elle est transmise par la console sur le
canal authentifié d'EX-12.4, et la console DOIT ne l'envoyer que pour une
adresse attribuée à la session de l'approbateur (EX-13.2). Elle n'est pas
signée en v0 : une console compromise peut forger une récusation, qui ne
fait que retirer une approbation ; une récusation signée est une
proposition (section 16).

**EX-10.5** La séparation ne voit que ce que la politique déclare. Une
adresse que `separation.identities` n'associe pas au demandeur est
éligible, même si elle est la sienne : la déclaration est de la
responsabilité de l'opérateur qui écrit la politique, et son omission est
visible à qui détient la pièce de politique (10.5). La règle « une personne,
une clé » (EX-8.11) est ce qui donne un sens à la liste. La console DOIT
en outre refuser de demander la signature d'un vote quand l'identité de
session de l'approbateur est le demandeur du ticket (EX-13.2, EX-13.18). Quand
`self_approval` vaut `interdite` et que le demandeur n'a pas d'entrée dans
`separation.identities` (une identité de service, par exemple), la séparation
est vide pour lui : le service le signale à la création du ticket (T1), la
console affiche le bandeau « séparation non vérifiable pour ce demandeur »
(EX-9.4), et la validation en avertit quand le noyau transmet les `launched_by`
configurés (EX-4.14, 12.2).

### 10.2 Fenêtre de contestation

Le niveau N2 de curators-hub est une « fenêtre de contestation » acceptée
par défaut quand elle s'écoule sans objection (« accepted by default when
the window elapses without dispute », `lib/validation.ts` L1-L7 et L291-L305
de noorchain-core, dépôt privé, lu le 2026-10-23) ; une contestation par un
curateur fait passer le signal en revue (L334-L352). L'acceptation par
défaut est exclue ici (EX-3.2) : la fenêtre de CT-3 suit l'atteinte du
seuil d'approbation et ne fait que retarder une approbation déjà signée au
seuil (5.6, EX-5.9).

**EX-10.6** Avec `contest_ms = 0`, il n'y a ni fenêtre ni objection : la
décision suit le décompte dès qu'un seuil est atteint (EX-7.27), et un vote
`refuse` isolé est compté sans bloquer. Les règles qui suivent valent pour
`C = contest_ms > 0`.

**EX-10.7** **Objections.** Une objection est un vote `refuse` accepté
(EX-9.10), donc d'un membre éligible du jeu figé, pendant la collecte
(`ouvert`, `seuil_atteint` ou `verification`), avant ou pendant une fenêtre
(EX-5.9, 2) ; elle est inscrite dans la trace avec son auteur et son
instant. Une objection non levée :

1. annule la fenêtre en cours et suspend la remise : le décompte rend
   `ouvert` tant que l'ensemble `O` des objections non levées n'est pas vide
   (EX-7.27) ;
2. n'est pas un refus : la décision `refuse` exige encore `t` votes `refuse`
   (EX-9.13), et une objection maintenue jusqu'à l'échéance donne `expire`
   (raison `echeance atteinte, objection non levee`, EX-7.11).

Un vote `refuse` accepté est donc toujours une objection quand `C > 0`,
même reçu avant que le seuil soit atteint : un membre qui refuse tôt garde
son opposition, et la fenêtre ne s'ouvre pas tant qu'il ne l'a pas levée
(trace `contestation-refus-anterieur` de l'annexe A.6). Il est aussi compté
dans `r` (EX-7.27), et retire au besoin une approbation de son auteur
(EX-7.26).

**EX-10.8** **Levée.** Une objection n'est levée que par un vote `approuve`
de son auteur (EX-5.9, 4). Ni sa récusation, ni sa sortie du jeu au cours
d'un nouveau gel (8.3), ni un changement de politique ne la lèvent : une
objection ne peut être écartée que par celui qui l'a faite, et à défaut le
ticket expire. Quand `O` redevient vide et que `a ≥ t`, une **nouvelle**
fenêtre complète s'ouvre (EX-7.27).

**EX-10.9** La fenêtre ne peut pas finir après l'échéance : un ticket encore
en `seuil_atteint` à l'échéance expire (T9, raison `echeance atteinte
pendant la fenetre de contestation`), puisque l'échéance passe avant la fin
de fenêtre au même instant (EX-7.7). Comme `contest_ms < E` (EX-5.10), une
approbation n'aboutit que si le seuil est atteint au moins `C` avant
l'échéance ; la console affiche cette limite (EX-9.4).

Justification. Google Cloud PAM fait d'un seul refus la fin d'une demande
(« If any approver denies the grant, then the grant moves to the denied
state », R3-F87, https://cloud.google.com/iam/docs/pam-approve-deny-grants) et
Azure Pipelines fait échouer l'étape sur une seule décision négative finale
(R3-F112,
https://learn.microsoft.com/en-us/azure/devops/pipelines/process/approvals?view=azure-devops) :
la fenêtre donne ce poids à une objection, pendant un temps borné, sans
créer de valeur de décision nouvelle. Elle ne change pas le seuil du
contrat et n'autorise rien par défaut. Ce n'est pas le droit de contester
une décision automatisée que le RGPD et la LPD donnent aux personnes
concernées, qui s'exerce après la décision (5.6).

### 10.3 Réglages

**EX-10.10** Les réglages qui déterminent une décision sont dans l'ensemble
de politique, donc hachés dans `policy_sha256` et annoncés dans la chaîne
avant usage (CT-2 EX-9.1, EX-10.21) ; les autres sont dans la configuration
du service ou de la console :

| Réglage | Où | Effet |
|---|---|---|
| `contest_ms` de chaque règle et de la règle par défaut | politique d'approbation (4.2) | fenêtre de contestation (10.2) |
| `separation.self_approval`, `separation.identities` | politique d'approbation (4.2) | séparation des tâches (10.1) |
| `approver_set` | politique d'approbation (4.2) | source du jeu (section 8) |
| `expire_after_ms`, `timeout_ms`, `mode`, `hold_timeout_ms` | `/policy/approval` (CT-2 §15.1) | délais (7.6), mode d'attente (section 11) |
| `escalation` : étapes `{ "after_ms", "notify" }`, `after_ms` strictement croissants et inférieurs à `E`, `notify` ∈ {`jeu`, `administrateur`, `demandeur`} | configuration du service | escalade (EX-7.13) |
| `max_open_tickets` : entier de 1 à 10 000, défaut 20 | configuration du service | plafond de tickets non décidés par `launched_by` (14.6) ; un `launched_by` par personne (`${oauth_subject}`, `${peer_user}`, CT-2) évite qu'un demandeur fixe partagé ne le consomme pour tous |
| `administrators` : identités de session des administrateurs de l'annuaire | configuration du service, recopiée dans l'annuaire | retrait d'un ticket (EX-7.15, EX-12.19), méthodes d'administration de l'annuaire (EX-13.17), lecture de toute vue (EX-12.14) |
| `set_poll_interval_ms` : défaut 10 000 | configuration du service | lecture et surveillance du jeu (8.2, 8.3) |
| point RPC de la chaîne du registre | configuration du service | lecture du jeu (EX-8.1) |
| contacts : administrateur de l'organisation ; canal de notification de chaque approbateur, désigné par l'identifiant de son entrée d'annuaire | configuration de la console (13.2) | notification, escalade (7.7) |
| annuaire des approbateurs : identités de session, adresses attribuées, alias de demandeur | état du service, document `annuaire-approbateurs-v0` (13.4), modifié seulement par les méthodes de 12.9 | identité de session et adresse attribuée (EX-13.2, EX-13.18), adresses connues pour la lecture du jeu (EX-8.1, pas 5) |
| `console_origin` : origine HTTPS de la console | configuration du service, recopiée dans l'annuaire | message d'inscription (EX-13.12, EX-13.14) |
| `registration_ttl_ms` : de 60 000 à 3 600 000, défaut 600 000 (choix de CT-3, sans source externe) | configuration du service, recopiée dans l'annuaire | validité d'un message d'inscription (EX-13.13) |
| `reauth_max_age_s` : de 0 à 3 600, défaut 900 (choix de CT-3, EX-13.8) | configuration du serveur de console | réauthentification avant chaque méthode de la liste d'EX-13.8 |
| `service_timeout_ms` : défaut 10 000 ; bornes non fixées par CT-3 (choix de CT-3, sans source externe) | configuration de la console | attente d'une réponse du service à une méthode du canal ; au-delà, « service indisponible » (12.7, 13.14) |
| `delai_signature_ms` : de 30 000 à 1 800 000, défaut 300 000 (choix de CT-3, sans source externe) | configuration de la console | attente de la réponse du portefeuille, jamais au-delà de l'échéance du ticket (EX-13.30) |

**EX-10.11** Un réglage de configuration NE DOIT changer ni le jeu, ni le
seuil, ni l'échéance, ni les éligibles, ni le décompte d'un ticket : il ne
règle que le moment des notifications, le rythme des lectures et le plafond
de 14.6. Ses changements sont inscrits dans le journal du service, pas dans
la chaîne.

### 10.4 Ce qui est journalisé

| Où | Ce qui y est | Valeur probante |
|---|---|---|
| Chaîne : événement de politique | l'ensemble de politique, dont `contest_ms`, `separation` et `approver_set`, par son empreinte `policy_sha256` | signé par l'enregistreur ; contenu prouvable avec la pièce de politique (CT-2 EX-8.11) |
| Chaîne : événement `retenue` | outil, pièce « arguments » rédigée, délégation (dont `launched_by`), `policy.rule`, `policy.ticket`, `intent`, `ts` | signé par l'enregistreur, prouvable par dossier |
| Chaîne : décision | `approval` : décision, `request_hash`, `threshold`, `approvers`, `signatures`, `at`, `reason` ; délégation du demandeur (comme seq 3 de CT-1 annexe A et seq 6 des vecteurs CT-2) | signatures des approbateurs (E-9), le reste attesté par l'enregistreur |
| Chaîne : appel relayé ou `refusee` | l'`approval` scellé, la `policy` de la demande (EX-7.18 ; CT-2 EX-7.12) | idem |
| Dossier : `approbations.json` | `approver_set` (`threshold`, `members`, `source`) | déclaratif (CT-6 EX-3.6) |
| Journal d'exploitation de l'enregistreur | `approval_pending`, `approval_deferred`, `approval_expired_deferred`, refus de remise (`approval_remise_refused`), refus de relais (`approval_relay_refused`) | aucune (CT-2 §9.2, §17.3) |
| Trace du ticket (`ticket-v0`, service) | votes acceptés, refusés et remplacés avec leur raison et leur instant, objections et levées, fenêtres de contestation ouvertes et annulées, récusations, éligibles, lectures du jeu, escalades, retrait, remises et acquittements | interne au client ; non signée en v0 |

### 10.5 Ce que CT-6 vérifie et ce qu'un réviseur peut établir

| Propriété | Ce que le dossier en montre | Vérifiée par CT-6 v0 | Hors CT-6 v0, avec des pièces du client |
|---|---|---|---|
| Au moins `t` adresses distinctes du jeu déclaré ont signé la décision | `approval`, `approbations.json` | oui (E-5, E-9, A-3) | — |
| La décision précède l'appel relayé | `seq` et `approval.at` (A-2) | oui | — |
| Une demande expirée ne porte aucune signature | `approval` (A-3) | oui | — |
| Le jeu déclaré était celui de l'organisation à la décision | `source` (8.4) | non : « déclaré par le dossier » (CT-6 EX-3.6) | relecture du registre (8.5), selon un nœud |
| Le demandeur n'a pas approuvé sa demande | `launched_by` de la demande et `approvers` de la décision | non ; le noyau l'a vérifié avant de sceller (SG-7, CT-2 EX-7.5) | oui, avec la pièce de politique (`separation`, authentifiée par `policy_sha256`) : aucune adresse de `approvers` n'est une adresse du demandeur ; cela ne vaut que pour les adresses déclarées (EX-10.5) |
| La séparation pouvait s'appliquer à ce demandeur | `launched_by` de la demande | non | oui, avec la pièce de politique : `separation.identities` a une entrée pour `launched_by` ; sinon la séparation était vide pour lui (EX-10.5) |
| Une personne n'a qu'une voix | adresses distinctes seulement | non | déclaratif seulement, avec l'annuaire exporté du client (EX-13.19) : deux signataires appartiennent à deux entrées distinctes ; cela ne prouve pas deux personnes (EX-13.10, EX-8.11) |
| La fenêtre de contestation a été respectée, aucune objection n'est restée | rien | non | seulement par la trace du ticket, déclarative |
| La décision est arrivée avant l'échéance | `approval.at`, `ts` de la demande si elle est voisine | non | oui, avec `expire_after_ms` de la pièce de politique : `approval.at < ts + E` |
| Le motif est celui des approbateurs | `approval.reason` | non : non signé (CT-1 §5.3) | non |

Un réviseur qui reçoit la trace du ticket du client peut recouper la
fenêtre de contestation et les objections ; il les tient alors du client,
comme `approver_set`. Les rendre vérifiables dans le dossier (champs signés
dans `A`, trace signée) est une proposition pour une version 1
(section 16).

## 11. Comportement du mandataire pendant l'attente

CT-2 fixe deux modes d'attente (`policy.approval.mode`) et laisse à CT-3 le
choix et l'usage (CT-2 §4.4 pas 5 et 6, R1-F34, R1-F35). La version 0.2 de
CT-2 signalait l'attente par le code `-32015` (`noortrace: approbation
requise`, `data: { "ticket", "state" }`, R1-F39) ; sa version 0.3, qui
applique la section 15, la signale par le **signal d'approbation** : un
résultat d'outil `isError: true`, de texte fixe, qui porte le ticket et son
état dans le texte et dans `_meta["noortrace/approval"] = { "ticket",
"state" }`, `state` ∈ {`en_attente`, `refuse`, `expire`} (CT-2 EX-4.49).
Cette section ferme la décision ouverte 4 de l'architecture (section 15) ;
elle ne crée aucun code d'erreur.

### 11.1 Décision : le mode `erreur` par défaut

**EX-11.1** Le mode d'attente par défaut est **`erreur`** : la configuration
de référence, la démonstration et toute configuration produite par les
outils du projet DOIVENT l'employer, et la commande de validation de
l'enregistreur (CT-2 §15.6) DOIT avertir quand `mode` vaut `retenir`.

**EX-11.2** Le mode `retenir` n'est admis que si `hold_timeout_ms` est
inférieur au plus petit délai par appel de **tous** les hôtes raccordés (table
11.2), d'au moins une seconde, et si la décision est attendue dans ce délai.
Il ne change rien au ticket : à `hold_timeout_ms`, l'hôte reçoit le signal
`en_attente` et le ticket continue (EX-7.14).

### 11.2 Justification

**Les délais des hôtes.** Une approbation humaine prend des minutes ou des
heures : les exemples publiés de CT-1 et CT-2 placent la décision de 7 à 20
minutes après la demande, et l'annexe A de CT-2 tient la requête de l'hôte
693 secondes en mode `retenir` (R1-F92 à R1-F95, calcul R1-F93), au-delà de
l'exemple `hold_timeout_ms: 50000` (R1-F53) ; les produits d'approbation
laissent 24 heures aux approbateurs (R3-F78, R3-F88, 7.6). Les délais
par défaut d'un appel d'outil mesurés dans le code ou la documentation
officielle sont :

| Hôte ou SDK | Délai par défaut d'un appel | Effet d'une progression | Fait et source |
|---|---|---|---|
| SDK Agents d'OpenAI 0.24.0 | 5 s (`client_session_timeout_seconds`) | non lu | R2-F41, https://github.com/openai/openai-agents-python/blob/0dc4cf152bff1f50bdc0e41f28808563406545b2/src/agents/mcp/server.py#L1973 |
| SDK MCP TypeScript 1.32.1 | 60 s | aucun, sauf `resetTimeoutOnProgress: true` | R2-F36, paquet npm `@modelcontextprotocol/sdk@1.32.1` |
| Claude Code, serveur HTTP, SSE ou connecteur | 60 s jusqu'au premier octet de la réponse | sans objet | R2-F30, https://code.claude.com/docs/en/mcp.md |
| Claude Desktop (déploiements « 3P »), serveur local ajouté par l'utilisateur | 60 s | non documenté | R2-F34, https://claude.com/docs/third-party/claude-desktop/configuration.md |
| Claude Desktop (déploiements « 3P »), sessions Cowork et chat | 180 s | non documenté | R2-F34 |
| claude.ai et Claude Desktop, connecteur distant | 240 s | non documenté | R2-F35, https://claude.com/docs/connectors/building.md |
| Claude Code, inactivité HTTP / stdio | 5 min / 30 min | remet l'inactivité à zéro | R2-F31, https://code.claude.com/docs/en/mcp.md |
| Claude Code, limite d'horloge (`MCP_TOOL_TIMEOUT`) | environ 28 h | ne la prolonge pas | R2-F30, https://code.claude.com/docs/en/env-vars.md |
| SDK MCP Python 2.3.0 et 1.30.0, langchain-mcp-adapters 0.3.2, en stdio | aucun délai de requête par défaut | sans objet | R2-F38, R2-F40, https://files.pythonhosted.org/packages/20/d7/4a2878f128df729db3ca04e71bfce26405cc2e0c9ebe19c592feeb4c61b9/mcp-2.3.0-py3-none-any.whl |
| SDK MCP Python 2.3.0, langchain-mcp-adapters 0.3.2, en HTTP | 300 s en lecture du flux SSE ; 30 s pour les autres opérations HTTP du SDK et pour le transport « streamable HTTP » de langchain-mcp-adapters | non lu dans le code (non vérifié) | R2-F39, R2-F40, https://github.com/langchain-ai/langchain-mcp-adapters/blob/52a4535f3eb4b98f386836e4d9b8c4cadf99afca/langchain_mcp_adapters/sessions.py#L53-L57 |

Les délais de Cursor ne figurent pas dans sa documentation officielle
(R2-F43, https://cursor.com/docs/mcp.md ; R2 NV-1, non vérifié), ni celui des
serveurs locaux de Claude Desktop grand public (R2 NV-2), ni ceux de
LangGraph hors de l'adaptateur (R2 NV-3). Claude Code fait en outre passer en
arrière-plan un appel qui dure plus de deux minutes (R2-F32,
https://code.claude.com/docs/en/mcp.md). Le plus petit délai par défaut est
de 5 secondes, et quatre des dix lignes coupent à 60 secondes ou moins : une
requête retenue jusqu'à la décision échoue chez presque tous ; une réponse
immédiate parvient à tous les hôtes avant leur délai. Elle doit aussi
parvenir au modèle : une erreur de protocole (« returned as standard
JSON-RPC errors », R2-F8, `server/tools.mdx` L742-L747), comme le `-32015`
de CT-2 version 0.2, n'est transmise au modèle qu'en faculté (« Clients
**MAY** provide protocol errors to language models », L784), alors que les
clients DEVRAIENT transmettre une erreur d'exécution `isError: true` (L785,
https://github.com/modelcontextprotocol/modelcontextprotocol/blob/80041ab0a139a8f4fb3adbc99f7ae9113ea59671/docs/specification/2026-07-28/server/tools.mdx#L742-L785) :
c'est pourquoi le signal d'approbation de CT-2 version 0.3 est un résultat
`isError: true` (CT-2 EX-4.49).

**La spécification MCP.** Elle demande à chaque client de fixer un délai à
toute requête et de toujours appliquer un délai maximal, même si une
progression peut remettre l'horloge à zéro, sans en fixer la valeur ; les
valeurs réelles sont celles de la table (R2-F13,
https://github.com/modelcontextprotocol/modelcontextprotocol/blob/80041ab0a139a8f4fb3adbc99f7ae9113ea59671/docs/specification/2026-07-28/basic/patterns/cancellation.mdx) :
retenir une requête pendant des minutes va contre ce que la spécification
attend des clients. La révision courante, `2026-07-28` (R2-F1,
https://modelcontextprotocol.io/specification/latest), est sans état (R2-F2)
et ne reprend plus un flux rompu : le client ré-émet la requête sous un
nouvel identifiant (R2-F5). Dans le cœur, hors MRTR (R2-F7) et hors
extension Tasks (R2-F23), un appel d'outil n'a pas d'état « en attente » :
la réponse est un résultat ou une erreur (R2-F6, R2-F8,
https://github.com/modelcontextprotocol/modelcontextprotocol/blob/80041ab0a139a8f4fb3adbc99f7ae9113ea59671/docs/specification/2026-07-28/server/tools.mdx#L135-L172).

**Les tâches de longue durée.** La révision `2026-07-28` sort les tâches du
cœur et en fait l'extension officielle `io.modelcontextprotocol/tasks`
(R2-F3), SEP-2663 au statut « Final » et schéma `2026-07-28` « Stable »
(R2-F22,
https://github.com/modelcontextprotocol/ext-tasks/blob/b3d28aceaa6d49f5f92258e3d06b61ad6f111e84/README.md#L19-L22),
limitée à `tools/call`, négociée requête par requête (R2-F23,
https://github.com/modelcontextprotocol/ext-tasks/blob/b3d28aceaa6d49f5f92258e3d06b61ad6f111e84/specification/2026-07-28/tasks.md#L61-L63),
avec `ttlMs` et un statut `completed` même pour un résultat `isError: true`
(R2-F24) ; sa documentation cite les approbations humaines comme cas d'usage
(R2-F27). Mais la matrice des extensions, publiée sur le site de MCP et
tenue par la communauté, n'a pas de colonne « Tasks » : aucun hôte n'y
déclare la prise en charge (R2-F28,
https://github.com/modelcontextprotocol/modelcontextprotocol/blob/80041ab0a139a8f4fb3adbc99f7ae9113ea59671/docs/extensions/client-matrix.mdx#L26-L50 ;
R2 NV-4, non vérifié hôte par hôte). CT-2 v0 rend `-31016` pour un résultat
`task` et laisse l'extension hors de sa version (CT-2 §4.4, §21). Les tâches
ne peuvent donc pas être le chemin de la version 0 (11.6). Les tâches
expérimentales du cœur de la révision `2025-11-25` (R2-F21), révision que
parle encore le SDK TypeScript 1.32.1 (R2-F37), restent elles aussi hors de
la version 0 : le frontal n'annonce pas la capacité `tasks` (CT-2 EX-4.8),
et sans elle un client NE DOIT PAS augmenter `tools/call` d'une tâche
(https://github.com/modelcontextprotocol/modelcontextprotocol/blob/80041ab0a139a8f4fb3adbc99f7ae9113ea59671/docs/specification/2025-11-25/basic/utilities/tasks.mdx#L113) ;
leur prise en charge par les hôtes n'a pas été examinée.

**L'élicitation ne prouve pas une approbation.** Le serveur ne doit pas se
fier, sans la vérifier, à une identification de l'utilisateur fournie par le
client (R2-F20) : rien dans une réponse `accept` n'établit qu'un membre du
`CuratorSet` a décidé. Claude Code peut y répondre seul par un crochet
(R2-F33). Le mode « form » ne doit pas servir à demander des informations
sensibles, c'est-à-dire des secrets et des identifiants qui donnent accès ou
autorisent des transactions (R2-F17,
https://github.com/modelcontextprotocol/modelcontextprotocol/blob/80041ab0a139a8f4fb3adbc99f7ae9113ea59671/docs/specification/2026-07-28/client/elicitation.mdx) ;
une approbation NOORTRACE est une signature EIP-191 sur `A` (9.1), que
l'élicitation ne porte pas. Une tâche n'est pas un canal de confiance
supérieur (R2-F26). La personne
devant l'hôte est l'opérateur de l'agent, pas un membre du `CuratorSet`.
L'approbation reste la signature de 9.1, recueillie par la console, hors de
l'hôte MCP.

### 11.3 Comportement observable, mode `erreur`

| Moment | Ce que reçoit l'hôte | Événement de la chaîne | Ticket |
|---|---|---|---|
| Premier appel, sortie `a_approuver` | signal d'approbation, `_meta["noortrace/approval"]: { "ticket": "apr-…", "state": "en_attente" }`, aussitôt | `retenue` | `reserve` puis `ouvert` |
| Ré-émission pendant l'attente | signal `en_attente`, même ticket | aucun (EX-7.19) | inchangé |
| Ré-émission après `approuve` | le résultat du serveur d'outils, comme pour tout appel relayé | appel relayé `executee` portant `approval` et la `policy` de la demande (CT-2 EX-7.12) | `consomme` |
| Ré-émission après `refuse` ou `expire`, dans le délai de reconnaissance | signal, `state: "refuse"` ou `"expire"` | `refusee` portant `approval` et la `policy` de la demande (EX-7.18) | inchangé |
| Ré-émission après le délai de reconnaissance ou après consommation | comme un premier appel | `retenue` d'un nouveau ticket | nouveau |
| Appel refusé par la politique (sans ticket) | résultat `isError: true` (11.5) | `refusee`, `policy.decision = "refuse"` | aucun |

**EX-11.3** En mode `erreur`, l'enregistreur rend le signal `en_attente`
dès que l'événement `retenue` est durable (CT-2 EX-4.19, §4.4 pas 6) ; il ne
retient aucune requête. Le signal est un résultat d'outil : il ne dépend
d'aucun code d'erreur, et un hôte qui transmet au modèle les erreurs
d'exécution, comme la spécification le demande (DEVRAIT), lui en transmet
le texte (EX-11.9).

### 11.4 Comportement observable, mode `retenir`

**EX-11.4** En mode `retenir`, l'enregistreur retient **au plus une**
requête de l'hôte par ticket : la requête qui a créé le ticket, ou, si
elle a pris fin (délai, annulation), la première ré-émission reconnue qui
suit. Toute autre ré-émission reconnue pendant l'attente reçoit aussitôt
le signal `en_attente`, sans événement. Une ré-émission reconnue après le
scellement d'une décision `approuve` dont le noyau relaie la requête
retenue reçoit aussi `en_attente` : le noyau l'a annoncé au service par
`held` (EX-11.5, T11), et le service ne sert l'approbation qu'une fois
(EX-7.17).

**EX-11.5** Quand la décision du ticket est scellée pendant qu'une requête est
retenue : `approuve` → le noyau acquitte le scellement avec `held: true`
(12.5), ce qui marque l'approbation servie, puis l'appel est relayé (CT-2 §4.4,
pas 7 et suivants, sans nouvelle évaluation, CT-2 EX-15.5) et le noyau envoie
`consommer` ; `refuse` ou `expire` → l'enregistreur scelle un événement
`refusee` qui reprend la `policy` de la demande et porte `approval`, et rend le
signal d'approbation de même `state` (CT-2 EX-4.50). La réponse finale à une
demande soumise à approbation est ainsi, dans les deux modes, un événement qui
porte `approval` : `executee` ou `refusee`.

**EX-11.6** Pendant la rétention, l'enregistreur PEUT envoyer à l'hôte des
`notifications/progress` si la requête porte un `progressToken` (R2-F14,
https://github.com/modelcontextprotocol/modelcontextprotocol/blob/80041ab0a139a8f4fb3adbc99f7ae9113ea59671/docs/specification/2026-07-28/basic/patterns/progress.mdx) ;
cela remet à zéro le délai d'inactivité de Claude Code (R2-F31) mais pas le
délai de 60 secondes du SDK TypeScript par défaut (R2-F36), ni une limite
d'horloge. Ce n'est pas une raison de choisir `retenir` (EX-11.2) ; CT-2
l'admet, à valeurs strictement croissantes et hors chaîne (CT-2 EX-4.50).

### 11.5 Ce que l'agent lit

**EX-11.7** Le signal d'approbation (CT-2 EX-4.49) est rendu pour toute
réponse `a_approuver` ou `refuse` qui porte un ticket (une réponse `autorise`
d'un ticket `approuve` est relayée) ; c'est un résultat d'outil
`isError: true` dont le texte fixe porte le ticket et l'état
(`noortrace: appel soumis a approbation ; ticket=<ticket> ; state=<state>`)
et dont `_meta["noortrace/approval"]` est exactement `{ "ticket", "state" }`,
avec :

| `state` | Quand |
|---|---|
| `en_attente` | ticket `reserve`, `ouvert`, `seuil_atteint`, `verification` ou `a_remettre` ; ou fin de la rétention en mode `retenir` |
| `refuse` | décision `refuse` scellée |
| `expire` | décision `expire` scellée |

Le texte n'est lu par l'agent que si l'hôte lui transmet le résultat, ce
que la spécification demande (DEVRAIT) pour une erreur d'exécution
(EX-11.9) ; `_meta` sert aux programmes de l'hôte.

**EX-11.8** Un appel refusé par la politique sans ticket (sortie `refuse` de
l'évaluation) reçoit un **résultat** d'outil
`isError: true` (CT-2 §4.4 pas 5, EX-4.49). Comme tout
résultat que rend le frontal, il porte
`_meta["io.modelcontextprotocol/serverInfo"]`, l'identité de l'enregistreur
de version `code.recorder` (CT-2 EX-4.4, §4.4 pas 14). Pour la version
`0.1.0`, il est exactement, pour un hôte de
l'ère moderne, `{"resultType":"complete","content":[{"type":"text","text":"noortrace: appel refuse par la politique"}],"isError":true,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"noortrace-enregistreur","version":"0.1.0"}}}` ;
pour un hôte de l'ère héritée, le même objet sans `resultType`. La
spécification MCP range les erreurs d'exécution dans le résultat, pour que le
modèle puisse se corriger (R2-F8,
https://github.com/modelcontextprotocol/modelcontextprotocol/blob/80041ab0a139a8f4fb3adbc99f7ae9113ea59671/docs/specification/2026-07-28/server/tools.mdx).
Le texte est fixe : il ne nomme pas la règle, pour ne pas apprendre à l'agent
quel seuil contourner (14.1).

**EX-11.9** Les fichiers d'intégration des hôtes (CT-2 §19.5) DEVRAIENT
donner à l'agent la conduite suivante, que rien ne peut lui imposer : après
le signal `en_attente`, dire à l'utilisateur que l'appel attend une
approbation et ne pas le répéter plus d'une fois par minute ; après `refuse`
ou `expire`, ne pas le répéter ; après le refus par la politique sans ticket
(EX-11.8), ne pas répéter l'appel, ne pas le fractionner ni le reformuler
(autre écriture d'un montant, d'une devise ou d'un identifiant), et dire à
l'utilisateur que la politique l'a refusé. Un résultat `isError` se
présente au modèle comme une erreur d'exécution qu'il peut corriger en
changeant ses arguments : sans cette conduite, il ferait de lui-même le
sondage et le fractionnement de 14.1 et 14.5. Le texte d'EX-11.8 reste fixe
et ne nomme pas la règle. Le signal est une erreur d'exécution, que
les clients DEVRAIENT transmettre au modèle (« **SHOULD** », R2-F8,
`server/tools.mdx` L785) ; que chaque hôte le fasse n'a pas été vérifié
(non vérifié, à tester en phase 2 avec les intégrations de CT-2 §19.5).
Le signal ne dépend d'aucun code d'erreur : la révision `2026-07-28` range
`-32000` à `-32019` dans une plage héritée, dont le récepteur NE DOIT
supposer aucun sens (sauf `-32002`, R2-F10), et c'est pourquoi CT-2
version 0.3 a retiré le code `-32015` de sa version 0.2 (15.2).

### 11.6 Tâches MCP et MRTR : hors de la version 0

**EX-11.10** La version 0 de l'enregistreur NE DOIT PAS répondre à un appel
soumis à approbation par un `CreateTaskResult` ni par un
`InputRequiredResult`. Proposition pour une révision de CT-2 et CT-3, quand
un hôte déclarera l'extension : si la requête déclare
`io.modelcontextprotocol/tasks` (R2-F23), rendre, une fois l'événement
`retenue` durable (« durably created », R2-F25), une tâche `working` de
`ttlMs` égal au temps restant jusqu'à l'échéance ; `approuve` → relais et
`completed` avec le résultat ; `refuse` ou `expire` → `completed` avec
`isError: true`, jamais `failed`, réservé aux erreurs JSON-RPC (R2-F24) ;
`tasks/cancel` annule la tâche, pas le ticket. Une élicitation en mode
« url » (R2-F17, R2-F19) pourrait conduire l'opérateur à la console ; elle
n'y vaudrait pas approbation (11.2), et son `requestState` ne garantit pas
l'usage unique, qu'assure la consommation du ticket ; pour une continuation
MRTR d'un résultat `input_required` venu du serveur d'outils, c'est le noyau
qui l'impose, en inscrivant et en consommant chaque `requestState` hérité
(CT-2 EX-4.21) (R2-F16,
https://github.com/modelcontextprotocol/modelcontextprotocol/blob/80041ab0a139a8f4fb3adbc99f7ae9113ea59671/docs/specification/2026-07-28/basic/patterns/mrtr.mdx#L231-L243).

## 12. Interface du service d'approbation

Le noyau de l'enregistreur est toujours le client : la surface d'écoute de
l'enregistreur est exhaustive et ne comprend pas de point d'entrée pour le
service (CT-2 EX-18.1), tandis que sa surface sortante comprend le service
d'approbation (CT-2 EX-18.2, R1-F56). Les décisions remontent donc par une
attente longue que le noyau ouvre (12.5).

### 12.1 Transport et authentification

**EX-12.1** Les messages sont des requêtes HTTP/1.1 `POST <base>/v0/<méthode>`
dont le corps et la réponse sont un objet JSON en UTF-8 (`Content-Type:
application/json`), analysé en JSON strict comme CT-2 §4.4 pas 1 l'exige
(clés uniques, aucun substitut isolé). `<base>` est
`policy.approval.service.url`, ou, quand `url` est nul, la prise Unix
`policy.approval.service.socket` avec la base `http://localhost` (CT-2
§15.1). Les clés JSON sont en anglais ; les valeurs énumérées en français,
sans accent. Toute clé inconnue dans une requête est une erreur
(`requete_invalide`).

**EX-12.2** L'authentification est celle de CT-2 EX-18.8 : sur la prise Unix,
identifiant d'utilisateur du pair égal à `peer_user` et répertoire de prise
non inscriptible par les hôtes ni par les agents ; en HTTP, mTLS ou jeton
porteur (`token`, référence de secret) en en-tête `Authorization: Bearer`,
et TLS hors de la boucle locale. Le service authentifie le noyau de la même
manière (identité du pair ou certificat client, ou un jeton distinct par
sens). Les décisions `autorise` et `refuse` ne sont pas signées : sans ce
canal authentifié, quiconque répondrait à la place du service ferait
relayer ou refuser n'importe quel appel.

**EX-12.3** Le service NE DOIT PAS recevoir la clé du journal ni écrire
d'événement (CT-2 EX-7.4) ; il ne joint que le noyau, le RPC du registre, la
console et les canaux de notification.

**EX-12.4** La console est cliente du service pour les entrées `voter`,
`recuser` et `retirer` de 7.4, et pour les autres méthodes du canal de la
console, dont 12.9 donne la liste complète. Ces messages passent par un canal
authentifié comme en EX-12.2 : mTLS, ou jeton porteur distinct de celui du noyau
(référence de secret) ; le service refuse un message d'une identité inconnue.
Chaque message porte l'identité de session de l'approbateur ou du demandeur
(`session_identity`, EX-13.2), que le service inscrit dans la trace du ticket.
L'authentification du canal ne protège pas d'une console compromise, qui détient
des identifiants valides : c'est pourquoi une récusation ne retire jamais un
refus (EX-10.4), et pourquoi une récusation et un retrait signés sont proposés
pour une version 1 (section 16).

### 12.2 `charger` : politique et outils susceptibles d'approbation

Envoyé par le noyau au démarrage et à chaque rechargement de l'ensemble de
politique (CT-2 EX-7.15, §15.4 pas 6), **et** à chaque changement de la liste
agrégée des outils (CT-2 EX-4.15).

Requête (abrégée : « … » marque une valeur omise) :

```json
{
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x3bac546e33b4ed1872f0214f92d6fd5333ffe38df9a281e8a49260d426d11ca1",
  "environment": "production",
  "policy_version": "2026-11-12",
  "policy_sha256": "0x…",
  "approval": { "rules": { "…": "document politique-approbation-v0 (section 4)" }, "mode": "erreur", "hold_timeout_ms": 50000, "expire_after_ms": 3600000, "timeout_ms": 2000 },
  "tools": [
    { "tool_announced": "sap__payments.create", "tool_original": "payments.create", "server_alias": "sap", "class": "ecriture", "effects": [ { "system": "SAP", "action": "ecriture", "object": "/arguments/claim_id", "extract": null, "amount": "/arguments/amount", "currency": "/arguments/currency" } ] }
  ],
  "requesters": [ "poste-cursor", "u.martin@assureur-demo.example" ]
}
```

| Membre | Contenu |
|---|---|
| `org_id`, `journal_id` | le journal de l'enregistreur (hex 32 octets) |
| `environment` | `recorder.environment` de la configuration de l'enregistreur (CT-2 §15.1), `production` ou `developpement` (EX-8.2) |
| `policy_version`, `policy_sha256` | ceux de l'événement `noortrace.journal.politique` qui annonce l'ensemble (CT-2 EX-8.11) |
| `approval` | le membre `/policy/approval` de l'ensemble, **sans** `service` (qui porte des références de secrets) |
| `tools` | la liste agrégée, triée par `tool_announced` ; `effects` est le gabarit d'effets de l'outil (CT-2 EX-7.6) ou `null` |
| `requesters` | les valeurs fixes de `launched_by` des connexions d'hôte de CT-2 (`mcp.hosts`, `sdk.hosts`), triées (unités UTF-16), sans doublon ; les gabarits `${peer_user}` et `${oauth_subject}` n'y figurent pas (CT-2 EX-7.15) ; elles servent au cinquième avertissement d'EX-4.14, que le service écrit dans son journal |

Réponse : `{ "policy_version", "policy_sha256", "approval_candidates": [noms
annoncés, triés] }` ; elle ne porte aucun avertissement.

**EX-12.5** Le service DOIT appliquer à `approval.rules` les vérifications
d'EX-4.2 (schéma `politique-approbation-v0`, règles que le schéma n'exprime
pas, dont celles d'EX-8.2 pour `approver_set`) et rendre
`politique_invalide`, avec toutes les erreurs dans `data.errors` (une seule,
`schema`, pour un document non conforme au schéma), en cas d'échec ; il calcule
`approval_candidates` par `CANDIDATS(P, L)` (EX-4.11), `L` étant les noms de
`tools` dans l'ordre de la liste, triée. Il garde chaque version chargée tant
qu'un appel évalué sous elle peut encore arriver (CT-2 EX-15.5 : les appels en
cours finissent avec l'ancienne) ; un ticket garde la version sous laquelle il a
été créé (EX-7.21). Le noyau consigne `approval_candidates` (CT-2 EX-7.4) ; tant
qu'il ne l'a pas, tout outil est susceptible d'approbation, et un nom absent de
la liste `tools` du dernier `charger` réussi l'est aussi (4.12).

### 12.3 `evaluer`

Requête : exactement l'objet de CT-2 EX-7.4, `{ "tool_announced",
"tool_original", "server_alias", "arguments", "class", "delegation",
"intent", "code", "context" }` ; `code.policy_version` désigne la version
chargée à appliquer.

Réponse :

| Membre | Type | Contenu |
|---|---|---|
| `rule` | chaîne ≤ 1 024 ou `null` | `policy.rule` (CT-1 §5.3) : celle de l'évaluation (section 6), ou celle de l'événement `retenue` du ticket (EX-7.16) |
| `decision` | `autorise`, `a_approuver`, `refuse` | sortie pour le noyau (EX-7.16) |
| `ticket` | identifiant (EX-7.1) ou `null` | non nul si et seulement si `ticket_state` est non nul |
| `ticket_state` | `nouveau`, `en_attente`, `approuve`, `refuse`, `expire` ou `null` | état du ticket rapproché (EX-7.16) |
| `approval` | objet `approval` de CT-1 §5.3 ou `null` | l'objet **scellé** (avec `at`), clé pour clé, tel que le noyau l'a scellé et rendu au service (`acquitter`, `expiration`), quand `ticket_state` vaut `approuve`, `refuse` ou `expire` ; `null` sinon |
| `approver_set` | jeu déclaré (`$defs/approver_set` : `threshold`, `members`, `source`) ou `null` | non nul si et seulement si `ticket_state` vaut `nouveau` : le jeu que le ticket déclarerait s'il n'était jamais figé, jeu statique de la politique ou jeu de repli courant (EX-8.3, EX-8.8) ; le noyau le garde pour sceller seul une expiration (EX-12.11) |

**EX-12.6** Les combinaisons admises sont exactement les sept combinaisons
(`decision`, `ticket_state`, `approval`) de la table d'EX-7.16, avec, pour
une décision scellée, `approval.ticket` égal à `ticket` et
`approval.decision` égal à `ticket_state`, et `approver_set` non nul pour
`nouveau` seulement. La réponse a exactement les six membres de la table
ci-dessus, dans un ordre quelconque ; `rule` est non nul pour `a_approuver`
(CT-1 §5.3) ; l'`approver_set` d'une réponse `nouveau` est exploitable :
forme de `$defs/approver_set` (SG-1), `source` d'EX-8.8, membres distincts,
`threshold.size` égal au nombre de membres et `threshold.required` au plus
`size` (la cohérence de SG-6), puisque le noyau peut avoir à en tirer seul
une décision `expire` (EX-12.11). Le noyau traite toute autre réponse comme
invalide, donc comme une indisponibilité du service (CT-2 §14.2) : le mandataire
rend `-31010`, raison `approbation`, jamais un relais ; il la consigne. Une
réponse dont l'`approval` diffère de la décision que le noyau a lui-même scellée
pour ce ticket est aussi invalide (RL-1, CT-2 EX-7.16, EX-7.21). CT-2 version
0.3 reçoit et applique les six membres (CT-2 EX-7.4, EX-7.16) ; `approver_set`
sert au noyau à sceller seul une expiration (EX-12.11).

Le service peut aussi répondre par une erreur (12.8) : `non_pret`
(EX-8.3), `politique_inconnue`, ou `plafond_atteint` quand l'évaluation
rendrait `a_approuver` et que le demandeur a déjà `max_open_tickets` tickets
non décidés (14.6). Après la reprise de `politique_inconnue` (12.8), le
noyau traite toute erreur d'`evaluer` comme une indisponibilité du service,
selon la matrice de CT-2 §14.2 : `-31010`, raison `approbation`, pour toute
écriture et tout outil susceptible d'approbation. `plafond_atteint` ne
survient que pour une sortie `a_approuver`, donc pour un outil susceptible :
l'appel n'est jamais relayé.

**EX-12.7** Le service DOIT répondre dans `timeout_ms` (défaut 2 000, CT-2
EX-7.4) : l'évaluation de la section 6 est en mémoire, le rapprochement aussi,
la réservation est une écriture locale (EX-7.22) ; aucune lecture du
registre n'a lieu pendant `evaluer` (8.2).

### 12.4 `ouvrir`

Envoyé par le noyau après le scellement durable de l'événement `retenue`
(CT-2 §4.4 pas 6, EX-7.18), et de nouveau au redémarrage pour tout `retenue`
sans décision (EX-7.25).

Requête : `{ "ticket", "request_hash", "request_seq", "request_ts",
"request_event", "arguments_piece" }` : identifiant, `hash`, `seq` et `ts`
de l'événement `retenue` ; l'événement lui-même, tel que scellé ; les octets
de la pièce « arguments » rédigée, en base64, ou `null` quand la référence
est en ligne (`value`). Le service garde l'événement et la pièce tant que le
ticket est actif, pour la console (EX-9.6), et les efface avec les
arguments (EX-7.24) ; dans `ticket-v0`, ils sont `request.retained_event` et
`request.arguments_piece`. Les traces de l'annexe A.6 omettent ces deux
membres : le service n'en fait aucun autre usage.

Réponse : `{ "ticket", "state", "deadline" }`, `deadline` = `request_ts + E`
(EX-7.10). Un `ouvrir` répété avec le même `request_hash` est sans effet et
rend l'état courant du ticket (EX-7.20) ; `deadline` est `null` pour un
ticket jamais ouvert que le noyau a expiré seul (T17). Avec un autre
`request_hash` sur un ticket dont la demande est connue, l'erreur
`ticket_deja_ouvert` dont `data.request_hash` donne le premier ; sur un
ticket inconnu, `ticket_inconnu`.

### 12.5 `decisions` et `acquitter` : remise de la décision

**EX-12.8** Le noyau tient en permanence une requête `decisions` ouverte :
`{ "wait_ms": 25000 }` (au plus 25 000) ; le service répond dès qu'une remise
est prête, ou au terme de `wait_ms` avec une liste vide. Le noyau relance
aussitôt. Une requête `decisions` sans réponse au terme de `wait_ms +
timeout_ms` vaut indisponibilité.

Réponse : `{ "remises": [ remise, … ] }`, une remise par ticket au plus,
dans l'ordre de leur calcul. Une remise (`$defs/remise` de `ticket-v0`) :

<!-- schema: ticket/remise -->
```json
{
  "remise_id": "apr-2201/1",
  "ticket": "apr-2201",
  "approval": {
    "decision": "approuve",
    "ticket": "apr-2201",
    "request_hash": "0x22a54600beeb4674976033c5a21740dfe45a1886ff1f69082b5c18141efd122d",
    "threshold": { "required": 2, "size": 3 },
    "approvers": [
      "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
      "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
    ],
    "signatures": [
      "0x6e8fb398cce443d4b4343245ac27679e1e460c1c441c0115a21055ec4f1dba09588f3b13b0cc7a9e0d8e1f20133ea0aac9eee9b88f8626ec3a6deafaddec41cd1b",
      "0x5635ca9bfbe1f348e2d67293766fba0d055c9c5b17ddfe2278f4da25ca772cbd79f82642a21e539a1ee256d1056255899c1e8d90938c3c3aeeb0315a4cd687591b"
    ],
    "reason": "Constat et facture concordants"
  },
  "approver_set": {
    "threshold": { "required": 2, "size": 3 },
    "members": [
      "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
      "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
      "0x90f79bf6eb2c4f870365e785982e1f101e93b906"
    ],
    "source": "CuratorSet c=2124 r=0xff7a89fa58a8ffa1173eb70799d7c184bf4d7fe1 s=0x35312352c0065a3fc46ce14dba05df3fcee9fbc2 h=1200..1214 b=0xbbdda14682d88cba1356b88a3fa30ecf233920d3a15f4caf97dcff023d21fbca"
  }
}
```

C'est la décision du ticket `apr-2201` des vecteurs de CT-1
(`journal-sinistres`, seq 6) : ajouter `at` (`2026-11-05T09:31:47.250Z`) à
`approval` redonne, clé pour clé, l'`approval` de cet événement ; la
`source` est celle du jeu de test de l'annexe A.2 (cas `decisions/valides/`
de l'annexe A.7).

`approval` est l'objet de CT-1 §5.3 **sans** `at`, que l'écrivain pose
(CT-2 EX-7.11, R1-F45). `remise_id` est `<ticket>/<n>`, `n` comptant les
remises du ticket à partir de 1 ; une remise re-présentée garde son
`remise_id`, une décision remplacée (T13) en prend un nouveau.

**EX-12.9** Pour chaque remise, le noyau applique SG-1 à SG-7 (9.4) puis
répond par `acquitter` (CT-2 EX-7.19) :

| `result` | Quand | Membres | Suite côté service |
|---|---|---|---|
| `scelle` | événement de décision durable | `seq`, `hash`, `at` (= `approval.at`), `decision`, `approval` (l'objet scellé, avec `at`), `held` (le noyau tient une requête retenue pour ce ticket et va la relayer, EX-11.5) | T11 |
| `temporaire` | mode dégradé du noyau (CT-2 §14.2, « décision remise pendant un mode dégradé ») | `reason` | T12 : la remise est re-présentée au plus tôt `timeout_ms` plus tard |
| `refuse` | une vérification SG- en échec | `reason` (table 12.8) ; pour `ticket_deja_decide`, `seq`, `hash`, `at`, `decision` et `approval` de la décision scellée, `request_hash` compris | T14 ou T20 (selon `approval.request_hash`), T15 ou T16 |

Requête `acquitter` : `{ "remise_id", "ticket", "result", "reason", "seq",
"hash", "at", "decision", "held", "approval" }`, membres non applicables à
`null`. Réponse : `{ "ticket", "state" }`. L'objet `approval` reçu est la
seule source de l'objet que le service rend ensuite aux ré-émissions
(EX-7.16) : le service le garde tel quel (`sealed.approval`), sans le
reconstruire, même quand il diffère de sa remise (motif rédigé par le noyau,
EX-9.14 ; décision différente, T14). Le noyau, lui, relaie l'objet de sa
propre décision scellée (RL-1, CT-2 EX-7.21).

### 12.6 `consommer` et expiration par le noyau

**EX-12.10** Après le scellement de l'appel relayé qui consomme une
approbation (EX-7.17, EX-11.5), le noyau envoie `consommer` : `{ "ticket",
"seq", "hash" }` ; réponse `{ "ticket", "state": "consomme" }` (T18), ou
`{ "ticket", "state": "clos" }` pour une consommation tardive (T22). Le noyau
tient pour finales ces deux réponses et les erreurs `requete_invalide` et
`ticket_inconnu`, et cesse alors ses essais (CT-2 EX-7.20) ; seul le premier
appel relayé sous l'approbation l'envoie, pas les continuations MRTR qui en
héritent (CT-2 EX-4.21).

**EX-12.11** Si, à l'échéance d'un ticket plus `timeout_ms`, aucune décision
n'est scellée (service muet, `ticket_inconnu`, ou remise `expire` refusée,
T16), le noyau scelle lui-même `expire`, comme CT-2 EX-9.4 le prévoit, avec
la raison `expire par l'enregistreur, service d'approbation sans reponse`,
et l'annonce au service par `expiration` : `{ "ticket", "seq", "hash", "at",
"approval" }` (T17), `approval` étant l'objet scellé, avec `at` et
`request_hash`. L'`approver_set` de cette décision est celui de la dernière
remise reçue pour ce ticket dont le jeu est exploitable (EX-12.6), quelle
que soit sa décision, sinon celui de la réponse `nouveau` de ce ticket
(12.3), que le noyau conserve durablement avec l'événement `retenue` (CT-2
EX-12.23) ; son `threshold` est toujours le `threshold` de cet
`approver_set`, de sorte que la décision vérifie A-3 de CT-1 même quand la
remise reçue a été refusée par SG-1 ou SG-6 ; pour une politique
`statique`, il peut aussi les prendre dans `approval.rules`. EX-8.3
garantit qu'une réponse `nouveau` porte toujours un jeu, et le noyau refuse
une réponse dont le jeu n'est pas exploitable (EX-12.6) : il a donc
toujours de quoi former `approval`.

### 12.7 Délais et indisponibilité

| Message | Délai | Sans réponse |
|---|---|---|
| `charger` | `timeout_ms` | tout outil susceptible d'approbation (CT-2 EX-7.4) ; nouvel essai |
| `evaluer` | `timeout_ms` | service indisponible : bloquant (`-31010`, raison `approbation`) pour toute écriture et tout outil susceptible, passant pour les autres lectures si la configuration le dit (CT-2 §14.2, R1-F52) |
| `ouvrir` | `timeout_ms` | nouvel essai jusqu'à succès ; la requête de l'hôte a déjà sa réponse (mode `erreur`) ou reste retenue |
| `decisions` | `wait_ms + timeout_ms` | nouvel essai ; les décisions attendent dans le service |
| `acquitter`, `consommer`, `expiration` | `timeout_ms` | nouvel essai, idempotent (EX-7.20) |
| `consulter` (console) | `service_timeout_ms` de la configuration de la console (10.3), 10 000 ms par défaut | la console affiche le service indisponible et ne demande aucune signature (13.14) |
| `voter` (console) | idem | la console renvoie le même vote, à l'identique ; `vote_identique` lui dit qu'il était inscrit (EX-12.16) |

**EX-12.12** Le service DEVRAIT exposer `GET <base>/v0/etat` :
`{ "ready": booléen, "set_read_at": horodatage ou null,
"open_tickets": entier }` ;
`ready` est faux tant qu'EX-8.3 n'est pas rempli.

### 12.8 Erreurs et raisons

Une erreur du service est une réponse HTTP 4xx ou 5xx de corps
`{ "error": { "code": "<raison>", "message": "<texte ASCII>",
"data": { … } } }`.
Les raisons de refus d'un vote (EX-9.10), d'une remise (SG-), d'une entrée
de ticket (EX-7.8) et d'une méthode du canal de la console (12.9) sont prises
dans la même liste fermée :

| Raison | Émise par | Sens |
|---|---|---|
| `requete_invalide` | service | corps non conforme (12.1) ; entrée bien formée qu'aucune transition n'admet et pour laquelle la table ne nomme pas de raison propre (EX-7.8) : `ouvrir` dont `request_ts` est postérieur à `at`, `consommer` hors `approuve` et hors T22, `acquitter` `scelle` d'une remise inconnue, `acquitter` ou `expiration` sur un ticket décidé avec d'autres données |
| `non_pret` | service | jeu de l'organisation jamais lu (EX-8.3) |
| `politique_invalide` | service | `approval.rules` refusé par EX-4.2 ou EX-8.2 ; `data.errors` les donne toutes (EX-12.5) |
| `politique_inconnue` | service | `code.policy_version` non chargée ; le noyau renvoie `charger` puis réessaie une fois |
| `ticket_inconnu` | service, noyau | identifiant inconnu |
| `ticket_deja_ouvert` | service | `ouvrir` d'un autre `request_hash` (12.4) |
| `ticket_non_ouvert`, `ticket_clos_aux_votes` | service | vote, récusation ou retrait hors des états admis (EX-9.10, T6, T10) |
| `jeu_non_fige` | service | vote avant le gel (EX-8.4) |
| `signature_invalide` | service, noyau | forme, recouvrement ou canonicité (EX-9.3, SG-5) |
| `hors_jeu`, `approbateur_hors_jeu` | service, noyau | adresse hors du jeu figé, ou hors `members` (SG-6) |
| `auto_approbation` | service, noyau | séparation des tâches (10.1, EX-9.10 ; SG-7) |
| `recuse` | service | récusation (10.1, EX-9.10) |
| `motif_trop_long` | service | motif de plus de 1 024 caractères (EX-9.10) |
| `plafond_atteint` | service | `max_open_tickets` atteint pour ce demandeur (14.6) |
| `vote_identique` | service | vote égal au vote courant, sans effet |
| `retrait_non_autorise` | service | entrée `retirer` dont `by` n'est ni le `launched_by` du ticket ni une identité de `administrators` (EX-7.15) |
| `remise_mal_formee` | noyau | SG-1 |
| `request_hash_different` | noyau | SG-2 |
| `ticket_deja_decide` | noyau | SG-3 |
| `echeance_depassee` | noyau | SG-4 |
| `seuil_non_atteint`, `approbateur_double`, `seuil_different_du_jeu`, `expire_avec_signatures` | noyau | SG-6 |
| `mode_degrade` | noyau | refus temporaire (12.5) |
| `session_non_autorisee` | service | méthode du canal de la console d'une identité de session à qui EX-12.14 ne donne pas accès au ticket, `voter` et `recuser` d'une adresse qui n'est pas l'adresse active de l'entrée active de cette identité (EX-12.16), ou `retirer` par une session qui n'est ni le demandeur ni un administrateur (EX-12.19) |
| `identite_invalide` | service | `session_identity` hors de la forme canonique d'EX-13.7 |
| `non_administrateur` | service | méthode d'administration de l'annuaire par une identité absente de `administrators` |
| `entree_inconnue`, `adresse_inconnue` | service | entrée ou adresse absente de l'annuaire |
| `message_invalide` | service | message d'inscription hors de la forme exacte d'EX-13.12, ou différent du texte du défi |
| `nonce_inconnu`, `nonce_deja_utilise` | service | nonce d'inscription jamais tiré, remplacé, ou déjà présenté (EX-13.13) |
| `inscription_expiree` | service | réception hors de `[Emis le, Expire le)` |
| `origine_differente`, `organisation_differente`, `identite_differente`, `adresse_differente` | service | champ du message différent de la configuration, de la session ou de l'adresse de la requête (EX-13.15) |
| `identite_desactivee` | service | entrée désactivée (EX-13.17) |
| `adresse_deja_attribuee` | service | adresse déjà présente dans l'annuaire, dans n'importe quel état (EX-13.10) |
| `etat_incompatible` | service | opération impossible dans l'état de l'adresse ou de l'entrée |
| `auto_validation` | service | validation par la personne de l'entrée (EX-13.17) |
| `revocation_non_autorisee` | service | révocation par une autre identité que la personne de l'entrée ou un administrateur |
| `demandeur_deja_lie`, `demandeur_inconnu` | service | alias de demandeur déjà lié à une entrée, ou absent de l'entrée |

Les raisons de la table à partir de `session_non_autorisee` sont celles du canal
de la console et de l'annuaire (12.9, 13.3 à 13.6), ajoutées par la version
0.3 ; elles ne refusent jamais une entrée de la machine à états de 7.4, qui ne
les voit pas. La raison `signature_invalide` vaut aussi pour la signature d'un
message d'inscription (EX-13.15), et `adresse_differente` est la raison du
service pour une adresse du message différente de la requête. Les refus que la
console oppose elle-même avant une signature (`identite_inconnue`,
`identite_desactivee`, `adresse_non_attribuee`, `session_du_demandeur`,
`jeu_non_fige`, `hors_jeu`, `empreinte_divergente`, …) sont ceux de
`$defs/code_console` de `console-approbation-v0` (9.6, 13.7, 13.14) ; ceux qui
portent le nom d'une raison du service en ont le sens.

### 12.9 Canal de la console

La console est cliente du service (EX-12.4) : sa page parle à son serveur de
console, qui authentifie la personne (EX-13.8) et relaie chaque méthode au
service sur le canal authentifié de la console (mTLS, ou jeton porteur
distinct de celui du noyau). Les méthodes suivent EX-12.1 : `POST
<base>/v0/<méthode>`, corps et réponse en JSON strict, clé inconnue refusée
(`requete_invalide`), erreurs de 12.8. Le corps de chaque méthode relayée
au service porte, dans son membre `session_identity`, l'identité de la
session que le serveur de console a authentifiée, sous la forme canonique
d'EX-13.7 ; le service refuse une valeur hors de cette forme
(`identite_invalide`, EX-12.13). La méthode `session` fait exception : sa
requête est l'objet vide (`$defs/requete_session`), qui ne porte aucune
identité ; elle est servie par le serveur de console lui-même, sans être
relayée au service, et sa réponse (`$defs/reponse_session`) rend l'identité
de la session authentifiée (EX-13.33, point 3). Les corps de `consulter` et
de `voter` sont décrits par `spec/schemas/console-approbation-v0.schema.json` (`$id`
`https://noortrace.example/schemas/v0/console-approbation.schema.json`), ceux
des autres méthodes par `spec/schemas/console-service-v0.schema.json` (`$id`
`https://noortrace.example/schemas/v0/console-service.schema.json`), où une
erreur a la forme de `$defs/erreur`.

**EX-12.13** Le service DOIT accepter sur le canal de la console, et sur
lui seul, les méthodes suivantes, et les refuser (`requete_invalide`) sur le
canal du noyau ; il DOIT refuser sur le canal de la console les méthodes du
noyau (12.2 à 12.6). Sur ce canal, `session_identity` n'est jamais nulle ;
une valeur hors de la forme canonique d'EX-13.7 est refusée
(`identite_invalide`) après la forme du corps et avant toute autre
vérification ; le service la garde telle quelle dans la trace du ticket
(`session_identity` de `$defs/vote` de `ticket-v0`, inchangé).

| Méthode | Requête (`$defs`) | Réponse acceptée (`$defs`) | Effet |
|---|---|---|---|
| `tickets` | `requete_tickets` | `reponse_tickets` | aucun ; tickets non décidés de l'organisation que la session peut voir (EX-12.14), avec leur échéance et leurs votes (EX-13.3) |
| `consulter` | `requete_consulter` | `vue_ticket` | aucun ; vue du ticket (EX-12.14) |
| `voter` | `requete_voter` | `reponse_voter` | entrée `voter` de 7.4 (EX-12.16) |
| `recuser` | `requete_recuser` | `reponse_etat` | entrée `recuser` de 7.4, données identiques, à l'instant de réception |
| `retirer` | `requete_retirer` | `reponse_etat` | entrée `retirer` de 7.4, données identiques, `session_identity` obligatoire (EX-12.19) |
| `annuaire` | `requete_annuaire` | `reponse_annuaire` | aucun (EX-12.17) |
| `preparer_inscription` | `requete_preparer_inscription` | `reponse_preparer_inscription` | défi d'inscription (EX-13.13) |
| `inscrire` | `requete_inscrire` | `reponse_adresse` | inscription (EX-13.15) |
| `valider`, `revoquer` | `requete_valider`, `requete_revoquer` | `reponse_adresse` | EX-13.17 |
| `desactiver`, `reactiver` | `requete_entree` | `reponse_entree` | EX-13.17 |
| `lier_demandeur`, `delier_demandeur` | `requete_demandeur` | `reponse_entree` | EX-13.17 |

Les corps de `voter`, `recuser` et `retirer` sont exactement les données des
entrées de 7.4 (`$defs/entree` de `ticket-v0`), `session_identity`,
facultatif dans l'entrée `retirer` d'une trace, étant obligatoire sur ce
canal (EX-12.19) : la machine à états, ses gardes et l'ordre des raisons
d'EX-9.10 ne changent pas, et la réponse à une entrée refusée est l'erreur de
12.8 qui porte la raison. Le contrôle de l'identité de session (EX-12.14,
EX-12.16, EX-12.19) est fait sur le canal, avant que
l'entrée ne soit formée : une méthode qu'il refuse ne crée aucune entrée et
n'apparaît pas dans la trace du ticket.

**EX-12.14** **`consulter`.** Requête `{ "ticket", "session_identity" }`.
Le service rend la vue du ticket (`$defs/vue_ticket`), qui porte les
arguments en clair, à une identité de session de l'organisation dont
l'entrée de l'annuaire est active et a pour adresse active un membre
éligible du jeu figé du ticket (`eligible`, 10.1 ; avant le gel, un membre
du jeu de repli, EX-8.3), ou qui est dans `administrators` (10.3), et à
aucune autre (`session_non_autorisee`), comme EX-13.2 le veut. La méthode
`tickets`, qui ne porte pas les arguments, liste ces mêmes tickets, et en
outre, pour une session dont l'entrée porte dans `requester_identities` le
`launched_by` d'un ticket, ce ticket, que le demandeur peut retirer
(EX-7.15). Une **session de l'organisation** est une identité de
`administrators`, ou une identité dont l'annuaire a une entrée active. Après
la forme du corps et l'identité (`requete_invalide`, `identite_invalide`,
EX-12.13), le service refuse `consulter` dans cet ordre, et rend la première
raison qui s'applique :

1. la session n'est pas une session de l'organisation :
   `session_non_autorisee` ;
2. le ticket est inconnu dans l'organisation : `ticket_inconnu` ;
3. le ticket est connu et la session ne peut pas en voir les arguments
   (ni administrateur, ni adresse active membre éligible ci-dessus) :
   `session_non_autorisee`.

Puis `ticket_non_ouvert` pour un ticket `reserve`, qui n'a pas encore
d'événement `retenue`. `tickets` applique le point 1 seul : une session de
l'organisation reçoit la liste, vide s'il le faut. Une session hors de
l'organisation n'apprend donc pas si un ticket existe ; une session de
l'organisation apprend seulement si un identifiant de ticket est connu,
sans en voir les arguments. Les cas sont dans
`annuaire/controles-canal.json` (A.10 ; `controleCanal` d'EX-13.32). La vue
porte :

- `request` : l'outil, les arguments en clair, l'intention, la délégation et
  la version de politique de la requête `evaluer` du ticket (CT-2 EX-7.4),
  que le service garde tant que le ticket est actif (EX-7.24) ;
- `request_hash`, `retained_event`, `arguments_piece` : exactement ce que le
  noyau a remis par `ouvrir` (12.4), sans réécriture ;
- `rule` (chaîne `policy.rule`, nom, description, niveau et `contest_ms` de
  la règle retenue) et, pour un ticket ouvrant, `opening` (EX-5.4) ;
- `effects` : le gabarit d'effets de l'outil (CT-2 EX-7.6) évalué sur les
  arguments, déclaratif et non lié à la signature ; chaque effet
  (`$defs/effet_vue`) a les cinq membres de l'effet de CT-1 et un membre
  `unresolved`, propre à la vue, qui liste chaque membre (`object`,
  `amount` ou `currency`) dont le pointeur désigne le résultat
  (`/result/…`) et ne peut donc pas être résolu avant l'exécution, avec ce
  pointeur ; la valeur d'un tel membre est `null` dans la vue, et la
  console l'affiche « connu après exécution » (EX-9.4). Un effet dont un
  pointeur vers les arguments ne se résout pas est omis, comme CT-2 EX-7.6
  le veut ; `$defs/effect` de CT-1 ne change pas, et l'événement scellé
  après l'exécution porte l'effet résolu, ou l'omet ;
- `deadline` (`request_ts + E`), `contest` (fin de la fenêtre de
  contestation en cours, objections non levées, dernier instant où le seuil
  doit être atteint, EX-10.9), `approver_set` (jeu figé, `null` avant le
  gel), `effective_required` (EX-8.6), `added_members` (membres ajoutés par
  un nouveau gel), `eligible` (10.1), `votes` (votes courants, sans
  signature, avec leur motif et leur instant) ;
- `separation` : `self_approval` de la politique du ticket, présence d'une
  entrée pour le demandeur et ses adresses (EX-10.1) ;
- `digests` : les `D_A` que le service calcule lui-même, pour `approuve` et
  pour `refuse`, depuis le `request_hash` du ticket. La console ne les fait
  jamais signer : elle les compare aux siens (EX-9.17).

Une vue n'est valable qu'au moment où elle est rendue : la console la
redemande après le choix de la décision et de l'adresse (EX-9.15).

**EX-12.15** La vue porte aussi, dans `separation`, le membre
`requester_directory_addresses` : les adresses actives que l'annuaire
attribue aux entrées dont `requester_identities` contient le `launched_by`
du ticket, triées. La console s'en sert pour l'avertissement
`separation_incomplete` d'EX-13.18, sans lire l'annuaire complet, qu'une
session ordinaire ne reçoit pas (EX-12.17).

Requête :

<!-- schema: console-approbation/requete_consulter -->
```json
{
  "ticket": "apr-2201",
  "session_identity": "oidc https://idp.assureur-demo.example approbateur-1"
}
```

Réponse, pour le ticket `apr-2201` des vecteurs de CT-1 (événement
`retenue` seq 5 et pièce « arguments » de `journal-valide`, tels quels ; la
valeur en clair de `beneficiary_iban`, que la pièce rédige, est choisie pour
l'exemple ; jeu de test 1 de A.2 figé à la hauteur 1200 ; le compte 2 a déjà
voté) :

<!-- schema: console-approbation/vue_ticket -->
```json
{
  "version": 0,
  "ticket": "apr-2201",
  "state": "ouvert",
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
  "request_hash": "0x22a54600beeb4674976033c5a21740dfe45a1886ff1f69082b5c18141efd122d",
  "request": {
    "tool_announced": "sap.payments.create",
    "tool_original": "sap.payments.create",
    "server_alias": "sap",
    "class": "ecriture",
    "arguments": {
      "claim_id": "2026-81044",
      "amount": "12500.00",
      "currency": "CHF",
      "beneficiary_iban": "CH9300762011623852957"
    },
    "intent": "Régler le sinistre 2026-81044 : 12500.00 CHF au bénéficiaire du contrat",
    "delegation": {
      "launched_by": "u.martin@assureur-demo.example",
      "on_behalf_of": "service-sinistres",
      "scope": "sinistres:lecture,paiement,courriel",
      "run_id": "run-2026-11-05-0007"
    },
    "policy_version": "2026-11-01"
  },
  "retained_event": {
    "version": 0,
    "seq": 5,
    "ts": "2026-11-05T09:12:09.904Z",
    "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
    "journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
    "recorder_key_id": "rec-test-01",
    "prev_hash": "0xb7029550addf2b15f8436077d6478d94ba5d5757e56179e8136b0cf91dec19a4",
    "delegation": {
      "launched_by": "u.martin@assureur-demo.example",
      "on_behalf_of": "service-sinistres",
      "scope": "sinistres:lecture,paiement,courriel",
      "run_id": "run-2026-11-05-0007"
    },
    "code": {
      "model": "fournisseur/modele@2026-09",
      "prompt_version": "0xfc944f11dae59f80bd591d538bb06c2a0227ce1badeb56f2a742ecf23774b3bd",
      "policy_version": "2026-11-01",
      "recorder": "0.1.0"
    },
    "intent": "Régler le sinistre 2026-81044 : 12500.00 CHF au bénéficiaire du contrat",
    "policy": {
      "rule": "paiement > 5000 CHF",
      "decision": "a_approuver",
      "ticket": "apr-2201",
      "redaction": "pii-v1"
    },
    "approval": null,
    "execution": {
      "tool": "sap.payments.create",
      "arguments": {
        "sha256": "0xa7f50f8522f252a345e0f06329d571bd525adba3c8e4b88035f11ce40ee1374c",
        "length": 97,
        "redacted": true
      },
      "status": "retenue",
      "result": null,
      "duration_ms": null,
      "is_error": null
    },
    "effects": [],
    "context": [
      {
        "sha256": "0xdfaf2094d6f01f9a1e7e77df796e44ee7a672dffca8d6fb947481d3e7b702bfa",
        "length": 56,
        "redacted": false,
        "kind": "document"
      },
      {
        "sha256": "0x791d7559f460761ffffd26e1ce5e93b35ecf09d2028b427500d33325db374d99",
        "length": 58,
        "redacted": false,
        "kind": "document"
      }
    ],
    "hash": "0x22a54600beeb4674976033c5a21740dfe45a1886ff1f69082b5c18141efd122d",
    "sig": "0x3321fe0f8dac62dc5d9ee0840a52f38c70ab3db23e3fe5cd002064ee124a465b24fb6b8549a244fff4b23186cead7dd95bc4b6eb849e912a0ca98652f5002d05"
  },
  "arguments_piece": "eyJjbGFpbV9pZCI6IjIwMjYtODEwNDQiLCJhbW91bnQiOiIxMjUwMC4wMCIsImN1cnJlbmN5IjoiQ0hGIiwiYmVuZWZpY2lhcnlfaWJhbiI6IltSRURJR0U6aWJhbl0ifQ==",
  "rule": {
    "policy_rule": "paiement > 5000 CHF",
    "name": "paiement > 5000 CHF",
    "description": "Chaque paiement est approuvé au seuil du jeu d'approbateurs.",
    "level": "revue",
    "contest_ms": 0
  },
  "opening": null,
  "effects": [
    {
      "system": "SAP",
      "action": "ecriture",
      "object": "2026-81044",
      "amount": "12500.00",
      "currency": "CHF",
      "unresolved": []
    }
  ],
  "deadline": "2026-11-05T10:12:09.904Z",
  "contest": {
    "window_end": null,
    "objections": [],
    "last_threshold_at": null
  },
  "approver_set": {
    "threshold": {
      "required": 2,
      "size": 3
    },
    "members": [
      "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
      "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
      "0x90f79bf6eb2c4f870365e785982e1f101e93b906"
    ],
    "source": "CuratorSet c=2124 r=0xff7a89fa58a8ffa1173eb70799d7c184bf4d7fe1 s=0x35312352c0065a3fc46ce14dba05df3fcee9fbc2 h=1200..1200 b=0x0d69b52a5fa6dc8b96b79c133fcb3b7368106273ac3c969915238b890ee2e491"
  },
  "effective_required": 2,
  "added_members": [],
  "eligible": [
    "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
    "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
  ],
  "votes": [
    {
      "approver": "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
      "decision": "approuve",
      "reason": null,
      "at": "2026-11-05T09:21:12.000Z"
    }
  ],
  "separation": {
    "self_approval": "interdite",
    "requester_declared": true,
    "requester_addresses": [
      "0x90f79bf6eb2c4f870365e785982e1f101e93b906"
    ],
    "requester_directory_addresses": [
      "0x90f79bf6eb2c4f870365e785982e1f101e93b906"
    ]
  },
  "digests": {
    "approuve": "0xa57cbdad280b5cb2e9f6ee87b85d8bc05e76a5966377e7d58046519464f7df7c",
    "refuse": "0xd2cace7b1eded2643785e99e2f5316ee6cb4fad6ea468426d30d76538ccab300"
  }
}
```

Sur cette vue, pour l'identité de session de l'exemple, qui détient le
compte 1, à l'instant `2026-11-05T09:25:00.000Z`, la décision `approuve` et
le motif « Constat et facture concordants », les treize contrôles
d'EX-9.15 passent : `blocking` est vide, `remaining_ms` vaut 2 829 904, et
l'empreinte affichée est `a57cbdad…64f7df7c` (EX-9.18). `remaining_ms`
(membre du modèle d'affichage) est le temps restant jusqu'à `deadline` à
l'instant du contexte, en millisecondes, nul sans échéance (le « temps
restant » d'EX-9.4) ; ici 10:12:09.904 − 09:25:00.000 = 2 829 904 ms.
Pour le compte 3, adresse du demandeur que la politique déclare, le modèle
donnerait
`auto_approbation` et, pour sa session, `session_du_demandeur` ; avec un
service conforme, cette session reçoit déjà `session_non_autorisee` de
`consulter`, le compte 3 n'étant pas éligible (EX-12.14, EX-9.15).

Les noms d'outil de cette vue sont ceux des vecteurs de CT-1
(`execution.tool` = `sap.payments.create`) ; l'exemple de 12.2 vient d'un
autre déploiement, à alias préfixé (`sap__payments.create`). Dans le
déploiement des vecteurs de CT-1, le serveur `sap` nomme lui-même son outil
`sap.payments.create`, annoncé sans préfixe (`tools.prefix: false`, CT-2
EX-4.10) : `tool_original` et `tool_announced` y sont égaux, comme dans les
vecteurs de CT-2. Dans celui de 12.2, l'alias préfixe le nom d'origine
`payments.create`. Le contrôle 4
d'EX-9.15 compare `request.tool_announced` à l'`execution.tool` de
l'événement du même ticket.

**EX-12.16** **`voter`.** Le corps est exactement les données (`data`) de
l'entrée `voter` de 7.4 (`$defs/entree` de `ticket-v0`) :
`{ "ticket", "approver", "decision", "signature", "reason",
"session_identity" }` ; `kind` et `at` n'y figurent pas, `at` étant
l'instant de réception, et un corps qui porte `kind` est refusé
(`requete_invalide`, EX-12.1) ; la console y met la signature qu'EX-9.21 a
normalisée, et le service, qui admet toute signature de 7.4, la normalise
de toute façon (EX-9.3). Le service vérifie d'abord, sur le canal, que
`approver` est l'adresse active de l'entrée active dont `session_identity`
est l'identité de la requête (EX-13.9) : `session_non_autorisee` sinon. Il
applique ensuite EX-9.10, persiste le vote (EX-7.22) et rend
`{ "ticket", "state" }`, l'état du ticket après le décompte (EX-7.27) ; un
vote refusé reçoit l'erreur de 12.8 dont le code est la raison d'EX-9.10.
Le corps de `recuser` est de même les données de l'entrée `recuser` de 7.4,
`{ "ticket", "approver", "session_identity" }`, sans `kind` ni `at`, et
`recuser` subit le même contrôle d'adresse avant l'entrée. Un vote renvoyé à
l'identique après un délai (12.7) reçoit `vote_identique` : la console
l'affiche comme « vote déjà inscrit ». Un nouveau vote de même décision,
même d'un autre motif, est identique (EX-9.10) et ne change pas le motif :
le motif inscrit reste le premier, et la console l'affiche comme « vote déjà
inscrit ; le motif n'a pas changé ».

Requête (compte 1, ticket `apr-2201`, signature des vecteurs de CT-1) :

<!-- schema: console-approbation/requete_voter -->
```json
{
  "ticket": "apr-2201",
  "approver": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
  "decision": "approuve",
  "signature": "0x6e8fb398cce443d4b4343245ac27679e1e460c1c441c0115a21055ec4f1dba09588f3b13b0cc7a9e0d8e1f20133ea0aac9eee9b88f8626ec3a6deafaddec41cd1b",
  "reason": "Constat et facture concordants",
  "session_identity": "oidc https://idp.assureur-demo.example approbateur-1"
}
```

Réponse : le compte 2 avait déjà voté `approuve`, le seuil effectif est 2 et
`contest_ms` vaut 0 : la décision `approuve` est calculée (EX-7.27).

<!-- schema: console-approbation/reponse_voter -->
```json
{
  "ticket": "apr-2201",
  "state": "verification"
}
```

**EX-12.17** La méthode `annuaire` rend à une identité de
`administrators` l'annuaire complet ; à toute autre session, le même
document réduit à l'entrée dont `session_identity` est celle de la session
(aucune, ou une seule) et aux opérations qui la concernent. Le document
réduit garde tels quels les autres membres de l'annuaire complet :
`version`, `org`, `org_id`, `console_origin`, `registration_ttl_ms`,
`administrators`, `revision` et `updated_at`. `revision` reste le compteur
global : elle change aussi pour une opération sur une autre entrée, ce qui
fait seulement refaire les contrôles (13.9, pas 7). Pour la console,
`revision` n'est qu'un indicateur de changement : une opération sur une autre
entrée ne change du document réduit que `revision` et `updated_at`, et le
contrôle qu'elle fait refaire rend, sur la même vue, le même résultat, sans
autre effet. Un document réduit n'est
pas un export au sens d'EX-13.19, dont il ne satisfait pas en général le
point 2. La requête est `{ "session_identity" }` (`$defs/requete_annuaire`,
13.9, pas 1) ; la réponse est un document `annuaire-approbateurs-v0`
(`$defs/reponse_annuaire` de `console-service-v0`), complet ou réduit, celui
que rend la fonction `annuaireDeSession` de `scripts/lib/console.mjs`.
Les méthodes
qui modifient l'annuaire (`inscrire`, `valider`, `revoquer`, `desactiver`,
`reactiver`, `lier_demandeur`, `delier_demandeur`) DOIVENT être persistées
avec `fsync`, comme une transition de ticket (EX-7.22), avant leur réponse ;
`preparer_inscription` persiste son défi de même. Une opération acceptée
incrémente `revision`, ajoute un élément à `operations` et pose `updated_at`
à son instant ; une opération refusée ne change pas l'annuaire et est
consignée dans le journal du service avec sa raison.

**EX-12.18** Les méthodes de l'annuaire ne changent ni un ticket, ni le
jeu figé, ni le seuil, ni les éligibles d'un ticket, ni le décompte : comme
un réglage de configuration (EX-10.11), l'annuaire n'entre pas dans la
décision. Il ne fait que dire quelle identité de session peut présenter les
votes et les récusations d'une adresse (EX-12.16) : une adresse membre du
jeu qui n'est l'adresse active d'aucune entrée ne peut pas voter, ce qui
retarde ou empêche une décision sans en produire aucune. Le noyau ne connaît
pas l'annuaire : il vérifie une remise par SG-1 à SG-7 seulement.

**EX-12.19** **`retirer` sur le canal.** Le corps est `{ "ticket", "by",
"reason", "session_identity" }` (`$defs/requete_retirer` de
`console-service-v0`) : les données de l'entrée `retirer` de 7.4, avec
`session_identity` obligatoire et non nulle. Pour un ticket connu, après la
forme du corps et l'identité (EX-12.13) et avant de former l'entrée, le
service exige l'une des deux conditions suivantes : `by` est le
`launched_by` du ticket et ce `launched_by` figure dans
`requester_identities` de l'entrée active de l'annuaire dont l'identité est
`session_identity` (le demandeur, EX-7.15) ; ou `by` est égal à
`session_identity` et cette identité figure dans `administrators`. Sinon, il
rend `session_non_autorisee`, et rien n'entre dans la trace du ticket.
L'entrée formée garde `session_identity` (membre facultatif de l'entrée
`retirer` de `ticket-v0`) ; la machine à états applique ensuite T10 et
EX-7.15 (`retrait_non_autorise`, `ticket_non_ouvert`,
`ticket_clos_aux_votes`). Le contrôle de l'identité de session des méthodes
`tickets`, `consulter` (EX-12.14), `voter`, `recuser` (EX-12.16) et
`retirer` est celui de la fonction `controleCanal` de la bibliothèque
(EX-13.32), qui rend d'abord `identite_invalide`, puis les raisons de la
méthode dans l'ordre de sa règle ; ses cas sont dans
`annuaire/controles-canal.json` (A.10). Face à `ticket_inconnu`, l'ordre est
le suivant : pour `tickets` et `consulter`, celui d'EX-12.14
(`session_non_autorisee` d'une session hors de l'organisation, puis
`ticket_inconnu`, puis `session_non_autorisee` d'une session qui ne peut
pas voir les arguments) ; pour `voter` et `recuser`, le contrôle d'adresse
se fait d'abord (EX-12.16) et ne dépend pas du ticket, de sorte que
`session_non_autorisee` passe avant `ticket_inconnu` ; pour `retirer`, le
contrôle ne se fait que pour un ticket connu (ci-dessus), et un ticket
inconnu reçoit `ticket_inconnu`.

## 13. Console d'approbation

La console est l'interface où les approbateurs lisent les demandes et
signent. La console d'exploitation est construite en phase 2 du plan de
projet à partir de curators-hub (architecture, « Ce qui est réutilisé de
noorchain-core ») ; cette section fixe ce qu'elle doit faire : qui est la
personne (13.3), quelles adresses lui sont attribuées et comment (13.4 à
13.8), comment elle signe et ce que la console fait de chaque panne (13.9 à
13.14). Une console de référence (13.15) montre ces exigences en œuvre ;
13.17 et 13.18 les résument pour l'approbateur et pour l'intégrateur.

### 13.1 Ce que curators-hub apporte, et ce qu'il ne faut pas reprendre

| curators-hub (noorchain-core, dépôt privé, R1-F82 à R1-F87, R5-F32 à R5-F38, R5-F45) | Dans la console CT-3 |
|---|---|
| Les clés des curateurs sont gardées par le serveur, qui signe pour eux dans leur session (« custodial pilot posture », R1-F83, R1-F84) | **Exclu.** Un serveur qui signe pour les approbateurs vide le contrôle 7 de son sens (R1-C23) |
| La clé de l'organisation naît dans le navigateur du propriétaire ; seule la signature quitte la page (`OrgOpSigner`, R1-F87) | Repris : c'est le modèle de toute signature d'approbateur |
| Aucun portefeuille de navigateur ; `signMessage` de viem sur des comptes locaux (R1-F82) | Ajouter les portefeuilles par les parcours de 13.9 : extension découverte par EIP-6963 et appelée par EIP-1193 `request` (R2-F50, R4-F1, R4-F5), portefeuille matériel par cette extension, mobile par WalletConnect v2 sur décision de l'organisation, fichier de clé chiffré lu dans la page ; `personal_sign` en octets (EX-9.7) |
| Message texte lisible pour une décision de curateur (`decisionMessage`, R1-F84) | Non repris en v0 : l'objet signé est `A` de CT-1 §6.3 ; piste de version 1 (section 16) |
| Vérification de la signature, puis appartenance par `isCurator` **à la tête** (R1-F84) | Appartenance au **jeu figé** du ticket (section 8), pas à la tête |
| Un vote par curateur, remplacé par le suivant ; récusation (R1-F84, `lib/validation.ts`) | Repris (EX-7.26, EX-10.4) |
| Fenêtre N2 acceptée par défaut à son terme (`sweepExpiredWindows`, `lib/validation.ts` L291-L305) | **Exclu** (10.2) |
| Libellés en deux langues, journal d'audit | Repris |
| Connexion par un identifiant système de 7 chiffres et un mot de passe, session de 8 heures (30 jours pour le propriétaire), aucune réauthentification avant un vote (R5-F32, R5-F33) | Remplacé : la personne est authentifiée par le système d'identité du client, et réauthentifiée depuis au plus `reauth_max_age_s` avant chaque méthode qui modifie l'annuaire ou un ticket (liste d'EX-13.8) |
| La session est liée à la clé par le **nom affiché** (`session.name` → `curatorByName`, R5-F34) | **Exclu** : le lien passe par l'identité de session canonique (paire émetteur et sujet, R5-F8) et l'adresse attribuée par l'annuaire (EX-13.7, EX-13.18) ; un nom affiché n'est jamais un identifiant |
| Paire de clés d'un curateur générée par le serveur (R5-F35) ; adresse de l'organisation inscrite **sans preuve de possession** (R5-F36) | **Exclu** : la clé naît chez l'approbateur (EX-13.1) et une adresse n'est attribuée que sur un message d'inscription signé par elle (EX-13.15) |
| Suppression d'une identité refusée tant qu'elle est membre du jeu (R5-F35) | Repris sous une autre forme : une entrée n'est jamais supprimée ; elle est désactivée, et ses adresses restent dans l'annuaire, révoquées (EX-13.17, EX-13.10) |
| Rapports et instantanés publics : des adresses, jamais des noms (R5-F37) | Repris (EX-13.11) |
| Politique de sécurité du contenu à nonce avec `'strict-dynamic'`, en rapport seul par défaut ; ni Trusted Types ni intégrité des sous-ressources (R5-F45) | Remplacé : politique **bloquante**, sans `'strict-dynamic'`, Trusted Types et intégrité des scripts exigés et mesurés (EX-13.35) |

### 13.2 Exigences

**EX-13.1** La clé d'un approbateur naît chez lui. Ni le serveur de
console ni le service ne la détiennent, ne la reçoivent ou ne la dérivent
jamais, et seule la signature est envoyée au service. La signature se fait
dans le portefeuille de l'approbateur, par les parcours a à c de 13.9
(extension de navigateur, portefeuille matériel par cette extension,
portefeuille mobile). Dans le seul parcours d (fichier de clé chiffré, 13.13,
comme `OrgOpSigner`), la page, dans le navigateur de l'approbateur, lit le
fichier, dérive `DK` et déchiffre la clé le temps d'une signature ; elle ne
l'envoie jamais et efface ses tampons dès la signature faite ou abandonnée
(EX-13.28, points 3 et 8). La page de référence n'offre pas ce parcours
(EX-13.31, point 2 ; EX-13.34, point 1).

**EX-13.2** La console authentifie la personne par le système d'identité du
client, celui qui nomme `delegation.launched_by` (CT-1 §5.3, R3-F123), sous
l'identité de session canonique d'EX-13.7, et ne lui attribue que l'adresse
active de son entrée de l'annuaire des approbateurs (13.4, EX-13.18). Elle
transmet l'identité de session avec chaque action ; le service l'inscrit dans
la trace du ticket (`session_identity`) et s'en sert pour autoriser un
retrait (EX-7.15, EX-12.19) et les méthodes du canal de la console
(EX-12.14, EX-12.16). La console DOIT refuser de demander une signature de vote,
et de soumettre un vote, dont l'adresse n'est pas attribuée à la session, ou
dont l'identité de session est le demandeur du ticket quand `self_approval` vaut
`interdite`, dans l'ordre et avec les raisons d'EX-13.18 (EX-10.5) ; elle NE
DOIT envoyer une récusation que pour une adresse attribuée à la session
(EX-10.4). Les actions passent par le canal authentifié d'EX-12.4. Une session
donne accès aux tickets de l'organisation de la personne, et à rien d'autre ;
les arguments en clair d'un ticket ne sont montrés qu'aux membres éligibles de
son jeu figé (avant le gel, aux membres du jeu de repli, EX-12.14) et aux
administrateurs de l'annuaire (`administrators`, 10.3), comme EX-12.14 le
précise.

**EX-13.3** Notification : à l'ouverture et à chaque escalade (7.7), par les
canaux configurés (courriel, messagerie, appel de webhook), avec le contenu
minimal d'EX-7.12. Le service DEVRAIT aussi notifier à chaque approbateur,
par un canal indépendant de la console, chaque vote inscrit en son nom ;
cette notification porte au moins le ticket, la décision, l'adresse,
`empreinte(D_A)` du vote (EX-9.18) et l'instant de son inscription, et
aucune identité de personne (EX-13.11). C'est ce qui rend visible la bascule
d'un refus en approbation, ou le vote d'un autre ticket, par une console
compromise (9.3) ; ce que fait l'approbateur d'une notification qui diffère
ou qui manque est en EX-9.20, point 7. Le service DEVRAIT, par le même
canal, notifier à la personne chaque opération de l'annuaire qui vise son
entrée (inscription, validation, révocation, désactivation, alias), ce qui
rend visible l'usage d'une session volée (14.8). Elle est recommandée, pas
obligatoire : la console de référence n'en a pas (13.15), et
l'organisation dit à ses approbateurs si elle l'a mise en place et dans
quel délai elle arrive. La console liste les tickets
ouverts avec leur échéance, l'état de la fenêtre de contestation et les
votes exprimés, et, pour un ticket, les tickets refusés ou expirés du même
demandeur et du même outil depuis moins de `E` (une variation cosmétique
des arguments rouvre une demande refusée, EX-7.18, 14.7).

**EX-13.4** Affichage et signature : EX-9.4 à EX-9.9 et EX-9.15 à
EX-9.22. La console DOIT être servie avec une politique de sécurité du
contenu qui interdit les scripts tiers, et avec l'intégrité des
sous-ressources ; EX-13.35 rend ces exigences mesurables (politique
bloquante, intégrité exigée des scripts, Trusted Types, encadrement
interdit). La construction reproductible et la publication de son code
relèvent de CT-7 et CT-8.

**EX-13.5** Actions : voter `approuve` ou `refuse` (motif facultatif, au plus
1 024 caractères, EX-9.10), changer son vote (EX-7.26), objecter pendant la
collecte (un vote `refuse` quand `contest_ms > 0`, avant ou pendant la
fenêtre de contestation, EX-10.7) et lever son objection (un vote
`approuve`, EX-10.8), se récuser (EX-10.4), retirer (demandeur ou
administrateur de l'annuaire, EX-7.15, EX-12.19). Se récuser, c'est déclarer
un conflit d'intérêts pour ce seul ticket : la récusation est définitive,
retire l'approbation courante de son auteur et laisse son refus compté
(EX-10.4), parce qu'une récusation n'est pas signée et qu'une console
compromise pourrait sinon effacer un refus (EX-12.4) : une récusation ne peut
qu'empêcher une approbation, jamais en produire une ni effacer un refus. Il
n'y a pas d'abstention en version 0 : un refus ne se retire qu'en votant
`approuve` (EX-7.26, EX-10.8), et se récuser ne le retire pas (EX-10.4). Qui
ne veut plus s'opposer sans approuver laisse son refus : avec
`contest_ms = 0`, il reste compté, et les autres membres peuvent encore
atteindre le seuil `approuve` (EX-10.6, EX-7.27) ; avec `contest_ms > 0`, il
reste une objection, et le ticket expire à l'échéance faute de levée, sauf si
le seuil de refus est atteint (EX-10.7, point 2). Retirer, c'est annuler la demande : le ticket expire aussitôt
(EX-7.15). Chaque action est transmise au service, qui l'inscrit dans la
trace du ticket avec son résultat ; la console affiche le refus et sa raison
(12.8).

**EX-13.6** La console avertit, avant la signature, que le motif ne doit
contenir aucune donnée personnelle (EX-9.14). Le motif est gardé dans la
trace du ticket par le service ; celui du vote qui complète le seuil devient
le `reason` de la décision scellée dans le journal (EX-9.14), où il ne peut
plus être effacé, et chaque motif peut être celui-là. N'y écrire ni nom, ni
courriel, ni IBAN, ni aucune valeur que la politique de rédaction masque dans
les arguments (le noyau DEVRAIT y appliquer les mêmes détecteurs, EX-9.14).
Exemple admis : « Constat et facture concordants ».

### 13.3 Identité de session et réauthentification

OpenID Connect ne garantit l'unicité et la stabilité que de la paire
émetteur `iss` et sujet `sub` : « the only guaranteed unique identifier for
a given End-User is the combination of the iss Claim and the sub Claim », et
le courriel, le nom et `preferred_username` « MUST NOT be used as unique
identifiers » (OIDC Core 1.0 §5.7, R5-F8). `sub` est une chaîne sensible à
la casse d'au plus 255 caractères ASCII, jamais réattribuée chez son
émetteur (R5-F1) ; `iss` est une URL `https` sans requête ni fragment
(R5-F2).

**EX-13.7** L'**identité de session** est une chaîne canonique, comparée
octet pour octet, de l'une des deux formes :

```text
oidc <iss> <sub>
utilisateur <domaine> <nom>
```

- `oidc` : `<iss>` est la valeur `iss` de l'ID Token, URL `https://…` sans
  `?` ni `#` ; `<sub>` est la valeur `sub`, de 1 à 255 caractères ASCII
  imprimables (U+0021 à U+007E) ;
- `utilisateur` : pour un système d'identité qui n'est pas OIDC, `<domaine>`
  nomme ce système (1 à 128 caractères ASCII imprimables, par exemple son nom
  DNS) et `<nom>` est l'identifiant stable et jamais réattribué de la
  personne dans ce système (1 à 255 caractères ASCII imprimables) ;
- les trois jetons sont séparés par une espace (U+0020) et n'en contiennent
  pas ; la chaîne fait au plus 256 caractères (la borne de `session_identity`
  dans `ticket-v0`). Motif : `$defs/identite_session`
  d'`annuaire-approbateurs-v0`.

Une identité qui ne s'écrit pas ainsi (sujet avec une espace ou un caractère
non ASCII, forme de plus de 256 caractères) n'est pas admise en version 0 :
la console refuse la session pour toute action (`identite_invalide`), et le
service toute méthode qui la porte (12.8). La console fait ce refus à la
réception de la réponse de session (EX-13.33, point 3), avant toute lecture
de ticket : elle n'affiche aucun ticket et n'offre aucune action. Pour une
telle session, elle ne construit aucun modèle d'affichage ; à la place de la
liste des tickets, elle affiche la raison `identite_invalide` de 12.8
(EX-13.29). Ce n'est pas un contrôle d'EX-9.15 : `identite_invalide`
n'entre jamais dans
`blocking` et n'est pas une valeur de `$defs/code_console` ; c'est la raison
du service (12.8, EX-12.13), que la console reprend. Le courriel, le nom affiché et
`preferred_username` ne sont jamais une identité de session. Avec un
fournisseur qui donne un `sub` différent à chaque client (`pairwise`,
R5-F9), l'identité de session de la console et le `launched_by` d'une
connexion d'hôte (CT-2, `${oauth_subject}`) ne se comparent pas : le lien
entre les deux est l'alias de demandeur de l'entrée (`requester_identities`,
13.4), posé par un administrateur (EX-13.17). Que la console et les
connexions d'hôte d'un client utilisent le même client OIDC n'est pas
vérifié (R5 NV-4).

Le jeton d'identité ne borne pas la session : « The ID Token expiration time
is unrelated the lifetime of the authenticated session » (R5-F12). La partie
de confiance juge seule si une réauthentification est nécessaire (NIST
SP 800-63B-4, R5-F15) ; `max_age` oblige le fournisseur à réauthentifier
au-delà du délai et rend `auth_time` obligatoire, `max_age=0` équivaut à
`prompt=login` (R5-F10, R5-F11) ; le client DEVRAIT contrôler `auth_time`
(R5-F12).

**EX-13.8** Avant de relayer l'une des méthodes qui modifient l'annuaire ou
un ticket, c'est-à-dire `voter`, `recuser`, `retirer`,
`preparer_inscription`, `inscrire`, `valider`, `revoquer` (y compris par la
personne de l'entrée), `desactiver`, `reactiver`, `lier_demandeur` et
`delier_demandeur`, le serveur de console DOIT
disposer, pour la session, d'une authentification active dont l'instant
(`auth_time` pour OIDC) date de moins de `reauth_max_age_s` secondes (10.3 ;
défaut 900, de 0 à 3 600 ; 0 exige une authentification pour chaque
action). À défaut, il relance l'authentification avec `max_age` égal à
`reauth_max_age_s` (`prompt=login` pour 0) et vérifie dans l'ID Token
`iss`, `aud`, `nonce` et `auth_time` (R5-F2 à R5-F5, R5-F11) ; un système
`utilisateur` qui ne donne pas l'instant d'authentification exige une
authentification pour chaque action. Il NE DOIT PAS relayer l'action avant
cette vérification. Les méthodes de lecture (`session`, `tickets`,
`consulter`, `annuaire`) n'exigent pas cette réauthentification. Le serveur
de console impose `session_identity` sur chaque méthode qu'il relaie au
service ; `session`, qu'il sert lui-même sans relais, a un corps vide et rend
cette identité (EX-13.33, point 3 ; 13.18). La valeur de 900
secondes est un choix de CT-3, pas une obligation qui s'imposerait à un
client : plus stricte que le délai global de réauthentification de NIST
SP 800-63B-4 au niveau AAL3 (12 heures au plus), elle est égale en valeur à
son délai d'inactivité recommandé (« The inactivity timeout SHOULD be no
more than 15 minutes », R5-F14), qui mesure une autre durée (le temps depuis
la dernière activité, et non depuis la dernière authentification). Les valeurs
`acr` ne sont pas normalisées par OIDC et se conviennent avec le
fournisseur (R5-F6) ; exiger une méthode particulière (`amr`, RFC 8176,
R5-F7) est un réglage du client, dont la prise en charge par chaque
fournisseur n'est pas vérifiée (R5 NV-3). Le serveur de console garde
`auth_time` dans son propre journal ; il n'entre pas dans la trace du
ticket en version 0 (section 16).

### 13.4 Annuaire des approbateurs

Les pratiques d'annuaire normalisées donnent les exigences reprises ici,
sans dépendre d'aucun produit : un identifiant de ressource « stable,
non-reassignable », un identifiant du domaine d'origine gardé à part
(`externalId`), un état administratif `active` (SCIM, RFC 7643, R5-F28) ;
et la tenue, pendant toute la vie d'une identité, du registre de tous les
authentificateurs qui lui sont liés (NIST SP 800-63B-4, R5-F31).

**EX-13.9** Le service tient, pour l'organisation de son journal, un
**annuaire des approbateurs**, document `annuaire-approbateurs-v0`
(`spec/schemas/annuaire-approbateurs-v0.schema.json`, `$id`
`https://noortrace.example/schemas/v0/annuaire-approbateurs.schema.json`,
JSON Schema 2020-12, `additionalProperties: false` à tous les niveaux,
clés sans objet présentes à `null`) :

| Membre | Contenu |
|---|---|
| `version` | `0` |
| `org`, `org_id` | nom court de l'organisation et son `org_id` (CT-1 §3) |
| `console_origin` | origine HTTPS de la console (EX-13.14) |
| `registration_ttl_ms` | validité d'un message d'inscription (10.3) |
| `administrators` | identités de session des administrateurs, copie du réglage de 10.3 : le réglage de configuration du service fait foi ; le service le recopie dans l'annuaire, qui le montre à la console et au réviseur ; chaque recopie d'une nouvelle valeur est une opération de l'annuaire (`changer_administrateurs`, EX-13.37) |
| `revision`, `updated_at` | nombre d'opérations acceptées et instant de la dernière |
| `entries` | une entrée par personne nommée |
| `operations` | opérations acceptées, en ajout seul (EX-13.17, EX-13.37) |

Une **entrée** porte : `id`, identifiant `apb-…` attribué par le service à
sa création (motif `^apb-[0-9a-z]+(-[0-9a-z]+)*$`, de 5 à 128 caractères),
unique et jamais réattribué, même après une perte d'état, aux conditions
d'EX-7.1 (64 bits aléatoires ou époque conservée hors du service ; les
vecteurs, qui partent d'un service sans perte d'état, emploient la
convention de A.10) ; `session_identity`, unique dans l'annuaire ; `external_id`
et `display_name`, facultatifs et sans effet ; `active` ;
`requester_identities`, les valeurs de `delegation.launched_by` qui désignent la
même personne ; `created_at` ; `addresses`, toutes les adresses jamais inscrites
par la personne, chacune avec son état (`en_attente`, `active`, `revoquee`), sa
preuve de possession, et les instants et auteurs de sa validation et de sa
révocation.

Exemple : l'annuaire de l'organisation des vecteurs après neuf opérations.
Les comptes 1 et 2 sont les adresses actives de deux approbateurs ; le
compte 4, inscrit par le second puis refusé par l'administrateur, reste
dans son entrée, révoqué ; le compte 3 est celui de la personne qui lance
l'agent, dont l'alias de demandeur `u.martin@assureur-demo.example` est lié
à son entrée. Chaque preuve est la vraie signature, par la clé de test de
son compte, du message qu'elle porte.

<!-- schema: annuaire-approbateurs -->
```json
{
  "version": 0,
  "org": "assureur-demo",
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "console_origin": "https://console.assureur-demo.example",
  "registration_ttl_ms": 600000,
  "administrators": [
    "oidc https://idp.assureur-demo.example admin-1"
  ],
  "revision": 9,
  "updated_at": "2026-11-10T10:30:00.000Z",
  "entries": [
    {
      "id": "apb-0001",
      "session_identity": "oidc https://idp.assureur-demo.example approbateur-1",
      "external_id": null,
      "display_name": "Approbateur 1",
      "active": true,
      "requester_identities": [],
      "created_at": "2026-11-10T08:00:30.000Z",
      "addresses": [
        {
          "address": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
          "state": "active",
          "proof": {
            "message": "noortrace/inscription/v0\nJe lie cette adresse a mon identite pour approuver dans NOORTRACE. Ce message n'est pas un vote.\nOrigine: https://console.assureur-demo.example\nOrganisation: assureur-demo\nIdentifiant d'organisation: 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab\nIdentite: oidc https://idp.assureur-demo.example approbateur-1\nAdresse: 0x70997970c51812dc3a010c7d01b50e0d17dc79c8\nEmis le: 2026-11-10T08:00:00.000Z\nExpire le: 2026-11-10T08:10:00.000Z\nNonce: dbcddc22164b049171cc7a6cda847ff2",
            "signature": "0x8f799ab2a84552c45d92dbbb89107933a01e8ea1ad2628656cf1acae8a326e2b1e422a677308bd27d4821637bafa04f9338b07b3b19368ec10472caeaa0afbca1c",
            "nonce": "dbcddc22164b049171cc7a6cda847ff2",
            "issued_at": "2026-11-10T08:00:00.000Z",
            "expires_at": "2026-11-10T08:10:00.000Z",
            "received_at": "2026-11-10T08:00:30.000Z"
          },
          "validated_at": "2026-11-10T08:30:00.000Z",
          "validated_by": "oidc https://idp.assureur-demo.example admin-1",
          "revoked_at": null,
          "revoked_by": null,
          "revocation_cause": null,
          "revocation_reason": null,
          "replaced_by": null
        }
      ]
    },
    {
      "id": "apb-0002",
      "session_identity": "oidc https://idp.assureur-demo.example approbateur-2",
      "external_id": null,
      "display_name": "Approbateur 2",
      "active": true,
      "requester_identities": [],
      "created_at": "2026-11-10T09:00:30.000Z",
      "addresses": [
        {
          "address": "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
          "state": "active",
          "proof": {
            "message": "noortrace/inscription/v0\nJe lie cette adresse a mon identite pour approuver dans NOORTRACE. Ce message n'est pas un vote.\nOrigine: https://console.assureur-demo.example\nOrganisation: assureur-demo\nIdentifiant d'organisation: 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab\nIdentite: oidc https://idp.assureur-demo.example approbateur-2\nAdresse: 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc\nEmis le: 2026-11-10T09:00:00.000Z\nExpire le: 2026-11-10T09:10:00.000Z\nNonce: f2bf7c26760882ab2a6c60c4c7312dfe",
            "signature": "0x47e62c0d5b6a19fd3b41c3f6727a69e039442d1d7729378b740677205997629e6f5a4f0356034341f4f1fdf8db01d1b38797e800fea763d1cfb9eeb00e1045be1b",
            "nonce": "f2bf7c26760882ab2a6c60c4c7312dfe",
            "issued_at": "2026-11-10T09:00:00.000Z",
            "expires_at": "2026-11-10T09:10:00.000Z",
            "received_at": "2026-11-10T09:00:30.000Z"
          },
          "validated_at": "2026-11-10T09:40:00.000Z",
          "validated_by": "oidc https://idp.assureur-demo.example admin-1",
          "revoked_at": null,
          "revoked_by": null,
          "revocation_cause": null,
          "revocation_reason": null,
          "replaced_by": null
        },
        {
          "address": "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65",
          "state": "revoquee",
          "proof": {
            "message": "noortrace/inscription/v0\nJe lie cette adresse a mon identite pour approuver dans NOORTRACE. Ce message n'est pas un vote.\nOrigine: https://console.assureur-demo.example\nOrganisation: assureur-demo\nIdentifiant d'organisation: 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab\nIdentite: oidc https://idp.assureur-demo.example approbateur-2\nAdresse: 0x15d34aaf54267db7d7c367839aaf71a00a2c6a65\nEmis le: 2026-11-10T09:20:00.000Z\nExpire le: 2026-11-10T09:30:00.000Z\nNonce: cf6c4169f875e3743b000af22f9519d3",
            "signature": "0xb2e78397cc1a6d31eff37bdeddb3733b183c4c7e56f61ebac3efe6d0df9379ef4de8dc76e0f26cfa518ce4be283fd71b76abac7d391bf5af1223af9bd2b7ed771b",
            "nonce": "cf6c4169f875e3743b000af22f9519d3",
            "issued_at": "2026-11-10T09:20:00.000Z",
            "expires_at": "2026-11-10T09:30:00.000Z",
            "received_at": "2026-11-10T09:20:30.000Z"
          },
          "validated_at": null,
          "validated_by": null,
          "revoked_at": "2026-11-10T09:41:00.000Z",
          "revoked_by": "oidc https://idp.assureur-demo.example admin-1",
          "revocation_cause": "administrateur",
          "revocation_reason": "Adresse non membre du jeu de l'organisation",
          "replaced_by": null
        }
      ]
    },
    {
      "id": "apb-0003",
      "session_identity": "oidc https://idp.assureur-demo.example u.martin",
      "external_id": null,
      "display_name": "U. Martin",
      "active": true,
      "requester_identities": [
        "u.martin@assureur-demo.example"
      ],
      "created_at": "2026-11-10T10:00:30.000Z",
      "addresses": [
        {
          "address": "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
          "state": "active",
          "proof": {
            "message": "noortrace/inscription/v0\nJe lie cette adresse a mon identite pour approuver dans NOORTRACE. Ce message n'est pas un vote.\nOrigine: https://console.assureur-demo.example\nOrganisation: assureur-demo\nIdentifiant d'organisation: 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab\nIdentite: oidc https://idp.assureur-demo.example u.martin\nAdresse: 0x90f79bf6eb2c4f870365e785982e1f101e93b906\nEmis le: 2026-11-10T10:00:00.000Z\nExpire le: 2026-11-10T10:10:00.000Z\nNonce: 1c41e3b5ac3371fbc61252431a785fce",
            "signature": "0xa6e586e35e22fd9171b5d8a29b910006148f4be3a82352105c6a5d668871a2644f9902f2fc7fa5747c1481a12aa37c93104e8e048b0bcb26e972ae1793aad50b1b",
            "nonce": "1c41e3b5ac3371fbc61252431a785fce",
            "issued_at": "2026-11-10T10:00:00.000Z",
            "expires_at": "2026-11-10T10:10:00.000Z",
            "received_at": "2026-11-10T10:00:30.000Z"
          },
          "validated_at": "2026-11-10T10:30:00.000Z",
          "validated_by": "oidc https://idp.assureur-demo.example admin-1",
          "revoked_at": null,
          "revoked_by": null,
          "revocation_cause": null,
          "revocation_reason": null,
          "replaced_by": null
        }
      ]
    }
  ],
  "operations": [
    {
      "seq": 1,
      "at": "2026-11-10T08:00:30.000Z",
      "op": "inscrire",
      "by": "oidc https://idp.assureur-demo.example approbateur-1",
      "entry": "apb-0001",
      "address": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
      "launched_by": null,
      "reason": null,
      "administrators": null
    },
    {
      "seq": 2,
      "at": "2026-11-10T08:30:00.000Z",
      "op": "valider",
      "by": "oidc https://idp.assureur-demo.example admin-1",
      "entry": "apb-0001",
      "address": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
      "launched_by": null,
      "reason": null,
      "administrators": null
    },
    {
      "seq": 3,
      "at": "2026-11-10T09:00:30.000Z",
      "op": "inscrire",
      "by": "oidc https://idp.assureur-demo.example approbateur-2",
      "entry": "apb-0002",
      "address": "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
      "launched_by": null,
      "reason": null,
      "administrators": null
    },
    {
      "seq": 4,
      "at": "2026-11-10T09:20:30.000Z",
      "op": "inscrire",
      "by": "oidc https://idp.assureur-demo.example approbateur-2",
      "entry": "apb-0002",
      "address": "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65",
      "launched_by": null,
      "reason": null,
      "administrators": null
    },
    {
      "seq": 5,
      "at": "2026-11-10T09:40:00.000Z",
      "op": "valider",
      "by": "oidc https://idp.assureur-demo.example admin-1",
      "entry": "apb-0002",
      "address": "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
      "launched_by": null,
      "reason": null,
      "administrators": null
    },
    {
      "seq": 6,
      "at": "2026-11-10T09:41:00.000Z",
      "op": "revoquer",
      "by": "oidc https://idp.assureur-demo.example admin-1",
      "entry": "apb-0002",
      "address": "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65",
      "launched_by": null,
      "reason": "Adresse non membre du jeu de l'organisation",
      "administrators": null
    },
    {
      "seq": 7,
      "at": "2026-11-10T10:00:30.000Z",
      "op": "inscrire",
      "by": "oidc https://idp.assureur-demo.example u.martin",
      "entry": "apb-0003",
      "address": "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
      "launched_by": null,
      "reason": null,
      "administrators": null
    },
    {
      "seq": 8,
      "at": "2026-11-10T10:20:00.000Z",
      "op": "lier_demandeur",
      "by": "oidc https://idp.assureur-demo.example admin-1",
      "entry": "apb-0003",
      "address": null,
      "launched_by": "u.martin@assureur-demo.example",
      "reason": null,
      "administrators": null
    },
    {
      "seq": 9,
      "at": "2026-11-10T10:30:00.000Z",
      "op": "valider",
      "by": "oidc https://idp.assureur-demo.example admin-1",
      "entry": "apb-0003",
      "address": "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
      "launched_by": null,
      "reason": null,
      "administrators": null
    }
  ]
}
```

**EX-13.10** **Une personne, une clé, dans l'annuaire.** Le service DOIT
tenir les invariants suivants, et refuser toute opération qui les
violerait :

1. une `session_identity` n'a qu'une entrée ;
2. une adresse figure dans une seule entrée de l'annuaire, une seule fois,
   dans quelque état que ce soit, et n'est jamais attribuée à une autre
   entrée, même révoquée (`adresse_deja_attribuee`) ;
3. une entrée a au plus une adresse `active` : la validation d'une adresse
   révoque l'adresse active précédente de la même entrée (cause
   `remplacee`, `replaced_by` = la nouvelle adresse) ;
4. une valeur de `requester_identities` appartient à une seule entrée
   (`demandeur_deja_lie`) ;
5. aucune entrée n'est supprimée.

C'est l'application, du côté de l'organisation, d'EX-8.11 : deux adresses
ne prouvent pas deux personnes, et une personne n'a qu'une voix. Ces
invariants ne prouvent pas qu'une personne n'a qu'un compte dans le système
d'identité du client (8.6).

**EX-13.11** **Données personnelles.** L'annuaire et ses preuves portent
des identités de personnes : le service ne les écrit dans aucun événement,
aucun dossier, aucun rapport ni aucune notification ; un dossier et un
rapport ne portent que des adresses (CT-1, CT-6), comme les instantanés de
curators-hub (R5-F37). `display_name` n'est jamais un identifiant et n'est
servi qu'aux administrateurs et à la personne de l'entrée. L'export de
l'annuaire à un réviseur (EX-13.19) est un acte du client, hors de
l'enregistreur.

### 13.5 Inscription par preuve de possession

Une adresse n'est attribuée à une personne que si cette personne prouve
qu'elle détient la clé, en signant avec elle un texte qui nomme la console,
l'organisation, son identité et l'adresse. La signature est faite dans le
portefeuille de la personne, par les parcours de signature de 13.9 à
13.13, la donnée de `personal_sign` étant alors les octets du texte et non
`D_A` (pour le parcours d, la page signe le condensé EIP-191 du texte) ; la
clé ne quitte jamais le portefeuille, ni, au parcours d, le navigateur de
l'approbateur (EX-13.1).

**EX-13.12** **Message d'inscription.** Le message est le texte suivant,
dix lignes séparées par LF (0x0A), sans LF final, sans CR, dont chaque
caractère est de l'ASCII imprimable (0x20 à 0x7E) ou LF :

```text
noortrace/inscription/v0
Je lie cette adresse a mon identite pour approuver dans NOORTRACE. Ce message n'est pas un vote.
Origine: <origine>
Organisation: <org>
Identifiant d'organisation: <org_id>
Identite: <identité de session>
Adresse: <adresse>
Emis le: <instant d'émission>
Expire le: <instant d'expiration>
Nonce: <nonce>
```

Les deux premières lignes sont fixes, au caractère près. `<origine>` est
`console_origin` (EX-13.14) ; `<org>` et `<org_id>` ceux de l'annuaire ;
`<identité de session>` la forme canonique d'EX-13.7 ; `<adresse>` en
hexadécimal minuscule avec `0x` (CT-1 §3, sans somme de contrôle EIP-55) ;
les instants au format de CT-1 §3 ; `<nonce>` 32 chiffres hexadécimaux
minuscules. Chaque clé est suivie de `:` et d'une espace, et sa valeur
s'étend jusqu'à la fin de la ligne. Analyser un message, c'est le découper
sur LF, exiger exactement dix lignes, les deux premières à l'identique,
chaque clé à sa place et chaque valeur dans sa grammaire, puis reconstruire
le texte depuis les valeurs lues et exiger l'égalité octet pour octet avec
le texte reçu : aucune variante (espace en plus, casse, CR, LF final,
caractère non ASCII, adresse en casse EIP-55) n'est admise
(`message_invalide`). Le message est signé en `personal_sign` sur ses
octets ASCII : EIP-191 version `0x45`, préimage `0x19 ‖ "Ethereum Signed
Message:\n" ‖ décimal(L) ‖ message`, `L` étant sa longueur en octets
(R5-F26).

Le message est en ASCII, sans accent, parce que l'application Ethereum de
Ledger affiche en hexadécimal tout message qui contient un octet ni
imprimable ni blanc (`isprint` et `isspace`, R2-F54 ; la ligne LF est un
blanc, et les appareils à petit écran la remplacent par une espace) et que
Trezor affiche `hex(…)` ce qui n'est pas de l'UTF-8 (R2-F55, R4-F25) ;
MetaMask affiche en texte un message qui ne fait pas 32 octets (R4-F15). Un
message ASCII est donc montré lisible par ces trois portefeuilles d'après
leur code ; le rendu réel sur chaque appareil n'a pas été observé (R4 NV-1,
R5 NV-1).

Exemple : la préparation de l'inscription du compte 1 par la personne de
l'entrée `apb-0001`, le 2026-11-10 à 08:00 UTC. Le texte fait 516 octets ;
sa préimage EIP-191 fait 545 octets (`L` s'écrit en trois chiffres) et son
condensé EIP-191 est
`0xaf9b14a62489fc34643813436d932180470bbfa1cb197aea3de5fe54f871c5ef`.

<!-- schema: console-service/requete_preparer_inscription -->
```json
{
  "session_identity": "oidc https://idp.assureur-demo.example approbateur-1",
  "address": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
}
```

<!-- schema: console-service/reponse_preparer_inscription -->
```json
{
  "fields": {
    "origin": "https://console.assureur-demo.example",
    "org": "assureur-demo",
    "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
    "identity": "oidc https://idp.assureur-demo.example approbateur-1",
    "address": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
    "issued_at": "2026-11-10T08:00:00.000Z",
    "expires_at": "2026-11-10T08:10:00.000Z",
    "nonce": "dbcddc22164b049171cc7a6cda847ff2"
  },
  "message": "noortrace/inscription/v0\nJe lie cette adresse a mon identite pour approuver dans NOORTRACE. Ce message n'est pas un vote.\nOrigine: https://console.assureur-demo.example\nOrganisation: assureur-demo\nIdentifiant d'organisation: 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab\nIdentite: oidc https://idp.assureur-demo.example approbateur-1\nAdresse: 0x70997970c51812dc3a010c7d01b50e0d17dc79c8\nEmis le: 2026-11-10T08:00:00.000Z\nExpire le: 2026-11-10T08:10:00.000Z\nNonce: dbcddc22164b049171cc7a6cda847ff2"
}
```

Le premier paramètre de `personal_sign` est `0x` suivi des 516 octets du
texte en hexadécimal minuscule (`0x6e6f6f7274726163652f696e736372…`) ; le
second est l'adresse. La signature du compte 1 sur ce texte est celle de la
requête `inscrire` :

<!-- schema: console-service/requete_inscrire -->
```json
{
  "session_identity": "oidc https://idp.assureur-demo.example approbateur-1",
  "address": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
  "message": "noortrace/inscription/v0\nJe lie cette adresse a mon identite pour approuver dans NOORTRACE. Ce message n'est pas un vote.\nOrigine: https://console.assureur-demo.example\nOrganisation: assureur-demo\nIdentifiant d'organisation: 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab\nIdentite: oidc https://idp.assureur-demo.example approbateur-1\nAdresse: 0x70997970c51812dc3a010c7d01b50e0d17dc79c8\nEmis le: 2026-11-10T08:00:00.000Z\nExpire le: 2026-11-10T08:10:00.000Z\nNonce: dbcddc22164b049171cc7a6cda847ff2",
  "signature": "0x8f799ab2a84552c45d92dbbb89107933a01e8ea1ad2628656cf1acae8a326e2b1e422a677308bd27d4821637bafa04f9338b07b3b19368ec10472caeaa0afbca1c"
}
```

<!-- schema: console-service/reponse_adresse -->
```json
{
  "entry": "apb-0001",
  "address": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
  "state": "en_attente",
  "revision": 1
}
```

**EX-13.13** **Défi.** `preparer_inscription` vérifie, dans cet ordre, la
forme de la requête (`requete_invalide`), l'identité (`identite_invalide`),
que l'entrée de cette identité, si elle existe, est active
(`identite_desactivee`) et que l'adresse n'est pas déjà dans l'annuaire
(`adresse_deja_attribuee`) ; puis le service tire un nonce de 128 bits par
un générateur cryptographique, pose `Emis le` à l'instant de la requête sur
son horloge et `Expire le` à `Emis le + registration_ttl_ms`, construit le
texte d'EX-13.12 et le rend avec ses champs. Un défi est à usage unique ;
un nouveau défi pour la même identité et la même adresse remplace le
précédent, dont le nonce devient inconnu. Le nonce protège du rejeu, comme
celui que l'ERC-4361 exige « per session initiation with enough entropy to
prevent replay attacks » (R5-F22). La console DOIT reconstruire elle-même le
texte depuis les champs reçus (bibliothèque, EX-13.32), exiger qu'il soit
égal, octet pour octet, au texte du service, que l'origine soit la sienne
(`window.location.origin`), que l'identité soit celle de sa session et
l'adresse celle que l'approbateur a choisie ; sinon elle NE DOIT PAS
demander de signature, et affiche, dans cet ordre de contrôle, le code
`message_invalide` (texte différent de celui qu'elle reconstruit),
`origine_differente`, `identite_differente` ou `adresse_differente`, avec la
réponse de la table des pannes de l'inscription (13.14).

**EX-13.14** **Origine.** `console_origin` est l'origine HTTPS exacte de la
console (schéma `https`, hôte en minuscules, port facultatif, sans chemin) ;
la console DOIT être servie en HTTPS depuis cette origine, et le service
DOIT comparer l'origine du message à `console_origin`
(`origine_differente`). L'ERC-4361 confie au portefeuille la comparaison du
domaine du message avec l'origine de la requête (« the Wallet MUST reject
the request unless the Wallet is in developer mode », R5-F21) ; un
portefeuille répandu ne fait qu'avertir (R5-F25), et les autres ne sont pas
vérifiés (R5 NV-2) : la comparaison du service est la seule sur laquelle
CT-3 compte.

**EX-13.15** **Vérification d'une inscription.** Le service accepte
`inscrire` si et seulement si, dans cet ordre (la première raison qui
s'applique est rendue) :

1. la requête a la forme de `requete_inscrire` (`requete_invalide`) ;
2. `session_identity` a la forme d'EX-13.7 (`identite_invalide`) ;
3. `message` respecte EX-13.12 (`message_invalide`) ;
4. le nonce du message est celui d'un défi connu (`nonce_inconnu`) et non
   encore présenté (`nonce_deja_utilise`) ; à partir de ce pas, le défi est
   marqué présenté, quel que soit le sort de la requête ;
5. l'instant de réception `r` vérifie `Emis le ≤ r < Expire le`
   (`inscription_expiree`) ;
6. `Origine` est `console_origin` (`origine_differente`) ;
7. `Organisation` et `Identifiant d'organisation` sont ceux de l'annuaire
   (`organisation_differente`) ;
8. `Identite` est `session_identity` de la requête et l'identité du défi
   (`identite_differente`) ;
9. `Adresse` est `address` de la requête et l'adresse du défi
   (`adresse_differente`) ;
10. le message est, octet pour octet, le texte du défi (`message_invalide`) ;
11. la signature, normalisée selon EX-9.3 (65 octets, `r` et `s` dans
    `[1, n − 1]`, `v ∈ {0, 1}` ramené à `{27, 28}`, `s` haut ramené en bas),
    recouvre `address` sur le condensé EIP-191 des octets du message
    (`signature_invalide`) ;
12. l'entrée de `session_identity`, si elle existe, est active
    (`identite_desactivee`) ;
13. l'adresse n'est dans aucune entrée (`adresse_deja_attribuee`).

Effet : l'entrée de `session_identity` est créée si elle n'existe pas
(`active` vrai, `requester_identities` vide), l'adresse y est ajoutée à
l'état `en_attente` avec sa preuve (le message, la signature **normalisée**,
le nonce, les deux instants du message et l'instant de réception), et
l'opération `inscrire` est inscrite. Une signature EIP-191 d'un compte
externe se vérifie par EIP-191, comme l'ERC-4361 l'exige (R5-F19) ; les
comptes de contrat (ERC-1271), dont la validité dépend de l'état de la
chaîne (R5-F19), ne sont pas admis en version 0 (section 16).

**EX-13.16** **Séparation des domaines.** Un message d'inscription et un
vote ne peuvent pas être pris l'un pour l'autre :

1. la préimage EIP-191 d'un vote fait 60 octets (`L = 32`, en-tête de 28
   octets) ; celle d'un message d'inscription conforme fait au moins
   468 octets (`L ≥ 439`, en-tête de 29 octets), et la fonction
   `L ↦ L + chiffres(L)` étant strictement croissante, la longueur de la
   préimage fixe `L` (R5-F27) : les deux préimages diffèrent toujours, et une
   signature de l'une ne vaut pour l'autre que sur une collision de Keccak-256 ;
2. le service ne vérifie un vote que sur `D_A` qu'il reconstruit
   (EX-9.10) et une inscription que sur le texte d'un défi qu'il a tiré
   (EX-13.15) : présentée comme vote, la signature d'inscription
   d'exemple recouvre `0xfac296ad1fc770d69ff4d1f69b67efbba7ae46f9` et non le
   compte 1 (`signature_invalide`) ; présentée comme inscription, la
   signature du vote du compte 1 sur `apr-0001` (trace
   `tickets/approuve-sans-contestation.json`, `0x510f909a…ee591c`) recouvre
   `0x8768051a828bb4301030920c9b69759b08e64bde` (`signature_invalide`) ;
3. la console NE DOIT demander `personal_sign` que sur 32 octets égaux à un
   `D_A` qu'elle a calculé et affiché (EX-9.6), ou sur un texte d'inscription
   qu'elle a reconstruit et affiché (EX-13.13), jamais sur autre chose.

Ces trois points ne parent pas le cas d'EX-9.9 : un site tiers qui ferait
signer à l'approbateur le `D_A` d'un ticket en attente obtiendrait une
signature valable, qui ne devient un vote qu'aux conditions d'EX-9.9
(« Signature obtenue hors de la console ») ; le point 3 exclut aussi de la
console les condensés du registre de CT-4, qui se signent hors d'elle
(EX-9.9). Le message d'inscription, lisible, n'ajoute pas de risque de vote,
puisqu'il ne se signe que pour l'identité et l'adresse qu'il nomme ; une
inscription obtenue d'une autre personne sur un site d'hameçonnage peut en
revanche confisquer son adresse (14.8).

Le format d'inscription n'est pas un message ERC-4361 (« Sign-In with
Ethereum », statut « Final », R5-F16), pour trois raisons tirées de son
texte : sa grammaire limite la phrase libre aux caractères réservés et non
réservés d'une URI et à l'espace (R5-F17), ce qui exclut une partie des
sujets OIDC, chaînes ASCII quelconques (R5-F1) ; sa garantie propre, la
comparaison du domaine par le portefeuille, n'est pas appliquée
uniformément (R5-F25, R5 NV-2) et la vérification de l'origine reste au
service (EX-13.14) ; il lie une session de connexion à une adresse
(R5-F20), alors que l'inscription est une déclaration durable, validée par
un tiers. Le texte d'inscription n'emploie pas la formule « wants you to sign
in with your Ethereum account », que les portefeuilles DEVRAIENT signaler
dans un message non conforme (R5-F21). Ses exigences reprennent celles de
l'ERC-4361 qui valent ici : texte lisible avant la signature, sans JSON ni
code hexadécimal autre que l'adresse (R5-F24, la ligne `Identifiant
d'organisation` et le nonce exceptés), domaine, nonce, instants d'émission
et d'expiration (R5-F18).

**Ce que voit l'approbateur à l'inscription.** La console affiche le texte
entier, ligne par ligne, avant d'appeler le portefeuille ; le portefeuille
montre le même texte (MetaMask, Ledger, Trezor d'après leur code, EX-13.12 ;
rendu non observé, R5 NV-1) ;
l'approbateur vérifie que l'origine est celle de la console qu'il a ouverte,
que la ligne `Identite` commence, après `oidc`, par l'adresse du système de
connexion de son organisation (l'émetteur), ou, après `utilisateur`, par le
nom de ce système (le sujet qui suit est un identifiant qu'il n'a pas à
connaître : la console refuse un texte dont l'identité n'est pas celle de la
session ouverte, `identite_differente`, EX-13.13, et le service aussi,
EX-13.15, point 8), et que l'adresse est celle de son portefeuille ; sinon il refuse dans le portefeuille et prévient
l'administrateur (13.14, 13.17).

### 13.6 Validation, rotation, révocation, désactivation

**EX-13.17** **Opérations.** Les méthodes suivantes modifient l'annuaire ;
chacune vérifie, dans l'ordre donné, la forme de la requête
(`requete_invalide`) et l'identité de session (`identite_invalide`), puis :

| Méthode | Vérifications, dans cet ordre | Effet |
|---|---|---|
| `valider` | session dans `administrators` (`non_administrateur`) ; entrée connue (`entree_inconnue`) ; adresse dans l'entrée (`adresse_inconnue`) ; session différente de la personne de l'entrée (`auto_validation`) ; entrée active (`identite_desactivee`) ; adresse `en_attente` (`etat_incompatible`) | adresse `active`, `validated_at`, `validated_by` ; l'adresse active précédente de l'entrée, s'il y en a une, devient `revoquee`, cause `remplacee`, `replaced_by` = l'adresse validée, `revocation_reason` nul, au même instant et par le même administrateur |
| `revoquer` | entrée connue ; adresse dans l'entrée ; session dans `administrators` ou personne de l'entrée (`revocation_non_autorisee`) ; adresse `en_attente` ou `active` (`etat_incompatible`) | adresse `revoquee`, cause `personne` si la session est la personne de l'entrée, `administrateur` sinon ; `revocation_reason` = le motif de la requête, facultatif (`null` sans motif) |
| `desactiver` | session dans `administrators` ; entrée connue ; entrée active (`etat_incompatible`) | `active` faux ; chaque adresse `en_attente` ou `active` devient `revoquee`, cause `desactivation`, `revocation_reason` nul (le motif reste dans l'opération) ; les défis de l'identité sont effacés |
| `reactiver` | session dans `administrators` ; entrée connue ; entrée inactive (`etat_incompatible`) | `active` vrai ; aucune adresse n'est rétablie : la personne en inscrit une nouvelle |
| `lier_demandeur` | session dans `administrators` ; entrée connue ; valeur liée à aucune entrée (`demandeur_deja_lie`) | ajout à `requester_identities` |
| `delier_demandeur` | session dans `administrators` ; entrée connue ; valeur dans l'entrée (`demandeur_inconnu`) | retrait de `requester_identities` |

Exemple : la validation de l'adresse du compte 1 par l'administrateur
`admin-1` (opération 2 de l'annuaire d'exemple), puis le refus que reçoit la
même requête envoyée par la personne de l'entrée elle-même.

<!-- schema: console-service/requete_valider -->
```json
{
  "session_identity": "oidc https://idp.assureur-demo.example admin-1",
  "entry": "apb-0001",
  "address": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
}
```

<!-- schema: console-service/reponse_adresse -->
```json
{
  "entry": "apb-0001",
  "address": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
  "state": "active",
  "revision": 2
}
```

<!-- schema: console-service/erreur -->
```json
{
  "error": {
    "code": "auto_validation",
    "message": "validation par la personne de l'entree",
    "data": {
      "entry": "apb-0001"
    }
  }
}
```

**Avant de valider.** Le service vérifie la preuve de possession, pas que
l'adresse appartient à la personne de l'entrée : une personne qui signe sans
lire, sur un site d'hameçonnage, un texte qui nomme l'identité d'un autre
fait inscrire son adresse dans l'entrée de cet autre (14.8). Avant de
valider, l'administrateur DOIT donc établir, par un canal indépendant de la
console, que la personne de l'entrée détient l'adresse et a demandé son
inscription : confirmation par la personne, de vive voix ou par la
messagerie de l'organisation, ou concordance avec la liste d'adresses que
l'administrateur du jeu tient pour le `CuratorSet` (8.3) ; sinon il
révoque l'adresse, avec un motif.

**Confiscation.** Une adresse inscrite dans une autre entrée que celle de
son détenteur n'est jamais rendue (EX-13.10, point 2), même révoquée : le
détenteur prévient l'administrateur de l'annuaire par un autre canal que la
console ; l'administrateur révoque l'adresse avec un motif (cause
`administrateur`), ce qui l'empêche d'être validée pour l'entrée qui l'a
inscrite ; le détenteur fait tourner sa clé (« Rotation » ci-dessous : une
nouvelle adresse, ajoutée au `CuratorSet`). Une libération, au profit de
son détenteur prouvé, d'une adresse jamais validée est une proposition pour
une version 1 (section 16). La trace `annuaire/traces/confiscation.json`
(A.10) montre ce déroulé.

Toute opération acceptée est inscrite dans `operations` avec `seq`, son
instant (horloge du service), `op`, `by` (l'identité de session qui l'a
faite), l'entrée, l'adresse ou l'alias de demandeur qu'elle vise, le motif,
et `administrators`, nul pour les méthodes de ce tableau (EX-13.37).
**Rotation** : la personne inscrit sa nouvelle adresse, l'administrateur
du jeu l'ajoute au `CuratorSet` (8.3), un administrateur de l'annuaire la
valide, ce qui révoque l'ancienne, puis l'administrateur du jeu retire
l'ancienne du `CuratorSet`. Entre ces pas, les deux adresses peuvent être
membres du jeu ; seule l'adresse active de l'annuaire peut voter par le
canal de la console (EX-13.18, EX-12.16). **Départ** : `desactiver` révoque
tout ; la personne est retirée du `CuratorSet` par son administrateur. Aucune
opération de l'annuaire ne touche à un ticket (EX-12.18) : un membre retiré du
jeu cesse de compter par le nouveau gel (EX-8.6), pas par l'annuaire.

Validation et révocation ne sont pas signées en version 0 : elles sont
attestées par le service, sur le canal authentifié de la console (EX-12.4).
Une validation signée par un administrateur est une proposition (section 16).

**EX-13.37** **Changement du réglage `administrators`.** Le réglage
`administrators` de la configuration du service fait foi (10.3, EX-13.9).
Quand le service démarre ou recharge sa configuration, et avant de servir
une méthode du canal de la console, il DOIT comparer ce réglage, comme liste
(mêmes identités, même ordre), à la copie de l'annuaire ; s'ils diffèrent, la
recopie de la nouvelle valeur est une opération de l'annuaire, persistée
comme les autres (EX-12.17) : `op` `changer_administrateurs`, `by` égal à la
chaîne `configuration` (le changement vient de la configuration, non d'une
session), `entry`, `address`, `launched_by` et `reason` nuls, et
`administrators` égal à `{ "before", "after" }`, la copie avant et la
nouvelle valeur ; `revision` est incrémentée, `updated_at` posé à l'instant
de l'opération, et le membre `administrators` de l'annuaire prend la
nouvelle valeur. Une valeur hors de la forme d'EX-13.9 (de 1 à 64 identités
canoniques distinctes) n'est pas recopiée : le service refuse de démarrer
avec elle. Aucune autre opération ne change `administrators`, et aucune
méthode du canal ne fait cette opération. Comme les autres opérations de
l'annuaire, elle ne touche à aucun ticket (EX-12.18) ; les droits
d'administrateur d'une session se jugent, à chaque méthode, sur la copie en
vigueur. Une session ordinaire ne reçoit pas cette opération dans le
document réduit d'EX-12.17, qui garde le membre `administrators`. La
fonction `recopierAdministrateurs` de la bibliothèque (EX-13.32) la réalise ;
le rejeu d'un annuaire exporté la rejoue (EX-13.19, point 6 ; cas
`annuaire/exports/administrateurs-*.json`, A.10).

### 13.7 Contrôles de la console à chaque action

**EX-13.18** Avant de demander la signature d'un vote, et avant d'envoyer
une récusation, la console DOIT lire l'annuaire de la session (méthode
`annuaire`) et la vue du ticket (méthode `consulter`), et refuser l'action
quand l'une des conditions suivantes est remplie ; la fonction de contrôle
de la bibliothèque (`controleVote`, EX-13.32) rend la première dans cet
ordre :

1. le jeu du ticket n'est pas figé (`jeu_non_fige`) ;
2. aucune entrée n'a pour `session_identity` celle de la session
   (`identite_inconnue`) ;
3. l'entrée est inactive (`identite_desactivee`) ;
4. l'adresse choisie dans le portefeuille n'est pas l'adresse `active` de
   l'entrée (`adresse_non_attribuee`) ;
5. l'adresse n'est pas membre du jeu figé (`hors_jeu`) ;
6. pour un vote, `self_approval` vaut `interdite` et le `launched_by` du
   ticket est dans `requester_identities` de l'entrée : la session est
   celle du demandeur (`session_du_demandeur`).

Correspondance avec les contrôles d'EX-9.15 :

| Condition d'EX-13.18 | Contrôle d'EX-9.15 | Raison |
|---|---|---|
| 1 | 7 | `jeu_non_fige` |
| 2, 3 et 4 | 9 | `identite_inconnue`, `identite_desactivee`, `adresse_non_attribuee` : la première qui s'applique, une seule |
| 5 | 10 | `hors_jeu` |
| 6 | 12 | `session_du_demandeur` |

`controleVote` rend la première raison de cet ordre ; le modèle d'affichage
porte dans `blocking` celle de chaque contrôle fait, avec les sauts
d'EX-9.15 tels qu'ils sont écrits : un échec au contrôle 7 fait sauter les
contrôles 10 et 11, pas le 9 ; un échec au 9 fait sauter 10 et 11 ; un échec
au 10 fait sauter 11.

Ces conditions sont les contrôles 7, 9, 10 et 12 d'EX-9.15, dans le même
ordre : le modèle d'affichage les porte toutes dans `blocking`, avec les
autres contrôles d'EX-9.15, dont l'adresse du demandeur selon la politique
(`separation.requester_addresses`), qui donne `auto_approbation` au
contrôle 11. Pour une récusation, les conditions 1 à 5 s'appliquent
(EX-10.4) : avant le gel, la console la refuse donc (`jeu_non_fige`,
condition 1). Pour un
retrait, la console n'envoie `retirer` qu'avec `by` égal au `launched_by` du
ticket quand il figure dans `requester_identities` de l'entrée de la
session, ou égal à l'identité de session quand elle est dans
`administrators` (EX-7.15) ; elle n'offre pas l'action autrement, et le
service refait ce contrôle sur le canal (EX-12.19). Une
adresse que l'annuaire attribue au demandeur du ticket
(`separation.requester_directory_addresses`, EX-12.15) et que la politique ne
déclare pas pour lui (`separation.requester_addresses`) donne un avertissement
`separation_incomplete`, affiché à tout approbateur du ticket, sans bloquer : la
séparation qui compte pour le noyau (SG-7) est celle de la politique, et l'écart
dit que la politique doit être complétée (EX-10.5). La console refait ces
contrôles juste avant d'envoyer le vote signé (13.9, pas 7), si le
`revision` de l'annuaire ou le `state` de la vue a changé depuis la lecture
du pas 3 de 13.9 ; tout autre changement de la vue n'y oblige pas. Les
contrôles alors exigés sont les conditions 1 à 6 ci-dessus (`controleVote`),
et non les treize contrôles d'EX-9.15 ; la console de référence refait en
plus ceux-ci sur la vue relue.

### 13.8 Ce qu'un réviseur peut recouper

**EX-13.19** Le client peut
remettre au réviseur l'annuaire exporté (méthode `annuaire` d'une session
administrateur). Le réviseur vérifie hors ligne, sans le service :

1. la forme (`annuaire-approbateurs-v0`) ;
2. `revision` égal au nombre d'opérations, `seq` de 1 à `revision`, instants
   croissants au sens large, `updated_at` égal à l'instant de la dernière
   (`revision_incoherente`) ;
3. identifiants d'entrée uniques (`identifiant_double`), identités uniques
   (`identite_double`), chaque adresse dans une seule entrée, une seule fois
   (`adresse_double`), au plus une adresse active par entrée
   (`deux_adresses_actives`) ;
4. pour chaque preuve : le message respecte EX-13.12, la signature est
   canonique (65 octets, `v ∈ {27, 28}`, `s` bas) et recouvre l'adresse
   (`preuve_invalide`) ; les lignes du message sont `console_origin`, `org`,
   `org_id`, l'identité de l'entrée et l'adresse, le nonce et les instants
   sont ceux de la preuve, et `Emis le ≤ received_at < Expire le`
   (`preuve_discordante`) ;
5. aucune adresse n'a été validée par la personne de son entrée
   (`auto_validation`) ;
6. le rejeu de `operations` depuis un annuaire vide, avec les règles
   d'EX-13.15 (hors nonce et horloge) et d'EX-13.17, redonne `entries`
   (`operations_incoherentes`). Une opération `inscrire` se rejoue avec les
   pas 3, 6 à 9 et 11 à 13 d'EX-13.15, l'identité et l'adresse du message
   étant comparées à `by` et à `address` de l'opération ; sa preuve est
   celle de l'adresse `address` dans l'entrée `entry` du document exporté,
   et une opération dont la preuve manque ne se rejoue pas ; l'entrée créée
   reçoit l'identifiant `entry` de l'opération, `active` vrai, aucun alias
   et `created_at` égal à l'instant de l'opération. Les droits
   d'administrateur d'une opération se jugent sur la liste en vigueur à
   cette opération : le rejeu part du `before` de la première opération
   `changer_administrateurs`, ou, s'il n'y en a pas, de `administrators` du
   document ; une opération `changer_administrateurs` se rejoue si son
   `before` est la liste en vigueur et diffère de son `after`, qui devient
   la liste en vigueur (EX-13.37) ; toute autre opération porte
   `administrators` nul. La comparaison finale porte sur la liste en vigueur,
   égale à `administrators` du document, puis sur `entries` ; elle exclut
   `external_id` et `display_name`, données sans effet (EX-13.9). Une
   preuve fausse donne donc à la fois l'écart du point 4 et
   `operations_incoherentes`.

Les écarts sont rapportés comme ceux de A.4 (liste complète, triée par
pointeur puis par code ; une non-conformité au schéma donne une seule
erreur `schema`). Chaque écart porte le pointeur JSON du membre
fautif : `revision_incoherente`, celui de `/revision`, `/updated_at`, ou de
`seq` ou `at` de l'opération fautive ; `identifiant_double`,
`identite_double` et `adresse_double`, celui de la seconde occurrence
(`/entries/<i>/id`, `/entries/<i>/session_identity`,
`/entries/<i>/addresses/<k>/address`) ; `deux_adresses_actives`,
`/entries/<i>/addresses` ; `preuve_invalide` et `preuve_discordante`,
`/entries/<i>/addresses/<k>/proof` ; `auto_validation`,
`/entries/<i>/addresses/<k>/validated_by` ; `operations_incoherentes`,
`/operations/<j>` de la première opération qui ne se rejoue pas, sinon
`/administrators` si le rejeu aboutit à une autre liste d'administrateurs,
sinon `/entries` s'il aboutit à d'autres entrées. Avec un dossier (CT-1 §11), le
réviseur peut alors relier chaque adresse de `approval.approvers` à l'entrée
dont elle était l'adresse active à `approval.at` (`validated_at ≤ at`, et
`revoked_at` nul ou postérieur), constater que deux signataires d'une même
décision appartiennent à deux entrées distinctes, et qu'aucun n'appartient à
l'entrée dont `requester_identities` contient le `launched_by` de la demande ;
avec la trace du ticket, que chaque vote compté porte l'identité de session de
cette entrée.

Ce recoupement est **déclaratif** : l'annuaire est tenu et exporté par le
client, ses opérations ne sont pas signées, et seules les preuves de
possession le sont, par les adresses elles-mêmes. Il nomme les personnes
derrière les adresses ; il ne remplace jamais le jeu figé du ticket ni le
jeu déclaré du dossier, que le contrôle 7 de CT-6 vérifie seul (EX-8.10).
Une adresse sans entrée n'invalide pas une décision : elle dit que
l'annuaire était incomplet.

### 13.9 Parcours de signature : vue d'ensemble

Un parcours de signature est la suite exacte des messages qui mène de la
demande affichée au vote inscrit. La clé ne quitte jamais le portefeuille ;
la console ne la voit pas, sauf dans le parcours d, où la page déchiffre un
fichier que l'approbateur lui donne, sans qu'il quitte son navigateur.

| Parcours | Portefeuille | Messages de la page vers le portefeuille | En version 0 |
|---|---|---|---|
| a | portefeuille de navigateur (extension) | EIP-6963 pour le découvrir, EIP-1193 `request` pour lui parler (13.10) | DOIT être offert |
| b | portefeuille matériel, par un portefeuille de navigateur qui le prend en charge | ceux du parcours a ; le portefeuille de navigateur parle à l'appareil (13.11) | offert par a |
| c | portefeuille mobile, par WalletConnect v2 | `wc_sessionRequest` chiffré, par un relais (13.12) | désactivé par défaut ; activable par organisation |
| d | fichier de clé chiffré (Web3 Secret Storage v3), lu dans la page | aucun : la page signe (13.13) | PEUT être offert |
| — | clé d'accès (passkey, WebAuthn) | — | hors de la version 0 (section 16) |

Messages, dans l'ordre (parcours a et b ; c et d en diffèrent aux pas 3 à 6,
et le parcours d n'a ni découverte ni `eth_requestAccounts`). Chaque message
entre la page et le service passe par le serveur de console, qui le relaie
après avoir imposé `session_identity` (12.9, 13.18) :

| Pas | De → vers | Message | Contenu exact |
|---|---|---|---|
| 1 | page → serveur de console → service | `consulter` et `annuaire` (12.9), pour l'affichage seul | `{ "ticket", "session_identity" }` ; `{ "session_identity" }` |
| 2 | service → page | vue du ticket et annuaire de la session | `$defs/vue_ticket`, `$defs/reponse_annuaire` ; la console affiche le modèle (EX-9.4), sans demander de signature |
| 3 | page → fournisseur, puis page → serveur de console → service | découverte EIP-6963, choix explicite du fournisseur, `eth_requestAccounts` (13.10, EX-13.22, EX-13.23) ; choix de la décision et de l'adresse ; nouveaux `consulter` et `annuaire`, sans condition (EX-9.15, EX-13.18) | écouteur `window.addEventListener("eip6963:announceProvider", …)`, posé au chargement de la page avant toute autre opération (donc avant le pas 1) et jamais retiré (EX-13.22, point 1), puis `window.dispatchEvent(new Event("eip6963:requestProvider"))` ; chaque annonce porte `detail.info` (`uuid`, `name`, `icon`, `rdns`) et `detail.provider` ; choix explicite du fournisseur ; `{ "method": "eth_requestAccounts" }` ; contrôles d'EX-9.15 et d'EX-13.18 sur ces réponses fraîches (EX-13.21) : le pas 4 n'a lieu que si `blocking` est vide |
| 4 | page → fournisseur | requête de signature (EX-13.24) | `{ "method": "personal_sign", "params": [ "0x" + 64 chiffres de D_A, adresse ] }` : 66 puis 42 caractères ASCII minuscules |
| 5 | portefeuille | signature | décode les 32 octets ; signe `H = keccak256(préimage)`, préimage de 60 octets : `0x19`, les 25 octets de `Ethereum Signed Message:\n`, les 2 octets `32`, puis les 32 octets de `D_A` |
| 6 | fournisseur → page | réponse | `"0x"` et 130 chiffres : `r` (32 octets), `s` (32), `v` (1) ; ou une erreur EIP-1193 |
| 7 | console, puis page → serveur de console → service | contrôle après signature (EX-9.21) ; puis `consulter` et `annuaire` de nouveau | forme, normalisation, recouvrement, adresse ; si `state` ou `revision` ont changé, la console refait les contrôles et n'envoie pas `voter` en cas d'échec (EX-13.18) |
| 8 | page → serveur de console → service | `voter` (12.9) | `{ "ticket", "approver", "decision", "signature", "reason", "session_identity" }` |
| 9 | service → page | réponse | `{ "ticket", "state" }`, ou l'erreur de 12.8 |

Au pas 3, l'ordre entre le choix du fournisseur (avec `eth_requestAccounts`)
et le choix de la décision est libre. Ce qui est fixé : aucune requête
`personal_sign` n'est envoyée avant que la décision, le fournisseur et
l'adresse soient choisis ; les nouveaux `consulter` et `annuaire` suivent le
dernier de ces choix (EX-9.15, EX-13.21). 13.17 (« Voter », pas 2 et 3) et
EX-13.33 (points 4 et 5) décrivent chacun un ordre admis.

**Lectures de la vue et de l'annuaire.** Un vote demande trois couples de
lectures `consulter` et `annuaire`, chacun fait à chaque fois : (i) au pas
1, pour l'affichage seul ; (ii) au pas 3, après le dernier des choix
(décision, fournisseur, adresse) : les treize contrôles d'EX-9.15 et ceux
d'EX-13.18 portent sur cette lecture ; (iii) au pas 7, après la vérification
de la signature (EX-9.21) et avant `voter` : la console ne refait les
conditions 1 à 6 d'EX-13.18 que si le `revision` de l'annuaire ou le `state`
de la vue a changé depuis la lecture (ii).

Pour le ticket `apr-2201` (EX-9.17), la préimage du pas 5 est, en
hexadécimal, `0x19457468657265756d205369676e6564204d6573736167653a0a3332`
(28 octets d'en-tête) suivi de
`a57cbdad280b5cb2e9f6ee87b85d8bc05e76a5966377e7d58046519464f7df7c` ; son
keccak256 est `H_approuve` =
`0xe9f3d8812e1fc736cd7957efb20093bfb3655c6568fc56e6133b2cc41d2cf6ea`.

Au parcours c, la découverte EIP-6963 et `eth_requestAccounts` du pas 3 sont
remplacés par l'appariement, par l'URI d'appariement montrée en code QR à la
seule session de l'approbateur (EX-13.27, point 3), et par l'établissement de
la session de la Sign API de WalletConnect v2 (13.12) ; le choix de la
décision et de l'adresse et les nouveaux `consulter` et `annuaire` du pas 3
demeurent. Aux pas 4 à 6, la requête est le `wc_sessionRequest`
d'EX-13.27, point 4, et sa réponse est traitée par EX-9.21 (EX-13.27,
point 5). CT-3 ne fixe aucun autre message de ce parcours, qu'aucun vecteur
ni test n'éprouve (13.12, section 16) ; l'adresse signataire reste l'adresse
active que l'annuaire attribue à la session (EX-13.2, EX-9.15, contrôle 9).

**EX-13.20** **Parcours admis.** La console DOIT offrir le parcours a, et
par lui le parcours b ; elle PEUT offrir le parcours d ; elle n'offre le
parcours c que si la configuration de l'organisation l'active (EX-13.27).
Aucun autre moyen ne produit la signature d'un vote : ni un serveur qui
signe (EX-3.4), ni `eth_sign`, ni `eth_signTypedData`, ni un `personal_sign`
dont la donnée serait du texte, ni une bibliothèque appelée avec la chaîne
`"0x…"` (EX-9.7).

**EX-13.21** **Une requête à la fois, sur action explicite.** La console
n'envoie une requête de signature que pour un triplet (ticket, décision,
adresse) dont la liste `blocking` est vide sur une vue fraîche
(EX-9.15), après une action explicite de l'approbateur sur l'écran qui
affiche l'empreinte ; une seule requête de signature est en cours à la
fois ; aucune n'est relancée sans nouvelle action ; changer de décision ou
d'adresse abandonne la requête en cours (toute réponse qui arrive ensuite
est ignorée, et la console ne l'envoie pas).

### 13.10 Parcours a : portefeuille de navigateur (EIP-1193, EIP-6963)

EIP-1193 (statut « Final ») définit le fournisseur : une méthode
`request({ method, params })` qui rend une promesse, rompue par une
`ProviderRpcError` dont `code` est normalisé (4001 refus de l'utilisateur,
4100 non autorisé, 4200 méthode non prise en charge, 4900 déconnecté de
toutes les chaînes, 4901 déconnecté de la chaîne demandée), et cinq
événements, dont `accountsChanged`, `chainChanged` et `disconnect` (R4-F1 à
R4-F3). Il recommande de traiter le fournisseur comme contrôlé par un
adversaire et de ne pas exposer de compte sans demande explicite (R4-F4).
EIP-6963 (statut « Final », qui requiert EIP-1193) fait annoncer chaque
portefeuille par un événement `eip6963:announceProvider` dont le `detail`
porte `info` (`uuid` UUIDv4, `name`, `icon` en URI `data:`, `rdns`) et
`provider` ; la page le déclenche par `eip6963:requestProvider` (R4-F5 à
R4-F7). `rdns` est déclaré par le portefeuille et peut imiter un autre
portefeuille ; une icône SVG ne doit être rendue que par `<img>` (R4-F5,
R4-F6). Deux annonces de même `uuid` signalent une imitation (R4-F8).
MetaMask annonce son fournisseur ainsi et valide `uuid` et `rdns`
(R4-F9) ; sans filtre, `BrowserProvider.discover` d'ethers 6.17.0 prend le
premier fournisseur annoncé (R4-F10), ce que la console ne fait pas.

**EX-13.22** **Découverte et choix du fournisseur.**

1. La page ajoute un écouteur de `eip6963:announceProvider` sur `window`
   avant toute autre opération et ne le retire pas de la vie de la page,
   puis appelle `window.dispatchEvent(new Event("eip6963:requestProvider"))`
   (R4-F7).
2. Une annonce n'est retenue que si l'événement porte un `detail` dont
   `info.uuid` est un UUID de version 4, `info.name` une chaîne non vide d'au
   plus 64 caractères, `info.icon` une chaîne qui commence par `data:`,
   `info.rdns` une chaîne, et `provider` un objet doté d'une fonction
   `request` ; sinon elle est ignorée (`annonce_invalide`).
3. Première annonce d'un `uuid` : le fournisseur est ajouté à la liste ;
   nouvelle annonce du même `uuid` par le même objet `provider` : sans effet
   (un portefeuille se réannonce à chaque `eip6963:requestProvider`) ; annonce
   du même `uuid` par un autre objet : les deux sont écartés et l'`uuid` est
   exclu pour la vie de la page (`annonce_en_double`). Les annonces écartées
   sont la première annonce de l'`uuid`, l'annonce en conflit et toute
   annonce ultérieure de cet `uuid`, quel qu'en soit l'objet ; une réannonce
   par le même objet avant le conflit n'est pas écartée.
4. La liste est affichée dans l'ordre des premières annonces, avec `name` et
   l'icône, rendue uniquement comme source d'un élément `<img>`, jamais
   insérée comme HTML ni comme SVG en ligne ; `rdns` est affiché avec la
   mention « déclaré par le portefeuille, non vérifié » et ne sert à aucune
   décision (R4-F6).
5. Aucun fournisseur n'est présélectionné, même s'il est seul : l'approbateur
   le choisit par une action explicite (`fournisseur_non_choisi` tant qu'il
   ne l'a pas fait).
6. Si aucune annonce n'est arrivée 1 000 ms après le pas 1, la page affiche
   « aucun portefeuille ne s'est annoncé » (`aucun_fournisseur`) et continue
   d'écouter ; une annonce tardive s'ajoute à la liste.
7. La console NE DOIT PAS employer `window.ethereum` sans choix explicite.
   Elle PEUT le proposer comme une entrée distincte, nommée « fournisseur non
   annoncé, non identifié », jamais présélectionnée, et seulement quand aucun
   fournisseur ne s'est annoncé ; la console de référence ne le propose pas.

**EX-13.23** **Accès aux comptes.** Le fournisseur choisi, la page envoie
`request({ "method": "eth_requestAccounts" })` (méthode d'EIP-1102, au
statut « Stagnant », que recommande EIP-1193 et que spécifie MetaMask,
R4-F4, R4-F11, R4-F12). Le résultat doit être un tableau de chaînes de la
forme `^0x[0-9a-fA-F]{40}$` (sinon `reponse_invalide`) ; la page les écrit en
minuscules. Pour un vote ou une récusation, elle n'en garde que l'adresse
active que l'annuaire attribue à la session (EX-13.2, EX-13.18) ; si elle
n'y est pas : `adresse_non_exposee`, et la page affiche cette adresse active ;
elle la retient dès qu'elle apparaît dans la liste, par `accountsChanged` ou
après une nouvelle lecture de l'annuaire. Pour une inscription (13.5),
l'approbateur choisit, sans présélection, le compte à inscrire parmi les
adresses reçues. Sur `accountsChanged`, une adresse choisie qui n'est plus dans
la liste reçue est abandonnée : l'approbateur choisit de nouveau ; une requête
de signature en cours n'est pas pour autant tenue pour valable, sa réponse
passant par EX-9.21.

**EX-13.24** **Requête de signature.** La requête est exactement :

<!-- schema: console-approbation/requete_signature -->
```json
{
  "method": "personal_sign",
  "params": [
    "0xa57cbdad280b5cb2e9f6ee87b85d8bc05e76a5966377e7d58046519464f7df7c",
    "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
  ]
}
```

`params[0]` est `"0x"` suivi des 64 chiffres hexadécimaux minuscules du `D_A`
calculé par la console pour la décision choisie (66 caractères) ;
`params[1]` est l'adresse choisie en minuscules (42 caractères). L'ordre est
la donnée puis l'adresse : c'est l'ordre de la spécification de MetaMask, de
son intergiciel, de Rabby, qui l'exige, et d'ethers (R4-F12, R4-F14,
R4-F18, R4-F20) ; l'heuristique de MetaMask qui accepte l'ordre inverse ne
joue pas pour 32 octets (66 caractères ne ressemblent pas à une adresse,
R4-F14), et la console n'envoie jamais l'ordre inverse. Le portefeuille
décode la donnée hexadécimale en 32 octets et signe la préimage de 60 octets
(R1-F91, R2-F61, R4-F12) ; la bibliothèque de signature de MetaMask rend
alors exactement la signature qu'ethers produit sur `getBytes(D_A)`
(R4-F17). L'exemple est celui du compte 1 sur `D_approuve` du ticket
`apr-2201` ; la signature attendue est celle de la requête `voter` de 12.9.

**EX-13.25** **Réseau.** `personal_sign` ne porte pas de chaîne : `D_A` ne
dépend d'aucun identifiant de chaîne (CT-1 §6.3). La console ne demande ni
`eth_chainId` ni un changement de chaîne pour un vote ; `chainChanged` est
sans effet sur la requête, et « mauvais réseau » n'est pas une panne d'un
vote. Une requête rompue avec 4900 ou 4901 est une indisponibilité du
portefeuille (13.14), et la console ne demande jamais de changer de réseau
pour y remédier.

### 13.11 Parcours b : portefeuille matériel par un portefeuille de navigateur

**EX-13.26** Un portefeuille matériel est employé à travers un portefeuille
de navigateur qui le prend en charge : la page envoie les mêmes messages
qu'au parcours a, et c'est le portefeuille de navigateur qui parle à
l'appareil ; la console ne parle à aucun appareil en version 0 (section 16).
L'approbateur compare l'empreinte sur l'écran de l'**appareil**, le seul que
l'ordinateur ne contrôle pas, et non sur la fenêtre du portefeuille de
navigateur (EX-9.20).

Ce que le code lu fait de la requête du parcours a :

| Étape | Ledger, application Ethereum, par MetaMask | Trezor, micrologiciel « core », par MetaMask |
|---|---|---|
| Méthodes admises | `personal_sign` seulement, pour les deux appareils (R4-F16) | idem |
| Message transmis | la donnée sans `0x`, à l'appareil (R4-F21) | la donnée en hexadécimal (`hex: true`) à Trezor Connect, qui la transmet telle quelle (R4-F27) |
| Écran de l'appareil | « Review message », paire « Message » en hexadécimal ; paire « Message hash » (`H`, condensé EIP-191) si le réglage « Transaction hash » est activé ; pas de réglage « blind signing » (R4-F23, R2-F54) | `hex(` + 64 chiffres + `)` (R4-F25, R2-F55) |
| Signature rendue par l'appareil au portefeuille de navigateur | `v ‖ r ‖ s` avec `v = 27 + parité` (+ 2 si `r` a dépassé l'ordre) (R4-F22) ; `s` ramené dans la moitié basse par le SDK publié (R4-F24 ; exécution par l'appareil non vérifiée, R4 NV-2) | `r ‖ s ‖ v` avec `v = 27 + recid`, `s` bas sur les deux branches (R4-F25, R4-F26) |
| Contrôle par le portefeuille de navigateur | `v ∈ {0, 1}` ramené à 27 ou 28 ; adresse recouvrée comparée, sinon erreur (R4-F21) | adresse rendue comparée, sinon erreur (R4-F27) |

La page n'attend jamais la forme `v ‖ r ‖ s`. Elle reçoit du portefeuille de
navigateur la réponse du pas 6 de 13.9, `r ‖ s ‖ v` (le porte-clés Ledger de
MetaMask la reconstruit dans cet ordre, R4-F21), qu'EX-9.21 lit dans cet
ordre quelle que soit la sortie de l'appareil. Une réponse dans un autre
ordre échoue à EX-9.21 (`signature_invalide` ou `adresse_differente`) et ne
produit aucun vote.

La console applique EX-9.21 quoi qu'il en soit : `v = 29` ou `30`, que
Ledger rendrait si `r` dépassait l'ordre, est refusé (`signature_invalide`),
comme le noyau le refuserait (SG-5). Ne sont pas vérifiés : le rendu réel, la
pagination et la troncature par modèle d'appareil (R4 NV-1) ; le
micrologiciel du Trezor Model One (R4 NV-3) ; que les porte-clés lus soient
ceux de l'extension publiée (R4 NV-5). Un refus sur l'appareil, un appareil
verrouillé ou une application fermée rompent la promesse avec le code que le
portefeuille de navigateur choisit ; la console le traite selon 13.14
(EX-13.29).

### 13.12 Parcours c : portefeuille mobile par WalletConnect v2

La Sign API de WalletConnect v2 établit une session entre l'application et
le portefeuille sur un transport JSON-RPC distant ; `personal_sign` y passe
dans `wc_sessionRequest` (requête CAIP-27), dont l'objet `request` porte
`method`, `params` et `expiry`, avec un `chainId` ; `expiry` doit tomber
entre maintenant + 300 s et maintenant + 604 800 s (R4-F28) ; les paramètres
de `personal_sign` sont la donnée puis l'adresse (R4-F28, R2-F61). Le contenu
est chiffré de bout en bout (X25519, ChaCha20-Poly1305) ; la clé symétrique
d'appariement est dans l'URI d'appariement (R4-F29). Le relais reçoit le
sujet, le message chiffré, la durée de vie et une étiquette, garde les
messages chiffrés d'un destinataire hors ligne, et authentifie le client par
un JWT signé (R4-F30). Il exige un identifiant de projet délivré par
WalletConnect ; sans liste d'origines autorisées, toutes les origines sont
admises ; les nœuds passerelles sont centralisés et gérés par WalletConnect,
sur un réseau à permission (R4-F31) ; le relais par défaut du SDK est
`wss://relay.walletconnect.org`, réglable (R4-F32).

**EX-13.27** Le parcours c est **désactivé par défaut**. Une organisation
l'active dans la configuration de la console, et alors :

1. le SDK est livré avec la console, sans script tiers (EX-13.4, EX-13.35) ; la
   politique de sécurité du contenu n'ouvre `connect-src` qu'à l'adresse du
   relais configurée, et non à la liste large que la documentation propose
   (R4-F32) ;
2. l'identifiant de projet (une référence de secret de la configuration) a
   une liste d'origines autorisées réduite à l'origine de la console
   (R4-F31) ;
3. l'URI d'appariement, qui porte la clé symétrique (R4-F29), n'est montrée
   (en code QR) qu'à la session authentifiée de l'approbateur ; elle n'est ni
   journalisée ni envoyée au service ;
4. la requête de session porte `request` =
   `{ "method": "personal_sign", "params": [ <les deux chaînes
   d'EX-13.24> ], "expiry": e }`, avec `e` au moins maintenant + 300 s et au
   plus l'échéance du ticket ; si l'échéance est à moins de 300 s, le
   parcours c n'est pas offert pour ce ticket (`delai_depasse`). Le `chainId`
   est celui de la session ; sa forme est fixée par la Sign API, pas par
   CT-3, et `D_A` n'en dépend pas (EX-13.25). Avec le défaut de
   `delai_signature_ms` (300 000 ms), la console peut cesser d'attendre
   alors que la requête reste valable dans le portefeuille mobile jusqu'à
   `expiry` ; une réponse arrivée ensuite est jetée (EX-13.30), et
   l'approbateur rejette la requête restée ouverte (EX-13.29) ;
5. la réponse suit EX-9.21, comme au parcours a ;
6. l'affichage d'un `personal_sign` binaire par les portefeuilles mobiles
   n'est pas vérifié (R4 NV-4, R2 NV-8) : la comparaison de l'empreinte
   (EX-9.20) reste exigée, et un portefeuille qui ne montre pas les 64
   chiffres doit être refusé par l'approbateur, qui vote alors avec un
   portefeuille qui détient la même clé et les montre (EX-9.20, point 5).

Ce que l'organisation accepte en l'activant : un service tiers obligatoire,
qui voit quand et entre quels clients des messages passent, et peut les
retenir ou les retarder (déni de service), sans lire `D_A` ni l'adresse
(R4-F29 à R4-F31). L'existence d'un relais auto-hébergeable compatible et la
conservation des métadonnées par le relais ne sont pas vérifiées (R4 NV-4).
La console de référence n'offre pas ce parcours (13.15), et aucun vecteur ni
test de la version 0 n'éprouve EX-13.27 : ce parcours, gardé parce que son
protocole est établi sur source primaire (R4-F28 à R4-F32), reste à éprouver
par l'organisation qui l'active (section 16).

### 13.13 Parcours d : fichier de clé chiffré

La définition Web3 Secret Storage, version 3, décrit un fichier JSON :
dérivation `pbkdf2` obligatoire (`prf` `hmac-sha256`, `c`, `salt`, `dklen`
au moins 32) ; MAC `keccak256(DK[16..32] ‖ ciphertext)` à comparer à `mac`
avant tout déchiffrement ; chiffrement `aes-128-ctr` obligatoire, de clé
`DK[0..16]` et de vecteur `iv` de 128 bits (R4-F33 ; tranches à borne haute
exclue, EX-9.18 : la définition écrit les mêmes octets `DK[16..31]` et
`DK[0..15]`, bornes incluses) ; ses vecteurs donnent
aussi la forme `scrypt` (`kdfparams` `dklen`, `n`, `p`, `r`, `salt`) et les
membres `crypto`, `id`, `version` (lecture propre, B.5). Le vecteur `scrypt`
publié est incohérent : ethers et eth-account le rejettent, et sa clé
dérivée n'est pas celle de scrypt sur son mot de passe et son sel (R4-F34) ;
ethers déchiffre `pbkdf2` et `scrypt`, exige `dklen` = 32 et chiffre par
défaut en `scrypt` avec `N = 2^17`, `r = 8`, `p = 1` (R4-F35).

**EX-13.28** **Format admis et traitement.**

1. Format : un objet JSON de membres `version` (3), `id` (chaîne) et
   `crypto`, lui-même de membres `cipher` (`aes-128-ctr`), `cipherparams`
   (`iv` : 16 octets), `ciphertext` (32 octets), `kdf`, `kdfparams`, `mac`
   (32 octets), les octets en hexadécimal sans `0x`, majuscules admises ;
   d'autres membres sont ignorés. Un membre manquant ou mal formé, ou une
   autre version : `fichier_cle_invalide`.
2. Dérivation admise : `pbkdf2` avec `prf` `hmac-sha256`, `c` entier de 1 à
   10 000 000, `salt` d'au moins 16 octets, `dklen` 32 ; ou `scrypt` avec `n`
   puissance de 2 de 2 à 2^18, `r` de 1 à 8, `p` de 1 à 4, `salt` d'au moins
   16 octets, `dklen` 32. Tout autre `cipher`, `kdf`, `prf` (dont
   `hmac-sha512`, qu'ethers accepte, R4-F35) ou paramètre hors de ces bornes :
   `fichier_cle_non_pris_en_charge`. Les bornes hautes, choix de CT-3 sans
   source externe, limitent le temps et la mémoire qu'un fichier peut
   imposer à la page.
3. Le fichier est lu dans la page (élément `<input type="file">`), jamais
   envoyé ni conservé ; le mot de passe est saisi dans la page, encodé en
   UTF-8 sans normalisation, jamais conservé ni envoyé.
4. `DK` = la dérivation sur le mot de passe et `salt` ; si
   `keccak256(DK[16..32] ‖ ciphertext)` diffère de `mac` :
   `mot_de_passe_ou_mac`, sans déchiffrer.
5. La clé `k` est le déchiffrement AES-128-CTR de `ciphertext`, de clé
   `DK[0..16]` et de compteur initial `iv` ; `k` lu comme entier doit être
   dans `[1, n − 1]` : `cle_invalide` sinon.
6. L'adresse de `k` doit être l'adresse choisie, attribuée à la session :
   `adresse_differente` sinon, avant toute signature.
7. La page signe `H` (EX-9.17) par ECDSA déterministe (RFC 6979), avec
   `s` dans la moitié basse et `v = 27 + recid`, puis applique EX-9.21 à
   sa propre signature.
8. La page efface `DK`, `k` et le mot de passe de ses tampons dès la
   signature faite ou abandonnée, et n'en garde aucune référence ; ce que
   le moteur JavaScript en garde ailleurs n'est pas maîtrisé.
9. Avertissement `derivation_faible` quand `c` < 262 144 (valeur du
   vecteur PBKDF2 de la définition) ou `n` < 2^17 (défaut d'ethers,
   R4-F35) : seuils choisis par CT-3. L'avertissement est porté dès que les
   points 1 et 2 passent, même si le fichier est refusé plus loin
   (`mot_de_passe_ou_mac`, `cle_invalide`, `adresse_differente`) ; il ne
   l'est pas pour un fichier refusé aux points 1 ou 2. Avec
   `adresse_differente`, l'adresse dérivée de la clé est rendue.

À l'import, la console DEVRAIT dire que la clé passe dans la mémoire de la
page et qu'un portefeuille matériel est recommandé (EX-9.9). L'import d'un
tel fichier par les portefeuilles de navigateur n'est pas vérifié (R4
NV-7). Un mot de passe non ASCII peut être dérivé autrement par d'autres
outils, qui normalisent ou non la chaîne (non vérifié) : les vecteurs
n'emploient qu'un mot de passe ASCII.

Exemple : fichier `pbkdf2` de la clé du compte 1, mot de passe
`noortrace/vecteurs/ct3/console/mot-de-passe`, `salt`, `iv` et `id` tirés des
étiquettes publiques `noortrace/vecteurs/ct3/console/fichier-cle/pbkdf2/sel`,
`…/iv` et `…/uuid` (A.11), 1 024 itérations pour que les tests restent
rapides ; ethers 6.17.0 le déchiffre en la clé du compte 1.

<!-- schema: console-approbation/fichier_cle -->
```json
{
  "crypto": {
    "cipher": "aes-128-ctr",
    "cipherparams": {
      "iv": "2fdd3ed19f4f90b26714a54a93c0b242"
    },
    "ciphertext": "4d43415e8a31d84d875d9cadd71a7e6f5ce5f684d8123c132a5e2c00bf2a3b10",
    "kdf": "pbkdf2",
    "kdfparams": {
      "c": 1024,
      "dklen": 32,
      "prf": "hmac-sha256",
      "salt": "fcbda17689938aecd191be553debe262842116301080efc4e44d931c48d9d2cc"
    },
    "mac": "f90c1c59621e41513172666878d7bc385fd4787152c57f3474354fd19936f898"
  },
  "id": "8c1c832a-edc8-40bc-a67b-1b0f95e86a0f",
  "version": 3
}
```

### 13.14 Pannes et réponses

**EX-13.29** Pour chaque panne des deux tables, la console DOIT donner la
réponse indiquée. Aucune panne ne produit de vote : refuser dans le
portefeuille (4001) n'est pas voter `refuse`, et la console ne transmet
jamais une panne du portefeuille au service comme une décision. Un message
d'erreur venu du portefeuille est affiché comme du texte, jamais interprété
comme du HTML. Les codes (`code_console`, codes EIP-1193) sont des
identifiants internes : la page affiche, en français, la réponse de la
colonne « Réponse de la console » (EX-13.33, point 8), le code entre
parenthèses.

Pannes d'un vote :

| Panne | Code (`code_console`) | Réponse de la console | Ce que fait l'approbateur |
|---|---|---|---|
| `consulter` ou `annuaire` sans réponse dans `service_timeout_ms`, ou en erreur | — (`ticket_inconnu`, `session_non_autorisee`, …) | aucune signature ; affiche « service indisponible » ou la raison | réessaie plus tard |
| Un contrôle d'EX-9.15 échoue | la raison du contrôle | aucune requête de signature ; affiche chaque raison de `blocking`, et pour `empreinte_divergente` les deux empreintes abrégées de chaque décision, celle de la console et celle du service (EX-9.17) | selon la raison ; pour `empreinte_divergente`, prévient l'administrateur (EX-9.20) |
| Aucun portefeuille annoncé | `aucun_fournisseur` | affiche le message 1 000 ms après la découverte, continue d'écouter (EX-13.22) | ouvre ou installe son portefeuille, ou emploie un autre parcours offert |
| Annonce invalide ou `uuid` revendiqué par deux objets | `annonce_invalide`, `annonce_en_double` | ignore l'annonce, ou exclut l'`uuid` | prévient l'administrateur : une extension imite un portefeuille ; si son vrai portefeuille est exclu, désactive l'extension en cause et recharge la page |
| Fournisseur non choisi | `fournisseur_non_choisi` | le bouton de signature reste inactif | choisit |
| `eth_requestAccounts` rompu par 4001 | `refus_approbateur` | aucun accès ; propose de recommencer sur action explicite | — |
| `eth_requestAccounts` ou `personal_sign` rompu par 4100 | `non_autorise` | redemande `eth_requestAccounts` une fois, puis attend une nouvelle action | autorise la page dans son portefeuille |
| Aucune adresse exposée n'est attribuée à la session | `adresse_non_exposee` | affiche l'adresse active que l'annuaire attribue à la session, sans signature ; la retient dès qu'elle apparaît (EX-13.23) | sélectionne ce compte dans son portefeuille |
| `accountsChanged` retire l'adresse choisie | — | abandonne le choix d'adresse, la requête en cours et l'écran de signature (EX-13.23) | choisit de nouveau |
| `personal_sign` rompu par 4001 | `refus_approbateur` | aucun vote ; affiche « signature refusée dans le portefeuille ; aucun vote n'a été envoyé » | pour s'opposer à la demande, signe `refuse` |
| Rompu par 4200 | `methode_non_prise_en_charge` | ce portefeuille ne peut pas voter ; aucun repli sur une autre méthode | choisit un autre portefeuille |
| Rompu par 4900 ou 4901, ou `disconnect` | `deconnecte`, `chaine_deconnectee` | portefeuille indisponible ; jamais de demande de changement de réseau (EX-13.25) | reconnecte son portefeuille |
| Rompu par un autre code ou sans code numérique | `erreur_portefeuille` | affiche le code et le message comme du texte | réessaie ou change de portefeuille |
| Promesse tenue avec autre chose qu'une chaîne hexadécimale | `reponse_invalide` | aucun vote | change de portefeuille |
| Pas de réponse dans `delai_signature_ms` (EX-13.30), ou échéance du ticket atteinte | `delai_depasse` | cesse d'attendre ; ignore toute réponse tardive, qu'elle n'envoie pas | rejette la requête restée ouverte dans son portefeuille |
| Signature mal formée (longueur, `r`, `s`, `v`) | `signature_invalide` | aucun vote | change de portefeuille et prévient l'administrateur |
| Adresse recouvrée différente de l'adresse choisie | `adresse_differente` | aucun vote ; affiche l'adresse recouvrée | vérifie le compte sélectionné dans son portefeuille |
| Parcours c : relais injoignable, session expirée, échéance à moins de 300 s | `erreur_portefeuille`, `delai_depasse` | aucun vote | emploie le parcours a |
| Parcours d : fichier ou paramètres refusés, mot de passe ou MAC faux, clé hors de l'intervalle | `fichier_cle_invalide`, `fichier_cle_non_pris_en_charge`, `mot_de_passe_ou_mac`, `cle_invalide` | aucune signature ; efface ce qu'elle a dérivé | ressaisit le mot de passe ou emploie un autre parcours |
| `voter` refusé par le service | la raison de 12.8 | affiche la raison ; le vote n'est pas inscrit | selon la raison |
| `voter` sans réponse | — | renvoie le même vote ; `vote_identique` vaut inscription (EX-12.16) | — |
| Notification indépendante (EX-13.3) qui nomme un autre ticket, une autre décision ou une autre empreinte, ou qui n'arrive pas dans le délai fixé par l'organisation | — | hors de la console | prévient l'administrateur par un autre canal ; tant que le ticket accepte des votes, signe la décision voulue depuis une console saine (EX-9.20, point 7) |

Pannes de l'inscription (13.5) :

| Panne | Code | Réponse de la console | Ce que fait l'approbateur |
|---|---|---|---|
| `preparer_inscription` sans réponse ou en erreur | — (`identite_desactivee`, `adresse_deja_attribuee`, …) | aucune signature ; affiche « service indisponible » ou la raison | pour `adresse_deja_attribuee` sur une adresse qu'il détient, ou `identite_desactivee`, prévient l'administrateur (EX-13.17, « Confiscation ») |
| Texte du service refusé par la console (EX-13.13) | `message_invalide`, `origine_differente`, `identite_differente`, `adresse_differente` | aucune requête de signature ; affiche la raison | ne signe rien ; prévient l'administrateur par un autre canal |
| Une ligne du texte affiché ne convient pas à l'approbateur | — | — | refuse dans le portefeuille ; prévient l'administrateur |
| `personal_sign` rompu par 4001 | `refus_approbateur` | affiche « signature refusée dans le portefeuille ; aucune inscription n'a été envoyée » | recommence sur action explicite s'il le veut |
| Rompu par 4100, 4200, 4900, 4901 ou un autre code, réponse invalide, délai | `non_autorise`, `methode_non_prise_en_charge`, `deconnecte`, `chaine_deconnectee`, `erreur_portefeuille`, `reponse_invalide`, `delai_depasse` | aucune inscription ; même réponse que pour un vote | comme pour un vote |
| Signature mal formée, ou qui recouvre une autre adresse | `signature_invalide`, `adresse_differente` | aucune requête `inscrire` | vérifie le compte choisi dans son portefeuille |
| `inscrire` refusé : `inscription_expiree`, `nonce_inconnu` (défi remplacé par une préparation plus récente), `nonce_deja_utilise` | la raison de 12.8 | affiche la raison ; rien n'est inscrit | recommence par une nouvelle préparation, sur action explicite |
| `inscrire` refusé : `organisation_differente`, `identite_desactivee`, `adresse_deja_attribuee`, autre raison | la raison de 12.8 | affiche la raison ; rien n'est inscrit | prévient l'administrateur |

**EX-13.30** **Délai.** La console attend la réponse du portefeuille au
plus `delai_signature_ms` (configuration de la console, défaut 300 000 ms,
de 30 000 à 1 800 000 ms), et jamais au-delà de l'échéance du ticket. Une
signature rendue après ce délai n'est pas envoyée : la console la jette.
Elle reste une signature valable de `D_A` (EX-9.2), c'est-à-dire le vote
que l'approbateur a bien voulu signer, et ne devient un vote qu'aux
conditions d'EX-9.9 (« Signature obtenue hors de la console » : un émetteur
du canal de la console, la session de l'approbateur ou un service
compromis) ; l'approbateur recommence par une nouvelle action s'il veut
voter. Le même délai vaut pour une requête de signature d'inscription. Au
moment du délai, la console affiche la réponse de la colonne « Réponse de la
console » de 13.14 (elle cesse d'attendre et ignore toute réponse tardive,
qu'elle n'envoie pas) ; CT-3 n'exige aucun autre avertissement quand une
réponse tardive arrive. La consigne de rejeter la requête restée ouverte dans
le portefeuille est dans la colonne « Ce que fait l'approbateur », que la
page n'est pas tenue d'afficher (EX-13.29) ; 13.17 (« Voter », pas 6) la
donne à l'approbateur. La console n'a rien d'autre à faire d'une signature
tardive que la jeter. Les parades sont hors d'elle : l'approbateur rejette
la requête restée ouverte dans son portefeuille, et la notification
indépendante d'EX-13.3, recommandée et non obligatoire en version 0, rend
visible un vote inscrit en son nom ; qu'une signature n'ait pas d'échéance
est une limite du format v0, acceptée en version 0 (EX-9.2, 9.3).

### 13.15 Console de référence

La console de référence montre, dans un navigateur réel, que les exigences
de 9.2 à 9.7 et de cette section se tiennent. Elle n'est pas la console
d'exploitation (phase 2) : elle n'a ni authentification, ni notification,
ni serveur ; son serveur de console et le service sont simulés par le test,
et elle emploie les défauts de `service_timeout_ms` et de
`delai_signature_ms` (10.3), sans réglage.

**EX-13.31** Le dépôt livre une console de référence, faite de trois
éléments :

1. `scripts/lib/console.mjs`, bibliothèque sans interface ni dépendance
   (EX-13.32) : modèle d'affichage d'EX-9.4 tiré d'une vue
   (`$defs/modele_affichage`, EX-9.15 à EX-9.19), empreinte et groupes,
   requête de signature (EX-13.24), vérification de la réponse et
   construction du vote (EX-9.21), découverte EIP-6963 (EX-13.22), fichier
   de clé (EX-13.28), identité de session, message d'inscription, sa
   vérification, opérations et contrôles de l'annuaire (13.3 à 13.8) ;
2. une page minimale sous `console/` (EX-13.33 à EX-13.35), qui emploie la
   bibliothèque et offre les parcours a et, par lui, b ; elle n'offre ni le
   parcours c (13.12), ni le parcours d (13.13), ni `window.ethereum` ;
3. un test de bout en bout dans Chromium, par Playwright (EX-13.36), qui
   sert la page, simule le serveur de console et le service, et annonce par
   EIP-6963 un fournisseur EIP-1193 simulé qui signe avec les clés de test
   de A.2. Aucun service réseau réel n'est joint.

**EX-13.32** **Bibliothèque.** `scripts/lib/console.mjs` est un module
ECMAScript sans aucune importation, qui s'exécute à l'identique sous Node 22
(version de l'intégration continue) et dans Chromium : SHA-256, Keccak-256,
secp256k1 (recouvrement, signature RFC 6979), JCS, analyse JSON stricte,
base64 et les primitives du fichier de clé (PBKDF2, scrypt, AES-128-CTR) y
sont écrits en JavaScript sur `BigInt` et `Uint8Array`, sans `eval`, sans
accès au réseau ni au DOM (la découverte reçoit sa cible d'événements en
argument), sans état global. Elle exporte au moins :

| Fonction | Rend | Règles |
|---|---|---|
| `identiteCanonique(champs)`, `analyserIdentite(texte)` | la forme canonique, ou l'erreur `identite_invalide` | EX-13.7 |
| `hachageEvenement(evenement)`, `condenses(a)`, `empreinte(x)`, `groupes(x)` | le hachage d'un événement (CT-1 §6.1) ; `A`, `JCS(A)`, `D_A`, `H`, empreintes et groupes (`$defs/condenses`) | EX-9.17 à EX-9.19 |
| `modeleAffichage(vue, contexte)` | le modèle d'affichage d'EX-9.4 tiré de la vue du ticket (`$defs/modele_affichage`), `contexte` donnant la session, son entrée, la décision, l'adresse, le motif et l'instant : contrôles d'EX-9.15, dont la comparaison de `digests`, avertissements, marque de l'intention (`intent_status`) et effets avec leurs membres non résolus (`unresolved`) | EX-9.4, EX-9.6, EX-9.15 à EX-9.19, EX-12.14 |
| `requetePersonalSign(donnees, adresse)` | `{ "method": "personal_sign", "params": [ données en hexadécimal minuscule, adresse en minuscules ] }`, données d'abord ; `donnees` est `D_A` ou les octets d'un texte d'inscription (`donneesPersonalSign`) | EX-13.24, EX-13.16 |
| `donneesPersonalSign(texteOuOctets)` | `"0x"` suivi de l'hexadécimal minuscule des octets UTF-8 du texte (des octets ASCII pour un message conforme, EX-13.12), ou des octets donnés | EX-13.12, EX-13.16 |
| `verifierSignature(octets, signature, adresse)` | la signature normalisée et l'adresse recouvrée sur le condensé EIP-191 des octets, ou `signature_invalide`, `adresse_differente` | EX-9.3, EX-9.21 |
| `verifierReponse(reponse, donnees, adresse)` | l'issue d'une requête au portefeuille, promesse tenue ou rompue : code de 13.14, ou la signature normalisée par `verifierSignature` | EX-9.21, EX-13.29 |
| `requeteVoter(vue, decision, signature, adresse, motif, session)` | le corps exact de `voter` (`$defs/requete_voter`) | EX-9.21, EX-12.16 |
| `Decouverte`, `decouvrir(annonces)` | la liste des fournisseurs annoncés et les annonces écartées, sans aucun choix | EX-13.22 |
| `lireFichierCle(texte, motDePasse, adresse)`, `signerCondense(cle, d_a)` | le contrôle et le déchiffrement d'un fichier de clé ; la signature RFC 6979 de `H`, puis l'effacement de la clé | EX-13.28 |
| `messageInscription(champs)`, `analyserMessageInscription(texte)` | le texte exact ; les champs, ou `message_invalide` | EX-13.12 |
| `verifierInscription(annuaire, defis, requete, recuA, { identifiant })` | `{ accepted, reason, entry, signature, defis }` : `defis` est la liste après le pas 4 d'EX-13.15, le défi présenté y étant marqué ; `identifiant` vaut `compteur` (convention des vecteurs, A.10) ou `aleatoire` (64 bits, défaut) | EX-13.15 |
| `appliquerOperation(annuaire, methode, requete, at, { defis, nonce, identifiant })` | `{ annuaire, defis, accepted, reason, response }` : le nouvel annuaire et la réponse, ou la raison du refus ; `nonce` est celui que `preparer_inscription` tire (fixé par les vecteurs, aléatoire sinon) | EX-13.13, EX-13.17, EX-13.10 |
| `controleVote(annuaire, session, action, adresse, ticket)` | `{ allowed, reason, warnings }` ; l'adresse est comparée en minuscules | EX-13.18 |
| `actionRetrait(annuaire, session, ticket)` | le `by` d'un retrait que la console peut envoyer : le `launched_by` du ticket quand il figure dans `requester_identities` de l'entrée de la session, sinon l'identité de session quand elle est dans `administrators`, sinon `null` (la console n'offre pas l'action) | EX-13.18, EX-7.15 |
| `controleCanal(annuaire, methode, requete, ticket)` | `null`, ou la première raison `identite_invalide`, `session_non_autorisee` ou `ticket_inconnu` du contrôle de session du service pour `tickets`, `consulter`, `voter`, `recuser` et `retirer`, dans l'ordre d'EX-12.14 et d'EX-12.19 ; `ticket` est nul pour un ticket inconnu dans l'organisation, et pour `tickets` | EX-12.14, EX-12.16, EX-12.19 |
| `recopierAdministrateurs(annuaire, administrateurs, at)` | `{ annuaire, changed }` : l'annuaire après l'opération `changer_administrateurs` si la liste diffère de la copie, inchangé sinon ; `identite_invalide` pour une liste hors de la forme d'EX-13.9 | EX-13.37 |
| `verifierAnnuaireExporte(document, { conforme })` | la liste triée des écarts ; `conforme` est le contrôle du schéma, fourni par l'appelant : sans lui, seule l'erreur `schema` d'un document que la vérification ne peut pas parcourir est garantie | EX-13.19, EX-13.37 |

Le service de référence (phase 2) et les tests emploient les mêmes
fonctions d'annuaire ; `scripts/lib/approbation.mjs` n'en dépend pas.

**EX-13.33** **Page : ce qu'elle DOIT faire.** La page `console/`
(`index.html`, `console.js`, `console.css`) :

1. est faite de fichiers statiques servis depuis l'origine de la console,
   sans construction, sans dépendance externe, sans police ni image tierce ;
   elle charge la bibliothèque depuis la même origine ;
2. charge chaque script par un élément `<script type="module">` qui porte
   `integrity` en `sha384-` ; la bibliothèque est déclarée dans une carte
   d'importation (`<script type="importmap">`) qui porte son intégrité, et
   le condensé `sha256-` de cette carte figure dans `script-src` ;
3. demande à son serveur de console, par la méthode `session` (requête
   `{}`, `$defs/requete_session` ; réponse `$defs/reponse_session`),
   l'identité de session, l'instant d'authentification et le rôle ; elle ne
   lit l'identité nulle part ailleurs. Pour un système `utilisateur` qui ne
   donne pas l'instant d'authentification, `auth_time` est l'instant où le
   serveur de console a reçu cette authentification, et `reauth_max_age_s`
   vaut 0 (EX-13.8). Le `reauth_max_age_s` de la réponse `session` est la
   valeur appliquée à cette session : le réglage du serveur de console (900
   par défaut, 10.3), ou 0 pour un système `utilisateur` qui ne donne pas
   l'instant d'authentification, quel que soit le réglage ; exemple :

<!-- schema: console-service/reponse_session -->
```json
{
  "session_identity": "oidc https://idp.assureur-demo.example approbateur-1",
  "auth_time": "2026-11-12T09:08:12.000Z",
  "administrator": false,
  "reauth_max_age_s": 900
}
```

4. découvre les portefeuilles par EIP-6963 et fait choisir le fournisseur
   par l'approbateur (EX-13.22, EX-13.23) ;
5. pour un ticket : lit la vue (`consulter`) et l'annuaire, applique
   `modeleAffichage` et `controleVote`, affiche le modèle sur un même écran
   (EX-9.4), et n'active « Approuver » et « Refuser » — chacun en un clic
   puis une confirmation, sans choix présélectionné (EX-9.5) — que si toutes
   les vérifications passent ; sinon elle affiche la raison. Le clic puis la
   confirmation sont le choix de la décision (EX-9.20, point 2) ; ce choix
   fait, la page demande la vue fraîche et l'annuaire et applique les
   contrôles d'EX-9.15 et d'EX-13.18 ; l'écran de signature affiche alors
   l'empreinte de cette décision, et seule une action explicite de
   l'approbateur sur cet écran, celle d'EX-13.21, envoie `personal_sign` ;
6. après la réponse du portefeuille, vérifie la signature
   (`verifierSignature`) et n'envoie `voter` qu'avec le corps de
   `requeteVoter`, construit sur la vue du ticket signé ; ouvrir un autre
   ticket abandonne l'écran de signature, la requête en cours et toute
   réponse qui suit (EX-9.21, point 8 ; EX-13.21) ; elle affiche la réponse
   ou la raison du refus (12.8) ;
7. pour une inscription : `preparer_inscription`, reconstruction et
   comparaison du texte (EX-13.13), affichage ligne par ligne,
   `personal_sign` sur le texte, `verifierSignature`, puis `inscrire` ;
8. affiche ses textes en français ; ne construit le DOM que par
   `createElement` et `textContent`.

**EX-13.34** **Page : ce qu'elle NE DOIT PAS faire.** La page NE DOIT PAS :

1. détenir, recevoir, dériver ou importer une clé ; lire un fichier de clé
   (le parcours d, 13.13, n'est pas offert par la page de référence) ; garder
   une signature ou une clé dans `localStorage`, `sessionStorage`, IndexedDB ou
   un cookie ;
2. appeler `eth_sign`, `eth_signTypedData`, `eth_sendTransaction` ou une
   méthode autre que celles des parcours de signature ; appeler
   `personal_sign` hors des cas d'EX-13.16 ; passer `D_A` comme chaîne à
   une bibliothèque (EX-9.7) ;
3. lire `window.ethereum` sans choix explicite de l'approbateur, ni tenir
   `rdns` pour une identité ;
4. charger une ressource d'une autre origine, employer `eval`, `Function`,
   `innerHTML`, un gestionnaire d'événement en ligne ou un script en ligne
   autre que la carte d'importation ;
5. envoyer un vote, une récusation ou une inscription quand une
   vérification a échoué, ni présélectionner une décision ;
6. s'afficher dans un cadre d'une autre page.

**EX-13.35** **En-têtes (EX-13.4 rendu mesurable).** Toute réponse HTML
de la console, de référence ou d'exploitation, DOIT porter un en-tête
`Content-Security-Policy` **bloquant** (pas seulement
`Content-Security-Policy-Report-Only`) au moins aussi restrictif que :

```text
default-src 'none'; script-src 'self' 'sha256-<carte d'importation>'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'
```

et l'en-tête `Integrity-Policy: blocked-destinations=(script)`. Sont
interdits dans `script-src` : `'unsafe-inline'`, `'unsafe-eval'`,
`'strict-dynamic'`, `data:`, `*` et toute origine tierce. `img-src data:`
sert aux icônes des portefeuilles, qu'EIP-6963 veut en URI `data:` et
rendues par `<img>` (R4-F6). Une console d'exploitation qui sert sa page
depuis un cadriciel PEUT remplacer le condensé par un nonce d'au moins
128 bits tiré à chaque réponse (R5-F40). Justification : la CSP n'est pas
une première ligne de défense mais une défense en profondeur (R5-F39) ; la
forme stricte par nonce ou condensé est la pratique recommandée, et
`'strict-dynamic'` la rend moins sûre (R5-F41) ; `object-src 'none'` et
`base-uri 'none'` (R5-F40, R5-F41) ; `frame-ancestors` contre le
détournement de clic, puisque le bouton de vote ne doit pas être encadrable
(R5-F40, R5-F41) ; Trusted Types ferme les injections dans le DOM (R5-F44) ;
l'intégrité des sous-ressources refuse un script altéré (R5-F42) et
`Integrity-Policy` bloque un script chargé sans métadonnée d'intégrité
(R5-F43). Mesures de la révision 0.3 sur le Chromium de Playwright
(141.0.7390.37), avec cette politique : un script en ligne n'est pas
exécuté ; une affectation de chaîne à `innerHTML` lève `TypeError` ; un
module dont les octets ne correspondent pas à l'intégrité de la carte
d'importation, ou un script d'entrée altéré, est bloqué ; un module importé
sans intégrité dans la carte est bloqué par `Integrity-Policy` ; la page
encadrée par une autre ne se charge pas. La prise en charge par d'autres
navigateurs n'est pas mesurée : Trusted Types est pris en charge par
Chrome 83, Firefox 148 et Safari 26, `Integrity-Policy` par Chrome 138,
Firefox 145 et Safari 26, partiellement pour les deux derniers (R5-F43,
R5-F44) ; CSP 3, SRI 2 et Trusted Types sont des projets de travail du W3C
(R5 NV-7).

**Limite.** L'intégrité des sous-ressources protège contre la substitution
d'une ressource, pas contre un serveur d'origine compromis qui sert un autre
document avec d'autres empreintes : la métadonnée d'intégrité vient du
document lui-même (R5-F42). C'est la console compromise de 3.5 et 9.3 ; la
publication des empreintes du document et la construction reproductible
relèvent de CT-7 et CT-8.

**EX-13.36** **Test de bout en bout.** Un test du dépôt charge la page de
référence dans Chromium par Playwright, sans aucun service réseau réel : le
serveur de console et le service sont simulés par interception des requêtes
de la page (même origine HTTPS fictive), et un fournisseur EIP-1193 simulé,
annoncé par EIP-6963, signe avec les clés de test des vecteurs. Il exige
au moins :

| Scénario | Attendu |
|---|---|
| Nominal | deux fournisseurs annoncés, listés, aucun appel avant le choix ; après le choix, le modèle d'EX-9.4 est affiché, chaque argument avec sa marque, et l'empreinte d'EX-9.18 de la décision choisie ; « Approuver » déclenche un seul `personal_sign` dont `params` est exactement `[D_A, adresse]` (66 et 42 caractères, minuscules) ; le corps de `voter` reçu par le service simulé est exactement celui du vecteur ; aucune erreur de script dans la page |
| Refus 4001 | aucun `voter` ; la page dit que la signature a été refusée ; les deux boutons restent offerts |
| Mauvaise adresse | le fournisseur rend une signature d'un autre compte : aucun `voter`, raison affichée |
| Empreinte divergente | `digests` du service différent du calcul de la page : aucun appel `personal_sign`, raison affichée avec les deux empreintes abrégées de chaque décision, celle de la console et celle du service |
| Formes de signature | `v` = 0 ou 1, `s` haut : vote envoyé avec la forme normalisée ; `v` = 29 ou 37, 64 octets : aucun `voter` |
| Changement de ticket | un autre ticket ouvert pendant l'écran de signature, ou pendant les attentes qui suivent le choix ou la signature : aucun écran de signature périmé, aucun `voter` pour le nouveau ticket avec la signature de l'ancien |
| Annuaire | adresse révoquée, entrée inactive, session demandeur, adresse hors jeu : boutons inactifs, raison d'EX-13.18 ; avertissement `separation_incomplete` affiché ; adresse active non exposée, affichée, puis retenue après `accountsChanged` ; `accountsChanged` qui retire l'adresse : écran de signature retiré |
| Inscription | `personal_sign` sur `[texte en hexadécimal, adresse]`, puis `inscrire` exact ; texte du service altéré d'un caractère, ou d'une autre origine : aucun appel au portefeuille ; `inscription_expiree` affichée avec la consigne de recommencer |
| Aucun portefeuille, annonce en double | la page le dit, 1 000 ms après la découverte et pas avant ; `window.ethereum` n'est pas lu (accès espionné) ; un `uuid` revendiqué par deux objets est écarté, les deux annonces comprises ; une réannonce par le même objet est sans effet |
| Politique du contenu | en-têtes exacts d'EX-13.35 ; script en ligne non exécuté ; affectation à `innerHTML` refusée ; bibliothèque servie altérée, ou script d'entrée altéré : la page ne s'initialise pas ; module importé sans intégrité dans la carte : bloqué ; page encadrée : non chargée ; aucune requête vers une autre origine |
| Intention et effets | intention portée par une référence (`console/modeles/intention-par-reference.json`) : marquée « non vérifiable par la console » ; effet dont un membre est tiré du résultat (`effet-connu-apres-execution.json`) : « connu après exécution » ; consignes de l'écran de signature : celles d'EX-9.20, dont la console saine à l'origine `console_origin` |

Le test n'installe aucun navigateur. Sur un poste, il est sauté, avec un
message, si `require("playwright")` échoue ou si Chromium ne se lance pas.
Quand la variable d'environnement `NOORTRACE_EXIGER_CHROMIUM` vaut `1`, le
saut est impossible : la même condition fait **échouer** le test, avec le
même message. L'intégration continue a un travail propre à ce test
(`.github/workflows/ci.yml`, travail `console-chromium`, sur un exécuteur
Ubuntu 24.04, système que Playwright 1.56.1 prend en charge, au contraire
d'Ubuntu 26.04) : il installe Playwright à la version mesurée sans l'ajouter à `package.json`
(`npm install --no-save playwright@1.56.1`), puis son Chromium et ses
dépendances système (`npx playwright install --with-deps chromium`), ce qui
demande l'accès au réseau, pose `NOORTRACE_EXIGER_CHROMIUM=1` et lance
`test/console.test.js` ; un test Chromium en attente y fait donc échouer le
travail. Les versions mesurées sont écrites dans `console/LISEZMOI.md`.

### 13.16 Vérifications AN-

| Id | Vérification | Règle |
|---|---|---|
| AN-1 | Forme canonique d'une identité de session : `oidc` et `utilisateur`, longueur, caractères, `iss` sans `?` ni `#`. | EX-13.7 |
| AN-2 | Message d'inscription : texte exact depuis les champs, octets passés à `personal_sign`, condensé EIP-191, longueur de préimage ; analyse stricte, toute variante refusée. | EX-13.12 |
| AN-3 | Vérification d'une inscription : chaque raison, et l'ordre quand deux défauts se cumulent ; défi présenté une seule fois. | EX-13.13, EX-13.15 |
| AN-4 | Signature d'inscription : normalisation d'EX-9.3, recouvrement sur les octets du texte. | EX-13.15 |
| AN-5 | Séparation des domaines : signature d'inscription refusée comme vote, signature de vote refusée comme inscription. | EX-13.16 |
| AN-6 | Opérations : validation par un administrateur autre que la personne, rotation, révocation, désactivation, réactivation, alias de demandeur ; chaque raison. | EX-13.17 |
| AN-7 | Une personne, une clé : adresse jamais réattribuée, une adresse active par entrée, identité et alias uniques. | EX-13.10 |
| AN-8 | Contrôles de la console avant un vote ou une récusation, ordre des raisons, avertissement `separation_incomplete`. | EX-13.18 |
| AN-9 | Vérification d'un annuaire exporté : invariants, preuves, rejeu des opérations, dont la recopie du réglage `administrators`. | EX-13.19, EX-13.37 |
| AN-10 | Contrôle de l'identité de session par le service sur le canal de la console : `tickets`, `consulter`, `voter`, `recuser`, `retirer` ; `identite_invalide`, `session_non_autorisee`, `ticket_inconnu` et leur ordre. | EX-12.14, EX-12.16, EX-12.19 |

### 13.17 Pas à pas pour l'approbateur

Ce qui suit résume, pour l'approbateur, les règles de 9.2 à 9.7 et de cette
section ; chaque pas renvoie à la règle qui le fonde. Ce pas à pas se suit
sans lire les règles citées : les renvois (EX-…) servent à l'administrateur
et à l'intégrateur, et les termes nécessaires sont dans le lexique.

**Lexique.** Condensé à signer (`D_A`) : les 32 octets que votre clé signe
pour ce ticket et cette décision (EX-9.17). Condensé EIP-191 (`H`) : ce que
certains appareils montrent sous « Message hash » (EX-9.17). Empreinte : les
8 premiers et les 8 derniers des 64 chiffres hexadécimaux d'un condensé
(EX-9.18). Pourquoi deux empreintes : votre portefeuille ne signe pas `D_A`
tel quel ; il signe `H`, calculé en hachant `D_A` précédé d'un en-tête fixe
(EX-9.17 ; 13.9, pas 5). Les portefeuilles lus montrent `D_A` (les 64
chiffres du message) ; certains appareils montrent en plus `H` sous « Message
hash ». La console affiche les deux, chacune sous son intitulé, pour que
chaque valeur de l'écran du portefeuille ait la sienne. Les deux ne se
ressemblent pas : une valeur qui ne correspond pas à son intitulé se refuse
(« Voter », pas 7). Le portefeuille calcule lui-même `H` à partir des 64
chiffres qu'il vous montre ; `H` ne dépend que de `D_A`. Le contrôle qui
compte est donc la comparaison des 64 chiffres montrés sous « Message » (ou
sur la ligne du message) avec l'« empreinte du condensé à signer ».
« Message hash », quand un appareil le montre, est une seconde valeur, qui
se compare à la seconde empreinte, celle dont l'intitulé nomme « Message
hash ». Comparez toujours une valeur à l'empreinte dont l'intitulé lui
correspond. Jeu d'approbateurs (`CuratorSet`) : la liste des adresses qui
peuvent voter, tenue par l'administrateur du jeu (section 8). Délai de
contestation (`contest_ms`) : affiché avec la règle (EX-9.4). Il est fixé
par la règle de la politique d'approbation de l'organisation qui a retenu la
demande (la règle déclenchée, ou la règle par défaut), et la console l'affiche
à côté de cette règle. En bref : à 0, votre refus ne compte que pour atteindre
le seuil de refus, et les autres peuvent encore approuver ; positif, il
empêche en plus toute approbation tant que vous ne votez pas `approuve`. En
détail : s'il est nul,
votre refus est compté parmi les refus, sans bloquer (EX-10.6). S'il est
positif, votre refus, toujours compté parmi les refus, est aussi une
objection : il empêche l'approbation tant que vous ne la levez pas par un
vote `approuve`, qu'il ait été fait avant ou pendant la fenêtre de
contestation (EX-9.13, EX-10.7, EX-10.8). Il n'y a pas d'abstention en
version 0 : un refus ne se retire qu'en votant `approuve` (EX-7.26,
EX-10.8), et se récuser ne le retire pas (EX-10.4). Qui ne veut plus
s'opposer sans approuver laisse son refus ; si le délai de contestation est
positif, le ticket expire alors à l'échéance faute de levée, sauf si le seuil
de refus est atteint (EX-10.7, point 2). Fenêtre de contestation : quand le
délai de contestation est positif, période de cette durée qui s'ouvre dès que
le seuil d'approbation est atteint sans objection ; l'approbation n'est
calculée et remise qu'à sa fin. Un refus pendant la fenêtre l'annule ; un
refus antérieur, non levé, l'empêche de s'ouvrir. Une nouvelle fenêtre
complète ne s'ouvre qu'une fois l'objection levée et le seuil de nouveau
atteint. Elle ne finit jamais après l'échéance : un ticket encore dans sa
fenêtre à l'échéance expire (EX-5.9, EX-10.7 à EX-10.9). `request_hash` : l'empreinte de la
demande retenue, que la console vérifie (EX-9.6). Signature d'un message
(`personal_sign`) : la seule demande de signature que la console adresse à
votre portefeuille ; ce n'est jamais une transaction (9.1). Données typées :
une demande de signature de données structurées (`eth_signTypedData`), que
la console ne fait jamais (EX-13.20). EIP-191 : la règle de signature de
messages qui fait qu'une signature de message ne peut pas servir de
transaction (9.1). Jeu figé : la liste des approbateurs et le seuil retenus
pour ce ticket ; seuls ses membres votent sur ce ticket. Ce sont les membres
et le seuil du `CuratorSet` fixés pour un ticket à son ouverture, ou à la
première lecture réussie qui la suit
(EX-8.4), puis de nouveau si ses membres ou son seuil changent pendant
l'attente (EX-8.6). Seuil effectif : le nombre de votes d'une même décision
exigé pour ce ticket, le plus grand seuil figé pour lui, qui ne baisse donc
jamais (EX-8.6). Nonce : une valeur tirée au hasard par le service pour un
seul message d'inscription (EX-13.13). `oidc <émetteur> <sujet>` : l'adresse
du système de connexion de l'organisation, suivie de l'identifiant stable
qu'il donne à votre compte (EX-13.7). Signature hors de la console : une
signature de 64 chiffres (un condensé de 32 octets) donnée ailleurs que dans
la console ou que dans l'outil du registre que l'organisation vous désigne ;
elle reste valable sans limite de temps (EX-9.2). La seule conduite à
tenir : prévenir l'administrateur par l'autre canal (« Qui prévenir, et
comment », ci-dessous) ; il peut retirer le ticket tant qu'il n'est pas
décidé, ou révoquer votre adresse, et vous changez alors de clé.

**Qui prévenir, et comment.** L'administrateur à prévenir (empreinte
divergente, signature refusée dans le portefeuille, texte d'inscription
refusé, notification qui diffère) est le contact administrateur de
l'organisation, déclaré dans la configuration de la console (10.3), comme en
EX-9.17 ; l'approbateur le connaît par l'organisation et non par la console,
car une console compromise peut afficher un faux contact. Les
administrateurs de l'annuaire, identités de session listées dans
`administrators` (10.3), valident et révoquent les adresses et peuvent
retirer un ticket (EX-13.17, EX-7.15). L'administrateur du jeu, détenteur de
la clé `admin` du `CuratorSet`, ajoute et retire les membres (3.1, EX-13.17,
« Rotation »). L'« autre canal que la console » est celui que l'organisation
désigne à ses approbateurs (téléphone, messagerie interne) : CT-3 ne le fixe
pas. Si vous croyez avoir signé hors de la console un condensé de 32 octets,
prévenez l'administrateur par l'autre canal. Un service conforme n'inscrit
cette signature comme vote que si elle lui parvient par le canal de la
console, au nom d'une session dont l'adresse active est la vôtre, tant que le
ticket accepte des votes ; un service d'approbation compromis peut aussi la
placer dans une remise (EX-9.9). Un administrateur de l'annuaire peut alors
retirer le ticket concerné tant qu'il n'est pas décidé ; le ticket expire
aussitôt (EX-7.15, EX-12.19). Il peut aussi révoquer votre adresse : le
service n'accepte alors plus aucun vote de cette adresse par la console
(EX-12.16), un vote déjà inscrit restant compté (EX-12.18), et vous changez
de clé (« Changer de clé »). Une décision déjà scellée ne s'annule pas
(SG-3). La même clé peut aussi servir, hors de la console, à signer des
opérations du registre NOORTRACE (CT-4). Sur l'écran du portefeuille, elles
ressemblent à un vote (64 chiffres) ; une telle signature obtenue par un
tiers ne produit ni vote ni notification, et c'est la surveillance du
registre par l'organisation qui la révèle. Ne signez 64 chiffres que dans la
console ou dans l'outil du registre que l'organisation vous désigne
(EX-9.9). Si
l'organisation a la notification indépendante, surveillez-la et appliquez
EX-9.20, point 7.

**Ce que l'organisation vous dit, et que CT-3 ne fixe pas.** Demandez à
votre organisation : le contact administrateur et l'autre canal par lequel
le prévenir (10.3, ci-dessus) ; le montant à partir duquel comparer les huit
groupes (EX-9.18) ; les sources où confronter une valeur « non vérifiable par
la console » (« Voter », pas 1) ; si la notification indépendante existe, et
dans quel délai elle arrive (EX-13.3) ; si votre adresse signe aussi des
opérations du registre NOORTRACE, et avec quel outil (EX-9.9) ; l'adresse de
son système de connexion (l'émetteur, la valeur `https://…` qui suit `oidc`
dans la ligne `Identite`), ou le nom de ce système après `utilisateur`
(« S'inscrire », pas 3). Sans seuil connu, les huit groupes peuvent se
comparer pour toute demande (9.3) ; sans source, une valeur non vérifiable
qui compte pour la décision conduit à voter `refuse` (« Voter », pas 1) ; si
l'organisation ne vous désigne aucun outil du registre, ne signez 64
chiffres que dans la console.

**Quel parcours de signature.** La console vous propose toujours le parcours
ordinaire, un portefeuille de navigateur (extension), de préférence relié à
un portefeuille matériel (EX-9.9, EX-13.20). Le portefeuille mobile
(parcours c) ne paraît que si l'organisation l'a activé ; le fichier de clé
(parcours d) ne paraît que si la console de l'organisation l'offre. Si l'un
d'eux paraît, demandez à l'organisation lequel employer.

**S'inscrire, une fois par adresse.**

1. Ouvrir la console à son adresse habituelle et se connecter par le
   système d'identité de l'organisation ; la console peut demander de se
   reconnecter (EX-13.8).
2. Choisir son portefeuille dans la liste de la console (jamais un
   portefeuille choisi d'office), puis le compte à inscrire.
3. Lire le message que la console affiche : l'origine doit être celle de la
   barre d'adresse, l'organisation la sienne, l'adresse celle du compte
   choisi, l'expiration dans quelques minutes, et la deuxième ligne doit
   dire « Ce message n'est pas un vote ». La ligne `Identite` n'est ni votre
   courriel ni votre nom affiché : c'est l'identifiant stable que le système
   d'identité de l'organisation donne à votre compte, `oidc <émetteur>
   <sujet>`, ou `utilisateur <domaine> <nom>` pour un système qui n'est pas
   OIDC (EX-13.7). Vérifier qu'elle commence, après `oidc`, par l'adresse du
   système de connexion de votre organisation (l'émetteur), ou, après
   `utilisateur`, par le nom de ce système. Si vous ne la connaissez pas, ne
   signez pas et demandez-la à l'administrateur par l'autre canal (« Ce que
   l'organisation vous dit »). Le sujet qui suit est un
   identifiant que vous n'avez pas à connaître : la console refuse un texte
   dont l'identité n'est pas celle de la session ouverte
   (`identite_differente`, EX-13.13), et le service aussi (EX-13.15,
   point 8). Si la
   console refuse le texte du service, elle le dit (`message_invalide`,
   `origine_differente`, …) : ne rien signer, et prévenir l'administrateur
   par un autre canal (13.14).
4. Accepter la signature dans le portefeuille : la console lui envoie une
   requête `personal_sign` dont la donnée est le texte affiché (EX-13.16,
   EX-13.12), et le portefeuille montre le même texte. Si une ligne diffère :
   refuser dans le portefeuille, puis prévenir l'administrateur. Si le défi a
   expiré (`inscription_expiree`) ou a été remplacé (`nonce_inconnu`) :
   recommencer par une nouvelle demande, sur action explicite (13.14).
5. Vous votez, sur un ticket dont vous n'êtes pas le demandeur, quand votre
   adresse est validée dans l'annuaire et ajoutée au `CuratorSet`. Pour un
   ticket ouvert après cet ajout, c'est immédiat. Pour un ticket ouvert
   avant, c'est après la prochaine relecture du `CuratorSet` par le service
   (au plus toutes les 10 secondes par défaut), et la console l'indique
   (`membres_ajoutes`). Vous n'avez rien à faire. En détail : l'adresse est
   « en attente » jusqu'à ce qu'un administrateur de l'annuaire, autre que
   soi, la valide, après avoir vérifié par un autre
   canal que vous avez demandé cette inscription (EX-13.17) ; la console le
   montre. Une adresse validée ne permet de voter que si elle est aussi
   membre du jeu d'approbateurs (`CuratorSet`), où l'administrateur du jeu
   l'inscrit, et seulement sur les tickets dont le jeu est figé après cet
   ajout (EX-8.4, EX-8.6) ; sinon la console refuse le vote (`hors_jeu`,
   EX-13.18). Le jeu d'un ticket est figé à son ouverture, ou à la première
   lecture réussie qui la suit (EX-8.4). Une adresse ajoutée au `CuratorSet`
   vote donc sur les tickets ouverts après cet ajout. Personne ne décide de
   re-figer un ticket déjà ouvert : le service surveille le `CuratorSet` et
   re-fige de lui-même chaque ticket en attente de décision dès qu'il
   constate un ajout, un retrait ou un changement de seuil ; il le relit au
   plus toutes les 10 secondes par défaut (`set_poll_interval_ms`, EX-8.5,
   EX-8.6). Une adresse ajoutée au `CuratorSet`, et validée dans l'annuaire,
   vote donc aussi sur les tickets déjà ouverts une fois ce nouveau gel fait ;
   la console la signale (`membres_ajoutes`, EX-9.15).
6. Si la console répond `adresse_deja_attribuee` pour une adresse que vous
   détenez, quelqu'un d'autre l'a inscrite : prévenir l'administrateur, qui
   la révoque ; elle ne vous sera pas rendue, et vous changez de clé
   (EX-13.17, « Confiscation »).

**Changer de clé.** Inscrire la nouvelle adresse comme ci-dessus et
demander à l'administrateur du jeu de l'ajouter au `CuratorSet`. Dès sa
validation, l'ancienne est révoquée et ne peut plus voter par la console,
même sur un ticket dont le jeu figé la contient ; l'administrateur du jeu la
retire ensuite du `CuratorSet`. La nouvelle adresse ne vote que sur les
tickets figés après son ajout (EX-13.17, EX-8.6). **Clé perdue** : la
révoquer. La révocation par la personne de l'entrée est la méthode
`revoquer` (EX-13.17) ; elle n'est pas signée et n'exige que la
réauthentification (EX-13.8). La console de référence (13.15) ne l'offre
pas : si votre console n'a pas cette action, demandez à un administrateur de
l'annuaire de révoquer l'adresse (cause `administrateur`). Puis prévenir
l'administrateur du jeu, qui la retire du `CuratorSet`.

**Voter.**

1. Ouvrir le ticket dans la console et lire la demande sur un même écran
   (EX-9.4) : l'outil, chaque argument et sa marque (« vérifié », « non
   vérifiable par la console »), les effets prévus (« connu après exécution »
   pour une valeur tirée du résultat), la règle, le délai de contestation, la
   délégation, l'intention (« déclarée par l'agent, non vérifiée », ou « non
   vérifiable par la console » quand l'événement la porte par une référence),
   le jeu, les votes et l'échéance. La marque « non vérifiable par la console
   » signale une valeur que la console n'a pas pu confronter à la demande
   retenue : un argument que la pièce scellée ne garde que sous forme rédigée
   ou pseudonymisée (par exemple `[REDIGE:iban]`), un chemin que la rédaction
   a supprimé, ou l'intention portée par une référence (EX-9.6 d, EX-9.15,
   contrôle 4). La valeur affichée vient alors du service seul : ni la console
   ni la signature ne la lient, et un service compromis peut la remplacer dans
   l'affichage (14.5) ; l'appel exécuté reste celui de la demande retenue
   (RL-2). Si cette valeur compte pour la décision, la confronter aux sources
   propres de l'organisation, que CT-3 ne fixe pas, ou voter `refuse`. Ces
   sources (par exemple le dossier de l'opération dans le système de gestion
   de l'organisation) vous sont désignées par l'organisation (« Ce que
   l'organisation vous dit, et que CT-3 ne fixe pas », ci-dessus). Sans une
   telle source, une valeur non vérifiable qui compte pour la décision, comme
   l'IBAN d'un paiement, conduit à voter `refuse`. Pour un paiement dont la
   pièce rédige l'IBAN, cette consigne vaut à chaque demande : confronter
   l'IBAN affiché à la source que l'organisation vous a désignée (par exemple
   le dossier du bénéficiaire dans son système de gestion), ou voter `refuse`.
   Demandez cette source avant votre premier vote sur un paiement.
2. Choisir sa décision, `approuve` ou `refuse` (aucune n'est présélectionnée,
   EX-9.5), et, s'il y a lieu, un motif sans donnée personnelle (EX-13.6).
   Se récuser et retirer la demande sont d'autres actions (EX-13.5).
3. Choisir son portefeuille dans la liste des portefeuilles annoncés
   (jamais un portefeuille choisi d'office, EX-13.22), puis le compte : la
   console ne propose que l'adresse active de son entrée (EX-13.23). La
   console ne demande au portefeuille que deux choses : l'accès à vos
   comptes, dans le portefeuille que vous avez choisi (`eth_requestAccounts`),
   et la signature d'un message, soit 64 chiffres hexadécimaux pour un vote,
   soit le texte affiché pour une inscription (EX-13.16, EX-13.20). Elle ne
   demande jamais de changer de réseau (EX-13.25), ni une transaction, ni des
   données typées. Une telle demande se refuse dans le portefeuille et se
   signale à l'administrateur (EX-9.20, point 5).
4. La console redemande la vue et l'annuaire et refait ses contrôles
   (EX-9.15). Si elle refuse, elle dit pourquoi : adresse non attribuée,
   demandeur du ticket, adresse hors du jeu figé ou non éligible (EX-13.18),
   ou `empreinte_divergente` (EX-9.17) ; il n'y a alors rien à signer, et
   pour `empreinte_divergente` on prévient l'administrateur.
5. Sinon, la console affiche l'empreinte du condensé à signer, `D_A`
   (8 premiers et 8 derniers chiffres, EX-9.18). Demander la signature : la
   console envoie au portefeuille une requête `personal_sign`, c'est-à-dire
   la signature d'un message et jamais d'une transaction, dont la donnée est
   les 32 octets de `D_A` (EX-13.24). Le portefeuille montre ce message en
   64 chiffres hexadécimaux.
6. Comparer les 64 chiffres du portefeuille à l'empreinte affichée sous
   l'intitulé « empreinte du condensé à signer » (`D_A`), les huit groupes
   pour une objection ou un montant élevé (l'organisation dit quel montant
   est élevé : CT-3 n'en fixe pas le seuil). Sur un appareil qui montre aussi
   « Message hash », comparer cette valeur à l'empreinte affichée à part,
   sous l'intitulé « condensé EIP-191, montré par certains appareils sous
   « Message hash » » (`H`), et jamais à l'empreinte du condensé à signer
   (EX-9.20). Sur Ledger, les 64 chiffres de `D_A` sont sous « Message » ;
   « Message hash » ne paraît que si le réglage « Transaction hash » de
   l'application Ethereum est activé, et s'il ne paraît pas, il n'y a rien
   d'autre à comparer. Le réglage « Transaction hash » n'est ni exigé ni
   déconseillé : sans lui, comparer « Message » à l'empreinte du condensé à
   signer suffit ; avec lui, comparer aussi « Message hash » à l'empreinte
   affichée sous l'intitulé « condensé EIP-191 ». Les autres portefeuilles
   lus (MetaMask, Rabby,
   Trezor) ne montrent, d'après leur code, que les 64 chiffres de `D_A`,
   sauf pour un condensé qui est de l'UTF-8, que la console signale
   (`condense_utf8`, EX-9.19) ; avec Trezor, on compare sur l'appareil, et
   non dans la fenêtre de Trezor Connect sur l'ordinateur (table d'EX-9.20).
   Cette table dit où chercher les 64 chiffres d'après le code des
   portefeuilles ; ce qui vous protège n'en dépend pas : si votre écran ne
   montre pas les 64 chiffres en entier, refusez et appliquez le pas 7, cas
   (ii). Vous n'avez donc pas à savoir d'avance ce que l'appareil
   montrera : chaque intitulé dit à quelle empreinte le comparer. Confirmer
   dans le portefeuille si tout concorde. Si la console annonce que le délai
   de signature est dépassé (`delai_depasse` ; 5 minutes par défaut, jamais
   au-delà de l'échéance), rejeter dans le portefeuille la demande restée
   ouverte : elle peut y rester signable, et une signature donnée ensuite
   reste valable sans limite de temps, même si la console ne l'envoie pas
   (EX-9.2, EX-13.30). Recommencer par une nouvelle action pour voter.
7. Deux cas se distinguent, l'un et l'autre tirés d'EX-9.20, point 5.

   (i) L'empreinte diffère, ou le portefeuille montre une transaction ou des
   données typées : la page de la console ou une extension du navigateur
   peut être compromise. Refuser dans le portefeuille, ne pas réessayer
   depuis cette page, et prévenir l'administrateur par un autre canal que la
   console (EX-9.20) ; pour s'opposer à la demande, signer `refuse` depuis
   une console saine (ci-dessous).

   (ii) Le portefeuille ne montre pas les 64 chiffres en hexadécimal, en
   entier (par exemple du texte à la place, EX-9.19) : refuser dans le
   portefeuille et ne pas voter avec ce portefeuille ; recharger la page de
   la console, puis voter avec un autre portefeuille qui détient la même clé
   et montre les 64 chiffres (EX-9.20, point 5) ; si aucun ne détient la
   clé, inscrire une autre adresse (« Changer de clé »).

   Refuser dans le portefeuille n'est pas voter `refuse` : aucun vote n'est
   envoyé (EX-13.29). Pour s'opposer à la demande, signer `refuse` depuis
   une console saine, au sens d'EX-9.20, point 5 : la console de
   l'organisation, ouverte à l'adresse de la ligne `Origine` de votre
   inscription (`console_origin`, EX-13.14), dans l'un de ces cas : (a) sur
   un autre poste que celui où l'écart est apparu ; (b) sur le même poste,
   dans un autre profil du navigateur, sans extension (l'administrateur peut
   vous dire comment l'ouvrir) ; (c) après que l'administrateur prévenu vous
   a dit avoir écarté la cause. Les trois cas sont des alternatives : si
   vous ne savez pas ouvrir un autre profil sans extension (b), employez un
   autre poste (a), ou attendez que l'administrateur vous dise avoir écarté
   la cause (c). « Saine » ne désigne que ces conditions :
   ce n'est pas une vérification que vous faites vous-même, et des empreintes
   qui concordent ne la prouvent pas (EX-9.20). Un administrateur de l'annuaire (`administrators`) prévenu peut
   aussi retirer le ticket tant qu'il n'est pas décidé, et le ticket expire
   aussitôt (EX-13.5, EX-7.15, EX-12.19) ; sinon, votre opposition ne compte
   qu'une fois `refuse` signé.
8. Après le vote, si l'organisation a mis en place la notification
   indépendante (EX-13.3), vérifier qu'elle annonce le vote inscrit en son
   nom avec le ticket, la décision choisie et l'empreinte affichée ; si elle
   diffère, ou n'arrive pas dans le délai que l'organisation a fixé,
   prévenir l'administrateur et, tant que le ticket accepte des votes,
   signer la décision voulue depuis une console saine (EX-9.20, point 7).

**Échéance.** Sans décision avant l'échéance (au plus 24 heures après la
demande), le ticket expire : l'action retenue n'est pas exécutée, et le délai
ne vaut jamais approbation (EX-7.10). L'échéance est fixée par la politique
de l'organisation (`expire_after_ms`, au plus 24 heures, 7.6, EX-7.10), qui
peut la fixer plus courte ; la console l'affiche avec le temps restant
(EX-9.4). Une escalade n'est qu'une notification de plus, qui ne change ni le
jeu, ni le seuil, ni l'échéance (EX-7.13).

### 13.18 Échanges, de bout en bout (pour l'intégrateur)

Chaque message entre la page et le service passe par le serveur de console
(12.9). **Imposer** `session_identity`, c'est, pour le serveur de console,
relayer la requête avec, pour `session_identity`, l'identité de la session
qu'il a authentifiée, quelle que soit la valeur que la page a mise ; une page
conforme y met déjà cette valeur, lue par la méthode `session` (EX-13.33,
point 3). Le serveur de console impose `session_identity` sur chaque méthode
qu'il relaie au service ; `session`, qu'il sert lui-même sans relais, a un
corps vide et rend cette identité (EX-13.33, point 3). Il vérifie la
réauthentification avant chaque méthode de la liste d'EX-13.8.

> **Réglages et formes réunis** (définis dans la table de 10.3 et dans les
> schémas). Réglages : `reauth_max_age_s`, défaut 900, de 0 à 3 600,
> configuration du serveur de console (EX-13.8) ; `service_timeout_ms`,
> défaut 10 000, configuration de la console (12.7) ; `delai_signature_ms`,
> défaut 300 000, de 30 000 à 1 800 000, configuration de la console
> (EX-13.30) ; contact administrateur de l'organisation, configuration de la
> console (10.3). Formes : le corps de `tickets` est `{ session_identity }`
> (`$defs/requete_tickets` de `console-service-v0`) ; ceux de `recuser`
> (`{ ticket, approver, session_identity }`, EX-12.16) et d'`annuaire`
> (`{ session_identity }`, 13.9, pas 1) sont donnés plus haut. Schémas :
> `console-approbation-v0`, `console-service-v0` et
> `annuaire-approbateurs-v0` (`spec/schemas/`).
>
> **Hors des sections 7.4, 9, 12 et 13**, l'intégrateur a besoin : des trois
> schémas (`console-approbation-v0`, dont `$defs/vue_ticket`,
> `$defs/modele_affichage` et `$defs/code_console` ; `console-service-v0` ;
> `annuaire-approbateurs-v0`) ; de CT-1 §6.1 (préfixe `P_H` et hachage d'un
> événement, contrôle 2 d'EX-9.15) ; de 10.1 (`eligible`, EX-10.3) ; de 10.3
> (réglages) ; d'EX-4.4 (résolution d'un pointeur, EX-9.16).

**Inscription.** Page → serveur de console : `session` (`{}`). Page →
portefeuille : découverte EIP-6963, choix, `eth_requestAccounts` (EX-13.22,
EX-13.23). Page → serveur de console → service : `preparer_inscription {
session_identity, address }` → `{ fields, message }`. Page :
`messageInscription(fields)` égal à `message`, origine, identité, adresse
vérifiées, sinon arrêt (`message_invalide`, `origine_differente`,
`identite_differente`, `adresse_differente`, EX-13.13). Page → portefeuille :
`request({ method: "personal_sign", params: [ hex(message), address ] })` →
signature, ou erreur 4001 (arrêt, rien n'est envoyé). Page :
`verifierSignature`, sinon arrêt. Page → serveur de console → service :
`inscrire { session_identity, address, message, signature }` → `{ entry,
address, state: "en_attente", revision }` ou une raison de 12.8.
Administrateur, depuis sa session : `valider { session_identity, entry,
address }` → `state: "active"`.

**Vote** (détail des neuf pas en 13.9). Page → serveur de console →
service : `consulter` et `annuaire`, trois fois, chacune à chaque vote
(13.9, « Lectures de la vue et de l'annuaire ») : au pas 1, pour
l'affichage ; au pas 3, après le dernier des choix (décision, fournisseur,
adresse), lecture sur laquelle portent les treize contrôles d'EX-9.15 ; au
pas 7, après la vérification de la signature et avant `voter`, où, si le
`state` de la vue ou le `revision` de l'annuaire a changé depuis la lecture
du pas 3, la console refait les contrôles d'EX-13.18 (conditions 1 à 6,
`controleVote`). Un changement de la vue sans changement de `state` (votes,
nouveau gel
d'EX-8.6 sur un ticket resté `ouvert`, fenêtre) n'oblige pas à refaire ce
contrôle : le service refait EX-9.3 et EX-9.10 à la réception du vote (par
exemple `hors_jeu` après un nouveau gel). Page : contrôles d'EX-9.15, dont
les vérifications d'EX-9.6, la
comparaison de `digests` (EX-9.17) et ceux d'EX-13.18 ; tout écart arrête
avant le portefeuille. Page → portefeuille : `personal_sign` sur
`[D_A, adresse]` (EX-13.24). Page : `verifierReponse` (EX-9.21). Page →
serveur de console → service : `voter` (EX-12.16) → `{ ticket, state }`, ou
`session_non_autorisee`, ou une raison d'EX-9.10.

**Retrait.** Page → serveur de console → service : `retirer { ticket, by,
reason, session_identity }`, `by` étant, selon EX-13.18, le `launched_by`
du ticket quand il figure dans `requester_identities` de l'entrée de la
session, sinon l'identité de session quand elle est dans `administrators` ;
dans aucun autre cas la console n'offre l'action (fonction
`actionRetrait(annuaire, session, ticket)` de la bibliothèque, qui rend ce
`by` ou `null`, EX-13.32) → `{ ticket, state }`, ou `session_non_autorisee`
(EX-12.19), ou
`retrait_non_autorise`, `ticket_non_ouvert`, `ticket_clos_aux_votes`
(EX-7.15, T10).

**Parcours c.** CT-3 en fixe seulement : la requête `request` d'EX-13.27,
point 4 (`personal_sign` sur les deux chaînes d'EX-13.24, `expiry` au moins
maintenant + 300 s et au plus l'échéance du ticket ; parcours non offert,
`delai_depasse`, si l'échéance est à moins de 300 s) ; le traitement de la
réponse par EX-9.21 (EX-13.27, point 5) ; l'abandon au délai
`delai_signature_ms` (EX-13.30) ; les conditions 1 à 3 d'EX-13.27 (SDK livré
avec la console et `connect-src` réduit au relais configuré, identifiant de
projet limité à l'origine de la console, URI d'appariement montrée à la
seule session de l'approbateur) ; et, pour l'approbateur, la comparaison de
l'empreinte (point 6). Tout le reste, `chainId` compris, relève de la Sign
API de WalletConnect v2 et reste à éprouver par l'organisation qui active le
parcours (13.12, section 16).

**Ce que la console refuse**, avant tout appel au portefeuille : une vue
dont l'événement `retenue`, la pièce ou un champ affiché ne concorde pas
(EX-9.6) ; un `D_A` différent de `digests` (EX-9.17) ; une identité de
session non canonique ; une adresse non attribuée, un demandeur, une adresse
hors du jeu figé ou non éligible (EX-9.15, EX-13.18) ; un texte
d'inscription différent de celui qu'elle reconstruit (EX-13.13) ; toute
méthode autre que `eth_requestAccounts` et `personal_sign`, et
`window.ethereum` sans choix explicite (EX-13.20, EX-13.22). Après le
portefeuille : une réponse qui n'est pas une signature de 65 octets de forme
admise, ou qui ne recouvre pas l'adresse choisie (EX-9.21), et toute réponse
arrivée après le délai, après un changement de décision ou d'adresse, ou
après l'ouverture d'un autre ticket (EX-13.21, EX-13.30). Chaque panne de
13.14 (4001, 4100, 4200, 4900, 4901 ou `disconnect`, autre code ou absence
de code numérique, réponse qui n'est pas une chaîne hexadécimale, délai)
reçoit la réponse des tables d'EX-13.29 : aucune ne produit de vote, et un
refus dans le portefeuille (4001) n'est pas un vote `refuse`.

## 14. Sûreté

### 14.1 Fractionnement d'un montant

Un agent qui sait qu'un paiement au-dessus de 5 000 CHF est retenu peut en
faire deux de 3 000 CHF. Le langage de la section 4 évalue un appel seul,
sans autre état que les fenêtres : la version 0 ne détecte pas un
fractionnement. Parades en v0 : ne pas dire à l'agent quelle règle l'a
arrêté (EX-11.8) ; des seuils bas et des règles par bénéficiaire
(section 4) ; une règle `fenetre` plutôt qu'une règle `automatique` pour les
montants moyens, dont le plafond `max_calls` et la portée (même outil, même
demandeur, mêmes valeurs désignées) bornent ce qu'une approbation laisse
passer (EX-5.2, EX-5.5) : au plus `max_calls` appels couverts, plus l'appel
ouvrant, chacun dans la condition, par portée. Pour l'exemple de 4.3, hors
appel ouvrant, une fenêtre couvre au plus 20 appels d'au plus 5 000 CHF
chacun, soit au plus 100 000 CHF en 8 heures par couple (demandeur,
bénéficiaire) ; la revue a posteriori des appels autorisés, que la chaîne
rend complète. Des prédicats cumulatifs (somme par
bénéficiaire et par période) exigent un état partagé du service, que deux
implémentations doivent évaluer à l'identique : proposition pour une
version 1 (section 16).

### 14.2 Rejeu d'une décision

| Rejeu | Ce qui l'empêche |
|---|---|
| Signature d'un ticket présentée pour un autre ticket, un autre journal, une autre organisation | `A` porte `ticket`, `journal_id`, `org_id` et `request_hash` (CT-1 §6.3) : `D_A` diffère, SG-5 échoue |
| Signature `approuve` présentée comme `refuse`, ou l'inverse | `decision` est dans `A` (EX-9.1) |
| Seconde décision pour un ticket décidé | SG-3 ; le noyau est le seul scelleur |
| Approbation scellée relayée deux fois | consommation unique tenue par le service (EX-7.17), y compris en mode `retenir` (`held`, T11), et vérifiée par le noyau : aucun appel `executee` ni intention ouverte ne porte déjà l'approbation (RL-3, CT-2 EX-7.21) ; une continuation MRTR, qui hérite de l'approbation, n'est relayée qu'une fois par `requestState`, inscrit et consommé par le noyau, puisque le protocole ne garantit pas l'usage unique d'un `requestState` (RL-3 en mode continuation, CT-2 EX-4.21, EX-12.23) |
| Approbation scellée relayée pour un autre appel que la demande retenue (« blanchiment ») | le noyau relaie l'objet de sa propre décision (RL-1) et compare l'appel à la demande retenue : outil, délégation, référence de la pièce « arguments » et MAC à clé du JCS intégral des arguments en clair (RL-2, CT-2 EX-7.21, EX-7.22) |
| Approbation scellée réutilisée des semaines plus tard | délai de reconnaissance (7.6) : après lui, une même demande ouvre un nouveau ticket ; et le noyau refuse tout relais à partir de `approval.at + E`, `E` de la version de la demande (RL-4, CT-2 EX-7.21) |
| Décision d'une autre demande sous un identifiant réattribué après une perte d'état | identifiant unique malgré la perte d'état (EX-7.1) ; T14 exige le même `request_hash`, sinon T20 ; le noyau refuse de sceller une `retenue` dont le ticket a déjà une décision scellée (CT-2 EX-7.17) |
| Signature non canonique (`s` haut) | refusée par le noyau (SG-5), normalisée par le service à la réception (EX-9.3) |
| Signature d'une autre forme : `v = 37` ou `38` (EIP-155), signature compacte de 64 octets, `s` haut, `v ∈ {0, 1}` | la console et le service contrôlent la forme avant toute bibliothèque, qui en accepterait certaines (EX-9.22) : `v ∈ {0, 1}` et `s` haut sont normalisés, le reste refusé (EX-9.3, EX-9.21) ; le noyau refuse toute forme non canonique (SG-5) |
| Signature EIP-191 rejouée comme transaction | impossible : préfixe `0x19` (R2-F44) |

EIP-712 laisse aussi le rejeu à l'application (R2-F49,
https://github.com/ethereum/EIPs/blob/f1bcca1b56ee91fe115d2a8d8fd731fd6ca38bb3/EIPS/eip-712.md) :
en v0, c'est la décision unique et la consommation unique qui le ferment.

### 14.3 Approbation hors délai

Une remise `approuve` ou `refuse` que le noyau ne peut pas sceller avant
l'échéance est refusée (SG-4) ; une décision remise à temps mais non scellée
à l'échéance devient caduque (EX-7.10) ; un ticket encore dans sa fenêtre de
contestation à l'échéance expire (EX-10.9). Les horloges du service et du
noyau DOIVENT être synchronisées comme celle de l'enregistreur (CT-2
EX-7.10) ; seul le noyau tranche (SG-4).

### 14.4 Substitution du jeu

| Attaque | Parade | Reste |
|---|---|---|
| Le service déclare un faux jeu (membres qu'il contrôle) | SG-6 ne compare qu'au jeu remis ; le réviseur peut relire le jeu à la hauteur de `source` (8.5) | en v0, le jeu reste « déclaré par le dossier » (CT-6) ; un service compromis peut faire sceller une décision signée par de fausses adresses : la parade est le canal authentifié et l'intégrité du service (CT-7). SG-1 ne contrôle que la forme de `source` ; comparer `c=` et `r=` à la politique ne parerait pas un service compromis, qui recopie ces valeurs et invente `s=` et `members` |
| Le jeu change pendant l'attente (membre retiré ou ajouté, seuil changé) | surveillance et nouveau gel (EX-8.5, EX-8.6), seuil effectif qui ne baisse jamais, membres ajoutés signalés, confirmation avant remise (EX-8.7) | une lecture d'état non prouvée (EX-8.2) ; des membres ajoutés par l'administrateur du jeu votent |
| L'administrateur du registre réassigne le jeu de l'organisation | le jeu est épinglé par la politique (`approver_set.set`) : la lecture d'un autre jeu est illisible (`jeu_non_attendu`) et le ticket expire (« jeu reassigne ») ; adopter un autre jeu exige une nouvelle version de politique, journalisée (EX-8.1, EX-8.6) | bloquer les approbations jusqu'à cette version (déni de service, public sur la chaîne) |
| Un jeu `statique`, écrit par l'opérateur, remplace celui du registre | refusé au chargement en production (EX-8.2) ; sa `source` le nomme (EX-8.8) | rien n'empêche l'opérateur de déclarer `developpement` : la valeur est dans la configuration, pas dans la chaîne |
| Le nœud RPC sert un état faux | interroger un validateur que le client opère ou un validateur partenaire (EX-8.2) | aucune preuve d'état dans noorcore (R1-F80) |

### 14.5 Confusion d'arguments

| Risque | Parade |
|---|---|
| La politique et le serveur d'outils lisent des valeurs différentes (grands entiers, décimaux) | CT-2 EX-4.44 refuse un nombre que la double précision ne représente pas exactement ; les montants sont des chaînes décimales (CT-1 §3) ; la section 4 compare des décimaux exacts |
| Clés en double, JSON ambigu, second message caché dans les arguments | analyse stricte et retrait des blancs (CT-2 §4.4 pas 1 et CT-2 EX-4.43) |
| L'approbateur voit un champ, le serveur en lit un autre (champ inconnu de la règle) | la console affiche tous les arguments (EX-9.4) ; la section 4 dit le sort d'un argument absent ou d'un autre type ; un prédicat qui borne les membres d'un objet (`membres_parmi`) est proposé (section 16) |
| Liste d'exclusion à égalité exacte (`egal`, `dans` sous un refus) contournée par une autre écriture de la valeur | avertissement d'EX-4.14 ; une liste blanche (`egal` ou `dans` sous un nombre impair de `none`) ne laisse rien passer |
| Le service affiche d'autres arguments que ceux de la demande retenue | la console vérifie l'événement `retenue` et la pièce « arguments » (EX-9.6 c et d) ; reste une valeur rédigée (`beneficiary_iban` sous `pii-v1`), qu'un service compromis peut substituer sans que la signature le révèle |
| Arguments modifiés entre la demande et le relais | la clé de rapprochement exige les mêmes arguments en clair (EX-7.3) ; le relais reprend les octets de la ré-émission, de même valeur. Le noyau compare l'appel relayé à la demande retenue : outil, délégation, référence de la pièce et MAC à clé du JCS intégral en clair (RL-2, CT-2 EX-7.21, EX-7.22), de sorte qu'un changement d'un seul champ rédigé est refusé avant le relais ; une continuation MRTR, qui n'est pas réévaluée, n'hérite d'une décision qu'avec le même MAC que l'appel d'origine (CT-2 EX-4.21) |
| La pièce rédigée ne montre pas le clair : `request_hash` ne lie que la forme rédigée | limite de v0 (CT-1 §5.4) ; la clé de rapprochement lie le clair dans le service |

### 14.6 Déni de service par tickets

**EX-14.1** Le service DOIT borner le nombre de tickets non décidés (états
`reserve` à `a_remettre`) par `launched_by` à `max_open_tickets` (10.3,
défaut 20). Un `launched_by` fixe partagé par plusieurs personnes partage
aussi ce plafond : la configuration de CT-2 DEVRAIT donner un `launched_by`
par personne (`${oauth_subject}`, `${peer_user}`). Au-delà,
une demande que l'évaluation retiendrait (`a_approuver`) ne crée pas de
ticket : le service rend l'erreur `plafond_atteint` (12.3, 12.8), que le
noyau traite comme une indisponibilité du service (`-31010`, raison
`approbation`, CT-2 §14.2) : l'appel n'est pas relayé, le défaut est
consigné au journal d'exploitation, et l'administrateur est notifié. Une
ré-émission reconnue d'un ticket existant n'est pas concernée. Le plafond
n'est pas une décision de la politique : il n'entre ni dans `policy.rule` ni
dans l'algorithme de la section 6, qui reste le seul à produire une
décision (EX-6.1).

**EX-14.2** Les notifications d'un même approbateur DEVRAIENT être
regroupées au-delà d'un débit fixé par la configuration du service, et la
console DOIT montrer le nombre de tickets ouverts par demandeur, ainsi que
les tickets refusés ou expirés du même demandeur et du même outil depuis
moins de `E` (EX-13.3) : une rafale de demandes, ou la même demande
rouverte par une variation cosmétique, ne doit pas pousser un approbateur à
approuver sans lire.
Les ré-émissions en attente ne produisent pas d'événement (EX-7.19) et les
quotas par connexion d'hôte de CT-2 (EX-4.47 de CT-2) bornent le reste.

### 14.7 Adversaires

| Adversaire (section 3) | Ce que CT-3 l'empêche de faire | Ce qu'il peut encore faire |
|---|---|---|
| Agent | relayer un appel retenu sans décision ; réutiliser une approbation pour d'autres arguments ou deux fois (EX-7.17), y compris par une continuation MRTR à champ rédigé changé ou par un `requestState` rejoué (CT-2 EX-4.21) ; rouvrir aussitôt une demande refusée en la répétant à l'identique (EX-7.18) ; profiter de la fenêtre d'un autre outil (EX-5.2) | fractionner et sonder les seuils (14.1) ; rouvrir une demande refusée par une variation cosmétique des arguments, qui est une nouvelle demande soumise aux approbateurs (EX-13.3, EX-14.2) ; harceler les approbateurs dans la limite du plafond (14.6) |
| Opérateur de l'agent (demandeur) | approuver sa propre demande avec une adresse déclarée pour lui (`self_approval: "interdite"`, EX-10.2) | se faire approuver par un complice du jeu ; voter avec une adresse non déclarée pour lui (EX-10.5) ; choisir `permise` s'il administre la politique (le changement est journalisé) |
| Approbateur malveillant ou contraint | décider seul quand `t ≥ 2` ; approuver hors délai | approuver avec un complice ; bloquer par une objection (fenêtre) jusqu'à l'expiration |
| Console compromise, ou émetteur sur le canal console → service | signer à la place de l'approbateur (EX-13.1) ; émettre sans identifiants valides (EX-12.4) ; effacer un refus par une récusation (EX-10.4) | faire signer un autre `D_A` que celui qu'elle affiche, ou `approuve` pour qui voulait refuser (9.3, limite de v0 ; parade : la notification indépendante, EX-13.3, l'outil hors ligne n'étant pas livré en v0) ; faire signer, présenté comme un vote, un condensé du registre de CT-4, sans vote inscrit ni notification (EX-9.9 ; parades : comparaison des huit groupes, surveillance du registre) ; dans le parcours d, lire le mot de passe et la clé déchiffrée, puis signer à la place de l'approbateur (EX-13.28) ; forger une récusation, qui ne retire qu'une approbation, ou un retrait, qui fait expirer le ticket (non signés en v0, section 16) ; ne pas transmettre un refus |
| Extension ou fournisseur malveillant dans le navigateur de l'approbateur | être choisi sans action de l'approbateur (EX-13.22) ; faire passer une signature d'un autre condensé, ou d'une autre adresse, pour un vote sur la demande affichée (EX-9.21) | faire signer par le vrai portefeuille le `D_A` d'une autre demande retenue, si l'approbateur ne compare pas l'empreinte (EX-9.20), puis le faire transmettre par un émetteur du canal de la console ; bloquer la signature |
| Relais du parcours mobile (13.12) | lire `D_A`, l'adresse ou la signature (chiffrement de bout en bout, R4-F29) ; faire accepter une réponse forgée (EX-9.21) | savoir quand et entre quels clients des messages passent ; retenir ou retarder les messages (R4-F30, R4-F31) |
| Service d'approbation compromis | faire sceller une décision `approuve` ou `refuse` sans signatures valides au seuil du jeu qu'il déclare (SG-5, SG-6), ou signée par une adresse déclarée du demandeur (SG-7) ; s'aligner sur la décision d'une autre demande (T14, T20, CT-2 EX-7.17) ; blanchir une approbation en faisant relayer un autre appel sous elle, ou le même deux fois (RL-1 à RL-4, CT-2 EX-7.21) ; afficher d'autres arguments que ceux de la demande retenue, hors champs rédigés (EX-9.6) | rendre `autorise` à tort, y compris pour une demande déjà retenue (non signé, EX-12.2 ; la chaîne le montre après coup : un appel relayé `autorise` après un `retenue` du même outil) ; déclarer un faux jeu (14.4) ; ignorer la fenêtre de contestation (EX-9.12) |
| Administrateur du jeu | abaisser le nombre de signatures d'un ticket en attente (seuil effectif, EX-8.6) | changer les membres ou le seuil : visible sur la chaîne, et pris en compte par les tickets ouverts (8.3) ; ajouter des membres qu'il contrôle, signalés |
| Administrateur du registre | faire décider un ticket par un jeu réassigné (jeu épinglé, EX-8.1, EX-8.6) | bloquer les approbations jusqu'à une nouvelle version de politique (14.4) |
| Exploitant du nœud RPC | — | servir un état faux du registre ou du jeu : aucune preuve d'état en v0 (14.4) |

### 14.8 Annuaire et inscription

| Attaque | Parade | Reste |
|---|---|---|
| Inscrire l'adresse d'un autre à son nom | la preuve de possession exige la signature de l'adresse sur un texte qui nomme l'identité (EX-13.15) | — |
| Faire signer à une personne une inscription de son adresse au nom de l'attaquant (confiscation) | le texte lisible nomme l'identité, l'origine et l'adresse ; le service exige que l'identité du message soit celle de la session qui présente la preuve (EX-13.15, pas 8) ; l'administrateur ne valide qu'après avoir établi, par un autre canal, que la personne de l'entrée détient l'adresse (EX-13.17, « Avant de valider ») | l'attaquant n'a besoin que de sa propre session : il prépare l'inscription de l'adresse de la victime, lui fait signer, sur un site d'hameçonnage, le texte qui nomme sa propre identité, puis le présente ; l'adresse est confisquée dès l'état `en_attente`, sans validation (EX-13.10, point 2) : l'administrateur la révoque et le détenteur change de clé (EX-13.17, « Confiscation » ; trace `annuaire/traces/confiscation.json`) ; déni de service ciblé, visible dans `operations` |
| Rejouer une preuve | nonce à usage unique, expiration, adresse jamais réattribuée (EX-13.13, EX-13.10) | — |
| Faire prendre une inscription pour un vote, ou l'inverse | préimages distinctes ; vérifications sur `D_A` reconstruit et sur le texte du défi (EX-13.16) | — |
| Administrateur malveillant | il ne valide pas sa propre adresse (`auto_validation`) ; ses opérations sont inscrites (`operations`) | il valide l'adresse d'un complice inscrite par celui-ci, lie un alias de demandeur à une mauvaise entrée : visible dans l'annuaire, sans effet sur le jeu, le seuil ni SG-7 (EX-12.18) ; il révoque ou désactive l'entrée d'un membre, qui ne peut plus voter par la console : déni de service, visible dans `operations` |
| Session volée (jeton ou cookie de la console) | réauthentification depuis au plus `reauth_max_age_s` avant chaque méthode qui modifie l'annuaire ou un ticket (EX-13.8) ; une adresse inscrite sous la session volée attend une validation que l'administrateur ne donne qu'après vérification par un autre canal (EX-13.17) ; la clé n'est pas dans la session (EX-13.1) ; notification de chaque opération de l'annuaire qui vise la personne (EX-13.3) | dans la fenêtre de `reauth_max_age_s`, ou à chaque réauthentification réussie par l'attaquant : révoquer l'adresse active de la personne, définitivement (EX-13.10, point 2), ce qui l'empêche de voter par la console jusqu'à une rotation de clé dans le `CuratorSet` (déni de service, visible dans `operations`, cause `personne`) ; inscrire une adresse de l'attaquant, en attente ; récuser la personne sur un ticket, ou retirer un ticket qu'elle a demandé ; lire les vues qu'elle peut voir |
| Console compromise | présenter sous une identité de session le vote d'une adresse qui n'est pas l'adresse active de son entrée (`session_non_autorisee`, EX-12.16), ou un retrait sous une session qui n'est ni le demandeur ni un administrateur (EX-12.19) ; signer, hors du parcours d (EX-13.1) | présenter un vote signé par une adresse sous l'identité de session de son entrée sans que la personne soit connectée, le service ne voyant pas l'authentification (EX-13.8) ; omettre les contrôles d'EX-13.18 |
| Service compromis | — | il fausse l'annuaire ; les preuves restent vérifiables (EX-13.19) et le jeu figé ne dépend pas de l'annuaire |

### 14.9 Parcours de signature

| Attaque | Parade | Reste |
|---|---|---|
| Un faux portefeuille s'annonce sous le nom, l'icône ou le `rdns` d'un autre (R4-F6) | aucun choix implicite ; un `uuid` revendiqué par deux objets est exclu ; `rdns` n'est pas une identité (EX-13.22) ; un fournisseur qui n'a pas la clé de l'approbateur ne rend pas une signature qui recouvre l'adresse choisie (EX-9.21) | une extension qui réannonce, avec un autre objet, l'`uuid` d'un vrai portefeuille lu dans son annonce le fait exclure pour la vie de la page : déni de service, contre lequel l'approbateur désactive l'extension et recharge la page (13.14) ; un faux fournisseur qui relaie vers le vrai en changeant `params[0]` relève de la ligne suivante ; une identité attestée des portefeuilles est hors de la version 0 (section 16) |
| Une extension s'interpose entre la page et le portefeuille et remplace `params[0]` par le `D_A` d'une autre demande | l'écran du portefeuille montre le condensé réellement signé, que l'approbateur compare à l'empreinte (EX-9.20) ; une signature d'un autre condensé ne recouvre pas l'adresse choisie sur le `D_A` de la console : aucun vote n'est envoyé (EX-9.21) | si l'approbateur ne compare pas, la signature de l'autre demande existe ; elle ne devient un vote qu'aux conditions d'EX-9.9 (« Signature obtenue hors de la console ») |
| Le fournisseur rend une signature forgée, malléable ou d'une autre forme | contrôle de forme, normalisation, recouvrement sur `H` et comparaison à l'adresse choisie (EX-9.21, EX-9.22) | — |
| Une bibliothèque encode `D_A` comme la chaîne `"0x…"` | la signature ne recouvre pas l'adresse sur `H` : `adresse_differente` (EX-9.7, EX-9.21) | — |
| Le service sert un événement, une pièce, des champs ou un `D_A` qui ne sont pas ceux de la demande retenue | contrôles d'EX-9.15 : `evenement_invalide`, `piece_invalide`, `champ_different`, `argument_different`, `empreinte_divergente` ; la console ne fait jamais signer le `D_A` du service (EX-9.17) | une valeur rédigée de la pièce peut être substituée dans l'affichage (14.5) |
| La console est compromise | — | elle affiche l'empreinte de ce qu'elle fait signer : limite du format v0 (9.3) ; parade : la notification indépendante (EX-13.3), l'outil hors ligne n'étant pas livré en v0 (section 16) |
| Une console compromise, ou un site tiers, présente comme un vote un condensé du registre de CT-4 (`registerDigest`, `revokeDigest`, `periodDigest`) | la console de CT-3 ne fait signer que `D_A` et le texte d'inscription (EX-13.16, point 3) ; comparaison de l'empreinte, et des huit groupes contre une empreinte cherchée hors ligne (EX-9.18) ; seuil du registre ; surveillance de `RecorderRegistered` et `PeriodSubmitted`, puis révocation (CT-4) | même forme de signature pour les deux usages, sans vote inscrit ni notification (EX-9.9) ; séparation de domaine au portefeuille (EIP-712) en version 1 (section 16) |
| Un site tiers présente le `D_A` d'un ticket en attente comme un message à signer | adresse réservée à NOORTRACE et signature dans la seule console (EX-9.9) | la comparaison de l'empreinte n'aide pas : c'est le vrai `D_A` ; la signature ne devient un vote qu'aux conditions d'EX-9.9 |
| La page de signature est encadrée par un autre site pour faire cliquer l'approbateur | politique de sécurité du contenu d'EX-13.35 (`frame-ancestors 'none'`) | — |
| Un clic répété envoie deux requêtes ou deux votes | une requête de signature à la fois (EX-13.21) ; un vote répété est `vote_identique`, sans effet (EX-12.16) | — |
| Une signature arrive après le délai, après un changement de décision ou d'adresse, ou après l'ouverture d'un autre ticket | ignorée, jamais envoyée (EX-9.21, point 8 ; EX-13.21, EX-13.30) | elle reste une signature valable du `D_A` signé (EX-9.2) |
| Le relais mobile retient, retarde ou observe | chiffrement de bout en bout ; parcours désactivé par défaut ; `expiry` borné par l'échéance (EX-13.27) | déni de service ; métadonnées de trafic vues par un tiers (R4-F30, R4-F31) |
| Le code d'appariement mobile est vu par un tiers | montré seulement à la session authentifiée, jamais journalisé (EX-13.27) | ce qu'un tiers en ferait n'est pas analysé ici (R4 NV-4) |
| Un script de la page lit la clé déchiffrée d'un fichier de clé | politique de sécurité du contenu (EX-13.4, EX-13.35) ; effacement des tampons (EX-13.28) ; portefeuille matériel recommandé (EX-9.9) | une page compromise lit la clé et le mot de passe : c'est pourquoi le parcours d n'est que permis |
| Canal auxiliaire temporel sur la signature locale du parcours d : la signature de `scripts/lib/console.mjs` (`signerHachage`, appelée par `signerCondense` : ECDSA à nonce RFC 6979 écrit en `BigInt`) n'est pas à temps constant, et la durée de ses multiplications et inversions dépend des bits de la clé et du nonce ; un observateur qui mesure ces durées pourrait en tirer de l'information sur la clé | aucun autre script ne s'exécute dans la page : politique de sécurité du contenu d'EX-13.4 et d'EX-13.35 (`script-src` limité à la page et à la carte d'importation, intégrité de chaque script, `Integrity-Policy`), sans ressource d'une autre origine (EX-13.34) ; la clé n'existe déchiffrée que le temps d'une signature et est effacée après usage (EX-13.28, `signerCondense`), chaque vote ne donnant qu'une signature ; la page de référence n'offre pas le parcours d (EX-13.31) | une mesure depuis l'extérieur de la page (autre processus ou autre onglet du poste, extension) n'est pas exclue, et aucune mesure de cette fuite n'a été faite ; les valeurs `BigInt` intermédiaires ne s'effacent pas : elles restent en mémoire jusqu'au ramasse-miettes. Recommandation : un approbateur exposé (montants élevés, rôle public, poste partagé) n'emploie pas le parcours d et signe avec un portefeuille matériel (parcours b, EX-9.9, 13.11), où la clé ne quitte pas l'appareil |

## 15. Décision ouverte 4 de l'architecture et alignement avec le dépôt

### 15.1 Décision 4 — comportement du mandataire pendant une approbation

**Close.** Le mode d'attente par défaut est `erreur` : l'appel soumis à
approbation est scellé `retenue`, l'hôte reçoit aussitôt le signal
d'approbation, un résultat d'outil `isError: true` qui porte le ticket et
`state: "en_attente"` (CT-2 EX-4.49), l'agent ré-émet l'appel, et seule une
ré-émission reconnue d'un ticket décidé `approuve` est relayée, une fois
(sections 7 et 11). Le mode `retenir` reste admis quand la décision est
attendue sous le délai de tous les hôtes raccordés (EX-11.2). L'approbation
se signe dans la console, hors de l'hôte MCP (section 13).

Justification : le plus court délai par défaut d'un appel d'outil chez les
hôtes et les SDK lus est de 5 secondes, et la plupart des autres sont d'une
à quatre minutes, alors qu'une approbation prend des minutes ou des heures
(11.2) ; la spécification MCP demande un délai maximal à toute requête,
sans en fixer la valeur (R2-F13) ; son mécanisme de tâches de longue durée,
désormais extension officielle et stable (R2-F22), n'est déclaré pris en
charge par aucun hôte dans les sources lues (R2-F28 ; non vérifié hôte par
hôte, R2 NV-4), et les tâches expérimentales du cœur de la révision
`2025-11-25` (R2-F21), que parle encore le SDK TypeScript 1.32.1 (R2-F37),
n'ont pas été examinées ; l'élicitation ne prouve pas une approbation
(11.2). Le principe de
l'architecture est tenu dans les deux modes : rien n'est relayé avant la
décision signée au seuil, et le délai écoulé est un refus journalisé
(`expire`, EX-7.10).

Ce que la décision ne règle pas : la conduite de chaque hôte quand il reçoit
le signal (à tester en phase 2, EX-11.9), et les tâches MCP quand un hôte les
prendra en charge (EX-11.10). L'asymétrie que laissait la version 0.2 de
CT-2, où l'attente était l'erreur de protocole `-32015`, que les clients
PEUVENT transmettre au modèle sans y être tenus (R2-F8), d'une plage que la
révision `2026-07-28` dit héritée et dont le récepteur ne suppose aucun sens
(R2-F10), est levée par sa version 0.3 : le signal est une erreur
d'exécution `isError: true`, que les clients DEVRAIENT transmettre au
modèle, et les codes propres de l'enregistreur sont pris hors de `-32768` à
`-32000` (CT-2 §4.4, EX-4.24, EX-4.49).

### 15.2 Alignement avec le dépôt

Points du dépôt que CT-3 rend caducs ou complète. Les lignes de la
version 0.3 (console, annuaire, parcours de signature) sont en fin de table,
avant celles de `package.json` et des scripts. Les fichiers racine de
documentation (`README.md`, `README.fr.md`, `ARCHITECTURE.md`,
`CHANGELOG.md`), `package.json`, `.github/workflows/ci.yml` et le renvoi de
CT-1 §8 sont alignés avec CT-3 (« fait »), y compris le signal
d'approbation de la version 0.3 de CT-2, qui remplace l'erreur avec ticket.
CT-2 l'est
par sa version 0.3 (2026-10-23) : chaque ligne qui la concerne est « fait »,
avec la règle de CT-2 qui l'applique, et chaque proposition de CT-3 y est
adoptée et normative ; aucune n'est écartée. Les règles de CT-3 qui décrivaient
CT-2 (EX-9.11, EX-9.12, 12.2, 12.8, section 11) sont alignées dans la même
livraison ; le code, les générateurs, les vecteurs et les vérificateurs Go qui
en dépendent le sont aussi (CT-2 §22).

| Emplacement | Avant CT-3 | Attendu par CT-3 | État |
|---|---|---|---|
| `ARCHITECTURE.md`, « Approbation : avant l'action, pas après », dernier paragraphe | « Le mandataire retient la réponse jusqu'à la décision ou jusqu'au délai de l'hôte ; au-delà, il renvoie une erreur qui porte le numéro de ticket […] Le choix entre les deux comportements est une décision ouverte, à régler au prototype. » | « Le mandataire répond aussitôt par un résultat d'erreur d'outil (`isError`) qui porte le numéro de ticket et son état (mode `erreur`, par défaut, CT-3 §11 ; CT-2 EX-4.49) ; l'agent ré-émet l'appel, relayé seulement après la décision signée au seuil, une fois. L'approbation se signe dans la console, hors de l'hôte MCP. » | fait |
| `ARCHITECTURE.md`, « Décisions ouvertes », point 4 | « CT-2 fixe les deux modes […] ; le choix et le cycle de vie du ticket relèvent de CT-3. » | « Close par CT-3 : mode `erreur` par défaut, `retenir` sous le délai des hôtes ; cycle de vie du ticket, jeu figé à l'ouverture et reconfirmé avant la décision (CT-3 §7, §8, §11). » | fait |
| `ARCHITECTURE.md`, même section, point 2 du déroulé | « Le seuil […] est celui du jeu d'approbateurs du client dans le contrat CuratorSet. » | ajouter « jeu épinglé par la politique, lu à l'ouverture du ticket, reconfirmé avant la décision ; un seuil abaissé pendant l'attente ne réduit pas les signatures exigées (CT-3 §8) » | fait |
| `ARCHITECTURE.md`, même point 2 | « Chaque approbateur signe sa décision avec sa clé, en EIP-191, comme les curateurs de NOORCHAIN signent aujourd'hui. » | « Chaque approbateur signe sa décision avec sa clé, en EIP-191, dans son portefeuille ; la console reprise du hub ne garde aucune clé (CT-3 §13). » (les curateurs de curators-hub signent aujourd'hui côté serveur, R1-F83) | fait |
| `ARCHITECTURE.md`, même section, premier paragraphe | « Trois sorties : autorisé et journalisé, à approuver, refusé. » | ajouter les trois niveaux, `automatique`, `fenetre` et `revue`, et la fenêtre de contestation, projetés sur ces trois sorties sans valeur nouvelle (CT-3 §5) | fait |
| `ARCHITECTURE.md`, « Déploiement », rétention « alignée sur l'art. 958f CO et l'art. 18 du Règlement IA » | art. 18 | l'art. 18 vise la documentation du fournisseur ; pour les journaux, les art. 19 § 1 et 26 § 6 disent « au moins six mois » (R3-F17, R3-F18, R3-F22) ; hors du champ de CT-3, signalé | fait |
| `ARCHITECTURE.md`, en-tête | « CT-1 pour les formats, CT-2 pour l'enregistreur, CT-6 pour le vérificateur » | ajouter « CT-3 pour les approbations » | fait |
| `ARCHITECTURE.md`, « Ce qui est réutilisé de noorchain-core », listes « Écrit au … » et « À construire » | CT-3 absent de « Écrit » ; « les approbations » à construire | « Écrit » : la spécification CT-3 et ses schémas ; « À construire » : le service et la console d'approbation (phase 2, sections 12 et 13) | fait |
| `README.md`, `README.fr.md` | listes des spécifications écrites : CT-1, CT-2, CT-6 | ajouter CT-3 (langage de règles, ticket, décision ouverte 4 close) | fait |
| `README.md`, ligne CT-3 | « an immediate error carrying the ticket by default » | « an immediate tool error result (`isError`) carrying the ticket and its state by default » (CT-2 EX-4.49) ; `README.fr.md` ne décrit pas l'attente | fait |
| CT-2 §4.4 pas 3 et EX-7.4 | réponse `{ rule, decision, ticket }` | réponse de 12.3, avec `ticket_state`, `approval` et, pour `nouveau`, `approver_set`, que le noyau conserve durablement avec l'événement `retenue` (EX-12.11) ; une réponse hors des sept combinaisons d'EX-12.6 est une indisponibilité (`-31010`) ; requête inchangée | fait (CT-2 0.3 : EX-7.4, EX-7.16, conservation par EX-12.23 ; `-31010` au lieu de `-32010`) |
| CT-2 §4.4 pas 6, scellement d'une `retenue` | toute sortie `a_approuver` est scellée | le noyau refuse de sceller une `retenue` dont `policy.ticket` a déjà une décision scellée dans le journal, quelle que soit la demande, et traite ce cas comme un défaut du service (`-31010`, raison `approbation`) ; deux `retenue` sans décision pour un même ticket restent admises (course d'EX-7.19) | adopté, normatif (CT-2 0.3, EX-7.17 ; `-31010`) |
| CT-2 §4.4 pas 6, message `ouvrir` | `{ ticket, request_hash, request_seq, request_ts }` | ajouter `request_event` (l'événement `retenue` scellé) et `arguments_piece` (octets de la pièce « arguments » rédigée, en base64, ou `null`), pour la vérification de la console (EX-9.6, 12.4) | fait (CT-2 0.3, EX-7.18) |
| CT-2 §4.4 pas 7 et EX-7.12, relais d'un appel qui porte un ticket | le noyau relaie avec l'`approval` que rend le service | vérifications de relais RL-1 à RL-4, chaque échec donnant `-31010`, raison `approbation`, et une alerte : RL-1, prendre l'`approval` de sa propre décision scellée pour ce ticket, et refuser s'il n'y en a pas ou si elle n'est pas `approuve` ; RL-2, égalité de `execution.tool`, de la délégation (`launched_by`, `on_behalf_of`, `scope`, jamais `run_id`), de la référence de la pièce « arguments » et d'un MAC à clé du JCS intégral des arguments en clair (clé propre au noyau, hors chaîne, MAC calculé et persisté au scellement de la `retenue` et gardé jusqu'à `approval.at + E`) avec ceux de la `retenue` de `request_hash` ; RL-3, aucun événement `executee` ne porte déjà cette approbation ; RL-4, `ts < approval.at + E`, `E` de la version de politique de la `retenue` (EX-7.10) | adopté, normatif (CT-2 0.3 : RL-1 à RL-4, EX-7.21, RL-4 tenant à l'instant de la vérification plus le `timeout_ms` de l'outil, strictement avant `approval.at + E`, et RL-3 aux continuations MRTR, une fois par `requestState`, EX-4.21 ; MAC de relais, clé `storage.relay_mac_key`, la même pour toutes les instances, EX-7.22 ; fichiers des approbations, EX-12.23 ; `-31010`) |
| CT-2, messages `acquitter` et `expiration` | `acquitter` : `seq`, `hash`, `at`, `decision` ; `expiration` : `seq`, `hash`, `at` | `acquitter` porte en plus l'objet `approval` scellé (avec `at` et `request_hash`) pour `scelle` et `ticket_deja_decide`, et `held` pour `scelle` (EX-11.5) ; `expiration` porte l'objet `approval` scellé (12.5, 12.6) | fait (CT-2 0.3 : EX-7.19, EX-7.20, EX-9.4) |
| CT-2 §15.4 pas 6, message `charger` | liste des outils et ensemble de politique | transmettre aussi les `launched_by` fixes des connexions d'hôte, pour l'avertissement d'EX-4.14 (10.5) | adopté, normatif (CT-2 0.3, EX-7.15 : membre `requesters`, ajouté à 12.2) |
| CT-2 §4.4 pas 5 | « `-32015` […] ou un résultat `isError: true` selon le mode choisi par CT-3 » | refus sans ticket : résultat `isError: true` au texte fixe d'EX-11.8 ; refus d'un ticket : signal d'approbation (CT-2 EX-4.49) et événement `refusee` qui reprend la `policy` de la demande (EX-7.16) | fait (CT-2 0.3 : §4.4 pas 5, EX-4.49 ; refus d'un ticket rendu par le signal d'approbation, résultat `isError`, au lieu de `-32015`) |
| CT-2 §4.4 pas 6 | chaque sortie `a_approuver` scelle un `retenue` | `ticket_state: "en_attente"` : aucun événement (EX-7.19) ; au plus une requête retenue par ticket (EX-11.4) ; `refusee` à la décision `refuse` ou `expire` d'une requête retenue (EX-11.5) ; progression permise pendant la rétention (EX-11.6) | fait (CT-2 0.3 : §4.4 pas 6, EX-4.50) |
| CT-2 EX-7.4 et §15.4 pas 6 | liste des noms annoncés, rendue au chargement ; outils « qu'une règle peut soumettre à approbation » | liste `CANDIDATS` d'EX-4.11, qui comprend aussi les outils qu'une règle peut refuser (4.12) ; un nom absent de la liste du dernier `charger` réussi est tenu pour susceptible ; message `charger` de 12.2 (membre `approval` sans `service`, `recorder.environment`, outils avec gabarits d'effets), renvoyé aussi à chaque changement de la liste agrégée (CT-2 EX-4.15) ; messages `ouvrir`, `decisions`, `acquitter`, `consommer`, `expiration` de 12.4 à 12.6 | fait (CT-2 0.3 : EX-7.4, EX-7.14 à EX-7.20, EX-4.15, EX-15.4 pas 6) |
| CT-2 EX-7.12 | appel relayé après `approuve` | même reprise de la `policy` de la demande pour l'événement `refusee` d'une ré-émission reconnue après `refuse` ou `expire` (EX-7.18) | fait (CT-2 0.3, EX-7.12) |
| CT-2 EX-9.4 | « une nouvelle tentative de l'agent est un nouvel appel » ; expiration du noyau « à `approval.expire_after_ms` » | une tentative reconnue reçoit le refus scellé pendant le délai de reconnaissance (EX-7.18), puis devient un nouvel appel ; l'échéance part du `ts` de l'événement `retenue`, avec l'`expire_after_ms` de la version de politique de cet événement (EX-7.10) ; le noyau expire seul à l'échéance plus `timeout_ms`, avec la raison, le `threshold` et l'`approver_set` d'EX-12.11 (dernière remise du ticket au jeu exploitable, sinon jeu de la réponse `nouveau` ; `threshold` celui du jeu) | fait (CT-2 0.3, EX-9.4) |
| CT-2 EX-7.5 | vérification de la décision avant scellement (E-5, E-9, A-3) | SG-1 à SG-6 dans l'ordre d'EX-9.11, avec les raisons de 12.8 ; SG-4 compare l'instant d'écriture (`approval.at`) à l'échéance ; proposition SG-7 : séparation des tâches vérifiée par le noyau avec la politique et l'événement `retenue` (EX-9.12) | fait ; SG-7 adoptée, normative (CT-2 0.3, EX-7.5 ; EX-9.11, EX-9.12 et 12.8 alignés) |
| CT-2 §15.3, exemple de configuration ; schéma de configuration, `policy.approval.rules` | `"mode": "retenir"` ; `rules` « opaque », tableau d'exemple `{ tool, when, decision, note }` | `"mode": "erreur"` (EX-11.1) ; `rules` = document `politique-approbation-v0` (section 4), désigné par `$ref` dans le schéma de configuration et validé par la commande de 15.6 de CT-2 ; les vecteurs `spec/vecteurs/ct-2/evenements/journal-demo/politique.json`, figés, gardent leur tableau illustratif (4.1) | fait (CT-2 0.3 : exemple de §15.3, EX-10.21, schéma de configuration ; `journal-demo/politique.json` figé, CT-2 annexe B.6) |
| CT-2 EX-15.4 pas 3 et 6, EX-15.5 | l'événement de politique est scellé (pas 6) avant que le service valide `policy.approval.rules` (EX-4.2) | appliquer EX-4.2 et EX-8.2 à `rules` dès le pas 3 et dans la commande de validation de CT-2 §15.6, pour qu'un document invalide soit refusé avant d'être annoncé ; sinon il est annoncé, puis bloque tout outil susceptible d'approbation (EX-4.2) | adopté, normatif (CT-2 0.3 : EX-15.4 pas 3, EX-15.5, EX-15.7) |
| CT-2 §15.4 pas 3 | avertissement sur `signer.max_message_bytes` d'après `threshold.size` | la remise porte exactement le seuil effectif de signatures (EX-7.28), qui ne dépasse pas le plus grand `threshold.size` lu : l'avertissement d'après `size` reste prudent ; avertissement quand `mode` vaut `retenir` (EX-11.1) | fait (CT-2 0.3, EX-15.4 pas 3) |
| CT-2 §12 (stockage) et exportateur | `approver_set` sans origine nommée | le noyau garde l'`approver_set` de chaque décision scellée, hors chaîne, et l'exportateur l'écrit tel quel dans `approbations.json` (EX-8.9) | fait (CT-2 0.3, EX-12.23) |
| CT-2 EX-10.2 | valeurs en ligne tirées des valeurs rédigées | y soumettre `approval.reason` (EX-9.14) | fait (CT-2 0.3 : EX-10.2, EX-10.24, obligation du noyau) |
| CT-2 §4.4, « Codes d'erreur de l'enregistreur », table des codes et EX-4.24 (la version 0.2 n'en parlait pas en §0.3) | « La révision 2026-07-28 réserve `-32000` à `-32019` aux implémentations » | la révision `2026-07-28` qualifie `-32000` à `-32019` d'hérités : aucune nouvelle allocation (MUST NOT), aucun usage par une nouvelle implémentation (SHOULD NOT), aucun sens supposé par le récepteur (MUST NOT), sauf `-32002` (`basic/index.mdx` L117-L121) ; un nouveau code DEVRAIT être pris hors de `-32768` à `-32000` (L153-L155) ; tous les codes `-32010` à `-32019` de CT-2 version 0.2 sont concernés, pour un hôte qui négocie cette révision (R2-F10). Proposition : signaler l'attente par un résultat `isError: true` qui porte le ticket, ou par des codes hors de la plage réservée (15.1). CT-3 ne crée aucun code | fait (CT-2 0.3 : issues d'approbation en résultat `isError`, EX-4.49 ; codes de l'enregistreur `-31010` à `-31017`, hors de `-32768` à `-32000` et de `100` à `599`, `-32015` retiré sans successeur, EX-4.24 ; §0.3 de CT-2 rappelle la politique) |
| CT-1 §8, changement de politique : « SHA-256 des octets de la politique, CT-3 » | renvoi à CT-3 | `policy_sha256` est défini par CT-2 EX-8.11 sur tout l'ensemble de politique ; CT-3 n'en donne pas d'autre (R1-C31) ; format inchangé | fait |
| `spec/README.md` | CT-3 « à écrire » ; dix schémas de CT-1, CT-2 et CT-6 | ligne CT-3 ; schémas `politique-approbation-v0` et `ticket-v0` ; vecteurs `vecteurs/ct-3/` | fait avec CT-3 |
| `CHANGELOG.md` | aucune entrée CT-3 | entrée CT-3 : spécification, schémas `politique-approbation-v0` et `ticket-v0`, implémentation de référence, vecteurs et vérificateur Go | fait |
| `CHANGELOG.md`, entrée CT-3 | « the proxy answers at once with an error carrying the ticket (`erreur` mode) by default » ; décompte du vérificateur Go de la version 0.1 | « the proxy answers at once with a tool error result (`isError`) carrying the ticket and its state (`erreur` mode) by default » ; décompte de la version 0.2 de CT-3 (annexe A.9) | fait |
| `spec/README.md` (version 0.3) | ligne CT-3 en version 0.2 ; deux schémas de CT-3 | ligne CT-3 en version 0.3 ; schémas `console-approbation-v0`, `annuaire-approbateurs-v0`, `console-service-v0` ; familles `annuaire/` et `console/` | fait avec CT-3 0.3 |
| `README.md`, `README.fr.md`, ligne CT-3 | règles, ticket, décision ouverte 4 | ajouter la console : personne nommée par le système d'identité du client, annuaire et inscription par preuve de possession, signature dans le portefeuille de l'approbateur, contrôle local de `D_A`, console de référence (section 13) | fait avec CT-3 0.3 |
| `ARCHITECTURE.md`, « Approbation : avant l'action, pas après », point 2 du déroulé | « Chaque approbateur signe sa décision avec sa clé, en EIP-191, dans son portefeuille […] » | ajouter : par l'un des parcours de signature de CT-3 §13.9 (portefeuille de navigateur, portefeuille matériel par lui, mobile sur décision de l'organisation, fichier de clé chiffré), après que la console a recalculé `D_A` ; une personne nommée, liée à son adresse par l'annuaire des approbateurs (CT-3 §13.4) | fait avec CT-3 0.3 |
| `ARCHITECTURE.md`, « Ce qui est réutilisé de noorchain-core » | « À construire » : le service et la console d'approbation | « Écrit » : la console de référence (bibliothèque, page, test) ; « À construire » : le service et la console d'exploitation (phase 2) ; de curators-hub ne sont repris ni la garde des clés par le serveur, ni le lien de session par le nom affiché, ni l'inscription d'adresse sans preuve de possession (13.1) | fait avec CT-3 0.3 |
| `CHANGELOG.md` | entrée CT-3 0.2 | entrée CT-3 0.3 : schémas `console-approbation-v0`, `annuaire-approbateurs-v0`, `console-service-v0`, raison `session_non_autorisee`, `scripts/lib/console.mjs`, page `console/`, test Chromium, familles `annuaire/` et `console/`, épreuve `acceptation-console/`, confrontation tierce | fait avec CT-3 0.3 |
| `.github/workflows/ci.yml`, travail de confrontation | CT-1, CT-2, CT-5, CT-6 | étapes de confrontation des signatures de CT-3 par eth-account et par ethers (EX-A.19) | fait avec CT-3 0.3 |
| `.github/workflows/ci.yml`, test de bout en bout de la console (EX-13.36) | absent : sans Playwright ni Chromium, le test est sauté | un travail qui installe Playwright et Chromium à versions épinglées (celles de `console/LISEZMOI.md`) et exécute `test/console.test.js` sans saut | fait avec CT-3 0.3 : travail `console-chromium` (`npm install --no-save playwright@1.56.1`, `npx playwright install --with-deps chromium`, `NOORTRACE_EXIGER_CHROMIUM=1`, sous lequel un test Chromium en attente fait échouer le travail ; EX-13.36, EX-A.11) |
| CT-4, tableau des opérations (« Approbateurs, par la console (CT-3 §13) ») et ses propositions à CT-3 §13 (la console recalcule et signe les demandes de clôture et d'inscription du registre) | les condensés du registre (`periodDigest`, `registerDigest`, `revokeDigest`) se signent par la console de CT-3 | non adoptée par CT-3 0.3 : la console ne fait signer que `D_A` et le texte d'inscription (EX-13.16, point 3) ; les condensés du registre se signent hors de la console, par un outil qui recalcule et montre les champs (CT-4 EX-7.10 ; EX-9.9) ; CT-4 retire « par la console (CT-3 §13) » et décrit cet outil ; le risque d'une même adresse pour les deux usages est en EX-9.9 et EX-9.18 | fait par CT-4 révision 0.4 (2026-10-26, textuelle) : l'outil prévu est la commande `signer` de l'outil de référence de CT-4 (`scripts/registre/noortrace-registre.mjs`, CT-4 7.2 et 7.7), ou tout outil qui satisfait CT-4 EX-7.10 ; la version 0 ne livre aucun outil qui signe ces condensés dans le portefeuille d'un approbateur, `signer` désignant sa clé par une référence (CT-4 EX-7.3) ; aucun vecteur de CT-4 ne change |
| `spec/README.md`, lignes CT-3 et CT-4 | CT-3 0.3 ; CT-4 0.3 | ligne CT-3 complétée (ordre des refus du canal, effets non résolus, recopie d'`administrators`, test Chromium en intégration continue) ; CT-4 en version 0.4 | fait avec CT-3 0.3 et CT-4 0.4 |
| `test/console-primitives.test.js` | primitives de `scripts/lib/console.mjs` comparées à `node:crypto`, ethers et `journal.mjs` dans `test/console.test.js`, sur des valeurs fixes | test différentiel permanent et déterministe contre `node:crypto`, `@noble/hashes`, `@noble/curves` et ethers (EX-A.9) | fait avec CT-3 0.3 |
| CT-2, `delegation.launched_by` et identité de session | `${oauth_subject}` ; aucune identité de session | aucun changement de CT-2 : l'alias de demandeur de l'annuaire rapproche `launched_by` de l'identité de session (13.3, 13.4) ; que la console et les connexions d'hôte emploient le même client OIDC n'est pas vérifié (R5 NV-4) | sans objet |
| `package.json`, `.github/workflows/ci.yml` | `vecteurs:ct1`, `ct2`, `ct6` | `vecteurs:ct3` ; régénération de `spec/vecteurs/ct-3` exigée à l'identique ; vérificateur Go de `ct-3` (`gofmt`, `go vet`, `go test`, `go run . ..`), étape sans condition (annexe A.9) | fait avec CT-3 |
| `scripts/lib/capture.mjs`, `erreursMotifRE2` (CT-2 EX-10.6, EX-10.23) | admet les quatre motifs à retour arrière exponentiel d'OWASP ; `limits.redaction_budget_ms` absent du code | hors de CT-3, signalé à CT-2 (R2-F84) | fait avec CT-2 0.3 (règles de structure et de taille d'EX-10.6, budget d'EX-10.23 ; code, vecteurs et vérificateur Go alignés dans la même livraison, CT-2 §22) |

## 16. Ce que cette version ne couvre pas

- **Une fenêtre prouvée par signature** : en v0, une fenêtre (5.3) est
  ouverte par une décision qui ne signe que la demande ouvrante, et les
  appels qu'elle couvre sont `autorise`, sans `approval` ; seul le
  rapprochement de 5.7 les relie à la décision. `A` ne porte ni instant ni
  durée (R3-F122). Une autorisation signée bornée dans le temps et en portée,
  à la manière de Microsoft Entra PIM ou de Google Cloud PAM (R3-F72 à
  R3-F75, R3-F83), ou une approbation différée comme celle d'Azure Pipelines
  (R3-F96), demande des champs signés (`not_before`, `not_after`, portée,
  `max_calls`) : proposition pour une version 1 du condensé, préfixe
  `noortrace/approbation/v1\n`, sans toucher la v0.
- **D'autres champs signés** : échéance, nom de l'outil, montant et devise,
  demandeur (R2, section 3.4) ; une récusation, un retrait ou une objection
  signés, qui fermeraient ce qu'une console compromise peut forger sur le
  canal d'EX-12.4 (EX-10.4).
- **Un affichage clair au portefeuille** : données typées EIP-712 ou texte
  lisible en ASCII (9.3, R2-F48, R2-F54, R2-F60) ; ERC-1271 et les comptes de
  contrat, dont la validité dépend de l'état de la chaîne (R2-F62).
- **Une séparation de domaine au portefeuille** entre les votes et les
  condensés du registre de CT-4, que la même adresse signe aujourd'hui sous
  la même forme (EX-9.9, EX-9.18) : des données typées EIP-712 dont le
  domaine diffère selon l'usage, qui changeraient l'objet signé de CT-1 et
  les condensés de CT-4.
- **La libération d'une adresse confisquée** : une adresse inscrite, jamais
  validée, dans l'entrée d'une autre personne (EX-13.17, « Confiscation »)
  pourrait être rendue à son détenteur prouvé, par une opération signée et
  inscrite ; en version 0, elle reste dans l'entrée qui l'a inscrite
  (EX-13.10, point 2) et son détenteur change de clé.
- **Les clés d'accès** (passkeys, WebAuthn) pour signer un vote. L'objet
  signé de CT-1 §6.3 est une signature EIP-191 secp256k1 dont le
  vérificateur recouvre une adresse, membre du `CuratorSet` (E-9, A-3) ; une
  clé d'accès (WebAuthn, P-256) n'en produit pas : choix de la version 0 ; les
  algorithmes que proposent les authentificateurs n'ont pas été examinés
  par les notes R4 et R5. Une clé d'accès PEUT servir à authentifier la
  session de l'approbateur auprès du système d'identité du client (13.3),
  jamais à voter. Piste pour une version 1 : un condensé
  `noortrace/approbation/v1\n` signé par une assertion WebAuthn, dont le défi
  serait ce condensé et qui est liée à une origine et à un identifiant de
  partie de confiance (R5-F29), un membre de jeu identifié par sa clé
  publique et non par une adresse, et la vérification correspondante ; elle
  toucherait CT-1 (forme et vérification des signatures), le `CuratorSet`
  (membres qui ne sont pas des adresses), le contrôle 7 de CT-6 et la
  cérémonie des clés de CT-7.
- **Ce qui reste du parcours mobile** (13.12) : la console de référence ne
  l'offre pas, et sa conformité n'est pas éprouvée par les tests de la
  version 0 ; l'existence d'un relais auto-hébergeable compatible, la
  conservation des métadonnées par le relais et l'affichage d'un
  `personal_sign` binaire par les portefeuilles mobiles ne sont pas vérifiés
  (R4 NV-4, R2 NV-8).
- **Un dialogue direct entre la page et un portefeuille matériel**, sans
  portefeuille de navigateur : la version 0 passe par lui (13.11).
- **Une identité attestée des portefeuilles** : `rdns` est déclaré par le
  portefeuille et peut en imiter un autre (R4-F6) ; une liste de
  portefeuilles admis par l'organisation, fondée sur une attestation, est
  hors de la version 0.
- **D'autres fichiers de clé** que Web3 Secret Storage version 3 aux
  paramètres d'EX-13.28.
- **La séparation des tâches et la fenêtre de contestation vérifiables dans
  le dossier** : liste des adresses de chaque demandeur signée par
  l'administrateur du `CuratorSet` plutôt que déclarée par l'opérateur dans
  la politique, demandeur signé dans `A`, objections et instants de vote dans
  la chaîne (10.5) ; un contrôle de CT-6 qui réévaluerait la règle et la
  séparation avec la pièce de politique (6.8, 10.5).
- **Le jeu d'approbateurs prouvé** : une ancre d'approbateurs dans le fichier
  d'ancres de CT-6, ou une preuve d'état si noorcore en sert une (8.5) ; un
  futur contrôle comparerait `approver_set` à cette ancre à la hauteur de
  `source`. Le contrôle 7 de CT-6 garde en v0 la provenance « déclaré par le
  dossier ».
- **Les prédicats cumulatifs** contre le fractionnement (14.1), et un
  prédicat linéaire `membres_parmi`, VRAI si tous les noms des membres d'un
  objet sont dans une liste, INDETERMINE si la valeur n'est pas un objet,
  contre les membres que la règle ne lit pas (14.5).
- **Un délai après refus** (`cooldown_after_refusal_ms` par couple
  `launched_by`, outil), qui rendrait une erreur comme `plafond_atteint`
  sans être une décision, contre la réouverture d'une demande refusée par
  une variation cosmétique (EX-7.18, 14.7).
- **Deux messages du noyau vers le service** : `annulation { ticket }`, qui
  inscrirait dans la trace l'annulation par l'hôte d'une requête retenue
  sans changer l'état (EX-7.14), et `liberer { ticket }`, qui libérerait une
  approbation servie dont le relais a échoué avant tout événement
  (EX-7.17).
- **Plusieurs niveaux d'approbation successifs** (Google Cloud PAM, R3-F87),
  des groupes d'approbateurs distincts, la délégation d'une voix.
- **L'accès d'urgence borné** : en v0, une règle `automatique` à
  `autorise` ajoutée puis retirée par deux changements de politique (5.2) ;
  une échéance de règle, et la revue après usage que Microsoft et AWS
  demandent (R3-F82, R3-F91, R3-F92), n'ont pas de forme en v0.
- **Les tâches MCP et MRTR** (11.6).
- **La console d'exploitation** (phase 2 : serveur de console,
  authentification par le système d'identité du client, notifications) : la
  version 0.3 livre une console de référence (13.15), qui en fixe le
  comportement côté navigateur sans l'être. Un **outil hors ligne**,
  indépendant de la console, qui recalcule `D_A` depuis l'événement
  `retenue` pour un second contrôle de l'approbateur : la bibliothèque de la
  console de référence, exécutée dans Node sur une vue exportée, en fait les
  calculs, sans en avoir l'indépendance.
- **La procédure de réexamen** d'une décision contestée par une personne
  concernée (5.6) et toute qualification réglementaire de NOORTRACE ou de
  ses clients (R3, section 2, non vérifié).
- **Un service pour plusieurs journaux** d'une même instance (CT-2 EX-13.7).
- **Un annuaire attesté** : validations et révocations signées par la clé
  d'un administrateur, ou annuaire ancré, qui rendraient l'annuaire
  vérifiable sans croire le client ; une identité de session attestée
  auprès du service (le service croit aujourd'hui le serveur de console,
  EX-12.16) ; l'instant d'authentification (`auth_time`) et la méthode
  (`amr`) inscrits avec chaque vote dans la trace du ticket (EX-13.8).
- **Les identités hors de la forme canonique** : sujet de plus de 255
  caractères, avec une espace ou hors de l'ASCII, forme de plus de 256
  caractères (EX-13.7) ; le rapprochement automatique de `launched_by`
  et de l'identité de session quand le fournisseur donne un sujet différent
  par client (R5-F9, R5 NV-4).
- **Les comptes de contrat** (ERC-1271) comme adresses d'approbateur, dont la
  signature dépend de l'état de la chaîne (R5-F19, R5 NV-8).

## Annexe A — Vecteurs CT-3

### A.1 Principes

**EX-A.1** Les vecteurs sont sous `spec/vecteurs/ct-3/`, produits par
`scripts/vecteurs/generer-ct3.mjs` (`npm run vecteurs:ct3`) et rejoués à
l'identique par `test/approbation.test.js` : horodatages, clés, identifiants
et ordres fixes, aucune valeur aléatoire. Le générateur n'efface et ne
réécrit que ses propres entrées de premier niveau (`INDEX.md`,
`constantes.json`, `acceptation-attendu.json`,
`acceptation-console-attendu.json` et les répertoires `acceptation/`,
`acceptation-console/`, `annuaire/`, `candidats/`, `console/`,
`decisions/`, `evaluation/`, `politiques/`, `politiques-invalides/`,
`signatures/`, `tickets/`), jamais `verificateur-independant/` ni
`confrontation/`, qu'il tient pour siens sans les lire ; il refuse, sans rien
effacer, un répertoire de sortie qui porte une autre entrée, et une option
`--sortie` sans répertoire. Les fichiers JSON sont écrits par
`JSON.stringify(objet, null, 2)` suivi d'un saut de ligne, comme ceux de CT-1 ;
les vecteurs de CT-1, CT-2, CT-4, CT-5 et CT-6 ne changent pas.

**EX-A.2** Chaque famille porte ses attendus dans ses propres fichiers ; un
même cas n'est jamais attendu à deux endroits. Les clés JSON sont en
anglais, les valeurs énumérées en français sans accent, les descriptions en
français.

**EX-A.3** Les vecteurs se valident par les schémas : les politiques
valides par `politique-approbation-v0` (section 4) ; dans
`ticket-v0.schema.json`, `politiques-invalides/attendu.json` par
`#/$defs/attendu_politiques_invalides`, `evaluation/` par
`#/$defs/fichier_evaluation`, `candidats/` par `#/$defs/fichier_candidats`,
`acceptation-attendu.json` par `#/$defs/attendu_acceptation`, les traces de
`tickets/` par `#/$defs/trace`, les cas de `decisions/` par
`#/$defs/cas_remise` et leurs remises valides par `#/$defs/remise`. Dans
`annuaire-approbateurs-v0.schema.json` : les annuaires de
`annuaire/annuaires/` et `annuaire/exports/` (sauf le cas `schema`) par le
schéma racine, `annuaire/messages.json` par `#/$defs/fichier_messages`,
`annuaire/inscriptions.json` par `#/$defs/fichier_inscriptions`,
`annuaire/domaines.json` par `#/$defs/fichier_domaines`, les traces de
`annuaire/traces/` par `#/$defs/trace_annuaire`,
`annuaire/controles-vote.json` par `#/$defs/fichier_controles_vote`,
`annuaire/controles-canal.json` par `#/$defs/fichier_controles_canal` et
`annuaire/exports/attendu.json` par `#/$defs/attendu_exports`. Dans
`console-approbation-v0.schema.json` : les cas de
`console/modeles/`, `console/requetes/`, `console/reponses/`,
`console/decouverte/` et `console/fichiers-cle/` par `#/$defs/cas_modele`,
`#/$defs/cas_requete`, `#/$defs/cas_reponse`, `#/$defs/cas_decouverte` et
`#/$defs/cas_fichier_cle`, et `acceptation-console-attendu.json` par
`#/$defs/attendu_acceptation_console`.

### A.2 Constantes

| Grandeur | Dérivation | Usage |
|---|---|---|
| Organisation | `assureur-demo`, `org_id = keccak256(UTF-8("assureur-demo"))` = `0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab` (CT-1 §13) | toutes les familles |
| Journal | `journal-approbations`, `journal_id = keccak256(UTF-8("journal-approbations"))` = `0x3bac546e33b4ed1872f0214f92d6fd5333ffe38df9a281e8a49260d426d11ca1` | toutes les familles, sauf le cas repris de CT-1 (A.7) |
| Versions de politique | `vecteurs-ct3-1`, puis `vecteurs-ct3-2` pour les changements de politique | `code.policy_version`, `charger` |
| Chaîne | `chain_id` `2124` (réseau de développement, `deployments/noorcore.json`) | `approver_set`, `jeu_lu`, `source` |
| Registre de test | les 20 premiers octets de `SHA-256(UTF-8("noortrace/vecteurs/ct3/registre"))` | idem ; adresse synthétique, sans contrat |
| Jeu de test `n` (n = 1, 2) | les 20 premiers octets de `SHA-256(UTF-8("noortrace/vecteurs/ct3/jeu/<n>"))` | idem ; le jeu 2 sert à la réassignation (8.3) |
| Hachage du bloc `h` | `SHA-256(UTF-8("noortrace/vecteurs/ct3/bloc/<h>"))`, `h` en décimal | idem ; synthétique |
| Hachage d'une demande `k` | `SHA-256(UTF-8("noortrace/vecteurs/ct3/demande/<k>"))` | `request_hash` des traces |
| Hachage d'un événement `seq` | `SHA-256(UTF-8("noortrace/vecteurs/ct3/evenement/<seq>"))`, `seq` en décimal | `hash` des entrées `acquitter`, `consommer` et `expiration` des traces, `decided` des cas de remise ; synthétique |
| Comptes | comptes 1 à 4 du mnémonique Hardhat (`test test … junk`, `m/44'/60'/0'/0/i`) : 1 `0x70997970c51812dc3a010c7d01b50e0d17dc79c8`, 2 `0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc`, 3 `0x90f79bf6eb2c4f870365e785982e1f101e93b906`, 4 `0x15d34aaf54267db7d7c367839aaf71a00a2c6a65` | jeu 1 : comptes 1 à 3, seuil 2 ; jeu 1 épinglé par les politiques `registre` des vecteurs (`approver_set.set`) ; compte 3 : adresse du demandeur (4.3) ; compte 4 : non-membre, ajouté au jeu dans les traces de changement, membre du jeu 2 |
| Demandeur | `u.martin@assureur-demo.example`, qui détient le compte 3 (`separation.identities`, comme en 4.3) | `delegation.launched_by` |
| Instant de base | `2026-11-12T09:00:00.000Z` | les traces datent leurs entrées à partir de lui |

Ces clés sont publiques et ne doivent jamais porter de valeur. Le fichier
`constantes.json` porte toutes ces valeurs, les clés privées des quatre
comptes et les adresses dérivées ; `INDEX.md` les imprime.

### A.3 Disposition

```text
spec/vecteurs/ct-3/
  INDEX.md                     généré : chaque cas, son attendu en une ligne, les constantes
  constantes.json              A.2
  politiques/                  politiques valides, une par fichier (A.4)
  politiques-invalides/        politiques refusées, une par fichier, et attendu.json (A.4)
  evaluation/                  cas d'évaluation par politique, avec leur sortie attendue (A.4)
  candidats/                   outils susceptibles d'approbation par politique (A.4)
  acceptation/                 l'épreuve des trois relecteurs : ce qu'ils voient (A.5)
  acceptation-attendu.json     les décisions attendues de l'épreuve, hors du répertoire qu'ils reçoivent
  annuaire/                    annuaires, messages et inscriptions, opérations, contrôles de la console (A.10)
    annuaires/                 annuaires de départ des traces et des cas
    messages.json
    inscriptions.json
    domaines.json
    traces/                    une suite d'opérations par fichier
    controles-vote.json
    controles-canal.json       contrôle de l'identité de session par le service (AN-10)
    exports/                   annuaires exportés et attendu.json
  tickets/                     traces de cycle de vie, une par fichier (A.6)
  decisions/
    valides/                   remises acceptées par le noyau (A.7)
    invalides/                 remises refusées (A.7)
  signatures/
    normalisation.json         normalisation d'EX-9.3 (A.8)
  console/                     contrôles de la console, vérifications CS- (A.11)
    modeles/                   vue du ticket et modèle d'affichage attendu
    requetes/                  de A à la requête personal_sign, préimage, signature attendue
    reponses/                  réponse du portefeuille, verdict, vote construit
    decouverte/                annonces EIP-6963 et liste proposée au choix
    fichiers-cle/              fichiers de clé chiffrés (Web3 Secret Storage v3)
  acceptation-console/         l'épreuve de lecture de la console : consigne et gabarit (A.11)
  acceptation-console-attendu.json  la grille de l'épreuve, hors du répertoire que les lecteurs reçoivent
  confrontation/               confrontation tierce (eth-account, ethers), jamais écrite par le générateur (A.11)
  verificateur-independant/    module Go, jamais écrit par le générateur (A.9)
```

### A.4 Politiques, évaluation et candidats (vérifications AP-)

Les vérifications AP- (4.15) ont leurs cas dans quatre familles. Les
politiques sont des documents `politique-approbation-v0` ; leurs règles et
le nombre de cas sont libres, chaque vérification AP- ayant au moins un cas.
La forme des fichiers est la suivante.

`politiques/<nom>.json` : un document valide.
`politiques-invalides/<nom>.json` : un document refusé ;
`politiques-invalides/attendu.json` :

<!-- schema: ticket/attendu_politiques_invalides -->
```json
{
  "version": 0,
  "cases": [
    { "file": "nom-double.json", "environment": "developpement", "expire_after_ms": 3600000,
      "checks": ["AP-2"], "errors": [ { "code": "nom_double", "pointer": "/rules/2/name" } ] }
  ]
}
```

`errors` est la liste **complète** des erreurs (EX-4.2), triée par
`pointer` puis par `code` ; les pointeurs se comparent comme des chaînes,
unité UTF-16 par unité (l'ordre de `Array.prototype.sort` et de la
comparaison d'octets en ASCII), sans ordre numérique des indices :
`/rules/10/name` précède `/rules/2/name`. Pour une non-conformité au
schéma, `errors` est exactement `[ { "code": "schema", "pointer": null } ]`,
une seule entrée quel que soit le nombre d'erreurs de schéma (deux
validateurs ne les découpent pas de même), et la seule de la liste : les
autres règles ne sont pas vérifiées (EX-4.2). Sinon chaque erreur porte l'un
des codes suivants et le pointeur JSON du membre fautif :

| Code | Pointeur |
|---|---|
| `nom_double` | `/rules/<i>/name` de la seconde occurrence, dans l'ordre du document, la règle par défaut étant lue la première |
| `pointeur_trop_long` | le membre `path` du prédicat (`/rules/<i>/when/…/path`), ou `/rules/<i>/window/same_arguments/<k>` |
| `condition_trop_profonde`, `trop_de_predicats` | `/rules/<i>/when` |
| `substitut_isole` | le membre chaîne qui porte le substitut |
| `launched_by_double` | `/separation/identities/<k>/launched_by` de la seconde occurrence |
| `contest_ms_trop_long` | `/rules/<i>/contest_ms` ou `/default/contest_ms` |
| `seuil_statique_incoherent` | `/approver_set/threshold` |
| `jeu_statique_en_production` | `/approver_set/source` |

`environment` est celui que transmet `charger` (EX-8.2) ; `expire_after_ms`,
toujours écrit, est la valeur de `/policy/approval/expire_after_ms` sous
laquelle le document est validé (EX-4.2, point 6) : 3 600 000, sauf pour un
cas qui exige une autre valeur.

`evaluation/<nom de la politique>.json` (esquisse : « … » marque une valeur
omise) :

```json
{
  "version": 0,
  "policy": "politiques/<nom>.json",
  "policy_version": "vecteurs-ct3-1",
  "cases": [
    {
      "id": "…", "description": "…", "checks": ["AP-14"],
      "t": "2026-11-12T10:00:00.000Z",
      "windows": [ { "…": "$defs/fenetre_ouverte de ticket-v0" } ],
      "request": { "…": "requête evaluer de 12.3 (CT-2 EX-7.4)" },
      "expected": {
        "rule": "…", "decision": "a_approuver",
        "contest_ms": 0,
        "opening": { "scope": { "policy_version": "…", "rule": "…", "tool": "…", "launched_by": "…", "values": ["…"] }, "duration_ms": 28800000, "max_calls": 20 },
        "windows": [ ]
      }
    }
  ]
}
```

`t` est l'instant d'évaluation, `windows` l'état `F` avant l'évaluation
(6.1), `expected.windows` l'état après (une unité consommée, EX-5.5 ;
la sortie d'`EVALUER` garde une fenêtre épuisée, que le service retire
ensuite, EX-5.6) ; `expected.contest_ms` est celui de la règle retenue pour
`a_approuver`, `null` sinon ; `expected.opening` est la portée et la
fenêtre d'un ticket ouvrant (EX-5.3), `null` sinon. Les politiques
`ordre.json` et `ordre-inverse.json` ont les mêmes règles en ordre inverse :
leurs cas exercent EX-4.9 (AP-12). Le ticket créé n'est pas attendu ici : il
l'est dans `tickets/`.

`candidats/<nom de la politique>.json` : `{ "version": 0, "policy", "cases":
[ { "id", "checks", "tools": [noms annoncés, dans l'ordre donné, doublons
permis], "approval_candidates": [noms rendus par CANDIDATS, EX-4.11] } ] }`.

### A.5 Épreuve d'acceptation

Critère du plan : trois relecteurs, dans les rôles d'approbateur, d'auditeur
et de développeur, lisent la même politique à l'aveugle et en tirent la même
décision sur dix cas (6.7).

```text
acceptation/
  consigne.md                  ce que fait chaque relecteur, ce qu'il rend
  politique.json               une politique : quelques règles sur un même outil (trois dans les vecteurs) et sa règle par défaut (section 4)
  cas/cas-01.json … cas-10.json  { "id", "request" } : la requête evaluer, sans attendu
  gabarit-reponse.json         { "role", "reviewer", "answers": [ { "id", "decision" } ] }
acceptation-attendu.json       { "version": 0, "policy": "acceptation/politique.json",
                                 "expected": [ { "id", "rule", "decision" } ] }
```

**EX-A.4** Les dix cas couvrent chacune des trois sorties (`autorise`,
`a_approuver`, `refuse`) au moins deux fois et comprennent au moins : une
égalité exacte au seuil d'une comparaison, un argument absent, un argument
d'un autre type, un autre outil que celui des règles. Aucun cas ne dépend
d'une fenêtre ni d'un ticket : l'épreuve porte sur la politique, avec `F`
vide.

**EX-A.5** `consigne.md` dit : chaque relecteur reçoit une copie du seul
répertoire `acceptation/` et la partie A de CT-3 (sections 0 à 6) ; il lit
la section 5 pour les niveaux, puis, pour décider, 4.2, 4.4 à 4.11 et 6.2 à
6.4 (un argument absent ou d'un autre type, les comparaisons exactes, la
logique à trois valeurs, le rang et la règle par défaut s'y trouvent) ; il
travaille seul, sans voir les réponses des autres ni
`acceptation-attendu.json`, et rend un fichier au format de
`gabarit-reponse.json` avec, pour chaque cas, une décision parmi `autorise`,
`a_approuver` et `refuse` ; les rôles d'approbateur et d'auditeur
n'exécutent aucun code. L'épreuve est réussie si les trois réponses sont
égales entre elles et à `acceptation-attendu.json` sur les dix cas ;
l'implémentation de référence et le vérificateur Go doivent, eux, rendre
`acceptation-attendu.json` (tests de A.9). Les réponses des relecteurs ne
sont pas des vecteurs et ne sont pas publiées par le générateur.

### A.6 `tickets/`

Une trace par fichier, au format `ticket-v0.schema.json#/$defs/trace`
(esquisse : « … » marque une valeur omise) :

```json
{
  "version": 0,
  "id": "approuve-sans-contestation",
  "description": "…",
  "checks": ["TK-3", "TK-6", "TK-8"],
  "org_id": "0x…", "journal_id": "0x…",
  "environment": "developpement",
  "policy_version": "vecteurs-ct3-1",
  "expire_after_ms": 3600000,
  "approver_set": { "source": "registre", "chain_id": 2124, "registry": "0x…", "set": "0x…", "members": null, "threshold": null },
  "separation": { "self_approval": "interdite", "identities": [ { "launched_by": "u.martin@assureur-demo.example", "addresses": [ "0x90f79bf6eb2c4f870365e785982e1f101e93b906" ] } ] },
  "service": { "max_open_tickets": 20, "escalation": [], "set_poll_interval_ms": 10000, "administrators": [] },
  "steps": [
    {
      "input": { "kind": "jeu_lu", "at": "2026-11-12T08:59:00.000Z", "data": {
        "status": "lu", "jeu": { "…": "objet jeu de ticket-v0, jeu 1 à la hauteur 1190" }, "cause": null } },
      "expected": { "tickets": { }, "accepted": true, "reason": null, "response": null,
        "remises": [], "windows": [] }
    },
    {
      "input": { "kind": "evaluer", "at": "2026-11-12T09:00:00.000Z", "data": {
        "request": { "…": "requête evaluer" },
        "evaluation": { "rule": "…", "decision": "a_approuver", "contest_ms": 0, "opening": null } } },
      "expected": { "tickets": { "apr-0001": "reserve" }, "accepted": true, "reason": null,
        "response": { "rule": "…", "decision": "a_approuver", "ticket": "apr-0001", "ticket_state": "nouveau", "approval": null,
          "approver_set": { "threshold": { "required": 2, "size": 3 }, "members": [ "0x…" ], "source": "CuratorSet c=2124 r=0x… s=0x… h=1190..1190 b=0x… repli" } },
        "remises": [], "windows": [] }
    }
  ]
}
```

`approver_set` et `separation` sont les membres de la politique
d'approbation (4.2) de la version `policy_version` ; `service` porte les
réglages de configuration de 10.3, dont `administrators`, les contacts qui
peuvent retirer (EX-7.15). Avec un jeu `registre`, une trace commence par
une lecture réussie du jeu (`jeu_lu`) : sans elle, `evaluer` reçoit
`non_pret` (EX-8.3), ce que seule la trace `non-pret` exerce.

Une trace ne porte pas le document de politique : une entrée `charger` n'y
a que `policy_version`, la version chargée prend les paramètres de la trace
(`expire_after_ms`, `approver_set`, `separation`), et la réponse attendue à
`charger` est `{ "policy_version" }` seulement (le message complet de 12.2
porte le document et rend aussi `policy_sha256` et `approval_candidates`).
De même, une entrée `ouvrir` n'y porte ni `request_event` ni
`arguments_piece` (12.4).

**EX-A.6** Une trace est jouée sur un service vide, dont le jeu de repli est
vide et la version en vigueur `policy_version` : les identifiants sont
`apr-0001`, `apr-0002`, … dans l'ordre des réservations. Chaque pas donne
une entrée de 7.4 (`kind`, `at`, et ses données dans `data`, de la forme de
`$defs/entree`) et son attendu. Une entrée `acquitter` d'un scellement, et
une entrée `expiration`, portent l'objet `approval` scellé complet, avec
`at` (12.5, 12.6). Pour `evaluer`, `data.evaluation` est la sortie qu'`EVALUER`
rendrait, avec `contest_ms` et `opening` du ticket qu'elle créerait (EX-5.3), de
sorte que la trace ne dépend pas des règles de l'évaluation (sections 4 à 6) ;
elle est ignorée pour une ré-émission reconnue (EX-7.6).
L'attendu donne : `tickets`, l'état de **chaque** ticket connu après le pas,
minuteurs échus compris (EX-7.7) ; `accepted` et `reason`, le sort de
l'entrée (EX-7.8, table 12.8 ; pour une erreur d'`evaluer`, `accepted` est
faux, `reason` est l'erreur et `response` est `null`) ; `response`, la
réponse rendue à l'émetteur (`charger`, `evaluer`, `ouvrir`, `acquitter`,
`consommer`, `expiration`), sinon `null` ; `remises`, les remises calculées
pendant le pas, dans l'ordre (12.5) ; `windows`, les fenêtres ouvertes après
le pas (`$defs/fenetre_ouverte`), triées par ticket. Les signatures des
entrées `voter` sont de vraies signatures EIP-191 des comptes de A.2 sur
`D_A` (9.1).

**EX-A.7** Les traces couvrent au moins :

| Fichier | Ce qu'il exerce |
|---|---|
| `approuve-sans-contestation.json` | réservation, ouverture, gel, votes des comptes 1 et 2, confirmation du jeu, remise, scellement, ré-émission `approuve` servie une fois, consommation, nouvel appel identique : nouveau ticket |
| `refuse-seuil.json` | deux refus : décision `refuse` ; ré-émission : `refuse` ; fin de reconnaissance : `clos` |
| `expire-sans-vote.json` | échéance sans vote : `expire`, raison `echeance atteinte sans decision` ; escalades sans effet sur l'état et l'échéance |
| `vote-remplace.json` | un approbateur change son vote ; vote de même décision et d'un autre motif sans effet (`vote_identique`) |
| `contestation-sans-objection.json` | `contest_ms > 0`, seuil atteint, approbation de plus sans effet sur la fenêtre, fin de fenêtre, remise |
| `contestation-objection-levee.json` | objection pendant la fenêtre, retour en `ouvert`, objection levée par son auteur, nouvelle fenêtre complète |
| `contestation-objection-maintenue.json` | objection jusqu'à l'échéance : `expire`, `echeance atteinte, objection non levee` ; récusation de l'auteur sans effet sur l'objection ni sur son refus |
| `contestation-refus-anterieur.json` | refus avant le seuil : objection (EX-10.7) ; les approbations n'ouvrent pas de fenêtre tant que son auteur ne l'a pas levée ; levée, une fenêtre complète s'ouvre |
| `contestation-apres-echeance.json` | seuil atteint `contest_ms` avant l'échéance : `expire`, `echeance atteinte pendant la fenetre de contestation` (EX-7.7, égalité comprise) |
| `jeu-change-pendant-contestation.json` | en `seuil_atteint`, nouveau gel du jeu épinglé (compte 4 ajouté, seuil inchangé) : fenêtre annulée, nouvelle fenêtre complète à l'instant de la lecture (EX-8.6) |
| `separation-auto-approbation.json`, `separation-auto-permise.json` | vote du compte 3, adresse du demandeur : refusé `auto_approbation` sous `interdite`, accepté sous `permise` |
| `seuil-inatteignable.json` | compte 3 inéligible, compte 1 récusé : un seul éligible pour un seuil de 2 ; `expire`, `echeance atteinte, seuil inatteignable` |
| `recusation.json` | récusation : vote `approuve` retiré, membre inéligible, récusation répétée refusée ; récusation d'un non-membre et du demandeur refusées |
| `recusation-refus-maintenu.json` | récusation d'un membre qui a refusé : son refus reste compté (EX-10.4) et complète la décision `refuse` |
| `jeu-change-membre-retire.json` | un signataire retiré du jeu avant la remise : vote écarté `hors_jeu`, retour en `ouvert` |
| `jeu-seuil-abaisse.json` | seuil du jeu épinglé ramené à 1 pendant l'attente : seuil effectif inchangé (2), remise de deux signatures avec le seuil confirmé 1 sur 3 (EX-7.28, EX-8.6) |
| `jeu-reassigne.json` | réassignation au jeu 2 pendant `verification` : lecture `illisible` (`jeu_non_attendu`), lecture `lu` du jeu 2 traitée de même, aucun gel, compte 4 `hors_jeu` ; `expire`, `echeance atteinte, jeu reassigne` |
| `jeu-illisible.json` | jeu jamais figé : votes refusés `jeu_non_fige`, `expire` sur le jeu de repli (`source` terminée par ` repli`) |
| `non-pret.json` | jeu registre jamais lu : `non_pret`, même après une lecture illisible ; version non chargée : `politique_inconnue` |
| `jeu-statique.json` | `approver_set` `statique` : gel immédiat, confirmation immédiate, `source` `jeu statique de la politique vecteurs-ct3-1` ; réponse `nouveau` avec le jeu statique |
| `signature-hors-jeu.json` | vote du compte 4 non membre : `hors_jeu` ; signature d'un autre ticket, sur la chaîne « 0x… », de 64 octets, `v = 29` : `signature_invalide` ; formes normalisées acceptées |
| `ordre-des-raisons-de-vote.json` | votes à deux défauts : la première raison d'EX-9.10 l'emporte |
| `reemission-en-attente.json` | ré-émission pendant l'attente : `en_attente`, même ticket ; ré-émission sur `reserve` : `nouveau`, même ticket ; `ouvrir` répété : état courant ; autre `request_hash` : `ticket_deja_ouvert` |
| `retrait.json`, `retrait-administrateur.json` | retrait par le demandeur ou par un administrateur (`administrators`) : `expire`, `echeance avancee par retrait` ; retrait par un tiers refusé |
| `acquittement-temporaire.json` | refus temporaire puis échéance : décision caduque remplacée par `expire` ; ancienne remise sans effet |
| `deja-decide.json` | `acquitter` `refuse` `ticket_deja_decide` de la même demande : alignement, `approval` gardé tel que reçu ; `expiration` du noyau et ré-émission qui reçoit son objet |
| `deja-decide-autre-demande.json` | `ticket_deja_decide` avec la décision d'une autre demande : aucun alignement, `clos` (T20) ; la ré-émission est une nouvelle demande |
| `acquittements-noyau.json` | T16 (votes écartés, retour en `ouvert`) et acquittement répété sans effet ; T14 avec une décision différente de la remise ; scellement contraire refusé ; T15, T13 et ancienne remise sans effet |
| `expiration-noyau.json` | T16 sur une remise `expire` puis T17 ; T17 depuis `reserve` (ouvrir tardif sans effet) et depuis `abandonne` |
| `retenir-double-reemission.json` | mode `retenir` : `acquitter` `scelle` avec `held`, ré-émission avant `consommer` : `en_attente` ; après : nouvelle demande |
| `consommation-tardive.json` | approbation servie, ticket `clos` à la fin du délai de reconnaissance (T19) ; `consommer` tardif admis sans changer l'état (T22) ; répété : sans effet ; d'un autre événement : `requete_invalide` |
| `reservation-abandonnee.json` | réservation sans `ouvrir` : `abandonne` ; `ouvrir` tardif : `a_remettre`, décision `expire` (`reservation abandonnee avant l'ouverture`) |
| `plafond.json` | `max_open_tickets` atteint : erreur `plafond_atteint`, aucun ticket ; une ré-émission reconnue reste servie ; sorties `autorise` et `refuse` non concernées |
| `fenetre-ouvrante.json` | tickets ouvrants approuvés : fenêtre ouverte à l'acquittement du scellement, `debut = approval.at`, remplacée par une fenêtre de même portée, épuisée puis retirée, une autre retirée à sa fin (TK-13) ; ticket non ouvrant approuvé : aucune fenêtre |
| `fenetre-politique-changee.json` | `charger` d'une autre version avant le scellement d'un ticket ouvrant : aucune fenêtre ; après : toutes les fenêtres fermées |
| `politique-changee.json` | ré-émission sous une nouvelle version : autre clé, nouvelle évaluation ; le ticket `approuve` n'est pas consommé et finit `clos` |

### A.7 `decisions/`

Un cas par fichier, au format `ticket-v0.schema.json#/$defs/cas_remise` :
`{ "version": 0, "id", "description", "check", "context": { "org_id",
"journal_id", "retained": [ { "seq", "ticket", "hash", "ts", "launched_by"
} ], "decided": [ { "ticket", "decision", "seq", "hash", "at" } ],
"expire_after_ms", "separation", "write_at" }, "remise", "expected": {
"result", "reason" } }`.
`retained` et `decided` sont les événements `retenue` (avec leur
`delegation.launched_by`) et les décisions déjà scellées du journal,
`expire_after_ms` et `separation` ceux de la politique de la version du
ticket (SG-4, SG-7), `write_at` l'instant d'écriture que le noyau poserait
(SG-4) ;
`check` est la vérification SG- visée (`null` pour un cas valide) ;
`expected.result` vaut `scelle` ou `refuse` et `expected.reason` est la
raison de la première vérification en échec dans l'ordre de 9.4 (EX-9.11).

**EX-A.8** `decisions/valides/` contient au moins : une approbation 2 sur 3
des comptes 1 et 2 ; un refus 2 sur 3 ; une expiration sans signature ;
une approbation sur un jeu `statique` (`source` d'EX-8.8) ;
la décision du ticket `apr-2201` des vecteurs de CT-1 (`journal-sinistres`,
seq 6), dont `approval` augmenté de `at` doit être égal, clé pour clé, à
celui de `spec/vecteurs/ct-1/journal-valide/evenements.json`, seq 6.
`decisions/invalides/` contient au moins un cas par raison de refus du noyau
de la table 12.8 (`remise_mal_formee`, `ticket_inconnu`,
`request_hash_different`, `ticket_deja_decide`, `echeance_depassee`,
`signature_invalide`, `approbateur_hors_jeu`, `approbateur_double`,
`seuil_different_du_jeu`, `expire_avec_signatures`, `seuil_non_atteint`,
`auto_approbation`), et
en particulier : une signature produite sur la chaîne `"0x…"` de `D_A` au lieu
de ses octets (EX-9.7) ; une signature `approuve` présentée dans une remise
`refuse` ; une signature d'un autre journal ; une signature à `s` haut ;
une remise dont `write_at` est égal à l'échéance (`echeance_depassee`) ; un
`remise_id` d'un autre ticket (SG-1) ; un jeu déclaré dont `size` diffère
du nombre de membres (SG-6) ; une approbation signée par une adresse du
demandeur sous `self_approval: "interdite"` (`auto_approbation`, SG-7 :
`invalides/sg7-auto-approbation.json`, qui remplace le cas
`valides/separation-non-verifiee-par-le-noyau`, valide avant la version 0.3
de CT-2) ; le même refus signé par le demandeur
(`invalides/sg7-refus-par-le-demandeur.json` : SG-7 vaut aussi pour
`refuse`) ; la même approbation sous `permise`, dans
`valides/separation-permise.json`. Il contient aussi, pour l'ordre d'EX-9.11, un
cas pour chaque paire de vérifications voisines en échec (`ordre-sg1-sg2` à
`ordre-sg6-sg7`) et pour les raisons de SG-6 dans leur ordre
(`approbateur_double` avant `approbateur_hors_jeu`, `approbateur_hors_jeu`
avant `seuil_different_du_jeu`, `seuil_different_du_jeu` avant
`expire_avec_signatures` et `seuil_non_atteint`).

### A.8 `signatures/normalisation.json`

`{ "version": 0, "cases": [ { "id", "signature", "expected", "reason" } ] }` :
`signature` en hexadécimal minuscule, de 65 octets sauf pour les cas de
longueur, qui sont refusés (64 octets, exigé ; 66 octets, présent),
`expected` la forme normalisée d'EX-9.3 ou `null` si elle est refusée,
`reason` `null` ou `signature_invalide`. Au moins : forme canonique
inchangée ; `s` haut et `v = 27` ; `s` haut et `v = 28` ; `v = 0` ;
`v = 1` ; `v = 29` (refusée) ; longueur de 64 octets (refusée) ; `r = 0`,
`r = n`, `s = 0` et `s = n` (refusées). Chaque forme normalisée recouvre la même
adresse que la forme d'entrée.

### A.9 Implémentations, tests et intégration continue

**EX-A.9** L'implémentation de référence est `scripts/lib/approbation.mjs` :
validation de la politique, évaluation (section 6), outils susceptibles,
machine à états du ticket (section 7, sections 8 et 10), construction et
vérification des remises (9.4) avec les fonctions EIP-191 de
`scripts/lib/journal.mjs`, normalisation d'EX-9.3. `test/approbation.test.js`
régénère les vecteurs dans un répertoire temporaire et exige les mêmes
octets, puis rejoue chaque famille par l'implémentation de référence.

Les familles `annuaire/` et `console/` sont rejouées par la bibliothèque de
la console de référence, `scripts/lib/console.mjs` (13.15), dans
`test/console.test.js` (EX-A.14, EX-A.16) ; le même fichier sert la page
`console/` et un service simulé à Chromium, par Playwright, pour les
scénarios d'EX-13.36 ; ce test est sauté, avec un message qui le dit, quand
Playwright ou Chromium ne se lancent pas, sauf sous
`NOORTRACE_EXIGER_CHROMIUM=1`, où il échoue (EX-13.36, EX-A.11).
`test/console-primitives.test.js` confronte en outre, de façon
déterministe (entrées tirées de SHA-256 d'un compteur, graine fixe), les
primitives de `scripts/lib/console.mjs` (SHA-256, HMAC-SHA-256,
PBKDF2-HMAC-SHA-256, scrypt, AES-128-CTR, dont un compteur qui déborde
2^128, Keccak-256, adresse, signature RFC 6979 à `s` bas, recouvrement, dont
un `s` haut avec l'identifiant de recouvrement inversé, condensé EIP-191) à
`node:crypto`, à `@noble/hashes`, à `@noble/curves` et à ethers, présents
dans `node_modules` (EX-13.32).

**EX-A.10** Le vérificateur Go indépendant est le module
`spec/vecteurs/ct-3/verificateur-independant` (`noortrace-ct3`, `go 1.24`,
bibliothèque standard seulement), écrit depuis la seule spécification (CT-3,
et CT-1 pour `A`, `D_A` et E-9), sans lire le code de `scripts/` ni de
`test/`, comme ceux de CT-1 et CT-2 ; il PEUT copier les fichiers des
modules CT-1 et CT-2 (JCS, JCS intégral, keccak256, secp256k1) en le disant
en tête de fichier. Il
recalcule toutes les familles de A.3 (constantes, schémas, évaluation,
candidats, épreuve, traces, remises, normalisation) et les familles
`annuaire/` et `console/` (A.10, A.11), s'exécute par
`go run . ..` depuis son répertoire, et rend `0` si tout concorde, `1` s'il
trouve au moins une discordance, qu'il liste, `2` pour un usage incorrect.

**EX-A.11** L'intégration continue régénère `spec/vecteurs/ct-3` et exige
`git diff --exit-code` et aucun fichier non suivi, puis lance dans le module
Go `gofmt -l` (sortie vide), `go vet ./...`, `go test ./...` et
`go run . ..`, à côté des tâches de CT-1, CT-2 et CT-6.

L'intégration continue rejoue aussi, dans son travail de confrontation, les
scripts de `spec/vecteurs/ct-3/confrontation/` (EX-A.18) avec les versions
exactes qu'ils déclarent, et exige des sorties égales, octet pour octet, aux
sorties publiées. Son travail `console-chromium` installe Playwright 1.56.1
(hors de `package.json`) et Chromium, et exécute `test/console.test.js` sous
`NOORTRACE_EXIGER_CHROMIUM=1` : le test de bout en bout d'EX-13.36 y tourne
et ne peut pas y être sauté (15.2) ; dans le travail `tests`, sans
Playwright, seule la partie Node du fichier tourne, et la partie Chromium y
est sautée avec son message.

### A.10 `annuaire/` (vérifications AN-)

Constantes propres à la famille, écrites par le générateur dans `INDEX.md`
et dans les fichiers de la famille, et non dans `constantes.json`, qui ne
change pas :

| Grandeur | Dérivation | Usage |
|---|---|---|
| Origine de la console | `https://console.assureur-demo.example` (domaine réservé `.example`) | `annuaire/` |
| Émetteur d'identité | `https://idp.assureur-demo.example` ; identités `oidc https://idp.assureur-demo.example approbateur-<n>` (comptes 1, 2 et 4), `… u.martin` (compte 3, alias de demandeur `u.martin@assureur-demo.example`), `… admin-1` (administrateur, sans adresse) | `annuaire/` |
| Nonce d'inscription `k` | 16 premiers octets de `SHA-256(UTF-8("noortrace/vecteurs/ct3/inscription/nonce/<k>"))`, en hexadécimal minuscule | `annuaire/` |
| Instant de base de l'annuaire | `2026-11-10T08:00:00.000Z` ; `registration_ttl_ms` 600 000 | `annuaire/` |
| Identifiant d'une entrée créée | `apb-` suivi, en décimal sur 4 chiffres complétés de zéros à gauche, du nombre d'entrées de l'annuaire avant la création, augmenté de un (les entrées ne sont jamais supprimées) : depuis `annuaires/avant-inscriptions.json`, qui a deux entrées, la première création donne `apb-0003`. Les vecteurs partent d'un service sans perte d'état, comme les traces d'EX-7.2 ; en exploitation, EX-13.9 s'applique (64 bits aléatoires ou époque) | `annuaire/` |

**EX-A.12** La famille `annuaire/` sert les vérifications AN-1 à AN-10
(13.16). Ses fichiers :

| Fichier | Format | Contenu |
|---|---|---|
| `annuaires/vide.json` | racine d'`annuaire-approbateurs-v0` | annuaire sans entrée, administrateur `admin-1` |
| `annuaires/reference.json` | racine | l'annuaire d'exemple de 13.4, octet pour octet la même valeur JSON |
| `annuaires/avant-inscriptions.json`, `annuaires/controles.json` | racine | les départs d'`inscriptions.json` et de `controles-vote.json` : la référence sans sa dernière opération, ou entière, puis l'entrée `apb-0002` désactivée |
| `messages.json` | `$defs/fichier_messages` | construction (AN-2) et analyse des textes, y compris refusés |
| `inscriptions.json` | `$defs/fichier_inscriptions` | vérifications d'`inscrire` (AN-3, AN-4, AN-7) |
| `domaines.json` | `$defs/fichier_domaines` | AN-5 |
| `traces/<nom>.json` | `$defs/trace_annuaire` | suites d'opérations (AN-6, AN-7) |
| `controles-vote.json` | `$defs/fichier_controles_vote` | AN-8 |
| `controles-canal.json` | `$defs/fichier_controles_canal` | AN-10 |
| `exports/<nom>.json`, `exports/attendu.json` | racine ; `$defs/attendu_exports` | AN-9 |

Une trace d'annuaire part de l'annuaire `initial` ; chaque pas donne une
méthode de 12.9, son instant (horloge du service), sa requête, le nonce que
le service tire s'il s'agit de `preparer_inscription`, et l'attendu : sort,
raison, réponse, `revision` et l'état résumé de chaque entrée. Les
signatures sont de vraies signatures EIP-191 des comptes de A.2 ; les
signatures non canoniques des cas de forme sont dérivées des signatures
canoniques par les transformations d'EX-9.3 (`s` → `n − s`, `v` inversé ;
`v` − 27), sans clé.

**EX-A.13** La famille couvre au moins :

| Fichier ou cas | Ce qu'il exerce |
|---|---|
| `messages.json` | les messages des comptes 1 à 4 de l'annuaire de référence ; textes refusés : CR LF, LF final, onze lignes, première ou deuxième ligne changée d'un caractère, clé en autre casse, espace double après `:`, caractère accentué, adresse en casse EIP-55, nonce de 31 ou de 33 chiffres, instant sans millisecondes, identité de quatre jetons |
| `inscriptions.json` | inscription acceptée qui crée l'entrée, et qui complète une entrée existante ; `s` haut et `v` = 0 acceptés et gardés normalisés ; chaque raison d'EX-13.15 au moins une fois, sauf `requete_invalide`, qu'un fichier conforme à `$defs/fichier_inscriptions` ne peut pas porter, dont `v` = 29, `v` = 37 et une signature de 64 octets (`signature_invalide`) ; message signé par une autre clé ; défi remplacé (`nonce_inconnu`) ; nonce présenté deux fois ; réception à `Expire le` exactement (`inscription_expiree`) et à `Emis le` exactement (acceptée) ; adresse d'une entrée révoquée réinscrite par une autre personne (`adresse_deja_attribuee`) ; pour l'ordre, un cas pour chaque paire de raisons voisines, sauf la paire `requete_invalide`/`identite_invalide` |
| `domaines.json` | la signature d'inscription d'exemple présentée comme vote sur le `A` d'`apr-0001` ; la signature du vote du compte 1 sur `apr-0001` présentée comme inscription sur le message d'exemple |
| `traces/inscription-validation.json` | défi ; `inscrire` refusée `requete_invalide` (membre en trop), puis la paire `requete_invalide`/`identite_invalide` (même requête avec une identité non canonique : `requete_invalide` d'abord) ; inscription, validation par `admin-1`, état sur lequel un contrôle de vote est autorisé |
| `traces/confiscation.json` | une personne inscrit, sous sa propre session, l'adresse d'une autre, qui a signé le texte à son nom : acceptée, en attente ; le détenteur reçoit `adresse_deja_attribuee` ; l'administrateur révoque avec un motif ; le détenteur reçoit toujours `adresse_deja_attribuee` (EX-13.17, « Confiscation ») |
| `traces/auto-validation.json` | un administrateur qui a une entrée valide sa propre adresse : `auto_validation` ; une identité hors d'`administrators` : `non_administrateur` |
| `traces/rotation.json` | deuxième adresse inscrite puis validée : la première `revoquee`, cause `remplacee`, `replaced_by` |
| `traces/revocation.json` | révocation par la personne (cause `personne`) et par un administrateur ; révocation par un tiers refusée ; révocation répétée : `etat_incompatible` |
| `traces/desactivation.json` | désactivation qui révoque tout, défi effacé, préparation refusée `identite_desactivee`, réactivation sans adresse rétablie, nouvelle inscription |
| `traces/adresse-jamais-reattribuee.json` | adresse révoquée d'une entrée, que prépare une autre identité : `adresse_deja_attribuee` dès `preparer_inscription` |
| `traces/alias-demandeur.json` | `lier_demandeur`, double liaison refusée, `delier_demandeur`, valeur inconnue refusée |
| `controles-canal.json` | `consulter` par une session éligible, par un administrateur, par une session dont l'adresse active n'est pas éligible (le demandeur sous `interdite`, `session_non_autorisee`) et par une identité sans entrée ; pour un ticket inconnu (`ticket` nul), `consulter` par une session de l'organisation, éligible ou non (`ticket_inconnu`), par une session hors de l'organisation ou d'entrée désactivée (`session_non_autorisee`) et par une identité non canonique ; `tickets` par une session de l'organisation, par un administrateur, par une session hors de l'organisation et d'entrée désactivée ; `voter` et `recuser` de l'adresse active, d'une autre adresse, d'une adresse révoquée ; `voter` pour un ticket inconnu, de l'adresse active (`ticket_inconnu`) et d'une autre adresse (`session_non_autorisee`) ; `retirer` par le demandeur (`by` = `launched_by`), par un administrateur (`by` = son identité), par un approbateur qui n'est pas le demandeur avec `by` = `launched_by` (`session_non_autorisee`), par un administrateur avec `by` = `launched_by`, par un approbateur avec `by` = son identité, et d'un ticket inconnu (`ticket_inconnu`) ; une identité non canonique (`identite_invalide`) |
| `controles-vote.json` | chaque raison d'EX-13.18 dans l'ordre, et chaque paire de raisons voisines (dont un demandeur par alias sous `interdite`, et le même autorisé sous `permise`), récusation par une adresse non attribuée, récusation par la session du demandeur (autorisée), vote autorisé, avertissement `separation_incomplete` |
| `exports/` | l'annuaire de référence sans écart ; un cas par code d'EX-13.19 : preuve signée par une autre clé, preuve dont l'identité diffère de l'entrée, deux adresses actives, une adresse dans deux entrées, identité en double, auto-validation, `revision` faux, opérations qui ne se rejouent pas, document non conforme au schéma ; la recopie d'un nouveau réglage `administrators` suivie d'une opération du nouvel administrateur (sans écart), une liste d'administrateurs changée sans opération (`/operations/1`) et une liste qui diffère de celle du rejeu (`/administrators`) (EX-13.37) |

**EX-A.14** Implémentations et tests. `scripts/lib/console.mjs`
(EX-13.32) rejoue toute la famille ; `test/console.test.js` régénère les
vecteurs dans un répertoire temporaire, exige les mêmes octets, et rejoue
chaque fichier ; le test de bout en bout d'EX-13.36 emploie l'annuaire de
référence et les vecteurs de la famille `console/` (A.11). Le vérificateur Go
indépendant recalcule la famille depuis le seul texte de CT-3 0.3 (formes,
messages, condensés EIP-191, recouvrements, ordres des raisons, opérations,
contrôles, exports). La confrontation tierce (EX-A.18) recouvre l'adresse de
chaque signature d'inscription de `inscriptions.json`, `domaines.json`,
`annuaires/reference.json` et des traces (`messages.json` ne porte aucune
signature) par eth-account (`encode_defunct(primitive=octets du texte)`,
`Account.recover_message`) et par ethers (`verifyMessage(texte)`) — pour le
texte ASCII, la chaîne et ses octets UTF-8 sont les mêmes octets — et la compare
à l'adresse attendue, avec les verdicts d'EX-A.18 : la forme est contrôlée par
le script avant la bibliothèque (EX-9.22), ces deux bibliothèques acceptant
d'autres formes (R4-F37, R4-F40).

### A.11 `console/`, épreuve de lecture et confrontation tierce

Vérifications CS-, servies par la famille `console/` (schéma
`console-approbation-v0`) :

| Id | Vérification | Règles | Fichiers |
|---|---|---|---|
| CS-1 | Événement `retenue` (statut, décision, ticket, hachage recalculé égal à `hash` et à `request_hash`) et pièce « arguments » (`sha256`, `length`, JSON strict, ou valeur en ligne) | EX-9.6 a et b, EX-9.15 (2, 3) | `modeles/` |
| CS-2 | Champs liés ; intention portée par une référence (`intent_status`) ; arguments feuille par feuille : `verifie`, `non_verifiable`, `different` ; chemin de la pièce absent de l'affichage ; effets dont un membre est tiré du résultat (`unresolved`) | EX-9.6 c et d, EX-9.15 (4, 5), EX-9.16, EX-12.14 | `modeles/` |
| CS-3 | `A`, `JCS(A)`, `D_A` et `H` des deux décisions ; égalité aux condensés du service ; empreinte et groupes ; UTF-8 | EX-9.17 à EX-9.19 | `modeles/`, `requetes/` |
| CS-4 | État, jeu, décision, adresse attribuée, membre, éligible, session du demandeur, motif ; ordre et complétude de `blocking` | EX-9.15 (1, 7 à 13) | `modeles/` |
| CS-5 | Requête `personal_sign` exacte ; préimage de 60 octets ; signature RFC 6979 attendue de la clé de test | EX-13.24 | `requetes/` |
| CS-6 | Réponse du portefeuille : codes EIP-1193, forme, normalisation, recouvrement sur `H`, adresse | EX-9.21, EX-13.29 | `reponses/` |
| CS-7 | Vote construit : corps exact de `voter` | EX-9.21 (8), EX-12.16 | `reponses/` |
| CS-8 | Découverte EIP-6963 : validation des annonces, réannonce, `uuid` en double, ordre | EX-13.22 | `decouverte/` |
| CS-9 | Fichier de clé : format, dérivation admise, MAC, déchiffrement, intervalle de la clé, adresse, avertissement | EX-13.28 | `fichiers-cle/` |

Un fichier par cas, de forme `$defs/cas_modele`, `$defs/cas_requete`,
`$defs/cas_reponse`, `$defs/cas_decouverte` ou `$defs/cas_fichier_cle`. Pour
`modeles/`, `input.view` est une vue du ticket (`$defs/vue_ticket`),
`input.session` l'identité de session, les adresses que l'annuaire lui
attribue et le fait qu'elle soit le demandeur, `input.now` l'instant du
calcul, et `expected` le modèle d'affichage complet (`$defs/modele_affichage`).
Pour `requetes/`, `input.account` est l'indice du compte de A.2 qui signe, et
`expected.signature` la signature RFC 6979 de ce compte sur `H`. Pour
`reponses/`, `input.response` est l'issue de la requête telle que la page la
reçoit, promesse tenue (`result`) ou rompue (`error`, avec `code` nul quand
l'erreur n'a pas de code numérique) ; `expected.vote` est le corps de `voter`
(12.9), ou `null`. Pour `decouverte/`, `provider` nomme l'objet fournisseur :
deux annonces de même nom désignent le même objet ; `expected.rejected`
donne l'indice, dans `input.announcements`, de chaque annonce écartée, avec
sa raison, selon le pas 3 d'EX-13.22 (première annonce de l'`uuid`, annonce
en conflit et toute annonce ultérieure de cet `uuid`).

**EX-A.15** La famille `console/` comprend au moins :

- `modeles/` : le ticket `apr-2201` des vecteurs de CT-1 (événement seq 5 et
  pièce de `journal-valide`, lus et jamais réécrits) pour `approuve` et pour
  `refuse`, valides, l'IBAN `non_verifiable` ; une demande de
  `journal-approbations` dont la référence des arguments est en ligne
  (événement `retenue` construit par le générateur et scellé par la clé de
  test `rec-test-01` de CT-1) ; un événement modifié d'un octet
  (`evenement_invalide`, condensés nuls) ; un `request_hash` de la vue
  différent du `hash` ; une pièce modifiée (`piece_invalide`, arguments
  `non_verifiable`) ; un outil, une règle, un `run_id` et une intention
  différents (`champ_different`) ; une intention que l'événement porte par
  une référence (ticket `apr-0902`, événement seq 10 chaîné au précédent et
  scellé par `rec-test-01` : `intent_status` `reference_non_verifiable`,
  signable) ; un effet dont `object` est tiré du résultat (`unresolved`,
  signable) ; un argument différent ; un argument en
  clair absent de la pièce (`non_verifiable`) ; un chemin de la pièce absent
  de l'affichage ; un `D_A` du service faux pour `approuve`, puis pour
  `refuse` seulement (`empreinte_divergente`) ; un ticket `approuve`
  (`ticket_clos_aux_votes`) ; un jeu non figé ; une décision absente ; une
  identité sans entrée (`identite_inconnue`), une entrée désactivée
  (`identite_desactivee`), une adresse non attribuée, une adresse attribuée
  hors du jeu (compte 4),
  l'adresse du demandeur (compte 3, `auto_approbation` et
  `session_du_demandeur`), un membre récusé (`recuse`) ; un motif de 1 025
  caractères ; un demandeur sans entrée dans `separation`
  (`separation_non_verifiable`) ; des membres ajoutés (`membres_ajoutes`) ;
  une adresse de l'annuaire pour le demandeur que la politique ne déclare
  pas (`separation_incomplete`) ;
  un cas à plusieurs défauts, pour l'ordre de `blocking` ;
- `requetes/` : les comptes 1 et 2 sur `D_approuve` et le compte 1 sur
  `D_refuse` du ticket `apr-2201`, dont les signatures sur `D_approuve` sont
  celles des vecteurs de CT-1 ; le compte 1 sur le ticket `apr-0001` de
  `decisions/valides/approbation-2-sur-3.json`
  (`D_A` = `0xce13c3f15c3eab4c81a4735828741b0acf205a46e59d6894ed2e7589b5777d0d`,
  `H` = `0x9079b529368f08023b43a2b61a7ab9f92c3c42a28cefe10dfc161b48835ca728`) ;
  un `D_A` dont le premier octet est nul, pour les conversions qui le
  perdraient (R4-F41) : décision `approuve`, `journal-approbations`,
  `request_hash` =
  `SHA-256(UTF-8("noortrace/vecteurs/ct3/demande/console-zero"))`
  = `0xd3620aa8af23a0d83931eb2db11403b2947430cbd89c3387781bce95ab06823b`,
  ticket `apr-c0-<k>` pour le plus petit entier `k ≥ 1` qui donne un premier
  octet nul : `k` = 542, `D_A` =
  `0x00d9060ac22cf499a79777dfeb7fa339783ac23f12571712c02663d9acdca5c7` ;
- `reponses/` : forme canonique ; `v = 0` et `v = 1` (normalisés) ; `s` haut
  avec `v = 27` et avec `v = 28` (normalisés) ; `v = 29`, `v = 37`, `v = 38`,
  64 octets (EIP-2098), 66 octets, `r = 0`, `s = n` (refusés,
  `signature_invalide`) ; chiffres majuscules (acceptés, écrits en
  minuscules) ; signature d'une autre adresse et signature de la chaîne
  `"0x…"` (`adresse_differente`) ; erreurs 4001, 4100, 4200, 4900, 4901, un
  autre code, une erreur sans code ; une promesse tenue avec `null` et avec
  une chaîne non hexadécimale (`reponse_invalide`) ;
- `decouverte/` : aucune annonce ; une annonce (aucune présélection) ; deux
  portefeuilles ; une réannonce par le même objet ; un `uuid` revendiqué par
  deux objets ; des annonces invalides (`uuid` qui n'est pas de version 4,
  icône qui n'est pas une URI `data:`, nom vide) ;
- `fichiers-cle/` : `pbkdf2` et `scrypt` valides (clé du compte 1, mot de
  passe `noortrace/vecteurs/ct3/console/mot-de-passe`, `salt`, `iv` et
  `id` tirés de
  `SHA-256(UTF-8("noortrace/vecteurs/ct3/console/fichier-cle/<cas>/sel"))`,
  `…/iv` (16 premiers octets) et `…/uuid` (16 premiers octets, bits de
  version 4 et de variante posés), `c` = 1 024, `n` = 1 024, `r` = 8,
  `p` = 1, avertissement `derivation_faible`) ; mauvais mot de passe et MAC
  modifié (`mot_de_passe_ou_mac`) ; `aes-128-cbc`, `kdf` inconnu,
  `prf` `hmac-sha512`, `dklen` 16, `n` qui n'est pas une puissance de 2, `n`
  = 2^19 (`fichier_cle_non_pris_en_charge`) ; `version` 1
  (`fichier_cle_invalide`) ; clé nulle (`cle_invalide`) ; clé du compte 2
  pour l'adresse du compte 1 (`adresse_differente`). Le vecteur `scrypt` de
  la définition, incohérent (R4-F34), n'est pas repris.

**EX-A.16** Chaque cas de `console/` valide contre sa définition de
`console-approbation-v0` ; deux générations donnent les mêmes octets ; les
signatures sont celles des comptes de A.2, par ECDSA déterministe (RFC 6979).
L'implémentation de référence et le vérificateur Go rendent `expected` pour
chaque cas.

**EX-A.17** **Épreuve de lecture de la console.** Critère du plan : deux
lecteurs, seuls et sans aide, chacun avec les seules sections de CT-3 que
son rôle reçoit, répondent par écrit aux questions de
`acceptation-console/consigne.md` :

| Rôle | Sections reçues | Questions |
|---|---|---|
| approbateur | 9 et 13 | Comment vous inscrivez-vous ? Comment signez-vous depuis la console avec votre portefeuille ? Que vérifiez-vous avant de signer ? Que faites-vous si l'empreinte diffère ? |
| développeur intégrateur | 7.4, 9, 12 et 13 | Quels messages la page, le portefeuille et le service échangent-ils, dans quel ordre, et avec quel contenu exact ? Que refuse la console, et à quel moment ? |

`acceptation-console-attendu.json` (`$defs/attendu_acceptation_console`)
donne, pour chaque question, les éléments qu'une réponse doit contenir et la
règle qui fonde chacun ; un troisième relecteur, qui n'a pas aidé les deux
autres, marque chaque élément présent ou absent. L'épreuve est réussie si
chaque réponse contient tous ses éléments. Les éléments sont au moins : pour
l'inscription, la connexion, le choix du portefeuille et du compte, la
lecture des lignes du message (origine, identité, adresse, « Ce message
n'est pas un vote » ; pour l'identité, la vérification de 13.17,
« S'inscrire », pas 3, l'émetteur après `oidc`, le sujet n'ayant pas à être
connu de l'approbateur : c'est le sens de l'élément « sa propre identité »
d'`acceptation-console-attendu.json`), la signature dans le portefeuille et
la validation
par un autre administrateur (13.17, EX-13.12 à EX-13.17) ; pour la signature, la
vue redemandée après le choix, le choix explicite du portefeuille et de
l'adresse, `personal_sign` et la comparaison de l'empreinte sur l'écran du
portefeuille ou de l'appareil (EX-9.15, EX-13.22 à EX-13.24, EX-9.20) ; pour ce
qu'il vérifie, les marques des arguments, la règle, la délégation, les 8
premiers et 8 derniers chiffres, « Message hash » comparé à `H`, un message en
hexadécimal et non une transaction (EX-9.4, EX-9.18, EX-9.20) ; si l'empreinte
diffère, refuser dans le portefeuille sans réessayer, prévenir l'administrateur
par un autre canal, et le fait qu'un refus dans le portefeuille n'est pas un
vote `refuse` (EX-9.20, EX-13.29) ; pour l'intégrateur, les neuf pas de 13.9
avec le contenu exact de `consulter`, de la requête `personal_sign` (ordre,
encodage) et de `voter`, puis les treize contrôles d'EX-9.15, les refus de forme
d'EX-9.21, les codes de 13.14, l'absence de `window.ethereum` implicite,
d'`eth_sign` et de toute signature du `D_A` du service. Les réponses des
lecteurs ne sont pas des vecteurs et ne sont pas publiées. Esquisse (« … »
marque une valeur omise) :

```json
{
  "version": 0,
  "roles": [
    { "role": "approbateur", "sections": [ "9", "13" ],
      "questions": [ { "id": "q4", "question": "Que faites-vous si l'empreinte diffère ?",
        "elements": [ { "element": "Refuser la requête dans le portefeuille et ne pas réessayer depuis cette page.", "rules": [ "EX-9.20" ] }, "…" ] }, "…" ] },
    { "role": "integrateur", "sections": [ "7.4", "9", "12", "13" ], "questions": [ "…" ] }
  ]
}
```

**EX-A.18** **Confrontation tierce.** Sous
`spec/vecteurs/ct-3/confrontation/`, jamais écrit par le générateur :

1. `eth-account/` : `LISEZMOI.md`, `exigences.txt` (eth-account 0.14.0,
   dernière version publiée à la date de la note R4 (R4-F39), et chacune de
   ses dépendances à une version exacte, installées sans résolution,
   `--no-deps`), `confronter_eth_account.py` ; pour chaque
   signature des vecteurs de CT-3 (entrées `voter` des traces de `tickets/`,
   remises de `decisions/`, formes de `signatures/normalisation.json`,
   `console/requetes/` et `console/reponses/`, messages d'inscription de
   `annuaire/`, A.10), il recalcule `D_A` (JCS et SHA-256) ou prend le
   message texte, recouvre l'adresse par `Account.recover_message` sur
   `encode_defunct(hexstr=D_A)` (jamais `text=` ni un entier, EX-9.22) ou
   `encode_defunct(primitive=<octets ASCII du message>)` pour un message
   d'inscription, et la
   compare à l'attendu ; il déchiffre chaque fichier valide de
   `console/fichiers-cle/` par `Account.decrypt` et compare l'adresse ;
2. `ethers/` : `LISEZMOI.md` et `confronter_ethers.mjs`, qui fait de même
   par `verifyMessage(getBytes(D_A), signature)` (ou le texte du message
   d'inscription) et `decryptKeystoreJsonSync`, avec l'ethers du dépôt
   (6.17.0, version `latest` à la date de la note R4, R4-F36), dont il écrit
   la version lue dans `node_modules/ethers/package.json` ;
3. `sorties/eth-account.txt` et `sorties/ethers.txt`, publiées : une ligne
   par signature (famille, cas, indice, adresse recouvrée, adresse attendue,
   verdict), sans chemin local. Le verdict est `concorde` quand la
   bibliothèque et CT-3 acceptent la forme et recouvrent la même adresse, ou
   la refusent tous deux ; `acceptee_par_la_bibliotheque` quand CT-3 refuse
   une forme que la bibliothèque accepte (attendu pour `v = 37` et `v = 38`
   avec les deux, et pour 64 octets avec ethers, R4-F38, R4-F41 ; et, pour
   une forme présentée au noyau, qui ne normalise pas (`decisions/invalides/`,
   SG-5) : `s` haut et `v` ∈ {0, 1} avec eth-account, `v` ∈ {0, 1} avec
   ethers) ;
   `refusee_par_la_bibliotheque` quand CT-3 normalise une forme que la
   bibliothèque refuse (attendu pour `s` haut avec ethers, R4-F37, R4-F38) ;
   `discordance` quand une forme que CT-3 accepte recouvre une autre
   adresse que l'attendue, ou qu'une forme canonique est refusée. Les deux
   écarts sont inscrits et ne font pas échouer le script ; une
   `discordance` le fait rendre 1. Ces écarts sont la raison d'EX-9.22.

**EX-A.19** L'intégration continue ajoute à son travail de confrontation
une étape par script (environnement virtuel Python pour eth-account, Node
pour ethers), qui exige le code 0 et des sorties égales aux sorties
publiées ; `test/confrontation.test.js` exige que les sorties publiées
portent sur les vecteurs du dépôt et rejoue chaque script quand son outil
est présent à la version déclarée.

## Annexe B — Sources des faits externes

Les renvois R1 à R5 du texte désignent des notes de recherche du lot CT-3,
internes et non publiées : R1 (code et spécifications du dépôt, contrats,
curators-hub), R2 (protocoles et signature : MCP, délais des hôtes, EIP-191,
portefeuilles, moteurs de politique), R3 (contrôle humain et pratiques :
règlement sur l'IA, RGPD, LPD, NIST, FINMA, produits d'approbation), R4
(portefeuilles : EIP-1193, EIP-6963, `personal_sign`, portefeuilles
matériels, WalletConnect v2, fichiers de clé, bibliothèques de
vérification), R5 (identité, annuaire et page de signature : OpenID Connect,
NIST SP 800-63B-4, ERC-4361, SCIM, WebAuthn, politique de sécurité du
contenu, curators-hub). Cette annexe donne, pour chaque renvoi des parties A
et B, l'objet du fait et les sources primaires que la note a consultées, à
la date indiquée ; ces sources font foi, pas la note. Un fait marqué « non
vérifié » le reste. Un intervalle « R3-F72 à R3-F78 » du texte renvoie à
chacun des faits qu'il couvre.

Conventions, reprises de CT-6 annexe B :

- un renvoi s'écrit comme dans le texte (« R2-F30 », « R1-NV4 », « R2 NV-4 »
  pour un point non vérifié, « R1-C23 » pour une conséquence de la note) ;
- « présent dépôt » désigne un fichier de ce dépôt public, cité par son
  chemin et ses lignes au commit `d3ac808` : source publique, recoupable ;
  les lignes de CT-2 y sont celles de sa version 0.2, que la version 0.3 a
  déplacées et, pour les codes d'erreur et l'attente, remplacées ;
- « noorchain-core » désigne le dépôt de référence, privé, au commit
  `618fcef` : un fait qui en est tiré n'est pas recoupable publiquement ;
- « expérience de la note » désigne une manipulation faite par la note (réseau
  de développement, mesure Node) dont les sorties ne sont pas publiées ;
- les URL sont recopiées de la note ; `MCP` abrège
  `https://github.com/modelcontextprotocol/modelcontextprotocol/blob/80041ab0a139a8f4fb3adbc99f7ae9113ea59671`
  et `EXT`
  `https://github.com/modelcontextprotocol/ext-tasks/blob/b3d28aceaa6d49f5f92258e3d06b61ad6f111e84`.

### B.1 R1 — Code et spécifications

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R1-F7 | sous-champs de `approval`, `threshold` lu « au moment de la décision » | présent dépôt, `spec/CT-1-evenements-et-formats.md` L218-L231 | 2026-10-23 |
| R1-F8 | objet signé `A` ; champs non signés ; réserve d'une version 1 | présent dépôt, CT-1 L233-L238 | 2026-10-23 |
| R1-F11 | signature EIP-191 de `A`, `D_A`, `P_A`, refus de `s` haut | présent dépôt, CT-1 L485-L505 ; https://eips.ethereum.org/EIPS/eip-191 | 2026-10-23 |
| R1-F16 | `approbations.json`, `approver_set` et `source` | présent dépôt, CT-1 L984, L1029-L1040 ; vecteurs `spec/vecteurs/**/approbations.json` | 2026-10-23 |
| R1-F20 | vérifications A-1 à A-4 | présent dépôt, CT-1 L1186-L1189 | 2026-10-23 |
| R1-F26 | schéma d'`approbations.json` (`source` de 1 à 256 caractères) | présent dépôt, `spec/schemas/dossier-v0.schema.json` L141-L176 | 2026-10-23 |
| R1-F27 | fonctions de référence de `A`, `D_A` et E-9 | présent dépôt, `scripts/lib/journal.mjs` L721-L772 | 2026-10-23 |
| R1-F34 | CT-2 §4.4 pas 5 (refus) | présent dépôt, CT-2 version 0.2, L690-L694 | 2026-10-23 |
| R1-F35 | CT-2 §4.4 pas 6 (modes `retenir` et `erreur`) | présent dépôt, CT-2 version 0.2, L695-L715 | 2026-10-23 |
| R1-F39 | code `-32015` et `data.state` ; codes fixes | présent dépôt, CT-2 version 0.2, L984, L988-L991 | 2026-10-23 |
| R1-F45 | `approval.at` posé par l'écrivain (CT-2 EX-7.11) | présent dépôt, CT-2 version 0.2, L2321-L2325, L2376-L2385 | 2026-10-23 |
| R1-F50 | 176 octets par couple adresse-signature ; borne du signataire | présent dépôt, CT-2 version 0.2, L3959-L3972 | 2026-10-23 |
| R1-F52 | lignes de la matrice de panne qui concernent CT-3 | présent dépôt, CT-2 version 0.2, L4929-L4932 | 2026-10-23 |
| R1-F53 | membre `policy.approval` et son exemple | présent dépôt, CT-2 version 0.2, L5082, L5351-L5365, L5560 | 2026-10-23 |
| R1-F54 | schéma de `policy.approval` ; délais en millisecondes bornés à 86 400 000 | présent dépôt, `spec/schemas/configuration-enregistreur-v0.schema.json` L1578-L1582, L2333-L2423 | 2026-10-23 |
| R1-F56 | canal authentifié du service d'approbation ; surfaces d'écoute et sortante | présent dépôt, CT-2 version 0.2, L5925-L5928, L6000-L6010 | 2026-10-23 |
| R1-F59 | jeu d'approbateurs déclaré par le dossier (CT-6) | présent dépôt, `spec/CT-6-verificateur.md` L247, L270, L273-L278 | 2026-10-23 |
| R1-F61 | énoncés du contrôle 7 | présent dépôt, CT-6 L698-L700 | 2026-10-23 |
| R1-F62 | ce que CT-6 ne prouve pas des approbateurs | présent dépôt, CT-6 L104-L107, L1168-L1171, L4010-L4012 | 2026-10-23 |
| R1-F66 | vecteurs CT-6 de refus et d'expiration (seq 7 `refusee`) | présent dépôt, `spec/vecteurs/ct-6/dossiers/valide-decision-refusee/`, `valide-decision-expiree/`, `scripts/vecteurs/ct6/decisions.mjs` L75-L82 | 2026-10-23 |
| R1-F69 | état et événements de `CuratorSet` | présent dépôt, `contracts/CuratorSet.sol` L55-L65, L92-L94 | 2026-10-23 |
| R1-F70 | vues de `CuratorSet`, sans liste des membres | présent dépôt, `contracts/CuratorSet.sol` L233-L243 | 2026-10-23 |
| R1-F71 | règles de mutation du jeu et du seuil | présent dépôt, `contracts/CuratorSet.sol` L168-L178, L192-L197, L245-L262 | 2026-10-23 |
| R1-F72 | administration signée du `CuratorSet` (`adminOpDigest`, `opNonce`), rejeu fermé sur quatre axes | présent dépôt, `contracts/CuratorSet.sol` L49-L53, L101-L117 | 2026-10-23 |
| R1-F73 | contrats identiques à ceux de noorchain-core | présent dépôt et noorchain-core (`diff`) ; non recoupable publiquement | 2026-10-23 |
| R1-F74 | `CuratorSetRegistry` : `curatorSetOf`, réassignation | présent dépôt, `contracts/CuratorSetRegistry.sol` L29-L32, L46-L102 | 2026-10-23 |
| R1-F75 | `ThresholdSignatures` : signatures ignorées, arrêt au seuil | présent dépôt, `contracts/ThresholdSignatures.sol` L54-L115 | 2026-10-23 |
| R1-F76 | `PeriodRegistry` relit le seuil à la transaction | présent dépôt, `contracts/PeriodRegistry.sol` L144-L159, L271-L281 | 2026-10-23 |
| R1-F78 | lectures à une hauteur, refus `-32000`, `eth_call` servi par le meneur | noorchain-core, `docs/RPC_SPEC_2.1.md` L207-L267 ; non recoupable publiquement | 2026-10-23 |
| R1-F79 | `eth_getLogs` borné à 16 384 blocs, pas d'`eth_subscribe` | noorchain-core, `docs/RPC_SPEC_2.1.md` L282-L293, `core/rpc/jsonrpc.go` L25-L28 ; non recoupable publiquement | 2026-10-23 |
| R1-F80 | pas de `personal_*`, pas d'`eth_getProof` | noorchain-core, `docs/RPC_SPEC_2.1.md` L297-L303 ; non recoupable publiquement | 2026-10-23 |
| R1-F81 | lectures effectives à une hauteur ; `0x` avant déploiement ; casse EIP-55 | expérience de la note sur le réseau de développement ; présent dépôt, `deployments/noorcore-orgs.json` | 2026-10-23 |
| R1-F82 | curators-hub n'emploie aucun portefeuille de navigateur | noorchain-core, `dapps/curators-hub` ; non recoupable publiquement | 2026-10-23 |
| R1-F83 | clés des curateurs gardées par le serveur | noorchain-core, `dapps/curators-hub/README.md` L308-L327, `lib/curator-registry.ts` L8-L13 ; non recoupable publiquement | 2026-10-23 |
| R1-F84 | message de décision de curateur, vérification à la tête, un vote par curateur | noorchain-core, `dapps/curators-hub/lib/curator-auth.ts` L53-L97, `app/api/signals/review/route.ts`, `lib/validation.ts` L396-L399 ; non recoupable publiquement | 2026-10-23 |
| R1-F85 | clôture de période : condensé brut de 32 octets signé en octets (`raw`) | noorchain-core, `dapps/curators-hub/lib/anchor.ts` L483-L503 ; non recoupable publiquement | 2026-10-23 |
| R1-F86 | ce que voit l'opérateur à la clôture : aperçu tronqué et empreinte | noorchain-core, `dapps/curators-hub/app/snapshot/page.tsx` L207-L258 ; non recoupable publiquement | 2026-10-23 |
| R1-F87 | `OrgOpSigner` : clé dans le navigateur, seule la signature part | noorchain-core, `dapps/curators-hub/components/OrgOpSigner.tsx` ; non recoupable publiquement | 2026-10-23 |
| R1-F89 | viem : `signMessage` en UTF-8 par défaut, `raw` pour des octets | https://viem.sh/docs/accounts/local/signMessage ; https://viem.sh/docs/actions/wallet/signMessage | 2026-10-23 |
| R1-F90 | ethers : `hashMessage` d'une chaîne en UTF-8, `getBytes` pour des octets | paquet npm `ethers` 6.17.0, `src.ts/hash/message.ts` L7-L15, L35-L42 (installé dans le présent dépôt) | 2026-10-23 |
| R1-F91 | MetaMask : `personal_sign` présente un défi en hexadécimal ; données binaires déconseillées | https://docs.metamask.io/wallet/reference/personal_sign ; https://docs.metamask.io/wallet/how-to/sign-data/ | 2026-10-23 |
| R1-F92 | exemple de référence de CT-1, ticket `apr-1192` | présent dépôt, CT-1 L329-L418, L1530-L1668 | 2026-10-23 |
| R1-F93 | annexe A de CT-2, mode `retenir`, 693 s de rétention (calcul) | présent dépôt, CT-2 version 0.2, L2795-L2797, L2888-L2908, L3122-L3125 | 2026-10-23 |
| R1-F94 | vecteurs CT-1, ticket `apr-2201` : `retenue` seq 5, décision seq 6, appel relayé seq 7 | présent dépôt, `spec/vecteurs/ct-1/journal-valide/evenements.json` | 2026-10-23 |
| R1-F95 | démonstration CT-2, ré-émission sans ticket | présent dépôt, `spec/vecteurs/ct-2/evenements/journal-demo/` | 2026-10-23 |
| R1-NV2 | affichage réel d'un défi `personal_sign` binaire : non observé | https://docs.metamask.io/wallet/reference/personal_sign | 2026-10-23 |
| R1-NV3 | délais des hôtes cités par CT-2, non relus par R1 (relus par R2-F30 à R2-F41) | présent dépôt, CT-2 (renvoi R7 F-25) | 2026-10-23 |
| R1-NV4 | `eth_call` sur un état élagué : non provoqué | noorchain-core, `docs/RPC_SPEC_2.1.md` §8.0 ; non recoupable publiquement | 2026-10-23 |
| R1-C23 | conséquence : reprendre la garde de curators-hub viderait le contrôle 7 | sources de R1-F82 à R1-F87 | 2026-10-23 |
| R1-C24 | conséquence : aucune échéance signée dans `A` | sources de R1-F11 et R1-F72 (`contracts/CuratorSet.sol` L49-L53, L101-L117) | 2026-10-23 |
| R1-C31 | conséquence : `policy_sha256` défini par CT-2 EX-8.11 | présent dépôt, CT-1 L639-L641, CT-2 version 0.2, L2587-L2592, L3709-L3724 | 2026-10-23 |

### B.2 R2 — Protocoles et signature

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R2-F1 | révision courante de MCP : `2026-07-28` | https://modelcontextprotocol.io/specification/latest ; MCP/`docs/docs.json#L33` ; MCP/`schema/2026-07-28/schema.ts#L30` | 2026-10-23 |
| R2-F2 | protocole sans état | MCP/`docs/specification/2026-07-28/changelog.mdx#L14` | 2026-10-23 |
| R2-F3 | tâches sorties du cœur, extension `io.modelcontextprotocol/tasks` | MCP/`docs/specification/2026-07-28/changelog.mdx#L22` | 2026-10-23 |
| R2-F5 | flux rompu : la requête est ré-émise avec un nouvel identifiant | MCP/`docs/specification/2026-07-28/changelog.mdx#L28` | 2026-10-23 |
| R2-F6 | forme de `tools/call` et de son résultat | MCP/`docs/specification/2026-07-28/server/tools.mdx#L135-L172` | 2026-10-23 |
| R2-F7 | MRTR : `InputRequiredResult` en réponse à `tools/call`, rejeu sous un autre identifiant | MCP/`docs/specification/2026-07-28/server/tools.mdx` L174-L178, L234 | 2026-10-23 |
| R2-F8 | erreurs de protocole (JSON-RPC), que les clients PEUVENT transmettre au modèle ; erreurs d'exécution (`isError`), qu'ils DEVRAIENT transmettre | MCP/`docs/specification/2026-07-28/server/tools.mdx` L738-L785 (L742-L747, L784-L785) | 2026-10-23 |
| R2-F9 | humain dans la boucle, entrées montrées avant l'appel | MCP/`docs/specification/2026-07-28/server/tools.mdx` L31-L43, L795-L803 | 2026-10-23 |
| R2-F10 | plages de codes d'erreur : `-32000` à `-32019` hérités (aucune nouvelle allocation, aucun usage par une nouvelle implémentation, aucun sens supposé par le récepteur, sauf `-32002`) ; `-32020` à `-32099` réservés ; nouveaux codes hors de `-32768` à `-32000` | MCP/`docs/specification/2026-07-28/basic/index.mdx` L109-L155 (L117-L121, L153-L155) | 2026-10-23 |
| R2-F11 | annulation : déconnexion en HTTP, notification en stdio | MCP/`docs/specification/2026-07-28/basic/patterns/cancellation.mdx#L7-L43` | 2026-10-23 |
| R2-F13 | délais : toujours un délai maximal | MCP/`docs/specification/2026-07-28/basic/patterns/cancellation.mdx` L45-L64 ; MCP/`docs/specification/2025-11-25/basic/lifecycle.mdx` L246-L261 | 2026-10-23 |
| R2-F14 | progression : `progressToken`, `notifications/progress` | MCP/`docs/specification/2026-07-28/basic/patterns/progress.mdx` L13-L67 | 2026-10-23 |
| R2-F16 | `requestState` : intégrité, pas d'usage unique garanti | MCP/`docs/specification/2026-07-28/basic/patterns/mrtr.mdx#L231-L243` | 2026-10-23 |
| R2-F17 | élicitation, modes « form » et « url » ; en « form », aucun secret ni identifiant qui donne accès ou autorise une transaction | MCP/`docs/specification/2026-07-28/client/elicitation.mdx` L12-L46 | 2026-10-23 |
| R2-F19 | réponse d'élicitation `accept` en mode « url » | MCP/`docs/specification/2026-07-28/client/elicitation.mdx` L370-L383, L434-L461 | 2026-10-23 |
| R2-F20 | lier la demande au client et à l'utilisateur ; ne pas se fier sans vérification à une identification de l'utilisateur fournie par le client | MCP/`docs/specification/2026-07-28/client/elicitation.mdx` L593-L657 | 2026-10-23 |
| R2-F21 | `2025-11-25` : élicitation `elicitation/create`, tâches expérimentales dans le cœur, `execution.taskSupport` | MCP/`docs/specification/2025-11-25/client/elicitation.mdx` L83 ; MCP/`docs/specification/2025-11-25/basic/utilities/tasks.mdx` L7-L12, L109-L117 | 2026-10-23 |
| R2-F22 | extension Tasks : SEP-2663 « Final », schéma `2026-07-28` « Stable » | MCP/`docs/seps/2663-tasks-extension.mdx` L7-L31 ; EXT/`README.md#L19-L22` | 2026-10-23 |
| R2-F23 | Tasks : `tools/call` seulement, négociation par requête | EXT/`specification/2026-07-28/tasks.md#L61-L63` (et L10, L85-L102) | 2026-10-23 |
| R2-F24 | objet `Task`, `ttlMs`, `completed` même avec `isError` | EXT/`specification/2026-07-28/tasks.md` L104-L160, L833-L837 | 2026-10-23 |
| R2-F25 | `CreateTaskResult` après création durable ; annulation coopérative | EXT/`specification/2026-07-28/tasks.md` L300-L507 | 2026-10-23 |
| R2-F26 | une tâche n'est pas un canal de confiance supérieur | EXT/`specification/2026-07-28/tasks.md` L348, L900-L905 | 2026-10-23 |
| R2-F27 | approbations humaines citées comme cas d'usage des tâches | MCP/`docs/extensions/tasks/overview.mdx` L17-L21, L110-L112, L264-L274 | 2026-10-23 |
| R2-F28 | matrice des extensions, tenue par la communauté, sans colonne Tasks | MCP/`docs/extensions/client-matrix.mdx#L26-L50` | 2026-10-23 |
| R2-F30 | Claude Code : `MCP_TOOL_TIMEOUT`, 60 s jusqu'au premier octet en HTTP | https://code.claude.com/docs/en/env-vars.md L490 ; https://code.claude.com/docs/en/mcp.md L438 | 2026-10-23 |
| R2-F31 | Claude Code : inactivité 5 min (HTTP) et 30 min (stdio), remise à zéro par progression | https://code.claude.com/docs/en/mcp.md L438, L442-L444 ; https://code.claude.com/docs/en/env-vars.md L328 | 2026-10-23 |
| R2-F32 | Claude Code : passage en arrière-plan après 2 min | https://code.claude.com/docs/en/mcp.md L446-L464 ; https://code.claude.com/docs/en/env-vars.md L326 | 2026-10-23 |
| R2-F33 | Claude Code : SDK TypeScript, élicitation, crochet `Elicitation` | https://code.claude.com/docs/en/mcp.md L327, L1450, L1454 | 2026-10-23 |
| R2-F34 | Claude Desktop (3P) : 180 s, 60 s pour un serveur local ajouté | https://claude.com/docs/third-party/claude-desktop/configuration.md L2740-L2752 | 2026-10-23 |
| R2-F35 | connecteurs claude.ai et Desktop : 240 s | https://claude.com/docs/connectors/building.md L69-L76 | 2026-10-23 |
| R2-F36 | SDK TypeScript 1.32.1 : 60 s, sans remise à zéro par défaut | paquet npm `@modelcontextprotocol/sdk@1.32.1`, `dist/esm/shared/protocol.d.ts` L57, L72-L89, `protocol.js` L740-L742, `types.js` L162 | 2026-10-23 |
| R2-F37 | SDK TypeScript 1.32.1 : révision `2025-11-25` | paquet npm `@modelcontextprotocol/sdk@1.32.1`, `package/dist/esm/types.js` L2 | 2026-10-23 |
| R2-F38 | SDK Python 2.3.0 : aucun délai de requête par défaut (`ClientSession`) | https://files.pythonhosted.org/packages/20/d7/4a2878f128df729db3ca04e71bfce26405cc2e0c9ebe19c592feeb4c61b9/mcp-2.3.0-py3-none-any.whl (`mcp/client/session.py` L408, L572-L578) | 2026-10-23 |
| R2-F39 | SDK Python 2.3.0, HTTP : 30 s pour connexion, écriture et pool, 300 s en lecture du flux SSE | https://files.pythonhosted.org/packages/20/d7/4a2878f128df729db3ca04e71bfce26405cc2e0c9ebe19c592feeb4c61b9/mcp-2.3.0-py3-none-any.whl (`mcp/shared/_httpx_utils.py` L13-L14) | 2026-10-23 |
| R2-F40 | langchain-mcp-adapters 0.3.2 et mcp 1.30.0 : aucun délai de requête ; HTTP : 300 s en lecture SSE, 30 s en « streamable HTTP » | https://github.com/langchain-ai/langchain-mcp-adapters/blob/52a4535f3eb4b98f386836e4d9b8c4cadf99afca/pyproject.toml#L17 ; même commit, `langchain_mcp_adapters/sessions.py` L53-L57 ; https://files.pythonhosted.org/packages/f5/f4/e58bc33317c92a0203664daaf00bf6f41166cc0149e5d6870a03f7cd004a/mcp-1.30.0-py3-none-any.whl | 2026-10-23 |
| R2-F41 | SDK Agents d'OpenAI 0.24.0 : 5 s | https://github.com/openai/openai-agents-python/blob/0dc4cf152bff1f50bdc0e41f28808563406545b2/src/agents/mcp/server.py#L1973 | 2026-10-23 |
| R2-F43 | Cursor : aucune valeur de délai documentée | https://cursor.com/docs/mcp.md | 2026-10-23 |
| R2-F44 | EIP-191 : format, versions, jamais une transaction | https://github.com/ethereum/ERCs/blob/6b7a48ffa791e30ceee94d869b5eae9521fe158f/ERCS/erc-191.md#L29-L55 | 2026-10-23 |
| R2-F47 | piège d'encodage : chaîne `"0x…"` hachée en UTF-8 ; mesure sur `D_A` | paquet npm `ethers` 6.17.0, `lib.esm/hash/message.js` L18-L25 ; expérience de la note (Node v22.22.0) | 2026-10-23 |
| R2-F48 | EIP-712 : domaine, motivation de l'affichage | https://github.com/ethereum/EIPs/blob/f1bcca1b56ee91fe115d2a8d8fd731fd6ca38bb3/EIPS/eip-712.md | 2026-10-23 |
| R2-F49 | EIP-712 sans protection contre le rejeu | même source, L26, L352-L356 | 2026-10-23 |
| R2-F50 | EIP-1193 : interface `request`, code 4001 | https://github.com/ethereum/EIPs/blob/f1bcca1b56ee91fe115d2a8d8fd731fd6ca38bb3/EIPS/eip-1193.md | 2026-10-23 |
| R2-F51 | MetaMask déconseille d'afficher des données binaires ; `eth_sign` déprécié | https://docs.metamask.io/wallet/how-to/sign-data | 2026-10-23 |
| R2-F53 | MetaMask affiche en hexadécimal un message de 32 octets | https://github.com/MetaMask/metamask-extension/blob/6b7ca07f635cbe04dad1040ff532623c629e531b/ui/helpers/utils/util.js#L830-L841 | 2026-10-23 |
| R2-F54 | Ledger affiche en hexadécimal un message non imprimable, sans « blind signing » | https://github.com/LedgerHQ/app-ethereum/blob/f7985b427841ace20795b548905ababf6a5b17a4/src/features/sign_message/cmd_sign_message.c#L165-L191 | 2026-10-23 |
| R2-F55 | Trezor affiche `hex(…)` ce qui n'est pas de l'UTF-8 | https://github.com/trezor/trezor-firmware/blob/30d30b37751c2d8e75da5746e18864948095f5db/core/src/apps/common/signverify.py#L31-L35 | 2026-10-23 |
| R2-F56 | `D_A` de CT-1 : ni UTF-8 valide ni ASCII imprimable | expérience de la note (Node) | 2026-10-23 |
| R2-F58 | Ledger : EIP-712 refusé sans réglage « blind signing » ou mode verbeux | https://github.com/LedgerHQ/app-ethereum/blob/f7985b427841ace20795b548905ababf6a5b17a4/src/features/sign_message_eip712_v0/cmd_sign_message_eip712.c#L14-L18 | 2026-10-23 |
| R2-F59 | MIP-3 (statut « Accepted ») : abandon d'`eth_sign` pour l'hameçonnage par signature à l'aveugle | https://github.com/MetaMask/metamask-improvement-proposals/blob/d05c7248bf914e07828fd55815d4c232d83d4d6f/MIPs/mip-3.md (L1-L29) | 2026-10-23 |
| R2-F60 | ERC-7730 : EIP-712 ne suffit pas à l'affichage | https://github.com/ethereum/ERCs/blob/6b7a48ffa791e30ceee94d869b5eae9521fe158f/ERCS/erc-7730.md | 2026-10-23 |
| R2-F61 | WalletConnect/Reown : paramètres de `personal_sign` (donnée, adresse), affichage laissé au portefeuille | https://docs.reown.com/advanced/multichain/rpc-reference/ethereum-rpc.md L9-L26 | 2026-10-23 |
| R2-F62 | ERC-1271 : validité dépendante de l'état | https://github.com/ethereum/ERCs/blob/6b7a48ffa791e30ceee94d869b5eae9521fe158f/ERCS/erc-1271.md | 2026-10-23 |
| R2-F63 | CT-1 et le contrat refusent `s` haut et `v` hors {27, 28} | présent dépôt, CT-1 L483-L505, `contracts/ThresholdSignatures.sol` L47, L79-L81 | 2026-10-23 |
| R2-F64 | EIP-2 : `(r, n − s, v ^ 1)` reste valide | https://github.com/ethereum/EIPs/blob/f1bcca1b56ee91fe115d2a8d8fd731fd6ca38bb3/EIPS/eip-2.md | 2026-10-23 |
| R2-F65 | mesure : la forme malléable recouvre la même adresse | expérience de la note (`@noble/curves` 1.9.0, ethers 6.17.0) | 2026-10-23 |
| R2-F66 | valeurs de `v`, `s` bas chez Trezor et ethers | https://github.com/ethereum/EIPs/blob/f1bcca1b56ee91fe115d2a8d8fd731fd6ca38bb3/EIPS/eip-155.md ; https://github.com/LedgerHQ/app-ethereum/blob/f7985b427841ace20795b548905ababf6a5b17a4/src/features/sign_message/ui_common_sign_message.c#L21-L27 ; https://github.com/trezor/trezor-firmware/blob/30d30b37751c2d8e75da5746e18864948095f5db/crypto/ecdsa.c#L754-L758 | 2026-10-23 |
| R2-F67 | Cedar : `forbid` l'emporte, refus par défaut | https://github.com/cedar-policy/cedar-docs/blob/3a37098eba6e02e716949cfc92b889b38db25602/docs/collections/_auth/authorization.md#L38-L58 | 2026-10-23 |
| R2-F68 | Cedar : « skip on error », une erreur peut empêcher un `forbid` de bloquer | https://github.com/cedar-policy/cedar-docs/blob/3a37098eba6e02e716949cfc92b889b38db25602/docs/collections/_auth/authorization.md#L58 ; https://github.com/cedar-policy/cedar-docs/blob/3a37098eba6e02e716949cfc92b889b38db25602/docs/collections/_policies/syntax-datatypes.md#L175 | 2026-10-23 |
| R2-F69 | Cedar : sémantique formelle en Lean, tests différentiels, autoriseur indépendant de l'ordre | https://github.com/cedar-policy/cedar-spec/blob/c9a03407a96a5a8bfadadd4db534e70125f42acb/README.md (L3, L12) ; même commit, `cedar-lean/Cedar/Spec/Authorizer.lean` L56-L62 | 2026-10-23 |
| R2-F70 | Cedar : pas d'expression régulière, `like` avec le seul joker `*` | https://github.com/cedar-policy/cedar-docs/blob/3a37098eba6e02e716949cfc92b889b38db25602/docs/collections/_policies/syntax-operators.md#L82-L88 | 2026-10-23 |
| R2-F71 | Cedar : `decimal` à quatre décimales au plus, littéraux seulement | https://github.com/cedar-policy/cedar-docs/blob/3a37098eba6e02e716949cfc92b889b38db25602/docs/collections/_policies/syntax-datatypes.md#L160-L177 ; https://github.com/cedar-policy/cedar-docs/blob/3a37098eba6e02e716949cfc92b889b38db25602/docs/collections/_policies/syntax-operators.md (L181-L189, L413-L429) | 2026-10-23 |
| R2-F72 | Cedar : `decimal` en entier de 64 bits à l'échelle 10^4 | https://github.com/cedar-policy/cedar/blob/4fe34d23a161200ba989718b654f7555a60b9e41/cedar-policy-core/src/extensions/decimal.rs#L35-L41 ; https://github.com/cedar-policy/cedar-spec/blob/c9a03407a96a5a8bfadadd4db534e70125f42acb/cedar-lean/Cedar/Spec/Ext/Decimal.lean#L36-L63 | 2026-10-23 |
| R2-F73 | CEL : termine toujours, entiers de 64 bits et `double`, pas de décimal | https://github.com/google/cel-spec/blob/8bef98f1caadc2036fe63d5516cf1df65dc4b741/doc/langdef.md (L8-L19, L208-L210, L220-L232) | 2026-10-23 |
| R2-F74 | CEL : `&&` et `||` absorbent les erreurs ; `matches` en RE2 | même source, L686-L694, L1224-L1229, L1833-L1835 | 2026-10-23 |
| R2-F75 | OPA/Rego : conflit de règles complètes, valeur `default`, RE2 | https://github.com/open-policy-agent/opa/blob/01eefbab7949abb5ddba07b938430d9ec64120de/docs/docs/policy-language.md (L989-L990, L1006-L1008, L2068-L2072) ; même commit, `docs/docs/policy-reference/builtins/regex.mdx` L11-L13 | 2026-10-23 |
| R2-F76 | AWS IAM : refus implicite par défaut, refus explicite prioritaire ; clé de condition absente : pas de correspondance | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html ; https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html | 2026-10-23 |
| R2-F78 | RE2 : temps linéaire, pas de référence arrière ni de voisinage | https://github.com/google/re2/blob/2da0056814cf180480a19f5cf811e7e1c054bf6d/README.md#L7-L28 | 2026-10-23 |
| R2-F79 | V8 : moteur à retour arrière, moteur linéaire expérimental | https://v8.dev/blog/non-backtracking-regexp | 2026-10-23 |
| R2-F80 | mesure : `/^(a+)+$/` sur Node v22.22.0, 472,6 ms pour 26 caractères | expérience de la note (Node v22.22.0) | 2026-10-23 |
| R2-F81 | JSON Schema 2020-12 : motifs ECMA-262, sous-ensemble interopérable | https://www.ietf.org/archive/id/draft-bhutton-json-schema-01.txt (L677-L712) ; https://www.ietf.org/archive/id/draft-bhutton-json-schema-validation-01.txt (L409-L417) | 2026-10-23 |
| R2-F82 | Go `regexp` : syntaxe RE2, temps linéaire | bibliothèque standard de Go 1.24.7, `src/regexp/regexp.go` L5-L14 (installation de la note) | 2026-10-23 |
| R2-F83 | CT-2 : sous-ensemble ECMAScript/RE2, borne `limits.redaction_budget_ms` | présent dépôt, CT-2 version 0.2, L3217-L3263, L3673-L3684 | 2026-10-23 |
| R2-F84 | mesure : `erreursMotifRE2` admet les motifs à retour arrière exponentiel | présent dépôt, `scripts/lib/capture.mjs` L794 ; expérience de la note | 2026-10-23 |
| R2-F85 | RFC 8259 : forme des nombres, entiers interopérables dans ±(2^53 − 1) | https://www.rfc-editor.org/rfc/rfc8259.txt (L364-L377, L405-L422) | 2026-10-23 |
| R2-F86 | RFC 8785 : nombres en double IEEE 754, montants en chaînes | https://www.rfc-editor.org/rfc/rfc8785.txt (L189-L193, L711-L728) | 2026-10-23 |
| R2-F89 | mesures : flottants, `JSON.parse` des grands entiers, ordre des chaînes, `Number()` | expérience de la note (Node v22.22.0) | 2026-10-23 |
| R2-F90 | mesure : grammaire décimale stricte et comparaison exacte par `BigInt` | expérience de la note (Node v22.22.0) | 2026-10-23 |
| R2 NV-1 | délais de Cursor : forum seulement, non vérifié | https://cursor.com/docs/mcp.md (aucune valeur) | 2026-10-23 |
| R2 NV-2 | délai des serveurs locaux de Claude Desktop grand public : non vérifié | https://claude.com/docs/third-party/claude-desktop/configuration.md | 2026-10-23 |
| R2 NV-3 | délais propres à LangGraph : non vérifié | — | 2026-10-23 |
| R2 NV-4 | prise en charge de Tasks hôte par hôte : non vérifié | MCP/`docs/extensions/client-matrix.mdx` | 2026-10-23 |
| R2 NV-5 | `s` bas chez Ledger : réduit par R4-F24 (SDK publié), pas levé (R4 NV-2) | https://github.com/LedgerHQ/app-ethereum (code de l'application lu, bibliothèque `cx` non publique) ; B.5 | 2026-10-23, 2026-10-26 |
| R2 NV-6 | Trezor, branche secp256k1-zkp : levé, `s` bas (R4-F26) | https://github.com/trezor/trezor-firmware ; B.5 | 2026-10-23, 2026-10-26 |
| R2 NV-7 | portefeuilles qui rendent `v ∈ {0, 1}` : non vérifié ; normalisation par le porte-clés Ledger de MetaMask (R4-F21), non reproduite par le code de l'application (R4 NV-2) | B.5 | 2026-10-23, 2026-10-26 |
| R2 NV-8 | affichage par les portefeuilles WalletConnect : non vérifié (inchangé, R4 NV-4) | https://docs.reown.com/advanced/multichain/rpc-reference/ethereum-rpc.md | 2026-10-23, 2026-10-26 |
| R2 NV-10 | filtrage EIP-712 « complet » de Ledger : non vérifié | https://developers.ledger.com/docs/device-app/integration/design-guidelines/transactions | 2026-10-23 |
| R2 NV-11 | MIP-3 : `eth_sign` absent de l'intergiciel et refusé par un test de bout en bout (R4-F14, R4-F16) ; sa présence dans l'extension publiée n'est pas vérifiée (R4 NV-5) | https://github.com/MetaMask/metamask-extension ; B.5 | 2026-10-23, 2026-10-26 |
| R2 (section 3.4) | propositions de condensé signé v1 (EIP-712, texte lisible) | sources de R2-F48, R2-F53 à R2-F55, R2-F58, R2-F60 | 2026-10-23 |

### B.3 R3 — Contrôle humain et pratiques

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R3-F4 | règlement (UE) 2024/1689, art. 14 § 4 a) : comprendre et surveiller | http://publications.europa.eu/resource/celex/32024R1689 (texte français du JO) | 2026-10-23 |
| R3-F5 | art. 14 § 4 b) : biais d'automatisation | même source | 2026-10-23 |
| R3-F6 | art. 14 § 4 c) : interpréter correctement les sorties | même source | 2026-10-23 |
| R3-F7 | art. 14 § 4 d) : ignorer, remplacer ou inverser une sortie | même source | 2026-10-23 |
| R3-F8 | art. 14 § 4 e) : intervenir, interrompre par une procédure d'arrêt | même source | 2026-10-23 |
| R3-F9 | art. 14 § 5, premier alinéa : vérification et confirmation par deux personnes physiques (annexe III, point 1 a)) | même source | 2026-10-23 |
| R3-F10 | art. 14 § 5, second alinéa : exception | même source | 2026-10-23 |
| R3-F11 | annexe III, point 1 a) : identification biométrique à distance | même source | 2026-10-23 |
| R3-F12 | considérant 73 : l'opérateur peut être l'une des deux personnes ; journaux | même source | 2026-10-23 |
| R3-F17 | art. 19 § 1 : journaux du fournisseur, au moins six mois | même source | 2026-10-23 |
| R3-F18 | art. 18 § 1 : dix ans pour la documentation, pas pour les journaux | même source | 2026-10-23 |
| R3-F21 | art. 26 § 5 : le déployeur surveille et suspend l'utilisation | même source | 2026-10-23 |
| R3-F22 | art. 26 § 6 : journaux du déployeur, au moins six mois | même source | 2026-10-23 |
| R3-F26 | règlement (UE) 2026/1744 du 8 juillet 2026, JO du 24.7.2026, modifie le règlement (UE) 2024/1689 | http://publications.europa.eu/resource/celex/32026R1744 | 2026-10-23 |
| R3-F27 | application du chapitre III, sections 1 à 3, reportée au 2 décembre 2027 (annexe III) et au 2 août 2028 (annexe I) | même source (art. 1, point modifiant l'art. 113) | 2026-10-23 |
| R3-F28 | aucun point de l'art. 1 du règlement 2026/1744 ne modifie les art. 12, 14, 18, 19, 26 ou 86 | même source | 2026-10-23 |
| R3-F31 | RGPD art. 22 § 3 : intervention humaine, point de vue, contestation | http://publications.europa.eu/resource/celex/32016R0679 | 2026-10-23 |
| R3-F32 | RGPD considérant 71 | même source | 2026-10-23 |
| R3-F33 | RGPD art. 21 : droit d'opposition, distinct | http://publications.europa.eu/resource/celex/32016R0679 | 2026-10-23 |
| R3-F35 | WP251rev.01, adoptées le 3 octobre 2017, révisées le 6 février 2018, endossées par le Comité européen de la protection des données | https://ec.europa.eu/newsroom/article29/redirection/document/49826 ; https://www.edpb.europa.eu/our-work-tools/general-guidance/endorsed-wp29-guidelines_en | 2026-10-23 |
| R3-F36 | WP251rev.01 p. 21 : intervention humaine de façade | https://ec.europa.eu/newsroom/article29/redirection/document/49826 | 2026-10-23 |
| R3-F37 | WP251rev.01 p. 21 : intervention significative, autorité de changer la décision | même source | 2026-10-23 |
| R3-F38 | WP251rev.01 p. 27 : réexamen par quelqu'un qui peut changer la décision | même source | 2026-10-23 |
| R3-F42 | LPD art. 21 al. 2 : point de vue, revue par une personne physique | https://fedlex.data.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2022/491/20250707/fr/html/fedlex-data-admin-ch-eli-cc-2022-491-20250707-fr-html-1.html | 2026-10-23 |
| R3-F46 | « contester » absent de l'art. 21 LPD | même source (recherche dans le texte) | 2026-10-23 |
| R3-F50 | NIST SP 800-53 Rev. 5, AC-5 | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf | 2026-10-23 |
| R3-F51 | AC-5, discussion | même source | 2026-10-23 |
| R3-F55 | AC-3(2), double autorisation | même source | 2026-10-23 |
| R3-F56 | CM-5(4) : double autorisation des changements | même source | 2026-10-23 |
| R3-F59 | CM-3(1) : notifier, signaler les demandes sans décision, interdire avant approbation | même source | 2026-10-23 |
| R3-F68 | AC-2, discussion : comptes temporaires et d'urgence, contournement de l'autorisation normale | même source | 2026-10-23 |
| R3-F69 | AC-2(2) : désactivation automatique des comptes temporaires et d'urgence | même source | 2026-10-23 |
| R3-F72 | Entra PIM : attribution éligible et active | https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure | 2026-10-23 |
| R3-F73 | Entra PIM : attribution bornée par des dates, accès juste-à-temps | https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure | 2026-10-23 |
| R3-F74 | Entra PIM : durée d'activation sous un maximum, motif, demande en attente | même source | 2026-10-23 |
| R3-F75 | Entra PIM : activation de 1 à 24 heures | https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings | 2026-10-23 |
| R3-F76 | Entra PIM : approbation à l'activation, deux approbateurs recommandés | https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings | 2026-10-23 |
| R3-F77 | Entra PIM : date de fin des attributions éligibles et actives | même source | 2026-10-23 |
| R3-F78 | Entra PIM : 24 heures pour approuver, non configurable | https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-approval-workflow | 2026-10-23 |
| R3-F79 | Entra PIM : pas d'approbation de sa propre demande | même source | 2026-10-23 |
| R3-F82 | comptes d'urgence : alerte, revue après usage | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access | 2026-10-23 |
| R3-F83 | Google Cloud PAM : droits temporaires, durée maximale | https://cloud.google.com/iam/docs/pam-overview | 2026-10-23 |
| R3-F85 | Google Cloud PAM : retrait d'une demande en attente par le demandeur (fonction en préversion) | même source | 2026-10-23 |
| R3-F87 | Google Cloud PAM : deux niveaux (fonction en préversion), un seul refus clôt la demande | https://cloud.google.com/iam/docs/pam-approve-deny-grants | 2026-10-23 |
| R3-F88 | Google Cloud PAM : pas d'auto-approbation, expiration à 24 heures | même source | 2026-10-23 |
| R3-F90 | AWS SEC03-BP03 : approbateurs secondaires, escalade | https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_permissions_emergency_process.html | 2026-10-23 |
| R3-F91 | AWS SEC03-BP03 : journal de toutes les tentatives, accès d'urgence comme porte dérobée | même source | 2026-10-23 |
| R3-F92 | AWS SEC03-BP03 : rotation des secrets après l'urgence | même source | 2026-10-23 |
| R3-F93 | Vault, groupes de contrôle : autorisation d'une requête précise, jeton à durée limitée | https://developer.hashicorp.com/vault/docs/enterprise/control-groups | 2026-10-23 |
| R3-F94 | Vault : durée et nombre d'autorisations par facteur | même source | 2026-10-23 |
| R3-F95 | Vault : politique Sentinel qui exige des autorisations de moins d'une heure | même source | 2026-10-23 |
| R3-F96 | Azure Pipelines : approbation différée | https://learn.microsoft.com/en-us/azure/devops/pipelines/process/approvals?view=azure-devops | 2026-10-23 |
| R3-F98 | GitHub : « prevent self-review » | https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments | 2026-10-23 |
| R3-F103 | GitHub : 30 jours d'attente au plus | https://docs.github.com/en/actions/reference/limits | 2026-10-23 |
| R3-F104 | GitHub : approbation périmée quand le diff change | https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches | 2026-10-23 |
| R3-F107 | GitLab : l'auteur ne peut pas approuver par défaut | https://docs.gitlab.com/user/project/merge_requests/approvals/settings/ | 2026-10-23 |
| R3-F108 | GitLab : approbation retirée quand des changements sont ajoutés | même source | 2026-10-23 |
| R3-F109 | GitLab : déclencheur exclu par défaut, une approbation par personne | https://docs.gitlab.com/ci/environments/deployment_approvals/ | 2026-10-23 |
| R3-F110 | Azure Pipelines : délai, auto-approbation réglable | https://learn.microsoft.com/en-us/azure/devops/pipelines/process/approvals?view=azure-devops | 2026-10-23 |
| R3-F111 | Azure Pipelines : liste des approbateurs figée au début | même source | 2026-10-23 |
| R3-F112 | Azure Pipelines : un refus final fait échouer l'étape | même source | 2026-10-23 |
| R3-F113 | AWS CodePipeline : échec à 7 jours, comme un rejet | https://docs.aws.amazon.com/codepipeline/latest/userguide/approvals.html | 2026-10-23 |
| R3-F115 | ServiceNow : approbation, rejet ou annulation automatique à l'échéance | https://www.servicenow.com/docs/api/khub/maps/QG7EzyJSIJf6bo5K1OVTbw/topics/s9vS_wC22WEjISzOnNTykA/content (passages rédigés, hors résumé généré en tête de page) | 2026-10-23 |
| R3-F119 | ServiceNow : exemple d'approbation automatique après un jour ouvré | même source | 2026-10-23 |
| R3-F122 | `A` ne porte ni instant ni durée | présent dépôt, CT-1 L233-L238 | 2026-10-23 |
| R3-F123 | `launched_by` nommé par le système d'identité du client | présent dépôt, CT-1 L189 | 2026-10-23 |
| R3 (section 2) | non vérifiés : escalade automatique dans les produits lus ; qualification réglementaire de NOORTRACE et de ses clients | sources de R3-F72 à R3-F113 ; aucune source pour la qualification | 2026-10-23 |

### B.4 Lectures propres à la partie B

| Fait | Source primaire | Consultée le |
|---|---|---|
| Niveaux N1, N2 et N3 de curators-hub ; N2 acceptée par défaut à son terme ; contestation d'un signal N2 vers N3 (10.2, 13.1) | noorchain-core, `dapps/curators-hub/lib/validation.ts` L1-L7, L291-L305, L334-L352 ; non recoupable publiquement | 2026-10-23 |
| La décision d'approbation porte la délégation du demandeur (10.4) | présent dépôt, `spec/vecteurs/ct-2/evenements/journal-demo/evenements.json` (seq 6) ; CT-1 annexe A (seq 3) | 2026-10-23 |
| Identifiant de chaîne du réseau de développement, `2124` (A.2) | présent dépôt, `deployments/noorcore.json` | 2026-10-23 |
| Adresse du compte Hardhat 4 (A.2) | dérivation du mnémonique public par ethers 6.17.0 (présent dépôt, `node_modules/ethers`) | 2026-10-23 |

### B.5 R4 — Portefeuilles

Révisions épinglées des sources, abrégées dans la table :

| Abrégé | Source | Révision |
|---|---|---|
| EIPS | https://github.com/ethereum/EIPs | `32678e29a6ddf80185f888b402988b662c727939` |
| MM-SPECS | https://github.com/MetaMask/api-specs (paquet 0.15.0) | `cfa8707dfa624ebf6a6826d7f493f310735f75eb` |
| MM-CORE | https://github.com/MetaMask/core, `packages/eth-json-rpc-middleware` (26.0.0) | `af0c0bee142298f1b6e105cec342e65a8b7ab451` |
| MM-EXT | https://github.com/MetaMask/metamask-extension | `17d8e74128b6d36cc3efe343d67039d6be57f853` |
| MM-ACC | https://github.com/MetaMask/accounts (`keyring-eth-ledger-bridge` 13.1.1, `keyring-eth-trezor` 11.0.1) | `20cf7555d5507c43cf303872332ba2eb965b6536` |
| MM-PROV | https://github.com/MetaMask/providers (22.1.1) | `4ac0b3e2df7de682a95d50e3429dadb0995862cf` |
| SIGUTIL | paquet npm `@metamask/eth-sig-util` 9.0.0 | — |
| RABBY | https://github.com/RabbyHub/Rabby | `f3fa88953363307d51fec897caf26001781add20` |
| LEDGER | https://github.com/LedgerHQ/app-ethereum | `f7985b427841ace20795b548905ababf6a5b17a4` |
| LSDK | https://github.com/LedgerHQ/ledger-secure-sdk | `51d2f39a10eddea6fe1ccbc9db20666ba00e911d` |
| TREZOR | https://github.com/trezor/trezor-firmware | `e59fe6acb7edb5eed2d5b5cbab2380a3acbbba9c` |
| SECP | https://github.com/bitcoin-core/secp256k1 (sous-module `vendor/secp256k1-zkp` de TREZOR) | `1a53f4961f337b4d166c25fce72ef0dc88806618` |
| TSUITE | https://github.com/trezor/trezor-suite | `1f0ceebcd5993df63c606465d20d0bbec6e4a3c6` |
| WCSPECS | https://github.com/WalletConnect/walletconnect-specs | `ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec` |
| WCCORE | paquet npm `@walletconnect/core` 2.26.0 | — |
| ETHORG | https://github.com/ethereum/ethereum-org-website | `99cb89553d6ca4e67e634552b7dc5ff91cb6c370` |
| ETHERS | paquet npm `ethers` 6.17.0 (celui du présent dépôt) | — |
| ETHACC | roue PyPI `eth_account-0.14.0-py3-none-any.whl`, avec eth-keys 0.8.0 | — |

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R4-F1 | EIP-1193, statut « Final » ; méthode `request` ; rejet par `ProviderRpcError` | EIPS `EIPS/eip-1193.md` L6, L71-L88 | 2026-10-26 |
| R4-F2 | EIP-1193 : codes 4001, 4100, 4200, 4900, 4901 | même fichier L96-L115, L147-L156 | 2026-10-26 |
| R4-F3 | EIP-1193 : événements `connect`, `disconnect`, `chainChanged`, `accountsChanged` ; une méthode et cinq événements | même fichier L160-L243 | 2026-10-26 |
| R4-F4 | EIP-1193 : fournisseur à traiter comme contrôlé par un adversaire ; comptes exposés seulement sur demande (`eth_requestAccounts`, `wallet_requestPermissions`) | même fichier L283-L311 | 2026-10-26 |
| R4-F5 | EIP-6963, statut « Final », requiert EIP-1193 ; `info` : `uuid` UUIDv4, `name`, `icon`, `rdns` | EIPS `EIPS/eip-6963.md` L7, L11, L46-L62 | 2026-10-26 |
| R4-F6 | EIP-6963 : icône en URI `data:`, SVG rendu par `<img>` ; `rdns` déclaratif, imitable, à ne pas employer pour la détection | même fichier L76, L83-L86 | 2026-10-26 |
| R4-F7 | EIP-6963 : `eip6963:announceProvider`, `eip6963:requestProvider`, écouteur gardé toute la vie de la page | même fichier L109-L163 | 2026-10-26 |
| R4-F8 | EIP-6963 : deux `info` de même `uuid` signalent une imitation | même fichier L251-L255 | 2026-10-26 |
| R4-F9 | MetaMask annonce par EIP-6963 et valide `uuid` et `rdns` | MM-PROV `src/EIP6963.ts` L11-L12, L165-L185 | 2026-10-26 |
| R4-F10 | ethers 6.17.0 : `BrowserProvider.discover` prend le premier fournisseur annoncé sans filtre ; délai par défaut 300 ms | ETHERS `src.ts/providers/provider-browser.ts` L227-L331 | 2026-10-26 |
| R4-F11 | `eth_requestAccounts` : EIP-1102, statut « Stagnant » ; EIP-2255 « Final » | EIPS `EIPS/eip-1102.md` L6, L79, L87 ; `EIPS/eip-2255.md` L7 | 2026-10-26 |
| R4-F12 | MetaMask : `personal_sign` prend la donnée puis l'adresse ; `eth_requestAccounts` d'abord ; codes 4001 et 4100 | MM-SPECS `openrpc.yaml` L217-L258, L924-L948, L1673-L1681 ; https://docs.metamask.io/metamask-connect/evm/reference/json-rpc-api/personal_sign.md | 2026-10-26 |
| R4-F14 | intergiciel de MetaMask : ordre (donnée, adresse), repli si le premier paramètre a la longueur d'une adresse ; `eth_sign` absent | MM-CORE `packages/eth-json-rpc-middleware/src/wallet.ts` L162-L178, L491-L505 ; `src/utils/validation.ts` L135-L138 | 2026-10-26 |
| R4-F15 | extension MetaMask : message de 32 octets en hexadécimal, ligne « message », copie ; texte si UTF-8 valide | MM-EXT `ui/helpers/utils/util.js` L830-L841 ; `ui/pages/confirmations/components/confirm/info/personal-sign/personal-sign.tsx` L45-L51, L155-L164 | 2026-10-26 |
| R4-F16 | `eth_sign` déprécié ; test de bout en bout qui attend une erreur ; Ledger et Trezor limités à `personal_sign` | MM-EXT `test/e2e/tests/confirmations/signatures/eth-sign.spec.ts` L7-L8 ; https://docs.metamask.io/metamask-connect/evm/guides/sign-data.md L14, L18, L427 | 2026-10-26 |
| R4-F17 | `@metamask/eth-sig-util` 9.0.0 : donnée `0x…` décodée en octets ; même signature que le vecteur ; `s` haut accepté au recouvrement | SIGUTIL `dist/utils.js` L46-L50, `dist/personal-sign.js` L17-L27 ; expérience de la note | 2026-10-26 |
| R4-F18 | Rabby : ordre (donnée, adresse) exigé, `eth_sign` refusé, hexadécimal si non UTF-8 | RABBY `src/background/controller/provider/controller.ts` L1440-L1482 ; `src/ui/utils/index.ts` L40-L50 ; `src/ui/views/Approval/components/SignText.tsx` L89-L90 | 2026-10-26 |
| R4-F19 | proportion des chaînes de 32 octets qui sont de l'UTF-8 valide : 1,004 × 10⁻⁸ | expérience de la note (dénombrement des séquences de la RFC 3629) | 2026-10-26 |
| R4-F20 | ethers : `signMessage` envoie `personal_sign` avec la donnée en hexadécimal puis l'adresse en minuscules | ETHERS `src.ts/providers/provider-jsonrpc.ts` L443-L447 | 2026-10-26 |
| R4-F21 | MetaMask et Ledger : message sans `0x`, `v ∈ {0, 1}` ramené à 27 ou 28, adresse recouvrée contrôlée | MM-ACC `packages/keyring-eth-ledger-bridge/src/ledger-keyring.ts` L466-L505, L816-L830 | 2026-10-26 |
| R4-F22 | application Ethereum de Ledger : `v = 27 + parité` (+ 2 si `r` déborde), sortie `v ‖ r ‖ s` | LEDGER `src/features/sign_message/ui_common_sign_message.c` L11-L27 ; `src/shared_context.h` L28-L29 ; `doc/apdu.md` L161-L202 | 2026-10-26 |
| R4-F23 | Ledger : « Review message », paire « Message », paire « Message hash » (condensé EIP-191) si « Transaction hash » est activé ; pas de « blind signing » | LEDGER `src/nbgl/ui_sign_message.c` L105-L164 ; `src/nbgl/ui_home.c` L190-L195 ; `src/features/sign_message/cmd_sign_message.c` L20-L22, L80-L92 | 2026-10-26 |
| R4-F24 | SDK de Ledger : `s` ramené dans la moitié basse sauf `CX_NO_CANONICAL`, que l'application n'emploie pas | LSDK `lib_standard_app/crypto_helpers.c` L161-L162 ; `src/cx_wrappers.c` L25-L46 ; `lib_cxng/src/cx_ecdsa.c` L117, L289-L298 ; `lib_cxng/include/lcx_common.h` L156 | 2026-10-26 |
| R4-F25 | Trezor « core » : `decode_message`, contrainte `CANONICAL_SIG_ETHEREUM`, `r ‖ s ‖ v`, `v = 27 + recid` ; `hex(…)` pour un message non UTF-8 | TREZOR `core/src/apps/ethereum/sign_message.py` L15-L58 ; `core/embed/upymod/modtrezorcrypto/modtrezorcrypto-secp256k1.h` L95-L162 ; `core/src/apps/common/signverify.py` L31-L35 | 2026-10-26 |
| R4-F26 | Trezor, branche secp256k1-zkp : `secp256k1_ecdsa_sign_recoverable`, `s` toujours bas | TREZOR `crypto/ecdsa.c` L1353-L1362, `crypto/zkp_ecdsa.c` L176-L255 ; SECP `src/ecdsa_impl.h` L266-L297, `include/secp256k1.h` L659 | 2026-10-26 |
| R4-F27 | MetaMask et Trezor : message en hexadécimal (`hex: true`) à Trezor Connect, qui le transmet et en montre un décodage en texte | MM-ACC `packages/keyring-eth-trezor/src/trezor-keyring.ts` L433-L456 ; TSUITE `packages/connect-core/src/api/ethereum/api/ethereumSignMessage.ts` L34-L62 | 2026-10-26 |
| R4-F28 | WalletConnect v2, Sign API : session sur transport JSON-RPC distant ; `wc_sessionRequest` (CAIP-27) avec `request` (`method`, `params`, `expiry`) et `chainId` ; `expiry` entre 300 s et 604 800 s ; `personal_sign` (donnée, adresse) | WCSPECS `docs/specs/clients/sign/README.md` L5 ; `docs/specs/clients/sign/rpc-methods.md` L224-L263 ; https://docs.reown.com/advanced/multichain/rpc-reference/ethereum-rpc.md L9-L22 | 2026-10-26 |
| R4-F29 | chiffrement de bout en bout X25519 et ChaCha20-Poly1305 ; clé symétrique d'appariement dans l'URI | WCSPECS `docs/specs/clients/core/crypto/readme.md` L5 ; `crypto-envelopes.md` L13-L31 ; `docs/specs/clients/core/pairing/pairing-uri.md` L6-L20 | 2026-10-26 |
| R4-F30 | relais : sujet, message chiffré, durée de vie, étiquette ; boîte aux lettres hors ligne ; client authentifié par JWT ; contenu illisible des nœuds | WCSPECS `docs/specs/servers/relay/relay-server-rpc.md` L29-L36 ; `docs/specs/clients/core/relay/relay-client-auth.md` L5-L15 ; https://docs.walletconnect.com/network/service-nodes.md L7 | 2026-10-26 |
| R4-F31 | identifiant de projet délivré par WalletConnect ; liste d'origines (vide : toutes admises) ; passerelles centralisées, réseau à permission | https://docs.walletconnect.com/wallets/web/cloud/relay.md L7-L35 ; https://docs.walletconnect.com/network/index.md L17-L28 | 2026-10-26 |
| R4-F32 | SDK : relais par défaut `wss://relay.walletconnect.org`, réglable ; politique de sécurité du contenu documentée à liste large | WCCORE `dist/types/constants/relayer.d.ts` L3, `dist/types/core.d.ts` L7 ; https://docs.reown.com/advanced/security/content-security-policy.md L23 | 2026-10-26 |
| R4-F33 | Web3 Secret Storage v3 : `pbkdf2` (`hmac-sha256`) obligatoire, MAC keccak256, `aes-128-ctr` obligatoire | ETHORG `public/content/developers/docs/data-structures-and-encoding/web3-secret-storage/index.md` L28-L73 | 2026-10-26 |
| R4-F34 | vecteur `pbkdf2` de la définition déchiffré ; vecteur `scrypt` rejeté par ethers et eth-account, clé dérivée publiée incohérente | même fichier L79-L152 ; expérience de la note | 2026-10-26 |
| R4-F35 | ethers 6.17.0 : `scrypt` et `pbkdf2` (`sha256`, `sha512`), `dklen` 32 exigé, chiffrement par défaut `scrypt` `N = 2^17`, `r = 8`, `p = 1` | ETHERS `src.ts/wallet/json-keystore.ts` L144-L178, L260 | 2026-10-26 |
| R4-F36 | ethers 6.17.0, version `latest` ; `hashMessage` et `verifyMessage` encodent une chaîne en UTF-8 | registre npm ; ETHERS `src.ts/hash/message.ts` L35-L51 | 2026-10-26 |
| R4-F37 | ethers : 64 octets lus comme signature compacte ; `v` normalisé depuis 0, 1, 27, 28 ou au moins 35 ; `s` haut refusé par l'accesseur | ETHERS `src.ts/crypto/signature.ts` L86-L88, L305-L349 ; `src.ts/crypto/signing-key.ts` L166-L177 | 2026-10-26 |
| R4-F38 | mesure ethers sur `D_A` : octets et chaîne, `s` haut, `v` = 0, 1, 37, 38, 29, 64 octets | expérience de la note (vecteur `decisions/valides/approbation-2-sur-3.json` du présent dépôt) | 2026-10-26 |
| R4-F39 | eth-account 0.14.0, dernière version ; `encode_defunct` (version `E`) prend `primitive`, `hexstr` ou `text` | https://pypi.org/pypi/eth-account/json ; ETHACC `eth_account/messages.py` L114-L185 | 2026-10-26 |
| R4-F40 | eth-account : `recover_message` ; `v` admis 0, 1, 27, 28, au moins 35 ; eth-keys admet `r` et `s` de 0 à n − 1 | ETHACC `eth_account/account.py` L447-L546 ; `eth_account/_utils/signing.py` L101-L118 ; eth-keys 0.8.0 `eth_keys/validation.py` L47, L105-L108 | 2026-10-26 |
| R4-F41 | mesure eth-account sur `D_A` : `hexstr` et octets justes ; `text=` signe 66 octets ; un entier perd l'octet nul de tête ; `s` haut et `v` = 37 ou 38 acceptés ; `v = 29` et 64 octets refusés | expérience de la note (même vecteur) | 2026-10-26 |
| R4 NV-1 | rendu réel d'un `personal_sign` de 32 octets, pagination et troncature : non observés | sources de R4-F15, R4-F18, R4-F23, R4-F25 | 2026-10-26 |
| R4 NV-2 | Ledger : exécution par l'appareil du code publié du SDK ; `v ∈ {0, 1}` non reproduit | sources de R4-F21, R4-F22, R4-F24 | 2026-10-26 |
| R4 NV-3 | Trezor Model One (micrologiciel « legacy ») : non lu | https://github.com/trezor/trezor-firmware | 2026-10-26 |
| R4 NV-4 | WalletConnect : affichage mobile d'un `personal_sign` binaire, relais auto-hébergeable, conservation des métadonnées : non vérifiés | sources de R4-F28 à R4-F32 | 2026-10-26 |
| R4 NV-5 | versions des porte-clés et retrait d'`eth_sign` dans l'extension MetaMask publiée : non vérifiés | sources de R4-F16, R4-F21, R4-F27 | 2026-10-26 |
| R4 NV-7 | import d'un fichier keystore v3 par les portefeuilles de navigateur : non vérifié | — | 2026-10-26 |
| R4 NV-10 | portefeuilles de navigateur autres que MetaMask et Rabby : non lus | — | 2026-10-26 |
| Lecture propre | Web3 Secret Storage v3 : membres `crypto`, `id`, `version` ; `kdfparams` de `scrypt` (`dklen`, `n`, `p`, `r`, `salt`) ; vecteur `pbkdf2` à `c` = 262 144 (13.13) | ETHORG, même fichier L79-L152 (copie de la note R4, relue le 2026-10-26) | 2026-10-26 |

Les mesures de la note (« expérience de la note ») portent sur un vecteur
public du présent dépôt ; leurs scripts et sorties ne sont pas publiés.

### B.6 R5 — Identité, annuaire et page de signature

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R5-F1 | `sub` : identifiant local, jamais réattribué, au plus 255 caractères ASCII, sensible à la casse | https://openid.net/specs/openid-connect-core-1_0.html (OIDC Core 1.0, errata set 2, « Final », 15 décembre 2023), §2 | 2026-10-26 |
| R5-F2 | `iss` : URL `https` sans requête ni fragment ; égalité exacte à la validation | même source, §2 et §3.1.3.7 | 2026-10-26 |
| R5-F3 | `aud` : contient le `client_id` ; refus d'un jeton pour un autre client | même source, §2 et §3.1.3.7 | 2026-10-26 |
| R5-F4 | `nonce` : lie la session et le jeton, contre le rejeu | même source, §2 et §3.1.3.7 | 2026-10-26 |
| R5-F5 | `auth_time` obligatoire avec `max_age` | même source, §2 | 2026-10-26 |
| R5-F6 | `acr` : valeurs à convenir entre les parties, contrôle par le client | même source, §2 et §3.1.3.7 | 2026-10-26 |
| R5-F7 | `amr` et valeurs de RFC 8176 (`hwk`, `mfa`, `pwd`, `swk`, `user`) | même source, §2 ; https://www.rfc-editor.org/rfc/rfc8176.txt | 2026-10-26 |
| R5-F8 | seule la paire `iss` + `sub` identifie une personne ; courriel et nom ne doivent pas servir d'identifiant | OIDC Core 1.0, §5.7 | 2026-10-26 |
| R5-F9 | types d'identifiant `public` et `pairwise` | OIDC Core 1.0, §8 | 2026-10-26 |
| R5-F10 | `prompt=login` : réauthentification obligatoire | OIDC Core 1.0, §3.1.2.1 et §3.1.2.3 | 2026-10-26 |
| R5-F11 | `max_age` : réauthentification au-delà du délai ; `max_age=0` équivaut à `prompt=login` | OIDC Core 1.0, §3.1.2.1 | 2026-10-26 |
| R5-F12 | le client DEVRAIT contrôler `auth_time` ; l'expiration du jeton est sans rapport avec la session | OIDC Core 1.0, §3.1.3.7 et §2 | 2026-10-26 |
| R5-F14 | durées de session AAL2 et AAL3 (AAL3 : 12 h au plus, inactivité 15 min au plus) | https://pages.nist.gov/800-63-4/sp800-63b.html (NIST SP 800-63B-4, août 2025) | 2026-10-26 |
| R5-F15 | la partie de confiance juge de la réauthentification ; intention ; résistance à l'hameçonnage | même source | 2026-10-26 |
| R5-F16 | ERC-4361 « Sign-In with Ethereum », « Final », préfixe ERC-191 | https://github.com/ethereum/ERCs/blob/4891ba3b86d2058d0f472dbf1500af6bb056caf2/ERCS/erc-4361.md L3-L11, L32 | 2026-10-26 |
| R5-F17 | grammaire ABNF du message ; `statement` sans LF, caractères d'URI | même source, L43-L94 | 2026-10-26 |
| R5-F18 | champs `domain`, `address`, `statement`, `uri`, `version`, `chain-id`, `nonce`, `issued-at`, `expiration-time` | même source, L112-L120 | 2026-10-26 |
| R5-F19 | vérification par ERC-191 pour un compte externe ; ERC-1271 dépendant de l'état | même source, L208-L213 | 2026-10-26 |
| R5-F20 | la partie de confiance compare le domaine à l'origine ; sessions liées à l'adresse | même source, L227-L235 | 2026-10-26 |
| R5-F21 | le portefeuille rejette un domaine discordant, signale la formule de connexion dans un message non conforme, affiche les champs | même source, L247-L281 | 2026-10-26 |
| R5-F22 | nonce par session, contre le rejeu | même source, L329, L377 | 2026-10-26 |
| R5-F24 | interface lisible avant la signature, sans JSON ni code hexadécimal | même source, L297, L313-L315 | 2026-10-26 |
| R5-F25 | MetaMask avertit d'un domaine discordant sans bloquer | https://docs.metamask.io/metamask-connect/evm/guides/sign-data/siwe/ | 2026-10-26 |
| R5-F26 | ERC-191, version `0x45` : préfixe et longueur décimale | https://github.com/ethereum/ERCs/blob/4891ba3b86d2058d0f472dbf1500af6bb056caf2/ERCS/erc-191.md L41-L47, L69-L75 | 2026-10-26 |
| R5-F27 | mesure : `L + chiffres(L)` strictement croissante ; préimage d'un vote de 60 octets ; condensé du `D_A` d'`apr-1192` | expérience de la note (Node v22, ethers 6.17.0 du présent dépôt) | 2026-10-26 |
| R5-F28 | SCIM : `id` stable et non réattribuable, `externalId`, `active`, `userName` | https://www.rfc-editor.org/rfc/rfc7643.txt | 2026-10-26 |
| R5-F29 | WebAuthn niveau 3 : opérations liées à une origine et à un identifiant de partie de confiance ; résistance à l'hameçonnage | https://www.w3.org/TR/2026/REC-webauthn-3-20260825/ (Recommendation, 25 août 2026), txt L1655-L1656, L1718-L1728 ; NIST SP 800-63B-4 (même URL que R5-F14) | 2026-10-26 |
| R5-F31 | registre de tous les authentificateurs liés à un compte | NIST SP 800-63B-4 (même URL que R5-F14) | 2026-10-26 |
| R5-F32 | curators-hub : identifiant de 7 chiffres, mot de passe, verrouillage | noorchain-core, `dapps/curators-hub/lib/logins.mjs` L3-L55, `lib/auth.ts` L9-L10 ; non recoupable publiquement | 2026-10-26 |
| R5-F33 | curators-hub : sessions de 8 h et 30 jours, aucune réauthentification avant un vote | noorchain-core, `lib/session-token.mjs` L4-L63, `app/api/signals/review/route.ts` L13-L14 ; non recoupable publiquement | 2026-10-26 |
| R5-F34 | curators-hub : session liée à la clé par le nom affiché | noorchain-core, `app/api/signals/review/route.ts` L16, `lib/curator-auth.ts` L34-L36, `lib/curator-registry.ts` L54-L63 ; non recoupable publiquement | 2026-10-26 |
| R5-F35 | curators-hub : clés générées par le serveur ; suppression refusée tant que membre du jeu | noorchain-core, `lib/curator-registry.ts` L173-L198, `lib/curator-key-vault.mjs` L1-L20, `lib/curators.ts` L257-L261 ; non recoupable publiquement | 2026-10-26 |
| R5-F36 | curators-hub : adresse d'organisation inscrite sans preuve de possession | noorchain-core, `lib/org-binding.mjs` L152-L163, `components/OwnerIdentityGate.tsx`, `app/api/org/identity/route.ts` L62-L73 ; non recoupable publiquement | 2026-10-26 |
| R5-F37 | curators-hub : surfaces publiques par adresses, jamais par noms | noorchain-core, `lib/signataires.mjs` L10-L14 ; non recoupable publiquement | 2026-10-26 |
| R5-F38 | curators-hub : une adresse dérivée par organisation | noorchain-core, `lib/paw/protocol.mjs` L3-L51 ; non recoupable publiquement | 2026-10-26 |
| R5-F39 | CSP 3 : défense en profondeur ; pas de `'unsafe-inline'` ni `data:` dans les scripts | https://www.w3.org/TR/2026/WD-CSP3-20260916/ (Working Draft, 16 septembre 2026) | 2026-10-26 |
| R5-F40 | CSP 3 : nonce unique d'au moins 128 bits ; `frame-ancestors` ; `base-uri 'none'` | même source | 2026-10-26 |
| R5-F41 | CSP stricte par nonce ou condensé ; `'strict-dynamic'` moins sûr ; `frame-ancestors` contre le détournement de clic | https://github.com/mdn/content/blob/9de14917b151f7db567a65d44c2685cea754b12a/files/en-us/web/http/guides/csp/index.md L356-L463 | 2026-10-26 |
| R5-F42 | SRI 1 : SHA-256, 384 et 512 ; refus d'une ressource altérée ; limite face au document | https://www.w3.org/TR/2016/REC-SRI-20160623/ (Recommendation, 23 juin 2016) | 2026-10-26 |
| R5-F43 | SRI 2 : `Integrity-Policy`, `blocked-destinations=(script)` ; prise en charge par navigateur | https://www.w3.org/TR/2026/WD-sri-2-20260320/ (Working Draft, 20 mars 2026) ; https://github.com/mdn/browser-compat-data, commit `dfccdeb611e3bcc4db697b614a71180bdd6cb3b6`, `http/headers/Integrity-Policy.json` | 2026-10-26 |
| R5-F44 | Trusted Types : `require-trusted-types-for 'script'`, `trusted-types 'none'` ; prise en charge | https://www.w3.org/TR/2026/WD-trusted-types-20261007/ (Working Draft, 7 octobre 2026) ; même commit de browser-compat-data, `api/TrustedTypePolicyFactory.json`, `http/headers/Content-Security-Policy.json` | 2026-10-26 |
| R5-F45 | CSP de curators-hub : nonce et `'strict-dynamic'`, rapport seul par défaut, sans Trusted Types ni SRI | noorchain-core, `lib/csp.mjs` L37-L78, `proxy.ts` L178-L180 ; non recoupable publiquement | 2026-10-26 |
| R5 NV-1 | rendu d'un message texte sur l'écran de Ledger et de Trezor : non observé | — | 2026-10-26 |
| R5 NV-2 | rejet d'un domaine discordant par les portefeuilles autres que MetaMask : non vérifié | — | 2026-10-26 |
| R5 NV-3 | prise en charge de `max_age`, `prompt=login`, `acr_values` et `amr` par les fournisseurs : non vérifiée | — | 2026-10-26 |
| R5 NV-4 | même client OIDC, donc même `sub`, pour la console et les connexions d'hôte : non vérifié | — | 2026-10-26 |
| R5 NV-7 | CSP 3, SRI 2 et Trusted Types sont des projets de travail ; SRI 1 est une Recommendation | sources de R5-F39, R5-F43, R5-F44 | 2026-10-26 |
| R5 NV-8 | réinterprétation d'un message par un portefeuille de compte de contrat : non vérifiée | — | 2026-10-26 |

### B.7 Lectures et mesures propres à la révision 0.3

| Fait | Source primaire | Consultée le |
|---|---|---|
| L'application Ethereum de Ledger n'affiche en hexadécimal qu'un message qui contient un octet ni imprimable ni blanc (`!isprint && !isspace`) ; sur les petits écrans, chaque blanc est affiché comme une espace (EX-13.12) | https://github.com/LedgerHQ/app-ethereum/blob/f7985b427841ace20795b548905ababf6a5b17a4/src/features/sign_message/cmd_sign_message.c L165-L206 (même révision que R2-F54) | 2026-10-26 |
| Message d'inscription d'exemple : 516 octets, préimage EIP-191 de 545 octets, condensé `0xaf9b14a6…71c5ef`, signature du compte 1 ; recouvrements croisés avec le vote d'`apr-0001` (EX-13.16) | expérience de la révision : `scripts/lib/journal.mjs` et ethers 6.17.0 du présent dépôt, clés de test publiques de `spec/vecteurs/ct-3/constantes.json` | 2026-10-26 |
| Chromium 141.0.7390.37 (Playwright 1.56.1) sous la politique d'EX-13.35 : script en ligne non exécuté, `innerHTML` refusé (`TypeError`), module altéré ou script d'entrée altéré bloqué par l'intégrité, module sans intégrité bloqué par `Integrity-Policy`, page encadrée non chargée | expérience de la révision (Node v22, Playwright du poste) ; chacune des cinq mesures est reproduite par le scénario « Politique du contenu » du test d'EX-13.36, sauté là où Playwright manque (EX-A.11) | 2026-10-26 |
