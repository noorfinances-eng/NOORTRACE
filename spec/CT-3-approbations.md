# CT-3 — Approbations

Version 0.2, 2026-10-23. Spécification normative, soumise à la revue de la
porte 1 du plan de projet (document interne). La version 0.2 aligne CT-3 sur
la version 0.3 de CT-2 ; la fin de la section 0 dit ce qu'elle change. Elle met
en œuvre la section « Approbation : avant l'action, pas après » de
l'[architecture cible](../ARCHITECTURE.md). Elle s'appuie sur les formats v0 de
[CT-1](CT-1-evenements-et-formats.md) sans les modifier, sur le point d'appel de
[CT-2](CT-2-enregistreur.md) (version 0.3, qui applique l'alignement de la
section 15) sans créer de code d'erreur, et laisse [CT-6](CT-6-verificateur.md)
inchangé. Elle clôt la décision ouverte 4 de l'architecture (sections 11 et 15).

La spécification a deux parties. La **partie A** (sections 0 à 6) dit qui
agit, ce qui est signé et journalisé, comment une règle s'écrit, ce que
valent les trois niveaux et comment une demande s'évalue. Un approbateur, un
auditeur ou un développeur peut s'y arrêter : elle suffit pour tirer d'une
règle la décision qu'elle donne. La **partie B** (sections 7 à 16 et
annexes) dit comment un ticket vit, d'où viennent le jeu d'approbateurs et
le seuil, ce que l'approbateur voit avant de signer, comment s'appliquent la
séparation des tâches et la fenêtre de contestation, ce que fait le
mandataire pendant l'attente, quels messages le service échange avec le
noyau, ce que la console doit faire, et comment les vecteurs sont disposés.
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
politique, portefeuilles, protocole MCP) viennent de trois notes de
recherche du lot CT-3, internes et non publiées, relues le 2026-10-23 sur
les sources primaires qu'elles citent : R1 (code et spécifications du
dépôt, contrats, console des curateurs), R2 (protocoles et signature), R3
(contrôle humain et pratiques). Chaque fait porte le renvoi du fait dans sa
note (« R2-F67 », « R3-F75 ») ou d'un point non vérifié (« R1-NV3 »,
« R2 NV-4 »). L'annexe B donne, pour chaque renvoi, l'objet du fait, les
sources primaires publiques et leur date. Ce qui n'a pas pu être vérifié est
écrit « non vérifié ».

Lecture : la partie A suffit pour tirer d'une règle la décision qu'elle
donne. Un approbateur ou un auditeur lit d'abord la section 5 (les niveaux),
puis, pour décider d'une demande, 4.2, 4.4 à 4.11 et 6.2 à 6.4 (sélection,
pointeurs, types, comparaisons exactes, chaînes, prédicats, logique à trois
valeurs, ordre des règles, algorithme, issues et chaîne `policy.rule`) ; un
développeur lit les sections 4 et 6 en entier.

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
10. l'interface du service d'approbation (section 12), la console
    (section 13), la sûreté (section 14) ;
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
| Le service d'approbation en processus et la console d'approbation | phase 2 du plan (sections 12 et 13) |

Relations avec les autres spécifications :

| Spécification | Ce que CT-3 en reprend | Ce que CT-3 lui fournit |
|---|---|---|
| CT-1 | `policy` et `approval` (§5.3), l'objet `A` et sa signature EIP-191 (§6.3), `approbations.json` (§11.2), E-5, E-9, A-1 à A-4 : tels quels | La syntaxe de `policy.rule` (6.4) ; la sémantique des règles et des tickets que CT-1 §15 renvoie à CT-3 ; la source du jeu déclaré (section 8) ; les champs signés supplémentaires, comme propositions pour une version 1 (section 16) |
| CT-2 | Le point d'appel avant relais (§4.4 pas 3 à 8, EX-7.4), les échanges du noyau avec le service (§7.5), la vérification avant scellement (SG-1 à SG-7, EX-7.5), les vérifications de relais (RL-1 à RL-4, EX-7.21), `approval.at` (EX-7.11), l'appel relayé et le `refusee` d'un ticket décidé (EX-7.12), le signal d'approbation, résultat `isError` qui porte `ticket` et `state` (EX-4.49), `policy.approval` (`mode`, `hold_timeout_ms`, `expire_after_ms`, `timeout_ms`, `service`), la matrice de panne (§14.2), les arguments en double précision exacte (EX-4.44) | Le contenu de `/policy/approval/rules` (4.1) ; la réponse au pas 3 (6.1) ; la liste des outils susceptibles d'approbation (4.12) ; le service, son interface et la remise des décisions (section 12) ; le mode d'attente par défaut (section 11) |
| CT-4 | `CuratorSetRegistry` et `CuratorSet`, lus sans écriture | Rien de nouveau ; ce qu'un registre pourrait un jour prouver d'une décision (section 16) |
| CT-6 | Le contrôle 7 et la provenance « déclaré par le dossier » du jeu (CT-6 EX-3.6), inchangés | Ce que chaque niveau prouve (5.7) ; ce qu'un futur contrôle pourrait recouper : réévaluation de la règle (6.8), séparation des tâches (section 10), jeu au registre (section 8) |
| CT-7 | — | La surface du service et de la console (3.5, section 14) ; la garde des clés d'approbateur (EX-3.4, sections 9 et 13) |
| CT-9 | — | Les identifiants EX-, AP-, TK- et SG-, les vecteurs `spec/vecteurs/ct-3`, l'épreuve d'acceptation à trois relecteurs (annexe A) |

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
| Réviseur | Celui qui vérifie un dossier ou un journal après coup, comme dans CT-6. |

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
| Chaque événement | L'enregistreur | Ed25519 (CT-1 §6.2) | Le vérificateur (E-8) |
| Réponse du service (`autorise`, `a_approuver`, `refuse`, outils susceptibles) | Personne | — | Canal authentifié (CT-2 EX-18.8) |
| Politique d'approbation | Personne ; son empreinte entre dans l'événement de politique | `policy_sha256` sur l'ensemble de politique en JCS intégral (CT-2 EX-10.21) | Le réviseur qui détient la pièce (CT-2 EX-8.11) |

`threshold`, `approvers`, `at` et `reason` ne sont pas signés par les
approbateurs ; ils sont attestés par la signature de l'enregistreur (CT-1
§5.3). L'objet `A` ne porte ni échéance, ni outil, ni fenêtre : une
signature d'approbation lie une demande exacte et rien d'autre (R1-F8,
R3-F122).

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
| **Console compromise** | Elle affiche une demande et fait signer autre chose ; elle émet sur le canal console → service avec des identifiants valides (EX-12.4). | Une signature vaut pour une seule demande retenue, celle de `request_hash` (CT-1 §6.3) ; la console recalcule `D_A` et l'affiche en entier (section 9). Effacer un refus par une récusation forgée : la récusation retire le vote `approuve` du membre, jamais son vote `refuse`, qui reste compté (EX-10.4). | Faire signer une autre demande réellement retenue sans que l'approbateur s'en aperçoive, si son portefeuille n'affiche que 32 octets en hexadécimal (R2-F53 à R2-F56, section 9). Faire signer `approuve` à qui voulait refuser la même demande : les deux objets `A` ne diffèrent que par `decision` (9.3) ; seuls l'outil hors ligne de recalcul de `D_A` et la notification de chaque vote inscrit par un canal indépendant (EX-13.3) le rendent visible. Ne pas transmettre un refus, forger une récusation ou un retrait : non signés en v0 (section 16). |
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
horloge du service).

| Entrée | Émetteur | Données | Section |
|---|---|---|---|
| `charger` | noyau | `policy_version` de l'ensemble chargé (le message complet de 12.2 porte aussi le document et la liste des outils ; une trace de l'annexe A.6 ne porte que `policy_version`) | 12.2 |
| `evaluer` | noyau, pas 3 | requête de CT-2 EX-7.4 ; pour une demande non reconnue, la sortie d'`EVALUER` (règle, décision, et pour `a_approuver` : `contest_ms`, ouvrant ou non, portée et fenêtre) | 6.2, 7.2, 12.3 |
| `ouvrir` | noyau, pas 6 | `request_hash`, `request_seq`, `request_ts` de l'événement `retenue` ; l'événement lui-même (`request_event`) et les octets de la pièce « arguments » (`arguments_piece`), pour la console (EX-9.6) | 12.4 |
| `jeu_lu` | lecteur de chaîne du service | résultat d'une lecture du jeu, `lu` ou `illisible` | 8.1 |
| `voter` | console | `approver`, `decision` (`approuve` ou `refuse`), `signature`, `reason` | 9.4, 7.11 |
| `recuser` | console | `approver` | 10.1 |
| `retirer` | console (demandeur, ou contact administrateur de la configuration du service, 10.3) | `by`, `reason` | 7.8 |
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
(identité de session égale à `launched_by`) et un contact administrateur de
la configuration du service (`administrators`, 10.3) PEUVENT retirer ;
l'échéance est avancée à l'instant du retrait et la décision est `expire`
avec la raison fixe d'EX-7.11. CT-1 v0 n'a pas de valeur « retiré » : un
retrait est une expiration avancée, que seul `reason` (attesté par
l'enregistreur, non signé) distingue dans un dossier. Google Cloud PAM admet
de même le retrait d'une demande en attente par le demandeur (fonction en
préversion, R3-F85,
https://cloud.google.com/iam/docs/pam-overview). Une valeur signée de retrait
est une proposition pour une version 1 (section 16).

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
5. les membres : les adresses connues du service (contacts des
   approbateurs, 10.3 ; adresses de `separation.identities` ; membres de ses
   lectures précédentes) pour lesquelles `isCurator(adresse)` vaut `true` à
   `H` ; si leur nombre est `n`, ce sont exactement les membres (un ensemble de
   `n` adresses membres parmi `n` membres est le jeu) ; sinon, le service
   reconstitue la liste par les journaux `CuratorAdded` et `CuratorRemoved` de
   `S` jusqu'à `H`, par tranches d'au plus 16 384 blocs (borne de `eth_getLogs`
   de noorcore, R1-F79), et la recoupe par `isCurator` à `H` et par `n` ; sans
   égalité : `illisible` (`membres_non_reconstitues`) ;
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

## 9. Signature et affichage

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
mesure sur le vecteur de CT-1, R2-F65). ethers et la branche trezor-crypto
du micrologiciel de Trezor produisent un `s` bas (R2-F66) ; ce n'est pas
vérifié pour la branche secp256k1-zkp de Trezor (R2 NV-6) ni pour Ledger
(R2 NV-5), ni qu'un portefeuille rende `v ∈ {0, 1}` (R2 NV-7). Toute autre
valeur de `v` est refusée (`signature_invalide`). Le noyau, lui, ne normalise
pas : il refuse une forme non canonique (SG-5), comme le vérificateur et le
contrat (R2-F63).

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
| Effets déclarés prévus : le gabarit d'effets de l'outil (CT-2 EX-7.6) évalué sur les arguments ; un pointeur vers le résultat est affiché « connu après exécution » | gabarits reçus par `charger` (12.2) | non |
| Règle déclenchée (`policy.rule`), sa description et son niveau (section 5), délai de contestation | politique, évaluation | `policy.rule` par `request_hash` |
| Pour un ticket ouvrant (5.3) : l'outil couvert, et lui seul ; la condition `when` rendue lisible ; chaque pointeur de `same_arguments` et sa valeur ; « au plus `max_calls` appels, chacun satisfaisant la condition, jusqu'à `approval.at` + `duration_ms` » | politique, ticket | non (EX-5.4) |
| Intention de l'agent, marquée « déclarée par l'agent, non vérifiée » | requête `evaluer` | par `request_hash` |
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
son retrait effectif du code n'est pas vérifié (R2 NV-11).
L'écran du portefeuille ne dit donc rien de la demande : il montre un
condensé. Le rendu réel d'un tel défi n'a pas été observé dans un
portefeuille (R1-NV2) ; celui des portefeuilles connectés par
WalletConnect n'est pas vérifié (R2 NV-8).

**EX-9.6** La console DOIT construire `A` à partir des champs affichés,
calculer `D_A` elle-même (SHA-256 de `P_A ‖ JCS(A)`), et non le recevoir du
serveur ; afficher `D_A` en entier ; et demander à l'approbateur de le
comparer, chiffre pour chiffre, à celui que montre son portefeuille. Elle
DOIT aussi vérifier ce qu'elle affiche contre la demande retenue, avec
l'événement `retenue` et la pièce « arguments » que le noyau remet par
`ouvrir` (12.4) et que le service lui sert :

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
signature sur `D_A` et l'égaler à l'adresse choisie par l'approbateur.

**EX-9.9** L'adresse d'un approbateur DEVRAIT être réservée aux opérations
NOORTRACE de son organisation (votes et opérations du registre au seuil), et
l'approbateur NE DEVRAIT signer un condensé de 32 octets que dans la console :
un site tiers qui présenterait `D_A` d'un ticket en attente comme « un
message à signer » obtiendrait un vote valide, et le portefeuille ne
permettrait pas de s'en apercevoir. Un portefeuille matériel DEVRAIT être
employé (la clé ne quitte pas l'appareil).

Ce que ces parades ne couvrent pas : une console compromise peut afficher une
demande et faire signer le `D_A` d'une autre, puisque l'approbateur ne voit
sur son portefeuille qu'un condensé ; elle peut aussi faire signer
`approuve` à qui a choisi `refuse` sur la même demande, les deux objets `A`
ne différant que par `decision` (EX-9.1). Pour les objections et les revues
de montant élevé, l'approbateur DEVRAIT recalculer `D_A` avec un outil hors
ligne indépendant de la console (section 16), et le service DEVRAIT lui
notifier, par un canal indépendant de la console (EX-13.3), chaque vote
inscrit en son nom avec sa décision ; c'est la limite du format v0 (CT-6 :
rien ne prouve que l'approbateur a lu ce qu'il approuvait, R1-F62). Les
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
une clé » (EX-8.11) est ce qui donne un sens à la liste. La console DEVRAIT
en outre refuser de soumettre un vote quand l'identité de session de
l'approbateur est le demandeur du ticket (EX-13.2). Quand `self_approval`
vaut `interdite` et que le demandeur n'a pas d'entrée dans
`separation.identities` (une identité de service, par exemple), la
séparation est vide pour lui : le service le signale à la création du
ticket (T1), la console affiche le bandeau « séparation non vérifiable pour
ce demandeur » (EX-9.4), et la validation en avertit quand le noyau
transmet les `launched_by` configurés (EX-4.14, 12.2).

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
| `administrators` : identités de session des contacts administrateurs | configuration du service | retrait d'un ticket (EX-7.15) |
| `set_poll_interval_ms` : défaut 10 000 | configuration du service | lecture et surveillance du jeu (8.2, 8.3) |
| point RPC de la chaîne du registre | configuration du service | lecture du jeu (EX-8.1) |
| contacts : administrateur de l'organisation ; approbateurs (adresse, identité de session, canal de notification) | configuration de la console (13.2) | notification, escalade, retrait (7.7, 7.8), identité de session (EX-13.2) |

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
| Une personne n'a qu'une voix | adresses distinctes seulement | non | non (EX-8.11) |
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
`recuser` et `retirer` (7.4). Ces messages passent par un canal authentifié
comme en EX-12.2 : mTLS, ou jeton porteur distinct de celui du noyau
(référence de secret) ; le service refuse un message d'une identité
inconnue. Chaque message porte l'identité de session de l'approbateur ou du
demandeur (`session_identity`, EX-13.2), que le service inscrit dans la
trace du ticket. L'authentification du canal ne protège pas d'une console
compromise, qui détient des identifiants valides : c'est pourquoi une
récusation ne retire jamais un refus (EX-10.4), et pourquoi une récusation
et un retrait signés sont proposés pour une version 1 (section 16).

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

**EX-12.12** Le service DEVRAIT exposer `GET <base>/v0/etat` :
`{ "ready": booléen, "set_read_at": horodatage ou null,
"open_tickets": entier }` ;
`ready` est faux tant qu'EX-8.3 n'est pas rempli.

### 12.8 Erreurs et raisons

Une erreur du service est une réponse HTTP 4xx ou 5xx de corps
`{ "error": { "code": "<raison>", "message": "<texte ASCII>",
"data": { … } } }`.
Les raisons de refus d'un vote (EX-9.10), d'une remise (SG-) et d'une entrée
de ticket (EX-7.8) sont prises dans la même liste fermée :

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
| `retrait_non_autorise` | service | `retirer` par une autre identité que le demandeur ou un contact administrateur (EX-7.15) |
| `remise_mal_formee` | noyau | SG-1 |
| `request_hash_different` | noyau | SG-2 |
| `ticket_deja_decide` | noyau | SG-3 |
| `echeance_depassee` | noyau | SG-4 |
| `seuil_non_atteint`, `approbateur_double`, `seuil_different_du_jeu`, `expire_avec_signatures` | noyau | SG-6 |
| `mode_degrade` | noyau | refus temporaire (12.5) |

## 13. Console d'approbation

La console est l'interface où les approbateurs lisent les demandes et
signent. Elle est construite en phase 2 du plan de projet à partir de
curators-hub (architecture, « Ce qui est réutilisé de noorchain-core ») ;
cette section fixe ce qu'elle doit faire, pas son code.

### 13.1 Ce que curators-hub apporte, et ce qu'il ne faut pas reprendre

| curators-hub (noorchain-core, dépôt privé, R1-F82 à R1-F87) | Dans la console CT-3 |
|---|---|
| Les clés des curateurs sont gardées par le serveur, qui signe pour eux dans leur session (« custodial pilot posture », R1-F83, R1-F84) | **Exclu.** Un serveur qui signe pour les approbateurs vide le contrôle 7 de son sens (R1-C23) |
| La clé de l'organisation naît dans le navigateur du propriétaire ; seule la signature quitte la page (`OrgOpSigner`, R1-F87) | Repris : c'est le modèle de toute signature d'approbateur |
| Aucun portefeuille de navigateur ; `signMessage` de viem sur des comptes locaux (R1-F82) | Ajouter les portefeuilles (extension, matériel) par EIP-1193 `request` (R2-F50) ; `personal_sign` en octets (EX-9.7) |
| Message texte lisible pour une décision de curateur (`decisionMessage`, R1-F84) | Non repris en v0 : l'objet signé est `A` de CT-1 §6.3 ; piste de version 1 (section 16) |
| Vérification de la signature, puis appartenance par `isCurator` **à la tête** (R1-F84) | Appartenance au **jeu figé** du ticket (section 8), pas à la tête |
| Un vote par curateur, remplacé par le suivant ; récusation (R1-F84, `lib/validation.ts`) | Repris (EX-7.26, EX-10.4) |
| Fenêtre N2 acceptée par défaut à son terme (`sweepExpiredWindows`, `lib/validation.ts` L291-L305) | **Exclu** (10.2) |
| Libellés en deux langues, journal d'audit | Repris |

### 13.2 Exigences

**EX-13.1** La console NE DOIT ni détenir, ni recevoir, ni dériver la clé d'un
approbateur ; la signature se fait dans le portefeuille de l'approbateur
(extension, portefeuille matériel, ou fichier de clé chiffré lu localement
comme `OrgOpSigner`), et seule la signature est envoyée au service.

**EX-13.2** La console authentifie la personne par le système d'identité du
client, celui qui nomme `delegation.launched_by` (CT-1 §5.3, R3-F123), et lui
attribue les adresses que sa configuration lui associe (contacts, 10.3). Elle
transmet l'identité de session avec chaque action ; le service l'inscrit dans
la trace du ticket (`session_identity`) et ne s'en sert que pour autoriser un
retrait (EX-7.15). La console DEVRAIT refuser de soumettre un vote dont
l'adresse n'est pas attribuée à la session, ou dont l'identité de session est
le demandeur du ticket quand `self_approval` vaut `interdite` (EX-10.5) ;
elle NE DOIT envoyer une récusation que pour une adresse attribuée à la
session (EX-10.4). Les actions passent par le canal authentifié
d'EX-12.4. Une
session donne accès aux tickets de l'organisation de la personne, et à rien
d'autre ; les arguments en clair d'un ticket ne sont montrés qu'aux membres
éligibles de son jeu figé et à l'administrateur de l'organisation.

**EX-13.3** Notification : à l'ouverture et à chaque escalade (7.7), par les
canaux configurés (courriel, messagerie, appel de webhook), avec le contenu
minimal d'EX-7.12. Le service DEVRAIT aussi notifier à chaque approbateur,
par un canal indépendant de la console, chaque vote inscrit en son nom avec
sa décision : c'est ce qui rend visible la bascule d'un refus en
approbation par une console compromise (9.3). La console liste les tickets
ouverts avec leur échéance, l'état de la fenêtre de contestation et les
votes exprimés, et, pour un ticket, les tickets refusés ou expirés du même
demandeur et du même outil depuis moins de `E` (une variation cosmétique
des arguments rouvre une demande refusée, EX-7.18, 14.7).

**EX-13.4** Affichage et signature : EX-9.4 à EX-9.9. La console DOIT être
servie avec une politique de sécurité du contenu qui interdit les scripts
tiers, et avec l'intégrité des sous-ressources ; la construction
reproductible et la publication de son code relèvent de CT-7 et CT-8.

**EX-13.5** Actions : voter `approuve` ou `refuse` (motif facultatif, au plus
1 024 caractères, EX-9.10), changer son vote (EX-7.26), objecter pendant la
collecte (un vote `refuse` quand `contest_ms > 0`, avant ou pendant la
fenêtre de contestation, EX-10.7) et lever son objection (un vote
`approuve`, EX-10.8), se récuser (EX-10.4), retirer (demandeur ou contact
administrateur, EX-7.15). Chaque action est
transmise au service, qui l'inscrit dans la trace du ticket avec son
résultat ; la console affiche le refus et sa raison (12.8).

**EX-13.6** La console avertit, avant la signature, que le motif est écrit
dans le journal sans pouvoir être effacé et ne doit contenir aucune donnée
personnelle (EX-9.14).

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
| Console compromise, ou émetteur sur le canal console → service | signer à la place de l'approbateur (EX-13.1) ; émettre sans identifiants valides (EX-12.4) ; effacer un refus par une récusation (EX-10.4) | faire signer un autre `D_A` que celui qu'elle affiche, ou `approuve` pour qui voulait refuser (9.3, limite de v0 ; parades : outil hors ligne et notification indépendante, EX-13.3) ; forger une récusation, qui ne retire qu'une approbation, ou un retrait, qui fait expirer le ticket (non signés en v0, section 16) ; ne pas transmettre un refus |
| Service d'approbation compromis | faire sceller une décision `approuve` ou `refuse` sans signatures valides au seuil du jeu qu'il déclare (SG-5, SG-6), ou signée par une adresse déclarée du demandeur (SG-7) ; s'aligner sur la décision d'une autre demande (T14, T20, CT-2 EX-7.17) ; blanchir une approbation en faisant relayer un autre appel sous elle, ou le même deux fois (RL-1 à RL-4, CT-2 EX-7.21) ; afficher d'autres arguments que ceux de la demande retenue, hors champs rédigés (EX-9.6) | rendre `autorise` à tort, y compris pour une demande déjà retenue (non signé, EX-12.2 ; la chaîne le montre après coup : un appel relayé `autorise` après un `retenue` du même outil) ; déclarer un faux jeu (14.4) ; ignorer la fenêtre de contestation (EX-9.12) |
| Administrateur du jeu | abaisser le nombre de signatures d'un ticket en attente (seuil effectif, EX-8.6) | changer les membres ou le seuil : visible sur la chaîne, et pris en compte par les tickets ouverts (8.3) ; ajouter des membres qu'il contrôle, signalés |
| Administrateur du registre | faire décider un ticket par un jeu réassigné (jeu épinglé, EX-8.1, EX-8.6) | bloquer les approbations jusqu'à une nouvelle version de politique (14.4) |
| Exploitant du nœud RPC | — | servir un état faux du registre ou du jeu : aucune preuve d'état en v0 (14.4) |

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

Points du dépôt que CT-3 rend caducs ou complète. Les fichiers racine de
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
- **La console elle-même** (phase 2) et un outil hors ligne qui recalcule
  `D_A` depuis l'événement `retenue` pour un second contrôle de
  l'approbateur.
- **La procédure de réexamen** d'une décision contestée par une personne
  concernée (5.6) et toute qualification réglementaire de NOORTRACE ou de
  ses clients (R3, section 2, non vérifié).
- **Un service pour plusieurs journaux** d'une même instance (CT-2 EX-13.7).

## Annexe A — Vecteurs CT-3

### A.1 Principes

**EX-A.1** Les vecteurs sont sous `spec/vecteurs/ct-3/`, produits par
`scripts/vecteurs/generer-ct3.mjs` (`npm run vecteurs:ct3`) et rejoués à
l'identique par `test/approbation.test.js` : horodatages, clés, identifiants
et ordres fixes, aucune valeur aléatoire. Le générateur n'efface et ne
réécrit que ses propres entrées de premier niveau (`INDEX.md`,
`constantes.json`, `acceptation-attendu.json` et les répertoires
`acceptation/`, `candidats/`, `decisions/`, `evaluation/`, `politiques/`,
`politiques-invalides/`, `signatures/`, `tickets/`), jamais
`verificateur-independant/` ; il refuse, sans rien effacer, un répertoire
de sortie qui porte une autre entrée, et une option `--sortie` sans
répertoire. Les fichiers JSON sont
écrits par `JSON.stringify(objet, null, 2)` suivi d'un saut de ligne, comme
ceux de CT-1 ; les vecteurs de CT-1, CT-2 et CT-6 ne changent pas.

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
`#/$defs/cas_remise` et leurs remises valides par `#/$defs/remise`.

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
  tickets/                     traces de cycle de vie, une par fichier (A.6)
  decisions/
    valides/                   remises acceptées par le noyau (A.7)
    invalides/                 remises refusées (A.7)
  signatures/
    normalisation.json         normalisation d'EX-9.3 (A.8)
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
| `retrait.json`, `retrait-administrateur.json` | retrait par le demandeur ou par un contact administrateur : `expire`, `echeance avancee par retrait` ; retrait par un tiers refusé |
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

**EX-A.10** Le vérificateur Go indépendant est le module
`spec/vecteurs/ct-3/verificateur-independant` (`noortrace-ct3`, `go 1.24`,
bibliothèque standard seulement), écrit depuis la seule spécification (CT-3,
et CT-1 pour `A`, `D_A` et E-9), sans lire le code de `scripts/` ni de
`test/`, comme ceux de CT-1 et CT-2 ; il PEUT copier les fichiers des
modules CT-1 et CT-2 (JCS, JCS intégral, keccak256, secp256k1) en le disant
en tête de fichier. Il
recalcule toutes les familles de A.3 (constantes, schémas, évaluation,
candidats, épreuve, traces, remises, normalisation), s'exécute par
`go run . ..` depuis son répertoire, et rend `0` si tout concorde, `1` s'il
trouve au moins une discordance, qu'il liste, `2` pour un usage incorrect.

**EX-A.11** L'intégration continue régénère `spec/vecteurs/ct-3` et exige
`git diff --exit-code` et aucun fichier non suivi, puis lance dans le module
Go `gofmt -l` (sortie vide), `go vet ./...`, `go test ./...` et
`go run . ..`, à côté des tâches de CT-1, CT-2 et CT-6.

## Annexe B — Sources des faits externes

Les renvois R1 à R3 du texte désignent trois notes de recherche du lot CT-3,
internes et non publiées : R1 (code et spécifications du dépôt, contrats,
curators-hub), R2 (protocoles et signature : MCP, délais des hôtes,
EIP-191, portefeuilles, moteurs de politique), R3 (contrôle humain et
pratiques : règlement sur l'IA, RGPD, LPD, NIST, FINMA, produits
d'approbation). Cette annexe donne, pour chaque renvoi des parties A et B,
l'objet du fait et les sources primaires que la note a consultées, à la date
indiquée ; ces sources font foi, pas la note. Un fait marqué « non vérifié »
le reste. Un intervalle « R3-F72 à R3-F78 » du texte renvoie à chacun des
faits qu'il couvre.

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
| R2 NV-5 | `s` bas chez Ledger : non vérifié | https://github.com/LedgerHQ/app-ethereum (code de l'application lu, bibliothèque `cx` non publique) | 2026-10-23 |
| R2 NV-6 | Trezor, branche secp256k1-zkp (`zkp_ecdsa_sign_digest`) : normalisation de `s` non lue, non vérifié | https://github.com/trezor/trezor-firmware | 2026-10-23 |
| R2 NV-7 | portefeuilles qui rendent `v ∈ {0, 1}` : non vérifié | — | 2026-10-23 |
| R2 NV-8 | affichage par les portefeuilles WalletConnect : non vérifié | https://docs.reown.com/advanced/multichain/rpc-reference/ethereum-rpc.md | 2026-10-23 |
| R2 NV-10 | filtrage EIP-712 « complet » de Ledger : non vérifié | https://developers.ledger.com/docs/device-app/integration/design-guidelines/transactions | 2026-10-23 |
| R2 NV-11 | MIP-3 : retrait effectif d'`eth_sign` dans le code de MetaMask : non vérifié | https://github.com/MetaMask/metamask-extension | 2026-10-23 |
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
