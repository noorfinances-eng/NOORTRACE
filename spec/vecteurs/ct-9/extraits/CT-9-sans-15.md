# CT-9 — Plan de tests

Version 0.4, 2026-11-10 (révision 0.4, fermeture de l'étape 5 de la phase 2
et alignement sur CT-5 (0.5) et CT-6 (0.5) ; révision 0.3 du 2026-11-03,
alignement sur les révisions du même jour de CT-1 (0.5), CT-4 (0.5), CT-5
(0.3), CT-6 (0.4), CT-7 (0.2) et CT-8 (0.2) ; révision 0.2 du même jour,
fermeture de l'étape 4 de la phase 2 ; version 0.1 du 2026-11-01, première
rédaction). Spécification normative,
soumise à la revue de la porte 1 du plan de projet (document interne).
Dernière des neuf spécifications de la phase 1, elle répond, une par une,
aux délégations que CT-1 à CT-8 lui font (table de traçabilité, section
0.2) : les tests unitaires et de propriétés sur le noyau (section 6), la
conformité aux vecteurs publiés (section 7), l'interopérabilité des exports,
des API et des intégrations (section 8), les parcours de bout en bout des
deux cas de démonstration (section 9), un test adversarial par menace du
modèle de CT-7 (section 10), les mesures et leur méthode (section 11), les
rejeux à l'aveugle (section 12), la revue de code (section 13) et la
correspondance de chaque critère de la porte 2 à des tests et à un verdict
calculable (section 14). Elle ferme la porte 1 et prépare la porte 2.

Son critère d'acceptation est celui du plan : **chaque menace du modèle a au
moins un test qui échoue si la réponse est retirée**. CT-9 le rend
vérifiable par machine : le catalogue `spec/vecteurs/ct-9/catalogue.json`
est la source unique des tests, le texte en reprend les tables, et l'outil
`scripts/tests/couverture.mjs` recompte, à chaque exécution des tests et dans
l'intégration continue, que chaque identifiant de CT-1 à CT-8 est couvert
par un test ou par une justification nommée, que chaque menace a son test
adversarial, que chaque renvoi à CT-9 a sa ligne et que chaque test déclaré
exécutable cite un test du dépôt qui existe mot pour mot.

L'enregistreur, le service d'approbation, le composant d'ancrage, la console
d'exploitation et le binaire Go du vérificateur ne sont pas construits :
CT-9 décrit des tests, il n'invente aucun résultat d'exécution. Un test dont
l'objet n'existe pas est « à écrire », rattaché à l'étape de la phase 2 qui
livre cet objet, avec ses préconditions, ses étapes et son oracle exacts ;
un test exécutable aujourd'hui l'est réellement, son résultat est celui de
l'exécution citée avec sa commande (annexe A). Les chiffres de couverture du
texte sont ceux que l'outil calcule, cités avec la commande ; la colonne
« mesure » des tests de mesure est vide en 0.1 et le dit. CT-9 ne modifie
aucune spécification CT-1 à CT-8 ni aucun vecteur `ct-1` à `ct-8` ; ce
qu'il leur propose est écrit en propositions PD- (section 17.2).

## 0. En-tête et conventions

### 0.1 Conventions

Les mots DOIT, NE DOIT PAS, DEVRAIT et PEUT ont le sens de la RFC 2119,
comme dans CT-1 à CT-8. Un DOIT de CT-9 s'adresse à l'auteur d'un test, à
l'outil de couverture, au générateur des vecteurs ou à l'intégration
continue ; il ne crée aucune obligation contractuelle.

Chaque règle normative porte un identifiant **EX-<section>.<n>** (EX-5.2 :
deuxième règle de la section 5), stable, numéroté dans l'ordre du texte à
l'intérieur de chaque section de premier niveau, sous-sections comprises ;
ceux de l'annexe A s'écrivent EX-A.<n>. Une règle ajoutée par une révision
reçoit le numéro qui suit le plus grand de sa section ; aucun numéro n'est
réattribué ; une règle retirée garde son numéro, marqué « retiré ».

Un renvoi à une autre spécification s'écrit toujours avec elle : « CT-2
EX-16.1 », « CT-6 T-7 », « CT-7 MN-17 », « CT-1 §12.1 ». Dans le catalogue
et dans les tables de CT-9, un identifiant d'une autre spécification est
**toujours** précédé d'elle, même dans une énumération (membre `covers`,
section 4.1), parce que l'outil de couverture le résout mécaniquement et que
plusieurs familles sont homonymes : T- (CT-6 : jeton ; CT-7 : texte de la
matrice), AN- (CT-3 : annuaire ; CT-5 : ancrage), P- (CT-1 : manifeste ;
CT-5 : propriété mesurable), K- (CT-1 : point de contrôle ; CT-6 : glose),
AT- (CT-1, CT-6 et CT-7 : la même vérification, définie par CT-1 §11.4),
SG- (CT-3, repris par CT-2), et trois familles de CT-9 doublent celles
d'une autre spécification : TR- (CT-7 : ligne de traçabilité ; CT-9 : rejeu
à l'aveugle), TC- (CT-8 : renvoi à CT-8 ; CT-9 : renvoi à CT-9), PD- (CT-8
et CT-9 : proposition, chacune les siennes). Un renvoi nu, hors d'une table,
est un renvoi à CT-9 ; dans une cellule de table, tout identifiant étranger
est préfixé de sa spécification, y compris TR-, TC-, PD- et EX-.

Les clés JSON sont en anglais ; les valeurs énumérées en français sans
accent (`executable`, `a_ecrire`, `vecteurs_et_depot`, `phase_2`,
`reussi`, `echec`) ; le texte libre, descriptions des vecteurs comprises, en
français accentué. Les noms d'hôtes d'exemple sont du domaine `.example` ;
les adresses d'exemple des plages de documentation RFC 5737 et RFC 3849, ou
`127.0.0.1`. Aucune clé réelle (seules les clés de test des vecteurs),
aucun prix, aucun nom d'hôte d'exploitation, aucun nom de produit
concurrent : la parité s'écrit en exigences mesurables (section 11, section
14).

Une **cible** est une valeur de conception non mesurée (CT-8 §0.1) ; une
**mesure** est le résultat d'une exécution réelle, avec sa commande, sa date
et son système de référence (section 11.1). En versions 0.1 à 0.4,
toute ligne de la table des mesures a sa colonne « mesure » vide : une valeur
mesurée vit dans un rapport de mesure, jamais dans le catalogue (EX-11.16).

Familles d'identifiants de CT-9 :

| Famille | Objet | Définie par |
|---|---|---|
| TC- | Renvoi d'une autre spécification à CT-9 et sa réponse | 0.2 |
| TU- | Test unitaire ou de propriétés sur une bibliothèque de référence | 3, 6 |
| TV- | Test de conformité d'une famille de vecteurs publiés | 3, 7 |
| TI- | Test d'interopérabilité (export, API, SDK, outil tiers) | 3, 8 |
| TE- | Test de bout en bout | 3, 9 |
| TA- | Test adversarial : une réponse retirée, une attaque, une observation | 3, 10 |
| TM- | Mesure : grandeur, cible, source, seuil d'échec, méthode | 3, 11 |
| TR- | Rejeu à l'aveugle : participant, matériel, sections interdites, grille, juge | 3, 12 |
| TQ- | Revue de code : composants, périmètre, grille | 3, 13 |
| NC- | Justification nommée de non-test d'un identifiant d'une autre spécification | 5.3 |
| PD- | Proposition de CT-9 à une autre spécification ou au dépôt, sans la modifier | 17.2 |

Les faits externes viennent de deux notes de recherche du lot CT-9, R10
(dépôt et délégations) et R11 (pratiques de test), internes et non
publiées, relues le 2026-11-01 ; un fait porte le renvoi de sa note
(« R10-F26 », « R11-F23 ») ; en cas d'ambiguïté avec le digest R11 cité par
CT-2, on écrit « CT-9 R11-F<n> ». L'annexe B donne pour chaque renvoi
l'objet, la source primaire et la date de lecture. Ce qui n'a pas pu être
vérifié est écrit « non vérifié ».

### 0.2 Ce que les autres spécifications délèguent à CT-9

Chaque occurrence de « CT-9 » dans `spec/*.md` (hors CT-9) au 2026-11-10 est
un renvoi, `spec/README.md` compris tel que cette livraison le réécrit :
**122 occurrences sur 114 lignes** (CT-1 : 3 occurrences sur 2 lignes ; CT-2 :
7 ; CT-3 : 4 ; CT-4 : 5 ; CT-5 : 10 ; CT-6 : 3 ; CT-7 : 20 occurrences sur 19
lignes ; CT-8 : 60 occurrences sur 59 lignes ; `spec/README.md` : 10
occurrences sur 5 lignes). La table les
reprend toutes, une ligne par occurrence, dans l'ordre des fichiers puis des
lignes ; la colonne « Spécification, section » nomme le dernier titre de
niveau 2 à 4 qui précède l'occurrence, hors bloc de code : « CT-n §s » quand
ce titre commence par un numéro, son texte entre guillemets sinon,
« en-tête » avant le premier titre (même procédé que `renvois.mjs` de CT-8,
R10-F3). Les numéros de ligne sont ceux du 2026-11-10 (révision 0.4),
indicatifs : l'outil compte par section, pas par ligne. Les réponses nomment
une section ou une famille de CT-9 ; « ce document » quand la ligne ne
délègue rien.

Comptage reproductible (lecture seule, exécuté le 2026-11-10) :

```bash
grep -o "CT-9" spec/CT-[1-8]-*.md spec/README.md | wc -l   # 122
grep -c "CT-9" spec/CT-[1-8]-*.md spec/README.md            # 114 lignes en tout
```

**EX-0.1** Toute occurrence de « CT-9 » dans une spécification de `spec/`
DOIT avoir sa ligne dans cette table (membre `traceability` du catalogue),
avec une réponse qui nomme une section, une famille ou une entrée de CT-9,
ou qui dit en clair que rien n'est délégué. La table est régénérée après
toute retouche de `spec/*.md` qui ajoute, retire ou déplace un « CT-9 » ;
le contrôle est celui de l'outil de couverture, règle (c) de la section 5.1
: il compte, fichier par fichier et section par section, les occurrences et
les lignes.

<!-- table TC -->
| Id | Spécification, section (ligne) | Ce qui est délégué à CT-9 | Réponse de CT-9 |
|---|---|---|---|
| TC-1 | CT-1 §12 (l. 2677) | Tests d'interopérabilité des trois correspondances d'export (OTel GenAI, projet IETF, SCITT) ; « aucune n'est implémentée en v0 ». | §8 (TI- d'export, à écrire, étape 8) ; SCITT : justification NC- hors version 0 (§5.3) ; proposition PD- sur RFC 9942 (§17.2). |
| TC-2 | CT-1 §17 (l. 3087) | Alignement de la révision 0.5 de CT-1 : CT-9 à mettre à jour (table de la section 5.2 et ligne TC-1), avec `spec/README.md`. | §5.2 : CT-1 en version 0.5 dans l'inventaire ; TC-1 régénérée (§0.2) ; révision 0.3 de ce document (§0.4). |
| TC-3 | CT-1 §17 (l. 3087) | Ligne de l'occurrence de « CT-9 » de CT-1 §12 après la révision 0.5 (renvoi de TC-1, ligne 2160 en version 0.4). | TC-1 (§0.2) : ligne relue sur le texte révisé par le générateur (EX-0.1). |
| TC-4 | CT-2 §0.1 (l. 37) | Rattachement des tests aux identifiants EX-. | §5.1, règle (a) ; membre `covers` de chaque entrée (§4.1). |
| TC-5 | CT-2 §1 (l. 527) | Périmètre : les tests sont hors de CT-2. | Ce document. |
| TC-6 | CT-2 §1 (l. 540) | Lit les EX-, les vecteurs (annexe B), la méthode de mesure (16) ; fixe les tests. | §7 (TV- de `ct-2`), §6 (TU- de CT-2), §11 (TM- de CT-2 §16). |
| TC-7 | CT-2 §10.4 (l. 6880) | Réappliquer la politique à une pièce stockée : égalité des octets (idempotence). | TV- `ct-2/redaction/` (§7), oracle « la seconde application ne change aucun octet ». |
| TC-8 | CT-2 §15.6 (l. 10365) | Règles de configuration que le schéma n'exprime pas : tests de CT-9. | TU- configuration et contrôles de démarrage (§6) ; TV- `ct-2/pieces-*` ; TE- installation (§9) pour la commande du démon. |
| TC-9 | CT-2 §16.2 (l. 10423) | Seuil de régression des mesures de performance, à décider par CT-9. | §11.4 : seuil de régression EX-11.15 ; proposition PD- à CT-2 EX-16.2 pas 7 (§17.2). |
| TC-10 | CT-2 §21 (l. 12257) | « Les tests » hors de CT-2. | Ce document. |
| TC-11 | CT-3 §0 (l. 37) | Rattachement aux EX-. | §5.1, règle (a). |
| TC-12 | CT-3 §1 (l. 309) | Périmètre. | Ce document. |
| TC-13 | CT-3 §1 (l. 337) | EX-, AP-, TK-, SG-, AN-, CS-, vecteurs `ct-3`, épreuve à trois relecteurs, épreuve de lecture de la console. | TR-1 (A.5, trois relecteurs) et TR-2 (A.11, console) en §12 ; EX-, AP-, TK-, SG-, AN-, CS- et vecteurs ct-3 : TU-, TV- (§6, §7). |
| TC-14 | CT-3 §7.12 (l. 2168) | Rattachement des TK-1 à TK-13 aux tests. | TV- `ct-3/tickets/` et TU- tickets (§6, §7) : `covers` CT-3 TK-1 à TK-13. |
| TC-15 | CT-4 §0 (l. 42) | Rattachement aux EX-. | §5.1, règle (a). |
| TC-16 | CT-4 §1 (l. 204) | Périmètre. | Ce document. |
| TC-17 | CT-4 §1 (l. 230) | EX-, RG-, vecteurs `ct-4`, épreuve d'acceptation sur le réseau de développement. | TR-3 (§7.12, relecteur sur le réseau de développement) en §12 ; EX-, RG- et vecteurs ct-4 : TV- (§7), TE- (§9). |
| TC-18 | CT-4 §9.2 (l. 3210) | Taille du certificat et de la capture d'une transaction d'un bloc plein de 64 ancres : mesure TM-31 de CT-9 du 2026-11-02 (certificat 32 587 octets ; capture 109 479 octets, 123 761 avec son index) ; bloc plein qui mêle des clôtures non mesuré. | TM-31 (§11, rapport `mesures/rapport-2026-11-02-capture-bloc-plein.json`, ligne `b_cap_bloc_plein` ; index et certificat relevés dans `notes`) ; bloc plein qui mêle des clôtures : TM-44 (à écrire, étape 8). |
| TC-19 | CT-4 §B.1 (l. 4249) | Point non vérifié 14 de R1 (taille d'un certificat de bloc plein) clos par la mesure TM-31 de CT-9 et son rapport. | TM-31 (§11) : rapport du 2026-11-02, certificat de 32 587 octets pour 64 transactions d'ancre (`notes`). |
| TC-20 | CT-5 §0 (l. 111) | Rattachement aux EX-. | §5.1, règle (a). |
| TC-21 | CT-5 §1 (l. 225) | Périmètre. | Ce document. |
| TC-22 | CT-5 §1 (l. 249) | EX-, AN-, vecteurs `ct-5`, épreuve à l'aveugle à deux relecteurs. | TR-4 (relecteur CT-5 et CT-1 §9 à §11) et TR-5 (second relecteur, CT-6 §7) en §12 ; consigne et grille sous spec/vecteurs/ct-9/ (EX-12.7) ; EX-, AN- et vecteurs ct-5 : TV- (§7). |
| TC-23 | CT-5 §3.6 (l. 468) | Mesures P-1 à P-6 sur le réseau de développement et sur les vecteurs. | TM-10 à TM-16 (P-1 à P-6) en §11 : sur les vecteurs (TM-10, TM-15), sur le réseau de développement (TM-11 à TM-14, exécutables depuis l'étape 5 par la campagne de `scripts/e2e/mesure-ancrage.mjs`, rapport `mesures/rapport-2026-11-10-ancrage.json` ; compléments à l'étape 8 : charge de TM-3 pour TM-11, prestataire qualifié réel pour TM-14) et sur le support WORM (TM-16, exécutable depuis l'étape 4, `ancres/` compris depuis l'étape 5). |
| TC-24 | CT-5 §5.3 (l. 1171) | Test à écrire : relève par le secours qualifié après retrait de `qualified` (EX-5.9). | TI-16 (§8), exécutable depuis l'étape 5 : relève de la clôture par le secours qualifié après retrait de `qualified`, sans rechargement, sur le composant d'ancrage (`test/ancrage-composant-pannes.test.js`, serveurs internes déclarés qualifiés par un instantané d'exemple) ; complément à l'étape 8 : prestataire qualifié réel. |
| TC-25 | CT-5 §7.2 (l. 1680) | AN-24 à AN-32 du serveur interne vérifiées sur un jeton émis. | TI-17 (§8), exécutable depuis l'étape 5 : AN-22 à AN-31 vérifiées sur les jetons émis par le serveur interne de référence du paquet d'ancrage (`test/ancrage-tsa-interne-*.test.js`, `test/enregistreur-ancrage-exigences.test.js`, `test/enregistreur-ancrage-parcours.test.js`) ; TM-18 (AN-26) et TM-19 (AN-24) en §11 pour les exigences mesurables, sur les mêmes essais et dans le rapport de la campagne de l'étape 5. |
| TC-26 | CT-5 §7.2 (l. 1689) | Épreuve de redémarrage du serveur interne (AN-26). | TI-17 (§8) et TM-18 (AN-26) en §11, exécutables depuis l'étape 5 : quatre jetons avant et quatre après un redémarrage du serveur interne (compteur de série durable), numéros strictement croissants, et le relevé `an26_serie_croissante` de la campagne (dix jetons, redémarrage, dix jetons) ; TM-19 (AN-24). |
| TC-27 | CT-5 §9.3 (l. 3962) | Capture d'une ancre de point (EX-9.9) : 123 761 octets pour une transaction d'un bloc plein de 64 ancres, mesure TM-31 de CT-9 du 2026-11-02 (109 479 octets de réponses JSON-RPC et 14 282 octets d'index). | TM-31 (§11, ligne `b_cap_bloc_plein` et `notes` du rapport du 2026-11-02) ; bloc plein qui mêle des clôtures : TM-44 (à écrire, étape 8). |
| TC-28 | CT-5 §14 (l. 4461) | Même test que l'occurrence de §5.3 : relève par le secours qualifié après retrait de `qualified` (EX-5.9). | TI-16 (§8), exécutable depuis l'étape 5 (`test/ancrage-composant-pannes.test.js` : relève de la clôture par le secours qualifié tant que la configuration n'est pas rechargée ; rechargement sans principal qualifié refusé) ; mesures en charge du planificateur : TM-17 (§11). |
| TC-29 | CT-5 §14 (l. 4463) | Tests EX- et AN-1 à AN-61, mesures P-1 à P-6, épreuve à l'aveugle. | §6, §7, §8 (TI-16, TI-17), §9 (TE-12), §11 (TM-10 à TM-19), §12 (TR-4, TR-5) ; état « proposition » levé par ce document. |
| TC-30 | CT-6 §0 (l. 70) | Rattachement aux EX-. | §5.1, règle (a). |
| TC-31 | CT-6 §1 (l. 218) | EX-, T-, O-, R-, N-, V-, vecteurs `ct-6`. | §6 (TU- jeton, preuve, registre), §7 (TV- de `ct-6`, dont V-1 à V-10). |
| TC-32 | CT-6 §6.9 (l. 1863) | Exécution des V- par comparaison du rapport à `attendu.json`. | TV- `ct-6/dossiers/` (§7) : oracle = rapport comparé à `attendu.json`. |
| TC-33 | CT-7 §0.1 (l. 59) | Rattachement aux EX-. | §5.1, règle (a). |
| TC-34 | CT-7 §0.2 (l. 176) | Revue de code de l'enregistreur, périmètre fixé par CT-7 (3.2, 3.4). | §13 (TQ- enregistreur). |
| TC-35 | CT-7 §0.3 (l. 279) | Ce que l'auteur de CT-9 lit dans CT-7. | Ce document ; annexe A. |
| TC-36 | CT-7 §1 (l. 287) | Un test par menace. | §10 : un TA- par menace, TA-1 à TA-98, même numéro que la menace (EX-10.1) ; cinq scénarios TA-99 à TA-103 (§10.5). |
| TC-37 | CT-7 §1 (l. 312) | Revue de code. | §13 (TQ-). |
| TC-38 | CT-7 §1 (l. 328) | Colonne « Test de CT-9 » de 3.4. | TR-6, TR-7, TR-8 (les trois épreuves de la section 9) en §12 ; un TA- par menace (§10, table 10.4 imprimée depuis `catalogue.json`) ; CR-, AT-, RV-, MX- et vecteurs ct-7 : TV- (§7), TU- (§6). |
| TC-39 | CT-7 §1 (l. 328) | Colonne « Test de CT-9 » de 3.4. | TR-6, TR-7, TR-8 (les trois épreuves de la section 9) en §12 ; un TA- par menace (§10, table 10.4 imprimée depuis `catalogue.json`) ; CR-, AT-, RV-, MX- et vecteurs ct-7 : TV- (§7), TU- (§6). |
| TC-40 | CT-7 §3.1 (l. 420) | Le test que CT-9 doit écrire (colonnes de 3.4). | EX-10.2 : le membre `threat_test_text` de chaque TA- est la cellule « Test de CT-9 » de 3.4 ; l'oracle du TA- la précise. |
| TC-41 | CT-7 §3.1 (l. 431) | Critère : le test échoue si la réponse est retirée. | EX-10.1, EX-10.3 : réponse retirée nommée (`response_removed`), mutant tué ; §10.8 pour les mutants exécutés le 2026-11-01. |
| TC-42 | CT-7 §3.4 (l. 674) | Préfixe fixe de la colonne. | EX-10.2 : `threat_test_text` commence par ce préfixe fixe (contrôlé par le schéma). |
| TC-43 | CT-7 §3.4 (l. 714) | Les tests de MN-22 et MN-9 valent pour l'agent. | TA-22 et TA-9 (phase 2, étapes 8 et 4) ; scénario TA-99 (§10.5). |
| TC-44 | CT-7 §3.4 (l. 736) | En-tête de la table 3.4. | §10 ; index des TA- par menace (annexe A). |
| TC-45 | CT-7 §3.8 (l. 1117) | Cellule « Test de CT-9 » = membre `test` privé du préfixe. | EX-10.2 : le catalogue lit `menaces.json`, jamais la table du texte ; l'outil de couverture compare `threat_test_text` au membre `test`. |
| TC-46 | CT-7 §4.1 (l. 1230) | Inventaire CLE- à jour, contrôlé par la revue de CT-9. | TQ- inventaire des clés (§13). |
| TC-47 | CT-7 §7.9 (l. 2950) | Parité de l'attestation : exigences mesurées par CT-9 (EX-7.18). | TM-20 (EX-7.18, six points constatés sur les vecteurs, exécutable) en §11. |
| TC-48 | CT-7 §7.9 (l. 2959) | Test sur tous les rapports des vecteurs : aucun « prouvé » appliqué au périmètre. | TV- `ct-6/dossiers/` (§7), exécutable : `test/verificateur.test.js`, it « EX-7.3 de CT-6, EX-7.18 point 3 de CT-7 : aucun texte des rapports n'applique « prouvé », … ». |
| TC-49 | CT-7 §7.10 (l. 2976) | Tests des menaces de l'attestation MN-78 à MN-91, MN-98. | TA-78 à TA-91 et TA-98 (§10.4) : tous exécutables sauf TA-88 (phase 2, étape 4, après PA-10). |
| TC-50 | CT-7 §10 (l. 3860) | Revue de code, non faite. | §13 (TQ-), état « à écrire », étape 8. |
| TC-51 | CT-7 §A.11 (l. 4324) | Menaces reliées à un test déjà possible (vecteurs de CT-1 à CT-6). | §10.4 : état « exécutable » avec le fichier et le titre exact du test du dépôt (règle de couverture (d), EX-5.4). |
| TC-52 | CT-7 §A.11 (l. 4325) | Les autres tests sont écrits par CT-9. | §10.4 : états « à écrire » (étape de la phase 2 et blocage nommés) ou « exécutable » avec complément à écrire ; chaque entrée a ses préconditions, ses pas et son oracle. |
| TC-53 | CT-8 « en-tête » (l. 24) | Convention « à mesurer (CT-9, porte 2) ». | §11 : chaque cible « à mesurer (CT-9, porte 2) » a sa ligne TM-21 à TM-40 avec cible, source et seuil d'échec ; colonne mesure vide en 0.1 (EX-11.16). |
| TC-54 | CT-8 « en-tête » (l. 35) | Critère du plan (moins d'une journée) mesuré à la porte 2. | TM-22 (durée de chaque pas IC-1 à IC-18, durée totale, attente relevée à part) et TM-23 (informations manquantes). |
| TC-55 | CT-8 « en-tête » (l. 37) | Ce que CT-9 chronomètre (EX-8.1). | TM- EX-8.1 (§11). |
| TC-56 | CT-8 §0.1 (l. 56) | Rattachement aux EX-. | §5.1, règle (a). |
| TC-57 | CT-8 §0.1 (l. 81) | Convention « cible ». | §2 (terminologie) et §11.4 : une cible devient une mesure par un rapport de mesure (EX-11.11) sur le système de référence (EX-11.1). |
| TC-58 | CT-8 §0.2 (l. 258) | Ordre d'écriture (traçabilité TC-104 de CT-8). | Ce document ; aucune réponse attendue. |
| TC-59 | CT-8 §0.3 (l. 281) | Ce que l'auteur de CT-9 lit dans CT-8. | Ce document ; annexe A. |
| TC-60 | CT-8 §1 (l. 342) | Périmètre. | Ce document. |
| TC-61 | CT-8 §1 (l. 356) | Onze familles, budgets, cibles, vecteurs `ct-8`, épreuves §14. | Mesures de la porte 2 : TM-21 à TM-40 (§11) ; épreuves de §14 : TR-9, TR-10, TR-11 (§12) ; EX-, CO-, IP-, IR-, IC-, DM-, SV-, PV-, CA-, OB-, PR- et vecteurs ct-8 : TV- (§7), TE- (§9). |
| TC-62 | CT-8 §2 (l. 365) | Budget de temps chronométré par CT-9. | TM-21 (IR-1 à IR-8) et TM-22 (IC-1 à IC-18) : chaque pas chronométré contre son budget, la somme contre la cible (EX-11.3, méthode `chronometre`). |
| TC-63 | CT-8 §3.3 (l. 490) | Épreuve de construction : volume nommé neuf. | TE- construction des images (§9), étape 7. |
| TC-64 | CT-8 §3.4 (l. 593) | Cible : pose de l'attribut immuable sous 60 s. | TM-26 (compagnon : pose des attributs ≤ 60 s). |
| TC-65 | CT-8 §3.4 (l. 602) | Épreuve de construction : compagnon, ouverture en lecture. | TE- construction des images (§9). |
| TC-66 | CT-8 §3.5 (l. 621) | Cible : TTL DNS ≤ 30 s. | TM-27 (TTL DNS du répartiteur ≤ 30 s). |
| TC-67 | CT-8 §3.6 (l. 639) | Mesure : égalité de deux constructions des images. | TM-28 (égalité des condensés de deux constructions). |
| TC-68 | CT-8 §3.6 (l. 661) | Revue de code et RA-22. | TQ- chaîne de construction et de publication (§13). |
| TC-69 | CT-8 §4.4 (l. 1651) | Épreuves de construction : images, `docker compose up`, `docker inspect`. | TE- construction des images (§9). |
| TC-70 | CT-8 §5.3 (l. 1761) | Épreuve d'intégration ICAP. | TI-19 (mode ICAP, §8) : serveur ICAP et épreuve avec Squid (ssl-bump) livrés à l'étape 4. |
| TC-71 | CT-8 §6.2 (l. 1858) | Seuils « cible » du contrôle préalable. | TM-29 (seuils cibles IP-2, IP-3 confrontés à la consommation observée). |
| TC-72 | CT-8 §7.1 (l. 2324) | Chronométrage IR-1 à IR-8 (900 s). | TM-21 (900 s, pas par pas, chaque durée publiée atteinte ou non) ; TR-9 ; critère de la porte 2 « installation par une personne extérieure en 15 min » (§14). |
| TC-73 | CT-8 §7.2 (l. 2502) | Mesure : taille des images téléchargées. | TM-24 (taille des images et durée du téléchargement, relevées à part du budget d'IR-6). |
| TC-74 | CT-8 §8.1 (l. 2575) | Titre « Durée et ce que CT-9 mesure ». | §11 : TM-22, TM-23 ; TE- d'A pour les verdicts du contrôle préalable final et du premier dossier. |
| TC-75 | CT-8 §8.1 (l. 2587) | Le système de référence est fixé par CT-9. | EX-11.1 (système de référence fixé en §11.1) ; TM-22 (durées), TM-23 (informations manquantes) ; verdicts IC-14 et IC-15 : TE-. |
| TC-76 | CT-8 §8.1 (l. 2587) | Le système de référence est fixé par CT-9. | EX-11.1 (système de référence fixé en §11.1) ; TM-22 (durées), TM-23 (informations manquantes) ; verdicts IC-14 et IC-15 : TE-. |
| TC-77 | CT-8 §8.3 (l. 2677) | Coefficients `f_pic`, `b_o`, `n_crl`, `b_crl` avant les mesures. | TM-33 (f_pic, b_o, b_acq, b_crl, n_crl) et TM-9 (m_0) ; IC-1 refait après mesure. |
| TC-78 | CT-8 §8.3 (l. 2700) | Script de préparation de l'hôte éprouvé sur le système de référence. | Le script de préparation de l'hôte est éprouvé pendant TM-22 (IC-2) sur le système de référence d'EX-11.1 ; TE- (§9). |
| TC-79 | CT-8 §8.3 (l. 2920) | Attente d'IC-16 et IC-17 relevée à part. | TM-22 : ligne `ic_attente_cloture` relevée à part, dans la durée totale, hors de la durée du pas IC-15. |
| TC-80 | CT-8 §8.3 (l. 2949) | Durées reportées pour CT-9 (procès-verbal IC-18). | TM-22 : les durées du procès-verbal d'IC-18 sont la source des lignes `ic_1` à `ic_18` et `ic_total`. |
| TC-81 | CT-8 §9 (l. 2983) | Débit et latence de CT-2 §16.1 à mesurer. | TM-1 à TM-4 (cibles de CT-2 §16.1) en §11. |
| TC-82 | CT-8 §9.2 (l. 3032) | EX-9.1 : chaque coefficient a une source citée ou est marqué « à mesurer (CT-9) ». | Coefficients marqués « à mesurer (CT-9) » : TM-30 (`b_ots` mis à niveau), TM-32 (`blocs_par_s` en production), TM-33 (`f_pic`, `b_o`, `b_acq`, `b_crl`, `n_crl`) et TM-9 (`m_0`) ; `b_cap` a pour source la mesure TM-31 (§11). |
| TC-83 | CT-8 §9.2 (l. 3051) | `b_ots` preuve mise à niveau. | TM-30 (octets d'une preuve .ots mise à niveau). |
| TC-84 | CT-8 §9.2 (l. 3052) | `b_cap` = 123 761 octets : mesure TM-31 de CT-9 du 2026-11-02, transaction d'un bloc plein de 64 ancres (109 479 octets de réponses JSON-RPC et 14 282 octets d'index). | TM-31 (rapport `mesures/rapport-2026-11-02-capture-bloc-plein.json` : ligne `b_cap_bloc_plein`, index relevé dans `notes`) ; réserve du bloc plein qui mêle des clôtures : TM-44 (à écrire, étape 8). |
| TC-85 | CT-8 §9.2 (l. 3055) | `blocs_par_s` en production. | TM-32 (blocs_par_s sur l'instance de production). |
| TC-86 | CT-8 §9.2 (l. 3057) | Six coefficients sans valeur par défaut à mesurer : `f_pic`, `b_o`, `b_acq`, `b_crl`, `n_crl`, `m_0`. | TM-33 (`f_pic`, `b_o`, `b_acq`, `b_crl`, `n_crl`) et TM-9 (`m_0`). |
| TC-87 | CT-8 §9.3 (l. 3152) | `m_0` à mesurer. | TM-9 (mémoire sous charge comparée à M_tamp). |
| TC-88 | CT-8 §9.3 (l. 3157) | Mesure de la mémoire au-delà de `M_tamp`. | TM- mémoire (§11). |
| TC-89 | CT-8 §10 (l. 3418) | Seuils d'alerte cibles. | TM-34 (seuils d'alerte cibles : faux positifs et faux négatifs). |
| TC-90 | CT-8 §10.6 (l. 3669) | Seuil mempool `<M>`. | TM-35 (seuil <M> de la mempool). |
| TC-91 | CT-8 §10.11 (l. 3782) | Durées des runbooks non mesurées. | TM-36 (durées de RB-1 à RB-8, publiées sans cible). |
| TC-92 | CT-8 §10.11 (l. 3817) | Un test de CT-9 par correction d'incident. | §3.2 (règle d'ajout d'une entrée) ; TE- runbooks (§9), oracle. |
| TC-93 | CT-8 §11 (l. 4193) | RPO et RTO cibles. | TM-37 (RPO et RTO par composant, exercices de restauration). |
| TC-94 | CT-8 §11.2 (l. 4251) | Fréquence de sauvegarde de l'état du service (15 min). | TM-37 : ligne `sauvegarde_etat_service_cadence` (cible 15 min). |
| TC-95 | CT-8 §11.3 (l. 4285) | Table RPO/RTO : cibles à mesurer. | TM-37 (table d'EX-11.5, toutes les cibles sauf la borne du bail). |
| TC-96 | CT-8 §11.10 (l. 4668) | Journal d'accès des supports WORM : disponibilité et format vérifiés en CT-9. | TM-39 (journal d'accès du support WORM : disponibilité et format par fournisseur). |
| TC-97 | CT-8 §12.2 (l. 4889) | Latence en mode observation. | TM-38 (latence ajoutée en mode observation, paire avec et sans). |
| TC-98 | CT-8 §12.2 (l. 4901) | Durée d'écriture lente, cible de CT-2 §16.1. | TM-38 : ligne `observation_ecriture` (durée d'écriture, cible de CT-2 §16.1). |
| TC-99 | CT-8 §13.1 (l. 5355) | Parité du paquet réviseur mesurée par CT-9 (EX-13.1). | TM-25 (point 7) en §11 ; points 1 à 6 : TV- ct-8/paquets/ (§7) et TR-10 (§12). |
| TC-100 | CT-8 §13.1 (l. 5387) | Temps du réviseur < 30 min. | TM-25 (temps du réviseur < 30 min), relevé pendant TR-10. |
| TC-101 | CT-8 §14 (l. 6999) | Conduite des trois épreuves de CT-8 §14. | TR-9, TR-10, TR-11 en §12, conduites selon le protocole commun de 12.1. |
| TC-102 | CT-8 §14.2 (l. 7102) | Durée de l'épreuve (b), mesure de CT-9. | EX-12.4 : consignation `consignation_rejeu` (schéma, §12.1), CT-8 EX-14.10 généralisée à toutes les épreuves TR-. |
| TC-103 | CT-8 §14.2 (l. 7104) | Consignation EX-14.10 par CT-9. | §12.1 (protocole commun) : consignation champ par champ. |
| TC-104 | CT-8 §15 (l. 7136) | Conformité des images à leur description : épreuve de construction. | TE- construction des images (§9). |
| TC-105 | CT-8 §15 (l. 7152) | Script de préparation éprouvé sur le système de référence. | EX-11.1 : système de référence de la porte 2 fixé en §11.1. |
| TC-106 | CT-8 §15 (l. 7153) | Système de référence fixé par CT-9. | §11.1. |
| TC-107 | CT-8 §15 (l. 7176) | Cibles des sections 10 à 12 à mesurer. | TM-37 (RPO, RTO, restauration), TM-38 (latence en observation), TM-35 (mempool) en §11. |
| TC-108 | CT-8 §15 (l. 7184) | Journal d'accès des supports : CT-9 l'établit. | TM-39 (journal d'accès par fournisseur) établit la source `journal_acces_support` avant que CT-8 EX-11.19 la tienne pour acquise. |
| TC-109 | CT-8 §15 (l. 7213) | Budgets IR et IC à mesurer. | TM-21 (900 s) et TM-22 (450 min, 480 avec la réserve) en §11 ; porte 2 en §14. |
| TC-110 | CT-8 §B.2 (l. 8150) | Ordre des champs de `chronyc -c tracking` à relever. | TM-40 (ordre des champs de chronyc -c tracking relevé sur chrony 4.6). |
| TC-111 | CT-8 §B.4 (l. 8205) | Latence en observation. | TM-38 (latence en observation). |
| TC-112 | CT-8 §B.5 (l. 8253) | Temps du réviseur. | TM-25 (temps du réviseur). |
| TC-113 | `spec/README.md` « Spécifications » (l. 23) | Ligne d'état de CT-9 dans la table des spécifications (version 0.3, révisions 0.3 et 0.2, contenu, figée en conception v1.0). | Ce document (en-tête) ; rien n'est délégué. |
| TC-114 | `spec/README.md` « Spécifications » (l. 23) | Ligne d'état de CT-9 dans la table des spécifications (version 0.3, révisions 0.3 et 0.2, contenu, figée en conception v1.0). | Ce document (en-tête) ; rien n'est délégué. |
| TC-115 | `spec/README.md` « Spécifications » (l. 26) | Ordre d'écriture des neuf spécifications : CT-9 en dernier. | Ce document, dernière spécification de la phase 1 ; rien n'est délégué. |
| TC-116 | `spec/README.md` « Schémas (`schemas/`) » (l. 71) | Description du schéma `plan-de-tests-v0` : catalogue, rapport de couverture, rapport de mesure, consignation. | §4.2 (schéma), §5.4 (rapport de couverture), §11.3 (rapport de mesure), §12.1 (consignation) ; annexe A.2. |
| TC-117 | `spec/README.md` « Schémas (`schemas/`) » (l. 71) | Description du schéma `plan-de-tests-v0` : catalogue, rapport de couverture, rapport de mesure, consignation. | §4.2 (schéma), §5.4 (rapport de couverture), §11.3 (rapport de mesure), §12.1 (consignation) ; annexe A.2. |
| TC-118 | `spec/README.md` « Schémas (`schemas/`) » (l. 71) | Description du schéma `plan-de-tests-v0` : catalogue, rapport de couverture, rapport de mesure, consignation. | §4.2 (schéma), §5.4 (rapport de couverture), §11.3 (rapport de mesure), §12.1 (consignation) ; annexe A.2. |
| TC-119 | `spec/README.md` « Schémas (`schemas/`) » (l. 71) | Description du schéma `plan-de-tests-v0` : catalogue, rapport de couverture, rapport de mesure, consignation. | §4.2 (schéma), §5.4 (rapport de couverture), §11.3 (rapport de mesure), §12.1 (consignation) ; annexe A.2. |
| TC-120 | `spec/README.md` « CT-9 (`vecteurs/ct-9/`) » (l. 452) | Titre de la section des vecteurs `ct-9/`. | Annexe A.1 (disposition de `spec/vecteurs/ct-9/`). |
| TC-121 | `spec/README.md` « CT-9 (`vecteurs/ct-9/`) » (l. 454) | Renvoi à l'annexe A pour la disposition des vecteurs. | Annexe A.1 ; générateur et déterminisme : EX-A.1. |
| TC-122 | `spec/README.md` « CT-9 (`vecteurs/ct-9/`) » (l. 454) | Renvoi à l'annexe A pour la disposition des vecteurs. | Annexe A.1 ; générateur et déterminisme : EX-A.1. |

### 0.3 Qui lit quoi

| Lecteur | Lit | Y trouve |
|---|---|---|
| Implémenteur d'un composant (phase 2) | 3, 4, 6 à 9, annexe A | les tests exécutables qu'il doit garder verts, les tests « à écrire » rattachés à son étape, leurs oracles exacts, la forme d'une entrée du catalogue |
| Auteur d'un test | 3, 4, 5, 15 (auteur du dépôt ; jamais un participant d'une épreuve) | les règles de chaque famille, la structure d'une entrée, les règles de couverture que l'outil applique, l'épreuve (c) qui vérifie qu'il peut ajouter une entrée seul |
| Responsable de la sécurité | 10, 13, 14 | le test adversarial de chaque menace, la grille de revue, ce que la porte 2 prouve |
| Relecteur de la porte 2 | 14, 16, 5.4, annexe A.12 | chaque critère « continuer si » et « arrêter si » avec ses tests et son verdict calculable ; ce que la porte 2 ne mesure pas ; les sources des verdicts (rapport de couverture, 5.4 ; rapport d'exécution, EX-A.19) |
| Auteur d'une autre spécification | 0.2, 1, 17 | la réponse à chacun de ses renvois et les propositions PD- qui lui sont adressées |
| Auteur d'un test adversarial | 10, annexe A.6 | pour chaque menace, la réponse retirée, l'attaque, l'observation attendue avec et sans la réponse ; la fabrique de mutants ; ce que les risques acceptés laissent hors de test |
| Ingénieur chargé des mesures de la porte 2 | 11, 14, annexe A.7 | le système de référence, la méthode, le schéma du rapport, la cible et le seuil d'échec de chaque grandeur, les lignes du rapport à produire |
| Examinateur des épreuves à l'aveugle | 12, 15, annexe A.8, A.9 | le protocole commun, le matériel à remettre et les sections à retirer, la grille à ne pas remettre, la consignation à remplir ; aucun participant ne lit 15, et les participants de TR-1 à TR-12 ne lisent pas 12 |

La section 15 décrit les épreuves à l'aveugle propres à CT-9 : elle n'est remise
à aucun participant. La section 12 n'est pas lue par les participants de TR-1 à
TR-12 ; les participants de TR-13 à TR-15 reçoivent CT-9 sans la section 15,
section 12 comprise, parce que TR-12 peut être tiré en (a) et que la ligne 2 de
la porte 2 renvoie à 12.3 (EX-12.3). Les grilles des vecteurs
(`acceptation-*-attendu.json`) ne sont jamais recopiées dans le texte remis. Les
renvois des sections 0 à 14 à la section 15 (0.3, 5.1, EX-4.6) ne portent aucune
règle : ce qu'un auteur d'entrée applique est en 3, 4 et 5.

### 0.4 Révisions

**Révision 0.4** (2026-11-10, fermeture de l'étape 5 de la phase 2 :
composant d'ancrage `paquets/ancrage` et son branchement dans
`paquets/enregistreur` ; alignement sur CT-5 (0.5) et CT-6 (0.5)). Aucune
règle n'est ajoutée ni retirée. Inventaire (5.2) : versions de CT-5 et de
CT-6 ; seule CT-6 ajoute des identifiants, EX-A.25 et EX-A.26 (vecteurs de sa
révision 0.5), et passe de 278 à 280 ; aucune n'en retire. Couverture (règle
(a)) : les deux sont couverts par les entrées qui éprouvent déjà ces
vecteurs, précisées (EX-4.6) : TV-48 (EX-A.25 : jetons
`t1-cle-longueur-non-minimale` et `t1-extension-mal-formee`, quarante et un
cas d'`attendu.json`), TV-49 (EX-A.26 : `o1-attestation-en-double.ots`),
TV-54 (sorties republiées de la confrontation) et TV-55 (binaire Go). Entrées
passées exécutables (EX-3.12) : TI-16 (autorités RFC 3161 et calendriers
OpenTimestamps publics, `min_interval_ms`, relève par le secours après
retrait de la qualification ; complément : prestataire qualifié réel, étape
8), TI-17 (serveur RFC 3161 interne, AN-22 à AN-31 et redémarrage), TE-12
(ancrage complet d'une racine, hors réseau public et sur le réseau de
développement), TE-14 (journal de l'enregistreur sur lui-même ; complément :
rotation de la clé de chaîne relayée au registre, étape 7) et TA-41 (secrets
par référence, sur le démon et le composant ; complément : mutant du
composant, étape 8) ; TE-16 (matrice des pannes de CT-2 §14.2), rattachée à
l'étape 4 faute de signataires des classes A à C et du composant d'ancrage,
tous deux livrés depuis, passe exécutable sur l'essai de la ligne « clé
indisponible » rejouée sur le démon réel et sur les essais du paquet qui
éprouvent les autres lignes une à une, dont « Disque presque plein » et
« Mémoire » (bornes de l'attente) sur le chemin du relais ; complément à
l'étape 8 : rejeu de la matrice entière sur le démon réel fini par des
dossiers vérifiés ; mesures TM-11 à TM-14, TM-17 à TM-19, TM-30, TM-41 et
TM-42 par la campagne de `scripts/e2e/mesure-ancrage.mjs` (collecte,
compléments, rapport), dont le rapport `mesures/rapport-2026-11-10-ancrage.json`
est relu par `test/plan-de-tests.test.js` (TM-18 et TM-19 aussi par les
essais du serveur interne), avec leurs compléments à l'étape 8 : charge de
TM-3 (TM-11, TM-41), prestataire qualifié réel (TM-14), relevé en temps réel
(TM-17), mise à niveau réelle par les calendriers publics (TM-30) ; complément
`ancres/` de TM-16 écrit. Rattachements reportés, chacun motivé dans
`blocking` : le complément de TA-62 (mutant de la relève sur le composant
livré, dont la partie positive est désormais éprouvée) et celui de TA-41, à
l'étape 8, possibles dès maintenant et non écrits ; aucune entrée ni aucun
complément ne reste rattaché à l'étape 5. Lecture des titres (EX-5.6, EX-4.2,
correction de l'outil) : une interpolation `${…}` d'un gabarit est lue comme
une expression, gabarits imbriqués compris ; `test/enregistreur-journal-soi.test.js`,
dont un gabarit imbriqué porte `\}`, n'était lu par aucun des trois lecteurs
(outil de couverture, vérificateur Go, confrontation), qui suivent tous trois.
Traçabilité (0.2) : 122 occurrences de « CT-9 », inchangées, numéros
« (l. N) » relus sur CT-5 et CT-6 révisées ; réponses aux occurrences de CT-5
§3.6, §5.3, §7.2 (deux) et §14 (deux) alignées sur les entrées passées
exécutables. Rapport de mesure (11.3) : lignes supplémentaires du rapport de
l'étape 5 nommées (EX-11.11). Le catalogue garde 322 entrées (`spec_version`
0.4) ; `test/plan-de-tests.test.js` suit. Sections touchées : en-tête, 0.1,
0.2, 0.4, 5.2, 5.5, 7 (table TV), 8 (introduction, table TI), 9 (table TE),
10.4 (table TA et lecture par état), 10.6, 11 (EX-11.12, 11.3, EX-11.16,
table TM), 14, 16, A.4 et A.5 (EX-A.10). Aucune spécification CT-1 à CT-8 n'est
modifiée par cette révision.

**Révision 0.3** (2026-11-03, alignement sur les révisions du même jour de
CT-1 (0.5), CT-4 (0.5), CT-5 (0.3), CT-6 (0.4), CT-7 (0.2) et CT-8 (0.2)).
Aucune règle n'est ajoutée ni retirée. Inventaire (5.2) : versions des six
spécifications révisées ; seule CT-6 ajoute des identifiants, seize EX-
(EX-4.16, EX-4.17, EX-5.13 à EX-5.20, EX-6.22, EX-9.23, EX-9.24, EX-A.22 à
EX-A.24), et passe de 262 à 278 ; aucune n'en retire. Couverture (règle (a))
: les seize sont couverts par des entrées existantes, précisées (EX-4.6) :
TU-15 (EX-9.23, EX-9.24), TV-7 (EX-4.16, EX-5.13, EX-5.16 à EX-5.19, par les
dossiers de la révision 0.5 de CT-1 rejoués par le vérificateur de CT-6),
TV-48 (EX-A.22), TV-52 (EX-4.16, EX-4.17, EX-5.14, EX-5.15, EX-5.20, EX-6.22,
EX-A.23, EX-A.24) et TV-55 (les seize, sur le binaire Go). TA-61 et TA-68 :
`covers` suit `response.refs` de `menaces.json` (EX-10.2 : CT-6 T-4,
EX-9.10 et EX-9.24 ; EX-9.23), la réponse retirée nomme ces règles, et
leurs mutants, à écrire, sont un complément (étape 8). Mesures : TM-31 suit
la mesure du 2026-11-02 que CT-8 révision 0.2 reprend (`b_cap` = 123 761
octets, index compris) ; TM-44, nouvelle et à écrire (étape 8), mesure la
capture d'un bloc plein qui mêle des clôtures (réserve de CT-8 §9.2) ; TV-66
relit `b_cap` dans le rapport de TM-31. Traçabilité (0.2) : 122 occurrences
de « CT-9 », cinq lignes TC- nouvelles (CT-1 §17, deux ; CT-4 §9.2 ; CT-4
§B.1 ; CT-5 §9.3), lignes renumérotées dans l'ordre des fichiers et des
lignes (EX-12.8 renvoie donc à TC-80, et non à TC-75), numéros « (l. N) »
relus sur les textes révisés ; réponses aux occurrences de CT-8 §9.2
(EX-9.1, `b_cap`, six coefficients sans valeur par défaut), de CT-5 §14 et
de la ligne de CT-9 de `spec/README.md` alignées.
Corrections : EX-7.1 renvoie à TV-52, et non à TV-53, et à CT-6 §6.9 ; la
lecture par état de 10.4 compte 79 TA- exécutables, dont 75 avec leurs
mutants dans `test/adversarial.test.js`. Le catalogue passe à 322 entrées
(`spec_version` 0.3) ; `test/plan-de-tests.test.js` suit. Sections touchées :
en-tête, 0.1, 0.2, 0.4, 5.2, 5.5, 6 (table TU), 7 (EX-7.1, table TV), 10.4
(table TA et lecture par état), 11 (introduction, EX-11.12, EX-11.16, table
TM, 11.6), 12 (EX-12.8) et 16. Aucune spécification CT-1 à CT-8 n'est
modifiée par cette révision.

**Révision 0.2** (2026-11-03, fermeture de l'étape 4 de la phase 2 :
démon enregistreur `paquets/enregistreur`, service d'approbation
`paquets/approbation`, SDK `paquets/sdk-js` et `paquets/sdk-python`).
Règles : EX-10.5 admet pour mutant une copie du paquet d'un composant de la
phase 2 (`paquets/<nom>`), dont `node_modules/` est un lien vers le dépôt ;
EX-10.3 dit qu'une exécution `phase_2` se joue sur un composant de la phase
2, attendu ou livré ; EX-A.8 et EX-A.11 suivent. Entrées passées
exécutables (EX-3.12) : TI-3 (client MCP de référence à travers le frontal),
TI-13 (SDK Python et TypeScript), TI-19 (mode ICAP derrière un Squid réel
avec ssl-bump, image `squid-openssl` construite et épinglée), TE-11 (bascule
du bail ; le défaut D-1 du démon que son test avait révélé est corrigé,
lecture 188 du LISEZMOI de `paquets/enregistreur`), TA-2, TA-8, TA-9, TA-12, TA-19, TA-24,
TA-26 (partie non conditionnée par PA-1) et TA-30 sur le démon (mutants du
paquet) ; compléments des TA-7, TA-10 et TA-11 écrits ; TM-16 exécutable
sur le support WORM en conteneur, son rapport de campagne publié
(`mesures/rapport-2026-11-03-p6-worm.json`), complément `ancres/` à l'étape
5. Rattachements corrigés, chacun motivé dans `blocking` : TA-41 et TE-14 à
l'étape 5, le complément de TA-62 à l'étape 5 (composant d'ancrage) ; le
complément de TA-14, TA-93 et les mesures de performance TM-1 à
TM-5, TM-7 à TM-9 et TM-38 à l'étape 8 (table 3.4). Restent rattachées à
l'étape 4, la livraison disant pourquoi elles ne passent pas (EX-3.12) :
TE-16, TA-31 et TA-33
(signataires des classes A, B et C non livrés) et TA-88 (PA-10). Corrections
d'entrées : l'attendu de TA-2 (CT-2 EX-17.2 ne nomme `delegation_refused`
que pour `run_id` et `on_behalf_of`), celui de TA-10 (l'événement de reprise
porte `execution.status` `executee`, CT-2 EX-12.14), l'oracle de TI-13 (la
table d'EX-6.7 est celle des issues de politique ; une panne rend les
exceptions d'EX-6.12) ; section 14 et section 16 alignées. Aucune
spécification CT-1 à CT-8 n'est modifiée.

## 1. Objet, périmètre et relations

CT-9 dit ce qui est testé, comment, avec quel oracle et à quel moment, pour
tout ce que CT-1 à CT-8 spécifient : il fixe huit niveaux de tests et leurs
règles (section 3), la forme lisible par machine du catalogue (section 4),
les règles de couverture et l'outil qui les vérifie (section 5), les tests
de chaque niveau (sections 6 à 13), la correspondance avec la porte 2
(section 14) et ses propres épreuves à l'aveugle (section 15). Il n'écrit
aucun test dans son texte : le texte décrit, le catalogue porte, le dépôt
exécute.

Hors périmètre : le comportement des composants (CT-2 à CT-5), les formats
(CT-1), le vérificateur (CT-6), la sécurité et la conformité (CT-7), le
déploiement (CT-8), que CT-9 teste sans les redéfinir ; les tests des
contrats et des outils antérieurs aux spécifications (`test/deploy.test.js`,
`test/periodRegistry.test.js`, `test/recorderRegistry.test.js`,
`test/thresholdSignatures.test.js`, `test/certificatCommit.test.js`), que
CT-9 rattache sans les réécrire ; l'exécution du binaire noorcore hors de
`chain/scripts/dev-net.sh` ; toute qualification juridique.

Dans la colonne « Ce que CT-9 en prend », les identifiants sont ceux de la
spécification de la ligne.

| Spécification | Ce que CT-9 en prend | Ce que CT-9 lui donne ou lui demande |
|---|---|---|
| CT-1 | Les vérifications D-, E-, C-, M-, P-, A-, K-, AT- de §11.4, les vecteurs `ct-1`, les correspondances d'export de §12, les clés de test de §13 | TU- du noyau (6), TV- de `ct-1` (7), TI- d'export (8) ; propositions PD-1 et PD-2 (§12.2, §12.3) |
| CT-2 | Les EX-, les vecteurs de l'annexe B, la méthode de mesure de §16, la démonstration de §19 | TU-, TV- de `ct-2`, TI- des API, SDK et adaptateurs, TE- de la démonstration et des pannes, TM- de §16.1 (11), seuil de régression (EX-11.15, PD-3, PD-16) |
| CT-3 | EX-, AP-, TK-, SG-, AN-, CS-, les vecteurs `ct-3`, les épreuves A.5 et A.11 | TU-, TV- de `ct-3`, TE- console, TR- des deux épreuves (12) |
| CT-4 | EX-, RG-, OP-, CP-, SU-, les vecteurs `ct-4`, l'épreuve de §7.12 | TU-, TV- de `ct-4`, TE- sur le réseau de développement, TR- de §7.12 ; SU- justifiés hors porte 2 (NC-) |
| CT-5 | EX-, AN-1 à AN-61, P-1 à P-6, les vecteurs `ct-5`, l'épreuve à deux relecteurs, le test « à écrire » de §14 | TU-, TV- de `ct-5`, TI- prestataires et serveur interne, TE- ancrage complet, TM- P-1 à P-6, TR- |
| CT-6 | EX-, T-, O-, R-, N-, V-, K-, AT-, AV-, les vecteurs `ct-6`, §7 « prouve et ne prouve pas » | TU-, TV- de `ct-6` (V- par comparaison du rapport à `attendu.json`), TR- « prouve / ne prouve pas », TQ- vérificateur ; binaire Go de §14 : TV- à écrire |
| CT-7 | La colonne « Test de CT-9 » des 98 menaces (`menaces.json`), CR-, AT-, RV-, MX-, les vecteurs `ct-7`, les trois épreuves de §9, le périmètre de la revue de code (§3.2, §3.4), l'inventaire CLE- | TA- un par menace (10), TV- de `ct-7`, TR- de §9, TQ- (13), TM- EX-7.18 |
| CT-8 | EX-, CO-, IP-, IR-, IC-, TP-, DM-, SV-, RB-, PV-, CA-, OB-, PR-, AV-PR-, les budgets et cibles « à mesurer (CT-9, porte 2) », les vecteurs `ct-8`, les épreuves de §14, EX-8.1 et EX-13.1 | TV- de `ct-8`, TE- installations, runbooks, sauvegarde, construction, TM- de chaque cible (11), TR- de §14 (12), système de référence (11.1) |

## 2. Terminologie

Les termes de CT-1 à CT-8 gardent leur sens ; CT-9 ajoute ceux-ci.

| Terme | Définition |
|---|---|
| Catalogue | Le fichier `spec/vecteurs/ct-9/catalogue.json` (schéma `plan-de-tests-v0`), source unique des tests ; le texte de CT-9 en imprime les tables (4.3). |
| Entrée | Un test du catalogue : identifiant stable, niveau, objet, identifiants couverts, préconditions, étapes, oracle, état, menaces (4.1). |
| Oracle | Ce qui est comparé à quoi pour décider qu'un test passe : une valeur calculée, un fichier attendu des vecteurs, le verdict d'un outil, une grille à part. Aucune définition normative publique n'a été lue (R11-NV2, R11-NV4) : celle-ci est propre à CT-9. |
| État | `executable` : le test existe dans le dépôt et s'exécute par la commande citée ; `a_ecrire` : son objet n'existe pas encore, l'entrée nomme l'étape de la phase 2 qui le livre et ce qui bloque. |
| Étape de la phase 2 | L'une des huit étapes du plan de projet, dans l'ordre de ses dépendances (3.4) ; une entrée « à écrire » en nomme exactement une. |
| Couvert | Un identifiant d'une autre spécification est couvert s'il figure dans le membre `covers` d'au moins une entrée, ou dans une justification NC- (5.1). |
| Réponse retirée | Dans un test adversarial, la règle de sécurité que l'on désactive dans une copie de l'implémentation ou dans la configuration pour montrer que le test échoue sans elle (CT-7 EX-3.2). |
| Système de référence | La machine, le système et les versions sur lesquels toute mesure de la porte 2 est faite (11.1). |
| Grille | Le fichier `acceptation-*-attendu.json` d'une épreuve à l'aveugle, hors du matériel remis, lu par le juge seulement ; pour TR-13 et TR-15, le catalogue et l'outil de couverture. |
| Juge | La personne qui compare la réponse d'un participant à la grille ou à la sortie de l'outil, et qui n'a pas aidé le participant. |
| Titre exact | Le texte source du premier argument d'un `describe` ou d'un `it` de `test/*.test.js`, tel qu'il figure dans le fichier, avant toute interpolation (4.1). |
| Réponse | La colonne « Réponse » d'une menace de CT-7 §3.4, c'est-à-dire les exigences EX- citées par `response.refs` de `menaces.json` (10.1). |
| Mutant | La copie des bibliothèques de référence où une réponse est retirée par un remplacement textuel exact et unique (10.3) ; un mutant est **tué** quand le test de la menace échoue sur lui et passe sur la référence, **survivant** sinon (vocabulaire du test par mutation, R11-F23, R11-F24). |
| Cible, mesure | Une cible est une valeur de conception qu'aucune exécution n'a établie (CT-8 §0.1) ; une mesure est le résultat d'une exécution réelle, publiée dans un rapport de mesure (11.3), atteinte ou non. |
| Seuil d'échec | La condition, écrite dans l'entrée TM-, qui rend la ligne du rapport `met` faux ; il égale la cible sauf réserve écrite par la source (11.4). |
| Épreuve à l'aveugle | Exercice où un participant, qui n'a pris part ni au projet ni à la rédaction de la spécification visée, ne reçoit que le matériel nommé, et dont la réponse est jugée par un juge contre une grille à part ou le verdict d'un outil (12.1). |
| Consignation | L'enregistrement, champ par champ, d'une épreuve (12.1, CT-8 EX-14.10) ; elle ne contient jamais la réponse du participant ni son nom. |

## 3. Niveaux et familles

### 3.1 Huit niveaux

CT-9 range tout test dans l'un de huit niveaux, chacun avec sa famille
d'identifiants, son objet et son oracle. Le niveau ne dit pas la taille du test
mais **d'où vient l'oracle** : une valeur calculée ou une source primaire (TU-),
un fichier des vecteurs publiés (TV-), une implémentation tierce ou l'outil
officiel d'un format (TI-), le verdict du vérificateur de CT-6 sur un dossier
produit par la chaîne entière (TE-), l'observation d'une attaque avec et sans la
réponse (TA-), un rapport de mesure comparé à une cible (TM-), une grille lue
par un juge (TR-), une grille de revue remplie (TQ-). Un même `describe` du
dépôt peut servir deux niveaux : un `it` qui construit son cas en mémoire est un
TU-, celui qui rejoue un fichier des vecteurs est un TV-. La colonne « Objet »
de la table dit où le test s'exerce, la colonne « Oracle » d'où vient son
verdict, et les deux se lisent ensemble : un test à oracle calculé qui exige un
composant de la phase 2 (le démon de l'étape 4, par exemple) n'est pas un TU-,
qui ne teste qu'une bibliothèque du dépôt, mais un TI- ou un TE- selon son
oracle ; une entrée dont les préconditions tiennent en bibliothèque et dont le
`blocking` attend le démon est rangée d'après son `blocking`, c'est-à-dire au
niveau que donne son oracle sur le composant attendu : TE- si l'oracle comprend
le verdict du vérificateur de CT-6 sur un dossier, TI- s'il comprend l'accord
d'un outil tiers ou de l'outil officiel d'un format.

<!-- table niveaux -->
| Niveau | Nom | Objet | Oracle | Section |
|---|---|---|---|---|
| TU- | Unitaires et propriétés | Bibliothèques de référence (`scripts/lib/*`, `console/`, contrats), noyau de CT-1 compris : canonicalisation, hachage, chaînage, Merkle, signatures, formats, et leurs règles en bibliothèque. | Valeur calculée dans le test, source primaire (vecteurs de RFC) ou bibliothèque tierce ; jamais un fichier des vecteurs publiés. | 6 |
| TV- | Conformité aux vecteurs | Chaque famille de `spec/vecteurs/ct-1` à `ct-8`, rejouée par l'implémentation de référence, par le vérificateur Go indépendant et, quand elle existe, par la confrontation tierce ; génération déterministe. | Le fichier attendu de la famille (`attendu.json`, `cas.json`, `expected`), à l'égalité octet pour octet ou au verdict près. | 7 |
| TI- | Interopérabilité | Exports de CT-1 §12, formats d'API et transports de CT-2, SDK et adaptateurs de cadres, OpenTelemetry, canal du service d'approbation, supports WORM, prestataires d'horodatage, registre, ICAP, paquets lus par des outils tiers. | L'implémentation tierce ou l'outil officiel du format accepte ce que NOORTRACE produit, et NOORTRACE accepte ce qu'il produit ; écarts connus consignés. | 8 |
| TE- | Bout en bout | Les deux cas de démonstration du plan et la démonstration de référence, de la capture au dossier vérifié ; installations, runbooks, sauvegarde, observation, haute disponibilité, ancrage complet, console, journal sur soi, construction des images, supervision. | Verdict du vérificateur de CT-6 (deux implémentations) sur les dossiers produits, plus l'observation nommée par chaque entrée. | 9 |
| TA- | Adversariaux | Une entrée par menace MN-1 à MN-98 de CT-7 et les cinq scénarios du plan : la réponse retirée, l'attaque, l'observation avec et sans la réponse. | Le test passe avec la réponse et échoue sans elle (CT-7 EX-3.2). | 10 |
| TM- | Mesures | Cibles de CT-2 §16, CT-5 P-1 à P-6, CT-7 EX-7.18, CT-8 (budgets, cibles, EX-8.1, EX-13.1), fenêtre de réécriture, latence ajoutée. | Rapport de mesure au schéma, sur le système de référence, comparé à la cible et au seuil d'échec ; aucune valeur inventée. | 11 |
| TR- | Rejeu à l'aveugle | Épreuves déléguées par CT-3, CT-4, CT-5, CT-6, CT-7 §9, CT-8 §14, les trois épreuves de CT-9 et le rejeu complet sur machine vierge. | Grille à part ou verdict d'un outil, jugé par une personne qui n'a pas aidé le participant ; consignation CT-8 EX-14.10. | 12 |
| TQ- | Revue de code | Périmètre fixé par CT-7 (composants de §3.2, menaces de §3.4), inventaire des clés, chaîne de construction, indépendance des vérificateurs Go. | Grille remplie : chaque menace du composant a sa réponse localisée et son TA- ; écarts tracés. | 13 |


**EX-3.1** Toute entrée du catalogue DOIT porter exactement un niveau, et
son identifiant DOIT commencer par la famille de ce niveau (`TU-`, `TV-`,
`TI-`, `TE-`, `TA-`, `TM-`, `TR-`, `TQ-`), suivie d'un entier strictement
positif. Les entrées sont groupées par niveau dans l'ordre de la table 3.1
(TU-, TV-, TI-, TE-, TA-, TM-, TR-, TQ-) et, dans chaque niveau, les numéros
se suivent dans l'ordre du catalogue ; aucun n'est réattribué. Une entrée
nouvelle prend le numéro qui suit le plus grand de son niveau et s'insère
après la dernière entrée de ce niveau (une TI- nouvelle après TI-20, avant
TE-1). Une entrée retirée garde son numéro et son état devient `a_ecrire`
avec la raison « retirée » dans `blocking`, jusqu'à la révision suivante qui
la supprime.

### 3.2 Règles de chaque famille

**EX-3.2 (TU-)** Un TU- NE DOIT PAS lire un fichier de `spec/vecteurs/` comme
oracle ; il PEUT en lire comme entrée (un événement, une clé de test). Un
test de propriétés fixe sa graine et son nombre d'exécutions dans le code,
épingle la version exacte de la bibliothèque de génération et consigne tout
contre-exemple par le couple `seed`/`path` qui le rejoue (R11-F17, R11-F18)
; il n'emploie aucune limite de temps (`skipAllAfterTimeLimit`,
`interruptAfterTimeLimit`, `timeout`), qui dépend de la machine.

**EX-3.3 (TV-)** Un TV- rejoue une famille de vecteurs nommée par son chemin
; son oracle est le fichier attendu de la famille ; il DOIT exister au
moins un TV- par famille de `ct-1` à `ct-8` et par mode de rejeu disponible
: implémentation de référence (`describe`/`it`), vérificateur Go
indépendant (étape de `ci.yml`), confrontation tierce (`describe` de
`test/confrontation.test.js`), plus un TV- de génération déterministe par
répertoire `ct-n`. Un vérificateur Go absent (`ct-6`, CT-6 §14) donne un
TV- « à écrire » rattaché à l'étape 2.

**EX-3.4 (TI-)** Un TI- nomme l'implémentation tierce ou l'outil officiel
du format, à version exacte, et dit dans son oracle ce que chacun accepte de
l'autre ; les écarts connus sont écrits dans l'oracle, jamais tus. Une
entrée `executable` porte la version exacte dans `preconditions` ; une
entrée `a_ecrire` (EX-3.10, EX-3.12) nomme l'outil et, pour la version, soit
renvoie à la version épinglée par une spécification nommée (TI-4 à TI-10 :
CT-2 §6.4), soit dit dans `blocking` qu'elle est fixée à la livraison de
l'étape nommée. Les huit intégrations de la porte 2 (OpenAI, Anthropic,
Gemini, LangGraph, CrewAI, LlamaIndex, LiteLLM, OpenTelemetry) ont chacune
leur TI-.

**EX-3.5 (TE-)** Un TE- traverse au moins trois composants et finit par un
dossier (ou un paquet) vérifié par le vérificateur de CT-6 ; son oracle nomme le
code de retour, les contrôles réussis et l'observation propre au parcours. Les
deux cas de démonstration du plan sont TE-1 et TE-2. Un composant, au sens de
cette règle, est l'un de ceux de CT-7 §3.2 ou l'objet d'une étape de la table
3.4 ; « le vérificateur de CT-6 » désigne ses deux implémentations (table 3.1),
le binaire Go livré à l'étape 2 (TV-55).

**EX-3.6 (TA-)** Un TA- nomme la réponse retirée (comment on la retire dans
une copie de l'implémentation de référence ou dans la configuration),
l'attaque jouée, l'observation attendue avec la réponse (le test passe) et
sans elle (le test échoue), et son niveau d'exécution (`vecteurs_et_depot`
ou `phase_2`). Chaque menace MN-1 à MN-98 a au moins un TA- ; la table TA-
par menace (annexe A) le rend lisible. Retirer la réponse est un mutant à
tuer (R11-F23 à R11-F27) : un TA- dont le mutant survit n'est pas un test.

**EX-3.7 (TM-)** Un TM- nomme la grandeur, l'unité, la cible, le mode de
comparaison, la source de la cible (identifiant d'une autre spécification), le
seuil d'échec et la méthode ; sa valeur mesurée vit dans le rapport de mesure,
jamais dans le catalogue (`measured` toujours `null` en 0.1).
`measure.percentiles` nomme le ou les agrégats comparés à la cible par le seuil
d'échec (`max` pour TM-43) ; la ligne du rapport publie, quelle que soit cette
liste, les agrégats qu'EX-11.4 impose à la grandeur (`p50`, `p95`, `p99` et
`max` pour une durée) : publier les quatre et comparer `max` seul est conforme.

**EX-3.8 (TR-)** Un TR- nomme le participant, le matériel remis, les
sections interdites, le fichier de grille (jamais recopié), le juge et la
règle de verdict ; sa consignation suit CT-8 EX-14.10.

**EX-3.9 (TQ-)** Un TQ- nomme les composants de CT-7 §3.2 qu'il couvre, le
périmètre de code et la grille ; son oracle exige que chaque menace du
composant ait sa réponse localisée dans le code et son TA-.

### 3.3 États

**EX-3.10** Une entrée est `executable` si et seulement si le test existe
dans le dépôt au commit éprouvé et s'exécute par la commande citée ; elle
cite alors un ou plusieurs `describe` (et, au besoin, `it`) de
`test/*.test.js` par leur titre exact, ou une ou plusieurs étapes de
`.github/workflows/ci.yml` par leur `name` exact quand aucun test mocha ne
le porte (vérificateurs Go, étapes d'intégration continue). Une entrée est
`a_ecrire` sinon ; elle nomme alors l'étape de la phase 2 qui livre son
objet (`phase2_step`) et ce qui bloque (`blocking`) ; un test possible dès
maintenant sur le dépôt mais non écrit est rattaché à l'étape 8 et son
`blocking` le dit. Aucun autre état. Une entrée `executable` dont une partie
de l'oracle attend un composant porte en plus `complement` (`phase2_step`,
`blocking`) : la partie citée s'exécute aujourd'hui, le complément est dû à
l'étape nommée ; la table l'imprime « exécutable ; complément à écrire
(étape n) ».

**EX-3.11** Un test `executable` DOIT être vert à chaque exécution de
`npm test` (ou de l'étape de CI citée) ; un test mis en attente par
l'absence d'un outil (interpréteur Python épinglé, Chromium, Go) reste
`executable` et son entrée nomme la condition dans `preconditions`. Avant ce
lot (R10-F30, journal de R10), la suite comptait 844 cas mocha : 838 réussis
et 6 en attente, tous dans `test/confrontation.test.js` ; la ligne de résumé
de Hardhat, « 844 passing (844 mocha) », compte les cas en attente parmi les
réussis. Avec `test/adversarial.test.js` et `test/plan-de-tests.test.js`,
`npx hardhat --config hardhat.config.mjs test` rend, au commit éprouvé de
cette version : résumé de mocha « 927 passing », « 6 pending », aucun échec,
code 0, soit 933 cas (844 + 58 + 31) ; la ligne de résumé de Hardhat dit
« 933 passing (933 mocha) », les 6 cas en attente comptés parmi les
réussis ; ces comptes sont ceux de l'exécution réelle de la commande, jamais
préécrits (annexe B.2, R10-F30).

### 3.4 Étapes de la phase 2

Une entrée « à écrire » se rattache à l'étape qui livre l'objet qu'elle
teste (table du plan, R10-F43 ; membre `phase2_steps` du catalogue).

<!-- table etapes -->
| Étape | Composant livré | Livré quand |
|---|---|---|
| 1 | Bibliothèque noyau : canonicalisation, hachage, chaînage, arbre de Merkle, signatures, formats | Tous les vecteurs de test passent |
| 2 | Vérificateur, construit en premier pour servir d'oracle à tout le reste | Rejette chaque dossier invalide des vecteurs, accepte chaque dossier valide |
| 3 | Registre de développement : instance noorcore, contrats, méthode du certificat de commit, image conteneur | Un client fictif ancre et clôt une période |
| 4 | Enregistreur : mandataire MCP, stockage et clôture de période, passerelle du modèle, moteur de politique et rétention des appels | Un agent de test traverse le mandataire ; chaque appel produit un événement que le vérificateur accepte |
| 5 | Ancrage : clients RFC 3161 et OpenTimestamps, serveur interne optionnel, planificateur | Une racine reçoit ses trois ancres et le vérificateur les valide |
| 6 | Console : tickets et approbations, onboarding, export du dossier, page de vérification | Un approbateur signe une décision depuis la console et le dossier exporté passe le vérificateur |
| 7 | Paquets, observabilité, runbooks | Installation complète chez un client fictif en une journée |
| 8 | Tests de bout en bout, adversariaux et de performance ; revue de sécurité interne du code | Chaque test adversarial échoue quand la réponse est retirée et passe sinon |


**EX-3.12** Quand une étape livre son objet, chaque entrée « à écrire »
rattachée à elle passe `executable` dans la même livraison, ou la livraison
dit pourquoi elle ne le peut pas (nouvelle étape, ou retrait motivé).

## 4. Catalogue lisible par machine

### 4.1 Structure d'une entrée

**EX-4.1** Chaque entrée du membre `tests` du catalogue porte : `id` (EX-3.1),
`level`, `title` (une ligne, ≤ 240 caractères), `specs` (spécifications visées :
l'ensemble des spécifications nommées par `covers`, dans l'ordre CT-1 à CT-8,
déduit par le générateur, et calculé de même dans une copie éditée à la main ;
une entrée sans `covers`, comme TR-13 à TR-15, nomme les siennes), `covers`
(identifiants couverts, chacun précédé de sa spécification, section 0.1 ; une
section « CT-n §s » est admise pour situer l'objet mais n'est pas comptée ; elle
s'écrit « CT-n §<numéro> », sans texte de titre (« CT-2 §7.4 »), le numéro étant
celui d'un titre de niveau 2 à 4 (« 7.4 », « A.4 ») ou la lettre d'une annexe ;
l'existence de la section citée est vérifiée par `definitions()` (5.2 : titre
qui commence par ce numéro, hors bloc de code), avertissement devenu erreur avec
`--strict`, EX-A.5), `preconditions` (liste non vide), `steps` (liste non vide,
dans l'ordre), `oracle` (ce qui est comparé à quoi), `status` (EX-3.10),
`threats` (menaces MN- couvertes ; pour un TA-, la liste `[MN-n]` qui compte
pour la règle (b) ; hors TA-, liste informative, éventuellement vide, des
menaces dont la réponse est aussi éprouvée par l'entrée, sans effet sur la règle
(b), chaque MN- cité devant exister dans `menaces.json`, EX-5.5), et, selon le
niveau, `adversarial` (TA-), `measure` (TM-), `replay` (TR-), `review` (TQ-),
interdits aux autres niveaux ; `notes` est libre. L'ordre de `covers` (hors TA-,
dont `covers` suit `response.refs`, EX-10.2) et celui de `threats` sont libres ;
les tables impriment l'ordre du catalogue. La racine du catalogue porte aussi
`levels`, `phase2_steps`, `non_tests` (5.3), `accepted_risks` (10.6) et
`traceability` (0.2).

**EX-4.2** Un titre cité par `status.tests` est le texte source du premier
argument de `describe(` ou `it(`, entre ses délimiteurs, tel qu'il figure
dans le fichier, avant toute interpolation (`${…}` compris) ; `describe`
seul désigne tous les `it` de ce `describe` ; `it` doit appartenir au
`describe` cité. Une étape de CI citée par `status.ci_steps` est la valeur
exacte d'un membre `name:` de `.github/workflows/ci.yml`.

Exemple d'une entrée exécutable (TV-2, imprimée depuis le catalogue,
conforme à `plan-de-tests-v0#/$defs/test`) :

<!-- schema: plan-de-tests/test -->
```json
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
}
```

Une entrée « à écrire » (TE-1, cas de démonstration « assurance ») a la
même forme, `status` réduit à `state`, `phase2_step` (8) et `blocking` ;
la voici, imprimée depuis le catalogue :

<!-- schema: plan-de-tests/test -->
```json
{
  "id": "TE-1",
  "level": "TE",
  "title": "Cas de démonstration « assurance » : agent de souscription et de tarification, de la capture au dossier vérifié",
  "specs": [
    "CT-2",
    "CT-3",
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
}
```

Les entrées TA-, TM-, TR- et TQ- ajoutent leur bloc propre (10.2, 11.5,
12.2, 13).

### 4.2 Schéma `plan-de-tests-v0`

**EX-4.3** Le catalogue valide contre
`spec/schemas/plan-de-tests-v0.schema.json` (draft 2020-12, `$id`
`https://noortrace.example/schemas/v0/plan-de-tests.schema.json`), qui se
compile en mode strict d'ajv et n'a aucune référence croisée. Sa racine décrit
le catalogue (`version` 0, `kind` `plan-de-tests`, `spec` `CT-9`,
`spec_version`, `date`, `levels` (huit), `phase2_steps` (huit), `tests`,
`non_tests`, `accepted_risks`, `traceability`) ; ses `$defs` décrivent une
entrée (`test`) et ses blocs propres (`adversarial`, 10 ; `mesure`, 11 ;
`rejeu`, 12 ; `revue`, 13), une justification (`justification_nc`), un risque
accepté relié à son test (`risque_accepte`, 10.6), une ligne de traçabilité
(`ligne_tc`), le rapport de l'outil de couverture (`rapport_couverture`, 5.4),
le rapport d'exécution (`rapport_execution`, EX-A.19), le rapport de mesure
(`rapport_mesure`, 11.3), la consignation d'une épreuve (`consignation_rejeu`,
12.1) et la grille d'une épreuve que CT-9 dote lui-même (`grille_acceptation`,
annexe A.9). Le schéma exige par `if`/`then` que l'état `executable` porte
`command` et `tests` ou `ci_steps`, que l'état `a_ecrire` porte `phase2_step` et
`blocking` et aucun `complement`, et que chaque niveau porte son bloc propre et
aucun autre ; `measure.measured` est `null` par schéma en version 0 ; un
scénario (`adversarial.threat` nul) porte `composition`. Le statut d'un résultat
du rapport d'exécution (`rapport_execution`, `results[].status`) est l'un de
`reussi`, `echec`, `en_attente` et `non_applicable`, les quatre qu'EX-A.19 et
EX-14.1 emploient ; `non_applicable` porte la partie d'une entrée conditionnée
par une proposition non adoptée (TA-26, TA-88).

```bash
npx --yes ajv-cli@5 compile --spec=draft2020 --strict=true \
  -s spec/schemas/plan-de-tests-v0.schema.json
npx --yes ajv-cli@5 validate --spec=draft2020 --strict=true \
  -s spec/schemas/plan-de-tests-v0.schema.json \
  -d spec/vecteurs/ct-9/catalogue.json
echo '{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"https://noortrace.example/schemas/v0/plan-de-tests.schema.json#/$defs/rapport_couverture"}' > rapport-couverture.schema.json
npx --yes ajv-cli@5 validate --spec=draft2020 --strict=true \
  -s rapport-couverture.schema.json -r spec/schemas/plan-de-tests-v0.schema.json \
  -d spec/vecteurs/ct-9/couverture.json
```

Exécuté le 2026-11-01 sur le schéma et le catalogue de référence de cette
version : schéma `valid`, catalogue `valid`, rapport de couverture `valid` ;
les neuf cas invalides de la famille `cas/` (exécutable sans titre ni
étape, à écrire sans étape, TA- sans bloc `adversarial`, identifiant sans
spécification, TM- avec une valeur mesurée, titre de `it` vide, complément
sans étape, `threat_test_text` sans le préfixe fixe, scénario sans
`composition`) rendent `invalid`, les deux cas valides `valid` (annexe
A.2) ; les dix-sept cas des rapports de mesure et des consignations
rendent leur attendu (annexe A.7, A.8).

### 4.3 Pas de double source : égalité du texte et du catalogue

**EX-4.4** Les quinze tables des sections 0.2, 3.1, 3.4, 5.3, 5.5 et 6 à
13 (marqueurs `<!-- table X -->`, EX-A.4 ; l'annexe A n'en porte aucune)
sont imprimées depuis le catalogue par le générateur
(`scripts/vecteurs/generer-ct9.mjs`), cellule par cellule ; l'outil de
couverture et le vérificateur Go indépendant relisent le texte et
échouent sur toute cellule qui diffère (même procédé que CT-7 §3.8 pour
`menaces.json`, R10-F26). Le catalogue est la source ; une correction se
fait dans la source de données du générateur, puis les tables du texte sont
remplacées par les blocs régénérés (EX-4.6), jamais éditées cellule par
cellule.

**EX-4.5** Le catalogue est lui-même écrit par le générateur depuis sa source
de données (`scripts/vecteurs/ct9/catalogue-donnees.mjs` et
`scripts/vecteurs/ct9/donnees/*.mjs`) ; deux générations donnent les mêmes
octets ; le générateur lit les spécifications, `menaces.json`,
`test/*.test.js` et `ci.yml` sans jamais les écrire, et n'écrit rien hors de
`spec/vecteurs/ct-9/`.

**EX-4.6 (ajout ou correction d'une entrée)** Quatre pas, dans cet ordre : (1)
éditer la source de données (`scripts/vecteurs/ct9/donnees/<niveau>.mjs` ; une
entrée nouvelle prend le numéro d'EX-3.1) ; (2) régénérer les vecteurs par `npm
run vecteurs:ct9`, puis imprimer les tables par `node
scripts/vecteurs/generer-ct9.mjs --tables <fichier hors de spec/vecteurs/ct-9/>`
et coller chaque bloc `<!-- table X -->` régénéré à la place du bloc du texte
(celui qui édite la source colle les tables ; dans l'épreuve (c), le
participant, EX-15.3) ; (3) mettre à jour les chiffres en prose de 5.5
(EX-5.10), que l'outil relit, et, s'ils changent, ceux de 10.8 et 16, à la
main : l'outil ne les relit pas (le vérificateur Go indépendant, A.10, relit le
compte des entrées « à écrire » de 16, et la confrontation tierce, A.11, le
nombre de `passing` de 10.8) ; (4) lancer `node scripts/tests/couverture.mjs`,
sans puis avec `--strict`, comme l'intégration continue (étape « outil de
couverture de CT-9 (code 0 exigé) » de `ci.yml`) : le code 0 dit que les règles
(a) à (d), EX-5.5, EX-4.4 et les chiffres de 5.5 tiennent. La régénération de
`ct-9` est le dernier acte d'une livraison : toute retouche d'un fichier
`test/*.test.js`, d'une spécification, de `menaces.json` ou de `ci.yml` l'oblige
(EX-A.6). Une copie du catalogue hors du dépôt lue par `--catalogue` sert à
l'essai, pas à la procédure : l'outil compare le texte au catalogue donné et
rend 1 tant que les tables ne sont pas collées. Pour un tel essai,
`index-ta-par-menace.json` est copié à côté de la copie (EX-A.5, EX-A.13) ;
sinon l'outil avertit, et l'avertissement est une erreur avec `--strict`.

## 5. Couverture

### 5.1 Règles normatives

**EX-5.1 (a)** Chaque identifiant EX- et chaque identifiant de vérification
défini par CT-1 à CT-8 (5.2) DOIT être couvert par au moins une entrée du
catalogue (membre `covers` ; pour une menace MN-n de CT-7, le membre
`threats` d'un TA-) ou porter une justification nommée de non-test NC-
(5.3). **EX-5.2 (b)** Chaque menace MN-1 à MN-98 de `menaces.json`
DOIT figurer dans `threats` d'au moins un TA-. **EX-5.3 (c)** Chaque
occurrence de « CT-9 » dans `spec/*.md` DOIT avoir sa ligne TC- (EX-0.1).
**EX-5.4 (d)** Chaque entrée `executable` DOIT citer des titres qui existent
mot pour mot dans `test/*.test.js` et des étapes qui existent dans
`ci.yml`. **EX-5.5** Un identifiant cité par `covers` ou par un NC- DOIT
exister dans la spécification nommée ; un identifiant inconnu, ou écrit
sans sa spécification, est une erreur, pas un avertissement.

La couverture se compte par identifiant, non par clause : un identifiant déjà
couvert n'appelle pas d'entrée nouvelle. Un **test plus fin** d'un identifiant
déjà couvert observe, pour le même identifiant, un comportement que l'entrée
existante n'observe pas, c'est-à-dire sur un autre composant (le démon au lieu
de la bibliothèque), avec un autre oracle (le verdict d'un outil tiers au lieu
d'une valeur calculée) ou à un autre niveau : c'est une entrée nouvelle (EX-3.1,
EX-4.6 ; un test du démon pour un identifiant que TI-13 couvre par les SDK en
est un, rangé selon 3.1). **Préciser** une entrée existante, c'est compléter ses
préconditions, ses pas ou son oracle sans nouvel oracle : c'est une correction
de sa source de données (EX-4.6) ; à composant, oracle et niveau égaux, un
comportement de plus que l'entrée n'observait pas est une précision de cette
entrée, jamais une entrée nouvelle. « L'entrée existante » désigne chaque entrée
dont `covers` porte déjà l'identifiant : une entrée nouvelle est justifiée si
elle diffère de chacune par le composant, l'oracle ou le niveau ; une entrée qui
ne couvre pas l'identifiant n'est pas la référence de cette règle. Le renvoi à
EX-15.3 ne porte aucune règle de couverture : il décrit l'épreuve (c), qui
applique cette règle.

### 5.2 Ce que l'outil lit dans chaque spécification

**EX-5.6** L'outil lit les identifiants définis par chaque spécification
avec `definitions()` de `scripts/conformite/verifier-renvois.mjs` (R10-F37),
sans le modifier : les EX- en gras (`**EX-s.k**` ou `**EX-s.k (`), les
familles à la première cellule d'une ligne de table (`| XX-k |`, gras
retiré), hors blocs de code ; il y ajoute, pour CT-8, les lignes `DM-n` en
début de ligne, les `**IR-n**`, `**IC-n**` en gras (déjà en table) et
RB-1 à RB-8 lus dans les titres `### 10.12` à `### 10.19` ; il exclut les
lignes `| CT-n |` des tables de relations et le faux positif `EIP-191` de
CT-7 (R10-F39, R10-F41). Lectures fixées : une famille s'écrit
`[A-Z]{1,3}(-[A-Z]{1,3})?-n` (second groupe facultatif : AV-T-, AV-PR-) à la
première cellule ; les lignes `DM-n` de CT-8 sont comptées bien qu'elles
soient dans le bloc de code du modèle de dimensionnement (22 lignes ; sans
elles CT-8 compterait 475 identifiants, non 497). Il lit les menaces dans
`menaces.json` (membre `threats[].id`), jamais dans la table du texte (CT-7
§3.8). Il lit les titres de tests au premier argument littéral de
`describe(` ou `it(` pris comme mot entier (non précédé d'un caractère
d'identifiant ni d'un point : `.split("…")` et `commit(` ne comptent pas),
délimiteur échappé admis dans le titre, commentaires et littéraux
d'expression rationnelle ignorés, texte pris tel qu'écrit avant
interpolation (EX-4.2) ; les expressions `describe\((["'`])(.*?)\1` et
`it\((["'`])(.*?)\1` en sont le raccourci, pas la définition. Il lit les
étapes de CI par `- name: `.

Inventaire au 2026-11-10 (commande ci-dessous ; les familles homonymes sont
comptées sous leur spécification) :

| Spécification | EX- | Vérifications et lignes de famille | Total | Familles (préfixe : nombre) |
|---|---|---|---|---|
| CT-1 (0.5) | 0 | 44 | 44 | D 2, E 11, C 3, M 3, P 5, A 4, K 9, AT 7 |
| CT-2 (0.6) | 324 | 11 | 335 | SG 7, RL 4 |
| CT-3 (0.4) | 203 | 56 | 259 | AP 17, TK 13, SG 7, AN 10, CS 9 |
| CT-4 (0.5) | 136 | 45 | 181 | RG 20, OP 12, CP 6, SU 7 |
| CT-5 (0.5) | 95 | 79 | 174 | P 6, AN 61, NV 12 |
| CT-6 (0.5) | 211 | 69 | 280 | T 11, O 7, R 11, N 4, V 10, K 2, AT 7, AV-T 4, AV-K 4, AV-R 3, AV-O 3, AV-AT 3 |
| CT-7 (0.2) | 117 | 463 | 580 | TR 101, MN 98, RA 82, CLE 29, CR 12, JS 12, PA 20, AT 7, T 10, MC 58, L 10, CL 6, RV 9, MX 9 |
| CT-8 (0.2) | 198 | 299 | 497 | TC 115, CO 14, FL 31, IP 13, IR 8, IC 18, TP 8, DM 22, SV 8, RB 8, PV 10, CA 6, OB 6, PR 12, AV-PR 4, PD 16 |
| Total | 1284 | 1066 | 2350 | — |

```bash
node -e 'import("./scripts/conformite/verifier-renvois.mjs").then(async (m) => {
  const fs = await import("node:fs");
  for (const f of fs.readdirSync("spec").filter((x) => /^CT-[1-8]-/.test(x))) {
    const d = m.definitions(fs.readFileSync("spec/" + f, "utf8"));
    console.log(f, "EX", d.ex.size, "familles", [...d.familles].filter((x) => !/^(CT|EIP)-/.test(x)).length);
  }
})'   # exécuté le 2026-11-10 ; CT-8 : + 22 DM- et 8 RB- hors tables
```

### 5.3 Justifications de non-test NC-

**EX-5.7** Une justification NC- porte `id`, `category` parmi `definition`
(glose ou définition sans comportement propre), `convention` (règle de
forme exécutée par un autre test), `texte_descriptif` (clause, modèle),
`delegue` (test porté par une autre spécification, nommée par
`delegated_to`), `hors_version_0` (critère relevé après la porte 2),
`renvoi` (ligne TR-/TC- sans réponse attendue), `proposition` (PA-, PD- non
adoptées), `ligne_de_modele` (RA- dont le test est celui de sa menace),
`non_verifie` (NV- de CT-5), la liste `covers` et une justification d'une
phrase au moins. Une justification ne couvre jamais un EX- en DOIT dont le
sujet est un composant construit ou à construire : un tel EX- a un test.

<!-- table NC -->
| Id | Catégorie | Identifiants | Justification |
|---|---|---|---|
| NC-1 | `proposition` | CT-7 PA- (20), CT-8 PD- (16) | Proposition adressée à une autre spécification, non appliquée : il n'y a rien à tester tant qu'elle n'est pas adoptée ; quand elle l'est, la règle qu'elle crée reçoit un EX- et un test. |
| NC-2 | `ligne_de_modele` | CT-7 RA- (82) | Risque accepté : réponse écrite d'une menace, nommé, borné, attribué (CT-7 §3.5), en bijection avec les menaces par `accepted_risk` (CT-7 RV-8, R10-F28). Le test d'un RA- est le TA- de sa menace ; la table TA- par menace (section des tests adversariaux) le rend lisible. |
| NC-3 | `non_verifie` | CT-5 NV- (12) | Point non vérifié de CT-5 : un fait que la rédaction n'a pas pu établir, pas une vérification ; il se clôt par une lecture de source primaire, pas par un test. |
| NC-4 | `texte_descriptif` | CT-7 CL- (6), CT-7 EX-C- (2) | Modèles de clauses contractuelles (CT-7 annexe C), à faire relire par le client ; aucun comportement d'un composant n'en dépend. Leur identité avec `matrice-conformite.json` est, elle, testée par MX-8 (TV- de la matrice). |
| NC-5 | `hors_version_0` | CT-4 SU- (7) | Critères de la règle de substitution (CT-4 §11.2) : relevés sur au moins trente jours d'un pilote en profil `prod-like`, donc après la porte 2 ; ils ne sont ni des vérifications d'une implémentation ni des mesures de la porte 2 (section porte 2, « ce que la porte 2 ne mesure pas »). |
| NC-6 | `convention` | CT-8 EX-0- (2) | Règles de forme de la table de traçabilité de CT-8 ; elles sont exécutées par `renvois.mjs` (TV- de la table TC-), cité ici pour mémoire : la couverture par un test prime et cette ligne ne compte que si l'outil ne trouvait pas le TV-. |

### 5.4 Outil de couverture

**EX-5.8** `scripts/tests/couverture.mjs` (`npm run tests:couverture`) lit,
en lecture seule : `spec/CT-1-*.md` à `spec/CT-8-*.md` et `spec/README.md`
(identifiants, occurrences de « CT-9 », tables du texte de CT-9),
`spec/vecteurs/ct-7/menaces.json`, `spec/vecteurs/ct-9/catalogue.json`,
`test/*.test.js`, `.github/workflows/ci.yml` et le texte de CT-9. Il écrit
un rapport conforme à `plan-de-tests-v0#/$defs/rapport_couverture` sur la
sortie standard (`--json`) ou dans le fichier donné (`--sortie`), et rend :
`0` si les règles (a) à (d), EX-5.5, EX-4.4, EX-3.10 (commande qui lance
chaque fichier cité), EX-10.3 (TA- exécutable avec mutant, étape de CI ou
complément), EX-10.10 (`measured_by`) et les chiffres de 5.5 tiennent ; `1`
si au moins une règle échoue (liste des écarts dans `errors`) : un
identifiant mal formé (sans spécification) ou inconnu est un écart de la
règle (a), code 1, pas un fichier illisible ; `2` sur une erreur d'usage ou
un fichier illisible. Il ne modifie aucun fichier.

L'outil ne valide pas le catalogue contre le schéma : la forme d'une entrée
(EX-4.1 ; états d'EX-3.10 : `blocking` et `phase2_step`, `tests` ou `ci_steps`)
est garantie par `plan-de-tests-v0` (EX-4.3) et par `test/plan-de-tests.test.js`
(EX-A.7) ; une entrée `a_ecrire` sans `blocking` ou une entrée `executable` sans
`tests` passe l'outil et est refusée par le schéma. Dans EX-5.8, « EX-3.10
(commande qui lance chaque fichier cité) » ne désigne que cette vérification de
la commande. De même, l'ordre et la numérotation d'EX-3.1 ne sont pas relus par
l'outil, qui ne relit que l'unicité et la forme (`TU-<n>`) des identifiants ; le
générateur refuse un identifiant en double, le vérificateur Go (EX-A.17) relit
l'unicité et la forme, et `test/plan-de-tests.test.js` l'ordre et l'absence de
trou ; une copie éditée à la main peut donc porter un numéro avec trou ou une
entrée mal placée sans que l'outil le signale, ce que la procédure d'EX-4.6
(source de données, régénération) rend impossible dans le dépôt.

L'outil ne relit pas non plus `specs`, que le générateur recalcule depuis
`covers` (EX-4.1) et que `test/plan-de-tests.test.js` vérifie sur le catalogue
du dépôt : dans une copie éditée à la main, un `specs` divergent n'est pas
signalé par l'outil. Trois lectures de sa sortie, à côté des codes 0, 1 et 2
d'EX-5.8 : une copie du catalogue lue par `--catalogue` rend 1, au moins par les
écarts d'EX-4.4, tant que les tables régénérées ne sont pas collées dans le
texte (EX-4.6) ; pour un ajout correct, ces écarts ne portent que sur la table
du niveau de l'entrée et sur la table `stats` et, si l'entrée change les
chiffres de 5.5 (entrée `executable`, identifiant jusque-là couvert par un NC-
seulement), sur ces chiffres ; tout écart des règles (a) à (d) ou d'EX-5.5, et
tout avertissement sous `--strict`, est un défaut de l'entrée ; la date imprimée
en tête (« Couverture CT-9 (<date>) », membre `date` du rapport) est celle de
l'exécution, sauf quand le générateur appelle l'outil et lui passe la date du
catalogue (`couverture.json`) ; le compte de lignes d'une table comparée
(« table TU : n lignes dans le texte, m dans le catalogue ») inclut l'en-tête et
le séparateur : une table de n entrées a n + 2 lignes.

**EX-5.9** Le rapport porte : les condensés SHA-256 de chaque entrée lue
(`inputs`), les totaux et le détail par spécification (`identifiers`, avec
la liste des identifiants non couverts et des identifiants cités inconnus),
les menaces sans TA- (`threats.without_ta`), les occurrences et lignes TC-
par clé de section (`traceability.missing`, `orphans`), les titres cités
absents (`executable.titles_missing`), les cellules du texte qui diffèrent
du catalogue (`text_tables.differences`) et le verdict. Le rapport publié
est `spec/vecteurs/ct-9/couverture.json` ; il est régénéré par le
générateur et comparé par la CI.

### 5.5 Chiffres de couverture

**EX-5.10** Les chiffres imprimés ici sont ceux du rapport
`spec/vecteurs/ct-9/couverture.json`, cités avec la commande qui les
produit ; aucun chiffre n'est écrit à la main.

État au 2026-11-10, calculé par `node scripts/tests/couverture.mjs` sur le
dépôt au commit éprouvé (`couverture.json` est sa sortie, écrite par le
générateur, EX-A.6 ; si l'outil trouve autre chose, le texte est régénéré,
jamais corrigé à la main) :

- 2350 identifiants définis par CT-1 à CT-8 : 2211 couverts par une entrée,
  139 par une justification NC-, **0 non couvert** ; aucun identifiant cité
  inconnu ;
- 98 menaces sur 98 avec un TA- (règle (b)) ;
- 122 occurrences de « CT-9 » et 122 lignes TC-, sans manque ni orpheline
  (règle (c)) ;
- 224 entrées exécutables citant 489 titres de tests ou étapes de CI, tous
  trouvés mot pour mot (règle (d)) ; verdict `reussi`.

Par spécification (identifiants, couverts par une entrée, par une
justification) : CT-1 44, 44, 0 ; CT-2 335, 335, 0 ; CT-3 259, 259, 0 ;
CT-4 181, 174, 7 ; CT-5 174, 162, 12 ; CT-6 280, 280, 0 ; CT-7 580, 476,
104 ; CT-8 497, 481, 16. Entrées du catalogue, par niveau (table imprimée
depuis le catalogue) :

<!-- table stats -->
| Niveau | Entrées | Exécutables | dont avec complément à écrire | À écrire |
|---|---|---|---|---|
| TU- | 39 | 39 | 0 | 0 |
| TV- | 76 | 75 | 1 | 1 |
| TI- | 20 | 8 | 1 | 12 |
| TE- | 17 | 6 | 2 | 11 |
| TA- | 103 | 80 | 12 | 23 |
| TM- | 44 | 16 | 5 | 28 |
| TR- | 15 | 0 | 0 | 15 |
| TQ- | 8 | 0 | 0 | 8 |
| Total | 322 | 224 | 21 | 98 |

## 6. Tests unitaires et de propriétés (TU-)

Les TU- exercent les bibliothèques de référence sans vecteur publié comme
oracle : le noyau de CT-1 (`scripts/lib/journal.mjs` : JCS v0, Ed25519,
hachage, chaînage, Merkle, cohérence, manifeste, dossier, attestation), les
bibliothèques de CT-2 (`capture.mjs`, `otel.mjs`, `worm.mjs`,
`cout-agent.mjs`), CT-3 (`approbation.mjs`, `console.mjs`), CT-4
(`conventions-registre.mjs`, outil de référence, contrats), CT-5
(`ancrage.mjs`), CT-6 (`horodatage.mjs`, `ots.mjs`, `registre.mjs`,
`verificateur.mjs`), CT-7 (`securite.mjs`), CT-8 (`deploiement.mjs`,
`exploitation.mjs`, `paquet.mjs`). Les trente-neuf entrées sont exécutables
par `npm test` ; TU-12 (propriétés aléatoires) porte depuis l'étape 1 sur la
bibliothèque noyau de production `paquets/noyau`.

**EX-6.1** Le TU-12 de propriétés fixe : bibliothèque `fast-check` à
version exacte (4.10.2 au 2026-11-01, R11-F16), graine constante écrite
dans le test, `numRuns` 200, `randomType` `xorshift128plus` écrit, aucune
limite de temps ; ses cinq propriétés (idempotence de JCS, détection de
toute mutation d'un octet par E-7, de toute transposition par C-2,
acceptation de toute preuve d'inclusion et de cohérence et refus de toute
preuve altérée, aller-retour Ed25519) sont écrites dans son entrée.

<!-- table TU -->
| Id | Objet | Identifiants couverts (famille : nombre) | Menaces | État |
|---|---|---|---|---|
| TU-1 | JCS v0 : forme canonique restreinte aux entiers (CT-1 §4) | CT-1 E- (1) | MN-4 | exécutable : `test/journal.test.js` |
| TU-2 | Ed25519 (RFC 8032) et dérivation des clés de test (CT-1 §6.2, §13) |  | — | exécutable : `test/journal.test.js` |
| TU-3 | Événement : hachage, signature, approbation, rotation, pièces (CT-1 §5 à §8) | CT-1 E- (9) | MN-84, MN-90 | exécutable : `test/journal.test.js` |
| TU-4 | Chaînage : `seq`, `prev_hash`, diagnostics nommés (CT-1 §7) | CT-1 C- (3) | MN-17 | exécutable : `test/journal.test.js` |
| TU-5 | Arbre de Merkle RFC 6962, preuves d'inclusion, période vide (CT-1 §9) | CT-1 M- (3), CT-1 P- (1) | — | exécutable : `test/journal.test.js` |
| TU-6 | Preuve de cohérence RFC 9162 §2.1.4 et points de contrôle (CT-1 §10.5 à §10.8) | CT-1 K- (6) | MN-74 | exécutable : `test/journal.test.js` |
| TU-7 | Manifeste de période : `periodHash`, signature, continuité, `anchorFingerprint` (CT-1 §10.1 à §10.4) | CT-1 P- (2) | — | exécutable : `test/journal.test.js` |
| TU-8 | Validation contre les schémas JSON de CT-1 (`validerSchema`) | CT-1 D- (1), CT-1 E- (1) | — | exécutable : `test/journal.test.js` |
| TU-9 | Dossier de preuve par la bibliothèque : assemblage, index, contrôles D-, P-, A- (CT-1 §11) | CT-1 D- (1), CT-1 P- (2), CT-1 A- (4), CT-1 E- (1) | — | exécutable : `test/journal.test.js` |
| TU-10 | Partie `attestation-perimetre.json` par la bibliothèque, AT-1 à AT-7 (CT-1 révision 0.4) | CT-1 AT- (7) | MN-79, MN-80, MN-82, MN-86, MN-89, MN-91 | exécutable : `test/journal.test.js` |
| TU-11 | Ligne de commande `scripts/verify/dossier.mjs` : codes 0, 1, 2 (CT-1 §11.4) |  | — | exécutable : `test/journal.test.js` |
| TU-12 | Propriétés aléatoires du noyau : canonicalisation, hachage, chaînage, Merkle, signature | CT-1 E- (2), CT-1 C- (1), CT-1 M- (1), CT-1 K- (1) | MN-4, MN-17 | exécutable : `test/noyau-proprietes.test.js` |
| TU-13 | Primitives de la console confrontées à `node:crypto`, `@noble/*` et `ethers` (CT-3 EX-13.32) | CT-3 EX-13- (1) | MN-52 | exécutable : `test/console-primitives.test.js`, `test/console.test.js` |
| TU-14 | Lecteur DER borné du vérificateur (CT-6 §9.3) | CT-6 EX-9- (1) | MN-68 | exécutable : `test/horodatage.test.js` |
| TU-15 | Jeton RFC 3161 construit en mémoire : T-1 à T-11, N-1, AV-T- (CT-6 §9, §12.2, §15.2) | CT-6 T- (11), CT-6 N- (1), CT-6 AV-T- (4), CT-6 EX-9- (24), CT-6 EX-12- (1), CT-6 EX-15- (1) | MN-61, MN-68 | exécutable : `test/horodatage.test.js` |
| TU-16 | Format `.ots`, en-têtes Bitcoin, O-1 à O-7 construits en mémoire (CT-6 §10, §15.2) | CT-6 O- (7), CT-6 N- (1), CT-6 AV-O- (3), CT-6 EX-10- (16), CT-6 EX-15- (1) | MN-70 | exécutable : `test/ots.test.js` |
| TU-17 | Registre : RLP, hachage BFT, reçus, journaux, parties, R-1 à R-10 et N-4 construits en mémoire (CT-6 §11) | CT-6 R- (11), CT-6 N- (2), CT-6 AV-R- (3), CT-6 EX-11- (3), CT-6 EX-12- (1), CT-6 EX-8- (1), CT-6 EX-4- (1), CT-6 EX-5- (2) | MN-34, MN-54, MN-59, MN-67, MN-71 | exécutable : `test/registre.test.js` |
| TU-18 | Certificat de commit : parité du décodeur JavaScript avec le code Go de noorcore (CT-4 §9, CT-6 §11) | CT-4 EX-9- (14) | MN-55 | exécutable : `test/certificatCommit.test.js` |
| TU-19 | Contrats du registre : `PeriodRegistry`, `RecorderRegistry`, signatures à seuil, déploiement (CT-4 §5) |  | MN-53, MN-73 | exécutable : `test/periodRegistry.test.js`, `test/recorderRegistry.test.js`, `test/thresholdSignatures.test.js`, `test/deploy.test.js` |
| TU-20 | JCS intégral (RFC 8785 tel quel) et étendue des valeurs relayées (CT-2 §8.1, EX-4.20) | CT-2 EX-8- (11), CT-2 EX-4- (1) | MN-4 | exécutable : `test/enregistreur.test.js` |
| TU-21 | Détecteurs exacts, politique de rédaction, motifs et budget (CT-2 §10) | CT-2 EX-10- (24), CT-7 EX-8- (2) | — | exécutable : `test/enregistreur.test.js` |
| TU-22 | Analyseur SSE et formes consolidées des flux Anthropic, Chat Completions, Responses (CT-2 §5.4) | CT-2 EX-5- (3) | — | exécutable : `test/enregistreur.test.js` |
| TU-23 | Frontal MCP en bibliothèque : agrégation de `tools/list`, lecture d'une requête d'hôte, codes d'erreur, quotas (CT-2 §4.3, §4.4) | CT-2 EX-4- (8), CT-2 EX-5- (2) | MN-7 | exécutable : `test/enregistreur.test.js` |
| TU-24 | Construction des événements, écrivain, segment, journal d'intention, reprise, horloge (CT-2 §7, §9, §12) | CT-2 EX-7- (4) | MN-10, MN-20, MN-21 | exécutable : `test/enregistreur.test.js` |
| TU-25 | Configuration et contrôles de démarrage (CT-2 §15, EX-7.15) | CT-2 EX-15- (8), CT-2 EX-7- (1) | MN-2, MN-11, MN-13, MN-14, MN-30, MN-43 | exécutable : `test/enregistreur.test.js`, `test/enregistreur-r05.test.js` |
| TU-26 | Passerelle Gemini et format `gemini` du SDK, règles en bibliothèque (CT-2 §5.4.5, EX-5.28 à EX-5.36, EX-6.8) | CT-2 EX-5- (10), CT-2 EX-6- (1), CT-2 EX-8- (1) | MN-11, MN-13 | exécutable : `test/enregistreur-r05.test.js` |
| TU-27 | Ingestion OpenTelemetry en bibliothèque : décodage, classement, doublons, refus (CT-2 §6.8) | CT-2 EX-6- (17) | MN-15, MN-16 | exécutable : `test/enregistreur-r05.test.js` |
| TU-28 | Copies WORM et gel juridique en bibliothèque (CT-2 §12.6, §12.11) | CT-2 EX-12- (13) | MN-27, MN-28 | exécutable : `test/enregistreur-r05.test.js` |
| TU-29 | Coût annuel par agent : formule et contrôles d'entrée (CT-2 §16.4) | CT-2 EX-16- (3) | — | exécutable : `test/enregistreur-r05.test.js` |
| TU-30 | Politique d'approbation : validation, évaluation, candidats, exemples de la spécification (CT-3 §3 à §6, §8.2) | CT-3 AP- (17), CT-3 EX-4- (14), CT-3 EX-5- (10), CT-3 EX-6- (8), CT-3 EX-3- (1), CT-3 EX-8- (1), CT-3 EX-9- (1), CT-3 EX-11- (1), CT-3 EX-12- (1) | MN-3 | exécutable : `test/approbation.test.js` |
| TU-31 | Tickets, remises, jeu d'approbateurs, mandataire en attente et échanges noyau ↔ service (CT-3 §7 à §12, §14 ; CT-2 §7.5) | CT-3 TK- (13), CT-3 SG- (7), CT-3 EX-7- (29), CT-3 EX-8- (11), CT-3 EX-9- (22), CT-3 EX-10- (11), CT-3 EX-11- (15), CT-3 EX-12- (1), CT-3 EX-14- (1), CT-3 EX-3- (1), CT-2 EX-7- (9), CT-2 EX-9- (1), CT-2 EX-10- (1), CT-2 EX-12- (1), CT-2 EX-4- (2), CT-2 EX-6- (1), CT-2 RL- (4), CT-2 SG- (7) | MN-5, MN-6, MN-38, MN-44, MN-48, MN-49, MN-50 | exécutable : `test/approbation.test.js` |
| TU-32 | Console de référence en bibliothèque : annuaire, modèle d'affichage, requêtes, réponses, découverte, fichiers de clé, propriétés statiques (CT-3 §9, §12.9, §13) | CT-3 AN- (10), CT-3 CS- (9), CT-3 EX-13- (36), CT-3 EX-9- (9), CT-3 EX-12- (4) | MN-35, MN-45, MN-46, MN-47, MN-52 | exécutable : `test/console.test.js` |
| TU-33 | Console de référence dans Chromium : parcours nominal, refus, délai, changement de ticket, annuaire, comptes, inscription, politique du contenu (CT-3 EX-13.36) | CT-3 EX-13- (5), CT-3 EX-9- (2) | MN-35, MN-45, MN-46, MN-52 | exécutable : `test/console.test.js` |
| TU-34 | Mode observation en bibliothèque : `evaluerObservation`, marque, relais, configuration (CT-3 révision 0.4, CT-2 révision 0.6) | CT-3 EX-11- (5), CT-3 EX-12- (1), CT-3 EX-6- (1), CT-2 EX-14- (5), CT-2 EX-15- (1), CT-2 EX-17- (1), CT-2 EX-4- (1), CT-2 EX-7- (1), CT-8 EX-12- (1) | — | exécutable : `test/observation.test.js`, `test/exploitation.test.js` |
| TU-35 | Registre CT-4 : exigences vérifiables hors ligne, outil de référence hors ligne, parcours sur le réseau Hardhat en mémoire, capture derrière un pont synthétique (CT-4 §3 à §9) | CT-4 OP- (12), CT-4 CP- (6), CT-4 RG- (1), CT-4 EX-3- (1), CT-4 EX-4- (10), CT-4 EX-5- (6), CT-4 EX-6- (1), CT-4 EX-7- (17), CT-4 EX-8- (21), CT-4 EX-A- (2), CT-6 EX-11- (1) | MN-40, MN-53, MN-56, MN-57, MN-72, MN-73 | exécutable : `test/registreCt4.test.js` |
| TU-36 | Planificateur d'ancrage en bibliothèque : comptages, coût, série des points, admission, complétude (CT-5 §3, §4, §10.3, §12) | CT-5 EX-4- (5), CT-5 EX-12- (2), CT-5 AN- (7), CT-5 EX-10- (1) | MN-41, MN-63, MN-65 | exécutable : `test/ancrage.test.js` |
| TU-37 | Attestation de périmètre et procès-verbal de cérémonie en bibliothèque : condensés, signatures, séparation des domaines, AT-1 à AT-4 (CT-7 §5.7, §5.8, §7.2, §7.7) | CT-7 EX-7- (2), CT-7 EX-5- (2), CT-7 EX-A- (1), CT-7 AT- (7), CT-7 CR- (12) | MN-32, MN-36, MN-37, MN-39, MN-81, MN-83, MN-92, MN-94 | exécutable : `test/securite.test.js` |
| TU-38 | Bibliothèques du déploiement et de l'exploitation : fichiers de conteneur, configuration rapide, archive autonome, outils donnés dès maintenant, configuration modèle de production (CT-8 §3.6, §4, §7.3, §8, §10.14) | CT-8 CO- (14), CT-8 EX-3- (1), CT-8 EX-4- (4), CT-8 IR- (2), CT-8 IC- (1), CT-8 EX-10- (2), CT-8 SV- (1), CT-8 EX-A- (2) | MN-22, MN-25 | exécutable : `test/deploiement.test.js`, `test/exploitation.test.js` |
| TU-39 | Outil du paquet réviseur : vérification, construction, instructions, corrections (CT-8 §13.5 à §13.11) | CT-8 PR- (12), CT-8 AV-PR- (4), CT-8 EX-13- (38), CT-8 EX-12- (1) | MN-78 | exécutable : `test/paquet-reviseur.test.js` |

## 7. Tests de conformité aux vecteurs (TV-)

Une entrée par famille de `spec/vecteurs/ct-1` à `ct-8` et par mode de
rejeu : implémentation de référence, vérificateur Go indépendant (étape de
`ci.yml` : `go run . ..`), confrontation tierce, génération déterministe.
Soixante-quinze des soixante-seize entrées sont exécutables ; TV-55
(vérificateur Go de CT-6) l'est depuis l'étape 2, et TV-76 (famille
`supervision/`, étape 7) est à écrire.

**EX-7.1** Les vérifications V-1 à V-10 de CT-6 §6.9 sont exécutées par
comparaison du rapport du vérificateur à l'`attendu.json` de chaque
dossier (TV-52), comme CT-6 le demande (renvoi TC- de CT-6 §6.9).
**EX-7.2** La rédaction idempotente d'une pièce stockée (CT-2 §10.4, renvoi
TC- de la ligne 6880) est l'oracle de TV-11 : réappliquer la politique à la
pièce rédigée ne change aucun octet. **EX-7.3** Les vecteurs `ct-1` à
`ct-8` et leurs générateurs ne changent pas par CT-9 (règle du lot) ; le
TV- de génération déterministe de chaque répertoire le garantit.

<!-- table TV -->
| Id | Objet | Identifiants couverts (famille : nombre) | Menaces | État |
|---|---|---|---|---|
| TV-1 | `ct-1/cles/` : clés de test dérivées des graines |  | — | exécutable : `test/journal.test.js` |
| TV-2 | `ct-1/jcs/cas-limites.json` : forme canonique ou refus | CT-1 E- (1) | MN-4 | exécutable : `test/journal.test.js` |
| TV-3 | `ct-1/journal-valide/` et les cinq journaux altérés : contrôles de la table 7.2 | CT-1 C- (3), CT-1 E- (11) | MN-17, MN-74 | exécutable : `test/journal.test.js` |
| TV-4 | `ct-1/merkle/arbres.json` : racines et preuves d'inclusion | CT-1 M- (3) | — | exécutable : `test/journal.test.js` |
| TV-5 | `ct-1/merkle/coherence.json` et `ct-1/points-de-controle/` : preuves de cohérence, séries valides et invalides | CT-1 K- (6) | MN-74 | exécutable : `test/journal.test.js` |
| TV-6 | `ct-1/manifestes/` : trois périodes consécutives et un manifeste discontinu | CT-1 P- (5) | — | exécutable : `test/journal.test.js` |
| TV-7 | `ct-1/dossiers/` : le dossier valide et chaque dossier invalide, par la bibliothèque et par le vérificateur de CT-6 | CT-1 D- (2), CT-1 A- (4), CT-1 AT- (7), CT-6 V- (1), CT-6 EX-6- (1), CT-7 EX-A- (2), CT-6 EX-4- (1), CT-6 EX-5- (5) | MN-74, MN-79, MN-80, MN-82, MN-84, MN-86, MN-89, MN-90, MN-91 | exécutable : `test/journal.test.js`, `test/verificateur.test.js` |
| TV-8 | Génération déterministe de `spec/vecteurs/ct-1` |  | — | exécutable : `test/journal.test.js` |
| TV-9 | Vérificateur Go indépendant de CT-1 : zéro discordance sur `spec/vecteurs/ct-1` | CT-1 E- (11), CT-1 C- (3), CT-1 M- (3), CT-1 P- (5), CT-1 A- (4), CT-1 K- (6), CT-1 AT- (7) | MN-66 | exécutable : étape de `ci.yml` |
| TV-10 | `ct-2/jcs-integral/cas.json` | CT-2 EX-8- (2) | MN-4 | exécutable : `test/enregistreur.test.js` |
| TV-11 | `ct-2/redaction/` : politiques, motifs, pièces rédigées, idempotence | CT-2 EX-10- (24) | — | exécutable : `test/enregistreur.test.js` |
| TV-12 | `ct-2/pieces-mcp/` : appels relayés ou refusés, agrégation de `tools/list` | CT-2 EX-4- (48) | MN-7 | exécutable : `test/enregistreur.test.js` |
| TV-13 | `ct-2/pieces-modele/` : Anthropic, OpenAI Chat Completions et Responses, Gemini | CT-2 EX-5- (34) | MN-11, MN-13 | exécutable : `test/enregistreur.test.js`, `test/enregistreur-r05.test.js` |
| TV-14 | `ct-2/otel/` : 48 cas d'ingestion OTLP en JSON et en protobuf | CT-2 EX-6- (17) | MN-15, MN-16 | exécutable : `test/enregistreur-r05.test.js` |
| TV-15 | `ct-2/worm/` : requêtes, états, périmètres, gardes, levées | CT-2 EX-12- (13) | MN-27, MN-28 | exécutable : `test/enregistreur-r05.test.js` |
| TV-16 | `ct-2/cout-agent/cas.json` : neuf cas de la formule | CT-2 EX-16- (3) | — | exécutable : `test/enregistreur-r05.test.js` |
| TV-17 | `ct-2/evenements/journal-demo/` : chaîne, pièces, politique, intention, segment, dossier de seq 7 | CT-2 EX-7- (13), CT-2 EX-9- (8), CT-2 EX-12- (3), CT-1 E- (11) | MN-23 | exécutable : `test/enregistreur.test.js` |
| TV-18 | Génération déterministe de `spec/vecteurs/ct-2` |  | — | exécutable : `test/enregistreur.test.js` |
| TV-19 | Vérificateur Go indépendant de CT-2 : zéro discordance sur `spec/vecteurs/ct-2` | CT-2 EX-8- (11), CT-2 EX-6- (17), CT-2 EX-12- (13), CT-2 EX-16- (3), CT-2 EX-4- (1) | MN-66 | exécutable : étape de `ci.yml` |
| TV-20 | Confrontation tierce de `ct-2` : google-genai 2.33.0 et opentelemetry-proto 1.45.1 | CT-2 EX-6- (2) | — | exécutable : `test/confrontation.test.js` |
| TV-21 | `ct-3/politiques/`, `politiques-invalides/`, `evaluation/`, `candidats/` : AP-1 à AP-17 | CT-3 AP- (17), CT-3 EX-A- (3) | MN-3 | exécutable : `test/approbation.test.js` |
| TV-22 | `ct-3/acceptation/` rejoué par l'implémentation de référence : dix décisions, matériel sans attendu (CT-3 EX-A.4, EX-A.5) | CT-3 EX-A- (2) | — | exécutable : `test/approbation.test.js` |
| TV-23 | `ct-3/tickets/` : traces de cycle de vie, TK-1 à TK-13 | CT-3 TK- (13), CT-3 EX-A- (2) | MN-5, MN-6, MN-38, MN-50 | exécutable : `test/approbation.test.js` |
| TV-24 | `ct-3/decisions/` et `ct-3/signatures/normalisation.json` : remises acceptées et refusées, SG-1 à SG-7 | CT-3 SG- (7), CT-3 EX-A- (1), CT-3 EX-9- (1) | MN-44, MN-48, MN-49 | exécutable : `test/approbation.test.js` |
| TV-25 | `ct-3/annuaire/` : annuaires, messages, inscriptions, domaines, traces, contrôles, exports (AN-1 à AN-10) | CT-3 AN- (10), CT-3 EX-A- (5) | MN-47 | exécutable : `test/console.test.js` |
| TV-26 | `ct-3/console/` : modèles, requêtes, réponses, découverte, fichiers de clé (CS-1 à CS-9) ; matériel de l'épreuve de lecture | CT-3 CS- (9), CT-3 EX-A- (1) | MN-45, MN-46 | exécutable : `test/console.test.js` |
| TV-27 | Génération déterministe de `spec/vecteurs/ct-3` | CT-3 EX-A- (4) | — | exécutable : `test/approbation.test.js`, `test/console.test.js` |
| TV-28 | Vérificateur Go indépendant de CT-3 : zéro discordance sur `spec/vecteurs/ct-3` | CT-3 EX-A- (2), CT-3 AP- (17), CT-3 TK- (13), CT-3 SG- (7), CT-3 AN- (10), CT-3 CS- (9) | MN-66 | exécutable : étape de `ci.yml` |
| TV-29 | Confrontation tierce de `ct-3` : signatures par ethers 6 et eth-account 0.14.0 | CT-3 EX-A- (2), CT-3 EX-9- (1) | — | exécutable : `test/confrontation.test.js` |
| TV-30 | `ct-4/identifiants.json`, `doctypes.json`, `empreintes.json` : RG-1 à RG-4 | CT-4 RG- (4) | — | exécutable : `test/registreCt4.test.js` |
| TV-31 | `ct-4/condenses.json` : RG-5 à RG-13 | CT-4 RG- (9) | MN-57 | exécutable : `test/registreCt4.test.js` |
| TV-32 | `ct-4/appels.json` et `transactions.json` : RG-14, RG-15, confrontation à ethers et à la capture | CT-4 RG- (2), CT-4 EX-A- (1) | MN-72 | exécutable : `test/registreCt4.test.js` |
| TV-33 | `ct-4/manifestes/` : RG-16 à RG-20, ancre `registry` dérivée | CT-4 RG- (5) | — | exécutable : `test/registreCt4.test.js` |
| TV-34 | `ct-4/demandes/` et `ct-4/inscription/` : schéma, OP-4, OP-6, OP-7 | CT-4 OP- (3) | — | exécutable : `test/registreCt4.test.js` |
| TV-35 | `ct-4/capture/` : CP-2 à CP-6, export des parties | CT-4 CP- (5), CT-4 EX-9- (3) | MN-56 | exécutable : `test/registreCt4.test.js` |
| TV-36 | Complétude des familles de `ct-4` : chaque RG-, OP- hors ligne et CP- a un cas réussi et un cas en échec ; exemples annotés | CT-4 EX-A- (1), CT-4 RG- (20) | — | exécutable : `test/registreCt4.test.js` |
| TV-37 | Génération déterministe de `spec/vecteurs/ct-4` | CT-4 EX-A- (3) | — | exécutable : `test/registreCt4.test.js` |
| TV-38 | Vérificateur Go indépendant de CT-4 : zéro discordance sur `spec/vecteurs/ct-4` | CT-4 RG- (20), CT-4 CP- (6), CT-4 OP- (3), CT-4 EX-A- (1) | MN-66 | exécutable : étape de `ci.yml` |
| TV-39 | `ct-5/requetes/` : `TimeStampReq` DER exacte, nonce, refus | CT-5 EX-5- (2), CT-5 AN- (2) | — | exécutable : `test/ancrage.test.js` |
| TV-40 | `ct-5/reponses/` : classement des réponses de l'autorité de test | CT-5 EX-5- (4), CT-5 EX-8- (1), CT-5 AN- (4) | MN-60, MN-76 | exécutable : `test/ancrage.test.js` |
| TV-41 | `ct-5/ots/` : fichiers `.ots` reconstruits, mise à niveau | CT-5 EX-6- (6), CT-5 EX-8- (1), CT-5 AN- (4) | — | exécutable : `test/ancrage.test.js` |
| TV-42 | `ct-5/planification/` et `ct-5/reprise/` : vingt et une traces du planificateur, files avant et après | CT-5 EX-4- (7), CT-5 EX-5- (4), CT-5 EX-6- (1), CT-5 EX-8- (14), CT-5 EX-9- (1), CT-5 AN- (16), CT-5 EX-A- (1) | MN-60, MN-62, MN-63, MN-64, MN-76 | exécutable : `test/ancrage.test.js` |
| TV-43 | `ct-5/cout/` et `ct-5/completude/` : onze cas de coût, six cas de complétude | CT-5 EX-12- (2), CT-5 EX-10- (1), CT-5 AN- (2), CT-5 EX-4- (1) | MN-17 | exécutable : `test/ancrage.test.js` |
| TV-44 | Vecteurs de CT-1 et de CT-6 inchangés par CT-5 ; aucun secret, prix ni adresse dans `ct-5` | CT-5 EX-A- (1), CT-5 AN- (2) | MN-41 | exécutable : `test/ancrage.test.js` |
| TV-45 | Génération déterministe de `spec/vecteurs/ct-5` | CT-5 EX-A- (4) | — | exécutable : `test/ancrage.test.js` |
| TV-46 | Vérificateur Go indépendant de CT-5 : zéro discordance sur `spec/vecteurs/ct-5` | CT-5 EX-A- (1), CT-5 EX-5- (1), CT-5 AN- (12) | MN-66 | exécutable : étape de `ci.yml` |
| TV-47 | Confrontation tierce de `ct-5` : openssl, python-opentimestamps, transparency-dev/merkle | CT-5 EX-A- (1) | — | exécutable : `test/confrontation.test.js` |
| TV-48 | `ct-6/rfc3161/` : jetons, clés, CRL, statuts T-1 à T-11, confrontation à `openssl ts -verify` | CT-6 T- (11), CT-6 EX-9- (2), CT-6 EX-A- (4) | MN-61 | exécutable : `test/horodatage.test.js` |
| TV-49 | `ct-6/ots/` : en-têtes synthétiques, preuves, statuts O-1 à O-7 | CT-6 O- (7), CT-6 EX-10- (2), CT-6 EX-A- (3), CT-6 EX-4- (1) | MN-70 | exécutable : `test/ots.test.js` |
| TV-50 | `ct-6/registre/` : parties dérivées de la capture, variantes, R-1 à R-10 et N-4 | CT-6 R- (10), CT-6 N- (1), CT-6 EX-A- (5) | MN-34, MN-54, MN-59, MN-67, MN-71 | exécutable : `test/registre.test.js` |
| TV-51 | `ct-6/ancres/` : fichiers d'ancres de test conformes à `ancres-confiance-v0` | CT-6 N- (3), CT-6 EX-12- (6), CT-6 EX-A- (1) | — | exécutable : `test/horodatage.test.js`, `test/ots.test.js` |
| TV-52 | `ct-6/dossiers/` : dossiers complets, verdicts, énoncés, V-1 à V-10 (rapport comparé à `attendu.json`) | CT-6 V- (10), CT-1 K- (3), CT-6 AT- (7), CT-6 AV-AT- (3), CT-6 AV-K- (4), CT-6 EX-5- (15), CT-6 EX-6- (22), CT-6 EX-7- (3), CT-6 EX-8- (11), CT-6 EX-4- (8), CT-6 EX-3- (2), CT-7 EX-8- (2), CT-6 EX-13- (2), CT-6 EX-15- (2), CT-6 EX-A- (11), CT-6 K- (2) | MN-17, MN-61, MN-68, MN-69, MN-78, MN-85, MN-98 | exécutable : `test/verificateur.test.js` |
| TV-53 | Génération déterministe de `spec/vecteurs/ct-6` (dossiers, rfc3161, ots, registre) | CT-6 EX-A- (3) | — | exécutable : `test/verificateur.test.js`, `test/horodatage.test.js`, `test/ots.test.js`, `test/registre.test.js` |
| TV-54 | Confrontation tierce de `ct-6` : openssl, python-opentimestamps, go-ethereum et noorcore | CT-6 EX-A- (6) | — | exécutable : `test/confrontation.test.js` |
| TV-55 | Vérificateur Go indépendant de CT-6 (binaire de CT-6 §14) : zéro discordance sur `ct-6/dossiers` | CT-6 EX-14- (11), CT-6 EX-4- (2), CT-6 EX-5- (8), CT-6 EX-6- (1), CT-6 EX-9- (2), CT-6 EX-A- (5) | MN-66 | exécutable : étape de `ci.yml` ; complément à écrire (étape 7) |
| TV-56 | `ct-7/menaces.json`, tables 3.2 à 3.5 et vérificateur de renvois : RV-1 à RV-9, table TR- de CT-7 | CT-7 RV- (9), CT-7 TR- (101), CT-7 EX-0- (1), CT-7 EX-3- (2), CT-7 EX-A- (4) | — | exécutable : `test/securite.test.js` |
| TV-57 | `ct-7/ceremonies/` : procès-verbaux valides et invalides, CR-1 à CR-12, commande `ceremonie.mjs` | CT-7 CR- (12), CT-7 EX-5- (2), CT-7 EX-A- (3) | MN-32, MN-36, MN-37, MN-39, MN-92, MN-94 | exécutable : `test/securite.test.js` |
| TV-58 | `ct-7/attestations/` : exemple, 18 cas hors dossier, signatures croisées, outil de référence | CT-7 EX-A- (3), CT-7 EX-7- (9) | MN-81, MN-83, MN-87, MN-89 | exécutable : `test/securite.test.js` |
| TV-59 | `ct-7/matrice-conformite.json` et `ct-7/matrice/invalides/` : MX-1 à MX-9, tables 8.2, 8.4, 8.9 et clauses cellule par cellule | CT-7 MX- (9), CT-7 MC- (58), CT-7 T- (10), CT-7 L- (10), CT-7 EX-8- (10), CT-7 EX-A- (3) | — | exécutable : `test/conformite.test.js` |
| TV-60 | `ct-7/cles-de-test.json` : clés publiques et adresses recalculées | CT-7 EX-4- (1), CT-7 EX-A- (1), CT-7 CLE- (1) | — | exécutable : `test/securite.test.js` |
| TV-61 | Génération déterministe de `spec/vecteurs/ct-7` ; grilles des épreuves à part des consignes | CT-7 EX-A- (9) | — | exécutable : `test/securite.test.js` |
| TV-62 | Vérificateur Go indépendant de CT-7 : zéro discordance sur `spec/vecteurs/ct-7` | CT-7 CR- (12), CT-7 AT- (7), CT-7 MX- (5), CT-7 EX-A- (3) | MN-66, MN-97 | exécutable : `test/plan-de-tests.test.js`, étape de `ci.yml` |
| TV-63 | Confrontation tierce de `ct-7` : signatures des procès-verbaux et des attestations par ethers et eth-account | CT-7 EX-A- (3) | — | exécutable : `test/confrontation.test.js` |
| TV-64 | `ct-8/conteneurs/` : 36 cas, CO-1 à CO-14 | CT-8 CO- (14), CT-8 EX-A- (2) | MN-22 | exécutable : `test/deploiement.test.js` |
| TV-65 | `ct-8/controle-prealable/` : 33 cas, IP-1 à IP-13, collecte réelle sans réseau | CT-8 IP- (13), CT-8 EX-6- (6), CT-8 FL- (3), CT-8 EX-A- (2) | — | exécutable : `test/deploiement.test.js` |
| TV-66 | `ct-8/dimensionnement/` : 16 cas, DM-1 à DM-22, tables 9.5, 9.6 et valeurs de CT-8 EX-14.2 | CT-8 DM- (22), CT-8 EX-9- (4), CT-8 EX-14- (1), CT-8 EX-A- (2) | — | exécutable : `test/deploiement.test.js` |
| TV-67 | Table de traçabilité de CT-8 : `renvois.mjs`, TC-1 à TC-115 | CT-8 TC- (115), CT-8 EX-0- (2), CT-8 EX-A- (2) | — | exécutable : `test/deploiement.test.js` |
| TV-68 | Chaînes interdites dans `deploiement/` et `spec/vecteurs/ct-8/` | CT-8 EX-A- (1) | — | exécutable : `test/deploiement.test.js` |
| TV-69 | `ct-8/observation/` : marques, correspondance avec CT-3, journal d'exemple, rapport, OB-1 à OB-6 | CT-8 OB- (6), CT-8 EX-12- (15), CT-8 EX-A- (4) | — | exécutable : `test/exploitation.test.js` |
| TV-70 | `ct-8/journaux/`, `proces-verbaux/`, `consultations/` : vérification de journal, PV-1 à PV-10, CA-1 à CA-6, runbooks SV-8 | CT-8 PV- (10), CT-8 CA- (6), CT-8 SV- (1), CT-8 EX-11- (3), CT-8 EX-10- (2), CT-8 EX-A- (2), CT-7 EX-8- (1) | MN-96 | exécutable : `test/exploitation.test.js` |
| TV-71 | `ct-8/paquets/` : dix-sept cas de `cas.json`, deux constructions identiques, recette GNU tar | CT-8 PR- (12), CT-8 AV-PR- (4), CT-8 EX-13- (1), CT-8 EX-A- (10) | MN-78 | exécutable : `test/paquet-reviseur.test.js`, étape de `ci.yml` |
| TV-72 | Matériel des épreuves de CT-8 §14 présent et cohérent : consignes, grilles, entrées de dimensionnement | CT-8 EX-14- (3), CT-8 EX-A- (1) | — | exécutable : `test/exploitation.test.js` |
| TV-73 | Génération déterministe de `spec/vecteurs/ct-8` | CT-8 EX-A- (7) | — | exécutable : `test/deploiement.test.js`, `test/paquet-reviseur.test.js` |
| TV-74 | Vérificateur Go indépendant de CT-8 : zéro discordance sur `spec/vecteurs/ct-8` | CT-8 DM- (22), CT-8 IP- (13), CT-8 PV- (10), CT-8 CA- (5), CT-8 PR- (9), CT-8 OB- (4), CT-8 EX-A- (4) | MN-66 | exécutable : étape de `ci.yml` |
| TV-75 | Confrontation tierce de `ct-8` : GNU tar, `sha256sum`, `jq`, `tarfile` de Python | CT-8 EX-A- (7) | — | exécutable : `test/confrontation.test.js` |
| TV-76 | `ct-8/supervision/` : SV-1 à SV-7, règles d'alerte, extracteur, tableau de bord | CT-8 SV- (7), CT-8 EX-10- (2), CT-8 EX-A- (1) | MN-29 | à écrire (étape 7) |

## 8. Tests d'interopérabilité (TI-)

Sept des vingt entrées sont exécutables : confrontation OTLP TI-12,
certificat de commit TI-18, paquets lus par GNU tar et `tarfile` TI-20,
depuis l'étape 4, le client MCP de référence à travers le frontal du démon
(TI-3) et les SDK Python et TypeScript (TI-13), et, depuis l'étape 5, les
prestataires RFC 3161 et calendriers OpenTimestamps publics (TI-16, dont le
complément, un prestataire qualifié réel, est dû à l'étape 8) et le serveur
RFC 3161 interne (TI-17) ; les treize autres attendent un composant ou une
épreuve (étape 6, 7 ou 8).

**EX-8.1** Les trois correspondances d'export de CT-1 §12 ont chacune leur
sort : OpenTelemetry GenAI (TI-1, étape 8, validée par `weaver registry
live-check` contre le registre épinglé par CT-2 EX-6.25, R11-F42) ; projet
IETF « agent audit trail » (TI-2, étape 8, écarts consignés : premier
`prev_hash` nul, ES256 par défaut, préfixe de domaine en paramètre de
profil, R11-F47) ; SCITT : hors version 0 (justification NC-, CT-1 §12.3),
avec la proposition PD-2 (RFC 9942 publiée, R11-F44). **EX-8.2** Les huit
intégrations de la porte 2 sont TI-4 (Anthropic), TI-5 (OpenAI), TI-6
(Gemini), TI-7 (LangChain et LangGraph), TI-8 (CrewAI), TI-9 (LlamaIndex),
TI-10 (LiteLLM) et TI-11 (OpenTelemetry) ; chacune joue le scénario de CT-2
§19.2 avec le SDK ou le cadre à la version épinglée par CT-2 §6.4, dans un
réseau où l'hôte ne joint que l'enregistreur, et finit par un dossier
vérifié par les deux vérificateurs.

<!-- table TI -->
| Id | Objet | Identifiants couverts (famille : nombre) | Menaces | État |
|---|---|---|---|---|
| TI-1 | Export OpenTelemetry GenAI d'un événement (CT-1 §12.1) validé par le registre des conventions | CT-2 EX-6- (1) | — | à écrire (étape 8) |
| TI-2 | Export au format du projet IETF « agent audit trail » (CT-1 §12.2) relu par un vérificateur du projet |  | — | à écrire (étape 8) |
| TI-3 | Protocole MCP réel : client de référence (stdio et Streamable HTTP, ère moderne) à travers le frontal | CT-2 EX-3- (6), CT-2 EX-4- (28) | MN-1, MN-8, MN-9 | exécutable : `test/enregistreur-mcp-client-reference.test.js` |
| TI-4 | Intégration Anthropic : SDK officiel avec `ANTHROPIC_BASE_URL` vers la passerelle (hors flux et flux) | CT-2 EX-5- (8) | — | à écrire (étape 8) |
| TI-5 | Intégration OpenAI : Chat Completions et Responses par le SDK officiel vers la passerelle | CT-2 EX-5- (4) | — | à écrire (étape 8) |
| TI-6 | Intégration Gemini : `google-genai` vers la passerelle (route `gemini`, `x-goog-api-key`) | CT-2 EX-19- (1), CT-2 EX-5- (4) | — | à écrire (étape 8) |
| TI-7 | Intégration LangChain et LangGraph : intergiciel `MiddlewareNoortrace`, `wrap_tool_call` | CT-2 EX-6- (12) | — | à écrire (étape 8) |
| TI-8 | Intégration CrewAI : crochets `before_tool_call` et `after_tool_call` enregistrés en dernier | CT-2 EX-6- (1) | — | à écrire (étape 8) |
| TI-9 | Intégration LlamaIndex : enveloppe de chaque outil | CT-2 EX-6- (1) | — | à écrire (étape 8) |
| TI-10 | Intégration LiteLLM : `CustomLogger` en bibliothèque et LiteLLM en mandataire devant la passerelle | CT-2 EX-6- (2) | — | à écrire (étape 8) |
| TI-11 | Intégration OpenTelemetry : agent instrumenté par un SDK OpenTelemetry vers le point d'entrée OTLP de l'enregistreur | CT-2 EX-6- (5) | MN-15, MN-16 | à écrire (étape 8) |
| TI-12 | Requêtes OTLP confrontées à `opentelemetry-proto` et réponses `ExportTraceServiceResponse` exactes | CT-2 EX-6- (2) | — | exécutable : `test/confrontation.test.js`, `test/enregistreur-r05.test.js` |
| TI-13 | SDK Python et TypeScript : interface publique, versions de langage, aucune exception vers l'agent | CT-2 EX-6- (7) | — | exécutable : `test/enregistreur-sdk-langages.test.js` |
| TI-14 | Canal réel noyau ↔ service d'approbation et console ↔ service : authentification, `evaluer`, `GET /v0/etat`, sessions | CT-3 EX-12- (13), CT-2 EX-7- (2) | MN-51, MN-77 | à écrire (étape 6) |
| TI-15 | Supports WORM réels (S3, Azure, GCS) : requêtes exactes, verrou, rétention, journal d'accès | CT-2 EX-12- (4), CT-2 EX-18- (1), CT-8 EX-11- (2) | MN-27, MN-28, MN-29 | à écrire (étape 7) |
| TI-16 | Prestataires RFC 3161 et calendriers OpenTimestamps réels : fiche de prestataire, `min_interval_ms`, qualification | CT-5 EX-11- (5), CT-5 AN- (9), CT-5 EX-5- (9), CT-5 EX-6- (3) | MN-62, MN-76 | exécutable : `test/ancrage-prestataires-reels.test.js`, `test/ancrage-composant-pannes.test.js` ; complément à écrire (étape 8) |
| TI-17 | Serveur RFC 3161 interne : AN-22 à AN-31 vérifiées sur un jeton émis, épreuve de redémarrage (AN-26) | CT-5 EX-7- (4), CT-5 AN- (10), CT-7 CLE- (1) | MN-42 | exécutable : `test/enregistreur-ancrage-exigences.test.js`, `test/enregistreur-ancrage-parcours.test.js`, `test/ancrage-tsa-interne-autorite.test.js`, `test/ancrage-tsa-interne-reponse.test.js`, `test/ancrage-tsa-interne-serveur.test.js` |
| TI-18 | Nœud noorcore et certificat de commit : JSON-RPC `noor_getCommitCertificate`, parité Go/JavaScript, confrontation go-ethereum | CT-6 EX-11- (21) | MN-55 | exécutable : `test/certificatCommit.test.js`, `test/confrontation.test.js` |
| TI-19 | Mode ICAP : raccord à un mandataire existant, sources admises | CT-2 EX-5- (2), CT-8 EX-5- (1) | MN-12 | exécutable : `test/enregistreur-modele-squid.test.js` |
| TI-20 | Export des pièces d'un dossier vers un paquet réviseur lu par des outils tiers (GNU tar, `tarfile`) | CT-8 EX-13- (3), CT-6 EX-14- (1) | — | exécutable : `test/confrontation.test.js` |

## 9. Tests de bout en bout (TE-)

**EX-9.1** TE-1 (assurance : agent de souscription et de tarification en
assurance de personnes) et TE-2 (administration : agent qui instruit des
demandes de prestations publiques) sont les deux cas de démonstration du
plan ; ils traversent la chaîne de la capture au dossier vérifié avec des
données fictives seulement, sur le système de référence de 11.1, et leur
oracle est le verdict des deux vérificateurs de CT-6 sur les dossiers et le
paquet produits. TE-3 est la démonstration de référence en une commande
(CT-2 §19). TE-4 (depuis l'étape 3) et TE-5 (de l'événement au dossier
vérifié sur les vecteurs) sont exécutables.

**EX-9.2** TE-4 (parcours CT-4 §7 sur le réseau de développement noorcore)
s'exécute par le script d'épreuve `scripts/e2e/parcours-registre.mjs`
(étape 3), qui démarre et arrête le réseau et rend un verdict JSON ; le test
qui le lance se met en attente sans binaire noorcore ; aucune étape de la CI
n'exécute noorcore (CT-5 EX-A.7) ; les deux relectures de CT-4 §7.12 sans
compte rendu dans le dépôt (R10-NV4) ne valent pas ce test.

<!-- table TE -->
| Id | Objet | Identifiants couverts (famille : nombre) | Menaces | État |
|---|---|---|---|---|
| TE-1 | Cas de démonstration « assurance » : agent de souscription et de tarification, de la capture au dossier vérifié | CT-2 EX-19- (3), CT-3 EX-14- (1), CT-6 EX-14- (1), CT-8 EX-13- (1) | MN-1, MN-18, MN-22 | à écrire (étape 8) |
| TE-2 | Cas de démonstration « administration » : agent qui instruit des demandes de prestations publiques | CT-2 EX-19- (1), CT-3 EX-14- (1), CT-6 EX-14- (1), CT-8 EX-13- (1) | MN-1, MN-44 | à écrire (étape 8) |
| TE-3 | Démonstration de référence en une commande : `docker compose up`, moins de deux minutes, verdict imprimé (CT-2 §19) | CT-2 EX-19- (5) | MN-1, MN-22 | à écrire (étape 8) |
| TE-4 | Parcours CT-4 §7 sur le réseau de développement noorcore : client inscrit, racine ancrée, période close, certificats capturés | CT-4 EX-4- (18), CT-4 EX-6- (23), CT-4 EX-10- (9), CT-4 EX-11- (1), CT-4 EX-3- (2), CT-4 EX-5- (6), CT-4 EX-A- (1) | MN-55, MN-58 | exécutable : `test/registre-dev.test.js` |
| TE-5 | De l'événement au dossier vérifié sur les vecteurs : `journal-demo` de CT-2, export des parties du registre, vérificateur de CT-6 | CT-2 EX-12- (1), CT-4 EX-9- (1), CT-6 EX-6- (1), CT-6 EX-8- (1) | MN-23 | exécutable : `test/enregistreur.test.js`, `test/registreCt4.test.js`, `test/verificateur.test.js` |
| TE-6 | Installation rapide IR-1 à IR-8 sur un hôte neuf, premier dossier vérifié | CT-8 IR- (8), CT-8 EX-7- (4), CT-8 EX-3- (1) | MN-14 | à écrire (étape 7) |
| TE-7 | Installation complète IC-1 à IC-18 sur une machine vierge, en moins d'une journée, avec le seul document | CT-8 IC- (18), CT-8 EX-8- (6), CT-8 EX-3- (14), CT-8 TP- (8), CT-7 EX-5- (9), CT-7 EX-7- (8) | MN-14, MN-33, MN-88 | à écrire (étape 7) |
| TE-8 | Flux réseau FL-1 à FL-31 observés sur le déploiement de test et runbooks RB-1 à RB-8 rejoués | CT-8 FL- (31), CT-8 RB- (8), CT-8 EX-5- (7), CT-8 EX-10- (19) | MN-29, MN-75, MN-96 | à écrire (étape 7) |
| TE-9 | Sauvegarde et reprise : chemins A, B et C, continuité de la chaîne, procès-verbaux | CT-8 EX-11- (19), CT-2 EX-12- (2), CT-7 EX-8- (3) | MN-19, MN-26 | à écrire (étape 7) |
| TE-10 | Mode observation de bout en bout : capture sans blocage, rapport d'observation, passage au mode bloquant | CT-8 EX-12- (1), CT-2 EX-14- (5), CT-3 EX-11- (5) | — | à écrire (étape 7) |
| TE-11 | Haute disponibilité à écrivain unique : bascule du bail, pertes admises, jeton de clôture (CT-2 §13) | CT-2 EX-13- (10), CT-2 EX-12- (23) | MN-19, MN-26 | exécutable : `test/enregistreur-ha-bascule.test.js` |
| TE-12 | Ancrage complet d'une racine : point de contrôle, ancre au registre, jeton RFC 3161, preuve OpenTimestamps, dossier vérifié hors ligne | CT-5 EX-9- (9), CT-5 EX-10- (6), CT-5 AN- (12), CT-5 EX-3- (5), CT-5 EX-4- (4), CT-5 EX-8- (2), CT-6 EX-13- (17), CT-6 EX-4- (7) | MN-17, MN-24 | exécutable : `test/enregistreur-ancrage-parcours.test.js` |
| TE-13 | Console : un approbateur s'inscrit, signe une décision depuis son portefeuille, le dossier exporté passe le vérificateur | CT-3 EX-13- (13), CT-3 EX-14- (1) | MN-35, MN-51 | à écrire (étape 6) |
| TE-14 | Journal de l'enregistreur sur lui-même : JS-1 à JS-12 observés sur le démon | CT-7 JS- (12), CT-7 EX-6- (3), CT-2 EX-17- (4) | MN-18, MN-96 | exécutable : `test/enregistreur-journal-soi.test.js` ; complément à écrire (étape 7) |
| TE-15 | Construction des images de référence : reproductibilité, `docker inspect`, volume nommé, compagnon d'immuabilité | CT-8 EX-4- (1), CT-8 EX-3- (4) | MN-22, MN-25 | à écrire (étape 7) |
| TE-16 | Matrice des pannes de CT-2 §14 rejouée sur le démon : classification des outils, ce qui est rendu à l'hôte, ce qui est journalisé, mode dégradé | CT-2 EX-14- (12) | MN-10, MN-21, MN-26, MN-33 | exécutable : `test/enregistreur-signataires-parcours.test.js`, `test/enregistreur-mcp-exigences.test.js`, `test/enregistreur-coeur-reprise.test.js`, `test/enregistreur-modele-exigences.test.js`, `test/enregistreur-mcp-parcours.test.js`, `test/enregistreur-politique-exigences.test.js`, `test/enregistreur-sdk-exigences.test.js`, `test/enregistreur-coeur-approbations.test.js`, `test/enregistreur-ancrage-exigences.test.js`, `test/enregistreur-journal-soi.test.js`, `test/enregistreur-worm-exigences.test.js`, `test/enregistreur-coeur-config.test.js`, `test/enregistreur-modele-securite.test.js`, `test/enregistreur-ha-exigences.test.js`, `test/enregistreur-ancrage-parcours.test.js`, `test/enregistreur-coeur-attente-bornes.test.js` ; complément à écrire (étape 8) |
| TE-17 | Supervision en charge : alertes prescrites levées sur incident, métriques `noortrace_*`, dossier produit sous charge vérifié | CT-2 EX-17- (4) | MN-29 | à écrire (étape 7) |

## 10. Tests adversariaux (TA-)

Un test adversarial éprouve une **réponse** de CT-7 §3.4 par l'attaque qu'elle
est censée arrêter, et prouve qu'il l'éprouve vraiment : le même test, rejoué
sur une copie où la réponse est retirée, doit échouer. Le niveau TA- reprend
les 98 menaces du modèle, une par une, puis les cinq scénarios adversariaux du
plan de projet, qui composent ces menaces de bout en bout. La section 10.6 dit
ce que les tests éprouvent de chaque risque accepté et ce qu'ils laissent hors
de portée.

### 10.1 Règles

**EX-10.1** Chaque menace MN-n de `spec/vecteurs/ct-7/menaces.json` DOIT avoir
dans le catalogue exactement un test `TA-n` de niveau `TA`, de membre
`adversarial.threat` égal à `MN-n` et de membre `threats` égal à `[MN-n]`.
Un TA- porte, dans son bloc `adversarial` (EX-4.1) : la **réponse retirée**
(`response_removed` :
`what`, la réponse telle que CT-7 la nomme avec ses exigences ; `how`, la
modification qui la retire ; `where`, le fichier, la configuration, le
générateur, la procédure ou le composant de phase 2 où elle se retire),
l'**attaque** jouée, l'observation attendue **avec** la réponse (le test passe)
et **sans** elle (le test échoue), les préconditions, les pas, l'oracle et
l'état.

**EX-10.2** Le membre `adversarial.threat_test_text` d'un TA- est la valeur
`test` de la menace dans `menaces.json`, préfixe « Le test échoue si la
réponse est retirée : » compris ; `covers` est la liste `response.refs` de
la menace, dans son ordre ; `adversarial.component` son composant ;
`adversarial.accepted_risk` l'identifiant de son risque accepté ou `null`.
L'outil de couverture vérifie ces égalités ; une menace sans TA-, un TA- sans
menace ou un TA- dont le texte diffère de `menaces.json` est une discordance.

**EX-10.3** L'état d'un TA- suit EX-3.10. `executable` : le test tourne
aujourd'hui et cite un ou plusieurs tests du dépôt par leur fichier et le
titre exact de leur `it` (règle de couverture (d)) ; quand le test est dans
`test/adversarial.test.js`, il DOIT fabriquer un mutant et exiger qu'il soit
tué (10.3) ; quand une partie de la réponse attend un composant, l'entrée
porte `complement` (étape et blocage), et la partie citée seule est
exécutée. `a_ecrire` : le test n'existe pas ; l'entrée porte l'étape du plan
qui livre l'objet manquant (`phase2_step`), ce qui bloque (`blocking`), ses
préconditions, ses pas et son oracle exacts ; un test possible dès
maintenant sur le dépôt mais non écrit est rattaché à l'étape 8 ; une
épreuve de procédure humaine (répétition de cérémonie : TA-95, TA-97)
aussi. Un TA- `executable` DOIT, soit citer un `it` de
`test/adversarial.test.js` qui fabrique son mutant et le tue (titre terminé
par « (tué) », ou « oracle sur le vecteur » pour EX-10.4), soit citer une
étape de `ci.yml` (`ci_steps`), soit porter `complement` ; sans
`complement`, ni son oracle ni ses pas n'annoncent une partie « à écrire »,
« à ajouter » ou « à éprouver » (l'outil de couverture le vérifie). Le
membre `adversarial.execution` dit où le test se joue : `vecteurs_et_depot`
(sur les vecteurs et les bibliothèques du dépôt) ou `phase_2` (il se joue
sur un composant de la phase 2, attendu ou livré). Aucun résultat d'exécution n'est écrit pour un test qui n'a pas
été exécuté.

**EX-10.4** Un TA- exécutable dont l'oracle porte sur un vecteur et dont la
réponse vit dans un générateur (TA-23, TA-72) nomme le générateur comme lieu
de la réponse retirée ; le mutant est alors la régénération, et
l'observation sans la réponse est le `git diff --exit-code` non vide de
l'intégration continue. Ces tests ne fabriquent pas de copie des
générateurs ; leurs pas sont « rejouer l'oracle sur le vecteur » puis
« régénérer et comparer ». Une réponse qui ne vit dans aucun générateur ni
aucune bibliothèque du dépôt (TA-41 : le planificateur de référence ne
résout aucun secret) n'a pas d'oracle sur les vecteurs : l'entrée est
`a_ecrire`.

### 10.2 Forme d'une entrée

Une entrée TA- suit `$defs/test` du schéma `plan-de-tests-v0` avec son bloc
`adversarial` (annexe A). Exemple, imprimé depuis `catalogue.json` (TA-3) :

<!-- schema: plan-de-tests/test -->
```json
{
  "id": "TA-3",
  "level": "TA",
  "title": "Réponse retirée : Plafond max_calls d'une fenêtre d'approbation (CT-3 EX-5.2, EX-5.5)",
  "specs": [
    "CT-3"
  ],
  "covers": [
    "CT-3 EX-11.8",
    "CT-3 EX-5.2",
    "CT-3 EX-5.5",
    "CT-3 §14.1"
  ],
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
    ],
    "command": "npx mocha --timeout 600000 test/adversarial.test.js && npx hardhat --config hardhat.config.mjs test test/approbation.test.js"
  },
  "threats": [
    "MN-3"
  ],
  "adversarial": {
    "threat": "MN-3",
    "component": "hote_agent",
    "response_removed": {
      "what": "Plafond max_calls d'une fenêtre d'approbation (CT-3 EX-5.2, EX-5.5)",
      "how": "Retirer la condition w.remaining >= 1 de la recherche d'une fenêtre couvrante",
      "where": "scripts/lib/approbation.mjs (fenêtre couvrante, EX-5.5)"
    },
    "attack": "Troisième appel de 3 000 CHF sous une fenêtre dont les deux unités sont consommées (cas fenetre-epuisee de evaluation/niveaux.json).",
    "expected_with_response": "evaluer rend a_approuver sur la règle « fenetre moyenne » : l'appel est retenu.",
    "expected_without_response": "evaluer rend autorise ; le test échoue.",
    "execution": "vecteurs_et_depot",
    "accepted_risk": "RA-3",
    "threat_test_text": "Le test échoue si la réponse est retirée : la politique de l'exemple de CT-3 §4.3 est évaluée sur deux appels de 3 000 CHF couverts par une fenêtre au plafond atteint ; le troisième appel doit être retenu ; sans le plafond `max_calls`, il est autorisé et le test échoue."
  }
}
```

### 10.3 Fabrique de mutants

**EX-10.5** Un mutant est une copie de `scripts/lib`, `scripts/verify`,
`scripts/conformite` et `scripts/registre` dans un répertoire temporaire, où
`spec/`,
`node_modules/`, `package.json` et `deploiement/` sont des liens symboliques
vers le dépôt, et où un ou plusieurs remplacements textuels sont appliqués à
un fichier copié. Chaque remplacement nomme la chaîne retirée, qui DOIT
apparaître exactement une fois dans le fichier (ou au moins une fois quand la
réponse est portée par plusieurs appels de même forme : fautes CR-2, contrôles
CP-4, refus `adresse_deja_attribuee`) ; sinon la fabrique s'arrête et le test
échoue. Le mutant est importé par son chemin de fichier (les modules du dépôt
et du mutant coexistent dans le même processus) ou exécuté par sa ligne de
commande ; les répertoires sont détruits à la fin de la suite. Pour un
composant de la phase 2 livré (révision 0.2), le mutant est de même une
copie de son paquet (`paquets/<nom>` : `src/`, `bin/`, `schemas/`,
`package.json`) dans un répertoire temporaire où `node_modules/` est un
lien symbolique vers celui du dépôt, avec les mêmes règles de
remplacement ; un démon mutant est lancé par le `bin/` de la copie.

**EX-10.6** Un remplacement retire la réponse et rien d'autre : une condition
devient `false`, un appel devient un appel vide, un statut est posé réussi.
Les formes admises, avec leur équivalent dans les outils de test par mutation
(CT-9 R11-F27) : retirer une condition (« remove conditionals »), retirer un
appel (« void method calls »), forcer un résultat (« true returns »). Un
mutant dont le remplacement change le format de sortie ou lève une exception
avant l'oracle est un mutant mal posé, pas un mutant tué.

**EX-10.7** Un test de `test/adversarial.test.js` rejoue d'abord l'oracle sur la
référence et exige le verdict des vecteurs (`attendu.json`, trace, cas), puis
sur le mutant et exige la négation de l'oracle (la vérification nommée
disparaît des échecs, la trace diverge, la remise est scellée, le cas est
accepté). Les deux attentes sont dans le même `it`, dont le titre commence par
l'identifiant TA- (ou les identifiants, séparés par « et ») puis la menace
entre parenthèses, et se termine par « (tué) » ou « (tués) ». Trois formes
sont admises en plus : (1) après la liste des menaces, un qualificatif
séparé par « , » et sans parenthèse (« partie exécutable ; … ») ; (2) pour
les oracles sur un vecteur d'EX-10.4 (TA-23, TA-72), le qualificatif
« oracle sur le vecteur » à la place de « (tué) », le mutant étant la
régénération ; (3) un `it` partagé par plusieurs TA- dont la réponse est la
même nomme chacun d'eux (« TA-17 et TA-61 (MN-17, MN-61) : … ») et chaque
entrée nommée le cite. Un TA- ne cite jamais un `it` dont le titre ne le
nomme pas.

**EX-10.8** Le fichier se lit depuis `test/` ; il admet `NOORTRACE_RACINE`
(racine du dépôt) et `NOORTRACE_TMP` (répertoire des mutants, par défaut
celui du système). Aucun de ses `it` n'exige `go` : la parité de l'outil
JavaScript avec le vérificateur Go de `ct-7` (CT-7 EX-A.21) est un test de
`test/plan-de-tests.test.js` cité par TV-62, mis en attente sans `go` comme
le rejeu Go de `test/confrontation.test.js` ; TA-97 (comparaison au second
outil par le signataire) est une épreuve de procédure, à écrire.

### 10.4 Les 98 tests

Table imprimée depuis `catalogue.json` (`tests` de niveau `TA`, TA-1 à TA-98 ;
les champs complets sont dans le fichier). « Tests » cite les fichiers des
`it` qui exécutent l'oracle ; le titre exact de chaque `it` est dans le
catalogue.

<!-- table TA -->
| TA | MN | Composant | État | Réponse retirée (où) | Tests |
|---|---|---|---|---|---|
| TA-1 | MN-1 | `hote_agent` | à écrire (étape 8) | deploiement (composition docker compose de CT-2 §19.1) | — |
| TA-2 | MN-2 | `hote_agent` | exécutable | paquets/enregistreur/src/mcp/delegation.mjs (resoudreDelegation) | `test/adversarial.test.js` |
| TA-3 | MN-3 | `hote_agent` | exécutable | scripts/lib/approbation.mjs (fenêtre couvrante, EX-5.5) | `test/adversarial.test.js`, `test/approbation.test.js` |
| TA-4 | MN-4 | `hote_agent` | exécutable | scripts/lib/capture.mjs | `test/adversarial.test.js`, `test/enregistreur.test.js` |
| TA-5 | MN-5 | `hote_agent` | exécutable ; complément à écrire (étape 8) | scripts/lib/approbation.mjs (ServiceApprobation.consommer) | `test/adversarial.test.js`, `test/approbation.test.js` |
| TA-6 | MN-6 | `hote_agent` | exécutable | scripts/lib/approbation.mjs (ServiceApprobation, ouverture d'un ticket) | `test/adversarial.test.js`, `test/approbation.test.js` |
| TA-7 | MN-7 | `mandataire_mcp` | exécutable | scripts/lib/capture.mjs (agregerOutils) ; paquets/enregistreur/src/mcp/frontal.mjs (recalculer) | `test/adversarial.test.js`, `test/enregistreur.test.js` |
| TA-8 | MN-8 | `mandataire_mcp` | exécutable | paquets/enregistreur/src/mcp/hote-http.mjs (_authentifier) | `test/adversarial.test.js` |
| TA-9 | MN-9 | `mandataire_mcp` | exécutable | paquets/enregistreur/src/mcp/amont.mjs (lancement des serveurs stdio) | `test/adversarial.test.js` |
| TA-10 | MN-10 | `mandataire_mcp` | exécutable | scripts/lib/capture.mjs (reprise) ; paquets/enregistreur/src/coeur.mjs (relais en deux temps) | `test/enregistreur.test.js`, `test/adversarial.test.js` |
| TA-11 | MN-11 | `passerelle_modele` | exécutable | paquets/enregistreur/src/modele/passerelle.mjs (envoi au fournisseur) ; schéma de configuration (auth_header, credentials propre) | `test/enregistreur-r05.test.js`, `test/adversarial.test.js` |
| TA-12 | MN-12 | `passerelle_modele` | exécutable | paquets/enregistreur/src/modele/icap.mjs (_connexion) ; configuration | `test/adversarial.test.js` |
| TA-13 | MN-13 | `passerelle_modele` | exécutable | scripts/lib/capture.mjs (echangeModele, branche gemini) | `test/adversarial.test.js`, `test/enregistreur-r05.test.js` |
| TA-14 | MN-14 | `passerelle_modele` | exécutable ; complément à écrire (étape 8) | spec/schemas/configuration-enregistreur-v0.schema.json ; démonstration | `test/adversarial.test.js` |
| TA-15 | MN-15 | `sdk_otel` | exécutable | scripts/lib/otel.mjs (nomOutil) | `test/adversarial.test.js`, `test/enregistreur-r05.test.js` |
| TA-16 | MN-16 | `sdk_otel` | exécutable | scripts/lib/otel.mjs (nomOutil) | `test/adversarial.test.js`, `test/enregistreur-r05.test.js` |
| TA-17 | MN-17 | `ecrivain_stockage` | exécutable | scripts/lib/verificateur.mjs, horodatage.mjs | `test/adversarial.test.js`, `test/verificateur.test.js` |
| TA-18 | MN-18 | `ecrivain_stockage` | à écrire (étape 8) | procédure du client (CT-7 EX-3.8) ; outil de rapprochement de la démonstration | — |
| TA-19 | MN-19 | `ecrivain_stockage` | exécutable | paquets/enregistreur/src/bail.mjs (MagasinBailFichier.valide) | `test/adversarial.test.js` |
| TA-20 | MN-20 | `ecrivain_stockage` | exécutable | scripts/lib/capture.mjs (relireSegment) | `test/adversarial.test.js` |
| TA-21 | MN-21 | `ecrivain_stockage` | exécutable | scripts/lib/capture.mjs (Ecrivain.horodater) | `test/adversarial.test.js`, `test/enregistreur.test.js` |
| TA-22 | MN-22 | `ecrivain_stockage` | à écrire (étape 8) | deploiement (volumes de la démonstration) | — |
| TA-23 | MN-23 | `ecrivain_stockage` | exécutable | générateur scripts/vecteurs/generer-ct2.mjs (le vecteur régénéré diffère : git diff en CI) | `test/adversarial.test.js`, `test/enregistreur.test.js` |
| TA-24 | MN-24 | `ecrivain_stockage` | exécutable | paquets/enregistreur/src/coffre.mjs (CoffreOriginaux.dechiffrer) | `test/adversarial.test.js` |
| TA-25 | MN-25 | `ecrivain_stockage` | à écrire (étape 7) | démarrage du démon (PA-4) ; procédure CT-7 EX-3.14 | — |
| TA-26 | MN-26 | `ecrivain_stockage` | exécutable | paquets/enregistreur/src/coeur.mjs (pas 7 du démarrage) ; émission des points aux instants alignés (CT-2 EX-12.24) | `test/adversarial.test.js` |
| TA-27 | MN-27 | `worm_gel` | exécutable | scripts/lib/worm.mjs (etatVerrou) | `test/adversarial.test.js`, `test/enregistreur-r05.test.js` |
| TA-28 | MN-28 | `worm_gel` | exécutable | scripts/lib/worm.mjs (verifierGarde) | `test/adversarial.test.js`, `test/enregistreur-r05.test.js` |
| TA-29 | MN-29 | `worm_gel` | à écrire (étape 7) | démon (fil de supervision) ; règles d'alerte de CT-8 §10 | — |
| TA-30 | MN-30 | `cles` | exécutable | paquets/enregistreur/src/configuration.mjs (reglesHorsSchema) | `test/adversarial.test.js` |
| TA-31 | MN-31 | `cles` | exécutable | paquets/enregistreur/src/signataires/rapprochement.mjs (rapprocher) ; outil noortrace-ctl cle rapprocher | `test/adversarial.test.js` |
| TA-32 | MN-32 | `cles` | exécutable | scripts/lib/securite.mjs (verifierCeremonie) | `test/adversarial.test.js`, `test/securite.test.js` |
| TA-33 | MN-33 | `cles` | exécutable | paquets/enregistreur/src/ecrivain.mjs (signature de l'événement) ; paquets/enregistreur/src/coeur.mjs (_santeSignataire) | `test/adversarial.test.js` |
| TA-34 | MN-34 | `cles` | exécutable | scripts/lib/registre.mjs | `test/adversarial.test.js`, `test/verificateur.test.js` |
| TA-35 | MN-35 | `cles` | à écrire (étape 8) | console/ (page de référence) | — |
| TA-36 | MN-36 | `cles` | exécutable | scripts/lib/securite.mjs | `test/adversarial.test.js`, `test/securite.test.js` |
| TA-37 | MN-37 | `cles` | exécutable | scripts/lib/securite.mjs | `test/adversarial.test.js`, `test/securite.test.js` |
| TA-38 | MN-38 | `cles` | exécutable | scripts/lib/approbation.mjs (lecture du jeu) | `test/adversarial.test.js`, `test/approbation.test.js` |
| TA-39 | MN-39 | `cles` | exécutable | scripts/lib/securite.mjs | `test/adversarial.test.js`, `test/securite.test.js` |
| TA-40 | MN-40 | `cles` | exécutable ; complément à écrire (étape 8) | scripts/registre/noortrace-registre.mjs | `test/registreCt4.test.js` |
| TA-41 | MN-41 | `cles` | exécutable ; complément à écrire (étape 8) | paquets/ancrage (file durable, traces du planificateur, acquisitions.ndjson, journal) et paquets/enregistreur (resoudreSecretsAncrage, journal d'exploitation) | `test/enregistreur-ancrage-exigences.test.js` |
| TA-42 | MN-42 | `cles` | exécutable ; complément à écrire (étape 8) | scripts/lib/securite.mjs | `test/adversarial.test.js`, `test/securite.test.js` |
| TA-43 | MN-43 | `cles` | exécutable ; complément à écrire (étape 8) | spec/schemas/configuration-enregistreur-v0.schema.json ($defs/secret_reference) ; démon (EX-17.3) en phase 2 | `test/adversarial.test.js` |
| TA-44 | MN-44 | `approbation_console` | exécutable | scripts/lib/approbation.mjs (verifierRemise) | `test/adversarial.test.js`, `test/approbation.test.js` |
| TA-45 | MN-45 | `approbation_console` | exécutable | scripts/lib/console.mjs (verifierSignature) | `test/adversarial.test.js`, `test/console.test.js` |
| TA-46 | MN-46 | `approbation_console` | exécutable | scripts/lib/console.mjs (Decouverte) | `test/adversarial.test.js`, `test/console.test.js` |
| TA-47 | MN-47 | `approbation_console` | exécutable | scripts/lib/console.mjs (annuaire) | `test/adversarial.test.js`, `test/console.test.js` |
| TA-48 | MN-48 | `approbation_console` | exécutable | scripts/lib/approbation.mjs (verifierRemise) | `test/adversarial.test.js`, `test/approbation.test.js` |
| TA-49 | MN-49 | `approbation_console` | exécutable | scripts/lib/approbation.mjs (normaliserSignature) | `test/adversarial.test.js`, `test/approbation.test.js` |
| TA-50 | MN-50 | `approbation_console` | exécutable | scripts/lib/approbation.mjs (geler) | `test/adversarial.test.js`, `test/approbation.test.js` |
| TA-51 | MN-51 | `approbation_console` | à écrire (étape 6) | service d'approbation (configuration, CT-8 PD-7) | — |
| TA-52 | MN-52 | `approbation_console` | à écrire (étape 8) | console/ (configuration par défaut) | — |
| TA-53 | MN-53 | `registre` | exécutable ; complément à écrire (étape 8) | scripts/registre/noortrace-registre.mjs (reassigner) | `test/registreCt4.test.js` |
| TA-54 | MN-54 | `registre` | exécutable | scripts/lib/registre.mjs | `test/adversarial.test.js`, `test/registre.test.js`, `test/verificateur.test.js` |
| TA-55 | MN-55 | `registre` | à écrire (étape 8) | chain/ (configuration du réseau de développement) | — |
| TA-56 | MN-56 | `registre` | exécutable | scripts/lib/conventions-registre.mjs (verifierCapture) | `test/adversarial.test.js`, `test/registreCt4.test.js` |
| TA-57 | MN-57 | `registre` | à écrire (étape 8) | scripts/lib/conventions-registre.mjs (condenseInscription) | — |
| TA-58 | MN-58 | `registre` | à écrire (étape 8) | scripts/lib/ancrage.mjs (echecRegistre) | — |
| TA-59 | MN-59 | `registre` | exécutable | scripts/lib/registre.mjs | `test/adversarial.test.js`, `test/registre.test.js`, `test/verificateur.test.js` |
| TA-60 | MN-60 | `ancrage` | exécutable | scripts/lib/ancrage.mjs (planificateur, réponse RFC 3161) | `test/adversarial.test.js`, `test/ancrage.test.js` |
| TA-61 | MN-61 | `ancrage` | exécutable ; complément à écrire (étape 8) | scripts/lib/horodatage.mjs, scripts/lib/ots.mjs | `test/adversarial.test.js`, `test/verificateur.test.js`, `test/horodatage.test.js` |
| TA-62 | MN-62 | `ancrage` | exécutable ; complément à écrire (étape 8) | scripts/lib/ancrage.mjs (relever) | `test/adversarial.test.js`, `test/ancrage.test.js`, `test/enregistreur-ancrage-exigences.test.js` |
| TA-63 | MN-63 | `ancrage` | exécutable | scripts/lib/ancrage.mjs | `test/adversarial.test.js`, `test/ancrage.test.js` |
| TA-64 | MN-64 | `ancrage` | exécutable | scripts/lib/ancrage.mjs (reconstruire) | `test/adversarial.test.js`, `test/ancrage.test.js` |
| TA-65 | MN-65 | `ancrage` | exécutable | scripts/lib/ancrage.mjs (verifierConfiguration) | `test/adversarial.test.js` |
| TA-66 | MN-66 | `verificateur` | exécutable ; complément à écrire (étape 8) | .github/workflows/ci.yml, job vecteurs | `test/confrontation.test.js` |
| TA-67 | MN-67 | `verificateur` | exécutable | scripts/lib/verificateur.mjs | `test/adversarial.test.js`, `test/verificateur.test.js` |
| TA-68 | MN-68 | `verificateur` | exécutable ; complément à écrire (étape 8) | scripts/lib/horodatage.mjs (lireDER) | `test/adversarial.test.js`, `test/verificateur.test.js`, `test/horodatage.test.js` |
| TA-69 | MN-69 | `verificateur` | exécutable | scripts/lib/registre.mjs, scripts/lib/verificateur.mjs | `test/adversarial.test.js`, `test/verificateur.test.js` |
| TA-70 | MN-70 | `verificateur` | exécutable | scripts/lib/ots.mjs | `test/adversarial.test.js`, `test/verificateur.test.js` |
| TA-71 | MN-71 | `exploitant` | exécutable | scripts/lib/registre.mjs | `test/adversarial.test.js`, `test/verificateur.test.js` |
| TA-72 | MN-72 | `exploitant` | exécutable | générateur generer-ct4.mjs (le vecteur régénéré diffère) | `test/adversarial.test.js`, `test/registreCt4.test.js` |
| TA-73 | MN-73 | `exploitant` | exécutable ; complément à écrire (étape 8) | scripts/registre/noortrace-registre.mjs (reassigner, administrer-jeu) | `test/registreCt4.test.js` |
| TA-74 | MN-74 | `administrateur_client` | exécutable | scripts/lib/journal.mjs | `test/adversarial.test.js`, `test/journal.test.js` |
| TA-75 | MN-75 | `administrateur_client` | à écrire (étape 7) | tâche d'exploitation hors du démon (CT-8 §11.12) | — |
| TA-76 | MN-76 | `reseau` | exécutable | scripts/lib/ancrage.mjs | `test/adversarial.test.js`, `test/ancrage.test.js` |
| TA-77 | MN-77 | `reseau` | à écrire (étape 6) | démon (client du service d'approbation) | — |
| TA-78 | MN-78 | `administrateur_client` | exécutable | scripts/lib/verificateur.mjs (fragmentPerimetre) | `test/adversarial.test.js`, `test/verificateur.test.js` |
| TA-79 | MN-79 | `verificateur` | exécutable | scripts/lib/securite.mjs | `test/adversarial.test.js`, `test/journal.test.js` |
| TA-80 | MN-80 | `verificateur` | exécutable | scripts/lib/securite.mjs | `test/adversarial.test.js`, `test/journal.test.js` |
| TA-81 | MN-81 | `verificateur` | exécutable | scripts/lib/securite.mjs (verifierAT1aAT4) | `test/adversarial.test.js`, `test/securite.test.js` |
| TA-82 | MN-82 | `administrateur_client` | exécutable | scripts/lib/securite.mjs | `test/adversarial.test.js`, `test/journal.test.js` |
| TA-83 | MN-83 | `verificateur` | exécutable | scripts/lib/securite.mjs | `test/adversarial.test.js`, `test/securite.test.js` |
| TA-84 | MN-84 | `ecrivain_stockage` | exécutable | scripts/lib/securite.mjs | `test/adversarial.test.js`, `test/journal.test.js` |
| TA-85 | MN-85 | `ecrivain_stockage` | exécutable | scripts/lib/verificateur.mjs (fragmentPerimetre) | `test/adversarial.test.js`, `test/verificateur.test.js` |
| TA-86 | MN-86 | `administrateur_client` | exécutable | scripts/lib/securite.mjs | `test/adversarial.test.js`, `test/journal.test.js` |
| TA-87 | MN-87 | `administrateur_client` | exécutable | scripts/lib/securite.mjs (controlerDeclaration) | `test/adversarial.test.js`, `test/securite.test.js` |
| TA-88 | MN-88 | `administrateur_client` | à écrire (étape 4) | démon (après adoption de PA-10 par CT-2) | — |
| TA-89 | MN-89 | `verificateur` | exécutable | scripts/lib/verificateur.mjs | `test/adversarial.test.js`, `test/journal.test.js`, `test/verificateur.test.js` |
| TA-90 | MN-90 | `ecrivain_stockage` | exécutable | scripts/lib/securite.mjs | `test/adversarial.test.js`, `test/journal.test.js` |
| TA-91 | MN-91 | `administrateur_client` | exécutable | scripts/lib/verificateur.mjs | `test/adversarial.test.js`, `test/journal.test.js` |
| TA-92 | MN-92 | `cles` | exécutable | scripts/lib/securite.mjs | `test/adversarial.test.js`, `test/securite.test.js` |
| TA-93 | MN-93 | `cles` | à écrire (étape 8) | scripts/lib/securite.mjs (verifierCeremonie), scripts/verify/ceremonie.mjs | — |
| TA-94 | MN-94 | `cles` | exécutable | scripts/lib/securite.mjs | `test/adversarial.test.js`, `test/securite.test.js` |
| TA-95 | MN-95 | `cles` | à écrire (étape 8) | procédure de cérémonie (répétition de la porte 2) | — |
| TA-96 | MN-96 | `administrateur_client` | à écrire (étape 8) | tâche d'exploitation (CT-8 EX-11.22) | — |
| TA-97 | MN-97 | `exploitant` | à écrire (étape 8) | procédure de signature, répétition de cérémonie de la porte 2 | — |
| TA-98 | MN-98 | `administrateur_client` | exécutable | scripts/lib/verificateur.mjs | `test/adversarial.test.js`, `test/verificateur.test.js` |


Lecture par état. **Exécutables** (80, dont 12 avec complément à écrire) :
les mutants sont fabriqués dans `test/adversarial.test.js` pour 75 entrées
(TA-17 par les mutants partagés « TA-17 et TA-61 », « TA-17 et TA-69 »),
et les tests existants cités rejouent les mêmes vecteurs ; depuis l'étape
4, ceux de TA-2, TA-7, TA-8, TA-9, TA-10, TA-11, TA-12, TA-19, TA-24, TA-26
et TA-30 se jouent sur le démon `paquets/enregistreur` (mutants du paquet,
EX-10.5) ; depuis l'étape 5, TA-41 se joue sur le démon et le composant
d'ancrage `paquets/ancrage` par les essais de leur branchement, sans mutant
(complément), et TA-62 cite en plus l'essai de la relève d'une demande en
cours sur le composant ; TA-40, TA-53 et TA-73 ne citent qu'un test existant (outil de
référence du registre sur le réseau Hardhat en mémoire) et portent en
complément le mutant de l'outil ; TA-66 cite le rejeu Go de
`test/confrontation.test.js` et, dans `ci_steps`, les sept étapes du job
`vecteurs` de `ci.yml` qui exécutent `go run . ..` dans chaque module Go.
**Avec complément à écrire** (12), tous rattachés à l'étape 8 : TA-41 et
TA-62 (mutants du composant d'ancrage livré, possibles dès maintenant ; la
version 0.3 rattachait celui de TA-62 à l'étape 5) ; TA-14 (démonstration de
référence) ; TA-66 ; TA-5,
TA-40, TA-42, TA-43, TA-53, TA-61, TA-68, TA-73 (partie possible dès
maintenant sur le dépôt, due à l'étape 8 ; pour TA-61 et TA-68, les mutants
des règles de la révision 0.4 de CT-6 : EX-9.10, EX-9.24 et EX-9.23). **À
écrire, possibles dès maintenant sur le dépôt** (6, rattachés à l'étape 8) :
TA-35, TA-52, TA-55, TA-57, TA-58 et TA-93, qui constate qu'une réponse de CT-7 n'est pas codée dans la
bibliothèque de référence (`notes` : réserve « daté par déclaration
seulement », PD-13, cas de vecteur de PD-9) et échouera jusqu'à ce qu'elle
le soit. TA-2 et TA-30, réponses autrefois non codées dans la bibliothèque
de référence (PD-12), sont codées par le démon de l'étape 4 et éprouvées
sur lui. TA-31 et TA-33 sont éprouvés sur le démon et ses signataires de
classe B (lot des signataires de l'étape 4). **À écrire, phase 2** (10) :
étape 4 pour TA-88 (PA-10) ; étape 6 (service et
console) pour TA-51, TA-77 ; étape 7 (paquets, observabilité) pour TA-25,
TA-29, TA-75 ; étape 8 (démonstration) pour TA-1, TA-18, TA-22, TA-96.
**Procédure** (2) : TA-95 et TA-97, à la répétition de cérémonie de la
porte 2 (étape 8). Les cinq scénarios TA-99 à TA-103 (10.5) sont à écrire
à l'étape 8. Deux entrées dépendent en partie d'une proposition non adoptée
(`status.depends_on`) : TA-26 (PA-1), exécutable pour sa partie non
conditionnée, et TA-88 (PA-10) ; la section 14 dit comment elles sont
comptées.

### 10.5 Les cinq scénarios du plan

Le plan de projet nomme cinq scénarios adversariaux : l'agent supprime ou
réécrit, l'opérateur réécrit après coup, l'horloge est manipulée,
l'enregistreur tombe, un prestataire est injoignable. Chacun est une entrée
TA-99 à TA-103 du catalogue, de bloc `adversarial` à menace nulle et à
`composition` : elle compose les tests des menaces qu'elle réunit, ses
`covers` sont l'union des leurs, et elle se joue de bout en bout sur la
démonstration de référence (phase 2, étape 8). Table imprimée depuis
`catalogue.json` :

<!-- table scenarios -->
| Scénario | Titre | Menaces | Tests composés | État |
|---|---|---|---|---|
| TA-99 | Scénario du plan : l'agent supprime ou réécrit (TA-1, TA-2, TA-3, TA-4, TA-5, TA-6, TA-7, TA-9, TA-15, TA-22) | MN-1, MN-2, MN-3, MN-4, MN-5, MN-6, MN-7, MN-9, MN-15, MN-22 | TA-1, TA-2, TA-3, TA-4, TA-5, TA-6, TA-7, TA-9, TA-15, TA-22 | à écrire (étape 8) |
| TA-100 | Scénario du plan : l'opérateur réécrit après coup (TA-17, TA-18, TA-19, TA-23, TA-26, TA-27, TA-28, TA-74, TA-84, TA-85, TA-86, TA-96) | MN-17, MN-18, MN-19, MN-23, MN-26, MN-27, MN-28, MN-74, MN-84, MN-85, MN-86, MN-96 | TA-17, TA-18, TA-19, TA-23, TA-26, TA-27, TA-28, TA-74, TA-84, TA-85, TA-86, TA-96 | à écrire (étape 8) |
| TA-101 | Scénario du plan : l'horloge est manipulée (TA-21, TA-60, TA-76, TA-93) | MN-21, MN-60, MN-76, MN-93 | TA-21, TA-60, TA-76, TA-93 | à écrire (étape 8) |
| TA-102 | Scénario du plan : l'enregistreur tombe (TA-10, TA-19, TA-20, TA-26, TA-29, TA-33, TA-64) | MN-10, MN-19, MN-20, MN-26, MN-29, MN-33, MN-64 | TA-10, TA-19, TA-20, TA-26, TA-29, TA-33, TA-64 | à écrire (étape 8) |
| TA-103 | Scénario du plan : un prestataire est injoignable (TA-55, TA-58, TA-62, TA-63, TA-76) | MN-55, MN-58, MN-62, MN-63, MN-76 | TA-55, TA-58, TA-62, TA-63, TA-76 | à écrire (étape 8) |


**EX-10.9** Un scénario passe quand chacun des tests qu'il compose passe et
quand son oracle de bout en bout (membre `oracle` de l'entrée) est observé sur
la démonstration ; il échoue si l'un des deux manque. L'oracle de bout en bout
nomme aussi la **borne** du scénario : ce que l'attaque obtient malgré les
réponses, c'est-à-dire l'ensemble des risques acceptés (10.6) des tests
qu'il compose, chacun par son identifiant (TA-99 : RA-1 à RA-6, RA-8, RA-13,
RA-19 ; TA-100 : RA-15, RA-16, RA-17, RA-20, RA-23, RA-24, RA-63, RA-66,
RA-71, RA-72, RA-80 ; TA-101 : RA-18, RA-54 ; TA-102 : RA-9, RA-17, RA-25,
RA-29, RA-66, RA-67 ; TA-103 : RA-50, RA-52, RA-55, RA-56, RA-65) ; son
`expected_without_response` nomme l'observation propre au scénario qui
manquerait sans les réponses.

### 10.6 Risques acceptés : ce que CT-9 teste, ce qu'il ne teste pas

**EX-10.10** Pour chaque risque accepté RA-n de CT-7 §3.5, le catalogue porte
une entrée `accepted_risks` qui nomme la menace, le test TA- de cette menace,
son état, ce que le test éprouve (la réponse qui borne le risque : avec elle,
l'observation attendue ; sans elle, l'échec) et ce que CT-9 **ne teste pas** :
ce que la borne laisse hors de la réponse, qui reste porté par qui accepte le
risque. Un RA- n'a pas de test propre : tester un risque accepté, ce serait
prétendre le réduire. La relation RA- vers MN- est une bijection (CT-7 RV-8),
donc chaque RA- a exactement un TA-. Une borne chiffrée (une durée, une
constante `c_T`, `c_K`, `clock_tolerance_s`) nomme dans `measured_by` les
entrées TM- qui la mesurent, sans prétendre la réduire : RA-15 (TM-13,
TM-42), RA-55 (TM-42), RA-66 (TM-10) le portent ; RA-18 (`clock_tolerance_s`),
RA-29 et RA-56 (échéances d'alerte) ont une borne chiffrée qu'aucune TM- de
la version 0.1 ne mesure : leurs TM- sont à créer à la révision suivante
(section 16). L'outil de couverture vérifie que chaque TM- cité existe, avec
une cible comparée et un seuil d'échec, et que les trois RA- nommés portent
`measured_by`.

Table imprimée depuis `catalogue.json` (`accepted_risks`, colonnes `name`,
`test`, `test_state`, `not_tested` ; `tested` et `bound` sont dans le
fichier) :

<!-- table RA -->
| RA | Risque | Test | État | Non testé par CT-9 |
|---|---|---|---|---|
| RA-1 | Complétude non prouvable par la chaîne | TA-1 | a_ecrire | qu'aucune voie hors du pare-feu déclaré n'existe : seul l'essai de sortie du client (CT-7 EX-3.13) s'en approche |
| RA-2 | Délégation déclarée par l'hôte | TA-2 | executable | l'exactitude de run_id et on_behalf_of déclarés par l'hôte |
| RA-3 | Fractionnement non détecté en ligne | TA-3 | executable | un fractionnement sous des règles et plafonds que le client n'a pas écrits |
| RA-4 | Liste d'exclusion contournable | TA-4 | executable | une liste d'exclusion contournée par une forme que la validation signale sans l'interdire |
| RA-5 | Harcèlement des approbateurs sous le plafond | TA-6 | executable | la lecture attentive des approbateurs sous le plafond |
| RA-6 | Effets déclarés, non constatés | TA-7 | executable | un changement de définition qui garde la même empreinte, ou une définition trompeuse dès la première lecture |
| RA-7 | Hôte local de confiance | TA-8 | executable | le vol du jeton d'un hôte légitime, qui journalise sous l'identité du jeton |
| RA-8 | Évasion du bac à sable d'un serveur stdio | TA-9 | executable | une évasion du bac à sable propre au noyau de l'hôte |
| RA-9 | Issue inconnue après panne | TA-10 | executable | l'écriture exécutée côté serveur entre le pas 9 et la panne, hors de toute intention |
| RA-10 | Clé de fournisseur hors de la passerelle | TA-11 | executable | une clé de fournisseur copiée hors de la passerelle par un autre canal |
| RA-11 | Exécution côté fournisseur | TA-13 | executable | ce que le fournisseur exécute côté serveur quand provider_mcp vaut relayer |
| RA-12 | Capture du modèle en lecture seule ou absente | TA-14 | executable | la capture en lecture seule (mode miroir) qui ne bloque rien, par construction |
| RA-13 | Déclaration d'un agent compromis | TA-15 | executable | la véracité des arguments déclarés par le SDK (chemin déclaratif) |
| RA-14 | Spans fabriqués par une source authentifiée | TA-16 | executable | la véracité des spans d'une source authentifiée |
| RA-15 | Fenêtre de réécriture | TA-17 | executable | la réécriture des événements que le dernier point ancré n'engage pas encore (fenêtre d'au plus c_K) |
| RA-16 | Omission par l'enregistreur | TA-18 | a_ecrire | un acte vu par l'enregistreur et jamais journalisé, ou un dossier défavorable non exporté |
| RA-17 | Magasin de bail compromis | TA-19 | executable | une fourche sur un stockage qui ne vérifie pas le jeton de clôture |
| RA-18 | Horodatage déclaré par l'enregistreur | TA-21 | executable | une horloge fausse mais cohérente dans la tolérance |
| RA-19 | Accès aux pièces par l'administrateur du client | TA-22 | a_ecrire | un accès au stockage par un privilège du système hors du modèle de CT-2 |
| RA-20 | Configuration d'exploitation hors de la chaîne | TA-23 | executable | une configuration d'exploitation changée hors de policy avant l'adoption de PA-2 |
| RA-21 | Connivence au coffre | TA-24 | executable | la lecture du coffre par le détenteur légitime de la seconde approbation |
| RA-22 | Enregistreur sur le chemin | TA-25 | a_ecrire | une image malveillante dont l'empreinte est celle publiée (chaîne de construction compromise) |
| RA-23 | Administrateur du compte du support | TA-27 | executable | la rétention du support au-delà de ce que son API rend |
| RA-24 | Séparation pose et levée non garantie par le support | TA-28 | executable | une collusion des deux personnes de la levée |
| RA-25 | Segment non encore copié | TA-29 | a_ecrire | la perte d'une copie avant l'échéance de la comparaison horaire |
| RA-26 | Graine en mémoire en classe C | TA-30 | executable | la copie de la clé elle-même en classe C ou D, sans signal |
| RA-27 | Usage du signataire entre deux rapprochements | TA-31 | executable | un compte inférieur du journal d'audit du backend (CT-7 EX-3.7 ne le qualifie pas) |
| RA-28 | Pouvoir propre de l'administrateur du backend | TA-32 | executable | une opération d'administration faite hors cérémonie et jamais constatée |
| RA-29 | Rupture de journal à la perte de la clé | TA-33 | executable | la disponibilité du signataire : seule la rupture propre est testée |
| RA-30 | Capacité restante d'une clé de chaîne compromise | TA-34 | executable | la consommation sous deux fois le budget |
| RA-31 | Clé d'approbateur exposée dans la page | TA-35 | a_ecrire | un portefeuille matériel compromis ou un approbateur qui signe sans lire |
| RA-32 | Identité des membres déclarée | TA-36 | executable | deux personnes réelles qui partagent volontairement une clé déclarée à l'une |
| RA-33 | Prise du jeu par la clé de gouvernance | TA-37 | executable | le vol d'une clé de gouvernance de classe A à C sans trace |
| RA-34 | Déni de service par réassignation | TA-38 | executable | une réassignation que le client ne sonde pas (CT-4 EX-8.12) |
| RA-35 | Clé de validateur en fichier | TA-39 | executable | une double signature au-delà de f fautifs (hypothèse de consensus) |
| RA-36 | Compte chaud de trésorerie | TA-40 | executable | un approvisionnement vers un destinataire admis mais détourné ensuite |
| RA-37 | Identifiant de prestataire volé | TA-41 | executable | l'usage des identifiants volés avant leur rotation |
| RA-38 | Jeton interne contre l'opérateur | TA-42 | executable | la qualité des jetons internes, étiquetés non qualifiés par construction |
| RA-39 | Secret de service divulgué | TA-43 | executable | la fuite d'un secret par un canal hors du démon (mémoire, cœur, sauvegarde) |
| RA-40 | Service d'approbation compromis | TA-44 | executable | l'intégrité du service en dehors des remises vérifiables par le noyau |
| RA-41 | Signature à l'aveugle d'un condensé de 32 octets | TA-45 | executable | une console compromise dont l'empreinte publiée est celle de la version altérée |
| RA-42 | Extension malveillante du navigateur | TA-46 | executable | un portefeuille malveillant choisi explicitement par l'approbateur |
| RA-43 | Déni de service sur l'annuaire | TA-47 | executable | un administrateur de l'annuaire qui valide une inscription qu'il n'a pas vérifiée hors ligne |
| RA-44 | Collusion ou contrainte des approbateurs | TA-48 | executable | une collusion d'au moins required membres |
| RA-45 | Membres ajoutés pendant l'attente | TA-50 | executable | un abaissement de seuil décidé avant l'ouverture du ticket |
| RA-46 | Lecture d'état non prouvée | TA-51 | a_ecrire | un validateur partenaire complice |
| RA-47 | Relais du parcours mobile | TA-52 | a_ecrire | la confidentialité des métadonnées vues par le relais du parcours c |
| RA-48 | Exploitant du registre hostile | TA-53 | executable | une demande écrite fausse mais consignée |
| RA-49 | Quorum de validateurs fautif | TA-54 | executable | au-delà de f validateurs fautifs, et la qualité des opérateurs partenaires |
| RA-50 | Saturation de la mempool | TA-55 | a_ecrire | une saturation sous la garde d'admission (débit légitime) |
| RA-51 | Dossier d'inscription non authentifié | TA-57 | a_ecrire | la réutilisation d'une signature dans une autre instance au même identifiant (hypothèse d'unicité des instances) |
| RA-52 | Empreinte prise | TA-58 | a_ecrire | un squat qui précède l'envoi de l'ancre (course perdue) |
| RA-53 | Code des contrats non vérifié (H7) | TA-59 | executable | une faille de contrat sans redéploiement (cycle de publication) |
| RA-54 | Autorité d'horodatage menteuse (H4) | TA-60 | executable | un antidatage dans la tolérance clock_tolerance_s, non contredit par une autre ancre |
| RA-55 | Ancrage dégradé | TA-62 | executable | l'allongement de la fenêtre de date pendant la panne, qui est mesuré (TM-42), non empêché |
| RA-56 | Arrêt de l'ancrage par un composant compromis | TA-63 | executable | un arrêt de l'ancrage au-delà de ce que la série des points montre |
| RA-57 | Environnement du vérificateur non épinglé | TA-66 | executable | l'environnement d'exécution du vérificateur jusqu'au binaire reproductible de la phase 2 |
| RA-58 | Fichier d'ancres du réviseur (H3) | TA-67 | executable | le choix des ancres par le réviseur lui-même |
| RA-59 | Puissance de calcul de l'adversaire (H5) | TA-70 | executable | une chaîne d'en-têtes au-dessus du point de contrôle plus longue que la profondeur minimale et fausse (hypothèse de travail) |
| RA-60 | Règles de noorcore non recoupables publiquement | TA-71 | executable | un jeu de validateurs obtenu de deux opérateurs complices |
| RA-61 | Cadence d'activité lisible au registre | TA-72 | executable | la lecture de la cadence des ancres par un observateur de la chaîne |
| RA-62 | Relais sans accord du client | TA-73 | executable | une confirmation hors bande forgée |
| RA-63 | Opérateur qui fabrique avant l'ancre ou déclare à tort | TA-74 | executable | l'exactitude du périmètre déclaré et le choix de ce qui est exporté |
| RA-64 | Supervision coupée par l'administrateur | TA-75 | a_ecrire | des alertes coupées entre deux relectures du Lecteur |
| RA-65 | Retard et observation par le réseau | TA-76 | executable | un délai de réponse dans max_response_delay_s |
| RA-66 | Changement d'état de l'enregistreur hors de la chaîne | TA-26 | executable | une interruption sans point manqué (plus courte que 2 × c_K) |
| RA-67 | Événements non synchronisés perdus à la panne | TA-20 | executable | une corruption silencieuse d'une ligne complète que la relecture ne couvre pas |
| RA-68 | Périmètre faux mais signé | TA-78 | executable | la véracité du périmètre déclaré |
| RA-69 | Validité jugée sur un `ts` déclaré | TA-80 | executable | une attestation renouvelée avec un périmètre faux |
| RA-70 | Jeu d'approbateurs de l'attestation déclaré | TA-82 | executable | un jeu déclaratif différent choisi sciemment |
| RA-71 | Inscription réécrite par qui tient la clé | TA-84 | executable | une inscription forgée sous la clé de l'événement prouvé par qui détient cette clé |
| RA-72 | Attestation non située dans le journal | TA-85 | executable | la date réelle de rédaction d'une attestation non inscrite |
| RA-73 | Divulgation du périmètre déclaré | TA-87 | executable | les informations que le client choisit d'écrire dans l'attestation |
| RA-74 | Inventaire périmé | TA-88 | a_ecrire | un hôte ajouté avant l'adoption de PA-10 et PA-11 |
| RA-75 | Nom de version de politique réannoncé | TA-91 | executable | la vigueur réelle d'une politique de même nom |
| RA-76 | Procès-verbal sans signataire indépendant | TA-92 | executable | deux personnes réelles qui se prêtent leurs clés de participant |
| RA-77 | Date déclarée du procès-verbal | TA-93 | a_ecrire | l'écart entre l'ancre de D_C et la fin déclarée, que le réviseur juge |
| RA-78 | Restauration hors cérémonie | TA-94 | executable | une restauration hors cérémonie révélée seulement à l'usage de la clé |
| RA-79 | Détenteurs de part déclarés distincts | TA-95 | a_ecrire | un témoin complice |
| RA-80 | Journal d'exploitation effaçable | TA-96 | a_ecrire | la copie elle-même avant l'adoption de PA-18 et sa mise en place |
| RA-81 | Outil de condensation non recoupé | TA-97 | a_ecrire | un second outil lui aussi modifié |
| RA-82 | Attestation non inscrite par choix du client | TA-98 | executable | la décision du réviseur face à une attestation non inscrite |


### 10.7 Ce que les tests adversariaux ne prouvent pas

- Un mutant tué prouve que le test voit la réponse telle qu'elle est codée
  dans l'implémentation de référence ; il ne prouve ni que la réponse est
  correcte au-delà des vecteurs, ni qu'aucune autre faille n'existe (CT-7 §10
  : la revue de code est le niveau TQ-).
- Le choix du remplacement est celui de l'auteur du test : un autre retrait de
  la même réponse pourrait survivre. Le catalogue nomme le remplacement exact
  pour que ce choix soit relu.
- Les tests de phase 2, les compléments et le test de procédure décrivent des
  épreuves ; ils n'ont produit aucun résultat. Les états « exécutable » ne
  valent que pour le commit éprouvé et l'environnement de 10.8.
- Les réponses que CT-7 range sous un risque accepté ne sont éprouvées que
  jusqu'à leur borne (10.6) ; ce qui dépasse la borne n'est pas testé, par
  construction.

### 10.8 Exécution du 2026-11-03

Commande, depuis le dépôt, avec `NOORTRACE_TMP` désignant un répertoire de
travail vide (Node.js v22.22.0, mocha 11.8.0, exécutée par le
superutilisateur, ce qu'exige TA-9 ; Docker et l'image Vault épinglée sont
requis par TA-31 et TA-33, en attente sans eux) :

```text
npx mocha --timeout 600000 test/adversarial.test.js
```

Résultat : « 71 passing (3m) », 0 en échec, 0 en attente ; les 75 mutants
fabriqués (un `it` peut en fabriquer plusieurs : TA-15 et TA-16, TA-61,
TA-64, TA-69 ; TA-14 et TA-43 mutent un schéma en mémoire, hors fabrique ;
les treize `it` du démon de l'étape 4 fabriquent chacun une copie du paquet
`paquets/enregistreur`, EX-10.5) ont tous été tués et les répertoires
temporaires détruits (aucun résidu sous `NOORTRACE_TMP`). Aucun `it`
n'exige `go`. L'exécution de la version 0.1 (2026-11-01, copie du fichier
lue hors de `test/` avec `NOORTRACE_RACINE`) avait rendu « 58 passing
(22s) » sur les 62 mutants des bibliothèques. Le fichier exécuté est celui
que l'annexe A.6 décrit, octet pour octet ; dans le dépôt, il est lancé par
`npm test` (Hardhat) et par l'intégration continue.

## 11. Mesures (TM-)

Les autres spécifications délèguent à CT-9 des grandeurs à mesurer : les
huit objectifs de CT-2 §16.1 et leur méthode (CT-2 EX-16.2, format 16.3),
les
six propriétés P-1 à P-6 de CT-5 §3.6, les exigences mesurables du serveur
interne (CT-5 §7.2), la parité de CT-7 EX-7.18, et chaque valeur de CT-8
écrite « à mesurer (CT-9, porte 2) » : les budgets d'installation (EX-7.1,
EX-8.1), les coefficients du dimensionnement (§9.2), les seuils de la
supervision (§10), les objectifs de reprise (EX-11.5), la latence en mode
observation (§12.2), le temps du réviseur (EX-13.1). Le plan de projet y
ajoute, pour la porte 2, la fenêtre de réécriture, l'installation en quinze
minutes par une personne extérieure et la démonstration en une commande.
Cette section fixe ce que ces délégations laissent ouvert : le système de
référence, la méthode, le format du rapport, le seuil d'échec de chaque
grandeur et le seuil de régression ; puis elle imprime la table des 44
entrées TM-. Aucune n'a de valeur mesurée dans le catalogue (EX-3.7) ; les
valeurs vivent dans les rapports de mesure (11.3).

### 11.1 Système de référence

**EX-11.1** Les mesures de la porte 2 comptent pour les cibles quand elles
sont faites sur le **système de référence**, défini par une classe et une
instance. La classe : machine `x64` d'au moins 4 processeurs logiques et
8 Gio de mémoire (planchers du profil de production d'IP-2, CT-8 §6.2), un
disque local NVMe ou SSD avec `fdatasync` honoré (condition de CT-2 §16.1),
aucun disque en mémoire, une distribution Linux dont le noyau et la version
sont ceux de l'intégration continue du dépôt au commit éprouvé
(`ubuntu-24.04` dans `.github/workflows/ci.yml`, travail `console-chromium`),
Node.js 22, Go et Python aux versions que la CI installe au commit éprouvé
(relevé du 2026-11-01 : `setup-go` 1.24.7 dans le travail des vecteurs,
`setup-python` 3.13 ; quand le binaire de CT-6 §14 entre dans `ci.yml`,
étape 2, TV-55, la CI y installe la version que son `go.mod` fixe, go1.27.3,
CT-6 EX-14.3, et le système de référence suit), GNU tar, OpenSSL de la
distribution ; la mise à l'échelle de fréquence du processeur désactivée ou
déclarée, l'état de l'ASLR déclaré, aucune autre charge pendant la mesure.
L'instance : la machine réelle de cette classe que la première campagne de la
porte 2 nomme (modèle de processeur, mémoire, disque, système, noyau,
versions) dans son rapport ; toutes les campagnes suivantes de la version 0
la réemploient ou nomment le changement.

**EX-11.2** Chaque rapport de mesure nomme sa machine (membre `system`,
11.3) et dit si elle est le système de référence (`system.reference`). Une
mesure faite hors du système de référence, avec `fdatasync` désactivé ou sur
disque en mémoire est publiée mais ne compte pas pour les cibles
(`counts_for_targets` faux, `met` null sur chaque ligne, raison dans
`excluded_reason`), règle de CT-2 EX-16.3. L'environnement de rédaction de
cette version (processeur Intel Xeon à 2,80 GHz, 4 processeurs, 16 Gio,
disque virtuel, Ubuntu 24.04.5, noyau 6.18.44, Node.js v22.22.0) n'est pas
le système de référence : ses relevés sur les vecteurs (TM-6, TM-10) sont
publiés avec `reference` faux.

### 11.2 Méthode

**EX-11.3 (échauffement et répétitions)** Le nombre d'échauffements et de
répétitions est fixé avant la mesure et écrit dans le rapport. Pour une
latence ou un débit de l'enregistreur : 2 000 appels d'échauffement puis
N = 20 000 (CT-2 EX-16.2, pas 3). Pour une durée d'un processus (reprise,
démonstration, vérification d'un dossier) : au moins 3 échauffements puis au
moins 10 répétitions. Pour une procédure humaine (installation, épreuve) :
une exécution par participant, sans échauffement, et aucun percentile ; les
valeurs de plusieurs participants sont publiées une par une. Pour un relevé
(taille, présence, ordre de champs) : une exécution, dont la commande est
citée. Un échantillon trop petit pour le percentile demandé rend la ligne
`excluded_reason` `echantillon_insuffisant`.

**EX-11.4 (percentiles et agrégats)** Les percentiles sont calculés par la
méthode du plus proche rang sur les N échantillons, échauffement exclu
(CT-2 EX-16.2, pas 4) : `p50`, `p95`, `p99` et `max` pour une latence ou une
durée ; `max` et `mean` pour une taille ; `value` pour un débit ou un
compte. Une latence n'est jamais publiée par sa seule moyenne ; la moyenne
arithmétique ne résume que des coûts et des tailles, jamais un rapport ni
un taux (R11-F34, règles 3, 4 et 8). Les échantillons bruts sont publiés
dans la ligne (`samples`) ou à part avec leur SHA-256 (`samples_sha256`) ;
aucun échantillon n'est retiré : une valeur aberrante est signalée dans
`notes`, pas supprimée (R11-F30).

**EX-11.5 (horloge)** Une durée machine se mesure sur l'horloge monotone
du processus qui mesure (`process.hrtime` ou équivalent), jamais sur
l'horloge murale ni sur l'horodatage d'un bloc (CT-5 P-2). Une procédure
humaine se mesure sur l'horloge murale, avec l'heure de début et de fin
consignées au procès-verbal (CT-8 IC-18). Un délai entre deux composants
(P-1, P-2, P-3, fenêtres) se lit sur l'horloge de l'enregistreur, source
unique des deux instants (CT-5 P-2) ; le rapport le dit dans `conditions`.
Aucune horloge n'est manipulée pendant une mesure ; les tests qui manipulent
l'horloge sont des TA- (horloge injectée de CT-5 EX-8.13, minuteries
simulées de Node ; R11-F5, R11-F53).

**EX-11.6 (unités)** Chaque ligne porte l'unité native de sa grandeur, prise
dans une liste fermée (`ms`, `s`, `min`, `octets`, `evenements_par_s`,
`blocs_par_s`, `nombre`, `booleen`, `ratio`, `texte`) ; aucune conversion
n'est faite dans le rapport (une latence en millisecondes, un budget
d'installation en minutes comme dans CT-8 §8.3, une taille en octets).

**EX-11.7 (conditions)** Les conditions de la cible (CT-2 §16.1 : disque
local, classe du signataire, tailles de charge, politique, connexions) sont
réunies et écrites dans `conditions` ; une ligne mesurée hors d'une de ses
conditions est publiée avec `excluded_reason` et ne compte pas. Le rapport
porte le SHA-256 de la configuration employée (`configuration_sha256`,
CT-2 EX-16.3) et le commit éprouvé.

**EX-11.8 (paire avec et sans)** Quand la soustraction de CT-2 §16.1
(`(t_reponse_hote − t_recu) − (t_reponse − t_envoi)`) n'est pas disponible
(mode observation, TM-38 ; adaptateurs ; mandataire ICAP), la latence
ajoutée se mesure par paire : deux montages identiques sauf la présence de
l'enregistreur sur le chemin, même machine, même charge, même séquence de
requêtes, même ordre ; les deux séries sont publiées en entier et la
différence des percentiles est rapportée comme telle (`pair_with_without`
vrai). Cette méthode est une composition de pratiques publiées (R11-F29 à
R11-F35), non une méthode normée : le rapport la nomme (R11-NV5).

**EX-11.9 (charge à cadence fixe)** Sous charge (TM-3, TM-11, TM-12), l'hôte
de test émet à cadence fixe et mesure chaque latence depuis l'instant prévu
de l'envoi, non depuis l'envoi effectif, pour que les réponses lentes ne
retardent pas la mesure des suivantes (omission coordonnée, R11-F35).

**EX-11.10 (relevé)** Un relevé (TM-24, TM-27, TM-39, TM-40) cite la commande
exacte, sa sortie en `text_value` ou `value`, et la version de l'outil
interrogé. La méthode `releve` du catalogue (`measure.method`, schéma
`$defs/mesure`) désigne la provenance de la valeur, une sortie ou un journal
lus, non le nombre d'exécutions ; celui-ci suit EX-11.3 selon la nature de la
grandeur : une exécution pour une taille, une présence ou un ordre (TM-24,
TM-27, TM-39, TM-40, que la méthode soit `releve` ou `lecture_api`) ; au moins 3
échauffements puis 10 répétitions pour une durée de processus (TM-43 : relevé de
la durée imprimée) ; pour un délai entre composants lu dans le journal ou les
dossiers (TM-41, TM-42), la série que l'entrée fixe (3 600 événements, sans
échauffement), sur l'horloge de l'enregistreur (EX-11.5). Aucune cible ni aucun
seuil n'en dépend.

### 11.3 Rapport de mesure

**EX-11.11** Une campagne de mesure produit un fichier conforme à
`$defs/rapport_mesure` de `plan-de-tests-v0` (CT-9 §4) :
`spec/vecteurs/ct-9/mesures/rapport-<AAAA-MM-JJ>-<etiquette>.json`, écrit par
l'ingénieur de la campagne, jamais par le générateur, sauf les deux exemples
de l'annexe A (le rapport vide de la version 0.1 et le rapport sur les
vecteurs). Le rapport porte : la date et l'instant, le commit éprouvé, la
version de CT-9, la machine (`system` : `reference`, `cpu`, `cores`,
`memory_bytes`, `disk.type` et `disk.fsync`, `os`, `kernel`, `node`, `go`,
`python`, `cpu_scaling`, `aslr`, `load_avg_1m`, `virtualized`), la méthode
(`warmup`, `repetitions`, `percentile_method` toujours `plus_proche_rang`,
`clock`, `pair_with_without`, `samples_published`), `configuration_sha256`,
`counts_for_targets`, et une ligne par grandeur (`results[]`) : `name`
(le `result_name` de l'entrée TM- désignée par `test_id` pour sa ligne
principale ; une ligne supplémentaire rattachée à la même entrée porte un
nom propre, distinct de tout `result_name` du catalogue, et la table 11.3
la nomme : `octets_ligne_annexe_a` pour TM-6), `test_id`, `unit`, `n`,
`connections`, `samples` ou `samples_sha256`, `value`, `p50`, `p95`, `p99`,
`min`, `max`, `mean`, `text_value`, `target`, `met`, `conditions`,
`excluded_reason`. Les noms exacts des membres et les valeurs énumérées
sont ceux de `$defs/rapport_mesure` du schéma
`spec/schemas/plan-de-tests-v0.schema.json`, qui fait foi sur cette liste :
`method.clock` vaut `monotone`, `murale`, `manuelle` ou `sans_objet` ;
`spec_version` porte la version de CT-9 ; aucun autre membre n'est admis.
Une valeur absente est `null`, jamais omise ni inventée ;
`met` n'est un booléen que si une valeur est présente et que le rapport
compte pour les cibles. Le rapport n'est pas une pièce et n'entre pas dans la
chaîne (CT-2 §16.3).

**EX-11.12** Les noms de lignes de CT-2 §16.3 sont repris tels quels
(`latence_appel_relaye`, `latence_premier_octet_sse`, `debit`, `signature`,
`octets_par_evenement`, `reprise`) et leurs cibles sont les mêmes ; un
rapport de CT-9 contient ce qu'un rapport de CT-2 §16.3 contient, plus la
machine complète, la méthode et les lignes des autres spécifications. CT-9
propose à CT-2 d'adopter ce format ou d'en écrire une projection (PD-16,
17.2) ; tant que le harnais de CT-2 EX-16.2 (`scripts/mesures/ct-2-perf.mjs`
et `npm run mesures:ct2`, livrables de la phase 2, absents du dépôt
aujourd'hui) n'existe pas ou n'a pas adopté cette forme, le rapport de CT-9
est écrit par l'ingénieur de la campagne (EX-11.11) à partir du rapport de
CT-2 §16.3 ; en versions 0.1 à 0.4, aucune mesure de CT-2 §16.1 n'est publiée et
les lignes TM-1 à TM-5, TM-7 et TM-8 ne figurent que dans le rapport vide.

**EX-11.13** Le rapport vide de la version 0.1 est
`spec/vecteurs/ct-9/mesures/rapport-2026-11-01-vide.json` : chaque ligne
porte sa cible et `null` partout ailleurs, `counts_for_targets` vrai et un
`system` à compléter à la porte 2. Le rapport sur les vecteurs est
`spec/vecteurs/ct-9/mesures/rapport-2026-11-01-vecteurs.json`
(`counts_for_targets` faux, `reference` faux) ; il porte les seules valeurs
mesurées de cette version, toutes recalculables depuis le dépôt :

| Ligne | Test | Valeur | Commande |
|---|---|---|---|
| `octets_par_evenement` | TM-6 | 9 lignes, 14 293 octets, moyenne 1 588,11, min 413, max 2 530 (saut de ligne compris) | `node -e` sur `spec/vecteurs/ct-2/evenements/journal-demo/segment.ndjson` (`Buffer.byteLength(l) + 1` par ligne) ; recoupé par `awk '{s+=length($0)+1}'`, 2026-11-01 |
| `octets_ligne_annexe_a` | TM-6 | 2 465 (ligne supplémentaire de TM-6, nom propre, EX-11.11) | `npx hardhat --config hardhat.config.mjs test test/enregistreur.test.js`, cas « … ligne de segment de 2465 octets » |
| `p1_cadence_vecteurs` | TM-10 | 12 délais événement → premier point qui l'engage (`samples`), maximum 56,583 s (seq 1), minimum 0 s (seq 12) ; aucun écart de cadence ; 3 540 s sur la série creuse | `delaisPoints` de `scripts/vecteurs/ct9/familles.mjs` à la génération (`npm run vecteurs:ct9`), recalculé par `test/plan-de-tests.test.js` ; cadence : `npx hardhat --config hardhat.config.mjs test test/ancrage.test.js`, cas « constaterCadence (AN-2, alerte point_manquant) … » |

Le rapport sur les vecteurs est imprimé ci-dessous sans ses membres
`samples` (les neuf tailles de ligne et les douze délais aux points sont
dans le fichier) :

```json
{
  "version": 0,
  "kind": "rapport-mesure",
  "date": "2026-11-01",
  "measured_at": "2026-11-01T18:40:00Z",
  "commit": "3a8e9619205e3928610990479121ffa4c0ace1d5",
  "spec_version": "0.1",
  "system": {
    "reference": false,
    "cpu": "Intel(R) Xeon(R) Processor @ 2.80GHz",
    "cores": 4,
    "memory_bytes": 16872808448,
    "disk": { "type": "virtuel", "fsync": null },
    "os": "Ubuntu 24.04.5 LTS",
    "kernel": "6.18.44-fc-v185",
    "node": "v22.22.0",
    "go": "go1.24.7",
    "python": "3.13.16",
    "cpu_scaling": "inconnu",
    "aslr": "inconnu",
    "load_avg_1m": null,
    "virtualized": true
  },
  "method": {
    "warmup": 0,
    "repetitions": 1,
    "percentile_method": "plus_proche_rang",
    "clock": "sans_objet",
    "pair_with_without": false,
    "samples_published": true
  },
  "configuration_sha256": null,
  "counts_for_targets": false,
  "results": [
    {
      "name": "octets_par_evenement", "test_id": "TM-6", "unit": "octets",
      "n": 9, "connections": null, "samples": ["…"], "samples_sha256": null,
      "value": null, "p50": null, "p95": null, "p99": null,
      "min": 413, "max": 2530, "mean": 1588.11, "text_value": null,
      "target": null, "met": null,
      "conditions": [
        "spec/vecteurs/ct-2/evenements/journal-demo/segment.ndjson, saut de ligne compris",
        "SHA-256 du segment : 8005e09ac381f1756db5a4b03db2986c35e693fc32ba75819f9a5299753dafc1"
      ],
      "excluded_reason": "vecteurs_seulement"
    }
  ]
}
```

Exemple de la méthode d'EX-11.3 et d'EX-11.4 sur une durée de processus,
exécuté le 2026-11-01 dans l'environnement de rédaction (hors système de
référence, donc sans valeur pour une cible, et sans ligne TM- : aucune
spécification ne fixe de cible à cette durée) : la vérification du dossier
`spec/vecteurs/ct-6/dossiers/valide-seq-7-complet` par
`node scripts/verify/dossier.mjs … --ancres … --entetes-bitcoin … --json`,
3 échauffements puis 20 répétitions, horloge monotone du processus parent,
donne p50 454,14 ms, p95 549,22 ms, p99 563,47 ms, min 389,96 ms, max
563,47 ms, moyenne 466,37 ms (programme `chronometrer.mjs` de la partie C,
échantillons conservés). Ce chiffre illustre le format ; il n'est repris
dans aucun rapport publié.

Le rapport de la campagne de l'étape 5 (révision 0.4) est
`spec/vecteurs/ct-9/mesures/rapport-2026-11-10-ancrage.json`, écrit par
`scripts/e2e/mesure-ancrage.mjs rapport` (EX-11.11) et relu par
`test/plan-de-tests.test.js` ; ses valeurs ne sont recopiées ni dans le
texte ni dans le catalogue. Ses lignes principales portent le `result_name`
de TM-11 à TM-14, TM-17 à TM-19, TM-30, TM-41 et TM-42 (et, avec le relevé
d'`ancres/` sur le support WORM, `p6_copie_worm` de TM-16) ; ses lignes
supplémentaires (EX-11.11) sont les suivantes :

| Ligne | Test | Ce qu'elle porte |
|---|---|---|
| `p1_cadence_porte_2` | TM-11 | P-1 dans la configuration de la porte 2 (`c_T` = 60 s, points chez le principal) |
| `p2_inclusion_porte_2` | TM-12 | `d_registre` dans la configuration de la porte 2 |
| `p3_d_point` | TM-13 | composante `d_point` de `d_jeton` (configuration par défaut) |
| `p3_d_attente` | TM-13 | composante `d_attente` de `d_jeton` |
| `p3_d_releve` | TM-13 | composante `d_releve` de `d_jeton` |
| `p3_d_tsa` | TM-13 | composante `d_tsa` de `d_jeton` |
| `p3_d_jeton_porte_2` | TM-13 | `d_jeton` dans la configuration de la porte 2 (hors de la condition `c_T` = 300 s de TM-13 : publiée à titre de comparaison) |
| `p4_cloture_porte_2` | TM-14 | clôture horaire dans la configuration de la porte 2 |
| `planificateur_debit_points` | TM-17 | points admis par seconde, J = 1 (rejeu accéléré) |
| `planificateur_journaux` | TM-17 | journaux servis, J = 10 (rejeu accéléré) |
| `an24_clock_offset` | TM-19 | écart d'horloge consigné par les serveurs internes (`tsa_clock_offset_ms`) |
| `b_ots_en_attente_public` | TM-30 | octets des preuves en attente des agrégateurs publics (option `--reseau-public`) |
| `w_ordre_porte_2` | TM-41 | `W_ordre` dans la configuration de la porte 2 |
| `w_date_defaut` | TM-42 | `W_date` dans la configuration par défaut (`c_T` = 300 s, 11.6) |

### 11.4 Cibles, seuils d'échec et régression

**EX-11.14** Chaque entrée TM- porte une cible (nombre, cible composée
`p50`/`p99`, texte, ou `null` quand la spécification dit « mesurée, aucune
cible »), le mode de comparaison (`au_plus`, `strictement_inferieur`,
`au_moins`, `p50_au_plus`, `p95_au_plus`, `p99_au_plus`,
`p50_et_p99_au_plus`, `somme_au_plus`, `egalite`, `aucune_cible`), la source
de la cible (identifiant de la spécification qui la fixe) et le seuil
d'échec. `strictement_inferieur` sert quand la source dit « moins de » : une
valeur égale à la cible est un échec (TM-25 : « moins de 30 minutes », CT-8
EX-13.1 ; TM-35 : seuil `<M>` ; TM-43 : « moins de deux minutes », CT-2
EX-19.1). Le seuil d'échec de l'entrée fait foi pour `met` ; il égale la
cible au sens du mode de comparaison, sauf réserve écrite par la source :
TM-22 a pour cible 450 min et pour seuil 480 min (CT-8 EX-8.1 : réserve de
30 min). Une ligne `aucune_cible` ne peut pas échouer : elle est publiée, et
son absence d'un rapport de la porte 2 est une lacune nommée.

**EX-11.15 (régression)** CT-2 EX-16.2 (pas 7) laisse à CT-9 le seuil de
régression. Règle : tant qu'aucun rapport de la porte 2 n'est publié,
aucun seuil ; le premier rapport publié sur le système de référence devient
la **référence** ; un rapport ultérieur sur le même système est une
régression quand, pour une ligne à cible, `p50` ou `p99` dépasse 1,2 fois la
valeur de référence, `value` d'un débit descend sous 0,9 fois la référence,
ou une ligne `met` vrai devient `met` faux. Ces coefficients sont un choix
de conception de CT-9, à confirmer à la première campagne ; le harnais de
CT-2 EX-16.2 (phase 2) rendra le code 0 que les cibles soient atteintes ou
non (CT-2 EX-16.2, pas 7), et c'est `scripts/tests/mesures.mjs --reference
--campagne` (annexe A, éprouvé par `test/plan-de-tests.test.js`) qui
compare au rapport de référence et rend 1 sur une régression.

**EX-11.16** En versions 0.1 à 0.4, le membre `measured` de chaque
entrée TM- est `null` et la colonne « Mesure » de la table 11.5 est vide :
aucune mesure de performance de l'enregistreur, du service d'approbation,
du composant d'ancrage ni des installations n'est faite sur le système de
référence ; parmi les seize entrées exécutables, TM-6 et TM-10 ont leur
résultat dans le rapport sur les vecteurs, TM-31 dans le rapport de sa
campagne sur le réseau de développement (étape 3), TM-16 dans le rapport de
sa campagne sur le support WORM en conteneur
(`mesures/rapport-2026-11-03-p6-worm.json`, étape 4, hors système de
référence ; `ancres/` depuis l'étape 5, dans les essais cités et dans le
rapport de l'étape 5 quand son relevé y est joint), TM-11 à TM-14, TM-17 à
TM-19, TM-30, TM-41 et TM-42 dans le rapport de la campagne de l'étape 5 sur
le réseau de développement (`mesures/rapport-2026-11-10-ancrage.json`, hors
système de référence, 11.3 ; TM-18 et TM-19 aussi dans les essais du serveur
interne qu'elles citent), TM-15 et
TM-20 dans les tests et les étapes de CI qu'elles citent (`scripts/tests/
mesures.mjs` le signale comme lacune nommée, MES-7), jamais dans le
catalogue.

### 11.5 Table des mesures

Imprimée depuis le catalogue (membre `tests`, niveau `TM`) ; une ligne par
entrée ; la colonne « Mesure » reste vide tant qu'aucun rapport de la porte
2 n'existe (EX-11.16). Les préconditions, étapes et oracle de chaque entrée
sont dans le catalogue.

<!-- table TM -->
| Id | Grandeur | Cible | Comparaison | Source | Seuil d'échec | Méthode | État | Mesure |
|---|---|---|---|---|---|---|---|---|
| TM-1 | latence ajoutée par appel relayé | p50 ≤ 5, p99 ≤ 50 ms | `p50_et_p99_au_plus` | CT-2 §16.1 | p50 > 5 ms ou p99 > 50 ms, `fsync` actif, sur le système de référence | `harnais` | à écrire (étape 8) | — |
| TM-2 | latence ajoutée à chaque octet d'un flux SSE | 10 ms | `au_plus` | CT-2 §16.1 | max > 10 ms sur le système de référence | `harnais` | à écrire (étape 8) | — |
| TM-3 | débit d'événements durables | 500 evenements_par_s | `au_moins` | CT-2 §16.1 | moins de 500 événements/s avec 16 connexions sur le système de référence | `harnais` | à écrire (étape 8) | — |
| TM-4 | latence ajoutée par échange de modèle hors flux | p50 ≤ 5, p99 ≤ 50 ms | `p50_et_p99_au_plus` | CT-2 §16.1 | p50 > 5 ms ou p99 > 50 ms sur le système de référence | `harnais` | à écrire (étape 8) | — |
| TM-5 | durée d'un appel sign par classe de backend | — | `aucune_cible` | CT-2 §16.1 | aucun : mesure publiée ; une classe absente du rapport est une lacune nommée | `harnais` | à écrire (étape 8) | — |
| TM-6 | octets par événement dans le segment, sur les vecteurs | — | `aucune_cible` | CT-2 §16.1 | aucun : mesure publiée ; la ligne de l'annexe A doit faire 2 465 octets | `comparaison_octets` | exécutable : `test/enregistreur.test.js` | — |
| TM-7 | octets par événement et par appel en charge | — | `aucune_cible` | CT-2 §16.1 | aucun : mesure publiée | `harnais` | à écrire (étape 8) | — |
| TM-8 | durée de reprise au démarrage pour un segment de 256 MiB | 2000 ms | `p99_au_plus` | CT-2 §16.1 | p99 > 2 000 ms sur disque local | `harnais` | à écrire (étape 8) | — |
| TM-9 | mémoire résidente à vide (m_0) et sous charge | — | `aucune_cible` | CT-2 §16.1 | aucun : mesure publiée ; `memoire_charge − memoire_vide > M_tamp` est une lacune de DM-19 à tracer | `releve` | à écrire (étape 8) | — |
| TM-10 | délai entre un événement et le premier point qui l'engage, sur les vecteurs | 61 s | `au_plus` | CT-5 P-1 | un écart de cadence sur la série publiée, ou un délai > 61 s | `comptage` | exécutable : `test/ancrage.test.js` | — |
| TM-11 | délai entre un événement et le premier point signé qui l'engage | 61 s | `au_plus` | CT-5 P-1 | max > 61 s ou un écart de cadence sur une heure | `releve` | exécutable : `test/plan-de-tests.test.js` ; complément à écrire (étape 8) | — |
| TM-12 | délai d'inclusion de l'ancre d'un point au registre (d_registre) | 60 s | `au_plus` | CT-5 P-2 | max > 60 s en fonctionnement nominal sur le réseau de développement | `releve` | exécutable : `test/plan-de-tests.test.js` | — |
| TM-13 | d_jeton : délai entre l'échéance de contresignature et genTime + précision | c_T (300 s) + d_jeton ; d_point ≤ 1 s, d_attente ≤ squat_wait_s, d_releve ≤ fallback_after_s (120 s), d_tsa publié | `au_plus` | CT-5 P-3 | une échéance non satisfaite avant la suivante, ou une composante au-delà de sa borne | `releve` | exécutable : `test/plan-de-tests.test.js` | — |
| TM-14 | clôture horaire qualifiée et attestée par deux calendriers | jeton qualifié ; au moins 2 calendriers ; T-11 reussi | `egalite` | CT-5 P-4 | partie absente, un seul calendrier, ou T-11 non reussi | `lecture_api` | exécutable : `test/plan-de-tests.test.js` ; complément à écrire (étape 8) | — |
| TM-15 | vérification hors ligne d'un dossier avec points de contrôle | code 0 sans reseau ; rapport identique | `egalite` | CT-5 P-5 | un code différent ou un rapport différent sans réseau | `comparaison_octets` | exécutable : `test/verificateur.test.js`, étape de `ci.yml` | — |
| TM-16 | fichiers de points, d'ancres et de manifestes sans copie WORM conforme | 0 nombre | `egalite` | CT-5 P-6 | au moins un fichier sans version au même SHA-256, ou une rétention plus courte | `lecture_api` | exécutable : `test/enregistreur-worm-mesure-p6.test.js`, `test/enregistreur-journal-soi.test.js`, `test/enregistreur-ancrage-exigences.test.js` | — |
| TM-17 | débit de points, journaux par instance et taille de la file en panne | — | `aucune_cible` | CT-5 §15 | aucun : mesure publiée ; une file non bornée est une lacune à tracer | `releve` | exécutable : `test/plan-de-tests.test.js` ; complément à écrire (étape 8) | — |
| TM-18 | paires de jetons successifs à numéros de série non croissants, redémarrage compris | 0 nombre | `egalite` | CT-5 AN-26 | une paire non croissante | `comptage` | exécutable : `test/enregistreur-ancrage-exigences.test.js`, `test/enregistreur-ancrage-parcours.test.js`, `test/plan-de-tests.test.js` | — |
| TM-19 | précision déclarée des jetons du serveur interne | 1 s | `au_plus` | CT-5 AN-24 | accuracy absent ou > 1 s sur un jeton | `releve` | exécutable : `test/enregistreur-ancrage-exigences.test.js`, `test/enregistreur-ancrage-parcours.test.js`, `test/plan-de-tests.test.js` | — |
| TM-20 | points de parité de CT-7 EX-7.18 non tenus sur les vecteurs | 0 nombre | `egalite` | CT-7 EX-7.18 | un point non tenu | `comptage` | exécutable : `test/verificateur.test.js`, étape de `ci.yml` | — |
| TM-21 | durée de l'installation rapide, IR-1 à IR-8 | 900 s | `somme_au_plus` | CT-8 EX-7.1 | somme des huit pas > 900 s pour un participant extérieur (critère du plan : 15 minutes) | `chronometre` | à écrire (étape 7) | — |
| TM-22 | durée de l'installation complète, IC-1 à IC-18 | 450 min | `somme_au_plus` | CT-8 EX-8.1 | durée totale, attente comprise, > 480 min (journée de 8 heures) | `chronometre` | à écrire (étape 7) | — |
| TM-23 | informations absentes de CT-8 nécessaires à l'installation complète | 0 nombre | `egalite` | CT-8 EX-8.1 | au moins une information manquante hors IC-2 | `comptage` | à écrire (étape 7) | — |
| TM-24 | taille des images et durée de leur téléchargement | — | `aucune_cible` | CT-8 IR-6 | aucun : mesure publiée | `releve` | à écrire (étape 7) | — |
| TM-25 | temps du réviseur, réception à résultat | 1800 s | `strictement_inferieur` | CT-8 EX-13.1 | 1 800 s ou plus (1 800,0 s exactement est un échec) pour un réviseur extérieur à sa première vérification | `chronometre` | à écrire (étape 8) | — |
| TM-26 | délai de pose des attributs par le compagnon | 60 s | `au_plus` | CT-8 EX-3.9 | max > 60 s sur dix segments | `releve` | à écrire (étape 7) | — |
| TM-27 | durée de vie DNS du nom du répartiteur | 30 s | `au_plus` | CT-8 §3.5 | TTL > 30 s | `lecture_api` | à écrire (étape 7) | — |
| TM-28 | artefacts dont deux constructions indépendantes diffèrent | 0 nombre | `egalite` | CT-8 EX-3.13 | un condensé différent | `comparaison_octets` | à écrire (étape 7) | — |
| TM-29 | consommation observée de processeurs, de mémoire et d'espace sous charge | 2 processeurs et 4 Gio (rapide) ; 4 et 8 Gio (production) ; 10 Gio d'espace (rapide) | `au_plus` | CT-8 EX-6.2 | une consommation observée au-dessus du plancher du profil | `releve` | à écrire (étape 7) | — |
| TM-30 | octets d'une preuve OpenTimestamps mise à niveau | — | `aucune_cible` | CT-8 EX-9.1 | aucun : mesure publiée | `comparaison_octets` | exécutable : `test/plan-de-tests.test.js` ; complément à écrire (étape 8) | — |
| TM-31 | octets de la capture d'une transaction d'un bloc plein de 64 ancres (réponses JSON-RPC ; index relevé à part) | — | `aucune_cible` | CT-8 EX-9.1 | aucun : mesure publiée | `comparaison_octets` | exécutable : `test/registre-dev.test.js` | — |
| TM-32 | blocs par seconde de l'instance de production | — | `aucune_cible` | CT-8 EX-9.1 | aucun : mesure publiée | `releve` | à écrire (étape 3) | — |
| TM-33 | coefficients f_pic, b_o, b_acq, b_crl, n_crl | — | `aucune_cible` | CT-8 EX-9.1 | aucun : mesure publiée ; IC-1 refait après mesure | `releve` | à écrire (étape 7) | — |
| TM-34 | faux positifs et faux négatifs des alertes à seuil cible | 0 nombre | `egalite` | CT-8 EX-10.11 | une alerte levée en nominal ou absente dans son scénario | `comptage` | à écrire (étape 7) | — |
| TM-35 | taille maximale observée de la file en attente du nœud | moitié de -txpool-max-pending | `strictement_inferieur` | CT-8 §10.6 | file observée ≥ <M> en nominal | `releve` | à écrire (étape 7) | — |
| TM-36 | durée de chaque runbook, alerte à sortie vérifiée | — | `aucune_cible` | CT-8 §10.11 | aucun : mesure publiée | `chronometre` | à écrire (étape 7) | — |
| TM-37 | RPO et RTO par composant, cadence de sauvegarde de l'état du service | RTO : 14 400 s (journal, pièces, ancrage), 12 s (bascule du segment ouvert), 3 600 s (service) ; RPO service : 900 s | `au_plus` | CT-8 EX-11.5 | une valeur mesurée au-dessus de sa cible | `chronometre` | à écrire (étape 7) | — |
| TM-38 | latence ajoutée en mode observation | p50 ≤ 5, p99 ≤ 50 ms | `p50_et_p99_au_plus` | CT-8 EX-12.5 | p50 > 5 ms ou p99 > 50 ms | `paire_avec_sans` | à écrire (étape 8) | — |
| TM-39 | présence, format et délai du journal d'accès du support WORM | présent et convertible par le collecteur | `egalite` | CT-8 EX-11.19 | un fournisseur sans journal lisible | `lecture_api` | à écrire (étape 7) | — |
| TM-40 | ordre des champs de chronyc -c tracking | ordre supposé par IP-5 | `egalite` | CT-8 IP-5 | un ordre différent | `releve` | à écrire (étape 7) | — |
| TM-41 | W_ordre : événement → inclusion au registre du premier point | 120 s | `p99_au_plus` | CT-5 EX-3.3 | p99 > 120 s en fonctionnement nominal | `releve` | exécutable : `test/plan-de-tests.test.js` ; complément à écrire (étape 8) | — |
| TM-42 | W_date : événement → genTime + précision du jeton du premier point contresigné | 300 s | `p99_au_plus` | CT-5 EX-3.3 | p99 > 300 s avec la configuration de la porte 2 (c_T = 60 s) ; p99 > 300 s + d_jeton avec la configuration par défaut | `releve` | exécutable : `test/plan-de-tests.test.js` | — |
| TM-43 | durée de la démonstration de référence | 120 s | `strictement_inferieur` | CT-2 EX-19.1 | 120 s ou plus (120,0 s exactement est un échec), images déjà téléchargées | `releve` | à écrire (étape 8) | — |
| TM-44 | octets de la capture d'une transaction d'un bloc plein qui mêle des clôtures (réponses JSON-RPC ; index relevé à part) | — | `aucune_cible` | CT-8 EX-9.1 | aucun : mesure publiée ; au-delà de 123 761 octets index compris, elle remplace `b_cap` | `comparaison_octets` | à écrire (étape 8) | — |


### 11.6 Ce que les mesures ne disent pas

Une cible atteinte sur le système de référence ne dit rien d'une autre
machine, d'un autre disque ni d'une charge d'une autre forme ; le rapport
le dit par `conditions`. `W_date` (TM-42) est une valeur rapportée, calculée
depuis le `ts` que déclare l'enregistreur, qui est l'adversaire visé (CT-6
§7.9) : la mesure borne la conception, elle ne prouve rien d'un dossier.
Les mesures humaines (TM-21 à TM-23, TM-25, TM-36) dépendent du participant
: une exécution par participant, publiée telle quelle, jamais moyennée. Les
coefficients mesurés (TM-30 à TM-33) remplacent les hypothèses de CT-8 §9.5
au procès-verbal du client, non dans CT-8, qui garde ses défauts jusqu'à sa
révision. La révision 0.2 de CT-8 a ainsi repris `b_cap`, mesuré par TM-31
le 2026-11-02 (109 479 octets de réponses et 14 282 octets d'index, soit
123 761 octets) ; un bloc plein qui mêle des clôtures (TM-44) n'est pas
mesuré.

---

## 12. Rejeu à l'aveugle (TR-)

Six spécifications délèguent à CT-9 une épreuve où une personne qui n'a pas
participé au projet travaille avec le seul texte : CT-3 (trois relecteurs
sur une politique, A.5 ; deux lecteurs de la console, A.11), CT-4 (un
relecteur crée un client, ancre et clôt sur le réseau de développement,
§7.12), CT-5 (un relecteur sur la cadence, la preuve, la fenêtre, le coût et
la panne ; un second sur CT-6 §7), CT-7 (trois épreuves, §9), CT-8 (trois
épreuves, §14). Le plan de projet exige en outre un rejeu complet « à
l'aveugle, à partir de la seule documentation » et, à la porte 2, une
vérification « reproduite sans aide, sur une machine vierge ». Cette section
fixe le protocole commun que chaque épreuve suit, la consignation, puis
imprime la table des épreuves ; les trois épreuves propres à CT-9 sont en
section 15, que les participants ne reçoivent pas.

### 12.1 Protocole commun

**EX-12.1 (participant)** Le participant n'a pris part ni au projet ni à la
rédaction de la spécification visée (CT-8 EX-14.1, EX-14.6) ; il tient le
rôle que l'épreuve nomme (approbateur, auditeur, développeur, ingénieur
d'exploitation, réviseur, administrateur, responsable de la sécurité ou de
la conformité, testeur). Il est désigné dans la consignation par un
pseudonyme (`P-<nn>`) ; aucun nom, aucune adresse, aucune donnée personnelle
n'entre dans le dépôt. Une même personne ne passe pas deux épreuves qui
partagent une grille.

**EX-12.2 (matériel)** Le participant reçoit exactement ce que l'entrée TR-
nomme dans `material`, et rien d'autre : un extrait d'une spécification
quand la grille est dans le texte (CT-7 sans la section 9 ni l'annexe A.15 ;
CT-8 sans la section 14 ni l'annexe A ; CT-8 section 13 seule ; CT-9 sans la
section 15), une consigne, des fichiers des vecteurs, un poste décrit. Les
extraits sont produits par le générateur (`spec/vecteurs/ct-9/extraits/`,
annexe A) pour que leur contenu soit celui du commit éprouvé ; le SHA-256 de
chaque archive ou fichier remis est consigné.

**EX-12.3 (sections interdites)** Chaque entrée TR- porte la liste fermée de
ce que le participant ne lit pas (`forbidden_sections`) : la grille, la
section de la spécification qui la contient ou la reprend, la section 15 de
CT-9 pour toute épreuve et la section 12 pour TR-1 à TR-12, le code du dépôt
quand l'épreuve le dit (CT-4 EX-7.14), toute documentation non publiée,
toute personne à interroger. L'interdit porte sur la lecture, non sur la
remise : TR-12 reçoit l'archive entière et ne lit ni 12, ni 15, ni les
entrées TR- du catalogue et d'`INDEX.md` ; TR-13 à TR-15 reçoivent CT-9 sans
la section 15, section 12 comprise. Deux exceptions à l'interdit de la
grille sont écrites : TR-10, dont la grille est `cas.json` et dont les
paquets sont tirés parmi ses cas ; TR-13, dont l'entrée du catalogue est à
la fois matériel et grille, par construction (la grille y est l'entrée et
les exigences qu'elle cite ; le verdict exige une contrepartie exécutable,
EX-15.1). Un participant qui a lu une section interdite est remplacé ;
l'épreuve n'est pas rejouée par lui.

**EX-12.4 (consignation)** Chaque épreuve est consignée dans un fichier conforme
à `$defs/consignation_rejeu` de `plan-de-tests-v0` (CT-9 §4), généralisation de
CT-8 EX-14.10 : identifiant TR-, date, commit éprouvé, participant (pseudonyme,
rôle, extériorité), juge (pseudonyme, indépendance), matériel remis avec son
SHA-256, sections interdites, chemin de la grille ou `null`, durée
(`duration_s`, horloge murale de la remise du matériel à la remise de la
réponse), nombre de demandes d'information hors du matériel
(`information_requests`), verdict (`status`, `disqualifying_statement`, un
membre par élément de la grille avec `present`), SHA-256 de la sortie jointe
quand le participant a exécuté un outil. La réponse elle-même n'est pas publiée
(CT-3 EX-A.5 : « les réponses des relecteurs ne sont pas des vecteurs ») ; la
consignation l'est, sous
`spec/vecteurs/ct-9/consignations/<TR-n>-<AAAA-MM-JJ>-<P-nn>.json`, par
l'examinateur, jamais par le générateur, sauf le gabarit de l'annexe A. Les noms
exacts des membres sont ceux de `$defs/consignation_rejeu` du même schéma, qui
fait foi : `participant` (`pseudonym`, `role`, `external`), `judge`
(`pseudonym`, `independent`), `material[]` (`item`, `sha256`),
`forbidden_sections`, `grid`, `duration_s`, `information_requests`, `verdict` ;
la consignation est écrite par l'examinateur, jamais par un participant, qui ne
reçoit pas le schéma.

**EX-12.5 (juge)** Le juge est une personne qui n'a pas aidé le participant
(CT-3 EX-A.17 : « un troisième relecteur, qui n'a pas aidé les deux autres
»). Il marque chaque élément de la grille présent ou absent dans la réponse,
applique les clauses disqualifiantes que la spécification écrit (CT-7
EX-9.3, EX-9.5 ; CT-8 EX-14.4, EX-14.8, EX-14.12 ; CT-5 EX-3.2 pour TR-4 ;
CT-6 §7.9 pour TR-5), relève la durée et compte les demandes d'information.
Quand la grille est le verdict d'un outil (TR-3, TR-12, TR-15), le juge
relève les codes de retour et les compare à ceux de l'intégration continue
au même commit.

**EX-12.6 (verdict)** Une épreuve est `reussi` si et seulement si chaque
élément de sa grille est présent et qu'aucune affirmation disqualifiante
n'est présente ; sinon `echec`. Un échec est publié avec les éléments absents
nommés, jamais avec la réponse ; il ne rend pas la spécification visée
fautive à lui seul : deux échecs de participants différents sur le même
élément ouvrent une proposition PD- à la spécification visée (17.2).

**EX-12.7 (grilles)** Les grilles sont des fichiers des vecteurs, référencés
par leur chemin dans l'entrée TR- (`grid`) et jamais recopiés dans une
consigne ni dans ce document : `spec/vecteurs/ct-3/acceptation-attendu.json`,
`ct-3/acceptation-console-attendu.json`,
`ct-7/acceptation-securite-attendu.json`,
`ct-7/acceptation-conformite-attendu.json`,
`ct-7/acceptation-attestation-attendu.json`,
`ct-8/acceptation-exploitation-attendu.json`,
`ct-8/acceptation-observation-attendu.json`, `ct-8/paquets/cas.json`, et,
pour les épreuves que leur spécification ne dote d'aucune grille (CT-5 ;
CT-9), les grilles produites par le générateur de `ct-9` :
`ct-9/acceptation-ancrage-attendu.json`,
`ct-9/acceptation-verdict-point-attendu.json`,
`ct-9/acceptation-porte-2-attendu.json` ; TR-13 a pour grille le catalogue
lui-même, remis au participant (exception d'EX-12.3 : l'entrée tirée est à
la fois matériel et grille, le verdict ne tenant que pour une contrepartie
exécutable de chaque précondition, étape et oracle). Un test de
`test/plan-de-tests.test.js` vérifie que chaque consigne remise
(`consigne.md`) ne contient aucun élément de sa grille (annexe A) et que la
grille de chaque autre TR- figure dans ses sections interdites.

**EX-12.8 (durée et aide)** La durée court de la remise du matériel à la remise
de la réponse, sur l'horloge murale ; elle est une mesure quand une entrée TM-
la vise (TR-10 : TM-25 ; TR-12, partie phase 2 : TM-21 et TM-23 ; TM-22 :
procès-verbal d'IC-18 de l'installation complète, TC-80 ; TR-9 est une épreuve
écrite, qui ne chronomètre aucune installation). Toute information demandée hors
du matériel est comptée et consignée, même quand elle est refusée ; compte pour
`information_requests` une question posée à une personne ou la lecture d'un
document non publié ; la consultation de la documentation publique d'un outil
que le matériel remis nomme (Node.js, Go, Python, GNU tar) n'est pas une demande
d'information, sans quoi l'installation sur une machine vierge ferait échouer
l'épreuve par construction ; pour le rejeu complet (TR-12) et l'installation
complète (TM-23), la cible est zéro.

### 12.2 Table des épreuves

Imprimée depuis le catalogue (membre `tests`, niveau `TR`) ; TR-1 à TR-11
sont les épreuves déléguées, TR-12 le rejeu complet (12.3), TR-13 à TR-15
les épreuves propres à CT-9 (section 15). Toutes sont « à écrire » au sens
d'EX-3.10 (aucune n'est un test automatisé) et rattachées à l'étape 8 ; le
membre `blocking` dit ce qui manque : le matériel est publié pour toutes
(consignes et grilles de TR-4, TR-5, TR-13 à TR-15 par le générateur de
`ct-9`, annexe A.9), la partie phase 2 de TR-12 attend l'enregistreur et la
démonstration, et chaque épreuve attend sa conduite à la porte 2.

<!-- table TR -->
| Id | Épreuve | Participant | Matériel remis | Sections interdites | Grille | Verdict | État |
|---|---|---|---|---|---|---|---|
| TR-1 | CT-3 annexe A.5 : trois relecteurs (approbateur, auditeur, développeur) tirent la même décision sur dix cas d'une politique | Trois relecteurs extérieurs, rôles approbateur, auditeur et développeur | spec/vecteurs/ct-3/acceptation/ (consigne.md, politique.json, cas/cas-01.json à cas-10.json, gabarit-reponse.json) ; CT-3, sections 0 à 6 | spec/vecteurs/ct-3/acceptation-attendu.json ; CT-3 sections 7 et suivantes et annexe A ; CT-9 section 12 ; les réponses des autres relecteurs | `spec/vecteurs/ct-3/acceptation-attendu.json` | Réussi si les trois réponses sont égales entre elles et à la grille sur les dix cas (CT-3 EX-A.5). | à écrire (étape 8) |
| TR-2 | CT-3 annexe A.11 (EX-A.17) : lecture de la console par un approbateur et un développeur intégrateur, jugée par un troisième relecteur | Un approbateur et un développeur intégrateur extérieurs | spec/vecteurs/ct-3/acceptation-console/consigne.md et gabarit-reponse.md ; CT-3 sections 9 et 13 (approbateur) ; 7.4, 9, 12 et 13 (intégrateur) | spec/vecteurs/ct-3/acceptation-console-attendu.json ; les autres sections de CT-3 ; CT-9 section 12 | `spec/vecteurs/ct-3/acceptation-console-attendu.json` | Réussi si chaque réponse contient tous les éléments de sa question dans la grille (CT-3 EX-A.17). | à écrire (étape 8) |
| TR-3 | CT-4 §7.12 : un relecteur qui n'a que la spécification crée un client, ancre une racine et clôt une période sur le réseau de développement ; une seconde personne rejoue `verifier` | Un relecteur extérieur ; une seconde personne pour le rejeu de `verifier` | CT-4 sections 0 à 14 ; dépôt au commit de la revue ; poste avec chain/runtime/bin/noorcore (réseau de développement) | le code de scripts/ ; CT-9 section 12 | verdict d'outil | Réussi si chaque condition d'EX-7.15 est vraie et si le rejeu de `verifier` donne le même résultat. | à écrire (étape 8) |
| TR-4 | CT-5 §1 : un relecteur qui n'a que CT-5 et CT-1 §9 à §11 dit la cadence des points, ce qu'un point prouve et ne prouve pas, la fenêtre de réécriture, le coût pour un prix unitaire donné et la conduite si le prestataire est injoignable | Un relecteur extérieur (profil : architecte ou auditeur technique) | spec/vecteurs/ct-9/acceptation-ancrage/consigne.md ; CT-5 entier ; CT-1 sections 9 à 11 | spec/vecteurs/ct-9/acceptation-ancrage-attendu.json ; CT-6, CT-8, CT-9 | `spec/vecteurs/ct-9/acceptation-ancrage-attendu.json` | Réussi si chaque réponse contient tous ses éléments et qu'aucune n'affirme qu'une date d'objet ancré est prouvée par l'ancrage. | à écrire (étape 8) |
| TR-5 | CT-5 §1 et CT-6 §7.9 : un second relecteur qui n'a que CT-6 §7 (révisée) dit ce que le verdict prouve de nouveau avec un point de contrôle, et ce qu'il ne prouve toujours pas | Un relecteur extérieur (profil : réviseur ou juriste technique) | spec/vecteurs/ct-9/acceptation-verdict-point/consigne.md ; CT-6 section 7 (7.1 à 7.10) ; rapport de vérification d'un dossier avec la partie, tiré des vecteurs ct-6 | spec/vecteurs/ct-9/acceptation-verdict-point-attendu.json ; les autres sections de CT-6 ; CT-5, CT-9 | `spec/vecteurs/ct-9/acceptation-verdict-point-attendu.json` | Réussi si chaque réponse contient tous ses éléments et qu'aucune ne présente `rewrite_window_ms` comme prouvé ni la détection comme active. | à écrire (étape 8) |
| TR-6 | CT-7 EX-9.1 : un responsable de la sécurité qui n'a que CT-7 sans la section 9 ni l'annexe A.15 répond à six scénarios d'attaque par la réponse, la détection et le risque résiduel | Un responsable de la sécurité extérieur | CT-7 sans la section 9 ni l'annexe A.15 ; spec/vecteurs/ct-7/acceptation-securite/consigne.md | CT-7 section 9 ; CT-7 annexe A.15 ; spec/vecteurs/ct-7/acceptation-securite-attendu.json ; CT-9 section 12 | `spec/vecteurs/ct-7/acceptation-securite-attendu.json` | Réussi si les six réponses contiennent chacune la menace, une réponse, une détection et le risque résiduel de la grille (CT-7 EX-9.1). | à écrire (étape 8) |
| TR-7 | CT-7 EX-9.2 et EX-9.3 : un responsable de la conformité qui n'a que CT-7 sans la section 9 ni l'annexe A.15 répond à trois questions sur cinq passages, puis à la sixième question | Un responsable de la conformité extérieur | CT-7 sans la section 9 ni l'annexe A.15 ; spec/vecteurs/ct-7/acceptation-conformite/consigne.md | CT-7 section 9 ; CT-7 annexe A.15 ; spec/vecteurs/ct-7/acceptation-conformite-attendu.json ; CT-9 section 12 | `spec/vecteurs/ct-7/acceptation-conformite-attendu.json` | Réussi si chaque réponse contient tous ses éléments et qu'aucune clause disqualifiante d'EX-9.3 n'est présente. | à écrire (étape 8) |
| TR-8 | CT-7 EX-9.4 et EX-9.5 : un administrateur du client qui n'a lu que la section 7 répond à six questions sur l'attestation de périmètre | Un administrateur du client extérieur | CT-7 section 7 ; spec/vecteurs/ct-7/acceptation-attestation/consigne.md ; spec/vecteurs/ct-7/acceptation-attestation/rapport.txt | CT-7 hors section 7 ; spec/vecteurs/ct-7/acceptation-attestation-attendu.json ; CT-9 section 12 | `spec/vecteurs/ct-7/acceptation-attestation-attendu.json` | Réussi si chaque réponse contient tous ses éléments et qu'aucune ne dit l'attestation « preuve du périmètre » ni « preuve de conformité ». | à écrire (étape 8) |
| TR-9 | CT-8 §14 épreuve (a), EX-14.1 à EX-14.5 : un ingénieur d'exploitation extérieur, avec CT-8 sans la section 14 ni l'annexe A, décrit les installations, dimensionne un cas et traite trois incidents | Un ingénieur d'exploitation extérieur au projet et à la rédaction de CT-8 | CT-8 sans la section 14 ni l'annexe A ; spec/vecteurs/ct-8/acceptation-exploitation/consigne.md ; spec/vecteurs/ct-8/acceptation-exploitation/entrees-dimensionnement.json | CT-8 section 14 ; CT-8 annexe A ; spec/vecteurs/ct-8/acceptation-exploitation-attendu.json ; CT-9 section 12 | `spec/vecteurs/ct-8/acceptation-exploitation-attendu.json` | Réussi selon CT-8 EX-14.5 : tous les éléments de CT-8 EX-14.2, dimensionnement à l'octet près, partie incidents réussie (CT-8 EX-14.4). | à écrire (étape 8) |
| TR-10 | CT-8 §14 épreuve (b), EX-14.6 à EX-14.10 : un réviseur extérieur, avec la seule section 13 et un poste sans réseau, vérifie deux paquets réviseurs en une commande et dit ce que le résultat prouve | Un réviseur extérieur au projet et à la rédaction de CT-8 | CT-8 section 13 ; paquet.tar (valide.tar et son empreinte) puis un second paquet tiré au sort parmi les cas de code 1 ou 4 ; poste sans réseau : Node.js 22, GNU tar, répertoire verificateur/ d'un paquet complet construit par la CI | CT-8 hors section 13 ; le dépôt ; spec/vecteurs/ct-8/paquets/cas.json ; toute personne à interroger | `spec/vecteurs/ct-8/paquets/cas.json` | Réussi selon CT-8 EX-14.8 pour chacun des deux paquets. | à écrire (étape 8) |
| TR-11 | CT-8 §14 épreuve (c), EX-14.11 et EX-14.12 : un administrateur du client qui n'a lu que la section 12 répond à cinq questions sur le mode observation | Un administrateur du client extérieur | CT-8 section 12 ; spec/vecteurs/ct-8/acceptation-observation/ (consigne.md, evenement-seq-3.json, rapport-observation.json) | CT-8 hors section 12 ; spec/vecteurs/ct-8/acceptation-observation-attendu.json ; CT-9 section 12 | `spec/vecteurs/ct-8/acceptation-observation-attendu.json` | Réussi selon CT-8 EX-14.12. | à écrire (étape 8) |
| TR-12 | Rejeu complet sur machine vierge : une personne extérieure, avec la seule documentation publiée, installe, régénère les vecteurs, exécute les tests et les vérificateurs, et vérifie un dossier et un paquet | Une personne extérieure au projet (profil : ingénieur) | archive du dépôt au commit éprouvé, ou son URL publique ; README.md, README.fr.md, spec/ (toute la documentation publiée ; les sections interdites sont présentes dans l'archive et ne sont pas lues) ; machine vierge au système de référence de 11.1 | toute documentation non publiée ; toute personne à interroger ; CT-9 sections 12 et 15, entrées TR- de spec/vecteurs/ct-9/catalogue.json et d'INDEX.md : présentes dans l'archive remise, non lues (EX-12.3) ; la liste des commandes à exécuter est celle de README.md et de la consigne | verdict d'outil | Réussi si chaque code de retour égale celui de la CI, si `information_requests` est nul et si le dossier et le paquet sont vérifiés par la copie jointe hors réseau. | à écrire (étape 8) |
| TR-13 | CT-9 épreuve (a) : un testeur qui n'a que CT-9 et la spécification visée écrit, pour cinq entrées « à écrire » tirées au sort, les préconditions, les étapes et l'oracle en code ou pseudo-code exécutable, sans contredire le catalogue | Un testeur extérieur au projet | CT-9 sans la section 15 ; les identifiants des cinq entrées tirées, remis par le juge ; les spécifications que ces entrées visent (membre `specs`) et, de toute autre spécification que leurs préconditions, pas, oracle ou bloc propre nomment, les sections citées ; spec/vecteurs/ct-9/acceptation-plan/consigne.md ; spec/vecteurs/ct-9/catalogue.json | CT-9 section 15 ; test/*.test.js du dépôt | `spec/vecteurs/ct-9/catalogue.json` | Réussi si les cinq fichiers rendus ont, pour chaque précondition, étape et oracle de leur entrée, une contrepartie exécutable et ne contredisent aucun oracle ; une réponse qui reprend le texte de l'entrée sans entrée concrète ni comparaison exécutable échoue. | à écrire (étape 8) |
| TR-14 | CT-9 épreuve (b) : un relecteur de la porte 2 qui n'a que CT-9 dit ce que le passage de la porte 2 prouve et ne prouve pas, et quel critère du plan chaque famille de tests sert | Un relecteur extérieur de la porte 2 | CT-9 sans la section 15 ; spec/vecteurs/ct-9/acceptation-porte-2/consigne.md | CT-9 section 15 ; spec/vecteurs/ct-9/acceptation-porte-2-attendu.json ; le plan de projet interne | `spec/vecteurs/ct-9/acceptation-porte-2-attendu.json` | Réussi si chaque réponse contient tous ses éléments et qu'aucune clause disqualifiante n'est présente. | à écrire (étape 8) |
| TR-15 | CT-9 épreuve (c) : un développeur qui n'a que CT-9 ajoute au catalogue un test pour une exigence donnée en suivant les seules règles de CT-9, et l'outil de couverture l'accepte | Un développeur extérieur au projet | CT-9 sans la section 15 ; dépôt au commit éprouvé ; spec/vecteurs/ct-9/acceptation-plan/consigne.md | CT-9 section 15 ; toute aide d'un auteur de CT-9 | verdict d'outil | Réussi si l'outil de couverture rend 0, sans et avec `--strict`, avec l'entrée ajoutée, qui couvre l'exigence désignée (exigence préfixée de sa spécification dans `covers`), et si aucune autre entrée n'a changé. | à écrire (étape 8) |


### 12.3 Rejeu complet sur machine vierge (TR-12)

**EX-12.9 (définition)** Le rejeu complet éprouve que la documentation publiée
suffit à reproduire, sans aide, ce que l'intégration continue établit : une
personne extérieure, sur une machine vierge de la classe du système de référence
(EX-11.1), avec la seule archive du dépôt au commit éprouvé (ou son URL
publique) et aucune autre source, installe les outils d'après `README.md`,
exécute `npm ci` puis `npm test`, régénère les vecteurs `spec/vecteurs/ct-1` à
`ct-9` et constate un diff nul (l'arbre régénéré est identique à l'arbre remis,
sans fichier de plus : sur un clone, `git diff --exit-code -- spec/vecteurs`
rend 0 et `git status --porcelain --untracked-files=all -- spec/vecteurs` ne
rend aucune ligne ; ou `diff -r` avec une seconde extraction de l'archive),
exécute `go run . ..` dans chaque `verificateur-independant/`, vérifie
`spec/vecteurs/ct-6/dossiers/valide-seq-7-complet` par
`scripts/verify/dossier.mjs` avec les ancres et les en-têtes de test, et
construit puis vérifie un paquet réviseur complet par sa copie jointe sous
`unshare -n env -i` (CT-8 EX-A.29) ; le réseau n'est coupé que pour cette
commande de vérification, le clone ou l'extraction, l'installation des outils et
`npm ci` se faisant avec réseau. En phase 2, elle poursuit par l'installation
rapide (TM-21), l'export du dossier d'IR-8 et sa vérification par les deux
vérificateurs, et la démonstration en une commande (TM-43), l'accès à Internet
coupé pendant cette seule mesure (CT-2 EX-19.1).

**EX-12.10 (critères)** Le rejeu est `reussi` si chaque code de retour
consigné égale celui de l'intégration continue au même commit (0 pour les
tests, les régénérations, les vérificateurs Go, le dossier et le paquet ; 3
pour `dossier.mjs … --exiger 4,5,8` sur `ct-1/dossiers/valide-seq-7`), si
`information_requests` est nul et si la durée est consignée. Un code
différent est un échec qui nomme la commande ; la porte 2 y répond
« reprendre CT-6 et l'étape 2 » (section 14).

**EX-12.11 (ce qu'il prouve)** Un rejeu réussi établit que les objets
publiés sont documentés, cohérents, complets et exécutables, et qu'un tiers
a régénéré les résultats avec ces objets (niveaux « Functional » et « Results
Reproduced » des définitions publiées de l'évaluation d'artefacts, R11-F37,
R11-F38) ; il ne prouve ni que les règles vérifiées sont les bonnes (CT-6
§7), ni qu'un autre tiers, sur une autre machine, obtiendrait la même chose
hors de la classe d'EX-11.1.

**EX-12.12 (partie conductible dès maintenant)** La partie dépôt d'EX-12.9 est
conductible dès la version 0.1, dès lors que `ci.yml` a été exécuté au commit
éprouvé et que ses codes de retour ont été consignés par le juge avant l'épreuve
(EX-12.5 : la grille est ce verdict ; sans cette exécution, la grille n'existe
pas et l'épreuve attend) ; une consignation publiée avant la porte 2 est admise
et compte pour la porte 2 si le commit éprouvé est celui de la porte. TR-12 peut
ainsi donner deux consignations sous le même identifiant, une pour la partie
dépôt et une pour la partie phase 2, au même commit éprouvé, avec deux
participants admis ; la ligne 2 de la porte 2 lit la partie dépôt, la ligne 7 la
partie phase 2 ; chaque consignation porte son verdict EX-12.10 sur ses propres
éléments, et son fichier porte l'étiquette de la partie dans son nom
(`TR-12-<AAAA-MM-JJ>-<P-nn>-depot.json`, `…-phase-2.json`).

### 12.4 Ce qu'un rejeu prouve et ne prouve pas

Une épreuve réussie prouve que le texte remis a suffi à ce participant pour
produire les éléments de la grille ; elle ne prouve pas que le texte suffit
à tout lecteur (un participant par rôle en version 0), ni que les éléments
de la grille sont les bons (la grille est écrite par les auteurs). Un échec
prouve qu'un lecteur extérieur n'a pas trouvé un élément ; il ne dit pas
seul si le texte ou la grille est en cause (EX-12.6). Les réponses ne sont
pas publiées ; la consignation l'est : qui veut contrôler le jugement relit
la consignation et la grille, pas la réponse.

---

## 13. Revue de code (TQ-)

CT-7 fixe le périmètre (composants de §3.2, menaces de §3.4) et constate
qu'aucune revue n'a été faite (CT-7 §10) ; CT-8 renvoie à la revue de code
pour une version publiée malveillante (RA-22, CT-8 §3.6) ; CT-7 §4.1 lui
confie le contrôle de l'inventaire des clés. Huit entrées, toutes à écrire
(étape 8, étape 7 pour la chaîne de construction) ; les bibliothèques de
référence et les modules Go existants sont relisibles dès maintenant selon
la même grille, ce que chaque entrée dit dans `blocking`.

**EX-13.1** Une revue TQ- est faite par une personne qui n'a pas écrit le
code relu, avec `menaces.json` et le catalogue ; sa grille remplie est
consignée avec le commit relu ; elle est réussie si chaque menace du
composant a sa réponse localisée (fichier, fonction) et son TA- qui échoue
quand la réponse est retirée, et si chaque écart est tracé en correction ou
en risque accepté nommé, borné, attribué (CT-7 §3.5). **EX-13.2** TQ-5
relit aussi les sept modules Go `verificateur-independant/` : bibliothèque
standard seule, aucune lecture ni recopie du JavaScript ; pour `ct-5`, la
partie que son `README.md` déclare non écrite à l'aveugle (R10-F35) est
relue à l'aveugle ou la mention « indépendant » est retirée.

<!-- table TQ -->
| Id | Objet | Identifiants couverts (famille : nombre) | Menaces | État |
|---|---|---|---|---|
| TQ-1 | Revue de code de l'enregistreur : frontal MCP, passerelle, SDK et ingestion, écrivain et stockage, WORM, clés (CT-7 §3.2 ; CT-2 §18) | CT-2 EX-18- (9), CT-2 EX-11- (19), CT-7 EX-3- (13), CT-2 EX-4- (3), CT-2 EX-5- (2), CT-2 EX-3- (1) | MN-1, MN-2, MN-7, MN-8, MN-9, MN-10, MN-11, MN-12, MN-13, MN-14, MN-15, MN-16, MN-17, MN-18, MN-19, MN-20, MN-21, MN-22, MN-23, MN-24, MN-25, MN-26, MN-27, MN-28, MN-29, MN-30, MN-31, MN-33, MN-43 | à écrire (étape 8) |
| TQ-2 | Revue de code du service d'approbation et de la console (CT-7 §3.2 `approbation_console` ; CT-3 §14) | CT-3 EX-14- (1), CT-3 EX-3- (3) | MN-35, MN-44, MN-45, MN-46, MN-47, MN-48, MN-49, MN-50, MN-51, MN-52 | à écrire (étape 8) |
| TQ-3 | Revue de code du registre et de l'exploitant : contrats, outil de référence, image du nœud, publication (CT-7 §3.2 `registre`, `exploitant` ; CT-4 §12) | CT-7 EX-8- (1) | MN-53, MN-54, MN-55, MN-56, MN-57, MN-58, MN-59, MN-71, MN-72, MN-73, MN-97 | à écrire (étape 8) |
| TQ-4 | Revue de code du composant d'ancrage (CT-7 §3.2 `ancrage` ; CT-5 §13) | CT-5 EX-13- (1), CT-5 AN- (1) | MN-60, MN-61, MN-62, MN-63, MN-64, MN-65, MN-76 | à écrire (étape 8) |
| TQ-5 | Revue de code du vérificateur et indépendance des vérificateurs Go (CT-7 §3.2 `verificateur` ; CT-6 §15) | CT-6 EX-15- (3), CT-6 EX-3- (6), CT-5 EX-A- (1), CT-7 EX-8- (1) | MN-66, MN-67, MN-68, MN-69, MN-70, MN-78, MN-79, MN-80, MN-81, MN-83, MN-89 | à écrire (étape 8) |
| TQ-6 | Revue des fichiers de déploiement et de la configuration de l'administrateur du client (CT-7 §3.2 `administrateur_client`, `reseau` ; CT-8 §3, §5) | CT-8 EX-5- (6) | MN-74, MN-75, MN-77, MN-82, MN-84, MN-85, MN-86, MN-87, MN-88, MN-90, MN-91, MN-96, MN-98 | à écrire (étape 8) |
| TQ-7 | Inventaire des clés et des secrets à jour : chaque clé ou secret introduit par une révision a sa ligne CLE- (CT-7 §4.1) | CT-7 CLE- (29), CT-7 EX-4- (10) | MN-30, MN-31, MN-39, MN-43 | à écrire (étape 8) |
| TQ-8 | Revue de la chaîne de construction et de publication des images : version publiée malveillante (RA-22, CT-8 §3.6) | CT-7 EX-3- (2), CT-8 EX-3- (3) | MN-25 | à écrire (étape 7) |

## 14. Porte 2

La porte 2 du plan (phase 2, étape 8) se lit en critères « continuer si » et
« arrêter ou reprendre si ». Chaque critère est rattaché à des entrées du
catalogue et à un verdict calculable depuis leurs résultats (rapport
d'exécution, rapport de mesure, consignation des TR-). Un critère sans test
n'existe pas ; un test sans critère est une exigence d'une spécification, pas un
critère de porte. Les verdicts se lisent dans trois sources et un rapport
d'outil : le rapport d'exécution (EX-A.19 : `results[].test_id`, `status` parmi
`reussi`, `echec`, `en_attente` et `non_applicable`, `reason`), le rapport de
mesure (11.3 : `results[].met`, et `counts_for_targets` et `system` du rapport),
les consignations des TR- (EX-12.4 : `verdict.status`), et `threats.without_ta`
de `couverture.json` (5.4). Les lignes se comptent dans l'ordre des tables :
« continuer si » 1 à 10, « arrêter ou reprendre si » 1 à 4 (les « lignes
d'arrêt ») ; le libellé de la ligne 1 est celui du plan, et ses entrées (TE-12,
TE-13, TA-99 à TA-103) en font partie.

**EX-14.1** La porte 2 est franchie si et seulement si chaque ligne « continuer
si » rend `vrai` ; une ligne « arrêter ou reprendre si » qui rend `vrai` nomme
la spécification et l'étape à reprendre, ou l'arrêt. Les dix lignes « continuer
si » et les quatre lignes « arrêter ou reprendre si » viennent du plan de projet
(R10-F45) : la ligne du plan qui groupe quatre exigences mesurables (fenêtre de
réécriture, installation, paquet réviseur, intégrations) y est scindée en quatre
lignes, les entrées qui servent chaque critère y sont nommées, et aucun prix n'y
figure (« à un prix compatible »). Un critère « continuer si » faux sans
contrepartie bloque la porte sans nommer de reprise, et la suite est décidée par
le plan, hors de CT-9 ; de même, « Arrêter » (lignes d'arrêt 3 et 4) nomme la
décision que prend le plan de projet, hors de CT-9. Le rapport d'exécution de la
porte 2 (EX-A.19) est la source des verdicts `reussi` ; une entrée dont une
partie dépend d'une proposition non adoptée (`status.depends_on` : TA-26, PA-1 ;
TA-88, PA-10) est comptée `non_applicable` pour cette partie, la proposition
étant nommée dans le rapport, et sa partie non conditionnée reste due ; TA-88,
entièrement conditionné, est `non_applicable` tant que PA-10 n'est pas adoptée
(RA-74 demeure) et exécuté sinon. Un résultat `non_applicable` ne rend aucune
ligne `faux` ; il est compté à part dans le rapport d'exécution, et la partie
non conditionnée de l'entrée est jugée comme toute autre. `status.depends_on` ne
porte qu'une proposition dont l'adoption crée la règle éprouvée : un PA- de
CT-7, ou un PD- de la table 17.2 (l'outil de couverture le cherche dans cette
table, 5.4) ; une proposition qui ne fixe qu'une forme ou une définition (ligne
de journal, statut, schéma de configuration, instants d'une durée imprimée :
CT-8 PD-7 pour TA-51 ; PD-25, PD-26 et PD-27 de CT-9 pour TM-43, TI-19 et TE-17)
est un écart consigné dans l'oracle (17.2), et la partie concernée reste due ;
au 2026-11-10, seules TA-26 (PA-1) et TA-88 (PA-10) portent `depends_on`. Une
réponse non codée à la porte 2 (TA-93, et, avant le démon de l'étape 4, TA-2
et TA-30) est un livrable manquant (EX-3.12) : la ligne 4 rend `faux` ; « Arrêter » ne vise qu'un mutant
qui survit à une réponse codée. Un mutant survivant est d'abord examiné par
l'examinateur de la porte 2 selon EX-10.5 et EX-10.6 (remplacement exact et
unique, réponse retirée et rien d'autre, chemin exercé par l'attaque) ; un
mutant mal posé est une correction du test à l'étape 8 : l'exécution au mutant
mal posé est publiée `echec`, la cause dans `reason`, et reste publiée comme
trace ; le test corrigé est rejoué, et c'est son résultat, porté au rapport
d'exécution de la porte 2, qui compte pour la ligne 4 ; seul un survivant
confirmé par la grille TQ- du composant (EX-13.1 : réponse localisée dans le
code que l'observation ne distingue pas) déclenche la ligne « Arrêter ». Les
deux cas se distinguent ainsi : une **réponse non codée** est une réponse
absente de l'implémentation, que le catalogue constate (`notes` de l'entrée ;
TA-93, 10.4) : livrable manquant, ligne 4 ; une **menace sans
réponse localisée** (ligne d'arrêt 3) est une réponse codée (entrée
`executable`, mutant fabriqué) dont le mutant survit et que la grille TQ- du
composant confirme : réponse localisée dans le code que l'observation ne
distingue pas (EX-13.1) ; « sans réponse localisée » veut dire sans réponse dont
l'effet est observable : la réponse existe dans le code, mais son retrait ne
change pas l'observation de l'attaque ; le mutant survivant et la grille qui le
confirme sont un même cas, vu par ses deux entrées. « Mutant tué » (ligne 4)
s'entend de l'observation `expected_without_response` de l'entrée, quelle que
soit la forme du retrait : mutant de la fabrique (EX-10.5), régénération
(EX-10.4 : TA-23, TA-72), étape de CI retirée (TA-66), complément dû à l'étape
nommée (TA-10, TA-40, TA-53) ou procédure humaine (TA-95, TA-97) ; une entrée
exécutable sans retrait joué aujourd'hui (TA-11) compte par son complément, dû à
l'étape nommée.

| Critère « continuer si » | Entrées | Verdict calculable |
|---|---|---|
| Les deux cas traversent la chaîne de la capture au dossier | TE-1, TE-2 ; TE-12 (ancrage complet), TE-13 (console) ; TA-99 à TA-103 joués sur la même démonstration | Rapport d'exécution (EX-A.19) : `reussi` pour TE-1, TE-2, TE-12 et TE-13 ; chaque dossier exporté par ces quatre entrées : code 0 des deux vérificateurs de CT-6 (JavaScript et Go), énoncé identique (CT-6 §6.5) ; TA-99 à TA-103 `reussi` selon EX-10.9, chaque dossier qu'un scénario exporte portant le code et l'énoncé que son oracle attend, identiques entre les deux vérificateurs (TA-100 attend CT-1 K-7 ou K-8 en échec, exécutées par CT-6 §9.9 et §11.9) ; un scénario dont un test composé échoue tombe sous la ligne 4 ; un scénario qui n'exporte aucun dossier compte pour cette ligne par la seule réussite de ses tests composés et de son oracle de bout en bout (EX-10.9), l'exigence du code 0 des deux vérificateurs ne s'appliquant qu'aux dossiers effectivement exportés ; un dossier non vérifié par les deux vérificateurs rend la ligne `faux` ; répartition entre les lignes 1 et 4 : pour un scénario, la ligne 1 lit son oracle de bout en bout (EX-10.9) et les dossiers qu'il exporte, la ligne 4 lit chacun de ses tests composés avec son mutant |
| La vérification est reproduite sans aide, à partir de la seule documentation : sur une machine vierge (TR-12) et sur le poste sans réseau d'un réviseur (TR-10) | TR-12 (rejeu complet, 12.3), TR-10 (CT-8 épreuve (b)) | Consignation `TR-12-<AAAA-MM-JJ>-<P-nn>-depot.json` (partie dépôt de TR-12, EX-12.12) : `reussi` selon EX-12.10 (codes égaux à ceux de la CI au même commit, `information_requests` = 0, durée consignée) ; la partie phase 2 (`…-phase-2.json`) est lue par la ligne 7 ; TR-10 `reussi` selon CT-8 EX-14.8 (codes et états des deux paquets égaux à `cas.json`, sortie jointe, phrase de CT-8 §13.10 (ce que le résultat prouve) ; demandes d'information comptées et publiées, sans cible) ; sinon `faux` |
| La latence ajoutée mesurée respecte l'objectif de CT-2 | TM-1, TM-2, TM-4 (CT-2 §16.1 : latence par appel relayé, premier octet SSE, échange de modèle hors flux) | Rapport de mesure (11.3) : lignes `latence_appel_relaye` (TM-1) et `latence_echange_modele` (TM-4) : `p50 ≤ 5 ms` et `p99 ≤ 50 ms` ; ligne `latence_premier_octet_sse` (TM-2) : `max ≤ 10 ms` (malgré son nom, cette ligne porte le maximum de la latence ajoutée sur tous les octets du flux, oracle de TM-2) ; soit `met` vrai des trois lignes (EX-11.14 : le seuil d'échec de TM-1, TM-2 et TM-4 égale leur cible) ; `system.reference` vrai, `system.disk.fsync` vrai, `counts_for_targets` vrai ; un `p50` hors cible rend la ligne `faux` sans reprise nommée, la ligne d'arrêt 2 ne lisant que `p99` et `max` (cas générique d'EX-14.1) |
| Les tests adversariaux passent | TA-1 à TA-98 (un par menace) et TA-99 à TA-103 (scénarios du plan), section 10 | Rapport d'exécution : chaque TA- `reussi` avec la réponse, et son mutant tué (échec sans la réponse) ; TA-26 (PA-1) et TA-88 (PA-10) `non_applicable` pour leur partie conditionnée tant que la proposition n'est pas adoptée (EX-14.1) ; TA-2 et TA-30 `reussi` exigé (réponses codées par le démon de l'étape 4), TA-93 `reussi` exigé (réponse à coder, PD-13, PD-9 ; étape 8) ; `threats.without_ta` vide dans `couverture.json` |
| La démonstration en une commande tourne | TE-3, TM-43 | TE-3 `reussi` ; rapport de mesure : `max` de la ligne `demonstration_duree` < 120 s (TM-43, `strictement_inferieur`, CT-2 EX-19.1), `met` vrai, `counts_for_targets` vrai sur le système de référence |
| Fenêtre de réécriture mesurée au plus égale à 5 min | TM-42 (`W_date`, P-3 de CT-5), TM-41 (`W_ordre`) | Rapport de mesure : `vrai` si et seulement si la ligne `w_date_porte_2` (TM-42) rend `met` vrai (`W_date` p99 ≤ 300 s avec la configuration de la porte 2 : `c_T` = 60 s, points chez le principal) et si la ligne `w_ordre` (TM-41) figure dans le même rapport (une ligne `results[]` de nom `w_ordre` y est présente), quelle que soit sa valeur (`met`, valeur mesurée et `excluded_reason`, `null` compris) (son seuil de 120 s est une exigence de supervision dérivée de CT-5 §3.3, pas un critère de porte) ; `faux` dans tout autre cas ; lecture provisoire du critère (11.6, 16, `blocking` de TM-42) : tant que le plan n'a pas confirmé la configuration, la ligne se calcule avec la lecture de TM-42 (`W_date` p99 ≤ 300 s, `c_T` = 60 s, points chez le principal) et le rapport de mesure nomme cette lecture dans `conditions` ; la confirmation du plan ne suspend pas le calcul, elle peut seulement en changer la configuration à la révision suivante de CT-9 (section 16) ; la ligne rend donc toujours `vrai` ou `faux` |
| Installation par une personne extérieure en 15 min | TE-6 ; TM-21 (IR-1 à IR-8), exécuté dans la partie phase 2 de TR-12 | Pour l'exécution d'un participant extérieur : rapport de mesure, ligne `ir_total` (`result_name` de TM-21) `met` vrai (≤ 900 s) ; consignation de TR-12, partie phase 2 : `participant.external` vrai (extériorité d'EX-12.4) et dossier de CT-8 IR-8 au code 0 des deux vérificateurs ; TE-6 est l'entrée qui décrit ce parcours, son verdict `reussi` n'est pas exigé par cette ligne ; TM-21 a deux exécutions possibles : celle de l'ingénieur du lot, qui joue le parcours de TE-6 à l'étape 7 et publie sa ligne `ir_total` (publiée, non comptée : aucune consignation de TR-12 ne la porte avec `participant.external` vrai), et celle du participant extérieur de TR-12, partie phase 2, seule comptée par cette ligne ; plusieurs participants sont jugés un par un (EX-11.3) et la ligne rend `vrai` dès qu'une exécution extérieure satisfait le critère |
| Paquet réviseur produit | TU-39, TV-71, TI-20 ; TR-10 (CT-8 épreuve (b)) ; TM-25 (EX-13.1 point 7) | Rapport d'exécution : TV-71 `reussi` (étape de CI « paquet réviseur complet, construit deux fois, vérifié par le dépôt puis par sa copie jointe hors réseau » : mêmes octets, code 0 de la copie jointe), TU-39 et TI-20 `reussi` ; consignation de TR-10 : verdict `reussi` ; rapport de mesure : chaque ligne `reviseur_temps` (TM-25) publiée pour un réviseur extérieur (une par participant, EX-11.3) a `met` vrai (< 30 min ; l'oracle de TM-25 fait foi : `value < 1800` s pour chaque participant ; la règle « dès qu'une exécution » de la ligne 7 ne vaut pas ici) ; la vérification hors réseau par la copie jointe est celle de TR-12 (EX-12.9) et du poste sans réseau de TR-10 |
| Intégrations OpenAI, Anthropic, Gemini, LangGraph, CrewAI, LlamaIndex, LiteLLM et OpenTelemetry exercées | TI-4 à TI-11 | Rapport d'exécution : huit `reussi` |
| Un prestataire accepte l'horodatage horaire par lots à un prix compatible | TI-16 (prestataires réels) | Part calculable : fiche de prestataire (CT-5 §11) au statut `qualified` (CT-5 EX-5.9), jeton acquis et vérifié (TI-16 `reussi`) ; la compatibilité du prix est une décision du plan de projet, consignée hors du dépôt, que CT-9 enregistre sans la recalculer ; le prix n'entre jamais dans le dépôt : le verdict est `vrai`/`faux` sans montant, écrit par l'examinateur de la porte 2 dans le rapport d'exécution (EX-A.19), `result` de TI-16, membre `reason` : « prix : décision du plan du <date>, compatible » ou « … incompatible » ; un prestataire qualifié à prix incompatible rend la ligne `faux`, cas générique d'EX-14.1 (blocage sans reprise nommée) |

| Critère « arrêter ou reprendre si » | Entrées | Verdict calculable | Suite |
|---|---|---|---|
| La reproduction échoue | TR-12, TR-10 | TR-12 : verdict `echec`, ou code d'un outil différent de celui de la CI au même commit ; TR-10 : verdict `echec` selon CT-8 EX-14.8 | Reprendre CT-6 et l'étape 2 |
| La latence est inacceptable pour un agent réel | TM-1, TM-2, TM-4 | `p99 > 50 ms` sur `latence_appel_relaye` ou `latence_echange_modele`, ou `max > 10 ms` sur `latence_premier_octet_sse`, avec `system.disk.fsync` vrai et `counts_for_targets` vrai | Reprendre CT-2 |
| Une menace du modèle n'a pas de réponse qui tienne | TA-1 à TA-103 ; TQ-1 à TQ-8 | Un TA- à réponse codée qui passe sans la réponse (mutant survivant), ou une grille TQ- avec une menace sans réponse localisée, les deux termes du « ou » désignant les deux entrées d'un même cas (EX-14.1 : survivant confirmé par la grille TQ- du composant) ; une grille seule, sans survivant, ne déclenche rien ; un survivant bien posé sans grille remplie n'arrête pas la porte : son TA- n'est pas `reussi`, la ligne 4 rend `faux` et la porte est bloquée sans reprise nommée (EX-14.1) ; une réponse non codée relève de la ligne 4 (livrable manquant), pas de l'arrêt | Arrêter |
| Aucun prestataire n'accepte le lot horaire à un prix compatible | TI-16 | Aucune fiche de prestataire au statut `qualified` avec jeton acquis (le prix n'entre pas dans ce verdict : un prestataire qualifié à prix jugé incompatible par le plan rend la ligne 10 `faux` sans arrêt ni reprise nommée, EX-14.1) | Arrêter |

L'achèvement de la revue interne TQ-1 à TQ-8 n'est pas un critère « continuer
si » de la porte 2 : les TQ- n'entrent dans la porte que par la ligne d'arrêt 3,
quand une grille remplie révèle une menace sans réponse localisée ; une grille
non remplie ne déclenche rien, et la porte franchie ne prouve pas que la revue a
été faite (EX-14.2). EX-3.12 (passage à `executable` des entrées rattachées à
l'étape livrée, ou motif écrit dans la livraison) vaut pour la livraison de
l'étape 8, non pour la porte : la porte peut être franchie sans grille TQ-
remplie ; son renvoi par EX-14.1 qualifie seulement une réponse non codée de
livrable manquant (TA-93, étape 8), que la ligne 4 juge.

**EX-14.2** Ce que la porte 2 ne mesure pas, et le dit : les critères SU-1 à
SU-7 de la règle de substitution (CT-4 §11.2, relevés sur trente jours de
pilote, NC- `hors_version_0`) ; la conformité d'un client à un texte (CT-7
§8 : correspondances techniques, jamais un avis) ; la preuve du périmètre de
capture (CT-7 §7.8 : l'attestation est déclarative) ; les durées des
sections 10 à 12 de CT-8 qui n'ont pas de TM- avec seuil d'échec (cibles
publiées, non critères) ; la robustesse des composants face à un attaquant
hors du modèle de menace de CT-7 §3.4 ; la revue de code par un tiers
indépendant (TQ- interne seulement, étape 8).

## 16. Ce que cette version ne couvre pas

- **Les résultats d'exécution des tests « à écrire »** : 98 entrées du
  catalogue (table de 5.5), les compléments des douze TA- exécutables et
  ceux de TV-55, de TI-16, de TE-14, de TE-16, de TM-11, TM-14, TM-17, TM-30
  et TM-41 n'ont aucun résultat ; aucun n'est inventé.
- **Les tests de propriétés** (TU-12) : écrits à l'étape 1 de la phase 2,
  sur la bibliothèque noyau ; cette version n'en fixait que les réglages.
- **Les tests de mutation automatisés** : CT-9 n'adopte aucun outil de
  mutation (StrykerJS, PIT, R11-F23 à R11-F27) ; chaque TA- retire sa
  réponse à la main, par une copie de l'implémentation ou une configuration
  ; un outil de mutation est une piste pour une version ultérieure.
- **La manipulation de l'horloge des binaires Go** (noorcore, vérificateurs)
  : `libfaketime` ne les atteint pas (R11-F51) ; les tests d'horloge passent
  par l'horloge injectée (`ancrage.mjs`, CT-5 EX-8.13) ou par des
  horodatages fixes ; aucun test ne règle l'horloge système.
- **L'exécution de noorcore dans l'intégration continue** : TE-4 et la
  variante de TE-12 sur le réseau de développement s'exécutent hors CI, par
  `chain/scripts/dev-net.sh` (CT-5 EX-A.7) ; la variante hors réseau public
  de TE-12 (nœud factice) est jouée par le travail `ancrage` de `ci.yml`.
- **Docker et les images** : aucune image de NOORTRACE construite ; les tests
  des étapes 4 et 5 lancent seulement des conteneurs de services tiers épinglés
  par condensé (S3 à Object Lock, PostgreSQL, etcd) ; TE-3, TE-6, TE-7, TE-15
  attendent les images de NOORTRACE.
- **Le vérificateur Go de CT-6** (binaire de CT-6 §14) : sa publication
  (EX-14.7, EX-14.9), complément de TV-55, étape 7.
- **La famille `supervision/` et SV-1 à SV-7** : TV-76 à écrire, lot
  suivant de CT-8.
- **Le rejeu réel du registre dans la confrontation** (go-ethereum et
  noorcore) : sorties publiées vérifiées, programme non rejoué en CI.
- **La version à épingler du registre GenAI** : le dépôt courant n'a aucune
  version publiée (R11-F40) ; TI-1 attend la révision de CT-2 EX-6.25.
- **Une définition normative publique de « test oracle », « test level »,
  « exit criteria »** : non lues (ISO/IEC/IEEE 29119-1 §4.1.10 et SEVOCAB
  hors aperçu gratuit, R11-NV2, R11-NV4) ; CT-9 définit ses termes (section
  2).
- **Les critères SU-1 à SU-7 de CT-4** : hors porte 2 (NC-, 14).
- **Le nombre de cas en attente dans la CI** : 6 ici (interpréteurs Python
  épinglés absents) ; dans le job `tests` sans Playwright, la partie
  Chromium de `console.test.js` s'ajoute (R10-NV7) ; le job
  `console-chromium` l'exige sans attente.
- **Les tests adversariaux de phase 2 non écrits** : 12 entrées TA- à menace
  d'exécution `phase_2` à écrire (dont TA-95 et TA-97, épreuves de
  procédure), les compléments des douze entrées de l'étape 8 (TA-5, TA-14,
  TA-40, TA-41, TA-42, TA-43, TA-53, TA-61, TA-62, TA-66, TA-68, TA-73) ;
  aucun complément n'est rattaché à l'étape 4 ; et les
  cinq scénarios de bout en bout : décrits avec préconditions, pas et oracle ; aucun n'a été
  exécuté, la console, la démonstration de référence et l'exploitation
  n'existant pas. Les dix TA- d'exécution `phase_2` passés
  exécutables à l'étape 4 (dont TA-31 et TA-33, lot des signataires) se
  jouent sur le démon (10.4) ; TA-41, passé exécutable à l'étape 5, se joue
  sur le démon et le composant d'ancrage, sans mutant (complément).
- **Une réponse non codée** dans l'implémentation de référence, que le plan
  de tests constate sans la corriger : CT-7 EX-5.11 (réserve sur un
  procès-verbal de production sans ancre de `D_C`, TA-93, PD-13 et PD-9,
  étape 8) ; son test échouera tant qu'elle n'est pas codée. CT-2 EX-7.2
  (TA-2) et EX-11.8 (TA-30), que la bibliothèque de référence ne code pas,
  sont codées par le démon de l'étape 4 et éprouvées sur lui.
- **Les mutants de l'outil de référence du registre** (TA-40, TA-53, TA-73),
  du lecteur `.ots` (O-1, TA-68), de `verifierRelais` (RL-2, RL-3, TA-5) et
  des règles de la révision 0.4 de CT-6 (`sid` sans certificat, CT-6
  EX-9.10, et clé ou algorithme hors de la version 0, CT-6 EX-9.24 : TA-61 ;
  borne des clés RSA, CT-6 EX-9.23 : TA-68) : les tests existants ou le
  mutant cité couvrent l'oracle ; le retrait de cette partie de la réponse
  est un complément (étape 8), non joué.
- **Le retrait de la relève elle-même** (TA-62) : sur la trace figée, il
  épuise les gigues injectées et lève avant l'oracle ; la relève d'une
  demande en cours est éprouvée sur le composant d'ancrage depuis l'étape 5,
  sans mutant ; le mutant du composant est le complément (étape 8, PD-24).
- **Les bornes chiffrées de RA-18, RA-29 et RA-56** (`clock_tolerance_s`,
  échéances d'alerte) : aucune entrée TM- ne les mesure en 0.1 ; `measured_by`
  reste vide pour elles (EX-10.10), les TM- sont à créer à la révision
  suivante.
- **Toute valeur mesurée de l'enregistreur, du service d'approbation, du
  composant d'ancrage, des installations et des runbooks sur le système de
  référence** : les 28 entrées TM- « à écrire » ont une cible et un seuil,
  aucune valeur ; le rapport vide de la version 0.1 le dit ligne par ligne
  (EX-11.13) ; les mesures de l'étape 5 sur le composant d'ancrage (11.3) sont
  faites hors du système de référence et ne comptent pour aucune cible.
- **Le prestataire qualifié réel** (TI-16, TM-14) : aucune autorité
  d'horodatage qualifiée n'est contractée ; les autorités publiques éprouvées
  ne sont pas déclarées `qualified`, et la clôture qualifiée est mesurée sur
  le serveur interne déclaré qualifié par un instantané d'exemple ;
  compléments à l'étape 8 (section 14, ligne 10).
- **Le système de référence comme instance** : la classe est fixée
  (EX-11.1), la machine sera nommée par la première campagne de la porte 2.
- **Le seuil de régression comme valeur confirmée** : les coefficients 1,2
  et 0,9 d'EX-11.15 sont un choix de conception, à confirmer à la première
  campagne.
- **Le sens exact du critère « fenêtre de réécriture mesurée au plus égale à
  5 min »** : TM-42 le lit comme `W_date` (p99) ≤ 300 s avec la
  configuration de la porte 2 (`c_T` = 60 s, points chez le principal, cas
  `cadence-une-minute-principal` de CT-5 §12.3), parce que la configuration
  par défaut de CT-5 (`c_T` = 300 s) borne `W_date` à `300 s + d_jeton` et ne
  peut pas tenir 300 s ; la configuration par défaut est mesurée et publiée
  à côté (`w_date_defaut`), et `W_ordre` (TM-41) l'est aussi. Ce choix est à
  confirmer par le plan.
- **Les épreuves elles-mêmes** : aucune des quinze épreuves TR- n'a été
  conduite pour cette version ; les deux relectures de CT-4 §7.12 (CT-4
  l. 119-122) n'ont pas de consignation publiée (R10-NV4) et ne comptent pas.
- **Une méthode normée de mesure par paire** : EX-11.8 compose des pratiques
  publiées (R11-F29 à R11-F35) ; aucune source primaire dédiée à la latence
  ajoutée par un mandataire n'a été lue (R11-NV5).
- **La conduite des épreuves de CT-5 et de CT-9** : leurs grilles et
  consignes sont publiées par le générateur de `ct-9` (EX-12.7, annexe A.9 ;
  éléments tirés de CT-5 §3.2, §3.3, §4.1, §11.2, §12.3 et de CT-6 §7.9,
  cités dans TR-4 et TR-5) ; aucune n'a été conduite.
- **Le relevé de `chronyc -c tracking`** (TM-40) : chrony est absent de
  l'environnement de rédaction ; aucun relevé.
- **La capture d'un bloc plein qui mêle des clôtures** (réserve de CT-8
  §9.2) : TM-44, à écrire (étape 8) ; `b_cap` repose sur TM-31, mesuré sur un
  bloc de 64 ancres seules.

## 17. Alignement avec le dépôt et propositions

### 17.1 Alignement

« fait » : livré par le lot CT-9 ; « à faire » : attendu d'un lot nommé.
Les fichiers racine (`README.md`, `README.fr.md`, `ARCHITECTURE.md`,
`CHANGELOG.md`, `NOTICE`) sont alignés hors de ce texte, dans la même
livraison (problèmes de la sortie structurée).

| Élément | Avant | Après | État |
|---|---|---|---|
| `spec/CT-9-plan-de-tests.md` | absent (« à écrire ») | version 0.1 | fait (ce lot) |
| `spec/schemas/plan-de-tests-v0.schema.json` | — | schéma de 4.2, mode strict, exemples validés | fait (ce lot) |
| `spec/vecteurs/ct-9/` | — | `catalogue.json`, `couverture.json`, `index-ta-par-menace.json`, `cas/`, `mesures/`, `consignations/`, consignes, grilles et extraits des épreuves, `INDEX.md`, `verificateur-independant/`, `confrontation/` (annexe A.1) | fait (ce lot), hors `verificateur-independant/` et `confrontation/` écrits par leurs lots |
| `scripts/vecteurs/generer-ct9.mjs`, `scripts/vecteurs/ct9/` | — | générateur et source de données du catalogue ; `npm run vecteurs:ct9` ; lit `spec/*.md`, `menaces.json`, `test/*.test.js`, `ci.yml` sans les écrire | fait (ce lot) |
| `scripts/tests/couverture.mjs` | — | outil de 5.4 ; `npm run tests:couverture` ; réutilise `definitions()` de `scripts/conformite/verifier-renvois.mjs` sans le modifier | fait (ce lot) |
| `test/plan-de-tests.test.js`, `test/adversarial.test.js` | — | tests de l'annexe A ; aucun fichier existant renommé ni modifié | fait (ce lot) |
| `.github/workflows/ci.yml` | quatre jobs | job des vecteurs : régénération de `ct-9` deux fois et diff nul, outil de couverture code 0, `npm run mesures:ct9`, vérificateur Go `ct-9` ; job de confrontation : recomptage Python et comparaison à `sorties/recompte.txt` (EX-A.10) | fait (ce lot) |
| `package.json` | — | scripts `vecteurs:ct9`, `tests:couverture`, `mesures:ct9` ; `fast-check` : non ajouté (TU-12 à écrire) | fait (ce lot) |
| `test/adversarial.test.js` | — | 58 `it`, 62 mutants (annexe A.6) ; exécuté le 2026-11-01 (10.8) | fait (ce lot) |
| `spec/vecteurs/ct-9/index-ta-par-menace.json` | — | index MN- vers TA- et scénarios (EX-A.13) | fait (ce lot) |
| `spec/README.md` | ligne CT-9 « à écrire » ; ordre d'écriture | ligne CT-9 « version 0.1, en revue pour la porte 1 » (ordre d'écriture inchangé) ; ligne du schéma `plan-de-tests-v0` ; section « CT-9 (`vecteurs/ct-9/`) » ; toute retouche de ce fichier préserve les comptes « CT-7 » (RV-7, `test/securite.test.js`) et « CT-8 » (`renvois.mjs`, `test/deploiement.test.js`) et le compte des « CT-9 » de 0.2 | fait (ce lot) |
| CT-5 §14, ligne CT-9 | état « proposition » | répondue par CT-9 0.1 | à aligner par l'éditeur de CT-5 (texte de CT-5 inchangé dans ce lot) |
| CT-7 §11, CT-8 §16 | « CT-9 à écrire » implicite dans les lignes PA-/PD- | sans changement de texte : CT-9 répond par la table TC- | aucun changement |

### 17.2 Propositions

Propositions de CT-9 à d'autres spécifications, sans les modifier ; chaque
point, tant qu'il n'est pas adopté, reste un écart consigné dans l'oracle
du test concerné.

| Id | Destinataire | Proposition | État |
|---|---|---|---|
| PD-1 | CT-1 §12.2 | Fixer la version du projet IETF (draft-sharif-agent-audit-trail-09 du 26 octobre 2026, individuel, non adopté par l'IETF, R11-F46) ; noter que le projet admet Ed25519 comme algorithme optionnel, ES256 par défaut, et que son premier `prev_hash` est `null` (R11-F47) : la ligne « Algorithme à confirmer dans le projet » peut être close | proposition |
| PD-2 | CT-1 §12.3 | Remplacer « les profils de reçus SCITT pour RFC 6962 sont encore en cours de définition » par le renvoi à RFC 9942 (COSE Receipts, profil `RFC9162_SHA256`, juin 2026, R11-F44) et à RFC 9943 (architecture, R11-F43) ; le report en v1 reste motivé par l'absence de dépendance CBOR/COSE du vérificateur v0 | proposition |
| PD-3 | CT-2 §16.2, pas 7 | Le seuil de régression est celui d'EX-11.15 : après le premier rapport publié sur le système de référence, une mesure dont `p50` ou `p99` dépasse 1,2 fois la référence, dont le débit descend sous 0,9 fois la référence, ou dont une ligne `met` vrai devient `met` faux est une régression ; le harnais de CT-2 EX-16.2 (phase 2, `npm run mesures:ct2`) rendra le code 0 que les cibles soient atteintes ou non (pas 7), et `scripts/tests/mesures.mjs --reference --campagne` rend 1 sur une régression | proposition |
| PD-4 | CT-2 EX-6.25 | Épingler, pour l'export OTel GenAI de CT-1 §12.1 (TI-1), une version du registre `gen_ai` : le dépôt `semantic-conventions-genai` n'a publié aucune version au 2026-11-01 (R11-F40) et `gen_ai.system` n'y figure plus (R11-F41) | proposition |
| PD-5 | CT-5 annexe A.5, `README.md` du module `ct-5` | Lever la réserve d'indépendance par la relecture à l'aveugle de TQ-5, ou retirer la mention « indépendant » pour la partie concernée (R10-F35) | proposition |
| PD-6 | CT-4 §7.12 | Écrire l'épreuve d'acceptation comme TR- de CT-9 (participant, matériel, sections interdites : « sans lire le code de `scripts/` », verdict EX-7.15) et son exécution automatique comme TE-4 ; les deux relectures déjà réussies n'ont pas de compte rendu dans le dépôt (R10-NV4) | proposition |
| PD-7 | `package.json` | Ajouter `fast-check` à version exacte en dépendance de développement quand TU-12 est écrit (étape 1), avec sa graine et `numRuns` dans le test | proposition |
| PD-8 | CT-8 §10.11 | Après chaque incident, nommer l'entrée du catalogue (identifiant TA-/TE-) qui couvre la correction, conformément à la phrase « le test de CT-9 qui la couvre » : la forme est « CT-9 TE-8 », vérifiable par l'outil de couverture | proposition |
| PD-9 | CT-7 annexe A.4, `scripts/vecteurs/generer-ct7.mjs` | Trois cas de cérémonie : `invalide-cr6-tsa-interne-classe-d` (MN-42), `invalide-cr7-validateur-sauvegarde` (MN-39, le cas existant porte une clé d'enregistreur, R10-NV3), `valide-production-sans-ancre` avec réserve (MN-93) | proposition |
| PD-10 | CT-5 annexe A, `scripts/vecteurs/generer-ct5.mjs` | Trace de planification `empreinte-squattee.json` (entrée `echec_registre`, code `empreinte_squattee`) pour MN-58 | proposition |
| PD-11 | CT-7 §3.4, ligne MN-98 | La cellule « Test de CT-9 » cite `valide-seq-7-complet-attestation` ; ce dossier porte une inscription (événement seq 12) et son énoncé ne dit pas « non inscrite au journal » ; le dossier sans inscription est `valide-seq-7-attestation-sans-inscription` (`ct-1`) ; corriger à la prochaine révision de CT-7, sans effet sur `menaces.json` d'ici là | proposition |
| PD-12 | CT-2, implémentation de référence (`scripts/lib/capture.mjs`, `scripts/lib/approbation.mjs`) | Coder CT-2 EX-7.2 (lecture bornée de `_meta["noortrace/delegation"]`) et CT-2 EX-11.8 (refus de la classe D en production) dans les bibliothèques, pour que TA-2 et TA-30 passent ; au 2026-11-01 ces deux réponses n'existaient que dans le texte | proposition ; depuis l'étape 4, le démon `paquets/enregistreur` les code et TA-2, TA-30 se jouent sur lui (révision 0.2) ; la bibliothèque de référence ne les code toujours pas |
| PD-13 | CT-7 §5.8, `scripts/lib/securite.mjs`, `scripts/verify/ceremonie.mjs` | Ajouter au rapport de `verifierCeremonie` la réserve d'EX-5.11 (procès-verbal de production sans ancre de `D_C` : « daté par déclaration seulement »), sans changer le verdict, pour que TA-93 passe | proposition |
| PD-14 | CT-9 section 0, règle de couverture (d) | Admettre qu'un état « exécutable » cite, en plus d'un `it` de `test/*.test.js`, une étape nommée de `.github/workflows/ci.yml` quand l'exécution n'est possible qu'en intégration continue (TA-66 : `go run . ..` de chaque module Go) | retirée de la liste des propositions : décision de CT-9 lui-même (EX-3.10 admet `ci_steps`), non une proposition à une autre spécification ; le numéro n'est pas réattribué |
| PD-15 | CT-7 §3.4, ligne MN-5 ; CT-2 §7.5 | Séparer dans le texte du test la part du service (consommation unique, TK-) et la part de l'enregistreur (RL-2, RL-3) ; CT-9 éprouve la première par mutant et nomme la seconde à écrire | proposition |
| PD-16 | CT-2 §16.2 (pas 7), §16.3 | Adopter le rapport de mesure de CT-9 (`$defs/rapport_mesure`) comme forme du rapport de `npm run mesures:ct2`, ou en faire une projection ; garder le code 0 du harnais ; le seuil de régression est PD-3 | proposition |
| PD-17 | CT-5 §1 (ligne CT-9), §14 (ligne CT-9) | En §14, remplacer l'état « proposition » par le renvoi aux entrées TR-4 et TR-5 ; en §1, ajouter le renvoi aux consignes et grilles de `spec/vecteurs/ct-9/acceptation-ancrage/` et `acceptation-verdict-point/` ; CT-5 ne publie ni consigne ni grille (R10-F8) | proposition |
| PD-18 | CT-5 §3.3, §4.4 | Écrire la configuration de la porte 2 (`c_T` = 60 s, points chez le principal) comme profil nommé de `ancrage-v0`, pour que TM-42 cite un profil et non une liste de réglages | proposition |
| PD-19 | CT-4 §7.12 | Consigner les épreuves selon `consignation_rejeu` (TR-3) : les deux relectures passées (CT-4 l. 119-122) n'ont laissé aucune consignation publiable | proposition |
| PD-20 | CT-8 §8.1, §15 | Renvoyer à CT-9 §11.1 pour le système de référence (« que CT-9 fixe ») ; après la première campagne, inscrire l'instance nommée | proposition |
| PD-21 | CT-8 §6.2 (IP-5), annexe B | Remplacer « à relever sur chrony 4.6, CT-9 » par le relevé de TM-40 quand il existe | proposition |
| PD-22 | CT-8 §14 (EX-14.10) | Renvoyer à `consignation_rejeu` de CT-9 §12.1, qui en est la forme lisible par machine | proposition |
| PD-23 | `package.json`, `.github/workflows/ci.yml` | Scripts `mesures:ct9` (validation des rapports de `spec/vecteurs/ct-9/mesures/` et des consignations contre le schéma) et, en phase 2, comparaison au rapport de référence (EX-11.15) | à faire (ce lot pour la validation ; phase 2 pour la comparaison) |
| PD-24 | CT-7 §3.4, ligne MN-62 (`menaces.json`, membre `test`) | Écrire « si la consignation `anchor_fallback` de la relève est retirée » ou doter la menace d'une trace ad hoc : sur la trace figée `principal-injoignable.json`, le retrait de la relève elle-même épuise les gigues injectées et lève avant l'oracle (EX-10.6) ; le mutant exécutable de TA-62 retire la consignation (détection), le retrait de la relève est son complément | proposition |
| PD-25 | CT-2 §19.1 (EX-19.1), §19.4 | Fixer les deux instants de la « durée totale » imprimée par `verificateur` (origine : démarrage du processus `verificateur` ou de la composition ; fin : impression du résultat) et l'horloge employée, pour que TM-43 relève une grandeur définie ; CT-9 lit en attendant « origine au démarrage du processus `verificateur`, horloge monotone » ; fixer aussi la précision de l'impression (millisecondes, ou trois décimales de seconde) : la comparaison de TM-43 porte sur la valeur imprimée (EX-11.14, `strictement_inferieur`) et une impression en secondes entières, comme « Durée totale : 41 s » de §19.4, ferait d'une exécution de 119,6 s imprimée « 120 s » un échec | proposition |
| PD-26 | CT-2 EX-17.2, EX-12.40 | Nommer la ligne du journal d'exploitation et la raison d'un client ICAP refusé (`icap_client_refused`, raison `source_non_admise` ou `certificat_client`) et le statut ICAP rendu (TI-19) ; fixer la sortie et le code de retour de `noortrace-ctl worm gel etat` (TA-75) ; fixer le statut encapsulé du blocage d'une adresse d'hôte inconnue en REQMOD (`401` et corps `hote_inconnu` d'EX-5.30, comme en passerelle) et la ligne du journal d'exploitation, et ajouter ce troisième cas à l'énumération des blocages en REQMOD d'EX-5.4 (TI-19) ; fixer la forme du `match` de l'entrée `model.hosts` d'`id` `"inconnu"` d'EX-5.8, qu'aucun texte ni schéma ne fixe (TI-19) | proposition |
| PD-27 | CT-8 §10.2 | Aligner le compte des métriques `noortrace_*` (« 43 ») sur la table de CT-2 §17.2 telle qu'elle est au commit éprouvé, ou le remplacer par un renvoi sans nombre (TE-17) | proposition |
| PD-28 | CT-8 §10.7 | Ajouter la règle d'alerte critique de la jauge `noortrace_releve_externe_ok{check}` (CT-8 EX-10.9 la prescrit, les tables de §10.4 à §10.7, qui font foi, ne la portent pas ; TA-75) | proposition |
| PD-29 | CT-7 §3.4, ligne MN-26 (`menaces.json`, membre `test`) | Faire porter le test sur la preuve de vie (série des points sans trou après redémarrage) en plus de la ligne `startup` : la réponse première de MN-26 est « points de contrôle à chaque instant aligné », qu'un démon qui écrit `startup` sans émettre de point passerait (TA-26) | proposition |
| PD-30 | CT-2 EX-14.11, CT-2 EX-17.1 | CT-2 EX-14.11 dit que `GET /healthz` rend `degraded` avec les raisons dans tout mode dégradé ; CT-2 EX-17.1 rend `503` et `{"status":"down",…}` quand aucun appel ne peut être servi (bail non détenu, clé indisponible) : préciser que `down`/`503` vaut pour les modes `cle` et `bail` et `degraded`/`200` pour les autres ; l'oracle de TA-33 ne lit pas `/healthz`, un test qui admet les deux états est conforme | proposition |

## Annexe A — Vecteurs, implémentation, intégration continue

### A.1 Principes et disposition

Les vecteurs de CT-9 sont le catalogue et ce qui s'en déduit ; aucun n'est
une valeur cryptographique nouvelle. Ils sont publiés sous
`spec/vecteurs/ct-9/`, produits par `scripts/vecteurs/generer-ct9.mjs`
(`npm run vecteurs:ct9`) depuis la source de données du générateur et les
fichiers qu'il lit sans les écrire (`spec/*.md`, `menaces.json`,
`test/*.test.js`, `ci.yml`).

```text
spec/vecteurs/ct-9/
  INDEX.md                        une section par fichier, une ligne par entrée et par cas
  catalogue.json                  A.2 : le catalogue (schéma plan-de-tests-v0, racine)
  couverture.json                 A.3 : sortie de l'outil de couverture sur le dépôt (rapport_couverture)
  index-ta-par-menace.json        A.6 : index des TA- par menace MN-1 à MN-98 (section 10)
  cas/                            A.3 : exemples valides et invalides de catalogue, chacun réduit
                                  à une entrée, avec attendu.json
  mesures/                        A.7 : rapports de mesure (vide, vecteurs) et cas (section 11)
  consignations/                  A.8 : gabarit de consignation d'épreuve et cas (section 12)
  acceptation-ancrage/            A.9 : consignes et grilles des épreuves sans grille ailleurs
  acceptation-verdict-point/      (TR-4, TR-5), des épreuves de CT-9 (TR-13 à TR-15) et extraits
  acceptation-plan/               des spécifications remis aux participants (SHA256SUMS)
  acceptation-porte-2/
  extraits/
  executions/                     A.12 : rapports d'exécution de la porte 2 (rapport_execution),
                                  écrits par l'examinateur ; jamais écrit par le générateur ;
                                  absent en version 0.1
  confrontation/                  recomptage indépendant en Python (programme et sorties publiées) ;
                                  jamais écrit par le générateur
  verificateur-independant/       module Go écrit depuis le seul texte de CT-9 ; jamais écrit par le
                                  générateur
```

**EX-A.1** Deux générations successives donnent les mêmes octets, sans
fichier de plus ; le générateur n'efface que ses propres entrées, refuse une
racine qui porte une entrée étrangère (hors `confrontation/`,
`verificateur-independant/` et `executions/`, qu'il ne touche jamais), et
n'écrit ni ne modifie aucun
fichier de `spec/vecteurs/ct-1` à `ct-8` ni leurs générateurs. Les fichiers
JSON sont indentés de deux espaces et finis par un saut de ligne ; les
descriptions sont en français accentué.

**EX-A.2** `INDEX.md` dit qu'il est produit par le générateur et ne doit pas
être édité ; il liste chaque entrée du catalogue (identifiant, niveau, état,
titre) et chaque cas de `cas/` avec son attendu.

### A.2 Catalogue, schéma et cas

**EX-A.3** `catalogue.json` valide contre la racine de
`plan-de-tests-v0.schema.json` (4.2) ; `couverture.json` contre
`#/$defs/rapport_couverture` ; chaque fichier de `cas/` contre la
définition que son `attendu.json` nomme, avec le verdict attendu (`valide`
ou `invalide` et le mot-clé fautif). Les cas de la version 0.1, chacun un
catalogue réduit à une entrée : `valide-minimal` (TV-2) ; `valide-ta`
(TA-3, bloc `adversarial` complet) ; `invalide-executable-sans-titre` (état
`executable` sans `tests` ni `ci_steps`) ; `invalide-a-ecrire-sans-etape`
(état `a_ecrire` sans `phase2_step`) ; `invalide-ta-sans-adversarial`
(niveau TA sans bloc `adversarial`) ;
`invalide-identifiant-sans-specification` (`covers` avec `E-2` nu) ;
`invalide-tm-mesure-inventee` (TM- dont `measured` n'est pas `null`) ;
`invalide-ta-titre-vide` (titre d'`it` vide) ;
`invalide-ta-complement-sans-etape` (`complement` sans `phase2_step`) ;
`invalide-ta-prefixe-test` (`threat_test_text` sans le préfixe fixe) ;
`invalide-ta-scenario-sans-composition` (menace nulle sans `composition`).
Les onze ont été validés le 2026-11-01 par ajv (4.2) : deux `valid`, neuf
`invalid`, chacun pour le mot-clé que son nom annonce.

**EX-A.4** Les tables du texte (0.2, 3.1, 3.4, 5.3, 5.5, 6 à 13) sont
imprimées depuis `catalogue.json`, chacune sous un marqueur
`<!-- table X -->` ; la règle d'impression d'une ligne est fixe par table :
pour TU-, TV-, TI-, TE-, TQ-, identifiant, titre, identifiants couverts
résumés par famille (« CT-6 T- (11) »), menaces, état (« exécutable :
`test/journal.test.js` », « exécutable : … ; complément à écrire (étape
4) » ou « à écrire (étape 4) ») ; pour TA-, menace, composant, état, lieu de
la réponse retirée, fichiers des tests ; pour TM-, grandeur, cible,
comparaison, source, seuil d'échec, méthode, état, mesure (vide) ; pour TR-,
participant, matériel, sections interdites, grille, verdict, état ; pour
NC-, catégorie, identifiants, justification ; pour TC-, clé et ligne,
délégué, réponse ; plus les scénarios, les risques acceptés, les niveaux,
les étapes et les comptes par niveau. Le générateur imprime ces blocs dans
un fichier intermédiaire (`--tables <fichier>`, hors de
`spec/vecteurs/ct-9/`) que celui qui a édité la source de données colle à
la place des blocs du texte (EX-4.6 ; celui de cette version a été produit
ainsi), et l'outil de couverture compare le texte publié au catalogue,
cellule par cellule (EX-4.4).

### A.3 Outil de couverture

**EX-A.5** `scripts/tests/couverture.mjs` est le programme de 5.4. Il
importe `definitions()` de `scripts/conformite/verifier-renvois.mjs` sans le
modifier (R10-F37, R10-F38) ; il lit les occurrences de « CT-9 » par le
procédé de 0.2 ; il résout chaque identifiant de `covers` et des NC- dans
l'inventaire de la spécification nommée (5.2) ; il applique les règles (a) à
(d) de 5.1, EX-4.4, EX-3.10, EX-10.3 et EX-10.10 ; il écrit le rapport de
5.4. Options : `--json`, `--sortie <fichier>`, `--texte <chemin de CT-9>`,
`--racine <dépôt>`, `--catalogue <fichier>` (copie du catalogue à l'essai ;
l'index TA- par menace est cherché à côté de cette copie, EX-A.13) et
`--strict`, qui fait des avertissements des erreurs : section « CT-n §s »
citée inconnue, menace citée hors TA- inconnue, index TA- par menace
absent. Il imprime aussi les entrées dont une partie dépend d'une
proposition non adoptée (`status.depends_on`, section 14). Codes 0, 1, 2.
La CI l'exécute sans puis avec `--strict` (étape « outil de couverture de
CT-9 (code 0 exigé) ») et exige 0 des deux ; `test/plan-de-tests.test.js`
exige aussi 0 avec et sans `--strict`.

**EX-A.6** `couverture.json` est la sortie de l'outil sur le dépôt au commit
éprouvé, écrite par le générateur (qui appelle l'outil) ; la CI la
régénère et exige un `git diff` vide. Son membre `inputs` porte les
SHA-256 des huit spécifications, du catalogue, de `menaces.json` et des
fichiers de tests (`test/plan-de-tests.test.js` compris, qui exige lui-même
l'égalité avec ce rapport : une seule régénération suffit, le test ne
contenant pas le condensé du rapport) : tout changement de ces fichiers
oblige à régénérer, et la régénération de `ct-9` est le dernier acte d'une
livraison (EX-4.6).

### A.4 Tests

**EX-A.7** `test/plan-de-tests.test.js` (nouveau ; aucun fichier existant
de `test/` n'est renommé ni modifié) exige : que `catalogue.json` et
`couverture.json` valident contre leurs schémas et que chaque cas de `cas/`
rende son attendu ; que l'outil de couverture rende 0 sur le dépôt et un
rapport égal, octet pour octet, à `couverture.json` aux membres `date` et
`tool.command` près ; que chaque table du texte de CT-9 égale le catalogue
(EX-4.4) ; que deux générations de `spec/vecteurs/ct-9` dans des
répertoires vides donnent les mêmes octets que le dépôt (hors
`confrontation/` et `verificateur-independant/`) ; que chaque entrée
`executable` cite des titres et des étapes qui existent (règle d) ; que le
compte d'occurrences de « CT-9 » égale le nombre de lignes TC- ; que les
chiffres imprimés en 5.5 sont ceux de `couverture.json`.

**EX-A.8** `test/adversarial.test.js` (nouveau) porte les TA- exécutables
d'`execution` `vecteurs_et_depot` (section 10) et, depuis la révision 0.2,
ceux d'`execution` `phase_2` qui se jouent sur le démon de l'étape 4
(mutants du paquet, EX-10.5) ; sa forme est fixée par 10.3 et A.6.

**EX-A.9** `test/plan-de-tests.test.js` porte aussi, pour les niveaux TM-
et TR- : la validation des onze cas de `mesures/cas/` et des six cas de
`consignations/cas/` contre les définitions `rapport_mesure` et
`consignation_rejeu` (schéma enveloppe, attendu `valid`/`invalid`) ; la
validation de chaque rapport de `mesures/` et de chaque consignation de
`consignations/` ; l'égalité des valeurs du rapport sur les vecteurs avec
un recalcul en mémoire (tailles de ligne du segment, 2 465 octets) ; pour
chaque entrée TM-, `measure.measured` null, `result_name` unique, cible
présente sauf `aucune_cible`, source définie dans sa spécification ; pour
chaque entrée TR-, `grid` égal à un fichier existant ou `null`, et aucune
consigne remise ne contient un élément de sa grille (comparaison des
chaînes des éléments à la consigne) ; l'égalité des tables 11.5, 12.2 et de
la table TC- du texte avec le catalogue ; et la régénération déterministe de
la famille. Commandes :

```bash
npx hardhat --config hardhat.config.mjs test test/plan-de-tests.test.js
echo '{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"https://noortrace.example/schemas/v0/plan-de-tests.schema.json#/$defs/rapport_mesure"}' > rapport-mesure.schema.json
npx --yes ajv-cli@5 validate --spec=draft2020 --strict=true \
  -s rapport-mesure.schema.json -r spec/schemas/plan-de-tests-v0.schema.json \
  -d spec/vecteurs/ct-9/mesures/rapport-2026-11-01-vecteurs.json
```

Exécuté le 2026-11-01 sur le schéma fusionné de cette version : les deux
rapports et le gabarit `valid`, les quatorze cas invalides `invalid`, chacun
pour la raison que son nom annonce.

Depuis la révision 0.4, le même fichier relit le rapport de la campagne de
l'étape 5 (`mesures/rapport-2026-11-10-ancrage.json`, 11.3) : forme
`rapport_mesure`, acceptation par `scripts/tests/mesures.mjs`, ligne du
`result_name` de chacune des entrées TM- qui le citent, à l'unité du
catalogue, avec sa valeur et son effectif, lignes supplémentaires nommées
par la table de 11.3, `met` nul hors du système de référence ; tant que le
rapport n'est pas publié, ce cas échoue en le nommant.

### A.5 Intégration continue

**EX-A.10** `ci.yml` reçoit, dans le job des vecteurs : `npm run
vecteurs:ct9` deux fois, `git diff --exit-code -- spec/vecteurs/ct-9` et
aucun fichier non suivi ; `node scripts/tests/couverture.mjs` (code 0
exigé) ; `npm run mesures:ct9` (rapports de mesure et consignations publiés
validés contre le schéma ; en phase 2, comparaison de chaque rapport de
campagne au rapport de référence, EX-11.15, échec sur une régression) ; le
vérificateur Go de `ct-9` (`gofmt -l`, `go vet ./...`, `go test ./...`,
`go run . ..`, zéro discordance) ; dans le job de confrontation : le
recomptage Python de A.11 et la comparaison de ses sorties aux sorties
publiées. Le job `tests` exécute `test/plan-de-tests.test.js` et
`test/adversarial.test.js` par `npm test` ; sans `go`, TA-97 y est en
attente, et il ne l'est pas dans le job des vecteurs, où Go est installé.
Depuis la révision 0.2, le job `sdk-python` exécute les essais Python du
SDK et des adaptateurs (`test/enregistreur-sdk-python.test.js`,
`test/enregistreur-sdk-adaptateurs.test.js`) avec `uv` épinglé, Python
3.10, 3.12 et 3.13, go1.27.3 et le binaire vérificateur, et refuse tout
essai en attente. Depuis la révision 0.4, le job `ancrage` exécute les essais
du composant d'ancrage et de son branchement dans l'enregistreur (étape 5 :
`test/ancrage-*.test.js`, `test/enregistreur-ancrage-*.test.js`,
`test/enregistreur-journal-soi.test.js`) avec le binaire vérificateur Go
(go1.27.3) et python-opentimestamps 0.4.5 ; ses seules attentes admises sont
celles du réseau de développement et du réseau public.

### A.6 Tests adversariaux : `test/adversarial.test.js`

**EX-A.11** `test/adversarial.test.js` est lancé par `npm test` (Hardhat) et
par l'intégration continue. Il contient, au 2026-11-03, 71 `it` répartis en
dix `describe` par composant (clés et cérémonie ; attestation de périmètre
; vérificateur hors ligne ; service d'approbation et noyau ; console et
annuaire ; enregistreur ; ingestion OpenTelemetry et copies WORM ;
planificateur d'ancrage ; registre ; démon de l'étape 4, describe de
premier niveau dont les treize `it` lancent le démon réel ou importent ses
modules, et leurs mutants du paquet). Chaque `it` suit EX-10.7, formes
admises comprises (qualificatif, oracle sur le vecteur, `it` partagé) ; la
fabrique de mutants suit EX-10.5 et EX-10.6. Le fichier
n'écrit rien dans le dépôt ; il écrit sous `NOORTRACE_TMP` (défaut : répertoire
temporaire du système) et détruit ses répertoires dans un `after`.

**EX-A.12** Les chaînes retirées par chaque mutant sont celles du catalogue
(`response_removed.how`, et le texte exact dans le fichier de test) ; quand un
fichier du dépôt change au point qu'une chaîne n'apparaît plus exactement une
fois, le test échoue avec le nom du mutant et le compte trouvé : c'est voulu,
le mutant doit être reposé avec la nouvelle réponse.

**EX-A.13** `spec/vecteurs/ct-9/index-ta-par-menace.json` donne, pour chaque
MN-, son TA-, son état et les scénarios qui le composent ; il est produit par
le générateur et lu par l'outil de couverture (règle (b)). Les cas invalides de
la famille `cas/` (A.2) comprennent, pour la partie TA- : un titre de `it`
vide, un complément sans étape, un `threat_test_text` sans le préfixe fixe
et un scénario sans `composition` ; chacun est refusé par le schéma.

### A.7 Famille `mesures/`

**EX-A.14** `spec/vecteurs/ct-9/mesures/` contient, écrits par le
générateur : `rapport-2026-11-01-vide.json` (le rapport vide de la version
0.1, EX-11.13) et `rapport-2026-11-01-vecteurs.json` (les relevés sur les
vecteurs : tailles de ligne du segment de la démonstration recalculées à la
génération depuis `spec/vecteurs/ct-2/evenements/journal-demo/segment.ndjson`,
2 465 octets de la ligne de l'annexe A, constat de cadence) ; et
`cas/cas.json` avec onze cas (`valide-vide`, `valide-vecteurs`,
`invalide-met-sans-valeur`, `invalide-compte-hors-reference`,
`invalide-fsync-desactive-compte`, `invalide-disque-memoire-compte`,
`invalide-met-sans-compter`, `invalide-unite-inconnue`,
`invalide-percentile-autre-methode`, `invalide-machine-incomplete`,
`invalide-test-id-autre-famille`), chacun avec son attendu `valid` ou
`invalid` pour ajv. Les rapports des campagnes de la porte 2 sont écrits
par l'ingénieur de la campagne à côté, jamais par le générateur, et
validés par le même test.

### A.8 Famille `consignations/`

**EX-A.15** `spec/vecteurs/ct-9/consignations/` contient le gabarit
`gabarit-TR-10.json` (SHA-256 à zéro, `duration_s` null, verdict d'exemple)
et `cas/cas.json` avec six cas (`valide-gabarit`,
`invalide-reussi-element-absent`, `invalide-reussi-disqualifiant`,
`invalide-juge-non-independant`, `invalide-nom-de-personne`,
`invalide-sans-materiel`). Les consignations réelles y sont ajoutées par
l'examinateur (EX-12.4).

### A.9 Consignes, grilles et extraits des épreuves

**EX-A.16** Le générateur écrit `spec/vecteurs/ct-9/acceptation-ancrage/
consigne.md` et `acceptation-ancrage-attendu.json` (TR-4),
`acceptation-verdict-point/consigne.md` et
`acceptation-verdict-point-attendu.json` (TR-5, avec le chemin du rapport
de vérification d'un dossier `ct-6` avec la partie),
`acceptation-plan/consigne.md` (TR-13, TR-15), `acceptation-porte-2/
consigne.md` et `acceptation-porte-2-attendu.json` (TR-14, produite depuis
la section 14 et la table des niveaux), et les extraits `extraits/
CT-7-sans-9-A15.md`, `extraits/CT-8-sans-14-A.md`, `extraits/CT-8-13.md`,
`extraits/CT-8-12.md`, `extraits/CT-7-7.md`, `extraits/CT-9-sans-15.md` avec
un fichier `SHA256SUMS`. Chaque grille de `ct-9` suit
`$defs/grille_acceptation` de `plan-de-tests-v0` (EX-4.3, EX-12.7 : `kind`
`grille-acceptation`, `test_id`, questions à éléments fondés chacun par une
règle, affirmations disqualifiantes d'EX-12.6), forme reprise de
`$defs/attendu_acceptation_console` de `console-approbation-v0` (CT-3) sans
ses rôles ; `test/plan-de-tests.test.js` (it « chaque TR- : grid égal à un
fichier existant ou null, a_ecrire à l'étape 8 ; les grilles de ct-9
valident contre grille_acceptation et portent le test_id de leur entrée »)
les valide. Les éléments des grilles de TR-4 et TR-5 sont ceux cités dans
les étapes de ces entrées (catalogue).

### A.10 Vérificateur Go indépendant

**EX-A.17** `spec/vecteurs/ct-9/verificateur-independant/` est un module Go
séparé (`noortrace-ct9`, Go 1.24, bibliothèque standard seule), écrit
depuis le seul texte de CT-9 et les schémas, sans lire le code JavaScript.
Il relit les huit spécifications et `spec/README.md` (identifiants par les
règles de 5.2, occurrences de « CT-9 » par le procédé de 0.2), `menaces.json`,
`catalogue.json`, `test/*.test.js` et `ci.yml` ; il recompte la couverture
(identifiants, menaces, renvois), vérifie l'unicité et la forme des
identifiants du catalogue (EX-3.1), l'existence des titres cités (EX-4.2),
l'égalité des tables du texte avec le catalogue (EX-4.4), et compare son
rapport à `couverture.json` membre par membre ; pour les niveaux TA-, TM-
et TR-, il relit que chaque TA-n a sa menace MN-n et son texte de test, que
chaque TM- a `measured` nul, une source définie et un `result_name` unique,
que chaque ligne d'un rapport de mesure publié a son TM-, que chaque TR-
référence une grille existante ou `null`, et que les tables 10.4, 10.5,
10.6, 11.5 et 12.2 égalent le catalogue. Il rend « 0 discordance » et le
code 0, ou la liste des écarts et le code 1 ; son `README.md` dit ce qu'il
recalcule et ce qu'il ne recalcule pas.

### A.11 Confrontation tierce

**EX-A.18** `spec/vecteurs/ct-9/confrontation/recompter.py` (Python 3,
`python3 -I`, bibliothèque standard seule) recompte, par ses propres
expressions régulières écrites depuis le texte de 5.2, les identifiants de
`spec/*.md`, les menaces de `menaces.json` et les titres de `test/*.test.js`,
et compare ses comptes, au moins, à `couverture.json` (totaux par
spécification et par famille, menaces, titres, nombre d'`it` dont le titre
commence par « TA- » et identifiants TA- qu'ils citent, lignes TM- et TR- du
texte et du catalogue et identifiants de leurs `covers`) ; il recompte aussi
la règle (a) identifiant par identifiant, les occurrences de « CT-9 » et
leurs clés de section contre la table TC-, les scénarios, les risques
acceptés, l'index TA- par menace, les étapes `- name:` de `ci.yml` citées,
les colonnes État et Mesure des tables 11.5 et 12.2 et les chiffres de 5.5
(périmètre exact dans `confrontation/LISEZMOI.md`) ; sa sortie est publiée
sous `confrontation/sorties/recompte.txt` et `test/confrontation.test.js`
n'est pas modifié :
la comparaison est faite par `test/plan-de-tests.test.js` et par la CI.
Toute discordance est une erreur ; une discordance voulue (famille exclue,
faux positif) est déclarée dans `LISEZMOI.md` avec sa raison.

### A.12 Rapport d'exécution

**EX-A.19** Le rapport d'exécution (`$defs/rapport_execution` : `kind`
`rapport-execution`, `date`, `commit`, `environment`, `results[]` avec
`test_id`, `status`, `command`, `reason`, `output_sha256`) est la source des
verdicts `reussi` de la section 14. Il est écrit par l'examinateur de la
porte 2 (phase 2, étape 8), jamais par le générateur, sous
`spec/vecteurs/ct-9/executions/rapport-<AAAA-MM-JJ>-<etiquette>.json`, un
`result` par entrée du catalogue exécutée (`status` `reussi`, `echec`,
`en_attente` ou `non_applicable`, cette dernière avec la proposition non
adoptée en `reason`, EX-14.1), la commande citée ; toute entrée `executable`
y figure, aucun `test_id` n'y est inconnu du catalogue. En version 0.1 le
seul rapport publiable est celui des entrées exécutables, rédigé depuis le
journal d'une exécution réelle de `npm test` et des étapes de CI, avec leur
commande ; aucun n'est publié, les objets de la porte 2 n'existant pas. La
validation (schéma, `test_id` connus, entrées exécutables présentes) est
celle de `scripts/tests/mesures.mjs --execution <fichier>`, à livrer avec le
premier rapport (phase 2).

## Annexe B — Sources primaires datées

### B.1 Notes de recherche

Les faits externes de CT-9 viennent de deux notes internes du lot, R10
(dépôt public et délégations à CT-9, sources locales seulement, aucun
téléchargement) et R11 (pratiques de test, sources primaires téléchargées
avec leurs SHA-256), relues le 2026-11-01. Les sources font foi, pas les
notes. Les renvois « R11-F<n> » de CT-9 sont ceux de son propre digest,
distinct du digest R11 cité par CT-2.

### B.2 Renvois cités par les sections 0 à 9, 13, 14, 16, 17 et l'annexe A

| Renvoi | Objet | Source primaire ou fichier lu | Lecture |
|---|---|---|---|
| R10-F1, R10-F2 | 107 lignes « CT-9 » (`grep -n \| wc -l`) dans `spec/*.md` avant la réécriture de `spec/README.md`, soit 105 lignes dans CT-1 à CT-8 et 2 dans l'ancien README (109 occurrences avec les 2 de l'ancien README) ; phrase commune de la section 0 des spécifications | `spec/CT-1-*.md` à `spec/CT-8-*.md`, `spec/README.md` ; recompté sur la livraison : 107 occurrences sur 105 lignes dans CT-1 à CT-8 et 10 occurrences sur 5 lignes dans `spec/README.md` réécrit, soit 117 occurrences sur 110 lignes (0.2, `couverture.json` `traceability`) | 2026-11-01 |
| R10-F3 | Procédé de rattachement d'une occurrence à sa section | `scripts/deploiement/renvois.mjs` l. 38-51 | 2026-11-01 |
| R10-F26 | `menaces.json` : 98 menaces, préfixe fixe du membre `test`, 14 composants | `spec/vecteurs/ct-7/menaces.json` ; CT-7 §3.8 | 2026-11-01 |
| R10-F28 | Bijection RA- ↔ MN- par `accepted_risk` (RV-8) | CT-7 §3.5 l. 813-917 ; `menaces.json` | 2026-11-01 |
| R10-F30 | Exécution réelle de la suite avant ce lot : 844 cas, 838 réussis, 6 en attente, code 0 (résumé Hardhat « 844 passing (844 mocha) », qui compte les cas en attente) ; après ce lot : EX-3.11 | `npx hardhat --config hardhat.config.mjs test`, journal de R10 ; exécution du commit éprouvé | 2026-11-01 |
| R10-F35 | Modules Go `ct-1` à `ct-5`, `ct-7`, `ct-8` ; aucun pour `ct-6` ; réserve d'indépendance de `ct-5` | `spec/vecteurs/ct-*/verificateur-independant/README.md` ; CT-6 §14 l. 5080 | 2026-11-01 |
| R10-F37 à R10-F39 | `definitions()`, `renvoiExiste()`, `occurrences()` et leurs expressions ; comptes par spécification | `scripts/conformite/verifier-renvois.mjs` l. 28-61 ; `scripts/deploiement/renvois.mjs` l. 24-80 | 2026-11-01 |
| R10-F41 | Familles et homonymies par spécification | tables de la section 0 de CT-2 à CT-8 ; CT-1 §11.4 | 2026-11-01 |
| R10-F43 à R10-F45 | Étapes de la phase 2, cas de démonstration, porte 2 (plan privé, l. 243-270 ; nom du concurrent non recopié) | document interne, lecture seule | 2026-11-01 |
| R10-NV4 | Épreuve CT-4 §7.12 réussie deux fois, sans compte rendu dans le dépôt | CT-4 l. 119-122, EX-7.14 | 2026-11-01 |
| R10-NV7 | Cas en attente selon l'environnement (Playwright) | `.github/workflows/ci.yml`, jobs `tests` et `console-chromium` | 2026-11-01 |
| R11-F7 | Aucune dépendance `fast-check`, `sinon`, `@stryker-mutator/*` dans le dépôt | `package.json`, `node_modules/` | 2026-11-01 |
| R11-F16 à R11-F18 | `fast-check` 4.10.2 ; `seed` `Date.now()` par défaut, `numRuns` 100, `path`, `xorshift128plus` ; rapport `seed`/`path` et rejeu | registre npm ; `https://fast-check.dev/docs/api/interfaces/Parameters/` ; `…/tutorials/quick-start/read-test-reports/` | 2026-11-01 |
| R11-F23 à R11-F27 | États des mutants (tué, survivant), score, désactivation avec motif ; opérateurs de PIT | `https://stryker-mutator.io/docs/…` ; `https://pitest.org/…` | 2026-11-01 |
| R11-F40, R11-F41 | Dépôt `semantic-conventions-genai` sans version publiée ; `gen_ai.system` absent du registre courant | `dl-R11/otel/README.md`, `CHANGELOG.md`, `registry-gen-ai.md` (SHA-256 en annexe de R11) | 2026-11-01 |
| R11-F42 | OpenTelemetry Weaver v0.28.0 (2026-10-14), `registry live-check`, niveaux `violation`/`improvement`/`information`, code de sortie non nul sur `violation` | `https://github.com/open-telemetry/weaver/releases` ; `dl-R11/otel/weaver_live_check_README.md` | 2026-11-01 |
| R11-F43, R11-F44 | RFC 9943 (architecture SCITT) et RFC 9942 (COSE Receipts, `RFC9162_SHA256`), juin 2026 | `dl-R11/ietf/rfc9943.txt` ; `https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/` | 2026-11-01 |
| R11-F46, R11-F47 | draft-sharif-agent-audit-trail-09 (26 octobre 2026, individuel) : `prev_hash` `null` pour la genèse, ES256 par défaut, Ed25519 optionnel | `dl-R11/ietf/draft-sharif-agent-audit-trail-09.txt` | 2026-11-01 |
| R11-F51 | `libfaketime` contourné par les programmes Go | `dl-R11/libfaketime/README` l. 75-121 | 2026-11-01 |
| R11-NV2, R11-NV4 | Définitions normatives de « test oracle », « test level », « exit criteria » non lues (aperçus gratuits, SEVOCAB indisponible) | ISO/IEC/IEEE 29119-1:2022 et 29119-3:2021, aperçus iTeh ; `https://www.computer.org/sevocab` | 2026-11-01, non vérifié |

### B.3 Tests adversariaux (section 10) : faits de CT-9 R11 et lectures du dépôt

Les faits externes de la section 10 viennent de la note de recherche CT-9 R11
(pratiques de test), interne, lue le 2026-11-01 sur les sources primaires
qu'elle cite ; « CT-9 R11-Fn » les distingue des faits R11 cités par CT-2.

| Renvoi | Objet | Source primaire, date de lecture |
|---|---|---|
| CT-9 R11-F23, R11-F24 | États des mutants (tué, survivant, sans couverture, délai, ignoré), score de mutation, « code coverage doesn't tell you everything about the effectiveness of your tests » | https://stryker-mutator.io/docs/mutation-testing-elements/mutant-states-and-metrics/ et https://stryker-mutator.io/docs/ ; StrykerJS 10.1.1 ; 2026-11-01 |
| CT-9 R11-F25 | Mutants équivalents et désactivation motivée (« : custom reason ») | https://stryker-mutator.io/docs/stryker-js/disable-mutants/ ; 2026-11-01 |
| CT-9 R11-F26, R11-F27 | « If your tests fail then the mutation is killed, if your tests pass then the mutation lived » ; opérateurs void method calls, remove conditionals, true/false returns | https://pitest.org/ et https://pitest.org/quickstart/mutators/ ; PIT 1.19.1 ; 2026-11-01 |
| CT-9 R11-F28 | Injection de fautes en exploitation : état stable, hypothèse, variation, rayon d'effet borné | https://principlesofchaos.org/ ; 2026-11-01 |
| CT-9 R11-F49 à R11-F51 | libfaketime v0.9.13 : préchargement sans privilège, formats, limites (binaires statiques, setuid, Go) | README du dépôt wolfcw/libfaketime (SHA-256 `5c8bd832…0f97a`, annexe A de R11) ; 2026-11-01 |
| CT-9 R11-F52, R11-F53 | MockTimers de Node (`Date`, `setTimeout` pilotés, `hrtime` non simulé ; exécution locale sous v22.22.0) | https://nodejs.org/api/test.html et exécution de la note ; 2026-11-01 |
| CT-9 R11-F54 | `@sinonjs/fake-timers` 15.4.0 : `hrtime`, `nextTick`, `performance` simulés | README du dépôt ; 2026-11-01 |

Lectures du dépôt (2026-11-01, arbre de travail ; les numéros de ligne sont
ceux de cette date) :

- `spec/vecteurs/ct-7/menaces.json` : 98 menaces, 82 risques, préfixe fixe
  du membre `test`.
- `scripts/lib/securite.mjs` : l. 862-1080, `verifierCeremonie`, CR-1 à
  CR-12 ; l. 462-660, `verifierPartieAttestation`, AT-1 à AT-7 ;
  l. 1266-1320, `controlerDeclaration`.
- `scripts/lib/verificateur.mjs` : l. 849-888, N-3 ; l. 903 et 1031-1035,
  AT- hors de `failed_checks` ; l. 1331-1368, `fragmentPerimetre`.
- `scripts/lib/registre.mjs` : l. 790-843, R-2 et R-4 ; l. 895-970, R-6 à
  R-9 ; l. 995-1096, R-10 et R-11.
- `scripts/lib/horodatage.mjs` : l. 163-166, fin de structure DER ;
  l. 1151-1159, T-2. `scripts/lib/ots.mjs` : l. 410, preuve de travail ;
  l. 545-548, O-2. `scripts/lib/journal.mjs` : l. 2531-2539, K-4.
- `scripts/lib/approbation.mjs` : l. 452, fenêtre couvrante ; l. 689-703,
  `normaliserSignature` ; l. 729-744, SG-5 à SG-7 ; l. 1457-1458, plafond ;
  l. 1571, seuil effectif ; l. 1595, `set_reassigned` ; l. 1797, `consommer`.
- `scripts/lib/console.mjs` : l. 1060, adresse recouvrée ; l. 1155-1159,
  uuid en double ; l. 1463 et 1488, `adresse_deja_attribuee`.
- `scripts/lib/capture.mjs` : l. 293, clé en double ; l. 442-444,
  `nombre_non_representable` ; l. 1968, espace `noortrace.` réservé ;
  l. 2924, `serveurs_mcp_fournisseur` ; l. 3626-3630, horloge ;
  l. 3694-3733, `relireSegment`.
- `scripts/lib/otel.mjs` : l. 798-801, `nomOutil`. `scripts/lib/worm.mjs` :
  l. 234-235, mode du verrou ; l. 428, `meme_identite`.
- `scripts/lib/ancrage.mjs` : l. 726, règle 4 d'AN-1 ; l. 1296-1297,
  `point_manquant` ; l. 1496, `file_perdue` ; l. 1784, `anchor_fallback` ;
  l. 1812-1830, `echecRegistre` ; l. 1923-1927, fraîcheur et horloge.
- `scripts/lib/conventions-registre.mjs` : l. 1407-1438, CP-4.
- `.github/workflows/ci.yml` : job `vecteurs`, étapes `go run . ..`.

Les vecteurs cités par les TA- sont ceux de `spec/vecteurs/ct-1` à `ct-7` au
même commit. Non vérifié : aucune exécution d'un test de phase 2 ; le
comportement des mutants sous une autre version de Node.js que v22.22.0.

### B.4 Mesures et rejeu à l'aveugle (sections 11, 12, 15)

Les faits externes des sections 11, 12 et 15 viennent du digest R11 du lot CT-9
(pratiques de test, lu le 2026-11-01 ; à citer « CT-9 R11-F<n> » quand CT-2 cite
son propre R11) et du digest R10 (dépôt et délégations) ; les lectures directes
et les exécutions sont datées du 2026-11-01, sauf la lecture de la référence de
Docker Compose (2026-11-02).

| Renvoi | Objet | Source primaire | Lecture |
|---|---|---|---|
| R11-F10 | « expected results », « test result », « test plan » (clause 3) | ISO/IEC/IEEE 29119-3:2021, aperçu officiel, 27-Oct-2021 | 2026-11-01 |
| R11-F15 | critères de sortie mesurables ou binaires | ISTQB CTFL v4.0.1, 2024-09-15 | 2026-11-01 |
| R11-F29, R11-F30 | échauffement, répétitions minimales, export des échantillons, aberrants signalés | hyperfine v2.0.0 (2026-10-07), page de manuel et `outlier_detection.rs` | 2026-11-01 |
| R11-F31, R11-F32 | échauffement, répétitions, contexte machine, mise à l'échelle de fréquence, ASLR | Google Benchmark v1.10.0, `user_guide.md`, `reducing_variance.md` | 2026-11-01 |
| R11-F34 | règles 3, 4, 5, 8, 9 : moyennes, percentiles, machine documentée | T. Hoefler, R. Belli, SC '15, DOI 10.1145/2807591.2807644 | 2026-11-01 |
| R11-F35 | omission coordonnée, mesure depuis l'instant prévu d'envoi | wrk2 `README.md` ; HdrHistogram | 2026-11-01 |
| R11-F37, R11-F38 | reproductibilité : « Results Reproduced », « Functional » | NISO RP-31-2021 (2021-01-28), annexe A | 2026-11-01 |
| R11-F5, R11-F53 | horloge injectée de CT-5 ; minuteries simulées de Node v22.22.0 | `scripts/lib/ancrage.mjs` l. 1098 ; exécution locale | 2026-11-01 |
| R11-NV5 | aucune source dédiée à la mesure par paire | — | non vérifié |
| R10-F4 à R10-F15 | épreuves déléguées : participants, matériel, grilles, verdicts | `spec/CT-3-approbations.md` l. 7188-7225, 7640-7672 ; `CT-4` l. 2767-2800 ; `CT-5` l. 201, 4382 ; `CT-6` l. 1471-1495, 2087-2200 ; `CT-7` l. 3745-3821, 4371-4384 ; `CT-8` l. 6907-7037 | 2026-11-01 |
| R10-F16 à R10-F25 | cibles et méthode : CT-2 §16 ; CT-5 §3.6, §7.2, §15 ; CT-8 EX-7.1, EX-8.1, §9.2, §10, EX-11.5, §12.2, EX-13.1 | `spec/CT-2-enregistreur.md` l. 10367-10456 ; `CT-5` l. 417-431, 1624-1645, 4426-4429 ; `CT-8` l. 2280-2289, 2539-2556, 2591-2612, 2995-3012, 3323-3326, 4189-4208, 4791-4811, 5261-5295 | 2026-11-01 |
| exécution | tailles des lignes du segment de la démonstration | `node -e` et `awk` sur `spec/vecteurs/ct-2/evenements/journal-demo/segment.ndjson` : 9 lignes, 14 293 octets, moyenne 1 588,11 | 2026-11-01 |
| exécution | durée de vérification d'un dossier (illustration de la méthode) | `chronometrer.mjs`, 3 échauffements, 20 répétitions, horloge monotone : p50 454,14 ms, p99 563,47 ms | 2026-11-01 |
| exécution | environnement de rédaction | `node --version` v22.22.0 ; `go version` go1.24.7 ; `python3 --version` 3.13.16 ; `uname -r` 6.18.44-fc-v185 ; `/proc/cpuinfo`, `free`, `lsblk`, `/etc/os-release` | 2026-11-01 |
| lecture | `docker compose up` (sortie agrégée des conteneurs, arrêt des conteneurs à la sortie, `--detach`, `--exit-code-from`, qui implique `--abort-on-container-exit`, arrêt de tous les conteneurs dès que l'un d'eux s'arrête) et `docker compose wait` (attente de l'arrêt des services nommés) : TM-43 | référence de la ligne de commande de Docker Compose, pages `reference/cli/docker/compose/up/` et `reference/cli/docker/compose/wait/` de docs.docker.com | 2026-11-02 |
| exécution | validation des schémas et des cas | `npx --yes ajv-cli@5` (`compile`, `validate`, `--spec=draft2020 --strict=true`) sur la partie C et la fusion avec la partie A | 2026-11-01 |
