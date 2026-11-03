# CT-8 — Déploiement et exploitation

Version 0.2, 2026-11-03 (révision 0.2 : coefficient `b_cap` mesuré sur un bloc
plein et dimensionnement qui en dépend, 0.4) ; version 0.1 du 2026-10-27,
première rédaction. Spécification normative, soumise à
la revue de la porte 1 du plan de projet (document interne). Elle répond, un par
un, aux renvois que CT-2 à CT-7 font à CT-8 (table de traçabilité, section
0.2) : les topologies et les paquets (section 3), les fichiers de conteneur de
référence et leurs vérifications statiques (section 4), les prérequis réseau
(section 5), le contrôle préalable d'un hôte (section 6), l'installation rapide
(section 7) et l'installation complète de production (section 8), le
dimensionnement (section 9), l'observabilité et les runbooks d'incident (section
10), la sauvegarde, la reprise, les mises à jour et le journal des
consultations et des accès (section 11), le mode observation (section 12) et le
paquet réviseur (section 13). Elle accompagne la révision 0.6 de CT-2 et la
révision 0.4 de CT-3, minimales et compatibles, qui ajoutent le mode
observation. Elle ne change aucun format figé de CT-1 v0 (événement, manifeste,
dossier, objet `A`, `D_A`, signature EIP-191 version `0x45`), ni aucun vecteur
de CT-1 à CT-7.

L'enregistreur, le service d'approbation et le composant d'ancrage ne sont pas
encore construits : CT-8 les spécifie pour la construction et n'invente aucun
résultat de mesure. Toute durée, tout débit ou toute capacité qu'aucune
exécution n'a établi est une **cible**, notée « à mesurer (CT-9, porte 2) ». Ce
qui existe et s'exécute aujourd'hui (le vérificateur de dossier, l'outil du
registre, le réseau de développement, les bibliothèques de référence, les
fichiers de conteneur analysés sans être lancés, le prototype de l'outil du
paquet réviseur) est mesuré, et chaque mesure citée donne sa commande.

Son critère d'acceptation est celui du plan : **l'enregistreur s'installe sur
une machine vierge en moins d'une journée en suivant le seul document, sans
autre aide**. « Le seul document » s'entend de CT-8 et des documents qu'il
désigne (EX-7.1, EX-8.1), plus, en version 0.1, la documentation de la
distribution pour IC-2, tant que le script de préparation de l'hôte manque
(section 15). Le critère est mesuré à la porte 2 (CT-9) quand l'enregistreur
existera ; d'ici là, CT-8 fixe la procédure exacte (section 8), son budget de
temps pas par pas et ce que CT-9 chronomètre (EX-8.1). La parité s'écrit en
exigences mesurables, sans référence à un produit : une installation rapide en
15 minutes au plus (EX-7.1) ; un mode observation qui capture les mêmes sources
que le mode bloquant, sans jamais bloquer un appel relayable ni le retarder par
une décision (section 12 ; au-delà des bornes d'attente de CT-2 EX-14.9,
l'appel est relayé et son événement perdu, compté, EX-12.3 et EX-12.14) ; un
paquet réviseur vérifiable hors ligne en une commande (EX-13.1).

## 0. En-tête et conventions

### 0.1 Conventions

Les mots DOIT, NE DOIT PAS, DEVRAIT et PEUT ont le sens de la RFC 2119, comme
dans CT-1 à CT-7. Un DOIT adressé au client ou à l'exploitant est une exigence
de la spécification : la condition pour que la pièce ou la procédure citée
produise l'effet décrit ; il ne crée aucune obligation contractuelle tant qu'un
contrat ne le reprend pas (même règle que CT-7 §0.1).

Chaque règle normative porte un identifiant **EX-<section>.<n>** (EX-6.2 :
deuxième règle de la section 6), stable, auquel le plan de tests (CT-9) attache
ses tests. Les identifiants sont numérotés dans l'ordre du texte à l'intérieur
de chaque section de premier niveau, sous-sections comprises ; ceux de
l'annexe A s'écrivent EX-A.<n>. Une règle ajoutée par une révision reçoit le
numéro qui suit le plus grand de sa section ; aucun numéro n'est réattribué ;
une règle retirée garde son numéro, marqué « retiré ».

Un renvoi à une autre spécification s'écrit avec elle : « CT-2 EX-18.4 », « CT-4
§10.3 », « CT-7 CLE-16 ». Dans une énumération, un identifiant écrit sans
« CT-n » devant se lit dans la spécification du premier élément de
l'énumération qui en nomme une (« CT-2 EX-17.1, EX-18.3 » : deux exigences de
CT-2) ; un renvoi nu, hors d'une telle énumération, est un renvoi à CT-8. Une
famille définie par une autre spécification garde sa définition (CT-4 CP-1 est
une vérification de capture ; CT-8 n'emploie pas le préfixe CP-).

Les clés JSON sont en anglais ; les valeurs énumérées en français sans accent
(`pret_avec_avertissements`, `non_execute`, `a_approuver`). Les noms d'hôtes
d'exemple sont du domaine réservé `.example` (RFC 2606) ; les adresses
d'exemple sont celles des plages de documentation de la RFC 5737
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) et de la RFC 3849
(`2001:db8::/32`), ou `127.0.0.1`. Aucune clé réelle (seules les clés de test
des vecteurs), aucun prix, aucun nom d'hôte d'exploitation ne figure dans CT-8
ni dans ses vecteurs.

Une **cible** est une valeur de conception non mesurée ; elle s'écrit avec « à
mesurer (CT-9, porte 2) ». Une **mesure** est le résultat d'une exécution
réelle, avec sa commande et sa date.

Familles d'identifiants de CT-8 :

| Famille | Objet | Définie par |
|---|---|---|
| TC- | Renvoi d'une autre spécification à CT-8 et sa réponse | 0.2 |
| CO- | Vérification statique d'un fichier Compose de référence contre la description des images (`deploiement/images/images.json`) | 4.4 |
| FL- | Flux réseau d'un déploiement : source, destination, port, protocole, raison, exigence citée | 5.1 |
| IP- | Vérification du contrôle préalable d'un hôte | 6.2 |
| IR- | Pas de l'installation rapide, avec sa commande, son résultat attendu, sa vérification et son budget | 7.2 |
| IC- | Pas de l'installation complète de production, même forme | 8.3 |
| TP- | Tâche planifiée d'exploitation posée à l'installation | 8.4 |
| DM- | Ligne de formule du dimensionnement | 9.3 |
| SV- | Vérification statique de la supervision : couverture des alertes prescrites par les règles, noms de métriques connus, étiquettes et gravités, extracteur des journaux, tableau de bord, forme des runbooks | 10.10 (table d'EX-10.11) |
| RB- | Runbook d'incident (RB-1 à RB-8) ; sa forme est fixée par EX-10.13 et vérifiée par SV-8 | 10.11 à 10.19 |
| PV- | Vérification d'un procès-verbal d'exploitation (`proces-verbal-exploitation-v0`) : forme, fichiers, totaux, condensés, personnes, cohérence de la sorte, vérification, continuité, rétention | 11.9 (table d'EX-11.18) |
| CA- | Vérification d'un fichier du journal des consultations et des accès (`consultation-v0`) : forme, rang, chaînage, ordre de collecte, rattachement à la source, rôle | 11.10 (table d'EX-11.20) |
| OB- | Vérification du mode observation : marque de `policy.rule`, cohérence de l'événement marqué, exclusivité sous une version de politique, absence d'approbation, rapport, correspondance d'une évaluation | 12.8 (table d'EX-12.16) |
| PR- | Vérification d'un paquet réviseur : taille, empreinte attendue, en-têtes ustar, types d'entrées, noms, forme déterministe, manifeste, correspondance, cohérence, extraction, vérificateur joint, attestation jointe | 13.8 (PR-1 à PR-12) |
| AV-PR- | Avertissement de l'outil de vérification du paquet, sans effet sur le code de retour | 13.9 (AV-PR-1 à AV-PR-4) |
| PD- | Proposition de CT-8 à une autre spécification ou au dépôt, sans la modifier | 16.2 (PD-10 à PD-12 posées en 10.10, PD-13 à PD-15 en 11.12) |

Les faits externes viennent de deux notes de recherche du lot CT-8, R8 (dépôt
public et noorchain-core) et R9 (pratiques publiées), internes et non publiées,
relues le 2026-10-27 sur les sources primaires qu'elles citent, et de lectures
directes de la rédaction (page de manuel `ioctl_iflags(2)`, runbooks et gabarit
d'observabilité de noorchain-core, manuels de GNU tar et de Python). Chaque
fait porte le renvoi de sa note (« R9-F25 ») ; l'annexe B donne pour chacun
l'objet, la source primaire, son URL ou son chemin et la date de lecture. Ce
qui n'a pas pu être vérifié est écrit « non vérifié ».

### 0.2 Ce que les autres spécifications délèguent à CT-8

Chaque occurrence de « CT-8 » dans `spec/*.md` (hors CT-8) au 2026-10-27, après
les révisions 0.6 de CT-2 et 0.4 de CT-3 et la mise à jour de `spec/README.md`
qui accompagnent CT-8 0.1, est un renvoi : 115 occurrences sur 106 lignes
(CT-1 : 0 ; CT-2 : 41 occurrences sur 37 lignes ; CT-3 : 9 ; CT-4 : 11 ; CT-5 :
12 ; CT-6 : 0 ; CT-7 : 28 occurrences sur 25 lignes ; `spec/README.md` : 14
occurrences sur 12 lignes). Avant ces révisions, il y en avait 89 sur 85
lignes. La table les reprend toutes, une ligne par occurrence, dans l'ordre des
fichiers (CT-1 à CT-7, puis `spec/README.md`) puis des lignes ; la colonne
« Spécification, section » nomme le dernier titre de niveau 2 à 4 qui précède
l'occurrence (hors bloc de code) : « CT-n §s » quand ce titre commence par un
numéro, son texte entre guillemets sinon. Les numéros de ligne sont ceux du
2026-10-27, indicatifs : le contrôle de l'annexe A.2 ne les lit pas, et une
retouche qui ne touche à aucun « CT-8 » peut les décaler sans régénération.

**EX-0.1** Toute occurrence de « CT-8 » dans une spécification de `spec/` DOIT
avoir sa ligne dans cette table, avec une réponse qui nomme une section, une
exigence ou un identifiant de CT-8, ou qui dit en clair que la question est hors
de la version 0.1 et où elle est portée (section 15). Dans la colonne « Ce qui
est délégué à CT-8 », un identifiant écrit sans « CT-n » devant est celui de la
spécification de la ligne ; dans la colonne « Réponse de CT-8 », celui de CT-8.
La table est régénérée après toute retouche de `spec/*.md` qui ajoute, retire ou
déplace un « CT-8 ». Le contrôle est automatique (annexe A.2) : il compte,
fichier par fichier et section par section, les occurrences et les lignes de la
table.

**EX-0.2** Hors de `spec/`, les mêmes renvois existent et reçoivent la même
réponse, sans ligne dans la table : `console/LISEZMOI.md` (l. 50 : construction
reproductible et publication de la console → EX-3.13 et EX-3.14) ;
`test/approbation.test.js` (l. 1517 : même objet → EX-3.13) ;
`scripts/conformite/matrice-donnees.mjs` (l. 3033, 3118, 3322, 3333, 3420) et
les vecteurs figés de CT-7 (`spec/vecteurs/ct-7/matrice-conformite.json`,
`menaces.json`, `matrice/invalides/*.json`,
`acceptation-conformite-attendu.json`), qui recopient les chaînes de L-1, L-2,
L-9 et de MN-55 → section 11 (PA-15 : 11.6, 11.9 à 11.11) et 10.6 (règle
`noortrace_registre_mempool`). Ces fichiers ne sont pas modifiés : les vecteurs
de CT-7 sont figés.

| Id | Spécification, section (ligne) | Ce qui est délégué à CT-8 | Réponse de CT-8 |
|---|---|---|---|
| TC-1 | CT-2 §0.4 (l. 161) | Note de la révision 0.6 : la parité du mode observation, exprimée en exigences mesurables. | Section 12 (EX-12.1 à EX-12.16). |
| TC-2 | CT-2 §0.4 (l. 179) | Note de la révision 0.6 : les cas du mode observation. | Annexe A.8 (vecteurs du mode observation). |
| TC-3 | CT-2 §1 (l. 527) | Le déploiement, la sauvegarde et l'exploitation du service. | Ce document : §3 à §9 (déploiement), §10 (observabilité et runbooks), §11 (sauvegarde, reprise, mises à jour). |
| TC-4 | CT-2 §1 (l. 539) | Table des relations : CT-8 reçoit les métriques et la santé (CT-2 §17) et la disposition du stockage (CT-2 §12) ; il fait le déploiement, la sauvegarde, la restauration. | Déploiement : §3 à §8 ; volumes et disposition : EX-3.5 ; santé et métriques : 10.2 ; sauvegarde et restauration du répertoire de CT-2 §12.1 : 11.2 à 11.4. |
| TC-5 | CT-2 §3.4 (l. 744) | Lancement d'un serveur d'outils stdio par l'orchestrateur, un conteneur par serveur. | Pont stdio, un conteneur par serveur, sous un utilisateur distinct : EX-3.7 et EX-3.8 (§3.4) ; service `pont-fichiers` du fichier de production (§4.3). |
| TC-6 | CT-2 §9.2 (l. 5824) | Archivage des fichiers tournés du journal d'exploitation avec le journal. | 11.11 (EX-11.22, EX-11.23) ; tâche TP-6 (EX-8.6) ; volume : DM-18 (§9.3). |
| TC-7 | CT-2 §10.7 (l. 7095) | L'accès au coffre des originaux, acte d'exploitation du client (avec CT-7). | EX-11.19 (source « coffre » du journal des consultations et des accès, 11.10) ; secret `cle-coffre` admis au seul service `enregistreur` (§4.1, CO-9). |
| TC-8 | CT-2 §11.2 (l. 7350) | Procédure de mise à jour qui prévoit le descellement TPM lié aux PCR. | EX-11.10 (descellement TPM, 11.5). |
| TC-9 | CT-2 §12.3 (l. 7715) | Faire du stockage à cache d'écriture protégé (EX-12.9) une exigence de déploiement. | EX-6.4 (vérification IP-13, bloquante en production) et pas IC-2 (§8.3). |
| TC-10 | CT-2 §12.4 (l. 7754) | Restauration depuis la copie WORM après `segment_corrupted`. | Chemin B d'EX-11.6 (11.4) ; runbooks RB-1 (EX-10.16) et RB-5 (EX-10.20). |
| TC-11 | CT-2 §12.6 (l. 8005) | Tâche planifiée de `poser` à chaque clôture et alerte de retard ; support sans mode Compliance à valider. | Tâche planifiée : TP-1 (EX-8.6) et EX-11.17 ; alerte de retard : règle `noortrace_gel_pose_en_retard` (10.4) ; support à valider : EX-3.4. |
| TC-12 | CT-2 §12.6 (l. 8026) | Service compagnon ou tâche d'orchestrateur qui pose les attributs `a` et `i` (CAP_LINUX_IMMUTABLE), hors du démon. | Service `attributs` : EX-3.9 (§3.4), image `noortrace/attributs`, seule exception de CO-4 et CO-6 (§4.4). |
| TC-13 | CT-2 §12.6 (l. 8140) | Moyen exact de soustraire `<prefix>gels/` aux droits de l'écrivain. | EX-8.4 (pas IC-9) : registre des gels dans un bucket distinct, ou politique de l'écrivain limitée aux sous-préfixes copiés ; contrôle par le rôle Lecteur. |
| TC-14 | CT-2 §12.7 (l. 8210) | La fin de rétention, acte d'exploitation. | EX-11.15 (11.7) ; procès-verbal `fin_de_retention` (11.9). |
| TC-15 | CT-2 §12.8 (l. 8250) | Titre « Sauvegarde et restauration (renvoi à CT-8) ». | §11. |
| TC-16 | CT-2 §12.8 (l. 8255) | Sauvegarde du journal, restauration, reconstruction depuis WORM, migration de support avec procès-verbal (Olico art. 10 al. 2 et 3). | EX-11.2 à EX-11.8 (11.2 à 11.4) ; migration de support avec procès-verbal : EX-11.13 et EX-11.14 (11.6). |
| TC-17 | CT-2 §12.11 (l. 8523) | `--motif` et `--reference` de l'outil de gel ne portent que des identifiants de dossier. | EX-11.16, point 2 (11.8) ; même règle pour `reason` d'un procès-verbal (11.9). |
| TC-18 | CT-2 §12.11 (l. 8698) | Procédure de levée qui répartit pose, demande et levée entre trois personnes, proposée à CT-8. | EX-11.16 (11.8) ; rôles posés à la création du support : EX-8.4 (pas IC-9). |
| TC-19 | CT-2 §12.11 (l. 8702) | Séparation des rôles sur le support, que CT-8 fait poser. | EX-8.4 (pas IC-9) : cinq rôles de CT-2 EX-18.9 créés et vérifiés à la création du support ; leur emploi dans la levée : EX-11.16. |
| TC-20 | CT-2 §12.11 (l. 8915) | Fin de rétention après la levée d'un gel. | EX-11.15, point 4 (11.7). |
| TC-21 | CT-2 §13.4 (l. 9082) | Bascule d'adresse (VIP, DNS, répartiteur) à la reprise d'une instance. | EX-3.11 (§3.5) ; pas et vérification : RB-2 (EX-10.17). |
| TC-22 | CT-2 §13.5 (l. 9123) | Volume bloc répliqué de façon synchrone pour qui n'admet pas la perte du segment ouvert. | EX-3.12 (§3.5) ; objectif de point de reprise du segment ouvert : 11.3. |
| TC-23 | CT-2 §14.6 (l. 9365) | CT-2 EX-14.13 : l'exploitation du mode observation, le passage au mode bloquant et ce que le mode prouve. | 12.1 à 12.7 ; passage : EX-12.11 et EX-12.12 ; preuve : EX-12.14. |
| TC-24 | CT-2 §17.4 (l. 10812) | Règles Prometheus des alertes prescrites. | EX-10.1 et EX-10.6 ; règles des tables de 10.4 à 10.7 ; fichier `deploiement/observabilite/regles-noortrace.yml`. |
| TC-25 | CT-2 §17.4 (l. 10829) | Alerte « Gel levé » à rapprocher de la procédure de levée. | Règle `noortrace_gel_leve` (10.4) ; procédure de levée : EX-11.16, point 5. |
| TC-26 | CT-2 §18.3 (l. 11018) | Système de fichiers racine en lecture seule « quand le conteneur le permet ». | Toujours dans les fichiers de référence : CO-5 (§4.4) ; écritures limitées aux volumes décrits (CO-11). |
| TC-27 | CT-2 §18.3 (l. 11034) | Poser les cinq rôles du support WORM à sa création. | EX-8.4 (pas IC-9). |
| TC-28 | CT-2 §18.3 (l. 11052) | Procédure de levée sur Azure et GCS, sans séparation pose et levée. | EX-11.16, point 4 ; activation approuvée du rôle de levée posée au pas IC-9 (EX-8.4). |
| TC-29 | CT-2 §18.4 (l. 11063) | Empreinte et attestation de provenance de l'image publiée. | EX-3.13 à EX-3.15 (§3.6). |
| TC-30 | CT-2 §19.6 (l. 12153) | Détail opérationnel du raccord ICAP. | Flux FL-4 (§5.1), EX-5.4 et pas IC-12 (§8.3). |
| TC-31 | CT-2 §21 (l. 12253) | Sauvegarde, restauration, migration de support, règles d'alerte Prometheus, empaquetage `.mcpb`, déploiement. | Déploiement : §3 à §8 ; paquets, dont le connecteur et `.mcpb` : EX-3.6 ; règles d'alerte : 10.4 à 10.7 ; sauvegarde, restauration, migration : §11. |
| TC-32 | CT-2 §21 (l. 12325) | Création du support, procédure de levée à deux personnes et fin de rétention, restées à la charge du client. | Création du support : EX-8.4 ; levée : EX-11.16 ; fin de rétention : EX-11.15. |
| TC-33 | CT-2 §21 (l. 12328) | Même délégation, « proposées à CT-8 (section 22) ». | Comme la ligne précédente. |
| TC-34 | CT-2 §21 (l. 12351) | Un mode « avertir », proposition pour une version ultérieure (pratique `warn`). | Introduction de la section 12 ; hors de la version 0.1 (§15). |
| TC-35 | CT-2 §22 (l. 12411) | Ligne CT-8 de l'alignement : création du support (rétention par défaut, rôles, restriction hors `<prefix>gels/`, politiques d'organisation), levée à deux personnes, relecture par le Lecteur, fin de rétention. | EX-8.4 et EX-8.5 (pas IC-9) ; levée à deux personnes : EX-11.16 ; relecture par le Lecteur : EX-10.9 et TP-4 ; fin de rétention : EX-11.15. |
| TC-36 | CT-2 §22 (l. 12411) | État de la ligne : « proposition (CT-8 à écrire) ». | Ce document répond ; l'état est mis à jour par la table « Révision 0.6 » de CT-2 §22. |
| TC-37 | CT-2 §22 (l. 12419) | Alignement, révision 0.6 : cas du mode observation (CT-8 annexe A). | Annexe A.8. |
| TC-38 | CT-2 §22 (l. 12419) | Même ligne, état « à faire (CT-8) ». | Annexe A.1 et A.8 : vecteurs produits par le générateur de CT-8. |
| TC-39 | CT-2 §22 (l. 12422) | Alignement, révision 0.6 : la ligne CT-8 de la révision 0.5. | EX-8.4 et EX-8.5 (pas IC-9), EX-11.16, EX-10.9 et TP-4, EX-11.15. |
| TC-40 | CT-2 §22 (l. 12422) | Même ligne, état antérieur « proposition, CT-8 à écrire ». | Ce document. |
| TC-41 | CT-2 §22 (l. 12422) | Même ligne, état attendu « répondue par CT-8 0.1 ». | Ce document, version 0.1. |
| TC-42 | CT-3 §0 (l. 259) | Note de la version 0.4 : le mode observation demandé par CT-8. | Section 12. |
| TC-43 | CT-3 §0 (l. 268) | Note de la version 0.4 : l'exception d'EX-11.1 pour l'installation rapide. | EX-7.3 et 7.3 : configuration de l'installation rapide en mode observation. |
| TC-44 | CT-3 §1 (l. 309) | L'exploitation du service d'approbation et de la console. | Composants `approbation` et `console` : §3 et §4 ; supervision du service : 10.2 et 10.7 ; sauvegarde de son état : 11.2 ; mise à jour : EX-11.12. |
| TC-45 | CT-3 §1 (l. 336) | La console d'exploitation, son serveur et son authentification par le système d'identité du client. | Serveur de la console de référence et son authentification : EX-3.3, flux FL-14 et FL-16, pas IC-11 ; la console d'exploitation (phase 2) reste hors de la version 0.1 (§15). |
| TC-46 | CT-3 §11.1 (l. 3426) | CT-3 EX-11.1 : l'installation rapide emploie le mode observation. | EX-7.3 et 7.3. |
| TC-47 | CT-3 §13.2 (l. 4579) | Publication des empreintes du document et construction reproductible (avec CT-7). | EX-3.13 et EX-3.14 (§3.6) ; publication et comparaison des empreintes : CT-7 EX-3.9, tâche TP-5 d'EX-8.6. |
| TC-48 | CT-3 §13.15 (l. 6129) | Publication des empreintes du document et construction reproductible (avec CT-7). | EX-3.13 et EX-3.14 (§3.6) ; publication et comparaison des empreintes : CT-7 EX-3.9, tâche TP-5 d'EX-8.6. |
| TC-49 | CT-3 §15.2 (l. 6871) | Alignement, révision 0.4 : mode observation. | Section 12 ; vecteurs : annexe A.8 ; vérificateur Go : annexe A.13 (OB-6). |
| TC-50 | CT-3 §16 (l. 6988) | Un mode « avertir » (pratique `warn`). | Introduction de la section 12 ; hors de la version 0.1 (§15). |
| TC-51 | CT-4 §1 (l. 204) | La supervision et la sauvegarde. | Supervision : 10.6 ; sauvegarde : EX-11.1, point 3 (aucune restauration d'un validateur). |
| TC-52 | CT-4 §1 (l. 229) | Table des relations : l'image, les topologies, les ports et les volumes (CT-4 §10), les seuils de provision (4.5), la rétention à tenir (CT-4 §9) ; la supervision, la sauvegarde des bases des validateurs, la publication des manifestes. | Image du nœud reprise : EX-3.6 et service `relais` (§4.3) ; ports et volumes : EX-3.5 ; capture et rétention : DM-11 (§9.3) et règle `noortrace_registre_marge_retention` (10.6) ; seuils de provision : règle `noortrace_registre_solde_bas` (10.6) ; sauvegarde des validateurs : EX-11.1, point 3 ; publication des manifestes : hors de la version 0.1 (§15). |
| TC-53 | CT-4 §4.5 (l. 719) | Seuil d'alerte de la consommation d'un expéditeur (EX-8.18). | Règle `noortrace_registre_examen_requis` (10.6). |
| TC-54 | CT-4 §4.5 (l. 749) | Alerte sur la taille de la mempool et sur `transaction underpriced`. | Règles `noortrace_registre_mempool` et `noortrace_registre_sous_tarif` (10.6) ; ligne de refus proposée : PD-12. |
| TC-55 | CT-4 §8.2 (l. 2866) | Alerte : clôture non soumise 24 heures après la fin de sa période. | Règle `noortrace_registre_cloture_non_soumise` (10.6). |
| TC-56 | CT-4 §8.7 (l. 3161) | Seuils d'alerte du solde des expéditeurs. | Règle `noortrace_registre_solde_bas` (10.6) et sonde d'EX-10.7. |
| TC-57 | CT-4 §9.4 (l. 3277) | Alerte : capture non faite dans l'heure. | Règle `noortrace_registre_capture_en_retard` (10.6). |
| TC-58 | CT-4 §10.2 (l. 3563) | Alerte sur la mempool de chaque validateur et sur `transaction underpriced`. | Règles `noortrace_registre_mempool` et `noortrace_registre_sous_tarif`, étiquette `target` par validateur (10.6). |
| TC-59 | CT-4 §10.2 (l. 3595) | Proposition de sauvegarde des validateurs. | EX-11.1, point 3, et ligne « Validateur » de la table d'EX-11.2 ; écart entre CT-4 EX-10.9 et CT-7 EX-4.4 : PD-16. |
| TC-60 | CT-4 §12 (l. 3785) | Menace d'empoisonnement de la mempool : alerte de CT-8. | Règle `noortrace_registre_mempool` (10.6). |
| TC-61 | CT-4 §13 (l. 3834) | Alignement : interdire la restauration de `db/leveldb` et de l'état de consensus ; superviser mempool, `transaction underpriced`, `noor_bft_equivocations_total`. | Restauration interdite : EX-11.1, point 3 ; supervision : règles `noortrace_registre_mempool`, `noortrace_registre_sous_tarif` et `noortrace_registre_equivocation` (10.6) ; relais jamais pour capture ni soumission : EX-3.6. |
| TC-62 | CT-5 §1 (l. 190) | La supervision au-delà des métriques et alertes de CT-5 §8. | 10.5 (règles du composant d'ancrage) et EX-10.9 (relectures hors du composant). |
| TC-63 | CT-5 §1 (l. 213) | Table des relations : métriques, alertes et procédures de la file (§8), serveur interne (§7), rétention des jetons (5.5), fichier d'en-têtes Bitcoin (6.6) ; supervision, sauvegarde de la file, publication des pièces aux réviseurs. | Composant d'ancrage dans le démon : EX-3.2 ; serveur interne : FL-21 et §15 ; règles : 10.5 ; runbooks RB-3 et RB-4 (EX-10.18, EX-10.19) ; sauvegarde de la file et des ancres : 11.2 ; rétention : EX-11.15 ; en-têtes : TP-3 et EX-11.24 ; publication des pièces aux réviseurs : paquet réviseur (13.2, EX-13.5, EX-13.7, 13.7) et EX-13.37, pas 1. |
| TC-64 | CT-5 §4.3 (l. 648) | Capacité de l'instance du registre pour le nombre de journaux cible. | DM-20 à DM-22 (§9.3), sortie `registry_journals_max` et `registry_capacity_share`. |
| TC-65 | CT-5 §5.3 (l. 1123) | Réétablissement du statut qualifié au plus tous les trente jours. | Tâche TP-2 d'EX-8.6 ; table des tâches périodiques d'EX-11.24. |
| TC-66 | CT-5 §5.5 (l. 1270) | Fin de rétention des jetons, acte d'exploitation. | EX-11.15. |
| TC-67 | CT-5 §6.5 (l. 1519) | Tenue du fichier d'en-têtes Bitcoin par l'exploitation (`fichier`). | Tâche TP-3 d'EX-8.6 et EX-11.24 ; flux FL-20 pour la source `bitcoin_rpc` ; fichier de la période joint au paquet réviseur sous `entetes/` (EX-13.5). |
| TC-68 | CT-5 §8.8 (l. 2054) | Fin de rétention des fichiers du planificateur. | EX-11.15. |
| TC-69 | CT-5 §8.9 (l. 2075) | Règles des alertes prescrites de l'ancrage. | EX-10.1 ; table de 10.5. |
| TC-70 | CT-5 §12.4 (l. 4336) | Dimensionnement : environ 650 Mo par an d'ancres par journal ; 187,1 Mo par jour de captures quand chaque transaction est dans un bloc plein d'ancres (CT-5 0.3 ; 10 Mo par jour en CT-5 0.2). | DM-9 et DM-11 (§9.3) recalculent ces deux grandeurs fichier par fichier ; écarts expliqués en §9.5. |
| TC-71 | CT-5 §14 (l. 4400) | Ligne CT-2 de l'alignement : métriques, journal et alerte de CT-5 §8.9, « proposition (CT-2 §17, CT-8) ». | Table de 10.5 ; noms de lignes et de membres à fixer : PD-11. |
| TC-72 | CT-5 §14 (l. 4406) | Ligne CT-8 : alertes de 8.9, sauvegarde des ancres et de la file, fin de rétention, source d'en-têtes, capacité de capture et dimensionnement, serveur interne, réétablissement de `qualified`. | Alertes : 10.5 ; sauvegarde des ancres et de la file : 11.2 ; fin de rétention : EX-11.15 ; en-têtes et `qualified` : TP-2, TP-3 (EX-8.6) et EX-11.24 ; capacité et dimensionnement : §9 ; serveur interne : FL-21. |
| TC-73 | CT-5 §15 (l. 4433) | L'exploitation d'un nœud Bitcoin pour la source d'en-têtes. | Hors de la version 0.1 (§15) ; flux FL-20 quand le client en exploite un ; tâche « en-têtes Bitcoin » d'EX-11.24. |
| TC-74 | CT-7 §0.2 (l. 184) | TR-43 : construction reproductible et publication du code de la console (avec CT-8). | EX-3.13 et EX-3.14 (§3.6). |
| TC-75 | CT-7 §0.2 (l. 184) | TR-43, réponse de CT-7 : « la construction reproductible relève de CT-8 ». | EX-3.13 et EX-3.14 (§3.6). |
| TC-76 | CT-7 §0.2 (l. 185) | TR-44 : publication des empreintes de la console et construction reproductible (avec CT-8). | EX-3.13 et EX-3.14 (§3.6). |
| TC-77 | CT-7 §0.2 (l. 185) | TR-44, réponse de CT-7 : « CT-8 pour la construction ». | EX-3.13 et EX-3.14 (§3.6). |
| TC-78 | CT-7 §0.2 (l. 249) | Renvoi hors de `spec/` (`test/approbation.test.js`) : construction reproductible et publication. | EX-3.13 et EX-3.14 (§3.6). |
| TC-79 | CT-7 §0.2 (l. 252) | Renvoi hors de `spec/` (`console/LISEZMOI.md`) : empreintes et construction reproductible. | EX-3.13 et EX-3.14 (§3.6). |
| TC-80 | CT-7 §1 (l. 314) | Hors du périmètre de CT-7 : la construction reproductible et l'exploitation. | Construction : §3.6 ; exploitation : §10 et §11. |
| TC-81 | CT-7 §1 (l. 327) | Table des relations : construction reproductible et publication de l'image et de la console (EX-3.9, EX-3.14), procédure de levée d'un gel, supervision tierce (CT-2 EX-17.7), journal des consultations et procès-verbal de migration (PA-15). | Construction et publication : §3.6 ; levée d'un gel : EX-11.16 ; supervision tierce : EX-10.9 ; journal des consultations : 11.10 ; procès-verbal de migration : 11.6 et 11.9. |
| TC-82 | CT-7 §3.4 (l. 729) | Détection d'une version publiée malveillante par la construction reproductible. | EX-3.13 (deux constructions indépendantes identiques) et EX-3.15 (§3.6) ; ce qu'elle ne détecte pas : §3.6, dernier alinéa. |
| TC-83 | CT-7 §3.4 (l. 732) | « La construction reproductible relève de CT-8, à écrire (section 11) ». | EX-3.13 à EX-3.15 (§3.6). |
| TC-84 | CT-7 §3.4 (l. 799) | MN-55 : alerte de CT-8 sur la taille de la mempool. | Règle `noortrace_registre_mempool` (10.6). |
| TC-85 | CT-7 §3.7 (l. 1040) | EX-3.9 de CT-7 : la construction reproductible du code de la console. | EX-3.13 et EX-3.14 (§3.6). |
| TC-86 | CT-7 §3.7 (l. 1087) | EX-3.14 de CT-7 : empreinte d'une version publiée de l'image de l'enregistreur. | EX-3.13 à EX-3.15 (§3.6) ; épinglage par condensé en production : IP-12 et pas IC-6. |
| TC-87 | CT-7 §6.2 (l. 2070) | PA-15 adressée à CT-8. | PA-15 : 11.6, 11.9, 11.10 et 11.11. |
| TC-88 | CT-7 §8.4 (l. 3435) | MC-54 : archivage des fichiers tournés du journal d'exploitation (L-9). | EX-11.22 et EX-11.23 (11.11). |
| TC-89 | CT-7 §8.4 (l. 3437) | MC-56 : procès-verbal de migration de support (L-2). | EX-11.13 et EX-11.14 (11.6) ; schéma `proces-verbal-exploitation-v0` (11.9). |
| TC-90 | CT-7 §8.4 (l. 3445) | Archivage au-delà de `logging.keep_files` (L-9). | EX-11.22. |
| TC-91 | CT-7 §8.8.2 (l. 3620) | Rétention : archivage des fichiers tournés relevant de CT-8 (L-9). | EX-11.22 et EX-11.23 ; volume : DM-18 (§9.3). |
| TC-92 | CT-7 §8.8.3 (l. 3691) | EX-8.15 de CT-7 : journal des consultations et des accès (PA-15). | EX-11.19 à EX-11.21 ; schéma `consultation-v0` ; la remise d'un paquet réviseur y est consignée (EX-13.37, pas 4). |
| TC-93 | CT-7 §8.8.3 (l. 3695) | EX-8.16 de CT-7 : fin de rétention consignée. | EX-11.15. |
| TC-94 | CT-7 §8.9 (l. 3726) | L-1 : consultations et accès (PA-15). | Comme pour CT-7 EX-8.15 : EX-11.19 à EX-11.21 et EX-13.37, pas 4 ; la collecte reste `releve_du_client` (EX-11.19). |
| TC-95 | CT-7 §8.9 (l. 3727) | L-2 : procès-verbal de migration (PA-15). | EX-11.13 et EX-11.14. |
| TC-96 | CT-7 §8.9 (l. 3734) | L-9 : archivage des fichiers tournés. | EX-11.22 et EX-11.23. |
| TC-97 | CT-7 §8.11 (l. 3765) | PA-15 : journal des consultations et des accès, procès-verbal de migration, archivage des fichiers tournés. | Les trois points de PA-15 : 11.6 et 11.9 (procès-verbal de migration), 11.10 (journal des consultations et des accès), 11.11 (archivage). |
| TC-98 | CT-7 §9 (l. 3828) | Synthèse Olico : archivage au-delà de `keep_files` (L-9). | EX-11.22. |
| TC-99 | CT-7 §10 (l. 3863) | Ce que CT-7 ne couvre pas : la construction reproductible de l'image et de la console. | EX-3.13 et EX-3.14 (§3.6). |
| TC-100 | CT-7 §11 (l. 3926) | Alignement : PA-15 « à faire (révisions à décider ; CT-8 à écrire) ». | §11 répond à CT-7 PA-15 ; l'état de la ligne de CT-7 §11 reste à aligner par l'éditeur de CT-7 (§16, PD-1). |
| TC-101 | CT-7 §11 (l. 3926) | Même ligne, « CT-8 à écrire ». | Ce document ; même mise à jour (PD-1). |
| TC-102 | `spec/README.md` « Spécifications » (l. 22) | Ligne CT-8 de la table des spécifications. | Ce document, version 0.1. |
| TC-103 | `spec/README.md` « Spécifications » (l. 22) | Lien vers ce document. | Ce document. |
| TC-104 | `spec/README.md` « Spécifications » (l. 26) | Ordre d'écriture : CT-7, CT-8, CT-9. | Ce document ; aucune réponse attendue. |
| TC-105 | `spec/README.md` « Schémas (`schemas/`) » (l. 63) | Ligne du schéma `conteneurs-v0`. | §4 (4.1, 4.4) ; annexe A.3. |
| TC-106 | `spec/README.md` « Schémas (`schemas/`) » (l. 64) | Ligne du schéma `controle-prealable-v0`. | §6 (6.3) ; annexe A.4. |
| TC-107 | `spec/README.md` « Schémas (`schemas/`) » (l. 65) | Ligne du schéma `dimensionnement-v0`. | §9 (9.4, 9.5) ; annexe A.5. |
| TC-108 | `spec/README.md` « Schémas (`schemas/`) » (l. 66) | Ligne du schéma `proces-verbal-exploitation-v0`. | 11.9 (EX-11.18). |
| TC-109 | `spec/README.md` « Schémas (`schemas/`) » (l. 67) | Ligne du schéma `consultation-v0`. | 11.10 (EX-11.20). |
| TC-110 | `spec/README.md` « Schémas (`schemas/`) » (l. 68) | Ligne du schéma `verification-journal-v0`. | EX-11.7. |
| TC-111 | `spec/README.md` « Schémas (`schemas/`) » (l. 69) | Ligne du schéma `rapport-observation-v0`. | 12.5 (EX-12.10) ; annexe A.8. |
| TC-112 | `spec/README.md` « Schémas (`schemas/`) » (l. 70) | Ligne du schéma `paquet-reviseur-v0`. | 13.3 ; annexe A.10. |
| TC-113 | `spec/README.md` « CT-8 (`vecteurs/ct-8/`) » (l. 428) | Titre de la section des vecteurs de CT-8. | Annexe A. |
| TC-114 | `spec/README.md` « CT-8 (`vecteurs/ct-8/`) » (l. 431) | Disposition des vecteurs fixée par l'annexe A. | Annexe A.1. |
| TC-115 | `spec/README.md` « CT-8 (`vecteurs/ct-8/`) » (l. 431) | Lien vers ce document. | Ce document. |

### 0.3 Qui lit quoi

| Lecteur | Lit | Y trouve |
|---|---|---|
| Ingénieur d'exploitation qui installe | sections 3 à 9 | les composants, leurs images, comptes, volumes, ports et secrets ; les fichiers de conteneur de référence ; les flux à ouvrir ; le contrôle préalable ; l'installation rapide et l'installation complète, pas à pas, avec leurs commandes, leurs résultats attendus, leurs vérifications et leurs budgets de temps ; le dimensionnement |
| Exploitant au quotidien | sections 10 et 11, et 13.4 pour le format de l'archive de sauvegarde (EX-11.2) | les points de collecte, les règles d'alerte, le tableau de bord ; les huit runbooks d'incident ; la sauvegarde, la reprise qui garde la continuité de la chaîne, les mises à jour sans rupture, la migration de support, la fin de rétention, le gel, le journal des consultations et des accès |
| Administrateur du client | section 12, et 5.4 et 8.5 pour l'attestation de périmètre | ce que le mode observation capture, ce qu'il ne bloque jamais, ce qu'un dossier en dit et comment passer au mode bloquant |
| Réviseur externe | section 13, d'abord 13.7, 13.10 et 13.11 | ce que contient un paquet réviseur, comment le vérifier en une commande, ce que le résultat prouve et ne prouve pas |
| Responsable de la sécurité | 3.1, 3.6, 5.2, 10.19 (RB-8), 11.1, 12.7 et 13.10 | ce qui sort du périmètre du client, la construction reproductible, la sortie réseau, la conduite sur compromission, les règles de sauvegarde des clés, les limites du mode observation et du paquet |
| Auteur d'une autre spécification | 0.2, section 1 et section 16 | la réponse à chacun de ses renvois et les propositions qui lui sont adressées |
| Implémenteur, auteur de CT-9 | sections 14 à 16, annexes A et B | les critères des épreuves à l'aveugle, ce que la version ne couvre pas, les vecteurs, l'implémentation de référence, les vérificateurs, la confrontation tierce et l'intégration continue |

La section 14 décrit les épreuves à l'aveugle ; elle n'est remise à aucun
participant, et aucune autre section n'en reprend les éléments attendus.

### 0.4 Révisions

**Révision 0.2** (2026-11-03). Le coefficient `b_cap` de 9.2 valait 11 096
octets : la somme de l'en-tête, du certificat de commit et du reçu les plus
grands de `spec/vecteurs/ct-6/registre/capture/`, relevés sur des blocs d'une
seule transaction, sans index, le bloc plein restant « non mesuré ». La mesure
TM-31 du plan de tests l'a faite le 2026-11-02 sur le réseau de développement
(`spec/vecteurs/ct-9/mesures/rapport-2026-11-02-capture-bloc-plein.json`) :
pour une transaction d'un bloc de 64 transactions, la capture que CT-4 EX-9.2
écrit compte 109 479 octets de réponses JSON-RPC et 14 282 octets d'index.
`b_cap` vaut désormais leur somme, 123 761 octets, plus de onze fois l'ancienne
valeur : la capture complète que le client conserve (tous les reçus du bloc et
l'index, EX-9.1), et non la forme à un seul reçu (39 544 octets dans le même
rapport), qui ne passe pas CT-4 CP-3 et ne permet pas l'export du dossier.
Sections touchées : en-tête et 0.4 (cette note) ; 0.2 (ligne TC-70, alignée sur
la révision 0.3 de CT-5 ; numéros « (l. N) » de la table recalculés) ; 8.3 (IC-1 : `D_lp`) ; 9.2 (EX-9.1, ligne `b_cap` de
la table et deux paragraphes qui la suivent) ; 9.3 (lecture de DM-11) ; 9.5
(texte d'introduction, sortie d'exemple, table des grandeurs, écarts avec CT-5
et poste dominant) ; 9.6 (table des cas) ; 14.1 (EX-14.2, point 3 : valeurs
recalculées) ; A.4 (variante de production : espace libre ; seuil du cas
`espace-insuffisant`) ; A.5 (seize cas ; relecture de la mesure de `b_cap`) ;
A.12 (EX-A.17 : `b_cap` relu dans le rapport de sa mesure) ; B.2 (A-E3). Les
formules DM-1 à DM-22, les schémas et les autres coefficients ne changent pas ;
aucun identifiant n'est ajouté ni retiré ; deux exigences sont modifiées :
EX-9.1 (forme que `b_cap` mesure, DOIT pour l'exploitant qui le remplace) et
EX-A.17 (relecture de `b_cap`). Vecteurs régénérés : `dimensionnement/` (les
treize cas valides ; les trois refus sont inchangés), `controle-prealable/`
(les seize cas du profil de production),
`acceptation-exploitation-attendu.json` et `INDEX.md` ; le vérificateur Go
indépendant lit la nouvelle table et relit le rapport de mesure. Elle
s'accompagne des révisions 0.5 de CT-4 (taille du certificat d'un bloc plein,
9.2, EX-9.7, B.1) et 0.3 de CT-5 (croissance des captures, EX-9.9, §12.4),
textuelles.

## 1. Objet, périmètre et relations

CT-8 dit comment NOORTRACE se déploie chez un client et s'exploite : quels
composants tournent où (section 3), sous quelle forme de conteneur (section 4),
avec quels flux réseau (section 5), sur quel hôte vérifié d'avance (section 6),
par quelles procédures pas à pas (sections 7 et 8), avec quelles ressources
(section 9) ; puis comment on le surveille et on réagit aux incidents (section
10), comment on le sauvegarde, le reprend, le met à jour et on trace les accès
à ses données (section 11), comment on l'essaie sans rien bloquer (section 12)
et comment un réviseur reçoit et vérifie ce qu'on lui remet (section 13). Les
sections 14 à 16 fixent les épreuves à l'aveugle, ce que la version ne couvre
pas et l'alignement avec le dépôt ; l'annexe A, les vecteurs, l'implémentation
et l'intégration continue ; l'annexe B, les sources datées.

Hors périmètre : le comportement de l'enregistreur (CT-2), du service
d'approbation (CT-3), du registre (CT-4) et de l'ancrage (CT-5), que CT-8
déploie sans le redéfinir, hors la révision du mode observation ; le
vérificateur (CT-6), que le paquet réviseur transporte sans le changer ; la
revue de sécurité, les clés et la cérémonie (CT-7), que CT-8 place dans la
procédure sans les réécrire ; l'exploitation de l'instance du registre par
l'exploitant NOORTRACE (validateurs, garde d'admission, publication du
manifeste d'instance), sauf ce qu'un client ou un partenaire en déploie chez lui
(relais, section 3) ; le plan de tests (CT-9) ; toute qualification juridique.

Dans la colonne « Ce que CT-8 en prend », les sections et les identifiants sont
ceux de la spécification de la ligne ; dans la dernière colonne, ceux de CT-8.

| Spécification | Ce que CT-8 en prend | Ce que CT-8 lui donne ou lui demande |
|---|---|---|
| CT-1 | Les formats v0 de l'événement (§5), du manifeste (§10) et du dossier (§11), JCS v0 (§4), les vérifications E-, C- et M-, les clés de test et le préfixe PKCS#8 (§13) | Aucun changement de format : le mode observation tient dans `policy.rule` et `policy.decision` `autorise` (12.3) ; le paquet réviseur transporte les dossiers octet pour octet (EX-13.3) |
| CT-2 | La configuration (§15), la surface d'écoute et la surface sortante exhaustives (EX-18.1, EX-18.2), la santé, les métriques et les alertes prescrites (§17), la disposition du stockage (§12), le bail (§13), les modes dégradés (§14), le support WORM et le gel (§12.6, §12.11), les commandes de `noortrace-ctl` | Les topologies, images, comptes, volumes, ports et secrets du démon (3, 4) ; la racine en lecture seule (CO-5) ; le compagnon des attributs (EX-3.9) ; la bascule d'adresse (EX-3.11) ; le cache d'écriture protégé (IP-13) ; les tâches planifiées (EX-8.6) ; les règles d'alerte (10.4) et les runbooks (10.11 à 10.19) ; la sauvegarde, la reprise et la migration (11) ; la révision 0.6 (mode observation, 12.9) ; les propositions PD-2 à PD-6, PD-10, PD-13 et PD-15 (16.2) |
| CT-3 | Le canal authentifié (§12.1), `evaluer` et `GET <base>/v0/etat` (§12, EX-12.12), la console et son serveur (§13), le mode `erreur` par défaut (EX-11.1) | L'image, le compte et les flux du service et du serveur de console (3, 5) ; leur supervision (10.7) ; la sauvegarde de l'état du service (EX-11.2, EX-11.4) ; la révision 0.4 (mode observation, 12.9) ; la proposition PD-7 |
| CT-4 | L'image et les drapeaux du nœud (§10), l'interdiction du relais pour la capture et la soumission (EX-10.5), l'interdiction de restaurer un validateur (EX-10.9), les alertes prescrites (EX-4.20, EX-8.3, EX-8.18, EX-9.4, EX-9.6, EX-10.8) | Le relais chez un client (EX-3.6) ; la capacité de l'instance pour un nombre de journaux (DM-20 à DM-22) ; les règles du registre (10.6) et le runbook RB-7 ; les propositions PD-12 et PD-16 |
| CT-5 | Les cadences et comptages (§4, §12), les alertes (§8.9), la file et sa reprise (§8), la rétention des pièces d'horodatage (EX-5.15), le fichier d'en-têtes (§6.5) | Le composant d'ancrage dans le démon (EX-3.2), ses flux (FL-17 à FL-21), son dimensionnement (9), les tâches TP-2 et TP-3, les règles (10.5) et les runbooks RB-3 et RB-4, la sauvegarde de la file (11.2) ; les propositions PD-11 et PD-12 |
| CT-6 | La ligne de commande, les codes et le rapport (§8), le fichier d'ancres du réviseur (§12), les archives publiées déterministes (EX-14.8) | Le vérificateur en conteneur sans réseau (EX-3.5) ; le paquet réviseur, qui transporte les dossiers et les fait vérifier chacun par le vérificateur de référence (13) ; la proposition PD-14 |
| CT-7 | L'inventaire des clés et des secrets (§4.2) et la conduite sur compromission (§4.6), la cérémonie (§5), l'attestation de périmètre (§7), les risques acceptés (RA-22, RA-57, RA-58), la proposition PA-15 | La construction reproductible et la publication des images (EX-3.13 à EX-3.15) ; la cérémonie placée dans l'installation (IC-7) ; l'attestation produite à l'installation (EX-5.7, EX-8.7) ; PA-15 (11.6, 11.9 à 11.11) ; le runbook RB-8, qui suit CT-7 §4.6 |
| CT-9 | Les mesures de la porte 2 | Les identifiants EX-, CO-, IP-, IR-, IC-, DM-, SV-, PV-, CA-, OB- et PR- ; les budgets de temps à chronométrer et les cibles à mesurer ; les vecteurs `spec/vecteurs/ct-8` ; les épreuves à l'aveugle (14) |

## 2. Terminologie

Les termes de CT-1 à CT-7 gardent leur sens ; CT-8 ajoute ceux-ci.

| Terme | Définition |
|---|---|
| Ancres du réviseur | Fichier d'ancres de confiance de CT-6 §12, écrit et contrôlé par le réviseur ; le paquet n'en porte qu'une copie remise par lui (EX-13.4). |
| Budget de temps | Durée cible d'un pas d'installation, à chronométrer par CT-9 ; la somme des budgets est la cible de la procédure. |
| Chemins de reprise A, B, C | A : restauration d'une archive complétée par les copies WORM ; B : reconstruction depuis les seules copies WORM ; C : journal neuf lié au registre (EX-11.6). |
| Cible | Valeur de conception non mesurée (0.1). |
| Contrôle préalable | Vérification exécutable d'un hôte avant l'installation (section 6) ; sa sortie est un rapport JSON au schéma `controle-prealable-v0`. |
| Description d'images | Le fichier `deploiement/images/images.json` (schéma `conteneurs-v0`) : pour chaque service de référence, son image, son étiquette exacte, son compte, ses volumes, ses ports, ses secrets admis et sa sonde. |
| Empreinte attendue | SHA-256 de l'archive que le réviseur reçoit par un autre canal que le paquet et passe par `--empreinte` (PR-2, EX-13.37). |
| Fichier Compose de référence | Fichier de `deploiement/compose/`, écrit pour la construction et vérifié statiquement (section 4) ; il n'est jamais lancé dans le dépôt. |
| Flux | Communication réseau ou locale d'un déploiement, identifiée par FL- (section 5). |
| Installation complète | Procédure de la section 8 : production, sur une machine vierge, en moins d'une journée. |
| Installation rapide | Procédure de la section 7 : un hôte, mode observation, au plus 15 minutes ; jamais une installation de production. |
| Journal des consultations et des accès | Fichiers chaînés `consultation-v0` qui consignent chaque accès au stockage de l'enregistreur, aux copies WORM, aux exports et au coffre des originaux (11.10). |
| Machine vierge | Hôte Linux dont le système vient d'être installé, sans moteur de conteneurs ni composant NOORTRACE. |
| Marque d'observation | Suffixe ` [observation <x>]` de `policy.rule` d'un appel scellé en mode observation, où `<x>` est la décision que la politique aurait rendue (`autorise`, `a_approuver`, `refuse`) ou `inconnu` (EX-12.6, CT-3 EX-6.8). |
| Mode bloquant | Mode `erreur` ou `retenir` de CT-3 §11 : la politique d'approbation est appliquée, un appel peut être refusé ou soumis à approbation. |
| Mode observation | Mode de l'ensemble de politique (`policy.approval.mode: "observation"`, CT-2 révision 0.6) où tout est capturé et journalisé comme en mode bloquant, où la politique d'approbation est évaluée sans être appliquée et où aucune panne ne bloque un appel relayable (section 12). |
| Paquet | Forme sous laquelle un composant est livré : image de conteneur, binaire, archive de déploiement (EX-3.6). Le paquet réviseur (section 13) est autre chose. |
| Paquet complet, paquet allégé | Paquet qui porte, ou ne porte pas, le vérificateur sous `verificateur/` (EX-13.8). |
| Paquet d'incident | Pièces d'un incident (chronologie, alertes, sorties des portes, procès-verbaux, rapports), rangées avec le journal et copiées sur le support WORM, sans pièce, secret ni argument (EX-10.15). |
| Paquet intact | Paquet dont les vérifications PR-1 à PR-9 ont réussi : ses fichiers sont ceux que son manifeste décrit, dans une archive de forme canonique (13.10). |
| Paquet réviseur | Archive tar ustar déterministe que l'exploitant du client remet à un réviseur : dossiers demandés, fichier d'ancres du réviseur, en-têtes Bitcoin, attestation et pièces publiées s'il y a lieu, instructions, vérificateur pour un paquet complet, et le manifeste `MANIFESTE.json` qui les décrit (section 13). |
| Pont stdio | Conteneur qui sert un serveur d'outils stdio en Streamable HTTP à l'enregistreur, un conteneur par serveur (EX-3.7). |
| Porte | Vérification qui doit réussir avant de passer au pas suivant d'un runbook ou d'une reprise (EX-10.14). |
| Procès-verbal d'exploitation | Document `proces-verbal-exploitation-v0` d'un acte d'exploitation sur un journal : sauvegarde, restauration, exercice de restauration, migration de support, fin de rétention, passage de mode (11.9). |
| Procès-verbal d'installation | Répertoire de l'exploitant où chaque pas de l'installation complète dépose sa sortie et son SHA-256 (EX-8.3). |
| Rapport d'observation | Décompte, version de politique par version, règle par règle et décision par décision, de ce que la politique aurait exigé pendant une suite d'événements (`rapport-observation-v0`, 12.5). |
| Relecture hors du composant | Contrôle exécuté sous une identité distincte du composant contrôlé, dont le résultat est une jauge alertée (EX-10.9). |
| RPO, RTO | Objectif de point de reprise et objectif de durée de reprise, au sens du NIST SP 800-34 Rev. 1 (11.3, R9-F36). |
| Runbook | Procédure écrite pour un incident, de forme fixe : détection, impact sur la preuve, invariants, pas avec leur porte, vérification de sortie, événements journalisés, après l'incident (EX-10.13). |
| Topologie | Lieu et forme du déploiement chez le client : sur site, tenant cloud du client, hébergeur suisse (section 3). |

## 3. Topologies et paquets

### 3.1 Composants, et ce qui reste chez le client

Les composants sont ceux de CT-7 §3.2, nommés par leur identifiant ; la colonne
« Service » est le nom du service dans les fichiers Compose de référence
(section 4).

| Composant (CT-7 §3.2) | Service | Paquet (EX-3.6) | Où il tourne | Ce qu'il détient |
|---|---|---|---|---|
| `mandataire_mcp`, `passerelle_modele` (avec le raccord ICAP), `sdk_otel`, `ecrivain_stockage` | `enregistreur` | image `noortrace/enregistreur` | chez le client, un démon par journal (CT-2 §3.4) | segments, pièces, journal d'intention, journal d'exploitation, bail, identifiants vers les serveurs d'outils et les fournisseurs |
| `ancrage` | dans `enregistreur` (EX-3.2) | même image | chez le client | file, identifiants des prestataires (CT-7 CLE-11), jetons et preuves |
| `worm_gel` | support du client ; service `attributs` pour les attributs locaux (EX-3.9) | image `noortrace/attributs` | support : chez le client ou chez son fournisseur de stockage ; `attributs` : sur l'hôte de l'enregistreur | copies verrouillées, registre des gels |
| `cles` | signataire du client (CT-2 §11) | module, service ou fichier selon la classe | chez le client | CLE-1, CLE-2 et les secrets de service de CT-7 §4.2 |
| `approbation_console` | `approbation`, `console` | images `noortrace/approbation`, `noortrace/console` | chez le client (EX-3.3) | politique, tickets, annuaire, identifiants du canal |
| `registre` (côté client) | `relais` (facultatif) | image `noortrace/noorcore` de `chain/docker/` | chez le client, pour ses applications seulement (EX-3.6) | rien d'autre qu'un relais JSON-RPC (CT-4 §10.3) |
| `verificateur` | `verificateur` | image `noortrace/verificateur` et binaire `noortrace-verifier` | n'importe où, sans réseau | rien |
| serveurs d'outils stdio | `pont-<alias>` (EX-3.7) | image `noortrace/pont-stdio` | chez le client | le serveur d'outils et ses données |

**EX-3.1** **Ce qui sort du périmètre du client.** Dans les trois topologies,
seuls les objets de la table suivante quittent le périmètre du client, et
seulement vers les destinations nommées ; le contenu du journal (événements,
pièces, segments, journal d'exploitation, tickets, annuaire) n'en sort jamais
par NOORTRACE. Le trafic que l'agent échange avec ses fournisseurs de modèle et
ses serveurs d'outils est celui du client : la passerelle le relaie (FL-8), elle
ne l'envoie nulle part ailleurs (CT-2 EX-18.2).

| Ce qui sort | Vers | Flux | Source |
|---|---|---|---|
| `org_id`, `journal_id`, clés publiques Ed25519 et clés de chaîne, empreintes d'ancre `keccak256(org_id ‖ journal_id ‖ periodHash)` et des points, champs de clôture, adresses et signatures d'approbateurs | registre (validateurs par leur garde d'admission) | FL-19 | CT-7 §8.6 ; CT-4 §6.5 |
| Requête `TimeStampReq` qui porte `periodHash` ou `checkpointHash` | prestataires RFC 3161 | FL-17 | CT-5 §5.1 ; CT-7 §8.6 |
| Engagement masqué par un nonce | calendriers OpenTimestamps | FL-18 | CT-5 §6.2 |
| Rien de NOORTRACE (requêtes de lecture de certificats et de reçus seulement) | relais vers le meneur | FL-22 | CT-4 §10.3 |

**EX-3.2** **Composant d'ancrage.** En version 0.1, le composant d'ancrage de
CT-5 s'exécute dans le démon de l'enregistreur, comme un fil distinct (CT-5
EX-8.1 admet « fil ou processus distinct »), désigné par `anchoring.ancrage`
(CT-2 §15.1) et configuré par le document `ancrage-v0` monté en lecture seule
(`/etc/noortrace/ancrage.json`). Il n'a donc ni image, ni compte, ni volume
propres ; ses flux sortants (FL-17 à FL-21) partent du service `enregistreur`.
Un processus distinct est admis par CT-5 mais n'est pas décrit par la version
0.1 (section 15).

**EX-3.3** **Service d'approbation et console.** Le service d'approbation (CT-3
§12) et le serveur de la console (CT-3 §13) tournent dans le périmètre du
client, dans les trois topologies : le service reçoit les arguments en clair
(CT-2 §3.2, pas 3) et la console les affiche à l'approbateur. Le serveur de
console authentifie les personnes par le système d'identité du client (CT-3
§13.3 : identité de session `oidc <iss> <sub>` ou `utilisateur <domaine> <nom>`,
flux FL-16) ; la page servie est celle d'une version publiée, dont les
empreintes sont publiées hors du serveur (CT-7 EX-3.9, EX-3.14 ci-dessous). Le
service et la console ne sont jamais exploités par l'exploitant NOORTRACE pour
le compte de plusieurs clients en version 0.1.

### 3.2 Les trois topologies

| | Sur site | Tenant cloud du client | Hébergeur suisse |
|---|---|---|---|
| Hôtes | Machines du client (physiques ou virtuelles), Linux | Machines virtuelles du tenant du client ; un orchestrateur de conteneurs est admis sous les conditions d'EX-3.10 | Environnement dédié au client chez un hébergeur en Suisse, exploité par le client ou pour son compte (CT-7 §8.6 : l'hébergeur est alors un sous-traitant du client, clause CT-7 CL-4) |
| Fichiers de référence | `deploiement/compose/production.yaml` | le même ; l'adaptation à un orchestrateur garde les exigences de la section 4 | le même |
| Stockage du journal | Disque local ou volume bloc attaché (CT-2 EX-12.2), cache d'écriture protégé (IP-13) | Volume bloc du fournisseur, attaché à un seul hôte (EX-3.10) | Volume bloc de l'hébergeur, même règle |
| Support WORM (CT-2 §12.6) | Stockage objet du client à verrouillage d'objets en mode conformité, ou celui d'un fournisseur | Verrouillage natif du fournisseur (`s3-object-lock`, `azure-immutable-blob`) ; `gcs-object-retention` refusé en production (CT-2 EX-12.30) | Service compatible S3 de l'hébergeur dont le mode conformité est **à valider** auprès de lui (CT-2 §12.6) ; à défaut, gel posé à chaque clôture (TP-1) |
| Clé de l'enregistreur (CT-7 CLE-1) | Classe A (module matériel) ou B (service de signature) recommandées, C admise | Classe B (service de signature du fournisseur) ou C (enveloppe) | Classe A chez l'hébergeur s'il l'offre, sinon B ou C |
| Bail (CT-2 §13.2) | `file` sur un hôte ; `postgresql` ou `etcd` pour deux instances | `postgresql` géré | `postgresql` |
| Registre | Point RPC d'un validateur par sa garde d'admission (CT-4 EX-10.8) ; validateur du client s'il en opère un (CT-4 §10.2) | idem | idem |
| Ce qui reste chez le client | Tout, sauf la table d'EX-3.1 | idem | idem ; l'hébergeur voit ce que le client lui confie, ce que le contrat règle (CT-7 CL-4, CL-6) |

**EX-3.4** **Choix de la topologie.** L'exploitant DOIT consigner, au premier
pas de l'installation complète (IC-1), la topologie retenue, le type de support
WORM, la classe de garde de CLE-1 et de CLE-2 et le magasin de bail ; en
production, un support dont le mode conformité n'est pas validé (topologie
« hébergeur suisse » en particulier) DOIT recevoir la tâche TP-1 (gel posé à
chaque clôture, CT-2 §12.6) tant que la validation manque.

### 3.3 Paquets et images

**EX-3.5** **Comptes, volumes, ports et secrets.** Chaque service tourne sous le
compte, avec les volumes, les ports et les secrets que décrit
`deploiement/images/images.json` (4.1) ; la table suivante en est la lecture.
Les ports sont ceux de l'exemple complet de CT-2 §15.3 (8300, 8400, 4318, 8500),
du raccord ICAP de CT-2 §19.6 (1344) et de l'image du nœud (CT-4 §10.4) ;
8600, 8601 et 8700 sont fixés par CT-8. Le compte est numérique, jamais 0, sauf
pour `attributs` (EX-3.9). Le démon ne peut écrire que dans `storage.root`, le
journal d'exploitation, le répertoire des prises (CT-2 EX-18.4) et son
répertoire temporaire en mémoire `/run/temporaire` (tmpfs borné, désigné par la
variable `TMPDIR`) : ce sont ses seuls volumes inscriptibles. Le relais n'a pas
de répertoire temporaire : le suiveur tourne en lecture seule sans lui (R8-F33).

Le volume des prises (`/run/noortrace`) est partagé par `enregistreur`, qui y
crée `mcp.sock` (FL-1), et `approbation`, qui y crée `approbation.sock` : les
deux services reçoivent le groupe supplémentaire `10010` (`noortrace-prises`,
clé `group_add`, CO-4), et leurs deux images DOIVENT créer `/run/noortrace` avec
le groupe 10010 et le mode `2770`, pour que la racine d'un volume neuf soit
inscriptible par les deux comptes quel que soit le premier conteneur qui le
monte (non vérifié : la recopie du propriétaire et du mode du répertoire de
l'image dans un volume nommé neuf est à éprouver à la construction, CT-9, porte
2). Un hôte d'agent de la même machine joint `mcp.sock` par un montage lié d'un
répertoire de l'hôte à la place du volume nommé, en mode `0750` et de groupe
celui des hôtes ; ce montage est une adaptation du client, que CO-11 refuse tant
que sa source n'est pas ajoutée à la description.

| Service | Compte (UID:GID) | Volumes (cible, accès) | Ports (dans le conteneur) | Secrets admis (motifs, CT-7 §4.2) |
|---|---|---|---|---|
| `enregistreur` | `10001:10001` (`noortrace`), groupe supplémentaire `10010` | `/var/lib/noortrace` rw (`storage.root`, volume exclusif, EX-3.10) ; `/var/log/noortrace` rw ; `/run/noortrace` rw (prises) ; `/var/lib/noortrace-exports` rw ; configuration et `ancrage.json` ro | 8300 MCP, 8400 passerelle, 1344 ICAP, 4318 OTLP, 8500 santé et métriques | `cle-enregistreur` (classe D, développement), `acces-signataire` (CLE-21), `cle-chaine` (CLE-2), `cle-mac-relais` (CLE-16), `dsn-bail` (CLE-19), `worm-ecrivain` (CLE-20, écrivain seul), `jeton-hote-*`, `jeton-passerelle` (CLE-14), `cle-fournisseur-*` (CLE-13), `tsa-*` (CLE-11), `bitcoin-rpc` (CLE-12), `tls-enregistreur` (CLE-24), `cle-pseudonymisation` (CLE-17), `cle-coffre` (CLE-18) |
| `attributs` | `0:0` | `/var/lib/noortrace` rw | aucun ; aucun réseau | aucun |
| `approbation` | `10002:10002` (`noortrace-approbation`), groupe supplémentaire `10010` | `/var/lib/noortrace-approbation` rw (tickets, annuaire) ; `/run/noortrace` rw (sa prise) ; configuration ro | 8600 canal de la console, sur le réseau interne `console` seulement ; 8601 état (`GET /v0/etat`, sans donnée de ticket), publié sur `127.0.0.1` de l'hôte en production pour la sonde (10.2) | `jeton-console-vers-service-approbation`, `jeton-noyau-vers-service` (CLE-23), `rpc-registre`, `notification-*`, `tls-approbation` (CLE-24) |
| `console` | `10003:10003` | configuration ro | 8700 HTTPS | `jeton-console-vers-service-console` (CLE-23), `oidc-client`, `tls-console` (CLE-24) |
| `pont-<alias>` | un compte par serveur, à partir de `10101:10101` | les données du serveur d'outils, et rien du journal | port interne du pont, réseau `outils` seulement | `jeton-pont-<alias>` (CLE-15) |
| `relais` | `65532:65532` (image de `chain/docker/`) | `/var/lib/noorcore` rw | 8545, 8080, 9090 publiés sur `127.0.0.1` | aucun dans le conteneur ; jeton de la garde côté applications |
| `verificateur` | `10005:10005` | `/var/lib/noortrace-exports` ro | aucun ; aucun réseau | aucun |

Le compte d'un secret monté depuis un fichier n'est pas réécrit par Compose
(« The `uid`, `gid`, and `mode` attributes are not implemented in Docker Compose
when the secret source of the secret is a `file` », R9-F25) : le fichier de
l'hôte DOIT donc appartenir déjà au compte du service qui le lit et être en mode
`0400` (CT-2 EX-15.3), ce que vérifie IP-10. Un fichier n'ayant qu'un
propriétaire, un même secret n'est jamais reçu par deux services de comptes
différents (CO-9, IP-10 : `secret_partage_entre_comptes`) : le jeton du canal de
la console (CLE-23) existe en deux fichiers de même contenu,
`jeton-console-vers-service-approbation` (compte 10002) et
`jeton-console-vers-service-console` (compte 10003). L'image de l'enregistreur
DOIT nommer dans son `/etc/passwd` les comptes `noortrace` (10001) et
`noortrace-approbation` (10002), parce que CT-2 authentifie le service par le
nom d'utilisateur du pair (`peer_user`, CT-2 EX-18.8) ; celle du service,
`noortrace` (10001), pour la même raison dans l'autre sens.

**EX-3.6** **Paquets.** Un déploiement emploie les paquets suivants, chacun
désigné par une version exacte et, en production, par son condensé ou son
SHA-256 publié (EX-3.14) :

| Paquet | Contenu | État au 2026-10-27 |
|---|---|---|
| `noortrace/enregistreur` | démon `noortrace` (CT-2), outil `noortrace-ctl`, composant d'ancrage (EX-3.2) | à construire (phase 2) |
| `noortrace/approbation` | service d'approbation (CT-3 §12) | à construire |
| `noortrace/console` | serveur de console et page de référence de `console/` (CT-3 §13) | à construire |
| `noortrace/attributs` | compagnon des attributs `a` et `i` (EX-3.9) | à construire |
| `noortrace/pont-stdio` | pont stdio vers Streamable HTTP (EX-3.7) | à construire |
| `noortrace/verificateur` et binaire `noortrace-verifier` | vérificateur (CT-6 §8) | l'implémentation de référence `scripts/verify/dossier.mjs` existe ; le binaire et l'image sont à construire |
| `noortrace/noorcore` | nœud noorcore de l'instance, image de `chain/docker/Dockerfile` (CT-4 §10.1) | construite sans correctif le 2026-10-21, 67,5 Mo, `User=65532:65532` (R8-F34) ; avec correctif, construction non rejouée (R8 NV-1) |
| `noortrace-connecteur` | connecteur stdio des hôtes (CT-2 §3.4) ; un paquet d'extension de bureau `.mcpb` (CT-2 §19.5.1) le portera en phase 2, son format n'étant pas relu par CT-8 (non vérifié) | à construire |
| Archive de déploiement `noortrace-deploiement-<version>.tar` | les fichiers que rend `fichiersArchive` (`scripts/lib/deploiement.mjs`), écrits par `scripts/deploiement/construire-archive.mjs --sortie <répertoire>` avec leur liste `SHA256SUMS` : `deploiement/` (fichiers Compose, description d'images, configurations de référence, `LISEZMOI.md`) ; les outils de `scripts/deploiement/` qui s'exécutent sur l'hôte (`configurer-rapide`, `controle-prealable`, `dimensionner`, `verifier-conteneurs`, `verifier-journal`, `rapport-observation`, `proces-verbal`, `consultations`) ; les bibliothèques de `scripts/lib/` qu'ils importent ; les schémas de `spec/schemas/` ; la liste des clés de test de CT-7 (`spec/vecteurs/ct-7/cles-de-test.json`, pour CT-2 EX-15.8) ; `LICENSE`, `NOTICE` ; une copie figée de la distribution ESM d'`ethers` et de `js-yaml` sous `node_modules/`. Elle s'exécute avec Node.js 22 sans npm ni réseau (test de l'annexe A.12). Archive déterministe (même recette que le paquet réviseur, section 13) | contenu écrit et éprouvé depuis le dépôt ; archive `.tar` publiée : à construire (phase 2) |

L'image du nœud est reprise telle quelle pour le **relais** d'un client
(`chain/docker/docker-compose.yml`, R8-F33) : suiveur `-role follower`,
conteneur en lecture seule, toutes capacités retirées, `no-new-privileges`
(R8-F33). Un relais NE DOIT servir ni à une capture ni à la soumission d'une
ancre ou d'une clôture (CT-4 EX-10.5) : le composant d'ancrage soumet au point
RPC d'un validateur, par sa garde d'admission (FL-19) ; la supervision du relais
sonde `eth_blockNumber` à travers lui, pas `/healthz`, qui répond `ok` meneur
arrêté (CT-4 EX-10.5 ; R8-F35). L'épinglage de ses deux images de base par
condensé (CT-4 EX-10.1, « à faire » en CT-4 §13) reste à faire dans
`chain/docker/Dockerfile` (R9-F34) : le fichier Compose de référence désigne
donc l'image par son étiquette exacte `618fcef-noortrace` (R9-F34), et la
production par son condensé publié (IC-6).

Les pas des sections 7 et 8 s'exécutent depuis le répertoire `deploiement/` de
l'archive extraite, sur l'hôte, avec les outils de l'archive. Trois pas
emploient des outils qui ne sont pas dans l'archive 0.1 : la cérémonie de
CT-7 (`npm run verify:ceremonie`, IC-7), la validation de `ancrage.json` (IC-13)
et l'attestation de périmètre (`npm run conformite:attestation`, IC-17) ; ils
s'exécutent sur le poste de l'exploitant, avec une copie du dépôt public à la
version publiée et `npm ci` fait (EX-8.2), jamais sur un hôte NOORTRACE. Le
script de préparation de l'hôte d'IC-2 est à écrire (phase 2) et absent de
l'archive 0.1.

### 3.4 Serveurs d'outils stdio en conteneur

Le démon lance un serveur stdio sous un utilisateur distinct « par un auxiliaire
privilégié minimal (`setuid`/`setgid`) […] ou par l'orchestrateur (un conteneur
par serveur, CT-8) » (CT-2 EX-3.5). Dans un conteneur dont toutes les capacités
sont retirées (CO-6), l'auxiliaire ne peut pas changer d'utilisateur ; CT-8
retient donc le conteneur par serveur.

**EX-3.7** **Pont stdio.** Dans un déploiement en conteneurs, chaque serveur
d'outils stdio DOIT tourner dans son propre conteneur `pont-<alias>`, sous un
compte qui lui est propre et distinct de celui du démon (CT-2 EX-3.5), attaché
au seul réseau interne `outils`, sans aucun volume du journal ni secret du
démon. Le pont lance la commande du serveur comme enfant et la sert en
Streamable HTTP à l'enregistreur, qui le déclare comme un serveur `http`
(`policy.servers.<alias>.transport.type = "http"`, CT-2 §15) avec un jeton
statique propre (`jeton-pont-<alias>`). Aucun autre conteneur que l'enregistreur
ne joint le pont (réseau `outils` interne, CO-14).

**EX-3.8** **Épinglage du serveur ponté.** La validation de CT-2 exige en
production l'empreinte de l'exécutable d'un serveur stdio
(`transport.integrity`, CT-2 EX-3.5) ; un serveur ponté étant déclaré en `http`,
cette vérification ne s'applique plus : l'épinglage passe par l'image du pont et
du serveur, désignée par son condensé (CO-2, IP-12), et par la commande exacte,
écrite dans le fichier Compose dont le SHA-256 est consigné au procès-verbal
d'installation (EX-8.3). Ce que le démon ne voit plus du serveur ponté : la
sortie d'erreur de l'enfant (`child_stderr`, CT-2 §17.3), qui reste dans les
journaux du conteneur du pont. Un transport stdio par prise locale, qui
garderait la vérification d'`integrity` par le démon, est proposé à CT-2 (PD-4).

**EX-3.9** **Compagnon des attributs.** Quand
`storage.seal.append_only_attribute` est vrai, le service `attributs` pose
l'attribut `a` sur le segment courant et le journal d'intention et `i` sur
chaque segment fermé et chaque manifeste (CT-2 EX-12.18), toutes les 60 secondes
au plus (cible, à mesurer (CT-9, porte 2)). Il est le seul service admis sous le
compte 0, avec exactement les capacités `LINUX_IMMUTABLE`, `FOWNER` et
`DAC_READ_SEARCH`, sans réseau (`network_mode: none`), et le démon n'a jamais
`CAP_LINUX_IMMUTABLE` (CT-2 EX-18.4). Motif des capacités : seul un processus
privilégié (`CAP_LINUX_IMMUTABLE`) pose ou retire `a` et `i`, et changer les
attributs d'un fichier exige d'en être propriétaire ou d'avoir `CAP_FOWNER`
(page de manuel `ioctl_iflags(2)`, lue le 2026-10-27, annexe B) ;
`DAC_READ_SEARCH` lui permet d'ouvrir des fichiers en `0400` qui appartiennent
au démon (non vérifié : le besoin d'ouvrir le fichier en lecture est déduit, à
éprouver à la construction, CT-9). Le compagnon peut, par `CAP_FOWNER`, changer
les droits d'un fichier : c'est un composant de confiance, minimal, dont l'image
est publiée et épinglée comme les autres.

### 3.5 Haute disponibilité et bascule

**EX-3.10** **Un seul écrivain par volume.** Le volume de `storage.root` d'un
journal DOIT être attaché à un seul hôte et monté par un seul service
`enregistreur` à la fois (CT-2 EX-13.2) : dans un fichier Compose, un seul
service le monte en écriture, plus `attributs` ; sous un orchestrateur, le
volume est réservé à un seul pod (`ReadWriteOncePod`, CT-2 EX-13.2). Le magasin
de bail (CT-2 §13.2) protège en plus contre un second processus.

**EX-3.11** **Bascule d'adresse.** Quand une instance passive reprend un journal
(CT-2 §13.4), l'adresse par laquelle les hôtes joignent l'enregistreur (adresse
virtuelle, nom DNS ou répartiteur) DOIT être basculée vers la nouvelle instance
seulement après que celle-ci répond `200` à `GET /readyz` (bail détenu, frontaux
à l'écoute, CT-2 EX-17.1), et jamais vers une instance qui répond `standby` à
`/healthz`. Un répartiteur DOIT sonder `/readyz` et non `/healthz`. Avec un nom
DNS, sa durée de vie est au plus de 30 secondes (cible, à mesurer (CT-9, porte
2)) ; MCP n'ayant pas de redirection (CT-2 §13.4), un hôte se reconnecte.

**EX-3.12** **Perte du segment ouvert.** Un client qui n'admet pas de perdre les
événements du segment ouvert d'une instance perdue avec son disque (CT-2 §13.5)
DOIT placer `storage.root` sur un volume bloc répliqué de façon synchrone sur un
second site ; le contrôle préalable ne le vérifie pas (déclaratif, consigné à
IC-1).

### 3.6 Construction reproductible et publication

**EX-3.13** **Construction reproductible.** Chaque image `noortrace/*` DOIT être
construite : avec ses images de base épinglées par condensé (`FROM …@sha256:…`,
R9-F30) ; avec l'heure des fichiers fixée à la date du commit
(`SOURCE_DATE_EPOCH`, R9-F11 ; même règle que les archives publiées de CT-6
EX-14.8, R9-F55) ; deux fois, par deux constructeurs indépendants, et les deux
condensés DOIVENT être égaux avant publication. Le même procédé vaut pour le
binaire `noortrace-verifier` et pour la page et les scripts de la console (CT-3
EX-13.4). L'égalité des deux constructions est une mesure de CT-9 (porte 2) ;
aucune image n'étant construite au 2026-10-27, aucune n'est revendiquée.

**EX-3.14** **Publication.** Pour chaque version, l'exploitant NOORTRACE DOIT
publier hors des serveurs qui servent les images et la console (note de version
et dépôt public) : le condensé de chaque image, le SHA-256 du binaire du
vérificateur, le SHA-256 du document de la console et de chaque script qu'elle
charge (CT-7 EX-3.9), le SHA-256 de l'archive de déploiement (EX-3.6), la liste
`SHA256SUMS` signée des fichiers du vérificateur du paquet réviseur (EX-13.20),
le commit, et une attestation de provenance de la construction (CT-2 EX-18.6).
Aucune version n'étant publiée au 2026-10-27, aucune de ces valeurs n'existe
encore : les pas qui les comparent (IR-1, IC-4, instructions de 13.11) ne
s'exécutent qu'à partir de la première version publiée. La comparaison
quotidienne des empreintes de la console par une supervision qui n'est pas
hébergée sur son serveur (CT-7 EX-3.9) est la tâche TP-5 (EX-8.6).

**EX-3.15** **Exécution.** En production, l'administrateur du client DOIT
n'exécuter que des images désignées par un condensé publié (CT-7 EX-3.14) : le
fichier Compose de production porte `@sha256:` pour chaque image (IP-12) ;
l'empreinte de l'image en cours DEVRAIT être consignée au démarrage (proposition
PA-4 de CT-7 à CT-2). Ce que la construction reproductible détecte : une image
publiée qui ne correspond pas au code publié. Ce qu'elle ne détecte pas : un
code publié malveillant ; c'est la revue de code de CT-9 et le risque RA-22 de
CT-7.

## 4. Fichiers de conteneur de référence

### 4.1 Disposition

**EX-4.1** Le dépôt public contient, sous `deploiement/` :

| Fichier | Contenu |
|---|---|
| `deploiement/LISEZMOI.md` | Ce que les fichiers sont, qu'ils ne sont jamais lancés dans le dépôt, comment les vérifier (`npm run deploiement:conteneurs`) |
| `deploiement/compose/rapide.yaml` | Installation rapide (section 7) : `enregistreur`, `approbation`, `verificateur` (profil `outils`) |
| `deploiement/compose/production.yaml` | Installation complète (section 8) : `enregistreur`, `attributs`, `approbation`, `console`, `pont-fichiers` (exemple d'un serveur stdio ponté), `relais` (profil `relais`), `verificateur` (profil `outils`) |
| `deploiement/images/images.json` | Description des services et de leurs images, schéma `conteneurs-v0` (exemple complet ci-dessous) |
| `deploiement/config/rapide/configuration.json` | Configuration de l'enregistreur de l'installation rapide (7.3), valide contre `configuration-enregistreur-v0` |
| `deploiement/config/modele-production/configuration.json` | Modèle de la configuration de l'enregistreur de production (8.3, table des écarts avec CT-2 §15.3), valide contre `configuration-enregistreur-v0` ; chaque secret y est lu dans `/run/secrets/<nom>` d'un secret que `production.yaml` monte dans `enregistreur` (test de l'annexe A.12) |

Le répertoire `secrets/` n'existe jamais dans le dépôt : il est créé à
l'installation (IR-2, IC-8). Les fichiers de configuration de production
(`config/production/`) sont écrits par l'exploitant à l'installation (IC-14),
à partir du modèle ci-dessus pour l'enregistreur ; leur forme est celle de CT-2
§15.3 et de CT-5 §4.4, avec les écarts de 8.3.

La description des images, complète :

<!-- schema: conteneurs -->
```json
{
  "version": 0,
  "description": "Descriptions des images et des services de référence de NOORTRACE (CT-8 §3 et §4). Une image noortrace/* de statut a_construire n'existe pas encore : sa description est l'exigence que la construction (phase 2) doit tenir. Les vérifications CO-1 à CO-14 confrontent chaque fichier Compose de deploiement/compose/ à ces descriptions.",
  "services": {
    "enregistreur": {
      "image": "noortrace/enregistreur",
      "tag": "0.1.0",
      "status": "a_construire",
      "kind": "service",
      "source": "CT-2 (démon : mandataire MCP, passerelle du modèle et raccord ICAP, points d'entrée SDK et OpenTelemetry, écrivain, stockage, bail, clôture, exportateur, composant d'ancrage de CT-5 en fil distinct)",
      "user": "10001:10001",
      "passwd": [
        {
          "name": "noortrace",
          "uid": 10001
        },
        {
          "name": "noortrace-approbation",
          "uid": 10002
        }
      ],
      "group_add": [
        "10010"
      ],
      "cap_add": [],
      "network_mode": null,
      "networks": [
        "hotes",
        "outils",
        "sortie"
      ],
      "ports": [
        8300,
        8400,
        1344,
        4318,
        8500
      ],
      "volumes": [
        {
          "target": "/var/lib/noortrace",
          "access": "rw"
        },
        {
          "target": "/var/log/noortrace",
          "access": "rw"
        },
        {
          "target": "/run/noortrace",
          "access": "rw"
        },
        {
          "target": "/var/lib/noortrace-exports",
          "access": "rw"
        },
        {
          "target": "/etc/noortrace/configuration.json",
          "access": "ro"
        },
        {
          "target": "/etc/noortrace/ancrage.json",
          "access": "ro"
        }
      ],
      "tmpfs": "/run/temporaire",
      "environment": [
        "TMPDIR"
      ],
      "bind_sources": [
        "./config/"
      ],
      "secrets": [
        "^cle-enregistreur$",
        "^cle-mac-relais$",
        "^acces-signataire$",
        "^cle-chaine$",
        "^dsn-bail$",
        "^worm-ecrivain$",
        "^jeton-hote(-[a-z0-9-]+)?$",
        "^jeton-passerelle$",
        "^cle-fournisseur-[a-z0-9-]+$",
        "^tsa-[a-z0-9-]+$",
        "^tls-enregistreur-(certificat|cle)$",
        "^bitcoin-rpc$",
        "^cle-pseudonymisation$",
        "^cle-coffre$",
        "^identifiant-outil-[a-z0-9-]+$",
        "^oauth-[a-z0-9-]+$"
      ],
      "probe": {
        "type": "commande",
        "test": [
          "CMD",
          "/usr/local/bin/noortrace-ctl",
          "sonde",
          "--url",
          "http://127.0.0.1:8500/readyz"
        ]
      }
    },
    "attributs": {
      "image": "noortrace/attributs",
      "tag": "0.1.0",
      "status": "a_construire",
      "kind": "service",
      "source": "CT-2 EX-12.18 : service compagnon qui pose les attributs a et i ; seul service admis sous l'utilisateur 0, avec trois capacités nommées",
      "user": "0:0",
      "passwd": [],
      "group_add": [],
      "cap_add": [
        "LINUX_IMMUTABLE",
        "FOWNER",
        "DAC_READ_SEARCH"
      ],
      "network_mode": "none",
      "networks": [],
      "ports": [],
      "volumes": [
        {
          "target": "/var/lib/noortrace",
          "access": "rw"
        }
      ],
      "tmpfs": "/run/temporaire",
      "environment": [
        "TMPDIR"
      ],
      "bind_sources": [],
      "secrets": [],
      "probe": {
        "type": "commande",
        "test": [
          "CMD",
          "/usr/local/bin/noortrace-attributs",
          "sonde"
        ]
      }
    },
    "approbation": {
      "image": "noortrace/approbation",
      "tag": "0.1.0",
      "status": "a_construire",
      "kind": "service",
      "source": "CT-3 §12 (service d'approbation)",
      "user": "10002:10002",
      "passwd": [
        {
          "name": "noortrace-approbation",
          "uid": 10002
        },
        {
          "name": "noortrace",
          "uid": 10001
        }
      ],
      "group_add": [
        "10010"
      ],
      "cap_add": [],
      "network_mode": null,
      "networks": [
        "console",
        "sortie"
      ],
      "ports": [
        8601
      ],
      "volumes": [
        {
          "target": "/var/lib/noortrace-approbation",
          "access": "rw"
        },
        {
          "target": "/run/noortrace",
          "access": "rw"
        },
        {
          "target": "/etc/noortrace-approbation/configuration.json",
          "access": "ro"
        }
      ],
      "tmpfs": "/run/temporaire",
      "environment": [
        "TMPDIR"
      ],
      "bind_sources": [
        "./config/"
      ],
      "secrets": [
        "^jeton-console-vers-service-approbation$",
        "^jeton-noyau-vers-service$",
        "^rpc-registre$",
        "^notification-[a-z0-9-]+$",
        "^tls-approbation$"
      ],
      "probe": {
        "type": "commande",
        "test": [
          "CMD",
          "/usr/local/bin/noortrace-approbation",
          "sonde",
          "--url",
          "http://127.0.0.1:8601/v0/etat"
        ]
      }
    },
    "console": {
      "image": "noortrace/console",
      "tag": "0.1.0",
      "status": "a_construire",
      "kind": "service",
      "source": "CT-3 §13 (serveur de console et page de référence de console/)",
      "user": "10003:10003",
      "passwd": [
        {
          "name": "noortrace-console",
          "uid": 10003
        }
      ],
      "group_add": [],
      "cap_add": [],
      "network_mode": null,
      "networks": [
        "console",
        "sortie"
      ],
      "ports": [
        8700
      ],
      "volumes": [
        {
          "target": "/etc/noortrace-console/configuration.json",
          "access": "ro"
        }
      ],
      "tmpfs": "/run/temporaire",
      "environment": [
        "TMPDIR"
      ],
      "bind_sources": [
        "./config/"
      ],
      "secrets": [
        "^jeton-console-vers-service-console$",
        "^oidc-client$",
        "^tls-console$"
      ],
      "probe": {
        "type": "commande",
        "test": [
          "CMD",
          "/usr/local/bin/noortrace-console",
          "sonde"
        ]
      }
    },
    "pont-fichiers": {
      "image": "noortrace/pont-stdio",
      "tag": "0.1.0",
      "status": "a_construire",
      "kind": "service",
      "source": "CT-8 §3.4 : pont qui sert un serveur d'outils stdio en Streamable HTTP, un conteneur par serveur (CT-2 EX-3.5)",
      "user": "10101:10101",
      "passwd": [
        {
          "name": "mcp-fichiers",
          "uid": 10101
        }
      ],
      "group_add": [],
      "cap_add": [],
      "network_mode": null,
      "networks": [
        "outils"
      ],
      "ports": [],
      "volumes": [
        {
          "target": "/srv/pieces",
          "access": "rw"
        }
      ],
      "tmpfs": "/run/temporaire",
      "environment": [
        "TMPDIR"
      ],
      "bind_sources": [
        "/srv/noortrace-outils/"
      ],
      "secrets": [
        "^jeton-pont-[a-z0-9-]+$"
      ],
      "probe": {
        "type": "commande",
        "test": [
          "CMD",
          "/usr/local/bin/noortrace-pont-stdio",
          "sonde",
          "--url",
          "http://127.0.0.1:9101/sante"
        ]
      }
    },
    "relais": {
      "image": "noortrace/noorcore",
      "tag": "618fcef-noortrace",
      "status": "existante",
      "kind": "service",
      "source": "chain/docker/Dockerfile et chain/docker/docker-compose.yml (CT-4 §10.3) ; jamais pour une capture ni une soumission (CT-4 EX-10.5)",
      "user": "65532:65532",
      "passwd": [],
      "group_add": [],
      "cap_add": [],
      "network_mode": null,
      "networks": [
        "sortie"
      ],
      "ports": [
        8545,
        8080,
        9090
      ],
      "volumes": [
        {
          "target": "/var/lib/noorcore",
          "access": "rw"
        }
      ],
      "tmpfs": null,
      "environment": [],
      "bind_sources": [],
      "secrets": [],
      "probe": {
        "type": "externe",
        "method": "eth_blockNumber"
      }
    },
    "verificateur": {
      "image": "noortrace/verificateur",
      "tag": "0.1.0",
      "status": "a_construire",
      "kind": "outil",
      "source": "CT-6 (noortrace-verifier, binaire autonome sans réseau)",
      "user": "10005:10005",
      "passwd": [],
      "group_add": [],
      "cap_add": [],
      "network_mode": "none",
      "networks": [],
      "ports": [],
      "volumes": [
        {
          "target": "/var/lib/noortrace-exports",
          "access": "ro"
        }
      ],
      "tmpfs": "/run/temporaire",
      "environment": [
        "TMPDIR"
      ],
      "bind_sources": [],
      "secrets": [],
      "probe": {
        "type": "aucune"
      }
    }
  }
}
```

### 4.2 `deploiement/compose/rapide.yaml`

Contenu exact (SHA-256
`12011feb774e00e24336801f91c960494e17731c7d2a0162f10bb59a3f372e5f`) :

```yaml
# Installation rapide de NOORTRACE (CT-8 §7) : un hôte, mode observation,
# classe de garde D, bail « file », sans copie WORM, ancrage de test
# (OpenTimestamps seul), sans approbation bloquante.
#
# Fichier de RÉFÉRENCE : les images noortrace/* sont à construire (phase 2) ;
# il est vérifié par analyse statique (CT-8 §4, vérifications CO-1 à CO-14),
# jamais lancé dans le dépôt. Les secrets sont des fichiers de ./secrets/
# créés au pas IR-2 (mode 0400), jamais une variable d'environnement.
#
# Depuis le répertoire deploiement/ (les chemins relatifs ./config et ./secrets
# se résolvent alors contre lui) :
#
#   docker compose --project-directory . -f compose/rapide.yaml up -d
#   docker compose --project-directory . -f compose/rapide.yaml ps

name: noortrace-rapide

services:
  enregistreur:
    image: noortrace/enregistreur:0.1.0
    user: "10001:10001"
    group_add:
      - "10010"
    command: ["--configuration", "/etc/noortrace/configuration.json"]
    read_only: true
    tmpfs:
      - /run/temporaire:size=67108864,mode=1777
    environment:
      TMPDIR: /run/temporaire
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    ports:
      - "127.0.0.1:8300:8300"
      - "127.0.0.1:8400:8400"
      - "127.0.0.1:8500:8500"
    volumes:
      - type: volume
        source: journal
        target: /var/lib/noortrace
      - type: volume
        source: exploitation
        target: /var/log/noortrace
      - type: volume
        source: prises
        target: /run/noortrace
      - type: volume
        source: exports
        target: /var/lib/noortrace-exports
      - type: bind
        source: ./config/rapide/configuration.json
        target: /etc/noortrace/configuration.json
        read_only: true
        bind:
          create_host_path: false
    secrets:
      - cle-enregistreur
      - cle-mac-relais
      - jeton-hote
      - jeton-passerelle
    networks:
      - hotes
      - sortie
    healthcheck:
      test: ["CMD", "/usr/local/bin/noortrace-ctl", "sonde", "--url", "http://127.0.0.1:8500/readyz"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 30s

  approbation:
    image: noortrace/approbation:0.1.0
    user: "10002:10002"
    group_add:
      - "10010"
    command: ["--prise", "/run/noortrace/approbation.sock", "--pair", "noortrace", "--etat", "/var/lib/noortrace-approbation"]
    read_only: true
    tmpfs:
      - /run/temporaire:size=16777216,mode=1777
    environment:
      TMPDIR: /run/temporaire
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    network_mode: none
    volumes:
      - type: volume
        source: approbation-etat
        target: /var/lib/noortrace-approbation
      - type: volume
        source: prises
        target: /run/noortrace
    healthcheck:
      test: ["CMD", "/usr/local/bin/noortrace-approbation", "sonde", "--url", "http://127.0.0.1:8601/v0/etat"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 10s

  verificateur:
    image: noortrace/verificateur:0.1.0
    user: "10005:10005"
    profiles: ["outils"]
    read_only: true
    tmpfs:
      - /run/temporaire:size=67108864,mode=1777
    environment:
      TMPDIR: /run/temporaire
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    restart: "no"
    network_mode: none
    volumes:
      - type: volume
        source: exports
        target: /var/lib/noortrace-exports
        read_only: true
    healthcheck:
      disable: true

networks:
  hotes: {}
  sortie: {}

volumes:
  journal: {}
  exploitation: {}
  prises: {}
  exports: {}
  approbation-etat: {}

secrets:
  cle-enregistreur:
    file: ./secrets/cle-enregistreur
  cle-mac-relais:
    file: ./secrets/cle-mac-relais
  jeton-hote:
    file: ./secrets/jeton-hote
  jeton-passerelle:
    file: ./secrets/jeton-passerelle
```

### 4.3 `deploiement/compose/production.yaml`

Contenu exact (SHA-256
`fcd775b9a6cde46b93dcf58b418d5517b0c854196ee15c7eb06e59cc334481e0`).
`NOORTRACE_IP_INTERNE` DOIT être l'adresse unicast d'une interface interne de
l'hôte, jamais `0.0.0.0` ni `::`, qui publieraient les frontaux sur toutes les
interfaces ; IP-6 le vérifie en production (`adresse_toutes_interfaces`,
`adresse_hors_hote`), CO-10 ne pouvant lire que le nom de la variable.
L'interpolation `${…:?…}` fait échouer Compose si elle manque (R9-F23 pour la
forme des références d'image ; mesure ci-dessous pour l'échec).

```yaml
# Installation complète de production de NOORTRACE (CT-8 §8) : topologies
# « sur site », « tenant cloud du client » et « hébergeur suisse » (CT-8 §3).
#
# Fichier de RÉFÉRENCE : les images noortrace/* sont à construire (phase 2) ;
# l'image du nœud est celle de chain/docker/Dockerfile. Il est vérifié par
# analyse statique (CT-8 §4, CO-1 à CO-14), jamais lancé dans le dépôt. Avant
# la mise en service, chaque étiquette est complétée par le condensé publié
# (pas IC-6) : le contrôle préalable de production refuse une image sans
# condensé (IP-12). NOORTRACE_IP_INTERNE est l'adresse de l'interface interne
# de l'hôte (jamais 0.0.0.0) ; les secrets sont des fichiers de ./secrets/
# (mode 0400), jamais une variable d'environnement. Depuis le répertoire
# deploiement/ :
#
#   docker compose --project-directory . -f compose/production.yaml up -d

name: noortrace

services:
  enregistreur:
    image: noortrace/enregistreur:0.1.0
    user: "10001:10001"
    group_add:
      - "10010"
    command: ["--configuration", "/etc/noortrace/configuration.json"]
    read_only: true
    tmpfs:
      - /run/temporaire:size=67108864,mode=1777
    environment:
      TMPDIR: /run/temporaire
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    ports:
      - "${NOORTRACE_IP_INTERNE:?adresse interne requise}:8300:8300"
      - "${NOORTRACE_IP_INTERNE:?adresse interne requise}:8400:8400"
      - "${NOORTRACE_IP_INTERNE:?adresse interne requise}:1344:1344"
      - "${NOORTRACE_IP_INTERNE:?adresse interne requise}:4318:4318"
      - "127.0.0.1:8500:8500"
    volumes:
      - type: volume
        source: journal
        target: /var/lib/noortrace
      - type: volume
        source: exploitation
        target: /var/log/noortrace
      - type: volume
        source: prises
        target: /run/noortrace
      - type: volume
        source: exports
        target: /var/lib/noortrace-exports
      - type: bind
        source: ./config/production/configuration.json
        target: /etc/noortrace/configuration.json
        read_only: true
        bind:
          create_host_path: false
      - type: bind
        source: ./config/production/ancrage.json
        target: /etc/noortrace/ancrage.json
        read_only: true
        bind:
          create_host_path: false
    secrets:
      - cle-mac-relais
      - acces-signataire
      - cle-chaine
      - dsn-bail
      - worm-ecrivain
      - jeton-hote-agents
      - jeton-hote-otel
      - jeton-passerelle
      - cle-fournisseur-anthropic
      - cle-fournisseur-openai
      - cle-fournisseur-gemini
      - tsa-principal
      - tsa-secours
      - tls-enregistreur-certificat
      - tls-enregistreur-cle
      - identifiant-outil-sap
      - identifiant-outil-fichiers
    networks:
      - hotes
      - outils
      - sortie
    healthcheck:
      test: ["CMD", "/usr/local/bin/noortrace-ctl", "sonde", "--url", "http://127.0.0.1:8500/readyz"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 60s
    depends_on:
      approbation:
        condition: service_healthy

  attributs:
    image: noortrace/attributs:0.1.0
    user: "0:0"
    command: ["--racine", "/var/lib/noortrace", "--intervalle-s", "60"]
    read_only: true
    tmpfs:
      - /run/temporaire:size=1048576,mode=1777
    environment:
      TMPDIR: /run/temporaire
    cap_drop:
      - ALL
    cap_add:
      - LINUX_IMMUTABLE
      - FOWNER
      - DAC_READ_SEARCH
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    network_mode: none
    volumes:
      - type: volume
        source: journal
        target: /var/lib/noortrace
    healthcheck:
      test: ["CMD", "/usr/local/bin/noortrace-attributs", "sonde"]
      interval: 60s
      timeout: 5s
      retries: 3
      start_period: 10s

  approbation:
    image: noortrace/approbation:0.1.0
    user: "10002:10002"
    group_add:
      - "10010"
    command: ["--configuration", "/etc/noortrace-approbation/configuration.json"]
    read_only: true
    tmpfs:
      - /run/temporaire:size=16777216,mode=1777
    environment:
      TMPDIR: /run/temporaire
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    ports:
      - "127.0.0.1:8601:8601"
    volumes:
      - type: volume
        source: approbation-etat
        target: /var/lib/noortrace-approbation
      - type: volume
        source: prises
        target: /run/noortrace
      - type: bind
        source: ./config/production/approbation.json
        target: /etc/noortrace-approbation/configuration.json
        read_only: true
        bind:
          create_host_path: false
    secrets:
      - jeton-console-vers-service-approbation
      - rpc-registre
      - notification-courriel
      - tls-approbation
    networks:
      - console
      - sortie
    healthcheck:
      test: ["CMD", "/usr/local/bin/noortrace-approbation", "sonde", "--url", "http://127.0.0.1:8601/v0/etat"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 10s

  console:
    image: noortrace/console:0.1.0
    user: "10003:10003"
    command: ["--configuration", "/etc/noortrace-console/configuration.json"]
    read_only: true
    tmpfs:
      - /run/temporaire:size=16777216,mode=1777
    environment:
      TMPDIR: /run/temporaire
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    ports:
      - "${NOORTRACE_IP_INTERNE:?adresse interne requise}:8700:8700"
    volumes:
      - type: bind
        source: ./config/production/console.json
        target: /etc/noortrace-console/configuration.json
        read_only: true
        bind:
          create_host_path: false
    secrets:
      - jeton-console-vers-service-console
      - oidc-client
      - tls-console
    networks:
      - console
      - sortie
    healthcheck:
      test: ["CMD", "/usr/local/bin/noortrace-console", "sonde"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 10s
    depends_on:
      approbation:
        condition: service_healthy

  pont-fichiers:
    image: noortrace/pont-stdio:0.1.0
    user: "10101:10101"
    command: ["--ecoute", "0.0.0.0:9101", "--jeton", "/run/secrets/jeton-pont-fichiers", "--", "/opt/mcp/server-filesystem/bin/server-filesystem", "/srv/pieces"]
    read_only: true
    tmpfs:
      - /run/temporaire:size=67108864,mode=1777
    environment:
      TMPDIR: /run/temporaire
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    volumes:
      - type: bind
        source: /srv/noortrace-outils/fichiers
        target: /srv/pieces
        bind:
          create_host_path: false
    secrets:
      - jeton-pont-fichiers
    networks:
      - outils
    healthcheck:
      test: ["CMD", "/usr/local/bin/noortrace-pont-stdio", "sonde", "--url", "http://127.0.0.1:9101/sante"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 10s

  relais:
    image: noortrace/noorcore:618fcef-noortrace
    user: "65532:65532"
    profiles: ["relais"]
    command:
      - -chain-id=${NOORCORE_CHAIN_ID:?identifiant BFT requis}
      - -evm-chain-id=${NOORCORE_EVM_CHAIN_ID:?identifiant EVM requis}
      - -data-dir=/var/lib/noorcore
      - -role=follower
      - -follow-rpc=${NOORCORE_LEADER_RPC:?point RPC du meneur requis}
      - -rpc-addr=0.0.0.0:8545
      - -health-addr=0.0.0.0:8080
      - -metrics-addr=0.0.0.0:9090
      - -p2p-addr=127.0.0.1:30303
      - -allow-public-bind
      - -network-profile=prod-like
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    ports:
      - "127.0.0.1:8545:8545"
      - "127.0.0.1:8080:8080"
      - "127.0.0.1:9090:9090"
    volumes:
      - type: volume
        source: noorcore-donnees
        target: /var/lib/noorcore
    networks:
      - sortie
    healthcheck:
      disable: true

  verificateur:
    image: noortrace/verificateur:0.1.0
    user: "10005:10005"
    profiles: ["outils"]
    read_only: true
    tmpfs:
      - /run/temporaire:size=67108864,mode=1777
    environment:
      TMPDIR: /run/temporaire
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    restart: "no"
    network_mode: none
    volumes:
      - type: volume
        source: exports
        target: /var/lib/noortrace-exports
        read_only: true
    healthcheck:
      disable: true

networks:
  hotes: {}
  outils:
    internal: true
  console:
    internal: true
  sortie: {}

volumes:
  journal: {}
  exploitation: {}
  prises: {}
  exports: {}
  approbation-etat: {}
  noorcore-donnees: {}

secrets:
  cle-mac-relais:
    file: ./secrets/cle-mac-relais
  acces-signataire:
    file: ./secrets/acces-signataire
  cle-chaine:
    file: ./secrets/cle-chaine
  dsn-bail:
    file: ./secrets/dsn-bail
  worm-ecrivain:
    file: ./secrets/worm-ecrivain
  jeton-hote-agents:
    file: ./secrets/jeton-hote-agents
  jeton-hote-otel:
    file: ./secrets/jeton-hote-otel
  jeton-passerelle:
    file: ./secrets/jeton-passerelle
  cle-fournisseur-anthropic:
    file: ./secrets/cle-fournisseur-anthropic
  cle-fournisseur-openai:
    file: ./secrets/cle-fournisseur-openai
  cle-fournisseur-gemini:
    file: ./secrets/cle-fournisseur-gemini
  tsa-principal:
    file: ./secrets/tsa-principal
  tsa-secours:
    file: ./secrets/tsa-secours
  tls-enregistreur-certificat:
    file: ./secrets/tls-enregistreur-certificat
  tls-enregistreur-cle:
    file: ./secrets/tls-enregistreur-cle
  identifiant-outil-sap:
    file: ./secrets/identifiant-outil-sap
  identifiant-outil-fichiers:
    file: ./secrets/identifiant-outil-fichiers
  jeton-console-vers-service-approbation:
    file: ./secrets/jeton-console-vers-service-approbation
  jeton-console-vers-service-console:
    file: ./secrets/jeton-console-vers-service-console
  rpc-registre:
    file: ./secrets/rpc-registre
  notification-courriel:
    file: ./secrets/notification-courriel
  tls-approbation:
    file: ./secrets/tls-approbation
  oidc-client:
    file: ./secrets/oidc-client
  tls-console:
    file: ./secrets/tls-console
  jeton-pont-fichiers:
    file: ./secrets/jeton-pont-fichiers
```

### 4.4 Vérifications statiques CO-

**EX-4.2** Chaque fichier de `deploiement/compose/` DOIT passer les
vérifications CO-1 à CO-14 contre `deploiement/images/images.json`, et `docker
compose -f <fichier> config --quiet` DOIT rendre le code 0 (avec
`NOORTRACE_IP_INTERNE`, `NOORCORE_CHAIN_ID`, `NOORCORE_EVM_CHAIN_ID` et
`NOORCORE_LEADER_RPC` posés pour `production.yaml`). Le contrôle est fait par
`scripts/deploiement/verifier-conteneurs.mjs` (sortie JSON au schéma
`conteneurs-v0`, `$defs/rapport`), en intégration continue, sans construire ni
lancer aucun conteneur. Une vérification en échec rend le code 1 ; un usage
invalide, le code 2.

| Id | Vérification | Motif |
|---|---|---|
| CO-1 | Le fichier s'analyse en YAML sans clé dupliquée ; ses clés de premier niveau sont parmi `name`, `services`, `networks`, `volumes` et `secrets` (ni `include`, ni extension `x-…`) ; `services` existe et n'est pas vide ; chaque service est décrit dans `images.json` | Lecture univoque : le fichier analysé est le fichier exécuté, sans fichier inclus ni fusion |
| CO-2 | Chaque `image` est `<nom>:<étiquette>`, `<nom>@sha256:<64 hex>` ou `<nom>:<étiquette>@sha256:<64 hex>`, avec le nom et l'étiquette exacte de la description ; jamais `latest`, jamais sans étiquette ni condensé | Une étiquette est mutable, un condensé ne l'est pas (R9-F30) ; forme `[<registry>/][<project>/]<image>[:<tag>\|@<digest>]` (R9-F23) |
| CO-3 | Aucune clé `build` | Les images sont construites ailleurs, reproductiblement (EX-3.13) |
| CO-4 | `user` présent, égal au compte de la description, numérique ; jamais `0` sauf pour `attributs` ; `group_add` égal à la liste de la description (`10010` pour `enregistreur` et `approbation`, EX-3.5, vide sinon) | Utilisateur non root à UID explicite (R9-F31) ; « Containers must be required to run as non-root users » (profil Restricted, R9-F32) ; sans `user`, le compte est celui de l'image, `root` à défaut (R9-F24) |
| CO-5 | `read_only: true` ; chaque `tmpfs` borné (`size=`) ; quand la description nomme un répertoire temporaire (`/run/temporaire`), il est monté en `tmpfs` et désigné par `TMPDIR` | Racine en lecture seule (CT-2 EX-18.4, R9-F24) ; mesure de durcissement propre à NOORTRACE, absente du profil Restricted (R9-F33) |
| CO-6 | `cap_drop: [ALL]` ; `cap_add` égal à la liste de la description (vide sauf `attributs`) | « Containers must drop ALL capabilities » (R9-F32) ; EX-3.9 |
| CO-7 | `security_opt` contient `no-new-privileges:true`, et jamais `seccomp:unconfined`, `apparmor:unconfined` ni `label:disable` (ni leur forme en `=`) | Pendant de l'interdiction d'escalade de privilèges du profil Restricted (R9-F32) |
| CO-8 | Chaque clé d'un service est dans la liste fermée `image`, `user`, `group_add`, `command`, `read_only`, `tmpfs`, `environment`, `cap_drop`, `cap_add`, `security_opt`, `restart`, `ports`, `volumes`, `secrets`, `networks`, `network_mode`, `healthcheck`, `depends_on`, `profiles` (et `build`, qui relève de CO-3) ; une autre clé n'est admise qu'à la valeur `false` ; donc ni `privileged`, `pid`, `ipc`, `devices`, `userns_mode`, `cgroup_parent`, `extends`, `volumes_from`, `entrypoint`, `env_file`…, et jamais `network_mode: host` | Isolation ; une liste fermée ne laisse pas passer une clé que la liste interdite aurait oubliée |
| CO-9 | Aucun `env_file` ; chaque variable d'`environment` est nommée par la description (liste fermée, `TMPDIR` seulement en 0.1), et aucune ne contient, sans égard à la casse, `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `PASS`, `PIN`, `DSN`, `CREDENTIAL`, `JETON`, `CLE`, `MOT_DE_PASSE`, `AUTH`, `BEARER` ou `COOKIE` ; aucune option `--jeton`, `--cle`, `--mot-de-passe`, `--token`, `--secret` ou `--password` dans `command`, `entrypoint` ou `healthcheck.test` dont la valeur n'est pas un chemin `/run/secrets/…` ; chaque secret de premier niveau a `file: ./secrets/<nom>` ou `external: true`, jamais `environment` ; un service ne reçoit que des secrets déclarés au premier niveau et admis par sa description, montés sous `/run/secrets/` ; un même secret n'est pas reçu par des services de comptes différents (`secret_partage_entre_comptes`, EX-3.5) | Secrets par fichier, jamais en clair dans l'environnement (CT-2 EX-18.4 ; R8-F56 ; accord explicite par service, R9-F25, R9-F26) |
| CO-10 | Chaque port publié a une adresse explicite, `127.0.0.1` ou `${NOORTRACE_IP_INTERNE:?…}`, jamais une plage, et un port de conteneur que la description admet | Aucune écoute sur toutes les interfaces de l'hôte |
| CO-11 | Chaque volume a une cible décrite ; une cible décrite `ro` est montée en lecture seule ; un montage lié part d'une source admise par la description (`./config/`, `/srv/noortrace-outils/`), avec `create_host_path: false`, sans composant `..`, et jamais de `/`, `/etc`, `/proc`, `/sys`, `/dev`, `/root`, `/home`, `/var/lib/docker` ni de la prise du moteur ; un volume nommé de premier niveau n'a ni pilote autre que `local` ni `driver_opts` (qui lieraient un chemin de l'hôte : `volume_lie_hote`) | Montages de l'hôte interdits sauf liste (profil Baseline : « HostPath volumes must be forbidden », R9-F32) ; création de chemin évitée (R9-F27) |
| CO-12 | Une sonde `commande` de la description donne un `healthcheck.test` en liste qui commence par `CMD` (jamais `CMD-SHELL`) ; une sonde `externe` ou `aucune` donne `healthcheck.disable: true` ; chaque `depends_on` est en forme longue, `condition: service_healthy` vers un service à sonde `commande` | Images sans interpréteur de commandes (R8-F33) ; `CMD-SHELL` passe par `/bin/sh` (R9-F28) ; ordre de démarrage sur l'état sain (R9-F28) |
| CO-13 | `restart: unless-stopped` pour un service, `restart: "no"` pour un outil | Un outil (vérificateur) ne redémarre pas en boucle |
| CO-14 | Un service de description `network_mode: none` (`attributs`, `verificateur`) a `network_mode: none` ; les autres déclarent leurs réseaux, tous admis par la description ; les réseaux `outils` et `console` sont `internal: true` | Le vérificateur n'a pas de réseau (architecture, « Déploiement ») ; les ponts ne joignent que l'enregistreur (EX-3.7) |

**EX-4.3** **Exceptions.** La liste des exceptions est fermée : le service
`attributs` (compte 0, trois capacités, EX-3.9) ; le service `relais`, dont la
sonde est externe (`eth_blockNumber`, CT-4 EX-10.5). Toute autre exception exige
une révision de CT-8.

**Mesures du 2026-10-27** (fichiers ci-dessus ; aucun conteneur construit ni
lancé) :

- prototype de `verifier-conteneurs.mjs` (lecture YAML par `js-yaml` 4.3.2, déjà
  présent dans `node_modules` du dépôt) : `rapide.yaml` et `production.yaml`
  `conforme`, CO-1 à CO-14 réussies ; trente-trois variantes altérées (annexe
  A.3) échouent chacune à la seule vérification visée (`npm run
  deploiement:conteneurs` et `npx hardhat test test/deploiement.test.js`) ;
- `docker compose -f compose/rapide.yaml config --quiet` : code 0 ;
  `NOORTRACE_IP_INTERNE=192.0.2.40 NOORCORE_CHAIN_ID=noortrace-2124-dev
  NOORCORE_EVM_CHAIN_ID=2124
  NOORCORE_LEADER_RPC=https://registre-test.example/rpc docker compose -f
  compose/production.yaml config --quiet` : code 0 ; sans ces variables : code
  1, « required variable NOORTRACE_IP_INTERNE is missing a value: adresse
  interne requise » (Docker Compose v5.6.0 ; le moteur n'était pas joignable,
  `docker info` : code 1 : l'analyse ne l'a pas sollicité).

**EX-4.4** **Ce que les vérifications ne prouvent pas.** CO-1 à CO-14 disent
qu'un fichier est conforme à la description ; elles ne disent pas qu'une image
existe, qu'elle tient sa description (compte, absence d'interpréteur, sonde), ni
qu'un conteneur démarre. Ces trois points sont des épreuves de construction
(CT-9, porte 2) : construire chaque image, lancer `docker compose up` sur un
hôte de test, relever `docker inspect` (compte, racine en lecture seule,
capacités) et l'état des sondes. Elles lisent le fichier tel qu'il est écrit, et
non la configuration effective que rendrait `docker compose config` : c'est
pourquoi CO-1 refuse `include` et CO-8 `extends`, qui feraient exécuter autre
chose que ce qui a été vérifié. Une vérification non exécutée parce qu'une
autre a échoué est `non_execute`, raison `prerequis_en_echec` : quand CO-1
échoue faute d'un document analysable (`yaml_invalide`, `services_absents`,
`cle_premier_niveau_non_admise`), CO-2 à CO-14 le sont toutes, et
`all_images_by_digest` vaut `false`.

## 5. Prérequis réseau

### 5.1 Table des flux

Un flux est identifié par FL-. « Port » est le port d'écoute de la destination ;
« port du service » quand il dépend du service du client et que CT-8 ne le fixe
pas. Les ports 8300, 8400, 4318 et 8500 sont ceux de l'exemple de CT-2 §15.3,
1344 celui de CT-2 §19.6, 8600, 8601 et 8700 ceux d'EX-3.5.

| Id | Source | Destination | Port | Protocole | Raison | Exigence citée |
|---|---|---|---|---|---|---|
| FL-1 | Hôte d'agent sur la même machine (connecteur stdio) | `enregistreur`, prise `/run/noortrace/mcp.sock` | — | prise Unix, mode `0660` | Frontal MCP pour un hôte stdio | CT-2 EX-18.1 |
| FL-2 | Hôtes d'agents | `enregistreur` | 8300 | HTTP(S), chemin `/mcp` | Frontal MCP en Streamable HTTP | CT-2 EX-18.1, EX-4.39 |
| FL-3 | Hôtes d'agents | `enregistreur` | 8400 | HTTP(S) | Passerelle du modèle | CT-2 §5.1.1, EX-18.1 |
| FL-4 | Mandataire d'interception du client | `enregistreur` | 1344 | ICAP ou ICAPS | Raccord ICAP, REQMOD et RESPMOD | CT-2 EX-5.3, §19.6 |
| FL-5 | Sources OpenTelemetry | `enregistreur` | 4318 | HTTPS, chemin `/v1/traces` | Ingestion OTLP | CT-2 EX-6.40 |
| FL-6 | Supervision du client | `enregistreur` ; `approbation` | 8500 ; 8601 | HTTP, `127.0.0.1` ou réseau de supervision ; HTTP sur `127.0.0.1` de l'hôte | `/healthz`, `/readyz`, `/metrics` ; état du service d'approbation (`GET /v0/etat`, 10.2) | CT-2 EX-17.1, EX-18.3 ; CT-3 §12 |
| FL-7 | `enregistreur` | Serveurs d'outils HTTP du client ; ponts `pont-<alias>` (réseau `outils`) | port du service | HTTPS ; HTTP sur le seul réseau interne `outils` | Relais des appels d'outils | CT-2 EX-18.2, §4.9 point 2 ; EX-3.7 |
| FL-8 | `enregistreur` | Fournisseurs de modèle (`upstream` des routes) | 443 | HTTPS | Relais des échanges de modèle | CT-2 §5.1, §4.9 points 1 et 2 |
| FL-9 | `enregistreur` | Service de signature (classe B) | port du service | HTTPS | Signature des événements et manifestes | CT-2 §11.2, EX-18.2 |
| FL-10 | `enregistreur` | Magasin de bail `postgresql` ou `etcd` | port du service | TLS | Bail et époque | CT-2 §13.2, EX-18.2 |
| FL-11 | `enregistreur` | Support WORM (API objet) | 443 | HTTPS | Copies verrouillées, relevés | CT-2 §12.6, EX-18.2 |
| FL-12 | `enregistreur` | `approbation`, prise `/run/noortrace/approbation.sock` ; à défaut HTTPS | — ; port du service | prise Unix (pair vérifié) ; HTTPS avec mTLS ou jeton | Évaluation, tickets, remises | CT-2 EX-18.8 ; CT-3 EX-12.1, EX-12.2 |
| FL-13 | `approbation` | Point RPC d'un validateur, par sa garde d'admission | 443 | HTTPS | Lecture du jeu d'approbateurs | CT-3 EX-12.3, §8.1 ; CT-4 EX-10.3 |
| FL-14 | Navigateurs des approbateurs → `console` ; `console` → `approbation` (réseau `console`) | `console` ; `approbation` | 8700 ; 8600 | HTTPS ; HTTPS avec mTLS ou jeton distinct | Console et son canal | CT-3 EX-12.4, EX-13.35 |
| FL-15 | `approbation` | Canaux de notification du client | port du service | TLS | Notifier les approbateurs | CT-3 EX-12.3 |
| FL-16 | `console` | Système d'identité du client (émetteur OIDC) | 443 | HTTPS | Identité de session | CT-3 §13.3 |
| FL-17 | `enregistreur` (ancrage) | Prestataires RFC 3161 | 443 | HTTPS (exigé hors rôle `interne` en production) | Jetons des manifestes et des points | CT-5 §5.2, EX-4.9 règle 4 |
| FL-18 | `enregistreur` (ancrage) | Calendriers OpenTimestamps (soumission et liste de mise à niveau) | 443 | HTTPS | Preuves `.ots` | CT-5 §6.2, §6.4 |
| FL-19 | `enregistreur` (ancrage, clé de chaîne) | Points RPC d'au moins deux validateurs d'opérateurs distincts, par leur garde d'admission ; jamais par un relais | 443 | HTTPS | Inscription, ancres, clôtures, captures | CT-4 EX-8.15, EX-10.5, EX-10.8 |
| FL-20 | `enregistreur` (ancrage) | Nœud Bitcoin du client (`headers_source: bitcoin_rpc`) | port du service | selon le nœud | En-têtes Bitcoin | CT-5 §6.5 |
| FL-21 | `enregistreur` (ancrage) | Serveur RFC 3161 interne | port du service | `http://127.0.0.1` sans authentification, ou TLS avec authentification du client | Contresignature interne | CT-5 AN-27 |
| FL-22 | Applications du client → `relais` ; `relais` → meneur | `relais` ; point RPC du meneur | 8545 sur `127.0.0.1` ; 443 | HTTP local ; HTTPS | Relais JSON-RPC pour les applications du client | CT-4 §10.3, EX-10.5 |
| FL-23 | `enregistreur` | Coffre de secrets (références `vault`) | port du service | HTTPS | Lecture des secrets au démarrage | CT-2 EX-15.3, EX-18.2 |
| FL-24 | `enregistreur` | Découverte OAuth des serveurs d'outils (URL épinglées) | 443 | HTTPS | Identifiants propres de l'enregistreur | CT-2 EX-4.40, EX-18.2 |
| FL-25 | Postes des gardiens et du Lecteur ; supervision non hébergée sur le serveur de console | Support WORM ; `console` | 443 ; 8700 | HTTPS | Gel, levée, relevé (CT-2 EX-17.7) ; comparaison des empreintes de la console (TP-5) | CT-2 EX-18.9, EX-17.7 ; CT-7 EX-3.9 |
| FL-26 | Hôtes NOORTRACE | Source de temps du client | port du service | protocole de la source | Horloge synchronisée (IP-5) | CT-2 §7.4 ; R9-F47 |
| FL-27 | Hôtes NOORTRACE | Résolveur DNS du client | port du service | DNS | Résolution des destinations (IP-7) | 5.3 |
| FL-28 | `verificateur`, `attributs` | aucune | — | — | Le vérificateur est un binaire sans réseau ; le compagnon n'en a pas besoin | architecture, « Déploiement » ; EX-3.9 |
| FL-29 | Hôtes NOORTRACE (moteur de conteneurs) | Registre de conteneurs des images `noortrace/*` (nom publié dans la note de version), ou miroir interne du client | 443 | HTTPS | Téléchargement des images par condensé (IR-6, IC-6, mises à jour 11.5) ; ouvert seulement pendant l'installation et les mises à jour | EX-3.14, EX-3.15 |
| FL-30 | Poste de l'exploitant ou hôte NOORTRACE | Serveur de téléchargement de l'archive de déploiement (adresse de la note de version) | 443 | HTTPS | Archive (IR-1, IC-4) ; son SHA-256 est comparé à la note de version, pas au serveur | EX-3.6, EX-3.14 |
| FL-31 | Hôtes NOORTRACE | Dépôts de paquets du système, ou miroir interne du client | 443 | HTTPS | Préparation de l'hôte (IC-2) et mises à jour du système (11.5) ; ouvert seulement pendant ces opérations | 11.5 |

**EX-5.1** La table est exhaustive pour un déploiement de référence : tout autre
flux d'un service ou d'un hôte NOORTRACE est un écart, à corriger ou à déclarer
dans l'attestation de périmètre (`not_captured` ou `egress.summary`, CT-7
§7.1). Les flux FL-7 à FL-11, FL-13, FL-15 à FL-21, FL-23 et FL-24 sont les
seuls flux sortants des services vers l'extérieur de l'hôte ; ce sont ceux de
la surface sortante exhaustive de CT-2 EX-18.2 et de CT-3 EX-12.3. FL-29 à
FL-31 sont ceux de l'hôte et de son moteur pendant l'installation et les mises
à jour ; ils ne transportent rien du journal, et DEVRAIENT être fermés en
dehors de ces opérations. Le poste de l'exploitant (EX-8.2) n'est pas un hôte
NOORTRACE : ses accès (dépôt public, registre npm) ne sont pas dans la table.

### 5.2 Règles de sortie du pare-feu

**EX-5.2** En production, le pare-feu de sortie du client DOIT :

1. refuser par défaut (`egress.default_policy = "refus_par_defaut"` de
   l'attestation, 5.4) ;
2. n'autoriser qu'à l'hôte de l'enregistreur les destinations de FL-7 et FL-8
   (serveurs d'outils et fournisseurs de modèle), et les refuser aux réseaux des
   hôtes et des agents (CT-2 §4.9, point 2 ; architecture, « Déploiement ») ;
3. autoriser FL-9 à FL-11, FL-13, FL-15 à FL-21, FL-23 et FL-24 vers les seules
   destinations que la configuration désigne (EX-6.5 les en tire), filtrées par
   nom plutôt que par adresse (CT-2 §4.9, point 1) ;
4. journaliser les tentatives refusées des réseaux d'hôtes vers les destinations
   de FL-7 et FL-8 : ce sont les contournements que l'enregistreur ne voit pas
   (CT-2 §4.9, point 5) ;
5. être exporté, à l'installation (IC-3) puis à chaque changement, dans un
   fichier dont le SHA-256 est inscrit dans l'attestation
   (`egress.rules_sha256`, CT-7 §7.1) ; le fichier reste chez le client ;
6. n'ouvrir FL-29 à FL-31 que vers les noms de la note de version ou les
   miroirs internes du client, et seulement pendant l'installation et les
   mises à jour (IC-3 les ouvre, IC-18 consigne leur fermeture).

### 5.3 TLS, mandataires et DNS

**EX-5.3** **TLS.** Tout flux qui quitte l'hôte est en TLS (HTTPS, ICAPS, TLS du
magasin de bail), sauf : les prises Unix (FL-1, FL-12) ; le réseau interne
`outils` vers un pont (FL-7, jeton statique) ; le relais sur `127.0.0.1`
(FL-22) ; le serveur RFC 3161 interne en `http://127.0.0.1` (FL-21, CT-5
AN-27) ; la santé sur `127.0.0.1` (FL-6). Un frontal de l'enregistreur qui
écoute hors de la boucle locale en production DEVRAIT avoir sa configuration TLS
(`mcp.http.tls`, `model.tls`), et DOIT l'avoir pour le point d'entrée
OpenTelemetry (CT-2 EX-6.40). Les flux sortants du démon NE DEVRAIENT PAS
traverser une interception TLS : le démon vérifie les certificats des
fournisseurs, des prestataires et des validateurs avec les autorités de son
image.

**EX-5.4** **Raccord ICAP.** Quand le frontal modèle est en mode `icap` (CT-2
§5.1.2), le mandataire du client joint l'enregistreur sur FL-4 aux services
`icap://<enregistreur>:1344/noortrace/reqmod` et `/respmod` (CT-2 §19.6), avec
ICAPS et certificat client ou une liste d'adresses (`model.icap.client_ca` ou
`allowed_sources`, exigé en production par CT-2 EX-15.4) ; l'adaptation est
limitée aux destinations des fournisseurs ; l'en-tête d'adresse cliente que le
mandataire transmet est déclaré (`client_address_header`, CT-2 EX-5.8). La
réponse en flux n'est pas bloquable et la corrélation REQMOD/RESPMOD est à
éprouver (CT-2 §5.1.2) : ce sont des limites, pas des réglages. L'intégration
est une épreuve de CT-9 (CT-2 §19.6 : à tester en phase 2).

**EX-5.5** **Mandataire sortant.** CT-2 ne définit aucun mandataire sortant pour
les connexions du démon. En version 0.1, les flux sortants de l'enregistreur
partent directement, filtrés par le pare-feu (EX-5.2). Un client dont la
politique impose un mandataire sortant le déclare (option `--mandataire` du
contrôle préalable, IP-9) et le fait traverser sans interception TLS ; la prise
en charge d'un mandataire sortant par la configuration de l'enregistreur est
proposée à CT-2 (PD-3). Un mandataire d'interception sur le chemin des **hôtes**
vers les fournisseurs est le mode ICAP (EX-5.4), pas un mandataire sortant de
l'enregistreur.

**EX-5.6** **DNS.** Les hôtes NOORTRACE résolvent par le résolveur du client
(FL-27). Chaque nom de destination de la configuration DOIT se résoudre depuis
l'hôte de l'enregistreur avant le démarrage (IP-7) ; les règles du pare-feu par
nom (EX-5.2, point 3) dépendent de ce même résolveur quand l'équipement filtre
par résolution (CT-2 §4.9, point 1).

### 5.4 Ce que l'attestation de périmètre en reprend

**EX-5.7** À l'installation complète (IC-17), l'administrateur remplit les
membres de l'attestation de périmètre (CT-7 §7.1) qui viennent de cette
section :

| Membre de l'attestation (CT-7 §7.1) | Tiré de |
|---|---|
| `egress.default_policy` | `refus_par_defaut` (EX-5.2, point 1) |
| `egress.rules_sha256`, `egress.rules_format` | SHA-256 et format de l'export du pare-feu (EX-5.2, point 5) |
| `egress.summary` | les règles 2 à 4 d'EX-5.2, en une phrase chacune |
| `egress.allowed_destinations[]` | une entrée par destination de FL-7, FL-8, FL-11, FL-17 à FL-19 et FL-24, et de FL-29 à FL-31 s'ils restent ouverts (`via` : `direct`) : `name` (le nom DNS), `via` (`enregistreur` ; `mandataire_sortant` pour les destinations atteintes par le mandataire du client en mode ICAP ou miroir ; `direct` pour les autres, à justifier), `description` (le FL- et sa raison) |
| `tools_via_proxy_only[].enforcement` | la règle 2 d'EX-5.2 pour chaque alias de `policy.servers` |
| `gateway_credentials[]` | les routes en `credentials: "propre"` et la référence de leur secret (`cle-fournisseur-*`, EX-3.5) |
| `agents[].capture_channels` | les flux FL-1 à FL-5 effectivement ouverts pour chaque agent |

L'attestation reste déclarative (CT-7 §7.8) : le contrôle préalable vérifie les
flux sortants que la configuration déclare (IP-8), pas l'absence d'autres
chemins.

## 6. Contrôle préalable

### 6.1 Commande

**EX-6.1** Le contrôle préalable est l'outil
`scripts/deploiement/controle-prealable.mjs`, livré dans l'archive de
déploiement (EX-3.6) et exécuté sur l'hôte de l'enregistreur par l'utilisateur
qui installe, avec Node.js 22 :

```bash
node scripts/deploiement/controle-prealable.mjs --profil rapide|production \
  [--configuration <configuration de l'enregistreur>] [--ancrage <ancrage-v0>] \
  [--compose <fichier Compose>] [--images deploiement/images/images.json] \
  [--secrets <répertoire des secrets>] [--stockage <chemin du stockage de storage.root>] \
  [--dimensionnement <sortie de dimensionner.mjs>] [--mandataire] \
  [--declare cache-protege] [--seulement <IP-n,…>] [--ip-interne <adresse>] [--json] \
  [--ecrire-observations <fichier>] [--observations <fichier>] [--date <horodatage>]
```

Un fichier n'est exigé que par les vérifications qui le lisent :
`--configuration` par IP-7, IP-8 et IP-10 ; `--secrets` par IP-10 ; `--images`
par IP-10 et IP-12 ; `--compose` par IP-12 et, en production, par IP-6 (ports
publiés) ; `--stockage` par IP-3 et IP-4. Une vérification non demandée par
`--seulement` ne lit rien et n'essaie aucune connexion. Sans configuration, la
borne d'erreur d'horloge d'IP-5 est 1 000 ms (`clock.warn_skew_ms` de
l'exemple de CT-2 §15.3). En production, l'adresse interne des ports publiés
est `--ip-interne`, à défaut la variable `NOORTRACE_IP_INTERNE` (que `sudo`
efface de l'environnement) ; sans l'une ni l'autre, la collecte d'IP-6 est
refusée (code 2).

Il procède en deux phases : la **collecte** relève sur l'hôte les observations
de 6.3 (`--ecrire-observations` les écrit) ; l'**évaluation**, fonction pure des
observations et des exigences du profil, produit le rapport. `--seulement`
restreint l'évaluation à une liste de vérifications : les autres sont
`non_execute`, raison `non_demandee`, non bloquantes (pas IC-5) ; un rapport
restreint ne vaut que pour les vérifications qu'il exécute, et l'installation
complète finit par un contrôle sans `--seulement` (IC-16). `--observations`
saute la collecte et évalue un fichier : un fichier d'observations
(`$defs/observations`), ou un fichier de cas des vecteurs (`$defs/cas`), dont
les observations, le seuil d'espace et la liste `only` sont repris et dont le
profil doit égaler `--profil` ; c'est ainsi que les vecteurs et les tests
rejouent l'évaluation sans hôte (annexe A.4) ; `--date` fixe `checked_at`.
Pendant la collecte, un répertoire des secrets illisible rend le code 2, relevé
avant tout essai de connexion ; un stockage illisible donne `storage` nul, et
IP-3 et IP-4 sont alors `non_execute` ; IP-8 rend la raison `mandataire` quand
une variable de mandataire existe et que la connexion directe est refusée ou
expire. Sans `--observations`, `checked_at` est l'horloge de l'hôte au moment de
la collecte et `tool` la version de l'outil (`0.1.0`) ; avec `--observations`,
l'un et l'autre sont ceux du fichier, `--date` remplaçant `checked_at`. Le
rapport ne contient ni nom d'hôte, ni secret, ni contenu de fichier ; il
contient les noms de destination de la configuration et les adresses que la
résolution a rendues. Codes de sortie : `0` prêt (avec ou sans avertissement) ;
`1` non prêt ; `2` usage invalide (option inconnue, fichier illisible,
configuration invalide contre son schéma).

### 6.2 Vérifications

**EX-6.2** Les vérifications sont exactement IP-1 à IP-13, dans cet ordre.
« Bloquante » : un échec, ou une non-exécution, rend le verdict `non_pret` dans
ce profil. Les seuils marqués « cible » sont à mesurer (CT-9, porte 2).

| Id | Vérifie | Mesure (collecte) | Réussie si | Rapide | Production | Exigence |
|---|---|---|---|---|---|---|
| IP-1 | Système | `os.platform()`, `os.arch()` | `linux` et architecture admise (`x64` ; `arm64` non vérifié pour les images) | bloquante | bloquante | EX-3.6 |
| IP-2 | Ressources | `os.availableParallelism()`, `os.totalmem()` | au moins 2 processeurs et 4 Gio (rapide), 4 et 8 Gio (production) : cibles | bloquante | bloquante | 9 (DM-19 pour la mémoire de tampons) |
| IP-3 | Espace libre sous `--stockage` | `fs.statfsSync` (`bavail × bsize`) | au moins 10 Gio (rapide, cible) ; au moins `local_bytes` de `--dimensionnement` (production) ; non exécutée sans dimensionnement | bloquante | bloquante | DM-16 ; CT-2 §17.4 (alerte « Disque ») |
| IP-4 | Système de fichiers sous `--stockage` | type relevé dans `/proc/self/mountinfo` (point de montage le plus long qui contient le chemin réel, liens symboliques résolus par `fs.realpathSync`) | `ext4`, `xfs` ou `btrfs` ; échec pour `nfs`, `nfs4`, `cifs`, `smb3`, `smbfs`, `fuse.sshfs` ; avertissement sinon | bloquante | bloquante | CT-2 EX-12.2, EX-12.18 |
| IP-5 | Horloge synchronisée | dans l'ordre : `chronyc -c tracking` (statut de saut différent de « Not synchronised », borne `|System time| + Root dispersion + Root delay / 2`, R9-F41, R9-F42) ; `timedatectl show -p NTPSynchronized --value` (R9-F44) ; présence de `/run/systemd/timesync/synchronized` (R9-F45) ; sinon source `aucune` | synchronisée et borne d'erreur au plus `clock.warn_skew_ms` (1 000 ms dans l'exemple de CT-2 §15.3) ; synchronisée sans borne connue (sources `timedatectl` et `timesyncd`) : avertissement `borne_inconnue`, qui n'est pas un échec ; non relevée (`clock` nul) : non exécutée, `mesure_absente` ; source `aucune` : non exécutée, `outil_absent` | non bloquante | bloquante | CT-2 §7.4 ; R9-F47 |
| IP-6 | Ports libres ; adresse interne | écoute d'essai `net.createServer().listen({host, port})` puis fermeture ; en production, l'adresse interne (`--ip-interne` ou `NOORTRACE_IP_INTERNE`) comparée à `0.0.0.0`, `::`, `[::]` et aux adresses des interfaces de l'hôte (`os.networkInterfaces()`) | en production, l'adresse interne n'est ni une adresse de toutes les interfaces (échec `adresse_toutes_interfaces`) ni hors des interfaces de l'hôte (échec `adresse_hors_hote`) ; puis tous les ports de l'adresse d'écoute libres (rapide : 8300, 8400 et 8500 sur `127.0.0.1`, ceux que publie `rapide.yaml` ; production : les ports publiés du fichier Compose), sinon `port_occupe` | bloquante | bloquante | EX-3.5 |
| IP-7 | Résolution des noms | `dns.promises.lookup(nom, {all: true})` pour chaque destination d'EX-6.5 | chaque nom résolu | bloquante | bloquante | EX-5.6 |
| IP-8 | Sortie réseau déclarée | connexion TCP de 5 s puis poignée de main TLS avec le nom (SNI) et les autorités du système, pour chaque destination d'EX-6.5 | chaque destination `ouvert` ; sinon raison `dns`, `refus`, `delai`, `tls` ou `mandataire` | bloquante | bloquante | EX-5.2, EX-5.3 |
| IP-9 | Mandataire | `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY` dans l'environnement | présence égale à la déclaration `--mandataire` ; avertissement sinon | non bloquante | bloquante (un avertissement n'est pas un échec) | EX-5.5 |
| IP-10 | Droits | `process.getuid()` ; `fs.statSync` du répertoire des secrets, de chaque fichier de secret et du fichier de configuration (chemin résolu, liens suivis) ; compte attendu tiré de `images.json` | dans cet ordre, la première faute donne la raison : répertoire des secrets avec un droit de groupe ou d'autrui, ou un secret avec un tel droit (`secrets_lisibles`) ; un secret dont le mode n'est ni `0400` ni `0600` (`secret_mode_non_conforme` : `0400` pour un secret lu seulement, `0600` toléré pour un secret que l'outil qui le crée laisse inscriptible par son propriétaire, jamais `0700`, `0200` ni `0000`) ; un secret admis par des services de comptes différents (`secret_partage_entre_comptes` : un fichier n'a qu'un propriétaire) ; un secret qui n'est pas propriété du compte du service qui le reçoit (`secret_proprietaire_incorrect`) ; la configuration avec un droit de groupe ou d'autrui (`configuration_lisible_par_autrui`), ou qui n'est pas propriété du compte du démon (`configuration_proprietaire_incorrect`) | bloquante | bloquante | CT-2 EX-15.3, EX-18.5 ; EX-3.5 |
| IP-11 | Moteur et Compose | `docker version` (le moteur répond) ; `docker compose version` | les deux rendent 0 | bloquante | bloquante | section 4 |
| IP-12 | Fichier Compose | `verifier-conteneurs.mjs` (CO-1 à CO-14) sur `--compose` | aucune CO- en échec (sinon `conteneurs_non_conformes`) ; en production, chaque image porte `@sha256:` (sinon `condense_requis`) | bloquante | bloquante | EX-4.2, EX-3.15 |
| IP-13 | Cache d'écriture protégé | déclaration `--declare cache-protege` de l'exploitant | déclaration présente ; non exécutée en rapide sans déclaration | non bloquante | bloquante (échec sans déclaration) | CT-2 EX-12.9 |

**EX-6.3** **Verdict.** Le verdict est `non_pret` si une vérification bloquante
du profil est `echoue` ou `non_execute` ; sinon `pret_avec_avertissements` si
une vérification n'est pas `reussi` ; sinon `pret`. Le code de sortie est `1`
pour `non_pret`, `0` sinon.

**EX-6.4** **Cache d'écriture.** Le contrôle préalable ne sait pas mesurer si le
cache d'écriture du stockage est protégé ou honore les commandes de vidage (CT-2
EX-12.9) : c'est une déclaration de l'exploitant (IP-13), qui DOIT la faire, en
production, d'après la documentation du disque ou du volume, et la consigner au
procès-verbal d'installation (IC-2) avec sa source. Sans elle, le contrôle de
production est `non_pret`.

**EX-6.5** **Destinations.** IP-7 et IP-8 portent sur les destinations que la
configuration déclare, et sur elles seules : l'hôte de chaque
`policy.servers.<alias>.transport.url` de type `http` (FL-7, sauf un pont du
réseau `outils`), de chaque `policy.model.routes[].upstream` (FL-8), de
`signer.backend.url` (FL-9), de `storage.seal.worm.endpoint` s'il est non nul
(FL-11), de `policy.approval.service.url` s'il est non nul (FL-12), de
`anchoring.registry.rpc_url` (FL-19), de `anchoring.rfc3161.url` et de chaque
`rfc3161.providers[].url` du document `ancrage-v0` (FL-17), de chaque calendrier
et de chaque entrée de `opentimestamps.upgrade.whitelist` (FL-18), et de
`VAULT_ADDR` quand une référence `vault` existe (FL-23), avec le port de l'URL
(443 par défaut pour `https`). Les destinations dont l'adresse n'est pas dans la
configuration (région d'un service géré sans `endpoint`, magasin de bail désigné
par un DSN secret) ne sont pas essayées : le rapport ne les mentionne pas, et le
pas IC-10 les vérifie à la main.

### 6.3 Observations, exigences et rapport

Le rapport suit le schéma `spec/schemas/controle-prealable-v0.schema.json`
(racine) ; les observations, `$defs/observations` ; un fichier de cas des
vecteurs, `$defs/cas`. Pour chaque vérification : `id`, `status` (`reussi`,
`echoue`, `avertissement`, `non_execute`), `reason` (code nommé ou `null`),
`measured`, `expected`, `blocking`.

**EX-6.6** **Formes de `measured` et `expected`.** Chaque vérification rend
les formes suivantes, quel que soit son statut ; une vérification non demandée
(`--seulement`) a `measured` nul. Les listes gardent l'ordre des observations.

| Id | `measured` | `expected` |
|---|---|---|
| IP-1 | `{platform, arch}` ; nul si le système n'est pas relevé | `{platform: "linux", architectures}` |
| IP-2 | `{cpus, memory_bytes}` | `{cpus_min, memory_min_bytes}` |
| IP-3 | `{free_bytes}` ; nul sans stockage relevé | `{free_min_bytes}`, nul en production sans dimensionnement |
| IP-4 | `{fstype}` ; nul sans stockage relevé | `{accepted}` (`ext4`, `xfs`, `btrfs`) |
| IP-5 | `{source, synchronized, error_bound_ms}` ; `{source: "aucune"}` sans outil ; nul sans relevé (`clock` nul) | `{synchronized: true, max_error_ms}` |
| IP-6 | `{busy, internal_address}` : `busy` liste les `{address, port}` attendus occupés ou non relevés ; `internal_address` est `{address, on_host}` en production, nul en rapide | `{free}` : les `{address, port}` attendus |
| IP-7 | `{unresolved}` : les noms sans adresse | `{resolved}` : tous les noms essayés |
| IP-8 | `{failed}` : les `{flow, host, port, result}` qui ne sont pas `ouvert` ; la raison est le `result` du premier | `{open}` : les flux essayés |
| IP-9 | `{environment_set}` | `{declared}` |
| IP-10 | `{uid_is_root, secrets_dir_mode, config_mode, config_uid, config_expected_uid}` | `{secret_modes: [256, 384], secrets_mode_mask: 63, config_mode_mask: 63}` (`0400`, `0600`, `0077`) |
| IP-11 | `{engine_ok, compose_ok}` | `{engine_ok: true, compose_ok: true}` |
| IP-12 | `{failed, all_images_by_digest}` : `failed` liste les CO- en échec ; nul sans fichier Compose (raison `fichier_absent`) | `{failed: [], images_by_digest}` (vrai en production) |
| IP-13 | `{declared}` | `{declared: true}` |

Exemple : observations d'un hôte qui prépare l'installation rapide avec la
configuration de 7.3 (adresses de documentation de la RFC 5737), puis le rapport
qu'en tire l'évaluation. Valeurs calculées par le prototype de l'évaluation
(exécution du 2026-10-27).

<!-- schema: controle-prealable/observations -->
```json
{
  "version": 0,
  "checked_at": "2026-10-27T09:00:00.000Z",
  "tool": "0.1.0",
  "platform": "linux",
  "arch": "x64",
  "cpus": 4,
  "memory_bytes": 8589934592,
  "storage": {
    "path": "/var/lib/docker/volumes",
    "fstype": "ext4",
    "free_bytes": 53687091200
  },
  "clock": {
    "source": "chrony",
    "synchronized": true,
    "error_bound_ms": 3.2
  },
  "ports": [
    {
      "address": "127.0.0.1",
      "port": 8300,
      "free": true
    },
    {
      "address": "127.0.0.1",
      "port": 8400,
      "free": true
    },
    {
      "address": "127.0.0.1",
      "port": 8500,
      "free": true
    }
  ],
  "dns": [
    {
      "name": "outils.interne.example",
      "addresses": [
        "192.0.2.21"
      ]
    },
    {
      "name": "api.anthropic.com",
      "addresses": [
        "198.51.100.31"
      ]
    },
    {
      "name": "api.openai.com",
      "addresses": [
        "198.51.100.32"
      ]
    },
    {
      "name": "a.pool.opentimestamps.org",
      "addresses": [
        "203.0.113.41"
      ]
    },
    {
      "name": "b.pool.opentimestamps.org",
      "addresses": [
        "203.0.113.42"
      ]
    }
  ],
  "egress": [
    {
      "flow": "FL-7",
      "host": "outils.interne.example",
      "port": 443,
      "result": "ouvert"
    },
    {
      "flow": "FL-8",
      "host": "api.anthropic.com",
      "port": 443,
      "result": "ouvert"
    },
    {
      "flow": "FL-8",
      "host": "api.openai.com",
      "port": 443,
      "result": "ouvert"
    },
    {
      "flow": "FL-18",
      "host": "a.pool.opentimestamps.org",
      "port": 443,
      "result": "ouvert"
    },
    {
      "flow": "FL-18",
      "host": "b.pool.opentimestamps.org",
      "port": 443,
      "result": "ouvert"
    }
  ],
  "proxy": {
    "declared": false,
    "environment_set": false
  },
  "rights": {
    "uid": 1000,
    "secrets_dir_mode": 448,
    "secret_files": [
      {
        "name": "cle-enregistreur",
        "mode": 256,
        "uid": 10001,
        "expected_uid": 10001
      },
      {
        "name": "cle-mac-relais",
        "mode": 256,
        "uid": 10001,
        "expected_uid": 10001
      },
      {
        "name": "jeton-hote",
        "mode": 256,
        "uid": 10001,
        "expected_uid": 10001
      },
      {
        "name": "jeton-passerelle",
        "mode": 256,
        "uid": 10001,
        "expected_uid": 10001
      }
    ],
    "config_mode": 256,
    "config_uid": 10001,
    "config_expected_uid": 10001
  },
  "engine": {
    "engine_ok": true,
    "compose_ok": true
  },
  "compose": {
    "file_sha256": null,
    "failed": [],
    "all_images_by_digest": false
  },
  "declarations": {
    "write_cache_protected": false
  }
}
```

<!-- schema: controle-prealable -->
```json
{
  "version": 0,
  "profile": "rapide",
  "checked_at": "2026-10-27T09:00:00.000Z",
  "tool": "0.1.0",
  "verdict": "pret_avec_avertissements",
  "exit_code": 0,
  "checks": [
    {
      "id": "IP-1",
      "status": "reussi",
      "reason": null,
      "measured": {
        "platform": "linux",
        "arch": "x64"
      },
      "expected": {
        "platform": "linux",
        "architectures": [
          "x64"
        ]
      },
      "blocking": true
    },
    {
      "id": "IP-2",
      "status": "reussi",
      "reason": null,
      "measured": {
        "cpus": 4,
        "memory_bytes": 8589934592
      },
      "expected": {
        "cpus_min": 2,
        "memory_min_bytes": 4294967296
      },
      "blocking": true
    },
    {
      "id": "IP-3",
      "status": "reussi",
      "reason": null,
      "measured": {
        "free_bytes": 53687091200
      },
      "expected": {
        "free_min_bytes": 10737418240
      },
      "blocking": true
    },
    {
      "id": "IP-4",
      "status": "reussi",
      "reason": null,
      "measured": {
        "fstype": "ext4"
      },
      "expected": {
        "accepted": [
          "ext4",
          "xfs",
          "btrfs"
        ]
      },
      "blocking": true
    },
    {
      "id": "IP-5",
      "status": "reussi",
      "reason": null,
      "measured": {
        "source": "chrony",
        "synchronized": true,
        "error_bound_ms": 3.2
      },
      "expected": {
        "synchronized": true,
        "max_error_ms": 1000
      },
      "blocking": false
    },
    {
      "id": "IP-6",
      "status": "reussi",
      "reason": null,
      "measured": {
        "busy": [],
        "internal_address": null
      },
      "expected": {
        "free": [
          {
            "address": "127.0.0.1",
            "port": 8300
          },
          {
            "address": "127.0.0.1",
            "port": 8400
          },
          {
            "address": "127.0.0.1",
            "port": 8500
          }
        ]
      },
      "blocking": true
    },
    {
      "id": "IP-7",
      "status": "reussi",
      "reason": null,
      "measured": {
        "unresolved": []
      },
      "expected": {
        "resolved": [
          "outils.interne.example",
          "api.anthropic.com",
          "api.openai.com",
          "a.pool.opentimestamps.org",
          "b.pool.opentimestamps.org"
        ]
      },
      "blocking": true
    },
    {
      "id": "IP-8",
      "status": "reussi",
      "reason": null,
      "measured": {
        "failed": []
      },
      "expected": {
        "open": [
          "FL-7",
          "FL-8",
          "FL-8",
          "FL-18",
          "FL-18"
        ]
      },
      "blocking": true
    },
    {
      "id": "IP-9",
      "status": "reussi",
      "reason": null,
      "measured": {
        "environment_set": false
      },
      "expected": {
        "declared": false
      },
      "blocking": false
    },
    {
      "id": "IP-10",
      "status": "reussi",
      "reason": null,
      "measured": {
        "uid_is_root": false,
        "secrets_dir_mode": 448,
        "config_mode": 256,
        "config_uid": 10001,
        "config_expected_uid": 10001
      },
      "expected": {
        "secret_modes": [
          256,
          384
        ],
        "secrets_mode_mask": 63,
        "config_mode_mask": 63
      },
      "blocking": true
    },
    {
      "id": "IP-11",
      "status": "reussi",
      "reason": null,
      "measured": {
        "engine_ok": true,
        "compose_ok": true
      },
      "expected": {
        "engine_ok": true,
        "compose_ok": true
      },
      "blocking": true
    },
    {
      "id": "IP-12",
      "status": "reussi",
      "reason": null,
      "measured": {
        "failed": [],
        "all_images_by_digest": false
      },
      "expected": {
        "failed": [],
        "images_by_digest": false
      },
      "blocking": true
    },
    {
      "id": "IP-13",
      "status": "non_execute",
      "reason": "declaration_absente",
      "measured": {
        "declared": false
      },
      "expected": {
        "declared": true
      },
      "blocking": false
    }
  ]
}
```

Lecture : l'hôte est `pret_avec_avertissements` ; la seule vérification qui n'a
pas réussi est IP-13, non exécutée faute de déclaration, non bloquante dans le
profil rapide (une installation rapide ne prétend pas à la durabilité de
production). Le code de sortie est 0.

## 7. Installation rapide

### 7.1 Ce qu'elle installe, et ce qu'elle ne prouve pas

**EX-7.1** **Durée.** L'installation rapide DOIT se faire en **15 minutes au
plus**, du début du pas IR-1 à la fin de la vérification du pas IR-8, par une
personne qui n'a que CT-8 et, pour la forme du fichier de configuration de
l'hôte d'agent (IR-7), CT-2 §19.5, sur un hôte dans l'état de départ d'EX-7.2.
La somme des budgets de 7.2 est de 900 secondes (cible) ; CT-9 la chronomètre à
la porte 2, pas par pas, et publie chaque durée mesurée, atteinte ou non.

**EX-7.2** **État de départ.** Un hôte Linux `x64` avec : un moteur de
conteneurs et le greffon Compose (IP-11) ; Node.js 22 ; `curl`, `openssl` et
`sudo` ; un utilisateur qui peut lancer `docker` (membre du groupe `docker`, ce
qui équivaut à des droits de superutilisateur, ou par `sudo` devant chaque
commande `docker` et `$DC`) ; une sortie HTTPS vers les destinations de la
configuration de 7.3 (serveur d'outils du client, fournisseurs de modèle, deux
calendriers OpenTimestamps) et vers FL-29 et FL-30 ; les ports 8300, 8400 et
8500 de `127.0.0.1` libres (ceux que publie `rapide.yaml` ; l'installation
rapide n'a pas d'ingestion OpenTelemetry, donc pas de 4318).
L'installation de ces éléments sur une machine vierge n'est pas comptée ici :
elle l'est dans l'installation complète (IC-2).

**EX-7.3** **Ce qui est installé.** Un seul hôte ; un enregistreur en
`recorder.environment: "developpement"` ; le **mode observation** (section 12 :
tout est capturé et journalisé, rien n'est bloqué ni retenu par la politique, ce
que la politique aurait exigé est consigné ; l'appel attend l'évaluation au plus
`policy.approval.timeout_ms`, 2 000 ms par défaut, puis est relayé avec la
marque `inconnu`, et l'écriture quand le stockage répond, EX-12.5 ; au-delà des
bornes d'attente de CT-2 EX-14.9, un événement est perdu sans trou dans la
chaîne, ce que seuls `event_lost` et `noortrace_events_lost_total` disent,
EX-12.14) ; la configuration par défaut de 7.3 ; une
clé de classe D générée sur l'hôte ; le bail `file` ; aucun support WORM ; un
**ancrage de test** : preuves OpenTimestamps des manifestes auprès de deux
calendriers publics, sans registre ni jeton RFC 3161 ; le service d'approbation,
sans console, sans approbation bloquante, dont l'enregistreur ne dépend pas pour
démarrer (aucun `depends_on` dans `rapide.yaml` : sans lui, chaque appel porte
la marque `inconnu`, CT-2 EX-14.15). Ce qu'elle ne prouve pas : une clé de
classe D n'offre aucune garantie de garde (CT-2 §11.2) ; sans registre ni jeton,
les contrôles 4 et 8 de CT-6 ne s'exécutent pas, et le contrôle 5 attend la mise
à niveau des preuves (CT-5 §6.4) ; un dossier issu d'une installation rapide dit
qu'il vient du mode observation (section 12). Ce n'est jamais une installation
de production : la validation de CT-2 refuse la classe D en `production` (CT-2
EX-11.8).

**EX-7.4** **Pas.** Chaque pas a sa commande, son résultat attendu et sa
vérification ; une vérification qui échoue arrête la procédure, et la ligne « Si
la vérification échoue » dit quoi faire. Toutes les commandes s'exécutent depuis
le répertoire `deploiement/` de l'archive, avec :

```bash
DC="docker compose --project-directory . -f compose/rapide.yaml"
```

`--project-directory .` fait résoudre `./config` et `./secrets` contre
`deploiement/` ; sans lui, Compose les résout contre `deploiement/compose/`
(mesure du 2026-10-27, `docker compose config` sur les deux formes, Docker
Compose v5.6.0).

### 7.2 Pas IR-1 à IR-8

| Pas | Objet | Budget (cible) |
|---|---|---|
| IR-1 | Obtenir et vérifier l'archive de déploiement | 60 s |
| IR-2 | Créer les secrets | 90 s |
| IR-3 | Écrire la configuration | 90 s |
| IR-4 | Contrôle préalable | 90 s |
| IR-5 | Valider la configuration par le démon | 60 s |
| IR-6 | Démarrer | 150 s |
| IR-7 | Raccorder un hôte et faire un appel | 180 s |
| IR-8 | Exporter et vérifier un premier dossier | 180 s |
| Total | | 900 s |

**IR-1 — Archive.**

```bash
curl -fsSLO https://noortrace.example/versions/0.1.0/noortrace-deploiement-0.1.0.tar
echo '<SHA-256 de la note de version>  noortrace-deploiement-0.1.0.tar' | sha256sum -c
mkdir noortrace && tar -xkf noortrace-deploiement-0.1.0.tar -C noortrace && cd noortrace/deploiement
(cd .. && sha256sum --strict -c SHA256SUMS --quiet)
```

`noortrace.example` est un domaine d'exemple (RFC 2606) : l'adresse réelle est
celle de la note de version (EX-3.14), qui donne aussi le SHA-256 de l'archive ;
la note est lue hors du serveur de téléchargement, et aucun fichier `.sha256`
n'est pris sur ce serveur, qui pourrait le recalculer pour une archive
modifiée. L'archive 0.1.0 est à construire (EX-3.6) : tant qu'aucune version
n'est publiée, ce pas n'a pas de valeur à comparer. Résultat attendu :
`noortrace-deploiement-0.1.0.tar: OK`, puis aucune ligne de la vérification de
`SHA256SUMS`. Vérification : les deux commandes rendent 0, et `ls
compose/rapide.yaml config/rapide/configuration.json
../scripts/deploiement/controle-prealable.mjs` liste les trois fichiers. Si la
vérification échoue : ne pas extraire, ou supprimer le répertoire extrait ;
reprendre le téléchargement.

**IR-2 — Secrets.**

```bash
install -d -m 0700 secrets
openssl genpkey -algorithm ed25519 -outform DER -out secrets/cle-enregistreur
for s in cle-mac-relais jeton-hote jeton-passerelle; do
  openssl rand -hex 32 | tr -d '\n' > "secrets/$s"
done
chmod 0400 secrets/*
sudo chown 10001:10001 secrets/*
```

Résultat attendu : `sudo stat -c '%a %u %s %n' secrets/*` rend `400 10001 48
secrets/cle-enregistreur` puis `400 10001 64` pour les trois autres. La clé est
une graine Ed25519 en PKCS#8 DER (préfixe `302e020100300506032b657004220420` de
CT-1 §13, 48 octets) ; la clé du MAC de relais et les jetons sont 32 octets en
hexadécimal, sans saut de ligne final (CT-2 EX-15.3). Mesure du 2026-10-27
(OpenSSL 3.0.13) : ces commandes produisent des fichiers de 48 et 64 octets, la
clé commence par ce préfixe. Si la vérification échoue : supprimer `secrets/` et
recommencer le pas.

**IR-3 — Configuration.**

```bash
node ../scripts/deploiement/configurer-rapide.mjs --org <nom court de l'organisation> \
  --journal <nom du journal> --serveur-outils https://<serveur d'outils>/mcp \
  --sortie config/rapide/configuration.json
sudo chown 10001:10001 config/rapide/configuration.json
sudo chmod 0400 config/rapide/configuration.json
```

Le script part de la configuration de référence (7.3), recalcule `org_id` et
`journal_id` par la dérivation de CT-4 §6.2 et §6.3 (`orgIdOf`, `journalIdOf` de
`scripts/lib/noortrace.mjs`), remplace l'URL du serveur d'outils, valide le
résultat contre `configuration-enregistreur-v0` et imprime `org_id`,
`journal_id` et le SHA-256 du fichier. Résultat attendu : `configuration valide`
et le code 0. Vérification : le SHA-256 imprimé est consigné. Si la vérification
échoue : le rapport nomme le pointeur JSON fautif ; corriger l'option et
relancer.

**IR-4 — Contrôle préalable.**

```bash
sudo "$(command -v node)" ../scripts/deploiement/controle-prealable.mjs --profil rapide \
  --configuration config/rapide/configuration.json --compose compose/rapide.yaml \
  --images images/images.json --secrets secrets \
  --stockage "$(docker info --format '{{.DockerRootDir}}')"
```

Le contrôle tourne avec `sudo` parce qu'il lit des fichiers qui n'appartiennent
plus qu'au compte du démon (IR-2, IR-3) ; il ne fait que lire et essayer des
connexions. Résultat attendu : verdict `pret` ou `pret_avec_avertissements`,
code 0 (exemple en 6.3). Vérification : code 0 ; le rapport est consigné
(`--json > controle-ir4.json`). Si la vérification échoue : la vérification IP-
en échec dit quoi corriger (port occupé, nom non résolu, sortie bloquée,
droits) ; relancer après correction. Le champ `DockerRootDir` de `docker info`
n'a pas été éprouvé ici (moteur non joignable, non vérifié) : à défaut,
`--stockage` reçoit le point de montage du système de fichiers qui portera le
volume des données de l'enregistreur. Avec `rapide.yaml`, ce volume est le
volume nommé `journal` (pilote par défaut, `journal: {}`), que le moteur range
sous son répertoire racine (`DockerRootDir`) : son système de fichiers est
celui de ce répertoire. Si `docker info` ne rend pas ce champ, `--stockage`
reçoit le point de montage du répertoire racine du moteur, relevé par `df
--output=target <répertoire> | tail -n 1` (la première ligne de `df` est un
en-tête : mesure du 2026-10-27, GNU coreutils 9.4). Le chemin par défaut de ce
répertoire n'est pas vérifié ici.

**IR-5 — Validation par le démon.**

```bash
$DC run --rm --no-deps enregistreur validate-config /etc/noortrace/configuration.json
```

Résultat attendu : aucune erreur, code 0 (CT-2 EX-15.7 : pas 1 à 3 de CT-2
§15.4, sans ouvrir le stockage ni les secrets). Les avertissements sont lus :
celui du mode observation (CT-2 EX-15.8), attendu, et par exemple celui de la
politique d'approbation sans règle. Vérification : code 0. Si la vérification
échoue : corriger le pointeur rapporté, revenir à IR-3.

**IR-6 — Démarrage.**

```bash
$DC up -d
$DC ps
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8500/readyz
```

Résultat attendu : `enregistreur` et `approbation` à l'état `healthy` ; `200`
pour `/readyz` (bail détenu, frontaux à l'écoute, CT-2 EX-17.1). Vérification :
`curl -s http://127.0.0.1:8500/healthz` rend `{"status":"ok"}`. Le budget
comprend le téléchargement des images, dont la taille n'est pas connue avant
leur construction : à mesurer (CT-9, porte 2). Si la vérification échoue : `$DC
logs enregistreur` ; la ligne `startup` du journal d'exploitation et les raisons
de `/healthz` (CT-2 §14.2) disent ce qui manque.

**IR-7 — Raccorder un hôte.** Dans le client MCP de l'hôte, déclarer le serveur
`http://127.0.0.1:8300/mcp` avec l'en-tête `Authorization: Bearer <jeton>`, où
`<jeton>` est le contenu de `secrets/jeton-hote` (`sudo cat
secrets/jeton-hote`) ; la forme du fichier de chaque hôte est celle de CT-2
§19.5. Faire faire à l'agent un appel d'outil.

```bash
curl -s http://127.0.0.1:8500/metrics | grep '^noortrace_events_total'
```

Résultat attendu : au moins une ligne
`noortrace_events_total{kind="appel_outil",…}` de valeur au moins 1 (CT-2
§17.2). Vérification : la même ligne existe, `noortrace_observation_mode` vaut
1, et `noortrace_calls_blocked_total` n'a augmenté pour aucun code de politique
(mode observation, EX-12.4). Si la vérification échoue :
`noortrace_upstream_errors_total` et le journal d'exploitation disent si le
serveur d'outils est injoignable (FL-7) ou si l'hôte n'est pas authentifié
(`auth_failed`).

**IR-8 — Premier dossier.**

```bash
$DC exec enregistreur noortrace-ctl close-period --now
$DC exec enregistreur noortrace-ctl dossier exporter --dernier --vers /var/lib/noortrace-exports/premier
$DC --profile outils run --rm verificateur /var/lib/noortrace-exports/premier
```

`close-period --now` n'est admise qu'en `developpement` (CT-2 §19.1) ; la
commande d'export est proposée à CT-2 (PD-2). Résultat attendu : le vérificateur
rend `valide`, code 0 (CT-6 §8), avec les contrôles 4 et 8 non exécutés pour
leur raison (aucun jeton RFC 3161, aucune capture du registre) et le contrôle 5
non exécuté tant que la preuve OpenTimestamps n'est pas mise à niveau.
Vérification : code 0 ; `policy.rule` de l'événement prouvé finit par la marque
` [observation <x>]` (EX-12.6, EX-12.9). Si la vérification échoue : le rapport
de CT-6 nomme la vérification en échec ; un code 2 dit que le dossier est
inutilisable (export incomplet).

### 7.3 Configuration par défaut

`deploiement/config/rapide/configuration.json` (SHA-256
`f4abc627701c23efc2fb14a731c46b44330bdaa7c2e3b80cdd6d156f838b72f8`, 472 lignes)
est l'exemple complet de CT-2 §15.3, changé aux seuls membres suivants ;
`configurer-rapide.mjs` le reproduit à l'octet avec les options d'exemple
d'IR-3 (annexe A.12). Il valide contre `configuration-enregistreur-v0` dans sa
forme de CT-2 révision 0.6, `politique-redaction-v0` et
`politique-approbation-v0` (commande en annexe A.16) ; le schéma de CT-2 0.5,
qui n'admet pas la valeur `observation`, le refuse.

| Membre | Valeur | Motif |
|---|---|---|
| `recorder` | `instance_id` `enregistreur-rapide-1` ; `org_id` et `journal_id` dérivés de `organisation-exemple` et `journal-rapide` (`0xd7ba…7a92`, `0x3f88…dc6a`), recalculés à IR-3 ; `environment` `developpement` | Classe D et `close-period --now` admises seulement hors production |
| `mcp.http` | écoute `0.0.0.0:8300` dans le conteneur (publiée sur `127.0.0.1`, CO-10) ; jeton statique `hote-local` lu dans `/run/secrets/jeton-hote` | Une connexion d'hôte |
| `mcp.hosts`, `model.hosts` | une connexion `hote-local` par frontal, `launched_by` `poste-local`, `scope` `observation` | Une connexion d'hôte par frontal actif (CT-2 EX-15.4) |
| `model` | écoute `0.0.0.0:8400` ; jeton `hote-local-passerelle` | Passerelle |
| `otel` | absent | Ingestion OpenTelemetry hors de l'installation rapide |
| `signer` | classe D, `rec-rapide-01`, fichier `/run/secrets/cle-enregistreur` | Clé générée à IR-2 |
| `storage.seal` | `append_only_attribute: false`, `worm: null` | Ni compagnon ni support WORM |
| `lease` | magasin `file` (`/var/lib/noortrace/bail`), `fencing: null` | Un hôte |
| `anchoring` | registre désactivé ; RFC 3161 désactivé ; OpenTimestamps activé, calendriers `https://a.pool.opentimestamps.org` et `https://b.pool.opentimestamps.org` ; `ancrage: null` | Ancrage de test sans compte ni contrat |
| `supervision.health_listen` | `0.0.0.0:8500` dans le conteneur, publiée sur `127.0.0.1` | Santé |
| `policy.version` | `rapide-2026-10-27-observation` | Le suffixe `-observation` est exigé de toute version en mode observation et interdit aux autres (CT-2 EX-15.8, révision 0.6) : `code.policy_version` de chaque événement (appel, échange, span, rotation ; décision : impossible, OB-4) nomme ainsi le mode (EX-12.9) |
| `policy.servers` | un seul serveur `outils`, transport `http`, URL remplacée à IR-3 | Le serveur d'outils du client |
| `policy.model.routes` | routes Anthropic et OpenAI de l'exemple en `credentials: "relayer"`, sans secret ; route Gemini retirée | L'hôte garde sa propre clé de fournisseur |
| `policy.approval.rules` | défaut `revue` (« Tout appel qu'aucune règle ne couvre aurait été soumis aux approbateurs. »), aucune règle, jeu `statique` de deux adresses de test publiques (comptes Hardhat 1 et 2, CT-7 CLE-28), seuil 2 sur 2 | Le mode observation consigne ce que la politique aurait exigé ; le jeu n'est jamais sollicité, et il est remplacé avant tout passage au mode bloquant (section 12) : hors du mode observation, la validation refuse ces adresses en production et les signale ailleurs (`approbateurs_de_test`, CT-2 EX-15.8) |
| `policy.approval.mode` | `observation` | Mode observation (section 12) ; seule exception au mode `erreur` par défaut (CT-3 EX-11.1, révision 0.4) |
| `policy.otel`, `policy.sdk` | absents | — |

## 8. Installation complète de production

### 8.1 Durée et ce que CT-9 mesure

**EX-8.1** L'installation complète DOIT se faire en **moins d'une journée de
travail de 8 heures**, sur une machine vierge (section 2), par un ingénieur
d'exploitation qui n'a que CT-8 et les documents que CT-8 désigne (CT-2, CT-5 et
CT-7 pour les formats qu'ils fixent ; CT-3 pour les réglages du service et de la
console, EX-10.10 ; CT-4 pour l'inscription au registre, §7 ; CT-6 §12 pour le
fichier d'ancres du premier dossier, IC-15), une fois les préalables d'EX-8.2
réunis.
Les budgets des pas IC-1 à IC-18 totalisent 450 minutes (cible), plus 30 minutes
de réserve : 480 minutes, soit exactement la journée de 8 heures ; l'objectif
est tenu tant que la durée totale mesurée, réserve comprise, reste sous 480
minutes. CT-9 mesure à la porte 2, sur le système de référence que CT-9
fixe : la durée de chaque pas ; la durée totale ; le nombre de fois où
l'ingénieur a eu besoin d'une information absente de CT-8 (cible : zéro) ; le
verdict du contrôle préalable final (`pret`, ou `pret_avec_avertissements` dont
chaque avertissement est expliqué au procès-verbal, IC-14) ; le verdict du
vérificateur sur le premier dossier (IC-15).

### 8.2 Préalables

**EX-8.2** Avant le jour de l'installation, l'exploitant DOIT avoir réuni, et
vérifié la liste, ce que l'installation consomme sans pouvoir le produire
elle-même : ces délais dépendent de tiers et ne sont pas chronométrés.

| Préalable | Qui le fournit | Utilisé à |
|---|---|---|
| Machine vierge, adresse interne (`NOORTRACE_IP_INTERNE`), noms DNS internes | équipe d'infrastructure du client | IC-2, IC-3 |
| Ouverture des flux de la section 5 par l'équipe réseau, si elle est distincte | équipe réseau | IC-3 |
| Compte du support WORM où l'administrateur peut créer un conteneur verrouillé en mode conformité ; identités des cinq rôles (CT-2 EX-18.9) | administrateur du compte du support | IC-9 |
| Contrats et comptes chez un prestataire RFC 3161 principal et, de préférence, un secours (CT-5 §5.3), identifiants (CT-7 CLE-11) | administrateur du client | IC-13 |
| Module ou service de signature pour CLE-1 et CLE-2 (classe A, B ou C), poste de cérémonie dont le SHA-256 de l'image est publié (CT-7 EX-5.3), participants convoqués (CT-7 §5.2) | administrateur du client, officiant | IC-7 |
| Approbateurs et leurs portefeuilles (CT-7 CLE-3), inscrits ou à inscrire à l'annuaire (CT-3 §13.4) | organisation | IC-11 |
| Client OIDC enregistré auprès du système d'identité du client pour la console | équipe d'identité | IC-11 |
| Dossier d'inscription de l'organisation au registre accepté par l'exploitant NOORTRACE (CT-4 §7) et points RPC d'au moins deux validateurs d'opérateurs distincts (CT-4 EX-8.15) | exploitant NOORTRACE | IC-13 |
| Jeu d'approbateurs de l'organisation déployé et assigné au registre, et lu (CT-4 §7.6, étapes `jeu_approbateurs`, `assignation` et `lecture_jeu` de `inscrire-client`) : sans lui, le service d'approbation reste `non_pret` (CT-3 EX-8.3) | exploitant NOORTRACE, approbateurs | IC-11 |
| Note de version publiée : condensés des images, SHA-256 de l'archive et du vérificateur (EX-3.14) | exploitant NOORTRACE | IC-1, IC-4, IC-6 |
| Poste de l'exploitant : Node.js 22, accès au serveur de l'archive (FL-30), copie du dépôt public à la version publiée avec `npm ci` fait et accès au registre npm (IC-7, IC-13, IC-17) ; ce poste n'est pas un hôte NOORTRACE | exploitant | IC-1, IC-7, IC-13, IC-17 |
| Entrées du dimensionnement (section 9) | exploitant | IC-1 |

### 8.3 Procès-verbal et pas IC-1 à IC-18

**EX-8.3** **Procès-verbal d'installation.** Chaque pas dépose sa sortie de
vérification dans un répertoire du procès-verbal (`/srv/noortrace-pv/`, mode
`0700`, propriété de l'utilisateur qui installe, pour que les redirections de
son shell y écrivent, hors des volumes de NOORTRACE), et le pas IC-18 en écrit
la liste avec le SHA-256 de chaque fichier. Le procès-verbal reste chez le
client avec le journal ; il ne contient aucun secret. Il porte la topologie et
les choix d'EX-3.4, la déclaration d'IP-13 et sa source, et les SHA-256 du
fichier Compose, de la configuration, de l'export du pare-feu et des
procès-verbaux de cérémonie.

| Pas | Objet | Budget (cible) | Exigences reprises |
|---|---|---|---|
| IC-1 | Ouvrir le procès-verbal ; fixer la topologie ; dimensionner | 15 min | EX-3.4, EX-3.12, section 9 |
| IC-2 | Préparer l'hôte : système, moteur et Compose, Node.js 22, horloge, stockage | 45 min | EX-6.4, CT-2 EX-12.2 |
| IC-3 | Pare-feu et DNS ; exporter les règles | 30 min | EX-5.2, EX-5.6 |
| IC-4 | Obtenir et vérifier l'archive | 5 min | EX-3.14 |
| IC-5 | Contrôle préalable du système | 10 min | IP-1, IP-2, IP-4, IP-5, IP-6, IP-11, IP-13 |
| IC-6 | Épingler les images par condensé | 15 min | EX-3.15, CO-2, IP-12 |
| IC-7 | Cérémonie des clés CLE-1 et CLE-2 | 60 min | CT-7 §5 |
| IC-8 | Secrets de service | 25 min | EX-3.5, CT-7 §4.2 |
| IC-9 | Support WORM | 40 min | EX-8.4, EX-8.5 |
| IC-10 | Bail et volume | 15 min | EX-3.10 |
| IC-11 | Service d'approbation et console | 40 min | EX-3.3, CT-3 §12, §13 |
| IC-12 | Raccords de capture | 30 min | EX-5.4, CT-2 §19.5 |
| IC-13 | Ancrage et registre | 35 min | CT-5 §4.4, CT-4 §7 |
| IC-14 | Configuration et contrôle préalable final | 15 min | EX-6.2, CT-2 EX-15.7 |
| IC-15 | Démarrage et premier dossier vérifié | 20 min | CT-6 §8 |
| IC-16 | Tâches planifiées, supervision, sauvegarde | 20 min | EX-8.6, sections 10 et 11 |
| IC-17 | Attestation de périmètre | 25 min | EX-8.7, CT-7 §7.4 |
| IC-18 | Clore le procès-verbal | 5 min | EX-8.3 |
| Total | | 450 min | |

Les commandes s'exécutent depuis `deploiement/` avec `DC="docker compose
--project-directory . -f compose/production.yaml"` et `PV=/srv/noortrace-pv`.
Les variables que `production.yaml` interpole (`NOORTRACE_IP_INTERNE` ;
`NOORCORE_CHAIN_ID`, `NOORCORE_EVM_CHAIN_ID` et `NOORCORE_LEADER_RPC` pour le
relais, EX-4.2) parviennent à chaque commande `$DC` qui lit le fichier (IC-6,
IC-11, IC-14, IC-15 ; pas 3 de 12.6) de l'une de deux façons : exportées dans
l'interpréteur d'un utilisateur du groupe `docker`, ou, sous `sudo`, qui les
efface de l'environnement (6.1), écrites devant la commande, comme la mesure de
4.4 les écrit devant `docker compose config` :

```bash
sudo NOORTRACE_IP_INTERNE=<adresse interne> NOORCORE_CHAIN_ID=<identifiant> \
  NOORCORE_EVM_CHAIN_ID=<identifiant EVM> NOORCORE_LEADER_RPC=<URL> $DC up -d
```

`sudo` transmet une affectation `VAR=valeur` placée avant la commande (`sudo -n
NOORTRACE_IP_INTERNE=192.0.2.40 env` l'imprime ; sudo 1.9.15p5, exécuté pour
cette version). La procédure n'écrit aucun fichier `.env` dans `deploiement/`,
et les fichiers de référence ne déclarent aucun `env_file` (CO-9).

**IC-1 — Procès-verbal, topologie, dimensionnement.** Sur le poste de
l'exploitant (Node.js 22), obtenir et vérifier l'archive comme à IR-1 ; IC-1
emploie les outils de cette copie vérifiée. Sur l'hôte, `sudo install -d -m 0700
-o "$(id -u)" -g "$(id -g)" "$PV"` ; écrire `"$PV"/IC-1-choix.txt` (topologie,
type de support WORM, classes de CLE-1 et CLE-2, magasin de bail, déclaration
d'EX-3.12). Sur le poste, depuis `deploiement/` de la copie, `node
../scripts/deploiement/dimensionner.mjs --entrees dimensionnement.json
--json > IC-1-dimensionnement.json`, puis copier ce fichier dans `"$PV"`. Avant
les mesures de CT-9, les entrées sans valeur par défaut de 9.2 prennent les
hypothèses de 9.5 (`f_pic` = 4, `b_o` = 512, `n_crl` = 2, `b_crl` = 833,
`b_acq` = 2 048, `m_0` nul), notées comme hypothèses au procès-verbal ; IC-1 est
refait après mesure. `D_lp` est un choix d'exploitation (purge des pièces, CT-2
EX-12.20) : `D_lp` = 365 (cas `pieces-purgees`, 9.6) retire 200,666 Gio à
l'exemple de 9.5, dont les captures du registre restent le premier poste. `D_l`
n'en est pas un : un fichier local n'est supprimé que par un procès-verbal
`fin_de_retention`, à l'échéance `retain_until` (EX-11.15 ; EX-11.13 pour la
source d'une migration) ; `D_l` couvre donc la plus longue durée qui sépare
l'écriture d'un segment de cette échéance, 4 018 jours (EX-8.4), valeur de
l'exemple de 9.5 : un segment écrit au début d'un exercice reste jusqu'à la fin
de cet exercice (au plus un an) plus `events_years` (dix ans), jours bissextiles
compris, soit 11 × 365 + 3 = 4 018 ; 3 650 = 365 × 10 est la borne en deçà de
laquelle le calculateur refuse (`retain_days_insuffisant`, EX-9.3), non la
valeur à retenir. Résultat attendu : `"valid": true`. Vérification :
`local_bytes`, `worm_bytes`, `memory_buffers_max_bytes` et
`registry_capacity_share` sont lus et reportés sur la commande de la machine et
du support.

**IC-2 — Hôte.** Installer sur la machine vierge le moteur de conteneurs et son
greffon Compose, Node.js 22, `chrony`, `curl` et `openssl`, par les paquets de
la distribution (FL-31) et selon sa documentation ; les noms des paquets de
chaque distribution ne sont pas vérifiés par CT-8 (non vérifié). Un script de
préparation de l'hôte, éprouvé par CT-9 sur le système de référence, est à
écrire (phase 2) : il est absent de l'archive 0.1. L'utilisateur qui installe
DOIT pouvoir lancer `docker` (groupe `docker`, qui équivaut à des droits de
superutilisateur, ou `sudo` devant chaque commande `docker` et `$DC`). Monter le
stockage de `storage.root` (système de fichiers `ext4`, `xfs` ou `btrfs`, local
ou volume bloc attaché, jamais NFS ni SMB, CT-2 EX-12.2) et consigner, avec sa
source (fiche du disque ou du volume), la déclaration que son cache d'écriture
est protégé ou honore les vidages (EX-6.4). Vérification : `docker version`,
`docker compose version`, `node --version` (`v22.`…) et `chronyc tracking`
(statut de saut « Normal », R9-F41) rendent 0 ; sorties dans `"$PV"/IC-2-*.txt`.

**IC-3 — Pare-feu et DNS.** Poser les règles d'EX-5.2 sur l'équipement du
client, avec FL-29 à FL-31 ouverts pour la durée de l'installation (règle 6) ;
exporter les règles ; `sha256sum <export> > "$PV"/IC-3-regles.sha256`.
Vérification : depuis un hôte du réseau des agents, `curl -sS -m 5 -o /dev/null
https://<fournisseur de modèle>/` échoue (refus ou délai : règle 2 d'EX-5.2) ;
la tentative apparaît au journal du pare-feu (règle 4).

**IC-4 — Archive.** Déposer sur l'hôte l'archive vérifiée à IC-1 (ou la
télécharger par FL-30), puis, comme à IR-1, comparer son SHA-256 à celui de la
note de version (EX-3.14), jamais à un fichier du serveur de téléchargement,
extraire par `tar -xkf` et vérifier `SHA256SUMS`. Vérification : les deux
commandes `sha256sum` d'IR-1 rendent 0 ; leur sortie va dans
`"$PV"/IC-4-archive.txt`.

**IC-5 — Contrôle préalable du système.**

```bash
sudo "$(command -v node)" ../scripts/deploiement/controle-prealable.mjs --profil production \
  --seulement IP-1,IP-2,IP-4,IP-5,IP-6,IP-11,IP-13 --declare cache-protege \
  --compose compose/production.yaml --ip-interne <adresse interne> \
  --stockage <point de montage de storage.root> --json > "$PV"/IC-5-controle.json
```

À ce pas, ni la configuration (IC-14) ni les secrets (IC-8) n'existent : les
vérifications demandées ne les lisent pas (EX-6.1) ; `--compose` donne à IP-6
les ports de production à essayer, et `--ip-interne` l'adresse interne, que
`sudo` aurait effacée de l'environnement avec `NOORTRACE_IP_INTERNE`. Le test
de l'annexe A.12 rejoue cette commande. Résultat attendu : code 0 ; les
vérifications non demandées sont `non_execute`, raison `non_demandee`, non
bloquantes. Vérification : aucune des sept
vérifications demandées n'est en échec. Si une vérification échoue : corriger
l'hôte (IC-2) avant de poursuivre.

**IC-6 — Images épinglées.** Dans `compose/production.yaml`, compléter chaque
`image` par le condensé de la note de version
(`noortrace/enregistreur:0.1.0@sha256:<64 hex>`, et de même pour chaque
service), puis :

```bash
node ../scripts/deploiement/verifier-conteneurs.mjs compose/production.yaml --images images/images.json --json > "$PV"/IC-6-conteneurs.json
$DC pull
```

Résultat attendu : `"verdict": "conforme"` et `"all_images_by_digest": true` ;
`pull` rend 0. Vérification : `sha256sum compose/production.yaml >>
"$PV"/IC-6-conteneurs.sha256`.

**IC-7 — Cérémonie des clés.** Conduire la cérémonie de CT-7 §5.4 pour CLE-1 et
CLE-2, dans la classe choisie à IC-1, et produire son procès-verbal (CT-7 §5.6).
Vérification : `npm run verify:ceremonie -- <procès-verbal>` (outil du dépôt,
vérifications CR- de CT-7 §5.8) rend 0 ; le procès-verbal et son SHA-256 vont
dans `"$PV"`. Le budget suppose les participants présents et le poste prêt
(EX-8.2).

**IC-8 — Secrets de service.** Créer `secrets/` (`install -d -m 0700 secrets`)
et un fichier par secret de la table d'EX-3.5, en `0400`, sans saut de ligne
final quand le secret est une chaîne, propriété du compte du service qui le
reçoit (`sudo chown 10001:10001` pour ceux de l'enregistreur, `10002:10002` pour
le service, `10003:10003` pour la console, `10101:10101` pour le pont). Le jeton
du canal de la console est écrit deux fois, avec le même contenu :
`jeton-console-vers-service-approbation` (10002) et
`jeton-console-vers-service-console` (10003) (EX-3.5). Jamais deux rôles WORM
dans un même fichier (CT-7 CLE-20). Vérification : `sudo stat -c '%a %u %n'
secrets/*`, consigné dans `"$PV"/IC-8-secrets.txt`, montre chaque fichier en
`400`, propriété du compte de son service ; IP-10 le revérifie au contrôle
préalable final (IC-14).

**IC-9 — Support WORM.**

**EX-8.4** À la création du support, l'administrateur du compte DOIT : (1) créer
le conteneur avec versionnement et verrouillage d'objets, rétention par défaut
en mode conformité, d'une durée au moins égale à `retain_days` de la
configuration, `4018` jours recommandés, seule durée qui couvre la fin de
l'exercice plus dix ans (onze ans au plus, jours bissextiles compris :
11 × 365 + 3 ; la durée court de l'écriture de chaque copie, alors que la
conservation des événements court de la fin de leur exercice, CT-2 EX-12.19 :
une copie écrite au début d'un exercice doit durer cet exercice plus dix ans),
`365 × events_years` (3 650 jours pour dix ans) étant
la borne de refus d'EX-9.3 (CT-2 EX-12.30 ; CT-7 EX-8.16 et §8.8.2) ; (2)
créer cinq identités distinctes pour les rôles d'Écrivain, de Gardien de pose,
de Gardien de levée, de Lecteur et d'Administrateur du compte, avec les droits
et les interdits de CT-2 EX-18.9 ; l'activation du rôle de Gardien de levée est
approuvée par une autre personne (CT-2 EX-18.9 ; sur Azure et GCS, c'est la
seule séparation de la pose et de la levée, CT-2 §18.3) ; (3) soustraire
`<prefix>gels/` aux droits de l'Écrivain en limitant sa politique aux ressources
des sous-préfixes que l'enregistreur copie, de sorte qu'aucune action d'écriture
de l'Écrivain ne couvre `<prefix>gels/` (première forme admise par CT-2
EX-12.32 ; la seconde, un registre des gels dans un autre conteneur, change
l'emplacement que lit `noortrace-ctl worm gel` et n'est pas retenue en version
0.1) ; (4) poser, quand le fournisseur l'offre, une politique d'organisation qui
lie l'administrateur du compte (CT-2 EX-18.9) ; (5) activer, quand le
fournisseur l'offre, le journal d'accès aux objets du conteneur, source du
journal des consultations et des accès (EX-11.19), et consigner au procès-verbal
d'installation qu'il ne l'offre pas sinon. Aucune écriture d'essai n'est faite
pour vérifier un refus : sur un support en mode conformité, un objet écrit par
erreur ne s'efface plus.

**EX-8.5** La création est vérifiée par lecture : l'export de la politique de
chaque identité est consigné (`"$PV"/IC-9-politiques/`, avec son SHA-256), et un
second exploitant vérifie qu'aucune action d'écriture de l'Écrivain ne couvre
`<prefix>gels/` et que seule l'identité de levée porte le droit de levée ; le
Lecteur relit avec ses identifiants la configuration de rétention par défaut
(outil du support) ; au démarrage (IC-15), la première ligne
`worm_lock_config_check` du journal d'exploitation est conforme (CT-2 EX-17.5).
La procédure de levée est celle d'EX-11.16, la relecture quotidienne celle
d'EX-10.9 (tâche TP-4) ; la fin de rétention, celle d'EX-11.15. Un second
support WORM (`copies` > 1 du dimensionnement, 9.1) se crée en refaisant IC-9 ;
son alimentation par l'enregistreur, sa relecture quotidienne (TP-4) et sa
couverture par RB-5 ne sont pas décrites en version 0.1 (section 15).

**IC-10 — Bail et volume.** Pour une instance : magasin `file` sur le volume de
`storage.root`. Pour deux instances : base PostgreSQL ou grappe etcd du client,
table ou préfixe de CT-2 §13.2, DSN dans `secrets/dsn-bail` ; volume bloc
attaché à un seul hôte (EX-3.10). Vérification : la connexion au magasin depuis
l'hôte réussit avec le compte de l'enregistreur (commande du magasin) ;
`lease.fencing` est non nul avec `postgresql` ou `etcd` (CT-2 EX-15.4). Avec
deux instances, la passive qui acquiert le bail relit le journal sur le volume
rattaché à son hôte et ouvre un segment neuf d'époque supérieure (CT-2 §13.4,
pas 4 et 5) ; si le volume est perdu avec l'instance active, son segment ouvert
l'est aussi (CT-2 §13.5), sauf volume bloc répliqué de façon synchrone (EX-3.12,
déclaré à IC-1 ; EX-11.5), et la reprise se fait depuis les copies WORM par le
chemin B (11.4).

**IC-11 — Service d'approbation et console.** Écrire
`config/production/approbation.json` et `config/production/console.json` avec
les réglages de CT-3 EX-10.10 (leur schéma est proposé à CT-3, PD-7) : jeu
d'approbateurs lu au registre (CT-3 EX-8.2), point RPC d'un validateur (FL-13),
origine de la console, émetteur OIDC et client de la console (FL-16), canaux de
notification ; inscrire les approbateurs à l'annuaire (CT-3 §13.4 à §13.8).
Le jeu de l'organisation est déjà déployé, assigné et lu au registre (préalable
d'EX-8.2). Vérification : `$DC up -d approbation console` puis `$DC ps`
(`healthy`) ; `curl -s http://127.0.0.1:8601/v0/etat` rend `ready: true` et
`set_read_at` non nul (CT-3 EX-12.12 ; port d'état d'EX-3.5) ; la page de la
console répond sur 8700 avec les en-têtes de CT-3 EX-13.35 ; ses empreintes
égalent celles de la note de version (CT-7 EX-3.9).

**IC-12 — Raccords de capture.** Déclarer les connexions d'hôte (`mcp.hosts`,
`model.hosts`, `sdk.hosts`, `otel.hosts`) et leurs jetons ; les routes du
frontal modèle en `credentials: "propre"`, avec les clés des fournisseurs
(`cle-fournisseur-*`) ; en mode ICAP, le raccord d'EX-5.4 sur le mandataire du
client. Vérification : la configuration de chaque hôte suit CT-2 §19.5 ; le
pare-feu refuse aux hôtes les destinations de FL-7 et FL-8 (IC-3).

**IC-13 — Ancrage et registre.** Écrire `config/production/ancrage.json`
(`ancrage-v0`, CT-5 §4.4 : prestataire principal qualifié, secours, cadences,
OpenTimestamps, file) ; établir le statut qualifié des prestataires depuis la
liste de confiance (CT-5 §5.3) ; inscrire la clé de l'enregistreur et la clé de
chaîne au registre (CT-4 §7.7, signatures des approbateurs) après avoir
approvisionné la clé de chaîne (CT-4 §7.6, étape `approvisionnement`, EX-4.19).
Vérification, sur le poste de l'exploitant (EX-8.2), depuis sa copie du dépôt
et avec une copie de `ancrage.json` : `npx --yes ajv-cli@5 validate
--spec=draft2020 --strict=true -s spec/schemas/ancrage-v0.schema.json -d
<copie de ancrage.json>` rend `valid` ; sur l'hôte, le contrôle préalable final
la relit (`--ancrage`, IC-14) ; la sortie de l'outil du registre pour
l'inscription (CT-4 §7.2, §7.7) est consignée.

**IC-14 — Configuration et contrôle préalable final.** Écrire
`config/production/configuration.json` à partir du modèle
`config/modele-production/configuration.json` de l'archive (`environment:
"production"`), qui est l'exemple de CT-2 §15.3 changé aux seuls membres de la
table ci-dessous, puis remplacer ses valeurs d'exemple (identifiants, noms,
URL, routes, serveurs) par celles du client ; `sudo chown 10001:10001` et `sudo
chmod 0400` le fichier ; puis :

```bash
$DC run --rm --no-deps enregistreur validate-config /etc/noortrace/configuration.json
sudo "$(command -v node)" ../scripts/deploiement/controle-prealable.mjs --profil production \
  --configuration config/production/configuration.json --ancrage config/production/ancrage.json \
  --compose compose/production.yaml --images images/images.json --secrets secrets \
  --stockage <point de montage> --dimensionnement "$PV"/IC-1-dimensionnement.json \
  --ip-interne <adresse interne> --declare cache-protege --json > "$PV"/IC-14-controle.json
```

| Membre (CT-2 §15.3) | Modèle de production | Motif |
|---|---|---|
| `mcp.http.listen`, `model.listen`, `otel.listen`, `supervision.health_listen` | `0.0.0.0:8300`, `0.0.0.0:8400`, `0.0.0.0:4318`, `0.0.0.0:8500` dans le conteneur | Un port publié n'atteint pas la boucle locale du conteneur ; la publication sur l'hôte est restreinte par `production.yaml` (CO-10, `NOORTRACE_IP_INTERNE` ou `127.0.0.1`) |
| Toute référence `{ "env": … }` (jetons statiques, DSN du bail, en-tête du serveur `sap`) | `{ "file": "/run/secrets/<nom>" }` : `jeton-hote-agents`, `jeton-passerelle`, `dsn-bail`, `identifiant-outil-sap` | Secrets par fichier, jamais dans l'environnement (CO-9, EX-3.5) |
| Fichiers de secrets de l'exemple | noms montés par `production.yaml` : `cle-chaine` (et non `cle-chaine-enveloppe`), `cle-fournisseur-anthropic`, `cle-fournisseur-openai`, `cle-fournisseur-gemini`, `jeton-hote-otel` | Chaque `file` est un secret que `production.yaml` monte dans `enregistreur` (test de l'annexe A.12) |
| `otel.tls` | `tls-enregistreur-certificat`, `tls-enregistreur-cle` | TLS exigé du point d'entrée OpenTelemetry hors boucle locale (CT-2 EX-6.40, EX-5.3) |
| `signer` | classe B, `vault-transit` (`https://signature.interne.example:8200`, clé `rec-sinistres-2026-01`, jeton `acces-signataire`) au lieu de la classe A par PKCS#11 | Un module PKCS#11 exige un montage de bibliothèque et de périphérique que CO-8 (`devices`) et CO-11 (montage non décrit) refusent : la classe A est une adaptation du client, à ajouter à la description des images, hors des fichiers de référence 0.1 |
| `policy.servers.fichiers` | transport `http` vers le pont `http://pont-fichiers:9101/mcp`, en-tête `identifiant-outil-fichiers` | Serveur stdio ponté (EX-3.7, EX-3.8) |

Résultat attendu : validation sans erreur (code 0) ; verdict `pret` ou
`pret_avec_avertissements`, code 0. Vérification : aucun avertissement non
expliqué au procès-verbal.

**IC-15 — Démarrage et premier dossier.** `$DC up -d` ; `/readyz` rend `200` ;
un appel d'outil d'un hôte raccordé ; attendre la clôture de l'heure,
l'inclusion de l'ancre au registre et le jeton RFC 3161 (CT-5) ; exporter le
dossier de l'appel (commande d'export proposée à CT-2, PD-2, comme à IR-8) et le
vérifier par `noortrace-verifier` avec un fichier d'ancres que l'exploitant
écrit lui-même selon CT-6 §12 (schéma
`spec/schemas/ancres-confiance-v0.schema.json` : toutes les clés présentes,
`null` ou liste vide pour ce qu'il ne fournit pas) à partir de ce qu'IC-13 a
inscrit et lu : `recorders[]` reprend la clé d'enregistreur et la clé de chaîne
inscrites au registre (`org_id`, `journal_id`, `key_id`, `public_key`,
`chain_key`) ; `registry` reprend l'identifiant de chaîne, les adresses des
trois contrats et le jeu de validateurs, avec ses hauteurs, lus au registre ;
`tsa_authorities[]` reprend le certificat du prestataire RFC 3161 principal et
le statut qualifié établi à IC-13 ; chaque entrée porte sa `source` (le jour de
l'installation, aucun réviseur n'en a encore remis). Résultat attendu :
`valide`, code 0, contrôles 4 et 8 exécutés et réussis ; le contrôle 5 attend la
mise à niveau de la preuve OpenTimestamps. Vérification : rapport JSON du
vérificateur au procès-verbal ; première ligne `worm_lock_config_check` conforme
(EX-8.5). La clôture et l'inclusion imposent une attente qui peut aller jusqu'à
une heure : le pas est placé pour qu'IC-16 et IC-17 se fassent pendant
l'attente. Le budget de 20 minutes d'IC-15 compte le travail de l'exploitant
(démarrage, appel, écriture du fichier d'ancres, export, vérification), non
cette attente, qui chevauche IC-16 et IC-17 ; l'attente entre dans la durée
totale d'EX-8.1, et CT-9 la relève à part pour que la durée du pas se compare
à son budget.

**IC-16 — Tâches, supervision, sauvegarde.** Poser les tâches planifiées
d'EX-8.6, brancher les règles d'alerte (section 10) et la sauvegarde (section
11). Vérification : chaque tâche a fait une première exécution réussie,
consignée. En version 0.1, les fichiers de `deploiement/observabilite/`,
l'extracteur, `regles.mjs` et la sonde ne sont pas livrés (section 15) : le
client transcrit les règles des tables de 10.4 à 10.7 dans sa supervision ;
celles qui reposent sur des noms proposés (PD-10 à PD-12) ne peuvent pas être
éprouvées et sont notées « non vérifiables » au procès-verbal. La vérification
d'IC-16 porte alors sur les tâches et la sauvegarde, dont l'archive et le
procès-verbal sont produits par les outils du client (EX-11.2).

**IC-17 — Attestation de périmètre.** Remplir l'attestation (CT-7 §7.4, pas 1 à
10) avec les membres de 5.4 (EX-5.7), la faire signer et l'inscrire au journal
(CT-7 §7.5). Vérification : `npm run conformite:attestation -- verifier
<attestation signée> --jeu <jeu.json>` (outil du dépôt, AT-1 à AT-4) rend 0.

**IC-18 — Clôture.** Fermer FL-29 à FL-31 au pare-feu (EX-5.2, règle 6) et
consigner l'export des règles comme à IC-3 ; puis :

```bash
cd "$PV" && find . -type f ! -name IC-18-liste.sha256 -print0 | LC_ALL=C sort -z \
  | xargs -0 sha256sum > IC-18-liste.sha256
```

Noter l'heure de fin. Vérification : `sha256sum --strict -c IC-18-liste.sha256`
rend 0 dans `"$PV"` ; la durée totale et la durée de chaque pas sont reportées
pour CT-9.

### 8.4 Tâches planifiées

**EX-8.6** L'installation complète pose les tâches suivantes, par le moyen
d'ordonnancement du client (minuteur du système, tâche de l'orchestrateur) ;
chaque exécution laisse une ligne horodatée avec son code de sortie, conservée
avec le journal (section 11).

| Id | Tâche | Cadence | Quand | Source |
|---|---|---|---|---|
| TP-1 | Poser le gel des copies de la période close (`noortrace-ctl worm gel poser`) | à chaque clôture | support dont le mode conformité n'est pas validé (EX-3.4) | CT-2 §12.6 |
| TP-2 | Réétablir le statut qualifié de chaque prestataire depuis la liste de confiance | à chaque nouvelle séquence de la liste, et au plus tous les 30 jours | toujours en production | CT-5 EX-5.9 |
| TP-3 | Mettre à jour le fichier d'en-têtes Bitcoin (`headers_source: fichier`) | une fois par jour (cible) | source `fichier` | CT-5 §6.5 |
| TP-4 | Relire le registre des gels et l'état `on` des versions gelées avec les identifiants du Lecteur, hors du démon | une fois par jour | support WORM configuré | CT-2 EX-17.7 |
| TP-5 | Comparer les empreintes de la page et des scripts de la console à celles de la note de version, depuis une supervision non hébergée sur son serveur | une fois par jour | console déployée | CT-7 EX-3.9 |
| TP-6 | Archiver les fichiers tournés du journal d'exploitation avec le journal | à chaque rotation | toujours | CT-7 PA-15 (EX-11.22) |
| TP-7 | Exercice de rotation d'urgence et de révocation | une fois par an | toujours en production | CT-7 EX-3.12 |
| TP-8 | Rejouer le contrôle préalable de production | après toute mise à jour, et une fois par mois (cible) | toujours | section 6 |

### 8.5 Attestation de périmètre

**EX-8.7** Une installation de production n'est close qu'avec une attestation de
périmètre signée et inscrite au journal (CT-7 §7), dont les membres tirés du
déploiement sont ceux d'EX-5.7. Elle est refaite à chaque changement de la table
des flux, des connexions d'hôte ou des routes, et au plus tard à l'échéance de
sa validité (CT-7 EX-7.2).

## 9. Dimensionnement

Le dimensionnement dit, pour une charge donnée, l'espace local et WORM, le débit
disque, la mémoire de tampons, le nombre de jetons et d'ancres, et la part de la
capacité du registre qu'occupe le déploiement. Il ne dit ni un coût (CT-2 §16.4
et CT-5 §12 en donnent les formules à prix paramétrés) ni une performance : les
cibles de débit et de latence sont celles de CT-2 §16.1, à mesurer (CT-9, porte
2).

### 9.1 Paramètres

Entrées du calculateur, par type de journal (schéma `dimensionnement-v0`,
racine) : `J` journaux de ce type (`count`) ; activité : `A` agents (`agents`),
`e` événements par heure d'activité et par agent (`events_per_hour`), `H` heures
d'activité par an (`active_hours`), `f_pic` rapport du débit de pointe au débit
moyen d'activité (`peak_factor`, à mesurer), `b_e` octets d'une ligne de segment
(`event_bytes` ; CT-2 §16.1 : « de l'ordre de 2 à 3 KiB »), `b_p` octets de
pièces nouvelles par événement et `n_p` pièces par événement
(`piece_bytes_per_event`, `pieces_per_event`, CT-2 §16.4), `q_w` part des
événements qui sont des appels de classe `ecriture` (`write_share`), `b_o`
octets du journal d'exploitation par événement (`ops_log_bytes_per_event`, à
mesurer) ; stockage : `D_l` et `D_lp` jours de conservation locale des segments
et des pièces, `storage.segment_max_bytes`, `min_free_bytes`,
`pending_max_bytes`, `rotate_max_bytes` et `keep_files` du journal
d'exploitation, `group_max_events` (`g`), et pour le support WORM `D_w`
(`retain_days`), `n_w` copies sur des supports distincts (`copies` ; en
version 0.1, l'enregistreur ne copie que vers un support, `storage.seal.worm` :
`copies` > 1 ne sert qu'à dimensionner un second support dont CT-8 0.1 ne
décrit ni l'alimentation ni la création, IC-9 se refait pour chaque support
créé, et RB-5 couvre des objets, des verrous et des gels, pas la perte d'un
support entier, hors de cette version, section 15), copie des pièces et du
journal d'exploitation ; ancrage : `c_K`, `c_T`, `a`, `r`,
`provider_role`, `registry.checkpoints`, `opentimestamps.checkpoint` (CT-5 §4.1,
§12.2), `Y_anc` (`rfc3161.retention_years`), `n_crl` CRL capturées par jeton et
`b_crl` leur taille, `b_acq` octets d'un enregistrement d'acquisition (CT-5
EX-5.13) ; mémoire : `C` somme des `quota.max_concurrent` des connexions d'hôte,
`request_max_bytes`, `response_max_bytes`, `m_0` mémoire résidente à vide
(`base_bytes`, `null` tant qu'elle n'est pas mesurée). Globale : `N_h` (8 760 ou
8 784). `δ_q = 1` si `provider_role = principal` ; `δ_s = 1` si `second_rang` ou
`interne` ; `δ_r = 0` si `registry.checkpoints = aucun`, 1 sinon (CT-5 §12.2) ;
`[x]` vaut 1 si `x` est vrai, 0 sinon.

Une charge décrite par la taille moyenne d'une pièce `s` se traduit par
`b_p` = `n_p` × `s` ; l'exemple de 9.5 (deux pièces de 3 Kio en moyenne par
événement) donne `b_p` = 6 144 et `n_p` = 2.

Si la charge n'est connue que par sa pointe `r_pic`, on pose `r_moy` = `r_pic` /
`f_pic` (`f_pic` = 4 avant mesure, IC-1) et `e` = `r_moy` × 3 600 / `A` (DM-2,
DM-3). `H` est le nombre d'heures d'activité par an, choix du client ; à défaut,
on prend `N_h` (activité continue), ce qui multiplie `E`, `V_e`, `V_p` et `V_o`
par `N_h` / `H` sans changer DM-6 à DM-11, qui ne dépendent que de `N_h`.

### 9.2 Coefficients

**EX-9.1** Chaque coefficient a une source citée ou est marqué « à mesurer
(CT-9) » ; l'exploitant PEUT remplacer un coefficient par sa propre mesure
(membre `coefficients` des entrées). Les mesures citées ont été faites le
2026-10-27 sur les vecteurs du dépôt, avec les commandes de l'annexe A.5, sauf
celle de `b_cap`, faite le 2026-11-02 sur le réseau de développement et relue
par la commande de l'annexe A.5 (révision 0.2). `b_cap` est la taille de ce
que le client conserve pour une transaction du registre qu'un dossier
prouvera : la capture de CT-4 EX-9.2, soit l'en-tête du bloc, le reçu de
**chaque** transaction du bloc, le certificat de commit et l'index de capture,
tels que CT-4 CP-6 les écrit, pour un bloc plein (64 transactions, CT-4 §4.4).
Un `b_cap` remplacé par l'exploitant DOIT mesurer cette forme complète sur un
bloc plein, jamais l'en-tête, le certificat et le seul reçu de la transaction.

| Coefficient | Valeur | Source |
|---|---|---|
| `b_pt` octets d'un point dans `points/periode-<ps>.ndjson` | 682 | mesure : ligne JCS v0 plus `\n` des 183 points de `spec/vecteurs/ct-1/points-de-controle/`, 681 à 682 octets |
| `b_man` octets du manifeste et de sa signature | 916 | mesure : `spec/vecteurs/ct-1/manifestes/periode-2.json` (631, ex aequo avec `periode-3.json`) et `periode-2.sig` (285, comme les deux autres), les plus grands des trois périodes |
| `b_tsq` octets d'une requête RFC 3161 | 113 | CT-5 §12.4 (plus grande requête relevée) ; 69 à 81 dans les vecteurs |
| `b_der` octets d'un jeton | 3 114 | CT-5 §12.4 (jeton avec l'unité et une racine RSA-3072, plus grand relevé) |
| `b_tsr_sup` octets de la réponse en plus du jeton | 9 | mesure : `.tsr` moins `.der` sur les 16 paires de `spec/vecteurs/ct-5/reponses/`, 9 octets dans chaque cas |
| `b_ots` octets d'une preuve `.ots` | 233 | CT-5 §12.4 (preuve en attente de deux calendriers) ; une preuve mise à niveau : à mesurer (CT-9) |
| `b_cap` octets de la capture d'une transaction du registre (index compris) | 123 761 | mesure TM-31 de CT-9 du 2026-11-02 (`spec/vecteurs/ct-9/mesures/rapport-2026-11-02-capture-bloc-plein.json`, outil `scripts/e2e/mesure-capture-bloc-plein.mjs`) : transaction d'un bloc plein de 64 ancres, 109 479 octets de réponses JSON-RPC (ligne `b_cap_bloc_plein`, `max`, trois répétitions égales : en-tête 5 846, certificat de commit 32 587, 64 reçus 71 046) et 14 282 octets d'index (`notes` du rapport) |
| `gaz_ancre`, `gaz_cloture` | 96 977 ; 314 256 | CT-5 EX-12.1 (CT-4 §4.5) |
| `tx_par_bloc` | 64 | CT-4 §4.4 (au plus 64 transactions par bloc, une par expéditeur) |
| `blocs_par_s` | 1,10 | CT-4 §4.4 : mesuré sur le réseau de développement le 2026-10-25 ; instance de production : à mesurer (CT-9) |
| `debit_cible` événements par seconde et par instance | 500 | CT-2 §16.1, cible non mesurée |
| `f_pic`, `b_o`, `b_acq`, `b_crl`, `n_crl`, `m_0` | — | à mesurer (CT-9) ; entrées sans valeur par défaut |

Pourquoi tous les reçus du bloc. La capture d'une transaction du registre
porte le reçu de chaque transaction de son bloc (CT-4 EX-9.2, point 2, et
EX-9.5), parce que la racine des reçus se recalcule sur tous (CT-4 CP-3 ;
CT-6 EX-11.2, R-7 du contrôle 8) ; l'export du dossier ne se fait que depuis
les captures, jamais depuis un nœud après coup (CT-4 EX-9.11), et le
certificat sort de la fenêtre de rétention d'un validateur (environ 76 heures
par défaut, CT-4 §9.5) : le répertoire des captures en est la seule copie,
gardée `Y_anc` années (DM-16). La forme à un seul reçu (en-tête,
certificat, reçu de la transaction : 39 544 octets au plus dans le même
rapport) ne passerait pas CP-3 et ne permettrait pas l'export ; la valeur de
la version 0.1, 11 096 octets, sommait les fichiers les plus grands de
captures de blocs d'une seule transaction, sans index. L'index de
capture (`capture-<h>-<i>-<rôle>.json`, CP-6) est écrit pour chaque
transaction, même quand deux transactions du client partagent un bloc : il est
compté. Le bloc plein est retenu parce qu'un bloc porte au plus 64
transactions (CT-4 §4.4) et que le reçu de chacune et sa transaction brute
dans le certificat agrandissent la capture : à composition égale, sa capture
est la plus grande.

Deux réserves, écrites pour que l'exploitant remplace `b_cap` quand elles
s'appliquent (EX-9.1). Le bloc mesuré ne porte que des ancres ; une clôture
est plus grande : son reçu fait 1 816 octets contre 1 107 à 1 111 pour une
ancre, et le certificat d'un bloc d'une clôture 7 419 octets contre 6 818
pour un bloc d'une ancre au même quorum (`spec/vecteurs/ct-6/registre/capture/`,
seuil de deux approbateurs ; la transaction brute d'une clôture grandit avec
le nombre de signatures d'approbateurs). Un bloc plein qui mêle des clôtures,
que peuvent produire les clôtures de nombreux journaux à la fin d'une même
période, n'est pas mesuré. Ensuite, la hauteur s'écrit dans chaque reçu,
dans l'en-tête, dans le certificat et dans l'index : de 19 088 à la mesure à
environ 3,5 × 10^8 après dix ans à 1,10 bloc par seconde, elle gagne quatre
chiffres, soit de l'ordre de 600 octets par capture d'un bloc plein (0,5 %,
calcul de cette révision, non mesuré).

### 9.3 Formules

**EX-9.2** Le calcul suit ces lignes, dans cet ordre, en double précision IEEE
754, chaque expression de gauche à droite avec les parenthèses écrites, sans
arrondi intermédiaire. Les sorties sont arrondies une seule fois : à l'entier
supérieur (`ceil`) pour les octets, les nombres et le gaz ; à trois décimales
(`round(x × 1000) / 1000`, demi vers le haut, toutes les grandeurs étant
positives) pour les débits et les transactions par heure ; à six décimales pour
`registry_capacity_share`.

```text
DM-1   E      = A × e × H                                              événements par an
DM-2   r_moy  = (A × e) / 3600                                         événements par seconde en activité
DM-3   r_pic  = r_moy × f_pic                                          pointe ; peak_over_target si r_pic > debit_cible
DM-4   V_e    = E × b_e                                                octets de segments par an
DM-5   V_p    = E × b_p ;  N_p = E × n_p                               octets et fichiers de pièces par an
DM-6   n_T    = 3600 / c_T ;  N_q = N_h × (1 + δ_q × (n_T − 1) × a) ;  N_s = N_h × δ_s × (n_T − 1) × a      jetons (CT-5 EX-12.1)
DM-7   N_a    = N_h × (1 + δ_r × (1 + 3600 / c_K))                     ancres au registre, au plus (CT-5 EX-12.1) ; clôtures : N_h
DM-8   N_ots  = N_h × (1 + [opentimestamps.checkpoint = mi_periode])   soumissions OpenTimestamps
DM-9   b_tok  = b_tsq + b_der + (b_der + b_tsr_sup) + n_crl × b_crl + b_acq ;  V_anc = (N_q + N_s) × (1 + r) × b_tok + N_ots × b_ots
DM-10  V_pts  = N_h × (3600 / c_K + 1) × b_pt ;  V_man = N_h × b_man ;  V_j = V_pts + V_man
DM-11  V_cap  = (N_a + N_h) × b_cap                                    captures des ancres et des clôtures
DM-12  V_o    = E × b_o                                                journal d'exploitation par an
DM-13  W_pic  = r_pic × (b_e + b_p + b_o)                              octets écrits par seconde en pointe
DM-14  F_max  = r_pic × (1 + q_w) ;  F_min = r_pic / g + r_pic × q_w   vidages (fdatasync) par seconde en pointe
DM-15  G      = N_a × gaz_ancre + N_h × gaz_cloture                    gaz par an, au plus (CT-5 EX-12.1)
DM-16  S_loc  = (V_e + V_j) × (D_l / 365) + V_p × (D_lp / 365) + (V_anc + V_cap) × Y_anc
                + keep_files × rotate_max_bytes + pending_max_bytes + 2 × min_free_bytes      espace local en régime établi
DM-17  S_w    = n_w × (V_e + V_j + V_anc + V_cap + [pieces_in_worm] × V_p + [ops_log_in_worm] × V_o) × (D_w / 365)      espace WORM
DM-18  A_o    = V_o × (D_l / 365)                                      archive du journal d'exploitation (TP-6)
DM-19  M_tamp = C × (request_max_bytes + response_max_bytes) ;  M = m_0 + M_tamp      mémoire de tampons, borne haute de configuration
DM-20  T_j    = (N_a + N_h) / N_h                                      transactions du registre par heure et par journal, au plus
DM-21  Cap_h  = tx_par_bloc × blocs_par_s × 3600 ;  J_max = floor(Cap_h / T_j)      capacité théorique de l'instance
DM-22  totaux : somme, type par type dans l'ordre des entrées, de J × S_loc, J × S_w, J × A_o, J × N_q, J × N_s, J × N_a, J × N_h, J × G, J × T_j, J × W_pic, J × F_max ;  part = (somme des J × T_j) / Cap_h
```

Lecture des lignes. DM-6 à DM-8 reprennent les comptages de CT-5 EX-4.11 et
EX-12.1, maxima quand `a = 1`. DM-9 compte, par jeton conservé (CT-5 EX-5.14),
la requête, le jeton extrait et la réponse qui le contient, les CRL capturées et
l'enregistrement d'acquisition. DM-14 borne les vidages par l'écrivain unique
(CT-2 §12.3) : au plus un par événement, plus un par intention d'écriture forcée
sur disque avant le relais (CT-2 §3.2, pas 6), au moins un par groupe plein.
DM-11 compte chaque ancre et chaque clôture à `b_cap`, capture d'une
transaction d'un bloc plein (9.2) : un bloc moins plein donne une capture
plus petite, et deux transactions du client dans un même bloc en partagent
l'en-tête, les reçus et le certificat (CT-4 EX-9.3) ; hors les deux réserves
de 9.2, DM-11 est une borne haute. DM-16 compte en régime établi (même sens
que CT-2 §16.4) la conservation locale de chaque classe, la rétention des pièces d'horodatage et des captures (CT-5
EX-5.15 ; pour les captures, durée retenue par CT-8 faute d'une durée fixée par
CT-4), le journal d'exploitation tenu localement, la borne du fichier d'attente,
et deux fois `min_free_bytes` pour que l'alerte « Disque » de CT-2 §17.4 ne se
lève pas en régime établi. `A_o` (DM-18) est la part du journal d'exploitation
dans l'archive de 11.2, sur le support de cette archive (EX-11.3) : elle n'est
pas comptée dans `S_loc`, qui ne compte que les `keep_files` fichiers tenus
localement ; sa copie WORM est comptée par DM-17 quand `ops_log_in_worm` est
vrai. Aucune ligne DM ne dimensionne le reste de l'archive de 11.2 (segments,
manifestes, points, pièces retenues, ancres, intentions, attente,
approbations) : sa taille est celle des fichiers copiés à la date de l'archive,
et le client la prévoit sur ce support. DM-19 est une borne de configuration
(tous les appels concurrents à leur taille maximale), pas une mesure ; `m_0` est
à mesurer (CT-9). `C` ne dépend pas du nombre d'agents : c'est la somme des
`quota.max_concurrent` des connexions d'hôte que la configuration de production
déclarera (IC-12, CT-2 §15) ; avant cette configuration, on prend les valeurs
prévues. Le calculateur rend `M_tamp` (`memory_buffers_max_bytes`) et `m_0`
(`memory_base_bytes`) séparément ; tant que `m_0` est nul (`base_bytes: null`,
IC-1), `M_tamp` n'est qu'une borne des seuls tampons, que la mesure de CT-9
complète, et le plancher de mémoire d'IP-2 reste exigé. DM-20 et DM-21 répondent
à CT-5 §4.3 (« la capacité de l'instance pour le nombre de journaux cible relève
de CT-8 ») : une instance qui sert `J` journaux à la cadence par défaut occupe
au plus `J × 63` transactions par heure, sur une capacité théorique de `64 ×
1,10 × 3600 = 253 440` ; la mempool (5 120 places, CT-4 §4.5) et la règle d'une
transaction par expéditeur et par bloc (CT-4 EX-4.14) restent des bornes à
surveiller (section 10).

**EX-9.3** **Refus.** Le calculateur refuse des entrées valides contre le schéma
mais incohérentes, et rend toutes les raisons, journal par journal :
`checkpoint_interval_s_non_diviseur` (`c_K` ne divise pas 3600, CT-2 EX-12.24) ;
`rfc3161_interval_s_invalide` (`c_T` n'est pas un multiple de `c_K` ou ne divise
pas 3600, CT-5 EX-4.9 règle 3) ; `retention_years_inferieure_a_10` (CT-5
EX-5.15) ; `retain_days_insuffisant` (`D_w < 365 × events_years`, CT-2
EX-15.4) ; `depassement_capacite` : après le calcul, une grandeur numérique de
sortie d'un journal dépasse 2^53 − 1, ou son produit par `count` le dépasse
(raison attribuée à ce journal) ; à défaut, un total entier de DM-22 arrondi
au-dessus la dépasse (raison attribuée au dernier journal) ; la sortie n'aurait
plus d'entiers exacts en JSON (I-JSON, RFC 7493 §2.2).

### 9.4 Calculateur

**EX-9.4** Le calculateur de référence est
`scripts/deploiement/dimensionner.mjs` :

```bash
node scripts/deploiement/dimensionner.mjs --entrees <fichier.json> [--json]
```

Il valide l'entrée contre `spec/schemas/dimensionnement-v0.schema.json`,
applique EX-9.3, puis les lignes DM-1 à DM-22, et écrit la sortie
(`$defs/sorties`) ; sans `--json`, il imprime la sortie JSON puis un résumé
lisible en Gio. `--entrees` admet aussi un fichier de cas des vecteurs
(`$defs/cas`), dont il reprend les entrées.
Codes : `0` calcul fait ; `1` entrées refusées par EX-9.3 (sortie `valid: false`
et `errors`) ; `2` usage ou entrée invalide contre le schéma. Le calcul est
déterministe : mêmes entrées, mêmes octets de sortie. Le vérificateur Go
indépendant de `spec/vecteurs/ct-8/` recalcule chaque cas depuis le seul texte
de cette section (annexe A.5).

### 9.5 Exemple calculé

Un journal de dix agents semblables à l'exemple de CT-2 §16.4 (8 heures par
jour, 120 événements par heure d'activité, `b_e` = 2 560, `b_p` = 6 144, `n_p` =
2) ; pointe quatre fois la moyenne, 10 % d'écritures et 512 octets de journal
d'exploitation par événement (trois **hypothèses de l'exemple**, non mesurées) ;
conservation locale et WORM de 4 018 jours, une copie WORM sans les pièces ;
cadences par défaut, points contresignés par un second rang (`a` = 1) ; deux CRL
de 833 octets par jeton (taille de la CRL vide de l'autorité de test,
`spec/vecteurs/ct-6/rfc3161/crl/crl-vide.pem`, sans valeur pour un prestataire
réel) et 2 048 octets par enregistrement d'acquisition (hypothèse) ; trois
connexions d'hôte de 32 appels concurrents, requêtes et réponses de 16 Mio au
plus. Valeurs calculées par le prototype du calculateur (exécution du
2026-10-27), recalculées par `scripts/deploiement/dimensionner.mjs` le
2026-11-03 avec le `b_cap` de la révision 0.2.

<!-- schema: dimensionnement -->
```json
{
  "version": 0,
  "hours_per_year": 8760,
  "coefficients": {},
  "journals": [
    {
      "id": "sinistres",
      "count": 1,
      "activity": {
        "agents": 10,
        "events_per_hour": 120,
        "active_hours": 2920,
        "peak_factor": 4,
        "event_bytes": 2560,
        "piece_bytes_per_event": 6144,
        "pieces_per_event": 2,
        "write_share": 0.1,
        "ops_log_bytes_per_event": 512
      },
      "storage": {
        "events_years": 10,
        "local_days": 4018,
        "pieces_days": 4018,
        "segment_max_bytes": 268435456,
        "min_free_bytes": 1073741824,
        "pending_max_bytes": 268435456,
        "ops_log": {
          "rotate_max_bytes": 104857600,
          "keep_files": 30
        },
        "fsync": {
          "group_max_events": 64,
          "group_max_wait_ms": 5
        },
        "worm": {
          "retain_days": 4018,
          "copies": 1,
          "pieces_in_worm": false,
          "ops_log_in_worm": false
        }
      },
      "anchoring": {
        "checkpoint_interval_s": 60,
        "rfc3161_interval_s": 300,
        "a": 1,
        "r": 0,
        "provider_role": "second_rang",
        "registry_checkpoints": "nouveaux_evenements",
        "ots_checkpoint": "aucun",
        "retention_years": 10,
        "crl_per_token": 2,
        "crl_bytes": 833,
        "acquisition_bytes": 2048
      },
      "memory": {
        "max_concurrent": 96,
        "request_max_bytes": 16777216,
        "response_max_bytes": 16777216,
        "base_bytes": null
      }
    }
  ]
}
```

<!-- schema: dimensionnement/sorties -->
```json
{
  "version": 0,
  "valid": true,
  "journals": [
    {
      "id": "sinistres",
      "count": 1,
      "events_per_year": 3504000,
      "mean_events_per_s": 0.333,
      "peak_events_per_s": 1.333,
      "peak_over_target": false,
      "segment_bytes_per_year": 8970240000,
      "piece_bytes_per_year": 21528576000,
      "piece_files_per_year": 7008000,
      "checkpoint_bytes_per_year": 364433520,
      "manifest_bytes_per_year": 8024160,
      "anchor_bytes_per_year": 1059968760,
      "capture_bytes_per_year": 68301220680,
      "ops_log_bytes_per_year": 1794048000,
      "tokens_qualified_per_year": 8760,
      "tokens_other_per_year": 96360,
      "registry_anchors_per_year_max": 543120,
      "registry_closures_per_year": 8760,
      "ots_submissions_per_year": 8760,
      "registry_tx_per_hour_max": 63,
      "registry_journals_max": 4022,
      "gas_per_year_max": 55423030800,
      "local_bytes": 1039011288480,
      "worm_bytes": 866389639584,
      "ops_archive_bytes": 19749273600,
      "peak_write_bytes_per_s": 12288,
      "peak_fsync_per_s_max": 1.467,
      "peak_fsync_per_s_min": 0.154,
      "memory_buffers_max_bytes": 3221225472,
      "memory_base_bytes": null
    }
  ],
  "totals": {
    "journals": 1,
    "local_bytes": 1039011288480,
    "worm_bytes": 866389639584,
    "ops_archive_bytes": 19749273600,
    "tokens_qualified_per_year": 8760,
    "tokens_other_per_year": 96360,
    "registry_anchors_per_year_max": 543120,
    "registry_closures_per_year": 8760,
    "gas_per_year_max": 55423030800,
    "registry_tx_per_hour_max": 63,
    "registry_capacity_tx_per_hour": 253440,
    "registry_capacity_share": 0.000249,
    "peak_write_bytes_per_s": 12288,
    "peak_fsync_per_s_max": 1.467
  }
}
```

| Grandeur | Calcul | Valeur |
|---|---|---|
| `E` | 10 × 120 × 2 920 | 3 504 000 événements par an |
| `r_moy`, `r_pic` | 1 200 / 3 600 ; × 4 | 0,333 et 1,333 événement par seconde ; sous la cible de 500 |
| `V_e`, `V_p` | 3 504 000 × 2 560 ; × 6 144 | 8 970 240 000 octets (8,354 Gio) ; 21 528 576 000 octets (20,050 Gio) |
| `N_q`, `N_s` | 8 760 × 1 ; 8 760 × 11 × 1 | 8 760 jetons qualifiés ; 96 360 de second rang |
| `N_a`, `G` | 8 760 × 62 ; 543 120 × 96 977 + 8 760 × 314 256 | 543 120 ancres au plus ; 55 423 030 800 gaz (égal à CT-5 §12.3) |
| `b_tok`, `V_anc` | 113 + 3 114 + 3 123 + 2 × 833 + 2 048 = 10 064 ; 105 120 × 10 064 + 8 760 × 233 | 1 059 968 760 octets par an (0,987 Gio) |
| `V_pts`, `V_man` | 8 760 × 61 × 682 ; 8 760 × 916 | 364 433 520 ; 8 024 160 octets par an |
| `V_cap` | (543 120 + 8 760) × 123 761 | 68 301 220 680 octets par an (63,610 Gio) |
| `S_loc` | DM-16 | 1 039 011 288 480 octets (967,655 Gio) |
| `S_w` | DM-17 | 866 389 639 584 octets (806,888 Gio) |
| `A_o` | 1 794 048 000 × 4 018 / 365 | 19 749 273 600 octets (18,393 Gio) |
| `W_pic`, `F_max`, `F_min` | 1,333… × 9 216 ; × 1,1 ; / 64 + × 0,1 | 12 288 octets par seconde ; 1,467 et 0,154 vidage par seconde |
| `M_tamp` | 96 × 33 554 432 | 3 221 225 472 octets (3 Gio), plus `m_0` à mesurer |
| `T_j`, `J_max`, part | 552 000 / 8 760 ; floor(253 440 / 63) ; 63 / 253 440 | 63 transactions par heure ; 4 022 journaux ; 0,000249 |

Écarts avec les ordres de grandeur de CT-5 §12.4. Le répertoire d'ancres y est
« d'environ 650 Mo par an » à 3,1 Ko le jeton avec sa requête et sa réponse ;
DM-9 sans CRL ni enregistrement d'acquisition donne `105 120 × 6 350 = 667 512
000` octets, du même ordre ; les CRL et les enregistrements, que CT-5 EX-5.14
conserve aussi, portent l'exemple à 1,06 Go par an. Les captures y étaient,
jusqu'à la révision 0.3 de CT-5, « d'environ 10 Mo par jour » à 7,5 Ko le
certificat d'un bloc d'une transaction ; DM-11 compte la capture d'un bloc
plein (en-tête, certificat, 64 reçus et index : 123 761 octets, 9.2) et les
clôtures : 1 512 captures et 187,1 Mo par jour, près de dix-neuf fois cet
ancien ordre de grandeur, que CT-5 0.3 remplace par cette valeur (CT-5 EX-9.9
et §12.4). Le poste dominant de l'espace local de l'exemple est celui des
captures du registre : dix ans de 63,610 Gio, 636,105 Gio sur 967,655, devant
les pièces (onze ans de 20,050 Gio, 220,715 Gio) ; sur le support WORM, les
captures font 700,238 Gio sur 806,888. Les captures ne dépendent que du nombre
de transactions du registre (DM-7, DM-11), donc de la cadence des ancres de
points (`c_K`, `registry.checkpoints`, CT-5 §12.2 ; cas `sans-ancre-des-points`
et `points-toutes-les-dix-secondes`), et de `b_cap` ; `D_lp` est le levier de
l'exploitation (cas `pieces-purgees`).

### 9.6 Cas des vecteurs

La famille `spec/vecteurs/ct-8/dimensionnement/` fait varier l'exemple, un
paramètre à la fois (annexe A.5) :

| Cas | Variation | `local_bytes` (Gio) | `worm_bytes` (Gio) | Jetons qualifiés / autres par an | Transactions par heure ; part |
|---|---|---|---|---|---|
| `reference` | — | 967,655 | 806,888 | 8 760 / 96 360 | 63 ; 0,000249 |
| `sans-worm` | aucun support WORM | 967,655 | 0 | 8 760 / 96 360 | 63 ; 0,000249 |
| `deux-copies-worm-et-pieces` | deux copies, pièces copiées | 967,655 | 2 055,207 | 8 760 / 96 360 | 63 ; 0,000249 |
| `points-chez-principal` | `provider_role = principal` | 967,655 | 806,888 | 105 120 / 0 | 63 ; 0,000249 |
| `contresignature-a-la-minute` | `c_T` = 60, principal | 1 007,066 | 850,273 | 525 600 / 0 | 63 ; 0,000249 |
| `ots-mi-periode` | preuve OpenTimestamps à mi-période | 967,674 | 806,909 | 8 760 / 96 360 | 63 ; 0,000249 |
| `sans-ancre-des-points` | `registry.checkpoints = aucun`, `c_T` = 3 600 | 342,712 | 118,938 | 8 760 / 0 | 2 ; 0,000008 |
| `pieces-purgees` | `D_lp` = 365 | 766,989 | 806,888 | 8 760 / 96 360 | 63 ; 0,000249 |
| `debit-au-dela-de-la-cible` | 50 agents, 10 000 événements par heure, actifs 8 760 h | 391 505,042 | 115 670,826 | 8 760 / 96 360 | 63 ; 0,000249 ; pointe 555,556 au-delà de 500 |
| `cent-journaux` | `J` = 100 | 96 765,467 | 80 688,823 | 876 000 / 9 636 000 | 6 300 ; 0,024858 |
| `deux-types-de-journaux` | plus trois journaux de deux agents à 30 événements par heure | 2 979,481 | 2 965,453 | 35 040 / 385 440 | 252 ; 0,000994 |
| `journal-inactif` | `e` = 0, `a` = 0 | 645,943 | 704,981 | 8 760 / 0 | 63 ; 0,000249 |
| `points-toutes-les-dix-secondes` | `c_K` = 10 | 4 015,100 | 4 159,730 | 8 760 / 96 360 | 363 ; 0,001432 ; `J_max` = 698 |
| `refus-cadence-non-diviseur` | `c_K` = 70 | refus : `checkpoint_interval_s_non_diviseur`, `rfc3161_interval_s_invalide` | | | |
| `refus-retention-ancres` | `Y_anc` = 5 | refus : `retention_years_inferieure_a_10` | | | |
| `refus-depassement-capacite` | un million d'agents à 100 000 événements par heure, `J` = 1 000 | refus : `depassement_capacite` (une sortie entière dépasserait 2^53 − 1) | | | |

Le cas `journal-inactif` garde le maximum d'ancres (DM-7 est une borne) ; sous
`nouveaux_evenements`, un journal sans activité n'ancre que ses manifestes (CT-5
EX-4.6).

## 10. Observabilité et runbooks d'incident

Cette section dit comment l'exploitant voit l'état de chaque composant et
reçoit les alertes que les autres spécifications prescrivent sans en donner
les règles : CT-2 §17.4 (31 lignes, comptées par `awk` sur ses deux tables le
2026-10-27 : 29 dans la table générale, 2 dans celle d'EX-17.8 de la révision
0.6), CT-5 §8.9 (19 alertes nommées), CT-4 EX-4.20, EX-8.3, EX-8.18,
EX-9.4, EX-9.6, EX-10.8 et §13, CT-7 EX-3.9 et MN-55. Elle reprend la forme
du gabarit d'observabilité de noorchain-core (`ops/observability/`, lu en
entier, R8-F42) sans en reprendre les noms fautifs : ce gabarit cite
`noorcore_rpc_errors_total` quand le binaire expose `noor_rpc_errors_total`
(R8-F43), et ses cibles `127.0.0.1:6260` et `6262` n'ont jamais été vues en
écoute (R8 NV-5). L'enregistreur, le service d'approbation et le composant
d'ancrage ne sont pas construits : aucune règle de cette section n'a été
exécutée contre eux, et tout seuil qui n'est pas un défaut écrit dans une
spécification est une cible « à mesurer (CT-9, porte 2) ».

**État au 2026-10-27.** Les fichiers de `deploiement/observabilite/` (règles
`regles-noortrace.yml`, tests des règles `tests-regles.yml`, configuration de
collecte `prometheus.yml`, tableau `tableau-noortrace.json`), l'extracteur
`extraire-journaux.mjs`, le générateur de règles `regles.mjs`, la sonde
`sonde.mjs`, la famille de vecteurs `supervision/` et les vérifications SV-1 à
SV-7 sont **à produire, lot suivant** : les tables de cette section en sont la
spécification, et aucun de ces fichiers n'existe dans le dépôt. SV-8 (lecture
du texte de CT-8) est la seule vérification de cette section qui s'exécute
déjà. Les runbooks emploient en revanche des outils livrés :
`verifier-journal.mjs`, `proces-verbal.mjs` et `consultations.mjs` (11.7,
11.9, 11.10).

### 10.1 Principes

**EX-10.1** Chaque alerte prescrite par CT-2 §17.4, CT-5 §8.9, CT-4 (EX-4.20,
EX-8.3, EX-8.18, EX-9.4, EX-9.6, EX-10.8, §13) et par CT-8 DOIT avoir au
moins une règle dans le fichier de référence
`deploiement/observabilite/regles-noortrace.yml` (format des règles
d'alerte de Prometheus, R8-F54), avec l'étiquette `exigence` qui nomme la
prescription (« CT-2 §17.4 Fourche ») ; une prescription qui porte deux
conditions reliées par « ou » a une règle par condition. SV-1 le vérifie
sur les tables de 10.4 à 10.7, qui font foi.

**EX-10.2** Une règle porte exactement les étiquettes `severity` (`critique`,
`majeure`, `mineure`), `component` (`enregistreur`, `ancrage`,
`approbation`, `registre`, `hote`, `exploitation`), `exigence` et `runbook`
(identifiant RB- de la section 10, ou `aucun`), et les annotations `summary`
et `description` en français ; aucune étiquette ni annotation ne porte un
argument, un nom d'utilisateur, un identifiant de ticket ou un nom d'hôte de
client (règle de CT-2 §17.2, reprise). La gravité est celle de la
prescription ; quand la prescription n'en donne pas, la table la fixe et le
dit (« gravité fixée par CT-8 »).

**EX-10.3** Le système de supervision, l'extracteur de 10.3 et la sonde
d'EX-10.7 tournent sous une identité distincte de celle de chaque
composant supervisé, avec un accès en lecture seule au journal
d'exploitation, au fichier des acquisitions de CT-5 (EX-5.14) et au journal
des consultations ; ils ne détiennent aucune clé de signature ni aucun
identifiant d'écriture du support WORM. Les relectures que CT-2 EX-17.7 et
CT-7 EX-3.9 exigent hors du composant sont celles d'EX-10.9.

### 10.2 Points de collecte

| Composant | Point | Contenu | Source |
|---|---|---|---|
| Enregistreur | `supervision.health_listen` (exemple de CT-2 §15.3 : `127.0.0.1:8500`), `GET /healthz`, `/readyz`, `/metrics` | santé et 43 métriques `noortrace_` (CT-2 §17.2) ; en révision 0.6, `noortrace_observation_mode` et `noortrace_events_lost_total` (EX-12.8) | R8-F1, R8-F2, R8-F7 |
| Composant d'ancrage | dans le démon (EX-3.2) : `GET /metrics` de `supervision.health_listen` | métriques `noortrace_anchoring_*` de CT-5 EX-8.15 et `noortrace_anchor_pending` | R8-F19 |
| Service d'approbation | port d'état 8601, publié sur `127.0.0.1` de l'hôte en production (EX-3.5, FL-6) : `GET http://127.0.0.1:8601/v0/etat` ; ni la prise `/run/noortrace/approbation.sock`, réservée au pair `noortrace` (CT-2 EX-18.8), ni le port 8600 du réseau interne `console` ne sont sondés ; l'installation rapide (`network_mode: none`) n'a que la sonde du conteneur | `ready`, `set_read_at`, `open_tickets` (CT-3 EX-12.12) ; la sonde de 10.7 les convertit en jauges | R8-F15 |
| Nœud du registre ou relais | `-metrics-addr` sur l'adresse de bouclage (désactivé par défaut ; 9645 à 9648 sur le réseau de développement) | métriques `noor_*`, dont `noor_bft_equivocations_total`, `noor_chain_height`, `noor_finalized_height` | R8-F21, R8-F37, R8-F43, R8-F45 |
| Sonde (EX-10.7) | fichier ou point d'exposition au format texte de Prometheus | `noortrace_registre_*` : réponse, hauteur, mempool, soldes ; `noortrace_approbation_*` : état du service | R8-F15, R8-F23, R8-F44 |
| Extracteur des journaux (10.3) | idem | `noortrace_journal_lignes_total`, `noortrace_journal_derniere_ligne_s`, `noortrace_proces_verbal_dernier_s` | 10.3 |
| Hôte | `node_exporter` sur `127.0.0.1:9100`, comme le gabarit de noorchain-core | métriques `node_*` du système | R8-F42 |

**EX-10.4** Tout point de collecte écoute sur l'adresse de bouclage ou sur un
réseau d'exploitation que la section 5 déclare, jamais sur une interface
publique ; la configuration de collecte de référence
(`deploiement/observabilite/prometheus.yml`) pose sur chaque cible
l'étiquette `role` (`active` ou `passive` pour une instance de
l'enregistreur, CT-2 §13 ; `validateur` ou `relais` pour un nœud), dont la
règle `noortrace_bail_non_detenu` a besoin pour savoir quelle instance doit
tenir le bail.

### 10.3 Extracteur des journaux

Plusieurs alertes prescrites portent sur une ligne d'un journal et non sur une
métrique : `worm_lock_config_check`, `worm_legal_hold_observed`,
`journal_fork`, `relay_mac_key_mismatch`, `disk_low` (CT-2 §17.4), les lignes
du composant d'ancrage (CT-5 EX-8.15) et les enregistrements d'acquisition
(CT-5 EX-5.13) (R8 conséquence 2). Prometheus ne lit pas de journal ; CT-8
les rend comptables par un extracteur.

**EX-10.5** L'extracteur de référence
`scripts/deploiement/extraire-journaux.mjs` lit, en ajout et sans jamais écrire
dans les fichiers lus : le journal d'exploitation (CT-2 EX-9.5, source
`exploitation`), le fichier de l'outil de gel (CT-2 EX-12.40, source `gel`), les
fichiers `acquisitions.ndjson` (CT-5 EX-5.14, source `acquisitions`), les
sorties JSON de l'outil du registre (`operations-registre-v0`, source
`registre`), le journal des consultations (11.10, source `consultations`) et les
procès-verbaux d'exploitation (11.9). Il expose, au format texte de Prometheus :

| Métrique | Type | Étiquettes | Sens |
|---|---|---|---|
| `noortrace_journal_lignes_total` | compteur | `source`, `event`, `level`, `detail` | lignes lues ; `event` est le membre `event` de la ligne (pour `acquisitions`, la constante `acquisition` ; pour `registre`, l'opération ; pour `consultations`, l'action) ; `detail` est fixé par la table ci-dessous, vide sinon |
| `noortrace_journal_derniere_ligne_s` | jauge | `source`, `event` | `ts` de la dernière ligne lue de cet `event`, en secondes UNIX |
| `noortrace_journal_illisibles_total` | compteur | `source` | lignes qui ne s'analysent pas en JSON strict ; jamais leur contenu |
| `noortrace_proces_verbal_dernier_s` | jauge | `kind` | `finished_at` du dernier procès-verbal valide (PV-1) de chaque sorte |

| Source | `event` | `detail` | Lu dans |
|---|---|---|---|
| `exploitation` | `worm_lock_config_check` | `conforme` ou `non_conforme` | verdict de la ligne (CT-2 EX-17.5) |
| `exploitation` | `worm_lock_check` | `gel_absent` quand les raisons disent un gel attendu absent, `non_conforme` pour une autre raison, `conforme` sinon | verdict et raisons (CT-2 EX-12.33) |
| `exploitation` | `worm_legal_hold_observed` | `garde_violee` quand la ligne porte une règle de garde violée, sinon `levee` pour un enregistrement `levee`, sinon `autre` | CT-2 EX-17.7 |
| `exploitation` | `anchoring_queue_rebuilt` | `recree` quand `recreated` > 0, `aucune` sinon | CT-5 EX-8.12 |
| `exploitation` | `anchor_refused` | `empreinte_squattee` ou `autre` | code de la ligne (CT-5 EX-8.10, EX-9.7) |
| `exploitation` | `checkpoint_anchor_late` | `interne` ou `exterieur` | rôle du prestataire des points (CT-5 EX-8.15) |
| `acquisitions` | `acquisition` | `horloge_suspecte` quand `freshness` le dit ; sinon `reponse_tardive_promue` quand l'avertissement `reponse_tardive` est porté par un jeton promu ; sinon `revoque` quand le jeton est marqué révoqué ; sinon l'issue (`outcome`) | CT-5 EX-5.13, EX-5.11, EX-5.10 étape 10 |
| `registre` | opération (`capturer`, `approvisionner`, …) | `marge_retention_basse` quand `outputs.retention.alert` est vrai ; `examen_requis` quand l'erreur l'est ; vide sinon | `scripts/registre/noortrace-registre.mjs` l. 755-761 et 2013 ; CT-4 EX-4.20, EX-9.6 |
| `consultations` | action (`lecture`, `export`, …) | rôle de la ligne (`inconnu` compris) | 11.10 |

Les noms exacts des membres de `data` qui portent le verdict, la règle de
garde violée, `recreated`, le code d'un refus et le rôle du prestataire ne
sont pas fixés par CT-2 0.5 ni par CT-5 0.2, qui en donnent le contenu
seulement : l'extracteur lit les noms que CT-2 et CT-5 fixeront, et ce
manque est la proposition PD-10 (CT-2) et PD-11 (CT-5) d'EX-10.12. L'extracteur
ne lit aucune pièce et n'expose aucune valeur hors de ces tables ; une ligne
d'un `event` absent des tables est comptée avec `detail` vide.

### 10.4 Règles de l'enregistreur

**EX-10.6** Les seuils des règles sont les défauts des spécifications
citées ; un client qui change un réglage (`pending_max_ms`,
`clock.warn_skew_ms`, `lock_audit_interval_days`, `min_free_bytes`,
`queue.anchor_pending_alert_s`, …) DOIT régénérer le fichier de règles avec
la commande `node scripts/deploiement/regles.mjs --configuration
<configuration de l'enregistreur> --ancrage <document ancrage-v0>`, qui
écrit les mêmes règles avec ses valeurs ; sans argument, elle écrit le
fichier de référence, identique octet pour octet à celui du dépôt (SV-6).

Expressions dans la syntaxe de Prometheus ; `<racine>` est le point de
montage de `storage.root`. Les durées de la colonne « Pendant » vont dans la
clause `for` (R8-F54).

| Règle | Expression | Pendant | Gravité | Exigence | Runbook |
|---|---|---|---|---|---|
| `noortrace_mode_degrade_critique` | `max by (instance, reason) (noortrace_degraded{reason=~"cle\|bail\|horloge"}) == 1` | 60s | critique | CT-2 §17.4 Mode dégradé | RB-1, RB-2, RB-6, RB-8 |
| `noortrace_mode_degrade_majeur` | `max by (instance, reason) (noortrace_degraded{reason=~"stockage\|attente\|approbation"}) == 1` | 60s | majeure (pour `approbation`, gravité fixée par CT-8) | CT-2 §17.4 Mode dégradé | RB-1 |
| `noortrace_mode_degrade_serveur` | `max by (instance, reason) (noortrace_degraded{reason=~"serveur:.*"}) == 1` | 60s | mineure | CT-2 §17.4 Mode dégradé | aucun |
| `noortrace_appels_bloques` | `rate(noortrace_calls_blocked_total[5m]) > 0` | — | majeure | CT-2 §17.4 Appels bloqués | RB-1 |
| `noortrace_attente_non_vide` | `noortrace_pending_events > 0` | 300s | majeure | CT-2 §17.4 Événements en attente | RB-1 |
| `noortrace_attente_ancienne` | `noortrace_pending_oldest_ms > 150000` (moitié de `pending_max_ms`, défaut 300 000) | — | majeure | CT-2 §17.4 Événements en attente | RB-1 |
| `noortrace_bail_non_detenu` | `noortrace_lease_epoch{role="active"} == 0` | — | critique | CT-2 §17.4 Bail | RB-2 |
| `noortrace_bail_renouvellement` | `increase(noortrace_lease_renew_failures_total[5m]) > 0` | — | critique | CT-2 §17.4 Bail | RB-2 |
| `noortrace_ancre_en_retard` | `noortrace_anchor_pending > 0` | 2h (`queue.anchor_pending_alert_s`, défaut 7 200) | majeure | CT-2 §17.4 Ancre en retard ; CT-5 §8.9 « ancre en retard » | RB-3 |
| `noortrace_copie_worm_en_retard` | `noortrace_worm_copy_pending > 0` | 1h | majeure | CT-2 §17.4 Copie WORM en retard | RB-5 |
| `noortrace_verrou_worm_non_conforme` | `noortrace_worm_lock_nonconforming > 0` | — | critique | CT-2 §17.4 Verrou WORM non conforme | RB-5 |
| `noortrace_retention_support_non_conforme` | `increase(noortrace_journal_lignes_total{event="worm_lock_config_check",detail="non_conforme"}[1d]) > 0` | — | critique | CT-2 §17.4 Verrou WORM non conforme | RB-5 |
| `noortrace_releve_en_retard` | `noortrace_worm_last_audit_age_s > 5184000` (2 × 30 × 86 400) | — | majeure | CT-2 §17.4 Relevé de verrouillage en retard | RB-5 |
| `noortrace_versions_inattendues` | `noortrace_worm_versions_unexpected > 0` | — | majeure | CT-2 §17.4 Versions inattendues | RB-5 |
| `noortrace_registre_gels_invalide` | `increase(noortrace_journal_lignes_total{event="worm_legal_hold_observed",detail="garde_violee"}[1d]) > 0` | — | critique | CT-2 §17.4 Registre des gels invalide | RB-5 |
| `noortrace_gel_non_pose` | `increase(noortrace_journal_lignes_total{event="worm_lock_check",detail="gel_absent"}[1d]) > 0` | — | critique | CT-2 §17.4 Gel non posé sur une version d'un gel actif | RB-5 |
| `noortrace_controle_integrite` | `increase(noortrace_integrity_check_failures_total{check!="configuration_worm"}[1h]) > 0` | — | critique | CT-2 §17.4 Contrôle d'intégrité en échec | RB-1, RB-5 |
| `noortrace_gel_leve` | `increase(noortrace_journal_lignes_total{event="worm_legal_hold_observed",detail="levee"}[1d]) > 0` | — | mineure | CT-2 §17.4 Gel levé | aucun (rapprocher d'EX-11.16) |
| `noortrace_horloge_ecart` | `abs(noortrace_clock_skew_ms) > 1000` (`clock.warn_skew_ms`, défaut 1 000) | — | mineure (critique par `noortrace_mode_degrade_critique`) | CT-2 §17.4 Horloge | RB-6 |
| `noortrace_definition_outil_changee` | `increase(noortrace_tool_definition_changes_total[1h]) > 0` | — | mineure | CT-2 §17.4 Définition d'outil changée | aucun |
| `noortrace_fourche` | `increase(noortrace_journal_lignes_total{event="journal_fork"}[5m]) > 0` | — | critique | CT-2 §17.4 Fourche | RB-2 |
| `noortrace_panne_apres_relais` | `increase(noortrace_calls_executed_not_durable_total[5m]) > 0` | — | critique | CT-2 §17.4 Panne après relais | RB-1 |
| `noortrace_relais_refuse` | `increase(noortrace_approval_relays_refused_total[5m]) > 0` | — | critique | CT-2 §17.4 Relais refusé ou identifiant en collision | RB-8 |
| `noortrace_remise_refusee` | `increase(noortrace_approval_remises_refused_total[1h]) > 0` | — | majeure | CT-2 §17.4 Remise refusée | RB-8 |
| `noortrace_politique_invalide_au_charger` | `increase(noortrace_journal_lignes_total{event="approval_policy_invalid"}[1h]) > 0` (nom de ligne proposé, PD-10) | — | majeure | CT-2 §17.4 Remise refusée (`politique_invalide`, CT-2 EX-7.15) | aucun |
| `noortrace_budget_redaction` | `increase(noortrace_redaction_budget_exceeded_total[1h]) > 0` | — | mineure | CT-2 §17.4 Budget de rédaction | aucun |
| `noortrace_budget_redaction_bloquant` | `increase(noortrace_calls_blocked_total{reason="redaction"}[1h]) > 0` | — | majeure | CT-2 §17.4 Budget de rédaction | aucun |
| `noortrace_cle_mac_relais` | `increase(noortrace_journal_lignes_total{event="relay_mac_key_mismatch"}[5m]) > 0` | — | critique | CT-2 §17.4 Clé du MAC de relais | RB-2 |
| `noortrace_quota_hote` | `increase(noortrace_calls_blocked_total{code="-31013",reason="quota"}[5m]) > 0` | — | mineure | CT-2 §17.4 Quota d'un hôte | aucun |
| `noortrace_otel_refusee` | `increase(noortrace_otel_requests_total{status=~"429\|503"}[5m]) > 0` | — | majeure | CT-2 §17.4 Ingestion OpenTelemetry refusée | aucun |
| `noortrace_otel_spans_rejetes` | `increase(noortrace_otel_spans_total{issue="rejete"}[1h]) > 0` | — | mineure | CT-2 §17.4 Spans rejetés | aucun |
| `noortrace_otel_retard` | `histogram_quantile(0.99, sum by (le) (rate(noortrace_otel_reception_lag_ms_bucket[15m]))) > 60000` | — | mineure | CT-2 §17.4 Retard de réception | aucun |
| `noortrace_otel_conventions` | `sum by (source) (increase(noortrace_otel_spans_total[1h])) > 0 and sum by (source) (increase(noortrace_otel_spans_total[1h])) == sum by (source) (increase(noortrace_otel_spans_total{issue="ignore",reason="hors_genai"}[1h]))` | — | mineure | CT-2 §17.4 Conventions OpenTelemetry renommées | aucun |
| `noortrace_otel_conflits` | `increase(noortrace_otel_conflicts_total[1h]) > 0` | — | mineure | CT-2 §17.4 Span OpenTelemetry rejoué | aucun |
| `noortrace_latence` | `histogram_quantile(0.99, sum by (le) (rate(noortrace_relay_latency_ms_bucket[15m]))) > 50` | — | mineure | CT-2 §17.4 Latence | aucun |
| `noortrace_disque_ligne` | `increase(noortrace_journal_lignes_total{event="disk_low"}[5m]) > 0` | — | majeure | CT-2 §17.4 Disque | RB-1 |
| `noortrace_disque_espace` | `node_filesystem_avail_bytes{mountpoint="<racine>"} < 2147483648` (2 × `min_free_bytes`, défaut 1 GiB) | — | majeure | CT-2 §17.4 Disque | RB-1 |
| `noortrace_gel_pose_en_retard` | `time() - noortrace_journal_derniere_ligne_s{source="gel",event="worm_legal_hold_set"} > 7200` (seulement pour un support sans mode Compliance validé, EX-11.17) | — | majeure (gravité fixée par CT-8) | CT-2 §12.6 (tâche de `poser` et alerte de retard) | RB-5 |

Les expressions des histogrammes sont la forme exécutable des conditions de
CT-2 §17.4, qui écrivent `histogram_quantile(0.99,
noortrace_relay_latency_ms)` ; la forme `rate(..._bucket[15m])` dit « sur 15
min ». La condition « sur l'instance attendue active » de l'alerte « Bail »
est l'étiquette `role` d'EX-10.4.

### 10.5 Règles du composant d'ancrage

Les bornes des histogrammes `noortrace_anchoring_d_*_s` ne sont pas fixées
par CT-5 ; CT-8 les fixe pour que `inclusion_alert_s` (défaut 60) en soit
une : 1, 2, 5, 10, 30, 60, 120, 300, 600, 1 800, 3 600, 7 200 secondes
(EX-10.6 les régénère si `inclusion_alert_s` change).

| Règle | Expression | Pendant | Gravité | Exigence | Runbook |
|---|---|---|---|---|---|
| `noortrace_ancrage_en_attente` | `increase(noortrace_journal_lignes_total{event=~"anchor_pending\|registry_pending"}[1h]) > 0` | — | mineure (gravité fixée par CT-8 ; le retard est majeur par `noortrace_ancre_en_retard`) | CT-5 §8.9 `anchor_pending`, `registry_pending` | RB-3 |
| `noortrace_ancrage_point_en_retard_exterieur` | `increase(noortrace_journal_lignes_total{event="checkpoint_anchor_late",detail="exterieur"}[1h]) > 0` | — | majeure | CT-5 §8.9 `checkpoint_anchor_late` | RB-4 |
| `noortrace_ancrage_point_en_retard_interne` | `increase(noortrace_journal_lignes_total{event="checkpoint_anchor_late",detail="interne"}[1h]) > 0` | — | mineure | CT-5 §8.9 `checkpoint_anchor_late` | RB-4 |
| `noortrace_ancrage_inclusion_lente` | `increase(noortrace_anchoring_d_registre_s_count[1h]) - increase(noortrace_anchoring_d_registre_s_bucket{le="60"}[1h]) > 0` | — | mineure | CT-5 §8.9 `inclusion_late` | RB-7 |
| `noortrace_ancrage_inclusion_lente_repetee` | même expression `> 3` | — | majeure (« si répétée » : plus de trois fois par heure, seuil fixé par CT-8) | CT-5 §8.9 `inclusion_late` | RB-7 |
| `noortrace_ancrage_prestataire_injoignable` | `noortrace_anchoring_last_success_age_s{kind=~"jeton_periode\|jeton_point"} > 900 and on (kind, provider) increase(noortrace_anchoring_attempts_total[15m]) > 0` | — | majeure (pour tout prestataire : CT-5 ne la prescrit que pour le principal, CT-8 ne distingue pas les rôles) | CT-5 §8.9 `prestataire_injoignable` | RB-4 |
| `noortrace_ancrage_prestataires_epuises_periode` | `noortrace_anchoring_queue_entries{kind="jeton_periode",state="a_reprendre"} > 0 and on () increase(noortrace_anchoring_attempts_total{kind="jeton_periode",outcome="echec_permanente"}[1h]) > 0` | — | critique | CT-5 §8.9 `prestataires_epuises` (période) | RB-4 |
| `noortrace_ancrage_prestataires_epuises_point` | `increase(noortrace_journal_lignes_total{event="anchor_refused",detail="autre"}[1h]) > 0` | — | majeure | CT-5 §8.9 `prestataires_epuises` (point) | RB-4 |
| `noortrace_ancrage_file` | `increase(noortrace_journal_lignes_total{event=~"anchor_queue_full\|anchor_queue_truncated_line\|anchor_queue_write_failed"}[5m]) > 0 or increase(noortrace_journal_lignes_total{event="anchoring_queue_rebuilt",detail="recree"}[5m]) > 0` | — | critique | CT-5 §8.9 `file_pleine`, `file_perdue` | RB-3 |
| `noortrace_ancrage_ots_abandon` | `noortrace_anchoring_ots_pending_age_s > 1209600` (`give_up_after_s`, défaut 14 jours) | — | majeure | CT-5 §8.9 `ots_give_up` | RB-3 |
| `noortrace_ancrage_ordre` | `increase(noortrace_journal_lignes_total{event="ordre_ancres_non_respecte"}[1d]) > 1` | — | mineure | CT-5 §8.9 `ordre_ancres_non_respecte` répété | aucun |
| `noortrace_ancrage_empreinte_squattee` | `increase(noortrace_journal_lignes_total{event="anchor_refused",detail="empreinte_squattee"}[1h]) > 0` | — | critique | CT-5 §8.9 `empreinte_squattee` | RB-7 |
| `noortrace_ancrage_horloge_suspecte` | `increase(noortrace_journal_lignes_total{source="acquisitions",detail="horloge_suspecte"}[1h]) > 0` | — | mineure | CT-5 §8.9 `horloge_suspecte` | RB-6 |
| `noortrace_ancrage_revoque` | `increase(noortrace_journal_lignes_total{source="acquisitions",detail="revoque"}[1h]) > 0` | — | critique | CT-5 §8.9 `revoque` | RB-4 |
| `noortrace_ancrage_reponse_tardive_promue` | `increase(noortrace_journal_lignes_total{source="acquisitions",detail="reponse_tardive_promue"}[1h]) > 0` | — | mineure | CT-5 §8.9 `reponse_tardive_promue` | RB-4 |
| `noortrace_ancrage_point_manquant` | `increase(noortrace_journal_lignes_total{event="point_manquant"}[5m]) > 0` | — | majeure | CT-5 §8.9 `point_manquant` | RB-1 |
| `noortrace_ancrage_jeton_anterieur` | `increase(noortrace_journal_lignes_total{event="jeton_anterieur_au_point"}[1h]) > 0` (ligne proposée, PD-11) | — | majeure | CT-5 §8.9 `jeton_anterieur_au_point` | RB-6 |
| `noortrace_ancrage_contresignature_tardive` | `increase(noortrace_journal_lignes_total{event="contresignature_tardive"}[1h]) > 0` (ligne proposée, PD-11) | — | mineure | CT-5 §8.9 `contresignature_tardive` | RB-4 |
| `noortrace_ancrage_volume` | `sum(increase(noortrace_anchoring_attempts_total[1h])) > 2 * <A_h>` | — | majeure | CT-5 §8.9 volume de requêtes | RB-8, après ventilation (RB-4) |

`<A_h>` est le nombre nominal de requêtes d'ancrage par heure d'un journal,
tiré des sorties du calculateur de la section 9 pour la configuration
(comptage de CT-5 EX-4.11) : (`tokens_qualified_per_year` +
`tokens_other_per_year` + `ots_submissions_per_year` +
`registry_anchors_per_year_max` + `registry_closures_per_year`) /
`hours_per_year` ; `regles.mjs` le reçoit du calculateur. Pendant la panne d'un
prestataire et le rattrapage qui la suit, les nouveaux essais dépassent
naturellement 2 × `<A_h>` : avant d'ouvrir RB-8, l'exploitant ventile
`noortrace_anchoring_attempts_total` par prestataire et par issue ; des échecs
vers le prestataire en panne suivis de succès de rattrapage relèvent de RB-4,
des succès en excès hors panne de RB-8.

### 10.6 Règles du registre et du nœud

**EX-10.7** La sonde de référence `scripts/deploiement/sonde.mjs` (à
produire, lot suivant) interroge, à chaque passage (défaut 15 s), `GET
http://127.0.0.1:8601/v0/etat` du service d'approbation (CT-3 EX-12.12 ; port
d'état d'EX-3.5), qu'elle expose en
`noortrace_approbation_pret` (`ready`, 1 ou 0),
`noortrace_approbation_tickets_ouverts` (`open_tickets`) et
`noortrace_approbation_jeu_lu_age_s` (âge de `set_read_at`), et chaque point
RPC déclaré
(validateurs joignables du client, relais) avec `eth_blockNumber` à travers
le relais (CT-4 EX-10.5 : la sonde `/healthz` d'un relais ne dit pas que le
meneur répond, R8-F23) et
`eth_getBlockTransactionCountByNumber("pending")` (taille de la mempool,
seule lecture offerte par noorcore, `core/rpc/jsonrpc_dispatch.go:2147-2152`,
R8-F44 ; ce qu'elle compte exactement n'est pas établi, R8 NV-3), lit le
solde de chaque expéditeur du manifeste d'instance (CT-4 EX-8.18), et expose
`noortrace_registre_sonde_ok{target}` (1 ou 0),
`noortrace_registre_hauteur{target}`, `noortrace_registre_mempool{target}`
et `noortrace_registre_solde_wei{sender}` (adresse publique de
l'expéditeur, jamais un compte de client). Elle ne soumet aucune
transaction. Sa partie registre se teste sur le réseau de développement
(`chain/scripts/dev-net.sh start`).

| Règle | Expression | Pendant | Gravité | Exigence | Runbook |
|---|---|---|---|---|---|
| `noortrace_registre_cible_muette` | `up{job="noorcore"} == 0` | 2m | critique | reprise de `NoorcoreTargetDown` (`ops/observability/alerts/noorcore.rules.yml` l. 37-43, R8-F42) | RB-7 |
| `noortrace_registre_sonde` | `noortrace_registre_sonde_ok == 0` | 2m | critique | CT-4 EX-10.5 | RB-7 |
| `noortrace_registre_hauteur_figee` | `changes(noortrace_registre_hauteur[5m]) == 0` | — | majeure (gravité fixée par CT-8 ; le registre ne bloque jamais l'enregistreur, CT-4 EX-8.1) | CT-4 §10 | RB-7 |
| `noortrace_registre_equivocation` | `increase(noor_bft_equivocations_total[5m]) > 0` | — | critique | CT-4 EX-10.8, §13 | RB-7 |
| `noortrace_registre_mempool` | `noortrace_registre_mempool > <M>` | 5m | majeure | CT-4 EX-4.20, EX-10.8 ; CT-7 MN-55 | RB-7 |
| `noortrace_registre_sous_tarif` | `increase(noortrace_journal_lignes_total{event="registry_send_refused",detail="transaction_underpriced"}[1h]) > 0` (ligne proposée, PD-12) | — | majeure | CT-4 §4.5, EX-10.8 | RB-7 |
| `noortrace_registre_cloture_non_soumise` | `noortrace_anchoring_last_success_age_s{kind="ancre_registre_periode"} > 90000` (une période de 3 600 s plus 24 h) | — | majeure | CT-4 EX-8.3 | RB-7 |
| `noortrace_registre_capture_en_retard` | `noortrace_anchoring_last_success_age_s{kind="ancre_registre_periode"} > 7200` (une demande n'est `obtenue` qu'après la capture, CT-5 EX-8.10) | — | majeure | CT-4 EX-9.4 | RB-7 |
| `noortrace_registre_solde_bas` | `noortrace_registre_solde_wei < <S>` | — | majeure | CT-4 EX-8.18 | aucun |
| `noortrace_registre_examen_requis` | `increase(noortrace_journal_lignes_total{source="registre",detail="examen_requis"}[1d]) > 0` | — | majeure | CT-4 EX-4.20 | aucun |
| `noortrace_registre_marge_retention` | `increase(noortrace_journal_lignes_total{source="registre",detail="marge_retention_basse"}[1d]) > 0` | — | majeure | CT-4 EX-9.6 | RB-7 |

`<M>` est la moitié de `-txpool-max-pending` du nœud (R8-F45), cible « à
mesurer (CT-9, porte 2) » ; `<S>` est le seuil de recomplément de la
provision de l'expéditeur (CT-4 4.5, EX-4.19), lu dans le manifeste
d'instance par `regles.mjs`.

### 10.7 Règles de l'hôte, de l'exploitation et du mode observation

| Règle | Expression | Pendant | Gravité | Exigence | Runbook |
|---|---|---|---|---|---|
| `noortrace_hote_disque` | `(node_filesystem_avail_bytes{fstype!~"tmpfs\|overlay"} / node_filesystem_size_bytes{fstype!~"tmpfs\|overlay"}) < 0.10` | 10m | majeure | reprise de `HostDiskSpaceLow` (l. 11-17, R8-F42) | RB-1 |
| `noortrace_hote_memoire` | `(node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) < 0.10` | 10m | majeure | reprise de `HostMemoryPressure` (l. 19-25) | aucun |
| `noortrace_hote_processeur` | `(1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m]))) > 0.90` | 15m | mineure | reprise de `HostCPUHigh` (l. 27-33) | aucun |
| `noortrace_approbation_non_pret` | `noortrace_approbation_pret == 0` (sonde de `GET <base>/v0/etat`, champ `ready`) | 5m | majeure (gravité fixée par CT-8) | CT-3 EX-12.12 | RB-1 |
| `noortrace_sauvegarde_en_retard` | `time() - noortrace_proces_verbal_dernier_s{kind="sauvegarde"} > <RPO>` | — | majeure | CT-8 EX-11.5 | aucun |
| `noortrace_exercice_restauration_en_retard` | `time() - noortrace_proces_verbal_dernier_s{kind="exercice_restauration"} > 34560000` (400 jours) | — | mineure | CT-8 EX-11.8 | aucun |
| `noortrace_acces_non_declare` | `increase(noortrace_journal_lignes_total{source="consultations",detail="inconnu"}[1h]) > 0` | — | majeure | CT-8 EX-11.20 (CA-6) | RB-8 |
| `noortrace_consultations_muettes` | `time() - max(noortrace_journal_derniere_ligne_s{source="consultations"}) > 86400` | — | majeure | CT-8 EX-11.19 | aucun |
| `noortrace_journal_illisible` | `increase(noortrace_journal_illisibles_total[1h]) > 0` | — | majeure | CT-8 EX-10.5 | aucun |
| `noortrace_mode_observation_actif` | `noortrace_observation_mode == 1` | — | mineure (rappel permanent : aucun appel n'est bloqué) | CT-2 §17.4 Mode observation actif (EX-17.8) ; CT-8 EX-12.8 | aucun |
| `noortrace_observation_pertes` | `increase(noortrace_events_lost_total[5m]) > 0` | — | majeure | CT-2 §17.4 Pertes en mode observation (EX-17.8) ; CT-2 EX-14.16 | RB-1 |

`<RPO>` est le RPO retenu par le client pour l'archive de sauvegarde (ligne
« Pièces non copiées » d'EX-11.5 ; cadence d'EX-11.24, un jour par défaut, soit
86 400), en secondes ; les autres RPO de la table d'EX-11.5 ont leurs propres
règles (par exemple `noortrace_copie_worm_en_retard` pour les segments
fermés).

### 10.8 Tableau de bord

**EX-10.8** Le tableau de référence
`deploiement/observabilite/tableau-noortrace.json`, de la forme du tableau
de noorchain-core (`uid`, panneaux, R8-F42), a un panneau par ligne
ci-dessous ; chaque expression ne nomme que des métriques de 10.2 et 10.3
(SV-7).

| Rangée | Panneaux (expressions) |
|---|---|
| Capture | événements par sorte et statut (`rate(noortrace_events_total[5m])`) ; latence ajoutée p50 et p99 (`noortrace_relay_latency_ms`) ; appels bloqués par raison |
| Durabilité | `fdatasync` p99 ; taille du groupe ; `noortrace_pending_events` ; `noortrace_degraded` par raison ; époque du bail par instance |
| Copies WORM | `noortrace_worm_copy_pending` ; âge du dernier relevé ; versions non conformes ; gels actifs |
| Ancrage | `noortrace_anchor_pending` par ancre ; `noortrace_anchoring_window_s` ; `d_jeton` p99 ; demandes par état |
| Registre | hauteur par cible ; mempool par cible ; équivocations ; soldes des expéditeurs |
| Approbation | `noortrace_approval_signals_total` par état ; remises et relais refusés ; `noortrace_approbation_pret` |
| Mode observation | `noortrace_observation_mode` ; marques par décision (`noortrace_observation_marks_total`, CT-2 EX-17.8) ; `noortrace_events_lost_total` |
| Hôte | processeur, mémoire, disque de `<racine>` (les trois panneaux du tableau de noorchain-core) |

### 10.9 Relectures hors du composant

**EX-10.9** Trois relectures DOIVENT tourner hors du composant qu'elles
contrôlent, sous l'identité qu'EX-10.3 décrit, et exposer leur résultat comme
une jauge `noortrace_releve_externe_ok{check}` (1 ou 0), alertée en critique
quand elle vaut 0 ou qu'elle n'a pas été mise à jour depuis 2 jours :
`registre_gels` (la relecture du registre des gels et de l'état `on` des
versions gelées par le rôle Lecteur, CT-2 EX-17.7 : `noortrace-ctl worm gel
etat` sous les identifiants du lecteur), `console` (la comparaison
quotidienne des SHA-256 de la page et des scripts de la console avec les
valeurs publiées hors du serveur, CT-7 EX-3.9), `copie_exploitation` (la
relecture de la série des fichiers du journal d'exploitation copiés sous
`<prefix>exploitation/`, 11.11).

### 10.10 Vérifications SV- et lacunes

**EX-10.10** Les règles se vérifient sans les composants : l'intégration
continue télécharge l'archive de Prometheus 3.5.0 pour Linux amd64 depuis la
page des versions du projet, compare son SHA-256 à
`e811827af26d822afb09a4f28314f61b618b12cff5369835a67f674d8b46f39a` (valeur
relevée le 2026-10-27 sur l'archive téléchargée et égale à celle du fichier
`sha256sums.txt` publié avec elle), puis exécute `promtool check rules` sur
le fichier de règles et `promtool test rules` sur
`deploiement/observabilite/tests-regles.yml` (R8-F53), qui donne pour chaque
règle une série qui la déclenche et une qui ne la déclenche pas. `promtool`
n'a pas été exécuté pour cette rédaction (R8 NV-4), et l'étape n'est pas dans
l'intégration continue tant que ces fichiers ne sont pas produits (lot
suivant).

**EX-10.11** Vérifications statiques, à exécuter par `test/deploiement.test.js`
sans réseau ; SV-1 à SV-7 attendent les fichiers du lot suivant, SV-8 est
exécutée :

| Id | Vérification |
|---|---|
| SV-1 | Chaque alerte prescrite (liste lue dans les tables de CT-2 §17.4 et de CT-5 §8.9, et les EX de CT-4 nommés par EX-10.1) a au moins une règle dont l'étiquette `exigence` la nomme ; chaque règle de 10.4 à 10.7 est dans le fichier, et rien d'autre. |
| SV-2 | Chaque nom de métrique d'une expression est dans 10.3, EX-10.7, EX-10.9, CT-2 §17.2, CT-5 EX-8.15, la révision 0.6 de CT-2 (EX-17.8), la liste `noor_*` relevée dans `core/metrics/metrics.go` et `snapshot.go` (R8-F43), `up` ou `node_*` des trois règles de l'hôte. |
| SV-3 | Étiquettes et annotations d'EX-10.2 : ensemble exact, `severity` énumérée, aucune autre étiquette ; noms de règles uniques, de la forme `^noortrace_[a-z0-9_]+$`. |
| SV-4 | Le fichier s'analyse en YAML ; chaque règle a `alert`, `expr`, `labels`, `annotations`, et `for` quand la colonne « Pendant » n'est pas vide. |
| SV-5 | L'extracteur, rejoué sur `spec/vecteurs/ct-8/supervision/journaux/`, rend exactement `attendu.prom` (compteurs, jauges, `detail` de la table de 10.3). |
| SV-6 | `regles.mjs` sans argument écrit le fichier du dépôt octet pour octet ; avec la configuration de `spec/vecteurs/ct-8/supervision/configuration-modifiee.json`, il écrit `regles-attendues.yml`. |
| SV-7 | Chaque expression du tableau ne nomme que des métriques admises par SV-2. |
| SV-8 | Chaque runbook RB-1 à RB-8 de la section 10 a les sept rubriques d'EX-10.13, dans cet ordre (lecture du texte de CT-8). |

**EX-10.12** Lacunes de nommage, écrites comme propositions sans modifier les
spécifications visées (aucune n'est appliquée par la révision 0.6 de CT-2,
qui reste minimale) :

| Id | Adressée à | Proposition | Motif |
|---|---|---|---|
| PD-10 | CT-2 (§17.3, EX-9.5) | Fixer les noms des membres de `data` des lignes `worm_lock_config_check` (verdict), `worm_lock_check` (raisons, dont « gel attendu absent »), `worm_legal_hold_observed` (règle de garde violée, `kind`), et nommer la ligne consignée pour `politique_invalide` au `charger` (CT-2 EX-7.15) ; exposer en métrique le compte des lignes par `event` | Règles de 10.4 exprimables sans hypothèse de nom ; 10.3 |
| PD-11 | CT-5 (§8.9) | Nommer les lignes `jeton_anterieur_au_point`, `contresignature_tardive`, et les membres de `data` de `anchor_refused` (code), `anchoring_queue_rebuilt` (`recreated` existe), `checkpoint_anchor_late` (rôle du prestataire) | Règles de 10.5 |
| PD-12 | CT-4 et CT-5 | Consigner chaque refus d'envoi au registre (ligne `registry_send_refused`, raison dont `transaction_underpriced`) par l'outil du registre et le composant d'ancrage | CT-4 EX-10.8 : l'erreur n'est visible qu'en réponse RPC (R8-F44) |

### 10.11 Runbooks d'incident : principe et gabarit

Un runbook dit à l'exploitant quoi faire quand une alerte de la section 10
se lève, et ce que l'incident change à la preuve. La forme est reprise des
runbooks de noorchain-core, lus et cités : des « operational / procedural
documents » qui « describe step-by-step validated procedures, gates, and
evidence expectations » (`docs/runbooks/INDEX.md` l. 5-7, R8-F39) ; une
discipline « 1 commande → 1 gate → étape suivante »
(`RUNBOOK-M27D-OPS.md` l. 24-30) ; des playbooks d'incident par symptôme
(l. 283-331) ; un « evidence pack » (annexe B, l. 576-606) ; un
après-incident « timeline, impact, RCA, remediation » (l. 332-341).
NOORTRACE n'en reprend jamais une restauration du répertoire de données d'un
validateur, que ces runbooks pratiquent (R8-F40, R8-F41) et que CT-4 EX-10.9
interdit (R8 conséquence 5). Les durées ne sont pas données : aucune n'est
mesurée (CT-9, porte 2).

**EX-10.13** Chaque runbook RB-n a ces sept rubriques, dans cet ordre (SV-8) :
**Détection** (règles de la section 10 et lignes de journal qui l'ouvrent) ;
**Impact sur la preuve** (ce qui manque ou devient déclaratif dans un
dossier, et pour quelle période) ; **Invariants** (ce qui ne se fait jamais
pendant l'incident) ; **Pas** (numérotés ; chacun a sa commande et sa porte,
la vérification qui permet de passer au suivant) ; **Vérification de
sortie** (l'état qui clôt l'incident) ; **Événements journalisés** (lignes
du journal d'exploitation et événements de la chaîne que l'incident
produit) ; **Après l'incident** (pièces et suites).

**EX-10.14** Une commande à la fois : le pas suivant ne commence qu'après la
porte du précédent. Les commandes sont celles des spécifications
(`noortrace-ctl reload`, `noortrace-ctl clock --accept`,
`noortrace-ctl close-period --now`, `noortrace-ctl worm releve`,
`noortrace-ctl worm gel …`, `noortrace validate-config` de CT-2) et celles
que CT-8 ajoute, à construire avec l'enregistreur sauf mention :

| Commande | Effet | Disponible |
|---|---|---|
| `noortrace-ctl etat` | rend `GET /healthz` et `/readyz` (CT-2 EX-17.1) et l'époque du bail | phase 2 |
| `node scripts/deploiement/verifier-journal.mjs <répertoire du journal> --cles <fichier> [--json]` | vérifie la chaîne des segments (E-1 à E-8, C-1 à C-3 de CT-1, en-têtes de CT-2 EX-12.3), la continuité d'un segment à l'autre et chaque manifeste présent ; rend la synthèse d'EX-11.7 (`verification-journal-v0`) | existe (outil de référence de CT-8, EX-11.7 ; rejoué sur `spec/vecteurs/ct-8/journaux/`) |
| `node scripts/deploiement/proces-verbal.mjs verifier <fichier> [--racine <répertoire>] [--cles <fichier>] [--json]` | vérifie un procès-verbal d'exploitation (PV-1 à PV-10, 11.9) | existe (rejoué sur `spec/vecteurs/ct-8/proces-verbaux/`) |
| `node scripts/deploiement/consultations.mjs verifier <fichier> [--sources <répertoire>] [--json]` | vérifie un journal des consultations (CA-1 à CA-6, 11.10) | existe (rejoué sur `spec/vecteurs/ct-8/consultations/`) |
| `noortrace-ctl worm restaurer <clé d'objet> --version <id>` | relit une version de la copie WORM, compare son SHA-256 au registre des copies et l'écrit dans un répertoire neuf, jamais sur l'original | phase 2 |
| `noortrace-ctl cle rotation-urgence` | exécute les pas de CT-2 EX-11.16 dans leur ordre | phase 2 |
| `node scripts/verify/dossier.mjs <dossier> --ancres <fichier>` | vérifie un dossier (CT-6) | existe (`scripts/verify/README.md` l. 374-417) |

**EX-10.15** Chaque incident produit un paquet d'incident, rangé avec le
journal sous `exploitation/incidents/<identifiant>/` et copié sur le support
WORM sous `<prefix>exploitation/incidents/` : la chronologie (UTC), les
alertes reçues, les sorties des portes, les procès-verbaux produits (11.9), les
rapports du vérificateur ; il ne contient ni pièce, ni secret, ni donnée
d'argument (règle de CT-2 EX-9.6, reprise). L'après-incident nomme la cause,
l'impact sur la preuve, la correction et le test de CT-9 qui la couvre.

### 10.12 RB-1 Écrivain arrêté

**EX-10.16** Le démon n'écrit plus : stockage indisponible, disque plein,
segment corrompu, démon arrêté.

- **Détection.** `noortrace_mode_degrade_majeur` (raison `stockage` ou
  `attente`), `noortrace_disque_*`, `noortrace_attente_*`,
  `noortrace_controle_integrite` ; lignes `storage_unavailable`,
  `segment_corrupted`, `segment_truncated`, `disk_low`,
  `pending_limit_reached` ; `noortrace-ctl etat` (phase 2, EX-10.14) muet.
- **Impact sur la preuve.** Aucun appel d'écriture n'est relayé sans
  événement durable (CT-2 EX-14.2) ; les lectures passantes ont des
  événements en attente, scellés plus tard avec leur `ts` de capture (CT-2
  EX-14.10) ; au-delà des bornes de CT-2 EX-14.9, les lectures sont bloquées
  aussi. En mode observation (section 12), rien n'est bloqué et les
  événements au-delà des bornes sont perdus et comptés (CT-2 EX-14.16).
- **Invariants.** Ne jamais modifier, tronquer ni supprimer à la main une
  ligne d'un segment ; ne jamais copier un segment de la copie WORM
  par-dessus l'original ; ne jamais lancer un second démon sur le même
  répertoire.
- **Pas.**
  1. `noortrace-ctl etat` ; porte : la raison est connue (`stockage`,
     `attente`) ou le démon ne répond pas.
  2. Si `disk_low` : libérer ou agrandir le volume, jamais en supprimant un
     fichier sous `storage.root` ; porte : espace libre ≥ 2 ×
     `min_free_bytes`.
  3. Si `segment_corrupted` (CT-2 EX-12.11) : arrêter le démon, placer le
     répertoire du journal hors service (renommage), puis appliquer la reprise
     de 11.4 chemin B (désigné ici, sans passer d'abord par le chemin A :
     l'archive quotidienne du chemin A est prise sur l'original local, dont un
     segment est corrompu, et peut porter la corruption, alors que chaque
     version WORM a été copiée à la fermeture de son segment et inscrite au
     registre des copies avec son SHA-256, CT-2 EX-12.16 et EX-12.29, ce qui se
     contrôle fichier par fichier, RB-5 pas 2) ; les intentions, l'attente, les
     approbations et les pièces sans `copy_pieces`, qui n'ont pas de copie WORM,
     sont alors perdues et listées au procès-verbal `restauration` ; porte :
     `verifier-journal.mjs` rend `valide` sur le répertoire reconstruit.
  4. Redémarrer ; porte : `noortrace-ctl etat` rend `ok`, la ligne
     `pending_flushed` est consignée si des événements attendaient.
  5. Exporter et vérifier le dossier du premier événement scellé après la
     reprise ; porte : `dossier.mjs` rend le code 0.
- **Vérification de sortie.** `noortrace_degraded` vaut 0 pour toutes les
  raisons, `noortrace_pending_events` vaut 0, `verifier-journal.mjs` rend
  `valide`.
- **Événements journalisés.** `degraded_enter`, `degraded_exit`,
  `storage_unavailable`, `segment_truncated` ou `segment_corrupted`,
  `pending_flushed` ; dans la chaîne : événements de reprise et événements
  en attente (CT-2 EX-9.8), jamais un événement « panne » (CT-2 EX-14.7).
- **Après l'incident.** Procès-verbal `restauration` si le chemin B a servi
  (11.9) ; cause du disque plein rapprochée du dimensionnement (section 9).

### 10.13 RB-2 Bail perdu

**EX-10.17** L'instance active perd son bail, ou deux instances se disputent
un journal.

- **Détection.** `noortrace_bail_non_detenu`, `noortrace_bail_renouvellement`,
  `noortrace_fourche`, `noortrace_cle_mac_relais` ; lignes `lease_lost`,
  `lease_lost_after_write`, `lease_standby`, `journal_fork`,
  `relay_mac_key_mismatch`.
- **Impact sur la preuve.** Pendant au plus `lease.ttl_ms`, aucun écrivain ;
  les appels en vol deviennent des événements de reprise ; le segment ouvert
  d'un volume perdu est perdu s'il n'a pas été copié (CT-2 §13.5) ; une
  fourche donne deux événements signés de même `seq`, que la relecture
  suivante arrête (CT-2 EX-13.10).
- **Invariants.** Ne jamais rendre le bail à une instance qui n'a pas relu
  le journal ; ne jamais monter le volume sur deux hôtes (CT-2 EX-13.2).
- **Pas.**
  1. Identifier l'instance qui détient l'époque la plus haute :
     `noortrace_lease_epoch` par instance ; porte : une seule instance a une
     époque non nulle.
  2. Rendre le stockage de l'ancienne active inaccessible en écriture par le
     moyen de `lease.fencing` (détachement ou réservation, CT-2 EX-13.10)
     si la bascule ne l'a pas fait ; porte : l'ancien hôte ne voit plus le
     volume.
  3. Basculer l'adresse de service (moyen de la topologie, EX-3.11) vers
     la nouvelle active ; porte : `noortrace-ctl etat` (phase 2, EX-10.14)
     rend `ok` sur l'adresse de service.
  4. Si `journal_fork` : ne rien redémarrer avant d'avoir consigné la taille
     finale des fichiers d'époque inférieure et relu le journal ; porte :
     `verifier-journal.mjs` nomme le `seq` de la fourche.
  5. Si `relay_mac_key_mismatch` : corriger la référence du secret CLE-16
     sur la passive (même clé pour toutes les instances, CT-7 §4.2) puis
     redémarrer la passive ; porte : la passive est `standby` sans la ligne.
- **Vérification de sortie.** Une seule instance active, `role="active"`
  porte l'époque la plus haute, `verifier-journal.mjs` rend `valide`.
- **Événements journalisés.** `lease_acquired`, `lease_lost`,
  `lease_standby`, `journal_fork` ; dans la chaîne : événements de reprise
  des intentions (CT-2 12.5) ; un événement de politique au démarrage si
  l'ensemble a changé (CT-2 EX-9.2).
- **Après l'incident.** Une fourche est un incident de sécurité : paquet
  d'incident remis au client et aux réviseurs des journaux concernés ;
  procès-verbal `restauration` si le chemin B a servi.

### 10.14 RB-3 Ancrage dégradé

**EX-10.18** Les ancres d'une période ou d'un point n'arrivent pas, ou la file
du composant d'ancrage est perdue.

- **Détection.** `noortrace_ancre_en_retard`, `noortrace_ancrage_en_attente`,
  `noortrace_ancrage_file`, `noortrace_ancrage_ots_abandon` ; lignes
  `anchor_pending`, `registry_pending`, `anchoring_queue_rebuilt`,
  `anchor_queue_*`.
- **Impact sur la preuve.** Rien ne bloque la capture (CT-2 §14.2, CT-5
  EX-4.8) ; les dossiers des périodes concernées n'ont pas encore leurs
  ancres ; sans l'ancre au registre, ils ne passent pas le contrôle 8 (CT-4
  EX-8.3, CT-6 EX-11.10) ; une file perdue ne fait perdre que du temps
  (CT-5 EX-8.12).
- **Invariants.** Ne jamais supprimer ni réécrire un fichier de la file
  (CT-5 EX-8.5) ; ne jamais créer à la main une demande.
- **Pas.**
  1. Lire `noortrace_anchoring_queue_entries` par sorte et état ; porte :
     la sorte en retard est connue.
  2. Si un prestataire est en cause : RB-4 ; si le registre : RB-7 ;
     porte : la cause est dans un autre runbook ou levée.
  3. Si la file est perdue ou tronquée : redémarrer le composant, qui
     confronte le stockage aux demandes et recrée celles qui manquent (CT-5
     EX-8.12) ; porte : ligne `anchoring_queue_rebuilt`. La clôture
     anticipée (`noortrace-ctl close-period --now`) n'est admise qu'en
     développement (CT-2 EX-19.4) : elle n'est jamais un pas de ce runbook.
- **Vérification de sortie.** `noortrace_anchor_pending` vaut 0 pour les
  trois ancres ; `noortrace_anchoring_window_s` revient sous `c_T`.
- **Événements journalisés.** `anchoring_started`, `anchoring_queue_rebuilt`,
  `anchor_retry`, `anchor_fallback`, `period_timestamped`, `ots_complete`.
- **Après l'incident.** Réexporter les dossiers des périodes concernées
  quand leurs ancres sont là (CT-5 EX-6.7).

### 10.15 RB-4 Prestataire d'horodatage injoignable

**EX-10.19** Le prestataire RFC 3161 principal, le secours ou tous les
calendriers OpenTimestamps ne répondent pas, ou un jeton est révoqué.

- **Détection.** `noortrace_ancrage_prestataire_injoignable`,
  `noortrace_ancrage_prestataires_epuises_*`, `noortrace_ancrage_revoque`,
  `noortrace_ancrage_reponse_tardive_promue`,
  `noortrace_ancrage_point_en_retard_*` ; enregistrements d'acquisition.
- **Impact sur la preuve.** La borne « au plus tard » de la période ou du
  point attend (`W_date`, CT-5 3.3) ; la relève au secours la rétablit
  (CT-5 EX-8.8) ; un jeton de période n'est jamais abandonné (CT-5 EX-4.5).
  Sans relève (`provider_role` `second_rang` ou `interne`, qui n'en ont
  pas, ou relève épuisée), une demande de jeton de point en erreur
  transitoire reste `a_reprendre` et passe `remplacee` dès qu'une échéance
  postérieure est satisfaite ; en erreur permanente, elle passe `refusee`
  et rend ses échéances (CT-5 EX-5.7, EX-8.8, §8.3). Après une longue
  panne, les événements de la panne sont couverts par le premier point
  contresigné au retour, qui les engage par préfixe (CT-5 P-3) : leur borne
  « au plus tard » est d'autant plus tardive. Défauts de CT-5 :
  `rfc3161.manifest.fallback_after_s` = 300,
  `rfc3161.checkpoints.fallback_after_s` = 120, `rfc3161.retry.max_ms` =
  300 000.
- **Invariants.** Ne jamais retirer une réponse conservée ; ne jamais
  promouvoir à la main un jeton.
- **Pas.**
  1. Vérifier la sortie réseau déclarée vers le prestataire (section 5) ;
     porte : connexion TLS établie depuis l'hôte du composant.
  2. Si le principal est seul en cause : laisser la relève jouer (CT-5
     EX-8.8) ; porte : `obtenue` chez le secours dans `fallback_after_s`.
  3. Si tous les prestataires d'une période échouent : changer de
     prestataire par la configuration `ancrage-v0` (réécriture en place,
     EX-11.12, puis redémarrage du composant, CT-5 EX-4.8) ; porte :
     `noortrace_anchoring_last_success_age_s` du nouveau prestataire baisse.
     Sans second contrat ni statut qualifié établi (le secours n'est que
     recommandé, EX-8.2), ce pas ne s'applique pas : attendre le retour du
     prestataire ; aucun jeton de période n'est abandonné (CT-5 EX-4.5), et la
     durée de l'attente est consignée au paquet d'incident.
  4. Si `revoque` : la demande repart au secours (CT-5 révision 0.2) ;
     informer les réviseurs des journaux concernés (CT-7 §4.6, ligne
     CLE-10 pour le serveur interne) ; porte : nouveau jeton promu.
- **Vérification de sortie.** Aucune demande `jeton_*` en `a_reprendre`
  depuis plus de `retry.max_ms`.
- **Événements journalisés.** `anchor_retry`, `anchor_fallback`,
  `anchor_response_rejected`, `period_timestamped`.
- **Après l'incident.** Réexport des dossiers ; si le prestataire est
  qualifié et que le statut a changé, réétablissement de `qualified`
  (EX-11.24). La relève et le rattrapage font dépasser à
  `noortrace_anchoring_attempts_total` deux fois le volume nominal : une
  alerte `noortrace_ancrage_volume` pendant ou juste après l'incident relève
  de ce runbook, non de RB-8, quand la ventilation par prestataire et par
  issue montre des échecs vers le prestataire en panne suivis de succès de
  rattrapage (10.5).

### 10.16 RB-5 Perte d'une copie WORM

**EX-10.20** Une copie manque, diffère de l'original, n'est pas verrouillée
comme la configuration le dit, a une version inattendue, ou un gel n'est pas
posé. Ce runbook couvre une copie manquante, différente, mal verrouillée ou
non gelée ; la perte d'un support entier n'est couverte par aucun runbook en
version 0.1 (section 15).

- **Détection.** `noortrace_copie_worm_en_retard`,
  `noortrace_verrou_worm_non_conforme`,
  `noortrace_retention_support_non_conforme`, `noortrace_versions_inattendues`,
  `noortrace_gel_non_pose`, `noortrace_registre_gels_invalide`,
  `noortrace_releve_en_retard`, `noortrace_gel_pose_en_retard` ; lignes
  `worm_copy_failed`, `worm_lock_check`, `worm_lock_audit`,
  `worm_versions_unexpected`, `worm_legal_hold_observed`.
- **Impact sur la preuve.** L'original local reste la référence (CT-2
  EX-12.17) ; tant que la copie manque, la perte du volume local perd les
  segments non copiés ; une copie non verrouillée peut être supprimée ; la
  chaîne, ses signatures et ses ancres ne changent pas : tout dossier se
  revérifie (CT-6).
- **Invariants.** Ne jamais supprimer une version, même inattendue (elle
  est une pièce de l'incident) ; ne jamais employer un rôle de contournement
  de la rétention ; ne jamais lever un gel hors de la procédure d'EX-11.16.
- **Pas.**
  1. `noortrace-ctl worm releve` ; porte : ligne `worm_lock_audit` avec
     les clés en cause.
  2. Copie manquante : laisser la supervision la réessayer (CT-2 EX-12.16) ;
     porte : version inscrite au registre des copies avec le bon SHA-256.
  3. Copie différente de l'original : comparer les deux SHA-256 avec
     `verifier-journal.mjs` sur l'original et sur la version restaurée par
     `noortrace-ctl worm restaurer` (phase 2, EX-10.14) ; porte :
     l'exemplaire qui vérifie est connu ; l'autre est une pièce de
     l'incident.
  4. Verrou ou rétention non conforme : corriger la configuration par
     défaut du support avec le rôle Administrateur du compte (CT-2 EX-18.9),
     jamais par l'écrivain ; porte : ligne `worm_lock_config_check`
     conforme.
  5. Gel non posé : reposer le gel par le gardien de pose (`noortrace-ctl
     worm gel poser`) ; porte : relecture d'EX-10.9 `registre_gels` à 1.
- **Vérification de sortie.** `noortrace_worm_copy_pending`,
  `noortrace_worm_lock_nonconforming` et `noortrace_worm_versions_unexpected`
  valent 0 au relevé suivant.
- **Événements journalisés.** `worm_copy_failed`, `worm_lock_check`,
  `worm_lock_audit`, `worm_versions_unexpected`, lignes de l'outil de gel ;
  aucun événement de la chaîne (CT-2 §9.1).
- **Après l'incident.** Une version inattendue ou un gel levé hors de
  l'outil est un incident de sécurité (RB-8) ; procès-verbal `restauration`
  si une copie a été réécrite à partir de l'original.

### 10.17 RB-6 Saut d'horloge

**EX-10.21** L'horloge de l'hôte recule au-delà de `clock.max_backstep_ms` ou
avance brutalement au-delà de `clock.max_forward_ms`, ou un prestataire
signale une horloge suspecte.

- **Détection.** `noortrace_mode_degrade_critique` (raison `horloge`),
  `noortrace_horloge_ecart`, `noortrace_ancrage_horloge_suspecte`,
  `noortrace_ancrage_jeton_anterieur` ; lignes `clock_backstep`,
  `clock_forward_jump`, `clock_skew`.
- **Impact sur la preuve.** Tout est bloqué (CT-2 §14.2) sauf en mode
  observation, où rien ne l'est mais où aucun `ts` n'est posé dans le futur
  (CT-2 EX-14.14) ; `ts` reste non décroissant ; les ancres extérieures
  bornent l'écart (CT-5 3.3).
- **Invariants.** Ne jamais régler l'horloge à la main vers l'arrière ; ne
  jamais employer `noortrace-ctl clock --accept` sans avoir établi l'heure
  par une source extérieure.
- **Pas.**
  1. Lire l'état de synchronisation de l'hôte (`chronyc -c tracking` ou
     `timedatectl`, R9-F41, R9-F44 ; à défaut l'appel `adjtimex(2)`, dont la
     valeur 5 signifie « clock not synchronized », R9-F46) ; porte : la
     source de temps est synchronisée.
  2. Comparer à une seconde source (horloge du magasin de bail, CT-2
     EX-7.13 ; `genTime` du dernier jeton) ; porte : l'écart est expliqué.
  3. Attendre le retour dans la tolérance, ou confirmer par
     `noortrace-ctl clock --accept` (consigné) ; porte : sortie du mode
     dégradé « horloge ».
- **Vérification de sortie.** `noortrace_degraded{reason="horloge"}` vaut 0 et
  `abs(noortrace_clock_skew_ms)` est sous `warn_skew_ms`.
- **Événements journalisés.** `clock_backstep`, `clock_forward_jump`,
  `clock_skew`, la confirmation ; aucun événement de la chaîne (CT-7 JS-8).
- **Après l'incident.** Rapprocher l'intervalle des jetons RFC 3161 de la
  période ; si l'horloge a été falsifiée, RB-8.

### 10.18 RB-7 RPC du registre injoignable

**EX-10.22** Le point RPC du registre (validateur joignable ou relais) ne
répond plus, la chaîne n'avance plus, ou une double signature est vue.

- **Détection.** `noortrace_registre_cible_muette`, `noortrace_registre_sonde`,
  `noortrace_registre_hauteur_figee`, `noortrace_registre_equivocation`,
  `noortrace_registre_cloture_non_soumise`,
  `noortrace_registre_capture_en_retard`, `noortrace_registre_mempool`,
  `noortrace_registre_sous_tarif`, `noortrace_registre_marge_retention`,
  `noortrace_ancrage_empreinte_squattee` ; ligne `registry_pending`.
- **Impact sur la preuve.** Le registre ne bloque jamais l'enregistreur
  (CT-4 EX-8.1) ; le contrôle 8 des dossiers des périodes non soumises
  attend (CT-4 EX-8.3) ; une capture faite trop tard perd le certificat
  hors de la fenêtre de rétention du validateur (CT-4 EX-9.4, EX-9.6).
- **Invariants.** Ne jamais restaurer le répertoire de données ni l'état de
  consensus d'un validateur depuis une sauvegarde (CT-4 EX-10.9) ; ne jamais
  soumettre une ancre ni capturer par un relais (CT-4 EX-10.5) ;
  `-bft-recovery-reset` n'existe qu'en profil de développement (CT-4 §13).
- **Pas.**
  1. Sonder `eth_blockNumber` à travers chaque point déclaré (sonde
     d'EX-10.7, à produire, section 15) ; porte : le point en cause est
     connu.
  2. Relais : redémarrer le conteneur du relais (image et Compose de
     `chain/docker`, EX-3.6) ; porte : `noortrace_registre_sonde_ok` à 1.
  3. Validateur du client injoignable : la soumission continue vers les
     autres validateurs de `--rpc`, qui reçoivent les mêmes octets (au moins
     deux validateurs d'opérateurs distincts en production, CT-4 EX-8.15) ;
     porte : `registry_pending` cesse.
  4. Hauteur figée sur tous les points : prévenir l'exploitant du registre
     (CT-4 §10) ; porte : accusé de réception.
  5. Équivocation : incident du registre ; conserver les preuves et les
     transmettre (CT-4 EX-10.8, §14) ; porte : paquet d'incident transmis.
  6. Empreinte prise au registre : suivre CT-4 §8.3 ; porte : décision
     consignée.
- **Vérification de sortie.** Hauteur qui avance, `registry_pending` absent
  depuis une période, captures faites dans l'heure.
- **Événements journalisés.** `registry_pending`, lignes de l'outil du
  registre (sorties `operations-registre-v0`).
- **Après l'incident.** Capturer les blocs encore dans la fenêtre de
  rétention ; consigner ceux qui en sont sortis (le certificat n'est plus
  récupérable auprès de ce nœud, CT-4 §9.5).

### 10.19 RB-8 Suspicion de compromission de clé

**EX-10.23** Une clé ou un secret de l'inventaire de CT-7 §4.2 est soupçonné
compromis : par une alerte (`noortrace_relais_refuse`,
`noortrace_remise_refusee`, `noortrace_ancrage_volume`,
`noortrace_acces_non_declare`, une version WORM inattendue, un gel levé hors
de l'outil), ou par un signalement.

- **Détection.** Les règles ci-dessus ; un écart de la relecture d'EX-10.9 ;
  un accès au coffre ou aux copies par un principal non déclaré (11.10). Avant
  d'ouvrir ce runbook sur `noortrace_ancrage_volume`, ventiler
  `noortrace_anchoring_attempts_total` par prestataire et par issue : des
  succès en excès hors de toute panne relèvent de ce runbook ; des échecs
  vers un prestataire en panne suivis de succès de rattrapage relèvent de
  RB-4.
- **Impact sur la preuve.** Selon la clé : CT-7 EX-4.8 liste, clé par clé,
  ce qui peut être invalide (événements signés entre l'instant présumé et la
  rotation pour CLE-1 ; décisions signées pour CLE-3 ; jetons émis pour
  CLE-10).
- **Invariants.** La conduite est celle de CT-7 §4.6, dans son ordre ; CT-8
  n'en change aucun pas ; ne jamais restaurer une clé d'usage `enregistreur`,
  `chaine` ou `validateur` depuis une sauvegarde (CT-7 EX-4.4).
- **Pas.**
  1. Nommer la clé (CLE-n) et l'instant présumé ; porte : la ligne de la
     table de CT-7 EX-4.8 est choisie.
  2. Exécuter les pas de cette ligne ; pour CLE-1 : `noortrace-ctl cle
     rotation-urgence` (phase 2, EX-10.14 ; CT-2 EX-11.16) tant que la clé est
     utilisable ; porte : événement `noortrace.journal.rotation-cle` scellé et
     nouvelle clé inscrite au registre.
  3. Pour un secret CLE-11 à CLE-25 : révocation chez l'émetteur, nouveau
     secret écrit en place dans `secrets/<nom>` (même fichier, EX-11.12),
     puis `noortrace-ctl reload` ou redémarrage (CT-7 EX-4.8) ; porte : ligne
     `config_reloaded` avec le nouveau SHA-256 du document, ou, pour un
     secret qu'un rechargement ne relit pas, redémarrage par `$DC up -d
     --force-recreate <service>` et `/readyz` à `200`.
  4. Extraire du journal des consultations (11.10) et des journaux de
     l'émetteur les accès depuis l'instant présumé ; porte : liste jointe au
     paquet d'incident.
- **Vérification de sortie.** Les vérifications de CT-7 (procès-verbal de
  cérémonie de la nouvelle clé, CR-) passent ; le registre montre la
  révocation.
- **Événements journalisés.** `noortrace.journal.rotation-cle` dans la
  chaîne ; `config_reloaded` ; procès-verbal de cérémonie (CT-7 §5).
- **Après l'incident.** Exercice annuel de rotation d'urgence de CT-7 EX-3.12
  mis à jour ; information des réviseurs prévue par CT-7 EX-4.8.

## 11. Sauvegarde, reprise, mises à jour, consultations et accès

Le journal de l'enregistreur est fait de fichiers texte en ajout seul,
nommés de façon triable, chacun porteur de ses preuves, et l'état de
l'écrivain se dérive des fichiers (CT-2 §12.8, EX-12.1). Sauvegarder, c'est
donc copier des fichiers ; restaurer, c'est les remettre sans en changer un
octet ; la chaîne, ses manifestes et ses ancres disent ensuite d'eux-mêmes
si la reprise est juste. Cette section fixe ce qu'on sauvegarde, les
objectifs de reprise, la procédure qui garde la continuité de la chaîne, les
mises à jour sans rupture, la migration de support avec procès-verbal, la
fin de rétention, la levée d'un gel, le journal des consultations et des
accès et l'archivage du journal d'exploitation : les trois points de CT-7
PA-15 et les lacunes L-1, L-2 et L-9 de CT-7 §8.9. Les définitions de
l'objectif de point de reprise (RPO : « the point in time to which data must
be recovered after an outage ») et de l'objectif de durée de reprise (RTO :
« The overall length of time an information system's components can be in
the recovery phase before negatively impacting the organization's mission »)
sont celles du NIST SP 800-34 Rev. 1, glossaire (R9-F36), avec la contrainte
« the RTO must normally be shorter than the MTD » (R9-F35). Aucune durée de
sauvegarde ou de reprise n'est mesurée : l'enregistreur, le service
d'approbation et le composant d'ancrage ne sont pas construits ; chaque
valeur est une cible « à mesurer (CT-9, porte 2) ».

### 11.1 Principes

**EX-11.1** La sauvegarde et la reprise obéissent à quatre règles :

1. **Octets intacts.** Un fichier du journal (12.1 de CT-2) est sauvegardé
   et restauré octet pour octet ; jamais réécrit, réencodé, fusionné ni
   « réparé ». Une fin de segment incomplète n'est tronquée que par
   l'écrivain lui-même (CT-2 EX-12.10) ; une ligne altérée n'est jamais
   tronquée (CT-2 EX-12.11). Seule exception : au chemin B (11.4),
   `journal.json`, qui n'a pas de copie WORM (PD-13) et que ce chemin ne
   prend dans aucune archive, est recréé depuis la configuration ; il n'est
   pas réécrit à partir d'octets existants.
2. **Aucune clé dans une sauvegarde d'hôte.** Une sauvegarde de volume,
   d'hôte ou de répertoire NE DOIT contenir ni clé privée, ni secret, ni
   graine : les clés d'usage `enregistreur`, `chaine`, `validateur`,
   `deployeur`, `relayeur`, `approvisionnement`, `tsa_interne` n'ont aucune
   sauvegarde ; `administrateur_registre`, `tresorerie` et `enveloppe` n'en
   ont qu'en partage k sur n, par cérémonie (CT-7 EX-4.4) ; les secrets
   CLE-11 à CLE-25 restent dans leur magasin, la configuration n'en portant
   que des références (CT-2 EX-15.3).
3. **Aucune restauration d'un validateur.** Le répertoire de données d'un
   validateur n'est jamais restauré depuis une sauvegarde, ni répliqué à
   chaud, ni copié par instantané à chaud (CT-4 EX-10.9) ; une sauvegarde
   d'un validateur ne sert qu'à l'analyse. Les procédures de noorchain-core
   qui restaurent ou copient à chaud le `-data-dir` (R8-F40, R8-F41) ne
   s'appliquent pas à un validateur du registre de NOORTRACE.
4. **Aucun retour en arrière d'une époque.** Le magasin de bail
   (PostgreSQL, etcd, fichier `path.epoch`, CT-2 §13.2) n'est jamais
   restauré à un état antérieur : son époque doit rester strictement
   croissante (CT-2 EX-13.4). Après sa perte, la ligne de bail est recréée
   avec une époque supérieure à toute époque présente dans les noms de
   fichiers du journal et dans les clés de ses copies WORM.

### 11.2 Ce qu'on sauvegarde

**EX-11.2** Le client DOIT tenir, pour chaque journal, les copies de la table
suivante. « WORM » est la copie de CT-2 EX-12.16 ; « archive » est une archive
de sauvegarde au format déterministe de 13.4 (sous-ensemble ustar, entrées
triées par nom, propriétaires 0, droits `0644`, une seule date pour toutes les
entrées, R9-F12), dont le procès-verbal `sauvegarde` (11.9) liste chaque fichier
avec sa longueur et son SHA-256. CT-8 0.1 ne fournit aucun outil qui crée
l'archive ni le procès-verbal `sauvegarde` : le client les produit avec ses
outils, au format de 13.4 et du schéma `proces-verbal-exploitation-v0`, et
`proces-verbal.mjs verifier` contrôle le procès-verbal (PV-1 à PV-10 ; PV-7 et
PV-8 avec `--racine` sur l'archive extraite) ; la forme de l'archive elle-même
n'a pas d'outil de contrôle en 0.1 (section 15).

| Objet | Emplacement | Copie WORM | Archive | Cadence de l'archive (cible) | Restauration |
|---|---|---|---|---|---|
| Segments, manifestes et signatures, séries de points | `segments/`, `manifestes/`, `points/` (CT-2 EX-12.1) | oui, à la fermeture (CT-2 EX-12.16) | oui | chaque jour, et avant toute migration ou mise à jour | chemin A ou B (11.4) |
| Pièces | `pieces/` | si `copy_pieces` (CT-2 EX-12.16) | oui, tant qu'elles sont retenues (CT-2 EX-12.20) | chaque jour | chemin A ; sans archive ni copie, une pièce perdue ne se reconstitue pas (CT-2 EX-12.20) |
| Journal d'intention, fichiers d'attente, fichiers des approbations, registre des copies, `journal.json` | `intentions/`, `attente/`, `approbations/`, `worm/`, `journal.json` | non (sauf `journal.json`, proposé à la copie par PD-13) | oui | chaque jour | chemin A ; le registre des copies se reconstruit depuis le support (CT-2 EX-12.1) |
| Ancres, file et acquisitions de CT-5 | `ancres/periode-*/`, `queue.path` | oui pour `ancres/` (CT-5 EX-5.15) | oui | chaque jour | chemin A ; la file se reconstruit (CT-5 EX-8.12) |
| Journal d'exploitation et fichiers tournés | `logging.*` de CT-2 | oui, sous `<prefix>exploitation/` (11.11) | oui | à chaque rotation | relecture seulement |
| Journal des consultations et des accès, procès-verbaux, paquets d'incident | `exploitation/` (11.9, 11.10, EX-10.15) | oui, sous `<prefix>exploitation/` | oui | chaque jour | relecture seulement |
| Configuration de l'enregistreur, document `ancrage-v0`, configuration du service d'approbation et du serveur de console | gestion de configuration du client ; `deploiement/config/` | non | oui, avec leur SHA-256 (la ligne `startup` porte celui de la configuration, CT-2 EX-15.4 pas 7) ; jamais le répertoire voisin `deploiement/secrets/`, exclu nommément de toute archive (EX-11.1, point 2 ; PV-10 le refuse) | à chaque changement | redéploiement (sections 4 et 8) |
| État du service d'approbation | documents `ticket-v0`, fenêtres, versions chargées, jeu de repli, compteur d'identifiants (CT-3 EX-7.22, EX-7.23) | non | oui | cible : toutes les 15 min (à mesurer, CT-9) | EX-11.4, point 3 |
| Magasin de bail | PostgreSQL, etcd ; pour le magasin `file`, `lease.store.path` et `<path>.epoch` sous `storage.root` | non | jamais restauré (EX-11.1, point 4) : `<path>` et `<path>.epoch` sont exclus nommément de l'archive | — | recréation (chemin A, pas 6) |
| Clés et secrets | modules, coffres | non | jamais dans une archive (EX-11.1, point 2) | — | CT-7 §4 et §5 |
| Nœud relais | volume `noorcore-donnees` | non | non : le relais n'a pas d'état propre (R8-F35) | — | redéploiement |
| Validateur | `db/leveldb` | non | jamais pour reprise (EX-11.1, point 3) | — | CT-4 EX-10.4 |

**EX-11.3** Les copies suivent la règle 3-2-1 publiée par l'US-CERT : « Keep
3 copies of any important file: 1 primary and 2 backups », « Keep the files
on 2 different media types », « Store 1 copy offsite » (R9-F40) : l'original
local, la copie WORM et l'archive, sur au moins deux supports distincts, dont
un hors du site de l'original, choisi pour ne pas être touché par le même
sinistre (critère du NIST SP 800-34 §3.4.2, R9-F37).

**EX-11.4** L'intégrité d'une archive est vérifiée à sa création et avant
toute restauration : chaque fichier relu a la longueur et le SHA-256 que le
procès-verbal `sauvegarde` donne (PV-4, PV-7), comme le contrôle CP-9 le
recommande (« cryptographic hashes are examples of mechanisms that can be
employed […] to protect the integrity of information system backups »,
R9-F39). Une archive s'extrait dans un répertoire neuf et vide,
inaccessible aux autres utilisateurs, en refusant tout membre absolu, tout
composant `..`, tout lien et tout fichier spécial (R9-F13, R9-F14, R9-F16,
R9-F22) : c'est la même règle que l'outil du paquet réviseur (section 13).
Le répertoire d'extraction appartient à root, en mode `0700` : l'archive fixe
les propriétaires à 0 et les droits à `0644` (EX-13.14), que le chemin A
remplace avant le démarrage (pas 6).
Pour l'état du service d'approbation, la restauration DOIT changer l'époque
du préfixe de ses identifiants de tickets avant toute création de ticket
(CT-3 EX-7.1 : « un préfixe d'époque conservé hors du service et changé à
chaque reconstruction »).

### 11.3 Objectifs de reprise

**EX-11.5** Le client DOIT fixer et consigner, pour chaque composant, un RPO
et un RTO inférieurs à sa durée maximale d'interruption admissible ; les
valeurs de la table sont les cibles de CT-8, toutes à mesurer (CT-9, porte
2), sauf la borne du bail, qui est un défaut de CT-2.

| Composant | RPO cible | RTO cible | Ce qui borne |
|---|---|---|---|
| Journal, segments fermés | délai de la copie WORM : alerte à 1 h (`noortrace_copie_worm_en_retard`) | chemin B : 4 h | CT-2 EX-12.16, EX-12.17 |
| Journal, segment ouvert | durée d'un segment, au plus une période (1 h) ; nul avec un volume bloc répliqué de façon synchrone (CT-2 §13.5) | bascule : `lease.ttl_ms` (défaut 10 000 ms) plus la reprise de l'écrivain (cible de CT-2 §16.1 : 2 s pour 256 MiB) | CT-2 §13, §16.1 (R8-F14) |
| Pièces non copiées | cadence de l'archive (1 jour) ; 1 h avec `copy_pieces` | chemin A : 4 h | EX-11.2 |
| Service d'approbation | 15 min ; un état perdu ne perd aucune preuve : le noyau renvoie `ouvrir` et scelle `expire` sur `ticket_inconnu` (CT-3 EX-7.25) | 1 h | CT-3 §7.10 |
| Composant d'ancrage | sans objet : la file se reconstruit (CT-5 EX-8.12) | 4 h ; rien ne bloque la capture (CT-5 EX-4.8) | CT-5 §8.7 |
| Configuration | nul (gestion de configuration) | durée de l'installation complète (section 8) | — |

La règle `noortrace_sauvegarde_en_retard` (10.7) alerte quand le dernier
procès-verbal `sauvegarde` est plus vieux que le RPO retenu.

### 11.4 Reprise qui garde la continuité de la chaîne

Trois chemins, choisis dans cet ordre sauf quand un runbook désigne le chemin
(RB-1, pas 3 : chemin B pour un `segment_corrupted`), sur le modèle « Path A
Restore », « Path B Redeploy » de noorchain-core (`RUNBOOK-M27D-OPS.md` l.
220-248, R8-F40), adapté au journal : A restaure l'archive et la complète par
les copies WORM ; B reconstruit depuis les seules copies WORM ; C ouvre un
journal neuf quand la chaîne ne peut plus continuer.

**EX-11.6** Une reprise DOIT garder la continuité de la chaîne : les fichiers
restaurés sont identiques octet pour octet à ceux que le registre des copies,
les copies WORM ou le procès-verbal `sauvegarde` désignent ; aucun événement
manquant n'est recréé ; l'écrivain repart avec une époque nouvelle et un
segment neuf dont l'en-tête porte `prev_hash` = `hash` du dernier événement
restauré (CT-2 EX-12.3, EX-13.9) ; une perte (segment ouvert non copié) est
dite dans le procès-verbal `restauration` (champ `observations`) et se voit
dans la chaîne (CT-2 §13.5 : le manifeste de la période ne pourra pas être
produit ou le sera sur un journal tronqué, ce que P-3 et le registre
révèlent).

Chemin A, pas à pas (chaque pas a sa porte, EX-10.14) :

1. Arrêter le démon et placer le répertoire du journal hors service par
   renommage, sans rien supprimer ; porte : `noortrace-ctl etat` (phase 2,
   EX-10.14) muet, aucun processus n'a le répertoire ouvert.
2. Vérifier l'archive contre son procès-verbal `sauvegarde` (EX-11.4) ;
   porte : PV-7 réussi.
3. Extraire l'archive dans un répertoire neuf (EX-11.4) ; porte : extraction
   sans refus.
4. Compléter par les copies WORM des segments, manifestes, points et ancres plus
   récents que l'archive (`noortrace-ctl worm restaurer`, phase 2, EX-10.14 ;
   une version inscrite au registre des copies par clé). Le segment ouvert à
   l'heure de l'archive y figure en version partielle, sous le nom de sa version
   close : pour chaque nom présent à la fois dans l'archive et dans le registre
   des copies, la version WORM remplace celle de l'archive quand celle-ci en est
   un préfixe octet pour octet, ce que le procès-verbal `restauration` consigne
   (champ `observations`) ; toute autre divergence est un incident (RB-5).
   Porte : chaque fichier ajouté ou remplacé a le SHA-256 inscrit.
5. `node scripts/deploiement/verifier-journal.mjs <répertoire> --cles
   <fichier>` ; porte : `verdict` `valide`, `last_seq` et `last_hash` notés.
6. Rendre le répertoire au compte du démon : `sudo chown -R 10001:10001
   <répertoire>`, puis `sudo find <répertoire> -type d -exec chmod 0700 {} +`
   et `sudo find <répertoire> -type f -exec chmod 0600 {} +` ; le mettre à la
   place de `storage.root` (volume neuf rempli depuis le répertoire, ou
   montage lié d'un répertoire de l'hôte, adaptation à déclarer dans la
   description des images, CO-11 ; la version 0.1 ne donne pas la commande
   qui remplit un volume nommé neuf en gardant les octets, le compte et les
   droits, section 15). Relever l'époque la plus haute `E` dans
   les noms des segments (CT-2 EX-12.1) et dans la liste des versions sous
   `<prefix>` (CT-2 EX-17.6, pas 1), et la consigner au procès-verbal
   `restauration`. Si le magasin de bail est perdu (EX-11.1, point 4) :
   magasin `file`, écrire `E` dans `<lease.store.path>.epoch` (compte 10001,
   mode `0600`), que le démon incrémente à l'acquisition (CT-2 §13.2) ;
   magasin `postgresql`, poser `epoch = E` sur la ligne du journal ; magasin
   `etcd`, dont l'époque est la révision de la grappe (CT-2 §13.2), qui ne se
   règle pas, la reprise exige une grappe dont la révision dépasse `E`, ce que
   la version 0.1 ne décrit pas au-delà (section 15). Puis démarrer le démon ;
   porte : `noortrace-ctl etat` rend `ok`, ligne `lease_acquired` avec une
   époque strictement supérieure à `E`, que porte aussi le nom du premier
   segment ouvert après la reprise.
7. Exporter et vérifier par CT-6 (`node scripts/verify/dossier.mjs`) le
   dossier du dernier événement restauré et celui du premier événement
   scellé après la reprise ; porte : code 0 pour les deux, et le second
   a `prev_hash` égal au `last_hash` du pas 5.
8. Écrire le procès-verbal `restauration` (11.9) et le copier sur le support
   WORM ; porte : PV-1 à PV-8 réussis.

Chemin B : les pas 1, 5 à 8, avec, à la place des pas 2 à 4, la liste des
versions sous `<prefix>` (CT-2 EX-17.6 pas 1) et leur restauration dans un
répertoire neuf ; les fichiers sans copie (intentions, attente, approbations,
pièces sans `copy_pieces`) sont perdus et listés dans le procès-verbal.
`journal.json` n'a pas de copie WORM (PD-13) : il est recréé (exception
d'EX-11.1, point 1) dans la forme de CT-2 EX-12.1 avec `recorder.org_id` et
`recorder.journal_id` de la configuration, et la porte du pas 5 le contrôle
(`verifier-journal.mjs` compare l'`org_id` et le `journal_id` de chaque en-tête
de segment à `journal.json`, EX-11.7). Les tickets ouverts dont la `retenue` est
dans la chaîne sont repris par le noyau, qui renvoie `ouvrir` et scelle `expire`
à défaut (CT-3 EX-7.25).

Chemin C : quand la clé courante est inutilisable et ne peut signer de
rotation, ou que la chaîne ne peut pas être reprise, un journal neuf est
ouvert et lié au registre (CT-2 EX-11.16, CT-7 EX-4.8 ligne CLE-1) ; l'ancien
reste vérifiable jusqu'à son dernier manifeste.

**EX-11.7** L'outil de référence `scripts/deploiement/verifier-journal.mjs`
vérifie un répertoire de journal de la disposition de CT-2 EX-12.1, sans
réseau, avec un fichier de clés au format de `cles.json` de CT-1 :
en-tête de chaque segment (CT-2 EX-12.3 : JCS v0, `noortrace_segment` 0,
`org_id` et `journal_id` de `journal.json`), suite des `first_seq` et des
époques non décroissantes (CT-2 EX-12.10 pas 1), `prev_hash` de chaque
en-tête égal au `hash` du dernier événement du segment précédent, chaque
ligne par E-1 à E-8 et la suite par C-1 à C-3 de CT-1, chaque manifeste
présent recalculé sur les événements de sa période et sa signature vérifiée
(CT-1 §10), et rend un rapport `verification-journal-v0` (schéma nouveau)
avec le code 0 (`valide`), 1 (`invalide`) ou 2 (usage). Il n'emploie que
`scripts/lib/journal.mjs` ; il ne remplace pas CT-6, qui vérifie un dossier
avec ses ancres.

**EX-11.8** Le client DOIT exercer une restauration au moins une fois par an
et après tout changement de support, sur une autre machine que celle de
l'original (« System recovery on an alternate platform from backup media »,
NIST SP 800-34 §3.5.1, R9-F38), avec des objectifs et des critères de
réussite écrits avant l'exercice (même source) : le chemin A ou B jusqu'au
pas 7, sur une copie, sans toucher au journal en service ; le procès-verbal
`exercice_restauration` donne les durées mesurées, qui sont les mesures de
RPO et de RTO de 11.3 pour ce client.

### 11.5 Mises à jour sans rupture de chaîne

**EX-11.9** **Logiciel de l'enregistreur.** Une mise à jour passe par une
reprise de bail, jamais par une modification du journal : (1) valider la
configuration avec la commande de la nouvelle version (`noortrace
validate-config`, CT-2 EX-15.7) ; (2) avec deux instances, mettre à jour la
passive, la démarrer (`standby`), puis arrêter l'active (drain de
`drain_timeout_ms`, CT-2 §13.5) : la passive prend le bail avec l'époque
suivante et ouvre un segment neuf (CT-2 §13.4) ; avec une seule instance,
arrêt propre, remplacement de l'image (désignée par son condensé, EX-3.15),
redémarrage : nouvelle époque, nouveau segment (CT-2 EX-13.9) ; (3) vérifier
la jonction : `verifier-journal.mjs` sur le répertoire et le dossier du
premier événement de la nouvelle version (`code.recorder` change, CT-1 §5).
Un ensemble de politique inchangé ne produit aucun événement de politique au
redémarrage (CT-2 EX-9.2).

**EX-11.10** **Descellement TPM.** Avec une clé scellée aux PCR (CT-2 §11.2 :
« un changement de micrologiciel ou de chargeur rend la graine
indescellable, ce qui est voulu et doit être prévu dans la procédure de mise
à jour », `CT-2:7295-7300`), une mise à jour du micrologiciel ou du chargeur
DOIT être précédée d'une rotation planifiée (CT-2 EX-11.15) vers une clé dont
la garde ne dépend pas des PCR qui changent, et suivie, si le client garde la
classe, d'une nouvelle rotation vers une clé scellée aux nouvelles valeurs ;
chaque rotation est un événement `noortrace.journal.rotation-cle`, une
inscription au registre et, quand CT-7 §5.1 l'exige, une cérémonie. Une
mise à jour faite sans cette rotation laisse la clé indescellable : c'est
une perte de clé (chemin C, EX-11.6).

**EX-11.11** **Rotation de clé.** Planifiée avant que la validité expire
pendant une période (CT-2 EX-9.3), inscrite au registre avant usage
(CT-2 §11.3), annoncée aux réviseurs par la mise à jour de leur fichier
d'ancres (CT-6 §12) ; la chaîne continue : l'événement de rotation est
signé par l'ancienne clé et contresigné par la nouvelle (CT-1 §8).

**EX-11.12** **Autres composants.** Le service d'approbation se met à jour
après persistance de son état (CT-3 EX-7.22) ; pendant son arrêt, le noyau
applique la matrice de CT-2 §14.2 (écritures et outils susceptibles
d'approbation bloqués en mode d'application ; rien n'est bloqué en mode
observation, section 12) : la mise à jour se fait dans une fenêtre annoncée.
Le composant d'ancrage se met à jour à tout moment : il ne bloque jamais la
capture et relit sa file au démarrage (CT-5 EX-4.8, EX-8.12). Un relais se
remplace (image de `chain/docker`, EX-3.6). Un validateur suit la mise en
service de CT-4 EX-10.4, sans restauration (EX-11.1, point 3). Une révision
de spécification qui ajoute un membre facultatif à un schéma (comme `otel`,
`sdk` ou le mode `observation`) s'applique par la configuration et un
redémarrage ou un rechargement ; aucun format figé de CT-1 v0 ne change en
place.

**Réécriture d'un fichier monté.** La configuration et chaque secret sont
montés fichier par fichier : un montage lié fixe l'inode, et un fichier
remplacé (éditeur qui écrit une copie, `mv`, `install`) n'est pas vu dans le
conteneur. Une configuration ou un secret se réécrit donc en place, sur le
même inode : `sudo tee <fichier> < <nouveau contenu> > /dev/null` (propriétaire
et mode inchangés), puis `noortrace-ctl reload` ; porte : la ligne
`config_reloaded` porte le SHA-256 que `sha256sum <fichier>` donne sur
l'hôte. Quand un rechargement ne suffit pas (secret lu au démarrage, CT-7
EX-4.8), ou si le fichier a été remplacé, le conteneur est recréé : `$DC up -d
--force-recreate <service>` ; porte : `/readyz` rend `200` et la ligne
`startup` porte ce SHA-256.

### 11.6 Migration de support avec procès-verbal

L'Olico exige un procès-verbal pour le transfert des données d'un support à
un autre (art. 10 al. 3, cité par CT-2 EX-12.20) ; CT-2 §12.8 renvoie la
migration à CT-8 et CT-7 PA-15 en demande la forme (lacune L-2).

**EX-11.13** Toute migration d'un journal d'un support à un autre (volume
local, volume bloc, support WORM, archive) DOIT produire un procès-verbal
`migration_support` (11.9) qui liste chaque fichier migré avec sa longueur,
son SHA-256 lu sur la source et son SHA-256 relu sur la destination, porte le
rapport de `verifier-journal.mjs` sur la destination et la continuité
(`last_seq`, `last_hash`), est signé par l'exécutant et un témoin d'identités
distinctes par les moyens du client (signature électronique ou manuscrite :
CT-8 n'en fixe pas le procédé), et est copié sur le support WORM sous
`<prefix>exploitation/proces-verbaux/`. La source n'est libérée qu'après la
copie WORM du procès-verbal, et jamais avant l'échéance de rétention de ce
qu'elle contient (11.7).

**EX-11.14** Pas : (1) archive de la source et procès-verbal `sauvegarde` ;
(2) arrêt du démon (ou bascule vers une instance qui écrit déjà sur la
destination) ; (3) inventaire de la source : liste triée, longueurs, SHA-256
(porte : PV-2, PV-3) ; (4) copie, en gardant le compte 10001 et les droits
`0700` et `0600` (chemin A, pas 6) ; (5) relecture de la destination et
comparaison fichier par fichier (porte : PV-4) ; (6) `verifier-journal.mjs`
sur la destination (porte : `valide`, PV-6, PV-8) ; (7) changement de
`storage.root` et redémarrage (porte : `lease_acquired`, nouveau segment) ;
(8) signature et copie WORM du procès-verbal. Une migration du support WORM
lui-même (vers un autre bucket) liste les clés et versions copiées ; la
rétention de la destination couvre au moins l'échéance restante de chaque
version (CT-2 EX-12.30) ; les versions de la source restent jusqu'à leur
échéance, aucun rôle ne pouvant les supprimer avant (mode Compliance).

### 11.7 Fin de rétention

**EX-11.15** Rien dans NOORTRACE ne supprime un événement, une copie WORM,
une pièce d'horodatage ni une ligne de la file (CT-2 EX-12.19, CT-5 EX-5.15,
EX-8.14, CT-7 EX-8.16). La fin de rétention est un acte d'exploitation, et
l'acte est un procès-verbal `fin_de_retention` (11.9), qui DOIT établir :

1. la base et la durée (`retention.basis`, `events_years`), et l'échéance
   `retain_until` = fin de l'exercice auquel les fichiers se rapportent plus
   `events_years` ans (CO art. 958f al. 1 : « Ce délai court à partir de la
   fin de l'exercice », cité par CT-2 EX-12.19) ; pour une copie WORM,
   l'échéance du support court de la date d'écriture (CT-7 EX-8.16) ;
2. l'absence de gel actif sur les fichiers (`active_holds` vide, lu au
   registre des gels comme la supervision le lit, CT-2 EX-17.7) ;
3. la liste des fichiers, avec longueurs et SHA-256, et deux identités
   distinctes, dont un témoin (PV-5) ;
4. après la levée d'un gel (CT-2 EX-12.40 pas 5), la même procédure, à
   l'échéance que le gel avait suspendue.

Les fichiers locaux ne sont supprimés qu'après la copie WORM du
procès-verbal ; les versions WORM expirent par la rétention du support et ne
sont supprimées que par le rôle Administrateur du compte (CT-2 EX-18.9),
jamais par l'écrivain, qui n'a pas `s3:DeleteObject` (CT-2 EX-12.32). Les
pièces d'horodatage, la file et les acquisitions de CT-5 suivent la même
règle, à `rfc3161.retention_years` au moins (CT-5 EX-5.15).

### 11.8 Gel juridique : pose, levée, rétention

**EX-11.16** Le client DOIT répartir les trois actes du gel entre des
personnes et des rôles distincts sur le support (CT-2 EX-12.38, EX-18.9) :

1. **Pose** : par le gardien de pose, seul (`noortrace-ctl worm gel poser`) ;
   poser n'ôte aucune protection.
2. **Demande de levée** : par le gardien de pose ou une personne qu'il
   désigne (`noortrace-ctl worm gel demander-levee`), avec un motif et une
   référence qui ne sont que des identifiants de dossier (CT-2 EX-12.36).
3. **Levée** : par le gardien de levée (`noortrace-ctl worm gel lever`),
   d'une identité différente de celle de la demande (règle `meme_identite`),
   dans les sept jours (règle `demande_expiree`) ; pour que trois personnes
   distinctes interviennent, le client attribue la pose, la demande et la
   levée à trois identités et le consigne dans le procès-verbal de création
   du support (pas IC-9, EX-8.4) ;
4. l'activation du rôle de levée est approuvée par une autre personne que
   celle qui l'active (CT-2 EX-12.38) ; sur Azure et Google Cloud Storage,
   où la pose et la levée ne se séparent pas sur le support (CT-2 §18.3),
   cette approbation et la règle de l'outil sont les seules barrières, ce
   que le client consigne ;
5. chaque levée est rapprochée de l'alerte `noortrace_gel_leve` (10.4) dans
   le jour, par une personne qui n'a ni demandé ni levé ; l'absence de
   rapprochement est un incident (RB-8).

**EX-11.17** Sur un support dont le mode Compliance n'est pas validé (cas
d'Exoscale, CT-2 §12.6), le gardien de pose DOIT poser un gel sur chaque
période close, par une tâche planifiée à chaque clôture (`noortrace-ctl worm
gel poser` sur la période close) ; la règle `noortrace_gel_pose_en_retard`
(10.4) alerte quand la dernière pose a plus de deux périodes. CT-2 §12.6 dit
ce que cette tâche ne couvre pas : entre la copie et la pose, la période
n'est protégée que par la rétention par défaut du support.

### 11.9 Procès-verbal d'exploitation

**EX-11.18** Les procès-verbaux des actes de 11.2 à 11.8 et de 12.6 suivent le
schéma `proces-verbal-exploitation-v0` (nouveau) et passent les
vérifications suivantes, que `scripts/deploiement/proces-verbal.mjs`
(`verifier <fichier> [--racine <répertoire>] [--cles <fichier>]`, `--cles`
valant par défaut `<racine>/cles.json`) exécute ; le résultat est
`{version, verdict, checks: [{id, status, detail}]}`, `status` `reussi`,
`echoue` ou `non_execute` (raisons `prerequis_en_echec` après l'échec de
PV-1, `racine_absente` sans `--racine`, `sans_objet` pour une sorte que la
vérification ne vise pas), codes 0 (valide), 1 (invalide), 2 (usage) :

| Id | Vérification |
|---|---|
| PV-1 | Le document est conforme au schéma (JSON strict, clés uniques). |
| PV-2 | `files` est trié par `path` (octets UTF-8), sans doublon, sans composant vide, `.` ni `..`. |
| PV-3 | `totals.files` est le nombre d'éléments de `files`, `totals.bytes` la somme des `length`. |
| PV-4 | Pour `sauvegarde`, `restauration`, `exercice_restauration` et `migration_support`, chaque `sha256_destination` est non nul et égal à `sha256_source` ; pour `fin_de_retention` et `passage_mode`, chaque `sha256_destination` est nul. |
| PV-5 | `operators` a des identités distinctes ; pour `migration_support`, `fin_de_retention` et `passage_mode`, au moins deux, dont un `temoin` ou un `approbateur` ; `started_at ≤ finished_at`. |
| PV-6 | Cohérence de la sorte : `destination` non nul exactement pour les quatre sortes de PV-4 ; `retention` non nul exactement pour `fin_de_retention` ; `mode_change` non nul exactement pour `passage_mode`, avec `from ≠ to` ; `continuity` non nul pour les quatre sortes de PV-4 ; `verification.result` vaut `valide` pour ces quatre sortes. |
| PV-7 | Avec `--racine`, chaque fichier de `files` existe sous la racine, fichier ordinaire (un lien n'est pas suivi), avec la longueur et le SHA-256 (`sha256_destination`, à défaut `sha256_source`) annoncés ; aucun autre fichier n'est exigé. |
| PV-8 | Avec `--racine` et pour les quatre sortes de PV-4, `verifier-journal.mjs` sur la racine (avec le fichier de clés) rend `valide`, et son `last_seq` et son `last_hash` égalent `continuity`. |
| PV-9 | Pour `fin_de_retention`, `retain_until` égale `fiscal_year_end` plus `events_years` ans (même mois et jour ; 29 février → 28 février d'une année non bissextile) et précède la date (`AAAA-MM-JJ`) de `started_at` ; `active_holds` est vide. |
| PV-10 | Pour les quatre sortes de PV-4, aucune clé ni aucun secret dans la copie : aucun `path` n'a de composant `secrets` ni ne commence par `run/secrets/` ; avec `--racine`, aucun fichier ne commence par le préfixe DER PKCS#8 d'une clé privée Ed25519 (`302e020100300506032b657004220420`, CT-1 §13) ni ne porte, dans ses 4 096 premiers octets, une ligne `-----BEGIN … PRIVATE KEY-----`. Une sauvegarde de clé suit la procédure de sa classe (CT-7 §4), jamais celle du journal (11.2). |

Exemple : migration du volume d'un journal de démonstration de sept
événements (valeurs calculées ; le segment et `journal.json` sont ceux du
journal d'exemple de 12.4, écrits par le générateur des vecteurs,
`spec/vecteurs/ct-8/journaux/valide/`).

<!-- schema: proces-verbal-exploitation -->
```json
{
  "version": 0,
  "kind": "migration_support",
  "id": "pv-2026-11-05-001",
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
  "started_at": "2026-11-05T09:20:00.000Z",
  "finished_at": "2026-11-05T09:41:12.000Z",
  "operators": [
    {
      "identity": "exploitant-noortrace-1",
      "role": "executant"
    },
    {
      "identity": "responsable-conformite",
      "role": "temoin"
    }
  ],
  "reason": "changement de volume, demande CHG-2026-0412",
  "source": {
    "medium": "volume_local",
    "locator": "volume noortrace-donnees, hote enregistreur-1"
  },
  "destination": {
    "medium": "volume_bloc",
    "locator": "volume noortrace-donnees-2, hote enregistreur-1"
  },
  "files": [
    {
      "path": "journal.json",
      "length": 233,
      "sha256_source": "0x219cfcec700c36d7f31921d33dce35c41d6b5e1c561b54b4d981a5b6a7625ccf",
      "sha256_destination": "0x219cfcec700c36d7f31921d33dce35c41d6b5e1c561b54b4d981a5b6a7625ccf"
    },
    {
      "path": "segments/seg-0000000000000001-00000000000000000001.ndjson",
      "length": 10086,
      "sha256_source": "0x0670cb8b7f374a6728082a73e43a7cf7a42f8202d9710cde72a3d27a641febb5",
      "sha256_destination": "0x0670cb8b7f374a6728082a73e43a7cf7a42f8202d9710cde72a3d27a641febb5"
    }
  ],
  "totals": {
    "files": 2,
    "bytes": 10319
  },
  "verification": {
    "tool": "verifier-journal 0.1.0 (CT-8 EX-11.7)",
    "command": "node scripts/deploiement/verifier-journal.mjs . --cles cles.json",
    "result": "valide",
    "report_sha256": null
  },
  "continuity": {
    "last_seq": 7,
    "last_hash": "0x30ebe8ce1b866c67c4b5e3b08f1742ad5981200bea7cfbf47561441d4f63abeb",
    "last_period_start": null
  },
  "retention": null,
  "mode_change": null,
  "observations": null
}
```

### 11.10 Journal des consultations et des accès

CT-7 EX-8.15 constate que NOORTRACE version 0 n'enregistre ni la lecture du
journal ou de ses copies, ni l'export d'un dossier, et exige du client qui
range son journal parmi ses livres qu'il journalise ces accès et les
conserve aussi longtemps que le journal (Olico art. 8 ; lacune L-1) ; PA-15
demande à CT-8 de le spécifier.

**EX-11.19** Le client DOIT tenir un journal des consultations et des accès qui
reçoit une ligne pour chaque accès, réussi ou refusé, de lecture, de liste,
d'écriture, de suppression, d'export, de restauration ou de changement de
droits, à `storage.root`, au support WORM, aux exports de dossiers et au coffre
des originaux (CT-2 §10.7), depuis cinq sources : l'audit du système
d'exploitation de l'hôte sur `storage.root` ; le journal d'accès aux objets tenu
par le fournisseur du support WORM (son activation à la création du support
relève du pas IC-9 (EX-8.4, point 5) ; sa disponibilité et son format par
support ne sont pas vérifiés ici et le sont en CT-9) ; l'exportateur de
dossiers ; `noortrace-ctl` et l'outil de gel ; le coffre. Un collecteur, sous
l'identité d'EX-10.3, convertit chaque enregistrement brut en une ligne
`consultation-v0` et l'ajoute au fichier du jour
`exploitation/consultations/consultations-<AAAA-MM-JJ>.ndjson` ; la règle
`noortrace_consultations_muettes` (10.7) alerte quand aucune ligne n'arrive
pendant un jour. La collecte reste du ressort du client (L-1 reste
`releve_du_client`) ; CT-8 en fixe la forme, la conservation et le contrôle.

**EX-11.20** Une ligne est un objet JCS v0 (CT-1 §4) suivi de `\n` ; les
vérifications CA- s'appliquent à un fichier :

| Id | Vérification |
|---|---|
| CA-1 | Chaque ligne s'analyse en JSON strict, est conforme à `consultation-v0` et est écrite en JCS v0. |
| CA-2 | `n` vaut 1 pour la première ligne et croît de 1, sans trou. |
| CA-3 | `prev_sha256` de la ligne 1 est le SHA-256 du nom du fichier en UTF-8 ; celui de la ligne `n` est le SHA-256 des octets de la ligne `n − 1` sans son `\n`. |
| CA-4 | `collected_at` ne décroît pas ; `ts` ≤ `collected_at`. |
| CA-5 | `source.record_sha256` est le SHA-256 de l'enregistrement brut que `source.locator` désigne, quand la source est fournie au contrôle. |
| CA-6 | `role` n'est pas `inconnu` ; un principal sans rôle déclaré lève `noortrace_acces_non_declare` (10.7) et ouvre RB-8. |

Le chaînage de CA-3 rend visible la suppression ou l'insertion d'une ligne
dans un fichier ; la copie WORM d'EX-11.21 empêche la réécriture du fichier
entier, que le chaînage seul ne détecte pas.

**EX-11.21** Chaque fichier du jour, une fois clos, est copié sur le support
WORM sous `<prefix>exploitation/consultations/`, avec la règle conditionnelle
de CT-2 EX-12.16, et conservé aussi longtemps que le journal (CT-7 EX-8.15) ;
ses lignes sont des données personnelles du client (identité des principaux)
et sont protégées comme le journal d'exploitation (CT-2 EX-9.6).

Première ligne du fichier d'exemple (export d'un dossier par un réviseur ;
valeurs calculées) :

<!-- schema: consultation -->
```json
{
  "version": 0,
  "n": 1,
  "prev_sha256": "0x0ad64198e302befed67d7008926dbd7e35ccd842ed9fd42d7932e38d714c9f8b",
  "ts": "2026-11-05T10:02:11.348Z",
  "collected_at": "2026-11-05T10:02:12.001Z",
  "source": {
    "kind": "outil_export",
    "record_sha256": "0xb2f85cc95498a25900469a5d6d7ea91994ed1c06cd5a5a5abecf303c798c223c",
    "locator": "exploitation/exports-2026-11-05.ndjson:1"
  },
  "principal": "reviseur-externe-1",
  "role": "exportateur",
  "action": "export",
  "object": {
    "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
    "journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
    "path": "dossier seq 3",
    "version_id": null
  },
  "outcome": "autorise",
  "motif": "AUDIT-2026-07"
}
```

### 11.11 Archivage du journal d'exploitation

**EX-11.22** Le démon ne garde que `logging.keep_files` fichiers tournés de
son journal d'exploitation (CT-2 EX-9.7) ; l'archivage au-delà relève de
CT-8 (CT-2 EX-9.6 ; lacune L-9). Chaque fichier tourné DOIT être copié, avant
d'être écarté par la rotation, sur le support WORM sous
`<prefix>exploitation/<instance_id>/` et dans l'archive de 11.2, et conservé
pour la durée du journal (CT-2 EX-9.6 : « conservé avec le journal, pour la
même durée ») ; `keep_files` DOIT être assez grand pour couvrir l'intervalle
de la copie (cible : deux intervalles). La copie est faite par une tâche
hors du démon tant que la proposition PA-18 de CT-7 (copie par l'écrivain)
n'est pas adoptée par CT-2.

**EX-11.23** La série copiée se relit hors du démon (EX-10.9,
`copie_exploitation`) : les fichiers d'une instance se suivent sans trou de
date (le `ts` de la première ligne d'un fichier suit celui de la dernière du
précédent) ; une discontinuité est alertée et consignée dans le paquet
d'incident. Le journal d'exploitation n'a pas de valeur probatoire (CT-2
§9.2) : sa copie sert la consignation des procédures exigée par l'Olico
(art. 9 al. 1 let. b ch. 4, CT-2 EX-12.21), pas la preuve des événements.

### 11.12 Tâches périodiques d'exploitation

**EX-11.24** Le client DOIT planifier les tâches suivantes, qui complètent les
tâches TP-1 à TP-8 posées à l'installation (EX-8.6) et en reprennent
quelques-unes ; chacune laisse une trace datée (ligne de journal ou
procès-verbal) que la supervision lit :

| Tâche | Cadence | Trace | Source |
|---|---|---|---|
| Archive de sauvegarde et procès-verbal `sauvegarde` | chaque jour, ou au RPO retenu | procès-verbal | EX-11.2, EX-11.5 |
| Exercice de restauration | une fois par an au moins, et après tout changement de support | procès-verbal `exercice_restauration` | EX-11.8 |
| Pose du gel sur la période close (support sans Compliance validé) | à chaque clôture | ligne `worm_legal_hold_set` | EX-11.17 |
| Relecture du registre des gels par le rôle Lecteur | chaque jour | `noortrace_releve_externe_ok{check="registre_gels"}` | EX-10.9 ; CT-2 EX-17.7 |
| Comparaison des empreintes de la console | chaque jour | `noortrace_releve_externe_ok{check="console"}` | EX-10.9 ; CT-7 EX-3.9 |
| Copie et relecture des fichiers tournés du journal d'exploitation | à chaque rotation ; relecture chaque jour | `noortrace_releve_externe_ok{check="copie_exploitation"}` | EX-11.22, EX-11.23 |
| Copie WORM des fichiers du journal des consultations | chaque jour | ligne `worm_copy_*` de la tâche | EX-11.21 |
| Réétablissement du statut qualifié des prestataires RFC 3161 | tous les trente jours au plus | ligne de l'outil d'ancrage | CT-5 EX-5.9 |
| Tenue du fichier d'en-têtes Bitcoin (source `fichier`) | une fois par jour (TP-3) ; chaque exécution traite chaque période dont une preuve est devenue complète depuis la précédente | `entetes-bitcoin.json` de la période | CT-5 EX-6.8 |
| Fin de rétention | à chaque échéance, après lecture du registre des gels | procès-verbal `fin_de_retention` | EX-11.15 |
| Exercice de rotation d'urgence et de révocation | une fois par an | procès-verbal de cérémonie | CT-7 EX-3.12 |

| Id | Adressée à | Proposition | Motif |
|---|---|---|---|
| PD-13 | CT-2 (EX-12.16) | Copier `journal.json` sur le support WORM comme les manifestes | Le chemin B (11.4) le reconstruit aujourd'hui depuis la configuration |
| PD-14 | CT-6 et l'exportateur | Écrire une ligne d'export (dossier, demandeur, instant) dans un fichier en ajout seul que le collecteur de 11.10 lit | Source `outil_export` d'EX-11.19 |
| PD-15 | CT-2 (§17.2) | Exposer `noortrace_worm_copy_last_success_age_s` par sorte de fichier copié | Règle de 10.4 sur la copie du journal d'exploitation et des consultations sans extracteur |

## 12. Mode observation

Un client qui installe NOORTRACE veut souvent voir d'abord ce que l'enregistreur
capture et ce que sa politique exigerait, sans qu'aucun appel de ses agents ne
soit bloqué ni retenu par la politique d'approbation (le temps d'écriture reste
celui du mode bloquant, EX-12.5). Les pratiques publiées de déploiement
progressif d'une politique distinguent trois comportements, combinables :
refuser, avertir sans refuser, consigner sans refuser ni avertir (actions
`deny`, `warn` et `dryrun` d'un contrôleur d'admission, R9-F48, R9-F49 ; modes
`enforce`, `warn` et `audit`, R9-F53 ; `validationActions` `Deny`, `Warn`,
`Audit`, R9-F51). Le mode observation de NOORTRACE est le troisième : la
politique d'approbation est évaluée sur chaque appel, ce qu'elle aurait exigé
est consigné dans l'événement signé, et rien n'est refusé ni retenu par la
politique. Rien de cela n'existait dans CT-2 0.5 ni dans CT-3 0.3, où les deux
modes d'attente (`retenir`, `erreur`) bloquent l'appel jusqu'à la décision
(R8-F47, R8-F48) ; la révision 0.6 de CT-2 et la révision 0.4 de CT-3, minimales
et compatibles, l'ajoutent (12.9). Les formats de CT-1 v0 ne changent pas.

Ce mode n'a rien de commun avec le « point d'observation » d'un adaptateur
de CT-2 (accroche qui ne peut rien empêcher, CT-2 §2, R9-F54), ni avec le
« mode observateur » de noorcore, décision ouverte 7 de l'architecture
(nœud non validateur qui rejoue les blocs, `ARCHITECTURE.md` l. 531-536,
R8-F26).

### 12.1 Définition et activation

**EX-12.1** L'ensemble de politique est **en mode observation** quand son
membre `policy.approval.mode` vaut `observation` (CT-2 révision 0.6, schéma
`configuration-enregistreur-v0` étendu de façon compatible). Comme tout membre
de l'ensemble de politique, ce réglage est haché dans `policy_sha256` et
annoncé dans la chaîne par un événement `noortrace.journal.politique` avant
le premier appel qu'il gouverne (CT-2 EX-9.1, EX-10.21) ; la pièce de
l'ensemble de politique, stockée sous son `policy_sha256` (CT-2 EX-8.11),
le prouve à qui la détient. Le service d'approbation le reçoit dans
`approval` du message `charger` (CT-3 §12.2), sans message nouveau.

**EX-12.2** Seul le membre `mode` change entre un ensemble en mode
observation et le même en mode bloquant ; la commande de validation (CT-2
EX-15.7) avertit nommément qu'aucun appel ne sera bloqué ni soumis à
approbation (CT-2 EX-15.8), et exige que `policy.version` finisse par
`-observation` (suffixe interdit hors de ce mode, CT-2 EX-15.8, révision 0.6).
L'installation rapide de la section 7 emploie ce mode et installe le service
d'approbation (EX-7.3) ; sans lui, chaque appel porte la marque `inconnu`
(12.3). Aucun ticket n'étant créé en observation, `hold_timeout_ms` et
`expire_after_ms` y sont sans effet ; ils restent écrits pour que le passage au
mode bloquant ne change que `mode` et `version` (12.6).

```text
"approval": { "rules": { … }, "mode": "observation", "hold_timeout_ms": 50000,
              "expire_after_ms": 3600000, "timeout_ms": 2000, "service": { … } }
```

L'ensemble de politique de l'exemple de CT-2 §15.3, avec `mode` à
`observation` et `version` à `2026-11-05-observation`, valide contre le
schéma étendu et non contre le schéma de CT-2 0.5 (vérifié par `ajv-cli` 5,
`--strict=true`) ; son empreinte est
`0x3d0e81832bce1e5b653040304a65dfdc0e3912ba24e10ae44b2b78431516da36`
(6 550 octets en JCS intégral, calcul de `empreinteEnsemblePolitique` de
`scripts/lib/capture.mjs`, la même fonction rendant pour l'ensemble de CT-2
§15.3 l'empreinte que CT-2 §10.6 imprime).

### 12.2 Ce qui est capturé, ce qui n'est jamais bloqué

**EX-12.3** En mode observation, l'enregistreur capture et journalise tout
ce qu'il capture en mode bloquant : chaque appel d'outil (frontal MCP, SDK),
chaque échange de modèle (passerelle, ICAP, miroir), chaque span admis par
l'ingestion OpenTelemetry ; mêmes pièces, même rédaction avant hachage (la
rédaction n'est pas une politique d'approbation : elle reste appliquée),
même signature, même chaînage, mêmes manifestes, points et ancres. Chaque
appel d'outil est évalué par le service d'approbation comme en mode bloquant
(CT-3 §6), et le résultat est porté par l'événement (12.3). Il capture les
mêmes sources que le mode bloquant et scelle un événement pour chaque appel
qu'il relaie tant qu'aucune borne d'attente de CT-2 EX-14.9 n'est atteinte.
Au-delà, le mode bloquant refuse l'appel (ni action ni événement), tandis que
le mode observation relaie l'appel et perd l'événement, perte comptée par la
ligne `event_lost` et par `noortrace_events_lost_total` (EX-12.14).

**EX-12.4** En mode observation, l'enregistreur NE DOIT JAMAIS, pour un appel
qu'il peut relayer : rendre le refus par la politique ou le signal d'approbation
(CT-2 EX-4.49) ; créer un ticket ou retenir une requête ; rendre `-31010` « mode
dégradé » d'une autre raison que `bail_non_detenu` (service d'approbation
indisponible, stockage, clé, horloge, attente, budget de rédaction) ; rendre
`-31013` « taille ou quota » de direction `quota` ; rendre `-31017` « panne
après relais » ; rendre à un échange de modèle le corps `noortrace_degrade` de
CT-2 §14.2. Les seules erreurs qu'il rend lui-même sont celles où il n'y a rien
à relayer ou rien à lire (liste fermée de CT-2 EX-14.17) : connexion d'hôte non
authentifiée (CT-2 §4.8) ; message de l'hôte qui n'est pas du JSON-RPC valide
(`-32700` « erreur d'analyse », `-32600` « requête invalide », `-32601`
« méthode inconnue », `-32602` « paramètres invalides ») ; `-31014` « outil
inconnu ou serveur injoignable » ; `-31013` « taille ou quota », directions
`requete` et `reponse` (au-delà de `limits.request_max_bytes` ou
`limits.response_max_bytes`) ; `-31016` « non relayable par la configuration »
(CT-2 §4.6) ; `-31010` de raison `bail_non_detenu`, rendu par une instance
passive qui n'est pas en service (seconde instance d'un déploiement à deux
instances, qui ne détient pas le bail d'écriture du journal et vers laquelle
l'adresse des hôtes ne doit pas être basculée, EX-3.11 ; CT-2 §13.4 ; une
adresse basculée vers elle relève de RB-2, runbook du bail perdu, 10.13). Les
délais (`-31011`) et annulations (`-31012`) viennent du serveur ou de l'hôte. Le
client règle `limits.*` au-dessus des tailles de ses outils. Le budget de
rédaction dépassé ne bloque pas : la pièce est remplacée par la pièce « non
rédigeable » de CT-2 EX-8.7 (`reason: "budget_redaction"`, `redacted: true`),
comme pour un outil de lecture, et l'appel est relayé (CT-2 EX-14.16). Le mode
bloquant, lui, aurait refusé un appel d'écriture ou susceptible d'approbation
par `-31010`, raison `redaction` (CT-2 EX-10.23, opération 1) : c'est la raison
`redaction` de la ligne `observation_would_block` (EX-12.7).

**EX-12.5** Le temps que l'enregistreur ajoute à un appel en mode observation ne
dépend d'aucune décision humaine ni d'aucune sortie de mode dégradé : il est
borné par l'attente de l'évaluation (au plus `policy.approval.timeout_ms`,
défaut 2 000, au-delà de quoi l'appel est relayé avec la marque `inconnu`) et
par l'écriture de l'intention et de l'événement quand le stockage répond, comme
en mode bloquant (CT-2 EX-4.19 ; cibles de latence de CT-2 §16.1, à mesurer,
CT-9) ; quand le stockage, la clé, le bail ou l'horloge font défaut, l'appel est
relayé sans attendre et l'événement est mis en attente (CT-2 EX-14.16 ; fichier
d'attente `attente/attente-<epoch>.ndjson` du journal, CT-2 §14.5 et EX-12.1 ;
son scellement à la reprise, CT-2 EX-14.10, est la ligne `pending_flushed` du
pas 4 de RB-1). L'événement reste durable avant la réponse quand le stockage
répond, parce que c'est ce qui rend la capture complète. Les bornes d'attente
sont celles de CT-2 EX-14.9 : `policy.failure.pending_max_events` (défaut
10 000), `limits.pending_max_bytes` (défaut 268 435 456) et
`policy.failure.pending_max_ms` (défaut 300 000) ; au-delà de l'une d'elles,
chaque événement est perdu et compté (EX-12.14). « Sans retard » s'entend d'un
retard dû à une décision ou à l'attente d'une sortie de mode dégradé. Le temps
d'écriture n'a pas de borne normative en version 0.1 : sa cible est celle de
CT-2 §16.1, à mesurer (CT-9). CT-2 0.6 ne fixe pas non plus de durée au-delà de
laquelle une écriture lente vaut panne : le mode dégradé « stockage », qui fait
relayer l'appel sans attendre, naît d'une erreur de `write` ou de `fdatasync`,
d'un disque plein, d'un segment corrompu ou d'un répertoire inaccessible (CT-2
§14.2, ligne « Stockage indisponible ») ; un stockage qui répond lentement
retarde donc l'appel sans borne écrite (section 15).

### 12.3 Ce qui est consigné

**EX-12.6** Chaque appel d'outil relayé en mode observation est un événement
`executee` de CT-1 v0 avec `policy.decision` = `autorise`, `policy.ticket` =
`null`, `approval` = `null`, et `policy.rule` = la chaîne de l'évaluation (CT-3
EX-6.4, avec ses marques ` [indetermine]` ou ` [fenetre …]`) suivie de la
**marque d'observation** ` [observation <x>]`, où `<x>` est la décision que la
politique a rendue (`autorise`, `a_approuver`, `refuse`), ou `inconnu` quand
l'évaluation n'a pas pu être faite (service indisponible, délai, réponse
invalide) ; dans ce dernier cas seulement, la chaîne qui précède la marque est
le nom fixe `evaluation impossible`. La marque est toujours la dernière ; elle
se lit après la dernière occurrence de ` [observation ` ; la grammaire est de
CT-3 (EX-6.8, révision 0.4), la chaîne reste sous les 1 024 caractères de CT-1.
Ces formes sont réservées : un nom de règle ne peut ni valoir `evaluation
impossible` (seul ou suivi de ` [`) ni contenir `[observation` (schéma
`politique-approbation-v0` et validation de CT-3 EX-4.2) ; une réponse du
service dont la `rule` porte une telle forme, ou dépasse 998 caractères (1 024
moins la plus longue marque, ` [observation a_approuver]`, 26 caractères), est
une réponse invalide : marque `inconnu` et `approval_response_invalid` (CT-2
EX-7.23, CT-3 EX-12.20). `policy.decision` vaut `autorise` parce que l'appel a
été relayé sans ticket : `a_approuver` exige un ticket (CT-1 §5.3) et le
vérificateur refuse la décision `sans_objet` pour un appel (vérification E-3
de CT-1, R8-F49) ; CT-2 EX-6.23 fait déjà de même pour un appel d'outil issu
d'un span, scellé `autorise` alors que la politique ne l'a pas décidé.

| Évaluation de la politique | `policy.rule` scellée |
|---|---|
| règle `lectures autorisees`, `autorise` | `lectures autorisees [observation autorise]` |
| règle `paiement > 5000 CHF`, `a_approuver` | `paiement > 5000 CHF [observation a_approuver]` |
| règle `paiement hors CHF`, `refuse` | `paiement hors CHF [observation refuse]` |
| règle par défaut `defaut : revue` | `defaut : revue [observation a_approuver]` |
| condition indéterminée | `paiement > 5000 CHF [indetermine] [observation a_approuver]` |
| service d'approbation sans réponse | `evaluation impossible [observation inconnu]` |

**EX-12.7** Le journal d'exploitation reçoit, pour chaque appel que le mode
bloquant aurait bloqué, retenu ou refusé, une ligne
`observation_would_block`, et, pour chaque événement perdu au-delà des bornes
d'attente, une ligne `event_lost` (raison, nombre) (CT-2 EX-17.2, révision
0.6). Le `data` de `observation_would_block` porte `would`, la raison, l'alias,
la classe et le `seq` de l'événement (`null` s'il est en attente), jamais les
arguments. `would` vaut `a_approuver`, `refuse` ou `inconnu`, ou `autorise`
quand la politique autorisait l'appel et que seuls une panne, un quota ou le
budget de rédaction l'auraient bloqué. La raison est celle que le mode
bloquant aurait rendue : `approbation`, `politique`, `redaction`, `quota`,
`stockage`, `cle`, `bail`, `horloge` ou `attente` ; `redaction` désigne le
budget de rédaction dépassé (EX-12.4), non la rédaction elle-même, qui reste
appliquée.

**EX-12.8** Les métriques de CT-2 EX-17.8 (révision 0.6) :
`noortrace_observation_mode` (jauge, 1 en mode observation),
`noortrace_observation_marks_total{would}` (compteur des événements marqués),
`noortrace_observation_would_block_total{reason}` et
`noortrace_events_lost_total{reason}` ; les règles
`noortrace_mode_observation_actif` et `noortrace_observation_pertes` de 10.7
les alertent.

### 12.4 Ce qu'un dossier dit

**EX-12.9** Tout dossier dont l'événement prouvé a été scellé en mode
observation le dit par `code.policy_version`, signé avec l'événement, qui finit
par `-observation` (CT-2 EX-15.8, révision 0.6) quel que soit l'événement (appel
d'outil, échange de modèle, span ou rotation ; un événement de décision est
impossible sous une version en observation, OB-4). Hors des appels d'outil,
`policy.rule` est nul et ne porte donc pas de marque ; seul l'appel d'outil le
dit en plus par la marque de `policy.rule`. Le vérificateur de CT-6 ne lit ni le
suffixe ni la marque et rend le même verdict qu'en mode bloquant : ils ne
changent ni l'intégrité, ni la signature, ni les ancres. L'outil de vérification
du paquet réviseur (section 13) déclare, pour chaque dossier, `observation_mode`
(EX-13.28), et son résumé lisible ajoute la ligne « Observation » : le nombre de
dossiers en mode observation et celui des appels marqués par décision
(`summary.observation`).

Événement `seq` 3 du journal d'exemple : un paiement de 7 400 CHF que la
politique de CT-2 §15.3 soumet à revue, relayé en mode observation (valeurs
calculées par le script de calcul, clé de test `rec-test-01` ; la chaîne des
sept événements passe `verifierChaine` de `scripts/lib/journal.mjs` et
chaque événement valide contre `evenement-v0`) :

<!-- schema: evenement -->
```json
{
  "version": 0,
  "seq": 3,
  "ts": "2026-11-05T08:01:30.400Z",
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
  "recorder_key_id": "rec-test-01",
  "prev_hash": "0xb8f666e5d7c656c5e673f6d9cf00700f5deeb831b7867fa46b0277b76708519c",
  "delegation": {
    "launched_by": "agent-sinistres",
    "on_behalf_of": "service-sinistres",
    "scope": "sinistres:lecture,paiement",
    "run_id": "run-2026-11-05-0042"
  },
  "code": {
    "model": "fournisseur/modele@2026-09",
    "prompt_version": null,
    "policy_version": "2026-11-05-observation",
    "recorder": "0.1.0"
  },
  "intent": null,
  "policy": {
    "rule": "paiement > 5000 CHF [observation a_approuver]",
    "decision": "autorise",
    "ticket": null,
    "redaction": null
  },
  "approval": null,
  "execution": {
    "tool": "sap__payments.create",
    "arguments": {
      "sha256": "0xfb18d13a89ee1dbd6ecd7b36f89085fb24d8298632fe8b5d8e581940150cb9a1",
      "length": 61,
      "redacted": false
    },
    "status": "executee",
    "result": {
      "sha256": "0xecef30d54ff85cb9f99d8866f15513d482157e03697d796feb8548477109da82",
      "length": 116,
      "redacted": false
    },
    "duration_ms": 213,
    "is_error": false
  },
  "effects": [
    {
      "system": "SAP",
      "action": "ecriture",
      "object": "PAY-000981",
      "amount": "7400.00",
      "currency": "CHF"
    }
  ],
  "context": [],
  "hash": "0xf9bf8b088b139609ca54f2abfac3dbb5c4333105ad0031e718e81c82dca80287",
  "sig": "0x0d923cd96e2a521cdbfaf7285ae222291ae10107ae43f5315acd624d09163a8d9b526ca97d913b87bdcc2d8fce1841164c5856c552112e0014a1f8caacfe0009"
}
```

### 12.5 Rapport d'observation

**EX-12.10** L'outil de référence `scripts/deploiement/rapport-observation.mjs
<événements> [--politiques <répertoire>] [--json]` (fichier NDJSON d'événements,
ou répertoire de journal de CT-2 EX-12.1 ; `--politiques` désigne un répertoire
de pièces d'ensembles de politique, un fichier `<policy_sha256 sans 0x>.json`
par ensemble, comme `observation/politiques/` des vecteurs, A.6, nécessaire à
OB-3 et OB-4, EX-12.16) rend le rapport `rapport-observation-v0` : pour chaque
version de politique, chaque règle (marque d'observation retirée, autres marques
gardées) et chaque décision, le nombre d'appels et, hors `autorise`, leurs
`seq` ; les totaux ; les anomalies OB-1 et OB-2. Il ne lit ni pièce ni clé : il
se recalcule par quiconque a les événements. Les autres marques sont gardées
pour que le responsable de la politique distingue une décision prise sur une
condition indéterminée (`seq` 6) d'une décision prise sur une condition établie
(`seq` 3) : la règle est la même, la correction attendue diffère. Rapport des
sept événements du journal d'exemple :

<!-- schema: rapport-observation -->
```json
{
  "version": 0,
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
  "first_seq": 1,
  "last_seq": 7,
  "from_ts": "2026-11-05T08:00:00.000Z",
  "to_ts": "2026-11-05T08:05:30.400Z",
  "events": 7,
  "tool_calls": 6,
  "observed": 6,
  "totals": {
    "autorise": 1,
    "a_approuver": 3,
    "refuse": 1,
    "inconnu": 1
  },
  "rows": [
    {
      "policy_version": "2026-11-05-observation",
      "rule": "defaut : revue",
      "would": "a_approuver",
      "count": 1,
      "seqs": [
        5
      ]
    },
    {
      "policy_version": "2026-11-05-observation",
      "rule": "evaluation impossible",
      "would": "inconnu",
      "count": 1,
      "seqs": [
        7
      ]
    },
    {
      "policy_version": "2026-11-05-observation",
      "rule": "lectures autorisees",
      "would": "autorise",
      "count": 1,
      "seqs": []
    },
    {
      "policy_version": "2026-11-05-observation",
      "rule": "paiement > 5000 CHF",
      "would": "a_approuver",
      "count": 1,
      "seqs": [
        3
      ]
    },
    {
      "policy_version": "2026-11-05-observation",
      "rule": "paiement > 5000 CHF [indetermine]",
      "would": "a_approuver",
      "count": 1,
      "seqs": [
        6
      ]
    },
    {
      "policy_version": "2026-11-05-observation",
      "rule": "paiement hors CHF",
      "would": "refuse",
      "count": 1,
      "seqs": [
        4
      ]
    }
  ],
  "anomalies": []
}
```

### 12.6 Passage au mode bloquant

**EX-12.11** Le passage du mode observation au mode bloquant (`erreur`, le
défaut de CT-3 EX-11.1, ou `retenir`) DOIT suivre ces pas, chacun avec sa
porte :

1. Produire le rapport d'observation de la période observée et le relire
   règle par règle avec le responsable de la politique ; porte : chaque
   ligne `a_approuver`, `refuse` et `inconnu` est attendue, ou la politique
   est corrigée (nouvelle version, toujours en observation).
2. Vérifier ce que le mode bloquant exige : annuaire des approbateurs
   peuplé et jeu d'approbateurs lisible (CT-3 §8, §13.4), console joignable,
   `noortrace_approbation_pret` à 1, délais des hôtes compatibles avec le
   mode choisi (CT-3 EX-11.2) ; remplacer le jeu d'approbateurs de test de
   l'installation rapide (comptes publics de CT-7 CLE-28, 7.3) par le jeu
   réel de l'organisation ; porte : aucune alerte de la section 10 sur le
   service d'approbation, et aucune adresse de CLE-28 dans le jeu de la
   nouvelle configuration (la validation du pas 3 le refuse en production et
   en avertit ailleurs : `approbateurs_de_test`, CT-2 EX-15.8).
3. Écrire la configuration avec `mode` à `erreur` ou à `retenir` (le mode
   choisi au pas 2, selon les délais des hôtes, CT-3 EX-11.2) et une
   `policy.version` nouvelle, sans le suffixe `-observation` et jamais
   employée dans ce journal (CT-7 PA-9), sur le même fichier (réécriture en
   place, EX-11.12), puis la valider dans le conteneur : `$DC run --rm
   --no-deps enregistreur validate-config /etc/noortrace/configuration.json`
   (comme à IR-5 ; `$DC` est celui d'EX-7.4 pour l'installation rapide, de
   8.3 pour la production) ; porte : code 0, sans l'avertissement
   `approbateurs_de_test`. L'exemple de procès-verbal qui suit vaut pour
   `erreur`.
4. `$DC exec enregistreur noortrace-ctl reload` (un changement du seul membre
   `policy` se recharge sans redémarrage, CT-2 EX-15.5) ; porte : ligne
   `config_reloaded` qui porte le SHA-256 du fichier relevé sur l'hôte, puis
   événement `noortrace.journal.politique` dont `policy_sha256` est celui du
   nouvel ensemble.
5. Vérifier, en cinq sous-pas :
   - 5a : la version écrite au pas 3 porte une règle de test `a_approuver`
     sur un appel d'un outil de lecture sans effet ;
   - 5b : `noortrace_observation_mode` vaut 0, et le rapport sur les
     événements qui suivent l'événement de politique a `observed` à 0 ;
   - 5c : l'appel de test reçoit le signal d'approbation (CT-2 EX-4.49) ; le
     ticket créé est refusé ou laissé expirer ;
   - 5d : une version suivante, toujours sans suffixe, retire la règle de
     test par les pas 3 et 4 (`validate-config`, `reload`, événement
     `noortrace.journal.politique`, de `seq` noté b) ;
   - 5e : le procès-verbal du pas 6 cite le ticket de test et le `seq` b dans
     `observations` ; 5d ne fait l'objet d'aucun procès-verbal
     `passage_mode`, le mode ne changeant pas (PV-6 exige `from ≠ to`).
6. Écrire le procès-verbal `passage_mode` (11.9), signé par l'exécutant et
   par l'approbateur de la décision de passage par les moyens du client
   (signature électronique ou manuscrite, EX-11.13 ; PV-5 exige deux
   identités distinctes, dont un `temoin` ou un `approbateur`, ici
   l'approbateur), avec le SHA-256 (JCS) du
   rapport relu au pas 1 et le `seq` de l'événement de politique ; le copier
   sur le support WORM. Pour cette sorte, `source` désigne le journal
   concerné, `verification` la vérification du journal faite après le pas 4,
   et le rapport relu au pas 1 est dans `mode_change.report_sha256`.

**EX-12.12** L'événement sur soi est l'événement que le journal écrit sur
lui-même pour annoncer un changement de sa propre configuration ; ici,
l'annonce du nouvel ensemble de politique. Celui du passage est l'événement
`noortrace.journal.politique` du pas 4 (CT-7 JS-6, porté par CT-1 v0) : tout
appel scellé après lui porte la nouvelle `policy_version` et aucune marque
d'observation ; tout appel dont l'évaluation a commencé avant lui finit sous
l'ancienne (CT-2 EX-15.5). Procès-verbal du passage du journal d'exemple
(valeurs calculées ; l'événement de politique serait le `seq` 8) :

<!-- schema: proces-verbal-exploitation -->
```json
{
  "version": 0,
  "kind": "passage_mode",
  "id": "pv-2026-11-05-002",
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
  "started_at": "2026-11-05T09:45:00.000Z",
  "finished_at": "2026-11-05T09:47:30.000Z",
  "operators": [
    {
      "identity": "administrateur-noortrace",
      "role": "executant"
    },
    {
      "identity": "responsable-conformite",
      "role": "approbateur"
    }
  ],
  "reason": "fin de la periode d'observation, decision COMITE-2026-11",
  "source": {
    "medium": "volume_local",
    "locator": "volume noortrace-donnees-2, hote enregistreur-1"
  },
  "destination": null,
  "files": [],
  "totals": {
    "files": 0,
    "bytes": 0
  },
  "verification": {
    "tool": "verifier-journal 0.1.0 (CT-8 EX-11.7)",
    "command": "node scripts/deploiement/verifier-journal.mjs . --cles cles.json",
    "result": "valide",
    "report_sha256": null
  },
  "continuity": null,
  "retention": null,
  "mode_change": {
    "from": "observation",
    "to": "erreur",
    "policy_version": "2026-11-05-erreur",
    "policy_sha256": "0x78cd21431c3fc9166386bdd513407967d05a2da496d704cbf0a5a1c31d9f1c5b",
    "policy_event_seq": 8,
    "report_sha256": "0x2df5ab6987cc8345b9a6f8bee1002b97b708901ee996faa44506bd9fb4254794"
  },
  "observations": null
}
```

L'exemple illustre le schéma avant le pas 5 : le procès-verbal réel du pas 6
porte, dans `observations`, l'identifiant du ticket de test et le `seq` de
l'événement `noortrace.journal.politique` qui retire la règle de test (pas 5),
et, dans `verification.report_sha256`, le SHA-256 du rapport de
`verifier-journal.mjs` rendu après le pas 4 ; ces deux valeurs ne changent ni le
schéma ni PV-1 à PV-10.

**EX-12.13** Le passage inverse, du mode bloquant au mode observation, suit
les pas 3 à 6, adaptés : au pas 3, `mode` à `observation` et une version
nouvelle qui finit par `-observation` ; au pas 5, `noortrace_observation_mode`
vaut 1 et chaque appel qui suit l'événement de politique porte une marque,
sans appel de test d'approbation ; au pas 6, `report_sha256` est nul. Il est
refusé tant qu'un ticket a une `retenue` sans décision scellée dans les
fichiers des approbations (raison `tickets_ouverts`, CT-2 EX-15.8) : le client
attend les décisions ou les expirations. Les fenêtres (autorisations bornées
dans le temps et en nombre d'appels, CT-3 §2) ouvertes avant le passage
restent dans le service : une autorisation déjà ouverte reste valable ; en
observation, un appel qu'elle couvre porte la marque
` [fenetre …] [observation autorise]` et n'est pas décompté (aucune unité
consommée, CT-3
EX-11.13).

### 12.7 Ce que le mode observation prouve et ne prouve pas

**EX-12.14** Un journal tenu en mode observation prouve, comme en mode
bloquant, l'intégrité, l'ordre, l'auteur et la date (dans les limites de
CT-6) de chaque événement scellé, et, par la marque, ce que la version de
politique annoncée aurait exigé pour chaque appel relayé. Il ne prouve pas :
qu'un humain a approuvé quoi que ce soit (aucun ticket n'existe) ; que la
politique aurait été appliquée telle quelle (un appel `a_approuver` aurait pu
être refusé ou expirer) ; que tous les appels ont été capturés, puisqu'au-delà
des bornes d'attente un événement est perdu sans trou dans la chaîne (les
`seq` sont attribués au scellement : la chaîne est complète pour les
événements scellés, non pour les appels relayés ; une chaîne sans lacune de
`seq` ne prouve donc pas que chaque appel relayé a son événement) et que
seuls le journal d'exploitation et `noortrace_events_lost_total` disent la
perte.

**EX-12.15** Le mode observation ne s'applique qu'à la politique
d'approbation et aux pannes ; il ne change ni la rédaction, ni
l'authentification des hôtes, ni la surface d'écoute (CT-2 §18), ni les
secrets, ni la garde des clés, ni le stockage. Un client NE DEVRAIT PAS
tenir en mode observation un journal dont des actions exigent, par contrat
ou par la loi, une approbation préalable.

### 12.8 Vérifications OB-

**EX-12.16** Vérifications du mode observation, exécutées par
`scripts/deploiement/rapport-observation.mjs`, le vérificateur Go de ct-8 et
`test/deploiement.test.js` :

| Id | Vérification | Entrée |
|---|---|---|
| OB-1 | Marque, sur toute chaîne `policy.rule` qui contient `[observation`. Dans cet ordre, la première erreur l'emporte : `trop_longue` (plus de 1 024 caractères, en points de code) ; `absente` (pas de ` [observation ` ou pas de `]` final ; la marque est lue après la dernière occurrence de ` [observation `) ; `valeur_inconnue` (`<x>` hors de `autorise`, `a_approuver`, `refuse`, `inconnu`) ; `nom_vide` (la chaîne qui précède la marque est vide ou finit par une espace) ; `marque_en_double` (la chaîne qui précède contient encore `[observation`) ; `inconnu_sans_nom_fixe` (`inconnu` alors que la chaîne qui précède n'est pas exactement `evaluation impossible`) ; `nom_fixe_sans_inconnu` (une autre valeur qu'`inconnu` alors que la chaîne qui précède est `evaluation impossible`, seule ou suivie de ` [`, nom réservé par CT-3 EX-6.8). Une marque valide rend la règle (chaîne qui précède) et la décision `<x>`. | chaîne |
| OB-2 | Cohérence : un événement d'un outil réservé (préfixe `noortrace.`) qui porte `[observation` est en anomalie `incoherence_marque` ; un appel d'outil dont la marque est valide (OB-1) est `executee`, avec `policy.decision` `autorise`, `policy.ticket` et `approval` nuls, sinon `incoherence_marque`. | événement |
| OB-3 | Exclusivité : sous une version de politique dont la pièce dit `mode` `observation`, chaque appel d'outil est marqué ; sous une autre, aucun ne l'est (`marque_hors_observation`, `marque_absente`). | événements et pièces de politique |
| OB-4 | Aucune approbation : sous une version en observation, aucun événement `retenue`, aucun `refusee` d'un appel, aucun `noortrace.approbation.decision` (`approbation_en_observation`). La version d'un événement est son `code.policy_version` ; son mode est celui de la pièce (`approval.mode`) que désigne l'événement `noortrace.journal.politique` qui annonce cette version (`policy_sha256` de ses arguments en ligne). | événements et pièces de politique |
| OB-5 | Rapport : le rapport recalculé sur les événements est identique, octet pour octet en JCS, au rapport attendu. | événements |
| OB-6 | Correspondance : pour un cas d'évaluation de CT-3 en mode observation, la réponse du service est `{rule, decision, null, null, null, null}` avec `rule` et `decision` de l'évaluation, aucune unité de fenêtre n'est consommée, aucun ticket n'est créé, et le membre `policy` scellé est celui d'EX-12.6 ; service indisponible : réponse nulle et `evaluation impossible [observation inconnu]`. | cas de `spec/vecteurs/ct-8/observation/correspondance.json` |

OB-3 et OB-4 exigent les pièces de politique (option `--politiques <répertoire>`
de l'outil, EX-12.10) ; sans elles, elles sont non exécutées et le rapport le
dit. Les anomalies sont triées par `seq`, puis par identifiant de vérification ;
un appel en anomalie OB-1 ou OB-2 n'est pas compté dans le rapport (`observed`,
`totals`, `rows`).

### 12.9 Révisions de CT-2 et de CT-3

Le mode exige deux révisions minimales et compatibles, dont le texte est dans
les révisions elles-mêmes : CT-2 0.6 (valeur `observation`, événement d'un appel
en mode observation, réponse du service sans ticket, pannes non bloquantes,
validation avec le suffixe `-observation` et le refus des approbateurs de test,
métriques et lignes de journal) et CT-3 0.4 (évaluation sans effet, combinaison
de réponse sans ticket, marque d'observation dans la grammaire de `policy.rule`,
formes réservées). Aucun vecteur existant de `spec/vecteurs/ct-2` ni de
`spec/vecteurs/ct-3` ne change ; les cas nouveaux sont dans
`spec/vecteurs/ct-8/observation/` (A.8).

## 13. Paquet réviseur

Le paquet réviseur est ce que l'exploitant du client remet à un réviseur
externe (organe de révision, auditeur, autorité) qui veut vérifier des
dossiers de preuve sans accès aux systèmes du client : une seule archive, qui
porte les dossiers demandés et de quoi les vérifier hors ligne, et un
manifeste qui la décrit fichier par fichier. Le réviseur la vérifie en une
commande. La section fixe la parité mesurable (13.1), le contenu et la
disposition (13.2), le manifeste (13.3), l'archive (13.4), la construction
(13.5), le vérificateur joint (13.6), la vérification (13.7 à 13.9), ce que
le paquet prouve et ne prouve pas (13.10), les instructions remises au
réviseur (13.11) et la remise (13.12). Elle ne change ni le dossier de CT-1
§11, ni le vérificateur de CT-6, ni le fichier d'ancres de CT-6 §12 : le
paquet les transporte.

Lecture : un réviseur qui ne lit qu'une partie lit 13.7, 13.10 et 13.11.

### 13.1 Exigences de parité, mesurables

**EX-13.1** La parité sur le paquet réviseur s'écrit en exigences que CT-9
mesure, sans référence à un produit :

1. Une seule commande vérifie tout le paquet, intégrité puis chaque dossier
   selon CT-6, et rend un code de retour et un résumé lisible (13.7) ; mesure :
   l'épreuve (b) de la section 14 et les 17 cas de la famille `paquets` (annexe
   A.10), dont le code de retour est exigé.
2. La vérification ne demande ni réseau, ni compte, ni autre installation que
   Node.js 22 ou ultérieur (éprouvé avec v22.22.0 sous Linux ; les versions
   ultérieures et les autres systèmes ne sont pas vérifiés, section 15) : le
   paquet complet porte le
   vérificateur et sa seule bibliothèque (13.6) ; mesure : la CI exécute la
   copie jointe d'un paquet complet, extrait hors du dépôt, dans un espace de
   noms réseau vide, et exige le code 0 (EX-A.29). Exécution du 2026-10-27 sur
   le prototype : code 0 (B.5).
3. L'archive est déterministe : deux constructions sur les mêmes entrées donnent
   les mêmes octets, et GNU tar, avec la recette d'EX-13.15, reproduit la même
   archive octet pour octet ; mesure : CI et confrontation (A.14, A.15).
4. Une empreinte attendue qui ne correspond pas, une altération d'octet, un
   fichier manquant ou en trop, un manifeste altéré, un nom absolu ou qui sort
   de l'archive, un lien, un doublon et une métadonnée non fixée sont détectés
   avant qu'un seul fichier soit écrit, et rendent le code 4 ; mesure : onze cas
   de la famille `paquets`.
5. Le résumé dit, pour le paquet, s'il est intact, et pour chaque dossier, le
   verdict et l'énoncé de CT-6 ; il dit d'où viennent les ancres employées et ne
   présente jamais comme prouvés ni le périmètre ni des ancres prises dans le
   paquet (13.10) ; mesure : test des rapports des vecteurs (EX-A.20).
6. Les instructions sont remises en français et en anglais, de même contenu
   (13.11) ; mesure : test de structure (mêmes titres, mêmes commandes, même
   table des codes, EX-A.20).
7. Le temps d'un réviseur, de la réception du paquet au résultat, est une cible
   de conception : moins de 30 minutes la première fois, lecture des
   instructions comprise ; à mesurer (CT-9, porte 2).

### 13.2 Contenu et disposition

```text
paquet-reviseur/
  MANIFESTE.json            manifeste (13.3) ; ne se liste pas lui-même
  LISEZMOI.md               instructions en français (13.11)
  README.md                 instructions en anglais (13.11)
  dossiers/<nom>/           un répertoire par dossier : dossier.json et ses parties présentes
  ancres/<nom>              fichier(s) d'ancres remis par le réviseur (CT-6 §12)
  entetes/<nom>             fichier(s) d'en-têtes Bitcoin (CT-6 §10.3, CT-5 EX-6.8)
  attestation/              facultatif : attestation-signee.json, jeu-approbateurs.json (CT-7 §7)
  pieces/                   facultatif : pièces publiées pour préparer les ancres (CT-5 §10.2, CT-4 §4.8)
  verificateur/             paquet complet seulement : vérificateur de référence et outil (13.6)
```

| Emplacement | `role` | Présence | Contenu | Source |
|---|---|---|---|---|
| `MANIFESTE.json` | — | toujours | manifeste `paquet-reviseur-v0` | outil de construction |
| `LISEZMOI.md`, `README.md` | `instructions` | toujours | textes de 13.11, octet pour octet | outil de construction |
| `dossiers/<nom>/` | `dossier` | au moins un dossier | `dossier.json` et le fichier de chaque partie déclarée présente | exportateur (CT-1 §11, CT-5 §10.1) |
| `ancres/<nom>` | `ancres` | si le réviseur a remis son fichier | fichier d'ancres de CT-6 §12 | réviseur |
| `entetes/<nom>` | `entetes` | si un dossier porte une preuve OpenTimestamps | `entetes-bitcoin.json` de la période | composant d'ancrage (CT-5 EX-6.8) |
| `attestation/attestation-signee.json`, `attestation/jeu-approbateurs.json` | `attestation` | au choix du client | attestation signée et jeu déclaré | administrateur du client (CT-7 §7.3, EX-7.13) |
| `pieces/<nom>` | `pieces` | facultatif | pièces publiées, sans secret | exploitant (CT-5 §10.2, CT-4 §4.8) |
| `verificateur/…` | `verificateur` | paquet complet | fichiers d'EX-13.20 | dépôt public, version publiée |

**EX-13.2** Toutes les entrées de l'archive sont sous un seul répertoire
racine, `paquet-reviseur/`, à l'emplacement que la table donne ; un fichier
ailleurs fait échouer PR-9. Une extraction ne répand donc rien hors de ce
répertoire.

**EX-13.3** `dossiers/<nom>/` porte un dossier tel que l'exportateur l'a
produit, `<nom>` étant le nom de son répertoire : `dossier.json` et le
fichier de chaque partie que l'index déclare présente, octet pour octet, et
rien d'autre (aucun `attendu.json`, aucune note). Un dossier n'est jamais
modifié pour entrer dans un paquet : un réexport produit un nouveau dossier
(CT-5 EX-10.5). Deux dossiers d'un paquet ont des noms distincts.

**EX-13.4** `ancres/` ne contient que des fichiers d'ancres que le réviseur
a remis à l'exploitant, copiés octet pour octet. L'exploitant NE DOIT PAS
écrire, compléter ni « corriger » un fichier d'ancres, ni en placer un que le
réviseur n'a pas remis : rien de l'exportateur n'est une ancre (CT-6
EX-12.1). Sans fichier remis, `anchors` vaut `null` pour chaque dossier, et
le réviseur donne le sien par `--ancres` (AV-PR-4 sinon). Dans les vecteurs,
le fichier d'ancres de test de CT-6 tient le rôle du fichier du réviseur.

**EX-13.5** Pour chaque dossier dont `preuve.ots` porte une attestation
Bitcoin, le fichier `entetes-bitcoin.json` de sa période (CT-5 EX-6.8,
EX-6.10) est joint sous `entetes/` et désigné par `bitcoin_headers`. Deux
fichiers de même nom et de contenus différents sont refusés à la
construction : l'exploitant les nomme par période
(`periode-<period_start>.json`). Le fichier reste déclaratif : il n'est cru
qu'au travers de O-5 et du point de contrôle du réviseur (CT-6 EX-10.4).

**EX-13.6** Quand le client le décide (CT-7 EX-7.14), le paquet porte
l'attestation de périmètre signée en vigueur pour les événements des
dossiers et le jeu d'approbateurs déclaré auquel ses signataires sont
comparés, sous les deux noms fixes de la table ; elle DEVRAIT être celle que
porte la partie `attestation-perimetre.json` des dossiers qui en ont une.
L'outil lui applique AT-1 à AT-4 (PR-12) sans effet sur le code de retour.

**EX-13.7** `pieces/` ne porte que des pièces publiées et sans secret qui
servent au réviseur à préparer et recouper ses ancres : fiches de
prestataire (CT-5 EX-10.6), captures de révocation, séries des points et
`acquisitions.ndjson` (CT-5 §10.2), manifeste d'instance et jeux de
validateurs (CT-4 §4.8, §9.7). Aucune ne contient de clé `auth`, `secret`,
`price`, `account` ni `password` (règle d'AN-54 de CT-5). L'outil de
vérification ne les lit pas ; elles ne sont pas des ancres.

**EX-13.8** Un paquet remis à un réviseur externe DOIT être complet (porter
`verificateur/`, 13.6), sauf si le réviseur demande par écrit un paquet
allégé parce qu'il détient déjà l'outil. Les vecteurs sont des paquets
allégés (EX-A.12).

**EX-13.9** `LISEZMOI.md` et `README.md` sont les textes de 13.11, octet
pour octet.

**EX-13.10** Le paquet ne contient que les dossiers que le réviseur a
demandés, et rien d'autre du journal : ni segment, ni pièce de contenu. Les
pièces fournies à part de CT-6 EX-4.6 (contenus dont les dossiers ne portent
que l'empreinte) ne sont pas dans un paquet de version 0 : elles portent des
données du client, et leur remise relève du client, hors du paquet.
Limites, choix de cette spécification : 1 000 dossiers, 10 000 fichiers,
64 Mio par fichier (la plus grande limite d'une partie de CT-6, EX-4.13),
512 Mio par archive.

### 13.3 Manifeste

Schéma : `spec/schemas/paquet-reviseur-v0.schema.json` (JSON Schema draft
2020-12, `$id`
`https://noortrace.example/schemas/v0/paquet-reviseur.schema.json`). Toutes
les clés sont présentes.

| Clé | Contenu |
|---|---|
| `format`, `version` | `noortrace/paquet-reviseur`, `0` |
| `label` | libellé du paquet, 1 à 256 caractères ; il ne nomme pas une personne |
| `created_at` | instant UTC à la seconde, millisecondes nulles (`AAAA-MM-JJTHH:MM:SS.000Z`) ; c'est la date de toutes les entrées de l'archive |
| `prepared_by` | fonction ou service qui a construit le paquet, 1 à 256 caractères ; jamais un nom de personne |
| `dossiers[]` | dans l'ordre de vérification : `path` (`dossiers/<nom>`), `anchors` (chemin sous `ancres/` ou `null`), `bitcoin_headers` (chemin sous `entetes/` ou `null`) |
| `attestation` | `null`, ou `{signed: "attestation/attestation-signee.json", approver_set: "attestation/jeu-approbateurs.json"}` |
| `verifier` | `null` (paquet allégé), ou `{tool, dossier_verifier, version, runtime}` (13.6) |
| `instructions` | `{fr: "LISEZMOI.md", en: "README.md"}` |
| `files[]` | chaque fichier de l'archive sauf `MANIFESTE.json` : `path` (relatif à `paquet-reviseur/`), `size` (octets), `sha256` (`0x` et 64 chiffres hexadécimaux minuscules), `role` |

**EX-13.11** `files` liste chaque fichier de l'archive sauf
`MANIFESTE.json`, une fois, par ordre strictement croissant des octets de
`path` ; `role` est celui de l'emplacement (table de 13.2) ; `sha256` est le
SHA-256 des octets du fichier. Un chemin est fait de 1 à 16 composants de
caractères `[A-Za-z0-9._@+-]`, qui ne commencent pas par un point, séparés
par `/`, et tient en 239 octets. Les chemins de `dossiers` sont distincts ;
`anchors` et `bitcoin_headers` désignent un fichier de rôle `ancres` ou
`entetes`, ou valent `null`.

**EX-13.12** L'outil de construction écrit le manifeste en UTF-8 par
`JSON.stringify(manifeste, null, 2)` suivi d'un saut de ligne, les membres
dans l'ordre de la table. L'outil de vérification n'exige pas cette forme :
il lit le manifeste en JSON strict (UTF-8, aucun membre en double), le
valide contre son schéma et applique PR-7 à PR-9.

Manifeste du paquet `valide.tar` des vecteurs (annexe A.10) : trois dossiers
de `spec/vecteurs/ct-6/dossiers`, le fichier d'ancres de test
`ancres-test.json` dans le rôle du fichier du réviseur, deux fichiers
d'en-têtes, l'attestation d'exemple de CT-7 et le manifeste d'instance du
réseau de développement de CT-4 ; paquet allégé (49 fichiers,
241 340 octets ; manifeste de 11 274 octets, SHA-256
`0x5667fad9e2d6f8da8e3960304a8bb227638834f3e9319da20241f1f86a353fb1`) :

<!-- schema: paquet-reviseur -->
```json
{
  "format": "noortrace/paquet-reviseur",
  "version": 0,
  "label": "Paquet de démonstration des vecteurs CT-8 : journal sinistres, période du 2026-11-05 de 09:00 à 10:00",
  "created_at": "2026-10-27T00:00:00.000Z",
  "prepared_by": "exploitant de l'instance de démonstration (vecteurs CT-8)",
  "dossiers": [
    {
      "path": "dossiers/valide-seq-7-complet",
      "anchors": "ancres/ancres-test.json",
      "bitcoin_headers": "entetes/chaine.json"
    },
    {
      "path": "dossiers/valide-seq-7-complet-attestation",
      "anchors": "ancres/ancres-test.json",
      "bitcoin_headers": "entetes/chaine.json"
    },
    {
      "path": "dossiers/valide-point-de-controle-complet",
      "anchors": "ancres/ancres-test.json",
      "bitcoin_headers": "entetes/chaine-points.json"
    }
  ],
  "attestation": {
    "signed": "attestation/attestation-signee.json",
    "approver_set": "attestation/jeu-approbateurs.json"
  },
  "verifier": null,
  "instructions": {
    "fr": "LISEZMOI.md",
    "en": "README.md"
  },
  "files": [
    {
      "path": "LISEZMOI.md",
      "size": 8340,
      "sha256": "0x858905b068fdf7cb3db303e3d614e8ac8712e2833f8c13522325c22a44aeac14",
      "role": "instructions"
    },
    {
      "path": "README.md",
      "size": 7729,
      "sha256": "0x4874a8613621cd372cfe8fef9bacb391d4772d4ee1bd9bfe74a421b8f2743d34",
      "role": "instructions"
    },
    {
      "path": "ancres/ancres-test.json",
      "size": 5924,
      "sha256": "0x2be4619fb82ce615244c78a054e71930322bc0bed894521dca5f8d6a3b6dc617",
      "role": "ancres"
    },
    {
      "path": "attestation/attestation-signee.json",
      "size": 4802,
      "sha256": "0x6a11cc55644a6822e466646d95227a612a12a7d810e670e4b354c7cfcf8fb636",
      "role": "attestation"
    },
    {
      "path": "attestation/jeu-approbateurs.json",
      "size": 281,
      "sha256": "0x9749dcfc84bc0b9b7bc5d47511d49d4491eb318f23b4aa06a7d2f132c15416d9",
      "role": "attestation"
    },
    {
      "path": "dossiers/valide-point-de-controle-complet/approbations.json",
      "size": 3345,
      "sha256": "0xbc5bed6d2eb45e074a6b22c3f4b06a779d0cfd65d3c090a470d421fa0e434dd4",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-point-de-controle-complet/certificat-commit.json",
      "size": 40069,
      "sha256": "0x2494c254a8878f6b7d83f776afe82d570eeb0489023cabb157a6783ceeec4a24",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-point-de-controle-complet/chemin.json",
      "size": 533,
      "sha256": "0x7430538558f0313a6969788883228d207fe483ae39777d0f482dd8b3cc529d70",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-point-de-controle-complet/cles.json",
      "size": 857,
      "sha256": "0xbea7e6ca61f66d94eef9a8121d90ff635333770b7f74e608a78e2e28fc0976cc",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-point-de-controle-complet/dossier.json",
      "size": 3148,
      "sha256": "0x4957bee4f661892fbcd0ac162900a982bda518a0ed9d46a751e627d6ab2663f9",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-point-de-controle-complet/evenement.json",
      "size": 2938,
      "sha256": "0x7849b34a2e1655c1522286af6b36fe1e402426ec6ad72b271c94119d88c91675",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-point-de-controle-complet/jeton-rfc3161.der",
      "size": 2103,
      "sha256": "0xdbfb99a9cd7a6b022614b62957cd4f9e17a168a43efa7dee729503937af58d13",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-point-de-controle-complet/manifeste.json",
      "size": 629,
      "sha256": "0xae8bd542d4631dcd6d6ee5ec3a270e0fda5a277041b2223881e37be15ca7f621",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-point-de-controle-complet/manifeste.sig",
      "size": 285,
      "sha256": "0x0cc7de26c51a06dd5393363c2f02a30c06b6ffa6c366cc27d586c2ab5ffebc90",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-point-de-controle-complet/points-de-controle.json",
      "size": 5099,
      "sha256": "0x817e9756dcd57635a27a68fc36cf9602a7d7373e719571b6136e5f8eff25ea4f",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-point-de-controle-complet/preuve.ots",
      "size": 316,
      "sha256": "0xf70b77c15a5226d537f34d7288a5b296cad3c0dbd5b0d2fc79d679e5dc3cff1f",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-point-de-controle-complet/registre.json",
      "size": 8708,
      "sha256": "0x738622e1f6a2782eb240a858f993f8e8fa843f5e3acbfa7b0fee6ffdbe024490",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-point-de-controle-complet/validateurs.json",
      "size": 1021,
      "sha256": "0xfaa68fb0afa478c832d19333d0f2516cc1691000f9a4b20c9917879fc8d6564d",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-point-de-controle-complet/voisins.json",
      "size": 4718,
      "sha256": "0x1063e5ab45274be78b61c659ab092c11e51c6a78b10a5e773cd0a3965bb6259d",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet-attestation/approbations.json",
      "size": 3345,
      "sha256": "0xbc5bed6d2eb45e074a6b22c3f4b06a779d0cfd65d3c090a470d421fa0e434dd4",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet-attestation/attestation-perimetre.json",
      "size": 5443,
      "sha256": "0x08c7b70e7b757bebc9137210446eabb60032c38f8d7bc2434da2df97cb423072",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet-attestation/certificat-commit.json",
      "size": 31434,
      "sha256": "0x61416b4822a4f94f5e35851baea2e0d6f2ac854978cb6b1946440acf2fea4b90",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet-attestation/chemin.json",
      "size": 533,
      "sha256": "0x7430538558f0313a6969788883228d207fe483ae39777d0f482dd8b3cc529d70",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet-attestation/cles.json",
      "size": 857,
      "sha256": "0xbea7e6ca61f66d94eef9a8121d90ff635333770b7f74e608a78e2e28fc0976cc",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet-attestation/dossier.json",
      "size": 3343,
      "sha256": "0xab143ce2aa2a4ac5eda90c9a5d84b47350f9e75a7f256d3a197f600a206dd7ca",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet-attestation/evenement.json",
      "size": 2938,
      "sha256": "0x7849b34a2e1655c1522286af6b36fe1e402426ec6ad72b271c94119d88c91675",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet-attestation/jeton-rfc3161.der",
      "size": 2103,
      "sha256": "0xdbfb99a9cd7a6b022614b62957cd4f9e17a168a43efa7dee729503937af58d13",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet-attestation/manifeste.json",
      "size": 629,
      "sha256": "0xae8bd542d4631dcd6d6ee5ec3a270e0fda5a277041b2223881e37be15ca7f621",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet-attestation/manifeste.sig",
      "size": 285,
      "sha256": "0x0cc7de26c51a06dd5393363c2f02a30c06b6ffa6c366cc27d586c2ab5ffebc90",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet-attestation/preuve.ots",
      "size": 316,
      "sha256": "0xf70b77c15a5226d537f34d7288a5b296cad3c0dbd5b0d2fc79d679e5dc3cff1f",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet-attestation/registre.json",
      "size": 7198,
      "sha256": "0x337cc0468f68f3acb8b19da3cad0b302ca967cfaa8542bd7e3f0e2a2c59d17fd",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet-attestation/validateurs.json",
      "size": 1021,
      "sha256": "0xfaa68fb0afa478c832d19333d0f2516cc1691000f9a4b20c9917879fc8d6564d",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet-attestation/voisins.json",
      "size": 4718,
      "sha256": "0x1063e5ab45274be78b61c659ab092c11e51c6a78b10a5e773cd0a3965bb6259d",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet/approbations.json",
      "size": 3345,
      "sha256": "0xbc5bed6d2eb45e074a6b22c3f4b06a779d0cfd65d3c090a470d421fa0e434dd4",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet/certificat-commit.json",
      "size": 31434,
      "sha256": "0x61416b4822a4f94f5e35851baea2e0d6f2ac854978cb6b1946440acf2fea4b90",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet/chemin.json",
      "size": 533,
      "sha256": "0x7430538558f0313a6969788883228d207fe483ae39777d0f482dd8b3cc529d70",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet/cles.json",
      "size": 857,
      "sha256": "0xbea7e6ca61f66d94eef9a8121d90ff635333770b7f74e608a78e2e28fc0976cc",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet/dossier.json",
      "size": 2918,
      "sha256": "0x314e835f7f808e4dfe79be546284d666022093f14c7d19633bf7dfecd0d9b7f7",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet/evenement.json",
      "size": 2938,
      "sha256": "0x7849b34a2e1655c1522286af6b36fe1e402426ec6ad72b271c94119d88c91675",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet/jeton-rfc3161.der",
      "size": 2103,
      "sha256": "0xdbfb99a9cd7a6b022614b62957cd4f9e17a168a43efa7dee729503937af58d13",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet/manifeste.json",
      "size": 629,
      "sha256": "0xae8bd542d4631dcd6d6ee5ec3a270e0fda5a277041b2223881e37be15ca7f621",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet/manifeste.sig",
      "size": 285,
      "sha256": "0x0cc7de26c51a06dd5393363c2f02a30c06b6ffa6c366cc27d586c2ab5ffebc90",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet/preuve.ots",
      "size": 316,
      "sha256": "0xf70b77c15a5226d537f34d7288a5b296cad3c0dbd5b0d2fc79d679e5dc3cff1f",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet/registre.json",
      "size": 7198,
      "sha256": "0x337cc0468f68f3acb8b19da3cad0b302ca967cfaa8542bd7e3f0e2a2c59d17fd",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet/validateurs.json",
      "size": 1021,
      "sha256": "0xfaa68fb0afa478c832d19333d0f2516cc1691000f9a4b20c9917879fc8d6564d",
      "role": "dossier"
    },
    {
      "path": "dossiers/valide-seq-7-complet/voisins.json",
      "size": 4718,
      "sha256": "0x1063e5ab45274be78b61c659ab092c11e51c6a78b10a5e773cd0a3965bb6259d",
      "role": "dossier"
    },
    {
      "path": "entetes/chaine-points.json",
      "size": 5661,
      "sha256": "0x3fc7c146aa312a74f1d46cafc843ae24672e0b4ebde0aac82234bc7d08ab2ada",
      "role": "entetes"
    },
    {
      "path": "entetes/chaine.json",
      "size": 5476,
      "sha256": "0x4c2b5496dc33b2395ee6e768595f23b56d06f9e725e7a56b789b19985430b9ba",
      "role": "entetes"
    },
    {
      "path": "pieces/instance-r1.json",
      "size": 6900,
      "sha256": "0xd700ac22b0de63f883a01c8b8cc315a140c2d80468d41a93fbf8247076215fc8",
      "role": "pieces"
    }
  ]
}
```

### 13.4 Archive déterministe

**EX-13.13 (format)** L'archive est au format ustar de POSIX (« ustar
Interchange Format » de pax, IEEE Std 1003.1-2024, R9-F1, R9-F2), non
compressée (`.tar`), sans en-tête étendu pax ni GNU. Motifs : avec des
horodatages entiers, ce format est reproductible sans en-tête pax (R9-F6,
R9-F12), c'est le choix recommandé quand la portabilité compte (R9-F10), et
GNU tar comme `tarfile` de Python le lisent (A.15). Ses limites (nom de 255
octets découpé en préfixe et nom, fichier de moins de 8 Gio, R9-F3, R9-F8)
sont au-delà de celles d'EX-13.10.

**EX-13.14 (entrées)** L'archive ne contient que des fichiers ordinaires
(`typeflag` `0`), sans entrée de répertoire, de lien ni de périphérique,
triés par ordre strictement croissant des octets de leur nom complet (ordre
de la locale C, R9-F10). Chaque en-tête de 512 octets a ces champs :

| Champ | Octets | Valeur |
|---|---|---|
| `name` | 0 à 99 | nom complet, ou sa partie après le préfixe ; octets puis NUL jusqu'à la fin du champ |
| `mode` | 100 à 107 | `0000644` puis NUL |
| `uid`, `gid` | 108 à 115, 116 à 123 | `0000000` puis NUL |
| `size` | 124 à 135 | taille en 11 chiffres octaux puis NUL |
| `mtime` | 136 à 147 | `created_at` en secondes depuis 1970, 11 chiffres octaux puis NUL |
| `chksum` | 148 à 155 | 6 chiffres octaux, NUL, espace : somme des 512 octets de l'en-tête, ce champ compté comme huit espaces |
| `typeflag` | 156 | `0` |
| `linkname` | 157 à 256 | NUL |
| `magic`, `version` | 257 à 262, 263 à 264 | `ustar` puis NUL ; `00` |
| `uname`, `gname` | 265 à 296, 297 à 328 | NUL |
| `devmajor`, `devminor` | 329 à 336, 337 à 344 | NUL |
| `prefix` | 345 à 499 | vide, ou préfixe du découpage |
| bourrage | 500 à 511 | NUL |

Découpage : un nom complet de 100 octets au plus va dans `name` et `prefix`
reste vide ; sinon `prefix` est le plus long début du nom qui s'arrête avant
un `/` et tient en 155 octets, et le reste, qui doit être non vide et tenir
en 100 octets, va dans `name` (sinon le nom n'est pas représentable) : c'est
la règle de GNU tar, qui coupe au dernier `/` des 156 premiers octets
(fonction `split_long_name` de `src/create.c` ; vérifié le 2026-10-27 avec
GNU tar 1.35 sur un nom de 103 octets, test « EX-13.14 » de
`test/paquet-reviseur.test.js`). Chaque fichier est suivi de ses octets, puis de
zéros jusqu'au multiple de 512 suivant. L'archive finit par deux blocs nuls,
puis par des zéros jusqu'au plus petit multiple de 10 240 octets (facteur de
blocage 20 de GNU tar, `-b20` de `tar --show-defaults`, R9-F9) : sa longueur
est `L = 10240 × ⌈(Σᵢ (512 + 512 × ⌈tᵢ ÷ 512⌉) + 1024) ÷ 10240⌉`, `tᵢ`
étant la taille du fichier `i`.

**EX-13.15 (recette GNU tar)** Depuis un paquet extrait, cette commande
reproduit l'archive octet pour octet ; la confrontation l'exige (A.15) :

```bash
cd <répertoire d'extraction>
find paquet-reviseur -type f | LC_ALL=C sort > liste.txt
LC_ALL=C tar --format=ustar --no-recursion --owner=0 --group=0 --numeric-owner \
    --mode=0644 --mtime=@<created_at en secondes> -cf paquet.tar -T liste.txt
```

Les options sont celles du manuel de GNU tar pour les archives
reproductibles (R9-F5, R9-F7), à deux différences près, qui viennent de ce
que l'archive ne porte que des fichiers : la liste triée remplace
`--sort=name` et `--no-recursion` empêche les entrées de répertoire ; le
mode est forcé à `0644` au lieu de `go+u,go-w`. Mesure du 2026-11-01 (GNU tar
1.35, après la révision des instructions de 13.11) : `valide.tar` des
vecteurs et le paquet complet de B.5 sont reproduits à l'identique (`cmp` :
aucun écart).

**EX-13.16 (compression)** Un paquet de version 0 n'est pas compressé : la
sortie d'un compresseur dépend de son implémentation, et la
reproductibilité n'a été établie que pour le `.tar`. Un paquet compressé
pour le transport est décompressé avant la vérification, et l'empreinte
attendue est celle du `.tar`. L'outil de vérification refuse une archive
compressée par PR-1 (longueur qui n'est pas un multiple de 512, le cas
presque toujours) ou par PR-3, et le dit dans les deux cas (les octets
`1f 8b` de gzip en tête).

### 13.5 Construction

```text
node scripts/paquet-reviseur/construire.mjs --description <description.json> --sortie <paquet.tar>
npm run paquet:construire -- --description <description.json> --sortie <paquet.tar>
```

**EX-13.17** La description est un document JSON conforme à
`paquet-reviseur-v0#/$defs/description_source` ; ses chemins relatifs se
résolvent contre le répertoire du fichier de description. Elle donne le
libellé, l'instant `created_at`, la fonction qui prépare le paquet, les
dossiers (répertoire, fichier d'ancres ou `null`, fichier d'en-têtes ou
`null`), l'attestation ou `null`, les pièces, et `include_verifier`.

**EX-13.18** L'outil, dans cet ordre : (1) valide la description, et refuse
un `created_at` qui n'est pas une date réelle (le 30 février, un mois 13 :
la date relue doit redonner la même chaîne) ou dont les secondes depuis 1970
sortent de 0 à 8¹¹ − 1, seules valeurs que le champ `mtime` représente
(EX-13.14) ; (2) pour
chaque dossier, lit `dossier.json` en JSON strict, le copie, puis copie le
fichier de chaque partie déclarée présente, refuse une partie absente ou un
nom de fichier qui n'est pas un simple nom ; (3) copie chaque fichier
d'ancres et d'en-têtes sous son nom de base, et refuse deux sources
différentes pour un même chemin ; (4) copie l'attestation sous ses noms
fixes, (5) les pièces sous leur nom de base, (6) les instructions de 13.11,
(7) le vérificateur si `include_verifier` (13.6) ; refuse deux chemins égaux
à la casse près (PR-5) et tout nom que PR-5 refuserait, avant d'écrire quoi
que ce soit ; (8) écrit le manifeste (13.3) et (9) l'archive (13.4), de date
`created_at` ; (10) écrit la sortie
sans jamais remplacer un fichier existant et imprime la taille et le SHA-256
de l'archive et du manifeste. Code 0 si l'archive est écrite ; code 2 pour
tout refus, avec un message, et rien n'est écrit. L'outil n'ouvre aucune
connexion réseau.

**EX-13.19** L'outil de construction ne juge pas les dossiers : il ne lance
pas CT-6. L'exploitant DEVRAIT vérifier le paquet par l'outil de 13.7 avant
de le remettre. `created_at` est déclaratif : c'est l'instant de
construction choisi par l'exploitant, tronqué à la seconde ; la même
description reconstruit les mêmes octets.

Description du paquet `valide.tar` des vecteurs, fichier
`spec/vecteurs/ct-8/paquets/description.json`, chemins relatifs à son
répertoire :

<!-- schema: paquet-reviseur/description_source -->
```json
{
  "version": 0,
  "label": "Paquet de démonstration des vecteurs CT-8 : journal sinistres, période du 2026-11-05 de 09:00 à 10:00",
  "created_at": "2026-10-27T00:00:00.000Z",
  "prepared_by": "exploitant de l'instance de démonstration (vecteurs CT-8)",
  "dossiers": [
    {
      "source": "../../ct-6/dossiers/valide-seq-7-complet",
      "anchors": "../../ct-6/ancres/ancres-test.json",
      "bitcoin_headers": "../../ct-6/ots/entetes/chaine.json"
    },
    {
      "source": "../../ct-6/dossiers/valide-seq-7-complet-attestation",
      "anchors": "../../ct-6/ancres/ancres-test.json",
      "bitcoin_headers": "../../ct-6/ots/entetes/chaine.json"
    },
    {
      "source": "../../ct-6/dossiers/valide-point-de-controle-complet",
      "anchors": "../../ct-6/ancres/ancres-test.json",
      "bitcoin_headers": "../../ct-6/ots/entetes/chaine-points.json"
    }
  ],
  "attestation": {
    "signed": "../../ct-7/attestations/exemple/attestation-signee.json",
    "approver_set": "../../ct-7/attestations/exemple/jeu.json"
  },
  "pieces": [
    "../../ct-4/manifestes/valides/developpement/instance-r1.json"
  ],
  "include_verifier": false
}
```

Construction du paquet complet de B.5 (même description, `include_verifier`
à `true`, chemins absolus). Exemple daté du 2026-11-01 : la taille et les
SHA-256 dépendent des octets du code joint et changent à chaque modification
d'un fichier de `verificateur/` ; ce sont les valeurs de ce dépôt à cette
date, et la commande les recalcule :

```text
Paquet        : sorties/complet.tar, 2314240 octets, SHA-256 0x7c2ef76e2f1ea147fd9483ce61a394fe285581c3d83ad226e15aae91c5c38e67
Manifeste     : 76 fichiers, 3 dossier(s), SHA-256 0x5d24c0cdccaa104c293184ff8d162bb2a6a54cef067bbf54d341571709be3705
Remise        : transmettez le SHA-256 du paquet au réviseur par un autre canal que l'archive (CT-8 EX-13.37)
```

### 13.6 Vérificateur joint

**EX-13.20** Un paquet complet porte sous `verificateur/` l'arbre suivant,
copié du dépôt public à une version publiée, chemins relatifs à la racine du
dépôt conservés :

| Fichier | Rôle |
|---|---|
| `LICENSE`, `NOTICE` | licence Apache-2.0 et avis du projet, que la diffusion reproduit (Apache-2.0 §4(d), comme CT-6 EX-14.10) |
| `scripts/paquet-reviseur/verifier.mjs`, `scripts/lib/paquet.mjs` | outil de vérification du paquet (13.7) et sa bibliothèque |
| `scripts/verify/dossier.mjs` | vérificateur de référence de CT-6 (CT-6 EX-8.1) |
| `scripts/lib/certificat-commit.mjs`, `console.mjs`, `horodatage.mjs`, `journal.mjs`, `ots.mjs`, `registre.mjs`, `securite.mjs`, `verificateur.mjs` | bibliothèques qu'importent les deux outils, et elles seules |
| `spec/schemas/` : `ancres-confiance-v0`, `attestation-perimetre-v0`, `dossier-v0`, `entetes-bitcoin-v0`, `evenement-v0`, `manifeste-v0`, `paquet-reviseur-v0`, `point-de-controle-v0`, `rapport-verification-v0`, `registre-v0`, `validateurs-v0` (`.schema.json`) | schémas que les deux outils lisent |
| `node_modules/ethers/dist/ethers.js`, `node_modules/ethers/LICENSE.md`, `node_modules/ethers/package.json` | la seule bibliothèque tierce (EX-13.21) |

Les tailles et les SHA-256 de ces fichiers sont dans le manifeste de chaque
paquet complet ; `node scripts/paquet-reviseur/verifier.mjs --version` les
imprime pour l'outil exécuté. Paquet complet de B.5, exemple daté du
2026-10-27 (valeurs qui changent avec le code) : 27 fichiers du vérificateur,
1 989 648 octets.

**EX-13.21** `ethers` est la seule dépendance des deux outils (importée par
`journal.mjs`, `securite.mjs`, `registre.mjs` et `certificat-commit.mjs`).
Le paquet complet en porte le fichier `dist/ethers.js` de la distribution
npm de la version que fixe `package-lock.json` (6.17.0 le 2026-10-27 :
1 023 273 octets, SHA-256
`0x98ef38ca12d3a7829eb2d8398e033434fe521b7a1873427e77f2eb5e8513f761`),
module ECMAScript d'un seul fichier qui n'importe rien, sa licence MIT
(`LICENSE.md`) et un `package.json` engendré par l'outil de construction,
qui fait désigner ce fichier par le nom `ethers`, au texte exact :

```json
{
  "name": "ethers",
  "version": "6.17.0",
  "type": "module",
  "main": "./dist/ethers.js",
  "exports": {
    ".": "./dist/ethers.js"
  },
  "license": "MIT",
  "description": "Copie de dist/ethers.js de la distribution npm d'ethers, jointe au vérificateur de référence (CT-8 §13)"
}
```

**EX-13.22** L'outil de vérification n'exécute jamais de code du paquet : il
vérifie chaque dossier avec son propre `scripts/verify/dossier.mjs`, celui de la
racine dont il est lui-même tiré, et PR-11 compare le vérificateur joint à ce
que l'outil exécuté joindrait. Quand l'outil exécuté est lui-même la copie
jointe d'un paquet extrait, cette comparaison serait celle de la copie à
elle-même : PR-11 est alors `non_execute`, raison `auto_comparaison`. Un
réviseur qui emploie la copie jointe exécute du code remis par l'exploitant : il
DEVRAIT d'abord contrôler les fichiers extraits par `sha256sum --strict -c`
contre la liste `SHA256SUMS` signée publiée avec la note de version, hors du
serveur de téléchargement (EX-3.14, comme CT-6 EX-14.9) ; ni le manifeste du
paquet ni la sortie de `--version` de la copie, produits par l'exploitant ou par
le code examiné, ne la remplacent ; sinon il croit l'exploitant pour l'outil
(CT-7 MN-66, RA-57). Le dépôt public est celui dont la note de version donne
l'adresse et le commit (EX-3.14). Tant qu'aucune version de l'outil n'est
publiée, cette liste n'existe pas, et le réviseur prend l'outil dans le dépôt
public, à un commit que l'exploitant lui nomme avec l'empreinte du paquet, par
le même canal (EX-13.37, pas 3) : il croit alors l'exploitant pour l'outil, et
la précaution (a) d'EX-13.38 n'est pas possible.

Ces deux règles ne se contredisent pas : l'outil, quel qu'il soit, ne charge
rien depuis l'archive qu'il vérifie ; c'est le réviseur qui décide
d'exécuter la copie jointe, et seulement après l'avoir extraite à part et
contrôlée par la liste `SHA256SUMS` publiée.

**EX-13.23** Quand le binaire `noortrace-verifier` de CT-6 §14 sera livré
(phase 2), un paquet PEUT le porter en plus ; le manifeste de version 0 ne
nomme que l'implémentation de référence (`verifier.version`), et un format
ultérieur nommera le binaire.

### 13.7 Vérification en une commande

```text
node <outil>/scripts/paquet-reviseur/verifier.mjs <paquet.tar> [--empreinte <sha256>]
     [--ancres <fichier>] [--exiger <contrôles>] [--langue fr|en] [--json]
     [--conserver <répertoire à créer>]
node <outil>/scripts/paquet-reviseur/verifier.mjs --version | --aide
npm run paquet:verifier -- <paquet.tar> [mêmes options]
```

`<outil>` est la racine du dépôt public, ou le répertoire `verificateur/`
d'un paquet complet extrait (EX-13.22). La commande recommandée est celle du
pas 2 des instructions au réviseur (13.11), avec `--empreinte` et `--ancres`
(EX-13.38) ; les exemples sans option de cette section montrent ce que l'outil
signale quand ces précautions manquent.

| Option | Valeur | Effet | Défaut |
|---|---|---|---|
| `<paquet.tar>` | fichier | l'archive ; exactement une | obligatoire |
| `--empreinte` | 64 chiffres hexadécimaux, avec ou sans `0x` | SHA-256 attendu de l'archive (PR-2) | aucune : PR-2 non exécutée |
| `--ancres` | fichier | fichier d'ancres du réviseur, employé pour tous les dossiers à la place de ceux du paquet | ceux du paquet (AV-PR-3), ou aucun |
| `--exiger` | numéros de 1 à 8 séparés par `,`, ou `tous` | transmis à CT-6 pour chaque dossier (CT-6 §8.2) | aucun |
| `--langue` | `fr` ou `en` | langue du résumé et des textes du rapport | `fr` |
| `--json` | — | rapport JSON sur la sortie standard (EX-13.29) | résumé lisible |
| `--conserver` | répertoire qui n'existe pas | l'outil y extrait le paquet et le garde | répertoire temporaire, effacé |
| `--version` | — | nom, version, environnement, puis SHA-256 de chaque fichier du vérificateur que l'outil joindrait (EX-13.20) | — |
| `--aide` | — | l'aide | — |

**EX-13.24** Une option inconnue, répétée ou sans sa valeur, une valeur hors
de son domaine, aucune ou plusieurs archives, un répertoire `--conserver`
qui existe déjà ou un fichier `--ancres` illisible rendent le code 2 (type
`usage`), avant toute lecture de l'archive ; avec `--json`, le rapport
d'erreur est en JSON. `--version` et `--aide` ne se combinent qu'avec
`--langue`.
`--option=valeur` et `--option valeur` sont équivalents (comme CT-6
EX-8.2).

**EX-13.25** L'outil, dans cet ordre :

1. lit l'archive entière (512 Mio au plus) ; un fichier absent, illisible
   ou trop grand rend le code 2 (type `archive_illisible`) ;
2. exécute PR-1 à PR-9 sur ses octets, sans rien écrire ; la première en
   échec arrête tout : code 4, aucun dossier n'est vérifié ;
3. extrait le paquet (PR-10) dans un répertoire neuf qu'il crée (mode
   `0700`, sous le répertoire temporaire du système, ou celui de
   `--conserver`, qui ne doit pas exister) : chaque répertoire créé un à un,
   chaque fichier ouvert en création exclusive, sans suivre de lien, mode
   `0600`, puis relu et comparé au manifeste ; un échec rend le code 2 (type
   `extraction_impossible`) ;
4. compare le vérificateur joint à lui-même (PR-11) ;
5. vérifie l'attestation jointe (PR-12) ;
6. vérifie chaque dossier, dans l'ordre du manifeste, par son propre
   vérificateur de CT-6 (EX-13.22) avec `--json`, le fichier d'ancres de
   `--ancres` s'il est donné, sinon celui que le manifeste désigne pour le
   dossier, sinon aucun, le fichier d'en-têtes du dossier, et `--exiger` et
   `--langue` s'ils sont donnés ;
7. efface le répertoire d'extraction, sauf avec `--conserver`, y compris
   quand PR-10 a échoué ;
8. écrit le résumé (EX-13.27) ou le rapport JSON (EX-13.29) sur la sortie
   standard, et rend le code d'EX-13.26.

Il n'ouvre aucune connexion réseau et ne lit aucune variable d'environnement
qui change son résultat.

**EX-13.26 (codes de retour)**

| Code | Sens |
|---|---|
| 0 | Paquet intact, tous les dossiers valides (code 0 de CT-6). |
| 1 | Paquet intact, au moins un dossier invalide (code 1 de CT-6). |
| 2 | Entrée inutilisable : usage, archive illisible, extraction impossible, erreur interne ; ou paquet intact dont au moins un dossier rend le code 2 de CT-6 (fichier d'ancres refusé, par exemple) et aucun le code 1. |
| 3 | Paquet intact, aucun dossier invalide ni inutilisable, au moins un dossier incomplet (code 3 de CT-6, `--exiger`). |
| 4 | Paquet non conforme : une vérification de PR-1 à PR-9 a échoué ; aucun dossier n'est vérifié. |

Priorité : 4, puis 1, 2, 3, 0. Le code 4 l'emporte sur tout, car aucun
dossier n'est alors vérifié ; entre dossiers, la priorité est 1, puis 2, 3
et 0. Pour chaque dossier, les codes 0 à 3 gardent le sens de CT-6 §8.3 ; le
code 4 est propre au paquet.

Conduite du réviseur selon le code (lecture de cette table et de CT-6 §8.3,
sans règle nouvelle) :

- **Code 2 de type `usage`** (option, fichier `--ancres` illisible,
  répertoire `--conserver` existant, EX-13.24) : il vient de la commande ;
  le réviseur la corrige et relance.
- **Code 2 sans erreur de l'outil** (`error` nul : un dossier rend le code 2
  de CT-6) : le rapport du dossier nomme l'entrée en cause ; un fichier
  d'ancres refusé met en cause ce fichier, celui du réviseur s'il l'a passé
  par `--ancres`, celui du paquet sinon, non l'intégrité du paquet.
- **Code 4, ou code 2 dû à l'archive** (`archive_illisible` pour une archive
  présente, `extraction_impossible` hors d'une cause locale comme l'espace ou
  les droits) : le paquet est refusé ; le réviseur garde l'archive, son
  SHA-256 et le rapport `--json`, et en demande un nouveau. Après un échec de
  PR-2, une seconde exécution sans `--empreinte` peut localiser l'écart (PR-3
  à PR-9 s'exécutent alors, EX-13.30 ; PR-8 nomme le fichier en cause) et se
  joint au signalement avec son rapport `--json` ; elle ne change pas la
  décision : le paquet reste refusé tant que le réviseur ne dispose pas d'une
  archive dont le SHA-256 égale l'empreinte reçue, relue (EX-13.31).
- **Code 1** : le paquet est bien celui que le manifeste décrit, mais au
  moins un dossier est invalide ; ce dossier ne prouve pas l'événement
  (CT-6 §8.3) : le réviseur conserve le rapport `--json` et le signale à
  l'exploitant. Chaque autre dossier garde le sens de son propre code, sous
  les ancres employées.
- **Code 3** : un contrôle exigé par `--exiger` n'a pas réussi ; le dossier
  n'est pas invalide, il est incomplet (son énoncé prouve moins que
  l'exigence) : le réviseur demande les pièces manquantes ou relance après la
  mise à niveau des preuves.

Les contrôles de CT-6 que les lignes `Dossiers :` et le rapport nomment par leur
numéro sont, sans reprendre ici leurs règles (CT-6 §5.1) : 1, hachage canonique
de l'événement ; 2, continuité de la chaîne avec les voisins ; 3, chemin de
Merkle jusqu'à la racine du manifeste ; 4, jeton RFC 3161 sur `periodHash` ; 5,
preuve OpenTimestamps contre les en-têtes Bitcoin ; 6, signature Ed25519 de
l'enregistreur ; 7, signatures des approbateurs et respect du seuil ; 8,
inclusion de la transaction du registre dans un bloc certifié par un quorum. Les
identifiants des vérifications en échec (`D-`, `E-`, `C-`, `M-`…) sont ceux de
CT-6 (section 8). Cette liste sert à lire la ligne d'un dossier ; elle ne change
pas la décision du réviseur, qui repose sur le code, le verdict et la provenance
des ancres (13.11).

**EX-13.27 (résumé lisible)** Lignes, dans cet ordre, étiquettes complétées par
des espaces jusqu'à quatorze caractères avant les deux-points, comme CT-6
EX-8.6 : le titre ; `Outil` (nom, version, environnement) ; `Archive` (chemin,
taille, SHA-256) ; `Manifeste` (SHA-256, libellé, `created_at`, `prepared_by`),
quand PR-7 a réussi ; `Paquet` (`INTACT` avec le nombre de fichiers, d'octets et
de dossiers, ou `NON CONFORME` avec la première vérification en échec et son
détail) ; `Vérifications non réussies :` puis une ligne par vérification PR- non
réussie (`[statut]`, identifiant, détail, raison) ; `Avertissements :` puis une
ligne par avertissement ; `Empreinte` et `Vérificateur` quand PR-2 et PR-11 ont
réussi (la précaution prise, EX-13.38), placées avant les vérifications non
réussies ; `Attestation` (retenue ou non), si le paquet en porte une ;
`Dossiers :` puis, pour chaque dossier, une ligne (`[VALIDE]`, `[INVALIDE]`,
`[INUTILISABLE]` ou `[INCOMPLET]`, chemin, code, contrôles par statut,
provenance des ancres, vérifications en échec, marque d'observation) et la ligne
`Énoncé` de CT-6 dans la langue choisie ; `Observation` (nombre de dossiers en
mode observation et marques par décision, `summary.observation`) quand au moins
un dossier est en mode observation ; enfin `Résultat` (décompte et code).
Libellés anglais : `Tool`, `Archive`, `Manifest`, `Package`, `Digest`,
`Verifier`, `Checks not passed:`, `Warnings:`, `Attestation`, `Dossiers:`,
`Statement`, `Observation`, `Result`. Pour le code 2 avant toute lecture, une
ligne `Erreur : {message}` sur la sortie d'erreur, comme CT-6 ; avec
`--langue en`, `Error: {message}` et un message en anglais (l'aide, le résumé et
les messages d'erreur sont bilingues). Le résumé n'écrit aucun caractère de
contrôle venu du paquet : tout caractère C0, C1 ou DEL d'un libellé, d'un nom ou
d'un détail est écrit sous une forme visible (`\xNN`, `NN` étant son code en
hexadécimal), et le schéma refuse ces caractères dans `label` et `prepared_by`
(test « corrections du paquet réviseur » de l'annexe A.12).

**EX-13.28 (mode observation)** Pour un dossier dont les contrôles 1 et 6 ont
réussi, le rapport JSON porte `observation_mode` = `true` quand
`code.policy_version` de `evenement.json` finit par `-observation` (CT-2
EX-15.8) ou que `policy.rule` porte une marque d'observation ; si `policy.rule`
finit par la marque de la section 12 (` [observation <x>]`, lue après la
dernière occurrence de ` [observation `), la ligne du dossier ajoute « mode
observation, la politique aurait rendu `<x>` » et le rapport porte
`observation` = `<x>` ; sinon, un dossier en mode observation (échange de
modèle, span, rotation ; décision : impossible, OB-4) ajoute « mode observation
(version de politique en observation), aucune approbation n'a été exigée ».
`summary.observation` compte ces dossiers et leurs marques. Ni le suffixe ni la
marque, signés avec l'événement, ne changent un verdict (section 12) ; le cas
`observation` de la famille `paquets` l'éprouve (EX-A.15).

**EX-13.29 (rapport JSON)** Avec `--json`, l'outil écrit un document
conforme à `paquet-reviseur-v0#/$defs/rapport`, y compris pour les codes 2
et 4 ; deux exécutions sur les mêmes entrées écrivent les mêmes octets, aux
chemins de `inputs` et à `tool.runtime` près.

| Clé | Contenu |
|---|---|
| `format`, `version` | `noortrace/rapport-paquet-reviseur`, `0` |
| `tool` | `name`, `version`, `runtime` (version de Node) |
| `language` | `fr` ou `en` |
| `inputs` | `archive` (chemin, taille, SHA-256, ou `null` si illisible), `expected_sha256`, `anchors_override` (chemin et SHA-256 du fichier de `--ancres`, ou `null`), `required_controls` |
| `manifest` | SHA-256, libellé, `created_at`, `prepared_by`, nombre de fichiers et d'octets, ou `null` si PR-7 n'a pas réussi |
| `checks` | PR-1 à PR-12 dans l'ordre : `id`, `status` (`reussi`, `echoue`, `non_execute`), `reason` (`null`, `empreinte_non_fournie`, `prerequis_en_echec`, `sans_objet`, `auto_comparaison`), `detail` |
| `package_status` | `intact`, `non_conforme`, ou `null` si l'archive n'a pas été lue |
| `warnings` | `{id, detail}`, AV-PR-1 à AV-PR-4 |
| `attestation` | `null`, ou `{retained, checks}` (AT-1 à AT-4) |
| `dossiers` | pour chaque dossier vérifié : `path`, `anchors` (`source` `paquet` ou `ligne_de_commande`, chemin, SHA-256 ; ou `null`), `bitcoin_headers`, `exit_code`, `verdict`, `index_sha256`, `failed_checks`, `control_statuses` (huit statuts), `observation`, `observation_mode`, `statement` (`{fr, en}` de CT-6) |
| `summary` | nombres de dossiers, valides, invalides, incomplets, inutilisables ; `observation` : dossiers en mode observation et marques par décision (`autorise`, `a_approuver`, `refuse`, `inconnu`) |
| `exit_code` | EX-13.26 |
| `error` | `null`, ou `{type, message}` (`usage`, `archive_illisible`, `extraction_impossible`, `erreur_interne`) |

Rapport du cas `fichier-altere` (un octet de `evenement.json` changé, code
4) :

<!-- schema: paquet-reviseur/rapport -->
```json
{
  "format": "noortrace/rapport-paquet-reviseur",
  "version": 0,
  "tool": {
    "name": "scripts/paquet-reviseur/verifier.mjs",
    "version": "0.1.0",
    "runtime": "node v22.22.0"
  },
  "language": "fr",
  "inputs": {
    "archive": {
      "path": "…/spec/vecteurs/ct-8/paquets/fichier-altere.tar",
      "size": 296960,
      "sha256": "0xb41b49dbe9b529f90b4de5b1c73986406951af163e0f9ed2a8381481227e7d29"
    },
    "expected_sha256": null,
    "anchors_override": null,
    "required_controls": []
  },
  "manifest": {
    "sha256": "0x5667fad9e2d6f8da8e3960304a8bb227638834f3e9319da20241f1f86a353fb1",
    "label": "Paquet de démonstration des vecteurs CT-8 : journal sinistres, période du 2026-11-05 de 09:00 à 10:00",
    "created_at": "2026-10-27T00:00:00.000Z",
    "prepared_by": "exploitant de l'instance de démonstration (vecteurs CT-8)",
    "files": 49,
    "bytes": 241340
  },
  "checks": [
    {
      "id": "PR-1",
      "status": "reussi",
      "reason": null,
      "detail": "296960 octets, 580 blocs"
    },
    {
      "id": "PR-2",
      "status": "non_execute",
      "reason": "empreinte_non_fournie",
      "detail": "aucune empreinte attendue (--empreinte)"
    },
    {
      "id": "PR-3",
      "status": "reussi",
      "reason": null,
      "detail": "50 entrées ustar bien formées"
    },
    {
      "id": "PR-4",
      "status": "reussi",
      "reason": null,
      "detail": "fichiers ordinaires seulement"
    },
    {
      "id": "PR-5",
      "status": "reussi",
      "reason": null,
      "detail": "50 noms relatifs sous paquet-reviseur/, uniques"
    },
    {
      "id": "PR-6",
      "status": "reussi",
      "reason": null,
      "detail": "ordre des noms, mode 0644, propriétaire 0/0, date 2026-10-27T00:00:00.000Z pour toutes les entrées"
    },
    {
      "id": "PR-7",
      "status": "reussi",
      "reason": null,
      "detail": "manifeste conforme : 49 fichiers, 3 dossier(s)"
    },
    {
      "id": "PR-8",
      "status": "echoue",
      "reason": null,
      "detail": "dossiers/valide-seq-7-complet/evenement.json : SHA-256 0x5133f8822bf0deb13b96972acbc684b928eeeec7bc177a6808b5dc8750be2d8d au lieu de 0x7849b34a2e1655c1522286af6b36fe1e402426ec6ad72b271c94119d88c91675"
    },
    {
      "id": "PR-9",
      "status": "non_execute",
      "reason": "prerequis_en_echec",
      "detail": "une vérification précédente a échoué"
    },
    {
      "id": "PR-10",
      "status": "non_execute",
      "reason": "prerequis_en_echec",
      "detail": "une vérification précédente a échoué"
    },
    {
      "id": "PR-11",
      "status": "non_execute",
      "reason": "prerequis_en_echec",
      "detail": "une vérification précédente a échoué"
    },
    {
      "id": "PR-12",
      "status": "non_execute",
      "reason": "prerequis_en_echec",
      "detail": "une vérification précédente a échoué"
    }
  ],
  "package_status": "non_conforme",
  "warnings": [],
  "attestation": null,
  "dossiers": [],
  "summary": {
    "dossiers": 0,
    "valid": 0,
    "invalid": 0,
    "incomplete": 0,
    "unusable": 0,
    "observation": {
      "dossiers": 0,
      "autorise": 0,
      "a_approuver": 0,
      "refuse": 0,
      "inconnu": 0
    }
  },
  "exit_code": 4,
  "error": null
}
```

Exemples de résumé lisible, produits par le prototype de l'outil sur les
vecteurs de l'annexe A.10 le 2026-11-01 (chemins abrégés). Paquet
`valide.tar`, sans option :

```text
$ node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/valide.tar
Vérification d'un paquet réviseur NOORTRACE (paquet-reviseur v0, CT-8 et CT-6)
Outil         : scripts/paquet-reviseur/verifier.mjs 0.1.0 (node v22.22.0)
Archive       : …/spec/vecteurs/ct-8/paquets/valide.tar, 296960 octets, SHA-256 0x8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982
Manifeste     : SHA-256 0x5667fad9e2d6f8da8e3960304a8bb227638834f3e9319da20241f1f86a353fb1 ; « Paquet de démonstration des vecteurs CT-8 : journal sinistres, période du 2026-11-05 de 09:00 à 10:00 » ; créé le 2026-10-27T00:00:00.000Z ; préparé par exploitant de l'instance de démonstration (vecteurs CT-8)
Paquet        : INTACT — 49 fichiers, 241340 octets décrits par le manifeste, 3 dossier(s)
Vérifications non réussies :
  [non exécuté] PR-2  aucune empreinte attendue (--empreinte) (empreinte_non_fournie)
  [non exécuté] PR-11 aucun vérificateur joint (sans_objet)
Avertissements :
  AV-PR-3 ancres prises dans le paquet : ancres/ancres-test.json (SHA-256 0x2be4619fb82ce615244c78a054e71930322bc0bed894521dca5f8d6a3b6dc617) ; comparez-les à votre fichier, ou passez le vôtre par --ancres
Attestation   : retenue (AT-1 à AT-4 réussies) — périmètre déclaré par ses signataires, non prouvé
Dossiers :
  [VALIDE]      dossiers/valide-seq-7-complet — code 0 ; contrôles réussis 1 2 3 4 5 6 7 8 ; ancres du paquet
                Énoncé : L'événement seq 7 (hachage 0x52030a580c0532eeae4a27f821c13a242b213d3732bf83663dd177130db3bd14) du journal 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164 de l'organisation 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab est bien formé, chaîné à ses voisins seq 6 et 8 et inclus dans la période du 2026-11-05T09:00:00Z au 2026-11-05T10:00:00Z close par le manifeste 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 ; l'événement est signé par la clé d'enregistreur rec-test-01 et le manifeste par la clé rec-test-02, clés fournies par le fichier d'ancres ; l'événement a été approuvé par 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 et 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc (2 signatures, seuil de 2 sur 3 du jeu déclaré par le dossier) ; selon AC de test CT-6 (unité TSA de test CT-6), le manifeste d'empreinte 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 existait au plus tard le 2026-11-05T10:00:06Z UTC ; le manifeste d'empreinte 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 existait avant la création du bloc Bitcoin 1001 (0x474467b4a5679ac228b840b99c9943f84f1c439537db877bac325061ac7d3026, réseau regtest), sous 20 blocs dont le travail se rattache au point de contrôle 1000 du réviseur ; heure inscrite par le mineur : 2026-11-05T13:50:00Z UTC, précision non garantie par le protocole ; borne sous hypothèse : 2026-11-05T14:50:00Z UTC (réseau d'essai, sans valeur probante) ; sur le registre noortrace-2124-dev, la clôture de cette période (organisation 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab, journal 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164) figure au bloc 16668 (heure déclarée par le bloc : 2026-10-22T22:20:56Z UTC), émise par le contrat PeriodRegistry 0x4ee6ecad1c2dae9f525404de8555724e3c35d07b, et son ancre 0x3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6 au bloc 16660 (heure déclarée 2026-10-22T22:20:49Z UTC), émise par AttestationRegistry 0xf4b146fba71f41e0592668ffbf264f1d186b2ca8 pour l'émetteur 0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49, clé de chaîne inscrite au bloc 16652 pour la clé d'enregistreur rec-test-02, que le réviseur tient pour la clé de chaîne de rec-test-02 ; chacun de ces blocs est signé par 3 des 4 validateurs du jeu 0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751 que le réviseur déclare (validators.json du réseau de développement, clés publiques seulement).
  [VALIDE]      dossiers/valide-seq-7-complet-attestation — code 0 ; contrôles réussis 1 2 3 4 5 6 7 8 ; ancres du paquet
                Énoncé : L'événement seq 7 (hachage 0x52030a580c0532eeae4a27f821c13a242b213d3732bf83663dd177130db3bd14) du journal 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164 de l'organisation 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab est bien formé, chaîné à ses voisins seq 6 et 8 et inclus dans la période du 2026-11-05T09:00:00Z au 2026-11-05T10:00:00Z close par le manifeste 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 ; l'événement est signé par la clé d'enregistreur rec-test-01 et le manifeste par la clé rec-test-02, clés fournies par le fichier d'ancres ; l'événement a été approuvé par 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 et 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc (2 signatures, seuil de 2 sur 3 du jeu déclaré par le dossier) ; selon AC de test CT-6 (unité TSA de test CT-6), le manifeste d'empreinte 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 existait au plus tard le 2026-11-05T10:00:06Z UTC ; le manifeste d'empreinte 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 existait avant la création du bloc Bitcoin 1001 (0x474467b4a5679ac228b840b99c9943f84f1c439537db877bac325061ac7d3026, réseau regtest), sous 20 blocs dont le travail se rattache au point de contrôle 1000 du réviseur ; heure inscrite par le mineur : 2026-11-05T13:50:00Z UTC, précision non garantie par le protocole ; borne sous hypothèse : 2026-11-05T14:50:00Z UTC (réseau d'essai, sans valeur probante) ; sur le registre noortrace-2124-dev, la clôture de cette période (organisation 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab, journal 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164) figure au bloc 16668 (heure déclarée par le bloc : 2026-10-22T22:20:56Z UTC), émise par le contrat PeriodRegistry 0x4ee6ecad1c2dae9f525404de8555724e3c35d07b, et son ancre 0x3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6 au bloc 16660 (heure déclarée 2026-10-22T22:20:49Z UTC), émise par AttestationRegistry 0xf4b146fba71f41e0592668ffbf264f1d186b2ca8 pour l'émetteur 0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49, clé de chaîne inscrite au bloc 16652 pour la clé d'enregistreur rec-test-02, que le réviseur tient pour la clé de chaîne de rec-test-02 ; chacun de ces blocs est signé par 3 des 4 validateurs du jeu 0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751 que le réviseur déclare (validators.json du réseau de développement, clés publiques seulement) ; le périmètre de capture est déclaré, non prouvé, par l'attestation 0x4481a2e47712539c4ca50f2eea3d6062ec11a70d497c153c1a6f707606657cfd valable du 2026-11-01T00:00:00Z au 2027-01-31T23:59:59.999Z, signée par 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 et 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc (2 signatures, seuil de 2 sur 3 du jeu déclaré par le dossier), non inscrite au journal (ni sa date ni son rang ne sont établis), et qui déclare 1 exception de capture.
  [VALIDE]      dossiers/valide-point-de-controle-complet — code 0 ; contrôles réussis 1 2 3 4 5 6 7 8 ; ancres du paquet
                Énoncé : L'événement seq 7 (hachage 0x52030a580c0532eeae4a27f821c13a242b213d3732bf83663dd177130db3bd14) du journal 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164 de l'organisation 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab est bien formé, chaîné à ses voisins seq 6 et 8 et inclus dans la période du 2026-11-05T09:00:00Z au 2026-11-05T10:00:00Z close par le manifeste 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 ; l'événement est signé par la clé d'enregistreur rec-test-01 et le manifeste par la clé rec-test-02, clés fournies par le fichier d'ancres ; l'événement a été approuvé par 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 et 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc (2 signatures, seuil de 2 sur 3 du jeu déclaré par le dossier) ; selon AC de test CT-6 (unité TSA de test CT-6), le manifeste d'empreinte 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 existait au plus tard le 2026-11-05T10:00:06Z UTC ; le manifeste d'empreinte 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 existait avant la création du bloc Bitcoin 1001 (0x474467b4a5679ac228b840b99c9943f84f1c439537db877bac325061ac7d3026, réseau regtest), sous 20 blocs dont le travail se rattache au point de contrôle 1000 du réviseur ; heure inscrite par le mineur : 2026-11-05T13:50:00Z UTC, précision non garantie par le protocole ; borne sous hypothèse : 2026-11-05T14:50:00Z UTC (réseau d'essai, sans valeur probante) ; sur le registre noortrace-2124-dev, la clôture de cette période (organisation 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab, journal 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164) figure au bloc 16668 (heure déclarée par le bloc : 2026-10-22T22:20:56Z UTC), émise par le contrat PeriodRegistry 0x4ee6ecad1c2dae9f525404de8555724e3c35d07b, et son ancre 0x3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6 au bloc 16660 (heure déclarée 2026-10-22T22:20:49Z UTC), émise par AttestationRegistry 0xf4b146fba71f41e0592668ffbf264f1d186b2ca8 pour l'émetteur 0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49, clé de chaîne inscrite au bloc 16652 pour la clé d'enregistreur rec-test-02, que le réviseur tient pour la clé de chaîne de rec-test-02 ; chacun de ces blocs est signé par 3 des 4 validateurs du jeu 0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751 que le réviseur déclare (validators.json du réseau de développement, clés publiques seulement) ; l'événement est couvert par le point de contrôle du journal de taille 8 de sa période (empreinte 0x93acd0fc36f93d7a267367e22367154e875d38c6368c527649d298619c90a4f4, signé par la clé d'enregistreur rec-test-01, fournie par le fichier d'ancres), préfixe prouvé de ce manifeste, horodaté au plus tard le 2026-11-05T09:32:03Z UTC selon AC de test CT-6 (unité TSA de test CT-6), antérieur à la création du bloc Bitcoin 1004 (0x103a3e5ed8957363710b4a21d5d954ca17aa82c0b575a7de5b089c5116af404e, réseau regtest) sous 17 blocs rattachés au point de contrôle Bitcoin 1000 du réviseur (réseau d'essai, sans valeur probante), ancré au registre noortrace-2124-dev au bloc 18928 (heure déclarée par le bloc : 2026-10-26T01:25:32Z UTC) par AttestationRegistry 0xf4b146fba71f41e0592668ffbf264f1d186b2ca8 ; une réécriture postérieure à cet instant serait détectée.
Résultat      : 3 dossier(s) valide(s) sur 3, 0 invalide(s), 0 incomplet(s), 0 inutilisable(s) — code 0
$ echo $?
0
```

Dans l'Énoncé de CT-6, « du réviseur » désigne le fichier d'ancres employé :
quand la ligne du dossier dit « ancres du paquet », comme ici, il faut lire
« de l'exploitant » tant que le réviseur n'a pas comparé ce fichier au sien
(AV-PR-3).

Sous `Vérifications non réussies :`, « non exécuté » n'est pas un échec : la
rubrique regroupe tout statut autre que `reussi`, et la raison entre
parenthèses, prise dans la liste fermée d'EX-13.30, dit laquelle est une
précaution omise : `empreinte_non_fournie` (PR-2 : le réviseur n'a pas donné
`--empreinte`, précaution omise) ; `sans_objet` (PR-11, PR-12 : le paquet ne
porte ni vérificateur ni attestation, rien n'est omis) ; `auto_comparaison`
(PR-11 : l'outil exécuté est la copie jointe, EX-13.22) ; `prerequis_en_echec`
(une vérification de PR-1 à PR-9 a échoué avant elle : le paquet est `NON
CONFORME`, code 4).

Le même paquet, en français, sous la forme complète recommandée (exécution du
2026-11-01, code 0 ; lignes `Énoncé` omises) :

```bash
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/valide.tar \
  --empreinte 8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982 \
  --ancres spec/vecteurs/ct-6/ancres/ancres-test.json
```

```text
Vérification d'un paquet réviseur NOORTRACE (paquet-reviseur v0, CT-8 et CT-6)
Outil         : scripts/paquet-reviseur/verifier.mjs 0.1.0 (node v22.22.0)
Archive       : …/spec/vecteurs/ct-8/paquets/valide.tar, 296960 octets, SHA-256 0x8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982
Manifeste     : SHA-256 0x5667fad9e2d6f8da8e3960304a8bb227638834f3e9319da20241f1f86a353fb1 ; « Paquet de démonstration des vecteurs CT-8 : journal sinistres, période du 2026-11-05 de 09:00 à 10:00 » ; créé le 2026-10-27T00:00:00.000Z ; préparé par exploitant de l'instance de démonstration (vecteurs CT-8)
Paquet        : INTACT — 49 fichiers, 241340 octets décrits par le manifeste, 3 dossier(s)
Empreinte     : SHA-256 égal à l'empreinte attendue 0x8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982 (PR-2)
Vérifications non réussies :
  [non exécuté] PR-11 aucun vérificateur joint (sans_objet)
Attestation   : retenue (AT-1 à AT-4 réussies) — périmètre déclaré par ses signataires, non prouvé
Dossiers :
  [VALIDE]      dossiers/valide-seq-7-complet — code 0 ; contrôles réussis 1 2 3 4 5 6 7 8 ; ancres de la ligne de commande
  [VALIDE]      dossiers/valide-seq-7-complet-attestation — code 0 ; contrôles réussis 1 2 3 4 5 6 7 8 ; ancres de la ligne de commande
  [VALIDE]      dossiers/valide-point-de-controle-complet — code 0 ; contrôles réussis 1 2 3 4 5 6 7 8 ; ancres de la ligne de commande
Résultat      : 3 dossier(s) valide(s) sur 3, 0 invalide(s), 0 incomplet(s), 0 inutilisable(s) — code 0
```

Le même paquet, en anglais, avec l'empreinte attendue et le fichier d'ancres
du réviseur donnés sur la ligne de commande (lignes `Statement` omises) :

```text
$ node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/valide.tar --langue en \
    --empreinte 8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982 --ancres spec/vecteurs/ct-6/ancres/ancres-test.json
Verification of a NOORTRACE reviewer package (paquet-reviseur v0, CT-8 and CT-6)
Tool          : scripts/paquet-reviseur/verifier.mjs 0.1.0 (node v22.22.0)
Archive       : …/spec/vecteurs/ct-8/paquets/valide.tar, 296960 bytes, SHA-256 0x8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982
Manifest      : SHA-256 0x5667fad9e2d6f8da8e3960304a8bb227638834f3e9319da20241f1f86a353fb1; "Paquet de démonstration des vecteurs CT-8 : journal sinistres, période du 2026-11-05 de 09:00 à 10:00"; created 2026-10-27T00:00:00.000Z; prepared by exploitant de l'instance de démonstration (vecteurs CT-8)
Package       : INTACT — 49 files, 241340 bytes described by the manifest, 3 dossier(s)
Digest        : SHA-256 equal to the expected digest 0x8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982 (PR-2)
Checks not passed:
  [not run]     PR-11 no verifier enclosed (sans_objet)
Attestation   : retained (AT-1 to AT-4 passed) — scope declared by its signatories, not proven
Dossiers:
  [VALID]       dossiers/valide-seq-7-complet — code 0; controls passed 1 2 3 4 5 6 7 8; command-line anchors
  [VALID]       dossiers/valide-seq-7-complet-attestation — code 0; controls passed 1 2 3 4 5 6 7 8; command-line anchors
  [VALID]       dossiers/valide-point-de-controle-complet — code 0; controls passed 1 2 3 4 5 6 7 8; command-line anchors
Result        : 3 valid dossier(s) of 3, 0 invalid, 0 incomplete, 0 unusable — code 0
```

Paquet `fichier-altere.tar` : un octet de
`dossiers/valide-seq-7-complet/evenement.json` changé, manifeste inchangé.

```text
$ node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/fichier-altere.tar
Vérification d'un paquet réviseur NOORTRACE (paquet-reviseur v0, CT-8 et CT-6)
Outil         : scripts/paquet-reviseur/verifier.mjs 0.1.0 (node v22.22.0)
Archive       : …/spec/vecteurs/ct-8/paquets/fichier-altere.tar, 296960 octets, SHA-256 0xb41b49dbe9b529f90b4de5b1c73986406951af163e0f9ed2a8381481227e7d29
Manifeste     : SHA-256 0x5667fad9e2d6f8da8e3960304a8bb227638834f3e9319da20241f1f86a353fb1 ; « Paquet de démonstration des vecteurs CT-8 : journal sinistres, période du 2026-11-05 de 09:00 à 10:00 » ; créé le 2026-10-27T00:00:00.000Z ; préparé par exploitant de l'instance de démonstration (vecteurs CT-8)
Paquet        : NON CONFORME — PR-8 : dossiers/valide-seq-7-complet/evenement.json : SHA-256 0x5133f8822bf0deb13b96972acbc684b928eeeec7bc177a6808b5dc8750be2d8d au lieu de 0x7849b34a2e1655c1522286af6b36fe1e402426ec6ad72b271c94119d88c91675
Vérifications non réussies :
  [non exécuté] PR-2  aucune empreinte attendue (--empreinte) (empreinte_non_fournie)
  [ÉCHEC]       PR-8  dossiers/valide-seq-7-complet/evenement.json : SHA-256 0x5133f8822bf0deb13b96972acbc684b928eeeec7bc177a6808b5dc8750be2d8d au lieu de 0x7849b34a2e1655c1522286af6b36fe1e402426ec6ad72b271c94119d88c91675
  [non exécuté] PR-9  une vérification précédente a échoué (prerequis_en_echec)
  [non exécuté] PR-10 une vérification précédente a échoué (prerequis_en_echec)
  [non exécuté] PR-11 une vérification précédente a échoué (prerequis_en_echec)
  [non exécuté] PR-12 une vérification précédente a échoué (prerequis_en_echec)
Résultat      : PAQUET NON CONFORME — aucun dossier n'est vérifié — code 4
$ echo $?
4
```

Paquet `contrefacon-coherente.tar` : le même octet changé et le manifeste
recalculé. Le paquet est intact ; c'est CT-6 qui rend le dossier invalide
(lignes `Énoncé` omises). C'est la limite de 13.10 : un paquet intact ne
prouve pas que ses dossiers sont bons.

```text
$ node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/contrefacon-coherente.tar
Vérification d'un paquet réviseur NOORTRACE (paquet-reviseur v0, CT-8 et CT-6)
Outil         : scripts/paquet-reviseur/verifier.mjs 0.1.0 (node v22.22.0)
Archive       : …/spec/vecteurs/ct-8/paquets/contrefacon-coherente.tar, 296960 octets, SHA-256 0xd806d8e7af25c118d9f241ead0c8b51892e10e778a8f1a0238f831334e822344
Manifeste     : SHA-256 0xbf155bc07671044be114fa5ca28f8d64485dd1481617d3728607f124ef78eb82 ; « Paquet de démonstration des vecteurs CT-8 : journal sinistres, période du 2026-11-05 de 09:00 à 10:00 » ; créé le 2026-10-27T00:00:00.000Z ; préparé par exploitant de l'instance de démonstration (vecteurs CT-8)
Paquet        : INTACT — 49 fichiers, 241340 octets décrits par le manifeste, 3 dossier(s)
Vérifications non réussies :
  [non exécuté] PR-2  aucune empreinte attendue (--empreinte) (empreinte_non_fournie)
  [non exécuté] PR-11 aucun vérificateur joint (sans_objet)
Avertissements :
  AV-PR-3 ancres prises dans le paquet : ancres/ancres-test.json (SHA-256 0x2be4619fb82ce615244c78a054e71930322bc0bed894521dca5f8d6a3b6dc617) ; comparez-les à votre fichier, ou passez le vôtre par --ancres
Attestation   : retenue (AT-1 à AT-4 réussies) — périmètre déclaré par ses signataires, non prouvé
Dossiers :
  [INVALIDE]    dossiers/valide-seq-7-complet — code 1 ; contrôles réussis 4 5 7 8 ; en échec 1 2 3 6 ; ancres du paquet ; vérifications en échec : D-1, D-2, E-7, E-8, C-1, C-2, M-1, M-3
  [VALIDE]      dossiers/valide-seq-7-complet-attestation — code 0 ; contrôles réussis 1 2 3 4 5 6 7 8 ; ancres du paquet
  [VALIDE]      dossiers/valide-point-de-controle-complet — code 0 ; contrôles réussis 1 2 3 4 5 6 7 8 ; ancres du paquet
Résultat      : 2 dossier(s) valide(s) sur 3, 1 invalide(s), 0 incomplet(s), 0 inutilisable(s) — code 1
$ echo $?
1
```

### 13.8 Vérifications PR-1 à PR-12

| Id | Vérifie | Défaut | Vecteur(s) |
|---|---|---|---|
| PR-1 | Taille de l'archive | code 4 | — (tests) |
| PR-2 | Empreinte attendue | code 4 | `empreinte-fausse` |
| PR-3 | En-têtes ustar et fin d'archive | code 4 | — (tests) |
| PR-4 | Fichiers ordinaires seulement | code 4 | `lien-symbolique`, `lien-physique` |
| PR-5 | Noms | code 4 | `chemin-hors-archive`, `chemin-absolu`, `nom-en-double` |
| PR-6 | Forme déterministe | code 4 | `metadonnees-non-fixees` |
| PR-7 | Manifeste | code 4 | — (tests) |
| PR-8 | Correspondance du manifeste et de l'archive | code 4 | `fichier-altere`, `fichier-manquant`, `fichier-en-trop`, `manifeste-altere` |
| PR-9 | Cohérence interne | code 4 | — (tests) |
| PR-10 | Extraction | code 2 | — (tests) |
| PR-11 | Vérificateur joint | AV-PR-1, sans effet sur le code | paquet complet de la CI |
| PR-12 | Attestation jointe (AT-1 à AT-4) | AV-PR-2, sans effet sur le code | `valide` (réussie) |

**EX-13.30 (ordre et arrêt)** Les vérifications s'exécutent dans l'ordre de
la table. La première de PR-1 à PR-9 en échec arrête la vérification : les
suivantes sont `non_execute`, raison `prerequis_en_echec`, et le code est 4.
PR-2 sans `--empreinte` est `non_execute`, raison `empreinte_non_fournie`,
et n'arrête rien. PR-11 et PR-12 sont `non_execute`, raison `sans_objet`,
quand le paquet ne porte pas de vérificateur ou d'attestation ; leur échec
ne change pas le code. Les raisons forment une liste fermée :
`empreinte_non_fournie`, `prerequis_en_echec`, `sans_objet`,
`auto_comparaison` (PR-11, EX-13.22).

**EX-13.31 (PR-1 à PR-3)** PR-1 : la longueur `L` de l'archive vérifie
1 024 ≤ `L` ≤ 536 870 912 et `L` est un multiple de 512. PR-2 : le SHA-256
de l'archive égale l'empreinte attendue ; un échec dit seulement que le
SHA-256 de l'archive diffère de la valeur donnée, et rien d'autre n'est lu :
le réviseur relit l'empreinte reçue avant de conclure que ce n'est pas le
paquet annoncé. PR-3 : les blocs se lisent dans
l'ordre depuis l'octet 0 ; un bloc entièrement nul marque la fin, et le
bloc suivant comme tous les octets qui suivent doivent être nuls ; tout
autre bloc est un en-tête dont `magic` vaut `ustar` puis NUL, `version`
vaut `00`, `chksum` a exactement la forme d'EX-13.14 et la valeur
recalculée, chaque champ numérique (`mode`, `uid`, `gid`, `size`, `mtime`)
est fait de chiffres octaux, de la largeur du champ moins un, suivis de NUL,
chaque champ de texte n'a que des NUL après son premier NUL, les octets 500
à 511 sont nuls, les données tiennent dans l'archive et leur bourrage est
nul ; l'archive a au moins une entrée, au plus 10 001, et une fin.

**EX-13.32 (PR-4 à PR-6)** PR-4 : chaque entrée a `typeflag` `0` et
`linkname` vide ; un lien physique (`1`), un lien symbolique (`2`), un
périphérique (`3`, `4`), un répertoire (`5`), un tube (`6`), un en-tête pax
(`x`, `g`), un nom ou un lien long GNU (`L`, `K`) ou un fichier d'ancien
format (NUL) est refusé. PR-5 : le nom complet (`prefix`, `/`, `name`
quand `prefix` n'est pas vide ; `name` sinon) est en ASCII imprimable, ne
commence pas par `/`, ne contient pas de composant `..`, commence par le
composant `paquet-reviseur`, a de 2 à 17 composants dont chacun après le
premier suit `[A-Za-z0-9_@+-][A-Za-z0-9._@+-]{0,99}`, tient en 255 octets,
est unique, unique aussi après passage des lettres ASCII en minuscules (un
système de fichiers insensible à la casse confondrait les deux, R9-F19), et
n'est pas le répertoire d'un autre nom ; le détail nomme le premier défaut
dans cet ordre. PR-6 : les noms sont strictement croissants dans l'ordre de
leurs octets, chaque en-tête porte le mode `0644`, les propriétaires 0,
`uname`, `gname`, `devmajor` et `devminor` vides, la même date que la
première entrée et le découpage nom/préfixe d'EX-13.14, et `L` vaut la
longueur d'EX-13.14.

**EX-13.33 (PR-7 à PR-9)** PR-7 : l'entrée `paquet-reviseur/MANIFESTE.json`
existe, tient en 16 Mio, se lit en JSON strict, suit son schéma ; `files` est
strictement croissant et ne liste pas `MANIFESTE.json` ; les chemins de
`dossiers` sont distincts ; `created_at`, en secondes, égale la date des
entrées. PR-8 : l'ensemble des fichiers de l'archive, manifeste excepté,
égale l'ensemble de `files` (un fichier déclaré absent, un fichier non
déclaré : échec) ; chaque fichier a la taille et le SHA-256 déclarés ; le
détail liste tous les écarts. PR-9 : chaque `role` est celui de
l'emplacement ; `LISEZMOI.md` et `README.md` existent ; chaque dossier
déclaré a son `dossier.json` ; chaque `anchors` et chaque `bitcoin_headers`
non nuls désignent un fichier de rôle `ancres` ou `entetes` ; chaque fichier
de rôle `dossier` est sous un dossier déclaré ; chaque fichier de rôle
`ancres` ou `entetes` est désigné par au moins un dossier ; les fichiers de
rôle `attestation` sont exactement les deux que nomme `attestation`, ou
aucun si elle est nulle ; aucun fichier de rôle `verificateur` si `verifier`
est nul, et `verifier.tool` et `verifier.dossier_verifier` présents sinon.

**EX-13.34 (PR-10 à PR-12)** PR-10 : l'extraction d'EX-13.25, pas 3, réussit
et chaque fichier relu a le SHA-256 du manifeste. PR-11 : l'ensemble et les
octets des fichiers de `verificateur/` égalent ceux que l'outil exécuté
joindrait (EX-13.20) ; un écart lève AV-PR-1 ; `non_execute`, raison
`auto_comparaison`, quand l'outil exécuté est la copie jointe d'un paquet
extrait (EX-13.22). PR-12 : AT-1 à AT-4 (CT-1
§11.4, CT-7 EX-7.16) appliquées à `attestation-signee.json` avec
`jeu-approbateurs.json` retiennent l'attestation ; sinon AV-PR-2.

### 13.9 Avertissements

| Id | Quand | Ce qu'il dit |
|---|---|---|
| AV-PR-1 | PR-11 en échec | Le vérificateur joint diffère de l'outil exécuté : la copie jointe ne s'emploie qu'après comparaison aux empreintes publiées. |
| AV-PR-2 | PR-12 en échec | L'attestation de périmètre jointe n'est pas retenue. |
| AV-PR-3 | Paquet intact, `--ancres` absente, un dossier au moins désigne un fichier d'ancres du paquet | Les ancres viennent du paquet ; le résumé donne leur SHA-256 à comparer au fichier du réviseur. |
| AV-PR-4 | Paquet intact, `--ancres` absente, un dossier au moins sans fichier d'ancres | Ce dossier est vérifié sans ancres : contrôles 4, 5 et 8 non exécutés (CT-6 EX-4.9). |

**EX-13.35** Un avertissement ne change aucun statut ni le code de retour ;
il figure dans le résumé et dans `warnings`, dans l'ordre de la table.

### 13.10 Ce que le paquet prouve et ne prouve pas

| Élément | Ce qu'une vérification réussie établit | Ce qu'elle n'établit pas |
|---|---|---|
| Paquet intact (PR-1 à PR-9) | Les fichiers sont ceux que le manifeste décrit, octet pour octet, dans une archive de forme canonique, sans lien ni nom qui sorte de la racine. | Qui a fait le paquet, ni quand : le manifeste n'est pas signé et `created_at` est déclaré. Un manifeste recalculé après une altération passe PR-8 (cas `contrefacon-coherente`). |
| Empreinte attendue (PR-2) | L'archive est celle dont le réviseur a reçu l'empreinte. | Que l'émetteur de l'empreinte est honnête : la force de PR-2 est celle du canal qui l'a portée. |
| Dossier `[VALIDE]` | L'énoncé de CT-6 pour ce dossier, sous les ancres employées (CT-6 §7). | Plus que CT-6 §7 : avec des ancres prises dans le paquet, le verdict repose sur l'exploitant tant que le réviseur ne les a pas comparées aux siennes (CT-6 H3, CT-7 RA-58). |
| Ancres du paquet | Leur SHA-256, imprimé pour comparaison (AV-PR-3). | Qu'elles sont celles du réviseur. |
| En-têtes Bitcoin | Rien par eux-mêmes : ils ne sont crus qu'au travers de O-5 (CT-6 EX-10.4). | Que la chaîne d'en-têtes est la plus travaillée. |
| Attestation (PR-12) | Les signataires du jeu déclaré ont signé ce texte (CT-7 §7.8). | Le périmètre lui-même : déclaré, non prouvé. |
| Pièces | Rien : l'outil ne les lit pas. | Qu'elles sont exactes ; le réviseur les recoupe à ses sources (CT-6 §12.5). |
| Vérificateur joint (PR-11) | Il est identique à l'outil exécuté. | Que l'outil exécuté est sûr : cela dépend d'où le réviseur le tient (EX-13.22). |
| Complétude | Rien. | Que le paquet porte tous les événements ou tous les dossiers d'une période : le réviseur choisit les dossiers ; la complétude au registre est un contrôle de série de CT-5 EX-10.7, hors du paquet. |
| Marque d'observation | Ce que la politique aurait rendu pour l'événement prouvé, signé avec lui (EX-13.28). | Ce qui s'est passé pour les appels que le paquet ne porte pas. |

Pour décider, comptent le code, le verdict et la provenance des ancres : avec
« ancres du paquet », un code 0 ne vaut qu'après comparaison de leur SHA-256 au
fichier du réviseur (AV-PR-3). Dans l'Énoncé de CT-6, « du réviseur » désigne
le fichier d'ancres employé : sous des ancres du paquet, il faut lire « de
l'exploitant » tant que cette comparaison n'est pas faite.

### 13.11 Instructions au réviseur

**EX-13.36** Les deux textes ci-dessous sont les fichiers `LISEZMOI.md` et
`README.md` du paquet, octet pour octet (UTF-8, fins de ligne LF, saut de
ligne final) ; l'outil de construction les copie de
`scripts/paquet-reviseur/instructions/`, et un test exige l'égalité de ces
fichiers et des blocs de cette section (EX-A.20). Ils sont génériques : rien
n'y dépend du paquet. Leurs SHA-256 du 2026-11-01, pour `LISEZMOI.md` :
`0x858905b068fdf7cb3db303e3d614e8ac8712e2833f8c13522325c22a44aeac14` ;
pour `README.md` :
`0x4874a8613621cd372cfe8fef9bacb391d4772d4ee1bd9bfe74a421b8f2743d34`.

<!-- fichier: LISEZMOI.md -->
```text
# Paquet réviseur NOORTRACE

Ce paquet contient des dossiers de preuve NOORTRACE et de quoi les vérifier
hors ligne. Son format est le paquet réviseur version 0 (spécification CT-8,
section 13) ; chaque dossier se vérifie selon la spécification CT-6.

## Contenu

- `MANIFESTE.json` : la liste des fichiers, avec la taille et le SHA-256 de
  chacun, et, pour chaque dossier, le fichier d'ancres et le fichier
  d'en-têtes Bitcoin avec lesquels le vérifier.
- `dossiers/` : un répertoire par dossier de preuve.
- `ancres/` : le fichier d'ancres de confiance que vous avez remis à
  l'exploitant. Assurez-vous qu'il est le vôtre : `sha256sum <votre fichier
  d'ancres>` doit donner la valeur que le résumé imprime (avertissement
  AV-PR-3), sans son préfixe `0x` ; sinon, ou si vous n'avez remis aucun
  fichier, donnez le vôtre par l'option `--ancres`.
- `entetes/` : des en-têtes Bitcoin, crus seulement au travers du point de
  contrôle de votre fichier d'ancres.
- `attestation/` (si présent) : l'attestation de périmètre signée et le jeu
  d'approbateurs que l'exploitant déclare.
- `pieces/` (si présent) : des pièces publiées par l'exploitant pour préparer
  et recouper vos ancres (fiches de prestataire, manifeste d'instance du
  registre…). Elles sont déclaratives : l'outil ne les lit pas, et elles ne
  remplacent pas vos propres sources.
- `verificateur/` (si présent) : le vérificateur de référence, l'outil de
  vérification du paquet et la seule bibliothèque dont ils dépendent.

## Vérifier en une commande

Il faut Node.js 22 (éprouvé avec v22.22.0 sous Linux ; les versions
ultérieures et les autres systèmes ne sont pas vérifiés) ; aucun accès au
réseau n'est nécessaire.

1. Prenez l'outil de vérification dans une source que vous jugez sûre : le
   dépôt public de NOORTRACE, dont la note de version donne l'adresse et le
   commit, à une version publiée, ou la copie jointe sous `verificateur/`.
   Pour employer la copie jointe :
   - extrayez le paquet dans un répertoire neuf et vide par
     `tar -xkf <paquet.tar> -C <répertoire>` (jamais avec l'option `-P`) et
     exigez le code 0 : avec `-k`, un nom en double fait échouer `tar` au
     lieu de remplacer le premier fichier par le second ;
   - dans `<répertoire>/paquet-reviseur/verificateur/`, contrôlez les
     fichiers extraits par `sha256sum --strict -c <SHA256SUMS>`, où
     `<SHA256SUMS>` est la liste signée des SHA-256 du vérificateur publiée
     avec la note de version, par un autre canal que le paquet ; ni le
     manifeste du paquet ni la sortie de `--version` de la copie ne la
     remplacent. Tant qu'aucune version de l'outil n'est publiée, il n'y a
     pas de telle liste et ce contrôle n'est pas possible : prenez l'outil
     dans le dépôt public, à un commit que l'exploitant vous nomme avec
     l'empreinte du paquet, par le même canal ; vous vous fiez alors à lui
     pour l'outil.
2. Lancez, depuis n'importe quel répertoire :

       node <outil>/scripts/paquet-reviseur/verifier.mjs <paquet.tar> \
            --empreinte <SHA-256 du paquet reçu par un autre canal> \
            --ancres <votre fichier d'ancres>

   `<outil>` est la racine du dépôt, ou le répertoire `verificateur/` de la
   copie extraite. Les deux options sont facultatives ; sans elles, le
   rapport le signale. `--json` donne le rapport en JSON, `--langue en` en
   anglais. `--exiger` exige des contrôles de CT-6 (numéros 1 à 8).

L'outil contrôle l'archive sans rien écrire (en-têtes, noms, fichiers contre
le manifeste), puis seulement l'extrait dans un répertoire neuf sous le
répertoire temporaire du système, vérifie chaque dossier, et efface ce
répertoire.

Sur un paquet valide, la rubrique « Vérifications non réussies » peut porter
jusqu'à trois lignes « non exécuté », qui ne sont pas des échecs :
`PR-2 (empreinte_non_fournie)` si vous n'avez pas donné `--empreinte`,
précaution omise ; `PR-11 (sans_objet)` si le paquet n'a pas de vérificateur
joint ; `PR-12 (sans_objet)` s'il n'a pas d'attestation. Avec la commande
recommandée, sur un paquet sans vérificateur joint et avec attestation, il
n'en reste qu'une : `PR-11`. `PR-11 (auto_comparaison)` dit que l'outil
exécuté est la copie jointe elle-même, qui ne peut pas se contrôler.

Les contrôles 1 à 8 et les identifiants `D-`, `E-`, `C-`, `M-` d'un dossier
sont ceux de CT-6 (section 8) ; la section 13.7 de CT-8 nomme les huit
contrôles. Pour décider, seuls comptent le code, le verdict et la provenance
des ancres : avec « ancres du paquet », un code 0 ne vaut qu'après
comparaison de leur SHA-256 à votre fichier (avertissement AV-PR-3). Dans la
ligne « Énoncé » d'un dossier, « du réviseur » désigne le fichier d'ancres
employé : tant que la ligne du dossier dit « ancres du paquet » et que vous
n'avez pas fait cette comparaison, lisez « de l'exploitant ».

## Codes de retour

Le code 4 l'emporte sur tout, car aucun dossier n'est alors vérifié ; entre
dossiers, la priorité est 1, puis 2, 3, 0.

| Code | Sens |
|---|---|
| 0 | Paquet intact, tous les dossiers valides. |
| 1 | Paquet intact, au moins un dossier invalide. |
| 2 | Entrée inutilisable : usage, archive illisible, extraction impossible, erreur interne ; ou paquet intact dont un dossier au moins rend le code 2 (fichier d'ancres refusé) et aucun le code 1. |
| 3 | Paquet intact, aucun dossier invalide ni inutilisable, au moins un dossier incomplet (option `--exiger`). |
| 4 | Paquet non conforme : aucun dossier n'est vérifié. |

Conduite selon le code :

- Code 1 : le paquet est bien celui que le manifeste décrit, mais au moins un
  dossier est invalide. Ce dossier ne prouve pas l'événement (CT-6 §8.3) :
  conservez le rapport `--json` et signalez-le à l'exploitant. Chaque autre
  dossier garde le sens de son propre code, sous les ancres employées.
- Code 2 de type `usage` (option, fichier `--ancres` illisible, répertoire
  `--conserver` existant) : il vient de votre commande ; corrigez-la et
  relancez. Un code 2 avec un paquet intact et un fichier d'ancres refusé met
  en cause ce fichier (le vôtre, ou celui du paquet si vous n'avez pas donné
  `--ancres`), non l'intégrité du paquet.
- Code 3 : un contrôle exigé par `--exiger` n'a pas réussi, sans qu'aucune
  vérification soit en échec ; le dossier n'est pas invalide, il est
  incomplet. Demandez les pièces manquantes ou relancez après la mise à
  niveau des preuves.
- Code 4, ou code 2 dû à l'archive (illisible, extraction impossible) : le
  paquet est refusé et n'est pas exploité. Conservez l'archive, son SHA-256
  et le rapport `--json`, et demandez à l'exploitant un nouveau paquet, dont
  l'empreinte vous parvient par un autre canal. Un échec de PR-2 dit
  seulement que le SHA-256 de l'archive diffère de la valeur donnée :
  relisez l'empreinte reçue avant de conclure que le paquet n'est pas celui
  annoncé. Après un échec de PR-2, une seconde exécution sans `--empreinte`
  peut localiser l'écart (PR-3 à PR-9 s'exécutent alors ; PR-8 nomme le
  fichier en cause) : joignez son rapport `--json` au signalement. Elle ne
  change pas la décision : le paquet reste refusé tant que vous n'avez pas
  une archive dont le SHA-256 égale l'empreinte reçue, relue.

## Ce que le résultat prouve, et ce qu'il ne prouve pas

- « Paquet intact » dit que les fichiers sont ceux que le manifeste décrit,
  octet pour octet. Il ne dit pas qui a fait le paquet : seule l'empreinte
  reçue par un autre canal (`--empreinte`) relie ce paquet à son émetteur.
- « VALIDE » pour un dossier reprend l'énoncé du vérificateur (CT-6), qui ne
  vaut que ce que valent les ancres employées. Des ancres prises dans le
  paquet sont celles de l'exploitant tant que vous ne les avez pas
  comparées aux vôtres.
- L'attestation de périmètre est déclarée par ses signataires, non prouvée.
- Le paquet ne prouve rien des événements qu'il ne contient pas : il ne dit
  pas que la liste des dossiers est complète.

## Sécurité

N'extrayez jamais un paquet avec `tar -P` ni dans un répertoire qui contient
déjà des fichiers. L'outil refuse les liens, les noms absolus, les noms qui
contiennent `..`, les doublons et tout fichier que le manifeste ne déclare
pas.
```

<!-- fichier: README.md -->
```text
# NOORTRACE reviewer package

This package contains NOORTRACE evidence dossiers and what is needed to verify
them offline. Its format is the reviewer package version 0 (specification
CT-8, section 13); each dossier is verified according to specification CT-6.

## Contents

- `MANIFESTE.json`: the list of files, with the size and SHA-256 of each,
  and, for each dossier, the anchors file and the Bitcoin headers file to
  verify it with.
- `dossiers/`: one directory per evidence dossier.
- `ancres/`: the trust anchors file that you gave to the operator. Make sure
  it is yours: `sha256sum <your anchors file>` must give the value that the
  summary prints (warning AV-PR-3), without its `0x` prefix; otherwise, or
  if you gave no file, give yours with the `--ancres` option.
- `entetes/`: Bitcoin headers, trusted only through the checkpoint of your
  anchors file.
- `attestation/` (if present): the signed scope attestation and the approver
  set that the operator declares.
- `pieces/` (if present): documents published by the operator to prepare and
  cross-check your anchors (provider records, registry instance manifest…).
  They are declarative: the tool does not read them, and they do not replace
  your own sources.
- `verificateur/` (if present): the reference verifier, the package
  verification tool and the only library they depend on.

## Verifying in one command

Node.js 22 is required (tested with v22.22.0 on Linux; later versions and
other systems are not verified); no network access is needed.

1. Take the verification tool from a source you trust: the public NOORTRACE
   repository, whose address and commit the release note gives, at a
   published version, or the enclosed copy under `verificateur/`. To use the
   enclosed copy:
   - extract the package into a new, empty directory with
     `tar -xkf <package.tar> -C <directory>` (never with the `-P` option)
     and require exit code 0: with `-k`, a duplicate name makes `tar` fail
     instead of replacing the first file with the second;
   - in `<directory>/paquet-reviseur/verificateur/`, check the extracted
     files with `sha256sum --strict -c <SHA256SUMS>`, where `<SHA256SUMS>`
     is the signed list of the verifier's SHA-256 published with the
     release note, over another channel than the package; neither the
     package manifest nor the `--version` output of the copy replaces it.
     As long as no version of the tool is published, there is no such
     list and this check is not possible: take the tool from the public
     repository, at a commit that the operator names to you together with
     the package digest, over the same channel; you then trust the
     operator for the tool.
2. Run, from any directory:

       node <tool>/scripts/paquet-reviseur/verifier.mjs <package.tar> \
            --empreinte <SHA-256 of the package received over another channel> \
            --ancres <your anchors file>

   `<tool>` is the root of the repository, or the `verificateur/` directory
   of the extracted copy. Both options are optional; without them, the
   report says so. `--json` gives the report in JSON, `--langue en` in
   English. `--exiger` requires CT-6 controls (numbers 1 to 8).

The tool checks the archive without writing anything (headers, names,
files against the manifest), then only extracts it into a new directory
under the system temporary directory, verifies each dossier, and deletes
that directory.

On a valid package, the "Checks not passed" section may hold up to three
"not run" lines, which are not failures: `PR-2 (empreinte_non_fournie)` if
you did not give `--empreinte`, an omitted precaution; `PR-11 (sans_objet)`
if the package has no enclosed verifier; `PR-12 (sans_objet)` if it has no
attestation. With the recommended command, on a package without an enclosed
verifier and with an attestation, only one remains: `PR-11`.
`PR-11 (auto_comparaison)` says that the running tool is the enclosed copy
itself, which cannot check itself.

Controls 1 to 8 and the `D-`, `E-`, `C-`, `M-` identifiers of a dossier are
those of CT-6 (section 8); section 13.7 of CT-8 names the eight controls.
For the decision, only the exit code, the verdict and the provenance of the
anchors count: with "package anchors", an exit code 0 is worth nothing until
you have compared their SHA-256 with your file (warning AV-PR-3). In the
"Statement" line of a dossier, "the reviewer's" means the anchors file that
was used: as long as the dossier line says "package anchors" and you have
not made that comparison, read "the operator's".

## Exit codes

Code 4 prevails over everything, because no dossier is then verified;
between dossiers, the priority is 1, then 2, 3, 0.

| Code | Meaning |
|---|---|
| 0 | Package intact, every dossier valid. |
| 1 | Package intact, at least one dossier invalid. |
| 2 | Unusable input: usage, unreadable archive, extraction impossible, internal error; or package intact where at least one dossier returns code 2 (anchors file refused) and none returns code 1. |
| 3 | Package intact, no dossier invalid or unusable, at least one dossier incomplete (`--exiger` option). |
| 4 | Package not conforming: no dossier is verified. |

What to do for each code:

- Code 1: the package is the one the manifest describes, but at least one
  dossier is invalid. That dossier does not prove the event (CT-6 §8.3):
  keep the `--json` report and report it to the operator. Every other
  dossier keeps the meaning of its own code, under the anchors used.
- Code 2 of type `usage` (option, unreadable `--ancres` file, existing
  `--conserver` directory): it comes from your command; correct it and run
  again. A code 2 with an intact package and a refused anchors file puts
  that file in question (yours, or the package's if you did not give
  `--ancres`), not the integrity of the package.
- Code 3: a control required by `--exiger` did not pass, while no check
  failed; the dossier is not invalid, it is incomplete. Ask for the missing
  pieces or run again after the proofs have been upgraded.
- Code 4, or code 2 due to the archive (unreadable, extraction impossible):
  the package is refused and is not used. Keep the archive, its SHA-256 and
  the `--json` report, and ask the operator for a new package, whose digest
  reaches you over another channel. A failed PR-2 only says that the SHA-256
  of the archive differs from the value given: re-read the digest you
  received before concluding that the package is not the announced one.
  After a failed PR-2, a second run without `--empreinte` can locate the
  difference (PR-3 to PR-9 then run; PR-8 names the file at fault): attach
  its `--json` report to your report. It does not change the decision: the
  package stays refused until you hold an archive whose SHA-256 equals the
  digest you received, re-read.

## What the result proves, and what it does not

- "Package intact" says that the files are those the manifest describes,
  byte for byte. It does not say who made the package: only the digest
  received over another channel (`--empreinte`) ties this package to its
  sender.
- "VALID" for a dossier repeats the statement of the verifier (CT-6), which
  is worth only what the anchors used are worth. Anchors taken from the
  package are the operator's until you have compared them with yours.
- The scope attestation is declared by its signatories, not proven.
- The package proves nothing about events it does not contain: it does not
  say that the list of dossiers is complete.

## Safety

Never extract a package with `tar -P` or into a directory that already holds
files. The tool refuses links, absolute names, names that contain `..`,
duplicates and any file the manifest does not declare.
```

### 13.12 Remise et conservation

**EX-13.37** La remise suit ces pas :

1. avant le paquet, l'exploitant publie au réviseur les pièces de CT-5
   §10.2 et le manifeste d'instance (CT-4 §4.8) ; le réviseur prépare son
   fichier d'ancres (CT-6 §12.5) et le remet, ou en remet le SHA-256 s'il
   préfère n'employer que `--ancres` ;
2. l'exploitant construit le paquet (13.5) et le vérifie par l'outil de 13.7
   (code 0 attendu, sauf si la demande porte sur un dossier invalide) ;
3. il remet l'archive par un canal, et son SHA-256 par un autre (message
   signé, courrier, lecture à voix haute) ; le réviseur passe ce SHA-256
   par `--empreinte` ;
4. il consigne la remise au journal des consultations et des accès
   (section 11, PA-15 de CT-7) : une ligne d'action `export` par paquet, qui
   nomme le SHA-256 de l'archive et celui du manifeste, le destinataire par
   sa fonction et le motif par un identifiant de dossier ;
5. il DEVRAIT conserver l'archive remise et son empreinte avec le journal,
   pour la durée de rétention de celui-ci (CT-7 §8) ;
6. le réviseur conserve le rapport `--json` de sa vérification.

**EX-13.38** Le réviseur qui veut la garantie la plus forte : (a) tient l'outil
du dépôt public (celui dont la note de version donne l'adresse et le commit,
EX-3.14) à une version publiée, ou contrôle la copie jointe par la liste
`SHA256SUMS` publiée (EX-13.22) ; (b) donne `--empreinte` ; (c) donne son propre
fichier d'ancres par `--ancres`. Le résumé dit lesquelles de ces trois
précautions ont été prises : PR-2 réussie ou non exécutée, PR-11, et la
provenance des ancres de chaque dossier.

## 15. Ce que cette version ne couvre pas

- **Les images elles-mêmes.** Les images `noortrace/*` ne sont pas construites ;
  leur conformité à leur description (compte, racine en lecture seule, sondes)
  est une épreuve de construction (EX-4.4, CT-9).
- **Les manifestes d'un orchestrateur** (ressources Kubernetes et équivalents) :
  la topologie « tenant cloud » est décrite avec les fichiers Compose ; une
  adaptation garde les exigences de la section 4 et d'EX-3.10.
- **Un processus distinct pour le composant d'ancrage** (EX-3.2) et **le serveur
  RFC 3161 interne** comme service de référence (CT-5 §7 ; flux FL-21
  seulement).
- **La console d'exploitation** de la phase 2 (CT-3 §13.15) ; seul le serveur de
  la console de référence est déployé.
- **L'exploitation d'un nœud Bitcoin** pour la source d'en-têtes (CT-5 §15) ; le
  flux FL-20 vaut quand le client en a un.
- **La publication du manifeste d'instance et l'exploitation des validateurs**
  par l'exploitant NOORTRACE (CT-4 §1, §10.2) : hors du déploiement chez un
  client.
- **Les commandes d'installation du moteur de conteneurs propres à chaque
  distribution** : un script de préparation de l'hôte, à écrire (phase 2) et
  absent de l'archive 0.1, sera éprouvé par CT-9 sur le système de référence
  que CT-9 fixe (IC-2, non vérifié ici).
- **Plusieurs supports WORM.** L'enregistreur 0.1 ne copie que vers un
  support (`storage.seal.worm`) : `copies` > 1 ne sert qu'à dimensionner un
  second support (9.1), dont CT-8 ne décrit ni l'alimentation ni la création ;
  la perte d'un support entier n'est couverte par aucun runbook (RB-5 couvre
  des objets, des verrous et des gels).
- **La reprise avec un magasin de bail `etcd` neuf** : son époque est la
  révision de la grappe, qui ne se règle pas ; le chemin A, pas 6, ne décrit
  pas comment la faire dépasser l'époque la plus haute du journal restauré.
- **Supervision et observabilité outillées** : les fichiers de
  `deploiement/observabilite/`, `extraire-journaux.mjs`, `regles.mjs`,
  `sonde.mjs`, la famille `supervision/` et SV-1 à SV-7 sont à produire, lot
  suivant (section 10) ; d'ici là, le client transcrit les règles (IC-16).
- **Outil de sauvegarde.** Aucun outil ne crée l'archive de sauvegarde ni le
  procès-verbal `sauvegarde`, et aucun ne contrôle la forme de l'archive
  (EX-11.2) ; au chemin A, pas 6, aucune commande n'est donnée pour remplir
  un volume nommé neuf en gardant les octets, le compte et les droits.
- **Borne de durée d'une écriture lente** : CT-2 0.6 ne fixe aucune durée
  au-delà de laquelle une écriture lente vaut panne ; en mode observation,
  elle retarde l'appel sans borne écrite (EX-12.5).
- **Un mandataire sortant** pour l'enregistreur (EX-5.5, PD-3).
- **Toute durée et toute capacité des sections 10 à 12** : RPO, RTO, durée
  d'une restauration, latence ajoutée en mode observation, seuil de la
  mempool ; ce sont des cibles, à mesurer à la porte 2 (CT-9) quand
  l'enregistreur, le service d'approbation et le composant d'ancrage
  existeront.
- **L'exécution des règles de supervision** : `promtool` n'a pas été exécuté
  pour cette version (R8 NV-4) ; l'intégration continue l'exécutera quand le
  fichier de règles sera produit (EX-10.10).
- **Le journal d'accès aux objets de chaque support WORM** : sa disponibilité,
  son activation et son format chez chaque fournisseur ne sont pas vérifiés ;
  CT-9 les établit avant que la source `journal_acces_support` (EX-11.19)
  soit tenue pour acquise.
- **La signature des procès-verbaux d'exploitation** : CT-8 en fixe le
  contenu et la copie WORM, non le procédé de signature, qui relève du
  client (EX-11.13).
- **Les noms de membres de `data`** de plusieurs lignes de journal (PD-10,
  PD-11) : l'extracteur de 10.3 les lira sous les noms que CT-2 et CT-5
  fixeront.
- **La taille exacte de la mempool** : `eth_getBlockTransactionCountByNumber`
  (`"pending"`) ne dit pas s'il compte les transactions non prêtes (R8
  NV-3).
- **La copie du journal d'exploitation par l'écrivain** (CT-7 PA-18) : non
  adoptée ; la copie est faite par une tâche hors du démon (EX-11.22).
- **Signature du paquet.** Le manifeste n'est pas signé ; l'origine du
  paquet ne s'établit que par l'empreinte remise par un autre canal
  (EX-13.37). Une signature du manifeste par une clé de l'exploitant
  inscrite à la cérémonie de CT-7 est une piste pour une version ultérieure
  du format.
- **Binaire Go dans le paquet.** Le paquet de version 0 ne porte que
  l'implémentation de référence JavaScript du vérificateur (EX-13.23).
- **Pièces fournies à part.** Les contenus dont les dossiers ne portent que
  l'empreinte (CT-6 EX-4.6) ne sont pas dans le paquet (EX-13.10).
- **Paquet compressé.** Non défini en version 0 (EX-13.16).
- **Systèmes du réviseur.** L'outil n'a été exécuté que sous Linux, avec
  Node.js v22.22.0 ; Windows, macOS et les autres versions de Node.js ne
  sont pas vérifiés.
- **Les installations elles-mêmes.** Ni l'installation rapide ni l'installation
  complète n'ont été exécutées : l'enregistreur, le service d'approbation et le
  composant d'ancrage ne sont pas construits. Leurs budgets de temps (900
  secondes, 450 minutes) sont des cibles, à mesurer à la porte 2 (CT-9) ; le
  critère du plan (moins d'une journée, sur une machine vierge, avec le seul
  document) n'est pas encore mesuré.
- **Un mode « avertir ».** En mode observation, l'agent ne reçoit aucun
  avertissement de ce que la politique aurait exigé ; un mode qui rendrait
  l'appel avec un avertissement lisible par l'agent, sans le bloquer (pratique
  `warn` d'un contrôleur d'admission, R9-F48, R9-F53), est une proposition pour
  une version ultérieure (CT-2 §21, CT-3 §16).

## 16. Alignement avec le dépôt et propositions

### 16.1 Alignement

Points du dépôt que CT-8 complète ou rend caducs, avec l'état attendu. Les
fichiers racine (`README.md`, `README.fr.md`, `ARCHITECTURE.md`, `CHANGELOG.md`,
`NOTICE`) sont alignés hors du texte de la spécification, dans la même
livraison.

| Élément | Avant | Après | État |
|---|---|---|---|
| CT-2 | version 0.5 ; deux modes d'attente bloquants | révision 0.6 minimale : valeur `observation`, CT-2 EX-4.51, EX-7.23 (formes réservées, 998 caractères), EX-14.13 à EX-14.17, EX-15.8 (suffixe `-observation`, `approbateurs_de_test`), EX-17.8 ; schéma `configuration-enregistreur-v0` étendu de façon compatible ; table « Révision 0.6 » de CT-2 §22 | fait (même livraison) |
| CT-3 | version 0.3 ; évaluation toujours suivie de ses effets | révision 0.4 minimale : CT-3 EX-6.8, EX-11.11 à EX-11.15, EX-12.20 ; exception d'EX-11.1 pour l'installation rapide ; nom `evaluation impossible` réservé dans `politique-approbation-v0` (aucun document des vecteurs ne le porte) | fait (même livraison) |
| CT-7 §11, ligne PA-15 | « à faire (révisions à décider ; CT-8 à écrire) » | répondue par 11.6, 11.9, 11.10 et 11.11 ; L-1 reste `releve_du_client` pour la collecte | à aligner par l'éditeur de CT-7 (texte de CT-7 inchangé dans ce lot) |
| `spec/README.md` | CT-8 « à écrire » ; CT-2 0.5 ; CT-3 0.3 | lignes CT-8 (0.1), CT-2 (0.6) et CT-3 (0.4) ; huit schémas nouveaux ; section « CT-8 (`vecteurs/ct-8/`) » | fait (même livraison) |
| `spec/schemas/` | — | `conteneurs-v0`, `controle-prealable-v0`, `dimensionnement-v0`, `proces-verbal-exploitation-v0`, `consultation-v0`, `verification-journal-v0`, `rapport-observation-v0`, `paquet-reviseur-v0` ; `configuration-enregistreur-v0` étendu ; `politique-approbation-v0` : nom réservé | fait (même livraison) |
| `deploiement/` | absent | `LISEZMOI.md`, `compose/rapide.yaml`, `compose/production.yaml`, `images/images.json`, `config/rapide/configuration.json`, `config/modele-production/configuration.json` (4.1) ; `observabilite/` (10.4 à 10.8) | fait (même livraison), sauf `observabilite/` : à produire, lot suivant |
| `scripts/deploiement/`, `scripts/lib/deploiement.mjs`, `scripts/lib/exploitation.mjs` | absents | contrôle préalable, configuration rapide, dimensionnement, vérification des conteneurs, renvois, archive de déploiement ; marque, rapport d'observation, vérification de journal, procès-verbaux, consultations (annexes A.2 à A.9) ; extracteur, règles, sonde | fait (même livraison), sauf l'extracteur, les règles et la sonde : à produire, lot suivant |
| `scripts/lib/paquet.mjs`, `scripts/paquet-reviseur/` | absents | outils de construction et de vérification du paquet réviseur et instructions (13.5 à 13.7, 13.11 ; annexe A.11) | fait (même livraison) |
| `scripts/lib/approbation.mjs` | évaluation avec effets | fonction ajoutée `evaluerObservation` (CT-3 EX-11.12), sans changer `evaluer` ; règles de la révision 0.6 de CT-2 (suffixe `-observation`, `approbateurs_de_test`, noms réservés, longueur de la règle) | fait (même livraison) |
| `spec/vecteurs/ct-8/` | absent | familles de l'annexe A.1, vérificateur Go indépendant, confrontation tierce | fait (même livraison), sauf la famille `supervision/` : à produire, lot suivant |
| `package.json` | — | scripts `vecteurs:ct8`, `deploiement:conteneurs`, `deploiement:renvois`, `deploiement:dimensionner`, `deploiement:controle`, `deploiement:archive`, `exploitation:verifier-journal`, `exploitation:rapport-observation`, `exploitation:proces-verbal`, `exploitation:consultations`, `paquet:construire`, `paquet:verifier` ; `js-yaml` 4.3.2 en dépendance de développement (PD-9) | fait (même livraison) |
| `.github/workflows/ci.yml` | — | étapes de l'annexe A.14 et de A.15 | écrites (même livraison) ; non exécutées par un exécuteur d'intégration continue à la date de CT-8 0.1 (EX-A.29) |
| `NOTICE` | — | un paquet complet redistribue `ethers` (licence MIT) avec sa licence (EX-13.21) | à décider avec les fichiers racine |

### 16.2 Propositions

Propositions de CT-8 à d'autres spécifications ou au dépôt, sans les
modifier. PD-10 à PD-12 sont posées en 10.10 (EX-10.12), PD-13 à PD-15 en
11.12 ; la table les reprend en une ligne. Les pas qui emploient une commande
de PD-2 (`noortrace-ctl sonde`, `dossier exporter`, `etat`, `worm restaurer`,
`cle rotation-urgence` : IR-8, IC-15, EX-10.14, runbooks, 11.4) ou un fichier
de configuration de PD-7 (service d'approbation et serveur de console, IC-11)
dépendent de ces propositions : tant que CT-2 et CT-3 ne les ont pas
adoptées, ce sont des exigences de construction (phase 2), non des commandes
exécutables.

| Id | Destinataire | Proposition | État |
|---|---|---|---|
| PD-1 | CT-2 §22 (ligne CT-8), CT-7 §11 (ligne PA-15), `spec/README.md` (ligne CT-8) | Mettre à jour l'état « CT-8 à écrire » : CT-8 0.1 répond (table de 0.2) | fait pour CT-2 (table de la révision 0.6) et `spec/README.md` ; à faire par l'éditeur de CT-7 |
| PD-2 | CT-2 (§15.6, §18.1) | Commandes de `noortrace-ctl` employées par les procédures et absentes de CT-2 : `sonde --url <url>` (sonde en forme `CMD` des fichiers Compose, image sans interpréteur, CO-12) ; `dossier exporter --seq <n> \| --dernier --vers <rép>` (IR-8, IC-15) ; `etat`, `worm restaurer` et `cle rotation-urgence` (EX-10.14) | proposition |
| PD-3 | CT-2 §15 | Un mandataire sortant pour les connexions du démon, désigné dans la configuration, sans interception TLS (EX-5.5) | proposition |
| PD-4 | CT-2 §4.7.1, §15 | Un transport stdio par prise locale vers un serveur lancé par l'orchestrateur, qui garderait la vérification d'`integrity` par le démon (EX-3.8) | proposition |
| PD-5 | CT-2 §15.3, §18.1 | Écrire, dans l'exemple ou dans une note, l'écoute `0.0.0.0` dans un conteneur dont les ports ne sont publiés que sur `127.0.0.1` ou l'adresse interne, et ce qu'en dit la validation (TLS exigé hors bouclage pour `otel`, CT-2 EX-6.40) | proposition |
| PD-6 | CT-2 §18.3 | Noms des comptes : `peer_user` désigne un nom ; les images NOORTRACE fixent les UID 10001 et 10002 et leurs noms (EX-3.5) | proposition (note) |
| PD-7 | CT-3 §10.3 | Un schéma de configuration du service d'approbation et du serveur de console (réglages de CT-3 EX-10.10), dont IC-11 a besoin pour être validé comme la configuration de l'enregistreur | proposition |
| PD-8 | `chain/docker/Dockerfile`, `chain/docker/docker-compose.yml`, `chain/docker/README.md` | Épingler les deux images de base par condensé (déjà « à faire », CT-4 §13) ; remplacer le domaine d'exemple `rpc.exemple.ch` par un nom réservé de la forme `.example` (non vérifié qu'il soit réservé, R8 NV-8) | à faire (autre lot) |
| PD-9 | `package.json` | Déclarer `js-yaml` en dépendance de développement à version exacte (4.3.2, déjà installée comme dépendance transitive) pour `verifier-conteneurs.mjs` | fait (même livraison) |
| PD-10 | CT-2 (§17.3, EX-9.5) | Fixer les noms des membres de `data` de plusieurs lignes du journal d'exploitation et nommer la ligne de `politique_invalide` au `charger` (10.10) | proposition |
| PD-11 | CT-5 (§8.9) | Nommer les lignes `jeton_anterieur_au_point` et `contresignature_tardive` et les membres de `data` de trois lignes du composant d'ancrage (10.10) | proposition |
| PD-12 | CT-4 et CT-5 | Consigner chaque refus d'envoi au registre (ligne `registry_send_refused`) (10.10) | proposition |
| PD-13 | CT-2 (EX-12.16) | Copier `journal.json` sur le support WORM (11.12) | proposition |
| PD-14 | CT-6 et l'exportateur | Écrire une ligne d'export dans un fichier en ajout seul que le collecteur de 11.10 lit (11.12) | proposition |
| PD-15 | CT-2 (§17.2) | Exposer `noortrace_worm_copy_last_success_age_s` par sorte de fichier copié (11.12) | proposition |
| PD-16 | CT-4 (EX-10.9) | Remplacer « Seule la clé est sauvegardée, hors ligne » par le renvoi à CT-7 EX-4.4 (aucune sauvegarde de la clé d'un validateur) : les deux spécifications disent le contraire ; EX-11.1 suit CT-7, plus récente et propre aux clés | proposition ; l'écart reste ouvert tant que CT-4 n'est pas révisée |

## Annexe B — Sources primaires datées

### B.1 Notes de recherche et lectures

Les faits externes de CT-8 viennent de deux notes de recherche internes du lot,
non publiées : R8 (dépôt public et noorchain-core) et R9 (pratiques publiées),
relues le 2026-10-27 sur les sources primaires qu'elles citent ; ces sources
font foi, pas les notes. Un fait porte le renvoi « R8-Fn » ou « R9-Fn » ; un
point non vérifié porte « NV-n » (R8). S'y ajoutent les lectures et les
exécutions directes de la rédaction, datées et accompagnées de leur commande.
Les parties suivantes donnent, pour chaque renvoi, l'objet du fait, la source
primaire publique ou le chemin du fichier lu, et la date de lecture. Ce qui
n'a pas pu être vérifié est écrit « non vérifié ».

### B.2 Sections 3 à 9 et annexes A.2 à A.5

| Renvoi | Objet | Source | URL ou chemin | Lu ou exécuté le |
|---|---|---|---|---|
| R8-F33 | Suiveur en conteneur : lecture seule, toutes capacités retirées, `no-new-privileges`, pas de sonde interne (image sans shell ni curl) | dépôt public | `chain/docker/docker-compose.yml`, l. 21-66 | 2026-10-27 |
| R8-F34 | Image du nœud : 67,5 Mo, `User=65532:65532` ; construction avec correctif non rejouée | dépôt public | `chain/docker/README.md`, l. 80-110 | 2026-10-27 |
| R8-F35 | Un suiveur est un mandataire JSON-RPC ; `/healthz` répond `ok` meneur arrêté | dépôt public | `chain/docker/README.md`, l. 377-407 | 2026-10-27 |
| R8-F56 | Secrets montés en fichier sous `/run/secrets/` ; risque des variables d'environnement | Docker, « Secrets in Compose » | https://docs.docker.com/compose/how-tos/use-secrets/ | 2026-10-27 |
| R8 NV-1 | Construction de l'image du nœud avec correctif : non rejouée | — | — | 2026-10-27 |
| R8 NV-8 | `rpc.exemple.ch` : non vérifié comme réservé | dépôt public | `chain/docker/docker-compose.yml`, l. 3 | 2026-10-27 |
| R9-F11 | `SOURCE_DATE_EPOCH` : horodatage des constructions | reproducible-builds.org | https://reproducible-builds.org/specs/source-date-epoch/ | 2026-10-27 |
| R9-F23 | Forme d'une référence d'image, par étiquette ou condensé | Compose Specification | https://raw.githubusercontent.com/compose-spec/compose-spec/main/spec.md (l. 1524-1537) | 2026-10-27 |
| R9-F24 | `read_only` ; `user`, `root` à défaut | idem | même fichier, l. 2090-2092, 2299-2301 | 2026-10-27 |
| R9-F25 | Accord explicite d'un secret ; `uid`, `gid`, `mode` non appliqués pour une source `file` | idem | même fichier, l. 2108-2180 | 2026-10-27 |
| R9-F26 | Secrets de premier niveau : sources `file` ou `environment`, `external` | Compose Specification | https://raw.githubusercontent.com/compose-spec/compose-spec/main/09-secrets.md | 2026-10-27 |
| R9-F27 | Volumes : `ro`, `create_host_path`, `tmpfs` borné | Compose Specification | spec.md, l. 2326-2405 | 2026-10-27 |
| R9-F28 | `healthcheck` (`CMD`, `CMD-SHELL` par `/bin/sh`, `NONE`) ; `depends_on` `service_healthy` | idem | spec.md, l. 2557-2600, 2490-2497 | 2026-10-27 |
| R9-F30 | Épingler une image de base par condensé | Docker, « Building best practices » | https://docs.docker.com/build/building/best-practices/ | 2026-10-27 |
| R9-F31 | `USER` non root à UID et GID explicites | idem | même page | 2026-10-27 |
| R9-F32 | Profils Restricted et Baseline : non root, toutes capacités retirées, pas d'escalade, pas de volume de l'hôte | Kubernetes, Pod Security Standards | https://kubernetes.io/docs/concepts/security/pod-security-standards/ | 2026-10-27 |
| R9-F33 | Le profil Restricted n'exige pas la racine en lecture seule | idem | source de la page (`grep -c readOnlyRootFilesystem` : 0) | 2026-10-27 |
| R9-F34 | `chain/docker` désigne ses images par étiquette, sans clé `user` ni `secrets` | dépôt public | `chain/docker/Dockerfile` l. 32, 96, 117 ; `docker-compose.yml` l. 29 | 2026-10-27 |
| R9-F41, R9-F42 | `chronyc tracking` : statut de saut ; borne d'erreur de l'horloge | chrony 4.6 | https://chrony-project.org/doc/4.6/chronyc.html | 2026-10-27 |
| R9-F44 | `timedatectl` : état de synchronisation | systemd | https://www.freedesktop.org/software/systemd/man/latest/timedatectl.html | 2026-10-27 |
| R9-F45 | `systemd-timesyncd` : SNTP seulement ; fichier `/run/systemd/timesync/synchronized` | systemd | https://www.freedesktop.org/software/systemd/man/latest/systemd-timesyncd.service.html | 2026-10-27 |
| R9-F47 | noorcore refuse une proposition datée de plus de 15 s dans le futur | noorchain-core, commit `618fcef` | `core/node/blockexec.go`, l. 62-67 | 2026-10-27 |
| R9-F55 | Archives publiées déterministes | dépôt public | `spec/CT-6-verificateur.md`, EX-14.8 | 2026-10-27 |
| A-L1 | Attributs `a` et `i` : `CAP_LINUX_IMMUTABLE` ; changer les attributs exige d'être propriétaire ou `CAP_FOWNER` | page de manuel `ioctl_iflags(2)` (copie locale SHA-256 `2332222a8bb9af5eecd9e8fabe58c9e935e003c21aba22e5a57d5e4e5abfb876`) | https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html | 2026-10-27 |
| A-E1 | `docker compose config --quiet` : code 0 sur les deux fichiers de référence ; code 1 sans les variables requises ; résolution des chemins relatifs avec et sans `--project-directory` | exécution, Docker Compose v5.6.0, moteur non joignable (`docker info` : code 1) | répertoire de travail de la rédaction | 2026-10-27 |
| A-E2 | `openssl genpkey -algorithm ed25519 -outform DER` : 48 octets, préfixe PKCS#8 de CT-1 §13 ; `openssl rand -hex 32 \| tr -d '\n'` : 64 octets | exécution, OpenSSL 3.0.13 | répertoire de travail de la rédaction | 2026-10-27 |
| A-E3 | Coefficients `b_pt`, `b_man`, `b_tsr_sup` ; `b_cap` (révision 0.2) | exécution, Node.js v22.22.0, sur les vecteurs du dépôt ; `b_cap` : mesure sur le réseau de développement (bloc de 64 transactions d'ancre, trois répétitions), rapport publié relu, décomposition recalculée (5 846 + 32 587 + 71 046 = 109 479 ; 109 479 + 14 282 = 123 761) | commandes d'A.5 ; `spec/vecteurs/ct-9/mesures/rapport-2026-11-02-capture-bloc-plein.json`, `scripts/e2e/mesure-capture-bloc-plein.mjs` | 2026-10-27 ; `b_cap` : mesuré le 2026-11-02, relu le 2026-11-03 |
| A-E4 | Prototype des vérifications CO- : deux fichiers conformes, vingt-trois variantes en échec chacune à sa seule vérification | exécution, `js-yaml` 4.3.2 de `node_modules` | répertoire de travail de la rédaction | 2026-10-27 |
| A-E5 | Validation des exemples et des cas contre les trois schémas nouveaux et contre `configuration-enregistreur-v0` | exécution, `ajv-cli@5`, mode strict | commandes d'A.16 | 2026-10-27 |

Points non vérifiés des sections 3 à 9 : le besoin de `DAC_READ_SEARCH` pour le
compagnon (EX-3.9) ; les noms de paquets du moteur de conteneurs par
distribution (IC-2) ; le champ `DockerRootDir` de `docker info` (IR-4, moteur
non joignable) ; l'ordre des champs de `chronyc -c tracking` (à relever sur
chrony 4.6, CT-9) ; l'architecture `arm64` des images (IP-1) ; le format `.mcpb`
(EX-3.6) ; la tenue des images à leur description, aucune n'étant construite
(EX-4.4).

### B.3 Sections 10 à 12 : faits de R8 et R9

| Renvoi | Objet | Source | Lu le |
|---|---|---|---|
| R8-F1, R8-F2 | Santé et 43 métriques de l'enregistreur | `spec/CT-2-enregistreur.md` l. 10533-10591 | 2026-10-27 |
| R8-F7 | Ports et chemins de l'exemple de configuration | `spec/CT-2-enregistreur.md` l. 9427-9651 | 2026-10-27 |
| R8-F14 | Cibles de performance non mesurées (latence, débit, reprise) | `spec/CT-2-enregistreur.md` l. 10245-10256 | 2026-10-27 |
| R8-F15 | Interface du service d'approbation, `GET <base>/v0/etat` | `spec/CT-3-approbations.md` l. 3622-3644, 3896-3899 | 2026-10-27 |
| R8-F19 | Métriques et alertes du composant d'ancrage | `spec/CT-5-ancrage.md` l. 2043-2111 | 2026-10-27 |
| R8-F21 | Ports et volumes du nœud | `spec/CT-4-registre.md` l. 3632-3644 | 2026-10-27 |
| R8-F22, R8-F23 | Validateur jamais restauré ; relais interdit pour capture et soumission, sonde par `eth_blockNumber` | `spec/CT-4-registre.md` l. 3510-3566, 3605-3630 | 2026-10-27 |
| R8-F26 | Décision ouverte 7 de l'architecture : mode observateur de noorcore | `ARCHITECTURE.md` l. 531-536 ; `spec/CT-4-registre.md` l. 3787-3792 | 2026-10-27 |
| R8-F35 | Le suiveur est un mandataire JSON-RPC sans état propre | `chain/docker/README.md` l. 377-407 | 2026-10-27 |
| R8-F37 | Ports du réseau de développement | `chain/scripts/dev-net.sh` | 2026-10-27 |
| R8-F39 | Nature et structure des runbooks de noorchain-core | noorchain-core, `docs/runbooks/INDEX.md` l. 5-16 (tête `618fcef8805ef5b4cb9291a3dd97be710e489297`) | 2026-10-27 |
| R8-F40, R8-F41 | Runbook d'exploitation M27D (déploiement, sauvegarde avec manifeste, chemins A et B, alertes, playbooks, après-incident) ; restaurations du `-data-dir` en M27E et M35 | noorchain-core, `docs/runbooks/RUNBOOK-M27D-OPS.md` l. 1-345 ; `RUNBOOK-M27E-BACKUP-RESTORE-DRILL.md` ; `RUNBOOK-M35-BACKUP-RESTORE-DR.md` | 2026-10-27 |
| R8-F42 | Gabarit d'observabilité de noorchain-core : collecte, règles système, `NoorcoreTargetDown`, tableau à trois panneaux | noorchain-core, `ops/observability/prometheus/prometheus.yml` l. 1-29 ; `alerts/noorcore.rules.yml` l. 1-52 ; `grafana/dashboards/noorcore-system-dashboard.json` | 2026-10-27 |
| R8-F43 | Noms réels des métriques de noorcore (`noor_*`) | noorchain-core, `core/metrics/metrics.go`, `core/metrics/snapshot.go` | 2026-10-27 |
| R8-F44 | Taille de la mempool lisible seulement par `eth_getBlockTransactionCountByNumber("pending")` | noorchain-core, `core/rpc/jsonrpc_dispatch.go` l. 2147-2152 | 2026-10-27 |
| R8-F45 | Drapeaux de `noorcore -h`, dont `-metrics-addr` et `-txpool-max-pending` (exécution réelle, code 0) | `chain/runtime/bin/noorcore -h` | 2026-10-27 |
| R8-F47 à R8-F49 | Aucun mode d'évaluation sans blocage dans CT-1 à CT-3 ; modes d'attente bloquants ; contraintes de `policy` de CT-1 | `spec/CT-2-enregistreur.md`, `spec/CT-3-approbations.md`, `spec/schemas/evenement-v0.schema.json` | 2026-10-27 |
| R8-F53, R8-F54 | `promtool test rules` ; clause `for` des règles d'alerte | https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/ ; https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/ | 2026-10-27 |
| R8 NV-3, NV-4, NV-5 | Composition de `PendingSnapshot()` non établie ; `promtool` absent ; cibles 6260 et 6262 jamais vues en écoute | non vérifié | 2026-10-27 |
| R9-F12 | Archive ustar reproductible avec GNU tar 1.35 (mesure : même SHA-256 pour deux arbres) | mesure de R9 | 2026-10-27 |
| R9-F13, R9-F14, R9-F16, R9-F22 | Extraction d'une archive non fiable : répertoire neuf ; refus mesurés de GNU tar 1.35 et de `tarfile` de Python 3.13.16 | https://www.gnu.org/software/tar/manual/html_node/Integrity.html ; https://www.gnu.org/software/tar/manual/html_node/Live-untrusted-data.html ; mesures de R9 | 2026-10-27 |
| R9-F35, R9-F36 | Définitions de RTO, RPO, MTD ; RTO plus court que la MTD | NIST SP 800-34 Rev. 1, §3.2.1 et glossaire, https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-34r1.pdf (SHA-256 du fichier lu `476f04d4c60b0770c1ac8b2720551972074ce78e936a3e7a535048416111d0df`) | 2026-10-27 |
| R9-F37, R9-F38, R9-F39 | Fréquence et stockage hors site des sauvegardes ; essai de restauration sur une autre plate-forme ; contrôle CP-9 (intégrité par condensés) | même document, §3.4.2, §3.5.1, annexe CP-9 | 2026-10-27 |
| R9-F40 | Règle 3-2-1 | US-CERT, « Data Backup Options », 2012, https://www.cisa.gov/sites/default/files/publications/data_backup_options.pdf (SHA-256 `dd87cf959d4a68da37cb5393ad0648fc2ad4eb090534138144b4eb7e15930450`) | 2026-10-27 |
| R9-F41, R9-F44, R9-F46 | `chronyc tracking` ; `timedatectl` ; état noyau « non synchronisée » mesuré par `adjtimex(2)` | https://chrony-project.org/doc/4.6/chronyc.html ; https://www.freedesktop.org/software/systemd/man/latest/timedatectl.html ; mesure de R9 (en-tête du noyau `linux/timex.h` l. 174, 194, 199) | 2026-10-27 |
| R9-F48, R9-F49, R9-F51, R9-F53 | Actions `deny`, `dryrun`, `warn` d'un contrôleur d'admission ; `validationActions` ; modes `enforce`, `audit`, `warn` | https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/website/docs/violations.md ; https://raw.githubusercontent.com/kubernetes/website/main/content/en/docs/reference/access-authn-authz/validating-admission-policy.md ; https://raw.githubusercontent.com/kubernetes/website/main/content/en/docs/concepts/security/pod-security-admission.md | 2026-10-27 |
| R9-F54 | Le terme « point d'observation » est déjà pris par CT-2 | `spec/CT-2-enregistreur.md` l. 568 | 2026-10-27 |

### B.4 Sections 10 à 12 : lectures et mesures directes

| Objet | Source, commande | Date |
|---|---|---|
| Discipline « 1 commande → 1 gate », chemins de reprise, playbooks d'incident, après-incident, modèle de paquet de preuves | noorchain-core, `docs/runbooks/RUNBOOK-M27D-OPS.md` l. 24-34, 124-142, 220-248, 283-341, 576-606, lu | 2026-10-27 |
| Règles système et règle de cible muette reprises | noorchain-core, `ops/observability/alerts/noorcore.rules.yml` l. 11-43, lu | 2026-10-27 |
| Marge de rétention calculée et signalée par l'outil du registre | `scripts/registre/noortrace-registre.mjs` l. 755-761, 2013, lu | 2026-10-27 |
| Options du vérificateur de dossier | `scripts/verify/README.md` l. 374-417, lu | 2026-10-27 |
| Identifiant de ticket unique après perte d'état (préfixe d'époque) | `spec/CT-3-approbations.md`, EX-7.1, lu | 2026-10-27 |
| Défauts des seuils (`warn_skew_ms`, `max_backstep_ms`, `max_forward_ms`, `inclusion_alert_s`, `anchor_pending_alert_s`, `give_up_after_s`) | `spec/CT-2-enregistreur.md` l. 5101-5139 ; `spec/CT-5-ancrage.md` l. 659-665, 750-755 | 2026-10-27 |
| Nombre de lignes de la table des alertes de CT-2 §17.4 : 29 | `awk 'NR>=10679 && NR<=10709' spec/CT-2-enregistreur.md \| grep '^\| ' \| grep -v '^\| Alerte\|^\|---' \| wc -l` | 2026-10-27 |
| Archive de Prometheus 3.5.0 pour Linux amd64 : SHA-256 `e811827af26d822afb09a4f28314f61b618b12cff5369835a67f674d8b46f39a`, égal à la ligne de `sha256sums.txt` publiée avec elle ; `promtool` non exécuté | `curl -sSL -o prometheus.tar.gz https://github.com/prometheus/prometheus/releases/download/v3.5.0/prometheus-3.5.0.linux-amd64.tar.gz ; sha256sum prometheus.tar.gz` ; `curl -sSL https://github.com/prometheus/prometheus/releases/download/v3.5.0/sha256sums.txt \| grep linux-amd64` | 2026-10-27 |
| Valeurs d'exemple des sections 11 et 12 (empreintes d'ensembles de politique, sept événements signés, segment, rapport, procès-verbaux, consultations) ; chaîne vérifiée par `verifierChaine` ; blocs annotés validés par `ajv-cli` 5 en mode strict | script de calcul de la rédaction, bibliothèques `scripts/lib/journal.mjs`, `capture.mjs`, `approbation.mjs`, clé de test `rec-test-01` (CT-1 §13) ; deux exécutions identiques | 2026-10-27 |
| Empreinte de l'ensemble de politique de CT-2 §15.3 recalculée par `empreinteEnsemblePolitique` : `0xd68bb713d14538549a347529a1f927a13ceffd444b351fe1b644242b2574e75c`, égale à la valeur imprimée par CT-2 (deux occurrences) | `grep -c` sur `spec/CT-2-enregistreur.md` | 2026-10-27 |

Non vérifié pour les sections 10 à 12 : la validité des règles par
`promtool` (EX-10.10, exécutée en intégration continue) ; la disponibilité et
le format du journal d'accès aux objets de chaque support WORM (EX-11.19) ;
toute durée de sauvegarde, de restauration ou de reprise, et la latence
ajoutée en mode observation (cibles, CT-9) ; les révisions plus récentes de
NIST SP 800-34 ; ISO 22301 et ISO/IEC 27031, non consultées (R9, section 2).

### B.5 Section 13 et annexes A.10, A.11 et A.15

Les faits R9-Fn viennent de la note de recherche R9 du lot CT-8 (interne,
non publiée), relue le 2026-10-27 sur les sources primaires qu'elle cite ;
ces sources font foi, pas la note.

| Renvoi | Objet | Source primaire, date de consultation |
|---|---|---|
| R9-F1, R9-F2, R9-F3, R9-F4 | Formats d'écriture de pax ; disposition ustar en blocs de 512 octets, fin par deux blocs nuls ; limites de nom (préfixe et nom, 256 caractères) et de lien ; en-tête `mtime` étendu seulement pour une date non représentable | The Open Group Base Specifications Issue 8, IEEE Std 1003.1-2024, pax : https://pubs.opengroup.org/onlinepubs/9799919799/utilities/pax.html ; 2026-10-27 |
| R9-F5, R9-F6 | Options de GNU tar pour une archive reproductible ; avec des dates entières, une sortie ustar | Manuel GNU tar, « Making tar Archives More Reproducible » : https://www.gnu.org/software/tar/manual/html_node/Reproducibility.html ; 2026-10-27 |
| R9-F7 | Sens de `--sort`, `--mtime`, `--numeric-owner`, `--owner`, `--format` | https://www.gnu.org/software/tar/manual/html_node/Option-Summary.html ; 2026-10-27 |
| R9-F8 | Limites du format ustar selon GNU tar (255 octets de nom, 8 Gio, dates < 2³³, identifiants < 2²¹) | https://www.gnu.org/software/tar/manual/html_node/Formats.html ; 2026-10-27 |
| R9-F9 | GNU tar 1.35 installé : format par défaut `gnu`, facteur de blocage 20 | mesure de la note : `tar --version`, `tar --show-defaults` ; 2026-10-27 |
| R9-F10 | Préférence pour ustar quand la portabilité compte ; propriétaires 0/0 et `--numeric-owner` ; tri en locale C | reproducible-builds.org, « Archive metadata » : https://reproducible-builds.org/docs/archives/ ; 2026-10-27 |
| R9-F11 | `SOURCE_DATE_EPOCH` : entier ASCII, date bornée | https://reproducible-builds.org/specs/source-date-epoch/ ; 2026-10-27 |
| R9-F12 | Deux arbres de dates et de modes différents donnent la même archive ; `--format=posix` et `--format=ustar` identiques, sans en-tête pax | mesure de la note, GNU tar 1.35 ; 2026-10-27 |
| R9-F13, R9-F14, R9-F15 | Extraction d'une archive non fiable : répertoire neuf et vide, refus par défaut d'écrire hors du répertoire de travail, dangers de `-P` et `-h` ; course sur lien symbolique | https://www.gnu.org/software/tar/manual/html_node/Integrity.html ; https://www.gnu.org/software/tar/manual/html_node/Live-untrusted-data.html ; Option-Summary.html ; 2026-10-27 |
| R9-F16 | GNU tar 1.35 face à quatre archives piégées : nom absolu ramené sous la destination, `..` refusé, lien symbolique créé, lien physique extérieur refusé | mesure de la note ; 2026-10-27 |
| R9-F17, R9-F18, R9-F19 | Filtres d'extraction de `tarfile` (`fully_trusted`, `tar`, `data`), leurs refus, conseils (répertoire neuf, pas de lien, noms confondus par la casse, doublons) | https://docs.python.org/3/library/tarfile.html ; 2026-10-27 |
| R9-F20 | Calendrier du filtre par défaut (PEP 706) | https://peps.python.org/pep-0706/ ; 2026-10-27 |
| R9-F21, R9-F22 | `tarfile` écrit en pax par défaut ; Python 3.13.16 sans filtre écrit hors de la destination, `data` refuse les trois cas dangereux, `tar` accepte un lien physique extérieur | documentation de `tarfile` ; mesure de la note ; 2026-10-27 |
| R9-F55 | Le dépôt exige déjà des archives publiées déterministes | `spec/CT-6-verificateur.md`, EX-14.8 (présent dépôt) |

Lectures et mesures directes de la rédaction de la section 13
(2026-10-27 ; les lignes qui citent les archives ont été remesurées le
2026-11-01, après la révision des instructions de 13.11) :

| Objet | Commande ou fichier | Résultat |
|---|---|---|
| Champs d'un en-tête écrit par GNU tar 1.35 avec `--format=ustar --owner=0 --group=0 --numeric-owner --mode=0644` | `od -A d -c -N 512` de l'archive | `mode` `0000644\0`, `uid` et `gid` `0000000\0`, `chksum` six chiffres puis NUL et espace, `uname`, `gname`, `devmajor`, `devminor` nuls : la table d'EX-13.14 |
| Recette d'EX-13.15 | `cmp` de l'archive de GNU tar et de celle de l'outil | identiques pour `valide.tar` (296 960 octets, SHA-256 `0x8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982`) et pour le paquet complet de 13.5 (exemple daté : 2 314 240 octets, SHA-256 `0x7c2ef76e2f1ea147fd9483ce61a394fe285581c3d83ad226e15aae91c5c38e67`, valeurs qui changent avec le code joint) |
| Déterminisme de l'outil | deux constructions du paquet complet (`cmp`) ; deux générations des vecteurs | mêmes octets |
| Copie jointe hors réseau | paquet complet extrait par `tar -xkf` hors du dépôt ; `unshare -n env -i TMPDIR=<rép> node <extrait>/paquet-reviseur/verificateur/scripts/paquet-reviseur/verifier.mjs <paquet> --empreinte <sha256> --json` en superutilisateur ; la même commande avec `unshare -rn`, en superutilisateur | code 0 ; PR-2 réussie ; PR-11 `non_execute`, raison `auto_comparaison` (EX-13.22) ; trois dossiers valides ; répertoire temporaire vide après l'exécution |
| `dist/ethers.js` | `sha256sum`, `grep -n "^import\|^export"` | 1 023 273 octets, SHA-256 `0x98ef38ca12d3a7829eb2d8398e033434fe521b7a1873427e77f2eb5e8513f761` ; aucune ligne `import` en tête de ligne, une seule déclaration `export { … }` (ligne 26618), qui exporte 194 noms ; les autres lignes qui commencent par `export` sont dans des commentaires (`explode_cp`, `CustomBlockNetworkPlugin` et `follow` ne sont pas exportés : `import()` du fichier) |
| Version et intégrité d'`ethers` | `package-lock.json`, entrée `node_modules/ethers` | version 6.17.0, `resolved` sur le registre npm, `integrity` sha512 de l'archive npm ; l'identité de `dist/ethers.js` avec le fichier de l'archive du registre n'a pas été vérifiée (non vérifié) |
| Dépendances des outils | `grep` des `import` de `scripts/verify/dossier.mjs` et de `scripts/lib/*.mjs` | `ethers` seule dépendance tierce, importée par `journal.mjs`, `securite.mjs`, `registre.mjs`, `certificat-commit.mjs` |
| Membres lus par les outils tiers | test « sorties publiées » de `test/confrontation.test.js` : listes de `gnutar.txt` et de `tarfile.txt` contre la lecture de l'outil | mêmes membres, un à un, pour les treize archives (nom, type, taille, mode, propriétaires, date, lien) : 0 écart |
| Validation des exemples | `npx --yes ajv-cli@5 validate --spec=draft2020 --strict=true` | les quatorze blocs annotés de CT-8 (manifeste, description, rapport, cas, procès-verbaux, consultation, événement, rapport d'observation, observations, conteneurs, dimensionnement) : `valid` |
| Environnement | `node --version`, `tar --version`, `python3 -I -c "import sys; print(sys.version)"` | v22.22.0 ; GNU tar 1.35 ; Python 3.13.16 |

Non vérifié : le comportement de l'outil sous Windows et macOS et avec
d'autres versions de Node.js ; d'autres versions de GNU tar et de Python ;
l'exécution sans privilège `unshare -rn` (essayée en superutilisateur
seulement) ; l'identité de
`dist/ethers.js` avec le fichier de l'archive npm publiée ; le temps qu'un
réviseur met à vérifier un paquet (à mesurer, CT-9, porte 2).
