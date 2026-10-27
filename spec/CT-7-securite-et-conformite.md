# CT-7 — Sécurité et conformité

Version 0.1, 2026-10-26 (première rédaction). Spécification normative,
soumise à la revue de la porte 1 du plan de projet (document interne). Elle
répond, un par un, aux renvois que CT-1 à CT-6 font à CT-7 (table de
traçabilité, section 0.2) : la revue de sécurité de NOORTRACE, composant par
composant (section 3) ; l'inventaire des clés et des secrets (section 4) ; la
cérémonie des clés et son procès-verbal vérifiable hors ligne (section 5) ; le
journal de l'enregistreur sur lui-même (section 6) ; l'attestation de
périmètre (section 7) ; la matrice de conformité (section 8). Elle accompagne
la révision 0.4 de CT-1 et la révision 0.3 de CT-6, qui ajoutent au dossier
la partie facultative `attestation-perimetre.json`. Elle ne change aucun
format figé de CT-1 v0 (événement, manifeste, objet `A`, `D_A`, signature
EIP-191 version `0x45`), ni CT-2 à CT-5, ni leurs vecteurs : ce qu'elle leur
demande est écrit comme proposition (sections 6.2, 6.3 et 8.11).

Son critère d'acceptation est celui du plan : une revue adversariale interne
où chaque menace a une réponse écrite et où aucune faille ne reste ouverte
sans réponse ; un risque accepté est une réponse s'il est nommé, borné et
attribué (3.5). La parité s'y écrit en exigences mesurables (EX-7.18,
section 8.7), sans référence à un produit. CT-7 établit des correspondances
techniques entre des textes et des pièces de preuve : ce n'est pas un avis
juridique, et rien n'y dit qu'un client est conforme (section 8).

## 0. En-tête et conventions

### 0.1 Conventions

Les mots DOIT, NE DOIT PAS, DEVRAIT et PEUT ont le sens de la RFC 2119, comme
dans CT-1 à CT-6. Un DOIT adressé au client (EX-8.12, EX-8.13, EX-8.15, EX-8.18,
par exemple) est une exigence de la spécification au sens de la RFC 2119 : la
condition pour que la pièce citée produise l'effet décrit. Il ne crée aucune
obligation juridique ou contractuelle tant qu'un contrat ne le reprend pas. Le
choix de l'instrument qui reprend une telle exigence (contrat avec l'exploitant
NOORTRACE, contrat d'hébergement, directive interne, par exemple) relève du
client et de ses conseils ; CT-7 ne le désigne pas.

Chaque règle normative porte un identifiant **EX-<section>.<n>** (EX-5.8 :
huitième règle de la section 5), stable, auquel le plan de tests (CT-9)
attache ses tests. Les identifiants sont numérotés dans l'ordre du texte à
l'intérieur de chaque section de premier niveau, sous-sections comprises.
Une règle ajoutée par une révision reçoit le numéro qui suit le plus grand de
sa section ; aucun numéro n'est réattribué ; une règle retirée garde son
numéro, marqué « retiré ».

Un renvoi à une autre spécification s'écrit toujours avec elle : « CT-2
EX-18.1 », « CT-1 §10.9 », « CT-6 T-7 » (vérification d'une famille,
définie comme première cellule d'une ligne de table de la spécification
citée). Dans les tables de la section 3, même un renvoi à CT-7 s'écrit
« CT-7 EX-3.10 » : le vérificateur de renvois (annexe A, RV-3) les extrait et
les résout mécaniquement.

Les clés JSON sont en anglais ; les valeurs énumérées sont en français, sans
accent (`usurpation`, `deni_de_service`, `officiant`, `partage_k_sur_n`).
Les encodages sont ceux de CT-1 §3.

CT-7 établit des **correspondances techniques** et des exigences de sécurité ;
il ne dit jamais qu'un client « est conforme » à un texte. Les formulations
admises sont « répond à », « contribue à », « ne couvre pas » et « relève du
client ».

Familles d'identifiants de CT-7 (une famille définie par une autre
spécification garde sa définition : CT-6 T-7 est une vérification du jeton,
T-3 sans préfixe un texte de la matrice) :

| Famille | Objet | Définie par |
|---|---|---|
| TR- | Renvoi d'une autre spécification à CT-7 et sa réponse | 0.2 |
| MN- | Menace du modèle de menace par composant : identifiant d'une ligne, pas une vérification | section 3 (table en 3.4, `spec/vecteurs/ct-7/menaces.json`) |
| RA- | Risque accepté : nommé, borné, attribué ; réponse écrite d'une menace dont le reste n'est pas empêché | 3.5 |
| CLE- | Ligne de l'inventaire des clés et des secrets | 4.2 |
| CR- | Vérification d'un procès-verbal de cérémonie des clés : forme, participants, chronologie, étapes, clés, classes, sauvegarde, membres, production, constats, signatures, objet | 5.8 |
| JS- | Événement obligatoire du journal de l'enregistreur sur lui-même | 6.1 |
| PA- | Proposition d'alignement adressée à une autre spécification, sans la modifier | 6.2, 6.3 et 8.11 |
| AT- | Vérification de l'attestation de périmètre, seule (AT-1 à AT-4) ou jointe à un dossier (AT-1 à AT-7) : forme, condensé, signatures, seuil, liaison au dossier, inscription au journal, politique en vigueur | CT-1 §11.4 (révision 0.4), reprises en 7.7 ; rattachement et absence d'effet sur le verdict : CT-6 §5.5 (révision 0.3) |
| T- | Texte retenu par la matrice de conformité (loi, ordonnance, règlement, circulaire, communication, recommandation), avec sa version, son URL et son applicabilité au 2026-10-26 | 8.2 |
| MC- | Ligne de la matrice : un passage cité exactement, ce qu'il exige et, élément par élément, la pièce de NOORTRACE qui y répond ou y contribue, ce qu'elle ne couvre pas et ce qui relève du client | 8.4 (`spec/vecteurs/ct-7/matrice-conformite.json`) |
| L- | Lacune de la matrice : écart nommé, borné et attribué | 8.9 |
| CL- | Modèle de clause contractuelle, à faire relire par le client | annexe C |
| RV- | Vérification du vérificateur de renvois : existence des renvois, réponse de chaque menace, égalité de la table et du fichier, rattachement des lignes sources, table de traçabilité | annexe A.10 |
| MX- | Vérification de `matrice-conformite.json` et de son identité avec les tables de CT-7 | annexe A.8 |

Les faits externes (publications du NIST, pratiques publiées de cérémonies,
règlements) viennent de deux notes de recherche du lot CT-7, R6 (réglementation)
et R7 (sécurité et cérémonies), internes et non publiées, relues le 2026-10-26
sur les sources primaires qu'elles citent. Chaque fait porte le renvoi du fait
dans sa note (« R7-F4 ») ou d'un point non vérifié. L'annexe B donne, pour
chaque renvoi, l'objet du fait, la source primaire publique, son URL et la date
de lecture. Ce qui n'a pas pu être vérifié est écrit « non vérifié ».

### 0.2 Ce que les autres spécifications délèguent à CT-7

Chaque occurrence de « CT-7 » dans `spec/*.md` au 2026-10-26 est un renvoi. La
table les reprend toutes, une ligne par occurrence, dans l'ordre des fichiers
(CT-1 à CT-6, puis `spec/README.md`) puis des lignes ; la colonne «
Spécification, section » nomme le dernier titre de niveau 2 à 4 qui précède
l'occurrence : « CT-n §s » quand ce titre commence par un numéro, son texte
entre guillemets sinon, et « en-tête » avant le premier titre. Le vérificateur
de renvois compte, spécification par spécification et section par section, les
occurrences de « CT-7 » et les lignes de cette table : une occurrence nouvelle
sans ligne, ou une ligne sans occurrence, fait échouer RV-7 (annexe A). Les
numéros de ligne sont ceux du 2026-10-27, recalculés après la dernière
modification de CT-1 à CT-6 et de `spec/README.md`, pour la lecture
seulement : RV-7 compte les occurrences par section, pas par ligne, et la
table se régénère après toute retouche qui ajoute, retire ou déplace un
« CT-7 ».

**EX-0.1** Toute occurrence de « CT-7 » dans une spécification de `spec/` DOIT
avoir sa ligne dans cette table, avec une réponse qui nomme une section, une
exigence ou un identifiant de CT-7 existant, ou qui renvoie à CT-7 entier par
« Ce document », ou qui dit en clair que la question est hors de CT-7 et qui la
porte (spécification ou partie nommée). Dans la colonne « Réponse de CT-7 », un
EX- ou un identifiant écrit sans « CT-n » devant se lit dans la spécification de
l'énumération qui le précède (« CT-6 EX-5.10 à EX-5.12 »), dans CT-7 à défaut ;
RV-3 et RV-7 le contrôlent (annexe A.10). Les révisions de CT-1 (0.4) et de CT-6
(0.3) qui accompagnent CT-7 0.1 ajoutent leurs propres renvois : ils ont leurs
lignes, comme ceux de `spec/README.md`.

| Id | Spécification, section (ligne) | Ce qui est délégué à CT-7 | Réponse de CT-7 |
|---|---|---|---|
| TR-1 | CT-1 « en-tête » (l. 6) | La définition de l'attestation de périmètre, objet de la révision 0.4. | Section 7 : contenu en 7.1, condensé et signature en 7.2 et 7.3. |
| TR-2 | CT-1 §1 (l. 50) | L'attestation que joint la partie facultative `attestation-perimetre.json`. | Section 7 ; jonction au dossier : CT-7 EX-7.13. |
| TR-3 | CT-1 §2 (l. 77) | La définition du terme « attestation de périmètre ». | Section 7 ; terme défini en section 2. |
| TR-4 | CT-1 §11.2 (l. 1472) | La forme de l'attestation signée portée par `signed`. | CT-7 EX-7.9 (7.3) ; schéma `attestation-perimetre-v0`, `$defs/attestation_signee`. |
| TR-5 | CT-1 §11.2 (l. 1472) | L'événement qui inscrit l'attestation au journal. | CT-7 EX-7.10 et EX-7.11 (7.5) ; porteur proposé à CT-2 : PA-8 (6.2). |
| TR-6 | CT-1 §11.2 (l. 1472) | L'attestation en vigueur pour l'événement prouvé. | CT-7 EX-7.13 (7.6). |
| TR-7 | CT-1 §11.2 (l. 1472) | Le condensé `D_P` et la signature EIP-191. | CT-7 EX-7.6 (7.2) ; séparation des domaines : CT-7 EX-7.7. |
| TR-8 | CT-1 §11.2 (l. 1472) | Le texte qui fait foi en cas d'écart. | CT-7 EX-7.6 ; les valeurs de l'exemple sont recalculées par les deux implémentations (annexe A.6). |
| TR-9 | CT-1 §11.2 (l. 1472) | Ce que le client remet à l'exportateur. | 7.4, pas 6 et 10 : l'attestation signée, assemblée puis jointe. |
| TR-10 | CT-1 §11.2 (l. 1690) | L'attestation de l'exemple de référence. | 7.1 (exemple complet) et 7.2 (valeurs calculées). |
| TR-11 | CT-1 §11.2 (l. 1855) | L'exemple d'inscription. | 7.5 : document de politique et événement seq 12. |
| TR-12 | CT-1 §11.2 (l. 1862) | L'événement d'inscription de l'exemple. | 7.5. |
| TR-13 | CT-1 §11.3 (l. 1902) | Ce que l'attestation prouve et ne prouve pas. | 7.8. |
| TR-14 | CT-1 §11.5 (l. 2136) | Le journal rejoué du dossier `valide-seq-12-attestation-inscrite`. | 7.5 ; vecteurs : annexe A.7. |
| TR-15 | CT-1 §11.5 (l. 2154) | La liste des dossiers de la révision 0.4. | Annexe A.7 (EX-A.10). |
| TR-16 | CT-1 §13 (l. 2236) | La dérivation de l'attestation de l'exemple. | 7.1 (étiquette de `rules_sha256`) et 7.2. |
| TR-17 | CT-1 §13 (l. 2236) | L'étiquette publique de l'empreinte fictive des règles de sortie. | 7.1 ; constantes des vecteurs : annexe A.6. |
| TR-18 | CT-1 §17 (l. 2454) | Notes de la révision 0.4 : l'attestation signée. | 7.3. |
| TR-19 | CT-1 §17 (l. 2457) | Notes de la révision 0.4 : préfixe, condensé et signature. | 7.2 (CT-7 EX-7.6, EX-7.7). |
| TR-20 | CT-1 §17 (l. 2477) | Alignement : dossiers de la révision 0.4. | 7.5 ; annexe A.7. |
| TR-21 | CT-1 §17 (l. 2481) | Alignement : ce que CT-7 doit fournir. | Section 7 et vecteurs `ct-7/attestations` (annexe A.6). |
| TR-22 | CT-1 §17 (l. 2481) | Alignement : état. | Ce document, version 0.1. |
| TR-23 | CT-1 §17 (l. 2482) | Les propositions à CT-2 qui permettent l'inscription. | 6.2, PA-8 et PA-9 ; tant qu'elles ne sont pas adoptées, risque accepté RA-72 (MN-85). |
| TR-24 | CT-1 §17 (l. 2482) | La décision attendue de CT-2. | 6.2 ; aucune proposition n'est appliquée avant son adoption (CT-7 EX-6.3). |
| TR-25 | CT-1 « Annexe B — Récapitulatif des valeurs » (l. 2786) | Le préfixe de domaine `P_P`. | 7.2 (CT-7 EX-7.6) ; distinct de tous les autres préfixes (CT-7 EX-7.7). |
| TR-26 | CT-2 §1 (l. 501) | Hors périmètre de CT-2 : la cérémonie des clés, l'analyse de conformité et la revue de sécurité. | Revue de sécurité : section 3 (modèle de menace, MN-7 à MN-29 pour l'enregistreur) ; cérémonie : section 5 ; conformité : section 8 (avertissement, matrice en 8.4 et `matrice-conformite.json`, rétention en 8.8, lacunes en 8.9) et modèles de clauses de l'annexe C. |
| TR-27 | CT-2 §1 (l. 513) | Table des relations : CT-2 fournit la surface d'attaque (§18) et les classes de garde (§11) ; il attend la cérémonie des clés et la revue. | §18 consolidé ligne par ligne en 3.3 ; classes admises par usage et environnement en 4.3 (CT-7 EX-4.2) ; cérémonie en section 5 ; revue en section 3. |
| TR-28 | CT-2 §10.7 (l. 7045) | L'accès au coffre des originaux est un acte d'exploitation du client. | Déchiffrement à deux personnes, consigné (CT-7 EX-3.11) ; clé du coffre inventoriée (CLE-18) ; menace MN-24, risque RA-21. La durée de conservation des originaux relève du client et n'a pas de plancher (CT-7 EX-8.18). |
| TR-29 | CT-2 §11.1 (l. 7236) | EX-11.4 : la cérémonie qui crée la clé et pose les droits d'administration et d'usage. | Cérémonie de création (CT-7 EX-5.1), étape « remettre la seule identité d'usage » du script de 5.4 ; menace MN-32. |
| TR-30 | CT-2 §11.3 (l. 7402) | EX-11.19 (1) : le support de secp256k1 par chaque backend se vérifie à la cérémonie. | Étape du script de 5.4 : signer un condensé d'essai et recouvrer l'adresse ; CR-5 contrôle que l'adresse déclarée dérive de la clé publique déclarée. |
| TR-31 | CT-2 §11.4 (l. 7440) | EX-11.15 : la rotation planifiée crée les nouvelles clés par l'identité d'administration, en cérémonie. | Cérémonie d'objet `rotation` (CT-7 EX-5.1) ; période de crypto au plus 730 jours, fondée sur R7-F4 (4.4, CT-7 EX-4.3). |
| TR-32 | CT-2 §11.6 (l. 7499) | Titre de §11.6 : cérémonie minimale, renvoi à CT-7. | Section 5. |
| TR-33 | CT-2 §11.6 (l. 7504) | Création, droits, preuve d'origine, sauvegarde et procès-verbal sont la cérémonie de CT-7 ; CT-2 n'en fixe que les sorties (`key_id`, clé publique, classe, backend, preuve d'origine). | Procès-verbal `ceremonie-cles-v0` (5.6) : `key_id`, `public_key`, `fingerprint`, `custody_class`, `backend`, `origin_proof_sha256` de chaque clé ; aucune sauvegarde de la clé de l'enregistreur (CT-7 EX-4.4, CR-7). |
| TR-34 | CT-2 §11.6 (l. 7511) | Corrélation permise entre un événement (`recorder_key_id`, `ts`) et l'appel de signature dans les journaux du backend. | Rapprochement au moins mensuel des appels de signature et des objets signés, exigé pour les classes A et B (CT-7 EX-3.7) ; menace MN-31, risque RA-27. |
| TR-35 | CT-2 §18 (l. 10815) | Analyse de menace complète, revue de code et conformité de l'enregistreur. | Analyse de menace : section 3 ; conformité : section 8 ; la revue de code est une épreuve de CT-9, dont CT-7 fixe le périmètre (composants de 3.2 et menaces de 3.4) : section 10. Les lignes MC-15 à MC-24, MC-35 à MC-40 et MC-51 à MC-58 de la matrice portent sur l'enregistreur. |
| TR-36 | CT-2 §18.5 (l. 10978) | Ce qu'une compromission de l'enregistreur fait à l'agent et à l'hôte (« l'inverse relève de CT-7 et de l'exploitation »). | Menace MN-25, risque RA-22 ; empreinte de l'image en cours (CT-7 EX-3.14, PA-4). |
| TR-37 | CT-2 §20 (l. 12028) | Décision 2 : la cérémonie n'est pas réglée par CT-2. | Section 5. |
| TR-38 | CT-2 §21 (l. 12105) | Hors de CT-2 : la cérémonie des clés et la revue de sécurité. | Sections 3 et 5. |
| TR-39 | CT-3 §1 (l. 291) | Hors périmètre de CT-3 : la cérémonie des clés d'approbateur et la revue de sécurité. | Clés d'approbateur : 4.2 (CLE-3, la clé naît chez l'approbateur) et cérémonie d'inscription des membres (5.1, CR-8) ; revue : MN-44 à MN-52. |
| TR-40 | CT-3 §1 (l. 318) | Table des relations : surface du service et de la console ; garde des clés d'approbateur (EX-3.4, §9, §13) ; une personne, une clé (8.6, 13.4) ; publication des empreintes de la page (EX-13.35). | Surface : MN-44 à MN-52 ; garde : CLE-3 et MN-35 ; une personne, une clé : CR-2, CR-8, MN-36, RA-32 ; empreintes : CT-7 EX-3.9. |
| TR-41 | CT-3 §8.6 (l. 2381) | EX-8.11 : « une personne, une clé » est tenue à l'inscription des membres, en cérémonie ; rien ne la vérifie en version 0. | Cérémonie d'objet `inscription_membres` (CT-7 EX-5.1) : chaque membre signe le procès-verbal avec sa clé devant un témoin qui vérifie son identité ; CR-8 et CR-11 ; reste déclaré : RA-32. |
| TR-42 | CT-3 §8.6 (l. 2393) | Deux comptes du système d'identité tenus par une même personne : à l'organisation de l'empêcher à l'inscription. | Même cérémonie : le témoin constate l'identité de chaque membre sur une pièce, hors du système d'identité (CT-7 EX-5.2) ; RA-32. |
| TR-43 | CT-3 §13.2 (l. 4486) | Construction reproductible et publication du code de la console (avec CT-8). | Publication des empreintes du document et des scripts hors du serveur et comparaison quotidienne (CT-7 EX-3.9) ; la construction reproductible relève de CT-8. |
| TR-44 | CT-3 §13.15 (l. 6036) | Publication des empreintes du document de la console et construction reproductible (avec CT-8). | CT-7 EX-3.9 ; CT-8 pour la construction. |
| TR-45 | CT-3 §14.4 (l. 6582) | Contre un service qui déclare un faux jeu, la parade est le canal authentifié et l'intégrité du service. | CT-7 EX-3.10 (identité distincte, image désignée par son empreinte consignée, lecture du jeu chez un validateur du client ou d'un partenaire) ; MN-44, RA-40. |
| TR-46 | CT-3 §16 (l. 6822) | Des membres de jeu qui ne seraient pas des adresses (évolution) toucheraient la cérémonie des clés. | Hors de la version 0.1 (section 10) : le procès-verbal consigne des adresses ; une version 1 ajouterait une valeur d'`algorithm` et la vérification correspondante à CR-5 et CR-11. |
| TR-47 | CT-4 §1 (l. 186) | Hors périmètre de CT-4 : les cérémonies de clés et la revue de sécurité. | Sections 3, 4 et 5. |
| TR-48 | CT-4 §1 (l. 211) | Table des relations : CT-4 fournit l'inventaire des clés du registre (3.1) et leurs menaces (3.5, §12) ; il attend les cérémonies et la garde. | Inventaire : 4.2 (CLE-4 à CLE-9) ; menaces consolidées en 3.3 ; garde : 4.3 ; cérémonies : 5.1. |
| TR-49 | CT-4 §4.4 (l. 556) | Cérémonie de la clé d'un validateur ; garde en module visée, non réalisable en version 0. | Cérémonie de création sur site (CT-7 EX-5.1) ; classe D seule admise en version 0, sans sauvegarde (4.3, 4.4 ; CR-6, CR-7) ; MN-39, RA-35. |
| TR-50 | CT-4 §5.5 (l. 1125) | EX-5.4 : la clé de l'administrateur du registre est gardée en module matériel par l'exploitant. | Classe A seule admise en production (CT-7 EX-4.2, CR-6), sauvegarde partagée exigée (CT-7 EX-4.4, CR-7) ; MN-38, RA-34. |
| TR-51 | CT-4 §7.2 (l. 1927) | En production, les clés sont gardées selon CT-2 §11 et CT-7. | Table des classes admises par usage et environnement (4.3, CT-7 EX-4.2). |
| TR-52 | CT-4 §7.5 (l. 2230) | EX-7.8 : « un membre = une personne, une personne = une clé », consigné par l'exploitant à la cérémonie. | Cérémonie d'objet `inscription_membres` ; CR-2 et CR-8 ; RA-32. |
| TR-53 | CT-4 §8.4 (l. 2961) | Le délai de révocation est borné par la disponibilité des approbateurs (4 h, astreinte : CT-3 §13, CT-7). | Exercice annuel de rotation d'urgence et de révocation, délai mesuré, cible 4 h (CT-7 EX-3.12) ; conduite en 4.6. |
| TR-54 | CT-4 §8.5 (l. 2995) | `--changement-administrateur` exige une demande consignée selon CT-7. | Procès-verbal d'objet `changement_administrateur`, signé par les membres présents et un témoin, que l'exploitant vérifie (CR-1 à CR-12) et conserve avant de relayer (CT-7 EX-5.1). |
| TR-55 | CT-4 §8.5 (l. 3030) | EX-8.21 : clé de gouvernance en classe A à C, jamais D ; cérémonie selon CT-7. | 4.3 (CR-6) et cérémonie de création (5.1) ; MN-37. |
| TR-56 | CT-4 §8.7 (l. 3133) | Compte d'approvisionnement recomplété par cérémonie. | Cérémonie d'objet `recompletement` (CT-7 EX-5.1) ; MN-40, RA-36. |
| TR-57 | CT-4 §10.5 (l. 3665) | La cérémonie de la clé de validateur, en fichier sur un seul site, relève de CT-7. | Même réponse que la ligne de §4.4 : CT-7 EX-5.1, CR-6, CR-7, RA-35. |
| TR-58 | CT-4 §12 (l. 3757) | Ligne « Clés des validateurs » : cérémonie selon CT-7. | MN-39 (consolidée en 3.3). |
| TR-59 | CT-4 §12 (l. 3759) | Ligne « Clé de gouvernance compromise » : garde en classe A à C (EX-8.21, CT-7). | MN-37 (consolidée en 3.3) ; 4.3. |
| TR-60 | CT-4 §12 (l. 3760) | Ligne « Clé de l'administrateur du registre » : garde en module (EX-5.4, CT-7). | MN-38 (consolidée en 3.3) ; 4.3, 4.4. |
| TR-61 | CT-4 §12 (l. 3761) | Ligne « Trésorerie » : cérémonie CT-7. | MN-40 (consolidée en 3.3) ; 5.1. |
| TR-62 | CT-5 §1 (l. 176) | Hors périmètre de CT-5 : la cérémonie des identifiants de prestataire. | Les identifiants d'accès ne sont pas des clés de signature : aucune cérémonie, création et rotation consignées (4.2, ligne CLE-11 ; 4.6) ; un certificat client se crée comme une clé de classe C ou D sur le poste du client. |
| TR-63 | CT-5 §1 (l. 199) | Table des relations : garde et rotation des secrets de l'ancrage ; procédure de statut qualifié d'un prestataire (5.3). | 4.2 (CLE-10 à CLE-12) et 4.6 ; constat du statut qualifié à deux personnes (CT-7 EX-4.5) ; MN-65. |
| TR-64 | CT-5 §3.4 (l. 395) | Ligne « Composant d'ancrage compromis » : rotation des identifiants (CT-7). | MN-63 (consolidée en 3.3) ; conduite de 4.6 pour CLE-11. |
| TR-65 | CT-5 §5.5 (l. 1256) | Ajustement de la rétention à toute durée légale plus longue que dix ans. | 8.8, CT-7 EX-8.12 : le client porte les trois paramètres de durée à la plus longue durée légale qui s'applique ; aucune durée de plus de dix ans dans les textes lus ; durées sectorielles non recherchées (lacune L-7) ; cohérence des paramètres : CT-7 EX-8.13, PA-13. |
| TR-66 | CT-5 §15 (l. 4418) | Garde en module de la clé du serveur interne et sa cérémonie. | Classe A à C exigée (4.3, CR-6) ; cérémonie de création (5.1) ; MN-42, RA-38. |
| TR-67 | CT-6 « en-tête » (l. 5) | La définition de l'attestation vérifiée par la révision 0.3. | Section 7. |
| TR-68 | CT-6 §1 (l. 145) | L'attestation que vérifie la partie facultative. | Section 7 ; vérifications : 7.7. |
| TR-69 | CT-6 §1 (l. 179) | Ce que CT-6 reprend de CT-7 : l'attestation, `D_P`, la règle « déclaré, jamais prouvé ». | 7.2 (CT-7 EX-7.6) et CT-7 EX-7.1 ; ce que CT-7 attend du rapport : CT-7 EX-7.17. |
| TR-70 | CT-6 §2 (l. 217) | La définition du terme. | Section 7 ; terme défini en section 2. |
| TR-71 | CT-6 §3.2 (l. 323) | Le périmètre reste une déclaration. | CT-7 EX-7.1. |
| TR-72 | CT-6 §3.4 (l. 404) | L'opérateur qui déclare faux. | Menace MN-78 (3.4), risque accepté RA-68 (3.5). |
| TR-73 | CT-6 §3.4 (l. 406) | L'attestation jointe sans inscription. | Menace MN-85, risque accepté RA-72. |
| TR-74 | CT-6 §4.2 (l. 465) | Le format de la partie. | Section 7 (7.1 à 7.6). |
| TR-75 | CT-6 §4.5 (l. 636) | La taille de l'exemple avec inscription. | 7.5. |
| TR-76 | CT-6 §5.5 (l. 858) | L'attestation jointe au dossier. | Section 7. |
| TR-77 | CT-6 §5.5 (l. 861) | La portée des vérifications AT-. | CT-7 EX-7.1. |
| TR-78 | CT-6 §5.5 (l. 893) | Le motif de l'absence d'effet sur le verdict. | CT-7 EX-7.1 ; menaces MN-78 et MN-89. |
| TR-79 | CT-6 §6.5 (l. 1205) | L'exemple du fragment FP. | 7.5 ; dossiers : annexe A.7. |
| TR-80 | CT-6 §7.2 (l. 1745) | Le détenteur de la clé et sa classe se constatent hors du vérificateur : procès-verbal d'inscription (CT-2 EX-11.13) et cérémonie des clés. | Le réviseur vérifie le procès-verbal (CR-1 à CR-12) et n'en tire la clé publique et la classe de garde de la ligne `recorders` de son fichier d'ancres qu'aux conditions de CT-7 EX-5.10 : un signataire connu de lui par un canal indépendant du client et un `D_C` ancré en production (5.9, CT-7 EX-5.11). |
| TR-81 | CT-6 §7.10 (l. 2348) | AT-7 ne compare que des noms de version ; un nom réannoncé avec un autre contenu la fait réussir tant que CT-2 ne l'interdit pas. | PA-9 (6.2) ; menace MN-91, risque accepté RA-75 ; CT-7 EX-7.11. |
| TR-82 | CT-6 §7.10 (l. 2349) | Ce qu'une conformité réglementaire supposerait. | Section 8 : correspondance technique, pas un avis juridique (CT-7 EX-8.1). |
| TR-83 | CT-6 §12.5 (l. 4908) | Ligne `recorders` : procès-verbal d'inscription de la clé et cérémonie des clés. | 5.9 (même réponse). |
| TR-84 | CT-6 §16 (l. 5392) | Le schéma `attestation-perimetre-v0`. | 7.1 ; `spec/schemas/attestation-perimetre-v0.schema.json`. |
| TR-85 | CT-6 §16 (l. 5394) | Les dossiers de la famille `ct-6`. | Annexe A.7 (EX-A.10). |
| TR-86 | CT-6 « A.8 Confrontation par des implémentations tierces » (l. 5911) | Les dossiers avec la partie. | Annexe A.7. |
| TR-87 | CT-6 « B.6 Notes du lot CT-7 (révision 0.3) » (l. 6251) | Les notes de recherche du lot. | Annexe B.1 (R7). |
| TR-88 | CT-6 « B.6 Notes du lot CT-7 (révision 0.3) » (l. 6253) | Les faits R7-F51 à R7-F53. | Annexe B.1. |
| TR-89 | CT-6 « B.6 Notes du lot CT-7 (révision 0.3) » (l. 6260) | Les extraits exacts des sources. | Annexe B.1, extraits cités par la section 7. |
| TR-90 | spec/README.md « Spécifications » (l. 21) | L'état de CT-7. | Ce document, version 0.1 du 2026-10-26. |
| TR-91 | spec/README.md « Spécifications » (l. 21) | Le lien vers ce document. | Ce document. |
| TR-92 | spec/README.md « Spécifications » (l. 26) | Ordre d'écriture : CT-7 après CT-3, CT-4 et CT-5. | Respecté (section 1) : CT-7 0.1 reprend CT-2 0.5, CT-3 0.3, CT-4 0.4 et CT-5 0.2 en l'état, et accompagne CT-1 0.4 et CT-6 0.3. |
| TR-93 | spec/README.md « Schémas (`schemas/`) » (l. 40) | Le schéma de l'attestation. | 7.1. |
| TR-94 | spec/README.md « Schémas (`schemas/`) » (l. 40) | L'exemple de l'attestation. | 7.1. |
| TR-95 | spec/README.md « Schémas (`schemas/`) » (l. 60) | Le schéma du modèle de menace. | 3.8. |
| TR-96 | spec/README.md « Schémas (`schemas/`) » (l. 61) | Le schéma du procès-verbal de cérémonie. | 5.6. |
| TR-97 | spec/README.md « Schémas (`schemas/`) » (l. 61) | L'exemple du procès-verbal. | 5.10. |
| TR-98 | spec/README.md « Schémas (`schemas/`) » (l. 62) | Le schéma de la matrice de conformité. | 8.3. |
| TR-99 | spec/README.md « CT-7 (`vecteurs/ct-7/`) » (l. 354) | Les vecteurs de CT-7. | Annexe A.2. |
| TR-100 | spec/README.md « CT-7 (`vecteurs/ct-7/`) » (l. 356) | La disposition des vecteurs. | Annexe A. |
| TR-101 | spec/README.md « CT-7 (`vecteurs/ct-7/`) » (l. 356) | Le lien vers ce document. | Ce document. |

Hors de `spec/`, cinq renvois existent aussi ; ils ne sont pas comptés par
RV-7 et reçoivent la même réponse : `test/approbation.test.js` (EX-3.4 de
CT-3 hors du test : garde des clés d'approbateur → 4.2, ligne CLE-3, et
MN-35 ; EX-12.2 de CT-3 hors : authentification du canal → MN-44, MN-77, CT-7
EX-3.10 ; EX-13.4 de CT-3, construction reproductible et publication → CT-7
EX-3.9 et CT-8), `scripts/registre/noortrace-registre.mjs` (arrêt OP-5 :
« demande consignée selon CT-7 » → procès-verbal de cérémonie d'objet
`changement_administrateur`, 5.1) et `console/LISEZMOI.md` (publication des
empreintes et construction reproductible → CT-7 EX-3.9 et CT-8).

Trois questions que d'autres spécifications laissent ouvertes sans écrire
« CT-7 » reçoivent aussi leur réponse ici :

- **Ce que le verdict ne dit pas d'un acte non journalisé** (CT-6 §3.4, ligne
  « Opérateur », « ne pas journaliser un acte » ; CT-2 §21, ce qui contourne
  la capture) : l'attestation de périmètre (section 7) le déclare, signé et
  rapporté « déclaré, non prouvé » ; elle nomme les exceptions connues
  (`not_captured`, `egress`, 7.1) ; ce qui reste est le risque accepté RA-1
  (complétude non prouvable) et, pour une déclaration fausse, RA-68.
- **Ce qu'il faut encore croire** (CT-6 §7.8) : 3.6 dit, hypothèse par
  hypothèse, ce qui la rend raisonnable et qui la porte ; l'attestation
  n'ajoute aucune hypothèse aux phrases prouvées, elle ajoute une
  déclaration dont la vérité repose sur ses signataires (7.8).
- **Les adversaires de CT-6 §3.4** : consolidés en 3.3 avec ceux de CT-2 à
  CT-5, chacun rattaché à au moins une menace de 3.4.

### 0.3 Qui lit quoi

| Lecteur | Lit | Y trouve |
|---|---|---|
| Responsable de la sécurité | sections 3 à 6 | pour chaque menace, la réponse, la détection et le risque résiduel ; les clés, leur garde, leur rotation et leur cérémonie ; ce que l'enregistreur journalise sur lui-même. Les réponses renvoient à des exigences de CT-1 à CT-6 dont CT-7 donne l'objet en une ligne : ce résumé suffit à nommer la réponse, juger sa force demande de lire l'exigence citée |
| Responsable de la conformité | section 8 et annexe C | pour chaque passage retenu, la pièce de NOORTRACE qui y répond ou y contribue, ce qui n'est pas couvert et ce qui relève du client ; des modèles de clauses à faire relire. La section 8 nomme chaque pièce par renvoi à CT-1 à CT-6 et en dit l'objet en une ligne : vérifier ce que la pièce fait demande de lire la spécification citée |
| Administrateur du client | section 7, et la section 5 pour une cérémonie | comment remplir l'attestation de périmètre, la faire signer et l'inscrire ; ce qu'elle prouve et ne prouve pas |
| Réviseur | 3.6, 5.9, 7.7 et 7.8 | ce qu'il doit encore croire ; comment tirer une clé d'un procès-verbal vérifié ; comment lire une attestation jointe |
| Auteur d'une autre spécification | 0.2, 6.2, 6.3 et 8.11 | la réponse à chacun de ses renvois et les propositions qui lui sont adressées |
| Implémenteur, auteur de CT-9 | section 9 et annexe A | vecteurs, implémentation de référence, vérificateurs, confrontation tierce, intégration continue, épreuves à l'aveugle |

## 1. Objet, périmètre et relations

CT-7 fixe, pour la version 0 de NOORTRACE :

1. le modèle de menace par composant : quatorze composants, leurs limites de
   confiance, chaque menace avec sa réponse, sa détection, son risque résiduel
   et le test que CT-9 doit écrire ; la consolidation, sans contradiction,
   des tables de menaces de CT-2 à CT-6 ; les exigences nées de cette
   consolidation ; la forme lisible par machine `menaces.json` (section 3) ;
2. l'inventaire de toutes les clés et de tous les secrets, leur classe de
   garde par usage et par environnement, leur génération, leur détention,
   leur rotation, leur révocation et la conduite en cas de compromission
   (section 4) ;
3. la cérémonie des clés : rôles, poste hors ligne, entropie, script pas à
   pas, sauvegarde partagée, et le procès-verbal `ceremonie-cles-v0`, signé
   par chaque participant et vérifiable hors ligne (section 5) ;
4. les événements que l'enregistreur doit journaliser sur lui-même, ce qui
   les porte dans CT-1 v0, ce qui les émet dans CT-2, et ce que CT-7 demande
   à CT-2 et à une version 1 de CT-1 pour combler les lacunes (section 6) ;
5. l'attestation de périmètre : contenu, condensé, signatures des membres du
   jeu d'approbateurs, inscription au journal, jonction au dossier,
   vérification, et ce qu'elle prouve et ne prouve pas (section 7) ;
6. la matrice de conformité : correspondance technique entre des passages de
   textes suisses et européens et les pièces de preuve de NOORTRACE, la
   rétention, les lacunes (section 8) ; des modèles de clauses de droit
   d'audit (annexe C) ;
7. les critères des trois épreuves à l'aveugle (section 9), ce que la
   version ne couvre pas (section 10), l'alignement avec le dépôt
   (section 11), les vecteurs, l'implémentation et l'intégration continue
   (annexe A) et les sources primaires datées (annexe B).

Hors périmètre : la revue de code elle-même, épreuve de CT-9 dont CT-7 fixe
le périmètre (section 10) ; la construction reproductible et l'exploitation
(CT-8) ; toute qualification juridique d'un client, toute affirmation de
conformité et tout avis juridique (section 8) ; tout changement des formats
de CT-1 v0 et de CT-2 à CT-5, que CT-7 propose sans les appliquer (6.2, 6.3,
8.11).

| Spécification | Ce que CT-7 en reprend | Ce que CT-7 lui fournit ou lui demande |
|---|---|---|
| CT-1 | Les préfixes de domaine (annexe B), l'objet `A`, `D_A` et EIP-191 version `0x45` (§6.3), JCS v0 (§4), les quatre sortes réservées (§5.1), ce qu'un point de contrôle prouve (§10.9) ; les champs de l'événement (§5.2, §5.3), les références de pièces (§5.4), le dossier v0 et ses parties facultatives (§11.1, §11.2), ses vérifications (§11.4) et les encodages (§3) | Le préfixe propre du procès-verbal de cérémonie (5.7) et celui de l'attestation (7.2), distincts de tous ceux de CT-1 ; l'attestation de périmètre et son condensé `D_P` (section 7), jointe par la quatorzième partie facultative `attestation-perimetre.json` et vérifiée par AT-1 à AT-7 (CT-1 révision 0.4) ; la table de passage entre les opérations de l'OPDo et `effects[].action` (8.5), sans changer le format v0 ; les propositions PA-7 et PA-16 pour une version 1 (6.3, 8.11) |
| CT-2 | La surface (§18), les classes de garde (§11.2), le journal sur lui-même (§9), les références de secrets (§15.2), le support WORM et ses rôles (§12.6, EX-18.9) ; l'ensemble de politique et `noortrace.journal.politique` (§8.5, EX-8.11, EX-9.1, EX-15.5) ; la rétention (EX-12.19 à EX-12.21, EX-15.4), le gel (EX-12.38), l'horloge (EX-7.10), la supervision (§17), la surface sortante (EX-18.2), ce que la capture ne couvre pas (§21) | La cérémonie des clés (section 5), la revue de sécurité (section 3), l'analyse de conformité (section 8), les événements obligatoires sur soi et les propositions PA-1 à PA-6, PA-8 à PA-11, PA-12, PA-13 et PA-16 (6.2, 8.11), les rapprochements des signatures et de l'usage des fournisseurs (EX-3.7, EX-3.8) |
| CT-3 | Les adversaires (§3.5) et la sûreté (§14) du service et de la console ; « une personne, une clé » (EX-8.11) ; les décisions signées, le refus et son motif (EX-9.13), l'annuaire (EX-13.10, EX-13.19), la trace du ticket (EX-7.24) | La cérémonie d'inscription des membres (5.1, CR-8), l'intégrité du service (EX-3.10), la publication des empreintes de la console (EX-3.9) ; les lignes de la matrice sur le contrôle humain (8.4) |
| CT-4 | Les rôles et clés du registre (§3.1), les adversaires (§3.5) et la sûreté (§12) ; la rétention des certificats (§9.5, EX-9.7), le manifeste d'instance (§4.8) | Les classes admises et la sauvegarde de chaque clé du registre (4.3, 4.4), les cérémonies de ces clés (5.1), l'exercice de révocation (EX-3.12) ; l'inventaire des composants tiers dans le manifeste d'instance (PA-14, 8.11) |
| CT-5 | Les adversaires (§3.4), la sûreté (§13), les secrets de l'ancrage (§4.4), le serveur interne (§7) ; la conservation des pièces d'horodatage (EX-5.15, EX-8.14), l'ancrage jamais bloquant (EX-4.12) | La garde et la rotation des identifiants de prestataire (4.2, 4.6), le constat à deux personnes du statut qualifié (4.5), la cérémonie de la clé du serveur interne (5.1) ; la réponse au renvoi d'EX-5.15 (8.8, EX-8.12) et la cohérence des durées (PA-13) |
| CT-6 | Le modèle de confiance (§3), ce qu'il faut encore croire (§7.8), les ancres du réviseur (§12.5) ; les huit contrôles (§5.1), les statuts, l'énoncé et le rapport (§5, §6, §8), l'absence de réseau (EX-3.3, V-8), la diffusion et la licence (§14.4) | Ce qui rend chaque hypothèse raisonnable et qui la porte (3.6) ; le procès-verbal vérifié comme source de la ligne `recorders` du fichier d'ancres (5.9) ; le rattachement des AT- aux contrôles 6 et 7 sans effet sur les statuts ni le verdict, le fragment FP, `facts.perimeter` et les avertissements AV-AT- (CT-6 révision 0.3) |
| CT-8 | — | La construction reproductible et la publication de l'image et de la console (EX-3.9, EX-3.14), la procédure de levée d'un gel, la supervision tierce (EX-17.7 de CT-2), le journal des consultations et le procès-verbal de migration de support (PA-15, 8.11) |
| CT-9 | — | Un test par menace (colonne « Test de CT-9 » de 3.4), les vérifications CR-, AT-, RV- et MX-, les vecteurs `spec/vecteurs/ct-7`, les trois épreuves à l'aveugle (section 9) |

## 2. Terminologie

| Terme | Définition |
|---|---|
| Composant | Une des quatorze parties de 3.2, avec ce qu'elle détient et la confiance qu'on lui accorde ; toute menace est rattachée à exactement un composant. |
| Menace | Un acteur, avec une capacité, qui vise un actif d'un composant ; identifiant MN-<n> (3.4). |
| Réponse | Ce qui empêche la menace ou la rend visible : renvois exacts à des exigences EX- ou à des vérifications de CT-1 à CT-7 ; à défaut, un risque accepté. |
| Risque accepté | Ce qui reste d'une menace après sa réponse, **nommé** (RA-<n>), **borné** (jusqu'où, combien de temps, sur quel périmètre) et **attribué** (qui le porte : client, exploitant NOORTRACE, réviseur, opérateur de validateur). Un risque accepté est une réponse écrite (3.5). |
| Exploitant NOORTRACE | NOORTRACE comme exploitant de l'instance du registre et éditeur du logiciel (l'« exploitant » de CT-4). |
| Administrateur du client | La personne ou l'équipe du client qui exploite l'enregistreur, le service d'approbation et l'ancrage, écrit la configuration et exporte les dossiers (l'« opérateur » de CT-6 §3.4 et l'« exploitant » de CT-5 §5.3 et §7) ; elle remplit l'attestation de périmètre et la fait signer (`prepared_by`). Elle n'a pas besoin d'être membre du jeu d'approbateurs ; sa seule identité ne fait jamais une signature. |
| Cérémonie des clés | Opération sur une clé (création, rotation, sauvegarde, restauration, destruction, inscription de membres, changement d'administrateur) conduite selon un script écrit, devant au moins deux personnes, et consignée dans un procès-verbal signé (section 5). |
| Officiant | Le participant qui exécute les étapes du script (rôle « Ceremony Administrator » de la pratique publiée, R7-F21). |
| Témoin | Le participant qui vérifie que l'officiant suit le script, horodate et paraphe chaque étape et consigne les écarts (rôle « Internal Witness », R7-F21, R7-F22). |
| Détenteur de part | Le participant qui garde une part d'une clé d'enveloppe partagée k sur n (R7-F13, R7-F26). |
| Procès-verbal | Le document `ceremonie-cles-v0` d'une cérémonie, signé par chaque participant (5.6, 5.7). |
| `D_C` | Le condensé du procès-verbal : Keccak-256 du préfixe `noortrace/ceremonie-cles/v0\n` suivi de la forme JCS v0 du procès-verbal privé de `signatures` (5.7). |
| Contrôle multipartite | Une fonction qui exige k personnes autorisées parmi n, k et n écrits fonction par fonction avec la raison pour laquelle k − 1 ne suffisent pas (R7-F12 ; 4.5). |
| Attestation de périmètre | Document (schéma `attestation-perimetre-v0`) par lequel l'organisation cliente déclare, pour une période, quels agents sont capturés, par quels canaux, quels outils ne sont joignables que par le mandataire, sous quelles règles de sortie, quels identifiants seule la passerelle détient, et ce qu'elle sait ne pas être capturé. Notée `P`. |
| Signataire | Membre du jeu d'approbateurs de l'organisation (CT-1 §2, « approbateur ») qui signe `D_P` en EIP-191 ; nommé dans `signatories`. |
| `D_P` | Condensé de l'attestation : `keccak256(P_P ‖ JCS(P))` (7.2). |
| Attestation signée | `P`, `D_P` déclaré et les signatures (`$defs/attestation_signee`) : ce que l'administrateur remet. |
| Inscription | L'événement `noortrace.journal.politique` dont l'ensemble de politique porte `D_P` (7.5) ; il ordonne l'attestation dans la chaîne et la date par les ancres de son propre dossier. |
| Attestation retenue | Dans un dossier : attestation jointe dont AT-1 à AT-5 réussissent et dont AT-6 réussit ou n'est pas exécutée faute d'inscription (`partie_absente`) ou faute d'une clé reliée à l'événement prouvé (`ancre_absente`) ; AT-7 n'y entre pas (CT-6 EX-6.19). Hors dossier (`attestations.json`, A.6) : attestation signée dont AT-1 à AT-4 réussissent (schéma `attestation-perimetre-v0`, membre `retained`). |
| Correspondance technique | Lien établi par CT-7 entre un passage d'un texte et une pièce de preuve que NOORTRACE produit. Ce n'est pas un avis juridique : elle ne dit ni que le texte s'applique au client, ni que le client le respecte. |
| Pièce (de la matrice) | Ce qui répond ou contribue à un passage : une partie du dossier (CT-1 §11), un contrôle ou une vérification de CT-6 ou de CT-1, une exigence EX- d'une spécification, une section, une clause de l'annexe C. À distinguer des pièces jointes d'un événement (CT-1 §5.4), purgeables par `pieces_days`, et des pièces comptables de l'Olico et du CO. |
| Relation | Pour un élément d'un passage : `repond_a` (une pièce de NOORTRACE fait ce que l'élément demande, sous la condition écrite s'il y en a une), `contribue_a` (une pièce aide le client sans faire tout ce qui est demandé), `ne_couvre_pas` (NOORTRACE ne fait pas ce qui est demandé), `releve_du_client` (ce qui est demandé est un acte, une décision ou une qualification du client). |
| Statut d'une ligne | `couvert`, `partiel` ou `hors_perimetre`, dérivé des relations de ses éléments (EX-8.3). |
| Applicabilité | État du texte au 2026-10-26 tel que les sources lues l'établissent : `en_vigueur`, `vigueur_a_confirmer`, `pas_encore_applicable` (avec ses dates), `publie` (communication ou recommandation, sans force obligatoire propre). |
| Composant tiers | Service qu'un autre que le client exploite et dont NOORTRACE dépend pour une ancre ou une fonction (8.6). |
| Lacune | Écart entre un passage et ce que NOORTRACE fait, nommé, borné, attribué et suivi d'une réponse (8.9). |
| Plancher de conservation | Durée minimale qu'une spécification impose à un paramètre de rétention ; elle n'est ni une durée recommandée, ni une durée maximale (8.8). |
| Contrôles 1 à 8 | Les huit contrôles du vérificateur de dossier (CT-6 §5.1) : 1, hachage canonique de l'événement égal à `hash` ; 2, continuité de la chaîne avec ses voisins ; 3, chemin de Merkle jusqu'à la racine du manifeste signé ; 4, jeton RFC 3161 ; 5, preuve OpenTimestamps sur Bitcoin ; 6, signature Ed25519 de l'enregistreur ; 7, signatures des approbateurs et seuil ; 8, inclusion au registre dans un bloc certifié par un quorum. |
| Manifeste | Document signé par l'enregistreur qui clôt une période et porte la racine de l'arbre de Merkle de ses événements ; son hachage `periodHash` est ce que le registre enregistre (CT-1 §2). |
| Ancre | Preuve extérieure qui engage une empreinte : jeton RFC 3161 (date selon une autorité d'horodatage), preuve OpenTimestamps sur Bitcoin (date « au plus tard »), inscription au registre (ordre et unicité, sans date) (CT-5 §3.3). |
| Canal capturé | Voie par laquelle l'enregistreur voit un acte de l'agent : mandataire MCP, passerelle, ICAP, miroir, SDK ou OpenTelemetry (`capture_channels`, 7.1) ; un acte passé par une autre voie n'est pas journalisé (CT-2 §21). |
| Gabarit d'effets | Modèle que le client écrit dans la configuration pour un outil, et qui fixe les effets déclarés de ses appels (CT-2 EX-7.6). |
| WORM | Support d'écriture unique (« write once, read many ») : un objet écrit ne peut y être ni modifié ni effacé avant l'échéance de sa rétention, dans la mesure que garantit le mode du support (copies verrouillées, CT-2 §12.6). |
| `storage.seal.worm` | Réglage de la configuration de l'enregistreur qui active les copies WORM (CT-2 EX-12.16). |
| `retain_days` | Durée de verrouillage, en jours, d'une copie WORM, comptée depuis l'écriture de chaque copie (CT-2 EX-12.30 ; 8.8.2). |
| Journal d'exploitation | Fichiers de lignes que le démon écrit sur lui-même (par exemple démarrage, rechargement de la configuration, refus d'authentification, purge des pièces), non signés et hors de la chaîne (CT-2 §9.1, §9.2, EX-9.6, EX-17.2) ; distinct du journal, suite d'événements signés et chaînés (CT-1). |
| `logging.keep_files` | Nombre de fichiers tournés du journal d'exploitation que le démon garde (`supervision.ops_log.keep_files` du document de configuration ; CT-2 EX-9.7). |

## 3. Modèle de menace par composant

Cette section est la revue de sécurité que CT-2, CT-3, CT-4 et CT-5 renvoient
à CT-7 (0.2). Elle reprend les tables d'adversaires et de sûreté de CT-2 §18,
CT-3 §3.5 et §14, CT-4 §3.5 et §12, CT-5 §3.4 et §13 et CT-6 §3.4 et §15.5,
les ramène à une seule grille, composant par composant, et y ajoute ce que
leur réunion fait apparaître. Son critère d'acceptation est celui du plan :
chaque menace a une réponse écrite, et aucune faille ne reste ouverte sans
réponse ; un risque accepté est une réponse s'il est nommé, borné et
attribué (3.5).

### 3.1 Méthode et grille

La démarche suit les quatre étapes du guide de modélisation des menaces
centrée sur les données du NIST, publication restée au stade de projet
initial (« (Initial Public Draft) », « NIST plans to finalize this
publication. », R7-F40) : « Step 1: Identify and Characterize the System and
Data of Interest » ; « Step 2: Identify and Select the Attack Vectors to Be
Included in the Model » ; « Step 3: Characterize the Security Controls for
Mitigating the Attack Vectors » ; « Step 4: Analyze the Threat Model »
(R7-F41). L'étape 1 est la table des composants (3.2) ; l'étape 2, les
colonnes « Acteur et capacité », « Actif visé » et « Effet » de 3.4 ;
l'étape 3, la colonne « Réponse » ; l'étape 4, les colonnes « Détection » et
« Risque résiduel » et la table 3.5.

Chaque menace est classée dans une ou plusieurs des six catégories du modèle
STRIDE, dont les définitions sont celles de la documentation qui le publie
(R7-F39) ; l'auteur et la date d'origine du modèle ne sont pas vérifiés
(R7, section 2) :

| Valeur | Catégorie | Définition citée (R7-F39) |
|---|---|---|
| `usurpation` | Spoofing | « Involves illegally accessing and then using another user's authentication information » |
| `alteration` | Tampering | « Involves the malicious modification of data » |
| `repudiation` | Repudiation | « Associated with users who deny performing an action without other parties having any way to prove otherwise » |
| `divulgation` | Information Disclosure | « Involves the exposure of information to individuals who are not supposed to have access to it » |
| `deni_de_service` | Denial of Service | « Denial of service (DoS) attacks deny service to valid users » |
| `elevation_de_privilege` | Elevation of Privilege | « An unprivileged user gains privileged access and thereby has sufficient access to compromise or destroy the entire system » |

La catégorie `repudiation` est le cœur du produit : ce qu'un journal signé
et ancré combat. Ce qu'une signature établit, et rien de plus, est dit par la
définition du NIST : « Source/identity authentication, […] Data integrity
authentication, and/or […] Support for signer non-repudiation. » (R7-F53).

**EX-3.1** Le modèle de menace est la table de 3.4 et le fichier
`spec/vecteurs/ct-7/menaces.json` (schéma `modele-menace-v0`, 3.8). Chaque
menace y porte, dans cet ordre : son identifiant MN-<n>, son composant (3.2),
ses catégories STRIDE, l'acteur et sa capacité, l'actif visé, l'effet, la
réponse, la détection, le risque résiduel et le test que CT-9 doit écrire ;
le fichier y ajoute les lignes des tables sources qu'elle consolide (table de
3.3). La table et le fichier DOIVENT dire la même chose, cellule par cellule
(RV-5).

**EX-3.2** Chaque menace DOIT avoir une réponse écrite : au moins un renvoi
exact à une exigence EX- ou à une vérification d'une famille de CT-1 à CT-7,
qui existe dans la spécification citée (RV-3) ; ou, à défaut, un risque
accepté de 3.5. Un risque résiduel non vide qui n'est ni empêché ni rendu
visible par la réponse DOIT être un risque accepté. « À définir » et « hors
périmètre » sans porteur ne sont pas des réponses. La colonne « Test de
CT-9 » nomme un test qui échoue si la réponse est retirée.

**EX-3.3** Chaque ligne des tables sources de 3.3 DOIT être rattachée à au
moins une menace (champ `sources` de `menaces.json`, RV-6). Une réponse de
CT-7 n'affaiblit jamais celle de la table source : elle la reprend par renvoi
et y ajoute ; un risque résiduel de CT-7 n'est jamais plus étroit que le
« reste » écrit par la table source. Une ligne ajoutée à une table source par
une révision ultérieure fait échouer RV-6 tant qu'elle n'est pas rattachée.

**EX-3.4** Chaque menace porte au moins une catégorie STRIDE ; une menace
qui porte sur la complétude du journal ou sur l'attribution d'un acte porte
`repudiation`.

### 3.2 Composants et limites de confiance

Quatorze composants. Une donnée qui franchit une limite entre deux composants
de confiance différente est une donnée d'attaquant pour celui qui la reçoit,
sauf si une signature vérifiée ou un canal authentifié dit d'où elle vient.

| Id | Composant | Détient | Confiance |
|---|---|---|---|
| `hote_agent` | Hôte de l'agent | Le processus de l'agent, l'hôte (application, cadre ou SDK) et leurs identifiants propres ; aucun accès au stockage ni au signataire (CT-2 EX-3.2). | Aucune : tout ce qu'il envoie est une donnée d'attaquant (CT-2 §3.3). |
| `mandataire_mcp` | Mandataire MCP | Le frontal MCP du démon : liste servie, définitions, identifiants propres vers les serveurs d'outils (CT-2 EX-4.40). | Partie de l'enregistreur ; les serveurs d'outils, eux, ne sont pas crus. |
| `passerelle_modele` | Passerelle du modèle et raccord ICAP | Les routes, les clés des fournisseurs en mode « propre » (CT-2 EX-5.8), le service ICAP et ses sources admises (CT-2 EX-5.3). | Partie de l'enregistreur ; le fournisseur et le mandataire ICAP ne sont pas crus. |
| `sdk_otel` | SDK et ingestion OpenTelemetry (chemin déclaratif) | Les prises du SDK et le point d'entrée OTLP, les jetons des sources (CT-2 EX-6.37). | Déclaratif : l'événement prouve une déclaration, pas l'acte (CT-2 §6.7). |
| `ecrivain_stockage` | Écrivain, stockage et bail | Les segments, le journal d'intention, les pièces, le journal d'exploitation, le bail et son époque (CT-2 §12, §13). | Pleine pour la chaîne qu'il écrit ; bornée par les ancres (CT-1 §10.9). |
| `worm_gel` | Copies WORM et gel juridique | Les copies verrouillées, le registre des copies, le registre des gels et les rôles du support (CT-2 EX-18.9). | Le support fait foi de la rétention qu'il rend ; les registres sont déclaratifs (CT-2 EX-12.41). |
| `cles` | Clés par classe de garde | Toutes les clés et tous les secrets de l'inventaire de 4.2, chacun dans sa classe A à D (CT-2 §11.2). | Celle de la classe : la plus forte en classe A, aucune garantie en classe D. |
| `approbation_console` | Service d'approbation et console | La politique, les tickets, l'annuaire, les identifiants du canal ; aucune clé d'approbateur (CT-3 EX-3.3, CT-3 EX-3.4). | Canal authentifié ; réponses non signées ; console non fiable pour l'approbateur (CT-3 §3.1). |
| `registre` | Registre (validateurs, RPC, contrats, administrateur, gouvernance, trésorerie) | La chaîne de noorcore, les contrats, les clés de validateur, d'administrateur, de gouvernance et de trésorerie (CT-4 §3.1). | Rien n'est cru sans certificat de commit vérifié contre le jeu du réviseur (CT-6 §11). |
| `ancrage` | Composant d'ancrage, prestataires RFC 3161, calendriers OpenTimestamps | La file, les identifiants d'accès aux prestataires, les jetons et preuves acquis (CT-5 §1). | Aucune clé Ed25519 ni clé de chaîne ; les prestataires sont crus seulement sous H4 (CT-6 §3.5). |
| `verificateur` | Vérificateur et ancres de confiance du réviseur | Le code du vérificateur, le fichier d'ancres du réviseur, le fichier d'en-têtes Bitcoin (CT-6 §4). | Il ne croit que son code, les primitives et les ancres du réviseur (CT-6 §3.1). |
| `exploitant` | Exploitant NOORTRACE | L'instance du registre, ses clés d'exploitation, le manifeste d'instance, la publication du logiciel (CT-4 §3.1). Ne détient ni le journal, ni ses copies, ni les pièces, ni CLE-1 ou CLE-2, créées et gardées par le client (4.2) ; le registre ne reçoit que des identifiants, des clés publiques, des empreintes, des adresses d'approbateurs et leurs signatures, jamais d'événement ni de pièce (8.6, CT-7 EX-8.10). | Adversaire « fournisseur » de CT-6 §3.4 : rien de ce qu'il sert n'est cru sans recoupement. |
| `administrateur_client` | Administrateur du client | La configuration, la politique, l'exploitation de l'enregistreur et du service, l'export des dossiers, l'attestation de périmètre. | Adversaire « opérateur » de CT-6 §3.4 ; ce qu'il déclare reste déclaré. |
| `reseau` | Réseau | Les liens entre l'hôte, le démon, les serveurs d'outils, les fournisseurs, les prestataires, le registre et la console. | Aucune : TLS ou prise locale authentifiée partout où un secret ou une décision circule. |

### 3.3 Tables sources consolidées

| Spécification | Section | Table | Lignes |
|---|---|---|---|
| CT-2 | 18.3 | Rôles sur le support WORM (EX-18.9) | 5 |
| CT-3 | 3.5 | Adversaires | 10 |
| CT-3 | 14.2 | Rejeu d'une décision | 10 |
| CT-3 | 14.4 | Substitution du jeu | 5 |
| CT-3 | 14.5 | Confusion d'arguments | 7 |
| CT-3 | 14.7 | Adversaires | 10 |
| CT-3 | 14.8 | Annuaire et inscription | 8 |
| CT-3 | 14.9 | Parcours de signature | 15 |
| CT-4 | 3.5 | Adversaires | 9 |
| CT-4 | 12 | Sûreté | 18 |
| CT-5 | 3.4 | Adversaires | 6 |
| CT-5 | 13 | Sûreté | 13 |
| CT-6 | 3.4 | Adversaires considérés | 6 |
| CT-6 | 15.5 | Attaques considérées | 23 |
| CT-2 | 18.5 | Ce qu'un enregistreur compromis peut et ne peut pas faire (liste) | 6 |

Les colonnes des tables sources divergent (« Reste », « Ce qui reste
possible », « Ce qu'il peut encore faire », « Réponse ») ; la grille de 3.4
les ramène à un seul jeu. La consolidation a relevé quatre écarts de
formulation, qui ne sont pas des contradictions une fois le régime nommé, et
les résout ainsi :

1. **Fenêtre de réécriture.** CT-2 §18.5 et EX-11.17 et CT-6 §3.4 parlent
   d'une heure plus le délai du jeton ; CT-1 §10.9 et CT-5 §3.3, depuis les
   points de contrôle, de `c_T` plus le délai du jeton. CT-7 retient les deux
   régimes dans le même risque accepté : une heure sans points, `c_T` plus
   `d_jeton` avec des points contresignés par un prestataire extérieur
   (RA-15). Ces grandeurs sont définies sous la table 3.5.
2. **« Exploitant ».** Le mot désigne NOORTRACE dans CT-4 et l'équipe
   d'exploitation du client dans CT-5 §5.3 et §7. CT-7 écrit « exploitant
   NOORTRACE » et « administrateur du client » (section 2) ; le composant
   `exploitant` de 3.2 est le premier, `administrateur_client` le second.
3. **Intégrité du service d'approbation.** CT-3 §14.4 nomme la parade
   (« le canal authentifié et l'intégrité du service ») sans la définir ;
   CT-7 EX-3.10 la définit.
4. **Délai de révocation.** CT-4 §8.4 et §12 renvoient au « contrat de
   service des approbateurs » ; CT-7 EX-3.12 le rend mesurable.

Rattachement, ligne par ligne (première cellule de la ligne, gras retiré ;
« puce n » pour la liste de CT-2 §18.5) :

| Spécification | Section | Ligne de la table source (première cellule) | Menaces de CT-7 |
|---|---|---|---|
| CT-2 | 18.3 | Écrivain | MN-27 |
| CT-2 | 18.3 | Gardien de pose | MN-28 |
| CT-2 | 18.3 | Gardien de levée | MN-28 |
| CT-2 | 18.3 | Lecteur | MN-28 |
| CT-2 | 18.3 | Administrateur du compte | MN-27 |
| CT-3 | 3.5 | Agent (et hôte) | MN-1 |
| CT-3 | 3.5 | Opérateur | MN-23 |
| CT-3 | 3.5 | Administrateur du registre | MN-38 |
| CT-3 | 3.5 | Administrateur du jeu | MN-50 |
| CT-3 | 3.5 | Exploitant du nœud RPC | MN-51 |
| CT-3 | 3.5 | Approbateur malveillant | MN-48 |
| CT-3 | 3.5 | Approbateur contraint | MN-48 |
| CT-3 | 3.5 | Console compromise | MN-45 |
| CT-3 | 3.5 | Extension ou fournisseur malveillant dans le navigateur de l'approbateur | MN-46 |
| CT-3 | 3.5 | Service d'approbation compromis | MN-44 |
| CT-3 | 14.2 | Signature d'un ticket présentée pour un autre ticket, un autre journal, une autre organisation | MN-49 |
| CT-3 | 14.2 | Signature `approuve` présentée comme `refuse`, ou l'inverse | MN-49 |
| CT-3 | 14.2 | Seconde décision pour un ticket décidé | MN-49 |
| CT-3 | 14.2 | Approbation scellée relayée deux fois | MN-5 |
| CT-3 | 14.2 | Approbation scellée relayée pour un autre appel que la demande retenue (« blanchiment ») | MN-5 |
| CT-3 | 14.2 | Approbation scellée réutilisée des semaines plus tard | MN-5 |
| CT-3 | 14.2 | Décision d'une autre demande sous un identifiant réattribué après une perte d'état | MN-49 |
| CT-3 | 14.2 | Signature non canonique (`s` haut) | MN-49 |
| CT-3 | 14.2 | Signature d'une autre forme : `v = 37` ou `38` (EIP-155), signature compacte de 64 octets, `s` haut, `v ∈ {0, 1}` | MN-49 |
| CT-3 | 14.2 | Signature EIP-191 rejouée comme transaction | MN-49 |
| CT-3 | 14.4 | Le service déclare un faux jeu (membres qu'il contrôle) | MN-44 |
| CT-3 | 14.4 | Le jeu change pendant l'attente (membre retiré ou ajouté, seuil changé) | MN-50 |
| CT-3 | 14.4 | L'administrateur du registre réassigne le jeu de l'organisation | MN-38 |
| CT-3 | 14.4 | Un jeu `statique`, écrit par l'opérateur, remplace celui du registre | MN-23 |
| CT-3 | 14.4 | Le nœud RPC sert un état faux | MN-51 |
| CT-3 | 14.5 | La politique et le serveur d'outils lisent des valeurs différentes (grands entiers, décimaux) | MN-4 |
| CT-3 | 14.5 | Clés en double, JSON ambigu, second message caché dans les arguments | MN-4 |
| CT-3 | 14.5 | L'approbateur voit un champ, le serveur en lit un autre (champ inconnu de la règle) | MN-4 |
| CT-3 | 14.5 | Liste d'exclusion à égalité exacte (`egal`, `dans` sous un refus) contournée par une autre écriture de la valeur | MN-4 |
| CT-3 | 14.5 | Le service affiche d'autres arguments que ceux de la demande retenue | MN-44 |
| CT-3 | 14.5 | Arguments modifiés entre la demande et le relais | MN-5 |
| CT-3 | 14.5 | La pièce rédigée ne montre pas le clair : `request_hash` ne lie que la forme rédigée | MN-44 |
| CT-3 | 14.7 | Agent | MN-1 |
| CT-3 | 14.7 | Opérateur de l'agent (demandeur) | MN-48 |
| CT-3 | 14.7 | Approbateur malveillant ou contraint | MN-48 |
| CT-3 | 14.7 | Console compromise, ou émetteur sur le canal console → service | MN-45 |
| CT-3 | 14.7 | Extension ou fournisseur malveillant dans le navigateur de l'approbateur | MN-46 |
| CT-3 | 14.7 | Relais du parcours mobile (13.12) | MN-52 |
| CT-3 | 14.7 | Service d'approbation compromis | MN-44 |
| CT-3 | 14.7 | Administrateur du jeu | MN-50 |
| CT-3 | 14.7 | Administrateur du registre | MN-38 |
| CT-3 | 14.7 | Exploitant du nœud RPC | MN-51 |
| CT-3 | 14.8 | Inscrire l'adresse d'un autre à son nom | MN-47 |
| CT-3 | 14.8 | Faire signer à une personne une inscription de son adresse au nom de l'attaquant (confiscation) | MN-47 |
| CT-3 | 14.8 | Rejouer une preuve | MN-47 |
| CT-3 | 14.8 | Faire prendre une inscription pour un vote, ou l'inverse | MN-47 |
| CT-3 | 14.8 | Administrateur malveillant | MN-47 |
| CT-3 | 14.8 | Session volée (jeton ou cookie de la console) | MN-47 |
| CT-3 | 14.8 | Console compromise | MN-45 |
| CT-3 | 14.8 | Service compromis | MN-44 |
| CT-3 | 14.9 | Un faux portefeuille s'annonce sous le nom, l'icône ou le `rdns` d'un autre (R4-F6) | MN-46 |
| CT-3 | 14.9 | Une extension s'interpose entre la page et le portefeuille et remplace `params[0]` par le `D_A` d'une autre demande | MN-46 |
| CT-3 | 14.9 | Le fournisseur rend une signature forgée, malléable ou d'une autre forme | MN-46 |
| CT-3 | 14.9 | Une bibliothèque encode `D_A` comme la chaîne `"0x…"` | MN-46 |
| CT-3 | 14.9 | Le service sert un événement, une pièce, des champs ou un `D_A` qui ne sont pas ceux de la demande retenue | MN-44 |
| CT-3 | 14.9 | La console est compromise | MN-45 |
| CT-3 | 14.9 | Une console compromise, ou un site tiers, présente comme un vote un condensé du registre de CT-4 (`registerDigest`, `revokeDigest`, `periodDigest`) | MN-45 |
| CT-3 | 14.9 | Un site tiers présente le `D_A` d'un ticket en attente comme un message à signer | MN-46 |
| CT-3 | 14.9 | La page de signature est encadrée par un autre site pour faire cliquer l'approbateur | MN-46 |
| CT-3 | 14.9 | Un clic répété envoie deux requêtes ou deux votes | MN-46 |
| CT-3 | 14.9 | Une signature arrive après le délai, après un changement de décision ou d'adresse, ou après l'ouverture d'un autre ticket | MN-46 |
| CT-3 | 14.9 | Le relais mobile retient, retarde ou observe | MN-52 |
| CT-3 | 14.9 | Le code d'appariement mobile est vu par un tiers | MN-52 |
| CT-3 | 14.9 | Un script de la page lit la clé déchiffrée d'un fichier de clé | MN-35 |
| CT-3 | 14.9 | Canal auxiliaire temporel sur la signature locale du parcours d : la signature de `scripts/lib/console.mjs` (`signerHachage`, appelée par `signerCondense` : ECDSA à nonce RFC 6979 écrit en `BigInt`) n'est pas à temps constant, et la durée de ses multiplications et inversions dépend des bits de la clé et du nonce ; un observateur qui mesure ces durées pourrait en tirer de l'information sur la clé | MN-35 |
| CT-4 | 3.5 | Exploitant | MN-53 |
| CT-4 | 3.5 | Validateurs fautifs, au plus f | MN-54 |
| CT-4 | 3.5 | Client | MN-57 |
| CT-4 | 3.5 | Clé de chaîne compromise | MN-34 |
| CT-4 | 3.5 | Approbateurs au seuil, de connivence | MN-37 |
| CT-4 | 3.5 | Clé de gouvernance compromise | MN-37 |
| CT-4 | 3.5 | Expéditeur sans solde qui atteint un point RPC en écriture : client authentifié mais compromis, poste qui atteint le relais RPC d'un client (10.3), tiers | MN-55 |
| CT-4 | 3.5 | Point RPC ou relais RPC menteur | MN-56 |
| CT-4 | 3.5 | Rejeu | MN-57 |
| CT-4 | 12 | Empoisonnement de la mempool par un expéditeur sans solde : client authentifié mais compromis, poste atteignant le relais RPC d'un client, tiers | MN-55 |
| CT-4 | 12 | Débit d'une clé | MN-55 |
| CT-4 | 12 | Clés des validateurs | MN-39 |
| CT-4 | 12 | Clé de chaîne compromise | MN-34 |
| CT-4 | 12 | Clé de gouvernance compromise, ou approbateurs de connivence | MN-37 |
| CT-4 | 12 | Clé de l'administrateur du registre | MN-38 |
| CT-4 | 12 | Trésorerie | MN-40 |
| CT-4 | 12 | Dossier d'inscription non authentifié | MN-57 |
| CT-4 | 12 | Demande signée rejouée | MN-57 |
| CT-4 | 12 | Substitution d'adresses | MN-57 |
| CT-4 | 12 | Rejeu entre chaînes | MN-57 |
| CT-4 | 12 | Rejeu entre organisations | MN-57 |
| CT-4 | 12 | Empreinte prise | MN-58 |
| CT-4 | 12 | Faille d'un contrat | MN-59 |
| CT-4 | 12 | Réorganisation | MN-59 |
| CT-4 | 12 | Panne d'un validateur | MN-55 |
| CT-4 | 12 | Relais RPC menteur | MN-56 |
| CT-4 | 12 | Validateurs coalisés | MN-54 |
| CT-5 | 3.4 | Opérateur ou enregistreur compromis : détient la clé Ed25519 ou l'usage du signataire | MN-17 |
| CT-5 | 3.4 | Prestataire RFC 3161 malhonnête ou compromis | MN-60 |
| CT-5 | 3.4 | Calendrier OpenTimestamps | MN-62 |
| CT-5 | 3.4 | Fournisseur du registre | MN-54 |
| CT-5 | 3.4 | Intermédiaire réseau entre l'enregistreur et un prestataire, un calendrier ou le registre | MN-76 |
| CT-5 | 3.4 | Composant d'ancrage compromis | MN-63 |
| CT-5 | 13 | Rejeu d'un jeton : un jeton obtenu sur une empreinte est présenté pour une autre, ou une réponse ancienne est renvoyée au client | MN-61 |
| CT-5 | 13 | Prestataire menteur ou compromis : `genTime` faux, antidaté ou postdaté | MN-60 |
| CT-5 | 13 | Horloge de l'enregistreur fausse ou manipulée | MN-21 |
| CT-5 | 13 | Perte ou corruption de la file | MN-64 |
| CT-5 | 13 | Points antidatés ou insérés par qui tient la clé de l'enregistreur | MN-17 |
| CT-5 | 13 | Prestataire injoignable longtemps (jours) | MN-62 |
| CT-5 | 13 | Série réécrite et ancrée à part par qui tient la clé de l'enregistreur et la clé de chaîne | MN-17 |
| CT-5 | 13 | Empreinte prise au registre (`empreinte_squattee`) | MN-58 |
| CT-5 | 13 | Fuite par les empreintes : le prestataire ou le calendrier apprend quelque chose du journal | MN-76 |
| CT-5 | 13 | Secrets d'accès au prestataire (Basic, certificat client) | MN-41 |
| CT-5 | 13 | Déni de service d'un calendrier ou d'un agrégateur OpenTimestamps | MN-62 |
| CT-5 | 13 | Interface du serveur interne exposée | MN-42 |
| CT-5 | 13 | Réponse surdimensionnée ou malformée d'un prestataire ou d'un calendrier | MN-68 |
| CT-6 | 3.4 | Opérateur : le client qui exploite l'agent et l'enregistreur, et qui exporte le dossier | MN-18 |
| CT-6 | 3.4 | Fournisseur NOORTRACE : il exploite le registre et publie le vérificateur | MN-53, MN-54, MN-66, MN-71 |
| CT-6 | 3.4 | Enregistreur compromis : un attaquant détient sa clé Ed25519, sa clé de chaîne, ou les deux | MN-17 |
| CT-6 | 3.4 | Autorité d'horodatage malhonnête ou compromise | MN-60 |
| CT-6 | 3.4 | Validateurs minoritaires : au plus f = ⌊(N − 1)/3⌋ validateurs du jeu du fichier d'ancres | MN-54 |
| CT-6 | 3.4 | Fournisseur d'en-têtes Bitcoin : l'exportateur, ou un mineur | MN-70 |
| CT-6 | 15.5 | Rejeu d'un jeton d'horodatage sur un autre manifeste | MN-61 |
| CT-6 | 15.5 | Jeton d'une TSA que le réviseur n'accepte pas, ou expirée à `genTime` | MN-61 |
| CT-6 | 15.5 | Clé de TSA compromise | MN-60 |
| CT-6 | 15.5 | Rétrogradation d'algorithme | MN-61 |
| CT-6 | 15.5 | Preuve OpenTimestamps d'un autre manifeste | MN-61 |
| CT-6 | 15.5 | Chaîne d'en-têtes sans travail, ou d'un autre réseau | MN-61 |
| CT-6 | 15.5 | Attestation désignant un autre bloc | MN-61 |
| CT-6 | 15.5 | Certificat d'une autre chaîne signé par le même jeu | MN-69 |
| CT-6 | 15.5 | Jeu de validateurs substitué (certificat forgé, `validateurs.json` assorti) | MN-69 |
| CT-6 | 15.5 | En-tête falsifié | MN-69 |
| CT-6 | 15.5 | Reçu falsifié qui garde le `blockHash` certifié | MN-69 |
| CT-6 | 15.5 | (révision 0.2) Point de contrôle du journal qui ne couvre pas l'événement (`tree_size ≤ leaf_index`), ou d'une autre période | MN-69 |
| CT-6 | 15.5 | (révision 0.2) Point d'un autre arbre présenté comme préfixe du manifeste | MN-69 |
| CT-6 | 15.5 | (révision 0.2) Jeton de la clôture, ou d'un autre point, rejoué comme jeton du point | MN-61 |
| CT-6 | 15.5 | (révision 0.2) Preuve OpenTimestamps d'une autre donnée embarquée pour le point | MN-61 |
| CT-6 | 15.5 | (révision 0.2) Référence au registre forgée (empreinte, `docType`, contrat) | MN-69 |
| CT-6 | 15.5 | (révision 0.2) Ancre de période relabellisée en ancre de point | MN-69 |
| CT-6 | 15.5 | (révision 0.2) Ancre de point non incluse présentée comme incluse | MN-69 |
| CT-6 | 15.5 | Événement émis par un autre contrat | MN-69 |
| CT-6 | 15.5 | Clôture ou ancre d'une autre période | MN-69 |
| CT-6 | 15.5 | Ancre absente traitée comme réussie | MN-61 |
| CT-6 | 15.5 | Ancre lue dans le dossier ou sur le réseau | MN-67 |
| CT-6 | 15.5 | Analyseur piégé (longueurs, profondeur, octets en trop, formes non minimales) | MN-68 |
| CT-2 | 18.5 | puce 1 | MN-17, MN-18 |
| CT-2 | 18.5 | puce 2 | MN-17 |
| CT-2 | 18.5 | puce 3 | MN-30 |
| CT-2 | 18.5 | puce 4 | MN-27 |
| CT-2 | 18.5 | puce 5 | MN-27 |
| CT-2 | 18.5 | puce 6 | MN-25 |

### 3.4 Table des menaces

La table est groupée par composant, dans l'ordre de 3.2 ; une menace ajoutée par
une révision prend le numéro qui suit le plus grand, quel que soit son
composant, et aucun numéro n'est réattribué (règle des identifiants de 0.1). La
colonne « Test de CT-9 » se lit précédée de « Le test échoue si la réponse est
retirée : ». Les menaces MN-78 à MN-91 et MN-98 sont celles de l'attestation de
périmètre (section 7), rangées sous leur composant ; MN-92 à MN-95 sont celles
de la cérémonie (section 5), MN-96 celle du journal d'exploitation et MN-97
celle de l'outil de condensation.

Les colonnes « Réponse » et « Détection » citent des vérifications d'autres
spécifications, dont voici l'objet en une ligne. Contrôles du vérificateur (CT-6
§5.1) : 1, hachage canonique de l'événement égal à `hash` ; 2, continuité de la
chaîne avec ses voisins ; 3, chemin de Merkle jusqu'à la racine du manifeste
signé ; 4, jeton RFC 3161 ; 5, preuve OpenTimestamps sur Bitcoin ; 6, signature
Ed25519 de l'enregistreur ; 7, signatures des approbateurs et seuil ; 8,
inclusion au registre dans un bloc certifié par un quorum. K-7, K-8 et K-9 : les
contrôles 4, 8 et 5 appliqués au point de contrôle qui couvre l'événement (CT-6
§5.4). R-10 : inscriptions des clés au registre ; l'émetteur de l'ancre est une
clé de chaîne sous laquelle la clé du manifeste est inscrite (CT-6 EX-11.19).
AN-61 : contrôle de complétude au registre, exécuté hors du vérificateur de
dossier (CT-5 EX-10.7). Les hypothèses H1 à H7 de CT-6 §3.5 sont résumées en
3.6. Notification indépendante de chaque vote (CT-3 EX-13.3, MN-45) :
recommandée (DEVRAIT) et absente de la console de référence, elle porte le
ticket, la décision, l'adresse, l'empreinte de `D_A` et l'instant de
l'inscription du vote, sans identité de personne ; elle révèle un vote que
l'approbateur n'a pas émis, une autre décision que la sienne ou le vote d'un
autre ticket. Un vote émis sans regarder n'est visible que si l'approbateur
rapproche l'empreinte notifiée de la demande qu'il croyait signer ; aucun
détecteur ne repère l'inattention elle-même.

L'effacement ou la modification du journal par l'agent n'a pas de ligne propre.
L'hôte et l'agent n'ont aucun droit sur `storage.root` ni sur le signataire
(3.2 ; réponse de MN-22 : CT-2 EX-3.2, CT-2 EX-18.5). Un serveur stdio qu'il
ferait agir relève de MN-9 (RA-8). Un événement scellé, modifié sans la clé de
l'enregistreur ni l'usage de son signataire, échoue aux contrôles 1, 2, 3 et 6
(CT-6 §3.4) ; avec l'une ou l'autre, il relève de MN-17 (RA-15). Supprimer les
derniers événements, qu'aucun événement suivant ni aucun point ancré n'engage
encore, ne fait échouer aucun contrôle. L'agent en est exclu, faute de droit sur
`storage.root` (MN-22). Pour qui a accès au stockage, cette suppression relève
de MN-17 et de la fenêtre RA-15. Elle n'est visible que pour les événements déjà
engagés par un point de contrôle ancré (K-7, K-8 ; CT-1 §10.9) ou déjà présents
dans une copie WORM (MN-27). Une copie effacée relève de MN-27 (RA-23). Taire un
acte relève de MN-1 et de MN-15 (RA-1, RA-13). L'agent n'ajoute aucun risque
résiduel propre au-delà de ces lignes. Les tests de CT-9 de ces lignes en
tiennent lieu : MN-22 (le volume du journal n'est pas monté dans le conteneur de
l'agent, ce qui exclut aussi toute écriture ou troncature par l'agent), MN-9 (un
serveur stdio n'écrit pas sous `storage.root`), MN-17 (un événement couvert par
un point ancré, réécrit et signé de nouveau, échoue à K-7 ou K-8), MN-27 (une
version WORM sans verrou rend le verdict non conforme). EX-3.2 attache un test
à chaque ligne MN- ; ce scénario, sans ligne propre, n'en demande pas d'autre.

Réécrire le journal après coup est hors de portée de l'exploitant NOORTRACE, qui
n'en tient ni copie ni clé (3.2). Ce qui lui reste est dans MN-53, MN-54, MN-66,
MN-71 et MN-73 (RA-48, RA-49, RA-57, RA-60, RA-62). La clé d'administration du
registre (CLE-5) relève de MN-38 (RA-34). L'outil de condensation qu'il publie
relève de MN-97 (RA-81). Une image de l'enregistreur malveillante publiée par
l'éditeur relève de MN-25 (RA-22) : EX-3.14 ne compare l'image exécutée qu'à une
version publiée, et la détection d'une version publiée malveillante relève de la
construction reproductible (CT-8). Ce reste est RA-22, porté par le client, y
compris quand l'image malveillante est une version publiée par l'éditeur : en
version 0, aucune revue de code n'a été faite (section 10) et la construction
reproductible relève de CT-8, à écrire (section 11) ; jusque-là, EX-3.14 ne
distingue pas une version publiée malveillante d'une version saine, et « hors de
portée » ne vaut que sous cette réserve.

| Id | Composant | Catégories | Acteur et capacité | Actif visé | Effet | Réponse | Détection | Risque résiduel | Test de CT-9 |
|---|---|---|---|---|---|---|---|---|---|
| MN-1 | Hôte de l'agent | `repudiation`, `elevation_de_privilege` | L'agent ou tout code de l'hôte qui a un accès réseau propre. | Complétude du journal : tout appel d'outil d'un serveur configuré passe par le mandataire. | Un appel atteint le serveur d'outils sans l'enregistreur ; aucun événement n'existe et aucun dossier ne peut montrer cette absence. | Serveurs stdio lancés par le démon et serveurs HTTP filtrés pour que seul le démon les joigne (CT-2 EX-4.1, CT-2 EX-3.4, CT-2 §4.9) ; agent sans les identifiants de l'enregistreur (CT-2 EX-4.40, CT-2 EX-4.41) ; règles de sortie et exceptions déclarées par l'attestation de périmètre (CT-7 §7) ; essai de sortie annuel (CT-7 EX-3.13). | Journal du pare-feu des tentatives de connexion directe (CT-2 §4.9, point 5) ; essai de sortie (CT-7 EX-3.13) ; le rapport de CT-6 dit « déclaré par » pour le périmètre (CT-7 §7). | Un acte hors du périmètre déclaré n'est jamais prouvé absent : le journal prouve ce qui est passé, pas que rien ne l'a contourné (CT-1 §15). Risque accepté RA-1. | dans la démonstration de référence, un conteneur d'agent tente de joindre directement le serveur d'outils HTTP ; la connexion doit échouer et figurer au journal du pare-feu ; sans la règle de sortie, la connexion aboutit et le test échoue. |
| MN-2 | Hôte de l'agent | `usurpation`, `repudiation` | L'agent, qui écrit ce qu'il veut dans `_meta` et dans sa délégation déclarée. | `delegation` de l'événement et portée des règles d'approbation. | Un appel est attribué à une autre personne, ou profite de la fenêtre d'approbation d'un autre demandeur. | `launched_by` vient de la configuration de la connexion d'hôte, jamais de l'hôte (CT-2 EX-7.2, CT-2 EX-7.3) ; l'évaluation ne lit que `launched_by` configuré (CT-3 EX-3.5) ; portée des fenêtres par demandeur et par outil (CT-3 EX-5.2). | Ligne `delegation_refused` du journal d'exploitation (CT-2 EX-17.2). | `run_id` et `on_behalf_of` restent déclaratifs (CT-2 §7.2). Risque accepté RA-2. | un appel dont `_meta` déclare un autre `launched_by` produit un événement qui porte celui de la configuration ; si l'enregistreur recopie la valeur de l'hôte, le test échoue. |
| MN-3 | Hôte de l'agent | `elevation_de_privilege` | L'agent qui connaît ou sonde les seuils de la politique. | Contrôle humain des montants soumis à approbation. | Un paiement est fractionné en appels sous le seuil d'une règle ; aucune approbation n'est demandée. | Aucune règle ne dit à l'agent ce qui l'a arrêté (CT-3 EX-11.8) ; règles par bénéficiaire et fenêtres à plafond `max_calls` (CT-3 EX-5.2, CT-3 EX-5.5, CT-3 §14.1). | Revue a posteriori des appels autorisés, que la chaîne rend complète pour le périmètre capturé (CT-3 §14.1). | La version 0 n'a pas de prédicat cumulatif ; un fractionnement n'est pas détecté au moment de l'appel (CT-3 §16). Risque accepté RA-3. | la politique de l'exemple de CT-3 §4.3 est évaluée sur deux appels de 3 000 CHF couverts par une fenêtre au plafond atteint ; le troisième appel doit être retenu ; sans le plafond `max_calls`, il est autorisé et le test échoue. |
| MN-4 | Hôte de l'agent | `alteration` | L'agent qui forge des arguments ambigus : clés en double, grands entiers, champ inconnu de la règle, autre écriture d'une valeur exclue. | Égalité entre ce que la politique évalue, ce que l'approbateur voit et ce que le serveur d'outils lit. | La politique ou l'approbateur lit une valeur, le serveur d'outils en exécute une autre. | Analyse stricte, retrait des blancs et refus des nombres non représentables (CT-2 EX-4.43, CT-2 EX-4.44) ; montants en chaînes décimales (CT-1 §3) ; affichage de tous les arguments (CT-3 EX-9.4) ; avertissement sur les listes d'exclusion (CT-3 §14.5). | Refus de l'appel au pas 1 du relais, consigné (CT-2 §4.4). | Une liste d'exclusion à égalité exacte reste contournable par une autre écriture de la valeur ; une liste blanche ne l'est pas (CT-3 §14.5). Risque accepté RA-4. | les vecteurs de `ct-2/` à clé en double et à nombre non représentable en double précision sont refusés avec le code attendu ; si l'analyse stricte est retirée, ils sont relayés et le test échoue. |
| MN-5 | Hôte de l'agent | `elevation_de_privilege`, `alteration` | L'agent qui rejoue, modifie ou ré-émet un appel après une approbation. | Lien entre une décision signée et l'appel exact qu'elle autorise. | Une approbation sert deux fois, pour d'autres arguments, pour un autre outil, ou des semaines plus tard. | Consommation unique et délai de reconnaissance (CT-3 EX-7.17, CT-3 EX-7.18) ; vérifications de relais et MAC à clé des arguments en clair (CT-2 EX-7.21, CT-2 EX-7.22) ; continuation MRTR liée au même MAC (CT-2 EX-4.21) ; `request_hash` dans l'objet signé (CT-1 §6.3). | Alerte « Relais refusé ou identifiant en collision » (CT-2 §17.4). | Aucun au-delà des hypothèses H1 et H2 de CT-6 et de l'intégrité du noyau. | les traces `ct-3/tickets/` `retenir-double-reemission` et `consommation-tardive` et les vérifications de relais RL-1 à RL-4 de l'enregistreur refusent un second relais et un relais d'arguments modifiés ; si la consommation unique ou RL-2 et RL-3 sont retirées, le second relais passe et le test échoue. |
| MN-6 | Hôte de l'agent | `deni_de_service` | L'agent qui multiplie les demandes, ou les rouvre par variation cosmétique. | Disponibilité du service d'approbation et attention des approbateurs. | Les approbateurs, inondés, approuvent sans lire ; le service sature. | Plafond de tickets ouverts par demandeur (CT-3 EX-14.1), regroupement des notifications et historique du demandeur à la console (CT-3 EX-14.2), quotas par connexion d'hôte (CT-2 EX-4.47). | Alerte « Quota d'un hôte » (CT-2 §17.4) ; erreur `plafond_atteint` notifiée à l'administrateur (CT-3 EX-14.1). | Le harcèlement reste possible sous le plafond (CT-3 §14.7). Risque accepté RA-5. | la vingt et unième demande retenue d'un même `launched_by` reçoit `plafond_atteint` ; sans le plafond, un ticket est créé et le test échoue. |
| MN-7 | Mandataire MCP | `alteration`, `usurpation` | Un serveur d'outils malveillant ou compromis. | Définition d'outil que l'agent a lue et nom des événements réservés. | Le serveur change la description d'un outil après coup (« rug pull ») ou annonce un outil `noortrace.*` pour forger un événement réservé. | Empreinte de chaque définition et pièce de définition servie (CT-2 EX-4.16, CT-2 EX-4.45) ; aucun outil propre annoncé et espace `noortrace.` réservé (CT-2 EX-4.2, CT-1 E-3). | Alerte « Définition d'outil changée » (CT-2 §17.4) ; E-3 au vérificateur (CT-1 E-3). | Ce que le serveur fait réellement n'est pas prouvé : `effects` est déclaré (CT-1 §5.3). Risque accepté RA-6. | un serveur de test change la description d'un outil entre deux `tools/list` ; la ligne `tool_definition_changed` et la nouvelle pièce de définition doivent exister ; sans l'empreinte, rien n'est consigné et le test échoue. |
| MN-8 | Mandataire MCP | `usurpation` | Un processus local qui se présente comme un hôte autorisé, ou qui a volé un jeton statique. | Attribution des appels à une connexion d'hôte et à sa délégation. | Des appels sont journalisés sous l'identité d'un autre hôte. | Authentification de tout appelant, comparaison en temps constant, limitation par jeton et par connexion (CT-2 EX-18.3, CT-2 EX-4.39) ; prise locale en mode `0660` pour le seul groupe autorisé (CT-2 EX-18.1). | Ligne `auth_failed` du journal d'exploitation (CT-2 EX-18.3). | Un processus du groupe autorisé, ou qui détient un jeton valide, est indiscernable d'un hôte légitime. Risque accepté RA-7. | une connexion HTTP sans jeton ou avec un jeton faux est refusée et consignée ; si l'authentification est retirée, l'appel est relayé et le test échoue. |
| MN-9 | Mandataire MCP | `elevation_de_privilege`, `divulgation` | Un serveur d'outils stdio compromis, lancé par le démon. | Secrets, stockage et configuration du démon. | Le serveur lit les secrets du démon, écrit dans le stockage du journal ou réutilise un jeton d'hôte. | Utilisateur distinct, bac à sable, environnement réduit aux variables déclarées (CT-2 EX-3.4, CT-2 EX-3.5, CT-2 EX-18.4) ; aucun relais de jeton (CT-2 EX-4.41) ; secrets désignés par fichier `0400` (CT-2 EX-15.3). | Aucune dans la chaîne ; la sortie d'erreur du serveur est bornée et consignée (CT-2 EX-4.32). | Une évasion du bac à sable donne les droits de l'utilisateur du serveur d'outils sur l'hôte. Risque accepté RA-8. | un serveur stdio de test tente de lire un fichier de secret du démon et d'écrire sous `storage.root` ; les deux accès doivent échouer ; si le serveur est lancé sous l'utilisateur du démon, ils réussissent et le test échoue. |
| MN-10 | Mandataire MCP | `repudiation` | Une panne (stockage, processus) au milieu d'un appel d'écriture. | Règle « aucun effet d'écriture sans événement durable ». | Le serveur d'outils a exécuté l'écriture mais l'événement n'est pas durable. | Ordre des pas, intention durable avant relais et reprise des intentions (CT-2 EX-4.19, CT-2 EX-12.12, CT-2 EX-12.14) ; code `-31017` rendu à l'hôte (CT-2 EX-4.46). | Alerte « Panne après relais » (CT-2 §17.4) ; événement de reprise de l'intention (CT-2 EX-9.8). | Le résultat de l'écriture peut manquer : l'événement de reprise dit que l'issue est inconnue. Risque accepté RA-9. | une panne injectée après le pas 9 laisse une intention ouverte que la reprise scelle ; sans l'intention durable, aucun événement n'existe et le test échoue. |
| MN-11 | Passerelle du modèle et raccord ICAP | `repudiation`, `elevation_de_privilege` | L'agent qui détient une clé de fournisseur ou une route de sortie directe. | Complétude des échanges avec le modèle. | L'agent interroge le fournisseur sans la passerelle ; aucun échange n'est journalisé. | Clé du fournisseur tenue par la passerelle seule (`credentials: "propre"`, CT-2 EX-5.8) et pare-feu de sortie (CT-2 §4.9, CT-2 EX-6.2) ; route `relayer` déclarée comme exception (CT-7 EX-3.6). | Rapprochement de l'usage déclaré par le fournisseur, clé par clé, avec les échanges journalisés (CT-7 EX-3.8). | Une clé personnelle de l'agent hors de la passerelle échappe au rapprochement. Risque accepté RA-10. | en mode `propre`, une requête de l'hôte qui porte sa propre clé voit cette clé retirée et la requête part avec celle de la passerelle ; si la clé de l'hôte traverse, le test échoue. |
| MN-12 | Passerelle du modèle et raccord ICAP | `usurpation`, `divulgation` | Une machine du réseau du client qui atteint le port ICAP. | Authenticité des échanges reçus par ICAP et confidentialité du trafic déchiffré. | Des transactions fabriquées deviennent des échanges signés, ou le trafic déchiffré se lit sur le lien ICAP. | Clients ICAP authentifiés par mTLS ou liste de sources, l'un des deux exigé en production (CT-2 EX-5.3) ; ICAP en clair seulement sur la boucle locale ou un segment dédié déclaré (CT-7 EX-3.15). | Refus d'une transaction d'une source inconnue, consigné (CT-2 EX-5.3). | Sur un segment partagé, une liste de sources peut être usurpée ; CT-7 EX-3.15 l'exclut en production. | une transaction REQMOD d'une adresse absente de `allowed_sources` est refusée ; si la vérification est retirée, elle devient un échange et le test échoue. |
| MN-13 | Passerelle du modèle et raccord ICAP | `repudiation` | L'agent qui fait exécuter des outils par le fournisseur (serveurs MCP déclarés au fournisseur, cache fournisseur). | Complétude des appels d'outils. | Des outils s'exécutent côté fournisseur, hors du mandataire MCP. | Requêtes refusées ou réduites à une référence selon la configuration (CT-2 EX-5.32) ; ce qui n'est pas capturé est dit (CT-2 §5.8). | Lignes `model_request_refused` (raison `serveurs_mcp_fournisseur`) et `provider_mcp_bypass` (CT-2 EX-17.2). | Ce que le fournisseur exécute de son côté n'est pas prouvé (CT-2 §5.8). Risque accepté RA-11. | une requête qui déclare un serveur MCP au fournisseur est refusée avec la raison attendue ; si le refus est retiré, elle part et le test échoue. |
| MN-14 | Passerelle du modèle et raccord ICAP | `repudiation` | Le client qui choisit le mode `miroir` ou `desactive`. | Rang de preuve des échanges avec le modèle. | Les échanges sont capturés en lecture seule, ou pas du tout, sans pouvoir être bloqués. | Rang de chaque mode écrit (CT-2 §5.1, CT-2 EX-5.1, CT-2 EX-5.6) ; mode déclaré dans l'attestation de périmètre (CT-7 §7). | Le mode est lisible dans la configuration et dans l'attestation de périmètre. | Un mode miroir ne peut rien empêcher ; un mode désactivé ne prouve rien du modèle. Risque accepté RA-12. | la validation de configuration refuse un mode inconnu et la démonstration de référence tourne en mode `passerelle` ; si le mode n'est plus contrôlé, le test échoue. |
| MN-15 | SDK et ingestion OpenTelemetry (chemin déclaratif) | `repudiation`, `alteration` | Un agent compromis qui emploie le SDK ou un adaptateur. | Exactitude des appels déclarés par le chemin déclaratif. | L'agent déclare d'autres arguments que ceux de l'acte, ou se tait. | Pare-feu de sortie exigé pour ce chemin (CT-2 EX-6.2) ; rang de preuve écrit et alias annoncés dans la chaîne (CT-2 §6.7, CT-2 EX-6.24) ; aucun hachage ni écriture dans le processus de l'agent (CT-2 EX-6.1). | Le lecteur reconnaît le chemin à l'alias de l'outil (CT-2 §6.7) ; le rapport dit « déclaré » (CT-7 §7). | Un agent compromis peut mentir ou se taire par ce chemin (CT-2 §6.3). Risque accepté RA-13. | un appel déclaré par le SDK produit un événement de préfixe `<alias SDK>__` reconnaissable ; si l'alias n'est plus annoncé dans l'ensemble de politique, le test échoue. |
| MN-16 | SDK et ingestion OpenTelemetry (chemin déclaratif) | `usurpation`, `deni_de_service` | Une source OpenTelemetry compromise, ou une machine qui atteint le point d'entrée. | Intégrité et disponibilité de l'ingestion ; écrivain partagé. | Des spans fabriqués deviennent des événements, ou l'ingestion sature l'écrivain. | Sources authentifiées, noms limités au préfixe de la source, bornes et quotas, TLS hors boucle locale en production (CT-2 EX-6.37, CT-2 EX-6.40, CT-2 EX-6.28, CT-2 EX-4.47). | Alertes « Ingestion OpenTelemetry refusée », « Spans rejetés », « Span OpenTelemetry rejoué avec un autre contenu » (CT-2 §17.4). | Une source authentifiée peut fabriquer des spans : c'est la déclarante (CT-2 EX-6.40, point 6). Risque accepté RA-14. | un span d'une source qui tente un nom d'un autre alias est rejeté ; si la règle du préfixe est retirée, il est scellé et le test échoue. |
| MN-17 | Écrivain, stockage et bail | `alteration`, `repudiation` | L'opérateur, ou un attaquant qui détient la clé Ed25519 ou l'usage du signataire. | Intégrité des événements déjà scellés de la période en cours. | Il réécrit et signe de nouveau les événements que le dernier point ancré n'engage pas encore, ou ancre une série réécrite à part. | Points de contrôle à cadence courte, contresignés et ancrés (CT-2 EX-12.24, CT-1 §10.9, CT-5 EX-4.3) ; admission de chaque point et contrôle de série (CT-5 AN-2, CT-5 AN-3) ; contrôle de complétude au registre (CT-5 EX-10.7) ; rotation d'urgence (CT-2 EX-11.16). | Contrôles 4, 5 et 8 et vérifications K-7 à K-9 au vérificateur (CT-6 §5.4) ; complétude au registre (CT-5 AN-61) ; alertes `jeton_anterieur_au_point` et `contresignature_tardive` (CT-5 §8.9). | La fenêtre de réécriture reste ouverte jusqu'au jeton du point couvrant (CT-1 §10.9, CT-5 §3.3). Risque accepté RA-15. | un dossier dont un événement couvert par un point ancré est réécrit et signé de nouveau doit échouer à K-7 ou K-8 ; si les ancres du point ne sont plus vérifiées, il passe et le test échoue. |
| MN-18 | Écrivain, stockage et bail | `repudiation` | L'opérateur ou un enregistreur compromis. | Complétude du journal pour ce qui a traversé l'enregistreur. | Un acte vu par l'enregistreur n'est pas journalisé, ou un dossier défavorable n'est pas exporté. | Aucune règle ne l'empêche contre qui tient l'enregistreur ; les effets restent chez le client et les journaux des serveurs d'outils et des fournisseurs existent hors de lui (CT-2 §18.5). | Rapprochement de l'usage des fournisseurs de modèle (CT-7 EX-3.8) ; comparaison par le client des journaux de ses serveurs d'outils, qu'aucune exigence de la version 0 ne fixe ; trou de la série des points (CT-5 §10). | Une omission par qui tient l'enregistreur n'est visible que par une source extérieure à lui. Risque accepté RA-16. | le rapprochement de CT-7 EX-3.8 sur la démonstration de référence trouve un échange de modèle envoyé hors de la journalisation ; si le rapprochement est retiré, l'écart passe inaperçu et le test échoue. |
| MN-19 | Écrivain, stockage et bail | `alteration` | Une bascule mal faite, un magasin de bail défaillant, ou deux instances actives. | Chaîne unique d'un journal (écrivain unique). | Deux écrivains écrivent deux suites concurrentes du même journal (fourche). | Bail, époque, jeton de clôture vérifié par le stockage et contrôle après écriture (CT-2 EX-13.1, CT-2 EX-13.4, CT-2 EX-13.5, CT-2 EX-13.6, CT-2 EX-13.10) ; le signataire ne signe que pour le titulaire du bail (CT-2 EX-11.3). | Alerte « Fourche » (`journal_fork`, CT-2 §17.4) ; alerte « Bail ». | Un magasin de bail compromis peut donner le bail à deux instances jusqu'au contrôle après écriture. Risque accepté RA-17. | deux écrivains de test dont le second reçoit une époque supérieure : l'écriture du premier est refusée par le stockage ; si le jeton de clôture n'est plus vérifié, les deux écrivent et le test échoue. |
| MN-20 | Écrivain, stockage et bail | `alteration`, `deni_de_service` | Une panne du disque, une coupure, une erreur `EIO` ou `ENOSPC`. | Intégrité des segments et de la fin du journal. | Une ligne tronquée ou corrompue rend un segment illisible. | Synchronisation, relecture et troncature d'une fin incomplète, mode dégradé « stockage » (CT-2 EX-12.8, CT-2 EX-12.10, CT-2 EX-12.11) ; copies WORM (CT-2 EX-12.16). | Contrôles périodiques d'intégrité (CT-2 EX-17.5) ; lignes `segment_truncated`, `segment_corrupted` (CT-2 EX-17.2). | Les événements non synchronisés au moment de la panne sont perdus ; aucun n'a reçu de réponse (CT-2 EX-12.6). Risque accepté RA-67. | un segment tronqué au milieu d'une ligne est relu et tronqué à la dernière ligne valide ; si la relecture est retirée, le démarrage accepte la ligne et le test échoue. |
| MN-21 | Écrivain, stockage et bail | `alteration` | Un attaquant ou un défaut qui déplace l'horloge de l'enregistreur. | `ts` des événements et des points, échéances de l'ancrage. | Des événements ou des points portent une date fausse. | Horloge synchronisée, `ts` non décroissant, blocage sur saut en avant (CT-2 EX-7.10, CT-2 EX-7.13, CT-1 §5.2) ; contrôle de `genTime` contre l'horloge locale (CT-5 EX-5.11) ; seule la contresignature extérieure date (CT-1 §10.9). | Alertes « Horloge » (CT-2 §17.4) et `horloge_suspecte` (CT-5 EX-5.11) ; AV-K-2 et AV-K-4 au rapport (CT-6 §7.9). | `ts` reste déclaratif à la tolérance près (CT-6 §3.2). Risque accepté RA-18. | un saut d'horloge en avant au-delà du seuil bloque l'écrivain et produit la ligne attendue ; si le contrôle est retiré, l'événement est scellé à la date sautée et le test échoue. |
| MN-22 | Écrivain, stockage et bail | `divulgation` | L'hôte, l'agent, ou une personne qui lit le volume du journal. | Pièces rédigées, journal d'exploitation, données personnelles qu'ils portent. | Lecture des pièces ou du journal d'exploitation par qui n'en a pas l'usage. | Aucun droit de l'hôte ni de l'agent sur `storage.root` (CT-2 EX-3.2, CT-2 EX-18.5) ; rédaction avant hachage (CT-2 EX-10.2) ; ce qui ne va jamais dans le journal d'exploitation (CT-2 EX-9.6, CT-2 EX-17.3). | Journaux d'accès du système de fichiers ou du support, tenus par le client. | Les pièces rédigées restent des données du client ; leur accès relève du client. Risque accepté RA-19. | le processus de l'agent de la démonstration ne peut pas lister `storage.root` ; si le volume est monté dans son conteneur, le test échoue. |
| MN-23 | Écrivain, stockage et bail | `alteration`, `repudiation` | L'administrateur du client, qui écrit la configuration et la politique. | Politique et configuration en vigueur. | La politique est assouplie, le jeu remplacé par un jeu `statique`, ou la configuration d'exploitation changée, sans trace. | Toute version de politique annoncée dans la chaîne avant usage, avec son empreinte (CT-2 EX-9.1, CT-2 EX-9.2, CT-2 EX-8.11) ; jeu `statique` refusé en production (CT-3 EX-8.2) ; empreinte de la configuration consignée (CT-2 EX-18.6) ; empreinte de la configuration d'exploitation dans la chaîne proposée (CT-7 §6, PA-2). | Événement `noortrace.journal.politique` (CT-1 §5.1) ; lignes `startup` et `config_reloaded` (CT-2 EX-17.2), que l'administrateur peut effacer (MN-96) ; copie WORM du journal d'exploitation proposée à CT-2 (CT-7 PA-18). | Un assouplissement de `policy` est visible, non empêché, car il est annoncé dans la chaîne (CT-2 EX-9.2) ; face à l'administrateur, un changement hors `policy` n'a aucune trace hors de PA-1 et PA-2 ; la signature de la configuration n'est pas en version 0 (CT-2 §21). Risque accepté RA-20. | un rechargement de politique produit un événement de politique avant le premier événement de la nouvelle version ; si l'événement n'est plus produit, le vecteur `ct-2/evenements/journal-demo/` diffère et le test échoue. |
| MN-24 | Écrivain, stockage et bail | `divulgation` | Une personne qui détient la clé du coffre des originaux. | Originaux non rédigés des pièces. | Lecture des valeurs que la rédaction protège. | Coffre chiffré, clé propre distincte de celle du signataire (CT-2 EX-10.22) ; déchiffrement à deux personnes et consigné (CT-7 EX-3.11). | Registre des accès au coffre (CT-7 EX-3.11). | Deux personnes de connivence lisent les originaux. Risque accepté RA-21. | l'outil de lecture du coffre refuse un déchiffrement sans seconde approbation distincte du demandeur ; si la seconde approbation est retirée, il déchiffre et le test échoue. |
| MN-25 | Écrivain, stockage et bail | `alteration`, `divulgation`, `elevation_de_privilege` | Un attaquant qui compromet le démon de l'enregistreur. | Ce que l'enregistreur relaie à l'agent et à l'hôte : résultats d'outils, réponses de modèle, clés en transit. | Le démon compromis change les résultats renvoyés à l'agent, lit les prompts et les clés de fournisseur, injecte des instructions. | Surfaces d'écoute et de sortie exhaustives, moindre privilège, mémoire non vidable (CT-2 EX-18.1, CT-2 EX-18.2, CT-2 EX-18.4, CT-2 EX-18.7) ; version du logiciel dans chaque événement et empreinte de l'image (CT-2 EX-18.6, CT-7 EX-3.14). | Écart entre l'empreinte de l'image en cours et celle de la version publiée (CT-7 EX-3.14) ; `code.recorder` dans la chaîne (CT-1 §5.3). | L'enregistreur est sur le chemin par conception : le compromettre, c'est compromettre ce qu'il relaie (CT-2 §18.5). Risque accepté RA-22. | le démarrage consigne l'empreinte de l'image et `code.recorder` ; une image dont l'empreinte diffère de la version publiée est signalée ; si la comparaison est retirée, le test échoue. |
| MN-26 | Écrivain, stockage et bail | `repudiation` | L'administrateur du client, ou un attaquant qui arrête, redémarre ou fait basculer l'enregistreur. | Datation, dans la chaîne, des changements d'état de l'enregistreur : démarrage, arrêt, bascule de bail. | Une interruption de la capture, ou une reprise par un autre écrivain, n'apparaît pas dans la chaîne ; un réviseur ne sait pas quand elle a eu lieu. | Points de contrôle produits à chaque instant aligné, qu'un événement ait été écrit ou non (preuve de vie, CT-2 EX-12.24) ; lignes `startup`, `lease_acquired`, `lease_lost` du journal d'exploitation (CT-2 EX-17.2) ; annonce de reprise proposée à CT-2 (CT-7 §6.2, PA-1). | Point manqué constaté (`point_manquant`, CT-5 §8.9) et trou dans la série des points publiée au réviseur (CT-5 §10.2) ; alertes « Bail » et « Fourche » (CT-2 §17.4) ; les lignes du journal d'exploitation, que l'administrateur peut effacer (MN-96). | Tant que PA-1 n'est pas adoptée, ces changements d'état restent hors de la chaîne (CT-7 §6.1) ; un redémarrage de moins de `c_K` ne laisse aucun trou dans la série des points. Risque accepté RA-66. | un redémarrage de l'enregistreur de la démonstration laisse une ligne `startup` et, une fois PA-1 adoptée, un événement d'annonce de reprise ; si la ligne `startup` n'est plus écrite, le test échoue. |
| MN-84 | Écrivain, stockage et bail | `alteration`, `repudiation` | L'exportateur, avec ou sans la clé de l'enregistreur, qui forge un événement d'inscription. | Inscription de l'attestation au journal. | Une attestation paraît inscrite à un rang où elle ne l'était pas. | Signature de l'inscription vérifiée sous la clé de l'événement prouvé, seule admise, et rang au plus celui de l'événement prouvé (CT-1 AT-6, CT-7 EX-7.10) ; l'inscription a son propre dossier, avec ses ancres (CT-7 EX-7.10). | Le dossier de l'événement d'inscription, confronté à ses ancres (CT-6 §5.1). | Même risque que la réécriture du journal par qui détient la clé, dans la fenêtre de réécriture (CT-1 §10.9) ; AT-6 ne relie pas l'inscription à la chaîne de l'événement prouvé par un hachage, seul `seq` est comparé : l'appartenance de l'inscription à la chaîne n'est prouvée que par son propre dossier. Risque accepté RA-71. | dans le dossier `valide-at6-inscription-signature-fausse`, AT-6 doit échouer ; si la vérification de la signature de l'inscription est retirée, AT-6 réussit et le test échoue. |
| MN-85 | Écrivain, stockage et bail | `repudiation` | Un enregistreur qui ne sait pas porter l'inscription tant que PA-8 n'est pas adoptée. | Date et rang de l'attestation. | Une attestation rédigée après coup paraît couvrir l'événement. | Sans inscription, AT-6 et AT-7 ne s'exécutent pas, raison `partie_absente`, et le fragment FP porte la clause fixe « non inscrite au journal (ni sa date ni son rang ne sont établis) » (CT-7 EX-7.12, CT-6 EX-6.19) ; membre `policy.perimeter` proposé à CT-2 (CT-7 PA-8). Seule l'inscription situe l'attestation : `validity.from` peut précéder `issued_at`, et un contrôle de l'un contre l'autre ne protégerait de rien, `issued_at` étant déclaré. | `facts.perimeter.inscription` nul dans le rapport (CT-6 EX-6.20). | Rien ne situe une attestation sans inscription dans le temps du journal, et sa validité peut être rétroactive. Risque accepté RA-72. | le dossier `valide-seq-7-attestation-sans-inscription` a un fragment FP qui porte la clause « non inscrite au journal » ; si la règle est retirée, le fragment annonce une inscription et le test échoue. |
| MN-90 | Écrivain, stockage et bail | `usurpation`, `repudiation` | L'exportateur, sans aucune clé de l'enregistreur : il ajoute à `cles.json` une clé qu'il génère et signe avec elle un événement d'inscription. | Inscription de l'attestation au journal. | Une attestation paraît inscrite au journal de l'événement prouvé, sous une clé que rien ne relie à ce journal. | AT-6 n'est réussie que si la clé de l'inscription est celle de l'événement prouvé ; sinon elle n'est pas exécutée (`ancre_absente`), AT-7 non plus, et FP le dit (CT-1 AT-6, CT-6 EX-5.12, CT-6 EX-6.19) ; la provenance de la clé est nommée dans FP, jamais « fournie par le fichier d'ancres » quand N-3 ne l'a pas comparée (CT-6 EX-6.19). | AT-6 `non_execute`, raison `ancre_absente`, dans le rapport (CT-6 EX-5.12) ; clause de FP « dont l'inscription jointe n'est pas signée par la clé de l'événement prouvé » (CT-6 EX-6.19). | Aucun au-delà de l'hypothèse H3 de CT-6 : la clé de l'événement prouvé n'est elle-même établie que par N-3 ; sans fichier d'ancres qui la donne, FP la dit « déclarée par le dossier ». | dans le dossier `valide-at6-cle-non-ancree`, AT-6 doit être `non_execute` (`ancre_absente`) et AT-7 non exécutée ; si la comparaison des clés est retirée, AT-6 réussit et le test échoue. |
| MN-27 | Copies WORM et gel juridique | `alteration`, `deni_de_service` | Un enregistreur compromis, un exploitant du client, ou l'administrateur du compte du support. | Copies verrouillées des segments, manifestes, points et ancres. | Effacer une copie, raccourcir sa rétention ou écrire une seconde version. | Rétention par défaut en mode Compliance, droits de l'écrivain réduits, rôles séparés (CT-2 EX-12.30, CT-2 EX-12.32, CT-2 EX-18.9) ; relevé de verrouillage (CT-2 EX-17.6). | Alertes « Verrou WORM non conforme », « Versions inattendues », « Relevé de verrouillage en retard » (CT-2 §17.4). | La suppression du compte du fournisseur et l'administrateur du compte non lié par une politique d'organisation restent hors de portée (CT-2 §18.5). Risque accepté RA-23. | le vecteur `ct-2/worm/` d'une version sans verrou rend le verdict non conforme ; si le contrôle du verrou est retiré, le test échoue. |
| MN-28 | Copies WORM et gel juridique | `alteration`, `elevation_de_privilege` | Une personne seule qui veut lever un gel, ou un démon qui écrit dans le registre des gels. | Gel juridique des copies et registre des gels. | Un gel est levé par une seule personne, ou le registre des gels est falsifié pour éteindre la surveillance. | Règle de garde de la levée par deux personnes, registre des gels écrit avant et après chaque action, gardien de levée distinct (CT-2 EX-12.37, CT-2 EX-12.38, CT-2 EX-18.9) ; relecture par le rôle Lecteur hors du démon (CT-2 EX-17.7). | Alertes « Registre des gels invalide », « Gel non posé sur une version d'un gel actif », « Gel levé » (CT-2 §17.4). | Sur les supports où la pose et la levée ne se séparent pas, la règle repose sur l'activation approuvée du rôle ; les identités du registre sont déclarées (CT-2 EX-12.41). Risque accepté RA-24. | le vecteur `ct-2/worm/` d'une levée demandée et accordée par la même identité est refusé par la règle de garde ; si la règle est retirée, la levée passe et le test échoue. |
| MN-29 | Copies WORM et gel juridique | `deni_de_service` | Une panne du support, du réseau ou des identifiants de l'écrivain. | Copie verrouillée d'un segment fermé. | Une copie manque ou est perdue ; seul l'original local reste. | Copie de chaque segment fermé, attribut local d'ajout seul, comparaison horaire (CT-2 EX-12.16, CT-2 EX-12.18, CT-2 EX-17.5). | Alertes « Copie WORM en retard » et « Contrôle d'intégrité en échec » (CT-2 §17.4). | Le segment courant et un segment fermé avant sa copie ne sont protégés que localement (CT-2 §18.5). Risque accepté RA-25. | une copie WORM rendue impossible fait monter `noortrace_worm_copy_pending` et lever l'alerte après une heure ; si la comparaison horaire est retirée, aucune alerte et le test échoue. |
| MN-30 | Clés par classe de garde | `divulgation`, `usurpation` | Un attaquant qui lit la mémoire du démon ou le disque (classes C et D). | Clé privée Ed25519 de l'enregistreur. | La clé est copiée ; l'attaquant signe hors de l'enregistreur. | Classe D refusée en production, non-exportabilité quand le backend l'offre, mémoire protégée (CT-2 EX-11.8, CT-2 EX-11.5, CT-2 EX-18.7) ; création en cérémonie (CT-7 EX-5.1) ; aucune sauvegarde (CT-7 EX-4.4). | Aucun signal du vol lui-même : en classes C et D, aucun journal du backend ne voit la signature (CT-7 EX-3.7). Les ancres extérieures (CT-6 §3.4) rendent visible la réécriture d'un événement couvert par un point ancré (contrôles 4, 5 et 8, vérifications K-7 à K-9, CT-6 §5.4) ; elles ne révèlent pas la copie de la clé. L'usage du signataire en classes A et B relève de MN-31. | En classe C, la graine est en mémoire du démon (CT-2 §11.2). Risque accepté RA-26. | une configuration de production en classe D est refusée au démarrage ; si le refus est retiré, le démon démarre et le test échoue. |
| MN-31 | Clés par classe de garde | `usurpation`, `elevation_de_privilege` | Un processus ou une personne qui obtient l'identité d'usage du signataire (classes A et B). | Usage de la clé de l'enregistreur hors de l'écrivain. | Des objets sont signés par le signataire sans être des événements de l'écrivain titulaire du bail. | Identité d'usage seule, signature seulement pour le titulaire du bail (CT-2 EX-11.4, CT-2 EX-11.3) ; rapprochement mensuel des appels de signature avec les objets signés (CT-7 EX-3.7). | Écart du rapprochement (CT-7 EX-3.7) ; journaux d'audit du backend (CT-2 §11.6). | Un usage abusif entre deux rapprochements n'est vu qu'au suivant ; les ancres bornent ce qu'il réécrit. Risque accepté RA-27. | un journal d'audit de backend de test qui compte une signature de plus que les objets signés de l'intervalle fait échouer le rapprochement ; si le rapprochement est retiré, l'écart passe et le test échoue. |
| MN-32 | Clés par classe de garde | `elevation_de_privilege` | Une personne qui détient l'identité d'administration d'un backend de clés. | Politique de clé : création, export, suppression, droits d'usage. | Elle rend une clé exportable, crée une clé hors cérémonie ou donne l'usage à un autre principal. | Séparation de l'administration et de l'usage (CT-2 EX-11.4) ; cérémonie à deux personnes au moins pour toute opération d'administration (CT-7 EX-5.1, CT-7 EX-5.2) ; contrôle multipartite écrit fonction par fonction (CT-7 EX-4.5). | Revue des journaux d'audit du backend (CT-7 EX-4.9) ; procès-verbal absent pour une opération constatée. | Un administrateur seul garde le pouvoir que le backend lui laisse. Risque accepté RA-28. | un procès-verbal de création signé par une seule personne échoue à CR-2 ; si CR-2 est retirée, il est valide et le test échoue. |
| MN-33 | Clés par classe de garde | `deni_de_service` | La perte ou la destruction du module, ou la perte du secret d'accès. | Continuité du journal. | La clé courante n'est plus utilisable : aucune rotation signée par elle ne peut exister. | Rupture de journal et nouveau journal lié au registre (CT-2 EX-11.16) ; révocation de l'ancienne clé de chaîne (CT-2 EX-11.14) ; pas de sauvegarde de la clé de l'enregistreur, par choix (CT-7 EX-4.4). | Mode dégradé « clé » et alerte critique (CT-2 §17.4). | Le journal est rompu ; le lien entre l'ancien et le nouveau journal est hors chaîne. Risque accepté RA-29. | un signataire injoignable sans reprise met le démon en mode dégradé « clé » bloquant ; si le démon continue d'écrire, le test échoue. |
| MN-34 | Clés par classe de garde | `usurpation`, `deni_de_service` | Un attaquant qui détient la clé de chaîne d'un enregistreur. | Ancres de l'organisation et provision de la clé. | Il ancre des empreintes quelconques, occupe celles de son organisation, disperse la provision vers des adresses neuves. | Provision bornée et alerte au-delà de deux fois le budget (CT-4 EX-4.20, CT-4 EX-8.18) ; révocation au seuil (CT-4 §8.4, CT-2 EX-11.14) ; une clôture exige toujours le seuil (CT-4 §3.3) ; le contrôle 8 écarte les ancres d'une clé révoquée (CT-6 R-10). | Alerte de consommation (CT-4 EX-8.18) ; journaux `Anchored` inattendus (CT-5 EX-10.7). | Jusqu'à la révocation et au-delà, tant que le solde le permet ; la dispersion défait la cadence d'une transaction par bloc (CT-4 §12). Risque accepté RA-30. | un dossier dont l'émetteur de l'ancre n'est pas la clé de chaîne inscrite pour la clé du manifeste échoue à R-10 ; si R-10 est retirée, il passe et le test échoue. |
| MN-35 | Clés par classe de garde | `usurpation`, `divulgation` | Un attaquant qui obtient la clé d'un approbateur : page compromise dans le parcours par fichier de clé, mesure temporelle, poste partagé. | Clé secp256k1 d'un approbateur. | Il signe des votes à la place de l'approbateur. | La clé naît chez l'approbateur et n'est jamais détenue par un serveur (CT-3 EX-3.4, CT-3 EX-13.1) ; parcours par fichier seulement permis, page de référence sans ce parcours (CT-3 EX-13.28, CT-3 EX-13.31) ; portefeuille matériel recommandé (CT-3 EX-9.9). | Notification de chaque vote inscrit par un canal indépendant (CT-3 EX-13.3). | Une page compromise lit la clé dans le parcours par fichier ; une mesure temporelle n'est pas exclue (CT-3 §14.9). Risque accepté RA-31. | la page de référence de la console n'offre pas le parcours par fichier de clé (test Chromium de CT-3) ; si le parcours y apparaît, le test échoue. |
| MN-36 | Clés par classe de garde | `usurpation`, `elevation_de_privilege` | Une personne qui tient deux clés du jeu, ou deux comptes du système d'identité. | Double autorisation que le seuil doit réaliser. | Une seule personne atteint seule un seuil de deux signatures. | « Une personne, une clé » (CT-3 EX-8.11, CT-3 EX-13.10, CT-4 EX-7.8) ; cérémonie d'inscription des membres : chaque membre signe le procès-verbal avec sa clé devant un témoin qui vérifie son identité (CT-7 EX-5.1, CT-7 CR-8, CT-7 CR-11). | Procès-verbal d'inscription des membres (CT-7 §5) ; annuaire exporté (CT-3 EX-13.19). | La vérification d'identité par le témoin est déclarée par le procès-verbal ; deux personnes de connivence restent deux signatures. Risque accepté RA-32. | un procès-verbal où deux membres déclarent la même adresse échoue à CR-2 ; si CR-2 est retirée, il est valide et le test échoue. |
| MN-37 | Clés par classe de garde | `elevation_de_privilege` | Un attaquant qui tient la clé de gouvernance d'une organisation, ou des approbateurs de connivence au seuil. | Jeu d'approbateurs de l'organisation et suite de ses clôtures. | Il prend le jeu en deux blocs, inscrit sa clé de chaîne et clôt une période frauduleuse qui rend le journal inachevable. | Clé de gouvernance en classe A à C, jamais D, créée en cérémonie (CT-4 EX-8.21, CT-7 EX-4.2) ; relais de l'exploitant sur confirmation hors bande (CT-4 EX-8.21) ; sondage des événements du jeu (CT-4 EX-8.12) ; journal abandonné et nouveau nom (CT-4 EX-8.10). | Sondage des événements du `CuratorSet` et des journaux par le client (CT-4 EX-8.12). | Le journal attaqué est perdu pour le contrôle 8 ; un délai ou une cosignature est seulement proposé (CT-4 §14). Risque accepté RA-33. | un procès-verbal de création de la clé de gouvernance en classe D pour la production échoue à CR-6 ; si la règle de classe est retirée, il est valide et le test échoue. |
| MN-38 | Clés par classe de garde | `elevation_de_privilege`, `deni_de_service` | Un attaquant qui tient la clé de l'administrateur du registre. | Assignation du jeu de chaque organisation. | Il réassigne le jeu de toute organisation vers une adresse qu'il contrôle ; le jeu réassigné peut aussi signer une attestation de périmètre ou faire inscrire une clé de chaîne. | Garde en module matériel, clé distincte, usage borné (CT-4 EX-5.4, CT-4 EX-3.1, CT-7 EX-4.2) ; jeu épinglé par la politique (CT-3 EX-8.1, CT-3 EX-8.6) ; réassignation sur demande écrite consignée (CT-4 EX-8.10, CT-7 EX-5.1). | Surveillance de `CuratorSetAssigned` (CT-4 EX-8.12) ; recoupement par le réviseur de l'historique des `CuratorSetAssigned` de l'organisation, du jeu épinglé jusqu'à la date des signatures (CT-7 EX-7.13). | Il bloque les approbations des organisations jusqu'à une nouvelle version de politique (CT-3 §14.4) ; une attestation ou une inscription de clé signée par le jeu réassigné n'est démasquée que par le recoupement de l'historique des réassignations. Risque accepté RA-34. | la trace `ct-3/tickets/` d'un jeu réassigné fait expirer le ticket avec la raison « jeu reassigne » ; si l'épinglage est retiré, le ticket est décidé par le jeu réassigné et le test échoue. |
| MN-39 | Clés par classe de garde | `alteration`, `elevation_de_privilege` | Un attaquant qui lit la clé d'un validateur, ou un opérateur qui restaure une base. | Votes des validateurs et unicité des certificats de commit. | Un validateur signe deux fois une même hauteur ; deux certificats contradictoires peuvent exister au-delà de f fautifs. | Clé générée sur site, fichier `0600`, un seul signataire actif, aucune restauration ni réplication, au plus f par opérateur et par site (CT-4 EX-10.7, CT-4 EX-10.9, CT-4 EX-4.12) ; création en cérémonie, sans sauvegarde (CT-7 EX-4.4, CT-7 EX-5.1). | Supervision de `noor_bft_equivocations_total` et publication des preuves proposées (CT-4 §14). | La garde en module n'est pas possible sans changer noorcore (CT-4 §10.5). Risque accepté RA-35. | un procès-verbal de création d'une clé de validateur avec sauvegarde échoue à CR-7 ; si la règle de sauvegarde est retirée, il est valide et le test échoue. |
| MN-40 | Clés par classe de garde | `elevation_de_privilege` | Un attaquant qui tient la clé du compte chaud de trésorerie. | Provision de NUR de toute l'instance. | Il vide la trésorerie ou approvisionne des expéditeurs qu'il contrôle. | Destinataires admis et plafond quotidien (CT-4 EX-8.20) ; trésorerie froide et compte d'approvisionnement borné recomplété par cérémonie (CT-4 EX-8.20, CT-7 EX-5.1). | Registre d'approvisionnements de l'exploitant et examen des consommations (CT-4 EX-8.18). | Un compte chaud signe en ligne ; la trésorerie froide est seulement proposée en version 0 (CT-4 §14). Risque accepté RA-36. | un approvisionnement vers un destinataire non admis est refusé par l'outil de référence ; si le contrôle est retiré, il part et le test échoue. |
| MN-41 | Clés par classe de garde | `divulgation`, `usurpation` | Un attaquant qui obtient un identifiant d'accès à un prestataire d'horodatage ou un certificat client. | Abonnement et identité du client auprès du prestataire. | Il fait horodater des empreintes aux frais du client ou épuise son débit. | Secrets par référence, jamais dans la file, les traces ni le journal (CT-5 EX-4.8, CT-5 AN-43) ; TLS vérifié (CT-5 EX-5.5) ; rotation et révocation des identifiants (CT-7 §4.6). | Alerte sur le volume de requêtes (CT-5 §8.9) ; `401` traité comme erreur permanente (CT-5 EX-5.12). | Un identifiant volé sert jusqu'à sa révocation chez le prestataire. Risque accepté RA-37. | aucune ligne de la file ni du journal d'exploitation des vecteurs `ct-5/` ne contient un secret (AN-43) ; si un secret y est écrit, le test échoue. |
| MN-42 | Clés par classe de garde | `usurpation` | Un attaquant qui tient la clé du serveur d'horodatage interne, ou l'opérateur lui-même. | Contresignature interne des points. | Il produit des jetons internes à n'importe quelle heure. | Clé hors de l'hôte de l'enregistreur, classe A à C, autre rôle d'exploitation (CT-5 EX-7.3) ; serveur étiqueté « non qualifié » (CT-5 EX-7.2) ; cérémonie de la clé (CT-7 EX-5.1). | Le réviseur choisit d'inscrire ou non l'autorité interne (CT-6 EX-3.8). | Contre l'opérateur, le jeton interne ne vaut rien (CT-5 EX-7.3). Risque accepté RA-38. | un procès-verbal de création de la clé du serveur interne en classe D échoue à CR-6 ; si la règle est retirée, il est valide et le test échoue. |
| MN-43 | Clés par classe de garde | `divulgation` | Une personne qui lit un secret de service : clé du MAC de relais, clé de pseudonymisation, jetons, DSN du bail, identifiants WORM ou de serveurs d'outils. | Secrets de l'inventaire de 4.2 hors des clés de signature. | Selon le secret : forger un relais, retrouver une valeur pseudonymisée par dictionnaire, usurper un hôte ou l'écrivain. | Références de secrets, fichiers `0400`, jamais écrits ni journalisés (CT-2 EX-15.3, CT-2 EX-18.4, CT-2 EX-17.3) ; rotation et conduite par secret (CT-7 §4.6). | Selon le secret : `auth_failed` (CT-2 EX-18.3), alerte « Clé du MAC de relais » (CT-2 §17.4). | Un secret lu sert jusqu'à sa rotation. Risque accepté RA-39. | la validation refuse une valeur littérale là où une référence de secret est attendue ; si la forme objet n'est plus exigée, le test échoue. |
| MN-92 | Clés par classe de garde | `usurpation`, `repudiation` | Une personne qui génère seule plusieurs clés de participant, ou qui inscrit comme témoin une personne absente ou une clé qu'elle détient. | Procès-verbal de cérémonie et ancres que le réviseur en tire. | Un procès-verbal de production paraît multipartite et témoigné alors qu'une seule personne l'a fabriqué et signé. | Un participant `temoin` distinct de l'exécutant à chaque étape, l'auditeur s'y ajoutant sans le remplacer (CR-4, CT-7 EX-5.9 ; règle du témoin, CT-7 EX-5.2) ; ancre tirée seulement d'un procès-verbal dont un signataire est connu du réviseur par un canal indépendant du client, auditeur qu'il a mandaté (CT-7 EX-5.10) ; clés de signature des participants inventoriées (CLE-29, 4.2). | CR-4 en échec quand aucun témoin n'est nommé (CT-7 EX-5.9) ; le réviseur constate qu'aucun signataire ne lui est connu par un canal indépendant. | Les CR- ne voient que des signatures valides : la présence réelle d'un témoin et l'identité des signataires restent déclarées (5.9). Risque accepté RA-76. | le cas `invalide-cr4-temoin-auditeur-seul` échoue à CR-4, et un procès-verbal signé par des clés d'une même personne sans auditeur mandaté ne donne aucune ancre au réviseur ; si la règle du témoin ou la condition d'EX-5.10 est retirée, le procès-verbal passe et le test échoue. |
| MN-93 | Clés par classe de garde | `repudiation`, `alteration` | Qui rédige un procès-verbal après coup et lui donne une date antérieure. | Date de création d'une clé et rang des événements qu'elle signe. | Une clé paraît créée en cérémonie avant les événements qu'elle a signés. | En production, `D_C` ancré par un jeton RFC 3161 joint au procès-verbal ou par une inscription au registre (CT-7 EX-5.11) ; recoupement de la clé d'enregistreur avec son inscription au registre (`registerRecorder`, contrôle 8 de CT-6), qui borne l'antidatage (CT-7 EX-5.10). | Absence d'ancre de `D_C`, ou date de l'ancre éloignée de `ended_at` (fin déclarée de la cérémonie, 5.6), constatée par le réviseur (CT-7 EX-5.11) ; CT-7 ne fixe pas de tolérance ; le réviseur juge l'écart, et une ancre ne prouve qu'une date au plus tard (RA-77). | Sans ancre, la date du procès-verbal n'est que déclarée. Risque accepté RA-77. | un procès-verbal de production sans ancre de `D_C` est signalé au réviseur comme daté par déclaration seulement ; si l'exigence d'ancrage est retirée, il est accepté sans réserve et le test échoue. |
| MN-94 | Clés par classe de garde | `elevation_de_privilege` | Qui restaure une clé sauvegardée sans réunir le seuil de détenteurs de part. | Clés sauvegardées par partage k sur n (4.4 : CLE-4 si le client l'a choisi, CLE-5, CLE-8 pour la trésorerie froide, CLE-26). | Une clé d'administrateur ou de gouvernance est reconstituée hors du contrôle multipartite. | CR-12 : un procès-verbal `restauration` porte `purpose_details` avec `2 ≤ k ≤ n` et au moins k participants `detenteur_part` (CT-7 EX-5.9 ; restauration : CT-7 EX-5.5) ; sauvegarde et partage selon 4.4 (CT-7 EX-5.5). | CR-12 en échec ; une restauration faite hors cérémonie ne se voit qu'à l'usage de la clé (4.7). | Une restauration hors cérémonie ne laisse de trace que par l'usage de la clé restaurée. Risque accepté RA-78. | le cas `invalide-cr12-restauration-sans-detenteur` échoue à CR-12 ; si la règle est retirée, il passe et le test échoue. |
| MN-95 | Clés par classe de garde | `elevation_de_privilege` | Une personne qui reçoit plusieurs parts sous des noms différents. | Seuil k de la sauvegarde partagée. | Le seuil de restauration est atteint par moins de k personnes. | Le témoin constate l'identité distincte de chaque détenteur de part et le consigne (CT-7 EX-5.2) ; la distinction est déclarée au procès-verbal (5.9). | Aucune par les CR- : l'identité distincte des détenteurs est un constat déclaré du témoin. | Que les détenteurs de part soient des personnes distinctes reste déclaré. Risque accepté RA-79. | un procès-verbal de `sauvegarde` qui remet deux parts à la même personne sous deux noms est relevé par le témoin dans `findings` ; si le constat du témoin est retiré, rien ne le relève et le test échoue. |
| MN-44 | Service d'approbation et console | `alteration`, `elevation_de_privilege` | Un service d'approbation compromis, qui répond ce qu'il veut sauf des signatures. | Décisions `autorise` et `refuse`, jeu déclaré, affichage des arguments. | Il rend `autorise` à tort, déclare un faux jeu, ignore la fenêtre de contestation ou affiche d'autres arguments. | Canal authentifié (CT-2 EX-18.8, CT-3 EX-12.2) ; vérification de toute remise (CT-2 EX-7.5, CT-3 SG-5, CT-3 SG-6, CT-3 SG-7) et des relais (CT-2 EX-7.21) ; contrôles de la console sur l'événement retenu et la pièce (CT-3 EX-9.6) ; intégrité du service (CT-7 EX-3.10). | Réévaluation par le réviseur (CT-3 §6.8) ; un appel `autorise` après un `retenue` du même outil dans la chaîne (CT-3 §14.7). | Le jeu reste « déclaré par le dossier » ; `autorise` n'est pas signé ; une valeur rédigée peut être substituée dans l'affichage (CT-3 §14.4, CT-3 §14.5). Risque accepté RA-40. | une remise `approuve` dont une signature ne recouvre pas un membre du jeu remis est refusée par SG-5 ou SG-6 ; si la vérification est retirée, la décision est scellée et le test échoue. |
| MN-45 | Service d'approbation et console | `usurpation`, `alteration` | Une console compromise, ou un émetteur sur le canal console vers service avec des identifiants valides. | Ce que l'approbateur signe et ce qui est transmis en son nom. | Elle fait signer un autre condensé que celui qu'elle affiche, présente un condensé du registre comme un vote, forge une récusation ou un retrait, ne transmet pas un refus. | Console qui recalcule et affiche `D_A` en entier, recouvre l'adresse sur son propre condensé (CT-3 EX-9.6, CT-3 EX-9.17, CT-3 EX-9.21) ; notification indépendante de chaque vote (CT-3 EX-13.3) ; une récusation ne retire jamais un refus (CT-3 EX-10.4) ; politique de sécurité du contenu (CT-3 EX-13.35) ; publication des empreintes de la page hors du serveur (CT-7 EX-3.9). | Notification d'un vote que l'approbateur n'a pas émis (CT-3 EX-13.3) ; écart d'empreinte de la page (CT-7 EX-3.9). | Limite du format v0 : l'approbateur qui ne compare pas l'empreinte peut signer une autre demande retenue, ou `approuve` pour qui voulait refuser (CT-3 §9.3). Risque accepté RA-41. | le vecteur `ct-3/console/` d'une réponse du portefeuille qui ne recouvre pas l'adresse sur le `D_A` de la console n'aboutit à aucun vote ; si le recouvrement est retiré, un vote part et le test échoue. |
| MN-46 | Service d'approbation et console | `usurpation`, `alteration` | Une extension ou un fournisseur malveillant dans le navigateur de l'approbateur, ou un site tiers. | Choix du portefeuille et message réellement signé. | Un faux portefeuille se fait choisir, s'interpose et remplace `params[0]`, rend une signature forgée, fait signer le `D_A` d'une autre demande, encadre la page. | Aucun choix implicite, doublons d'`uuid` exclus (CT-3 EX-13.22) ; comparaison de l'empreinte à l'écran du portefeuille (CT-3 EX-9.20) ; recouvrement et contrôle de forme avant toute bibliothèque (CT-3 EX-9.21, CT-3 EX-9.22) ; une requête à la fois, réponses tardives ignorées (CT-3 EX-13.21, CT-3 EX-13.30) ; `frame-ancestors 'none'` (CT-3 EX-13.35). | Vote refusé `adresse_differente` ou signature ignorée, consignés par la console (CT-3 §13.14). | Un approbateur qui ne compare pas peut signer le `D_A` d'une autre demande retenue ; une extension peut bloquer la signature (CT-3 §14.9). Risque accepté RA-42. | les vecteurs `ct-3/console/` de découverte avec `uuid` dupliqué excluent les deux annonces ; si l'exclusion est retirée, un portefeuille est choisi et le test échoue. |
| MN-47 | Service d'approbation et console | `usurpation`, `deni_de_service` | Un attaquant qui vole une session de la console, un administrateur d'annuaire malveillant, ou un site d'hameçonnage. | Annuaire des approbateurs : inscriptions, validations, révocations. | Il inscrit l'adresse d'un autre, confisque une adresse, rejoue une preuve, révoque ou désactive un membre. | Preuve de possession sur un texte qui nomme l'identité, nonce unique, adresse jamais réattribuée (CT-3 EX-13.13, CT-3 EX-13.15, CT-3 EX-13.10) ; réauthentification récente (CT-3 EX-13.8) ; validation après vérification par un autre canal, jamais de sa propre adresse (CT-3 EX-13.17) ; séparation des domaines (CT-3 EX-13.16). | Notification de chaque opération qui vise la personne (CT-3 EX-13.3) ; `operations` de l'annuaire (CT-3 §13.6). | Confiscation et révocation par session volée restent possibles : déni de service visible (CT-3 §14.8). Risque accepté RA-43. | la trace `ct-3/annuaire/traces/confiscation.json` aboutit à l'état attendu ; si la vérification d'identité du message est retirée, l'inscription est acceptée sous une autre session et le test échoue. |
| MN-48 | Service d'approbation et console | `elevation_de_privilege` | Un approbateur malveillant ou contraint, une collusion, ou le demandeur lui-même. | Seuil des approbations et séparation des tâches. | Une collusion d'au moins `required` membres décide ; un approbateur est forcé de signer ; le demandeur s'approuve. | Seuil d'adresses distinctes (CT-1 A-3) ; séparation du demandeur et vérification par le noyau (CT-3 EX-10.2, CT-3 SG-7) ; fenêtre de contestation (CT-3 §5.6). | Décision signée donc attribuable (contrôle 7, CT-6 §5) ; objection pendant la fenêtre (CT-3 EX-10.7). | Pas de signal de contrainte en version 0 ; une collusion au seuil décide (CT-3 §3.5). Risque accepté RA-44. | une remise signée par l'adresse déclarée du demandeur est refusée par SG-7 ; si SG-7 est retirée, la décision est scellée et le test échoue. |
| MN-49 | Service d'approbation et console | `alteration`, `usurpation` | Qui détient une signature d'approbateur et la présente ailleurs, sous une autre forme, ou deux fois. | Lien d'une signature à un ticket, une décision, un journal et une organisation. | Une signature sert pour un autre ticket, une autre décision, une seconde décision, ou comme transaction. | Objet signé `A` complet (CT-1 §6.3, CT-3 EX-9.1) ; décision unique scellée par le noyau (CT-3 SG-3) ; normalisation et refus des formes non canoniques (CT-3 EX-9.3, CT-3 EX-9.22, CT-3 SG-5) ; identifiant unique malgré la perte d'état (CT-3 EX-7.1, CT-2 EX-7.17) ; préfixe `0x19` (CT-1 §6.3). | Refus SG consignés (CT-2 §17.4, « Remise refusée »). | Aucun au-delà des hypothèses H1 et H2 de CT-6. | le fichier `ct-3/signatures/normalisation.json` est rejoué : chaque forme refusée l'est ; si le contrôle de forme est délégué à la bibliothèque, une forme refusée passe et le test échoue. |
| MN-50 | Service d'approbation et console | `elevation_de_privilege` | L'administrateur du jeu d'approbateurs. | Membres et seuil du jeu pendant l'attente d'un ticket. | Il abaisse le seuil ou ajoute des membres qu'il contrôle pendant qu'un ticket attend. | Surveillance, nouveau gel, seuil effectif qui ne baisse jamais, membres ajoutés signalés, confirmation avant remise (CT-3 EX-8.5, CT-3 EX-8.6, CT-3 EX-8.7). | Membres ajoutés signalés à la console et dans la trace (CT-3 EX-8.6) ; événements publics du jeu (CT-4 EX-8.12). | Des membres ajoutés par l'administrateur votent (CT-3 §14.4). Risque accepté RA-45. | la trace `ct-3/tickets/` d'un seuil abaissé pendant l'attente garde le seuil effectif d'origine ; si le seuil suit la baisse, le test échoue. |
| MN-51 | Service d'approbation et console | `alteration` | L'exploitant du nœud RPC que le service interroge. | Lecture du jeu d'approbateurs au registre. | Le service fige un jeu inventé. | Interroger un validateur que le client opère ou un validateur partenaire (CT-3 EX-8.2, CT-7 EX-3.10). | Le réviseur relit le jeu à la hauteur de `source` (CT-3 §8.5). | noorcore ne sert aucune preuve d'état (CT-3 §14.4). Risque accepté RA-46. | la validation de la configuration du service refuse en production un point RPC qui n'est pas déclaré comme validateur du client ou d'un partenaire ; si la règle est retirée, le test échoue. |
| MN-52 | Service d'approbation et console | `divulgation`, `deni_de_service` | Le relais du parcours mobile, ou un tiers qui voit le code d'appariement. | Messages entre la console et le portefeuille mobile. | Le relais retient, retarde ou observe les métadonnées ; un tiers apparie son portefeuille. | Chiffrement de bout en bout, parcours désactivé par défaut, échéance bornée, code montré à la seule session authentifiée et jamais journalisé (CT-3 EX-13.27). | Délai de la console (CT-3 EX-13.30). | Déni de service et métadonnées de trafic (CT-3 §14.9) ; l'usage d'un code vu par un tiers n'est pas analysé (CT-3 §14.9). Risque accepté RA-47. | la configuration par défaut de la console de référence n'offre pas le parcours c ; s'il apparaît sans activation, le test échoue. |
| MN-53 | Registre (validateurs, RPC, contrats, administrateur, gouvernance, trésorerie) | `elevation_de_privilege`, `deni_de_service` | L'exploitant du registre, qui tient l'administration du registre et sert le RPC. | Jeu assigné à une organisation et suite de ses clôtures. | Il réassigne le jeu d'une organisation, inscrit des clés et soumet une clôture qui rend un journal inachevable. | Réassignation sur demande écrite et jeu administré par la même clé de gouvernance (CT-4 EX-8.10) ; jeu épinglé (CT-3 EX-8.6) ; demande consignée par procès-verbal (CT-7 EX-5.1). | Surveillance de `CuratorSetAssigned` et des journaux par le client (CT-4 EX-8.12). | Un journal ainsi rendu inachevable est abandonné ; c'est public (CT-4 §3.5). Risque accepté RA-48. | l'outil de référence refuse un nouveau jeu dont `admin()` diffère sans `--changement-administrateur` (OP-5) ; si le contrôle est retiré, la réassignation part et le test échoue. |
| MN-54 | Registre (validateurs, RPC, contrats, administrateur, gouvernance, trésorerie) | `alteration` | Des validateurs fautifs ou coalisés, ou le fournisseur du registre qui contrôle un quorum. | Certificats de commit et blocs du registre. | Des blocs faux passent le contrôle 8 ; deux certificats contradictoires existent. | Au plus f validateurs par opérateur et par site, validateurs partenaires (CT-4 EX-4.12, CT-4 EX-10.6) ; aucune date tirée du registre (CT-4 EX-3.2) ; quorum calculé sur le jeu du réviseur (CT-6 R-2). | Publication des preuves de double signature (CT-4 §14) ; ancres RFC 3161 et Bitcoin indépendantes du registre (CT-5 §3.4). | Contre un quorum, le contrôle 8 ne prouve rien (CT-6 §3.4). Risque accepté RA-49. | le dossier `invalide-r2-jeu-substitue` de `ct-6/dossiers/` échoue à R-2 ; si le quorum est calculé sur `validateurs.json`, il passe et le test échoue. |
| MN-55 | Registre (validateurs, RPC, contrats, administrateur, gouvernance, trésorerie) | `deni_de_service` | Un expéditeur sans solde qui atteint un point RPC en écriture, une clé qui envoie trop, ou une panne de validateur. | Mempool et capacité d'inclusion du registre. | La mempool se remplit de transactions jamais prêtes ; les ancres et clôtures attendent. | Garde d'admission par client, RPC des validateurs fermés, soumission à au moins deux validateurs (CT-4 EX-10.8, CT-4 EX-10.3, CT-4 EX-8.15) ; une clé de chaîne par clé Ed25519 (CT-2 EX-11.19) ; le registre ne bloque jamais l'enregistreur (CT-2 §14.2). | Alerte de CT-8 sur la taille de la mempool (CT-4 §12) ; `registry_pending` (CT-2 EX-17.2). | Le contrôle du solde à l'admission par noorcore est seulement proposé (CT-4 §14). Risque accepté RA-50. | l'épreuve SU-2 de CT-4 est rejouée sur le réseau de développement ; si la garde d'admission est retirée, les transactions à 1 wei sont refusées et le test échoue. |
| MN-56 | Registre (validateurs, RPC, contrats, administrateur, gouvernance, trésorerie) | `alteration`, `usurpation` | Un point RPC ou un relais RPC menteur. | Lectures d'état, reçus et identifiant de chaîne servis aux outils. | Il sert un état, des reçus ou un identifiant de chaîne faux. | Capture auprès d'un validateur, certificat vérifié contre le jeu du manifeste avant d'être tenu pour capturé (CT-4 CP-1, CT-4 CP-4) ; contrôle d'identifiant (CT-4 EX-4.9) ; tout recalculé au vérificateur (CT-6 §11.1). | Échec CP-4 consigné (CT-4 §9.4). | Un relais peut retenir ; il ne peut pas forger un quorum (CT-4 §12). | le vecteur `ct-4/capture/` d'un certificat altéré est refusé par CP-4 ; si CP-4 est retirée, la capture est tenue pour faite et le test échoue. |
| MN-57 | Registre (validateurs, RPC, contrats, administrateur, gouvernance, trésorerie) | `usurpation`, `alteration` | Qui rejoue une signature ou une transaction d'une autre chaîne, d'une autre organisation, ou une demande signée ancienne ; qui altère un dossier d'inscription. | Condensés signés au seuil, transactions et dossier d'inscription. | Une signature ou une transaction sert ailleurs ; d'autres clés sont inscrites qu'annoncé. | Identifiant EVM, adresse, étiquette et `org_id` dans chaque condensé, transactions de type 2 seulement, clés propres à l'instance (CT-4 EX-4.8, CT-4 §6.6) ; une demande par position et échéance `expires_at` (CT-4 EX-8.19) ; contrôle du client avant toute politique (CT-4 EX-7.17) ; manifeste et adresses recoupés (CT-4 OP-1, CT-4 RG-19). | Refus `demande_existante` ou échec OP consigné (CT-4 §7.3). | Le dossier d'inscription n'est authentifié par personne en version 0 (CT-4 EX-7.8). Risque accepté RA-51. | le vecteur `ct-4/condenses.json` d'une signature d'une autre organisation est refusé ; si `orgId` sort du condensé, il est accepté et le test échoue. |
| MN-58 | Registre (validateurs, RPC, contrats, administrateur, gouvernance, trésorerie) | `deni_de_service` | Qui voit une empreinte avant son inclusion : horodateur, chemin RPC, intermédiaire. | Unicité de l'empreinte d'ancre au registre. | Il ancre l'empreinte le premier ; l'ancre légitime est refusée. | Ancre du registre envoyée avant la requête d'horodatage, attente bornée pour un point (CT-4 EX-8.4, CT-5 EX-4.7, CT-5 EX-9.6) ; aucun nouvel essai, incident consigné (CT-5 EX-9.7, CT-4 EX-8.6). | Statut `empreinte_squattee` (CT-5 §9). | Une empreinte liée à l'émetteur est seulement proposée (CT-4 §14). Risque accepté RA-52. | une trace du planificateur où l'empreinte est déjà ancrée aboutit à `empreinte_squattee` sans nouvel essai, incident consigné ; si l'ordre « ancre d'abord » ou l'arrêt des essais est retiré, la trace diffère et le test échoue. |
| MN-59 | Registre (validateurs, RPC, contrats, administrateur, gouvernance, trésorerie) | `alteration` | Un défaut du code d'un contrat, ou une réorganisation apparente de la chaîne. | Sens des journaux émis par les contrats (H7) et décision des blocs. | Une faille fait émettre ce qu'un attaquant veut ; un outil s'appuie sur une tête non décidée. | Aucune mise à niveau en place, redéploiement et nouvelle révision du manifeste (CT-4 EX-5.9, CT-4 EX-5.10, CT-4 EX-4.25) ; bloc décidé seulement par un certificat vérifié (CT-4 CP-4). | R-8 sur un dossier réparti entre deux générations de contrats (CT-6 R-8). | H7 n'est pas vérifiée par le vérificateur (CT-6 §3.5). Risque accepté RA-53. | le dossier `invalide-r8-autre-contrat` échoue à R-8 ; si l'adresse du contrat n'est plus comparée à l'ancre, il passe et le test échoue. |
| MN-60 | Composant d'ancrage, prestataires RFC 3161, calendriers OpenTimestamps | `alteration` | Un prestataire RFC 3161 malhonnête ou compromis, ou dont la clé est compromise. | `genTime` des jetons. | Il antidate ou postdate un jeton. | Contrôle de `genTime` à l'acquisition, qui marque le jeton sans le refuser (CT-5 EX-5.11) ; deux prestataires d'exploitants distincts, pour la continuité et non pour une confrontation de deux jetons (CT-5 EX-11.2) ; en version 0, aucun prestataire de secours utilisable n'est documenté (CT-5 EX-11.3) : la relève par le secours est le mécanisme prévu, elle n'opère qu'avec un secours conforme et joignable, et sans lui c'est le régime dégradé de RA-55 qui s'applique ; preuve OpenTimestamps sur chaque clôture, borne « au plus tard » seulement (CT-5 EX-6.2) ; révocation `keyCompromise` vue par T-10 (CT-6 T-10) ; second jeton d'un prestataire d'un autre exploitant proposé (CT-7 PA-19). | `horloge_suspecte` et alerte (CT-5 EX-5.11) ; `noortrace_anchoring_d_jeton_s` (CT-5 §8.9). | H4 n'est pas vérifiable ; un antidatage n'est borné par aucune autre ancre du dossier, Bitcoin ne donnant qu'une borne « au plus tard » (CT-6 §3.4). Risque accepté RA-54. | un jeton antidaté de moins de `clock_tolerance_s`, accepté sous H4, n'est contredit par aucune ancre du dossier et le rapport le dit borne « au plus tard » seulement ; la réponse `ct-5/reponses/` à `genTime` hors tolérance est promue et marquée `horloge_suspecte` ; si le marquage est retiré, le test échoue. |
| MN-61 | Composant d'ancrage, prestataires RFC 3161, calendriers OpenTimestamps | `alteration`, `usurpation` | Qui présente une pièce d'ancrage d'une autre donnée : jeton, preuve OpenTimestamps, chaîne d'en-têtes, attestation. | Lien entre une ancre et le `periodHash` ou le `checkpointHash` qu'elle doit porter. | Une ancre d'un autre manifeste, d'un autre point, d'une autre autorité ou d'un autre bloc passe pour celle de la période. | Nonce frais et égalité stricte à l'acquisition (CT-5 EX-5.3) ; T-2, T-5, T-7, O-2, O-4, O-5 sur l'empreinte recalculée (CT-6 T-2, CT-6 T-5, CT-6 T-7, CT-6 O-2, CT-6 O-4, CT-6 O-5) ; K-7 et K-9 pour un point (CT-1 K-7, CT-1 K-9) ; `non_execute` jamais compté comme réussi (CT-6 §6). | Statut `echoue` de la vérification au rapport (CT-6 §8.6). | Aucun au-delà des hypothèses H1 à H5 de CT-6. | les dossiers `invalide-t2-jeton-autre-manifeste`, `invalide-o2-preuve-autre-manifeste` et `invalide-k7-jeton-autre-empreinte` échouent à la vérification nommée ; si l'empreinte n'est plus recalculée, ils passent et le test échoue. |
| MN-62 | Composant d'ancrage, prestataires RFC 3161, calendriers OpenTimestamps | `deni_de_service` | Un calendrier OpenTimestamps, un agrégateur, ou un prestataire RFC 3161 injoignable longtemps. | Obtention des preuves de date. | Les preuves restent en attente ; la fenêtre de date s'allonge. | Au moins deux calendriers d'exploitants distincts, `min_responses`, abandon alerté (CT-5 EX-4.9, CT-5 EX-6.6, CT-5 EX-8.11) ; relève par le secours et file durable (CT-5 EX-5.7, CT-5 EX-8.5) ; en version 0, aucun prestataire de secours utilisable n'est documenté (CT-5 EX-11.3) : la relève est le mécanisme prévu, elle n'opère qu'avec un secours conforme et joignable, et sans lui c'est le régime dégradé de RA-55 qui s'applique ; une preuve en attente n'est jamais une preuve (CT-6 O-7). | Alerte `prestataire_injoignable` (aucun `obtenue` d'un prestataire sollicité depuis 15 min) et alerte « ancre en retard » au-delà de `anchor_pending_alert_s` (CT-5 §8.9) ; `upper_bound` du dossier (CT-6 §6.6). | Sans secours utilisable, ce qui est le régime de la version 0 (CT-5 EX-11.3), la fenêtre de réécriture pour la date se dégrade vers `3600 s + d` puis `n × 3600 s + d` (CT-5 §13) jusqu'au premier jeton obtenu ; pendant ce temps, la borne `c_T` plus `d_jeton` de RA-15 ne vaut pas. Risque accepté RA-55. | la trace `ct-5/planification/principal-injoignable.json`, où un secours de test (`qtsa-secours`) est configuré, produit les rejets consignés (`anchor_response_rejected`) et la relève (`anchor_fallback`) attendus ; le test éprouve le mécanisme et ne dit pas qu'un secours utilisable existe en version 0 (CT-5 EX-11.3) ; si la relève est retirée, la trace diffère et le test échoue. |
| MN-63 | Composant d'ancrage, prestataires RFC 3161, calendriers OpenTimestamps | `deni_de_service`, `repudiation` | Un composant d'ancrage compromis, qui tient les identifiants des prestataires. | Régularité de l'ancrage et abonnement du client. | Il cesse d'ancrer, fait horodater des empreintes quelconques, divulgue `checkpointHash`. | Aucune clé Ed25519 ni clé de chaîne dans le composant (CT-2 EX-11.19, CT-5 §3.4) ; moindre privilège (CT-2 EX-18.4) ; alerte de volume et rotation des identifiants (CT-5 §8.9, CT-7 §4.6) ; l'ancrage ne modifie jamais ce qu'il prouve (CT-5 EX-13.1). | Points attendus absents, `point_manquant`, `anchor_pending` (CT-5 §8.9). | Un arrêt de l'ancrage allonge la fenêtre RA-15 jusqu'à sa détection. Risque accepté RA-56. | la trace `point-manquant` de `ct-5/planification/` lève l'alerte attendue ; si la détection est retirée, la trace diffère et le test échoue. |
| MN-64 | Composant d'ancrage, prestataires RFC 3161, calendriers OpenTimestamps | `deni_de_service` | Une perte ou une corruption de la file d'ancrage. | Demandes d'ancrage en cours. | Des demandes sont oubliées. | Écriture avant envoi, `fdatasync`, reconstruction au démarrage, copie WORM des fichiers de file (CT-5 EX-8.5, CT-5 EX-8.12, CT-5 EX-8.14). | Alerte `file_perdue` et ligne `anchoring_queue_rebuilt` (CT-5 EX-8.12). | Une perte ne fait perdre que du temps, jamais un événement (CT-5 §13). | la trace `file-perdue` recrée les demandes manquantes ; si la reconstruction est retirée, la trace diffère et le test échoue. |
| MN-65 | Composant d'ancrage, prestataires RFC 3161, calendriers OpenTimestamps | `usurpation` | L'exploitant du client qui déclare qualifié un prestataire qui ne l'est pas, ou ne suit pas un retrait. | Statut « qualifié » de l'instantané d'acquisition. | Des jetons non qualifiés portent un instantané `qualified` faux. | Statut établi sur la liste de confiance, jamais sur une déclaration, ré-établi à chaque séquence et au plus tous les trente jours (CT-5 EX-5.9) ; constat fait par une personne et relu par une seconde (CT-7 EX-4.5) ; le réviseur établit lui-même le statut (CT-6 T-11). | Vérification du statut qualifié au vérificateur, avec le fichier d'ancres du réviseur (CT-6 T-11). | L'instantané reste déclaratif pour le réviseur (CT-5 EX-5.9). | une configuration de production sans principal qualifié est refusée par AN-1 ; si la règle 4 d'AN-1 est retirée, le rechargement passe et le test échoue. |
| MN-66 | Vérificateur et ancres de confiance du réviseur | `alteration`, `elevation_de_privilege` | Le fournisseur qui publie un vérificateur altéré, ou un environnement d'exécution compromis. | Verdicts rendus au réviseur. | Le réviseur exécute un code qui dit « valide » à tort. | Implémentation de référence publiée et relisible ; binaire reconstruit et comparé octet pour octet à partir de la phase 2 (CT-6 EX-14.6, CT-6 EX-14.8) ; vérificateurs indépendants confrontés sur les vecteurs (CT-6 §3.1). | Reconstruction et comparaison (CT-6 §14.3) ; confrontation des vecteurs. | En version 0, croire Node et `ethers`, que la spécification n'épingle pas (CT-6 §7.8). Risque accepté RA-57. | les vérificateurs Go indépendants de `ct-1` à `ct-5` rendent les mêmes valeurs que l'implémentation de référence sur leurs vecteurs ; une discordance fait échouer le test. |
| MN-67 | Vérificateur et ancres de confiance du réviseur | `usurpation` | Qui fournit au réviseur de fausses ancres, ou un dossier qui porte ses propres ancres. | Fichier d'ancres du réviseur (H3). | Le vérificateur rattache les preuves à une autorité, un contrat ou un jeu que le réviseur n'a pas choisi. | Aucune ancre tirée du dossier ni du réseau (CT-6 EX-3.3, CT-6 EX-3.4, CT-6 EX-12.1) ; recoupement des ancres par le réviseur (CT-6 §12.5) ; clés d'enregistreur prises dans un procès-verbal de cérémonie vérifié dont un signataire est connu du réviseur par un canal indépendant du client (CT-7 EX-5.10). | N-1 à N-4 au vérificateur (CT-6 N-3, CT-6 N-4). | H3 : le fichier d'ancres dit vrai (CT-6 §3.5). Risque accepté RA-58. | un dossier dont la clé de `cles.json` diffère de l'ancre `recorders` échoue à N-3 ; si N-3 est retirée, il passe et le test échoue. |
| MN-68 | Vérificateur et ancres de confiance du réviseur | `deni_de_service`, `elevation_de_privilege` | Qui fabrique un dossier, un jeton ou une réponse piégés pour l'analyseur. | Sûreté du vérificateur et du composant d'ancrage. | Longueurs, profondeur, octets en trop ou formes non minimales font paniquer, boucler ou mal lire. | Bornes, aucune récursion non bornée, cibles de fuzzing (CT-6 EX-15.1, CT-6 EX-15.2, CT-6 EX-15.3) ; corps de réponse bornés à l'acquisition (CT-5 EX-5.12). | Code 2 ou échec T-1 et O-1 au rapport (CT-6 §8.3). | Aucun au-delà des bornes de CT-6 §15.1. | les dossiers `invalide-t1-octet-en-trop` et `invalide-o1-octet-en-trop` échouent à T-1 et O-1 ; si la lecture DER redevient permissive, ils passent et le test échoue. |
| MN-69 | Vérificateur et ancres de confiance du réviseur | `alteration`, `usurpation` | L'exportateur qui forge les pièces du registre ou de la partie des points d'un dossier. | Pièces `registre.json`, `certificat-commit.json`, `validateurs.json` et `points-de-controle.json`. | Un certificat d'une autre chaîne, un en-tête ou un reçu falsifié, un événement d'un autre contrat, un point d'un autre arbre ou une ancre relabellisée passent pour ceux du dossier. | Recalcul de tout contre les ancres du réviseur : R-4, R-6, R-7, R-8, R-9, R-11 (CT-6 R-4, CT-6 R-6, CT-6 R-7, CT-6 R-8, CT-6 R-9, CT-6 R-11) ; K-1, K-4, K-5 et K-8 pour un point (CT-1 K-1, CT-1 K-4, CT-1 K-5, CT-1 K-8). | Statut `echoue` de la vérification nommée au rapport (CT-6 §8.6). | Aucun au-delà des hypothèses H1, H2, H6 et H7 de CT-6. | les dossiers `invalide-r4-autre-chaine`, `invalide-r6-entete-modifie`, `invalide-r7-recu-falsifie`, `invalide-r9-cloture-autre-periode`, `invalide-r11-ancre-de-periode` et `invalide-k8-empreinte` échouent à la vérification nommée ; si l'une est retirée, son dossier passe et le test échoue. |
| MN-70 | Vérificateur et ancres de confiance du réviseur | `alteration` | Le fournisseur d'en-têtes Bitcoin : l'exportateur, ou un mineur. | Chaîne d'en-têtes qui rattache une preuve OpenTimestamps au point de contrôle Bitcoin du réviseur. | Il mine au-dessus du point de contrôle autant de blocs que la chaîne fournie en contient. | Travail recalculé au-dessus du point de contrôle du réviseur et profondeur minimale (CT-6 O-5, CT-6 EX-10.9). | Échec O-5 au rapport (CT-6 §10.4). | H5 ne tient pas sur un réseau d'essai (CT-6 §3.5). Risque accepté RA-59. | le dossier `invalide-o5-chaine-sans-travail` échoue à O-5 ; si le travail n'est plus recalculé, il passe et le test échoue. |
| MN-79 | Vérificateur et ancres de confiance du réviseur | `usurpation`, `alteration` | L'exportateur qui joint l'attestation d'une autre organisation ou d'un autre journal. | Liaison de l'attestation au dossier. | Un périmètre étranger semble couvrir l'événement prouvé. | `org_id` et `journal_id` de l'attestation comparés à ceux de l'événement prouvé (CT-1 AT-5, CT-7 EX-7.16). | AT-5 en échec et avertissement AV-AT-1, sans effet sur le verdict (CT-6 EX-5.11, CT-6 §5.5). | Aucun. | dans le dossier `valide-at5-autre-journal`, AT-5 doit échouer et l'attestation ne pas être retenue ; si la comparaison du `journal_id` est retirée, elle est retenue et le test échoue. |
| MN-80 | Vérificateur et ancres de confiance du réviseur | `alteration` | L'exportateur qui joint une attestation expirée ou pas encore valide, ou l'opérateur qui réécrit `ts` avant l'ancrage. | Période de validité de l'attestation. | Une attestation hors de sa validité semble couvrir l'événement. | `ts` de l'événement prouvé compris dans `validity` (CT-1 AT-5) ; attestation renouvelée avant `validity.until` (CT-7 EX-7.5). | AT-5 en échec, AV-AT-1 (CT-6 EX-5.11). | `ts` est déclaratif (CT-1 §5.2) : qui réécrit `ts` avant l'ancrage le peut aussi pour AT-5, dans la fenêtre de réécriture (CT-1 §10.9). Risque accepté RA-69. | dans le dossier `valide-at5-hors-validite`, AT-5 doit échouer ; si le contrôle de `validity` est retiré, l'attestation est retenue et le test échoue. |
| MN-81 | Vérificateur et ancres de confiance du réviseur | `usurpation` | Qui présente une signature substituée, non canonique, ou d'une adresse hors du jeu ou hors des signataires nommés. | Signatures de l'attestation. | Une attestation semble signée par le jeu d'approbateurs. | Signature canonique recouvrée sur `M` et égale à l'adresse déclarée (CT-1 AT-3, CT-7 EX-7.6) ; adresses distinctes, membres du jeu, nommées dans `signatories`, au moins au seuil (CT-1 AT-4, CT-7 EX-7.8). | AT-3 ou AT-4 en échec, AV-AT-1 (CT-6 EX-5.11). | Aucun, sous H1 et H2 de CT-6. | les cas `invalide-at3-*` et `invalide-at4-*` de `ct-7/attestations/attestations.json` échouent chacun à la vérification visée ; si le recouvrement de l'adresse est retiré, la signature substituée passe et le test échoue. |
| MN-83 | Vérificateur et ancres de confiance du réviseur | `usurpation` | Qui présente comme signature d'attestation une signature produite pour un autre usage (approbation, inscription d'approbateur, procès-verbal de cérémonie, condensé du registre), ou l'inverse. | Séparation des domaines de signature. | Une signature obtenue ailleurs vaut attestation. | Préfixe propre `P_P`, Keccak-256 et non SHA-256 comme `D_A` (CT-7 EX-7.7) ; `D_P` recalculé par le signataire depuis le fichier, jamais signé par la console (CT-7 EX-7.8) ; préfixe distinct du procès-verbal (CT-7 EX-5.7). | AT-3 en échec (CT-1 AT-3). | Aucun, sous H1 de CT-6. | chaque signature croisée de `ct-7/attestations/croises.json` est refusée ; si la vérification compare l'adresse sans recalculer `D_P` depuis le fichier, une signature croisée passe et le test échoue. |
| MN-89 | Vérificateur et ancres de confiance du réviseur | `deni_de_service`, `alteration` | Qui fabrique une partie `attestation-perimetre.json` énorme ou malformée. | Disponibilité du vérificateur et stabilité du verdict. | Déni de service, ou verdict changé par une pièce jointe. | Limites de 4 Mio et de 2 097 152 octets décodés (CT-6 EX-4.15) ; au-delà de 4 Mio, la partie n'est lue, en flux, que pour D-2, jusqu'au plafond de 64 Mio au-delà duquel l'entrée est inutilisable (CT-6 EX-4.15) ; aucune AT- n'a d'effet sur les statuts ni sur le verdict (CT-6 EX-5.11, CT-6 V-10). | AT-1 en échec, AV-AT-1 (CT-1 AT-1). | Aucun. | les dossiers `valide-at1-partie-nulle` et `valide-at1-taille` gardent le verdict `valide` avec AT-1 en échec ; si l'exclusion des AT- du verdict est retirée, ils deviennent invalides et le test échoue. |
| MN-71 | Exploitant NOORTRACE | `usurpation`, `alteration` | L'exploitant NOORTRACE, qui publie le manifeste d'instance, sert le RPC et opère des validateurs. | Adresses de contrats, identifiant de chaîne et jeux de validateurs que le réviseur reprend. | Le réviseur reprend sans recoupement des adresses ou un jeu qui désignent un contrat ou des validateurs de l'exploitant. | Manifeste en révisions chaînées et publiées (CT-4 EX-4.25) ; recoupement par le réviseur avec les transactions de déploiement et un jeu obtenu d'au moins deux opérateurs indépendants (CT-6 §12.5, CT-4 RG-19) ; au plus f validateurs de l'exploitant en production (CT-4 EX-4.12). | Écart lors du recoupement (CT-6 §12.5). | Sans recoupement, la confiance du réviseur repose sur l'exploitant (CT-6 §3.4) ; les règles de calcul du contrôle 8 viennent du code privé de noorcore (CT-6 §7.8). Risque accepté RA-60. | le dossier `invalide-r4-autre-chaine` échoue quand l'identifiant de chaîne de l'ancre diffère ; si la comparaison est retirée, il passe et le test échoue. |
| MN-72 | Exploitant NOORTRACE | `divulgation` | Tout lecteur de la chaîne du registre : validateurs, partenaires, exploitant. | Métadonnées d'activité du client. | La cadence des ancres et des clôtures d'un `org_id` est lisible, et révèle le rythme d'activité de ses journaux. | Seules des empreintes de 32 octets et des clés publiques sont écrites (CT-4 §3.4) ; `org_id` et `journal_id` jamais envoyés aux prestataires (CT-5 §13) ; serveur interne pour les points si la cadence est jugée sensible (CT-5 §7). | Aucune : la lecture de la chaîne n'est pas tracée. | La cadence par organisation reste lisible par qui lit la chaîne. Risque accepté RA-61. | aucune transaction des vecteurs `ct-4/transactions.json` ne porte autre chose que des empreintes, des clés publiques et des identifiants ; si un champ de contenu apparaît, le test échoue. |
| MN-73 | Exploitant NOORTRACE | `elevation_de_privilege` | Un membre de l'exploitant qui relaie une administration de jeu ou approvisionne une clé sans l'accord du client. | Jeu du client et provision de ses clés. | Une opération d'administration est relayée pour le compte du client sans son accord. | Relais et approvisionnement seulement sur confirmation hors bande consignée (CT-4 EX-8.21) ; demande de changement d'administrateur consignée par procès-verbal (CT-7 EX-5.1). | Événements publics du jeu sondés par le client (CT-4 EX-8.12). | La confirmation hors bande est un acte d'exploitation déclaré. Risque accepté RA-62. | l'outil de référence refuse `administrer-jeu` sans référence de confirmation ; si la référence n'est plus exigée, le test échoue. |
| MN-97 | Exploitant NOORTRACE | `alteration`, `usurpation` | Qui altère l'outil de référence publié par l'exploitant NOORTRACE (`attestation.mjs`, `ceremonie.mjs`) ou le poste qui l'exécute. | Condensé que le signataire croit signer (`D_P`, `D_C`). | L'outil affiche un condensé et en fait signer un autre ; une attestation ou un procès-verbal que le signataire n'a pas lu porte sa signature. | Comparaison du condensé, groupe de huit chiffres par groupe de huit, entre l'écran du portefeuille matériel et un second outil indépendant ; avec un fichier de clé, recalcul obligatoire par ce second outil (CT-7 EX-5.8, CT-7 EX-7.8) ; modes `condenser` et `condenser-pv` du vérificateur Go de `ct-7` (CT-7 EX-A.21). | Écart constaté par la comparaison ; recalcul de `D_P` par AT-2 et de `D_C` par le vérificateur de procès-verbal chez le réviseur (CT-1 AT-2, CT-7 EX-5.9). | Un signataire qui ne compare pas signe ce que l'outil lui présente. Risque accepté RA-81. | un outil modifié pour faire signer un autre condensé est arrêté par la comparaison au second outil ; si la comparaison est retirée, la signature est produite et le test échoue. |
| MN-74 | Administrateur du client | `repudiation`, `alteration` | L'administrateur du client, qui exploite l'enregistreur et exporte les dossiers. | Dossiers remis au réviseur et attestation de périmètre. | Il fabrique un journal faux avant la clôture, choisit les voisins, les pièces et le point qu'il exporte, ne produit pas un dossier défavorable, déclare un périmètre plus large que le vrai. | Ancres extérieures de la période et des points (CT-6 §3.4, CT-1 §10.9) ; série des points publiée au réviseur (CT-5 §10.2) ; attestation de périmètre signée par des membres du jeu, rapportée « déclaré par » (CT-7 §7). | Série des points et complétude au registre (CT-5 EX-10.7) ; recoupement de l'attestation par le réviseur. | Ce qui est fabriqué avant l'ancre est ancré tel quel ; l'attestation reste une déclaration. Risque accepté RA-63. | un dossier dont la partie des points embarque un point qui ne couvre pas l'événement échoue à K-4 ; si K-4 est retirée, il passe et le test échoue. |
| MN-75 | Administrateur du client | `deni_de_service`, `repudiation` | L'administrateur du client qui coupe la supervision, les alertes ou la relecture des gels. | Détection des incidents de 17.4 de CT-2. | Les alertes ne partent plus ; un incident passe inaperçu. | Relecture par un rôle Lecteur hors du démon (CT-2 EX-17.7, CT-2 EX-18.9) ; métriques publiques sur la santé (CT-2 EX-17.1) ; le réviseur demande la série des points (CT-5 §10.2). | Trou dans la série des points et dans `noortrace_worm_last_audit_age_s` (CT-2 §17.4). | Une supervision coupée par qui la tient n'est vue que par un tiers. Risque accepté RA-64. | la relecture quotidienne par le Lecteur alerte sur une version d'un gel actif qui n'est pas `on` ; si la relecture n'est faite que par le démon, le test échoue. |
| MN-78 | Administrateur du client | `repudiation`, `alteration` | L'administrateur du client et les approbateurs qui signent une attestation de périmètre plus large que la réalité. | Ce que le réviseur croit du périmètre de capture. | Un réviseur croit que tout passe par l'enregistreur alors qu'un canal le contourne. | Le périmètre est rapporté « déclaré, non prouvé » et n'est jamais compté parmi ce que le dossier prouve (CT-7 EX-7.1, CT-7 EX-7.17, CT-6 EX-6.19, CT-6 EX-7.3) ; signataires nommés, membres du jeu, au moins au seuil (CT-7 EX-7.8, CT-1 AT-4) ; toute sortie `direct` déclarée dans `not_captured` (CT-7 EX-7.4) ; essai de sortie annuel (CT-7 EX-3.13). | Essai d'exfiltration, au mieux par un évaluateur indépendant (CT-7 EX-3.13) ; journal des refus du pare-feu (CT-2 §4.9) ; l'énoncé et `facts.perimeter` nomment les signataires (CT-6 EX-6.20). | Une déclaration fausse et signée reste fausse : le dossier ne la corrige pas (CT-7 §7.8). Risque accepté RA-68. | sur tous les rapports des vecteurs, aucun énoncé n'applique « prouvé » ou « vérifié » au périmètre et chaque fragment FP contient « déclaré, non prouvé » ; si la règle d'EX-6.19 de CT-6 est retirée, un énoncé dit le périmètre vérifié et le test échoue. |
| MN-82 | Administrateur du client | `usurpation`, `elevation_de_privilege` | L'exportateur qui déclare dans `approver_set` un jeu qui contient sa propre adresse. | Jeu d'approbateurs auquel AT-4 compare les signataires. | Une attestation signée par un tiers paraît atteindre le seuil. | Jeu déclaratif nommé avec sa source dans l'énoncé et dans `facts.perimeter.set_source` (CT-7 EX-7.17, CT-6 EX-6.20) ; avertissement AV-AT-2 quand il diffère du jeu de `approbations.json` (CT-6 §5.5). | AV-AT-2 ; recoupement par le réviseur avec le `CuratorSet` de l'organisation et l'historique de ses `CuratorSetAssigned`, du jeu épinglé par la politique (CT-3 EX-8.6) jusqu'à la date des signatures, toute réassignation intervenue entre-temps étant signalée (CT-7 EX-7.13). | Le jeu de l'attestation est déclaré par le dossier, comme celui du contrôle 7 (CT-6 §3.3). Risque accepté RA-70. | le dossier `valide-at4-jeu-different` porte AV-AT-2 ; si l'avertissement est retiré, le rapport ne le porte plus et le test échoue. |
| MN-86 | Administrateur du client | `repudiation`, `alteration` | L'administrateur du client qui rédige et inscrit l'attestation après l'événement qu'elle prétend couvrir. | Rang de l'attestation dans le journal. | Couverture rétroactive d'un incident. | `seq` de l'inscription au plus celui de l'événement prouvé (même `hash` recalculé en cas d'égalité), et `ts` au plus le sien (CT-1 AT-6, CT-7 EX-7.13). | AT-6 en échec, AV-AT-1 (CT-6 EX-5.11). | Sans inscription, la menace se ramène à MN-85 (RA-72) ; avec une inscription sous une autre clé que celle de l'événement prouvé, à MN-90. | dans le dossier `valide-at6-inscription-posterieure`, AT-6 doit échouer ; si la comparaison des `seq` est retirée, l'attestation est retenue et le test échoue. |
| MN-87 | Administrateur du client | `divulgation` | Tout destinataire d'un dossier qui porte l'attestation et, au choix du client, son inscription. | Topologie, noms d'hôtes, routes et politique du client. | Fuite d'information vers chaque réviseur. | Ni secret, ni adresse IP, ni contenu des règles de sortie dans l'attestation, refus par l'outil de référence (CT-7 EX-7.3) ; inscription jointe au choix du client (CT-7 EX-7.14). | Relecture de l'attestation avant sa signature (CT-7 §7.4, pas 3 et 5). | Ce que l'attestation porte est divulgué à chaque réviseur. Risque accepté RA-73. | l'outil de référence refuse une adresse IPv4 dans `host` ; si le refus est retiré, l'attestation est acceptée et le test échoue. |
| MN-88 | Administrateur du client | `repudiation` | L'administrateur du client dont le périmètre change pendant la validité de l'attestation (agent ajouté, règle de sortie modifiée). | Exactitude de l'attestation en vigueur. | L'attestation en vigueur devient fausse sans que rien ne le signale. | Nouvelle attestation dès qu'un élément déclaré change (CT-7 EX-7.5) ; consignes et métrique d'échéance proposées à CT-2 (CT-7 PA-10, CT-7 PA-11). | Consigne `perimeter_unlisted_host` et métrique d'échéance, une fois PA-10 et PA-11 adoptées ; essai de sortie annuel (CT-7 EX-3.13). | Jusqu'à l'attestation suivante, l'inventaire peut être périmé. Risque accepté RA-74. | une fois PA-10 adoptée, une connexion d'hôte dont l'alias manque à l'inventaire produit la consigne ; si la consigne est retirée, rien n'est écrit et le test échoue. |
| MN-91 | Administrateur du client | `alteration`, `repudiation` | L'administrateur du client qui réannonce, sous un nom de version déjà employé, une politique au contenu différent. | Lien entre l'attestation inscrite et la version de politique de l'événement prouvé. | AT-7 réussit alors que l'attestation inscrite n'était plus en vigueur pour l'événement. | AT-7 ne compare que des noms, et FP dit « de même nom », jamais que l'attestation était en vigueur (CT-1 AT-7, CT-6 EX-6.19) ; unicité des noms de version proposée à CT-2 (CT-7 PA-9). | Deux événements `noortrace.journal.politique` de même `policy_version` et de `policy_sha256` différents, visibles dans le journal (CT-1 §5.1) ; `same_policy_version` de `facts.perimeter.inscription` (CT-6 EX-6.20). | Tant que PA-9 n'est pas adoptée, la vigueur de l'attestation pour l'événement n'est pas établie par AT-7. Risque accepté RA-75. | le dossier `valide-at7-nom-reannonce` fait réussir AT-7 et son FP ne dit que « même nom » ; si FP affirme la vigueur de l'attestation, le test échoue. |
| MN-96 | Administrateur du client | `repudiation`, `alteration` | L'administrateur du client, qui a les droits d'exploitation de l'hôte de l'enregistreur. | Journal d'exploitation : lignes `startup`, `config_reloaded`, `lease_*`, `clock_*` et `worm_*` (CT-2 EX-17.2). | Il redémarre l'enregistreur ou passe `model.mode` en `desactive`, membre hors `policy`, puis efface les lignes qui le montrent ; aucune trace ne reste hors de la chaîne. | Changements de `policy` annoncés dans la chaîne (CT-2 EX-9.2) ; copie WORM des fichiers tournés du journal d'exploitation, relue hors du démon par le rôle Lecteur, proposée à CT-2 (CT-7 PA-18). | Aucune en version 0 ; une fois PA-18 adoptée, discontinuité de la série copiée, signalée par un avertissement. | Tant que PA-18 n'est pas adoptée, un changement hors `policy` et un redémarrage de moins de `c_K` n'ont aucune trace que l'administrateur ne puisse effacer. Risque accepté RA-80. | une ligne effacée du journal d'exploitation de la démonstration de référence est détectée par comparaison à sa copie WORM ; sans la copie, l'effacement passe inaperçu et le test échoue. |
| MN-98 | Administrateur du client | `repudiation` | Le client qui, une fois PA-8 adoptée, choisit de ne pas inscrire l'attestation ou de ne pas joindre l'inscription. | Date et rang de l'attestation. | Une attestation rédigée après coup paraît couvrir l'événement. | Inscription exigée dès que l'enregistreur sait la porter (CT-7 EX-7.5) ; clause fixe « non inscrite au journal (ni sa date ni son rang ne sont établis) » de FP (CT-6 EX-6.19). | `facts.perimeter.inscription` nul dans le rapport (CT-6 EX-6.20) ; clause de FP. | Le réviseur décide, en lisant la clause, de ce que vaut une attestation non située. Risque accepté RA-82. | le dossier `valide-seq-7-complet-attestation` de `ct-6` porte la clause « non inscrite au journal » dans son énoncé ; si la clause est retirée, l'énoncé ne dit plus que l'attestation n'est pas située et le test échoue. |
| MN-76 | Réseau | `divulgation`, `deni_de_service` | Un intermédiaire réseau entre l'enregistreur et un prestataire, un calendrier, le registre, un serveur d'outils ou un fournisseur. | Confidentialité et délai des échanges sortants. | Il lit, retarde ou coupe le trafic ; il voit une empreinte avant son inclusion. | TLS vérifié vers les prestataires (CT-5 EX-5.5) et les amonts (CT-2 EX-4.40) ; condensé OpenTimestamps masqué par un nonce (CT-5 EX-6.2) ; réponses tardives rejetées (CT-5 EX-5.11) ; ancre au registre d'abord (CT-5 EX-4.7) ; l'ancrage ne bloque jamais (CT-2 §14.2). | Délais et erreurs consignés (CT-5 §8.9, CT-2 EX-17.2). | Retarder allonge la fenêtre ; une empreinte vue peut être prise au registre (RA-52) ; un prestataire voit la cadence d'un compte (CT-5 §13). Risque accepté RA-65. | une réponse RFC 3161 reçue au-delà de `max_response_delay_s` est classée `reponse_tardive` ; si la fraîcheur n'est plus contrôlée, elle est promue et le test échoue. |
| MN-77 | Réseau | `divulgation`, `usurpation` | Un tiers sur le réseau entre l'hôte, le démon, le service d'approbation et la console. | Jetons d'hôte, décisions du service, sessions de la console. | Il lit un jeton, répond à la place du service, vole une session. | Prises locales ou TLS, jetons comparés en temps constant (CT-2 EX-18.3) ; canal du service authentifié par mTLS ou jeton et TLS hors boucle locale (CT-3 EX-12.2, CT-2 EX-18.8) ; console en HTTPS, réauthentification récente (CT-3 EX-13.8) ; certificats TLS inventoriés et tournés (CT-7 §4.2). | `auth_failed` (CT-2 EX-18.3) ; `approval_response_invalid` (CT-2 EX-17.2). | Aucun au-delà de la garde des certificats et des jetons (RA-39). | une réponse du service reçue sur un canal non authentifié est traitée comme une indisponibilité ; si l'authentification du canal est retirée, la réponse est appliquée et le test échoue. |

### 3.5 Risques acceptés

Un risque accepté est **nommé** (RA-<n> et son nom), **borné** (la colonne
« Borne » dit jusqu'où, sur quel périmètre ou pendant combien de temps) et
**attribué** (la colonne « Porté par » dit qui l'accepte et le surveille). Les
risques portés par le client sont ceux qu'il accepte en déployant NOORTRACE ;
ceux portés par l'exploitant NOORTRACE engagent son exploitation du registre ou
la publication de l'enregistreur et des spécifications (RA-72) ; ceux portés par
le réviseur dépendent de ses ancres. La publication de l'enregistreur ne fait
porter à l'exploitant NOORTRACE que RA-72 ; elle ne lui transfère pas RA-22, le
risque d'une image malveillante, porté par le client (3.4).

Dans la colonne « Risque résiduel » de 3.4, « Aucun » signifie qu'aucun risque
ne reste. « Aucun au-delà des hypothèses Hn de CT-6 » signifie que ce qui reste
est une hypothèse de CT-6, portée par le réviseur (3.6), et non un risque
accepté RA-. Les deux formes se lisent « aucun » au sens d'EX-9.1.

**EX-3.5** La liste des risques acceptés portés par le client DOIT être
remise au client avant sa mise en production, avec la menace et la borne de
chacun ; l'attestation de périmètre (section 7) PEUT y renvoyer dans ses
exceptions connues.

| Id | Risque | Borne | Porté par | Menaces |
|---|---|---|---|---|
| RA-1 | Complétude non prouvable par la chaîne | Bornée aux voies que le pare-feu déclaré laisse ouvertes et aux exceptions listées dans l'attestation de périmètre | client | MN-1 |
| RA-2 | Délégation déclarée par l'hôte | Limitée à `run_id` et `on_behalf_of`, que ni la politique ni le contrôle 7 ne lisent | client | MN-2 |
| RA-3 | Fractionnement non détecté en ligne | Borné par les règles et les plafonds de fenêtre que le client écrit ; visible à la revue | client | MN-3 |
| RA-4 | Liste d'exclusion contournable | Limitée aux règles `egal` ou `dans` sous un refus, que la validation signale | client | MN-4 |
| RA-5 | Harcèlement des approbateurs sous le plafond | Au plus `max_open_tickets` tickets ouverts par demandeur (20 par défaut) | client | MN-6 |
| RA-6 | Effets déclarés, non constatés | Limité au comportement du serveur d'outils derrière un nom et une définition empreints | client | MN-7 |
| RA-7 | Hôte local de confiance | Limité aux membres du groupe de la prise et aux détenteurs d'un jeton statique en cours de validité | client | MN-8 |
| RA-8 | Évasion du bac à sable d'un serveur stdio | Limitée aux droits de l'utilisateur distinct de `transport.user`, sans droit sur `storage.root` ni sur les secrets | client | MN-9 |
| RA-9 | Issue inconnue après panne | Une intention au plus par appel en vol au moment de la panne, signalée par l'événement de reprise | client | MN-10 |
| RA-10 | Clé de fournisseur hors de la passerelle | Limitée aux clés que le client n'a pas inventoriées dans l'attestation de périmètre | client | MN-11 |
| RA-11 | Exécution côté fournisseur | Limitée aux routes où la configuration admet les serveurs MCP du fournisseur | client | MN-13 |
| RA-12 | Capture du modèle en lecture seule ou absente | Limitée aux journaux dont la configuration nomme `miroir` ou `desactive` | client | MN-14 |
| RA-13 | Déclaration d'un agent compromis | Limitée aux outils de préfixe d'un alias du SDK, que le pare-feu borne à ce que l'agent peut joindre | client | MN-15 |
| RA-14 | Spans fabriqués par une source authentifiée | Limités au préfixe de la source et à ses quotas | client | MN-16 |
| RA-15 | Fenêtre de réécriture | Au plus `c_T` plus `d_jeton` (300 s plus le délai du jeton par défaut, CT-5 P-3) avec un prestataire extérieur pour les points ; une heure plus le délai du jeton sans points ; pendant une panne des prestataires sans secours utilisable, la borne dégradée de RA-55 (CT-5 §13) | client | MN-17 |
| RA-16 | Omission par l'enregistreur | Limitée aux actes dont aucun autre système du client ne garde trace | client | MN-18 |
| RA-17 | Magasin de bail compromis | Limité à l'intervalle avant le contrôle après écriture d'EX-13.10 de CT-2 | client | MN-19 |
| RA-18 | Horodatage déclaré par l'enregistreur | Écart au plus `clock_tolerance_s` (120 s par défaut) avant alerte ; toute date prouvée vient des ancres | client | MN-21 |
| RA-19 | Accès aux pièces par l'administrateur du client | Limité aux personnes à qui le client donne l'accès au volume | client | MN-22 |
| RA-20 | Configuration d'exploitation hors de la chaîne | Jusqu'à l'adoption de PA-2 ; face à l'administrateur, un changement hors `policy` n'a aucune trace hors de PA-1 et PA-2, la ligne `config_reloaded` pouvant être effacée (RA-80) ; les changements de `policy` restent annoncés (CT-2 EX-9.2) | client | MN-23 |
| RA-21 | Connivence au coffre | Limitée aux deux personnes que le client désigne pour chaque accès | client | MN-24 |
| RA-22 | Enregistreur sur le chemin | Limité au trafic que le démon relaie, à ses secrets en mémoire et à la fenêtre RA-15 | client | MN-25 |
| RA-23 | Administrateur du compte du support | Limité au compte qui porte le support ; une politique d'organisation le lie | client | MN-27 |
| RA-24 | Séparation pose et levée non garantie par le support | Limitée aux supports d'EX-12.34 de CT-2 sans séparation des droits, et à la fenêtre d'un jour de la relecture | client | MN-28 |
| RA-25 | Segment non encore copié | Au plus un segment courant plus le délai d'alerte d'une heure | client | MN-29 |
| RA-26 | Graine en mémoire en classe C | Limitée aux journaux en classe C ; la fenêtre RA-15 borne ce qu'une clé copiée réécrit | client | MN-30 |
| RA-27 | Usage du signataire entre deux rapprochements | Au plus l'intervalle de rapprochement (un mois) pour la découverte, la fenêtre RA-15 pour l'effet | client | MN-31 |
| RA-28 | Pouvoir propre de l'administrateur du backend | Limité aux backends sans contrôle multipartite natif ; vu à la revue des journaux d'audit | client | MN-32 |
| RA-29 | Rupture de journal à la perte de la clé | Un journal rompu par perte, lien consigné au registre et au journal d'exploitation | client | MN-33 |
| RA-30 | Capacité restante d'une clé de chaîne compromise | Le solde résiduel de la clé, borné par `P_k`, et le délai de révocation (4 h visé, ou le délai mesuré par l'exercice de CT-7 EX-3.12 s'il est supérieur) | client | MN-34 |
| RA-31 | Clé d'approbateur exposée dans la page | Limitée aux approbateurs qui emploient le parcours par fichier de clé ; le seuil exige d'autres signatures | client | MN-35 |
| RA-32 | Identité des membres déclarée | Limitée à ce que le témoin a constaté, nommé dans le procès-verbal | client | MN-36 |
| RA-33 | Prise du jeu par la clé de gouvernance | Un journal rendu inachevable, remplacé par un nouveau nom ; collusion d'au moins `required` membres pour la variante de connivence | client | MN-37 |
| RA-34 | Déni de service par réassignation | Jusqu'à la publication d'une nouvelle version de politique par l'organisation ; public sur la chaîne. Une attestation de périmètre ou une inscription de clé de chaîne signée par le jeu réassigné vaut tant que le réviseur ne recoupe pas l'historique des `CuratorSetAssigned` (CT-7 EX-7.13) ; voir aussi RA-48 | exploitant NOORTRACE | MN-38 |
| RA-35 | Clé de validateur en fichier | Au plus f validateurs par opérateur et par site ; H6 de CT-6 | opérateur de validateur | MN-39 |
| RA-36 | Compte chaud de trésorerie | Le plafond `fees.max_daily_budget_gas` par jour, puis le solde du compte d'approvisionnement | exploitant NOORTRACE | MN-40 |
| RA-37 | Identifiant de prestataire volé | Le débit de l'abonnement jusqu'à la révocation chez le prestataire | client | MN-41 |
| RA-38 | Jeton interne contre l'opérateur | Limité aux points contresignés par le serveur interne ; la clôture reste qualifiée | client | MN-42 |
| RA-39 | Secret de service divulgué | Jusqu'à la rotation prévue en 4.6 pour ce secret | client | MN-43 |
| RA-40 | Service d'approbation compromis | Limité aux réponses non signées et au jeu déclaré ; jamais une décision `approuve` sans signatures valides du jeu remis | client | MN-44 |
| RA-41 | Signature à l'aveugle d'un condensé de 32 octets | Limitée aux demandes réellement retenues de l'organisation et aux approbateurs qui ne comparent pas l'empreinte, en deux cas : (a) quand `required` ≥ 2 et qu'au moins un des signataires qui forment le seuil compare l'empreinte, la signature à l'aveugle des autres ne suffit pas, et une demande ne passe qu'avec la signature de ce signataire ; (b) quand `required` = 1, ou quand aucun signataire du seuil ne compare, la seule borne est l'ensemble des demandes retenues de l'organisation (voir aussi RA-44) | client | MN-45 |
| RA-42 | Extension malveillante du navigateur | Limitée au poste de l'approbateur, aux demandes retenues et au déni de service | client | MN-46 |
| RA-43 | Déni de service sur l'annuaire | Limité à l'état `en_attente` ou à la révocation d'une adresse, visible dans `operations`, sans effet sur le jeu figé | client | MN-47 |
| RA-44 | Collusion ou contrainte des approbateurs | Au moins `required` membres distincts, chacun attribuable par sa signature | client | MN-48 |
| RA-45 | Membres ajoutés pendant l'attente | Visibles sur la chaîne et signalés ; le nombre de signatures exigé ne baisse pas | client | MN-50 |
| RA-46 | Lecture d'état non prouvée | Limitée au nœud que le service interroge ; nulle si ce nœud est un validateur que le client opère | client | MN-51 |
| RA-47 | Relais du parcours mobile | Limité aux organisations qui activent le parcours c | client | MN-52 |
| RA-48 | Exploitant du registre hostile | Un journal par organisation visée, remplacé par un nouveau nom ; visible sur la chaîne | exploitant NOORTRACE | MN-53 |
| RA-49 | Quorum de validateurs fautif | H6 de CT-6 : au plus f fautifs sur N ≥ 3f + 1 | opérateur de validateur | MN-54 |
| RA-50 | Saturation de la mempool | Retard des ancres au registre, jamais un blocage d'appel ; les autres ancres restent | exploitant NOORTRACE | MN-55 |
| RA-51 | Dossier d'inscription non authentifié | Limité à l'inscription, que le client contrôle avant toute politique | client | MN-57 |
| RA-52 | Empreinte prise | La période ou le point visé perd son ancre au registre ; les ancres RFC 3161 et Bitcoin restent | client | MN-58 |
| RA-53 | Code des contrats non vérifié (H7) | Limité au sens donné aux journaux émis ; sans H7, le contrôle 8 établit encore l'émission dans un bloc certifié | exploitant NOORTRACE | MN-59 |
| RA-54 | Autorité d'horodatage menteuse (H4) | Un antidatage n'est borné par aucune autre ancre : la preuve OpenTimestamps ne donne qu'une borne « au plus tard », et le registre ne date rien (CT-6 §3.4). Une postdatation ne fait qu'affaiblir la borne « au plus tard », que le contrôle 5 resserre. Le contrôle d'acquisition (CT-5 EX-5.11) protège seulement un client honnête contre un prestataire qui le trompe de plus de `clock_tolerance_s`, et il marque le jeton sans le refuser | réviseur | MN-60 |
| RA-55 | Ancrage dégradé | La fenêtre de réécriture pour la date, dégradée vers `3600 s + d` puis `n × 3600 s + d` (CT-5 §13), affichée par `noortrace_anchoring_window_s` et montrée par `upper_bound` du dossier ; rien n'est caché au réviseur | client | MN-62 |
| RA-56 | Arrêt de l'ancrage par un composant compromis | Jusqu'à l'alerte d'ancre en retard (deux heures au plus, CT-2 §17.4) | client | MN-63 |
| RA-57 | Environnement du vérificateur non épinglé | Jusqu'à la livraison du binaire reproductible de la phase 2 | réviseur | MN-66 |
| RA-58 | Fichier d'ancres du réviseur (H3) | Limité à ce que le réviseur n'a pas recoupé selon CT-6 §12.5 | réviseur | MN-67 |
| RA-59 | Puissance de calcul de l'adversaire (H5) | Le nombre de blocs fournis au-dessus du point de contrôle du réviseur ; nul sur un réseau d'essai | réviseur | MN-70 |
| RA-60 | Règles de noorcore non recoupables publiquement | Le seul contrôle 8 ; la confrontation à go-ethereum couvre la racine des reçus et le décodage des journaux | exploitant NOORTRACE | MN-71 |
| RA-61 | Cadence d'activité lisible au registre | Nombre et instants des transactions par `org_id`, jamais leur contenu | client | MN-72 |
| RA-62 | Relais sans accord du client | Limité aux opérations que la clé de gouvernance a signées ; visibles sur la chaîne | exploitant NOORTRACE | MN-73 |
| RA-63 | Opérateur qui fabrique avant l'ancre ou déclare à tort | Avant le jeton du point couvrant (RA-15) ; l'attestation engage ses signataires nommés | client | MN-74 |
| RA-64 | Supervision coupée par l'administrateur | Jusqu'à la relecture du Lecteur tiers (un jour) ou la demande du réviseur | client | MN-75 |
| RA-65 | Retard et observation par le réseau | La fenêtre de date s'allonge du retard ; seules des empreintes de 32 octets circulent vers les prestataires | client | MN-76 |
| RA-66 | Changement d'état de l'enregistreur hors de la chaîne | Un trou de plus de `c_K` (60 s par défaut) dans la série des points est visible par qui lit la série ; un redémarrage de moins de `c_K` n'en laisse aucun, et face à l'administrateur il n'a aucune trace hors de PA-1 et PA-18 (RA-80) | client | MN-26 |
| RA-67 | Événements non synchronisés perdus à la panne | Les seuls événements de la validation groupée en cours (CT-2 EX-12.7), dont aucun n'a reçu de réponse ni produit d'effet d'écriture sans intention durable | client | MN-20 |
| RA-68 | Périmètre faux mais signé | Borné à la période `validity` et aux journaux nommés ; les signataires nommés en répondent | client | MN-78 |
| RA-69 | Validité jugée sur un `ts` déclaré | La fenêtre de réécriture de RA-15 | client | MN-80 |
| RA-70 | Jeu d'approbateurs de l'attestation déclaré | Limité à ce que le dossier déclare ; le jeu et sa source sont nommés dans l'énoncé | réviseur | MN-82 |
| RA-71 | Inscription réécrite par qui tient la clé | La fenêtre de réécriture de RA-15, sur l'événement d'inscription | client | MN-84 |
| RA-72 | Attestation non située dans le journal | Limité aux dossiers sans inscription, jusqu'à l'adoption de PA-8 par CT-2, que l'exploitant NOORTRACE suit au titre de la publication de l'enregistreur et des spécifications ; ensuite, RA-82 | exploitant NOORTRACE | MN-85 |
| RA-73 | Divulgation du périmètre déclaré | Limitée aux membres de l'attestation et, si le client le joint, au document de politique | client | MN-87 |
| RA-74 | Inventaire périmé | L'intervalle entre le changement et l'inscription de l'attestation suivante, collecte des signatures comprise, au plus la validité, que AT-1 limite à 366 jours (CT-1 AT-1, CT-7 EX-7.2) | client | MN-88 |
| RA-75 | Nom de version de politique réannoncé | Jusqu'à l'adoption de PA-9 par CT-2 ; limité aux dossiers dont l'inscription porte un nom de version réannoncé, ce que le journal montre ; FP ne dit que « même nom » | réviseur | MN-91 |
| RA-76 | Procès-verbal sans signataire indépendant | Limité aux procès-verbaux dont aucun signataire n'est connu du réviseur par un canal indépendant du client ; aucune ancre n'en est tirée (CT-7 EX-5.10) | client | MN-92 |
| RA-77 | Date déclarée du procès-verbal | Sans ancre de `D_C`, la date est déclarée ; avec une ancre, l'antidatage est borné par la date du jeton ou de l'inscription au registre (CT-7 EX-5.11) | réviseur | MN-93 |
| RA-78 | Restauration hors cérémonie | Limité aux clés sauvegardées (4.4) ; une restauration hors cérémonie ne se voit qu'à l'usage de la clé restaurée (4.7) | client | MN-94 |
| RA-79 | Détenteurs de part déclarés distincts | Limité aux sauvegardes partagées ; la distinction des personnes est un constat déclaré du témoin (5.9) | client | MN-95 |
| RA-80 | Journal d'exploitation effaçable | Jusqu'à l'adoption de PA-18 par CT-2 ; un changement hors `policy` et un redémarrage de moins de `c_K` n'ont aucune trace hors du journal d'exploitation | client | MN-96 |
| RA-81 | Outil de condensation non recoupé | Limité aux signatures faites sans comparaison du condensé à un second outil indépendant (CT-7 EX-5.8, CT-7 EX-7.8) | client | MN-97 |
| RA-82 | Attestation non inscrite par choix du client | Après l'adoption de PA-8 : limité aux dossiers dont l'attestation n'est pas inscrite ou dont l'inscription n'est pas jointe ; FP le dit (CT-6 EX-6.19) et le réviseur en décide | client | MN-98 |

Grandeurs des bornes (3.3, MN-17, MN-26, MN-62 ; RA-15, RA-55, RA-56, RA-66),
reprises de CT-5 :

- `c_K` : cadence de production des points de contrôle
  (`checkpoint_interval_s`, 60 s par défaut ; CT-5 §0, P-1) ;
- `c_T` : cadence des contresignatures RFC 3161 des points
  (`rfc3161.checkpoints.interval_s`, 300 s par défaut ; CT-5 P-3) ;
- `d_jeton` : délai d'obtention du jeton, `genTime + précision − D_k` mesuré,
  qui se décompose en `d_point + d_attente + d_relève + d_tsa` (CT-5 EX-3.5) ;
- `d` : délai d'obtention de l'ancre, entre une échéance et l'instant que
  l'ancre prouve (CT-5 §2) ;
- `n` : dans la borne dégradée `n × 3600 s + d` de CT-5 §13, le nombre de
  périodes d'une heure écoulées jusqu'au premier jeton obtenu ; CT-5 ne le nomme
  que par cette formule. `n` se compte à partir de la période qui contient
  l'événement (`n` = 1 quand la clôture de cette période obtient son jeton) ; la
  valeur atteinte se lit sur `noortrace_anchoring_window_s`, qui en affiche la
  borne courante, et, pour un événement donné, sur `upper_bound` du dossier
  (RA-55).

La progression de la borne dégradée se lit ainsi : sans jeton sur les points,
seule la clôture horaire de la période peut dater une réécriture, et la borne
devient `3600 s + d` ; tant que la clôture reste sans jeton et est réessayée,
chaque heure ajoute 3600 s, d'où `n × 3600 s + d` (CT-5 §13). `d_jeton` n'est
pas un réglage mais une mesure, affichée par `noortrace_anchoring_d_jeton_s`
(CT-5 §8.9). RA-15 et RA-55 bornent la date par le jeton RFC 3161. Une preuve
OpenTimestamps de la clôture reste une ancre indépendante (contrôle 5) : la
création du bloc Bitcoin termine aussi la fenêtre, sans que son instant soit
prouvé (CT-1 §10.9), et CT-7 n'en tire aucune borne plus serrée. Une panne des
seuls calendriers OpenTimestamps ne touche pas la borne RFC 3161.

Seuils des alertes d'ancrage (MN-62, RA-56) : `queue.anchor_pending_alert_s`
vaut 7200 s par défaut (CT-5 §4.4) ; ce sont les deux heures de RA-56, celles
de l'alerte « Ancre en retard » de CT-2 §17.4. `prestataire_injoignable` est
une alerte plus précoce, propre à chaque prestataire, levée quand aucun
`obtenue` n'est venu de lui depuis 15 min alors qu'il a été sollicité
(CT-5 §8.9).

### 3.6 Ce qu'il faut encore croire (CT-6 §7.8), hypothèse par hypothèse

CT-6 §7.8 dresse la liste de ce qu'un réviseur doit croire pour que le
verdict signifie ce qu'il dit. CT-7 dit, pour chaque élément, ce qui le rend
raisonnable, la menace qui le vise et qui le porte.

| Élément de CT-6 §7.8 | Ce qui le rend raisonnable | Menace et risque | Porté par |
|---|---|---|---|
| Le vérificateur exécuté est conforme (binaire reconstruit à partir de la phase 2, implémentation de référence relue, Node et `ethers` crus en version 0) | Vérificateurs Go indépendants confrontés sur tous les vecteurs ; construction reproductible (CT-6 EX-14.6, EX-14.8) | MN-66, RA-57 | réviseur |
| H1, H2 : aucune collision, aucune signature forgée sans la clé | Primitives standard ; algorithmes refusés (CT-6 §15.4) | — | réviseur (hypothèse de cryptographie) |
| H3 : le fichier d'ancres dit vrai | Recoupement de CT-6 §12.5 ; clés d'enregistreur tirées d'un procès-verbal de cérémonie vérifié dont un signataire est connu du réviseur par un canal indépendant du client (EX-5.10) | MN-67, RA-58 | réviseur |
| H4 : l'autorité d'horodatage n'a pas menti sur l'heure | Contrôle de `genTime` à l'acquisition, qui ne protège qu'un client honnête (CT-5 EX-5.11) ; borne Bitcoin indépendante contre une postdatation seulement (CT-5 EX-6.2) ; deux prestataires d'exploitants distincts pour la continuité, non pour une confrontation (CT-5 EX-11.2) ; second jeton proposé (PA-19) | MN-60, RA-54 | réviseur |
| H5 : personne n'a pu miner au-dessus du point de contrôle Bitcoin | Profondeur minimale et point de contrôle choisis par le réviseur | MN-70, RA-59 | réviseur |
| H6 : au plus f validateurs fautifs | Au plus f validateurs par opérateur et par site, partenaires indépendants (CT-4 EX-4.12) | MN-54, RA-49 | opérateur de validateur |
| H7 : le code déployé est celui du dépôt | Aucune mise à niveau en place, redéploiement publié (CT-4 EX-5.9, EX-5.10) | MN-59, RA-53 | exploitant NOORTRACE |
| Règles du contrôle 8 tirées du code privé de noorcore | Confrontation de la racine des reçus et des journaux à go-ethereum (CT-6 annexe A.8) | MN-71, RA-60 | exploitant NOORTRACE |

### 3.7 Exigences nées de la consolidation

La réunion des tables fait apparaître des réponses que les spécifications
sources nomment sans les fixer, ou que personne ne porte. CT-7 les fixe.

**EX-3.6** **Clé de fournisseur hors de l'agent.** En production, chaque
route de modèle DEVRAIT être en `credentials: "propre"` (CT-2 EX-5.8) ; une
route en `credentials: "relayer"` laisse la clé du fournisseur à l'agent, qui
peut alors joindre le fournisseur sans la passerelle : l'attestation de
périmètre DOIT la lister parmi les exceptions connues (section 7).

**EX-3.7** **Rapprochement des signatures.** Pour une clé de l'enregistreur en
classe A ou B, l'administrateur du client DOIT, au moins une fois par mois et
après tout incident, compter les opérations de signature que le journal d'audit
du backend attribue à l'identité d'usage de la clé sur un intervalle, et les
comparer au nombre d'objets signés par cette clé dans le journal sur le même
intervalle : événements, manifestes, points de contrôle et contresignatures de
rotation (CT-1 annexe B, préfixes de signature). Un compte du backend supérieur
est un incident de compromission (4.6). Les journaux d'audit du backend sont
conservés aussi longtemps que le journal (CT-2 EX-12.19). C'est la corrélation
que CT-2 §11.6 permet ; elle répond à l'exigence d'examiner « the logs created
to record security-relevant events » (R7-F9, troisième type d'audit). En classe
C et D, aucun journal du backend ne voit la signature : le rapprochement est
impossible, ce que dit RA-26. Cette version ne qualifie pas un compte inférieur,
c'est-à-dire des objets signés sans opération du backend. Un tel compte signale
soit un journal d'audit incomplet, soit des signatures faites hors du backend ;
l'administrateur du client décide s'il traite un compte inférieur comme un
incident de 4.6 ; la version 0 ne l'y oblige pas.

**EX-3.8** **Rapprochement de l'usage des fournisseurs.** L'administrateur du
client DEVRAIT, au moins une fois par mois, comparer, clé par clé, le nombre
de requêtes que chaque fournisseur de modèle déclare pour une clé détenue par
la passerelle au nombre d'échanges `noortrace.modele.echange` de la route
correspondante. Un excédent révèle un usage de la clé hors de la passerelle.
Ce rapprochement relève du client et dépend de ce que le fournisseur publie.

**EX-3.9** **Empreintes de la console.** Pour chaque version de la console
d'approbation, l'exploitant de la console DOIT publier, hors du serveur qui
la sert (note de version, dépôt), le SHA-256 du document et de chaque script
qu'elle charge ; une supervision qui n'est pas hébergée sur ce serveur DOIT
récupérer la page au moins une fois par jour et comparer ces empreintes ; un
écart est une alerte critique. La construction reproductible du code relève
de CT-8. Cette exigence rend visible le serveur d'origine compromis que
l'intégrité des sous-ressources ne voit pas (CT-3 §13.15, « Limite »).

**EX-3.10** **Intégrité du service d'approbation.** En production, le service
d'approbation DOIT s'exécuter sous une identité de système distincte de
celles du démon de l'enregistreur et du serveur de la console ; son image
DOIT être désignée par son empreinte, consignée à son démarrage ; ses
lectures du jeu d'approbateurs DOIVENT viser un validateur que le client
opère ou un validateur partenaire (CT-3 EX-8.2) ; son canal avec le noyau est
authentifié (CT-2 EX-18.8, CT-3 EX-12.2).

**EX-3.11** **Coffre des originaux.** Quand le coffre de CT-2 EX-10.22 est
activé, le déchiffrement d'une pièce DOIT exiger deux personnes distinctes,
le demandeur et une autre personne autorisée, et chaque accès DOIT être
consigné hors du coffre avec le `sha256` de la pièce, les deux identités,
l'instant et le motif, et conservé aussi longtemps que le journal. Fondement :
la double autorisation de SP 800-53, « Dual authorization mechanisms require
the approval of two authorized individuals to execute » (AC-3(2), R7-F33),
appliquée à l'information d'audit par AU-9(5) (R7-F35).

**EX-3.12** **Exercice de révocation.** Au moins une fois par an,
l'administrateur du client DOIT exécuter, sur une instance de préproduction
ou de production, une rotation d'urgence de la clé de l'enregistreur suivie
de la révocation de l'ancienne clé de chaîne (CT-2 EX-11.16, CT-4 §8.4), et
mesurer le délai entre la décision et l'inclusion de la révocation. Le délai
visé est d'au plus 4 heures, valeur que CT-4 §8.4 propose pour l'astreinte
des approbateurs ; le résultat est consigné dans un procès-verbal (section 5,
objet `rotation_urgence`). Le délai visé n'est pas un seuil d'échec de
l'exercice. Le procès-verbal consigne l'instant de la décision et celui de
l'inclusion de la révocation (`purpose_details`, 5.6) ; un délai mesuré
supérieur à 4 heures y figure comme une entrée de `findings` de `kind: "ecart"`
(5.6). Il remplace alors les 4 heures comme estimation du délai de révocation
qui borne RA-30 ; lors d'un incident réel, c'est le délai effectivement constaté
qui borne RA-30.

**EX-3.13** **Essai de sortie.** L'administrateur du client DEVRAIT, au moins
une fois par an et après tout changement des règles de sortie, éprouver que
chaque agent de l'attestation de périmètre ne joint aucun serveur d'outils ni
aucun fournisseur de modèle autrement que par l'enregistreur. C'est l'essai
d'exfiltration de SP 800-53, « Conduct exfiltration tests » (SC-7(10)(b),
R7-F45), et la méthode « test » de SP 800-53A, qui compare « the actual state
of the object to the desired state » (R7-F51). Le résultat est une pièce du
client, que l'attestation PEUT citer ; mené par un évaluateur indépendant
(R7-F52), il prouve davantage qu'une déclaration de l'exploitant.

**EX-3.14** **Image de l'enregistreur.** L'administrateur du client DOIT
n'exécuter en production qu'une image de l'enregistreur dont l'empreinte est
celle d'une version publiée (CT-8) ; l'empreinte de l'image en cours DEVRAIT
être consignée au démarrage (proposition PA-4 à CT-2, 6.2), à côté de la
version que `code.recorder` porte dans chaque événement (CT-2 EX-18.6).

**EX-3.15** **ICAP.** En production, le raccord ICAP DOIT être ICAPS avec
certificat client (CT-2 EX-5.3), sauf quand le lien ICAP est la boucle locale
ou un segment de réseau que seuls le mandataire du client et l'enregistreur
atteignent ; l'attestation de périmètre nomme ce cas. Sur ce lien circule le
trafic déchiffré par le mandataire.

### 3.8 Forme lisible par machine : `menaces.json`

`spec/vecteurs/ct-7/menaces.json` porte la table de 3.4 et la consolidation
de 3.3. Schéma : `spec/schemas/modele-menace-v0.schema.json` (JSON Schema
draft 2020-12, sans référence croisée, compilable en mode strict). Champs :
`version` (0), `kind` (`modele-menace`), `spec`, `spec_version`, `date`,
`components` (table de 3.2), `source_tables` (table de 3.3 : spécification,
section, nombre de lignes), `threats`. Une menace porte `id`, `component`,
`stride`, `actor`, `asset`, `effect`, `response` et `detection` (chacun
`{ text, refs }`, `refs` étant les renvois du texte dans l'ordre de leur
première occurrence, sans doublon), `residual` (`{ text, accepted_risk }`,
`accepted_risk` nul ou `{ id, name, bound, owner }`, `owner` reprenant la
colonne « Porté par » de 3.5 : client → `client`, exploitant NOORTRACE →
`exploitant_noortrace`, réviseur → `reviseur`, opérateur de validateur →
`operateur_validateur`), `test` (qui commence par
« Le test échoue si la réponse est retirée : ») et `sources` (lignes des
tables sources, `{ spec, section, row }`).

Dans la table de 3.4, la cellule « Risque résiduel » est `residual.text`
suivi, quand `accepted_risk` n'est pas nul, de « Risque accepté RA-<n>. » ;
la cellule « Test de CT-9 » est `test` privé de son préfixe fixe.

Exemple complet réduit à une menace, MN-1, et aux deux tables sources
qu'elle consolide (le fichier publié porte les 98 menaces et les quinze
tables) :

<!-- schema: modele-menace -->
```json
{
  "version": 0,
  "kind": "modele-menace",
  "spec": "CT-7",
  "spec_version": "0.1",
  "date": "2026-10-26",
  "components": [
    {
      "id": "hote_agent",
      "name": "Hôte de l'agent",
      "holds": "Le processus de l'agent, l'hôte (application, cadre ou SDK) et leurs identifiants propres ; aucun accès au stockage ni au signataire (CT-2 EX-3.2).",
      "trust": "Aucune : tout ce qu'il envoie est une donnée d'attaquant (CT-2 §3.3)."
    }
  ],
  "source_tables": [
    {
      "spec": "CT-3",
      "section": "3.5",
      "rows": 10
    },
    {
      "spec": "CT-3",
      "section": "14.7",
      "rows": 10
    }
  ],
  "threats": [
    {
      "id": "MN-1",
      "component": "hote_agent",
      "stride": [
        "repudiation",
        "elevation_de_privilege"
      ],
      "actor": "L'agent ou tout code de l'hôte qui a un accès réseau propre.",
      "asset": "Complétude du journal : tout appel d'outil d'un serveur configuré passe par le mandataire.",
      "effect": "Un appel atteint le serveur d'outils sans l'enregistreur ; aucun événement n'existe et aucun dossier ne peut montrer cette absence.",
      "response": {
        "text": "Serveurs stdio lancés par le démon et serveurs HTTP filtrés pour que seul le démon les joigne (CT-2 EX-4.1, CT-2 EX-3.4, CT-2 §4.9) ; agent sans les identifiants de l'enregistreur (CT-2 EX-4.40, CT-2 EX-4.41) ; règles de sortie et exceptions déclarées par l'attestation de périmètre (CT-7 §7) ; essai de sortie annuel (CT-7 EX-3.13).",
        "refs": [
          "CT-2 EX-4.1",
          "CT-2 EX-3.4",
          "CT-2 §4.9",
          "CT-2 EX-4.40",
          "CT-2 EX-4.41",
          "CT-7 §7",
          "CT-7 EX-3.13"
        ]
      },
      "detection": {
        "text": "Journal du pare-feu des tentatives de connexion directe (CT-2 §4.9, point 5) ; essai de sortie (CT-7 EX-3.13) ; le rapport de CT-6 dit « déclaré par » pour le périmètre (CT-7 §7).",
        "refs": [
          "CT-2 §4.9",
          "CT-7 EX-3.13",
          "CT-7 §7"
        ]
      },
      "residual": {
        "text": "Un acte hors du périmètre déclaré n'est jamais prouvé absent : le journal prouve ce qui est passé, pas que rien ne l'a contourné (CT-1 §15).",
        "accepted_risk": {
          "id": "RA-1",
          "name": "Complétude non prouvable par la chaîne",
          "bound": "Bornée aux voies que le pare-feu déclaré laisse ouvertes et aux exceptions listées dans l'attestation de périmètre",
          "owner": "client"
        }
      },
      "test": "Le test échoue si la réponse est retirée : dans la démonstration de référence, un conteneur d'agent tente de joindre directement le serveur d'outils HTTP ; la connexion doit échouer et figurer au journal du pare-feu ; sans la règle de sortie, la connexion aboutit et le test échoue.",
      "sources": [
        {
          "spec": "CT-3",
          "section": "3.5",
          "row": "Agent (et hôte)"
        },
        {
          "spec": "CT-3",
          "section": "14.7",
          "row": "Agent"
        }
      ]
    }
  ]
}
```

## 4. Clés et secrets

### 4.1 Principes

Une compromission est « The unauthorized disclosure, modification,
substitution or use of sensitive key information » (R7-F1) ; l'usage non
autorisé d'une clé non exportable en est une, ce que CT-2 §11 sait déjà
(identité d'usage, EX-11.4). Un plan de reprise après compromission comprend
« An inventory of all cryptographic keys (e.g., the location of all keys and
certificates in a system) » (R7-F7, point d) ; tout accès à une clé « shall
be traceable to the entity accessing them » (R7-F8). Le règlement délégué
(UE) 2024/1774, art. 7 § 1, énumère les étapes du cycle de vie qu'une
politique de gestion des clés d'une entité financière couvre : « la
génération, le renouvellement, le stockage, la sauvegarde, l'archivage, la
récupération, la transmission, le retrait, la révocation et la destruction »
(R7-F17) ; CT-7 ne dit pas qu'un client y est soumis (section 8) : il fournit
l'inventaire et les procédures auxquels une telle politique peut renvoyer.

**EX-4.1** L'inventaire de 4.2 DOIT lister toute clé et tout secret de
NOORTRACE, chez le client et chez l'exploitant NOORTRACE. Une révision d'une
spécification qui introduit une clé ou un secret DOIT ajouter sa ligne à
4.2 dans la même livraison ; la revue de CT-9 le contrôle.

### 4.2 Inventaire

Classes de garde A à D de CT-2 §11.2. « Production » vaut pour
`recorder.environment: "production"` et pour une instance du registre de
`nature` production ; « développement » pour tout le reste. Une référence de
secret est la forme de CT-2 EX-15.3 (`env`, `file`, `vault`).

| Id | Clé ou secret | Algorithme | Classe (production ; développement) | Génère | Détient | Rotation | Révocation | Compromission (4.6) |
|---|---|---|---|---|---|---|---|---|
| CLE-1 | Clé de l'enregistreur (CT-2 §11) | Ed25519 | A, B ou C ; D | L'administrateur du client, en cérémonie (5.1), dans le module (A), le service (B) ou sur le poste hors ligne (C, graine enveloppée aussitôt) | Le signataire ; le démon n'a que l'identité d'usage (CT-2 EX-11.4) | Planifiée, période d'au plus 730 jours recommandée (DEVRAIT, CT-2 EX-11.15, EX-4.3) ; d'urgence sur soupçon (CT-2 EX-11.16) | Au registre, par la clé de chaîne qui la porte (CT-2 EX-11.14) | Rotation d'urgence, révocation, nouveau journal si la clé est inutilisable ; liste des événements signés depuis l'instant présumé |
| CLE-2 | Clé de chaîne (CT-2 EX-11.19) | secp256k1 | A, B ou C ; D | Avec CLE-1, en cérémonie ; support de secp256k1 par le backend éprouvé à la cérémonie | Le signataire de la clé de chaîne, hors du composant d'ancrage | Avec CLE-1, ou seule (CT-2 EX-11.19, point 4) | `revokeRecorder` au seuil des approbateurs (CT-4 §8.4) | Révocation, rotation de la seule clé de chaîne ; solde résiduel consigné (RA-30) |
| CLE-3 | Clés d'approbateur (CT-3) | secp256k1 | sans objet : portefeuille du détenteur, matériel recommandé (CT-3 EX-9.9) | L'approbateur lui-même (CT-3 EX-13.1) ; adresse consignée en cérémonie d'inscription (5.1) | L'approbateur seul (CT-3 EX-3.4) | À la demande de l'organisation : nouvelle adresse au `CuratorSet` et à l'annuaire (CT-3 §13.6) | Retrait du `CuratorSet` par l'administrateur du jeu, révocation à l'annuaire | Retrait du jeu, révocation à l'annuaire, revue des décisions signées depuis l'instant présumé |
| CLE-4 | Clé de gouvernance, administrateur du `CuratorSet` (CT-4 §5.5) | secp256k1 | A, B ou C ; D | Le client, en cérémonie | L'administrateur du jeu (client) | Transfert d'administration du `CuratorSet` (CT-4 §5.5) | Transfert d'administration | Conduite de CT-4 EX-8.10 : journal abandonné, réassignation sur demande consignée par procès-verbal d'objet `changement_administrateur` |
| CLE-5 | Clé de l'administrateur du registre (CT-4 EX-5.4) | secp256k1 | A ; D | L'exploitant NOORTRACE, en cérémonie | L'exploitant NOORTRACE, module matériel | Transfert d'administration du contrat (CT-4 §5.5) | Transfert d'administration | Notification de toutes les organisations, qui vérifient leur jeu épinglé (CT-3 EX-8.6) ; transfert vers une clé neuve |
| CLE-6 | Clé du déployeur (CT-4 EX-3.1) | secp256k1 | A, B ou C ; D | L'exploitant NOORTRACE, en cérémonie | L'exploitant NOORTRACE | Une par instance (CT-4 EX-4.8) | — | Celle de CLE-5 si la clé a gardé un rôle d'administration (CT-4 §5.4), sinon nouvelle clé |
| CLE-7 | Clé du relayeur de l'exploitant (CT-4 EX-3.1) | secp256k1 | A, B ou C ; D | L'exploitant NOORTRACE, en cérémonie | L'exploitant NOORTRACE | Libre quant à l'échéance, en cérémonie `rotation` (5.1) | — | Aucune autorité (CT-4 EX-3.3) : nouvelle clé ; provision perdue |
| CLE-8 | Trésorerie froide et compte d'approvisionnement (CT-4 EX-8.20) | secp256k1 | A, B ou C ; D | L'exploitant NOORTRACE, en cérémonie | L'exploitant NOORTRACE ; trésorerie froide hors ligne | Recomplément du compte d'approvisionnement par cérémonie (objet `recompletement`) | — | Transfert du solde vers une trésorerie neuve ; plafonds de CT-4 EX-8.20 |
| CLE-9 | Clés de validateur (CT-4 EX-10.7) | secp256k1 | D (fichier, seul possible en version 0) ; D | L'opérateur de validateur, sur son site, en cérémonie | Le seul nœud, fichier `0600` | Changement du jeu de validateurs (CT-4 §4.4) | Retrait du jeu de validateurs | Retrait du jeu, publication de toute preuve de double signature (CT-4 §14) |
| CLE-10 | Clé du serveur d'horodatage interne (CT-5 EX-7.3) | RSA d'au moins 3072 bits ou ECDSA P-256 (CT-5 AN-31) | A, B ou C ; D | L'administrateur du client, autre rôle que celui de l'enregistreur, en cérémonie | Le serveur interne, hors de l'hôte de l'enregistreur | Validité d'au plus trois ans (CT-5 AN-31) | CRL publiée (CT-5 AN-31) | Révocation `keyCompromise` ; les réviseurs retirent l'autorité de leur fichier d'ancres |
| CLE-11 | Identifiants d'accès aux prestataires RFC 3161 : mot de passe Basic, clé et certificat client (CT-5 EX-4.8) | secret ; clé du certificat client | référence de secret | L'administrateur du client, à l'ouverture du compte ; clé du certificat client sur le poste du client | Le composant d'ancrage | À l'échéance du certificat client, au plus tard, et sur compromission | Chez le prestataire | Révocation chez le prestataire, nouvelle référence, rechargement (RA-37) |
| CLE-12 | Authentification du nœud Bitcoin, si configurée (CT-5 §4.4) | secret | référence de secret | L'administrateur du client | Le composant d'ancrage | Selon la politique du client | Sur le nœud | Changer le secret du nœud |
| CLE-13 | Clés des fournisseurs de modèle, routes `propre` (CT-2 EX-5.8) | secret | référence de secret | L'administrateur du client, chez le fournisseur | La passerelle seule | Selon la politique du client et du fournisseur | Chez le fournisseur | Révocation chez le fournisseur ; rapprochement d'EX-3.8 sur l'intervalle |
| CLE-14 | Jetons statiques des hôtes, des sources OpenTelemetry et du SDK en TCP (CT-2 EX-4.39, EX-6.37) | secret | référence de secret | L'administrateur du client | Le démon et l'hôte ou la source | Au moins annuelle (DEVRAIT) et au départ d'une personne qui le connaissait | Retrait de la configuration | Retrait, nouveau jeton ; lignes `auth_failed` relues |
| CLE-15 | Identifiants de l'enregistreur vers les serveurs d'outils : client OAuth, en-têtes (CT-2 EX-4.40) | secret | référence de secret | L'administrateur du client | Le démon | Selon le serveur d'outils | Chez le serveur d'outils | Révocation chez le serveur d'outils |
| CLE-16 | Clé du MAC de relais (CT-2 EX-7.22) | secret | référence de secret | L'administrateur du client | Le démon ; même clé pour toutes les instances d'un journal | À chaque rotation planifiée de CLE-1 (DEVRAIT) | — | Nouvelle clé sur toutes les instances d'un journal à la fois (alerte « Clé du MAC de relais », CT-2 §17.4) |
| CLE-17 | Clé de pseudonymisation (CT-2 EX-10.12) | secret | référence de secret | L'administrateur du client | Le démon | Jamais sans nouvelle politique de rédaction : la changer change les pseudonymes | — | Nouvelle politique ; les pseudonymes déjà écrits sont exposés à une recherche par dictionnaire |
| CLE-18 | Clé du coffre des originaux (CT-2 EX-10.22) | AES-256-GCM, 32 octets | référence de secret | L'administrateur du client | Le démon, jamais le signataire | Selon la politique du client | — | Nouvelle clé, rechiffrement du coffre ; accès consignés relus (EX-3.11) |
| CLE-19 | DSN du magasin de bail (CT-2 §13.2) | secret | référence de secret | L'administrateur du client | Le démon | Selon la politique du client | Sur le magasin | Nouveau secret ; alerte « Bail » relue |
| CLE-20 | Identifiants du support WORM : écrivain, gardien de pose, gardien de levée, lecteur (CT-2 EX-18.9) | secret | référence de secret (écrivain) ; hors du démon (les trois autres) | L'administrateur du compte du support | Chacun son rôle, jamais deux rôles pour une personne de garde | Selon la politique du client | Sur le support | Révocation sur le support ; relevé de verrouillage immédiat (CT-2 EX-17.6) |
| CLE-21 | Accès au signataire : code PKCS#11, jeton du service de signature, identité d'usage IAM (CT-2 EX-11.18) | secret | référence de secret | L'administrateur du client, lors de la cérémonie de CLE-1, sans cérémonie propre (5.1) | Le démon | Avec CLE-1 | Sur le backend | Comme CLE-1 (usage abusif, RA-27) |
| CLE-22 | Identité d'administration du backend de clés (CT-2 EX-11.4) | identité du backend | hors du démon | L'administrateur du compte du backend | Des personnes nommées, jamais le démon | Selon la politique du client | Sur le backend | Revue des journaux d'audit du backend ; rotation de toutes les clés que l'identité administre |
| CLE-23 | Jetons ou certificats du canal noyau ↔ service d'approbation et console ↔ service (CT-3 EX-12.2, EX-12.4) | secret ; certificat | référence de secret | L'administrateur du client | Le noyau, le service, le serveur de la console ; un jeton distinct par sens | Au moins annuelle (DEVRAIT) | Retrait de la configuration du service | Nouveau jeton ou certificat ; décisions `autorise` de l'intervalle réévaluées (CT-3 §6.8) |
| CLE-24 | Certificats TLS des services : passerelle hors boucle locale, point d'entrée OpenTelemetry (CT-2 EX-6.40), ICAPS (CT-2 EX-5.3), service d'approbation, console, frontal du serveur interne (CT-5 AN-27) | clé TLS | fichier du service | L'administrateur du client | Chaque service | À l'échéance du certificat | Chez l'autorité qui l'a émis | Révocation et nouveau certificat |
| CLE-25 | Sessions de la console : jeton ou témoin du système d'identité du client (CT-3 §13.3) | jeton de session | — | Le système d'identité du client | Le navigateur de la personne | Réauthentification avant toute modification (CT-3 EX-13.8) | Fin de session au système d'identité | Fin des sessions de la personne ; revue des `operations` de l'annuaire (CT-3 §14.8) |
| CLE-26 | Clé d'enveloppe d'une sauvegarde partagée (4.4) | AES-256 | A, B ou C ; D | En cérémonie (objet `sauvegarde`), dans le module quand il l'offre | Partagée k sur n entre détenteurs de part | Avec la clé qu'elle protège | — | Nouvelle sauvegarde sous une enveloppe neuve ; parts anciennes détruites et consignées |
| CLE-27 | Clé d'interception TLS du mandataire du client, mode ICAP (CT-2 §5.1) | clé de l'autorité d'interception | hors de NOORTRACE | Le client | Le mandataire du client | Selon la politique du client | Chez le client | Hors de NOORTRACE : qui la tient lit tout le trafic déchiffré |
| CLE-28 | Clés de test publiées par les vecteurs (CT-1 §13, CT-3 annexe A.2, CT-4 annexe A.2, CT-6 annexe A.3) | toutes | jamais en production (EX-4.10) | Dérivées d'étiquettes publiques | Le dépôt public | — | — | Sans objet : elles sont publiques |
| CLE-29 | Clés de signature des participants d'une cérémonie (5.2, 5.7) | secp256k1 | sans objet : portefeuille du participant, matériel recommandé | Le participant lui-même, avant la cérémonie | Le participant seul ; son adresse figure au procès-verbal et, pour un auditeur mandaté par le réviseur, est communiquée au réviseur par un canal indépendant du client (EX-5.10) | À la demande du participant : la nouvelle adresse figure au procès-verbal suivant | Publication de l'adresse retirée par l'organisation qui tient la liste des participants, et par le réviseur pour l'auditeur qu'il mandate | Les procès-verbaux signés depuis l'instant présumé ne comptent plus cette signature ; le réviseur ne tire plus d'ancre d'un procès-verbal que cette seule clé rendait indépendant (EX-5.10) |

### 4.3 Classes admises par usage et environnement

**EX-4.2** En production, une clé ne DOIT être gardée que dans une classe de
la table ci-dessous ; la vérification CR-6 l'applique à tout procès-verbal
(5.8), et la validation de la configuration de CT-2 l'applique déjà à CLE-1 et
CLE-2 (CT-2 EX-11.8, EX-11.19). En développement, toute classe est admise.

| Usage (`keys[].usage`) | Clés | Classes admises en production | Fondement |
|---|---|---|---|
| `enregistreur` | CLE-1 | A, B, C | CT-2 EX-11.8 (D refusée) |
| `chaine` | CLE-2 | A, B, C | CT-2 EX-11.19, point 1 |
| `approbateur` | CLE-3 | `sans_objet` : la clé n'est pas gardée par NOORTRACE | CT-3 EX-3.4, EX-13.1 |
| `gouvernance` | CLE-4 | A, B, C | CT-4 EX-8.21 |
| `administrateur_registre` | CLE-5 | A | CT-4 EX-5.4 (module matériel) |
| `deployeur`, `relayeur`, `tresorerie`, `approvisionnement` | CLE-6 à CLE-8 | A, B, C | choix de CT-7 : une clé qui engage l'instance n'est jamais un fichier en clair |
| `validateur` | CLE-9 | D | CT-4 EX-10.7 : noorcore ne lit la clé que dans un fichier (RA-35) |
| `tsa_interne` | CLE-10 | A, B, C | CT-5 EX-7.3 |
| `enveloppe` | CLE-26 | A, B, C | choix de CT-7 |

### 4.4 Périodes de crypto et sauvegarde

**EX-4.3** La période de crypto d'une clé de signature est d'au plus trois
ans ; pour CLE-1 et CLE-2, elle DEVRAIT être d'au plus 730 jours, comme le
recommande CT-2 EX-11.15. Fondement : pour une clé
privée de signature, « a maximum cryptoperiod of about one to three years is
recommended » et « A private signature key shall be destroyed at the end of
its cryptoperiod » (R7-F4). La borne de 730 jours de CT-2 EX-11.15 tombe dans
cet intervalle ; c'est ce fondement, et non une page de fournisseur, que
CT-7 retient pour elle.

**EX-4.4** Une clé privée de signature ne DOIT pas être sauvegardée, sauf
celles dont la perte ne peut pas être réparée par une rotation diffusée à
temps : « In general, private signature keys shall not be archived »,
« exceptions may exist », par exemple « the private signature key of a CA »
(R7-F5). En conséquence :

| Usage | Sauvegarde | Raison |
|---|---|---|
| `enregistreur`, `chaine` | aucune | La rotation d'urgence et, à la perte, la rupture de journal la remplacent (CT-2 EX-11.16) ; une copie serait une seconde voie de signature |
| `validateur` | aucune | Un validateur restauré revote sans mémoire de ses votes (CT-4 EX-10.9) |
| `approbateur` | hors de NOORTRACE | La clé est celle de la personne ; sa perte se répare par une nouvelle adresse (CLE-3) |
| `deployeur`, `relayeur`, `approvisionnement`, `tsa_interne` | aucune | Une clé neuve la remplace sans perte |
| `administrateur_registre`, `tresorerie` | partage k sur n exigé en production | Sa perte fige l'assignation des jeux ou les fonds de l'instance |
| `gouvernance` | aucune ou partage k sur n, au choix du client | Sa perte se répare par la réassignation sur demande (CT-4 EX-8.10) |
| `enveloppe` | partage k sur n, toujours | C'est sa raison d'être |

Une sauvegarde partagée est une copie chiffrée de la clé sous une clé
d'enveloppe (CLE-26), elle-même partagée en n parts dont k reconstituent la
clé et k − 1 n'apprennent rien d'elle (R7-F10, R7-F13), avec 2 ≤ k ≤ n,
chaque part détenue par une personne distincte, dans un sac à témoin
d'effraction en un lieu distinct (« tamper-evident bags, stored in
geographically dispersed locations », R7-F26). k DEVRAIT être au plus
n − 1, pour qu'une part perdue n'empêche pas la restauration. La
restauration est une cérémonie (objet `restauration`) et a lieu « only by
personnel in Trusted Roles using, at least, dual control in a physically
secured environment » (R7-F31) ; la sauvegarde se décrit avec « how, where,
and the circumstances under which keys and their metadata are backed up »
(R7-F14), ce que le procès-verbal porte (5.6).

### 4.5 Contrôle multipartite, fonction par fonction

**EX-4.5** Chaque fonction ci-dessous exige k personnes autorisées parmi n,
avec la raison écrite pour laquelle k − 1 ne suffisent pas ; c'est la forme
qu'exige SP 800-130 : « The CKMS design shall specify all functions that
require multiparty control, specifying k and n for each function » et « why
any k of the n entities can enable the desired function, but k−1 of the
entities cannot » (R7-F12).

| Fonction | k | n | Pourquoi k − 1 ne suffisent pas |
|---|---|---|---|
| Création, rotation, sauvegarde, restauration, destruction d'une clé de 4.3 (sauf CLE-3) | 2 : officiant et témoin, plus les détenteurs de part pour une restauration | les participants du procès-verbal | Le procès-verbal n'est valide qu'avec un officiant, un témoin distinct et la signature de chacun (CR-2, CR-11) |
| Restauration d'une sauvegarde partagée | k du partage, au moins 2 | n du partage | k − 1 parts n'apprennent rien de la clé d'enveloppe (R7-F10) |
| Inscription d'une clé d'enregistreur, révocation, clôture d'une période | `required` du jeu | `size` du jeu | Le contrat vérifie le seuil (CT-4 §3.3, CT-1 A-3) |
| Décision d'approbation | `required` | `size` | Le noyau vérifie le seuil (CT-2 EX-7.5, CT-3 SG-6) |
| Levée d'un gel juridique | 2 | gardiens de pose et de levée | Règle de garde (CT-2 EX-12.38) |
| Déchiffrement d'une pièce du coffre | 2 | personnes autorisées | CT-7 EX-3.11 |
| Constat du statut qualifié d'un prestataire (CT-5 EX-5.9) | 2 : une personne lit la liste de confiance, une autre relit le constat avant le rechargement | administrateurs de l'ancrage | Une déclaration erronée d'une seule personne ferait acquérir des jetons marqués qualifiés à tort |
| Relais d'une administration de jeu ou d'un approvisionnement par l'exploitant | 2 organisations : confirmation hors bande du client, relais de l'exploitant | 2 | CT-4 EX-8.21 |
| Changement d'administrateur du jeu sur perte de la clé de gouvernance | les membres présents du jeu en vigueur, au moins `required`, plus l'exploitant | `size` plus 1 | Le procès-verbal d'objet `changement_administrateur` est vérifié par l'exploitant, qui compte les membres du jeu en vigueur lu sur la chaîne avant de relayer (CT-4 EX-8.10) |

Pour la première ligne, CR-2 et CR-11 vérifient des adresses distinctes, pas
des personnes distinctes ni indépendantes du client. La distinction des
personnes est un constat déclaré du témoin (5.9, MN-92, RA-76). Seul un
signataire que le réviseur connaît par un canal indépendant du client, en
pratique un auditeur qu'il a mandaté, fait du procès-verbal une source d'ancre
pour le réviseur (EX-5.10).

**EX-4.6** Un contrôle multipartite DOIT compter des personnes autres que le
demandeur quand la fonction est demandée par une personne : un mécanisme où
« the requesting user can provide one of the required approvals » (R7-F37)
réalise un seuil de deux avec une seule personne en plus du demandeur
seulement si le seuil configuré est de trois.

**EX-4.7** Une clé de classe A ne DOIT jamais exister hors du module autrement
que sous forme de parts ou chiffrée : « the key shall only exist outside of a
FIPS 140 cryptographic module as multiple key shares » (R7-F10). Un partage
fait par un logiciel hors du module (« Split and reconstruction of the Wrap
Key is done in the software », R7-F38) n'est admis que pour la clé
d'enveloppe CLE-26, sur le poste hors ligne de la cérémonie, et la
reconstitution n'a lieu que sur ce poste ou dans le module.

### 4.6 Conduite en cas de compromission

**EX-4.8** Pour chaque clé de 4.2, l'administrateur qui la détient DOIT tenir,
avant la mise en production, un plan de reprise qui contient au moins les
points a à i de SP 800-57 : les personnes à prévenir et ce qu'on leur dit,
celles qui agissent, la méthode pour obtenir une clé neuve, l'inventaire des
clés (4.2), la formation, les personnes d'appui, la vérification de
révocation, le suivi des opérations de changement de clé (R7-F7, a à i) ; et,
pour une clé de signature, l'identification des signatures qui peuvent être
invalides (R7-F7, point l). « When a key is compromised, all use of the key to
apply cryptographic protection to information […] shall cease, and the
compromised key shall be revoked » (R7-F6).

Ordre pour les clés de NOORTRACE, sur soupçon :

| Clé | Pas, dans l'ordre | Qui est prévenu | Ce qui est listé |
|---|---|---|---|
| CLE-1 | (1) rotation d'urgence tant que la clé reste utilisable (CT-2 EX-11.16) ; (2) révocation de l'ancienne clé de chaîne ; (3) si la clé est inutilisable, nouveau journal lié au registre | réviseurs des journaux concernés, approbateurs | les événements signés entre l'instant présumé et la rotation, et le dernier point ancré avant cet instant (RA-15) |
| CLE-2 | (1) révocation au seuil ; (2) nouvelle clé de chaîne pour la même clé Ed25519 (CT-2 EX-11.19, point 4) | exploitant NOORTRACE (provision) | les ancres émises depuis l'instant présumé ; le solde résiduel (RA-30) |
| CLE-3 | (1) retrait du `CuratorSet` ; (2) révocation à l'annuaire ; (3) nouvelle adresse en cérémonie d'inscription | administrateur du jeu, autres membres | les décisions signées par l'adresse depuis l'instant présumé |
| CLE-4 | (1) prévenir l'exploitant NOORTRACE par le canal hors bande convenu ; (2) sonder les événements du jeu ; (3) conduite de CT-4 EX-8.10 | exploitant NOORTRACE, réviseurs | les opérations du jeu et les clôtures depuis l'instant présumé |
| CLE-5 | (1) transfert d'administration vers une clé neuve ; (2) relecture de toutes les assignations | toutes les organisations | les `CuratorSetAssigned` depuis l'instant présumé |
| CLE-8 | (1) transfert du solde ; (2) gel des approvisionnements | organisations dont la provision dépend | les virements depuis l'instant présumé |
| CLE-9 | (1) retrait du validateur du jeu ; (2) publication de toute double signature | autres opérateurs, réviseurs | les hauteurs votées depuis l'instant présumé |
| CLE-10 | (1) révocation `keyCompromise` ; (2) retrait des fichiers d'ancres | réviseurs | les jetons émis depuis l'instant présumé |
| CLE-11 à CLE-25 | (1) révocation chez l'émetteur ; (2) nouvelle référence de secret et rechargement | selon le secret | les accès depuis l'instant présumé, dans les journaux de l'émetteur |

L'instant présumé est l'estimation que le détenteur de la clé fait d'après les
indices dont il dispose ; CT-7 n'en fixe pas la méthode. En classes C et D, où
aucun journal du backend ne voit la signature (EX-3.7), rien ne le borne vers le
passé hormis la création de la clé ; pour CLE-1, le dernier point ancré avant
cet instant borne ce qu'une réécriture a pu toucher sans être vue (RA-15).

Rotation de CLE-1 par qui détient la clé compromise. L'événement de rotation
signé par l'ancienne clé (CT-1 §8) ne suffit pas à faire reconnaître la
nouvelle clé : elle n'a la provenance « inscrite au registre » qu'une fois
inscrite, ce qui exige le seuil `required` du jeu (4.5, CT-4 §8.4), et la
provenance « fournie par le fichier d'ancres » que si le réviseur la tient
d'un procès-verbal vérifié (5.9, EX-5.10). Une rotation que l'attaquant
signerait vers sa propre clé, sans cette inscription, ne donne qu'une clé
« déclarée par le dossier » (CT-6 EX-3.6, table des provenances de CT-6
§6.5). La révocation de l'ancienne clé de chaîne exige le même seuil (CT-4
EX-8.8).

### 4.7 Traces du cycle de vie

**EX-4.9** Chaque événement du cycle de vie d'une clé de 4.3 DOIT laisser une
trace qui porte au moins le demandeur, la clé, le motif et l'instant, comme
SP 800-152 les liste pour la génération, la suspension, la révocation, la
destruction et la récupération (R7-F16) :

| Événement | Trace |
|---|---|
| Génération, sauvegarde, restauration, destruction | Procès-verbal de cérémonie (section 5) |
| Inscription, révocation d'une clé d'enregistreur et de sa clé de chaîne | Registre (CT-4 §8.4), capturé (CT-4 §9.4) |
| Rotation de la clé de l'enregistreur | Événement `noortrace.journal.rotation-cle` (CT-1 §8) et procès-verbal de la nouvelle clé |
| Usage (chaque signature) | Journal d'audit du backend, classes A et B ; rapproché par EX-3.7 |
| Changement d'un secret de 4.2 | Journal d'exploitation de l'enregistreur (`config_reloaded`, CT-2 EX-18.6) et journal de l'émetteur |

### 4.8 Clés de test

**EX-4.10** Aucune clé publiée par les vecteurs de `spec/vecteurs/` ne DOIT
servir en production. `spec/vecteurs/ct-7/cles-de-test.json` liste leurs clés
publiques et adresses (Ed25519 de CT-1 §13, comptes Hardhat 0 à 9 du
mnémonique public de CT-3 annexe A.2, clés dérivées de CT-4 annexe A.2, clés
RSA de test de CT-6 annexe A.3) ; la validation de la configuration de
production DEVRAIT refuser toute clé de cette liste (proposition PA-5 à
CT-2, 6.2).

## 5. Cérémonie des clés

Les pratiques publiées de deux cérémonies publiques convergent sur cinq
pièces, que cette section reprend : un script préparé à l'avance (« prepare
and follow a Key Generation Script », R7-F29 ; « Proposed Key Signing Key
Ceremony Script », R7-F20) ; un témoin qui suit le script, horodate et
paraphe chaque étape et consigne les écarts (R7-F21, R7-F22) ; un
procès-verbal signé par les participants (« participants sign IW's script »,
R7-F22 ; « recorded, dated, and signed », R7-F25) ; un enregistrement vidéo ou
un auditeur qui assiste (« have a Qualified Auditor witness the CA Key Pair
generation process or record a video of the entire CA Key Pair generation
process », R7-F29) ; les journaux et l'empreinte de l'image du poste de
signature (R7-F20). CT-7 en fait un format vérifiable hors ligne : le
procès-verbal `ceremonie-cles-v0`, signé par chaque participant en EIP-191
comme une décision d'approbation.

### 5.1 Quand une cérémonie est exigée

**EX-5.1** Les opérations suivantes DOIVENT se faire en cérémonie et donner
un procès-verbal (champ `purpose`) :

| Objet (`purpose`) | Clés | Exigée | Ce que le procès-verbal consigne en plus |
|---|---|---|---|
| `creation` | CLE-1, CLE-2, CLE-4 à CLE-10, CLE-26 | en production ; en développement, DEVRAIT pour s'y exercer | la clé publique, son empreinte, la classe, le backend, la preuve d'origine ; pour CLE-2, la signature d'un condensé d'essai et l'adresse recouvrée (CT-2 EX-11.19, point 1) |
| `rotation` | les mêmes | rotation planifiée (CT-2 EX-11.15) | la nouvelle clé ; l'ancienne reste nommée dans `findings` jusqu'à sa révocation |
| `rotation_urgence` | CLE-1, CLE-2 | rotation d'urgence (CT-2 EX-11.16), exercice d'EX-3.12 | l'instant de la décision et celui de l'inclusion de la révocation (`purpose_details` : `decided_at`, `revocation_included_at`) |
| `revocation`, `destruction` | toutes celles de 4.3 | toujours | la référence de la transaction de révocation (`purpose_details` : `tx_hash`) ou le SHA-256 de la preuve de destruction du backend (`destruction_proof_sha256`) |
| `sauvegarde`, `restauration` | celles de 4.4 avec partage | toujours | le partage : k, n, détenteurs (5.5) ; pour une restauration, `purpose_details` : `backup_ceremony_digest` (`D_C` du procès-verbal de sauvegarde), `k`, `n` |
| `inscription_membres` | CLE-3 | à la constitution du jeu et à chaque nouveau membre | une entrée `approbateur` par membre et la signature de chaque membre avec cette clé (CR-8, CR-11) |
| `changement_administrateur` | CLE-4 | demande de CT-4 EX-8.10 sur perte de la clé de gouvernance (`--changement-administrateur`) | les membres présents du jeu en vigueur, chacun signataire ; la nouvelle clé de gouvernance ; `purpose_details` : `approver_set_hash` (empreinte du jeu en vigueur) et `required` (son seuil) |
| `recompletement` | CLE-8 | recomplément du compte d'approvisionnement (CT-4 EX-8.20) | la référence de la transaction (`purpose_details` : `tx_hash`) ; aucune clé produite |

Les objets `creation`, `rotation`, `sauvegarde`, `inscription_membres` et
`autre` ont `purpose_details` nul ; CR-12 vérifie la forme propre à chaque autre
objet et les règles de 5.8.

Les identifiants d'accès et les secrets de service (CLE-11 à CLE-25) ne
demandent pas de cérémonie : leur création et leur rotation sont consignées
(4.7). CLE-21, l'accès au signataire, est créée lors de la cérémonie de
CLE-1, sans cérémonie propre (4.2). Une clé d'approbateur ne naît jamais en
cérémonie : elle naît chez son détenteur (CT-3 EX-13.1) ; la cérémonie
d'inscription consigne son adresse et la preuve que le membre la tient. Une
clé de signature de participant (CLE-29) non plus : le participant la génère
lui-même, avant la cérémonie (4.2).

### 5.2 Rôles

**EX-5.2** Une cérémonie réunit au moins deux personnes. Chaque participant a
exactement un rôle :

| Rôle (`role`) | Fait | Ne fait jamais | Pratique publiée |
|---|---|---|---|
| `officiant` | Lit chaque étape à voix haute puis l'exécute ; décide de la suite d'un écart après avoir consulté le témoin | Être témoin de ses propres étapes | « Ceremony Administrator » (R7-F21) ; « The CA reads each step aloud prior to its performance » (R7-F22) |
| `temoin` | Suit le script, annonce et consigne l'heure de fin de chaque étape, la paraphe, consigne chaque écart ; constate l'identité de chaque participant sur une pièce d'identité, hors du système d'identité du client | Exécuter une étape | « Internal Witness » (R7-F21, R7-F22) |
| `detenteur_part` | Reçoit et garde une part d'une clé d'enveloppe (5.5) | Garder deux parts d'un même partage | « Recovery Key Share Holders » (R7-F26) |
| `auditeur` | Assiste et atteste, pour le compte d'un tiers | Exécuter une étape, garder une part ou une clé | « Third party auditors do not participate in the multi-person control » (R7-F28) ; « Audit personnel also may not participate in the multi-person control » (R7-F24) |
| `membre` | Membre du jeu d'approbateurs : signe le procès-verbal avec la clé dont l'adresse est inscrite | Signer pour un autre membre | CT-3 EX-8.11 |
| `observateur` | Assiste | Exécuter une étape | « External Witnesses » (R7-F21) |

L'officiant et le témoin sont deux personnes distinctes ; un témoin est
distinct de toute personne dont il paraphe une étape. La personne qui audite
une cérémonie n'y tient ni étape ni part (SP 800-130 : « audit logs should be
managed by someone other than a system administrator », R7-F11).

### 5.3 Poste, entropie, enregistrements

**EX-5.3** Une clé générée sur le poste de la cérémonie (`generated_in:
"poste"`) l'est sur un poste démarré depuis une image dont le SHA-256 est
publié avant la cérémonie, interfaces réseau désactivées (`workstation.offline:
true`). Une clé générée dans un module ou un service l'est par le générateur
aléatoire du module ou du service (`entropy.source: "module"`) ; jamais par une
valeur saisie par une personne. En production, la cérémonie est filmée en
entier ou suivie par un auditeur (CR-9), et le SHA-256 de chaque
enregistrement (vidéo, journal du poste, journal du module, script annoté,
preuve d'origine) est inscrit au procès-verbal (`records`). Les enregistrements
sont conservés avec le procès-verbal (EX-5.11). Le poste démarre d'un support
sans écriture persistante ; à défaut, son stockage est effacé ou détruit à la
fin de la cérémonie, étape témoignée et consignée au procès-verbal.

### 5.4 Script pas à pas

**EX-5.4** Le script est écrit, versionné et publié aux participants avant la
cérémonie ; son SHA-256 est inscrit au procès-verbal (`script.sha256`, exigé
en production par CR-9). Chaque étape est lue par l'officiant, exécutée,
puis horodatée et paraphée par un témoin (« Upon the successful completion of
a step, the IW will announce and record its time of completion, and initials
that step in their script », R7-F22). Un participant qui voit un problème
interrompt la cérémonie ; l'écart est évalué, décidé par l'officiant après
consultation du témoin, consigné (`outcome: "exception"` et une entrée de
`findings`) et traité comme un incident (« an exception is regarded as an
incident », R7-F22).

Script de référence d'une création de la clé de l'enregistreur et de sa clé
de chaîne (objet `creation`, classe A) ; le script réel est celui du backend :

1. Lire le script à voix haute et comparer son SHA-256 à celui publié.
2. Vérifier les scellés du module, démarrer le poste sur l'image dont le
   SHA-256 est inscrit, constater l'absence de réseau.
3. Constater l'identité de chaque participant (témoin).
4. Générer dans le module la clé Ed25519, non exportable quand le backend
   l'offre (CT-2 EX-11.5).
5. Lire la clé publique, calculer son SHA-256 et l'afficher à tous.
6. Générer la clé de chaîne secp256k1 ; signer un condensé d'essai de 32
   octets et recouvrer l'adresse : elle DOIT égaler l'adresse dérivée de la
   clé publique (c'est l'épreuve du support de secp256k1 par le backend, CT-2
   EX-11.19, point 1).
7. Remettre au démon la seule identité d'usage : ni export, ni suppression,
   ni changement de la politique de clé (CT-2 EX-11.4).
8. Exporter la preuve d'origine quand le backend la produit (CT-2 EX-11.13)
   et calculer son SHA-256.
9. Arrêter l'enregistrement ; calculer les SHA-256 des enregistrements et des
   journaux.
10. Écrire le procès-verbal ; chaque participant recalcule `D_C` sur son
    propre poste (EX-5.8) et signe.

Pour une inscription de membres, les pas 4 à 8 sont remplacés, pour chaque
membre, par : le témoin constate l'identité du membre ; le membre lit son
adresse dans son portefeuille ; l'officiant l'inscrit au procès-verbal ; le
membre signera `D_C` avec cette clé au pas 10, ce qui prouve qu'il la tient.

Le constat d'identité (pas 3) fait partie du rôle du témoin (EX-5.2) : il n'est
pas facultatif. Le procès-verbal n'a aucun membre pour le type ou le numéro de
la pièce d'identité présentée (5.6), et aucune CR- ne lit ce constat, qui reste
déclaré (5.9, RA-32, RA-76).

### 5.5 Sauvegarde et partage

**EX-5.5** Une sauvegarde (objet `sauvegarde`) suit 4.4 : la clé est chiffrée
sous une clé d'enveloppe (CLE-26) générée dans le module quand il l'offre,
sinon sur le poste hors ligne ; la clé d'enveloppe est partagée en n parts
dont k reconstituent la clé (EX-4.7) ; chaque part est remise à un détenteur
distinct, dans un sac à témoin d'effraction dont le numéro est inscrit dans
`findings` (`kind: "observation"`) ; le procès-verbal porte, pour la clé
sauvegardée, `backup: { scheme: "partage_k_sur_n", k, n, holders }`. Une
restauration (objet `restauration`) réunit au moins k détenteurs, un officiant
et un témoin ; les parts utilisées sont, après usage, détruites ou remises sous
sac neuf, ce que le procès-verbal consigne. Un poste de restauration suit
EX-5.3 : support sans écriture persistante, ou stockage effacé ou détruit en fin
de cérémonie, étape témoignée et consignée. Le témoin constate l'identité
distincte de chaque détenteur de part (EX-5.2) ; cette distinction reste un
constat déclaré (5.9, RA-79).

### 5.6 Procès-verbal : forme

**EX-5.6** Le procès-verbal est un document JSON `ceremonie-cles-v0`
(`spec/schemas/ceremonie-cles-v0.schema.json`, JSON Schema draft 2020-12,
sans référence croisée, compilable en mode strict), encodé en UTF-8, toutes
ses clés présentes. Il est en JCS v0 (CT-1 §4) : aucun nombre non entier.

| Membre | Contenu |
|---|---|
| `version`, `kind` | `0`, `"ceremonie-cles"` |
| `ceremony_id` | identifiant `^[a-z0-9][a-z0-9.-]{0,63}$`, unique chez qui tient les procès-verbaux |
| `scope` | `client` ou `exploitant` (exploitant NOORTRACE) |
| `organization` | `name` et `org_id` (32 octets de CT-1 §3, ou `null` pour une cérémonie de l'exploitant qui ne concerne aucune organisation) |
| `purpose`, `environment` | objet de 5.1 ; `production`, `preproduction` ou `developpement` |
| `purpose_details` | `null` pour `creation`, `rotation`, `sauvegarde`, `inscription_membres` et `autre` ; sinon l'objet propre à l'objet : `rotation_urgence` `{ decided_at, revocation_included_at }` ; `revocation` et `recompletement` `{ tx_hash }` ; `destruction` `{ destruction_proof_sha256 }` ; `restauration` `{ backup_ceremony_digest, k, n }` ; `changement_administrateur` `{ approver_set_hash, required }` (instants de CT-1 §3, condensés de 32 octets en hexadécimal) |
| `place`, `started_at`, `ended_at` | lieu en clair ; instants de CT-1 §3 |
| `script` | `title`, `version`, `sha256` (ou `null`, refusé en production) |
| `workstation` | `description`, `offline`, `image_sha256` (ou `null`) |
| `entropy` | `source` (`module`, `systeme_du_poste`, `detenteur`, `sans_objet`) et `description` |
| `participants[]` | `id` (`p1`, `p2`…), `name`, `role` (5.2), `affiliation`, `address` (adresse secp256k1 avec laquelle le participant signe) |
| `steps[]` | `n` (1, 2…), `action`, `performed_by`, `witnessed_by` (identifiants de témoins ou d'auditeurs), `at`, `outcome` (`fait`, `exception`) |
| `keys[]` | `key_id` (identifiant de clé de CT-1 §3), `usage` (4.3), `algorithm` (`ed25519`, `secp256k1`, `rsa`, `ecdsa_p256`, `aes256`), `generated_in` (`module`, `service`, `poste`, `detenteur`), `custody_class` (`A` à `D`, ou `sans_objet` pour une clé d'approbateur), `backend`, `public_key`, `fingerprint`, `address`, `origin_proof_sha256`, `backup` (5.5) |
| `records[]` | `kind` (`video`, `journal_poste`, `journal_module`, `script_annote`, `preuve_origine`, `autre`), `name`, `sha256` |
| `findings[]` | `n`, `step` (ou `null`), `kind` (`ecart`, `incident`, `observation`), `text`, `resolution` (ou `null`) |
| `signatures[]` | `participant`, `signature` (65 octets `r ‖ s ‖ v`) ; hors du condensé |

Encodage des clés publiques : Ed25519, les 32 octets de la RFC 8032 ;
secp256k1, la forme non compressée de 65 octets `0x04 ‖ X ‖ Y` ; RSA et ECDSA
P-256, le `SubjectPublicKeyInfo` en DER ; `aes256` n'a ni clé publique, ni
empreinte, ni adresse. `fingerprint` est le SHA-256 des octets de
`public_key`. Pour secp256k1, `address` est les 20 derniers octets de
Keccak-256(`X ‖ Y`) ; une clé d'approbateur PEUT n'avoir que son adresse
(`public_key` et `fingerprint` nuls), sa clé publique n'étant pas toujours
lisible depuis le portefeuille.

### 5.7 Condensé et signatures

**EX-5.7** Le condensé du procès-verbal et la signature de chaque
participant sont :

```text
V   = le procès-verbal privé de son membre signatures
D_C = Keccak-256( P_C || JCS(V) )                  32 octets
P_C = octets UTF-8 de "noortrace/ceremonie-cles/v0\n"
    = 6e6f6f7274726163652f636572656d6f6e69652d636c65732f76300a   (28 octets)
M   = Keccak-256( "\x19Ethereum Signed Message:\n32" || D_C )
sig = ECDSA-secp256k1.Sign( sk(participant), M ) = r (32) || s (32) || v (1), v ∈ {0x1b, 0x1c}
```

`JCS` est la forme canonique v0 de CT-1 §4, encodée en UTF-8. La signature
est celle de CT-1 §6.3 (EIP-191, version `0x45`, `personal_sign` sur les 32
octets de `D_C`) : `signer.signMessage(getBytes(D_C))` d'ethers. Elle est
canonique : `s` dans la moitié basse de l'ordre, `v` dans {27, 28}.

Séparation des domaines. `P_C` diffère de chacun des préfixes de CT-1 (annexe
B : événement, signature d'événement, manifeste, signature de manifeste,
approbation, signature de rotation, point de contrôle, signature de point),
de la première ligne du texte d'inscription de CT-3 (`noortrace/inscription/v0`)
et du préfixe de l'attestation de périmètre (section 7). `D_C` est un
Keccak-256 et `D_A` un SHA-256 : égaler l'un et l'autre demande une collision
entre deux fonctions (H1 de CT-6). Le texte d'inscription est signé avec sa
longueur décimale, plusieurs centaines d'octets, dans le préfixe EIP-191 :
sa préimage n'a pas la longueur de celle d'un condensé de 32 octets. Les
condensés du registre de CT-4 §6.6 sont des Keccak-256 de préimages ABI qui
ne commencent pas par `P_C`.

**EX-5.8** Un participant NE DOIT signer `D_C` qu'après l'avoir recalculé
lui-même, sur son poste, depuis le fichier du procès-verbal, avec l'outil de
référence (`node scripts/verify/ceremonie.mjs --condense <fichier>`, qui imprime
aussi les groupes de huit chiffres) ou un outil conforme, et avec un second
outil indépendant du premier, par exemple le mode `condenser-pv` du vérificateur
Go de `ct-7` (EX-A.21), puis comparé à ce que son portefeuille affiche, groupe
de huit chiffres par groupe de huit comme CT-3 EX-9.18. Qui signe par un fichier
de clé, sans portefeuille qui affiche le condensé, DOIT comparer les deux outils
entre eux. Un condensé fourni par
l'officiant seul n'est jamais signé : c'est ainsi qu'un membre évite de
signer, présenté comme un procès-verbal, une décision `D_A` ou un condensé du
registre (MN-45).

### 5.8 Vérifications CR-

**EX-5.9** Un vérificateur de procès-verbal exécute, hors ligne et sans
réseau, CR-1 à CR-12 dans cet ordre ; chaque vérification est `reussi`,
`echoue` ou `non_execute`. CR-1 en échec rend CR-2 à CR-12 `non_execute`
(raison `prerequis_en_echec`) ; sinon toutes sont exécutées, et toutes celles
qui échouent sont rapportées. Le procès-verbal est **valide** si et
seulement si les douze vérifications sont `reussi`. Le fichier lu fait au plus
1 Mio.

| Id | Vérification | Échoue quand |
|---|---|---|
| CR-1 | Forme : JSON strict (clés uniques, aucun nombre non entier ni hors de l'intervalle sûr, aucun substitut isolé, comme E-2 de CT-1) et conforme au schéma `ceremonie-cles-v0` | l'analyse ou le schéma échoue |
| CR-2 | Participants : `id` distincts, adresses distinctes, au moins deux participants, exactement un `officiant`, au moins un `temoin` ; aucun `auditeur` n'exécute une étape ni ne détient une part | une de ces règles est violée |
| CR-3 | Chronologie : `started_at ≤ ended_at` ; `steps[i].n = i + 1` ; `at` non décroissant le long des étapes et compris dans `[started_at, ended_at]` ; instants à la milliseconde, dates du calendrier (CT-1 §3) | une de ces règles est violée |
| CR-4 | Étapes : `performed_by` est un participant ; chaque `witnessed_by` est un `temoin` ou un `auditeur` distinct de l'exécutant ; chaque étape a au moins un `witnessed_by` de rôle `temoin`, l'auditeur s'ajoutant au témoin sans le remplacer ; une étape `exception` a au moins une entrée de `findings` qui la nomme | une de ces règles est violée |
| CR-5 | Clés : `key_id` distincts ; algorithme de l'usage (4.3 : `ed25519` pour `enregistreur` ; `secp256k1` pour `chaine`, `approbateur`, `gouvernance`, `administrateur_registre`, `deployeur`, `relayeur`, `tresorerie`, `approvisionnement` et `validateur` ; `rsa` ou `ecdsa_p256` pour `tsa_interne` ; `aes256` pour `enveloppe`) ; `generated_in` vaut `detenteur` si et seulement si l'usage est `approbateur` ; encodage de 5.6 ; `fingerprint` égal au SHA-256 de `public_key`, ou nul avec elle ; `address` nulle hors de secp256k1 ; pour secp256k1, point de la courbe et `address` égale à l'adresse dérivée | une de ces règles est violée |
| CR-6 | Classes : `custody_class` vaut `sans_objet` si et seulement si l'usage est `approbateur` ; en production, classe admise par la table de 4.3 | une de ces règles est violée |
| CR-7 | Sauvegarde : `aucune` a `k` et `n` nuls et aucun détenteur ; `partage_k_sur_n` a `2 ≤ k ≤ n`, n détenteurs distincts, tous de rôle `detenteur_part` ; règle de 4.4 par usage (aucune sauvegarde pour `enregistreur`, `chaine`, `approbateur`, `validateur`, `deployeur`, `relayeur`, `approvisionnement`, `tsa_interne` ; partage pour `enveloppe` ; partage en production pour `administrateur_registre` et `tresorerie`) | une de ces règles est violée |
| CR-8 | Membres : chaque clé d'usage `approbateur` a l'adresse d'exactement un participant `membre`, et chaque `membre` a exactement une telle clé | une de ces règles est violée |
| CR-9 | Production (`environment: "production"` seulement) : `script.sha256` non nul ; un enregistrement `video` ou un participant `auditeur` ; si une clé a `generated_in: "poste"`, `workstation.offline` vrai et `image_sha256` non nul | une de ces règles est violée |
| CR-10 | Constats : `findings[i].n = i + 1` ; `step` nul ou numéro d'une étape ; un `incident` a une `resolution` non nulle | une de ces règles est violée |
| CR-11 | Signatures : exactement une entrée par participant et aucune autre ; chaque signature canonique (65 octets, `v` dans {27, 28}, `r` et `s` entre 1 et l'ordre du groupe moins 1, `s` au plus la moitié de l'ordre) ; l'adresse recouvrée sur `M` (5.7) est celle du participant | une de ces règles est violée |
| CR-12 | Objet : `purpose_details` nul pour `creation`, `rotation`, `sauvegarde`, `inscription_membres` et `autre`, de la forme propre à l'objet sinon (5.6) ; `rotation_urgence` : `decided_at` ≤ `revocation_included_at` ; `restauration` : `2 ≤ k ≤ n` et au moins k participants `detenteur_part` ; `changement_administrateur` : au moins `required` participants `membre` et une clé d'usage `gouvernance` ; `creation`, `rotation` et `rotation_urgence` : au moins une clé ; `sauvegarde` : au moins une clé sauvegardée par `partage_k_sur_n` ; `inscription_membres` : au moins une clé d'usage `approbateur` | une de ces règles est violée |

Le rapport rend le verdict, `D_C`, la liste des vérifications en échec, celle
des non exécutées et les adresses des signataires, dans la forme du fichier
`attendu.json` des vecteurs (`#/$defs/attendu` du schéma). `signers` liste les
adresses des participants dont la signature satisfait CR-11 (canonique, et
l'adresse recouvrée sur `M` est celle du participant), dans l'ordre de
`participants`, sans doublon ; la liste est vide quand CR-1 échoue. Sur la
sortie lisible, la commande de référence imprime, pour un procès-verbal valide,
cette phrase, et rien de plus fort :

```text
Procès-verbal <ceremony_id> : forme, chronologie, clés et <n> signatures vérifiées (D_C = <D_C>). Les identités, les rôles, les étapes et les constats sont déclarés par le procès-verbal et ses signataires.
```

### 5.9 Ce que le procès-verbal prouve et ne prouve pas ; usage par le réviseur

| Ce que CR-1 à CR-12 établissent | Ce qu'elles n'établissent pas |
|---|---|
| Chaque adresse de `participants` a signé ce procès-verbal exact (R7-F53, sous H1 et H2 de CT-6). | Que la personne nommée tient l'adresse : c'est ce que le témoin a constaté, déclaré. |
| Les clés publiques, empreintes et adresses déclarées sont cohérentes entre elles ; la clé de chaîne déclarée est bien celle de son adresse. | Que la clé a été générée comme écrit, qu'elle est non exportable, qu'aucune copie n'existe : seule la preuve d'origine du backend, quand il en produit une, l'appuie (CT-2 EX-11.13). |
| La classe déclarée est admise pour l'usage en production ; la sauvegarde suit 4.4. | Que la classe déclarée est la classe réelle. |
| Les étapes sont ordonnées et chacune témoignée par au moins un `temoin` distinct de son exécutant ; chaque écart est consigné. | Que les étapes ont eu lieu ; que rien d'autre n'a eu lieu. La vidéo et l'auditeur sont les pièces qui s'en approchent (méthodes « examine » et « interview » de SP 800-53A, R7-F51). |
| L'objet a les membres structurés qui lui sont propres, et les règles de CR-12 sur les participants et les clés tiennent. | Que les détenteurs de part sont des personnes distinctes : c'est un constat déclaré du témoin (RA-79). |
| Les signatures portent sur ce procès-verbal exact. | Qu'un signataire est indépendant du client (EX-5.10, RA-76) ; que la cérémonie a eu lieu à la date déclarée, sans ancre de `D_C` (EX-5.11, RA-77). |

**EX-5.10** Un réviseur qui veut inscrire la clé d'un enregistreur dans la ligne
`recorders` de son fichier d'ancres (CT-6 §12.5) PEUT la tirer d'un
procès-verbal de création ou de rotation qu'il vérifie (CR-1 à CR-12), à une
condition : au moins un signataire du procès-verbal a une adresse que le
réviseur connaît par un canal indépendant du client, en pratique un auditeur
qu'il a mandaté. L'appartenance d'un signataire au `CuratorSet` ne suffit pas :
le client administre ce jeu (CLE-4). Le réviseur reprend `public_key` de la clé
d'usage `enregistreur`, et l'adresse de la clé d'usage `chaine` pour sa clé de
chaîne ; il note la classe déclarée, que le vérificateur ne contrôle pas (CT-6
§7.2). Il DOIT recouper la clé de chaîne avec son inscription au registre
(`registerRecorder`, certifiée par le contrôle 8 de CT-6) ; ce recoupement borne
l'antidatage du procès-verbal, mais ne protège pas contre l'administrateur du
client, qui inscrit lui-même la clé. C'est la réponse aux renvois de CT-6 §7.2
et §12.5.

**EX-5.11** Le procès-verbal, ses enregistrements et le script sont conservés
aussi longtemps que le plus long des journaux dont la clé signe ou ancre des
événements (CT-2 EX-12.19), avec une copie sur le support WORM du client
(CT-2 §12.6) ; la preuve d'origine transmise au registre (CT-2 EX-11.13) PEUT
être `D_C`. En production, `D_C` DOIT être ancré : par un jeton RFC 3161 sur
`D_C`, obtenu après les signatures et conservé avec le procès-verbal, hors de
son condensé, ou par sa transmission au registre comme preuve d'origine. Aucune
CR- ne lit cette ancre : le réviseur la contrôle lui-même, et un procès-verbal
sans ancre n'a qu'une date déclarée (RA-77).

**EX-5.12** Le procès-verbal porte des noms de personnes : il est remis au
réviseur et aux auditeurs qui en ont l'usage, non publié ; `name` PEUT être
une désignation de fonction quand l'organisation tient ailleurs la liste des
personnes.

### 5.10 Exemple calculé

Création, en production, de la clé de l'enregistreur et de sa clé de chaîne
de l'organisation `assureur-demo` (valeurs de test : clé Ed25519 `rec-test-01`
de CT-1 §13 ; clé de chaîne, officiant, témoin et auditeur : comptes Hardhat
3, 1, 2 et 4 de `spec/vecteurs/ct-3/constantes.json` ; SHA-256 des
enregistrements, du script et de l'image dérivés d'étiquettes
`noortrace/vecteurs/ct7/…` ; un procès-verbal réel ne porte jamais une clé
de `cles-de-test.json`, EX-4.10). L'étape 5 a un écart, consigné. Le
procès-verbal est valide (CR-1 à CR-12 réussies).

<!-- schema: ceremonie-cles -->
```json
{
  "version": 0,
  "kind": "ceremonie-cles",
  "ceremony_id": "cer-2026-11-02-sinistres-01",
  "scope": "client",
  "organization": {
    "name": "assureur-demo",
    "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab"
  },
  "purpose": "creation",
  "purpose_details": null,
  "environment": "production",
  "place": "Salle de cérémonie, site principal (exemple)",
  "started_at": "2026-11-02T08:00:00.000Z",
  "ended_at": "2026-11-02T09:10:00.000Z",
  "script": {
    "title": "Création de la clé de l'enregistreur et de sa clé de chaîne",
    "version": "1",
    "sha256": "0xa3415496b2c101b78f6e4e8307705aac29139294aa0bf679f8b7e49e3fd00f08"
  },
  "workstation": {
    "description": "Poste d'administration du module, démarré sur support en lecture seule, interfaces réseau désactivées",
    "offline": true,
    "image_sha256": "0x2408b216725cd9a613845dc2b9efa49582fd569b72e1a8979313683fd0562da5"
  },
  "entropy": {
    "source": "module",
    "description": "Générateur aléatoire du module ; aucune valeur saisie"
  },
  "participants": [
    {
      "id": "p1",
      "name": "Officiant (compte de test 1)",
      "role": "officiant",
      "affiliation": "assureur-demo, exploitation",
      "address": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
    },
    {
      "id": "p2",
      "name": "Témoin (compte de test 2)",
      "role": "temoin",
      "affiliation": "assureur-demo, sécurité",
      "address": "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
    },
    {
      "id": "p3",
      "name": "Auditeur (compte de test 4)",
      "role": "auditeur",
      "affiliation": "cabinet d'audit (exemple)",
      "address": "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"
    }
  ],
  "steps": [
    {
      "n": 1,
      "action": "Lire le script à voix haute et comparer son SHA-256 à celui publié avant la cérémonie",
      "performed_by": "p1",
      "witnessed_by": [
        "p2",
        "p3"
      ],
      "at": "2026-11-02T08:02:00.000Z",
      "outcome": "fait"
    },
    {
      "n": 2,
      "action": "Vérifier les scellés du module, démarrer le poste sur l'image dont le SHA-256 est inscrit, constater l'absence de réseau",
      "performed_by": "p1",
      "witnessed_by": [
        "p2"
      ],
      "at": "2026-11-02T08:10:00.000Z",
      "outcome": "fait"
    },
    {
      "n": 3,
      "action": "Générer dans le module la clé Ed25519 rec-test-01, non exportable",
      "performed_by": "p1",
      "witnessed_by": [
        "p2"
      ],
      "at": "2026-11-02T08:21:00.000Z",
      "outcome": "fait"
    },
    {
      "n": 4,
      "action": "Lire la clé publique Ed25519, calculer son SHA-256 et l'afficher à tous",
      "performed_by": "p1",
      "witnessed_by": [
        "p2",
        "p3"
      ],
      "at": "2026-11-02T08:24:00.000Z",
      "outcome": "fait"
    },
    {
      "n": 5,
      "action": "Générer dans le module la clé de chaîne secp256k1, signer un condensé d'essai et recouvrer l'adresse",
      "performed_by": "p1",
      "witnessed_by": [
        "p2"
      ],
      "at": "2026-11-02T08:35:00.000Z",
      "outcome": "exception"
    },
    {
      "n": 6,
      "action": "Remettre au démon la seule identité d'usage : ni export, ni suppression, ni changement de politique",
      "performed_by": "p1",
      "witnessed_by": [
        "p2"
      ],
      "at": "2026-11-02T08:48:00.000Z",
      "outcome": "fait"
    },
    {
      "n": 7,
      "action": "Exporter l'attestation du module (preuve d'origine) et calculer son SHA-256",
      "performed_by": "p1",
      "witnessed_by": [
        "p2",
        "p3"
      ],
      "at": "2026-11-02T08:55:00.000Z",
      "outcome": "fait"
    },
    {
      "n": 8,
      "action": "Arrêter l'enregistrement vidéo, calculer les SHA-256 des enregistrements et des journaux",
      "performed_by": "p1",
      "witnessed_by": [
        "p2",
        "p3"
      ],
      "at": "2026-11-02T09:05:00.000Z",
      "outcome": "fait"
    }
  ],
  "keys": [
    {
      "key_id": "rec-test-01",
      "usage": "enregistreur",
      "algorithm": "ed25519",
      "generated_in": "module",
      "custody_class": "A",
      "backend": "pkcs11",
      "public_key": "0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045",
      "fingerprint": "0x06fa51071909aab2e05b5a04643eca0f984a73824809f5ddeba5b63c8a7d5c88",
      "address": null,
      "origin_proof_sha256": "0x018ac515d811bcd8db6e592c2c1c73945774caadc69bab3f881a7459e4561b51",
      "backup": {
        "scheme": "aucune",
        "k": null,
        "n": null,
        "holders": []
      }
    },
    {
      "key_id": "chaine-test-03",
      "usage": "chaine",
      "algorithm": "secp256k1",
      "generated_in": "module",
      "custody_class": "A",
      "backend": "pkcs11",
      "public_key": "0x0420b871f3ced029e14472ec4ebc3c0448164942b123aa6af91a3386c1c403e0ebd3b4a5752a2b6c49e574619e6aa0549eb9ccd036b9bbc507e1f7f9712a236092",
      "fingerprint": "0x40aeb6ea3c51d30271f5bc2801e6b95f31b02ae8e470a19ebeac967b60bd0478",
      "address": "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
      "origin_proof_sha256": null,
      "backup": {
        "scheme": "aucune",
        "k": null,
        "n": null,
        "holders": []
      }
    }
  ],
  "records": [
    {
      "kind": "video",
      "name": "camera-1.mp4",
      "sha256": "0x6cfcb6099d7e00281179f5af504960bfdede22670a825c0bf1035b774a3237f2"
    },
    {
      "kind": "journal_module",
      "name": "journal-module.txt",
      "sha256": "0x43e562f9f1ad1011f1b13981ba65e0e45b795f5837d0279011786ed6622477b3"
    },
    {
      "kind": "preuve_origine",
      "name": "attestation-rec-test-01.der",
      "sha256": "0x018ac515d811bcd8db6e592c2c1c73945774caadc69bab3f881a7459e4561b51"
    }
  ],
  "findings": [
    {
      "n": 1,
      "step": 5,
      "kind": "ecart",
      "text": "Le premier condensé d'essai a été signé avec la mauvaise étiquette de clé ; signature écartée, étape refaite sur l'étiquette prévue.",
      "resolution": "Étape 5 refaite à 08:41 ; adresse recouvrée égale à l'adresse déclarée."
    }
  ],
  "signatures": [
    {
      "participant": "p1",
      "signature": "0x930dde84b7d248f54a1f98f79974fa2d011864be260bfe04f84d1ae77eb478930d205ed3b10a07f7cd46294f17e902ef7bbf0408c952974bec7159d6014646a21c"
    },
    {
      "participant": "p2",
      "signature": "0x33f16937aa94ddf3e52d2368770adb86db17dd9ea72bd4fce7fdaaaa770c8d13727b854205f0c373914ecbd726b69eee2893df28160c1394af26f6dcb1a9dcba1b"
    },
    {
      "participant": "p3",
      "signature": "0x7e45505b4c7bfe96dcbd6461d387650e52fbfcaee69b62f81f934a19c4e094735893fc00c6762c0c2991d6a7c23a4ef4caadebfbcb48d683c2f800d656e8c32a1c"
    }
  ]
}
```

Forme canonique `JCS(V)` (4771 octets UTF-8, une ligne) :

```text
{"ceremony_id":"cer-2026-11-02-sinistres-01","ended_at":"2026-11-02T09:10:00.000Z","entropy":{"description":"Générateur aléatoire du module ; aucune valeur saisie","source":"module"},"environment":"production","findings":[{"kind":"ecart","n":1,"resolution":"Étape 5 refaite à 08:41 ; adresse recouvrée égale à l'adresse déclarée.","step":5,"text":"Le premier condensé d'essai a été signé avec la mauvaise étiquette de clé ; signature écartée, étape refaite sur l'étiquette prévue."}],"keys":[{"address":null,"algorithm":"ed25519","backend":"pkcs11","backup":{"holders":[],"k":null,"n":null,"scheme":"aucune"},"custody_class":"A","fingerprint":"0x06fa51071909aab2e05b5a04643eca0f984a73824809f5ddeba5b63c8a7d5c88","generated_in":"module","key_id":"rec-test-01","origin_proof_sha256":"0x018ac515d811bcd8db6e592c2c1c73945774caadc69bab3f881a7459e4561b51","public_key":"0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045","usage":"enregistreur"},{"address":"0x90f79bf6eb2c4f870365e785982e1f101e93b906","algorithm":"secp256k1","backend":"pkcs11","backup":{"holders":[],"k":null,"n":null,"scheme":"aucune"},"custody_class":"A","fingerprint":"0x40aeb6ea3c51d30271f5bc2801e6b95f31b02ae8e470a19ebeac967b60bd0478","generated_in":"module","key_id":"chaine-test-03","origin_proof_sha256":null,"public_key":"0x0420b871f3ced029e14472ec4ebc3c0448164942b123aa6af91a3386c1c403e0ebd3b4a5752a2b6c49e574619e6aa0549eb9ccd036b9bbc507e1f7f9712a236092","usage":"chaine"}],"kind":"ceremonie-cles","organization":{"name":"assureur-demo","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab"},"participants":[{"address":"0x70997970c51812dc3a010c7d01b50e0d17dc79c8","affiliation":"assureur-demo, exploitation","id":"p1","name":"Officiant (compte de test 1)","role":"officiant"},{"address":"0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc","affiliation":"assureur-demo, sécurité","id":"p2","name":"Témoin (compte de test 2)","role":"temoin"},{"address":"0x15d34aaf54267db7d7c367839aaf71a00a2c6a65","affiliation":"cabinet d'audit (exemple)","id":"p3","name":"Auditeur (compte de test 4)","role":"auditeur"}],"place":"Salle de cérémonie, site principal (exemple)","purpose":"creation","purpose_details":null,"records":[{"kind":"video","name":"camera-1.mp4","sha256":"0x6cfcb6099d7e00281179f5af504960bfdede22670a825c0bf1035b774a3237f2"},{"kind":"journal_module","name":"journal-module.txt","sha256":"0x43e562f9f1ad1011f1b13981ba65e0e45b795f5837d0279011786ed6622477b3"},{"kind":"preuve_origine","name":"attestation-rec-test-01.der","sha256":"0x018ac515d811bcd8db6e592c2c1c73945774caadc69bab3f881a7459e4561b51"}],"scope":"client","script":{"sha256":"0xa3415496b2c101b78f6e4e8307705aac29139294aa0bf679f8b7e49e3fd00f08","title":"Création de la clé de l'enregistreur et de sa clé de chaîne","version":"1"},"started_at":"2026-11-02T08:00:00.000Z","steps":[{"action":"Lire le script à voix haute et comparer son SHA-256 à celui publié avant la cérémonie","at":"2026-11-02T08:02:00.000Z","n":1,"outcome":"fait","performed_by":"p1","witnessed_by":["p2","p3"]},{"action":"Vérifier les scellés du module, démarrer le poste sur l'image dont le SHA-256 est inscrit, constater l'absence de réseau","at":"2026-11-02T08:10:00.000Z","n":2,"outcome":"fait","performed_by":"p1","witnessed_by":["p2"]},{"action":"Générer dans le module la clé Ed25519 rec-test-01, non exportable","at":"2026-11-02T08:21:00.000Z","n":3,"outcome":"fait","performed_by":"p1","witnessed_by":["p2"]},{"action":"Lire la clé publique Ed25519, calculer son SHA-256 et l'afficher à tous","at":"2026-11-02T08:24:00.000Z","n":4,"outcome":"fait","performed_by":"p1","witnessed_by":["p2","p3"]},{"action":"Générer dans le module la clé de chaîne secp256k1, signer un condensé d'essai et recouvrer l'adresse","at":"2026-11-02T08:35:00.000Z","n":5,"outcome":"exception","performed_by":"p1","witnessed_by":["p2"]},{"action":"Remettre au démon la seule identité d'usage : ni export, ni suppression, ni changement de politique","at":"2026-11-02T08:48:00.000Z","n":6,"outcome":"fait","performed_by":"p1","witnessed_by":["p2"]},{"action":"Exporter l'attestation du module (preuve d'origine) et calculer son SHA-256","at":"2026-11-02T08:55:00.000Z","n":7,"outcome":"fait","performed_by":"p1","witnessed_by":["p2","p3"]},{"action":"Arrêter l'enregistrement vidéo, calculer les SHA-256 des enregistrements et des journaux","at":"2026-11-02T09:05:00.000Z","n":8,"outcome":"fait","performed_by":"p1","witnessed_by":["p2","p3"]}],"version":0,"workstation":{"description":"Poste d'administration du module, démarré sur support en lecture seule, interfaces réseau désactivées","image_sha256":"0x2408b216725cd9a613845dc2b9efa49582fd569b72e1a8979313683fd0562da5","offline":true}}
```

| Calcul | Valeur |
|---|---|
| SHA-256 de la clé publique Ed25519 (`fingerprint` de `rec-test-01`) | `0x06fa51071909aab2e05b5a04643eca0f984a73824809f5ddeba5b63c8a7d5c88` |
| SHA-256 de la clé publique de chaîne (65 octets) | `0x40aeb6ea3c51d30271f5bc2801e6b95f31b02ae8e470a19ebeac967b60bd0478` |
| Adresse de chaîne : 20 derniers octets de Keccak-256(`X ‖ Y`) | `0x90f79bf6eb2c4f870365e785982e1f101e93b906` |
| `D_C = Keccak-256(P_C ‖ JCS(V))` | `0x737c29754b0f9259cbb51db37fa76114ff723442eabaa77afbe70b7caecd9478` |
| `M = Keccak-256("\x19Ethereum Signed Message:\n32" ‖ D_C)` | `0x6b05c5fd515c359b10b2a23395b4af5bc36048170aff11719fd23e032447db68` |
| Signature de `p1` (compte 1, `0x70997970c51812dc3a010c7d01b50e0d17dc79c8`) | `0x930dde84b7d248f54a1f98f79974fa2d011864be260bfe04f84d1ae77eb478930d205ed3b10a07f7cd46294f17e902ef7bbf0408c952974bec7159d6014646a21c` |
| Signature de `p2` (compte 2, `0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc`) | `0x33f16937aa94ddf3e52d2368770adb86db17dd9ea72bd4fce7fdaaaa770c8d13727b854205f0c373914ecbd726b69eee2893df28160c1394af26f6dcb1a9dcba1b` |
| Signature de `p3` (compte 4, `0x15d34aaf54267db7d7c367839aaf71a00a2c6a65`) | `0x7e45505b4c7bfe96dcbd6461d387650e52fbfcaee69b62f81f934a19c4e094735893fc00c6762c0c2991d6a7c23a4ef4caadebfbcb48d683c2f800d656e8c32a1c` |

Fichier attendu de ce cas dans les vecteurs
(`ceremonies/valide-creation-enregistreur/attendu.json`) :

<!-- schema: ceremonie-cles/attendu -->
```json
{
  "verdict": "valide",
  "digest": "0x737c29754b0f9259cbb51db37fa76114ff723442eabaa77afbe70b7caecd9478",
  "failed": [],
  "not_executed": [],
  "signers": [
    "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
    "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
    "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"
  ]
}
```

L'exemple abrège le script de 5.4 : il omet le constat d'identité (pas 3) parce
qu'aucune CR- ne le lit, non parce qu'il serait facultatif (EX-5.2), et le pas
10, écriture et signature du procès-verbal, dont `signatures` est la trace ; ses
huit étapes sont les pas 1, 2 et 4 à 9. L'étape refaite garde l'instant de sa
première exécution (étape 5, 08:35), et la reprise est datée dans `findings`
(08:41). Les CR- réussies ne disent rien de l'ancre de `D_C`, qu'EX-5.11 exige
encore en production et que l'exemple ne montre pas. L'auditeur `p3` ne fournit
une ancre au réviseur que s'il a été mandaté par lui (EX-5.10).

## 6. Journal de l'enregistreur sur lui-même

Un enregistreur dont l'état change sans trace dans la chaîne laisse un
réviseur sans moyen de dater ce changement. CT-1 v0 ne réserve que quatre
noms sous `noortrace.` (CT-1 §5.1, E-3) et CT-2 n'en ajoute aucun (CT-2
§9.1) : seuls `noortrace.journal.rotation-cle` et `noortrace.journal.politique`
parlent de l'enregistreur lui-même. Les formats de CT-1 v0 sont figés. Cette
section dresse la liste des événements que CT-7 juge obligatoires, dit pour
chacun ce qui le porte aujourd'hui et ce qui l'émet, et écrit chaque lacune
comme une proposition adressée à CT-2 (6.2) ou à une version 1 de CT-1
(6.3), sans modifier ni CT-2, ni CT-1, ni leurs vecteurs. Tant qu'une
proposition n'est pas adoptée, la lacune est un risque accepté.

### 6.1 Événements obligatoires sur soi

**EX-6.1** Les événements de la table sont obligatoires. Un événement porté
(« porté ») DOIT être émis comme la colonne « Émis par » le dit ; un événement
dont le porteur est proposé (« proposé ») DEVRAIT l'être dès que la
proposition est adoptée par CT-2 ; un événement « hors chaîne » est consigné
où la colonne le dit, et son absence de la chaîne est le risque accepté
nommé.

| Id | Événement | Porteur dans CT-1 v0 | Émis par (CT-2) | État | Détection et risque tant que la lacune demeure |
|---|---|---|---|---|---|
| JS-1 | Démarrage de l'enregistreur | aucun aujourd'hui ; `noortrace.journal.politique` proposé (annonce de reprise) | ligne `startup` du journal d'exploitation (CT-2 EX-17.2, EX-18.6) ; événement de politique seulement si l'ensemble a changé (CT-2 EX-9.2, EX-9.8 pas 4) | proposé (PA-1) | Trou dans la série des points (CT-5 §10.2) ; RA-66 |
| JS-2 | Arrêt | aucun | aucune ligne propre : la liste d'EX-17.2 de CT-2 n'a pas d'événement d'arrêt | hors chaîne ; ligne `shutdown` proposée (PA-3) | Trou dans la série des points et dans les `ts` ; RA-66 |
| JS-3 | Bail : acquisition, perte, bascule | aucun aujourd'hui ; `noortrace.journal.politique` proposé (annonce de reprise par le nouvel écrivain) | `lease_acquired`, `lease_lost`, `lease_standby`, `journal_fork` (CT-2 EX-17.2, EX-13.10) | proposé (PA-1) | Alerte « Bail », alerte « Fourche » (CT-2 §17.4) ; RA-66 |
| JS-4 | Rotation de la clé de l'enregistreur | `noortrace.journal.rotation-cle` (CT-1 §8) | CT-2 EX-9.3, EX-11.15, EX-11.16 | porté | E-10 et C-3 au vérificateur (CT-1 §11.4) |
| JS-5 | Rotation de la seule clé de chaîne | aucun, par conception : la clé qui signe les événements ne change pas | registre : révocation et inscription (CT-2 EX-11.19, point 4 ; CT-4 §8.4) | hors chaîne (au registre) | Contrôle 8 et N-4 de CT-6 ; pas de risque nouveau |
| JS-6 | Changement de politique | `noortrace.journal.politique` (CT-1 §5.1, §8) | CT-2 EX-9.1, EX-9.2 | porté | Contrôle de la `policy_version` de chaque événement (CT-2 EX-9.1) |
| JS-7 | Changement de configuration hors politique | aucun aujourd'hui ; `noortrace.journal.politique` proposé, par l'empreinte de la configuration d'exploitation dans l'ensemble de politique | ligne `config_reloaded` avec le SHA-256 du document (CT-2 EX-18.6) | proposé (PA-2) | Empreinte consignée localement ; RA-20 |
| JS-8 | Saut d'horloge | aucun ; `ts` reste non décroissant (CT-1 §5.2) | blocage de l'écrivain sur saut en avant (CT-2 EX-7.13) ; lignes `clock_skew`, `clock_backstep` | hors chaîne ; sorte réservée proposée pour CT-1 v1 (PA-7) | Contresignature extérieure, `horloge_suspecte` (CT-5 EX-5.11) ; RA-18 |
| JS-9 | Gel juridique posé ou levé | aucun (CT-2 §9.1) | registre des gels sur le support WORM (CT-2 EX-12.37) ; `worm_legal_hold_observed` (CT-2 EX-17.7) | hors chaîne (au registre des gels) ; PA-7 | Alertes « Gel levé », « Registre des gels invalide » (CT-2 §17.4) ; RA-24 |
| JS-10 | Perte d'une copie WORM | aucun | `worm_copy_failed`, `integrity_check`, `worm_versions_unexpected` (CT-2 EX-17.2, EX-17.5, EX-17.6) | hors chaîne ; PA-7 | Alertes « Copie WORM en retard », « Contrôle d'intégrité en échec » ; RA-25 |
| JS-11 | Ancrage dégradé | aucun | `anchor_pending`, `registry_pending` (CT-2 EX-17.2) ; métriques de CT-5 §8.9 | hors chaîne ; PA-7 | `upper_bound` du dossier et fenêtre affichée (CT-5 §8.9) ; RA-55 |
| JS-12 | Attestation de périmètre reçue | aucun aujourd'hui ; `noortrace.journal.politique` proposé, par le condensé de l'attestation dans l'ensemble de politique | — | proposé (PA-8) | AT-1 à AT-7 (7.7) ; RA-72 |

**EX-6.2** Tant que PA-1 n'est pas adoptée, le démarrage, l'arrêt et la
bascule de bail ne sont pas dans la chaîne : c'est le risque accepté RA-66,
**Changement d'état de l'enregistreur hors de la chaîne**, borné par la
cadence des points de contrôle (un trou de plus de `c_K` dans la série des
points, 60 s par défaut, est visible par qui lit la série, CT-5 §10.2) et
porté par le client. Tant que PA-7 n'est pas adoptée, JS-8 à JS-11 restent
dans les journaux et registres qui les portent aujourd'hui, avec les risques
acceptés nommés dans la table.

### 6.2 Ce que CT-7 demande à CT-2

Les propositions ne modifient ni CT-2 ni ses vecteurs ; CT-2 les adopte, les
amende ou les refuse dans une révision, et cette table est mise à jour. Les
propositions PA-8 à PA-11 servent l'attestation de périmètre (section 7).
PA-12, PA-13 et PA-16, issues de la matrice de conformité, s'adressent aussi à
CT-2 ; elles sont en 8.11 avec PA-14 (CT-4), PA-15 (CT-8), PA-17 et PA-20 (CT-2)
et PA-19 (CT-5 et CT-1). PA-17 figure aussi dans cette table, parce qu'elle
touche la supervision de l'enregistreur ; PA-18 sert le journal d'exploitation
(MN-96).

| Id | Proposition | Section de CT-2 visée | Événement servi | Compatibilité |
|---|---|---|---|---|
| PA-1 | **Annonce de reprise.** À chaque prise d'écriture d'un journal (démarrage, bascule de bail), au pas 4 de la séquence d'EX-9.8, produire un événement `noortrace.journal.politique` même si l'ensemble de politique n'a pas changé : sa valeur est alors celle du dernier annoncé. Un événement de politique dont la valeur égale la précédente se lit « reprise d'un écrivain ». La phrase de §9.1 « L'enregistreur ne produit aucun autre événement sur lui-même » est complétée en conséquence. | §9.1 (EX-9.2, EX-9.8), §13.4 | JS-1, JS-3 | Aucun format nouveau : l'événement est de CT-1 v0 et passe E-3 ; un journal existant reste valide |
| PA-2 | **Empreinte de la configuration d'exploitation.** Ajouter à l'ensemble de politique un membre facultatif `exploitation_sha256` : SHA-256 du JCS intégral du document de configuration privé de son membre `policy` (les références de secrets y sont des emplacements, jamais des valeurs, CT-2 EX-15.3). Tout changement de la configuration d'exploitation change alors `policy_sha256` et produit un événement de politique (EX-9.1). | §8.5 (EX-8.11), §15.1, EX-15.4 | JS-7 | Extension compatible du schéma `configuration-enregistreur-v0` (membre facultatif) ; un ensemble sans le membre garde son empreinte |
| PA-3 | **Ligne d'arrêt.** Ajouter `shutdown` (arrêt ordonné : raison, durée de fonctionnement, dernier `seq`) à la liste des événements du journal d'exploitation. | EX-17.2 | JS-2 | Journal d'exploitation seulement |
| PA-4 | **Empreinte de l'image.** Ajouter au `data` de la ligne `startup` l'empreinte de l'image ou du binaire en cours (CT-7 EX-3.14). | EX-18.6, EX-17.2 | — (MN-25) | Journal d'exploitation seulement |
| PA-5 | **Clés de test refusées.** En `environment: "production"`, la validation au démarrage refuse toute clé publique de `spec/vecteurs/ct-7/cles-de-test.json` pour la clé de l'enregistreur et la clé de chaîne (CT-7 EX-4.10). | EX-15.4 | — (MN-30) | Refus nouveau en production seulement |
| PA-6 | **Signature du document de configuration.** Rappel du point que CT-2 §21 laisse hors de la version 0 : signature détachée par l'administrateur du client, vérifiée avant chargement, pour une version ultérieure. | §18.4, §21 | JS-7 | Version ultérieure |
| PA-8 | **Membre `policy.perimeter`.** Ajouter à l'ensemble de politique (`configuration-enregistreur-v0`, `$defs/policy_set`) un membre facultatif `perimeter` = `{ "attestation_digest": hex de 32 octets }`, ajout compatible comme `otel` et `sdk` en révision 0.5. Recevoir une attestation est alors un rechargement de politique, qui scelle `noortrace.journal.politique` (EX-15.5) ; la table de §9.1 nomme « attestation de périmètre reçue » portée par cet événement. | EX-8.11, EX-9.1, EX-15.2, EX-15.5, §9.1 | JS-12 | Extension compatible du schéma de configuration ; inscrit l'attestation sans nom réservé nouveau (CT-7 EX-7.10) |
| PA-9 | **Unicité des noms de version de politique.** Un nom de version de politique déjà annoncé dans un journal ne serait plus jamais annoncé de nouveau avec un autre `policy_sha256`, au démarrage (EX-9.2) comme au rechargement (EX-15.5). | EX-9.2, EX-15.5 | JS-6, JS-12 | Refus nouveau au chargement ; AT-7 compare des noms de version (CT-7 EX-7.11) |
| PA-10 | **Consignes de l'attestation.** Ajouter au journal d'exploitation `perimeter_attestation_loaded` (`D_P`, `validity`), `perimeter_attestation_expired` (instant au-delà de `validity.until`) et `perimeter_unlisted_host` (connexion d'hôte dont l'`alias` ne figure dans aucun `agents[].agent_id` de l'attestation en vigueur, quand l'organisation emploie les alias comme identifiants d'agents). | §9.2, §17 | JS-12 | Journal d'exploitation seulement ; détection de MN-88 |
| PA-11 | **Métrique d'échéance.** Ajouter la métrique `noortrace_perimeter_attestation_expiry_seconds` (secondes jusqu'à `validity.until`, négative après). | §17 | — (MN-88) | Métrique seulement ; alerte avant l'échéance (CT-7 EX-7.5) |
| PA-17 | **Relecture tournante des segments.** Relire tous les segments fermés et les comparer à leur copie WORM, chaque segment au moins une fois par période fixée et configurable, résultat dans la ligne `integrity_check` (détail en 8.11). | EX-17.5, EX-12.21 | JS-10 | Supervision seulement ; aucun format nouveau |
| PA-18 | **Copie du journal d'exploitation.** L'écrivain copie sur le support WORM, sous `<prefix>exploitation/`, avec la même règle conditionnelle qu'EX-12.16, chaque fichier tourné du journal d'exploitation, ou au moins les lignes `startup`, `shutdown` (PA-3), `config_reloaded`, `lease_*`, `clock_*` et `worm_*`. Le rôle Lecteur d'EX-18.9 relit cette copie hors du démon, et une discontinuité de la série produit un avertissement. | EX-12.16, EX-17.2, EX-18.9 | JS-1 à JS-3, JS-7 à JS-11 | Support WORM seulement ; détection de MN-96 |

### 6.3 Ce que CT-7 propose pour une version 1 de CT-1

| Id | Proposition | Événements servis |
|---|---|---|
| PA-7 | Une cinquième sorte réservée, `noortrace.journal.etat`, dont `execution.arguments` est une référence en ligne `{ "state": <valeur énumérée>, "detail": … }` (`demarrage`, `arret`, `bail`, `saut_horloge`, `gel_pose`, `gel_leve`, `copie_worm_perdue`, `ancrage_degrade`), signée comme tout événement. Elle exige une version 1 du format (E-3 refuse aujourd'hui tout autre nom réservé) : CT-1 v0 n'est pas modifié. | JS-1 à JS-3, JS-8 à JS-11 |

**EX-6.3** Aucune proposition de 6.2, 6.3 ou 8.11 n'est appliquée par
l'enregistreur de version 0 tant que la spécification visée ne l'a pas adoptée ;
un enregistreur conforme à CT-2 0.5 reste conforme à CT-7 0.1, les écarts étant
les risques acceptés RA-18, RA-20, RA-24, RA-25, RA-55, RA-66 et RA-80, et, pour
l'attestation de périmètre, RA-72 et RA-75.

## 7. Attestation de périmètre

NOORTRACE prouve ce que l'enregistreur a vu passer. Il ne prouve pas que
tout est passé par lui : un acte de l'agent par un canal qui n'est ni MCP ni
une API de modèle configurée n'est pas journalisé, et aucun dossier ne peut
prouver ni cet acte ni son absence (CT-2 §21) ; l'opérateur peut « ne pas
journaliser un acte » (CT-6 §3.4). L'attestation de périmètre ne comble pas
ce manque : elle le **nomme**. C'est une déclaration de l'organisation
cliente, signée par des membres de son jeu d'approbateurs, inscrite dans son
journal une fois PA-8 adoptée (en version 0, jointe sans inscription,
EX-7.12), jointe au dossier, que le réviseur vérifie hors ligne. Le rapport
dit « déclaré par », jamais « prouvé ».

Cette section dit ce que l'attestation contient (7.1), comment elle se
condense et se signe (7.2, 7.3), comment l'administrateur du client la
remplit, la fait signer et l'inscrit (7.4, 7.5), comment elle entre dans le
dossier (7.6), ce que le réviseur vérifie (7.7), ce qu'elle prouve et ne
prouve pas (7.8), les exigences mesurables de parité (7.9), ses menaces
(7.10) et ce qu'elle demande à CT-2 (7.11). Un administrateur du client
qui ne lit que cette section sait la remplir, la faire signer, et ce qu'elle
prouve ; l'épreuve de la section 9 (EX-9.4) le vérifie.

Termes employés. Le **jeu d'approbateurs** est l'ensemble d'adresses et le seuil
`required` que l'organisation inscrit au `CuratorSet` du registre (CT-3 §8, CT-4
§5.5). L'**ensemble de politique** est le membre `policy` de la configuration de
l'enregistreur, dont chaque version est annoncée dans la chaîne par un événement
`noortrace.journal.politique` (CT-2 §15, CT-1 §5.1). Une **connexion d'hôte**
est l'entrée de configuration par laquelle un hôte d'agent se connecte
à l'enregistreur (`mcp.hosts`, `model.hosts`, `sdk.hosts`, `otel.hosts`, CT-2
§3). Une **route** est l'entrée `policy.model.routes` par laquelle la passerelle
joint un fournisseur, avec `credentials: "propre"` quand la passerelle seule
tient la clé (CT-2 EX-5.8). Le **dossier** est l'ensemble de fichiers qui prouve
un événement (CT-1 §11), et l'**exportateur** celui qui le produit. Une
attestation **retenue** est définie en section 2 ; le **fichier d'ancres** est
celui du réviseur (CT-6 §3.5). Le `ts` d'un événement est l'instant que donne
l'horloge de l'enregistreur, déclaratif, que seules les ancres bornent (CT-1
§5.2). La **fenêtre de réécriture** de RA-15 est le temps pendant lequel qui
tient la clé de l'enregistreur peut réécrire un événement avant qu'un jeton RFC
3161 ne l'engage : au plus 300 s plus le délai du jeton avec la configuration
par défaut et des points de contrôle contresignés par un prestataire extérieur,
une heure plus ce délai sans points, davantage pendant une panne des
prestataires (RA-55). H1 et H2 sont les hypothèses de cryptographie de CT-6
§3.5 : aucune collision, aucune signature forgée sans la clé. N-3 compare la clé
de l'enregistreur à celle du fichier d'ancres du réviseur (CT-6 §12). FP est le
fragment de l'énoncé du rapport qui décrit l'attestation (CT-6 EX-6.19). Le
contrôle 7 vérifie les signatures des approbateurs et le seuil (CT-6 §5.1).
RA-69 se lit donc : la validité est jugée sur un `ts` déclaré, que qui tient la
clé peut réécrire tant que cette fenêtre reste ouverte ; et RA-71 : qui tient la
clé peut réécrire l'inscription dans la même fenêtre. Les raisons de
non-exécution des vérifications AT- (CT-1 §11.4) se lisent ainsi :
`partie_absente`, aucune inscription jointe (`inscription: null`), AT-6 et AT-7
ne s'exécutent pas ; `ancre_absente`, AT-6 non exécutée parce que l'inscription
est signée par une autre clé que celle de l'événement prouvé ;
`piece_hors_dossier`, AT-7 non exécutée parce que l'inscription jointe n'est pas
celle de la version de politique de l'événement prouvé. Le **jeu épinglé par la
politique** est le `CuratorSet` que la politique d'approbation attend
(`approver_set.set`, CT-3 EX-8.1).

En version 0, tant que PA-8 n'est pas adoptée, l'administrateur passe du pas 7
aux pas 9 et 10 de 7.4 ; le pas 8 et la section 7.5 décrivent l'inscription
telle qu'elle sera.

**EX-7.1 (nature).** L'attestation est une déclaration du client.
Aucune sortie de NOORTRACE (énoncé, rapport, console, documentation, page
de démonstration) NE DOIT la présenter comme une preuve du périmètre : le
périmètre est « déclaré par » ses signataires ; « vérifié » et « prouvé » ne
qualifient que le condensé, les signatures, le seuil et l'inscription. Une
attestation retenue ne change aucun statut de contrôle ni aucun verdict ; une
attestation non retenue est signalée (CT-6 AV-AT-1, fragment FP) sans
invalider l'événement prouvé (CT-6 EX-5.11). Motif : une signature établit
l'origine et l'intégrité d'une donnée et appuie la non-répudiation de son
signataire (R7-F53) ; elle n'établit pas que la donnée est vraie. Une
déclaration de l'administrateur du client relève des méthodes « examine » et
« interview », pas de la méthode « test », et c'est une autoévaluation sans
indépendance (R7-F51, R7-F52).

### 7.1 Contenu

L'attestation `P` est un objet JSON au schéma
`spec/schemas/attestation-perimetre-v0.schema.json` (`$id`
`https://noortrace.example/schemas/v0/attestation-perimetre.schema.json`),
treize membres, tous obligatoires, clés en anglais, valeurs énumérées en
français sans accent. Les horodatages suivent CT-1 §3.

| Membre | Contenu | Rempli par l'administrateur à partir de |
|---|---|---|
| `version` | `0` | — |
| `org` | `org_id` (CT-1 §3 : 32 octets ; pour une organisation inscrite au registre, le Keccak-256 des octets UTF-8 de `slug`, comme `orgIdOf` de `scripts/lib/noortrace.mjs`), `slug` d'où il est dérivé, `name` | le dossier d'inscription au registre (CT-4 §7) |
| `journals` | Journaux couverts : `journal_id`, `name` ; identifiants distincts | la configuration de chaque enregistreur (`recorder.journal_id`, CT-2 §15) |
| `validity` | `from`, `until`, bornes incluses, `from ≤ until`, au plus 366 jours entre les deux (EX-7.2, refusé par AT-1 au-delà) | la décision de l'organisation (EX-7.5) |
| `issued_at` | Instant de rédaction, déclaratif | l'horloge de l'administrateur |
| `prepared_by` | `identity` (même forme que `delegation.launched_by`, CT-1 §5.3 : chaîne de 1 à 256 caractères, l'identité de la personne telle que le système d'identité du client la nomme, par exemple `u.martin@assureur-demo.example` ; ce courriel et la chaîne `oidc …` de l'exemple complet sont deux formes admises) et `function` de l'administrateur du client | le système d'identité du client |
| `agents` | Inventaire : `agent_id` (distincts), `journal_id` (l'un de `journals`), `host` (nom d'inventaire, jamais une adresse IP), `framework`, `capture_channels` (`mandataire_mcp`, `passerelle`, `icap`, `miroir`, `sdk`, `opentelemetry`), `notes` | l'inventaire des agents de l'organisation ; les connexions d'hôte de chaque enregistreur (`mcp.hosts`, `model.hosts`, `sdk.hosts`, `otel.hosts`, CT-2 §15) |
| `tools_via_proxy_only` | Serveurs d'outils joignables seulement par le mandataire : `server_alias` (alias de `policy.servers`, CT-2 EX-4.9), `tools` (noms, ou `*` : tous les outils du serveur, y compris ceux qu'il annonce pendant la validité), `enforcement` (comment l'organisation l'impose) | `policy.servers` et la mise en application par le réseau (CT-2 §4.9) |
| `egress` | Règles de sortie : `default_policy` (`refus_par_defaut` ou `autorisation_par_defaut`), `rules_sha256` (SHA-256 des octets de l'export des règles, conservé par le client), `rules_format`, `summary`, `allowed_destinations` (`name`, `via` : `enregistreur`, `mandataire_sortant` ou `direct`, `description`) | l'export du pare-feu de sortie |
| `gateway_credentials` | Identifiants d'API que seule la passerelle détient : `route` (`path` d'une route de `policy.model.routes`), `provider_label`, `secret_ref` (référence de secret de CT-2 §15.2 : `env`, `file` ou `vault`) ; la désignation, jamais la valeur | `policy.model.routes` de la configuration |
| `not_captured` | Exceptions connues : `channel`, `description`, `compensating_control` (`null` déclare qu'aucun contrôle compensatoire n'existe) | l'analyse de l'organisation ; CT-2 §21 |
| `signatories` | Personnes qui peuvent signer : `name`, `function`, `address` (adresses distinctes) ; il suffit que `required` d'entre elles, adresses distinctes du jeu, signent (AT-4 : signataires tous dans `signatories` et dans le jeu, en nombre au moins `required`). Un signataire nommé qui ne signe pas n'oblige ni à modifier `P` ni à refaire les pas 3 à 7 de 7.4 | l'annuaire des approbateurs (CT-3 §13.4) |
| `declaration` | Texte que les signataires déclarent, en clair (1 à 4096 caractères) | l'organisation |

Valeurs de `capture_channels`. `mandataire_mcp` : le frontal MCP de
l'enregistreur (connexions `mcp.hosts`). `passerelle` : le frontal modèle en
mode passerelle (`model.hosts`). `icap` : le raccord ICAP du mandataire du
client. `miroir` : une copie passive du trafic déchiffré, fournie par un
équipement du client (CT-2, modes du frontal modèle). `sdk` : le point d'entrée
SDK (`sdk.hosts`). `opentelemetry` : l'ingestion OpenTelemetry (`otel.hosts`).
`host` est le nom que l'hôte porte dans l'inventaire de l'organisation, jamais
une adresse IP. `agent_id` est un identifiant au choix de l'organisation,
distinct pour chaque agent, de la forme que fixe le schéma (une lettre ou un
chiffre, puis au plus 127 lettres, chiffres, `.`, `_`, `:`, `/` ou `-`) ;
l'organisation peut y reprendre l'alias de la connexion d'hôte, ce que PA-10
exploiterait.

Longueurs maximales du schéma `attestation-perimetre-v0` (chaînes d'au moins un
caractère). `notes` et `compensating_control` : chaîne ou `null`, 1024
caractères au plus. `org.name`, `host`, `channel`,
`allowed_destinations[].name`, `signatories[].name` et `function`,
`prepared_by.identity` et `function` : 256 au plus. `journals[].name`,
`framework` et `rules_format` : 128 au plus. `enforcement` et les champs
`description` : 1024 au plus. `summary` et `declaration` : 4096 au plus.

`signatories[].name` est un texte libre ; une désignation de fonction, comme
« Approbateur 1 » dans l'exemple, satisfait le schéma. Le lien entre une
personne et une adresse est celui de l'annuaire (7.8, ligne Signatures). Tout ce
qui est écrit dans `signatories` est divulgué à chaque réviseur (MN-87, RA-73).

`issued_at` est l'instant de rédaction : il est fixé avant les signatures,
puisqu'il fait partie de `P`, et le changer change `D_P`. Toute correction du
texte après le pas 4 de 7.4 impose de refaire les pas 3 à 7. `issued_at` prend
alors l'instant de rédaction du texte corrigé, que les signatures couvriront ;
`D_P` change de toute façon, puisque le texte change. Aucune vérification ne
contrôle sa valeur au-delà de sa forme (AT-1 ; MN-85).

**EX-7.2 (forme).** Une attestation DOIT valider contre
`attestation-perimetre-v0` et respecter les relations que le schéma n'exprime
pas : `validity.from ≤ validity.until` (instants) ; `validity.until −
validity.from` au plus 366 jours (31 622 400 000 ms) ; dates existantes du
calendrier (CT-1 §3) ; `journal_id` distincts dans `journals` ; `journal_id` de
chaque agent présent dans `journals` ; `agent_id` distincts ; `address`
distinctes dans `signatories` ; forme canonique JCS v0 calculable (CT-1 §4 :
aucun nombre non entier, aucune clé en double, aucun substitut isolé). C'est la
vérification AT-1 (CT-1 §11.4).

**EX-7.3 (ce qui n'y figure jamais).** Une attestation NE DOIT contenir aucune
valeur de secret (clé d'API, jeton, mot de passe, phrase de passe, clé privée),
aucune adresse IP, aucun contenu des règles de sortie (seule leur empreinte et
un résumé) et aucune donnée personnelle autre que l'identité et la fonction de
l'administrateur et les noms, fonctions et adresses des signataires. Les
identifiants d'API sont désignés par leur emplacement (`secret_ref`), comme dans
la configuration de CT-2 (EX-15.3). Motif : l'attestation voyage avec les
dossiers vers des réviseurs (CT-6) ; ce qu'elle porte est divulgué à chacun
(MN-87). Le vérificateur ne peut pas le contrôler. L'outil de référence (7.4 :
`verifier --forme`, `verifier` sur une attestation signée, `condenser` et
`signer`) refuse toute chaîne qui CONTIENT une adresse IPv4 ou IPv6 dans un
membre nommé `host`, `name`, `description`, `summary`, `channel`, `enforcement`
ou `notes`, à toute profondeur (donc `org.name`, `journals[].name`,
`signatories[].name` et `egress.allowed_destinations[].name`), et avertit sur
une chaîne de plus de 20 caractères sans espace dans `secret_ref` qui n'est pas
un chemin ni un nom de variable ; cet avertissement ne bloque ni `condenser` ni
`signer` (7.4, pas 3). Les autres membres ne sont pas examinés, notamment les
textes libres `framework`, `declaration`, `compensating_control`, `identity`,
`function`, `provider_label` et `rules_format`, ainsi que `server_alias`,
`tools` et `route`. Aucun outil ne détecte une donnée personnelle : la relecture
de l'administrateur (pas 3) est la seule garde.

**EX-7.4 (cohérence).** Toute destination `allowed_destinations` dont `via` vaut
`direct` et qu'un agent de l'inventaire peut joindre DOIT avoir une ligne dans
`not_captured`. Tout agent dont `capture_channels` contient `passerelle` DEVRAIT
avoir sa route dans `gateway_credentials` quand la route est en `credentials:
"propre"` (CT-2 EX-5.8). Un tableau `not_captured` vide déclare qu'aucune
exception n'est connue de l'organisation, non qu'il n'en existe pas ; l'outil de
référence le rappelle à l'administrateur avant la signature. L'administrateur
juge, d'après les règles de sortie, si un agent peut joindre la destination.
L'outil de référence ne relie pas les destinations aux agents : il tient toute
destination `direct` pour joignable et exige une ligne `not_captured` dont
`channel` est égal, à l'octet près, au `name` de la destination. Il l'exige même
pour une destination `direct` qu'aucun agent de l'inventaire ne peut joindre :
la `description` de la ligne le dit alors (par exemple « aucun agent de
l'inventaire ne joint cette destination selon les règles de sortie ») et
`compensating_control` nomme la règle de sortie qui l'empêche. Le rapport compte
cette ligne parmi les exceptions déclarées (CT-6 EX-6.19, EX-6.20) ; le réviseur
en lit la portée à sa description. Il ne contrôle pas la seconde règle (route
d'un agent `passerelle` dans `gateway_credentials`) : elle relève de la
relecture. Aucun champ de l'attestation ne relie un agent à une route : la
passerelle choisit la route par le chemin de la requête (CT-2 EX-5.2), parmi
celles de `policy.model.routes`, pour toute connexion d'hôte de `model.hosts`.
Les routes d'un agent `passerelle` sont donc celles dont ses requêtes appellent
le chemin, et, à défaut de le savoir, toutes ; l'administrateur vérifie à la
relecture que chacune de ces routes en `credentials: "propre"` figure dans
`gateway_credentials`. Un outil ajouté à un serveur déclaré avec `tools: ["*"]`
est couvert par la déclaration ; s'il ne passe pas par le mandataire, une
nouvelle attestation est due (EX-7.5). Si un outil d'un serveur de
`tools_via_proxy_only` est joignable autrement que par le mandataire, la
déclaration de ce serveur est inexacte. La nouvelle attestation restreint
`tools` ou retire le serveur, et déclare ce canal dans `not_captured`, comme
toute exception connue. Jusqu'à elle, l'ancienne est inexacte (RA-74, et RA-68
si elle l'était dès l'origine).

**EX-7.5 (validité et renouvellement).** `validity` couvre au plus 366 jours
(EX-7.2). L'organisation DEVRAIT signer l'attestation suivante avant
`validity.until`, avec un `validity.from` au plus tard égal à l'instant prévu de
son inscription, et l'inscrire dès que PA-8 est adoptée. Elle DOIT en signer une
nouvelle dès qu'un élément déclaré change : agent ajouté, canal changé, règle de
sortie modifiée, exception découverte ; et DOIT l'inscrire dès que
l'enregistreur sait porter `policy.perimeter` (PA-8) ; d'ici là, elle est jointe
sans inscription (EX-7.12, RA-72). Les tournures « dès que PA-8 est adoptée » et
« dès que l'enregistreur sait porter `policy.perimeter` (PA-8) » désignent le
même moment : l'adoption de PA-8 par une révision de CT-2, qui ajoute
`policy.perimeter` à l'enregistreur (7.4, pas 8). Le DEVRAIT de la deuxième
phrase porte sur la signature avant `validity.until` et sur le choix de
`validity.from` ; l'inscription, elle, est due (DOIT), comme le rappelle
EX-7.12. Jusqu'à cette révision de CT-2, EX-7.12 s'applique : l'attestation est
jointe sans inscription. La liste qui suit les deux-points donne des exemples ;
le critère est qu'un élément déclaré du périmètre (agents, canaux, outils
joignables par le seul mandataire, règles de sortie, identifiants de la
passerelle, exceptions) ne décrive plus la réalité : agent ajouté ou retiré,
canal changé, règle de sortie modifiée, route en `credentials: "propre"` ajoutée
ou retirée, `secret_ref` déplacé, exception découverte. Un changement qui ne
rend inexact aucun de ces éléments, par exemple un nouvel outil qui passe par le
mandataire sur un serveur déclaré avec une liste explicite d'outils, n'en exige
pas. Cet outil est capturé, puisqu'il passe par le mandataire ; il n'est
seulement pas déclaré dans `tools_via_proxy_only`. L'attestation suivante,
remplie depuis `policy.servers` (7.4, pas 1), reprend la liste à jour. Le
déclencheur est la modification des règles de sortie ; un `rules_sha256`
différent en est le signe quand on refait l'export. Un nouvel export des mêmes
règles n'oblige pas à une nouvelle attestation tant que le fichier conservé (pas
9), dont l'empreinte est déclarée, reste celui qu'on présente. Une attestation
ne se révoque pas : une attestation plus récente la remplace pour les événements
postérieurs à son inscription (7.5) ; sans inscription, aucun rang du journal ne
marque ce remplacement, et le réviseur ne le lit qu'à `validity` et à la date de
signature déclarées (RA-72). Une attestation qui remplace une attestation non
inscrite DEVRAIT avoir un `validity.from` postérieur à celui de l'attestation
qu'elle remplace. L'ancienne reste la déclaration signée de ce que
l'organisation savait, pour sa période. Elle n'est exacte que jusqu'au
changement. Une exception découverte montre qu'elle était inexacte dès l'origine
(RA-68), sans la révoquer. Entre le changement et l'inscription de la nouvelle
attestation, collecte des signatures comprise, l'ancienne reste en vigueur alors
qu'elle est devenue inexacte : c'est RA-74. Rien n'oblige à faire le changement
de politique et l'inscription dans le même rechargement ; s'ils sont séparés,
l'intervalle qui les sépare entre dans RA-74.

Exemple complet : l'attestation des vecteurs (organisation `assureur-demo`,
journaux `journal-principal` de l'exemple de référence de CT-1 et
`journal-sinistres` de ses vecteurs, validité du 1er novembre 2026 au
31 janvier 2027). Les noms d'hôtes, de routes et de fichiers sont fictifs ;
`rules_sha256` est le SHA-256 des octets UTF-8 de la chaîne `export fictif
des règles de sortie du pare-feu, vecteurs CT-7`.
Dans les vecteurs, la chaîne tient lieu du fichier d'export ; en exploitation,
l'empreinte porte sur les octets du fichier conservé.

<!-- schema: attestation-perimetre -->
```json
{
  "version": 0,
  "org": {
    "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
    "slug": "assureur-demo",
    "name": "Assureur démo SA"
  },
  "journals": [
    {
      "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
      "name": "journal-principal"
    },
    {
      "journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
      "name": "journal-sinistres"
    }
  ],
  "validity": {
    "from": "2026-11-01T00:00:00.000Z",
    "until": "2027-01-31T23:59:59.999Z"
  },
  "issued_at": "2026-10-30T16:00:00.000Z",
  "prepared_by": {
    "identity": "oidc https://idp.assureur-demo.example admin-agents",
    "function": "administrateur de la plate-forme d'agents"
  },
  "agents": [
    {
      "agent_id": "agent-sinistres",
      "journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
      "host": "hote-agents-01",
      "framework": "service Python, SDK NOORTRACE 0.1",
      "capture_channels": [
        "mandataire_mcp",
        "passerelle"
      ],
      "notes": null
    },
    {
      "agent_id": "agent-principal",
      "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
      "host": "hote-agents-02",
      "framework": "hôte MCP de bureau",
      "capture_channels": [
        "mandataire_mcp",
        "icap"
      ],
      "notes": "requêtes de modèle vues par le mandataire HTTPS de l'organisation"
    }
  ],
  "tools_via_proxy_only": [
    {
      "server_alias": "sap",
      "tools": [
        "*"
      ],
      "enforcement": "seul l'hôte de l'enregistreur joint le serveur d'outils SAP (règle de sortie 12)"
    },
    {
      "server_alias": "crm",
      "tools": [
        "claims.get"
      ],
      "enforcement": "jeton du serveur CRM détenu par l'enregistreur seul (règle de sortie 13)"
    }
  ],
  "egress": {
    "default_policy": "refus_par_defaut",
    "rules_sha256": "0xf36e414b01b7813795a3220703368246d2904119c701835cfbef527c2bfb23ae",
    "rules_format": "export texte du pare-feu",
    "summary": "Refus par défaut. Les hôtes d'agents ne joignent que l'enregistreur ; seul l'hôte de l'enregistreur joint les fournisseurs de modèle et les serveurs d'outils ; les refus sont journalisés au pare-feu.",
    "allowed_destinations": [
      {
        "name": "fournisseurs de modèle",
        "via": "enregistreur",
        "description": "route /v1/messages de la passerelle"
      },
      {
        "name": "serveurs d'outils SAP et CRM",
        "via": "enregistreur",
        "description": "frontal MCP de l'enregistreur"
      },
      {
        "name": "relais de messagerie interne",
        "via": "direct",
        "description": "envoi de courriels hors capture, déclaré dans not_captured"
      }
    ]
  },
  "gateway_credentials": [
    {
      "route": "/v1/messages",
      "provider_label": "fournisseur",
      "secret_ref": {
        "file": "/run/secrets/cle-fournisseur"
      }
    }
  ],
  "not_captured": [
    {
      "channel": "relais de messagerie interne",
      "description": "Un courriel envoyé par le relais SMTP sans passer par l'outil mail.send n'est pas journalisé par l'enregistreur.",
      "compensating_control": "journal du relais SMTP conservé un an"
    }
  ],
  "signatories": [
    {
      "name": "Approbateur 1",
      "function": "responsable des sinistres",
      "address": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
    },
    {
      "name": "Approbateur 2",
      "function": "responsable de la conformité",
      "address": "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
    }
  ],
  "declaration": "Nous déclarons qu'à notre connaissance, pendant la période de validité, les agents de l'inventaire n'atteignent leurs outils et leurs modèles que par les canaux de capture indiqués, sous les règles de sortie dont l'empreinte est donnée, sauf les cas déclarés non capturés."
}
```

Les champs du périmètre reprennent des contrôles publiés, sans qu'aucune
norme lue n'exige une attestation de cette forme : le refus par défaut
(SC-7(5) de SP 800-53 r5, R7-F43 ; SP 800-41 r1, R7-F46), le passage par un
mandataire authentifié (SC-7(8), R7-F44), l'absence d'authentifiant statique
en clair dans les applications (IA-5(7), R7-F47) et le moindre privilège des
processus (AC-6, R7-F48). Qu'une passerelle soit seule à détenir les
identifiants d'API est un choix de conception de NOORTRACE fondé sur ces
contrôles ; aucune norme lue ne l'exige comme tel (R7, section 2).

### 7.2 Condensé et signature

```text
P_P  = octets UTF-8 de "noortrace/attestation-perimetre/v0\n"
     = 6e6f6f7274726163652f6174746573746174696f6e2d706572696d657472652f76300a   (35 octets)
D_P  = keccak256( P_P || JCS(P) )                          32 octets
M    = keccak256( "\x19Ethereum Signed Message:\n32" || D_P )
sig  = ECDSA-secp256k1.Sign( sk(signataire), M ) = r (32) || s (32) || v (1), v ∈ {0x1b, 0x1c}
```

**EX-7.6 (condensé et signature).** `JCS(P)` est la forme canonique JCS v0
de CT-1 §4 de l'objet `P` entier, encodée en UTF-8 ; `D_P` est le Keccak-256
de `P_P` suivi de ces octets. La signature suit CT-1 §6.3 (EIP-191, version
`0x45`, `personal_sign`), avec `D_P` à la place de `D_A` : c'est exactement
`signer.signMessage(getBytes(D_P))` d'ethers et `Account.sign_message(
encode_defunct(primitive=D_P))` d'eth-account. Une signature est acceptée si
et seulement si elle fait 65 octets, que `s` est dans la moitié basse de
l'ordre du groupe, que `v` vaut 27 ou 28 et que l'adresse recouvrée depuis
`(M, r, s, v)` est celle que la signature déclare (AT-3). `D_P` est un
Keccak-256, et non un SHA-256 comme `D_A` : il est, comme les condensés du
registre (CT-4), destiné à des signataires qui le recalculent avec les outils
de l'écosystème EIP-191.

**EX-7.7 (séparation des domaines).** `P_P` est propre à l'attestation. Une
signature de `D_P` ne vaut ni approbation, ni inscription d'approbateur, ni
procès-verbal de cérémonie, ni condensé du registre, et réciproquement :

| Message signé en EIP-191 | Préimage du condensé, premiers octets | Pourquoi aucune collision utile |
|---|---|---|
| `D_P` (attestation) | `keccak256` de `noortrace/attestation-perimetre/v0\n…` | — |
| `D_A` (approbation, CT-1 §6.3) | `SHA-256` de `noortrace/approbation/v0\n…` | autre fonction de hachage et autre préfixe : égaler `D_P` et `D_A` demande une collision entre deux fonctions (H1 de CT-6) |
| Texte d'inscription d'un approbateur (CT-3 §13.5) | texte UTF-8 qui commence par `noortrace/inscription/v0\n`, signé avec sa longueur décimale dans le préfixe EIP-191 | la préimage de `M` pour un condensé fait 60 octets (`0x19`, 25 octets de `Ethereum Signed Message:\n`, `32`, `D_P`) ; pour ce texte de plusieurs centaines d'octets, 26 octets, sa longueur en décimal, puis le texte : préimages de longueurs différentes, égaler les deux `M` est une collision de Keccak-256 (H1) |
| Procès-verbal de cérémonie (section 5) | `keccak256` de `noortrace/ceremonie-cles/v0\n…` | même fonction, préfixes différents : égaler les deux condensés est une collision de Keccak-256 (H1) |
| Condensés du registre (`periodDigest`, `registerDigest`, `revokeDigest`, CT-4) | `keccak256` d'une préimage qui commence par `chainId` sur 32 octets | un `chainId` inférieur à 2^248 commence par un octet nul, `P_P` par `0x6e` : préimages différentes, collision de Keccak-256 (H1) |

Les vecteurs croisés de l'annexe A.6 (`croises.json`) présentent une
signature de chacun de ces messages comme une signature d'attestation, et
inversement : chacune est refusée (AT-3), parce que l'adresse recouvrée sur
le mauvais message n'est pas celle du signataire.

**EX-7.8 (signataires).** Chaque signature DOIT être produite par la clé d'un
membre du jeu d'approbateurs de l'organisation (CT-3 §8, CT-1 §2) nommé dans
`signatories` ; le nombre de signataires distincts DOIT atteindre le seuil
`required` du jeu (AT-4). L'administrateur du client ne compte que s'il est
lui-même membre du jeu et signe avec sa clé d'approbateur ; son identité dans
`prepared_by` n'est pas une signature. Un signataire NE DOIT signer que `D_P`
qu'il a recalculé lui-même depuis le fichier de l'attestation, après en avoir lu
les membres en clair : jamais un condensé reçu tout fait (même règle que CT-4
EX-7.10 pour le registre). Comme en EX-5.8, il DOIT comparer `D_P`, groupe de
huit chiffres par groupe de huit, entre l'écran du portefeuille matériel et un
second outil indépendant de l'outil de signature, par exemple le mode
`condenser` du vérificateur Go de `ct-7` (EX-A.21) : depuis le répertoire
`spec/vecteurs/ct-7/verificateur-independant/`, `go run . condenser
<attestation.json>` imprime `D_P` suivi de ses groupes de huit chiffres ; s'il
signe par un fichier de clé, sans portefeuille qui affiche le condensé, le
recalcul par ce second outil est obligatoire. eth-account seul ne convient pas :
il ne calcule pas la forme JCS v0 préfixée de `P_P`. La console de CT-3 ne signe
que des décisions d'approbation (`D_A`) et NE DOIT PAS signer une attestation ;
la signature se fait par l'outil de référence (7.4) ou un outil qui remplit
cette règle, avec la clé d'approbateur sur son support habituel (portefeuille
matériel, fichier de clé chiffré de CT-3 §13.13).

Exemple numérique (attestation de 7.1, comptes Hardhat 1 et 2 du jeu de
trois au seuil de deux des vecteurs ; signatures RFC 6979, déterministes) :

```text
JCS(P)  = 3201 octets
D_P     = 0x4481a2e47712539c4ca50f2eea3d6062ec11a70d497c153c1a6f707606657cfd
M       = 0x6a4450a8f1729139886741854c27c710dc468ef6888ad3260a5574718d14f790
sig (0x70997970c51812dc3a010c7d01b50e0d17dc79c8)
        = 0x77cd5463cb88d5e9327bc0f31aecde620267a3a2267efd3cbf18839a57955af1793571375853490a4d494f5eaf28a90812ac70c8fae00d18a7d1edb372ee44f11c
sig (0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc)
        = 0x7d80f09897a9661ecd568bd94ccd75d0b53381566aa77c108b28cafa6b6bdc617ad35c56e5976232b50568f40b3901bb7d19d5e8be3d14bccd76c1b283e5f26f1c
```

La signature du compte 3 sur le même `M`,
`0x3daebe7960d9870ebf2d5a03492283474286dbf28f7e53f20b51ba60f6e01cd603332971435717c899b12c9dd0a37aa7704e9500645a67732f7821eaf034648b1c`,
attribuée au compte 2, recouvre `0x90f79bf6eb2c4f870365e785982e1f101e93b906`
et fait échouer AT-3 (cas `invalide-at3-signature-substituee`, annexe A.6).

### 7.3 Attestation signée

**EX-7.9 (forme remise).** L'administrateur remet une **attestation
signée** (`attestation-perimetre-v0#/$defs/attestation_signee`) :
`{ "version": 0, "attestation": P, "digest": D_P, "signatures": [ { "address",
"signature" } ] }`, au moins une signature, au plus 64. `digest` est déclaré
et recalculé par le vérificateur (AT-2) ; l'ordre des signatures est libre ;
une adresse n'y figure qu'une fois (AT-4). Le fichier est écrit en UTF-8 ;
sa mise en forme est libre, puisque seule `JCS(P)` est condensée.

Forme de l'attestation signée de l'exemple (l'objet `P` est celui de 7.1 ;
le fichier complet est
`spec/vecteurs/ct-7/attestations/exemple/attestation-signee.json`) :

```text
{ "version": 0,
  "attestation": P,
  "digest": "0x4481a2e47712539c4ca50f2eea3d6062ec11a70d497c153c1a6f707606657cfd",
  "signatures": [
    { "address": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "signature": "0x77cd…f11c" },
    { "address": "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "signature": "0x7d80…f26f1c" } ] }
```

### 7.4 Remplir, faire signer, inscrire : pas à pas pour l'administrateur du client

Ce qui suit est la procédure de l'administrateur du client. Elle suppose que
l'organisation est inscrite au registre (CT-4 §7), que son jeu
d'approbateurs existe et que ses enregistreurs tournent. L'outil de
référence est `scripts/conformite/attestation.mjs` ; un autre outil convient
s'il fait les mêmes contrôles (EX-7.8).

1. **Rassembler les pièces.** L'`org_id` et le `slug` (dossier
   d'inscription, CT-4 §7.10) ; le `journal_id` de chaque enregistreur
   (configuration, `recorder.journal_id`) ; la liste des connexions d'hôte de
   chaque enregistreur (`mcp.hosts`, `model.hosts`, `sdk.hosts`,
   `otel.hosts`) ; `policy.servers` et `policy.model.routes` ; l'export du
   pare-feu de sortie ; l'annuaire des approbateurs (CT-3 §13.4) ; la liste
   des exceptions connues.
2. **Remplir le gabarit.** `node scripts/conformite/attestation.mjs gabarit
   > attestation.json` produit un gabarit conforme au schéma ; remplir chaque
   membre selon la table de 7.1. Calculer `rules_sha256` sur le fichier
   d'export exact que l'organisation conservera (`sha256sum` du fichier,
   préfixé de `0x`). N'écrire ni secret, ni adresse IP, ni contenu de règle
   (EX-7.3). Déclarer toute sortie `direct` dans `not_captured` (EX-7.4).
3. **Contrôler.** `node scripts/conformite/attestation.mjs verifier --forme
   attestation.json` applique AT-1 et les contrôles d'EX-7.3 et EX-7.4, et
   affiche les membres en clair. Corriger jusqu'à ce qu'il ne signale plus
   d'erreur. Seules les erreurs d'AT-1, d'EX-7.3 (adresse IP) et d'EX-7.4
   (sortie `direct` sans ligne `not_captured`) bloquent `condenser` et `signer`
   (code 1). L'avertissement sur une chaîne de `secret_ref` et le rappel d'un
   `not_captured` vide ne bloquent pas : l'administrateur relit l'avertissement
   et laisse la chaîne si elle désigne bien un emplacement de secret et non une
   valeur. C'est le comportement de l'outil de référence.
4. **Condenser.** `node scripts/conformite/attestation.mjs condenser
   attestation.json` refait les contrôles du pas 3 (code 1 s'ils échouent),
   imprime `D_P` et l'affiche par groupes de huit chiffres. Transmettre aux
   signataires le **fichier**, jamais le seul condensé.
5. **Faire signer.** Chaque signataire, membre du jeu, exécute de son côté `node
   scripts/conformite/attestation.mjs signer attestation.json --cle
   fichier:<fichier de la clé en hexadécimal 0x>` ou `--cle keystore:<fichier de
   clé chiffré de CT-3 §13.13>`, le mot de passe étant lu dans la variable
   `NOORTRACE_MOT_DE_PASSE` ; toute autre forme rend le code 2. L'outil refait
   les contrôles du pas 3, recalcule `D_P`, affiche les membres et `D_P` par
   groupes de huit chiffres, demande confirmation (sauf `--oui`), signe et écrit
   `{ "address", "signature" }`. Le signataire compare `D_P` à un second outil
   indépendant avant de confirmer (EX-7.8). Il faut au moins `required`
   signataires distincts du jeu (EX-7.8). `fichier:` lit une clé privée en clair
   et sert aux vecteurs et au développement. Pour une clé d'approbateur réelle,
   le support habituel désigné par EX-7.8 est le portefeuille matériel ou le
   fichier de clé chiffré (`keystore:`). `--oui` ne dispense pas de la
   comparaison d'EX-7.8 : avec cette option, le signataire compare `D_P` avant
   de lancer `signer`, entre la sortie de `condenser` sur son propre poste et le
   second outil. L'outil de référence de la version 0 ne signe qu'avec
   `fichier:` ou `keystore:`. Un signataire à portefeuille matériel signe `D_P`
   avec un autre outil qui remplit EX-7.8 (`personal_sign` des 32 octets de
   `D_P`, après recalcul et comparaison au second outil et à l'écran du
   portefeuille), puis remet `{ "address", "signature" }` au pas 6. La version 0
   ne nomme pas cet outil ; convient tout outil qui fait `personal_sign` des 32
   octets de `D_P` après les comparaisons d'EX-7.8. La remise `{ "address",
   "signature" }` est en hexadécimal minuscule (CT-1 §3, adresse comprise : pas
   de somme de contrôle EIP-55), avec `v` égal à 27 ou 28 : `assembler` la
   recopie telle quelle. Une remise en majuscules fait échouer AT-1 au pas 7,
   une signature dont `v` vaut 0 ou 1 y fait échouer AT-3 ; le signataire ajoute
   alors 27 à `v` avant de la remettre.
6. **Assembler.** `node scripts/conformite/attestation.mjs assembler
   attestation.json signature-1.json signature-2.json >
   attestation-signee.json`.
7. **Vérifier comme un réviseur.** `node scripts/conformite/attestation.mjs
   verifier attestation-signee.json --jeu jeu.json` ; `--jeu` est obligatoire
   pour une attestation signée (code 2 sinon). `jeu.json` a la forme de
   `approver_set` dans `approbations.json` (CT-1 §11.2) : `threshold`,
   `members`, `source`. On le lit au préalable, en ligne, dans le `CuratorSet`
   de l'organisation au registre (CT-4 §5.5), par la lecture à une hauteur de
   CT-3 EX-8.1 : `curatorSetOf(orgId)`, puis le seuil et les membres de ce
   `CuratorSet`, tous lus à une même hauteur de bloc `H`. `source` (texte libre,
   CT-1 §11.2) porte l'instance du registre (`chain_id`), l'adresse du
   `CuratorSet` et la hauteur `H`. La section 7 ne nomme pas d'outil pour ces
   lectures ; un client RPC qui lit l'état d'un contrat à une hauteur donnée
   suffit. La version 0 ne fixe pas `H` : elle exige seulement que le seuil et
   les membres soient lus à une même hauteur, à la date des signatures
   (EX-7.13). AT-4 compare les signataires au jeu lu à `H`, et le réviseur
   recoupe tout l'intervalle des signatures avec l'historique des
   `CuratorSetAssigned` (EX-7.13). L'administrateur inscrit `H` dans `source`,
   où il peut aussi noter cet intervalle (ci-dessous). `members` s'écrit en
   adresses minuscules (CT-1 §3), et `threshold` porte `required` (le seuil lu)
   et `size` (le nombre de membres). Seule la vérification qui suit est hors
   ligne : l'outil n'ouvre aucune connexion. AT-1 à AT-4 doivent réussir ; codes
   de retour : 0 si l'attestation est retenue, 1 sinon, 2 pour une entrée
   illisible. Que ce jeu soit celui de la date des signatures reste une
   déclaration (7.8, ligne Seuil). Quand la collecte s'étale, « la date des
   signatures » s'entend de l'intervalle entre la première et la dernière
   signature ; le recoupement d'EX-7.13 couvre tout cet intervalle. Les
   signatures ne portent pas de date, et aucun membre de l'attestation signée ni
   de la partie ne consigne cet intervalle en version 0 ; `source` étant un
   texte libre de 256 caractères au plus (CT-1 §11.2), l'administrateur peut y
   noter l'intervalle à côté de `chain_id`, de l'adresse et de `H` ; le réviseur
   le lit comme déclaré.
8. **Inscrire.** Ajouter `D_P` à l'ensemble de politique de chaque enregistreur
   dont le journal figure dans `journals`, membre
   `policy.perimeter.attestation_digest`, avec une **nouvelle**
   `policy.version`, et recharger (CT-2 EX-15.5) : l'enregistreur scelle
   l'événement `noortrace.journal.politique` qui inscrit l'attestation (7.5).
   Tant que CT-2 n'a pas adopté PA-8, ce pas n'est pas réalisable et
   l'attestation reste sans inscription (MN-85). Une fois l'attestation
   inscrite, elle ne reste en vigueur que si chaque nouvelle version de
   politique garde `policy.perimeter.attestation_digest` égal à `D_P` ; le
   retirer retire l'attestation des événements suivants (EX-7.11). L'inscription
   à joindre est celle de la version de politique de l'événement prouvé
   (EX-7.11, AT-7).
9. **Conserver.** Garder l'attestation signée, le fichier d'export des règles de
   sortie dont `rules_sha256` est l'empreinte, et le document de politique qui
   l'inscrit, aussi longtemps que les journaux qu'elle couvre (dix ans, CT-2
   EX-12.19), sur le même support (copies WORM, CT-2 §12.6). En version 0, sans
   inscription, on conserve l'attestation signée et le fichier d'export des
   règles ; le document de politique qui l'inscrit n'existe qu'une fois PA-8
   adoptée.
10. **Joindre et renouveler.** L'exportateur joint l'attestation en vigueur
    aux dossiers (7.6). Signer la suivante avant `validity.until`, avec un
    `validity.from` au plus tard à l'instant de l'inscription (EX-7.5 et
    paragraphe qui suit EX-7.11), et dès qu'un élément déclaré change, puis
    l'inscrire comme au pas 8 dès que PA-8 est adoptée (EX-7.5). En version 0,
    sans inscription, la règle pratique est celle d'EX-7.5 : un
    `validity.from` postérieur à celui de l'attestation remplacée.

Ce que l'administrateur doit savoir avant de faire signer, en une table
(la section 7.8 la développe) :

| L'attestation, une fois vérifiée, établit | Elle n'établit pas |
|---|---|
| que ces adresses, membres du jeu déclaré, ont signé exactement ce texte, et qu'il n'a pas changé depuis | que le périmètre déclaré est exact, ni qu'aucun agent ne contourne la capture |
| avec l'inscription jointe (impossible en version 0, PA-8) : qu'un événement signé par la clé de l'événement prouvé, de rang et d'instant déclaré au plus ceux de cet événement, annonce une politique qui porte `D_P` ; l'appartenance à la même chaîne n'est pas prouvée, seul `seq` est comparé (7.8) | la date de sa signature ; la date de l'inscription n'est prouvée que par le dossier de l'événement d'inscription |
| quelles exceptions l'organisation déclarait connaître | qu'il n'existe pas d'autre exception |

### 7.5 Inscription au journal

**EX-7.10 (porteur).** L'attestation est inscrite dans chaque journal
qu'elle couvre par l'événement `noortrace.journal.politique` (CT-1 §5.1,
§8 ; CT-2 §9.1) de l'ensemble de politique dont le membre
`perimeter.attestation_digest` vaut `D_P` (proposition PA-8 à CT-2) :
`execution.arguments.value.policy_sha256` est le SHA-256 du document de
politique (CT-2 EX-8.11), qui contient `D_P`. Aucun nom réservé nouveau
n'est créé : le format v0 de l'événement ne change pas. L'inscription
**ordonne** l'attestation dans la chaîne (son `seq`, son `prev_hash`) et la
**date** au plus tard par les ancres de la période ou du point de contrôle
qui l'engagent (CT-5) ; ces ancres sont celles du dossier de l'événement
d'inscription, que l'exportateur produit à part, non celles du dossier où
l'attestation est jointe.

**EX-7.11 (une inscription par journal, une attestation à la fois).** Un
ensemble de politique porte au plus un `D_P`. L'attestation en vigueur pour
un événement est celle dont `D_P` figure dans l'ensemble de politique de sa
`code.policy_version` ; une attestation nouvelle s'inscrit par une version
de politique nouvelle (CT-2 EX-15.5 exige déjà une `policy.version`
différente au rechargement ; PA-9 demande qu'un nom de version déjà annoncé ne
soit jamais réannoncé avec un autre `policy_sha256`). Retirer `perimeter` de
l'ensemble de politique retire l'attestation des événements suivants. AT-7 ne
compare que des noms de version : tant que PA-9 n'est pas adoptée, un nom
réannoncé avec un autre contenu la fait réussir (MN-91, RA-75), et le fragment
FP ne dit alors que « même nom ». Un changement de version légitime qui garde le
même `D_P` rend lui aussi AT-7 `non_execute` (`piece_hors_dossier`) pour les
événements de la nouvelle version : il faut joindre l'inscription de cette
version.

Une attestation inscrite avant son `validity.from` est en vigueur pour des
événements que sa validité ne couvre pas. Pour eux, AT-5 échoue et l'attestation
n'est pas retenue (AV-AT-1). L'attestation précédente ne l'est pas non plus si
son inscription est jointe : la version de politique de l'événement n'est plus
la sienne (AT-7). Pour l'éviter, l'administrateur fixe le `validity.from` de
l'attestation suivante au plus tard à l'instant prévu de son inscription (7.4,
pas 10).

Après une rotation de la clé de l'enregistreur, une inscription signée par
l'ancienne clé rend AT-6 `non_execute` (`ancre_absente`), et AT-7 `non_execute`
(`prerequis_en_echec`), pour les événements signés par la nouvelle ;
l'attestation peut rester retenue (section 2). Pour qu'AT-6 s'exécute pour eux,
une inscription signée par la nouvelle clé est nécessaire : une nouvelle
version de politique, annoncée après la rotation, qui porte le même `D_P`.

Chaque journal listé a son ensemble de politique et sa propre inscription. Si
l'inscription réussit dans un journal et pas dans l'autre, AT-6 ne peut réussir
que pour les événements du premier ; pour le second, l'attestation se joint sans
inscription (EX-7.12).

**EX-7.12 (sans inscription).** Tant que l'enregistreur ne sait pas porter
`policy.perimeter` (PA-8), ou quand le client ne veut pas divulguer son document
de politique au réviseur (7.6), l'attestation est jointe sans inscription
(`inscription: null`) : AT-6 et AT-7 ne s'exécutent pas (raison admise
`partie_absente`), le fragment FP de l'énoncé porte la clause fixe « non
inscrite au journal (ni sa date ni son rang ne sont établis) » (CT-6 EX-6.19),
et rien ne situe l'attestation dans le temps du journal ; sa validité peut même
commencer avant sa signature, `issued_at` étant déclaré. C'est le risque accepté
RA-72 tant que PA-8 n'est pas adoptée (menace MN-85), puis RA-82 quand le client
choisit de ne pas inscrire ou de ne pas joindre l'inscription (MN-98). Inscrire
est une exigence (EX-7.5 : DOIT dès que l'enregistreur sait porter
`policy.perimeter`) ; joindre l'inscription au dossier est un choix du client
(EX-7.14), parce qu'il divulgue le document de politique. RA-82 couvre deux
cas : le client qui ne suit pas EX-7.5, reste d'un écart à une exigence et non
une option, et celui qui, ayant inscrit, ne joint pas l'inscription, choix admis
par EX-7.14.

Exemple : le journal rejoué des vecteurs (`journal-sinistres`, CT-1 §13),
où l'événement de politique seq 12 annonce un ensemble de politique réduit,
pour les vecteurs, à son membre `perimeter` et à sa version. Le document de
politique, en forme canonique intégrale (CT-2 EX-8.11), et son SHA-256 :

```text
document = {"perimeter":{"attestation_digest":"0x4481a2e47712539c4ca50f2eea3d6062ec11a70d497c153c1a6f707606657cfd"},"version":"2026-11-05"}
SHA-256  = 0x5016ffc47d07a5ec0dae8c464a0a5cf466cd4f425fadbf293dafbd36617f63d9   (policy_sha256)
base64   = eyJwZXJpbWV0ZXIiOnsiYXR0ZXN0YXRpb25fZGlnZXN0IjoiMHg0NDgxYTJlNDc3MTI1MzljNGNhNTBmMmVlYTNkNjA2MmVjMTFhNzBkNDk3YzE1M2MxYTZmNzA3NjA2NjU3Y2ZkIn0sInZlcnNpb24iOiIyMDI2LTExLTA1In0=
```

L'événement d'inscription, scellé par `rec-test-02` (même enveloppe que
seq 12 des vecteurs de CT-1, à `execution.arguments` près ; `prev_hash` est
le hachage de seq 11, inchangé) :

<!-- schema: evenement -->
```json
{
  "version": 0,
  "seq": 12,
  "ts": "2026-11-05T10:05:00.000Z",
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
  "recorder_key_id": "rec-test-02",
  "prev_hash": "0xf92b743f6e089038b2182131434071ef5d6fe5c4dbc55fd8c30a0e431725efdb",
  "delegation": {
    "launched_by": "noortrace-enregistreur",
    "on_behalf_of": null,
    "scope": "journal:administration",
    "run_id": null
  },
  "code": {
    "model": null,
    "prompt_version": null,
    "policy_version": "2026-11-05",
    "recorder": "0.1.0"
  },
  "intent": null,
  "policy": {
    "rule": null,
    "decision": "sans_objet",
    "ticket": null,
    "redaction": null
  },
  "approval": null,
  "execution": {
    "tool": "noortrace.journal.politique",
    "arguments": {
      "sha256": "0xabf74619ab04a14027f13003aacba674f864cdebb83d611b001391543cc965aa",
      "length": 116,
      "redacted": false,
      "value": {
        "policy_version": "2026-11-05",
        "policy_sha256": "0x5016ffc47d07a5ec0dae8c464a0a5cf466cd4f425fadbf293dafbd36617f63d9"
      }
    },
    "status": "executee",
    "result": null,
    "duration_ms": null,
    "is_error": null
  },
  "effects": [],
  "context": [],
  "hash": "0x5aac251a7fa898317e6fd40eae4594234960cf682e4a182cf2de0a9f65b0ef90",
  "sig": "0x7e757e190377226dac6baf2ba65db8d534565003e16603863a3bdc111c8cb00ff87ce43cfffa3e8f81f434c3de28b624d3480d64688bddd640355f3a2e718f04"
}
```

### 7.6 Joindre au dossier

**EX-7.13 (partie du dossier).** L'exportateur PEUT joindre à un dossier
l'attestation en vigueur pour l'événement prouvé, sous la forme de la
quatorzième partie facultative `attestation-perimetre.json` de CT-1
(révision 0.4, §11.1 et §11.2) : l'attestation signée, le jeu
d'approbateurs déclaré auquel ses signataires sont comparés (`approver_set`,
même forme et même `source` que dans `approbations.json`, lu dans le
`CuratorSet` de l'organisation à la date des signatures) et, s'il la
fournit, l'inscription (`inscription` : l'événement de 7.5, complet, et les
octets du document de politique en base64). L'attestation jointe DOIT être
celle dont la validité couvre le `ts` de l'événement prouvé, et dont
l'inscription, si elle est jointe, précède cet événement dans le journal. Quand
le journal ne porte aucune inscription (tant que PA-8 n'est pas adoptée), aucune
règle de la version 0 ne départage deux attestations dont les validités couvrent
le `ts` : l'exportateur en joint une, et rien ne situe l'une par rapport à
l'autre dans le journal (RA-72). Le remplacement « pour les événements
postérieurs à son inscription » (EX-7.5) suppose l'inscription. Quand
l'inscription existe mais n'est pas jointe (EX-7.12), l'exportateur DOIT joindre
l'attestation en vigueur au sens d'EX-7.11, et le réviseur ne peut pas le
vérifier (RA-72).

Le réviseur qui recoupe le jeu déclaré avec le `CuratorSet` de l'organisation
« à la date des signatures » recoupe aussi l'historique des `CuratorSetAssigned`
de l'organisation, du jeu épinglé par la politique (CT-3 EX-8.6) jusqu'à cette
date : toute réassignation intervenue entre-temps est signalée dans son rapport,
car un administrateur du registre malveillant peut réassigner le jeu à des
adresses qu'il contrôle (MN-38, RA-34).

Pour l'administrateur : l'exportateur, en pratique l'administrateur du client,
déclare lui-même le jeu auquel AT-4 compare les signataires. Le réviseur le
recoupe avec le `CuratorSet` et l'historique des `CuratorSetAssigned` (MN-82,
RA-70).

**EX-7.14 (inscription jointe ou non).** Joindre l'inscription divulgue le
document de politique entier au réviseur (règles d'approbation, de
rédaction, carte des serveurs d'outils, routes) : cette décision relève du
client. Sans elle, l'attestation est vérifiée sans sa place dans le journal
(EX-7.12).

**EX-7.15 (absence).** Un dossier sans la partie, ou qui la déclare absente
(raison « aucune attestation de périmètre », par exemple), ne dit rien du
périmètre. Aucun outil de NOORTRACE NE DOIT présenter l'absence
d'attestation comme un périmètre complet, ni l'absence d'exception déclarée
comme l'absence d'exception.

### 7.7 Vérification par le réviseur

**EX-7.16 (vérifications).** L'attestation se vérifie hors ligne, sans
réseau et sans ancre nouvelle du réviseur, par les vérifications AT-1 à
AT-7 de CT-1 §11.4 (révision 0.4), reprises ici pour la lecture :

| Id | Vérifie | Avec |
|---|---|---|
| AT-1 | forme de la partie et de l'attestation (schémas, EX-7.2 dont la validité d'au plus 366 jours, JCS v0) | la partie seule |
| AT-2 | `digest` égal à `D_P` recalculé | AT-1 |
| AT-3 | chaque signature canonique, recouvrant l'adresse qu'elle déclare, sur `M` | AT-2 |
| AT-4 | adresses distinctes, toutes dans `signatories` et dans `approver_set.members`, en nombre au moins `threshold.required` ; `required ≤ size` = nombre de membres | AT-3 |
| AT-5 | `org.org_id` et `journal_id` de l'événement prouvé couverts ; `ts` de l'événement dans `validity` | AT-1, événement exploitable |
| AT-6 | inscription : événement bien formé (E-1 à E-7, E-11) et signé par la clé de `cles.json` qui signe l'événement prouvé (même `recorder_key_id` ; une autre clé : `non_execute`, `ancre_absente`), `noortrace.journal.politique` de la même organisation et du même journal, document de politique de SHA-256 `policy_sha256` dont `/perimeter/attestation_digest` vaut `D_P`, `seq` au plus celui de l'événement prouvé (même `hash` recalculé en cas d'égalité) et `ts` au plus le sien ; aucun hachage ne relie l'inscription à la chaîne de l'événement prouvé | AT-2, `evenement.json` et `cles.json` exploitables ; `partie_absente` sans inscription |
| AT-7 | la version de politique de l'événement prouvé a le même nom que celle de l'inscription (noms seulement, PA-9) | AT-6 ; `piece_hors_dossier` sinon |

Hors de tout dossier (une attestation signée et un jeu, avant de la
joindre), AT-1 à AT-4 s'appliquent seules, et l'attestation est retenue si
elles réussissent ; c'est ce que rejouent les vecteurs de la famille
`ct-7/attestations` (annexe A.6).

**EX-7.17 (rapport).** Le jeu d'approbateurs auquel AT-4 compare les
signataires est déclaratif, avec sa source, comme celui du contrôle 7 (CT-6
§3.3) : la version 0 n'a ni ancre d'approbateurs ni preuve d'état du
registre. Le rapport du vérificateur dit le périmètre « déclaré, non
prouvé », nomme le condensé, la validité, les signataires, le seuil et le
jeu déclaré, et l'inscription quand AT-6 a réussi (fragment FP de l'énoncé,
`facts.perimeter` dont `provenance` vaut toujours `declaree` ; CT-6 EX-6.19,
EX-6.20). Une attestation non retenue est signalée par AV-AT-1 et par le
fragment FP « non retenue », sans changer le verdict.

### 7.8 Ce qu'elle prouve et ne prouve pas

| Élément | Ce qu'une vérification réussie établit | Ce qu'elle n'établit pas |
|---|---|---|
| Condensé (AT-2) | Le texte de l'attestation est celui que les signatures couvrent, octet pour octet après forme canonique. | Que ce texte est vrai. |
| Signatures (AT-3) | Les clés de ces adresses ont signé `D_P` (origine, intégrité, appui à la non-répudiation, R7-F53, sous H1 et H2 de CT-6). | Que les personnes nommées dans `signatories` tiennent ces clés : le lien personne-adresse est celui de l'annuaire (CT-3 §13.5), hors du dossier. |
| Seuil (AT-4) | Au moins `required` adresses distinctes du jeu déclaré ont signé. | Que le jeu déclaré est le `CuratorSet` de l'organisation à cette date : déclaratif, comme pour le contrôle 7 (CT-1 §15). |
| Liaison (AT-5) | L'attestation nomme l'organisation et le journal de l'événement, et sa validité couvre l'instant déclaré de l'événement. | Que l'agent qui a produit l'événement figure dans l'inventaire ; `ts` reste déclaratif (CT-1 §5.2). |
| Inscription (AT-6) | `D_P` figure dans l'ensemble de politique annoncé par un événement signé par la clé de l'événement prouvé, de rang et d'instant déclaré au plus ceux de l'événement prouvé. | L'appartenance de l'inscription à la chaîne de l'événement prouvé : aucun hachage ne les relie, seul `seq` est comparé ; ni l'inclusion de l'événement d'inscription dans une période ancrée, ni sa date : son propre dossier les prouve (comme pour les décisions de `approbations.json`, CT-1 §15). La clé elle-même n'est établie que par N-3 (MN-90). |
| Politique en vigueur (AT-7) | L'événement prouvé porte une version de politique de même nom que celle qui inscrit l'attestation. | Que l'attestation était en vigueur pour l'événement : un nom de version réannoncé avec un autre contenu fait réussir AT-7 (PA-9, MN-91, RA-75). |
| Le périmètre lui-même | Rien : il est déclaré. | Qu'aucun agent ne contourne la capture ; que les règles exportées sont celles qui s'appliquent ; que l'inventaire est complet. Seul un essai (méthode « test » de SP 800-53A, R7-F51), par exemple un essai d'exfiltration (SC-7(10) b), R7-F45), mené par un évaluateur indépendant (R7-F52), en rapproche ; il relève du client. |
| La conformité réglementaire | Rien. | La section 8 (matrice) établit des correspondances techniques ; aucune ne dit qu'un client est conforme. |

L'essai de sortie est recommandé (DEVRAIT, EX-3.13 : au moins une fois par an et
après tout changement des règles de sortie), mené et porté par le client ; il
n'est pas une condition de l'attestation, qui PEUT en citer le résultat
(EX-3.13).

### 7.9 Exigences de parité, mesurables

**EX-7.18 (parité).** La parité de NOORTRACE sur l'attestation de périmètre
s'écrit en exigences que CT-9 mesure, sans référence à un produit :

1. tout dossier PEUT porter l'attestation en vigueur, et le vérificateur la
   vérifie sans réseau (CT-6 EX-3.3, V-8) ;
2. le rapport nomme, pour une attestation retenue, `D_P`, la validité, les
   adresses signataires, le seuil et la source du jeu, le nombre d'agents,
   les canaux, le nombre d'exceptions, l'empreinte des règles de sortie et,
   avec l'inscription, son `seq` et son `hash` (`facts.perimeter`) ;
3. aucun énoncé, aucun résumé, aucune ligne du rapport ne contient « prouvé » ou
   « vérifié » appliqué au périmètre (test de CT-9 sur tous les rapports des
   vecteurs) ;
4. une attestation non retenue ne change ni un statut de contrôle ni le
   verdict ni le code de retour, et produit toujours AV-AT-1 (V-10 de CT-6) ;
5. un dossier sans attestation a le même rapport qu'avec un vérificateur
   de la révision 0.2 de CT-6, au membre `facts.perimeter` (`null`), à
   `verifier.schemas` (dix schémas) et, si la quatorzième partie est
   déclarée absente, à la ligne d'`absent_parts` près (CT-6 EX-6.21) ;
6. deux implémentations indépendantes (référence JavaScript, vérificateur
   Go de `spec/vecteurs/ct-7`) rendent les mêmes statuts AT- sur tous les
   vecteurs, et deux bibliothèques tierces (ethers, eth-account) recouvrent
   les mêmes adresses de toutes les signatures d'attestation (annexe A.13).

### 7.10 Menaces propres à l'attestation

Les menaces de l'attestation sont consolidées dans la table du modèle de
menace (3.4) et dans `menaces.json`, chacune avec sa réponse, sa détection,
son risque résiduel et le test de CT-9 :

- MN-78 : périmètre déclaré plus large que la réalité, signé (risque accepté
  RA-68) ;
- MN-79 : attestation d'une autre organisation ou d'un autre journal ;
- MN-80 : attestation hors de sa validité (RA-69) ;
- MN-81 : signature substituée, non canonique, ou d'une adresse hors du jeu ;
- MN-82 : jeu d'approbateurs déclaré par l'exportateur (RA-70) ;
- MN-83 : signature produite pour un autre domaine ;
- MN-84 : inscription forgée par l'exportateur, avec ou sans la clé de
  l'enregistreur (RA-71) ;
- MN-85 : attestation sans inscription tant que PA-8 n'est pas adoptée
  (RA-72) ;
- MN-86 : attestation inscrite après l'événement qu'elle prétend couvrir ;
- MN-87 : divulgation du périmètre déclaré (RA-73) ;
- MN-88 : inventaire périmé pendant la validité (RA-74) ;
- MN-89 : partie énorme ou malformée ;
- MN-90 : inscription signée par une clé non reliée à l'événement prouvé ;
- MN-91 : nom de version de politique réannoncé (RA-75) ;
- MN-98 : attestation non inscrite par choix du client (RA-82).

### 7.11 Ce que l'attestation demande à CT-2

Les propositions de l'attestation sont PA-8 à PA-11 de la table 6.2 : le
membre `policy.perimeter` de l'ensemble de politique (PA-8), l'unicité des
noms de version de politique (PA-9), les consignes du journal d'exploitation
(PA-10) et la métrique d'échéance (PA-11). CT-2 et ses vecteurs ne changent
pas dans ce lot ; tant que PA-8 n'est pas adoptée, une attestation réelle
n'a pas d'inscription (EX-7.12, RA-72).

## 8. Matrice de conformité

> **Avertissement.** Cette matrice établit une correspondance technique entre
> des passages de textes et des pièces de preuve produites par NOORTRACE. Elle
> n'est pas un avis juridique et ne dit jamais qu'un client est conforme : la
> qualification du client, l'applicabilité de chaque texte et la conformité
> relèvent du client et de ses conseils.

Cette section met en regard des passages de textes suisses et européens et les
pièces de preuve de NOORTRACE. Pour chaque passage, elle cite le texte
exactement, dit ce qu'il exige, puis, élément par élément, quelle pièce y répond
ou y contribue, ce qu'elle ne couvre pas et ce qui relève du client. Elle dit
aussi quand le texte s'applique : les quatre articles retenus du règlement (UE)
2024/1689 (art. 12, 14, 19 et 26) ne s'appliquent pas encore au 2026-10-26 (T-8,
EX-8.4) ; la matrice ne retient aucun autre article de ce règlement.

Un responsable de la conformité qui ne lit que cette section trouve, pour un
article donné, la ligne qui le cite (8.4, colonne « Référence »), la pièce
qui y répond (colonne « Pièce NOORTRACE »), ce qui n'est pas couvert et ce
qui relève de lui (deux colonnes suivantes) ; la sous-section 8.10 montre la
lecture d'une ligne. Il n'y trouve jamais qu'il est conforme.

La section 8 nomme chaque pièce par renvoi à CT-1 à CT-6 et en dit l'objet en
une ligne. Vérifier ce que la pièce fait demande de lire la spécification citée.

Dans cette section et l'annexe C, « l'Exploitant » des clauses et « l'exploitant
NOORTRACE » désignent NOORTRACE ; « l'exploitant » de CT-5 est l'administrateur
du client (section 2). Une « pièce » est celle de la matrice (section 2), non
une pièce jointe d'un événement ni une pièce comptable.

**EX-8.1 (avertissement).** Toute sortie de NOORTRACE qui reproduit la
matrice ou l'une de ses lignes (document, page, export, réponse d'un outil)
DOIT porter l'avertissement ci-dessus, mot pour mot ; c'est la valeur du
membre `warning` de `matrice-conformite.json`, que le schéma fixe. Aucune
sortie NE DOIT dire ni laisser entendre qu'un client « est conforme », que
NOORTRACE « garantit » ou « certifie » une conformité, ni présenter une ligne
`couvert` autrement que comme une correspondance technique.

Motif : la qualification d'un client (système d'IA à haut risque, entité
financière au sens de DORA, fonction essentielle externalisée, traitement de
données sensibles à grande échelle) n'a été recherchée dans aucune source
(R6, point non vérifié NV-8) et relève de lui ; elle inclut l'applicabilité
territoriale des textes de l'Union à une entreprise suisse, que CT-7 n'a pas
recherchée (non vérifié) ; la communication FINMA
08/2024 ne contient aucune occurrence de « journal », « traçab », « trace »,
« enregistr » ni « piste » (R6-F10) : la matrice ne lui prête pas une
exigence de journalisation qu'elle n'écrit pas.

### 8.1 Vocabulaire et statut d'une ligne

Chaque ligne découpe le passage en **éléments**. Chaque élément porte une
relation (section 2) : `repond_a`, `contribue_a`, `ne_couvre_pas` ou
`releve_du_client`, ses pièces, et une condition quand la pièce n'existe
que sous un réglage (« si `storage.seal.worm` est configuré »).

**EX-8.2 (vocabulaire).** Les relations s'écrivent « répond à »,
« contribue à », « ne couvre pas », « relève du client » ; un élément
`repond_a` ou `contribue_a` nomme au moins une pièce. Hors de l'avertissement,
aucun texte de la matrice ne contient « est conforme », « sont conformes »,
« garantit la conformité », « certifi » ni « avis juridique » (MX-7).

**EX-8.3 (statut dérivé).** Le statut d'une ligne n'est pas choisi, il se
calcule :

| Statut | Condition sur les éléments de la ligne |
|---|---|
| `hors_perimetre` | aucun élément `repond_a` ni `contribue_a` |
| `couvert` | au moins un élément `repond_a`, aucun `contribue_a`, aucun `ne_couvre_pas` (des éléments `releve_du_client` peuvent rester) |
| `partiel` | tous les autres cas : au moins un `repond_a` ou `contribue_a`, et au moins un `contribue_a` ou `ne_couvre_pas` |

Un élément `repond_a` qui porte une `condition` compte comme `contribue_a` dans
cette dérivation : une ligne dont une réponse n'existe que sous un réglage est
`partiel` (MC-17 et MC-20, dont le stockage séparé n'existe que si
`storage.seal.worm` est configuré).

Le schéma porte cette règle (`$defs/ligne`, `allOf`) ; MX-3 la recalcule.

Les renvois d'un élément `releve_du_client` sont des repères, non des pièces.
Dans MC-17 et MC-20, CT-2 EX-18.4 et EX-18.9 restreignent l'accès aux fichiers
de l'enregistreur lui-même : NOORTRACE ne répond pas à l'élément et n'y
contribue pas, il reste au client.
`couvert` veut dire : ce que le passage demande à un système de
journalisation et de preuve a une pièce de NOORTRACE qui y répond, et le
reste relève du client. Ce n'est jamais « le client est conforme ».

### 8.2 Textes retenus et applicabilité

Dix textes, lus le 2026-10-26 sur leurs sources primaires (annexe B, R6) :

| Texte | Source | Titre | Nature | Version | Destinataires | Applicabilité au 2026-10-26 | Note |
|---|---|---|---|---|---|---|---|
| T-1 | S1 | Communication FINMA sur la surveillance 08/2024, « Gouvernance et gestion des risques en lien avec l'utilisation de l'intelligence artificielle » | `communication_surveillance` | 18 décembre 2024 | assujettis à la surveillance de la FINMA qui utilisent l'IA | `publie` | Une communication sur la surveillance décrit des constats et des points évalués ; elle ne crée pas d'obligation nouvelle. Le texte ne contient aucune occurrence de « journal », « traçab », « trace », « enregistr » ni « piste » (R6-F10). |
| T-2 | S2 | Circulaire FINMA 2018/3 « Outsourcing » | `circulaire` | du 21 septembre 2017, en vigueur le 1er avril 2018, dernière modification du 4 novembre 2020 | entreprises assujetties qui externalisent une fonction essentielle (Cm 3 et 4) | `vigueur_a_confirmer` | Vigueur au 2026-10-26 déduite de deux documents de la FINMA, non lue dans un acte (R6-F13, NV-1). Les chiffres marginaux ont été lus sur le rendu des pages. Les catégories d'assujettis visées par la circulaire, dont les entreprises d'assurance, n'ont pas été lues (non vérifié) : savoir si elle s'applique au client relève de lui (NV-8). |
| T-3 | S5 | Ordonnance sur la protection des données (OPDo, RS 235.11) | `ordonnance` | état le 1er décembre 2025 | responsables du traitement et sous-traitants privés (art. 4 al. 1) ; organes fédéraux (art. 4 al. 2) | `en_vigueur` : à partir du 2025-12-01 (art. 4, nouvelle teneur du 29 octobre 2025 (RO 2025 694)) | Le délai du 31 décembre 2026 de l'art. 46 al. 1 vise l'examen de l'art. 4 al. 2, organes fédéraux seulement (R6-F27). |
| T-4 | S6 | PFPDT, « Recommandations techniques du PFPDT relative à la journalisation prévue à l'art. 4 OPDo » | `recommandation` | version 1.1 du 15 octobre 2026 | responsables du traitement soumis à l'art. 4 OPDo | `publie` | Recommandations de l'autorité de surveillance ; elles précisent l'art. 4 OPDo sans s'y substituer. |
| T-5 | S8 | PFPDT, « Update - La loi actuelle sur la protection des données est directement applicable à l'IA » | `recommandation` | publiée le 8 mai 2025 | fabricants, fournisseurs et exploitants de systèmes d'IA | `publie` | Même teneur dans la page « IA et protection des données » du 24 septembre 2025 (S9). Aucun guide du PFPDT propre à la journalisation des systèmes d'IA trouvé (NV-7). |
| T-6 | S10 | Règlement (UE) 2022/2554 (DORA) | `reglement_ue` | JO L 333 du 27.12.2022 | entités financières au sens du règlement | `en_vigueur` : à partir du 2025-01-17 (tout le règlement (art. 64)) | La qualification du client comme entité financière relève du client (NV-8). Normes techniques sur la sous-traitance et la politique contractuelle non lues (NV-4). L'applicabilité territoriale de ce texte à une entreprise établie en Suisse n'a pas été recherchée (non vérifié) ; elle relève du client et de ses conseils (EX-8.1, NV-8). |
| T-7 | S11 | Règlement délégué (UE) 2024/1774 (cadre de gestion du risque lié aux TIC) | `reglement_delegue_ue` | JO L du 25.6.2024 | entités financières au sens du règlement (UE) 2022/2554 | `en_vigueur` | Entrée en vigueur le vingtième jour suivant la publication (art. 42) ; le texte ne fixe pas de date d'application distincte, aucune autre date lue (NV-5). L'applicabilité territoriale de ce texte à une entreprise établie en Suisse n'a pas été recherchée (non vérifié) ; elle relève du client et de ses conseils (EX-8.1, NV-8). |
| T-8 | S12 | Règlement (UE) 2024/1689 sur l'intelligence artificielle | `reglement_ue` | JO L du 12.7.2024 ; consolidation du 27.07.2026 (règlement (UE) 2026/1744), articles cités identiques | fournisseurs (art. 12, 14, 19) et déployeurs (art. 26) de systèmes d'IA à haut risque | `pas_encore_applicable` : à partir du 2027-12-02 (systèmes à haut risque de l'annexe III) ; à partir du 2028-08-02 (systèmes à haut risque de l'annexe I) | Art. 113 point c), tel que modifié par le règlement (UE) 2026/1744 : aucun des art. 12, 14, 19 et 26 ne s'applique au 2026-10-26 (R6-F55, R6-F56). Le classement d'un système à haut risque relève du client (NV-8). L'art. 12 ne mentionne ni intégrité ni protection contre la manipulation des journaux (constat de lecture, R6-F50) ; NV-10 reste un point non vérifié parce que les normes harmonisées qui préciseraient ce point n'ont pas été lues. L'applicabilité territoriale de ce texte à une entreprise établie en Suisse n'a pas été recherchée (non vérifié) ; elle relève du client et de ses conseils (EX-8.1, NV-8). |
| T-9 | S15 | Ordonnance concernant la tenue et la conservation des livres de comptes (Olico, en allemand GeBüV, RS 221.431) | `ordonnance` | état le 1er janvier 2013 | entreprises tenues de tenir et conserver des livres | `en_vigueur` | Vise les livres et pièces comptables : un journal d'agent n'en fait partie que si le client l'y range (qualification qui relève du client). |
| T-10 | S16 | Code des obligations (RS 220), art. 958f | `loi` | état le 1er octobre 2026 (même texte de l'art. 958f au 1er juillet 2027) | entreprises tenues de tenir une comptabilité | `en_vigueur` | Même remarque que pour l'Olico : la qualification du journal relève du client. |

**EX-8.4 (applicabilité).** Chaque ligne porte l'applicabilité de son texte. Une
ligne d'un texte `pas_encore_applicable` DOIT être affichée avec les dates
à partir desquelles il s'applique, jamais masquée ni présentée comme en
vigueur : les art. 12, 14, 19 et 26 du règlement (UE) 2024/1689 s'appliquent
à partir du 2 décembre 2027 pour les systèmes de l'annexe III et du 2 août 2028
pour ceux de l'annexe I (art. 113 point c), tel que modifié par le règlement
(UE) 2026/1744 ; R6-F55, R6-F56) ; leur texte est identique dans la
consolidation du 27.07.2026 (R6-F57). Une ligne d'un texte `vigueur_a_confirmer`
DOIT dire que la vigueur est à confirmer : c'est le cas de la circulaire FINMA
2018/3, dont la vigueur au 2026-10-26 est déduite de deux documents de la FINMA
et non lue dans un acte (R6-F13 ; lacune L-8). L'art. 4 OPDo s'applique dans sa
nouvelle teneur depuis le 1er décembre 2025 (R6-F24) ; le délai du 31 décembre
2026 de l'art. 46 al. 1 OPDo vise les seuls organes fédéraux (R6-F27) et la
matrice ne l'attribue à aucun responsable privé. DORA s'applique depuis le 17
janvier 2025 (R6-F39) ; le règlement délégué (UE) 2024/1774 entre en vigueur le
vingtième jour suivant sa publication et ne fixe pas de date d'application
distincte (R6-F48, point non vérifié NV-5). Les valeurs `en_vigueur` ou
`pas_encore_applicable` ne disent que l'état du texte, pas qu'il vise le client.
Pour les textes de l'Union (T-6, T-7, T-8), l'applicabilité territoriale à une
entreprise établie en Suisse n'a pas été recherchée (non vérifié) ; elle relève
du client et de ses conseils (EX-8.1, NV-8). Pour la circulaire FINMA 2018/3, la
vigueur au 2026-10-26 n'a pas été lue dans un acte (NV-1), et les catégories
d'assujettis visées, dont les entreprises d'assurance, n'ont pas été lues (non
vérifié) ; savoir si elle s'applique au client relève de lui (NV-8).

La date de référence de la matrice est le 2026-10-26, pour l'applicabilité et
pour `read_on`. R6-F66, lu le 2026-10-27 et cité par l'annexe C (CL-5), complète
la lecture de DORA art. 30 sans changer d'applicabilité. Les numéros de ligne de
0.2 désignent l'état des autres spécifications au 2026-10-27.

### 8.3 Forme lisible par machine : `matrice-conformite.json`

Le fichier `spec/vecteurs/ct-7/matrice-conformite.json` porte toute la
matrice ; son schéma est `spec/schemas/matrice-conformite-v0.schema.json`
(JSON Schema 2020-12, `additionalProperties: false` à tous les niveaux) :

| Membre | Contenu |
|---|---|
| `version`, `family`, `spec`, `spec_version`, `date` | `0`, `"matrice-conformite"`, `"CT-7"`, `"0.1"`, `"2026-10-26"` |
| `warning` | l'avertissement, constante du schéma |
| `texts[]` | `id` (T-), `source` (annexe B), `title`, `nature`, `version`, `url`, `read_on`, `addressee`, `applicability` (`status`, `from[]` : `{date, scope}`, `note`) |
| `rows[]` | `id` (MC-), `text`, `reference` (article, alinéa, lettre, chiffre marginal), `facts` (renvois aux faits de la note R6 ou R7, annexe B), `quote` (citation exacte, segments joints par « […] »), `source_url`, `read_on`, `requirement`, `applicability`, `elements[]` (`element`, `relation`, `pieces[]`, `condition`), `status` |
| `pieces[]` | `{kind, spec, ref}` : `exigence` (`EX-s.k`), `verification` (CT-1 ou CT-6, `X-n`), `controle` (CT-6, `1` à `8`), `partie` (CT-1, nom de partie du dossier), `section` (`§s`), `clause` (CT-7, `CL-n`) |
| `clauses[]` | `id`, `title`, `serves` (lignes qui citent la clause) |
| `gaps[]` | `id` (L-), `title`, `rows`, `response` (`risque_accepte`, `proposition`, `renvoi`, `releve_du_client`), `bound`, `owner`, `rule` |

**EX-8.5 (forme et identité).** `matrice-conformite.json` DOIT être conforme
à `matrice-conformite-v0` ; ses textes, ses lignes, ses clauses et ses
lacunes DOIVENT être, cellule par cellule, ceux des tables 8.2, 8.4, 8.9 et
de l'annexe C, selon la mise en forme fixée en annexe A (A.8, MX-8).

**EX-8.6 (citations).** Chaque `quote` DOIT reproduire mot pour mot le
passage de la source primaire nommée par `source_url`, lue à la date
`read_on` ; les coupes sont marquées « […] » et rien d'autre n'est retiré,
sinon un appel de note ou un numéro de page qu'un saut de page intercale. La
comparaison à la source est faite à la rédaction, par script, et refaite à
chaque relecture d'un texte (EX-8.20) ; les sources ne sont pas dans le dépôt
et l'intégration continue ne la refait pas.

**EX-8.7 (renvois).** Chaque pièce DOIT désigner une définition existante :
une exigence en gras dans la spécification nommée, une vérification de
CT-1 §11.4 ou de CT-6, un contrôle de 1 à 8, une partie du dossier, une
section, une clause de l'annexe C (MX-4 ; RV-3 du vérificateur de renvois).

Exemple : le fichier réduit à la ligne MC-17 et à son texte (il n'est pas le
fichier publié, qui en a 58) :

<!-- schema: matrice-conformite -->
```json
{
  "version": 0,
  "family": "matrice-conformite",
  "spec": "CT-7",
  "spec_version": "0.1",
  "date": "2026-10-26",
  "warning": "Cette matrice établit une correspondance technique entre des passages de textes et des pièces de preuve produites par NOORTRACE. Elle n'est pas un avis juridique et ne dit jamais qu'un client est conforme : la qualification du client, l'applicabilité de chaque texte et la conformité relèvent du client et de ses conseils.",
  "texts": [
    {
      "id": "T-3",
      "source": "S5",
      "title": "Ordonnance sur la protection des données (OPDo, RS 235.11)",
      "nature": "ordonnance",
      "version": "état le 1er décembre 2025",
      "url": "https://fedlex.data.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2022/568/20251201/fr/html/fedlex-data-admin-ch-eli-cc-2022-568-20251201-fr-html-2.html",
      "read_on": "2026-10-26",
      "addressee": "responsables du traitement et sous-traitants privés (art. 4 al. 1) ; organes fédéraux (art. 4 al. 2)",
      "applicability": {
        "status": "en_vigueur",
        "from": [
          {
            "date": "2025-12-01",
            "scope": "art. 4, nouvelle teneur du 29 octobre 2025 (RO 2025 694)"
          }
        ],
        "note": "Le délai du 31 décembre 2026 de l'art. 46 al. 1 vise l'examen de l'art. 4 al. 2, organes fédéraux seulement (R6-F27)."
      }
    }
  ],
  "rows": [
    {
      "id": "MC-17",
      "text": "T-3",
      "reference": "art. 4 al. 5",
      "facts": [
        "R6-F26"
      ],
      "quote": "5 Les procès-verbaux de journalisation sont conservés durant au moins un an, séparément du système dans lequel les données personnelles sont traitées. Ils sont accessibles uniquement aux organes et aux personnes chargés de vérifier l’application des dispositions relatives à la protection des données personnelles ou de préserver ou restaurer la confidentialité, l’intégrité, la disponibilité et la traçabilité des données, et ne peuvent être utilisés qu’à cette fin.",
      "source_url": "https://fedlex.data.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2022/568/20251201/fr/html/fedlex-data-admin-ch-eli-cc-2022-568-20251201-fr-html-2.html",
      "read_on": "2026-10-26",
      "requirement": "Conservation au moins un an, séparément du système qui traite les données ; accès réservé aux personnes chargées de la protection ou de la sécurité des données ; usage limité à cette fin.",
      "applicability": "en_vigueur",
      "elements": [
        {
          "element": "Conservation : au moins dix ans pour les événements, manifestes et signatures",
          "relation": "repond_a",
          "pieces": [
            {
              "kind": "exigence",
              "spec": "CT-2",
              "ref": "EX-12.19"
            },
            {
              "kind": "exigence",
              "spec": "CT-2",
              "ref": "EX-15.4"
            },
            {
              "kind": "exigence",
              "spec": "CT-7",
              "ref": "EX-8.12"
            }
          ],
          "condition": null
        },
        {
          "element": "Stockage séparé : copie WORM de chaque segment, manifeste et signature, hors du système de l'agent et des systèmes du client qu'il touche",
          "relation": "repond_a",
          "pieces": [
            {
              "kind": "exigence",
              "spec": "CT-2",
              "ref": "EX-12.16"
            },
            {
              "kind": "exigence",
              "spec": "CT-2",
              "ref": "EX-12.30"
            }
          ],
          "condition": "si `storage.seal.worm` est configuré"
        },
        {
          "element": "Restriction de l'accès aux journaux et limitation de leur usage ; l'enregistreur ne s'en charge que pour ses propres fichiers (utilisateur dédié, droits restreints)",
          "relation": "releve_du_client",
          "pieces": [
            {
              "kind": "exigence",
              "spec": "CT-2",
              "ref": "EX-18.4"
            },
            {
              "kind": "exigence",
              "spec": "CT-2",
              "ref": "EX-18.9"
            }
          ],
          "condition": null
        }
      ],
      "status": "partiel"
    }
  ],
  "clauses": [],
  "gaps": []
}
```

Une ligne `partiel` d'un texte pas encore applicable :

<!-- schema: matrice-conformite/ligne -->
```json
{
  "id": "MC-50",
  "text": "T-8",
  "reference": "art. 26 § 6",
  "facts": [
    "R6-F54"
  ],
  "quote": "6. Les déployeurs de systèmes d’IA à haut risque assurent la tenue des journaux générés automatiquement par ce système d’IA à haut risque dans la mesure où ces journaux se trouvent sous leur contrôle, pendant une période adaptée à la destination du système d’IA à haut risque, d’au moins six mois, sauf disposition contraire dans le droit de l’Union ou le droit national applicable, en particulier dans le droit de l’Union sur la protection des données à caractère personnel.",
  "source_url": "http://publications.europa.eu/resource/celex/32024R1689",
  "read_on": "2026-10-26",
  "requirement": "Le déployeur tient les journaux sous son contrôle pendant une période adaptée, d'au moins six mois.",
  "applicability": "pas_encore_applicable",
  "elements": [
    {
      "element": "Durée : au moins dix ans pour les événements",
      "relation": "repond_a",
      "pieces": [
        {
          "kind": "exigence",
          "spec": "CT-2",
          "ref": "EX-12.19"
        },
        {
          "kind": "exigence",
          "spec": "CT-7",
          "ref": "EX-8.12"
        }
      ],
      "condition": null
    },
    {
      "element": "Journaux sous le contrôle du déployeur : journal, pièces et clés sur son infrastructure ; clause de conservation",
      "relation": "contribue_a",
      "pieces": [
        {
          "kind": "exigence",
          "spec": "CT-7",
          "ref": "EX-8.10"
        },
        {
          "kind": "clause",
          "spec": "CT-7",
          "ref": "CL-3"
        }
      ],
      "condition": null
    },
    {
      "element": "Plancher de dix ans non réductible face à la réserve du droit de la protection des données (lacune L-5)",
      "relation": "ne_couvre_pas",
      "pieces": [
        {
          "kind": "exigence",
          "spec": "CT-7",
          "ref": "EX-8.14"
        }
      ],
      "condition": null
    },
    {
      "element": "Période adaptée à la destination, lien avec la documentation du droit des services financiers",
      "relation": "releve_du_client",
      "pieces": [],
      "condition": null
    }
  ],
  "status": "partiel"
}
```

### 8.4 Table de la matrice

Lecture : la colonne « Texte » porte l'identifiant du texte (8.2) et son
applicabilité ; « Pièce NOORTRACE » liste les éléments `repond_a` et
`contribue_a`, chacun suivi de ses pièces ; « Ne couvre pas » et « Relève du
client » listent les autres éléments ; « Statut » se dérive (EX-8.3). Les
pièces s'écrivent « CT-n EX-s.k », « CT-6 contrôle n », « CT-1 partie
`nom` », « CT-n §s » ou « CT-7 CL-n ». Un statut se lit avec les conditions
de ses éléments (EX-8.3). « Partie `attestation_perimetre` » est le nom de la
partie dans `dossier.json` (CT-1 §11.1), dont le fichier est
`attestation-perimetre.json`.

| Ligne | Texte | Référence | Citation exacte (fait) | Ce qui est exigé | Pièce NOORTRACE (répond à, contribue à) | Ne couvre pas | Relève du client | Statut |
|---|---|---|---|---|---|---|---|---|
| MC-1 | T-1, `publie` | ch. 2.1 « Gouvernance » et 2.2 « Inventaire et classification des risques » | « La FINMA a évalué si les assujettis ayant recours à de nombreuses applications ou à des applications importantes disposaient d’une gouvernance en matière d’IA comprenant notamment un inventaire centralisé, y compris une classification des risques et les mesures qui en découlent » (R6-F4) | Une gouvernance de l'IA comprenant un inventaire centralisé des applications, leur classification des risques et les mesures qui en découlent. | contribue à : Inventaire des agents capturés, par journal : identifiant, hôte, cadre, canal de capture, et ce qui n'est pas capturé, déclaré par l'organisation et signé — CT-1 partie `attestation_perimetre` ; contribue à : Modèle et version du prompt système observés, événement par événement — CT-1 §5.3 | — | Tenue de l'inventaire centralisé, classification des risques, mesures qui en découlent | partiel |
| MC-2 | T-1, `publie` | ch. 2.1 « Gouvernance », externalisation | « En cas d’externalisation, elle a évalué si les assujettis avaient mis en place des tests, des contrôles et des clauses contractuelles supplémentaires régissant les compétences et les questions de responsabilité et s’ils s’étaient assurés que les tiers auxquels ils faisaient appel disposaient des compétences et de l’expérience nécessaires. » (R6-F4) | En cas d'externalisation : tests, contrôles et clauses contractuelles supplémentaires sur les compétences et la responsabilité ; compétence et expérience du tiers. | contribue à : Modèles de clauses de droit d'audit, d'accès, de réversibilité, de sous-traitance et de notification d'incident — CT-7 CL-1, CT-7 CL-3, CT-7 CL-4, CT-7 CL-5 ; contribue à : Contrôles que le client exécute lui-même sur les preuves, hors ligne, sans le service de l'exploitant — CT-6 EX-3.3, CT-6 §5.1 | — | Choix et rédaction des clauses, évaluation des compétences et de l'expérience du tiers | partiel |
| MC-3 | T-1, `publie` | ch. 2.4 « Tests et surveillance constante » | « La surveillance comprend aussi l’analyse des cas où le résultat a été ignoré ou modifié par les utilisateurs, puisque de telles corrections manuelles peuvent indiquer des points faibles. » (R6-F6) | La surveillance des applications d'IA comprend l'analyse des cas où le résultat a été ignoré ou modifié par les utilisateurs. | contribue à : Trace signée des actions de l'agent refusées par des approbateurs ou expirées sans décision — CT-1 §5.3, CT-3 EX-9.13, CT-1 A-3, CT-6 contrôle 7 | Résultats du modèle ignorés ou modifiés par un utilisateur hors d'une approbation : la version 0 ne capture pas la correction humaine d'une sortie — CT-7 EX-8.19 | Analyse des cas, seuils et méthodes de validation | partiel |
| MC-4 | T-1, `publie` | ch. 2.5 « Documentation » | « Pour les applications importantes, la FINMA a évalué si les assujettis abordaient dans la documentation le but de l’application, la sélection et la préparation des données, le choix du modèle, les mesures de performance, les hypothèses, les limitations, les tests et les contrôles ainsi que les solutions de repli. » (R6-F7) | Documentation des applications importantes : but, données, choix du modèle, mesures de performance, hypothèses, limitations, tests, contrôles, solutions de repli. | contribue à : Identification du modèle, de la version du prompt système et de la version de politique de chaque action — CT-1 §5.3, CT-2 EX-9.1 | Documentation du but, des données, du choix du modèle, des performances et des limitations | Rédaction et tenue de la documentation | partiel |
| MC-5 | T-1, `publie` | ch. 2.6 « Explicabilité » | « La FINMA a constaté que les résultats ne sont souvent pas compris, expliqués ou reproduits et qu’ils ne peuvent donc pas être évalués de manière critique. » (R6-F8) | Comprendre, expliquer et reproduire les résultats pour pouvoir les évaluer de manière critique. | contribue à : Entrées et sorties de chaque action et de chaque échange avec le modèle, conservées comme pièces référencées par leur SHA-256 — CT-1 §5.4, CT-1 E-6, CT-2 §8.2 | Explication du comportement du modèle | Évaluation critique des résultats | partiel |
| MC-6 | T-1, `publie` | ch. 2.7 « Vérification indépendante » | « Pour les applications importantes, la FINMA a évalué si la vérification indépendante inclut l’émission d’un avis objectif, averti et impartial sur l’adéquation et la fiabilité d’une procédure pour un cas d’application donné » (R6-F9) | Une vérification indépendante émettant un avis objectif, averti et impartial sur l'adéquation et la fiabilité d'une procédure. | — | Avis sur l'adéquation et la fiabilité d'une application d'IA : le vérificateur de CT-6 vérifie des preuves de journal, pas une application | Organisation de la vérification indépendante et prise en compte de ses conclusions | hors_perimetre |
| MC-7 | T-2, `vigueur_a_confirmer` | Cm 14 | « Un inventaire des fonctions externalisées doit être établi et tenu à jour. Il comprendra une description de la fonction externalisée, le fournisseur (y compris les sous-traitants), le bénéficiaire et l'organe responsable au sein de l’entreprise (cf. Cm 20). » (R6-F15) | Inventaire tenu à jour des fonctions externalisées : fonction, fournisseur et sous-traitants, bénéficiaire, organe responsable. | contribue à : Inventaire publié des composants tiers employés par NOORTRACE, avec leur rôle, ce qu'ils reçoivent et l'effet de leur perte sur les preuves — CT-7 EX-8.9, CT-7 CL-4 | — | Tenue de l'inventaire, désignation du bénéficiaire et de l'organe responsable | partiel |
| MC-8 | T-2, `vigueur_a_confirmer` | Cm 18 et 18.1 | « Lors de la décision statuant sur l’outsourcing et du choix du prestataire, les possibilités et les conséquences d’un changement doivent être prises en considération. Le prestataire doit offrir la garantie d’un exercice durable de la fonction. […] La réintégration ordonnée de la fonction externalisée ou le transfert à un autre prestataire doivent être garantis. » (R6-F16) | Prendre en compte les possibilités et conséquences d'un changement ; garantir la réintégration ordonnée ou le transfert à un autre prestataire. | contribue à : Journal, pièces et clés tenus sur l'infrastructure du client ; formats publiés ; vérification sans service ni compte de l'exploitant — CT-1 §11.2, CT-6 EX-3.3, CT-7 EX-8.10 ; contribue à : Clause de conservation, de restitution et de réversibilité — CT-7 CL-3 | — | Décision, plan et exécution de la réintégration ou du transfert | partiel |
| MC-9 | T-2, `vigueur_a_confirmer` | Cm 20 et 21 | « Le système de contrôle interne de l’entreprise doit s’étendre à la fonction externalisée. […] L’entreprise s’assure que le prestataire lui reconnaisse le droit de lui donner des instructions et de procéder aux contrôles nécessaires à cet effet. » (R6-F17) | Étendre le contrôle interne à la fonction externalisée ; droit de donner des instructions et de procéder aux contrôles nécessaires. | contribue à : Clause de droit d'audit, de regard et d'instruction — CT-7 CL-1 ; contribue à : Supervision et contrôles périodiques que l'administrateur du client peut brancher sur son propre système — CT-2 EX-17.5, CT-2 §17.4 | — | Désignation de l'organe responsable, surveillance suivie du prestataire | partiel |
| MC-10 | T-2, `vigueur_a_confirmer` | Cm 24 et 25 | « En cas d’externalisations déterminantes pour la sécurité (notamment dans le domaine informatique), l’entreprise et le prestataire fixent par contrat les exigences en matière de sécurité. L’entreprise doit veiller à leur respect. […] L’entreprise et le prestataire élaborent un dispositif de sécurité qui permet en cas d’urgence la continuité de la fonction externalisée. » (R6-F19) | Exigences de sécurité fixées par contrat et respectées ; dispositif de continuité en cas d'urgence. | contribue à : Exigences de sécurité publiées de l'enregistreur, du vérificateur et de l'ancrage — CT-2 §18, CT-6 §3.4, CT-5 §3.4 ; contribue à : Continuité : écrivain unique avec bail et bascule, ancrage jamais bloquant, copies WORM pour reconstruire — CT-2 §13, CT-5 EX-4.12, CT-2 EX-12.17 ; contribue à : Clauses de sécurité, de lieux de traitement et de notification d'incident — CT-7 CL-5, CT-7 CL-6 | — | Fixation contractuelle des exigences et contrôle de leur respect, plan d'urgence | partiel |
| MC-11 | T-2, `vigueur_a_confirmer` | Cm 26 | « L’entreprise, sa société d’audit et la FINMA doivent être en mesure de vérifier le respect des dispositions prudentielles auprès du prestataire. Un droit de regard et d’examen intégral, permanent et sans entraves sur la fonction externalisée doit leur être reconnu par contrat. » (R6-F20) | Droit de regard et d'examen intégral, permanent et sans entraves de l'entreprise, de sa société d'audit et de la FINMA, reconnu par contrat. | contribue à : Clause de droit de regard, d'examen et d'audit au profit du client, de sa société d'audit et de l'autorité — CT-7 CL-1 ; contribue à : Dossier vérifiable hors ligne par un tiers, sans accès au système de l'exploitant ni au réseau — CT-6 EX-3.3, CT-6 EX-12.1, CT-6 V-8 | — | Reconnaissance contractuelle du droit et son exercice | partiel |
| MC-12 | T-2, `vigueur_a_confirmer` | Cm 29 | « Si le prestataire n’est pas assujetti à la surveillance de la FINMA, il doit s’engager par contrat envers l’entreprise à mettre à la disposition de la FINMA tous les renseignements et documents relatifs au domaine d’activités transféré dont la FINMA a besoin pour remplir ses tâches de surveillance. » (R6-F20) | Engagement contractuel du prestataire non assujetti de mettre à disposition de la FINMA tous les renseignements et documents nécessaires. | contribue à : Clause d'information de l'autorité de surveillance — CT-7 CL-1 | — | Conclusion de l'engagement et transmission à la FINMA | partiel |
| MC-13 | T-2, `vigueur_a_confirmer` | Cm 30 et 31 | « Un transfert à l’étranger est autorisé à condition que l’entreprise puisse expressément garantir qu’elle-même, sa société d’audit ainsi que la FINMA peuvent exercer et faire appliquer leurs droits de regard et d’examen. La capacité d’assainissement et de liquidation de l’entreprise en Suisse doit être garantie. Il faut que l’accès aux informations nécessaires à cet effet soit possible à tout moment en Suisse. » (R6-F21) | Transfert à l'étranger seulement si les droits de regard et d'examen restent exerçables et si l'accès aux informations nécessaires est possible à tout moment en Suisse. | contribue à : Journal, pièces, clés de l'enregistreur et dossiers tenus sur l'infrastructure que le client choisit ; seuls des condensés et des clés publiques partent vers les ancres — CT-7 EX-8.9, CT-2 EX-18.2 ; contribue à : Clause sur les lieux de traitement et de stockage — CT-7 CL-6 | — | Choix des lieux d'hébergement et garantie expresse des droits | partiel |
| MC-14 | T-2, `vigueur_a_confirmer` | Cm 33 et 34 | « L’entreprise s’assure d'être informée suffisamment tôt du recours, ou du changement de recours, à des sous-traitants exerçant des fonctions essentielles et de pouvoir mettre un terme à l’outsourcing de manière ordonnée au sens du Cm 18.1. En cas de recours à des sous-traitants, les obligations et les garanties du prestataire nécessaires au respect de la présente circulaire doivent leur être transférées. » (R6-F22) | Information précoce sur le recours à des sous-traitants exerçant des fonctions essentielles ; transfert des obligations et garanties aux sous-traitants. | contribue à : Inventaire publié des composants tiers de NOORTRACE — CT-7 EX-8.9 ; contribue à : Clause de sous-traitance — CT-7 CL-4 | — | Mesures contractuelles et procédure interne d'autorisation (Cm 34, 35) | partiel |
| MC-15 | T-3, `en_vigueur` | art. 4 al. 1 | « Lors de traitements automatisés de données sensibles à grande échelle ou de profilages à risque élevé et lorsque les mesures préventives ne suffisent pas à garantir la protection des données, le responsable du traitement privé et son sous-traitant privé journalisent au moins l’enregistrement, la modification, la communication, l’effacement et la destruction des données ainsi que l’accès aux données. La journalisation est notamment nécessaire lorsque, sans cette mesure, il n’est pas possible de vérifier a posteriori que les données ont été traitées conformément aux finalités pour lesquelles elles ont été collectées ou communiquées. » (R6-F24) | Dans les cas visés, journaliser au moins l'enregistrement, la modification, la communication, l'effacement, la destruction et l'accès aux données. | contribue à : Chaque action de l'agent par un canal capturé est un événement signé dont les effets portent une action parmi `lecture`, `ecriture`, `suppression`, `envoi`, `execution`, selon la table de passage — CT-1 §5.3, CT-2 EX-7.6, CT-7 EX-8.8 | Distinction entre enregistrement et modification, et entre effacement et destruction, dans l'énumération des actions de CT-1 v0 — CT-7 EX-8.8 ; Traitements faits par d'autres systèmes que l'agent, ou par un canal que l'enregistreur ne voit pas — CT-2 EX-4.1, CT-1 partie `attestation_perimetre` | Qualification du traitement (données sensibles à grande échelle, profilage à risque élevé, insuffisance des mesures préventives) | partiel |
| MC-16 | T-3, `en_vigueur` | art. 4 al. 4 | « 4 La journalisation doit fournir des informations sur l’identité de la personne qui a effectué le traitement, la nature, la date et l’heure du traitement et, cas échéant, l’identité du destinataire des données. » (R6-F26) | Identité de la personne, nature, date et heure du traitement, et le cas échéant identité du destinataire. | contribue à : Identité de la personne ou du service qui a lancé l'agent, pour le compte de qui, et identité technique de l'enregistreur — CT-1 §5.3, CT-1 §5.2 ; répond à : Date et heure : `ts` de l'horloge synchronisée de l'enregistreur, borné par les ancres — CT-1 §5.2, CT-2 EX-7.10, CT-6 contrôle 4, CT-6 contrôle 5 ; contribue à : Nature : outil appelé et action déclarée de chaque effet — CT-1 §5.3, CT-2 EX-7.6 | Destinataire des données : aucun champ propre ; le système et l'objet d'un effet `envoi` y contribuent sans le nommer — CT-7 EX-8.8 | Rattachement de l'identité technique de l'agent à une personne responsable | partiel |
| MC-17 | T-3, `en_vigueur` | art. 4 al. 5 | « 5 Les procès-verbaux de journalisation sont conservés durant au moins un an, séparément du système dans lequel les données personnelles sont traitées. Ils sont accessibles uniquement aux organes et aux personnes chargés de vérifier l’application des dispositions relatives à la protection des données personnelles ou de préserver ou restaurer la confidentialité, l’intégrité, la disponibilité et la traçabilité des données, et ne peuvent être utilisés qu’à cette fin. » (R6-F26) | Conservation au moins un an, séparément du système qui traite les données ; accès réservé aux personnes chargées de la protection ou de la sécurité des données ; usage limité à cette fin. | répond à : Conservation : au moins dix ans pour les événements, manifestes et signatures — CT-2 EX-12.19, CT-2 EX-15.4, CT-7 EX-8.12 ; répond à : Stockage séparé : copie WORM de chaque segment, manifeste et signature, hors du système de l'agent et des systèmes du client qu'il touche (si `storage.seal.worm` est configuré) — CT-2 EX-12.16, CT-2 EX-12.30 | — | Restriction de l'accès aux journaux et limitation de leur usage ; l'enregistreur ne s'en charge que pour ses propres fichiers (utilisateur dédié, droits restreints) — CT-2 EX-18.4, CT-2 EX-18.9 | partiel |
| MC-18 | T-3, `en_vigueur` | art. 3 al. 3 let. a à c | « 3 Pour assurer la traçabilité, le responsable du traitement et le sous-traitant prennent des mesures appropriées afin que: a. il soit possible de vérifier quelles données personnelles sont saisies ou modifiées dans le système de traitement automatisé de données, par quelle personne et à quel moment (contrôle de la saisie); b. il soit possible de vérifier à qui sont communiquées les données personnelles à l’aide d’installations de transmission (contrôle de la communication); c. les violations de la sécurité des données puissent être rapidement détectées (détection) et que des mesures puissent être prises pour atténuer ou éliminer les conséquences (réparation). » (R6-F28) | Contrôle de la saisie, contrôle de la communication, détection rapide des violations de la sécurité des données et réparation. | contribue à : Saisie et modification par l'agent : événement signé avec l'identité de lancement, l'outil, les effets et l'instant — CT-1 §5.3, CT-6 contrôle 6 ; contribue à : Communication par l'agent : effets `envoi` et échanges avec le modèle journalisés — CT-1 §5.1, CT-2 EX-7.6 ; contribue à : Détection : toute modification du journal est apparente au vérificateur, et la supervision alerte sur un contrôle d'intégrité en échec — CT-1 E-7, CT-1 C-2, CT-2 EX-17.5 | — | Mesures de réparation et traitement des violations | partiel |
| MC-19 | T-4, `publie` | ch. 2.1.1 « Saisie » | « Cela permet de retracer ultérieurement quel système a accédé au système, sous quelle identité technique cet accès a eu lieu et qui est responsable de cette identité technique. » (R6-F32) | Retracer quel système a accédé, sous quelle identité technique, et qui en est responsable. | répond à : Système et identité technique : connexion d'hôte, identifiant de clé de l'enregistreur, exécution de l'agent — CT-1 §5.2, CT-1 §5.3 ; contribue à : Personne ou service qui a lancé l'agent, telle que le système d'identité du client la nomme — CT-1 §5.3 | — | Attribution de chaque identité technique à une personne ou à une entité responsable | partiel |
| MC-20 | T-4, `publie` | ch. 2.1.2 « Enregistrement » | « Les données de journalisation doivent être stockées de manière sécurisée et protégée, séparément des systèmes de traitement des données afin de garantir leur disponibilité même si le système principal est en dérangement (p. ex. à la suite d’une attaque par un rançongiciel). » (R6-F33) | Stockage sécurisé, protégé, séparé des systèmes de traitement, disponible même si le système principal est en dérangement. | répond à : Copie WORM en mode sans contournement, à partir de laquelle le journal se reconstruit (si `storage.seal.worm` est configuré) — CT-2 EX-12.16, CT-2 EX-12.17, CT-2 EX-12.30 | — | Sécurité de l'hébergement, sauvegardes, droits d'accès au support — CT-2 EX-18.9 | partiel |
| MC-21 | T-4, `publie` | ch. 3.1 let. c | « c) Vérification régulière des données de journalisation : il convient de vérifier régulièrement que les données de journalisation sont complètes, qu’elles n’ont pas été manipulées et que les directives de sécurité sont respectées. » (R6-F34) | Vérifier régulièrement que les journaux sont complets, non manipulés, et que les directives de sécurité sont respectées. | contribue à : Complétude et absence de manipulation : relecture horaire et quotidienne, comparaison aux copies WORM, continuité des manifestes ; vérification d'un dossier par un tiers — CT-2 EX-17.5, CT-6 §5.1 | Contrôle périodique de l'intégrité et de la lisibilité des segments anciens et de leurs copies WORM : non spécifié en version 0 (lacune L-10) | Respect des directives de sécurité du client | partiel |
| MC-22 | T-4, `publie` | ch. 3.1 let. f et g | « f) Horodatage : les données de journalisation sont horodatées afin de consigner le moment précis de la survenue d’un événement dans le système. […] g) Synchronisation : la précision de l’horodatage dépend directement de la synchronisation précise de tous les systèmes du réseau. La synchronisation des horloges de tous les systèmes, effectuée au moyen d’un serveur NTP commun, permet de garantir la précision et la cohérence des données du journal. » (R6-F34) | Horodater chaque entrée ; synchroniser les horloges de tous les systèmes sur un serveur NTP commun. | répond à : Horodatage de chaque événement à la milliseconde, et preuve d'existence au plus tard par jeton RFC 3161 et OpenTimestamps — CT-1 §5.2, CT-6 contrôle 4, CT-6 contrôle 5 ; répond à : Horloge synchronisée de l'enregistreur, écarts consignés et alertés — CT-2 EX-7.10, CT-2 §17.4 | — | Synchronisation des autres systèmes du client | couvert |
| MC-23 | T-4, `publie` | ch. 3.2 let. b | « b) Durée de conservation : il importe de définir une durée de conservation claire pour les données de journalisation afin d’éviter de les conserver inutilement. Il convient évidemment de respecter les exigences légales en matière de durée de conservation. La durée de conservation des données de journalisation en rapport avec le traitement de données personnelles est fixée à au moins un an. » (R6-F35) | Définir une durée de conservation claire, éviter la conservation inutile, respecter les durées légales, au moins un an. | répond à : Au moins un an : les événements sont conservés au moins dix ans — CT-2 EX-12.19, CT-7 EX-8.12 ; contribue à : Éviter la conservation inutile : pièces purgeables, rédaction avant hachage — CT-2 EX-12.20, CT-2 EX-10.2 | Les données personnelles en ligne des événements ne peuvent pas être effacées avant le plancher de dix ans — CT-7 EX-8.14 | Fixation de la durée claire et de sa justification | partiel |
| MC-24 | T-4, `publie` | ch. 4, FAQ 9 | « 9) Est-il autorisé d’utiliser des services externes à la demande pour la gestion des procès-verbaux de journalisation ? Dans la mesure du possible, il convient de consulter le service juridique et le conseiller à la protection des données de l’entreprise, car les risques dans le domaine des données personnelles ont plutôt tendance à augmenter qu’à diminuer. Nous déconseillons de recourir à de tels services. Une telle solution est exceptionnellement possible si on recourt déjà à un logiciel en tant que service (software-as-a-service) pour le traitement des données, à condition que les personnes susmentionnées aient déjà été consultées. » (R6-F36) | Déconseille les services externes pour la gestion des journaux, sauf exception : logiciel en tant que service déjà employé pour le traitement, après consultation du service juridique et du conseiller à la protection des données. | répond à : L'enregistreur et le journal sont chez le client ; les ancres ne reçoivent que des condensés, des clés publiques et des adresses — CT-7 EX-8.9, CT-2 EX-18.2 | — | Choix d'un hébergement externe de l'enregistreur, s'il en fait un ; recours éventuel à l'exception et consultation préalable du service juridique et du conseiller à la protection des données | couvert |
| MC-25 | T-5, `publie` | page du 8 mai 2025, paragraphe sur la transparence | « Compte-tenu des exigences de la LPD, les fabricants, fournisseurs et exploitants de systèmes d’IA doivent rendre transparent la finalité, le fonctionnement et la source de données traités par l’intelligence artificielle. » (R6-F38) | Rendre transparents la finalité, le fonctionnement et la source des données traitées par l'IA. | — | Transparence envers les personnes concernées | Information des personnes, analyse d'impact en cas de risque élevé | hors_perimetre |
| MC-26 | T-6, `en_vigueur` | art. 28 § 1 a) | « les entités financières qui ont conclu des accords contractuels pour l’utilisation de services TIC dans le cadre de leurs activités restent à tout moment pleinement responsables du respect et de l’exécution de toutes les obligations découlant du présent règlement et du droit applicable aux services financiers; » (R6-F40) | L'entité financière reste pleinement responsable de ses obligations malgré le recours à des services TIC. | — | — | Responsabilité de l'entité financière | hors_perimetre |
| MC-27 | T-6, `en_vigueur` | art. 28 § 3 | « Aux fins de leur cadre de gestion du risque lié aux TIC, les entités financières tiennent et mettent à jour, au niveau de l’entité et aux niveaux sous-consolidé et consolidé, un registre d’informations en rapport avec tous les accords contractuels portant sur l’utilisation de services TIC fournis par des prestataires tiers de services TIC. » (R6-F41) | Tenir un registre d'informations sur tous les accords d'utilisation de services TIC. | contribue à : Inventaire publié des composants tiers de NOORTRACE, utilisable pour renseigner le registre — CT-7 EX-8.9, CT-7 CL-4 | — | Tenue du registre d'informations | partiel |
| MC-28 | T-6, `en_vigueur` | art. 28 § 6 | « Lorsqu’elles exercent leurs droits d’accès, d’inspection et d’audit à l’égard d’un prestataire tiers de services TIC, les entités financières déterminent au préalable, sur la base d’une approche fondée sur les risques, la fréquence des audits et des inspections, ainsi que les domaines qui doivent faire l’objet d’un audit, dans le respect des normes d’audit communément admises et conformément à toute instruction de surveillance relative à l’utilisation et à l’incorporation de ces normes d’audit. » (R6-F42) | Fixer à l'avance, selon les risques, la fréquence et les domaines des audits et inspections. | contribue à : Clause de droit d'audit qui laisse au client fréquence et domaines — CT-7 CL-1 ; contribue à : Contrôles du dossier répétables à toute fréquence, hors ligne — CT-6 EX-3.3, CT-6 V-8 | — | Détermination de la fréquence et des domaines | partiel |
| MC-29 | T-6, `en_vigueur` | art. 28 § 8 | « Les entités financières définissent des solutions alternatives et élaborent des plans de transition leur permettant de supprimer les services TIC visés par le contrat et les données pertinentes détenues par le prestataire tiers de services TIC, et de les transférer en toute sécurité et intégralement à des prestataires alternatifs ou de les réincorporer en interne. » (R6-F44) | Solutions alternatives et plans de transition pour retirer les services et données et les transférer intégralement. | contribue à : Journal et preuves chez le client, formats publiés, vérification sans l'exploitant — CT-1 §11.2, CT-6 EX-3.3, CT-7 EX-8.10 ; contribue à : Clause de réversibilité — CT-7 CL-3 | — | Plan de transition | partiel |
| MC-30 | T-6, `en_vigueur` | art. 29 § 2 | « Lorsque les accords contractuels relatifs à l’utilisation de services TIC qui soutiennent des fonctions critiques ou importantes prévoient une sous-traitance, les entités financières évaluent si et comment des chaînes de sous-traitance potentiellement longues ou complexes sont susceptibles de compromettre leur capacité à assurer un suivi rigoureux des fonctions visées par le contrat et la capacité de l’autorité compétente à surveiller efficacement l’entité financière à cet égard. » (R6-F45) | Évaluer si des chaînes de sous-traitance longues ou complexes compromettent le suivi et la surveillance. | contribue à : Inventaire des composants tiers, avec l'effet de la perte de chacun sur les preuves — CT-7 EX-8.9 ; contribue à : Clause de sous-traitance — CT-7 CL-4 | — | Évaluation de la chaîne | partiel |
| MC-31 | T-6, `en_vigueur` | art. 30 § 2 c) | « des dispositions sur la disponibilité, l’authenticité, l’intégrité et la confidentialité en ce qui concerne la protection des données, y compris les données à caractère personnel; » (R6-F46) | Dispositions contractuelles sur la disponibilité, l'authenticité, l'intégrité et la confidentialité des données. | contribue à : Substance technique des dispositions : authenticité et intégrité vérifiables (hachage, chaînage, signature de l'enregistreur et des approbateurs) ; leur rédaction contractuelle relève du client — CT-6 contrôle 1, CT-6 contrôle 2, CT-6 contrôle 6, CT-6 contrôle 7 ; contribue à : Disponibilité : copies WORM ; confidentialité : rédaction avant hachage — CT-2 EX-12.16, CT-2 EX-10.2 ; contribue à : Clause de sécurité — CT-7 CL-6 | — | Rédaction des dispositions contractuelles | partiel |
| MC-32 | T-6, `en_vigueur` | art. 30 § 2 d) | « des dispositions sur la garantie de l’accès, de la récupération et de la restitution, dans un format facilement accessible, des données à caractère personnel et autres traitées par l’entité financière en cas d’insolvabilité, de résolution, de cessation des activités du prestataire tiers de services TIC ou de résiliation des accords contractuels; » (R6-F46) | Accès, récupération et restitution des données dans un format facilement accessible en cas de fin du prestataire ou de résiliation. | contribue à : Format facilement accessible : JSON UTF-8 et formats publiés de CT-1 ; journal tenu par le client — CT-1 §3, CT-1 §11.2 ; contribue à : Clause de restitution — CT-7 CL-3 | — | Négociation et exercice de la restitution | partiel |
| MC-33 | T-6, `en_vigueur` | art. 30 § 3 e) | « e) le droit d’assurer un suivi permanent des performances du prestataire tiers de services TIC, qui comprend les éléments suivants: i) les droits illimités d’accès, d’inspection et d’audit par l’entité financière ou par une tierce partie désignée, et par l’autorité compétente, et le droit de prendre des copies des documents pertinents sur place s’ils sont essentiels aux activités du prestataire tiers de services TIC, dont l’exercice effectif n’est pas entravé ou limité par d’autres accords contractuels ou politiques d’exécution; ii) le droit de convenir d’autres niveaux d’assurance si les droits d’autres clients sont affectés; iii) l’obligation pour le prestataire tiers de services TIC de coopérer pleinement lors des inspections sur place et des audits effectués par les autorités compétentes, le superviseur principal, l’entité financière ou une tierce partie désignée; et iv) l’obligation de fournir des précisions sur la portée, les procédures à suivre et la fréquence de ces inspections et audits; » (R6-F47) | Pour les fonctions critiques ou importantes : droits illimités d'accès, d'inspection et d'audit, coopération lors des inspections, précisions sur la portée et la fréquence. | contribue à : Clause de droit d'audit et de coopération — CT-7 CL-1 ; contribue à : Accès au vérificateur et aux formats sans restriction d'usage — CT-7 CL-2, CT-6 §14.4 | — | Qualification de la fonction comme critique ou importante, exercice des droits | partiel |
| MC-34 | T-6, `en_vigueur` | art. 30 § 3 f) | « les stratégies de sortie, en particulier la fixation d’une période de transition adéquate obligatoire: […] ii) qui permet à l’entité financière de migrer vers un autre prestataire tiers de services TIC ou de recourir à des solutions en interne adaptées à la complexité du service fourni. » (R6-F47) | Stratégies de sortie avec période de transition adéquate permettant la migration ou l'internalisation. | contribue à : Clause de réversibilité avec période de transition — CT-7 CL-3 ; contribue à : Aucune preuve ne dépend d'un service de l'exploitant pour être vérifiée — CT-7 EX-8.10 | — | Durée de la période de transition, exécution de la sortie | partiel |
| MC-35 | T-7, `en_vigueur` | art. 12 § 1 | « 1. Dans le cadre des garanties contre les intrusions et l’utilisation abusive de données, les entités financières élaborent, documentent et mettent en œuvre des procédures, protocoles et outils de journalisation. » (R6-F49) | Élaborer, documenter et mettre en œuvre des procédures, protocoles et outils de journalisation. | contribue à : Outil de journalisation des actions des agents, spécifié et publié — CT-1 §5, CT-2 §3 | — | Procédures et protocoles de l'entité | partiel |
| MC-36 | T-7, `en_vigueur` | art. 12 § 2 a) | « a) l’identification des événements à enregistrer dans le journal, la durée de conservation des journaux et les mesures visant à sécuriser et à gérer les données des journaux, en tenant compte de la finalité pour laquelle les journaux sont créés; » (R6-F49) | Identifier les événements à enregistrer, fixer la durée de conservation, sécuriser et gérer les données des journaux. | contribue à : Liste publiée des événements que NOORTRACE enregistre, journal de l'enregistreur sur lui-même compris ; l'entité identifie les siens — CT-1 §5.1, CT-2 §9 ; répond à : Sécuriser les données des journaux : hachage, chaînage, signatures, ancres, copies WORM — CT-6 contrôle 6, CT-2 EX-12.16 ; répond à : Durée de conservation réglable, plancher de dix ans — CT-2 EX-12.19, CT-7 EX-8.12 | — | Choix de la durée selon la finalité et l'évaluation du risque, dernier alinéa de l'article | partiel |
| MC-37 | T-7, `en_vigueur` | art. 12 § 2 c) | « c) l’obligation de consigner dans les journaux les événements relatifs à l’ensemble des éléments suivants: i) le contrôle de l’accès logique et physique, tel que visé à l’article 21, et la gestion de l’identité; ii) la gestion des capacités; iii) la gestion des modifications; iv) les opérations de TIC, y compris les activités liées aux systèmes de TIC; v) le trafic réseau, y compris les performances des réseaux de TIC; » (R6-F49) | Consigner les événements relatifs au contrôle d'accès et à l'identité, aux capacités, aux modifications, aux opérations de TIC et au trafic réseau. | contribue à : Gestion des modifications : chaque changement de l'ensemble de politique est un événement de la chaîne avant usage — CT-2 EX-9.1, CT-2 EX-10.21 ; contribue à : Opérations de TIC : actions des agents et échanges avec les modèles ; identité de lancement et décisions d'approbation signées — CT-1 §5.1, CT-6 contrôle 7 | Contrôle d'accès physique, gestion des capacités, trafic réseau en dehors des échanges capturés | Journalisation des autres systèmes de TIC | partiel |
| MC-38 | T-7, `en_vigueur` | art. 12 § 2 d) | « d) des mesures visant à protéger les systèmes de journalisation et les informations des journaux contre les manipulations, la suppression et l’accès non autorisé, au repos, en transit et, le cas échéant, en cours d’utilisation; » (R6-F49) | Protéger les systèmes et informations de journalisation contre la manipulation, la suppression et l'accès non autorisé. | répond à : Manipulation : détectée par hachage, chaînage, signatures et ancres — CT-1 E-7, CT-1 C-2, CT-6 contrôle 6, CT-6 contrôle 4 ; répond à : Suppression : copies WORM non supprimables avant l'échéance, levée de gel à deux personnes (si `storage.seal.worm` est configuré) — CT-2 EX-12.30, CT-2 EX-12.38 ; contribue à : Accès non autorisé : moindre privilège de l'enregistreur, rédaction avant hachage — CT-2 EX-18.4, CT-2 EX-10.2 | — | Contrôle d'accès aux journaux et à leurs copies | partiel |
| MC-39 | T-7, `en_vigueur` | art. 12 § 2 e) | « e) des mesures visant à détecter les défaillances des systèmes de journalisation; » (R6-F49) | Détecter les défaillances des systèmes de journalisation. | répond à : Santé, métriques, alertes prescrites et contrôles périodiques de l'enregistreur — CT-2 EX-17.1, CT-2 §17.4, CT-2 EX-17.5 | — | Branchement des alertes et réaction | couvert |
| MC-40 | T-7, `en_vigueur` | art. 12 § 2 f) | « f) sans préjudice de toute exigence réglementaire applicable en vertu du droit de l’Union ou du droit national, la synchronisation des horloges de chacun des systèmes de TIC de l’entité financière avec une horloge de référence fiable et documentée. » (R6-F49) | Synchroniser les horloges de chaque système de TIC avec une horloge de référence fiable et documentée. | répond à : Horloge synchronisée de l'enregistreur, écarts consignés — CT-2 EX-7.10 | — | Horloge de référence et synchronisation des autres systèmes | couvert |
| MC-41 | T-7, `en_vigueur` | art. 7 § 1 à 3 | « 1. Les entités financières incluent dans la politique de gestion des clés cryptographiques visée à l’article 6, paragraphe 2, point d), des exigences relatives à la gestion des clés cryptographiques tout au long de leur cycle de vie, notamment en ce qui concerne la génération, le renouvellement, le stockage, la sauvegarde, l’archivage, la récupération, la transmission, le retrait, la révocation et la destruction de ces clés cryptographiques. […] 3. Les entités financières élaborent et mettent en œuvre des méthodes pour remplacer les clés cryptographiques en cas de perte ou lorsque ces clés sont compromises ou endommagées. » (R7-F17) | Gérer les clés cryptographiques sur tout leur cycle de vie ; méthodes de remplacement en cas de perte ou de compromission. | contribue à : Inscription, rotation planifiée, rotation d'urgence et révocation des clés de l'enregistreur — CT-2 EX-11.13, CT-2 EX-11.15, CT-2 EX-11.16 | — | Politique de gestion des clés de l'entité | partiel |
| MC-42 | T-8, `pas_encore_applicable` | art. 12 § 1 | « 1. Les systèmes d’IA à haut risque permettent, techniquement, l’enregistrement automatique des événements (journaux) tout au long de la durée de vie du système. » (R6-F50) | Enregistrement automatique des événements tout au long de la durée de vie du système. | contribue à : Enregistrement automatique de chaque action et de chaque échange avec le modèle qui passent par un canal capturé — CT-2 §3, CT-1 §5.1 | Événements qui ne passent pas par un canal capturé — CT-2 EX-4.1, CT-1 partie `attestation_perimetre` | Classement du système à haut risque et couverture de toute sa durée de vie | partiel |
| MC-43 | T-8, `pas_encore_applicable` | art. 12 § 2 | « 2. Afin de garantir un degré de traçabilité du fonctionnement d’un système d’IA qui soit adapté à la destination du système, les fonctionnalités de journalisation permettent l’enregistrement des événements pertinents pour: a) repérer les situations susceptibles d’avoir pour effet que le système d’IA à haut risque présente un risque au sens de l’article 79, paragraphe 1, ou d’entraîner une modification substantielle; b) faciliter la surveillance après commercialisation visée à l’article 72; et c) surveiller le fonctionnement du système d’IA à haut risque comme prévu à l’article 26, paragraphe 5. » (R6-F50) | Événements pertinents pour repérer les risques, la surveillance après commercialisation et la surveillance par le déployeur. | contribue à : Actions, refus, approbations et échanges avec le modèle, datés et signés — CT-1 §5.1, CT-6 contrôle 7 | — | Choix des événements pertinents selon la destination du système | partiel |
| MC-44 | T-8, `pas_encore_applicable` | art. 14 § 4 d) | « d) de décider, dans une situation particulière, de ne pas utiliser le système d’IA à haut risque ou d’ignorer, remplacer ou inverser la sortie du système d’IA à haut risque; » (R6-F51) | Les personnes chargées du contrôle humain peuvent décider de ne pas utiliser le système, ou ignorer, remplacer ou inverser sa sortie. | contribue à : Approbation ou refus signés d'une action proposée par l'agent, avant qu'elle soit relayée — CT-3 EX-9.13, CT-1 A-3, CT-6 contrôle 7 | Remplacer ou inverser une sortie : non capturé en version 0 (lacune L-6, 8.9) | Conception du contrôle humain par le fournisseur | partiel |
| MC-45 | T-8, `pas_encore_applicable` | art. 14 § 4 e) | « e) d’intervenir dans le fonctionnement du système d’IA à haut risque ou d’interrompre le système au moyen d’un bouton d’arrêt ou d’une procédure similaire permettant au système de s’arrêter de manière sécurisée. » (R6-F51) | Intervenir dans le fonctionnement ou interrompre le système de manière sécurisée. | — | Bouton d'arrêt ou procédure d'interruption du système d'IA | Conception de l'arrêt | hors_perimetre |
| MC-46 | T-8, `pas_encore_applicable` | art. 14 § 5 | « […] aucune mesure ou décision n’est prise par le déployeur sur la base de l’identification résultant du système sans vérification et confirmation distinctes de cette identification par au moins deux personnes physiques disposant des compétences, de la formation et de l’autorité nécessaires. » (R6-F51) | La première phrase du § 5, coupée dans la citation (« […] ») et lue dans S12 (R6-F51), limite la règle aux systèmes visés à l'annexe III, point 1 a) : pour eux, vérification et confirmation distinctes par au moins deux personnes physiques. | contribue à : Seuil d'approbation configurable ; avec `required ≥ 2`, au moins deux adresses distinctes du jeu ont signé — CT-1 A-3, CT-3 EX-8.11, CT-3 EX-13.10 | — | Compétences, formation et autorité des personnes ; portée limitée à l'annexe III, point 1 a) (première phrase du § 5, R6-F51) ; fixer `threshold.required ≥ 2` ; choisir `separation.self_approval` (CT-3 section 10), réglage de la politique d'approbation qui, sur la valeur « interdite », empêche toute adresse déclarée pour le demandeur de compter parmi les approbateurs (CT-3 SG-7) : CT-3 rapporte que le considérant 73 admet que l'une des deux personnes soit celle qui fait fonctionner le système (CT-3 §5.4 ; R3-F12 est un fait de la note de CT-3, non de l'annexe B de CT-7), d'où un réglage et non une interdiction ; tenir une personne par clé à l'inscription (CT-3 EX-8.11, non vérifié en version 0) | partiel |
| MC-47 | T-8, `pas_encore_applicable` | art. 19 § 1 | « 1. Les fournisseurs de systèmes d’IA à haut risque assurent la tenue des journaux générés automatiquement par leurs systèmes d’IA à haut risque, visés à l’article 12, paragraphe 1, dans la mesure où ces journaux se trouvent sous leur contrôle. Sans préjudice du droit de l’Union ou du droit national applicable, les journaux sont conservés pendant une période adaptée à la destination du système d’IA à haut risque, d’au moins six mois, sauf disposition contraire dans le droit de l’Union ou le droit national applicable, en particulier dans le droit de l’Union sur la protection des données à caractère personnel. » (R6-F52) | Le fournisseur tient les journaux sous son contrôle pendant une période adaptée, d'au moins six mois. | répond à : Durée : au moins dix ans pour les événements — CT-2 EX-12.19, CT-7 EX-8.12 ; contribue à : Journaux sous le contrôle de qui les tient : journal, pièces et clés sur l'infrastructure du client ; clause de conservation — CT-7 EX-8.10, CT-7 CL-3 | Plancher de dix ans non réductible face à la réserve du droit de la protection des données (lacune L-5) — CT-7 EX-8.14 | Qualité de fournisseur, contrôle des journaux, période adaptée à la destination | partiel |
| MC-48 | T-8, `pas_encore_applicable` | art. 26 § 2 | « 2. Les déployeurs confient le contrôle humain à des personnes physiques qui disposent des compétences, de la formation et de l’autorité nécessaires ainsi que du soutien nécessaire. » (R6-F53) | Confier le contrôle humain à des personnes physiques compétentes, formées et dotées de l'autorité nécessaire. | contribue à : Approbateurs nommés par le système d'identité du client, inscrits dans un annuaire exportable, une personne et une clé — CT-3 EX-13.10, CT-3 EX-13.19 | — | Compétence, formation, autorité et soutien des personnes | partiel |
| MC-49 | T-8, `pas_encore_applicable` | art. 26 § 5 | « Les déployeurs surveillent le fonctionnement du système d’IA à haut risque sur la base de la notice d’utilisation et, le cas échéant, informent les fournisseurs conformément à l’article 72. Lorsque les déployeurs ont des raisons de considérer que l’utilisation du système d’IA à haut risque conformément à la notice d’utilisation pourrait conduire à ce que le système d’IA présente un risque au sens de l’article 79, paragraphe 1, ils en informent, sans retard injustifié, le fournisseur ou le distributeur ainsi que l’autorité de surveillance du marché concernée, et suspendent l’utilisation de ce système. » (R6-F53) | Surveiller le fonctionnement selon la notice, informer et suspendre en cas de risque. | contribue à : Journal signé des actions et décisions, disponible pour la surveillance — CT-1 §5.1, CT-6 §5.1 | — | Surveillance, information du fournisseur et de l'autorité, suspension | partiel |
| MC-50 | T-8, `pas_encore_applicable` | art. 26 § 6 | « 6. Les déployeurs de systèmes d’IA à haut risque assurent la tenue des journaux générés automatiquement par ce système d’IA à haut risque dans la mesure où ces journaux se trouvent sous leur contrôle, pendant une période adaptée à la destination du système d’IA à haut risque, d’au moins six mois, sauf disposition contraire dans le droit de l’Union ou le droit national applicable, en particulier dans le droit de l’Union sur la protection des données à caractère personnel. » (R6-F54) | Le déployeur tient les journaux sous son contrôle pendant une période adaptée, d'au moins six mois. | répond à : Durée : au moins dix ans pour les événements — CT-2 EX-12.19, CT-7 EX-8.12 ; contribue à : Journaux sous le contrôle du déployeur : journal, pièces et clés sur son infrastructure ; clause de conservation — CT-7 EX-8.10, CT-7 CL-3 | Plancher de dix ans non réductible face à la réserve du droit de la protection des données (lacune L-5) — CT-7 EX-8.14 | Période adaptée à la destination, lien avec la documentation du droit des services financiers | partiel |
| MC-51 | T-9, `en_vigueur` | art. 3 | « Le mode de tenue, de saisie et de conservation doit garantir que les livres et les pièces comptables ne puissent être modifiés sans que la modification soit apparente. » (R6-F59) | Les livres et pièces ne peuvent être modifiés sans que la modification soit apparente. | répond à : Toute modification d'un événement, d'un voisin, d'un chemin ou d'un manifeste est apparente au vérificateur — CT-6 contrôle 1, CT-6 contrôle 2, CT-6 contrôle 3, CT-6 contrôle 6 | — | Qualification du journal comme livre ou pièce comptable | couvert |
| MC-52 | T-9, `en_vigueur` | art. 6 | « 1 Jusqu’à la fin du délai de conservation, toute personne autorisée doit pouvoir, en tout temps et dans un délai raisonnable, consulter et vérifier les livres et les pièces comptables. 2 Le personnel, les appareils et les instruments auxiliaires sont mis à disposition en tant qu’ils sont nécessaires à la consultation et à la vérification. 3 Dans le cadre du droit de consultation, la possibilité doit être offerte, à la personne autorisée qui le demande, de rendre les livres lisibles sans l’aide d’instruments auxiliaires. » (R6-F61) | Consultation et vérification en tout temps ; lecture possible sans instruments auxiliaires sur demande. | contribue à : Événements et dossiers en JSON UTF-8 lisible ; vérificateur libre et hors ligne — CT-1 §3, CT-6 EX-3.3, CT-7 CL-2 | Pièces binaires ou rédigées : leur lecture sans instrument dépend de leur format | Mise à disposition du personnel et des moyens de consultation | partiel |
| MC-53 | T-9, `en_vigueur` | art. 8 | « Art. 8 Archives Les informations sont inventoriées systématiquement et protégées contre les accès non autorisés. Les consultations et les accès sont enregistrés. Ces enregistrements sont soumis à la même obligation de conservation que les supports de données. » (R6-F62) | Archives inventoriées et protégées ; consultations et accès enregistrés et conservés aussi longtemps que les supports. | contribue à : Registre des copies WORM et relevé de verrouillage : inventaire des copies — CT-2 EX-12.29, CT-2 EX-17.6 | Enregistrement des consultations et des accès au journal et à ses copies — CT-7 EX-8.15 | Journalisation des accès au stockage et à ses copies, conservée aussi longtemps | partiel |
| MC-54 | T-9, `en_vigueur` | art. 9 al. 1 let. b | « b. les supports d’information modifiables si: 1. des procédés techniques (p. ex. signature électronique) sont utilisés, qui garantissent l’intégrité des informations enregistrées, 2. le moment où les informations ont été enregistrées peut être prouvé sans possibilité de falsification (p. ex. grâce à un système d’horodatage), 3. les autres prescriptions relatives à l’utilisation du procédé en question qui existent au moment de l’enregistrement sont respectées, et 4. les procédures et les modes d’utilisation de ces supports sont consignés et les informations nécessaires (protocoles, journal de bord des connexions [log files]) sont également conservées. » (R6-F63) | Supports modifiables admis si intégrité garantie par un procédé technique, moment d'enregistrement prouvé, prescriptions respectées, procédures consignées et journaux conservés. | répond à : Ch. 1 : signature électronique de chaque événement et de chaque manifeste — CT-6 contrôle 6, CT-2 EX-12.21 ; répond à : Ch. 2 : moment d'enregistrement prouvé par horodatage RFC 3161 et OpenTimestamps : une date au plus tard, celle de la période ou du point de contrôle qui engage l'événement (CT-1 §10.9) ; le `ts` de l'événement reste déclaratif ; le jeton RFC 3161 vaut sous l'hypothèse H4 de CT-6 (prestataire honnête, RA-54, PA-19), et la preuve OpenTimestamps donne une borne indépendante (contrôle 5) — CT-6 contrôle 4, CT-6 contrôle 5, CT-5 EX-5.15 ; contribue à : Ch. 4 : journal d'exploitation, qui porte l'identité de connexion d'hôte et les refus d'authentification, conservé avec le journal dans la limite de `logging.keep_files` ; purges consignées — CT-2 EX-9.6, CT-2 EX-12.20 | Archivage des fichiers tournés du journal d'exploitation au-delà de `logging.keep_files` : renvoyé à CT-8 (lacune L-9) | Ch. 3 : autres prescriptions du procédé ; qualification du journal | partiel |
| MC-55 | T-9, `en_vigueur` | art. 10 al. 1 | « 1 L’intégrité et la lisibilité des supports d’information sont régulièrement contrôlées. » (R6-F64) | Contrôle régulier de l'intégrité et de la lisibilité des supports. | contribue à : Relecture et vérification horaire et quotidienne des segments, comparaison aux copies WORM — CT-2 EX-17.5, CT-2 EX-12.21 | Contrôle périodique de l'intégrité et de la lisibilité des segments anciens et de leurs copies WORM : non spécifié en version 0 (lacune L-10) | Contrôle des supports qu'il exploite hors de l'enregistreur | partiel |
| MC-56 | T-9, `en_vigueur` | art. 10 al. 2 et 3 | « 2 Le format des données peut être modifié et les données peuvent être transférées sur d’autres supports d’information (migration), s’il est garanti: a. que les informations restent complètes et exactes, et b. que la disponibilité et la lisibilité continuent de satisfaire aux exigences légales. 3 Le transfert des données d’un support d’information à un autre doit faire l’objet d’un procès-verbal. Ce dernier est conservé avec les informations. » (R6-F64) | Migration admise si complétude, exactitude, disponibilité et lisibilité sont garanties ; procès-verbal de transfert conservé. | contribue à : Après migration, chaque dossier se vérifie de nouveau : la complétude et l'exactitude se constatent par les contrôles — CT-6 §5.1 | Procès-verbal de migration de support : renvoyé à CT-8, non spécifié en version 0 (lacune L-2, 8.9) — CT-2 §12.8 | Décision et exécution de la migration | partiel |
| MC-57 | T-10, `en_vigueur` | art. 958f al. 1 | « 1 Les livres et les pièces comptables ainsi que le rapport de gestion et le rapport de révision sont conservés pendant dix ans. Ce délai court à partir de la fin de l’exercice. » (R6-F65) | Conservation pendant dix ans à partir de la fin de l'exercice. | répond à : Événements, manifestes, signatures, pièces d'horodatage et file conservés au moins dix ans à compter de la fin de l'exercice — CT-2 EX-12.19, CT-5 EX-5.15, CT-5 EX-8.14, CT-7 EX-8.12 | — | Qualification du journal comme livre ou pièce comptable ; fin de l'exercice | couvert |
| MC-58 | T-10, `en_vigueur` | art. 958f al. 3 | « 3 Les livres et les pièces comptables peuvent être conservés sur support papier, sur support électronique ou sous toute forme équivalente, pour autant que le lien avec les transactions et les autres faits sur lesquels ils portent soit garanti et que leur lecture reste possible en toutes circonstances. » (R6-F65) | Support électronique admis si le lien avec les faits est garanti et si la lecture reste possible en toutes circonstances. | répond à : Lien avec les faits : chaque pièce jointe est liée à son événement par son SHA-256, l'événement à la chaîne — CT-1 E-6, CT-6 contrôle 1 ; contribue à : Lecture : formats publiés et vérificateur libre, hors ligne — CT-1 §3, CT-6 EX-3.3, CT-7 CL-2 | — | Lecture en toutes circonstances des supports qu'il exploite | partiel |

Note sur MC-54. Le ch. 4 vise les protocoles et le journal de bord des
connexions du procédé d'enregistrement lui-même. Le journal d'exploitation y
contribue : chaque ligne porte l'identité de connexion d'hôte (`host`, CT-2
EX-9.5, EX-17.2) et les refus d'authentification (`auth_failed`) ; son archivage
au-delà de `logging.keep_files` est renvoyé à CT-8 (L-9). La trace des
consultations du journal archivé et de ses copies relève de l'art. 8 (MC-53) ;
c'est la lacune L-1, qui ne touche pas MC-54. L'al. 2 de l'art. 9 (« 2 Les
supports d’information sont réputés modifiables lorsqu’ils peuvent être modifiés
ou effacés sans que l’opération soit détectable sur le support de données
lui-même (p. ex. bandes magnétiques, disquettes magnétiques ou
optico-magnétiques, disques durs ou disques amovibles, disques à l’état solide
[solid-state]). », R6-F63) range le stockage de l'enregistreur parmi les
supports modifiables, d'où la let. b ; la let. a ne s'applique pas. La note ne
qualifie que le stockage de l'enregistreur. Elle ne dit pas si les copies WORM
relèvent de la let. a : CT-7 ne l'a pas examiné (non vérifié), et la
qualification relève du client. CT-7 n'a pas identifié les prescriptions visées
par le ch. 3 (non vérifié) ; les établir relève du client.

### 8.5 Opérations de l'art. 4 OPDo et actions de CT-1

L'art. 4 al. 1 OPDo nomme six opérations ; CT-1 v0 n'a que cinq valeurs de
`effects[].action`, format figé (CT-1 §5.3).

**EX-8.8 (table de passage).** La correspondance est celle-ci, et seulement
celle-ci ; elle vit dans CT-7 et ne change pas le format v0 :

| Opération (art. 4 al. 1 et al. 4 OPDo) | `effects[].action` de CT-1 | Ce qui la distingue dans l'événement | Ce qui manque |
|---|---|---|---|
| Accès | `lecture` | outil appelé (`execution.tool`), `system`, `object` | — |
| Enregistrement | `ecriture` | outil appelé, `object` | distinction avec la modification (L-4) |
| Modification | `ecriture` | outil appelé, `object` | distinction avec l'enregistrement (L-4) |
| Communication | `envoi` | `system`, `object` ; échange avec le modèle (`noortrace.modele.echange`) | destinataire sans champ propre (L-3) |
| Effacement | `suppression` | outil appelé, `object` | distinction avec la destruction (L-4) |
| Destruction | `suppression` | outil appelé, `object` | distinction avec l'effacement (L-4) |
| — | `execution` | outil appelé | aucune opération de l'art. 4 al. 1 ne lui correspond seule |
| Identité de la personne (al. 4) | — | `delegation.launched_by`, `on_behalf_of`, `run_id` ; identité technique : connexion d'hôte et `recorder_key_id` | rattachement à une personne responsable : relève du client |
| Date et heure (al. 4) | — | `ts` (CT-2 EX-7.10), borné par les ancres (CT-6 contrôles 4 et 5) | — |

Les effets sont déclarés par l'enregistreur à partir du gabarit d'effets de
l'outil (CT-2 EX-7.6) : le client qui veut distinguer l'enregistrement de la
modification, ou nommer le destinataire, le fait dans le nom de l'outil et
dans `object`, par ses gabarits. Ce qui ne passe pas par un canal capturé
n'est pas journalisé (CT-2 EX-4.1) ; l'attestation de périmètre (section 7)
le déclare, sans le prouver.

Exemple informatif, sous `policy.servers.<alias>.tools` de la configuration
(gabarits d'effets de CT-2 EX-7.6) : deux outils distincts, l'un qui crée une
fiche et l'autre qui la modifie, dont `object` nomme la fiche ; un outil
d'envoi dont `object` nomme le système destinataire. Comme le dit L-3, un
destinataire écrit dans `object` est une valeur en ligne de l'événement, non
purgeable (L-5) ; un pointeur s'y résout dans les valeurs rédigées (CT-2
EX-7.6).

```json
{
  "fiches.creer": {
    "class": "ecriture",
    "timeout_ms": null,
    "effects": [
      { "system": "CRM", "action": "ecriture", "object": "/result/structuredContent/fiche_id", "amount": null, "currency": null }
    ],
    "failure": null
  },
  "fiches.modifier": {
    "class": "ecriture",
    "timeout_ms": null,
    "effects": [
      { "system": "CRM", "action": "ecriture", "object": "/arguments/fiche_id", "amount": null, "currency": null }
    ],
    "failure": null
  },
  "dossier.transmettre": {
    "class": "ecriture",
    "timeout_ms": null,
    "effects": [
      { "system": "CRM", "action": "envoi", "object": "destinataire : gestion des sinistres du réassureur", "amount": null, "currency": null }
    ],
    "failure": null
  }
}
```

L'al. 3 (« 3 Pour les données personnelles accessibles à tout un chacun,
l’enregistrement, la modification, l’effacement et la destruction des données
doivent au moins être journalisés dans les cas prévus aux al. 1 et 2, 1re
phrase. », R6-F26) ne demande qu'une partie des opérations de l'al. 1. La table
d'EX-8.8 et la ligne MC-15 s'y appliquent ; il n'a pas de ligne propre.

### 8.6 Composants tiers de NOORTRACE

La circulaire FINMA 2018/3 (Cm 14, Cm 33) et DORA (art. 28 § 3, art. 29
§ 2) demandent de connaître le prestataire et ses sous-traitants. NOORTRACE
dépend des composants suivants, qu'un autre que le client exploite :

| Composant | Exploité par | Contracté par | Rôle | Ce qu'il reçoit | Ce qu'il ne reçoit jamais | Effet de sa perte sur les preuves |
|---|---|---|---|---|---|---|
| Registre (validateurs, RPC, contrats) | l'exploitant NOORTRACE et des opérateurs de validateurs partenaires, nommés avec leur site dans le manifeste d'instance (CT-4 §4.8) | le client avec l'exploitant NOORTRACE ; les opérateurs de validateurs avec l'exploitant NOORTRACE | inscription des clés d'enregistreur, clôtures et ancres des périodes et des points, jeux d'approbateurs (CT-4) | `org_id`, `journal_id`, clés publiques Ed25519 et clés de chaîne, `periodHash`, empreintes d'ancre, adresses des approbateurs et leurs signatures sur les condensés du registre | événements, pièces, prompts, arguments, résultats | le contrôle 8 ne s'exécute plus pour les périodes non inscrites ; l'enregistreur continue sans bloquer (CT-2 §14 ; CT-5 EX-4.12) ; les certificats déjà capturés par le client restent sa seule copie, suffisante (CT-4 §9.5) |
| Prestataires d'horodatage RFC 3161 | prestataires choisis selon CT-5 §5.3 et §11 | le client | jeton sur `periodHash` ou `checkpointHash` | la requête `TimeStampReq` de CT-5 §5.1, qui porte une empreinte | tout contenu du journal | le contrôle 4 ne s'exécute plus pour les périodes non horodatées ; les jetons obtenus restent vérifiables hors ligne avec le fichier d'ancres du réviseur (CT-6 §9) |
| Calendriers OpenTimestamps, réseau Bitcoin | tiers publics | aucun contrat (service public) | preuve d'existence avant un bloc | une empreinte (CT-5 §6.2) | tout contenu du journal | le contrôle 5 ne s'exécute plus, ou une preuve reste incomplète tant qu'elle n'est pas mise à niveau (CT-5 §6.4) ; les autres ancres ne changent pas |
| Relais du parcours c de la console (WalletConnect v2) | tiers choisi par le client, ou relais qu'il héberge (CT-3 §13.12) | le client | transport entre la console et le portefeuille mobile d'un approbateur | les messages de la session de signature et leurs métadonnées, dont la conservation n'est pas vérifiée (CT-3, R4 NV-4) | la clé de l'approbateur | le parcours c ne sert plus ; les autres parcours de signature restent (CT-3 §13.9) |

Un composant figure dans l'inventaire quand une ancre ou une fonction de
NOORTRACE en dépend et qu'un autre que le client l'exploite (section 2), que le
contrat soit passé par l'exploitant NOORTRACE ou par le client. Les prestataires
RFC 3161 (compte ouvert par l'administrateur du client, CLE-11) et le relais du
parcours c (choisi par le client, CT-3 §13.12) y figurent donc, bien que le
client les contracte. N'y figurent pas : le serveur d'horodatage interne (CT-5
§7) et l'hébergement de l'enregistreur et du service d'approbation, que le
client exploite lui-même ou fait exploiter pour son compte ; le support WORM,
qui est le stockage du client ; les fournisseurs de modèles, les serveurs
d'outils, le système d'identité et la source de temps, qui sont l'environnement
du client que NOORTRACE observe ou dans lequel il s'exécute.

CT-7 ne qualifie pas le rôle de l'exploitant NOORTRACE au sens de la LPD et de
l'OPDo (responsable du traitement, sous-traitant, ou ni l'un ni l'autre), ni
les adresses et signatures d'approbateurs comme données personnelles : c'est
une qualification juridique, que CT-7 n'a pas recherchée (non vérifié) et qui
relève du client et de ses conseils. La table dit seulement ce que le registre
reçoit.

**EX-8.9 (inventaire des tiers).** L'exploitant NOORTRACE DOIT publier cet
inventaire avec le manifeste d'instance (CT-4 §4.8) et le tenir à jour ; tout
ajout, retrait ou changement d'un composant, de son exploitant ou de son
lieu DOIT être annoncé aux clients avant de prendre effet (clause CL-4).
PA-14 demande à CT-4 d'en faire un membre du manifeste d'instance.

### 8.7 Réversibilité et accès : exigences mesurables

La circulaire 2018/3 (Cm 18.1) et DORA (art. 28 § 8, art. 30 § 2 d) et
§ 3 f)) demandent qu'on puisse sortir d'un prestataire. Pour NOORTRACE, la
parité s'écrit en exigences mesurables :

**EX-8.10 (aucune preuve ne dépend de l'exploitant).** (a) Les huit contrôles
de CT-6 s'exécutent sans réseau, sans compte ni service de l'exploitant
NOORTRACE (CT-6 EX-3.3) ; mesure : les vecteurs de `spec/vecteurs/ct-6`
rejoués sous `unshare -n` donnent le même rapport (CT-6 V-8). (b) Les
événements, pièces, manifestes, points, pièces d'horodatage et captures du
registre sont écrits sur le stockage du client (CT-2 §12.1, CT-5 EX-5.14,
CT-4 §9.4) ; mesure : CT-1 §11.2 et la table 8.6 nomment le producteur de
chaque partie d'un dossier, et aucune n'est obtenue de l'exploitant au moment
de la vérification.
(c) La seule donnée de preuve que les validateurs gardent seuls, au-delà de
leur fenêtre de rétention, est le certificat de commit : le client le
capture dans la fenêtre (CT-4 EX-9.11) et le conserve (EX-8.17). (d) À la fin
du contrat, aucune action de l'exploitant n'est nécessaire pour vérifier les
dossiers déjà exportés.

**EX-8.11 (formats et vérificateur).** Les formats (CT-1), les schémas
(`spec/schemas`), les vecteurs et le vérificateur de référence sont publiés
avec le code, sous licence Apache-2.0 (CT-6 EX-14.10) ; un vérificateur de
version 0 lit les dossiers de version 0, et une version ultérieure lira les
dossiers de version 0 avec leurs règles (CT-6 EX-14.11). La clause CL-2 en
fait un engagement contractuel.

### 8.8 Rétention

#### 8.8.1 Durées exigées par les textes lus

| Texte, passage | Durée | Point de départ | Objet | Fait | Applicabilité |
|---|---|---|---|---|---|
| CO art. 958f al. 1 | dix ans | fin de l'exercice | livres, pièces comptables, rapport de gestion, rapport de révision | R6-F65 | en vigueur ; un journal n'en relève que si le client l'y range |
| Olico art. 4 al. 2 | même période que les livres | — | instructions de travail | R6-F60 | en vigueur, même condition |
| Olico art. 8 | même obligation que les supports | — | enregistrements des consultations et des accès aux archives | R6-F62 | en vigueur, même condition |
| Olico art. 10 al. 3 | conservé avec les informations | — | procès-verbal de migration | R6-F64 | en vigueur, même condition |
| OPDo art. 4 al. 5 | au moins un an, séparément du système de traitement | non précisé | procès-verbaux de journalisation | R6-F26 | en vigueur depuis le 1er décembre 2025, dans les cas de l'al. 1 |
| PFPDT, recommandations, ch. 3.2 let. b | au moins un an ; durée claire ; pas plus longtemps que les dispositions légales | non précisé | données de journalisation | R6-F35 | publication de l'autorité |
| Règlement (UE) 2024/1689, art. 19 § 1 | au moins six mois, période adaptée à la destination, sauf disposition contraire, notamment de protection des données | non précisé | journaux sous le contrôle du fournisseur | R6-F52 | pas encore applicable |
| Règlement (UE) 2024/1689, art. 26 § 6 | même règle | non précisé | journaux sous le contrôle du déployeur | R6-F54 | pas encore applicable |
| Règlement délégué (UE) 2024/1774, art. 12 § 2 a) et dernier alinéa | fixée par l'entité selon la finalité et l'évaluation du risque | — | journaux | R6-F49 | en vigueur |
| DORA, circulaire 2018/3, communication 08/2024 | aucune durée dans les passages lus | — | — | — | — |
| Droit bancaire, droit des assurances, LBA | non recherché (NV-6) | — | — | — | relève du client (L-7) |

#### 8.8.2 Ce que NOORTRACE conserve

| Objet | Où | Durée | Règle |
|---|---|---|---|
| Événements (segments), manifestes, signatures | stockage de l'enregistreur | au moins dix ans à compter de la fin de l'exercice ; `storage.retention.events_years ≥ 10`, refusé sinon | CT-2 EX-12.19, EX-15.4 |
| Copies WORM des segments fermés, manifestes, signatures, séries de points et répertoires `ancres/` | support WORM du client | `retain_days ≥ 365 × events_years`, à compter de la date d'écriture de chaque copie ; seuls 4 018 jours (recommandés) couvrent la fin de l'exercice plus dix ans ; un gel juridique prolonge la conservation des copies qu'il couvre jusqu'à sa levée par deux personnes | CT-2 EX-12.16, EX-12.30, EX-12.19, EX-12.38 |
| Pièces | stockage de l'enregistreur | `storage.retention.pieces_days`, ou sans limite (`null`) ; purge sautée pour les pièces d'un gel actif ; chaque purge consignée | CT-2 EX-12.20 |
| Journal d'exploitation | stockage de l'enregistreur | durée du journal visée par CT-2 EX-9.6 ; le démon n'en tient que `logging.keep_files` fichiers, l'archivage des fichiers tournés relève de CT-8 (L-9) | CT-2 EX-9.6 |
| Pièces d'horodatage, file, acquisitions | `ancres/` | au moins dix ans (`rfc3161.retention_years ≥ 10`) | CT-5 EX-5.15, EX-8.14 |
| Trace du ticket, sans arguments | service d'approbation | aussi longtemps que le journal | CT-3 EX-7.24 |
| Arguments en clair d'un ticket | service d'approbation | jusqu'à la fin du ticket | CT-3 EX-7.24 |
| Certificats de commit | validateurs | 300 000 hauteurs par défaut, environ 75,8 h ; au moins 3 000 000 recommandées | CT-4 §9.5, EX-9.7 |
| Captures du registre, annuaire exporté, registre des copies, registre des gels, procès-verbaux de cérémonie, attestations de périmètre | stockage du client | aussi longtemps que les événements qu'ils servent | CT-7 EX-8.17 |
| Originaux du coffre (facultatif) | répertoire distinct | sans plancher ; fixée par le client | CT-2 EX-10.22, CT-7 EX-8.18 |

Pour tout journal, comptable ou non, la fin de l'exercice est le point de départ
que CT-2 EX-12.19 fixe pour calculer le plancher ; ce n'est pas une
qualification du journal comme pièce comptable. Les 4 018 jours couvrent la fin
de l'exercice en cours plus dix ans, soit environ onze ans (CT-2 EX-12.16).

En résumé : événements, au moins dix ans à compter de la fin de l'exercice, pour
tout journal (CT-2 EX-12.19) ; copies WORM, `retain_days` à compter de
l'écriture de chaque copie. Le minimum exigé avec `events_years = 10`, 3 650
jours, peut expirer jusqu'à environ un an avant le plancher des événements ;
4 018 jours (recommandé) l'évitent ; PA-20 propose d'en faire une erreur quand
la base est l'art. 958f CO.

#### 8.8.3 Confrontation

Le plancher de dix ans de CT-2 et de CT-5 égale la durée du CO, la plus
longue des textes lus, et dépasse les minimums de l'OPDo et du PFPDT (un an)
et du règlement (UE) 2024/1689 (six mois). Il heurte deux autres règles :
le PFPDT demande d'« éviter de les conserver inutilement » et de ne pas
conserver « plus longtemps que ce que prévoient les dispositions légales »
(R6-F35), et le règlement (UE) 2024/1689 réserve les dispositions contraires
du droit de la protection des données (R6-F52, R6-F54). Les règles suivantes
en tiennent compte.

**EX-8.12 (durées plus longues).** Les durées de NOORTRACE sont des
planchers. Quand une durée légale qui s'applique aux journaux d'un client
dépasse dix ans, le client DOIT porter `storage.retention.events_years`,
`retain_days` et `rfc3161.retention_years` à cette durée ; les trois
paramètres acceptent toute valeur au-dessus du plancher. Aucun texte lu
n'impose plus de dix ans (8.8.1) ; les durées sectorielles n'ont pas été
recherchées (NV-6) et relèvent du client (L-7). C'est la réponse au renvoi
de CT-5 EX-5.15.

**EX-8.13 (cohérence des durées).** Pour un même journal,
`rfc3161.retention_years` DOIT être au moins égal à
`storage.retention.events_years`, et `retain_days` au moins égal à
`365 × events_years` (déjà exigé par CT-2 EX-15.4). Tant que PA-13 n'est
pas adoptée, la première égalité est une exigence portée par le client, que
ni CT-2 ni CT-5 ne contrôlent.

**EX-8.14 (minimisation).** Les pièces se purgent (`pieces_days`) et se rédigent
avant hachage (CT-2 EX-10.2) ; les événements ne se purgent pas avant leur
plancher. Les données personnelles qu'un événement porte en clair
(`delegation.launched_by`, `on_behalf_of`, `intent`, `effects`, adresses et
motif d'une décision d'approbation) restent donc au moins dix ans, même pour un
client dont le journal n'est pas une pièce comptable. C'est le risque accepté de
la lacune L-5 : nommé ici, borné à toutes les valeurs en ligne de CT-2 EX-10.2
(`delegation`, `intent`, `effects`, `code.model`, nom de prompt, motifs et
adresses d'approbation) et aux pièces hors chaîne qui nomment des personnes
(`participants[].name` et `affiliation` des procès-verbaux, section 5 ;
`prepared_by.identity` et signataires des attestations, section 7), attribué au
client qui décide de journaliser ces données sous ce plancher ; PA-12 et PA-13
proposent un plancher réglable. « Qui décide » vise le choix des valeurs que le
client fait porter aux membres en ligne (identifiant de personne ou désignation
de fonction). Le plancher de dix ans ne se règle pas en version 0. Tant que
PA-12 et PA-13 ne sont pas adoptées, ce choix est le levier du client ; le
conflit avec MC-23, MC-47 et MC-50 reste ouvert, et c'est le risque accepté de
L-5.

**EX-8.15 (consultations).** NOORTRACE version 0 n'enregistre ni la lecture
du journal ou de ses copies, ni l'export d'un dossier. Un client qui range
son journal parmi ses livres DOIT journaliser les accès à `storage.root`, au
support WORM et aux exports, et conserver ces enregistrements aussi
longtemps que le journal (Olico art. 8, R6-F62 ; lacune L-1) ; PA-15
demande à CT-8 de le spécifier.

**EX-8.16 (fin de rétention).** Rien dans NOORTRACE ne supprime un événement,
une copie WORM ou une pièce d'horodatage. La fin de rétention est un acte
d'exploitation consigné (CT-8) ; les durées des événements courent de la fin de
l'exercice ; pour les copies WORM, l'échéance court de la date d'écriture, et
seul `retain_days ≥ 4 018` (recommandé) couvre la fin de l'exercice plus dix
ans ; un gel juridique la suspend pour les copies qu'il couvre (CT-2 EX-12.19,
EX-12.38). PA-20 propose à CT-2 une erreur, et non plus un avertissement, sous
`365 × (events_years + 1)` quand la base est l'art. 958f CO.

**EX-8.17 (pièces hors chaîne).** Les pièces hors chaîne qui servent à
vérifier ou à recouper un dossier DOIVENT être conservées au moins aussi
longtemps que les événements qu'elles servent : captures du registre (CT-4
§9.4), annuaire exporté (CT-3 EX-13.19), trace du ticket (CT-3 EX-7.24),
registre des copies (CT-2 EX-12.29), registre des gels (CT-2 EX-12.37),
procès-verbaux de cérémonie (section 5), attestations de périmètre
(section 7).

**EX-8.18 (coffre des originaux).** Le coffre facultatif des originaux non
rédigés (CT-2 EX-10.22) n'a pas de plancher : il existe pour une obligation
de produire l'original, dont la durée fixe la sienne. Le client DOIT
consigner cette durée et la purge des originaux ; l'accès au coffre est un
acte consigné (section 3).

### 8.9 Lacunes

**EX-8.19 (lacunes).** Tout écart que la matrice trouve entre un passage et
ce que NOORTRACE fait, quand une pièce de CT-7 y renvoie, DOIT être une
lacune de cette table : nommée, bornée, attribuée, avec une réponse
(`risque_accepte`, `proposition`, `renvoi` ou `releve_du_client`). La table
et `gaps` de `matrice-conformite.json` disent la même chose (MX-8).

| Lacune | Écart | Lignes | Réponse | Borne | Attribuée à | Règle |
|---|---|---|---|---|---|---|
| L-1 | Consultations et accès au journal non enregistrés par NOORTRACE | MC-53 | `releve_du_client` | Toute modification du contenu du journal est détectée par les contrôles 1 à 8 ; elle n'est empêchée que par la copie WORM, si elle est configurée ; seule la trace des lectures manque. | client (journalisation de son stockage) ; proposition PA-15 à CT-8 | CT-7 EX-8.15 |
| L-2 | Procès-verbal de migration de support non spécifié | MC-56 | `renvoi` | Tout dossier se revérifie après migration ; seul le procès-verbal manque. | CT-8 (CT-2 §12.8) ; proposition PA-15 | CT-7 EX-8.19 |
| L-3 | Destinataire des données sans champ propre | MC-16 | `risque_accepte` | Le système et l'objet d'un effet `envoi` sont journalisés ; le destinataire peut figurer dans l'objet par le gabarit d'effets. Le destinataire écrit dans `object` n'est pas purgeable (L-5). | client (gabarits d'effets, CT-2 EX-7.6) ; format v0 figé | CT-7 EX-8.8 |
| L-4 | Enregistrement et modification, effacement et destruction non distingués | MC-15 | `risque_accepte` | L'outil appelé et l'objet distinguent l'opération ; seule l'énumération `action` est plus grossière. | client (nommage des outils et gabarits) ; une version 1 du format peut l'affiner | CT-7 EX-8.8 |
| L-5 | Plancher de dix ans pour les données personnelles en ligne des événements | MC-23, MC-47, MC-50 | `proposition` | Touche les valeurs en ligne de CT-2 EX-10.2 (`delegation`, `intent`, `effects`, `code.model`, nom de prompt, motifs et adresses d'approbation) et, hors chaîne, `participants[].name` et `affiliation` des procès-verbaux (section 5), `prepared_by.identity` et les signataires des attestations (section 7) ; les pièces sont purgeables et rédigées. | proposition PA-12 à CT-2 et PA-13 à CT-5 ; risque accepté par le client tant qu'elles ne sont pas adoptées | CT-7 EX-8.14 |
| L-6 | Sorties ignorées, remplacées ou inversées hors approbation non capturées | MC-3, MC-44 | `risque_accepte` | Seuls les refus et expirations d'approbation sont journalisés et signés. | client (journalisation de l'application) ; proposition PA-16 pour une version 1 | CT-7 EX-8.19 |
| L-7 | Durées sectorielles de conservation non recherchées | MC-57 | `releve_du_client` | Les paramètres de durée acceptent toute valeur supérieure au plancher. | client (NV-6) | CT-7 EX-8.12 |
| L-8 | Vigueur de la circulaire FINMA 2018/3 au 2026-10-26 non lue dans un acte | MC-7, MC-8, MC-9, MC-10, MC-11, MC-12, MC-13, MC-14 | `renvoi` | Les lignes restent valables comme correspondance technique ; leur statut juridique est à confirmer. Pour la circulaire FINMA 2018/3, la vigueur au 2026-10-26 n'a pas été lue dans un acte (NV-1), et les catégories d'assujettis visées, dont les entreprises d'assurance, n'ont pas été lues (non vérifié) ; savoir si elle s'applique au client relève de lui (NV-8). | prochaine révision de CT-7 (NV-1) | CT-7 EX-8.4 |
| L-9 | Archivage du journal d'exploitation au-delà de `logging.keep_files` non spécifié | MC-54 | `renvoi` | Le démon ne garde que `logging.keep_files` fichiers tournés ; la durée du journal (CT-2 EX-9.6) n'est tenue pour le journal d'exploitation que si le client archive les fichiers tournés. | CT-8 ; proposition PA-15 étendue à l'archivage des fichiers tournés | CT-7 EX-8.19 |
| L-10 | Contrôle périodique de l'intégrité et de la lisibilité des segments anciens et de leurs copies WORM non spécifié | MC-21, MC-55 | `proposition` | Segments fermés du jour et de l'heure contrôlés (CT-2 EX-17.5) ; tout dossier exporté se revérifie entièrement (CT-6 §5.1). | proposition PA-17 à CT-2 (EX-17.5) | CT-7 EX-8.19 |

L-1 et L-9 visent deux journaux différents (section 2) : L-1, l'enregistrement
des consultations et des accès au journal (Olico art. 8, MC-53) ; L-9, la
conservation des fichiers tournés du journal d'exploitation (Olico art. 9 al. 1
let. b ch. 4, MC-54).

### 8.10 Lire une ligne

Exemple : un responsable de la conformité cherche l'art. 4 al. 5 OPDo. Il trouve
MC-17 (texte T-3, `en_vigueur`). La citation dit ce que le texte exige : au
moins un an, séparément du système, accès restreint, usage limité. La colonne
« Pièce NOORTRACE » dit que la conservation répond à l'exigence (CT-2 EX-12.19 :
au moins dix ans) et que le stockage séparé y répond si le support WORM est
configuré (CT-2 EX-12.16, EX-12.30). « Relève du client » : restreindre l'accès
aux journaux et limiter leur usage. Statut : `partiel`, car le stockage séparé
n'existe que sous condition (EX-8.3). Cela ne dit pas que le client est
conforme : il lui reste à établir que l'art. 4 al. 1 s'applique à ses
traitements, à configurer le support WORM et à restreindre l'accès.

### 8.11 Propositions aux autres spécifications

Propositions d'alignement, sans modifier les spécifications nommées ni leurs
vecteurs (famille PA-, section 6.2 ; PA-18 y figure) :

| Id | Adressée à | Proposition | Motif |
|---|---|---|---|
| PA-12 | CT-2 (EX-15.4, 15.1) | Un membre facultatif `storage.retention.basis` (`co_958f` par défaut, ou `autre`) ; avec `autre`, `events_years ≥ 1` est admis et un avertissement est consigné ; avec `co_958f`, le plancher reste dix ans | Minimisation (PFPDT ch. 3.2 let. b, R6-F35) ; lacune L-5 |
| PA-13 | CT-2 et CT-5 | À la validation, quand la configuration de l'enregistreur désigne le document `ancrage-v0` (`anchoring.ancrage`), vérifier `rfc3161.retention_years ≥ storage.retention.events_years` ; aligner le plancher de CT-5 sur celui de PA-12 | EX-8.13 ; L-5 |
| PA-14 | CT-4 (§4.8) | Un membre `third_parties[]` du manifeste d'instance : composant, exploitant, lieu, rôle, données reçues, effet de la perte | EX-8.9 ; circulaire 2018/3 Cm 14 et 33, DORA art. 28 § 3 et art. 29 § 2 |
| PA-15 | CT-8 | Spécifier le journal des consultations et des accès au stockage, aux copies WORM et aux exports, le procès-verbal de migration de support (CT-2 §12.8) et l'archivage des fichiers tournés du journal d'exploitation avec le journal, pour la même durée (CT-2 EX-9.6) | Olico art. 8, art. 9 al. 1 let. b ch. 4 et art. 10 al. 3 ; lacunes L-1, L-2 et L-9 |
| PA-16 | CT-1 version 1 et CT-2 | Journaliser une sortie de l'agent ignorée, remplacée ou inversée par une personne hors d'une approbation, et distinguer enregistrement et modification, effacement et destruction | Communication FINMA 08/2024 ch. 2.4 ; règlement (UE) 2024/1689 art. 14 § 4 d) ; lacunes L-4 et L-6 ; format v0 figé |
| PA-17 | CT-2 (EX-17.5) | Relecture tournante de tous les segments fermés et comparaison à leur copie WORM, chaque segment au moins une fois par période fixée et configurable, résultat dans la ligne `integrity_check` ; CT-2 EX-12.21 annonce une relecture périodique qu'EX-17.5 n'exécute que pour les segments du jour et de l'heure | PFPDT ch. 3.1 let. c ; Olico art. 10 al. 1 ; lacune L-10 |
| PA-19 | CT-5 et CT-1 | En production, chaque clôture DEVRAIT recevoir un second jeton RFC 3161 d'un prestataire d'un autre exploitant, joint au dossier par une partie optionnelle nouvelle, compatible comme `points-de-controle.json` ; CT-6 retiendrait le `genTime` le plus tardif comme borne « au plus tard », si bien qu'un seul prestataire honnête neutralise un antidatage | H4 de CT-6 ; MN-60, RA-54 |
| PA-20 | CT-2 (EX-15.4) | Avec `storage.retention.basis` à `co_958f` (PA-12), refuser `retain_days` sous `365 × (events_years + 1)` au lieu d'un avertissement, pour que les copies WORM couvrent la fin de l'exercice plus dix ans | CO art. 958f al. 1 ; EX-8.16 |

### 8.12 Révision

**EX-8.20 (révision).** La matrice est datée. Chaque version de CT-7 DOIT
relire les textes `vigueur_a_confirmer` et `pas_encore_applicable` et
chercher, pour chaque texte, une version ou une consolidation plus récente ;
une ligne relue prend la nouvelle date dans `read_on`, et une citation qui a
changé change la ligne, son statut et, au besoin, ses lacunes.

## 9. Épreuves à l'aveugle

Trois épreuves vérifient que CT-7 se lit seul. Chacune est passée par une
personne qui n'a lu que ce que l'épreuve nomme, jamais la section 9 ni
l'annexe A.15 ; la consigne lui est remise,
la grille des éléments attendus reste dans un fichier à part, qu'elle ne
reçoit pas (annexe A.15). Une réponse réussit si elle contient tous les
éléments de sa grille.

La grille étant dans CT-7 même, remettre le fichier entier rendrait l'aveugle
impossible. La consigne remet donc au lecteur un extrait de CT-7 dont la
section 9 et l'annexe A.15 sont retirées (EX-9.1, EX-9.2) ; pour EX-9.4, un
extrait réduit à la section 7.

**EX-9.1** **Responsable de la sécurité.** Un responsable de la sécurité qui n'a
que CT-7, sans la section 9 ni l'annexe A.15, reçoit six scénarios d'attaque et
répond, pour chacun, par la réponse (au moins une exigence EX- citée par la
ligne MN- correspondante), la détection et le risque résiduel (identifiant RA-
ou « aucun »). La table ci-dessous est la grille, publiée à part
(`spec/vecteurs/ct-7/acceptation-securite-attendu.json`) ; elle ne lui est pas
remise. L'épreuve réussit si les six réponses
contiennent chacune la menace, une réponse, une détection et le risque
résiduel de la grille.

| Scénario remis | Menace | Éléments attendus |
|---|---|---|
| La graine de la clé de l'enregistreur, gardée en classe C, a pu être lue sur l'hôte | MN-30 | rotation d'urgence (CT-2 EX-11.16) ; ancres extérieures ; rapprochement impossible en classe C ; RA-26 |
| Un agent joint directement un serveur d'outils HTTP sans passer par le mandataire | MN-1 | CT-2 EX-4.1, pare-feu ; journal du pare-feu, essai de sortie (CT-7 EX-3.13) ; RA-1 |
| La console fait signer à un approbateur le condensé d'une autre demande retenue | MN-45 | recalcul et affichage de `D_A`, notification indépendante (CT-3 EX-13.3) ; empreintes de la page (CT-7 EX-3.9) ; RA-41 |
| La clé de gouvernance d'une organisation est volée | MN-37 | classe A à C, cérémonie, sondage des événements du jeu (CT-4 EX-8.12) ; RA-33 |
| Le service d'approbation rend `autorise` pour un appel que la politique soumet à approbation | MN-44 | canal authentifié, intégrité du service (CT-7 EX-3.10) ; réévaluation (CT-3 §6.8) ; RA-40 |
| Un gel juridique est levé par une seule personne | MN-28 | règle de garde (CT-2 EX-12.38), Lecteur hors du démon (CT-2 EX-17.7) ; alerte « Gel non posé sur une version d'un gel actif » ; RA-24 |

**EX-9.2** **Responsable de la conformité.** L'épreuve est passée par une
personne qui n'a lu que CT-7, sans la section 9 ni l'annexe A.15.
`spec/vecteurs/ct-7/acceptation-conformite/consigne.md` lui pose, pour chacun
des cinq passages suivants, trois questions : (a) quelle pièce de NOORTRACE y
répond ou y contribue ; (b) qu'est-ce qui n'est pas couvert ou relève du
client ; (c) quel est le statut de la ligne et le texte s'applique-t-il
aujourd'hui ; puis une sixième : « la matrice dit-elle que votre organisation
est conforme ? ». La grille est la table ci-dessous, que la personne ne
reçoit pas ; `acceptation-conformite-attendu.json` la reproduit et est
produite par le générateur depuis `matrice-conformite.json` :

| Passage | Ligne | Éléments attendus |
|---|---|---|
| OPDo art. 4 al. 5 | MC-17 | (a) conservation au moins dix ans, CT-2 EX-12.19 ; stockage séparé par la copie WORM, si elle est configurée, CT-2 EX-12.16 ; (b) restriction de l'accès et de l'usage : client ; (c) `partiel` (la réponse sur le stockage séparé est sous condition, EX-8.3), en vigueur, sous la condition de l'al. 1 |
| Règlement délégué (UE) 2024/1774, art. 12 § 2 d) | MC-38 | (a) manipulation détectée (hachage, chaînage, signatures, ancres) ; suppression empêchée par les copies WORM si configurées ; contribution du moindre privilège ; (b) contrôle d'accès aux journaux : client ; (c) `partiel`, en vigueur |
| Règlement (UE) 2024/1689, art. 26 § 6 | MC-50 | (a) durée de dix ans au moins ; journaux sur l'infrastructure du client, clause CL-3 ; (b) plancher de dix ans non réductible face à la réserve du droit de la protection des données (L-5) ; période adaptée à la destination, qualité de déployeur : client ; (c) `partiel`, pas encore applicable : 2 décembre 2027 (annexe III), 2 août 2028 (annexe I) |
| Olico art. 9 al. 1 let. b | MC-54 | (a) signature de chaque événement et manifeste, horodatage RFC 3161 et OpenTimestamps ; journal d'exploitation : contribue à ; (b) archivage du journal d'exploitation au-delà de `keep_files` : CT-8 (L-9) ; autres prescriptions du procédé et qualification du journal comme livre : client ; (c) `partiel`, en vigueur |
| DORA art. 30 § 3 e) | MC-33 | (a) clauses CL-1 et CL-2, vérificateur publié ; (b) qualification de la fonction comme critique ou importante, exercice des droits : client ; (c) `partiel`, applicable depuis le 17 janvier 2025 |
| Sixième question | — | non : correspondance technique, pas un avis juridique ; la qualification et la conformité relèvent du client |

**EX-9.3** L'épreuve réussit si chaque réponse contient tous ses éléments ;
une réponse qui dit qu'une ligne `couvert` rend le client conforme, ou qui
présente l'un des art. 12, 14, 19 ou 26 du règlement (UE) 2024/1689 comme
applicable au 2026-10-26 (T-8), échoue quels que soient ses autres éléments.

**EX-9.4** **Administrateur du client.** L'épreuve est passée par une personne
qui n'a lu que la section 7.
`spec/vecteurs/ct-7/acceptation-attestation/consigne.md` lui donne l'attestation
de l'exemple, un dossier `ct-1` avec la partie et son rapport, et six
questions ; la grille, dans `acceptation-attestation-attendu.json`, que la
personne ne reçoit pas, liste les éléments que chaque réponse DOIT contenir :

| Question | Éléments attendus |
|---|---|
| Q1. Quelles pièces rassemblez-vous pour remplir l'attestation ? | `org_id` et `slug` ; `journal_id` de chaque journal ; connexions d'hôte ; `policy.servers` et routes ; export du pare-feu et son SHA-256 ; annuaire des approbateurs ; exceptions connues (7.4, pas 1) |
| Q2. Qui doit signer, et combien ? | des membres du jeu d'approbateurs, nommés dans `signatories`, au moins `required` distincts ; l'administrateur ne compte que s'il est membre (EX-7.8) |
| Q3. Que vérifie un signataire avant de signer ? | il recalcule `D_P` depuis le fichier, lit les membres en clair, ne signe jamais un condensé reçu tout fait ; pas par la console (EX-7.8) |
| Q4. Qu'est-ce qui ne doit jamais figurer dans l'attestation ? | valeurs de secrets, adresses IP, contenu des règles, données personnelles hors identités nommées (EX-7.3) |
| Q5. Que prouve l'attestation vérifiée, et que ne prouve-t-elle pas ? | qui a signé, intégrité du texte, seuil atteint du jeu déclaré, rang d'inscription ; pas l'exactitude du périmètre, pas l'absence de contournement, pas la date de signature (7.8) |
| Q6. Le rapport du dossier fourni dit-il que le périmètre est prouvé ? | non : « déclaré, non prouvé » ; le verdict ne dépend pas de l'attestation (EX-7.1) |

**EX-9.5** L'épreuve réussit si chaque réponse contient tous ses éléments ; une
réponse qui dit l'attestation « preuve du périmètre » ou « preuve de
conformité » échoue, quels que soient ses autres éléments.

## 10. Ce que cette version ne couvre pas

- **La revue de code** de l'enregistreur, du service et de la console : une
  épreuve de CT-9, dont CT-7 fixe le périmètre (composants de 3.2, menaces de
  3.4) ; aucune revue n'a été faite pour cette version.
- **La construction reproductible** de l'image de l'enregistreur et de la
  console : CT-8 (CT-7 EX-3.9 et EX-3.14 n'en exigent que la publication et
  la comparaison des empreintes).
- **Un signal de contrainte** pour un approbateur forcé de signer, et la
  récusation et le retrait signés : propositions de CT-3 §16 pour une version
  1.
- **Des membres de jeu qui ne sont pas des adresses** (CT-3 §16) : le
  procès-verbal ne connaît que des adresses ; une version 1 ajouterait une
  valeur d'`algorithm` à CR-5 et CR-11.
- **Le contrôle multipartite natif des modules** (quorum de cartes, k sur n
  dans le module) : les pages qui le décrivent pour d'autres modules que ceux
  cités ne sont pas lues (R7, section 2, non vérifié) ; CT-7 l'exige par la
  cérémonie (4.5), pas par le module.
- **Les normes payantes** ISO/IEC 27001:2022 (A.8.24, A.8.15), ISO/IEC 11770
  et les rôles de FIPS 140-3 : non lues (non vérifié) ; aucune exigence de
  CT-7 ne s'y fonde.
- **Les rapports d'attestation** SOC 2, SOC 3, ISAE 3000 et ISAE 3402 : leurs
  définitions ne sont pas lues (non vérifié) ; CT-7 n'en dit que ce que la
  déclaration de pratiques citée en R7-F28 dit d'un audit annuel.
- **La portée juridique** d'une déclaration ou d'un procès-verbal signé : non
  recherchée (aucun avis juridique).
- **Les propositions PA-1 à PA-20** (6.2, 6.3, 8.11) : tant qu'elles ne sont
  pas adoptées, les risques acceptés qu'elles réduiraient demeurent (RA-18,
  RA-20, RA-24, RA-25, RA-54, RA-55, RA-66, RA-72, RA-75, RA-80 ; lacunes
  L-1 à L-6, L-9 et L-10 de la matrice).
- **La preuve du périmètre de capture** : l'attestation de périmètre est une
  déclaration signée ; aucune vérification ne prouve que le périmètre est
  exact ni complet (7.8). Seul un essai de sortie mené par le client, au
  mieux par un évaluateur indépendant, s'en approche (EX-3.13).
- **Une norme qui exigerait qu'une passerelle soit seule à détenir les
  identifiants d'API** : aucune n'a été trouvée ; c'est un choix de
  conception de NOORTRACE, fondé sur des contrôles publiés (7.1, R7,
  section 2, non vérifié).
- **Un avis juridique** : la matrice (section 8) établit des correspondances
  techniques ; la qualification d'un client (système d'IA à haut risque,
  entité financière, fonction essentielle externalisée, traitement de données
  sensibles à grande échelle), l'applicabilité de chaque texte et la
  conformité relèvent du client et de ses conseils (NV-8).
- **Les durées de conservation sectorielles** (droit bancaire, droit des
  assurances, LBA) : non recherchées (lacune L-7, NV-6).
- **La vigueur de la circulaire FINMA 2018/3 au 2026-10-26** et une date
  d'application propre du règlement délégué (UE) 2024/1774 : non lues dans
  un acte (lacune L-8, NV-1, NV-5) ; la prochaine révision de CT-7 les relit
  (EX-8.20).

## 11. Alignement avec le dépôt

CT-7 version 0.1 est la première rédaction ; elle ne clôt aucune décision
ouverte de l'architecture. « fait » : livré dans le dépôt, par ce lot de
spécification ou par le lot nommé ; « à faire » : attendu d'un autre lot ou
d'une autre spécification, nommé.

| Emplacement | Attendu par CT-7 0.1 | État |
|---|---|---|
| `spec/CT-1-evenements-et-formats.md`, `spec/CT-6-verificateur.md` | révisions 0.4 et 0.3 : partie facultative `attestation-perimetre.json`, vérifications AT-1 à AT-7, fragment FP, `facts.perimeter`, avertissements AV-AT- | fait |
| `spec/schemas/` | schémas nouveaux `modele-menace-v0`, `ceremonie-cles-v0`, `attestation-perimetre-v0`, `matrice-conformite-v0` ; `dossier-v0` et `rapport-verification-v0` étendus de façon compatible | fait |
| `spec/README.md` | CT-1 version 0.4, CT-6 version 0.3, CT-7 version 0.1 ; schémas nouveaux ; famille `ct-7` | fait |
| `scripts/lib/securite.mjs`, `scripts/verify/ceremonie.mjs`, `scripts/conformite/attestation.mjs`, `scripts/conformite/verifier-renvois.mjs`, `scripts/conformite/matrice-donnees.mjs` | implémentation de référence (annexe A.8 à A.10) | fait (lot de code de CT-7) |
| `scripts/lib/journal.mjs`, `scripts/lib/verificateur.mjs`, `scripts/verify/dossier.mjs` | quatorzième partie, AT-1 à AT-7 sans effet sur le verdict, FP, `facts.perimeter`, dix schémas | fait (lot de code de CT-7) |
| `scripts/vecteurs/generer-ct7.mjs`, `spec/vecteurs/ct-7/` ; dossiers nouveaux de `ct-1` et `ct-6` | vecteurs de l'annexe A, deux générations identiques | fait (lot de code de CT-7) |
| `spec/vecteurs/ct-7/verificateur-independant/` ; vérificateurs Go de `ct-1` et de sa copie de `ct-2` | vérificateur indépendant (A.12) | fait (lot de code de CT-7) |
| `spec/vecteurs/ct-7/confrontation/` ; `test/securite.test.js`, `test/conformite.test.js`, `test/confrontation.test.js` ; `.github/workflows/ci.yml` ; `package.json` | confrontation tierce, tests et intégration continue (A.11, A.13, A.14) | fait (lot de code de CT-7) |
| CT-2 | propositions PA-1 à PA-6, PA-8 à PA-13, PA-16 à PA-18 et PA-20 (6.2, 8.11) | à faire (révision de CT-2 à décider) |
| CT-1 version 1 ; CT-4 ; CT-5 ; CT-8 | propositions PA-7, PA-16, PA-19 ; PA-14 ; PA-13, PA-19 ; PA-15 | à faire (révisions à décider ; CT-8 à écrire) |
| `README.md`, `README.fr.md`, `ARCHITECTURE.md`, `CHANGELOG.md` | mention de CT-7 0.1 : modèle de menace, clés, cérémonie et procès-verbal, journal sur soi, attestation de périmètre déclarative, matrice de conformité présentée comme correspondance technique | à faire (alignement des documents racine) |

## Annexe A — Vecteurs, implémentation, intégration continue

### A.1 Principes

**EX-A.1** Les vecteurs de CT-7 sont produits par
`scripts/vecteurs/generer-ct7.mjs` (`npm run vecteurs:ct7`) sous
`spec/vecteurs/ct-7/`. Tout est déterministe : deux générations successives
donnent des fichiers identiques octet pour octet. Les clés de test sont la
clé Ed25519 `rec-test-01` de CT-1 §13 et les comptes Hardhat dérivés du
mnémonique public de `spec/vecteurs/ct-3/constantes.json` (chemin
`m/44'/60'/0'/0/i`, i = 1 à 8), lus et jamais réécrits ; les autres
empreintes (script, image du poste, enregistrements, preuves d'origine)
sont le SHA-256 d'étiquettes `noortrace/vecteurs/ct7/…`. Les vecteurs de
CT-2, CT-3, CT-4 et CT-5 et leurs générateurs ne changent pas ; ceux de CT-1
et CT-6 ne reçoivent, pour ce lot, que les dossiers nouveaux de
l'attestation (A.7).

Les vecteurs de l'attestation sont produits par
`scripts/vecteurs/generer-ct7.mjs` (`npm run vecteurs:ct7`) avec la
bibliothèque de référence `scripts/lib/securite.mjs`, rejoués à l'identique
par `test/securite.test.js`, confrontés par le vérificateur Go indépendant
`spec/vecteurs/ct-7/verificateur-independant` et, pour les signatures, par
deux bibliothèques tierces (A.13). Tout est déterministe : comptes Hardhat
1 à 4 des vecteurs de CT-3 (clés publiques, sans valeur), signatures
RFC 6979, horodatages fixes, `rules_sha256` dérivé d'une étiquette.

**EX-A.2** Deux exécutions du générateur produisent des fichiers
identiques octet pour octet ; la CI régénère `spec/vecteurs/ct-7` et exige
un `git diff` vide.

**EX-A.3** Le générateur de CT-7 ne réécrit aucun fichier de `ct-1` à
`ct-6`. Les dossiers nouveaux de A.7 sont produits par les générateurs de
leur famille, `scripts/vecteurs/generer-ct1.mjs` et
`scripts/vecteurs/generer-ct6.mjs`, avec `scripts/lib/securite.mjs` ; ils
ne changent aucun fichier existant de ces familles, sauf `INDEX.md`. Les
vecteurs de `ct-2` à `ct-5` et leurs générateurs ne changent pas.

### A.2 Disposition

| Répertoire ou fichier | Contenu | Résultat attendu |
|---|---|---|
| `ct-7/menaces.json` | Le modèle de menace (3.8), tiré des tables de 3.2 à 3.5 | RV-1 à RV-6, RV-8 |
| `ct-7/ceremonies/<cas>/proces-verbal.json`, `attendu.json` | Procès-verbaux valides et invalides (A.4) ; `attendu.json` valide contre `ceremonie-cles-v0#/$defs/attendu` | verdict, `D_C`, vérifications en échec et non exécutées, signataires |
| `ct-7/cles-de-test.json` | Clés publiques et adresses publiées par les vecteurs (EX-4.10), schéma `ceremonie-cles-v0#/$defs/cles_de_test` | égalité avec les clés recalculées |
| `ct-7/acceptation-securite/` et `ct-7/acceptation-securite-attendu.json` | Consigne et scénarios de l'épreuve de EX-9.1 ; la grille à part (`modele-menace-v0#/$defs/grille_securite`) | les six réponses contiennent leurs éléments |
| `ct-7/confrontation/ceremonies/` | Programmes et sorties publiées : recouvrement des signatures des procès-verbaux par ethers et par eth-account 0.14.0 ; jamais écrit par le générateur | aucune discordance |
| `ct-7/verificateur-independant/` | Vérificateur Go écrit depuis le seul texte de CT-7 (et CT-1 §6.3 pour EIP-191), module séparé, partagé avec l'attestation | zéro discordance |
| `ct-7/attestations/constantes.json` | `P_P` en hexadécimal, comptes et adresses, `org_id`, `journal_id` des deux journaux, étiquette de `rules_sha256` | égalité des dérivations |
| `ct-7/attestations/exemple/` | `attestation.json` (l'exemple de 7.1), `jcs.txt` (`JCS(P)`, 3201 octets), `condense.json` (`D_P`, `M`, signatures des comptes 1 et 2), `attestation-signee.json`, `jeu.json` | égalité avec 7.2 |
| `ct-7/attestations/attestations.json` | cas valides et invalides hors dossier (schéma `attestation-perimetre-v0#/$defs/fichier_vecteurs`) | `digest`, adresses recouvrées, statuts de AT-1 à AT-4, `retained` |
| `ct-7/attestations/croises.json` | signatures croisées entre `D_P`, `D_A`, texte d'inscription de CT-3, procès-verbal de cérémonie et condensés du registre (EX-7.7) ; schéma `attestation-perimetre-v0#/$defs/croises` | chaque signature croisée refusée |
| `ct-7/acceptation-attestation/` et `ct-7/acceptation-attestation-attendu.json` | épreuve de lecture de l'administrateur (section 9, EX-9.4) ; la grille dans un fichier à part (`attestation-perimetre-v0#/$defs/grille_attestation`) ; `rapport.txt`, sortie de `node scripts/verify/dossier.mjs` sur `ct-1/dossiers/valide-seq-12-attestation-inscrite`, sans les lignes qui commencent par « Vérificateur : » et « Répertoire : », qui dépendent de la machine | chaque réponse contient tous ses éléments |
| `ct-7/confrontation/attestations/` | programmes et sorties publiées d'ethers et d'eth-account 0.14.0 (A.13) | aucune discordance |
| les dossiers d'EX-A.10 dans `ct-1/dossiers/` et `ct-6/dossiers/` | dossiers nouveaux avec la partie `attestation-perimetre.json` (A.7) | verdict, statuts AT-, avertissements, énoncé |
| `ct-7/matrice-conformite.json` | la matrice (section 8) | MX-1 à MX-9 réussies |
| `ct-7/matrice/invalides/<cas>.json` | la matrice altérée en un point (A.8) | les MX- listées en échec |
| `ct-7/matrice/invalides/attendu.json` | pour chaque cas, la liste exacte des MX- en échec (`matrice-conformite-v0#/$defs/cas_invalides_matrice`) | égalité |
| `ct-7/acceptation-conformite/consigne.md` | consigne de l'épreuve du responsable de la conformité (section 9, EX-9.2) | — |
| `ct-7/acceptation-conformite-attendu.json` | grille de l'épreuve, hors du répertoire remis (`matrice-conformite-v0#/$defs/grille_conformite`) | chaque réponse contient ses éléments |
| `ct-7/INDEX.md` | Index généré : chaque cas et son attendu ; la consolidation ligne par ligne | — |

### A.3 `menaces.json`

**EX-A.4** Le texte de CT-7 est la source : le générateur lit la table des
composants (3.2), la table de consolidation (3.3), la table des menaces (3.4)
et celle des risques acceptés (3.5) dans `spec/CT-7-securite-et-conformite.md`
et écrit `menaces.json` (`refs` extraits du texte par l'expression de RV-4 ;
menaces dans l'ordre de la table 3.4 ; `sources` d'une menace dans l'ordre de
la table de rattachement de 3.3 ; mise en forme `JSON.stringify(objet, null,
2)` suivie d'un saut de ligne).
`source_tables` est recalculé depuis les tables sources des spécifications
citées. Un écart entre le texte et le fichier publié est donc une génération
non faite, que l'intégration continue voit (EX-A.26).

**EX-A.5** Le générateur refuse d'écrire (code non nul) si RV-2, RV-3, RV-4,
RV-6 ou RV-8 échoue.

### A.4 `ceremonies/`

**EX-A.6** Chaque cas est un répertoire qui contient `proces-verbal.json` (le
fichier vérifié, octets exacts) et `attendu.json`
(`ceremonie-cles-v0#/$defs/attendu`). Un cas invalide est construit depuis un
cas valide par une seule mutation, puis signé de nouveau par tous ses
participants (sauf quand la mutation porte sur les signatures), de sorte que
seule la vérification visée échoue, sauf quand la mutation rend une autre
vérification impossible à satisfaire, ce que la table nomme (une cérémonie à un
participant ne peut avoir de témoin : CR-4). Cas publiés, au moins :

| Cas | Mutation | Vérifications en échec |
|---|---|---|
| `valide-creation-enregistreur` | — (exemple de 5.10) | — |
| `valide-inscription-membres` | production ; officiant et témoin (comptes 1 et 2), membres (comptes 5 et 6), clés `approbateur` réduites à l'adresse, vidéo | — |
| `valide-sauvegarde-administrateur-registre` | portée `exploitant`, `org_id` nul ; clé `administrateur_registre` de classe A et clé `enveloppe`, partage 2 sur 3 (détenteurs : comptes 5 à 7) | — |
| `valide-changement-administrateur` | membres présents du jeu (comptes 1 et 2), nouvelle clé `gouvernance` de classe A, officiant de l'exploitant (compte 8) | — |
| `valide-developpement-classe-d` | développement, clé `enregistreur` de classe D, script sans empreinte, sans vidéo ni auditeur | — |
| `valide-restauration-administrateur-registre` | portée `exploitant` ; restauration de la clé `administrateur_registre` sauvegardée par `valide-sauvegarde-administrateur-registre` (`backup_ceremony_digest` = son `D_C`, partage 2 sur 3) ; deux détenteurs de part présents | — |
| `valide-rotation-urgence-chaine` | rotation d'urgence de la clé de chaîne ; `decided_at` avant `revocation_included_at` | — |
| `invalide-cr1-cle-en-double` | texte JSON avec une clé en double | CR-1 (et CR-2 à CR-12 non exécutées) |
| `invalide-cr1-nombre-non-entier` | `version` vaut `0.0` | CR-1 |
| `invalide-cr1-schema` | membre `place` retiré | CR-1 |
| `invalide-cr2-un-seul-participant` | seul l'officiant | CR-2, CR-4 (une seule personne ne peut témoigner d'aucune étape) |
| `invalide-cr2-deux-officiants` | le témoin devient officiant (un second témoin ajouté) | CR-2 |
| `invalide-cr2-adresse-en-double` | l'auditeur a l'adresse du témoin | CR-2 |
| `invalide-cr2-auditeur-executant` | une étape exécutée par l'auditeur | CR-2 |
| `invalide-cr3-etape-avant-le-debut` | `at` de la première étape avant `started_at` | CR-3 |
| `invalide-cr3-numerotation` | deux étapes de même `n` | CR-3 |
| `invalide-cr4-temoin-de-lui-meme` | l'officiant parmi les témoins de son étape | CR-4 |
| `invalide-cr4-exception-sans-constat` | `findings` vide | CR-4 |
| `invalide-cr4-temoin-auditeur-seul` | une étape témoignée par le seul auditeur | CR-4 |
| `invalide-cr5-empreinte-fausse` | `fingerprint` de la clé Ed25519 changé | CR-5 |
| `invalide-cr5-adresse-de-chaine` | `address` de la clé de chaîne remplacée | CR-5 |
| `invalide-cr5-ed25519-33-octets` | clé Ed25519 de 33 octets | CR-5 |
| `invalide-cr6-classe-d-en-production` | clé `enregistreur` en classe D | CR-6 |
| `invalide-cr6-administrateur-registre-classe-b` | clé `administrateur_registre` en classe B | CR-6 |
| `invalide-cr7-sauvegarde-enregistreur` | partage 2 sur 2 de la clé `enregistreur` | CR-7 |
| `invalide-cr7-k-superieur-a-n` | `k = 3`, `n = 2` | CR-7 |
| `invalide-cr8-membre-sans-cle` | un `membre` sans clé `approbateur` | CR-8 |
| `invalide-cr9-sans-video-ni-auditeur` | production sans vidéo ni auditeur | CR-9 |
| `invalide-cr9-poste-en-ligne` | clé `generated_in: "poste"`, `offline` faux | CR-9 |
| `invalide-cr10-incident-sans-resolution` | constat `incident`, `resolution` nulle | CR-10 |
| `invalide-cr11-signature-manquante` | une signature retirée | CR-11 |
| `invalide-cr11-autre-proces-verbal` | une étape modifiée après signature | CR-11 |
| `invalide-cr11-s-haut` | une signature en forme `s` haut | CR-11 |
| `invalide-cr11-signature-d-une-decision` | le témoin a signé le `D_A` de la décision `apr-1192` de CT-1 §6.4 au lieu de `D_C` | CR-11 |
| `invalide-cr11-signataire-substitue` | la signature du témoin faite par un autre compte | CR-11 |
| `invalide-cr12-details-inattendus` | `purpose_details` non nul pour l'objet `creation` | CR-12 |
| `invalide-cr12-creation-sans-cle` | objet `creation` sans clé | CR-12 |
| `invalide-cr12-restauration-sans-detenteur` | restauration 2 sur 3 avec un seul participant `detenteur_part` | CR-12 |
| `invalide-cr12-urgence-ordre` | `decided_at` après `revocation_included_at` | CR-12 |
| `invalide-cr12-administrateur-sous-seuil` | changement d'administrateur avec un membre présent pour `required` = 2 | CR-12 |

### A.5 `cles-de-test.json` et `INDEX.md`

**EX-A.7** `cles-de-test.json` liste, par source (`ct-1`, `ct-3`, `ct-4`,
`ct-6`), chaque clé publique de test publiée par les vecteurs, sa forme
(`ed25519`, `secp256k1` avec adresse, `rsa` avec SHA-256 du
`SubjectPublicKeyInfo`) et son étiquette ou son chemin de dérivation ; il est
recalculé par le générateur depuis les fichiers de clés des vecteurs, lus et
jamais réécrits. `INDEX.md` liste chaque cas de `ceremonies/` avec son
attendu, et la table de consolidation de 3.3.

### A.6 Cas hors dossier (`attestations.json`, `croises.json`)

**EX-A.8** `attestations.json` porte au moins les cas suivants ; chaque
cas invalide ne change qu'un élément de l'exemple, et son `expected` donne
la liste exacte des statuts de AT-1 à AT-4 (une AT- non exécutée porte
`prerequis_en_echec`) ; `retained` vaut vrai si et seulement si AT-1 à AT-4
réussissent (schéma `attestation-perimetre-v0`) :

| Cas | Altération | AT- en échec |
|---|---|---|
| `valide-deux-signatures` | l'exemple de 7.2, comptes 1 et 2, jeu de 3 au seuil de 2 | aucun |
| `valide-trois-signatures` | le compte 3 signe aussi | aucun |
| `valide-seuil-un` | jeu `{ required: 1, size: 3 }`, une signature | aucun |
| `invalide-at1-membre-en-trop` | membre inconnu dans `P` | AT-1 |
| `invalide-at1-validite-inversee` | `validity.from` après `validity.until` | AT-1 |
| `invalide-at1-validite-trop-longue` | `validity.until` = `2027-11-02T00:00:00.001Z`, plus de 366 jours après `validity.from` | AT-1 |
| `invalide-at1-date-inexistante` | `validity.until` = `2027-02-30T00:00:00.000Z` | AT-1 |
| `invalide-at1-agent-journal-inconnu` | `journal_id` d'un agent absent de `journals` | AT-1 |
| `invalide-at1-signataires-en-double` | deux entrées de `signatories` de même adresse | AT-1 |
| `invalide-at1-nombre-non-entier` | `version` vaut `0.0` dans le texte JSON | AT-1 |
| `invalide-at2-condense-faux` | `digest` d'une autre attestation | AT-2 |
| `invalide-at3-signature-substituee` | signature du compte 3 déclarée pour le compte 2 (7.2) | AT-3 |
| `invalide-at3-s-haut` | signature du compte 2 en forme non canonique (`s` haut, `v` complémenté) | AT-3 |
| `invalide-at3-v-hors-domaine` | `v` = `0x00` | AT-3 |
| `invalide-at4-seuil-non-atteint` | une seule signature pour un seuil de 2 | AT-4 |
| `invalide-at4-non-membre` | signature valide du compte 4, nommé dans `signatories`, absent du jeu | AT-4 |
| `invalide-at4-hors-signataires` | signature valide du compte 3, membre du jeu, absent de `signatories` | AT-4 |
| `invalide-at4-adresse-en-double` | la même signature deux fois | AT-4 |
| `invalide-at4-seuil-incoherent` | `required` = 4 pour `size` = 3 | AT-4 |

**EX-A.9** `croises.json` porte, pour le compte 1 : sa signature de
`D_A` du ticket `apr-1192` de CT-1 (§6.4), du texte d'inscription de
CT-3 §13.5 (exemple de CT-3), d'un procès-verbal de cérémonie des vecteurs
de CT-7 (A.4) et de `periodDigest` d'une clôture des vecteurs de
CT-4, chacune présentée comme signature de l'attestation de l'exemple
(AT-3 `echoue`, adresse recouvrée attendue donnée) ; et sa signature de
`D_P` présentée comme signature de `D_A`, du texte d'inscription et du
procès-verbal (refusée par E-9 de CT-1, AN- de CT-3, CR- de CT-7).

### A.7 Dossiers avec la partie (familles de CT-1 et de CT-6)

**EX-A.10** Les dossiers nouveaux portent la partie
`attestation-perimetre.json` en quatorzième position (CT-1 §11.1, révision
0.4) et un `attendu.json` qui donne, en plus de l'attendu habituel, le
statut et la raison de AT-1 à AT-7, les avertissements AV-AT- et, pour CT-6,
l'énoncé complet avec son fragment FP. Les clés de l'`attendu.json` de `ct-1`
(`perimeter_target`, `perimeter_checks`, `perimeter_retained`, `warnings`) sont
définies par CT-1 §11.5 (révision 0.4). Au moins :

| Famille | Dossier | Construction | Attendu |
|---|---|---|---|
| `ct-1` | `valide-seq-12-attestation-inscrite` | journal rejoué de 7.5 (seq 12 inscrit `D_P`) ; dossier de seq 12 ; partie avec inscription | valide ; AT-1 à AT-7 réussies |
| `ct-1` | `valide-seq-7-attestation-sans-inscription` | `valide-seq-7` de CT-1 et la partie sans inscription, point de contrôle déclaré absent | valide ; AT-6, AT-7 `non_execute` (`partie_absente`) |
| `ct-1` | `valide-seq-7-attestation-declaree-absente` | quatorze parties, la quatorzième absente avec la raison « aucune attestation de périmètre » | valide ; aucune AT- au rapport ; la partie dans `absent_parts` |
| `ct-1` | `valide-seq-13-at7-autre-version` | journal rejoué prolongé d'un seq 13 `noortrace.journal.politique` d'une autre version, sans `perimeter` ; dossier de seq 13, inscription seq 12 | valide ; AT-7 `non_execute` (`piece_hors_dossier`), AV-AT-3 ; attestation retenue, FP « sans preuve qu'elle était en vigueur pour cet événement » |
| `ct-1` | `valide-at7-nom-reannonce` | journal rejoué prolongé d'un seq 13 qui réannonce le nom de version `2026-11-05` avec un autre document, sans `perimeter` ; dossier de seq 13, inscription seq 12 | valide ; AT-6 et AT-7 réussies (noms seulement) ; FP « de même nom », jamais « en vigueur » (MN-91) |
| `ct-1` | `valide-at7-attestation-remplacee` | journal rejoué prolongé d'un seq 13 qui inscrit une attestation B sous la version `2026-11-06` ; dossier de seq 13 qui joint l'attestation A et son inscription seq 12 | valide ; AT-7 `non_execute` (`piece_hors_dossier`), AV-AT-3 ; FP « sans preuve qu'elle était en vigueur » |
| `ct-1` | `valide-at1-partie-nulle` | partie réduite au littéral `null`, index recalculé | valide ; AT-1 `echoue`, AT-2 à AT-7 `non_execute` (`prerequis_en_echec`), AV-AT-1 |
| `ct-1` | `valide-at1-taille` | partie de 4 Mio plus un octet, conforme à son schéma, complétée par des espaces de mise en forme (CT-6 EX-4.15) | valide ; AT-1 `echoue`, AT-2 à AT-7 `non_execute` (`prerequis_en_echec`), AV-AT-1 |
| `ct-1` | `valide-at2-condense-faux` | `digest` d'une autre attestation | valide ; AT-2 `echoue`, AT-6 et AT-7 `non_execute` (`partie_absente`, qui l'emporte), AV-AT-1 |
| `ct-1` | `valide-at3-signature-substituee` | partie du cas de A.6 | valide ; AT-3 `echoue`, AT-4 `non_execute`, AV-AT-1 |
| `ct-1` | `valide-at4-jeu-different` | dossier `valide-seq-7` (`approbations.json` présent) ; `approver_set` de la partie = comptes 1, 2 et 4 | valide ; AT- réussies (sauf AT-6, AT-7 `partie_absente`), AV-AT-2 |
| `ct-1` | `valide-at4-seuil-non-atteint` | une seule signature pour un jeu déclaré au seuil de 2 | valide ; AT-4 `echoue`, AV-AT-1 |
| `ct-1` | `valide-at5-autre-journal` | attestation qui ne couvre que `journal-principal` | valide ; AT-5 `echoue`, AV-AT-1 |
| `ct-1` | `valide-at5-hors-validite` | validité du 1er au 4 novembre 2026, événement du 5 | valide ; AT-5 `echoue`, AV-AT-1 |
| `ct-1` | `valide-at6-inscription-posterieure` | dossier de seq 11 du journal rejoué, inscription seq 12 | valide ; AT-6 `echoue`, AT-7 `non_execute` (`prerequis_en_echec`), AV-AT-1 |
| `ct-1` | `valide-at6-document-autre-condense` | document de politique dont `attestation_digest` est un autre condensé, événement rescellé en conséquence | valide ; AT-6 `echoue` |
| `ct-1` | `valide-at6-inscription-signature-fausse` | événement d'inscription signé par `rec-test-01` alors qu'il nomme `rec-test-02` | valide ; AT-6 `echoue` |
| `ct-1` | `valide-at6-cle-non-ancree` | `cles.json` augmenté d'une clé `rec-forge-01` que l'exportateur génère (graine : SHA-256 de `noortrace/vecteurs/ct7/rec-forge-01`) ; inscription forgée seq 2 signée par elle | valide ; AT-6 `non_execute` (`ancre_absente`), AT-7 `non_execute` (`prerequis_en_echec`) ; attestation retenue sans inscription reliée (MN-90) |
| `ct-1` | `invalide-d2-attestation-sha256` | `sha256` de la partie remplacé dans l'index | invalide ; D-2 seule en échec (l'index n'est plus celui de l'exportateur, CT-1 §11.4) |
| `ct-1` | `invalide-e1-attestation-non-executee` | `evenement.json` de `valide-seq-7-attestation-sans-inscription` avec un membre hors schéma | invalide (E-1, E-7, E-8, C-2, M-1) ; AT-5 `non_execute`, aucune AT- en échec ; AV-AT-1 nomme AT-5 |
| `ct-6` | `valide-seq-7-complet-attestation` | `valide-seq-7-complet` et la partie sans inscription, point de contrôle déclaré absent | valide ; huit contrôles inchangés ; énoncé = celui de `valide-seq-7-complet` avec FP et sa clause « non inscrite au journal » |
| `ct-6` | `valide-seq-7-complet-attestation-non-retenue` | même, signature substituée | valide ; mêmes statuts de contrôles ; FP « non retenue » ; AV-AT-1 |
| `ct-6` | `valide-seq-7-complet-attestation-cle-non-ancree` | `valide-seq-7-complet-attestation` avec l'inscription forgée de `valide-at6-cle-non-ancree` | valide ; huit contrôles inchangés ; AT-6 `non_execute` (`ancre_absente`) ; FP sans inscription reliée |
| `ct-6` | `valide-point-de-controle-complet-attestation` | `valide-point-de-controle-complet` et la partie | valide ; FK puis FP |
| `ct-6` | `invalide-t6-signature-attestation` | `invalide-t6-signature` et une attestation retenue | invalide ; énoncé d'EX-6.9 sans FP ; `facts.perimeter` gardé pour le diagnostic |

**EX-A.11** Les dossiers de CT-1 et de CT-6 antérieurs à ce lot gardent
leur `attendu.json` ; leur rapport ne diffère que par `facts.perimeter`
(`null`) et par la liste des schémas de `verifier.schemas` (CT-6 EX-6.21).

### A.8 Matrice de conformité : vérifications MX- et cas invalides

`spec/vecteurs/ct-7/matrice-conformite.json` est écrit par
`scripts/vecteurs/generer-ct7.mjs` (`npm run vecteurs:ct7`) depuis une seule
source de données, `scripts/conformite/matrice-donnees.mjs`, qui porte les
textes, les lignes, les clauses et les lacunes tels que la section 8 les
publie ; les citations y sont recopiées du fichier, jamais retapées. Les
tables de CT-7 ne sont pas générées dans la spécification : MX-8 les
compare au fichier.

**EX-A.12** Deux exécutions du générateur écrivent un
`matrice-conformite.json` identique octet pour octet
(`JSON.stringify(objet, null, 2)` suivi d'un saut de ligne) ; l'intégration
continue régénère `spec/vecteurs/ct-7` et exige un diff vide.

| Id | Vérification |
|---|---|
| MX-1 | Le fichier est conforme à `matrice-conformite-v0` (c'est RV-1 pour ce fichier). |
| MX-2 | Identifiants uniques et numérotés 1 à n dans l'ordre du fichier : T-, MC-, CL-, L- ; chaque `text` d'une ligne existe ; `source_url`, `read_on` et `applicability` d'une ligne égalent `url`, `read_on` et `applicability.status` de son texte. |
| MX-3 | Le statut recalculé selon EX-8.3 égale `status`, pour chaque ligne. |
| MX-4 | Chaque pièce existe (c'est RV-3 pour ce fichier) : `exigence` définie en gras (`**EX-s.k**` ou `**EX-s.k (`) dans la spécification `spec` ; `verification` première cellule d'une ligne de la table de CT-1 §11.4 (CT-1) ou d'une table de vérifications de CT-6 ; `controle` de 1 à 8 ; `partie` dans l'énumération des noms de parties de `dossier-v0` ; `section` titre de niveau 2 à 4 de la spécification ; `clause` sous-section `CL-n` de l'annexe C de CT-7. |
| MX-5 | `clauses[].serves` égale la liste, dans l'ordre des lignes, des lignes dont un élément cite la clause ; chaque clause sert au moins une ligne ; chaque sous-section de l'annexe C a sa clause, même identifiant et même titre. |
| MX-6 | Chaque lacune nomme des lignes existantes et une règle `EX-8.k` définie dans CT-7 ; chaque ligne dont un élément `ne_couvre_pas` cite une pièce de CT-7 est nommée par au moins une lacune. |
| MX-7 | Hors de `warning`, aucune chaîne du fichier ne contient, sans tenir compte de la casse, « est conforme », « sont conformes », « garantit la conformité », « certifi » ni « avis juridique » ; chaque `quote` est non vide, ne contient pas « ... », et ses coupes s'écrivent « […] ». |
| MX-8 | Les tables de CT-7 égalent le fichier, cellule par cellule, après retrait des espaces de fin (un `|` d'une valeur s'écrit `\|` dans la cellule) : 8.2 (textes), 8.4 (lignes), 8.9 (lacunes), annexe C (table des clauses). Mise en forme : voir ci-dessous. |
| MX-9 | Un texte `pas_encore_applicable` a au moins une date `from`, et chacune de ses dates `from` est postérieure à `date` ; chaque fait de `facts` figure dans la table des faits de l'annexe B de CT-7. |

Mise en forme des cellules (MX-8). Table 8.4 : « Ligne » = `id` ;
« Texte » = `text`, une virgule, une espace, `applicability` entre accents
graves ; « Référence » = `reference` ; « Citation exacte (fait) » = « `quote` »
entre guillemets français, une espace, `facts` joints par « , » entre
parenthèses ; « Ce qui est exigé » = `requirement` ; « Pièce NOORTRACE » =
les éléments `repond_a` et `contribue_a`, dans l'ordre du fichier, chacun
écrit « répond à : » ou « contribue à : », `element`, ` (condition)` si
`condition` n'est pas nul, puis « — » et les pièces jointes par « , » ;
« Ne couvre pas » et « Relève du client » = les éléments de cette relation,
même forme sans préfixe ; plusieurs éléments sont joints par « ; » ; une
cellule vide s'écrit « — » ; « Statut » = `status`. Une pièce s'écrit
« CT-6 contrôle n » (`controle`), « CT-1 partie `nom` » (`partie`), sinon
« `spec` `ref` ». Table 8.2 : `id`, `source`, `title`, `nature` entre accents
graves, `version`, `addressee`, `applicability.status` entre accents graves
suivi, s'il y a des dates, de « : » et des « à partir du `date` (`scope`) »
joints par « ; », puis `note` (« — » si nul). Table 8.9 : `id`, `title`,
`rows` joints par « , », `response` entre accents graves, `bound`, `owner`,
« CT-7 » et `rule`. Table des clauses : `id`, `title`, `serves` joints par
« , ».

**EX-A.13** `scripts/conformite/verifier-renvois.mjs` exécute MX-1 à MX-9 sur
`matrice-conformite.json` et sur le texte de CT-7, en plus de RV-1 à RV-9 ; il
imprime toutes les erreurs et sort avec un code non nul si l'une échoue. Il est
lancé par `npm test` et par l'intégration continue ; la commande ne prend aucun
argument (code 2 sinon). Sur chaque cas de A.8, sa fonction `verifierMatrice`,
que rejoue `test/conformite.test.js`, échoue exactement aux MX- de
`attendu.json`.

**EX-A.14** Chaque cas ne change qu'un point de la matrice publiée. MX-8,
qui compare le fichier publié aux tables de CT-7, ne s'exécute pas sur les
cas :

| Cas | Altération | MX- en échec |
|---|---|---|
| `statut-force` | MC-57 passe de `couvert` à `partiel` | MX-1, MX-3 |
| `couvert-avec-contribution` | MC-1 passe à `couvert` | MX-1, MX-3 |
| `renvoi-inexistant` | une pièce de MC-17 devient `CT-2 EX-12.999` | MX-4 |
| `section-inexistante` | la pièce `CT-2 §12.8` de MC-56 devient `CT-2 §12.99` | MX-4 |
| `clause-orpheline` | la clause CL-5 n'est plus citée par aucune ligne, `serves` inchangé | MX-5 |
| `lacune-ligne-inconnue` | L-1 nomme `MC-99` | MX-6 |
| `mot-interdit` | le `requirement` de MC-57 se termine par « : le client est conforme » | MX-7 |
| `ia-sans-date` | `from` de T-8 devient `[]` | MX-1, MX-9 |
| `texte-inconnu` | MC-42 porte `text: "T-11"` | MX-2 |
| `fait-hors-annexe` | MC-1 cite `R6-F99` | MX-9 |
| `lignes-permutees` | les lignes MC-25 et MC-26 échangent leur place | MX-2 |
| `ia-date-passee` | `from` de T-8 reçoit en tête une date passée, `2026-08-02` | MX-9 |

### A.9 Implémentation de référence

**EX-A.15** `scripts/lib/securite.mjs` (module ECMAScript sans dépendance hors
du dépôt et de `node_modules`) exporte, pour la cérémonie : `PREFIXE_CEREMONIE`
(`"noortrace/ceremonie-cles/v0\n"`), les tables de 4.3, 4.4 et CR-5
(`ALGORITHME_PAR_USAGE`, `CLASSES_ADMISES_PRODUCTION`, `SAUVEGARDE_PAR_USAGE`),
`condenseCeremonie(pv)` (`D_C` en hexadécimal `0x`, sur le procès-verbal privé
de `signatures`), `signerCeremonie(pv, cles)` (rend le procès-verbal avec ses
signatures, EX-5.7) et `verifierCeremonie(octets, { schema })` (rend
`{ verdict, digest, statuses, failed, not_executed, signers }`, chaque statut
avec son détail, EX-5.9 ; `schema` facultatif) ; et, pour le modèle de
menace, `refsDe(texte)`, `lireTablesCt7(texte)` et `construireMenaces(...)`,
qu'emploient le générateur et le vérificateur de renvois. La forme JCS v0
est celle de `scripts/lib/journal.mjs` ; Keccak-256 et le recouvrement
secp256k1 sont ceux de `scripts/lib/console.mjs`.

**EX-A.16** `scripts/verify/ceremonie.mjs <fichier> [--json] [--condense]` :
vérifie un procès-verbal hors ligne (EX-5.9) ; codes de retour 0 (valide), 1
(invalide), 2 (fichier absent, illisible ou de plus de 1 Mio) ; `--condense`
imprime `D_C` seul, pour le participant qui le recalcule avant de signer
(EX-5.8) ; `--json` imprime le rapport (`#/$defs/attendu` plus les statuts).

**EX-A.17 (bibliothèque).** `scripts/lib/securite.mjs` exporte, pour
l'attestation : `PREFIXE_ATTESTATION`, `condenseAttestation(P)`,
`messageAttestation(D_P)`, `signerAttestation(wallet, P)`,
`assemblerAttestation(P, signatures)`, `verifierAttestation(signee, jeu,
{ brut, schemas } = {})` (AT-1 à AT-4 ; rend `{ digest, recovered, checks,
retained, details }`, forme de `$defs/cas_attestation.expected` plus
`details`) et `verifierPartieAttestation({ octets, inexploitable, evenement,
cles, approbations, schemas })` (AT-1 à AT-7 dans un dossier, détails
`{ fr, en }`) ; `scripts/lib/journal.mjs` et `scripts/verify/dossier.mjs`
l'emploient pour la partie (CT-1 révision 0.4, CT-6 révision 0.3).
L'outil `scripts/conformite/attestation.mjs` (`gabarit`, `condenser`,
`signer`, `assembler`, `verifier`) suit 7.4 ; il n'ouvre aucune connexion.

### A.10 Vérificateur de renvois

**EX-A.18** `scripts/conformite/verifier-renvois.mjs` exécute RV-1 à RV-9 et
sort avec un code non nul à la première vérification en échec, après avoir
imprimé toutes les erreurs. Il ne prend aucun argument : tout argument rend le
code 2. Il est lancé par `npm test` (par `test/securite.test.js`) et par
l'intégration continue.

| Id | Vérification |
|---|---|
| RV-1 | `menaces.json` est conforme à `modele-menace-v0` ; `matrice-conformite.json` à `matrice-conformite-v0` (section 8). |
| RV-2 | Chaque menace a `response.refs` non vide ou `residual.accepted_risk` non nul ; `test` commence par le préfixe fixe ; les identifiants MN- et RA- sont uniques et numérotés sans trou : l'ensemble des numéros est {1..n}, quel que soit l'ordre dans le fichier (la table 3.4 est groupée par composant) ; chaque RA- est rattaché à une seule menace ; `owner` est dans l'énumération. |
| RV-3 | Chaque renvoi existe : `CT-n EX-s.k` est défini en gras (`**EX-s.k**` ou `**EX-s.k (`) dans la spécification `n` ; `CT-n §s` est le numéro d'un titre de niveau 2 à 4 ; `CT-n XX-k` est la première cellule d'une ligne de table ; pour `CT-7`, dans CT-7 lui-même. Sont contrôlés les renvois de `menaces.json`, ceux de `matrice-conformite.json` et la colonne « Réponse de CT-7 » de la table 0.2. Pour cette colonne, un EX- ou un identifiant d'une famille de CT-7 (CLE-, CR-, JS-, PA-, MN-, RA-, MC-, CL-, RV-, MX-, TR-) sans « CT-n » devant se lit dans la spécification de l'énumération qui le précède (« CT-n EX-a, EX-b et EX-c », « CT-n EX-a à EX-b »), dans CT-7 à défaut ; le texte entre accents graves n'est pas lu. |
| RV-4 | `refs` est la liste des renvois du texte, dans l'ordre de leur première occurrence, sans doublon, selon l'expression `CT-([1-9]) (EX-[0-9A-Z]+\.[0-9]+\|§[0-9A-Z]+(\.[0-9]+)*\|[A-Z]{1,2}-[0-9]+)` ; aucun `EX-s.k` n'apparaît sans `CT-n ` devant dans `response` ni `detection`. |
| RV-5 | Les tables de 3.2, 3.4 et 3.5 de CT-7 et `menaces.json` disent la même chose, cellule par cellule (espaces de fin retirés, `\|` rendu par `|`). |
| RV-6 | Chaque ligne des tables sources de `source_tables` existe encore dans sa spécification (première cellule, gras retiré ; « puce n » pour une liste) et est rattachée à au moins une menace ; chaque `sources[]` désigne une ligne existante ; `rows` est le nombre de lignes de la table. |
| RV-7 | Pour chaque spécification de `spec/` (et `spec/README.md`), le nombre d'occurrences de « CT-7 » par section égale le nombre de lignes de la table 0.2 de CT-7 pour ce couple ; chaque section de CT-7 nommée dans la colonne « Réponse de CT-7 » existe ; chaque cellule de cette colonne nomme une section, une exigence ou un identifiant de CT-7 existant, renvoie au document entier par « Ce document », ou dit « hors de CT-7 » et nomme son porteur (une spécification CT-n, le client ou l'exploitant). Sections reconnues : « section N », « sections N et M », « sections N à M », « annexe X », « annexe X.n », et les numéros n.m et X.n isolés ; ne sont pas lus un numéro précédé de « version » ou « révision », un numéro inclus dans un renvoi « CT-n §… » ou « CT-n EX-… », ni le texte entre accents graves ; « annexe X » désigne le titre « ## Annexe X ». |
| RV-8 | Chaque risque accepté de la table 3.5 a sa menace dans `menaces.json`, et inversement, avec le même nom, la même borne et le même porteur. |
| RV-9 | `cles-de-test.json` égale les clés recalculées depuis les fichiers de clés des vecteurs. |

### A.11 Tests

**EX-A.19** `test/securite.test.js` : rejoue chaque cas de `ceremonies/` par
`verifierCeremonie` et par `scripts/verify/ceremonie.mjs` (verdict, `D_C`,
échecs, non exécutées, signataires, code de retour) ; valide chaque
`proces-verbal.json` valide et chaque `attendu.json` contre le schéma ;
recalcule l'exemple de 5.10 (`D_C`, `M`, empreintes, adresse de chaîne, trois
signatures) ; lance le vérificateur de renvois ; vérifie que deux générations de
`ct-7/` sont identiques ; et, si `ct-7/confrontation/` porte des sorties, que
chaque adresse recouvrée par ethers et par eth-account égale le signataire
attendu. Il rejoue aussi `attestations.json`, `croises.json` et `exemple/` de
`ct-7/attestations` par `verifierAttestation` (EX-A.8, EX-A.9), recalcule les
valeurs de 7.2 et vérifie que l'outil de référence refuse une adresse IPv4 dans
`host` (MN-87). Les dossiers nouveaux de A.7 sont rejoués par
`test/journal.test.js` (famille `ct-1`) et `test/verificateur.test.js` (famille
`ct-6`, avec V-10 de CT-6). Chaque menace de 3.4 dont la colonne « Test de
CT-9 » désigne un test déjà possible dans le dépôt (vecteurs de CT-1 à CT-6)
PEUT y être reliée ; les autres sont écrites par CT-9.

**EX-A.20** `test/securite.test.js` (ou un fichier `test/conformite.test.js`)
vérifie : la conformité du fichier publié et des exemples annotés de CT-7
(annotations `matrice-conformite` et `matrice-conformite/ligne`) ; MX-1 à
MX-9 sur le fichier publié ; l'échec exact de chaque cas de A.8 ; la
grille de l'épreuve de EX-9.2 recalculée depuis le fichier.

### A.12 Vérificateur indépendant

**EX-A.21** `spec/vecteurs/ct-7/verificateur-independant/` est un module Go
séparé, écrit depuis le seul texte de CT-7 et de CT-1 §6.3, sans cgo ; il
recalcule `D_C`, exécute CR-1 à CR-12 sur chaque cas de `ceremonies/` et
compare au fichier `attendu.json` ; zéro discordance (`go run . ..`). Les
briques Keccak-256 et secp256k1 PEUVENT être copiées sans modification du
vérificateur Go de `ct-3`, chaque fichier copié portant en tête « Copié sans
modification de spec/vecteurs/ct-3/verificateur-independant/<fichier> ». Le
même module vérifie les attestations (EX-A.22) et peut rejouer une partie des
vérifications de la matrice (EX-A.23). Il offre aussi deux modes de recalcul
pour le signataire qui compare un condensé à un second outil (EX-5.8, EX-7.8) :
`go run . condenser <attestation.json>` imprime `D_P` et `go run . condenser-pv
<proces-verbal.json>` imprime `D_C`, chacun suivi de ses groupes de huit
chiffres.

**EX-A.22 (vérificateur Go indépendant).** Le module
`spec/vecteurs/ct-7/verificateur-independant` est écrit depuis le seul texte
de CT-7 (et CT-1 §6.3 pour EIP-191) ; ses briques Keccak-256 et secp256k1
PEUVENT être copiées sans modification du vérificateur Go de `ct-3`, avec
l'en-tête « Copié sans modification de … ». Il recalcule `JCS(P)`, `D_P`,
`M`, recouvre chaque adresse et rejoue AT-1 à AT-4 sur `attestations.json`,
`croises.json` et `exemple/`, avec zéro discordance (`go run . ..`). Les
vérificateurs Go de `ct-1` (et sa copie de `ct-2`) sont étendus, depuis le
texte de CT-1 0.4, à la quatorzième partie et à AT-1 à AT-7. Pour AT-3, le
vérificateur de `ct-1` PEUT reprendre `secp256k1.go` sans modification du
vérificateur Go de `ct-3`, avec l'en-tête « Copié sans modification de
spec/vecteurs/ct-3/verificateur-independant/secp256k1.go » ; sa copie de `ct-2`
(`ct1_secp256k1.go`) suit la règle de copie existante du module `ct-2`. Le
renommage d'un identifiant propre à `ct-1` (`modP` en `modPEd25519`, dans
`crypto.go` et `ct1_crypto.go`) pour éviter le conflit de noms est admis.

**EX-A.23** Le vérificateur Go de `spec/vecteurs/ct-7/verificateur-independant`
PEUT rejouer MX-1 à MX-3, MX-5 et MX-9 sur `matrice-conformite.json` et sur
les cas de A.8, depuis le seul texte de CT-7 ; MX-4, MX-6, MX-7 et MX-8,
qui lisent les autres spécifications ou le texte de CT-7, restent au
vérificateur de renvois.

### A.13 Confrontation tierce

**EX-A.24** `spec/vecteurs/ct-7/confrontation/ceremonies/` porte un
`LISEZMOI.md`, un programme Node qui recouvre chaque signature de chaque
procès-verbal par `ethers` (`verifyMessage(getBytes(D_C), sig)`), un
programme Python qui la recouvre par eth-account 0.14.0
(`Account.recover_message(encode_defunct(primitive=D_C), signature=sig)`),
leurs sorties publiées (`sorties/`) et `exigences.txt` qui épingle la
version. Le générateur n'écrit jamais dans ce répertoire. Les formes que CT-7
refuse et qu'une bibliothèque accepte (`s` haut par eth-account) sont des écarts
inscrits dans le `LISEZMOI.md`, non des discordances ; seule la signature du cas
`invalide-cr11-s-haut` (A.4) en produit. Quand CR-1 échoue, le vecteur ne donne
ni `D_C` ni adresse recouvrée attendue (`digest` nul) : la confrontation PEUT
alors recouvrer les signatures sur le condensé de la formule de 5.7, appliquée
au texte lu avec trois règles (un membre en double garde sa dernière occurrence,
un nombre à partie fractionnaire nulle est lu comme entier, le schéma n'est pas
vérifié) ; l'adresse attendue est celle que recouvre la référence. Ces lignes
forment la famille `cr1-lecture-permissive` et ne valent pas définition de
`D_C` ; seuls `invalide-cr1-cle-en-double` et `invalide-cr1-nombre-non-entier`
exigent réellement ces règles.

**EX-A.25 (confrontation tierce).** `spec/vecteurs/ct-7/confrontation/
attestations/` contient un `LISEZMOI.md`, un programme Node qui recouvre
chaque signature d'attestation des vecteurs par `ethers`
(`verifyMessage(getBytes(D_P), signature)`) et un programme Python qui la
recouvre par eth-account 0.14.0 (`Account.recover_message(encode_defunct(
primitive=D_P), signature=…)`), leurs sorties publiées et un fichier
`exigences.txt` qui épingle la version ; `test/confrontation.test.js` relie
les sorties aux vecteurs et rejoue les programmes si l'outil est présent ;
toute discordance fait échouer le test. Les verdicts sont ceux de la
confrontation de CT-3 (`concorde`, `acceptee_par_la_bibliotheque`,
`refusee_par_la_bibliotheque`, `discordance`) ; les formes que CT-7 refuse
et qu'une bibliothèque accepte (constatées par la confrontation de CT-3 :
`s` haut et `v` de 0 ou 1 par eth-account ; `v` de 0 ou 1 et forme compacte
de 64 octets par ethers) sont des écarts inscrits dans le `LISEZMOI.md`, non
des discordances ; seules les signatures des cas invalides de forme (A.4 et A.6)
en produisent. Quand AT-1 échoue, le vecteur ne donne ni `D_P` ni adresse
recouvrée attendue ; la confrontation PEUT recouvrer les signatures sur le
condensé de 7.2 appliqué au texte lu avec les trois règles d'EX-A.24 (famille
`attestations/cas`), sans que cela vaille définition de `D_P` ; seul
`invalide-at1-nombre-non-entier` exige réellement ces règles.

### A.14 Intégration continue

**EX-A.26** `ci.yml` ajoute : la régénération de `ct-7` et un `git diff
--exit-code` nul sur `spec/vecteurs/ct-7` ; `go run . ..` du vérificateur
Go de `ct-7` ; `node scripts/conformite/verifier-renvois.mjs` ; au job de
confrontation, l'exécution des deux programmes de A.13 et la comparaison de
leurs sorties aux sorties publiées.

**EX-A.27 (intégration continue).** Le fichier `ci.yml` régénère
`spec/vecteurs/ct-7` et exige un diff vide (EX-A.2), exécute le vérificateur Go
de `ct-7` et les vérificateurs étendus de `ct-1` et `ct-2`, exécute le
vérificateur de renvois (`scripts/conformite/verifier-renvois.mjs` : les EX-
cités par la section 7 et par `menaces.json` pour les lignes de l'attestation
existent), et ajoute au job de confrontation les deux programmes de EX-A.25.

**EX-A.28** Le fichier `ci.yml` régénère `spec/vecteurs/ct-7` et exige un
diff vide (EX-A.12), puis exécute
`node scripts/conformite/verifier-renvois.mjs` (EX-A.13).

### A.15 Épreuves à l'aveugle

**EX-A.29** `ct-7/acceptation-securite/consigne.md` remet au relecteur les six
scénarios de EX-9.1 sans les menaces ; la grille est
`ct-7/acceptation-securite-attendu.json`, que le relecteur ne reçoit pas.
`ct-7/acceptation-conformite/consigne.md` et
`ct-7/acceptation-attestation/consigne.md` remettent de même les questions de
EX-9.2 et EX-9.4 ; leurs grilles sont
`ct-7/acceptation-conformite-attendu.json`, produite par le générateur depuis
`matrice-conformite.json`, et `ct-7/acceptation-attestation-attendu.json`. Les
consignes de EX-9.1 et EX-9.2 remettent CT-7 sans la section 9 ni l'annexe A.15.
`ct-7/acceptation-attestation/rapport.txt` est la sortie de `node
scripts/verify/dossier.mjs` sur
`ct-1/dossiers/valide-seq-12-attestation-inscrite`, sans les lignes qui
commencent par « Vérificateur : » et « Répertoire : ».

### A.16 Ce qui ne change pas

**EX-A.30** Ce lot ne modifie aucun fichier existant de `spec/vecteurs/ct-1`
à `ct-6` (sauf `INDEX.md` de `ct-1` et `ct-6`, pour les dossiers nouveaux de
l'attestation, et les vérificateurs Go de `ct-1` et de sa copie de `ct-2`,
étendus à AT-1 à AT-7 selon EX-A.22) ; les générateurs de `ct-2` à `ct-5` ne
changent pas, ceux de `ct-1` et `ct-6` ne gagnent que les dossiers nouveaux
(EX-A.3) ; RV-6 lit les tables sources sans les écrire. Seule exception :
les confrontations `reponses` et `coherence` de `ct-5` lisent aussi le
dossier nouveau `valide-point-de-controle-complet-attestation` de `ct-6`,
dont `points-de-controle.json` est celui de
`valide-point-de-controle-complet` ; leurs sorties publiées
(`ct-5/confrontation/sorties/reponses.txt` et `coherence.txt`) sont
rejouées et portent un bloc de plus, identique à celui de ce dossier, sans
autre différence, et leurs `LISEZMOI.md` comptent dix-huit dossiers de
`ct-6`.

**EX-A.31** Le générateur ne réécrit aucun fichier de `ct-2` à `ct-5` ; la
famille `matrice` n'ajoute rien à `ct-1` ni à `ct-6`.

## Annexe B — Sources primaires datées

Les faits externes de CT-7 viennent de deux notes de recherche internes du
lot, non publiées : R6 (réglementation) et R7 (sécurité et cérémonies),
relues le 2026-10-26 sur les sources primaires qu'elles citent. Un fait porte
le renvoi « R6-Fn » ou « R7-Fn » ; un point non vérifié porte « NV-n » (R6) ou
renvoie à la section 2 de R7. Cette annexe donne, pour chaque renvoi, l'objet
du fait, la source primaire publique, son URL, la date de lecture et, quand le
fichier a été téléchargé, son SHA-256. Ce qui n'a pas pu être vérifié est
écrit « non vérifié ».

### B.1 R7 — Sécurité et cérémonies

Toutes les sources sont lues le 2026-10-26. Les extraits cités par CT-7 sont
recopiés mot pour mot de la source ; « […] » marque une coupe.

| Renvoi | Objet | Source primaire, URL | SHA-256 du fichier lu |
|---|---|---|---|
| R7-F1, R7-F4 à R7-F8, R7-F10 | NIST SP 800-57 Part 1 Rev. 5 (mai 2020) : compromission, période de crypto d'une clé privée de signature, sauvegarde, conduite et plan de reprise après compromission, traçabilité, connaissance partagée | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf | `cc32391022c1382ac7c91490f6bcc8838e0f889925270da23ef4e800e2ecb7ad` |
| R7-F9, R7-F53 (signature numérique, non-répudiation) | NIST SP 800-57 Part 1 Rev. 5 : audit des systèmes de gestion de clés ; définitions « Digital signature » et « Non-repudiation » | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf | `cc32391022c1382ac7c91490f6bcc8838e0f889925270da23ef4e800e2ecb7ad` |
| R7-F11 à R7-F14 | NIST SP 800-130 (août 2013) : rôles, contrôle multipartite (FR 6.98, 6.99), partage de clé (FR 6.100), sauvegarde (FR 6.47, 6.49) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-130.pdf | `937d2f89c476a055419844c81912a1aa46193d7801f8f0d22c74cf38ce860dc4` |
| R7-F16 | NIST SP 800-152 (octobre 2015) : événements de gestion de clés à journaliser et leurs champs (PR:8.15) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-152.pdf | `e274bf1c58db4f681b0f03bf8545836e33ae391de35b31071fdf5cba9e396c4d` |
| R7-F17 | Règlement délégué (UE) 2024/1774, JO L du 25.6.2024, art. 7 « Gestion des clés cryptographiques », texte français | http://publications.europa.eu/resource/celex/32024R1774 | `ee56cba0cc5137f75c50e8e318ac1484b772bc01abe7cac81502e9d97bf0f659` |
| R7-F20 | IANA, cérémonie 62 de la clé de signature de la racine du DNS (12 août 2026) : pièces publiées | https://www.iana.org/dnssec/ceremonies/62 | — (page HTML) |
| R7-F21 | IANA, rôles d'une cérémonie (page révisée le 2018-11-06) | https://www.iana.org/help/key-ceremony-roles | — (page HTML) |
| R7-F22 | IANA, script proposé de la cérémonie 62 : lecture, paraphes, exceptions, attestation du témoin | https://data.iana.org/ksk-ceremony/62/KC62_Script.pdf | `5d372174ccf992785b3aa87a40945177d08bba01c22b7b377d7a7690076c84ac` |
| R7-F24 à R7-F26, R7-F28 | IANA, déclaration de pratiques DNSSEC de l'opérateur de la clé, 9e édition, en vigueur le 2026-10-07 : séparation des tâches, génération en cérémonie, M sur N, sauvegarde, audit | https://www.iana.org/dnssec/procedures/ksk-operator/ksk-dps-20261007.html | `8f0e9530a02f215899e86e278d2d3a7f35a24a25271822571d6c52d40ca9411f` |
| R7-F29, R7-F31 | CA/Browser Forum, Baseline Requirements 2.3.1 (4 octobre 2026, Ballot SC104) : §6.1.1.1 (script de génération, témoin ou vidéo), §5.2.2 (double contrôle de la sauvegarde) | https://raw.githubusercontent.com/cabforum/servercert/main/docs/BR.md | `ee4e4e95ba0f3fa1e11cb0dc01b2337aa26e88b8c7724c78f25e5743fc1e151e` |
| R7-F33, R7-F35, R7-F43, R7-F44, R7-F45, R7-F47, R7-F48, R7-F53 (AU-10) | NIST SP 800-53 Rev. 5 (septembre 2020) : AC-3(2), AU-9(5), SC-7(5), SC-7(8), SC-7(10), IA-5(7), AC-6, AU-10 | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf | `fc63bcd61715d0181dd8e85998b1e6201ae3515fc6626102101cab1841e11ec6` |
| R7-F36 | Documentation d'un service de gestion de secrets : scellement par partage de Shamir | https://developer.hashicorp.com/vault/docs/concepts/seal | — (page HTML) |
| R7-F37 | Documentation d'un module matériel en nuage : authentification par quorum (M sur N), le demandeur comptant pour une approbation | https://docs.aws.amazon.com/cloudhsm/latest/userguide/quorum-authentication.html | — (page HTML) |
| R7-F38 | Documentation d'un module matériel : clé d'enveloppe de sauvegarde partagée entre gardiens, partage fait hors du module | https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-backup-restore.html | — (page HTML) |
| R7-F39 | Documentation publiant le modèle STRIDE (page mise à jour le 2026-03-04 selon ses métadonnées) | https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats | `cc8bd45eb5cca7ebca82e3f5ffdcc5bbdd8ab1b9c7f1e111cdfb7202917beb61` |
| R7-F40, R7-F41 | NIST SP 800-154, projet initial (mars 2016), statut lu sur la page du NIST : définitions et méthode en quatre étapes | https://csrc.nist.gov/files/pubs/sp/800/154/ipd/docs/sp800_154_draft.pdf ; statut : https://csrc.nist.gov/pubs/sp/800/154/ipd | `53fc49939603cffe116b0dc6d07cc81b46c072411dc1c2d2ed5c41a6b3933286` |
| R7-F51, R7-F52 | NIST SP 800-53A Rev. 5 (janvier 2022) : méthodes d'évaluation (examiner, interroger, tester) et indépendance de l'évaluateur | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53Ar5.pdf | `75665570048b969ad465a4f4f1db425ce505c374951c2c64e462949c6b21be47` |
| R7-F46 | NIST SP 800-41 Rev. 1 (septembre 2009) : pare-feu et mandataires sortants, refus de ce qui n'est pas expressément permis | https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-41r1.pdf | `06642409a8f0dcc9de8725f2d76d6feedea2d4d1faa860c2ee18488863dd1f4f` |

Non vérifié (R7, section 2), et sur quoi aucune exigence de CT-7 ne se fonde :
ISO/IEC 27001:2022 A.8.24 et A.8.15 (texte payant) ; ISO/IEC 11770 et les
rôles de FIPS 140-3 ; les définitions d'attestation de SOC 2, SOC 3, ISAE
3000 et ISAE 3402 ; NIST SP 800-57 Part 2 Rev. 1 ; les valeurs par défaut du
nombre de parts du scellement de Shamir de R7-F36 ; le mécanisme M sur N
d'autres modules ; une norme qui exige qu'une passerelle sortante soit seule
à détenir les identifiants d'API (le motif repose sur R7-F44, R7-F47 et
R7-F48, et reste un choix de conception) ; la portée juridique d'une
déclaration signée ; le script annoté de la cérémonie 62 et ses exceptions ;
l'auteur et la date d'origine du modèle STRIDE. La définition « Key share »
de SP 800-57 porte « any k key shares (where k ≥ n) », contraire à celle de
« Split knowledge » : CT-7 ne cite que la seconde (R7-F10).

Extraits cités par la section 7 (attestation de périmètre) :

| Renvoi | Fait | Source primaire | Lue le |
|---|---|---|---|
| R7-F43 | SC-7(5) : « Deny network communications traffic by default and allow network communications traffic by exception » | NIST SP 800-53 Rev. 5, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf, p. PDF 325-326 | 2026-10-26 |
| R7-F44 | SC-7(8) : « Route [Assignment: organization-defined internal communications traffic] to [Assignment: organization-defined external networks] through authenticated proxy servers at managed interfaces. » | même document, p. PDF 326 | 2026-10-26 |
| R7-F45 | SC-7(10) : « (a) Prevent the exfiltration of information; and (b) Conduct exfiltration tests [Assignment: organization-defined frequency]. » | même document, p. PDF 327 | 2026-10-26 |
| R7-F46 | « Generally, firewalls should block all inbound and outbound traffic that has not been expressly permitted by the firewall policy » | NIST SP 800-41 Rev. 1, https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-41r1.pdf, p. PDF 28 | 2026-10-26 |
| R7-F47 | IA-5(7) : « Ensure that unencrypted static authenticators are not embedded in applications or other forms of static storage. » | NIST SP 800-53 Rev. 5, p. PDF 167 | 2026-10-26 |
| R7-F48 | AC-6 : « Employ the principle of least privilege, allowing only authorized accesses for users (or processes acting on behalf of users) that are necessary to accomplish assigned organizational tasks. » | NIST SP 800-53 Rev. 5, p. PDF 63 | 2026-10-26 |
| R7-F51 | « Assessment methods define the nature of the assessor actions and include examine, interview, and test. » | NIST SP 800-53A Rev. 5, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53Ar5.pdf, p. PDF 22 | 2026-10-26 |
| R7-F52 | « An independent assessor is any individual capable of conducting an impartial assessment of security and privacy controls employed within or inherited by a system. » | même document, p. PDF 33 | 2026-10-26 |
| R7-F53 | Signature numérique : « Source/identity authentication, […] Data integrity authentication, and/or […] Support for signer non-repudiation. » | NIST SP 800-57 Part 1 Rev. 5, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf, glossaire | 2026-10-26 |
| R7, section 2 | Aucune norme lue n'exige qu'une passerelle sortante soit seule à détenir les identifiants d'API ; la portée juridique d'une déclaration signée par l'exploitant n'a pas été recherchée (avis juridique exclu) | non vérifié | 2026-10-26 |
| EIP-191 | Signature `personal_sign`, version `0x45` | reprise de CT-1 §6.3 et de ses sources ; aucun fait nouveau | — |

### B.2 R6 — Réglementation

Toutes les sources sont lues le 2026-10-26 (R6-F66 le 2026-10-27), en français,
langue officielle de chacune. Les citations de la section 8 sont recopiées mot
pour mot ; « […] » marque une coupe ; un appel de note, une note de bas de page
ou un numéro de page qu'un saut de page intercale sont omis. Pour la circulaire
FINMA 2018/3, les chiffres marginaux ont été lus sur le rendu des pages, la
couche texte du PDF ne les portant pas. Les versions consolidées ont été
cherchées par les points SPARQL de Fedlex
(https://fedlex.data.admin.ch/sparqlendpoint) et de l'Office des publications de
l'Union (https://publications.europa.eu/webapi/rdf/sparql) ; les textes de
l'Union ont été lus par le dépôt Cellar de l'Office des publications, en XHTML
français.

| Source | Texte, version | URL officielle | SHA-256 du fichier lu |
|---|---|---|---|
| S1 | Communication FINMA sur la surveillance 08/2024, 18.12.2024, FR | https://www.finma.ch/fr/~/media/finma/dokumente/dokumentencenter/myfinma/4dokumentation/finma-aufsichtsmitteilungen/20241218-finma-aufsichtsmitteilung-08-2024.pdf?sc_lang=fr | `0352db880cfc090cbf8dd72766fbe795cb6e5b4c7af3872573f374ca488e2aab` |
| S2 | Circ.-FINMA 18/3 « Outsourcing », dernière modification 4.11.2020, FR ; le nom du fichier se termine par `_de`, mais le contenu servi avec `sc_lang=fr` est la version française, et l'adresse en `_fr.pdf` répond 404 ; le SHA-256 est celui de la version française lue | https://www.finma.ch/fr/~/media/finma/dokumente/dokumentencenter/myfinma/rundschreiben/finma-rs-2018-03-01012021_de.pdf?sc_lang=fr | `0d883fa03a92c9ae2fd657de2fcfeebd98697c75f956bb7bbe9620a3319bd5dd` |
| S3 | FINMA, « Circulaires FINMA - destinataires » (titre de la page), FR | https://www.finma.ch/fr/~/media/finma/dokumente/dokumentencenter/myfinma/4dokumentation/rundschreiben/adressaten-finma-rundschreiben.pdf?sc_lang=fr | `61a79ead65fe3fb945d156404bb43008ac3b802cabbf6979577d0a2152ba1b16` |
| S4 | FINMA, « Projets réglementaires de la FINMA », « État et perspectives au 1er septembre 2026 », FR | https://www.finma.ch/fr/~/media/finma/dokumente/dokumentencenter/myfinma/4dokumentation/rundschreiben/finanzmarktregulierung-vorhaben.pdf?sc_lang=fr | `2b9d6de7c2e2e866d87c9839aff6ce17512ec6690a6ac20d59b7011cdd8c5cc5` |
| S5 | OPDo (RS 235.11), état le 1.12.2025, FR | https://fedlex.data.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2022/568/20251201/fr/html/fedlex-data-admin-ch-eli-cc-2022-568-20251201-fr-html-2.html | `bd70d1f92aec8808906dfc1afd40bd53b47157c9baf1f308e8049d98d9ba58f1` |
| S6 | PFPDT, recommandations techniques, journalisation art. 4 OPDo, v1.1 du 15.10.2026, FR | https://www.edoeb.admin.ch/dam/fr/sd-web/HKcvqpRgro2P/Empfehlung%20Protokollierung%20nach%20DSV_FR.pdf | `6c8cc8608801fcaac0e55d5c832cfcd7192ca4ceba4bbe0f03b025af828cb311` |
| S7 | PFPDT, guide TOM, 15.1.2024, FR | https://www.edoeb.admin.ch/dam/fr/sd-web/eVhrh8wY3QcR/leitfaden_tom.pdf | `1c972d6e41fbc5d7fe794d6cdd307e4170772b00607bf580d3a17ada1c47bde6` |
| S8 | PFPDT, « Update - La loi actuelle sur la protection des données est directement applicable à l’IA », 8.5.2025 | https://www.edoeb.admin.ch/fr/update-loi-actuelle-applicable-ia | `c14bbc13ed89f88f7974cf9937e4e9fd830a3d3bb8a61b528a5f9f6af1b6a21d` |
| S9 | PFPDT, « IA et protection des données », 24.9.2025 | https://www.edoeb.admin.ch/fr/ia-et-protection-des-donnees | `e21fc10a190d1b04347179edfab22e6a1358e2cb7b056f992989ffd7aa2eaed0` |
| S10 | Règlement (UE) 2022/2554 (DORA), JO L 333 du 27.12.2022, FR | http://publications.europa.eu/resource/celex/32022R2554 (ELI http://data.europa.eu/eli/reg/2022/2554/oj) | `b1ae836d79ba2831d3be11834b359eb5a0cf099cc3e478d1b2ef3198061e7c57` |
| S11 | Règlement délégué (UE) 2024/1774, JO L du 25.6.2024, FR | http://publications.europa.eu/resource/celex/32024R1774 | `ee56cba0cc5137f75c50e8e318ac1484b772bc01abe7cac81502e9d97bf0f659` |
| S12 | Règlement (UE) 2024/1689, JO L du 12.7.2024, FR | http://publications.europa.eu/resource/celex/32024R1689 | `d8b1a7775f597dc8d49a2bdc91af0dca3bc12ac558b97504685f9534660bb44e` |
| S13 | Règlement (UE) 2024/1689, consolidé au 27.07.2026, FR | http://publications.europa.eu/resource/celex/02024R1689-20260727 | `248c47ff5dd6583d98711347541047e7a2b83d5122174312558a8a17d90b81f8` |
| S14 | Règlement (UE) 2026/1744, JO L du 24.7.2026, FR | http://publications.europa.eu/resource/celex/32026R1744 | `9f4fcd8d6f274684d5c0fe0309fc020bcda60190dac6f074f676a3352ff442ad` |
| S15 | Olico (RS 221.431), état le 1.1.2013, FR | https://fedlex.data.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2002/216/20130101/fr/html/fedlex-data-admin-ch-eli-cc-2002-216-20130101-fr-html-6.html | `f3826ca042ffa06b9ec37945666148ea8e46583b4895879f3e4692e42b667452` |
| S16 | Code des obligations, état le 1.10.2026, FR | https://fedlex.data.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/27/317_321_377/20261001/fr/html/fedlex-data-admin-ch-eli-cc-27-317_321_377-20261001-fr-html-3.html | `706344c71bcdd08aa450796e9d88263acf762c933058277e4975339b2a8bd75e` |
| S17 | Code des obligations, état le 1.7.2027 (comparaison de l'art. 958f) | https://fedlex.data.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/27/317_321_377/20270701/fr/html/fedlex-data-admin-ch-eli-cc-27-317_321_377-20270701-fr-html-4.html | `e3aaba1989e08e8558ebfbf6042e1b9733ceddc3aeb75ee5f5fe7030a898376e` |

Faits relevés par la note R6 ; ceux que ni la section 8 ni l'annexe C ne citent
(R6-F1, R6-F2, R6-F12, R6-F14, R6-F23, R6-F25, R6-F30, R6-F31, R6-F37, R6-F43 et
R6-F58) n'ont été examinés par aucune ligne de la matrice :

| Renvoi | Objet du fait | Source (annexe B, table des sources) | Lu le |
|---|---|---|---|
| R6-F1 | Communication FINMA 08/2024 : identité et date | S1 | 2026-10-26 |
| R6-F2 | Communication FINMA 08/2024 : absence de loi spécifique, exigences neutres | S1 | 2026-10-26 |
| R6-F4 | Gouvernance, inventaire centralisé, recours à des tiers (points évalués) | S1 | 2026-10-26 |
| R6-F6 | Tests et surveillance constante, dont les corrections manuelles | S1 | 2026-10-26 |
| R6-F7 | Documentation | S1 | 2026-10-26 |
| R6-F8 | Explicabilité | S1 | 2026-10-26 |
| R6-F9 | Vérification indépendante | S1 | 2026-10-26 |
| R6-F10 | Vocabulaire absent | S1 | 2026-10-26 |
| R6-F12 | Identité, dates, dernière modification | S2 | 2026-10-26 |
| R6-F13 | Statut au 2026-10-26 (indices) | S3, S4 | 2026-10-26 |
| R6-F14 | Cm 3 et 4, définitions | S2 | 2026-10-26 |
| R6-F15 | Cm 14, inventaire | S2 | 2026-10-26 |
| R6-F16 | Cm 16, 18 et 18.1, analyse du risque et réversibilité | S2 | 2026-10-26 |
| R6-F17 | Cm 20 et 21, contrôle interne et instructions | S2 | 2026-10-26 |
| R6-F19 | Cm 24 et 25, sécurité et continuité | S2 | 2026-10-26 |
| R6-F20 | Cm 26 à 29, audit et information (établissement, société d'audit, FINMA) | S2 | 2026-10-26 |
| R6-F21 | Cm 30 et 31, transfert à l'étranger | S2 | 2026-10-26 |
| R6-F22 | Cm 32 à 35, contrat et sous-traitance en chaîne | S2 | 2026-10-26 |
| R6-F23 | OPDo : version consolidée lue | S5 | 2026-10-26 |
| R6-F24 | OPDo art. 4 al. 1 (responsable privé), nouvelle teneur du 29 octobre 2025 | S5 | 2026-10-26 |
| R6-F25 | OPDo art. 4 al. 2 et 2bis (organes fédéraux) | S5 | 2026-10-26 |
| R6-F26 | OPDo art. 4 al. 3, 4 et 5 (contenu, conservation, séparation, accès) | S5 | 2026-10-26 |
| R6-F27 | OPDo art. 46 al. 1, disposition transitoire (organes fédéraux seulement) | S5 | 2026-10-26 |
| R6-F28 | OPDo art. 2 let. d et art. 3 al. 3 (traçabilité) | S5 | 2026-10-26 |
| R6-F30 | OPDo art. 5 (règlement de traitement des personnes privées) | S5 | 2026-10-26 |
| R6-F31 | PFPDT, recommandations techniques relatives à la journalisation prévue à l'art. 4 OPDo, version 1.1 du 15 octobre 2026 | S6 | 2026-10-26 |
| R6-F32 | PFPDT, saisie et identité technique | S6 | 2026-10-26 |
| R6-F33 | PFPDT, enregistrement séparé | S6 | 2026-10-26 |
| R6-F34 | PFPDT, recommandations techniques (intégrité, horodatage, synchronisation) | S6 | 2026-10-26 |
| R6-F35 | PFPDT, durée de conservation et stockage | S6 | 2026-10-26 |
| R6-F36 | PFPDT, FAQ (sauvegarde, scripts, services externes) | S6 | 2026-10-26 |
| R6-F37 | PFPDT, guide TOM du 15 janvier 2024 | S7 | 2026-10-26 |
| R6-F38 | PFPDT et IA | S8 | 2026-10-26 |
| R6-F39 | DORA : application (art. 64) | S10 | 2026-10-26 |
| R6-F40 | DORA art. 28 § 1 a), responsabilité | S10 | 2026-10-26 |
| R6-F41 | DORA art. 28 § 3, registre d'informations | S10 | 2026-10-26 |
| R6-F42 | DORA art. 28 § 6, droits d'accès, d'inspection et d'audit | S10 | 2026-10-26 |
| R6-F43 | DORA art. 28 § 7 c) et d), résiliation | S10 | 2026-10-26 |
| R6-F44 | DORA art. 28 § 8, stratégies de sortie | S10 | 2026-10-26 |
| R6-F45 | DORA art. 29 § 2, sous-traitance en chaîne | S10 | 2026-10-26 |
| R6-F46 | DORA art. 30 § 1 et § 2, clauses de tout accord TIC | S10 | 2026-10-26 |
| R6-F47 | DORA art. 30 § 3 e) et f), fonctions critiques ou importantes : accès, inspection, audit, sortie | S10 | 2026-10-26 |
| R6-F48 | Règlement délégué (UE) 2024/1774, identité | S11 | 2026-10-26 |
| R6-F49 | Règlement délégué (UE) 2024/1774, art. 12 en entier | S11 | 2026-10-26 |
| R6-F50 | Règlement (UE) 2024/1689, art. 12, enregistrement | S12 | 2026-10-26 |
| R6-F51 | Règlement (UE) 2024/1689, art. 14, contrôle humain | S12 | 2026-10-26 |
| R6-F52 | Règlement (UE) 2024/1689, art. 19, journaux générés automatiquement, durée | S12 | 2026-10-26 |
| R6-F53 | Règlement (UE) 2024/1689, art. 26 § 1, 2 et 5, déployeurs | S12 | 2026-10-26 |
| R6-F54 | Règlement (UE) 2024/1689, art. 26 § 6, journaux du déployeur | S12 | 2026-10-26 |
| R6-F55 | Règlement (UE) 2024/1689, art. 113, dates d'application, texte consolidé | S13, S14 | 2026-10-26 |
| R6-F56 | Règlement (UE) 2024/1689 : place des articles dans le chapitre III, donc dates d'application | S12, S13 | 2026-10-26 |
| R6-F57 | Règlement (UE) 2024/1689 : articles cités non modifiés par le règlement (UE) 2026/1744 | S13, S14 | 2026-10-26 |
| R6-F58 | Olico : version et base | S15 | 2026-10-26 |
| R6-F59 | Olico art. 2 al. 2 et art. 3, intégrité | S15 | 2026-10-26 |
| R6-F60 | Olico art. 4, documentation | S15 | 2026-10-26 |
| R6-F61 | Olico art. 6, disponibilité et consultation | S15 | 2026-10-26 |
| R6-F62 | Olico art. 7 et 8, organisation et archives | S15 | 2026-10-26 |
| R6-F63 | Olico art. 9, supports autorisés | S15 | 2026-10-26 |
| R6-F64 | Olico art. 10, contrôle et migration | S15 | 2026-10-26 |
| R6-F65 | CO art. 958f, conservation des livres et pièces comptables | S16 | 2026-10-26 |
| R6-F66 | DORA art. 30 § 2 f), § 3 b) et c), assistance, notification et plans d'urgence (citations ci-dessous) | S10 | 2026-10-27 |
| R7-F17 | Règlement délégué (UE) 2024/1774, art. 7 « Gestion des clés cryptographiques », § 1 et § 3 (fait de la note R7) | S11 | 2026-10-26 |

R6-F66, lu le 2026-10-27 dans le fichier de S10
(http://publications.europa.eu/resource/celex/32022R2554, SHA-256 du fichier
XHTML lu en tête de cette annexe) : art. 30 § 2 f) « l’obligation pour le
prestataire tiers de services TIC de fournir à l’entité financière, sans frais
supplémentaires ou à un coût déterminé ex ante, une assistance en cas d’incident
lié aux TIC en rapport avec le service TIC fourni à l’entité financière; » ;
art. 30 § 3 b) « les délais de préavis et les obligations de notification du
prestataire tiers de services TIC à l’entité financière, y compris la
notification de tout développement susceptible d’avoir une incidence
significative sur la capacité du prestataire tiers de services TIC à fournir les
services TIC qui soutiennent des fonctions critiques ou importantes de manière
efficace conformément aux niveaux de service convenus; » ; art. 30 § 3 c)
« l’obligation pour le prestataire tiers de services TIC de mettre en œuvre et
de tester des plans d’urgence et de mettre en place des mesures, des outils et
des politiques de sécurité des TIC qui fournissent un niveau approprié de
sécurité en vue de la prestation de services par l’entité financière,
conformément à son cadre réglementaire; »

Non vérifié (R6, section 2), et sur quoi aucune ligne de la matrice ne fonde une
relation `repond_a` : la vigueur de la circulaire FINMA 2018/3 au 2026-10-26,
déduite et non lue dans un acte (NV-1, lacune L-8) ; l'absence de communication
FINMA propre à l'IA postérieure au 18 décembre 2024 (NV-2) ; le contenu de la
circulaire FINMA 2023/1 « Risques et résilience opérationnels – banques »
(NV-3) ; les normes techniques de DORA sur la sous-traitance (art. 30 § 5) et
sur la politique contractuelle (art. 28 § 10) (NV-4) ; une date d'application
propre du règlement délégué (UE) 2024/1774 (NV-5) ; les durées sectorielles de
conservation (NV-6, lacune L-7) ; un guide du PFPDT propre à l'IA et à la
journalisation des agents (NV-7) ; la qualification d'un client (NV-8) ;
l'intégrité des journaux au sens de l'art. 12 du règlement (UE) 2024/1689
(NV-10) : le texte de l'article ne mentionne ni intégrité ni protection contre
la manipulation (constat de lecture, R6-F50), et le point reste non vérifié
parce que les normes harmonisées qui le préciseraient n'ont pas été lues ; la
matrice ne lui attribue pas cette exigence.

## Annexe C — Modèles de clauses de droit d'audit

> **Modèle à faire relire par le client.** Ces clauses sont des modèles de
> rédaction, non un avis juridique. Elles servent les exigences nommées sous
> chacune ; leur adaptation, leur négociation et leur suffisance pour un
> contrat donné relèvent du client et de ses conseils.

« L'Exploitant » désigne NOORTRACE comme exploitant du registre et éditeur
du vérificateur ; « le Client » l'organisation qui exploite l'enregistreur ;
« le Réviseur » sa société d'audit ou toute tierce partie qu'il désigne ;
« l'Autorité » toute autorité de surveillance compétente pour le Client. Les
crochets `[…]` marquent ce que le Client complète.

Les clauses ne visent, comme prestataire, que l'Exploitant. Un hébergeur tiers
de l'enregistreur, du service d'approbation ou du stockage, que 8.6 exclut de
l'inventaire, n'est visé par aucune d'elles : ses droits d'audit, de
restitution et de localisation relèvent d'un contrat distinct du Client.

Un passage « cité pour orientation » sous une clause en a inspiré la
rédaction, mais aucune ligne de la matrice ne l'examine : aucune
correspondance n'est établie.

**EX-C.1** Aucune sortie de NOORTRACE NE DOIT présenter ces clauses comme
suffisantes pour un texte ni comme un avis juridique ; chacune reproduit la
mention « Modèle à faire relire par le client ».

**EX-C.2** Chaque clause nomme les lignes de la matrice qu'elle sert ; la
liste est celle de `clauses[].serves` de `matrice-conformite.json` (MX-5) :

| Clause | Titre | Lignes servies |
|---|---|---|
| CL-1 | Droit d'audit, de regard et d'information | MC-2, MC-9, MC-11, MC-12, MC-28, MC-33 |
| CL-2 | Accès au vérificateur et aux formats | MC-33, MC-52, MC-58 |
| CL-3 | Conservation, restitution et réversibilité | MC-2, MC-8, MC-29, MC-32, MC-34, MC-47, MC-50 |
| CL-4 | Sous-traitance | MC-2, MC-7, MC-14, MC-27, MC-30 |
| CL-5 | Notification d'incident | MC-2, MC-10 |
| CL-6 | Lieux de traitement et exigences de sécurité | MC-10, MC-13, MC-31 |

### CL-1 Droit d'audit, de regard et d'information

1. L'Exploitant reconnaît au Client, au Réviseur et à l'Autorité un droit
   d'accès, de regard, d'inspection et d'audit intégral, permanent et sans
   entraves sur les prestations [désignation des prestations], y compris le
   droit de prendre copie sur place des documents pertinents.
2. Le Client fixe, selon une approche fondée sur les risques, la fréquence,
   la portée et les domaines de ces audits ; l'Exploitant précise sur
   demande ses procédures et coopère pleinement aux inspections et audits du
   Client, du Réviseur et de l'Autorité.
3. L'Exploitant met à la disposition de l'Autorité tous les renseignements et
   documents relatifs aux prestations dont elle a besoin pour sa
   surveillance. Le Client peut confier l'audit à l'organe de révision de
   l'Exploitant si celui-ci dispose des compétences requises ; le rapport est
   alors remis sur demande au Client, au Réviseur et à l'Autorité.
4. Aucun autre accord ni aucune politique de l'Exploitant ne limite
   l'exercice effectif de ces droits. Si leur exercice affecte les droits
   d'autres clients, les parties conviennent d'un autre niveau d'assurance
   [modalités].
5. L'Exploitant reconnaît au Client le droit de lui donner des instructions
   sur les prestations [désignation des prestations] et de procéder aux
   contrôles nécessaires à cet effet.

Lignes de la matrice : MC-2, MC-9, MC-11, MC-12, MC-28, MC-33 (circulaire FINMA
2018/3 Cm 20 et 21, dont le droit de donner des instructions repris au point 5,
Cm 26 et 29 ; DORA art. 28 § 6 et art. 30 § 3 e) ; communication FINMA 08/2024
ch. 2.1). Passages sans ligne dans la matrice, cités pour orientation,
correspondance non établie par 8.4 : circulaire FINMA 2018/3 Cm 27 ; DORA art.
30 § 2 g). La seconde phrase du point 3 s'inspire du Cm 27 pour la délégation
de l'audit à l'organe de révision de l'Exploitant, et du Cm 29 pour la remise
de son rapport (R6-F20). Ne fait pas : fixer la fréquence des audits, ce qui
relève du Client.

### CL-2 Accès au vérificateur et aux formats

1. L'Exploitant publie, pour toute la durée de conservation des journaux du
   Client et [n] ans au-delà, les spécifications des formats, les schémas,
   les vecteurs et le code du vérificateur, avec chacune de leurs versions,
   sous une licence qui permet au Client, au Réviseur et à l'Autorité de les
   exécuter, de les reconstruire et de les modifier pour leurs propres
   vérifications.
2. Aucune vérification d'un dossier ne requiert un compte, une clé, un
   service ni une connexion de l'Exploitant (CT-7 EX-8.10) ; l'Exploitant
   maintient cette propriété dans toute version.
3. L'Exploitant annonce tout changement de format [n] jours avant sa
   publication ; les dossiers produits sous une version antérieure restent
   vérifiables avec leurs règles.

Lignes de la matrice : MC-33, MC-52, MC-58 (DORA art. 30 § 3 e) ; Olico art. 6 ;
CO art. 958f al. 3). Passages sans ligne dans la matrice : aucun. Ne fait pas :
mettre à disposition le personnel et les moyens de consultation du Client.

### CL-3 Conservation, restitution et réversibilité

1. Le journal, les pièces, les manifestes, les preuves d'ancrage, les
   captures du registre et les clés de l'enregistreur sont tenus sur
   l'infrastructure que le Client désigne ; l'Exploitant n'en détient aucune
   copie nécessaire à leur vérification.
2. Les données que l'Exploitant tient pour le Client (inscriptions au
   registre, manifeste d'instance, jeux de validateurs, certificats de commit
   que ses validateurs gardent) sont restituées sur demande et à la fin du
   contrat dans un format documenté et facilement accessible, dans un délai
   de [délai].
3. En cas de résiliation, d'insolvabilité, de résolution ou de cessation
   d'activité de l'Exploitant, une période de transition de [durée] est
   garantie, pendant laquelle le registre reste lisible et le Client peut
   capturer tout certificat dont il a besoin.
4. L'Exploitant ne supprime aucune donnée qu'il tient pour le Client avant
   [échéance] sans l'accord écrit du Client.

Lignes de la matrice : MC-2, MC-8, MC-29, MC-32, MC-34, MC-47, MC-50
(communication FINMA 08/2024 ch. 2.1 ; circulaire FINMA 2018/3 Cm 18 et 18.1 ;
DORA art. 28 § 8, art. 30 § 2 d) et § 3 f) ; règlement (UE) 2024/1689 art. 19 §
1 et art. 26 § 6, les journaux restant sous le contrôle de qui les tient).
Passages sans ligne dans la matrice : aucun. Ne fait pas : la durée de
conservation que le Client doit tenir (section 8.8).

### CL-4 Sous-traitance

1. L'inventaire des composants tiers (CT-7 §8.6), avec leur exploitant, leur
   lieu, leur rôle et les données qu'ils reçoivent, est annexé au contrat.
2. L'Exploitant informe le Client [préavis] avant tout ajout, retrait ou
   changement d'un composant tiers, de son exploitant ou de son lieu ; le
   Client peut s'y opposer et mettre fin aux prestations de manière ordonnée.
3. L'Exploitant transfère à ses sous-traitants les obligations et garanties
   nécessaires au respect du présent contrat, droits d'audit (CL-1) compris.

Lignes de la matrice : MC-2, MC-7, MC-14, MC-27, MC-30 (communication FINMA
08/2024 ch. 2.1 ; circulaire FINMA 2018/3 Cm 14, 33 et 34 ; DORA art. 28 § 3 et
art. 29 § 2). Passages sans ligne dans la matrice, cités pour orientation,
correspondance non établie par 8.4 : DORA art. 30 § 2 a). Ne fait pas :
l'évaluation de la chaîne de sous-traitance, qui relève du Client.

### CL-5 Notification d'incident

1. L'Exploitant notifie au Client, sans retard injustifié et au plus tard
   [délai], tout incident qui touche les preuves du Client : compromission
   ou soupçon de compromission d'une clé du registre, indisponibilité du
   registre au-delà de [durée], perte de certificats de commit, fourche,
   défaut publié d'une version du vérificateur ou d'un format, compromission
   du canal de publication.
2. La notification nomme la nature de l'incident, les périodes et journaux
   touchés, ce que les dossiers déjà exportés prouvent encore, les mesures
   prises et un contact.
3. L'Exploitant tient et teste des plans d'urgence pour ces incidents
   [fréquence].
4. Le Client notifie à l'Exploitant la compromission d'une clé
   d'enregistreur ou de chaîne inscrite au registre, pour sa révocation.

Lignes de la matrice : MC-2, MC-10 (communication FINMA 08/2024 ch. 2.1 ;
circulaire FINMA 2018/3 Cm 24 et 25). Passages sans ligne dans la matrice, cités
pour orientation, correspondance non établie par 8.4 : DORA art. 30 § 3 b)
(préavis et obligations de notification du prestataire) et § 3 c) (plans
d'urgence), R6-F66. Ne fait pas : la notification que le Client doit à son
autorité ; l'assistance en cas d'incident de DORA art. 30 § 2 f), que le Client
stipule ; les droits de résiliation de DORA art. 28 § 7, qui relèvent du Client.

### CL-6 Lieux de traitement et exigences de sécurité

1. Les lieux (pays ou régions) où le registre, ses nœuds, son RPC et la
   publication du vérificateur sont exploités, et ceux où les données du
   Client que l'Exploitant reçoit sont traitées et stockées, sont annexés au
   contrat ; tout changement suit CL-4.
2. Les exigences de sécurité de l'Exploitant sont celles des spécifications
   publiées [liste des sections retenues] ; l'Exploitant en démontre le
   respect au Client et au Réviseur sur demande.

Lignes de la matrice : MC-10, MC-13, MC-31 (circulaire FINMA 2018/3 Cm 24, 30 et
31 ; DORA art. 30 § 2 c)). Passages sans ligne dans la matrice, cités pour
orientation, correspondance non établie par 8.4 : DORA art. 30 § 2 b). Ne fait
pas : le choix des lieux d'hébergement du Client.
