# CT-5 — Ancrage

Version 0.2, 2026-10-26 (la version 0.1 est du 2026-10-25). Spécification
normative, soumise à la revue de la porte 1 du plan de projet (document
interne). Elle met en œuvre les points 2
et 3 de la section « Ancrage » de l'[architecture cible](../ARCHITECTURE.md)
(horodatage qualifié RFC 3161, ancrage public OpenTimestamps) et son option
« serveur RFC 3161 interne, non qualifié », et elle fixe la cadence à laquelle
le point de contrôle de [CT-1](CT-1-evenements-et-formats.md) (révision 0.3,
§10.5 à §10.9) est ancré au registre de [CT-4](CT-4-registre.md), contresigné
par une autorité RFC 3161 et, en option, horodaté par OpenTimestamps. Elle
s'appuie sur les formats v0 de CT-1 sans les modifier, reprend ce que
[CT-2](CT-2-enregistreur.md) produit à chaque point et à chaque clôture et ce
qu'il attend d'un ancrage jamais bloquant (CT-2 §14.2), et se conforme à ce que
[CT-6](CT-6-verificateur.md) §13.1, §13.2 et, depuis sa révision 0.2, §13.4
(EX-13.14 à EX-13.19) exigent de CT-5. Elle ne change ni CT-4 ni CT-6 : ce
qu'elle leur demande est écrit en section 14 et repris par leurs révisions,
écrites avec ce lot (CT-4 0.3 : le libellé de `docType` du point, §6.4 et
EX-6.6 ; CT-6 0.2 : la vérification de la partie `points-de-controle.json`,
§5.4, §7.9, §11.9 et §13.4).

**Révision 0.2.** Elle applique la revue de la version 0.1 : points produits
aux instants alignés `period_start + j × c_K` et plafond de `2 + 3600 / c_K`
ancres par heure (EX-4.1, 4.3, EX-9.8, EX-12.1, coût et provision recalculés) ;
décomposition de `d_jeton` (EX-3.5) ; dernier point contresigné défini par les
jetons obtenus ou en cours, échéances rendues sur refus (EX-4.3, EX-8.4) ;
repli de clôture sur le point de clôture quand le registre tarde (EX-4.2) ;
ligne `envoyee` avant l'envoi (EX-8.5, AN-32) ; transitions `envoyee →
a_envoyer` et `obtenue → a_reprendre` (EX-8.3) ; reconstruction de la file à
chaque démarrage et fichiers d'époque (EX-8.5, EX-8.12) ; choix du point
couvrant par rang d'ancre (EX-10.2) ; complétude au registre (EX-10.7, AN-61) ;
`W_ordre` réécrit (3.3, 13) ; alertes `point_manquant`,
`jeton_anterieur_au_point`, `contresignature_tardive`,
`reponse_tardive_promue` (8.9) ; secours qualifié en production (EX-4.9) ;
précisions d'EX-5.7 à EX-5.11, EX-6.1, EX-8.8, EX-8.10, §11, §12.2, §13 ;
vecteurs portés à vingt et une traces et à la famille `completude` (annexe A).
Elle s'accompagne de CT-1 révision 0.3 précisée (alignement, choix du point
couvrant), de CT-2 révision 0.4 (production des points), de notes de CT-4
révision 0.3 et de précisions de CT-6 révision 0.2 (§7.9, AV-K-4).

La spécification a deux parties. La **partie A** (sections 0 à 6) dit ce que
l'ancrage prouve et ne prouve pas, quelle fenêtre de réécriture il laisse,
à quelles cadences il travaille, et comment se construisent, octet pour
octet, une requête d'horodatage RFC 3161, la vérification d'un jeton avant
son stockage, un fichier OpenTimestamps et le fichier d'en-têtes Bitcoin. Un
développeur qui écrit un client d'ancrage peut s'y arrêter : elle suffit pour
produire une requête, vérifier et conserver un jeton, soumettre un condensé à
des calendriers et remettre les pièces au dossier. La **partie B** (sections 7
à 15 et annexes) dit comment s'exploite le serveur RFC 3161 interne optionnel,
comment le planificateur tient sa file d'attente durable et reprend après une
panne, comment les points sont ancrés au registre, ce qui est remis à
l'exportateur et au réviseur, quelles sont les contraintes techniques des
prestataires retenus, combien coûte un journal par an pour un prix unitaire
donné, quelles menaces sont traitées, ce que la version ne couvre pas,
comment les vecteurs sont disposés et d'où viennent les faits externes.

## 0. En-tête et conventions

Les mots DOIT, NE DOIT PAS, DEVRAIT et PEUT ont le sens de la RFC 2119, comme
dans CT-1, CT-2, CT-3, CT-4 et CT-6.

Chaque règle normative porte un identifiant **EX-<section>.<n>** (EX-5.3 :
troisième règle de la section 5), stable, auquel le plan de tests (CT-9)
attache ses tests. Les identifiants sont numérotés dans l'ordre du texte à
l'intérieur de chaque section de premier niveau, sous-sections comprises. Une
règle ajoutée par une révision reçoit le numéro qui suit le plus grand de sa
section ; aucun numéro n'est réattribué ; une règle retirée garde son numéro,
marqué « retiré ».

Les vérifications élémentaires portent l'identifiant de leur famille :

| Famille | Objet | Définie par |
|---|---|---|
| AN- | Ce que l'ancrage calcule et contrôle : configuration, échéances, choix des points, requête RFC 3161 et vérification du jeton avant stockage, fraîcheur, classement des erreurs, stockage et conservation, soumission et fichier OpenTimestamps, mise à niveau, fichier d'en-têtes, remise au dossier (partie A : AN-1 à AN-21, table en 6.8) ; serveur interne, file d'attente et reprise, ancre des points au registre, remise à l'exportateur et au réviseur, prestataires, coût, complétude au registre (partie B : AN-22 à AN-61 ; table complète AN-1 à AN-61 en annexe A.8) | sections 4, 5, 6 ; sections 7 à 12 |
| K- | Vérification de la partie `points-de-controle.json` d'un dossier | CT-1 §11.4, reprise sans changement ; CT-6 (révision 0.2) fixe les contrôles où elle compte |
| T-, O-, R-, N- | Contrôles 4, 5 et 8 et fichier d'ancres du réviseur | CT-6 §9 à §12, reprises sans changement ; CT-5 exécute T-1 à T-9 à l'acquisition, sur l'empreinte demandée (5.4) |
| RG-, OP-, CP- | Conventions, outils et capture du registre | CT-4 §6, §7.3, §9.4, reprises sans changement |

Les documents JSON de CT-5 suivent les encodages de CT-1 §3 : octets en
hexadécimal minuscule préfixé `0x` ; horodatages RFC 3339 en UTC à trois
décimales ; entiers JSON dans `[0, 2^53 − 1]`, au-delà chaîne décimale ;
base64 (RFC 4648 §4, alphabet standard, remplissage `=`, sans saut de ligne)
pour les seuls fichiers binaires embarqués dans `points-de-controle.json`
(CT-1 §3, révision 0.3). Les clés JSON sont en anglais ; les valeurs
énumérées sont en français, sans accent (`principal`, `second_rang`,
`nouveaux_evenements`, `mi_periode`, `transitoire`). Les fichiers binaires
(requête `TimeStampReq`, réponse `TimeStampResp`, jeton `TimeStampToken`,
fichier `.ots`) sont écrits et conservés **tels que produits ou reçus**,
jamais réencodés (CT-6 EX-13.3).

Notation : `‖` concatène des octets ; `SHA-256` est le SHA-256 de FIPS 180-4
et `keccak256` le Keccak-256 de l'EVM (CT-4 §0) ; `P_M ‖ C_M` est le
manifeste préfixé de CT-1 §10.2 (empreinte `periodHash`) et `P_K ‖ C_K` le
point de contrôle préfixé de CT-1 §10.6 (empreinte `checkpointHash`) ; `c_K`
est la cadence de production des points (`checkpoint_interval_s`, CT-1
§10.5), `c_T` la cadence des contresignatures RFC 3161 des points
(`rfc3161.checkpoints.interval_s`) ; `D_k` la `k`-ième échéance de
contresignature d'une période ; `d_registre`, `d_jeton`, `d_bitcoin` les
délais d'obtention de chaque ancre (3.3) ; `W` la fenêtre de réécriture
(3.3) ; les durées sont en secondes (`s`) sauf mention contraire. « L'heure »
désigne la période de CT-1 §2 : une heure UTC pleine `[period_start,
period_end)`.

« La référence » désigne l'implémentation JavaScript de ce lot :
`scripts/lib/journal.mjs` (construction et vérification d'un point de
contrôle, preuve de cohérence, partie de dossier, CT-1 §10.5 à §11.2) et
`scripts/lib/ancrage.mjs` (planificateur à horloge injectée : échéances, file
d'attente, reprise, choix du prestataire ; construction d'une `TimeStampReq`
DER ; construction d'un fichier `.ots` ; formule de coût ; sans réseau), avec
le générateur `scripts/vecteurs/generer-ct5.mjs` et les tests. Elle et le
vérificateur Go indépendant de `spec/vecteurs/ct-5/verificateur-independant`
(annexe A), écrit depuis cette seule spécification, rendent sur les mêmes
entrées les mêmes octets et les mêmes verdicts AN- ; des implémentations
tierces confrontent les sorties (annexe A : `openssl ts -query -in -text` sur
les requêtes, `python-opentimestamps` sur les fichiers `.ots`, `openssl ts
-verify` sur les jetons). Les fonctions nommées dans ce document sont celles
de la référence ; une autre implémentation peut nommer les siennes autrement.

Les faits externes viennent de deux notes de recherche du lot CT-5, internes
et non publiées, relues le 2026-10-25 sur les sources primaires qu'elles
citent (textes des RFC 3161, 5035, 5816, 6962 et 9162 ; politiques et guides
publics des prestataires d'horodatage ; listes de confiance signées ; code et
documentation officiels d'OpenTimestamps et des outils cités) : **R1**
(prestataires RFC 3161, OpenTimestamps, reprise ; faits R1-F1 à R1-F73) et
**R2** (points de contrôle, cohérence, stockage à verrou d'objet ; faits R2-F1
à R2-F61). Un fait est cité par son numéro ; l'annexe B donne la
source, la ligne et la date de chacun. Ce que ces notes n'ont pas pu établir
est marqué « non vérifié » dans le texte et listé en annexe B. Aucun prix ne
figure dans cette spécification : la formule de coût (section 12) prend le
prix unitaire d'un jeton en paramètre, et les devis viennent après la
conception. La parité avec les produits comparables s'écrit en exigences
mesurables (3.6), jamais par un nom.

## 1. Objet, périmètre et relations

CT-5 fixe, pour la version 0 de l'ancrage :

1. le modèle : les deux objets ancrés (manifeste, point de contrôle), les
   trois ancres, ce que chacune prouve et ne prouve pas, la fenêtre de
   réécriture qui en résulte et sa formule, les adversaires et les hypothèses
   (section 3) ;
2. les cadences : production des points (lue de CT-2), ancre des points au
   registre, contresignature RFC 3161 des points, clôture horaire qualifiée,
   OpenTimestamps ; le document de configuration `ancrage-v0` et ses bornes ;
   ce qui est obligatoire et ce qui est optionnel (section 4) ;
3. le client RFC 3161 : la requête, octet pour octet ; le transport ; le
   choix du prestataire (principal, secours, second rang, interne) ; la
   vérification du jeton avant stockage, par les vérifications T- de CT-6 ;
   le classement des erreurs ; le stockage et la conservation dix ans
   (section 5) ;
4. le client OpenTimestamps : l'empreinte, la soumission aux calendriers, le
   fichier `.ots`, la mise à niveau, la source d'en-têtes Bitcoin, ce qui est
   remis au dossier (section 6) ;
5. le serveur RFC 3161 interne non qualifié (section 7), le planificateur, sa
   file durable et sa reprise (section 8), l'ancre des points au registre
   (section 9), ce qui est remis à l'exportateur et au réviseur (section 10),
   les contraintes techniques de deux prestataires tirées de leur
   documentation publique (section 11), la formule de coût (section 12), la
   sûreté (section 13), l'alignement avec le dépôt (section 14), ce que la
   version ne couvre pas (section 15), les vecteurs (annexe A) et les sources
   (annexe B).

Hors périmètre : les formats de l'événement, du manifeste, du point de
contrôle, de la preuve de cohérence et du dossier (CT-1, révision 0.3,
inchangés par CT-5) ; la production des points et des manifestes, la clé de
l'enregistreur et la clé de chaîne (CT-2) ; la politique d'approbation
(CT-3) ; les contrats, l'encodage des transactions, la capture et la conduite
d'envoi au registre (CT-4, que le texte de CT-5 ne modifie pas : ce que CT-5
lui demande, la cadence des ancres de points et un libellé, est porté par la
révision 0.3 de CT-4) ; le vérificateur, les contrôles 4, 5 et 8 et l'énoncé
(CT-6, que le texte de CT-5 ne modifie pas : la vérification de la partie
`points-de-controle.json` est portée par la révision 0.2 de CT-6 ; CT-5
produit les parties et réutilise ses vérifications à l'acquisition) ; la relation contractuelle avec les
prestataires et leurs prix ; la validation à long terme des jetons
(renouvellement d'horodatage, CT-6 §17 ; section 15) ; la cérémonie des
identifiants de prestataire (CT-7) ; la supervision au-delà des métriques
et alertes que la section 8 prescrit (CT-8) ; le plan de tests (CT-9).

Ce que la version 0 livre :

| Élément | Livré |
|---|---|
| Cette spécification ; les schémas `spec/schemas/ancrage-v0.schema.json` (4.4) et `spec/schemas/planificateur-ancrage-v0.schema.json` (8.10, annexe A) | avec CT-5 |
| La référence JavaScript : `scripts/lib/journal.mjs` (point de contrôle, preuve de cohérence, partie de dossier) et `scripts/lib/ancrage.mjs` (planificateur à horloge injectée, requête DER, fichier `.ots`, formule de coût ; sans réseau) ; `scripts/lib/verificateur.mjs` et `scripts/verify/dossier.mjs` pour la partie (CT-6 0.2) | avec le lot CT-5 |
| Les vecteurs `spec/vecteurs/ct-5` (annexe A) et les familles `points-de-controle/` et `merkle/coherence.json` de `spec/vecteurs/ct-1` (CT-1 §13), leurs générateurs et leurs tests | avec le lot CT-5 |
| Les vérificateurs Go indépendants : extension de `spec/vecteurs/ct-1/verificateur-independant` (points, cohérence) et `spec/vecteurs/ct-5/verificateur-independant` | avec le lot CT-5 |
| La confrontation par des implémentations tierces : `openssl ts` sur les requêtes et les jetons, `python-opentimestamps` sur les fichiers `.ots` (annexe A) | avec le lot CT-5 |
| Le contrat avec un prestataire principal et un prestataire de secours (section 11), leurs identifiants d'accès et la procédure de qualification (5.3) | après la porte 1 ; les devis viennent après la conception |
| Le serveur RFC 3161 interne en production (section 7) | optionnel ; le réseau de développement et les vecteurs en emploient un |

Relations avec les autres spécifications :

| Spécification | Ce que CT-5 lui fournit | Ce que CT-5 en attend |
|---|---|---|
| CT-1 (révision 0.3) | Les ancres d'un point de contrôle pour la partie `points-de-controle.json` : jeton RFC 3161 sur `checkpointHash`, référence de l'ancre au registre, preuve `.ots` du fichier `P_K ‖ C_K` (CT-1 §11.2 ; section 10) ; les constantes de nonce des vecteurs (CT-1 §13) ; les cadences dont CT-1 §10.9 reprend les valeurs par défaut (60 s, 300 s) | Le format du point (§10.5), ses préfixes et `checkpointHash` (§10.6), la preuve de cohérence (§10.7), la partie du dossier et sa disposition unique, ancres embarquées en base64 (§11.2), les vérifications K-1 à K-9 (§11.4), inchangés |
| CT-2 | La cadence des contresignatures et des ancres, les états et les alertes de l'ancrage (sections 4 et 8), le document de configuration `ancrage-v0` que `anchoring` désigne (4.4, section 14), les fichiers d'ancres sous `storage.root` (5.5), ce que la copie WORM doit couvrir (5.5, section 14) | Un point de contrôle toutes les `checkpoint_interval_s` secondes au plus et un à la clôture (CT-1 §10.5, règle 1), le manifeste et sa signature à la clôture, remis au composant d'ancrage sans attendre son résultat (CT-2 §14.2 : jamais bloquant, `anchor_pending`, `registry_pending`) ; la clé de chaîne qui signe les ancres (CT-2 EX-11.19) ; l'horloge de CT-2 §7.4 ; la disposition du stockage (§12.1), la copie WORM (§12.6) et la rétention (§12.7) ; les métriques et alertes (§17) |
| CT-4 | La cadence des ancres de points et leur nombre par jour, dont le budget de provision d'EX-4.19 doit tenir compte (4.3, section 9) ; l'ordre « ancre du registre envoyée, puis requête RFC 3161 » pour les points, qui étend EX-8.4 (4.3) ; l'empreinte d'un point, `keccak256(org_id ‖ journal_id ‖ checkpointHash)` (CT-1 §10.6) | Le libellé `noortrace/point-de-controle/v0` et sa valeur dans la table de `docType` (CT-4 §6.4, révision 0.3) ; le gaz d'`anchor` (§4.5) ; l'encodage de l'appel et de la transaction (§6.7) ; la conduite d'envoi, de reprise et de remplacement (§8) ; la capture des transactions pour K-8 (§9.4) |
| CT-6 | Les parties `jeton-rfc3161.der` et `preuve.ots` du manifeste, les ancres embarquées d'un point, le fichier `entetes-bitcoin.json` hors des parties (EX-13.7), les CRL capturées après `genTime` (EX-13.12), publiées pour le réviseur (section 10) ; l'étiquette « non qualifié » du serveur interne pour le fichier d'ancres | Les vérifications T- et O-, réutilisées sur l'empreinte demandée : T-1 à T-9 à l'acquisition (EX-5.10, étape 6), T-10 après le délai `crl_capture.delay_s` (étape 10), jamais T-11, puisque `qualified` est déclaratif (EX-5.9) ; les O- à la création et à la mise à niveau des preuves (6.3, 6.4) ; EX-13.1 à EX-13.7, EX-13.12, EX-13.13 et, pour les points, EX-13.14 à EX-13.19 (§13.4, révision 0.2), reprises comme exigences propres ; le format du fichier d'ancres (§12.2) ; la révision 0.2, écrite : K-1 à K-9 rattachées aux contrôles 3, 6, 2, 4, 8 et 5 (§5.4, EX-5.7), raisons de non-exécution (EX-5.9), rôle `ancre_point_de_controle` de `registre.json` et vérification R-11 (§11.9), fragment FK de l'énoncé (EX-6.16), `facts.checkpoint` (EX-6.17), section 7.9 |
| CT-7 | L'inventaire des secrets de l'ancrage (identifiants et certificats client des prestataires, 4.4) et de ce qu'un composant d'ancrage compromis peut faire (3.4) | La garde et la rotation de ces secrets ; la procédure par laquelle l'exploitant établit et renouvelle le statut qualifié d'un prestataire (5.3) |
| CT-8 | Les métriques, alertes et procédures d'exploitation de la file et de la reprise (section 8), l'exploitation du serveur interne (section 7), la rétention des jetons (5.5), la mise à jour du fichier d'en-têtes Bitcoin (6.6) | La supervision, la sauvegarde de la file, la publication des pièces aux réviseurs |
| CT-9 | Les identifiants EX- et AN-, les vecteurs `spec/vecteurs/ct-5` (annexe A) ; l'épreuve d'acceptation à l'aveugle : un relecteur qui n'a que CT-5 et CT-1 §9 à §11 dit la cadence des points, ce qu'un point prouve et ne prouve pas, la fenêtre de réécriture, le coût annuel d'un journal pour un prix unitaire donné et ce qui se passe quand le prestataire est injoignable ; un second relecteur relit CT-6 §7 révisée et décrit ce que le verdict prouve de nouveau | Les tests |

## 2. Terminologie

| Terme | Définition |
|---|---|
| Ancre | Preuve extérieure à l'enregistreur qu'une empreinte existait à un instant ou avant un événement observable : jeton RFC 3161 (date, selon une autorité), transaction du registre (ordre, selon un quorum de validateurs), attestation Bitcoin d'une preuve OpenTimestamps (antériorité à un bloc, sans autorité). L'architecture en prévoit trois par période ; CT-5 les applique aussi aux points de contrôle. |
| Objet ancré | Le manifeste préfixé `P_M ‖ C_M` (empreinte `periodHash`, CT-1 §10.2) ou le point de contrôle préfixé `P_K ‖ C_K` (empreinte `checkpointHash`, CT-1 §10.6). Une ancre porte sur l'empreinte ; la TSA ne reçoit que ses 32 octets. |
| Point de contrôle | Tête signée de l'arbre de la période en cours (CT-1 §10.5), produite par l'enregistreur toutes les `c_K` secondes au plus et à la clôture. |
| Clôture | Fin d'une période : manifeste, signature, puis ses trois ancres (CT-1 §10, CT-4 §8.2). |
| Contresignature | Jeton RFC 3161 obtenu sur `checkpointHash` d'un point de contrôle, à cadence `c_T` ; « contresignature qualifiée » quand le prestataire est qualifié (ci-dessous). |
| Prestataire | Autorité d'horodatage RFC 3161 joignable par HTTP. Rôles : **principal** (qualifié, manifeste et, par défaut, points), **secours** (qualifié, relève du principal), **second rang** (toute autorité RFC 3161, qualifiée ou non, pour les points intermédiaires), **interne** (serveur RFC 3161 du client, non qualifié, section 7). |
| Qualifié | Statut mesurable d'un prestataire : son unité d'horodatage figure dans un service de type `http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST` au statut `granted` d'une liste de confiance nationale référencée par la liste des listes de la Commission européenne (R1-F48), ou, en Suisse, dans la liste de confiance suisse comme service reconnu (CT-6 §12.5) ; établi par l'exploitant à une date, pour une liste de numéro de séquence donné (5.3). Jamais une déclaration du prestataire seule (R1-F43). |
| Jeton | `TimeStampToken` (RFC 3161 §2.4.2) extrait d'une `TimeStampResp`, en DER, non réencodé. |
| Nonce | Entier aléatoire de 64 bits de la requête, que la réponse DOIT reprendre (RFC 3161 §2.4.1 et §2.4.2, R1-F1, R1-F2) ; fraîcheur de la réponse, jamais une date. |
| Fraîcheur | Propriété d'une réponse reçue dans le délai admis après la requête qui porte son nonce (RFC 3161 §4, point 4, R1-F13). |
| Fenêtre de réécriture `W` | Durée pendant laquelle une réécriture d'un événement par qui détient la clé de l'enregistreur reste indétectable : `W = T − t_e`, `T` étant l'instant de la première ancre extérieure qui engage l'événement (CT-1 §10.9 ; 3.3). |
| Échéance `D_k` | Instant `period_start + k × c_T` auquel le planificateur demande la contresignature d'un point (4.2). |
| Délai d'obtention `d` | Durée entre une échéance et l'instant que l'ancre prouve, au sens strict pour `d_jeton` seul : `d_jeton = genTime + précision − D_k` pour un point, `− period_end` pour un manifeste (EX-5.11), le seul instant prouvé, selon l'autorité. Les deux autres délais n'ont pas la même nature : `d_registre` = instant de réception du reçu, lu sur l'horloge de l'enregistreur, `− checkpoint_ts` (`− generated_at` pour un manifeste ; P-2, EX-8.15), mesure de supervision sans échéance (l'ancre d'un point part dès son admission, EX-4.6) et sans instant prouvé (le registre ne date rien, 3.2) ; `d_bitcoin` compte jusqu'à la création du bloc attesté, instant qui n'est pas prouvé non plus. |
| Calendrier, agrégateur | Serveur OpenTimestamps qui reçoit un condensé (`POST /digest`), le journalise, l'agrège dans un arbre et l'inscrit dans Bitcoin, puis sert la preuve complète (`GET /timestamp/<engagement>`) ; les agrégateurs publics relaient vers les calendriers (R1-F56, R1-F64, R1-F65). |
| Preuve en attente | Fichier `.ots` dont les attestations sont toutes « en attente » (étiquette `83dfe30d2ef90c8e`) : un engagement et une URI de calendrier, promesse d'inclusion non vérifiable sans le calendrier (R1-F59, R1-F60). Elle ne prouve rien (CT-6 O-7). |
| Mise à niveau | Remplacement d'une attestation en attente par le chemin complet jusqu'à une attestation Bitcoin (`0588960d73d71901`), obtenu du calendrier (R1-F58, R1-F62). |
| File d'attente | Journal durable, en ajout seul, des demandes d'ancrage et de leurs tentatives, écrit avant tout envoi (section 8). |
| Tentative | Une requête envoyée à un prestataire ou à un calendrier, avec son nonce, son instant et son résultat ; une demande peut compter plusieurs tentatives. |
| Composant d'ancrage | Ce que CT-5 spécifie : il s'exécute dans le démon de l'enregistreur (CT-2 §3.4) ou comme service compagnon sous le même contrôle ; il ne détient aucune clé Ed25519 ; les transactions du registre sont signées par la clé de chaîne de CT-2 EX-11.19 ; ses seuls secrets sont les identifiants d'accès aux prestataires. |

## 3. Modèle

### 3.1 Deux objets, trois ancres

L'architecture ancre une empreinte par heure et par journal, `periodHash`,
par trois moyens indépendants. CT-1 (révision 0.3) ajoute un second objet, le
point de contrôle, dont l'empreinte `checkpointHash` reçoit les mêmes ancres à
cadence courte. Rien d'autre n'est ancré : ni racine seule (une racine se
répète, CT-6 §9.1), ni événement, ni pièce.

| Objet ancré | Empreinte | Ancre au registre (CT-4) | Ancre RFC 3161 | Ancre OpenTimestamps | Cadence |
|---|---|---|---|---|---|
| Manifeste de période, `P_M ‖ C_M` (CT-1 §10.2) | `periodHash` | `AttestationRegistry.anchor(keccak256(org_id ‖ journal_id ‖ periodHash), docType noortrace/periode/v0)`, puis `PeriodRegistry.submitPeriod` (CT-4 §6.4 à §6.6, §8.2) | Jeton **qualifié** du prestataire principal sur `periodHash` (CT-6 §9, EX-13.1 à EX-13.4) | Fichier `.ots` du fichier `P_M ‖ C_M`, au moins deux calendriers (CT-6 §10, EX-13.5) | Une fois par heure, à la clôture (CT-1 décision 1) |
| Point de contrôle, `P_K ‖ C_K` (CT-1 §10.6) | `checkpointHash` | `AttestationRegistry.anchor(keccak256(org_id ‖ journal_id ‖ checkpointHash), docType noortrace/point-de-controle/v0)` (CT-1 §10.6 ; CT-4 §6.4 révision 0.3 ; section 9) | Jeton sur `checkpointHash`, par le prestataire principal, ou pour les points intermédiaires par un prestataire de second rang ou le serveur interne si la configuration le dit (4.2, 5.3) | En option, un point par période (4.2, section 6) | Points produits toutes les `c_K` s (défaut 60) et à la clôture ; ancre au registre à chaque point qui engage un nouvel événement ; contresignature toutes les `c_T` s (défaut 300) |

**EX-3.1** Le composant d'ancrage n'ancre que ces deux objets, et seulement
par leur empreinte : `periodHash` recalculé depuis le manifeste signé que la
clôture lui remet, `checkpointHash` recalculé depuis le point signé que
l'enregistreur lui remet (CT-1 §10.6, `hachagePointDeControle`). Il vérifie la
signature de l'objet sous la clé en vigueur avant d'en ancrer l'empreinte
(AN-3) : une empreinte dont l'objet ne vérifie pas n'est pas ancrée, et le
défaut est consigné et alerté (section 8). Il ne remet jamais aux prestataires
ni aux calendriers autre chose que des octets d'empreinte ou d'engagement
(32 octets) : aucun événement, aucune pièce, aucun identifiant de journal.

### 3.2 Ce que chaque ancre prouve, et ne prouve pas

Ce que prouve chaque ancre d'une période est fixé par CT-6 §7 (contrôles 4, 5
et 8) ; ce que prouve chaque ancre d'un point est fixé par CT-1 §10.9. CT-5
n'y ajoute rien et ne retire rien ; il en fixe la cadence et la conduite. Le
résumé qui suit sert à lire la section 3.3.

| Ancre | Prouve, quand sa vérification réussit (CT-6 §7, CT-1 §10.9) | Ne prouve pas |
|---|---|---|
| Jeton RFC 3161 | L'empreinte existait au plus tard à `genTime` augmenté de la précision du jeton, selon l'autorité qui l'a signé (CT-6 EX-9.20) ; la force de cette date est celle de l'autorité : qualifiée (présomption légale, architecture « Ancrage et droit de la preuve »), de second rang, ou interne (seulement qu'une clé de l'exploitant a signé ce condensé et cette heure déclarée, R1-F55). | Une borne « pas avant » ; que l'autorité était digne de confiance (hypothèses H3 et H4 de CT-6, fichier d'ancres du réviseur) ; la date de l'événement lui-même, dont `ts` reste déclaratif (CT-1 §15). |
| Ancre au registre | Sous H6 et H7 : l'ordre, entre les blocs, de l'empreinte par rapport aux autres empreintes ancrées, et l'unicité de l'empreinte sur la chaîne (CT-4 §3.4, §8.3). | Aucune date : l'horodatage d'un bloc est choisi par son proposant (CT-6 §7, §11.8). |
| Attestation Bitcoin (OpenTimestamps) | L'empreinte existait avant la création d'un bloc Bitcoin, sous `k` confirmations, sans aucune autorité (CT-6 §10, H5). | Rien avant l'inclusion dans Bitcoin : une preuve en attente ne prouve rien (CT-6 O-7 ; R1-F59, R1-F60) ; l'inclusion prend des heures (6.5). |
| Signature du point par l'enregistreur | Une attribution à la clé `key_id` (CT-1 §10.9). | Rien contre qui détient cette clé. |

**EX-3.2** Aucune date portée par un objet ancré (`ts` d'un événement,
`generated_at` d'un manifeste, `checkpoint_ts` d'un point) n'est tenue pour
prouvée par le composant d'ancrage, par l'exportateur ni par le réviseur :
seule la contresignature extérieure date (CT-1 §10.5, `checkpoint_ts`
déclaratif). Le composant d'ancrage emploie l'horloge de l'enregistreur (CT-2
§7.4) pour planifier ses échéances et contrôler la fraîcheur (5.4), jamais
pour produire une preuve.

### 3.3 Fenêtre de réécriture

Qui détient la clé de l'enregistreur (ou l'usage de son signataire, CT-6
§3.4) peut réécrire et signer de nouveau tout ce qu'aucune ancre extérieure
n'engage encore. Pour un événement de `ts = t_e`, la fenêtre pendant laquelle
une réécriture reste indétectable est `W = T − t_e`, où `T` est l'instant que
prouve la première ancre extérieure qui engage l'événement (CT-1 §10.9). Trois
fenêtres coexistent, une par nature d'ancre, parce que chaque ancre prouve une
chose différente (3.2) :

| Fenêtre | Ancre | Borne, points de contrôle en service (CT-5) | Borne, ancres horaires seules (CT-6 §3.4, CT-1 §10.9) | Valeurs par défaut |
|---|---|---|---|---|
| `W_ordre` : durée de conception après laquelle l'empreinte d'un point qui engage l'événement figure au registre ; l'ancre fixe l'ordre relatif de deux versions présentées ensemble et l'unicité de l'empreinte (sous H6 et H7), ne date rien et n'empêche aucune autre version d'être ancrée (ci-dessous) | registre | `W_ordre ≤ c_K + d_registre` : l'événement est engagé par le premier point aligné qui le suit, produit au plus `c_K` après lui (CT-1 §10.5, règle 1), dont l'ancre est incluse `d_registre` plus tard (4.3) ; durée mesurée par l'exploitant (P-2), qu'aucun dossier ne prouve | `W_ordre ≤ 3600 + d_clôture + d_registre` | `60 s + d_registre` ; `d_registre` est de l'ordre d'un intervalle de bloc en fonctionnement nominal (CT-4 §9.5 : 1,10 à 1,14 bloc par seconde mesurés sur le réseau de développement), alerte au-delà de `registry.inclusion_alert_s` (défaut 60 s) |
| `W_date` : après `T`, une réécriture est contredite par un jeton dont la date fait foi selon son autorité | RFC 3161 | `W_date ≤ c_T + d_jeton` : l'événement est engagé par le premier point dont `checkpoint_ts ≥ D_k`, `D_k` étant la première échéance qui suit `t_e` (`D_k − t_e ≤ c_T`), et le jeton de ce point porte `genTime + précision = D_k + d_jeton` (4.2), avec `d_jeton = d_point + d_attente + d_relève + d_tsa` (EX-3.5) | `W_date ≤ 3600 + d_clôture + d_jeton` | `300 s + d_jeton` par le prestataire désigné pour les points ; pour la clôture, `3600 s + d_clôture + d_jeton` par le prestataire qualifié, comme avant |
| `W_bitcoin` : après `T`, une réécriture est contredite sans aucune autorité | OpenTimestamps | avec l'option `mi_periode` (EX-6.1) : `W_bitcoin ≤ k_m × c_T + d_point + d_bitcoin` pour les événements de `ts < D_{k_m}`, `k_m = ⌈n_T / 2⌉` (`d_point` : délai entre `D_{k_m}` et le point sélectionné, EX-3.5), soit 1800 s pour `c_T = 300` (`D_6`) et 2160 s pour `c_T = 720` (`D_3`) ; avec `n_T` impair, « la première moitié » se lit « avant `D_{k_m}` » ; `3600 + d_clôture + d_bitcoin` pour les autres événements ; sans `mi_periode` (le défaut), `3600 + d_clôture + d_bitcoin` pour tous | `W_bitcoin ≤ 3600 + d_clôture + d_bitcoin` | `d_bitcoin` se compte en heures (6.5) : cette fenêtre n'est pas celle qui borne la réécriture, c'est celle qui survit à la défaillance d'une autorité |

**EX-3.3** Avec la configuration par défaut de la section 4 (`c_K = 60 s`,
`c_T = 300 s`, ancre au registre de chaque point qui engage un nouvel
événement, contresignature des points par le prestataire principal), la
conception borne la fenêtre de réécriture d'un événement à **`300 s + d_jeton`
pour la date**, et fixe à **`60 s + d_registre`** la durée de conception de la
fenêtre d'ordre (`W_ordre`, ci-dessous : ce n'est pas une borne de réécriture
qu'un dossier prouve), contre `3600 s + d_clôture + d_jeton` avec les seules
ancres horaires. Ces valeurs sont des propriétés de la conception ; la
supervision mesure `d_jeton` et `d_registre`
sur chaque ancre obtenue (AN-2) et lève une alerte quand une échéance n'est
pas satisfaite avant la suivante (4.2, section 8). Pendant une panne totale
des prestataires des points, `checkpoint_anchor_late` ne part qu'au retour,
quand une échéance postérieure est satisfaite (EX-8.4, règle 1) ; l'alerte est
alors portée par `prestataire_injoignable` à 15 min (8.9), et la jauge
`noortrace_anchoring_window_s` montre la dérive de `W_date` dès qu'elle
commence. Aucune alerte n'est levée sur cette jauge seule : elle croît aussi,
sans défaut, pour un journal sans activité (échéances `sans_objet`) et ne
mesure rien avec un prestataire des points `interne`. Le vérificateur de dossier,
lui, ne mesure rien : il énonce la borne `T` que le dossier porte (CT-6 §7.9,
révision 0.2, fragment FK d'EX-6.16 : « l'événement est couvert par le point
de contrôle du journal de taille … de sa période …, horodaté au plus tard le …
UTC selon … ; une réécriture postérieure à cet instant serait détectée »).
Ce fragment n'apparaît qu'aux conditions d'EX-6.16 de CT-6 : contrôles 1, 3
et 6 réussis, K-1 à K-5 réussies, K-6 réussie ou non exécutée pour la raison
`piece_hors_dossier`, et au moins une ancre du point vérifiée (K-7, K-9, ou
K-8 avec une inclusion prouvée par R-11). La clause « horodaté au plus tard le
… » demande K-7 réussie ; avec la seule clause Bitcoin ou la seule clause
registre, le fragment se termine par « postérieure à la création de ce bloc »
ou « postérieure à l'inclusion de cette ancre », et aucune date n'est prouvée.
La seule borne de réécriture au point qu'un dossier prouve est donc celle de
la date (K-7).

**EX-3.5** (révision 0.2 ; numéro attribué selon la section 0, placé ici
parce qu'il décompose le `d_jeton` d'EX-3.3) `d_jeton` se décompose en quatre délais, que la
supervision rapporte séparément (8.9 : `d_point_s`, `d_attente_s`,
`d_releve_s`, `d_tsa_s` de la ligne `checkpoint_countersigned`) : `d_point = checkpoint_ts − D_k`, le
décalage du point sélectionné, au plus la tolérance d'alignement de CT-1
§10.5, règle 1 (1 s), puisque les points sont produits aux instants
`period_start + j × c_K` et que `c_T` est un multiple de `c_K` ;
`d_attente ≤ registry.squat_wait_s`, l'attente de l'inclusion de l'ancre du
point au registre (EX-4.7) ; `d_relève`, nul sauf relève par le secours
(`rfc3161.checkpoints.fallback_after_s` au plus, EX-5.7) ; `d_tsa = genTime +
précision − instant d'envoi`, le délai propre à l'autorité. La borne de date
s'écrit donc `W_date ≤ c_T + d_point + d_attente + d_relève + d_tsa`. La
valeur qui fait foi est le `d_jeton` mesuré, `genTime + précision − D_k`
(EX-5.11) : il contient tout, y compris les attentes de reprise chez le même
prestataire (EX-8.9), qui s'ajoutent aux quatre termes nommés quand `d_tsa`
est compté depuis l'envoi de la tentative promue. Avant une relève, elles
tiennent dans `rfc3161.checkpoints.fallback_after_s` (terme `d_relève`) ;
sans relève, rien ne les borne, et l'échéance finit `remplacee` si une
échéance postérieure est satisfaite d'abord (EX-4.4). Un point aligné manquant
(production interrompue, alerte `point_manquant`, 8.9) reporte la sélection
d'au plus `c_K` + 1 s, à cause de la tolérance d'alignement de CT-1 §10.5,
règle 1. Le pire cas sans relève et sans reprise est donc `c_T + c_K + 1 s +
squat_wait_s + d_tsa`, soit `366 s + d_tsa` aux valeurs par défaut.

L'ancre au registre ne fixe pas de position absolue : le registre accepte
toute empreinte nouvelle, et qui détient à la fois la clé de l'enregistreur et
la clé de chaîne peut ancrer une seconde série de points pour la même période.
Elle fixe l'ordre relatif de deux versions présentées ensemble et l'unicité de
chaque empreinte ; une série réécrite et ancrée à part ne se voit que par le
contrôle de complétude au registre (EX-10.7, AN-61), qui confronte toutes les
ancres de points émises par la clé de chaîne du journal à la série publiée.
`W_ordre` est une durée de conception, mesurée par l'exploitant (P-2), non une
garantie qu'un dossier isolé porte : c'est le délai au bout duquel
l'empreinte d'un point qui engage l'événement figure au registre. Passé ce
délai, une réécriture ne se voit que si deux versions sont présentées ensemble
(leur ordre au registre), ou par le contrôle de complétude fait sur la série
publiée ; une version réécrite, présentée seule avec sa propre série ancrée,
ne la montre pas, et le registre ne date rien.

Ce que la fenêtre ne dit pas : avant `T`, rien n'empêche qui détient la clé de
réécrire la période en cours et le point qui n'est pas encore ancré ; après
`T`, la réécriture **devient détectable**, sans être empêchée : confrontée à
l'ancre d'origine (dossier d'origine qui porte la partie, ou série et ancres
publiées), la version réécrite ne passe plus K-2, K-5 et K-7 (ou K-9, ou K-8
et R-11 ; CT-1 §11.4, CT-6 EX-6.16). Présentée seule, elle peut passer le
vérificateur : sans la partie, avec la seule borne de la clôture ; avec un
nouveau point contresigné plus tard, avec ses K- et un `T` postérieur, que le
rapport montre (`rewrite_window_end`, CT-6 EX-6.17). C'est le sens de CT-6
§7.9 (« détectable par quiconque détient ce dossier, non détectée »). Un attaquant qui détient la clé peut aussi arrêter la production des
points ou l'ancrage : la fenêtre redevient alors celle des ancres horaires, et
l'arrêt se voit dans la série des points et au registre (section 8,
supervision), jamais dans un dossier isolé (CT-1 §10.9, « ce que le dossier ne
montre pas »).

**EX-3.4** La contresignature d'un point n'est jamais substituée au jeton
qualifié de la clôture : le manifeste de chaque période reçoit son jeton du
prestataire principal (ou de secours) comme CT-6 §13.1 l'exige, quelles que
soient les contresignatures de points obtenues dans l'heure. Le point de
contrôle réduit la fenêtre ; la clôture horaire garde la présomption légale.

### 3.4 Adversaires

Les adversaires de CT-6 §3.4 sont repris ; cette table dit ce que l'ancrage à
cadence courte change pour chacun, et ce qu'un composant d'ancrage compromis
peut faire.

| Adversaire | Ce qu'on lui suppose | Ce que l'ancrage des points l'empêche de faire | Ce qu'il peut encore faire |
|---|---|---|---|
| **Opérateur ou enregistreur compromis** : détient la clé Ed25519 ou l'usage du signataire | Il réécrit et signe de nouveau ce qu'il veut ; il peut arrêter l'enregistreur ou l'ancrage | Présenter, après `T`, une autre version d'un événement engagé par un point ancré : la racine, `last_hash` ou `prev_checkpoint_hash` du point changeraient, donc `checkpointHash`, que l'ancre ne porte plus (K-2, K-5, K-7, K-8). Insérer ou antidater un point parmi des points déjà ancrés : la chaîne `prev_checkpoint_hash`, la monotonie de `tree_size`, la preuve de cohérence et l'unicité de l'empreinte au registre le contredisent (CT-1 §10.9 ; R2-F21, R2-F26). | Réécrire tout ce qui suit le dernier point ancré (fenêtre `W`) ; produire des points à n'importe quel `checkpoint_ts` (seule la contresignature date ; un point antidaté se voit au jeton, alertes `jeton_anterieur_au_point` et `contresignature_tardive`, 8.9) ; avec la clé de chaîne en plus, ancrer au registre une seconde série réécrite, que seul le contrôle de complétude au registre révèle (EX-10.7, AN-61) ; cesser d'ancrer, ce que la supervision voit (points attendus absents, `point_manquant`, `anchor_pending`) et qu'un dossier isolé ne montre pas. |
| **Prestataire RFC 3161** malhonnête ou compromis | Il signe n'importe quel `genTime` (H4 non tenue) | Rien de plus que CT-6 : un jeton sur une autre empreinte, ou d'une autorité que le réviseur n'a pas choisie, échoue au contrôle 4 (T-2, T-7). | Antidater ou postdater. Parades de conception : deux ancres indépendantes de lui (ordre au registre, Bitcoin) ; un prestataire de secours lui aussi qualifié ; le contrôle de `genTime` contre l'horloge locale à l'acquisition (5.4, `horloge_suspecte`), qui détecte un écart grossier au moment de l'acquisition seulement. |
| **Calendrier OpenTimestamps** | Il peut refuser le service ou retarder | Rien : il ne peut pas produire une fausse preuve, Bitcoin seul prouve (R1-F59). | Ne jamais inclure l'engagement : la preuve reste en attente ; parade : `m ≥ 2` calendriers indépendants (6.3), alerte après `give_up_after_s` (6.5). |
| **Fournisseur du registre** | Il sert ce qu'il veut par le RPC ; il contrôle des validateurs | Comme CT-6 §3.4 : rien tant qu'il contrôle moins d'un quorum ; aucune date n'est tirée du registre. | Avec un quorum : faire passer de faux blocs (le contrôle 8 ne prouve alors rien contre lui). Les ancres RFC 3161 et Bitcoin ne dépendent pas de lui. |
| **Intermédiaire réseau** entre l'enregistreur et un prestataire, un calendrier ou le registre | Il lit et retarde le trafic | Il ne voit que des empreintes de 32 octets (TLS obligatoire vers les prestataires, 5.2) ; un condensé OpenTimestamps est masqué par un nonce de 16 octets (6.2) ; une réponse retardée au-delà du délai admis est rejetée (5.4). | Retarder (allonge `d`), couper (la file reprend, section 8). Qui voit `checkpointHash` peut calculer l'empreinte d'ancre et l'ancrer le premier au registre (CT-4 §8.3) : d'où l'ordre « ancre du registre envoyée d'abord » (4.3). |
| **Composant d'ancrage compromis** | Il tient les identifiants d'accès aux prestataires ; il ne tient aucune clé Ed25519 et n'a pas la clé de chaîne (CT-2 EX-11.19, hors de lui) | Forger un point, un manifeste ou une ancre : il n'a pas la clé ; le registre refuse un émetteur qui n'est pas la clé de chaîne inscrite (CT-6 N-4). | Cesser d'ancrer ; faire horodater des empreintes quelconques aux frais du client (abonnement, débit) ; divulguer `checkpointHash` et `periodHash` (sans conséquence sur les contenus, avec le risque de CT-4 §8.3). Parade : moindre privilège (CT-2 §18.3), alerte sur le volume de requêtes (section 8), rotation des identifiants (CT-7). |

Le composant d'ancrage construit la transaction `anchor` ; la clé de chaîne
la signe, et cette clé est tenue hors de lui selon sa classe de garde (CT-2
EX-11.19, `anchoring.registry.chain_key`). Ce que le signataire de la clé de
chaîne accepte de signer relève de CT-2, non de CT-5 : un composant d'ancrage
compromis peut faire ancrer des empreintes quelconques dans la mesure où ce
signataire l'accepte, sans jamais tenir la clé.

### 3.5 Hypothèses

Les phrases de la section 3.3 sont vraies sous les hypothèses H1 à H7 de CT-6
§3.5 (résistance des fonctions de hachage et des signatures ; fichier
d'ancres du réviseur exact ; autorité d'horodatage honnête à `genTime` ; pas
de réorganisation Bitcoin au-dessus du point de contrôle ; au plus `f`
validateurs fautifs ; code des contrats). CT-5 n'en ajoute qu'une, qui ne
porte pas sur la preuve :

| H | Hypothèse | Ce qui en dépend |
|---|---|---|
| H8 | L'horloge de l'enregistreur est dans les tolérances de CT-2 §7.4 (EX-7.9, EX-7.13) pendant que le composant d'ancrage planifie ses échéances et contrôle la fraîcheur des réponses. | La cadence effective des échéances (4.2) et le contrôle `horloge_suspecte` (5.4). Jamais une preuve : si H8 tombe, les ancres restent vraies et les fenêtres de 3.3 restent bornées par les dates des ancres, seule la régularité des échéances souffre, ce que la supervision voit. |

### 3.6 Exigences de niveau de preuve, mesurables

Les propriétés suivantes sont celles que la conception doit atteindre avec sa
configuration par défaut ; CT-9 les mesure sur le réseau de développement et
sur les vecteurs. Elles s'énoncent sans référence à un produit.

| Id | Exigence | Mesure |
|---|---|---|
| P-1 | Tout nouvel événement est engagé par une tête d'arbre signée par l'enregistreur au plus `c_K = 60 s` (plus la tolérance d'alignement de 1 s) après son `ts` ; les points sont produits aux instants `period_start + j × c_K` et à la clôture (CT-1 §10.5, règle 1 ; CT-2 révision 0.4). | Série des points d'une période : `checkpoint_ts(premier point de tree_size > i) − ts(événement i) ≤ c_K + 1 s` pour tout `i` ; constat de cadence (`constaterCadence`, AN-2) sans écart. |
| P-2 | Cette tête est ancrée au registre et son ancre incluse dans un bloc au plus `c_K + d_registre` après l'événement, avec `d_registre ≤ registry.inclusion_alert_s = 60 s` en fonctionnement nominal (fenêtre d'ordre). | Pour chaque ancre de point : instant de réception du reçu d'inclusion, sur l'horloge de l'enregistreur (jamais l'horodatage du bloc, que le proposant choisit), moins `checkpoint_ts` : au plus `inclusion_alert_s`. Avec P-1 (`checkpoint_ts − ts ≤ c_K + 1 s`), cela donne `c_K + 1 s + d_registre` après le `ts` de l'événement. Ces instants (`ts`, `checkpoint_ts`, réception du reçu) sont tous lus sur l'horloge de l'enregistreur : c'est une durée de conception mesurée, non prouvée (3.3). |
| P-3 | Cette tête, ou une tête postérieure qui l'engage par préfixe (preuve de cohérence, CT-1 §10.7), est contresignée par une autorité RFC 3161 au plus `c_T + d_jeton` après l'événement, avec `c_T = 300 s` par défaut et `d_jeton = d_point + d_attente + d_relève + d_tsa` (EX-3.5). Lecture : `W_date ≤ c_T (300 s) + d_jeton`, avec `d_jeton = d_point (≤ 1 s) + d_attente (≤ squat_wait_s) + d_relève (≤ fallback_after_s) + d_tsa`. | Pour chaque échéance `D_k` satisfaite : `genTime + précision − D_k = d_jeton`, rapporté avec ses quatre composantes (8.9) ; aucune échéance non satisfaite avant la suivante en fonctionnement nominal. |
| P-4 | La clôture horaire est contresignée par un prestataire qualifié (CT-6 EX-13.4) et horodatée par OpenTimestamps auprès d'au moins deux calendriers (CT-6 EX-13.5). | Parties `jeton-rfc3161.der` et `preuve.ots` du dossier ; T-11 réussie avec le fichier d'ancres du réviseur. |
| P-5 | Un dossier se vérifie hors ligne, sans réseau ni concours du fournisseur, points de contrôle compris (CT-6 §14.2 ; CT-1 §11.2 : ancres du point embarquées en base64). | Vérificateur de CT-6 (révision 0.2) sur les dossiers des vecteurs CT-5 et CT-6, sans réseau. |
| P-6 | Les points, leurs ancres (jetons, preuves, enregistrements d'acquisition) et les manifestes reçoivent une copie en stockage à verrou d'objet, mode sans contournement par aucun rôle du client, rétention au moins égale à la rétention des événements (CT-2 §12.6, §12.7 ; 5.5). | Pour chaque fichier : une version dont le SHA-256 égale celui de l'original, et le mode et la date de rétention rendus par l'API du support (R2-F36 : lecture déclarative, qui complète les ancres sans les remplacer, CT-2 §12.6). |

## 4. Cadences

### 4.1 Les cadences

| Cadence | Objet | Qui | Valeur par défaut | Bornes | Paramètre |
|---|---|---|---|---|---|
| Production des points | Point de contrôle | Enregistreur (CT-2 révision 0.4) | un point à chaque instant `period_start + j × c_K` (`j = 0 … 3600 / c_K − 1`, tolérance 1 s), soit toutes les 60 s, et un point à la clôture | 10 à 3600 s ; diviseur de 3600 | `checkpoint_interval_s` (CT-2 ; recopié dans `ancrage-v0`, 4.4) |
| Ancre des points au registre | `checkpointHash` → `anchor` | Composant d'ancrage, clé de chaîne de CT-2 | chaque point qui engage un nouvel événement (`nouveaux_evenements`) | `tous`, `nouveaux_evenements`, `aucun` (hors production) | `registry.checkpoints` |
| Contresignature RFC 3161 des points | `checkpointHash` → jeton | Prestataire du rôle désigné | une échéance toutes les 300 s, la dernière de l'heure étant la clôture ; un point sans nouvel événement n'est pas contresigné | 60 à 3600 s ; multiple de `checkpoint_interval_s` ; diviseur de 3600 | `rfc3161.checkpoints.interval_s`, `rfc3161.checkpoints.provider_role`, `rfc3161.checkpoints.countersign_idle` |
| Clôture horaire | `periodHash` → `anchor`, `submitPeriod`, jeton qualifié, `.ots` | Composant d'ancrage ; prestataire principal (secours en relève) ; calendriers | une fois par heure, à la clôture | — | `rfc3161.manifest.fallback_after_s`, `opentimestamps.*` |
| OpenTimestamps d'un point | `P_K ‖ C_K` → `.ots` | Calendriers | aucun | `aucun`, `mi_periode` | `opentimestamps.checkpoint` |
| Mise à niveau OpenTimestamps | preuves en attente | Calendriers | première tentative 6 h après la soumission, puis toutes les 30 min ; alerte après 14 jours | ≥ 60 s entre deux tentatives | `opentimestamps.upgrade.*` |

### 4.2 Échéances et sélection des points

**EX-4.1** L'enregistreur produit un point de contrôle à chaque instant
`period_start + j × c_K`, `j = 0 … 3600 / c_K − 1`, à la tolérance
d'alignement de 1 s près, et un point à la clôture, avant ou avec le
manifeste (CT-1 §10.5, règle 1 ; CT-2 révision 0.4) ; deux points alignés
consécutifs sont donc distants d'au plus `c_K` + 1 s ; le point de clôture
suit le dernier point aligné de `c_K` (à la tolérance d'alignement près) plus
le délai de production de la clôture après `period_end`, que la règle 1 ne
borne pas, et le constat de cadence (AN-2) signale l'écart quand il dépasse
`c_K` + 1 s ; une période compte
au plus `3600 / c_K + 1` points. Le composant d'ancrage ne produit aucun
point : il reçoit chaque point signé, en recalcule `checkpointHash`, vérifie
sa signature et sa place dans la série (AN-3 ; CT-1 §10.5, règles 2 à 5 : quand
les événements de la période lui sont remis, `root` et `last_hash` sont
recalculés, `admettrePoint`), puis décide de ses ancres. L'alignement n'est
pas une condition d'admission : un point hors cadence est admis et ancré, et
l'écart est constaté (`constaterCadence`, AN-2) et alerté (`point_manquant`
quand aucun point n'est admis pendant `2 × c_K`, 8.9). Il lit
`checkpoint_interval_s` dans sa configuration (4.4) et refuse au démarrage une
valeur différente de celle de l'enregistreur (AN-1).

**EX-4.2** Les échéances de contresignature d'une période sont `D_k =
period_start + k × c_T` pour `k = 1 … n_T − 1`, où `n_T = 3600 / c_T` ; la
`n_T`-ième échéance est la clôture, dont le jeton qualifié porte `periodHash`
(CT-6 §13.1) et tient lieu de contresignature du point de clôture. `c_T` est
un multiple de `checkpoint_interval_s` et un diviseur de 3600, entre 60 et
3600 s ; avec `c_T = 3600`, aucun point n'est contresigné et seule la clôture
l'est. Motif de la dernière échéance confondue avec la clôture : le point de
clôture et le manifeste engagent exactement les mêmes feuilles (CT-1 §10.5,
règle 4) ; un jeton sur chacun coûterait un jeton qualifié de plus par heure
sans réduire aucune fenêtre. « Tient lieu » veut dire que la date de la fin
de l'heure est portée par le jeton du manifeste et lue dans le contrôle 4 de
CT-6 (`facts.timestamp.upper_bound`), pas dans la partie
`points-de-controle.json` : pour un événement de `ts ≥ D_{n_T−1}` (13:55 avec
`c_T = 300`), aucun point qui le couvre n'a en général de jeton propre (les
points alignés qui suivent `D_{n_T−1}` n'ont que leur ancre au registre, et le
point de clôture n'est contresigné que dans les deux cas ci-dessous) ; la
partie porte alors au mieux l'ancre au registre (fragment FK sans clause
jeton, `rewrite_window_end` nul), et la fenêtre de ces événements est bornée
par le jeton du manifeste : au plus `c_T` plus son délai compté depuis
`period_end` (EX-5.11). Cette règle ne vaut que pour la `n_T`-ième
échéance : un point de clôture qu'une échéance antérieure encore ouverte
sélectionne est contresigné comme tout point (EX-4.3). Repli de clôture
(révision 0.2) : quand la demande `jeton_periode` reste `attente_registre`
plus de `registry.squat_wait_s` après la clôture (registre injoignable, EX-4.7
et EX-8.4), le planificateur DOIT demander un `jeton_point` sur le point de
clôture, dans les conditions d'EX-4.7 pour l'ancre de ce point, sauf si ce
point a déjà une demande ou n'engage aucun nouvel événement par rapport au
dernier point contresigné. Le `checkpointHash` du point de clôture est
distinct de `periodHash` : la requête ne révèle pas l'empreinte de la période
et ne crée pas le risque de CT-4 §8.3. Ce jeton borne la fin de l'heure tant
que le jeton qualifié du manifeste attend ; il ne le remplace pas (EX-3.4) ;
il est consigné `checkpoint_closing_fallback` (8.9) et se compte dans les
jetons de points (trace `registre-indisponible-cloture`, annexe A). Il n'a
lieu que si le registre tarde, hors du fonctionnement nominal : il s'ajoute
aux maxima d'EX-4.11, au plus un par période, de sorte qu'une telle période
peut compter `n_T` jetons de points au lieu de `n_T − 1`.

**EX-4.3** À l'échéance `D_k`, le point à contresigner est le **premier point
de la période dont `checkpoint_ts ≥ D_k`** ; la requête part dès que ce point
est reçu et vérifié. Il engage tous les événements de `ts < D_k` et donne la
borne `W_date ≤ c_T + d_jeton` de 3.3. Le dernier point dont `checkpoint_ts <
D_k` ne convient pas : il laisserait les événements survenus entre lui et
`D_k` attendre l'échéance suivante (`W_date ≤ c_T + c_K + d_jeton`). Un même
point n'est demandé qu'une fois : un jeton obtenu sur un point satisfait
toutes les échéances passées non encore satisfaites de la période (il engage
tout ce que les points antérieurs engageaient), ce qui fait qu'après une
interruption de l'enregistreur une seule requête rattrape les échéances
manquées : aucun point n'est produit pendant l'interruption, et le premier
point suivant est sélectionné par toutes les échéances ouvertes. Pendant une
panne du prestataire, il en va autrement : chaque échéance dont le point
engage de nouveaux événements par rapport au dernier point contresigné (qui
compte les demandes encore actives) crée sa propre demande, et ces demandes
s'accumulent (EX-8.5, règle 4). Au retour du prestataire, les `jeton_periode`
partent d'abord (EX-8.7) ; chacun satisfait la `n_T`-ième échéance de sa
période et clôt `remplacee` les demandes de points de cette période encore
actives (EX-8.4, règle 1) ; les demandes de la période en cours partent par
`checkpoint_ts` croissant, et, comme une demande n'est close `remplacee` que
lorsqu'une échéance postérieure est satisfaite, plusieurs jetons de rattrapage
peuvent être obtenus pour cette période, au plus `n_T − 1`, dans les maxima
d'EX-4.11. Trois emplois du mot : « pas de rattrapage » (EX-4.4) veut dire qu'aucun
point nouveau n'est sélectionné pour une échéance qui a déjà une demande ;
« jetons de rattrapage » (ci-dessus) désigne les jetons obtenus au retour pour
des demandes déjà créées ; « rattrapage » au registre (EX-9.5) désigne l'envoi
de la seule ancre du dernier point admis. Le **dernier point contresigné** de la période est
le point de plus grand `tree_size` dont le jeton est obtenu, ou dont la
demande `jeton_point` est encore active (ni `refusee` ni `remplacee`) : une
demande refusée rend ses échéances, qui redeviennent ouvertes et sont
servies par le point suivant, et le dernier point contresigné redescend
(trace `refus-puis-preuve-de-vie`). Une échéance qui a déjà une demande, dans
un état quelconque, ne sélectionne plus de point. Si le point sélectionné
n'engage **aucun nouvel événement** par rapport au dernier point contresigné
de la période (même `tree_size`), l'échéance est satisfaite sans requête et
consignée `sans_objet`,
sauf si `rfc3161.checkpoints.countersign_idle` est vrai (défaut : faux) :
contresigner une tête inchangée ne réduit aucune fenêtre et coûte un jeton ;
un journal sans activité ne coûte ainsi que sa clôture horaire (4.6).
Le point de clôture (CT-1 §10.5, règle 4) peut être le point sélectionné par
une échéance `D_k`, `k < n_T`, quand aucun point n'a été produit entre `D_k`
et la clôture : il est alors contresigné comme tout point, en plus du jeton
qualifié du manifeste, parce que la règle est la même pour toute échéance et
que ce jeton de point n'attend pas l'inclusion de l'ancre de la période
(EX-8.4) ; en fonctionnement nominal (un point par minute) le cas ne survient
pas, et l'exemple ci-dessous comme la trace de 8.10 l'illustrent (`K4` pour
`D_11`).

**EX-4.4** Une échéance dont la contresignature n'est pas obtenue avant que
l'échéance suivante soit satisfaite est close `remplacee` : le composant
d'ancrage ne rattrape pas les points (le point suivant couvre un préfixe plus
long), et la clôture, toujours rattrapée (EX-4.5), couvre la fin de l'heure.
L'échéance non satisfaite est consignée dans la file avec sa cause (section 8)
et compte dans la métrique de retard ; la supervision lève une alerte quand
une échéance est close `remplacee` (`checkpoint_anchor_late`, section 8) : la
fenêtre de date de l'intervalle correspondant est alors celle de l'ancre
suivante, non celle de la conception.

**EX-4.5** Le manifeste est toujours ancré, quel que soit le délai : ses trois
ancres sont demandées à la clôture et réessayées jusqu'à obtention (section 8,
file durable ; CT-2 §14.2, `anchor_pending`, `registry_pending`), avec l'alerte
« ancre en retard » de CT-2 §17.4 au-delà de `queue.anchor_pending_alert_s`
(défaut 7200 s). Un jeton obtenu longtemps après la clôture reste valable et
allonge d'autant la fenêtre, ce que CT-6 §7.2 dit au réviseur.

Exemple, période 1 de l'exemple de référence de CT-1 (`period_start =
1793710800`, 2026-11-03T13:00:00Z, série des points de CT-1 §10.8, `c_T =
300`) : les échéances sont `D_1 = 13:05:00`, …, `D_11 = 13:55:00`, et la
clôture tient lieu de `D_12`. La série de l'exemple est volontairement courte
(un point à 13:42, un à 13:53, un à 13:54, la clôture à 14:00:00.250) ; avec
la règle EX-4.3, `K1` (13:42:00) satisfait `D_1` à `D_8` en une requête,
`K2` (13:53:00) satisfait `D_9` et `D_10`, `K4` (14:00:00.250) satisfait
`D_11`, et le manifeste reçoit le jeton de la clôture. Le jeton de l'exemple
de CT-1 §11.2 est celui de `K2` (`genTime` 13:53:02, précision 1 s) : pour
l'événement `seq` 4 de l'annexe A de CT-1 (`ts` 2026-11-03T13:52:41.090Z),
`T = 13:53:03` et `W_date` vaut 22 s environ (jeton de l'autorité de test des
vecteurs, sans valeur probante ; contre l'opérateur, seul un prestataire
extérieur borne `W_date`, EX-7.3). La série de l'exemple n'est pas alignée
(CT-1 §10.8) ; un enregistreur à la cadence nominale produit un point à chaque
instant `period_start + j × c_K` : `D_k` sélectionne alors le point produit à
`D_k` lui-même (`d_point` ≤ 1 s), si les points sont produits aux instants
`D_k`, et `d_jeton` se réduit à `d_attente + d_tsa` (EX-3.5).

### 4.3 Ancre des points au registre

**EX-4.6** Chaque point dont `tree_size` est strictement supérieur au
`tree_size` du dernier point de la même période déjà ancré au registre (ou
dont `tree_size ≥ 1` s'il n'y en a pas encore) est ancré par
`AttestationRegistry.anchor` avec l'empreinte `keccak256(org_id ‖ journal_id
‖ checkpointHash)` et le `docType` `noortrace/point-de-controle/v0` (CT-1
§10.6 ; CT-4 §6.4, révision 0.3 ; section 9). C'est la règle
`registry.checkpoints = "nouveaux_evenements"`, par défaut : un point sans
nouvel événement (preuve de vie, CT-1 §10.5, règle 1) engage les mêmes
feuilles que le point ancré précédent et n'apporte rien à l'ordre ; l'ancrer
coûterait du gaz et une place de mempool. La règle `tous` ancre chaque point,
preuves de vie comprises (un battement de cœur visible au registre) ; la règle
`aucun` est admise hors production seulement (AN-1). La fenêtre d'ordre de 3.3
est la même sous `nouveaux_evenements` et sous `tous`.

**EX-4.7** L'ancre d'un point part au registre **avant** sa requête
RFC 3161 : la requête n'est envoyée qu'après l'inclusion de l'ancre, ou,
si l'inclusion n'est pas constatée dans `registry.squat_wait_s` (défaut 5 s),
sans l'attendre, le risque de CT-4 §8.3 (empreinte ancrée par un tiers qui
l'aurait vue) étant alors accepté et consigné pour ce point. Motif : la
requête RFC 3161 révèle `checkpointHash` en clair à l'autorité et à tout
intermédiaire, et l'empreinte d'ancre s'en déduit (`org_id` et `journal_id`
sont publics) ; CT-4 EX-8.4 impose le même ordre pour la clôture. La preuve
OpenTimestamps peut partir en parallèle : les calendriers ne voient qu'un
engagement masqué par un nonce (6.2).

Nombre d'ancres au registre par journal et par heure (révision 0.2) : une
période compte au plus `3600 / c_K + 1` points, les `3600 / c_K` points
alignés et le point de clôture (EX-4.1) ; sous `nouveaux_evenements` comme
sous `tous`, au plus `1 + 3600 / c_K` appels `anchor` de points, plus celui du
manifeste, soit `2 + 3600 / c_K` appels `anchor` et un `submitPeriod`. Pour
`c_K = 60` : au plus 62 ancres et une clôture par heure, 1 488 ancres et 24
clôtures par jour. Le décompte suppose la cadence d'EX-4.1 ; un enregistreur
qui produit plus de points que l'alignement ne le prévoit dépasse ce plafond,
ce que la supervision voit (volume des requêtes et des ancres, 8.9). Le gaz
d'`anchor` ne dépend que des octets nuls des données d'appel (CT-4 §4.5) : le
`docType` du point,
`0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178` (CT-1
annexe B), n'a aucun octet nul, comme celui de la période ; la borne de CT-4
§4.5, 96 977 gaz au plus par ancre, vaut donc pour l'ancre d'un point. Le budget
journalier de la clé de chaîne d'un journal (CT-4 EX-4.19, gaz de référence
100 000 pour `anchor` et 350 000 pour `submitPeriod`) devient
`b = 24 × (62 × 100 000 + 350 000) = 157 200 000` wei par jour et la provision à
trente jours `P = 30 × b + 3 000 000 = 4 719 000 000` wei, soit 4,719 × 10⁻⁹
NUR : CT-4 EX-4.19 est à aligner (section 14). La cadence par expéditeur reste
d'une transaction par bloc au plus (CT-4 EX-4.14), soit une occupation de la
mempool d'au plus 63 transactions par heure et par journal ; la capacité de
l'instance pour le nombre de journaux cible relève de CT-8.

### 4.4 Configuration

**EX-4.8** La configuration de l'ancrage est un document JSON unique,
`ancrage-v0`, schéma `spec/schemas/ancrage-v0.schema.json` (JSON Schema draft
2020-12, sans référence croisée, compilable en mode strict). Toutes les clés
sont présentes ; une valeur qui ne s'applique pas vaut `null` ou une liste
vide. Il est désigné par la configuration de l'enregistreur (CT-2 §15, clé
`anchoring` ; proposition d'alignement en section 14) et validé au démarrage
comme elle (CT-2 §15.4) : une configuration invalide empêche le démarrage du
composant d'ancrage, et l'enregistreur continue de produire points et
manifestes (CT-2 §14.2 : l'ancrage ne bloque jamais). Les secrets (identifiant
et mot de passe d'accès à un prestataire, certificat client, authentification
du nœud Bitcoin) sont désignés par leur emplacement (`env`, `file`, `vault`,
CT-2 §15.2), jamais écrits en clair. Aucun prix n'y figure.

| Clé | Contenu | Défaut |
|---|---|---|
| `version` | `0` | — |
| `checkpoint_interval_s` | `c_K`, recopie de CT-2 (EX-4.1) | 60 |
| `rfc3161.providers[]` | un prestataire par point d'accès : `id`, `role` (`principal`, `secours`, `second_rang`, `interne`), `url`, `auth` (`aucune`, `basic`, `certificat_client` ; secret par emplacement), `hash` (`sha256`), `policy_oid` (envoyé) et `accepted_policies` (admises, T-9), `anchor_certificates` (PEM, T-7 à l'acquisition), `qualified` (statut mesurable, 5.3) ou `null`, `min_interval_ms`, `request_timeout_ms`, `correlation_header`, `source` | un `principal` exactement ; `secours` DEVRAIT exister |
| `rfc3161.manifest.fallback_after_s` | délai avant la relève par le secours pour le manifeste (5.3) | 300 |
| `rfc3161.checkpoints` | `interval_s` (`c_T`), `provider_role` (`principal`, `second_rang`, `interne`, `aucun`), `fallback_after_s`, `countersign_idle` (EX-4.3) | 300, `principal`, 120, `false` |
| `rfc3161.freshness` | `max_response_delay_s`, `clock_tolerance_s` (5.4) | 60, 120 |
| `rfc3161.retry` | `initial_ms`, `factor`, `max_ms`, `jitter_ms` (5.4, section 8) | 5000, 2, 300000, 250 |
| `rfc3161.retention_years` | conservation (5.5) | 10 |
| `rfc3161.crl_capture` | `enabled`, `delay_s` (CT-6 EX-13.12 ; 5.4) | `true`, 600 |
| `registry` | `checkpoints` (EX-4.6), `squat_wait_s` (EX-4.7), `inclusion_alert_s` (3.3) ; le point RPC et la clé de chaîne restent dans `anchoring.registry` de CT-2 | `nouveaux_evenements`, 5, 60 |
| `opentimestamps` | `enabled`, `calendars[]`, `min_responses`, `timeout_ms`, `checkpoint` (`aucun`, `mi_periode`), `upgrade` (`whitelist[]`, `first_after_s`, `interval_s`, `give_up_after_s`), `headers_source` (`null`, `bitcoin_rpc`, `fichier`) (section 6) | `true`, les quatre agrégateurs publics (6.2), 2, 5000, `aucun`, (les quatre calendriers publics, 21600, 1800, 1209600), `null` |
| `queue` | `path`, `max_pending`, `anchor_pending_alert_s` (section 8) | sous `storage.root`, 100000, 7200 |

Exemple complet, valide contre le schéma (point d'accès des prestataires
fictifs ; les certificats d'autorité sont ceux de l'AC de test des vecteurs
CT-6, `spec/vecteurs/ct-6/rfc3161/cles/ac-test.pem`, sans valeur hors des
tests ; les listes de confiance citées sont celles lues le 2026-10-25,
R1-F26 et R1-F42, données ici à titre d'exemple de la forme) :

<!-- schema: ancrage -->
```json
{
  "version": 0,
  "checkpoint_interval_s": 60,
  "rfc3161": {
    "providers": [
      {
        "id": "qtsa-principal",
        "role": "principal",
        "url": "https://horodatage-principal.example/tsa",
        "auth": { "method": "basic", "secret": { "env": "NOORTRACE_TSA_PRINCIPAL" } },
        "hash": "sha256",
        "policy_oid": null,
        "accepted_policies": null,
        "anchor_certificates": [ "-----BEGIN CERTIFICATE-----\nMIIERTCCAq2gAwIBAgIBATANBgkqhkiG9w0BAQsFADBEMQswCQYDVQQGEwJDSDEb\nMBkGA1UECgwSTk9PUlRSQUNFIHZlY3RldXJzMRgwFgYDVQQDDA9BQyBkZSB0ZXN0\nIENULTYwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjBEMQswCQYDVQQG\nEwJDSDEbMBkGA1UECgwSTk9PUlRSQUNFIHZlY3RldXJzMRgwFgYDVQQDDA9BQyBk\nZSB0ZXN0IENULTYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC6/DG2\nIeKP3DpkymqTJju07MV4T6897KG3c54dBNvYkDp/5+sTszTfscX97zJNe9yEdQUk\nGOWgsWVsHuPfwdIHkxOpg+iTzXesOigZ5Z3nnRhGhaapFOt7dw8Y2k11Ph5D020d\nVFg6mmF/3o/DjQYmBZWVslZrBPZ1Ox+BAgtJ8TEfzM2WKQJU7ynOKTkRqVhGIzGU\nKQs7y8ajeXsYPcHVE9DPgAsBlvfocHBjPM6HTAPr2uQAGyxmWbi0TVURCLWjosA/\np2rVipwtUY5kOummqe1WeYYu4TJGFS9UwTv0Wb9QdSwgDF4Gil9QlRBdsgjK0q8l\nLl9d5aMc2+Ek7ygoFy5fOayFbuEW2C+p8AVORcTe6NyVtAr+BKKyRT/5cqg4mg3/\nVuWp2xtLcfnibL0Xv6dDINQa9cvXrZ8ffQVQoXvWypT/qB95A2UIABnlJ+Puy7pw\n4Ig+jW7xtDfZq7E6gtmkWcO+K7ZJAWSFHt5G1+gu8629c0f/+lIMtWEUMAcCAwEA\nAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYE\nFOWYQz/533+Z5pdz2xPeP7Dek5haMA0GCSqGSIb3DQEBCwUAA4IBgQBj1DnJODOM\nt0uQ+W3l/EaxbhJgxxTz+W/W/Em7iIpehUEmdfwoMd5Sz3IZLNQA2n7bdNUrn0au\nnsS+EHO5RgxbMSVD2Wi5ykwltNKVFI3sROPQW9jcqzVlKH+2ychGk9CTsJL0sGhJ\nCdJJEap84UVrXYL9W4xH5kdqSpbyJmRi8g7+9SuKDYwjQbrxEHErvlLqbrRRgNtU\nYhTnqQXRsi979JY/zbhhaBG/u6q20wKKh5PvqwiK7JXGgrQIiN+wBc4R8SvROy2B\nzsQNc0vkgZCxTgOrhRcHa5XkZVXmaFk8Vc7QMzadGjB455cy0yXVjJK1A6H705CO\n8i8/bSz+s0l9z4fxELG1uEPtH/DZypUrSRxhV6UU1fF/ltGFQib6XI3s7FvRKWev\nqlvZV1dpGUobK/tZiKkItGiVmDuHS98d3nEu07PkQrdrIDpedKBE70InQztk6BuO\nTJXpBjWvMH4G7P6/U3gIEV2lvvx53XljANu1Rj7bVhZH2YHavlIJ+TE=\n-----END CERTIFICATE-----\n" ],
        "qualified": {
          "framework": "eidas",
          "service_type": "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
          "status": "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
          "trusted_list": {
            "territory": "AT",
            "sequence_number": 75,
            "issue_date": "2026-06-15T14:44:12.000Z",
            "url": "https://www.signatur.rtr.at/vertrauensliste.xml"
          },
          "source": "exemple : liste de confiance AT, séquence 75, lue le 2026-10-25 ; point d'accès fictif ; certificat de l'AC de test des vecteurs CT-6, sans valeur hors des tests"
        },
        "min_interval_ms": 0,
        "request_timeout_ms": 10000,
        "correlation_header": "X-Request-ID",
        "source": "documentation publique du prestataire principal, lue le 2026-10-25 (section 11)"
      },
      {
        "id": "qtsa-secours",
        "role": "secours",
        "url": "https://horodatage-secours.example/qts",
        "auth": { "method": "basic", "secret": { "file": "/run/secrets/tsa-secours" } },
        "hash": "sha256",
        "policy_oid": null,
        "accepted_policies": null,
        "anchor_certificates": [ "-----BEGIN CERTIFICATE-----\nMIIERTCCAq2gAwIBAgIBATANBgkqhkiG9w0BAQsFADBEMQswCQYDVQQGEwJDSDEb\nMBkGA1UECgwSTk9PUlRSQUNFIHZlY3RldXJzMRgwFgYDVQQDDA9BQyBkZSB0ZXN0\nIENULTYwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjBEMQswCQYDVQQG\nEwJDSDEbMBkGA1UECgwSTk9PUlRSQUNFIHZlY3RldXJzMRgwFgYDVQQDDA9BQyBk\nZSB0ZXN0IENULTYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC6/DG2\nIeKP3DpkymqTJju07MV4T6897KG3c54dBNvYkDp/5+sTszTfscX97zJNe9yEdQUk\nGOWgsWVsHuPfwdIHkxOpg+iTzXesOigZ5Z3nnRhGhaapFOt7dw8Y2k11Ph5D020d\nVFg6mmF/3o/DjQYmBZWVslZrBPZ1Ox+BAgtJ8TEfzM2WKQJU7ynOKTkRqVhGIzGU\nKQs7y8ajeXsYPcHVE9DPgAsBlvfocHBjPM6HTAPr2uQAGyxmWbi0TVURCLWjosA/\np2rVipwtUY5kOummqe1WeYYu4TJGFS9UwTv0Wb9QdSwgDF4Gil9QlRBdsgjK0q8l\nLl9d5aMc2+Ek7ygoFy5fOayFbuEW2C+p8AVORcTe6NyVtAr+BKKyRT/5cqg4mg3/\nVuWp2xtLcfnibL0Xv6dDINQa9cvXrZ8ffQVQoXvWypT/qB95A2UIABnlJ+Puy7pw\n4Ig+jW7xtDfZq7E6gtmkWcO+K7ZJAWSFHt5G1+gu8629c0f/+lIMtWEUMAcCAwEA\nAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYE\nFOWYQz/533+Z5pdz2xPeP7Dek5haMA0GCSqGSIb3DQEBCwUAA4IBgQBj1DnJODOM\nt0uQ+W3l/EaxbhJgxxTz+W/W/Em7iIpehUEmdfwoMd5Sz3IZLNQA2n7bdNUrn0au\nnsS+EHO5RgxbMSVD2Wi5ykwltNKVFI3sROPQW9jcqzVlKH+2ychGk9CTsJL0sGhJ\nCdJJEap84UVrXYL9W4xH5kdqSpbyJmRi8g7+9SuKDYwjQbrxEHErvlLqbrRRgNtU\nYhTnqQXRsi979JY/zbhhaBG/u6q20wKKh5PvqwiK7JXGgrQIiN+wBc4R8SvROy2B\nzsQNc0vkgZCxTgOrhRcHa5XkZVXmaFk8Vc7QMzadGjB455cy0yXVjJK1A6H705CO\n8i8/bSz+s0l9z4fxELG1uEPtH/DZypUrSRxhV6UU1fF/ltGFQib6XI3s7FvRKWev\nqlvZV1dpGUobK/tZiKkItGiVmDuHS98d3nEu07PkQrdrIDpedKBE70InQztk6BuO\nTJXpBjWvMH4G7P6/U3gIEV2lvvx53XljANu1Rj7bVhZH2YHavlIJ+TE=\n-----END CERTIFICATE-----\n" ],
        "qualified": {
          "framework": "eidas",
          "service_type": "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
          "status": "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
          "trusted_list": {
            "territory": "PL",
            "sequence_number": 163,
            "issue_date": "2026-10-23T11:45:38.000Z",
            "url": "https://www.nccert.pl/tsl/PL_TSL.xml"
          },
          "source": "exemple : liste de confiance PL, séquence 163, lue le 2026-10-25 ; point d'accès fictif ; certificat de test"
        },
        "min_interval_ms": 0,
        "request_timeout_ms": 10000,
        "correlation_header": null,
        "source": "documentation publique du prestataire de secours, lue le 2026-10-25 (section 11)"
      },
      {
        "id": "tsa-interne",
        "role": "interne",
        "url": "http://127.0.0.1:2020/",
        "auth": { "method": "aucune", "secret": null },
        "hash": "sha256",
        "policy_oid": "1.3.6.1.4.1.99999.1.1",
        "accepted_policies": [ "1.3.6.1.4.1.99999.1.1" ],
        "anchor_certificates": [ "-----BEGIN CERTIFICATE-----\nMIIERTCCAq2gAwIBAgIBATANBgkqhkiG9w0BAQsFADBEMQswCQYDVQQGEwJDSDEb\nMBkGA1UECgwSTk9PUlRSQUNFIHZlY3RldXJzMRgwFgYDVQQDDA9BQyBkZSB0ZXN0\nIENULTYwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjBEMQswCQYDVQQG\nEwJDSDEbMBkGA1UECgwSTk9PUlRSQUNFIHZlY3RldXJzMRgwFgYDVQQDDA9BQyBk\nZSB0ZXN0IENULTYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC6/DG2\nIeKP3DpkymqTJju07MV4T6897KG3c54dBNvYkDp/5+sTszTfscX97zJNe9yEdQUk\nGOWgsWVsHuPfwdIHkxOpg+iTzXesOigZ5Z3nnRhGhaapFOt7dw8Y2k11Ph5D020d\nVFg6mmF/3o/DjQYmBZWVslZrBPZ1Ox+BAgtJ8TEfzM2WKQJU7ynOKTkRqVhGIzGU\nKQs7y8ajeXsYPcHVE9DPgAsBlvfocHBjPM6HTAPr2uQAGyxmWbi0TVURCLWjosA/\np2rVipwtUY5kOummqe1WeYYu4TJGFS9UwTv0Wb9QdSwgDF4Gil9QlRBdsgjK0q8l\nLl9d5aMc2+Ek7ygoFy5fOayFbuEW2C+p8AVORcTe6NyVtAr+BKKyRT/5cqg4mg3/\nVuWp2xtLcfnibL0Xv6dDINQa9cvXrZ8ffQVQoXvWypT/qB95A2UIABnlJ+Puy7pw\n4Ig+jW7xtDfZq7E6gtmkWcO+K7ZJAWSFHt5G1+gu8629c0f/+lIMtWEUMAcCAwEA\nAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYE\nFOWYQz/533+Z5pdz2xPeP7Dek5haMA0GCSqGSIb3DQEBCwUAA4IBgQBj1DnJODOM\nt0uQ+W3l/EaxbhJgxxTz+W/W/Em7iIpehUEmdfwoMd5Sz3IZLNQA2n7bdNUrn0au\nnsS+EHO5RgxbMSVD2Wi5ykwltNKVFI3sROPQW9jcqzVlKH+2ychGk9CTsJL0sGhJ\nCdJJEap84UVrXYL9W4xH5kdqSpbyJmRi8g7+9SuKDYwjQbrxEHErvlLqbrRRgNtU\nYhTnqQXRsi979JY/zbhhaBG/u6q20wKKh5PvqwiK7JXGgrQIiN+wBc4R8SvROy2B\nzsQNc0vkgZCxTgOrhRcHa5XkZVXmaFk8Vc7QMzadGjB455cy0yXVjJK1A6H705CO\n8i8/bSz+s0l9z4fxELG1uEPtH/DZypUrSRxhV6UU1fF/ltGFQib6XI3s7FvRKWev\nqlvZV1dpGUobK/tZiKkItGiVmDuHS98d3nEu07PkQrdrIDpedKBE70InQztk6BuO\nTJXpBjWvMH4G7P6/U3gIEV2lvvx53XljANu1Rj7bVhZH2YHavlIJ+TE=\n-----END CERTIFICATE-----\n" ],
        "qualified": null,
        "min_interval_ms": 0,
        "request_timeout_ms": 5000,
        "correlation_header": null,
        "source": "serveur RFC 3161 interne non qualifié (section 7) ; AC et politique de test des vecteurs CT-6"
      }
    ],
    "manifest": { "fallback_after_s": 300 },
    "checkpoints": { "interval_s": 300, "provider_role": "principal", "fallback_after_s": 120, "countersign_idle": false },
    "freshness": { "max_response_delay_s": 60, "clock_tolerance_s": 120 },
    "retry": { "initial_ms": 5000, "factor": 2, "max_ms": 300000, "jitter_ms": 250 },
    "retention_years": 10,
    "crl_capture": { "enabled": true, "delay_s": 600 }
  },
  "registry": { "checkpoints": "nouveaux_evenements", "squat_wait_s": 5, "inclusion_alert_s": 60 },
  "opentimestamps": {
    "enabled": true,
    "calendars": [
      "https://a.pool.opentimestamps.org",
      "https://b.pool.opentimestamps.org",
      "https://a.pool.eternitywall.com",
      "https://ots.btc.catallaxy.com"
    ],
    "min_responses": 2,
    "timeout_ms": 5000,
    "checkpoint": "aucun",
    "upgrade": {
      "whitelist": [
        "https://alice.btc.calendar.opentimestamps.org",
        "https://bob.btc.calendar.opentimestamps.org",
        "https://finney.calendar.eternitywall.com",
        "https://ots.btc.catallaxy.com"
      ],
      "first_after_s": 21600,
      "interval_s": 1800,
      "give_up_after_s": 1209600
    },
    "headers_source": { "type": "fichier", "network": "mainnet", "path": "/var/lib/noortrace/bitcoin/entetes-bitcoin.json" }
  },
  "queue": { "path": "/var/lib/noortrace/ancrage", "max_pending": 100000, "anchor_pending_alert_s": 7200 }
}
```

**EX-4.9 (AN-1, configuration)** Au démarrage et à chaque rechargement, le
composant d'ancrage valide le document contre son schéma, puis applique les
règles que le schéma n'exprime pas ; une règle violée refuse la configuration
(démarrage) ou le rechargement (l'ancienne reste en vigueur), avec un rapport
nominatif :

1. `checkpoint_interval_s` égal à la valeur de l'enregistreur et diviseur
   de 3600 ; en profil de production, la valeur de l'enregistreur DOIT être
   connue (CT-2 révision 0.4, `checkpoint_interval_s` de
   `configuration-enregistreur-v0`) : une valeur absente refuse la
   configuration ;
2. exactement un prestataire de rôle `principal` ; au plus un de rôle
   `secours` ; des `id` distincts ;
3. `rfc3161.checkpoints.interval_s` multiple de `checkpoint_interval_s` et
   diviseur de 3600 ;
4. en profil de production (CT-2 §15 : la même notion de profil que
   l'enregistreur) : `provider_role ≠ "aucun"`, `registry.checkpoints ≠
   "aucun"`, `opentimestamps.enabled = true`, le `principal` a `qualified ≠
   null`, le `secours`, s'il existe, a `qualified ≠ null` (révision 0.2 : la
   relève de la clôture reste qualifiée, EX-5.7), et tout `url` de rôle autre
   qu'`interne` commence par `https://` ;
   un `url` de rôle `interne` en `http://` n'est admis que vers une adresse
   locale (`127.0.0.1`, `::1`, `localhost`) ;
5. `opentimestamps.enabled = true` ⇒ au moins deux `calendars` distincts,
   `min_responses ≤ longueur de calendars`, au moins une entrée dans
   `upgrade.whitelist` ;
6. `rfc3161.retention_years ≥ 10` ; `retry.initial_ms ≤ retry.max_ms` ;
   `upgrade.interval_s ≥ 60` (CT-6 EX-13.6 ; R1-F64) ;
7. `provider_role = "second_rang"` ⇒ un prestataire de ce rôle existe ;
   `provider_role = "interne"` ⇒ un prestataire de ce rôle existe ;
8. chaque PEM d'`anchor_certificates` se lit comme un certificat par le
   lecteur de CT-6 §9.3 (sinon N-1 à l'acquisition : la configuration le dit
   d'avance).

### 4.5 Obligatoire et optionnel

**EX-4.10** En production :

| Élément | Statut | Motif |
|---|---|---|
| Points de contrôle produits par l'enregistreur (`c_K ≤ 60 s` DEVRAIT) | DOIT | P-1 ; CT-1 §10.5 |
| Ancre de chaque point qui engage un nouvel événement au registre | DOIT | P-2 ; fenêtre d'ordre 3.3 |
| Contresignature RFC 3161 des points toutes les `c_T ≤ 300 s` DEVRAIT, par le `principal` ou un `second_rang` | DOIT pour la cible de parité de 3.3 ; l'`interne` seulement si le modèle de menace exclut l'opérateur, ce que consigne la fiche de prestataire (EX-10.6) | P-3 ; fenêtre de date 3.3 ; contre l'opérateur, seul un prestataire extérieur borne `W_date` (EX-7.3) ; `aucun` hors production seulement |
| Jeton qualifié de la clôture, prestataire `principal` (`secours` en relève) | DOIT | P-4 ; CT-6 EX-13.4 ; architecture |
| Preuve OpenTimestamps du manifeste, au moins deux calendriers, mise à niveau | DOIT | P-4 ; CT-6 EX-13.5, EX-13.6 |
| Prestataire de `secours` qualifié | DEVRAIT | continuité de la clôture qualifiée pendant une panne du principal (5.3) |
| Preuve OpenTimestamps d'un point par période (`mi_periode`) | PEUT | réduit `W_bitcoin` pour la première moitié de l'heure (3.3) ; coût nul (section 12) |
| Serveur RFC 3161 interne (section 7) | PEUT | points intermédiaires sans jeton payant ; jamais une preuve qualifiée (R1-F55) |
| Fichier d'en-têtes Bitcoin joint au dossier (6.6) | DEVRAIT | CT-6 EX-13.7 ; sans lui, O-5 n'est pas exécutée tant que le réviseur ne produit pas le sien |
| Copie WORM des points, jetons, preuves et enregistrements d'acquisition (5.5) | DOIT quand `storage.seal.worm` est configuré (CT-2 §12.6) | P-6 |

### 4.6 Comptages

**EX-4.11** Pour la formule de coût (section 12) et le dimensionnement, le
composant d'ancrage DOIT pouvoir rendre, pour une configuration donnée, les
comptages suivants (AN-4), que la référence calcule sans réseau
(`compterJetons` d'`ancrage.mjs`) : par journal et par heure en fonctionnement
nominal, `n_T = 3600 / c_T` jetons RFC 3161, dont un jeton **qualifié** pour
la clôture et `n_T − 1` jetons de points par le prestataire du rôle
`provider_role` ; au plus `2 + 3600 / c_K` ancres `anchor` (`1 + 3600 / c_K`
points et le manifeste, 4.3) et un `submitPeriod` ; `1` soumission
OpenTimestamps (plus `1` si `checkpoint =
mi_periode`). Par jour : 24 fois ces valeurs ; par an : `N_h` fois, `N_h`
étant le nombre d'heures de l'année (8 760, ou 8 784 pour une année
bissextile). Table pour les valeurs de `c_T` admises les plus courantes
(`N_h = 8 760`) :

| `c_T` | Jetons par heure (`n_T`) | dont points (`n_T − 1`) | Jetons par jour | Jetons par an | Jetons **qualifiés** par an si `provider_role = principal` | si `provider_role = second_rang` ou `interne` |
|---|---|---|---|---|---|---|
| 60 | 60 | 59 | 1 440 | 525 600 | 525 600 | 8 760 qualifiés + 516 840 autres |
| 120 | 30 | 29 | 720 | 262 800 | 262 800 | 8 760 + 254 040 |
| 180 | 20 | 19 | 480 | 175 200 | 175 200 | 8 760 + 166 440 |
| **300** (défaut) | **12** | **11** | **288** | **105 120** | **105 120** | **8 760 + 96 360** |
| 600 | 6 | 5 | 144 | 52 560 | 52 560 | 8 760 + 43 800 |
| 900 | 4 | 3 | 96 | 35 040 | 35 040 | 8 760 + 26 280 |
| 1800 | 2 | 1 | 48 | 17 520 | 17 520 | 8 760 + 8 760 |
| 3600 | 1 | 0 | 24 | 8 760 | 8 760 | 8 760 |

Ces nombres sont des maxima : ils supposent au moins un nouvel événement
dans chaque intervalle de `c_T` secondes ; une échéance sans nouvel événement
ne consomme aucun jeton (EX-4.3, `countersign_idle` faux), de sorte qu'un
journal sans activité ne consomme que ses 24 jetons de clôture par jour ; une
panne du prestataire ne fait pas dépasser ces maxima : au retour, les demandes
de points déjà créées sont servies dans la limite de `n_T − 1` par période
(EX-4.3), et celles des périodes dont le jeton de clôture est obtenu passent
`remplacee` ; elle ne change pas le nombre des jetons de clôture (EX-4.5).
Seuls s'y ajoutent les jetons obtenus en double pendant une relève, quand
les deux prestataires sont sollicités en parallèle (EX-5.7, EX-8.8), qui se
comptent dans `r` (12.2), et le jeton du repli de clôture, au plus un par
période et seulement quand le registre tarde (EX-4.2). Une
requête en échec (réponse d'erreur, 50 à 60 octets, R1-F16) compte ou non dans
la facturation selon le modèle du prestataire (section 11, section 12 :
paramètre).

### 4.7 Jamais bloquant ; horloge

**EX-4.12** Aucune opération d'ancrage ne se trouve sur le chemin d'un appel
d'outil, d'un échange de modèle, de l'écriture d'un événement, de la
production d'un point ni de la clôture : l'enregistreur remet le point ou le
manifeste au composant d'ancrage, qui l'inscrit dans sa file durable (section
8) et rend la main ; les requêtes partent et sont réessayées hors de ce
chemin (CT-2 §14.2, « jamais bloquant » ; EX-4.5). Un prestataire, un
calendrier ou le registre injoignable n'a d'autre effet qu'un retard d'ancre,
consigné (`anchor_pending`, `registry_pending`), mesuré (section 8) et alerté
(CT-2 §17.4).

**EX-4.13** Les échéances `D_k` et les instants d'envoi sont lus sur
l'horloge de l'enregistreur (CT-2 §7.4) ; les délais de reprise et de
fraîcheur sur son horloge monotone. Un recul ou un saut d'horloge au-delà des
tolérances de CT-2 bloque l'écrivain (CT-2 EX-7.9, EX-7.13) et donc la
production des points ; le composant d'ancrage, lui, continue de servir la
file (les demandes déjà inscrites sont envoyées) et n'en inscrit pas de
nouvelles tant qu'aucun point n'est produit. Il ne corrige jamais un
`checkpoint_ts`, un `generated_at` ni un `genTime`.

### 4.8 Vérifications AN-1 à AN-4

| Id | Vérification | Entrées | Sortie |
|---|---|---|---|
| AN-1 | Configuration : schéma `ancrage-v0` puis les huit règles d'EX-4.9 | document `ancrage-v0`, profil, `checkpoint_interval_s` de CT-2 | `valide`, ou la liste complète des règles violées |
| AN-2 | Échéances et fenêtres : pour une période, la liste des `D_k` (EX-4.2) ; pour une série de points et une liste d'ancres obtenues (instant du bloc, `genTime + précision`), le point sélectionné à chaque échéance (EX-4.3 et EX-8.4, règle 1, font foi : dans le planificateur, le dernier point contresigné avance sur un jeton obtenu ou sur une demande `jeton_point` active, et recule sur un refus, qui rend ses échéances ; AN-2, qui ne reçoit que les ancres obtenues, toutes demandes closes, le fait avancer sur les seuls jetons obtenus), les échéances satisfaites et `remplacee` (EX-4.4), et les délais `d_registre`, `d_jeton` par ancre (3.3) ; constat de cadence (EX-4.1 : écart entre deux points consécutifs, ou entre le début de la période et le premier point, au plus `c_K` + 1 s ; `constaterCadence`) ; alertes `jeton_anterieur_au_point` (`genTime + précision < checkpoint_ts − clock_tolerance_s`) et `contresignature_tardive` (`genTime + précision − checkpoint_ts > c_T`) | `period_start`, configuration, série des points, ancres obtenues | table des échéances, délais, écarts de cadence, alertes (`checkpoint_anchor_late`, `jeton_anterieur_au_point`, `contresignature_tardive`, `point_manquant`) |
| AN-3 | Admission d'un objet à ancrer : signature du point (CT-1 §10.6) ou du manifeste (CT-1 §10.2) sous la clé en vigueur ; place du point dans la série (`prev_checkpoint_hash`, `tree_size` et `checkpoint_ts` non décroissants, `checkpoint_ts ≥ period_start`, CT-1 §10.5) ; quand les événements de la période sont fournis, `root`, `last_seq` et `last_hash` recalculés (CT-1 §10.5, règle 2 ; règles de refus `racine`, `last_seq`, `last_hash` d'`admettrePoint` (`ancrage.mjs`), la règle `racine` correspondant à la règle `root` de CT-1 §10.5 (`verifierSeriePointsDeControle`)) ; empreinte recalculée | point ou manifeste, série de la période, clés, événements (facultatif) | `admis` avec l'empreinte, ou `refuse` avec la règle |
| AN-4 | Sélection et comptages : points à ancrer au registre selon `registry.checkpoints` (EX-4.6) ; nombres de jetons, d'ancres et de soumissions par heure, par jour et par an pour une configuration (EX-4.11) | configuration, série des points | listes et comptages |

## 5. Client RFC 3161

### 5.1 La requête, octet pour octet

**EX-5.1** Une requête d'horodatage est une structure `TimeStampReq` (RFC
3161 §2.4.1) encodée en DER, sans aucun autre champ que ceux de la table, dans
cet ordre :

| Champ | Octets | Règle |
|---|---|---|
| `TimeStampReq` | `30 L` | `SEQUENCE`, longueur définie minimale |
| `version` | `02 01 01` | toujours 1 |
| `messageImprint` | `30 31` puis `hashAlgorithm` et `hashedMessage` (pour SHA-256) | `MessageImprint` |
| `hashAlgorithm` | `30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00` | SHA-256 seulement (EX-5.2) : `AlgorithmIdentifier` avec paramètres `NULL` explicites, forme que `openssl ts -query` écrit (R1-F16 : 56 octets pour une requête SHA-256 sans nonce ni `certReq`) |
| `hashedMessage` | `04 20` puis 32 octets | l'empreinte de l'objet ancré : `periodHash` ou `checkpointHash` ; la longueur égale celle de l'algorithme (RFC 3161 §2.4.1, R1-F8) |
| `reqPolicy` | `06 …` | **absent** sauf si `policy_oid` du prestataire est non nul (EX-5.4) |
| `nonce` | `02 L` puis 1 à 9 octets | `INTEGER` DER de l'entier non signé de 64 bits d'EX-5.3 : encodage minimal, octet `00` de tête seulement si le bit de poids fort du premier octet significatif vaut 1 |
| `certReq` | `01 01 ff` | toujours `TRUE` (EX-5.4) |
| `extensions` | — | jamais (EX-5.4) |

Toute autre forme (champ supplémentaire, longueur non minimale, `BOOLEAN`
autre que `ff`, nonce encodé avec des zéros superflus) n'est pas une requête
de CT-5 ; la référence la refuse à la construction (AN-5). La requête fait au
plus 70 octets en SHA-256 sans politique : 69 ou 70 dans la quasi-totalité des
cas (nonce de 8 ou 9 octets), moins quand les octets de tête du nonce sont
nuls ; c'est aussi la taille de la forme que `openssl ts -query -digest
<empreinte> -sha256 -cert` produit (nonce de 64 bits tiré par OpenSSL ;
R1-F16 : « SHA-256 + nonce 64 bits + certReq = 70 octets »).

Exemple : requête sur `checkpointHash` du point `K2` de CT-1 §10.5
(`0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff`), avec
le nonce de CT-1 §13 (`0x74a6f4979421411e`, 64 premiers bits de
`SHA-256(UTF-8("noortrace/vecteurs/v0/ct-1/nonce-tsa/point-de-controle/exemple"))`),
69 octets :

```text
30 43                                              TimeStampReq, 67 octets
   02 01 01                                        version 1
   30 31                                           messageImprint
      30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 sha256, NULL
      04 20 6a 8e 03 5a b9 b9 09 37 a5 b0 d4 11 18 56 7c 95
            2f 3c e4 9c 89 5b 81 63 6a b7 0b 51 62 53 e6 ff  checkpointHash K2
   02 08 74 a6 f4 97 94 21 41 1e                   nonce (bit de poids fort nul : 8 octets)
   01 01 ff                                        certReq TRUE

hex : 30430201013031300d0609608648016503040201050004206a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff020874a6f4979421411e0101ff
```

Avec un nonce dont le bit de poids fort vaut 1, par exemple
`0xf4a6f4979421411e`, le champ devient `02 09 00 f4 a6 f4 97 94 21 41 1e` et la
requête fait 70 octets (`30 44 …`). Avec `reqPolicy = 1.3.6.1.4.1.99999.1.1`
(politique de l'autorité de test de CT-6), le champ
`06 0a 2b 06 01 04 01 86 8d 1f 01 01` s'insère entre `messageImprint` et
`nonce` : 81 octets.

Confrontation (annexe A) : `openssl ts -query -in requete-point-k2.tsq -text`
(OpenSSL 3.0.13) rend `Version: 1`, `Hash Algorithm: sha256`, les 32 octets
de l'empreinte, `Policy OID: unspecified`, `Nonce: 0x74A6F4979421411E`,
`Certificate required: yes` ; et `openssl ts -verify -queryfile
requete-point-k2.tsq -token_in -in <jeton de CT-1 §11.2> -CAfile ac-test.pem
-untrusted tsa-test.pem` rend « Verification: OK » : le jeton de l'exemple de
CT-1 répond exactement à cette requête (même empreinte, même nonce). Les deux
fichiers sont publiés dans `spec/vecteurs/ct-5` (annexe A).

**EX-5.2** L'algorithme du `messageImprint` est SHA-256, et seulement lui en
version 0 (`hash = "sha256"`) : l'empreinte est `periodHash` ou
`checkpointHash` tels quels, ce que T-2 et K-7 de CT-6 comparent. Un jeton
sur un autre algorithme (SHA-384, SHA-512, que les prestataires lus acceptent
aussi, R1-F20, R1-F35, R1-F43) porterait une autre empreinte du même fichier
`P ‖ C`, échouerait à T-2 et ne servirait à rien dans un dossier v0 ; son
admission relève d'une version ultérieure de CT-6 et de CT-5 (section 15).
Les prestataires lus acceptent tous SHA-256 (R1-F20, R1-F35, R1-F36, R1-F38,
R1-F43). SHA-1 et MD5 ne sont jamais envoyés : un prestataire conforme les
refuse (`badAlg`, R1-F8) et CT-6 §15.4 les refuse à la vérification.

**EX-5.3 (AN-6, nonce)** Chaque tentative porte un nonce **nouveau** : 64
bits tirés d'un générateur aléatoire cryptographique, formant l'entier non
signé `n ∈ [1, 2^64 − 1]` (un tirage nul est rejoué), encodé en `INTEGER` DER
minimal. Le même nonce n'est jamais réemployé pour un même journal, ce que la
référence contrôle contre le journal d'acquisition de la file (section 8) ;
une nouvelle tentative pour la même empreinte (reprise, relève par le
secours, réponse tardive) porte un nouveau nonce, de sorte qu'une réponse
tardive d'une tentative antérieure soit reconnaissable et ne soit jamais
promue à la place de la réponse attendue (RFC 3161 §4, point 4, R1-F13 ; R1,
conséquence 7). Le nonce ne prouve que la fraîcheur de la réponse (RFC 3161
§2.4.1, R1-F1) ; il n'est jamais une date et n'est contrôlé qu'à l'acquisition
(CT-6 EX-9.15, EX-13.2). Les vecteurs dérivent leurs nonces d'étiquettes
publiées, comme CT-1 §13.

**EX-5.4** `certReq` vaut toujours `TRUE` : la réponse porte alors le
certificat de l'unité d'horodatage (RFC 3161 §2.4.1, R1-F4 ; RFC 5816 pour
`ESSCertIDv2`, R1-F14) et T-4 de CT-6 ne dépend pas du fichier d'ancres du
réviseur (CT-6 EX-13.1). Aucune extension n'est envoyée : une extension non
reconnue fait refuser la requête (`unacceptedExtension`, R1-F8). `reqPolicy`
n'est présent que si `policy_oid` du prestataire est non nul ; il vaut alors
cet OID et la réponse DOIT porter la même politique (RFC 3161 §2.4.2, R1-F5 ;
5.4). Par défaut, aucune politique n'est demandée : le prestataire applique
la sienne, que `accepted_policies` contrôle à l'acquisition (T-9).

### 5.2 Transport

**EX-5.5 (AN-7)** La requête est envoyée par HTTP sur TLS (version 1.2 au
moins), méthode `POST`, vers `url` du prestataire, avec `Content-Type:
application/timestamp-query`, `Accept: application/timestamp-reply,
application/timestamp-response`, `Content-Length` exact et le DER de la
requête pour seul corps (RFC 3161 §3.4, R1-F9 : la RFC nomme la réponse
`application/timestamp-reply` dans un paragraphe et
`application/timestamp-response` dans un autre, et les deux sont admis en
réponse). La variante `GET` qu'un prestataire peut offrir (requête encodée
dans l'URL, R1-F35) n'est jamais employée : elle inscrit la requête dans les
journaux d'accès des intermédiaires. L'authentification suit `auth.method` :
`basic` (RFC 7617, en-tête `Authorization`, seulement sur TLS ; R1-F35,
R1-F41), `certificat_client` (authentification TLS mutuelle par un certificat
d'accès, R1-F31, R1-F46), `aucune` (rôle `interne` sur une adresse locale
seulement, AN-1). Quand `correlation_header` est non nul, l'en-tête porte
l'identifiant de tentative (5.4), que le prestataire reprend dans ses
journaux (R1-F35 : `X-Request-ID`, `X-Correlation-ID`). Le délai d'une
requête est `request_timeout_ms` ; au moins `min_interval_ms` séparent deux
requêtes vers le même prestataire, quel que soit l'objet (CT-6 EX-13.4). Une
réponse de statut HTTP 200 dont le corps est une `TimeStampResp` DER d'au plus
128 Kio est lue (5.4) ; tout autre statut, un `Content-Type` autre que les
deux admis ou un corps plus long est une erreur classée par EX-5.12. Aucun
mandataire ni cache intermédiaire côté client ne se trouve sur le chemin des
requêtes d'ancrage (CT-4 EX-10.5, même motif qu'EX-4.7).

### 5.3 Choix du prestataire

**EX-5.6** Les quatre rôles et leur emploi :

| Rôle | Qualifié | Objets | Quand |
|---|---|---|---|
| `principal` | DOIT (AN-1, production) | manifeste ; points si `provider_role = principal` | toujours en premier pour le manifeste ; pour les points, à chaque échéance |
| `secours` | DOIT, s'il est configuré | manifeste ; points si `provider_role = principal` | en relève du principal (EX-5.7) |
| `second_rang` | PEUT | points si `provider_role = second_rang` | à chaque échéance ; sans relève |
| `interne` | jamais (R1-F55) | points si `provider_role = interne` | à chaque échéance ; sans relève ; section 7 |

**EX-5.7 (AN-12, relève)** Manifeste : la demande part au `principal` ; si
aucun jeton valable n'est obtenu `rfc3161.manifest.fallback_after_s` après la
première tentative, ou dès la première erreur **permanente** (EX-5.12), la
demande part aussi au `secours`, et les deux sont poursuivies en parallèle
jusqu'à obtention d'un jeton valable de l'un d'eux ; les tentatives de l'autre
sont alors arrêtées, et un jeton qui arriverait encore est conservé (5.5) sans
être promu. La demande n'est jamais abandonnée (EX-4.5). Points : la demande
part au prestataire du rôle `provider_role` ; pour `principal`, la relève par
le `secours` suit la même règle avec `rfc3161.checkpoints.fallback_after_s` ;
pour `second_rang` et `interne`, il n'y a pas de relève. Sans relève (ou
relève épuisée), une demande de point en erreur **transitoire** reste
`a_reprendre` et passe `remplacee` quand une échéance postérieure est
satisfaite (EX-4.4) ; en erreur **permanente**, elle passe `refusee` (EX-8.8)
et rend ses échéances, qui redeviennent ouvertes (EX-4.3) : le point suivant
qui engage un nouvel événement les sert, sinon elles sont closes `remplacee`
quand une échéance postérieure est satisfaite. Si `principal` et `secours`
échouent tous deux de façon permanente sur un manifeste, la demande reste
ouverte, réessayée à la cadence maximale de `retry` (section 8), et l'alerte
« ancre en retard » est levée au délai de CT-2 §17.4.

**EX-5.8 (AN-13, jeton retenu)** Quand plusieurs jetons valables existent pour
la même empreinte (relève, réponse tardive, nouvelle tentative après
`horloge_suspecte`), tous sont conservés (5.5) et **un seul** est remis au
dossier : parmi ceux d'un prestataire dont `qualified` est non nul, celui dont
`genTime + précision` est le plus petit ; à défaut, le plus petit parmi tous.
Le choix est déterministe et consigné dans l'enregistrement d'acquisition ;
l'exportateur (section 10) ne choisit pas lui-même. La règle s'applique aux
jetons valables et frais (EX-5.10, étapes 1 à 7) déjà reçus au moment où la
demande passe `obtenue`, et ce choix est fait une seule fois : un jeton reçu
après ce moment (tentative de l'autre prestataire arrêtée trop tard, EX-5.7)
ou une réponse tardive non promue (EX-5.11) est conservé comme pièce et n'est
jamais promu. Le champ `promoted` d'EX-5.13 désigne ce choix ; il ne change
qu'à une révocation constatée (EX-5.10, étape 10 ; `obtenue → a_reprendre`,
EX-8.3).

**EX-5.9 (qualifié, mesurable)** Un prestataire est tenu pour qualifié par
le composant d'ancrage, et son objet `qualified` renseigné, si et seulement si
l'exploitant a constaté, et consigne dans `qualified.source` avec la date de
lecture :

1. pour `eidas` : une liste de confiance nationale référencée par la liste
   des listes de la Commission européenne
   (`https://ec.europa.eu/tools/lotl/eu-lotl.xml`, R1-F48) contient, pour ce
   prestataire, un service de type
   `http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST` au statut
   `http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted` dont l'identité
   numérique correspond aux `anchor_certificates` (sujet ou clé publique de
   l'unité ou de son AC), à la date de lecture ; le territoire, le numéro de
   séquence, la date d'émission et l'URL de la liste sont écrits dans
   `qualified.trusted_list` (R1-F26, R1-F39, R1-F42, R1-F45, R1-F47) ;
2. pour `zertes` : la liste de confiance suisse (CT-6 §12.5 : « recognised »
   y vaut « qualified » ; territoire `CH`, numéro de séquence, date d'émission
   et URL écrits dans `qualified.trusted_list`) donne le service comme
   reconnu, et l'attestation de l'organisme de reconnaissance accrédité
   (certificat de reconnaissance, R1-F28) est conservée hors du dépôt public
   et citée dans `qualified.source` ; la note R1 n'a pas obtenu cette liste
   (NV-5) : tant qu'elle n'a pas été lue, aucun prestataire n'est déclaré
   `qualified` au titre de `zertes`, l'attestation seule ne suffisant pas plus
   qu'une déclaration du prestataire.

Une déclaration du prestataire, une page commerciale ou la seule présence du
`qcStatement` `0.4.0.19422.1.1` dans le certificat de l'unité ne suffisent pas :
le `qcStatement` est un indice (R1-F21, R1-F43 ; EN 319 422 non relue, non
vérifié R1 NV-10), la liste de confiance fait foi (R1-F43 : « A Relying Party
is expected to use a Trusted List to establish whether the TSP and the TSU are
Qualified »). Le statut est ré-établi à chaque nouvelle séquence de la liste
et au plus tard tous les trente jours (valeur de conception, CT-8), et un
changement (statut `withdrawn`, R1-F45, R1-F47) retire `qualified` et lève une
alerte. Le rôle configuré ne change pas tant que l'exploitant n'a pas rechargé
une configuration : les jetons sont acquis avec l'instantané `qualified =
null`, donc non qualifiés ; pour la clôture, la relève par le secours qualifié
s'applique comme pour une erreur permanente du principal (EX-5.7) ; AN-1
(règle 4) refuse tout rechargement tant qu'aucun principal qualifié n'est
désigné. Cette règle est normative pour le composant d'ancrage ; dans la
version 0, ni la référence ni les vecteurs ne l'exercent (aucune entrée du
planificateur ne porte le retrait) : l'exploitant l'applique en provoquant la
relève, et le test reste à écrire (CT-9, section 14). Les jetons déjà promus
gardent l'instantané `qualified` consigné à leur acquisition (EX-5.13). Pour le réviseur, tout ceci est déclaratif : il établit lui-même
le statut dans son fichier d'ancres (CT-6 §12.5, T-11) ; l'instantané de
`qualified` au moment de l'acquisition est consigné (5.4) et transmis
(section 10) pour l'aider.

### 5.4 Vérification avant stockage

**EX-5.10 (AN-8 à AN-11)** À la réception d'une réponse, le composant
d'ancrage exécute, dans cet ordre, et s'arrête à la première étape en échec :

| Étape | Vérification | Code d'erreur | Classe (EX-5.12) | Source |
|---|---|---|---|---|
| 1 | Statut HTTP 200, `Content-Type` admis, corps ≤ 128 Kio (EX-5.5) | `http_<statut>`, `type_contenu`, `taille` | selon le statut (EX-5.12) | R1-F9 |
| 2 | Le corps se lit comme une `TimeStampResp` par le lecteur DER borné de CT-6 §9.3 ; `status` (`PKIStatus`) vaut 0 ou 1 et un `TimeStampToken` est présent ; `status` 2 à 5 : pas de jeton, `PKIFailureInfo` lu ; toute autre valeur : erreur | `reponse_illisible`, `statut_<n>`, `echec_<failureInfo>` (`badAlg`, `badRequest`, `badDataFormat`, `timeNotAvailable`, `unacceptedPolicy`, `unacceptedExtension`, `addInfoNotAvailable`, `systemFailure`) | voir EX-5.12 | RFC 3161 §2.4.2, R1-F6, R1-F7 |
| 3 | `messageImprint.hashAlgorithm` égal à celui de la requête et `hashedMessage` égal à l'empreinte envoyée | `empreinte_differente` | permanente, alerte | RFC 3161 §2.2, R1-F3 |
| 4 | `nonce` présent dans `TSTInfo` et égal à celui de la requête | `nonce_absent`, `nonce_different` | permanente, alerte | RFC 3161 §2.4.2, R1-F2 |
| 5 | Si `reqPolicy` a été envoyé : `policy` égal ; dans tous les cas, `policy` dans `accepted_policies` quand elle n'est pas `null` | `politique_differente`, `politique_refusee` | permanente | RFC 3161 §2.4.2, R1-F5 |
| 6 | T-1 à T-9 de CT-6 §9.5 (`verifierJeton` d'`horodatage.mjs`, avec pour empreinte attendue celle de la requête et pour ancres les `anchor_certificates` et `accepted_policies` du prestataire), T-7 évaluée à `genTime` ; T-11 n'est pas exécutée ici (`qualified` est déclaratif, EX-5.9) | `verification_T-<n>` | permanente, alerte | CT-6 EX-13.2 |
| 7 | Fraîcheur (EX-5.11) : `received_at − sent_at ≤ max_response_delay_s` | `reponse_tardive` | transitoire (nouvelle tentative, nouveau nonce) | RFC 3161 §4, point 4, R1-F13 |
| 8 | Horloge (EX-5.11) : `\|genTime − sent_at\| ≤ clock_tolerance_s` | `horloge_suspecte` (avertissement : le jeton est promu) | — | R1, conséquence 1 |
| 9 | Écriture (5.5) : requête, réponse complète, jeton extrait, enregistrement d'acquisition, puis `fsync` ; la demande passe à `obtenue` | `ecriture` | transitoire | CT-6 EX-13.3 |
| 10 | Différé de `crl_capture.delay_s` : capture de la CRL (ou réponse OCSP) de chaque certificat du chemin de T-7, émise après `genTime`, puis T-10 ; une révocation lève une alerte critique, marque le jeton `revoque`, et la demande passe de `obtenue` à `a_reprendre` (EX-8.3) et repart au secours ; une même capture sert à tous les jetons d'une même unité dont le `genTime` la précède (CT-6 EX-13.17) | `crl_indisponible` (réessayée), `revoque` | — | CT-6 EX-13.12, EX-13.17, T-10 |

Les étapes 3 à 6 refont ce que RFC 3161 §2.2 impose au demandeur (R1-F3 :
« what was time-stamped corresponds to what was requested », identifiant de
certificat, condensé, OID, fraîcheur par le nonce, signature, puis statut de
révocation). Dans les traces du planificateur (8.10), l'entrée
`reponse_rfc3161` porte, outre le corps, `content_type`, `body_size` et
`policy_check` (issue de l'étape 5 : `conforme`, `politique_differente`,
`politique_refusee`), de sorte que le classement des erreurs rejoue les
étapes 1 et 5 (`classer`, trace `reponse-hors-profil`). Elles ne remplacent pas
la vérification du réviseur (CT-6 contrôle 4), qui refait tout avec ses propres
ancres ; elles garantissent qu'aucun jeton inutilisable n'est stocké comme
ancre, et que le défaut est vu à l'instant où une nouvelle tentative est encore
utile.

**EX-5.11 (AN-10, fraîcheur)** `sent_at` et `received_at` sont lus sur
l'horloge monotone de l'enregistreur et convertis en instants UTC au moment
de l'envoi (H8). Une réponse reçue plus de `max_response_delay_s` après
l'envoi est **suspecte** (RFC 3161 §4, point 4) : son jeton est conservé
comme pièce (5.5) sans être promu, et une nouvelle tentative, avec un nouveau
nonce, est faite ; si la nouvelle réponse est fraîche, elle est promue ; si
trois réponses successives sont tardives, la troisième est promue avec
l'avertissement `reponse_tardive` et l'alerte `reponse_tardive_promue`
(mineure, 8.9), pour ne pas priver la période
d'ancre. Un `genTime` qui s'écarte de `sent_at` de plus de
`clock_tolerance_s` ne fait pas échouer la tentative : le jeton est promu,
marqué `horloge_suspecte`, et une alerte est levée, parce que l'écart vient
soit de l'horloge locale (CT-2 §7.4 la surveille), soit de l'autorité (H4),
et que dans les deux cas le réviseur jugera avec ses ancres (CT-6 AV-T-4,
§7.2). Le délai `d_jeton` mesuré par la supervision (AN-2) est `genTime +
précision − D_k` pour un point, `genTime + précision − period_end` pour un
manifeste.

**EX-5.12 (AN-11, classement des erreurs)** Toute tentative en échec est
classée `transitoire` ou `permanente` ; la file (section 8) rejoue une erreur
transitoire avec l'attente de `retry` (initiale `initial_ms`, multipliée par
`factor` à chaque échec, plafonnée à `max_ms`, plus une gigue uniforme dans
`[0, jitter_ms]`), en respectant un en-tête `Retry-After` quand il est présent
(secondes ou date RFC 1123), et ne rejoue **jamais** une erreur permanente
sans modification (changement de prestataire, de politique ou de
configuration) :

| Cause | Classe | Conduite |
|---|---|---|
| Erreur de transport : résolution de nom, connexion, TLS, réinitialisation, délai `request_timeout_ms` | transitoire | rejouer ; nouveau nonce |
| HTTP 408 | transitoire | rejouer immédiatement une fois, puis avec attente |
| HTTP 429, 500, 502, 503, 504 | transitoire | rejouer après `Retry-After` ou l'attente de `retry` |
| Autre HTTP 4xx ou 5xx, `Content-Type` non admis, corps trop long, réponse illisible | permanente | ne pas rejouer ; alerte ; relève (EX-5.7) |
| `PKIStatus` 2 (`rejection`) avec `badAlg`, `badRequest`, `badDataFormat`, `unacceptedPolicy`, `unacceptedExtension`, `addInfoNotAvailable` | permanente | la requête est en cause : alerte nominative ; relève |
| `PKIStatus` 2 avec `timeNotAvailable` ou `systemFailure`, `PKIStatus` 3 (`waiting`) | transitoire | rejouer ; nouveau nonce |
| `PKIStatus` 4 ou 5 (`revocationWarning`, `revocationNotification`) | permanente, alerte critique | le certificat de l'unité est ou va être révoqué : relève immédiate ; le prestataire perd `qualified` jusqu'à décision de l'exploitant |
| Empreinte, nonce ou politique différents (étapes 3 à 5), T-1 à T-9 en échec | permanente, alerte | la réponse est conservée comme pièce ; relève |
| Réponse tardive (étape 7) | transitoire | EX-5.11 |
| Écriture impossible (étape 9) | transitoire | rejouer l'écriture ; la réponse reçue n'est pas renvoyée |

Les règles de reprise ne sont pas propres à CT-5 : rejouer sans modification
sur 500 et 503 en respectant `Retry-After`, ne pas rejouer un 4xx sans
modification (RFC 9162 §4 pour les journaux de transparence, R1-F68 ;
pratique du client de Certificate Transparency : 408 immédiat, 429 et 503 avec
attente et gigue, échéance fixée par l'appelant, R1-F70). Aucun des
prestataires lus ne publie de recommandation de reprise (R1-F73) : la seule
règle normative est celle de RFC 3161 §4, point 4 (R1-F13).

**EX-5.13 (AN-14, enregistrement d'acquisition)** Chaque tentative, qu'elle
aboutisse ou non, produit un enregistrement en ajout seul dans la file
(section 8 en fixe le fichier et sa durabilité), avec au moins : `attempt_id`
(identifiant unique, repris dans `correlation_header`), `org_id`,
`journal_id`, `period_start`, `object` (`manifeste` ou `point`), `imprint`
(l'empreinte demandée), `hash_algorithm`, `deadline_index` (`k`, ou `null`
pour le manifeste), `provider_id`, `provider_role`, `qualified` (instantané
d'EX-5.9 ou `null`), `nonce`, `request_sha256`, `sent_at`, `received_at`,
`http_status`, `pki_status`, `pki_failure_info`, `outcome` (`obtenue`,
`echec_transitoire`, `echec_permanente`, `reponse_tardive`, et `en_cours` tant
que la réponse n'est pas arrivée, 8.2), `error_code`
(5.4), `token_sha256`, `gen_time`, `accuracy`, `upper_bound` (`genTime +
précision`), `serial_number`, `policy`, `tsu_subject`, `freshness` (`nonce`,
`horloge_suspecte`), `checks` (statut de T-1 à T-10), `promoted` (le jeton
retenu d'EX-5.8), et les chemins des fichiers écrits (5.5). Il ne contient
jamais le secret d'accès. Il est la source des métriques de la section 8 et
de ce que l'exportateur remet au réviseur (section 10).

### 5.5 Stockage et conservation

**EX-5.14 (AN-14)** Les pièces d'horodatage sont écrites sous la racine de
stockage de l'enregistreur (CT-2 EX-12.1), par journal :

```text
<root>/<org_id>/<journal_id>/ancres/periode-<period_start>/
  rfc3161/<objet>-<provider_id>-<attempt_id>.tsq     requête TimeStampReq, DER tel qu'envoyé
  rfc3161/<objet>-<provider_id>-<attempt_id>.tsr     réponse TimeStampResp, DER tel que reçu (réponse d'erreur comprise)
  rfc3161/<objet>-<provider_id>-<attempt_id>.der     TimeStampToken extrait, DER tel quel (absent si la réponse n'en porte pas)
  rfc3161/<objet>-<provider_id>-<attempt_id>.crl.pem CRL capturées après genTime (EX-5.10, étape 10), une par certificat du chemin
  ots/<objet>-<n>.ots                                preuve OpenTimestamps, version n (6.5)
  entetes-bitcoin.json                               fichier d'en-têtes de la période (6.6)
  acquisitions.ndjson                                enregistrements d'acquisition de la période (EX-5.13), ajout seul
```

où `<objet>` vaut `manifeste` ou `point-<checkpointHash sans 0x>`,
`<period_start>` s'écrit sur dix chiffres et `<attempt_id>` est ASCII et
triable ; les noms de fichiers sont ceux que porte l'enregistrement
d'acquisition (un jeton sous un autre nom n'est pas une pièce de CT-5). Les
points eux-mêmes sont écrits par l'enregistreur (CT-1 §15 : « la copie des
points relève de CT-2 » ; proposition pour CT-2 §12.1 en section 14) ; les
captures des transactions du registre suivent CT-4 §9.4. Le jeton remis au
dossier comme partie `jeton_rfc3161` est le fichier `.der` du jeton promu,
copié octet pour octet (CT-6 EX-13.3 : jamais réencodé ; le vérificateur
compare les SHA-256). Toute écriture est synchronisée sur le disque avant que
la demande soit dite `obtenue` (EX-5.10, étape 9), et un fichier existant
n'est jamais réécrit (CT-4 EX-9.3, même règle).

**EX-5.15 (AN-15, conservation)** Les fichiers de 5.5 et la file sont
conservés **au moins dix ans** (`rfc3161.retention_years ≥ 10`), durée que le
plan fixe ; elle couvre la rétention des événements de CT-2 EX-12.19 (dix ans
à compter de la fin de l'exercice, CO art. 958f), et son ajustement à toute
durée légale plus longue relève de CT-7. Rien dans le composant d'ancrage ne
supprime une pièce ; la fin de rétention est un acte d'exploitation (CT-8).
Quand `storage.seal.worm` est configuré, le répertoire `ancres/` de chaque
période est copié vers le support WORM comme les manifestes (CT-2 EX-12.16 :
clé d'objet portant l'époque, écriture conditionnelle à l'absence, mode sans
contournement par aucun rôle du client, rétention au moins égale à celle des
événements) ; la supervision compare les SHA-256 (CT-2 EX-12.17). Ce qu'une
telle copie établit et ce qu'elle laisse déclaratif est fixé par les pages
officielles des supports (R2-F29 à R2-F40) : une version écrite ne peut plus
être écrasée ni supprimée avant l'échéance, pour personne dans le mode sans
contournement, mais la date d'écriture rendue par l'API n'est pas signée et
rien n'empêche une nouvelle version sous la même clé (R2-F30, R2-F36) ; la
copie complète donc les ancres sans jamais en tenir lieu (CT-2 §12.6 ; P-6).
Le renouvellement d'un horodatage avant l'affaiblissement de son algorithme ou
l'expiration de son certificat (RFC 3161 §4, point 3, R1-F13) n'est pas dans
la version 0 (section 15 ; CT-6 §17).

### 5.6 Canal sans `TimeStampReq`

**EX-5.16** La version 0 ne couvre que le transport de RFC 3161 §3.4 : une
`TimeStampReq` DER envoyée telle quelle, une `TimeStampResp` DER reçue telle
quelle. Un prestataire qui n'expose son horodatage qu'au travers d'une
enveloppe (un condensé en entrée, un jeton en sortie, sans nonce ni `certReq`
exposés ; R1-F30, R1-F32, non vérifié R1 NV-1 et NV-4) ne peut pas tenir le
rôle `principal` ni `secours` en version 0 : la fraîcheur par le nonce
(EX-5.3) et l'égalité de la requête (EX-5.10, étapes 3 à 5) n'y sont pas
mesurables. Un adaptateur pour un tel canal, avec fraîcheur par l'horloge
locale et marquage `fraicheur: horloge_locale`, est une proposition de la
section 15 ; la section 11 dit, prestataire par prestataire, ce qui est
publié.

### 5.7 Vérifications AN-5 à AN-15

| Id | Vérification | Entrées | Sortie |
|---|---|---|---|
| AN-5 | Requête : octets DER exacts d'EX-5.1 pour (empreinte, algorithme, nonce, politique) ; refus de toute autre forme ; relecture par un lecteur DER borné (CT-6 §9.3) identique à l'entrée | empreinte, `hash`, nonce, `policy_oid` | octets, ou refus |
| AN-6 | Nonce : 64 bits, `n ≥ 1`, encodage minimal, nouveau à chaque tentative, jamais réemployé dans le journal d'acquisition | tentative, journal d'acquisition | `conforme`, ou `nonce_reemploye`, `nonce_mal_encode` |
| AN-7 | Transport : méthode, en-têtes, corps, TLS, authentification, délai, `min_interval_ms` (EX-5.5), observés sur un prestataire de test | configuration, trace HTTP | conformité de chaque en-tête et délai |
| AN-8 | Réponse : lecture DER bornée, `PKIStatus` 0 ou 1 avec jeton, 2 à 5 sans jeton, autre valeur refusée (EX-5.10, étapes 1 et 2) | `TimeStampResp` | statut, `PKIFailureInfo`, jeton extrait |
| AN-9 | Égalités : empreinte et algorithme, nonce, politique (étapes 3 à 5) ; puis T-1 à T-9 avec l'empreinte demandée et les ancres du prestataire (étape 6) ; T-10 différée (étape 10) | requête, réponse, `anchor_certificates`, `accepted_policies`, CRL | statut de chaque égalité et de T-1 à T-10 |
| AN-10 | Fraîcheur : `received_at − sent_at` contre `max_response_delay_s` ; `genTime` contre `sent_at` et `clock_tolerance_s` ; conduite d'EX-5.11 (troisième réponse tardive promue avec avertissement) | enregistrement d'acquisition | `fraiche`, `reponse_tardive`, `horloge_suspecte` |
| AN-11 | Classement d'une erreur en `transitoire` ou `permanente` et attente de reprise (table d'EX-5.12 ; `Retry-After` ; gigue bornée) | cause, `retry`, en-têtes | classe, attente |
| AN-12 | Choix du prestataire et relève (EX-5.6, EX-5.7) : pour une suite datée de tentatives et de résultats, le prestataire sollicité à chaque instant et l'état de la demande | configuration, trace de tentatives | prestataire par tentative, `obtenue` ou `remplacee` |
| AN-13 | Jeton retenu parmi plusieurs jetons valables (EX-5.8) | jetons, `qualified` par prestataire | le jeton promu |
| AN-14 | Stockage : noms de fichiers, octets identiques à ceux envoyés et reçus (SHA-256), enregistrement d'acquisition complet et sans secret (EX-5.13, EX-5.14) | répertoire `ancres/`, file | conformité fichier par fichier |
| AN-15 | Conservation : `retention_years ≥ 10` ; aucune opération de suppression dans le composant ; copie WORM demandée pour `ancres/` quand `storage.seal.worm` est configuré (EX-5.15) | configuration, journal d'exploitation | conformité |

## 6. Client OpenTimestamps

### 6.1 Ce qui est horodaté

**EX-6.1 (AN-16)** Le fichier horodaté est la suite d'octets de l'objet
préfixé : `P_M ‖ C_M` pour un manifeste (empreinte de fichier `periodHash`,
CT-6 EX-10.1, EX-13.5), `P_K ‖ C_K` pour un point de contrôle (empreinte
`checkpointHash`, CT-1 §10.6). L'opération de hachage du fichier est SHA-256
(`08`) : l'empreinte écrite dans le fichier `.ots` est exactement `periodHash`
ou `checkpointHash`, ce que O-2 et K-9 de CT-6 comparent. Le composant
d'ancrage recalcule l'empreinte depuis les octets du fichier avant toute
soumission ; il ne la lit jamais dans `manifeste.sig` ni dans un
enregistrement. Exemple : le fichier `P_K ‖ C_K` du point `K2` de CT-1 §10.6
fait 572 octets et son SHA-256 est
`0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff`.

Le manifeste est horodaté à chaque clôture quand `opentimestamps.enabled` est
vrai (CT-6 EX-13.5) ; un point par période l'est en option
(`opentimestamps.checkpoint = "mi_periode"`) : le point sélectionné à
l'échéance `D_{k_m}`, `k_m = ⌈n_T / 2⌉` (`D_6`, trente minutes après le début
de la période, avec `c_T = 300` ; `D_3` avec `c_T = 720`, `n_T = 5` impair,
trace `mi-periode-impair`) ; aucun si `n_T = 1`. La soumission ne dépend pas de
la contresignature : quand l'échéance médiane est satisfaite sans requête
(`sans_objet`, aucun nouvel événement) ou que le rôle des points est `aucun`,
le point sélectionné à `D_{k_m}` est soumis quand même.

### 6.2 Soumission aux calendriers

**EX-6.2 (AN-17)** La soumission reproduit `ots stamp` du client officiel
(`otsclient/cmds.py`, `stamp_command` et `create_timestamp`, lus le
2026-10-25 ; R1-F56, R1-F61, R1-F62) : (1) un nonce de 16 octets, tiré d'un
générateur aléatoire cryptographique, est ajouté à la fin de l'empreinte
(opération `f0`), puis le résultat est haché (opération `08`) : l'engagement
`e = SHA-256(empreinte ‖ nonce)` ; (2) `e` (32 octets) est envoyé à chacun des
`calendars` par `POST <url>/digest`, corps = les 32 octets, en-tête `Accept:
application/vnd.opentimestamps.v1` (`opentimestamps/calendar.py`, R1-F63 ; le
serveur refuse un condensé de plus de 64 octets, R1-F64) ; (3) chaque réponse
200 (`application/octet-stream`, au plus 10 000 octets, R1-F63) est un
`Timestamp` sérialisé portant sur `e` : une suite d'opérations d'agrégation
du calendrier terminée par une attestation en attente qui porte l'URI du
calendrier (R1-F60, R1-F64) ; elle est relue par le lecteur de CT-6 §10.2
(mêmes règles que O-1, profil `{f0, f1, 08}` de O-3) et refusée sinon ; (4)
quand au moins `min_responses` réponses valables sont arrivées dans
`timeout_ms` (défaut 2 et 5 000 ms, valeurs du client officiel, R1-F61), le
fichier `.ots` est écrit (6.3) ; sinon la demande reste dans la file et la
soumission est rejouée plus tard avec le **même** nonce et le même engagement
(un calendrier qui a déjà journalisé `e` rend la même promesse : le journal du
calendrier est écrit avant toute réponse, R1-F65 ; rejouer ne crée pas de
doublon). Le nonce rend l'engagement sans lien calculable avec `periodHash`
ou `checkpointHash` : les calendriers ne voient jamais l'empreinte (CT-4 §8.3,
CT-6 EX-A.7), et c'est pourquoi la soumission peut partir en même temps que
l'ancre du registre (EX-4.7). Les agrégateurs publics du client officiel sont
les valeurs par défaut de `calendars` (R1-F56 :
`https://a.pool.opentimestamps.org`, `https://b.pool.opentimestamps.org`,
`https://a.pool.eternitywall.com`, `https://ots.btc.catallaxy.com`) ; aucun
d'eux ne publie de limite de débit ni d'engagement de disponibilité (R1-F67,
non vérifié R1 NV-11). Le composant d'ancrage ne crée jamais de transaction
Bitcoin lui-même (l'option de portefeuille du client officiel n'est pas
employée).

**EX-6.3** Le composant d'ancrage n'emploie pas la bibliothèque officielle :
il écrit lui-même les octets de 6.3, que la confrontation de l'annexe A fait
relire et resérialiser à l'identique par `python-opentimestamps`, comme CT-6
A.8 le fait pour ses vecteurs.

### 6.3 Le fichier `.ots`

**EX-6.4 (AN-18)** Le fichier `.ots` écrit par CT-5 a la forme de CT-6 §10.2
(en-tête magique, version `01`, opération `08`, empreinte de 32 octets, arbre)
et son arbre est, octet pour octet :

```text
f0 10 <nonce, 16 octets>                 append nonce
08                                       sha256 → engagement e
<arbre des réponses des calendriers>     fusion des Timestamp reçus pour e
```

L'arbre des réponses est la **fusion** des `Timestamp` reçus (le client
officiel fusionne chaque réponse dans le nœud de l'engagement,
`timestamp.merge(result)`), sérialisée dans l'ordre que la bibliothèque de
référence impose (`opentimestamps/core/timestamp.py`, `Timestamp.serialize`,
lu le 2026-10-25) et que CT-5 reproduit pour que la relecture et la
resérialisation par cette bibliothèque rendent les mêmes octets :

1. sous un nœud, les attestations viennent d'abord, puis les opérations ;
2. les attestations sont triées par étiquette (8 octets, comparaison
   d'octets), puis, pour deux attestations en attente, par URI (comparaison
   des suites de caractères), pour deux attestations Bitcoin par hauteur ;
3. les opérations sont triées par code d'opération, puis par argument
   (comparaison d'octets) ;
4. chaque branche sauf la dernière est précédée de `ff` ; une attestation est
   introduite par `00` ; une opération par son code et, pour `f0` et `f1`,
   l'argument en `varbytes`.

Avant toute attestation Bitcoin, l'arbre des réponses d'un nœud ne porte en
pratique que des attestations en attente (quand un calendrier répond par la
seule promesse) et des sous-arbres d'agrégation `f0`/`f1`/`08` terminés par une
promesse. Exemple minimal, point `K2`, deux calendriers qui répondent chacun
par la seule attestation en attente, nonce dérivé pour l'exemple des 16
premiers octets de
`SHA-256(UTF-8("noortrace/vecteurs/v0/ct-5/ots/nonce/point-k2"))` =
`a10f0dccae630a2791dde3924b507379`, engagement
`e = 1e0e083c9976f92dfa6f0ba6c9ce296c9360d18d59416ba0354f64393b1fd480`,
195 octets :

```text
00 4f 70 65 6e 54 69 6d 65 73 74 61 6d 70 73 00 00 50 72 6f 6f 66 00 bf 89 e2 e8 84 e8 92 94   en-tête magique
01                                                                                           version
08                                                                                           sha256 du fichier
6a 8e 03 5a b9 b9 09 37 a5 b0 d4 11 18 56 7c 95 2f 3c e4 9c 89 5b 81 63 6a b7 0b 51 62 53 e6 ff   checkpointHash K2
f0 10 a1 0f 0d cc ae 63 0a 27 91 dd e3 92 4b 50 73 79                                        append nonce
08                                                                                           sha256 → e
ff                                                                                           branche suivante
00 83 df e3 0d 2e f9 0c 8e 2e 2d 68 74 74 70 73 3a 2f 2f 61 6c 69 63 65 2e 62 74 63 2e 63 61 6c 65 6e 64 61 72 2e 6f 70 65 6e 74 69 6d 65 73 74 61 6d 70 73 2e 6f 72 67
                                                                                             en attente, https://alice.btc.calendar.opentimestamps.org (varbytes(varbytes(uri)) : 2e 2d puis 45 octets)
00 83 df e3 0d 2e f9 0c 8e 2c 2b 68 74 74 70 73 3a 2f 2f 62 6f 62 2e 62 74 63 2e 63 61 6c 65 6e 64 61 72 2e 6f 70 65 6e 74 69 6d 65 73 74 61 6d 70 73 2e 6f 72 67
                                                                                             en attente, https://bob.btc.calendar.opentimestamps.org

SHA-256 du fichier : 0x64a62afc6526fdd0ea34c57ea70eb8e4711f2fc49ff8fc6a3c4cd38596efa8b6
base64 (forme embarquée dans points-de-controle.json, CT-1 §11.2) :
AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEIao4DWrm5CTelsNQRGFZ8lS885JyJW4FjarcLUWJT5v/wEKEPDcyuYwonkd3jkktQc3kI/wCD3+MNLvkMji4taHR0cHM6Ly9hbGljZS5idGMuY2FsZW5kYXIub3BlbnRpbWVzdGFtcHMub3JnAIPf4w0u+QyOLCtodHRwczovL2JvYi5idGMuY2FsZW5kYXIub3BlbnRpbWVzdGFtcHMub3Jn
```

Ce fichier passe O-1, O-2 (empreinte = `checkpointHash`) et O-3 de CT-6 avec
l'implémentation de référence, et le contrôle 5 est `non_execute`, raison
`partie_absente`, par O-7 : « aucune attestation Bitcoin : 2 attestations en
attente » : c'est l'état de toute preuve avant sa mise à niveau. La réponse
d'un calendrier réel porte en général des opérations d'agrégation avant la
promesse (R1-F65 : agrégation par seconde dans un arbre de Merkle) ; la
structure est la même. Les vecteurs de l'annexe A publient ce fichier
(`ots/point-k2-minimal.ots`) et un exemple à branches de calendrier,
`ots/point-k2-en-attente.ots` (233 octets), où chaque calendrier ajoute ses
propres opérations avant sa promesse (A.2, A.4), comme CT-6 EX-A.7 ; tous
deux sont relus et resérialisés à l'identique par la bibliothèque officielle
(annexe B.3).

**EX-6.5** Le fichier est écrit en **création exclusive**, une fois toutes les
réponses exigées reçues, et jamais réécrit : une mise à niveau écrit une
nouvelle version `<objet>-<n+1>.ots` à côté de la précédente (5.5), à la
manière du client officiel qui renomme l'ancien fichier en `.bak` avant
d'écrire le nouveau et refuse d'écraser un `.bak` existant (R1-F62). La
version la plus récente est celle que l'enregistrement d'acquisition désigne
et que l'exportateur remet (6.6).

### 6.4 Mise à niveau

**EX-6.6 (AN-19)** Pour chaque attestation en attente d'une preuve, le
composant d'ancrage demande `GET <uri>/timestamp/<e en hexadécimal>` au
calendrier désigné par l'URI de l'attestation, si cette URI figure dans
`upgrade.whitelist` (R1-F56 : le client officiel n'interroge que des
calendriers d'une liste blanche ; une URI hors liste est ignorée avec un
avertissement, l'attestation restant telle quelle), avec l'en-tête `Accept`
d'EX-6.2. Réponses : 404 avec le corps « Pending confirmation in Bitcoin
blockchain » ou « Timestamped by transaction … ; waiting for … confirmations »
(engagement connu, pas encore complet) ou « Not found » (engagement non encore
visible, cas d'un engagement tout juste journalisé), tous servis avec
`Cache-Control: public, max-age=60` (R1-F64) : nouvelle tentative au plus tôt
`upgrade.interval_s` plus tard, jamais moins de 60 s ; 200 : un `Timestamp`
sérialisé sur `e` (au plus 10 000 octets), servi avec `max-age=31536000`
parce qu'il ne changera plus (R1-F64), relu par le lecteur de CT-6 §10.2 et
**fusionné** dans la preuve (R1-F62 : `sub_stamp.merge(upgraded_stamp)`),
l'attestation en attente de ce calendrier étant remplacée par le chemin reçu.
La preuve fusionnée est vérifiée avant d'être écrite : O-1, O-3 et, quand une
source d'en-têtes est configurée (6.5), O-4 et O-5 contre les en-têtes de
CT-5 ; un chemin reçu qui ne passe pas O-3, ou dont le résultat n'est pas la
racine de l'en-tête à la hauteur attestée, est refusé, consigné et alerté (un
calendrier ne peut pas forger une preuve, R1-F59, mais il peut en servir une
corrompue). Cadence : première tentative `upgrade.first_after_s` après la
soumission (défaut 21 600 s : le serveur officiel n'émet une transaction qu'à
un intervalle de 6 à 12 h, puis attend 6 confirmations, R1-F66), puis toutes
les `upgrade.interval_s` (défaut 1 800 s) jusqu'à une attestation Bitcoin ;
au-delà de `upgrade.give_up_after_s` (défaut 14 jours) sans attestation, une
alerte est levée et les tentatives continuent une fois par jour : la preuve
en attente n'est jamais supprimée, le calendrier promettant de garder les
engagements complétés indéfiniment (R1-F59).

**EX-6.7** Une preuve est **complète** quand elle porte au moins une
attestation Bitcoin (étiquette `0588960d73d71901`, R1-F60) ; elle est **en
attente** sinon. Une preuve en attente est exportée telle quelle (6.6), le
contrôle 5 du vérificateur la déclare alors non exécutée (O-7) et l'énoncé ne
dit rien de Bitcoin ; une preuve complète déclenche la réexportation des
dossiers de la période (CT-6 EX-13.6 ; section 10). Le composant d'ancrage ne
tient compte d'aucun nombre de confirmations : c'est le réviseur qui exige
`min_confirmations` dans son fichier d'ancres (CT-6 O-6), et le calendrier ne
sert un chemin complet qu'après ses propres confirmations (6 par défaut,
R1-F66). Une attestation d'une autre étiquette (autre chaîne) est conservée
et ignorée (CT-6 §10.2).

### 6.5 Source d'en-têtes Bitcoin

**EX-6.8 (AN-20)** Quand `opentimestamps.headers_source` n'est pas `null`,
le composant d'ancrage produit, pour chaque période dont au moins une preuve
est complète, le fichier `entetes-bitcoin.json` au schéma
`entetes-bitcoin-v0` (CT-6 §10.3) : `network` celui de la source,
`start_height = max(0, 2016 × (⌊h ÷ 2016⌋ − 1))` et une fin au moins égale à
`h' + 11`, `h` et `h'` étant la plus petite et la plus grande hauteur
attestées par les preuves de la période (manifeste et, le cas échéant, point ;
CT-6 EX-13.13 et EX-10.13), `headers` les en-têtes bruts de 80 octets dans
l'ordre de sérialisation de Bitcoin, jamais une valeur affichée par un
explorateur ou un appel RPC qui inverse les octets (CT-6 EX-10.3), `source`
le texte qui dit d'où ils viennent. Les en-têtes viennent d'un nœud Bitcoin
sous le contrôle du client (`bitcoin_rpc` : en-têtes sérialisés rendus par le
nœud, authentification par emplacement de secret) ou d'un fichier au même
schéma tenu par l'exploitation (`fichier`, CT-8). Le fichier est déclaratif
(CT-6 EX-10.4) : quiconque peut le produire, et il n'est cru qu'au travers de
O-5, qui le rattache au point de contrôle Bitcoin du réviseur ; CT-5 le
fournit pour que le réviseur n'ait pas à tenir un nœud, et le réviseur peut
produire le sien (CT-6 §12.5). Les en-têtes ne sont jamais tirés d'un
calendrier ni d'un explorateur public.

**EX-6.9** Le composant d'ancrage vérifie lui-même chaque preuve complète
contre ses en-têtes (O-4 : le résultat des opérations est la racine de
Merkle de l'en-tête attesté ; O-5 : chaînage et preuve de travail des
en-têtes entre eux, CT-6 EX-10.9 sans point de contrôle de réviseur) avant de
la promouvoir ; une discordance est consignée et alertée, la preuve restant
conservée.

### 6.6 Ce qui est remis au dossier

**EX-6.10 (AN-21)** À l'exportateur (section 10), pour la période d'un
événement : la dernière version du fichier `.ots` du manifeste, copiée octet
pour octet comme partie `preuve_ots` (`preuve.ots`, CT-1 §11.2) ; pour le
point qui couvre l'événement, la dernière version de sa preuve en base64 dans
`anchors.ots.proof` de `points-de-controle.json`, ou `null` si ce point n'a
pas été horodaté (CT-1 §11.2 : une seule disposition, ancres embarquées) ; le
fichier `entetes-bitcoin.json` de la période, placé à côté du dossier et non
dans ses parties (CT-6 EX-13.7, lu par le réviseur avec `--entetes-bitcoin`).
Une preuve en attente est remise telle quelle ; l'exportateur consigne
qu'une réexportation suivra la mise à niveau (EX-6.7).

### 6.7 Vérifications AN-16 à AN-21

| Id | Vérification | Entrées | Sortie |
|---|---|---|---|
| AN-16 | Objet horodaté : fichier `P ‖ C` reconstruit depuis l'objet signé, SHA-256 égal à `periodHash` ou `checkpointHash` ; point sélectionné pour `mi_periode` (EX-6.1) | manifeste ou point, configuration | octets du fichier, empreinte, point sélectionné |
| AN-17 | Soumission : nonce de 16 octets, `e = SHA-256(empreinte ‖ nonce)`, requête `POST /digest` (corps 32 octets, en-tête `Accept`), relecture des réponses, seuil `min_responses` dans `timeout_ms`, rejeu avec le même engagement (EX-6.2) | empreinte, nonce, réponses simulées | engagement, requêtes, décision d'écrire ou de remettre en file |
| AN-18 | Fichier `.ots` : octets exacts d'EX-6.4 pour (empreinte, nonce, réponses), ordre de sérialisation de la bibliothèque de référence, création exclusive ; relecture O-1, O-2, O-3 réussies | empreinte, nonce, réponses | octets ; relu et resérialisé à l'identique par `python-opentimestamps` (annexe A) |
| AN-19 | Mise à niveau : liste blanche, cadence (≥ 60 s, `first_after_s`, `interval_s`, `give_up_after_s`), fusion d'un chemin reçu, vérification O-3 (et O-4, O-5 avec en-têtes) avant écriture, nouvelle version sans réécriture, état `complete` ou `en_attente` (EX-6.6, EX-6.7) | preuve, réponses simulées (404, 200), en-têtes | nouvelle version ou refus, état |
| AN-20 | Fichier d'en-têtes : schéma `entetes-bitcoin-v0`, `start_height` et fin selon EX-6.8, en-têtes bruts contigus, source déclarée ; O-4 et O-5 de la preuve contre ces en-têtes (EX-6.9) | preuves complètes, source d'en-têtes | fichier, statuts O-4, O-5 |
| AN-21 | Remise au dossier : `preuve.ots` octet pour octet, `anchors.ots.proof` en base64 canonique de la dernière version, `entetes-bitcoin.json` hors des parties, preuve en attente remise avec mention de réexportation (EX-6.10) | période, dossier exporté | conformité |

### 6.8 Récapitulatif des vérifications de la partie A

| Id | Objet | Section |
|---|---|---|
| AN-1 | Configuration `ancrage-v0` et règles hors schéma | 4.4 |
| AN-2 | Échéances, points sélectionnés, délais `d_registre` et `d_jeton`, échéances `remplacee`, constat de cadence, alertes `jeton_anterieur_au_point` et `contresignature_tardive` | 4.2, 3.3 |
| AN-3 | Admission d'un objet à ancrer (signature, série, racine et `last_hash`, empreinte) | 4.2 |
| AN-4 | Points à ancrer au registre ; comptages par heure, jour, an | 4.3, 4.6 |
| AN-5 | Requête `TimeStampReq` DER exacte | 5.1 |
| AN-6 | Nonce | 5.1 |
| AN-7 | Transport HTTP | 5.2 |
| AN-8 | Lecture de la réponse, `PKIStatus` | 5.4 |
| AN-9 | Égalités empreinte, nonce, politique ; T-1 à T-10 à l'acquisition | 5.4 |
| AN-10 | Fraîcheur et horloge | 5.4 |
| AN-11 | Classement des erreurs et attente de reprise | 5.4 |
| AN-12 | Choix du prestataire et relève | 5.3 |
| AN-13 | Jeton retenu | 5.3 |
| AN-14 | Enregistrement d'acquisition et stockage | 5.4, 5.5 |
| AN-15 | Conservation | 5.5 |
| AN-16 | Objet horodaté OpenTimestamps | 6.1 |
| AN-17 | Soumission aux calendriers | 6.2 |
| AN-18 | Fichier `.ots` | 6.3 |
| AN-19 | Mise à niveau | 6.4 |
| AN-20 | Fichier d'en-têtes Bitcoin | 6.5 |
| AN-21 | Remise au dossier | 6.6 |

La partie B numérote ses vérifications d'AN-22 à AN-61 (serveur interne,
section 7 ; file d'attente et reprise, section 8 ; ancre des points au
registre, section 9 ; remise à l'exportateur et au réviseur, section 10 ;
prestataires, section 11 ; coût, section 12 ; AN-61 : complétude au registre,
EX-10.7, section 10) ; l'annexe A.8 donne la table complète, AN-1 à AN-61.

## 7. Serveur RFC 3161 interne non qualifié (optionnel)

### 7.1 Rôle

Le serveur interne est une autorité d'horodatage RFC 3161 exploitée par le
client ou par le fournisseur, dont la clé et l'horloge sont sous le contrôle
de l'exploitant. Il n'est inscrit sur aucune liste de confiance et n'est
jamais « qualifié » au sens de la section 11. Il sert à une seule chose :
contresigner des **points de contrôle intermédiaires** (CT-1 §10.5) aux
échéances de la section 4 quand la configuration désigne le rôle `interne`
pour les points (`rfc3161.checkpoints.provider_role`, EX-4.8, EX-5.6), afin de
borner la fenêtre de réécriture entre deux ancres qualifiées sans acheter un
jeton qualifié toutes les cinq minutes (section 12). C'est l'objet que
l'architecture appelait « contresignature interne à la minute » (R2-F60) ;
CT-1 révision 0.3 lui a donné un format (le point de contrôle) et cette
section lui donne ses limites.

**EX-7.1** Le serveur interne NE DOIT PAS produire le jeton de clôture d'une
période (`jeton_periode`, empreinte `periodHash`) : ce jeton reste celui du
prestataire `principal` ou de son `secours`, tous deux qualifiés (EX-5.6,
EX-5.7). Un prestataire de rôle `interne` ne peut porter aucun de ces deux
rôles : chaque prestataire a un champ `role` unique (EX-4.8), et, en
production, la configuration est refusée au démarrage si le principal (ou le
secours) n'est pas qualifié (EX-4.9, règle 4 ; CT-2 §15.4).

**EX-7.2** Un jeton du serveur interne prouve seulement qu'une clé contrôlée
par l'exploitant a signé ce condensé et cette heure déclarée (R1-F55 : la
RFC 3161 §2.1 impose à la TSA une source de temps « trustworthy », ce qu'un
réviseur ne peut pas constater pour un serveur de l'exploitant). Il
s'étiquette tel quel partout : `qualified: null` dans la configuration (EX-4.8)
et dans le fichier d'ancres du réviseur (CT-6 §12.2), nom d'autorité qui dit
« interne, non qualifié » (`name`, repris dans l'énoncé par CT-6 EX-9.20),
rôle `interne` dans la configuration, la fiche de prestataire (EX-10.6) et
les lignes de file (section 8). Ce qu'il prouve et ne
prouve pas est dit par CT-6 §7 et par CT-1 §10.9, qui ne sont pas réécrits
ici.

**EX-7.3** Contre qui le jeton interne vaut-il ? Contre un enregistreur
compromis dont l'attaquant ne tient pas aussi la clé du serveur interne : la
clé de la TSA interne DOIT être gardée hors de l'hôte de l'enregistreur, sous
une classe de garde A à C de CT-2 §11.2, par un autre rôle d'exploitation que
celui qui administre l'enregistreur. Contre l'opérateur lui-même, le jeton
interne ne vaut rien : il tient la clé et l'horloge. C'est pourquoi la
fenêtre de réécriture **vis-à-vis de l'opérateur** reste bornée par les seules
ancres extérieures (registre pour l'ordre, prestataire qualifié ou de second
rang pour la date, Bitcoin), et c'est ce que la section 3 et CT-6 §7.9
disent.

### 7.2 Exigences d'exploitation, mesurables

Les exigences suivent la RFC 3161 et le code des trois serveurs lus (R1-F49 à
R1-F54) ; elles sont écrites pour être vérifiées par CT-9 sur un jeton émis,
jamais par la seule lecture d'une configuration.

| Id | Exigence | Mesure |
|---|---|---|
| AN-22 | Le certificat de l'unité porte `extKeyUsage` critique, réduit à `id-kp-timeStamping` (1.3.6.1.5.5.7.3.8), et n'est pas un certificat d'AC (RFC 3161 §2.3, R1-F12 ; sigstore `verify.go`, R1-F54) | T-8 de CT-6 réussie sur chaque jeton émis ; `openssl x509 -text` |
| AN-23 | Les condensés acceptés sont SHA-256, SHA-384, SHA-512 et rien d'autre : une requête SHA-1 ou MD5 reçoit `PKIStatus` 2 avec `badAlg` (R1-F8) ; la configuration de test d'uts-server qui admet `md5, sha1` (R1-F52) n'est jamais celle de production | requête `-sha1` → réponse de rejet `badAlg` (essai de la note R1 avec `openssl ts -reply` : « unrecognized or unsupported algorithm identifier », R1-F50) |
| AN-24 | La précision déclarée (`accuracy`) est présente dans chaque jeton, au plus 1 s, et l'horloge du serveur est asservie à une source de temps dont l'écart mesuré est consigné (R1-F11, R1-F19 : un prestataire qualifié arrête le service au-delà de sa dérive admise ; le serveur interne DOIT cesser d'émettre au-delà de `accuracy`) | `accuracy` lu par T-1 ; journal d'exploitation `tsa_clock_offset` |
| AN-25 | Le nonce de la requête est repris à l'identique dans le jeton (R1-F2) ; une requête sans nonce est refusée par le client de la section 5, jamais par le serveur | `openssl ts -verify -queryfile <requête>` : « nonce mismatch » si le nonce diffère (essai de cette spécification, annexe B.3) |
| AN-26 | Le numéro de série est unique et strictement croissant à travers les redémarrages (RFC 3161 §2.4.2, R1-F10) ; `openssl ts` ne verrouille pas son fichier `serial` (R1-F49) : un seul processus émetteur par clé, ou un serveur qui sérialise ses émissions (uts-server, sigstore `timestamp-authority`) | deux jetons successifs du même serveur ont des `serialNumber` croissants ; épreuve de redémarrage (CT-9) |
| AN-27 | Le serveur n'est joignable que par TLS avec authentification du client (certificat client ou `Basic` sur TLS), depuis les seules adresses de l'enregistreur, sauf une adresse locale (`127.0.0.1`, `::1`, `localhost`) en `http://` sans authentification, que la règle 4 d'EX-4.9 admet pour le seul rôle `interne` ; `openssl ts` n'a pas de serveur HTTP (R1-F49 : « HTTP server support is provided in the form of a separate apache module ») : un frontal est obligatoire | tentative anonyme refusée ; `ssl_verify_peer` ou équivalent (R1-F52) |
| AN-28 | Chaque jeton émis est journalisé **hors du serveur** (par le frontal ou par le client) avec son numéro de série, son `genTime`, son `messageImprint` et son nonce : `openssl ts -reply` n'écrit aucun journal, seul `serial` est mis à jour (R1-F50) | le journal porte une ligne par jeton reçu par le client |
| AN-29 | La politique est un OID de l'arc privé de l'exploitant, déclaré dans `accepted_policies` de l'autorité du fichier d'ancres ; une requête qui porte une autre `reqPolicy` est refusée (`unacceptedPolicy`, R1-F5 ; essai : réponse de rejet de 50 octets, annexe B.3) | T-1 lit la politique ; `openssl ts -reply` sur une politique inconnue rend « the requested TSA policy is not supported by the TSA » |
| AN-30 | Le certificat de l'unité est inclus dans le jeton (`certReq` vrai, R1-F4) et l'attribut signé est `signingCertificateV2` avec `ESSCertIDv2` SHA-256 (RFC 5816, R1-F14, R1-F15) ; `ess_cert_id_alg = sha256` pour `openssl ts` (R1-F16) | T-4 réussie sans intermédiaire dans le fichier d'ancres |
| AN-31 | La clé de l'unité est RSA d'au moins 3072 bits ou ECDSA P-256 ; sa validité est d'au plus trois ans (pratique d'un prestataire qualifié, R1-F22) et sa CRL est publiée à une adresse que le fichier d'ancres du réviseur peut citer (CT-6 EX-13.12) | T-7 et T-10 réussies à `genTime` |

**EX-7.4** Le serveur interne de référence des vecteurs est l'autorité de test
de CT-6 (`spec/vecteurs/ct-6/rfc3161/cles`, clés RSA 3072 publiques,
politique `1.3.6.1.4.1.99999.1.1`, `scripts/vecteurs/ct6/rfc3161.mjs`) ; il
ne sert qu'aux vecteurs et aux tests, jamais à un déploiement. Une
configuration `openssl ts` équivalente (section `[tsa_config1]` :
`signer_digest = sha256`, `digests = sha256, sha384, sha512`, `accuracy =
secs:1, millisecs:0, microsecs:0`, `ess_cert_id_alg = sha256`,
`default_policy = 1.3.6.1.4.1.99999.1.1`) a produit, pour cette
spécification, une réponse `granted` de 3164 octets à une requête de 69 octets
de la forme de l'annexe A.4 (empreinte du point `K2`, nonce de CT-1 §13 ;
jeton de 3155 octets avec l'unité et l'AC), vérifiée par `openssl ts -verify
-queryfile` ; les tailles concordent avec les mesures de
la note (R1-F16 : 884 octets sans certificat, 3082 à 3114 avec l'unité et
une racine RSA-3072).

### 7.3 Ce que le serveur interne ne remplace pas

- Il ne remplace pas le jeton qualifié de la clôture (EX-7.1) ni le
  prestataire de second rang : il est le **troisième** choix pour les points,
  quand `rfc3161.checkpoints.provider_role` le désigne (EX-5.6), et son coût
  nul (section 12) est la seule raison de le préférer ; il n'a pas de relève
  (EX-5.7) : une échéance qu'il ne sert pas est close `remplacee` par la
  suivante (EX-4.4).
- Il ne borne pas la fenêtre de réécriture vis-à-vis de l'opérateur (EX-7.3) :
  pour un journal dont le modèle de menace comprend l'opérateur, la cible
  « 300 s plus le délai du jeton » (CT-1 §10.9) exige un prestataire
  extérieur pour les points.
- Il n'est pas une ancre de la série : un point contresigné en interne reste
  un point signé par l'enregistreur et contresigné par l'exploitant ; le
  chaînage et la monotonie (CT-1 §10.5) sont vérifiés par CT-5 sur la série,
  pas par lui.

## 8. Planificateur

### 8.1 Rôle et place

Le planificateur est la partie du composant d'ancrage qui transforme deux
faits durables, « un point de contrôle est admis » et « une période est
close », en demandes d'ancres, puis en ancres : ancre au registre (CT-4,
section 9), jeton RFC 3161 (section 5), preuve OpenTimestamps (section 6). Il
tient la **file d'attente durable**, applique les échéances de la section 4,
décide **quand** envoyer **quoi** à **qui**, confie chaque réponse aux
vérifications de la section 5 ou 6 avant de la stocker, reprend ce qui a
échoué et rend compte à la supervision. Il ne produit ni point ni manifeste
(CT-2), ne signe rien avec la clé Ed25519 de l'enregistreur, et ne touche
jamais au chemin d'un appel d'outil (EX-4.12).

**EX-8.1** Le planificateur s'exécute hors du chemin de relais de l'agent :
fil ou processus distinct, qui ne détient aucun verrou de l'écrivain. La seule
interaction de l'écrivain avec lui est la **remise** d'un point ou d'un
manifeste signé, qui n'attend aucune réponse réseau (EX-4.12) ; le
planificateur en déduit ses demandes et les écrit dans la file (8.5). Aucune
panne d'un prestataire, du registre, d'un calendrier ou de la file elle-même
ne bloque, ne retarde ni ne refuse un appel d'outil ou un échange de modèle :
c'est la ligne « Ancrage (CT-5) indisponible » de CT-2 §14.2, « jamais
bloquant » (R2-F57). Si la file ne peut pas être écrite (disque plein),
l'ajout est consigné (`anchor_queue_write_failed`), la demande reste en
mémoire dans la borne de `queue.max_pending`, et la supervision alerte
(`file_perdue`, 8.9) ; le point ou le manifeste, eux, sont déjà durables chez
l'enregistreur. Les échéances se lisent sur l'horloge de l'enregistreur et
les attentes sur son horloge monotone (EX-4.13, H8).

**EX-8.2** Le planificateur lit la configuration `ancrage-v0` d'EX-4.8 ; les
clés qu'il emploie, aux noms et défauts de la section 4, sont :
`checkpoint_interval_s` (`c_K`, 60) ; `rfc3161.providers[]` (`id`, `role`,
`policy_oid`, `qualified`, `min_interval_ms`, `request_timeout_ms` ; les
secrets, certificats et sources sont lus par le client de la section 5, pas
par le planificateur) ; `rfc3161.manifest.fallback_after_s` (300) ;
`rfc3161.checkpoints.{interval_s, provider_role, fallback_after_s,
countersign_idle}` (300, `principal`, 120, faux) ;
`rfc3161.freshness.{max_response_delay_s, clock_tolerance_s}` (60, 120) ;
`rfc3161.retry.{initial_ms, factor, max_ms, jitter_ms}` (5000, 2, 300000,
250) ; `registry.{checkpoints, squat_wait_s, inclusion_alert_s}`
(`nouveaux_evenements`, 5, 60) ; `opentimestamps.{enabled, calendars,
min_responses, timeout_ms, checkpoint, upgrade.{first_after_s, interval_s,
give_up_after_s}}` ; `queue.{path, max_pending, anchor_pending_alert_s}`
(sous `storage.root`, 100 000, 7200). Les traces normatives de 8.10 portent
cette **projection** de la configuration (`$defs/configuration` de
`planificateur-ancrage-v0.schema.json`, mêmes chemins et mêmes bornes que
`ancrage-v0`, `qualified` réduit à un booléen) ; le document complet est validé
par AN-1.

### 8.2 Objets

Une **demande** est l'unité de la file : une sorte (`kind`), un sujet (une
période ou un point : `org_id`, `journal_id`, `period_start`, l'empreinte
ancrée `hash`, `tree_size` pour un point, l'instant déclaré par
l'enregistreur), pour une demande de point les indices `k` des échéances
qu'elle sert (EX-4.3), un état (8.3), une échéance interne `due_at`, la liste
de ses tentatives et, quand elle aboutit, un résultat (fichier conservé,
SHA-256, taille, prestataire, `received_at` de la tentative promue, borne
« au plus tard » tirée de l'ancre). Sa clé d'idempotence est
`id = <kind>:<hash>` ; il n'existe jamais deux demandes de même `id` dans la
file (EX-8.5). Les six sortes :

| `kind` | Sujet | Créée quand | Prestataire |
|---|---|---|---|
| `ancre_registre_point` | point | un point admis engage un nouvel événement (EX-4.6 ; `tous` : chaque point) | registre (section 9) |
| `jeton_point` | point | un point admis est le premier dont `checkpoint_ts ≥ D_k` pour au moins une échéance `D_k` ouverte sans demande (EX-4.3) ; ou, repli de clôture, le point de clôture quand `jeton_periode` attend le registre plus de `squat_wait_s` (EX-4.2 ; demande sans échéance) | `rfc3161.checkpoints.provider_role` (EX-5.6), relève par le `secours` si `principal` (EX-5.7) |
| `ots_point` | point | le point sélectionné à l'échéance médiane `D_{k_m}`, si `opentimestamps.checkpoint = mi_periode`, même quand l'échéance est `sans_objet` (EX-6.1) | calendriers |
| `ancre_registre_periode` | période | clôture | registre (CT-4 §8.2, pas 2) |
| `jeton_periode` | période | clôture (envoi après l'inclusion de l'ancre, EX-8.4) | `principal`, relève par le `secours` (EX-5.7) |
| `ots_periode` | période | clôture | calendriers (EX-6.2) |

Une **tentative** porte son rang `n`, le prestataire, l'instant de départ, le
nonce de la requête RFC 3161 (frais à chaque tentative, EX-5.3), l'identifiant
de tentative `attempt_id` d'EX-5.13 (transmis dans `correlation_header`,
R1-F35), son issue (`obtenue`, `echec_transitoire`, `echec_permanente`,
`reponse_tardive`, `en_cours` : les issues d'EX-5.13), le code d'erreur
d'EX-5.10, le statut HTTP, le `PKIStatus` et le `PKIFailureInfo` lus (R1-F6,
R1-F7), la valeur d'un en-tête `Retry-After` et l'instant de la tentative
suivante. Les formats exacts sont `$defs/demande`, `$defs/tentative` et
`$defs/resultat` du schéma ; l'enregistrement d'acquisition complet d'EX-5.13
est écrit à part (8.5).

### 8.3 États et transitions

**EX-8.3** Les états d'une demande et les seules transitions admises :

| État | Sens | Transitions sortantes |
|---|---|---|
| `a_envoyer` | écrite dans la file, pas encore envoyée | → `envoyee` (envoi) ; → `remplacee` (EX-9.5, ancre de point couverte par un point plus récent) |
| `attente_registre` | jeton RFC 3161 qui attend l'inclusion de l'ancre au registre du même sujet (EX-4.7, EX-8.4) | → `envoyee` (inclusion constatée, ou `squat_wait_s` écoulé pour un point) ; → `remplacee` (EX-4.4) |
| `envoyee` | requête partie, réponse attendue (`en_cours`) | → `obtenue` (réponse promue, EX-5.10) ; → `en_attente` (preuve OpenTimestamps avec attestation en attente, EX-6.2) ; → `a_reprendre` (échec transitoire ou réponse tardive, EX-5.11, EX-5.12) ; → `envoyee` (relève : la demande est aussi en cours chez le secours, EX-5.7) ; → `a_envoyer` (relève immédiate après une `echec_permanente` sans autre tentative en cours : la demande est réécrite `a_envoyer` pour le secours, puis `envoyee`, EX-8.8) ; → `refusee` (échec permanent sans relève possible ; `empreinte_squattee`, EX-9.7) ; → `remplacee` (EX-4.4) |
| `a_reprendre` | tentative suivante programmée à `due_at` (EX-8.9) | → `envoyee` ; → `remplacee` |
| `en_attente` | preuve OpenTimestamps détenue, attestation en attente ; mise à niveau programmée (EX-6.6) | → `complete` ; → `en_attente` (mise à niveau sans attestation Bitcoin) |
| `obtenue` | jeton promu et stocké (EX-5.8), ou ancre incluse et capturée | final, sauf → `a_reprendre` pour `jeton_periode` et `jeton_point` quand une révocation est constatée après coup (EX-5.10, étape 10 : la demande repart au secours ; révision 0.2) |
| `complete` | preuve OpenTimestamps avec attestation Bitcoin, stockée (EX-6.7) | final |
| `sans_objet` | échéance de point satisfaite sans requête : le point sélectionné n'engage aucun nouvel événement (EX-4.3, `countersign_idle` faux) | final |
| `refusee` | échec permanent chez le prestataire désigné et chez son secours, ou `empreinte_squattee` | final ; alerte ; un `jeton_point` refusé rend ses échéances (EX-4.3) |
| `remplacee` | échéance close par la suivante (EX-4.4), ou ancre de point non envoyée qu'un point plus récent couvre (EX-9.5) ; `replaced_by` nomme la demande qui la couvre | final |

Un `jeton_periode` n'a pas d'état final autre qu'`obtenue` : il n'est jamais
abandonné (EX-4.5, EX-5.7) ; après un échec permanent chez le principal et le
secours, il reste `a_reprendre` au pas `retry.max_ms` et la supervision alerte.
Toute transition écrit une nouvelle ligne de la demande dans la file **avant**
que l'action qui en découle soit entreprise (8.5) ; la dernière ligne d'un
`id` fait foi.

### 8.4 Échéances et ordre des ancres

**EX-8.4** Le planificateur applique les règles de la section 4 ainsi :

1. **Échéances d'une période.** Dès qu'il connaît une période (premier point
   admis ou clôture), il tient la liste des échéances `D_k = period_start + k ×
   c_T`, `k = 1 … n_T − 1` (EX-4.2), chacune `ouverte` dès que l'horloge
   atteint `D_k`, puis `satisfaite`, `sans_objet` ou `remplacee`. À l'arrivée
   d'un point admis de `checkpoint_ts = t`, toutes les échéances ouvertes non
   satisfaites de `D_k ≤ t` le sélectionnent (il est le premier point de
   `checkpoint_ts ≥ D_k`, EX-4.3) ; une échéance qui a déjà une demande, dans
   un état quelconque, ne sélectionne plus de point. Si son `tree_size`
   dépasse celui du dernier point contresigné de la période (point de plus
   grand `tree_size` dont le jeton est `obtenue` ou dont la demande n'est pas
   finale, EX-4.3), ou si `countersign_idle` est vrai, une seule demande
   `jeton_point` est créée pour lui, avec la liste de ces `k` ; sinon ces
   échéances sont closes `sans_objet` et aucune requête ne part. Une demande
   `jeton_point` qui passe `refusee` rend ses échéances : elles redeviennent
   ouvertes sans demande, et le dernier point contresigné est recalculé. Quand
   le jeton est obtenu, toutes les échéances de la demande sont `satisfaite`.
   Quand une échéance `D_{k+1}` est satisfaite alors qu'une demande servant une
   échéance antérieure n'est pas `obtenue`, cette demande et ses échéances
   passent `remplacee` (`replaced_by` la demande de `D_{k+1}`), la ligne
   `checkpoint_anchor_late` est écrite et la supervision alerte (EX-4.4) : aucun
   rattrapage des points. La `n_T`-ième échéance est la clôture : elle est
   satisfaite par le `jeton_periode`.
2. **Clôture.** À la clôture, trois demandes sont écrites :
   `ancre_registre_periode` (`a_envoyer`), `jeton_periode`
   (`attente_registre`), `ots_periode` (`a_envoyer`). L'ancre part dès que la
   clé de chaîne n'a plus de transaction sans reçu (EX-9.4). La requête
   RFC 3161 du `periodHash` NE DOIT PAS partir avant l'inclusion **et** la
   capture de l'ancre (CT-4 EX-8.4, DOIT sans borne) ; tant que le registre ne
   répond pas, `jeton_periode` reste `attente_registre`, réexaminée à chaque
   entrée et au plus tard toutes les `inclusion_alert_s`, et la supervision
   alerte `registry_pending` puis « ancre en retard » à
   `queue.anchor_pending_alert_s` (EX-4.5). Repli de clôture (EX-4.2) :
   `registry.squat_wait_s` après la clôture, si `jeton_periode` est encore
   `attente_registre`, une demande `jeton_point` sans échéance est créée pour
   le point de clôture (s'il n'a pas déjà de demande et engage un nouvel
   événement), avec la ligne `checkpoint_closing_fallback` ; elle suit la
   règle 3 pour l'ancre de ce point, et elle est close `remplacee` si le jeton
   de la période est obtenu avant elle. Si l'instance n'a pas de registre
   configuré (CT-2 `anchoring.registry` absent, hors production seulement,
   EX-4.9), `jeton_periode` part aussitôt. La soumission OpenTimestamps part
   aussitôt dans tous les cas (EX-4.7, EX-6.2).
3. **Point.** `ancre_registre_point` part dès l'admission du point (EX-4.6,
   EX-9.3). `jeton_point` attend l'inclusion de `ancre_registre_point:<hash>`
   au plus `registry.squat_wait_s` (défaut 5 s), puis part avec la ligne
   `ordre_ancres_non_respecte` (EX-4.7, EX-9.6). Quand le point n'a pas d'ancre
   au registre (`registry.checkpoints = aucun`, ou point sans nouvel événement
   contresigné parce que `countersign_idle` est vrai), la requête part
   aussitôt.
4. Les fenêtres de 3.3 s'en déduisent : `W_date ≤ c_T + d_jeton`, avec
   `d_jeton = d_point + d_attente + d_relève + d_tsa` (EX-3.5) ; `W_ordre ≤
   c_K + d_registre`.

### 8.5 File d'attente durable

**EX-8.5** La file est un fichier NDJSON en ajout seul,
`<queue.path>/file-<epoch>.ndjson` (l'époque est celle du bail de CT-2 §13,
pour que deux écrivains d'époques différentes n'écrivent jamais le même
fichier), une ligne par état successif d'une demande, chaque ligne étant la
forme canonique JCS intégral (CT-2 §8.1) d'un objet `$defs/demande`. Les
enregistrements d'acquisition d'EX-5.13 sont écrits, eux, dans
`acquisitions.ndjson` du répertoire de la période (EX-5.14), une ligne JCS
intégral par tentative, et c'est ce fichier que l'exportateur lit (section
10). Règles :

1. **Écriture avant envoi.** La ligne `a_envoyer` (ou `attente_registre`) est
   écrite et synchronisée sur le disque (`fdatasync`) **avant** toute requête
   réseau ; la ligne `envoyee`, avec le nonce et l'`attempt_id` de la
   tentative, l'est **avant** que la requête parte : dans une trace (8.10),
   l'action `ecrire_file` de l'état `envoyee` précède toujours, au même
   instant, l'action d'envoi (`envoyer_rfc3161`, `envoyer_registre`,
   `soumettre_ots` ; `mettre_a_niveau_ots` est précédée de la ligne
   `en_attente`), ce qu'AN-32 vérifie. C'est la discipline du
   calendrier OpenTimestamps, qui journalise chaque engagement avec `fsync`
   avant de répondre (R1-F65), et des journaux de transparence, qui rendent la
   soumission idempotente (R1-F69, R1-F71 ; R1-F72). Une réponse qui arrive
   pour une tentative sans ligne `envoyee` (impossible par construction, sauf
   corruption) est écrite dans `acquisitions.ndjson` avec l'issue
   `echec_permanente` et le code `tentative_inconnue`, et n'est pas promue.
2. **Une demande par clé.** `id = <kind>:<hash>` est unique ; une entrée reçue
   pour un `id` déjà présent dans un état final est ignorée et consignée
   (`anchor_duplicate_ignored`). Un redémarrage qui relit la file ne crée donc
   jamais deux demandes pour un même sujet ; une réponse tardive à une
   tentative remplacée ou relevée (nonce différent de la tentative en cours)
   est conservée comme pièce (EX-5.8, EX-5.11) mais ne change pas l'état.
3. **Dernière ligne fait foi.** À la lecture, les lignes sont rejouées dans
   l'ordre ; l'état courant d'une demande est sa dernière ligne ; une ligne
   tronquée en fin de fichier (arrêt pendant l'écriture) est ignorée et
   consignée (`anchor_queue_truncated_line`), jamais réparée.
4. **Borne.** Le nombre de demandes **actives** (non finales) ne dépasse pas
   `queue.max_pending` (défaut 100 000) ; au-delà, l'alerte `file_pleine` est
   critique, un nouveau point n'est plus ancré (sa demande n'est pas créée,
   `anchor_queue_full` est consigné) mais une clôture crée toujours ses trois
   demandes : le jeton de clôture n'est jamais sacrifié. Par EX-4.4 (aucun
   rattrapage des points), le nombre de demandes actives de points d'une
   période reste borné par le nombre d'échéances : une panne accumule jusqu'à
   `n_T − 1` demandes `jeton_point` par période (et le repli de clôture),
   jusqu'à ce que le jeton de clôture les close `remplacee` ; seules les
   demandes de périodes ne sont jamais closes, et s'accumulent (trois par heure
   de panne et par journal). Pendant une panne de l'autorité, le jeton de
   clôture d'une période attend lui aussi : les `jeton_point` de cette période
   restent donc actifs, et ils s'accumulent d'heure en heure, au plus
   `n_T − 1` par période (plus la demande du repli de clôture quand le
   registre tarde aussi, EX-4.2), jusqu'à l'obtention de ce jeton. Les trois
   demandes de période ne s'accumulent toutes que si le registre et les
   calendriers sont aussi injoignables. Quand seule l'autorité est en panne,
   seule `jeton_periode` reste active du fait de la panne : l'ancre au
   registre est obtenue, et `ots_periode` suit son cours ordinaire
   (`en_attente` jusqu'à la mise à niveau, EX-8.11), panne ou non.
5. **Compaction.** Un fichier de file dont toutes les demandes sont finales
   PEUT être compacté en un fichier `file-<epoch>.<n>.compact.ndjson` qui ne
   garde que la dernière ligne de chaque `id` ; l'original est conservé selon
   EX-5.15. La compaction n'a jamais lieu sur le fichier courant.
6. **Plusieurs époques.** À la lecture, tous les fichiers `file-*.ndjson` du
   répertoire, compactés ou non, sont relus et leurs lignes fusionnées par
   `id` (dernière ligne lue, dans l'ordre des époques puis des lignes) ;
   une ligne tronquée est signalée par fichier (`lireFiles` ; traces
   `bascule-epoque` et `bascule-epoque-fichier-perdu`).

### 8.6 Requête, acquisition et relève

**EX-8.6** Chaque tentative RFC 3161 construit la requête d'EX-5.1 pour
l'empreinte du sujet, avec le `policy_oid` du prestataire et un nonce frais
(EX-5.3), l'envoie selon EX-5.5 et confie la réponse aux étapes d'EX-5.10. Le
planificateur ne refait aucune vérification : il reçoit de l'étape 9 ou 10 une
issue d'EX-5.13 et le code d'erreur, et en tire la transition d'état :
`obtenue` → `obtenue` (le jeton promu est celui d'EX-5.8) ;
`echec_transitoire` ou `reponse_tardive` → `a_reprendre` avec `due_at`
d'EX-8.9 ; `echec_permanente` → relève (EX-8.8) ou `refusee`. En exploitation
le nonce vient du générateur aléatoire du système ; dans les vecteurs il est
dérivé d'une étiquette (annexe A.2). Un nonce dont le bit de poids fort vaut 1
porte un octet `00` de tête dans l'INTEGER DER : la requête fait alors 70
octets au lieu de 69 sans politique (annexe A.4, cas `periode-1-reference`).

**EX-8.7** Points et clôture dans la même file. Une seule file sert les six
sortes ; les demandes de points n'ont jamais la priorité sur les demandes de
périodes : à égalité d'échéance, le `jeton_periode` est envoyé d'abord, parce
qu'il est le seul qui ne soit jamais remplacé (EX-4.5). `min_interval_ms` d'un
prestataire est respecté entre deux requêtes qui lui sont adressées, toutes
demandes confondues (EX-5.5) ; quand plusieurs demandes attendent le même
prestataire, l'ordre est : `jeton_periode` par `period_start` croissant, puis
`jeton_point` par `checkpoint_ts` croissant.

**EX-8.8** Relève (EX-5.7). Pour un `jeton_periode` : la demande part au
`principal` ; si aucun jeton promu n'est obtenu `manifest.fallback_after_s`
après la première tentative, ou dès la première `echec_permanente`, la demande
part **aussi** au `secours` (action `releve`), et les deux séries de
tentatives sont poursuivies en parallèle, chacune avec ses nonces, jusqu'à la
première réponse promue ; les tentatives de l'autre prestataire sont alors
arrêtées (aucune nouvelle requête) et une réponse qui arriverait encore est
conservée sans être promue (EX-5.8). Pour un `jeton_point` dont
`provider_role` est `principal`, même règle avec `checkpoints.fallback_after_s`
(120) ; pour `second_rang` et `interne`, aucune relève : sur erreur
transitoire, la demande reste `a_reprendre` jusqu'à ce que l'échéance suivante
soit satisfaite et la close `remplacee` (EX-4.4). Une relève qui suit une
`echec_permanente` sans autre tentative en cours réécrit la demande
`a_envoyer` puis `envoyee` (EX-8.3). Une `echec_permanente` chez tous les
prestataires d'une demande de point la rend `refusee` et rend ses échéances
(EX-4.3) ; chez le principal et le secours d'un
`jeton_periode`, la demande reste ouverte au pas `retry.max_ms` (EX-5.7) et
l'alerte `prestataires_epuises` est critique.

**EX-8.9** Attente de reprise (EX-5.12). Après une `echec_transitoire` ou une
`reponse_tardive`, la tentative suivante est programmée à `now + d`, où : `d =
Retry-After` si la réponse 429 ou 503 en porte un (secondes ou date RFC 1123 ;
RFC 9162 §4, R1-F68 ; R1-F70) ; `d = 0` sur le premier 408 d'une demande chez
un prestataire (R1-F70), puis la règle générale ; sinon `d = min(retry.max_ms,
retry.initial_ms × retry.factor^(k−1)) + gigue`, `k` étant le nombre
d'échecs transitoires consécutifs de cette demande chez ce prestataire et la
gigue un entier de millisecondes de `[0, retry.jitter_ms]` (gigue bornée, comme
celle du client de Certificate Transparency, R1-F70). Dans une trace
normative la gigue est consommée dans `jitter_ms` (8.10). Un `jeton_periode`
dont les deux prestataires échouent de façon transitoire alterne entre eux au
pas `retry.max_ms` jusqu'à obtention.

**EX-8.10** Registre. `ancre_registre_*` suit CT-4 §8.6 : envoi des mêmes
octets aux validateurs configurés, `receipt_wait` par
`registry.inclusion_alert_s` puis `capturer --envoi --renvoyer`, puis
`--remplacer` au même nonce (CT-4 EX-8.16) ; une inclusion constatée est suivie
de la capture de CT-4 §9.4 (action `programmer` de raison `capture`, puis
`stocker` avec le SHA-256 de l'index de capture), et la demande n'est `obtenue`
qu'une fois l'index écrit (AN-48). Dans les traces normatives, l'entrée
`inclusion_registre` porte déjà la capture (`capture_sha256`) : la référence
émet alors directement `stocker`, et l'action `programmer` de raison `capture`
n'apparaît que lorsque la capture est différée (schéma,
`$defs/action_attendue`) ; aucune trace de cette version ne l'exerce.
`empreinte_squattee` rend la demande `refusee` sans nouvel essai (EX-9.7). Un
délai d'inclusion supérieur à `registry.inclusion_alert_s` lève `inclusion_late`
(P-2).

**EX-8.11** OpenTimestamps (EX-6.2 à EX-6.7). `ots_periode` et `ots_point`
soumettent l'engagement `e = SHA-256(empreinte ‖ nonce de 16 octets)` à
chaque calendrier ; la demande passe `en_attente` dès que `min_responses`
réponses valables sont arrivées dans `timeout_ms` et que le fichier `.ots` est
écrit (EX-6.4, EX-6.5), sinon elle reste `a_reprendre` et la soumission est
rejouée avec le **même** engagement (EX-6.2 : le calendrier a journalisé `e`
avant de répondre, R1-F65). La mise à niveau est programmée à `now +
upgrade.first_after_s` (21 600 s), puis toutes les `upgrade.interval_s`
(1 800 s, jamais moins de 60 s, R1-F64) ; une réponse 404 laisse `en_attente`,
une attestation Bitcoin fusionnée et vérifiée (EX-6.6) écrit la nouvelle
version et passe `complete`, ce qui déclenche le réexport (EX-6.7, section
10). Au-delà de `upgrade.give_up_after_s` (14 jours), l'alerte `ots_give_up`
est levée et la mise à niveau continue une fois par jour : une preuve en
attente n'est jamais supprimée (R1-F59).

### 8.7 Reprise au démarrage et références

**EX-8.12** Au démarrage, le planificateur relit la file (8.5) et, pour chaque
demande non finale : `envoyee` → `a_reprendre` immédiatement (la réponse a pu
se perdre ; nouvelle tentative, nouveau nonce, nouvel `attempt_id`, de même
préfixe `<kind>:<16 premiers hex de l'empreinte>` et de rang `n + 1` (annexe
A.2), l'`attempt_id`
restant unique par tentative, EX-5.13 ; une réponse tardive à l'ancien nonce est conservée, non promue) ;
`attente_registre` → interroge l'inclusion (`lookup(empreinte)` de CT-4 OP-9
et l'index de capture) ; `a_reprendre` → garde `due_at` ; `en_attente` → mise
à niveau à `max(due_at, now)` ; `ancre_registre_*` `envoyee` → reprise de CT-4
§8.6. Il relit aussi les échéances de la période en cours depuis les demandes
de points de la file (celles qui sont `obtenue` disent les échéances
satisfaites ; une échéance `sans_objet` n'est pas conservée et redevient
ouverte), consigne `anchoring_started` avec le nombre de demandes relues,
et applique EX-4.4 aux demandes de points relues. La file relue est la
fusion de tous les fichiers `file-*.ndjson` du répertoire (EX-8.5, règle 6).
Puis, à chaque démarrage et quel que soit l'état de la file, il confronte
les objets durables du stockage de l'enregistreur (CT-2 §12) aux demandes
relues : l'entrée `stockage_relu` (8.10) porte les manifestes (`periods`) et
les points (`checkpoints`) ; toute période close sans ses trois demandes
reçoit celles qui manquent, et le dernier point d'une période ouverte sans
demande est admis comme à sa réception (EX-8.4, règles 1 et 3). Il consigne
`anchoring_queue_rebuilt` avec le nombre de demandes recréées, de périodes et
de points examinés, et lève `file_perdue` (critique) si au moins une demande
est recréée : une file perdue ne fait perdre que du temps (traces
`file-perdue` et `bascule-epoque-fichier-perdu`).

**EX-8.13** Références JavaScript du lot : `scripts/lib/ancrage.mjs` expose
le planificateur **à horloge injectée et sans réseau** (`creerPlanificateur
(config, { maintenant, aleatoire })`, qui reçoit les entrées de
`$defs/evenement_entree` et rend les actions de `$defs/action_attendue`), la
construction d'une `TimeStampReq` DER (EX-5.1), la construction et la fusion
d'un fichier `.ots` (EX-6.4), les comptages d'EX-4.11 (`compterJetons`), la
vérification de série (AN-3 ; CT-1 §10.9) et la formule de coût (section 12) ;
`rejouerTrace(trace)` exécute une trace de 8.10 et rend la liste d'actions et
la file finale, que les tests comparent à `expected` et `queue_after`. Les
appels réseau (HTTP vers les prestataires et les calendriers, JSON-RPC vers le
registre par `noortrace.mjs` et `conventions-registre.mjs`) sont dans un
adaptateur distinct que les vecteurs n'exercent pas. Un outil de ligne de
commande `noortrace-ancrage` (`serie`, `cout`, `trace`) PEUT être fourni ; il
n'est pas exigé par cette version.

### 8.8 Conservation

**EX-8.14** Les fichiers de file et `acquisitions.ndjson` sont conservés avec
les pièces d'horodatage, au moins `rfc3161.retention_years` ans, dix au moins
(EX-5.15 ; CT-2 §12.7), et copiés vers le support WORM avec le répertoire
`ancres/` de chaque période (EX-5.15 ; CT-2 EX-12.16 : copie conditionnelle à
l'absence, `sha256` recalculé, jamais l'ETag ; P-6). Rien dans le
planificateur ne supprime un fichier ; la fin de rétention est un acte
d'exploitation (CT-8).

### 8.9 Supervision

**EX-8.15** Métriques, dans l'espace de noms de CT-2 §17.2 (étiquettes en
anglais, valeurs en français sans accent, jamais un nom d'hôte ni un
identifiant de compte) :

| Nom | Type | Étiquettes | Sens |
|---|---|---|---|
| `noortrace_anchor_pending` | jauge | `anchor` (`registre`, `rfc3161`, `ots`) | existe (CT-2 §17.2) : périodes dont l'ancre n'est pas confirmée ; inchangée |
| `noortrace_anchoring_queue_entries` | jauge | `kind`, `state` | demandes par sorte et par état |
| `noortrace_anchoring_attempts_total` | compteur | `kind`, `provider`, `outcome` | tentatives et issues d'EX-5.13 |
| `noortrace_anchoring_last_success_age_s` | jauge | `kind`, `provider` | âge du dernier `obtenue` |
| `noortrace_anchoring_deadlines_total` | compteur | `state` (`satisfaite`, `sans_objet`, `remplacee`) | échéances de points (EX-4.3, EX-4.4) |
| `noortrace_anchoring_window_s` | jauge | `journal` (identifiant abrégé) | âge, en secondes, du dernier point ou manifeste contresigné par un prestataire **extérieur** : borne courante de `W_date` (3.3) |
| `noortrace_anchoring_d_jeton_s` | histogramme | `kind`, `provider` | `d_jeton` d'EX-5.11 (`genTime + précision − D_k`, ou `− period_end`) |
| `noortrace_anchoring_d_point_s` | histogramme | — | `d_point` d'EX-3.5 (`checkpoint_ts − D_k` du point sélectionné) ; `d_attente`, `d_relève` et `d_tsa` se lisent sur les lignes `checkpoint_countersigned` (`d_attente_s`, `d_releve_s`, `d_tsa_s`) |
| `noortrace_anchoring_d_registre_s` | histogramme | `kind` | `d_registre` de P-2 (instant du reçu − `checkpoint_ts` ou `generated_at`) |
| `noortrace_anchoring_ots_pending_age_s` | jauge | — | âge de la preuve en attente la plus ancienne |

Alertes prescrites (CT-8 donne les règles) : `anchor_pending` et
`registry_pending` (CT-2 §14.2) ; « ancre en retard »
(`noortrace_anchor_pending > 0` pendant plus de `queue.anchor_pending_alert_s`,
CT-2 §17.4 : majeure) ; `checkpoint_anchor_late` (une échéance `remplacee`,
EX-4.4 : majeure quand le prestataire des points est extérieur, mineure pour
le serveur interne) ; `inclusion_late`
(`d_registre > registry.inclusion_alert_s`, P-2 : mineure, majeure si répétée) ;
`prestataire_injoignable` (aucun `obtenue` d'un prestataire depuis 15 min alors
qu'il a été sollicité : majeure pour le principal) ; `prestataires_epuises`
(critique pour une période, majeure pour un point) ; `file_pleine`,
`file_perdue` (`anchor_queue_full`, `anchor_queue_truncated_line`,
`anchor_queue_write_failed` : critique) ; `ots_give_up` (majeure) ;
`ordre_ancres_non_respecte` répété (mineure) ; `empreinte_squattee` (critique :
incident de CT-4 §8.3) ; `horloge_suspecte` et `revoque` (EX-5.11, EX-5.12 :
mineure et critique) ; `reponse_tardive_promue` (troisième réponse tardive
promue, EX-5.11 : mineure) ; `point_manquant` (aucun point admis pendant
`2 × c_K`, EX-4.1, AN-2 : majeure ; elle ne porte que sur la production des
points, jamais sur leur contresignature, que `prestataire_injoignable` et
`noortrace_anchoring_window_s` suivent, 3.3) ; `jeton_anterieur_au_point`
(`genTime + précision < checkpoint_ts −
clock_tolerance_s` : majeure, point antidaté ou horloge de l'enregistreur en
avance, 3.4) ; `contresignature_tardive` (`genTime + précision − checkpoint_ts >
c_T` : mineure) ; volume de requêtes (`noortrace_anchoring_attempts_total`
au-delà de deux fois le comptage d'EX-4.11 sur une heure : majeure, 3.4
« composant d'ancrage compromis » ; le compteur compte toutes les tentatives,
quelle que soit leur issue (`outcome`), échecs compris : pendant une panne
longue, les reprises des demandes accumulées peuvent dépasser ce seuil et
lever l'alerte en même temps que `prestataire_injoignable`, et on les lit
ensemble). Journal d'exploitation (CT-2 §17.3, format
d'EX-9.5) : `anchoring_started`, `anchoring_stopped`, `anchoring_queue_rebuilt`
(`recreated`, `periods`, `checkpoints`), `anchor_pending` et
`registry_pending` (existent), `checkpoint_countersigned` (avec `tree_size`,
`provider`, `deadlines`, `d_jeton_s`, `d_point_s`, `d_attente_s`,
`d_releve_s`, `d_tsa_s`, et `closing_fallback` pour le repli de clôture ;
les quatre composantes sont les différences de quatre instants comptés en
secondes entières, tronquées, depuis `D_k` (depuis `period_end` pour le
repli) : `checkpoint_ts` du point, premier envoi de la demande, envoi de la
tentative promue, `genTime + précision` du jeton ; leur somme est donc
exactement `d_jeton_s`, et `d_releve_s` porte ensemble la relève et les
attentes de reprise, EX-3.5), `checkpoint_closing_fallback` (`tree_size`,
`period_request`, `squat_wait_s`, EX-4.2), `point_manquant`
(`last_checkpoint_ts`, `gap_s`), `checkpoint_not_anchored` (point sans
nouvel événement), `checkpoint_anchor_late`, `deadline_sans_objet`,
`period_timestamped`, `anchor_retry`, `anchor_fallback`,
`anchor_response_rejected` (code d'EX-5.10, jamais le jeton),
`anchor_replaced`, `anchor_refused`, `ots_submitted`, `ots_upgraded`,
`ots_complete`, `anchor_queue_full`, `anchor_queue_write_failed`,
`anchor_queue_truncated_line`, `anchor_duplicate_ignored`,
`ordre_ancres_non_respecte`. Aucune ligne ne porte un secret, un jeton ni une
pièce.

### 8.10 Traces normatives

Les traces sont des données de test normatives : chacune est validée par le
schéma `planificateur-ancrage-v0` et rejouée par `rejouerTrace` et par le
vérificateur Go indépendant (annexe A). Elles ne sont pas faites pour être
lues : les règles du planificateur sont toutes énoncées par EX-8.1 à EX-8.15,
et EX-8.16 n'ajoute que l'exigence de rejouer les traces à l'identique. Un
lecteur qui cherche les règles peut sauter la suite de cette section sans
perdre aucune exigence.

**EX-8.16** Une trace est un document JSON conforme à la racine de
`spec/schemas/planificateur-ancrage-v0.schema.json` : la projection de la
configuration (EX-8.2), une liste de gigues injectées, la file au départ, une
suite d'**entrées** horodatées par l'horloge injectée (démarrage, point
produit et admis, période close, tic, réponse d'un prestataire, réponse des
calendriers, inclusion au registre, échec du registre, objets durables relus
du stockage au démarrage (`stockage_relu`, EX-8.12), arrêt) et la suite
exacte des **actions** attendues, puis la file finale. Les réponses des
prestataires sont des entrées : la trace ne contient pas de jeton, seulement
son SHA-256, sa taille, `genTime`, `accuracy`, le nonce lu et les
vérifications T- réussies ; c'est pourquoi le planificateur de référence est
sans réseau et prend ces résultats en entrée (EX-8.13). L'implémentation de
référence et le vérificateur indépendant (annexe A.5) DOIVENT rendre, sur les
mêmes entrées, exactement la liste `expected` (égalité des formes canoniques
JCS v0 de chaque action, dans l'ordre) et la file `queue_after`. Deux entrées
de même instant sont traitées dans l'ordre de la liste ; une action produite à
l'instant d'une entrée porte cet instant, et les actions d'un même instant
sont rangées dans l'ordre où les règles les produisent. Les nonces et
`attempt_id` d'une trace sont dérivés d'étiquettes (annexe A.2) ; l'horloge
n'est jamais lue.

Trace de référence : la période 1 de l'exemple de référence de CT-1 (annexe A
de CT-1 : points `K1` à `K4` de CT-1 §10.8, clôture à 14:00:00.250 Z,
`periodHash` `0xa864…c9f1`), configuration de 4.4 avec `provider_role =
interne` (serveur de test de CT-6) pour exercer la section 7 et `calendars`
réduits aux deux calendriers d'A.2, tous les prestataires joignables. On y lit
la sélection d'EX-4.3 (`K1`, premier point de `checkpoint_ts ≥ D_1 … D_8`,
satisfait huit échéances en une requête ; `K2` satisfait `D_9` et `D_10` ; `K3`,
sans nouvel événement et sans échéance ouverte, n'est ni ancré ni contresigné ;
`K4` satisfait `D_11`), l'ordre des ancres d'EX-4.7 (ancre du point, inclusion
sous `squat_wait_s`, puis jeton ; ancre de la période après l'ancre de `K4`,
puis jeton de clôture), l'écriture de chaque ligne `envoyee` avant son envoi
(EX-8.5, règle 1) et la soumission OpenTimestamps parallèle. La série de
l'exemple n'étant pas alignée (CT-1 §10.8), la trace porte aussi les constats de
cadence : `point_manquant` à 13:44 (aucun point depuis `K1`, 13:42, pendant
`2 × c_K`) et à 13:56 (depuis `K3`, 13:54). Le fichier est validé contre le
schéma, et chaque `envoyer_rfc3161` porte le SHA-256 de la `TimeStampReq`
d'EX-5.1 construite avec le nonce indiqué (`request_size` 82 pour `K1` et `K4` :
politique du serveur interne et nonce à bit haut ; 81 pour `K2` ; 70 pour la
période : sans politique, nonce à bit haut).

<!-- schema: planificateur-ancrage -->
```json
{
  "version": 0,
  "id": "heure-nominale-reference",
  "description": "Période 1 de l'exemple de référence de CT-1 (annexe A de CT-1) : points K1 à K4 de CT-1 §10.8, clôture à 14:00:00.250Z ; échéances D_1 à D_11 toutes les 300 s, la clôture tenant lieu de D_12 (EX-4.2, EX-4.3) ; registre, prestataire principal, serveur interne pour les points et calendriers tous joignables ; aucune reprise. Les réponses des prestataires sont des entrées de la trace (jetons représentés par leur SHA-256) ; l'horloge est injectée.",
  "config": {
    "checkpoint_interval_s": 60,
    "rfc3161": {
      "providers": [
        {
          "id": "qtsa-principal",
          "role": "principal",
          "policy_oid": null,
          "qualified": true,
          "min_interval_ms": 0,
          "request_timeout_ms": 10000
        },
        {
          "id": "qtsa-secours",
          "role": "secours",
          "policy_oid": null,
          "qualified": true,
          "min_interval_ms": 0,
          "request_timeout_ms": 10000
        },
        {
          "id": "tsa-interne",
          "role": "interne",
          "policy_oid": "1.3.6.1.4.1.99999.1.1",
          "qualified": false,
          "min_interval_ms": 0,
          "request_timeout_ms": 5000
        }
      ],
      "manifest": {
        "fallback_after_s": 300
      },
      "checkpoints": {
        "interval_s": 300,
        "provider_role": "interne",
        "fallback_after_s": 120,
        "countersign_idle": false
      },
      "freshness": {
        "max_response_delay_s": 60,
        "clock_tolerance_s": 120
      },
      "retry": {
        "initial_ms": 5000,
        "factor": 2,
        "max_ms": 300000,
        "jitter_ms": 250
      }
    },
    "registry": {
      "checkpoints": "nouveaux_evenements",
      "squat_wait_s": 5,
      "inclusion_alert_s": 60
    },
    "opentimestamps": {
      "enabled": true,
      "calendars": [
        "https://alice.btc.calendar.opentimestamps.org",
        "https://bob.btc.calendar.opentimestamps.org"
      ],
      "min_responses": 2,
      "timeout_ms": 5000,
      "checkpoint": "aucun",
      "upgrade": {
        "first_after_s": 21600,
        "interval_s": 1800,
        "give_up_after_s": 1209600
      }
    },
    "queue": {
      "max_pending": 100000,
      "anchor_pending_alert_s": 7200
    }
  },
  "jitter_ms": [],
  "queue_before": [],
  "inputs": [
    {
      "t": "2026-11-03T13:40:00.000Z",
      "type": "demarrage",
      "data": {}
    },
    {
      "t": "2026-11-03T13:42:00.000Z",
      "type": "point_produit",
      "data": {
        "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
        "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
        "period_start": 1793710800,
        "tree_size": 2,
        "checkpoint_hash": "0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
        "checkpoint_ts": "2026-11-03T13:42:00.000Z"
      }
    },
    {
      "t": "2026-11-03T13:42:03.000Z",
      "type": "inclusion_registre",
      "data": {
        "request_id": "ancre_registre_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
        "block_number": 20001,
        "capture_sha256": "0xd781c9f6d2119900b31def6351c1628402f99d947580b9c8844fb5d1dbdaf976"
      }
    },
    {
      "t": "2026-11-03T13:42:05.000Z",
      "type": "reponse_rfc3161",
      "data": {
        "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
        "attempt": 1,
        "transport": "reponse",
        "http_status": 200,
        "pki_status": 0,
        "failure_info": null,
        "retry_after_s": null,
        "nonce_in_response": "0xdfa0d4356144414f",
        "imprint_matches": true,
        "checks_passed": [
          "T-1",
          "T-2",
          "T-3",
          "T-4",
          "T-5",
          "T-6",
          "T-7",
          "T-8",
          "T-9"
        ],
        "gen_time": "2026-11-03T13:42:04Z",
        "accuracy_s": 1,
        "token_sha256": "0x9c4cd8444c868abd119d0722ff94ad4db74be85aac0f61736b2bb99eabf5397b",
        "token_size": 2104
      }
    },
    {
      "t": "2026-11-03T13:45:00.000Z",
      "type": "tic",
      "data": {}
    },
    {
      "t": "2026-11-03T13:50:00.000Z",
      "type": "tic",
      "data": {}
    },
    {
      "t": "2026-11-03T13:53:00.000Z",
      "type": "point_produit",
      "data": {
        "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
        "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
        "period_start": 1793710800,
        "tree_size": 4,
        "checkpoint_hash": "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
        "checkpoint_ts": "2026-11-03T13:53:00.000Z"
      }
    },
    {
      "t": "2026-11-03T13:53:02.000Z",
      "type": "inclusion_registre",
      "data": {
        "request_id": "ancre_registre_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
        "block_number": 20660,
        "capture_sha256": "0x13527153088884e754778e40e50d8eacf9d927af09c2e3e07b61d92ab4cf480b"
      }
    },
    {
      "t": "2026-11-03T13:53:04.000Z",
      "type": "reponse_rfc3161",
      "data": {
        "request_id": "jeton_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
        "attempt": 1,
        "transport": "reponse",
        "http_status": 200,
        "pki_status": 0,
        "failure_info": null,
        "retry_after_s": null,
        "nonce_in_response": "0x018032ff0d74cfda",
        "imprint_matches": true,
        "checks_passed": [
          "T-1",
          "T-2",
          "T-3",
          "T-4",
          "T-5",
          "T-6",
          "T-7",
          "T-8",
          "T-9"
        ],
        "gen_time": "2026-11-03T13:53:03Z",
        "accuracy_s": 1,
        "token_sha256": "0xdf609f6978c714743257fa993063aadc33ecbe9c7177ad993d7fda99573a8a0a",
        "token_size": 2104
      }
    },
    {
      "t": "2026-11-03T13:54:00.000Z",
      "type": "point_produit",
      "data": {
        "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
        "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
        "period_start": 1793710800,
        "tree_size": 4,
        "checkpoint_hash": "0x3feb86ac4d6d8c054bef224f131f0276d2f1c9c9db2a6ce06adec173378d8867",
        "checkpoint_ts": "2026-11-03T13:54:00.000Z"
      }
    },
    {
      "t": "2026-11-03T13:55:00.000Z",
      "type": "tic",
      "data": {}
    },
    {
      "t": "2026-11-03T14:00:00.250Z",
      "type": "point_produit",
      "data": {
        "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
        "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
        "period_start": 1793710800,
        "tree_size": 5,
        "checkpoint_hash": "0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
        "checkpoint_ts": "2026-11-03T14:00:00.250Z"
      }
    },
    {
      "t": "2026-11-03T14:00:00.250Z",
      "type": "periode_close",
      "data": {
        "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
        "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
        "period_start": 1793710800,
        "period_hash": "0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
        "generated_at": "2026-11-03T14:00:00.250Z"
      }
    },
    {
      "t": "2026-11-03T14:00:01.000Z",
      "type": "reponse_ots",
      "data": {
        "request_id": "ots_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
        "calendars_answered": 2,
        "attestation": "en_attente",
        "proof_sha256": "0x9c6433e33949ee9a14685c8929590f0e32f6c611b3b9ea99294cee22a9ba2355",
        "proof_size": 233
      }
    },
    {
      "t": "2026-11-03T14:00:02.000Z",
      "type": "inclusion_registre",
      "data": {
        "request_id": "ancre_registre_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
        "block_number": 21085,
        "capture_sha256": "0x873b4cf5eb73f0f4aa2f6170bda40bd892c5676267b69d53ae552eff403964e4"
      }
    },
    {
      "t": "2026-11-03T14:00:03.000Z",
      "type": "reponse_rfc3161",
      "data": {
        "request_id": "jeton_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
        "attempt": 1,
        "transport": "reponse",
        "http_status": 200,
        "pki_status": 0,
        "failure_info": null,
        "retry_after_s": null,
        "nonce_in_response": "0x9cd8e6f026675bc3",
        "imprint_matches": true,
        "checks_passed": [
          "T-1",
          "T-2",
          "T-3",
          "T-4",
          "T-5",
          "T-6",
          "T-7",
          "T-8",
          "T-9"
        ],
        "gen_time": "2026-11-03T14:00:02Z",
        "accuracy_s": 1,
        "token_sha256": "0xbd2962cc35dc49ee94680cb7b547faabe605d7ffcaf53087c18129c72acb3501",
        "token_size": 2104
      }
    },
    {
      "t": "2026-11-03T14:00:04.000Z",
      "type": "inclusion_registre",
      "data": {
        "request_id": "ancre_registre_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
        "block_number": 21087,
        "capture_sha256": "0x906e615b692493ef817e85d0ed12e9c98e860de2fb0cb904fe3ddfecfd20c25a"
      }
    },
    {
      "t": "2026-11-03T14:00:05.000Z",
      "type": "reponse_rfc3161",
      "data": {
        "request_id": "jeton_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
        "attempt": 1,
        "transport": "reponse",
        "http_status": 200,
        "pki_status": 0,
        "failure_info": null,
        "retry_after_s": null,
        "nonce_in_response": "0xf144cca6ec50dcdb",
        "imprint_matches": true,
        "checks_passed": [
          "T-1",
          "T-2",
          "T-3",
          "T-4",
          "T-5",
          "T-6",
          "T-7",
          "T-8",
          "T-9"
        ],
        "gen_time": "2026-11-03T14:00:05Z",
        "accuracy_s": 1,
        "token_sha256": "0x2be26388aab7e646d8a3a81d220456c2bf39f45832a2138659478e7f2cbeabb3",
        "token_size": 3082
      }
    },
    {
      "t": "2026-11-03T14:01:00.000Z",
      "type": "arret",
      "data": {}
    }
  ],
  "expected": [
    {
      "t": "2026-11-03T13:40:00.000Z",
      "action": "journaliser",
      "request_id": null,
      "detail": {
        "event": "anchoring_started",
        "queue_entries": 0
      }
    },
    {
      "t": "2026-11-03T13:42:00.000Z",
      "action": "ecrire_file",
      "request_id": "ancre_registre_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "state": "a_envoyer"
      }
    },
    {
      "t": "2026-11-03T13:42:00.000Z",
      "action": "ecrire_file",
      "request_id": "ancre_registre_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "state": "envoyee"
      }
    },
    {
      "t": "2026-11-03T13:42:00.000Z",
      "action": "envoyer_registre",
      "request_id": "ancre_registre_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "fingerprint": "0xd0cd916d070ecb8c2af3a3b62b933ccd6e61fd481ea2b70312ab988fabac8540",
        "doc_type": "0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178"
      }
    },
    {
      "t": "2026-11-03T13:42:00.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "k": 1,
        "state": "ouverte"
      }
    },
    {
      "t": "2026-11-03T13:42:00.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "k": 2,
        "state": "ouverte"
      }
    },
    {
      "t": "2026-11-03T13:42:00.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "k": 3,
        "state": "ouverte"
      }
    },
    {
      "t": "2026-11-03T13:42:00.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "k": 4,
        "state": "ouverte"
      }
    },
    {
      "t": "2026-11-03T13:42:00.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "k": 5,
        "state": "ouverte"
      }
    },
    {
      "t": "2026-11-03T13:42:00.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "k": 6,
        "state": "ouverte"
      }
    },
    {
      "t": "2026-11-03T13:42:00.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "k": 7,
        "state": "ouverte"
      }
    },
    {
      "t": "2026-11-03T13:42:00.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "k": 8,
        "state": "ouverte"
      }
    },
    {
      "t": "2026-11-03T13:42:00.000Z",
      "action": "ecrire_file",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "state": "attente_registre"
      }
    },
    {
      "t": "2026-11-03T13:42:00.000Z",
      "action": "programmer",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "next_at": "2026-11-03T13:42:05.000Z",
        "reason": "attente_registre"
      }
    },
    {
      "t": "2026-11-03T13:42:03.000Z",
      "action": "stocker",
      "request_id": "ancre_registre_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "sha256": "0xd781c9f6d2119900b31def6351c1628402f99d947580b9c8844fb5d1dbdaf976",
        "size": 4096,
        "bound": null
      }
    },
    {
      "t": "2026-11-03T13:42:03.000Z",
      "action": "ecrire_file",
      "request_id": "ancre_registre_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "state": "obtenue"
      }
    },
    {
      "t": "2026-11-03T13:42:03.000Z",
      "action": "ecrire_file",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "state": "envoyee"
      }
    },
    {
      "t": "2026-11-03T13:42:03.000Z",
      "action": "envoyer_rfc3161",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "provider": "tsa-interne",
        "attempt": 1,
        "digest": "0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
        "nonce": "0xdfa0d4356144414f",
        "policy_oid": "1.3.6.1.4.1.99999.1.1",
        "request_sha256": "0x9ad9fd7abe2292919c298eee0bcaa4153a62a7fb1d1d9a6876d291df23bf0c3d",
        "request_size": 82
      }
    },
    {
      "t": "2026-11-03T13:42:05.000Z",
      "action": "stocker",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "sha256": "0x9c4cd8444c868abd119d0722ff94ad4db74be85aac0f61736b2bb99eabf5397b",
        "size": 2104,
        "bound": "2026-11-03T13:42:05.000Z"
      }
    },
    {
      "t": "2026-11-03T13:42:05.000Z",
      "action": "ecrire_file",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "state": "obtenue"
      }
    },
    {
      "t": "2026-11-03T13:42:05.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "k": 1,
        "state": "satisfaite"
      }
    },
    {
      "t": "2026-11-03T13:42:05.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "k": 2,
        "state": "satisfaite"
      }
    },
    {
      "t": "2026-11-03T13:42:05.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "k": 3,
        "state": "satisfaite"
      }
    },
    {
      "t": "2026-11-03T13:42:05.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "k": 4,
        "state": "satisfaite"
      }
    },
    {
      "t": "2026-11-03T13:42:05.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "k": 5,
        "state": "satisfaite"
      }
    },
    {
      "t": "2026-11-03T13:42:05.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "k": 6,
        "state": "satisfaite"
      }
    },
    {
      "t": "2026-11-03T13:42:05.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "k": 7,
        "state": "satisfaite"
      }
    },
    {
      "t": "2026-11-03T13:42:05.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "k": 8,
        "state": "satisfaite"
      }
    },
    {
      "t": "2026-11-03T13:42:05.000Z",
      "action": "journaliser",
      "request_id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "detail": {
        "event": "checkpoint_countersigned",
        "tree_size": 2,
        "provider": "tsa-interne",
        "deadlines": [
          1,
          2,
          3,
          4,
          5,
          6,
          7,
          8
        ],
        "d_jeton_s": 125,
        "d_point_s": 120,
        "d_attente_s": 3,
        "d_releve_s": 0,
        "d_tsa_s": 2
      }
    },
    {
      "t": "2026-11-03T13:44:00.000Z",
      "action": "journaliser",
      "request_id": null,
      "detail": {
        "event": "point_manquant",
        "last_checkpoint_ts": "2026-11-03T13:42:00.000Z",
        "gap_s": 120
      }
    },
    {
      "t": "2026-11-03T13:44:00.000Z",
      "action": "alerter",
      "request_id": null,
      "detail": {
        "code": "point_manquant",
        "severity": "majeure"
      }
    },
    {
      "t": "2026-11-03T13:45:00.000Z",
      "action": "echeance",
      "request_id": null,
      "detail": {
        "k": 9,
        "state": "ouverte"
      }
    },
    {
      "t": "2026-11-03T13:50:00.000Z",
      "action": "echeance",
      "request_id": null,
      "detail": {
        "k": 10,
        "state": "ouverte"
      }
    },
    {
      "t": "2026-11-03T13:53:00.000Z",
      "action": "ecrire_file",
      "request_id": "ancre_registre_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "detail": {
        "state": "a_envoyer"
      }
    },
    {
      "t": "2026-11-03T13:53:00.000Z",
      "action": "ecrire_file",
      "request_id": "ancre_registre_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "detail": {
        "state": "envoyee"
      }
    },
    {
      "t": "2026-11-03T13:53:00.000Z",
      "action": "envoyer_registre",
      "request_id": "ancre_registre_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "detail": {
        "fingerprint": "0x7f721a4526c614882ff41ac33792c6d05fa7fb6dd98bc1c369d0e277029f4e44",
        "doc_type": "0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178"
      }
    },
    {
      "t": "2026-11-03T13:53:00.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "detail": {
        "k": 9,
        "state": "ouverte"
      }
    },
    {
      "t": "2026-11-03T13:53:00.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "detail": {
        "k": 10,
        "state": "ouverte"
      }
    },
    {
      "t": "2026-11-03T13:53:00.000Z",
      "action": "ecrire_file",
      "request_id": "jeton_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "detail": {
        "state": "attente_registre"
      }
    },
    {
      "t": "2026-11-03T13:53:00.000Z",
      "action": "programmer",
      "request_id": "jeton_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "detail": {
        "next_at": "2026-11-03T13:53:05.000Z",
        "reason": "attente_registre"
      }
    },
    {
      "t": "2026-11-03T13:53:02.000Z",
      "action": "stocker",
      "request_id": "ancre_registre_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "detail": {
        "sha256": "0x13527153088884e754778e40e50d8eacf9d927af09c2e3e07b61d92ab4cf480b",
        "size": 4096,
        "bound": null
      }
    },
    {
      "t": "2026-11-03T13:53:02.000Z",
      "action": "ecrire_file",
      "request_id": "ancre_registre_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "detail": {
        "state": "obtenue"
      }
    },
    {
      "t": "2026-11-03T13:53:02.000Z",
      "action": "ecrire_file",
      "request_id": "jeton_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "detail": {
        "state": "envoyee"
      }
    },
    {
      "t": "2026-11-03T13:53:02.000Z",
      "action": "envoyer_rfc3161",
      "request_id": "jeton_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "detail": {
        "provider": "tsa-interne",
        "attempt": 1,
        "digest": "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
        "nonce": "0x018032ff0d74cfda",
        "policy_oid": "1.3.6.1.4.1.99999.1.1",
        "request_sha256": "0x5a0dc94d0164a9a084c7114174908dc7a3b757ee1cbb12ceeb212b6c1386c4b8",
        "request_size": 81
      }
    },
    {
      "t": "2026-11-03T13:53:04.000Z",
      "action": "stocker",
      "request_id": "jeton_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "detail": {
        "sha256": "0xdf609f6978c714743257fa993063aadc33ecbe9c7177ad993d7fda99573a8a0a",
        "size": 2104,
        "bound": "2026-11-03T13:53:04.000Z"
      }
    },
    {
      "t": "2026-11-03T13:53:04.000Z",
      "action": "ecrire_file",
      "request_id": "jeton_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "detail": {
        "state": "obtenue"
      }
    },
    {
      "t": "2026-11-03T13:53:04.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "detail": {
        "k": 9,
        "state": "satisfaite"
      }
    },
    {
      "t": "2026-11-03T13:53:04.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "detail": {
        "k": 10,
        "state": "satisfaite"
      }
    },
    {
      "t": "2026-11-03T13:53:04.000Z",
      "action": "journaliser",
      "request_id": "jeton_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "detail": {
        "event": "checkpoint_countersigned",
        "tree_size": 4,
        "provider": "tsa-interne",
        "deadlines": [
          9,
          10
        ],
        "d_jeton_s": 184,
        "d_point_s": 180,
        "d_attente_s": 2,
        "d_releve_s": 0,
        "d_tsa_s": 2
      }
    },
    {
      "t": "2026-11-03T13:54:00.000Z",
      "action": "journaliser",
      "request_id": null,
      "detail": {
        "event": "checkpoint_not_anchored",
        "reason": "aucun_nouvel_evenement",
        "tree_size": 4
      }
    },
    {
      "t": "2026-11-03T13:55:00.000Z",
      "action": "echeance",
      "request_id": null,
      "detail": {
        "k": 11,
        "state": "ouverte"
      }
    },
    {
      "t": "2026-11-03T13:56:00.000Z",
      "action": "journaliser",
      "request_id": null,
      "detail": {
        "event": "point_manquant",
        "last_checkpoint_ts": "2026-11-03T13:54:00.000Z",
        "gap_s": 120
      }
    },
    {
      "t": "2026-11-03T13:56:00.000Z",
      "action": "alerter",
      "request_id": null,
      "detail": {
        "code": "point_manquant",
        "severity": "majeure"
      }
    },
    {
      "t": "2026-11-03T14:00:00.250Z",
      "action": "ecrire_file",
      "request_id": "ancre_registre_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
      "detail": {
        "state": "a_envoyer"
      }
    },
    {
      "t": "2026-11-03T14:00:00.250Z",
      "action": "ecrire_file",
      "request_id": "ancre_registre_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
      "detail": {
        "state": "envoyee"
      }
    },
    {
      "t": "2026-11-03T14:00:00.250Z",
      "action": "envoyer_registre",
      "request_id": "ancre_registre_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
      "detail": {
        "fingerprint": "0xa7f0a30f11f724f5ae4bd7ba952079fa513dfe0ed70c051bdfc5bbe9c67b3792",
        "doc_type": "0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178"
      }
    },
    {
      "t": "2026-11-03T14:00:00.250Z",
      "action": "echeance",
      "request_id": "jeton_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
      "detail": {
        "k": 11,
        "state": "ouverte"
      }
    },
    {
      "t": "2026-11-03T14:00:00.250Z",
      "action": "ecrire_file",
      "request_id": "jeton_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
      "detail": {
        "state": "attente_registre"
      }
    },
    {
      "t": "2026-11-03T14:00:00.250Z",
      "action": "programmer",
      "request_id": "jeton_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
      "detail": {
        "next_at": "2026-11-03T14:00:05.250Z",
        "reason": "attente_registre"
      }
    },
    {
      "t": "2026-11-03T14:00:00.250Z",
      "action": "ecrire_file",
      "request_id": "ancre_registre_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "state": "a_envoyer"
      }
    },
    {
      "t": "2026-11-03T14:00:00.250Z",
      "action": "ecrire_file",
      "request_id": "jeton_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "state": "attente_registre"
      }
    },
    {
      "t": "2026-11-03T14:00:00.250Z",
      "action": "ecrire_file",
      "request_id": "ots_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "state": "a_envoyer"
      }
    },
    {
      "t": "2026-11-03T14:00:00.250Z",
      "action": "programmer",
      "request_id": "ancre_registre_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "next_at": "2026-11-03T14:00:00.250Z",
        "reason": "attente_nonce"
      }
    },
    {
      "t": "2026-11-03T14:00:00.250Z",
      "action": "programmer",
      "request_id": "jeton_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "next_at": "2026-11-03T14:01:00.250Z",
        "reason": "attente_registre"
      }
    },
    {
      "t": "2026-11-03T14:00:00.250Z",
      "action": "ecrire_file",
      "request_id": "ots_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "state": "envoyee"
      }
    },
    {
      "t": "2026-11-03T14:00:00.250Z",
      "action": "soumettre_ots",
      "request_id": "ots_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "digest": "0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
        "nonce": "0x29447d7a96d0433897b22e5156a977a5",
        "calendars": [
          "https://alice.btc.calendar.opentimestamps.org",
          "https://bob.btc.calendar.opentimestamps.org"
        ]
      }
    },
    {
      "t": "2026-11-03T14:00:01.000Z",
      "action": "stocker",
      "request_id": "ots_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "sha256": "0x9c6433e33949ee9a14685c8929590f0e32f6c611b3b9ea99294cee22a9ba2355",
        "size": 233,
        "bound": null
      }
    },
    {
      "t": "2026-11-03T14:00:01.000Z",
      "action": "ecrire_file",
      "request_id": "ots_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "state": "en_attente"
      }
    },
    {
      "t": "2026-11-03T14:00:01.000Z",
      "action": "programmer",
      "request_id": "ots_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "next_at": "2026-11-03T20:00:01.000Z",
        "reason": "mise_a_niveau"
      }
    },
    {
      "t": "2026-11-03T14:00:02.000Z",
      "action": "stocker",
      "request_id": "ancre_registre_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
      "detail": {
        "sha256": "0x873b4cf5eb73f0f4aa2f6170bda40bd892c5676267b69d53ae552eff403964e4",
        "size": 4096,
        "bound": null
      }
    },
    {
      "t": "2026-11-03T14:00:02.000Z",
      "action": "ecrire_file",
      "request_id": "ancre_registre_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
      "detail": {
        "state": "obtenue"
      }
    },
    {
      "t": "2026-11-03T14:00:02.000Z",
      "action": "ecrire_file",
      "request_id": "jeton_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
      "detail": {
        "state": "envoyee"
      }
    },
    {
      "t": "2026-11-03T14:00:02.000Z",
      "action": "envoyer_rfc3161",
      "request_id": "jeton_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
      "detail": {
        "provider": "tsa-interne",
        "attempt": 1,
        "digest": "0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
        "nonce": "0x9cd8e6f026675bc3",
        "policy_oid": "1.3.6.1.4.1.99999.1.1",
        "request_sha256": "0x6f88f4e45d32b85bd8a49454ac91a0bf859a7b58225be8de0fc634aa59d787bd",
        "request_size": 82
      }
    },
    {
      "t": "2026-11-03T14:00:02.000Z",
      "action": "ecrire_file",
      "request_id": "ancre_registre_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "state": "envoyee"
      }
    },
    {
      "t": "2026-11-03T14:00:02.000Z",
      "action": "envoyer_registre",
      "request_id": "ancre_registre_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "fingerprint": "0x3200e496c555b46459191c852a7f79b1e0b4156802cac2f2df7b80b0aa9d823b",
        "doc_type": "0x2970f32daf26845541b559f8505ddade17ab51994fab81cbfe0dbd81ab9671ee"
      }
    },
    {
      "t": "2026-11-03T14:00:03.000Z",
      "action": "stocker",
      "request_id": "jeton_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
      "detail": {
        "sha256": "0xbd2962cc35dc49ee94680cb7b547faabe605d7ffcaf53087c18129c72acb3501",
        "size": 2104,
        "bound": "2026-11-03T14:00:03.000Z"
      }
    },
    {
      "t": "2026-11-03T14:00:03.000Z",
      "action": "ecrire_file",
      "request_id": "jeton_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
      "detail": {
        "state": "obtenue"
      }
    },
    {
      "t": "2026-11-03T14:00:03.000Z",
      "action": "echeance",
      "request_id": "jeton_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
      "detail": {
        "k": 11,
        "state": "satisfaite"
      }
    },
    {
      "t": "2026-11-03T14:00:03.000Z",
      "action": "journaliser",
      "request_id": "jeton_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
      "detail": {
        "event": "checkpoint_countersigned",
        "tree_size": 5,
        "provider": "tsa-interne",
        "deadlines": [
          11
        ],
        "d_jeton_s": 303,
        "d_point_s": 300,
        "d_attente_s": 2,
        "d_releve_s": 0,
        "d_tsa_s": 1
      }
    },
    {
      "t": "2026-11-03T14:00:04.000Z",
      "action": "stocker",
      "request_id": "ancre_registre_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "sha256": "0x906e615b692493ef817e85d0ed12e9c98e860de2fb0cb904fe3ddfecfd20c25a",
        "size": 4096,
        "bound": null
      }
    },
    {
      "t": "2026-11-03T14:00:04.000Z",
      "action": "ecrire_file",
      "request_id": "ancre_registre_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "state": "obtenue"
      }
    },
    {
      "t": "2026-11-03T14:00:04.000Z",
      "action": "ecrire_file",
      "request_id": "jeton_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "state": "envoyee"
      }
    },
    {
      "t": "2026-11-03T14:00:04.000Z",
      "action": "envoyer_rfc3161",
      "request_id": "jeton_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "provider": "qtsa-principal",
        "attempt": 1,
        "digest": "0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
        "nonce": "0xf144cca6ec50dcdb",
        "policy_oid": null,
        "request_sha256": "0xd8fc9ff1a6908df641f9bd6e6a6c72e90eacda3837e6b8cc78d82d9f92919399",
        "request_size": 70
      }
    },
    {
      "t": "2026-11-03T14:00:05.000Z",
      "action": "stocker",
      "request_id": "jeton_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "sha256": "0x2be26388aab7e646d8a3a81d220456c2bf39f45832a2138659478e7f2cbeabb3",
        "size": 3082,
        "bound": "2026-11-03T14:00:06.000Z"
      }
    },
    {
      "t": "2026-11-03T14:00:05.000Z",
      "action": "ecrire_file",
      "request_id": "jeton_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "state": "obtenue"
      }
    },
    {
      "t": "2026-11-03T14:00:05.000Z",
      "action": "echeance",
      "request_id": "jeton_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "k": 12,
        "state": "satisfaite"
      }
    },
    {
      "t": "2026-11-03T14:00:05.000Z",
      "action": "journaliser",
      "request_id": "jeton_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "detail": {
        "event": "period_timestamped",
        "provider": "qtsa-principal",
        "d_jeton_s": 6
      }
    },
    {
      "t": "2026-11-03T14:01:00.000Z",
      "action": "journaliser",
      "request_id": null,
      "detail": {
        "event": "anchoring_stopped",
        "queue_entries": 9
      }
    }
  ],
  "queue_after": [
    {
      "version": 0,
      "id": "ancre_registre_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "kind": "ancre_registre_point",
      "subject": {
        "kind": "point",
        "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
        "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
        "period_start": 1793710800,
        "hash": "0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
        "tree_size": 2,
        "declared_at": "2026-11-03T13:42:00.000Z"
      },
      "deadlines": [],
      "state": "obtenue",
      "created_at": "2026-11-03T13:42:00.000Z",
      "due_at": null,
      "attempts": [
        {
          "n": 1,
          "provider": null,
          "started_at": "2026-11-03T13:42:00.000Z",
          "nonce": null,
          "correlation_id": "ancre_registre_point:fbc4715789d5bfee:1",
          "outcome": "obtenue",
          "error_code": null,
          "http_status": null,
          "pki_status": null,
          "failure_info": null,
          "retry_after_s": null,
          "next_at": null,
          "detail": "ancre incluse au bloc 20001"
        }
      ],
      "result": {
        "sha256": "0xd781c9f6d2119900b31def6351c1628402f99d947580b9c8844fb5d1dbdaf976",
        "size": 4096,
        "provider": null,
        "obtained_at": "2026-11-03T13:42:03.000Z",
        "bound": null
      },
      "replaced_by": null
    },
    {
      "version": 0,
      "id": "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
      "kind": "jeton_point",
      "subject": {
        "kind": "point",
        "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
        "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
        "period_start": 1793710800,
        "hash": "0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
        "tree_size": 2,
        "declared_at": "2026-11-03T13:42:00.000Z"
      },
      "deadlines": [
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8
      ],
      "state": "obtenue",
      "created_at": "2026-11-03T13:42:00.000Z",
      "due_at": null,
      "attempts": [
        {
          "n": 1,
          "provider": "tsa-interne",
          "started_at": "2026-11-03T13:42:03.000Z",
          "nonce": "0xdfa0d4356144414f",
          "correlation_id": "jeton_point:fbc4715789d5bfee:1",
          "outcome": "obtenue",
          "error_code": null,
          "http_status": 200,
          "pki_status": 0,
          "failure_info": null,
          "retry_after_s": null,
          "next_at": null,
          "detail": "granted ; T-1 a T-9 reussies"
        }
      ],
      "result": {
        "sha256": "0x9c4cd8444c868abd119d0722ff94ad4db74be85aac0f61736b2bb99eabf5397b",
        "size": 2104,
        "provider": "tsa-interne",
        "obtained_at": "2026-11-03T13:42:05.000Z",
        "bound": "2026-11-03T13:42:05.000Z"
      },
      "replaced_by": null
    },
    {
      "version": 0,
      "id": "ancre_registre_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "kind": "ancre_registre_point",
      "subject": {
        "kind": "point",
        "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
        "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
        "period_start": 1793710800,
        "hash": "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
        "tree_size": 4,
        "declared_at": "2026-11-03T13:53:00.000Z"
      },
      "deadlines": [],
      "state": "obtenue",
      "created_at": "2026-11-03T13:53:00.000Z",
      "due_at": null,
      "attempts": [
        {
          "n": 1,
          "provider": null,
          "started_at": "2026-11-03T13:53:00.000Z",
          "nonce": null,
          "correlation_id": "ancre_registre_point:6a8e035ab9b90937:1",
          "outcome": "obtenue",
          "error_code": null,
          "http_status": null,
          "pki_status": null,
          "failure_info": null,
          "retry_after_s": null,
          "next_at": null,
          "detail": "ancre incluse au bloc 20660"
        }
      ],
      "result": {
        "sha256": "0x13527153088884e754778e40e50d8eacf9d927af09c2e3e07b61d92ab4cf480b",
        "size": 4096,
        "provider": null,
        "obtained_at": "2026-11-03T13:53:02.000Z",
        "bound": null
      },
      "replaced_by": null
    },
    {
      "version": 0,
      "id": "jeton_point:0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
      "kind": "jeton_point",
      "subject": {
        "kind": "point",
        "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
        "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
        "period_start": 1793710800,
        "hash": "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
        "tree_size": 4,
        "declared_at": "2026-11-03T13:53:00.000Z"
      },
      "deadlines": [
        9,
        10
      ],
      "state": "obtenue",
      "created_at": "2026-11-03T13:53:00.000Z",
      "due_at": null,
      "attempts": [
        {
          "n": 1,
          "provider": "tsa-interne",
          "started_at": "2026-11-03T13:53:02.000Z",
          "nonce": "0x018032ff0d74cfda",
          "correlation_id": "jeton_point:6a8e035ab9b90937:1",
          "outcome": "obtenue",
          "error_code": null,
          "http_status": 200,
          "pki_status": 0,
          "failure_info": null,
          "retry_after_s": null,
          "next_at": null,
          "detail": "granted ; T-1 a T-9 reussies"
        }
      ],
      "result": {
        "sha256": "0xdf609f6978c714743257fa993063aadc33ecbe9c7177ad993d7fda99573a8a0a",
        "size": 2104,
        "provider": "tsa-interne",
        "obtained_at": "2026-11-03T13:53:04.000Z",
        "bound": "2026-11-03T13:53:04.000Z"
      },
      "replaced_by": null
    },
    {
      "version": 0,
      "id": "ancre_registre_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "kind": "ancre_registre_periode",
      "subject": {
        "kind": "periode",
        "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
        "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
        "period_start": 1793710800,
        "hash": "0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
        "tree_size": null,
        "declared_at": "2026-11-03T14:00:00.250Z"
      },
      "deadlines": [],
      "state": "obtenue",
      "created_at": "2026-11-03T14:00:00.250Z",
      "due_at": null,
      "attempts": [
        {
          "n": 1,
          "provider": null,
          "started_at": "2026-11-03T14:00:02.000Z",
          "nonce": null,
          "correlation_id": "ancre_registre_periode:a864281e05663ee5:1",
          "outcome": "obtenue",
          "error_code": null,
          "http_status": null,
          "pki_status": null,
          "failure_info": null,
          "retry_after_s": null,
          "next_at": null,
          "detail": "ancre incluse au bloc 21087"
        }
      ],
      "result": {
        "sha256": "0x906e615b692493ef817e85d0ed12e9c98e860de2fb0cb904fe3ddfecfd20c25a",
        "size": 4096,
        "provider": null,
        "obtained_at": "2026-11-03T14:00:04.000Z",
        "bound": null
      },
      "replaced_by": null
    },
    {
      "version": 0,
      "id": "ancre_registre_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
      "kind": "ancre_registre_point",
      "subject": {
        "kind": "point",
        "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
        "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
        "period_start": 1793710800,
        "hash": "0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
        "tree_size": 5,
        "declared_at": "2026-11-03T14:00:00.250Z"
      },
      "deadlines": [],
      "state": "obtenue",
      "created_at": "2026-11-03T14:00:00.250Z",
      "due_at": null,
      "attempts": [
        {
          "n": 1,
          "provider": null,
          "started_at": "2026-11-03T14:00:00.250Z",
          "nonce": null,
          "correlation_id": "ancre_registre_point:804585ae4e9601a9:1",
          "outcome": "obtenue",
          "error_code": null,
          "http_status": null,
          "pki_status": null,
          "failure_info": null,
          "retry_after_s": null,
          "next_at": null,
          "detail": "ancre incluse au bloc 21085"
        }
      ],
      "result": {
        "sha256": "0x873b4cf5eb73f0f4aa2f6170bda40bd892c5676267b69d53ae552eff403964e4",
        "size": 4096,
        "provider": null,
        "obtained_at": "2026-11-03T14:00:02.000Z",
        "bound": null
      },
      "replaced_by": null
    },
    {
      "version": 0,
      "id": "jeton_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "kind": "jeton_periode",
      "subject": {
        "kind": "periode",
        "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
        "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
        "period_start": 1793710800,
        "hash": "0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
        "tree_size": null,
        "declared_at": "2026-11-03T14:00:00.250Z"
      },
      "deadlines": [],
      "state": "obtenue",
      "created_at": "2026-11-03T14:00:00.250Z",
      "due_at": null,
      "attempts": [
        {
          "n": 1,
          "provider": "qtsa-principal",
          "started_at": "2026-11-03T14:00:04.000Z",
          "nonce": "0xf144cca6ec50dcdb",
          "correlation_id": "jeton_periode:a864281e05663ee5:1",
          "outcome": "obtenue",
          "error_code": null,
          "http_status": 200,
          "pki_status": 0,
          "failure_info": null,
          "retry_after_s": null,
          "next_at": null,
          "detail": "granted ; T-1 a T-9 reussies"
        }
      ],
      "result": {
        "sha256": "0x2be26388aab7e646d8a3a81d220456c2bf39f45832a2138659478e7f2cbeabb3",
        "size": 3082,
        "provider": "qtsa-principal",
        "obtained_at": "2026-11-03T14:00:05.000Z",
        "bound": "2026-11-03T14:00:06.000Z"
      },
      "replaced_by": null
    },
    {
      "version": 0,
      "id": "jeton_point:0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
      "kind": "jeton_point",
      "subject": {
        "kind": "point",
        "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
        "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
        "period_start": 1793710800,
        "hash": "0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107",
        "tree_size": 5,
        "declared_at": "2026-11-03T14:00:00.250Z"
      },
      "deadlines": [
        11
      ],
      "state": "obtenue",
      "created_at": "2026-11-03T14:00:00.250Z",
      "due_at": null,
      "attempts": [
        {
          "n": 1,
          "provider": "tsa-interne",
          "started_at": "2026-11-03T14:00:02.000Z",
          "nonce": "0x9cd8e6f026675bc3",
          "correlation_id": "jeton_point:804585ae4e9601a9:1",
          "outcome": "obtenue",
          "error_code": null,
          "http_status": 200,
          "pki_status": 0,
          "failure_info": null,
          "retry_after_s": null,
          "next_at": null,
          "detail": "granted ; T-1 a T-9 reussies"
        }
      ],
      "result": {
        "sha256": "0xbd2962cc35dc49ee94680cb7b547faabe605d7ffcaf53087c18129c72acb3501",
        "size": 2104,
        "provider": "tsa-interne",
        "obtained_at": "2026-11-03T14:00:03.000Z",
        "bound": "2026-11-03T14:00:03.000Z"
      },
      "replaced_by": null
    },
    {
      "version": 0,
      "id": "ots_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
      "kind": "ots_periode",
      "subject": {
        "kind": "periode",
        "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
        "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
        "period_start": 1793710800,
        "hash": "0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
        "tree_size": null,
        "declared_at": "2026-11-03T14:00:00.250Z"
      },
      "deadlines": [],
      "state": "en_attente",
      "created_at": "2026-11-03T14:00:00.250Z",
      "due_at": "2026-11-03T20:00:01.000Z",
      "attempts": [
        {
          "n": 1,
          "provider": null,
          "started_at": "2026-11-03T14:00:00.250Z",
          "nonce": null,
          "correlation_id": "ots_periode:a864281e05663ee5:1",
          "outcome": "obtenue",
          "error_code": null,
          "http_status": null,
          "pki_status": null,
          "failure_info": null,
          "retry_after_s": null,
          "next_at": "2026-11-03T20:00:01.000Z",
          "detail": "2 calendriers ; attestation en attente"
        }
      ],
      "result": {
        "sha256": "0x9c6433e33949ee9a14685c8929590f0e32f6c611b3b9ea99294cee22a9ba2355",
        "size": 233,
        "provider": null,
        "obtained_at": "2026-11-03T14:00:01.000Z",
        "bound": null
      },
      "replaced_by": null
    }
  ]
}
```

Les autres traces normatives (annexe A.4, famille `planification/`) :
`principal-injoignable` (erreurs de transport puis 503 avec `Retry-After`,
attentes d'EX-8.9, relève par le secours après `fallback_after_s`, jeton
promu du secours, réponse tardive du principal conservée non promue),
`refus-permanent-releve` (`unacceptedPolicy` du principal : relève immédiate,
aucune réexpédition de la requête refusée), `reponse-tardive` (deux réponses
tardives puis une troisième promue avec avertissement, EX-5.11),
`horloge-suspecte` (jeton promu avec avertissement), `echeance-remplacee`
(serveur interne injoignable pendant deux échéances : `checkpoint_anchor_late`,
aucun rattrapage, fenêtre observée), `registre-indisponible` (ancre de point
sans reçu : `squat_wait_s` puis `ordre_ancres_non_respecte` ; ancre de période
sans reçu : `jeton_periode` en `attente_registre`, `registry_pending`, alerte à
`anchor_pending_alert_s`), `redemarrage-reprise` (`queue_before` non vide avec
des demandes `envoyee`, `attente_registre`, `en_attente` : transitions
d'EX-8.12), `ots-mise-a-niveau` (soumission, 404 en attente, puis attestation
Bitcoin : `complete`, réexport), `preuve-de-vie` (`countersign_idle` vrai),
`file-pleine` (`max_pending` atteint : points non ancrés, clôture toujours
servie), `prestataire-min-interval` (`min_interval_ms` respecté entre deux
demandes vers le même prestataire).

### 8.11 Vérifications

| Id | Vérification |
|---|---|
| AN-32 | Toute requête réseau est précédée, dans la file, d'une ligne `envoyee` de la demande portant le nonce de la requête : dans chaque trace, l'action `ecrire_file` d'état `envoyee` précède l'action d'envoi de la même demande, et `mettre_a_niveau_ots` suit une ligne `en_attente` (épreuve : couper l'alimentation du processus entre l'écriture et l'envoi n'y laisse jamais une requête sans ligne) |
| AN-33 | Une seule demande par `id` dans l'état courant de la file ; un `demarrage` sur une file donnée produit les transitions d'EX-8.12 et aucune autre |
| AN-34 | Transitions d'état conformes à la table d'EX-8.3 sur chaque trace ; aucun `jeton_periode` dans un état final autre qu'`obtenue` |
| AN-35 | Échéances : pour chaque trace, liste des `D_k`, point sélectionné par échéance (premier point de `checkpoint_ts ≥ D_k`), une demande par point, `sans_objet` sans nouvel événement par rapport au dernier point contresigné, échéances rendues par une demande refusée, `remplacee` quand l'échéance suivante est satisfaite d'abord (EX-4.3, EX-4.4, EX-8.4) |
| AN-36 | Ordre des ancres d'EX-8.4 : `jeton_periode` ne part qu'après `inclusion_registre` de son ancre ; `jeton_point` part au plus `squat_wait_s` après son admission, avec `ordre_ancres_non_respecte` si l'ancre n'est pas incluse |
| AN-37 | Attente de reprise conforme à EX-8.9 (table des cas : `Retry-After`, 408, suite 5 s, 10 s, 20 s, …, 300 s avec gigue injectée) |
| AN-38 | Relève conforme à EX-8.8 : instant de la relève, tentatives parallèles, arrêt de l'autre prestataire à la première promotion, réponse tardive conservée non promue |
| AN-39 | File et priorité : `jeton_periode` servi avant `jeton_point` à égalité d'échéance ; `min_interval_ms` respecté toutes demandes confondues (EX-8.7) |
| AN-40 | Registre : capture avant `obtenue` ; `empreinte_squattee` → `refusee` sans nouvel essai ; `inclusion_late` au-delà de `inclusion_alert_s` (EX-8.10) |
| AN-41 | OpenTimestamps : `en_attente` dès `min_responses` réponses, mise à niveau à `first_after_s` puis `interval_s` (≥ 60 s), `complete` à la première attestation Bitcoin, réexport demandé, `ots_give_up` au-delà de `give_up_after_s` (EX-8.11) |
| AN-42 | Chaque trace de la famille `planification/` rejouée rend `expected` et `queue_after` à l'identique (référence et vérificateur Go) |
| AN-43 | Aucune ligne du journal d'exploitation ni de la file ne contient un jeton, une pièce, un secret ou une adresse de compte |

## 9. Ancre des points au registre

### 9.1 Ce qui est ancré

**EX-9.1** Un point de contrôle est ancré par `AttestationRegistry.anchor`
avec l'empreinte `fingerprint = keccak256(org_id ‖ journal_id ‖
checkpointHash)` (96 octets, même construction que `anchorFingerprint` de la
période, CT-1 §10.4 et §10.6) et le `docType` du libellé
`noortrace/point-de-controle/v0`, soit
`0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178`
(CT-1 annexe B), que CT-4 §6.4 inscrit dans sa table en révision 0.3 par la
voie de son EX-6.6 (un libellé nouveau, jamais un sens nouveau sous un libellé
ancien). L'émetteur est la clé de chaîne sous laquelle la clé Ed25519 qui a
signé le point est inscrite (CT-6 N-4, R-10). Exemple : le point `K2` de
l'exemple de référence de CT-1 a pour empreinte
`0x7f721a4526c614882ff41ac33792c6d05fa7fb6dd98bc1c369d0e277029f4e44`
(CT-1 annexe B) ; les points `K1`, `K3` et `K4` ont pour empreintes
`0xd0cd916d070ecb8c2af3a3b62b933ccd6e61fd481ea2b70312ab988fabac8540`,
`0xa1aeb874daa988a4833c394476c4ea740096a3496ed081ae6f8592fb4912a837` et
`0xa7f0a30f11f724f5ae4bd7ba952079fa513dfe0ed70c051bdfc5bbe9c67b3792`
(calculs de cette spécification, annexe A.2).

**EX-9.2** L'ancre d'un point se distingue de l'ancre d'une période par son
seul `docType` : la vérification R-9 de CT-6 n'admet que le `docType` de
période (CT-4 EX-6.6) et reste inchangée ; CT-6 révision 0.2 vérifie l'ancre
d'un point par une vérification à part, R-11, sur la seule entrée de rôle
`ancre_point_de_controle` de `registre.json` (CT-6 §11.9, EX-11.24), et K-8
compare la référence `anchors.registry` de la partie à l'empreinte et au
`docType` recalculés et au contrat du fichier d'ancres (CT-6 EX-11.25 ;
section 10). Un point n'est jamais ancré sous le `docType` de période, ni une
période sous celui du point.

### 9.2 Quels points, quand, dans quel ordre

**EX-9.3** Les points ancrés sont ceux que `registry.checkpoints` désigne
(EX-4.6) : `nouveaux_evenements` (défaut) : tout point admis dont `tree_size`
dépasse celui du dernier point de la même période déjà ancré (ou dont
`tree_size ≥ 1` s'il n'y en a pas encore) ; `tous` : chaque point, preuves de
vie comprises ; `aucun` : hors production seulement (EX-4.9). L'ancre est
envoyée **dès l'admission du point**, sans attendre l'échéance de
contresignature : elle fixe l'ordre, et son coût en gaz est connu (9.3).
L'envoi suit CT-4 §8.6 (EX-8.13 à EX-8.17 : type 2, 1 wei, mêmes octets à au
moins deux validateurs d'opérateurs distincts en production, reprise par
`capturer --envoi`), et sa capture suit CT-4 §9.4 (CP-1 à CP-6),
immédiatement après le reçu : tout point ancré peut devenir le point couvrant
d'un dossier (CT-1 §11.2), donc toute ancre de point est une transaction « que
le dossier prouvera » au sens de CT-4 EX-9.2.

**EX-9.4** Une seule transaction par expéditeur et par bloc (CT-4 EX-4.14) :
le planificateur sérialise les envois d'une même clé de chaîne ; un point
admis alors qu'une ancre de la même clé attend son reçu reste `a_envoyer`,
programmé (action `programmer`, raison `attente_nonce`, 8.10), et part dès le
reçu. À la
cadence par défaut (un point par minute, un bloc par seconde environ, CT-4
§9.5), la file de transactions d'un journal ne dépasse pas une ancre en
attente en régime normal ; l'ancre de la période ne part qu'après le reçu de
l'ancre du point de clôture de la même clé.

**EX-9.5** Rattrapage. Quand le registre redevient joignable après une
indisponibilité, les demandes `ancre_registre_point` encore `a_envoyer` d'une
même période ne sont pas toutes envoyées : seule celle du point admis le plus
récent part, les autres passent `remplacee` avec `replaced_by` (section 8).
Motif : un point plus récent engage, par sa racine, tous les événements des
points antérieurs (préfixe, CT-1 §10.7), et l'ordre au registre est celui de
l'inclusion, que des ancres tardives ne changeraient pas ; c'est le pendant,
pour l'ordre, de l'absence de rattrapage des points d'EX-4.4. Les ancres déjà
**envoyées** suivent la reprise de CT-4 §8.6 (renvoi des mêmes octets, puis
remplacement au même nonce), jamais un abandon : un nonce n'est jamais employé
pour un autre contenu. L'ancre d'une période n'est jamais remplacée (EX-4.5).

**EX-9.6** Ordre vis-à-vis des autres ancres du même point (EX-4.7, CT-4
§8.3). L'ancre du registre part d'abord ; la requête RFC 3161 du point attend
son inclusion **au plus** `registry.squat_wait_s` (défaut 5 s), puis part
quand même avec la ligne `ordre_ancres_non_respecte` dans le journal
d'exploitation et le risque de CT-4 §8.3 consigné pour ce point (section 8,
EX-8.4). Pour un point, le préjudice d'un squat est limité à la vérification
K-8 de ce point (le jeton date toujours le point) : une attente de quelques
secondes suffit, et une attente plus longue allongerait `d_jeton`. Pour la
période, CT-4 EX-8.4 reste un DOIT sans borne (EX-8.4).

**EX-9.7** `empreinte_squattee` sur un point (CT-4 OP-9, EX-8.6) : aucun
nouvel essai pour ce point ; la demande passe `refusee`, l'incident est
consigné avec `lookup(empreinte)` et le bloc de l'ancre étrangère, l'alerte est
critique, et les points suivants continuent d'être ancrés. Le point garde son
jeton RFC 3161 ; un dossier qui le choisit comme point couvrant porte
`registry: null`.

### 9.3 Coût en gaz et provision

Le gaz d'`anchor` ne dépend que des octets nuls des 196 octets de données
d'appel (CT-4 §4.5 : 43 octets nuls incompressibles, 96 977 au plus, 12 gaz
de moins par octet nul de l'empreinte, de l'adresse de l'émetteur, de `r` ou
de `s`). Le `docType` du point n'a **aucun octet nul**, comme celui de la
période (comptage de cette spécification, annexe B.3 ; 4.3) : la borne de
96 977 gaz par ancre vaut pour un point comme pour une période. Le nombre
d'ancres par heure et par journal est au plus `2 + 3600 / c_K` (62 par
défaut : `1 + 3600 / c_K` points et le manifeste) plus une clôture (4.3).

**EX-9.8** La provision de la clé de chaîne est celle que 4.3 calcule avec le
gaz de référence de CT-4 EX-4.19 : `b = 24 × (62 × 100 000 + 350 000) =
157 200 000` wei par jour et par journal, `P = 30 × b + 3 000 000 =
4 719 000 000` wei (4,719 × 10⁻⁹ NUR) ; la borne de consommation d'une clé
compromise (CT-4 EX-4.20) passe de 327 000 000 à 4 719 000 000 gaz, soit 281
transactions au plafond de 2^24 ou environ 157 blocs pleins de 30 000 000
gaz, toujours à une transaction par bloc au plus. Une révision suivante de
CT-4 (après la 0.3) met à jour l'exemple d'EX-4.19 et la ligne « Débit d'une
clé » de sa section 12 (« deux opérations par période et par journal »
devient « au plus 63 par période et par journal à la cadence par défaut » :
62 `anchor` et un `submitPeriod`) ; CT-4 0.3 en porte la note (section 14).

**EX-9.9** Capture. Chaque ancre de point capturée pèse un en-tête, tous les
reçus de son bloc et un certificat de commit (environ 7,5 Ko par certificat
d'un bloc d'une transaction, CT-4 §9.7) : à soixante ancres par heure,
l'archive des captures d'un journal croît d'environ 10 Mo par jour (ordre de
grandeur, à mesurer en phase 2, CT-2 §16). La capture est idempotente (CT-4
EX-9.3) et DOIT être faite dans la fenêtre de rétention du validateur (CT-4
§9.5) ; une capture manquée n'arrête pas l'ancrage des points suivants et est
reprise par `capturer --transaction` tant que la fenêtre le permet.

### 9.4 Vérifications

| Id | Vérification |
|---|---|
| AN-44 | `fingerprint` recalculée depuis `org_id`, `journal_id` et `checkpointHash` du point (CT-1 §10.6) égale celle des données d'appel ; non nulle |
| AN-45 | `docType` des données d'appel égal à `0x72c4…2178` pour un point, à `0x2970…71ee` pour une période ; jamais l'un pour l'autre |
| AN-46 | Émetteur de l'ancre = clé de chaîne sous laquelle `key_id` du point est inscrite (`recorderOf`, CT-4 OP-9) |
| AN-47 | Transaction conforme à CT-4 RG-15 (type 2, `chainId`, 1 wei, limite `gas_limit`) ; `gasUsed ≤ 96 977` |
| AN-48 | Index de capture conforme à `operations-registre-v0` avec le rôle `ancre` et CP-2 à CP-6 réussies, écrit avant que la demande passe `obtenue` (section 8) |
| AN-49 | Après un rattrapage, exactement une ancre envoyée pour le dernier point admis de la période, et les demandes antérieures non envoyées en `remplacee` avec `replaced_by` (trace `registre-indisponible-cloture`, annexe A : deux points admis pendant l'indisponibilité, la première ancre passe `remplacee`) ; aucune ancre de période remplacée |

### 9.5 Ce que CT-4 ajoute (révision 0.3)

La révision 0.3 de CT-4, écrite avec ce lot et textuelle, applique les deux
premières lignes de la table (table des `docType` de §6.4, EX-6.6, section 0
de CT-4) ; les autres lignes sont attendues d'une révision suivante et du lot
de code (section 14).

| Emplacement de CT-4 | Ajout |
|---|---|
| §6.4, table des `docType` | ligne `noortrace/point-de-controle/v0` = `0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178`, usage « ancre d'un point de contrôle (CT-1 §10.6, CT-5 §9) », depuis la révision 0.3 |
| §6.9 RG-3 et vecteurs `doctypes.json` | le nouveau libellé, admis, avec sa valeur |
| EX-6.6 | « toute ancre […] porte `docType` de période » devient « de période pour une période, de point de contrôle pour un point » |
| EX-4.19, table et exemple | nombre d'`anchor` par jour : `24 × 62` à la cadence par défaut (ancres de périodes comprises) ; exemple recalculé (EX-9.8, 4.3) |
| §12, ligne « Débit d'une clé » | « au plus 63 opérations par période et par journal » |
| §9.4, EX-9.2 | « `anchor` » couvre les ancres de points |
| `scripts/lib/noortrace.mjs`, `scripts/lib/registre.mjs`, `scripts/lib/conventions-registre.mjs` | constante `DOC_TYPE_POINT_DE_CONTROLE` ; l'outil de référence `ancrer` accepte `--point <fichier du point>` et dérive l'empreinte du `checkpointHash` |

Aucun contrat ne change : `AttestationRegistry.anchor` prend déjà un
`docType` libre (CT-4 EX-6.6).

## 10. Ce qui est remis à l'exportateur et au réviseur

### 10.1 À l'exportateur, pour le dossier

L'exportateur assemble le dossier de CT-1 §11 (treize parties au plus) et ses
entrées à part (CT-6 §4.3). Il lit, pour la période d'un événement, le
répertoire d'ancres d'EX-5.14 (`<root>/<org_id>/<journal_id>/ancres/periode-
<period_start>/` : requêtes, réponses et jetons `rfc3161/`, preuves `ots/`,
`entetes-bitcoin.json`, `acquisitions.ndjson`), la série des points de la
période écrite par l'enregistreur (CT-1 §15 ; proposition pour CT-2 §12.1 en
section 14 : `points/periode-<period_start>.ndjson`, un point signé par
ligne) et les index de capture des ancres au registre (CT-4 §9.4). Il ne lit
pas la file d'attente : `acquisitions.ndjson` suffit, et c'est son champ
`promoted` qui dit quel jeton remettre (EX-5.8, EX-5.13).

**EX-10.1** Parties de la période (inchangées) : `jeton-rfc3161.der` est la
copie octet pour octet du fichier `.der` du jeton **promu** du manifeste
(EX-5.14 ; CT-6 EX-13.3), `preuve.ots` la dernière version de la preuve du
manifeste (EX-6.10), les trois parties du registre celles de CT-4 §9.6 ;
`entetes-bitcoin.json` est placé à côté du dossier, hors des parties (EX-6.8,
EX-6.10, CT-6 EX-13.7).

**EX-10.2** Choix du point couvrant (révision 0.2). Pour un événement
d'indice de feuille `i` (`chemin.leaf_index`), l'exportateur prend, parmi les
points de la série de la période de `tree_size > i`, dans cet ordre de
préférence : (1) un point qui porte un jeton RFC 3161 promu
(`acquisitions.ndjson`) ; (2) à défaut, un point qui porte une preuve `.ots`
complète ; (3) à défaut, un point dont l'ancre au registre est capturée
(index de capture) ; (4) à défaut, un point sans ancre (la partie reste utile
par sa preuve de cohérence, K-1 à K-6). À rang égal, il prend le plus petit
`tree_size`, puis, à `tree_size` égal, le premier point de la série (plus
petit `checkpoint_ts`). À défaut de tout point (la période n'a pas de point
admis après `i`), la partie est déclarée absente avec la raison « aucun point
de contrôle » (CT-1 §11.1). C'est la règle de CT-1 §11.2 et de CT-6 EX-13.18
(`choisirPointCouvrant` de `journal.mjs`, qui reçoit les ancres). Motif : sous
`nouveaux_evenements`, le premier point qui engage un événement est ancré au
registre seul, et le point contresigné à l'échéance suivante, de même
`tree_size`, ne l'est pas (EX-4.6) ; choisir le premier point ôterait au
dossier sa clause jeton et sa borne datée (CT-6 §7.9). Ainsi, pour seq 7 de la
période 1 des vecteurs de CT-1 (`leaf_index` 6), le point retenu est celui de
09:35, contresigné à `D_7`, et non celui de 09:32, ancré au registre seul
(AN-51 ; dossier CT-6 `valide-point-de-controle-point-contresigne`).
L'exportateur ne choisit jamais entre deux jetons d'un même point : le jeton
promu est fixé par EX-5.8.

**EX-10.3** Construction de la partie `points-de-controle.json` (CT-1 §11.2) :
le point, `checkpoint_hash` recalculé (CT-1 §10.6), la preuve de cohérence
`PROOF(tree_size, D[count])` recalculée depuis les feuilles de la période
(CT-1 §10.7, `preuveCoherenceDossier` de `journal.mjs`), et les trois ancres :
`anchors.rfc3161.token` = base64 canonique du fichier `.der` du jeton promu
du point, `anchors.ots.proof` = base64 canonique de la dernière version du
fichier `.ots` du point (EX-6.10), `anchors.registry` = `chain_id` (identifiant
EVM, que CT-6 rapporte sans le comparer, EX-11.25), `contract`, `fingerprint`
(9.1), `doc_type`, `block_number`, `block_hash`, `transaction_hash`, `log_index`
lus dans l'index de capture de l'ancre du point (CT-4 §9.4) ; chaque ancre
absente vaut `null`. Un jeton du serveur interne est embarqué comme un autre :
c'est le fichier d'ancres du réviseur qui dit qu'il n'est pas qualifié (EX-7.2),
et l'énoncé de CT-6 nomme l'autorité par le libellé du réviseur (CT-6 EX-9.20).

**EX-10.4** Quand le point couvrant porte une ancre au registre, l'exportateur
ajoute à `registre.json` l'entrée de rôle `ancre_point_de_controle` construite
depuis la capture de cette ancre (CT-4 EX-9.8, `entreeRegistre`), et à
`certificat-commit.json` le certificat de son bloc, dans la limite d'entrées du
schéma `registre-v0` étendu par CT-6 révision 0.2 (une entrée de ce rôle au
plus, 17 entrées au plus ; CT-6 EX-11.23). Avec cette entrée, R-11 prouve
l'inclusion de l'ancre du point (CT-6 EX-11.24) et l'énoncé reçoit sa clause
registre ; sans elle, la référence `registry` est déclarative : K-8 peut
réussir, l'énoncé ne porte pas la clause registre et CT-6 lève AV-K-1 (CT-6
EX-11.25).

**EX-10.5** Réexport. Une période dont la preuve OpenTimestamps passe de
`en_attente` à `complete` (EX-6.7) déclenche le réexport des dossiers déjà
produits pour cette période, comme CT-6 EX-13.6 l'exige ; de même quand un
point obtient une ancre après l'export (jeton de relève promu plus tard, ancre
de registre capturée après coup, preuve de point complète). L'exportateur ne
modifie jamais un dossier remis : il en produit un nouveau, dont
`generated_at` est postérieur, et consigne le réexport.

### 10.2 Au réviseur

Le réviseur prépare son fichier d'ancres (CT-6 §12) seul ; CT-5 ne le lui
écrit pas (CT-6 EX-12.1 : rien du dossier ni de l'exportateur n'est une
ancre). CT-5 publie, hors des dossiers, ce qui lui permet de le préparer et de
le recouper :

| Pièce publiée | Contenu | Usage par le réviseur |
|---|---|---|
| Fiche de prestataire | pour chaque prestataire configuré : `id`, `role`, `url`, `policy_oid` et `accepted_policies`, les `anchor_certificates` en PEM avec leurs SHA-256, l'instantané `qualified` d'EX-5.9 (cadre, type de service, statut, territoire, numéro de séquence, date d'émission et URL de la liste de confiance, ou attestation ZertES, `source` avec la date de lecture), l'adresse de la CRL ou de l'OCSP ; pour le serveur interne : la mention « non qualifié » et la politique privée ; le résultat daté de l'épreuve d'EX-11.4 | `tsa_authorities[]` de son fichier d'ancres, qu'il recoupe sur la liste de confiance lui-même (R1-F43 : « A Relying Party is expected to use a Trusted List ») ; `qualified` n'est renseigné que par lui (CT-6 §12.5, T-11) |
| Captures de révocation | CRL (ou réponses OCSP) de chaque certificat du chemin de chaque jeton promu, émises après `genTime`, avec source et instant de capture (EX-5.10, étape 10 ; CT-6 EX-13.12) | `revocation.crls[]`, `revocation.statements[]` |
| Fichier d'en-têtes Bitcoin | EX-6.8 | `--entetes-bitcoin`, ou son propre fichier depuis son nœud (CT-6 §12.5) |
| Série des points et acquisitions | `points/periode-<period_start>.ndjson` et `acquisitions.ndjson` de chaque période (sans secret, EX-5.13) | contrôles de série que le dossier ne fait pas (CT-1 §10.9 : chaînage, monotonie, cadence, échéances satisfaites, `d_jeton`, `d_registre`) ; `ancrage.mjs` les exécute (AN-2, AN-3) et imprime les fenêtres observées ; avec les journaux `Anchored` du registre, contrôle de complétude (EX-10.7, AN-61) |
| Manifeste d'instance et jeux de validateurs | ceux de CT-4 §4.8 et §9.7 (CT-6 EX-13.11) | `registry` de son fichier d'ancres |

**EX-10.6** La fiche de prestataire est un document JSON
(`prestataire-<id>.json`) dont la forme est celle de l'élément `providers[]`
d'`ancrage-v0` **privé de `auth`**, complété des SHA-256 des certificats et
du résultat de l'épreuve d'EX-11.4 ; elle ne contient ni identifiant de
compte, ni secret, ni prix. L'exploitant la republie à chaque changement de
`qualified` (EX-5.9) ou de certificat. Quand le prestataire des points est de
rôle `interne` ou `second_rang` non qualifié, la fiche porte la mention que la
cible de 3.3 (`W_date`) n'est pas tenue face à l'opérateur (EX-4.10, EX-7.3).

**EX-10.7** (révision 0.2) Complétude au registre (AN-61). Pour une période
et un journal, toute ancre `Anchored` de `docType` point de contrôle émise par
une clé de chaîne du journal entre le premier bloc de la période et le bloc
de l'ancre de la période DOIT avoir pour empreinte `keccak256(org_id ‖
journal_id ‖ checkpointHash)` d'un point de la série publiée de la période ou
de celle de la période suivante ; une ancre qui n'en a pas est **orpheline**
(signe d'une série réécrite et ancrée à part, 3.3). La série de la période
suivante est requise quand elle existe : son premier point qui engage un
événement peut être ancré avant l'ancre de la période, qui attend le reçu de
l'ancre du point de clôture (EX-9.4), donc dans la même fenêtre de blocs ;
sans elle, cette ancre paraîtrait orpheline (cas
`periode-suivante-non-servie`). Dans chaque série (les points d'une période
d'un journal), l'ordre des blocs (puis des `log_index`) des ancres rattachées
DOIT suivre l'ordre des `checkpoint_ts` de leurs points ; une inversion est
signalée `hors_ordre`. Les séries ne sont pas confrontées entre elles. Le contrôle est un contrôle de série, hors dossier :
`verifierCompletudeRegistre` d'`ancrage.mjs` le fait à partir des journaux
capturés (`journals`, une entrée par série, `anchors`, `issuers`,
`from_block`, `to_block`) et rend
`{ complete, orphans, out_of_order, attached }` (famille `completude` des
vecteurs, annexe A.4). `from_block` et `to_block` sont des entrées de
l'appelant ; elles s'établissent par l'ordre du registre, jamais par l'heure
des blocs (3.2), comme la référence les lit : `from_block`, exclu, est le bloc
de l'ancre de la période précédente du même journal ; `to_block`, inclus, le
bloc de l'ancre de la période (l'ancre d'une période part après le reçu de
l'ancre de son point de clôture, EX-9.4). Le contrôle ne révèle une série
concurrente qu'à l'intérieur de la fenêtre ainsi fixée.

### 10.3 Vérifications

| Id | Vérification |
|---|---|
| AN-50 | `jeton-rfc3161.der`, `preuve.ots`, `rfc3161.token` et `ots.proof` du dossier égalent octet pour octet (après décodage base64 canonique) les fichiers promus du répertoire d'ancres désignés par `acquisitions.ndjson` |
| AN-51 | Point couvrant choisi selon EX-10.2 pour chaque dossier des vecteurs ; la partie produite passe K-1 à K-6 de CT-1 §11.4 et, avec le fichier d'ancres de test, K-7 à K-9 selon ses ancres |
| AN-52 | `registry` de la partie égale, champ pour champ, l'index de capture de l'ancre du point ; `registre.json` porte l'entrée `ancre_point_de_controle` quand la capture existe, et `certificat-commit.json` le certificat de son bloc |
| AN-53 | Réexport déclenché par `en_attente → complete` et par toute ancre obtenue après l'export ; le dossier antérieur est conservé et le nouveau a un `generated_at` postérieur |
| AN-54 | Fiche de prestataire : forme d'EX-10.6, certificats PEM dont les SHA-256 égalent ceux déclarés, aucune clé `auth`, `secret`, `price`, `account` ni `password` |
| AN-61 | (révision 0.2) Complétude au registre d'EX-10.7 : aucune ancre de point orpheline émise par la clé de chaîne du journal dans la fenêtre de blocs de la période, séries de la période et de la période suivante servies, et, dans chaque série, ordre des blocs conforme à celui des `checkpoint_ts` ; chaque cas de `completude/` reproduit (`complete`, `orphans`, `out_of_order`, `attached`) |

## 11. Prestataires

### 11.1 Ce que « qualifié » veut dire ici

**EX-11.1** « Qualifié » a le sens mesurable d'EX-5.9 : un service de type
`http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST` au statut `granted` d'une liste
de confiance nationale référencée par la liste des listes de l'Union
européenne (R1-F48), identité numérique recoupée avec les `anchor_certificates`,
territoire, numéro de séquence, date d'émission et URL de la liste consignés
(eIDAS) ; ou, pour la Suisse, le service reconnu dans la liste de confiance
suisse au titre de la loi fédérale sur la signature électronique (ZertES ; CT-6
§12.5, `trusted_list.territory = "CH"`), l'attestation de l'organisme de
reconnaissance étant conservée hors du dépôt public (R1-F28) ; la note R1
n'ayant pas obtenu cette liste (NV-5), EX-5.9 ne déclare aucun prestataire
`qualified` au titre de `zertes` avant sa lecture. Ni une
déclaration du prestataire, ni un `qcStatement` (`esi4-qtstStatement-1`,
0.4.0.19422.1.1, R1-F21, R1-F43 ; EN 319 422 non relue, NV-10), ni un OID de
politique ne suffisent (R1-F43 : « A Relying Party is expected to use a
Trusted List to establish whether the TSP and the TSU are Qualified »). La
section 11 ajoute à EX-5.9 ce que la fiche de prestataire publie (EX-10.6) et
l'épreuve d'acceptation d'un jeton (EX-11.4) ; le vérificateur de CT-6 ne
croit, lui, que le `qualified` du fichier d'ancres du réviseur (T-11).

**EX-11.2** La configuration porte exactement un `principal` qualifié et
DEVRAIT porter un `secours` qualifié d'un **autre exploitant** (EX-4.9, règle
2 ; EX-4.10) : la panne ou la fin de contrat de l'un ne laisse pas une période
sans jeton qualifié (EX-5.7, EX-8.8). Le prestataire des points PEUT être le
`principal`, un prestataire de second rang (non qualifié mais extérieur : la
fenêtre vis-à-vis de l'opérateur reste bornée), ou le serveur interne
(section 7) ; c'est `rfc3161.checkpoints.provider_role` qui le dit (EX-5.6).

### 11.2 Deux prestataires, d'après leur documentation publique

Les deux prestataires ci-dessous sont ceux dont la documentation publique a
été lue pour cette spécification (note R1, sources en annexe B) : l'un reconnu
en Suisse (ZertES) et qualifié dans l'Union par sa filiale autrichienne,
l'autre qualifié en Autriche avec une interface RFC 3161 nue documentée. Ils
sont nommés comme objets techniques ; aucun prix n'est relevé (R1 : « aucun
prix relevé »), aucun n'est préféré, et la section 12 prend le prix en
paramètre. Tout ce qui n'a pas été lu dans une source primaire est dit « non
vérifié ».

| Contrainte | P1 — Swisscom Trust Services (Swisscom (Schweiz) AG, ZertES ; Swisscom IT Services Finance S.E., Vienne, eIDAS) | P2 — A-Trust GmbH (Autriche, eIDAS) |
|---|---|---|
| Interface publiée | **Aucun point d'accès RFC 3161 nu publié** (NV-1) : le seul point d'accès documenté est l'enveloppe du « All-in Signing Service » (AIS), `https://ais.swisscom.com`, SOAP `/AIS-Server/ws` ou REST `/AIS-Server/rs/v1.0/sign` et `/pending`, qui rend le jeton RFC 3161 encapsulé (`<RFC3161TimeStampToken>`, type `urn:ietf:rfc:3161`) dans une réponse OASIS DSS (R1-F30, R1-F32) ; le client envoie un condensé, pas une `TimeStampReq` (R1-F32) | HTTP POST du corps DER avec `Content-Type: application/timestamp-query`, réponse `application/timestamp-reply` ; variantes GET documentées, non employées (R1-F35, R1-F36) ; production `https://timestamp.a-trust.at/`, test `https://hs-abnahme.a-trust.at/timestamp/` (R1-F36) |
| Authentification | AIS : certificat client TLS (seul le certificat d'entité finale est envoyé, chaîne refusée ; EKU « Client Authentication »), identités revendiquées par fournisseur d'application (R1-F31) ; la politique d'horodatage cite aussi « Basic Authentication über SSL/TLS » pour l'AIS (R1-F24) | HTTP Basic (R1-F35, R1-F36) ; identifiants de test publics `test / test`, `testEcdsa / test` sur le système de test (R1-F37) |
| Algorithmes de condensé | SHA-256, SHA-384, SHA-512 (politique d'horodatage, R1-F20 ; AIS, R1-F32) | SHA-224, SHA-256, SHA-384, SHA-512, SHA3-224 à SHA3-512 ; RIPEMD-160 et RIPEMD-256 à l'interface (R1-F35, R1-F36) ; la politique de certification ne nomme que `sha224, sha256, sha384, sha512, sha3-224` (R1-F38) ; CT-5 n'envoie que SHA-256 (section 5) |
| Politique (`reqPolicy`) | `2.16.756.1.83.100.4.5` (politique d'horodatage Autriche, version 3.3 du 10.10.2023, R1-F17, R1-F20), facultative dans la requête, reprise dans le jeton (R1-F21) ; conformité déclarée ETSI EN 319 401 et EN 319 421 (R1-F17) | `1.2.40.0.17.1.26` (a.sign premium timestamp, CP 1.0.4 du 14.12.2022), « in Übereinstimmung mit ETSI EN 319 421 [0.4.0.2023.1.1] » (R1-F38) ; identifiant inséré dans les jetons de production : non vérifié (NV-6) |
| Nonce, `certReq` | Décrits comme facultatifs par la politique d'horodatage (R1-F20) ; **non exposés par l'AIS**, qui prend un condensé (NV-4) : via l'AIS, la fraîcheur par le nonce n'est pas mesurable (EX-5.16) | Requête RFC 3161 complète : le nonce et `certReq` sont ceux de la requête ; l'exemple officiel emploie `-no_nonce` et la prise en charge du nonce en production n'est pas confirmée par la documentation (NV-6) ; le client de CT-5 l'envoie et rejette une réponse qui ne le reprend pas (EX-5.10, étape 4) |
| Exactitude, source de temps | 500 ms par rapport à UTC ; au-delà, alarme et arrêt automatique du service jusqu'à recalibrage (R1-F19) ; `accuracy` 500 ms dans le jeton (R1-F21) | au plus 1 s par rapport à UTC ; au-delà, aucun jeton émis et incident journalisé (R1-F38) |
| Clés et certificats | TSU RSA 3072 SHA-256, validité au plus 3 ans, une seule clé active par unité ; émetteur « CN=Swisscom TSU 4.1, O=Swisscom IT Services Finance S.E., C=AT » ; certificats publiés au dépôt défini par le CP/CPS (URL non lue, NV-5) ; OCSP indiqué dans le certificat ; `QCStatement` 0.4.0.19422.1.1 ; `signingCertificate` ESSCertID (R1-F18, R1-F21, R1-F22) | unités « a-sign-premium-timestamping-07 », « -09 », « -10 » (sujets sur la liste de confiance, R1-F39) ; clés RSA et ECDSA sur le système de test (R1-F37) ; fichier d'AC fourni avec l'exemple officiel (`ATrustCaFile.pem`, R1-F37) |
| Qualification constatée | eIDAS : liste de confiance AT (`https://www.signatur.rtr.at/vertrauensliste.xml`, séquence 75, 2026-06-15), prestataire « Swisscom IT Services Finance S.E. », service QTST « Swisscom TSS CA 4.1 », `granted` depuis 2021-01-07 (R1-F26) ; ZertES : certificat KPMG n° 272/2025 du 31.10.2025 pour Swisscom (Schweiz) AG, horodatages qualifiés, ETSI EN 319 421 (2023-05) et EN 319 422, valable jusqu'au 04.11.2028, audits annuels (R1-F28) ; la politique ZertES (version 1.3) précise que l'horodatage ZertES est produit via la filiale autrichienne (R1-F25) | eIDAS : liste de confiance AT, prestataire « A-Trust GmbH », trois services QTST `granted` (depuis 2022-08-11, 2023-08-27, 2025-09-15) (R1-F39) ; statut du certificat de conformité après le 04.02.2026 : non vérifié (NV-6) |
| Disponibilité | « 7x24h » hors interruptions planifiées, absence de base de temps, force majeure ; aucun pourcentage (R1-F23) | aucun engagement chiffré lu (NV-6) |
| Limites de débit, volumes | AIS : 1500 sessions simultanées, lots de 300 documents, résultat asynchrone à relever sous 15 min ; aucune limite par horodatage publiée (R1-F30, R1-F33 ; NV-3) | aucune limite publiée (NV-6) ; CT-5 applique `min_interval_ms` configuré (EX-5.5) |
| Codes d'erreur | AIS : `Pending`, `RequesterError`, `ResponderError`, `SubsystemError` ; `CantServeTimely` (surcharge), `TimestampError`, `UnsupportedDigestAlgorithm`, `AuthenticationFailed`, `ServiceInactive`, `GeneralError` ; « list may not be complete » ; aucun délai de reprise recommandé (R1-F34, R1-F73) | aucun code HTTP documenté hors `200` (R1-F36, NV-6) ; les `PKIStatus` et `PKIFailureInfo` de la RFC s'appliquent (R1-F6, R1-F7) |
| Modèle contractuel | non vérifié (NV-2) | abonnement facturé d'avance, durée minimale, tarifs par liste de prix ; « par jeton » non établi (R1-F40) ; aucun prix relevé |
| Ce qui n'est pas vérifié | NV-1 (point d'accès RFC 3161 nu), NV-2 (modèle tarifaire), NV-3 (limites par horodatage), NV-4 (nonce et `certReq` via AIS), NV-5 (TP postérieure à 3.3, URL du dépôt des certificats, liste SAS) | NV-6 (CPS 1.0.4 inaccessible, nonce en production, codes HTTP, limites, disponibilité, OID inséré, statut de conformité après le 04.02.2026) |

Conséquences pour la configuration :

**EX-11.3** Le client de la section 5 parle RFC 3161 « nu » (POST DER,
EX-5.5). Un prestataire qui n'offre qu'une enveloppe (le cas de P1 dans la
documentation lue, NV-1) ne peut tenir en version 0 ni le rôle `principal` ni
le rôle `secours` (EX-5.16 : la fraîcheur par le nonce et l'égalité de la
requête n'y sont pas mesurables). Son emploi suppose soit un point d'accès
RFC 3161 nu, à établir avec le prestataire (NV-1), soit un **adaptateur**,
proposition de la section 15, qui construirait l'enveloppe, extrairait le
`TimeStampToken` DER sans le réencoder (CT-6 EX-13.3), rapporterait au
planificateur une classe d'EX-5.12 (`CantServeTimely` → transitoire ;
`UnsupportedDigestAlgorithm`, `AuthenticationFailed` → permanente ;
`ServiceInactive`, `GeneralError` → transitoire avec alerte) et marquerait la
tentative `fraicheur: horloge_locale` (EX-5.16). Conséquence, en version
0 : des deux prestataires documentés, seul P2 est utilisable comme
`principal` ou `secours`, et aucun `secours` documenté ne l'est encore : ceux
d'EX-11.5 restent à établir (NV-7, NV-8) ; un `secours` utilisable suppose de
lever NV-1 pour P1 ou NV-7 pour le prestataire polonais, et la levée de NV-6
pour P2 (nonce en production, OID inséré) est un préalable à la porte 1.
Les garanties de panne avec relève (`d_relève ≤ fallback_after_s`, 120 s pour
les points ; clôture qualifiée maintenue) supposent un `secours` qui remplit
cette condition ; tant qu'il n'en existe pas, c'est le régime « sans secours »
qui s'applique (EX-5.7, section 13) : jetons de points clos `remplacee`,
clôture réessayée sans fin, `W_date` qui se dégrade vers `n × 3600 s + d`.
Tant que NV-6 n'est pas levé, la fraîcheur par le nonce chez P2 n'est pas
confirmée. L'exemple de 4.4 ne montre que la forme : ses points d'accès sont
fictifs, et la liste citée pour son `principal` (AT, séquence 75, R1-F26) est
lue sur l'inscription de P1, qui ne peut tenir ni le rôle `principal` ni le
rôle `secours` en version 0 (la même séquence porte aussi les services de P2,
R1-F39).

**EX-11.4** Avant la mise en service d'un prestataire, l'exploitant exécute
l'épreuve d'acceptation d'un jeton : une requête d'EX-5.1 sur une empreinte
de test, la réponse vérifiée par EX-5.10 (nonce repris, T-1 à T-10 avec les
`anchor_certificates` et `accepted_policies` du prestataire), `openssl ts
-verify -queryfile` « Verification: OK », et le certificat de l'unité retrouvé
dans la liste de confiance ou l'attestation (EX-5.9) ; sur le système de test de
P2, les jetons « cannot be validated » (certificat de test, R1-F37) : l'épreuve
n'y vaut que pour l'interface, pas pour la qualification. Le résultat et la date
vont dans la fiche de prestataire.

**EX-11.5** Autres prestataires qualifiés lus dans la note R1, utilisables
comme `secours` après la même épreuve : un prestataire polonais à point
d'accès `https://qts.certum.pl/default/basic`, HTTP Basic (guide 2020,
R1-F41 ; QTST `granted` sur la liste PL, R1-F42 ; détails techniques actuels
non vérifiés, NV-7) ; un prestataire néerlandais dont la déclaration TSA
annonce la prise en charge de `reqPolicy`, du nonce et de `certReq`, SHA-256
à SHA-512, ± 1 s, et renvoie à la liste de confiance pour la qualification
(R1-F43, R1-F44 ; unités QTST `granted` sur la liste NL, R1-F45 ; noms d'hôte
non publiés, NV-8) ; un prestataire allemand dont la fiche produit annonce
RFC 3161 et un certificat d'accès individuel sans documentation technique
publique (R1-F46 ; QTST `granted` sur la liste DE, R1-F47 ; NV-9). Les textes
ETSI EN 319 421 et 319 422 n'ont pas été lus (NV-10).

### 11.3 Serveur interne

Le serveur interne (section 7) figure dans la configuration avec le rôle
`interne`, `qualified: null`, sa politique privée dans `policy_oid` et
`accepted_policies`, son URL (locale en `http://`, ou TLS) et `auth` (EX-4.8,
EX-4.9) ; il n'a ni liste de confiance ni contrat. Ses contraintes mesurables
sont AN-22 à AN-31.

### 11.4 Vérifications

| Id | Vérification |
|---|---|
| AN-55 | Le `principal` et, s'il existe, le `secours` ont `qualified` non nul, conforme à `$defs/qualification` d'`ancrage-v0`, avec un statut `granted` (ou reconnu, ZertES) et une liste de confiance nommée (`trusted_list` ; pour `zertes`, l'attestation de reconnaissance en plus dans `source`, EX-5.9) ; aucun prestataire de rôle `interne` ne porte ces rôles (EX-7.1, EX-4.9) |
| AN-56 | Le `principal` et le `secours` sont d'exploitants distincts (EX-11.2 ; `source` de chacun le dit) |
| AN-57 | La fiche de prestataire porte le résultat de l'épreuve d'EX-11.4, daté, avec le SHA-256 du certificat de l'unité retrouvé sur la liste ou l'attestation |
| AN-58 | `min_interval_ms` configuré respecté : deux requêtes consécutives au même prestataire espacées d'au moins cette durée, toutes demandes confondues (EX-5.5, EX-8.7 ; trace `prestataire-min-interval`, annexe A) |

## 12. Coût

### 12.1 Ce qui coûte et ce qui ne coûte pas

Trois postes : les jetons RFC 3161 (achetés à un prestataire, au jeton ou au
forfait : la seule forme contractuelle lue est un abonnement facturé d'avance
avec durée minimale, R1-F40 ; aucun prix n'est relevé, NV-2, NV-6, et aucun
prix ne figure dans ce dépôt), le gaz du registre (monnaie non échangeable,
coût nominal, CT-4 §4.5) et OpenTimestamps (calendriers publics « free to
use », R1-F57 : coût nul, hors l'infrastructure de la source d'en-têtes
d'EX-6.8). Le stockage et la capture s'ajoutent en ordre de grandeur (12.4).
La formule prend le prix en paramètre ; les devis viennent après la conception.

### 12.2 Formule par journal et par an

Les comptages sont ceux d'EX-4.11 (`compterJetons`). Notations : `N_h` le
nombre d'heures de l'année (8 760, ou 8 784 pour une année bissextile) ;
`c_T` la cadence de contresignature des points
(`rfc3161.checkpoints.interval_s`, défaut 300 ; `n_T = 3600 / c_T` échéances par
heure, la dernière étant la clôture : `n_T − 1` échéances de points, 11 par
défaut) ; `a` la **part des échéances de points dont le point sélectionné engage
au moins un nouvel événement** (0 ≤ a ≤ 1 ; `a = 1` si `countersign_idle` est
vrai, puisque chaque échéance produit alors un jeton ; `a = 1` donne les maxima
de la table de 4.6) ; `c_K` la cadence des points
(`checkpoint_interval_s`, 60) ; `J` le nombre de journaux ; `p_q` le prix
unitaire d'un jeton qualifié, `p_s` celui d'un jeton de second rang (0 pour le
serveur interne) ; `F` un forfait annuel et `Q` le nombre de jetons qualifiés
qu'il comprend (`F = 0` pour un modèle au jeton) ; `r` la part de requêtes
facturées en plus par jeton obtenu (reprises, réponses d'erreur facturées, et
jetons obtenus en double pendant une relève, quand les deux prestataires sont
sollicités en parallèle et qu'un jeton tardif est conservé, EX-5.7 : 0 par
défaut, R1-F73 ne donnant aucune règle de prestataire ; avec `r = 0`, la formule
suppose qu'aucune relève n'est facturée) ; `δ_q = 1` si
`provider_role = principal`, `δ_s = 1` si `provider_role` est `second_rang` ou
`interne`, `δ_r = 1` si `registry.checkpoints ≠ aucun`.

**EX-12.1** Nombres par journal et par an :

```text
N_q  = N_h × (1 + δ_q × (n_T − 1) × a)        jetons qualifiés : la clôture, plus les points si le prestataire des points est le principal
N_s  = N_h × δ_s × (n_T − 1) × a              jetons de second rang ou internes
N_a  ≤ N_h × (1 + δ_r × (1 + 3600 / c_K))     ancres au registre (4.3, paragraphe qui suit EX-4.7 : au plus 2 + 3600 / c_K par heure)
G    ≤ N_a × 96 977 + N_h × 314 256           gaz par an : ancres (9.3) et clôtures (CT-4 §4.5, 314 256 mesurés au plus)
```

`N_h × 314 256` est le gaz de `submitPeriod` seul (CT-4 §4.5 : 234 079 à
314 256 mesurés). L'ancre du manifeste est comptée dans `N_a`, par le terme 1
de `1 + δ_r × (1 + 3600 / c_K)`. Aucun gaz n'est compté deux fois.

**EX-12.2** Coût par journal et par an, puis total :

```text
modèle au jeton      : C_j = p_q × N_q × (1 + r) + p_s × N_s × (1 + r)
forfait avec quota   : C_j = F + p_q × max(0, N_q × (1 + r) − Q) + p_s × N_s × (1 + r)     (Q illimité : le terme p_q disparaît)
total                : C = J × C_j     (un forfait par journal ; un forfait partagé entre journaux se traite avec Q partagé : C = F + p_q × max(0, J × N_q × (1 + r) − Q) + J × p_s × N_s × (1 + r))
gaz                  : G × J wei par an, au prix de 1 wei par gaz (CT-4 EX-4.15) ; 1 NUR = 10^18 wei
OpenTimestamps       : 0
```

Un relecteur qui connaît `p_q` et sa cadence lit le coût annuel de son journal
dans la première ligne : à cadences par défaut et points chez le prestataire
principal, `C_j = p_q × 8 760 × (1 + 11 a)` ; points chez un second rang,
`C_j = 8 760 p_q + 96 360 a p_s` ; points chez le serveur interne, `C_j =
8 760 p_q`.

### 12.3 Exemples numériques, à prix symbolique

Les valeurs sont celles de la famille `cout/` des vecteurs (annexe A.4,
`$defs/cas_cout`), `p` désignant une unité symbolique et jamais un prix ;
`p_q = 1 p`, `p_s = 0,2 p` sauf mention ; `N_h = 8 760`, `c_K = 60`,
`c_T = 300`, `registry.checkpoints = nouveaux_evenements`.

| Cas | Hypothèses | `N_q` | `N_s` | `N_a` (au plus) | `C_j` |
|---|---|---|---|---|---|
| `defaut-second-rang-a1` | points chez un second rang, `a = 1` | 8 760 | 96 360 | 543 120 | 8 760 p + 19 272 p = **28 032 p** |
| `defaut-second-rang-a025` | idem, `a = 0,25` | 8 760 | 24 090 | 543 120 | **13 578 p** |
| `points-chez-principal-a025` | points chez le principal, `a = 0,25` | 32 850 | 0 | 543 120 | **32 850 p** |
| `points-chez-principal-a1-dix-journaux` | points chez le principal, `a = 1`, `J = 10` (maxima de 4.6) | 105 120 | 0 | 543 120 | 105 120 p par journal, **1 051 200 p** au total |
| `serveur-interne` | points chez le serveur interne (`p_s = 0`), `a = 1` | 8 760 | 96 360 | 543 120 | **8 760 p** |
| `forfait-avec-quota` | `F = 10 000 p`, `Q = 10 000`, points chez un second rang, `a = 1` | 8 760 | 96 360 | 543 120 | 10 000 p + 0 + 19 272 p = **29 272 p** |
| `forfait-depasse-points-principal` | `F = 10 000 p`, `Q = 10 000`, points chez le principal, `a = 1` | 105 120 | 0 | 543 120 | 10 000 p + 95 120 p = **105 120 p** |
| `sans-points` | `c_T = 3600`, aucune ancre de point au registre (version antérieure) | 8 760 | 0 | 8 760 | **8 760 p** |
| `preuve-de-vie` | `countersign_idle` vrai, second rang (`a` sans effet) | 8 760 | 96 360 | 543 120 | **28 032 p** |
| `reprises-facturees` | points chez le principal, `a = 0,5`, `r = 0,1` | 56 940 | 0 | 543 120 | 56 940 × 1,1 p = **62 634 p** |
| `cadence-une-minute-principal` | `c_T = 60`, points chez le principal, `a = 1`, `N_h = 8 784` | 527 040 | 0 | 544 608 | **527 040 p** |

Dans les noms des cas, « defaut » veut dire « cadences par défaut », pas
« prestataire par défaut » : par défaut, les points vont au `principal`
(`provider_role = principal`, 4.4), et `C_j = p × 8 760 × (1 + 11 a)`, soit
105 120 p pour `a = 1`. Le cas `serveur-interne` suppose `a = 1` (`N_s =
96 360`) ; son coût, 8 760 p, ne dépend pas de `a`, puisque `p_s = 0`.

Lecture : avec les cadences par défaut, les points de contrôle multiplient
par douze au plus le nombre de jetons d'un journal actif en continu (table de
4.6) ; le choix du prestataire des points (principal, second rang, interne)
est ce qui fixe la facture, et `a` ce qui la module. Le gaz : à cadences par
défaut, `G ≤ 543 120 × 96 977 + 8 760 × 314 256 = 55 423 030 800 ≈ 5,54 ×
10^10` wei par journal et par an, soit 5,54 × 10^-8 NUR ; sans ancre des points,
`G ≤ 3,60 × 10^9` wei.

### 12.4 Stockage et capture (ordres de grandeur)

Un jeton avec le certificat de l'unité et une racine RSA-3072 pèse 3082 à
3114 octets, 2022 avec l'unité seule, 884 sans certificat (mesures de la note,
R1-F16 ; 2104 octets pour le jeton de l'autorité de test de CT-1 §11.2) ; une
requête 56 à 113 octets (R1-F16), 69 à 82 dans les vecteurs de l'annexe A ;
une réponse d'erreur 50 à 57 octets (R1-F16) ; une preuve `.ots` en attente de
deux calendriers 195 à 233 octets (EX-6.4 ; annexe A.4). À `N_q + N_s =
105 120` jetons par an et 3,1 Ko le jeton, avec sa requête et sa réponse
conservées (EX-5.14), le répertoire d'ancres d'un journal croît d'environ
650 Mo par an, 6,5 Go sur dix ans ; les captures d'ancres de points (9.3)
d'environ 10 Mo par jour. Ces chiffres entrent dans le dimensionnement de
CT-8, pas dans la formule de coût.

### 12.5 Vérifications

| Id | Vérification |
|---|---|
| AN-59 | `cout(entrées)` de la référence rend, pour chaque cas de la famille `cout/`, exactement les six grandeurs attendues (`$defs/cas_cout.expected`) ; le vérificateur Go les recalcule depuis EX-12.1 et EX-12.2 ; avec `a = 1`, `N_q` et `N_s` égalent la table de 4.6 |
| AN-60 | Aucune valeur de prix réel dans le dépôt : les champs `unit_price_*` et `subscription_fee` des vecteurs sont des unités symboliques (1, 0,2, 10 000) et `INDEX.md` le dit |

## 13. Sûreté

Les adversaires sont ceux de CT-6 §3.4 (opérateur, fournisseur NOORTRACE,
enregistreur compromis, autorité d'horodatage malhonnête, validateurs
minoritaires, fournisseur d'en-têtes) et de la section 3 de la partie A. La
table dit, pour chaque menace propre à l'ancrage, le constat tiré des sources
et la réponse de cette spécification ; ce que chaque ancre prouve et ne prouve
pas reste dit par CT-6 §7 et CT-1 §10.9.

| Menace | Constat | Réponse |
|---|---|---|
| **Rejeu d'un jeton** : un jeton obtenu sur une empreinte est présenté pour une autre, ou une réponse ancienne est renvoyée au client | Le jeton engage son `messageImprint` (T-2 de CT-6 le compare à l'empreinte recalculée du sujet) ; deux sujets n'ont jamais la même empreinte (`periodHash` porte un nonce, CT-1 §10.1 ; deux points diffèrent par `checkpoint_ts` ou `prev_checkpoint_hash`, CT-1 §10.5) ; une réponse ancienne ne porte pas le nonce de la requête courante (R1-F1, R1-F2) | nonce frais à chaque tentative et égalité stricte exigée (EX-5.3, EX-5.10 étape 4 : `nonce_different` est une erreur permanente, alertée, qui déclenche la relève) ; réponse tardive `reponse_tardive`, non promue sauf la troisième, avec avertissement (EX-5.11, R1-F13) ; `openssl ts -verify -queryfile` reproduit le refus (« nonce mismatch », annexe B.3) ; un canal sans nonce n'est admis ni comme principal ni comme secours (EX-5.16) |
| **Prestataire menteur ou compromis** : `genTime` faux, antidaté ou postdaté | Hypothèse H4 de CT-6 : rien dans un jeton ne prouve que l'heure est juste ; seul Bitcoin donne une borne indépendante (CT-6 §3.4, contrôle 5) ; un prestataire qualifié arrête son service au-delà de sa dérive admise (R1-F19, R1-F38), ce qu'il déclare | `\|genTime − sent_at\| ≤ clock_tolerance_s` à l'acquisition, sinon le jeton est promu mais marqué `horloge_suspecte` et alerté (EX-5.11) : un prestataire qui ment de plus de deux minutes est vu à l'instant où une autre tentative est encore utile, et le réviseur juge avec ses ancres (CT-6 AV-T-4) ; deux prestataires qualifiés d'exploitants distincts (EX-11.2) ; preuve OpenTimestamps sur chaque clôture (EX-6.2) ; `noortrace_anchoring_d_jeton_s` rend visible un jeton tardif ; le vérificateur n'y ajoute rien (CT-6 §7.2) |
| **Horloge de l'enregistreur** fausse ou manipulée | `checkpoint_ts` et `generated_at` sont déclaratifs (CT-1 §10.5, CT-2 EX-7.10) ; CT-2 bloque l'écrivain sur un saut d'horloge (EX-7.13) ; le planificateur lit l'horloge pour ses échéances, la relève (EX-8.8) et les attentes (EX-8.9) | les attentes se calculent sur l'horloge monotone du processus, les échéances `D_k` et les instants consignés sur l'horloge de l'enregistreur (EX-4.13, H8) ; aucune échéance n'est datée par un prestataire ; une horloge locale fausse fait marquer `horloge_suspecte` des jetons justes, sur tous les prestataires à la fois : symptôme reconnaissable (EX-5.11) ; CT-1 §10.9 : seule la contresignature extérieure date |
| **Perte ou corruption de la file** | La file est le seul état du planificateur ; sa perte ferait oublier des demandes | écriture avant envoi, `fdatasync`, dernière ligne fait foi, ligne tronquée ignorée (EX-8.5) ; les sujets sont durables ailleurs (segments, manifestes, points : CT-2 §12) et, à chaque démarrage, une **reconstruction** confronte ces objets (entrée `stockage_relu`) aux demandes relues de tous les fichiers `file-*.ndjson` et recrée celles qui manquent (`anchoring_queue_rebuilt`, alerte `file_perdue`, EX-8.12 ; traces `file-perdue`, `bascule-epoque-fichier-perdu`) ; les fichiers de file sont copiés vers le WORM (EX-8.14) ; une perte ne fait perdre que du temps (fenêtre), jamais un événement |
| **Points antidatés ou insérés** par qui tient la clé de l'enregistreur | Il peut signer un point à n'importe quel `checkpoint_ts` (CT-1 §10.9) ; il ne peut pas obtenir d'un prestataire extérieur un `genTime` antérieur à l'horloge de celui-ci, ni insérer un point dans une série déjà contresignée sans casser `prev_checkpoint_hash` et la cohérence RFC 9162 des têtes (R2-F21 : un signataire ne doit jamais signer un point incohérent avec un point antérieur ; R2 conséquence 21) ; au registre, une empreinte ne s'ancre qu'une fois (CT-4 §8.3) | admission de chaque point par AN-3 avant toute ancre (signature, place dans la série, CT-1 §10.5) ; série vérifiée par `ancrage.mjs` (AN-2, AN-3 ; 10.2) : chaînage, monotonie de `tree_size` et de `checkpoint_ts`, échéances, cadence ; pour chaque point contresigné, l'alerte `jeton_anterieur_au_point` si `genTime + accuracy < checkpoint_ts − clock_tolerance_s` et l'alerte `contresignature_tardive` si `genTime + accuracy − checkpoint_ts > c_T` (AN-2, 8.9 ; `tableEcheances` et le planificateur) ; CT-6 révision 0.2 rapporte `checkpoint_ts` et `rewrite_window_end` dans `facts.checkpoint` (CT-6 EX-6.17), signale par AV-K-2 un `checkpoint_ts` postérieur au jeton (CT-6 EX-9.22) et par AV-K-4 un jeton postérieur de plus de 3600 s au point (CT-6 §7.9), sans changer de verdict : un grand écart peut signaler un point produit après coup |
| **Prestataire injoignable longtemps** (jours) | La RFC ne fixe aucune reprise (R1-F9) ; les prestataires n'en recommandent aucune (R1-F73) ; RFC 9162 et les clients de transparence rejouent les 5xx avec `Retry-After` et backoff, jamais les 4xx (R1-F68, R1-F70) | file durable bornée, attente plafonnée à `retry.max_ms`, relève par le secours pour la clôture (EX-5.7, EX-8.8) et, avec `provider_role = principal` (le défaut), pour les demandes de points aussi, au bout de `checkpoints.fallback_after_s` (120 s) ou dès une erreur permanente ; échéances closes `remplacee` sans rattrapage pour les points (EX-4.4) seulement sans secours, ou avec un prestataire des points `second_rang` ou `interne` ; repli sur le serveur interne, non qualifié (section 7), **par décision de l'exploitant**, qui recharge la configuration avec `provider_role = interne` : aucune bascule automatique, chaque demande part d'abord au rôle configuré et attend `fallback_after_s` avant la relève (EX-5.7, EX-8.8) ; alertes à 15 min et `anchor_pending_alert_s` (8.9) ; la fenêtre de réécriture pour la date se dégrade vers `3600 s + d` puis `n × 3600 s + d`, ce que `noortrace_anchoring_window_s` affiche et que le dossier montre (`upper_bound`) : rien n'est caché au réviseur. Cette dégradation est celle du régime sans secours, qui s'applique en version 0 : aucun secours utilisable n'est documenté (EX-11.3). Avec un secours conforme et joignable, la relève maintient `W_date ≤ c_T + d_point + d_attente + checkpoints.fallback_after_s + d_tsa`, soit 426 s + `d_tsa` par défaut (EX-3.5), et la clôture reste qualifiée |
| **Série réécrite et ancrée à part** par qui tient la clé de l'enregistreur et la clé de chaîne | le registre accepte toute empreinte nouvelle : il fixe l'ordre relatif et l'unicité des empreintes, pas une position, et ne date rien (3.3) | contrôle de complétude au registre sur la série publiée (EX-10.7, AN-61) : toute ancre de point émise par la clé de chaîne du journal dans la fenêtre de la période doit correspondre à un point publié, dans l'ordre des `checkpoint_ts` ; `W_ordre` reste une durée de conception mesurée (P-2), non une garantie du dossier |
| **Empreinte prise au registre** (`empreinte_squattee`) | qui voit l'empreinte avant l'inclusion peut l'ancrer le premier (CT-4 §8.3) ; l'horodateur la voit | ancre d'abord, jeton ensuite : sans borne pour la période (CT-4 EX-8.4), bornée à `squat_wait_s` pour un point (EX-4.7, EX-8.4, EX-9.6) ; aucun nouvel essai sur `empreinte_squattee`, incident consigné (EX-9.7, CT-4 EX-8.6) |
| **Fuite par les empreintes** : le prestataire ou le calendrier apprend quelque chose du journal | la TSA reçoit 32 octets et ne les examine pas (CT-6 §9.1) ; des jetons sur la même empreinte se corrèlent (RFC 3161 §4 point 5, R1-F13) ; un calendrier reçoit un condensé noncé (section 6) | une empreinte par sujet, jamais répétée ; le prestataire voit la cadence et le nombre de points d'un compte, pas leur contenu : un client qui tient cette cadence pour sensible choisit le serveur interne pour les points (section 7) ; `org_id` et `journal_id` ne sont jamais envoyés à un prestataire |
| **Secrets d'accès** au prestataire (Basic, certificat client) | HTTP Basic chez P2 et dans l'enveloppe de P1 (section 11) | références de secrets de CT-2 §15.2 dans `auth.secret` (EX-4.8), jamais dans la file, les traces, le journal ni les vecteurs (AN-43) ; TLS 1.2 au moins avec vérification du certificat du serveur (EX-5.5) ; un `401` est une erreur permanente (EX-5.12) qui alerte sans jamais être rejouée |
| **Déni de service d'un calendrier** ou d'un agrégateur OpenTimestamps | « at worst they can deny service, not produce false proofs » ; « the public calendars are a central point of failure » (R1-F59) ; aucune limite de débit publiée (R1-F67) | au moins deux calendriers d'exploitants distincts (CT-6 EX-13.5, EX-4.9), `min_responses`, `give_up_after_s` avec alerte (EX-6.6, EX-8.11) ; une preuve en attente n'est jamais présentée comme preuve (CT-6 O-7, EX-6.7) |
| **Interface du serveur interne** exposée | `openssl ts` n'a pas de serveur HTTP ni de verrou de `serial` (R1-F49) ; la configuration de test d'uts-server admet MD5 et SHA-1 (R1-F52) | AN-22 à AN-31 : TLS client, condensés restreints, émetteur unique, journal hors serveur, clé hors de l'hôte de l'enregistreur (EX-7.3) |
| **Réponse surdimensionnée ou malformée** d'un prestataire ou d'un calendrier | lecteur DER borné de CT-6 (profondeur 32) ; corps de `TimeStampResp` admis jusqu'à 128 Kio (EX-5.5) ; réponse de calendrier bornée à 10 000 octets par le client officiel (R1-F63) | les bornes de CT-6 §15.1 s'appliquent à l'acquisition (T-1) ; une réponse HTTP de plus de 128 Kio (RFC 3161) ou 10 000 octets (calendrier) est une erreur permanente sans lecture (EX-5.12) |

**EX-13.1** Aucune réponse de prestataire, aucune preuve et aucune ancre ne
modifie un événement, un point ou un manifeste déjà durable ; l'ancrage
n'écrit que dans son répertoire d'ancres et dans sa file. Une attaque sur
l'ancrage peut retarder une preuve de date, jamais altérer ce qui est prouvé.

## 14. Alignement avec le dépôt

Ce que cette spécification rend caduc ou attend d'autres lots. « fait » : dans
ce lot de spécification ; « à faire » : attendu des références JavaScript, des
vecteurs ou d'une autre spécification, nommés ; « proposition » : changement
d'une autre spécification écrit ici, non appliqué. Les documents racine
(`README.md`, `README.fr.md`, `ARCHITECTURE.md`, `CHANGELOG.md`, `NOTICE`) ne
sont pas modifiés par ce lot : la dernière ligne dit ce qui doit y changer.

| Emplacement | Avant | Attendu par CT-5 | État |
|---|---|---|---|
| `spec/schemas/ancrage-v0.schema.json` | — | document de configuration `ancrage-v0` (4.4) : draft 2020-12, sans référence croisée, mode strict d'ajv ; `queue.path` ne porte que la file, les enregistrements d'acquisition étant écrits par période dans le répertoire d'ancres (EX-5.14, EX-8.5) | fait |
| `spec/schemas/planificateur-ancrage-v0.schema.json` | — | schéma des traces du planificateur, de la file (`$defs/demande`), des cas de coût et de requête et du fichier de famille (8.10, annexe A) ; mots-clés dans le sous-ensemble de `validerSchema` (CT-4 §7.2) ; compilable en mode strict d'ajv (`type` explicite et propriétés typées sur les sous-schémas conditionnels `subject` et `deadlines` de `$defs/demande`, `data` de `$defs/evenement_entree` et `detail` de `$defs/action_attendue`) | fait |
| `scripts/lib/ots.mjs` | tri de deux attestations en attente sœurs par octets sérialisés | tri par URI (comparaison de chaînes), comme `PendingAttestation.__lt__` de la bibliothèque officielle (EX-6.4, règle 2 ; annexe B.3) ; les vecteurs CT-6 existants n'ont aucune paire d'attestations en attente de longueurs différentes et ne changent pas | fait (comparateur aligné ; vecteurs CT-6 inchangés) |
| `scripts/lib/ancrage.mjs` | — | planificateur à horloge injectée, sans réseau ; `TimeStampReq` DER (EX-5.1) ; fichier `.ots` (EX-6.4) ; comptages (`compterJetons`, EX-4.11) ; vérification de série (AN-2, AN-3) ; coût ; `rejouerTrace` (EX-8.13) | fait |
| `scripts/lib/journal.mjs` | CT-1 révision 0.3 à coder | point de contrôle, cohérence, partie `points_de_controle`, `choisirPointCouvrant`, `preuveCoherenceDossier` (CT-1 §17) ; CT-5 les emploie (EX-10.3) | fait (CT-1 révision 0.3) |
| `scripts/lib/verificateur.mjs`, `scripts/verify/dossier.mjs` | huit contrôles sans la partie | K-7 à K-9 sur `checkpoint_hash` (CT-6 révision 0.2) | fait (CT-6 révision 0.2) |
| `scripts/lib/noortrace.mjs`, `scripts/lib/registre.mjs`, `scripts/lib/conventions-registre.mjs` | `DOC_TYPE_PERIODE` seul | `DOC_TYPE_POINT_DE_CONTROLE` = `0x72c4…2178` ; `ancrer --point` (9.5) | fait pour `DOC_TYPE_POINT_DE_CONTROLE` et le rôle `ancre_point_de_controle` (capture par `scripts/vecteurs/capturer-ct6.mjs --ancre-point`) ; `ancrer --point` de l'outil de CT-4 : à faire (CT-4, révision suivante) |
| `scripts/vecteurs/generer-ct5.mjs`, `spec/vecteurs/ct-5/` | — | familles de l'annexe A, deux générations identiques, `INDEX.md` | fait |
| `spec/vecteurs/ct-5/verificateur-independant/` | — | module Go écrit depuis la seule spécification (annexe A.5) | fait |
| `test/ancrage.test.js`, `.github/workflows/ci.yml`, `package.json` | rien pour CT-5 | tests de l'annexe A.7, script `vecteurs:ct5`, étapes de CI | fait |
| `spec/vecteurs/ct-6/` (CT-6 révision 0.2) | 50 dossiers sans la partie | nouveaux dossiers avec `points-de-controle.json` (valides et invalides, un par vérification K-7 à K-9), les 50 inchangés ; `openssl ts -verify` sur les jetons des nouveaux dossiers (A.6) | fait (`generer-ct6.mjs` ; confrontation par `spec/vecteurs/ct-5/confrontation/reponses/` et CT-6 A.8) |
| CT-1 | révision 0.3 | aucune modification de format : CT-5 reprend §10.5 à §10.9 et §11.2 tels quels ; CT-1 §15 renvoie à CT-5 pour la cadence, la file et les prestataires ; K-3 (clé du point absente d'un `cles.json` exploitable : échec) et K-8 (`chain_id` rapporté, non comparé) alignés d'un mot sur CT-6 §5.4 et EX-11.25 | fait (renvoi ; alignement textuel de §11.4) |
| CT-2 §15, clé `anchoring` | `registry {enabled, rpc_url, chain_key, next_chain_key}`, `rfc3161 {enabled, url}`, `opentimestamps {enabled, calendars}` | `anchoring.registry` inchangé (point RPC et clé de chaîne, EX-4.8 ; `rpc_url` en liste, CT-4 §13) ; `rfc3161` et `opentimestamps` remplacés par une référence au document `ancrage-v0` d'EX-4.8 (`anchoring.ancrage: <chemin>`), validé au démarrage avec la configuration (EX-4.9) ; schéma `configuration-enregistreur-v0` étendu de façon compatible (membre facultatif) | fait (CT-2 révision 0.4 : `anchoring.ancrage` et `checkpoint_interval_s` facultatifs, 15.1 ; `rfc3161` et `opentimestamps` de CT-2 restent en place jusqu'au lot de code) |
| CT-2 §3.1, §3.2, §12.1, §12.6, §14.2, §17 | « Ancrage (CT-5) indisponible : l'ancre est réessayée par la supervision » ; aucun point de contrôle | production des points (`checkpoint_interval_s`, à la clôture ; CT-1 §10.5), écriture de la série `points/periode-<period_start>.ndjson` sous `storage.root` (10.1 ; CT-1 §15), remise des points et manifestes au composant d'ancrage (EX-4.12, EX-8.1), copie WORM des points et du répertoire `ancres/` (EX-5.15, EX-8.14, P-6) ; métriques et journal d'EX-8.15 ; alerte « Ancre en retard » à `queue.anchor_pending_alert_s` | fait pour la production, l'alignement, la série, la remise, la copie WORM et la ligne de 14.2 (CT-2 révision 0.4, 12.10, EX-12.24 à EX-12.28) ; métriques, journal et alerte de 8.9 : proposition (CT-2 §17, CT-8) ; code de l'enregistreur : à faire |
| CT-4 §0, §6.4, EX-6.6, EX-4.19 et §12 (notes) | un `docType` ; version 0.2 | ligne `noortrace/point-de-controle/v0` dans la table des `docType`, EX-6.6 complété, révision 0.3 minimale (9.5) ; constante `DOC_TYPE_POINT_DE_CONTROLE` des bibliothèques (`noortrace.mjs`, `registre.mjs`, `conventions-registre.mjs`) ; notes de révision à EX-4.19 et à la ligne « Débit d'une clé » (`24 × 62`, 63 opérations par période) | fait (CT-4 révision 0.3, texte ; constante faite) |
| CT-4 §6.9 (RG-3, vecteur `doctypes.json`), exemple d'EX-4.19 et ligne « Débit d'une clé » de §12 recalculés, outil `ancrer --point` | un libellé dans le vecteur ; budget à deux opérations par période | section 9.5 | à faire (CT-4, révision suivante ; vecteurs ct-4 et outil inchangés par ce lot) |
| CT-6 §5.4, §6.5, §6.7, §7.9, §9.9, §10.9, §11.9, §12.5, §13.4, annexe A | contrôle 4 sur `periodHash` seul ; `registre.json` à trois rôles ; aucune exigence pour les points | K-1 à K-9 rattachées aux contrôles 3 (K-1, K-2, K-4, K-5), 6 (K-3), 2 (K-6), 4 (K-7), 8 (K-8) et 5 (K-9), une K- `non_execute` étant sans effet sur le statut du contrôle (EX-5.7, EX-5.8) ; raisons de non-exécution `partie_absente` (ancre `null`), `ancre_absente`, `piece_hors_dossier` (K-6), `prerequis_en_echec` (EX-5.9) ; fragment FK de l'énoncé « l'événement est couvert par le point de contrôle du journal […], horodaté au plus tard le … ; une réécriture postérieure à cet instant serait détectée » (EX-6.16) et `facts.checkpoint` avec `rewrite_window_end` et `rewrite_window_ms` (EX-6.17) ; section 7.9 (ce que le verdict prouve de nouveau : fenêtre de réécriture bornée au point) ; rôle `ancre_point_de_controle` de `registre.json` (une entrée au plus, 17 entrées au plus), vérification R-11 à part, R-9 inchangée (§11.9) ; AV-K-1 à AV-K-3 ; EX-13.14 à EX-13.19 (§13.4) ; vecteurs EX-A.13 à EX-A.17 | fait (CT-6 révision 0.2, 2026-10-25 ; code et vecteurs faits) |
| `scripts/lib/ancrage.mjs`, vérificateur Go, traces (révision 0.2) | — | ligne `envoyee` écrite avant l'envoi (EX-8.5, AN-32) ; dernier point contresigné et échéances rendues sur refus (EX-4.3) ; repli de clôture (EX-4.2) ; reconstruction de la file et fichiers d'époque (EX-8.12, EX-8.5 règle 6) ; alertes `point_manquant`, `jeton_anterieur_au_point`, `contresignature_tardive`, `reponse_tardive_promue` ; classement des étapes 1 et 5 (EX-5.10) ; admission avec racine et `last_hash` (AN-3) ; `constaterCadence`, `verifierCompletudeRegistre` (AN-61), `lireFiles` ; quatre composantes de `d_jeton` sur la ligne `checkpoint_countersigned` (EX-3.5, 8.9) ; neuf traces nouvelles (vingt et une) et la famille `completude` | fait |
| Retrait de la qualification du principal (EX-5.9) | — | relève de la clôture par le secours qualifié tant que la configuration n'est pas rechargée | à faire (règle normative pour le composant d'ancrage ; aucune entrée du planificateur ne porte le retrait, la règle est appliquée par l'exploitant, qui provoque la relève ; test à écrire, CT-9) |
| CT-8 | — | alertes de 8.9, sauvegarde du répertoire d'ancres et de la file, fin de rétention (EX-5.15, EX-8.14), source d'en-têtes Bitcoin (EX-6.8), capacité de capture et dimensionnement (EX-9.9, 12.4), exploitation du serveur interne (7.2), réétablissement de `qualified` tous les trente jours (EX-5.9) | proposition |
| CT-9 | — | tests attachés aux EX- et AN- des deux parties (AN-1 à AN-61) ; mesures P-1 à P-6 de 3.6 ; épreuve à l'aveugle (un relecteur qui n'a que CT-5 et CT-1 §9 à §11 dit la cadence des points, ce qu'un point prouve et ne prouve pas, la fenêtre, le coût pour un prix unitaire donné, la conduite quand le prestataire est injoignable ; un second relecteur lit CT-6 §7 révisée) | proposition |
| `spec/README.md` | CT-5 « à écrire » | CT-5 version 0.2 en revue ; lignes des schémas `ancrage-v0` (4.4) et `planificateur-ancrage-v0` (8.10) ; section « CT-5 (`vecteurs/ct-5/`) » avec la table de l'annexe A.4 ; versions de CT-1 (0.3), CT-4 (0.3) et CT-6 (0.2) ; `-r spec/schemas/point-de-controle-v0.schema.json` dans les commandes qui chargent le schéma de dossier | fait |
| `README.md`, `README.fr.md`, `ARCHITECTURE.md` (« Ancrage », point 2 et paragraphe « En option, un serveur RFC 3161 interne […] contresigne la chaîne toutes les minutes » ; « Modèle de menace », ligne « L'enregistreur lui-même est compromis » : « les ancres horaires bornent la fenêtre de réécriture ; contresignature interne à la minute en option »), `CHANGELOG.md` | contresignature interne « à la minute », fenêtre « une heure » | points de contrôle toutes les 60 s ancrés au registre, contresignés au plus toutes les 300 s par un prestataire extérieur ou interne, clôture horaire qualifiée inchangée ; fenêtre bornée au point (CT-1 §10.9 : `60 s + d_registre` pour l'ordre, `300 s + d_jeton` pour la date) ; CT-5 écrit ; schéma et vecteurs `ct-5` au journal des changements | à faire (documents racine, hors de ce lot) |

## 15. Ce que cette version ne couvre pas

- **L'adaptateur d'enveloppe** d'un prestataire qui n'expose pas RFC 3161 nu
  (OASIS DSS, SOAP ou REST : le cas documenté de P1, section 11) : la version
  0 spécifie le client RFC 3161 nu (EX-5.16) et les classes qu'un adaptateur
  devrait rapporter (EX-11.3), pas l'adaptateur ; un tel prestataire ne peut
  pas être `principal` ni `secours` en version 0.
- **La validation à long terme** des jetons : re-horodatage ou notarisation
  d'un jeton avant l'expiration du certificat de l'unité (RFC 3161 §4,
  R1-F13), enregistrements de preuve (RFC 4998) ; la version 0 capture les
  preuves de non-révocation peu après `genTime` (EX-5.10, étape 10 ; CT-6
  EX-13.12) et conserve dix ans (EX-5.15, EX-8.14), sans plus.
- **Les témoins et cosignatures** des journaux de transparence (C2SP
  `tlog-witness`, `tlog-cosignature`, R2-F26 à R2-F28) : une cosignature de
  témoin bornerait l'antériorité et l'unicité de vue des points sans
  prestataire d'horodatage ; cités seulement, comme CT-4 §11.3 le fait pour un
  journal de remplacement.
- **Une borne inférieure** (« pas avant ») pour un point : un point qui
  engagerait une valeur fraîche extérieure (hachage du jeton précédent, en-tête
  Bitcoin connu) la donnerait (R2, conséquence 22) ; proposition de conception
  sans source externe, non retenue.
- **Un calendrier OpenTimestamps propre**, l'exploitation d'un nœud Bitcoin
  pour la source d'en-têtes (section 6, CT-8), et la soumission à des
  agrégateurs plutôt qu'aux calendriers.
- **Le regroupement de plusieurs empreintes** en une requête : RFC 3161 porte
  un `messageImprint` par requête ; l'enveloppe de P1 admet des lots (R1-F33) ;
  un arbre de Merkle d'empreintes de plusieurs journaux horodaté en une
  requête réduirait `N_q` d'un facteur `J` au prix d'une preuve d'inclusion
  supplémentaire dans le dossier : à étudier avec CT-6.
- **Les algorithmes post-quantiques** (ML-DSA chez les témoins, R2-F22) et les
  condensés autres que SHA-256 dans les requêtes (EX-5.2 : SHA-256 seulement en
  version 0).
- **La garde en HSM de la clé du serveur interne** et sa cérémonie (CT-7) ;
  AN-31 n'exige que la classe de garde.
- **Un prix** : aucun prix, aucun devis, aucun modèle tarifaire autre que la
  formule paramétrée de la section 12.
- **La révocation d'une ancre** (`AttestationRegistry.revoke`) : hors de la
  version 0 (CT-4 §14) ; une ancre de point refusée reste refusée.
- **Les variantes GET** de l'interface de P2 (requête dans l'URL, R1-F35) : le
  client n'emploie que POST.
- **Les mesures en charge** du planificateur (débit de points, nombre de
  journaux par instance, taille de la file en régime de panne) : CT-2 §16, à
  mesurer en phase 2 ; les ordres de grandeur de 12.4 et 9.3 ne sont pas des
  mesures.
- **Les points de contrôle de plusieurs enregistreurs** d'un même journal
  (bascule de CT-2 §13) : la série d'une période est produite par l'écrivain
  en titre ; le point du nouvel écrivain chaîne le dernier point copié du
  précédent, ce que CT-2 §13 devra dire.

## Annexe A — Vecteurs CT-5

### A.1 Principes

**EX-A.1** Les vecteurs sont sous `spec/vecteurs/ct-5/`, produits par
`scripts/vecteurs/generer-ct5.mjs` (`npm run vecteurs:ct5`) et rejoués à
l'identique : aucune valeur aléatoire, aucune lecture de l'horloge ; les
nonces, gigues, identifiants de corrélation et instants sont dérivés
d'étiquettes ou fixés (A.2). Les fichiers JSON sont écrits par
`JSON.stringify(objet, null, 2)` suivi d'un saut de ligne ; les fichiers
binaires (`.tsq`, `.tsr`, `.der`, `.ots`) tels que construits. Le générateur
n'efface et ne réécrit que ses propres entrées de premier niveau, jamais
`verificateur-independant/` ni `confrontation/` ; il refuse, sans rien
effacer, un répertoire de sortie qui porte une autre entrée.

**EX-A.2** Entrées lues, jamais réécrites : l'exemple de référence de CT-1
(annexe A de CT-1 : événements, manifeste de la période 1, points `K1` à `K6`
de §10.8), les manifestes et clés de `spec/vecteurs/ct-1/` (CT-1 §13), les
clés et certificats de l'autorité de test de CT-6
(`spec/vecteurs/ct-6/rfc3161/cles`, `scripts/vecteurs/ct6/rfc3161.mjs`) et les
preuves `spec/vecteurs/ct-6/ots/preuves/{o7-en-attente,periode-1}.ots`. Les
vecteurs de CT-1, CT-2, CT-3, CT-4 et CT-6 ne changent pas ; les dossiers avec
la partie `points-de-controle.json` sont des vecteurs de CT-1 (K-1 à K-6) et
de CT-6 révision 0.2 (K-7 à K-9), pas de CT-5.

**EX-A.3** Chaque règle EX- des sections 4 à 12 et chaque vérification AN-1 à
AN-61 qui se calcule hors réseau a au moins un cas qui réussit et au moins un
cas qui échoue ou qui refuse, nommé dans `INDEX.md` avec la règle qu'il
exerce ; les familles `requetes`, `reponses` et `ots` servent AN-5 à AN-11 et
AN-16 à AN-19 de la partie A, la famille `planification` AN-2, AN-4, AN-12,
AN-13 et les AN- de la section 8, la famille `completude` AN-61. Les
traces de planification sont conformes à la racine du schéma
`planificateur-ancrage-v0` ; les familles `requetes`, `cout` et `completude`
à `#/$defs/fichier_vecteurs` ; chaque ligne d'une file à `#/$defs/demande`.
Deux règles n'ont pas de cas dans cette version, ce que `INDEX.md` dit : la
capture différée d'EX-8.10 (action `programmer` de raison `capture`) et la
transition `obtenue → a_reprendre` sur révocation (EX-8.3 ; aucune entrée de
trace ne porte une révocation).

### A.2 Constantes

| Grandeur | Dérivation ou valeur | Usage |
|---|---|---|
| Journal de référence | `org_id` `0xa581…daab`, `journal_id` `0x0e27…c64b`, période 1 `[1793710800, 1793714400)`, `periodHash` `0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1`, points `K1` à `K6` (CT-1 §10.8, annexe B) | traces, requêtes |
| Journal des vecteurs | `journal-sinistres` de CT-1 §13 : trois `periodHash` de `spec/vecteurs/ct-1/manifestes/attendu.json` | requêtes, traces longues |
| Nonce RFC 3161 d'une tentative | 64 premiers bits de `SHA-256(UTF-8("noortrace/vecteurs/v0/ct-5/nonce-tsa/<journal>/<periode\|point>/<empreinte hex sans 0x>/<n>"))`, entier non signé (EX-5.3 : `n ≥ 1`, encodage DER minimal) ; `<journal>` est `journal-principal` ou `journal-sinistres`, `<n>` le rang de la tentative | requêtes, traces (même construction que le nonce de CT-1 §13, étiquette `…/ct-1/nonce-tsa/point-de-controle/exemple` → `0x74a6f4979421411e`, requête `requete-point-k2.tsq` d'EX-5.1) |
| Nonce OpenTimestamps | 16 premiers octets de `SHA-256(UTF-8("noortrace/vecteurs/v0/ct-5/ots/nonce/<journal>/<periode\|point>/<empreinte hex sans 0x>"))` ; pour `point-k2-en-attente.ots` : `…/ots/nonce/journal-principal/point/6a8e035a…e6ff` → `67408294dbd584a4dda160e16129c6b5`, engagement `e = c1cb7611d9e35803bceab098d24a183876e134fcda969d249a92bf5013eca0aa` ; l'exemple minimal d'EX-6.4 (`point-k2-minimal.ots`) garde son étiquette propre, `…/ots/nonce/point-k2` → `a10f0dccae630a2791dde3924b507379` | fichiers `.ots` |
| Opérations de calendrier synthétiques | `f1` de 16 premiers octets de `SHA-256(UTF-8("noortrace/vecteurs/v0/ct-5/ots/calendrier/<alice\|bob>/<sujet>"))` puis `08`, puis l'attestation en attente de l'URI du calendrier ; `<sujet>` est `<journal>/<periode\|point>/<empreinte hex sans 0x>`, comme pour le nonce (pour `point-k2-en-attente.ots` : `alice` → `86b4b0a3caa98d05a58a4023cc6c953b`, `bob` → `da4ee3a72268b161c2f158aec8af42fd` ; fichier de 233 octets, SHA-256 `0x8bdf7ed01c73e1b53cb1765e7c456c0ca92056af9685bc3c537a06f51182687a`) | fichiers `.ots` en attente |
| Calendriers | `https://alice.btc.calendar.opentimestamps.org`, `https://bob.btc.calendar.opentimestamps.org` (calendriers publics par défaut, R1-F56, R1-F57) | configuration des traces |
| `attempt_id` (identifiant de corrélation) | `<kind>:<16 premiers hex de l'empreinte>:<n>` | traces (EX-5.13) |
| Prestataires des traces | `qtsa-principal` (`principal`, `qualified` vrai), `qtsa-secours` (`secours`, `qualified` vrai), `tsa-interne` (`interne`, politique `1.3.6.1.4.1.99999.1.1`, `qualified` faux) : la projection (EX-8.2) de l'exemple de configuration d'EX-4.8, dont les URL sont en `.example` ; et, pour les traces qui exercent ce rôle, `tsa-second-rang` (`second_rang`, `qualified` faux), absent de l'exemple d'EX-4.8 ; aucun identifiant de compte | traces |
| SHA-256 des jetons des traces | `SHA-256(UTF-8("jeton <nom>"))` pour un jeton représenté, `<nom>` étant une étiquette libre choisie par la trace (le plus souvent le nom du point ou de la période et le prestataire ; elle n'a pas à suivre un nommage dérivable, seule son unicité dans la trace compte, et la valeur est recopiée telle quelle par le vérificateur), `SHA-256(UTF-8("capture <id> <bloc>"))` pour un index de capture représenté, `SHA-256(UTF-8("preuve en attente periode 1"))` pour la preuve `.ots` représentée de la trace de 8.10 (`0x9c6433e3…2355`, taille 233 déclarée) | traces (les jetons et preuves eux-mêmes sont dans `reponses/` et `ots/`) |
| Autorité de test | celle de CT-6 (`ac-test`, `tsa-test`, RSA 3072, politique `1.3.6.1.4.1.99999.1.1`) | `reponses/`, confrontation |
| Prix symbolique | `p_q = 1`, `p_s = 0,2`, `F = 10 000`, `Q = 10 000` : unités, jamais un prix | `cout/` |

Empreintes d'ancre des points de référence (section 9.1) : `K1`
`0xd0cd916d070ecb8c2af3a3b62b933ccd6e61fd481ea2b70312ab988fabac8540`, `K2`
`0x7f721a4526c614882ff41ac33792c6d05fa7fb6dd98bc1c369d0e277029f4e44`, `K3`
`0xa1aeb874daa988a4833c394476c4ea740096a3496ed081ae6f8592fb4912a837`, `K4`
`0xa7f0a30f11f724f5ae4bd7ba952079fa513dfe0ed70c051bdfc5bbe9c67b3792`
(`keccak256(org_id ‖ journal_id ‖ checkpointHash)`, calcul pour cette
spécification avec `ethers` 6 du présent dépôt). Ces clés et valeurs sont
publiques et ne doivent jamais porter de valeur ; `constantes.json` les porte
toutes et `INDEX.md` les imprime.

### A.3 Disposition

```text
spec/vecteurs/ct-5/
  INDEX.md                       généré : chaque cas, son attendu en une ligne, les constantes
  constantes.json                A.2
  requetes/
    requetes.json                famille requetes (#/$defs/cas_requete) : DER, taille, SHA-256, nonce, fichier
    requete-point-k2.tsq         la requête d'EX-5.1 (nonce de CT-1 §13), à laquelle le jeton de CT-1 §11.2 répond
    *.tsq                        les autres TimeStampReq, octets exacts
  reponses/
    reponses.json                réponses TimeStampResp de l'autorité de test et attendu d'EX-5.13 (issue, code)
    *.tsr, *.der                 réponses et jetons extraits : granted-*, rejet-*, reponse-tardive-1 à 3, horloge-suspecte,
                                 t6-signature, statut-5, waiting (jetons sur checkpointHash K2 et sur les periodHash)
  ots/
    point-k2-minimal.ots         l'exemple d'EX-6.4 : deux promesses nues sous l'engagement (195 octets)
    point-k2-en-attente.ots      preuve en attente à deux calendriers sur checkpointHash K2, une branche par calendrier (233 octets, A.2)
    periode-1-en-attente.ots     idem sur le periodHash de la période 1 de référence
    mise-a-niveau.json           paire (avant, après) : o7-en-attente.ots → periode-1.ots de CT-6 (lus, non copiés) ; attendu : en_attente → complete
  planification/
    heure-nominale-reference.json   la trace de 8.10
    principal-injoignable.json, refus-permanent-releve.json, reponse-tardive.json, horloge-suspecte.json,
    echeance-remplacee.json, registre-indisponible.json, redemarrage-reprise.json, ots-mise-a-niveau.json,
    preuve-de-vie.json, file-pleine.json, prestataire-min-interval.json   (8.10, version 0.1)
    refus-puis-preuve-de-vie.json, refus-puis-preuve-de-vie-redemarrage.json, file-perdue.json,
    bascule-epoque.json, bascule-epoque-fichier-perdu.json, registre-indisponible-cloture.json,
    mi-periode-impair.json, reponse-hors-profil.json, point-manquant.json   (révision 0.2 : vingt et une traces)
  reprise/
    <trace>.avant.ndjson, <trace>.apres.ndjson    files avant et après le démarrage des traces qui en ont une, une demande par ligne (JCS intégral)
    <trace>.epoque-<n>.ndjson                     fichiers d'époque relus ensemble (bascule-epoque, EX-8.5 règle 6)
  cout/
    cout.json                    famille cout (#/$defs/cas_cout) : les onze cas de 12.3
  completude/
    completude.json              famille completude (#/$defs/cas_completude) : six cas d'EX-10.7 (AN-61)
  verificateur-independant/      module Go, jamais écrit par le générateur (A.5)
  confrontation/                 programmes et sorties tiers, jamais écrits par le générateur (A.6)
```

### A.4 Familles

| Famille | Cas | Règles exercées | Attendu |
|---|---|---|---|
| `requetes` | `requete-point-k2` (EX-5.1 : 69 octets, nonce `0x74a6f4979421411e`) ; `point-k2-exemple` (69 octets, nonce `0x018032ff0d74cfda`, SHA-256 `0x6f69038e3ba10962a7b6af72d5366e4b04946a9cf06aa2bb17d818bbc6ef736a`) ; `point-k2-exemple-politique-interne` (81 octets, `reqPolicy` `1.3.6.1.4.1.99999.1.1`) ; `periode-1-reference` (70 octets : nonce `0xf144cca6ec50dcdb` à bit haut, octet `00` de tête dans l'INTEGER) ; `periode-1-reference-tentative-2` (70 octets, nonce `0xe514f7e31f6ba99e`) ; `periode-1-vecteurs` (69 octets, nonce `0x29ccc3c9db80e87b`) ; cas refusés par le constructeur : condensé de 31 octets, nonce nul, nonce encodé avec un zéro superflu, `certReq` faux (EX-5.1, AN-5, AN-6) | EX-5.1, EX-5.3, EX-8.6 | octets DER exacts ; `openssl ts -query -in -text` lit `Version: 1`, `Hash Algorithm: sha256`, les 32 octets, `Policy OID`, `Nonce`, `Certificate required: yes` (A.6) |
| `reponses` | réponse `granted` de l'autorité de test à chaque requête de `requetes/` (`genTime` fixé, `serialNumber` 1001 et suivants, `accuracy` 1 s ; pour `requete-point-k2`, le jeton de CT-1 §11.2 lui-même) ; `granted` avec nonce différent ; `granted` sans nonce ; `granted` sur une autre empreinte ; `granted` avec une politique hors `accepted_policies` ; rejet `unacceptedPolicy` (50 octets) ; rejet `badAlg` ; `waiting` (statut 3) ; statut 5 ; jeton dont T-6 échoue (signature altérée) ; réponse HTTP représentée 503 avec `Retry-After: 30`, 429, 408, 404, 401, corps de plus de 128 Kio ; réponse arrivée après `max_response_delay_s` (une, deux, puis trois fois) ; `genTime` hors `clock_tolerance_s` | EX-5.10 à EX-5.12, AN-8 à AN-11 | issue d'EX-5.13 (`obtenue`, `echec_transitoire`, `echec_permanente`, `reponse_tardive`), code d'EX-5.10 (`statut_2`, `echec_unacceptedPolicy`, `nonce_absent`, `nonce_different`, `empreinte_differente`, `politique_refusee`, `verification_T-6`, `reponse_tardive`, `http_503`…), avertissement `horloge_suspecte`, attente de reprise ; `openssl ts -verify -queryfile` : « Verification: OK » ou « nonce mismatch » (A.6) |
| `ots` | `point-k2-minimal.ots`, l'exemple d'EX-6.4 (195 octets, deux attestations en attente sœurs, triées par URI comme la bibliothèque officielle) ; `point-k2-en-attente.ots` (233 octets : deux branches de calendrier à opérations propres, A.2) ; `periode-1-en-attente.ots` ; paire de mise à niveau | EX-6.2 à EX-6.7, AN-17 à AN-19, EX-8.11 | octets exacts ; lecture par `ots.mjs` : O-1 à O-3 réussies, O-7 `non_execute` (`partie_absente`) ; réécriture identique par la bibliothèque officielle (A.6) |
| `planification` | les vingt et une traces de 8.10 et A.3 | EX-4.1 à EX-4.7, EX-5.7, EX-5.10, EX-5.11, EX-5.12, EX-6.1, EX-8.3 à EX-8.12, EX-9.5 ; AN-2, AN-4, AN-12, AN-13 et les AN- des sections 8, 9 et 11 | `expected` et `queue_after` reproduits à l'identique par `rejouerTrace` |
| `reprise` | files avant et après `demarrage` (six traces), fichiers d'époque | EX-8.5 (règle 6), EX-8.12, AN-33 | lignes finales égales ; une seule demande par `id` ; fusion des époques par `lireFiles` |
| `cout` | les onze cas de 12.3 | EX-4.11, EX-12.1, EX-12.2, AN-4 | six grandeurs par cas ; avec `a = 1`, égalité avec la table de 4.6 |
| `completude` | `serie-publiee-complete`, `serie-reecrite-ancres-orphelines`, `ancres-hors-ordre`, `periode-suivante-dans-la-fenetre`, `periode-suivante-non-servie`, `emetteur-doctype-et-fenetre` | EX-10.7, AN-61 | `complete`, `orphans`, `out_of_order`, `attached` reproduits par `verifierCompletudeRegistre` |

### A.5 Vérificateur Go indépendant

**EX-A.4** Le module `spec/vecteurs/ct-5/verificateur-independant`
(`noortrace-ct5`, `go 1.24`, bibliothèque standard seulement) est écrit
depuis la seule spécification (CT-5, et CT-1 §10.5 à §10.7 et CT-6 §9 et §10
pour ce qu'ils définissent), sans lire `scripts/` ni `test/`, comme ceux de
CT-1 à CT-4 ; il PEUT copier les fichiers de keccak256, JSON et JCS de ces
modules en le disant en tête de fichier. Il recalcule : les `TimeStampReq`
DER (famille `requetes`, octet pour octet, EX-5.1) ; la lecture d'une
`TimeStampResp` (statut, `failureInfo`, extraction du `TimeStampToken`, nonce,
`messageImprint`, `genTime`, `accuracy`) et le classement d'EX-5.10 à EX-5.12
(famille `reponses`) ; la lecture et l'écriture des `.ots` en attente (famille
`ots`, EX-6.4) ; les échéances et comptages de la section 4 (EX-4.2, EX-4.3,
EX-4.11) ; le planificateur de la section 8 comme machine à états
déterministe, rejouant chaque trace (famille `planification`) et chaque file
(famille `reprise`) ; la formule de coût (famille `cout`). Il s'exécute par
`go run . ..` depuis son répertoire et rend `0` si tout concorde, `1` s'il
trouve une discordance, qu'il liste, `2` pour un usage incorrect. Les
vérifications T- qu'une réponse exige sont, pour ce module, des entrées de la
trace (résultats déclarés) : il ne réimplémente pas CT-6, dont le module de
`ct-1` ne couvre pas non plus les contrôles 4, 5 et 8. Il recalcule aussi la
famille `completude` (EX-10.7) et fusionne les fichiers d'époque de `reprise/` ;
l'absence d'un `attendu.json` annoncé est une erreur, non une note. Indépendance
(révision 0.2) : le module a été écrit depuis la spécification, puis audité et
complété lors de la correction de la révision 0.2 par un rédacteur qui avait lu
la référence ; son indépendance repose sur cette déclaration, que son
`README.md` répète.

### A.6 Confrontation par des implémentations tierces

**EX-A.5** `confrontation/` porte les programmes et leurs sorties publiées
(`sorties/*.txt`), chaque sous-répertoire avec son `LISEZMOI.md` (commande,
versions, limites) :

| Famille | Outil tiers | Ce qu'il confirme |
|---|---|---|
| `requetes/` | OpenSSL 3.0.13, `openssl ts -query -in <fichier>.tsq -text` | version, algorithme, les 32 octets du condensé, `Policy OID`, `Nonce`, `Certificate required` de chaque requête (EX-5.1) ; `openssl asn1parse` : structure DER, `NULL` explicite dans l'`AlgorithmIdentifier`, INTEGER du nonce (9 octets avec `00` de tête pour un bit haut à 1) ; `openssl ts -verify -queryfile requete-point-k2.tsq -token_in -in <jeton de CT-1 §11.2>` « Verification: OK » |
| `reponses/` | OpenSSL 3.0.13, `openssl ts -reply -in <fichier>.tsr -text`, `openssl ts -verify -queryfile <requête> -in <réponse> -CAfile ac-test.pem -untrusted tsa-test.pem`, `openssl ts -reply -token_out` | statut, `failureInfo`, champs de `TSTInfo` ; « Verification: OK » pour une réponse `ok` et « nonce mismatch » pour un nonce différent ; jeton extrait égal au `.der` publié ; sur les jetons des nouveaux dossiers de CT-6 révision 0.2 (`points-de-controle.json`), `openssl ts -verify -digest <checkpoint_hash> -token_in` « Verification: OK » (confrontation de CT-6, A.8) |
| `ots/` | `python-opentimestamps` 0.4.5 (paquet PyPI `opentimestamps`, LGPL-3.0 ou ultérieure), hors ligne : `DetachedTimestampFile.deserialize`, `assert_eof`, `serialize`, `all_attestations` | lecture de chaque `.ots`, fin de fichier exacte, empreinte, attestations en attente avec leur URI, **réécriture octet pour octet identique** (l'ordre des branches est celui de la bibliothèque : attestations puis opérations, triées) |
| `coherence/` | `transparency-dev/merkle` v0.0.2 (module Go épinglé par `go.sum`), `proof.VerifyConsistency` | preuves de cohérence de `spec/vecteurs/ct-1/merkle/coherence.json` et des séries `points-de-controle/` (CT-1 §10.7) : acceptées et refusées comme l'attendu ; limite décrite : la bibliothèque accepte une preuve depuis `size1 = 0`, que CT-1 §10.7 rejette (annexe B de CT-1) |
| `planification/`, `cout/`, `completude/` | aucun outil tiers : la confrontation est celle du module Go (A.5) | — |

Une limite d'un outil n'est pas une discordance et est décrite dans le
`LISEZMOI.md` ; `test/confrontation.test.js` exige que les sorties publiées
portent sur les vecteurs du dépôt (SHA-256 des fichiers, cas, aucune
discordance) ; la CI rejoue `requetes`, `reponses`, `ots` et `coherence`
(job `confrontation` : OpenSSL présent, `pip install opentimestamps==0.4.5`
dans un environnement virtuel comme pour CT-6 A.8, Go installé par
`setup-go` et module `transparency-dev/merkle` téléchargé par le mandataire de
modules). La concordance est
la condition de publication des vecteurs, comme pour CT-1 §13 et CT-6 A.8.

### A.7 Tests et intégration continue

**EX-A.6** `test/ancrage.test.js` (lancé par `npm test`) régénère les vecteurs
dans un répertoire temporaire et exige les mêmes octets ; rejoue chaque
famille par `scripts/lib/ancrage.mjs` ; valide chaque exemple annoté
`<!-- schema: ancrage -->` (EX-4.8) et `<!-- schema: planificateur-ancrage -->`
(8.10) de cette spécification contre son schéma (`validerSchema` de
`journal.mjs`, dont `motsClesHorsSousEnsemble` rend une liste vide sur ces
deux schémas) ; vérifie que la projection d'EX-8.2 de l'exemple d'EX-4.8, où
`provider_role` vaut `interne` et `calendars` les deux calendriers d'A.2, est le
`config` de la trace de référence ; vérifie sur la trace de 8.10 que chaque
`request_sha256` est celui de la requête reconstruite avec le nonce indiqué ;
lit les `.ots` avec `ots.mjs` (O-1 à O-3 réussies, O-7 `non_execute`) ;
exécute la formule de coût sur les onze cas ; vérifie que les 40 dossiers de
CT-1 et les 50 de CT-6 gardent leur verdict (aucun fichier de ces familles ne
change) ; et qu'aucun fichier de données de `spec/vecteurs/ct-5/` (sorties
de confrontation comprises ; sources et documents de `verificateur-independant/`
et de `confrontation/` exceptés) ne contient les chaînes `price`, `password`,
`credential`, une adresse IP ni une clé privée. Exemption : les noms de champs
`unit_price_qualified` et `unit_price_second_rank` de la famille `cout`,
imposés par `$defs/cas_cout`, et leurs homologues du module Go (`UnitPrice*`),
qui portent des unités symboliques (AN-60), jamais un prix.

**EX-A.7** L'intégration continue régénère `spec/vecteurs/ct-5` et exige
`git diff --exit-code` et aucun fichier non suivi, puis lance dans le module
Go `gofmt -l` (sortie vide), `go vet ./...`, `go test ./...` et `go run . ..`,
à côté des tâches de CT-1, CT-2, CT-3, CT-4 et CT-6 ; ce job n'accède pas au
réseau. Le job `confrontation` (A.6) installe `opentimestamps` épinglé et
télécharge le module Go épinglé (`go.sum`) : c'est la seule étape qui accède
au réseau. Aucune étape n'exécute le binaire noorcore. Dans le job `tests`, le
rejeu Go de `test/confrontation.test.js` est sauté quand Go est absent, et le
job `confrontation` le fait.

### A.8 Récapitulatif des vérifications AN-1 à AN-61

| Id | Objet | Section |
|---|---|---|
| AN-1 | Configuration `ancrage-v0` et règles hors schéma | 4.4 |
| AN-2 | Échéances, points sélectionnés, délais `d_registre` et `d_jeton`, échéances `remplacee`, constat de cadence, alertes `jeton_anterieur_au_point` et `contresignature_tardive` | 4.2, 3.3 |
| AN-3 | Admission d'un objet à ancrer (signature, série, racine et `last_hash`, empreinte) | 4.2 |
| AN-4 | Points à ancrer au registre ; comptages par heure, jour, an | 4.3, 4.6 |
| AN-5 | Requête `TimeStampReq` DER exacte | 5.1 |
| AN-6 | Nonce | 5.1 |
| AN-7 | Transport HTTP | 5.2 |
| AN-8 | Lecture de la réponse, `PKIStatus` | 5.4 |
| AN-9 | Égalités empreinte, nonce, politique ; T-1 à T-10 à l'acquisition | 5.4 |
| AN-10 | Fraîcheur et horloge | 5.4 |
| AN-11 | Classement des erreurs et attente de reprise | 5.4 |
| AN-12 | Choix du prestataire et relève | 5.3 |
| AN-13 | Jeton retenu | 5.3 |
| AN-14 | Enregistrement d'acquisition et stockage | 5.4, 5.5 |
| AN-15 | Conservation | 5.5 |
| AN-16 | Objet horodaté OpenTimestamps | 6.1 |
| AN-17 | Soumission aux calendriers | 6.2 |
| AN-18 | Fichier `.ots` | 6.3 |
| AN-19 | Mise à niveau | 6.4 |
| AN-20 | Fichier d'en-têtes Bitcoin | 6.5 |
| AN-21 | Remise au dossier | 6.6 |
| AN-22 | EKU `timeStamping` critique et unique du serveur interne | 7.2 |
| AN-23 | condensés SHA-2 seulement, `badAlg` sinon | 7.2 |
| AN-24 | précision déclarée, arrêt au-delà | 7.2 |
| AN-25 | nonce repris à l'identique | 7.2 |
| AN-26 | numéro de série unique et croissant | 7.2 |
| AN-27 | TLS et authentification du client, adresse locale admise | 7.2 |
| AN-28 | journal des jetons émis hors du serveur | 7.2 |
| AN-29 | politique privée, `unacceptedPolicy` sinon | 7.2 |
| AN-30 | certificat inclus, `ESSCertIDv2` SHA-256 | 7.2 |
| AN-31 | clé et validité de l'unité, CRL publiée | 7.2 |
| AN-32 | écriture avant envoi | 8.11 |
| AN-33 | une demande par `id`, reprise au démarrage | 8.11 |
| AN-34 | transitions d'état | 8.11 |
| AN-35 | échéances et sélection des points | 8.11 |
| AN-36 | ordre des ancres | 8.11 |
| AN-37 | attente de reprise | 8.11 |
| AN-38 | relève | 8.11 |
| AN-39 | priorité et `min_interval_ms` | 8.11 |
| AN-40 | registre : capture, squat, inclusion tardive | 8.11 |
| AN-41 | OpenTimestamps : états et mise à niveau | 8.11 |
| AN-42 | rejeu des traces | 8.11 |
| AN-43 | aucun secret dans la file ni le journal | 8.11 |
| AN-44 | empreinte d'ancre d'un point | 9.4 |
| AN-45 | `docType` du point et de la période | 9.4 |
| AN-46 | émetteur de l'ancre | 9.4 |
| AN-47 | transaction conforme, gaz borné | 9.4 |
| AN-48 | capture avant `obtenue` | 9.4 |
| AN-49 | rattrapage : dernier point, `remplacee` | 9.4 |
| AN-50 | pièces du dossier égales aux fichiers promus | 10.3 |
| AN-51 | point couvrant et partie `points-de-controle.json` | 10.3 |
| AN-52 | référence `registry` et `registre.json` | 10.3 |
| AN-53 | réexport | 10.3 |
| AN-54 | fiche de prestataire | 10.3 |
| AN-55 | qualification du principal et du secours | 11.4 |
| AN-56 | exploitants distincts | 11.4 |
| AN-57 | épreuve d'acceptation datée | 11.4 |
| AN-58 | `min_interval_ms` respecté | 11.4 |
| AN-59 | formule de coût et comptages | 12.5 |
| AN-60 | aucun prix réel | 12.5 |
| AN-61 | complétude au registre (révision 0.2) | 10.3 |

## Annexe B — Sources des faits externes

Les renvois R1 et R2 désignent deux notes de recherche du lot CT-5, internes
et non publiées, relues le 2026-10-25 sur les sources primaires qu'elles
citent : R1 (prestataires RFC 3161, serveurs internes, OpenTimestamps,
reprise), R2 (points de contrôle, cohérence RFC 9162, témoins, stockage
inaltérable, dépôt). Cette annexe donne, pour chaque fait et chaque point non
vérifié que cette spécification cite, l'objet et les sources primaires ; ces
sources font foi, pas la note. Un fait marqué « non vérifié » le reste. B.3
donne les lectures et essais faits pour cette spécification hors des notes.
Conventions de CT-4 annexe B : « présent dépôt » désigne un fichier de ce dépôt
public ; « essai de cette spécification » une manipulation faite pour cette
spécification, dont les sorties ne sont pas publiées sauf mention dans l'annexe
A.

### B.1 R1 — Prestataires RFC 3161, serveurs internes, OpenTimestamps, reprise

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R1-F1, R1-F2 | nonce : fraîcheur, présence et égalité obligatoires dans le jeton | https://www.rfc-editor.org/rfc/rfc3161.txt (§2.4.1, §2.4.2) | 2026-10-25 |
| R1-F3 | obligations du demandeur à la réception (statut, empreinte, certificat, nonce ou horloge locale, politique) | https://www.rfc-editor.org/rfc/rfc3161.txt (§2.2) | 2026-10-25 |
| R1-F4, R1-F5 | `certReq` et `reqPolicy` | https://www.rfc-editor.org/rfc/rfc3161.txt (§2.4.1, §2.4.2) | 2026-10-25 |
| R1-F6, R1-F7 | `PKIStatus`, `PKIFailureInfo` | https://www.rfc-editor.org/rfc/rfc3161.txt (§2.4.2) | 2026-10-25 |
| R1-F8 | `messageImprint`, refus `badAlg`, extension inconnue | https://www.rfc-editor.org/rfc/rfc3161.txt (§2.4.1) | 2026-10-25 |
| R1-F9 | transport HTTP, types de contenu, absence de règle de reprise | https://www.rfc-editor.org/rfc/rfc3161.txt (§3.4) | 2026-10-25 |
| R1-F10, R1-F11, R1-F12 | `serialNumber`, `genTime`, `accuracy`, EKU `id-kp-timeStamping` critique, ESSCertID | https://www.rfc-editor.org/rfc/rfc3161.txt (§2.3, §2.4.2) | 2026-10-25 |
| R1-F13 | sécurité : re-horodatage, réponse tardive suspecte, corrélation d'empreintes | https://www.rfc-editor.org/rfc/rfc3161.txt (§4) | 2026-10-25 |
| R1-F14, R1-F15 | ESSCertIDv2, `SigningCertificateV2` | https://www.rfc-editor.org/rfc/rfc5816.txt ; https://www.rfc-editor.org/rfc/rfc5035.txt | 2026-10-25 |
| R1-F16 | tailles mesurées de requêtes et de réponses | essai de la note, OpenSSL 3.0.13 (aucune URL ; sorties non publiées) | 2026-10-25 |
| R1-F17 à R1-F24 | politique d'horodatage ITSF 3.3 (eIDAS, Autriche) : OID, conformité ETSI, TSU, exactitude 500 ms, formats de requête et de jeton, algorithmes, disponibilité, authentification | https://w3.swissdigicert.ch/TP_TSA_2_16_756_1_83_de.pdf | 2026-10-25 (document du 10.10.2023) |
| R1-F25 | politique d'horodatage ZertES 1.3, production via la filiale autrichienne | https://w3.swissdigicert.ch/TP_TSA_2_16_756_1_83_de.pdf (seconde partie) | 2026-10-25 |
| R1-F26, R1-F39 | liste de confiance autrichienne : services QTST `granted` des deux prestataires, séquence 75 | https://www.signatur.rtr.at/vertrauensliste.xml | 2026-10-25 (liste du 2026-06-15) |
| R1-F27 | annonce du statut qualifié eIDAS de la filiale | https://trustservices.swisscom.com/en/about-us/news/swisscom-becomes-issuer-of-an-eu-eidas-qualified-time-stamp | 2026-10-25 |
| R1-F28 | certificat de reconnaissance ZertES n° 272/2025, validité jusqu'au 04.11.2028 | https://trustservices.swisscom.com/hubfs/Zertifikat_Swisscom_ZertES_2025_Nr.272_V1.2_signed.pdf | 2026-10-25 |
| R1-F29 à R1-F34 | guide de référence AIS 2.15 : horodatages qualifiés RFC 3161 encapsulés, point d'accès, sessions, authentification, condensés, lots, mode asynchrone, codes de résultat | https://trustservices.swisscom.com/hubfs/Website%20Files/Documents/Developer%20Documentation/Reference_Guide-All-in-Signing-Service-en.pdf | 2026-10-25 |
| R1-F35 | interface RFC 3161 de P2 : POST, GET, `application/timestamp-query`, Basic, en-têtes de corrélation, algorithmes | https://docs.a-trust.at/apis/Timestamp/ ; https://docs.a-trust.at/apis/Timestamp/CommunicationInterface | 2026-10-25 |
| R1-F36 | spécification OpenAPI : serveurs de test et de production, réponse 200 | https://docs.a-trust.at/swagger/Timestamp.yaml | 2026-10-25 |
| R1-F37 | système de test, identifiants publics, exemple `openssl ts`, jetons de test non validables | https://docs.a-trust.at/apis/Timestamp/testsystem ; https://docs.a-trust.at/apis/Timestamp/Example ; https://github.com/A-Trust/TimestampClient | 2026-10-25 |
| R1-F38 | politique de certification 1.0.4 : OID, ETSI EN 319 421, algorithmes, exactitude 1 s | https://a-trust.at/downloads/de/Certificate%20Policies/_Archiv/a-sign-premium-timestamp/a-sign-premium-timestamp_cp.pdf | 2026-10-25 (document du 14.12.2022) |
| R1-F40 | conditions générales 1.2 : facturation d'avance, durée minimale, liste de prix (aucun prix relevé) | document des conditions générales du prestataire P2 pour les horodatages qualifiés, version 1.2, août 2024 (URL non recopiée dans la note) | 2026-10-25 |
| R1-F41, R1-F42 | prestataire polonais : point d'accès Basic ; liste de confiance PL | https://www.files.certum.eu/documents/manual_en/Qualified%20Time%20Stamp%20-%20configuration%20and%20activation%20instructions_2020.pdf ; https://www.nccert.pl/tsl/PL_TSL.xml | 2026-10-25 |
| R1-F43, R1-F44, R1-F45 | prestataire néerlandais : déclaration TSA 1.11 (nonce, `reqPolicy`, `certReq`, algorithmes, liste de confiance), politique 2.13 (TCP ou HTTP, disponibilité), liste de confiance NL | https://www.digicert.com/content/dam/digicert/pdfs/legal/quovadis/archive/2023/qv-tsa-disclosure-statement-1.11-approved.pdf ; https://www.digicert.com/content/dam/digicert/pdfs/legal/quovadis/qv-tspps-v2-13-en.pdf ; https://www.rdi.nl/site/binaries/content/assets/site-content/bestanden/current-tsl.xml | 2026-10-25 |
| R1-F46, R1-F47 | prestataire allemand : fiche produit ; liste de confiance DE | https://www.d-trust.de/files/dokumente/pdf/produktblatt_qualifizierte_zeitstempel.pdf ; https://tl.bundesnetzagentur.de/TL-DE.xml | 2026-10-25 |
| R1-F48 | liste des listes de l'Union, type de service QTST, statut `granted` | https://ec.europa.eu/tools/lotl/eu-lotl.xml | 2026-10-25 (séquence 397, 2026-10-15) |
| R1-F49 | `openssl ts` : pas de serveur HTTP, `serial` non verrouillé, options, nonce recommandé | https://docs.openssl.org/master/man1/openssl-ts/ | 2026-10-25 |
| R1-F50 | `openssl ts -reply` : `signer_digest` requis, rejet SHA-1 `badAlg`, politique refusée, aucun journal | essai de la note, OpenSSL 3.0.13 (aucune URL) | 2026-10-25 |
| R1-F51, R1-F52 | uts-server : README, configuration de test (ports, `throttle`, TLS client, `digests` incluant MD5 et SHA-1) | https://raw.githubusercontent.com/kakwa/uts-server/master/README.rst ; https://raw.githubusercontent.com/kakwa/uts-server/master/tests/cfg/uts-server.cnf ; https://uts-server.readthedocs.io/ | 2026-10-25 |
| R1-F53, R1-F54 | sigstore timestamp-authority : README, vérifications du nonce, de l'empreinte et de l'EKU | https://raw.githubusercontent.com/sigstore/timestamp-authority/main/README.md ; https://raw.githubusercontent.com/sigstore/timestamp-authority/main/pkg/verification/verify.go | 2026-10-25 |
| R1-F55 | ce qu'un serveur interne ne prouve pas (source de temps « trustworthy », qualification par liste de confiance) | https://www.rfc-editor.org/rfc/rfc3161.txt (§2.1) ; déclaration TSA 1.11 ci-dessus | 2026-10-25 |
| R1-F56, R1-F57 | calendriers et agrégateurs par défaut ; calendriers publics « free to use » ; page d'état | https://raw.githubusercontent.com/opentimestamps/python-opentimestamps/master/opentimestamps/calendar.py ; https://opentimestamps.org/ ; http://uptime.opentimestamps.net/ | 2026-10-25 |
| R1-F58, R1-F59 | README du client (heures de confirmation, horodatage incomplet, mise à niveau, cache) ; annonce (promesses du calendrier, déni de service sans fausse preuve, point de défaillance central) | https://raw.githubusercontent.com/opentimestamps/opentimestamps-client/master/README.md ; https://petertodd.org/2016/opentimestamps-announcement | 2026-10-25 |
| R1-F60 | `PendingAttestation` : URI seule, étiquette `83dfe30d2ef90c8e`, longueur maximale 1000 ; attestation Bitcoin `0588960d73d71901` | https://raw.githubusercontent.com/opentimestamps/python-opentimestamps/master/opentimestamps/core/notary.py | 2026-10-25 |
| R1-F61, R1-F62 | options du client (`-w`, `--wait-interval 30`, `--timeout 5`, `-m 2`), écriture exclusive, `.bak`, boucle de mise à niveau | https://raw.githubusercontent.com/opentimestamps/opentimestamps-client/master/otsclient/args.py ; https://raw.githubusercontent.com/opentimestamps/opentimestamps-client/master/otsclient/cmds.py | 2026-10-25 |
| R1-F63, R1-F64 | protocole du calendrier : `POST /digest`, `GET /timestamp/<hex>`, 404 en attente, `Cache-Control` 60 s puis un an, 64 octets, 10 000 octets | https://raw.githubusercontent.com/opentimestamps/python-opentimestamps/master/opentimestamps/calendar.py ; https://raw.githubusercontent.com/opentimestamps/opentimestamps-server/master/otsserver/rpc.py ; …/otsserver/stamper.py | 2026-10-25 |
| R1-F65, R1-F66 | journal du calendrier `fsync` avant réponse, agrégation 1 s ; intervalle de transaction 6 h × [1, 2], six confirmations | https://raw.githubusercontent.com/opentimestamps/opentimestamps-server/master/otsserver/calendar.py ; https://raw.githubusercontent.com/opentimestamps/opentimestamps-server/master/otsd ; …/otsserver/stamper.py | 2026-10-25 |
| R1-F67 | aucune limite de débit publiée | constat négatif sur les sources R1-F56 à R1-F66 | 2026-10-25 |
| R1-F68, R1-F69 | RFC 9162 : 500/503 rejouables, `Retry-After`, 4xx non rejoués ; même SCT pour une soumission déjà vue ; RFC 6962 | https://www.rfc-editor.org/rfc/rfc9162.txt (§4) ; https://www.rfc-editor.org/rfc/rfc6962.txt | 2026-10-25 |
| R1-F70 | client de Certificate Transparency : 408 immédiat, 429 et 503 avec backoff et gigue, `Retry-After`, échéance de l'appelant | https://raw.githubusercontent.com/google/certificate-transparency-go/master/jsonclient/client.go | 2026-10-25 |
| R1-F71 | Rekor : 409 sur une entrée existante | https://raw.githubusercontent.com/sigstore/rekor/main/openapi.yaml | 2026-10-25 |
| R1-F72, R1-F73 | pratiques « écriture avant envoi » ; aucune recommandation de reprise chez les prestataires | synthèse de la note sur R1-F35, R1-F62, R1-F65, R1-F69, R1-F71 ; constat négatif sur les documents de prestataires ci-dessus | 2026-10-25 |
| R1, conséquences 1 et 7 | fraîcheur par l'horloge locale quand un canal ne transmet pas le nonce (EX-5.16) ; nouveau nonce à chaque tentative et délai maximal d'acceptation (EX-5.3, EX-5.11) | synthèse de la note sur R1-F1 à R1-F3, R1-F13, R1-F68, R1-F70 | 2026-10-25 |
| R1, points non vérifiés NV-1 à NV-12 | voir B.4 | — | — |

### B.2 R2 — Points de contrôle, cohérence, témoins, dépôt

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R2-F7 | algorithme de vérification de la preuve de cohérence RFC 9162 §2.1.4.2, reproduit par CT-1 §10.7 (K-5 ; 3.4, 13) | https://www.rfc-editor.org/rfc/rfc9162.txt (§2.1.4.2) | 2026-10-25 |
| R2-F13 | cas de bord du vérificateur de référence de la preuve de cohérence (tailles, preuve vide) | https://raw.githubusercontent.com/transparency-dev/merkle/main/proof/verify.go ; https://raw.githubusercontent.com/transparency-dev/merkle/main/proof/proof.go | 2026-10-25 |
| R2-F21 | un signataire ne signe jamais un point incohérent avec un point qu'il a signé | https://raw.githubusercontent.com/C2SP/C2SP/main/tlog-checkpoint.md (stable : https://c2sp.org/tlog-checkpoint) | 2026-10-25 |
| R2-F22 | signatures admises sur un point (ML-DSA-44, Ed25519) | même source | 2026-10-25 |
| R2-F26 | sens d'une cosignature (cohérence avec toutes les vues observées, monotonie) | https://raw.githubusercontent.com/C2SP/C2SP/main/tlog-cosignature.md | 2026-10-25 |
| R2-F27, R2-F28 | protocole de témoin (409, 422, persistance avant réponse) ; pratique publiée | https://raw.githubusercontent.com/C2SP/C2SP/main/tlog-witness.md ; https://raw.githubusercontent.com/transparency-dev/witness/main/README.md | 2026-10-25 |
| R2-F29 à R2-F34 | stockage à verrou d'objet S3 : modèle WORM, versionnage et protection par version, mode sans contournement (« compliance »), mode à contournement nominatif (« governance »), rétention prolongeable seulement, effet d'une suppression (EX-5.15, P-6) | https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html | 2026-10-25 |
| R2-F35 | activation irréversible du verrou, rétention par défaut d'un compartiment | https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-configure.html | 2026-10-25 |
| R2-F36 | ce qu'un réviseur peut lire d'un objet verrouillé (mode, date de rétention), rendu par l'API sans signature : déclaratif (EX-5.15, P-6 ; CT-6 §7.9) | https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectRetention.html | 2026-10-25 |
| R2-F37 | stockage immuable Azure Blob (politiques de rétention, verrouillage de la politique) | https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview | 2026-10-25 |
| R2-F38, R2-F39 | Google Cloud Storage : verrou de compartiment, verrou de rétention par objet | https://docs.cloud.google.com/storage/docs/bucket-lock ; https://docs.cloud.google.com/storage/docs/object-lock | 2026-10-25 |
| R2-F40 | MinIO : verrouillage d'objets (documentation communautaire) | https://docs.min.io/community/minio-object-store/administration/object-management/object-retention.html | 2026-10-25 |
| R2-F45 | empreinte d'ancre et `docType` : `keccak256(utf8(libellé))`, un libellé nouveau pour un sens nouveau, unicité d'une empreinte sur la chaîne (EX-9.1, EX-9.2, 13) | présent dépôt, `spec/CT-1-evenements-et-formats.md` §10.4, `spec/CT-4-registre.md` §6.4 à §6.6 | 2026-10-25 |
| R2-F52 | contrôle 4 de CT-6 à empreinte paramétrée ; nonce non contrôlé par le vérificateur | présent dépôt, `spec/CT-6-verificateur.md` §9, `scripts/lib/horodatage.mjs` | 2026-10-25 |
| R2-F53 | exigences de CT-6 §13 imposées à CT-5 | présent dépôt, `spec/CT-6-verificateur.md` §13 | 2026-10-25 |
| R2-F57 | CT-2 : ancrage jamais bloquant, configuration `anchoring`, horloge | présent dépôt, `spec/CT-2-enregistreur.md` §14.2, §15, EX-7.9, EX-7.10, EX-11.17 | 2026-10-25 |
| R2-F58 | CT-2 : copies WORM, `sha256` et non ETag | présent dépôt, `spec/CT-2-enregistreur.md` §12.6 | 2026-10-25 |
| R2-F59 | CT-4 : ordre des opérations d'une période, unicité par position, journal de remplacement | présent dépôt, `spec/CT-4-registre.md` §8.2, EX-8.19, §11.3 | 2026-10-25 |
| R2-F60 | architecture : contresignature interne « à la minute » en option | présent dépôt, `ARCHITECTURE.md`, « Ancrage » et « Modèle de menace » | 2026-10-25 |
| R2, conséquences 19 à 22 | fenêtre de réécriture, ce que chaque pièce borne, borne inférieure absente | synthèse de la note sur CT-6 §3.4, §7.2 et RFC 9162 (présent dépôt ; https://www.rfc-editor.org/rfc/rfc9162.txt) | 2026-10-25 |

### B.3 Lectures et essais pour cette spécification, hors des notes

| Fait | Règle | Source ou essai | Date |
|---|---|---|---|
| Une `TimeStampReq` construite octet pour octet d'après la section 5 (version 1, `AlgorithmIdentifier` SHA-256 à `NULL` explicite, nonce de 64 bits, `certReq` TRUE) fait 69 octets pour un nonce sans bit haut, 70 avec (`00` de tête), 81 avec `reqPolicy` `1.3.6.1.4.1.99999.1.1` ; `openssl ts -query -in -text` en lit la version, l'algorithme, le condensé, la politique, le nonce et `Certificate required: yes` ; `openssl ts -query -digest … -sha256 -cert` produit 59 octets sans nonce et 70 avec un nonce à bit haut | EX-8.6, A.4, A.6 | essai de cette spécification, OpenSSL 3.0.13 (`openssl ts -query`, `asn1parse`), requêtes de la famille `requetes` | 2026-10-25 |
| `openssl ts -reply` configuré comme un serveur interne (`signer_digest = sha256`, `ess_cert_id_alg = sha256`, `accuracy = secs:1, millisecs:0, microsecs:0`) avec les clés de test de CT-6 répond `granted` (3164 octets avec l'unité et l'AC, jeton extrait de 3155 octets) à une requête de 69 octets sur l'empreinte du point `K2` (nonce de CT-1 §13) ; `openssl ts -verify -queryfile` rend « Verification: OK » ; la même réponse confrontée à une requête dont le nonce diffère d'une unité rend « nonce mismatch » ; une requête portant une politique inconnue reçoit un rejet de 50 octets « the requested TSA policy is not supported by the TSA » | EX-7.4, AN-25, AN-29, A.6 | essai de cette spécification, OpenSSL 3.0.13, `spec/vecteurs/ct-6/rfc3161/cles` (présent dépôt) | 2026-10-25 |
| `openssl ts -verify -queryfile requete-point-k2.tsq -token_in -in <jeton de CT-1 §11.2> -CAfile ac-test.pem -untrusted tsa-test.pem` rend « Verification: OK » : le jeton de 2104 octets de CT-1 §11.2 (SHA-256 `0x0a7cd7a1…9f91`) répond exactement à la requête de 69 octets d'EX-5.1 (même empreinte, même nonce `0x74a6f4979421411e`, dérivé de l'étiquette de CT-1 §13 et recalculé) ; `openssl ts -verify -digest 6a8e…e6ff -token_in` rend le même résultat | EX-5.1, A.6 | essai de cette spécification, OpenSSL 3.0.13, `spec/vecteurs/ct-6/rfc3161/cles` (présent dépôt) | 2026-10-25 |
| Le fichier `P_K ‖ C_K` du point `K2` (préfixe de 31 octets, puis `C_K` de CT-1 §10.6) fait 572 octets et son SHA-256 est le `checkpointHash` `0x6a8e035a…e6ff` | EX-6.1 | calcul pour cette spécification, JCS recalculé | 2026-10-25 |
| Les `docType` `0x72c4…2178` (point) et `0x2970…71ee` (période) sont `keccak256` des libellés `noortrace/point-de-controle/v0` et `noortrace/periode/v0` ; l'empreinte d'ancre du point `K2` est `0x7f72…4e44` (CT-1 annexe B) | EX-9.1, 4.3 | calcul pour cette spécification avec `ethers` 6 du présent dépôt | 2026-10-25 |
| Ordre de sérialisation d'un fichier `.ots` (EX-6.4) : attestations avant opérations ; attestations triées par étiquette puis, pour deux attestations en attente, par URI, pour deux attestations Bitcoin par hauteur ; opérations par code puis par argument ; `ff` entre branches | EX-6.2, EX-6.4, EX-6.6 | sources officielles lues le 2026-10-25 : `opentimestamps/core/timestamp.py` (`Timestamp.serialize`, l. 101-128), `opentimestamps/core/notary.py` (`__lt__`, l. 56-62, 133-137, 213-218), `opentimestamps/core/op.py` (`__lt__`, l. 83-89), `otsclient/cmds.py` (`stamp_command` l. 147-209, `create_timestamp` l. 48-131, `upgrade_timestamp` l. 221-336), `opentimestamps/calendar.py` | 2026-10-25 |
| Le fichier `point-k2-minimal.ots` d'EX-6.4 (195 octets, SHA-256 `0x64a62afc…a8b6`, deux promesses nues triées par URI) et le fichier `point-k2-en-attente.ots` (nonce et opérations de calendrier dérivés des étiquettes d'A.2, 233 octets, SHA-256 `0x8bdf7ed0…687a`) sont lus par `scripts/lib/ots.mjs` (O-1 à O-3 réussies, O-7 non exécutée, `partie_absente`) ; `python-opentimestamps` 0.4.5 les désérialise sans reste, rend les deux `PendingAttestation` avec leurs URI, et les resérialise octet pour octet à l'identique | EX-6.4, EX-8.11, 12.4, A.4, A.6 | essai de cette spécification, `scripts/lib/ots.mjs` (présent dépôt), `pip install opentimestamps==0.4.5` dans un environnement virtuel | 2026-10-25 |
| Deux attestations en attente **sœurs** sous un même nœud sont écrites par `ots.mjs` dans un ordre (octets de l'attestation, préfixe de longueur compris) que la bibliothèque officielle ne reproduit pas (tri par URI) : `point-k2-minimal.ots` suit l'ordre de la bibliothèque (EX-6.4, règle 2), que `ots.mjs` ne rendrait pas en écriture ; `point-k2-en-attente.ots` place chaque attestation sous les opérations de son calendrier, où les deux outils concordent ; le comparateur d'`ots.mjs` a été aligné (section 14) | A.6, EX-6.4, EX-8.11 | même essai | 2026-10-25 |
| Les `docType` `0x72c4…2178` (point) et `0x2970…71ee` (période) et l'empreinte du point `K2` n'ont aucun octet nul : la borne de 96 977 gaz par `anchor` (CT-4 §4.5) vaut pour un point | 9.3 | comptage pour cette spécification ; CT-4 §4.5 (présent dépôt) | 2026-10-25 |
| Empreintes d'ancre des points `K1` à `K4` (A.2) | EX-9.1 | calcul avec `ethers` 6 du présent dépôt (`keccak256(concat([org_id, journal_id, checkpointHash]))`), `K2` égale à CT-1 annexe B | 2026-10-25 |
| Le schéma `planificateur-ancrage-v0` n'emploie que les mots-clés de `validerSchema` ; la trace de 8.10, les familles `cout` et `requetes` et chaque ligne de `queue_after` y sont conformes ; la famille `cout` reproduit, pour `a = 1`, les maxima de la table de 4.6 | EX-8.16, EX-A.3, AN-4 | `scripts/lib/journal.mjs` (présent dépôt), `validerSchema`, `MOTS_CLES_VALIDATION` ; calcul pour cette spécification | 2026-10-25 |
| Valeurs de 12.3 et de la famille `cout` | EX-12.1, EX-12.2 | calcul pour cette spécification d'après les formules | 2026-10-25 |
| Mesures de gaz de CT-4 (`anchor` 96 977 au plus, `submitPeriod` 314 256 au plus), budget d'EX-4.19, une transaction par expéditeur et par bloc, rétention des certificats | 9.3, EX-9.8, EX-9.9 | présent dépôt, `spec/CT-4-registre.md` §4.5, EX-4.14, EX-4.19, EX-4.20, §9.5, §9.7 | 2026-10-25 |
| Partie `points-de-controle.json`, vérifications K-1 à K-9, point de contrôle, préfixes, fenêtre de réécriture | sections 9, 10, 13 | présent dépôt, `spec/CT-1-evenements-et-formats.md` §10.5 à §10.9, §11.2, §11.4 (révision 0.3) | 2026-10-25 |

### B.4 Non vérifié

Repris de la note R1 (points NV-1 à NV-12) et de la note R2, tels que cités
par cette spécification ; aucun n'est tranché ici.

| Point | Objet |
|---|---|
| NV-1 | existence d'un point d'accès RFC 3161 nu chez P1 hors de l'enveloppe AIS ; aucun nom d'hôte publié |
| NV-2 | modèle tarifaire de P1 |
| NV-3 | limites de débit ou de volume par horodatage chez P1 (seules bornes : 1500 sessions, 300 documents par lot, 15 min) |
| NV-4 | prise en charge réelle du nonce et de `certReq` via l'enveloppe de P1 |
| NV-5 | politique de P1 postérieure à 3.3, URL du dépôt de certificats des unités, liste des prestataires reconnus ZertES |
| NV-6 | P2 : CPS 1.0.4 inaccessible, nonce en production, codes d'erreur HTTP, limites de débit, disponibilité chiffrée, OID de politique inséré, modèle « par jeton », statut du certificat de conformité après le 04.02.2026 |
| NV-7 | prestataire polonais : détails techniques actuels au-delà du guide 2020 |
| NV-8 | prestataire néerlandais : noms d'hôte, déclaration TSA postérieure à 1.11, validité de la politique 2.13 après le 7 novembre 2025 |
| NV-9 | prestataire allemand : point d'accès, algorithmes, politique, authentification |
| NV-10 | ETSI EN 319 421 et 319 422 non lus ; `esi4-qtstStatement-1` cité d'après deux prestataires |
| NV-11 | OpenTimestamps : limites de débit des agrégateurs, engagements de disponibilité, délai réel de confirmation en 2026, exploitant d'un calendrier |
| NV-12 | instance publique de sigstore timestamp-authority ; page de configuration d'uts-server ; activité récente du projet uts-server |
| R2-NV3 | algorithme réellement employé par les témoins publics en 2026 |
| R2-NV7 | pratiques de témoin hors C2SP et transparency-dev |

Aucun prix, aucun identifiant de compte, aucune adresse IP et aucune clé
privée ne figurent dans cette spécification ni dans ses vecteurs ; les URL de la
configuration des traces sont des noms réservés `.example`.
