# Vecteurs de test CT-1

Produits par `scripts/vecteurs/generer-ct1.mjs` (`node scripts/vecteurs/generer-ct1.mjs`),
rejoués par `test/journal.test.js`. Tout est déterministe : rejouer le générateur
produit exactement les mêmes octets. Les clés JSON sont en anglais (formats de
CT-1) ; les descriptions, en français. Chaque répertoire porte un `attendu.json`
qui dit ce qu'un vérificateur conforme doit obtenir.

Le générateur n'écrit que les entrées décrites ici (`INDEX.md`, `cles`, `jcs`, `journal-valide`, `journal-supprime`, `journal-modifie`, `journal-insere`, `journal-insere-sans-cle`, `journal-reordonne`, `merkle`, `manifestes`, `points-de-controle`, `dossiers`),
qu'il efface et réécrit à chaque exécution ; toute autre entrée du répertoire
est laissée telle quelle (le vérificateur indépendant Go de
`verificateur-independant/`, par exemple, qui confronte tous ces vecteurs).

Les constantes des vecteurs (journal `journal-sinistres`, étiquettes de nonce
`noortrace/vecteurs/v0/nonce/journal-sinistres/periode-N`) sont celles de la
seconde table de CT-1 §13 ; elles diffèrent de celles de l'exemple de référence
de la spécification (journal `journal-principal`, annexe A).

Journal fictif : organisation `assureur-demo` (`org_id` = keccak256 du slug),
journal `journal-sinistres` (`journal_id` = keccak256 du nom), un agent qui instruit
et règle un sinistre automobile le 5 novembre 2026 entre 09:12 et 10:05 UTC.
Clés d'enregistreur `rec-test-01` puis `rec-test-02` (rotation en seq 9) ;
approbateurs : comptes 1 à 3 du mnémonique Hardhat, seuil 2 sur 3.

## `cles/`

| Fichier | Contenu |
|---|---|
| `cles-test.json` | Les deux paires Ed25519 de test (étiquette de graine, graine, clé privée PKCS#8, clé publique, validité), les trois comptes d'approbateur (mnémonique, chemin, adresse, clé privée) et les nonces des périodes, avec leur dérivation. Clés jetables et publiques. |
| `cles.json` | Les mêmes clés publiques au format `cles.json` d'un dossier (CT-1 §11.2), avec la validité annoncée : `rec-test-01` de 2026-11-01T00:00:00.000Z à 2026-11-05T09:59:58.000Z (instant de la rotation, inclus), `rec-test-02` à partir de 2026-11-05T09:59:58.000Z. |

## `jcs/`

`cas-limites.json` : les cas limites de la forme canonique JCS v0 de CT-1 §4,
chacun avec `name`, `input` (un texte JSON) et `canonical` (la forme canonique,
ou `null` si le document est invalide : nombre non entier ou hors de
l'intervalle sûr, substitut isolé, clé en double).

## `journal-valide/`

Douze événements (`evenements.json`) : échange avec le modèle (seq 1, 4, 10),
appels d'outil autorisés (seq 2, 3, 8 ; seq 2 et 3 portent des arguments en ligne),
appel retenu pour approbation (seq 5, ticket `apr-2201`, arguments rédigés
`pii-v1`), décision d'approbation signée EIP-191 par les comptes Hardhat 1 et 2
(seq 6), appel relayé après approbation (seq 7), rotation de clé contresignée
(seq 9, dernier événement de la période 1), appel refusé par la politique
(seq 11), changement de politique (seq 12). `attendu.json` : chaîne valide,
hash, signature, `prev_hash` et longueur canonique de chaque événement, objet
d'approbation `A` et son condensé `D_A`. `pieces.json` : les pièces référencées
(octets UTF-8, `sha256`, `length`). `cles.json` : les clés publiques nécessaires.

## `journal-supprime/`, `journal-modifie/`, `journal-insere/`, `journal-insere-sans-cle/`, `journal-reordonne/`

Le même journal altéré ; `attendu.json` donne la liste exacte des contrôles en
échec (`controles_en_echec`, table 7.2 de CT-1 : tous les symptômes sont
rapportés, chaque événement pour lui-même puis chaque couple consécutif dans
l'ordre du fichier), les diagnostics nommés de l'implémentation de référence
(`type`, `controle`, `seq`) et les messages produits.

| Répertoire | Altération | Contrôles en échec | Diagnostics |
|---|---|---|---|
| `journal-supprime/` | seq 4 retiré | C-1, C-2 | `suppression` (C-1) et `rupture` (C-2) en seq 5 |
| `journal-modifie/` | `intent` de seq 7 modifié, `hash` et `sig` inchangés | E-7, E-8, C-2 | `modification` (E-7) et `signature` (E-8) en seq 7, `rupture` (C-2) en seq 8 |
| `journal-insere/` | événement forgé, signé avec la clé de l'enregistreur, inséré entre seq 4 et seq 5 avec seq 5 | C-1, C-2 | `insertion` (C-1), `rupture` (C-2) et `horodatage` (C-1) en seq 5 |
| `journal-insere-sans-cle/` | même insertion, signée par une autre clé que celle annoncée | E-8, C-1, C-2 | `signature` (E-8) en plus des trois précédents |
| `journal-reordonne/` | seq 5 et seq 6 échangés de place | C-1, C-2 | `reordonnancement` (C-1) en seq 5, `rupture` (C-2) en seq 6, 5 et 7, `horodatage` (C-1) en seq 5 |

La troncature de la fin du journal n'est pas détectable par la chaîne seule
(CT-1 §7.2) : elle relève du manifeste (P-3, P-4) ; le dossier
`dossiers/invalide-periode-tronquee/` en donne le cas.

## `merkle/`

`arbres.json` : arbres RFC 6962 de 0, 1, 2, 3, 5, 8, 12 et 1000 feuilles
(feuilles, racine, preuves d'inclusion pour des indices choisis, dont le premier
et le dernier ; toutes les feuilles pour n = 5, la forme de l'exemple de
CT-1 §9.4). La période vide a la racine nulle (convention NOORTRACE de
`PeriodRegistry`), distinguée de SHA-256("") de la RFC 6962.

`coherence.json` (révision 0.3) : preuves de cohérence RFC 9162 §2.1.4 (CT-1
§10.7) entre les arbres de `arbres.json`, paires `(1, 2)`, `(2, 3)`, `(3, 5)`,
`(5, 8)`, `(8, 12)`, `(4, 8)`, `(4, 12)`, `(1, 12)`, `(12, 12)` (preuve vide), et
sondes refusées (`m = 0`, `m > n`, chemin tronqué, nœud en trop, racines
échangées, chemin vide, `m = n` avec chemin). Chaque cas donne `first_size`,
`second_size`, `first_root`, `second_root`, `path`, `valid` et `reason`.

## `manifestes/`

Trois périodes consécutives du journal : `periode-1.json` (seq 1 à 9, signé par
`rec-test-02`, clé en vigueur à la clôture puisque seq 9 est la rotation),
`periode-2.json` (seq 10 à 12), `periode-3.json` (vide : `last_seq = first_seq - 1`,
racine nulle), chacun avec sa signature `.sig`. `discontinu.json` prétend suivre
la période 1 avec `first_seq` 11 et un `prev_period_hash` faux. `attendu.json` :
forme canonique, `periodHash`, signature, `anchorFingerprint` et `PeriodMeta` de
chaque période, continuité attendue, erreurs du manifeste discontinu.

## `points-de-controle/` (révision 0.3)

Séries complètes des points de contrôle (CT-1 §10.5 à §10.8) des trois
périodes : `periode-N.json` est le tableau des points, un par minute depuis
`period_start` (cadence par défaut de 60 s, à `:00.000`, points sans nouvel
événement compris) puis le point de clôture à `generated_at` du manifeste
(`tree_size = count`) ; 61 points par période. `tree_size` compte les
événements de la période horodatés au plus tard à `checkpoint_ts` ; la clé est
celle en vigueur (règle 5 : la rotation de seq 9 à 2026-11-05T09:59:58.000Z fait signer le
point de clôture de la période 1 par `rec-test-02`) ; la période 3, vide, ne
porte que des points `tree_size = 0` dont `last_hash` est le hash de seq 12.
`attendu.json` donne, pour chaque point, `checkpoint_hash`, la forme canonique
`C_K`, le `prev_checkpoint_hash` attendu, la clé et la preuve de cohérence vers
la racine du manifeste (`null` pour `tree_size = 0`), et pour chaque série
invalide de `invalides/` (dérivée de la période 1) les règles violées
(`rules_failed` : `chainage`, `tree_size_decroissant`,
`checkpoint_ts_decroissant`, `dernier_point`, `cle_en_vigueur`,
`validite_cle`, `signature`, `last_hash`) et les erreurs de l'implémentation
de référence.

## `dossiers/`

Chaque sous-répertoire est un dossier de preuve v0 complet (les douze parties
déclarées dans `dossier.json`, les cinq parties réservées à CT-4 et CT-5
absentes avec la raison « hors périmètre CT-1 » ; révision 0.3 : les
dossiers `*-point-de-controle`, `*-partie-declaree-absente` et `invalide-k*`
déclarent une treizième partie `points-de-controle.json`, vérifications K-1 à
K-6, ancres à `null` ; révision 0.4 : les dossiers `*attestation*`,
`valide-at*` et `valide-seq-13-at7-autre-version` déclarent quatorze
parties, la quatorzième `attestation-perimetre.json`, vérifications AT-1 à
AT-7, sans effet sur le verdict, CT-7 annexe A.7) plus un fichier
`attendu.json`, étranger au dossier et ignoré par le vérificateur, qui donne le
verdict attendu : `valide`, `controle` (le contrôle visé), `controles_en_echec`
(la liste **exacte** des contrôles en échec, dans l'ordre de CT-1 §11.4) et une
description. Chaque contrôle de la table 11.4 a au moins un dossier qui le fait
échouer (CT-1 §11.5). Sauf mention contraire, les dossiers invalides sont dérivés
de `valide-seq-7` et leur index est recalculé après l'altération, pour que seul
le contrôle visé échoue ; quand une cascade est inévitable, elle est listée.
« Journal rejoué » : l'altération est faite à la source et la chaîne, les
manifestes et le dossier sont recalculés.

Révision 0.4 (CT-1 §11.5, CT-7 annexe A.7) : l'`attendu.json` d'un dossier
qui déclare la quatorzième partie donne en plus `perimeter_target` (la
vérification AT- que le dossier exerce : en échec, non exécutée avec sa raison,
ou réussie quand le cas vise un avertissement, AV-AT-2 pour
`valide-at4-jeu-different` ; `null` pour les dossiers de référence et
pour `invalide-d2-attestation-sha256`), `perimeter_checks` (statut et raison de
AT-1 à AT-7, dans l'ordre ; vide quand la partie est déclarée absente),
`perimeter_retained` (attestation retenue, CT-6 EX-6.19 ; `null` sans la
partie) et `warnings` (avertissements AV-AT-). L'attestation est celle de
CT-7 §7.1, signée par les comptes Hardhat 1 et 2 (D_P
`0x4481a2e47712539c4ca50f2eea3d6062ec11a70d497c153c1a6f707606657cfd`) ; le
« journal rejoué de CT-7 §7.5 » est `journal-valide` dont seq 12 annonce le
document de politique réduit
`{"perimeter":{"attestation_digest":D_P},"version":"2026-11-05"}` (hash
`0x5aac251a7fa898317e6fd40eae4594234960cf682e4a182cf2de0a9f65b0ef90`). Une
vérification AT- en échec ne rend jamais le dossier invalide ; seule D-2 porte
sur le fichier de la partie.

| Répertoire | Verdict attendu | Altération |
|---|---|---|
| `valide-seq-7/` | valide | Dossier de l'appel relayé après approbation (seq 7) : voisins seq 6 et seq 8, période 1 (neuf événements, clôturée par rec-test-02 après la rotation de seq 9), approbation apr-2201 des comptes Hardhat 1 et 2. Les cinq parties réservées à CT-4 et CT-5 sont absentes avec la raison « hors périmètre CT-1 ». Le contrôle A-4 est non exécuté : l'événement de demande (seq 5) n'est pas un voisin. |
| `valide-seq-6/` | valide | Dossier de la décision d'approbation (seq 6) : voisins seq 5 (la demande, retenue) et seq 7 (l'appel relayé) ; approbations.json contient l'événement prouvé lui-même (A-2) ; A-4 est exécuté, le hash recalculé de seq 5 égale request_hash et son status vaut retenue. |
| `invalide-index-seq/` | **D-1** | dossier.json annonce event.seq 8 alors que evenement.json porte seq 7 : l'index ne décrit pas l'événement du dossier. |
| `invalide-partie-nulle/` | **E-1** | evenement.json contient le littéral JSON null ; l'index le déclare présent avec son SHA-256 exact (D-2 passe). La partie est inexploitable : E-1 échoue, les contrôles qui en dépendent sont non exécutés sans raison admise, le dossier est invalide et le rapport ne reprend rien de l'index à la place de l'événement. |
| `invalide-echange-sans-reponse/` | **E-3** (en échec : E-1, E-3) | Journal rejoué où l'échange avec le modèle (seq 1) porte result, duration_ms et is_error à null : la table 5.3 exige la référence à la réponse, la durée et le drapeau d'erreur pour noortrace.modele.echange (E-3), et le schéma la porte (E-1). |
| `invalide-sans-objet-appel/` | **E-3** | voisins.next (seq 8, appel d'outil mail.send) porte policy.decision = sans_objet, valeur réservée aux événements qui ne sont pas des appels d'outil ; rescellé, donc hash et signature valides : seul E-3 le refuse. |
| `invalide-redaction-absente/` | **E-4** | voisins.next (seq 8) porte une référence rédigée (execution.arguments, redacted: true) mais policy.redaction est null : la règle de rédaction appliquée doit être nommée. |
| `invalide-signature-manquante/` | **E-5** | Journal rejoué où approval.approvers compte deux adresses et approval.signatures une seule signature (valide, du compte Hardhat 1) : les deux tableaux doivent avoir la même longueur. |
| `invalide-reference-en-ligne/` | **E-6** | Journal rejoué où la référence en ligne de la décision (execution.arguments, value = A) déclare une length supérieure de 1 à celle de JCS(value) : le sha256 est juste, la length ne l'est pas (voisin précédent et approbations.json). |
| `invalide-prev-hash-voisin/` | **C-2** | voisins.next (seq 8) porte un prev_hash qui n'est pas le hash recalculé de l'événement prouvé ; rescellé, donc hash et signature valides : la chaîne est rompue entre seq 7 et seq 8. |
| `invalide-cle-voisin/` | **C-3** | Journal rejoué où seq 10 est horodaté à l'instant exact de la rotation (seul instant où les deux clés valent, E-11) ; dossier de la rotation (seq 9) dont le voisin suivant est signé par rec-test-01, rescellé : la clé attendue après la rotation est rec-test-02. |
| `invalide-feuille-etrangere/` | **M-1** | chemin.json et le manifeste (re-signé) sont bâtis sur un arbre où la feuille d'indice 6 n'est pas SHA-256(0x00 || hash de seq 7) : le chemin mène à la racine (M-2), la racine est celle du manifeste (M-3), mais la feuille ne prouve pas l'événement. |
| `invalide-ts-hors-periode/` | **P-2** | Dossier de seq 1 horodaté 08:59:59.999Z, avant period_start de la période 1 (09:00:00Z) ; seq 2 est rechaîné et rescellé, l'arbre et le manifeste sont recalculés et re-signés : tout est cohérent sauf l'appartenance de l'événement à la période. |
| `invalide-periode-tronquee/` | **P-3** | Le manifeste de la période 1 est refait sur huit feuilles (seq 1 à 8, last_seq = 8) et re-signé par rec-test-02 ; dossier de seq 8 dont le voisin suivant (seq 9, la rotation, 09:59:58.000Z) est hors de l'intervalle de seq mais horodaté dans la période : le manifeste a tronqué sa période. |
| `invalide-periode-deux-heures/` | **P-1** | manifeste.json porte period_end = period_start + 7200 (deux heures), re-signé : une période est une heure UTC pleine, period_end = period_start + 3600 ; l'événement et ses voisins restent dans la fenêtre élargie (P-2, P-3 passent). |
| `invalide-manifeste-cle-perimee/` | **P-5** | Le manifeste est signé par rec-test-01 (periodHash et signature cohérents) alors que cles.json arrête sa validité à l'instant de la rotation (09:59:58.000Z), avant generated_at (10:00:00.300Z) : la clé en vigueur à la clôture était rec-test-02. |
| `invalide-ticket-approbations/` | **A-1** | approbations.json porte le ticket apr-9999 alors que approval.ticket de l'événement vaut apr-2201. |
| `invalide-decision-etrangere/` | **A-2** | La décision jointe dans approbations.json porte un approval.reason différent (champ non signé par les approbateurs, rescellé par l'enregistreur) : approval n'est plus égal, clé pour clé, à celui de l'événement prouvé. |
| `invalide-demande-refusee/` | **A-4** | Journal rejoué où seq 5 est refusé par la politique (status refusee) au lieu d'être retenu ; dossier de la décision seq 6 dont request_hash désigne bien ce voisin : son status n'est pas retenue. |
| `invalide-approbateur-double/` | **A-3** (en échec : E-1, A-3) | Journal rejoué où le compte Hardhat 1 figure deux fois dans approvers avec deux signatures valides : le schéma impose des approbateurs distincts (uniqueItems, E-1) et A-3 compte les approbateurs distincts. |
| `invalide-signature-s-haut/` | **E-9** | Journal rejoué où signatures[1] est mise en forme haute (s remplacé par n - s, v complémenté) : même point, même adresse pour un vérificateur laxiste, refusée comme non canonique (E-9), comme par le contrat ThresholdSignatures. |
| `invalide-cles-key-id-double/` | **E-8** | cles.json porte deux entrées rec-test-01 (la seconde avec une autre clé publique) : l'identifiant doit être unique, sinon le verdict dépendrait de l'ordre de lecture. |
| `invalide-cles-autre-journal/` | **E-8** | cles.json porte le journal_id d'un autre journal (journal-principal, celui de l'exemple de la spécification) : les clés doivent être rattachées au journal de l'événement prouvé. |
| `invalide-rotation-validite-annoncee/` | **E-10** | Dossier de la rotation (seq 9) dont cles.json annonce rec-test-02 valide à partir de 09:00:00Z alors que la rotation est horodatée 09:59:58.000Z : la validité d'une clé issue d'une rotation est celle que le journal annonce (CT-1 §8, règle 3). |
| `invalide-hash-faux/` | **E-7** | Le champ hash de evenement.json est réécrit (contenu et signature intacts) : le hash recalculé ne correspond plus. L'index est recalculé pour que D-1 et D-2 passent ; les contrôles qui recalculent le hash (C-2, M-1) passent aussi. |
| `invalide-signature-fausse/` | **E-8** | La signature de evenement.json est une signature Ed25519 valide, mais produite par rec-test-02 alors que recorder_key_id vaut rec-test-01. |
| `invalide-chemin-permute/` | **M-2** | Les deux premiers nœuds de chemin.json sont échangés : l'algorithme d'inclusion ne retombe pas sur la racine. |
| `invalide-chemin-tronque/` | **M-2** | Le dernier nœud de chemin.json est retiré : le chemin n'a pas la longueur attendue pour (leaf_index, tree_size) et sn ne retombe pas à 0. |
| `invalide-leaf-index-decale/` | **M-3** (en échec : M-2, M-3) | leaf_index de chemin.json vaut 7 au lieu de 6 : il ne vaut plus seq - first_seq (M-3) et le chemin, interprété à cette position, ne mène plus à la racine (M-2). |
| `invalide-voisin-incoherent/` | **C-1** | voisins.next porte seq 9 au lieu de 8 et a été rescellé avec la clé de l'enregistreur : hash, signature et prev_hash sont valides, mais il n'est pas le voisin immédiat. |
| `invalide-racine-manifeste/` | **M-3** | La racine de manifeste.json est celle d'un arbre à huit feuilles (seq 1 à 8) et le manifeste a été re-signé : periodHash et signature sont cohérents entre eux (P-5), mais la racine ne correspond pas à celle du chemin. |
| `invalide-racine-nulle/` | **P-4** (en échec : M-3, P-1, P-4) | Racine nulle avec count = 9, manifeste re-signé : la convention de la période vide est violée (P-4), le schéma du manifeste l'interdit (P-1) et le chemin ne mène pas à cette racine (M-3). |
| `invalide-index-sha256/` | **D-2** | dossier.json déclare pour chemin.json un SHA-256 qui n'est pas celui du fichier : le dossier a été modifié après l'écriture de l'index. |
| `invalide-nombre-non-entier/` | **E-2** | evenement.json porte duration_ms = 530.0 : même valeur entière, forme fractionnaire, interdite par JCS v0. Un analyseur strict refuse le fichier ; les contrôles qui dépendent de l'événement ne sont pas exécutés. |
| `invalide-hex-majuscules/` | **E-1** | code.prompt_version de voisins.next est en hexadécimal majuscule ; l'événement a été rescellé (hash et signature valides sur cette forme) : seul le schéma le refuse. |
| `invalide-approbateur-substitue/` | **E-9** | Journal rejoué où signatures[1] est produite par le compte Hardhat 3 alors que approvers[1] reste le compte 2 : l'adresse recouvrée ne correspond pas (dans l'événement prouvé, dans le voisin précédent qui est la décision, et dans approbations.json). |
| `invalide-seuil-non-atteint/` | **A-3** | Journal rejoué avec une seule signature d'approbateur (compte Hardhat 1) pour un seuil déclaré de 2 sur 3 : la signature est valide, le seuil n'est pas atteint. |
| `invalide-cle-hors-validite/` | **E-11** | cles.json annonce rec-test-01 valide à partir de 09:31:48.500Z : l'événement prouvé (09:31:48.006Z) et son voisin précédent sont signés avant la validité annoncée. |
| `invalide-rotation-contresignature/` | **E-10** | Dossier de l'événement de rotation (seq 9) d'un journal rejoué où counter_sig a été produite par l'ancienne clé : la contresignature ne vérifie pas sous new_public_key. |
| `invalide-ts-voisin/` | **C-1** | Journal rejoué où seq 6 porte ts 09:31:48.500Z, postérieur au ts de seq 7 (09:31:48.006Z) : les horodatages décroissent le long de la chaîne. |
| `valide-seq-7-point-de-controle/` | valide | Dossier de seq 7 avec la treizième partie (révision 0.3) : point de contrôle de 09:32:00.000Z, premier point de la série de la période 1 qui couvre la feuille 6 (tree_size 8, last_seq 8, signé par rec-test-01), preuve de cohérence de huit feuilles vers neuf, aucune ancre (les trois à null). K-1 à K-6 réussies (K-6 exécutée : l'événement last_seq, seq 8, est le voisin suivant) ; K-7 à K-9 non exécutées, ancre absente ; A-4 non exécuté comme dans valide-seq-7. |
| `valide-seq-7-partie-declaree-absente/` | valide | Dossier de seq 7 dont l'index déclare treize parties, la treizième absente avec la raison « aucun point de contrôle » : verdict identique à valide-seq-7, K-1 à K-9 non exécutées pour une raison admise (partie absente). |
| `invalide-k1-point-autre-periode/` | **K-1** | Le point porte le period_start de la période 2 (re-signé, checkpoint_hash recalculé) : il ne décrit pas la période du manifeste, et son checkpoint_ts (09:32:00.000Z) précède ce period_start. |
| `invalide-k2-checkpoint-hash/` | **K-2** | checkpoint_hash déclaré n'est pas SHA-256(P_K || C_K) du point : l'empreinte que les ancres porteraient n'est pas celle de ce point. |
| `invalide-k3-signature-point/` | **K-3** | Le point annonce key_id rec-test-01 mais sa signature est produite par rec-test-02 (corps inchangé : checkpoint_hash juste, K-2 passe) : signature invalide sous la clé annoncée. |
| `invalide-k4-point-trop-court/` | **K-4** | Le point joint (2026-11-05T09:31:48.000Z, tree_size 6, last_seq 6, chaîné au point de 09:31:00.000Z) ne couvre pas la feuille 6 de l'événement prouvé (seq 7, 09:31:48.006Z) : preuve de cohérence correcte de six feuilles vers neuf (K-5), last_hash vérifié sur le voisin précédent (K-6), mais leaf_index n'est pas strictement inférieur à tree_size et ts est postérieur à checkpoint_ts. |
| `invalide-k5-coherence-tronquee/` | **K-5** | Le dernier nœud de consistency.path est retiré : l'algorithme de CT-1 §10.7 ne retombe pas sur les deux racines (chemin trop court pour (8, 9)). |
| `invalide-k6-last-hash/` | **K-6** | last_hash du point réécrit (point re-signé, checkpoint_hash recalculé : K-2 et K-3 passent) : l'événement last_seq (seq 8) est le voisin suivant et son hash recalculé n'est pas celui que le point annonce. |
| `valide-seq-7-point-de-cloture/` | valide | Dossier de seq 7 dont la treizième partie porte le point de clôture de la période 1 (2026-11-05T10:00:00.300Z, tree_size 9 = count) : preuve de cohérence de neuf feuilles vers neuf, chemin vide et racines égales (CT-1 §10.7, m = n) ; K-1 à K-5 réussies ; K-6 non exécutée pour une raison admise (l'événement last_seq, seq 9, est hors du dossier) ; K-7 à K-9 non exécutées, ancres nulles. |
| `invalide-k1-double-defaut/` | **K-1** | La partie porte un membre « extra » hors du schéma et un chemin de cohérence tronqué : K-1 échoue sur le schéma ; K-2 à K-9 ne sont pas exécutées (prérequis K-1 en échec), si bien que le chemin tronqué n'est pas examiné et K-5 n'est pas en échec. |
| `valide-seq-12-attestation-inscrite/` | valide ; attestation retenue | Journal rejoué de CT-7 §7.5 : seq 12 (rec-test-02) annonce la politique 2026-11-05 dont le document réduit porte perimeter.attestation_digest = D_P de l'attestation de CT-7 §7.1. Dossier de seq 12, quatorze parties (la treizième absente, « aucun point de contrôle ») ; la partie porte l'attestation signée par les comptes Hardhat 1 et 2, le jeu des comptes 1 à 3 au seuil de 2, et l'inscription (seq 12 et le document en base64). AT-1 à AT-7 réussissent : attestation retenue et inscrite (clé rec-test-02, celle de l'événement prouvé) ; AT-7 ne compare que le nom de la version de politique, et l'énoncé dit « sous une version de politique de même nom que celle de cet événement » (CT-6 EX-6.19). |
| `valide-seq-7-attestation-sans-inscription/` | valide ; attestation retenue | Dossier valide-seq-7 avec la quatorzième partie sans inscription (inscription vaut null) et la treizième absente : AT-1 à AT-5 réussissent, AT-6 et AT-7 ne sont pas exécutées (partie absente) ; l'attestation est retenue sans place dans le journal (CT-7 EX-7.12). Le jeu déclaré est celui de approbations.json : aucun avertissement. |
| `valide-seq-7-attestation-declaree-absente/` | valide ; aucune AT- | Dossier valide-seq-7 dont l'index déclare quatorze parties, la treizième et la quatorzième absentes (« aucun point de contrôle », « aucune attestation de périmètre ») : aucune vérification AT- n'est exécutée ni rapportée ; le dossier ne dit rien du périmètre (CT-7 EX-7.15). |
| `valide-seq-13-at7-autre-version/` | valide ; AT-7 visée, attestation retenue (AV-AT-3) | Journal rejoué prolongé d'un seq 13 (10:20:00.000Z) qui annonce la politique 2026-11-06, sans membre perimeter ; dossier de seq 13 dont la partie joint l'inscription seq 12. AT-6 réussit (seq 12 précède seq 13) ; AT-7 n'est pas exécutée (pièce hors dossier : l'ensemble de politique en vigueur pour l'événement n'est pas celui de l'inscription), avertissement AV-AT-3 ; l'attestation reste retenue, et l'énoncé dit « sans preuve qu'elle était en vigueur pour cet événement (version de politique différente) » (CT-6 EX-6.19). |
| `valide-at1-partie-nulle/` | valide ; AT-1 visée, attestation non retenue (AV-AT-1) | La partie attestation-perimetre.json est le littéral null (index recalculé) : AT-1 échoue, AT-2 à AT-7 ne sont pas exécutées (prérequis en échec), AV-AT-1 ; le dossier reste valide (CT-1 §11.4, CT-6 EX-5.11). |
| `valide-at1-taille/` | valide ; AT-1 visée, attestation non retenue (AV-AT-1) | La partie fait 4194305 octets (4 Mio plus un octet) : la même partie que valide-seq-7-attestation-sans-inscription, complétée par des espaces de mise en forme avant le saut de ligne final, donc conforme à son schéma. Au-delà de la limite de CT-6 EX-4.15 : AT-1 échoue, AT-2 à AT-7 ne sont pas exécutées, AV-AT-1 ; D-2 réussit (SHA-256 de l'index exact), le dossier reste valide. |
| `valide-at3-signature-substituee/` | valide ; AT-3 visée, attestation non retenue (AV-AT-1) | La signature du compte Hardhat 3 sur D_P est déclarée pour le compte 2 (cas invalide-at3-signature-substituee de CT-7 annexe A.6) : l'adresse recouvrée est 0x90f79bf6eb2c4f870365e785982e1f101e93b906, AT-3 échoue, AT-4 n'est pas exécutée, AV-AT-1 ; le dossier reste valide. |
| `valide-at4-jeu-different/` | valide ; AT-4 visée, attestation retenue (AV-AT-2) | Le jeu déclaré par la partie est celui des comptes Hardhat 1, 2 et 4 (seuil de 2 sur 3), approbations.json déclare les comptes 1 à 3 : AT-4 réussit (les comptes 1 et 2 sont membres des deux jeux), l'attestation est retenue, et AV-AT-2 signale les deux jeux différents. |
| `valide-at5-autre-journal/` | valide ; AT-5 visée, attestation non retenue (AV-AT-1) | Attestation (signée par les comptes 1 et 2) qui ne couvre que journal-principal et son agent : l'événement prouvé est de journal-sinistres, AT-5 échoue, AV-AT-1 ; le dossier reste valide. |
| `valide-at5-hors-validite/` | valide ; AT-5 visée, attestation non retenue (AV-AT-1) | Attestation valable du 1er au 4 novembre 2026 (signée par les comptes 1 et 2), événement prouvé du 5 novembre : ts hors de la validité, AT-5 échoue, AV-AT-1 ; le dossier reste valide. |
| `valide-at6-inscription-posterieure/` | valide ; AT-6 visée, attestation non retenue (AV-AT-1) | Dossier de seq 11 du journal rejoué, dont la partie joint l'inscription seq 12 : l'inscription suit l'événement prouvé (seq et ts), AT-6 échoue, AT-7 n'est pas exécutée (prérequis en échec), AV-AT-1 ; le dossier reste valide. |
| `valide-at6-document-autre-condense/` | valide ; AT-6 visée, attestation non retenue (AV-AT-1) | Journal rejoué dont seq 12 annonce un document de politique dont perimeter.attestation_digest est SHA-256(« noortrace/vecteurs/ct7/autre-attestation ») et non D_P (événement rescellé, dossier de seq 12) : AT-6 échoue, AV-AT-1 ; le dossier reste valide. |
| `valide-at6-inscription-signature-fausse/` | valide ; AT-6 visée, attestation non retenue (AV-AT-1) | Dossier valide-seq-12-attestation-inscrite dont l'événement d'inscription joint à la partie est signé par rec-test-01 alors qu'il nomme rec-test-02 (hash inchangé, evenement.json intact) : la signature est invalide sous la clé nommée, AT-6 échoue, AV-AT-1 ; le dossier reste valide. |
| `valide-at6-cle-non-ancree/` | valide ; AT-6 visée, attestation retenue | Dossier valide-seq-7-attestation-sans-inscription où l'exportateur ajoute à cles.json une clé rec-forge-01 (graine = SHA-256 de « noortrace/vecteurs/ct7/rec-forge-01 ») et joint une inscription forgée : seq 2, 09:10:00.000Z, signée par rec-forge-01, document de politique portant D_P sous la version de l'événement prouvé. L'événement prouvé (seq 7) est signé par rec-test-01 : la clé de l'inscription n'est pas la sienne, rien ne la relie au journal, AT-6 n'est pas exécutée (ancre_absente) et AT-7 non plus (prérequis) ; l'attestation est retenue sans clause d'inscription (CT-6 EX-6.19), le dossier reste valide (CT-7 MN-84, MN-90). |
| `valide-at2-condense-faux/` | valide ; AT-2 visée, attestation non retenue (AV-AT-1) | signed.digest est le D_P d'une autre attestation (issued_at du 31 octobre) : AT-2 échoue ; AT-3 et AT-4 réussissent, les signatures portant sur le D_P recalculé ; inscription nulle, AT-6 et AT-7 ne sont pas exécutées, partie absente (la raison partie_absente l'emporte sur l'échec d'AT-2, CT-6 EX-5.12) ; AV-AT-1 ; le dossier reste valide (CT-6 EX-5.11, V-10). |
| `valide-at4-seuil-non-atteint/` | valide ; AT-4 visée, attestation non retenue (AV-AT-1) | L'attestation n'est signée que par le compte Hardhat 1, pour un jeu déclaré au seuil de 2 sur 3 : AT-3 réussit, AT-4 échoue, AV-AT-1 ; le dossier reste valide (CT-6 EX-5.11, V-10). |
| `invalide-e1-attestation-non-executee/` | **E-1** (en échec : E-1, E-7, E-8, C-2, M-1) ; AT-5 visée, attestation non retenue (AV-AT-1) | evenement.json de valide-seq-7-attestation-sans-inscription porte un membre hors schéma (extra) : E-1 échoue, avec E-7, E-8, C-2 et M-1 que le hash recalculé met en échec, et le dossier est invalide. AT-1 à AT-4 réussissent ; AT-5 n'est pas exécutée (evenement.json inexploitable) ; inscription nulle, AT-6 et AT-7 non exécutées (partie absente). Aucune AT- n'est en échec, et l'attestation n'est pas retenue : AV-AT-1 nomme AT-5, non exécutée (CT-6 5.5). |
| `valide-at7-nom-reannonce/` | valide ; AT-7 visée, attestation retenue | Journal rejoué prolongé d'un seq 13 (10:20:00.000Z) qui annonce, sous le même nom de version 2026-11-05, un autre document de politique, sans membre perimeter (ce que CT-2 0.5 n'interdit pas au démarrage tant que PA-9 n'est pas adoptée) ; dossier de seq 13 dont la partie joint l'inscription seq 12. AT-6 et AT-7 réussissent : AT-7 ne compare que des noms. L'énoncé dit seulement « sous une version de politique de même nom que celle de cet événement », jamais que l'attestation était en vigueur (CT-7 MN-91, RA-75). |
| `valide-at7-attestation-remplacee/` | valide ; AT-7 visée, attestation retenue (AV-AT-3) | Journal rejoué prolongé d'un seq 13 (10:20:00.000Z) qui inscrit une attestation B (issued_at 10:15, une exception de capture de plus) sous la version 2026-11-06 ; l'exportateur joint au dossier de seq 13 l'attestation A et son inscription seq 12. AT-6 réussit ; AT-7 n'est pas exécutée (pièce hors dossier), AV-AT-3 ; l'attestation A est retenue, et l'énoncé dit « sans preuve qu'elle était en vigueur pour cet événement » (CT-6 EX-6.19, CT-7 EX-7.11). |
| `invalide-d2-attestation-sha256/` | **D-2** ; attestation retenue | Dossier valide-seq-7-attestation-sans-inscription dont l'index déclare pour attestation-perimetre.json un autre SHA-256 : D-2 échoue et le dossier est invalide, parce que l'index n'est plus celui que l'exportateur a scellé (CT-1 §11.4) ; l'attestation elle-même est vérifiée et retenue, sans effet sur ce verdict. |

Vérification d'un dossier : `node scripts/verify/dossier.mjs spec/vecteurs/ct-1/dossiers/valide-seq-7`
(code 0), `node scripts/verify/dossier.mjs spec/vecteurs/ct-1/dossiers/invalide-hash-faux --json`
(code 1, `controles[].ok === false` pour E-7).
