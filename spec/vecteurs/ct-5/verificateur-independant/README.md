# Vérificateur Go de cohérence des vecteurs CT-5 (non indépendant)

Un vérificateur des vecteurs de CT-5, écrit en Go depuis la spécification
[`spec/CT-5-ancrage.md`](../../../CT-5-ancrage.md) (et, pour ce qu'ils
définissent, CT-1 §10.5 à §10.7, CT-6 §9 et §10, RFC 3161, le schéma
`spec/schemas/planificateur-ancrage-v0.schema.json` qu'elle cite), et **en
partie recopié de la référence JavaScript** (annexe A.5, EX-A.4). Il
recalcule ce que la spécification définit et le confronte à chaque valeur
attendue trouvée dans `spec/vecteurs/ct-5` ; une discordance désigne une
ambiguïté de la spécification ou une faute de l'un des deux, et le
vérificateur la liste sans la masquer. C'est un vérificateur de cohérence
des vecteurs, **pas une implémentation indépendante** : sa concordance avec
les vecteurs ne vaut pas confrontation indépendante, et il ne compte pas
parmi les confrontations indépendantes du plan de tests (CT-9 EX-13.2,
TA-66).

**Nom du répertoire.** Le répertoire garde le nom
`verificateur-independant/`, que suivent l'intégration continue, les renvois
et les autres modules. Pour `ct-5`, ce nom est historique et ne vaut pas
déclaration d'indépendance.

**Pourquoi il n'est pas indépendant (CT-5 A.5, complément du 2026-11-15 de
la révision 0.10, décision du porteur).** Le module a d'abord été écrit
depuis la spécification seule. Lors de la correction de la révision 0.2 de
CT-5, il a été audité puis complété (ordre « ligne `envoyee` puis envoi »
d'AN-32, transitions `envoyee → a_envoyer` et `obtenue → a_reprendre`
d'EX-8.3, échéances rendues sur refus, repli de clôture, reconstruction de
la file et fichiers d'époque, nouvelles alertes, classement des étapes 1 et
5, famille `completude`, plafond d'ancres `2 + 3600 / c_K`) par un rédacteur
qui avait aussi lu la référence JavaScript. La revue de sécurité interne de
l'étape 8 a ensuite établi que des parties du module sont identiques à la
référence (même découpage, mêmes noms de variables, mêmes commentaires,
mêmes messages d'erreur dans le même ordre) : la lecture et la construction
des requêtes RFC 3161 (`der.go`), la lecture et le classement des réponses
(`reponse.go`), le registre du planificateur (`planificateur.go`), au
moins ; le reste n'a pas été relu à l'aveugle. Le module est donc tenu pour
en partie recopié de la référence, et la mention « indépendant » lui est
retirée.

Bibliothèque standard uniquement (`crypto/sha256`, `crypto/sha3` pour les
tests, `encoding/hex`, `encoding/base64`, `math/big`, `regexp`, `encoding/json`
pour la seule sortie du rapport). Module `noortrace-ct5`, `go 1.24`. Trois fichiers sont copiés du
vérificateur de CT-1, comme EX-A.4 l'admet, et le disent en tête : `json.go`
(analyseur JSON strict), `jcs.go` (forme canonique JCS v0), `keccak.go`
(Keccak-256 pour les empreintes d'ancre et les `docType`).

## Usage

```bash
cd spec/vecteurs/ct-5/verificateur-independant
go run . ..                        # rapport texte, code 0 si tout concorde
go run . -v ..                     # liste aussi les valeurs concordantes et les détails
go run . -json .. > rapport.json
go test ./...                      # tests propres au module (voir plus bas)
```

`go build` sans `-o` produit un binaire `noortrace-ct5` (nom du module) dans
ce répertoire ; `noortrace-ct5` et `verificateur` sont exclus par le
`.gitignore` local.

Codes de retour : `0` tout concorde (les valeurs hors périmètre, voir
« Limites », sont énoncées mais ne comptent pas) ; `1` au moins une
discordance ou une erreur (fichier illisible, disposition non reconnue) ; `2`
usage incorrect ou racine introuvable.

Le rapport compte, par famille puis au total, les valeurs recalculées, les
concordantes, les discordantes (avec attendu et obtenu) et les hors
périmètre ; la dernière ligne dit « tout concorde » ou « DISCORDANCE ou
erreur ». Deux exécutions sur les mêmes fichiers rendent le même rapport :
rien n'est tiré de l'horloge ni du hasard.

## Ce qui est recalculé

| Famille | Fichiers lus | Valeurs recalculées et confrontées |
|---|---|---|
| constantes | `constantes.json`, `ots/point-k2-en-attente.ots`, `../ct-1/manifestes/attendu.json` | `org_id` et `journal_id` = keccak256 des noms (CT-1 §13), `docType` des ancres de période et de point (CT-4 §6.4), empreinte d'ancre keccak256(org_id ‖ journal_id ‖ empreinte) de chaque période et de chaque point (§9.1), `period_end = period_start + 3600`, nonces et opérations de calendrier dérivés des étiquettes d'A.2 (64 premiers bits ou 16 premiers octets de SHA-256), engagement `e`, taille et SHA-256 du fichier `.ots` cité, rôles des prestataires ; les trois `periodHash` et le `journal_id` du journal des vecteurs égaux à ceux des manifestes de `spec/vecteurs/ct-1` (EX-A.2) |
| requetes | `requetes/requetes.json`, `refusees.json`, `*.tsq` | `TimeStampReq` DER octet pour octet (EX-5.1 : version 1, `AlgorithmIdentifier` SHA-256 à `NULL` explicite, `reqPolicy` facultatif, nonce INTEGER minimal, `certReq` TRUE), nonce dérivé de l'étiquette, taille, SHA-256, octets du fichier, relecture ; refus du constructeur et du lecteur (AN-5, AN-6 : empreinte de 31 octets, nonce nul ou hors de 64 bits, `certReq` faux, zéro de tête superflu) avec la règle et le message |
| reponses | `reponses/reponses.json`, `*.tsr`, `*.der`, `../requetes/*.tsq` | SHA-256 des requêtes et des réponses ; classement d'EX-5.10 à EX-5.12 : transport (statut HTTP, type de contenu, taille), `PKIStatus`, `PKIFailureInfo`, extraction du `TimeStampToken` (égal au `.der` publié), `messageImprint`, nonce du `TSTInfo`, politique demandée et politiques admises, vérifications T- déclarées, fraîcheur (`max_response_delay_s`, troisième réponse tardive promue) et horloge (`clock_tolerance_s`) ; `genTime`, `accuracy`, borne supérieure ; attente de reprise d'EX-8.9 (`Retry-After`, premier 408 immédiat, retrait exponentiel plafonné) |
| ots | `ots/ots.json`, `*.ots`, `mise-a-niveau.json`, preuves de CT-6 citées | fichier `.ots` d'EX-6.4 construit (en-tête, empreinte, `f0` nonce, `08`, branches des calendriers dans l'ordre de la bibliothèque de référence : attestations avant opérations, attestations en attente triées par URI, opérations par étiquette puis argument), taille, SHA-256, octets, engagement, état (`en_attente` ou `complete`, EX-6.7), vérifications O-1 à O-3 et O-7 (CT-6 §10.4), URI relues ; mise à niveau d'EX-6.6 : lecture de la réponse du calendrier, remplacement de l'attestation en attente, resérialisation égale à la preuve complète de CT-6 |
| planification | `planification/*.json` (soixante-deux traces) | rejeu de chaque trace par le planificateur de la section 8 (machine à états à horloge injectée) : chaque action de `expected` (forme canonique JCS v0, dans l'ordre), chaque demande de `queue_after` ; `request_sha256` et `request_size` de chaque `envoyer_rfc3161` recalculés depuis le détail attendu ; puis les invariants de la section 8.11 sur la trace rejouée (table ci-dessous) |
| reprise | `reprise/*.avant.ndjson`, `*.apres.ndjson` (vingt-cinq paires), fichiers d'époque, la trace de même nom | relecture de la file (dernière ligne d'un id fait foi, ligne tronquée signalée), lignes égales à la forme canonique de `queue_before`, rejeu de la trace depuis la file relue, lignes finales égales à `queue_after` et au fichier `.apres.ndjson`, une seule demande par id |
| configuration | `configuration/configuration.json` (vingt-cinq cas), `../../schemas/ancrage-v0.schema.json` | AN-1 (EX-4.9) : chaque document validé contre le schéma `ancrage-v0` (règle `schema` ; les règles suivantes ne sont alors pas évaluées), puis les règles 1 à 9 pour le profil (`developpement`, `test`, `production`) et la valeur `checkpoint_interval_s` de l'enregistreur ; `valide` et la liste triée des règles violées (`schema`, puis `1` à `9`, 4 bis comptant pour 4) confrontés à l'attendu (complément du 2026-11-16 ; voir plus bas) |
| cout | `cout/cout.json` | formule de la section 12 (EX-12.1, EX-12.2) : jetons qualifiés et de second rang par journal et par an, ancres au registre, borne de gaz, coût par journal et total, arrondis à trois décimales ; pour les cas à `a = 1` (ou `countersign_idle` vrai), `N_q`, `N_s` et `N_a` égalent `N_h` fois les comptages par heure d'EX-4.11, recalculés à part (table de 4.6, AN-59) ; les prix sont les paramètres symboliques du cas, jamais une valeur du module (AN-60) |
| completude | `completude/completude.json` | AN-61 (EX-10.7) : `complete`, `orphans`, `out_of_order`, `attached` de chaque cas, recalculés depuis les séries publiées et les ancres capturées |

Invariants vérifiés sur chaque trace de `planification/` (fichier
`invariants.go`), chacun comptant pour une valeur « aucun écart » :

| Règle | Ce qui est vérifié |
|---|---|
| AN-32 | toute action `envoyer_rfc3161`, `envoyer_registre` ou `soumettre_ots` est accompagnée, au même instant, d'une ligne `envoyee` de la demande ; pour une requête RFC 3161, la ligne porte le nonce et le rang de la tentative (EX-8.5, règle 1) ; un renvoi d'ancre déjà `envoyee` est admis (EX-8.12) |
| AN-33 | une seule demande par `id` dans `queue_after`, état égal à la dernière ligne écrite ; au `demarrage`, les seules transitions d'EX-8.12 (une demande `envoyee` passe `a_reprendre`, une ancre `envoyee` est renvoyée sans réécriture, `attente_registre` interroge l'inclusion, `en_attente` est reprogrammée à `max(due_at, now)`, `a_reprendre` (jeton, soumission, ancre) garde `due_at` ou le voit borné, la réécriture `a_reprendre → a_reprendre` n'étant admise que comme borne d'EX-4.13, une soumission OpenTimestamps `a_reprendre` qui porte une tentative en cours est reprise comme `envoyee` (réécriture suivie de `programmer immediat`), aucun état final sans réponse) |
| AN-34 | chaque `ecrire_file` est une transition de la table d'EX-8.3 (première ligne `a_envoyer` ou `attente_registre`), ou l'une des écritures du démarrage que le texte admet hors de la table : première ligne `obtenue` d'une demande de jeton recréée (EX-8.12), `a_reprendre → a_reprendre` de la borne d'EX-4.13, et `a_reprendre → a_reprendre` d'une soumission OpenTimestamps relue avec une tentative en cours, suivie de `programmer immediat` (EX-8.12) ; `obtenue → a_reprendre` (EX-5.8, EX-5.10) est dans la table ; aucun `jeton_periode` dans un état final autre qu'`obtenue` |
| AN-35 | une échéance ouverte par l'horloge l'est à `D_k = period_start + k × c_T` ; chaque `k` d'une demande `jeton_point` est dans `[1, n_T − 1]`, le point a `checkpoint_ts ≥ D_k` et aucun point antérieur de la période ne satisfaisait déjà `D_k` ; un `k` n'est servi que par une demande (EX-4.2, EX-4.3) |
| AN-36 | un `jeton_periode` n'est envoyé qu'après une entrée `inclusion_registre` de son ancre ; un `jeton_point` dont l'ancre est partie n'est envoyé qu'après son inclusion, son refus `empreinte_squattee`, ou la ligne `ordre_ancres_non_respecte` écrite à `admission + squat_wait_s` (EX-8.4, EX-9.6, EX-9.7) ; à chaque `ecrire_file` qui fait passer une ancre au registre à `envoyee` depuis un autre état, états suivis depuis `queue_before` et les `ecrire_file` précédents (A.4) : (1) pour une ancre de période, aucune ancre de point de même `org_id`, `journal_id` et `period_start` n'est dans un état non final (EX-8.4, règle 2 ; EX-9.4) ; (2) aucune ancre de période de même `org_id` et `journal_id` et de `period_start` plus petit n'est dans un état non final (EX-9.4, clé retenue) ; (3) pour une ancre de point, aucune ancre d'un point antérieur de sa période et de son journal (`checkpoint_ts` plus petit, puis l'ordre de la file) n'est dans un état non final (EX-9.4) |
| AN-37 | après chaque rejet transitoire, l'attente programmée est recalculée depuis les entrées : `Retry-After` pour 429 et 503, 0 pour le premier 408 de la demande chez ce prestataire, sinon `min(max_ms, initial_ms × factor^(k−1))` plus la gigue de `jitter_ms` consommée dans l'ordre, avec la raison attendue (EX-8.9) ; de même après l'échec d'une soumission OpenTimestamps (moins de `min_responses` réponses valables, attestation `aucune` ou preuve nulle : `k` sur la série de la soumission, EX-8.11), la réponse ne s'appliquant qu'à une tentative ouverte (`soumettre_ots`, `mettre_a_niveau_ots` ou ligne `en_cours` de `queue_before`, fermée par la réponse suivante ou, pour une soumission, par le `demarrage`), sans lire l'action `rejeter_reponse` (A.4) et après un échec signalé par le registre (`k` : tentatives non obtenues de l'ancre, EX-8.10) |
| AN-39, AN-58 | au moins `min_interval_ms` entre deux requêtes au même prestataire, toutes demandes confondues ; à un même instant, `jeton_periode` servi avant `jeton_point` (EX-8.7) |
| AN-40, AN-48 | `stocker` (index de capture) précède `obtenue` pour une ancre au registre ; `empreinte_squattee` donne `refusee` sans renvoi ; une inclusion constatée plus d'`inclusion_alert_s` après la création de l'ancre a été alertée `inclusion_late` depuis le dernier démarrage (EX-8.10, complément du 2026-11-16 ; EX-9.7) |
| AN-41 | `en_attente` après une soumission exige une réponse `en_attente` d'au moins `min_responses` calendriers au même instant ; la mise à niveau est programmée `first_after_s` après la soumission puis toutes les `max(interval_s, 60 s)`, et un jour plus tard dès que l'âge de la demande, compté depuis son `created_at`, atteint `give_up_after_s` ; `complete` exige une attestation Bitcoin reçue à cet instant et la ligne `ots_complete` avec réexport (EX-8.11) |
| AN-43 | aucune ligne de journal, d'alerte ni de file ne porte un mot de passe, un secret, un en-tête d'autorisation, un identifiant d'accès, un prix (mots de `MotsInterdits`, sans tenir compte de la casse) ni une adresse IP |
| A.2 | formes représentées : `capture_sha256` de chaque inclusion vaut `SHA-256(UTF-8("capture <id> <bloc>"))` ; dans la trace de référence, la preuve `.ots` représentée vaut `SHA-256(UTF-8("preuve en attente periode 1"))`, taille 233 |

Le planificateur (`planificateur.go`) porte les règles EX-4.2 à EX-4.7
(échéances, sélection du point, échéances remplacées, ancre des points,
ordre des ancres), EX-5.10 à EX-5.12 (classement), EX-8.3 à EX-8.12 (états,
file, priorité et `min_interval_ms`, relève, attente de reprise, registre,
OpenTimestamps, redémarrage) et EX-9.3 à EX-9.5 (une transaction par clé de
chaîne, clé retenue, remplacement des ancres encore à envoyer). Les nonces et les gigues
viennent d'une source dérivée des étiquettes d'A.2 et de `jitter_ms`
(EX-8.13) ; l'horloge n'est jamais lue.

## Révision 0.6 de CT-5

Le module rejoue les traces sous les règles de la révision 0.6 :

- **Fenêtre de 32 tentatives** (EX-8.5, règle 7) : chaque ligne écrite porte
  au plus 32 tentatives par rang croissant (les tentatives en cours toujours,
  puis les plus récentes) et `attempts_total`, plus grand rang ; une tentative
  nouvelle a le rang `attempts_total + 1`, au démarrage compris (EX-8.12),
  jamais « nombre de tentatives portées + 1 » (`Fenetre`, `Demande.Total`,
  `ajouterTentative`). Une réponse à une tentative de rang connu que la ligne
  ne porte plus est traitée comme une réponse à une tentative close
  (`tentative_close`, conservée, non promue, prestataire `null`).
- **Lecture** : `attempts_total` est facultatif (une ligne d'avant la révision
  ne le porte pas, il vaut alors le nombre de ses tentatives) ; une telle
  ligne de plus de 32 tentatives est lue telle quelle. **Écriture** :
  `ControlerLigneEcrite` refuse une ligne de plus de 32 tentatives, sans
  `attempts_total`, ou dont `attempts_total` n'est pas le plus grand rang ;
  chaque trace confronte ses lignes écrites et ses files (`queue_before`,
  `queue_after`) à `$defs/demande` révisé (`maxItems` 32).
- **`d_admission_s`** (EX-3.5, 8.9) sur `checkpoint_countersigned` : cinq
  instants tronqués à la seconde depuis `D_k` (depuis `period_end` pour le
  repli) — `checkpoint_ts`, admission du point (instant de l'entrée
  `point_produit`, ou de la reconstruction au démarrage), premier envoi,
  envoi de la tentative promue, borne du jeton ; `d_attente_s` compté depuis
  l'admission.
- **Lignes d'une tentative** (EX-8.15) : `anchor_retry`, `anchor_fallback` et
  `anchor_response_rejected` portent `attempt` (rang) et `attempt_id`.
- AN-37 lit le prestataire d'une tentative sur sa requête (`envoyer_rfc3161`),
  la file finale ne portant plus les tentatives sorties de la fenêtre.

Le compactage de la file (EX-8.5, règle 5) n'est pas une action de trace et
ne change ni `expected` ni `queue_after` : il n'est pas recalculé ici.

## Révision 0.10 de CT-5

Le module rejoue les vecteurs régénérés avec la révision 0.10 (traces
`redemarrage-releve`, `redemarrage-echeance-remplacee`,
`file-lignes-illisibles`, `releve-pendant-reprise`, cas `statut-6` de
`reponses/`). Ce qui a changé :

- **Minuterie de relève reposée au démarrage** (EX-8.12, EX-8.8) : pour toute
  demande de jeton non finale qui admet la relève et dont le secours n'est ni
  engagé ni épuisé, la minuterie est reposée à premier envoi +
  `fallback_after_s` ; échue, la relève part à l'instant du démarrage
  (traces `redemarrage-releve` et `file-pleine` : cent jetons de clôture relevés
  au démarrage). Le premier envoi est lu comme pour `d_jeton` (tentative de
  rang 1, sinon la plus ancienne tentative portée).
- **EX-4.4 appliquée aux demandes de points relues** (EX-8.12) : une demande
  `jeton_point` non finale dont toutes les échéances sont inférieures à une
  échéance `satisfaite` d'une autre demande de la période est close
  `remplacee` au démarrage, avec `remplacer`, les échéances `remplacee`, la
  ligne `checkpoint_anchor_late` et l'alerte de 8.9 (trace
  `redemarrage-echeance-remplacee`) ; sa reprise programmée ne part pas.
- **Série d'échecs relue** (EX-8.9) : `k` est repris de la ligne relue, par
  prestataire ; une tentative `redemarrage` (ou en cours au démarrage, qu'EX-8.12
  clôt ainsi) interrompt la série, et l'échec suivant a `k = 1` ; sans elle,
  une demande relue `a_reprendre` garde ses échecs antérieurs. AN-37 reprend
  la même série depuis `queue_before`.
- **`PKIStatus` hors de 0 à 5** (EX-5.10, étape 2) : `statut_<n>`,
  permanente, non critique, jeton non lu ni promu (cas `statut-6`) ; le
  `status` est lu comme tout INTEGER (complément à deux, plusieurs octets
  admis) et un `status` au-delà de ±(2^53 − 1) rend la réponse
  `reponse_illisible` ; `pki_status` consigné tel que lu.
- **Arcs d'OID sur 128 bits** (EX-5.1, EX-4.9 règle 9) : à l'encodage comme au
  décodage d'une requête, un arc au-delà de 2^128 − 1 est refusé ; les arcs
  sont lus et écrits en entiers non bornés (un arc de plus de 64 bits n'est
  plus tronqué).
- **Relecture de la file** (EX-8.5, règle 3) : un fragment de fin de fichier
  sans fin de ligne est retiré, même lisible ; une ligne mal formée hors de
  la fin est consignée et ignorée, la ligne valide précédente du même `id`
  faisant foi. La famille `reprise` ne suppose plus les fichiers d'époque
  tous lisibles : elle confronte le nombre de lignes mal formées et le
  fragment de fin, comptés ligne à ligne, à ce que la relecture consigne
  (trace `file-lignes-illisibles`), puis la relecture à la file avant.

Ces corrections ont été écrites depuis le texte révisé de CT-5 et les
vecteurs, sans lire la référence ; elles ne rendent pas le module
indépendant (voir plus haut, et CT-5 A.5).

## Compléments du 2026-11-16 de CT-5

Le module rejoue les sept traces nouvelles (`empreinte-squattee`,
`empreinte-squattee-repli`, `registre-saut-horloge`,
`redemarrage-due-at-borne`, `redemarrage-jeton-sans-acquisition`,
`file-perdue-jeton-point-obtenu`, `file-perdue-jeton-periode-obtenu`), leurs
fichiers de `reprise/`, et vérifie la famille `configuration`. Règles
appliquées, chacune citée en commentaire à l'endroit du code qui l'applique :

- **Ancre d'une période refusée** (EX-9.7, EX-8.4 règle 2) : après
  `empreinte_squattee` sur `ancre_registre_periode`, `jeton_periode` reste
  `attente_registre`, aucune requête RFC 3161 sur `periodHash` ne part,
  l'attente est réexaminée toutes les `inclusion_alert_s` (ligne
  `registry_pending` à chaque examen, alerte une fois) ; le refus de l'ancre
  d'un point libère toujours son `jeton_point`.
- **Repli de clôture après ce refus** (EX-8.4 règle 2, EX-9.7) :
  `squat_wait_s` après la clôture, le repli est engagé dès que
  `jeton_periode` est encore `attente_registre`, quel que soit l'état de
  l'ancre de la période.
- **Rejeux bornés par passe** (EX-8.10) : une passe est le traitement d'une
  entrée ; le renvoi d'une ancre sans reçu et l'examen de l'attente du
  registre d'un `jeton_periode` sont rejoués au plus quatre fois par passe et
  par demande ; au quatrième rejeu, la minuterie est reposée à sa première
  échéance postérieure à l'instant de l'entrée ; pour l'ancre, la ligne
  `anchor_retry` (`kind`, `mode` `renvoi`, `error_code` `recu_absent`,
  `missed_deadlines`, `attempt`, `attempt_id` de la tentative close) est
  écrite avant le renvoi si au moins une échéance est sautée.
- **Série d'échecs** (EX-8.9) : une tentative `obtenue` ou en échec permanent
  interrompt la série du prestataire en cours de marche comme à la relecture
  (`Planificateur.reponseRfc3161`, `relireSerie`, AN-37).
- **Demandes couvrantes au démarrage** (EX-8.12) : les demandes de jeton
  `obtenue` relues de la période, les `jeton_point` par plus petite échéance
  croissante (repli de clôture compté `n_T`, égalité dans l'ordre de la file),
  puis le `jeton_periode` ; chacune clôt les demandes non finales qui servent
  une échéance ouverte inférieure à sa plus grande échéance ; `replaced_by`
  nomme la première ; `window_s` = borne du jeton couvrant − `D_k` de la plus
  petite échéance close. Le premier envoi de la relève reposée est la
  tentative de rang 1, sinon la plus ancienne tentative portée.
- **Borne de `due_at` au démarrage** (EX-4.13) : la reprise d'une demande
  `a_reprendre` (jeton, soumission OpenTimestamps) dont `due_at` dépasse
  l'instant du démarrage plus `retry.max_ms` est ramenée à cette borne :
  `programmer` (raison `backoff`) puis ligne réécrite `a_reprendre` ; la mise
  à niveau d'une preuve `en_attente` n'est pas bornée.
- **Demande `obtenue` sans enregistrement** (EX-5.8) : avec le membre
  `acquisitions` de l'entrée `demarrage`, juste après `anchoring_started` et
  dans l'ordre de la file, une demande de jeton `obtenue` sans enregistrement
  de même `request_id` et de même `token_sha256` perd son résultat, est écrite
  `a_reprendre` à l'instant du démarrage, alertée `file_perdue` (critique),
  puis reprise au rang `attempts_total + 1` ; sans le membre, rien.
- **Demande recréée `obtenue`** (EX-8.12) : avec le membre `acquisitions` de
  l'entrée `stockage_relu`, une demande de jeton recréée qui a un
  enregistrement (le dernier pour une même demande) est écrite `obtenue` avec
  son résultat, sans tentative ; ses échéances sont satisfaites (`n_T` pour
  le `jeton_periode`) ; aucune requête, attente du registre, repli de
  clôture, pièce ni ligne `checkpoint_countersigned` ou `period_timestamped`.
- **Schéma** (`planificateur-ancrage-v0`) : le membre facultatif
  `acquisitions` des entrées `demarrage` et `stockage_relu` est lu selon
  `$defs/acquisition_relue` (exactement `request_id`, une demande de jeton,
  et `result`, de `$defs/resultat` ; au plus 20 000 éléments pour
  `stockage_relu`) ; un élément hors de cette forme refuse l'entrée.
- **Invariants** : AN-34 et AN-33 admettent les deux écritures que ces
  compléments imposent hors de la table d'EX-8.3 : première ligne `obtenue`
  d'une demande recréée avec enregistrement (EX-8.12) et `a_reprendre →
  a_reprendre` au démarrage après la borne de `due_at` (EX-4.13).
- **Famille `configuration`** (AN-1, EX-4.9) : `schema.go` valide le document
  contre `ancrage-v0` (sous-ensemble de JSON Schema 2020-12 que ce schéma
  emploie ; un autre mot-clé refuse le schéma au chargement ; les motifs
  ECMA-262 sont traduits pour `regexp`) ; `regles_an1.go` applique les règles
  1 à 9 : 1 (valeur de l'enregistreur, diviseur de 3600, valeur connue en
  production), 2, 3, 4 (production : `provider_role`, `registry.checkpoints`,
  OpenTimestamps, `principal` et `secours` qualifiés, `https://`,
  `headers_source` non nul ; tout profil : `interne` jamais qualifié, `url`
  sans identifiant, `auth.method` et `auth.secret` cohérents, règles
  d'adresse et d'authentification du rôle `interne`, que suit hors
  production un `principal` non qualifié ; `https://` avec authentification
  pour un `principal` qualifié, un `secours` ou un `second_rang`), 4 bis
  (forme de `crl_hosts`, par le schéma), 5, 6, 7, 8 (lecture du PEM, voir
  « Limites ») et 9 (OID encodable par l'encodeur d'EX-5.1, arcs sur 128
  bits, DER d'au plus 127 octets).

### Compléments suivants du 2026-11-16

Le module rejoue aussi les dix-neuf traces publiées depuis
(`redemarrage-jeton-recree-couvrant`, `redemarrage-ancres-a-reprendre`,
`repli-ancre-incluse-jeton-retenu`, `ots-reponses-insuffisantes`,
`redemarrage-ots-soumission-envoyee`, `ots-preuve-absente`,
`redemarrage-ots-a-reprendre-en-cours`, `reponses-hors-tentative`,
`registre-renvois`, `redemarrage-releve-deux-series`,
`minuteries-simultanees`, `jeton-tardif-avertissements`,
`redemarrage-ordre-de-la-file`, `redemarrage-a-envoyer-cle-libre`,
`redemarrage-echeances-remplacees`, `registre-inclusion-apres-attente`,
`redemarrage-prestataires-epuises`, `registre-cle-par-journal`,
`minuteries-deux-journaux` ; cinquante-quatre traces en tout), leurs fichiers
de `reprise/` (vingt et une paires en tout) et les vingt-cinq cas de la
famille `configuration`. Règles appliquées, chacune citée en commentaire :

- **Demande recréée `obtenue`** (EX-8.12) : elle s'applique comme à sa
  promotion (EX-4.4) : demandes de points non finales qui servent une
  échéance ouverte inférieure à sa plus grande échéance (`n_T` pour le
  `jeton_periode`) closes `remplacee` avec `checkpoint_anchor_late`, échéance
  ouverte sans demande `remplacee`, repli de clôture clos par le
  `jeton_periode` (`appliquerPromotion`).
- **Ordre du démarrage** (EX-8.12) : `anchoring_started`, réouvertures
  d'EX-5.8, échéances relues, EX-4.4, puis une passe dans l'ordre de la file
  (une ancre `a_envoyer` n'attend le nonce que si sa clé est occupée ; une
  ancre `a_reprendre` garde son `due_at`, borné par EX-4.13, et repart à
  `max(due_at, t)`), puis les départs comme après toute entrée, puis les
  minuteries échues.
- **Registre** (EX-8.10) : un échec signalé (hors `empreinte_squattee`) clôt
  la tentative (`echec_permanente` pour `refus_*`) ; `refus_*` rend `refusee`
  l'ancre d'un point (`prestataires_epuises` majeure, `anchor_refused`, son
  jeton part) ; sinon `anchor_retry` (mode `reprise`, tentative close),
  `a_reprendre`, `programmer backoff` (`k` : tentatives non obtenues ;
  `retry.max_ms` pour le refus de l'ancre d'une période) ; à l'échéance,
  renvoi si la clé est libre, sinon `attente_nonce`. Un reçu ou un échec ne
  s'applique qu'à une ancre en vol, sinon `anchor_duplicate_ignored` avec
  `state` (ou `reason` `demande_inconnue`) ; une ancre renvoyée n'a pas de
  `due_at` ; `inclusion_late` au reçu se compte depuis la création de
  l'ancre, sauf si un renvoi l'a levée depuis le démarrage.
- **Clé de chaîne** (EX-9.4) : celle du journal du sujet (`org_id`,
  `journal_id`) ; candidates aux départs : ancres `a_envoyer` et ancres
  `a_reprendre` échues sans reprise programmée ; pour chaque clé libre, la
  première candidate part (ordre remplacé depuis : voir plus bas).
- **OpenTimestamps** (EX-8.11, EX-8.9, EX-8.12) : moins de `min_responses`
  réponses valables (`reponses_insuffisantes`) ou aucune preuve écrite
  (`preuve_absente`) : `rejeter_reponse` (transitoire), ligne
  `anchor_response_rejected`, `a_reprendre`, `programmer backoff` sur la
  série de la soumission, relue au démarrage depuis la ligne ; à la mise à
  niveau, une attestation Bitcoin sans preuve laisse `en_attente` ; une ligne
  `a_reprendre` qui porte une tentative en cours se reprend comme `envoyee`.
- **Réponses qui ne s'appliquent pas** (EX-8.5, règles 1 et 2) :
  `demande_inconnue`, `tentative_inconnue` (jeton gardé, borne nulle),
  `tentative_close`, `demande_close`, avec `attempt`, `attempt_id`,
  `provider` et `kept` ; borne d'une pièce seulement si le jeton passe les
  étapes 3 à 6 d'EX-5.10 pour la tentative qu'il désigne (nonce gardé quand
  la tentative sort de la fenêtre de 32).
- **Classement** (EX-5.10) : `status` 0 ou 1 sans `TimeStampToken` :
  `reponse_illisible` ; `PKIFailureInfo` hors des huit valeurs : `statut_2` ;
  précision hors de la plage d'un instant : `verification_T-7`.
- **Minuteries de même échéance** (EX-8.16) : celles des périodes
  (échéances, cadence) d'abord, dans l'ordre d'armement quel que soit le
  journal, puis celles des demandes dans l'ordre de la file, puis
  d'armement.
- **Invariants** : AN-34 admet en plus la réécriture d'une soumission relue
  avec une tentative en cours ; AN-37 vérifie l'attente des soumissions et
  des ancres reprises ; AN-40 compte le délai d'inclusion depuis la création.

### Derniers compléments du 2026-11-16

Le module rejoue aussi les quatre traces publiées en dernier
(`registre-refus-ancre-periode`, `registre-ordre-des-points`,
`registre-periode-apres-point-de-cloture`, `redemarrage-ots-abandon-origine` ;
cinquante-huit traces en tout), les deux traces changées
(`redemarrage-a-envoyer-cle-libre`, `registre-indisponible-cloture`) et leurs
fichiers de `reprise/` (vingt-trois paires en tout). Règles appliquées,
chacune citée en commentaire :

- **Ordre des ancres d'une clé** (EX-9.4, EX-8.12 point 6) : quand la clé se
  libère, et après la passe du démarrage, part au plus une ancre de la clé,
  la première des ancres qui attendent par `period_start` croissant, puis,
  dans une période, ses points par `checkpoint_ts` croissant, puis l'ancre
  de la période ; l'ordre de la file ne départage que les égalités ; les
  clés sont servies dans l'ordre de la file de leur première ancre en
  attente (`servir`, `avantDansLaCle`).
- **L'ancre de la période après celles de ses points** (EX-9.4, EX-8.4
  règle 2) : elle ne part pas tant qu'une ancre de point de sa période et de
  son journal n'est pas finale (`periodeBloquee`) ; à sa création ou à
  l'échéance de sa reprise, elle attend alors (`programmer attente_nonce`,
  `attendOuEnvoie`) ; aux départs, si la première ancre de la clé est une
  période ainsi bloquée, rien ne part.
- **Refus définitif de l'ancre d'une période** (EX-8.10) : après la ligne
  `anchor_retry`, l'alerte `prestataires_epuises` critique, une fois par
  ancre depuis le dernier démarrage ; reprise à exactement `retry.max_ms`,
  sans gigue.
- **Âge d'abandon OpenTimestamps** (EX-8.11) : compté depuis `created_at` de
  la demande, au démarrage comme en marche (`ots_give_up`, mise à niveau
  quotidienne).
- **Invariants** : AN-33 n'admet la réécriture `a_reprendre → a_reprendre`
  au démarrage que comme borne d'EX-4.13 ou reprise d'une soumission relue
  avec une tentative en cours ; AN-36 vérifie que l'ancre d'une période ne
  passe `envoyee` qu'après les ancres de ses points ; AN-37 établit qu'une
  réponse des calendriers s'applique par la tentative ouverte (A.4), sans
  lire l'action `rejeter_reponse` ; AN-41 exige la mise à niveau quotidienne
  au-delà de `give_up_after_s` comptés depuis la création.

### Compléments de clôture du 2026-11-16

Le module rejoue aussi les quatre traces publiées en dernier
(`registre-periode-retient-la-cle`, `redemarrage-ots-abandon-soumission-tardive`,
`registre-refus-ancre-periode-redemarrage`, `registre-points-en-reprise` ;
soixante-deux traces en tout) et les fichiers de `reprise/` des deuxième et
troisième (vingt-cinq paires en tout) ; la famille `configuration` garde ses
vingt-cinq cas. Règles appliquées, chacune citée en commentaire :

- **Clé retenue par une période antérieure** (EX-9.4, « une ancre de période
  qui attend retient sa clé ») : une ancre est retenue tant qu'une ancre de
  période de son journal, d'une période antérieure, n'est pas finale
  (`retenue`). Retenue, elle attend (`programmer attente_nonce`, sans
  minuterie) à sa création et à l'échéance de sa reprise (`attendOuEnvoie`) ;
  quand la clé se libère et après la passe du démarrage, si la première
  candidate de la clé est retenue, rien ne part (`servir`). La passe du
  démarrage (EX-8.12, point 5) est inchangée.
- **Ordre des ancres des points d'une période** (EX-9.4) : l'ancre d'un point
  est retenue tant que l'ancre d'un point antérieur de sa période et de son
  journal (`checkpoint_ts` plus petit, puis `created_at`, puis `id` :
  `PointAnterieur`) n'est pas finale ; mêmes effets.
- **Remplacement d'une ancre de point en reprise** (EX-9.5) : à l'admission
  d'un point, une ancre de point de la même période et du même journal
  « encore à envoyer » passe `remplacee` (`remplacer`, `ecrire_file
  remplacee`, `journaliser anchor_replaced`, dans l'ordre de la file), sa
  reprise n'ayant pas lieu. Encore à envoyer : `a_envoyer`, ou `a_reprendre`
  dont toutes les tentatives sont closes sur un code d'échec sans admission
  (`CodesSansAdmission`), sans tentative sortie de la fenêtre de 32 avant le
  dernier démarrage (`attempts_total` égal au nombre de tentatives de la
  ligne relue) ni sortie pendant la marche sur un autre code
  (`encoreAEnvoyer`, `noterFenetreRelue`).
- **Soumission OpenTimestamps aboutie au-delà de l'âge d'abandon**
  (EX-8.11) : l'alerte `ots_give_up` majeure est levée dès le passage
  `en_attente`, après `stocker` et avant l'écriture `en_attente`, une fois
  par demande depuis le dernier démarrage (marque effacée au `demarrage`) ;
  la première mise à niveau reste à `first_after_s`, la cadence quotidienne
  suit sa réponse sans attestation, sans nouvelle alerte.
- **Déjà suivis** : candidates du point 6 du démarrage (EX-8.12 : une
  `a_reprendre` échue a sa reprise armée par la passe) ; alerte du refus
  définitif de l'ancre d'une période levée de nouveau après un redémarrage
  (EX-8.10) ; ordre d'une action et d'une entrée du même instant (A.4,
  AN-37).
- **Invariants** : AN-36 vérifie sur chaque trace ses trois invariants
  (A.4) : ancre de la période après celles de ses points, clé retenue par une
  période antérieure, ancres des points d'une période dans l'ordre.

## Interprétations retenues

- EX-8.5, règle 1, dit que la ligne `envoyee` est écrite avant que la requête
  parte ; la trace normative de 8.10 range pourtant l'action `ecrire_file`
  `envoyee` après `envoyer_rfc3161`, `envoyer_registre` ou `soumettre_ots`
  du même instant. Le rejeu reproduit l'ordre de la trace normative (AN-42)
  et l'invariant AN-32 exige la ligne au même instant, dans l'un ou l'autre
  ordre.
- Les vérifications T- qu'une réponse exige sont des entrées de la trace
  (`checks_passed`) et de la famille `reponses` ; une T- absente de la liste
  vaut échec de cette T- (code `verification_T-<n>`), comme EX-A.4 le prévoit.
- Les jetons représentés des traces (`SHA-256(UTF-8("jeton <nom>"))`, A.2) ne
  sont pas recalculés : le `<nom>` n'est pas fixé par la spécification ; ce
  sont des entrées, recopiées telles quelles dans `stocker` et `result`.
- Révision 0.6 : l'instant d'admission d'un point dont les demandes viennent
  de la file relue (admis avant le démarrage) est la plus ancienne date de
  création de ses demandes, créées à son admission (EX-8.4, règle 1) ; le
  premier envoi d'un jeton est la tentative de rang 1 si la ligne la porte
  encore, sinon l'instant retenu pendant le rejeu, sinon la plus ancienne
  tentative portée (le texte ne dit pas d'où le tirer quand la fenêtre l'a
  retiré et que le processus a redémarré). La ligne `anchor_fallback` porte la
  tentative la plus récente, dont l'issue (délai de relève ou erreur
  permanente) déclenche la relève ; `anchor_retry` porte la tentative qu'il
  renvoie (au démarrage) ou, après `echec_registre`, la tentative close
  (EX-8.10, complément du 2026-11-16).
- Révision 0.10, EX-4.4 au démarrage : quand plusieurs demandes ont une
  échéance satisfaite au-delà de celles de la demande close, `replaced_by`
  nomme celle de la plus petite (la « `D_{k+1}` » d'EX-4.4), à défaut le
  `jeton_periode` obtenu (échéance `n_T`) ; `window_s` se lit, comme en cours
  de rejeu, sur la borne du jeton qui couvre moins `D_k` de la plus petite
  échéance close. Une demande sans échéance (repli de clôture) n'est close au
  démarrage que par le jeton de clôture obtenu (EX-4.2). Ces fermetures
  précèdent les transitions de reprise, comme l'ordre du démarrage d'EX-8.12
  le fixe désormais (complément du 2026-11-16, point 4).
- Révision 0.10, série relue (EX-8.9) : un résultat autre qu'un échec
  transitoire (`obtenue`, `echec_permanente`) interrompt aussi la série ;
  `k` n'est compté que sur les tentatives que la ligne porte (fenêtre de 32).
  Le complément du 2026-11-16 le dit désormais, en cours de marche aussi.
- Complément du 2026-11-16, EX-5.8 : un enregistrement « de même
  `token_sha256` » est cherché parmi ceux de même `request_id`
  (`$defs/acquisition_relue` : « la demande de jeton qu'il sert ») ; deux
  jetons distincts ayant des SHA-256 distincts, le verdict est le même.
- Complément du 2026-11-16, EX-8.12 : une demande recréée `obtenue` s'applique
  comme à sa promotion (EX-4.4), le texte le disant désormais ; `window_s` se
  lit sur la borne de son résultat (`bound`, à défaut `obtained_at`).
- Complément du 2026-11-16, EX-8.10 et EX-8.11 : « une fois par ancre (ou
  par demande) depuis le dernier démarrage » est tenu par une marque de
  l'état interne de la demande, effacée à chaque `demarrage`.
- Règle 9 d'EX-4.9 : « DER de l'OID d'au plus 127 octets » est lu sur
  l'OBJECT IDENTIFIER complet (étiquette, longueur et contenu).

## Tests du module

`go test ./...` : permutation Keccak confrontée à `crypto/sha3`, requête
d'EX-5.1 (69 octets, nonce de CT-1 §13) et refus d'AN-5 et AN-6, exemple
minimal d'EX-6.4 (195 octets) et resérialisation, formule de coût sur le
premier cas de 12.3, attente de reprise d'EX-8.9 et sa suite 5 s, 10 s, …,
300 s, table des transitions d'EX-8.3, invariants de la section 8.11 sur la
trace de référence, fenêtre de 32 tentatives et lecture des lignes d'avant
la révision 0.6 (`TestFenetreTentatives06`), rejeu des traces publiées et confrontation complète
des vecteurs (ces deux derniers ignorés quand les vecteurs sont absents, en
échec quand le rapport porte une discordance). Révision 0.10
(`revision010_test.go`, un test par règle) : `PKIStatus` hors de 0 à 5 et
hors des entiers représentables (`TestStatutHorsTableEX510`), arcs d'OID sur
128 bits (`TestArcsOID128BitsEX51`), fragment de fin et ligne mal formée
(`TestFragmentEtLignesIllisiblesEX85`), relève reposée au démarrage
(`TestReleveReposeeAuDemarrageEX812`), EX-4.4 appliquée aux demandes relues
(`TestEcheancesRemplaceesAuDemarrageEX812`), série d'échecs relue et AN-37
(`TestSerieDeReprisesRelueEX89`). Compléments du 2026-11-16
(`complement20261116_test.go`, un test par règle) : ancre de période refusée
(`TestAncrePeriodeRefuseeEX97`), repli après ce refus
(`TestRepliApresRefusEX84`), rejeux bornés par passe
(`TestRejeuxBornesParPasseEX810`), demandes couvrantes relues
(`TestCouvrantesReluesEX812`), série interrompue en cours de marche
(`TestSerieInterrompueEnMarcheEX89`), borne de `due_at`
(`TestBorneDueAtAuDemarrageEX413`), réouverture sans enregistrement
(`TestReouvertureSansAcquisitionEX58`), demande recréée obtenue
(`TestDemandeRecreeeObtenueEX812`), forme du membre `acquisitions`
(`TestAcquisitionsSchema`), famille `configuration` publiée
(`TestFamilleConfigurationAN1`) et chaque règle d'AN-1 sur des documents
construits (`TestReglesConfigurationEX49`). Compléments suivants
(`complements20261116_suite_test.go`, un test par règle) :
`TestReponsesInsuffisantesEX811`, `TestSerieSoumissionRelueEX89` (entrées
construites), `TestPreuveAbsenteEX811`, `TestReponseOtsHorsTentativeEX85`,
`TestOtsAReprendreEnCoursEX812`, `TestReponseRfc3161HorsTentativeEX85`,
`TestBornePieceEX85`, `TestClassementEX510`,
`TestEvenementsRegistreIgnoresEX810`, `TestEchecRegistreAReprendreEX810`,
`TestOrdreMinuteriesEX816`, `TestMinuteriesDeuxJournauxEX816`,
`TestOrdreDemarrageEX812`, `TestAncresAReprendreEX812`,
`TestInclusionLateDepuisCreationEX810` (et AN-40), `TestCleParJournalEX94`,
`TestRecreeeCouvranteEX812`, `TestAttenteSoumissionAN37`. Derniers
compléments (`ordre_des_ancres_test.go`, un test par règle) :
`TestOrdreDesAncresDuneCleEX94`, `TestPeriodeBloqueeAuxDepartsEX94`,
`TestPeriodeBloqueeAReprendreEX94` (file relue construite),
`TestRefusAncrePeriodeEX810`, `TestAgeAbandonOtsEX811`,
`TestAN33SoumissionRelueEnCours`, `TestAN37SansActionRejet`,
`TestAN36PeriodeApresSesPoints` et `TestAN41AgeAbandonDepuisCreation` (ces
cinq derniers sur une trace publiée altérée). Compléments de clôture
(`cle_retenue_test.go`, un test par règle) :
`TestCleRetenueParLaPeriodeAnterieureEX94`,
`TestRemplacementAncreEnRepriseEX95`,
`TestAncreRetenueParUnPointAnterieurEX94`,
`TestAlerteAbandonSoumissionTardiveEX811`, `TestAN36CleRetenue` et
`TestAN36PointsAnterieurs` (ces deux derniers sur les actions attendues
d'une trace publiée, altérées).

## Limites

- Les vérifications T-1 à T-9 de CT-6 ne sont pas refaites : la famille
  `reponses` et les traces les déclarent (`checks_passed`), comme EX-A.4 le
  prévoit ; le module lit le `TSTInfo` (empreinte, nonce, `genTime`,
  `accuracy`, politique) sans vérifier la signature ni le chemin.
- Le verdict `openssl_verify` de la famille `reponses` est celui d'un outil
  tiers : il est énoncé « hors périmètre » et confronté par
  `../confrontation/`.
- Le module ne valide pas les traces contre le schéma
  `planificateur-ancrage-v0` (c'est le rôle de `test/ancrage.test.js`) ; il
  lit seulement leurs demandes et le membre `acquisitions` de leurs entrées
  selon leurs `$defs`. Il valide en revanche chaque document de la famille
  `configuration` contre `ancrage-v0`.
- Le recul de l'heure murale (EX-4.13) n'est pas représenté : une entrée
  antérieure à l'instant déjà servi est refusée (A.3).
- Règle 4 d'EX-4.9 : le refus d'un document qui désigne un prestataire au
  retrait de `qualified` en vigueur (état du composant, EX-5.9) et, règle 4
  bis, le contrôle des adresses de CRL à la capture (EX-5.10, étape 10) ne se
  lisent pas dans le document et ne sont pas appliqués (A.3).
- Règle 8 d'EX-4.9 : le PEM est lu par le lecteur DER borné du module
  (longueurs minimales, étiquettes inférieures à 31, profondeur au plus 32,
  aucun octet après la structure) et doit avoir la forme d'un `Certificate`
  X.509 ; les autres contrôles du profil de CT-6 §9.3 (EX-9.4 : formes des
  types universels, noms ; EX-9.21 : valeurs `DEFAULT` encodées) ne sont pas
  refaits, comme le reste de CT-6 (EX-A.4). Aucun cas publié ne viole la
  règle 8.
