# Vérificateur indépendant CT-5 (Go, salle blanche)

Un second vérificateur des vecteurs de CT-5, écrit en Go depuis la
spécification [`spec/CT-5-ancrage.md`](../../../CT-5-ancrage.md) (et, pour
ce qu'ils définissent, CT-1 §10.5 à §10.7, CT-6 §9 et §10, RFC 3161, le
schéma `spec/schemas/planificateur-ancrage-v0.schema.json` qu'elle cite),
sans importer ni reprendre le code JavaScript de `scripts/` ni les tests de
`test/` (annexe A.5, EX-A.4). Il recalcule ce que la spécification définit et
le confronte à chaque valeur attendue trouvée dans `spec/vecteurs/ct-5`. Deux
implémentations écrites séparément qui tombent sur les mêmes octets rendent
les vecteurs probants ; une discordance désigne une ambiguïté de la
spécification ou une faute de l'une des deux, et le vérificateur la liste
sans la masquer.

**Indépendance (révision 0.2 de CT-5).** Le module a été écrit depuis la
spécification seule. Lors de la correction de la révision 0.2, il a été audité
puis complété (ordre « ligne `envoyee` puis envoi » d'AN-32, transitions
`envoyee → a_envoyer` et `obtenue → a_reprendre` d'EX-8.3, échéances rendues
sur refus, repli de clôture, reconstruction de la file et fichiers d'époque,
nouvelles alertes, classement des étapes 1 et 5, famille `completude`, plafond
d'ancres `2 + 3600 / c_K`) par un rédacteur qui avait aussi lu la référence
JavaScript. Les règles ajoutées sont celles du texte révisé, mais cette partie
du module n'est plus une écriture à l'aveugle : son indépendance repose sur
cette déclaration, et une relecture à l'aveugle reste à faire (CT-9).

Bibliothèque standard uniquement (`crypto/sha256`, `crypto/sha3` pour les
tests, `encoding/hex`, `math/big`, `encoding/json` pour la seule sortie du
rapport). Module `noortrace-ct5`, `go 1.24`. Trois fichiers sont copiés du
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
| planification | `planification/*.json` | rejeu de chaque trace par le planificateur de la section 8 (machine à états à horloge injectée) : chaque action de `expected` (forme canonique JCS v0, dans l'ordre), chaque demande de `queue_after` ; `request_sha256` et `request_size` de chaque `envoyer_rfc3161` recalculés depuis le détail attendu ; puis les invariants de la section 8.11 sur la trace rejouée (table ci-dessous) |
| reprise | `reprise/*.avant.ndjson`, `*.apres.ndjson`, la trace de même nom | relecture de la file (dernière ligne d'un id fait foi, ligne tronquée signalée), lignes égales à la forme canonique de `queue_before`, rejeu de la trace depuis la file relue, lignes finales égales à `queue_after` et au fichier `.apres.ndjson`, une seule demande par id |
| cout | `cout/cout.json` | formule de la section 12 (EX-12.1, EX-12.2) : jetons qualifiés et de second rang par journal et par an, ancres au registre, borne de gaz, coût par journal et total, arrondis à trois décimales ; pour les cas à `a = 1` (ou `countersign_idle` vrai), `N_q`, `N_s` et `N_a` égalent `N_h` fois les comptages par heure d'EX-4.11, recalculés à part (table de 4.6, AN-59) ; les prix sont les paramètres symboliques du cas, jamais une valeur du module (AN-60) |

Invariants vérifiés sur chaque trace de `planification/` (fichier
`invariants.go`), chacun comptant pour une valeur « aucun écart » :

| Règle | Ce qui est vérifié |
|---|---|
| AN-32 | toute action `envoyer_rfc3161`, `envoyer_registre` ou `soumettre_ots` est accompagnée, au même instant, d'une ligne `envoyee` de la demande ; pour une requête RFC 3161, la ligne porte le nonce et le rang de la tentative (EX-8.5, règle 1) ; un renvoi d'ancre déjà `envoyee` est admis (EX-8.12) |
| AN-33 | une seule demande par `id` dans `queue_after`, état égal à la dernière ligne écrite ; au `demarrage`, les seules transitions d'EX-8.12 (une demande `envoyee` passe `a_reprendre`, une ancre `envoyee` est renvoyée sans réécriture, `attente_registre` interroge l'inclusion, `en_attente` est reprogrammée à `max(due_at, now)`, aucun état final sans réponse) |
| AN-34 | chaque `ecrire_file` est une transition de la table d'EX-8.3 (première ligne `a_envoyer` ou `attente_registre`) ; aucun `jeton_periode` dans un état final autre qu'`obtenue` |
| AN-35 | une échéance ouverte par l'horloge l'est à `D_k = period_start + k × c_T` ; chaque `k` d'une demande `jeton_point` est dans `[1, n_T − 1]`, le point a `checkpoint_ts ≥ D_k` et aucun point antérieur de la période ne satisfaisait déjà `D_k` ; un `k` n'est servi que par une demande (EX-4.2, EX-4.3) |
| AN-36 | un `jeton_periode` n'est envoyé qu'après une entrée `inclusion_registre` de son ancre ; un `jeton_point` dont l'ancre est partie n'est envoyé qu'après son inclusion, son refus `empreinte_squattee`, ou la ligne `ordre_ancres_non_respecte` écrite à `admission + squat_wait_s` (EX-8.4, EX-9.6, EX-9.7) |
| AN-37 | après chaque rejet transitoire, l'attente programmée est recalculée depuis les entrées : `Retry-After` pour 429 et 503, 0 pour le premier 408 de la demande chez ce prestataire, sinon `min(max_ms, initial_ms × factor^(k−1))` plus la gigue de `jitter_ms` consommée dans l'ordre, avec la raison attendue (EX-8.9) |
| AN-39, AN-58 | au moins `min_interval_ms` entre deux requêtes au même prestataire, toutes demandes confondues ; à un même instant, `jeton_periode` servi avant `jeton_point` (EX-8.7) |
| AN-40, AN-48 | `stocker` (index de capture) précède `obtenue` pour une ancre au registre ; `empreinte_squattee` donne `refusee` sans renvoi ; une inclusion constatée plus d'`inclusion_alert_s` après l'envoi a été alertée `inclusion_late` (EX-8.10, EX-9.7) |
| AN-41 | `en_attente` après une soumission exige une réponse `en_attente` d'au moins `min_responses` calendriers au même instant ; la mise à niveau est programmée `first_after_s` après la soumission puis toutes les `max(interval_s, 60 s)` (ou un jour après `give_up_after_s`) ; `complete` exige une attestation Bitcoin reçue à cet instant et la ligne `ots_complete` avec réexport (EX-8.11) |
| AN-43 | aucune ligne de journal, d'alerte ni de file ne porte un mot de passe, un secret, un en-tête d'autorisation, un identifiant d'accès, un prix (mots de `MotsInterdits`, sans tenir compte de la casse) ni une adresse IP |
| A.2 | formes représentées : `capture_sha256` de chaque inclusion vaut `SHA-256(UTF-8("capture <id> <bloc>"))` ; dans la trace de référence, la preuve `.ots` représentée vaut `SHA-256(UTF-8("preuve en attente periode 1"))`, taille 233 |

Le planificateur (`planificateur.go`) porte les règles EX-4.2 à EX-4.7
(échéances, sélection du point, échéances remplacées, ancre des points,
ordre des ancres), EX-5.10 à EX-5.12 (classement), EX-8.3 à EX-8.12 (états,
file, priorité et `min_interval_ms`, relève, attente de reprise, registre,
OpenTimestamps, redémarrage) et EX-9.3 à EX-9.5 (une transaction par clé de
chaîne, remplacement des ancres non parties). Les nonces et les gigues
viennent d'une source dérivée des étiquettes d'A.2 et de `jitter_ms`
(EX-8.13) ; l'horloge n'est jamais lue.

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

## Tests du module

`go test ./...` : permutation Keccak confrontée à `crypto/sha3`, requête
d'EX-5.1 (69 octets, nonce de CT-1 §13) et refus d'AN-5 et AN-6, exemple
minimal d'EX-6.4 (195 octets) et resérialisation, formule de coût sur le
premier cas de 12.3, attente de reprise d'EX-8.9 et sa suite 5 s, 10 s, …,
300 s, table des transitions d'EX-8.3, invariants de la section 8.11 sur la
trace de référence, rejeu des douze traces publiées et confrontation complète
des vecteurs (ces deux derniers ignorés quand les vecteurs sont absents, en
échec quand le rapport porte une discordance).

## Limites

- Les vérifications T-1 à T-9 de CT-6 ne sont pas refaites : la famille
  `reponses` et les traces les déclarent (`checks_passed`), comme EX-A.4 le
  prévoit ; le module lit le `TSTInfo` (empreinte, nonce, `genTime`,
  `accuracy`, politique) sans vérifier la signature ni le chemin.
- Le verdict `openssl_verify` de la famille `reponses` est celui d'un outil
  tiers : il est énoncé « hors périmètre » et confronté par
  `../confrontation/`.
- Le module ne valide pas les vecteurs contre les schémas JSON
  (`planificateur-ancrage-v0`) : c'est le rôle de `test/ancrage.test.js`.
- La reconstruction de la file depuis le stockage (`anchoring_queue_rebuilt`,
  EX-8.12) et les règles hors schéma de la configuration (EX-4.9) ne sont pas
  exercées par les vecteurs et ne sont pas recalculées ici.
