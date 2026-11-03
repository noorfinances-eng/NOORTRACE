# Vérificateur indépendant CT-1 (Go, salle blanche)

Un second vérificateur des formats de CT-1, écrit en Go depuis la seule
spécification [`spec/CT-1-evenements-et-formats.md`](../../../CT-1-evenements-et-formats.md)
(révision 0.5) et ses schémas, sans lire ni reprendre le code JavaScript de
`scripts/`. Il recalcule tout ce que la spécification définit et le confronte
à chaque valeur attendue trouvée dans les vecteurs de `spec/vecteurs/ct-1`.
Deux implémentations écrites séparément qui tombent sur les mêmes octets
rendent les vecteurs probants ; une discordance désigne une ambiguïté de la
spécification ou une faute de l'une des deux.

Bibliothèque standard uniquement (`crypto/ed25519`, `crypto/sha256`,
`crypto/sha3` pour les tests, `encoding/hex`, `encoding/base64`, `math/big`,
`encoding/json` pour la seule sortie du rapport). Module `noortrace-ct1`,
`go 1.24`. Depuis la révision 0.4, la courbe secp256k1 (recouvrement d'une
adresse EIP-191, AT-3) est `secp256k1.go`, copié sans modification du
vérificateur Go de `ct-3` (en-tête « Copié sans modification de … ») ; elle
emploie le `Keccak256` de `keccak.go`.

## Usage

```bash
cd spec/vecteurs/ct-1/verificateur-independant
go build -o verificateur .
./verificateur ../                 # rapport texte, code 0 si tout concorde
./verificateur -v ../              # liste aussi les valeurs concordantes et les contrôles
./verificateur -json ../ > rapport.json
./verificateur -strict ../         # exige l'égalité exacte des ensembles de contrôles en échec
go test ./...                      # tests propres au module (voir plus bas)
```

`go build` sans `-o` produit un binaire `noortrace-ct1` (nom du module) dans ce
répertoire ; `noortrace-ct1` et `verificateur` sont exclus par le `.gitignore`
local.

Codes de retour : `0` tout concorde (les valeurs hors périmètre, voir
« Limites », sont énoncées mais ne comptent pas) ; `1` au moins une
discordance ou une erreur (fichier illisible, disposition non reconnue) ; `2`
usage incorrect ou racine introuvable. Les vecteurs publiés concordent en mode
strict : chaque `attendu.json` donne la liste exacte des contrôles en échec,
cascades comprises (CT-1 §11.5).

Le rapport compte, par famille puis au total, les valeurs recalculées, les
concordantes, les discordantes (avec attendu et obtenu) et les hors
périmètre.

## Ce qui est recalculé

| Famille | Fichiers lus | Valeurs recalculées et confrontées |
|---|---|---|
| clés | `cles/cles-test.json`, `cles/cles.json` | graine = SHA-256(étiquette) et conformité de l'étiquette à §13 ; clé publique Ed25519 depuis la graine (RFC 8032 §5.1.5) ; encodage PKCS#8 ; clé canonique et hors petit ordre ; `org_id` = keccak256(slug), `journal_id` = keccak256(nom) ; nonces = SHA-256(étiquette) ; forme des adresses et clés d'approbateurs |
| journaux | `journal-*/evenements.json`, `attendu.json`, `cles.json`, `pieces.json` | règle exacte de la vérification d'un journal (§7.2, révision 0.5), en trois temps : chaque événement pour lui-même (E-1 à E-11, profondeur d'au plus 128 depuis l'objet de l'événement, puis l'origine `prev_hash` nul si et seulement si `seq = 1`), `cles.json` lu d'abord (manquements : un symptôme E-8 de type `cles` en tête) puis comparé à chaque événement (`org_id`, `journal_id`) ; la suite des `seq` sur tout le fichier (insertions, suppressions, réordonnancements) ; chaque couple consécutif (rupture, horodatage, journal, clé) ; symptômes typés (type, contrôle, `seq`) confrontés dans l'ordre aux `diagnostics` de `attendu.json`, et verdict de chaîne ; pour le journal valide : `hash`, `prev_hash`, longueur canonique, signature Ed25519, contresignature de rotation, `JCS(A)` et `D_A`, approbateurs, bornes de séquence ; SHA-256 et longueur des pièces fournies à part (E-6) |
| arbres | `merkle/arbres.json` | feuilles SHA-256(0x00 ‖ D[i]), racine RFC 6962 (période vide : 32 octets nuls, distingués de SHA-256("")), chemin d'audit de chaque preuve, `leaf_hash`, `tree_size`, et exécution de l'algorithme de vérification de §9.3 |
| cohérence | `merkle/coherence.json` (révision 0.3) | preuve de cohérence RFC 9162 §2.1.4 régénérée nœud pour nœud (`PROOF(m, D[0..n-1])`, §10.7), racines des deux arbres, et exécution de l'algorithme de vérification de §10.7 : chaque cas valide accepté, chaque sonde (`m = 0`, `m > n`, chemin tronqué, nœud en trop, racines échangées, chemin vide, `m = n` avec chemin) refusée |
| manifestes | `manifestes/*.json`, `*.sig`, `attendu.json` | P-1, P-4, P-5 ; forme canonique `C_M` ; `periodHash` ; signature ; racine recalculée depuis le journal valide (fenêtre `[period_start, period_end)` et liste `seq`) ; `count` ; `anchorFingerprint` = keccak256(org_id ‖ journal_id ‖ periodHash) ; correspondance `PeriodMeta` ; continuité P-5 entre périodes déclarées et discontinuité attendue |
| points de contrôle | `points-de-controle/periode-N.json`, `invalides/*.json`, `attendu.json` (révision 0.3) | règles de série de §10.5 évaluées point par point (révision 0.5) : chaînage par `prev_checkpoint_hash`, `tree_size` et `checkpoint_ts` non décroissants, `checkpoint_ts ≥ period_start`, `root` et `last_hash` recalculés depuis les événements fournis (non évaluées, `piece_hors_dossier` ou `prerequis_en_echec`, quand un événement manque ou ne se hache pas, jamais remplacés par 32 octets nuls), dernier point égal au manifeste, clé en vigueur par la règle exacte de la règle 5 (événement `last_seq` fourni, sinon `cles.json`), signature et validité annoncée ; pour chaque point : forme canonique `C_K`, `checkpointHash = SHA-256(P_K ‖ C_K)`, `prev_checkpoint_hash`, signature Ed25519 sur `P_SK ‖ C_K`, clé en vigueur, preuve de cohérence `PROOF(tree_size, D[0..count-1])` vers la racine du manifeste et sa vérification ; pour chaque série invalide, les règles violées (`rules_failed`) et non évaluées (`rules_not_evaluated`, absent : liste vide) ; révision 0.5 : `evenements_partiels` (série vérifiée avec les seuls événements de `events` et le `cles.json` de `keys`) |
| dossiers | `dossiers/*/` | les contrôles D-1, D-2, E-1 à E-11 (E-9 : forme canonique des signatures et adresses recouvrées sur `D_A`), C-1 à C-3, M-1 à M-3, P-1 à P-5, A-1 à A-4 et, révision 0.3, K-1 à K-9 sur la treizième partie `points-de-controle.json` (index à douze, treize ou quatorze parties ; index à douze parties ou partie déclarée absente : aucune K- ; K-7 à K-9 non exécutées, raison admise, pour une ancre `null`) ; révision 0.5 : contrôle porteur de chaque partie, cinq cas de partie inexploitable (fichier manquant ou non ordinaire : D-2 seule, sauf `approbations.json` déclarée présente avec `approval` nul : D-2 et A-1 ; au-delà de la limite : contrôle porteur, SHA-256 non comparé ; pas du JSON, marque d'ordre d'octets, UTF-8 mal formé ou profondeur au-delà de 128 : contrôle porteur ; sans forme canonique : E-2 ; pas un objet : contrôle porteur), contrôles qui lisent une partie inexploitable non exécutés sans raison admise sauf échec, partie contraire à son schéma exploitable, relations à terme absent, mal typé ou incalculable en échec, `dossier.json` illisible (code 2) ou sans forme canonique (E-2), partie réservée présente et ancre non nulle jamais « valides » ; verdict confronté à `attendu.json` ; validité au sens de §11.4 (aucun échec et aucun contrôle non exécuté sans raison admise) ; borne du verdict énoncée (§11.3) ; révision 0.4 : AT-1 à AT-7 sur la quatorzième partie `attestation-perimetre.json` (schéma de la partie et de l'attestation transcrits, relations d'AT-1, forme canonique de toute la partie, taille de 4 Mio, base64 canonique du document de politique d'au plus 2 097 152 octets ; `D_P = keccak256(P_P ‖ JCS(P))` ; signatures EIP-191 canoniques et adresses recouvrées ; seuil et jeu déclaré ; liaison à l'événement prouvé ; inscription : E-1 à E-8 et E-11 de l'événement, document de politique, `perimeter.attestation_digest`, rang et instant ; version de politique), statuts et raisons (`prerequis_en_echec`, `partie_absente`, `piece_hors_dossier`) confrontés à `perimeter_checks` de `attendu.json`, sans effet sur le verdict ; aucune AT- pour un index à douze ou treize parties ou une partie déclarée absente |
| jcs | `jcs/cas-limites.json` (`{ cas: [{ name, input, canonical \| null }] }`) | forme canonique d'un texte JSON (§4) ou refus |

Implémentation propre de chaque brique : analyseur JSON strict (révision
0.5 : marque d'ordre d'octets et UTF-8 mal formé ne sont pas un texte JSON ;
substitut écrit en octets, comme l'échappé, et clé en double sont des défauts
de forme canonique, E-2, rendus après la syntaxe ; profondeur d'au plus 128
objets et tableaux imbriqués, la racine comprise, pour un document du format
v0 ; texte littéral des nombres conservé), forme canonique JCS v0 (tri par unités de code UTF-16,
échappement minimal d'ECMAScript, entiers seuls ; `encoding/json` n'est pas
utilisé pour la sortie canonique car `json.Marshal` échappe `<`, `>`, `&`,
U+2028 et U+2029), SHA-256 à préfixes de domaine, Ed25519 avec refus de `S`
non réduit, des clés non canoniques et des points de petit ordre (décodage
RFC 8032 §5.1.3 et `[8]A` en `math/big`), arbre RFC 6962 et algorithme de
§9.3, Keccak-256 (confronté à `crypto/sha3` dans les tests) pour les seules
valeurs que l'EVM impose en keccak256.

## Disposition des vecteurs reconnue

Le vérificateur reconnaît la disposition des vecteurs publiés, fixée par
CT-1 §13 et `spec/vecteurs/ct-1/INDEX.md` :

```
cles/cles-test.json, cles/cles.json
jcs/cas-limites.json
journal-valide/{evenements.json, attendu.json, cles.json, pieces.json}
journal-{supprime,modifie,insere,insere-sans-cle,reordonne}/{evenements.json, attendu.json}
merkle/arbres.json
merkle/coherence.json
manifestes/{periode-N.json, periode-N.sig, discontinu.json, discontinu.sig, attendu.json}
points-de-controle/{periode-N.json, invalides/*.json, attendu.json}
dossiers/<nom>/{dossier.json, …, points-de-controle.json, attestation-perimetre.json, attendu.json}
```

et, en repli, une disposition documentée ici au cas où l'intégration la
préférerait : `cles.json` à la racine (mêmes champs), `jcs/*.json` (cas
`{ name, input, canonical | null }`), `evenements/**/*.json` et
`chaines/*.json` (événement nu, tableau, ou `{ expected, events }`),
`arbres/*.json` (`{ leaves, root, paths }`), `dossiers/attendus.json`
(`{ "<nom>": "valide" | "E-7" | [...] }`) ou nom de répertoire
`valide-*` / `invalide-<CTRL>-*`.

Verdict attendu : `{ "valide": bool, "controles_en_echec": [...] }`,
`{ "valide": bool, "diagnostics": [{ "controle": ... }] }` ou
`{ "expected": "valide" | "E-7" | [...] }`. Sans déclaration, un vecteur est
attendu valide.

Sémantique de la confrontation d'un verdict : attendu « valide » ⇔ aucun
contrôle en échec et aucun contrôle non exécuté sans raison admise (§11.4) ;
attendu une liste de contrôles ⇔ chacun est en échec. Hors mode strict, les
échecs supplémentaires sont rapportés en note mais admis ; `-strict` exige
l'égalité des ensembles, ce que les vecteurs publiés satisfont (leurs
`attendu.json` listent les cascades).

## Tests du module (`go test`)

- RFC 8785 : exemples de §3.2.2 (chaînes, littéraux) et jeu de tri de
  §3.2.3 (l'émoji précède U+FB33 par unités UTF-16), nombres non entiers
  refusés ; les quatorze cas limites de CT-1 §4.
- RFC 8032 : vecteur TEST 1 (clé, signature, vérification), refus d'un `S`
  non réduit, des huit points de petit ordre et des encodages non canoniques ;
  clés et nonces de test de §13.
- RFC 6962 : feuilles, nœuds, racines des arbres de 1 à 8 feuilles du jeu
  historique de Certificate Transparency, chemins d'audit et refus (indice hors
  arbre, chemin tronqué, trop long, permuté) ; exemple complet de §9.4.
- RFC 9162 §2.1.4 (CT-1 §10.7) : preuves de cohérence `(1, 8)`, `(6, 8)`,
  `(2, 5)`, `(6, 7)` du même jeu, nœud pour nœud, toutes les paires `(m, n)`
  jusqu'à 8, la préposition de la racine quand `m` est une puissance de deux,
  et le refus des sondes (racines échangées, chemin tronqué, nœud en trop,
  chemin permuté, chemin vide, `m = 0`, `m > n`, `m = n` avec chemin).
- Point de contrôle `K2` de §10.6 : forme canonique `C_K`, `checkpointHash`,
  signature sous `rec-test-01` (et refus sous `rec-test-02`), règle « racine
  nulle si et seulement si `tree_size = 0` », clé en vigueur avant et après la
  rotation de seq 5 ; les dossiers publiés à treize parties (K-1 à K-6
  passées, K-7 à K-9 non exécutées pour une raison admise, un échec exact par
  dossier `invalide-k*`) et à douze parties (K-1 à K-9 non exécutées pour une
  raison admise, verdict inchangé).
- Série de l'exemple de référence (§10.8) : les six points `K1` à `K6`
  reconstruits depuis la table, racines et `last_hash` recalculés depuis le
  journal de l'annexe A, `checkpointHash` et signature de chacun, règles de
  série de §10.5 sur les deux périodes (dont la période vide) et leurs sondes
  (point de clôture retiré, points permutés, clé substituée, `last_hash`
  faux), forme canonique de `K5`, racines des préfixes `MTH(D[0..m-1])` et
  preuves `PROOF(m, D[5])` pour `m` de 1 à 4, refus sans la préposition de la
  racine pour `m = 4`.
- Keccak-f[1600] confronté à `crypto/sha3` (SHA3-256), `keccak256("")`,
  `org_id`, `journal_id` et `anchorFingerprint` de la spécification.
- Exemple de référence de CT-1 (`testdata/reference`, annexe A) : hash et
  signature des cinq événements, forme canonique de seq 4, `JCS(A)` et `D_A`,
  contresignature de rotation, `periodHash` et signatures des deux
  manifestes, continuité, racine, dossier de seq 4 valide, et les sept
  empreintes SHA-256 que `dossier.json` de §11.1 déclare (les sept fichiers,
  `approbations.json` compris depuis que §11.2 l'imprime, sont reproduits
  octet pour octet) ; les altérations de §11.5 avec les contrôles qu'elles
  doivent faire échouer, les parties réduites au littéral `null` (un seul
  contrôle en échec, celui qui porte la partie), l'échange avec le modèle
  sans réponse (E-1, E-3), la validité annoncée d'une clé de rotation (E-10),
  l'unicité des clés de `cles.json` (E-8), la troncature d'une période (P-3)
  et l'ordre décision puis relais (A-2).
- Révision 0.4 (`attestation_test.go`) : l'exemple de
  `attestation-perimetre.json` imprimé en §11.2, réécrit comme les autres
  parties (indentation de deux espaces, saut de ligne final), fait 5 443
  octets et a le SHA-256 que §11.1 déclare ; `D_P` de §13 et de l'annexe B,
  `P_P` ; joint au dossier de référence à quatorze parties, AT-1 à AT-5
  réussissent, AT-6 et AT-7 ne sont pas exécutées (`partie_absente`) et le
  dossier reste valide ; altérations (signature attribuée à un autre compte,
  condensé déclaré faux, seuil de trois, validité terminée, date
  inexistante, membre inconnu) : l'AT- visée échoue, les suivantes ne sont
  pas exécutées selon les prérequis de §11.4, le dossier reste valide ;
  quatorzième partie déclarée absente : aucune AT-.
- Révision 0.5 de CT-1 (`revision05_test.go`), un cas en réussite et un
  cas en échec par règle : lecture du JSON (marque d'ordre d'octets et UTF-8
  mal formé : pas un texte JSON ; substitut écrit en octets, apparié ou non :
  E-2 ; clé en double suivie d'une erreur de syntaxe : erreur de syntaxe ;
  profondeur 128 admise, 129 refusée ; `[[1]]` de profondeur 2) ; chaîne non
  vide (blancs `White_Space` et U+FEFF) ; parties du dossier (partie
  manquante : D-2 seule ; lien symbolique : D-2 ; répertoire du nom d'une
  partie absente : admis ; au-delà de 16 Mio : contrôle porteur, D-2 non
  comparée ; 16 Mio exactement : lue ; marque d'ordre d'octets : E-1 seule,
  les contrôles qui lisent l'événement non exécutés, M-2, P-3 et P-4
  exécutés ; profondeur 129 : E-1 ; substitut en octets : E-2 ; nombre non
  entier : E-2 seule ; partie réservée présente : dossier jamais valide) ;
  index (absent, pas du JSON ou trop profond : code 2 ; nombre non entier ou
  clé en double : E-2 ; au-delà de 1 Mio ou tableau : D-1 ; contraire à son
  schéma : D-1 et rien d'autre ; autre journal : D-1) ; relations (`seq` en
  chaîne : D-1, E-1, E-7, E-8, C-1, C-2, M-1, M-3, P-2, A-2 exactement ;
  `ts` inexistant : C-1, P-2, E-11, A-2 en échec ; `chemin.json` contraire
  à son schéma : M-1 et M-3 exécutées ; `approver_set` à membre en trop : A-3
  exécutée sur ses valeurs ; `cles.json` d'un autre journal ou à membre
  `seed` : E-10, E-11, P-5 non exécutées ; `voisins.json` inexploitable :
  A-4 sans raison admise ; voisin qui n'est pas un objet) ; A-1 (raison
  exacte, raison de U+FEFF ou de U+0085 : D-2, raison vide : D-1, `approval`
  non nul et partie déclarée absente : A-4 exécutée) ; E-3 (décision à
  effets, appel retenu à effets, `policy_version` de 0, 128 et 129
  caractères), E-4 (chaîne vide, chaîne de blancs), E-5 et E-9 (signature
  en trop, `v` hors de {27, 28}, `signatures` nul, signature attribuée à un
  autre approbateur, approbateur sans signature : E-5 seule) ; K-1 à K-9 (ancre au registre non nulle : K-8
  recalcule `fingerprint` et compare `doc_type`, puis non exécutée sans
  raison admise ; P-1 en échec : K-1 non exécutée ; `voisins.json`
  inexploitable : K-6 sans raison admise ; clé en double : E-2 ; au-delà de
  1 Mio : K-1 ; M-3 en échec : K-4 non exécutée) ; attestation de périmètre
  à nombre non entier hors de `signed.attestation` : AT-1 ; journal
  (réordonnancement sans trou rapporté, deux suppressions, `cles.json` d'une
  autre organisation : E-8 pour chaque événement, `cles.json` défectueux :
  un symptôme `cles/E-8/null` en tête, origine contrôlée sur chaque
  événement, profondeur d'un événement de journal) ; série de points
  (période 1 sans les événements 5 à 9 : `root` et `last_hash` non évaluées,
  `piece_hors_dossier`, aucune règle violée ; événement 8 altéré : `root` et
  `last_hash` violées ; événement 8 sans forme canonique :
  `prerequis_en_echec` ; période vide sans l'événement 12 : `last_hash` non
  évaluée ; clé en vigueur d'un point de `last_seq = 0` par `cles.json`, et
  violée sous une autre clé).
- Compléments du 2026-11-03 (`revision05_test.go`) : `evenement.json` nul
  avec manifeste de 7 200 s et `key_id` en double : E-1, E-8, P-1, P-5
  exactement ; `approbations.json` déclarée présente sans fichier, `approval`
  nul : D-2 et A-1 ; membre `previous` absent : C-1, C-2, C-3, P-3 ;
  `previous` = "x" d'une décision : E-1, C-1, C-2, C-3, P-3, E-2 à E-11 non
  exécutées, A-4 admise ; `approval` = 5 : E-1, E-3, E-5, E-7, E-8, E-9,
  C-2, M-1, A-1 à A-4 ; `execution.tool` = 5 : E-1, E-3, E-7, E-8, C-2, M-1 ;
  raison et détail d'une partie réservée ; attestation de 64 Mio + 1 : code
  2, `taille_depassee` ; attendu `exit_code`/`error_kind` (et non `code`,
  `code_retour`), `exit_code_exiger_4` hors périmètre ; série : seq 5
  manquant et seq 6 non canonique (`root` `prerequis_en_echec` puis
  `piece_hors_dossier`, `last_hash` `piece_hors_dossier`), sans `cles.json`
  ni événements, `cles.json` défectueux, noms fermés (`tree_size > count` :
  `last_seq` ; clé inconnue : `signature` et `cle_en_vigueur` ; point hors
  schéma : `period_start`) ; journal : `ts` inexistant, E-1 et deux
  symptômes `horodatage` ; règle d'origine non évaluée pour un `seq` qui
  n'est pas un entier, dans un journal et dans un dossier
  (`TestOrigineSeqNonEntier`).
- Les vecteurs publiés dans le répertoire parent, s'ils sont présents : tout
  doit concorder.

## Limites

- **Contrôle 7 (E-9)** : vérifiée en entier depuis la révision 0.5 de ce
  vérificateur (forme canonique de chaque signature, CT-6 EX-5.19, puis
  adresse recouvrée sur `M = keccak256("\x19Ethereum Signed Message:\n32" ‖
  D_A)` par `secp256k1.go` et comparée à `approvers[i]`). L'adresse des
  comptes Hardhat n'est pas dérivée du mnémonique (BIP-32 hors périmètre) ;
  la copie de ce code dans `ct-2` signe ses cas synthétiques avec les clés
  privées de test publiques de ces comptes.
- **Contrôles 4, 5 et 8** (CT-5, CT-4) : non exécutables ; le verdict d'un
  dossier est borné comme §11.3 l'impose et la borne est énoncée. Révision
  0.5 (§11.4) : une partie réservée déclarée présente est rapportée non
  vérifiée (`T-*`, `O-*` ou `R-*` non exécutée, raison
  `prerequis_en_echec`, détail « vérification de CT-6 non exécutée par ce
  vérificateur »), quelle que soit sa taille, et le dossier n'est jamais
  valide pour ce vérificateur ; D-2 compare son SHA-256 dans les limites de
  CT-6 EX-4.13.
- **K-7 à K-9** (révision 0.3) : les ancres d'un point de contrôle (jeton
  RFC 3161, ancre au registre, preuve OpenTimestamps) réemploient les
  vérifications de CT-6 ; ce vérificateur les déclare non exécutées, raison
  admise, quand l'ancre vaut `null` (tous les vecteurs publiés de `ct-1`).
  Révision 0.5 (§11.4) : une ancre non nulle laisse K-7 et K-9 non
  exécutées, sans raison admise ; K-8 recalcule `fingerprint =
  keccak256(org_id ‖ journal_id ‖ checkpointHash)` et compare `doc_type` à
  `keccak256("noortrace/point-de-controle/v0")` (CT-4 §6.4), un écart la met
  en échec, et n'est sinon pas exécutée, sans raison admise ; le dossier
  n'est donc jamais valide pour ce vérificateur (avant la révision 0.5 : hors
  périmètre, dossier valide).
- Les schémas JSON sont transcrits à la main en Go (E-1, D-1, K-1 avec ses
  `$defs` `points_de_controle`, `preuve_coherence`, `ancre_rfc3161_point`,
  `ancre_registre_point`, `ancre_ots_point` et `base64` ; AT-1 avec
  `attestation_perimetre`, `base64_document` et, du schéma
  `attestation-perimetre-v0`, l'attestation, `attestation_signee`,
  `jeu_approbateurs` et `reference_secret`), ce n'est pas un validateur JSON
  Schema générique ; une divergence entre le schéma et sa transcription
  serait une faute de ce vérificateur.
- **Révision 0.4, notions de CT-6 et de CT-7** : `perimeter_target` (la
  vérification qu'un dossier exerce), `perimeter_retained` (attestation
  retenue) et `warnings` (avertissements AV-AT-) des `attendu.json` sont
  nommés par CT-1 §11.5, mais leur valeur dépend de CT-6 (rétention
  d'EX-6.19, avertissements d'EX-6.15) ; ils sont rapportés hors périmètre.
  Les statuts et raisons de AT-1 à AT-7 sont, eux, confrontés : AT-1 refuse
  une validité de plus de 366 jours, AT-6 n'est pas exécutée
  (`ancre_absente`) quand l'inscription est signée par une autre clé que
  celle de l'événement prouvé, et AT-7 ne l'est pas non plus dans ce cas.
- Les pièces ne sont vérifiées que si elles sont fournies à part
  (`pieces.json`) ou en ligne (`value`).
- Module `go 1.24` ; essais faits avec go1.27.3 ; aucune dépendance.

## Règles de la révision 0.5 (renvois)

Ce vérificateur n'avait pas de section « Lectures » : ses choix étaient
dans « Limites ». La révision 0.5 de CT-1 tranche dans le texte ce qu'il
appliquait ou n'appliquait pas ; chaque règle, avec l'endroit du code :

| Règle | CT-1 0.5 (et CT-6 0.4) | Code |
|---|---|---|
| UTF-8 mal formé et marque d'ordre d'octets : pas un texte JSON ; substitut écrit en octets : E-2 | §3, §4 règle 3 ; CT-6 EX-4.16 | `json.go` (`ParseJSONProfondeur`, `codageAdmis`) |
| Profondeur d'au plus 128, comptée sur les conteneurs, la racine comprise ; événement de journal : E-1 | §4 règle 7 ; CT-6 EX-4.13, EX-4.16 | `json.go` (`ParseJSONV0`, `Profondeur`), `evenement.go` (`ControlerJournal`) |
| Chaîne non vide (blancs `White_Space` et U+FEFF) : raison d'absence (D-2), `policy.redaction` (E-4) | §3 ; §11.4 D-2, E-4 | `evenement.go` (`ChaineNonVide`), `dossier.go` (`controlerEmpreintes`) |
| `org_id`, `journal_id` non nuls : E-1, P-1 | §3 ; §11.4 E-1, P-1 | `evenement.go`, `manifeste.go` (`ValiderSchemaManifeste`) |
| Règle exacte de E-3 | §5.3 ; CT-6 EX-5.17 | `evenement.go` (`controlerSorte`) |
| E-5 et E-9 : tableaux, signature sans approbateur, forme canonique, adresse recouvrée | §6.3, §11.4 E-9 ; CT-6 EX-5.19 | `evenement.go` (`controlerApprobationForme`) |
| Voisin qui n'est pas un objet ou membre absent (règle unique) : C-1, E-1 s'il est présent (E-2 à E-11 non exécutées), C-2, C-3, P-3 ; ni candidat à A-4 ni à K-6 ; règle d'origine de C-2 sur chaque événement, voisins compris, évaluée seulement pour un `seq` entier | §11.4 ; CT-6 EX-5.13 | `dossier.go` (`controlerVoisins`, `controlerManifeste`), `evenement.go` (`ControlerEvenement`) |
| `approval` ni nul ni objet : A-1 à A-4 en échec ; `execution.tool` qui n'est pas une chaîne : E-3 | §11.4 « Autres termes mal typés » | `dossier.go` (`controlerApprobations`), `evenement.go` (`controlerSorte`) |
| « Sauf s'il échoue sur ce qu'il lit des autres parties » : la part de la règle qui ne lit pas la partie inexploitable est évaluée | §11.4 ; CT-6 EX-5.15 | `dossier.go` |
| K-6 jugée sur l'événement prouvé quand `last_seq` est le sien, quel que soit `voisins.json` | §10.5, §11.4 K-6 ; CT-6 EX-5.9 | `dossier.go` (`controlerPointsDeControle`) |
| Série : liste fermée des noms de règle, ordre des listes, `prerequis_en_echec` avant `piece_hors_dossier`, règles qui lisent `cles.json` sans lui | §10.5 | `point.go` (`ordreRegles`, `ControlerSerie`), `vecteurs.go` (`evenementsPartiels`) |
| Document de politique de l'inscription : profondeur d'au plus 128, nombres libres | §4 règle 7 | `attestation.go` |
| Attendu d'une entrée inutilisable : `exit_code` = 2 et `error_kind` ; `exit_code_exiger_4` (option de CT-6) rapporté hors périmètre | §11.5 ; CT-6 EX-A.3 | `vecteurs.go` (`attenduCode2`, `comparerExiger4`), `dossier.go` (`TypeErreur`) |
| Vérification d'un journal : trois temps, symptômes typés, `seq` sur tout le fichier, `cles.json` comparé à chaque événement | §7.2 | `evenement.go` (`ControlerJournal`), `vecteurs.go` (`comparerSymptomes`) |
| Clé en vigueur quand l'événement `last_seq` manque | §10.5 règle 5 | `point.go` (`CleEnVigueurPoint`) |
| `root` et `last_hash` point par point, `rules_not_evaluated`, aucune valeur par défaut | §10.5 | `point.go` (`ControlerSerie`) |
| Contrôle porteur, cinq cas de partie inexploitable, limites de taille | §11.4 ; CT-6 EX-4.11, EX-4.13, EX-4.17 | `dossier.go` (`lireBorne`, `analyserPartie`, `lirePartie`) |
| `dossier.json` : code 2, E-2, D-1, rien d'autre | §11.4 ; CT-6 EX-4.11 point 3, EX-4.12 | `dossier.go` (`VerifierDossier`, `controlerIndex`) |
| Partie contraire à son schéma exploitable ; relations à terme absent, mal typé ou incalculable en échec | §11.4 ; CT-6 EX-5.13 | `dossier.go`, `evenement.go` (`ControlerPaire`, accès typés) |
| `evenement.json` inexploitable : D-1, E-1 à E-11, C-, M-1, M-3, P-1, P-2, P-5, A-, K-, AT-5, AT-6 non exécutées sauf échec | §11.4 ; CT-6 EX-5.14, EX-5.15 | `dossier.go` |
| `cles.json` exploitable si et seulement si la première partie de E-8 réussit (sinon E-10 pour ses comparaisons, E-11, P-5, K-3, AT-6 non exécutées) ; schéma strict de `#/$defs/cles` | §11.4 | `cles.go` (`ChargerClesDossier`), `dossier.go` (`controlerCles`) |
| A-1 : raison exacte « aucune approbation liée » ; A-4 exécutée quand `approbations.json` est absent ou inexploitable | §11.1, §11.4 A-1 ; CT-6 EX-5.16 | `dossier.go` (`controlerApprobations`) |
| A-4 : demande reconnue au seul hash ; `voisins.json` inexploitable : sans raison admise | §11.4 A-4 ; CT-6 EX-5.18 | `dossier.go` (`controlerDemande`) |
| K-1 non exécutée quand P-1 n'a pas réussi ou que l'événement est inexploitable ; K-4 quand M-3 n'a pas réussi ; K-6 avec `voisins.json` inexploitable : sans raison admise | §11.4 (révisions 0.3 et 0.5) ; CT-6 EX-5.9 | `dossier.go` (`controlerPointsDeControle`) |
| Partie réservée présente, ancre non nulle : jamais « valide » ; K-8 recalcule `fingerprint` et `doc_type` | §11.4 | `dossier.go` (`controlerEmpreintes`, `controlerAncresPoint`) |
| `attestation-perimetre.json` : tout défaut des cas (b) à (e), forme canonique comprise, porté par AT-1 ; AT-5 et AT-6 exigent E-1 et E-2 réussies | §11.4 ; CT-6 EX-4.15 | `attestation.go` (`controlerAttestation`) |

Les neuf lectures que la première passe de la révision 0.5 laissait
ouvertes (ordre des `seq` d'un journal, `rupture` sur un hash incalculable,
voisin non objet et A-4, raison d'une série, `cle_en_vigueur` sans
`cles.json`, noms de règle, partie réservée trop grande, attestation au-delà
de 64 Mio, forme de l'attendu du code 2) sont tranchées dans le texte
complété le 2026-11-03 (CT-1 §7.2, §10.5, §11.4, §11.5 ; CT-6 EX-4.15,
EX-5.9, EX-5.13, EX-A.3) et appliquées comme le texte le dit. Aucune lecture
ne reste ouverte.

## Écarts relevés entre la spécification et les vecteurs publiés

Aucune discordance de calcul, en mode strict comme en mode par défaut. Les
écarts de convention relevés par la première confrontation (étiquettes de
nonce des vecteurs distinctes de celles de l'exemple de référence ; famille
`jcs/` absente ; cascades C-2 des journaux altérés non listées) ont été résorbés
dans la spécification (§13 distingue les constantes de l'exemple de celles des
vecteurs ; §7.2 fixe que tous les symptômes sont rapportés) et dans les
vecteurs (`jcs/cas-limites.json`, `controles_en_echec` des journaux). Jusqu'à
la révision 0.4, les seules valeurs non confrontées étaient celles du
contrôle E-9 ; depuis la révision 0.5, E-9 est vérifiée (voir « Limites »).

Révision 0.4 (2026-10-27) : les quatorze dossiers de l'attestation de
périmètre concordent, statut et raison de chaque AT- compris ; total de 2 955
valeurs confrontées, 2 911 concordantes, **0 discordante**, 44 hors
périmètre (les 2 valeurs E-9, et `perimeter_target`, `perimeter_retained`
et `warnings` des 14 dossiers, notions de CT-6 et de CT-7).

Révision 0.5 (2026-11-03, complétée ; seconde vague de vecteurs) : les
quatre-vingt-dix-sept dossiers publiés, les dix journaux (dont
`journal-cles-autre-organisation`, `journal-seq-chaine`,
`journal-ts-inexistant` et `journal-non-canonique`), les séries de points
(dix séries invalides, quatre entrées `evenements_partiels`) et les
manifestes concordent en mode strict ; les symptômes des journaux (type,
contrôle, `seq`, dans l'ordre) sont confrontés à leurs `diagnostics`. La
règle d'origine de C-2 n'est évaluée que pour un `seq` entier (point 36 :
CT-1 §7.2 temps 1, §11.4 « Autres termes mal typés », CT-6 EX-5.13 ; sinon
E-1 seule porte le défaut, dans un journal comme dans un dossier). Total de
3 064 valeurs confrontées, 3 001 concordantes, **0 discordante**, 63 hors
périmètre (`perimeter_target`, `perimeter_retained` et `warnings` des 21
dossiers qui déclarent la quatorzième partie). E-9 étant vérifiée en entier,
`invalide-approbateur-substitue` et `invalide-signature-s-haut` concordent.
