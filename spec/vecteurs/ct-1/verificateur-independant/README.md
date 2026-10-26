# Vérificateur indépendant CT-1 (Go, salle blanche)

Un second vérificateur des formats de CT-1, écrit en Go depuis la seule
spécification [`spec/CT-1-evenements-et-formats.md`](../../../CT-1-evenements-et-formats.md)
et ses trois schémas, sans lire ni reprendre le code JavaScript de
`scripts/`. Il recalcule tout ce que la spécification définit et le confronte
à chaque valeur attendue trouvée dans les vecteurs de `spec/vecteurs/ct-1`.
Deux implémentations écrites séparément qui tombent sur les mêmes octets
rendent les vecteurs probants ; une discordance désigne une ambiguïté de la
spécification ou une faute de l'une des deux.

Bibliothèque standard uniquement (`crypto/ed25519`, `crypto/sha256`,
`crypto/sha3` pour les tests, `encoding/hex`, `math/big`, `encoding/json` pour
la seule sortie du rapport). Module `noortrace-ct1`, `go 1.24`.

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
| journaux | `journal-*/evenements.json`, `attendu.json`, `cles.json`, `pieces.json` | contrôles E-1 à E-8, E-10, E-11 de chaque événement et C-1 à C-3 de chaque couple, verdict de chaîne ; pour le journal valide : `hash`, `prev_hash`, longueur canonique, signature Ed25519, contresignature de rotation, `JCS(A)` et `D_A`, approbateurs, bornes de séquence ; SHA-256 et longueur des pièces fournies à part (E-6) |
| arbres | `merkle/arbres.json` | feuilles SHA-256(0x00 ‖ D[i]), racine RFC 6962 (période vide : 32 octets nuls, distingués de SHA-256("")), chemin d'audit de chaque preuve, `leaf_hash`, `tree_size`, et exécution de l'algorithme de vérification de §9.3 |
| cohérence | `merkle/coherence.json` (révision 0.3) | preuve de cohérence RFC 9162 §2.1.4 régénérée nœud pour nœud (`PROOF(m, D[0..n-1])`, §10.7), racines des deux arbres, et exécution de l'algorithme de vérification de §10.7 : chaque cas valide accepté, chaque sonde (`m = 0`, `m > n`, chemin tronqué, nœud en trop, racines échangées, chemin vide, `m = n` avec chemin) refusée |
| manifestes | `manifestes/*.json`, `*.sig`, `attendu.json` | P-1, P-4, P-5 ; forme canonique `C_M` ; `periodHash` ; signature ; racine recalculée depuis le journal valide (fenêtre `[period_start, period_end)` et liste `seq`) ; `count` ; `anchorFingerprint` = keccak256(org_id ‖ journal_id ‖ periodHash) ; correspondance `PeriodMeta` ; continuité P-5 entre périodes déclarées et discontinuité attendue |
| points de contrôle | `points-de-controle/periode-N.json`, `invalides/*.json`, `attendu.json` (révision 0.3) | règles de série de §10.5 (chaînage par `prev_checkpoint_hash`, `tree_size` et `checkpoint_ts` non décroissants, `checkpoint_ts ≥ period_start`, racine et `last_hash` recalculés depuis le journal, période vide comprise, dernier point égal au manifeste, clé en vigueur d'après le journal, signature et validité annoncée) ; pour chaque point : forme canonique `C_K`, `checkpointHash = SHA-256(P_K ‖ C_K)`, `prev_checkpoint_hash`, signature Ed25519 sur `P_SK ‖ C_K`, preuve de cohérence `PROOF(tree_size, D[0..count-1])` vers la racine du manifeste et sa vérification ; pour chaque série invalide, les règles violées (`rules_failed`) |
| dossiers | `dossiers/*/` | les contrôles D-1, D-2, E-1 à E-8, E-10, E-11, C-1 à C-3, M-1 à M-3, P-1 à P-5, A-1 à A-4 et, révision 0.3, K-1 à K-6 sur la treizième partie `points-de-controle.json` (index à douze ou treize parties ; index à douze parties ou partie déclarée absente : K-1 à K-9 non exécutées pour une raison admise ; partie présente mais inexploitable ou K-1 en échec : K-2 à K-9 non exécutées sans raison admise ; K-7 à K-9 non exécutées, raison admise, pour une ancre `null`, hors périmètre sinon) ; verdict confronté à `attendu.json` ; validité au sens de §11.4 (aucun échec et aucun contrôle non exécuté sans raison admise) ; une partie présente qui n'est pas un objet JSON met en échec le contrôle qui la porte ; borne du verdict énoncée (§11.3) |
| jcs | `jcs/cas-limites.json` (`{ cas: [{ name, input, canonical \| null }] }`) | forme canonique d'un texte JSON (§4) ou refus |

Implémentation propre de chaque brique : analyseur JSON strict (clés en
double, substituts isolés, UTF-8 mal formé et BOM refusés ; texte littéral des
nombres conservé), forme canonique JCS v0 (tri par unités de code UTF-16,
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
dossiers/<nom>/{dossier.json, …, points-de-controle.json, attendu.json}
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
- Les vecteurs publiés dans le répertoire parent, s'ils sont présents : tout
  doit concorder.

## Limites

- **Contrôle 7 (E-9), signatures EIP-191 des approbateurs** : hors
  périmètre. Le recouvrement d'adresse secp256k1 n'est pas dans la
  bibliothèque standard ; la structure est contrôlée (E-1, E-5, A-3 : formes,
  longueurs égales, approbateurs distincts et membres du jeu, seuil atteint),
  l'objet signé `A` et son condensé `D_A` sont recalculés, mais aucune
  signature d'approbateur n'est vérifiée. Un vecteur dont le seul contrôle
  attendu en échec est E-9 est rapporté « hors périmètre », ni concordant ni
  discordant. L'adresse des comptes Hardhat n'est pas dérivée non plus.
- **Contrôles 4, 5 et 8** (CT-5, CT-4) : non exécutables ; le verdict d'un
  dossier est borné comme §11.3 l'impose et la borne est énoncée.
- **K-7 à K-9** (révision 0.3) : les ancres d'un point de contrôle (jeton
  RFC 3161, ancre au registre, preuve OpenTimestamps) réemploient les
  vérifications de CT-6 ; ce vérificateur les déclare non exécutées, raison
  admise, quand l'ancre vaut `null` (tous les vecteurs publiés de `ct-1`) et
  hors périmètre quand une ancre est fournie (vecteurs de CT-6 révision 0.2).
- Les schémas JSON sont transcrits à la main en Go (E-1, D-1, K-1 avec ses
  `$defs` `points_de_controle`, `preuve_coherence`, `ancre_rfc3161_point`,
  `ancre_registre_point`, `ancre_ots_point` et `base64`), ce n'est pas un
  validateur JSON Schema générique ; une divergence entre le schéma et sa
  transcription serait une faute de ce vérificateur.
- Les pièces ne sont vérifiées que si elles sont fournies à part
  (`pieces.json`) ou en ligne (`value`).
- Go 1.24 est utilisé (c'est la version installée) ; aucune dépendance.

## Écarts relevés entre la spécification et les vecteurs publiés

Aucune discordance de calcul, en mode strict comme en mode par défaut. Les
écarts de convention relevés par la première confrontation (étiquettes de
nonce des vecteurs distinctes de celles de l'exemple de référence ; famille
`jcs/` absente ; cascades C-2 des journaux altérés non listées) ont été résorbés
dans la spécification (§13 distingue les constantes de l'exemple de celles des
vecteurs ; §7.2 fixe que tous les symptômes sont rapportés) et dans les
vecteurs (`jcs/cas-limites.json`, `controles_en_echec` des journaux). Les seules
valeurs non confrontées sont celles du contrôle E-9, hors périmètre de ce
vérificateur (voir « Limites »), vérifiées par l'implémentation de référence.
