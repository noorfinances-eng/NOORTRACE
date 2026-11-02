# noortrace-verifier

Vérificateur hors ligne d'un dossier de preuve NOORTRACE v0, écrit en Go :
le binaire de CT-6 §14 (nom fixé par CT-8). Il lit un dossier (CT-1 §11), les
entrées à part et le fichier d'ancres du réviseur (CT-6 §4), exécute les
huit contrôles de l'architecture (§5), et rend un verdict, un énoncé en
français et en anglais, une borne et un rapport lisible ou JSON
(`rapport-verification-v0`, §6 à §8). Il n'ouvre aucune connexion réseau, ne
lit aucun magasin de certificats du système, ni l'horloge (EX-3.2, EX-3.3).

C'est une implémentation indépendante de l'implémentation de référence
JavaScript, écrite depuis la spécification seule (voir « Salle blanche »),
pour être confrontée à elle et aux vérificateurs indépendants des vecteurs.

## État

| Partie | État |
|---|---|
| Module, lecture bornée, JSON strict, JCS v0, schémas embarqués (dix, EX-8.11) | fait |
| Index : D-1, D-2 | fait |
| Contrôles 1, 2, 3, 6, 7 : E-1 à E-11, C-1 à C-3, M-1 à M-3, P-1 à P-5, A-1 à A-4 | fait |
| Point de contrôle du journal : K-1 à K-6 ; K-7, K-8, K-9 (cadre : prérequis, ancre nulle, base64 canonique) | fait ; le cœur de K-7, K-8 et K-9 relève des contrôles 4, 8 et 5 |
| Attestation de périmètre : AT-1 à AT-7, FP, `facts.perimeter`, AV-AT- | fait |
| Fichier d'ancres (N-1), fichier d'en-têtes (N-2), clés d'enregistreur (N-3) | fait ; le profil DER strict de §9.3 et EX-9.21 est appliqué aux certificats et CRL du fichier d'ancres par `horodatage.ControleurAncres` |
| Statuts des contrôles, verdict, énoncé (F0 à F8, FK, FP), borne, faits, rapport lisible et JSON, codes de retour, ligne de commande | fait |
| Contrôle 4 (T-1 à T-11, cœur de K-7), paquet `horodatage` | fait ; voir `horodatage/LISEZMOI.md` |
| Contrôle 5 (O-1 à O-7, cœur de K-9), paquet `ots` | fait ; voir `ots/LISEZMOI.md` |
| Contrôle 8 (R-1 à R-11, N-4, K-8), paquet `registre` | fait ; voir `registre/LISEZMOI.md` |

Les huit contrôles sont construits : chaque dossier de `spec/vecteurs/ct-1`
et de `spec/vecteurs/ct-6` est rejoué contre son `attendu.json` sans
discordance. Le garde-fou de construction reste en place : un paquet dont
`Construit()` vaudrait faux ferait rendre au binaire le code 2
(`erreur_interne`) sur tout dossier qui porte ses parties, avec un
avertissement sur la sortie d'erreur, plutôt qu'un verdict qui ignorerait une
partie présente (EX-4.2).

`INTERFACES.md` est le contrat des trois paquets des contrôles 4, 5 et 8.

## Ligne de commande (CT-6 §8)

```text
noortrace-verifier <répertoire> [--ancres <fichier>] [--entetes-bitcoin <fichier>]
                   [--pieces <répertoire>] [--second-manifeste <fichier>]
                   [--exiger <contrôles>] [--langue fr|en] [--json] [--detail]
noortrace-verifier --version
noortrace-verifier --aide
```

| Option | Effet |
|---|---|
| `--ancres` | fichier d'ancres du réviseur (`ancres-confiance-v0`, §12) |
| `--entetes-bitcoin` | chaîne d'en-têtes Bitcoin (`entetes-bitcoin-v0`, §10.3) |
| `--pieces` | répertoire des pièces nommées par leur `sha256` (E-6, EX-4.6) |
| `--second-manifeste` | manifeste précédent ou suivant du même journal (P-5, EX-4.7) |
| `--exiger` | numéros de 1 à 8, distincts, séparés par `,`, ou `tous` : un contrôle exigé non réussi rend `incomplet` |
| `--langue` | `fr` (défaut) ou `en` : textes seulement, jamais statuts, raisons, verdict ni code |
| `--json` | rapport JSON sur la sortie standard (y compris pour le code 2) |
| `--detail` | rapport lisible : toutes les vérifications |
| `--version` | nom, version, version de Go, SHA-256 des dix schémas embarqués |
| `--aide`, `--help` | aide |

`--option=valeur` équivaut à `--option valeur`. Une option inconnue,
répétée, sans valeur, hors de son domaine, zéro ou plusieurs répertoires :
code 2, type `usage` (EX-8.2). `--version` et `--aide` ne se combinent qu'avec
`--langue`.

Codes de retour (§8.3) :

| Code | Verdict | Sens |
|---|---|---|
| 0 | `valide` | aucune vérification en échec ; toute non-exécution a une raison admise |
| 1 | `invalide` | au moins une vérification en échec ou non exécutée sans raison admise |
| 2 | aucun | entrée inutilisable : usage, dossier, schémas, fichier d'ancres ou entrée à part illisibles, taille dépassée, erreur interne |
| 3 | `incomplet` | comme 0, mais un contrôle exigé par `--exiger` n'a pas réussi |

Le rapport (lisible ou JSON) va sur la sortie standard ; les messages
d'erreur sur la sortie d'erreur, ainsi que l'avertissement de binaire
provisoire si l'un des contrôles 4, 5 ou 8 n'était pas construit.

## Architecture

```text
verificateur/
  cmd/noortrace-verifier/   ligne de commande (§8.1, §8.2), codes de retour, aide, --version
  moteur/                   ordre d'EX-5.2, isolement des étapes (EX-15.2), statuts (§6.3),
                            verdict (§6.4), faits (§6.7), énoncé et borne, rapport
  rapport/                  modèle du rapport rapport-verification-v0 (§8.6), rapport lisible
                            (§8.5), énoncé F0 à F8, FK, FP, I0 à I2 (§6.5), borne (§6.6)
  dossier/                  index et parties (CT-1 §11), D-, E-, C-, M-, P-, A-, K-1 à K-6, AT-
  ancres/                   fichier d'ancres (N-1), fichier d'en-têtes (N-2), N-3
  entree/                   lectures bornées d'EX-4.13, fichiers ordinaires seuls, sans
                            suivre de lien ; SHA-256 en flux (EX-4.15)
  jsonv/                    JSON strict et borné (doublons, substituts, profondeur 128)
  jcs/                      forme canonique JCS v0 (CT-1 §4)
  schema/                   dix schémas embarqués, validateur JSON Schema 2020-12
  cryptographie/            SHA-256, Keccak-256, Ed25519 strict, EIP-191, base64 canonique, Merkle
  commun/                   statuts, raisons, vérifications, textes bilingues, instants d'EX-6.11
  horodatage/               contrôle 4 (T-1 à T-11, K-7, profil DER strict du fichier d'ancres)
  ots/                      contrôle 5 (O-1 à O-7, K-9, chaîne d'en-têtes)
  registre/                 contrôle 8 (R-1 à R-11, N-4, K-8)
  scripts/construire.sh             construction reproductible (EX-14.6)
  scripts/verifier-sans-reseau.sh   preuves d'absence de réseau (EX-14.5)
  vendor/                   dépendances vendorisées (modules.txt versionné)
  LICENCES-TIERCES          avis de licences de Go, x/crypto et decred (EX-14.9, EX-14.10)
```

## Construction

### Go go1.27.3

CT-6 EX-14.3 exige go1.27.3 exactement. L'archive officielle se prend sur
<https://go.dev/dl/> et se vérifie par le SHA-256 que publie
`https://go.dev/dl/?mode=json&include=all` ; pour `linux/amd64` :

```bash
curl -sSLO https://go.dev/dl/go1.27.3.linux-amd64.tar.gz
echo "65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40  go1.27.3.linux-amd64.tar.gz" | sha256sum -c
tar -C "$HOME/outils" -xzf go1.27.3.linux-amd64.tar.gz   # répertoire hors du dépôt
export PATH="$HOME/outils/go/bin:$PATH"
go version   # go version go1.27.3 linux/amd64
```

`go.mod` porte `go 1.27` et `toolchain go1.27.3` (voir « Lectures », point
2) ; `scripts/construire.sh` refuse toute autre version que go1.27.3.

### Dépendances

Bibliothèque standard, `golang.org/x/crypto` v0.58.0 (paquets `cryptobyte`,
pour le lecteur DER du contrôle 4) et
`github.com/decred/dcrd/dcrec/secp256k1/v4` v4.4.1 (recouvrement des
signatures secp256k1), vendorisées. `go.sum` porte exactement les six lignes
d'EX-14.1 (dont `github.com/decred/dcrd/crypto/blake256` v1.1.0, dépendance
déclarée du module secp256k1 dont aucun paquet n'entre dans le binaire, donc
absente de `vendor/`). Keccak-256 est écrit dans `cryptographie/keccak.go`
(voir « Lectures », point 1). Sans cgo.

### Construction reproductible (EX-14.6, EX-14.8)

```bash
scripts/construire.sh -v 0.1.0 -o dist/noortrace-verifier   # linux/amd64 par défaut
scripts/construire.sh -v 0.1.0 -p linux/arm64 -o dist/noortrace-verifier-linux-arm64
```

Le script applique la recette d'EX-14.6 et rien d'autre
(`GOTOOLCHAIN=local GOENV=off GOFLAGS=-mod=vendor GOPROXY=off GOSUMDB=off
CGO_ENABLED=0 GOAMD64=v1`, `go build -trimpath -buildvcs=false
-ldflags='-buildid= -X main.version=<version>'`) et imprime le SHA-256 du
binaire. Deux constructions de la version 0.1.0 pour `linux/amd64`, depuis
deux copies des sources à deux chemins différents, avec deux caches de
construction et de modules différents et vides, ont donné les mêmes octets :
`80b790b0c581640ade9379710e2cff39ef9402ef5592355003a129bedd6dc79f`. Ce
SHA-256 vaut pour l'état des sources à la date de l'essai ; il change avec
le code.

### Absence de réseau (EX-14.5)

```bash
scripts/verifier-sans-reseau.sh [<binaire>]
```

Les quatre preuves : `go list -deps` sans `net/http`, `crypto/tls`,
`os/exec` ; `go tool nm` sans `net.(*Resolver)` ni `net.(*Dialer)` ; mêmes
codes et mêmes rapports JSON sous `unshare -n` qu'hors isolement (142
exécutions : les dossiers de CT-1 avec et sans ancres, deux dossiers de
CT-6) ; trace `strace -f -e trace=%network` vide pour chacune. Une preuve que
la machine ne permet pas n'est pas simulée : le script le dit et rend le
code 3. `net` et `net/url` figurent dans `go list -deps` parce que
`crypto/x509` les importe (§14.2).

Artefact connu de `strace` : quand le processus se termine (`exit_group`)
au moment où le fil de surveillance de l'exécutif Go (`sysmon`, boucle sur
`nanosleep`) entre dans un appel système, `strace` écrit `???( <detached
...>`, appel qu'il ne peut plus décoder ; une trace complète sans filtre de
ces exécutions ne contient aucun appel réseau. Le script relance alors
l'exécution (au plus cinq fois) et n'admet le cas que sur une trace vide ;
il imprime le nombre de relances.

## Tests

```bash
GOFLAGS=-mod=vendor go test ./...
GOFLAGS=-mod=vendor go test -run TestInventaireVecteurs -v ./moteur
```

- `moteur/vecteurs_test.go` rejoue chaque dossier de
  `spec/vecteurs/ct-1/dossiers` (sans ancres, puis avec `ancres-test.json`)
  et de `spec/vecteurs/ct-6/dossiers` contre son `attendu.json` : code,
  `failed_checks`, statuts, vérifications non exécutées, avertissements,
  énoncé dans les deux langues, borne, AT-, conformité du rapport au schéma.
  Un dossier dont l'attendu dépend d'un contrôle 4, 5 ou 8 encore provisoire
  est marqué « en attente des contrôles 4, 5, 8 » (`t.Skip`, avec la
  raison) ; ce qui ne relève pas de ces contrôles y est comparé quand même.
  `TestInventaireVecteurs` compte les dossiers rejoués et en attente.
  L'attente se lève d'elle-même quand `Construit()` des paquets concernés
  vaut vrai.
- `cmd/noortrace-verifier/main_test.go` : usage (EX-8.2), `--version`,
  `--aide`, rapports lisibles égaux aux exemples de CT-6 §8.5, rapports JSON
  conformes, déterministes et indépendants de `--langue`, entrées à part,
  refus du binaire provisoire.
- `moteur/refus_test.go` : index absent, illisible, d'une autre version, de
  plus de 1 Mio ; partie d'une autre version, trop profonde, trop grande,
  absente du répertoire ; attestation de plus de 4 Mio et de plus de 64 Mio ;
  panique isolée ; déterminisme.
- Tests unitaires de `jsonv`, `jcs` (cas limites de CT-1), `cryptographie`
  (Keccak-256, exemples de CT-1 §6.4, Merkle de CT-1), `schema` (copies
  conformes à `spec/schemas`, motifs), `entree` (tube nommé, liens
  symboliques), `ancres` (N-1, N-2, N-3, forme canonique, identifiants de
  validateurs, entrées qui ne sont pas des fichiers ordinaires).
- `dossier/correctifs_test.go`, `dossier/ordinaire_unix_test.go` :
  non-régression des correctifs de la relecture de l'étape 2 (E-3 sur une
  décision voisine, données dans `dossier/testdata/e3-voisin-decision` ;
  index, `points-de-controle.json` et `evenement.json` sans forme
  canonique ; A-2 et A-3 sans A-1 ; E-9 sur des signatures nulles ; parties
  en tube nommé ou en lien).
- Cibles de fuzzing (EX-15.3) : `jsonv.FuzzAnalyser`, `jcs.FuzzCanonique`,
  `ancres.FuzzAncres`, `ancres.FuzzEntetes` ; `go test -fuzz` sur l'une
  d'elles avec `-fuzztime`.

## Salle blanche

Le binaire est écrit depuis `spec/*.md`, `spec/schemas/*.json` et les
fichiers de données de `spec/vecteurs/ct-1` et `spec/vecteurs/ct-6`, et
depuis eux seuls. Ses auteurs n'ouvrent, ne lisent, ne cherchent ni
n'importent `scripts/**` (implémentation de référence), `paquets/**`
(bibliothèque noyau), les tests JavaScript de vérification, les répertoires
`spec/vecteurs/*/verificateur-independant/` ni `spec/vecteurs/*/confrontation/`.
Un passage ambigu ou contraire à un vecteur est tranché ici, dans
« Lectures », jamais en consultant une autre implémentation. Cette règle vaut
pour les trois paquets des contrôles 4, 5 et 8.

## Lectures

Passages de CT-6, CT-1 et CT-7 ambigus, ou contraires entre eux ou à la
réalité des outils, et lecture retenue.

1. **EX-14.1 et Keccak-256.** EX-14.1 cite `sha3.NewLegacyKeccak256` de
   `golang.org/x/crypto` et fixe la liste fermée des dépendances et les six
   lignes de `go.sum`. Or, dans x/crypto v0.58.0, `sha3` importe
   `golang.org/x/sys/cpu` : l'employer ajoute `golang.org/x/sys` v0.49.0 à
   `go.mod` et deux lignes à `go.sum`. Lecture : la liste fermée prévaut ;
   Keccak-256 est écrit dans `cryptographie/keccak.go` (permutation
   Keccak-f[1600]) et contrôlé par des vecteurs publics (chaîne vide,
   frontières de bloc de 135 et 136 octets, `docType`, `org_id`).
2. **EX-14.3 et `go.mod`.** « exactement go1.27.3, inscrite dans `go.mod`
   (lignes `go` et `toolchain`) ». go1.27.3 refuse une ligne `toolchain`
   égale à la ligne `go` (`go 1.27.3` et `toolchain go1.27.3` : « updates to
   go.mod needed », même en mode vendor). Lecture : `go 1.27` (version du
   langage) et `toolchain go1.27.3` (chaîne exacte) ; `construire.sh`
   refuse toute chaîne autre que go1.27.3.
3. **EX-15.2 et la consigne de construction.** La consigne dit qu'« une
   panique devient un échec du contrôle » ; EX-15.2 dit qu'elle est rendue
   comme erreur interne (code 2), « jamais comme un statut `reussi`,
   `echoue` ou `non_execute` ». Lecture : EX-15.2.
4. **Raison provisoire.** Les paquets à construire rendent `a_construire`,
   hors de la liste fermée d'EX-6.2. Le binaire rend alors le code 2
   (`erreur_interne`) : un rapport avec cette raison ne suivrait pas le
   schéma, et un verdict qui ignorerait la partie contredirait EX-4.2.
5. **K- en échec, partie requise absente.** EX-5.8 : une K- en échec rend
   son contrôle `echoue` (règle 1 d'EX-6.4). EX-9.18, EX-10.12, EX-11.20 :
   partie absente, contrôle `non_execute` (EX-4.3). Cas d'une K-7, K-8 ou
   K-9 en échec alors que `jeton-rfc3161.der`, `preuve.ots` ou les parties du
   registre sont absents : aucun vecteur. Lecture : `echoue` (la règle 1
   s'applique avant la règle 2, et le dossier est invalide dans les deux
   cas).
6. **« evenement.json exploitable ».** Pour AT-5 et AT-6, CT-1 §11.4
   (révision 0.4) précise « exploitable (E-1, E-2) » : un événement prouvé
   contraire à son schéma rend AT-5 `prerequis_en_echec` (vecteur
   `invalide-e1-attestation-non-executee`). Les vérifications E-, C-, M- et
   P-, elles, s'exécutent sur un événement qui est un objet JSON même quand
   E-1 échoue : `invalide-echange-sans-reponse` attend E-1 et E-3 en échec,
   `invalide-e1-attestation-non-executee` E-1, E-7, E-8, C-2 et M-1. Deux
   notions sont donc retenues : objet JSON (E-, C-, M-, P-, K-) et E-1, E-2
   réussies (AT-).
7. **A-2, « chaque événement de events passe E-1 à E-11 ».** Lu comme
   « est soumis à E-1 à E-11 », l'échec étant porté par la vérification E-
   concernée : `invalide-approbateur-substitue` et
   `invalide-signature-s-haut` n'attendent que E-9 en échec, alors que la
   décision jointe porte la même signature.
8. **A-1 et le schéma de `approbations.json`.** Les événements de `events`
   relèvent de E-1, comme ceux de `voisins.json` (CT-1 §11.4 le dit pour C-1
   seulement) : A-1 valide l'enveloppe. Vecteur `invalide-approbateur-double`
   (E-1 et A-3, pas A-1). A-2 et A-3 ne dépendent pas de A-1 (CT-1 §11.4 ne
   leur donne pas A-1 pour prérequis ; EX-5.5) : elles s'exécutent quand A-1
   échoue sur le `ticket` ou le `request_hash` (vecteur
   `invalide-ticket-approbations` : A-1 seule en échec, A-2 et A-3
   réussies). Elles ne sont pas exécutées (`prerequis_en_echec`) quand
   `approbations.json` est absent, inexploitable ou contraire à son
   enveloppe, défaut que A-1 porte : elles n'ont alors rien à lire.
9. **E-2, « un fichier sans forme canonique ».** Appliqué à toutes les
   parties JSON de CT-1, `points-de-controle.json` compris (CT-1 §11.4 ;
   CT-6 EX-4.14) ; ses conséquences portent sur le hachage des événements
   (E-7, E-8, C-2, M-1…) et sur `periodHash` (P-1, P-5). Un
   `points-de-controle.json` sans forme canonique (nom en double, nombre
   non entier) met E-2 en échec et laisse K-1 à K-9 non exécutées
   (`prerequis_en_echec`) : rien n'en est lu, puisque la lecture d'un nom
   en double serait arbitraire. `attestation-perimetre.json` reste hors de
   E-2 : son défaut relève d'AT-1, sans effet sur le verdict (EX-5.11).
   `dossier.json` : point 20 ; `evenement.json` : point 10 ; parties
   réservées du contrôle 8 : `registre/LISEZMOI.md`, « Lectures », point 5.
10. **D-1 quand `evenement.json` est inexploitable.** La comparaison
    d'`event.seq` et `event.hash` n'est pas possible ; D-1 est jugée sur le
    schéma (vecteur `invalide-partie-nulle` : E-1 seule en échec).
    `evenement.json` sans forme canonique (vecteur
    `invalide-nombre-non-entier`, `duration_ms` = 530.0) est inexploitable
    au sens de CT-1 §11.4 : E-2 en échec, et l'événement prouvé n'est pas
    lu ; E-1, E-3 à E-11 (sauf échec sur un voisin ou une décision jointe),
    C-1 à C-3, M-1, M-3, P-1, P-2, P-5 et A-1 à A-4 ne sont pas exécutées
    (`prerequis_en_echec`), comme pour un `evenement.json` qui n'est pas un
    objet JSON ; rien n'en est repris dans le rapport (désignation `null`).
    E-1 suit E-2 ici : la validation contre le schéma d'un objet à nom en
    double dépendrait de l'occurrence lue.
11. **Index contraire à son schéma.** CT-1 ne dit pas comment lire les
    parties d'un index non conforme. Lecture : D-1 `echoue`, toutes les
    autres vérifications de CT-1 `prerequis_en_echec`, contrôles 4, 5 et 8
    `non_execute` (`prerequis_en_echec`). Même traitement pour un index de
    plus de 1 Mio (EX-4.11).
12. **Partie au-delà de sa limite et D-2.** EX-4.13 interdit de lire
    au-delà de la limite ; D-2 demande le SHA-256 du fichier. Lecture : le
    SHA-256 n'est pas calculé, D-2 ne juge pas cette partie, et la
    vérification de la partie échoue (EX-4.11). Seule
    `attestation-perimetre.json` est hachée en flux jusqu'à 64 Mio
    (EX-4.15).
13. **E-3.** Règles appliquées, tirées des tables 5.1 et 5.3 de CT-1 et de
    §8 : nom `noortrace.` inconnu refusé ; appel d'outil : `policy.decision`
    autre que `sans_objet`, et `result`, `duration_ms`, `is_error` selon
    `status` ; échange avec le modèle : `sans_objet`, `executee`, réponse
    complète ; décision, rotation, politique : `sans_objet`, `intent` nul,
    `executee`, réponse nulle, `arguments.value` présente ; décision :
    `approval` non nul et `arguments.value` égale, clé pour clé, à l'objet
    signé `A = { decision, journal_id, org_id, request_hash, ticket }` de son
    `approval` et de son enveloppe (table 5.1 : « référence en ligne
    (`value`) à l'objet signé par les approbateurs » ; §6.3), pour tout
    événement que E-3 contrôle (événement prouvé, voisins, décisions de
    `approbations.json`), et pas seulement par A-2 pour les décisions
    jointes ; rotation et politique : `approval` nul ; rotation :
    `effects` égal à l'effet de la règle 4 de §8 ; politique :
    `arguments.value` = `{ policy_version, policy_sha256 }`. Rien n'est exigé
    de `approval` pour un échange ni des `effects` d'une décision ou d'une
    politique : CT-1 ne le dit pas.
14. **A-4, événement de demande « dans le dossier ».** Reconnu comme le
    voisin dont le hachage recalculé égale `request_hash` ; son `status`
    doit être `retenue` (vecteur `invalide-demande-refusee`). Sans un tel
    voisin : `piece_hors_dossier`.
15. **JSON non UTF-8 ou avec marque d'ordre d'octets.** CT-1 §3 exige de
    l'UTF-8 sans marque ; un tel fichier n'est pas du JSON (partie
    inexploitable).
16. **Désignation de l'événement (`event`, `org_id`, `journal_id`).** Lue
    dans `evenement.json` quand ses valeurs suivent les formats du schéma du
    rapport ; sinon `null`, pour que le rapport reste conforme (EX-8.5).
17. **Clause jeton de FK sans précision.** EX-6.16 remplace
    « `{upper_bound_K}` UTC » par « `{gen_time_K}` UTC, à la précision près
    de la politique `{policy_K}`, que le jeton n'indique pas », suivi de
    « selon `{authority_K}` (unité …) ». Texte reproduit à la lettre.
18. **`--exiger`.** Un numéro répété ou écrit avec un zéro de tête est hors
    du domaine (code 2, `usage`) ; les contrôles exigés sont rapportés dans
    l'ordre croissant.
19. **`unshare -n`.** Essayé ici en superutilisateur, comme le rapporte
    §14.2 ; la forme sans privilège n'a pas été essayée par un utilisateur
    sans privilège (point non vérifié 4 du digest R4, toujours ouvert).

20. **`dossier.json` sans forme canonique.** CT-1 §11.4 range
    « un fichier sans forme canonique (nombre non entier, clé en double,
    substitut isolé) » sous E-2, et ne réserve le code 2 qu'à un
    `dossier.json` absent ou « qui n'est pas du JSON » (CT-6 EX-4.12). Un
    index à nom en double ou à nombre non entier est du JSON (RFC 8259 ne
    fait des noms uniques qu'une recommandation) : lecture retenue, pas de
    code 2, mais E-2 en échec, et rien n'est lu de l'index, pas même son
    schéma, puisque la lecture d'un nom en double serait arbitraire. D-1,
    D-2 et les autres vérifications de CT-1 sont `non_execute`
    (`prerequis_en_echec`), les contrôles 4, 5 et 8 aussi (même traitement
    que le point 11). Le verdict est `invalide`, jamais `valide`. Le
    contrôle de forme canonique précède celui du schéma.
21. **Fichier d'ancres et fichier d'en-têtes sans forme canonique.** CT-6
    EX-12.2 et EX-12.3 ne demandent que « lisible, conforme à son schéma ».
    Le texte se tait sur un nom en double ou un nombre non entier
    (`"height": 1000.0`, `"start_height": 990.0`), que le lecteur lirait en
    dernière occurrence ou par sa valeur. Lecture retenue, pour ne jamais
    employer un document ambigu : la forme canonique de CT-1 §4 est exigée,
    et son défaut rend l'entrée inutilisable (code 2) : N-1, type
    `ancres_inutilisables` ; N-2, type `entree_illisible`.
22. **Identifiants de validateurs.** EX-12.2 : chaque jeu « se charge comme
    le nœud le charge ». Le nœud applique `strings.TrimSpace` aux
    identifiants : `ancres.LireJeu` en fait autant (fichier d'ancres et
    `validateurs.json`), puis exige des identifiants non vides et distincts ;
    le hachage du jeu (EX-11.8) porte sur l'identifiant ainsi chargé. Un
    identifiant fait d'espaces est vide ; deux identifiants égaux après
    retrait des espaces sont en double.
23. **Entrées qui ne sont pas des fichiers ordinaires.** CT-6 EX-4.12 range
    « pas un fichier » parmi les refus du système de fichiers, sans dire
    comment le constater sans bloquer : ouvrir un tube nommé attend un
    écrivain, sans fin (EX-15.2). Lecture retenue, pour toute entrée lue
    (parties du dossier, `dossier.json`, `--ancres`, `--entetes-bitcoin`,
    `--second-manifeste`, pièces de `--pieces`) : `Lstat` d'abord, et rien
    n'est ouvert si le chemin n'est pas un fichier ordinaire ; ouverture
    ensuite sans suivre de lien (`O_NOFOLLOW`) et sans attente
    (`O_NONBLOCK`), puis `fstat` sur le descripteur, qui doit être un
    fichier ordinaire et le même que celui que `Lstat` a vu. Un lien
    symbolique n'est jamais suivi, même vers un fichier conforme. Une
    partie déclarée présente qui n'est pas un fichier ordinaire compte comme
    absente du répertoire : D-2 en échec, les vérifications qui en dépendent
    `prerequis_en_echec`. `dossier.json`, un fichier d'ancres, d'en-têtes,
    un second manifeste ou une pièce qui n'est pas un fichier ordinaire rend
    l'entrée inutilisable (code 2). Les répertoires désignés (le dossier,
    `--pieces`) peuvent être des liens.
24. **E-9 sans tableau de signatures.** `approval.approvers` ou
    `approval.signatures` qui n'est pas un tableau (`null` compris) : E-9
    en échec, au lieu de réussir sur zéro signature recouvrée ; E-1 et E-5
    portent aussi le défaut.

## Licences

Code du module : Apache-2.0 (fichiers `LICENSE` et `NOTICE` du dépôt). Les
avis des licences tierces des composants qui entrent dans le binaire (Go,
`x/crypto` avec `PATENTS`, decred) sont reproduits dans `LICENCES-TIERCES`
(EX-14.9, EX-14.10) ; la mention de ces licences dans le fichier `NOTICE` du
dépôt reste à faire hors de ce module (CT-6 §16, ligne `NOTICE`).
