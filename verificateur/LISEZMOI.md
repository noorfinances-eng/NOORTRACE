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
  entree/                   lectures bornées d'EX-4.13, SHA-256 en flux (EX-4.15)
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
`25c83d4b80a74e140b95c294606d64de4c1b0157412973004a8818a08fa3bd61`. Ce
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
  conformes à `spec/schemas`, motifs), `entree`, `ancres` (N-1, N-2, N-3).
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
   (E-1 et A-3, pas A-1).
9. **E-2, « un fichier sans forme canonique ».** Appliqué à toutes les
   parties JSON de CT-1 ; ses conséquences portent sur le hachage des
   événements (E-7, E-8, C-2, M-1…) et sur `periodHash` (P-1, P-5).
10. **D-1 quand `evenement.json` est inexploitable.** La comparaison
    d'`event.seq` et `event.hash` n'est pas possible ; D-1 est jugée sur le
    schéma (vecteur `invalide-partie-nulle` : E-1 seule en échec).
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
    `approval` non nul ; rotation et politique : `approval` nul ; rotation :
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

## Licences

Code du module : Apache-2.0 (fichiers `LICENSE` et `NOTICE` du dépôt). Les
avis des licences tierces des composants qui entrent dans le binaire (Go,
`x/crypto` avec `PATENTS`, decred) sont reproduits dans `LICENCES-TIERCES`
(EX-14.9, EX-14.10) ; la mention de ces licences dans le fichier `NOTICE` du
dépôt reste à faire hors de ce module (CT-6 §16, ligne `NOTICE`).
