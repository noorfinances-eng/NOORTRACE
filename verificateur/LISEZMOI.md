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

Les huit contrôles sont construits et alignés sur CT-6 révision 0.4 et CT-1
révision 0.5 (voir « Règles des révisions », plus bas) : chaque dossier de
`spec/vecteurs/ct-1` et de `spec/vecteurs/ct-6` (88 et 91 au 2026-11-03,
vecteurs des révisions compris) est rejoué contre son `attendu.json` sans
discordance, avec `--exiger <n>` en plus quand l'attendu porte
`exit_code_exiger_<n>`. Le garde-fou de construction reste en place : un paquet dont
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

`go.mod` porte `go 1.27` et `toolchain go1.27.3` (CT-6 EX-14.3, révision
0.4) ; `scripts/construire.sh` refuse toute autre version que go1.27.3.

### Dépendances

Bibliothèque standard, `golang.org/x/crypto` v0.58.0 (paquets `cryptobyte`,
pour le lecteur DER du contrôle 4) et
`github.com/decred/dcrd/dcrec/secp256k1/v4` v4.4.1 (recouvrement des
signatures secp256k1), vendorisées. `go.sum` porte exactement les six lignes
d'EX-14.1 (dont `github.com/decred/dcrd/crypto/blake256` v1.1.0, dépendance
déclarée du module secp256k1 dont aucun paquet n'entre dans le binaire, donc
absente de `vendor/`). Keccak-256 est écrit dans `cryptographie/keccak.go`
(CT-6 EX-14.1, révision 0.4). Sans cgo.

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
`45f2a18bbe0859b3734178009315ff4fec6668c3c7e9a4140f2dbc3f032aba26`
(sources alignées sur CT-6 révision 0.4 et CT-1 révision 0.5 complétées, essai du
2026-11-03). Ce SHA-256 vaut pour l'état des sources à la date de l'essai ;
il change avec le code.

### Absence de réseau (EX-14.5)

```bash
scripts/verifier-sans-reseau.sh [<binaire>]
```

Les quatre preuves : `go list -deps` sans `net/http`, `crypto/tls`,
`os/exec` ; `go tool nm` sans `net.(*Resolver)` ni `net.(*Dialer)` ; mêmes
codes et mêmes rapports JSON sous `unshare -n` qu'hors isolement (196
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
- Règles des révisions (CT-1 0.5, CT-6 0.4), chacune en réussite et en
  échec : `dossier/revision05_test.go` (E-3 sorte par sorte, E-4, E-1
  identifiants nuls, E-9, D-1, D-2, A-1, A-4 et K-6 avec `voisins.json`
  inexploitable, enveloppes contraires au schéma, parties sans forme
  canonique, `seq` en chaîne, AT-1) ; `horodatage/revision04_test.go`
  (EX-9.15, EX-9.23, EX-9.24) et les cas d'EX-9.10 de
  `horodatage/controles_test.go` ; `registre/scenarios_test.go` (EX-11.6,
  EX-11.14, AV-K-1) ; `jsonv/jsonv_test.go` (profondeur, substituts en
  octets) ; `moteur/revision04_test.go` (EX-4.11, EX-4.12, EX-4.16, EX-5.15,
  EX-6.22, E-3 d'un appel sans approbation, EX-9.10 et EX-9.24 de bout en
  bout).
- Cibles de fuzzing (EX-15.3) : `jsonv.FuzzAnalyser`, `jcs.FuzzCanonique`,
  `ancres.FuzzAncres`, `ancres.FuzzEntetes`, `horodatage.FuzzJeton`,
  `horodatage.FuzzCertificat`, `horodatage.FuzzCRL`, `ots.FuzzAnalyser`,
  `registre.FuzzRegistre`, `registre.FuzzLigne` ; `go test -fuzz` sur l'une
  d'elles avec `-fuzztime` (30 s chacune en CI).

## Salle blanche

Le binaire est écrit depuis `spec/*.md`, `spec/schemas/*.json` et les
fichiers de données de `spec/vecteurs/ct-1` et `spec/vecteurs/ct-6`, et
depuis eux seuls. Ses auteurs n'ouvrent, ne lisent, ne cherchent ni
n'importent `scripts/**` (implémentation de référence), `paquets/**`
(bibliothèque noyau), les tests JavaScript de vérification, les répertoires
`spec/vecteurs/*/verificateur-independant/` ni `spec/vecteurs/*/confrontation/`.
Un passage ambigu ou contraire à un vecteur est signalé ici (« Lectures
encore ouvertes ») et tranché par le texte, jamais en consultant une autre
implémentation. Cette règle vaut pour les trois paquets des contrôles 4, 5
et 8.

## Règles des révisions (CT-6 0.4, CT-1 0.5)

Les vingt-quatre lectures que la construction du binaire avait dû retenir
sont devenues des règles du texte (CT-6 révision 0.4, section 16 ; CT-1
révision 0.5, section 17). Le binaire applique la règle, et chaque point
renvoie à elle ; « changé » signale un comportement que la révision a
modifié.

| Point | Règle |
|---|---|
| Keccak-256 hors de `golang.org/x/crypto/sha3` | CT-6 EX-14.1 (révision 0.4, correction) |
| `go.mod` : `go 1.27`, `toolchain go1.27.3` | CT-6 EX-14.3 (révision 0.4, correction) |
| Panique : code 2, `erreur_interne`, jamais un statut | CT-6 EX-15.2 (révision 0.4) |
| Contrôle non construit : code 2, jamais une raison hors liste | CT-6 EX-4.2 (révision 0.4) |
| K-7, K-8 ou K-9 en échec, partie requise absente : contrôle `echoue` | CT-6 EX-4.3, EX-9.18, EX-10.12, EX-11.20 (révision 0.4) |
| Partie « exploitable » ; « `evenement.json` exploitable (E-1, E-2) » pour AT-5 et AT-6 | CT-6 §2, EX-5.13 ; CT-1 §11.4 (révision 0.5) ; une partie sans forme canonique n'est plus exploitable : E-2 échoue, son contrôle porteur n'est pas exécuté (changé pour `voisins.json`, `chemin.json`, `manifeste.sig`, `cles.json`, `approbations.json`) |
| A-2, « passe E-1 à E-11 » | CT-6 EX-5.16 |
| A-1 et son enveloppe ; A-2 et A-3 sans A-1 | CT-6 EX-5.16 ; CT-1 §11.4, A-1 (révision 0.5) : raison exacte « aucune approbation liée » (changé) ; A-2 et A-3 exécutées sur une enveloppe contraire à son schéma (changé) |
| Portée de E-2 | CT-6 EX-5.20 ; CT-1 §11.4, cas (d) |
| D-1 quand `evenement.json` est inexploitable | CT-6 EX-5.14 : `non_execute` (`prerequis_en_echec`), jamais `reussi` (changé) ; CT-1 §11.4, D-1 : `org_id` et `journal_id` comparés (changé) |
| Événement prouvé inexploitable et parties réservées | CT-6 EX-5.15 (le binaire était conforme) |
| Index contraire à son schéma ou de plus de 1 Mio | CT-6 EX-4.11, point 3 |
| Partie au-delà de sa limite et D-2 | CT-6 EX-4.11, point 2 ; CT-1 §11.4, cas (b) |
| Partie déclarée présente absente du répertoire | CT-6 EX-4.11, point 1 ; CT-1 §11.4, cas (a) |
| E-3 | CT-6 EX-5.17 ; CT-1 §5.3, règle exacte de E-3 (révision 0.5) : appel d'outil (politique, statut, approbation, effets vides), échange (`approval` nul), décision (forme canonique de `A`, effets vides), rotation et politique (`launched_by`) (changé) |
| A-4, demande reconnue au seul hachage | CT-6 EX-5.18 ; `voisins.json` inexploitable : `prerequis_en_echec` (changé) ; de même K-6 (EX-5.9, changé) |
| JSON non UTF-8, marque d'ordre d'octets, profondeur, forme canonique | CT-6 EX-4.16 ; CT-1 §3, §4 règle 7 (révision 0.5) : substitut écrit en octets (`ED A0 80`) = E-2 (changé) ; profondeur comptée sur les conteneurs, la racine comprise, 128 admise (changé) |
| Désignation de l'événement | CT-6 EX-6.22 : `event`, `org_id`, `journal_id` jugés un à un, `event.tool` nul seul (changé) |
| Clause jeton de FK sans précision | CT-6 EX-6.16 (révision 0.4) |
| `--exiger` | CT-6 EX-8.2 (révision 0.4) |
| `dossier.json` sans forme canonique | CT-6 EX-4.12, point 2 ; CT-1 §11.4, « `dossier.json` » |
| Fichier d'ancres, fichier d'en-têtes, second manifeste sans forme canonique | CT-6 EX-4.12, point 3, EX-12.2, EX-12.3 : code 2 (changé pour le second manifeste, qui faisait échouer P-5) |
| Identifiants de validateurs | CT-6 EX-12.2 (révision 0.4) |
| Fichiers ordinaires, aucun lien suivi | CT-6 EX-4.17 ; CT-1 §11.4, D-2 : aucun fichier ordinaire du nom d'une partie déclarée absente (changé : une autre entrée de ce nom ne compte plus comme présente) |
| E-9 sans tableau de signatures ; signature sans approbateur | CT-6 EX-5.19 ; CT-1 §11.4, E-9 (révision 0.5) : toutes les signatures sont parcourues (changé) |

Autres règles de la révision appliquées : E-1 et P-1 refusent `org_id` ou
`journal_id` nul (CT-1 §3) ; D-2 et E-4 exigent une chaîne non vide au sens
de CT-1 §3 (blancs Unicode et U+FEFF) ; AT-1 juge la forme canonique de toute
la partie et les dates de l'inscription (CT-1 §11.4, AT-1) ; T-4 échoue
pour un `sid` introuvable dès que le jeton porte des certificats ou qu'une
autorité d'horodatage est fournie (CT-6 EX-9.10) ; clés RSA de 2048 à 8192
bits, exposant impair de 3 à 2³¹ − 1, refusées avant tout calcul (CT-6
EX-9.23) ; clé ou algorithme hors de la version 0 (CT-6 EX-9.24) ;
`serialNumber` de toute taille (CT-6 EX-9.15, le binaire était conforme) ;
lignes de certificat : `Type` du corps non comparé, `proposer` fait de
blancs accepté, AV-R-2 pour un corps non canonique (CT-6 EX-11.6,
EX-11.14) ; AV-K-1 levé seulement avec K-8 réussie (CT-6 EX-11.25).

## Lectures encore ouvertes

Passages que le texte révisé ne tranche pas ; la lecture retenue est celle
du code.

1. **`unshare -n`** (CT-6 §14.2). Essayé ici en superutilisateur ; la forme
   sans privilège n'a pas été essayée par un utilisateur sans privilège
   (point non vérifié 4 du digest R4, toujours ouvert).
2. **Octets d'un corps de proposition** (CT-6 EX-11.6). Les types des
   membres connus de `Proposal` et de `Vote` sont contrôlés comme le nœud
   les décode (ligne refusée sinon) ; pour AV-R-2, le corps d'un precommit
   est réencodé et comparé octet pour octet, celui d'une proposition est
   contrôlé sur les formes que nomme la table (casse, doublon, membre
   inconnu, ordre, espaces, `proposer` vide ou de blancs, `height` ou
   `round` absent ou `null`, `blockHash` en `0X` ou en majuscules), sans
   réencodage complet de `Proposal`.
3. **Membre `previous` ou `next` absent et E-2 à E-11.** CT-6 EX-5.13 et
   CT-1 §11.4 disent qu'un membre absent n'est pas un événement (E-1 ne le
   concerne pas) ; la phrase « E-2 à E-11 ne s'y exécutent pas » est
   rattachée au voisin présent. Lecture : pour un membre absent, E-2 à E-11
   ne sont pas touchées (rien à vérifier) ; pour un voisin présent qui n'est
   pas un objet, ou un élément de `events` qui n'en est pas un, elles sont
   `non_execute` (`prerequis_en_echec`) faute d'échec ailleurs.

Tranchés depuis par les compléments des deux révisions (règle appliquée) :
voisin qui n'est pas un objet et membre absent (EX-5.13), `approval` ni nul
ni objet et `execution.tool` non chaîne (EX-5.13 : E-1, E-3, A-1 à A-4),
K-6 quand `last_seq` est l'événement prouvé (EX-5.9), `genTime` illisible
dans le cas 2 d'EX-9.24, preuve OpenTimestamps hors du profil seul
(EX-10.12 : textes de O-3 et du résumé), forme des attendus
(`exit_code_exiger_4`, `exit_code` 2 et `error_kind`, EX-A.3).

## Licences

Code du module : Apache-2.0 (fichiers `LICENSE` et `NOTICE` du dépôt). Les
avis des licences tierces des composants qui entrent dans le binaire (Go,
`x/crypto` avec `PATENTS`, decred) sont reproduits dans `LICENCES-TIERCES`
(EX-14.9, EX-14.10) ; la mention de ces licences dans le fichier `NOTICE` du
dépôt reste à faire hors de ce module (CT-6 §16, ligne `NOTICE`).
