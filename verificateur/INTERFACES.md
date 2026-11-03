# Interfaces des contrôles 4, 5 et 8

État : les trois contrôles sont construits et les fichiers `provisoire.go`
remplacés. Ce document reste le contrat de leurs paquets. Une seule évolution
a suivi la première version : le champ `PointDeclare` de `registre.Entree`
(la partie `points-de-controle.json` est déclarée présente, que K-1 ait
réussi ou non), sans lequel R-11 ne pouvait pas distinguer une partie absente
d'une partie déclarée dont K-1 a échoué (dossiers `invalide-k1-*`).

Ce document s'adresse aux trois développeurs qui écrivent, en parallèle, les
contrôles 4 (jeton RFC 3161), 5 (preuve OpenTimestamps) et 8 (registre et
certificat de commit) du binaire `noortrace-verifier`. Avec CT-6 et les
vecteurs de `spec/vecteurs/ct-6`, il suffit : il n'est pas utile de lire le
reste du module, sauf `commun` (types partagés) et les paquets utilitaires
nommés en fin de document.

Chaque contrôle vit dans son paquet :

| Contrôle | Paquet | Fichier fixe | Fichier à remplacer |
|---|---|---|---|
| 4, et K-7 | `horodatage` | `horodatage/interface.go` | `horodatage/provisoire.go` |
| 5, et K-9 | `ots` | `ots/interface.go` | `ots/provisoire.go` |
| 8, et N-4, K-8 | `registre` | `registre/interface.go` | `registre/provisoire.go` |

Règles communes aux trois :

1. **Ne changez ni les types ni les signatures de `interface.go`.** Le moteur
   (`moteur/`) et le rapport (`rapport/`) en dépendent. Une évolution
   nécessaire se discute d'abord et se fait dans un seul commit qui adapte
   le moteur.
2. **Remplacez `provisoire.go`** par votre implémentation (autant de fichiers
   que vous voulez dans le paquet) et fixez la constante `construit` à
   `true`. Tant qu'elle vaut `false`, le moteur refuse de rendre un verdict
   sur un dossier qui porte vos parties (code 2, `erreur_interne`) et les
   tests de rejeu marquent ces dossiers « en attente des contrôles 4, 5, 8 ».
3. **Raisons de non-exécution** : uniquement celles de la liste fermée de
   CT-6 §6.2 (`commun.PartieAbsente`, `AncreAbsente`, `HorsPerimetreVersion`,
   `PieceHorsDossier`, `PrerequisEnEchec`). `commun.AConstruire` est
   réservée au code provisoire ; le moteur la refuse.
4. **Aucune entrée-sortie** : pas de fichier, pas de réseau, pas de variable
   d'environnement, pas d'horloge système (EX-3.2, EX-3.3). Tout ce que vous
   pouvez lire est dans `Entree`. N'importez ni `net/http`, ni `crypto/tls`,
   ni `os/exec` (EX-14.5 ; `scripts/verifier-sans-reseau.sh` le contrôle).
   N'appelez jamais `x509.Certificate.Verify` (EX-3.3, EX-14.4).
5. **Dépendances** : bibliothèque standard, `golang.org/x/crypto/cryptobyte`
   et `github.com/decred/dcrd/dcrec/secp256k1/v4` (et son sous-paquet
   `ecdsa`), déjà vendorisés. Keccak-256 est fourni par
   `cryptographie.Keccak256` (voir « Utilitaires ») : n'importez pas
   `golang.org/x/crypto/sha3`, qui tirerait `golang.org/x/sys` hors de la
   liste fermée d'EX-14.1. Un nouveau paquet vendorisé de ces deux modules
   exige `go mod vendor` ; aucun nouveau module.
6. **Pas de panique, récursion bornée** (EX-15.2). Le moteur isole chaque
   étape : une panique devient une erreur interne (code 2), jamais un
   statut. Bornes de §15.1 à respecter dans vos analyseurs.
7. **Textes** : chaque `Detail`, `Resume`, `Proposition` et avertissement
   est un `commun.Texte` (`Fr`, `En`). Les propositions d'énoncé doivent
   être égales, octet pour octet, à celles des `attendu.json` (V-5).
8. **Ordre** : les vérifications dans l'ordre de leurs numéros ; les
   avertissements dans l'ordre de leur objet (EX-6.15 : attestations dans
   l'ordre du `.ots`, CRL dans l'ordre du fichier d'ancres puis du jeton,
   extensions dans l'ordre du jeton, certificats et entrées dans l'ordre de
   leur partie). Le moteur trie ensuite tous les avertissements par rang de
   la vérification qui les lève, puis par identifiant ; il garde votre ordre
   pour un même identifiant et une même vérification.
9. **Tranches non nulles** : les tableaux que le schéma du rapport exige
   (`Revocation`, `Attestations`, `Entries`, `Certificates`, `Signers`…)
   sont des tranches vides (`[]T{}`), jamais `nil`, quand elles n'ont pas
   d'élément.

## Comment le résultat entre dans le verdict et le rapport

Le moteur (`moteur/moteur.go`) applique CT-6 §5.2 :

- **Ordre de `checks`** : D, E, C, M, P, A, K-1 à K-9, AT-1 à AT-7, puis
  T-1 à T-11, O-1 à O-7, R-1 à R-11, N-3, N-4. Vos vérifications sont
  insérées telles que vous les rendez.
- **`failed_checks`, `blocking_unexecuted`** : toutes les vérifications en
  échec, et toutes celles non exécutées pour `prerequis_en_echec`, de toute
  famille (sauf AT-). Une seule rend le dossier invalide (code 1).
- **Statut du contrôle** (EX-6.4) : `echoue` dès qu'une vérification qui le
  sert est en échec (vos T-, O-, R-, et K-7, K-9, K-8, N-4) ; sinon, si une
  partie requise est déclarée absente, `non_execute` avec la raison
  d'EX-4.3 (`hors_perimetre_version` pour « hors périmètre CT-1 »,
  `partie_absente` sinon), sans vous appeler ; sinon le couple
  `Resultat.Statut`, `Resultat.Raison` que vous rendez, qui applique la
  règle propre de votre section (EX-9.18, EX-10.12, EX-11.20).
- **Borne** (EX-6.12) et **élément de F7** (EX-6.8) : dérivés du statut.
- **`--exiger`** : un contrôle exigé non réussi donne `incomplet` (code 3).
- **Faits** : `facts.timestamp`, `facts.bitcoin`, `facts.registry` reçoivent
  votre `Faits` si et seulement si le contrôle réussit (EX-6.13) ;
  `facts.checkpoint.timestamp`, `.bitcoin`, `.registry` reçoivent les faits
  de K-7, K-9 et K-8 réussies (EX-6.17).
- **Énoncé** : `Proposition` devient le fragment F4, F5 ou F6 (EX-6.8). Le
  moteur construit lui-même le fragment FK (EX-6.16) à partir de vos `Faits`.
- **`summary`** du contrôle : votre `Resume` ; vide, le moteur écrit la liste
  des vérifications en échec ou non exécutées.
- **`anchors_used`** : vos `AncresEmployees`.
- **Avertissements** : vos `Avertissements`, triés (EX-6.15).

Une K-7, K-9 ou K-8 **en échec** rend son contrôle `echoue` même quand ses
parties requises sont déclarées absentes : la règle 1 d'EX-6.4 précède la
partie absente (CT-6 révision 0.4, EX-4.3, EX-9.18, EX-10.12, EX-11.20).

Les tests de rejeu (`moteur/vecteurs_test.go`) comparent chaque dossier à son
`attendu.json` : verdict, code, `failed_checks`, statuts des huit contrôles,
`not_executed`, avertissements, énoncé dans les deux langues, borne, AT-. Un
dossier sort de l'attente quand **tous** les contrôles réservés dont il
dépend sont construits. Suivre l'avancement :

```bash
go test -run TestInventaireVecteurs -v ./moteur
go test -run 'TestVecteursCT6' -v ./moteur | grep -E -- '--- (PASS|FAIL|SKIP)'
```

## Contrôle 4 : `horodatage`

### Signature

```go
func Verifier(e Entree) Resultat
func Construit() bool

type ControleurAncres struct{}
func (ControleurAncres) Certificat(der []byte) error
func (ControleurAncres) CRL(der []byte) error
```

`Entree`, `Resultat`, `Faits`, `Precision`, `Qualifie`, `Revocation` : voir
`horodatage/interface.go`, documentés champ par champ.

### Contrat

- **Appel pour la clôture** (`Usage == Cloture`) : quand l'index déclare
  `jeton-rfc3161.der` présent. `Etat` dit si le fichier a été lu dans sa
  limite de 64 Kio (`entree.Lu`), s'il la dépasse (`entree.TropGrand` : T-1
  échoue, EX-9.3) ou s'il manque (`entree.Absent`, `entree.Illisible` : D-2
  porte l'échec ; rendez T-1 `non_execute`, `prerequis_en_echec`, et les
  suivantes en cascade).
- **Appel pour K-7** (`Usage == Point`) : quand la partie
  `points-de-controle.json` a K-1 et K-2 réussies et `anchors.rfc3161` non
  nul. Le moteur a déjà décodé le base64 canonique et refusé plus de 64 Kio
  (K-7 `echoue` sans appel). `EmpreinteAttendue` est `checkpoint_hash`
  recalculé ; ajoutez AV-K-2 et AV-K-4 (§9.9).
- **Rendez les onze T-** dans l'ordre (`IDs`), `Controles = []int{4}`, même
  quand une partie est inexploitable (statuts en cascade, EX-5.5 et la table
  9.5). Quand `EmpreinteDisponible` est faux, T-2 est `non_execute`,
  `prerequis_en_echec`, et les autres s'exécutent (EX-5.4 ; dossier
  `invalide-p1-manifeste-membre-en-trop`).
- **`Statut`, `Raison`** : EX-9.18 sur les onze (T-11 exclue). Pour Point,
  c'est le statut de K-7 (EX-9.22).
- **`Faits`** : EX-9.19, non nil si et seulement si `Statut` vaut `reussi`.
  `Qualified` non nil si et seulement si T-11 a réussi. Remplissez aussi
  `GenTimeInstant` et `UpperBoundInstant` (nil sans `accuracy`) : le moteur
  en tire `rewrite_window_end` et `rewrite_window_ms`.
- **`Proposition`** (Cloture, contrôle réussi) : EX-9.20 exactement, sans
  « ; » de tête, suffixe qualifié compris.
- **`AncresEmployees`** : `/tsa_authorities/<i>` de l'autorité retenue par
  T-7 et `/revocation/crls/<i>` des CRL retenues par T-10.
- **N-1** : `ControleurAncres` applique au fichier d'ancres le profil de
  §9.3, EX-9.21 (valeurs `DEFAULT` encodées) et EX-9.4 (noms). Une erreur
  rend le fichier d'ancres inutilisable (code 2, `ancres_inutilisables`,
  `N-1`). Le paquet `ancres` a déjà exigé un PEM d'un seul objet lisible par
  `crypto/x509` et un certificat v3. Construit : les deux méthodes
  relisent l'objet avec le lecteur strict du paquet `horodatage`.

### Sections de CT-6 à couvrir

§9 en entier (9.1 à 9.9 : EX-9.1 à EX-9.22, AV-T-1 à AV-T-4, AV-K-2,
AV-K-4) ; §3.3 et EX-3.3 ; EX-4.11 ; EX-5.4, EX-5.5 ; §6.2 ; EX-12.2 (pour
N-1), §12.1 et §12.2 (autorités, CRL, déclarations, qualification) ; §13.1 ;
EX-14.1, EX-14.4 ; §15.1 (profondeur DER 32, 16 certificats, chemin de 5
certificats) ; libellés de la table 9.5 (déjà dans `rapport/lisible.go`) ;
annexes A.3 et A.8.

### Vecteurs qui l'exercent

- `spec/vecteurs/ct-6/rfc3161/` : clés et certificats (`cles/`), jetons
  (`jetons/`), CRL (`crl/`), et `attendu.json` (statuts de T-1 à T-11 par
  jeton avec `ancres-test.json`, faits, résultats d'OpenSSL).
- `spec/vecteurs/ct-6/ancres/` : `ancres-test.json`,
  `ancres-qualification-declaree.json`, `ancres-tsa-revoquee.json`,
  `ancres-unite-epinglee-revoquee.json`, `ancres-deux-autorites.json`.
- Dossiers (`spec/vecteurs/ct-6/dossiers/`) : `valide-seq-7-complet`,
  `valide-seq-7-complet-sans-ancres`, `valide-seq-7-complet-sans-entetes`,
  `valide-t11-qualification-declaree`, `valide-t7-deux-autorites`,
  `valide-unite-sans-cn`, `invalide-t1-octet-en-trop`,
  `invalide-t1-default-explicite`, `invalide-t1-cn-utf8-invalide`,
  `invalide-t2-jeton-autre-manifeste`, `invalide-t3-message-digest`,
  `invalide-t4-ess-autre-certificat`, `invalide-t5-sha1`,
  `invalide-t6-signature`, `invalide-t6-signature-attestation`,
  `invalide-t7-tsa-expiree`, `invalide-t8-eku-non-critique`,
  `invalide-t9-extension-critique`, `invalide-t10-tsa-revoquee`,
  `invalide-t10-unite-epinglee-revoquee`,
  `invalide-p1-manifeste-membre-en-trop` (T-2 sans `periodHash`).
- K-7 : `valide-point-de-controle-complet`, `-jeton-seul`,
  `-point-contresigne`, `-point-de-cloture`, `-sans-ancres-reviseur`,
  `-complet-attestation`, `invalide-k7-jeton-autre-empreinte`,
  `invalide-k7-jeton-signature` ; `invalide-k7-base64-non-canonique` est
  traité par le moteur.

## Contrôle 5 : `ots`

### Signature

```go
func Verifier(e Entree) Resultat
func Construit() bool
```

`Entree`, `Resultat`, `Faits`, `Attestation`, `PointBitcoin` : voir
`ots/interface.go`.

### Contrat

- **Appel pour la clôture** (`Usage == Cloture`) : quand l'index déclare
  `preuve.ots` présent ; `Etat` comme pour le contrôle 4 (limite 256 Kio,
  EX-10.2 ; `TropGrand` : O-1 échoue).
- **Appel pour K-9** (`Usage == Point`) : K-1 et K-2 réussies,
  `anchors.ots` non nul, base64 canonique décodé par le moteur (plus de
  256 Kio ou non canonique : K-9 `echoue` sans appel). `EmpreinteAttendue`
  est `checkpoint_hash`.
- `Entetes` : le fichier `--entetes-bitcoin` contrôlé par N-2 (réseau,
  hauteur de départ, en-têtes de 80 octets), ou nil (O-4 à O-6 `non_execute`,
  `partie_absente`, EX-4.5). `Ancre` : l'ancre `bitcoin`, ou nil
  (`ancre_absente`).
- **Rendez les sept O-** dans l'ordre (`IDs`), `Controles = []int{5}`.
  `EmpreinteDisponible` faux : O-2 `non_execute`, `prerequis_en_echec`, les
  autres s'exécutent (EX-5.4, EX-10.6).
- **`Statut`, `Raison`** : EX-10.12 (pour Point : statut de K-9, EX-10.16).
- **`Faits`** : EX-10.14, non nil si et seulement si `Statut` vaut
  `reussi` ; `BlockHash` dans l'ordre d'affichage ; `CumulativeWork` en
  chaîne décimale ; `BlockTimeInstant` décodé.
- **`Proposition`** (Cloture, contrôle réussi) : EX-10.15, suffixe
  « (réseau d'essai, sans valeur probante) » sur `regtest` compris.
- **Avertissements** : AV-O-1 à AV-O-3 avec `Verification` = l'O- qui le
  lève (AV-O-3 sur O-5 ; le moteur le renomme K-9 pour le point, d'où AV-O-3
  deux fois dans `valide-point-de-controle-complet`).
- **`AncresEmployees`** : `/bitcoin` quand O-5 a employé l'ancre.

### Sections de CT-6 à couvrir

§10 en entier (EX-10.1 à EX-10.16) ; EX-4.5, EX-4.9 ; EX-5.4, EX-5.5 ;
§12.2 (ancre `bitcoin`) ; §13.2 ; §15.1 (255 opérations par chemin,
arguments et messages de 1 à 4096 octets, `varuint` de 9 octets, charge
d'attestation de 8192 octets) ; libellés de la table 10.4 ; annexes A.4 et
A.8.

### Vecteurs qui l'exercent

- `spec/vecteurs/ct-6/ots/` : `preuves/*.ots`, `entetes/*.json` et
  `attendu.json` (statuts de O-1 à O-7, faits, avertissements par preuve).
- Dossiers : `valide-seq-7-complet`, `valide-seq-7-complet-sans-entetes`
  (`partie_absente`), `valide-deux-attestations` (AV-O-1),
  `valide-attente-uri-vide`, `valide-o3-branche-hors-profil` (AV-O-2),
  `invalide-o1-octet-en-trop`, `invalide-o2-preuve-autre-manifeste`,
  `invalide-o3-resultat-trop-long`, `invalide-o4-mauvaise-hauteur`,
  `invalide-o5-chaine-sans-travail`,
  `non-execute-o5-point-de-controle-hors-entetes`,
  `non-execute-o6-profondeur`, `non-execute-o7-en-attente`,
  `invalide-p1-manifeste-membre-en-trop` (O-2 sans `periodHash`).
- K-9 : `valide-point-de-controle-complet`,
  `valide-point-de-controle-ots-en-attente`,
  `invalide-k9-preuve-autre-empreinte`.

## Contrôle 8 : `registre`

### Signature

```go
func Verifier(e Entree) Resultat
func Construit() bool
func (e Entree) PartiesPresentes() bool
func (e Entree) N4Figure() bool
```

`Entree`, `Partie`, `Manifeste`, `Point`, `ReferencePoint`, `Resultat`,
`Inscription`, `Faits`, `EntreeFaits`, `EvenementCloture`, `EvenementAncre`,
`EvenementInscription`, `CertificatFaits`, `FaitsAncrePoint` : voir
`registre/interface.go`.

### Contrat

- **Appels** : quand `registre.json` et `certificat-commit.json` sont
  déclarés présents (`PartiesPresentes()`), ou, à défaut, quand la partie
  `points-de-controle.json` porte une référence `anchors.registry` avec K-1
  et K-2 réussies (pour K-8 seule : ne rendez alors ni R- ni N-4,
  EX-5.6, et une inclusion `declarative` ; AV-K-1 n'est levé que si K-8
  réussit, EX-11.25, révision 0.4).
- `Registre`, `Certificat`, `Validateurs` : octets lus dans leur limite
  (64 Mio, 64 Mio, 1 Mio) et état de lecture (`TropGrand` : R-1 ou R-3
  échoue, EX-4.11). `Validateurs.Presente` faux : R-3 `non_execute` avec la
  raison d'EX-4.3 (`RaisonAbsence`), sans effet sur le contrôle.
- `Manifeste.Valide` faux (P-1 non réussie) : R-9 et R-10 `non_execute`,
  `prerequis_en_echec` (EX-5.4) ; N-4 ne figure pas (EX-12.5).
- `ClesExploitables` faux : R-10 `non_execute`, `prerequis_en_echec`
  (EX-11.19).
- **Rendez les R-** (`IDs`, `Controles = []int{8}`) quand les parties
  sont présentes : R-1 à R-10 toujours ; R-11 seulement avec `Point` non nil
  ou une entrée `ancre_point_de_controle` (EX-6.18, `INDEX.md` des vecteurs),
  `partie_absente` sans entrée (EX-11.24) ; cas de K-1 en échec : voir
  `registre/LISEZMOI.md`, « Lectures ».
- **`N4`** : non nil si et seulement si `N4Figure()` (EX-12.5) ;
  `Controles = []int{8}`.
- **`K8`** : non nil si et seulement si `Point.Reference` non nil et
  `Point.K2` (EX-11.25) ; `Controles = []int{8}`. Les autres cas de K-8
  (`prerequis_en_echec`, `partie_absente` pour une référence nulle) sont
  posés par le moteur.
- **`Statut`, `Raison`** : EX-11.20, échecs de K-8 et de N-4 compris.
- **`Faits`** : EX-11.21, non nil si et seulement si `Statut` vaut
  `reussi` ; `EntreeFaits.Event` reçoit une valeur `EvenementCloture`,
  `EvenementAncre` ou `EvenementInscription`.
- **`FaitsPoint`** : EX-11.25, non nil si et seulement si K-8 a réussi ;
  `Inclusion` `prouvee` (R-11 a rattaché la référence dans un contrôle 8
  réussi ; `BlockTime` et `Issuer` alors renseignés) ou `declarative`.
- **`Inscriptions`** : les inscriptions prouvées par R-10 réussie dans un
  contrôle 8 réussi. Le moteur en tire la provenance « inscrite au
  registre » des clés (EX-6.8), de la clé du point (EX-6.16) et de la clé de
  l'inscription d'une attestation (EX-6.19).
- **`Proposition`** : EX-11.22 (mentions de R-10 et de N-4, proposition de
  signature par groupes de jeux) ; F6.
- **`AncresEmployees`** : `/registry`, `/registry/validator_sets/<i>` des
  jeux retenus par R-2, `/recorders/<i>` de l'enregistreur comparé par N-4.

### Sections de CT-6 à couvrir

§11 en entier (EX-11.1 à EX-11.25, AV-R-1 à AV-R-3, AV-K-1, AV-K-3) ;
EX-12.5 (N-4), §12.2 (ancre `registry`, `recorders`) ; EX-4.3, EX-5.4,
EX-5.6 ; §13.3 ; EX-14.2 (adaptateur secp256k1 : la signature de R-5 est
`R ‖ S ‖ V` avec `V` dans {0, 1}, EX-11.7) ; §15.1 (17 entrées, 256 reçus,
256 journaux, 4 sujets, 16 certificats, 128 lignes, lignes de 4 Mio) ;
libellés de la table 11.4 ; annexes A.5 et A.8.

### Vecteurs qui l'exercent

- `spec/vecteurs/ct-6/registre/` : `capture/` (réponses brutes),
  `periode-1/`, `periode-1-point/`, `periode-2/`, `variantes/`,
  `trie.json` et `attendu.json` (hachages BFT, racines des reçus, journaux
  décodés).
- Dossiers : `valide-seq-7-complet`, `valide-sans-inscription` (AV-R-1),
  `valide-ligne-non-canonique` (AV-R-2), `valide-provenance-registre`,
  `valide-provenance-mixte`, `valide-deux-jeux-validateurs`,
  `invalide-r1-sans-ancre`, `invalide-r2-jeu-substitue`,
  `invalide-r3-validateurs-declares`, `invalide-r4-autre-chaine`,
  `invalide-r5-quorum`, `invalide-r6-entete-modifie`,
  `invalide-r7-recu-falsifie`, `invalide-r8-autre-contrat`,
  `invalide-r9-cloture-autre-periode`,
  `invalide-r10-inscription-cle-inconnue`, `invalide-n4-cle-chaine`,
  `invalide-p1-manifeste-membre-en-trop` (R-9, R-10 sans manifeste).
- K-8 et R-11 : `valide-point-de-controle-complet`,
  `valide-point-de-controle-reference-declarative` (AV-K-1),
  `invalide-k8-empreinte`, `invalide-k8-contrat`,
  `invalide-r11-ancre-de-periode`.

## Utilitaires disponibles

| Besoin | Fonction |
|---|---|
| SHA-256, Keccak-256 | `cryptographie.Sha256`, `cryptographie.Keccak256` |
| Hexadécimal « 0x » minuscule (CT-1 §3) | `cryptographie.Hex`, `cryptographie.Hex32`, `cryptographie.LireHex` |
| Clé secp256k1 | `cryptographie.LireCleSecp256k1`, `cryptographie.AdresseDeCle` |
| Instants d'EX-6.11, horodatages de CT-1 §3 | `commun.FormaterInstant`, `commun.FormaterSecondes`, `commun.LireHorodatage` |
| Listes « a, b et c » | `commun.JoindreListe` |
| Agrégat d'une vérification à portée multiple (§11.4) | `commun.Agreger` |
| Ordre des raisons (EX-6.5) | `commun.PremiereRaison` |
| JSON strict et borné (doublons, profondeur 128) | `jsonv.Analyser` |
| Schémas embarqués | `schema.Valider(schema.Registre, v)`, `schema.Valider(schema.Registre+"#/$defs/certificat_commit", v)`, `schema.Valider(schema.Validateurs, v)` |
| Jeu de validateurs (chargement d'EX-12.2) | `ancres.LireJeu`, `(*ancres.Registre).JeuPourHauteur` |
| Clé de chaîne d'un enregistreur de l'ancre | `(*ancres.Ancres).CleChainePour` |
