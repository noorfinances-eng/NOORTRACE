# Vérificateur indépendant CT-7 (Go, salle blanche)

Un second vérificateur des vecteurs de
[CT-7](../../../CT-7-securite-et-conformite.md) (version 0.1), écrit en Go
depuis le seul texte de CT-7, de CT-1 §6.3 (signature EIP-191) et des
schémas que CT-7 nomme, sans lire ni reprendre le code JavaScript de
`scripts/` ni de `test/` (CT-7 EX-A.21 à EX-A.23). Il recalcule chaque
valeur que les vecteurs de `spec/vecteurs/ct-7` déclarent et la confronte.
Deux implémentations écrites séparément qui tombent sur les mêmes octets
rendent les vecteurs probants ; une discordance désigne une ambiguïté de la
spécification ou une faute de l'une des deux.

Module propre `noortrace-ct7` (`go 1.24`), bibliothèque standard
uniquement, sans cgo. Deux briques sont copiées sans modification du
vérificateur Go de `ct-3`, comme EX-A.21 le permet, chacune avec l'en-tête
« Copié sans modification de spec/vecteurs/ct-3/verificateur-independant/… » :
`keccak.go` (Keccak-256 de l'EVM) et `secp256k1.go` (courbe, recouvrement
SEC 1 §4.1.6, signature déterministe RFC 6979). Tout le reste est écrit ici :
analyseur JSON strict, forme canonique JCS v0, validateur JSON Schema
(draft 2020-12, réduit aux mots-clés des quatre schémas, tout mot-clé
inconnu refusé), dérivation BIP-39 et BIP-32 des comptes de test, lecture
des tables et des blocs du texte de CT-7.

## Usage

```bash
cd spec/vecteurs/ct-7/verificateur-independant
go run . ..                        # rapport texte, code 0 si tout concorde
go run . -v ..                     # liste aussi les valeurs concordantes et hors périmètre
go run . -json .. > rapport.json
go test ./...                      # tests propres au module (voir plus bas)
go run . condenser attestation.json     # D_P et ses groupes de huit chiffres (CT-7 EX-7.8)
go run . condenser-pv proces-verbal.json # D_C et ses groupes de huit chiffres (CT-7 EX-5.8)
```

Les deux derniers modes servent de second outil indépendant au signataire
qui compare un condensé à l'écran de son portefeuille (CT-7 EX-5.8, EX-7.8,
EX-A.21) : ils lisent le fichier, recalculent la forme JCS v0 et le
condensé préfixé, et n'ouvrent aucune connexion.

La racine donnée est `spec/vecteurs/ct-7` ; le texte de CT-7 et les schémas
sont lus à `../../CT-7-securite-et-conformite.md` et `../../schemas/` de
cette racine, le mnémonique de test à `../ct-3/constantes.json` et les
fichiers PEM de test à `../ct-6/rfc3161/cles/`. `go build` produit un
binaire `noortrace-ct7`, exclu par le `.gitignore` local.

Codes de retour : `0` tout concorde (les valeurs hors périmètre sont
énoncées, pas comptées) ; `1` au moins une discordance ou une erreur
(fichier illisible, table du texte introuvable) ; `2` usage incorrect ou
racine introuvable.

## Ce qui est recalculé

| Famille | Fichiers lus | Valeurs recalculées et confrontées |
|---|---|---|
| constantes | `attestations/constantes.json`, `../ct-3/constantes.json`, `attestations/exemple/jeu.json` | mnémonique égal à celui de `ct-3` ; adresse de chaque compte au chemin `m/44'/60'/0'/0/i` (BIP-39, BIP-32) ; `prefix_hex` et `prefix_utf8` = `P_P` ; `org_id` = keccak256(slug) ; `journal_id` = keccak256(nom) ; `rules_sha256` = SHA-256 de l'étiquette, étiquette citée par 7.1 ; `approver_set` = `jeu.json` |
| ceremonies | `ceremonies/<cas>/{proces-verbal.json, attendu.json}` | `attendu.json` conforme à `#/$defs/attendu` ; CR-1 (JSON strict, 1 Mio, schéma `ceremonie-cles-v0`) à CR-12 dans l'ordre d'EX-5.9 ; verdict, `D_C = Keccak-256(P_C ‖ JCS(V))`, vérifications en échec, non exécutées (`prerequis_en_echec` derrière CR-1), adresses des signataires dans l'ordre de `participants` (EX-5.9) ; chaque signature valide d'un compte de test reproduite par RFC 6979 ; chaque cas exigé par la table d'A.4 publié |
| exemple 5.10 | texte de CT-7 §5.7 et §5.10, `ceremonies/valide-creation-enregistreur/` | `P_C` (hexadécimal, 28 octets) ; procès-verbal imprimé conforme au schéma et égal au fichier ; `JCS(V)` (4 748 octets) imprimé ; empreintes des deux clés, adresse de chaîne, `D_C`, `M`, les trois signatures (égales, recouvrées, reproduites) ; `attendu.json` égal à celui imprimé |
| attestations | `attestations/attestations.json` | fichier conforme à `#/$defs/fichier_vecteurs` ; pour chaque cas, AT-1 (schémas `attestation_signee` et `jeu_approbateurs`, relations d'EX-7.2, JCS v0, texte JSON strict pour `invalide-at1-nombre-non-entier`) à AT-4 avec leurs prérequis ; `digest` (D_P recalculé, `null` si AT-1 échoue), adresses recouvrées (`null` pour une signature non canonique), statuts et raisons, `retained` ; signatures valides reproduites par RFC 6979 ; chaque cas exigé par la table d'A.6 publié |
| exemple 7.1-7.5 | `attestations/exemple/`, texte de CT-7 §7.1 à §7.5 | `JCS(P)` octet pour octet (`jcs.txt`, 3 201 octets), `D_P`, `M`, deux signatures (recouvrées, reproduites) ; attestation signée = attestation et signatures de l'exemple, AT-1 à AT-4 réussies contre `jeu.json` ; exemple imprimé en 7.1 = `attestation.json` ; `P_P` (35 octets), longueur de `JCS(P)`, `D_P`, `M`, signatures et signature du compte 3 attribuée au compte 2 (adresse recouvrée) de 7.2 ; `digest` de 7.3 ; document de politique de 7.5 : SHA-256, base64, forme canonique, `perimeter.attestation_digest` = `D_P`, cohérence de l'événement imprimé (`policy_sha256`, version, outil) |
| croises | `attestations/croises.json` | chaque signature est celle du compte 1 sur le message d'origine (recouvrée, reproduite par RFC 6979) ; `D_P` et `D_C` des messages et des cibles recalculés ; texte d'inscription en `noortrace/inscription/v0` ; adresse recouvrée sur le message présenté, statut `echoue`, vérification qui refuse (CT-1 AT-3, CT-1 E-9, CT-7 CR-11, CT-3 AN-) |
| matrice | `matrice-conformite.json`, `matrice/invalides/`, texte de CT-7 (annexes B et C, §8.3, A.8) | MX-1 (schéma `matrice-conformite-v0`), MX-2, MX-3 (statut d'EX-8.3), MX-5 (`serves`, sous-sections de l'annexe C), MX-9 (dates des textes pas encore applicables, faits des tables de l'annexe B) sur le fichier publié ; exemples annotés de 8.3 conformes et égaux aux lignes du fichier ; pour chaque cas de A.8, l'ensemble exact des MX- exécutées ici en échec ; `attendu.json` égal à la table d'EX-A.14 |
| menaces | `menaces.json`, texte de CT-7 §3.2 à §3.5 et §3.8 | RV-1 (schéma `modele-menace-v0`) ; RV-2 (réponse écrite, préfixe du test, MN- et RA- sans trou) ; RV-4 (`refs` recalculés par l'expression du texte, aucun `EX-` sans `CT-n`) ; RV-5 (tables 3.2, 3.4, 3.5 égales au fichier cellule par cellule) ; RV-8 (risques acceptés : nom, borne, porteur, menaces) ; table des tables sources de 3.3 et `sources` de chaque menace dans l'ordre du rattachement ; exemple de 3.8 conforme et égal au fichier |
| cles-de-test | `cles-de-test.json`, `../ct-6/rfc3161/cles/*.pem` | `ct-1` : clé Ed25519 depuis la graine SHA-256 de l'étiquette (CT-1 §13) ; `ct-3` : clé publique et adresse au chemin de dérivation ; `ct-6` : SHA-256 du `SubjectPublicKeyInfo` du certificat (lu sans décoder les noms) ou de la clé privée PKCS#8 ; `ct-4` : point de la courbe et adresse dérivée, longueur Ed25519 ; présence des quatre sources |

## Tests du module (`go test`)

- Keccak-f[1600] confronté à SHA3-256 de la bibliothèque standard,
  `keccak256("")`.
- Cas limites de la forme canonique (CT-1 §4) : tri par unités UTF-16,
  échappements, zéro négatif, refus des nombres non entiers, hors
  intervalle, substituts isolés, noms en double.
- Motifs que RE2 n'accepte pas tels quels (`{32,4096}`, `{1,4095}`) : bornes
  exactes ; `\s` d'ECMAScript.
- Instants de CT-1 §3 : dates inexistantes refusées, jamais renormalisées.
- Comptes Hardhat 0 à 4 du mnémonique public.
- Exemple numérique de 7.2 : longueur de `JCS(P)`, `D_P`, `M`, signatures
  des comptes 1, 2 et 3 reproduites et recouvrées.
- Mutations du procès-verbal de 5.10 faites dans le test et signées à
  nouveau : la vérification visée, et elle seule (avec ses conséquences
  écrites, par exemple une exception qui n'est plus nommée), échoue ; une
  signature en forme `s` haute ne fait échouer que CR-11.
- Les vecteurs publiés, s'ils sont présents : tout doit concorder.

## Limites (hors périmètre)

- **MX-4, MX-6, MX-7 et MX-8** : elles lisent les autres spécifications ou
  comparent les tables du texte à la matrice ; EX-A.23 les laisse au
  vérificateur de renvois. Les MX- de ces familles attendues en échec par
  un cas de A.8 sont rapportées hors périmètre.
- **RV-3, RV-6, RV-7, RV-9 du vérificateur de renvois** : existence des
  renvois et des lignes sources dans les autres spécifications, occurrences
  de « CT-7 » ; les clés de test sont, elles, recalculées (famille
  `cles-de-test`).
- **Dérivation des clés de `ct-4`** depuis leur étiquette (CT-4 annexe A.2) :
  CT-7 ne la fixe pas ; seule la cohérence interne de chaque clé est
  vérifiée (18 valeurs hors périmètre).
- **Provenance des condensés `D_A` et du registre** de `croises.json` : seule
  la signature du compte 1 sur ces condensés est vérifiée ; leur calcul
  relève de CT-1 §6.4 et de CT-4.
- **Hachage et signature de l'événement d'inscription de 7.5** (CT-1 §6.1,
  §6.2) : vérifiés par le vérificateur de `ct-1` sur le dossier
  `valide-seq-12-attestation-inscrite`.
- **Épreuves à l'aveugle** (`acceptation-*-attendu.json`) : grilles
  d'épreuves humaines, aucune valeur à recalculer.
- **AT-5 à AT-7**, qui demandent un dossier, sont vérifiées par le
  vérificateur de `ct-1` (et sa copie dans `ct-2`).

## Choix de lecture du texte

- La signature EIP-191 est refusée avant tout recouvrement si elle n'a pas
  65 octets, `v` dans {27, 28}, `r` et `s` dans [1, n − 1] et `s` dans la
  moitié basse (CR-11, EX-7.6) ; l'adresse recouvrée d'une signature
  refusée vaut `null` dans les attendus.
- Les signataires d'un procès-verbal (`signers`) sont les adresses des
  participants dont la signature est valide, dans l'ordre des signatures,
  sans doublon.
- Une attestation hors dossier est « retenue » quand AT-1 à AT-4 réussissent
  (définition de la section 2, réduite aux vérifications hors dossier).
- La colonne « Porté par » de 3.5 s'écrit `client`, `exploitant_noortrace`,
  `reviseur`, `operateur_validateur` dans le fichier.
- CR-5 : `fingerprint` est nul si et seulement si `public_key` l'est ; une
  clé secp256k1 sans clé publique n'est admise que pour l'usage
  `approbateur` ; `address` est nulle hors de secp256k1.

## Confrontation

Confrontation du 2026-10-27 : 1 241 valeurs recalculées, 1 241
concordantes, **0 discordante**, 32 hors périmètre, 0 erreur. Par famille :
`constantes` 13, `ceremonies` 395 (40 cas), `exemple 5.10` 21,
`attestations` 118 (19 cas), `exemple 7.1-7.5` 32, `croises` 43 (7 cas),
`matrice` 48 (fichier publié et 12 cas), `menaces` 518 (98 menaces, 14
composants, 82 risques acceptés), `cles-de-test` 53.
