# Confrontation des preuves de cohérence RFC 9162 (CT-5, annexe A.6 ; CT-1 §10.7)

`main.go` relit les preuves de cohérence des vecteurs CT-1 révision 0.3 sans
le code du dépôt, avec une implémentation de référence de Certificate
Transparency : le module Go `github.com/transparency-dev/merkle` v0.0.2
(licence Apache 2.0), dont les vecteurs publics (`proof/verify_test.go`) sont
ceux que CT-1 §10.7 cite. Le programme ne fait que construire l'arbre avec la
bibliothèque, lui demander racines et preuves, lui soumettre les preuves des
vecteurs et comparer.

| Ce qui est recalculé | Par |
|---|---|
| racines RFC 6962 des arbres (feuilles : `hash` des événements, hachées `SHA-256(0x00 ‖ hash)` ; nœuds `SHA-256(0x01 ‖ g ‖ d)`) | `rfc6962.DefaultHasher`, `testonly.Tree.HashAt` |
| `PROOF(m, D[0..n-1])` de la RFC 9162 §2.1.4.1, nœud pour nœud | `testonly.Tree.ConsistencyProof` (`proof.Consistency`, puis `Rehash`) |
| verdict de chaque preuve (`first_size`, `second_size`, `first_root`, `second_root`, `path`) : acceptée ou refusée | `proof.VerifyConsistency` |
| refus des sondes de corruption (racines échangées, tailles échangées, chemin vide, tronqué, nœud en trop au début ou à la fin, racine quelconque, chaque nœud remplacé) | `proof.VerifyConsistency` |

Entrées, dans l'ordre de la sortie :

1. les vecteurs publics de la bibliothèque, recopiés dans `main.go` depuis
   `proof/verify_test.go` de la version v0.0.2 (huit feuilles de 0 à 16 octets,
   huit racines, racine de l'arbre vide, cinq preuves de cohérence, hachage
   « quelconque » des sondes) : ils établissent que l'arbre construit ici est
   celui de ces vecteurs ; `merkle/logverifier/log_verifier_test.go` de
   `google/trillian` v1.3.13 porte les huit mêmes racines et quatre des cinq
   preuves, `(1, 1)`, `(1, 8)`, `(6, 8)` et `(2, 5)`, à l'identique ; la
   preuve `(6, 7)` n'y figure pas (comparaison directe des deux fichiers
   sources, lus le 2026-10-25, faite le 2026-10-26) ;
2. `spec/vecteurs/ct-1/merkle/coherence.json` : arbre des douze feuilles de
   `journal-valide`, racines des deux tailles de chaque cas accepté, preuve
   régénérée nœud pour nœud, verdict de chacun des seize cas (acceptés et
   sondes refusées) ;
3. `spec/vecteurs/ct-1/points-de-controle/attendu.json` avec les manifestes
   et `journal-valide/attendu.json` : racine de chaque manifeste recalculée
   depuis les feuilles de sa période (`first_seq` à `last_seq`), preuve de
   chaque point régénérée (les points sont regroupés par
   `(first_size, second_size)`), points de `tree_size` 0 sans preuve ;
4. la partie `points-de-controle.json` de chaque dossier de
   `spec/vecteurs/ct-1/dossiers` et de `spec/vecteurs/ct-6/dossiers` qui la
   porte : preuve régénérée depuis les feuilles de la période dont la racine
   est `second_root`, verdict comparé aux vérifications en échec attendues
   (`controles_en_echec` ou `failed_checks` de `attendu.json`) : refus attendu
   quand K-5 y figure, acceptation sinon.

## Ce que la bibliothèque fait autrement

- `first_size = 0` : la version v0.0.2 accepte une preuve vide depuis une
  taille nulle sans lire `first_root` (« Any size greater than 0 is consistent
  with size 0 », `proof/verify.go`) ; la branche `main` du même dépôt la refuse
  (« consistency proof from empty tree is meaningless »). CT-1 §10.7 ne
  définit pas `m = 0` et le rejette avant tout calcul : la période vide de
  NOORTRACE a une racine nulle, non la racine RFC 6962 de l'arbre vide, et
  aucun point de `tree_size` 0 ne porte de preuve. Le cas `(0, 5)` de
  `coherence.json` est donc relevé comme limite de l'outil, non comme
  discordance.
- Les raisons de refus sont celles de la bibliothèque (« empty proof »,
  « wrong proof size 3, want 4 », « size2 (5) < size1 (3) »,
  `RootMismatchError`) ; la comparaison porte sur accepté ou refusé, la
  raison est imprimée.
- Dossiers dont K-1 est attendue en échec : le vérificateur n'exécute pas K-5
  (prérequis en échec) ; l'égalité du chemin avec la preuve régénérée et le
  verdict de la bibliothèque sont imprimés pour information et ne sont pas
  comptés (les dossiers `invalide-k1-double-defaut` portent un chemin tronqué
  que le vérificateur n'examine pas). Une partie `null` est sans objet.

## Exécution

```bash
cd spec/vecteurs/ct-5/confrontation/coherence
go run . ../../../ct-1 ../../../ct-6
```

Go 1.24 ou ultérieur. À la première construction, `go` résout le module
tiers par le proxy de modules (`go.sum` épingle
`github.com/transparency-dev/merkle v0.0.2 h1:Q9nBoQcZcgPamMkGn7ghV8XiTZ/kRxn1yCG81+twTK4=`
et sa dépendance de test `github.com/google/go-cmp v0.5.9`) ; le programme
lui-même n'accède pas au réseau. Code de retour : 0 si tout concorde, 1
sinon, 2 si une entrée est illisible ou l'usage incorrect. La sortie de
référence est `../sorties/coherence.txt` (transparency-dev/merkle v0.0.2,
Go 1.24.7) : huit racines et cinq preuves publiques (43 sondes refusées),
seize cas de `coherence.json`, trois périodes de 61 points, neuf dossiers de
CT-1 et dix-sept de CT-6 à partie `points-de-controle.json` (un `null` ; deux
points de clôture à preuve vide, `(9, 9)`), 0 discordance, 1 limite de l'outil.

Sources des vecteurs publics (lues le 2026-10-25) :
`https://raw.githubusercontent.com/transparency-dev/merkle/v0.0.2/proof/verify_test.go`,
`https://raw.githubusercontent.com/google/trillian/v1.3.13/merkle/logverifier/log_verifier_test.go`
(Copyright 2017 Google LLC, licence Apache 2.0) ;
`https://raw.githubusercontent.com/transparency-dev/merkle/main/proof/verify.go`
pour le traitement de `size1 = 0` dans la branche `main`.
