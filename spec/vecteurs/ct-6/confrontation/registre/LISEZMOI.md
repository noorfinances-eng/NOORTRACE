# Confrontation des vecteurs du registre (CT-6, annexe A.8)

`main.go` recalcule les vecteurs de `spec/vecteurs/ct-6/registre` sans le
code JavaScript du dépôt, avec des implémentations tierces :

| Ce qui est recalculé | Par |
|---|---|
| hachage du bloc (`BFTBlockHash`) | `node.BFTBlockHash` de noorcore, et `crypto.Keccak256` de go-ethereum sur la préimage de `attendu.json` |
| racine des reçus, encodage de consensus, bloom | `types.DeriveSha`, `Receipts.EncodeIndex`, `types.CreateBloom` de go-ethereum v1.17.0 |
| trie générique (`trie.json`) | `trie.StackTrie` de go-ethereum |
| journaux `PeriodSubmitted`, `Anchored`, `RecorderRegistered` | `accounts/abi` de go-ethereum, sur une ABI recopiée des déclarations de `contracts/*.sol` ; les sujets 0 sont recalculés depuis les signatures |
| certificats de commit | `consensus.DecodeSignedEnvelope`, `consensus.VerifyEnvelope`, `consensus.ValidatorSetHash`, `consensus.Quorum2f1` de noorcore |
| statuts de R-1 à R-10 et N-4 de chaque jeu de parties et de chaque variante (R-10 : au moins une inscription de la clé du manifeste sous l'émetteur de l'ancre, EX-11.19 ; N-4 : entrée ancre liée et R-5 réussie pour le certificat de son bloc, EX-12.5) | refaits en Go à partir de ces primitives, comparés aux statuts de `attendu.json` |
| `periodHash` des manifestes | SHA-256 de « noortrace/manifeste/v0\n » suivi de la forme canonique imprimée par `spec/vecteurs/ct-1/manifestes/attendu.json` |

Les certificats capturés sont aussi vérifiés par
`scripts/verify/certificat-commit.mjs --chaine noortrace-2124-dev` contre
`capture/validators.json` (`../sorties/registre-certificats.txt`).

## Exécution

Le module emploie noorchain-core (module `noorchain-evm-l1`, commit `618fcef`,
celui que `chain/scripts/build-noorcore.sh` épingle) en lecture seule, par la
directive `replace` de `go.mod`, qui suppose une copie de noorchain-core à côté
du dépôt (`../noorchain-core` depuis la racine du dépôt) ; pour une autre
copie : `go mod edit -replace noorchain-evm-l1=<chemin>`. go-ethereum est
celui que noorchain-core épingle (v1.17.0), Go 1.26.9.

```bash
cd spec/vecteurs/ct-6/confrontation/registre
go run . ../../registre ../../../ct-1
```

Code de retour : 0 si tout concorde, 1 sinon, 2 si une entrée est illisible.
La sortie de référence est `../sorties/registre.txt` (283 concordances, aucun
écart, sur les cinq jeux de parties et les quinze variantes de
`attendu.json`, dont le jeu sans clés d'enregistreur dans l'ancre, N-4
absente). La construction n'écrit rien dans la copie de noorchain-core.
`../sorties/registre-certificats.txt` transcrit les vérifications par
`certificat-commit.mjs`, chemins rendus relatifs à la racine du dépôt.
