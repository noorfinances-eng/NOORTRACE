# scripts/verify — vérification hors ligne d'un certificat de commit

`certificat-commit.mjs` vérifie, **sans faire confiance au nœud**, le certificat
de décision qu'un validateur noorcore conserve pour chaque hauteur commise en
mode BFT. La logique est dans `scripts/lib/certificat-commit.mjs` (fonctions
pures, testées octet par octet contre le code Go) ; ce dossier porte la ligne
de commande et son mode d'emploi.

## Ce qu'est un certificat de commit

Le nœud écrit à chaque commit un `DecidedCert`
(`core/consensus/cert_store.go`, clé LevelDB `cert/v1/<hauteur>`), conservé
sur 300 000 hauteurs par défaut (`NOOR_BFT_CERT_RETENTION_HEIGHTS`). Il contient :

| Champ | Contenu |
|---|---|
| `chainId` | identifiant de chaîne BFT (`noortrace-2124-dev` pour le réseau de développement) |
| `valsetHash` | hachage du jeu de validateurs sous lequel le bloc a été décidé (`0x…`, 32 octets) |
| `h`, `r` | hauteur et tour décidé |
| `hash` | hachage du bloc (`0x…`), le même que `eth_getBlockByNumber` rend pour cette hauteur |
| `prop` | la **ligne brute** de l'enveloppe signée de la proposition du tour décidé |
| `cmts` | les **lignes brutes** des enveloppes signées des precommits de ce tour pour ce bloc (au moins le quorum) |

Le nœud le sert par `noor_getCommitCertificate` (`core/rpc/commit_certificate.go`,
spécification §13.1 de `docs/RPC_SPEC_2.1.md`, niveau Experimental) sous une
forme lisible : `height` et `round` en quantités `0x…`, `chainId`, `valsetHash`,
`blockHash`, `proposal.line` (la ligne brute) et `precommits[].line` (les lignes
brutes), accompagnés de champs **décodés** (`validatorId`, `bodyHash`, `sig`), du
jeu que le nœud utilise **actuellement** (`validatorSet`, son hachage
`validatorSetHash` et `validatorSetMatchesCertificate`, vrai quand ce hachage est
le `valsetHash` du certificat) et de son propre avis (`canonical`, `quorum`). Le
vérificateur ne retient que les lignes brutes et les champs d'identité du
certificat ; tout le reste est ignoré, et le jeu vient du fichier
`--validateurs`, jamais de la réponse. Il accepte aussi la réponse JSON-RPC
complète (`{jsonrpc, id, result}`) et le `DecidedCert` brut (`h`, `r`, `hash`,
`prop`, `cmts`).

Le nœud rend le bloc durable (reçus compris) **avant** d'écrire son certificat :
pendant quelques millisecondes, `noor_getCommitCertificate` sur la hauteur de
tête répond `-32000` avec un message `not yet persisted … retry shortly`. Ce
message est transitoire et distinct de l'absence définitive (`no commit
certificate stored …`) : un script qui demande le certificat juste après le reçu
réessaie en boucle courte (quelques tentatives espacées de quelques dizaines de
millisecondes) au lieu d'archiver « pas de certificat ». Le présent
vérificateur, appelé avec `--rpc --bloc`, rend le code 2 (entrée inutilisable)
sur ce message, jamais le code 1.

Les lignes sont exactement les trames qui ont circulé entre validateurs. Chaque
enveloppe (`core/consensus/signing.go`) lie par une signature secp256k1 le
domaine `noor/v1/bft`, la chaîne, le type de message, l'identifiant du
validateur, le hachage du jeu, la hauteur, le tour, le hachage du bloc et le
hachage sha256 du corps (le vote ou la proposition en JSON).

## Ce que le vérificateur prouve

Avec un certificat et un fichier `validators.json` (`{validators:[{id, pubKeyHex}]}`),
il établit que :

1. le certificat est bien formé (chaîne, hauteur > 0, tour, hachages de 32
   octets, une proposition, au moins une ligne de precommit) ;
2. le jeu fourni se charge comme le nœud le charge (identifiants non vides et
   uniques, clés non vides, exploitables et toutes distinctes) et son hachage,
   recalculé (`sha256("noor/v1/valsethash|" ‖ id ‖ 0 ‖ clé ‖ 0 …)`, identifiants
   triés), est **celui que le certificat désigne** ;
3. la proposition est une enveloppe `CONS_PROPOSAL` valide : domaine, chaîne,
   hachage du jeu, hauteur, tour et bloc égaux au certificat, `bodyHash` égal au
   sha256 des octets d'origine du corps, corps `Proposal` cohérent (hauteur,
   tour, bloc, `proposer` égal au signataire), signature canonique dont la clé
   recouvrée est celle du validateur nommé dans le jeu fourni ;
4. **chaque** ligne de precommit est une enveloppe `CONS_PRECOMMIT` valide selon
   les mêmes règles, avec un corps `Vote` de type precommit (2) pour cette
   hauteur, ce tour et ce bloc, dont `Voter` est le signataire ;
5. les signataires des precommits sont **distincts** et au moins aussi nombreux
   que le quorum du jeu (`floor((N + f) / 2) + 1`, `f = floor((N − 1) / 3)` :
   3 sur 4) ;
6. avec `--en-ligne`, que le bloc du certificat est le bloc canonique que le
   nœud rend à cette hauteur (`eth_getBlockByNumber`), et avec `--bloc`, que le
   certificat obtenu est celui du bloc demandé.

Rien de ce que le nœud a décodé n'est cru : `validatorId`, `bodyHash` et `sig`
sont relus dans la ligne brute, le corps est haché sur ses octets d'origine
(jamais re-sérialisé), la clé publique est **recouvrée** de la signature puis
comparée, sous forme non compressée, à celle du jeu fourni (le fichier peut
porter des clés de 65, 64 ou 33 octets ; le hachage du jeu est calculé sur les
octets tels que déclarés). Un certificat n'est déclaré valide que si tous les
contrôles passent : une ligne invalide, un signataire en double ou un quorum
manquant le rendent invalide, même si d'autres lignes suffiraient.

### Ce que le vérificateur accepte : ce que le décodeur du nœud accepte

Le nœud stocke les lignes telles qu'il les a reçues du réseau, après les avoir
acceptées. Son décodeur (`encoding/json`, `VerifyEnvelope`, le dispatcher) est
plus permissif que son encodeur : si le vérificateur n'acceptait que la forme
que l'encodeur Go produit, un seul validateur émettant une ligne légale mais non
canonique rendrait « INVALIDE » un bloc réellement décidé. Le vérificateur
reproduit donc la tolérance du décodeur, ni plus ni moins :

| Tolérance (acceptée, **signalée** dans `remarques`) | Refus (comme le nœud) |
|---|---|
| noms de membres JSON comparés sans la casse (`Domain`, `BODY`, aussi `ſ`/`S` et le signe Kelvin/`K`), dernière occurrence gagnante | nom de membre différent (`domaine`) |
| base64 à bits de bourrage non nuls, `\n`/`\r` dans le base64 | alphabet URL, bourrage absent ou mal placé |
| hachage de corps en `0X…` ou chiffres majuscules | hachage sans `0x`, `null`, absent |
| `Voter`/`proposer` vide ou `null` (le signataire est le `validatorId`) | `Voter` présent et différent (même composé d'espaces), `proposer` différent |
| `Vote.Type` différent du type d'enveloppe ou absent (le dispatcher impose celui de l'enveloppe) | `Type` non entier, hors `uint8`, chaîne |
| membres inconnus dans le corps, espaces et ordre quelconques | entiers non littéraux (`8328.0`, `"8328"`, négatifs), champs de `Proposal` mal typés |

Une ligne acceptée sous une forme non canonique n'invalide rien ; le contrôle
correspondant porte `remarques` (`--json`) et son détail l'indique. Le contrat
est vérifié ligne par ligne contre les vecteurs « lignes » produits par Go
(section « Parité »).

En résumé : **un quorum du jeu fourni a signé ce bloc à cette hauteur.**

## Ce que le vérificateur ne prouve pas

- **Que le jeu fourni est le bon.** Il vérifie que le certificat désigne ce jeu
  et que les signatures en viennent ; si l'on fournit un faux jeu et un
  certificat forgé avec ses clés, tout passe. C'est au dossier de porter le
  `validators.json` et son origine (pour le réseau de développement :
  `chain/runtime/validators.json`, généré par `chain/scripts/dev-net.sh`).
- **Que le certificat vient de la bonne chaîne, sans `--chaine`.** Le `chainId`
  est lié à chaque signature et comparé aux lignes, mais il n'est comparé à une
  attente que si `--chaine` est donné : un même jeu de validateurs réutilisé
  sur un réseau d'essai et sur le réseau cible y signe des certificats tout
  aussi valides. Sans `--chaine`, le rapport porte un avertissement qui nomme
  la chaîne déclarée ; donner `--chaine` dès que la chaîne attendue est connue.
- Que le bloc est canonique **hors ligne** : sans `--en-ligne`, seul le
  certificat parle. Un suiveur noorcore relaie ces appels au leader sans
  répliquer blocs ni état ; interroger plusieurs validateurs reste le geste
  prudent.
- Le contenu du bloc : le hachage du bloc BFT est calculé sur les engagements
  de la proposition (`BFTBlockHash`) ; ce vérificateur n'exécute pas le bloc et
  ne recalcule pas ce hachage depuis les engagements.
- Que le proposant était celui de la rotation pour ce tour : non vérifié ici
  (le quorum de precommits suffit à établir la décision).
- Que le certificat existe encore : au-delà de la rétention, le nœud n'en a
  plus ; d'où l'option `--enregistrer` pour le mettre au dossier à temps.

## Usage

```bash
# depuis un fichier (sortie de noor_getCommitCertificate, telle quelle ou son champ result)
node scripts/verify/certificat-commit.mjs certificat-8328.json --validateurs chain/runtime/validators.json \
  --chaine noortrace-2124-dev

# depuis le nœud, avec comparaison au bloc canonique et archivage du certificat
node scripts/verify/certificat-commit.mjs --rpc http://127.0.0.1:8645 --bloc 8328 \
  --validateurs chain/runtime/validators.json --chaine noortrace-2124-dev --en-ligne \
  --enregistrer dossier/certificat-8328.json

# rapport JSON (pour un script), identifiant de chaîne attendu
npm run verify:certificat -- certificat-8328.json --validateurs chain/runtime/validators.json \
  --chaine noortrace-2124-dev --json
```

| Option | Rôle |
|---|---|
| `<fichier>` | certificat en JSON |
| `--rpc <url>` | point JSON-RPC d'un nœud (requis avec `--bloc` et `--en-ligne`) |
| `--bloc <hauteur\|0xhash\|latest>` | obtient le certificat par `noor_getCommitCertificate` (paramètre envoyé : quantité `0x…`, hachage de 32 octets ou `latest`) |
| `--validateurs <fichier>` | jeu de validateurs, **obligatoire** |
| `--en-ligne` | compare au bloc canonique (`eth_getBlockByNumber` à la hauteur du certificat) |
| `--chaine <id>` | identifiant de chaîne BFT attendu ; recommandé, avertissement dans le rapport sinon |
| `--enregistrer <fichier>` | écrit le certificat obtenu par RPC |
| `--json` | rapport en JSON : `{valide, controles:[{nom, ok, detail, …, remarques?}], signataires, quorum, tailleJeu, chainId, hauteur, ronde, blockHash, valsetHash, proposant, avertissements, source, enLigne}` |

Codes de retour : **0** valide, **1** invalide (au moins un contrôle
cryptographique, de quorum ou de liaison en échec sur un certificat bien
formé : une affirmation sur la chaîne), **2** entrée inutilisable (option
manquante, fichier illisible, JSON qui n'est pas un certificat ou certificat
mal formé — contrôle `structure` en échec, par exemple `{"h":5}` —, nœud
injoignable, méthode inconnue du nœud, bloc sans certificat ou certificat de la
tête pas encore écrit).

Noms des contrôles : `structure`, `jeu_validateurs`, `hachage_jeu`, `chaine`,
`hauteur`, `bloc_demande`, `bloc_canonique` (les quatre derniers selon les
options), `proposition`, `precommit` (un par ligne, avec `indice` et
`validatorId`), `signataires_distincts`, `quorum`.

## Fixture du réseau de développement

`test/fixtures/certificat-commit/` porte une réponse réelle du réseau de
développement (`certificat-8316.json`, hauteur 8316, le bloc du déploiement
d'AttestationRegistry), le bloc canonique correspondant (`bloc-8316.json`,
`eth_getBlockByNumber`) et le `validators.json` du réseau ; les tests vérifient
le certificat contre ce jeu, la concordance avec le bloc canonique et le refus
contre un autre jeu.

## Parité avec le code Go

`test/certificatCommit.test.js` (lancé par `npx hardhat test`) contient des
vecteurs de référence produits par le code Go de noorcore lui-même
(`SigningDigest`, `ValidatorSetHash`, `Quorum2f1`, enveloppes signées par des
clés jetables fixes, certificat complet, lignes canoniques ou non avec le verdict
du nœud, fichiers `validators.json` avec ce que le nœud en charge) : le
JavaScript doit rendre les mêmes digests et hachages, accepter le certificat Go,
reconstruire les mêmes lignes octet pour octet (les signatures secp256k1 sont
déterministes, RFC 6979, des deux côtés) et donner à **chaque** ligne le verdict
du nœud. Les altérations (signature modifiée, bloc modifié, quorum manquant,
signataire en double, validateur hors jeu, mauvais jeu, prevote au lieu de
precommit, `bodyHash` incohérent, S haut, vote nul) sont toutes refusées.

Les vecteurs sont épinglés et exportés par un test Go permanent de noorchain-core,
`core/consensus/signing_vectors_test.go` : un changement de `SigningDigest`, de
`ValidatorSetHash` ou de la tolérance du décodeur fait échouer ce test côté Go.
Pour régénérer la constante `VECTEURS_GO` du test JavaScript (depuis la copie de
travail de noorchain-core, le fichier de validateurs étant celui du fixture) :

```bash
NOOR_SIGNING_VECTORS_OUT=/tmp/vectors.json \
NOOR_SIGNING_VECTORS_VALIDATORS_FILE=$PWD/test/fixtures/certificat-commit/validators.json \
  go test ./core/consensus/ -run TestSigningVectors -count=1
# puis recopier le contenu de /tmp/vectors.json tel quel dans VECTEURS_GO
```

Un vecteur qui change après régénération signale un changement du protocole ou
du décodeur : la cause est à comprendre côté Go avant toute recopie.
