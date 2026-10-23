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
  certificat forgé avec ses clés, tout passe. C'est au réviseur de fournir à
  `--validateurs` un jeu obtenu par une voie indépendante (pour le réseau de
  développement : `chain/runtime/validators.json`, produit par
  `chain/scripts/dev-net.sh` ; sinon, auprès d'au moins deux opérateurs de
  validateurs indépendants, CT-6 §12.5). Pour un dossier, `dossier.mjs`
  prend ce jeu dans le fichier d'ancres du réviseur. La partie
  `validateurs.json` du dossier reste déclarative : elle ne sert qu'à la
  vérification de cohérence R-3 et à guider le réviseur (CT-6 EX-3.4,
  §11.2.3).
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
  ne recalcule pas ce hachage depuis les engagements. Le contrôle 8 de
  `dossier.mjs` le fait (section suivante, R-6 et R-7) : il recalcule
  `BFTBlockHash` depuis l'en-tête et la racine des reçus depuis tous les reçus
  du bloc, puis vérifie le certificat contre le jeu de validateurs que le
  réviseur déclare dans son fichier d'ancres.
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

---

# `dossier.mjs` — vérification hors ligne d'un dossier de preuve (CT-1 et CT-6)

`dossier.mjs` est l'implémentation de référence JavaScript du **vérificateur**
de [CT-6](../../spec/CT-6-verificateur.md). Il vérifie un **dossier de preuve
v0** tel que [CT-1](../../spec/CT-1-evenements-et-formats.md) §11 le définit :
un répertoire qui prouve **un** événement du journal (index `dossier.json`,
`evenement.json`, `voisins.json`, `chemin.json`, `manifeste.json`,
`manifeste.sig`, `cles.json`, `approbations.json`, et les cinq parties
`jeton-rfc3161.der`, `preuve.ots`, `registre.json`, `certificat-commit.json`,
`validateurs.json`). Il exécute les **huit contrôles** de l'architecture, hors
ligne, contre les **ancres de confiance** que le réviseur fournit, et rend un
verdict, un énoncé d'une phrase qui n'affirme que ce qui a été prouvé, et un
rapport lisible (français ou anglais) ou JSON.

La logique est dans `scripts/lib/verificateur.mjs` (statuts, verdict, énoncé,
rapports), qui réunit `scripts/lib/journal.mjs` (CT-1), `horodatage.mjs`
(contrôle 4), `ots.mjs` (contrôle 5) et `registre.mjs` (contrôle 8) ; ce fichier
porte la ligne de commande : lecture bornée des entrées, options, sorties,
codes de retour. Aucun accès réseau, aucune lecture de l'horloge du système
pour décider d'un statut, aucun magasin de certificats du système. Le binaire
Go de la phase 2 (`noortrace-verifier`, CT-6 §14) aura la même interface et
rendra les mêmes statuts.

## Les huit contrôles

| N° | Contrôle | Vérifications | Parties et entrées | Ancres |
|---|---|---|---|---|
| 1 | hachage canonique de l'événement | E-1, E-2, E-3, E-4, E-6, E-7 | `evenement.json` ; pièces si `--pieces` | — |
| 2 | chaînage avec les voisins | C-1, C-2, P-3 | `voisins.json` | — |
| 3 | inclusion dans la racine du manifeste | M-1 à M-3, P-1 à P-5 | `chemin.json`, `manifeste.json`, `manifeste.sig` ; second manifeste si `--second-manifeste` | — |
| 4 | jeton RFC 3161 sur `periodHash` | T-1 à T-11 (T-11 sans effet sur le statut) | `jeton-rfc3161.der` | autorités d'horodatage, politiques, révocation, statut qualifié déclaré |
| 5 | preuve OpenTimestamps et en-têtes Bitcoin | O-1 à O-7 | `preuve.ots` ; en-têtes par `--entetes-bitcoin` | réseau, point de contrôle, profondeur minimale |
| 6 | signatures de l'enregistreur | E-8, E-10, E-11, C-3, P-5 ; N-3 | `cles.json`, signatures | clés d'enregistreur, facultatives |
| 7 | signatures des approbateurs et seuil | E-5, E-9, A-1 à A-4 | `approbations.json` quand l'événement porte une approbation | — |
| 8 | inclusion au registre, bloc certifié par un quorum | R-1 à R-10 (R-3 et R-10 sans effet sur le statut) ; N-4 | `registre.json`, `certificat-commit.json` ; `validateurs.json` facultatif | identifiant de chaîne, adresses des contrats, jeux de validateurs ; clé de chaîne, facultative |

Les vérifications D-1 à A-4 sont celles de CT-1 §11.4, sans changement :

| Groupe | Vérifications | Ce qui est établi |
|---|---|---|
| D | D-1, D-2 | l'index est conforme au schéma et désigne bien l'événement ; chaque fichier présent a le SHA-256 déclaré, chaque partie absente est réellement absente, avec une raison |
| E | E-1 à E-11 | chaque événement du dossier (prouvé, voisins, décisions d'approbation) est conforme au schéma, a une forme canonique JCS v0, est cohérent avec sa sorte, porte un `hash` recalculé égal, une signature Ed25519 valide sous la clé de `cles.json`, un `ts` déclaré dans la période de validité que `cles.json` annonce pour cette clé (ce qui ne date pas la signature), des signatures d'approbateur EIP-191 qui recouvrent les adresses déclarées, et, pour une rotation, une contresignature valide ; avec `--pieces`, les pièces fournies à part ont le `sha256` et la `length` de leur référence |
| C | C-1 à C-3 | l'événement est chaîné à ses voisins immédiats : `seq` contigus, `ts` non décroissants, `prev_hash` égaux aux hachages **recalculés**, clé constante sauf après une rotation |
| M | M-1 à M-3 | la feuille est `SHA-256(0x00 ‖ hash recalculé)`, le chemin d'audit mène à la racine par l'algorithme de la RFC 9162, et cette racine est celle du manifeste |
| P | P-1 à P-5 | le manifeste est conforme, couvre l'événement et ses voisins, et son `periodHash = SHA-256("noortrace/manifeste/v0\n" ‖ JCS(manifeste))` est celui que signe `manifeste.sig` ; avec `--second-manifeste`, les deux manifestes se chaînent (CT-1 §10.3) |
| A | A-1 à A-4 | `approbations.json` est présent si et seulement si l'événement porte une approbation ; décisions cohérentes ; approbateurs distincts, membres du jeu déclaré, au seuil ; `request_hash` recalculé quand l'événement de demande est dans le dossier |

Les **trois ancres portent sur `periodHash`** (CT-6 §9.1, §10.1, §11) : le
jeton RFC 3161 a pour empreinte `periodHash`, la preuve OpenTimestamps a pour
empreinte de fichier `periodHash`, et le registre enregistre `periodHash`
(`PeriodSubmitted`) et `anchorFingerprint = keccak256(org_id ‖ journal_id ‖
periodHash)` (`Anchored`). Le vérificateur recalcule toujours `periodHash`
depuis `manifeste.json` ; il ne le lit jamais dans une autre partie.

- **Contrôle 4** (T-1 à T-11, CT-6 §9) : structure DER stricte du
  `TimeStampToken`, empreinte égale à `periodHash`, attributs signés,
  certificat signataire désigné par `signingCertificate(V2)`, algorithmes admis,
  signature, chemin de certification **à `genTime`** jusqu'à une autorité du
  fichier d'ancres, usage horodatage, contenu de `TSTInfo`, non-révocation par
  une CRL ou une déclaration du fichier d'ancres ; T-11 dit seulement si
  l'énoncé peut écrire « qualifié » (statut déclaré par le réviseur).
- **Contrôle 5** (O-1 à O-7, CT-6 §10) : format `.ots` officiel lu strictement,
  empreinte de fichier égale à `periodHash`, opérations du profil `f0`, `f1`,
  `08` rejouées, résultat égal aux octets 36 à 67 de l'en-tête du bloc attesté,
  chaîne d'en-têtes rattachée au point de contrôle du réviseur, preuve de
  travail recalculée au-dessus de lui, profondeur au moins
  `min_confirmations`.
- **Contrôle 8** (R-1 à R-10, CT-6 §11) : `BFTBlockHash` recalculé depuis
  l'en-tête (ce n'est pas le hachage d'un en-tête Ethereum), racine des reçus
  recalculée sur tous les reçus du bloc, certificat de commit vérifié contre le
  jeu de validateurs **du fichier d'ancres** (jamais celui du dossier ni du
  nœud), identifiant de chaîne et adresses des contrats égaux à ceux de
  l'ancre, `PeriodSubmitted` et `Anchored` égaux aux valeurs du manifeste,
  inscription de la clé du manifeste sous la clé de chaîne qui a signé l'ancre.
- **N-3 et N-4** (CT-6 §12.4) : quand le fichier d'ancres donne une clé
  d'enregistreur sous le triplet (`org_id`, `journal_id`, `key_id`) d'une clé
  de `cles.json` qui signe un événement du dossier ou le manifeste, sa
  `public_key` doit être celle de `cles.json` (N-3, contrôle 6 ; une clé sous
  un autre `key_id` n'est pas comparée). La clé de chaîne de la clé du
  manifeste doit être l'émetteur de l'ancre (N-4, contrôle 8). N-1 et N-2
  (conformité du fichier d'ancres et du fichier d'en-têtes) ne figurent pas
  au rapport : en défaut, l'entrée est inutilisable.

## Statuts, verdict, énoncé

Chaque vérification et chaque contrôle est `reussi`, `echoue` ou `non_execute`
avec une raison de la liste fermée de CT-6 §6.2 : `partie_absente`,
`ancre_absente`, `hors_perimetre_version`, `piece_hors_dossier` (admises) ou
`prerequis_en_echec` (non admise). Une ancre absente n'est **jamais** comptée
comme un succès.

| Verdict | Code | Sens |
|---|---|---|
| `valide` | 0 | aucune vérification en échec ; toute non-exécution a une raison admise |
| `invalide` | 1 | au moins une vérification en échec, ou non exécutée sans raison admise |
| — | 2 | entrée inutilisable : usage, dossier, schémas, fichier d'ancres ou entrée à part illisibles, limite de taille dépassée, erreur interne ; rien n'est affirmé |
| `incomplet` | 3 | comme 0, mais un contrôle exigé par `--exiger` n'a pas réussi |

Les codes 0, 1 et 2 gardent le sens de la version CT-1. Sur les quarante
dossiers de `spec/vecteurs/ct-1/dossiers` (cinq parties absentes avec la raison
« hors périmètre CT-1 »), sans fichier d'ancres ou avec un fichier d'ancres
conforme qui ne donne, pour l'organisation et le journal du dossier, aucune
clé d'enregistreur ou les mêmes clés que `cles.json` (`ancres-test.json` par
exemple), le code de retour et la liste des vérifications en échec sont ceux
de leur `attendu.json` (CT-6 EX-6.14) ; les contrôles 4, 5 et 8 y sont non
exécutés (`hors_perimetre_version`) et le rapport porte une **borne**
(`verdict borné : contrôle 4 non exécuté (…), …`). Un fichier d'ancres non
conforme rend le code 2 ; un fichier d'ancres qui donne, pour le triplet
(`org_id`, `journal_id`, `key_id`) d'une clé de `cles.json` qui signe un
événement du dossier ou le manifeste, une autre `public_key` fait échouer
N-3, donc le contrôle 6, et rend le dossier invalide (code 1) : c'est voulu,
la clé du dossier contredit celle que le réviseur tient pour vraie.

L'**énoncé** (CT-6 §6.5) est la seule phrase à citer : pour un verdict valide,
il dit ce que chaque contrôle réussi établit (l'événement, sa période, ses
clés et leur provenance — `déclarées par le dossier`, `fournies par le fichier
d'ancres` ou `inscrites au registre`, clé par clé quand les deux clés n'ont pas
la même (`facts.recorder_keys.source` vaut alors `mixte`) —, l'approbation,
le refus signé ou la demande expirée selon `approval.decision`, la date au plus tard
selon l'autorité d'horodatage, l'antériorité au bloc Bitcoin, l'inscription au
registre), puis ce qu'il ne prouve pas (`ce dossier ne prouve rien sur sa date
(contrôles 4 et 5) …`). Pour un verdict invalide, il nomme les vérifications
en échec et n'affirme rien sur l'événement. Ce que chaque verdict prouve et ne
prouve pas, phrase par phrase, est à la section 7 de CT-6.

## Ce que le vérificateur ne prouve pas

En bref (détail : CT-6 §7) : que l'événement a eu lieu à l'heure `ts` qu'il
porte ; que l'agent a fait ce que l'événement décrit ; que la clé
d'enregistreur appartient à l'organisation, au-delà de ce que disent les
mentions de l'énoncé (« fournie par le fichier d'ancres » : la clé que le
réviseur déclare, H3 ; « inscrite au registre » : un événement
`RecorderRegistered` émis à l'adresse `recorder_registry` du fichier
d'ancres, qui ne vaut inscription admise par le contrat que sous H7) ; que
les approbateurs étaient habilités ; que l'autorité d'horodatage est
qualifiée (c'est la déclaration du réviseur) ; l'heure précise du bloc
Bitcoin ; une date tirée du registre ; que les blocs du registre sont
authentiques si un quorum de ses validateurs s'est entendu ; que le code aux
adresses des contrats est celui de ce dépôt ; un fait d'état du registre
(appartenance au `CuratorSet`, non-révocation d'une clé).
Tout ce qui vient du dossier est **déclaratif** ; seul le fichier d'ancres est
**de confiance**, et il est préparé par le réviseur.

## Usage

```bash
# dossier complet des vecteurs CT-6, avec les ancres et les en-têtes de test : code 0
node scripts/verify/dossier.mjs spec/vecteurs/ct-6/dossiers/valide-seq-7-complet \
  --ancres spec/vecteurs/ct-6/ancres/ancres-test.json \
  --entetes-bitcoin spec/vecteurs/ct-6/ots/entetes/chaine.json

# le même, en anglais, toutes les vérifications listées
node scripts/verify/dossier.mjs spec/vecteurs/ct-6/dossiers/valide-seq-7-complet \
  --ancres spec/vecteurs/ct-6/ancres/ancres-test.json \
  --entetes-bitcoin spec/vecteurs/ct-6/ots/entetes/chaine.json --langue en --detail

# dossier de CT-1 sans ancres : code 0, verdict borné (4, 5, 8 non exécutés)
node scripts/verify/dossier.mjs spec/vecteurs/ct-1/dossiers/valide-seq-7

# exiger une date et une inscription au registre : code 3 (incomplet)
node scripts/verify/dossier.mjs spec/vecteurs/ct-1/dossiers/valide-seq-7 --exiger 4,5,8

# dossier invalide : code 1, le rapport nomme la vérification en échec (ici E-7)
node scripts/verify/dossier.mjs spec/vecteurs/ct-1/dossiers/invalide-hash-faux

# rapport JSON (schéma spec/schemas/rapport-verification-v0.schema.json)
npm run verify:dossier -- mon-dossier --ancres mes-ancres.json --json > rapport.json
npx --yes ajv-cli@5 validate --spec=draft2020 --strict=true \
  -s spec/schemas/rapport-verification-v0.schema.json -d rapport.json
```

| Option | Rôle |
|---|---|
| `<répertoire>` | le dossier : `dossier.json` et les parties présentes ; tout autre fichier est ignoré |
| `--ancres <fichier>` | fichier d'ancres de confiance du réviseur (`spec/schemas/ancres-confiance-v0.schema.json`, CT-6 §12) ; jamais cherché ailleurs ; sans lui, les vérifications qui exigent une ancre sont non exécutées (`ancre_absente`) |
| `--entetes-bitcoin <fichier>` | chaîne d'en-têtes Bitcoin (`spec/schemas/entetes-bitcoin-v0.schema.json`) ; déclarative, crue seulement par O-5 |
| `--pieces <répertoire>` | pièces nommées par leur `sha256` en hexadécimal minuscule sans `0x` (E-6) |
| `--second-manifeste <fichier>` | manifeste précédent ou suivant du même journal (P-5) |
| `--exiger <contrôles>` | numéros de 1 à 8 séparés par `,`, ou `tous` : un contrôle exigé qui n'a pas réussi rend le verdict `incomplet` (code 3) |
| `--langue fr\|en` | langue du rapport lisible et des textes du rapport JSON (défaut `fr`) ; l'énoncé JSON est toujours donné dans les deux langues |
| `--json` | rapport JSON (`spec/schemas/rapport-verification-v0.schema.json`) au lieu du rapport lisible, y compris pour le code 2 |
| `--detail` | rapport lisible : toutes les vérifications, pas seulement celles qui n'ont pas réussi |
| `--schemas <dir>` | répertoire des schémas (défaut : `spec/schemas`) |
| `--version`, `--aide` | version, environnement et SHA-256 des huit schémas ; aide (code 0) ; exclusives : avec un répertoire, l'une avec l'autre ou avec une autre option que `--langue` et `--schemas`, code 2 (usage ; rapport d'erreur JSON avec `--json`) |

Limites de lecture (CT-6 EX-4.13) : `dossier.json` 1 Mio ; parties JSON de CT-1
16 Mio ; `jeton-rfc3161.der` 64 Kio ; `preuve.ots` 256 Kio ; `registre.json` et
`certificat-commit.json` 64 Mio ; `validateurs.json` 1 Mio ; fichier d'ancres
16 Mio ; fichier d'en-têtes 64 Mio et 200 000 en-têtes ; second manifeste
1 Mio ; pièce 1 Gio ; imbrication JSON 128 niveaux. Une partie au-delà de sa
limite n'est pas lue au-delà : elle est inexploitable et fait échouer la
vérification qui la porte ; une entrée à part au-delà de sa limite rend le
code 2.

Écart avec la version CT-1 de ce script : le libellé des lignes du rapport
lisible (« vérification(s) en échec ») et la sortie JSON, remplacée par le
rapport `rapport-verification-v0` (`verdict`, `failed_checks`,
`blocking_unexecuted`, `controls`, `checks`, `statement`, `bound`…), comme
CT-6 EX-6.14 le prévoit ; les codes de retour et la liste des vérifications en
échec ne changent pas.

## Vecteurs

`spec/vecteurs/ct-1/dossiers/` (générés par `npm run vecteurs:ct1`, décrits dans
`spec/vecteurs/ct-1/INDEX.md` et CT-1 §11.5) porte deux dossiers valides (l'appel
relayé seq 7, la décision seq 6) et, pour chaque contrôle de CT-1 §11.4, au
moins un dossier qui le fait échouer, chacun avec son `attendu.json`.
`test/journal.test.js` rejoue chacun avec la bibliothèque et avec cette ligne de
commande ; le vérificateur indépendant Go de
`spec/vecteurs/ct-1/verificateur-independant` les confronte tous.

`spec/vecteurs/ct-6/` (générés par `npm run vecteurs:ct6`, décrits dans
`spec/vecteurs/ct-6/INDEX.md` et CT-6 annexe A) porte les jetons, preuves,
chaînes d'en-têtes et parties du registre des contrôles 4, 5 et 8, les
fichiers d'ancres de test (`ancres/`) et les dossiers complets (`dossiers/`) :
`valide-seq-7-complet` (le dossier de CT-1 complété des cinq parties, les huit
contrôles réussis) et ses variantes, une par vérification T-, O-, R-, N-3 et
N-4, chacune avec son `attendu.json` (vérifications en échec, statut des huit
contrôles, non-exécutions, avertissements dans l'ordre de CT-6 EX-6.15, code,
énoncé et borne dans les deux langues, fichier d'ancres et d'en-têtes à
employer), ainsi que les dossiers de décision refusée et expirée
(`valide-decision-refusee`, `valide-decision-expiree`). `test/verificateur.test.js`
rejoue chacun par cette ligne de commande, valide chaque rapport JSON contre son
schéma, reconstruit l'énoncé du dossier complet fragment par fragment et
vérifie la génération déterministe. `spec/vecteurs/ct-6/confrontation/`
porte la confrontation des vecteurs par OpenSSL, python-opentimestamps et
go-ethereum (CT-6 annexe A.8), que `test/confrontation.test.js` relie aux
vecteurs. Les clés RSA de `rfc3161/cles/` sont publiques et réservées aux
tests.
