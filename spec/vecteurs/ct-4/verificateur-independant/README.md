# Vérificateur indépendant CT-4 (Go, salle blanche)

Un second vérificateur des vecteurs de [CT-4](../../../CT-4-registre.md),
écrit en Go depuis la seule spécification (CT-4, et ce qu'elle cite de CT-1
§9 et §10 et de CT-6 §11 et §12) et les schémas qu'elle désigne
(`instance-registre-v0`, `inscription-client-v0`, `operations-registre-v0`,
et `registre-v0` et `validateurs-v0` de CT-6 pour les parties exportées),
sans lire ni reprendre le code JavaScript de `scripts/` ni de `test/`. Il
recalcule chaque valeur que les vecteurs de `spec/vecteurs/ct-4` déclarent,
famille par famille selon l'annexe A, et la confronte à l'attendu. Deux
implémentations écrites séparément qui tombent sur les mêmes octets et les
mêmes verdicts RG- rendent les vecteurs probants ; une discordance désigne
une ambiguïté de la spécification ou une faute de l'une des deux (CT-4 §0,
EX-A.5).

Module propre `noortrace-ct4` (`go 1.24`), **bibliothèque standard
uniquement** : aucun `go.sum`, aucun accès au réseau, et le réseau de
développement n'est jamais lancé. Trois fichiers reprennent du code du
vérificateur indépendant de CT-3, ce qu'EX-A.5 permet, en le disant en
tête : `keccak.go` (Keccak-256 de l'EVM), `secp256k1.go` (courbe en
`math/big`, recouvrement SEC 1 §4.1.6, signature RFC 6979) et `json.go`
(analyseur strict qui garde l'ordre des membres et le texte des nombres).
Tout le reste est écrit ici : BIP-39 et BIP-32, RLP, ABI de 6.7.2, trie
Merkle-Patricia et bloom des reçus, `BFTBlockHash`, hachage d'un jeu de
validateurs, lecture et vérification des enveloppes du certificat de commit,
JCS v0, validateur JSON Schema 2020-12 réduit aux mots-clés des schémas.

## Usage

```bash
cd spec/vecteurs/ct-4/verificateur-independant
go run . ..                       # rapport texte
go run . -v ..                    # liste aussi chaque valeur concordante et hors périmètre
go run . -json .. > rapport.json  # rapport complet en JSON
go build -o verificateur . && ./verificateur ..
gofmt -l . ; go vet ./... ; go test ./...
```

`go build` sans `-o` produit `noortrace-ct4` ; `noortrace-ct4` et
`verificateur` sont exclus par le `.gitignore` local.

Entrées lues, jamais écrites : les vecteurs du répertoire donné ; les
schémas `../../schemas/*.schema.json` ; le texte `../../CT-4-registre.md`
(tables, exemples imprimés, exemples annotés) ; les manifestes et
`attendu.json` de `../ct-1/manifestes/` ; la capture unique
`../ct-6/registre/capture/` et les parties `../ct-6/registre/periode-1/` ;
`chain/config/alloc-dev.json` du dépôt. `test/fixtures/` n'est pas lu : le
jeu de validateurs du réseau de développement est pris dans l'exemple de
manifeste de 4.8 (« copie publique
test/fixtures/certificat-commit/validators.json ») et confronté au
`validators.json` de la capture de CT-6.

Codes de retour (EX-A.5) : `0` tout concorde (les valeurs hors périmètre
sont énoncées avec leur raison et ne comptent pas) ; `1` au moins une
discordance, listée avec l'attendu, la valeur recalculée et la phrase de la
spécification qui fonde le calcul ; `2` usage incorrect ou racine
introuvable.

Le rapport imprime, par famille puis au total, le nombre de cas, de valeurs
recalculées, concordantes, discordantes et hors périmètre, puis
« Résultat : tout concorde. » ou la liste des discordances.

## Ce qui est recalculé

| Famille | Fichiers lus | Valeurs recalculées et confrontées |
|---|---|---|
| texte | `CT-4-registre.md` | sélecteurs de 6.7.1 (keccak256 des signatures), `topics[0]` de 5.7, sélecteurs des erreurs de 5.8, `docType` de 6.4, `org_id` et `journal_id` de 6.2 et 6.3, octets et longueurs des étiquettes et des préimages de 6.6.2, `op` des opérations d'un `CuratorSet`, préfixe EIP-191 et `n/2` de 6.6.3 ; exemples de 6.5 et 6.6.4 recalculés depuis les transactions réelles de la capture de CT-6 (`E(meta)` mot par mot, `periodDigest`, `anchorDigest`, `registerDigest`, `revokeDigest`, `adminOpDigest`, hachages signés, signataires recouvrés) ; EX-6.17 (644, 196 et 388 octets, tête de la clôture) ; exemple de 6.7.3 resigné par RFC 6979 (charge, hachage, `yParity`, `r`, `s`, 302 octets, hachage, RG-15) ; ligne de règles d'EX-4.3 recalculée sur `chain/config/alloc-dev.json` ; table du quorum de 4.4 ; provision d'EX-4.19 et d'EX-4.20 ; fenêtres de 9.5, EX-9.7 et EX-4.27 ; chaque exemple annoté validé contre son schéma, et ceux de 4.8, 7.7, 7.10 et 9.4 égaux aux fichiers des vecteurs qui les reprennent ; SHA-256 des fichiers de la capture de CT-6 que l'index de 9.4 déclare |
| constantes | `constantes.json` | comptes Hardhat 0 à 4 dérivés de la mnémonique (BIP-39, BIP-32, `m/44'/60'/0'/0/i`) et leurs adresses ; clés de graine SHA-256(UTF-8(…)) des clés de chaîne, des validateurs d'essai, des comptes de l'instance de production et des exemples, leurs adresses et clés publiques ; clés Ed25519 des graines ; `org_id`, `journal_id` ; adresses des contrats (table de 5.3 et `CREATE(déployeur, nonce)`) ; hachages des deux jeux (CT-6 EX-11.8) ; SHA-256 de la genèse ; `periodHash` des trois manifestes de CT-1 (CT-1 §10.2) ; manifeste d'exemple de A.2 (racine RFC 6962 des trois événements, nonce, `periodHash`, empreinte) ; frais par défaut ; transactions de la capture relues dans les propositions (hachage, nonce, frais, limite, expéditeur, événement du rôle) |
| identifiants | `identifiants.json` | RG-1 (grammaire, forme de production) et RG-2 ; `org_id`, `journal_id` |
| doctypes | `doctypes.json` | RG-3 dans les deux sens (libellé → valeur, valeur → libellé, valeur nulle) |
| empreintes | `empreintes.json` | RG-4 : préimage de 96 octets, empreinte ; `periodHash` recalculé du manifeste de CT-1 désigné et empreinte égale à `anchor_fingerprint` de son `attendu.json` ; empreintes déclarées des refus reproduites depuis leur description |
| condenses | `condenses.json` | RG-5 (bornes, période vide, uri, continuité ; `PeriodMeta` tiré champ pour champ du manifeste de CT-1) ; RG-6 à RG-11 (préimage, longueur, condensé, hachage signé ; condensés déclarés des refus reproduits : autre chaîne, autre contrat, `registeredAt + 1`, étiquette d'ancre, nonce 1) ; `registeredAt` égal à l'horodatage du bloc de l'inscription dans la capture ; RG-12 (hachage signé, forme canonique, recouvrement, 65 octets) ; RG-13 ; chaque signature valide **reproduite octet pour octet** par la clé de son signataire (RFC 6979) ; signatures des cinq opérations au seuil égales à celles des transactions réelles (EX-A.4) |
| appels | `appels.json` | RG-14 : données d'appel de 6.7.2, longueurs de la table, arguments des constructeurs ; pour chaque transaction de la capture, donnée égale à celle de la transaction réelle lue dans `txsRaw` du certificat capturé (EX-A.4) |
| transactions | `transactions.json` | chaque transaction resignée depuis ses champs et sa clé (RFC 6979) : charge signée, hachage, `yParity`, `r`, `s`, octets, hachage, expéditeur ; transactions de la capture égales octet pour octet aux transactions réelles ; RG-15 sur les octets (type, chaîne, frais et remplacement `⌈1,1 × p⌉`, limite, liste d'accès, signature, objet, données relues et réécrites selon RG-14) ; expéditeur recouvré des formes non protégée, à liste d'accès et à `s` haut |
| manifestes | `manifestes/` | RG-16 (schéma, horodatages existants, chaînage des révisions), RG-17 (SHA-256 et forme de la genèse, section `rules` d'EX-4.2, ligne de règles, identifiants, somme des soldes), RG-18 (chargement des jeux, hachage, opérateurs, intervalles, domaines de panne en production), RG-19 (`CREATE`, arguments d'EX-5.2, contrats en service, preuves : SHA-256 et rôle de l'index, CP-2, CP-3, CP-4 et CP-6 sur les blocs de déploiement synthétiques signés par le jeu d'essai, statut du reçu, transaction sans destinataire signée par le déployeur au nonce déclaré, racine des transactions), RG-20 (ancre `registry` dérivée, comparée à l'ancre fournie) ; verdict de chaque RG-, première vérification en échec, ancre dérivée hors `source` |
| demandes | `demandes/` | schéma `demande_signature`, OP-6 (condensé recalculé depuis `fields`, `evm_chain_id` et `contract`, hachage signé), OP-7 ; condensé et signataires attendus ; signatures reproduites ; hachage de bloc synthétique de `signer_set` de l'exemple de 7.7 |
| inscription | `inscription/` | schéma `inscription-client-v0`, OP-4 ; `org_id` ; instance du réseau de développement (EX-7.2), provision `P_k` (EX-4.19), trésorerie ; pour l'exemple de 7.10, hachages de bloc et de transaction synthétiques, noms des index de capture, `curator_set`, `approver_set`, `set_read`, références des étapes reprises dans `result` |
| capture | `capture/` | CP-2 (`BFTBlockHash`, hauteur, hachage du reçu et de l'index), CP-3 (un reçu par transaction dans l'ordre, racine des reçus, transaction à son indice), CP-4 hors ligne (lignes de la proposition et des precommits, condensés, signatures, quorum, identifiant BFT, hauteur, bloc, `txsRaw`, racine des transactions), CP-5 (émetteur, `topics[0]` du rôle, disposition de CT-6 EX-11.9), CP-6 (schéma et nom de l'index, noms des réponses, SHA-256, réponses JSON-RPC complètes) ; export de la période 1 (EX-9.8 à EX-9.10) égal en valeurs JSON, hors `source`, aux parties de `../ct-6/registre/periode-1`, conforme aux schémas de CT-6, entrées choisies selon EX-9.8 |
| format | tous les `*.json`, `INDEX.md` | octets = `JSON.stringify(valeur, null, 2)` suivi d'un saut de ligne (EX-A.1), hors réponses JSON-RPC brutes (CP-6) et copies de `alloc-dev.json` (contrôlées par leur SHA-256) ; chaque cas présent dans `INDEX.md` |
| couverture | les issues recalculées | EX-A.3 : RG-1 à RG-20, OP-4, OP-6, OP-7, CP-2 à CP-6 ont chacune au moins un cas qui réussit et un cas qui échoue sur elle |

## Ce qui n'est pas recalculé (hors périmètre)

- **Motifs d'échec des RG-** (`slug_invalide`, `frais_non_conformes`…) : la
  table de 6.9 fixe pour chaque RG- ses motifs ; ce vérificateur confronte la
  vérification en échec, pas encore son motif (une version suivante le
  fera). Même chose pour les codes d'OP-7 que 7.11 attache aux signataires
  non rangés, en double ou dont la signature ne recouvre pas `signer`
  (`signature_non_canonique`) et à un émetteur autre que la clé de chaîne
  (`signataire_hors_jeu`), et pour `entree_illisible`, que 7.11 rattache à la
  première vérification d'OP-6 (demandes) ou d'OP-4 (dossiers) sur un
  document non conforme à son schéma.
- `source` des ancres `registry` dérivées (« à la discrétion du réviseur »,
  RG-20) ; `INDEX.md`, résumé généré ; code de création synthétique ;
  hauteur et hachage de bloc de `signer_set` des demandes de A.2 (lecture du
  jeu à la tête, bloc non capturé) ; SHA-256 du binaire et du correctif de
  noorcore (artefacts hors du dépôt public) ; expéditeur d'une enveloppe
  illisible (cas `illisible` de `transactions`, RG-15 `echoue`).

## Lectures retenues là où le texte laisse un choix

- **Manifeste non conforme au schéma** : ce n'est pas un manifeste ; RG-17 à
  RG-20 échouent avec RG-16 et aucune ancre n'est rendue (6.8, EX-6.19).
  L'ancre `registry` dérivée n'est rendue que si RG-20 réussit (EX-6.23) ;
  avec une ancre fournie, RG-20 la compare à l'ancre dérivée, membres
  `source` exceptés ; un nom sans contrat en service ou avec plusieurs rend
  la dérivation impossible (6.9).
- **CP-2 à CP-6** suivent la table de 9.4 : CP-2 compare `hash` et `number`
  de l'en-tête à `block_hash` et `block_number` de l'index et au `blockHash`
  du reçu de la transaction capturée ; CP-3 lit la correspondance d'un reçu
  à sa transaction dans le reçu (`transactionHash` du reçu de rang i égal au
  hachage de rang i de l'en-tête) ; CP-4 exige que `validator_set_hash` de
  l'index soit le hachage du jeu employé ; CP-5 : rôles à événement et
  événement attendu selon OP-11 ; CP-6 juge les noms des fichiers, dont
  `recu-<hachage de transactions[i]>.json`.
- **OP-4** : hors lecture d'état, les codes sont `jeu_invalide` et, en
  production, `cle_invalide` pour une classe de garde D ; **OP-7**
  s'exécute dans l'ordre de son texte (forme, recouvrement, distinction,
  ordre, appartenance, seuil, émetteur).
- **Lignes du certificat** (CT-6 EX-11.6) : tolérance du décodeur du nœud
  décrite par `scripts/verify/README.md` (noms de membres sans la casse,
  dernière occurrence gagnante, base64 standard tolérant, hachage du corps en
  toute casse, `Voter` ou `proposer` vide admis) ; les noms des membres de
  l'enveloppe et des corps sont ceux de CT-4 9.2 et de CT-6 EX-11.14, et
  ceux que portent les lignes capturées.
- **Motifs ECMAScript** : `raw_transaction` est borné par `maxLength` dans
  le schéma ; par précaution, une répétition bornée au-delà de 1000, que RE2
  refuse, perdrait sa borne haute à la traduction.

## Tests du module (`go test`)

- Keccak-f[1600] confronté à `crypto/sha3` (SHA3-256), `keccak256("")` ;
  RLP (encodages connus, refus des formes non minimales et tronquées) ; racine
  d'un trie vide ; `BFTBlockHash` de l'exemple de CT-6 EX-11.4 (bloc 8316).
- Compte Hardhat 0 dérivé de la mnémonique, son adresse, `CREATE` de 5.3 ;
  signature RFC 6979 puis recouvrement ; forme à `s` haut refusée ; signataire
  de la seconde signature de 6.6.4.
- `periodHash` et `anchorFingerprint` de l'exemple de CT-1 §10.1 et §10.4 ;
  cas limites de JCS v0 ; `JSON.stringify(…, null, 2)`.
- Conventions (slug de production, libellé hors table, ordre de RG-13,
  longueurs de 6.7.2, quorum) ; refus du validateur de schémas (valeur non
  conforme, mot-clé inconnu).
- Tolérance et refus du lecteur de lignes (casse admise, nom de membre
  différent, precommit en double, quorum manquant, autre jeu).
- Chaque variante des manifestes et des captures échoue pour la raison que
  décrit son cas ; une valeur attendue altérée d'un chiffre dans une copie
  des vecteurs est relevée comme discordance avec sa règle.
- Les vecteurs publiés : aucune discordance, sans tolérance.

## Écarts relevés entre la spécification et les vecteurs publiés

Confrontation du 2026-10-25, après la revue de la porte 1 : 815 cas, 2 147
valeurs recalculées, 2 147 concordantes, **0 discordante**, 158 hors
périmètre (listées avec leur raison par `go run . -v ..`).

Les trois discordances de la confrontation précédente (cas
`cp3-recu-autre-nom` : le reçu identique octet pour octet désigné sous un
autre nom, que les vecteurs jugeaient sous CP-3 et ce vérificateur sous
CP-6) sont réglées en faveur du texte de 9.4 : le nom `recu-<hachage>.json`
relève de CP-6 et la correspondance d'un reçu à sa transaction se lit dans le
reçu (CP-3) ; le cas attend CP-6 `echoue`, et le cas `cp3-recu-autre-transaction`
exerce CP-3. Les trois hachages de transaction de l'exemple de 7.10 se
recalculent désormais depuis le `step` de l'étape, comme 7.10 l'écrit.
