# chain/docker/ — image conteneur du nœud noorcore

Ce répertoire livre le nœud noorcore de NOORTRACE sous forme d'image conteneur :
le même binaire que `chain/runtime/bin/noorcore` (commit épinglé de
noorchain-core, `go build ./core`), dans une image minimale sans shell, lancé par
un utilisateur non root, et dont **tous** les drapeaux viennent de la commande.
Il contient aussi la mesure, faite sur le réseau de développement, de ce qu'un
nœud **suiveur** (`-role follower -follow-rpc …`) fournit réellement à qui
l'exploite chez lui — et de ce qui lui manque pour être une copie indépendante
de la chaîne.

| Fichier | Rôle |
|---|---|
| `Dockerfile` | construction multi-étapes : Go épinglé → binaire → image distroless |
| `docker-compose.yml` | exemple d'un suiveur en conteneur |
| `README.md` | ce document |

Rien ici ne touche à `chain/scripts/` ni au réseau de développement : l'image
est un emballage du même binaire, pas une autre chaîne.

## Construction

```bash
# depuis la racine du dépôt ; commit par défaut : 618fcef8805ef5b4cb9291a3dd97be710e489297,
# plus les correctifs déposés dans chain/patches/ (fournis hors dépôt, voir son LISEZMOI) ; le contexte
# de construction est chain/ pour que l'image les voie
docker build -f chain/docker/Dockerfile -t noortrace/noorcore:618fcef-noortrace chain

# un autre commit de noorchain-core
docker build -f chain/docker/Dockerfile --build-arg NOORCORE_COMMIT=<sha complet> -t noortrace/noorcore:<étiquette> chain

# vérification de la syntaxe et des règles BuildKit, sans construire
docker build --check -f chain/docker/Dockerfile chain
```

Ce que fait le `Dockerfile` :

1. **Étape `build`**, depuis `golang:1.26.9-bookworm` : la version de Go est celle
   qu'impose le `go.mod` de noorchain-core (`go 1.26.9`) ; `GOTOOLCHAIN=local`
   interdit tout téléchargement d'une autre chaîne de compilation, un `go.mod` qui
   demanderait plus récent fait échouer la construction. Clone à profondeur 1 du
   commit `NOORCORE_COMMIT` (un commit, pas une branche), vérification que la tête
   est bien ce commit, puis `go build -trimpath -o … ./core` avec cgo (comme le
   binaire de `chain/runtime/bin/`). Les caches de modules et de compilation sont
   des montages BuildKit, jamais copiés dans l'image.
2. **Image finale** `gcr.io/distroless/base-debian12:nonroot` : Debian 12 comme
   l'étape de construction (même glibc, le binaire y est lié parce que la
   cryptographie secp256k1 de go-ethereum passe par cgo), autorités TLS et tzdata,
   ni shell ni gestionnaire de paquets. Binaire en `/usr/local/bin/noorcore`,
   volume `/var/lib/noorcore` (créé vide, propriété de 65532:65532), utilisateur
   `65532:65532` (`nonroot`), `ENTRYPOINT ["/usr/local/bin/noorcore"]`, **pas de
   `CMD`**.

Pourquoi aucun mode par défaut : noorcore lancé sans drapeaux démarre une chaîne
locale de banc d'essai (rôle `follower` sans `-follow-rpc`, chaîne 2121, données
dans `./data`, `core/config/config.go`). Dans un conteneur ce serait un nœud qui
produit des blocs pour personne. Les drapeaux viennent donc toujours de la
commande (`docker run … image -chain-id …`).

Arguments de construction :

| Argument | Défaut | Rôle |
|---|---|---|
| `GO_VERSION` | `1.26.9` | étiquette de l'image Go ; à ne changer qu'avec le `go.mod` |
| `NOORCORE_REPO` | `https://github.com/noorfinances-eng/noorchain-core.git` | dépôt cloné |
| `NOORCORE_COMMIT` | `618fcef8805ef5b4cb9291a3dd97be710e489297` | commit de noorchain-core construit, après application des correctifs de `chain/patches/` |

Secrets BuildKit facultatifs, jamais écrits dans une couche :

- `github_token` : le dépôt noorchain-core est **privé** ; là où le clone anonyme
  est refusé, passer un jeton d'accès en lecture :
  `docker build --secret id=github_token,src=/chemin/jeton …`. Il n'est utilisé que
  dans l'en-tête HTTP de la commande `git fetch`.
- `ca_bundle` : uniquement derrière un mandataire d'entreprise qui réécrit TLS,
  l'autorité à faire confiance (pour `git` et pour `go`), sans jamais désactiver la
  vérification : `--secret id=ca_bundle,src=/chemin/ca.pem`. Avec un tel
  mandataire, passer aussi `--build-arg HTTPS_PROXY=… --build-arg NO_PROXY=…` et,
  s'il écoute sur la boucle locale de l'hôte, `--network host`.

### Construction vérifiée le 21 octobre 2026

- `docker build --check chain/docker` : `Check complete, no warnings found.`
- Variante avec correctifs (contexte `chain/`, `COPY patches/`, `git apply`), le soir du
  21 octobre : `docker build --check -f chain/docker/Dockerfile chain` sans avertissement ;
  la construction complète n'a pas pu être rejouée, Docker Hub ayant répondu
  `429 Too Many Requests` à la résolution de `golang:1.26.9-bookworm` à deux reprises.
  Le même enchaînement, clone du commit épinglé puis `git apply` puis `go build`, a été
  rejoué avec succès par `chain/scripts/build-noorcore.sh --force` (33 s, méthode
  présente dans le binaire). À rejouer dès que le registre répond.
- `docker build … -t noortrace/noorcore:618fcef chain/docker` (Docker 29.8.2,
  BuildKit) : clone et vérification du commit en 2,8 s (`noorchain-core au commit
  618fcef8805ef5b4cb9291a3dd97be710e489297, go 1.26.9`), `go version go1.26.9
  linux/amd64`, téléchargement des modules et `go build` en 58,5 s ; image finale
  **67,5 Mo** sur disque (20,3 Mo de contenu compressé), `User=65532:65532`,
  `Entrypoint=["/usr/local/bin/noorcore"]`, `Cmd=null`, volume `/var/lib/noorcore`.
- Images de base résolues à cette date : `golang:1.26.9-bookworm@sha256:d9c68c2c…641453c`,
  `gcr.io/distroless/base-debian12:nonroot@sha256:7f0c72cd…061567e5` (étiquettes
  épinglées dans le `Dockerfile`, condensés notés ici pour la reproductibilité).
- L'environnement de construction passait par un mandataire d'entreprise : la
  construction a utilisé `--network host --build-arg HTTPS_PROXY=… --build-arg
  NO_PROXY=… --secret id=ca_bundle,src=…` ; le dépôt privé a été cloné sans jeton
  parce que ce mandataire porte l'authentification GitHub. Ailleurs, passer
  `--secret id=github_token,src=…`.
- Conteneur lancé en suiveur contre le réseau de développement (`--network host
  --read-only`, drapeaux de la section « Exécution en suiveur », RPC `127.0.0.1:8658`) :
  `eth_chainId` → `0x84c`, `eth_blockNumber` → `0x2669` **égal au leader au même
  instant**, `/healthz` → `ok`, processus `noorcore` sous l'utilisateur `65532`,
  `ReadonlyRootfs=true` ; volume rempli de `db/` et `oprec/` propriété 65532 ;
  `docker stop` → `node stopped`, `NOORCHAIN 2.1 — shutdown clean` ; conteneur et
  volume supprimés ensuite.

## Exécution en validateur

Un validateur a besoin, dans le volume ou dans des montages en lecture seule, du
matériel que `chain/scripts/dev-net.sh` génère au premier `start` :
`validators.json` (clés publiques des quatre validateurs), sa clé privée
secp256k1 (`nodeN.key`, mode 0600, propriété de 65532), et le document de genèse
`chain/config/alloc-dev.json`. Les drapeaux sont ceux de `dev-net.sh`
(`lancer_noeud`) ; seul le réseau change.

```bash
docker run -d --name noorcore-v1 --network host \
  -v noorcore-v1:/var/lib/noorcore \
  -v "$PWD/chain/runtime/validators.json:/etc/noorcore/validators.json:ro" \
  -v "$PWD/chain/runtime/keys/node1.key:/etc/noorcore/validator.key:ro" \
  -v "$PWD/chain/config/alloc-dev.json:/etc/noorcore/alloc.json:ro" \
  noortrace/noorcore:618fcef-noortrace \
    -chain-id noortrace-2124-dev -evm-chain-id 2124 \
    -data-dir /var/lib/noorcore \
    -role leader -consensus bft \
    -validator-id v1 -validators-file /etc/noorcore/validators.json \
    -validator-key-file /etc/noorcore/validator.key \
    -alloc-file /etc/noorcore/alloc.json \
    -p2p-addr 127.0.0.1:31400 -boot-peers 127.0.0.1:31401,127.0.0.1:31402,127.0.0.1:31403 \
    -rpc-addr 127.0.0.1:8645 -health-addr 127.0.0.1:8745 -metrics-addr 127.0.0.1:9645 \
    -network-profile dev
```

- Quatre validateurs au minimum (`core/node/node.go` : « bft: validator set size
  < 4 not supported »), un seul `-role leader`, les autres `-role follower` **sans**
  `-follow-rpc` : ce rôle-là ne change que le routage RPC, pas le consensus (ils
  servent leur propre état, comme node2 à node4 du réseau de développement).
- Réseau ponté au lieu de `--network host` : écouter sur `0.0.0.0` exige
  `-allow-public-bind` (`core/main.go`, `validateBindSafety`), et, dès que le
  profil n'est plus `dev`, un port p2p public exige `-p2p-require-auth` avec un
  jeton d'au moins 32 caractères (`NOOR_P2P_AUTH_TOKEN`) **et** `-p2p-tls` avec
  certificat et clé (`validateP2PHardeningProfile`).
- Profil `testnet`, `mainnet` ou `prod-like` : `-bft-allow-experimental` est
  obligatoire, `-validator-key-file` aussi (pas de clé en ligne de commande), et
  les fichiers secrets doivent être en mode 0600 (`validateBFTProductionGuard`,
  `validateSecretFilePermissions`).
- Un arrêt propre est `docker stop` (SIGTERM : l'état de consensus est persisté).
  Un arrêt brutal laisse un marqueur de reprise qui fait refuser le redémarrage ;
  en profil `dev` seulement, `-bft-recovery-reset` l'efface sur geste explicite.

## Exécution en suiveur

```bash
# contre le réseau de développement (validateurs sur 127.0.0.1 de l'hôte)
docker run -d --name noorcore-suiveur --network host --read-only \
  -v noorcore-suiveur:/var/lib/noorcore \
  noortrace/noorcore:618fcef-noortrace \
    -chain-id noortrace-2124-dev -evm-chain-id 2124 \
    -data-dir /var/lib/noorcore \
    -role follower -follow-rpc http://127.0.0.1:8645 \
    -rpc-addr 127.0.0.1:8655 -health-addr 127.0.0.1:8755 -metrics-addr 127.0.0.1:9655 \
    -p2p-addr 127.0.0.1:31410 \
    -network-profile dev

curl -s http://127.0.0.1:8655 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'
```

`docker-compose.yml` montre la variante en réseau ponté : le nœud écoute sur
`0.0.0.0` à l'intérieur du conteneur (`-allow-public-bind`), Docker ne publie les
ports que sur `127.0.0.1` de l'hôte, le leader est désigné par
`NOORCORE_LEADER_RPC` (défaut `http://host.docker.internal:8645`), le système de
fichiers est en lecture seule hors du volume, toutes les capacités sont retirées.

```bash
NOORCORE_LEADER_RPC=https://rpc.exemple.ch docker compose -f chain/docker/docker-compose.yml up -d
```

Un suiveur n'a besoin ni de `validators.json`, ni de clé, ni de document de
genèse : il ne participe pas au consensus et ne rejoue rien (section suivante).
`-evm-chain-id` doit néanmoins être **le bon** : `eth_chainId` est répondu
localement à partir de ce drapeau, pas relayé (mesuré plus bas).

## Volumes

| Chemin dans le conteneur | Contenu | Remarque |
|---|---|---|
| `/var/lib/noorcore` | `db/leveldb/` (chaîne, consensus, certificats `cert/v1/…`, index des transactions), `db/geth/` (état EVM), `oprec/oprec.jsonl` (journal d'exploitation, rotation 16 × 16 Mio) | déclaré `VOLUME` ; propriété 65532:65532. Un montage lié (`-v /srv/noorcore:/var/lib/noorcore`) doit appartenir à 65532 sur l'hôte : `chown 65532:65532 /srv/noorcore` |
| `/etc/noorcore/…` (convention) | `validators.json`, clé privée, document de genèse | montages en lecture seule, validateur seulement ; la clé en mode 0600 et propriété 65532 |

Le nœud n'écrit que sous `-data-dir` : `--read-only` fonctionne (vérifié).

## Ports

Les adresses d'écoute viennent des drapeaux ; `EXPOSE` dans le `Dockerfile` n'est
qu'une documentation. Valeurs du réseau de développement pour repère :

| Service | Drapeau | Défaut du binaire | dev-net (node1) | Suiveur de test |
|---|---|---|---|---|
| JSON-RPC HTTP | `-rpc-addr` | désactivé si absent | `127.0.0.1:8645` | `127.0.0.1:8655` |
| Santé `/healthz` | `-health-addr` | `127.0.0.1:8080` | `127.0.0.1:8745` | `127.0.0.1:8755` |
| Métriques Prometheus `/metrics` | `-metrics-addr` | désactivé si absent | `127.0.0.1:9645` | `127.0.0.1:9655` |
| P2P BFT | `-p2p-addr` | `127.0.0.1:30303` | `127.0.0.1:31400` | `127.0.0.1:31410` (écoute, inutilisé) |

Dans `docker-compose.yml` : 8545, 8080, 9090 à l'intérieur, publiés sur
`127.0.0.1` de l'hôte.

## Variables d'environnement

Lues par le binaire (`core/main.go`, `core/config/`) ; toutes facultatives :

| Variable | Effet |
|---|---|
| `NOOR_HTTP_AUTH_TOKEN` | jeton Bearer exigé sur RPC, `/healthz` et `/metrics` (équivalent de `-http-auth-token`) |
| `NOOR_RPC_TRUSTED_PROXIES` | CIDR dont `X-Forwarded-For` / `X-Real-IP` désignent le client pour la limitation de débit (équivalent de `-rpc-trusted-proxies`) ; vide = jamais |
| `NOOR_RPC_MAX_BLOCK_RANGE` | plafond d'intervalle de blocs d'`eth_getLogs` (défaut 16384) |
| `NOOR_BFT_CERT_RETENTION_HEIGHTS` | rétention des certificats de commit (défaut 300 000 hauteurs) ; validateurs seulement |
| `NOOR_P2P_AUTH_TOKEN` | jeton AUTH partagé du maillage p2p (équivalent de `-p2p-auth-token`) ; validateurs seulement |
| `NOOR_P2P_REQUIRE_CHAIN_ID=1` | évince un pair qui n'annonce pas d'identité de chaîne |
| `NOOR_POSS_*`, `NOOR_ACCEPT_NEW_EMISSION_PARAMS` | règles d'émission PoSS, gravées au premier démarrage et vérifiées ensuite ; **ne pas les poser** pour NOORTRACE (chaîne sans émission, voir `chain/README.md` et `dev-net.sh` qui les efface) |

Aucun drapeau n'a d'équivalent `NOORCORE_*` : la commande du conteneur est la
seule configuration du nœud.

## Ce qu'un suiveur fournit aujourd'hui

Mesures du 21 octobre 2026 sur le réseau de développement (quatre validateurs,
leader `127.0.0.1:8645`, hauteur ≈ 9 200), avec le binaire
`chain/runtime/bin/noorcore`. Trois suiveurs de test lancés avec un `-data-dir`
temporaire : **A** `-follow-rpc http://127.0.0.1:8645` (RPC `127.0.0.1:8655`),
**B** `-follow-rpc http://127.0.0.1:1` (port fermé : leader injoignable, RPC
`8656`), **C** comme A mais `-evm-chain-id 2125` (faux, RPC `8657`). Les
validateurs n'ont pas été touchés.

### Ce que fait le code (`core/node/loop_follower.go`, `core/rpc/jsonrpc_dispatch.go`)

- La boucle suiveur envoie `eth_blockNumber` au leader **une fois par seconde**,
  garde le maximum vu dans `n.height` et écrit une ligne `tick | height: … |
  follower: true`. Elle ne lit aucun bloc, aucune transaction, aucun état, aucun
  certificat.
- Le serveur RPC consulte une table de routage `ethRouting`. Dès que `FollowRPC`
  est non vide : les méthodes `routeLeaderOnly` sont **relayées** telles quelles au
  leader (`proxyToLeader` : un `POST` HTTP de la requête, la réponse est décodée
  puis ré-encodée) ; `routeLocalThenProxy` (`eth_getTransactionReceipt`,
  `eth_getTransactionByHash`) répond localement si trouvé, sinon relaie ;
  `routeLocal` répond localement. Relayées : `eth_blockNumber`, `eth_syncing`,
  `eth_getBalance`, `eth_getCode`, `eth_getStorageAt`, `eth_call`,
  `eth_getTransactionCount`, `eth_sendRawTransaction`, `eth_getBlockByNumber`,
  `eth_getBlockByHash`, `eth_getLogs`, les filtres, `eth_feeHistory`,
  `eth_getBlockReceipts`, les méthodes par index et oncles, et
  `noor_getCommitCertificate`. Locales : `eth_chainId`, `net_version`,
  `web3_clientVersion`, `eth_gasPrice`, `eth_maxPriorityFeePerGas`,
  `eth_estimateGas`, `eth_accounts`, `eth_protocolVersion`, `noor_txindexStatus`.
- Si le leader ne répond pas : `{"code":-32000,"message":"leader unreachable"}`.

### Mesures, mot pour mot

`eth_chainId` — identique sur les trois (local) :

```
8645: {"jsonrpc":"2.0","id":1,"result":"0x84c"}
8655: {"jsonrpc":"2.0","id":1,"result":"0x84c"}
8656: {"jsonrpc":"2.0","id":1,"result":"0x84c"}
```

Suiveur **C** (`-evm-chain-id 2125`, leader 2124) — `eth_chainId` ment, parce qu'il
est répondu depuis le drapeau local et non relayé :

```
C eth_chainId: {"jsonrpc":"2.0","id":1,"result":"0x84d"}
C net_version: {"jsonrpc":"2.0","id":1,"result":"2125"}
```

`eth_blockNumber` — relayé ; B répond l'erreur du relais :

```
8645: {"jsonrpc":"2.0","id":1,"result":"0x2412"}
8655: {"jsonrpc":"2.0","id":1,"result":"0x2412"}
8656: {"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"leader unreachable"}}
L=0x2412 A=0x2412   (trois paires consécutives identiques)
```

`eth_getBlockByNumber ["0x207c", false]` — même contenu, octets différents : le
relais ré-encode le résultat avec les clés en ordre alphabétique.

```
sha256 de la réponse brute   8645: 67c0658d26d8f14e7c59b3f53f9efb870a56e5a8f0c6241ab701357afb86b706
                             8655: 161aa5712823c09d5434ed5dddbb39898edd43e05756667937ce4ca2c48e56f3
sha256 du result, clés triées, [“0x207c”, true]
                             8645: 9297a1a74e8a985ef59d056c2ef3e3fc7a7d9c4e1c1c842fea4b26cb0caf1b08
                             8655: 9297a1a74e8a985ef59d056c2ef3e3fc7a7d9c4e1c1c842fea4b26cb0caf1b08
début du result              8645: {"number":"0x207c","hash":"0x8d74ec1247ecaa63a37d374b5757ef22b532577c4bd8145e2cc13f282cf24…
                             8655: {"baseFeePerGas":"0x1","difficulty":"0x0","extraData":"0x","gasLimit":"0x1c9c380","gasUsed…
hash du bloc via 8655 : 0x8d74ec1247ecaa63a37d374b5757ef22b532577c4bd8145e2cc13f282cf2410c
8656: {"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"leader unreachable"}}
```

`eth_getLogs [{"fromBlock":"0x2000","toBlock":"0x2200","address":"0xf4B146FbA71F41E0592668ffbF264F1D186b2Ca8"}]`
(AttestationRegistry) — 2 journaux, réponses identiques à l'octet près :

```
8645: 06dcf3d5ed1d55f13ef0dd81c6e62837430c075ba2aeb492ec0d3a7e2c448236
8655: 06dcf3d5ed1d55f13ef0dd81c6e62837430c075ba2aeb492ec0d3a7e2c448236
8656: {"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"leader unreachable"}}
```

`eth_call` — `getThreshold()` (`0xe75235b8`) sur le CuratorSet `canton-demo`
`0xD84379CEae14AA33C123Af12424A37803F885889`, puis `latestPeriodId()`
(`0xc5d24601`) sur PeriodRegistry (qui revert : l'erreur est relayée telle quelle) :

```
8645 getThreshold: {"jsonrpc":"2.0","id":1,"result":"0x0000000000000000000000000000000000000000000000000000000000000002"}
8655 getThreshold: {"jsonrpc":"2.0","id":1,"result":"0x0000000000000000000000000000000000000000000000000000000000000002"}
8656 getThreshold: {"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"leader unreachable"}}
8645 latestPeriodId: {"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"execution reverted"}}
8655 latestPeriodId: {"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"execution reverted"}}
```

`noor_txindexStatus` — **local** : le suiveur décrit son propre index, vide ; B
répond la même chose sans leader :

```
8645: {"jsonrpc":"2.0","id":1,"result":{"enabled":true,"ready":true,"ok":true,"last_indexed_height":9234,"finalized_height":9170,"lag_blocks":-64,"indexed_transaction_count":93,"count_ok":true,"rebuild_status":"ok","corrupt_entries_total":0,"inconsistent_entries_total":0,"missing_canonical_entries_total":0,"lookup_total":0,"lookup_found_total":0,"lookup_not_found_total":0,"lookup_errors_total":0,"last_error_class":"","rebuild_total":0,"rebuild_failures_total":0}}
8655: {"jsonrpc":"2.0","id":1,"result":{"enabled":true,"ready":true,"ok":true,"last_indexed_height":0,"finalized_height":0,"lag_blocks":0,"indexed_transaction_count":0,"count_ok":true,"rebuild_status":"ok","corrupt_entries_total":0,"inconsistent_entries_total":0,"missing_canonical_entries_total":0,"lookup_total":0,"lookup_found_total":0,"lookup_not_found_total":0,"lookup_errors_total":0,"last_error_class":"","rebuild_total":1,"rebuild_failures_total":0}}
8656: (identique à 8655)
```

Autres méthodes, même schéma : `eth_syncing` (`false` relayé, B injoignable) ;
`eth_getTransactionReceipt` de `0xc5a3c23d…9671a3` (A relaie le reçu du leader,
`blockHash 0x8d74ec…410c`, `blockNumber 0x207c` ; B injoignable) ; `eth_getBalance`
du déployeur (`0xde0b6b3a54ae9df` des deux côtés ; B injoignable) ; `eth_getCode`
d'AttestationRegistry (même sha256 `bea0e24d…feb9`) ; `noor_getCommitCertificate
["0x207c"]` (A relaie le certificat du leader, clés réordonnées ; B injoignable) ;
`eth_sendRawTransaction ["0x00"]` (A relaie l'erreur du leader `-32602 invalid
params: invalid raw tx` : **les écritures aussi passent par le suiveur** ; B
injoignable) ; méthode inconnue : `-32601 method not found` localement.

Latence (`curl -w %{time_total}`, secondes, boucle locale) :

```
eth_blockNumber   8645: 0.000627 0.000597 0.000627 0.000559 0.000616
                  8655: 0.001167 0.001654 0.001239 0.001359 0.001265
eth_getLogs       8645: 0.001021 0.001220 0.001140
                  8655: 0.002082 0.002771 0.003284
```

Santé et métriques — `/healthz` répond `ok` (HTTP 200) sur A **et sur B** : la
sonde dit que le processus répond, pas que le leader est joignable (la règle de
progression de `core/health` n'est armée que pour un validateur BFT).

```
8755: ok  http=200
8756: ok  http=200
A /metrics : noor_chain_height 9234   noor_node_role_info{role="follower"} 1
B /metrics : noor_chain_height 0      noor_rpc_requests_total{method="eth_blockNumber",code="err"} 1
journal B, une ligne par seconde (308 en cinq minutes) :
[node] 2026/10/21 13:33:58 follower: follow-rpc post error: Post "http://127.0.0.1:1": dial tcp 127.0.0.1:1: connect: connection refused
```

État local — le `-data-dir` d'A fait **52 Kio** au démarrage et **52 Kio** cinq
minutes et 304 ticks plus tard ; contenu intégral (clés lues sur une copie) :

```
db/leveldb : 4 clés — "emissionparams/v1/anchor" (212 octets), "selftest/v1" (1), "txidx/v1/applied" (1), "txidx/v1/count" (8)
db/geth    : 0 clé
oprec/oprec.jsonl : 1 ligne (node_start)
```

À titre de comparaison, `chain/runtime/data/node1` (validateur) : 23 Mio de `db`
et 7,5 Mio d'`oprec`.

### Conclusion : ce qu'un client gagne à exploiter un suiveur chez lui

Un suiveur est un **mandataire JSON-RPC** devant le leader, avec un processus
noorcore autour : il ne détient ni bloc, ni transaction, ni état EVM, ni
certificat de commit, et il n'en vérifie aucun. Concrètement, le client gagne :

- une **adresse RPC locale** qu'il contrôle : son propre jeton Bearer
  (`NOOR_HTTP_AUTH_TOKEN`), sa propre limitation de débit par client, ses propres
  journaux et métriques (`noor_rpc_requests_total` par méthode), un endroit où
  changer le leader (`-follow-rpc`) sans toucher ses applications ;
- une réponse `eth_chainId` / `net_version` **locale**, ce qui est une garantie si
  le drapeau est juste, et un mensonge s'il est faux (suiveur C) ;
- un relais fidèle au contenu (preuve : `eth_getLogs` identique à l'octet,
  `eth_getBlockByNumber` identique à l'ordre des clés près), au prix d'environ
  **+0,6 à 2 ms** par appel en boucle locale, et du ré-encodage des réponses
  (ordre alphabétique des clés : un client qui hache la réponse brute verra une
  différence).

Il **ne gagne pas** :

- de disponibilité : leader arrêté, tout sauf `eth_chainId`, `net_version`,
  `web3_clientVersion`, `noor_txindexStatus` (vide) et les stubs répond
  `leader unreachable`, et `/healthz` continue de dire `ok` ;
- d'indépendance ni de vérification : ce que le leader dit, le suiveur le
  répète ; un leader fautif ou compromis n'est pas détecté ; le certificat de
  commit (`noor_getCommitCertificate`) est relayé, pas vérifié, et les hauteurs
  élaguées chez le leader le sont aussi vues du suiveur ;
- de données : rien n'est stocké, donc rien ne survit au leader, et une
  réinstallation du suiveur ne coûte ni ne rapporte rien ;
- un `noor_txindexStatus` qui décrit la chaîne : il décrit l'index vide du
  suiveur (`last_indexed_height 0`), ce qui peut tromper une supervision.

## Ce qu'il faudrait pour une copie indépendante

Estimation argumentée depuis le code au commit `618fcef…` (le correctif de
`chain/patches/` pour la RPC du certificat) ; ce n'est pas un
engagement. Une « copie indépendante » est un **observateur** : un nœud qui n'est
pas validateur, qui reçoit les propositions et precommits signés, vérifie chaque
certificat (≥ 2f+1 signatures du jeu de validateurs), ré-exécute chaque bloc sur
son propre état et sert ensuite le RPC depuis ses données. Les pièces existent en
grande partie, mais pas leur assemblage pour un non-validateur.

Ce qui existe déjà :

- **La vérification et l'injection d'un bloc décidé** sans l'avoir voté :
  `core/node/loop_bft_tick.go`, `maybeInjectBFTDecided` (chemin « InjectDecided »)
  prend une proposition signée et ≥ 2f+1 precommits distincts déjà passés par
  `consensus.VerifyEnvelope`, fait ré-exécuter le bloc par le validateur de
  proposition (`validateBFTProposalForLoop`, état père = propre tête) et commet.
  C'est exactement ce qu'un observateur doit faire à chaque hauteur.
- **Le rattrapage** : `maybeEmitBFTCatchupRequestAt` émet `NOOR_CATCHUP_REQ`
  (`core/consensus/catchup_wire.go`, ≤ 32 hauteurs par requête, pas plus d'une
  requête toutes les 2 s, seulement si au moins un pair est connecté et que le
  moteur est bloqué) ; le répondeur (`loop_bft_line.go`,
  `serveBFTCatchupRequestAt`) renvoie les certificats **scellés** qu'il détient, en
  ordre croissant, bornés en octets, une réponse par pair et par intervalle. Pour
  une hauteur dont **personne** n'a plus le certificat, `loop_bft_certified_ancestor.go`
  sert le bloc lui-même (`NOOR_CATCHUP_BLOCK`) et le requérant ne le garde que si
  le certificat vérifié de la hauteur **suivante** le nomme comme parent et que sa
  ré-exécution redonne ce hachage.
- **Le service RPC local depuis ses propres données** : node2 à node4 du réseau de
  développement sont `-role follower` sans `-follow-rpc` et servent blocs, journaux,
  état et certificats depuis leur base ; un observateur sans `FollowRPC` emprunte le
  même chemin, rien à écrire côté RPC.
- **L'état de genèse** : `initBFTWorldState` → `applyAllocBootstrap` reconstruit
  l'état initial depuis le même `alloc-dev.json` ; l'observateur a donc besoin du
  document de genèse et de `validators.json`, rien de secret.

Ce qui manque :

1. **Un rôle observateur dans noorchain-core.** `Node.Start` refuse le mode BFT si
   `-validator-id` n'est pas dans le jeu (« bft: validator-id not in validator
   set »), et la boucle BFT charge une clé privée de validateur
   (`loop_bft_validator_identity.go`). Le moteur lui-même refuse de démarrer sans
   identifiant (`engine.go`, `Start` : « engine: self id empty »), ne se croit
   proposeur que si son identifiant est dans la rotation (`isProposerLocked`) et
   enregistre ses propres prevotes et precommits à chaque round sans autre
   condition (`castNilPrecommit`, étapes `StepPrevote` et `StepPrecommit`). Il faut
   donc un mode passif explicite : un rôle qui saute les deux gardes du nœud, un
   moteur qui avance de round en round sur les seuls votes reçus et **n'émet
   jamais** les siens, pas de clé. Taille : modérée, dans `core/main.go`
   (validation des drapeaux), `core/node/node.go`, `loop_bft_*.go` et
   `core/consensus/engine.go`, avec les tests à côté.
2. **L'admission au maillage p2p.** Le transport n'exige pas d'être validateur :
   un pair est admis par jeton AUTH, mTLS, liste de CIDR et identité de chaîne
   (`core/network/network.go`). En profil `dev` (réseau de développement) un
   observateur se connecte sans rien ; en production il lui faut le jeton partagé
   et un certificat client — une décision d'exploitation (qui l'on admet), et une
   borne : chaque observateur consomme un créneau de pair (`-p2p-max-peers`) et du
   trafic de diffusion chez les validateurs.
3. **L'historique au-delà de la rétention.** Les certificats sont élagués sous
   `tête − 300 000` (`DefaultCertRetentionHeights`). Pour le réseau de
   développement (≈ 9 500 hauteurs) tout est encore là : un observateur parti de la
   genèse rattraperait à 32 hauteurs par réponse et par pair, soit quelques
   minutes. Pour une chaîne plus vieille que la fenêtre, il n'existe ni instantané
   d'état, ni téléchargement de blocs vérifié par la chaîne des hachages depuis le
   premier certificat disponible : c'est le gros morceau, et il n'est pas commencé.
   Sans lui, un observateur ne peut démarrer qu'avant que la chaîne n'ait
   300 000 blocs, ou depuis une copie de confiance du `-data-dir` d'un validateur.
4. **Côté NOORTRACE**, l'image de ce répertoire n'aurait rien à changer : les
   drapeaux viennent de la commande. Le `docker-compose.yml` passerait de
   `-follow-rpc …` à `-role observer -validators-file … -alloc-file … -boot-peers …`,
   avec le port p2p publié.

Oui, un nœud non validateur **peut** suivre le consensus avec les primitives
présentes (vérification des enveloppes contre `validators.json`, injection des
décisions, rattrapage, ancêtre certifié) : rien dans le protocole n'exige qu'il
vote. Ce qui lui manque est un rôle qui l'y autorise sans clé ni voix, et, pour
une chaîne âgée, un moyen vérifié de reconstituer le passé élagué. D'ici là, la
copie indépendante de NOORTRACE reste **l'archive des certificats de commit à côté
des reçus** (`chain/README.md`, « Rétention »), vérifiable hors ligne sans aucun
nœud.
