# chain/ — instance de développement dédiée de noorcore pour NOORTRACE

Ce répertoire lance une chaîne EVM permissionnée **dédiée à NOORTRACE**, distincte
de la chaîne PoSS de NOORCHAIN, **sans émission ni jeton** : quatre validateurs
BFT en boucle locale, sur une seule machine. Elle sert de registre d'exploitation
pour le développement des contrats et de l'enregistreur ; rien ici n'est destiné
à un réseau public.

## Rôle de l'instance

- Registre d'exploitation substituable de NOORTRACE (décision du 20 octobre 2026 :
  NOORTRACE tourne sur une instance dédiée de noorcore, pas sur la chaîne du PoSS).
- Aucune émission : la section `rules` du document de genèse déclare une chaîne
  dont l'émission PoSS est désactivée, et le nœud vérifie cette déclaration à
  chaque démarrage avant de toucher quoi que ce soit (voir « Preuve » plus bas).
- Aucun jeton : le NUR natif n'y sert qu'à payer le gaz ; les quatre comptes
  préchargés sont des comptes de test publics.

## Source de noorcore et binaire

| Élément | Valeur |
|---|---|
| Dépôt | `https://github.com/noorfinances-eng/noorchain-core` |
| Correctif | `chain/patches/0001-noor_getCommitCertificate.patch`, appliqué sur le commit `618fcef8805ef5b4cb9291a3dd97be710e489297` à la construction ; il ajoute la méthode JSON-RPC `noor_getCommitCertificate` (voir plus bas). Le dépôt noorchain-core n'est pas modifié |
| Binaire | `chain/runtime/bin/noorcore`, construit le 21 octobre 2026 depuis le commit épinglé plus le correctif : `bash chain/scripts/build-noorcore.sh --force` (Go 1.26.9) |
| Binaire précédent | `chain/runtime/bin/noorcore.618fcef` : le binaire construit depuis le commit `618fcef` seul, sans la méthode, conservé pour retour arrière |

Le script `chain/scripts/build-noorcore.sh` clone le commit `618fcef` de noorchain-core,
applique les correctifs de `chain/patches/` avec `git apply`, puis construit :
`build-noorcore.sh --force` reconstruit ainsi un binaire avec `noor_getCommitCertificate`
sans qu'aucune branche n'existe dans noorchain-core. La chaîne existante reprend sans
changement avec ce binaire : la méthode est additive, rien du consensus ni du format
sur disque ne change.

## Identifiants (à réserver)

| Identifiant | Valeur | Remarque |
|---|---|---|
| Identifiant EVM (`eth_chainId`, EIP-155) | **2124** (`0x84c`) | distinct de 2121 (chaîne PoSS de NOORCHAIN), 2122 et 2123 (répétitions et pilote) |
| Identifiant de chaîne BFT (`--chain-id`) | **`noortrace-2124-dev`** | séparation de domaine des enveloppes BFT signées |

Ces deux valeurs sont à réserver pour NOORTRACE : un nœud d'un autre réseau qui
répondrait sur l'un de nos ports est refusé par `dev-net.sh start`, jamais pris
pour le nôtre.

## Prérequis

- Linux, `bash` ≥ 4.4, `curl`, `git`.
- `node` ≥ 18 : la génération des clés de validateur utilise uniquement le module
  `crypto` intégré (`createECDH("secp256k1")`), aucun paquet.
- `go` : nécessaire seulement pour **reconstruire** le binaire. Le `go.mod` de
  noorchain-core impose `go 1.26.9` ; avec `GOTOOLCHAIN=auto` (le défaut), la
  chaîne de compilation est téléchargée si besoin.
- Ports de boucle locale libres (tableau plus bas).

## Commandes

```bash
# depuis la racine du dépôt
bash chain/scripts/build-noorcore.sh            # construit le binaire s'il manque (clone à profondeur 1 du commit épinglé)
bash chain/scripts/build-noorcore.sh --force    # reconstruit quoi qu'il arrive

bash chain/scripts/dev-net.sh start             # démarre les quatre validateurs (idempotent, nœud par nœud)
bash chain/scripts/dev-net.sh status            # état, hauteurs, ports ; code de retour 0 si les quatre sont debout
bash chain/scripts/dev-net.sh stop              # arrêt propre (SIGTERM, état de consensus persisté)
```

`start` est idempotent : il sonde chaque nœud, relance seulement ceux qui manquent
(une grappe à moitié tombée est sous son quorum et doit pouvoir être rattrapée),
et refuse si un port est tenu par un autre réseau ou par une autre grappe de même
numéro. Au premier `start`, il génère le matériel de validateur ; s'il manque le
binaire, il appelle `build-noorcore.sh`.

Les nœuds sont détachés (`setsid` + `nohup`, entrée sur `/dev/null`, sortie dans
les journaux) : ils survivent à la fermeture du terminal qui les a lancés.

Variables d'environnement facultatives :

| Variable | Effet |
|---|---|
| `NOORTRACE_RUNTIME_DIR` | répertoire d'exécution (défaut : `chain/runtime`) |
| `NOORTRACE_NOORCORE_SRC` | copie de noorchain-core déjà présente, utilisée en lecture seule par `build-noorcore.sh` à la place du clone (doit être au commit épinglé) |
| `NOORTRACE_BFT_RECOVERY_RESET=1` | efface un marqueur de reprise BFT laissé par un arrêt brutal (profil dev seulement, geste explicite) |

Un point JSON-RPC pour les outils (Hardhat, scripts de déploiement) :
`http://127.0.0.1:8645`, identifiant de chaîne `2124`.

## Ports (boucle locale, 127.0.0.1 uniquement)

| Nœud | Rôle BFT | RPC JSON | p2p | Santé (`/healthz`) | Métriques (`/metrics`) |
|---|---|---|---|---|---|
| node1 (`v1`) | leader | **8645** | 31400 | 8745 | 9645 |
| node2 (`v2`) | follower | 8646 | 31401 | 8746 | 9646 |
| node3 (`v3`) | follower | 8647 | 31402 | 8747 | 9647 |
| node4 (`v4`) | follower | 8648 | 31403 | 8748 | 9648 |

Aucune collision avec les valeurs par défaut de noorchain (RPC 8545, p2p 30303,
santé 8080) ni avec la grappe de démo du hub (p2p 31301 à 31304, RPC 9546 à 9548).
Les quatre nœuds sont des validateurs à part entière ; « leader » et « follower »
ne changent que le routage RPC, pas le consensus.

## Ce qui vit sous chain/runtime/ (gitignoré)

```
chain/runtime/
  bin/noorcore          binaire construit depuis 618fcef plus le correctif de chain/patches (voir « Source de noorcore »)
  bin/noorcore.618fcef  binaire précédent, construit depuis le commit 618fcef seul
  src/noorchain-core/   clone à profondeur 1 (seulement si build-noorcore.sh a cloné)
  keys/node{1..4}.key   clés privées secp256k1 des validateurs (mode 0600)
  validators.json       { "validators": [ { "id": "v1", "pubKeyHex": "0x04…" }, … ] }
  data/node{1..4}/      base LevelDB et état EVM de chaque nœud
  logs/node{1..4}.log   journaux (ajoutés à chaque démarrage, séparés par une ligne « === dev-net: démarrage … »)
  pids/node{1..4}.pid   pid de chaque nœud
```

Le matériel de validateur est généré **une seule fois** et réutilisé aux
redémarrages : un jeu de clés neuf ferait refuser la chaîne existante. Pour
repartir d'une chaîne neuve : `stop`, puis supprimer `keys/`, `validators.json`
et `data/`.

Les journaux sont verbeux : les lignes de routine du rebroadcast BFT portent le
préfixe syslog `<7>` (niveau debug), environ 200 Ko par minute et par nœud. Pour
lire un journal sans elles : `grep -v '^<7>' chain/runtime/logs/node1.log`.

## Document de genèse : chain/config/alloc-dev.json

Format de `core/node/alloc.go` : `chainId` (EVM), `alloc[{address, balanceWei}]`
et la section facultative `rules`, que `core/node/genesis_rules_guard.go` compare
à la ligne canonique des règles du nœud (`consensusRulesFormat`) **avant** d'ancrer
quoi que ce soit, et refuse de démarrer sur tout écart.

Pour un nœud **sans émission** (variable `NOOR_POSS_EMISSION_ENABLED` non définie,
le défaut de `core/config/poss_emission_env.go`), `resolvePoSSEmissionParams`
rend une configuration vide, et la section `rules` doit donc porter exactement :

| Champ | Valeur | Pourquoi |
|---|---|---|
| `chainId` | `"noortrace-2124-dev"` | le `--chain-id` du nœud |
| `possEnabled` | `false` | émission désactivée |
| `possRewards` | `"0x0000000000000000000000000000000000000000"` | adresse nulle (rendue `addr.Hex()` de l'adresse vide) |
| `possCapWei` | `"0"` | plafond nul |
| `possGenesisUnix`, `possHalvingSec`, `possSubperiodSec` | `0` | aucune période |
| `possEmissionModel` | `"noormint/v1"` | constante `possEmissionModel` de `core/node/poss_emission.go`, présente sur la ligne de règles **même quand l'émission est désactivée** |

L'identifiant EVM n'est pas répété dans `rules` : il est porté par le `chainId` de
tête du document (2124). `dev-net.sh` efface les variables `NOOR_POSS_*` et
`NOOR_ACCEPT_NEW_EMISSION_PARAMS` avant tout lancement, pour que la ligne de
règles du nœud soit celle-ci quel que soit l'environnement de l'opérateur.

### Preuve : la ligne de journal de la vérification des règles

Au premier démarrage, chaque nœud écrit dans son journal (`chain/runtime/logs/node1.log`) :

```
[node] 2026/10/21 10:26:13 genesis rules: verified against /home/user/Polymarkets/chain/config/alloc-dev.json | chainId=noortrace-2124-dev evmChainId=2124 possEnabled=false possRewards=0x0000000000000000000000000000000000000000 possCapWei=0 possGenesisUnix=0 possHalvingSec=0 possSubperiodSec=0 possEmissionModel=noormint/v1
[node] 2026/10/21 10:26:13 emission params: anchored | chainId=noortrace-2124-dev evmChainId=2124 possEnabled=false possRewards=0x0000000000000000000000000000000000000000 possCapWei=0 possGenesisUnix=0 possHalvingSec=0 possSubperiodSec=0 possEmissionModel=noormint/v1
```

Aux démarrages suivants, la même ligne `genesis rules: verified against …` est
suivie de `emission params: verified against anchor` et de
`head: restored | height: N`. Un écart entre le document et le nœud produit à la
place `genesis rules: REFUSING TO START — this node's consensus rules do not match
the genesis document`, avec le champ qui diffère ; le nœud ne démarre pas.

## Certificat de commit BFT : `noor_getCommitCertificate`

Un reçu de transaction et un hachage de bloc disent qu'**un** nœud tient la
transaction dans un bloc ; ils ne disent pas que le jeu de validateurs a décidé ce
bloc. Le certificat de commit le dit : la proposition signée du round décidant et
les ≥ 2f+1 precommits signés (3 sur 4 ici) qui l'ont clos — exactement les trames
que chaque validateur a vérifiées avant de commettre. Chaque validateur le garde
sur disque par hauteur (`cert/v1/<hauteur>`) ; le binaire de cette instance le sert
désormais par JSON-RPC, avec le jeu de validateurs qui permet de le vérifier sans
nœud.

Méthode : `noor_getCommitCertificate` (niveau Experimental de la politique de
stabilité de noorchain-core : codes stables, champs ajoutés mais jamais retirés),
**exactement un** paramètre — hauteur hexadécimale sans zéro de tête (`"0x207c"`),
étiquette `"latest"`, ou hachage de bloc de 32 octets (résolu par la table
canonique : le hachage d'un bloc de branche latérale répond `unknown block`) ; un
second paramètre ou `"0x0064"` sont refusés (`-32602`). Spécification complète
(champs, erreurs, rétention, procédure de vérification hors ligne du condensé) :
`docs/RPC_SPEC_2.1.md` §13.1, tel que le correctif de `chain/patches/` l'ajoute à
noorchain-core.

Réponse, en résumé : `height`, `round`, `chainId` (`noortrace-2124-dev`),
`valsetHash`, `blockHash` ; `canonical.{blockHash, matchesCertificate}` (le hachage
que rend `eth_getBlockByNumber` à cette hauteur, et s'il égale celui du
certificat) ; `proposal.{line, validatorId, bodyHash, sig}` ; `precommits[]`
(`line` brute telle que stockée, plus les champs décodés) ;
`quorum.{validators, required, precommits}` (N, 2f+1, signataires **distincts** —
N et 2f+1 sont ceux du jeu **courant** du nœud) ; `validatorSet[]` dans l'ordre
canonique (le jeu courant, clés telles que configurées), `validatorSetHash` (son
hachage) et `validatorSetMatchesCertificate` (vrai quand ce hachage est le
`valsetHash` du certificat ; faux si `validators.json` a changé entre deux
exécutions du nœud : le jeu servi n'est alors pas celui qui a signé, et le
vérificateur doit prendre le sien) ; `signing.{domain, digestPrefix, scheme}` ;
`retention.{heights, pruned}`. Le nœud ne revérifie pas les signatures en servant :
la réponse est faite pour être vérifiée hors ligne.

Erreurs : `-32602` paramètre absent, surnuméraire ou mal formé ; `-32000 unknown
block` (hauteur au-delà de la tête, hachage inconnu ou non canonique) ; `-32000`
avec un message qui nomme la rétention quand le certificat est élagué ou absent ;
`-32000 … not yet persisted … retry shortly` pour la hauteur de **tête** pendant
les quelques millisecondes qui séparent l'écriture du bloc (reçus compris) de
celle de son certificat — transitoire, à réessayer, jamais à archiver comme une
absence (constaté sur cette instance : 2 réponses de ce type sur 600 appels
`["latest"]` consécutifs). Les quatre nœuds de cette instance sont des validateurs
et tiennent chacun leurs certificats ; la méthode répond sur les quatre ports RPC.
Un vrai suiveur (`-follow-rpc`) relaie l'appel au leader et répond `-32603
internal error` si la réponse du leader dépasse 2 MiB (certificat d'un très gros
bloc : interroger le leader directement).

### Rétention : extraire le certificat juste après le reçu

Le nœud ne garde que les **300 000 dernières hauteurs** de certificats
(`consensus.DefaultCertRetentionHeights`, surchargeable par
`NOOR_BFT_CERT_RETENTION_HEIGHTS`), soit ≈ 83 h à un bloc par seconde ; à chaque
commit, tout certificat sous `tête − 300 000` est supprimé. `retention.heights`
donne la fenêtre effective du nœud interrogé, `retention.pruned` dit si la hauteur
demandée est déjà sous la fenêtre.

Recommandation pour l'enregistreur NOORTRACE : **dès que
`eth_getTransactionReceipt` rend le reçu de la transaction d'ancrage, appeler
`noor_getCommitCertificate` avec `receipt.blockNumber` (ou `receipt.blockHash`) et
archiver la réponse à côté du reçu**, avec le `validators.json` (clés publiques)
du réseau. Le reçu est disponible dès que le bloc est durable et le certificat
quelques millisecondes plus tard : sur `not yet persisted`, **réessayer en boucle
courte** (quelques tentatives espacées de quelques dizaines de millisecondes, ou
jusqu'à ce que la tête ait dépassé le bloc) avant de conclure quoi que ce soit.
Passée la fenêtre de rétention, le nœud répond `-32000` et l'évidence n'est plus
récupérable auprès de lui. La vérification se fait ensuite hors ligne, sans nœud
(§13.1 de la spécification) ; les vecteurs ci-dessous servent de référence.

### Vecteurs enregistrés : test/fixtures/certificat-commit/

| Fichier | Contenu |
|---|---|
| `certificat-8316.json` | réponse complète réelle de `noor_getCommitCertificate(["0x207c"])` sur 127.0.0.1:8645 (ré-extraite après l'ajout de `validatorSetHash` / `validatorSetMatchesCertificate` ; lignes, hachages et quorum inchangés) : bloc 8316, qui porte la transaction de déploiement d'`AttestationRegistry` (`0xc5a3c23d…9671a3`, `deployments/noorcore.json`) |
| `bloc-8316.json` | réponse de `eth_getBlockByNumber(["0x207c", false])` : son `hash` est le `blockHash` du certificat |
| `validators.json` | le jeu de validateurs du réseau de développement, clés **publiques** seulement (copie de `chain/runtime/validators.json`) |

Preuve relevée le 21 octobre 2026, réseau relancé avec le binaire reconstruit :

- `["latest"]` (hauteur 0x2170) : `canonical.matchesCertificate = true`,
  3 precommits, `quorum = {validators: 4, required: 3, precommits: 3}`,
  `retention = {heights: 300000, pruned: false}` ;
- `["0x207c"]` : `blockHash = 0x8d74ec1247ecaa63a37d374b5757ef22b532577c4bd8145e2cc13f282cf2410c`,
  égal au `hash` de `eth_getBlockByNumber("0x207c")` et au `blockHash` du reçu de
  `0xc5a3c23d…9671a3` ; proposition signée par `v1`, precommits de `v4`, `v1`, `v3` ;
  même réponse par le hachage de bloc, et depuis node2 (8646) ;
- `["0x3b9aca00"]` : `-32000 unknown block` ; `["0x"]`, `[]`, `[12]` : `-32602` ;
- la réponse 8316 vérifiée hors ligne avec `consensus.VerifyEnvelope` contre
  `validators.json` : les quatre lignes passent, `valsetHash` recalculé égal ; un
  octet de signature modifié fait échouer la vérification.

```bash
curl -s http://127.0.0.1:8645 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"noor_getCommitCertificate","params":["0x207c"]}'
```

## Comptes préchargés (développement seulement)

Les quatre premiers comptes par défaut de Hardhat (mnémonique de test public
`test test test … junk`, chemin `m/44'/60'/0'/0/i`), 1 NUR chacun
(`1000000000000000000` wei, soit `0xde0b6b3a7640000`) :

| Index | Adresse |
|---|---|
| 0 | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` |
| 1 | `0x70997970C51812dc3A010C7d01b50e0d17dc79C8` |
| 2 | `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC` |
| 3 | `0x90F79bf6EB2c4f870365E785982E1f101E93b906` |

Les clés privées de ces comptes sont publiques : **développement uniquement**. Un
réseau prod-like a un déployeur dont la clé est générée et gardée hors dépôt, et
un document de genèse qui ne précharge que lui.

## Ce qui est dev only

- Profil réseau `dev` (`--network-profile dev`) : pas de `--bft-allow-experimental`
  exigé, permissions des fichiers de clé non vérifiées, messages BFT acceptés sans
  durcissement p2p, et `--bft-recovery-reset` disponible pour effacer un marqueur de
  reprise.
- Quatre validateurs sur une seule machine, en boucle locale : aucune tolérance à
  la panne de la machine elle-même.
- Pas d'authentification p2p (`--p2p-require-auth`), pas de TLS, pas de jeton HTTP.
- Comptes préchargés publics.
- Journaux dans des fichiers plats, sans rotation.

## Ce qui change pour un réseau prod-like à quatre validateurs sur deux sites

1. **Profil** `--network-profile prod-like` et `--bft-allow-experimental` sur
   chaque unité ; le nœud exige alors `--validator-key-file` (jamais de clé en
   ligne de commande), refuse les messages BFT non signés et refuse un fichier de
   clé lisible au-delà de son propriétaire (`0600`).
2. **Matériel** : une clé par validateur, générée sur son site et jamais copiée ;
   seul `validators.json` (clés publiques) circule, identique sur les quatre.
3. **Document de genèse** : même `rules` (sans émission), `chainId` à réserver
   définitivement (un autre numéro que 2124, qui reste celui du développement),
   déployeur hors dépôt à la place des comptes Hardhat ; le même fichier sur les
   quatre nœuds, vérifié par la ligne `genesis rules: verified against`.
4. **Réseau** : deux validateurs par site, p2p sur une adresse non locale, donc
   `--p2p-require-auth` avec un jeton d'au moins 32 caractères
   (`NOOR_P2P_AUTH_TOKEN`), `--p2p-tls` avec certificats et CA
   (`--p2p-tls-ca`, `--p2p-tls-require-client-cert` pour le mTLS),
   `--p2p-allowed-cidrs` restreint aux deux sites, `--boot-peers` croisés entre
   sites. Quorum 2f+1 = 3 : la perte d'un site entier (deux validateurs) arrête la
   production de blocs sans la corrompre ; c'est la limite d'un jeu de quatre.
5. **Exposition** : RPC derrière un mandataire TLS, `--rpc-trusted-proxies` posé,
   jeton HTTP (`NOOR_HTTP_AUTH_TOKEN`) sur rpc/santé/métriques ; jamais de
   `--allow-public-bind` sans ce périmètre.
6. **Exploitation** : unités systemd (`Restart=always`, `StartLimitBurst` fini pour
   qu'un validateur qui refuse de reprendre apparaisse en `failed`), journald avec
   `LogLevelMax=info`, supervision de `/healthz` et `/metrics`. En prod-like, le
   marqueur de reprise après arrêt brutal n'est pas effaçable : le nœud analyse et
   repart seul si c'est prouvé sûr, sinon `noorcore bft-recovery inspect`.
7. **Identifiants** : `--chain-id` et `--evm-chain-id` propres au réseau, réservés
   et documentés avant la première genèse ; ils entrent dans la ligne de règles
   ancrée au premier boot et ne se changent plus sans fork coordonné.
