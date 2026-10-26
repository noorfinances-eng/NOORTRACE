# Capture unique du registre (vecteurs CT-6, annexe A.5)

Ce répertoire est une **entrée** des vecteurs de CT-6 : les réponses JSON-RPC
brutes que le réseau de développement de noorcore a rendues pour les sept
transactions de registre dont les dossiers de CT-6 se servent. Le générateur
(`scripts/vecteurs/ct6/registre.mjs`) le lit et ne le réécrit jamais ; il en
dérive `periode-1/`, `periode-2/`, `variantes/`, `trie.json` et
`attendu.json`. On ne recapture que si la capture doit changer
(spec/CT-6-verificateur.md, EX-A.1 et EX-A.8).

## Capture du 2026-10-22

| Élément | Valeur |
|---|---|
| Date | 2026-10-22T22:21:03.442Z (`capture.json`, champ `date`) |
| Réseau | `noortrace-2124-dev` (identifiant EVM 2124), quatre validateurs BFT lancés par `bash chain/scripts/dev-net.sh start` |
| Nœud interrogé | node1, validateur `v1`, JSON-RPC en boucle locale (port 8645) : un validateur, jamais un suiveur (EX-13.8) |
| noorcore | commit `618fcef8805ef5b4cb9291a3dd97be710e489297` de noorchain-core, plus le correctif `0001-noor_getCommitCertificate.patch` (chain/README.md, « Source de noorcore ») ; binaire `chain/runtime/bin/noorcore` de SHA-256 `0xb02a011a2fddd77b7ca6a00b8f376320dc7a419c6a5f47dcaca2a35a56ef33c6` |
| Dépôt NOORTRACE | commit `f01364684c937370da7827c0fbd54257034465b0`, avec `scripts/vecteurs/capturer-ct6.mjs` dans l'arbre de travail |
| Contrats | ceux de `deployments/noorcore.json` (blocs 8316 à 8328) : `PeriodRegistry` `0x4ee6ecad1c2dae9f525404de8555724e3c35d07b`, `AttestationRegistry` `0xf4b146fba71f41e0592668ffbf264f1d186b2ca8`, `RecorderRegistry` `0xbec49fa140acaa83533fb00a2bb19bddd0290f25`, `CuratorSetRegistry` `0x172076e0166d1f9cc711c77adf8488051744980c` |
| Jeu de validateurs | `validators.json`, copie octet pour octet de `chain/runtime/validators.json` (clés publiques seulement), hachage `0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751` |

Constat local, consigné dans `capture.json` (`code_contrats`) : le code
déployé aux quatre adresses est égal au code compilé de `contracts/`
(`npm run compile`), octets des immuables (adresse du `CuratorSetRegistry`)
et métadonnées CBOR finales (empreinte des sources) mis à part. Ce constat ne
prouve rien au réviseur : le code des contrats aux adresses de l'ancre n'est
pas prouvé par la version 0 du vérificateur (CT-6, hypothèse H7).

### Transactions

Toutes relayées par le compte Hardhat 0 (`0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266`),
une par bloc ; chaque bloc ne porte que cette transaction (un reçu de type 2).

| Bloc | Rôle | Objet | Transaction |
|---|---|---|---|
| 16636, 16640 | (non capturés) | déploiement du `CuratorSet` de `assureur-demo` (comptes Hardhat 1 à 3, seuil 2) et assignation | — |
| 16648 | inscription | `rec-test-01` sous `0xaa2a59656361352e96ef2eed355316ef8b29dab7` | `0x932ae471728698ae648a109858081ccfadbf20e472bd85cdc47115550dc85158` |
| 16652 | inscription | `rec-test-02` sous `0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49` | `0x158850e1aae6d6a6eb7125387c581d580886135a7fafbe871e4185b66beea062` |
| 16656 | inscription | `rec-test-03` (clé étrangère aux dossiers) sous `0xe2bdcef6264103ab6c88fa3c1b5a2ceacd995b22` | `0x3a55a9dc62d6d587a0cf6c231c5586bc323a2190a1ac27bb646c33f66825c2b2` |
| 16660 | ancre | période 1, empreinte `0x3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6`, émetteur `rec-test-02` | `0x70edd263160e4fcd6c6887ac21daf4556720ef662facdf9bb12292366f120779` |
| 16664 | ancre | période 2, émetteur `rec-test-02` | `0xb9bdfb0db9059c2fb4d4789e3fb28e2ee4bcf5fee0ff13cedfd96a2b79ffeb39` |
| 16668 | clôture | période 1 (`periodHash` `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914`), `PeriodSubmitted` d'identifiant 5 | `0xd9fb0d69567fa4f5ecbf51179198fa02f30524a3275678405cfc11307374bbc0` |
| 16672 | clôture | période 2 (`periodHash` `0xe867be7f64b77e49a9c3066d33aa39cffc5b5a588edec54f99cb2d07ff33bf19`) | `0xbb53b23f5406a11c8d62fbb29a574ce04eca719dcc14f7118582e37278ac256f` |

Chaque certificat porte la proposition de `v1` et exactement le quorum de
precommits (`v4`, `v1`, `v3` : 3 sur 4), ce dont la variante
`invalide-r5-quorum` se sert.

Les heures des blocs (2026-10-22) précèdent les dates fictives des
manifestes de CT-1 (2026-11-05) : sans effet, aucune vérification ne compare
l'heure déclarée d'un bloc à celles du manifeste (EX-A.9).

### Fichiers

| Fichier | Contenu |
|---|---|
| `bloc-<h>.json` | réponse brute de `eth_getBlockByNumber(h, false)` |
| `recu-<hash>.json` | réponse brute de `eth_getTransactionReceipt(hash)`, pour chaque transaction du bloc |
| `certificat-<h>.json` | réponse brute de `noor_getCommitCertificate(h)` |
| `validators.json` | jeu de validateurs du réseau, clés publiques seulement |
| `capture.json` | description : date, commits, contrats, organisation, transactions avec leur rôle, leur bloc et leurs fichiers ; `points_de_controle` : transactions d'ancre de point de contrôle (complément EX-A.15) ; `complements` : compléments de capture datés |
| `CAPTURE.md` | ce document |

Les octets des fichiers JSON-RPC sont ceux de la réponse HTTP, sans
réécriture (adresses en casse mixte EIP-55 comprises : l'exportateur, ici le
générateur, les met en minuscules, CT-6 §11.2.1). Seul `capture.json`, qui
n'est pas une réponse du nœud, a été retouché après la capture : son champ
`rpc` désigne le nœud par son rôle et son port, sans adresse, comme le script
l'écrit désormais.

### Clés

Aucune clé privée n'est dans ce répertoire ni nulle part dans le dépôt pour
ces transactions, hors les clés de test publiques suivantes, qui ne doivent
porter aucune valeur :

- comptes Hardhat 0 à 3 : mnémonique publique `test test test test test test test test test test test junk`, chemins `m/44'/60'/0'/0/<i>` (comme les vecteurs de CT-1) ;
- clés de chaîne des enregistreurs : SHA-256(UTF-8(`noortrace/vecteurs/v0/cle-chaine/rec-test-0N`)) ;
- clés Ed25519 : graine SHA-256(UTF-8(`noortrace/vecteurs/v0/cle-enregistreur/rec-test-0N`)) (CT-1 §13).

Les clés privées des validateurs du réseau de développement restent sous
`chain/runtime/keys/`, hors du dépôt ; `validators.json` n'en porte que les
clés publiques.

## Complément du 2026-10-26 : ancre du point de contrôle couvrant seq 7 (CT-6 révision 0.2, EX-A.15)

Sur le même réseau de développement (même chaîne, mêmes contrats, même jeu de
validateurs : `validators.json` inchangé, hachage
`0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751`), une
transaction de plus, capturée dès son reçu par la même procédure (bloc, tous
les reçus du bloc, certificat de commit) ; les sept blocs du 2026-10-22 n'ont
été ni relus ni réécrits. `capture.json` reçoit cette transaction (rôle
`ancre_point_de_controle`) sous la clé séparée `points_de_controle`, et un
champ `complements` qui date l'opération ; la liste `transactions` garde ses
sept entrées du 2026-10-22, que le générateur de CT-4 lit telle quelle (ses
vecteurs ne changent pas).

| Bloc | Rôle | Objet | Transaction |
|---|---|---|---|
| 18928 | ancre_point_de_controle | point de contrôle couvrant seq 7 de la période 1 (`spec/vecteurs/ct-1/points-de-controle/periode-1.json`, `checkpoint_ts` 2026-11-05T09:32:00.000Z, `tree_size` 8, `last_seq` 8, `checkpointHash` `0x93acd0fc36f93d7a267367e22367154e875d38c6368c527649d298619c90a4f4`) : `AttestationRegistry.anchor` de l'empreinte `0x12923cb6e38ca2e7c8ff193954dadf345607988204d2bae5ecbdc502859c8339` = keccak256(org_id ‖ journal_id ‖ checkpointHash), `docType` `0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178` (`noortrace/point-de-controle/v0`), émetteur `rec-test-01` (`0xaa2a59656361352e96ef2eed355316ef8b29dab7`, clé qui a signé le point, inscrite au bloc 16648) | `0xcaacb0feed55717561dfe8ee9732636038cd667192ccba8c412e7586af641135` |

Le certificat du bloc 18928 porte la proposition de `v1` et quatre precommits
(les sept blocs de 2026 portaient le quorum exact de trois). Le générateur
dérive de cette entrée `periode-1-point/` (les quatre entrées de `periode-1/`
plus celle-ci, cinq certificats) et la variante
`variantes/invalide-r11-ancre-de-periode/`.

```bash
bash chain/scripts/dev-net.sh start
node scripts/vecteurs/capturer-ct6.mjs --ancre-point spec/vecteurs/ct-1/points-de-controle/periode-1.json
bash chain/scripts/dev-net.sh stop
```

Le complément refuse d'agir si `capture.json` porte déjà une entrée sous
`points_de_controle` (ou une transaction `ancre_point_de_controle`), si
l'empreinte du point est déjà ancrée, ou si la clé de chaîne de la clé du point
n'est pas celle inscrite dans la capture ; la série de points de CT-1 doit être
figée avant (son `checkpointHash` est l'entrée : le générateur de CT-6 s'arrête
si elle a changé depuis).

## Procédure exacte

```bash
npm run compile                               # artefacts hh-artifacts/ (ABI, code du CuratorSet)
bash chain/scripts/dev-net.sh start           # quatre validateurs, la chaîne avance
node scripts/vecteurs/capturer-ct6.mjs        # amorce, inscrit, ancre, clôture, capture
bash chain/scripts/dev-net.sh stop
bash chain/scripts/dev-net.sh status          # 0/4 validateurs debout (code 1)
node scripts/vecteurs/ct6/registre.mjs        # rederive registre/ depuis la capture
```

Le script refuse d'agir si l'organisation `assureur-demo` est déjà amorcée,
si l'une des deux empreintes est déjà ancrée ou si l'un des deux `periodHash`
est déjà connu, et refuse d'écrire dans un répertoire de capture non vide sans
`--remplacer`. Il vérifie que les clés de chaîne et les clés Ed25519 dérivées
sont celles de l'annexe A.5, que les condensés calculés par les contrats
(`registerDigest`, `periodDigest`) égalent ceux du client, que chaque
transaction a le statut 1, puis capture chaque bloc dès le reçu obtenu, en
réessayant `noor_getCommitCertificate` tant que le nœud répond « not yet
persisted ».

## Recapturer

La chaîne du réseau de développement où cette capture a été faite garde
l'organisation, les inscriptions, les ancres et les clôtures : la même
procédure y est refusée. Recapturer exige un réseau neuf, dans un répertoire
d'exécution vide, le réseau principal de développement arrêté (mêmes ports) :

```bash
bash chain/scripts/dev-net.sh stop
export NOORTRACE_RUNTIME_DIR="$(mktemp -d)"                   # répertoire d'exécution neuf
mkdir -p "$NOORTRACE_RUNTIME_DIR/bin" && cp chain/runtime/bin/noorcore "$NOORTRACE_RUNTIME_DIR/bin/"
bash chain/scripts/dev-net.sh start                           # nouveau jeu de validateurs, nouvelle genèse
export NOORTRACE_DEPLOYMENTS_DIR="$(mktemp -d)"               # deployments/noorcore.json n'est pas touché
NOOR_PRIVATE_KEY=<clé du compte Hardhat 0> node scripts/deploy/deploy-noortrace.mjs --network noorcore
node scripts/vecteurs/capturer-ct6.mjs --deploiement "$NOORTRACE_DEPLOYMENTS_DIR/noorcore.json" --remplacer
bash chain/scripts/dev-net.sh stop
unset NOORTRACE_RUNTIME_DIR NOORTRACE_DEPLOYMENTS_DIR
node scripts/vecteurs/ct6/registre.mjs
```

Un réseau neuf a un autre jeu de validateurs, d'autres hauteurs, d'autres
heures et d'autres hachages : `attendu.json` est alors rederivé par le
générateur, et les valeurs des contrôles 8 citées en exemple par la
spécification (section 8) restent illustratives. Que les adresses des
contrats redéployés soient les mêmes (adresses de création dérivées du nonce
du compte 0) n'a pas été vérifié.
