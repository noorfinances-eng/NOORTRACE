# Confrontation des signatures d'attestation de périmètre

Confrontation tierce des signatures d'attestation de périmètre des vecteurs
de CT-7
([`spec/CT-7-securite-et-conformite.md`](../../../../CT-7-securite-et-conformite.md),
version 0.1, §7.2, EX-7.6, EX-7.7, AT-3, EX-A.25), et de celles que portent
les dossiers nouveaux de CT-1 (révision 0.4) et de CT-6 (révision 0.3) avec
la partie `attestation-perimetre.json` (CT-7 A.7), par deux bibliothèques :

- `ethers`, celle du dépôt (version lue dans
  `node_modules/ethers/package.json`, 6.17.0 à la date de la sortie
  publiée), par `confronter_ethers.mjs` ;
- `eth-account` 0.14.0, licence MIT, par `confronter_eth_account.py`, aux
  versions épinglées par `exigences.txt`, identiques à celles de
  `spec/vecteurs/ct-3/confrontation/eth-account/exigences.txt`.

Ce répertoire n'est jamais écrit par le générateur
(`scripts/vecteurs/generer-ct7.mjs`). Aucun des deux programmes n'importe de
code de `scripts/` : chacun relit les vecteurs, recalcule lui-même `D_P` et
porte sa propre référence de CT-7 (contrôle de forme d'EX-7.6, JCS v0 de
CT-1 §4, Keccak-256 et recouvrement secp256k1 écrits dans le programme, sans
bibliothèque) ; la bibliothèque confrontée est la seule qu'il emploie.

## Commandes

Depuis la racine du dépôt, après `npm ci` :

```sh
node spec/vecteurs/ct-7/confrontation/attestations/confronter_ethers.mjs spec/vecteurs/ct-7 spec/vecteurs/ct-1 spec/vecteurs/ct-6 > sortie-ethers.txt
diff spec/vecteurs/ct-7/confrontation/attestations/sorties/ethers.txt sortie-ethers.txt
```

Pour eth-account, dans un environnement virtuel :

```sh
python3 -m venv <répertoire>/venv-eth-account
<répertoire>/venv-eth-account/bin/pip install --only-binary :all: --no-deps -r spec/vecteurs/ct-7/confrontation/attestations/exigences.txt
<répertoire>/venv-eth-account/bin/pip check
<répertoire>/venv-eth-account/bin/python -I spec/vecteurs/ct-7/confrontation/attestations/confronter_eth_account.py spec/vecteurs/ct-7 spec/vecteurs/ct-1 spec/vecteurs/ct-6 > sortie-eth-account.txt
diff spec/vecteurs/ct-7/confrontation/attestations/sorties/eth-account.txt sortie-eth-account.txt
```

`--no-deps` interdit toute autre résolution que celle d'`exigences.txt`, et
`pip check` ne relève aucune dépendance manquante. L'interpréteur est lancé
avec `-I` : ni le répertoire du programme ni le répertoire courant n'entrent
dans le chemin d'importation.

Le code de sortie est 0 sans discordance, 1 avec au moins une, 2 pour un
usage incorrect. Les sorties publiées sont `sorties/ethers.txt` et
`sorties/eth-account.txt` ; elles ne portent aucun chemin local.

## Ce que font les programmes

Pour chaque signature confrontée, le programme :

1. recalcule le condensé : `D_P = Keccak-256(P_P ‖ JCS(P))`, `P_P` étant les
   octets UTF-8 de `noortrace/attestation-perimetre/v0\n` (§7.2) ;
2. contrôle lui-même la forme avant d'appeler la bibliothèque (EX-7.6) :
   65 octets, `r` et `s` dans `[1, n − 1]`, `s ≤ n/2`, `v ∈ {27, 28}` ;
   CT-7 ne normalise jamais une signature ;
3. recouvre l'adresse avec la signature telle que le vecteur la porte :
   - ethers : `verifyMessage(getBytes(D_P), signature)`, sur les 32 octets
     du condensé, jamais sur la chaîne `0x…` ;
   - eth-account : `Account.recover_message(encode_defunct(primitive=<32
     octets de D_P>), signature=…)`, puis par `encode_defunct(hexstr=D_P)` ;
     les deux appels doivent rendre la même adresse, ou le même refus ;
   - pour le texte d'inscription de CT-3 d'un cas croisé : ethers
     `verifyMessage(texte, signature)`, eth-account
     `encode_defunct(primitive=<octets UTF-8 du texte>)` puis
     `encode_defunct(text=<texte>)` ;
4. compare l'adresse recouvrée à l'adresse attendue, ou, quand le vecteur
   n'en nomme aucune, à celle que recouvre la référence du programme.

Signatures confrontées, par famille de la sortie :

| Famille | Source | Adresse attendue |
|---|---|---|
| `attestations/exemple` | `attestations/exemple/condense.json` et `attestation-signee.json` (exemple de §7.2, comptes 1 et 2) | l'adresse déclarée de chaque signature |
| `attestations/cas` | chaque cas de `attestations/attestations.json` (A.6) | `expected.recovered[i]` quand AT-1 réussit ; celle de la référence quand AT-1 échoue |
| `attestations/croises` | chaque cas de `attestations/croises.json` (EX-7.7, A.6) : indice 0 sur le message que le compte 1 a signé, indice 1 sur le message que le cas lui fait présenter | indice 0 : l'adresse du compte 1 ; indice 1 : `expected.recovered` |
| `ct-1/dossiers`, `ct-6/dossiers` | la partie `attestation-perimetre.json` de chaque dossier qui la porte (A.7) | l'adresse déclarée quand AT-3 réussit dans `attendu.json` ; sinon celle de la référence |

Les programmes exigent en outre que les vecteurs s'accordent avec leur
référence ; un écart est une `discordance` :

- exemple : `jcs.txt` égal, octet pour octet, à `JCS(P)` recalculé ;
  `jcs_length`, `digest` et `message` (`M`, EIP-191 version `0x45`) de
  `condense.json` égaux aux valeurs recalculées ; `digest` et `attestation`
  de `attestation-signee.json` égaux à ceux de l'exemple ;
- `attestations.json` : AT-1 réussie, `expected.digest` égal à `D_P`
  recalculé, une entrée de `expected.recovered` par signature, et, AT-3
  réussie, chaque adresse recouvrée égale à l'adresse déclarée ; AT-1 en
  échec, `expected.recovered` nul ;
- `croises.json` : `attestation_digest` égal au `D_P` de l'exemple ; le
  condensé d'un message `ceremonie` égal au `digest` de
  `ceremonies/valide-creation-enregistreur/attendu.json` ; l'adresse
  recouvrée sur le message présenté différente de celle du compte 1 ;
- dossiers : AT-2 réussie, `D_P` recalculé égal au `digest` de la partie.

Une attestation dont AT-1 échoue n'a pas de `D_P` selon CT-7. Pour le cas
`invalide-at1-nombre-non-entier`, dont `input.signed` est un texte JSON où
`version` vaut `0.0`, les programmes lisent ce texte de façon permissive
(`0.0` lu comme l'entier `0`) et recouvrent les signatures sur le `D_P` de
cette lecture, avec l'adresse de la référence pour attendue ; de même pour
les autres cas AT-1, dont le schéma n'est pas vérifié ici.

Ne sont pas confrontés : la partie du dossier `valide-at1-partie-nulle`,
réduite au littéral `null`, qui ne porte aucune signature ; le dossier
`valide-seq-7-attestation-declaree-absente`, où la partie est déclarée
absente ; et la signature `sig` de l'événement d'inscription
(`inscription.event`), qui est une signature Ed25519 de l'enregistreur
(CT-1 §6), non une signature secp256k1 d'EIP-191.

## Verdicts

Ce sont ceux de la confrontation de CT-3 (EX-A.25) :

| Verdict | Sens |
|---|---|
| `concorde` | CT-7 et la bibliothèque acceptent la forme et recouvrent l'adresse attendue, ou la refusent tous deux |
| `acceptee_par_la_bibliotheque` | CT-7 refuse une forme que la bibliothèque accepte |
| `refusee_par_la_bibliotheque` | dans CT-3, une forme normalisée que la bibliothèque refuse ; jamais rendu ici : CT-7 ne normalise pas, et une forme canonique refusée est une `discordance` |
| `discordance` | une forme que CT-7 accepte recouvre une autre adresse que l'attendue ou est refusée par la bibliothèque, les deux appels d'`encode_defunct` divergent, ou le vecteur contredit la référence ; le programme rend alors 1 |

## Sorties publiées (2026-10-27)

- `sorties/ethers.txt` (ethers 6.17.0) : 100 signatures ; 99 `concorde`, 1
  `acceptee_par_la_bibliotheque`, 0 `refusee_par_la_bibliotheque`, 0
  `discordance`.
- `sorties/eth-account.txt` (eth-account 0.14.0, eth-keys 0.8.0, Python
  3.13) : 100 signatures ; 98 `concorde`, 2 `acceptee_par_la_bibliotheque`,
  0 `refusee_par_la_bibliotheque`, 0 `discordance`.

Les deux sorties portent les mêmes lignes, dans le même ordre, avec les mêmes
adresses attendues ; seuls l'adresse recouvrée et le verdict dépendent de la
bibliothèque.

Écarts inscrits, non des discordances (EX-A.25 : cas invalides de forme
de A.4 et A.6), tous deux sur les cas invalides de forme de A.6 :

- `invalide-at3-v-hors-domaine` (indice 1, `v = 0x00`) : CT-7 refuse la
  forme (AT-3) ; ethers et eth-account l'acceptent toutes deux
  (`acceptee_par_la_bibliotheque`) et recouvrent une adresse qui n'est pas
  celle du compte 2, `v = 0` étant lu comme la parité 0 ;
- `invalide-at3-s-haut` (indice 1, `s` haut, `v` complémenté) : CT-7 refuse
  la forme ; ethers la refuse aussi (`concorde`) ; eth-account l'accepte et
  recouvre l'adresse du compte 2 (`acceptee_par_la_bibliotheque`).

Ces écarts sont la raison pour laquelle un vérificateur d'attestation
contrôle la forme lui-même avant d'appeler une bibliothèque (EX-7.6).

Les signatures croisées (`attestations/croises`) recouvrent l'adresse du
compte 1 sur le message qu'il a signé et une autre adresse sur le message
présenté : les deux bibliothèques et la référence s'accordent sur chacune,
ce qui fait échouer AT-3, E-9 de CT-1, AN-4 de CT-3 et CR-11 de CT-7 comme
les vecteurs l'attendent.
