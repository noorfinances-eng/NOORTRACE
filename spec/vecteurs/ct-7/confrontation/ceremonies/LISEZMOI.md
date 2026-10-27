# Confrontation des signatures des procès-verbaux de cérémonie

Confrontation tierce des signatures des procès-verbaux de cérémonie des clés
des vecteurs de CT-7
([`spec/CT-7-securite-et-conformite.md`](../../../../CT-7-securite-et-conformite.md),
version 0.1, §5.7, CR-11 de §5.8, EX-A.24) par deux bibliothèques :

- `ethers`, celle du dépôt (version lue dans
  `node_modules/ethers/package.json`, 6.17.0 à la date de la sortie
  publiée), par `confronter_ethers.mjs` ;
- `eth-account` 0.14.0, licence MIT, par `confronter_eth_account.py`, aux
  versions épinglées par `exigences.txt`, identiques à celles de
  `spec/vecteurs/ct-3/confrontation/eth-account/exigences.txt`.

Ce répertoire n'est jamais écrit par le générateur
(`scripts/vecteurs/generer-ct7.mjs`). Aucun des deux programmes n'importe de
code de `scripts/` : chacun relit les vecteurs, recalcule lui-même `D_C` et
porte sa propre référence de CT-7 (contrôle de forme de CR-11, JCS v0 de
CT-1 §4, Keccak-256 et recouvrement secp256k1 écrits dans le programme, sans
bibliothèque) ; la bibliothèque confrontée est la seule qu'il emploie.

## Commandes

Depuis la racine du dépôt, après `npm ci` :

```sh
node spec/vecteurs/ct-7/confrontation/ceremonies/confronter_ethers.mjs spec/vecteurs/ct-7 > sortie-ethers.txt
diff spec/vecteurs/ct-7/confrontation/ceremonies/sorties/ethers.txt sortie-ethers.txt
```

Pour eth-account, dans un environnement virtuel :

```sh
python3 -m venv <répertoire>/venv-eth-account
<répertoire>/venv-eth-account/bin/pip install --only-binary :all: --no-deps -r spec/vecteurs/ct-7/confrontation/ceremonies/exigences.txt
<répertoire>/venv-eth-account/bin/pip check
<répertoire>/venv-eth-account/bin/python -I spec/vecteurs/ct-7/confrontation/ceremonies/confronter_eth_account.py spec/vecteurs/ct-7 > sortie-eth-account.txt
diff spec/vecteurs/ct-7/confrontation/ceremonies/sorties/eth-account.txt sortie-eth-account.txt
```

`--no-deps` interdit toute autre résolution que celle d'`exigences.txt`, et
`pip check` ne relève aucune dépendance manquante. L'interpréteur est lancé
avec `-I` : ni le répertoire du programme ni le répertoire courant n'entrent
dans le chemin d'importation.

Le code de sortie est 0 sans discordance, 1 avec au moins une, 2 pour un
usage incorrect. Les sorties publiées sont `sorties/ethers.txt` et
`sorties/eth-account.txt` ; elles ne portent aucun chemin local.

## Ce que font les programmes

Pour chaque signature (`signatures[i]`) du `proces-verbal.json` de chaque cas
de `ceremonies/`, dans l'ordre alphabétique des cas puis dans l'ordre du
fichier :

1. le programme recalcule `D_C = Keccak-256(P_C ‖ JCS(V))`, `V` étant le
   procès-verbal privé de son membre `signatures` et `P_C` les octets UTF-8
   de `noortrace/ceremonie-cles/v0\n` (§5.7), et exige qu'il égale le
   `digest` de `attendu.json` ;
2. il contrôle lui-même la forme avant d'appeler la bibliothèque (CR-11) :
   65 octets, `r` et `s` dans `[1, n − 1]`, `s ≤ n/2`, `v ∈ {27, 28}` ;
   CT-7 ne normalise jamais une signature ;
3. il recouvre l'adresse avec la signature telle que le vecteur la porte :
   - ethers : `verifyMessage(getBytes(D_C), signature)`, sur les 32 octets
     de `D_C`, jamais sur la chaîne `0x…` ;
   - eth-account : `Account.recover_message(encode_defunct(primitive=<32
     octets de D_C>), signature=…)`, puis par `encode_defunct(hexstr=D_C)` ;
     les deux appels doivent rendre la même adresse, ou le même refus ;
4. il compare l'adresse recouvrée à l'adresse attendue : celle du
   participant (`participants[].address`) quand `attendu.json` la range
   parmi les signataires (`signers`), sinon celle que recouvre la référence
   du programme. Dans ce second cas, la référence ne doit pas recouvrir
   l'adresse du participant : le vecteur dirait faux en l'écartant.

Les trois cas où CR-1 échoue (`invalide-cr1-cle-en-double`,
`invalide-cr1-nombre-non-entier`, `invalide-cr1-schema`) n'ont pas de `D_C`
selon CT-7 (`digest` nul, CR-2 à CR-12 non exécutées, EX-5.9). Leurs
signatures sont tout de même confrontées, sous la famille
`ceremonies/cr1-lecture-permissive`, sur le `D_C` d'une lecture permissive
du fichier (dernière occurrence d'une clé en double, `0.0` lu comme l'entier
`0`, schéma non vérifié), avec l'adresse de la référence pour attendue. Cette
lecture n'est pas celle de CT-7, qui l'admet pour la seule confrontation
(EX-A.24) sans qu'elle vaille définition de `D_C` ; elle constate seulement
que la bibliothèque et la référence recouvrent la même adresse sur les mêmes
octets.

## Verdicts

Ce sont ceux de la confrontation de CT-3 (EX-A.25) :

| Verdict | Sens |
|---|---|
| `concorde` | CT-7 et la bibliothèque acceptent la forme et recouvrent l'adresse attendue, ou la refusent tous deux |
| `acceptee_par_la_bibliotheque` | CT-7 refuse une forme que la bibliothèque accepte |
| `refusee_par_la_bibliotheque` | dans CT-3, une forme normalisée que la bibliothèque refuse ; jamais rendu ici : CT-7 ne normalise pas, et une forme canonique refusée est une `discordance` |
| `discordance` | une forme que CT-7 accepte recouvre une autre adresse que l'attendue ou est refusée par la bibliothèque, les deux appels d'`encode_defunct` divergent, ou le vecteur contredit la référence ; le programme rend alors 1 |

## Sorties publiées (2026-10-27)

- `sorties/ethers.txt` (ethers 6.17.0) : 130 signatures ; 130 `concorde`,
  0 `acceptee_par_la_bibliotheque`, 0 `refusee_par_la_bibliotheque`, 0
  `discordance`.
- `sorties/eth-account.txt` (eth-account 0.14.0, eth-keys 0.8.0, Python
  3.13) : 130 signatures ; 129 `concorde`, 1
  `acceptee_par_la_bibliotheque`, 0 `refusee_par_la_bibliotheque`, 0
  `discordance`.

Les deux sorties portent les mêmes lignes, dans le même ordre, avec les mêmes
adresses attendues ; seuls l'adresse recouvrée et le verdict dépendent de la
bibliothèque.

Écart inscrit, non une discordance (EX-A.24, EX-A.25) : la signature `s` haut du
cas `invalide-cr11-s-haut` (indice 1, témoin) est refusée par CT-7 (CR-11) ;
ethers la refuse aussi (`concorde`) ; eth-account l'accepte et recouvre
l'adresse du témoin (`acceptee_par_la_bibliotheque`). C'est la raison pour
laquelle un vérificateur de procès-verbal contrôle la forme lui-même avant
d'appeler une bibliothèque.

Les signatures des cas `invalide-cr11-autre-proces-verbal`,
`invalide-cr11-signataire-substitue` et
`invalide-cr11-signature-d-une-decision` recouvrent, sur `D_C`, une autre
adresse que celle du participant : la bibliothèque et la référence
recouvrent la même (`concorde`), ce qui fait échouer CR-11 comme le vecteur
l'attend.
