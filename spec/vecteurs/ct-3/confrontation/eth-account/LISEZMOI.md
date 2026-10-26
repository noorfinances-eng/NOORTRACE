# Confrontation des signatures CT-3 par eth-account

Confrontation tierce des signatures des vecteurs de CT-3
([`spec/CT-3-approbations.md`](../../../../CT-3-approbations.md), révision 0.3,
EX-A.14, EX-A.18, EX-9.22) par la bibliothèque Python `eth-account` 0.14.0,
version la plus récente publiée sur PyPI le 2026-10-26 (roue publiée le
2026-08-23), licence MIT. Ce répertoire n'est jamais écrit par le générateur.

`confronter_eth_account.py` ne lit aucun code du dépôt : il relit les
vecteurs, recalcule lui-même `D_A` et porte sa propre référence de CT-3
(contrôle de forme d'EX-9.22, normalisation d'EX-9.3, Keccak-256 et
recouvrement secp256k1 écrits dans le programme, sans bibliothèque).

## Commande

Depuis la racine du dépôt :

```sh
python3 -m venv <répertoire>/venv-eth-account
<répertoire>/venv-eth-account/bin/pip install --only-binary :all: --no-deps -r spec/vecteurs/ct-3/confrontation/eth-account/exigences.txt
<répertoire>/venv-eth-account/bin/pip check
<répertoire>/venv-eth-account/bin/python -I spec/vecteurs/ct-3/confrontation/eth-account/confronter_eth_account.py spec/vecteurs/ct-3 > sortie.txt
diff spec/vecteurs/ct-3/confrontation/sorties/eth-account.txt sortie.txt
```

`exigences.txt` donne la version exacte d'`eth-account` et de chacune de ses
dépendances résolues par `pip` (dont `eth-keys` 0.8.0, qui fait le
recouvrement, `eth-keyfile` 0.10.0, qui déchiffre les fichiers de clé, et
`pycryptodome` 3.24.1) ; `--no-deps` interdit toute autre résolution, et
`pip check` ne relève aucune dépendance manquante. L'interpréteur est lancé
avec `-I` : ni le répertoire du programme ni le répertoire courant n'entrent
dans le chemin d'importation.

Le code de sortie est 0 sans discordance, 1 avec au moins une, 2 pour un
usage incorrect. La sortie publiée est `../sorties/eth-account.txt` ; elle ne
porte aucun chemin local et ne dépend ni de la machine ni de la version de
Python (identique avec Python 3.12 et 3.13).

## Ce que fait le programme

Pour chaque signature des entrées `voter` des traces de `tickets/`, des
remises de `decisions/`, de `signatures/normalisation.json`, de
`console/requetes/` et de `console/reponses/`, et des signatures d'inscription
de `annuaire/` (`inscriptions.json`, `domaines.json`, preuves de `annuaires/`
et de `exports/`, requêtes `inscrire` des traces) :

1. il contrôle lui-même la forme, avant d'appeler la bibliothèque
   (EX-9.22) : 65 octets, `r` et `s` dans `[1, n − 1]`, et
   `v ∈ {0, 1, 27, 28}` là où CT-3 normalise (service, console),
   `v ∈ {27, 28}` et `s ≤ n/2` là où il ne normalise pas (noyau, réviseur d'un
   annuaire exporté) ;
2. il recalcule `D_A` (JCS des cinq chaînes de `A`, puis SHA-256 de
   `noortrace/approbation/v0\n ‖ JCS(A)`, CT-1 §6.3) et recouvre l'adresse par
   `Account.recover_message`, avec la signature telle que le vecteur la porte :
   - pour un vote, sur `encode_defunct(hexstr=D_A)` (EX-A.18), puis sur
     `encode_defunct(primitive=<32 octets de D_A>)` (EX-9.22) ;
   - pour un message d'inscription, sur
     `encode_defunct(primitive=<octets du message>)` (EX-A.14, EX-A.18), puis
     sur `encode_defunct(text=<message>)` : le texte est ASCII, ses octets
     UTF-8 sont ses octets ;

   les deux appels doivent rendre la même adresse, ou le même refus ; jamais
   `text="0x…"` pour un vote, qui signerait 66 octets, ni un entier, qui
   perdrait les octets nuls de tête (EX-9.22 ; `console/requetes/apr-c0-542-*`
   porte un `D_A` dont le premier octet est nul) ;
3. il compare l'adresse recouvrée à l'adresse attendue : celle que le vecteur
   nomme (approbateur d'un vote accepté ou refusé pour une raison qui suit la
   signature dans l'ordre d'EX-9.10, approbateurs d'une remise scellée ou
   refusée après SG-5, adresse d'une inscription acceptée ou refusée après la
   signature dans l'ordre d'EX-13.15, adresse d'une preuve que
   `exports/attendu.json` ne déclare pas invalide, adresse recouvrée attendue
   d'un cas de `console/reponses/` ou de `domaines.json`, approbateur d'une
   requête de `console/requetes/`), ou, à défaut, celle que recouvre la
   référence du programme sur la forme normalisée.

Le programme exige en outre que les vecteurs s'accordent avec sa référence :
`D_A` de chaque requête de `console/requetes/` égal à `expected.digests.d_a` ;
forme normalisée de chaque cas de `signatures/normalisation.json` égale à
`expected`, et adresse recouvrée parmi les comptes de test de
`constantes.json` ; forme normalisée de chaque réponse acceptée de
`console/reponses/` égale à `expected.signature`. Un écart est une
`discordance`.

Les fichiers de `console/fichiers-cle/` que CT-3 accepte, ou dont il refuse
seulement l'adresse, sont déchiffrés par `Account.decrypt` et l'adresse de la
clé obtenue est comparée à celle du vecteur ; les fichiers que CT-3 refuse
pour leur format ou leurs paramètres ne sont pas présentés à la bibliothèque.

Ne sont pas confrontés : les votes adressés à un ticket jamais ouvert dans la
trace (aucun `request_hash`, donc aucun `D_A`) et `annuaire/messages.json`,
qui ne porte aucune signature.

## Verdicts

| Verdict | Sens |
|---|---|
| `concorde` | CT-3 et la bibliothèque acceptent la forme et recouvrent l'adresse attendue, ou la refusent tous deux |
| `acceptee_par_la_bibliotheque` | CT-3 refuse une forme que la bibliothèque accepte |
| `refusee_par_la_bibliotheque` | CT-3 normalise une forme que la bibliothèque refuse |
| `discordance` | une forme que CT-3 accepte recouvre une autre adresse que l'attendue, une forme canonique est refusée, les deux appels d'`encode_defunct` divergent, ou le vecteur contredit la référence ; le programme rend alors 1 |

Sortie régénérée le 2026-10-26 pour les trois annuaires exportés `annuaire/exports/administrateurs-*.json` ajoutés par la fermeture de la révision 0.3 (EX-13.37) : douze preuves de plus, toutes `concorde` ; les 318 lignes précédentes sont inchangées.

Sortie publiée : 330 signatures et fichiers ; 325 `concorde`, 5
`acceptee_par_la_bibliotheque`, 0 `refusee_par_la_bibliotheque`, 0
`discordance`. Les cinq écarts sont ceux qu'annoncent EX-9.22 et R4-F40,
R4-F41 :

- `v = 37` et `v = 38` (forme EIP-155, `console/reponses/v-37.json`,
  `v-38.json`, `annuaire/inscriptions` `v-37`) : eth-account les accepte et
  recouvre, pour `v = 38`, une autre adresse que le signataire ; CT-3 les
  refuse ;
- `s` haut et `v ∈ {0, 1}` présentés au noyau
  (`decisions/invalides/sg5-s-haut.json`, `sg5-v-zero-un.json`) :
  eth-account les accepte, le noyau les refuse (SG-5), lui qui ne normalise
  pas.

Là où CT-3 normalise (service, console), eth-account accepte aussi `s` haut
et `v ∈ {0, 1}` et recouvre la même adresse : `concorde`. Une signature de
64 octets et `v = 29` sont refusées par les deux : `concorde`. Ces écarts
sont la raison d'EX-9.22 : un programme qui vérifie la signature d'un vote
contrôle la forme lui-même avant d'appeler une bibliothèque.
