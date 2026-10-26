# Confrontation des signatures CT-3 par ethers

Confrontation tierce des signatures des vecteurs de CT-3
([`spec/CT-3-approbations.md`](../../../../CT-3-approbations.md), révision 0.3,
EX-A.14, EX-A.18, EX-9.22) par la bibliothèque ethers du dépôt (version lue
dans `node_modules/ethers/package.json`, 6.17.0 à la date de la note R4,
R4-F36). Ce répertoire n'est jamais écrit par le générateur.

`confronter_ethers.mjs` n'importe rien de `scripts/` : il relit les vecteurs,
recalcule lui-même `D_A` et porte sa propre référence de CT-3 (contrôle de
forme d'EX-9.22, normalisation d'EX-9.3, Keccak-256 et recouvrement
secp256k1 écrits dans le programme, sans bibliothèque) ; ethers est la seule
bibliothèque qu'il emploie.

## Commande

Depuis la racine du dépôt, après `npm ci` :

```sh
node spec/vecteurs/ct-3/confrontation/ethers/confronter_ethers.mjs spec/vecteurs/ct-3 > sortie.txt
diff spec/vecteurs/ct-3/confrontation/sorties/ethers.txt sortie.txt
```

Le code de sortie est 0 sans discordance, 1 avec au moins une, 2 pour un
usage incorrect. La sortie publiée est `../sorties/ethers.txt` ; elle ne porte
aucun chemin local.

## Ce que fait le script

Pour chaque signature des entrées `voter` des traces de `tickets/`, des
remises de `decisions/`, de `signatures/normalisation.json`, de
`console/requetes/` et `console/reponses/`, et des signatures d'inscription de
`annuaire/` (`inscriptions.json`, `domaines.json`, preuves de `annuaires/` et
`exports/`, requêtes `inscrire` des traces) :

1. il contrôle lui-même la forme avant d'appeler la bibliothèque (EX-9.22) :
   65 octets, `r` et `s` dans `[1, n − 1]`, et `v ∈ {0, 1, 27, 28}` là où CT-3
   normalise (service, console), `v ∈ {27, 28}` et `s ≤ n/2` là où il ne
   normalise pas (noyau, réviseur d'un annuaire exporté) ;
2. il recalcule `D_A` (JCS des cinq chaînes de `A`, puis SHA-256 de
   `noortrace/approbation/v0\n ‖ JCS(A)`) et appelle
   `verifyMessage(getBytes(D_A), signature)`, ou `verifyMessage(texte,
   signature)` pour un message d'inscription (texte ASCII : ses octets UTF-8
   sont ses octets), avec la signature telle que le vecteur la porte ;
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
`discordance`. Ne sont pas confrontés : les votes adressés à un ticket jamais
ouvert dans la trace (aucun `request_hash`, donc aucun `D_A`) et
`annuaire/messages.json`, qui ne porte aucune signature. Les lignes sont
celles de `confronter_eth_account.py`, dans le même ordre, avec les mêmes
adresses attendues : seules l'adresse recouvrée et le verdict dépendent de la
bibliothèque.

Les fichiers de clé de `console/fichiers-cle/` que CT-3 accepte, ou dont il
refuse seulement l'adresse, sont déchiffrés par `decryptKeystoreJsonSync` et
l'adresse obtenue est comparée à celle du vecteur ; les fichiers que CT-3
refuse pour leur format ou leurs paramètres ne sont pas présentés à la
bibliothèque (le cas `n = 2^19` imposerait 512 Mo de mémoire).

## Verdicts

| Verdict | Sens |
|---|---|
| `concorde` | CT-3 et la bibliothèque acceptent la forme et recouvrent l'adresse attendue, ou la refusent tous deux |
| `acceptee_par_la_bibliotheque` | CT-3 refuse une forme que la bibliothèque accepte : attendu pour `v = 37` et `v = 38` et pour une signature compacte de 64 octets (R4-F37, R4-F38) |
| `refusee_par_la_bibliotheque` | CT-3 normalise une forme que la bibliothèque refuse : attendu pour un `s` haut (R4-F37, R4-F38) |
| `discordance` | une forme que CT-3 accepte recouvre une autre adresse que l'attendue, une forme canonique est refusée, ou le vecteur contredit la référence ; le script rend alors 1 |

Sortie régénérée le 2026-10-26 pour les trois annuaires exportés `annuaire/exports/administrateurs-*.json` ajoutés par la fermeture de la révision 0.3 (EX-13.37) : douze preuves de plus, toutes `concorde` ; les 318 lignes précédentes sont inchangées.

Sortie publiée : 330 signatures et fichiers ; 314 `concorde`, 9
`acceptee_par_la_bibliotheque` (`v = 37` et `v = 38`, 64 octets, et, présentés
au noyau qui ne normalise pas, `v ∈ {0, 1}`), 7 `refusee_par_la_bibliotheque`
(`s` haut là où CT-3 normalise), 0 `discordance`.

Les deux écarts attendus sont la raison d'EX-9.22 : un programme qui vérifie
la signature d'un vote contrôle la forme lui-même avant d'appeler une
bibliothèque.
