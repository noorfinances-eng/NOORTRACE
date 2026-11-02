# Paquet `ots` : contrôle 5 et K-9

Preuve OpenTimestamps de `periodHash` contre les en-têtes Bitcoin (CT-6
section 10, vérifications O-1 à O-7) et sa réutilisation par K-9 sur le
`checkpoint_hash` d'un point de contrôle du journal (EX-10.16). Le contrat
avec le moteur est dans `../INTERFACES.md`, section « Contrôle 5 » ; les
types et la signature sont fixés par `interface.go`.

## Fichiers

| Fichier | Contenu |
|---|---|
| `interface.go` | types et signature fixés (inchangés) |
| `format.go` | O-1 : lecture stricte du `.ots` (§10.2, EX-10.2, EX-10.5), `Analyser`, cible de fuzzing |
| `execution.go` | O-3 : exécution des opérations du profil `{f0, f1, 08}` (EX-10.7) |
| `entetes.go` | lecture de la chaîne d'en-têtes : `H(i)`, `prev`, `racine`, `nTime`, `nBits`, `dSHA`, `SetCompact`, `GetCompact`, réajustement, travail ; règles 1 à 6 d'EX-10.9 (O-5) |
| `verifier.go` | O-1 à O-7, statut (EX-10.12), faits (EX-10.14), proposition F5 (EX-10.15), résumé, AV-O-1 à AV-O-3 (§10.7), `construit = true` |
| `*_test.go` | tests (voir plus bas) |

Le fichier d'en-têtes est lu et contrôlé par N-2 dans le paquet `ancres`
(schéma, 200 000 en-têtes, `start_height + n − 1 < 2³²`) ; ce paquet en fait
la lecture que CT-6 confie au contrôle 5 (champs des en-têtes de 80 octets,
chaînage, travail, difficulté, heure médiane, temps du bloc, travail cumulé).

## Bornes (§15.1, EX-15.2)

Fichier de 256 Kio ; `varuint` de forme minimale et de 9 octets au plus ;
arguments de 1 à 4096 octets ; messages et résultats de 1 à 4096 octets ;
charge d'attestation de 0 à 8192 octets ; URI de 0 à 1000 octets dans
`A-Z a-z 0-9 - . _ / :` ; hauteur inférieure à 2³² ; 255 opérations par
chemin. La récursion de l'analyseur et de l'exécution passe par une
opération à chaque niveau et s'arrête donc à 255 ; l'exécution ne garde que
les messages du chemin courant et les résultats de 32 octets. Les boucles
sur les en-têtes sont itératives et bornées par leur nombre.

## Tests

- `vecteurs_test.go` : les douze preuves de `spec/vecteurs/ct-6/ots/preuves`
  (lecture, attestations, résultats des opérations), les cinq fichiers
  d'en-têtes (hauteurs, hachages affichés), les vingt cas de
  `ots/attendu.json` (statuts de O-1 à O-7, statut du contrôle ou de K-9,
  avertissements triés comme le moteur, faits octet pour octet), et les
  soixante et onze dossiers de `ct-6/dossiers` qui portent `preuve.ots` :
  statuts O- et K-9, statut du contrôle 5, avertissements AV-O-, proposition
  F5 présente dans l'énoncé attendu.
- `format_test.go` : O-1 et O-3 sur des fichiers construits et hostiles
  (troncature à chaque longueur, octets en trop, étiquettes inconnues,
  longueurs absurdes, `varuint` non minimaux ou de 10 octets, charges et URI
  aux bornes, 255 et 256 opérations, 100 000 opérations imbriquées, fichier
  de 256 Kio à 20 000 attestations, résultats de 4096 et 4097 octets).
- `entetes_test.go` : `SetCompact` et `GetCompact` (cas de Bitcoin Core),
  réajustement sur les quatre cas de `pow_tests.cpp` de Bitcoin Core
  (recalculés indépendamment), travail, en-tête réel du bloc 358391 de §10.3,
  et chaque règle d'EX-10.9 en réussite et en échec sur des chaînes regtest
  minées par le test.
- `verifier_test.go` : chaque O- en réussite, en échec et non exécutée,
  statut du contrôle, faits, proposition exacte (regtest avec borne médiane,
  réseau principal sans borne ni suffixe), résumé, avertissements, K-9.
- `fuzz_test.go` : `FuzzAnalyser` (graines : les preuves de l'annexe A.4 et
  des fichiers construits) ; vérifie aussi la forme du résultat complet.

```bash
go test ./ots
go test -run '^$' -fuzz FuzzAnalyser -fuzztime 60s ./ots
```

## Lectures

Passages de CT-6 ambigus ou que les vecteurs précisent, et lecture retenue.
Aucun vecteur de `spec/vecteurs/ct-6` ne contredit le texte.

1. **AV-O-3, « O-5 exécutée sur le réseau `regtest` » (§10.7).** Exécutée :
   `reussi` ou `echoue` (le dossier `invalide-o5-chaine-sans-travail` porte
   AV-O-3 avec O-5 en échec ; `non-execute-o5-point-de-controle-hors-entetes`
   n'en porte pas). Le réseau est celui de l'ancre, qui le fixe (R2-F22) :
   une ancre `mainnet` contre un fichier `regtest` fait échouer O-5
   (règle 1) sans AV-O-3.
2. **Ordre des règles d'EX-10.9 quand plusieurs s'appliquent.** EX-10.9 ne
   le fixe pas ; EX-4.12 dit seulement qu'un chaînage faux fait échouer O-5
   et qu'un fichier sans la hauteur du point de contrôle la laisse non
   exécutée. Lecture : les règles 1 (réseau) et 2 (chaînage) sont examinées
   d'abord et un échec y prévaut sur la règle 3 non applicable (une chaîne
   qui se contredit se contredit quelles que soient les ancres, EX-5.3) ;
   puis la règle 3 ; puis, de `c + 1` à `t`, les règles 4 à 6, où un échec
   prévaut sur une règle 5 non applicable (`ancre_absente`, réajustement dont
   l'en-tête `i − 2016` manque).
3. **AV-O-2 : quelle vérification le lève.** EX-10.7 le fait lever pour une
   attestation sous une opération hors profil (O-3), EX-10.11 pour une
   attestation en attente ou inconnue (O-7). Les vecteurs le confirment par
   l'ordre des avertissements : `valide-o3-branche-hors-profil` (AV-O-2
   avant AV-O-3, donc O-3) et `valide-attente-uri-vide` (AV-O-3 avant AV-O-2,
   donc O-7). Une attestation en attente ou inconnue située sous une
   opération hors profil ne lève qu'un AV-O-2, sur O-3. AV-O-2 de O-7 est
   levé dès que O-1 réussit, même quand O-7 est non exécutée
   (`non-execute-o7-en-attente`).
4. **Attestations sous une opération en défaut (O-3 en échec).** Rien n'est
   calculé sous l'opération fautive ; une attestation en attente qui s'y
   trouve lève quand même AV-O-2 (O-7), comme l'attend
   `invalide-o3-resultat-trop-long`. La bibliothèque de référence refuse ce
   fichier dès la lecture (R2-F67) ; CT-6 range ce défaut sous O-3, O-1
   réussie, et c'est ce que fait ce paquet.
5. **O-3 et la raison `hors_perimetre_version`.** La table d'EX-5.9 dit que
   K-9 porte `hors_perimetre_version` quand « la vérification réutilisée le
   dit (… opération OpenTimestamps hors profil, O-3) ». EX-10.7 dit pourtant
   que O-3 réussit si les opérations du profil s'exécutent sans défaut et que
   les opérations hors profil ne changent pas son statut. Lecture : O-3 est
   `reussi` ou `echoue` ; c'est O-4 qui porte `hors_perimetre_version` quand
   aucune attestation Bitcoin n'est comparable parce qu'elles sont toutes
   sous une opération hors profil, et le statut du contrôle (ou de K-9) le
   reprend par EX-6.5 (EX-10.12 : « une attestation hors profil donne
   `hors_perimetre_version` »). Un arbre sans aucune opération du profil (une
   attestation posée sur l'empreinte du fichier) donne O-3 réussie.
6. **Raison de O-4 non exécutée.** EX-10.8 dit « `non_execute` sinon » ;
   une attestation hors profil est `hors_perimetre_version`, une attestation
   dont l'en-tête manque `ancre_absente` ; plusieurs : la première dans
   l'ordre d'EX-6.5.
7. **Attestation Bitcoin sous une opération hors profil et O-7.** O-7
   réussit « si l'arbre porte au moins une attestation Bitcoin » ; elle
   compte donc, et O-5 s'exécute. Si c'est la seule, O-4 est non exécutée
   (`hors_perimetre_version`).
8. **Résultat qui ne fait pas 32 octets.** EX-10.8 exige que `r` « fasse
   exactement 32 octets et égale » `racine(h)` : un tel résultat est comparé
   et ne concorde pas (attestation `echoue`).
9. **Règle 5 du réseau principal.** `Δ` est calculé en entier signé, comme
   dans Bitcoin Core (`int64_t`), puis ramené dans `[302 400, 4 838 400]` ;
   le produit est calculé sans borne de taille, ce qui donne le même
   résultat que l'`arith_uint256` de Bitcoin Core pour `powLimit` = 2²²⁴ − 1.
   Une cible précédente négative ou en débordement (seul le point de
   contrôle de l'ancre peut l'avoir, les suivants passant la règle 4) fait
   échouer O-5.
10. **`anchors_used`.** « `/bitcoin` quand O-5 a employé l'ancre » : quand
    O-5 est `reussi` ou `echoue`, pas quand elle n'est pas exécutée.
11. **`summary` du contrôle 5.** Rendu seulement quand le contrôle réussit,
    au format de l'exemple de 8.6 (« bloc Bitcoin 1001 du réseau regtest,
    20 confirmations (réseau d'essai) ») ; sinon le moteur écrit la liste des
    vérifications non exécutées. La proposition F5 n'est rendue que pour la
    clôture ; pour K-9, le moteur construit FK depuis les faits.
12. **Fichier d'en-têtes vide.** Impossible après N-2 (schéma, `minItems`
    1) ; traité par défense comme un fichier qui ne contient pas la hauteur
    du point de contrôle (O-5 `ancre_absente`).
