# Vecteurs de test CT-2

Produits par `scripts/vecteurs/generer-ct2.mjs` (`npm run vecteurs:ct2`), rejoués
par `test/enregistreur.test.js`, confrontés par le vérificateur Go indépendant de
`verificateur-independant/`. Disposition : annexe B de
[CT-2](../../CT-2-enregistreur.md). Tout est déterministe : rejouer le générateur
produit exactement les mêmes octets. Les clés JSON sont en anglais, les
descriptions en français ; chaque famille porte ses attendus.

Le générateur n'écrit que les entrées décrites ici (`INDEX.md`, `jcs-integral`, `redaction`, `pieces-mcp`, `pieces-modele`, `evenements`),
qu'il efface et réécrit à chaque exécution ; toute autre entrée du répertoire
(le vérificateur Go de `verificateur-independant/`) est laissée telle quelle.
Les vecteurs de CT-1 (`../ct-1/`) ne changent pas.

## Constantes

| Grandeur | Dérivation | Valeur |
|---|---|---|
| Organisation | `assureur-demo`, `org_id = keccak256(UTF-8("assureur-demo"))` | `0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab` |
| Journal | `journal-demo`, `journal_id = keccak256(UTF-8("journal-demo"))` | `0x1c085ec2ae5b20dfef4c1b84694fb81a8c553e0a6e7a4fed3e5a6ada4bb9bd0e` |
| Nonce période 1 | `SHA-256(UTF-8("noortrace/vecteurs/v0/nonce/journal-demo/periode-1"))` | `0x45af944ecd7f0ca63796707debb5045347d8a12212a044c5d3a0f1c4be941283` |
| Clé de pseudonymisation de test | `SHA-256(UTF-8("noortrace/vecteurs/v0/cle-pseudonyme/test"))`, 32 octets ; variable d'environnement `NOORTRACE_VECTEURS_CLE_PSEUDO` de `politique-pseudonyme-test.json` | `0x139011dc372b3ce979a162b0dee18753e67e1477ea4db3c55f929829c2ca3808` |
| Clé de l'enregistreur | `rec-test-01` de CT-1 §13 (graine publique) | `0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045` |
| Approbateurs | comptes Hardhat 1 à 3, seuil 2 sur 3 (CT-1 §13) | `0x70997970c51812dc3a010c7d01b50e0d17dc79c8`, `0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc`, `0x90f79bf6eb2c4f870365e785982e1f101e93b906` |
| Période de démonstration | `[1794304800, 1794308400)` = 2026-11-10T10:00:00Z → 11:00:00Z | — |
| Version de l'enregistreur | `code.recorder` | `0.1.0` |
| Ensemble de politique | `policy_version` de `evenements/journal-demo/politique.json` | `demo-2026-11`, `policy_sha256` `0x310e81a9764658f3d2580d2611b55e211581104a0f786b252fed29e3d84fa80f` |

Clés et graines sont publiques et jetables : elles ne doivent jamais porter de valeur.

## `jcs-integral/cas.json`

Tableau d'objets `{ name, input, canonical, note }` (annexe B.2) : `input` est un
texte JSON tel qu'il serait reçu, `canonical` sa forme canonique **JCS intégral**
(RFC 8785 telle quelle, nombres par la règle ES6 Number::toString, CT-2 §8.1), ou
`null` si le texte n'a pas de forme canonique (NaN, Infinity, débordement de la
double précision, clé en double, substitut isolé, texte qui n'est pas du JSON).
Les 26 lignes de la table de l'annexe B de la RFC 8785 (24 finies), l'exemple de
la RFC 8785 §3.2.2 (forme canonique de §3.2.3, octets de §3.2.4), les données de
tri de §3.2.3, la table de CT-2 §8.1 et les cas limites de CT-1 §4.

| Cas | Forme canonique | Note |
|---|---|---|
| `rfc8785-b-01-0000000000000000` | `0` | RFC 8785, annexe B, ligne 1 (IEEE 754 0000000000000000, zéro) ; entrée non canonique équivalente. |
| `rfc8785-b-02-8000000000000000` | `0` | RFC 8785, annexe B, ligne 2 (IEEE 754 8000000000000000, zéro négatif) ; entrée non canonique équivalente. |
| `rfc8785-b-03-0000000000000001` | `5e-324` | RFC 8785, annexe B, ligne 3 (IEEE 754 0000000000000001, plus petit nombre positif (dénormalisé)) ; entrée non canonique équivalente. |
| `rfc8785-b-04-8000000000000001` | `-5e-324` | RFC 8785, annexe B, ligne 4 (IEEE 754 8000000000000001, plus petit nombre négatif) ; entrée canonique. |
| `rfc8785-b-05-7fefffffffffffff` | `1.7976931348623157e+308` | RFC 8785, annexe B, ligne 5 (IEEE 754 7fefffffffffffff, plus grand nombre positif) ; entrée non canonique équivalente. |
| `rfc8785-b-06-ffefffffffffffff` | `-1.7976931348623157e+308` | RFC 8785, annexe B, ligne 6 (IEEE 754 ffefffffffffffff, plus grand nombre négatif) ; entrée non canonique équivalente. |
| `rfc8785-b-07-4340000000000000` | `9007199254740992` | RFC 8785, annexe B, ligne 7 (IEEE 754 4340000000000000, plus grand entier exact positif, note (1)) ; entrée non canonique équivalente. |
| `rfc8785-b-08-c340000000000000` | `-9007199254740992` | RFC 8785, annexe B, ligne 8 (IEEE 754 c340000000000000, plus grand entier exact négatif, note (1)) ; entrée non canonique équivalente. |
| `rfc8785-b-09-4430000000000000` | `295147905179352830000` | RFC 8785, annexe B, ligne 9 (IEEE 754 4430000000000000, environ 2**68, note (2) : la sérialisation ne garde pas la précision étendue) ; entrée non canonique équivalente. |
| `rfc8785-b-10-7fffffffffffffff` | refus | RFC 8785, annexe B, ligne 10 (IEEE 754 7fffffffffffffff, NaN : pas de représentation JSON, note (3)) ; entrée non canonique équivalente. |
| `rfc8785-b-11-7ff0000000000000` | refus | RFC 8785, annexe B, ligne 11 (IEEE 754 7ff0000000000000, Infinity : pas de représentation JSON, note (3)) ; entrée non canonique équivalente. |
| `rfc8785-b-12-44b52d02c7e14af5` | `9.999999999999997e+22` | RFC 8785, annexe B, ligne 12 (IEEE 754 44b52d02c7e14af5) ; entrée non canonique équivalente. |
| `rfc8785-b-13-44b52d02c7e14af6` | `1e+23` | RFC 8785, annexe B, ligne 13 (IEEE 754 44b52d02c7e14af6) ; entrée non canonique équivalente. |
| `rfc8785-b-14-44b52d02c7e14af7` | `1.0000000000000001e+23` | RFC 8785, annexe B, ligne 14 (IEEE 754 44b52d02c7e14af7) ; entrée non canonique équivalente. |
| `rfc8785-b-15-444b1ae4d6e2ef4e` | `999999999999999700000` | RFC 8785, annexe B, ligne 15 (IEEE 754 444b1ae4d6e2ef4e) ; entrée non canonique équivalente. |
| `rfc8785-b-16-444b1ae4d6e2ef4f` | `999999999999999900000` | RFC 8785, annexe B, ligne 16 (IEEE 754 444b1ae4d6e2ef4f) ; entrée non canonique équivalente. |
| `rfc8785-b-17-444b1ae4d6e2ef50` | `1e+21` | RFC 8785, annexe B, ligne 17 (IEEE 754 444b1ae4d6e2ef50, seuil de la notation exponentielle) ; entrée non canonique équivalente. |
| `rfc8785-b-18-3eb0c6f7a0b5ed8c` | `9.999999999999997e-7` | RFC 8785, annexe B, ligne 18 (IEEE 754 3eb0c6f7a0b5ed8c) ; entrée non canonique équivalente. |
| `rfc8785-b-19-3eb0c6f7a0b5ed8d` | `0.000001` | RFC 8785, annexe B, ligne 19 (IEEE 754 3eb0c6f7a0b5ed8d) ; entrée non canonique équivalente. |
| `rfc8785-b-20-41b3de4355555553` | `333333333.3333332` | RFC 8785, annexe B, ligne 20 (IEEE 754 41b3de4355555553) ; entrée non canonique équivalente. |
| `rfc8785-b-21-41b3de4355555554` | `333333333.33333325` | RFC 8785, annexe B, ligne 21 (IEEE 754 41b3de4355555554) ; entrée non canonique équivalente. |
| `rfc8785-b-22-41b3de4355555555` | `333333333.3333333` | RFC 8785, annexe B, ligne 22 (IEEE 754 41b3de4355555555, le nombre de l'exemple de la RFC 8785 §3.2.2) ; entrée non canonique équivalente. |
| `rfc8785-b-23-41b3de4355555556` | `333333333.3333334` | RFC 8785, annexe B, ligne 23 (IEEE 754 41b3de4355555556) ; entrée canonique. |
| `rfc8785-b-24-41b3de4355555557` | `333333333.33333343` | RFC 8785, annexe B, ligne 24 (IEEE 754 41b3de4355555557) ; entrée non canonique équivalente. |
| `rfc8785-b-25-becbf647612f3696` | `-0.0000033333333333333333` | RFC 8785, annexe B, ligne 25 (IEEE 754 becbf647612f3696) ; entrée non canonique équivalente. |
| `rfc8785-b-26-43143ff3c1cb0959` | `1424953923781206.2` | RFC 8785, annexe B, ligne 26 (IEEE 754 43143ff3c1cb0959, arrondi au pair, note (4)) ; entrée non canonique équivalente. |
| `rfc8785-b-infini-par-debordement` | refus | Texte JSON syntaxiquement valide dont la valeur déborde la double précision (Infinity) : refusé. |
| `rfc8785-exemple-3-2-2` | `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0…` | L'objet de la RFC 8785 §3.2.2 ; forme canonique de §3.2.3, octets UTF-8 de §3.2.4. |
| `rfc8785-tri-3-2-3` | `{"\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small …` | Données de tri de la RFC 8785 §3.2.3 : membres triés par unités de code UTF-16, valeurs dans l'ordre Carriage Return, One, Control, Latin Small Letter O With Diaeresis, Euro Sign, Emoji: Grinning Face, Hebrew Letter Dalet With Dagesh. |
| `ct2-8-1-un` | `1` | CT-2 §8.1 |
| `ct2-8-1-un-virgule-zero` | `1` | CT-2 §8.1 : la valeur, pas le texte |
| `ct2-8-1-un-cinquante` | `1.5` | CT-2 §8.1 |
| `ct2-8-1-exposant` | `1000` | CT-2 §8.1 |
| `ct2-8-1-exposant-majuscule` | `100` | CT-2 §8.1 |
| `ct2-8-1-1e21` | `1e+21` | CT-2 §8.1 : seuil de la notation exponentielle en ES6 |
| `ct2-8-1-1e20` | `100000000000000000000` | CT-2 §8.1 |
| `ct2-8-1-moins-zero` | `0` | CT-2 §8.1 |
| `ct2-8-1-moins-zero-virgule` | `0` | CT-2 §8.1 |
| `ct2-8-1-un-millionieme` | `0.000001` | CT-2 §8.1 |
| `ct2-8-1-un-dix-millionieme` | `1e-7` | CT-2 §8.1 |
| `ct2-8-1-plus-petit-denormalise` | `5e-324` | CT-2 §8.1 |
| `ct2-8-1-perte-2-53` | `9007199254740992` | CT-2 §8.1 : perte au-delà de 2^53 (RFC 7493 §2.2) |
| `ct2-8-1-perte-grand-entier` | `1.2345678901234568e+29` | CT-2 §8.1 : perte |
| `ct2-8-1-perte-decimales` | `3.141592653589793` | CT-2 §8.1 : perte de décimales |
| `ct1-4-tri-des-cles` | `{"a":2,"b":1}` | CT-1 §4 : tri des clés |
| `ct1-4-tri-utf16` | `{"Z":3,"z":2,"é":1}` | CT-1 §4 : unités UTF-16, Z (0x5A) < z (0x7A) < é (0xE9) |
| `ct1-4-cle-echappee` | `{"é":1}` | CT-1 §4 : la clé est décodée avant le tri, puis écrite en clair |
| `ct1-4-paire-de-substituts` | `{"a😀":1}` | CT-1 §4 : un caractère, quatre octets UTF-8 |
| `ct1-4-controle-minuscules` | `{"a":"x\u0001y"}` | CT-1 §4 : contrôle échappé en minuscules |
| `ct1-4-controle-majuscules-en-entree` | `{"a":"\u001f\u000b"}` | Contrôles échappés en majuscules à l'entrée, en minuscules à la sortie |
| `ct1-4-echappements-courts` | `{"a":"\b\t\n\f\r\"\\/"}` | Échappement minimal : formes courtes, / en clair |
| `ct1-4-u007f-en-clair` | `{"a":"\u007f"}` | CT-1 §4 : U+007F n'est pas échappé |
| `ct1-4-u2028-u2029-en-clair` | `{"a":"\u2028\u2029"}` | U+2028 et U+2029 en clair |
| `ct1-4-zero-negatif` | `{"a":0}` | CT-1 §4 : zéro négatif |
| `ct1-4-conteneurs-vides` | `{"a":[],"b":{}}` | CT-1 §4 |
| `ct1-4-non-entier-valide-en-integral` | `{"a":1}` | Invalide en JCS v0 (CT-1 §4), valide en JCS intégral : la valeur 1 |
| `ct1-4-exposant-valide-en-integral` | `{"a":1000}` | Invalide en JCS v0, valide en JCS intégral |
| `ct1-4-hors-intervalle-sur-perte` | `{"a":9007199254740992}` | Invalide en JCS v0 ; en JCS intégral la forme canonique n'est PAS l'entrée : perte au-delà de 2^53 (RFC 7493 §2.2) |
| `ct1-4-cle-en-double` | refus | CT-1 §4 : clé en double, invalide |
| `ct1-4-cle-en-double-apres-decodage` | refus | Clé en double après décodage, invalide |
| `ct1-4-substitut-haut-isole` | refus | CT-1 §4 : substitut isolé, invalide |
| `ct1-4-substitut-bas-isole` | refus | Substitut bas isolé, invalide |
| `nombres-dans-une-structure` | `{"a":0.1,"z":[1.1,-0.0025,{"x":0,"y":100}]}` | Nombres non entiers dans des objets et tableaux imbriqués |
| `nan-dans-un-objet` | refus | NaN n'est pas du JSON |
| `zero-de-tete` | refus | Zéro de tête : pas du JSON (RFC 8259) |
| `point-final` | refus | Partie fractionnaire vide : pas du JSON |
| `signe-plus` | refus | Signe + : pas du JSON |

## `redaction/`

`politique-pii-v1.json` : la politique de CT-2 §10.9, octets identiques au bloc
imprimé (plus un saut de ligne final) ; JCS intégral de 1462 octets, SHA-256
`0x9116aac6ee1d124d155ffb22acd39b1cf2270cac07b30b239e9996012d787f4e`.
`politique-pseudonyme-test.json` (`pii-pseudo-test`) : la même politique avec
l'action pseudonyme sur chaque règle et la clé de test ci-dessus.
`politique-regles-test.json` (`pii-regles-test`) : sélecteurs par pointeur JSON,
détecteur champ (remplacer, supprimer), motif nommé, règles enchaînées, puis les
cinq détecteurs ; elle porte les cas obligatoires que `pii-v1` ne peut pas
porter (elle n'a ni path, ni champ, ni regex appliquée).

`cas.json` : tableau d'objets `{ name, policy, scope, tool, input, expected, note }`.
`expected.piece` est le texte UTF-8 de la pièce stockée (JCS intégral de la
valeur rédigée, ou le texte pour une pièce text/plain : une entrée de type
chaîne est toujours une pièce texte, et `expected.media_type` vaut alors
`text/plain`) ; `sha256`, `length`, `redacted` forment la référence de CT-1 §5.4 ;
`matches` liste, règle par règle et détecteur par détecteur dans l'ordre
d'application, les correspondances comptées (EX-10.17), sans les détecteurs
qui n'ont rien trouvé ; `detector` vaut le type du détecteur (`iban`, `avs`,
`carte`, `email`, `telephone`, `regex`, `champ`). Pour chaque cas, réappliquer la
politique à la pièce stockée redonne les mêmes octets (EX-10.15).

| Cas | Politique | Portée | Pièce | Correspondances | Note |
|---|---|---|---|---|---|
| `iban-compact-valide` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/iban × 1 | IBAN suisse de l'exemple de CT-2 §10.3.2, forme compacte : reste 1 au MOD 97-10. |
| `iban-groupes-valide` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/iban × 1 | Même IBAN en groupes de quatre séparés par des espaces : même forme normalisée, valide ; la correspondance va du C au dernier chiffre, séparateurs compris. |
| `iban-compact-invalide` | pii-v1 | arguments | inchangée | — | Dernier chiffre modifié : reste 28, somme de contrôle fausse, non rédigé. |
| `iban-groupes-invalide` | pii-v1 | arguments | inchangée | — | Forme groupée à somme de contrôle fausse : non rédigée (ni comme IBAN, ni comme carte : la suite de chiffres commence après une lettre). |
| `iban-pays-ch` | pii-v1 | resultat | rédigée | identifiants-arguments-resultat/iban × 1 | IBAN CH de 21 caractères construit par la méthode de génération (clé = 98 − reste), groupes de quatre. |
| `iban-pays-li` | pii-v1 | resultat | rédigée | identifiants-arguments-resultat/iban × 1 | IBAN LI de 21 caractères construit par la méthode de génération (clé = 98 − reste), forme compacte. |
| `iban-pays-de` | pii-v1 | resultat | rédigée | identifiants-arguments-resultat/iban × 1 | IBAN DE de 22 caractères construit par la méthode de génération (clé = 98 − reste), forme compacte. |
| `iban-pays-fr` | pii-v1 | resultat | rédigée | identifiants-arguments-resultat/iban × 1 | IBAN FR de 27 caractères construit par la méthode de génération (clé = 98 − reste), groupes de quatre. |
| `iban-pays-it` | pii-v1 | resultat | rédigée | identifiants-arguments-resultat/iban × 1 | IBAN IT de 27 caractères construit par la méthode de génération (clé = 98 − reste), forme compacte. |
| `iban-pays-at` | pii-v1 | resultat | rédigée | identifiants-arguments-resultat/iban × 1 | IBAN AT de 20 caractères construit par la méthode de génération (clé = 98 − reste), forme compacte. |
| `iban-pays-es` | pii-v1 | resultat | rédigée | identifiants-arguments-resultat/iban × 1 | IBAN ES de 24 caractères construit par la méthode de génération (clé = 98 − reste), forme compacte. |
| `iban-pays-nl` | pii-v1 | resultat | rédigée | identifiants-arguments-resultat/iban × 1 | IBAN NL de 18 caractères construit par la méthode de génération (clé = 98 − reste), forme compacte. |
| `iban-pays-be` | pii-v1 | resultat | rédigée | identifiants-arguments-resultat/iban × 1 | IBAN BE de 16 caractères construit par la méthode de génération (clé = 98 − reste), groupes de quatre. |
| `iban-pays-gb` | pii-v1 | resultat | rédigée | identifiants-arguments-resultat/iban × 1 | IBAN GB de 22 caractères construit par la méthode de génération (clé = 98 − reste), groupes de quatre. |
| `iban-pays-lu` | pii-v1 | resultat | rédigée | identifiants-arguments-resultat/iban × 1 | IBAN LU de 20 caractères construit par la méthode de génération (clé = 98 − reste), forme compacte. |
| `iban-exemple-pay-uk` | pii-v1 | resultat | rédigée | identifiants-arguments-resultat/iban × 1 | Exemple Pay.UK cité en CT-2 §10.3.2 (BBAN avec lettres). |
| `iban-hors-table` | pii-v1 | resultat | inchangée | — | IBAN norvégien NO9386011117947, somme de contrôle valide, pays hors de la table de CT-2 §10.3.2 : non détecté en version 0 (§10.8). |
| `iban-minuscules` | pii-v1 | resultat | inchangée | — | IBAN en minuscules : non détecté en version 0 (CT-2 §10.8). |
| `avs-compact-valide` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/avs × 1 | Numéro AVS de l'exemple de l'ordonnance, sans séparateur : clé 7. |
| `avs-points-valide` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/avs × 1 | Écriture 756.XXXX.XXXX.XX de l'OFAS. |
| `avs-espaces-valide` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/avs × 1 | Séparateurs espaces, tous identiques. |
| `avs-points-invalide` | pii-v1 | arguments | inchangée | — | Clé de contrôle fausse (0 au lieu de 7) : non rédigé. |
| `avs-compact-invalide` | pii-v1 | arguments | inchangée | — | Treize chiffres sans séparateur, clé fausse : non rédigé par avs ; la suite ne passe pas non plus Luhn (carte). |
| `avs-separateurs-mixtes` | pii-v1 | arguments | inchangée | — | Séparateurs présents mais différents (point puis espace) : pas un candidat AVS (CT-2 §10.3.3, pas 1). |
| `carte-compacte-valide` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/carte × 1 | Quinze chiffres commençant par 37, passe Luhn. |
| `carte-espaces-valide` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/carte × 1 | Même numéro groupé par espaces. |
| `carte-tirets-valide` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/carte × 1 | Même numéro groupé par traits d'union. |
| `carte-invalide` | pii-v1 | arguments | inchangée | — | Dernier chiffre modifié : ne passe pas Luhn. |
| `carte-points-non-detectee` | pii-v1 | arguments | inchangée | — | Numéro valide écrit avec des points : le point n'est pas un séparateur de carte (CT-2 §10.3.4, §10.8). |
| `email-valide` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/email × 1 | Forme Dot-string@Domain. |
| `email-suivi-d-un-point` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/email × 1 | Adresse suivie du point final d'une phrase : le point n'appartient pas au domaine, l'adresse est rédigée et le point reste (CT-2 §10.3.5, pas 1). |
| `email-suivi-d-un-tiret` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/email × 1 | Adresse suivie d'un trait d'union puis d'une espace : le trait d'union final n'appartient pas au domaine. |
| `email-points-doubles` | pii-v1 | arguments | inchangée | — | Partie locale à deux points consécutifs (pas une Dot-string) et domaine à un seul label : non rédigés. |
| `email-long` | pii-v1 | resultat | rédigée | identifiants-arguments-resultat/email × 1 | Vecteur de coût (EX-10.23) : 20 000 caractères de partie locale avant le premier @ (au-delà de 64 : aucun candidat, lecture bornée), puis une adresse rédigée ; une recherche qui reprend « un caractère plus loin » après chaque rejet est quadratique sur ce texte, la lecture bornée à partir de chaque @ est linéaire. |
| `email-dernier-label-court` | pii-v1 | arguments | inchangée | — | Dernier label du domaine d'une seule lettre : validation refusée, non rédigé. |
| `email-partie-locale-64` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/email × 1 | Partie locale de 64 octets : la borne de la RFC 5321 §4.5.3.1.1, rédigée. |
| `email-partie-locale-65` | pii-v1 | arguments | inchangée | — | Partie locale de 65 octets : au-delà de la borne, non rédigée (aucune sous-adresse n'est retenue, la frontière avant l'interdit). |
| `telephone-valide` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/telephone × 1 | Forme internationale de l'exemple de CT-2 §10.3.6. |
| `telephone-compact-valide` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/telephone × 1 | Même numéro sans séparateur. |
| `telephone-trop-court` | pii-v1 | arguments | inchangée | — | Sept chiffres : sous la longueur minimale de 8, non rédigé. |
| `telephone-quinze-chiffres` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/telephone × 1 | Quinze chiffres, la borne d'E.164 : rédigé (la suite ne passe pas Luhn, le détecteur carte qui précède ne la prend pas). |
| `telephone-seize-chiffres` | pii-v1 | arguments | inchangée | — | Seize chiffres : au-delà de la borne d'E.164, non rédigé (ni comme carte : ne passe pas Luhn). |
| `telephone-national-non-detecte` | pii-v1 | arguments | inchangée | — | Forme nationale sans + : non détectée en version 0 (CT-2 §10.8). |
| `telephone-parenthese-horaire` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/telephone × 1 | Une « ( » qui ne se referme pas sur des chiffres termine le candidat avant elle : le plus long préfixe valide est rédigé (CT-2 §10.3.6). |
| `telephone-groupe-final` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/telephone × 1 | Un groupe (chiffres) que rien ne suit n'entre pas dans le candidat. |
| `telephone-groupe-colle` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/telephone × 1 | Groupe collé suivi d'une lettre : le candidat s'arrête avant la « ( », qui est une frontière. |
| `telephone-groupe-interne` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/telephone × 1 | Groupe (0) suivi de chiffres : il fait partie du candidat, ses chiffres comptent (douze). |
| `telephone-colles` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/telephone × 2 | Deux numéros collés : la fin de la première correspondance vaut frontière pour la seconde (EX-10.9) ; la pièce est idempotente (EX-10.15). |
| `faux-positifs` | pii-v1 | arguments | inchangée | — | Montant, date, heure, numéro de dossier, référence, code pays seul, seize chiffres qui ne passent pas Luhn, numéro de carte précédé de lettres (pas de frontière) et numéro de carte porté par un nombre JSON (jamais examiné, EX-10.5) : rien n'est rédigé. |
| `exemple-10-9-arguments` | pii-v1 | arguments | rédigée | identifiants-arguments-resultat/iban × 1 | Premier exemple de CT-2 §10.9 (arguments de CT-1 §5.5) : 96 octets, valeur de l'annexe A de CT-2. |
| `exemple-10-9-texte-libre` | pii-v1 | resultat | rédigée | identifiants-arguments-resultat/iban × 1, identifiants-arguments-resultat/avs × 1, identifiants-arguments-resultat/carte × 1, identifiants-arguments-resultat/email × 1, identifiants-arguments-resultat/telephone × 1 | Second exemple de CT-2 §10.9 : cinq détecteurs, cinq correspondances, 148 octets. |
| `idempotence-piece-deja-redigee` | pii-v1 | arguments | inchangée | — | L'entrée est la pièce déjà rédigée : la politique ne la change pas, redacted faux, octets identiques (EX-10.15). |
| `portee-requete` | pii-v1 | requete | rédigée | identifiants-modele/telephone × 1 | Portée requete : corps d'une requête de modèle, règle à tools "*" ; le numéro de sinistre n'est pas une donnée personnelle et reste. |
| `portee-reponse` | pii-v1 | reponse | rédigée | identifiants-modele/email × 1 | Portée reponse : une réponse de l'API Messages. |
| `portee-prompt-systeme` | pii-v1 | prompt_systeme | rédigée | identifiants-modele/email × 1 | Portée prompt_systeme : la pièce est le texte UTF-8 (text/plain), la racine est la chaîne (EX-10.19). |
| `portee-prompt-systeme-intact` | pii-v1 | prompt_systeme | inchangée | — | Prompt sans donnée détectée : stocké en clair, redacted faux (CT-1 §15 : risque de confirmation par dictionnaire, EX-10.19). |
| `portee-contexte-json` | pii-v1 | contexte | rédigée | identifiants-contexte/iban × 1, identifiants-contexte/telephone × 1 | Portée contexte : document JSON remis par le SDK. |
| `portee-contexte-texte` | pii-v1 | contexte | rédigée | identifiants-contexte/iban × 1 | Portée contexte : document text/plain, racine = la chaîne. |
| `champ-sur-nombre` | pii-regles-test | arguments | rédigée | montant-champ/champ × 1 | Sélecteur path + détecteur champ, action remplacer : le nombre JSON désigné devient la chaîne jeton (EX-10.11). |
| `champ-outil-non-vise` | pii-regles-test | arguments | inchangée | — | La règle montant-champ vise demo__payments.create seulement : pour demo__claims.get elle ne s'applique pas. |
| `supprimer-membre` | pii-regles-test | resultat | rédigée | note-interne-supprimee/champ × 1 | Action supprimer sur un membre (tools demo__*) : le membre est retiré de son objet parent. |
| `supprimer-element` | pii-regles-test | arguments | rédigée | copie-supprimee/champ × 1 | Action supprimer sur un élément de tableau : remplacé par le jeton, les indices ne bougent pas (CT-2 §10.2.3). |
| `motif-nomme` | pii-regles-test | resultat | rédigée | numero-sinistre/regex × 2 | Motif nommé numero-sinistre (RE2 \b20[0-9]{2}-[0-9]{5}\b) : deux correspondances. |
| `passages-multiples` | pii-regles-test | contexte | rédigée | iban-contexte/iban × 1, telephone-contexte/telephone × 1 | Règles telephone-contexte puis iban-contexte : au premier passage, le « + » suit un chiffre et n'est pas une frontière ; l'IBAN rédigé, son jeton en fait une ; le second passage rédige le téléphone (EX-10.14). |
| `jeton-opaque` | pii-v1 | contexte | inchangée | — | Un jeton de pseudonyme dont les douze chiffres (378282246313) passent Luhn n'est pas une carte : les détecteurs ne voient pas l'intérieur d'un jeton (EX-10.9). |
| `regles-enchainees` | pii-regles-test | resultat | rédigée | note-interne-supprimee/champ × 1, numero-sinistre/regex × 1, identifiants/iban × 1 | Trois règles modifient la même pièce, dans l'ordre : note-interne-supprimee, numero-sinistre puis identifiants ; montant-champ et copie-supprimee ne s'appliquent pas (portée), sans erreur. |
| `pointeur-non-resolu` | pii-regles-test | arguments | inchangée | — | Le pointeur /amount_cents ne résout pas : la règle est sans effet pour cette pièce, sans erreur (note du journal d'exploitation). |
| `pseudonyme-iban` | pii-pseudo-test | arguments | rédigée | identifiants-arguments-resultat/iban × 1 | Valeur normalisée CH9300762011623852957 : le jeton de CT-2 §10.9 ; la forme groupée et la forme compacte donnent le même pseudonyme. |
| `pseudonyme-avs` | pii-pseudo-test | arguments | rédigée | identifiants-arguments-resultat/avs × 1 | Valeur normalisée : les treize chiffres. |
| `pseudonyme-carte` | pii-pseudo-test | arguments | rédigée | identifiants-arguments-resultat/carte × 1 | Valeur normalisée : les chiffres seuls. |
| `pseudonyme-email` | pii-pseudo-test | arguments | rédigée | identifiants-arguments-resultat/email × 1 | Domaine ramené en minuscules ASCII, partie locale telle quelle : même jeton que j.dupont@example.ch (CT-2 §10.9). |
| `pseudonyme-telephone` | pii-pseudo-test | arguments | rédigée | identifiants-arguments-resultat/telephone × 1 | Valeur normalisée : + suivi des chiffres. |
| `pseudonyme-champ-chaine` | pii-pseudo-test | arguments | rédigée | iban-champ/champ × 1, identifiants-arguments-resultat/iban × 1 | Règle champ (étiquette iban) sur une chaîne et détecteur iban dans le texte : le pseudonyme de champ est calculé sur la chaîne elle-même, d'où le même jeton (EX-10.11, EX-10.13). |

## `pieces-mcp/`

**`appels/<cas>/`** : un `tools/call` reçu d'un hôte. `hote.jsonl` et `amont.jsonl` : une
enveloppe `{"dir","t","line"}` par message JSON-RPC échangé, `line` étant le texte
exact (une ligne stdio, ou le corps d'un POST quand `transports.host` vaut `http`) ;
`{"dir":"in","t","eof":true}` marque la fin de fichier sur la sortie standard d'un
serveur stdio. `hote.jsonl` commence par l'échange `tools/list` qui sert la liste à
la connexion d'hôte (EX-4.13, EX-4.45). `attendu.json` : nom annoncé, nom d'origine,
alias, classe (de la définition courante), `rejected` (refus au pas 1 : ni pièce ni
événement), pièces « arguments », « résultat », « définition d'outil » servie,
définition courante si elle diffère (sinon null) et « liste annoncée » (référence et
octets), `context` (EX-4.45, EX-7.7), `is_error`, `duration_ms` (`t_reponse − t_envoi` ;
pour une issue sans réponse, `t_reponse` suit EX-4.48), l'erreur rendue à l'hôte, les
deux ères (`protocols`) et les deux transports (`transports`). Les arguments sont
rédigés par `pii-v1`. La ligne amont recopie les arguments reçus, blancs non
significatifs retirés (EX-4.20, EX-4.43) ; la réponse rendue recopie `result` de même,
avec les deux réécritures de 4.4 pas 14 (`_meta` `io.modelcontextprotocol/serverInfo`
posé à l'identité de l'enregistreur, inséré en fin de `result` quand `_meta` manque ;
`resultType: "complete"` inséré en tête quand il manque et que l'hôte est moderne) et
l'`id` de l'hôte recopié depuis son texte.

| Cas | Outil | is_error | Erreur rendue | Note |
|---|---|---|---|---|
| `arguments-non-canonisables/` | refus au pas 1 | — | -32602 | Un nombre hors de la double précision (1e400) : le JCS intégral ne sait pas l'écrire ; refus -32602 data.reason arguments_non_canonisables, id null (l'analyse stricte s'arrête), sans relais, sans pièce, sans événement (EX-4.44). |
| `arguments-non-entiers/` | `demo__claims.search` (lecture) | faux | — | Arguments portant des nombres non entiers exactement représentables : la pièce est en JCS intégral (1.0 → 1, 1e3 → 1000), la ligne relayée garde les octets d'origine (EX-4.20) ; les trois nombres ont la même valeur décimale que leur forme (EX-4.44). Le résultat porte aussi un nombre non entier (0.8125). |
| `blancs-non-significatifs/` | `demo__claims.get` (lecture) | faux | — | Requête de l'hôte et réponse du serveur avec espaces et tabulations entre les jetons : les octets relayés (arguments vers le serveur, result vers l'hôte) sont recopiés blancs non significatifs retirés, sans autre changement (EX-4.20, EX-4.43). |
| `corps-http-multiligne/` | `demo__claims.search` (lecture) | faux | — | Corps POST Streamable HTTP valide dont les blancs entre jetons sont des CRLF et des LF, et dont les arguments portent, entre deux sauts de ligne, un message JSON-RPC complet : admis (le cadrage par corps n'interdit pas CR), relayé au serveur stdio en une seule ligne, blancs retirés ; sans EX-4.43, un serveur stdio lirait le message enchâssé comme un second appel, hors politique et hors chaîne. |
| `definition-servie-differente/` | `demo__claims.get` (lecture) | faux | — | La liste servie à cette connexion d'hôte portait une description piégée de demo__claims.get ; le serveur l'a remplacée depuis : context porte, dans cet ordre, la définition servie, la définition courante (autre sha256) et la liste annoncée servie (EX-4.45, EX-7.7) ; la classe vient de la définition courante (4.4 pas 2). |
| `delai/` | `demo__claims.search` (lecture) | vrai | -32011 | Délai de l'outil (policy.servers.demo.tools["claims.search"].timeout_ms = 30000) écoulé : t_reponse = t_envoi + timeout_ms (EX-4.48), annulation amont à cet instant (stdio : notifications/cancelled avec le requestId amont), événement is_error vrai avec la pièce -32011, erreur -32011 rendue ; la réponse amont tardive est ignorée (EX-4.22). |
| `erreur-jsonrpc/` | `demo__claims.get` (lecture) | vrai | -32602 | Erreur de protocole JSON-RPC du serveur : pièce {"noortrace_jsonrpc_error": error}, is_error vrai ; l'erreur est rendue à l'hôte avec le même code, le même message et le même data, et l'id de l'hôte (4.4 pas 12 et 14). |
| `execute-ecriture/` | `demo__payments.create` (ecriture) | faux | — | Appel d'écriture relayé après approbation, celui de seq 7 de evenements/journal-demo : arguments rédigés (IBAN groupé → [REDIGE:iban]), octets des arguments recopiés dans la ligne amont, résultat avec structuredContent, réponse rendue avec serverInfo de l'enregistreur. La clé _meta noortrace/delegation déclarée par l'hôte est relayée telle quelle (4.4 pas 9). context : la définition servie à l'hôte par le tools/list qui précède, puis la liste annoncée (EX-4.45). |
| `hote-herite-serveur-moderne/` | `demo__claims.get` (lecture) | faux | — | Hôte de l'ère héritée (poignée de main initialize faite à la connexion, id numérique, aucun _meta) vers un serveur moderne : le frontal ajoute les _meta requis (protocolVersion, clientCapabilities, clientInfo de l'enregistreur) ; la réponse est rendue avec l'id numérique de l'hôte et serverInfo. |
| `hote-moderne-serveur-herite/` | `archives__documents.get` (lecture) | faux | — | Hôte moderne vers un serveur hérité : sonde server/discover refusée (-32601, erreur non moderne), bascule en initialize (EX-4.6), puis tools/call avec la version négociée avec ce serveur ; le résultat reçu n'a pas de resultType : la pièce le garde tel quel (avant réécriture), la réponse rendue à l'hôte moderne reçoit resultType complete en tête et serverInfo (4.4 pas 14). |
| `id-entier-long/` | `demo__claims.get` (lecture) | faux | — | L'id de la requête de l'hôte est un entier au-delà de 2^53 : la réponse rendue recopie ses octets depuis le texte reçu (12345678901234567890), sans passer par la double précision (4.4 pas 14) ; l'id amont est l'identifiant propre du frontal. |
| `injoignable/` | `demo__payments.create` (ecriture) | vrai | -32014 | Le processus du serveur stdio se termine après l'envoi, avant toute réponse : l'enveloppe {"dir":"in","t":…,"eof":true} marque la fin de fichier sur sa sortie standard, instant qui est t_reponse (EX-4.48). Appel d'écriture déjà relayé (son intention existait), événement is_error vrai avec la pièce -32014, erreur -32014 rendue (EX-4.33, matrice de 14.2). |
| `input-required/` | `demo__payments.create` (ecriture) | faux | — | Résultat intermédiaire MRTR (resultType input_required, une elicitation) : relayé tel quel, événement à is_error faux dont la pièce est le result entier (EX-4.21) ; la ré-émission de l'hôte serait un second appel. L'hôte a déclaré elicitation, transmise au serveur (EX-4.7, EX-4.28). |
| `ligne-avec-cr/` | refus au pas 1 | — | -32700 | Une ligne stdio qui contient un CR (U+000D, ici comme blanc après les arguments) : refus -32700 data.reason cr_dans_la_ligne, id null, sans relais (EX-4.43) ; un serveur stdio Python lirait CR comme une fin de ligne. |
| `lot-refuse/` | refus au pas 1 | — | -32600 | Un lot JSON-RPC (tableau) reçu de l'hôte : une seule erreur -32600, id null, data.reason lot_non_pris_en_charge, aucun élément relayé (EX-4.3). |
| `nombre-non-representable/` | refus au pas 1 | — | -32602 | Un entier au-delà de 2^53 dans les arguments : sa forme JCS intégral (12345678901234567000) n'a pas la valeur reçue ; refus -32602 data.reason nombre_non_representable avec l'id de la requête, sans relais, sans pièce, sans événement (EX-4.44). |
| `resultat-is-error/` | `demo__claims.get` (lecture) | vrai | — | Erreur d'exécution de l'outil (isError: true dans le résultat, page Tools) : la pièce est le result entier, is_error vrai ; la réponse est rendue normalement. |
| `resultat-non-objet/` | `demo__claims.get` (lecture) | vrai | -32603 | Le serveur répond un result qui est une chaîne : erreur de protocole du serveur ; pièce {"noortrace_jsonrpc_error": {code -32603, message « noortrace: resultat amont invalide », data.result_type string}}, is_error vrai, même erreur rendue à l'hôte (4.4 pas 12 et 14). |
| `taille-depassee/` | `demo__claims.search` (lecture) | vrai | -32013 | Réponse amont au-delà de limits.response_max_bytes (512 octets pour ce cas) : lecture arrêtée à la borne (t_reponse, EX-4.48), connexion amont fermée, événement is_error vrai avec la pièce -32013 (direction reponse), erreur -32013 rendue (4.4 pas 11). |

**`agregation/`** : `serveurs.json` (tableau de serveurs `{ alias, tools }`) et
`attendu.json` (`prefix`, `page_size`, `announced` avec `definition_sha256`,
`rejected` avec la raison `nom_reserve`, `nom_invalide` ou `collision`, `pages`).
Trois cas séparés dans des sous-répertoires de même forme : `normalisation/`
(`normalisations` : gabarit et normalisation d'une connexion d'hôte, deux noms qui
deviennent identiques sont tous deux rejetés, EX-4.11 règle 3), `sans-prefixe/`
(préfixe désactivé avec deux serveurs : configuration refusée, `configuration_refusee: true`)
et `sans-prefixe-un-serveur/` (préfixe désactivé, un serveur, collision interne).

## `pieces-modele/`

Un répertoire par cas : `requete.json` (corps reçu, mise en forme libre),
`requete-entetes.json` (sans en-tête d'authentification), `reponse.json` (hors flux)
ou `reponse.sse` (transcription SSE, octets exacts, LF), `reponse-entetes.json`
(statut HTTP, `content-type` et identifiant de requête du fournisseur : le statut
et le type de média décident du traitement, 5.3.1), `attendu.json` :
`options` (`prompt_in_request`, `prompt_system`), `refused` (refus de la passerelle,
EX-5.7 : `status`, `reason`, `body` ; la requête est alors dans `requete.brut`, octets
exacts, et il n'y a ni réponse ni pièce), `consolidated` (forme consolidée en clair,
null hors flux), pièces « requête »,
« réponse », « prompt système » et « intention » (référence et octets, null si
absente), `code_model`, `prompt_version`, `intent` (chaîne, référence text/plain ou
null), `tool_calls` (en clair : `arguments` est l'objet `input` pour l'API Messages,
la chaîne reçue pour OpenAI), `is_error`, `incomplete`. La politique est `pii-v1` ;
`prompt_in_request` vaut `reference` (le prompt système est remplacé par
`[REDIGE:prompt-systeme]` dans la pièce « requête », ce qui la marque rédigée), sauf
pour `openai-chat-prompt-inline/` (`inline` : prompt laissé en place, rédigé).
Les transcriptions sont écrites à la main d'après les formes documentées
(digest R2) ; les identifiants et noms de modèles sont fictifs. Les noms d'outils
vus par le modèle n'ont pas de point (l'API Messages et Chat Completions le
refusent) : `demo__claims_get` pour l'outil annoncé `demo__claims.get`.

| Cas | Format, route | code.model | intent | is_error | Note |
|---|---|---|---|---|---|
| `anthropic-messages-erreur-http/` | anthropic-messages, `/v1/messages` | `anthropic/modele-messages-exemple` | null | vrai | Statut 529 : pièce « réponse » {"noortrace_http_error": {status, content_type, body}} avec le corps d'erreur entier (F-A32), is_error vrai ; code.model tiré de la requête faute de réponse exploitable ; pas de prompt système, prompt_version null ; la requête n'est pas rédigée (redacted faux). |
| `anthropic-messages-flux/` | anthropic-messages, `/v1/messages` | `anthropic/modele-messages-exemple` | référence | faux | Flux SSE texte seul, avec un ping : forme consolidée = message de message_start, texte accumulé, stop_reason et usage cumulatif de message_delta (output_tokens remplacé, input_tokens conservé). L'intention contient une adresse : rédigée, elle devient une référence text/plain (EX-5.21). |
| `anthropic-messages-flux-bom/` | anthropic-messages, `/v1/messages` | `anthropic/modele-messages-exemple` | chaîne | faux | Transcription précédée d'une marque d'ordre d'octets (EF BB BF) : l'analyseur la retire avant la première ligne (HTML Living Standard, « Parsing an event stream »), le premier événement est message_start. |
| `anthropic-messages-flux-incomplet/` | anthropic-messages, `/v1/messages` | `anthropic/modele-messages-exemple` | chaîne | vrai, incomplet | Flux coupé par le fournisseur au milieu d'un événement, avant message_stop : l'événement inachevé n'est pas distribué (5.4.1), la forme consolidée porte noortrace_flux_incomplet: true, is_error vrai (EX-5.13). |
| `anthropic-messages-flux-outil/` | anthropic-messages, `/v1/messages` | `anthropic/modele-messages-exemple` | chaîne | faux | Flux avec un bloc tool_use : tampon des input_json_delta (premier fragment vide, F-A27), analysé au content_block_stop ; l'IBAN de input est rédigé dans la pièce « réponse » ; tool_calls rend input en clair (il sert à la corrélation, EX-5.22). |
| `anthropic-messages-non-flux/` | anthropic-messages, `/v1/messages` | `anthropic/modele-messages-exemple` | chaîne | faux | Réponse hors flux : la pièce « réponse » est le JCS intégral du corps reçu. Prompt système en deux blocs TextBlockParam joints par \n, rédigé (adresse) : pièce text/plain dont le SHA-256 est code.prompt_version ; dans la pièce « requête », system devient [REDIGE:prompt-systeme] (EX-8.5), ce qui la marque redacted. |
| `anthropic-messages-reponse-non-json/` | anthropic-messages, `/v1/messages` | `anthropic/modele-messages-exemple` | null | vrai | Statut 200 dont le corps n'est pas du JSON (Content-Type Text/HTML avec paramètre) : media_type text/html (minuscules, sans paramètre) ; le texte UTF-8 est rédigé par les règles de portée reponse (adresse → [REDIGE:email]), pièce redacted ; aucune forme exploitable, is_error vrai, intent null, code.model tiré de la requête (5.3.1, EX-8.7). |
| `anthropic-messages-requete-non-analysable/` | anthropic-messages, `/v1/messages` | — | — | refus 400 (corps_non_analysable) | Corps de requête tronqué (JSON invalide) : la passerelle répond 400 avec un corps d'erreur au format du fournisseur (type invalid_request_error), ne relaie rien et n'écrit aucun événement (EX-5.7) ; requete.brut porte les octets reçus. |
| `bedrock-mantle-non-flux/` | anthropic-messages, `/anthropic/v1/messages` | `bedrock-mantle/anthropic.modele-messages-exemple` | chaîne | faux | Même corps que l'API Messages, route distincte, libellé bedrock-mantle ; le model de la réponse porte le préfixe anthropic. (F-A34) : code.model = bedrock-mantle/anthropic.modele-messages-exemple. |
| `openai-chat-flux/` | openai-chat, `/v1/chat/completions` | `openai/modele-chat-exemple` | chaîne | faux | Chunks data seuls, un commentaire SSE, champ obfuscation jamais recopié, usage du dernier chunk (include_usage), fin par data: [DONE] (EX-5.16). |
| `openai-chat-flux-outils/` | openai-chat, `/v1/chat/completions` | `openai/modele-chat-exemple` | null | faux | Deux appels d'outils accumulés par index : id, type et function.name fixés par le premier fragment qui les porte, function.arguments concaténé et gardé en chaîne, jamais analysé pour la pièce (F-O10) ; content reste null, intent null. |
| `openai-chat-non-flux/` | openai-chat, `/v1/chat/completions` | `openai/modele-chat-exemple` | chaîne | faux | Prompt système = contenus des messages developer et system dans l'ordre (chaîne, ou text des parties), joints par \n ; chacun est remplacé par [REDIGE:prompt-systeme] dans la pièce « requête ». intent = choices[0].message.content. |
| `openai-chat-prompt-inline/` | openai-chat, `/v1/chat/completions` | `openai/modele-chat-exemple` | chaîne | faux | prompt_in_request: inline : le prompt système reste dans la pièce « requête », chaque partie text rédigée par les règles de portée prompt_systeme (l'adresse devient [REDIGE:email]) ; la pièce « prompt système » (parties jointes par \n, rédigée) donne toujours code.prompt_version (EX-8.5). |
| `openai-responses-flux/` | openai-responses, `/v1/responses` | `openai/modele-responses-exemple` | chaîne | faux | Événements typés (data seules) jusqu'à response.completed : la forme consolidée est l'objet response de ce dernier événement, les deltas ne sont pas accumulés (EX-5.17). Prompt système = instructions puis l'item developer de input, joints par \n. |
| `openai-responses-flux-incomplet/` | openai-responses, `/v1/responses` | `openai/modele-responses-exemple` | chaîne | vrai, incomplet | Flux arrêté avant tout événement terminal : forme = response du dernier response.in_progress, noortrace_flux_incomplet: true, et output complété par les items de response.output_item.done reçus (le message ; l'appel d'outil inachevé n'y est pas) ; is_error vrai. |

## `evenements/journal-demo/`

La courte exécution de la démonstration de référence (CT-2 §19.2), chaînée avec
`rec-test-01` et vérifiable par les outils de CT-1 (`verifierChaine`,
`scripts/verify/dossier.mjs`) :

| seq | ts | Outil | hash |
|---|---|---|---|
| 1 | `2026-11-10T10:14:02.115Z` | `noortrace.journal.politique` | `0x5e537eda63b8cc8a7594d12ada66d9390121497aee3b28179cf483153c2be9bb` |
| 2 | `2026-11-10T10:14:05.906Z` | `noortrace.modele.echange` | `0x380d228a5d2f42111eeeb66176f7cbad439797617faf52d04e5ed9c61a95bd1a` |
| 3 | `2026-11-10T10:14:06.209Z` | `demo__claims.get (executee)` | `0xdcd1599fc1e60bbb6d1500c3b8fd46f0c36cf4c72460ee803ee1fdc070409766` |
| 4 | `2026-11-10T10:14:07.657Z` | `noortrace.modele.echange` | `0xa41a64abac691ea1a366fced46372bfa27108af6f74a2d46f019102211470711` |
| 5 | `2026-11-10T10:14:07.805Z` | `demo__payments.create (retenue)` | `0x7cfe6351df89a865292782d733fe1296f99e659d5627f3314ec8753801d15caf` |
| 6 | `2026-11-10T10:21:33.250Z` | `noortrace.approbation.decision` | `0x405f9d441acb3f22eed81d2c8448acef5bdc6bf94ea5c09e81383a6952c3c9cc` |
| 7 | `2026-11-10T10:21:35.431Z` | `demo__payments.create (executee)` | `0xfec51c4d6cad5f6689ddee02c5ac6c674f9ad6bf2597334adad1d9fddcb8fc85` |
| 8 | `2026-11-10T10:21:36.322Z` | `noortrace.modele.echange` | `0x0f6586838c44f405c571b117e190646720ff1a99a25a7741abf7649b9a679030` |

| Fichier | Contenu |
|---|---|
| `evenements.json` | les huit événements complets |
| `attendu.json` | chaîne valide, `hash`, `sig`, `prev_hash` et longueur canonique de chaque événement, objet `A` et `D_A` de la décision, `policy_sha256` (JCS intégral de `politique.json`, 3006 octets), `intention_sha256`, empreinte du segment, erreur -32015 rendue à seq 5, corrélations, période |
| `pieces.json` | les pièces stockées : définition d'outil, requêtes, réponses, prompts système, intentions rédigées, arguments, résultats, document d'ensemble de politique ; `media_type` null pour une pièce JSON |
| `cles.json` | `cles.json` des dossiers pour `rec-test-01` |
| `segment.ndjson` | l'en-tête de segment (`epoch: 1`, `first_seq: 1`) puis les huit lignes JCS v0, octets exacts (12.2) |
| `intentions.ndjson` | la ligne intention de seq 7 (`intent_id` `i-00000000000000000001-000000000001`), sa ligne contexte et sa levée (12.5) |
| `entrees.json` | les entrées brutes : l'entrée de connexion d'hôte `agent-demo` (groupe `demo`), les trois échanges de modèle (requête, type et corps de la réponse, `t_complet`), les trois `tools/call` (ligne reçue, `t_recu`, `inherits_from_seq`) et la liste servie, pour recalculer pièces et corrélation |
| `politique.json` | le membre `policy` de la configuration de démonstration (rédaction `pii-v1`), haché pour `policy_sha256` de seq 1 |
| `dossier-seq-7/` | le dossier CT-1 v0 de l'appel d'écriture relayé (seq 7), assemblé par `scripts/lib/journal.mjs`, et son `attendu.json` : valide, A-4 non exécuté avec raison admise |

Corrélation (EX-5.22) avec `tool_name_sanitize: true`, groupe `demo` et `run_id`
`run-demo-0001` : seq 3 et seq 5 trouvent leur bloc `tool_use` (seq 2 et seq 4) et
tirent `intent` de la réponse rédigée ; seq 7, ré-émission après approbation, ne passe
pas par la corrélation : elle reprend de seq 5 `policy`, `intent` et `code` (4.4 pas 3,
EX-7.12). Les effets sont évalués sur les valeurs rédigées des pièces (EX-7.6). Vérification du dossier :
`node scripts/verify/dossier.mjs spec/vecteurs/ct-2/evenements/journal-demo/dossier-seq-7` (code 0).
