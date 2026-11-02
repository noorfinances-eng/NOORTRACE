# Paquet `registre` : contrôle 8, N-4 et K-8

Contrôle 8 de CT-6 (§11) : inclusion des transactions du registre dans des
blocs certifiés par un quorum du jeu de validateurs que le réviseur déclare.
Le paquet exécute R-1 à R-11 (EX-11.10 à EX-11.19, EX-11.24), N-4 (EX-12.5)
et K-8 (EX-11.25), pose le statut du contrôle (EX-11.20), les faits
(EX-11.21, EX-11.25), la proposition de l'énoncé (EX-11.22) et les
avertissements AV-R-1 à AV-R-3, AV-K-1 et AV-K-3. Le contrat avec le moteur
est `interface.go` et `INTERFACES.md`, section « Contrôle 8 ».

Aucune entrée-sortie : tout est lu dans `Entree`. Dépendances : bibliothèque
standard (dont `encoding/json`, voir « Lectures », point 2),
`github.com/decred/dcrd/dcrec/secp256k1/v4` et son sous-paquet `ecdsa`, et
les paquets `ancres`, `commun`, `cryptographie` (Keccak-256, SHA-256),
`entree`, `jsonv`, `schema` du module.

## Fichiers

| Fichier | Contenu |
|---|---|
| `interface.go` | interface fixe (types, signatures, `IDs`, `DocTypePoint`) |
| `registre.go` | enchaînement de R-1 à R-11, N-4, K-8 ; statut, faits, avertissements, ancres employées |
| `lecture.go` | lecture de `registre.json`, `certificat-commit.json`, `validateurs.json` (jsonv, schémas embarqués), appariement de R-1 |
| `bloc.go` | `BFTBlockHash` (EX-11.4), RLP, bloom, encodage d'un reçu, trie des reçus (EX-11.5) |
| `certificat.go` | lecture des lignes (EX-11.6), condensé signé (EX-11.7), signature `R ‖ S ‖ V`, hachage d'un jeu et quorum (EX-11.8), R-5 d'un certificat (EX-11.14) |
| `journaux.go` | forme et décodage de `PeriodSubmitted`, `Anchored`, `RecorderRegistered` (EX-11.9) |
| `enonce.go` | proposition d'EX-11.22 (F6) et résumé (`summary`) |

## Tests

| Fichier | Ce qu'il vérifie |
|---|---|
| `vecteurs_test.go` | les 23 jeux de `spec/vecteurs/ct-6/registre/attendu.json` (7 jeux de parties, 16 variantes) : statut de R-1 à R-11 et N-4, statut et raison du contrôle 8, avertissements, proposition fr/en octet pour octet, faits |
| `dossiers_test.go` | les 73 dossiers de `spec/vecteurs/ct-6/dossiers`, entrée construite comme le moteur la construit : R-, N-4, K-8, statut du contrôle 8, AV-R-, AV-K-1, AV-K-3, fragment F6 dans l'énoncé attendu, inclusion du point |
| `calcul_test.go` | préimage et hachage BFT des huit blocs capturés et de l'exemple d'EX-11.4, encodage des reçus, racines (capture et `trie.json`), journaux décodés, sujets et `docType`, quorum, hachage du jeu, lignes canoniques, signature `R ‖ S ‖ V` (S haut, V hors de {0, 1}, longueur) |
| `scenarios_test.go`, `fabrique_test.go` | parties fabriquées (validateurs de clés connues) : chaque vérification en réussite et en échec, raisons de non-exécution, avertissements, faits, proposition à un et deux groupes |
| `hostile_test.go` | JSON tronqué, trop profond, octets quelconques, bornes de §15.1 dépassées, longueurs absurdes, lignes hostiles : aucune panique, échec de R-1, R-3 ou R-5 |
| `fuzz_test.go` | `FuzzRegistre` (les deux parties et tout le contrôle derrière), `FuzzLigne` (lecture et vérification d'une ligne) |

```bash
go test ./registre
go test -run '^$' -fuzz FuzzRegistre -fuzztime 60s -fuzzminimizetime 3s ./registre
go test -run '^$' -fuzz FuzzLigne -fuzztime 60s ./registre
```

Une exécution de `FuzzRegistre` vérifie une vingtaine de signatures : sans
`-fuzzminimizetime`, la minimisation d'une entrée nouvelle de plusieurs
dizaines de kilo-octets dure longtemps et le compteur d'exécutions reste à
zéro pendant ce temps.

## Lectures

Passages de CT-6 que le texte ne tranche pas, ou que l'interface ne permet
pas de suivre ; chaque point dit la section, le vecteur et la lecture
retenue.

1. **Présence de R-11, et interface insuffisante pour K-1 en échec.**
   INTERFACES.md demandait « les onze R- » et EX-11.24 dit « Aucune entrée
   `ancre_point_de_controle` : `non_execute` (`partie_absente`) ». Mais
   EX-6.18 garde aux cinquante dossiers antérieurs leurs vérifications non
   exécutées, et leurs `attendu.json` ne portent pas R-11
   (`valide-seq-7-complet`, `invalide-r1-sans-ancre`,
   `valide-point-de-controle-declare-absent`…) ; `INDEX.md` des vecteurs le
   dit : « R-11 ne figure au rapport qu'avec la partie
   `points-de-controle.json` déclarée présente ou une entrée
   `ancre_point_de_controle` ». Lecture retenue : R-11 figure si
   `Entree.Point` n'est pas nil ou si `registre.json` porte l'entrée (la ligne
   d'INTERFACES.md a été réécrite en ce sens).
   **Limite de l'interface** : `Entree.Point` est nil quand la partie est
   déclarée présente mais que K-1 échoue. Le paquet ne peut alors pas savoir
   que la partie est présente : `invalide-k1-partie-inexploitable` attend
   R-11 `partie_absente` (le paquet ne la fait pas figurer) et
   `invalide-k1-double-defaut` attend R-11 `prerequis_en_echec` (le paquet
   rend `partie_absente`, faute de savoir que K-2 n'a pas pu réussir). Les
   deux dossiers dépendent aussi des contrôles 4 et 5. Correction possible,
   à décider avec le moteur : un champ de `Entree` qui dit la partie
   déclarée présente (par exemple `PointDeclare bool`), ou un `Point` non
   nil avec un drapeau `K1`. Le test `dossiers_test.go` consigne ces deux
   écarts sans les compter comme des échecs.
2. **Lecture des lignes de certificat (EX-11.6).** EX-11.6 renvoie au
   `scripts/verify/README.md` de l'implémentation de référence, hors de la
   salle blanche. La règle est prise dans CT-4 §9.2 : « noms comparés sans la
   casse, dernière occurrence retenue, membres inconnus ignorés », corps
   `Proposal` et `Vote` du nœud, octets en base64 standard. Le nœud étant
   écrit en Go, le paquet décode les lignes avec `encoding/json` dans des
   types qui portent ces noms (hauteur et tour en `uint64`, hachages et
   signature en `[]byte`, corps en `json.RawMessage`, dont les octets
   d'origine donnent `bodyHash`). Une ligne acceptée est canonique si elle
   est égale, octet pour octet, à la sérialisation `encoding/json` de
   l'enveloppe décodée ; sinon AV-R-2. Le `blockHash` d'un corps se lit
   « 0x » ou « 0X » suivi de 64 chiffres hexadécimaux, sans casse imposée.
   Toutes les lignes capturées sont canoniques ; la ligne au membre
   `Domain` de `valide-ligne-non-canonique` est acceptée et lève AV-R-2.
3. **R-11, règle 3, quand R-10 n'a pas réussi.** EX-11.24 ne prévoit que
   deux cas : R-10 réussie qui prouve des inscriptions de la clé du point,
   ou aucune inscription de cette clé dans le dossier (AV-K-3). Lecture
   retenue : AV-K-3 si R-10 a réussi sans inscription de la clé du point, ou
   si R-10 est `non_execute` (`partie_absente`, aucune entrée
   `inscription`) ; si R-10 a échoué ou n'est pas exécutée faute de
   prérequis, les inscriptions ne sont pas prouvées, la règle 3 ne
   s'applique pas et R-11 est `non_execute` (`prerequis_en_echec`, EX-5.5).
   Aucun vecteur ne porte ce cas.
4. **AV-K-1.** Levé, sur K-8, quand la référence est vérifiée par K-8 et
   que la table de §11.9 le dit : parties du contrôle 8 absentes, entrée
   absente, ou R-11 `non_execute` pour une raison admise. R-11 en échec ou
   non exécutée faute de prérequis ne le lève pas
   (`invalide-r11-ancre-de-periode` : aucun AV-K-1). Une R-11 réussie dans
   un contrôle 8 qui ne réussit pas donne `inclusion` `declarative` sans
   AV-K-1 (le commentaire de `Resultat.FaitsPoint` dit « et AV-K-1 est
   levé » ; la table de §11.9 ne le lève pas : la table est suivie). Aucun
   vecteur ne porte ce cas.
5. **Noms en double.** CT-6 ne refuse pas un nom en double dans
   `registre.json`, `certificat-commit.json` ou `validateurs.json` : ils
   sont lus comme `JSON.parse` les lit (dernière occurrence, lecteur
   `jsonv`).
6. **Entiers que le rapport ne peut pas écrire.** L'identifiant de
   `PeriodSubmitted` (`uint256`, `topics[1]`) et `publishedAt` sont rendus en
   `int64` par l'interface (`EvenementCloture`). Une valeur au-delà de
   2^63 − 1 rend la forme du journal non conforme pour R-9, avec ce motif
   dans le détail. Un contrat réel n'en émet pas.
7. **Octets de remplissage (EX-11.9, EX-11.18, EX-11.19).** Un entier ou
   une adresse occupe un mot dont les octets de tête sont nuls : R-9 l'exige
   pour le relayeur, `periodStart` à `version`, `w8`, `publishedAt`, la
   longueur de `uri` et l'émetteur de l'ancre, et le remplissage de `uri`
   nul ; R-10 pour la clé de chaîne et le relayeur. R-11 (règle 1) n'exige
   que ce qu'elle énumère (3 sujets, `topics[0]`, 32 octets de `docType`).
8. **R-10 et l'émetteur de l'ancre.** La règle de l'émetteur s'applique si
   l'entrée `ancre` a passé R-6 et R-7 et que son journal a au moins trois
   sujets ; les inscriptions considérées sont celles dont la forme et les
   valeurs sont justes. AV-R-1 est levé quand P-1 a réussi, que `cles.json`
   est exploitable et qu'aucune inscription valide ne porte la clé du
   manifeste (`valide-sans-inscription`) ; il ne l'est pas quand P-1 échoue
   (`invalide-p1-manifeste-membre-en-trop`). La mention « clé de chaîne
   inscrite au bloc » de la proposition exige R-10 réussie et une
   inscription de la clé du manifeste sous l'émetteur ; le bloc est celui de
   la première, dans l'ordre de `registre.json`.
9. **R-3.** `validateurs.json` est chargé comme le nœud le charge
   (`ancres.LireJeu` : identifiants non vides et distincts, clés exploitables
   et distinctes, `from_height ≤ to_height`) ; un défaut fait échouer R-3. Le
   recouvrement des intervalles n'est pas contrôlé (EX-11.12 ne le demande
   pas) : un jeu qui contient la hauteur et dont le hachage égale
   `valsetHash` suffit.
10. **Faits.** `signers` est trié dans l'ordre croissant des octets
    (`attendu.json` : `["v1", "v3", "v4"]` pour des precommits de `v4`, `v1`,
    `v3`) ; `entries` et `certificates` suivent l'ordre de leur partie.
11. **N-4.** L'émetteur est lu dans `topics[2]` du journal de l'ancre même
    si R-9 refuse sa forme ; un journal de moins de trois sujets fait
    échouer N-4.
12. **Ancres employées.** `/registry` dès que R-1 a réussi avec une ancre
    `registry` ; les jeux retenus par R-2 pour une hauteur (que le hachage
    concorde ou non), triés ; l'enregistreur de N-4 quand la comparaison a
    lieu.
13. **K-8.** `org_id` ou `journal_id` de l'événement illisibles : K-8
    `non_execute` (`prerequis_en_echec`), l'empreinte ne pouvant être
    recalculée. Les autres non-exécutions de K-8 sont posées par le moteur.
14. **R-1 en échec.** R-2 à R-10 et N-4 sont `non_execute`
    (`prerequis_en_echec`) ; R-11, si elle figure, aussi, ou `partie_absente`
    si `registre.json` a pu être lu et ne porte pas d'entrée de point.
15. **Résumé.** Hors exemple de §8.5, sa forme est libre (V-5 ne le compare
    pas) : rôles dans l'ordre inscriptions, ancre, ancre de point, clôture,
    puis « n validateurs sur N à chaque bloc », ou « au moins n » quand le
    nombre varie.
