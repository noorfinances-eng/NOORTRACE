# Vérificateur indépendant CT-3 (Go, salle blanche)

Un second vérificateur des vecteurs de [CT-3](../../../CT-3-approbations.md),
écrit en Go depuis la seule spécification (CT-3, et CT-1 pour l'objet signé
`A`, son condensé `D_A`, le contrôle E-9, le hachage et la signature d'un
événement et les références de pièce) et les schémas qu'elle cite
(`politique-approbation-v0`, `ticket-v0`, depuis la révision 0.3
`annuaire-approbateurs-v0`, `console-approbation-v0` et `console-service-v0`,
et, par renvoi, `evenement-v0`), sans lire ni reprendre le code JavaScript de
`scripts/`, de `test/` ni de la page `console/`. Il
recalcule chaque valeur que les vecteurs de `spec/vecteurs/ct-3` déclarent,
famille par famille selon l'annexe A, et la confronte à l'attendu. Deux
implémentations écrites séparément qui tombent sur les mêmes valeurs rendent
les vecteurs probants ; une discordance désigne une ambiguïté de la
spécification ou une faute de l'une des deux (CT-3 §0, EX-A.10).

Module propre `noortrace-ct3` (`go 1.24`), **bibliothèque standard
uniquement** : aucun `go.sum`, aucun accès au réseau. Trois fichiers reprennent
du code des vérificateurs indépendants de CT-1 et CT-2, ce qu'EX-A.10 permet,
en le disant en tête : `keccak.go` (copie de CT-1), `jcs.go` (JCS v0 de CT-1,
JCS intégral de CT-2) et `json.go` (analyseur de CT-1, adapté pour lire un
substitut UTF-16 isolé au lieu de le refuser, ce qu'exige le code
`substitut_isole` d'EX-4.2).

## Usage

```bash
cd spec/vecteurs/ct-3/verificateur-independant
go run . ..                       # rapport texte
go run . -v ..                    # liste aussi chaque valeur concordante et hors périmètre
go run . -json .. > rapport.json  # rapport complet en JSON
go build -o verificateur . && ./verificateur ..
gofmt -l . ; go vet ./... ; go test ./...
```

`go build` sans `-o` produit `noortrace-ct3` ; `noortrace-ct3` et
`verificateur` sont exclus par le `.gitignore` local.

Le vérificateur lit, à côté des vecteurs, les schémas
(`../../schemas/*.schema.json`, obligatoires), la spécification
(`../../CT-3-approbations.md`, pour les comparaisons au texte) et le journal
valide des vecteurs CT-1 (`../ct-1/journal-valide/` : `evenements.json` pour
le cas `ct1-apr-2201` d'EX-A.8 et le ticket `apr-2201` de la famille
`console/`, `pieces.json` pour la pièce « arguments », `cles.json` pour la
clé publique `rec-test-01`) ; il n'écrit rien.

Codes de retour (EX-A.10) : `0` tout concorde (les valeurs hors périmètre
sont énoncées avec leur raison et ne comptent pas) ; `1` au moins une
discordance, listée avec l'attendu, la valeur recalculée et la règle de la
spécification qui fonde le calcul, ou une erreur (fichier absent ou
illisible) ; `2` usage incorrect ou racine introuvable.

Le rapport imprime, par famille puis au total, le nombre de valeurs
recalculées, concordantes, discordantes et hors périmètre, puis
« Résultat : tout concorde. » ou la liste des discordances.

## Ce qui est recalculé

| Famille | Fichiers lus | Valeurs recalculées et confrontées |
|---|---|---|
| constantes | `constantes.json` | `org_id` et `journal_id` (keccak256), registre et jeux 1 et 2 (20 premiers octets de SHA-256 des étiquettes), étiquettes, versions de politique, `chain_id`, mnémonique, **clé privée de chaque compte dérivée du mnémonique** (BIP-39 puis BIP-32, `m/44'/60'/0'/0/i`), adresse de chaque clé (secp256k1, keccak256) et adresses imprimées en A.2, demandeur, instant de base, `expire_after_ms` |
| format | tous les `*.json` | octets du fichier = `JSON.stringify(valeur, null, 2)` suivi d'un saut de ligne (EX-A.1) : indentation, conteneurs vides, nombres par `Number::toString`, échappements, substitut isolé écrit `\udxxx` |
| schemas | les fichiers qu'EX-A.3 désigne | conformité à `politique-approbation-v0` (politiques valides, politique de l'épreuve) et aux `$defs` de `ticket-v0` qu'EX-A.3 désigne (`attendu_politiques_invalides`, `fichier_evaluation`, `fichier_candidats`, `attendu_acceptation`, `trace`, `cas_remise`, `remise` des cas valides, remises et fenêtres attendues des traces par `attendu_pas`, `requete_evaluer` des cas de l'épreuve) ; depuis la révision 0.3, `annuaire-approbateurs-v0` (annuaires de `annuaires/` et `exports/` sauf le cas `schema`, `fichier_messages`, `fichier_inscriptions`, `fichier_domaines`, `trace_annuaire`, `fichier_controles_vote`, `fichier_controles_canal`, `attendu_exports`) et `console-approbation-v0` (`cas_modele`, `cas_requete`, `cas_reponse`, `cas_decouverte`, `cas_fichier_cle`, `attendu_acceptation_console`) ; les requêtes des traces d'annuaire par `console-service-v0` (forme : `requete_invalide`) |
| politiques | `politiques/*.json` | validation complète d'EX-4.2 sans erreur ; `assureur.json` égale à l'exemple de §4.3 lu dans le texte ; `assureur-permute.json` de même valeur, chaque objet en ordre inverse (AP-17) |
| politiques-invalides | `politiques-invalides/*.json`, `attendu.json` | liste complète des erreurs d'EX-4.2 et d'EX-8.2 : exactement l'entrée `schema` à pointeur nul pour un document non conforme au schéma, sinon chaque règle hors schéma avec son pointeur, triée par pointeur (unités UTF-16) puis par code, sous l'`environment` et l'`expire_after_ms` du cas ; l'exemple d'attendu imprimé en A.4 |
| evaluation | `evaluation/*.json` et leurs politiques | pour chaque cas : `rule`, `decision`, `contest_ms`, `opening` (portée avec l'outil annoncé) et `windows` après l'évaluation, par `EVALUER` (6.2) avec `SELECTIONNE`, `RESOUDRE`, `NUMERIQUE`, `COMPARER` (entiers `math/big`, jamais de flottant), `PREDICAT`, la logique de Kleene, `ISSUE` (EX-6.2), la chaîne `policy.rule` (EX-6.4) et les fenêtres (EX-5.2 à EX-5.5) ; chaque vérification AP-1 à AP-17 a au moins un cas (A.4) |
| candidats | `candidats/*.json` | `approval_candidates` par `CANDIDATS` (EX-4.11) ; l'exemple de 4.12 lu dans le texte |
| acceptation | `acceptation/`, `acceptation-attendu.json` | `rule` et `decision` des dix cas (F vide) ; couverture d'EX-A.4 (chaque sortie au moins deux fois, égalité exacte au seuil, argument absent, argument d'un autre type, autre outil, aucune règle `fenetre`) ; forme du gabarit, présence de la consigne, attendu hors du répertoire remis ; des règles qui sélectionnent toutes les mêmes outils (A.5) |
| tickets | `tickets/*.json` | chaque trace rejouée entrée par entrée sur un service vide (EX-A.6) : après chaque pas, l'état de **chaque** ticket, `accepted`, `reason`, `response`, les remises calculées pendant le pas (contenu complet : `remise_id`, `approvers` dans l'ordre d'acceptation, signatures normalisées, motif, seuil, membres, `source` d'EX-8.8) et les fenêtres ; minuteurs d'EX-7.7 (fin de fenêtre comprise), transitions T1 à T22 (T22 : `consommer` tardif d'une approbation servie, ticket `clos`), clé de rapprochement d'EX-7.3 (JCS intégral des arguments), réponses d'EX-7.16 et EX-7.17 (`approver_set` de la réponse `nouveau`, approbation servie une fois, `held`), votes et décompte (EX-7.26 à EX-7.29, EX-9.10 avec recouvrement de chaque signature sur `D_A`), séparation et récusation (10.1, refus d'un récusé maintenu), objections (10.2, refus antérieur au seuil compris), jeu épinglé (`jeu_non_attendu`), gel, nouveau gel, seuil effectif et confirmation du jeu (8.1 à 8.3), jeu de repli, remises (12.5), acquittements et expirations du noyau avec l'objet `approval` reçu (T11 à T17, T20), fenêtres ouvertes, consommées, épuisées et retirées (EX-5.4 à EX-5.6, EX-4.12), retrait par un contact administrateur (EX-7.15) ; identifiants `apr-0001`, … ; hachages synthétiques des blocs, des demandes (`demande/<k>`) et des événements (`evenement/<seq>`, A.2) ; cohérence de chaque `data.evaluation` (portée d'un ticket ouvrant, EX-5.2) ; trace exigée par EX-A.7 présente ; TK-1 à TK-13 servies ; escalades de 10.3 bien formées ; réponse à `charger` réduite à `{ policy_version }` (A.6) |
| decisions | `decisions/valides/*.json`, `decisions/invalides/*.json` | `expected.result`, `expected.reason` et `check` par SG-1 à SG-7 dans l'ordre d'EX-9.11 et de CT-2 EX-7.5 (recouvrement secp256k1 de chaque signature sur `D_A`, canonicité, A-3 ; SG-7, séparation des tâches : sous `self_approval` `interdite` du contexte, aucune adresse de `approvers` parmi celles de l'entrée de `separation.identities` dont `launched_by` est, octet pour octet, celui de la `retenue` de `request_hash`) ; couverture d'EX-A.8 (une raison par cas de refus du noyau, `auto_approbation` comprise, signature sur la chaîne `"0x…"` de `D_A`, signature `approuve` dans une remise `refuse`, `s` haut, signature d'un autre journal, écriture à l'échéance ; pour chaque paire de vérifications voisines, de SG-1/SG-2 à SG-6/SG-7, un cas où les deux échouent, chaque vérification étant aussi évaluée seule, refusé par la première ; les cinq remises valides exigées et une approbation signée par une adresse du demandeur sous `permise`) ; SG-1 exige un `remise_id` de la forme `<ticket>/<n>` ; le cas `ct1-apr-2201` : `approval` plus `at` égal à l'événement seq 6 du journal valide de CT-1, remise égale à l'exemple de §12.5 |
| signatures | `signatures/normalisation.json`, et les signatures valides des deux familles précédentes | forme normalisée d'EX-9.3 ou refus `signature_invalide` (`r` ou `s` hors de `[1, n − 1]` compris) ; même adresse recouvrée avant et après normalisation (A.8), sur le `D_A` où la forme canonique figure ; présence des sept formes exigées par A.8 ; **reproduction octet pour octet** de chaque signature valide par la clé du compte (ECDSA à nonce RFC 6979) |
| annuaire | `annuaire/` (A.10, AN-1 à AN-10) | `annuaires/reference.json` égal à l'exemple de 13.4 lu dans le texte, `vide.json` égal au même annuaire sans entrée ; `messages.json` : texte construit depuis les champs (EX-13.12), analyse stricte et champs relus, longueur, donnée de `personal_sign`, condensé EIP-191, longueur de la préimage ; l'exemple d'EX-13.12 (516 octets, préimage de 545, condensé imprimé) ; `inscriptions.json` : `accepted`, `reason`, `entry` (identifiant d'une entrée créée recalculé selon la convention de A.10), signature normalisée par les treize vérifications d'EX-13.15 dans l'ordre (défi marqué présenté dès le pas 4) ; `domaines.json` : adresse recouvrée sur `D_A` ou sur le texte (EX-13.16) et les deux adresses que le texte imprime ; chaque trace de `traces/` rejouée pas à pas (défi d'EX-13.13 avec le nonce du pas, inscription, opérations d'EX-13.17 et leurs raisons dans l'ordre de la table, invariants d'EX-13.10) : `accepted`, `reason`, `response` complète, `revision`, état résumé de chaque entrée, et l'état final de `annuaire-de-reference` égal à `annuaires/reference.json` (noms affichés mis à part) ; `controles-vote.json` : `allowed`, `reason`, `warnings` d'EX-13.18 et `directory_requester_addresses` recalculé depuis l'annuaire (EX-12.15) ; `controles-canal.json` : `reason` du contrôle de l'identité de session des méthodes `tickets`, `consulter`, `voter`, `recuser` et `retirer` (EX-12.13 : `identite_invalide` d'abord ; EX-12.14 : session hors de l'organisation, puis `ticket_inconnu` pour un ticket nul, puis session qui ne peut pas voir les arguments ; EX-12.16, EX-12.19 : contrôle d'adresse avant `ticket_inconnu` pour `voter` et `recuser`, `ticket_inconnu` d'abord pour `retirer`), requête conforme au `$defs` de sa méthode, chaque méthode exercée en passe et en refus, et `ticket_inconnu` exercé pour `consulter`, `voter` et `retirer` ; `exports/` : liste complète des écarts d'EX-13.19 (forme, `revision`, unicités, preuves, auto-validation, rejeu des opérations depuis un annuaire vide, droits d'administrateur jugés sur la liste en vigueur, opération `changer_administrateurs` d'EX-13.37 et pointeur `/administrators`), triée par pointeur puis par code ; chaque signature d'inscription acceptée **reproduite** par la clé du compte ; chaque nonce égal au nonce `k` de A.10 ; couverture d'EX-A.13 (textes refusés, raisons d'EX-13.15, formes de signature, instants limites, raisons d'EX-13.18, codes d'EX-13.19) |
| console | `console/` (A.11, CS-1 à CS-9) | `modeles/` : chaque membre du modèle d'affichage (EX-9.4) par les treize contrôles d'EX-9.15 dans l'ordre (hachage recalculé de l'événement `retenue` par CT-1 §6.1, pièce base64 contre `sha256` et `length` ou valeur en ligne par CT-1 §5.4, champs liés, feuilles d'EX-9.16, `A`, `JCS(A)`, `D_A`, `H`, empreintes, groupes et UTF-8 des deux décisions, comparaison à `digests`, annuaire, éligibilité, motif en points de code) et les avertissements, `intent_status` (contrôle 4 : `reference_non_verifiable` pour une intention que l'événement porte par un objet) et les effets copiés de la vue, dont chaque membre listé dans `unresolved` est nul et désigne `/result` (EX-12.14) ; l'événement seq 10 de l'intention par référence chaîné à l'événement seq 9 ; la vue d'exemple d'EX-12.15 et ce que le texte en dit (`blocking` vide, `remaining_ms` 2 829 904, empreinte, refus du compte 3), l'exemple d'EX-9.16, les valeurs d'EX-9.17 et d'EX-9.18 ; événement seq 5 et pièce de CT-1 repris tels quels ; signature Ed25519 de l'événement en ligne par `rec-test-01` (CT-1 §6.2) ; `requetes/` : condensés, préimage de 60 octets, requête `personal_sign` d'EX-13.24, signature **reproduite** par la clé du compte, égale à celle de CT-1 pour `apr-2201`, `D_A` et `H` imprimés pour `apr-0001`, plus petit `k` d'`apr-c0-<k>` (542) recherché ; `reponses/` : issue d'EX-9.21 et de la table de 13.14 (code, signature normalisée, adresse recouvrée, vote construit), l'exemple d'EX-9.21 lu dans le texte ; `decouverte/` : liste proposée et annonces écartées (EX-13.22) ; `fichiers-cle/` : issue d'EX-13.28 (format, dérivation admise, MAC, AES-128-CTR, intervalle de la clé, adresse, `derivation_faible`), sel, vecteur d'initialisation et identifiant tirés des étiquettes de A.11, l'exemple d'EX-13.28 ; couverture d'EX-A.15 |
| acceptation-console | `acceptation-console-attendu.json`, `acceptation-console/` | rôles, sections et questions de la table d'EX-A.17, chaque règle citée définie dans CT-3, questions présentes dans la consigne, gabarit présent, grille hors du répertoire remis |

Briques écrites ici : secp256k1 en `math/big` (multiplication, recouvrement
SEC 1 §4.1.6, signature RFC 6979, contrôlés contre les adresses de A.2 et les
deux signatures imprimées en §12.5) ; BIP-39 et BIP-32 (`crypto/pbkdf2`,
`crypto/hmac`) ; EIP-191 sur `D_A` et sur un texte ; un validateur JSON Schema
2020-12 réduit aux mots-clés des six schémas (un mot-clé inconnu est une
erreur, jamais ignoré ; `prefixItems` et `items` qui le suit ; les motifs
ECMAScript sont traduits pour `regexp`) ; une machine à états du service ; la
vérification SG du noyau ; depuis la révision 0.3, l'annuaire et ses
opérations (`annuaire.go`), le modèle d'affichage, la réponse du portefeuille,
la découverte et le fichier de clé (`console.go`), scrypt de la RFC 7914
(`scrypt.go`, que la bibliothèque standard n'a pas ; PBKDF2-HMAC-SHA-256 par
`crypto/pbkdf2`, AES-128-CTR par `crypto/aes` et `crypto/cipher`, Ed25519 par
`crypto/ed25519`).

## Ce qui n'est pas recalculé (hors périmètre)

- **`data.evaluation` des traces** : une trace fournit la sortie d'`EVALUER`
  sans les règles qui la produisent (A.6) ; elle est reprise telle quelle,
  seule sa cohérence (portée, `contest_ms`, `opening`) est contrôlée.
- **`INDEX.md` et le texte de `acceptation/consigne.md`** : documents générés
  ou libres, sans valeur attendue propre.
- Ce que les traces ne publient pas : le document `ticket-v0` persisté
  (`transitions`, `votes`, `eligible`), les notifications, les escalades, la
  re-présentation d'une remise après `temporaire` (T12), la lecture du
  registre sur la chaîne (8.1) : la machine joue les entrées `jeu_lu` telles
  quelles.
- Les refus que les traces n'exercent pas (un `consommer` ou un `retirer`
  hors des états admis) sont implémentés selon les tables 7.5 et 12.8 mais
  ne sont confrontés à aucun attendu.
- **Texte de `acceptation-console/consigne.md`** : texte libre ; seules les
  questions d'EX-A.17 y sont cherchées.
- Les sorties de `confrontation/` (EX-A.18) : elles sont rejouées par
  l'intégration continue avec les bibliothèques tierces, pas par ce module.

## Lectures retenues là où le texte laisse un choix

Les choix qu'une version précédente du texte laissait ouverts sont désormais
écrits dans la spécification et appliqués tels quels : vote identique de
même décision quel que soit le motif (EX-9.10), ordre des pointeurs en
unités UTF-16 (A.4), exactement l'entrée `schema` pour une politique non
conforme au schéma (EX-4.2), retrait des fenêtres à leur fin et à leur
épuisement (EX-5.6), refus hors table par `requete_invalide` (EX-7.8),
`expiration` répétée idempotente (EX-7.20), `r` et `s` hors de
`[1, n − 1]` refusés (EX-9.3).

La révision 0.3 laisse des choix que les vecteurs tranchent et que ce
vérificateur lit ainsi (aucun ne donne de discordance) :

- **Rejeu d'un annuaire exporté** (EX-13.19, point 6) : une opération
  `inscrire` reprend la preuve que l'entrée `op.entry` du document porte pour
  `op.address` (introuvable : l'opération ne se rejoue pas) ; une entrée créée
  prend l'identifiant `op.entry` ; les vérifications d'EX-13.15 « hors nonce
  et horloge » omettent les pas 4, 5 et la comparaison au défi des pas 8 à
  10 ; `external_id` et `display_name`, qu'aucune opération ne pose, sont
  repris du document avant la comparaison des entrées.
- **Condensés du modèle d'affichage** : nuls seulement quand le contrôle 2
  d'EX-9.15 échoue (« le modèle n'a pas de condensés ») ; une pièce invalide
  ou un champ différent les laisse calculés, comme le dit EX-9.17 (« Après
  les contrôles 2 à 4 »).
- **`request.request_hash` du modèle** : celui de la vue ; `seq` et `ts` :
  ceux de l'événement servi.
- **Avertissement `separation_non_verifiable` et bandeau** : sous
  `self_approval` `interdite` et `requester_declared` faux (EX-9.4, 10.5).
- **Découverte** (EX-13.22, point 3) : quand un autre objet reprend un
  `uuid`, l'annonce qui l'avait fait retenir et la nouvelle sont écartées
  (`annonce_en_double`), puis toute annonce ultérieure de cet `uuid` ; une
  réannonce par le même objet avant le conflit n'est pas écartée.
- **Fichier de clé** (EX-13.28) : `derivation_faible` n'est porté que si le
  fichier a passé les points 1 et 2 (la dérivation a lieu) ; l'adresse de la
  clé déchiffrée est rendue avec `adresse_differente`.
- **Motif d'une adresse révoquée par la validation d'une autre adresse ou
  par la désactivation de l'entrée** : nul (le motif de l'opération
  `desactiver` reste dans `operations`) ; aucun vecteur ne l'expose.

## Tests du module (`go test`)

- Révision 0.3, sans les vecteurs : identités de session canoniques et
  refusées (EX-13.7) ; l'exemple d'EX-13.12 (516 octets, préimage de 545,
  condensé imprimé, signature du compte 1 égale à celle de l'annuaire
  d'exemple) et ses variantes refusées ; les deux adresses d'EX-13.16 ; un
  scénario d'annuaire construit ici (défi, inscription, défi présenté deux
  fois, validation par un non-administrateur refusée, rotation, adresse
  jamais réattribuée, contrôles d'EX-13.18, export sans écart puis `revision`
  faussée et auto-validation) ; la vue d'exemple d'EX-12.15 (hachage de
  l'événement, modèle signable, `remaining_ms`, empreinte ; événement modifié,
  condensé faux pour `refuse`, motif de 1 025 points de code) ; l'exemple
  d'EX-9.21 et les formes refusées, la requête d'EX-13.24 ; une découverte
  construite ici ; le fichier de clé d'EX-13.28 (déchiffrement, mauvais mot
  de passe, autre adresse, bornes, étiquettes) ; les feuilles d'EX-9.16.
- Keccak-f[1600] confronté à `crypto/sha3` ; `org_id`, `journal_id` de CT-3
  et de CT-1.
- Comptes 1 à 4 de A.2 dérivés du mnémonique ; signature puis recouvrement,
  forme à `s` haut et sa normalisation ; les deux signatures de l'exemple de
  §12.5 recouvrent les approbateurs qu'il nomme ; registre, jeu 1 et bloc 1214
  de l'exemple d'EX-8.9.
- JCS v0 (cas limites de CT-1 §4), JCS intégral (table de CT-2 EX-8.1),
  `JSON.stringify(…, null, 2)`, horodatages inexistants refusés.
- Comparaisons exactes d'EX-4.6, pointeurs d'EX-4.4, logique de Kleene et
  garde `existe` (4.10), sélection (EX-4.3).
- **Table de §6.7 transcrite du texte**, évaluée sur la politique de §4.3 lue
  dans la spécification (décision, `policy.rule`, consommation de la fenêtre,
  `contest_ms`, ouverture) ; exemple de 4.12.
- Règles d'EX-4.2 hors schéma sur des documents construits (32 et 33 jetons,
  8 et 9 niveaux, 64 et 65 prédicats, noms en double, substitut isolé,
  `contest_ms`) ; refus du validateur de schémas.
- Un scénario de service construit sans les vecteurs (jeu statique, votes
  signés par les clés dérivées, auto-approbation refusée, vote identique,
  remise acceptée par SG-1 à SG-7, refusée par SG-7 sous `interdite` et
  acceptée sous `permise` ou pour un `launched_by` différent d'un octet,
  refusée à l'échéance avant SG-7, consommation unique) ; échéance avant
  un vote de même instant (EX-7.7).
- Les vecteurs publiés dans le répertoire parent : tout doit concorder.

## Écarts relevés entre la spécification et les vecteurs publiés

Confrontation du 2026-10-23, après correction de la spécification et des
vecteurs : 4 590 valeurs recalculées, 4 590 concordantes, **0 discordante**,
81 hors périmètre (79 `data.evaluation` des traces, `INDEX.md`, texte de la
consigne). Les écarts de la confrontation précédente (politique de l'épreuve
à plusieurs règles, réponse réduite à `charger`, fenêtres échues gardées,
étiquette d'événement absente de A.2) sont résolus dans le texte de CT-3.

Confrontation du 2026-10-23 avec la version 0.3 de CT-2 (SG-7 adoptée,
contexte des cas de remise augmenté de `launched_by` et `separation`) :
4 613 valeurs recalculées, 4 613 concordantes, **0 discordante**, 81 hors
périmètre. Avant la mise à jour de ce vérificateur, les deux cas `sg7-*`
étaient recalculés `scelle` : c'est l'effet attendu de la révision, pas un
écart.

Confrontation du 2026-10-23 avec la version 0.2 de CT-3 (transition T22,
trace `consommation-tardive`) : 4 718 valeurs recalculées, 4 718
concordantes, **0 discordante**, 83 hors périmètre (81 `data.evaluation` des
traces, `INDEX.md`, texte de la consigne). Avant la mise à jour de ce
vérificateur, le `consommer` tardif de la nouvelle trace était refusé
(`requete_invalide`) : c'est l'effet attendu de T22, pas un écart.

Confrontation du 2026-10-26 avec la révision 0.3 de CT-3 (familles
`annuaire/` et `console/`, épreuve de lecture de la console) : 6 922 valeurs
recalculées, 6 922 concordantes, **0 discordante**, 96 hors périmètre (81
`data.evaluation` des traces, 12 identifiants d'entrée créée, `INDEX.md`,
textes des deux consignes). Les valeurs des familles anciennes ne changent
pas (4 830 avant l'extension, sur les vecteurs de la révision 0.3).

Confrontation du 2026-10-26 avec les corrections de la révision 0.3 de CT-3
(règle EX-12.19, famille AN-10 `annuaire/controles-canal.json`, trace
d'annuaire `confiscation`) : 7 005 valeurs recalculées, 7 005 concordantes,
**0 discordante**, 84 hors périmètre (81 `data.evaluation` des traces,
`INDEX.md`, textes des deux consignes). Les identifiants d'entrée créée,
hors périmètre à la confrontation précédente, sont désormais recalculés
selon la convention que A.10 fixe pour les vecteurs.

Confrontation du 2026-10-26 avec la fermeture des points ouverts de la
révision 0.3 de CT-3 (ordre des refus de `tickets` et de `consulter`
d'EX-12.14 et ticket inconnu sur le canal, opération `changer_administrateurs`
d'EX-13.37 rejouée par EX-13.19, `intent_status` et membres `unresolved` des
effets de la vue) : 7 149 valeurs recalculées, 7 149 concordantes,
**0 discordante**, 84 hors périmètre. Ce vérificateur a été étendu depuis le
seul texte de CT-3 (EX-12.14, EX-12.19, EX-13.19, EX-13.37, EX-9.15,
contrôle 4, EX-A.13, EX-A.15) ; une altération d'un attendu de chacun des
cas nouveaux (raison d'un ticket inconnu, `intent_status`, `by` d'une
opération après la recopie) y est relevée comme discordance.
