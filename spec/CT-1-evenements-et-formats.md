# CT-1 — Modèle d'événement et formats

Version 0.2, 21 octobre 2026 (révision après la confrontation de l'implémentation
de référence `scripts/lib/journal.mjs` et du vérificateur indépendant Go de
`spec/vecteurs/ct-1/verificateur-independant`). Spécification normative, soumise
à la revue de la porte 1 du [plan](../docs/plan.md). Elle met en œuvre la section « Modèle
d'événement » et la chaîne de traitement de l'[architecture cible](../ARCHITECTURE.md)
et clôt ses décisions ouvertes 1 et 5 (section 14).

Les mots DOIT, NE DOIT PAS, DEVRAIT et PEUT ont le sens de la RFC 2119. Une règle
notée « le vérificateur rejette » est un contrôle que le vérificateur de CT-6
exécute ; la table de la section 11.4 les récapitule avec leur identifiant.
Les clés JSON sont en anglais ; les valeurs énumérées sont en français, sans
accent, comme dans l'architecture (`a_approuver`, `approuve`).

## 1. Objet et périmètre

CT-1 fixe, pour la version 0 du format :

1. l'événement de journal, ses dix-sept clés et leurs contraintes ;
2. la forme canonique sur laquelle portent le hachage et la signature ;
3. le hachage SHA-256 et la signature Ed25519 de chaque événement, avec les
   préfixes de domaine, octet par octet ;
4. le chaînage par `seq` et `prev_hash` et ce qu'il détecte ;
5. la rotation de clé de l'enregistreur, qui est un événement du journal ;
6. l'arbre de Merkle RFC 6962 des événements d'une période, la convention de la
   période vide et la preuve d'inclusion ;
7. le manifeste de période, son hachage `periodHash`, sa signature et sa
   continuité avec la période précédente et avec le contrat `PeriodRegistry` ;
8. le dossier de preuve, fichier par fichier, et les contrôles du vérificateur
   que CT-1 rend exécutables ;
9. les correspondances d'export, en tables, sans implémentation ;
10. les clés et comptes de test des vecteurs.

Hors périmètre : la capture (CT-2), le langage de règles et le cycle de vie des
tickets (CT-3), le registre (CT-4), les ancres RFC 3161 et OpenTimestamps
(CT-5), la ligne de commande du vérificateur (CT-6). La section 15 dresse la
liste de ce que cette version ne couvre pas.

## 2. Terminologie

| Terme | Définition |
|---|---|
| Journal | Suite d'événements d'une organisation, identifiée par (`org_id`, `journal_id`), en ajout seul, numérotée par `seq` à partir de 1. |
| Événement | Un enregistrement du journal : un appel d'outil, un échange avec le modèle, une décision d'approbation, ou un événement du journal sur lui-même (rotation de clé, changement de politique). |
| Enregistreur | Composant chez le client qui produit, chaîne et signe les événements. Il détient une clé Ed25519 identifiée par `recorder_key_id`. |
| Pièce | Contenu volumineux ou rédigé (arguments, résultat, messages, document) conservé chez le client et désigné dans l'événement par une référence (section 5.4). |
| Référence | Objet `{ sha256, length, redacted }` qui désigne une pièce par le SHA-256 de ses octets. |
| Période | Une heure UTC pleine `[period_start, period_end)`. Lot de clôture : arbre de Merkle, manifeste, signature. |
| Manifeste | Objet qui décrit une période ; son hachage `periodHash` est ce que `PeriodRegistry` enregistre. |
| Racine | Racine de l'arbre de Merkle des événements d'une période, 32 octets. |
| Chemin d'audit | Preuve d'inclusion d'une feuille dans l'arbre, RFC 6962 §2.1.1. |
| Dossier | Répertoire exporté pour un événement, avec tout ce qu'il faut pour le vérifier hors ligne. |
| Vérificateur | Programme hors ligne de CT-6 qui exécute les contrôles de la section 11.4. |
| Approbateur | Personne dont l'adresse secp256k1 est membre du jeu d'approbateurs de l'organisation (`CuratorSet`) ; signe en EIP-191. |
| JCS | JSON Canonicalization Scheme, RFC 8785, avec la restriction v0 de la section 4. |

## 3. Conventions d'encodage

| Donnée | Encodage | Exemple |
|---|---|---|
| Octets (hachages, clés, signatures, nonces) | Hexadécimal minuscule, préfixe `0x`, sans espace. Un hachage de 32 octets fait 66 caractères ; une signature Ed25519 de 64 octets, 130 ; une signature EIP-191 de 65 octets, 132 ; une adresse de 20 octets, 42. Les majuscules sont refusées, y compris dans les adresses (pas de somme de contrôle EIP-55). | `0x471dab56…dc00` |
| Horodatages | RFC 3339, UTC, exactement trois décimales de seconde, suffixe `Z` : `AAAA-MM-JJThh:mm:ss.mmmZ`. Pas de décalage horaire, pas de seconde intercalaire (`:60`). La date DOIT exister dans le calendrier grégorien proleptique : `2026-02-30`, `2026-04-31` ou `2026-02-29` (année non bissextile) respectent le motif des schémas mais ne se décodent pas, et rendent le document invalide (E-1) ; un vérificateur dont l'analyseur renormalise une telle date (`Date.parse` d'ECMAScript fait du 30 février un 2 mars) DOIT la rejeter, jamais la décaler. Toute comparaison d'horodatages (C-1, E-11, P-2, P-3, P-5) porte sur les instants décodés, à la milliseconde, jamais sur les chaînes. | `2026-11-03T13:52:41.090Z` |
| Secondes UNIX (manifeste) | Entier, secondes depuis 1970-01-01T00:00:00Z, sans fraction. | `1793710800` |
| Entiers | Nombres JSON entiers dans `[-(2^53-1), 2^53-1]`. Au-delà, chaîne décimale. | `412` |
| Montants | Chaîne décimale `^-?(0|[1-9][0-9]*)(\.[0-9]{1,8})?$`, jamais un nombre JSON (section 4). | `"7400.00"` |
| Identifiants de clés | Chaîne `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`. | `rec-test-01` |
| `org_id`, `journal_id` | 32 octets, ceux que `RecorderRegistry` et `PeriodRegistry` connaissent (`keccak256(slug)` et `keccak256(nom)` dans `scripts/lib/noortrace.mjs`, mais opaques pour CT-1 : n'importe quels 32 octets non nuls). | `0xa581bb78…daab` |
| Valeur nulle | `null` JSON. Une clé optionnelle par le sens est toujours présente, à `null` : la forme d'un objet est fixe. Deux exceptions, et deux seulement : `media_type` et `value` d'une référence (section 5.4) sont **absentes** quand elles ne s'appliquent pas, jamais `null` (le schéma refuse `"media_type": null`, E-1). | `"on_behalf_of": null` |

Les fichiers JSON sont en UTF-8 sans marque d'ordre d'octets. Leur mise en forme
(indentation, ordre des clés) est libre : seule la forme canonique compte pour les
hachages et les signatures. Le SHA-256 d'un fichier du dossier (section 11)
porte, lui, sur les octets du fichier tel qu'il est écrit.

## 4. Forme canonique : JCS v0

La forme canonique d'une valeur JSON est celle de la RFC 8785 (JCS), avec une
restriction : **aucun nombre non entier**. Règles exactes, applicables par un
implémenteur qui ne lit pas la RFC :

1. **Objets.** Les membres sont triés par nom, les noms comparés comme suites
   d'unités de code UTF-16 (ordre lexicographique des unités de code, pas des
   points de code ni de la locale ; c'est l'ordre de `Array.prototype.sort` sans
   comparateur en ECMAScript). Deux membres de même nom : le document est
   invalide (le vérificateur rejette, E-2). Sérialisation : `{` `"nom"` `:` valeur
   (`,` …) `}` sans aucun espace ni saut de ligne.
2. **Tableaux.** Dans l'ordre donné : `[` valeur (`,` …) `]` sans espace.
3. **Chaînes.** Sérialisées comme `JSON.stringify` d'ECMAScript 2019 et
   suivants : guillemet `"` → `\"`, barre oblique inverse `\` → `\\`, U+0008 →
   `\b`, U+0009 → `\t`, U+000A → `\n`, U+000C → `\f`, U+000D → `\r`, les autres
   caractères de contrôle U+0000–U+001F → `\u00XX` avec `XX` en **minuscules** ;
   tout autre caractère, y compris `/`, les caractères non ASCII, U+007F, U+2028
   et U+2029, en clair, encodé en UTF-8. Les chaînes DOIVENT être des suites de
   points de code Unicode bien formées : un substitut isolé (U+D800–U+DFFF non
   apparié) est invalide (E-2). Aucune normalisation Unicode (NFC, NFD) n'est
   appliquée : `é` précomposé et `e` + U+0301 sont deux chaînes différentes.
4. **Nombres.** Seuls les entiers de `[-(2^53-1), 2^53-1]` sont admis.
   Sérialisation : signe `-` si négatif, puis chiffres décimaux sans zéro de
   tête, sans fraction, sans exposant ; `-0` se sérialise `0`. Un nombre avec une
   partie fractionnaire, un exposant, ou hors de l'intervalle, rend le document
   invalide (E-2), même si JCS saurait le sérialiser : la restriction supprime la
   seule partie de la RFC 8785 dont les implémentations divergent (algorithme de
   plus courte représentation des flottants). Un montant, un taux, un score sont
   des chaînes décimales ou des entiers en unité mineure.
5. **Littéraux.** `true`, `false`, `null` en minuscules.
6. **Rien d'autre.** Aucun espace, aucune indentation, aucun saut de ligne, pas
   de marque d'ordre d'octets. La sortie est une chaîne, encodée en UTF-8 pour le
   hachage.

Cas limites, avec le résultat attendu :

| Entrée (JSON) | Forme canonique | Remarque |
|---|---|---|
| `{"b":1,"a":2}` | `{"a":2,"b":1}` | tri des clés |
| `{"é":1,"z":2,"Z":3}` | `{"Z":3,"z":2,"é":1}` | unités UTF-16 : `Z` (0x5A) < `z` (0x7A) < `é` (0xE9) |
| `{"é":1}` | `{"é":1}` | la clé est décodée avant le tri, puis écrite en clair |
| `{"a😀":1}` | `{"a😀":1}` | la paire de substituts code un seul caractère, écrit en UTF-8 (4 octets) |
| `{"a":"x\u0001y"}` | `{"a":"x\u0001y"}` | contrôle → `\u0001`, minuscules |
| `{"a":"\u007f"}` | `{"a":"<U+007F en clair>"}` | U+007F n'est pas échappé |
| `{"a":"/"}` | `{"a":"/"}` | `/` n'est pas échappé |
| `{"a":1.0}` | invalide | non entier (même valeur entière, forme fractionnaire) |
| `{"a":1e3}` | invalide | exposant |
| `{"a":9007199254740993}` | invalide | hors intervalle sûr |
| `{"a":-0}` | `{"a":0}` | zéro négatif |
| `{"a":[]}`, `{"a":{}}` | `{"a":[]}`, `{"a":{}}` | conteneurs vides |
| `{"a":"\ud800"}` | invalide | substitut isolé |
| `{"a":1,"a":2}` | invalide | clé en double |

Vérification par un implémenteur : pour tout objet JSON qui respecte la
restriction, `JSON.stringify` d'ECMAScript appliqué après tri récursif des clés
donne exactement la forme canonique. C'est l'implémentation de référence des
vecteurs.

## 5. Événement v0

### 5.1 Vue d'ensemble

Un événement est un objet JSON à dix-sept clés, toutes obligatoires, sans autre
clé (`additionalProperties: false`). Neuf forment l'enveloppe, huit sont le
modèle de l'architecture.

```text
version, seq, ts, org_id, journal_id, recorder_key_id, prev_hash,   ─ enveloppe (chaînage)
delegation, code, intent, policy, approval, execution, effects, context,   ─ les huit champs
hash, sig                                                           ─ enveloppe (scellement)
```

Quatre sortes d'événements partagent cette forme. Elles se distinguent par
`execution.tool`, dont l'espace de noms `noortrace.` est réservé : le mandataire
NE DOIT PAS relayer un outil réel dont le nom commence par `noortrace.`, et un tel
nom ailleurs que dans la liste suivante est invalide (E-3).

| Sorte | `execution.tool` | `execution.arguments` | `execution.result` |
|---|---|---|---|
| Appel d'outil (`tools/call` MCP) | nom de l'outil tel qu'annoncé par `tools/list` | référence aux arguments | référence au résultat, ou `null` si l'appel n'a pas été exécuté |
| Échange avec le modèle | `noortrace.modele.echange` | référence à la requête (messages envoyés, prompt système) | référence à la réponse |
| Décision d'approbation | `noortrace.approbation.decision` | référence **en ligne** (`value`) à l'objet signé par les approbateurs (section 5.3, `approval`) | `null` |
| Rotation de clé | `noortrace.journal.rotation-cle` | référence en ligne à l'annonce de rotation (section 8) | `null` |
| Changement de politique | `noortrace.journal.politique` | référence en ligne `{ "policy_version": …, "policy_sha256": … }` | `null` |

Un lot est une heure UTC (section 9). Un événement par appel d'outil et par
échange avec le modèle : c'est la décision ouverte 1 de l'architecture, close en
section 14.

### 5.2 Enveloppe, champ par champ

| Clé | Type | Contraintes | Exemple |
|---|---|---|---|
| `version` | entier | Constante `0`. | `0` |
| `seq` | entier | `≥ 1`, `≤ 2^53-1`. Le premier événement d'un journal porte `1` ; chaque événement suivant porte `seq` précédent + 1, sans trou ni doublon. | `4` |
| `ts` | horodatage | Horloge de l'enregistreur. NE DOIT PAS être antérieur au `ts` de l'événement précédent (égalité admise). La stratégie de l'enregistreur quand son horloge recule est du ressort de CT-2 ; l'invariant est celui-ci. Appartient à la période `[period_start, period_end)` du manifeste qui couvre `seq`. | `"2026-11-03T13:52:41.090Z"` |
| `org_id` | hex 32 octets | Non nul. Identique pour tous les événements du journal. | `"0xa581…daab"` |
| `journal_id` | hex 32 octets | Non nul. Identique pour tous les événements du journal. | `"0x0e27…c64b"` |
| `recorder_key_id` | identifiant de clé | Clé Ed25519 qui a produit `sig`. Change exactement après un événement de rotation (section 8). | `"rec-test-01"` |
| `prev_hash` | hex 32 octets | `hash` de l'événement `seq - 1` ; `0x00…00` (32 octets nuls) si et seulement si `seq = 1`. | `"0xadeb…d832"` |
| `hash` | hex 32 octets | Section 6.1. | `"0x471d…dc00"` |
| `sig` | hex 64 octets | Section 6.2. | `"0xcd09…bf00"` |

### 5.3 Les huit champs

Chaque sous-champ est obligatoire ; « nullable » signifie que `null` est admis.

**`delegation` — provenance de la délégation.** Qui a lancé l'agent, pour le
compte de qui, avec quels droits.

| Sous-champ | Type | Contraintes | Exemple |
|---|---|---|---|
| `launched_by` | chaîne 1–256 | Identité de la personne ou du service qui a lancé l'agent, telle que le système d'identité du client la nomme. Pour un événement du journal sur lui-même : `"noortrace-enregistreur"`. | `"u.martin@assureur-demo.example"` |
| `on_behalf_of` | chaîne ≤ 256, nullable | Pour le compte de qui (service, client final, dossier). | `"service-sinistres"` |
| `scope` | chaîne 1–1024 | Droits accordés à l'agent, dans le vocabulaire du client. | `"sinistres:lecture,paiement"` |
| `run_id` | chaîne ≤ 128, nullable | Identifiant de l'exécution de l'agent, pour regrouper ses événements. | `"run-2026-11-03-0142"` |

**`code` — provenance du code.**

| Sous-champ | Type | Contraintes | Exemple |
|---|---|---|---|
| `model` | chaîne ≤ 256, nullable | Identifiant du modèle tel que vu au proxy de sortie : fournisseur, nom, version. `null` quand aucun modèle n'intervient. | `"fournisseur/modele@2026-09"` |
| `prompt_version` | hex 32 octets, nullable | SHA-256 des octets UTF-8 du prompt système **tel qu'il est conservé chez le client** : une pièce comme une autre (section 5.4), rédigée avant hachage si elle contient une donnée sensible (règle de CT-2). Ce champ identifie une version du prompt ; il ne doit pas permettre de la recouper, d'où la règle de la section 5.4 et le risque énoncé en section 15. `null` si inconnu. | `"0xb715…6b58"` |
| `policy_version` | chaîne 1–128 | Version de la politique en vigueur, nommée par le client (CT-3). | `"2026-11-01"` |
| `recorder` | chaîne 1–64 | Version du logiciel de l'enregistreur. | `"0.1.0"` |

**`intent` — intention.** Chaîne ≤ 4096 caractères, ou référence (section 5.4)
quand le texte est plus long ou rédigé, ou `null`. Pour un appel d'outil, c'est le
texte de l'assistant qui précède l'appel dans la réponse du modèle, s'il existe.
Pour un échange avec le modèle, le texte produit par l'assistant. `null` pour les
décisions d'approbation et les événements du journal.

**`policy` — évaluation de politique.**

| Sous-champ | Type | Contraintes | Exemple |
|---|---|---|---|
| `rule` | chaîne ≤ 1024, nullable | Règle appliquée, dans la syntaxe de CT-3. Obligatoire (non nulle) quand `decision` vaut `a_approuver` ; `null` quand `decision` vaut `sans_objet`. | `"paiement > 5000 CHF"` |
| `decision` | énumération | `autorise`, `a_approuver`, `refuse` : les trois sorties de l'architecture, pour un appel d'outil. `sans_objet` : l'événement n'est pas soumis à la politique (échange avec le modèle, décision d'approbation, événement du journal). | `"a_approuver"` |
| `ticket` | chaîne ≤ 128, nullable | Identifiant du ticket d'approbation. Obligatoire quand `decision` vaut `a_approuver` ; repris par la décision d'approbation et par l'appel relayé. | `"apr-1192"` |
| `redaction` | chaîne ≤ 128, nullable | Nom et version de la règle de rédaction appliquée aux pièces de l'événement avant hachage (CT-2). `null` si aucune pièce n'a été rédigée. Toute référence avec `redacted: true` dans l'événement exige une valeur non nulle ici (E-4). | `"pii-v1"` |

**`approval` — approbation humaine.** `null` si aucune approbation n'est liée.
Sinon un objet, identique dans l'événement de décision et dans l'appel relayé
qui en découle.

| Sous-champ | Type | Contraintes | Exemple |
|---|---|---|---|
| `decision` | énumération | `approuve`, `refuse`, `expire` (délai écoulé sans décision : refus journalisé). | `"approuve"` |
| `ticket` | chaîne 1–128 | Le ticket de `policy.ticket`. | `"apr-1192"` |
| `request_hash` | hex 32 octets | `hash` de l'événement qui a créé le ticket : l'appel d'outil retenu (`execution.status = "retenue"`). Lie la décision à l'outil et aux arguments exacts qui ont été soumis. | `"0xdd3b…fce0"` |
| `threshold` | objet `{ required, size }` | Entiers ≥ 1 : signatures requises sur la taille du jeu, lus dans le `CuratorSet` de l'organisation au moment de la décision. | `{ "required": 2, "size": 3 }` |
| `approvers` | tableau d'adresses | Adresses secp256k1 (20 octets, minuscules) des approbateurs qui ont signé, sans doublon. Vide si `decision` vaut `expire`. | `["0x7099…79c8", "0x3c44…93bc"]` |
| `signatures` | tableau de signatures EIP-191 | `signatures[i]` a été produite par `approvers[i]` ; même longueur que `approvers` (E-5). Format en section 6.3. | `["0x9b56…a01b", "0xed53…151b"]` |
| `at` | horodatage | Instant où le seuil a été atteint (ou le délai écoulé), horloge de l'enregistreur. | `"2026-11-03T13:52:40.511Z"` |
| `reason` | chaîne ≤ 1024, nullable | Motif donné par les approbateurs. | `"Pièces validées"` |

L'objet signé par chaque approbateur est `A = { decision, journal_id, org_id,
request_hash, ticket }` (section 6.3). `threshold`, `approvers`, `at` et `reason`
ne sont pas signés par les approbateurs : ils sont attestés par la signature de
l'enregistreur sur l'événement. CT-3 fixe le cycle de vie du ticket et peut
ajouter des champs signés dans une version 1 du condensé ; la forme du champ
`approval` ne change pas.

**`execution` — exécution.**

| Sous-champ | Type | Contraintes | Exemple |
|---|---|---|---|
| `tool` | chaîne `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$` | Nom de l'outil MCP, ou nom réservé (section 5.1). | `"sap.payments.create"` |
| `arguments` | référence | Arguments de l'appel (`params.arguments` du `tools/call`), rédigés selon `policy.redaction` puis hachés. Toujours une référence, jamais les arguments eux-mêmes, sauf référence en ligne (`value`) pour les événements réservés ou les petits arguments non rédigés. | `{ "sha256": "0x0fb2…aaf9", "length": 96, "redacted": true }` |
| `status` | énumération | `executee` : l'appel a été relayé et a répondu ; `retenue` : non relayé, en attente d'approbation (ticket créé) ; `refusee` : non relayé (politique `refuse`, approbation `refuse` ou `expire`). | `"executee"` |
| `result` | référence, nullable | Résultat (`result` du `tools/call`, ou réponse du modèle). Référence obligatoire si `status = "executee"` et que l'événement est un appel d'outil ou un échange avec le modèle ; `null` si `status` vaut `retenue` ou `refusee`, et toujours `null` pour une décision d'approbation, une rotation de clé et un changement de politique (table ci-dessous ; E-1 et E-3). | `{ "sha256": "0x8bbf…9624", "length": 85, "redacted": false }` |
| `duration_ms` | entier ≥ 0, nullable | Durée entre l'envoi au serveur d'outils (ou au modèle) et la réception de la réponse, millisecondes. Entier obligatoire si `status = "executee"` et que l'événement est un appel d'outil ou un échange avec le modèle ; `null` sinon (appel retenu ou refusé, décision d'approbation, rotation, changement de politique). | `412` |
| `is_error` | booléen, nullable | Drapeau `isError` de la réponse MCP (ou erreur HTTP du modèle). Booléen obligatoire dans les mêmes cas que `duration_ms` ; `null` sinon. | `false` |

Les trois sous-champs se lisent sorte par sorte ; le vérificateur applique cette
table (E-3) et le schéma la porte dans l'`allOf` de `execution` (E-1) :

| Sorte | `status` | `result` | `duration_ms` | `is_error` |
|---|---|---|---|---|
| Appel d'outil exécuté | `executee` | référence | entier ≥ 0 | booléen |
| Appel d'outil retenu ou refusé | `retenue` ou `refusee` | `null` | `null` | `null` |
| Échange avec le modèle | `executee` | référence à la réponse | entier ≥ 0 | booléen |
| Décision d'approbation, rotation de clé, changement de politique | `executee` | `null` | `null` | `null` |

Un échange avec le modèle est toujours `executee` : une requête qui n'obtient
pas de réponse exploitable est journalisée avec `is_error: true` et une
référence à ce qui a été reçu (corps d'erreur, ou pièce vide de longueur 0). Un
échange sans `result`, sans `duration_ms` ou sans `is_error` est invalide (E-1,
E-3) : l'événement seq 1 de l'annexe A porte les trois.

**`effects` — effets.** Tableau, vide si aucun effet (appel retenu, refusé,
lecture pure sans objet nommé). Chaque élément :

| Sous-champ | Type | Contraintes | Exemple |
|---|---|---|---|
| `system` | chaîne 1–128 | Système du client touché. | `"SAP"` |
| `action` | énumération | `lecture`, `ecriture`, `suppression`, `envoi`, `execution`. | `"ecriture"` |
| `object` | chaîne 1–512 | Identifiant de la ressource dans ce système. | `"PAY-2026-55120"` |
| `amount` | chaîne décimale, nullable | Montant en unité majeure, point décimal, jusqu'à huit décimales. | `"7400.00"` |
| `currency` | chaîne `^[A-Z]{3}$`, nullable | Code ISO 4217. `amount` et `currency` sont tous deux `null` ou tous deux renseignés. | `"CHF"` |

Les effets sont déclarés par le mandataire à partir de la description de l'outil
et de ses arguments (CT-2, CT-3) ; ils ne prouvent pas que le système du client
a bien changé, ils prouvent ce que l'enregistreur a vu passer.

**`context` — provenance du contexte.** Tableau de références, vide si aucune.
Chaque élément porte `sha256`, `length`, `redacted` (section 5.4) et `kind` ∈
{`document`, `donnees`, `memoire`, `autre`}, plus `media_type` optionnel. Pas de
valeur en ligne : un document du contexte est toujours une pièce.

### 5.4 Références de charge utile et rédaction

Tout champ volumineux ou rédigé est remplacé par une référence :

```json
{ "sha256": "0x…", "length": 96, "redacted": true }
```

| Clé | Type | Règle |
|---|---|---|
| `sha256` | hex 32 octets | SHA-256 des octets de la pièce **telle qu'elle est stockée** chez le client, après rédaction s'il y a lieu. |
| `length` | entier ≥ 0 | Nombre d'octets de la pièce stockée. |
| `redacted` | booléen | `true` si la pièce stockée diffère de ce qui a circulé (règle de rédaction `policy.redaction`). |
| `media_type` | chaîne, optionnelle | Type de média de la pièce, en minuscules (`application/json`, `application/pdf`). |
| `value` | valeur JSON, optionnelle | Pièce en ligne. Interdite si `redacted` vaut `true`. Quand `value` est présente, la pièce **est** `JCS(value)` en UTF-8 : `sha256 = SHA-256(JCS(value))` et `length` = longueur en octets de `JCS(value)` (E-6). `value` respecte JCS v0 (aucun nombre non entier). |

Règles :

- La rédaction se fait avant hachage. Le journal ne contient donc jamais la
  donnée sensible, ni en clair ni par un hachage de sa forme en clair. Une
  référence rédigée ne peut pas être recoupée avec l'original.
  `code.prompt_version` suit la même règle : c'est le SHA-256 du prompt système
  tel qu'il est stocké, après rédaction s'il y a lieu (section 5.3).
- `media_type` et `value` sont absentes quand elles ne s'appliquent pas
  (section 3) : une référence qui porte `"media_type": null` est invalide
  (E-1), et sa forme canonique différerait de celle de la référence sans
  `media_type`.
- La pièce stockée est conservée à côté du journal, chez le client, sous son
  `sha256` ; le dossier (section 11) ne l'emporte pas, sauf décision du client.
  Un vérificateur qui reçoit la pièce la hache et compare (E-6).
- Comment une requête ou une réponse est sérialisée en octets avant hachage
  (par exemple la ligne JSON-RPC telle que reçue) est fixé par CT-2 ; CT-1
  n'impose que ceci : la pièce stockée est exactement ce qui a été haché.

### 5.5 Exemple complet

L'appel relayé après approbation de l'exemple de référence (seq 4 ; les quatre
autres événements sont en annexe A). Il valide contre
`schemas/evenement-v0.schema.json` ; ses `hash` et `sig` sont recalculés en
section 6.4.

<!-- schema: evenement -->
```json
{
  "version": 0,
  "seq": 4,
  "ts": "2026-11-03T13:52:41.090Z",
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
  "recorder_key_id": "rec-test-01",
  "prev_hash": "0xadeb42cb3a4557effbf1bf2dd0a973a1e74563cd39fbb747202d6a4a0f5ad832",
  "delegation": {
    "launched_by": "u.martin@assureur-demo.example",
    "on_behalf_of": "service-sinistres",
    "scope": "sinistres:lecture,paiement",
    "run_id": "run-2026-11-03-0142"
  },
  "code": {
    "model": "fournisseur/modele@2026-09",
    "prompt_version": "0xb71552443a0b6e9793dd337ab10d057b354013fba35c2c82fdbdfb6df99d6b58",
    "policy_version": "2026-11-01",
    "recorder": "0.1.0"
  },
  "intent": "Régler le sinistre 2026-77812 après validation des pièces",
  "policy": {
    "rule": "paiement > 5000 CHF",
    "decision": "a_approuver",
    "ticket": "apr-1192",
    "redaction": "pii-v1"
  },
  "approval": {
    "decision": "approuve",
    "ticket": "apr-1192",
    "request_hash": "0xdd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0",
    "threshold": {
      "required": 2,
      "size": 3
    },
    "approvers": [
      "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
      "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
    ],
    "signatures": [
      "0x9b56cadb515c1fc18cc37f5b85bc78be8c916daef1ef9017fb3067f19dbcc8585ae2b338117e554f3ec7faa77bc615c82a17a695a4f76295383d9c931d2648a01b",
      "0xed53b07b60869c24a79d2f3db4729bdbc7ff581b1540e19e188f15ffed99d73f1f69b4e247299dcaecf9d69ad3487c313cd48fc1a7d7874f0a55a27330c074151b"
    ],
    "at": "2026-11-03T13:52:40.511Z",
    "reason": "Pièces validées"
  },
  "execution": {
    "tool": "sap.payments.create",
    "arguments": {
      "sha256": "0x0fb2fc1e0625e460687315e9861347a2f0ac8680068c84582080b3f46c8faaf9",
      "length": 96,
      "redacted": true
    },
    "status": "executee",
    "result": {
      "sha256": "0x8bbf8ae044c8bb12e88bf5065c9bf73bf5e2ea3222208355a24893722ab19624",
      "length": 85,
      "redacted": false
    },
    "duration_ms": 412,
    "is_error": false
  },
  "effects": [
    {
      "system": "SAP",
      "action": "ecriture",
      "object": "PAY-2026-55120",
      "amount": "7400.00",
      "currency": "CHF"
    }
  ],
  "context": [
    {
      "sha256": "0x2aca5294d591501378fe8629f9713fdf75af93a641fb1ab58c8e231edec823a4",
      "length": 48,
      "redacted": false,
      "kind": "document"
    },
    {
      "sha256": "0x7a184a4b8008ea03571b17038db8e653df769bba34b014c3df866a265af9de21",
      "length": 44,
      "redacted": false,
      "kind": "document"
    }
  ],
  "hash": "0x471dab56146ae2e4c678120af7faf5eed7b1f8e5db3657226de97614bde4dc00",
  "sig": "0xcd09159db6ca010502826e1130f1415f3c07e06aa9b663bb47a8ad0bff58d5ebaae96ef204dffc490dc1684386e9d7270256b41f3f2bf4f0b75ec369276cbf00"
}
```

Les pièces référencées, pour que l'exemple soit reproductible (octets UTF-8 du
texte, sans saut de ligne final) :

| Pièce | Octets | `length` | `sha256` |
|---|---|---|---|
| arguments (rédigés, `pii-v1`) | `{"claim_id":"2026-77812","amount":"7400.00","currency":"CHF","beneficiary_iban":"[REDIGE:iban]"}` | 96 | `0x0fb2fc1e0625e460687315e9861347a2f0ac8680068c84582080b3f46c8faaf9` |
| résultat | `{"content":[{"type":"text","text":"Paiement PAY-2026-55120 créé"}],"isError":false}` | 85 | `0x8bbf8ae044c8bb12e88bf5065c9bf73bf5e2ea3222208355a24893722ab19624` |
| pièce 1 | `piece 1 (contenu fictif) : constat du 2026-10-28` | 48 | `0x2aca5294d591501378fe8629f9713fdf75af93a641fb1ab58c8e231edec823a4` |
| pièce 2 | `piece 2 (contenu fictif) : facture du garage` | 44 | `0x7a184a4b8008ea03571b17038db8e653df769bba34b014c3df866a265af9de21` |
| `code.prompt_version` | `prompt systeme fictif v3` | 24 | `0xb71552443a0b6e9793dd337ab10d057b354013fba35c2c82fdbdfb6df99d6b58` |

## 6. Hachage et signature

### 6.1 Hachage d'un événement

Soit `E` l'événement et `E'` l'objet `E` privé de ses clés `hash` et `sig`
(quinze clés). Soit `C = JCS(E')`, encodé en UTF-8.

```text
hash = SHA-256( P_H || C )
P_H  = octets UTF-8 de "noortrace/evenement/v0\n"
     = 6e6f6f7274726163652f6576656e656d656e742f76300a   (23 octets, le dernier est 0x0a)
```

Le préfixe de domaine sépare les hachages d'événements de tout autre usage de
SHA-256 dans le système (manifeste, feuilles de Merkle, pièces). Le vérificateur
recalcule `hash` depuis `E'` et compare à `E.hash` (E-7). Il n'utilise jamais
`E.hash` comme entrée d'un autre calcul sans l'avoir recalculé.

### 6.2 Signature d'un événement

```text
sig = Ed25519.Sign( sk(recorder_key_id), P_S || C )
P_S = octets UTF-8 de "noortrace/signature-evenement/v0\n"
    = 6e6f6f7274726163652f7369676e61747572652d6576656e656d656e742f76300a   (33 octets)
```

Ed25519 « pur » de la RFC 8032 §5.1 : pas de pré-hachage (pas Ed25519ph), pas de
contexte (pas Ed25519ctx). Le message signé est le préfixe suivi des octets
canoniques, pas le hachage : la signature ne dépend pas du champ `hash`, et le
vérificateur la contrôle depuis `E'` (E-8). Signature de 64 octets `R || S` ;
le vérificateur DOIT refuser une signature dont `S` n'est pas réduit modulo
l'ordre du groupe (contrôle de la RFC 8032 §5.1.7) et une clé publique de
petit ordre. Clé publique de 32 octets (RFC 8032 §5.1.5), trouvée dans
`cles.json` par `recorder_key_id` (section 11).

Équation de vérification : la forme **sans cofacteur** de la RFC 8032 §5.1.7,
`[S]B = R + [k]A`, et non `[8][S]B = [8]R + [8][k]A`. `R` et `A` DOIVENT être
des encodages canoniques (coordonnée `y < p`, RFC 8032 §5.1.3 : un `y ≥ p` est
refusé, pas réduit) ; `A` NE DOIT PAS être l'un des huit points de petit ordre
(`8·A = 0`, encodages en annexe B). Une clé d'ordre mixte (`A' + T`, `T` de
petit ordre) n'est pas exclue par ces règles et les deux équations divergent
sur elle : c'est pourquoi l'équation est fixée, et pourquoi une bibliothèque qui
vérifie avec le cofacteur n'est pas conforme. Les deux implémentations du dépôt
vérifient sans cofacteur.

### 6.3 Signature d'une décision d'approbation (EIP-191)

Les approbateurs signent avec leur clé secp256k1, comme pour les contrats du
registre, par `personal_sign` (EIP-191, version `0x45`). Le condensé interne
reste en SHA-256 ; keccak256 n'intervient que là où EIP-191 l'impose, dans le
préfixe.

```text
A   = { "decision": …, "journal_id": …, "org_id": …, "request_hash": …, "ticket": … }
D_A = SHA-256( P_A || JCS(A) )          32 octets
P_A = octets UTF-8 de "noortrace/approbation/v0\n"
    = 6e6f6f7274726163652f617070726f626174696f6e2f76300a   (25 octets)
M   = keccak256( "\x19Ethereum Signed Message:\n32" || D_A )
sig = ECDSA-secp256k1.Sign( sk(approbateur), M ) = r (32) || s (32) || v (1), v ∈ {0x1b, 0x1c}
```

C'est exactement `signer.signMessage(getBytes(D_A))` d'ethers et la convention
de `ThresholdSignatures.prefixed`. Le vérificateur recouvre l'adresse depuis
`(M, r, s, v)` et la compare à `approvers[i]` (E-9) ; il refuse une signature
non canonique (`s` dans la moitié haute de l'ordre, `v` hors de {27, 28}),
comme le contrat. Il n'y a pas de domaine de chaîne ni d'adresse de contrat
dans `A` : la décision est hors chaîne, liée à l'organisation, au journal, au
ticket et à l'événement de demande.

### 6.4 Exemple numérique (événement seq 4)

Forme canonique `C` de l'événement de la section 5.5 (2188 octets UTF-8, une
seule ligne ; les accents sont en clair) :

```text
{"approval":{"approvers":["0x70997970c51812dc3a010c7d01b50e0d17dc79c8","0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"],"at":"2026-11-03T13:52:40.511Z","decision":"approuve","reason":"Pièces validées","request_hash":"0xdd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0","signatures":["0x9b56cadb515c1fc18cc37f5b85bc78be8c916daef1ef9017fb3067f19dbcc8585ae2b338117e554f3ec7faa77bc615c82a17a695a4f76295383d9c931d2648a01b","0xed53b07b60869c24a79d2f3db4729bdbc7ff581b1540e19e188f15ffed99d73f1f69b4e247299dcaecf9d69ad3487c313cd48fc1a7d7874f0a55a27330c074151b"],"threshold":{"required":2,"size":3},"ticket":"apr-1192"},"code":{"model":"fournisseur/modele@2026-09","policy_version":"2026-11-01","prompt_version":"0xb71552443a0b6e9793dd337ab10d057b354013fba35c2c82fdbdfb6df99d6b58","recorder":"0.1.0"},"context":[{"kind":"document","length":48,"redacted":false,"sha256":"0x2aca5294d591501378fe8629f9713fdf75af93a641fb1ab58c8e231edec823a4"},{"kind":"document","length":44,"redacted":false,"sha256":"0x7a184a4b8008ea03571b17038db8e653df769bba34b014c3df866a265af9de21"}],"delegation":{"launched_by":"u.martin@assureur-demo.example","on_behalf_of":"service-sinistres","run_id":"run-2026-11-03-0142","scope":"sinistres:lecture,paiement"},"effects":[{"action":"ecriture","amount":"7400.00","currency":"CHF","object":"PAY-2026-55120","system":"SAP"}],"execution":{"arguments":{"length":96,"redacted":true,"sha256":"0x0fb2fc1e0625e460687315e9861347a2f0ac8680068c84582080b3f46c8faaf9"},"duration_ms":412,"is_error":false,"result":{"length":85,"redacted":false,"sha256":"0x8bbf8ae044c8bb12e88bf5065c9bf73bf5e2ea3222208355a24893722ab19624"},"status":"executee","tool":"sap.payments.create"},"intent":"Régler le sinistre 2026-77812 après validation des pièces","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","policy":{"decision":"a_approuver","redaction":"pii-v1","rule":"paiement > 5000 CHF","ticket":"apr-1192"},"prev_hash":"0xadeb42cb3a4557effbf1bf2dd0a973a1e74563cd39fbb747202d6a4a0f5ad832","recorder_key_id":"rec-test-01","seq":4,"ts":"2026-11-03T13:52:41.090Z","version":0}
```

| Calcul | Valeur |
|---|---|
| `SHA-256(P_H ‖ C)` = `hash` | `0x471dab56146ae2e4c678120af7faf5eed7b1f8e5db3657226de97614bde4dc00` |
| `Ed25519(sk(rec-test-01), P_S ‖ C)` = `sig` | `0xcd09159db6ca010502826e1130f1415f3c07e06aa9b663bb47a8ad0bff58d5ebaae96ef204dffc490dc1684386e9d7270256b41f3f2bf4f0b75ec369276cbf00` |
| Clé publique `rec-test-01` | `0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045` |

Décision d'approbation (événement seq 3, annexe A), objet signé et signatures :

```text
JCS(A) = {"decision":"approuve","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","request_hash":"0xdd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0","ticket":"apr-1192"}
D_A    = 0x59b49949b9e97d7e3fd9d46a3992476dd2cc27c48e25ef77b467816d144f37a7
```

| Approbateur | Adresse | Signature `r ‖ s ‖ v` |
|---|---|---|
| Compte Hardhat 1 | `0x70997970c51812dc3a010c7d01b50e0d17dc79c8` | `0x9b56cadb515c1fc18cc37f5b85bc78be8c916daef1ef9017fb3067f19dbcc858` ‖ `5ae2b338117e554f3ec7faa77bc615c82a17a695a4f76295383d9c931d2648a0` ‖ `1b` |
| Compte Hardhat 2 | `0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc` | `0xed53b07b60869c24a79d2f3db4729bdbc7ff581b1540e19e188f15ffed99d73f` ‖ `1f69b4e247299dcaecf9d69ad3487c313cd48fc1a7d7874f0a55a27330c07415` ‖ `1b` |

## 7. Chaînage

### 7.1 Règles

1. Le premier événement d'un journal porte `seq = 1` et `prev_hash =
   0x0000000000000000000000000000000000000000000000000000000000000000`.
2. Tout événement `seq = n > 1` porte `prev_hash = hash(événement n − 1)`.
3. `seq` croît de 1 en 1 : pas de trou, pas de doublon, pas de retour en arrière.
4. `ts` ne décroît jamais le long de la chaîne.
5. `org_id` et `journal_id` sont constants le long de la chaîne.
6. `recorder_key_id` est constant, sauf immédiatement après un événement de
   rotation (section 8).
7. Le journal est en ajout seul : un événement écrit n'est ni modifié ni
   supprimé. Une correction est un nouvel événement.

### 7.2 Ce que la chaîne détecte

Soit un vérificateur qui tient deux événements consécutifs `a` et `b` (`b.seq =
a.seq + 1`) et recalcule leurs hachages et signatures.

| Altération | Symptôme | Contrôle |
|---|---|---|
| Modification d'un champ de `a` | `hash(a)` recalculé ≠ `a.hash`, ou `sig(a)` invalide si `a.hash` a été réécrit ; et `b.prev_hash ≠ hash(a)` | E-7, E-8, C-2 |
| Suppression de `a` (le vérificateur tient `a−1` et `b`) | `b.seq ≠ (a−1).seq + 1` ; `b.prev_hash ≠ hash(a−1)` | C-1, C-2 |
| Insertion d'un événement `x` entre `a` et `b` | `x.seq` en double ou `b.seq` décalé ; `b.prev_hash ≠ hash(x)` ; `x.sig` invalide si l'attaquant n'a pas la clé | C-1, C-2, E-8 |
| Réordonnancement (`b` avant `a`) | `b.prev_hash ≠ hash(a)` et `a.prev_hash ≠ hash(b)` ; `seq` non croissant | C-1, C-2 |
| Troncature de la fin du journal, ou d'une période | Non détectable par la chaîne seule : détectée par le manifeste de période (`last_seq`, racine) et ses ancres (sections 9 et 10), et par tout dossier qui porte le voisin omis (P-3 : un voisin de `seq = last_seq + 1` horodaté avant `period_end` prouve que le manifeste a tronqué sa période) | P-3, P-4 |
| Réécriture complète par qui détient la clé | Non détectable par la chaîne ni par la signature : détectée par les ancres externes de la période (CT-5) et par le registre (CT-4), qui bornent la fenêtre de réécriture à une heure | hors CT-1 |

La colonne « Contrôle » liste **tous** les symptômes observables, et un
vérificateur de chaîne les rapporte tous, pas seulement le premier : il
contrôle chaque événement pour lui-même (E-1 à E-11), puis chaque couple
d'événements consécutifs **dans l'ordre du fichier** (C-1 : `seq`, `ts`,
`org_id`, `journal_id` ; C-2 : `prev_hash` contre le hachage recalculé du
précédent ; C-3 : clé). Une suppression se voit donc à la fois par le trou de
`seq` (C-1) et par le `prev_hash` qui ne correspond plus (C-2) ; une
modification, par E-7 et E-8 sur l'événement et C-2 sur le suivant. Pour
l'insertion, E-8 n'apparaît que si l'attaquant n'a pas la clé de
l'enregistreur ; les vecteurs publient les deux cas (`journal-insere`, événement
forgé signé avec la clé : C-1, C-2 ; `journal-insere-sans-cle` : C-1, C-2, E-8).

Le dossier de preuve n'emporte que les voisins immédiats (section 11) : le
vérificateur contrôle donc C-1 et C-2 sur trois événements, et s'en remet au
chemin de Merkle et au manifeste pour le reste de la période.

## 8. Rotation de clé

Une rotation est un événement du journal, `execution.tool =
"noortrace.journal.rotation-cle"`, signé par l'**ancienne** clé
(`recorder_key_id` = ancienne) et contresigné par la **nouvelle** à l'intérieur
du corps, donc sous le hachage et la signature de l'ancienne.

`execution.arguments` est une référence en ligne dont `value` est :

```json
{
  "journal_id": "0x…",
  "new_key_id": "rec-test-02",
  "new_public_key": "0x…",
  "old_key_id": "rec-test-01",
  "org_id": "0x…",
  "valid_from": "2026-11-03T13:59:59.999Z",
  "counter_sig": "0x…"
}
```

```text
R           = value sans counter_sig (six clés)
counter_sig = Ed25519.Sign( sk(new_key_id), P_R || JCS(R) )
P_R         = octets UTF-8 de "noortrace/signature-rotation/v0\n"
            = 6e6f6f7274726163652f7369676e61747572652d726f746174696f6e2f76300a   (32 octets)
```

Règles :

1. `old_key_id` = `recorder_key_id` de l'événement de rotation ; `valid_from` =
   `ts` de l'événement ; `org_id` et `journal_id` = ceux de l'événement (E-10).
2. Tout événement de `seq` strictement supérieur à celui de la rotation porte
   `recorder_key_id = new_key_id`, jusqu'à la rotation suivante (C-3).
3. Dans `cles.json` (section 11), la nouvelle clé a `valid_from = ts` de la
   rotation et l'ancienne a `valid_to = ts` (bornes incluses : à l'instant exact
   de la rotation, les deux valent). Cette règle est normative quelle que soit
   la `source` nommée dans `cles.json` : la validité d'une clé issue d'une
   rotation du journal est celle que le journal annonce, et non la date
   d'inscription au registre (`registeredAt` de `RecorderRegistry`, qui relève
   du contrôle 8). Quand le dossier prouve l'événement de rotation, le
   vérificateur la contrôle (E-10) ; dans tous les cas, il contrôle que le `ts`
   de chaque événement est dans l'intervalle annoncé de la clé qui le signe
   (E-11). `new_key_id` DOIT différer de `old_key_id` (E-10) : les identifiants
   sont uniques dans `cles.json`, et une rotation vers le même identifiant
   rendrait C-3 et E-11 indécidables.
4. `effects` porte `{ "system": "noortrace", "action": "ecriture", "object":
   "cle:<new_key_id>", "amount": null, "currency": null }`.
5. L'inscription de la nouvelle clé dans `RecorderRegistry` (signatures des
   approbateurs au seuil, `registerDigest`) et la révocation de l'ancienne
   relèvent de CT-4 ; la cohérence entre l'événement de rotation et le registre
   est un contrôle de CT-4 (section 11.4, contrôle 8).

Exemple (seq 5 de l'annexe A) : `JCS(R)` et sa contresignature.

```text
JCS(R)      = {"journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","new_key_id":"rec-test-02","new_public_key":"0xfd08757fa4798c3c8757bbf5a0db49580cbcb80075ddb30f13f881b0f47aacb3","old_key_id":"rec-test-01","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","valid_from":"2026-11-03T13:59:59.999Z"}
counter_sig = 0xe107f72204e19597866fb4967e8c30285027f5f87af7fe865a7360c640a8926d1c9c0699e25bb1fe6c6e0fdf161fbbbe5e0edeb8e2fb153234e863ae4598ae04
```

Un changement de politique suit le même schéma avec `noortrace.journal.politique`
et `value = { "policy_version": "…", "policy_sha256": "0x…" }` (SHA-256 des
octets de la politique, CT-3), sans contresignature.

## 9. Arbre de Merkle, période vide, preuve d'inclusion

### 9.1 Construction (RFC 6962 §2.1)

Entrées : les `hash` des événements de la période, dans l'ordre des `seq`,
`D[0..n-1]` (`D[i]` = hachage de l'événement `first_seq + i`, 32 octets).

```text
feuille  L(i)        = SHA-256( 0x00 || D[i] )                               33 octets hachés
nœud     N(g, d)     = SHA-256( 0x01 || g || d )                             65 octets hachés
MTH(D[0..0])         = L(0)                                                  n = 1
MTH(D[0..n-1])       = N( MTH(D[0..k-1]), MTH(D[k..n-1]) )                   n > 1, k = plus grande puissance de 2 strictement inférieure à n
```

Le préfixe `0x00` des feuilles et `0x01` des nœuds rend impossible de faire
passer un nœud pour une feuille (attaque de second pré-image). `D[i]` est le
hachage de l'événement, pas sa forme canonique : la feuille se recalcule depuis
le seul `hash`, mais le vérificateur d'un dossier recalcule d'abord `hash`
depuis l'événement (E-7) avant d'en faire une feuille (M-1).

### 9.2 Période vide

Une période sans événement a pour racine **32 octets nuls** :
`0x0000000000000000000000000000000000000000000000000000000000000000`.

C'est une convention NOORTRACE, imposée par `PeriodRegistry.submitPeriod` qui
exige `root == bytes32(0)` quand `lastSeq + 1 == firstSeq`, et non le hachage de
l'arbre vide de la RFC 6962 (`MTH({}) = SHA-256("") =
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`). Un
implémenteur qui reprend une bibliothèque RFC 6962 DOIT traiter `n = 0` à part.
Inversement, une période non vide ne peut pas avoir une racine nulle (P-4) : la
probabilité qu'un SHA-256 soit nul est négligeable, et le contrat la refuse.

### 9.3 Preuve d'inclusion

Pour la feuille d'indice `m` (0 ≤ m < n) dans l'arbre de taille `n`, le chemin
d'audit `PATH(m, D[0..n-1])` de la RFC 6962 §2.1.1 :

```text
PATH(0, {d0})          = {}
PATH(m, D[0..n-1])     = PATH(m, D[0..k-1])     || { MTH(D[k..n-1]) }     si m < k
                       = PATH(m − k, D[k..n-1]) || { MTH(D[0..k-1]) }     si m ≥ k
```

Le fichier `chemin.json` porte `tree_size = n`, `leaf_index = m = seq −
first_seq`, `leaf_hash = L(m)`, `path` (du bas vers le haut) et `root`.

Vérification (algorithme de la RFC 9162 §2.1.3.2, reproduit pour qu'il n'y ait
pas à la lire) :

```text
entrées : leaf_hash, m, n, path[0..p-1], root attendue
si m ≥ n : rejeter
fn ← m ; sn ← n − 1 ; r ← leaf_hash
pour chaque h de path, dans l'ordre :
    si sn = 0 : rejeter                      (chemin trop long)
    si fn est impair ou fn = sn :
        r ← SHA-256(0x01 || h || r)           (h est à gauche)
        tant que fn n'est pas impair et fn ≠ 0 : fn ← fn >> 1 ; sn ← sn >> 1
    sinon :
        r ← SHA-256(0x01 || r || h)           (h est à droite)
    fn ← fn >> 1 ; sn ← sn >> 1
accepter si et seulement si sn = 0 et r = root
```

Le vérificateur DOIT exécuter cet algorithme, et non recalculer la racine en
devinant la position des nœuds : il garantit que `path` a exactement la longueur
attendue pour `(m, n)` (M-2).

### 9.4 Exemple numérique complet

Période `[2026-11-03T13:00:00Z, 14:00:00Z)`, cinq événements (annexe A), `n = 5`,
`k = 4`.

| | Valeur |
|---|---|
| `D[0]` = hash seq 1 | `0x64994cc38adf2e7532b2f02fae0e78086b1970c5ffd36a37dc3c78143cfe8179` |
| `D[1]` = hash seq 2 | `0xdd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0` |
| `D[2]` = hash seq 3 | `0xadeb42cb3a4557effbf1bf2dd0a973a1e74563cd39fbb747202d6a4a0f5ad832` |
| `D[3]` = hash seq 4 | `0x471dab56146ae2e4c678120af7faf5eed7b1f8e5db3657226de97614bde4dc00` |
| `D[4]` = hash seq 5 | `0x506e54e1ec35a6432114fc06947b23c753ce6d5cf4260354b7fdbed011b04f05` |
| `L(0)` = SHA-256(00 ‖ D[0]) | `0xd5e2098df5be8721f7343aab8ad414a5bea5b55bb0fb0e72eb8fb9bb6c3f5a8b` |
| `L(1)` | `0x3ef9fdf53c5fd27d37c20efdce9d0d8bfcfd459d491e5cb66dd3f384540d270c` |
| `L(2)` | `0x8380b74438d71a5fb81aa3b62f1c7e0b06cb0e9c73f5d5a42f44372e203fbf3e` |
| `L(3)` | `0x3617a8c28e38e476cc671a109baf783cd70e1f24eca0278280a215b28f1c55db` |
| `L(4)` | `0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0` |
| `N01` = SHA-256(01 ‖ L(0) ‖ L(1)) | `0xa5b5b030de6510a06da18b109b73e7b85c4afe3e6d0fb89b4bd9b53b3d42f79e` |
| `N23` = SHA-256(01 ‖ L(2) ‖ L(3)) | `0x2fb61705d23c09d71bebc1a297940ce119c3bda5b3357d39d76043cb554cfea8` |
| `N0123` = SHA-256(01 ‖ N01 ‖ N23) | `0x22264c23c7f8fea323dd1998376576e0fa4d14c67dc577dc7a01e5ae9c2e4cf6` |
| racine = SHA-256(01 ‖ N0123 ‖ L(4)) | `0x6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06` |

```text
                racine
               /      \
          N0123        L(4)
         /     \
      N01       N23
     /   \     /   \
   L(0) L(1) L(2) L(3)
```

Preuve d'inclusion de l'événement seq 4 (`m = 3`, `n = 5`) : `path = [L(2), N01,
L(4)]`.

<!-- schema: chemin -->
```json
{
  "version": 0,
  "tree_size": 5,
  "leaf_index": 3,
  "leaf_hash": "0x3617a8c28e38e476cc671a109baf783cd70e1f24eca0278280a215b28f1c55db",
  "path": [
    "0x8380b74438d71a5fb81aa3b62f1c7e0b06cb0e9c73f5d5a42f44372e203fbf3e",
    "0xa5b5b030de6510a06da18b109b73e7b85c4afe3e6d0fb89b4bd9b53b3d42f79e",
    "0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0"
  ],
  "root": "0x6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06"
}
```

Déroulé de la vérification : `fn = 3, sn = 4, r = L(3)`.

| Étape | `h` | Condition | Calcul | `fn, sn` après |
|---|---|---|---|---|
| 1 | `L(2)` | `fn = 3` impair | `r = SHA-256(01 ‖ L(2) ‖ L(3)) = N23` | `1, 2` |
| 2 | `N01` | `fn = 1` impair | `r = SHA-256(01 ‖ N01 ‖ N23) = N0123` | `0, 1` |
| 3 | `L(4)` | `fn = 0` pair, `fn ≠ sn` | `r = SHA-256(01 ‖ N0123 ‖ L(4)) = racine` | `0, 0` |

`sn = 0` et `r = root` : la preuve est acceptée.

## 10. Manifeste de période

### 10.1 Contenu

<!-- schema: manifeste -->
```json
{
  "version": 0,
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
  "period_start": 1793710800,
  "period_end": 1793714400,
  "first_seq": 1,
  "last_seq": 5,
  "count": 5,
  "root": "0x6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06",
  "prev_period_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "recorder_key_id": "rec-test-02",
  "nonce": "0xcfcd0a8277074d0839e4469fdced701c0fdf2855f1001e17d3fada335da05547",
  "generated_at": "2026-11-03T14:00:00.250Z"
}
```

| Clé | Type | Contraintes |
|---|---|---|
| `version` | entier | Constante `0`. Ce `0` est aussi la valeur `version` de `PeriodMeta`. |
| `org_id`, `journal_id` | hex 32 octets | Ceux des événements. |
| `period_start` | secondes UNIX | Heure UTC pleine : multiple de 3600. Inclus. |
| `period_end` | secondes UNIX | `period_start + 3600`. Exclu. |
| `first_seq` | entier ≥ 1 | `1` pour la première période du journal ; sinon `last_seq` de la période précédente + 1. |
| `last_seq` | entier ≥ 0 | Dernier `seq` de la période ; `first_seq − 1` si la période est vide. |
| `count` | entier ≥ 0 | `last_seq − first_seq + 1`. |
| `root` | hex 32 octets | Section 9 ; 32 octets nuls si et seulement si `count = 0`. |
| `prev_period_hash` | hex 32 octets | `periodHash` de la période précédente du journal ; 32 octets nuls pour la première. |
| `recorder_key_id` | identifiant de clé | Clé qui signe le manifeste : la clé **en vigueur à la clôture**, c'est-à-dire la dernière clé annoncée dont `valid_from ≤ generated_at` ; autrement dit la clé du dernier événement du journal avant la clôture, ou `new_key_id` si cet événement est une rotation. Une rotation en dernier événement de la période fait donc signer le manifeste par la nouvelle clé. |
| `nonce` | hex 32 octets | Aléa frais par manifeste. Deux clôtures d'une même heure n'ont jamais la même empreinte ; un `periodHash` ne se répète donc jamais, ce que `PeriodRegistry` exige (unicité par organisation). |
| `generated_at` | horodatage | Instant de production du manifeste, ≥ `period_end` en temps nominal. |

Les événements de la période sont ceux dont `period_start ≤ ts < period_end`,
et ils sont contigus en `seq` puisque `ts` ne décroît pas (section 7). La
rotation de clé de l'exemple (seq 5, `rec-test-01` → `rec-test-02`) est le
dernier événement de la période : l'événement de rotation lui-même est signé
par l'ancienne clé, mais le manifeste, produit après lui, l'est par la
nouvelle, comme celui de la période vide qui suit.

### 10.2 Hachage et signature

```text
C_M        = JCS(manifeste), UTF-8
periodHash = SHA-256( P_M || C_M )
P_M        = octets UTF-8 de "noortrace/manifeste/v0\n"
           = 6e6f6f7274726163652f6d616e6966657374652f76300a   (23 octets)
sig_M      = Ed25519.Sign( sk(recorder_key_id), P_SM || C_M )
P_SM       = octets UTF-8 de "noortrace/signature-manifeste/v0\n"
           = 6e6f6f7274726163652f7369676e61747572652d6d616e6966657374652f76300a   (33 octets)
```

La signature est portée **à côté** du manifeste, dans `manifeste.sig`, jamais
dedans : `periodHash` ne dépend pas de la signature, et le contrat ne voit que
`periodHash`.

<!-- schema: manifeste_sig -->
```json
{
  "version": 0,
  "period_hash": "0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
  "recorder_key_id": "rec-test-02",
  "sig": "0xaddb3e23b4616a69b345932cb717b41c8aedf30b2aa676ff8f657f7180277c0f16c7f468f09d4b5caa331d44de0a1562451a3aec01b9bd44cf5083b45a41ed01"
}
```

Exemple : forme canonique du manifeste de la section 10.1 et résultats.

```text
C_M        = {"count":5,"first_seq":1,"generated_at":"2026-11-03T14:00:00.250Z","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","last_seq":5,"nonce":"0xcfcd0a8277074d0839e4469fdced701c0fdf2855f1001e17d3fada335da05547","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","period_end":1793714400,"period_start":1793710800,"prev_period_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","recorder_key_id":"rec-test-02","root":"0x6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06","version":0}
periodHash = 0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1
sig_M      = 0xaddb3e23b4616a69b345932cb717b41c8aedf30b2aa676ff8f657f7180277c0f16c7f468f09d4b5caa331d44de0a1562451a3aec01b9bd44cf5083b45a41ed01   (clé rec-test-02)
```

### 10.3 Période vide et continuité

La période suivante de l'exemple est vide, signée par la clé issue de la
rotation :

<!-- schema: manifeste -->
```json
{
  "version": 0,
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
  "period_start": 1793714400,
  "period_end": 1793718000,
  "first_seq": 6,
  "last_seq": 5,
  "count": 0,
  "root": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "prev_period_hash": "0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1",
  "recorder_key_id": "rec-test-02",
  "nonce": "0x2b2b0095b99b60b2b3baae78815fd1590b4c01c6e63304ab0a682e5f6270f86d",
  "generated_at": "2026-11-03T15:00:00.112Z"
}
```

```text
periodHash = 0x3ed80e52f0d52f184986da64ba009947998cfd41624899ad5137594c58f9be4b
sig_M      = 0x054847990ed1662c10a2b5cde8d7389a17af5a074d6e068c0a3ed855b79d2368c4cd95e425d0b28a3534b108864018c6f6b9bfc994ab0bdc639adf5f0b9fbb03   (clé rec-test-02)
```

Continuité entre deux manifestes consécutifs `p` et `q` du même journal
(contrôle P-5, quand le vérificateur tient les deux) :

- `q.period_start = p.period_end` ;
- `q.first_seq = p.last_seq + 1` ;
- `q.prev_period_hash = periodHash(p)`.

Les deux premières règles sont celles que `PeriodRegistry.submitPeriod` impose
(« discontinuité temporelle », « discontinuité de sequence ») ; la troisième
chaîne les manifestes entre eux indépendamment du registre.

### 10.4 Correspondance avec `PeriodRegistry`

`PeriodRegistry.PeriodMeta` reçoit, champ pour champ :

| `PeriodMeta` | Source | Remarque |
|---|---|---|
| `orgId` | `org_id` | |
| `journalId` | `journal_id` | |
| `periodHash` | `periodHash` = SHA-256 de la section 10.2 | Opaque pour le contrat, qui exige seulement non nul et unique par organisation. La NatSpec de `contracts/PeriodRegistry.sol` (`PeriodMeta.periodHash`) et le calcul de `scripts/e2e/dev-roundtrip.mjs` sont alignés sur cette définition : SHA-256 du manifeste canonique préfixé, `version: 0` (section 16). |
| `root` | `root` | Nulle si et seulement si la période est vide. |
| `periodStart`, `periodEnd` | `period_start`, `period_end` | |
| `firstSeq`, `lastSeq` | `first_seq`, `last_seq` | |
| `version` | `version` (= 0) | |
| `uri` | emplacement du manifeste, libre | Pas dans le manifeste : il ne peut pas se contenir. |

`count`, `prev_period_hash`, `recorder_key_id`, `nonce` et `generated_at` ne vont
pas au contrat ; ils sont couverts par `periodHash`. Le condensé que les
approbateurs signent pour la clôture, `periodDigest`, et l'empreinte ancrée dans
`AttestationRegistry`, `anchorFingerprint = keccak256(org_id ‖ journal_id ‖
periodHash)`, restent en keccak256 parce que l'EVM l'impose, et sont ceux de
`scripts/lib/noortrace.mjs`. Pour l'exemple :
`anchorFingerprint = 0x3200e496c555b46459191c852a7f79b1e0b4156802cac2f2df7b80b0aa9d823b`.
Le contrôle de ces valeurs contre le registre est le contrôle 8 (CT-4).

## 11. Dossier de preuve v0

### 11.1 Forme

Un dossier est un répertoire. Il prouve **un** événement : il ne contient
jamais d'autre événement que l'événement prouvé, ses deux voisins immédiats, et
les événements de décision d'approbation liés à son ticket (pour le dossier
d'une décision, `approbations.json` contient l'événement prouvé lui-même, A-2).
Les fichiers du répertoire que `dossier.json` ne déclare pas (le fichier
`attendu.json` des vecteurs, par exemple) sont ignorés par le vérificateur : ni
vérifiés, ni exploités. Les pièces fournies à part (E-6) et un second manifeste
(continuité, P-5) ne sont pas des parties du dossier : ce sont des entrées
supplémentaires de la ligne de commande du vérificateur, fixées par CT-6. Son
index est `dossier.json` :

<!-- schema: dossier -->
```json
{
  "version": 0,
  "event": {
    "seq": 4,
    "hash": "0x471dab56146ae2e4c678120af7faf5eed7b1f8e5db3657226de97614bde4dc00"
  },
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
  "generated_at": "2026-11-04T09:15:00.000Z",
  "parts": [
    { "name": "evenement", "file": "evenement.json", "sha256": "0x389595f49b2f8576ac9c6784f5cdb4f4cfc5ff6841d154c36f0457246bd11115", "present": true, "reason_if_absent": null },
    { "name": "voisins", "file": "voisins.json", "sha256": "0xe8f1b441393b1c743d162d69dc5406a240ed43431644321653d33e3bf78bb7b8", "present": true, "reason_if_absent": null },
    { "name": "chemin", "file": "chemin.json", "sha256": "0x128b24e022caccbfb5398e8dc6cbe2d4488fca71bfd066a358ccebcc5f85900b", "present": true, "reason_if_absent": null },
    { "name": "manifeste", "file": "manifeste.json", "sha256": "0x2ba05975e6ce3c0dce6f44107a1406bc4389fdaddeb5d7ad2787c175b0baae2a", "present": true, "reason_if_absent": null },
    { "name": "manifeste_sig", "file": "manifeste.sig", "sha256": "0xc65e38f9dd1853e0989934335095ef543163e61c46da8b54b6986420de5d9251", "present": true, "reason_if_absent": null },
    { "name": "cles", "file": "cles.json", "sha256": "0xd3832a43940191a60512937c61900c0b1a00299e5bb7177765d744bfd25c377f", "present": true, "reason_if_absent": null },
    { "name": "approbations", "file": "approbations.json", "sha256": "0xa9b7effadb2793db2a5bc0ae8e4f9f7181aadcd9510860ef69071437da4341ba", "present": true, "reason_if_absent": null },
    { "name": "jeton_rfc3161", "file": "jeton-rfc3161.der", "sha256": null, "present": false, "reason_if_absent": "hors périmètre CT-1" },
    { "name": "preuve_ots", "file": "preuve.ots", "sha256": null, "present": false, "reason_if_absent": "hors périmètre CT-1" },
    { "name": "registre", "file": "registre.json", "sha256": null, "present": false, "reason_if_absent": "hors périmètre CT-1" },
    { "name": "certificat_commit", "file": "certificat-commit.json", "sha256": null, "present": false, "reason_if_absent": "hors périmètre CT-1" },
    { "name": "validateurs", "file": "validateurs.json", "sha256": null, "present": false, "reason_if_absent": "hors périmètre CT-1" }
  ]
}
```

Les douze parties sont toujours déclarées, dans cet ordre. `sha256` est le
SHA-256 des octets du fichier tel qu'il est dans le répertoire (D-2), ce qui
fige le dossier : la mise en forme des fichiers JSON du dossier est libre, mais
elle ne doit plus changer une fois l'index écrit. Les SHA-256 ci-dessus sont ceux
des fichiers écrits par `JSON.stringify(objet, null, 2)` suivi d'un saut de
ligne, l'implémentation de référence des vecteurs. Une partie absente a
`sha256: null`, `present: false` et une raison non vide. Les cinq dernières
parties sont réservées à CT-5 (jeton RFC 3161, preuve OpenTimestamps) et CT-4
(reçu de la transaction du registre, certificat de commit du bloc, jeu de
validateurs) ; dans les vecteurs de CT-1 elles sont absentes avec la raison
« hors périmètre CT-1 ». Les six premières sont toujours présentes ;
`approbations.json` est absent, avec la raison « aucune approbation liée »,
quand `approval` de l'événement prouvé vaut `null`.

### 11.2 Fichiers

| Fichier | Schéma | Contenu |
|---|---|---|
| `dossier.json` | `dossier-v0.schema.json` | L'index ci-dessus. |
| `evenement.json` | `evenement-v0.schema.json` | L'événement prouvé, complet. |
| `voisins.json` | `dossier-v0.schema.json#/$defs/voisins` | `{ "version": 0, "previous": événement ou null, "next": événement ou null }`. `previous` est `null` si et seulement si `seq = 1` ; `next` est `null` si l'événement est le dernier connu du journal au moment de l'export. |
| `chemin.json` | `#/$defs/chemin` | Preuve d'inclusion (section 9.3). `leaf_index = seq − first_seq` du manifeste. |
| `manifeste.json` | `manifeste-v0.schema.json` | Le manifeste de la période qui contient l'événement. |
| `manifeste.sig` | `#/$defs/manifeste_sig` | Signature du manifeste (section 10.2). JSON malgré son extension. |
| `cles.json` | `#/$defs/cles` | `{ "version": 0, "org_id", "journal_id", "keys": [ { "key_id", "algorithm": "ed25519", "public_key", "valid_from", "valid_to", "source" } ] }`. Toutes les clés nommées par les événements et le manifeste du dossier y figurent. `org_id` et `journal_id` sont ceux de l'événement prouvé ; `key_id` et `public_key` sont uniques dans `keys` (deux entrées de même identifiant, ou deux identifiants pour une même clé publique, rendent le fichier inexploitable : E-8) ; `valid_to`, s'il n'est pas `null`, est ≥ `valid_from`. `valid_from` et `valid_to` (nullable) sont la période de validité **telle qu'annoncée** : `source` nomme d'où l'exportateur la tient (registre CT-4, événement de rotation, onboarding, vecteurs), et le vérificateur ne peut pas la prouver par lui-même sans `registre.json` ; pour une clé introduite par une rotation du journal, elle est fixée par la section 8, règle 3. |
| `approbations.json` | `#/$defs/approbations` | `{ "version": 0, "ticket", "request_hash", "approver_set": { "threshold": { "required", "size" }, "members": [adresses], "source" }, "events": [événements de décision complets] }`. Le jeu déclaré et sa source ; les événements `noortrace.approbation.decision` du ticket. `source` est un texte libre (1 à 256 caractères) qui dit d'où vient le jeu (`CuratorSet` lu à telle hauteur, vecteurs) ; il entre dans le SHA-256 du fichier, d'où l'exemple complet ci-dessous. |
| `jeton-rfc3161.der` | CT-5 | Jeton d'horodatage qualifié sur SHA-256 de la racine. |
| `preuve.ots` | CT-5 | Preuve OpenTimestamps de la racine. |
| `registre.json` | CT-4 | Reçu de `submitPeriod` et de `anchor`, valeurs lues (`getPeriod`, `lookup`, `recorderByPubKey`). |
| `certificat-commit.json` | CT-4 | Certificat de commit du bloc (`noor_getCommitCertificate`), vérifié par `scripts/verify/certificat-commit.mjs`. |
| `validateurs.json` | CT-4 | Jeu de validateurs du bloc. |

Exemple de `cles.json` du dossier de référence :

<!-- schema: cles -->
```json
{
  "version": 0,
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
  "keys": [
    {
      "key_id": "rec-test-01",
      "algorithm": "ed25519",
      "public_key": "0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045",
      "valid_from": "2026-11-01T00:00:00.000Z",
      "valid_to": "2026-11-03T13:59:59.999Z",
      "source": "vecteurs CT-1"
    },
    {
      "key_id": "rec-test-02",
      "algorithm": "ed25519",
      "public_key": "0xfd08757fa4798c3c8757bbf5a0db49580cbcb80075ddb30f13f881b0f47aacb3",
      "valid_from": "2026-11-03T13:59:59.999Z",
      "valid_to": null,
      "source": "vecteurs CT-1"
    }
  ]
}
```

Exemple de `approbations.json` du même dossier (la décision seq 3 de l'annexe A,
complète ; son SHA-256 est celui que `dossier.json` de la section 11.1 déclare) :

<!-- schema: approbations -->
```json
{
  "version": 0,
  "ticket": "apr-1192",
  "request_hash": "0xdd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0",
  "approver_set": {
    "threshold": {
      "required": 2,
      "size": 3
    },
    "members": [
      "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
      "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
      "0x90f79bf6eb2c4f870365e785982e1f101e93b906"
    ],
    "source": "comptes Hardhat 1 à 3 (vecteurs CT-1)"
  },
  "events": [
    {
      "version": 0,
      "seq": 3,
      "ts": "2026-11-03T13:52:40.511Z",
      "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
      "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
      "recorder_key_id": "rec-test-01",
      "prev_hash": "0xdd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0",
      "delegation": {
        "launched_by": "u.martin@assureur-demo.example",
        "on_behalf_of": "service-sinistres",
        "scope": "sinistres:lecture,paiement",
        "run_id": "run-2026-11-03-0142"
      },
      "code": {
        "model": "fournisseur/modele@2026-09",
        "prompt_version": "0xb71552443a0b6e9793dd337ab10d057b354013fba35c2c82fdbdfb6df99d6b58",
        "policy_version": "2026-11-01",
        "recorder": "0.1.0"
      },
      "intent": null,
      "policy": {
        "rule": null,
        "decision": "sans_objet",
        "ticket": "apr-1192",
        "redaction": null
      },
      "approval": {
        "decision": "approuve",
        "ticket": "apr-1192",
        "request_hash": "0xdd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0",
        "threshold": {
          "required": 2,
          "size": 3
        },
        "approvers": [
          "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
          "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
        ],
        "signatures": [
          "0x9b56cadb515c1fc18cc37f5b85bc78be8c916daef1ef9017fb3067f19dbcc8585ae2b338117e554f3ec7faa77bc615c82a17a695a4f76295383d9c931d2648a01b",
          "0xed53b07b60869c24a79d2f3db4729bdbc7ff581b1540e19e188f15ffed99d73f1f69b4e247299dcaecf9d69ad3487c313cd48fc1a7d7874f0a55a27330c074151b"
        ],
        "at": "2026-11-03T13:52:40.511Z",
        "reason": "Pièces validées"
      },
      "execution": {
        "tool": "noortrace.approbation.decision",
        "arguments": {
          "sha256": "0xc9b9e6f3ebf13147b98aa59a238979c3dc629b1b6d2ba3f623ea5f122df2a0bb",
          "length": 287,
          "redacted": false,
          "value": {
            "decision": "approuve",
            "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
            "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
            "request_hash": "0xdd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0",
            "ticket": "apr-1192"
          }
        },
        "status": "executee",
        "result": null,
        "duration_ms": null,
        "is_error": null
      },
      "effects": [],
      "context": [],
      "hash": "0xadeb42cb3a4557effbf1bf2dd0a973a1e74563cd39fbb747202d6a4a0f5ad832",
      "sig": "0x5ba332ccd1a5eaeebd119c0a353f9ee474338edeb07c11584d00cb7145c222a9f2a3e5a792f2e7d71588aeac7543d5d7f07ea39002db3d8b6f6c425972a23006"
    }
  ]
}
```

### 11.3 Les huit contrôles de l'architecture

| N° | Contrôle de l'architecture | Pièces | Exécutable avec |
|---|---|---|---|
| 1 | Hachage canonique de l'événement et égalité avec `hash` | `evenement.json` | **CT-1** |
| 2 | Continuité de la chaîne avec les voisins fournis | `voisins.json` | **CT-1** |
| 3 | Recalcul du chemin de Merkle jusqu'à la racine | `chemin.json`, `manifeste.json` | **CT-1** |
| 4 | Signature du jeton RFC 3161 et égalité avec SHA-256 de la racine | `jeton-rfc3161.der`, chaîne de certificats | CT-5 |
| 5 | Preuve OpenTimestamps contre les en-têtes Bitcoin | `preuve.ots`, en-têtes | CT-5 |
| 6 | Signature Ed25519 de l'enregistreur sur l'événement | `evenement.json`, `cles.json` | **CT-1** |
| 7 | Signatures des approbateurs et respect du seuil | `approbations.json` | **CT-1** |
| 8 | Inclusion de la transaction du registre dans un bloc certifié par un quorum | `registre.json`, `certificat-commit.json`, `validateurs.json` | CT-4 |

Tant que 4, 5 et 8 ne sont pas exécutables, le verdict du vérificateur est
borné : « cet événement est bien formé, chaîné à ses voisins, inclus dans la
période close par ce manifeste signé par cette clé, et approuvé par ces
adresses » ; il ne dit rien sur la date ni sur l'ancre. Le vérificateur DOIT
énoncer cette borne dans sa sortie quand des parties sont absentes.

### 11.4 Contrôles du vérificateur, numérotés

Ce qu'un réviseur peut attendre, contrôle par contrôle. Un dossier est valide si
tous les contrôles exécutés passent **et** si chaque contrôle non exécuté l'est
pour une raison admise : partie absente avec raison dans l'index (A-2, A-3 et
A-4 quand `approval` est `null` ; contrôles des parties réservées), ou événement
de demande hors du dossier (A-4). Un seul échec rend le dossier invalide ; un
contrôle non exécuté pour toute autre raison le rend invalide aussi, et le
vérificateur le dit à part des échecs. Un contrôle dont la pièce est absente
avec raison est « non exécuté », jamais « passé ».

Une partie déclarée présente dont le fichier n'est pas un objet JSON (texte qui
n'est pas du JSON, littéral `null`, tableau, nombre) ou qui ne respecte pas son
schéma met en échec le contrôle qui porte la partie : `dossier.json` → D-1,
`evenement.json` → E-1, l'enveloppe de `voisins.json` → C-1 (ses événements →
E-1), `chemin.json` → M-2, `manifeste.json` → P-1, `manifeste.sig` → P-5,
`cles.json` → E-8, `approbations.json` → A-1 ; un fichier sans forme canonique
(nombre non entier, clé en double, substitut isolé) → E-2. Les contrôles qui
dépendent de la partie sont alors non exécutés, sans raison admise, et le
dossier est invalide. Le vérificateur ne reprend rien d'une partie inexploitable
dans son rapport (pas de `seq` ni de `hash` lus dans l'index à la place de
`evenement.json`).

| Id | Contrôle | Contrôle de l'architecture |
|---|---|---|
| D-1 | `dossier.json` valide contre son schéma ; `event.seq` et `event.hash` égaux à ceux de `evenement.json`. | — |
| D-2 | Pour chaque partie présente, SHA-256 du fichier = `sha256` déclaré ; pour chaque partie absente, fichier absent du répertoire et raison non vide. | — |
| E-1 | Chaque événement du dossier valide contre `evenement-v0.schema.json`. | 1 |
| E-2 | Forme canonique calculable : aucun nombre non entier ou hors intervalle, aucun substitut isolé, aucune clé en double. | 1 |
| E-3 | `execution.tool` en `noortrace.` est l'un des quatre noms réservés ; les champs de l'événement sont cohérents avec sa sorte (tables 5.1 et 5.3 : `policy.decision`, `approval`, `intent`, `status`, `result`, `duration_ms`, `is_error`, `arguments.value`, `effects`). | 1 |
| E-4 | Toute référence `redacted: true` est accompagnée d'un `policy.redaction` non nul. | 1 |
| E-5 | `approval.approvers` et `approval.signatures` ont la même longueur ; `approval.ticket = policy.ticket`. | 7 |
| E-6 | Toute référence avec `value` vérifie `sha256 = SHA-256(JCS(value))` et `length` ; toute pièce fournie à part vérifie son `sha256` et sa `length`. | 1 |
| E-7 | `hash` recalculé depuis l'objet (section 6.1) égal à `hash`. | 1 |
| E-8 | `cles.json` conforme à son schéma, `org_id` et `journal_id` égaux à ceux de l'événement, `key_id` et `public_key` uniques, `valid_to ≥ valid_from` ; `sig` valide sous la clé publique `recorder_key_id` de `cles.json`, sur `P_S ‖ C` (section 6.2) ; clé absente de `cles.json` : échec. | 6 |
| E-9 | Pour chaque `i`, l'adresse recouvrée de `signatures[i]` sur `D_A` (section 6.3) = `approvers[i]` ; signature canonique. | 7 |
| E-10 | Événement de rotation : `old_key_id`, `valid_from`, `org_id`, `journal_id` cohérents avec l'enveloppe ; `new_key_id ≠ old_key_id` ; `counter_sig` valide sous `new_public_key` ; dans `cles.json`, `new_public_key` = clé de `new_key_id`, `valid_from` de `new_key_id` = `ts` et `valid_to` de `old_key_id` = `ts` (section 8, règle 3). | 6 |
| E-11 | `ts` de chaque événement dans `[valid_from, valid_to]` (bornes incluses, instants à la milliseconde) de la clé qui le signe ; `valid_to` nul : pas de borne haute. Clé absente de `cles.json` : non exécuté, l'échec est porté par E-8. | 6 |
| C-1 | `voisins.json` : objet `{ "version": 0, "previous", "next" }` ; `previous.seq = seq − 1` (ou `previous = null` et `seq = 1`), `next.seq = seq + 1` (ou `next = null`) ; `ts` non décroissants ; `org_id`, `journal_id` identiques. | 2 |
| C-2 | `prev_hash = hash(previous)` recalculé ; `next.prev_hash = hash(evenement)` recalculé ; `prev_hash` nul si et seulement si `seq = 1`. | 2 |
| C-3 | `recorder_key_id` de `next` = `new_key_id` si l'événement prouvé est une rotation, sinon = `recorder_key_id` de l'événement ; même règle entre `previous` et l'événement. | 6 |
| M-1 | `chemin.leaf_hash = SHA-256(0x00 ‖ hash)` avec `hash` recalculé (E-7). | 3 |
| M-2 | Algorithme de la section 9.3 sur `(leaf_hash, leaf_index, tree_size, path)` donne `chemin.root`. | 3 |
| M-3 | `chemin.root = manifeste.root` ; `chemin.tree_size = manifeste.count` ; `chemin.leaf_index = seq − manifeste.first_seq`. | 3 |
| P-1 | `manifeste.json` valide contre son schéma ; `period_end = period_start + 3600` ; `count = last_seq − first_seq + 1` ; `org_id`, `journal_id` égaux à ceux de l'événement. | 3 |
| P-2 | `first_seq ≤ seq ≤ last_seq` et `period_start ≤ ts < period_end` pour l'événement prouvé (instants : `ts` décodé à la milliseconde, bornes en secondes). | 3 |
| P-3 | Pour chaque voisin de la même période (`first_seq ≤ voisin.seq ≤ last_seq`), `period_start ≤ voisin.ts < period_end` ; un voisin hors période a `seq = first_seq − 1` **et** `ts < period_start`, ou `seq = last_seq + 1` **et** `ts ≥ period_end`. Un voisin hors période par `seq` mais horodaté dans la période prouve que le manifeste a tronqué sa période (section 7.2). | 2, 3 |
| P-4 | `root` nulle si et seulement si `count = 0` ; `count ≥ 1` dans un dossier (il contient un événement). | 3 |
| P-5 | `periodHash` recalculé (section 10.2) = `manifeste.sig.period_hash` ; `sig` valide sous la clé `manifeste.sig.recorder_key_id` de `cles.json` ; `manifeste.recorder_key_id` = `manifeste.sig.recorder_key_id` ; `generated_at` dans `[valid_from, valid_to]` (bornes incluses) de cette clé ; `cles.json` inexploitable (E-8) : non exécuté. Avec un second manifeste fourni à part : continuité de la section 10.3. | 3, 6 |
| A-1 | `approbations.json` présent si et seulement si `approval ≠ null` ; `ticket` et `request_hash` égaux à ceux de `approval`. | 7 |
| A-2 | Chaque événement de `events` passe E-1 à E-11 ; `execution.tool = "noortrace.approbation.decision"` ; `approval` égal, clé pour clé, à celui de l'événement prouvé ; `execution.arguments.value = A` (section 6.3). Si l'événement prouvé n'est pas une décision : chaque décision a `seq` < `seq` de l'événement prouvé et `approval.at ≤ ts` de l'événement prouvé (la décision précède l'appel relayé qui en découle). Si l'événement prouvé est une décision : il figure dans `events` (hash recalculé égal). | 7 |
| A-3 | Approbateurs distincts, tous membres de `approver_set.members`, en nombre ≥ `threshold.required` ; `threshold` de l'événement = `approver_set.threshold` ; `required ≤ size = longueur de members`. Pour `decision = "refuse"`, mêmes règles ; pour `expire`, aucune signature. | 7 |
| A-4 | `request_hash` : si l'événement de demande est dans le dossier (voisin), son `hash` recalculé = `request_hash` et son `execution.status = "retenue"` ; sinon, non vérifiable, signalé. | 7 |

Les contrôles des parties réservées (4, 5, 8) sont spécifiés par CT-5 et CT-4,
qui reprendront la numérotation (`T-`, `O-`, `R-`).

### 11.5 Vecteurs de dossiers publiés

Les vecteurs de `spec/vecteurs/ct-1/dossiers/` (index dans
`spec/vecteurs/ct-1/INDEX.md`, produits par `scripts/vecteurs/generer-ct1.mjs`)
publient deux dossiers valides et, pour **chaque** contrôle de la table 11.4,
au moins un dossier qui échoue à ce contrôle. Chaque dossier porte un
`attendu.json` (fichier étranger au dossier, ignoré par le vérificateur) qui
donne le contrôle visé et la liste **exacte** des contrôles en échec : quand une
altération entraîne d'autres échecs (cascade), ils y figurent, et le mode strict
d'un vérificateur exige l'égalité des listes. Les altérations portent de
préférence sur le voisin suivant, dont le hachage n'entre dans aucun autre
calcul du dossier ; une altération de l'événement prouvé ou du voisin précédent
change un hachage dont dépendent C-2 et M-1, d'où les cascades ; « journal
rejoué » désigne une altération faite à la source, chaîne et manifestes
recalculés, de sorte que le dossier est cohérent et que seul le contrôle visé
tombe.

| Dossier | Visé | En échec | Altération |
|---|---|---|---|
| `valide-seq-7/` | — | aucun | L'appel relayé après approbation (seq 7) : voisins seq 6 et 8, période 1, approbation des comptes Hardhat 1 et 2. A-4 non exécuté : la demande (seq 5) n'est pas un voisin. |
| `valide-seq-6/` | — | aucun | La décision d'approbation (seq 6) : `approbations.json` contient l'événement prouvé ; A-4 exécuté, la demande (seq 5, `retenue`) est le voisin précédent. |
| `invalide-index-seq/` | D-1 | D-1 | `event.seq` de `dossier.json` décalé. |
| `invalide-index-sha256/` | D-2 | D-2 | `sha256` de `chemin.json` dans l'index remplacé. |
| `invalide-hex-majuscules/` | E-1 | E-1 | `code.prompt_version` du voisin suivant en majuscules, voisin rescellé. |
| `invalide-partie-nulle/` | E-1 | E-1 | `evenement.json` réduit au littéral `null`, index recalculé : partie présente, SHA-256 exact, contenu inexploitable. |
| `invalide-echange-sans-reponse/` | E-3 | E-1, E-3 | Journal rejoué : l'échange avec le modèle seq 1 sans `result`, `duration_ms` ni `is_error` ; dossier de seq 1. |
| `invalide-nombre-non-entier/` | E-2 | E-2 | `duration_ms: 530.0` dans `evenement.json`. |
| `invalide-sans-objet-appel/` | E-3 | E-3 | `policy.decision = sans_objet` sur l'appel d'outil du voisin suivant, rescellé. |
| `invalide-redaction-absente/` | E-4 | E-4 | `policy.redaction = null` sur le voisin suivant, dont les arguments sont rédigés, rescellé. |
| `invalide-signature-manquante/` | E-5 | E-5 | Journal rejoué : deux approbateurs, une seule signature. |
| `invalide-reference-en-ligne/` | E-6 | E-6 | Journal rejoué : `length` de la référence en ligne de la décision augmenté de 1. |
| `invalide-hash-faux/` | E-7 | E-7 | `hash` de l'événement réécrit, contenu et signature intacts. |
| `invalide-signature-fausse/` | E-8 | E-8 | `sig` produite par `rec-test-02` alors que `recorder_key_id` vaut `rec-test-01`. |
| `invalide-cles-key-id-double/` | E-8 | E-8 | `cles.json` : seconde entrée `rec-test-01` portant la clé publique de `rec-test-02`. |
| `invalide-cles-autre-journal/` | E-8 | E-8 | `cles.json` : `journal_id` d'un autre journal. |
| `invalide-approbateur-substitue/` | E-9 | E-9 | Journal rejoué : `signatures[1]` du compte Hardhat 3, `approvers[1]` inchangé. |
| `invalide-signature-s-haut/` | E-9 | E-9 | Journal rejoué : `signatures[1]` en forme non canonique (`s` haut, `v` complémenté). |
| `invalide-rotation-contresignature/` | E-10 | E-10 | Journal rejoué : `counter_sig` produite par l'ancienne clé ; dossier de la rotation (seq 9). |
| `invalide-rotation-validite-annoncee/` | E-10 | E-10 | Dossier de la rotation ; `cles.json` annonce `rec-test-02` valide avant le `ts` de la rotation. |
| `invalide-cle-hors-validite/` | E-11 | E-11 | `cles.json` annonce `rec-test-01` valide après le `ts` de l'événement prouvé et de son voisin précédent. |
| `invalide-voisin-incoherent/` | C-1 | C-1 | `seq` du voisin suivant décalé, rescellé. |
| `invalide-ts-voisin/` | C-1 | C-1 | Journal rejoué : `ts` du voisin précédent postérieur à celui de l'événement. |
| `invalide-prev-hash-voisin/` | C-2 | C-2 | `prev_hash` du voisin suivant réécrit, rescellé. |
| `invalide-cle-voisin/` | C-3 | C-3 | Journal rejoué (seq 10 à l'instant de la rotation) ; dossier de la rotation, voisin suivant signé par l'ancienne clé, rescellé. |
| `invalide-feuille-etrangere/` | M-1 | M-1 | Arbre et manifeste (re-signé) bâtis sur une autre feuille à la position de l'événement prouvé. |
| `invalide-chemin-permute/` | M-2 | M-2 | Deux nœuds de `path` échangés. |
| `invalide-chemin-tronque/` | M-2 | M-2 | Dernier nœud de `path` retiré. |
| `invalide-leaf-index-decale/` | M-3 | M-2, M-3 | `leaf_index` + 1 : le chemin lu à cette position ne mène plus à la racine. |
| `invalide-racine-manifeste/` | M-3 | M-3 | Racine d'un arbre à huit feuilles dans le manifeste, re-signé. |
| `invalide-racine-nulle/` | P-4 | M-3, P-1, P-4 | Racine nulle avec `count = 9`, re-signé : schéma (P-1), convention de la période vide (P-4), chemin (M-3). |
| `invalide-periode-deux-heures/` | P-1 | P-1 | `period_end = period_start + 7200` dans le manifeste, re-signé : une période est une heure pleine. |
| `invalide-ts-hors-periode/` | P-2 | P-2 | Dossier de seq 1 horodaté avant `period_start`, voisin suivant, arbre et manifeste recalculés et re-signés. |
| `invalide-periode-tronquee/` | P-3 | P-3 | Manifeste à huit feuilles (`last_seq = 8`) re-signé ; dossier de seq 8 dont le voisin suivant (seq 9) est horodaté dans la période. |
| `invalide-manifeste-cle-perimee/` | P-5 | P-5 | Manifeste re-signé par `rec-test-01`, dont la validité s'arrête avant `generated_at`. |
| `invalide-ticket-approbations/` | A-1 | A-1 | `ticket` de `approbations.json` différent de `approval.ticket`. |
| `invalide-decision-etrangere/` | A-2 | A-2 | `approval.reason` de la décision jointe modifié, décision rescellée : `approval` n'est plus égal clé pour clé. |
| `invalide-seuil-non-atteint/` | A-3 | A-3 | Journal rejoué : un seul approbateur pour un seuil de 2. |
| `invalide-approbateur-double/` | A-3 | E-1, A-3 | Journal rejoué : le compte Hardhat 1 deux fois dans `approvers` (`uniqueItems` du schéma, E-1 ; A-3). |
| `invalide-demande-refusee/` | A-4 | A-4 | Journal rejoué : la demande (seq 5) refusée par la politique ; dossier de la décision (seq 6) qui l'approuve pourtant. |

Les journaux altérés (`journal-supprime`, `journal-modifie`, `journal-insere`,
`journal-insere-sans-cle`, `journal-reordonne`) portent de même un
`attendu.json` avec les diagnostics nommés et la liste exacte des contrôles en
échec de la table 7.2.

## 12. Correspondances d'export

Aucune des trois correspondances n'est implémentée en v0 ; elles sont données
pour que le format ne les rende pas impossibles, et pour que CT-9 puisse écrire
les tests d'interopérabilité. Les noms d'attributs sont ceux des conventions
sémantiques OpenTelemetry GenAI et du projet IETF au moment de la rédaction, tous
deux en cours d'évolution ; une version 1 fixera le nom exact retenu.

### 12.1 OpenTelemetry GenAI

Un événement devient un span. Un appel d'outil est un span `execute_tool` ; un
échange avec le modèle, un span d'inférence.

| Événement NOORTRACE | Attribut ou champ OpenTelemetry | Remarque |
|---|---|---|
| `execution.tool` (outil réel) | `gen_ai.operation.name = "execute_tool"`, `gen_ai.tool.name` | |
| `execution.tool = noortrace.modele.echange` | `gen_ai.operation.name = "chat"` | |
| `code.model` | `gen_ai.request.model` (et `gen_ai.response.model` si connu) ; `gen_ai.provider.name` = partie avant `/` | |
| `delegation.run_id` | `gen_ai.conversation.id` | |
| `delegation.launched_by`, `on_behalf_of` | `enduser.id`, attribut de ressource `noortrace.delegation.*` | Pas d'attribut GenAI dédié : préfixe propre, documenté comme tel. |
| `ts`, `execution.duration_ms` | `start_time`, `end_time` du span | `end = start + duration_ms` |
| `execution.is_error` | `error.type`, statut du span | |
| `execution.arguments`, `execution.result` | `gen_ai.tool.call.arguments`, `gen_ai.tool.call.result` : **non exportés** ; à la place `noortrace.ref.arguments.sha256`, `.length`, `.redacted` | Les contenus restent chez le client. |
| `intent` | `gen_ai.output.messages` (texte de l'assistant), opt-in | Rédaction préalable. |
| `policy.*`, `approval.*`, `effects[]`, `context[]` | attributs `noortrace.policy.*`, `noortrace.approval.*`, événements de span `noortrace.effect`, liens de span vers `context[].sha256` | Pas d'équivalent GenAI. |
| `seq`, `prev_hash`, `hash`, `sig`, `org_id`, `journal_id`, `recorder_key_id` | `noortrace.journal.*` | Le span n'est pas la preuve : la preuve est le dossier. |

### 12.2 Projet IETF « agent audit trail » (draft-sharif-agent-audit-trail)

| Concept du projet | NOORTRACE v0 | Compatibilité |
|---|---|---|
| Enregistrement d'audit par action de l'agent | Événement (section 5) | Même granularité. |
| Chaînage par hachage du précédent | `prev_hash`, premier à zéro | Identique. |
| Canonicalisation JCS avant hachage | JCS v0 (section 4) | Identique, avec la restriction sur les nombres, qui est un sous-ensemble. |
| Hachage SHA-256 | SHA-256 avec préfixe de domaine | Le préfixe est propre à NOORTRACE ; un vérificateur du projet ne retrouverait pas nos hachages sans lui. À négocier : le préfixe sera exposé comme paramètre de profil. |
| Signature de l'enregistreur | Ed25519 (section 6.2) | Algorithme à confirmer dans le projet. |
| Arbre de Merkle RFC 6962 par lot | Section 9 | Identique, sauf la période vide (racine nulle), propre à NOORTRACE. |
| Champs de l'enregistrement | Les huit champs | Correspondance de noms à établir quand le projet se stabilise ; aucune donnée des huit champs n'est sans contrepartie prévue. |

### 12.3 SCITT (RFC 9943), reporté en v1

| Concept SCITT | NOORTRACE | Décision |
|---|---|---|
| Déclaration signée (COSE_Sign1) | Manifeste + `manifeste.sig` | v1 : enveloppe COSE du manifeste, en plus de la forme JSON. |
| Service de transparence | Registre (CT-4) + ancres (CT-5) | Le registre n'est pas un service SCITT ; un pont est envisageable. |
| Reçu (preuve d'inclusion signée) | `chemin.json` + `manifeste.sig` | v1 : reçu COSE sur le même chemin RFC 6962. |
| Identifiant d'émetteur | `org_id`, `recorder_key_id` | |

Reporté parce que v0 vise un vérificateur sans dépendance CBOR/COSE et parce que
les profils de reçus SCITT pour RFC 6962 sont encore en cours de définition.

## 13. Clés et comptes de test, vecteurs

Les vecteurs sont déterministes : horodatages fixes, nonces fixes, aucune
valeur aléatoire à l'exécution. Deux jeux de constantes coexistent et ne doivent
pas être confondus : celles de **l'exemple de référence** de ce document
(annexe A, sections 5 à 11 : journal `journal-principal`, cinq événements,
deux périodes) et celles des **vecteurs publiés** sous `spec/vecteurs/ct-1`
(journal `journal-sinistres`, douze événements, trois périodes). Les clés
d'enregistreur et les comptes d'approbateurs sont les mêmes dans les deux.

Clés et comptes communs :

| Clé | Dérivation | Valeur |
|---|---|---|
| Graine Ed25519 `rec-test-01` | `SHA-256(UTF-8("noortrace/vecteurs/v0/cle-enregistreur/rec-test-01"))` | `0x6215c33a2801ef7f21a894e98924eba8d72e3514f5fe7929ce0b595f5d39fa79` |
| Clé publique `rec-test-01` | RFC 8032 §5.1.5 depuis la graine | `0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045` |
| Graine Ed25519 `rec-test-02` | `SHA-256(UTF-8("noortrace/vecteurs/v0/cle-enregistreur/rec-test-02"))` | `0x4aa9b030b0d9dbc1eb4e2619929bb7ace43b6479678c6162ea467c84a6bda5db` |
| Clé publique `rec-test-02` | idem | `0xfd08757fa4798c3c8757bbf5a0db49580cbcb80075ddb30f13f881b0f47aacb3` |
| `org_id` | `keccak256(UTF-8("assureur-demo"))` | `0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab` |

Constantes de l'exemple de référence (annexe A) :

| Grandeur | Dérivation | Valeur |
|---|---|---|
| `journal_id` | `keccak256(UTF-8("journal-principal"))` | `0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b` |
| Nonce période 1 | `SHA-256(UTF-8("noortrace/vecteurs/v0/nonce/periode-1"))` | `0xcfcd0a8277074d0839e4469fdced701c0fdf2855f1001e17d3fada335da05547` |
| Nonce période 2 | `SHA-256(UTF-8("noortrace/vecteurs/v0/nonce/periode-2"))` | `0x2b2b0095b99b60b2b3baae78815fd1590b4c01c6e63304ab0a682e5f6270f86d` |

Constantes des vecteurs publiés (`spec/vecteurs/ct-1/cles/cles-test.json`, qui
porte aussi les graines, les clés privées PKCS#8 et les comptes) :

| Grandeur | Dérivation | Valeur |
|---|---|---|
| `journal_id` | `keccak256(UTF-8("journal-sinistres"))` | `0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164` |
| Nonce période N (N = 1, 2, 3) | `SHA-256(UTF-8("noortrace/vecteurs/v0/nonce/journal-sinistres/periode-N"))` | période 1 : `0x20043d08510abdc2f2aa983921401083affcadb38760de64856927195c818dd3` ; période 2 : `0xa57b8896278fbd10b1e209de387295d6a5d2137e6f64a1f534b0e60129be9168` ; période 3 : `0x547f937bb769c72eb8faefc6511fbb9c0fd7f7341f0c5b73ffd7bc2214114da0` |
| Feuilles de l'arbre de 1000 (`merkle/arbres.json`) | `SHA-256(UTF-8("noortrace/vecteurs/v0/merkle/feuille/<i>"))`, i = 0 … 999 | feuille 0 : `0x9e341958a7bf201706ec15220c16236b59c0436818eb18061a7f0603f45cf989` |

Approbateurs : les comptes 1 à 3 du mnémonique Hardhat par défaut (`test test
test test test test test test test test test junk`, chemin `m/44'/60'/0'/0/i`),
jeu de trois au seuil de deux. Ces clés sont publiques et ne doivent jamais
porter de valeur.

| Compte | Adresse (minuscules) | Clé privée |
|---|---|---|
| 1 | `0x70997970c51812dc3a010c7d01b50e0d17dc79c8` | `0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d` |
| 2 | `0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc` | `0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a` |
| 3 | `0x90f79bf6eb2c4f870365e785982e1f101e93b906` | `0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6` |

Les signatures secp256k1 sont déterministes (RFC 6979) et les signatures
Ed25519 le sont par construction : deux implémentations conformes produisent
les mêmes octets que l'annexe A. La graine Ed25519 est la clé privée de 32
octets de la RFC 8032 ; en PKCS#8, elle s'écrit `302e020100300506032b657004220420`
suivi de la graine.

Les vecteurs publiés sous `spec/vecteurs/ct-1/` (index : `INDEX.md` de ce
répertoire ; générateur : `scripts/vecteurs/generer-ct1.mjs`, rejoué à
l'identique par `test/journal.test.js`) sont disposés ainsi :

| Répertoire ou fichier | Contenu | Attendu |
|---|---|---|
| `cles/cles-test.json`, `cles/cles.json` | les constantes ci-dessus, les clés de test et le `cles.json` des dossiers | égalité des dérivations |
| `jcs/cas-limites.json` | les cas limites de la section 4 (entrée en texte JSON, forme canonique ou `null` si invalide) | égalité octet par octet, ou refus |
| `journal-valide/` | douze événements, `hash`, `sig`, longueur canonique, `A` et `D_A`, pièces | chaîne valide, égalité |
| `journal-supprime/`, `journal-modifie/`, `journal-insere/`, `journal-insere-sans-cle/`, `journal-reordonne/` | le journal altéré | diagnostics et contrôles de la table 7.2 |
| `merkle/arbres.json` | arbres de 0, 1, 2, 3, 5, 8, 12 et 1000 feuilles, racines, preuves d'inclusion | égalité, preuves acceptées |
| `manifestes/` | trois périodes consécutives (dont une vide), signatures, `anchorFingerprint`, `PeriodMeta`, continuité, un manifeste discontinu | égalité, P-5 |
| `dossiers/` | les dossiers de la section 11.5 | `valide` ou liste exacte des contrôles en échec |

Le vérificateur indépendant Go de `spec/vecteurs/ct-1/verificateur-independant`
recalcule tout depuis ce document et confronte chaque valeur ; sa concordance
avec l'implémentation de référence est la condition de publication des
vecteurs.

## 14. Décisions ouvertes de l'architecture closes par CT-1

**Décision 1 — granularité.** Close : un événement par appel d'outil
(`tools/call`), un événement par échange avec le modèle (une requête et sa
réponse), un événement par décision d'approbation, un événement par changement
du journal sur lui-même ; un lot par heure UTC. Justification : l'appel d'outil
est l'unité d'action observable au mandataire et l'unité que la politique
évalue ; une granularité plus fine (par message) n'ajouterait que des événements
sans action, une plus grosse (par exécution d'agent) empêcherait de prouver un
appel sans révéler les autres, ce que le dossier exige. L'heure est la période
du contrat `PeriodRegistry` et le pas d'ancrage qualifié de l'architecture ; un
lot plus court multiplierait le coût d'horodatage sans réduire la fenêtre de
réécriture en dessous de ce que la contresignature interne optionnelle couvre.
Le coût et la latence restent à mesurer en phase 2 (CT-2), mais cette mesure ne
changera pas le format : un événement dont la pièce est volumineuse reste de
taille bornée, puisque les pièces sont des références.

**Décision 5 — version 0 du format d'export.** Close : le format v0 est celui
de ce document, figé par ses trois schémas et ses vecteurs ; `version: 0` dans
l'événement, le manifeste et le dossier. Les entretiens avec des réviseurs
prévus par l'architecture ont lieu à la porte 1 sur ce document, et non avant
sa rédaction : un réviseur se prononce sur un format écrit, avec des vecteurs,
pas sur un principe. Une modification issue de ces entretiens produit une
version 1 avec ses propres préfixes de domaine (`…/v1`) ; un vérificateur v1
continue d'accepter v0. Ce qui est délibérément laissé à v1 : les formats
d'export (section 12), l'enveloppe COSE, les hachages de bord dans le manifeste.

## 15. Ce que cette version ne couvre pas

- **La date.** Sans les contrôles 4 et 5 (CT-5), rien dans un dossier CT-1 ne
  prouve à quel moment un événement a existé ; `ts` est l'horloge de
  l'enregistreur, déclarative.
- **L'ancre et le registre.** Sans le contrôle 8 (CT-4), rien ne prouve que le
  manifeste a été enregistré ni que la clé de l'enregistreur était inscrite ;
  `cles.json` et `approver_set` sont déclaratifs, avec leur source.
- **La légitimité des approbateurs.** Le contrôle 7 établit que les adresses
  nommées ont signé et atteignent le seuil déclaré ; que ces adresses soient
  membres du `CuratorSet` de l'organisation à cet instant relève du contrôle 8.
- **L'inclusion des événements d'approbation.** `approbations.json` prouve leur
  forme et leurs signatures, pas leur inclusion dans une période ; chacun se
  prouve par son propre dossier.
- **Les événements au-delà des voisins.** La chaîne n'est contrôlée que sur
  trois événements ; la période entière est couverte par la racine.
- **Les pièces.** Le dossier ne contient ni arguments, ni résultats, ni
  documents ; il contient leurs références. Le client les joint s'il le décide.
- **Le contenu des effets.** `effects` est ce que l'enregistreur a déclaré voir,
  pas une preuve que le système cible a changé.
- **La sémantique des règles et des tickets** (CT-3), **la sérialisation des
  pièces avant hachage et la rédaction** (CT-2), **la ligne de commande et la
  sortie du vérificateur** (CT-6).
- **Le prompt système.** `code.prompt_version` est l'empreinte du prompt tel
  qu'il est stocké ; si le client le stocke en clair, cette empreinte permet de
  confirmer un prompt deviné (recherche par dictionnaire sur un texte court) et
  circule dans tout dossier. La rédaction du prompt avant stockage, ou son
  remplacement par un identifiant de version nommé, relèvent de CT-2.
- **Les hachages de bord** (`hash` du premier et du dernier événement) dans le
  manifeste : la racine les couvre, et la continuité de chaîne entre deux
  périodes se contrôle sur les événements eux-mêmes ; à reconsidérer en v1 si
  un réviseur demande à contrôler la jonction sans les événements.
- **La compression, le chiffrement et le transport** des dossiers.
- **Les nombres non entiers** dans toute structure hachée.

## 16. Alignement avec le dépôt

Points du dépôt que cette spécification a rendus caducs, avec leur état :

| Emplacement | Avant CT-1 | Attendu par CT-1 | État |
|---|---|---|---|
| `contracts/PeriodRegistry.sol`, commentaire de `PeriodMeta.periodHash` | « keccak256 du manifeste canonique » | « SHA-256 du manifeste canonique préfixé (CT-1 §10.2) ; opaque pour le contrat » | fait |
| `scripts/e2e/dev-roundtrip.mjs`, calcul d'essai | `keccak256(canonical(manifest))`, `version: 1`, manifeste d'essai | `periodHash` de la section 10.2 (`scripts/lib/journal.mjs`), `version: 0`, manifeste conforme au schéma | fait |
| `ARCHITECTURE.md`, exemple d'événement | `sha256:…`, `sig: {alg, key_id, value}`, `arguments_hash` | Forme de la section 5 (`0x…`, `recorder_key_id` + `sig`, références) | à aligner (orchestrateur) |
| `ARCHITECTURE.md`, « Modèle d'événement » : le manifeste porte « les hachages de bord » | hachages de bord dans le manifeste | la version 0 n'en porte pas (section 15) : le manifeste porte la racine, `first_seq` et `last_seq` | à aligner (orchestrateur) |
| `ARCHITECTURE.md`, « Dossier et vérification » : le dossier contient « les hachages de ses voisins » | hachages des voisins | les voisins complets (`voisins.json`, section 11.2), dont les hachages se recalculent (C-2) | à aligner (orchestrateur) |
| `spec/README.md`, disposition des vecteurs | `jcs/`, `evenements/`, `chaines/`, `arbres/` (n = 0, 1, 2, 3, 5, 8) | la disposition publiée (section 13 et `spec/vecteurs/ct-1/INDEX.md`) | fait |

`scripts/lib/noortrace.mjs` ne calcule pas `periodHash` (c'est
`scripts/lib/journal.mjs` qui le fait) ; ses `periodDigest`, `registerDigest`,
`revokeDigest` et `anchorFingerprint` sont conformes à cette spécification tels
quels.

## Annexe A — Les cinq événements de l'exemple de référence

Période `[1793710800, 1793714400)`, journal `(0xa581…daab, 0x0e27…c64b)`, clé
`rec-test-01` puis `rec-test-02`. Les hachages de l'annexe B s'en déduisent.

Seq 1 — échange avec le modèle (requête rédigée par `pii-v1` : le prompt système
est remplacé ; réponse non rédigée).

<!-- schema: evenement -->
```json
{
  "version": 0,
  "seq": 1,
  "ts": "2026-11-03T13:41:02.004Z",
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
  "recorder_key_id": "rec-test-01",
  "prev_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "delegation": {
    "launched_by": "u.martin@assureur-demo.example",
    "on_behalf_of": "service-sinistres",
    "scope": "sinistres:lecture,paiement",
    "run_id": "run-2026-11-03-0142"
  },
  "code": {
    "model": "fournisseur/modele@2026-09",
    "prompt_version": "0xb71552443a0b6e9793dd337ab10d057b354013fba35c2c82fdbdfb6df99d6b58",
    "policy_version": "2026-11-01",
    "recorder": "0.1.0"
  },
  "intent": "Régler le sinistre 2026-77812 après validation des pièces",
  "policy": {
    "rule": null,
    "decision": "sans_objet",
    "ticket": null,
    "redaction": "pii-v1"
  },
  "approval": null,
  "execution": {
    "tool": "noortrace.modele.echange",
    "arguments": {
      "sha256": "0xdfa3f1295a71adac1cdb0817911e6285a4c54ac0034fadbcc08a00660023e6ec",
      "length": 164,
      "redacted": true
    },
    "status": "executee",
    "result": {
      "sha256": "0x06d1525814574f7becc8954bd107d8ee8b7e4cd02e76bf5ef32255e26d628da8",
      "length": 286,
      "redacted": false
    },
    "duration_ms": 1843,
    "is_error": false
  },
  "effects": [],
  "context": [],
  "hash": "0x64994cc38adf2e7532b2f02fae0e78086b1970c5ffd36a37dc3c78143cfe8179",
  "sig": "0x6e67bd0e34a2411c8ad4b552951e76f924b6999195c012edddaba3a991fd9b67020e5e9407749537546d016e43422e57389aef716b2e791ae80f2698349cf307"
}
```

Pièces de seq 1 (octets UTF-8) :

| Pièce | Octets | `length` | `sha256` |
|---|---|---|---|
| requête (rédigée) | `{"model":"fournisseur/modele@2026-09","messages":[{"role":"system","content":"[REDIGE:prompt-systeme]"},{"role":"user","content":"Traite le sinistre 2026-77812."}]}` | 164 | `0xdfa3f1295a71adac1cdb0817911e6285a4c54ac0034fadbcc08a00660023e6ec` |
| réponse | `{"content":[{"type":"text","text":"Régler le sinistre 2026-77812 après validation des pièces"},{"type":"tool_use","name":"sap.payments.create","input":{"claim_id":"2026-77812","amount":"7400.00","currency":"CHF","beneficiary_iban":"CH9300762011623852957"}}],"stop_reason":"tool_use"}` | 286 | `0x06d1525814574f7becc8954bd107d8ee8b7e4cd02e76bf5ef32255e26d628da8` |

Seq 2 — appel d'outil retenu pour approbation (`request_hash` des décisions).

<!-- schema: evenement -->
```json
{
  "version": 0,
  "seq": 2,
  "ts": "2026-11-03T13:41:07.218Z",
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
  "recorder_key_id": "rec-test-01",
  "prev_hash": "0x64994cc38adf2e7532b2f02fae0e78086b1970c5ffd36a37dc3c78143cfe8179",
  "delegation": {
    "launched_by": "u.martin@assureur-demo.example",
    "on_behalf_of": "service-sinistres",
    "scope": "sinistres:lecture,paiement",
    "run_id": "run-2026-11-03-0142"
  },
  "code": {
    "model": "fournisseur/modele@2026-09",
    "prompt_version": "0xb71552443a0b6e9793dd337ab10d057b354013fba35c2c82fdbdfb6df99d6b58",
    "policy_version": "2026-11-01",
    "recorder": "0.1.0"
  },
  "intent": "Régler le sinistre 2026-77812 après validation des pièces",
  "policy": {
    "rule": "paiement > 5000 CHF",
    "decision": "a_approuver",
    "ticket": "apr-1192",
    "redaction": "pii-v1"
  },
  "approval": null,
  "execution": {
    "tool": "sap.payments.create",
    "arguments": {
      "sha256": "0x0fb2fc1e0625e460687315e9861347a2f0ac8680068c84582080b3f46c8faaf9",
      "length": 96,
      "redacted": true
    },
    "status": "retenue",
    "result": null,
    "duration_ms": null,
    "is_error": null
  },
  "effects": [],
  "context": [
    {
      "sha256": "0x2aca5294d591501378fe8629f9713fdf75af93a641fb1ab58c8e231edec823a4",
      "length": 48,
      "redacted": false,
      "kind": "document"
    },
    {
      "sha256": "0x7a184a4b8008ea03571b17038db8e653df769bba34b014c3df866a265af9de21",
      "length": 44,
      "redacted": false,
      "kind": "document"
    }
  ],
  "hash": "0xdd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0",
  "sig": "0x772fcce11f32137ee890e69ca3bbde90a1f97f6a5d45442430486daa3ed8268460954eb9e9cd1a675579c0b9004da5d12032946ed3d19ac50d3469cbafafb606"
}
```

Seq 3 — décision d'approbation (comptes Hardhat 1 et 2, seuil 2 sur 3).

<!-- schema: evenement -->
```json
{
  "version": 0,
  "seq": 3,
  "ts": "2026-11-03T13:52:40.511Z",
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
  "recorder_key_id": "rec-test-01",
  "prev_hash": "0xdd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0",
  "delegation": {
    "launched_by": "u.martin@assureur-demo.example",
    "on_behalf_of": "service-sinistres",
    "scope": "sinistres:lecture,paiement",
    "run_id": "run-2026-11-03-0142"
  },
  "code": {
    "model": "fournisseur/modele@2026-09",
    "prompt_version": "0xb71552443a0b6e9793dd337ab10d057b354013fba35c2c82fdbdfb6df99d6b58",
    "policy_version": "2026-11-01",
    "recorder": "0.1.0"
  },
  "intent": null,
  "policy": {
    "rule": null,
    "decision": "sans_objet",
    "ticket": "apr-1192",
    "redaction": null
  },
  "approval": {
    "decision": "approuve",
    "ticket": "apr-1192",
    "request_hash": "0xdd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0",
    "threshold": {
      "required": 2,
      "size": 3
    },
    "approvers": [
      "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
      "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
    ],
    "signatures": [
      "0x9b56cadb515c1fc18cc37f5b85bc78be8c916daef1ef9017fb3067f19dbcc8585ae2b338117e554f3ec7faa77bc615c82a17a695a4f76295383d9c931d2648a01b",
      "0xed53b07b60869c24a79d2f3db4729bdbc7ff581b1540e19e188f15ffed99d73f1f69b4e247299dcaecf9d69ad3487c313cd48fc1a7d7874f0a55a27330c074151b"
    ],
    "at": "2026-11-03T13:52:40.511Z",
    "reason": "Pièces validées"
  },
  "execution": {
    "tool": "noortrace.approbation.decision",
    "arguments": {
      "sha256": "0xc9b9e6f3ebf13147b98aa59a238979c3dc629b1b6d2ba3f623ea5f122df2a0bb",
      "length": 287,
      "redacted": false,
      "value": {
        "decision": "approuve",
        "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
        "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
        "request_hash": "0xdd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0",
        "ticket": "apr-1192"
      }
    },
    "status": "executee",
    "result": null,
    "duration_ms": null,
    "is_error": null
  },
  "effects": [],
  "context": [],
  "hash": "0xadeb42cb3a4557effbf1bf2dd0a973a1e74563cd39fbb747202d6a4a0f5ad832",
  "sig": "0x5ba332ccd1a5eaeebd119c0a353f9ee474338edeb07c11584d00cb7145c222a9f2a3e5a792f2e7d71588aeac7543d5d7f07ea39002db3d8b6f6c425972a23006"
}
```

Seq 4 — appel relayé : section 5.5.

Seq 5 — rotation de clé (dernier événement de la période, signé par
`rec-test-01`, contresigné par `rec-test-02`).

<!-- schema: evenement -->
```json
{
  "version": 0,
  "seq": 5,
  "ts": "2026-11-03T13:59:59.999Z",
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
  "recorder_key_id": "rec-test-01",
  "prev_hash": "0x471dab56146ae2e4c678120af7faf5eed7b1f8e5db3657226de97614bde4dc00",
  "delegation": {
    "launched_by": "noortrace-enregistreur",
    "on_behalf_of": null,
    "scope": "journal:administration",
    "run_id": null
  },
  "code": {
    "model": null,
    "prompt_version": null,
    "policy_version": "2026-11-01",
    "recorder": "0.1.0"
  },
  "intent": null,
  "policy": {
    "rule": null,
    "decision": "sans_objet",
    "ticket": null,
    "redaction": null
  },
  "approval": null,
  "execution": {
    "tool": "noortrace.journal.rotation-cle",
    "arguments": {
      "sha256": "0xcdf11568d6619b72c7e8e90eb8f30f461b6732ed464694ecd04156161f8c256a",
      "length": 488,
      "redacted": false,
      "value": {
        "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
        "new_key_id": "rec-test-02",
        "new_public_key": "0xfd08757fa4798c3c8757bbf5a0db49580cbcb80075ddb30f13f881b0f47aacb3",
        "old_key_id": "rec-test-01",
        "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
        "valid_from": "2026-11-03T13:59:59.999Z",
        "counter_sig": "0xe107f72204e19597866fb4967e8c30285027f5f87af7fe865a7360c640a8926d1c9c0699e25bb1fe6c6e0fdf161fbbbe5e0edeb8e2fb153234e863ae4598ae04"
      }
    },
    "status": "executee",
    "result": null,
    "duration_ms": null,
    "is_error": null
  },
  "effects": [
    {
      "system": "noortrace",
      "action": "ecriture",
      "object": "cle:rec-test-02",
      "amount": null,
      "currency": null
    }
  ],
  "context": [],
  "hash": "0x506e54e1ec35a6432114fc06947b23c753ce6d5cf4260354b7fdbed011b04f05",
  "sig": "0x25dfd83d35cdb8a803d87531b7a7a8f75176e01327acb12ce06e9ad502cab94213f82b09f7f9b0286f4acd700f1413e4a6b46446464f26da772541cda0627608"
}
```

## Annexe B — Récapitulatif des valeurs

| Grandeur | Valeur |
|---|---|
| `P_H` (événement) | `6e6f6f7274726163652f6576656e656d656e742f76300a` |
| `P_S` (signature d'événement) | `6e6f6f7274726163652f7369676e61747572652d6576656e656d656e742f76300a` |
| `P_M` (manifeste) | `6e6f6f7274726163652f6d616e6966657374652f76300a` |
| `P_SM` (signature de manifeste) | `6e6f6f7274726163652f7369676e61747572652d6d616e6966657374652f76300a` |
| `P_A` (approbation) | `6e6f6f7274726163652f617070726f626174696f6e2f76300a` |
| `P_R` (contresignature de rotation) | `6e6f6f7274726163652f7369676e61747572652d726f746174696f6e2f76300a` |
| hash seq 1 … 5 | `0x6499…8179`, `0xdd3b…fce0`, `0xadeb…d832`, `0x471d…dc00`, `0x506e…4f05` (valeurs complètes en annexe A et section 9.4) |
| racine période 1 | `0x6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06` |
| `periodHash` période 1 | `0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1` |
| `periodHash` période 2 (vide) | `0x3ed80e52f0d52f184986da64ba009947998cfd41624899ad5137594c58f9be4b` |
| `anchorFingerprint` période 1 | `0x3200e496c555b46459191c852a7f79b1e0b4156802cac2f2df7b80b0aa9d823b` |
| `D_A` (ticket apr-1192) | `0x59b49949b9e97d7e3fd9d46a3992476dd2cc27c48e25ef77b467816d144f37a7` |

Les huit points de petit ordre de la courbe (encodages canoniques, RFC 8032
§5.1.2), refusés comme clé publique `A` (section 6.2) :

```text
0100000000000000000000000000000000000000000000000000000000000000   (point neutre, ordre 1)
ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f   (ordre 2)
0000000000000000000000000000000000000000000000000000000000000000   (ordre 4)
0000000000000000000000000000000000000000000000000000000000000080   (ordre 4)
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a   (ordre 8)
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa   (ordre 8)
26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05   (ordre 8)
26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85   (ordre 8)
```
