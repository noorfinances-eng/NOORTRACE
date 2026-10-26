# CT-1 — Modèle d'événement et formats

Version 0.3, 25 octobre 2026 (révision 0.3 : point de contrôle de la période en
cours, preuve de cohérence RFC 9162 et partie facultative
`points-de-controle.json` du dossier, sections 10.5 à 10.9, 11.2, 11.4 et 17 ;
rien du format v0 n'est retiré ni modifié. La version 0.2 du 21 octobre 2026
avait suivi la confrontation de l'implémentation de référence
`scripts/lib/journal.mjs` et du vérificateur indépendant Go de
`spec/vecteurs/ct-1/verificateur-independant`). Spécification normative, soumise
à la revue de la porte 1 du plan de projet (document interne). Elle met en œuvre la section « Modèle
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
11. (révision 0.3) le point de contrôle de la période en cours, tête signée de
    l'arbre à cadence courte, sa preuve de cohérence avec le manifeste et la
    partie facultative `points-de-controle.json` du dossier (sections 10.5 à
    10.9, 11.2 et 11.4) ; l'ancrage des points relève de CT-5, leur
    vérification de CT-6 (révision 0.2).

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
| Point de contrôle | (révision 0.3) Tête signée de l'arbre de la période en cours : racine des `n` premières feuilles, dernier `seq` couvert et son `hash`, instant, chaînage au point précédent de la période ; produit par l'enregistreur à cadence courte, ancré par CT-5. Section 10.5. |
| Preuve de cohérence | (révision 0.3) Liste de nœuds qui prouve que l'arbre des `m` premières feuilles est un préfixe de l'arbre de `n ≥ m` feuilles, RFC 9162 §2.1.4. Section 10.7. |
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
| Octets en base64 (révision 0.3) | Réservé aux deux fichiers binaires embarqués dans `points-de-controle.json` (jeton RFC 3161 en DER, preuve `.ots`) : base64 de la RFC 4648 §4, alphabet standard, remplissage `=`, sans saut de ligne ; les octets décodés sont le fichier tel qu'il a été produit, jamais réencodé (CT-6 EX-13.3). Partout ailleurs, les octets restent en hexadécimal `0x`. | `MIIINAYJ…RYkA==` |

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

Les octets de la pièce « arguments » sont ici dans l'ordre des clés du
réseau. CT-1 n'impose que l'égalité entre la pièce stockée et la pièce hachée ;
l'enregistreur de CT-2 sérialise les pièces JSON en forme canonique intégrale
après rédaction (CT-2 §8), si bien que le même appel y produit une autre
empreinte, de même longueur (CT-2, annexe A). Les vecteurs de CT-1 ne changent
pas.

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

Révision 0.3 : la dernière ligne de la table reste vraie pour la chaîne seule.
L'heure qu'elle cite est la fenêtre des ancres horaires de la clôture. Quand
l'enregistreur produit des points de contrôle (section 10.5) et que CT-5 les
ancre à l'extérieur, la réécriture par qui détient la clé n'est plus possible
sans détection au-delà du dernier point ancré : la fenêtre est bornée par la
cadence des points et le délai d'obtention de l'ancre, non plus par l'heure
(section 10.9).

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
   relèvent de CT-4 (§8.4) ; la cohérence entre l'événement de rotation et le
   registre relève du contrôle 8 (CT-6 §11).

Exemple (seq 5 de l'annexe A) : `JCS(R)` et sa contresignature.

```text
JCS(R)      = {"journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","new_key_id":"rec-test-02","new_public_key":"0xfd08757fa4798c3c8757bbf5a0db49580cbcb80075ddb30f13f881b0f47aacb3","old_key_id":"rec-test-01","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","valid_from":"2026-11-03T13:59:59.999Z"}
counter_sig = 0xe107f72204e19597866fb4967e8c30285027f5f87af7fe865a7360c640a8926d1c9c0699e25bb1fe6c6e0fdf161fbbbe5e0edeb8e2fb153234e863ae4598ae04
```

Un changement de politique suit le même schéma avec `noortrace.journal.politique`
et `value = { "policy_version": "…", "policy_sha256": "0x…" }` (SHA-256 des
octets de l'ensemble de politique, défini par CT-2 EX-8.11), sans
contresignature.

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
Le contrôle de ces valeurs contre le registre est le contrôle 8 (CT-6 §11).

### 10.5 Point de contrôle (révision 0.3)

Le manifeste n'engage la période qu'à sa clôture, une fois par heure : entre
deux clôtures, qui détient la clé de l'enregistreur peut réécrire et signer de
nouveau toute la période en cours (section 7.2, CT-6 §3.4). Le **point de
contrôle** réduit cette fenêtre. C'est une tête signée de l'arbre de Merkle de
la période en cours, que l'enregistreur produit à cadence courte et que CT-5
ancre à l'extérieur (registre, autorité RFC 3161, OpenTimestamps) : un
événement couvert par un point ancré ne peut plus être réécrit sans que l'ancre
le contredise.

Règles :

1. **Cadence.** L'enregistreur produit un point de contrôle à chaque instant
   `period_start + j × checkpoint_interval_s`, `j = 0 … 3600 /
   checkpoint_interval_s − 1` (paramètre de la configuration de
   l'enregistreur, CT-2 révision 0.4, EX-12.24 ; défaut : 60 ; diviseur de
   3600), à la tolérance d'alignement de 1 s près (`checkpoint_ts` dans
   `[instant, instant + 1 s]`), et un point à la clôture de la période, avant
   ou avec le manifeste ; deux points alignés consécutifs sont donc distants
   d'au plus `checkpoint_interval_s` + 1 s. Le point de clôture suit le
   dernier point aligné de `checkpoint_interval_s` (à la tolérance
   d'alignement près) plus le délai de production de la clôture après
   `period_end`, que la règle 1 ne borne pas ; le constat de cadence (CT-5
   AN-2) signale l'écart quand il dépasse `checkpoint_interval_s` + 1 s. Une
   période compte au plus `3600 /
   checkpoint_interval_s + 1` points (précision de la révision 0.3 faite avec
   CT-5 révision 0.2 ; le format ne change pas). Un point sans nouvel
   événement est permis et attendu (preuve de vie) ; il ne change que
   `checkpoint_ts` et `prev_checkpoint_hash`. La cadence n'est ni un contrôle
   du vérificateur de dossier, qui ne voit qu'un point (section 11), ni une
   condition de validité de la série (règles 2 à 5) : un arrêt légitime de
   l'enregistreur produit un écart ; elle se constate sur la série, par la
   supervision (CT-2) et par CT-5 (constat de cadence et alerte
   `point_manquant`, CT-5 AN-2, 8.9). La série de l'exemple de 10.8 est
   volontairement incomplète (quatre points pour la période 1) ; les séries
   des vecteurs (section 13) sont alignées, un point par minute et la
   clôture.
2. **Contenu.** Le point d'indice de taille `n` engage les `n` premiers
   événements de la période, dans l'ordre des `seq` : `root` est la racine
   RFC 6962 de `D[0..n-1]` par la règle de hachage de la section 9.1, les
   feuilles étant les mêmes que celles du manifeste ; `tree_size = n` ;
   `last_seq = first_seq + n − 1` (`first_seq` du manifeste de la période) ;
   `last_hash` est le `hash` de l'événement `last_seq`, tête de la chaîne au
   moment du point. Pour `n = 0` (aucun événement encore dans la période),
   `root` vaut 32 octets nuls (convention de la section 9.2),
   `last_seq = first_seq − 1` et `last_hash` est le `hash` de ce dernier
   événement, qui appartient à la période précédente, ou 32 octets nuls si le
   journal est vide.
3. **Chaîne des points.** Les points d'une période se chaînent par
   `prev_checkpoint_hash` : le `checkpointHash` (section 10.6) du point
   précédent de la même période, 32 octets nuls pour le premier point de la
   période. Le long de la chaîne, `tree_size` ne décroît jamais et
   `checkpoint_ts` ne décroît jamais ; `checkpoint_ts ≥ period_start`. Chaque
   période ouvre une nouvelle chaîne : les périodes se chaînent entre elles par
   `prev_period_hash` (section 10.3), non par les points.
4. **Dernier point.** Le dernier point d'une période a `tree_size = count`,
   `root = root` et `last_seq = last_seq` du manifeste : c'est la jonction
   entre la série des points et le manifeste, et c'est elle qui rend la preuve
   de cohérence de la section 10.7 applicable à tout point de la période.
5. **Clé.** `key_id` est la clé de l'enregistreur en vigueur à
   `checkpoint_ts`, par la règle de `recorder_key_id` du manifeste
   (section 10.1) : la clé du dernier événement de `seq ≤ last_seq`, ou
   `new_key_id` si cet événement est une rotation. Même espace de noms que
   `recorder_key_id` ; la clé est trouvée dans `cles.json` (section 11).
   Cette phrase dit ce que l'exportateur doit fournir ; quand la clé du point
   manque dans un `cles.json` exploitable, l'échec est porté par K-3, non par
   E-8 (section 11.4), et le dossier est invalide, puisque K-3 échoue dans le
   contrôle 6.
6. **Ce que le point ne porte pas.** Ni nonce ni `first_seq` : `first_seq` se
   déduit de `last_seq − tree_size + 1`, et l'unicité de deux points de même
   contenu est donnée par `checkpoint_ts` et par le chaînage. Ni signature de
   tiers : les ancres du point sont portées à côté (CT-5 ; section 11.2).

Noms des règles de série. La vérification d'une série de points d'une
période contre son manifeste (`verifierSeriePointsDeControle` de la
référence ; famille `points-de-controle/` de la section 13, champ
`rules_failed`) nomme chaque écart par l'une de ces règles : `chainage`
(règle 3, `prev_checkpoint_hash`), `tree_size_decroissant` et
`checkpoint_ts_decroissant` (règle 3), `period_start` (en-tête du point ou
`checkpoint_ts < period_start`, règle 3), `root`, `last_seq` et `last_hash`
(règle 2), `dernier_point` (règle 4), `cle_en_vigueur` (règle 5 : `key_id`
n'est pas la clé en vigueur), `signature` (signature invalide sous la clé
désignée), `validite_cle` (règle 5 : `checkpoint_ts` hors de l'intervalle
`valid_from`, `valid_to` de la clé dans `cles.json`, comme E-8 pour un
événement). La cadence (règle 1) n'a pas de nom de règle : c'est un constat
de CT-5, non un écart de validité.

<!-- schema: point-de-controle -->
```json
{
  "version": 0,
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
  "period_start": 1793710800,
  "tree_size": 4,
  "root": "0x22264c23c7f8fea323dd1998376576e0fa4d14c67dc577dc7a01e5ae9c2e4cf6",
  "last_seq": 4,
  "last_hash": "0x471dab56146ae2e4c678120af7faf5eed7b1f8e5db3657226de97614bde4dc00",
  "checkpoint_ts": "2026-11-03T13:53:00.000Z",
  "prev_checkpoint_hash": "0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
  "key_id": "rec-test-01",
  "sig": "0x29f6f3f6463ecba15185a160d923033e48d4c15f97f747105894b0dd49a3e021b489a9b6591416fcc71f68e174a251d9cf790fcbac39b6fdc74fd6a61f49870f"
}
```

| Clé | Type | Contraintes |
|---|---|---|
| `version` | entier | Constante `0`. |
| `org_id`, `journal_id` | hex 32 octets | Ceux des événements et du manifeste. |
| `period_start` | secondes UNIX | Le `period_start` du manifeste de la période (heure UTC pleine). |
| `tree_size` | entier ≥ 0 | `n`, nombre d'événements de la période engagés par le point ; `≤ count` du manifeste. |
| `root` | hex 32 octets | Racine RFC 6962 des `n` premières feuilles (section 9.1) ; 32 octets nuls si et seulement si `n = 0`. |
| `last_seq` | entier ≥ 0 | `first_seq + n − 1` ; `first_seq − 1` si `n = 0`. |
| `last_hash` | hex 32 octets | `hash` de l'événement `last_seq` (tête de chaîne) ; 32 octets nuls si `last_seq = 0`. |
| `checkpoint_ts` | horodatage | Instant de production, horloge de l'enregistreur : déclaratif, comme `ts` et `generated_at`. Seule une contresignature extérieure date le point (section 10.9). |
| `prev_checkpoint_hash` | hex 32 octets | `checkpointHash` du point précédent de la même période ; 32 octets nuls pour le premier. |
| `key_id` | identifiant de clé | Clé Ed25519 qui a produit `sig` (règle 5). |
| `sig` | hex 64 octets | Section 10.6. Portée **dans** l'objet, à la différence du manifeste : le point circule seul vers les ancres. |

Schéma : `schemas/point-de-controle-v0.schema.json`. Les relations
arithmétiques et le chaînage ne sont pas exprimables dans le schéma ; ce sont
les vérifications K-1 à K-6 de la section 11.4.

### 10.6 Hachage et signature du point

```text
K'             = point privé de sa clé sig (onze clés)
C_K            = JCS(K'), UTF-8
checkpointHash = SHA-256( P_K || C_K )
P_K            = octets UTF-8 de "noortrace/point-de-controle/v0\n"
               = 6e6f6f7274726163652f706f696e742d64652d636f6e74726f6c652f76300a   (31 octets)
sig            = Ed25519.Sign( sk(key_id), P_SK || C_K )
P_SK           = octets UTF-8 de "noortrace/signature-point-de-controle/v0\n"
               = 6e6f6f7274726163652f7369676e61747572652d706f696e742d64652d636f6e74726f6c652f76300a   (41 octets)
```

Ed25519 « pur », mêmes règles de vérification qu'en section 6.2. Le hachage ne
couvre pas la signature : `checkpointHash` est l'empreinte que les ancres
portent (jeton RFC 3161 sur `checkpointHash`, empreinte d'ancre
`keccak256(org_id ‖ journal_id ‖ checkpointHash)` au registre avec le `docType`
`noortrace/point-de-controle/v0`, fichier `P_K ‖ C_K` pour OpenTimestamps),
exactement comme `periodHash` l'est pour le manifeste (section 10.4). Ces deux
préfixes s'ajoutent aux six de l'annexe B ; aucun préfixe existant ne change.

Exemple : le point `K2` ci-dessus (quatre événements engagés, signé par
`rec-test-01`).

```text
C_K            = {"checkpoint_ts":"2026-11-03T13:53:00.000Z","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","key_id":"rec-test-01","last_hash":"0x471dab56146ae2e4c678120af7faf5eed7b1f8e5db3657226de97614bde4dc00","last_seq":4,"org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","period_start":1793710800,"prev_checkpoint_hash":"0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4","root":"0x22264c23c7f8fea323dd1998376576e0fa4d14c67dc577dc7a01e5ae9c2e4cf6","tree_size":4,"version":0}
checkpointHash = 0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff
sig            = 0x29f6f3f6463ecba15185a160d923033e48d4c15f97f747105894b0dd49a3e021b489a9b6591416fcc71f68e174a251d9cf790fcbac39b6fdc74fd6a61f49870f   (clé rec-test-01)
```

### 10.7 Preuve de cohérence (RFC 9162 §2.1.4)

Le manifeste engage les `N = count` feuilles de la période ; un point de
contrôle de taille `n < N` engage les `n` premières. La preuve de cohérence
entre `root(n)` et `R = root(N)` établit que l'arbre du point est un **préfixe**
de l'arbre du manifeste : les `n` premières feuilles sont les mêmes dans les
deux. Un événement d'indice de feuille `i < n`, prouvé inclus dans `R` par
`chemin.json` (section 9.3), est donc couvert par le point sans second chemin
d'inclusion : c'est ce que la partie `points-de-controle.json` exploite
(section 11.2). Pour `n = N`, la preuve est vide et les racines sont égales.

Génération, RFC 9162 §2.1.4.1 (identique à RFC 6962 §2.1.2) ; `k` est la plus
grande puissance de deux strictement inférieure à `n` :

```text
PROOF(m, D[0..n-1])             = SUBPROOF(m, D[0..n-1], vrai)                                 0 < m < n
SUBPROOF(m, D[0..m-1], vrai)    = {}                                                           m = n, racine déjà connue
SUBPROOF(m, D[0..m-1], faux)    = { MTH(D[0..m-1]) }                                           m = n, racine à fournir
SUBPROOF(m, D[0..n-1], b)       = SUBPROOF(m, D[0..k-1], b)        || { MTH(D[k..n-1]) }       si m ≤ k
                                = SUBPROOF(m − k, D[k..n-1], faux) || { MTH(D[0..k-1]) }       si m > k
```

La preuve compte au plus `⌈log2 n⌉ + 1` nœuds. Les cas `m = 0` et `m > n` ne
sont pas définis ; `m = n` donne la preuve vide. La période vide (`n = 0`,
racine nulle, section 9.2) n'a pas de tête RFC 6962 : aucune preuve ne part
d'elle ni n'y mène. Certaines implémentations acceptent pourtant une preuve
vide depuis une taille nulle : `transparency-dev/merkle` v0.0.2
(`proof.VerifyConsistency`, « Any size greater than 0 is consistent with size
0 ») le fait sans lire `first_root`, ce que la branche principale du même
dépôt refuse ; la confrontation de CT-5 (annexe A.6, `confrontation/coherence`)
relève ce cas comme une limite de l'outil. Le rejet de `m = 0` ci-dessous est
donc délibéré : il évite qu'une racine nulle de NOORTRACE soit confondue avec
la racine RFC 6962 de l'arbre vide, `SHA-256("")`.

Vérification, algorithme de la RFC 9162 §2.1.4.2, reproduit pour qu'il n'y ait
pas à la lire (la RFC 6962 ne donne pas d'algorithme de vérification) :

```text
entrées : m = first_size, n = second_size, first_root, second_root, path[0..p-1]
si m = 0 ou n < m : rejeter                                 (hors de la définition)
si m = n : accepter si et seulement si path est vide et first_root = second_root
si path est vide : rejeter
si m est une puissance de 2 : préposer first_root à path    (la racine de l'ancien arbre n'y figure pas)
fn ← m − 1 ; sn ← n − 1
tant que fn est impair : fn ← fn >> 1 ; sn ← sn >> 1
fr ← path[0] ; sr ← path[0]
pour chaque h de path à partir du deuxième élément, dans l'ordre :
    si sn = 0 : rejeter                                     (chemin trop long)
    si fn est impair ou fn = sn :
        fr ← SHA-256(0x01 || h || fr)                       (h est à gauche, dans les deux arbres)
        sr ← SHA-256(0x01 || h || sr)
        tant que fn n'est pas impair et fn ≠ 0 : fn ← fn >> 1 ; sn ← sn >> 1
    sinon :
        sr ← SHA-256(0x01 || sr || h)                       (h est à droite, dans le second arbre seulement)
    fn ← fn >> 1 ; sn ← sn >> 1
accepter si et seulement si fr = first_root et sr = second_root et sn = 0
```

Le vérificateur DOIT exécuter cet algorithme, et non recalculer les deux
racines en devinant la position des nœuds : il garantit que `path` a
exactement la longueur attendue pour `(m, n)` et refuse un nœud en trop, un
nœud manquant, un nœud permuté, des racines échangées et des tailles qui ne
correspondent pas à la preuve (K-5). Une implémentation écrite d'après ce texte
reproduit nœud pour nœud les vecteurs de cohérence publiés par les
implémentations de référence de Certificate Transparency (arbres de huit
feuilles de 0 à 16 octets, preuves `(1, 8)`, `(6, 8)`, `(2, 5)`, `(6, 7)`) et
refuse leurs sondes de corruption ; ces vecteurs et leurs sondes sont à
rejouer dans `test/journal.test.js` (section 17).

### 10.8 Exemple numérique complet

Série des points de l'exemple de référence (annexe A ; feuilles, nœuds et
racine de la section 9.4). La série est volontairement courte pour rester
lisible : un enregistreur à la cadence par défaut produirait un point par
minute, les points supplémentaires étant des preuves de vie qui ne changent
que `checkpoint_ts` et `prev_checkpoint_hash`. `K2` est l'exemple de la
section 10.5 ; `K4` est le point de clôture de la période 1 (`tree_size = 5 =
count`, `root` = racine du manifeste, signé par `rec-test-02`, clé en vigueur
après la rotation de seq 5) ; `K5` et `K6` sont les deux points de la période
vide (`tree_size = 0`, racine nulle, `last_hash` = `hash` de seq 5, tête de
chaîne héritée de la période 1).

| Point | `tree_size` | `root` | `last_seq` | `checkpoint_ts` | `prev_checkpoint_hash` | `key_id` | `checkpointHash` | `sig` |
|---|---|---|---|---|---|---|---|---|
| K1 | 2 | `0xa5b5b030de6510a06da18b109b73e7b85c4afe3e6d0fb89b4bd9b53b3d42f79e` | 2 | `2026-11-03T13:42:00.000Z` | `0x0000000000000000000000000000000000000000000000000000000000000000` | `rec-test-01` | `0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4` | `0x96c006c0f2be56f834413b6ee08961badd810c893bbdd9d40bb5d48bd498f7d66b89cb29979e0907e48b4ec33250e7f0b89f89447f0d4f57d78b11cf6675c409` |
| K2 | 4 | `0x22264c23c7f8fea323dd1998376576e0fa4d14c67dc577dc7a01e5ae9c2e4cf6` | 4 | `2026-11-03T13:53:00.000Z` | `0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4` | `rec-test-01` | `0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff` | `0x29f6f3f6463ecba15185a160d923033e48d4c15f97f747105894b0dd49a3e021b489a9b6591416fcc71f68e174a251d9cf790fcbac39b6fdc74fd6a61f49870f` |
| K3 | 4 | `0x22264c23c7f8fea323dd1998376576e0fa4d14c67dc577dc7a01e5ae9c2e4cf6` | 4 | `2026-11-03T13:54:00.000Z` | `0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff` | `rec-test-01` | `0x3feb86ac4d6d8c054bef224f131f0276d2f1c9c9db2a6ce06adec173378d8867` | `0x8e37a2cf042ceacaab8d81df08591802228330d76e398a2fe1813ec10b6d2bb9c68282f3e6a481a4723ec76fd48179f76568cfec12e7c1ba32d2120cbf2a4c0a` |
| K4 | 5 | `0x6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06` | 5 | `2026-11-03T14:00:00.250Z` | `0x3feb86ac4d6d8c054bef224f131f0276d2f1c9c9db2a6ce06adec173378d8867` | `rec-test-02` | `0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107` | `0xe2dd1ae0b182e6da7d34a6ebb611dc8a628297a09b03e987e921f8c71659c572fcf70b428f678380fb4c05d73bf6118a41d5e25ffb7d10eb8e689a426c63e80e` |
| K5 | 0 | `0x0000000000000000000000000000000000000000000000000000000000000000` | 5 | `2026-11-03T14:01:00.000Z` | `0x0000000000000000000000000000000000000000000000000000000000000000` | `rec-test-02` | `0x3c4bd86148138e52a1ef6912c7ab4fa98ffdaf90879900887833e726b5a9e153` | `0x7bd3835f0f686cdd5141f0d0d590b293a09724cd1bce9b6ffd3e337f3dfa189f77945264ca4a0743d6e5e35c164dc7f81f64b877974b497a567094b6a130730f` |
| K6 | 0 | `0x0000000000000000000000000000000000000000000000000000000000000000` | 5 | `2026-11-03T15:00:00.112Z` | `0x3c4bd86148138e52a1ef6912c7ab4fa98ffdaf90879900887833e726b5a9e153` | `rec-test-02` | `0xd6e22871885b68962dadee69f9fa2ff3a76949d23550d1682d3564bcc705474d` | `0x4993daaf14482da9001d4eb6123dab4720cfa62f8da39e8ecc9a7cdd547d67c520acaaddddfa6684e6a1a368ae0f4e982c019c254ecf2e64f8aff26a591c0d02` |

Le premier point de la période vide, complet :

<!-- schema: point-de-controle -->
```json
{
  "version": 0,
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
  "period_start": 1793714400,
  "tree_size": 0,
  "root": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "last_seq": 5,
  "last_hash": "0x506e54e1ec35a6432114fc06947b23c753ce6d5cf4260354b7fdbed011b04f05",
  "checkpoint_ts": "2026-11-03T14:01:00.000Z",
  "prev_checkpoint_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "key_id": "rec-test-02",
  "sig": "0x7bd3835f0f686cdd5141f0d0d590b293a09724cd1bce9b6ffd3e337f3dfa189f77945264ca4a0743d6e5e35c164dc7f81f64b877974b497a567094b6a130730f"
}
```

```text
C_K            = {"checkpoint_ts":"2026-11-03T14:01:00.000Z","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","key_id":"rec-test-02","last_hash":"0x506e54e1ec35a6432114fc06947b23c753ce6d5cf4260354b7fdbed011b04f05","last_seq":5,"org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","period_start":1793714400,"prev_checkpoint_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","root":"0x0000000000000000000000000000000000000000000000000000000000000000","tree_size":0,"version":0}
checkpointHash = 0x3c4bd86148138e52a1ef6912c7ab4fa98ffdaf90879900887833e726b5a9e153
```

Racines des préfixes de l'arbre de la période 1 (`MTH(D[0..m-1])`, notation de
la section 9.4) :

| `m` | Racine | Valeur |
|---|---|---|
| 1 | `L(0)` | `0xd5e2098df5be8721f7343aab8ad414a5bea5b55bb0fb0e72eb8fb9bb6c3f5a8b` |
| 2 | `N01` | `0xa5b5b030de6510a06da18b109b73e7b85c4afe3e6d0fb89b4bd9b53b3d42f79e` |
| 3 | `N012 = SHA-256(01 ‖ N01 ‖ L(2))` | `0x3f18df046e3c8dbff1ec006b9533cb0be82d756c347c8838a25f03bfda5cd399` |
| 4 | `N0123` | `0x22264c23c7f8fea323dd1998376576e0fa4d14c67dc577dc7a01e5ae9c2e4cf6` |
| 5 | racine | `0x6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06` |

Preuves de cohérence vers la racine (`n = 5`, `k = 4`) :

| `PROOF(m, D[5])` | Dérivation | Nœuds, dans l'ordre |
|---|---|---|
| `m = 1` | `SUBPROOF(1, D[0..3], vrai) ‖ {L(4)}` → `SUBPROOF(1, D[0..1], vrai) ‖ {N23} ‖ {L(4)}` → `{L(1)}` puis `N23`, `L(4)` | `[L(1), N23, L(4)]` |
| `m = 2` | `SUBPROOF(2, D[0..3], vrai) ‖ {L(4)}` → `SUBPROOF(2, D[0..1], vrai) = {}` puis `N23`, `L(4)` | `[N23, L(4)]` |
| `m = 3` | `SUBPROOF(3, D[0..3], vrai) ‖ {L(4)}` → `3 > 2` : `SUBPROOF(1, D[2..3], faux) ‖ {N01}` → `{L(2)} ‖ {L(3)}` | `[L(2), L(3), N01, L(4)]` |
| `m = 4` | `SUBPROOF(4, D[0..3], vrai) = {}` puis `L(4)` | `[L(4)]` |

Valeurs :

```text
PROOF(1, D[5]) = ["0x3ef9fdf53c5fd27d37c20efdce9d0d8bfcfd459d491e5cb66dd3f384540d270c", "0x2fb61705d23c09d71bebc1a297940ce119c3bda5b3357d39d76043cb554cfea8", "0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0"]
PROOF(2, D[5]) = ["0x2fb61705d23c09d71bebc1a297940ce119c3bda5b3357d39d76043cb554cfea8", "0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0"]
PROOF(3, D[5]) = ["0x8380b74438d71a5fb81aa3b62f1c7e0b06cb0e9c73f5d5a42f44372e203fbf3e", "0x3617a8c28e38e476cc671a109baf783cd70e1f24eca0278280a215b28f1c55db", "0xa5b5b030de6510a06da18b109b73e7b85c4afe3e6d0fb89b4bd9b53b3d42f79e", "0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0"]
PROOF(4, D[5]) = ["0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0"]
```

Déroulé de la vérification de `PROOF(3, D[5])` (`m = 3` n'est pas une
puissance de deux : rien n'est préposé) : `fn = 2`, `sn = 4`, `fn` pair, pas de
décalage initial, `fr = sr = L(2)`.

| Étape | `h` | Condition | `fr` | `sr` | `fn, sn` après |
|---|---|---|---|---|---|
| 1 | `L(3)` | `fn = 2` pair, `fn ≠ sn` | `L(2)` | `SHA-256(01 ‖ L(2) ‖ L(3)) = N23` | `1, 2` |
| 2 | `N01` | `fn = 1` impair | `SHA-256(01 ‖ N01 ‖ L(2)) = N012` | `SHA-256(01 ‖ N01 ‖ N23) = N0123` | `0, 1` |
| 3 | `L(4)` | `fn = 0` pair, `fn ≠ sn` | `N012` | `SHA-256(01 ‖ N0123 ‖ L(4)) = racine` | `0, 0` |

`fr = N012 = first_root`, `sr = racine = second_root`, `sn = 0` : la preuve est
acceptée.

Déroulé de `PROOF(4, D[5])`, le cas du point `K2` (`m = 4` est une puissance de
deux) : `first_root = N0123` est préposé, `path = [N0123, L(4)]` ; `fn = 3`,
`sn = 4` ; `fn` impair → décalages jusqu'à `fn = 0`, `sn = 1` ;
`fr = sr = N0123`. Pour `h = L(4)` : `sn ≠ 0`, `fn = 0` pair et `fn ≠ sn`, donc
`sr = SHA-256(01 ‖ N0123 ‖ L(4)) = racine`, puis `fn = 0`, `sn = 0`.
`fr = N0123`, `sr = racine`, `sn = 0` : acceptée. Sans la préposition, `path`
n'aurait qu'un élément et `fr`, `sr` vaudraient `L(4)` : refusée, comme il se
doit.

### 10.9 Ce qu'un point de contrôle prouve et ne prouve pas

Un point de contrôle **signé** par l'enregistreur n'est qu'une attribution :
qui détient la clé peut en produire autant qu'il veut, à n'importe quel
`checkpoint_ts`. Ce qui donne au point sa valeur est ce que CT-5 y attache,
pièce par pièce :

| Ancre du point | Ce qu'elle prouve, quand sa vérification réussit | Ce qu'elle ne prouve pas |
|---|---|---|
| Jeton RFC 3161 sur `checkpointHash` | Le point, donc les `n` premiers événements de la période (par `root`) et la tête de chaîne (`last_hash`), existaient au plus tard à `genTime` augmenté de la précision du jeton, selon l'autorité qui l'a signé (CT-6 §9, EX-9.20 ; qualification selon le fichier d'ancres du réviseur). | Que l'autorité est digne de confiance (fichier d'ancres, hypothèses H3 et H4 de CT-6) ; une borne « pas avant » ; la date de l'événement lui-même (`ts` reste déclaratif). Un jeton d'un serveur interne, non qualifié, prouve seulement qu'une clé contrôlée par l'exploitant a signé ce condensé et cette heure déclarée : il s'étiquette tel quel dans le fichier d'ancres et dans l'énoncé (CT-6 §7). |
| Ancre au registre (`AttestationRegistry.anchor`, empreinte `keccak256(org_id ‖ journal_id ‖ checkpointHash)`, `docType` `noortrace/point-de-controle/v0`) | Sous les hypothèses H6 et H7 de CT-6 : l'ordre, entre les blocs, de l'empreinte du point par rapport aux autres empreintes ancrées, et l'unicité de cette empreinte sur la chaîne. | Aucune date : l'horodatage d'un bloc est celui de son proposant (CT-6 §7, §11.8). Aucune position : le registre accepte toute empreinte nouvelle, et qui tient la clé de l'enregistreur et la clé de chaîne peut ancrer une autre série ; seul le contrôle de complétude au registre sur la série publiée le révèle (CT-5 EX-10.7, AN-61). |
| Preuve OpenTimestamps du fichier `P_K ‖ C_K` | Le point existait avant la création d'un bloc Bitcoin, sous `k` confirmations, indépendamment de toute autorité (CT-6 §10). | La preuve n'existe qu'à l'inclusion dans Bitcoin (plusieurs heures après la soumission) ; avant, l'attestation est en attente et ne prouve rien. |

**Fenêtre de réécriture.** Soit un événement de `ts = t_e`. Qui détient la clé
de l'enregistreur peut réécrire et signer de nouveau tout ce qui n'est pas
encore engagé par une ancre extérieure. La fenêtre pendant laquelle une
réécriture de cet événement reste indétectable est `W = T − t_e`, où `T` est
l'instant de la première ancre extérieure qui engage l'événement. Avec les
seules ancres horaires (manifeste), `T` est l'instant du jeton de la clôture :
`W ≤ 3600 s + d_clôture + d_jeton` (CT-6 §3.4). Avec des points de contrôle
ancrés par un moyen, la borne générale est `W ≤ c_moyen + d_moyen`, où
`c_moyen` est l'intervalle entre deux ancres successives de ce moyen et
`d_moyen` son délai d'obtention : `c_K` (60 s) pour le registre, qui ancre
chaque point engageant un nouvel événement, d'où un ordre (non une date) à
`60 s + d_registre` ; `c_T` (300 s) pour le jeton, CT-5 contresignant, à chaque
échéance de 300 s (CT-5 §4.2), le premier point produit à partir de cette
échéance s'il engage un nouvel événement, d'où une date à `300 s + d_jeton`
(CT-5 EX-3.5 décompose `d_jeton`). L'ancre au registre ne fournit aucun
instant `T` : `60 s + d_registre` est la durée de conception `W_ordre` de
CT-5 §3.3, mesurée par l'exploitant (CT-5 P-2) ; ce n'est pas une borne de
`W` qu'un dossier prouve. Seules les ancres qui datent fournissent `T` : le
jeton, dont l'instant `genTime` augmenté de la précision est prouvé selon son
autorité (K-7) ; la création du bloc Bitcoin termine aussi la fenêtre (K-9),
sans que cet instant soit prouvé. Le manifeste de la période reste
contresigné par le prestataire qualifié de la clôture (CT-5 EX-3.4) ; le point
de clôture n'a de jeton propre que s'il est sélectionné par une échéance
antérieure (CT-5 EX-4.3) ou par le repli de clôture (CT-5 EX-4.2). Après `T`,
une réécriture de l'événement, du point ou d'un point antérieur de la chaîne
change `root`, `last_hash` ou `prev_checkpoint_hash`, donc `checkpointHash`, que
l'ancre ne porte plus : elle devient détectable. Confrontée à l'ancre
d'origine (dossier d'origine qui porte la partie, ou série et ancres
publiées), la version réécrite ne passe plus K-2, K-5 et K-7 (ou K-9, ou K-8
et R-11 de CT-6 ; section 11.4). Présentée seule, elle peut passer le
vérificateur : sans la partie, avec la seule borne de la clôture ; avec un
nouveau point contresigné plus tard, avec ses K- et un `T` postérieur, que le
rapport montre (`rewrite_window_end`, CT-6 EX-6.17). C'est le sens de CT-6
§7.9 : détectable par quiconque détient le dossier d'origine, non détectée.
Avant `T`, rien ne l'empêche, et le vérificateur de dossier le dit (CT-6
§7).

**Ce que le dossier ne montre pas.** Le dossier (section 11.2) ne porte que le
point qui couvre l'événement prouvé, avec sa preuve de cohérence vers le
manifeste et ses ancres : il prouve que cet événement était engagé par ce point
à l'instant de l'ancre. Il ne porte pas la série : le chaînage
(`prev_checkpoint_hash`), la monotonie de `tree_size` et de `checkpoint_ts` et
la cadence se contrôlent sur la série des points, chez le client et par CT-5 ;
un point inséré ou antidaté dans une série déjà ancrée ne chaîne plus les
points ancrés et contredit leur preuve de cohérence, mais c'est la série qui
le montre, pas un dossier. Le dossier ne prouve pas non plus que le point est
le premier à couvrir l'événement : l'exportateur choisit, parmi les points de
`tree_size > i`, celui qui porte la meilleure ancre (jeton, puis `.ots`
complète, puis registre, section 11.2 ; CT-5 EX-10.2), et la borne `T` est
celle de ce point. Il ne prouve pas non plus qu'aucune autre série n'a été
ancrée pour la même période (CT-5 EX-10.7).

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

Révision 0.3 : une **treizième partie facultative**, `points_de_controle`
(`points-de-controle.json`, section 11.2), peut suivre les douze, toujours en
treizième position, présente avec son SHA-256 ou absente avec une raison
(« aucun point de contrôle », par exemple). Un index à douze parties reste
valide : les dossiers produits avant la révision 0.3 et ceux dont
l'exportateur ne connaît pas la partie ne changent pas de verdict (K-1 à
K-9 ne sont pas exécutées et ne figurent pas au rapport, CT-6 EX-5.7). Avec la
partie, l'index du dossier de référence ci-dessus reçoit la ligne suivante après
`validateurs`, tout le reste étant inchangé (`generated_at` compris) :

```json
{"name": "points_de_controle", "file": "points-de-controle.json", "sha256": "0xe9340e56c7c7ad6d7b1e168ad1e5d8616f3aa6dfc31e46a49860c89f38460a05", "present": true, "reason_if_absent": null}
```

et, quand l'exportateur déclare la partie sans la fournir :

```json
{"name": "points_de_controle", "file": "points-de-controle.json", "sha256": null, "present": false, "reason_if_absent": "aucun point de contrôle"}
```

Le schéma `dossier-v0.schema.json` admet les deux formes de l'index (douze
parties exactement, ou treize dont la treizième est `points_de_controle`) ;
un index à quatorze parties, ou dont la treizième porte un autre nom ou un
autre fichier, est invalide (D-1).

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
| `jeton-rfc3161.der` | CT-6 §9 | Jeton d'horodatage qualifié sur `periodHash` (section 10.2), produit par CT-5. |
| `preuve.ots` | CT-6 §10 | Preuve OpenTimestamps de `periodHash`, produite par CT-5. |
| `registre.json` | `registre-v0.schema.json` (CT-6 §11.2.1) | Entrées des transactions prouvées (inscription de clé, `anchor`, `submitPeriod`) : en-tête et tous les reçus de leur bloc, index du reçu et du journal prouvés ; aucune valeur d'état. Produit par CT-4. |
| `certificat-commit.json` | `registre-v0.schema.json#/$defs/certificat_commit` (CT-6 §11.2.2) | Un certificat de commit (`noor_getCommitCertificate`) par bloc nommé dans `registre.json`. Produit par CT-4. |
| `validateurs.json` | `validateurs-v0.schema.json` (CT-6 §11.2.3) | Jeux de validateurs déclarés, avec leurs hauteurs de validité. Produit par CT-4. |
| `points-de-controle.json` | `#/$defs/points_de_controle` | (révision 0.3, facultative) `{ "version": 0, "checkpoint", "checkpoint_hash", "consistency", "anchors" }`. `checkpoint` : un point de contrôle (section 10.5) de `tree_size` strictement supérieur à `leaf_index` de `chemin.json`, choisi par l'exportateur dans cet ordre de préférence (révision 0.3 précisée avec CT-5 révision 0.2, EX-10.2) : un point qui porte un jeton RFC 3161, à défaut une preuve `.ots` complète, à défaut une ancre au registre, à défaut un point sans ancre ; à rang égal le plus petit `tree_size`, puis le premier de la série (plus petit `checkpoint_ts`) ; le vérificateur accepte tout point qui couvre l'événement (K-4) ; `checkpoint_hash` : son `checkpointHash` (section 10.6), recalculé par le vérificateur ; `consistency` : la preuve de cohérence de la section 10.7, `{ "version": 0, "first_size" = tree_size, "second_size" = count du manifeste, "first_root" = root du point, "second_root" = root du manifeste, "path" }`, vide si `tree_size = count` ; `anchors` : `rfc3161` (`{ "token" }`, `TimeStampToken` DER en base64 dont le `messageImprint` est (SHA-256, `checkpoint_hash`)), `registry` (référence de l'ancre du point au registre : `chain_id`, `contract`, `fingerprint = keccak256(org_id ‖ journal_id ‖ checkpoint_hash)`, `doc_type`, `block_number`, `block_hash`, `transaction_hash`, `log_index` ; entiers de la section 3, non les quantités hexadécimales de `registre.json`), `ots` (`{ "proof" }`, fichier `.ots` en base64 sur `P_K ‖ C_K`) ; chaque ancre non fournie vaut `null`. Une seule disposition : le jeton et la preuve sont embarqués en base64 (section 3) plutôt que placés dans des fichiers séparés, pour que la partie n'en fasse qu'une (un SHA-256 dans l'index, D-2) et que les parties v0 restent douze. La preuve d'inclusion de la transaction du registre (en-tête, reçus, certificat de commit) n'est pas dans cette partie : CT-6 (révision 0.2) fixe comment `registre.json` et `certificat-commit.json` la portent (vérification K-8) ; sans elle, la référence `registry` est déclarative. Le point est produit par CT-2 (révision 0.4, 12.10) ; ses ancres par CT-5 (jeton, preuve) et CT-4 (référence au registre). Pour la référence au registre : le composant d'ancrage de CT-5 décide quand l'ancre du point part (CT-5 EX-4.6, EX-9.3) et l'envoie avec la clé de chaîne de CT-2 ; CT-4 fixe la transaction, la conduite d'envoi (§8.6) et la capture (§9.4) ; l'exportateur lit la référence dans l'index de capture de CT-4 (CT-5 EX-10.3). |

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

Exemple de `points-de-controle.json` (révision 0.3) du dossier de référence
(seq 4, `leaf_index = 3`) : le point `K2` de la section 10.8 (`tree_size = 4`,
premier point qui couvre la feuille 3), la preuve `PROOF(4, D[5])` et, pour
ancre, un jeton RFC 3161 sur `checkpointHash` produit par l'autorité
d'horodatage de test de CT-6 (`spec/vecteurs/ct-6/rfc3161/cles`, clés
publiques, sans valeur hors des tests ; RSA-3072, politique
`1.3.6.1.4.1.99999.1.1`, `genTime` `2026-11-03T13:53:02Z`, précision 1 s,
numéro de série 1001, nonce de la section 13, certificat de l'unité inclus
comme l'exige CT-6 EX-13.1). Les ancres au registre et OpenTimestamps ne sont
pas fournies (`null`). Le fichier est écrit par
`JSON.stringify(objet, null, 2)` suivi d'un saut de ligne, comme les autres
parties ; son SHA-256,
`0xe9340e56c7c7ad6d7b1e168ad1e5d8616f3aa6dfc31e46a49860c89f38460a05`, est celui
que la ligne de la section 11.1 déclare.

<!-- schema: points_de_controle -->
```json
{
  "version": 0,
  "checkpoint": {
    "version": 0,
    "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
    "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
    "period_start": 1793710800,
    "tree_size": 4,
    "root": "0x22264c23c7f8fea323dd1998376576e0fa4d14c67dc577dc7a01e5ae9c2e4cf6",
    "last_seq": 4,
    "last_hash": "0x471dab56146ae2e4c678120af7faf5eed7b1f8e5db3657226de97614bde4dc00",
    "checkpoint_ts": "2026-11-03T13:53:00.000Z",
    "prev_checkpoint_hash": "0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4",
    "key_id": "rec-test-01",
    "sig": "0x29f6f3f6463ecba15185a160d923033e48d4c15f97f747105894b0dd49a3e021b489a9b6591416fcc71f68e174a251d9cf790fcbac39b6fdc74fd6a61f49870f"
  },
  "checkpoint_hash": "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff",
  "consistency": {
    "version": 0,
    "first_size": 4,
    "second_size": 5,
    "first_root": "0x22264c23c7f8fea323dd1998376576e0fa4d14c67dc577dc7a01e5ae9c2e4cf6",
    "second_root": "0x6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06",
    "path": [
      "0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0"
    ]
  },
  "anchors": {
    "rfc3161": {
      "token": "MIIINAYJKoZIhvcNAQcCoIIIJTCCCCECAQMxDTALBglghkgBZQMEAgEwgccGCyqGSIb3DQEJEAEEoIG3BIG0MIGxAgEBBgorBgEEAYaNHwEBMDEwDQYJYIZIAWUDBAIBBQAEIGqOA1q5uQk3pbDUERhWfJUvPOSciVuBY2q3C1FiU+b/AgID6RgPMjAyNjExMDMxMzUzMDJaMAMCAQECCHSm9JeUIUEeoEmkRzBFMQswCQYDVQQGEwJDSDEbMBkGA1UECgwSTk9PUlRSQUNFIHZlY3RldXJzMRkwFwYDVQQDDBBUU0EgZGUgdGVzdCBDVC02oIIEcjCCBG4wggLWoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwRDELMAkGA1UEBhMCQ0gxGzAZBgNVBAoMEk5PT1JUUkFDRSB2ZWN0ZXVyczEYMBYGA1UEAwwPQUMgZGUgdGVzdCBDVC02MB4XDTI2MDYwMTAwMDAwMFoXDTI3MDYwMTAwMDAwMFowRTELMAkGA1UEBhMCQ0gxGzAZBgNVBAoMEk5PT1JUUkFDRSB2ZWN0ZXVyczEZMBcGA1UEAwwQVFNBIGRlIHRlc3QgQ1QtNjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBANqw2sqDHnfUcwAjebW4gf/nTBnpqQrr7+tTWWi0OVuuKUHuW6uPpyKzTjTOmFt/cDnAYrww6IwWDLYX/F6od/qDz/Qec15QpuL73qfr63eU8dJqEAOgtaCTzB7f4Sy6cPi9DqYnhfDFPA/a7OR04ZsT2vSuVAi+upbtZV8eq9s7xtXugWerg44GMGcCJYznRtA8NrUuAcXdgFknS1qDKVViPGzf0bOe6do5idou5rSDAvn9VKFxwpljqZK/YJBabyg9lXPXEltyuUmd85KmapeLPef9xYYvLW4CimIFTxvUWZ/WlN8klS7U6Zgy1+ucTA8mevmzXxMikMtYPN060i70tRxRIDO2bQsL5xO0K881JkgkaLx34ycZ+gMzMxGTbCm2ESDUIG7PnLFW6hLHzIkxWvjp+fyIbAsRRj2TuZK5MIfJB8sy/w3NVbcCFKAGm4qH+npzy//8tWCrqLKKIa2O9Whi0EkgMmbMbwTnqF4ONvNQiH2pcbpBHjdhKSATpQIDAQABo2owaDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFELg6KaAwgf9L7GxVCxQnxzZ8oqTMB8GA1UdIwQYMBaAFOWYQz/533+Z5pdz2xPeP7Dek5haMA0GCSqGSIb3DQEBCwUAA4IBgQCRb/3NoC1+dyvORRAAwJ2wtFtffwCRyO8WRbI8bYqnziyye2WBC4uvGRDG8ruzPgVLm0bDUAIUPgKFLU/lMD/R6Vnh5OD6G5NgQrhpGB4GeAL2XjWIzBtWO0IRl/8XDTkRfXKQO1lcsDxG44Dn8AC9+NDputiV/OYgTV6cUtNQfR5hkIIEE5vqXlEDaotKLm9rgZLrAXWGBTZq4kHdjevIMGQ5pNMNWMQWa1OqEWc2i6FA+/NdrOOfowBRz8r2ncp0djyrZTSUFDxpHjvap5oHNEYs23bUaRLlWleaxLMeMStSN+nLeB1wxWAigyqEnGfcib0Xa7whTfjRzVHH+jYhnaIacgrld8i/yGfMnCzJBXBoiEPD4A/zLl2vSSXdUP+nDYkqBoxHGHUtoX2Bpa5R0+jLYkZlUetdt3GBo2ja1HSVUrvmbXkNsmeqmDFe9jNuUIeG/S8gYP6PA/mlblS4nA2YSENJF+T0FU+NHa+2ARo+ARycP8udcZ1kzXR7fu0xggLLMIICxwIBATBJMEQxCzAJBgNVBAYTAkNIMRswGQYDVQQKDBJOT09SVFJBQ0UgdmVjdGV1cnMxGDAWBgNVBAMMD0FDIGRlIHRlc3QgQ1QtNgIBAjALBglghkgBZQMEAgGggdYwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCBoNpAsCXTThTc1WajfFdfzug/fS2egEZGc3mweIFU3eTCBhgYLKoZIhvcNAQkQAi8xdzB1MHMwcQQgAFn6h7SwJDKrPCy+26uu/g5LSDk1KSE4XG+x3xA1w6kwTTBIpEYwRDELMAkGA1UEBhMCQ0gxGzAZBgNVBAoMEk5PT1JUUkFDRSB2ZWN0ZXVyczEYMBYGA1UEAwwPQUMgZGUgdGVzdCBDVC02AgECMA0GCSqGSIb3DQEBCwUABIIBgE3VDRv40oAM0/RJNRiKOBjgKpK7/b8jS/wwJ94RLzVwWeAAuITHtIhtd6oQD2hRARcfrvoiZdxx3UY5CURKWpNzOxBLgiGkSGwAuQZyf9Se5F1EkCEQrGR8AawmkIqPJtt6s8ug0qCS+HQN9KL0Cev4v37oSfyWglHA0BXTuOalbYVZKQ0EBUDGSecK5YiwjciTt0geHn60CONXRLxy1HCOMzeJAE9vMwYXEssje+BhihE2vmW83jJ+FmC2t3wzC10tSIdOPJfkWB/CdOHFkyjZlsVHJNYeE/oqIdPEXBBs285D+zsm24Of9RyREw4C4P++wbare48ovo4UWjeseaNqKz8whjWjN0PyrjZaUTBhGKE//H78PhhymkJmUVujRwVpt+IxSjpTXCMJb7/HLxDejfq+wjaevyFAOa+Jd2vEhnvwVopsDm937Y7NU+EoXe3La5KUrK39AFwDt0MjRXQgVVOAgHuvCqriR+Bn8PEqq2i8EfAV6e+lvNwdHREYkA=="
    },
    "registry": null,
    "ots": null
  }
}
```

Le jeton décodé fait 2104 octets (SHA-256
`0x0a7cd7a11ffdea5b7ec14f0e9af35588bf8fdfa7fb70ac9b82b6be2d0a389f91`) ; il
passe T-1 à T-10 de CT-6 avec le fichier d'ancres de test
`spec/vecteurs/ct-6/ancres/ancres-test.json` (T-11 non exécutée : autorité
non déclarée qualifiée), ce qui donne `upper_bound = 2026-11-03T13:53:03Z` ;
et, une fois le base64 décodé dans un fichier, `openssl ts -verify -digest
6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff -token_in -in
<fichier> -CAfile ac-test.pem -untrusted tsa-test.pem` rend « Verification:
OK ». La même partie avec les trois ancres à `null` (point et preuve seuls)
est valide aussi ; son SHA-256 est
`0x1c10718bce466f0f8bd31501209f7dcabd675d9c83b0eb0c81e20a1b5b86aa65`.

Forme d'une référence `registry` (valeurs illustratives : identifiant de
chaîne du réseau de développement de CT-4, adresse, bloc et transaction à
zéro ; aucune transaction de ce nom n'existe), avec l'empreinte et le
`docType` que le point `K2` recevrait :

```json
{
  "chain_id": 2124,
  "contract": "0x0000000000000000000000000000000000000000",
  "fingerprint": "0x7f721a4526c614882ff41ac33792c6d05fa7fb6dd98bc1c369d0e277029f4e44",
  "doc_type": "0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178",
  "block_number": 0,
  "block_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "transaction_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "log_index": 0
}
```

`doc_type` est `keccak256(UTF-8("noortrace/point-de-controle/v0"))`, libellé
que CT-4 §6.4 inscrit dans sa table en révision 0.3 ; `fingerprint` est
`keccak256(org_id ‖ journal_id ‖ checkpoint_hash)` sur 96 octets, comme en
section 10.4.

### 11.3 Les huit contrôles de l'architecture

| N° | Contrôle de l'architecture | Pièces | Exécutable avec |
|---|---|---|---|
| 1 | Hachage canonique de l'événement et égalité avec `hash` | `evenement.json` | **CT-1** |
| 2 | Continuité de la chaîne avec les voisins fournis | `voisins.json` | **CT-1** |
| 3 | Recalcul du chemin de Merkle jusqu'à la racine | `chemin.json`, `manifeste.json` | **CT-1** |
| 4 | Signature du jeton RFC 3161 et égalité avec `periodHash` (section 10.2) | `jeton-rfc3161.der`, chaîne de certificats | CT-6 (jeton produit par CT-5) |
| 5 | Preuve OpenTimestamps contre les en-têtes Bitcoin | `preuve.ots`, en-têtes | CT-6 (preuve produite par CT-5) |
| 6 | Signature Ed25519 de l'enregistreur sur l'événement | `evenement.json`, `cles.json` | **CT-1** |
| 7 | Signatures des approbateurs et respect du seuil | `approbations.json` | **CT-1** |
| 8 | Inclusion de la transaction du registre dans un bloc certifié par un quorum | `registre.json`, `certificat-commit.json`, `validateurs.json` | CT-6 (parties produites par CT-4) |

Tant que 4, 5 et 8 ne sont pas exécutables, le verdict du vérificateur est
borné : « cet événement est bien formé, chaîné à ses voisins, inclus dans la
période close par ce manifeste signé par cette clé, et approuvé par ces
adresses » ; il ne dit rien sur la date ni sur l'ancre. Le vérificateur DOIT
énoncer cette borne dans sa sortie quand des parties sont absentes.

Révision 0.3 : quand la partie `points-de-controle.json` est présente, les
vérifications K-1 à K-9 de la section 11.4 s'ajoutent aux contrôles 2, 3, 4,
5, 6 et 8 (colonne « Contrôle de l'architecture ») ; les huit contrôles
restent huit. CT-6 (révision 0.2) fixe en un seul endroit dans quels contrôles
elles comptent, la raison de non-exécution quand la partie est absente, et la
proposition qu'elles ajoutent à l'énoncé : « couvert par un point de contrôle
horodaté au plus tard le … ; une réécriture postérieure à cet instant serait
détectée », dont la section 10.9 dit la portée exacte.

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
schéma met en échec le contrôle qui porte la partie : `dossier.json` → D-1
(sauf un `dossier.json` absent ou qui n'est pas du JSON : l'entrée est alors
inutilisable, code 2, sans verdict, CT-6 EX-4.12),
`evenement.json` → E-1, l'enveloppe de `voisins.json` → C-1 (ses événements →
E-1), `chemin.json` → M-2, `manifeste.json` → P-1, `manifeste.sig` → P-5,
`cles.json` → E-8, `approbations.json` → A-1 ; un fichier sans forme canonique
(nombre non entier, clé en double, substitut isolé) → E-2. Les contrôles qui
dépendent de la partie sont alors non exécutés, sans raison admise, et le
dossier est invalide. Le vérificateur ne reprend rien d'une partie inexploitable
dans son rapport (pas de `seq` ni de `hash` lus dans l'index à la place de
`evenement.json`).

Révision 0.3 : `points-de-controle.json` présent mais inexploitable, ou
contraire à son schéma ou à ses relations au manifeste → K-1 ; quand K-1
n'a pas réussi (en échec, ou non exécutée faute de P-1 réussie), K-2 à K-9
ne sont pas exécutées, sans raison admise (`prerequis_en_echec` dans le
rapport de CT-6, EX-5.9), y compris quand une ancre vaut `null` : la raison
admise « partie absente » d'une ancre nulle ne vaut qu'avec K-1 réussie ; le
dossier est invalide, et seul K-1 est en échec (dossiers
`invalide-k1-double-defaut` de CT-1 et de CT-6). K-4 n'est pas exécutée,
sans raison admise, quand M-3 n'a pas réussi.

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
| K-1 | (révision 0.3) `points-de-controle.json` valide contre `#/$defs/points_de_controle` (le point contre `point-de-controle-v0.schema.json`) ; `checkpoint.org_id` et `journal_id` égaux à ceux de l'événement ; `checkpoint.period_start = manifeste.period_start` ; `1 ≤ tree_size ≤ manifeste.count` ; `last_seq = manifeste.first_seq + tree_size − 1` ; `root` non nulle ; `checkpoint_ts ≥ period_start` (instants, section 3). | 3 |
| K-2 | (révision 0.3) `checkpointHash` recalculé (section 10.6) = `checkpoint_hash` déclaré. | 3 |
| K-3 | (révision 0.3) `checkpoint.sig` valide sous la clé publique `key_id` de `cles.json`, sur `P_SK ‖ C_K` ; `checkpoint_ts` dans `[valid_from, valid_to]` (bornes incluses) de cette clé ; `cles.json` inexploitable (E-8) : non exécuté, l'échec étant porté par E-8 ; clé `key_id` absente d'un `cles.json` exploitable : échec (CT-6 §5.4 ; la section 11.2 n'exige pas que `cles.json` porte la clé du point, E-8 ne porte donc pas cet échec). | 6 |
| K-4 | (révision 0.3) Couverture : `chemin.leaf_index < tree_size` (soit `seq ≤ last_seq`) et `ts` de l'événement prouvé ≤ `checkpoint_ts` (instants à la milliseconde). | 3 |
| K-5 | (révision 0.3) `consistency.first_size = tree_size`, `second_size = manifeste.count`, `first_root = checkpoint.root`, `second_root = manifeste.root` ; l'algorithme de la section 10.7 sur `(first_size, second_size, first_root, second_root, path)` accepte (preuve vide et racines égales si `tree_size = count`). | 3 |
| K-6 | (révision 0.3) `last_hash` : si l'événement de `seq = last_seq` est dans le dossier (événement prouvé ou voisin), son `hash` recalculé (E-7) = `last_hash` ; sinon, non vérifiable, signalé (comme A-4). | 2 |
| K-7 | (révision 0.3) `anchors.rfc3161` non nul : `token` décodé (base64 canonique, remplissage exact), puis vérifications T-1 à T-11 de CT-6 §9 avec `checkpoint_hash` recalculé pour empreinte attendue à la place de `periodHash` ; `null` : non exécuté, partie absente. | 4 |
| K-8 | (révision 0.3) `anchors.registry` non nul : `fingerprint = keccak256(org_id ‖ journal_id ‖ checkpoint_hash)` recalculée ; `doc_type` égal à la valeur de la table CT-4 §6.4 pour `noortrace/point-de-controle/v0` ; `contract` égal à celui du fichier d'ancres (CT-6 §12) et `chain_id` (identifiant EVM) rapporté sans être comparé, le fichier d'ancres n'en portant pas (CT-6 EX-11.25) ; inclusion de la transaction par les vérifications R- de CT-6 §11 quand `registre.json` et `certificat-commit.json` en portent l'entrée (CT-6, révision 0.2), sinon référence déclarative, signalée ; `null` : non exécuté, partie absente. | 8 |
| K-9 | (révision 0.3) `anchors.ots` non nul : `proof` décodé (base64 canonique), puis vérifications O-1 à O-7 de CT-6 §10 avec `checkpoint_hash` pour empreinte de fichier (fichier horodaté : `P_K ‖ C_K`) ; `null` : non exécuté, partie absente. | 5 |

Les contrôles des parties réservées (4, 5, 8) sont spécifiés par CT-6
(vérifications `T-`, `O-`, `R-` et `N-`) ; CT-5 et CT-4 produisent les
parties.

Les vérifications K-1 à K-9 (révision 0.3) ne s'exécutent que si la partie
`points_de_controle` est déclarée présente. Partie absente avec raison, ou
index à douze parties : les neuf ne sont pas exécutées et ne figurent pas au
rapport (alignement sur CT-6 EX-5.7 ; la partie absente figure dans
`absent_parts` quand elle est déclarée), et le verdict d'un dossier antérieur
à la révision 0.3 ne change pas. K-1 à K-6 sont exécutables avec les seules
pièces du dossier ; K-7, K-8 et K-9 réutilisent les vérifications `T-`, `R-` et
`O-` de CT-6 sur une autre empreinte que `periodHash`, avec les mêmes ancres du
réviseur, et chacune est non exécutée, raison admise, quand son ancre vaut
`null`. Une vérification K-7 réussie fournit à l'énoncé l'instant `upper_bound`
du jeton du point, borne de la fenêtre de réécriture de la section 10.9, quand
les conditions du fragment FK de CT-6 (EX-6.16) sont réunies : contrôles 1, 3
et 6 réussis, K-1 à K-5 réussies, K-6 réussie ou non exécutée pour la raison
`piece_hors_dossier` ; sans K-7 réussie, le fragment ne porte que la clause
Bitcoin (K-9) ou la clause registre (K-8 avec inclusion prouvée), et aucune
date n'est prouvée au point. CT-6 (révision 0.2) fixe la phrase et dans quels
contrôles les K- comptent.

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

Révision 0.3 : les vecteurs de la révision s'ajoutent sans changer les
quarante dossiers ci-dessus (section 17) : famille `points-de-controle/`
(séries complètes des points des trois périodes des vecteurs, hachages,
signatures, preuves de cohérence vers le manifeste), famille
`merkle/coherence.json` (preuves de cohérence entre les arbres publiés de
`merkle/arbres.json`, dont `PROOF(5, D[8])` et `PROOF(8, D[12])`, et cas
refusés : `m = 0`, `m > n`, chemin tronqué, nœud en trop, racines échangées)
et des dossiers portant la partie `points-de-controle.json`, valides et
invalides, au moins un par vérification K-1 à K-6 (K-7 à K-9 relèvent des
vecteurs de CT-6), dont `valide-seq-7-point-de-cloture` (point de clôture,
`tree_size = count`, preuve vide et racines égales, K-6 non exécutée,
`piece_hors_dossier`) et `invalide-k1-double-defaut` (membre hors schéma et
chemin tronqué : seul K-1 en échec, K-2 à K-9 non exécutées). `INDEX.md` les
décrit.

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
| Nonce RFC 3161 du jeton de l'exemple de `points-de-controle.json` (révision 0.3, section 11.2) | 64 premiers bits de `SHA-256(UTF-8("noortrace/vecteurs/v0/ct-1/nonce-tsa/point-de-controle/exemple"))`, entier non signé | `0x74a6f4979421411e` (8405674686396055838) ; autorité : clés `tsa-test` et `ac-test` de `spec/vecteurs/ct-6/rfc3161/cles`, numéro de série 1001, `genTime` `20261103135302Z` |

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
| `points-de-controle/` (révision 0.3) | séries complètes des points des trois périodes, `checkpointHash`, signatures, preuves de cohérence vers chaque manifeste, chaînage | égalité, signatures et preuves acceptées, chaînage et monotonie |
| `merkle/coherence.json` (révision 0.3) | preuves de cohérence entre les arbres publiés de `arbres.json` ; cas refusés | égalité, acceptation, refus |
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
l'événement, le manifeste et le dossier. Une modification ultérieure du
format, issue de la revue de la porte 1 ou du prototype, produit une version 1
avec ses propres préfixes de domaine (`…/v1`) ; un vérificateur v1 continue
d'accepter v0. Ce qui est délibérément laissé à v1 : les formats
d'export (section 12), l'enveloppe COSE, les hachages de bord dans le manifeste.

## 15. Ce que cette version ne couvre pas

- **La date.** Sans les contrôles 4 et 5 (CT-5), rien dans un dossier CT-1 ne
  prouve à quel moment un événement a existé ; `ts` est l'horloge de
  l'enregistreur, déclarative.
- **L'ancre et le registre.** Sans le contrôle 8 (CT-6), rien ne prouve que le
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
- **La cadence, la file et les prestataires des points de contrôle**
  (révision 0.3). CT-1 fixe le format du point, sa preuve de cohérence et les
  vérifications K- ; l'intervalle (`checkpoint_interval_s`), la production à
  la clôture et la copie des points relèvent de CT-2 ; les cadences
  d'ancrage, la file d'attente, la reprise et le choix des prestataires
  relèvent de CT-5 ; la vérification de la partie dans les contrôles et
  l'énoncé relèvent de CT-6 (révision 0.2).
- **La série des points.** Le dossier ne porte qu'un point : le chaînage,
  la monotonie et la cadence se contrôlent sur la série, hors du dossier
  (section 10.9).

## 16. Alignement avec le dépôt

Points du dépôt que cette spécification a rendus caducs, avec leur état :

| Emplacement | Avant CT-1 | Attendu par CT-1 | État |
|---|---|---|---|
| `contracts/PeriodRegistry.sol`, commentaire de `PeriodMeta.periodHash` | « keccak256 du manifeste canonique » | « SHA-256 du manifeste canonique préfixé (CT-1 §10.2) ; opaque pour le contrat » | fait |
| `scripts/e2e/dev-roundtrip.mjs`, calcul d'essai | `keccak256(canonical(manifest))`, `version: 1`, manifeste d'essai | `periodHash` de la section 10.2 (`scripts/lib/journal.mjs`), `version: 0`, manifeste conforme au schéma | fait |
| `ARCHITECTURE.md`, exemple d'événement | `sha256:…`, `sig: {alg, key_id, value}`, `arguments_hash` | Forme de la section 5 (`0x…`, `recorder_key_id` + `sig`, références) | fait |
| `ARCHITECTURE.md`, « Modèle d'événement » : le manifeste porte « les hachages de bord » | hachages de bord dans le manifeste | la version 0 n'en porte pas (section 15) : le manifeste porte la racine, `first_seq` et `last_seq` | fait |
| `ARCHITECTURE.md`, « Dossier et vérification » : le dossier contient « les hachages de ses voisins » | hachages des voisins | les voisins complets (`voisins.json`, section 11.2), dont les hachages se recalculent (C-2) | fait |
| `spec/README.md`, disposition des vecteurs | `jcs/`, `evenements/`, `chaines/`, `arbres/` (n = 0, 1, 2, 3, 5, 8) | la disposition publiée (section 13 et `spec/vecteurs/ct-1/INDEX.md`) | fait |

`scripts/lib/noortrace.mjs` ne calcule pas `periodHash` (c'est
`scripts/lib/journal.mjs` qui le fait) ; ses `periodDigest`, `registerDigest`,
`revokeDigest` et `anchorFingerprint` sont conformes à cette spécification tels
quels.

## 17. Révisions

**Version 0.1** (octobre 2026) : première rédaction, soumise à la porte 1.

**Version 0.2** (21 octobre 2026) : révision après la confrontation de
l'implémentation de référence et du vérificateur indépendant Go (section 16) :
constantes de l'exemple distinguées de celles des vecteurs (section 13), tous
les symptômes rapportés (section 7.2), famille `jcs/`, cascades listées dans
les `attendu.json` (section 11.5), renvois textuels à CT-4 et CT-6.

**Version 0.3** (25 octobre 2026). Ajouts seuls ; aucun format v0 (événement,
manifeste, dossier à douze parties, objets `A` et `R`, signatures, six
préfixes de domaine) n'est retiré ni modifié, et les quarante dossiers de la
section 11.5 gardent leur verdict et leur liste exacte de contrôles en échec :

- **Point de contrôle** (sections 10.5, 10.6) : nouveau document, tête signée
  de l'arbre de la période en cours à cadence courte (défaut 60 s, et à la
  clôture), onze clés sous le hachage et la signature dans l'objet, préfixes
  `noortrace/point-de-controle/v0\n` et
  `noortrace/signature-point-de-controle/v0\n`, règles de chaînage et de
  monotonie, dernier point égal au manifeste, point sans événement admis ;
  schéma `point-de-controle-v0.schema.json`.
- **Preuve de cohérence** (section 10.7) : algorithmes de génération et de
  vérification de la RFC 9162 §2.1.4 reproduits, cas de bord fixés,
  obligation d'exécuter l'algorithme ; exemple complet (section 10.8).
- **Partie facultative `points-de-controle.json`** (sections 11.1, 11.2) :
  treizième partie du dossier, index à douze ou treize parties, point couvrant
  l'événement, preuve de cohérence vers le manifeste, ancres embarquées en
  base64 (jeton RFC 3161, référence au registre, preuve OpenTimestamps) ;
  `dossier-v0.schema.json` étendu de façon compatible (`$defs`
  `points_de_controle`, `preuve_coherence`, `ancre_rfc3161_point`,
  `ancre_registre_point`, `ancre_ots_point`, `base64`).
- **Vérifications K-1 à K-9** (section 11.4), portée des ancres d'un point et
  fenêtre de réécriture (section 10.9), convention base64 (section 3), note de
  la section 7.2, termes (section 2), constantes et familles de vecteurs
  (sections 11.5 et 13), limites (section 15).

Alignement de la révision 0.3 avec le dépôt. « fait » : dans ce lot ; « à
faire » : attendu d'un autre lot ou d'une autre spécification, nommé ; aucune
ligne ne change de format.

| Emplacement | Avant | Attendu par la révision 0.3 | État |
|---|---|---|---|
| `spec/schemas/point-de-controle-v0.schema.json` | — | schéma du point (section 10.5), draft 2020-12, mode strict | fait |
| `spec/schemas/dossier-v0.schema.json` | douze parties exactement | index à douze ou treize parties (`oneOf` de deux tuples, mode strict), `$defs` de la partie et de ses ancres ; les 40 dossiers de CT-1 et les 50 de CT-6 restent valides | fait |
| `scripts/lib/journal.mjs` | arbre, inclusion, manifeste, dossier à douze parties | préfixes `P_K`, `P_SK` ; construction, hachage, signature et vérification d'un point ; `preuveCoherence`, `verifierCoherence` (section 10.7) ; partie `points_de_controle` (treizième, facultative) dans `indexDossier` et `verifierDossier` ; K-1 à K-6 (K-7 à K-9 dans `verificateur.mjs`, avec `horodatage.mjs`, `registre.mjs`, `ots.mjs` sur `checkpoint_hash`) ; `choisirPointCouvrant` avec les ancres (section 11.2) ; prérequis de K-2 à K-9 (section 11.4) ; registre de schémas à quatre entrées | fait (lot CT-5 ; précisions de la revue faites) |
| `scripts/vecteurs/generer-ct1.mjs`, `spec/vecteurs/ct-1/INDEX.md` | familles de la section 13 | familles `points-de-controle/` et `merkle/coherence.json`, dossiers avec la partie (section 11.5), dont `valide-seq-7-point-de-cloture` et `invalide-k1-double-defaut` ; deux générations identiques ; les entrées existantes inchangées octet pour octet | fait |
| `test/journal.test.js` | inclusion confrontée aux vecteurs de Certificate Transparency | cohérence confrontée aux mêmes vecteurs publics (section 10.7 : `(1, 1)`, `(1, 8)`, `(6, 8)`, `(2, 5)`, `(6, 7)` et leurs sondes, toute paire `1 ≤ m ≤ n ≤ 64`) ; `PROOF(1..4, D[5])`, `MTH(D[0:3])`, K1 à K6 de la section 10.8 ; exemples annotés `point-de-controle` et `points_de_controle` de ce document validés et recalculés ; rejeu de `merkle/coherence.json` et de `points-de-controle/attendu.json` ; `choisirPointCouvrant` | fait |
| `spec/vecteurs/ct-1/verificateur-independant` | douze parties exactement (`dossier.go`) ; inclusion seule (`merkle.go`) | treizième partie facultative ; point, hachage, signature ; cohérence ; K-1 à K-6 (K-7 à K-9 hors périmètre, comme les contrôles 4, 5 et 8) ; nouvelles familles de vecteurs ; aucune K- au rapport sans la partie (section 11.4, CT-6 EX-5.7) | fait |
| CT-6 (révision 0.2) | huit contrôles sans la partie ; exemples des sections 8.5 et 8.6 (empreinte de `dossier-v0.schema.json`) | vérification de la partie (K-1 à K-9) dans les contrôles, raison de non-exécution, proposition d'énoncé, section 7 ; exemple JSON de la section 8.6 à régénérer, l'empreinte du schéma de dossier ayant changé avec cette révision | fait (CT-6 révision 0.2, 2026-10-25 : §5.4, §7.9, §9.9, §10.9, §11.9, §13.4) ; exemple 8.6 à régénérer avec le code |
| CT-4 §6.4 | une ligne (`noortrace/periode/v0`) | ligne `noortrace/point-de-controle/v0` = `0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178`, ancre d'un point de contrôle (section 11.2) | fait (CT-4 révision 0.3, texte : table de §6.4 et EX-6.6 ; constante des bibliothèques faite ; vecteur `doctypes.json` et `ancrer --point` à faire, CT-5 §9.5) |
| CT-5 | — | production des ancres des points (registre, RFC 3161 au plus toutes les 300 s par défaut, OpenTimestamps), file d'attente et reprise sans bloquer l'agent, conservation, contraintes des prestataires, formule de coût | fait (CT-5 version 0.2, 2026-10-26) ; code et vecteurs faits |
| CT-2 | pas de point de contrôle ; contresignature interne « à la minute » de l'architecture non formatée | production des points (`checkpoint_interval_s`, alignement, clôture), série `points/periode-<period_start>.ndjson`, copie WORM des points avec les segments (§12.6) | fait (CT-2 révision 0.4, 12.10) ; code de l'enregistreur à faire |
| `spec/README.md` | CT-1 version 0.2 ; table des schémas sans le point ; commandes `ajv` sans `-r point-de-controle-v0.schema.json` | CT-1 version 0.3 ; ligne du schéma du point ; `-r spec/schemas/point-de-controle-v0.schema.json` dans toute commande qui charge le schéma de dossier (le schéma de dossier le référence par son `$id`) | fait (index et vecteurs) |
| `README.md`, `README.fr.md`, `ARCHITECTURE.md`, `CHANGELOG.md` | « contresignature interne à la minute en option » ; fenêtre de réécriture « une heure » | point de contrôle formaté par CT-1 0.3 et ancré par CT-5 ; fenêtre bornée au point (section 10.9) ; révision 0.3 au journal des changements | à faire (documents racine) |

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
| `P_K` (point de contrôle, révision 0.3) | `6e6f6f7274726163652f706f696e742d64652d636f6e74726f6c652f76300a` |
| `P_SK` (signature de point de contrôle, révision 0.3) | `6e6f6f7274726163652f7369676e61747572652d706f696e742d64652d636f6e74726f6c652f76300a` |
| `checkpointHash` K1 … K6 (section 10.8) | `0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4`, `0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff`, `0x3feb86ac4d6d8c054bef224f131f0276d2f1c9c9db2a6ce06adec173378d8867`, `0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107`, `0x3c4bd86148138e52a1ef6912c7ab4fa98ffdaf90879900887833e726b5a9e153`, `0xd6e22871885b68962dadee69f9fa2ff3a76949d23550d1682d3564bcc705474d` |
| `docType` `noortrace/point-de-controle/v0` | `0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178` |
| `anchorFingerprint` du point K2 | `0x7f721a4526c614882ff41ac33792c6d05fa7fb6dd98bc1c369d0e277029f4e44` |

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
