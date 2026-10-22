# Vérificateur indépendant CT-2 (Go, salle blanche)

Un second vérificateur des vecteurs de [CT-2](../../../CT-2-enregistreur.md),
écrit en Go depuis la seule spécification (CT-2, et CT-1 pour les
événements), sans lire ni reprendre le code JavaScript de `scripts/` ni de
`test/`. Il recalcule tout ce que les vecteurs de `spec/vecteurs/ct-2`
déclarent, famille par famille selon l'annexe B, et confronte chaque valeur.
Deux implémentations écrites séparément qui tombent sur les mêmes octets
rendent les vecteurs probants ; une discordance désigne une ambiguïté de la
spécification ou une faute de l'une des deux.

Module propre `noortrace-ct2` (`go 1.24`), bibliothèque standard uniquement.
Le module CT-1 (`spec/vecteurs/ct-1/verificateur-independant`) n'est pas
modifié : son code est **copié** ici (fichiers `ct1_*.go`, lui-même écrit sans
le JavaScript), avec trois adaptations signalées en tête des fichiers :
`ct1_json.go` retient la position en octets de chaque valeur (pour comparer
les octets relayés, EX-4.20), `ct1_rapport.go` a un titre paramétrable et un
libellé général pour les valeurs hors périmètre, `ct1_reference_test.go` lit
les vecteurs CT-1 dans `../../ct-1` (le test prouve que la copie est fidèle).

## Usage

```bash
cd spec/vecteurs/ct-2/verificateur-independant
go build -o verificateur .
./verificateur ..                 # rapport texte, code 0 si tout concorde
./verificateur -v ..              # liste aussi les valeurs concordantes et les contrôles CT-1
./verificateur -json .. > rapport.json
./verificateur -strict ..         # verdicts de chaîne : égalité exacte des contrôles en échec
go test ./...                     # tests propres au module (voir plus bas)
```

`go build` sans `-o` produit `noortrace-ct2` ; `noortrace-ct2` et
`verificateur` sont exclus par le `.gitignore` local.

Codes de retour : `0` tout concorde (les valeurs hors périmètre sont
énoncées, avec leur raison, et ne comptent pas) ; `1` au moins une
discordance ou une erreur (fichier absent ou illisible, famille de l'annexe B
manquante) ; `2` usage incorrect ou racine introuvable.

Le rapport dit, pour chaque valeur : la famille, le vecteur, la grandeur,
l'**attendu** (la valeur déclarée par le vecteur, ou, pour un contrôle de
cohérence, la valeur que la spécification exige) et l'**obtenu** (la valeur
recalculée, ou constatée). Si la spécification se trouve à côté des vecteurs
(`../../CT-2-enregistreur.md`), la période de démonstration y est relue
(ligne « Période de démonstration » de l'annexe B).

## Ce qui est recalculé

| Famille | Fichiers lus | Valeurs recalculées et confrontées |
|---|---|---|
| constantes | — | `org_id = keccak256("assureur-demo")`, clé de pseudonymisation de test, cohérence des deux écritures de la période de démonstration |
| jcs-integral | `cas.json` | JCS intégral (RFC 8785, 8.1) de chaque texte d'entrée, ou refus (`null`) ; couverture de la table 1 de la RFC 8785 (note) |
| redaction | `politique-pii-v1.json`, `politique-pseudonyme-test.json`, toute autre `politique-*.json`, `motifs.json`, `cas.json` | octets du bloc imprimé en 10.9, longueur et SHA-256 du JCS intégral de `pii-v1` (10.6), forme d'EX-10.6 (sous-ensemble commun des motifs compris) ; `politique-pseudonyme-test.json` = `pii-v1` modifiée comme B.3 le dit (règle `iban-champ` en tête, `encoding: "hex"`) ; chaque motif de `motifs.json` admis ou refusé (EX-10.6) ; pour chaque cas : pièce rédigée (octets, `sha256`, `length`, `redacted`), décomptes `matches` (EX-10.17), idempotence (EX-10.15) |
| pieces-mcp | `appels/<cas>/{hote,amont}.jsonl`, `attendu.json` ; `agregation/**/{serveurs,attendu}.json` | lecture de la requête (4.4 pas 1 : CR, JSON strict, lot, EX-4.44) et refus ; nom annoncé, nom d'origine, alias ; pièces « arguments », « résultat » (forme `noortrace_jsonrpc_error` comprise, résultat non objet), « définition » servie et « liste annoncée » (depuis le `tools/list` de `hote.jsonl`), `context` (EX-4.45), classe ; `is_error`, `duration_ms` (EX-4.48), `error_rendered`, messages fixes (EX-4.24) ; octets de `params.arguments` relayés = octets reçus sans blancs (EX-4.20, EX-4.43), lignes sans CR ni LF ; `id` rendu recopié depuis le texte de l'hôte ; identité `clientInfo`/`serverInfo` ; résultat rendu = résultat amont aux réécritures près (4.4 pas 14) ; ères de protocole ; `timeout_ms`, `limits` ; agrégation : noms annoncés, classes, rejets et raisons d'EX-4.11, pages, `definition_sha256`, normalisations, refus de configuration |
| pieces-modele | `<fournisseur>-<cas>/{requete.json ou requete.brut, requete-entetes.json, reponse.json ou reponse.sse, reponse-entetes.json, attendu.json}` | refus d'une requête non analysable (EX-5.7) ; analyse SSE (5.4.1), invariance à la fragmentation, forme consolidée (5.4.2 à 5.4.4, EX-5.27) ; type de média (5.3.1 pas 5) ; pièces « requête » (prompt remplacé par `[REDIGE:prompt-systeme]` ou rédigé en place, EX-8.5), « réponse » (forme `noortrace_http_error` ou pièce non JSON d'EX-8.7 comprises), « prompt système » ; `code_model`, `prompt_version`, `intent` (tiré de la réponse rédigée, chaîne ou référence), `tool_calls`, `is_error`, `incomplete`, `route`, `status` |
| evenements | `journal-demo/{evenements,attendu,pieces,cles,politique,entrees}.json`, `segment.ndjson`, `intentions.ndjson`, dossiers | contrôles CT-1 E-1 à E-8, E-10, E-11, C-1 à C-3 (code CT-1) et verdict ; `hash`, `sig`, `prev_hash`, longueur canonique ; `JCS(A)`, `D_A` ; séquence de 19.2 ; `policy_sha256` (JCS intégral de `politique.json`) ; références de pièces (E-6), JCS intégral et idempotence de chaque pièce rédigeable, `policy.redaction` (EX-10.20) ; segment octet par octet ; journal d'intention (neuf clés, `intent_id` et époque, `upstream_id`, `host`, référence des arguments, `intention_sha256`, contexte, levée) ; pièces et grandeurs des échanges depuis `entrees.json` ; corrélation sur les valeurs en clair (EX-5.22) et reprise de l'appel retenu (EX-7.12) ; `context` des appels (EX-4.45) ; effets (EX-7.6) ; erreur `-32015` rendue ; période ; dossiers CT-1 (contrôles 1, 2, 3, 6) |
| index | `INDEX.md` | `journal_id`, clé de test, nonces imprimés, familles décrites |

Briques propres à CT-2 : JCS intégral (nombres par la règle ES6
`Number::toString` sur la double la plus proche, `strconv.FormatFloat` en
précision `-1` remis en forme ; `encoding/json` n'est pas utilisé pour la
sortie canonique), les cinq détecteurs de 10.3 au caractère près (segments
entre jetons, fin de correspondance valant frontière, lectures bornées pour
l'adresse électronique), passages jusqu'au point fixe (EX-10.14), motifs
nommés (paquet `regexp`, RE2) et vérification du sous-ensemble commun
d'EX-10.6, actions `remplacer`, `pseudonyme` (HMAC-SHA-256, clé décodée selon
son `encoding`), `supprimer`, pointeurs RFC 6901, lecture d'une requête d'hôte
(4.4 pas 1), analyseur SSE incrémental, trois réassemblages, extraction de
5.5.

## Conventions de lecture

Chaque choix est fait depuis le texte de CT-2 ; il est rappelé dans le
rapport quand il porte sur une valeur.

1. **Transcriptions (B.4).** Dans `hote.jsonl`, `in` est reçu de l'hôte et
   `out` rendu à l'hôte ; dans `amont.jsonl`, `out` est envoyé au serveur et
   `in` reçu de lui ; `{"dir":"in","t":…,"eof":true}` est la fin de fichier
   de la sortie standard du serveur. L'échange `tools/list` vient d'abord ;
   la requête examinée est la ligne `in` suivante, la réponse rendue la
   ligne `out` qui la suit. `transports.host: "http"` désigne un corps POST,
   où un CR est un blanc.
2. **Pièce « résultat » sans réponse exploitable.** Une erreur de
   l'enregistreur rendue à l'hôte (`-32011`, `-32012`, `-32013` côté réponse,
   `-32014`) prime sur une réponse amont tardive ou tronquée ; la pièce est
   `{"noortrace_jsonrpc_error": <erreur rendue>}` (8.2, EX-4.22, EX-4.48).
3. **`duration_ms` (EX-4.48).** Délai : `t_envoi + timeout_ms`, instant de
   l'annulation amont ; serveur injoignable : instant de la fin de fichier ;
   taille : instant de la ligne qui dépasse la borne ; sinon la réponse.
4. **Définition courante (EX-4.45).** Les transcriptions ne portent que la
   liste servie : une `definition_current` non nulle n'est contrôlée que dans
   sa cohérence (JCS intégral, `sha256`, `name`, différence avec la
   définition servie) ; elle donne alors la classe et entre dans `context`.
5. **Classe d'outil.** Sans configuration dans les vecteurs `pieces-mcp`, la
   classe vient de `readOnlyHint` de la définition courante (EX-4.17) ; dans
   `evenements`, de `politique.json` (`servers.<alias>.tools.<nom>.class`,
   puis `class_default`), à défaut `ecriture`.
6. **Refus de configuration (agrégation sans préfixe, deux serveurs).** Clé
   `configuration_refusee` (et quelques graphies voisines).
7. **Pièce texte dans `redaction/cas.json`.** Pièce texte si la portée est
   `prompt_systeme` ou si le cas (ou `expected`) déclare un `media_type`
   `text/*` ; sinon pièce JSON.
8. **Décomptes `matches`.** Triplets de nombre non nul, additionnés sur les
   passages, comparés sans ordre ; un détecteur `regex` ou `champ` est
   reconnu sous `regex`, son nom ou `regex:<nom>` (de même `champ`).
9. **Politiques supplémentaires.** Toute `redaction/politique-*.json` est
   chargée et nommée par son `name`.
10. **Clé de pseudonymisation.** Variable d'environnement décodée selon
    l'`encoding` de la référence ; à défaut, pour la variable des vecteurs,
    la clé de test de l'annexe B.
11. **Format de `attendu.json` de `evenements`.** `events` (B.6) ou `hashes`
    (forme de `ct-1/journal-valide`) ; `A` et `D_A` au premier niveau ou sous
    `approbation`. Les clés supplémentaires présentes (`correlation`,
    `period`, `segment_sha256`, …) sont confrontées.
12. **Nonce de période.** `N = 1` pour la première période du journal.
13. **Dossiers.** Tout répertoire sous `evenements/` qui porte un
    `dossier.json` est vérifié par le code CT-1 ; verdict attendu : son
    `attendu.json`, sinon valide.

## Constats des confrontations, corrigés dans la spécification

- Annexe B, période de démonstration : `[1794304800, 1794308400)`
  (2026-11-10T10:00:00Z → 11:00:00Z) ; l'ancienne valeur désignait le
  2026-11-07.
- B.3, B.4, B.5, B.6 décrivent toutes les entrées des vecteurs
  (`politique-regles-test.json`, `motifs.json`, `reponse-entetes.json`,
  `requete.brut`, `entrees.json`, échange `tools/list`, enveloppe `eof`,
  `protocols`, `transports`, `context`, `options`, `refused`).
- 10.3.5 : le point final d'une phrase n'appartient pas au domaine ; une
  adresse qui le précède est rédigée. La recherche est bornée autour de
  chaque `@` (coût linéaire).
- EX-4.11 fixe le vocabulaire des raisons de rejet, confronté désormais.
- La corrélation (EX-5.22) se recalcule sur les valeurs en clair publiées
  dans `entrees.json`, et non plus sur les pièces rédigées.

## Limites

- **Signatures EIP-191 des approbateurs** (contrôle 7, E-9) : hors
  périmètre, comme dans le vérificateur CT-1 (secp256k1 n'est pas dans la
  bibliothèque standard). Contrôles 4, 5 et 8 des dossiers (CT-4, CT-5) : non
  exécutables, verdict borné.
- **Validation de schéma** : pas de validateur JSON Schema générique ; la
  forme des événements est celle transcrite par le code CT-1, celle des
  politiques se limite aux règles d'EX-10.6.
- **Motifs nommés** : sémantique RE2 du paquet `regexp`, après vérification
  du sous-ensemble commun d'EX-10.6.
- **Décodage UTF-8 du flux SSE** : un octet invalide donne un U+FFFD par
  octet, pas par sous-partie maximale comme l'algorithme WHATWG ; sans effet
  sur un flux UTF-8 valide.
- **Longueurs en caractères** (`intent` de 4096, `code.model` de 256) :
  comptées en points de code.
- **Nombres hors de la double précision finie** (`1e400`) : refusés (RFC 8785
  §3.2.2.3), là où `JSON.stringify` écrirait `null`.

## Tests du module (`go test`)

- RFC 8785 (lue sur rfc-editor.org) : les 26 lignes de la table 1 de
  l'annexe B (sérialisation et relecture bit à bit), l'exemple de 3.2.2 à
  3.2.4 (octets UTF-8), le jeu de tri de 3.2.3, l'annexe E ; NaN, Infinity,
  débordement refusés ; cas obligatoires de B.2 ; table des nombres de 8.1.
- Détecteurs : exemples valides et invalides de 10.3.2 à 10.3.6 (IBAN suisse
  et Pay.UK, reste 28, AVS de l'ordonnance, Luhn, adresses de 64 et 65
  octets, adresse suivie d'un point ou d'un trait d'union, coût linéaire,
  téléphones de 15 et 16 chiffres, numéros collés, groupes entre
  parenthèses) ; onze IBAN construits par la méthode de génération de
  10.3.2 ; frontières, séparateurs, jetons jamais détectés ; règles `champ`,
  `supprimer`, pointeurs, motif nommé ; passages jusqu'au point fixe, jetons
  opaques, `champ` sur un jeton, pseudonyme d'une chaîne ; décodage des
  secrets ; sous-ensemble commun d'EX-10.6 ; collision après normalisation.
- Lecture d'une requête d'hôte (EX-4.43, EX-4.44) : nombres exacts, CR,
  lot, corps HTTP, id au-delà de 2^53, blancs retirés.
- Valeurs imprimées par CT-2 (`testdata/spec`, blocs extraits du document) :
  exemples de 10.9 (96 et 148 octets), pseudonymes de test, empreintes de
  `pii-v1` et de l'ensemble de politique de 15.3, annexe A (définition,
  liste annoncée, résultat, ligne intention à neuf clés, événements seq 2 et
  4 et leur `context`, ligne de segment, octets relayés).
- SSE : règles de 5.4.1, fragmentation en toute position, octet par octet et
  aléatoire (graine fixe) ; formes consolidées des trois fournisseurs,
  flux incomplets, JSON d'outil invalide, erreur en flux, données
  malformées (EX-5.27) ; extraction de 5.5.
- Agrégation, transcriptions ; arborescence synthétique complète dans la
  disposition de l'annexe B (dont les valeurs imprimées par la
  spécification), puis altération d'un octet du segment.
- Code CT-1 copié : ses tests, et les vecteurs publiés de `ct-1` (tout doit
  concorder).
