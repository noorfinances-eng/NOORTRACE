# Vérificateur indépendant CT-2 (Go, salle blanche)

Un second vérificateur des vecteurs de [CT-2](../../../CT-2-enregistreur.md)
(révision 0.5), écrit en Go depuis la seule spécification (CT-2, et CT-1 pour
les événements), sans lire ni reprendre le code JavaScript de `scripts/` ni
de `test/`. Il recalcule tout ce que les vecteurs de `spec/vecteurs/ct-2`
déclarent, famille par famille selon l'annexe B, et confronte chaque valeur.
Deux implémentations écrites séparément qui tombent sur les mêmes octets
rendent les vecteurs probants ; une discordance désigne une ambiguïté de la
spécification ou une faute de l'une des deux.

Module propre `noortrace-ct2` (`go 1.24`), bibliothèque standard uniquement.
Le module CT-1 (`spec/vecteurs/ct-1/verificateur-independant`) n'est pas
modifié : son code est **copié** ici (fichiers `ct1_*.go`, lui-même écrit sans
le JavaScript), à jour de la révision 0.4 de CT-1 (point de contrôle, preuve
de cohérence, treizième partie du dossier, K-1 à K-6 ; quatorzième partie
facultative `attestation-perimetre.json` et AT-1 à AT-7, `ct1_attestation.go`
et `ct1_attestation_test.go`, avec la courbe secp256k1 que le module CT-1
copie sans modification du vérificateur de `ct-3`, `ct1_secp256k1.go`), avec
trois adaptations signalées en tête des fichiers : `ct1_json.go` retient
la position en octets de chaque valeur (pour comparer les octets relayés,
EX-4.20), `ct1_rapport.go` a un titre paramétrable et un libellé général
pour les valeurs hors périmètre, `ct1_reference_test.go` et
`ct1_point_test.go` lisent les vecteurs CT-1 dans `../../ct-1` (ces tests
prouvent que la copie est fidèle).

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
| redaction | `politique-pii-v1.json`, `politique-pseudonyme-test.json`, toute autre `politique-*.json`, `motifs.json`, `cas.json` | octets du bloc imprimé en 10.9, longueur et SHA-256 du JCS intégral de `pii-v1` (10.6), forme d'EX-10.6 (sous-ensemble commun des motifs et règles de structure et de taille compris) ; `politique-pseudonyme-test.json` = `pii-v1` modifiée comme B.3 le dit (règle `iban-champ` en tête, `encoding: "hex"`) ; chaque motif de `motifs.json` admis ou refusé (EX-10.6, sous-ensemble commun, quantificateurs sans zéro non significatif, puis règles a) à c) : aucune répétition imbriquée ou ambiguë, aucun groupe quantifié qui peut être vide, taille développée d'au plus 1 000), la règle qui le refuse égale à celle que nomme `note`, la première correspondance de chaque texte de `matches` (paquet `regexp`, motif tel quel), les motifs exigés par B.3 (quatre motifs d'OWASP et les six autres refusés, trois quantificateurs à zéro non significatif refusés, `[0-9]+$`, un groupe `(?P<nom>…)` et quatre motifs à « (?P< » admis), aucun attendu de durée ; pour chaque cas : pièce rédigée (octets, `sha256`, `length`, `redacted`), décomptes `matches` (EX-10.17), idempotence (EX-10.15) |
| pieces-mcp | `appels/<cas>/{hote,amont}.jsonl`, `attendu.json` ; `agregation/**/{serveurs,attendu}.json` | lecture de la requête (4.4 pas 1 : CR, JSON strict, lot, EX-4.44) et refus ; nom annoncé, nom d'origine, alias ; pièces « arguments », « résultat » (forme `noortrace_jsonrpc_error` comprise, résultat non objet), « définition » servie et « liste annoncée » (depuis le `tools/list` de `hote.jsonl`), `context` (EX-4.45), classe ; `is_error`, `duration_ms` (EX-4.48), `error_rendered`, codes et messages fixes de la table de 4.4 (`-31010` à `-31017`, `-31015` non attribué) et codes admis par EX-4.24 pour toute erreur rendue par l'enregistreur lui-même (ni `-32000` à `-32099` hors `-32020` à `-32022`, ni `-32002`, `-32042`, `100` à `599`) ; `approval` et `result_rendered` (`null` pour un appel relayé) ; cas d'approbation (B.4) : réponse d'`evaluer` simulée parmi les combinaisons d'EX-7.16, issue sans relais (aucune ligne amont, pièce « arguments » du pas 4, `pieces.result`, `is_error`, `duration_ms` et `error_rendered` nuls), résultat rendu par l'enregistreur (EX-4.49 : refus par la politique ou signal d'approbation, texte fixe, `_meta` `serverInfo` et `noortrace/approval`, `resultType` pour l'ère moderne seulement, sans `structuredContent` ni nom de règle), ligne rendue octet pour octet (membres dans l'ordre des exemples, `id` recopié), cas obligatoires `approbation-refus` (hôte moderne) et `approbation-en-attente` (hôte hérité) ; octets de `params.arguments` relayés = octets reçus sans blancs (EX-4.20, EX-4.43), lignes sans CR ni LF ; `id` rendu recopié depuis le texte de l'hôte ; identité `clientInfo`/`serverInfo` ; résultat rendu = résultat amont aux réécritures près (4.4 pas 14) ; ères de protocole ; `timeout_ms`, `limits` ; agrégation : noms annoncés, classes, rejets et raisons d'EX-4.11, pages, `definition_sha256`, normalisations, refus de configuration |
| pieces-modele | `<fournisseur>-<cas>/{requete.json ou requete.brut, requete-entetes.json, reponse.json ou reponse.sse, reponse-entetes.json, attendu.json}` | refus d'une requête non analysable (EX-5.7) ; analyse SSE (5.4.1), invariance à la fragmentation, forme consolidée (5.4.2 à 5.4.4, EX-5.27) ; type de média (5.3.1 pas 5) ; pièces « requête » (prompt remplacé par `[REDIGE:prompt-systeme]` ou rédigé en place, EX-8.5), « réponse » (forme `noortrace_http_error` ou pièce non JSON d'EX-8.7 comprises), « prompt système » ; `code_model`, `prompt_version`, `intent` (tiré de la réponse rédigée, chaîne ou référence), `tool_calls`, `is_error`, `incomplete`, `route`, `status` |
| pieces-modele, cas `gemini-*` (révision 0.5) | `gemini-<cas>/{requete-ligne.json, requete.json ou requete.brut, requete-entetes.json, reponse.json ou reponse.sse, reponse-entetes.json, attendu.json}` ; `gemini-sdk-*/{requete.json, reponse-morceaux.json, attendu.json}` | normalisation du chemin (EX-5.2), route de collection, segment de modèle et méthode (EX-5.28), chaîne de requête interprétée et raison du refus dans l'ordre d'examen (`cle_dans_url`, `flux_sans_sse`, `parametre_non_admis`, EX-5.29), corps AIP-193 exact et `Content-Type` du refus (EX-5.30), refus `corps_non_analysable` (EX-5.7) et `serveurs_mcp_fournisseur` (EX-5.32), `404` sans corps (`route_inconnue`) ; cible reconstruite vers l'amont (`upstream_target`) ; `data` final sans ligne vide distribué (EX-5.34), invariance à la fragmentation ; forme consolidée d'EX-5.35 (membres de premier niveau remplacés, candidats par `index` admis créés dans l'ordre d'apparition, parts ajoutées sans fusion, morceau d'erreur, fin normale par `finishReason` ou `promptFeedback`) ; réponse d'erreur analysée en JSON quel que soit le `Content-Type` (EX-5.31) ; pièces « requête » (`systemInstruction.parts` remplacé par `[{"text":"[REDIGE:prompt-systeme]"}]` ou rédigé en place, EX-8.5), « réponse », « prompt système » (colonne Gemini de 5.5) ; `code_model` (`modelVersion` de la réponse rédigée, à défaut segment du chemin passé aux détecteurs, EX-5.36 ; pour le SDK, `request.model` privé de `models/`, EX-6.8) ; `intent` (parts sans `thought: true`, sans séparateur) ; `tool_calls` (parts `functionCall` de `candidates[0]`, `id` ou `null`, `args` ou `{}`) ; membres retirés par EX-6.8 pas 3 (`removed_members`) ; `request_line`, `model_segment`, `via`, `refused`, `status` |
| otel (révision 0.5) | `<cas>/{source.json, requete.json ou requete.pb ou requete.brut, requete-entetes.json, attendu.json}` | chemin, méthode, jeton, type de contenu, codage (`gzip` décomprimé sous la borne, autre codage `415`), bornes avant et après décompression (EX-6.26 à EX-6.28) ; décodage JSON strict d'EX-6.29 (champs inconnus et noms snake_case ignorés, `null` = absent, identifiants hexadécimaux, énumérations en nombre, entiers 64 bits lus sur leur texte, `doubleValue` et ses trois chaînes, base64 des quatre variantes, `AnyValue` à un membre au plus, `keyStrindex` sans `key`) et protobuf d'EX-6.30 (décodeur écrit pour ce module : types de fil, étiquette 0, varint de plus de dix octets, longueurs, champ non répété en double, `oneof`, UTF-8, `bool_value`, champs inconnus sautés) ; statut et corps exacts de la réponse en JSON et en protobuf, `retry_after` (EX-6.27) ; forme normalisée (EX-6.31 : première occurrence d'une clé gardée, entiers au-delà de 2^53 − 1 en chaîne, attributs de contenu analysés) ; classification et raisons (EX-6.32), `rejected_spans`, comptes par issue ; doublons depuis `seen` et dans la requête (EX-6.33) ; recouvrements depuis `recorded` (groupe d'hôte, fenêtre, plus ancien non apparié, nom `N` ou modèle `M`, `overlap_seq`, EX-6.34) ; pièces de déclaration de source, d'enveloppe, « requête », « réponse », « prompt système », « intention », « arguments », « résultat » par réapplication de `pii-v1` (EX-6.35) ; événement complet (EX-6.36 : délégation et `run_id` passé au motif d'EX-7.2 et aux détecteurs, `code.model` `<fournisseur>/<M>` ou `inconnu/<M>`, `intent`, `policy`, nom d'outil ou `nom-invalide`, `duration_ms`, `is_error`, effets par gabarit ou effet par défaut, `context`, `policy.redaction`), `hash` et `sig` Ed25519 recalculés avec la clé de test `rec-test-01`, chaîne depuis `chain` ; événement attendu passé aux contrôles E-1 à E-8 et C-1 à C-3 du code CT-1 ; `lag_ms` ; paires JSON et protobuf identiques ; valeurs imprimées par 6.8.16 (neuf pièces, deux `hash`, deux `sig`, hash précédent) ; cas obligatoires de B.8 |
| worm (révision 0.5) | `requetes.json`, `etats.json`, `perimetres.json`, `gardes.json` | requêtes exactes d'EX-12.39 (cible encodée octet par octet, `/` gardé dans le chemin S3 et Azure, `%2F` dans le nom GCS, en-têtes triés, corps XML de S3, `Content-MD5` RFC 1864, longueur, SHA-256 ; constantes imprimées par EX-12.39) ; contrôle du verrou d'EX-12.33 (mode, échéance RFC 3339 ou IMF-fixdate ramenée à CT-1 §3, `echeance_courte` sous `copied_at + retain_days − 1 h`, gel, raisons et notes, verdict ; `retain_until_min` recalculé depuis l'exemple d'EX-12.29) ; périmètre d'EX-12.35 (manifestes, signature, série de points, ancres, segments de toutes époques, pièces copiées, versions retenues, anomalies, liste triée par octets, empreinte ; exemple imprimé de 673 octets) ; empreintes des enregistrements et règle de garde d'EX-12.38 (neuf codes, une erreur par rang et par règle) ; empreintes imprimées en 12.11 et 811 octets de `0001-pose` ; cas obligatoires de B.9 |
| cout-agent (révision 0.5) | `cas.json` | formule d'EX-16.4 ligne par ligne en double précision, arrondi d'EX-16.5 ; colonne `C` de la table de 16.4 ; renvoi de B.10 au `cost_per_journal` de `ct-5/cout/cout.json` ; neuf cas obligatoires |
| evenements | `journal-demo/{evenements,attendu,pieces,cles,politique,entrees}.json`, `segment.ndjson`, `intentions.ndjson`, dossiers | contrôles CT-1 E-1 à E-8, E-10, E-11, C-1 à C-3 (code CT-1) et verdict ; `hash`, `sig`, `prev_hash`, longueur canonique ; `JCS(A)`, `D_A` ; séquence de 19.2 ; `policy_sha256` (JCS intégral de `politique.json`) ; références de pièces (E-6), JCS intégral et idempotence de chaque pièce rédigeable, `policy.redaction` (EX-10.20) ; segment octet par octet ; journal d'intention (neuf clés, `intent_id` et époque, `upstream_id`, `host`, référence des arguments, `intention_sha256`, contexte, levée) ; pièces et grandeurs des échanges depuis `entrees.json` ; corrélation sur les valeurs en clair (EX-5.22) et reprise de l'appel retenu (EX-7.12) ; `context` des appels (EX-4.45) ; effets (EX-7.6) ; signal d'approbation rendu pour chaque `retenue` (`result_rendered_seq_<seq>`, mode `erreur` de `politique.json`, ère de la requête d'`entrees.json`, EX-4.49 ; `error_rendered_seq_` de la version 0.2 refusé) ; période ; dossiers CT-1 (contrôles 1, 2, 3, 6) |
| index | `INDEX.md` | `journal_id`, clé de test, nonces imprimés, familles décrites, chaque cas de `pieces-mcp/appels` listé (B.7) ; révision 0.5 : familles `otel/`, `worm/`, `cout-agent/` décrites, chaque cas `otel/` et `gemini-*` listé, bucket, préfixe et période de `worm/`, mention des unités symboliques, table `C` et `C_J` de `cout-agent/` recalculée |

Briques propres à CT-2 : JCS intégral (nombres par la règle ES6
`Number::toString` sur la double la plus proche, `strconv.FormatFloat` en
précision `-1` remis en forme ; `encoding/json` n'est pas utilisé pour la
sortie canonique), les cinq détecteurs de 10.3 au caractère près (segments
entre jetons, fin de correspondance valant frontière, lectures bornées pour
l'adresse électronique), passages jusqu'au point fixe (EX-10.14), motifs
nommés (paquet `regexp`, RE2) et vérification du sous-ensemble commun
d'EX-10.6 et de ses règles de structure et de taille (analyse descendante
qui calcule, pour chaque groupe, la présence d'un quantificateur ou d'une
alternative, celle d'un élément qui consomme un caractère, et la taille
développée), actions `remplacer`, `pseudonyme` (HMAC-SHA-256, clé décodée selon
son `encoding`), `supprimer`, pointeurs RFC 6901, lecture d'une requête d'hôte
(4.4 pas 1), analyseur SSE incrémental, trois réassemblages, extraction de
5.5 ; résultats rendus par l'enregistreur (EX-4.49), sérialisés dans l'ordre
de leurs membres, et classement d'une réponse d'`evaluer` (EX-7.16).
Révision 0.5 : route et chaîne de requête Gemini, réassemblage Gemini
(`gemini.go`) ; décodeurs OTLP JSON et protobuf sans bibliothèque protobuf,
forme normalisée et réponses (`otel.go`), pièces, événements et signature
Ed25519 d'un span (`famille_otel.go`, `crypto/ed25519`) ; décompression
`gzip` bornée (`compress/gzip`) ; requêtes WORM, `Content-MD5`
(`crypto/md5`, `encoding/base64`), contrôle du verrou, périmètre et règle
de garde (`famille_worm.go`) ; formule du coût (`famille_cout.go`).

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
   l'enregistreur rendue à l'hôte (`-31011`, `-31012`, `-31013` côté réponse,
   `-31014`) prime sur une réponse amont tardive ou tronquée ; la pièce est
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
14. **Cas de `pieces-mcp` sans échange amont.** B.4 dit que les cas
    d'approbation sont rendus en mode d'attente `erreur`, celui de la
    configuration de référence (CT-3 EX-11.1) ; `attendu.json` ne porte pas
    de membre `mode`. Quand `amont.jsonl` est vide (refus au pas 1, cas
    d'approbation sans relais), `protocols.server` est déclaratif (B.4) :
    hors périmètre ; `protocols.host` est lu sur la requête de l'hôte, ou,
    pour un refus au pas 1 dont la requête est illisible, sur sa requête
    `tools/list`.
15. **Erreur rendue par l'enregistreur lui-même (EX-4.24).** Une erreur du
    pas 1, une erreur `-31011` à `-31014` qui remplace la réponse amont, ou
    toute erreur dont le `message` commence par `noortrace:` ; une erreur
    relayée du serveur garde son code.
16. **`result_rendered_seq_<seq>` (B.6).** Comparé comme valeur JSON
    (« l'objet `result` de la ligne rendue ») ; l'ordre des membres, qui ne
    vaut que pour les octets rendus à l'hôte, est vérifié sur les lignes de
    `pieces-mcp`.
17. **Routes Gemini (B.5).** Les deux routes de collection `/v1beta/models`
    et `/v1/models` sont configurées, de libellé `gemini`, `provider_mcp`
    absent (`refuser`) ; le `Content-Type` d'un refus est
    `text/event-stream` pour un `streamGenerateContent` qui porte un
    paramètre `alt` de valeur `sse` (même refusé pour une autre raison),
    `application/json; charset=UTF-8` sinon (EX-5.30).
18. **Échange déclaré par le SDK (`gemini-sdk-*`).** `status` est un
    paramètre d'`echangeModele` que les fichiers d'entrée de B.5 ne portent
    pas : il est lu dans `attendu.json` comme valeur déclarée ; un tableau
    `response` est consolidé par EX-5.35, fin du tableau = fin normale.
19. **Forme d'erreur réduite (EX-5.35 pas 2).** Un morceau d'erreur reçu
    avant tout morceau valide donne `{"noortrace_erreur_flux": …}`, puis le
    pas 6 s'applique tel qu'écrit (`noortrace_flux_incomplet: true`, aucun
    candidat ni `promptFeedback`) ; aucun vecteur ne porte ce cas.
20. **Ordre des refus OTLP.** Chemin (`404`), méthode (`405`), jeton
    (`401`, tout `token_id` non nul désigne un jeton de la source, B.8),
    type de contenu ou codage (`415`), borne avant puis après décompression
    (`413`), décodage (`400`) ; un `gzip` illisible est un corps non
    décodable. Les quotas (`429`) et le mode dégradé (`503`) n'ont pas de
    vecteur.
21. **Recouvrement (EX-6.34).** `seen` et `recorded` sont relus comme la
    table des doublons et le registre de recouvrement de la source ; une
    entrée de `seen` compte si `at` est dans `[t_reception −
    dedup_window_ms, t_reception]`. Le modèle `M` d'un span d'inférence est
    celui d'EX-6.36 (pièces rédigées), calculé avant la décision ; le nom
    `N` d'un span d'outil est le nom déclaré d'EX-6.35.
22. **Ordres non écrits dans la spécification (worm).** Anomalies d'un
    périmètre : période par période (pas 2, puis pas 3 : signature, série de
    points, `segment_absent`), puis pas 5 clé par clé (octets UTF-8),
    `versions_multiples` avant `marqueur_de_suppression` ; une pièce
    attendue sans version n'est pas une anomalie. Erreurs de garde : une par
    enregistrement et par règle, dans l'ordre des rangs puis de la table
    d'EX-12.38 ; `meme_identite` et `demande_expiree` comparent la levée à
    la demande désignée par `request_sha256`, `demande_inconnue` à la
    dernière `demande_levee` qui la précède. Ces ordres sont ceux
    qu'INDEX.md et la description de `gardes.json` déclarent.
23. **`chain` des cas `otel/` (INDEX.md, B.8).** `seq_start` 2 et
    `prev_hash` = SHA-256(`noortrace/vecteurs/v0/otel/<cas>/precedent`) :
    un `prev_hash` non nul exige `seq` ≥ 2 (règle C-2 de CT-1) ; les deux cas de
    l'exemple de 6.8.16 portent la chaîne du texte (`seq_start` 21). Le cas
    `pb-identifiants-invalides` reprend l'étiquette de son jumeau JSON (mêmes
    événements, B.8), ce qu'INDEX.md dit désormais.

## Constats des confrontations, corrigés dans la spécification

Confrontation de la version 0.3 (2026-10-23) : 2 484 valeurs recalculées,
2 482 concordantes, **0 discordante**, 2 hors périmètre (`protocols.server`
des deux cas d'approbation sans relais), 0 erreur. Avant la mise à jour de ce
vérificateur, les écarts étaient ceux qu'appelle la révision : codes
`-31011`, `-31013` et `-31014` des cas `delai`, `taille-depassee` et
`injoignable` non reconnus comme erreurs de l'enregistreur (la table était
celle de la version 0.2, `-32010` à `-32017`), motifs des règles a) à c)
admis, cas d'approbation sans relais lus comme des appels relayés.

Confrontation du 2026-10-23 après la relecture de la version 0.3 : 2 512
valeurs recalculées, 2 506 concordantes, **0 discordante**, 6 hors périmètre
(`protocols.server`, déclaratif selon B.4, des six cas sans échange amont :
deux cas d'approbation sans relais et quatre refus au pas 1), 0 erreur. Ce
vérificateur applique désormais au contrôle des motifs le point 5 d'EX-10.6
(zéro non significatif dans un quantificateur, refusé) et recalcule, pour
les motifs de `motifs.json` qui portent `matches`, la première
correspondance avec le paquet `regexp` sur le motif tel quel ; il lit
`protocols.host` d'un refus au pas 1 sur la requête `tools/list`, et ne lit
plus de membre `mode` dans `attendu.json`.

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

Confrontation du 2026-10-26, révision 0.5 : 5 584 valeurs recalculées,
5 578 concordantes, **0 discordante**, 6 hors périmètre (les mêmes
`protocols.server` déclaratifs), 0 erreur ; par famille : `pieces-modele`
1 170 (dont 698 pour les 22 cas `gemini-*`), `otel` 1 808, `worm` 322,
`cout-agent` 165, `index` 108. Avant cette extension, les 22 cas `gemini-*`
étaient des erreurs (« nom de cas hors des formes de B.5 ») et les familles
`otel/`, `worm/` et `cout-agent/` n'étaient pas lues. Constats relevés sans
discordance de valeur :

- EX-12.33 renvoie à « l'annexe B.8 » pour `worm/etats.json`, décrit en B.9.
- EX-12.35 et EX-12.38 ne fixent ni l'ordre des anomalies d'un périmètre ni
  celui des erreurs d'une suite de garde, ni le sort d'une pièce attendue
  sans version : les vecteurs et INDEX.md les fixent (convention 22).
- INDEX.md disait que tous les cas `otel/` autres que l'exemple de 6.8.16
  ont le `prev_hash` de leur propre nom ; `pb-identifiants-invalides` a celui
  de `json-identifiants-invalides` (convention 23). Corrigé à la relecture
  de la révision 0.5, avec `seq_start` porté de 1 à 2 (règle C-2).
- Avec `pii-v1`, la règle de portée `contexte` rédigeait en `[REDIGE:carte]`
  l'horodatage `end_time_unix_nano` (19 chiffres qui passent Luhn) de la
  pièce d'enveloppe dans 23 des 41 cas `otel/` : les horodatages déclarés,
  que 6.7 et EX-6.38 disent lisibles dans cette pièce, n'y étaient plus.
  Corrigé à la relecture de la révision 0.5 : seuls les membres textuels de
  N(S) passent la rédaction (EX-6.35), règle que ce vérificateur applique en
  recalculant chaque pièce d'enveloppe.

Confrontation du 2026-10-26 après la relecture de la révision 0.5 : 6 036
valeurs recalculées, 6 030 concordantes, **0 discordante**, 6 hors
périmètre (les mêmes `protocols.server` déclaratifs), 0 erreur ; par
famille : `pieces-modele` 1 409 (30 cas `gemini-*`), `otel` 1 963 (48 cas),
`worm` 365 (dont `levees.json`), `cout-agent` 165, `index` 123. Les écarts
constatés avant la mise à jour de ce vérificateur étaient ceux qu'appelle la
relecture : chaîne des cas `otel/` (`seq_start` 2), ligne de requête Gemini
portant `host_known`, `data` final sans fin de ligne lu comme le fait le SDK
Python (EX-5.34).

Le 2026-10-27, la copie du code CT-1 passe à la révision 0.4 (quatorzième
partie, AT-1 à AT-7) : aucune valeur des vecteurs de `ct-2` ne change (6 036
recalculées, 6 030 concordantes, 0 discordante, 6 hors périmètre) ; les
dossiers de `ct-1` de la révision 0.4 sont rejoués par
`TestVecteursCT1Publies` et `ct1_attestation_test.go`.

## Limites

- **Signatures EIP-191 des approbateurs** (contrôle 7, E-9) : hors
  périmètre, comme dans le vérificateur CT-1. Les signatures de
  l'attestation de périmètre (AT-3, révision 0.4 de CT-1) sont, elles,
  recouvrées par le code CT-1 copié. Contrôles 4, 5 et 8 des dossiers (CT-4,
  CT-5) : non exécutables, verdict borné.
- **Validation de schéma** : pas de validateur JSON Schema générique ; la
  forme des événements est celle transcrite par le code CT-1, celle des
  politiques se limite aux règles d'EX-10.6.
- **Motifs nommés** : sémantique RE2 du paquet `regexp`, après vérification
  du sous-ensemble commun d'EX-10.6 et de ses règles a) à c). Le budget de
  temps d'EX-10.23 n'est pas exercé : son dépassement dépend de la machine
  (EX-10.4) et aucun vecteur n'en porte (B.3).
- **`politique.json` de `journal-demo`** : figé (B.6) ; seul est vérifié que
  `approval.rules` y reste un tableau, sans validation de schéma.
- **Approbation** : les vérifications RL-1 à RL-4 (EX-7.21), SG-1 à SG-7
  (EX-7.5 ; vecteurs de CT-3, `decisions/`), le MAC de relais (EX-7.22) et
  les fichiers des approbations (EX-12.23) n'ont pas de vecteur CT-2 ; la
  réponse d'`evaluer` des cas est simulée, sa classification (EX-7.16) est
  vérifiée, pas l'égalité de son `approval` avec une décision scellée par le
  noyau (RL-1).
- **Décodage UTF-8 du flux SSE** : un octet invalide donne un U+FFFD par
  octet, pas par sous-partie maximale comme l'algorithme WHATWG ; sans effet
  sur un flux UTF-8 valide.
- **Longueurs en caractères** (`intent` de 4096, `code.model` de 256) :
  comptées en points de code.
- **Nombres hors de la double précision finie** (`1e400`) : refusés (RFC 8785
  §3.2.2.3), là où `JSON.stringify` écrirait `null`.
- **OpenTelemetry** : OTLP/gRPC n'est pas servi (EX-6.26) ; quotas (`429`),
  mode dégradé (`503`), borne de temps de rédaction et
  `limits.piece_max_bytes` sans vecteur, non exercés ; les liens d'un span
  ne sont que comptés (EX-6.31), leur contenu n'est pas décodé ; un entier
  32 bits en JSON n'est admis que sous forme de littéral entier (`1.0` et
  `1e0` refusés), lecture stricte d'EX-6.29.
- **Gemini** : `provider_mcp: "relayer"`, borne de taille (`413`, EX-5.33),
  requête comprimée (`415`), délais et mode dégradé (`503`, `504`) sans
  vecteur ; leurs corps d'EX-5.30 sont vérifiés par les tests.
- **WORM et coût** : aucune requête n'est envoyée ; la règle de garde est
  recalculée sur les enregistrements fournis, sans les identités réelles
  (EX-12.38 le dit) ; le facteur des premières années d'EX-16.4 n'a pas
  d'entrée dans `cout-agent-v0` et n'est pas recalculé.

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
  secrets ; sous-ensemble commun d'EX-10.6 et ses règles a) à c) (chaque
  exemple du texte refusé par la règle qu'il illustre, tailles développées
  de `[0-9]{1000}x` et `(a|aa){1,1000}$`, 1 001 et 3 001) ; collision après
  normalisation.
- Approbation (version 0.3) : les deux résultats imprimés par EX-4.49,
  octet pour octet, et la ligne de 359 octets du signal de l'annexe A
  recalculée depuis la requête de l'annexe A et sa réponse d'`evaluer` ;
  les six combinaisons d'EX-7.16 et des réponses invalides ; codes admis et
  refusés par EX-4.24 ; messages `ouvrir` et `consommer` de l'annexe A
  (`request_seq`, `request_hash`, `request_ts`, `arguments_piece` en base64
  recalculé depuis la pièce du pas 4, `hash` de seq 4, décision 693 s après
  la retenue).
- Lecture d'une requête d'hôte (EX-4.43, EX-4.44) : nombres exacts, CR,
  lot, corps HTTP, id au-delà de 2^53, blancs retirés.
- Valeurs imprimées par CT-2 (`testdata/spec`, blocs extraits du document) :
  exemples de 10.9 (96 et 148 octets), pseudonymes de test, empreintes de
  `pii-v1` et de l'ensemble de politique de 15.3 (6 533 octets,
  `0xd68b…e75c` en révision 0.5, EX-10.21, au lieu de 6 126 octets et
  `0xa75a…8912` en version 0.4 ; `rules` document `politique-approbation-v0`,
  mode `erreur`, entrée de `separation.identities` pour `poste-cursor`,
  `storage.relay_mac_key`), annexe A (définition,
  liste annoncée, résultat, ligne intention à neuf clés, événements seq 2 et
  4 et leur `context`, ligne de segment, octets relayés).
- SSE : règles de 5.4.1, fragmentation en toute position, octet par octet et
  aléatoire (graine fixe) ; formes consolidées des trois fournisseurs,
  flux incomplets, JSON d'outil invalide, erreur en flux, données
  malformées (EX-5.27) ; extraction de 5.5.
- Agrégation, transcriptions ; arborescence synthétique complète dans la
  disposition de l'annexe B (dont les valeurs imprimées par la
  spécification, et trois cas d'approbation : signal de l'annexe A, refus
  d'EX-4.49, signal d'un hôte hérité), puis altération d'un octet du
  segment ; altérations de la version 0.3 détectées (membres du résultat
  rendu dans un autre ordre, ancienne erreur `-32015` à la place du signal,
  motif d'OWASP déclaré admis).
- Code CT-1 copié : ses tests, et les vecteurs publiés de `ct-1` (tout doit
  concorder).
- Révision 0.5 (`revision05_test.go`, blocs de `testdata/spec/ex-*`) :
  transcription de 5.4.5 → forme consolidée imprimée, `code.model`,
  `intent`, appel en position 2, flux coupé incomplet ; `data` final
  (EX-5.34) ; neuf corps d'EX-5.30 ; routes et chaînes de requête
  (EX-5.2, EX-5.28, EX-5.29) ; lot de 6.8.16 → neuf pièces et deux
  événements imprimés (`hash`, `sig`) ; refus du décodeur protobuf
  (EX-6.30) et corps de réponse (EX-6.27) ; échéances d'EX-12.33 ;
  liste des objets (673 octets), `0001-pose` (811 octets) et `0004-levee`
  d'EX-12.35 et EX-12.37, encodage d'EX-12.39 ; cas `reference` de 16.4 ;
  l'arborescence synthétique recopie `otel/`, `worm/` et `cout-agent/` des
  vecteurs publiés, et une altération de chacune est détectée.
