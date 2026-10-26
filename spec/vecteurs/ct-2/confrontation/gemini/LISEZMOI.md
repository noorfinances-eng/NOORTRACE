# Confrontation des cas Gemini (CT-2, annexe B.5, révision 0.5)

`confronter_gemini.py` relit les cas `spec/vecteurs/ct-2/pieces-modele/gemini-*`
sans le code du dépôt, avec le SDK Python officiel `google-genai` 2.33.0
(version la plus récente publiée sur PyPI le 2026-10-26, licence Apache-2.0),
employé hors ligne. Les types du SDK sont des modèles `pydantic` à alias
camelCase qui **refusent les membres inconnus** (`extra='forbid'`,
`google/genai/_common.py` l. 600-617 de la roue 2.33.0) : un membre que le
SDK ne connaît pas, ou une valeur qu'il ne sait pas lire, fait échouer
l'analyse. Le client du SDK (`genai.Client`) est branché sur un transport
`httpx.MockTransport` : il construit la requête qu'il enverrait et lit, par
son propre chemin, la réponse enregistrée du vecteur, octet pour octet. Aucun
réseau n'est contacté (adresse de base `https://passerelle.invalid/`,
`trust_env=False`, clé fictive).

| Ce qui est confronté | Par |
|---|---|
| clés de premier niveau de chaque `requete.json` incluses dans `GenerateContentRequest` du document de découverte (révision `20261024`, v1beta ou v1 selon la route, R11-F11, R11-F2 ; listes recopiées dans le programme) | comparaison de listes |
| chaque élément de `contents`, `systemInstruction`, chaque élément de `tools`, `toolConfig`, `generationConfig`, chaque élément de `safetySettings` : accepté, et **relu à l'identique** (rien de perdu, d'ajouté ni de transformé) | `types.Content`, `types.Tool`, `types.ToolConfig`, `types.GenerationConfig`, `types.SafetySetting` : `model_validate_json`, puis `model_dump(mode="json", by_alias=True, exclude_none=True)` |
| requête reconstruite par le client depuis les valeurs du vecteur : cible envoyée égale à `upstream_target` (route, segment, méthode, `?alt=sse` pour le flux, R11-F5), corps envoyé égal à `requete.json`, clé dans l'en-tête `x-goog-api-key` et jamais dans l'URL (EX-5.29, R11-F6) | `client.models.generate_content`, `generate_content_stream` |
| transcription `reponse.sse` : valeurs `data` distribuées selon EX-5.14 et EX-5.34 (relues ici du texte de la spécification, `data` final sans ligne vide compris) égales aux objets que lit le lecteur de flux du SDK, dans l'ordre ; corps d'erreur `text/event-stream` sans `data:` (R11-F19) lu par équilibre des accolades, égal au corps analysé par l'enregistreur (EX-5.31) | `HttpResponse.segments` (`google/genai/_api_client.py` l. 468-522) |
| chaque objet `data` de statut `2xx`, chaque `reponse.json` `2xx`, chaque élément de `reponse-morceaux.json` sans les membres retirés par EX-6.8 (et tel que déclaré, `sdkHttpResponse` étant un champ du type du SDK) : accepté et relu à l'identique ; morceau d'erreur et corps d'erreur `4xx` : refusés (`extra_forbidden` sur `error`) | `types.GenerateContentResponse.model_validate_json` |
| lecture complète par le client : nombre d'objets rendus avant toute erreur, objets relus égaux aux objets reçus (hors membres propres au SDK : `sdkHttpResponse`, `automaticFunctionCallingHistory`, `parsed`), erreur `errors.APIError` (code, statut, message) égale au corps analysé par l'enregistreur (EX-5.31) ou à `noortrace_erreur_flux` (EX-5.35 pas 2), `intent` égal à la concaténation des `GenerateContentResponse.text` (candidat 0, parts `thought` exclues, sans séparateur : la règle de 5.5), `tool_calls` égal aux `GenerateContentResponse.function_calls` (`id`, `name`, `args`) | `generate_content(_stream)`, `.text`, `.function_calls` |
| chaque `consolidated` d'`attendu.json` privé des clés `noortrace_*` : accepté et relu à l'identique ; avec ces clés : refusé (EX-5.18) | `types.GenerateContentResponse.model_validate_json` |
| chaque corps de refus de la passerelle (EX-5.30, AIP-193), servi au client avec son statut et son `Content-Type` : `errors.APIError` levée, `code`, `status` et `message` égaux au corps, classe `ClientError` ; `404` sans corps : code lu | `errors.APIError.raise_for_response` |

## Divergences voulues, limites de l'outil

- `gemini-requete-non-analysable` : le corps porte la clé `contents` deux
  fois ; l'analyseur JSON de `pydantic` l'admet (la dernière occurrence
  l'emporte), l'enregistreur le refuse (EX-5.7 point 2). Divergence voulue.
- `gemini-flux-index` : le fragment d'`index` `"0"` (une chaîne) est lu par
  le SDK comme l'entier `0` (conversion du mode non strict de `pydantic`) et
  son texte entre dans `.text` ; l'enregistreur l'ignore (EX-5.35 pas 4,
  EX-5.27 (1)). Le SDK ne rejette rien : la valeur est transformée. Divergence
  voulue, imprimée trois fois (objet `data`, objet relu par le client,
  `intent`).
- `gemini-flux-index-desordre` : le premier fragment reçu porte l'index 1 ;
  l'enregistreur crée les candidats dans l'ordre de première apparition et
  tire `intent` de `candidates[0]` de la forme (EX-5.35 pas 4, 5.5), le SDK
  prend `candidates[0]` de chaque morceau. Divergence voulue (`intent`).
- `gemini-flux-index-limites` : l'index est lu en double précision (EX-5.27
  (1), EX-8.1) : `1.0` vaut 1, `9007199254740993` vaut 2^53, et le fragment
  d'index `9007199254740994` est ignoré ; `pydantic` relit `1.0` en `1`
  (écart de texte) et le SDK prend `candidates[0]` de chaque morceau.
  Divergence voulue, imprimée trois fois.
- `gemini-refus-mcp-fournisseur` : le client du SDK envoie l'objet
  `McpServer` sans ses alias : `streamable_http_transport` au lieu de
  `streamableHttpTransport`, le nom du document de découverte
  (`google/genai/models.py` l. 4094-4099 et `_common.py` l. 283-284 :
  `model_dump(exclude_none=True)` sans `by_alias`). Le membre `mcpServers`
  lui-même garde son nom, ce qui suffit au refus d'EX-5.32. Limite de
  l'outil, publiée comme telle.
- Le client ajoute `generationConfig: {}` dès qu'une configuration est donnée
  (`models.py` l. 1605-1612), et `automaticFunctionCallingHistory: []` à la
  réponse hors flux d'une requête qui porte des outils : ce sont des membres
  sans valeur ou propres au SDK, retirés avant comparaison et signalés dans la
  sortie.
- Le chemin de réponse du client retire en silence les membres inconnus
  avant validation (`_from_response`, `_common.py` l. 665-690 :
  `_remove_extra_fields`) ; c'est pourquoi chaque objet est aussi analysé par
  `model_validate_json`, qui les refuse, et pourquoi l'objet relu par le
  client est comparé à l'objet reçu.
- Les cibles refusées par la passerelle (`?key=`, `alt` absent ou `proto`,
  route `tunedModels`) ne peuvent pas être émises par le SDK : la cible est
  « sans objet » pour ces cas ; leur corps de refus est confronté, de même
  que ceux de `gemini-refus-cache` (`cache_fournisseur`) et de
  `gemini-hote-inconnu` (`401`, `UNAUTHENTICATED`).
- Le programme emploie `google.genai._api_client.HttpResponse`, membre
  interne du SDK, pour relire les flux comme le client : son comportement
  peut changer d'une version à l'autre, d'où l'épinglage.
- `gemini-forme-inattendue` : le SDK refuse de construire une requête sans
  `contents` (`ValueError`), comme attendu ; sa réponse est analysée
  (section 3).

Le programme emploie `google.genai._api_client.HttpResponse`, membre interne
du SDK, pour lire la transcription SSE par le lecteur du SDK lui-même ; un
changement de ce membre se verrait à l'exécution, pas en silence.

## Exécution

```bash
python3 -m venv <répertoire>/venv-genai
<répertoire>/venv-genai/bin/pip install --only-binary :all: --no-deps -r spec/vecteurs/ct-2/confrontation/gemini/exigences.txt
<répertoire>/venv-genai/bin/python -I spec/vecteurs/ct-2/confrontation/gemini/confronter_gemini.py spec/vecteurs/ct-2
```

`exigences.txt` donne les versions exactes de `google-genai` 2.33.0 et de
toutes ses dépendances résolues par `pip` (dont `pydantic` 2.14.1, licence
MIT, `pydantic-core` 2.50.1 et `httpx` 0.28.1) ; `--no-deps` interdit toute
autre résolution, et `pip check` ne relève aucune dépendance manquante. Code
de retour : 0 si tout concorde, 1 sinon, 2 pour un usage incorrect. La sortie
ne dépend ni de la version de Python (identique avec Python 3.12 et 3.13) ni
de la machine ; elle doit être égale, octet pour octet, à la sortie de
référence `../sorties/gemini.txt` : 30 cas `gemini-*`, 8 divergences
voulues, 1 limite de l'outil, 0 discordance.
