# Confrontation de la famille otel/ (CT-2, section 6.8 et annexe B.8, révision 0.5)

`confronter_otel.py` relit les cas `spec/vecteurs/ct-2/otel` sans le code du
dépôt, avec les messages générés d'`opentelemetry-proto` 1.45.1 (licence
Apache-2.0) et la bibliothèque `protobuf` 7.36.2 (licence BSD à trois
clauses), versions de R11-F43, les plus récentes publiées sur PyPI le
2026-10-26. La forme normalisée d'un span (EX-6.31) est recalculée ici, en
Python, depuis le message que rend la bibliothèque, puis comparée à
`normalized` d'`attendu.json`.

| Ce qui est confronté | Par |
|---|---|
| chaque `requete.json` (et le corps décomprimé de `gzip-json`) : conversion des identifiants hexadécimaux `traceId`, `spanId`, `parentSpanId` (liens compris) en base64, la forme que lit la bibliothèque, puis analyse en `ExportTraceServiceRequest` ; JSON relu sans perte avant conversion (ordre des membres, doublons, texte des nombres conservés) | `google.protobuf.json_format.Parse(…, ignore_unknown_fields=True)` |
| chaque `requete.pb` | `ExportTraceServiceRequest.FromString` |
| statut : la bibliothèque accepte le corps si et seulement si le vecteur attend `200` (refus de `json-non-analysable` et `pb-tronque` compris) | idem |
| span par span : `path`, `trace_id`, `span_id`, `parent_span_id`, `name`, `kind`, `start_time_unix_nano`, `end_time_unix_nano` (entiers 64 bits en décimal, au-delà de 2^53 compris), `status`, attributs du span, de la ressource et de la portée, événements (valeurs V d'EX-6.31 : entier au-delà de 2^53 − 1 en chaîne, double non fini en chaîne, octets en base64, `AnyValue` vide et `stringValueStrindex` à `null`, attribut à `keyStrindex` sans `key` ignoré, première occurrence d'une clé gardée, six attributs de contenu analysés en JSON strict dans les attributs du span seulement), autres membres, puis forme normalisée complète | messages de la bibliothèque ; nombres comparés sur leur valeur double (JCS intégral, 8.1) |
| `requete.pb` de `pb-exemple-6-8-16` et de `pb-identifiants-invalides` (les autres sont tronqués, à champ double ou à champs inconnus) : octets du générateur égaux à la sérialisation déterministe de la bibliothèque (champs dans l'ordre de leur numéro, chacun une fois, B.8) | `SerializeToString(deterministic=True)` |
| paires `json-exemple-6-8-16` / `pb-exemple-6-8-16` et `json-identifiants-invalides` / `pb-identifiants-invalides` : même message, et sérialisation de la forme JSON égale aux octets protobuf | `==` des messages, `SerializeToString(deterministic=True)` |
| corps de réponse de chaque cas `200` : `partialSuccess.rejectedSpans` égal au nombre de spans rejetés ; corps JSON réécrit par la bibliothèque égal à `body_json` (`rejectedSpans` en chaîne décimale, R11-F39) ; corps protobuf égal à la sérialisation de la bibliothèque, octet pour octet (vide pour un succès complet) | `ExportTraceServiceResponse`, `MessageToDict`, `SerializeToString(deterministic=True)` |
| piège de R11-F44 : sans conversion, `Parse` lit le `traceId` hexadécimal de `json-exemple-6-8-16` comme du base64 et rend 24 octets | `json_format.Parse` |

## Divergences voulues, limites

Quatre corps sont acceptés par la bibliothèque et refusés par NOORTRACE
(`400`), chacun par une règle de 6.8 ; la sortie les publie comme
divergences voulues :

- `json-enum-en-chaine` : `"kind": "SPAN_KIND_CLIENT"` est lu comme `3` ;
  EX-6.29 refuse une énumération en chaîne (R11-F39).
- `json-identifiant-non-hexadecimal` : le `traceId` est écrit en base64
  (`W47/95gDgQPSabYzgT/GDA==`) ; la bibliothèque le lit (c'est sa forme
  native, R11-F44) ; EX-6.29 n'admet que l'hexadécimal.
- `pb-champ-double` : le champ `name` présent deux fois ; la bibliothèque
  garde le dernier (`execute_tool autre`) ; EX-6.30 refuse.
- `json-entier-fractionnaire` : `"flags": 1.0` ; la bibliothèque le lit
  comme `1` ; EX-6.29 exige un texte sans fraction ni exposant.

Limite de l'outil, montrée par une sonde (section 4 de la sortie) :
`json_format.Parse` lit aussi les noms de champs d'origine en snake_case
(`trace_state`, `dropped_attributes_count`, `schema_url`…), qu'OTLP/JSON
tient pour inconnus et que NOORTRACE ignore (EX-6.29, R11-F39). Dans
`json-champ-inconnu`, ces champs portent la valeur par défaut et la forme
normalisée concorde ; la sonde remplace en mémoire `"trace_state": ""` par
`"trace_state": "sonde"` et la bibliothèque rend `"sonde"`.

Ne sont pas confrontés : le statut des cas refusés avant tout décodage
(`401`, `404`, `405`, `413`, `415` : authentification, chemin, méthode,
taille, type ou codage de contenu, ordre des décisions d'EX-6.27, EX-6.28,
EX-6.37), dont le corps est seulement dit analysable ou non ; le corps `Status`
des réponses de refus (`{"message": …}` ou champ 2 en protobuf), message
`google.rpc.Status` qui n'est ni dans `opentelemetry-proto` ni dans `protobuf` ;
la classification, les doublons, les recouvrements, les pièces et les
événements, que le vérificateur Go recalcule. `pb-champ-inconnu` : la
bibliothèque saute les numéros inconnus, comme EX-6.30, mais les garde comme
champs inconnus et les réémet à la sérialisation ; la sortie donne la taille
avant et après `DiscardUnknownFields`.

## Exécution

```bash
python3 -m venv <répertoire>/venv-otel
<répertoire>/venv-otel/bin/pip install --only-binary :all: --no-deps -r spec/vecteurs/ct-2/confrontation/otel/exigences.txt
<répertoire>/venv-otel/bin/python -I spec/vecteurs/ct-2/confrontation/otel/confronter_otel.py spec/vecteurs/ct-2
```

Code de retour : 0 si tout concorde, 1 sinon, 2 pour un usage incorrect. La
sortie ne dépend ni de la version de Python (identique avec Python 3.12 et
3.13) ni de la machine ; elle doit être égale, octet pour octet, à la sortie
de référence `../sorties/otel.txt` : 48 cas, 40 requêtes analysées par la
bibliothèque, 8 statuts décidés avant le décodage, 34 corps de réponse
confrontés, 4 divergences voulues, 1 limite de l'outil, 0 discordance.
