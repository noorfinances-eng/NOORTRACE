# Vérificateur indépendant CT-9 (Go, salle blanche)

Second lecteur des vecteurs de [CT-9](../../../CT-9-plan-de-tests.md)
(version 0.1), écrit en Go depuis le seul texte de CT-9 et le schéma
`plan-de-tests-v0`, sans lire ni reprendre le code JavaScript de
`scripts/` (EX-A.17). Il relit les mêmes entrées que l'outil de
couverture du dépôt et recalcule chaque valeur publiée sous
`spec/vecteurs/ct-9/` ; chaque valeur recalculée est un contrôle,
**concordant**, **discordant** ou **hors périmètre** (une valeur que le
texte seul ne permet pas de recalculer, avec sa raison). Deux programmes
écrits séparément qui tombent sur les mêmes nombres rendent le rapport
publié probant ; une discordance désigne une ambiguïté du texte, une
régénération oubliée ou une faute de l'un des deux.

Module propre `noortrace-ct9` (`go 1.24`), bibliothèque standard
seulement (`bufio` n'est pas nécessaire : les fichiers sont lus d'un
bloc), sans cgo ni dépendance. Le programme n'écrit rien.

## Usage

```bash
cd spec/vecteurs/ct-9/verificateur-independant
gofmt -l . && go vet ./... && go test ./...
go run . ..            # rapport texte ; code 0 si et seulement si 0 discordance
go run . -v ..         # chaque contrôle, raison des hors périmètre comprise
go run . -json .. > rapport.json
```

L'argument est le répertoire des vecteurs `spec/vecteurs/ct-9` ; la
racine du dépôt en est le troisième parent. Codes de retour : `0` aucune
discordance ; `1` au moins une discordance ; `2` usage incorrect ou
fichier illisible. La dernière ligne du rapport texte donne le total des
valeurs recalculées et leur répartition (concordantes, discordantes, hors
périmètre) ; sans `-v`, seules les discordances sont détaillées.

## Ce qu'il recalcule

- **Identifiants définis par CT-1 à CT-8** (5.2, EX-5.6), par ses propres
  expressions : `**EX-s.k**` et `**EX-s.k (` en gras, familles en
  première cellule d'une ligne de table (gras retiré), hors blocs de
  code ; exclusion des préfixes `CT-` et `EIP-` ; pour CT-8, les lignes
  `DM-n` en début de ligne (blocs compris), `**IR-n**`, `**IC-n**` et
  RB-1 à RB-8 des titres 10.12 à 10.19 ; les numéros de sections (titres
  de niveau 2 à 4). L'inventaire de la table de 5.2 (EX-, vérifications,
  total, familles, version de chaque spécification) est confronté à ces
  comptes.
- **Occurrences de « CT-9 »** (0.2) dans `spec/CT-1-*.md` à `CT-8-*.md`
  puis `spec/README.md`, clé « préfixe section », et les comptes par
  fichier (occurrences, lignes) que la section 0.2 imprime.
- **Menaces** de `menaces.json` : un TA-n par MN-n, `threats`,
  `threat_test_text`, `covers`, `component`, `accepted_risk` égaux
  (EX-10.1, EX-10.2) ; risques acceptés (10.6) ; scénarios TA-103 à TA-107
  (10.5 : composition, union des `covers` et des menaces, titre, état) ;
  `index-ta-par-menace.json` entrée par entrée (EX-A.13).
- **Titres des tests** (EX-4.2) par une analyse lexicale propre de
  `test/*.test.js` (commentaires, chaînes, gabarits, expressions
  rationnelles ; dans un gabarit, une interpolation `${…}` lue comme une
  expression, gabarits imbriqués compris, révision 0.4 ; appartenance d'un
  `it` à ses `describe` par les accolades) et **étapes de CI** (`- name:` de `ci.yml`) ; existence de
  chaque titre cité par une entrée exécutable (règle (d)) ; forme
  d'EX-10.7 de chaque `it` de `test/adversarial.test.js` (TA- cités,
  menaces, « (tué) », exception d'EX-10.4), nombre d'`it` et de
  `describe` d'EX-A.11.
- **Catalogue** : unicité et forme des identifiants, numéros qui se
  suivent par niveau (EX-3.1), états (EX-3.10), blocs propres (EX-4.1),
  racine (version, kind, spec, `spec_version` et `date` égaux à l'en-tête
  du texte), niveaux et étapes ; règles de couverture (a) à (d) et EX-5.5
  : pour chaque identifiant qu'aucune entrée ne couvre, la justification
  NC- qui le porte (identifiant, catégorie d'EX-5.7) ; TM- (`measured`
  nul, source définie, `result_name` unique, cible et comparaison,
  TM-22, les quatre exécutables d'EX-11.16) ; TR- (grille existante ou
  `null`, à écrire à l'étape 8).
- **Tables du texte** (EX-4.4, EX-A.4) : les quinze tables marquées
  `<!-- table X -->`, réimprimées depuis le catalogue et comparées
  cellule par cellule ; les chiffres de 5.5 (EX-5.10) ; les chiffres et
  identifiants que la prose énonce sans ambiguïté (sections 6, 7, 12.2,
  13, 16).
- **`couverture.json`** membre par membre : totaux, détail par
  spécification (identifiants, couverts, NC-, non couverts et leur liste,
  familles), menaces, traçabilité, exécutables et titres, tables,
  verdict, `errors`, et les SHA-256 d'entrée (`inputs`) recalculés
  (EX-A.6).
- **Schéma** `plan-de-tests-v0` : un validateur JSON Schema (draft
  2020-12) restreint aux mots-clés du schéma, écrit ici ; `catalogue.json`
  (racine), `couverture.json`, les rapports de mesure, le gabarit et les
  consignations, les grilles valident ; chaque cas de `cas/`,
  `mesures/cas/` et `consignations/cas/` rend le verdict attendu, et pour
  `cas/` le mot-clé fautif attendu figure parmi les mots-clés violés.
- **Rapports de mesure** (EX-11.11, EX-11.13) : chaque ligne a son TM-
  (nom = `result_name`, ou ligne nommée par la table de 11.3), son unité ;
  rapport vide : cibles du catalogue, `null` ailleurs ; rapport sur les
  vecteurs : tailles de ligne de `segment.ndjson`, n, min, max, moyenne et
  SHA-256 recalculés, table et bloc JSON de 11.3 égaux au fichier.
- **Consignation** `gabarit-TR-10.json` (EX-A.15) : TR-10, grille et
  sections interdites du catalogue, SHA-256 à zéro, `duration_s` null.
- **Grilles** (EX-12.7, EX-A.16) : `kind`, `test_id`, chemin égal au
  membre `grid` de l'entrée, règles connues (identifiant, section ou
  fichier des vecteurs), aucune consigne ne contient un élément de sa
  grille, nombre de questions de la consigne ; la grille de TR-14
  recalculée en entier depuis les deux tables de la section 14, EX-14.2
  et la table des niveaux (EX-15.2).
- **Extraits** (EX-12.2, EX-A.16) : chaque extrait égale, octet pour
  octet, la découpe de sa spécification par sections de niveau 2 et 3,
  hors blocs de code ; `SHA256SUMS` égale les condensés recalculés.
- **`INDEX.md`** (EX-A.2) : ligne de chaque entrée (identifiant, niveau,
  état, titre), de chaque cas avec son attendu, de chaque grille, et ses
  comptes.

## Ce qu'il ne recalcule pas (hors périmètre, raison imprimée par `-v`)

- Les résultats d'exécution : « 844 passing », « 60 passing », les 65
  mutants tués, les valeurs rendues par `test/enregistreur.test.js` et
  `test/ancrage.test.js` dans le rapport sur les vecteurs ; il n'exécute
  aucun test et ne lit pas le code des tests, seulement leurs titres.
- `date` et `tool.command` de `couverture.json` (exclus par EX-A.7), le
  libellé des écarts (`errors`), `commit`, `measured_at` et `system` des
  rapports de mesure (repris par le bloc de 11.3, dont l'égalité est,
  elle, contrôlée).
- L'ordre des erreurs d'un validateur tiers : le mot-clé fautif attendu
  d'un cas est confronté à l'ensemble des mots-clés violés, pas au
  premier.
- Les paraphrases : éléments des grilles de TR-4 et TR-5, affirmations
  disqualifiantes, éléments d'exemple du gabarit, seuils d'échec en toutes
  lettres, la règle de jugement d'EX-5.7 sur le sujet d'un EX-, le compte
  « 18 entrées TA- » de la section 16 (définition ambiguë).
- La sortie du recomptage Python (`confrontation/`) et le déterminisme du
  générateur, qui sont des exécutions.

## Fichiers

| Fichier | Contenu |
|---|---|
| `main.go` | options, codes de retour |
| `rapport.go` | contrôles (concordant, discordant, hors périmètre), résumé, sorties texte et JSON |
| `texte.go` | spécifications, identifiants (5.2), sections, occurrences de « CT-9 » (0.2), découpe des extraits, nombres en français |
| `titres.go` | analyse lexicale des `describe`/`it` (EX-4.2), étapes de `ci.yml`, titres d'EX-10.7 |
| `schema.go` | validateur JSON Schema (draft 2020-12, mots-clés du schéma) |
| `catalogue.go` | structures du catalogue, de `menaces.json`, des rapports, des grilles et des listes de cas |
| `tables.go` | impression des quinze tables (EX-A.4) et comparaison au texte (EX-4.4) |
| `couverture.go` | règles (a) à (d), EX-5.5, menaces, index, traçabilité, titres, tables, TM-, TR-, comparaison à `couverture.json`, condensés |
| `vecteurs.go` | schéma, cas, rapports de mesure, consignation, grilles, extraits, `INDEX.md`, prose, hors périmètre |
| `verificateur_test.go` | tests unitaires des briques et rejeu sur le dépôt (zéro discordance) |
