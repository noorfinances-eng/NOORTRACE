# Vérificateur indépendant CT-8 (Go, salle blanche)

Un second vérificateur des vecteurs de
[CT-8](../../../CT-8-deploiement-et-exploitation.md), écrit en Go depuis le
seul texte de CT-8 et les schémas qu'il nomme (`conteneurs-v0`,
`controle-prealable-v0`, `dimensionnement-v0`, `paquet-reviseur-v0`,
`proces-verbal-exploitation-v0`), et des passages de CT-1 (§6.1, §6.2, table
des contrôles E- et C-) et de CT-2 (EX-12.1, EX-12.3) qu'il cite, sans
lire ni reprendre le code JavaScript de `scripts/`, de `test/` ni les
fichiers de `deploiement/` (EX-A.21, EX-A.24). Il recalcule chaque valeur
que les vecteurs de `spec/vecteurs/ct-8` déclarent, famille par famille
selon l'annexe A, et la confronte à l'attendu. Deux implémentations écrites
séparément qui tombent sur les mêmes valeurs rendent les vecteurs probants ;
une discordance désigne une ambiguïté de la spécification ou une faute de
l'une des deux.

Module propre `noortrace-ct8` (`go 1.24`), **bibliothèque standard uniquement**
(`archive/tar`, `crypto/sha256`, `encoding/json` pour le rapport,
`crypto/ed25519` pour E-8) : aucun `go.sum`, aucun accès au réseau. Cinq
fichiers reprennent du code d'autres vérificateurs indépendants, et le disent en
tête : `json.go` et `jcs.go` (copies de ct-7), `texte.go` et `rapport.go`
(repris de ct-7, en-tête et titre seuls changés), `schema.go` (repris de ct-7,
étendu des mots-clés `exclusiveMinimum`, `exclusiveMaximum`, `minProperties`,
`maxProperties`, `propertyNames`, `minContains`, `maxContains`, et d'une
évaluation composant par composant des motifs `^C(/C){0,k}$` que RE2 refuse) et
`format.go` (repris de ct-3).

## Usage

```bash
cd spec/vecteurs/ct-8/verificateur-independant
go run . ..                       # rapport texte
go run . -v ..                    # liste aussi chaque valeur concordante et hors périmètre
go run . -json .. > rapport.json  # rapport complet en JSON
go build -o verificateur . && ./verificateur ..
gofmt -l . ; go vet ./... ; go test ./...
```

`go build` sans `-o` produit `noortrace-ct8` ; `noortrace-ct8` et
`verificateur` sont exclus par le `.gitignore` local.

Le vérificateur lit, à côté des vecteurs, la spécification
(`../../CT-8-deploiement-et-exploitation.md`), les schémas
(`../../schemas/*.schema.json`) et, pour les mesures de 9.2 et les entrées
du paquet (EX-A.11), des vecteurs d'autres spécifications : les points et
les manifestes de `ct-1`, les réponses de `ct-5`, les dossiers, les ancres,
les en-têtes et la capture du registre de `ct-6`, l'attestation d'exemple de
`ct-7`, le manifeste d'instance de `ct-4`, et le rapport de la mesure de
`b_cap` publié sous `ct-9/mesures/` (révision 0.2 de CT-8). Il n'écrit rien : PR-10
(extraction) est jouée en mémoire.

Codes de retour (EX-A.21) : `0` tout concorde (les valeurs hors périmètre
sont énoncées avec leur raison et ne comptent pas) ; `1` au moins une
discordance, listée avec l'attendu et la valeur recalculée, ou une erreur
(fichier absent ou illisible) ; `2` usage incorrect ou racine introuvable.

## Décomptes

Exécution du 2026-11-03 (révision 0.2 de CT-8), `go run . ..` depuis ce
répertoire :

| Famille | Recalculées | Concordantes | Discordantes | Hors périmètre |
|---|---|---|---|---|
| disposition | 16 | 16 | 0 | 1 |
| coefficients | 12 | 12 | 0 | 0 |
| dimensionnement | 838 | 838 | 0 | 0 |
| controle-prealable | 2 979 | 2 979 | 0 | 0 |
| paquets | 849 | 849 | 0 | 23 |
| conteneurs | 377 | 377 | 0 | 37 |
| observation | 46 | 46 | 0 | 1 |
| journaux | 49 | 49 | 0 | 3 |
| consultations | 7 | 7 | 0 | 0 |
| proces-verbaux | 14 | 14 | 0 | 0 |
| **Total** | **5 187** | **5 187** | **0** | **65** |

« Résultat : tout concorde. »

## Ce qui est recalculé

| Famille | Fichiers lus | Valeurs recalculées et confrontées |
|---|---|---|
| disposition | `spec/vecteurs/ct-8/` | présence de chaque entrée de la disposition d'A.1 ; aucune entrée hors de cette disposition |
| coefficients | `ct-1/points-de-controle/periode-{1,2,3}.json`, `ct-1/manifestes/periode-*.{json,sig}`, `ct-5/reponses/*.{der,tsr}`, `ct-9/mesures/rapport-2026-11-02-capture-bloc-plein.json`, `ct-6/registre/capture/{bloc,certificat,recu}-*` | mesures de 9.2 rejouées comme les commandes d'A.5 : `b_pt` (ligne JCS v0 plus `\n` la plus longue des 183 points, 681 à 682 octets), `b_man` (631 + 285), `b_tsr_sup` (9 octets sur les 16 paires), chacune égale à la valeur de la table de 9.2 ; `b_cap` (révision 0.2) relu dans le rapport de sa mesure : ligne `b_cap_bloc_plein` de TM-31 en octets, trois échantillons de 109 479 et `max` égal au plus grand, décomposition de chaque répétition dans `notes` (5 846 + 32 587 + 71 046, 64 reçus), plus grand index de capture (14 282) et forme à un seul reçu (39 544), valeur de la table de 9.2 égale au `max` plus l'index (123 761) ; étendues des fichiers des blocs d'une transaction de `ct-6/registre/capture/`, dont 9.2 tire ses réserves (1 498 ; 6 818 à 7 782 ; 1 107 à 1 816) |
| dimensionnement | `dimensionnement/*.json`, blocs de 9.5, tables de 9.2 et de 9.6 | coefficients lus dans la table de 9.2 (EX-9.1) ; refus d'EX-9.3, toutes les raisons, journal par journal ; DM-1 à DM-22 en `float64`, dans l'ordre écrit, `math.Ceil` et `math.Round(x*1000)/1000` (six décimales pour la part), comparaison de chaque nombre à l'égalité exacte (EX-A.22) ; membres et ordre de la sortie ; exemple de 9.5 recalculé et égal à la sortie imprimée, octet pour octet sous `JSON.stringify` ; `reference` égal à l'exemple ; chaque ligne de 9.6 (Gio à trois décimales, jetons, transactions par heure et part, pointe, `J_max`, refus) ; forme EX-A.1 et schéma `$defs/cas` de chaque fichier |
| controle-prealable | `controle-prealable/*.json`, blocs de 6.3, table d'A.4 | IP-1 à IP-13 de la table d'EX-6.2 (seuils des deux profils, systèmes de fichiers admis et refusés, borne d'horloge et `borne_inconnue`, ports du profil rapide ou publiés et adresse interne, destinations, première faute d'IP-10 dans l'ordre du texte, `condense_requis`, déclaration du cache d'EX-6.4), `--seulement` (EX-6.1), verdict et code d'EX-6.3 ; pour chaque vérification : `id`, `status`, `reason`, `blocking`, `expected` et `measured` selon la table d'EX-6.6 ; exemple de 6.3 réévalué et égal au rapport imprimé ; `pret-rapide` égal aux observations de 6.3 ; variante de production d'A.4 (8 processeurs, 16 Gio, 1 200 Gio, ports sur `192.0.2.40`, condensés, cache) ; seuil de `pret-production` égal à `local_bytes` de 9.5 recalculé ; table d'A.4 (profil, verdict, vérifications nommées) ; forme EX-A.1 et schéma |
| paquets | `paquets/cas.json`, `paquets/*.tar`, `paquets/description.json`, blocs de 13.3, 13.5, 13.7, 13.11, table et exemple d'A.10 | chaque archive lue deux fois, lecture brute des blocs de 512 octets (EX-13.14, EX-13.31) et `archive/tar`, accordées sur chaque entrée (nom, type, taille, mode, propriétaires, noms, date, lien, périphériques, format, données) ; longueur `L` d'EX-13.14 ; PR-1 à PR-9 (EX-13.30 à EX-13.33 : arrêt à la première en échec, PR-2 avec `options.expected_sha256`), PR-10 en mémoire, PR-11 et PR-12 `sans_objet` sans vérificateur ni attestation ; état du paquet, AV-PR-1 à AV-PR-4 (13.9), code d'EX-13.26 à partir des codes de `expected.dossiers` ; SHA-256 et taille de chaque archive et de chaque fichier ; décompte, octets et SHA-256 de `cas.json` d'EX-A.13 ; table d'EX-A.13 entière ; 17 cas dont onze de code 4 (EX-13.1), les sept cas qu'A.10 désigne, cas `observation` d'EX-A.15 (dossiers, `observation_mode`, `observation`, décompte) ; découpage nom/préfixe d'EX-13.14 (plus long préfixe, règle de GNU tar) ; manifeste de `valide.tar` égal à celui de 13.3 (49 fichiers, 236 017 octets, 11 274 octets, SHA-256), écrit par `JSON.stringify(m, null, 2)` plus saut de ligne (EX-13.12), `created_at` de 1 793 059 200 secondes ; `LISEZMOI.md` et `README.md` égaux aux blocs de 13.11 et à leurs SHA-256 ; détails PR- et manifeste du rapport de `fichier-altere` de 13.7 ; SHA-256 du manifeste recalculé de `contrefacon-coherente` ; `description.json` égale à 13.5, chaque fichier de `valide.tar` égal à sa source (EX-13.18, EX-A.11) ; chaque variante égale à `valide.tar` sauf la seule chose que décrit EX-A.13 (entrée retirée, ajoutée ou remplacée, octet `7` devenu `9`, lien, mode `0600`) |
| conteneurs | `conteneurs/*.yaml`, `conteneurs/*.attendu.json`, `images.json`, blocs de 4.1 à 4.3, table d'A.3 | `images.json` égal au bloc de 4.1 ; `valide-rapide.yaml` et `valide-production.yaml` égaux aux blocs de 4.2 et 4.3 et à leurs SHA-256 ; `valide-production-condenses.yaml` reconstruit depuis 4.3 (`@sha256:` et 32 fois `ab`) ; SHA-256 de chaque fichier ; `all_images_by_digest` lu sur les clés `image:` ; verdict cohérent avec les vérifications ; pour chaque cas invalide, la seule vérification en échec et son code selon A.3, fragment de remplacement présent (forme courte ou en blocs) ; forme EX-A.1 et schéma |

| observation | `observation/marques.json`, `evenements.ndjson`, `rapport-attendu.json`, `journal/`, `politiques/`, `invalides/`, table d'EX-A.7, valeurs d'EX-A.8 | OB-1 (EX-12.16, ordre des erreurs) sur chaque cas de `marques.json` et chaque ligne de la table d'EX-A.7 ; rapport d'EX-12.10 recalculé sur les sept événements et égal, en JCS, à `rapport-attendu.json` ; longueur et SHA-256 du segment et SHA-256 du rapport égaux aux valeurs d'EX-A.8 ; nom de chaque pièce égal à son SHA-256 ; anomalies OB-1 à OB-4 de chaque suite invalide (OB-3 et OB-4 avec les pièces) |
| journaux | `journaux/<cas>/` (`journal.json`, `segments/`, `cles.json`, `attendu.json`) | EX-11.7 hors manifestes : `journal.json` (CT-2 EX-12.1), en-tête de chaque segment (CT-2 EX-12.3), `first_seq` et époques, `prev_hash` des en-têtes, ligne finale, E-2, E-7 (`SHA-256(P_H ‖ JCS(E'))`, CT-1 §6.1), E-8 (Ed25519 sur `P_S ‖ JCS(E')`, CT-1 §6.2), clé inconnue, C-1 et C-2 ; segments (nom, `first_seq`, époque, événements, longueur, SHA-256), `first_seq`, `last_seq`, `last_hash`, erreurs rejouées et verdict |
| consultations | `consultations/<cas>/*.ndjson`, `attendu.json`, A.9 | CA-1 (JSON strict, JCS), CA-2, CA-3 (SHA-256 du nom puis de la ligne précédente), CA-4, CA-6 : statut de chaque vérification ; SHA-256 de la première ligne égal à la valeur d'A.9 |
| proces-verbaux | `proces-verbaux/valides/`, `invalides/`, `racine/`, `cles.json`, `attendu.json` | statut de PV-1 à PV-10 (EX-11.18) : schéma, tri, totaux, condensés, personnes, cohérence de la sorte, fichiers de la racine, journal de la racine par la vérification d'EX-11.7, échéance de rétention, chemins et contenus de secrets |

## Ce qui n'est pas recalculé

- **CO-1 à CO-14 sur le YAML** (36 valeurs) : la bibliothèque standard de Go
  n'a pas d'analyseur YAML ; le module ne rejoue que ce qui se lit sans
  analyse (voir la table).
- **Codes de dossier de CT-6** (17 valeurs) : EX-A.24 ; le code agrégé
  d'EX-13.26 est recalculé à partir d'eux.
- **PR-12** des cas qui portent une attestation (5 valeurs) : AT-1 à AT-4
  relèvent des vérificateurs de ct-1 et de ct-7 ; AV-PR-2 suit alors le
  statut attendu.
- **PR-11** d'un paquet complet : les vecteurs sont des paquets allégés.
- **`all_images_by_digest` d'un fichier qui ne s'analyse pas**
  (`yaml-cle-dupliquee`) : le texte ne fixe pas cette valeur.
- **Détail de PR-2 non exécutée** dans le rapport de 13.7 : texte propre à
  l'outil.
- **`supervision/`** (A.1 : à produire avec l'extracteur et les règles,
  lot suivant) : rien à recalculer.
- **Manifestes des journaux** (3 cas : `valide-manifeste`,
  `manifeste-altere`, `signature-manifeste-fausse`) : le recalcul d'un
  manifeste (arbre de Merkle de CT-1 §10) n'est pas rejoué ; le verdict de
  ces cas est hors périmètre, leurs segments et leurs autres erreurs sont
  recalculés. E-1, E-3 à E-6, E-9 à E-11 et C-3 ne sont pas rejoués (aucun
  cas ne les attend).
- **OB-6** (`correspondance.json`, `reponses.json`) : l'évaluation des
  politiques de CT-3 relève du vérificateur Go de ct-3.
- **CA-5** : non exécutée sans les enregistrements bruts des sources, comme
  dans les vecteurs ; le détail des vérifications PV- et CA- est un texte
  propre à l'outil, seul le statut est comparé.

## Tests

`go test ./...` : `TestVecteurs` exige « tout concorde » sur
`spec/vecteurs/ct-8` ; les autres tests construisent des archives selon
EX-13.14 et vérifient que chaque défaut est arrêté par la bonne vérification
(PR-1 à PR-9, dont la casse, le répertoire d'un autre nom et l'ordre), le
découpage nom/préfixe, le code d'EX-13.26, les arrondis et Number::toString,
les refus d'EX-9.3, le remplacement d'un coefficient (EX-9.1), des branches
du contrôle préalable non exercées par les vecteurs (production sans seuil,
`--seulement`, moteur absent, plate-forme non Linux) et le motif
`$defs/chemin` de `paquet-reviseur-v0`.
