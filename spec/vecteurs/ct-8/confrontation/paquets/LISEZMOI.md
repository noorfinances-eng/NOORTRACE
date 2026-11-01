# Confrontation des paquets réviseurs (CT-8, annexe A.15)

Les deux programmes de ce répertoire lisent chaque archive de
`spec/vecteurs/ct-8/paquets/` avec des outils tiers, sans le code du dépôt
(EX-A.32 à EX-A.35). Ils n'ouvrent aucune connexion et n'écrivent que dans
le répertoire de travail qu'on leur donne, qui doit être neuf et vide. Le
générateur des vecteurs n'écrit ni n'efface ce répertoire (EX-A.1).

| Programme | Outils tiers | Ce qu'il fait |
|---|---|---|
| `confronter_gnutar.sh` | GNU tar, `sha256sum` (GNU coreutils), `jq` | SHA-256 de chaque archive comparé à `archive_sha256` de `cas.json` ; liste par `tar --list --verbose --numeric-owner --full-time` (locale C, fuseau UTC) ; extraction par `tar -xf` dans un répertoire neuf et vide, code et messages ; liens extraits ; entrées apparues hors de la destination ; `sha256sum --strict -c` de chaque fichier déclaré par le manifeste extrait ; fichiers extraits absents du manifeste ; membres listés comparés au manifeste (nom répété, type, membre non déclaré, taille) ; reconstruction de `valide.tar` par la recette d'EX-13.15 et `cmp` |
| `confronter_tarfile.py` | `tarfile` de Python, filtre `data` ; `hashlib` | SHA-256 de chaque archive comparé à `cas.json` ; membres lus (type, nom, taille, mode, propriétaires, date, cible de lien, en-têtes pax) ; `extractall(filter="data")` dans un répertoire neuf et vide, exception éventuelle ; liens extraits ; entrées hors de la destination ; SHA-256 des fichiers extraits contre le manifeste ; membres lus comparés au manifeste |

## Commandes

Depuis la racine du dépôt, chaque programme dans un répertoire de travail
neuf, vide et hors du dépôt :

```bash
T=$(mktemp -d)
mkdir "$T/gnutar" "$T/tarfile"
bash spec/vecteurs/ct-8/confrontation/paquets/confronter_gnutar.sh \
    spec/vecteurs/ct-8/paquets "$T/gnutar" \
    > spec/vecteurs/ct-8/confrontation/paquets/sorties/gnutar.txt
python3 -I spec/vecteurs/ct-8/confrontation/paquets/confronter_tarfile.py \
    spec/vecteurs/ct-8/paquets "$T/tarfile" \
    > spec/vecteurs/ct-8/confrontation/paquets/sorties/tarfile.txt
```

Code de retour : 0 sans discordance, 1 avec au moins une discordance, 2 pour
un usage incorrect (arguments, répertoire de travail non vide, outil absent,
`tar` qui n'est pas GNU tar, `cas.json` illisible). Les sorties ne portent
aucun chemin local : le répertoire de travail y est écrit `<travail>`. Deux
exécutions dans des répertoires neufs donnent les mêmes octets.

Versions des sorties publiées (lues par les programmes et imprimées en
première ligne) : GNU tar 1.35, GNU coreutils 9.4, `jq` 1.7, Python 3.13.16.
Une autre implémentation de `sha256sum` (uutils coreutils) est admise :
seuls ses condensés comptent ; `tar` doit rester GNU tar (code 2 sinon).

## Règle de comparaison

Pour chaque archive, l'attendu est le cas de `cas.json` sans option qui
porte sur elle (`valide`, `fichier-altere`, etc.) : `package_status` et la
vérification PR- en échec. Chaque programme écrit une ligne `-- résultat`
avec l'un de ces verdicts :

| Attendu de CT-8 | `concorde` | `limite_de_l_outil` | `DISCORDANCE` |
|---|---|---|---|
| paquet intact | extraction acceptée, aucun écart au manifeste, aucun lien | — | tout autre résultat |
| PR-8 en échec (contenu contre le manifeste) | l'écart est trouvé (SHA-256, fichier absent ou en trop) ou l'extraction est refusée | — | aucun écart trouvé |
| PR-4, PR-5 ou PR-6 en échec | l'outil refuse l'extraction | l'outil accepte l'archive | — |

Une entrée apparue hors de la destination (trois niveaux au-dessus de
chaque destination sont surveillés), ou une archive dont le SHA-256 n'est
pas celui de `cas.json`, est toujours une discordance. La dernière ligne de
chaque sortie donne le bilan.

## Résultats publiés

Treize archives. Aucune discordance ; aucun des deux outils n'a écrit hors
de son répertoire de destination ; `valide.tar` est reconstruit à
l'identique par GNU tar (SHA-256
`8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982`).

| Archive | Règle de CT-8 | GNU tar | `tarfile` (`data`) |
|---|---|---|---|
| `valide.tar` | intact | `concorde` | `concorde` |
| `observation.tar` | intact (EX-A.15) | `concorde` | `concorde` |
| `contrefacon-coherente.tar` | intact (dossier invalide, 13.10) | `concorde` | `concorde` |
| `fichier-altere.tar` | PR-8 | `concorde` (`sha256sum` : 1 échec) | `concorde` (SHA-256 différent) |
| `fichier-manquant.tar` | PR-8 | `concorde` (fichier absent) | `concorde` (fichier absent) |
| `fichier-en-trop.tar` | PR-8 | `concorde` (fichier en trop) | `concorde` (fichier en trop) |
| `manifeste-altere.tar` | PR-8 | `concorde` (`sha256sum` : 1 échec) | `concorde` (SHA-256 différent) |
| `chemin-hors-archive.tar` | PR-5 | `concorde` (code 2, « Member name contains '..' ») | `concorde` (`OutsideDestinationError`) |
| `chemin-absolu.tar` | PR-5 | `limite_de_l_outil` | `limite_de_l_outil` |
| `nom-en-double.tar` | PR-5 | `limite_de_l_outil` | `limite_de_l_outil` |
| `lien-symbolique.tar` | PR-4 | `limite_de_l_outil` | `concorde` (`LinkOutsideDestinationError`) |
| `lien-physique.tar` | PR-4 | `limite_de_l_outil` | `limite_de_l_outil` |
| `metadonnees-non-fixees.tar` | PR-6 | `limite_de_l_outil` | `limite_de_l_outil` |

Les membres listés par GNU tar et lus par `tarfile` (nom, type, taille,
mode, propriétaires, date, cible de lien) sont, un à un, ceux que lit
l'outil de référence (`lireArchive` de `scripts/lib/paquet.mjs`) ; les
écarts au manifeste qu'ils trouvent sont ceux que PR-8 signale. Le test
`test/confrontation.test.js` l'exige, et exige que les résultats égalent la
table d'EX-A.32.

## Limites des outils tiers (EX-A.33, EX-A.35)

Ce qu'un outil accepte et que CT-8 refuse n'est pas une discordance : CT-8
est plus strict que ces outils par choix (EX-13.14).

- Nom absolu (`chemin-absolu.tar`) : GNU tar retire le `/` initial
  (« Removing leading `/' from member names ») et extrait le fichier sous la
  destination, code 0 ; le filtre `data` de `tarfile` fait de même. Le
  fichier n'apparaît qu'à la comparaison au manifeste. CT-8 le refuse (PR-5).
- Nom en double (`nom-en-double.tar`) : les deux outils extraient les deux
  entrées, la seconde remplace la première ; seule la comparaison au
  manifeste le révèle (SHA-256 de `LISEZMOI.md`). La documentation de
  `tarfile` le dit : une archive peut porter plusieurs versions d'un fichier,
  la dernière l'emporte (R9-F19).
- Lien symbolique vers l'extérieur (`lien-symbolique.tar`) : GNU tar crée le
  lien sans le suivre, code 0 (il refuse de suivre un lien qui sort du
  répertoire de travail, R9-F13) ; un programme lancé ensuite le suivrait.
  Le filtre `data` le refuse (`LinkOutsideDestinationError`) et arrête
  l'extraction : les fichiers qui suivent dans l'archive ne sont pas
  extraits (46 écarts au manifeste).
- Lien physique interne (`lien-physique.tar`) : les deux outils créent
  `ancres/double`, lien vers un fichier de l'archive ; il n'apparaît qu'à la
  comparaison au manifeste. Le filtre `tar` de Python accepte même un lien
  physique vers un fichier extérieur par chemin absolu (R9-F22).
- Mode `0600` (`metadonnees-non-fixees.tar`) : aucun des deux outils ne
  vérifie les métadonnées ; le contenu est intact. Seule PR-6 le refuse.
- Nom contenant `..` (`chemin-hors-archive.tar`) : GNU tar refuse le membre
  (code 2) mais extrait les autres ; `tarfile` s'arrête au premier refus,
  avant d'extraire le manifeste.
- `tarfile` sans filtre, en Python 3.13, écrit hors de la destination
  (fichier absolu, `..`, écriture à travers un lien symbolique, lien
  physique vers un fichier extérieur : R9-F22) ; le filtre par défaut ne
  devient `data` qu'en Python 3.14 (R9-F17, R9-F20). L'argument `filter`
  n'existe pas avant Python 3.12 ; le test ne rejoue le programme qu'à
  partir de cette version.
- GNU tar 1.35 a aussi été mesuré face à quatre archives piégées autres que
  ces vecteurs (R9-F16) : nom absolu ramené sous la destination, `..`
  refusé, lien symbolique absolu créé, lien physique absolu refusé ; rien
  n'a été écrit hors de la destination. Ces mesures ne valent que pour ces
  cas.

On n'extrait jamais une archive non fiable avec `tar -P`
(`--absolute-names`) ni `tar -h` (`--dereference`), qui lèvent ces
protections (R9-F13, R9-F15), ni avec `extractall` sans filtre (R9-F17) ;
on extrait dans un répertoire neuf et vide (R9-F13, R9-F19).

## Intégration continue

Le travail `confrontation` de `.github/workflows/ci.yml` rejoue les deux
programmes dans des répertoires neufs (code 0 exigé), compare leurs sorties
aux sorties publiées, octet pour octet quand la première ligne (versions des
outils) est la même, puis applique aux nouvelles sorties le test de
`test/confrontation.test.js` (variable `NOORTRACE_CT8_SORTIES`) : un
changement de version qui change un résultat (code, lien, écart, exception,
verdict) fait échouer la CI ; un libellé différent d'une autre version, non.
Les versions de l'exécuteur sont celles qu'imprime la première ligne de
chaque sortie ; elles ne sont pas épinglées par ce répertoire.
