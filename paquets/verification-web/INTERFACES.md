# Interfaces de la page de vérification (CT-6 §18, révision 0.7)

Ce document est le contrat de l'étape 6 pour le paquet
`@noortrace/verification-web` : la page statique qui exécute, dans un
travailleur du navigateur, le vérificateur `noortrace-verifier` compilé en
WebAssembly (CT-6 §18). Avec CT-6 §4, §6, §8, §12, §14 et §18, le schéma
`rapport-verification-v0` et les dossiers de `spec/vecteurs/ct-1` et
`spec/vecteurs/ct-6`, il suffit.

CT-6 §18 n'impose pas d'emplacement : il exige que les fichiers de la page
soient produits « par un script du dépôt, de façon déterministe » (EX-18.6).
Ce paquet porte ce script et les sources de la page ; le vérificateur Go
(`verificateur/`) n'est pas modifié.

## 1. Ce que la page exécute

Le programme est `cmd/noortrace-verifier` du module `verificateur/`, **sans
commande nouvelle** : EX-18.3 compile le paquet principal des binaires pour
`GOOS=js GOARCH=wasm`, le module n'ayant aucun fichier propre à `js` ou à
`wasm` et n'important pas `syscall/js`. La construction ajoute au module un
seul fichier, un script :

```text
verificateur/scripts/construire-wasm.sh [-v <version>] -o <répertoire>
```

Il applique, et seulement elle, la recette d'EX-18.3 :

```bash
GOTOOLCHAIN=local GOENV=off GOFLAGS=-mod=vendor GOPROXY=off GOSUMDB=off CGO_ENABLED=0 \
GOOS=js GOARCH=wasm \
go build -trimpath -buildvcs=false -ldflags='-buildid= -X main.version=<version>' \
  -o <répertoire>/noortrace-verifier.wasm ./cmd/noortrace-verifier
```

(`GOAMD64` est omis), refuse toute autre chaîne que go1.27.3 (`go env
GOVERSION`), recopie sans changement `$(go env GOROOT)/lib/wasm/wasm_exec.js`
dans `<répertoire>/wasm_exec.js`, et imprime le SHA-256 des deux fichiers.
`<version>` est celle des binaires (défaut `0.1.0`, comme
`scripts/construire.sh`). Contrôles d'EX-18.3 :
`GOOS=js GOARCH=wasm go list -deps ./cmd/noortrace-verifier` ne nomme ni
`net/http`, ni `crypto/tls`, ni `os/exec`, et `syscall/js` n'est importé que
par `os` et `syscall` de la bibliothèque standard.

## 2. Fichiers produits

```text
node paquets/verification-web/src/construire.mjs --wasm <répertoire de construire-wasm.sh> --version <version> --sortie <répertoire>
```

Le script lit `noortrace-verifier.wasm` et `wasm_exec.js`, les sources de
`src/`, et écrit dans `<répertoire>` (qui doit être absent ou vide), de façon
déterministe (aucune date, aucun aléa, aucun chemin de la machine) :

| Fichier | Contenu (EX-18.5, EX-18.6, table de 18.3) |
|---|---|
| `index.html` | la page ; aucun script ni style en ligne, aucun attribut de gestionnaire d'événement ; `<link rel="stylesheet" href="page.css" integrity="sha384-…" crossorigin="anonymous">`, `<script src="verificateur-wasm.js" integrity="sha384-…" crossorigin="anonymous"></script>`, `<script src="page.js" integrity="sha384-…" crossorigin="anonymous"></script>`, dans cet ordre (`crossorigin="anonymous"` exigé sous `Integrity-Policy`, CT-6 0.7, EX-18.6) ; `lang="fr"` |
| `page.css` | les styles ; polices du système |
| `page.js` | un seul script classique, sans importation (aucune requête après le chargement, EX-18.11) : choix des fichiers, lecture des archives, transmission au travailleur, affichage |
| `verificateur-wasm.js` | exactement `globalThis.NOORTRACE_VERIFICATEUR_WASM = "`, le base64 (RFC 4648 §4, avec remplissage, sans saut de ligne) de `noortrace-verifier.wasm`, `";`, LF |
| `travailleur.js` | le prélude (système de fichiers, `process`, `path`, EX-18.8), puis `wasm_exec.js` sans changement, puis le pilote (constante `EMPREINTE_WASM`, exécutions d'EX-18.9) |
| `noortrace-verifier.wasm` | l'artefact, publié pour comparaison ; la page ne le charge pas |
| `SHA256SUMS` | `<sha256>  <fichier>` pour chacun des six fichiers ci-dessus, triés par nom (format de `sha256sum`), à reporter dans le `SHA256SUMS` signé de la version (EX-14.9, EX-18.4) |
| `en-tetes.json` | pour l'hébergeur et les essais : par fichier, les en-têtes d'EX-18.12, exactement |

Deux exécutions du script sur les mêmes entrées donnent les mêmes octets.
Les fichiers produits ne sont pas versionnés.

Sources (`src/`) : `construire.mjs` ; `page/` (`index.modele.html`,
`page.css`, modules de `page.js` assemblés par le script : archives,
interface, libellés français et anglais) ; `travailleur/` (`prelude.js`,
`pilote.js`). Les modules d'archive (ZIP, `tar` `ustar`, `pax` et GNU,
gzip) sont écrits dans le paquet ; la décompression `deflate` et gzip emploie
`DecompressionStream` du navigateur (`deflate-raw`, `gzip`), sans
dépendance.

## 3. Page et travailleur

### 3.1 Messages

`page.js` crée le travailleur une fois, depuis `travailleur.js`, par la
politique de types de confiance `noortrace-travailleur` (créée une fois,
elle rend `travailleur.js` et refuse toute autre valeur), ou, sans types de
confiance, par la chaîne constante `travailleur.js` (EX-18.12). Messages
(`postMessage`, octets transférés) :

| Sens | Message |
|---|---|
| page → travailleur | `{ "type": "artefact", "octets": ArrayBuffer }` : les octets décodés de `NOORTRACE_VERIFICATEUR_WASM`, une fois |
| travailleur → page | `{ "type": "artefact_pret", "version", "empreinte" }` (empreinte `0x…`, EX-18.5) ou `{ "type": "artefact_altere", "calculee", "attendue" }` (rien n'est compilé) |
| page → travailleur | `{ "type": "verifier", "fichiers": [ { "chemin", "octets" } ], "repertoires": [ chemin ], "options": { "ancres", "entetes", "exiger", "langue", "detail" } }` ; `chemin` relatif à `/entrees` : `dossier/<chemin relatif>`, `ancres.json`, `entetes-bitcoin.json` ; `repertoires`, facultatif : les entrées de répertoire d'une archive, que l'arbre présente même vides ; `options.ancres` et `options.entetes`, booléens, concordent avec la présence d'`ancres.json` et d'`entetes-bitcoin.json` ; `options.langue` toujours donnée (EX-18.8) |
| travailleur → page | `{ "type": "resultat", "executions": [ { "arguments", "code", "sortie", "erreur" }, { … } ] }` (lisible puis `--json` ; `sortie` et `erreur` en `Uint8Array`) ou `{ "type": "non_faite", "cause" }` ; `non_faite` aussi en réponse à `artefact`, quand `WebAssembly.compile` échoue (la page affiche alors « vérification non faite », EX-18.9, EX-18.12) |

### 3.2 Exécution

Le travailleur calcule `crypto.subtle.digest("SHA-256", octets)` et le
compare à `EMPREINTE_WASM` avant `WebAssembly.compile` ; chaque exécution est
une instance neuve du module compilé, avec `go.argv` =
`["noortrace-verifier", "dossier", …]` dans l'ordre d'EX-18.8 (`--ancres
ancres.json`, `--entetes-bitcoin entetes-bitcoin.json`, puis `--exiger`
(forme canonique d'EX-8.2, numéros croissants), `--langue`, `--detail`,
`--json`), `go.env` vide, le répertoire de travail `/entrees`, et le code de
sortie lu par `go.exit`. L'arbre en lecture seule, ses erreurs POSIX, ses
modes, ses couples (`dev`, `ino`), ses membres d'état et les objets
`process` et `path` sont exactement ceux d'EX-18.8 ; les sorties 1 et 2 sont
recueillies par `write` et par `writeSync`, qu'emploie l'environnement
d'exécution de Go pour ses messages d'arrêt (CT-6 0.7, EX-18.8) ; après
chaque exécution, le pilote annule les minuteries laissées programmées
(EX-18.9).

### 3.3 Affichage

Selon EX-18.2, EX-18.5, EX-18.7 et EX-18.9 : phrase fixe permanente, version
et empreinte, noms des fichiers choisis et ligne de commande équivalente,
rapport lisible dans un `<pre>` par `textContent`, code et son sens, énoncé
en français et en anglais (`statement.fr`, `statement.en`) pour 0, 1 et 3,
« Aucune affirmation sur ce dossier. » pour 2, sortie d'erreur ; « aucun
rapport » sur un refus d'archive ; « vérification non faite » quand les
deux codes diffèrent ou qu'une exécution n'a pas de code. Langue de la page :
français, anglais au choix, par une table de libellés de mêmes clés.

## 4. Hébergement

La page est servie sur une origine distincte de toute console et de toute
application d'exploitant, qui ne sert rien d'autre (EX-18.11), avec les
en-têtes d'EX-18.12 (`en-tetes.json`). Ce paquet ne contient pas de serveur :
les essais servent les fichiers par interception des requêtes dans
Playwright, sur une origine HTTPS fictive, avec ces en-têtes.

## 5. Essais

Fichiers `test/verification-page-*.test.js`, outils sous
`test/fixtures/verification-page/`. Sans go1.27.3, la construction est mise
en attente avec un message (comme les essais Go existants) ; sans
Playwright ou sans navigateur, les essais de navigateur aussi, et ils
échouent sous `NOORTRACE_EXIGER_CHROMIUM=1`.

- Reproductibilité (EX-18.4) : deux constructions, depuis deux copies des
  sources à deux chemins, avec deux caches vides, donnent les mêmes octets
  pour l'artefact et pour chaque fichier produit.
- Identité (EX-18.10), sous Node, le prélude et le pilote de
  `travailleur.js` exécutés tels quels : chaque dossier de
  `spec/vecteurs/ct-1/dossiers` et de `spec/vecteurs/ct-6/dossiers`, avec et
  sans `ancres-test.json` et `chaine.json`, en français et en anglais, avec
  et sans `--exiger 4,5,8`, rend la même sortie standard, la même sortie
  d'erreur et le même code, octet pour octet, que le binaire natif de la
  même construction exécuté dans un répertoire `/entrees` équivalent.
- Dans Chromium (Playwright 1.56.1) : la page sous les en-têtes d'EX-18.12 ;
  un échantillon fixé de dossiers (au moins un par code 0, 1, 2 et 3), chacun
  comme répertoire et sous chaque forme d'archive d'EX-18.7 fabriquée par les
  recettes d'EX-18.13 ; chaque refus d'archive ; aucune requête après le
  chargement, aucune violation de politique ; artefact altéré d'un octet non
  compilé et aucun rapport (TA-101) ; stockage vide et aucun service worker
  après une vérification ; en-têtes présents.
- Gecko et WebKit : la même suite quand Playwright les a installés, en
  attente sinon ; l'épreuve complète d'EX-18.13 dans les trois moteurs, en
  leur dernière version publiée, précède la publication d'une version.

## 6. État et précisions (étape 6)

Fait à l'étape 6, et éprouvé par les quatre fichiers d'essai de la section 5
(voir `LISEZMOI.md`) : `verificateur/scripts/construire-wasm.sh`,
`src/construire.mjs`, la page, le travailleur, la lecture des archives.
Chromium seul est éprouvé ; Gecko et WebKit restent en attente.

Précisions que l'écriture a imposées, consignées ici plutôt que changées en
silence dans les sections précédentes :

1. **`crossorigin="anonymous"`** sur le `link` et les deux `script`
   d'`index.html`. Mesure (Chromium 141.0.7390.37) : sous
   `Integrity-Policy: blocked-destinations=(script style)`, un script classique
   de même origine qui porte `integrity` mais pas `crossorigin` est bloqué
   (requête en mode `no-cors`, échec « integrity ») ; avec `crossorigin`, il
   se charge. Le même navigateur écrit, pour la valeur d'EX-18.12, « The
   Integrity-Policy destination 'style' is not supported. » ; ce n'est pas
   une violation, les essais le relèvent à part. Le travailleur (destination
   `worker`) se charge sous cet en-tête sans attribut d'intégrité.
2. **Message `verifier`** : membre facultatif `repertoires` (liste de
   chemins relatifs à `/entrees`), pour les entrées de répertoire d'une
   archive, que l'arbre présente même vides. `options.ancres` et
   `options.entetes` sont des booléens, qui doivent concorder avec la
   présence de `ancres.json` et de `entetes-bitcoin.json` dans `fichiers`.
3. **`non_faite` après `artefact`** : si `WebAssembly.compile` échoue (par
   exemple une politique qui refuserait `'wasm-unsafe-eval'`), le
   travailleur répond `{ "type": "non_faite", "cause" }` et la page affiche
   « vérification non faite » (EX-18.12, EX-18.9).
4. **`writeSync`** : en plus de `write`, l'arbre recueille
   `fs.writeSync` sur les descripteurs 1 et 2, qu'emploie l'environnement
   d'exécution de Go (`runtime.wasmWrite`) pour ses messages d'arrêt.
5. **Minuteries** : après chaque exécution, le pilote annule les minuteries
   que le programme a laissées programmées (`go._scheduledTimeouts` de
   `wasm_exec.js`) ; leur échéance après la sortie lèverait « Go program has
   already exited » pendant l'exécution suivante (constaté par l'essai
   d'identité).
6. **`syscall/js`** (section 1) : sous go1.27.3, les paquets de la
   bibliothèque standard qui l'importent, parmi les dépendances de
   `cmd/noortrace-verifier`, sont `syscall` et `time` (`zoneinfo_js.go`, qui
   lit le fuseau du navigateur), et non `os` et `syscall` ; aucun paquet du
   module ni de `vendor/` ne l'importe. Question posée au porteur.
7. **Refus d'EX-18.7** : une archive mal formée (sommes de contrôle, CRC-32,
   tailles, données tronquées, flux comprimé invalide) est refusée comme
   « archive mal formée » ; la borne de 256 Mio porte sur la somme des tailles
   décompressées des entrées d'un ZIP et sur le flux tar (décompressé pour
   `.tar.gz`) ; les 4 096 entrées comptent les entrées de fichier et de
   répertoire, `.` comprise, sans les en-têtes `x`, `g` et `L`. Un répertoire
   choisi n'est soumis à aucune de ces bornes, qu'EX-18.7 ne pose que pour
   les archives. **Tranché par CT-6 0.7 (EX-18.7)** : un répertoire choisi
   est soumis aux mêmes bornes, comptées sur ses fichiers et
   sous-répertoires et sur la somme des tailles de ses fichiers, avant toute
   lecture (`bornesRepertoire` d'`archives.js`, appelée par l'interface).
8. **`construire-wasm.sh`** refuse de construire si `GOWASM`,
   `GOEXPERIMENT` ou `GOFIPS140` sont posées dans l'environnement : la
   recette d'EX-18.3 ne les nomme pas, `GOENV=off` ne les neutralise pas, et
   elles changent l'artefact. **Tranché par CT-6 0.7 (EX-14.6, EX-18.3)** :
   la recette les vide (`GOEXPERIMENT= GOFIPS140= GOWASM=`, écrites dans la
   ligne `env` des deux scripts de `verificateur/scripts/`) ; un script peut
   refuser une valeur non vide, ce que font `construire-wasm.sh` et
   `construire.sh`.

Les points 1 à 5 sont versés dans les sections 2 et 3 ci-dessus (révision
0.7 de CT-6) ; le point 6 est inscrit dans CT-6 0.7 (EX-18.3, annexe B.9).
