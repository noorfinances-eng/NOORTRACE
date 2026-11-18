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
| `index.html` | la page ; aucun script ni style en ligne, aucun attribut de gestionnaire d'événement ; `<link rel="stylesheet" href="page.css" integrity="sha384-…" crossorigin="anonymous">` et `<script src="page.js" integrity="sha384-…" crossorigin="anonymous"></script>` dans l'en-tête, `<script src="verificateur-wasm.js" integrity="sha384-…" crossorigin="anonymous"></script>` à la fin du corps, dans cet ordre (`crossorigin="anonymous"` exigé sous `Integrity-Policy`, CT-6 0.7, EX-18.6 ; place des scripts : complément du 2026-11-17, point 10 de la section 6) ; `lang="fr"` |
| `page.css` | le bloc de style commun aux écrans NOORTRACE (repères `/* noor-theme:debut */` et `/* noor-theme:fin */`), puis les styles de la page ; polices du système, aucune adresse |
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
deux codes diffèrent, qu'une exécution n'a pas de code, que la `version` du
bloc `verifier` du rapport JSON n'est pas celle que la page annonce, ou que
l'utilisateur a arrêté la vérification.

Présentation (complément du 2026-11-17 de CT-6 §18 ; point 10 de la
section 6). Identifiants stables de l'affichage, que les essais lisent :

| Élément | Contenu | Replié |
|---|---|---|
| `#phrase-fixe`, `#etat-verificateur` | phrase d'EX-18.2 ; état du vérificateur (en chargement, prêt, indisponible) | jamais |
| `#artefact` | phrase d'EX-18.5 (version et empreinte) dans `#detail-empreinte` ; artefact altéré ou vérificateur indisponible : dans `#alerte-verificateur` | seulement quand le vérificateur est prêt |
| `#options` | fichier d'ancres, fichier d'en-têtes, `--exiger`, `--langue`, `--detail` ; `#resume-options` résume les choix dans son titre | oui |
| `#dossier-choisi`, `#verifier`, `#arreter` | dossier choisi, lancement, arrêt | jamais |
| `#verdict`, `#verdict-mot`, `#code` | grand verdict : mot tiré du code de retour, phrase du code (table de CT-6 §8.3) | jamais |
| `#tous-reussis`, `#verdict-borne`, `#exiges-non-reussis`, `#resume-indisponible` | sous le verdict : les huit contrôles réussis ; « Contrôles qui n'ont pas pu être faits : n° … » ; contrôles exigés non réussis ; liste des contrôles illisible | jamais |
| `#avertissements`, `#sortie-erreur` | `warnings` du rapport JSON ; sortie d'erreur non vide | jamais (une sortie d'erreur vide est dite vide dans `#detail-rapport`) |
| `#enonce-fr`, `#enonce-en` | énoncés, tels quels | celui de l'autre langue, dans `#detail-enonce-autre` |
| `#controles` (`li[data-numero][data-statut]`) | les huit contrôles de `controls` : statut, raison de CT-6 §6.2 et son code, `summary` | jamais |
| `#message-erreur`, `#aucune-affirmation` | code 2 : `error.message`, phrase fixe | jamais |
| `#rapport-lisible`, `#rapport-json`, `pre.commande` | sortie standard des deux exécutions et ligne de commande équivalente, telles quelles | oui (`#detail-rapport`, `#detail-json`, `#detail-commande`) |
| `.aucun-rapport`, `.alerte`, `.non-faite`, `.cause` | refus d'archive ; « vérification non faite » et sa cause | jamais |

Langage (complément du 2026-11-18 de CT-6 §18). S'ajoutent aux identifiants
ci-dessus, sans en retirer :

| Élément | Contenu | Replié |
|---|---|---|
| `#garantie`, `#confiance-courante` | la garantie en clair, toujours sous le titre ; la mise en garde d'EX-18.2 en langage courant, au-dessus de `#phrase-fixe` | jamais |
| `#confiance` | le bandeau qui porte `#confiance-courante`, `#phrase-fixe`, `#alerte-verificateur` et `#detail-empreinte` : avant `#formulaire` à l'arrivée ; dans `#resultat-contenu`, juste avant `#specialistes`, dès qu'un rapport, un refus ou une vérification non faite a été affiché ; de nouveau en tête si le vérificateur est altéré ou indisponible | jamais |
| `#comment` | « Comment ça marche », cinq lignes | oui |
| `#options-specialistes` | dans `#options` : le nom de la ligne de commande de chaque option | oui |
| `#dossier-verifie`, `#nom-verifie`, `#verifier-autre` | après un rapport : le dossier examiné, et le bouton qui ramène les étapes (`#formulaire` porte alors la classe `pv-reduit`) | jamais |
| `#phrase-courante` | sous `#verdict-mot` : la phrase en langage courant du code de retour, d'un refus ou d'une vérification non faite | jamais |
| `#reserves` | la ligne fixe des réserves, quand `warnings` porte un avertissement ou ne se lit pas (codes 0 et 3) | jamais |
| `#code` | inchangé (« Code de retour … »), dans une ligne `.pv-exact` (`#formule-exacte`) introduite par « Formule exacte du vérificateur : », en tête de `#specialistes` (troisième lecture) | jamais |
| `#avertissements li.pv-reserve[data-id]` | `.pv-reserve-courante` (phrase de la table, absente hors table), puis `.pv-reserve-exacte` (texte du vérificateur) | jamais |
| `#controles li` | `.nt-controle-titre`, `.pv-controle-prouve`, `.pv-controle-raison` (non fait), `.pv-controle-echec` et `.pv-controle-dit` (échoué) | jamais |
| `#detail-controles .pv-resume-exact[data-numero]` | le `summary` de chaque contrôle, tel quel | oui |
| `#enonce-fr .pv-membre`, `#enonce-en .pv-membre` | les membres de phrase de l'énoncé ; leur concaténation est l'énoncé | comme l'énoncé |
| `#limites`, `#suite`, `#imprimer` | « Ce que ce résultat ne dit pas » ; « Et maintenant ? » ; impression | jamais |
| `#refus-courant` | la raison d'un refus en langage courant, au-dessus de `.alerte` (raison exacte) | jamais |
| `#specialistes` | titre et phrase au-dessus de `#detail-rapport`, `#detail-json`, `#detail-commande` | ses blocs, oui |

Seconde lecture, même date (CT-6 §18, EX-18.9, points 14 à 19). S'ajoutent :

| Élément | Contenu | Replié |
|---|---|---|
| `#verdict-titre` | le titre du verdict : `#verdict-mot` (le mot du code, seul dans son élément) puis, sous le code 0 restreint, `#verdict-mention` | jamais |
| `#verdict` (classes) | `nt-verdict-valide` seulement pour huit contrôles réussis sans avertissement ; sinon `pv-verdict-reserve` (un contrôle non réussi ou un avertissement) ou `pv-verdict-neutre` (rapport qui ne se lit pas exactement) | jamais |
| `#non-prouve` | sous le titre : ce que les contrôles non réussis laissent sans preuve, en mots | jamais |
| `#controles li[data-reserves]` | contrôle réussi auquel le rapport rattache un avertissement : pastille « Réussi, avec réserve », identifiants dans `data-reserves`, `.pv-controle-reserve` avec un lien vers `#avertissements` | jamais |
| `#avertissements li.pv-reserve[data-fois]` | une réserve par identifiant de la table : `.pv-reserve-fois` quand elle est signalée plusieurs fois, puis une `.pv-reserve-exacte` par avertissement | jamais |
| `#en-resume` (`li[data-ligne]`), `#resume-fin` | « En résumé », avant `#enonce` : `action`, `periode`, `approbation`, `limite_autorite`, `limite_bitcoin` ; la phrase finale | jamais |
| `.pv-controle-dit[data-verification]` | code 1 : ce que le vérificateur dit d'une vérification en échec (`detail`), l'identifiant à la fin ; sur la ligne du contrôle qui la porte, sinon sous le verdict | jamais |
| `#piece-en-cause` | code 2 : la pièce en cause, d'après `error.kind` | jamais |
| `#refus-titre` | titre courant d'un refus, au-dessus de `.aucun-rapport` (introduite par « Mention fixée pour un refus : ») | jamais |
| `#dossier-choisi.pv-choisi-refuse` | étape 1, tant qu'un refus du dossier choisi est affiché | jamais |

Troisième lecture, même date (CT-6 §18, EX-18.7 et EX-18.9). S'ajoutent, sans
rien retirer ; `#code` et `.aucun-rapport` ne sont plus dans `#verdict` :

| Élément | Contenu | Replié |
|---|---|---|
| `#verdict-titre.pv-titre-mention` | titre dont le mot porte une mention : le mot et la mention à la même taille | jamais |
| `#formule-exacte` | en tête de `#specialistes`, après sa phrase : la ligne qui porte `#code` | jamais |
| `#mention-refus` | après un refus, en tête de `#specialistes` : la ligne qui porte `.aucun-rapport` (« Mention fixée pour un refus : ») | jamais |
| `#controles .pv-controle-raison` | la phrase d'un contrôle non fait, d'après la raison, le contrôle et les pièces ajoutées à l'étape 2, puis la raison exacte (`data-valeur`) entre parenthèses | jamais |
| `#consigne-ancres` | étape 2 : la consigne de sûreté sur la liste des références de confiance, à la taille du texte courant | avec `#options` |
| `#nom-ancres.pv-fichier-refuse`, `#nom-entetes.pv-fichier-refuse` | étape 2, tant qu'un refus de cette pièce complémentaire est affiché | avec `#options` |
| `#verifier` | inactif tant qu'un refus est affiché ; `#aide-verifier` dit pourquoi | jamais |

`presentationVerdict`, `clesNonProuve`, `controlesDeLAvertissement`,
`grouperAvertissements`, `clePieceEnCause` et `lignesEnResume` (section
« Langage courant » d'`interface.js`) sont des fonctions sans effet, que les
essais chargent telles qu'écrites.

`data-exact` marque un élément dont le texte est celui du vérificateur ou une
phrase fixée par CT-6 (`#phrase-fixe`, `#artefact`, `#code`, les énoncés,
`.pv-reserve-exacte`, `#sortie-erreur`, `#message-erreur`, la raison exacte
d'un refus, `.pv-resume-exact`, les trois textes préformatés) ; `data-valeur`
marque une valeur venue des données posée dans une phrase de la page.

Le mot du verdict ne dépend que du code de retour. La liste des contrôles ne
montre que des valeurs du rapport JSON : `lireControles` rend `null` (aucune
liste, « résumé indisponible ») si `controls` n'est pas exactement huit
contrôles numérotés de 1 à 8, de statut `reussi`, `echoue` ou `non_execute`,
avec une raison pour un contrôle non exécuté et pour lui seul, ou si la liste
contredit le code (sous 0 ou 3, un contrôle `echoue` ou non exécuté pour
`prerequis_en_echec`). Thème : `data-theme="clair"` sur `<html>` pour l'état
clair, aucun attribut pour le sombre ; état initial selon
`prefers-color-scheme`, bascule par `#bascule-theme`, aucun stockage. Toute chaîne venue d'une entrée passe
par `neutraliser` avant `textContent` : commandes C0 (sauf tabulation et saut
de ligne), DEL, C1, U+2028, U+2029 et marques de direction sont affichées
sous la forme visible `\u{…}`. Langue de la page :
français, anglais au choix, par une table de libellés de mêmes clés.

### 3.4 Bornes et arrêt (revue de sécurité de l'étape 8)

Les bornes d'EX-18.7 sont des constantes nommées, en un seul endroit
(`BORNES_ARCHIVE` d'`archives.js`) : 4 096 entrées, 256 Mio décompressés,
64 composants et 4 096 octets UTF-8 par chemin d'entrée (`r_chemin_long`,
appliquée avant tout autre examen du chemin, en temps linéaire), 512 Mio par
fichier lu, contrôlée sur la taille déclarée par le navigateur avant toute
lecture (`r_fichier_trop_gros`). Le parcours d'un répertoire déposé s'arrête à
la première entrée de trop ou au premier chemin trop long. L'arbre du
travailleur est numéroté sans récursion. Le bouton « Arrêter » (`#arreter`,
actif pendant une vérification) détruit le travailleur, affiche
« vérification non faite » avec la cause, et un travailleur neuf reçoit
l'artefact : c'est la seule requête que la page fait après son chargement
(`travailleur.js`, même origine). Aucun délai n'est imposé.

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
- Présentation (complément du 2026-11-17), `verification-page-presentation.test.js` :
  sous Node, lecture des contrôles, libellés, gabarit, feuille de style ;
  dans un navigateur, sans chaîne Go (artefact factice, travailleur de
  remplacement, rapports écrits par l'essai) : verdict selon le code, liste
  selon le rapport, contrôle non exécuté jamais montré réussi (deux mutants
  tués), rapports intacts dans leurs blocs repliés, avertissements visibles,
  thème sans stockage ; de bout en bout avec go1.27.3 sur cinq dossiers des
  vecteurs.
- Langage (complément du 2026-11-18), même fichier : sous Node, les tables de
  phrases (par code de retour, par avertissement, « ce que ce résultat ne dit
  pas ») égales à celles de CT-6 §18 dans les deux langues, aucune phrase hors
  table, membres de phrase d'un énoncé, aucun libellé du premier niveau ne
  porte un terme de technicien ; dans un navigateur : phrase du code et
  d'aucun autre, formule exacte entière dessous, réserves, avertissement hors
  table sans phrase, énoncé et texte copié intacts, réduction des étapes après
  un rapport, mot du verdict et début de sa phrase sur le premier écran sans
  défiler à 1280×800 et à 390×844, aucun terme de technicien au premier niveau
  de chaque écran en français et en anglais ; neuf mutants tués.
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

9. **Revue de sécurité de l'étape 8** (EX-18.8,
   EX-8.6) : bornes de 64 composants et 4 096 octets par
   chemin et de 512 Mio par fichier (section 3.4), valeurs proposées au
   porteur et à écrire dans CT-6 EX-18.7 ; bouton « Arrêter » et nouvelle
   demande de `travailleur.js` après un arrêt, à écrire dans EX-18.9 et
   EX-18.11 ; comparaison de la version du rapport, à écrire dans EX-18.9 ;
   neutralisation des chaînes affichées, à rattacher à la règle commune
   d'EX-8.5 et EX-8.6.

10. **Présentation des écrans (complément du 2026-11-17, décision du
    porteur)**, écrit dans CT-6 §18 (18.3, EX-18.5, EX-18.6, EX-18.7,
    EX-18.9, EX-18.11) : thème commun aux écrans du dépôt, en deux états
    sans stockage ; `page.js` dans l'en-tête, `verificateur-wasm.js` en fin
    de corps ; options et empreinte dans des blocs repliés ; grand verdict,
    liste des contrôles et avertissements tirés du code de retour et du
    rapport JSON ; rapport lisible, rapport JSON (affiché depuis ce
    complément) et ligne de commande dans des blocs repliés, tels quels ;
    bouton « Copier ». Les messages entre la page et le travailleur, le
    travailleur, le prélude et l'artefact ne changent pas.

Les points 1 à 5 sont versés dans les sections 2 et 3 ci-dessus (révision
0.7 de CT-6) ; le point 6 est inscrit dans CT-6 0.7 (EX-18.3, annexe B.9).
