# @noortrace/verification-web — page de vérification (CT-6 §18)

La page statique et publique qui exécute dans le navigateur, dans un
travailleur, le vérificateur `noortrace-verifier` compilé en WebAssembly,
sur un dossier que l'utilisateur choisit et qui ne quitte pas son poste ;
elle affiche le rapport du binaire, sans rien y ajouter (CT-6 §18) : le
verdict, la liste des contrôles et les avertissements qu'elle met en avant se
lisent dans le code de retour et dans le rapport JSON du binaire. Le
paquet porte le script qui produit, de façon déterministe, les fichiers de
la page à partir de l'artefact WebAssembly. Le contrat est dans
`INTERFACES.md` ; son état est à la fin de ce fichier.

## Construire la page

Il faut go1.27.3 exactement (CT-6 EX-14.3, EX-18.3), installé hors du dépôt
et vérifié comme le dit `verificateur/LISEZMOI.md`, et Node 22.

```bash
# 1. L'artefact et le fichier de soutien de la chaîne Go (recette d'EX-18.3).
verificateur/scripts/construire-wasm.sh -v 0.1.0 -o <répertoire de l'artefact>
# 2. Les fichiers de la page, dans un répertoire absent ou vide.
node paquets/verification-web/src/construire.mjs --wasm <répertoire de l'artefact> --version 0.1.0 --sortie <répertoire de la page>
```

`construire-wasm.sh` refuse toute autre chaîne que go1.27.3, et refuse de
construire si `GOWASM`, `GOEXPERIMENT` ou `GOFIPS140` sont posées (elles
changeraient l'artefact sans être des entrées de la recette). Il imprime le
SHA-256 de `noortrace-verifier.wasm` et de `wasm_exec.js`. `construire.mjs`
écrit `index.html`, `page.css`, `page.js`, `verificateur-wasm.js`,
`travailleur.js`, `noortrace-verifier.wasm`, `SHA256SUMS` (les six fichiers
de la page, au format de `sha256sum`, à reporter dans le `SHA256SUMS` signé
de la version) et `en-tetes.json` (les en-têtes d'EX-18.12, par fichier), et
imprime `SHA256SUMS`. La version passée aux deux scripts est la même : celle
des binaires. Les fichiers produits ne sont pas versionnés.

Le réviseur reconstruit et compare : `sha256sum --strict -c SHA256SUMS` dans
le répertoire de la page.

## Servir la page

Le paquet ne contient pas de serveur. L'hébergeur sert les six fichiers de la
page, et rien d'autre, sur une origine HTTPS propre (EX-18.11), avec, pour
chacun, exactement les en-têtes de `en-tetes.json` (EX-18.12). Pour les
essais, `test/fixtures/verification-page/navigateur.mjs` sert un répertoire
de page par interception des requêtes dans Playwright, sur l'origine fictive
`https://verification.example`, avec ces en-têtes, et relève les requêtes,
les réponses et les messages du navigateur :

```js
import { lancer, ouvrir, attendreArtefact, deplierOptions, lancerVerification } from "./test/fixtures/verification-page/navigateur.mjs";
const { navigateur } = await lancer("chromium");
const o = await ouvrir(navigateur, "<répertoire de la page>");
await o.page.goto("https://verification.example/index.html");
await attendreArtefact(o.page);           // texte de #artefact : version et empreinte
o.marquer();                              // requêtes relevées à partir d'ici
await o.page.setInputFiles("#entree-repertoire", "<dossier exporté>");
await deplierOptions(o.page);             // fichiers facultatifs et options : dans le bloc replié #options
await lancerVerification(o.page);         // #verdict-mot, #code, #controles, #enonce-fr, #enonce-en, #rapport-lisible, #rapport-json, #sortie-erreur
```

`deplierOptions` vient du même fichier : le fichier d'ancres, le fichier
d'en-têtes, les contrôles à exiger, la langue et le détail du rapport sont
dans un bloc replié, qu'un essai ouvre par son titre avant d'y agir.

`test/fixtures/verification-page/outils.mjs` construit l'artefact, la page
et le binaire natif de la même construction (`construireTout`) et exécute ce
binaire dans un répertoire `/entrees` (`RacineNatif`, par `unshare --root`),
pour comparer son rapport à celui de la page (EX-18.10).

## Sources

```text
src/construire.mjs              assemble les fichiers de la page (EX-18.6)
src/page/index.modele.html      modèle de index.html, rempli des libellés français et des intégrités
src/page/page.css               bloc de style commun aux écrans NOORTRACE, puis styles de la page ; polices du système
src/page/libelles-fr.js         libellés français (phrases fixes de CT-6 §18 mot pour mot)
src/page/libelles-en.js         libellés anglais, mêmes clés
src/page/archives.js            lecture des archives .zip, .tar (ustar, pax, GNU), .tar.gz, .tgz (EX-18.7)
src/page/interface.js           choix des fichiers, travailleur, thème, affichage (EX-18.2, EX-18.5, EX-18.9, EX-18.11)
src/travailleur/prelude.js      arbre /entrees en lecture seule, process, path (EX-18.8)
src/travailleur/pilote.js       contrôle de l'empreinte, deux exécutions (EX-18.5, EX-18.9)
```

`page.js` est l'assemblage, dans un seul script classique sans importation,
des quatre modules de `src/page/`, dans l'ordre libellés français, libellés
anglais, archives, interface. `travailleur.js` est exactement `prelude.js`,
puis `wasm_exec.js` de go1.27.3 sans changement, puis `pilote.js` où la
construction écrit `EMPREINTE_WASM` et la version.

## Présentation (complément du 2026-11-17 de CT-6 §18)

La page se lit en trois temps : « 1. Choisissez le dossier » (une zone de
dépôt, deux boutons), « 2. Options (facultatif) » (un bloc replié dont le
titre résume les choix faits : fichier d'ancres, fichier d'en-têtes,
contrôles à exiger, langue et détail du rapport, chacun avec un libellé
courant et son nom de la ligne de commande entre parenthèses), « 3. Vérifier ».
La phrase fixe d'EX-18.2 est dans un bandeau toujours visible, l'état du
vérificateur dans l'en-tête ; la phrase qui porte l'empreinte est dans le bloc replié
« Empreinte du vérificateur », juste dessous. Un artefact altéré ou un
vérificateur indisponible s'affiche dans une alerte, jamais repliée.

Le résultat commence par un grand verdict : un mot tiré du seul code de
retour (« Valide », « Non valide », « Aucun verdict », « Incomplet »), puis la
phrase du code, entière. Suivent les avertissements du rapport JSON et la
sortie d'erreur si elle n'est pas vide, l'énoncé dans la langue de la page,
tel quel, et la liste des huit contrôles : pour chacun, le statut que le
rapport JSON lui donne, sa raison en clair avec son code, et son résumé.
La page ne calcule aucun statut. Un contrôle que le rapport ne dit pas
`reussi` n'est jamais montré réussi ; un verdict « valide » dont un contrôle
n'est pas réussi le dit sous le verdict (« Valide, avec des contrôles non
exécutés : … ») ; un rapport dont la liste des contrôles ne se lit pas
exactement, ou contredit le code, n'est pas résumé, et la page le dit
(`lireControles` d'`interface.js`). Le rapport lisible, le rapport JSON, la
ligne de commande équivalente et l'énoncé dans l'autre langue sont dans des
blocs repliés, tels quels, avec un bouton « Copier » quand le navigateur
l'offre ; la page les ouvre à l'impression.

Deux états d'affichage, sombre et clair : la page s'ouvre dans celui du
système (`prefers-color-scheme`), un bouton passe de l'un à l'autre, et rien
n'est mémorisé (EX-18.11 : aucun stockage). `page.js` est chargé dans
l'en-tête pour poser cet état avant le premier affichage. `page.css` commence
par le bloc de style commun aux trois écrans du dépôt, entre les repères
`/* noor-theme:debut */` et `/* noor-theme:fin */` ; les règles de la page
viennent après, sous le préfixe `pv-`, sans redéfinir un jeton du bloc. Les
icônes sont des tracés SVG, écrits dans le gabarit ou construits par
`interface.js` ; aucune image, aucune police embarquée.

## Bornes et limites (EX-18.7 ; revue de sécurité de l'étape 8)

Toutes les bornes sont des constantes nommées en tête de
`src/page/archives.js` (`BORNES_ARCHIVE`), et nulle part ailleurs : 4 096
entrées et 256 Mio décompressés par dossier (CT-6 EX-18.7), 64 composants et
4 096 octets UTF-8 par chemin d'entrée, 512 Mio par fichier lu (valeurs
proposées par la revue de sécurité de l'étape 8 ; un dossier de CT-6 §4 a ses parties à sa
racine, soit au plus deux composants dans une archive, et au plus 64 Mio par
partie, 247 Mio en tout). Un chemin d'entrée est borné avant tout autre
examen, en temps linéaire en sa longueur : l'archive de 393 octets dont un
chemin a 100 000 composants (CT-6 EX-18.7) est refusée en quelques millisecondes,
raison `r_chemin_long`. La taille d'un fichier (archive, fichier d'un
répertoire, ancres, en-têtes) est contrôlée sur la taille que le navigateur
déclare, avant toute lecture (`r_fichier_trop_gros`). Le parcours d'un
répertoire déposé s'arrête à la première entrée au-delà de 4 096 et au premier
chemin trop long, avant toute lecture de fichier. L'arbre du travailleur est
numéroté sans récursion : la profondeur d'un chemin ne borne pas la pile.
Le bouton « Arrêter » met fin à une vérification en cours : le travailleur est
détruit, la page affiche « vérification non faite » avec la cause, et un
travailleur neuf reçoit l'artefact (une nouvelle demande de `travailleur.js`
à la même origine, la seule après le chargement) ; demandé pendant la lecture
du dossier, l'arrêt retient l'envoi. La page affiche « vérification non
faite » quand la `version` du bloc `verifier` du rapport JSON diffère de celle
qu'elle annonce. Toute chaîne venue d'une entrée (rapport lisible, énoncés,
message d'erreur, sortie d'erreur, chemin d'entrée, nom de fichier) passe par
`neutraliser` d'`interface.js` avant l'affichage : commandes C0 (sauf
tabulation et saut de ligne), DEL, C1, U+2028, U+2029 et marques de direction
sont rendues sous la forme visible `\u{…}`. La page n'impose aucun délai : un
dossier de 247 Mio peut demander plusieurs minutes, et c'est l'utilisateur
qui arrête.

## Essais

| Fichier | Ce qu'il éprouve | Conditions |
|---|---|---|
| `test/verification-page-sources.test.js` | refus et formes admises des archives (dont les sept recettes d'EX-18.13 sur les 190 dossiers), arbre du prélude, libellés et phrases fixes | `zip`, `tar` GNU et `gzip` pour les recettes, en attente sinon |
| `test/verification-page-construction.test.js` | reproductibilité (deux copies, deux chemins, deux caches), formes des fichiers produits, en-têtes, `go list -deps` | go1.27.3, en attente sinon |
| `test/verification-page-identite.test.js` | identité, octet pour octet, avec le binaire natif sur les 190 dossiers (6 460 exécutions) | go1.27.3 et `unshare --root`, en attente sinon |
| `test/verification-page-chromium.test.js` | la page dans Chromium sous les en-têtes, échantillon fixé sous chaque forme, refus, requêtes, politiques, stockage, TA-101 ; Firefox et WebKit quand Playwright les a | Playwright 1.56.1 et son Chromium, go1.27.3, `unshare --root` ; échoue sous `NOORTRACE_EXIGER_CHROMIUM=1` |
| `test/verification-page-revue.test.js` | revue de sécurité (étape 8) sous Node : bornes des chemins et des fichiers, archive hostile de 100 000 composants refusée en moins d'une seconde, compteur du parcours, arbre sans récursion, `neutraliser`, libellés des bornes | aucune ; `NOORTRACE_RACINE` pour éprouver une copie des sources |
| `test/verification-page-presentation.test.js` | présentation : lecture des contrôles du rapport JSON, libellés, gabarit et feuille de style sous Node ; dans un navigateur, avec un artefact factice et un travailleur de remplacement, verdict selon le code, liste des contrôles selon le rapport, deux mutants tués, rapports intacts dans leurs blocs, avertissements visibles, thème ; de bout en bout sur cinq dossiers des vecteurs | Playwright et son Chromium pour la partie navigateur ; go1.27.3 pour le bout en bout ; en attente sinon |
| `test/verification-page-revue-navigateurs.test.js` | revue de sécurité (étape 8) dans les trois moteurs : archive hostile (réponse en moins d'une seconde), fichier de 513 Mio, répertoire déposé, version du rapport, bouton « Arrêter », chaînes hostiles affichées | comme `verification-page-chromium.test.js` ; Firefox et WebKit en attente s'ils manquent |

La chaîne Go est prise dans `NOORTRACE_GO_BIN`, à défaut dans le `PATH`.
Playwright est chargé par `require("playwright")`, installé sans être
ajouté à `package.json` (`npm install --no-save playwright@1.56.1`, puis
`npx playwright install chromium`).

Fichiers repris de noorchain-core : aucun.

## État (étape 6)

Fait : script `verificateur/scripts/construire-wasm.sh`, `construire.mjs`,
page, travailleur, lecture des archives, essais ci-dessus. Mesures du
2026-11-11 (go1.27.3, Node 22.22.0, Playwright 1.56.1, Chromium
141.0.7390.37) : artefact de 11 762 554 octets, mêmes octets sur deux
constructions ; zéro discordance sur 6 460 exécutions ; Chromium vert.
Firefox et WebKit : non éprouvés (absents du poste). Les précisions apportées
au contrat sont à la fin de `INTERFACES.md`.
