# @noortrace/verification-web — page de vérification (CT-6 §18)

La page statique et publique qui exécute dans le navigateur, dans un
travailleur, le vérificateur `noortrace-verifier` compilé en WebAssembly,
sur un dossier que l'utilisateur choisit et qui ne quitte pas son poste ;
elle affiche le rapport du binaire, sans rien y ajouter (CT-6 §18). Le
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
import { lancer, ouvrir, attendreArtefact, lancerVerification } from "./test/fixtures/verification-page/navigateur.mjs";
const { navigateur } = await lancer("chromium");
const o = await ouvrir(navigateur, "<répertoire de la page>");
await o.page.goto("https://verification.example/index.html");
await attendreArtefact(o.page);           // texte de #artefact : version et empreinte
o.marquer();                              // requêtes relevées à partir d'ici
await o.page.setInputFiles("#entree-repertoire", "<dossier exporté>");
await lancerVerification(o.page);         // #code, #rapport-lisible, #enonce-fr, #enonce-en, #sortie-erreur
```

`test/fixtures/verification-page/outils.mjs` construit l'artefact, la page
et le binaire natif de la même construction (`construireTout`) et exécute ce
binaire dans un répertoire `/entrees` (`RacineNatif`, par `unshare --root`),
pour comparer son rapport à celui de la page (EX-18.10).

## Sources

```text
src/construire.mjs              assemble les fichiers de la page (EX-18.6)
src/page/index.modele.html      modèle de index.html, rempli des libellés français et des intégrités
src/page/page.css               styles, polices du système
src/page/libelles-fr.js         libellés français (phrases fixes de CT-6 §18 mot pour mot)
src/page/libelles-en.js         libellés anglais, mêmes clés
src/page/archives.js            lecture des archives .zip, .tar (ustar, pax, GNU), .tar.gz, .tgz (EX-18.7)
src/page/interface.js           choix des fichiers, travailleur, affichage (EX-18.2, EX-18.5, EX-18.9)
src/travailleur/prelude.js      arbre /entrees en lecture seule, process, path (EX-18.8)
src/travailleur/pilote.js       contrôle de l'empreinte, deux exécutions (EX-18.5, EX-18.9)
```

`page.js` est l'assemblage, dans un seul script classique sans importation,
des quatre modules de `src/page/`, dans l'ordre libellés français, libellés
anglais, archives, interface. `travailleur.js` est exactement `prelude.js`,
puis `wasm_exec.js` de go1.27.3 sans changement, puis `pilote.js` où la
construction écrit `EMPREINTE_WASM` et la version.

## Essais

| Fichier | Ce qu'il éprouve | Conditions |
|---|---|---|
| `test/verification-page-sources.test.js` | refus et formes admises des archives (dont les sept recettes d'EX-18.13 sur les 190 dossiers), arbre du prélude, libellés et phrases fixes | `zip`, `tar` GNU et `gzip` pour les recettes, en attente sinon |
| `test/verification-page-construction.test.js` | reproductibilité (deux copies, deux chemins, deux caches), formes des fichiers produits, en-têtes, `go list -deps` | go1.27.3, en attente sinon |
| `test/verification-page-identite.test.js` | identité, octet pour octet, avec le binaire natif sur les 190 dossiers (6 460 exécutions) | go1.27.3 et `unshare --root`, en attente sinon |
| `test/verification-page-chromium.test.js` | la page dans Chromium sous les en-têtes, échantillon fixé sous chaque forme, refus, requêtes, politiques, stockage, TA-101 ; Firefox et WebKit quand Playwright les a | Playwright 1.56.1 et son Chromium, go1.27.3, `unshare --root` ; échoue sous `NOORTRACE_EXIGER_CHROMIUM=1` |

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
