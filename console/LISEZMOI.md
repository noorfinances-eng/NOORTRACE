# Console d'approbation de référence

Page minimale de la console de référence de CT-3
([`spec/CT-3-approbations.md`](../spec/CT-3-approbations.md), révision 0.3,
section 13.15, EX-13.31 à EX-13.36). Elle n'est pas la console
d'exploitation (phase 2) : elle n'a ni authentification, ni notification ;
son serveur de console et le service d'approbation sont simulés par le test
`test/console.test.js`.

## Fichiers

| Fichier | Rôle |
|---|---|
| `index.html` | page statique, **produite** par `node scripts/console/empreintes.mjs --ecrire` : carte d'importation de la bibliothèque avec son intégrité `sha384-`, script d'entrée avec son intégrité `sha384-` |
| `console.js` | script d'entrée (module) : découverte EIP-6963, choix explicite du portefeuille, modèle d'affichage, décision, écran de signature, `personal_sign`, vérification de la réponse, `voter` ; inscription par preuve de possession |
| `console.css` | feuille de style, servie depuis la même origine |
| `../scripts/lib/console.mjs` | bibliothèque sans interface ni dépendance (EX-13.32), servie **sans copie** à l'URL `/scripts/lib/console.mjs` de la même origine |

La page offre le parcours a (portefeuille de navigateur, EIP-1193 et
EIP-6963) et, par lui, le parcours b (portefeuille matériel par un
portefeuille de navigateur). Elle n'offre ni le parcours c (portefeuille
mobile), ni le parcours d (fichier de clé), ni `window.ethereum`. Elle ne
détient, ne reçoit ni ne dérive aucune clé et ne garde rien dans le
navigateur.

## Ce que le serveur de console doit servir

Le serveur sert la racine du dépôt telle quelle : la page à
`<origine>/console/`, la bibliothèque à `<origine>/scripts/lib/console.mjs`,
et relaie au service les méthodes `POST <origine>/v0/<méthode>` du canal de
la console (12.9), plus sa propre méthode `session`
(`$defs/reponse_session` de `console-service-v0`). L'origine est celle de
`console_origin` de l'annuaire (HTTPS, EX-13.14).

Toute réponse HTML de la console porte les deux en-têtes d'EX-13.35. La
valeur exacte de `Content-Security-Policy`, qui contient le condensé
`sha256-` de la carte d'importation, est imprimée par
`node scripts/console/empreintes.mjs` (et le test exige qu'elle soit à
jour) ; sa forme est :

```text
Content-Security-Policy: default-src 'none'; script-src 'self' 'sha256-<carte d'importation>'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'
Integrity-Policy: blocked-destinations=(script)
```

Après toute modification de `console.js` ou de `scripts/lib/console.mjs`,
lancer `node scripts/console/empreintes.mjs --ecrire`, qui réécrit
`index.html` avec les nouvelles intégrités, puis servir la nouvelle valeur de
l'en-tête. La publication des empreintes et la construction reproductible
relèvent de CT-7 et CT-8 (EX-13.4).

## Test de bout en bout

`test/console.test.js` charge la page dans Chromium par Playwright
(EX-13.36), sans réseau : le serveur de console et le service sont simulés
dans le test, et un fournisseur EIP-1193 simulé, annoncé par EIP-6963, signe
avec les clés de test des vecteurs. Versions mesurées : Playwright 1.56.1 et
son Chromium 141.0.7390.37, sous Node 22. Playwright n'est pas une
dépendance du dépôt : le test le charge s'il est installé sur le poste, et se
saute avec un message sinon, ou si Chromium ne se lance pas ; il n'installe
aucun navigateur. Sous `NOORTRACE_EXIGER_CHROMIUM=1`, le saut est impossible :
la même condition fait échouer le test. L'intégration continue a un travail
propre, `console-chromium` (`.github/workflows/ci.yml`), sur un exécuteur
Ubuntu 24.04 (Playwright 1.56.1 n'installe pas Chromium sur Ubuntu 26.04),
qui installe
Playwright 1.56.1 sans l'ajouter à `package.json`
(`npm install --no-save playwright@1.56.1`), puis son Chromium
(`npx playwright install --with-deps chromium`), pose
`NOORTRACE_EXIGER_CHROMIUM=1` et lance le test : un test Chromium en attente
y fait échouer le travail (CT-3 EX-13.36). Dans le travail `tests`, sans
Playwright, seule la partie Node du test tourne.

La signature locale d'un fichier de clé (parcours d, que cette page n'offre
pas) par `signerCondense` n'est pas à temps constant : un approbateur exposé
emploie un portefeuille matériel (CT-3 14.9).
