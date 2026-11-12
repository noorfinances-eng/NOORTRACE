# Pages de la console (`src/pages/`)

Écrans de la console d'exploitation (contrat `paquets/console/INTERFACES.md`,
section 3 ; CT-3 9.2 à 9.7, 13.2 à 13.18, EX-13.43, EX-13.47, EX-13.48) :
pages statiques à intégrité, sans autre script en ligne que la carte
d'importation, construites par le DOM (`createElement`, `textContent`),
servies par le serveur de console (`src/serveur/`) d'après `manifeste.json`.
Parcours de signature a et b seulement (portefeuille de navigateur découvert
par EIP-6963, et par lui un portefeuille matériel) ; ni parcours c, ni
parcours d, ni `window.ethereum`.

Aucun fichier n'est repris de noorchain-core : la grammaire visuelle et les
libellés de curators-hub n'ont servi que de patrons (deux thèmes par
`prefers-color-scheme`, chaque encre ayant ses deux valeurs ; table de
libellés par langue), avec une palette neutre (gris seulement) et les polices
du système.

## Fichiers

| Fichier | Rôle |
|---|---|
| `construire.mjs` | générateur des cinq écrans et du manifeste (contrat 3.3) ; `node src/pages/construire.mjs` vérifie (code 1 si un fichier produit est périmé), `--ecrire` réécrit |
| `manifeste.json`, `ecrans/*.html` | produits par `construire.mjs --ecrire`, versionnés |
| `statique/console.css` | feuille de style |
| `statique/ecrans/<écran>.mjs` | module d'entrée de chaque écran : `tickets`, `ticket`, `inscription` (« Mon adresse »), `annuaire`, `connexion` |
| `statique/commun/client.mjs` | client de `/v0/` (`fetch` de même origine, `credentials: "same-origin"`, JSON), lecture de la session, connexion locale, déconnexion |
| `statique/commun/dom.mjs` | construction du DOM par `createElement` et `textContent` |
| `statique/commun/libelles.mjs` | `t(cle, valeurs)`, table choisie selon `document.documentElement.lang` |
| `statique/commun/cadre.mjs` | démarrage d'un écran (session, `identite_invalide`, navigation), bandeau, affichage d'une erreur et de son code |
| `statique/commun/fournisseurs.mjs` | découverte EIP-6963, liste des portefeuilles, appels EIP-1193 lus sans confiance |
| `statique/libelles/fr.mjs` | les textes (contrat 3.6) |

La bibliothèque n'est pas recopiée : `/statique/bibliotheque/<module>.mjs`
sert les fichiers de `src/bibliotheque/` eux-mêmes, et
`/statique/modules/@noble/<paquet>/<fichier>.js` les fichiers des paquets
`@noble/hashes` et `@noble/curves` résolus comme le serveur les résout.

## Générateur

- Fichiers servis : chaque fichier de `statique/` ; les modules atteints
  depuis les modules d'entrée et les tables de libellés, en suivant les
  importations statiques (spécificateurs `noortrace-console/…`, `@noble/…`
  et relatifs). Un fichier de `statique/` qu'aucun écran n'atteint est une
  erreur.
- Les importations sont trouvées par une analyse lexicale du texte
  (commentaires, chaînes, gabarits, expressions régulières), et non par une
  recherche d'expression régulière sur le texte brut : les commentaires de
  `@noble/curves` contiennent des exemples d'importation (`import { p256 }
  from '@noble/curves/nist.js'`) qui ne sont pas des importations. La
  fermeture compte 15 fichiers `@noble/*` (9 de `curves`, 6 de `hashes`) ;
  l'essai la recalcule avec l'analyseur de V8 (`vm.SourceTextModule`) et la
  confronte aux requêtes que font les cinq écrans dans Chromium.
- Carte d'importation : `JSON.stringify` sans espace de `{ imports,
  integrity }`, `integrity` triée ; la même dans les cinq écrans.
- Écrans : `<html lang="fr">`, dans le `<head>` et dans cet ordre `<meta
  charset>`, `<meta name="viewport">`, `<title>` (texte de `fr.mjs`), la
  feuille à intégrité, la carte, le module d'entrée à intégrité ; le corps est
  `<div id="principal"></div>` et un `<noscript>`.
- Déterministe : aucune date, aucun aléa, aucun chemin de la machine ; les
  mêmes octets quel que soit le répertoire courant.

## Lectures du contrat et de CT-3

Chacune est éprouvée par `test/exploitation-console-pages-chromium.test.js`.

- **Pas 1 et boutons de décision.** « Approuver » et « Refuser » ne sont actifs
  que si les contrôles d'EX-9.15 passent sur la lecture du pas 1, hors le
  contrôle 8 (décision) et le contrôle 13 (motif, fait au pas 3), l'adresse
  étant l'adresse active que l'annuaire attribue à la session (la seule que la
  page retient pour un vote, EX-13.23), et si `controleVote` l'admet.
- **Empreintes.** Aucune empreinte de `D_A` avant le choix de la décision
  (EX-9.20, point 2 ; décision de l'étape 6 sur le contrat 3.4) ; l'écran de
  signature ne montre que celle de la décision choisie ;
  `empreinte_divergente` montre les deux de chaque décision (table de 13.14).
- **Consignes d'EX-9.20.** Affichées sous le modèle, puis dans l'écran de
  signature quand il paraît ; l'origine de la console saine est
  `console_origin` de l'annuaire lu.
- **Après une panne du portefeuille** (refus, délai, signature refusée), la
  décision est à choisir de nouveau : les deux boutons sont offerts.
- **`voter` sans réponse** (504 ou requête sans réponse) : le même corps est
  renvoyé une fois ; toujours sans réponse, un bouton « Renvoyer le même vote »
  renvoie ce même corps, jamais un autre.
- **Vue d'un autre ticket** que celui de l'adresse de l'écran : ni affichée ni
  signée (`reponse_service_invalide` de `$defs/code_console`, CT-3 0.6,
  EX-13.29).
- **Réponse du serveur hors de sa forme** (session, vue, annuaire) :
  `reponse_service_invalide` (clé `console.reponse_service_invalide`).
- **Récusation** : envoyée pour l'adresse active que l'annuaire attribue à la
  session, lue juste avant (`annuaire` et `consulter`, puis `controleVote(…,
  "recuser", …)`) ; aucun portefeuille n'est demandé (elle n'est pas signée).
- **Retrait** : offert seulement si `actionRetrait` rend un `by` ; le motif est
  exigé par la page (le schéma l'admet nul).
- **Ticket ouvrant** : la condition `when` est affichée en JSON indenté.
- **Délai d'une signature d'inscription** : `echeanceAttente(delai,
  Expire le du défi, …)` (CT-3 0.6, EX-13.30) ; un défi échu à l'action ne
  fait demander aucune signature (`inscription_expiree`, consigne de
  recommencer).
- **Règle de 3.5** : la page note chaque méthode de la liste d'EX-13.8
  qu'elle envoie, avec son instant ; pour `reauth_max_age_s` = 0, un envoi à
  `auth_time` ou après impose la réauthentification, sauf
  `preparer_inscription` seule avant l'`inscrire` qui suit (EX-13.48, point
  5, révision 0.6). Avant `preparer_inscription`, la session est relue et la
  page fait réauthentifier d'abord si l'authentification ne couvrirait pas
  l'`inscrire` au terme de l'attente admise (`min(delai_signature_ms,
  registration_ttl_ms)` + 30 s).
- **Révocation par la personne** (« Mon adresse ») : offerte pour une
  adresse en attente ou active de sa propre entrée, confirmée par un second
  clic sous la consigne qu'elle est définitive, motif facultatif ; le
  serveur exige la réauthentification d'EX-13.8.
- **Annuaire** : « Valider » n'est offert ni pour sa propre entrée, ni pour une
  entrée inactive, ni pour une adresse qui n'est pas en attente ; le service
  refait chaque contrôle. La consigne « Avant de valider » paraît avec la
  confirmation, avant l'envoi.
- **Déconnexion** : le bandeau offre « Se déconnecter » (`POST /deconnexion`).
- **Langue** : `libelles.mjs` importe `fr.mjs` ; une autre langue de
  `document.documentElement.lang` est importée dynamiquement de
  `libelles/<langue>.mjs`, que le générateur nomme dans la carte dès que le
  fichier existe.

## Essais

```text
npx mocha test/exploitation-console-pages.test.js test/exploitation-console-pages-chromium.test.js
NOORTRACE_EXIGER_CHROMIUM=1 npx mocha test/exploitation-console-pages-chromium.test.js
```

Outils : `test/fixtures/exploitation-console/portefeuille.mjs` (fournisseur
EIP-1193 simulé, annoncé par EIP-6963, clés dérivées au moment de l'essai du
mnémonique public de CT-3 A.2) et
`test/fixtures/exploitation-console/pages/site.mjs` (serveur de console et
service simulés par interception, en-têtes de 2.6, espions du stockage).
