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
libellés de curators-hub n'ont servi que de patrons (deux thèmes, chaque
encre ayant ses deux valeurs ; table de libellés par langue), avec les
polices du système.

Complément du 2026-11-17, décision du porteur (présentation des écrans) : la
palette neutre est remplacée par le thème commun des écrans NOORTRACE (deux
états, sombre et clair ; couleurs, cartes, pastilles, logo en texte), dont le
bloc ouvre `statique/console.css` entre deux repères et se retrouve à
l'octet dans la page de vérification et l'outil d'inscription. Ses valeurs
de couleur suivent celles du thème de curators-hub ; aucun fichier n'en est
recopié, ni feuille, ni composant, ni police, ni image. Le contrat du paquet
(`INTERFACES.md`, 3.2 à 3.4) dit ce qui est admis (couleurs, logo) et ce qui
reste interdit (tout stockage, toute ressource, toute police téléchargée).

## Fichiers

| Fichier | Rôle |
|---|---|
| `construire.mjs` | générateur des cinq écrans et du manifeste (contrat 3.3) ; `node src/pages/construire.mjs` vérifie (code 1 si un fichier produit est périmé), `--ecrire` réécrit |
| `manifeste.json`, `ecrans/*.html` | produits par `construire.mjs --ecrire`, versionnés |
| `icones.mjs` | tracés des icônes et du signe du logo, que `construire.mjs` écrit dans chaque écran en gabarits `<template id="icone-<nom>">` ; non servi |
| `statique/console.css` | feuille de style : le thème commun (entre `/* noor-theme:debut */` et `/* noor-theme:fin */`), puis les règles propres à la console |
| `statique/commun/theme.mjs` | état du thème : sombre sans attribut, clair par `data-theme="clair"` ; suit `prefers-color-scheme`, bascule pour la page affichée, aucun stockage ; premier module de chaque écran |
| `statique/commun/lisible.mjs` | fonctions pures : `resumeVerifie` (phrase d'une demande composée des seules valeurs vérifiées), `groupesValeurs` (feuilles vérifiées, à contrôler, différentes), `libelleValeur` et `LIBELLES_VALEURS` (libellé courant d'une valeur), `partiesIdentite`, `montantLisible`, parties d'une durée et d'un instant |
| `statique/ecrans/<écran>.mjs` | module d'entrée de chaque écran : `tickets`, `ticket`, `inscription` (« Mon adresse »), `annuaire`, `connexion` |
| `statique/commun/client.mjs` | client de `/v0/` (`fetch` de même origine, `credentials: "same-origin"`, JSON), lecture de la session, connexion locale, déconnexion |
| `statique/commun/dom.mjs` | construction du DOM par `createElement` et `textContent` ; composants du thème (bouton, bandeau, pastille, marque, bloc replié) ; `icone()` clone le gabarit d'une icône |
| `statique/commun/libelles.mjs` | `t(cle, valeurs)`, table choisie selon `document.documentElement.lang` |
| `statique/commun/cadre.mjs` | démarrage d'un écran (session, `identite_invalide`), barre haute (logo, navigation, personne, déconnexion, bascule de thème), identité de session en entier sous la barre, affichage d'une erreur et de son code, instants et durées en mots, pastille d'un état |
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
  charset>`, `<meta name="viewport">`, `<meta name="theme-color">`, `<title>`
  (texte de `fr.mjs`), la feuille à intégrité, la carte, le module du thème
  à intégrité (avec `blocking="render"` : le premier affichage l'attend), le
  module d'entrée à intégrité ; le corps est `<div
  id="principal"></div>`, un `<noscript>`, puis un gabarit `<template>` par
  icône (complément du 2026-11-17).
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

## Présentation (complément du 2026-11-17)

Éprouvée par `test/exploitation-console-presentation-chromium.test.js` et
`test/theme-commun.test.js`.

- **Phrase d'en-tête.** `resumeVerifie(modele)` ne lit que le modèle
  d'affichage : un argument n'y entre que si sa feuille a l'état `verifie` ;
  l'outil, le demandeur et la règle n'y entrent que si l'événement est
  vérifié et les champs liés égaux. Le montant n'est reconnu que par les
  couples de pointeurs `/amount` et `/currency`, ou `/montant` et `/devise` :
  la console ne devine pas le sens d'un autre champ. Les effets déclarés,
  que le service évalue seul, ne servent jamais au résumé. Mutant tué : sans
  la condition d'état, un montant non vérifiable s'affiche en tête.
- **Rien d'exigé n'est replié.** Le détail technique ne porte que des codes
  bruts, des noms de champs et des instants exacts ; il se rouvre de
  lui-même après un nouvel affichage s'il était ouvert.
- **Adresses en entier.** Une adresse ne s'abrège pas, même dans un tableau :
  deux adresses qui partagent leurs extrémités se confondraient.
- **Pas de capitale ajoutée à une phrase fixée.** Les phrases de 13.14 et
  les marques d'EX-9.4 s'affichent telles que CT-3 les écrit ; la capitale
  d'une pastille d'état est un rendu de la feuille de style, sauf pour la
  décision d'un vote (`approuve`, `refuse`), valeur signée.
- **Motif.** Le champ et son avertissement paraissent à la confirmation de
  la décision : on ne saisit pas un motif sans voir l'avertissement.
- **Limite.** La liste des tickets ne porte pas les arguments (`tickets` ne
  les rend pas) : elle ne peut pas dire le montant d'une demande.

## Essais

```text
npx mocha test/exploitation-console-pages.test.js test/exploitation-console-pages-chromium.test.js test/exploitation-console-presentation-chromium.test.js test/theme-commun.test.js
NOORTRACE_EXIGER_CHROMIUM=1 npx mocha test/exploitation-console-pages-chromium.test.js
```

Outils : `test/fixtures/exploitation-console/portefeuille.mjs` (fournisseur
EIP-1193 simulé, annoncé par EIP-6963, clés dérivées au moment de l'essai du
mnémonique public de CT-3 A.2) et
`test/fixtures/exploitation-console/pages/site.mjs` (serveur de console et
service simulés par interception, en-têtes de 2.6, espions du stockage).

## Langage (complément du 2026-11-18)

Éprouvé par `test/exploitation-console-langage-chromium.test.js`.

- **À qui parlent les écrans.** À une personne qui décide, pas à un
  technicien : chaque phrase visible sans rien ouvrir se comprend sans avoir
  lu la spécification. L'essai relève le texte visible de chaque écran, hors
  des blocs repliés fermés, hors des valeurs venues des données
  (`data-valeur`), des phrases fixées (`data-fixe`) et des codes entre
  parenthèses (`code-brut`), et n'y admet aucun mot de sa liste.
- **Phrases fixées.** Les marques, les intitulés de l'écran de signature,
  les sept consignes et les textes que CT-3 cite restent mot pour mot ;
  l'essai compare chaque nœud `data-fixe` à la liste des textes fixés. Une
  phrase en langage courant les précède, qui n'affirme rien de plus.
- **Valeurs à contrôler.** `groupesValeurs` range une feuille que la console
  n'a pas pu vérifier dans le groupe « À contrôler par vous-même », jamais
  avec les feuilles vérifiées ; une feuille d'un état inconnu aussi. Mutant
  vu : la feuille rendue avec les vérifiées.
- **Libellés courants.** `libelleValeur` ne lit que le dernier segment du
  chemin, dans la table fixe de CT-3 EX-9.4 ; le chemin exact reste affiché.
  Mutant vu : `beneficiary_iban` libellé « Montant ».
- **Longueur.** L'écran d'une demande est resserré, sans rien replier de ce
  qu'EX-9.4 demande ; un essai borne sa hauteur dans le cas simple.
- **Après la décision confirmée.** La page amène au choix du portefeuille
  (défilement et focus sur `#vote`), sans en choisir aucun. Mutant vu :
  l'appel retiré.
- **Contestation.** Dans la liste, une demande sans délai de contestation
  n'en dit rien ; avec un délai, la carte le dit en mots.
- **Consignes courantes.** Sur l'écran de signature, quatre consignes en
  langage courant, fixées par le complément du 2026-11-18 de CT-3 EX-9.20,
  précèdent le bouton ; le texte de référence d'EX-9.20 reste entier, dans
  le bloc « Consignes complètes ». L'essai compare les quatre lignes au
  texte du complément. Mutant vu : la quatrième consigne retirée.
- **Codes.** Le code entre parenthèses accompagne une panne ; un état
  attendu du parcours ou un avertissement s'affiche sans code, qui est au
  détail technique. Le résultat d'une signature s'affiche sous l'en-tête
  de la demande, et la page y amène.
- **Montant dans la liste.** Pour dix demandes en cours au plus, la liste
  lit la vue de chaque demande et affiche le montant vérifié
  (`montantVerifie`), rien sinon ; des lectures seulement. Mutant vu : le
  montant non vérifié affiché.
- **Barre et défilement.** À 1280 de large, la barre tient sur une ligne
  avec toute police courante ; la page note sa hauteur réelle
  (`data-barre`) et la feuille en tire `scroll-padding-top` : ce que la
  page amène vient sous la barre, quelle que soit sa hauteur. Les essais
  du navigateur se jouent avec les polices de la machine et avec celles
  d'un poste sans Inter (`FONTCONFIG_FILE` qui écarte Inter : DejaVu Sans).
  Mutant vu : la hauteur supposée de 5 rem.
- **« inchangé ».** Sous les valeurs inchangées, et dans la liste dès qu'un
  montant inchangé y paraît, une légende bien visible dit ce que la marque
  veut dire et ne veut pas dire, et invite à comparer aux pièces. Mutant
  vu : la légende retirée.
- **Récusation et retrait.** Au pied des cartes « Qui décide » et « Qui
  demande » : jamais entre le choix du portefeuille et la signature.
  Mutant vu : la récusation remise à côté du portefeuille.
- **« Contester ».** Expliqué une fois par écran, là où le mot paraît
  d'abord.
- **Annuaire.** Chaque action dit en une phrase ce qu'elle fait, à côté de
  son bouton ; « Définitif » en tête de la phrase d'une action qu'on ne
  peut pas défaire, redit à la confirmation. Mutant vu : la mention retirée.
- **Chaque bloc au bon moment.** Le choix du portefeuille ne paraît qu'une
  fois la décision confirmée, et plus après une signature ; après sa
  décision, la page dit qu'elle est enregistrée et qu'il n'y a plus rien à
  faire. Un essai par état de la demande. Mutant vu : le portefeuille offert
  avant la décision.
- **Panne de signature.** En haut de l'écran, la page amenée dessus ; une
  phrase dit que la décision n'est pas enregistrée ; « Réessayer ». Mutants
  vus : l'écran de signature laissé en place ; la consigne de ne pas
  réessayer retirée.
- **Limites.** Dans la liste, le montant n'est affiché que pour les dix
  premières demandes en cours, et seulement quand la console l'a vérifié
  (la réponse `tickets` ne porte pas les arguments). Les autres approbateurs restent des adresses
  pour une session ordinaire, dont l'annuaire ne porte que sa propre fiche.
  Le décalage d'un instant reste écrit « UTC+1 ».

## Décisions du porteur du 2026-11-19

Éprouvées par `test/exploitation-console-langage-chromium.test.js`, les
essais des pages, du serveur (`session`) et du service (`consulter`). Elles
remplacent ce qui précède là où elles le contredisent ; le détail est au
complément du 2026-11-19 de `INTERFACES.md`, 3.4.

- **« inchangé ».** La marque d'une valeur `verifie` se dit « inchangé » ;
  la légende et le groupe à contrôler le disent avec ce mot.
- **Titre.** Une phrase modèle de l'organisation (`titles`, configuration
  du serveur de console, transmise par `session`) donne le titre d'une
  demande, rempli des seules valeurs « inchangé » (`titreDemande`) ; sinon,
  la phrase d'avant. Mutant vu : une valeur non contrôlée admise.
- **Un seul code.** L'écran de signature montre en grand le code de
  contrôle en entier ; l'autre forme est derrière le lien « Mon
  application affiche un autre code ». Mutant vu : l'autre forme ouverte
  d'emblée.
- **Refus dans l'application.** Plus de « Réessayer » : « Prévenez votre
  administrateur : ne réessayez pas. », puis un lien discret pour qui a
  refusé par erreur. Mutant vu : « Réessayer » de nouveau offert.
- **Noms.** Chaque décision donnée porte le nom que la vue tire de
  l'annuaire (`approver_names`), ou « adresse inconnue de l'annuaire » ; la
  personne connectée porte le même nom en haut et dans la demande.

