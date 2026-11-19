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

La page se lit en trois temps : le choix du dossier (une zone de dépôt, deux
boutons), les pièces complémentaires et les options (un bloc replié dont le
titre résume les choix faits : fichier d'ancres, fichier d'en-têtes,
contrôles à exiger, langue et détail du rapport, chacun avec un libellé
courant), le lancement. Les titres des étapes et les libellés sont ceux de la
section « Langage » ci-dessous.
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
n'est pas réussi le dit dans son titre (« Valide, mais tout n'est pas
prouvé ») et sous le verdict (« Contrôles qui n'ont pas pu être faits :
n° … ») ; un rapport dont la liste des contrôles ne se lit pas
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

## Langage (complément du 2026-11-18 de CT-6 §18)

La page parle à une personne qui n'a pas lu la spécification : auditeur,
juriste, client, autorité de contrôle. Ce qui précède reste vrai ; ce qui
suit le complète, et en remplace les mots là où c'est dit.

- **Avant la vérification.** Sous le titre « Vérifier un dossier de preuve »,
  une phrase dit à quoi sert la page et pour qui, puis la garantie : « La
  vérification se fait sur votre ordinateur. Aucun fichier ne quitte votre
  poste. » Un bloc replié « Comment ça marche » tient en cinq lignes. La phrase
  fixe d'EX-18.2 reste affichée, en petit, sous la même mise en garde en
  langage courant, introduite par « Mention exacte : ». Les trois étapes :
  « 1. Choisissez le dossier de preuve que vous avez reçu » (un fichier
  compressé ou un dossier de fichiers, deux boutons, le glisser-déposer),
  « 2. Ajoutez les pièces complémentaires, si vous les avez » (la « liste des
  références de confiance » est le fichier d'ancres, l'« extrait de la chaîne
  Bitcoin » le fichier d'en-têtes ; sous chacune, ce que son absence empêche),
  « 3. Lancez la vérification ». Les noms de la ligne de commande sont réunis
  dans un bloc replié à la fin de l'étape 2.
- **Le résultat.** Dans l'ordre : le mot du verdict ; une phrase en langage
  courant fixée par code de retour ; la ligne « Attention : ce résultat a des
  réserves… » quand le rapport porte un avertissement (codes 0 et 3) ; ce que
  la page tire du rapport (« Les huit contrôles ont réussi. », « Contrôles qui
  n'ont pas pu être faits : n° … »). Puis les
  réserves (chaque avertissement en langage courant, puis tel quel), les huit
  contrôles (une ligne chacun : « Réussi », « Échoué » ou « Non fait », le nom
  courant, ce qu'il sert à prouver ; la raison dessous quand il n'est pas
  réussi ; le résumé du vérificateur dans un bloc replié), le texte exact du
  vérificateur (l'énoncé, chaque membre de phrase dans un bloc à part, sans
  qu'un caractère change, texte copié compris), « Ce que ce résultat ne dit
  pas », « Et maintenant ? » (avec « Imprimer ce résultat »), et « Pour les
  spécialistes » : en tête, la phrase du code, entière, en petit, introduite
  par « Formule exacte du vérificateur : » ; puis le rapport lisible, le
  rapport JSON et la ligne de commande, repliés.
- **Tables fixées.** Les phrases par code de retour, les phrases par
  avertissement (`AV-…`) et les lignes de « Ce que ce résultat ne dit pas »
  sont celles des tables de CT-6 §18 (EX-18.9, points 6, 7 et 10), mot pour
  mot, en français et en anglais ; `interface.js` les prend par le code ou par
  l'identifiant, et n'écrit aucune phrase hors table.
- **Refus et pannes.** Chaque raison de refus d'EX-18.7 est dite en langage
  courant, avec ce qu'il faut faire (libellés `c_r_…`), puis telle quelle
  (« Raison exacte : »). La cause d'une « vérification non faite » et le
  message d'un vérificateur altéré ou indisponible suivent la même règle.
- **Réduction des étapes.** Après un rapport, les trois étapes laissent la
  place à une ligne, « Dossier examiné : … », et au bouton « Vérifier un autre
  dossier » ; ce bouton, le choix ou le dépôt d'un autre dossier les ramènent.
  Un refus et une vérification non faite les laissent. « Arrêter » ne paraît
  que pendant une vérification.
- **Place de la mise en garde.** À l'arrivée, la mise en garde d'EX-18.2
  (phrase courante, mention exacte, bloc de l'empreinte) est en tête, avant
  les étapes. Dès qu'un rapport, un refus ou une vérification non faite a été
  affiché, elle passe sous le résultat, juste avant « Pour les spécialistes »,
  entière et jamais repliée : le mot du verdict et sa phrase tiennent alors
  sur le premier écran, à 1280 comme à 390 px de large. La garantie reste sous
  le titre. Elle revient en tête si le vérificateur est altéré ou
  indisponible.
- **Marques.** Un texte du vérificateur, ou une phrase fixée par CT-6, est
  dans un élément `data-exact` ; une valeur venue des données, dans un élément
  `data-valeur`. L'essai du langage relève ce qui se lit hors de ces éléments
  et des blocs repliés fermés, et y refuse une liste publiée de termes de
  technicien.

Seconde lecture, même date (CT-6 §18, EX-18.9, points 14 à 19). Une règle :
la présentation ne peut que restreindre, jamais étendre, ce que le code de
retour dit ; ce qu'elle ajoute vient du seul rapport JSON, lu exactement.

- **« Valide » restreint.** Le mot vient toujours du code. Sous le code 0, le
  vert plein et son bouclier ne restent que pour huit contrôles réussis sans
  avertissement. Sinon le verdict prend la teinte de l'avertissement et le
  titre porte une mention fixe : « Valide, mais tout n'est pas prouvé » (un
  contrôle non réussi), « Valide, avec des réserves » (un avertissement), ou
  les deux. Juste dessous, ce que le dossier ne prouve pas, en mots : « Ce
  dossier ne prouve ni sa date, ni son inscription au registre public. » Si
  le rapport ne se lit pas exactement : le mot seul, en teinte neutre.
- **Contrôle réussi avec réserve.** Un avertissement est rattaché à un
  contrôle par le rapport lui-même (sa vérification, `check`, figure dans la
  liste `checks` du contrôle). La ligne du contrôle porte alors « Réussi, avec
  réserve » et renvoie aux réserves ; « Les huit contrôles ont réussi »
  devient « …, dont N avec réserve ». Sans rattachement donné par le rapport,
  aucune ligne ne change. Quand l'avertissement dit le contrôle sans valeur de
  preuve (AV-O-3, réseau d'essai ; table de CT-6 §18, point 15), la ligne porte
  « Sans valeur de preuve (réseau d'essai) » : le contrôle n'est plus compté
  parmi les réussis, ni dans « En résumé », et compte comme non prouvé.
- **Clés du dossier.** Sous les codes 0 et 3, quand le rapport dit que les
  clés du contrôle 6 sont celles que le dossier déclare (`facts.recorder_keys`),
  ou que le jeu d'approbateurs du contrôle 7 est celui du dossier
  (`facts.approval.set_source`), la ligne le dit, en teinte d'avertissement :
  cela montre que le dossier est cohérent, pas qui l'a signé.
- **Réserve signalée plusieurs fois.** Même identifiant, même phrase : dite
  une fois, suivie de « Le vérificateur la signale N fois dans ce dossier. »,
  puis chacun des textes exacts.
- **En résumé.** Avant le texte exact, quelques champs du rapport recopiés
  dans des gabarits fixes : le numéro d'ordre de l'action (`event.seq`), la
  période (`period`, en toutes lettres, temps universel, sans conversion de
  fuseau), l'approbation (`facts.approval` : nombre de signatures, nombre
  exigé), l'instant « au plus tard » de l'autorité d'horodatage
  (`facts.timestamp.upper_bound`). Chaque ligne seulement si son champ se lit
  et si son contrôle est réussi ; aucune hors des codes 0 et 3 ; aucune
  empreinte. Le rapport ne donne pas d'instant « au plus tard » sans hypothèse
  pour la chaîne Bitcoin : la ligne renvoie au texte exact. Quand le contrôle 8
  a réussi, une ligne dit que les heures du registre public, notées par le
  registre lui-même, ne sont comparées à rien. Le bloc finit par
  « Ce résumé aide à lire ; seul le texte exact ci-dessous fait foi. »
- **Non valide, aucun verdict, refus.** Sous un contrôle échoué, ce que le
  vérificateur dit de la vérification en échec, son identifiant à la fin
  entre parenthèses. Sous « Aucun verdict », la pièce en cause en clair,
  d'après le type de l'erreur (`error.kind`). Un refus porte le titre
  « Fichier refusé » ; la mention fixée « aucun rapport » est en tête de
  « Pour les spécialistes ». L'étape 1 dit le fichier refusé, sans coche ni
  « Tout est prêt ».
- **Étape 2.** Sous « Liste des références de confiance » : l'organisation
  qui a remis le dossier la fournit, c'est un fichier dont le nom finit par
  .json, et ce qui se passe sans elle. Quatrième lecture : la consigne de
  sûreté ajoute que la liste doit parvenir par un autre moyen que le dossier
  lui-même ; venue avec lui, elle ne prouve rien de plus que lui.

Troisième lecture, même date (CT-6 §18, EX-18.7 et EX-18.9) :

- **Titre du verdict.** Le mot et sa mention se lisent d'un seul tenant, à
  la même taille (« Valide, mais tout n'est pas prouvé ») ; ce que le dossier
  ne prouve pas suit, en gras, avant toute autre phrase. Le cadre du verdict
  n'est écrit qu'en langage courant : la formule exacte du vérificateur est
  en tête de « Pour les spécialistes », entière et jamais repliée.
- **Contrôle non fait.** Sa phrase dit quoi demander, et à qui, d'après la
  raison du rapport, le numéro du contrôle et les pièces ajoutées à l'étape
  2 (table de CT-6 §18, point 8) ; la raison exacte suit, entre parenthèses
  (cinquième lecture : elle est en tête de « Pour les spécialistes »).
  Une pièce absente du dossier renvoie à l'organisation qui l'a remis, non à
  l'étape 2. « Et maintenant ? » renvoie à ces lignes.
- **Réserves.** Chaque phrase de la table dit ce qui est signalé, puis sa
  conséquence (« Conséquence : … »).
- **Refus.** Tant qu'un refus est affiché, « Vérifier » est inactif et l'aide
  dit pourquoi ; ce qui est refusé (le dossier, ou une pièce complémentaire)
  est dit refusé là où il a été choisi ; un autre choix efface le refus.
- **Étape 2.** « Vérifiez d'où vient cette liste : c'est elle qui désigne
  les tiers de confiance. » est une phrase à part, à la taille du texte
  courant.
- **Barre haute.** Quand la page amène le résultat, ou l'étape 1, en haut de
  l'écran, elle lit la hauteur réelle de la barre haute (qui change avec la
  police et la largeur) et place l'élément dessous.

Cinquième lecture, même date (CT-6 §18, EX-18.5 et EX-18.9) :

- **Contrôle exigé sans valeur de preuve.** Le vérificateur rend 0 quand un
  contrôle exigé est réussi sur un réseau d'essai (CT-6 7.5) ; la page ne dit
  plus l'exigence remplie : titre « Valide, mais ce que vous avez exigé n'est
  pas prouvé, et avec des réserves », phrase du verdict à part, ligne
  « Contrôles que vous avez exigés et qui sont sans valeur de preuve : … »,
  troisième ligne de « Et maintenant ? » à part. La formule exacte, en tête
  de « Pour les spécialistes », reste celle du code 0.
- **Clés et approbateurs du dossier.** La pastille dit « Cohérent ; identité
  du signataire non prouvée » (contrôle 6) ou « … des approbateurs … »
  (contrôle 7) ; ces contrôles ne sont plus comptés parmi les réussis, ni
  dans le décompte ni dans le titre, et ce qu'ils ne prouvent pas est dit sous
  le titre. En version 0, le jeu d'approbateurs est toujours celui du
  dossier : sous le code 0, un rapport dont le contrôle 7 a réussi n'a donc
  plus le vert plein.
- **Deux causes de `hors_perimetre_version`.** D'après `absent_parts` : une
  partie requise du contrôle déclarée absente « hors périmètre CT-1 » (le
  dossier a été préparé sans elle), ou une pièce présente d'une forme que
  cette version ne contrôle pas ; une phrase chacune.
- **Codes.** La raison exacte d'un contrôle non fait (`ancre_absente`…) et
  les références des vérifications en échec (code 1) sont en tête de « Pour
  les spécialistes », hors de tout bloc replié, et non plus sur la ligne du
  contrôle ou sous le verdict ; le renvoi d'un contrôle aux réserves ne porte
  plus l'identifiant de l'avertissement, qui est dans son texte exact.
- **Registre public.** La ligne de « En résumé » dit qu'un écart entre les
  heures du registre et la période n'est ni signalé, ni expliqué, ni contrôlé
  par le vérificateur, et à qui demander une explication.
- **Empreintes publiées.** La mise en garde dit qui les publie (le projet,
  avec chaque version, dans un fichier signé) ; le bloc de l'empreinte nomme
  ce fichier (`SHA256SUMS`, EX-18.4). Le texte ne fixe pas l'adresse de cette
  publication : la page ne la donne pas.

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
| `test/verification-page-presentation.test.js` | présentation : lecture des contrôles du rapport JSON, libellés, gabarit et feuille de style sous Node ; dans un navigateur, avec un artefact factice et un travailleur de remplacement, verdict selon le code, liste des contrôles selon le rapport, deux mutants tués, rapports intacts dans leurs blocs, avertissements visibles, thème ; de bout en bout sur cinq dossiers des vecteurs ; langage (complément du 2026-11-18) : tables de phrases égales à celles de CT-6 dans les deux langues, phrase du code et d'aucun autre, avertissement hors table sans phrase, énoncé en membres de phrase et texte copié intacts, réduction des étapes, premier écran après une vérification à 1280×800 et à 390×844, aucun terme de technicien au premier niveau, neuf mutants tués | Playwright et son Chromium pour la partie navigateur ; go1.27.3 pour le bout en bout ; en attente sinon |
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
