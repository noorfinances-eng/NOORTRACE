# Paquet réviseur NOORTRACE

Ce paquet contient des dossiers de preuve NOORTRACE et de quoi les vérifier
hors ligne. Son format est le paquet réviseur version 0 (spécification CT-8,
section 13) ; chaque dossier se vérifie selon la spécification CT-6.

## Contenu

- `MANIFESTE.json` : la liste des fichiers, avec la taille et le SHA-256 de
  chacun, et, pour chaque dossier, le fichier d'ancres et le fichier
  d'en-têtes Bitcoin avec lesquels le vérifier.
- `dossiers/` : un répertoire par dossier de preuve.
- `ancres/` : le fichier d'ancres de confiance que vous avez remis à
  l'exploitant. Assurez-vous qu'il est le vôtre : `sha256sum <votre fichier
  d'ancres>` doit donner la valeur que le résumé imprime (avertissement
  AV-PR-3), sans son préfixe `0x` ; sinon, ou si vous n'avez remis aucun
  fichier, donnez le vôtre par l'option `--ancres`.
- `entetes/` : des en-têtes Bitcoin, crus seulement au travers du point de
  contrôle de votre fichier d'ancres.
- `attestation/` (si présent) : l'attestation de périmètre signée et le jeu
  d'approbateurs que l'exploitant déclare.
- `pieces/` (si présent) : des pièces publiées par l'exploitant pour préparer
  et recouper vos ancres (fiches de prestataire, manifeste d'instance du
  registre…). Elles sont déclaratives : l'outil ne les lit pas, et elles ne
  remplacent pas vos propres sources.
- `verificateur/` (si présent) : le vérificateur de référence, l'outil de
  vérification du paquet et la seule bibliothèque dont ils dépendent.

## Vérifier en une commande

Il faut Node.js 22 (éprouvé avec v22.22.0 sous Linux ; les versions
ultérieures et les autres systèmes ne sont pas vérifiés) ; aucun accès au
réseau n'est nécessaire.

1. Prenez l'outil de vérification dans une source que vous jugez sûre : le
   dépôt public de NOORTRACE, dont la note de version donne l'adresse et le
   commit, à une version publiée, ou la copie jointe sous `verificateur/`.
   Pour employer la copie jointe :
   - extrayez le paquet dans un répertoire neuf et vide par
     `tar -xkf <paquet.tar> -C <répertoire>` (jamais avec l'option `-P`) et
     exigez le code 0 : avec `-k`, un nom en double fait échouer `tar` au
     lieu de remplacer le premier fichier par le second ;
   - dans `<répertoire>/paquet-reviseur/verificateur/`, contrôlez les
     fichiers extraits par `sha256sum --strict -c <SHA256SUMS>`, où
     `<SHA256SUMS>` est la liste signée des SHA-256 du vérificateur publiée
     avec la note de version, par un autre canal que le paquet ; ni le
     manifeste du paquet ni la sortie de `--version` de la copie ne la
     remplacent. Tant qu'aucune version de l'outil n'est publiée, il n'y a
     pas de telle liste et ce contrôle n'est pas possible : prenez l'outil
     dans le dépôt public, à un commit que l'exploitant vous nomme avec
     l'empreinte du paquet, par le même canal ; vous vous fiez alors à lui
     pour l'outil.
2. Lancez, depuis n'importe quel répertoire :

       node <outil>/scripts/paquet-reviseur/verifier.mjs <paquet.tar> \
            --empreinte <SHA-256 du paquet reçu par un autre canal> \
            --ancres <votre fichier d'ancres>

   `<outil>` est la racine du dépôt, ou le répertoire `verificateur/` de la
   copie extraite. Les deux options sont facultatives ; sans elles, le
   rapport le signale. `--json` donne le rapport en JSON, `--langue en` en
   anglais. `--exiger` exige des contrôles de CT-6 (numéros 1 à 8).

L'outil contrôle l'archive sans rien écrire (en-têtes, noms, fichiers contre
le manifeste), puis seulement l'extrait dans un répertoire neuf sous le
répertoire temporaire du système, vérifie chaque dossier, et efface ce
répertoire.

Sur un paquet valide, la rubrique « Vérifications non réussies » peut porter
jusqu'à trois lignes « non exécuté », qui ne sont pas des échecs :
`PR-2 (empreinte_non_fournie)` si vous n'avez pas donné `--empreinte`,
précaution omise ; `PR-11 (sans_objet)` si le paquet n'a pas de vérificateur
joint ; `PR-12 (sans_objet)` s'il n'a pas d'attestation. Avec la commande
recommandée, sur un paquet sans vérificateur joint et avec attestation, il
n'en reste qu'une : `PR-11`. `PR-11 (auto_comparaison)` dit que l'outil
exécuté est la copie jointe elle-même, qui ne peut pas se contrôler.

Les contrôles 1 à 8 et les identifiants `D-`, `E-`, `C-`, `M-` d'un dossier
sont ceux de CT-6 (section 8) ; la section 13.7 de CT-8 nomme les huit
contrôles. Pour décider, seuls comptent le code, le verdict et la provenance
des ancres : avec « ancres du paquet », un code 0 ne vaut qu'après
comparaison de leur SHA-256 à votre fichier (avertissement AV-PR-3). Dans la
ligne « Énoncé » d'un dossier, « du réviseur » désigne le fichier d'ancres
employé : tant que la ligne du dossier dit « ancres du paquet » et que vous
n'avez pas fait cette comparaison, lisez « de l'exploitant ».

## Codes de retour

Le code 4 l'emporte sur tout, car aucun dossier n'est alors vérifié ; entre
dossiers, la priorité est 1, puis 2, 3, 0.

| Code | Sens |
|---|---|
| 0 | Paquet intact, tous les dossiers valides. |
| 1 | Paquet intact, au moins un dossier invalide. |
| 2 | Entrée inutilisable : usage, archive illisible, extraction impossible, erreur interne ; ou paquet intact dont un dossier au moins rend le code 2 (fichier d'ancres refusé) et aucun le code 1. |
| 3 | Paquet intact, aucun dossier invalide ni inutilisable, au moins un dossier incomplet (option `--exiger`). |
| 4 | Paquet non conforme : aucun dossier n'est vérifié. |

Conduite selon le code :

- Code 1 : le paquet est bien celui que le manifeste décrit, mais au moins un
  dossier est invalide. Ce dossier ne prouve pas l'événement (CT-6 §8.3) :
  conservez le rapport `--json` et signalez-le à l'exploitant. Chaque autre
  dossier garde le sens de son propre code, sous les ancres employées.
- Code 2 de type `usage` (option, fichier `--ancres` illisible, répertoire
  `--conserver` existant) : il vient de votre commande ; corrigez-la et
  relancez. Un code 2 avec un paquet intact et un fichier d'ancres refusé met
  en cause ce fichier (le vôtre, ou celui du paquet si vous n'avez pas donné
  `--ancres`), non l'intégrité du paquet.
- Code 3 : un contrôle exigé par `--exiger` n'a pas réussi, sans qu'aucune
  vérification soit en échec ; le dossier n'est pas invalide, il est
  incomplet. Demandez les pièces manquantes ou relancez après la mise à
  niveau des preuves.
- Code 4, ou code 2 dû à l'archive (illisible, extraction impossible) : le
  paquet est refusé et n'est pas exploité. Conservez l'archive, son SHA-256
  et le rapport `--json`, et demandez à l'exploitant un nouveau paquet, dont
  l'empreinte vous parvient par un autre canal. Un échec de PR-2 dit
  seulement que le SHA-256 de l'archive diffère de la valeur donnée :
  relisez l'empreinte reçue avant de conclure que le paquet n'est pas celui
  annoncé. Après un échec de PR-2, une seconde exécution sans `--empreinte`
  peut localiser l'écart (PR-3 à PR-9 s'exécutent alors ; PR-8 nomme le
  fichier en cause) : joignez son rapport `--json` au signalement. Elle ne
  change pas la décision : le paquet reste refusé tant que vous n'avez pas
  une archive dont le SHA-256 égale l'empreinte reçue, relue.

## Ce que le résultat prouve, et ce qu'il ne prouve pas

- « Paquet intact » dit que les fichiers sont ceux que le manifeste décrit,
  octet pour octet. Il ne dit pas qui a fait le paquet : seule l'empreinte
  reçue par un autre canal (`--empreinte`) relie ce paquet à son émetteur.
- « VALIDE » pour un dossier reprend l'énoncé du vérificateur (CT-6), qui ne
  vaut que ce que valent les ancres employées. Des ancres prises dans le
  paquet sont celles de l'exploitant tant que vous ne les avez pas
  comparées aux vôtres.
- L'attestation de périmètre est déclarée par ses signataires, non prouvée.
- Le paquet ne prouve rien des événements qu'il ne contient pas : il ne dit
  pas que la liste des dossiers est complète.

## Sécurité

N'extrayez jamais un paquet avec `tar -P` ni dans un répertoire qui contient
déjà des fichiers. L'outil refuse les liens, les noms absolus, les noms qui
contiennent `..`, les doublons et tout fichier que le manifeste ne déclare
pas.
