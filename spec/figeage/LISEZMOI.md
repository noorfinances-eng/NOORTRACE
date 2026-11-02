# Figeage de la conception v1.0

La conception de NOORTRACE est figée en version 1.0 le 2 novembre 2026 :
c'est la porte 1 du plan de projet, qui ouvre la construction (phase 2).
Les neuf spécifications, leurs schémas et leurs vecteurs de test restent
modifiables, mais **toute modification est tracée** : aucun fichier de
`spec/` ne change, n'apparaît ni ne disparaît sans une entrée du registre.

## Ce qui est figé

Chaque fichier versionné sous `spec/`, sauf ce répertoire `spec/figeage/` :
les textes `CT-1` à `CT-9`, `spec/README.md`, les schémas de `schemas/` et
les vecteurs de `vecteurs/`, vérificateurs indépendants et confrontations
compris.

| Fichier | Contenu |
|---|---|
| `conception-v1.0.sha256` | Le manifeste : une ligne `<sha256>  <chemin>` par fichier figé, triée par octets, au format de `sha256sum`. Il n'est jamais réécrit. |
| `modifications.json` | Le registre : la version de la conception, la date du figeage, le SHA-256 du manifeste, puis les modifications `MC-1`, `MC-2`… dans l'ordre. |

Une modification porte son identifiant, sa date (`AAAA-MM-JJ`, jamais
antérieure à la précédente), l'étape de la construction qui la demande
(1 à 8, ou `null`), son motif en clair et la liste de ses fichiers, chacun
avec son condensé avant et après (`null` pour un fichier ajouté ou
supprimé).

## Vérifier

```sh
npm run conception:figeage
```

L'outil `scripts/conception/figeage.mjs` rejoue le registre depuis le
manifeste et compare l'état obtenu aux fichiers présents (suivis par git, et
nouveaux fichiers non ignorés). Il rend 0 si chaque écart est consigné, 1
s'il trouve un fichier modifié, ajouté ou supprimé sans consignation, un
manifeste retouché ou un registre mal formé, 2 en cas d'usage incorrect. Il
tourne dans l'intégration continue et dans `test/figeage.test.js`.

Le manifeste se vérifie aussi sans l'outil, depuis la racine du dépôt, tant
qu'aucune modification n'est consignée :

```sh
sha256sum -c spec/figeage/conception-v1.0.sha256
```

## Modifier une spécification

1. Faire la modification (texte, schéma, générateur puis vecteurs régénérés).
2. Consigner tous les fichiers touchés en une entrée :

   ```sh
   node scripts/conception/figeage.mjs --consigner --etape <n> --motif "<pourquoi>"
   ```

3. Mettre la modification et le registre dans le même commit.

Le motif dit ce qui change et pourquoi, en une ou deux phrases. Une
modification qui change une exigence (un `DOIT`, un format, un code
d'erreur) le dit, et la révision de la spécification visée est notée dans
son en-tête comme avant le figeage.
