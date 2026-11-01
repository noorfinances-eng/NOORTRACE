# deploiement/ — fichiers de conteneur de référence de NOORTRACE

Ce répertoire contient les fichiers de conteneur de **référence** de CT-8
(`spec/CT-8-deploiement-et-exploitation.md`, sections 3, 4, 7 et 8). Ils sont
écrits pour la construction de la phase 2 : les images `noortrace/*` qu'ils
désignent ne sont pas encore construites, sauf celle du nœud
(`noortrace/noorcore`, `chain/docker/Dockerfile`). Ils ne sont jamais lancés
dans le dépôt ; ils sont vérifiés par analyse statique.

| Fichier | Contenu |
|---|---|
| `compose/rapide.yaml` | Installation rapide, au plus 15 minutes (CT-8 §7) : un hôte, mode observation, classe de garde D, ancrage de test |
| `compose/production.yaml` | Installation complète de production (CT-8 §8) |
| `images/images.json` | Description des services et de leurs images (schéma `spec/schemas/conteneurs-v0.schema.json`) |
| `config/rapide/configuration.json` | Configuration de l'enregistreur de l'installation rapide (schéma `configuration-enregistreur-v0`) |
| `config/modele-production/configuration.json` | Modèle de la configuration de l'enregistreur de production (CT-8 §8.3, pas IC-14), dont chaque secret est lu dans `/run/secrets/` d'un secret que `compose/production.yaml` monte |

Vérifier les fichiers (vérifications CO-1 à CO-14 de CT-8 §4.4) :

```bash
npm run deploiement:conteneurs
```

Les commandes Compose s'exécutent depuis ce répertoire, avec
`--project-directory .`, pour que `./config` et `./secrets` se résolvent
contre lui :

```bash
docker compose --project-directory . -f compose/rapide.yaml config --quiet
```

Le répertoire `secrets/` n'existe jamais dans le dépôt : il est créé à
l'installation (CT-8, pas IR-2 et IC-8), avec un fichier par secret en mode
`0400`, propriété du compte du service qui le lit ; il n'entre jamais dans une
archive de sauvegarde (CT-8 EX-11.2).

L'archive de déploiement (CT-8 EX-3.6) contient ce répertoire, les outils de
`scripts/deploiement/` qui s'exécutent sur l'hôte, leurs bibliothèques, les
schémas et une copie figée de leurs deux dépendances ; elle s'écrit par
`npm run deploiement:archive -- --sortie <répertoire à créer>`, avec la liste
`SHA256SUMS` de ses fichiers.
