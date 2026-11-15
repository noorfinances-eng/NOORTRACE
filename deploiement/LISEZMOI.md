# deploiement/ — fichiers de conteneur de référence de NOORTRACE

Ce répertoire contient les fichiers de déploiement de **référence** de CT-8
(`spec/CT-8-deploiement-et-exploitation.md`, sections 3, 4, 7, 8, 10 et 11).
Les images `noortrace/*` que les fichiers Compose désignent sont construites
depuis `conteneurs/<nom>/Dockerfile` (étape 7), sans être publiées ; celle du
nœud (`noortrace/noorcore`) depuis `chain/docker/Dockerfile`. Les fichiers
Compose ne sont jamais lancés dans le dépôt : ils sont vérifiés par analyse
statique, et les essais des images les lancent sur un projet Compose
temporaire.

| Fichier | Contenu |
|---|---|
| `compose/rapide.yaml` | Installation rapide, au plus 15 minutes (CT-8 §7) : un hôte, mode observation, classe de garde D, ancrage de test (jeton RFC 3161 de clôture du serveur interne non qualifié, service `horodatage` dans l'espace réseau de l'enregistreur ; outil `horodatage-init` du pas IR-2 ; preuves OpenTimestamps) |
| `compose/production.yaml` | Installation complète de production (CT-8 §8) |
| `images/images.json` | Description des services et de leurs images (schéma `spec/schemas/conteneurs-v0.schema.json`) |
| `config/rapide/configuration.json` | Configuration de l'enregistreur de l'installation rapide (schéma `configuration-enregistreur-v0`) |
| `config/modele-production/configuration.json` | Modèle de la configuration de l'enregistreur de production (CT-8 §8.3, pas IC-14), dont chaque secret est lu dans `/run/secrets/` d'un secret que `compose/production.yaml` monte |
| `config/rapide/ancrage.json` | Document `ancrage-v0` de l'installation rapide (CT-8 §7.3) : le serveur RFC 3161 interne en prestataire principal (`http://127.0.0.1:2020/`, admis hors production seulement, CT-5 EX-4.9 règle 4), calendriers OpenTimestamps, aucun registre ; au pas IR-3, `configurer-rapide.mjs --ac-horodatage --sortie-ancrage` y recopie le certificat de l'AC créée au pas IR-2 (dans le dépôt : l'AC de test des vecteurs de CT-6) |
| `hote/preparer-hote.sh` | Préparation de l'hôte du système de référence, Ubuntu 24.04 (CT-8 IC-2) : paquets du système, Node.js 22.23.4 à SHA-256 épinglé, groupe, stockage ; `--simulation` dit ce qui reste à faire |
| `taches/` | Gabarits systemd des tâches TP-1 à TP-8 et de la sauvegarde (CT-8 EX-8.6, IC-16), `poser-taches.sh`, `executer-tache.sh` (une ligne horodatée par exécution), modèle des réglages `taches.env.modele` |
| `runbooks/RB-<n>.md` | Copies des runbooks RB-1 à RB-8 de CT-8 §10.12 à §10.19, égales aux blocs du texte (`node scripts/deploiement/extraire-runbooks.mjs --verifier`) ; CT-8 fait foi |
| `observabilite/` | Supervision de référence (CT-8 §10) : `regles-noortrace.yml` (règles d'alerte), `tests-regles.yml` (tests pour `promtool test rules`), `prometheus.yml` (collecte), `tableau-noortrace.json` (tableau de bord) ; la règle `noortrace_image_differente` (CT-8 §10.4, gravité critique) alerte sur toute ligne `image_mismatch` du journal d'exploitation, que le démon lancé avec `--image-attendue` écrit quand l'empreinte de son code diffère de celle de l'image publiée (CT-2 EX-18.10) |

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
archive de sauvegarde (CT-8 EX-11.2). L'installation rapide n'a aucun secret
RFC 3161 : les clés du serveur interne restent dans le volume `horodatage`,
où l'outil `horodatage-init` les crée au pas IR-2 ; il en écrit le certificat
de l'AC et la CRL sous `config/rapide/` (`ac-horodatage.pem`,
`crl-horodatage.pem`), que le réviseur porte dans son fichier d'ancres pour
que le contrôle 4 s'exécute (CT-8 IR-8).

L'archive de déploiement (CT-8 EX-3.6) contient ce répertoire, les outils de
`scripts/deploiement/` qui s'exécutent sur l'hôte (dont `sauvegarde.mjs` et
`archiver-journal-exploitation.mjs`), leurs bibliothèques, les schémas et une
copie figée de leurs deux dépendances ; elle s'écrit par
`npm run deploiement:archive -- --sortie <répertoire à créer>`, avec la liste
`SHA256SUMS` de ses fichiers. Les outils de supervision ne sont pas encore
dans l'archive ; ils s'exécutent depuis une copie du dépôt :

```bash
node scripts/deploiement/regles.mjs --configuration <configuration> --ancrage <ancrage.json> > regles.yml
node scripts/deploiement/extraire-journaux.mjs --repertoire <journaux> --sortie <collecteur textfile>/noortrace.prom
node scripts/deploiement/sonde.mjs --approbation http://127.0.0.1:8601 --rpc validateur=<url> --sortie <fichier>
node scripts/deploiement/sonde.mjs releve --check registre_gels --sortie <fichier> -- <commande de relecture>
node scripts/deploiement/collecteur.mjs lancer --travail <répertoire> --cible enregistreur=127.0.0.1:8500 --cible noorcore=aucune --textfile <collecteur textfile>
node scripts/deploiement/mesure-supervision.mjs tm-34 … | tm-35 relever … | tm-35 rapport …
```

Le collecteur lance Prometheus 3.5.0 (binaire de l'archive à SHA-256 fixé de
CT-8 EX-10.10) sur la boucle locale avec les règles de référence ;
`mesure-supervision.mjs` joue les campagnes de mesure de la supervision (CT-9
TM-34, TM-35), hors système de référence.

Règles de la revue de sécurité de l'étape 8 : `poser-taches.sh` refuse une
racine qui n'appartient pas au superutilisateur ou qu'un autre compte peut
écrire (code 2) ; `poser-taches.sh --supervision [<répertoire>]` pose les
services `noortrace-extracteur` et `noortrace-sonde` (compte
`noortrace-supervision`, `superviser.sh`) ; avec `NOORTRACE_SUPERVISION`,
TP-4, TP-5 et la relecture de TP-6 passent par `sonde.mjs releve`, qui rend
le code de la relecture, et chaque tâche écrit `tache-<id>.prom` ; TP-4 relit
tout le registre des gels (`worm gel liste`), `NOORTRACE_TP4_GELS` est
facultatif ; `sonde.mjs` et `extraire-journaux.mjs` écrivent, en mode
`--intervalle`, leur témoin de vie `noortrace_<outil>_derniere_passe_s`, et
l'extracteur écarte un procès-verbal daté dans le futur ; `preparer-hote.sh`
exige Node.js v22.23.4, vérifie l'archive sur une copie privée, pose la
rotation des journaux du moteur dans `daemon.json` (`--daemon-json` pour les
essais) et ne suit aucun lien dans le procès-verbal ;
`archiver-journal-exploitation.mjs` chaîne son index (rang, empreinte
précédente), reprend après panne, ne suit aucun lien et borne la taille
(`--octets-max`) ; l'archive de sauvegarde n'emporte que le répertoire du
journal ; le banc client fictif tourne dans le projet `noortrace-banc` et
refuse un hôte qui porte le projet `noortrace` ; `configurer-rapide.mjs`
avertit sans `--ac-horodatage` ; le pont stdio prend `--inactivite-ms`,
resérialise chaque message, tient en cours l'identifiant d'une requête
abandonnée et expose `sessions_max` sur `/sante`, et son serveur de fichiers
ne se termine sur aucun message.

Les cas de démonstration de CT-9 TE-1 et TE-2 (assurance, administration) se
jouent sur les images de la démonstration de référence : voir
`demo/cas/LISEZMOI.md`.

L'extracteur et la sonde écrivent au format texte de Prometheus, par
renommage, pour le collecteur de fichiers de l'exportateur de nœud
(`127.0.0.1:9100`). Les images se construisent depuis la racine du dépôt par
`node scripts/deploiement/construire-images.mjs --double --sortie <répertoire>`
(outil de la personne qui construit, hors de l'archive) ; aucune image n'est
poussée vers un registre. Le démon Docker doit employer le magasin d'images
containerd (`/etc/docker/daemon.json` : `{"features": {"containerd-snapshotter":
true}}`, défaut de Docker 29) : avec le magasin classique, défaut de Docker 28,
l'option `rewrite-timestamp` est ignorée et le script refuse de construire.
