# demo/ — démonstration de référence de NOORTRACE

La démonstration de CT-2 §19 (`spec/CT-2-enregistreur.md`) : un agent
scénarisé traite un sinistre fictif à travers l'enregistreur, un paiement est
retenu jusqu'à l'approbation de deux approbateurs, la période est close et
enregistrée sur une instance de développement du registre, et le dossier de
preuve du paiement est vérifié hors ligne. Sans clé d'API, sans accès à
Internet, avec des données fictives seulement.

```bash
docker compose -f demo/compose.yaml up
```

La commande affiche les journaux des neuf services. Le service `verificateur`
imprime le résultat (CT-2 §19.4) :

```text
noortrace — démonstration de référence
  enregistreur    : 0.1.0, clé rec-test-01 (classe D, démonstration), bail file, époque 1
  journal         : assureur-demo / journal-demo, 8 événements, période 2026-11-13T07:00:00Z → 08:00:00Z
  registre-dev    : clé inscrite (RecorderRegistry), période enregistrée (PeriodRegistry), racine ancrée (AttestationRegistry), bloc certifié par 4 validateurs
  dossier         : dossiers/seq-7/ (demo__payments.create, approuvé par 0x7099…79c8 et 0x3c44…93bc, seuil 2 sur 3)
  vérificateur    : 6 contrôles [ok], 2 non exécutés avec raison admise (T-*, O-* : démonstration hors ligne)
  Résultat : VALIDE — cet événement est bien formé, chaîné à ses voisins, inclus dans la période close par ce manifeste
             signé par cette clé, approuvé par ces adresses, et son ancre est dans un bloc que les validateurs nommés ont signé.
             Il ne prouve pas la date (ancres RFC 3161 et OpenTimestamps absentes : démonstration hors ligne).
  Ce que l'agent n'a pas pu faire : joindre outils-demo ou modele-demo directement (réseaux séparés) ; obtenir
  le résultat de payments.create avant qu'un événement durable existe ; effacer seq 5 (sa demande retenue).
  Durée totale : 52,108 s
```

La période, le nombre de validateurs qui ont signé le bloc le moins signé
(trois ou quatre : le quorum est de trois) et la durée varient d'un passage à
l'autre ; le reste est fixe. Le service se termine avec le code 0 si le
dossier est valide, 1 sinon.

`docker compose up` reste attachée tant que les autres services tournent
(Ctrl-C pour finir). Pour un script, qui doit rendre la main à la fin du
vérificateur :

```bash
docker compose -f demo/compose.yaml up --detach
docker compose -f demo/compose.yaml wait verificateur      # code du vérificateur
docker compose -f demo/compose.yaml logs --no-log-prefix verificateur
```

La clôture anticipée termine le journal (CT-2 EX-19.4) : un nouveau passage
exige un nouveau journal.

```bash
docker compose -f demo/compose.yaml down --volumes
```

Le port de santé de l'enregistreur est publié sur `127.0.0.1:8500` ; s'il est
pris, `NOORTRACE_DEMO_PORT_SANTE=<port> docker compose …`.

## Ce que la démonstration ne prouve pas

- **La date.** Aucun jeton RFC 3161, aucune preuve OpenTimestamps : la
  démonstration est hors ligne. Les contrôles 4 et 5 du vérificateur ne sont
  pas exécutés, et le résultat le dit.
- **Rien sur un déploiement réel.** Toutes les clés sont des clés de test
  publiques (ci-dessous) ; l'enregistreur tourne en `developpement`, classe
  de garde D, que la production refuse ; le registre est une instance neuve à
  chaque lancement, dont les quatre validateurs tournent dans un seul
  conteneur.
- **Rien sur un modèle.** `modele-demo` n'est pas un modèle : il rend trois
  réponses fixes.

## Les services

| Service | Image | Réseaux | Rôle |
|---|---|---|---|
| `enregistreur` | `noortrace/enregistreur` | `hotes`, `outils`, `fournisseurs`, `registre`, `sante` | Le démon : frontal MCP (`:8300/mcp`), passerelle de modèle (`:8400`), santé (`:8500`) ; composant d'ancrage |
| `outils-demo` | `noortrace/outils-demo` | `outils` | Serveur d'outils MCP (ère `2026-07-28`) : `claims.get`, `claims.search`, `payments.create` |
| `modele-demo` | `noortrace/modele-demo` | `fournisseurs` | Simulateur de l'API Messages (CT-2 §19.3) |
| `agent-demo` | `noortrace/agent-demo` | `hotes` | Agent scénarisé ; il ne joint que l'enregistreur, et l'affiche |
| `registre-dev` | `noortrace/registre-dev` | `registre` | Instance de développement du registre : quatre validateurs, contrats déployés au démarrage |
| `approbation` | `noortrace/approbation` | aucun | Le service d'approbation de CT-3, tel qu'il est livré : distinct du démon, sans aucune clé d'approbateur |
| `approbateur-demo` | `noortrace/approbateur-demo` | `registre` | Les approbateurs : **seul détenteur** des clés des comptes Hardhat 1 à 3 |
| `exploitation-demo` | `noortrace/enregistreur` | aucun | Les gestes de l'exploitant, dans l'espace de processus du démon : clôture anticipée, remise de la demande de clôture signée, export du dossier |
| `verificateur` | `noortrace/verificateur-demo` | aucun | Vérifie le dossier exporté (binaire `noortrace-verifier`) et imprime le résultat ; ne fait que vérifier |

Les quatre réseaux `hotes`, `outils`, `fournisseurs` et `registre` sont
internes (aucune sortie). `sante` ne sert qu'à publier le port de santé sur la
boucle locale de l'hôte, sans traduction d'adresse en sortie.

Séquence (CT-2 §19.2) :

1. `registre-dev` démarre la chaîne, déploie les contrats, le jeu
   d'approbateurs de l'organisation et approvisionne la clé de chaîne de
   l'enregistreur.
2. `approbateur-demo` inscrit la clé de l'enregistreur au registre (demande
   signée par les comptes 1 et 2), puis inscrit ses deux approbateurs à
   l'annuaire du service d'approbation.
3. `enregistreur` démarre ; `agent-demo` joue le tour : échange de modèle,
   lecture `demo__claims.get`, échange en flux SSE, écriture
   `demo__payments.create` retenue (`a_approuver`).
4. `approbateur-demo` lit le ticket par le canal de la console, recalcule ce
   qu'il signe et vote avec les comptes 1 et 2 ; le service remet la décision
   au démon, qui la vérifie et la scelle ; l'agent ré-émet l'appel, qui est
   relayé.
5. `exploitation-demo` clôt la période, remet le manifeste aux approbateurs,
   remet au démon la demande de clôture qu'ils ont signée, attend que le démon
   l'ait relayée au registre, puis fait exporter le dossier de `seq 7`.
6. `verificateur` vérifie le dossier et imprime.

## Qui détient quelle clé

Toutes ces clés sont **publiques** : elles viennent des vecteurs de la
spécification et ne protègent rien.

| Clé | Détenteur | D'où elle vient |
|---|---|---|
| Clé Ed25519 `rec-test-01` de l'enregistreur (`cle-rec-test-01.pem`) | `enregistreur` | CT-1 §13 : graine SHA-256 de `noortrace/vecteurs/v0/cle-enregistreur/rec-test-01` |
| Clé de chaîne de `rec-test-01` | `enregistreur` | CT-4 : SHA-256 de `noortrace/vecteurs/v0/cle-chaine/rec-test-01` |
| Comptes Hardhat 1 à 3 (approbateurs) | `approbateur-demo`, et lui seul | mnémonique publique de test (CT-3 annexe A.2) |
| Compte Hardhat 0 (trésorerie et déployeur du développement) | `registre-dev` | même mnémonique (CT-4) |
| Clés des quatre validateurs | `registre-dev` | CT-4 : SHA-256 de `noortrace/vecteurs/ct4/validateur/v<i>` |
| Jetons d'hôte, de passerelle, du canal de la console, clé du simulateur, clé MAC de relais, clé de stockage du service | écrits dans `compose.yaml` | valeurs de démonstration |

Ni le démon ni le service d'approbation ne détiennent de clé d'approbateur :
`approbateur-demo` signe, le service compte les votes, le démon vérifie les
signatures avant de sceller.

## Fichiers

| Fichier | Contenu |
|---|---|
| `compose.yaml` | La composition |
| `configuration-demo.json` | Configuration de l'enregistreur (schéma `configuration-enregistreur-v0`) : mode `passerelle`, politique `demo-2026-12`, approbation en mode `erreur` |
| `compose.modele-reel.yaml`, `configuration-demo-modele-reel.json` | Option « modèle réel » : surcharge de la composition et configuration à la route du fournisseur |
| `ancrage-demo.json`, `instance-registre.json` | Document `ancrage-v0` et manifeste d'instance du registre, montés côte à côte ; le manifeste est celui que `registre-dev` déploie, à l'octet près |
| `approbation-demo.json` | Configuration du service d'approbation (`configuration-approbation-v0`) |
| `ancres-demo.json` | Fichier d'ancres du réviseur que `verificateur` emploie (CT-6 §12) |
| `attestation-perimetre-demo.json` | Attestation de périmètre de la démonstration (CT-7 §7), non signée |
| `cle-rec-test-01.pem` | Clé de test de l'enregistreur, PKCS#8 |
| `exploitation-demo.mjs` | Programme du service `exploitation-demo` |
| `rapprochement.mjs` | Rapprochement de l'usage du fournisseur de modèle et du journal (CT-7 EX-3.8) |
| `construire-images.mjs` | Construction des six images de la démonstration |
| `mesurer-duree.mjs` | Mesure de la durée (CT-9 TM-43) |

## Option « modèle réel » (CT-2 EX-19.3)

```bash
MODELE_REEL=<identifiant du modèle> ANTHROPIC_API_KEY=<clé> \
  docker compose -f demo/compose.yaml -f demo/compose.modele-reel.yaml up
```

Le fichier de surcharge donne à l'enregistreur la configuration
`configuration-demo-modele-reel.json` : la route `/v1/messages` part vers le
fournisseur, avec la clé de la passerelle (`credentials: "propre"`), lue dans
la variable d'environnement, jamais écrite sur disque ni dans le journal.
L'agent joue alors un vrai tour d'agent, où le modèle décide des appels : la
sortie n'est plus déterministe (le nombre d'événements et le `seq` du paiement
changent), et sans paiement approuvé il n'y a pas de dossier, donc pas de
verdict. Le réseau `fournisseurs` trouve une sortie ; l'agent reste sur le seul
réseau `hotes`, sans la clé.

**Cette option n'a pas été exécutée contre l'interface réelle** : les essais
du dépôt ne joignent aucun réseau public et n'emploient aucune clé. Seules sa
configuration et sa surcharge sont vérifiées, sans être lancées.

## Construire les images

Les images ne sont pas publiées : elles se construisent depuis le dépôt, avec
Docker et le magasin d'images containerd (`deploiement/LISEZMOI.md`).

```bash
npm ci
npm run compile                                   # codes de création des contrats (hh-artifacts/)
node scripts/deploiement/construire-images.mjs --images enregistreur,approbation
node demo/construire-images.mjs
```

`noortrace/registre-dev` exige en plus l'image locale du nœud,
`noortrace/noorcore:618fcef-noortrace`, construite par `chain/docker/Dockerfile`
avec le correctif de `chain/patches/`, qui n'est pas dans le dépôt : sans elle,
cette image ne se construit pas, et la démonstration ne se lance pas.

## Rapprochement de l'usage (CT-7 EX-3.8)

Le simulateur publie le nombre de requêtes reçues par clé et par route
(`GET /demo/usage`). `rapprochement.mjs` le compare au nombre d'échanges
`noortrace.modele.echange` du journal ; un excédent révèle un usage de la clé
de la passerelle hors de l'enregistreur.

```bash
node demo/rapprochement.mjs --configuration demo/configuration-demo.json \
  --segments <copie des segments du journal> --usage <relevé du simulateur>
```

Code 0 sans écart, 3 avec un écart.

## Essais

```bash
npx mocha --timeout 600000 test/demonstration.test.js               # sans moteur de conteneurs
npx mocha --timeout 600000 test/demonstration-composition.test.js   # composition lancée ; en attente sans Docker ou sans les images
```
