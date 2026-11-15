# demo/cas/ — les deux cas de démonstration du plan

Les deux cas de l'étape 8 (CT-9 TE-1 et TE-2 ; plan de projet, annexe III du
règlement), joués sur l'infrastructure de la démonstration de référence
(`demo/compose.yaml`, `demo/LISEZMOI.md`), avec la console d'exploitation
réelle de CT-3 et le service d'approbation réel :

| Cas | Entrée | Agent | Décision soumise aux approbateurs | Dossiers exportés |
|---|---|---|---|---|
| `assurance` | TE-1 (annexe III, point 5 c) | souscription en assurance de personnes : lit la proposition, demande la classe de risque de la grille, enregistre la décision | `souscription.decider` : acceptation en classe C avec majoration en pour cent → **approuvée** par deux approbateurs depuis la console | l'écriture approuvée, la décision |
| `administration` | TE-2 (annexe III, point 5 a) | instruction d'une demande de prestation : lit la demande, vérifie les pièces, notifie la décision | `decision.notify` « refuser » → **refusée** par les deux approbateurs depuis la console ; l'agent notifie alors les pièces à compléter (automatique) | la décision de refus, l'appel autorisé |

Données fictives seulement : pseudonymes (`P-01`, `D-07`), tranches d'âge,
domaines `.example`, clés de test publiques. **Rien qui se paie** : aucune
devise, aucune somme ; le cas « assurance » rend une classe de risque et une
majoration en pour cent (décision du porteur du 13 novembre 2026).

## Ce qui change par rapport à la démonstration de référence

La surcharge `compose.cas.yaml` se lit après `demo/compose.yaml`, avec le
fichier de variables du cas (`<cas>/cas.env`). Mêmes images : aucune n'est
reconstruite ; les programmes des cas (`commun/*.mjs`) sont montés dans les
images, à côté des programmes de la démonstration qu'ils réemploient.

| Service | Démonstration de référence | Cas |
|---|---|---|
| `outils-demo` | serveur d'outils des sinistres | `commun/outils-cas.mjs` : catalogue JSON du cas (`<cas>/outils.json`) |
| `modele-demo` | simulateur à scénario fixe | `commun/modele-cas.mjs` : scénario JSON du cas (`<cas>/modele.json`) |
| `agent-demo` | agent scénarisé | `commun/agent-cas.mjs` : attend la décision des approbateurs ; un refus est rendu au modèle, qui poursuit |
| `approbateur-demo` | inscrit la clé, vote, signe la clôture | `commun/approbateur-cas.mjs` : inscrit la clé et signe la clôture ; **ne vote pas** |
| `approbation` | service réel, sans réseau | inchangé ; configuration du passage (`approbation-cas.json` : organisation, journal, origine de la console réelle, administrateur) |
| console | — (votes par le canal de la console, scriptés) | **serveur de console réel** (`paquets/console`) sur l'hôte, relié à la prise du canal de la console du service (volume `prise-console`) ; les approbateurs s'inscrivent et signent depuis ses écrans |
| `horodatage` | — | serveur RFC 3161 interne (`noortrace/tsa-interne`, CT-8 §7) dans l'espace réseau de l'enregistreur : jeton de la période, contrôle 4 |
| `exploitation-demo` | exporte le dossier de seq 7 | `commun/exploitation-cas.mjs` : exporte les dossiers que nomme `NOORTRACE_CAS_EXPORTS` |
| `verificateur` | imprime CT-2 §19.4 | non lancé (profil `reference`) : vérification hors de la composition |

Les quatre réseaux internes et les attachements ne changent pas : l'agent ne
joint que l'enregistreur.

## Jouer un cas

Préparation du passage (les gestes IR-2 et IR-3 de CT-8 : autorité du serveur
interne dans le volume `horodatage`, document d'ancrage, configuration du
service), dans un répertoire de travail absolu :

```bash
T=$PWD/travail-assurance
node demo/cas/preparer.mjs preparer --cas assurance --travail "$T" --projet cas-assurance \
  --origine-console https://127.0.0.1:8443 --issuer https://127.0.0.1:8444
NOORTRACE_CAS_TRAVAIL="$T" docker compose -p cas-assurance --project-directory demo \
  --env-file demo/cas/assurance/cas.env -f demo/compose.yaml -f demo/cas/compose.cas.yaml \
  up --detach enregistreur horodatage
```

L'origine de la console et l'émetteur d'identité sont ceux du serveur de
console et du fournisseur OIDC que l'on déploie ensuite sur l'hôte (le service
d'approbation n'admet que cette origine et cet administrateur, `oidc <issuer>
admin-1`). Dans les essais, ce sont le serveur de console réel et le fournisseur
OIDC simulé des essais de l'étape 6, et les approbateurs sont deux personnes
dans Chromium avec le portefeuille EIP-1193 simulé (comptes de test 1 et 2) ;
aucun fournisseur d'identité ni portefeuille réel n'est fourni ici.

Puis : les deux approbateurs s'inscrivent (écran Mon adresse), l'administrateur
les valide (écran Annuaire) ; `up --detach agent-demo` ; les approbateurs
décident sur l'écran Ticket ; l'agent termine ; `up --detach exploitation-demo`
clôt la période et exporte les dossiers dans le volume `exports`
(`dossiers/<nom>/`, contexte `cas.json`). Enfin le fichier d'ancres du
réviseur, avec une CRL postérieure à la clôture :

```bash
node demo/cas/preparer.mjs ancres --cas assurance --travail "$T" --projet cas-assurance
```

Vérification hors ligne de chaque dossier (copié hors du volume) par les deux
vérificateurs de CT-6, puis paquet réviseur de CT-8 §13 :

```bash
node scripts/verify/dossier.mjs <dossier> --ancres "$T/ancres-cas.json"
noortrace-verifier <dossier> --ancres "$T/ancres-cas.json"
node scripts/paquet-reviseur/construire.mjs --description <description.json> --sortie paquet.tar
node scripts/paquet-reviseur/verifier.mjs paquet.tar --ancres "$T/ancres-cas.json" --empreinte <sha256>
```

Résultat attendu (joué par `test/cas-demonstration-composition.test.js`) :
verdict `valide`, contrôles 1, 2, 3, 4, 6, 7 et 8 réussis (7 pour un
événement qui porte une approbation), contrôle 5 non exécuté (aucune preuve
OpenTimestamps : la démonstration est hors ligne), même énoncé par les deux
vérificateurs ; paquet : code 0, PR-1 à PR-12 réussies, avec l'attestation de
périmètre du cas (`<cas>/attestation-perimetre-cas.json`) signée par les deux
comptes de test.

Un nouveau passage exige un nouveau journal : `docker compose … down --volumes`.

## Fichiers

| Fichier | Contenu |
|---|---|
| `compose.cas.yaml` | La surcharge commune aux deux cas |
| `preparer.mjs` | `preparer` (autorité, `ancrage-cas.json`, `approbation-cas.json`) et `ancres` (`ancres-cas.json`) |
| `commun/outils-cas.mjs`, `modele-cas.mjs`, `agent-cas.mjs`, `approbateur-cas.mjs`, `exploitation-cas.mjs` | Programmes des cas, montés dans les images |
| `<cas>/cas.env` | Variables de la surcharge : organisation, journal, dossiers à exporter, consigne de l'agent |
| `<cas>/configuration-cas.json` | Configuration de l'enregistreur : politique d'approbation du cas, outils, rédaction |
| `<cas>/outils.json`, `<cas>/modele.json` | Catalogue du serveur d'outils, scénario du simulateur |
| `<cas>/attestation-perimetre-cas.json` | Attestation de périmètre du cas (CT-7 §7), non signée |

## Essais

```bash
npx mocha --timeout 600000 test/cas-demonstration.test.js                # sans moteur de conteneurs
npx mocha --timeout 1800000 test/cas-demonstration-composition.test.js   # composition, console réelle dans Chromium
```

Le second est en attente, condition nommée, sans Docker, sans les neuf images,
sans openssl ou sans Chromium ; le binaire Go de CT-6 est lu dans
`NOORTRACE_VERIFIER_BIN`.
