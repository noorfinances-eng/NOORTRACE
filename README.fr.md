# NOORTRACE

La boîte noire des agents IA pour les entreprises régulées suisses et européennes.

Chaque appel d'outil et chaque échange avec le modèle d'un agent IA qui passent
par l'enregistreur sont consignés hors de portée de l'agent. Les actions
sensibles passent par une approbation humaine tracée. L'ensemble est horodaté
par un prestataire de confiance qualifié et restitué en dossier de preuve. Un
réviseur, un régulateur ou un tribunal peuvent le vérifier eux-mêmes, hors
ligne. Ce que la vérification prouve, et ce qu'il faut encore croire, est écrit
dans la spécification du vérificateur (CT-6 §7).

## Pourquoi

- **Les agents effacent leurs traces.** Dans l'étude de Tübingen du 24 septembre 2026,
  presque tous les harness testés laissent l'agent supprimer ses propres journaux,
  certains dans 80 % des essais ([arXiv 2609.30266](https://arxiv.org/pdf/2609.30266)).
- **Les journaux actuels ne valent pas comme preuve.** Ils sont produits et consommés
  par la même partie, modifiables par l'opérateur, conservés 14 à 30 jours par les
  outils d'observabilité. Un journal modifiable est une affirmation, pas une preuve.
- **Les obligations existent déjà.** Pour les entités financières, DORA s'applique
  depuis le 17 janvier 2025, et son règlement délégué 2024/1774 (art. 12) exige de
  protéger les journaux contre la manipulation et la suppression. Dans sa
  communication 08/2024, la FINMA évalue notamment l'analyse des cas où un résultat
  de l'IA a été ignoré ou modifié par les utilisateurs. Depuis le 1er décembre 2025,
  l'art. 4 al. 1 OPDo impose aux responsables privés de journaliser certains
  traitements automatisés (données sensibles à grande échelle, profilage à risque
  élevé) quand les mesures préventives ne suffisent pas, et l'al. 5 de conserver
  ces journaux au moins un an. Le Règlement IA exige que les systèmes à haut risque
  permettent l'enregistrement automatique des événements, à partir du 2 décembre
  2027 (annexe III) et du 2 août 2028 (annexe I). CT-7 §8 dit, texte
  par texte, ce qu'une pièce de NOORTRACE couvre et ce qui reste au client ; ce
  n'est pas un avis juridique.
- **Personne ne vend la preuve vérifiable par un tiers.** L'observabilité débogue, la
  gouvernance documente, la sécurité prévient, les plateformes journalisent dans leurs
  murs.

## Ce que NOORTRACE livre

1. **Un enregistreur déployé chez le client**, entre l'agent et ses outils, qui
   consigne chaque action dans un journal chaîné que l'agent ne peut ni lire ni modifier.
2. **L'approbation humaine des actions sensibles**, bornée, tracée et contestable,
   avec l'identité de l'approbateur et l'instant de la décision : une personne
   nommée, authentifiée par le système d'identité du client, qui signe avec sa
   propre clé dans son propre portefeuille (CT-3).
3. **L'horodatage qualifié par lots**, reconnu ZertES et eIDAS, complété par un
   ancrage public gratuit pour la vérification sans intermédiaire. Des points de
   contrôle signés chaque minute, ancrés au registre et contresignés toutes les
   cinq minutes au plus, ramènent la fenêtre de réécriture à 300 s plus le délai
   du jeton (CT-5).
4. **Un dossier de preuve exportable et un vérificateur ouvert**, que le réviseur
   exécute lui-même, hors ligne, sans accès à nos systèmes ; CT-6 §7 dit ce
   qu'il prouve et ce qu'il faut encore croire. Le dossier peut porter une
   attestation de périmètre signée par le client (agents, canaux de capture,
   exceptions connues), que le vérificateur présente comme déclarée, jamais
   comme prouvée (CT-7 §7).
5. **Des intégrations larges** : passerelle pour Anthropic, OpenAI et Gemini,
   SDK Python et TypeScript pour LangChain, LangGraph, CrewAI, LlamaIndex, le
   SDK Agents d'OpenAI et LiteLLM, ingestion des traces OpenTelemetry, et un gel
   juridique des copies non modifiables levé à deux personnes (CT-2).

## Ce que NOORTRACE n'est pas

- Pas un outil d'observabilité ni de débogage.
- Pas une plateforme de gouvernance documentaire : NOORTRACE lui fournit des preuves.
- Pas une blockchain vendue comme telle : la chaîne est un composant d'exploitation.
- Pas un service de journalisation externalisé : les données restent chez le client,
  seules des empreintes en sortent.

## Ce qui vient de NOORCHAIN

| Composant NOORCHAIN | Rôle dans NOORTRACE |
|---|---|
| Registre d'attestations (contrats PoSS) | Registre des lots d'empreintes et des approbations |
| Jeux d'approbateurs, repris des contrats de curateurs, bornés et contestables | Moteur d'approbation humaine des actions sensibles |
| Hub et console Fondation | Base de la console de revue et d'export des dossiers |
| Discipline de preuves, runbooks, observabilité | Exploitation et audit du service |
| La chaîne EVM permissionnée | Instance dédiée à NOORTRACE, distincte de la chaîne PoSS et sans jeton ; registre d'exploitation substituable |

Terminologie : dans ce dépôt, « approbateur » désigne le rôle que les contrats de
NOORCHAIN nomment curateur. La mécanique est reprise, le mot et la fonction sociale
ne le sont pas. Décision du 20 octobre 2026 : NOORTRACE tourne sur une instance
dédiée de noorcore, pas sur la chaîne du PoSS.

## Documents

- [Architecture cible](ARCHITECTURE.md)
- `archive/polyscan/` : outil d'analyse Polymarket antérieur, sans lien avec le produit

Les documents de projet, étude de marché, plan, offres et notes juridiques, ne sont pas
dans ce dépôt.

## Code

Règle du dépôt : noorchain-core est une référence en lecture seule. On y lit, on en
copie, on ne l'écrit jamais depuis ce projet ; toute adaptation de noorcore vit ici,
sous forme de correctif fourni hors dépôt et déposé dans `chain/patches/` à la
construction.

- `chain/` : instance de développement dédiée de noorcore, quatre validateurs BFT en
  boucle locale, sans émission ni jeton ; voir [chain/README.md](chain/README.md).
- `spec/` : spécifications normatives, schémas JSON et vecteurs de test ; CT-1 pour
  les formats, CT-2 pour l'enregistreur, CT-3 pour les approbations, CT-4 pour le
  registre, CT-5 pour l'ancrage, CT-6 pour le vérificateur, CT-7 pour la sécurité
  et la conformité, CT-8 pour le déploiement et l'exploitation, CT-9 pour le
  plan de tests. Les vecteurs de CT-1 à CT-5 et de CT-7 à CT-9 sont recalculés
  par des vérificateurs Go écrits depuis la seule spécification ; ceux de CT-5 et de CT-6 aussi par
  OpenSSL et la bibliothèque officielle d'OpenTimestamps, ceux de CT-6 par
  go-ethereum, les preuves de cohérence par une implémentation publique de la
  RFC 9162, les échanges Gemini et les traces OpenTelemetry de CT-2 par les
  bibliothèques officielles google-genai et opentelemetry-proto, les signatures
  de CT-3 par ethers et eth-account, les signatures d'attestation et de
  procès-verbal de CT-7 aussi, les paquets réviseurs de CT-8 par GNU tar, le
  module `tarfile` de Python et `sha256sum` ; voir
  [spec/README.md](spec/README.md).
- `contracts/` : AttestationRegistry, CuratorSet et CuratorSetRegistry repris de
  noorchain-core sans modification ; PeriodRegistry, dérivé de PoSSRegistry de
  noorchain-core, RecorderRegistry, et la bibliothèque ThresholdSignatures, dont la
  boucle de signatures reprend celle de PoSSRegistry, écrits pour NOORTRACE.
- `test/` et `scripts/` : tests Hardhat, déploiement, amorçage d'une organisation,
  parcours complet sur le réseau de développement. `npm install`, puis `npm test`.
- `scripts/lib/` : implémentation de référence de CT-1, de la partie calculable de
  CT-2 (dont, depuis sa révision 0.5, Gemini à la passerelle, l'ingestion
  OpenTelemetry, le gel juridique des copies WORM et le coût par agent), de CT-3
  (dont, depuis sa révision 0.3, la bibliothèque de la console), des conventions
  de CT-4, du planificateur d'ancrage de CT-5, des contrôles 4, 5 et 8 de CT-6,
  avec les vérifications K- des points de contrôle et AT- de l'attestation de
  périmètre, de CT-7 (attestation, procès-verbal de cérémonie des clés) et de
  CT-8 (contrôle préalable, dimensionnement, vérifications des fichiers de
  conteneur, marque d'observation, paquet réviseur, journal d'exploitation).
- `scripts/conformite/` : vérificateur des renvois de CT-7 (chaque exigence citée
  par le modèle de menace et la matrice de conformité existe).
- `deploiement/` : fichiers de déploiement de référence de CT-8 : fichiers
  Compose de l'installation rapide et de la production, description des
  images, configurations, préparation de l'hôte, gabarits des tâches
  planifiées, copies des runbooks, règles d'alerte de référence ; voir
  [deploiement/LISEZMOI.md](deploiement/LISEZMOI.md). Les images sont
  construites depuis `conteneurs/` (étape 7), sans être publiées.
- `scripts/deploiement/` : outils de CT-8 : contrôle préalable d'un hôte,
  calculateur de dimensionnement, vérification statique des fichiers Compose,
  configuration rapide, archive de déploiement, vérification d'un répertoire
  de journal, rapport d'observation, procès-verbaux d'exploitation, journal des
  consultations, vérificateur des renvois vers CT-8 ; depuis l'étape 7,
  sauvegarde et reprise, archivage du journal d'exploitation, règles d'alerte,
  extracteur des journaux, sonde, construction des images et banc
  d'installation complète.
- `scripts/paquet-reviseur/` : construction d'un paquet réviseur déterministe
  et sa vérification hors ligne en une commande, avec les instructions
  remises au réviseur ; voir
  [scripts/paquet-reviseur/instructions/LISEZMOI.md](scripts/paquet-reviseur/instructions/LISEZMOI.md).
- `scripts/tests/` : outil de couverture de CT-9 (chaque exigence et chaque
  vérification de CT-1 à CT-8 couverte par un test ou par une justification
  nommée, chaque menace de CT-7 par un test adversarial, chaque renvoi à CT-9
  par sa ligne) et contrôle des rapports de mesure.
- `verificateur/` : binaire vérificateur hors ligne `noortrace-verifier`, en
  Go (étape 2 de la construction, CT-6 §14) : les huit contrôles, écrit
  depuis le seul texte de CT-6, construction reproductible, aucun code réseau ;
  voir [verificateur/LISEZMOI.md](verificateur/LISEZMOI.md).
- `paquets/noyau/` : bibliothèque noyau de production (`@noortrace/noyau`,
  étape 1 de la construction) : forme canonique, hachage, signatures, chaînage,
  Merkle, manifestes, points de contrôle et contrôles du dossier de CT-1, écrite
  depuis le seul texte de CT-1 et éprouvée sur tous ses vecteurs ; voir
  [paquets/noyau/LISEZMOI.md](paquets/noyau/LISEZMOI.md).
- `scripts/conception/` : contrôle du figeage de la conception v1.0 (chaque
  modification de `spec/` consignée dans `spec/figeage/modifications.json`).
- `paquets/enregistreur/`, `paquets/ancrage/` : démon enregistreur (étape 4),
  avec l'export du dossier sur demande (`noortrace-ctl dossier exporter`,
  étape 6) et, à l'étape 7, ses commandes de santé et de clôture anticipée et la
  clé de chaîne de classe B ou C, et composant d'ancrage (étape 5).
- `conteneurs/` : fichiers de construction des images `noortrace/*` (CT-8 §3.3,
  §3.6, étape 7), sans interpréteur de commandes, construites deux fois aux
  mêmes condensés et non publiées ; pont stdio et son serveur de fichiers
  minimal.
- `scripts/publication/` : préparation d'une version sans rien publier (CT-6
  §14.4) ; voir [scripts/publication/LISEZMOI.md](scripts/publication/LISEZMOI.md).
- `paquets/approbation/`, `paquets/console/` : service d'approbation et console
  d'exploitation de CT-3 §13 (étape 6) : bibliothèque commune, serveur de
  console (OIDC, sessions, relais authentifié vers le service) et pages
  chargées avec leur intégrité, où l'approbateur inscrit son adresse et signe
  dans son portefeuille ; voir [paquets/console/LISEZMOI.md](paquets/console/LISEZMOI.md).
- `paquets/inscription/` : inscription des clients par l'exploitant (CT-4
  §7.14, étape 6) : interface web qui ne tient aucune clé, agent séparé qui les
  tient, paquet client remis et contrôlé à la réception.
- `paquets/verification-web/` : page de vérification (CT-6 §18, étape 6) : le
  vérificateur Go compilé en WebAssembly s'exécute dans le navigateur et rend
  le rapport du binaire, octet pour octet.
- `console/` : console d'approbation de référence de CT-3, page statique sous
  une politique de sécurité du contenu stricte, testée de bout en bout dans
  Chromium ; voir [console/LISEZMOI.md](console/LISEZMOI.md).
- `scripts/registre/` : outil de référence de CT-4 (`npm run registre`) :
  inscription d'un client, ancrage, clôture de période et capture des preuves sur
  le réseau de développement.
- `scripts/verify/` : vérificateur hors ligne des dossiers de preuve, avec les huit
  contrôles de CT-6 et les ancres de confiance du réviseur, et vérificateur hors
  ligne des certificats de commit BFT, en parité octet par octet avec noorcore ;
  voir [scripts/verify/README.md](scripts/verify/README.md).
- `chain/docker/` : image conteneur du nœud, validateur ou relais RPC, avec l'étude
  mesurée du mode suiveur ; voir [chain/docker/README.md](chain/docker/README.md).

## Statut

2 novembre 2026 : les neuf spécifications de conception sont écrites et
figées en conception v1.0 (porte 1) ; toute modification ultérieure de
`spec/` est consignée dans un registre que l'intégration continue vérifie
(`spec/figeage/`). La construction commence. Les spécifications : CT-1 des
formats, CT-2 de l'enregistreur, CT-3 des approbations, CT-4 du registre, CT-5
de l'ancrage, CT-6 du vérificateur, CT-7 de la sécurité et de la conformité,
CT-8 du déploiement et de l'exploitation et CT-9 du plan de tests, avec leurs
vecteurs, leur implémentation de référence et leur confrontation
indépendante. Existent aussi : le vérificateur de
dossier, avec les huit contrôles ; l'outil du paquet réviseur ; l'outil de
couverture du plan de tests ; l'instance de développement, les contrats du
registre avec leurs tests, le parcours complet exécuté sur le réseau de
développement ; la méthode RPC du certificat de commit, portée comme correctif
sur noorcore fourni hors dépôt, et son vérificateur hors ligne ; la console
d'approbation de référence ; le binaire Go du vérificateur (étape 2),
l'enregistreur (étape 4) et le composant d'ancrage avec ses clients réseau
(étape 5). L'étape 6 livre le service d'approbation, la console d'exploitation
(un approbateur inscrit son adresse par preuve de possession et signe une
décision dans son propre portefeuille), l'inscription des organisations par
l'exploitant, l'export des dossiers par l'enregistreur et la page de
vérification ; son critère est démontré : une décision signée depuis la
console, le dossier exporté accepté par les deux vérificateurs. L'étape 7 livre
les six images `noortrace/*` (sans interpréteur, deux constructions aux mêmes
condensés, non publiées), les commandes `noortrace-ctl sonde`, `etat` et
`close-period --now`, la clé de chaîne de classe B ou C tenue par un service de
gestion de clés et sa rotation d'urgence relayée au registre, les règles
d'alerte de référence avec leur extracteur, leur générateur et leur sonde, la
préparation de l'hôte, les tâches planifiées, la sauvegarde et la reprise, les
copies des runbooks et une version préparée sans rien publier. Son critère a
été joué sur un banc sans réseau public : l'installation complète IC-1 à IC-18
de CT-8, déroulée par un harnais en 58 min (dont 57 d'attente de la clôture de
l'heure), le premier dossier accepté par les deux vérificateurs ; ce banc n'est
pas le système de référence, et l'installation sur une machine vierge par un
ingénieur extérieur est rattachée à l'étape 8. Reste la campagne de bout en
bout, adversariale et de performance (étape 8).

## Licence

Apache License 2.0, voir `LICENSE` et `NOTICE`. Les contrats Solidity portent un
en-tête MIT, ceux repris de noorchain-core comme ceux écrits ici ; la MIT est
compatible avec Apache-2.0. La version anglaise de cette page est `README.md`.
