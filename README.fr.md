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
- **Les obligations existent déjà.** DORA exige des logs protégés contre l'altération
  depuis le 17 janvier 2025 (RTS 2024/1774, art. 12). La FINMA évalue la traçabilité
  et l'analyse des corrections humaines depuis la Communication 08/2024. L'art. 4 OPDo
  révisé impose la journalisation des accès machine et un examen écrit d'ici le
  31 décembre 2026. Le Règlement IA rend la journalisation automatique obligatoire le
  2 décembre 2027 pour les systèmes de l'annexe III.
- **Personne ne vend la preuve vérifiable par un tiers.** L'observabilité débogue, la
  gouvernance documente, la sécurité prévient, les plateformes journalisent dans leurs
  murs.

## Ce que NOORTRACE livre

1. **Un enregistreur déployé chez le client**, entre l'agent et ses outils, qui
   consigne chaque action dans un journal chaîné que l'agent ne peut ni lire ni modifier.
2. **L'approbation humaine des actions sensibles**, bornée, tracée et contestable,
   avec l'identité de l'approbateur et l'instant de la décision.
3. **L'horodatage qualifié par lots**, reconnu ZertES et eIDAS, complété par un
   ancrage public gratuit pour la vérification sans intermédiaire. Des points de
   contrôle signés chaque minute, ancrés au registre et contresignés toutes les
   cinq minutes au plus, ramènent la fenêtre de réécriture à 300 s plus le délai
   du jeton (CT-5).
4. **Un dossier de preuve exportable et un vérificateur ouvert**, que le réviseur
   exécute lui-même, hors ligne, sans accès à nos systèmes ; CT-6 §7 dit ce
   qu'il prouve et ce qu'il faut encore croire.
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
  registre, CT-5 pour l'ancrage, CT-6 pour le vérificateur. Les vecteurs de CT-1
  à CT-5 sont recalculés par des vérificateurs Go écrits depuis la seule
  spécification ; ceux de CT-5 et de CT-6 aussi par OpenSSL et la bibliothèque
  officielle d'OpenTimestamps, ceux de CT-6 par go-ethereum, les preuves de
  cohérence par une implémentation publique de la RFC 9162, les échanges
  Gemini et les traces OpenTelemetry de CT-2 par les bibliothèques officielles
  google-genai et opentelemetry-proto ; voir
  [spec/README.md](spec/README.md).
- `contracts/` : AttestationRegistry, CuratorSet et CuratorSetRegistry repris de
  noorchain-core sans modification ; PeriodRegistry, dérivé de PoSSRegistry de
  noorchain-core, RecorderRegistry, et la bibliothèque ThresholdSignatures, dont la
  boucle de signatures reprend celle de PoSSRegistry, écrits pour NOORTRACE.
- `test/` et `scripts/` : tests Hardhat, déploiement, amorçage d'une organisation,
  parcours complet sur le réseau de développement. `npm install`, puis `npm test`.
- `scripts/lib/` : implémentation de référence de CT-1, de la partie calculable de
  CT-2 (dont, depuis sa révision 0.5, Gemini à la passerelle, l'ingestion
  OpenTelemetry, le gel juridique des copies WORM et le coût par agent), de CT-3, des conventions de CT-4, du planificateur d'ancrage de CT-5 et
  des contrôles 4, 5 et 8 de CT-6, avec les vérifications K- des points de
  contrôle.
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

26 octobre 2026 : conception technique en cours. Écrits : les spécifications CT-1
des formats, CT-2 de l'enregistreur, CT-3 des approbations, CT-4 du registre, CT-5
de l'ancrage et CT-6 du vérificateur, avec leurs vecteurs, leur implémentation de
référence et leur confrontation indépendante ; le vérificateur de dossier, avec les huit contrôles ;
l'instance de développement, les contrats du registre avec leurs tests, le
parcours complet exécuté sur le réseau de développement ; la méthode RPC du
certificat de commit, portée comme correctif sur noorcore fourni hors dépôt, et
son vérificateur hors ligne. À construire : l'enregistreur lui-même, le service
d'approbation, le composant d'ancrage et ses clients réseau, le binaire Go du
vérificateur et la console
(approbations, inscription des organisations, export des dossiers, page de
vérification).

## Licence

Apache License 2.0, voir `LICENSE` et `NOTICE`. Les contrats Solidity portent un
en-tête MIT, ceux repris de noorchain-core comme ceux écrits ici ; la MIT est
compatible avec Apache-2.0. La version anglaise de cette page est `README.md`.
