# NOORTRACE

La boîte noire des agents IA pour les entreprises régulées suisses et européennes.

Chaque action d'un agent IA est enregistrée hors de portée de l'agent, les actions
sensibles passent par une approbation humaine tracée, l'ensemble est horodaté par un
prestataire de confiance qualifié et restitué en dossier de preuve qu'un réviseur,
un régulateur ou un tribunal peuvent vérifier sans faire confiance au fournisseur.

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
  murs. Détail dans [l'étude de marché](docs/etude-de-marche-2026-10-20.md).

## Ce que NOORTRACE livre

1. **Un enregistreur déployé chez le client**, entre l'agent et ses outils, qui
   consigne chaque action dans un journal chaîné que l'agent ne peut ni lire ni modifier.
2. **L'approbation humaine des actions sensibles**, bornée, tracée et contestable,
   avec l'identité de l'approbateur et l'instant de la décision.
3. **L'horodatage qualifié par lots**, reconnu ZertES et eIDAS, complété par un
   ancrage public gratuit pour la vérification sans intermédiaire.
4. **Un dossier de preuve exportable et un vérificateur ouvert**, que le réviseur
   exécute lui-même, sans accès à nos systèmes et sans nous faire confiance.

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

## Marché et modèle, en bref

| Question | Réponse |
|---|---|





Ces chiffres sont des estimations issues de l'étude de marché du 20 octobre 2026 ;
les sources et les réserves y figurent.

## Feuille de route

Le [plan du projet](docs/plan.md) enchaîne quatre phases en série : conception
technique complète, construction, validation externe, pilote et industrialisation.
Chaque phase se termine par une porte avec des critères pour continuer ou arrêter.
Aucun entretien de vente avant un prototype complet, aucun pilote avant qu'un
réviseur externe ait reproduit la vérification.

## Documents

- [Étude de marché](docs/etude-de-marche-2026-10-20.md) et [notes de recherche](docs/recherche/)
- [Architecture cible](ARCHITECTURE.md)
- [Plan du projet](docs/plan.md)
- [Présentation « NOORTRACE sur NOORCHAIN »](docs/presentation/README.md)
- [Offre pilote](docs/offre-pilote.md)
- [Note juridique](docs/note-juridique.md), à faire valider par un juriste
- `archive/polyscan/` : outil d'analyse Polymarket antérieur, sans lien avec le produit

## Statut

21 octobre 2026 : phase 1 du plan, conception technique complète, en cours. Aucun
code produit n'existe encore ; l'architecture cible est au niveau 0.2 et les
spécifications CT-1 à CT-9 sont à écrire.

## Licence

À définir. En attendant, tous droits réservés.
