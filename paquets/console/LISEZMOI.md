# @noortrace/console — console d'approbation d'exploitation (CT-3 §13)

La console où les approbateurs d'une organisation lisent les demandes
retenues et signent leurs décisions dans leur propre portefeuille, telle que
la fixe CT-3 §13 (révision 0.5). Le paquet réunit trois parties :

- la **bibliothèque** (`src/bibliotheque/`), qui s'exécute à l'identique sous
  Node 22 et dans Chromium : modèle d'affichage, condensés et empreintes,
  vérification des signatures, découverte des portefeuilles, et le module
  d'annuaire que le service d'approbation importe (une seule implémentation
  des règles de l'annuaire) ;
- le **serveur de console** (`src/serveur/`, `bin/noortrace-console`), sans
  cadriciel : OIDC (système local hors production seulement), sessions en
  mémoire, relais authentifié vers le service d'approbation, politique de
  sécurité du contenu bloquante, santé et sonde ;
- les **pages** (`src/pages/`), statiques, chargées avec leur intégrité, sans
  script en ligne autre que la carte d'importation.

Parcours de signature offerts : a (portefeuille de navigateur) et, par lui,
b (portefeuille matériel). Interface en français.

**État : en construction, étape 6.** Le contrat est dans `INTERFACES.md`.

Fichiers repris de noorchain-core : aucun à ce jour.
