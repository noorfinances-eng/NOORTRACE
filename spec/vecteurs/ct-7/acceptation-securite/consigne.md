# Épreuve à l'aveugle du responsable de la sécurité (CT-7, EX-9.1)

Vous recevez la spécification CT-7 (`spec/CT-7-securite-et-conformite.md`,
version 0.1) sans sa section 9 ni son annexe A.15, et rien d'autre. Répondez
seul et par écrit. Pour chacun des six scénarios d'attaque ci-dessous,
donnez :

1. la menace de CT-7 qui le décrit (identifiant MN-) ;
2. la réponse : au moins une exigence (EX-) citée par cette menace ;
3. la détection : le contrôle du dossier ou la supervision qui la révèle ;
4. le risque résiduel : l'identifiant du risque accepté (RA-), ou « aucun ».

Un relecteur qui ne vous a pas aidé compare ensuite vos réponses à une grille
qui n'est pas dans ce répertoire.

## Scénarios

S1. La graine de la clé de l'enregistreur, gardée en classe C, a pu être lue sur
    l'hôte.
S2. Un agent joint directement un serveur d'outils HTTP sans passer par le
    mandataire.
S3. La console fait signer à un approbateur le condensé d'une autre demande
    retenue.
S4. La clé de gouvernance d'une organisation est volée.
S5. Le service d'approbation rend `autorise` pour un appel que la politique
    soumet à approbation.
S6. Un gel juridique est levé par une seule personne.
