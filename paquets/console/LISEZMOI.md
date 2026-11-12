# @noortrace/console — console d'approbation d'exploitation (CT-3 §13)

La console où les approbateurs d'une organisation lisent les demandes
retenues et signent leurs décisions dans leur propre portefeuille, telle que
la fixe CT-3 §13 (révision 0.6). Le paquet réunit trois parties :

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
b (portefeuille matériel) ; ni c (WalletConnect), ni d (fichier de clé).
Interface en français.

**État : livré (étape 6).** Le contrat est dans `INTERFACES.md`, qui porte
les décisions de l'assemblage de l'étape 6 et de la révision 0.6 de CT-3.

## Lectures des trois parties

Quand le texte laissait un choix, chaque partie l'écrit dans son propre
`LISEZMOI.md`, avec l'essai qui l'éprouve :

- `src/bibliotheque/LISEZMOI.md` : modules, exports en plus de ceux du
  contrat, lectures (erreurs `TypeError` des valeurs que le contrat ne nomme
  pas, annuaire, signatures, découverte EIP-6963, modèle d'affichage), aucun
  écart aux vecteurs (hors `fichiers-cle/`, en
  attente : parcours d non offert) ; fermeture `@noble/*` de quinze fichiers ;
- `src/serveur/LISEZMOI.md` : modules et lectures du texte (chemins selon le
  système d'identité, page d'erreur, exception de l'inscription sous
  `reauth_max_age_s` = 0, `identity_ready`, refus au démarrage d'EX-10.14,
  magasin d'autorités du système chargé explicitement) ; ce magasin suit les
  emplacements d'OpenSSL (`SSL_CERT_FILE`, `SSL_CERT_DIR`), jamais
  `NODE_EXTRA_CA_CERTS`, qui ne vaut que pour le magasin « extra » de Node,
  que le serveur ne lit pas : une autorité interne du fournisseur ou du
  service s'installe dans le magasin du système (contrat 2.8, CT-3 EX-13.42) ;
- `src/pages/LISEZMOI.md` : fichiers, générateur et manifeste, lectures des
  écrans (pas 1 et boutons, empreintes, renvoi de `voter`,
  `reponse_service_invalide`, inscription bornée par `Expire le` et
  réauthentification avant `preparer_inscription`, révocation de sa propre
  adresse, langue).

## Dépendances

À version exacte (`package.json`, contrat 0.2) : `@noble/hashes` 2.4.0 et
`@noble/curves` 2.4.0 (bibliothèque, licence MIT), `@noortrace/approbation`
0.1.0 (espace de travail, serveur seulement). Aucune autre : le serveur
n'emploie que `node:*`. Les essais emploient en plus Playwright 1.56.1
(installé hors de `package.json`) et le fournisseur OIDC d'essai, qui
importe `jose` 6.2.15 (dépendance de développement de la racine du dépôt, à
version exacte, licence MIT ; jamais distribuée, d'où aucune mention dans
`NOTICE`).

## Fichiers repris de noorchain-core

Aucun. Les patrons de curators-hub que CT-3 13.1 dit repris (jeton de
session signé, garde d'hôte, thème, libellés) ont été écrits d'après le
texte de CT-3, sans recopie de code, de commentaire ni de donnée ; les
`LISEZMOI.md` des trois parties le constatent.
