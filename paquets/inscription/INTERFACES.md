# Interfaces de l'inscription des clients (CT-4 §7.13 et §7.14, révision 0.7)

Ce document est le contrat de l'étape 6 pour le paquet
`@noortrace/inscription` : l'application d'exploitant de CT-4 §7.14, faite
d'une interface web (section 2) et d'un agent séparé et privilégié
(section 3), qui conduisent les pas de CT-4 §7.1 et produisent le paquet
client de CT-4 §7.13 (section 4). Avec CT-4 (sections 3 à 9, dont 7, 8.5,
8.6, 9.4, 9.6), CT-3 EX-8.1, les schémas `inscription-client-v0`,
`operations-registre-v0`, `instance-registre-v0`, `paquet-client-v0` et
`configuration-approbation-v0`, il suffit.

**État (étape 6) : fait.** Chaque section ci-dessous est mise en œuvre ; les
précisions apportées par la construction, qui ne changent pas le contrat,
sont réunies en section 6, et les questions ouvertes dans le rapport de
l'étape. L'assemblage de l'étape 6 (CT-4 révision 0.7) a ajouté : la sortie
`paquet-client` du travail « paquet » et les codes d'EX-7.30 (3.3, 4) ; le
travail `administrer-jeu` et sa préparation (0.1, 3.3) ; la reprise d'une
étape `echec` déjà accomplie (EX-7.29, 3.4) et `funding` nul ; la liste
close des types de champ d'EX-7.25 (2.1) ; une confirmation par
approvisionnement ou par demande d'administration, consommée (3.5) ; une
lecture bornée en flux des réponses JSON-RPC et un délai sur chaque
connexion à la prise, avec au plus quatre auxiliaires `python3` à la fois
(3.2, 6.1).

L'outil de référence `scripts/registre/noortrace-registre.mjs` n'est ni lu ni
importé : il sert de juge, en boîte noire (EX-7.24, épreuve). Aucun fichier
n'est recopié de noorchain-core à ce jour ; les patrons repris de la console
de la Fondation (comptes, file de travaux de l'agent, périmètre public) le
sont sans code, et toute recopie future est inscrite dans `LISEZMOI.md`.

## 0. Règles communes

### 0.1 Périmètre de l'étape 6

- Réseau de développement (identifiant EVM 2124) et réseau Hardhat en
  mémoire (31337) : pas 1 à 6 et 10 de CT-4 §7.1, et le paquet client. Les pas
  7 à 9 (première période) sont ceux de l'enregistreur de CT-2 ; l'application
  ne les conduit pas, et la commande `manifeste-essai` n'est pas offerte.
- Production : seul le pas 1 (dossier préparé) ; EX-7.3 refuse en production
  les références `fichier:` et `env:` pour l'administrateur du registre et la
  trésorerie, et l'application refuse ce que l'outil refuse (EX-7.24).
- Des commandes de CT-4 §8, `administrer-jeu` est offerte (EX-7.26, TE-22 ;
  décision de l'assemblage de l'étape 6), avec la préparation de sa demande
  (`condense administration_jeu`) et la confirmation hors bande d'EX-7.26 ;
  `reassigner`, `revoquer-cle` et `publier-jeu` ne sont pas offertes à
  l'étape 6. L'approvisionnement du pas 5 et la commande `approvisionner` le
  sont, avec la confirmation hors bande d'EX-7.26. Le code `cle_revoquee`
  est hors d'atteinte des travaux offerts.
- Pas 6 : l'application prépare la demande d'inscription (`condense
  inscription`), la remet aux approbateurs **hors d'elle**, et relaie la
  demande signée qu'on lui rend (`inscrire-cle`) après OP-6 et OP-7 ; aucune
  page ne fait signer un condensé de CT-4 §6.6 (EX-7.27). Dans les essais,
  la demande est signée par les clés d'essai dérivées du mnémonique public, hors
  de l'application.

### 0.2 Arborescence

```text
paquets/inscription/
  package.json            @noortrace/inscription
  LISEZMOI.md, INTERFACES.md
  bin/
    noortrace-inscription-agent   l'agent (section 3)
    noortrace-inscription-web     l'interface : sert le résultat de « next build » (section 2)
  schemas/                copies à l'identique de spec/schemas (0.4)
  src/
    commun/               modules purs partagés par l'interface et l'agent : formes des travaux,
                          types de champs, références de clés, contrôle du paquet (4.3)
    agent/                agent (Node seulement)
    web/                  projet Next.js (répertoire racine de « next build ») : app/, composants/, lib/, proxy.mjs, next.config.mjs
```

### 0.3 Dépendances

| Dépendance | Version exacte | Emploi |
|---|---|---|
| `next` | 16.4.6 | interface web |
| `react`, `react-dom` | 19.3.1 | interface web |
| `@noortrace/ancrage` | 0.1.0 (espace de travail) | registre : transactions, envois, captures, export (0.5) |
| `@noortrace/approbation` | 0.1.0 (espace de travail) | `LecteurJeu` (pas 4), `RegistreSchemas`, `lireJsonStrict` |
| `@noortrace/noyau` | 0.1.0 (espace de travail) | `keccak256` (identifiants de CT-4 §6.2), forme canonique |

Les trois liens d'espace de travail sont déjà déclarés ; `next`, `react` et
`react-dom` sont ajoutés par l'étape 6 avec le verrou, à version exacte.
Aucune autre dépendance : ni TypeScript, ni feuille de style compilée, ni
base de données, ni client de messagerie. `next.config.mjs` désactive
l'optimisation des images (`images: { unoptimized: true }`) : la route
d'optimisation des images n'est pas servie.

**Version retenue et preuve (2026-11-11).** `npm view next versions --json`
donne pour 16.x, en dernier, `16.4.6` (étiquette `latest`, publiée le
2026-11-09) ; `npm view react dist-tags` donne `latest` `19.3.1`. Sur un
projet jetable, `npm install --save-exact next@<v> react@19.3.1
react-dom@19.3.1` puis `npm audit --json` (npm 10.9.4, Node 22.22.0) :

| `next` | Vulnérabilités connues |
|---|---|
| 16.4.6 | aucune (`total` 0) |
| 16.4.5 | aucune (`total` 0) |
| 16.3.8 | 3 : GHSA-2464-fhr4-w9xw (critique, exécution de code par l'optimisation d'images SVG), GHSA-673q-mjm6-r5xr (critique, exécution de code par `use cache`), GHSA-p3m5-59mp-jv5r (élevée, déni de service par les Server Actions), toutes sur `>=16.0.0 <=16.4.0` |

Aucune version 16.x antérieure à 16.4.1 n'est donc admise. Licences de l'arbre de 16.4.6 : MIT, Apache-2.0, ISC, BSD-3-Clause,
0BSD, CC-BY-4.0 (`caniuse-lite`, données) ; les binaires facultatifs
`@img/sharp-*` sont en LGPL-3.0-or-later et n'entrent dans aucune image
(installation sans dépendances facultatives, étape 7).

### 0.4 Schémas

Copies à l'identique, sous `schemas/`, comparées octet pour octet à
`spec/schemas` par un essai : `inscription-client-v0`,
`operations-registre-v0`, `instance-registre-v0`, `paquet-client-v0`,
`configuration-approbation-v0`, `annuaire-approbateurs-v0`, `evenement-v0`,
`ticket-v0`, `politique-approbation-v0`, chargées dans un `RegistreSchemas`
de `@noortrace/approbation`. Les schémas de `@noortrace/ancrage/registre`
(`REGISTRE_SCHEMAS`, `verifierIndexCapture`, `verifierEnvoi`,
`verifierIssue`, `verifierDemandeSchema`) servent pour les captures, envois,
issues et demandes.

### 0.5 Ce que l'agent importe

De `@noortrace/ancrage/registre` (exports réels) :

| Besoin | Exports |
|---|---|
| Transactions (RG-15) | `construireTransaction`, `signerTransaction`, `serialiserTransaction`, `lireTransaction`, `verifierRG15`, `adresseCreation`, `chargeASignerDe`, `fraisRemplacement`, `LIMITE_GAZ_MAX`, `FRAIS_NOMINAUX` |
| Clés de chaîne (classe D, développement) | `SignataireChaineFichier`, `SignataireChaine`, `adresseDepuisClePublique`, `recouvrerSignataire` |
| JSON-RPC vers les validateurs | `ClientRpc`, `ErreurRpc`, `clientSurPoint` |
| Lectures du registre (OP-8, OP-12) | `appelLecture`, `recorderOf`, `recorderByPubKey`, `isActiveRecorder`, `inscriptionAilleurs` (complément du 2026-11-16 : clé de chaîne inscrite sous une autre organisation, `cle_chaine_autre_organisation`, CT-4 EX-8.22), `ErreurLecture`, `SELECTEURS`, `SIGNATURES_FONCTIONS`, `SIGNATURES_EVENEMENTS`, `SUJETS`, `EVENEMENT_PAR_ROLE` |
| Condensés et demandes (pas 6) | `registerDigest`, `hachageSigne`, `verifierSignatureCondense`, `verifierJeuSignatures`, `encoderRegisterRecorder`, `condenseDemande`, `verifierDemande`, `verifierSlug`, `verifierNomJournal` |
| Envois, issues, captures (8.6, §9) | `nomEnvoi`, `nomIssue`, `lireEnvois`, `envoisSansIssue`, `ecrireExclusif`, `synchroniserRepertoire`, `capturer`, `verifierCapture`, `listerCaptures`, `obtenirCertificat`, `ROLES_CAPTURE` |
| Export et contrôle 8 (pas 10) | `exporterPartiesRegistre`, `entreeRegistre`, `choisirCaptures`, `lireCapture` |
| Manifeste d'instance | `verifierManifeste`, `verifierManifesteRepertoire`, `contratsEnService`, `ancreReviseur`, `lireJeux`, `jeuPourHauteur`, `hachageJeuHex` |
| Schémas | `REGISTRE_SCHEMAS`, `verifierIndexCapture`, `verifierEnvoi`, `verifierIssue`, `verifierDemandeSchema`, `verifierRegistreV0`, `verifierCertificatCommitV0`, `verifierValidateursV0`, `verifierManifesteSchema` |

De `@noortrace/approbation` : `LecteurJeu` (pas 4 : `new LecteurJeu({ url,
timeout_ms, org_id, depuis_bloc })` puis `lire({ chain_id, registry, set })`,
qui rend `{ status, jeu, cause }`, CT-3 EX-8.1), `RegistreSchemas`,
`lireJsonStrict`. De `@noortrace/noyau` : `keccak256`, `jcs`.

Absents de ces paquets, écrits par l'agent dans `src/agent/` et nulle part
ailleurs : le code de création de `CuratorSet(set_admin, members, threshold)`
(code d'octets lu dans `hh-artifacts/contracts/CuratorSet.sol/CuratorSet.json`,
produit par `npm run compile`, et arguments encodés), l'appel
`setCuratorSet(bytes32,address)`, les lectures `admin()`,
`isRegistered(bytes32)` et `curatorSetOf(bytes32)` du registre des jeux, et
le virement de valeur (RG-15). Chaque sélecteur est recalculé (Keccak-256 de
la signature) et comparé, par un essai, à l'ABI des artefacts. Le paquet
`@noortrace/ancrage` n'est pas modifié.

## 1. Comptes de l'exploitant

- Fichier des comptes, par référence (`fichier:`) dans la configuration de
  l'interface, de la forme `$defs/fichier_comptes` de
  `configuration-console-v0` : `{ "version": 0, "accounts": [ { "name",
  "salt", "key" } ] }`, `key` = scrypt(mot de passe en UTF-8, `salt`,
  N = 131 072, r = 8, p = 1, 32 octets), noms deux à deux distincts. Aucune
  adresse électronique, aucune réinitialisation par courriel : un compte se
  crée ou se change en réécrivant le fichier, hors de l'application.
- Identité d'un exploitant : `exploitant <name>` ; c'est celle que porte
  chaque travail (EX-7.23).
- Session : identifiant de 32 octets tiré au hasard, en mémoire, cookie
  `__Host-noortrace-inscription` (`Secure; HttpOnly; SameSite=Strict;
  Path=/`, MAC HMAC-SHA256 sous une clé tirée au démarrage) ; durée 8 h ;
  verrou progressif sur les échecs, comme EX-13.47 de CT-3 (seuil de cinq
  échecs, `min(2^(f − 5), 900)` s), par couple (adresse cliente, nom)
  (revue de l'étape 8, CT-7 CLE-37) ; au plus 10 000 sessions, les sessions
  échues purgées à chaque ouverture.
- Le fichier des comptes est un fichier ordinaire du compte du serveur de
  l'interface, lisible de son seul propriétaire (`0400` ou `0600`) ; le
  serveur refuse de démarrer sinon (revue de l'étape 8, CT-7 CLE-37).
- L'interface n'a qu'un rôle : un exploitant authentifié peut tout ce
  qu'elle offre. Chaque travail et chaque confirmation consignent son
  identité.

## 2. Interface web (`src/web/`, Next.js 16.4.6)

### 2.1 Ce qu'elle ne fait jamais (EX-7.23, EX-7.25, EX-7.27, EX-7.28)

- tenir une clé, une graine, une mnémonique, un jeton, un mot de passe de clé
  ou une référence **résolue** ; aucun champ de page ni de route n'en reçoit
  la valeur ; un champ de référence de clé n'admet que `fichier:<chemin>`,
  `graine:<chemin>`, `hardhat:<i>` (EX-7.3) et `alias:<nom>` (alias de la
  configuration de l'agent ; `env:` est réservée à cette configuration,
  CT-4 EX-7.25), et refuse
  sans la garder ni la consigner une valeur nue (64 chiffres hexadécimaux
  avec ou sans `0x`, une mnémonique, tout texte hors de ces formes) ; l'agent
  n'ouvre un fichier désigné par un travail que sous son répertoire de clés
  (`cles.repertoire`, 3.1) et rend, pour toute référence qui ne se résout pas,
  un seul message, sans détail sur les fichiers de l'hôte ;
- exposer au navigateur le chemin de la prise de l'agent ou une réponse de
  l'agent autre que la sortie d'un travail ;
- demander à un portefeuille de signer quoi que ce soit ;
- servir une ressource d'une autre origine, ou une route publique autre que
  `/connexion` et `POST /api/connexion`.

Chaque champ a un type déclaré de la liste close d'EX-7.25 (révision 0.7),
`TYPES_DECLARES` de `src/commun/champs.mjs` : adresse, hachage, clé
publique Ed25519, slug, nom de journal, seuil, montant, référence de clé,
texte, entier, origine HTTPS et identité de session (formes
d'`annuaire-approbateurs-v0`), document JSON contrôlé contre son schéma
(demande signée, documents `cle_enregistreur`), chemin relatif sous le
répertoire du client sans composant `.` ni `..`, et la liste de valeurs d'un
de ces types (`liste_adresses`, `liste_noms_journal`, `liste_identites`,
`liste_documents`) ; aucun autre. Une liste de choix porte le type de ses
valeurs (`adresse` pour une clé de chaîne du dossier, `chemin` pour une
période, `texte` pour un identifiant de clé ou une opération du jeu). Le
champ des documents `cle_enregistreur` (`liste_documents`) a une zone par
document ; toutes les zones portent son nom et son type : ce sont les
valeurs d'une même liste (2.5). La valeur est contrôlée côté serveur par
`src/commun/champs.mjs` et `src/commun/travaux.mjs` (et répétée dans la page
pour l'affichage seulement).

### 2.2 Pages

| Chemin | Contenu |
|---|---|
| `/connexion` | nom et mot de passe |
| `/clients` | clients connus : slug, `org_id`, état de chaque étape (EX-7.16), dernier travail |
| `/clients/nouveau` | pas 1 : les options de `inscrire-client --preparer` (CT-4 7.5) ; en développement, choix des clés d'essai ou des références |
| `/clients/<slug>` | dossier : étapes et leurs états, sorties des travaux, actions offertes selon l'état (pas 2 à 5 ; `approvisionner` ; `condense inscription` ; relais d'une demande signée ; `capturer` ; `exporter` ; `verifier` ; préparation et relais d'une demande d'administration du jeu) |
| `/clients/<slug>/confirmations` | registre des confirmations hors bande (EX-7.26), chacune avec le travail qui l'a consommée, et formulaire d'ajout |
| `/clients/<slug>/paquet` | production du paquet client (sortie `paquet-client`), son contrôle, et le gabarit (`console_origin` et `administrators` donnés par écrit par le client, ou `null`) |

Le contenu de chaque page est celui de cette table ; sa présentation est
celle de 2.4.

### 2.3 Routes

Routes de Next (`src/web/app/api/…/route.mjs`), toutes en JSON strict,
toutes sous session sauf `POST /api/connexion` :

| Méthode | Chemin | Corps | Effet | Réponse |
|---|---|---|---|---|
| `POST` | `/api/connexion` | `{ name, password }` | ouvre la session | 204 ; 401 ; 429 |
| `POST` | `/api/deconnexion` | `{}` | ferme la session | 204 |
| `GET` | `/api/clients` | — | lit l'état (3.6) | liste des clients |
| `GET` | `/api/clients/<slug>` | — | lit le dossier et les travaux du client | dossier, travaux et sorties |
| `POST` | `/api/travaux` | un travail typé (3.3), sans identité | remet le travail à l'agent avec l'identité de la session | `{ id }` ; 400 (forme) ; 503 (agent injoignable) |
| `GET` | `/api/travaux/<id>` | — | lit l'état du travail | `$defs/travail` (3.3) |
| `POST` | `/api/clients/<slug>/confirmations` | une confirmation (3.5) | la remet à l'agent | `{ id }` |
| `GET` | `/api/clients/<slug>/paquet` | — | archive `tar` (POSIX `ustar`) du dernier paquet produit, produite à la demande après le contrôle d'EX-7.22 | `application/x-tar` ; 409 avec la sortie de `paquet-client controler` si le contrôle refuse |

Une requête d'une autre méthode que `GET` exige l'en-tête `Origin` égal à
l'origine de l'interface ; aucun en-tête `Access-Control-Allow-*`. La
politique de sécurité du contenu est bloquante, à nonce tiré à chaque
réponse (`script-src 'nonce-…' 'self'`, `style-src 'self'`,
`default-src 'none'`, `connect-src 'self'` (les formulaires remettent les
travaux par `fetch` à la même origine ; décision de l'assemblage de
l'étape 6), `frame-ancestors 'none'`, `form-action 'self'`,
`base-uri 'none'`, `object-src 'none'`), posée par `src/web/proxy.mjs` ;
l'interface n'est pas la console de CT-3, et EX-13.35 ne s'y applique pas.
Le périmètre public est `/connexion`, `POST /api/connexion` et les fichiers
statiques de la construction (`/_next/static/`, sans donnée), nécessaires à
l'écran de connexion.

Corps des requêtes (relecture de l'étape 6, `src/web/lib/bornes.mjs`) :
256 Kio au plus. Le serveur de l'interface (`bin/noortrace-inscription-web`)
répond avant Next, sans lire le corps et en fermant la connexion, 413
(`corps_trop_grand`) à un `Content-Length` au-delà de la borne et 411
(`longueur_exigee`) à un corps sans longueur annoncée (`Transfer-Encoding`) :
Next retient le corps d'une requête jusqu'à sa fin avant le mandataire et la
route, et le tronque sans le dire au-delà de sa propre borne
(`experimental.proxyClientMaxBodySize`, réglée à 256 Kio + 1 octet au lieu de
10 Mio). Une requête entière, corps compris, a 60 s. La route lit encore le
corps par morceaux et le refuse (413) dès la borne franchie.

### 2.4 Présentation des écrans

Complément du 2026-11-17, décision du porteur (présentation des écrans).
L'interface se lit comme un parcours guidé ; ce complément ne retire aucune
action ni aucune donnée de 2.2, et ne change ni les routes, ni la politique
de sécurité du contenu, ni les types de champ de 2.1.

- **Thème commun.** `src/web/app/globals.css` s'ouvre par le bloc de jetons
  et de composants commun aux écrans NOORTRACE, entre les repères
  `/* noor-theme:debut */` et `/* noor-theme:fin */`, identique à l'octet à
  celui de la console d'approbation et de la page de vérification ; les
  règles propres de l'outil viennent après lui (classes `ins-`), lisent ses
  jetons et n'en redéfinissent aucun. Aucune police, aucune image, aucune
  adresse dans la feuille ; aucun attribut `style` dans les pages
  (`style-src 'self'`) ; les icônes sont des SVG écrits dans le HTML.
- **Deux états d'affichage.** Sombre : l'état du document sans attribut,
  rendu sans script. Clair : `data-theme="clair"` sur `<html>`. Le bouton de
  bascule de la barre haute mémorise le choix dans le navigateur
  (`localStorage`, clé `noor.theme`, valeurs `clair` ou `sombre`,
  `src/web/lib/theme.mjs`) ; toute autre valeur vaut `sombre`. C'est le
  seul emploi du stockage du navigateur : ni clé, ni référence, ni donnée
  d'un client, ni identité n'y entre (2.1 reste entier). L'état clair
  mémorisé est posé avant le premier affichage par une amorce de quelques
  octets dans l'en-tête du gabarit, en script porteur du nonce de la
  réponse : `script-src 'nonce-…' 'self'` l'admet sans changement.
  L'impression rend en clair ; les blocs repliés fermés sont ouverts
  avant l'impression, puis refermés (un bloc fermé ne s'imprime pas).
- **Barre haute.** Le mot NOORTRACE, « Inscription des clients », la
  navigation (Clients, Nouveau client), l'identité de la session en entier,
  la déconnexion, la bascule. Sans session (`/connexion`), ni navigation ni
  identité. Sous la barre, quand `nature` de la configuration n'est pas
  `production`, un bandeau dit « Réseau d'essai » (affichage seulement :
  l'agent tranche, EX-7.3).
- **Mots au lieu de codes** (`src/web/lib/parcours.mjs`, module pur). Chaque
  étape (`steps[].step`) a un titre et une phrase qui dit ce qu'elle fait ;
  chaque état d'EX-7.16 a un libellé : `a_faire` « À faire », `envoyee`
  « Envoyée », `incluse` « Incluse », `capturee` et `faite` « Fait », `echec`
  « Échec » ; chaque commande de 3.3, chaque état d'un travail et chaque
  `result` d'une sortie ont le leur ; chaque `error.code` de
  `operations-registre-v0` et chaque refus de l'interface reçoivent une
  phrase et une conduite à tenir tirées de CT-4 7.11. Un code inconnu reste
  affiché tel quel. Un état se lit par un mot et une icône, jamais par la
  seule couleur. Les instants se lisent en UTC (« 12 novembre 2026 à
  08:05 UTC »).
- **Valeurs exactes.** Rien n'est abrégé ni reformulé. Les codes, l'objet,
  le hachage de transaction, le bloc, la capture, le contrat, l'erreur et
  l'instant exact d'une étape, l'`org_id`, les identifiants de l'instance,
  les adresses et la sortie JSON d'un travail se lisent, tels quels, dans
  un bloc replié (`<details>`) ouvert sur demande. Ce qui engage ne se
  replie pas : sur `/clients/<slug>/confirmations`, la personne du client,
  le canal, l'instant exact, l'objet visé, le SHA-256 de la pièce en
  entier, l'exploitant et le travail qui a consommé la confirmation ; sur
  `/clients/<slug>/paquet`, le SHA-256 du manifeste du paquet en entier.
- **Parcours.** `/clients` : une carte par client (nom, état, « n étapes
  sur m », prochaine action, date de la dernière action). `/clients/<slug>` :
  le nom, l'état et la prochaine action avec son bouton ; une étape `echec`
  en bandeau, avec la conduite à tenir ; puis les étapes dans l'ordre, la
  préparation du dossier (pas 1) en étape 1 ; les autres actions de 2.2,
  repliées ; les demandes de signature ; l'historique des travaux. La
  prochaine action est un guide : confirmation hors bande à consigner tant
  qu'une étape `approvisionnement` à faire n'a pas de confirmation inscrite
  et non consommée (3.5), étapes 2 à 5, demande d'inscription à préparer,
  puis à faire signer hors de l'application et à relayer (EX-7.27),
  première période, export, vérification, paquet. Elle n'autorise rien :
  l'agent refait chaque contrôle (EX-7.23).
- **Formulaires.** Un libellé (`<label for>`) et une aide par champ, des
  sections courtes, des exemples fictifs en `.example`. Une saisie refusée
  dans la page se dit en clair sous le champ fautif, sans recopier la
  valeur ; un refus du serveur ou de l'agent s'affiche en bandeau, avec la
  conduite à tenir, le code et le message exacts au détail. Le refus
  `confirmation_absente` affiche « confirmation hors bande absente »
  (EX-7.26). Sur `/clients/<slug>/confirmations`, l'objet demandé suit
  l'opération choisie (clé de chaîne, ou condensé de la demande). Quand un
  travail finit, la page relit la fiche auprès du serveur.
- **Accessibilité.** Focus visible, cibles de 44 px au toucher, lisible de
  390 px à 1280 px de large sans défilement horizontal.

### 2.5 Langage des écrans

Complément du 2026-11-18, décision du porteur (langage des écrans).
L'interface parle à la personne de l'équipe qui inscrit un client et qui
n'est pas développeuse. Ce complément ne change ni les pages de 2.2, ni les
routes, ni la politique de sécurité du contenu, ni les types de champ de
2.1, ni l'agent, ni la forme du dossier. Il remplace, en 2.4, les libellés
cités (« Incluse », « Réseau d'essai »), l'affichage de l'identité de
session, la disposition de la fiche et l'ordre de la prochaine action quand
un envoi est resté sans réponse ; le reste de 2.4 tient.

- **Premier niveau.** Tout ce qui se lit sans rien ouvrir se comprend sans
  avoir lu la spécification : ni code, ni nom de champ, ni terme de
  technicien. La liste publiée de ces termes est dans
  `test/fixtures/inscription/langage.mjs` ; un essai lit chaque écran et
  chaque état et n'en trouve aucun. Les valeurs exactes ne disparaissent
  pas : codes, hachages, identifiants, sortie d'un travail et message d'une
  erreur restent dans le détail replié de l'écran ; un nom qui vient des
  données (client, enregistreur, adresse, empreinte, identité, exemple de
  saisie) s'affiche tel quel, dans un élément marqué `data-valeur`.
- **Vocabulaire** (`src/web/lib/parcours.mjs`, `LEXIQUE`). « registre
  public », « empreinte », « journal », « enregistreur », « preuve de
  date », « signature », « adresse de signature », « nombre d'approbations
  requises » sont les mots du glossaire commun aux écrans NOORTRACE. Mots
  propres à cet outil : « compte technique » (la clé de chaîne d'un
  enregistreur), « crédits d'écriture » (ce qui paie une écriture sur le
  registre), « liste des approbateurs » (le jeu), « responsable des
  approbateurs » (la clé de gouvernance), « service d'inscription »
  (l'agent), « confirmation du client » (la confirmation hors bande),
  « paquet du client ». Chaque écran porte, replié, le lexique « Les mots
  de cet outil ».
- **Étapes.** Chaque étape a un nom courant en verbe et une phrase :
  « Préparer le dossier », « Enregistrer les approbateurs »
  (`jeu_approbateurs`), « Rattacher les approbateurs au client »
  (`assignation`), « Contrôler les approbateurs » (`lecture_jeu`),
  « Alimenter le compte technique » (`approvisionnement`), « Inscrire
  l'enregistreur » (`inscription`), « Déposer la première preuve de date »
  (`premiere_ancre`), « Clore la première période » (`premiere_cloture`).
  Chaque état d'EX-7.16 a un mot et une phrase : `a_faire` « À faire »,
  `envoyee` « Envoyée », `incluse` « Inscrite », `capturee` et `faite`
  « Fait », `echec` « Échec ».
- **Écran d'accueil.** `/clients` dit à quoi il sert et porte deux blocs
  repliés : « Comment ça marche » (cinq lignes) et « Les huit étapes, une
  par une ».
- **Prochaine action.** C'est une consigne : ce qu'il faut faire (titre à
  l'impératif), pourquoi, ce qu'il faut avoir sous la main, le bouton, et ce
  qui se passera après le clic. Pour une confirmation à noter, la consigne
  dit ce que le client doit confirmer : le montant du versement, le nom de
  l'enregistreur et l'adresse exacte du compte technique. « Commencer » se
  dit quand rien n'a été tenté, « Continuer » après un arrêt sans échec,
  « Reprendre » seulement après un échec ; pour un envoi resté sans
  réponse, la consigne dit « aller chercher la réponse ».
  Un client inscrit dont le paquet est produit n'a plus de « prochaine
  action » : l'intitulé devient « Inscription terminée ».
- **Envoi resté sans réponse.** Tant qu'une étape est `envoyee` ou
  `incluse`, la consigne est d'aller chercher la réponse du registre public
  pour cet envoi, avant toute autre (confirmation du client comprise) :
  « Allez chercher la réponse du registre public pour l'étape N », bouton
  « Chercher la réponse », et dessous « Rien n'est renvoyé, rien n'est
  dépensé. » Le bouton remet le travail `capturer` avec le hachage de
  l'étape (`envoi` pour `envoyee`, `transaction` pour `incluse`), sans champ
  à remplir. Ce travail ne fait que lire le registre (le reçu de la
  transaction connue, sa preuve) et ranger la preuve dans le dossier ; il ne
  soumet aucune transaction. C'est la reprise d'EX-7.13 : jamais une
  nouvelle transaction, et aucune confirmation n'est exigée pour elle. Le
  même geste a la même formule partout : nom de l'action (« Aller chercher
  la réponse du registre public »), étiquette de la liste et de la fiche
  (« Réponse à aller chercher »), messages d'erreur qui y renvoient.
  L'écran ne propose alors aucune autre action à côté de la consigne.
  La reprise n'est proposée que pour une étape dont l'agent envoie
  lui-même la transaction (pas 2, 3, 5 et 6) : il a écrit l'envoi dans les
  captures du client avant de marquer l'étape `envoyee`, et `capturer` le
  relit. Pour la première ancre et la première clôture, faites chez le
  client avec ses propres outils, l'envoi n'est pas dans les données de
  l'agent : la consigne reste neutre, sans action. Elle dit d'abord que
  l'étape se fait chez le client, puis qu'elle est notée « Envoyée »
  depuis tel instant et attend la réponse du registre public, puis :
  « si la fiche n'a pas changé à votre prochaine visite, prévenez
  l'équipe technique ».
- **Fiche courte.** Le premier écran montre l'avancement, la consigne et
  son bouton. Une étape faite ou à venir tient en une ligne (« Fait le … »),
  son détail replié ; seules l'étape où l'on en est et une étape en échec
  sont développées. Les actions de 2.2 qui ne servent pas dans l'état
  courant restent accessibles dans un bloc replié « Actions rarement
  utiles », chacune avec ce qu'elle fait et quand s'en servir.
  L'historique des travaux est replié ; sa ligne de titre dit la dernière
  action.
- **Jamais deux choses contraires.** Le dernier travail d'une commande dont
  la sortie dit `reussi` ou `deja_fait` alors qu'une étape qu'elle conduit
  est `echec` dans le dossier se lit « Terminé, avec une étape en échec »,
  sur la liste comme dans l'historique ; sa sortie exacte n'est pas
  retouchée. Une étape en échec se dit une fois, en bandeau (ce qui s'est
  passé, ce qui a été dépensé) ; la conduite à tenir est dans la consigne.
- **Erreurs.** Chaque refus et chaque `error.code` dit ce qui s'est passé,
  si quelque chose a été envoyé ou dépensé, et quoi faire (recommencer,
  attendre, prévenir l'équipe technique) ; le code et le message exacts
  sont dans « Détail à transmettre à l'équipe technique ». `agent_injoignable`
  se dit « Le service d'inscription ne répond pas », `session_absente`
  « Votre connexion à l'outil a pris fin », un travail `en_attente` « En
  attente de son tour ». Le refus `confirmation_absente` affiche une phrase
  courante, puis la mention de CT-4 EX-7.26, mot pour mot : « confirmation
  hors bande absente ». Un client inconnu et une panne de préparation d'un
  écran ont leur page (`app/not-found.js`, `app/error.js`).
- **Barre.** « Connecté : » et le nom du compte ; l'identité de session
  entière reste dans l'attribut `data-identite` et l'info-bulle. Hors
  production, le bandeau dit « Mode essai : rien de ce que vous faites ici
  ne touche le registre réel. »
- **Formulaires.** L'aide de chaque champ dit ce qu'on attend, d'où vient
  l'information (le client la donne par écrit, ou le champ se laisse vide)
  et, pour une adresse, ce qui se passe si elle est fausse (CT-4 EX-7.8).
  L'exemple s'écrit sous le champ (« Exemple : … »), jamais dans le champ.
  La consommation prévue par jour (le budget journalier d'EX-4.19) et la
  référence de notre réserve de crédits d'écriture (la trésorerie) (pas 1)
  sont rangées dans « Réglages avancés », replié : laissées vides, elles
  valent le budget par défaut et la trésorerie de l'agent, que l'agent
  recalcule et contrôle (EX-4.19, EX-8.20).
- **Le mot « demande ».** À l'écran, le document `demande_signature` que
  le client fait signer se dit « document à faire signer par le client »,
  puis « document signé » : « demande » est le mot de la console
  d'approbation pour ce qu'un approbateur doit décider, et un même mot
  n'a pas deux sens d'un outil à l'autre. Le nom « demande » ne paraît
  donc pas au premier niveau des écrans (l'essai le refuse) ; le verbe
  reste. Les noms de fichier, de commande et de paramètre (`demande`,
  `demandes/`) ne changent pas.
- **Qui envoie le document signé.** Aucun choix à faire, et rien de
  présélectionné : un envoi sur le registre ne part pas d'un choix fait à
  la place de la personne, et l'écran ne lui pose pas de question qu'elle
  ne peut pas trancher. Pour `inscrire-cle` et `administrer-jeu`, le bouton
  dit lui-même qui envoie : « Envoyer par notre compte d'envoi » (le
  relayeur de l'exploitant, seul admis pour un vrai client), avec dessous
  « C'est le cas habituel : notre société envoie le document signé au
  registre public et paie cet envoi. » L'envoi par le compte que désigne
  une référence (essais seulement) est une action à part, rangée dans
  « Actions rarement utiles », avec son champ, que la page refuse vide. Ce
  que la route reçoit pour chacun ne change pas : `relayeur: true`, après le
  document, pour le premier ; la référence seule (`cle_chaine` ou
  `expediteur`) pour le second.
- **Aides de saisie** (CT-4 EX-7.25, complément du 2026-11-18). Elles
  remplissent un champ d'un type déclaré, n'ont pas de nom de champ et
  n'envoient rien. `/clients/<slug>/confirmations` : « Choisir la pièce »
  lit le fichier dans la page et écrit son SHA-256
  (`crypto.subtle.digest`) dans le champ de l'empreinte, sans envoyer ni
  garder le fichier ; « Date et heure » et « Maintenant » écrivent
  l'instant en UTC, à la forme de 3.5, dans le champ de l'instant ; sous
  le champ, l'aide dit « Heure de votre poste ; l'outil la convertit »,
  et la valeur convertie s'affiche en clair dès qu'elle est connue, pour
  que l'heure du poste et l'heure enregistrée ne se confondent pas.
  `/clients/nouveau` : « Tirer un nom au hasard » écrit un slug de la forme
  de production (`crypto.getRandomValues`). La saisie à la main reste
  possible. Sur la fiche, « Copier le document » met dans le
  presse-papiers le texte exact du document à remettre au client.
- **Paquet.** L'écran dit ce que le paquet contient (EX-7.18), que son
  empreinte, celle de `paquet-client.json`, se donne au client par un autre
  moyen que le paquet, et que le client contrôle le paquet à la réception
  (EX-7.17, EX-7.22). Quatre lignes, hors de tout bloc replié : ce qu'il
  contient ; ce qu'il ne contient pas (aucune clé secrète, aucun mot de
  passe ; l'outil y a cherché les clés de l'exploitant qui ont servi à
  l'inscription, `secrets_checked` d'EX-7.21, et dit combien) ; à qui le
  remettre (au client seul : le paquet porte les reçus d'autres
  organisations des mêmes blocs, EX-7.21) ; ce que le client vérifie. Le téléchargement passe par la page quand le script
  tourne (le lien reste un lien) : un refus du contrôle (409) se lit sur
  l'écran, en clair. Un paquet déjà produit ne se refait que sur une raison
  dite ; son formulaire est replié.
- **Seconde lecture** (même complément, après une lecture des écrans par
  une personne sans formation). Rien de ce qui suit ne change une route,
  un corps envoyé, l'agent ni le dossier.
  - *Ce qui a été fait.* Une carte de la liste sans travail dit « Vous
    n'avez encore rien lancé pour ce client. » L'historique s'intitule
    « Historique des actions lancées depuis cet outil » et renvoie aux
    étapes pour l'état du client. La fiche dit des confirmations ce
    qu'elles sont devenues : « 1 notée, utilisée pour le versement du … »,
    « 1 notée, prête à servir » ; un versement fait sans aucune
    confirmation au registre, que l'agent ne permet pas (3.5), est dit
    anormal, avec « prévenez l'équipe technique ».
  - *Dates.* Chaque date porte son libellé : « Dossier préparé le … »,
    « Dernière action : …, le … ».
  - *Une étiquette, un sens.* « Réponse à aller chercher » : un envoi de
    l'agent attend qu'on aille chercher sa réponse, une action attend la
    personne. « En attente
    du registre » : une étape envoyée par le client attend sa réponse.
    « En attente chez le client » : la suite se fait chez lui. Dans ces
    deux cas la personne n'a rien à faire. Une étape `a_faire` que le
    client fait lui-même (`premiere_ancre`, `premiere_cloture`) se dit
    « À faire par le client ».
  - *Durées.* Aucune durée chiffrée : la reprise d'un envoi attend la
    réponse « quelques minutes d'ordinaire », parce que l'interface ne lit
    pas le réglage de l'agent qui la borne (`delai_s`, 120 par défaut,
    3.1) et qu'un chiffre écrit ne le suivrait pas. Les autres attentes
    n'en ont pas :
    l'écran dit à partir de quand s'inquiéter (« si la fiche n'a pas
    changé à votre prochaine visite »), sans chiffre.
  - *Ce que le client confirme.* La consigne et le formulaire disent ce que
    sont les crédits d'écriture (CT-4 EX-4.16, EX-4.19 : ils paient les
    écritures de l'enregistreur, ne s'achètent ni ne se vendent, et c'est
    la trésorerie de l'exploitant qui les verse) et comment faire
    confirmer l'adresse du compte : par écrit et en entier, jamais dictée
    ni comparée en partie (EX-7.26 : la confirmation porte sur le compte).
  - *Relecture avant de noter.* Le formulaire de confirmation redit en
    haut ce que le client confirme (montant et compte, ou document). Son
    bouton, « Relire avant de noter », contrôle la saisie et affiche un
    récapitulatif (ce qui est confirmé, la personne, le moyen, la date à
    l'heure du poste et en UTC, la pièce et le début et la fin de son
    empreinte) ; rien n'est envoyé. Seul « C'est exact, noter la
    confirmation » envoie, et il envoie l'objet relu, celui de 2.3. Toute
    retouche d'un champ annule la relecture.
  - *Date.* Le champ natif s'affiche dans la langue du navigateur : sous
    le champ, la date choisie est redite en toutes lettres, en français
    (« 18 novembre 2026 à 10 h 12, heure de votre poste »), au-dessus de
    l'instant converti.
  - *Qui envoie.* Remplacé à la troisième lecture : plus aucun choix (voir
    « Qui envoie le document signé »).
  - *Nom tiré au hasard.* Sous le champ du nom court, et sur la fiche d'un
    client dont le nom a la forme de production d'EX-6.2 : « Ce nom ne dit
    pas qui est le client : notez la correspondance dans votre fichier des
    clients. » Aucun champ n'est ajouté ; le dossier ne change pas.
- **Troisième lecture** (même complément, après une nouvelle lecture des
  écrans par une personne sans formation). Rien de ce qui suit ne change
  une route, un corps envoyé, l'agent ni le dossier.
  - *Fiches d'enregistreur.* Au pas 1, la personne colle le contenu de
    chaque fichier que le client a envoyé, tel quel, dans une zone par
    fiche ; « Ajouter une autre fiche » ouvre une zone de plus (seize au
    plus), « Retirer cette zone » en retire une. La page assemble la liste,
    dans l'ordre des zones : le corps envoyé est celui que donnait la saisie
    à la main de « [ fiche, fiche ] ». Une zone vide, une liste entre
    crochets ou un texte qui n'est pas une fiche entière (il lui manque un
    membre exigé par `#/$defs/cle_enregistreur`) est refusé dans la page,
    sous la zone, avec ce qu'il faut faire ; rien n'est envoyé. Le serveur
    et l'agent contrôlent la fiche contre son schéma, comme avant. La
    première zone ne peut pas rester vide : une liste sans fiche, que la
    route admet (`min: 0`), est refusée dans la page, et la phrase dit
    pourquoi (« Il faut au moins une fiche : l'outil n'inscrit au registre
    public que les enregistreurs dont la fiche est donnée ici, et il ne
    pourra plus en ajouter une fois le dossier préparé. ») : le travail
    `condense-inscription` ne prend que le `key_id` d'un enregistreur du
    dossier, et un dossier ne se prépare qu'une fois (CT-4 7.1, pas 6 ;
    7.5) ; CT-4 ne décrit pas d'inscription sans enregistreur.
  - *Formulaire de confirmation.* Chaque pas a sa phrase, sous son bouton,
    et seulement à ce pas : « Ce bouton n'enregistre rien : il vous montre
    ce que vous allez noter. », puis, à la relecture, « Ce bouton enregistre
    la confirmation. Elle ne pourra plus être effacée. »
  - *Confirmation attendue.* Une confirmation est attendue pour un
    versement de l'inscription à faire (étape `approvisionnement` à faire
    ou en échec) sans confirmation prête à servir pour ce compte (la règle de
    la consigne de la fiche), ou pour un document de changement des
    approbateurs préparé, ni envoyé ni remplacé par sa version signée, sans
    confirmation prête à servir pour son empreinte. Sinon l'écran des
    confirmations dit « Aucune confirmation n'est attendue pour ce client
    pour l'instant. » et range le formulaire dans un bloc replié, « Noter
    une autre confirmation (rare) ».
  - *Copier.* Un bouton « Copier » suit l'adresse du compte technique (fiche,
    formulaire et cartes des confirmations) et chaque empreinte qui se
    compare ou se transmet (pièce d'une confirmation, document de
    changement des approbateurs, paquet). La copie se fait par
    `navigator.clipboard.writeText`, dans le clic ; si le navigateur la
    refuse, le texte exact est sélectionné et la phrase dit de le copier au
    clavier. Rien n'est envoyé ; la politique de 2.3 ne change pas (le
    presse-papiers n'en relève pas, et aucun en-tête `Permissions-Policy`
    ne le restreint). Sur téléphone, une adresse se coupe en deux moitiés
    de 21 caractères, une empreinte en deux de 33.
  - *Premier écran, quelle que soit la police.* À 1280 px, la fiche prend
    la largeur de l'écran (80rem) et une consigne sans champ met son bouton
    à droite de ses phrases : le bouton reste dans le premier écran, et une
    étape faite ou à venir sur une ligne, avec une police de remplacement
    plus large que celle du thème (celle d'un poste qui n'a pas Inter).
- **Quatrième lecture** (même complément, après une nouvelle lecture des
  écrans par une personne sans formation). Rien de ce qui suit ne change
  une route, un corps envoyé, l'agent ni le dossier.
  - *Crédits d'écriture.* Chaque écran qui les nomme dit une fois, juste
    après le premier texte qui les nomme sans rien ouvrir, ce qu'ils sont
    (`CREDITS_EN_CLAIR`) : « Les crédits d'écriture ne sont pas de
    l'argent : ils servent seulement à payer les écritures sur le registre
    public, et chaque écriture en consomme. Ils ne s'achètent pas, ne se
    vendent pas et ne s'échangent pas : c'est notre société qui les
    fournit, et le client ne les paie pas. » (CT-4 4.5, EX-4.15, EX-4.16,
    EX-4.19). Là où le client confirme un versement, s'y ajoute ce que
    permet ce versement (ses preuves de date et ses clôtures de période,
    8.1), et la fiche dit d'où vient le montant (calculé à partir de la
    consommation prévue ; seule la différence est versée). Aucune durée
    n'est écrite : la provision dépend de `provision_days` et de
    `gas_limit` du manifeste du registre, que l'interface n'affiche pas, et
    l'exemple de 30 jours d'EX-4.19 ne compte pas les preuves de date des
    points de contrôle. Les mots « compte de paiement » et « budget » ne
    s'écrivent plus sur aucun écran : « réserve de crédits d'écriture »,
    « consommation prévue par jour ».
  - *Vérifier une pièce.* Sur `/clients/<slug>/confirmations`, quand une
    confirmation est notée, un bouton à part, « Calculer l'empreinte d'une
    pièce — rien n'est enregistré », hors du formulaire qui note : la page
    lit le fichier choisi, calcule son SHA-256 par le même calcul que
    « Choisir la pièce » (`empreinteFichier`), l'affiche avec « Copier
    l'empreinte » et dit si c'est celle de la pièce d'une confirmation de la
    liste. Aucune requête ne part, aucun champ n'est rempli ; l'élément de
    choix du fichier n'a pas de nom et porte le type `hachage` (CT-4
    EX-7.25, complément du 2026-11-18).
  - *Paquet.* Les quatre lignes disent ce que le paquet contient (la
    description du registre seulement quand le dossier en nomme une),
    qu'aucun de ses fichiers n'est fait pour porter une clé secrète, un
    jeton ou un mot de passe et que l'outil y a cherché les `n` secrets dont
    il s'est servi (`secrets_checked`, EX-7.21), et pourquoi il porte aussi
    la trace d'autres opérations du même bloc, dont celles d'autres clients
    (EX-7.21, EX-9.5 ; CP-3 : la preuve d'une opération se contrôle avec
    tous les reçus de son bloc).
  - *Valeurs brutes.* La liste de 2.4 tient : rien de ce qui engage ne se
    replie. Sur une confirmation, la date de la confirmation et celle où
    elle a été notée se lisent en mots, la personne qui l'a notée par le
    nom de son compte (comme dans la barre), l'action qui l'a utilisée par
    son nom et sa date ; sous ces mots, en petit et sans rien ouvrir,
    l'instant exact de la confirmation, l'identité de session entière et
    l'identifiant de l'action. Seul l'instant exact où elle a été notée
    passe au détail technique de la carte. Dans le formulaire, l'instant
    exact n'est plus un champ au premier niveau : il se calcule depuis la
    date et l'heure choisies, qui se lisent en mots, et son champ (celui
    qui part vers la route) est rangé dans « Réglages avancés », replié,
    qui s'ouvre si l'instant est refusé ; la relecture, avant le clic qui
    note, en donne la valeur exacte sans rien ouvrir.
  - *Ce qui a échoué.* Une étape en échec (`transaction_annulee`) dit sa
    cause d'après la vérification qui l'a rendue : un reçu refusé (OP-11)
    laisse l'étape sans capture, « Le registre public a reçu l'opération,
    mais elle n'a pas eu l'effet attendu. » ; une relecture contredite
    (OP-12) vient après la capture, « Le registre public a inscrit
    l'opération, mais le contrôle fait juste après ne retrouve pas ce qui
    devait être inscrit. » ; pour un travail, la vérification est
    `error.check` de sa sortie. Le code reste au détail. La consigne de
    reprise dit « Vous n'avez rien à corriger d'ici ».
  - *Rien à réunir.* Quand la consigne ne demande rien à avoir sous la
    main, elle dit « Rien à réunir » (et non plus « Rien à préparer », qui
    contredisait « Préparez le document »).
- **Cinquième lecture** (même complément, après une nouvelle lecture des
  écrans par une personne sans formation). Rien de ce qui suit ne change
  une route, un corps envoyé, l'agent ni le dossier ; rien de ce qui engage
  (2.4) ne se replie.
  - *Secrets du paquet.* La ligne « Ce qu'il ne contient pas » dit ce que
    l'outil a cherché sans contredire « aucune clé secrète n'est demandée
    dans cet outil » : les `n` clés secrètes et le jeton d'accès dont le
    service d'inscription s'est servi pour ce client (EX-7.21 ;
    `secrets_checked` les compte par option, `--jeton` pour le jeton), qu'il
    garde lui-même et que personne ne saisit ici ; aucun fichier n'en
    contient. Une ligne « Ce qu'il montre d'autres clients » dit exactement
    ce que portent les reçus et les transactions des mêmes blocs (EX-9.5) :
    l'identifiant d'un client sur le registre (un code, qui pour un client
    du registre réel ne permet pas de le reconnaître, EX-6.2), des
    adresses, des empreintes, des montants de crédits, le texte joint à une
    clôture de période ; rien de ce que ces clients nous ont transmis hors
    du registre public.
  - *Nouveau client.* « Essai » n'a qu'un sens, celui du bandeau « Mode
    essai » (un registre d'essai). L'aide du nom court dit d'abord le cas
    habituel, tirer un nom au hasard (EX-6.2) ; en mode essai seulement,
    elle ajoute qu'un nom libre est admis. Le formulaire qui prend
    approbateurs et enregistreur dans un fichier de clés déposé par
    l'équipe technique s'appelle « Préparer un client de démonstration ».
    Une saisie refusée l'est en entier : la page contrôle tous les champs
    (le contrôle natif du navigateur, qui ne montrait que le premier champ
    vide, est remplacé par le sien), signale chaque champ et chaque zone de
    fiche fautifs, et nomme sous le bouton les champs à corriger.
  - *Ce qu'une confirmation autorise.* Une seule opération (EX-7.26) : un
    versement sur un compte technique, ou un changement des approbateurs
    déjà enregistrés. Pour l'inscription, c'est le versement de l'étape 5 ;
    les étapes 2 à 4 n'en demandent pas, mais l'action qui fait les étapes
    2 à 5 ne commence pas sans elle (le service d'inscription refuse de
    l'admettre). La consigne de la fiche, l'écran des confirmations et le
    formulaire le disent ainsi.
  - *Crédits d'écriture.* L'explication (`CREDITS_EN_CLAIR`) est un bloc
    replié, « Qu'est-ce qu'un crédit d'écriture ? » (`CreditsEnClair`),
    juste après le premier texte de l'écran qui les nomme, une fois par
    écran au plus ; sous un bandeau d'erreur, il le suit au lieu d'y
    entrer. Le montant d'un versement et le compte qui le reçoit restent
    écrits sans rien ouvrir. Un repère vrai accompagne le montant
    (`repereEnClair`) : une preuve de date consomme d'ordinaire au plus
    100 000 crédits et une clôture de période au plus 350 000 (gaz de
    référence d'EX-4.19, 1 wei par gaz d'EX-4.15), et le nombre de preuves
    de date suivies de leur clôture que la consommation prévue par jour paie
    au moins (⌊b / 450 000⌋). Le montant
    lui-même ne donne aucun nombre d'écritures : un envoi exige un solde
    d'au moins sa limite de gaz (EX-4.18), réglage que l'écran n'affiche
    pas. Aucune durée.
  - *Autres.* « Rien à réunir » devient « Vous n'avez rien à rassembler
    avant de cliquer » ; l'empreinte du paquet est dite là où la fiche en
    parle d'abord ; sous « Envoyer par notre compte d'envoi », la phrase
    dit l'autre cas et où il est rangé. Sur téléphone, la note d'un bloc
    replié passe sous son titre.

## 3. Agent (`src/agent/`, `bin/noortrace-inscription-agent`)

### 3.1 Configuration et ligne de commande

```text
noortrace-inscription-agent --config <fichier>
```

Document JSON strict, `version` 0 :

| Membre | Contenu |
|---|---|
| `prise` | chemin absolu de la prise `AF_UNIX` (EX-7.28), de 103 octets UTF-8 au plus (complément du 2026-11-16 : `chemin_prise_trop_long`, `CHEMIN_PRISE_MAX_OCTETS` de `src/agent/client.mjs`) |
| `interface_uid` | identifiant numérique du compte du serveur de l'interface, seul pair admis |
| `donnees` | répertoire des données de l'agent (3.6) |
| `nature` | `developpement` ou `production` (celle de l'instance) |
| `instance` | chemin d'`instance-registre.json`, ou `null` (réseau de développement, EX-7.2) |
| `rpc` | points JSON-RPC de validateurs (EX-7.1) |
| `jeton` | référence `env:`/`fichier:` du jeton du nœud, ou `null` |
| `comptes` | références par rôle : `deployeur`, `administrateur`, `tresorerie`, `relayeur` ; ou `exploitant` (réseaux 2124 et 31337 seulement, EX-7.3) ; formes d'EX-7.3 seulement |
| `cles` | facultatif, `{ repertoire, alias }` (CT-4 EX-7.25) : `repertoire`, chemin absolu du seul répertoire dont un travail peut désigner un fichier (`fichier:`, `graine:`), ou `null` ; `alias`, au plus 64 noms `[a-z0-9][a-z0-9-]*` → références d'EX-7.3, qu'un travail désigne par `alias:<nom>` |
| `delai_s` | attente du reçu (défaut 120) |

L'agent refuse de démarrer avec une référence qu'EX-7.3 refuse pour la
nature de l'instance (en production : toute référence `fichier:` ou `env:`,
quel que soit le rôle), sur une prise
dont le répertoire n'appartient pas à son compte, n'est pas en `0750` ou dont
le groupe a un autre membre que le compte de l'interface, s'il a une prise
d'écoute `AF_INET` ou `AF_INET6`, si `interface_uid` est son propre compte
ou le compte 0 ou s'il tourne sous le compte 0 (EX-7.23), et, en production,
avec un point `rpc` en `http://` hors de la boucle locale (EX-7.1).
Prêt, il écrit `{"pret":true,"pid":<n>,"prise":<chemin>}` sur la sortie
standard ; SIGTERM l'arrête après le travail en cours.

### 3.2 Prise locale et compte du pair (EX-7.28)

- Écoute `net.createServer({ pauseOnConnect: true })` sur `prise` (mode
  `0660`, groupe de l'interface) ; aucune autre écoute.
- À chaque connexion, avant de lire aucun octet, l'agent obtient du noyau le
  compte du pair par `SO_PEERCRED`. Node 22 n'offre pas cette option : l'agent
  passe le descripteur de la connexion, sans le lire, à un processus auxiliaire
  sans dépendance (`python3 -I`, bibliothèque standard :
  `socket.socket(fileno=3)`, `getsockopt(SOL_SOCKET, SO_PEERCRED, 12)`, puis
  `detach()`), par `child_process.spawn(…, { stdio: ["ignore", "pipe",
  "pipe", connexion] })`, et lit `pid uid gid` sur sa sortie. Mesuré le
  2026-11-11 (Node 22.22.0, Python 3.13) : compte du pair lu, `bytesRead` nul
  avant le contrôle, données lues ensuite par l'agent. Un pair d'un autre
  compte que `interface_uid`, ou un auxiliaire en échec, ferme la connexion ;
  le refus (compte du pair, instant) est consigné en ajout seul et rien n'est
  exécuté.
- Protocole : une requête par connexion, un objet JSON strict sur une ligne
  (LF final), réponse de même forme, puis fermeture. Taille maximale d'une
  requête : 65 536 octets.
- Bornes (relecture de l'étape 6) : toute connexion, admise ou non, est
  fermée après 10 s d'inactivité (`DELAI_CONNEXION_MS`) ; au plus quatre
  auxiliaires `python3` tournent à la fois (`AUXILIAIRES_MAX`), les autres
  connexions attendent leur tour sans qu'aucun octet soit lu ; au plus 64
  connexions simultanées (`CONNEXIONS_MAX`).

| Requête | Réponse |
|---|---|
| `{ "version": 0, "kind": "travail", "exploitant": "<identité>", "travail": <travail typé> }` | `{ "accepte": true, "id": "trv-<32 chiffres hexadécimaux>" }` ou `{ "accepte": false, "code", "message" }` |
| `{ "version": 0, "kind": "confirmation", "exploitant": "<identité>", "confirmation": <confirmation> }` | `{ "accepte": true, "id": "cnf-<32 chiffres hexadécimaux>" }` ou refus |

Rien d'autre ne passe sur la prise : l'état se lit dans les fichiers de 3.6.
Codes de refus : `requete_invalide` (forme), `reference_refusee` (EX-7.3,
EX-7.25 ; une référence de travail hors du répertoire de clés ou d'un alias
inconnu rend le message unique de 2.1), `confirmation_absente` (EX-7.26),
`client_inconnu`, `file_pleine` (plus de 64 travaux en attente),
`instance_illisible` (manifeste d'instance illisible, ou dont la nature ou
les identifiants diffèrent de ceux du démarrage, revue de l'étape 8).

### 3.3 Travaux typés et file

Un travail est `{ "commande", "slug", "parametres" }`, `commande` parmi :

| `commande` | Pas | Paramètres | Sortie (`operations-registre-v0#/$defs/sortie`, `command`) |
|---|---|---|---|
| `inscrire-client-preparer` | 1 | options de 7.5 (`org`, `journaux`, `approbateurs`, `seuil`, `admin_jeu`, `cles_enregistreur` (documents `cle_enregistreur`), `budget_jour`, `tresorerie`) ; en développement, `cles_essai` | `inscrire-client` |
| `inscrire-client` | 2 à 5 | — (le dossier du client) | `inscrire-client` |
| `approvisionner` | 8.7 | `cle_chaine` (adresse) | `approvisionner` |
| `condense-inscription` | 6 | `key_id` | `condense` |
| `inscrire-cle` | 6 | `demande` (la demande signée, document `demande_signature`), `cle_chaine` (référence) ou `relayeur` | `inscrire-cle` |
| `capturer` | 7.11, EX-7.29 | `transaction` ou `envoi` | `capturer` |
| `exporter` | 10 | `manifeste` (chemin dans les données), `cles` | `exporter` |
| `verifier` | 10 | `parties`, `manifeste`, `ancres` (facultatif) | `verifier` |
| `paquet` | 7.13 | `prepared_by`, `console_origin` et `administrators` (ou `null`) | `paquet-client` (EX-7.30, opération `produire`) |
| `condense-administration` | 8.5 | `op` (une des cinq opérations de RG-11), `arg` (adresse, ou entier pour `CuratorSet.setThreshold`, absent pour `CuratorSet.acceptAdmin`) ; le jeu est celui du client | `condense` |
| `administrer-jeu` | 8.5 | `demande` (la demande signée par l'administrateur du jeu, document `demande_signature` d'opération `administration_jeu`), `expediteur` (référence) ou `relayeur` | `administrer-jeu` |

La file est unique et ordonnée ; l'agent exécute un travail à la fois,
refait chaque vérification OP- et CP- avant d'écrire (EX-7.23), et ne fait
jamais confiance à l'interface. État d'un travail (`$defs/travail`, forme
interne au paquet) : `{ "id", "commande", "slug", "exploitant", "recu_a",
"etat", "debut", "fin", "sortie" }`, `etat` parmi `en_attente`, `en_cours`,
`fini`, `refuse` (avant exécution : référence, confirmation, forme ; ou, à
l'exécution, confirmation absente au moment d'un versement ou d'un relais,
sans sortie) et `abandonne` (agent arrêté en cours : le travail n'est pas
repris ; le dossier dit l'état réel, et l'exploitant relance, EX-7.13). Le
travail `paquet` a une sortie `paquet-client` comme les autres (révision 0.7 :
plus de `resultat_paquet`). La sortie suit
EX-7.24 : mêmes `checks` dans le même ordre, mêmes `result`, `exit_code` et
`error.code` que l'outil de référence sur le même état.

### 3.4 États d'étape (EX-7.16)

L'agent tient le dossier `inscription-client-v0` du client et le réécrit
(fichier temporaire, `fsync`, renommage) à chaque passage d'une étape :
`a_faire`, `envoyee` (juste avant `eth_sendRawTransaction`), `incluse` (dès
le reçu `0x1` et OP-11), `capturee` (après CP-6), `faite` (étape sans
transaction), `echec` (`status` `0x0` ou relecture contredite). La reprise
suit la table d'EX-7.16 : jamais un nouvel envoi pour une étape `envoyee` ou
`incluse`. EX-7.29 (révision 0.7) : une étape `echec` que sa reprise trouve
accomplie reste `echec` (`deja_fait`) ; le travail `capturer` d'une
`transaction` qu'aucune étape ne porte et dont le reçu montre, émis par le
contrat de l'étape, l'événement de l'étape avec ses valeurs, capture le bloc,
vérifie OP-11 puis OP-12 et passe l'étape à `capturee` (seul passage
d'`echec` à `capturee`). Un approvisionnement fait sans transaction (solde
déjà au moins `P_k`) est `faite`, et `result.recorders[].funding` de la clé
vaut `null`.

### 3.5 Confirmations hors bande (EX-7.26)

Confirmation : `{ "operation": "approvisionnement" | "approvisionner" |
"administrer-jeu", "objet", "personne_client", "canal", "instant",
"piece_sha256" }`, `objet` valant `{ "org_id", "cle_chaine" }` pour un
approvisionnement et `{ "org_id", "digest" }` (le condensé de la demande)
pour `administrer-jeu` ; l'agent y ajoute l'exploitant et l'instant de
réception et l'inscrit en ajout seul. Un travail `inscrire-client` dont
l'étape `approvisionnement` reste à faire, `approvisionner`, ou
`administrer-jeu`, est refusé (`confirmation_absente`) sans confirmation
inscrite et non consommée pour chaque clé de chaîne ou pour la demande
visée ; aucune sortie n'est produite et rien n'est envoyé ; l'interface
affiche « confirmation hors bande absente ».

Une confirmation n'autorise qu'un approvisionnement ou qu'un relais (choix
de l'assemblage de l'étape 6, lecture stricte d'EX-7.26 et d'EX-8.21 : « avant
*tout* approvisionnement ») : juste avant l'envoi qui s'en sert, l'agent la
consomme par une ligne `{ "consommation": "<id>", "travail", "org_id",
"cle_chaine" | "digest", "instant" }` du même registre, en ajout seul, et ne
compte plus qu'une confirmation non consommée. Un travail qui n'envoie rien
(clé déjà au-dessus du seuil, refus avant l'envoi, reprise d'un envoi connu)
ne consomme rien.

La pièce qui porte la confirmation (courrier signé, procès-verbal) reste
hors de l'application : l'exploitant qui l'a recueillie en saisit le SHA-256
(`piece_sha256`, formulaire de 2.2), et les sorties `approvisionner`
(`reussi` comme `deja_fait`) et `administrer-jeu` (`reussi`) de l'agent
portent `outputs.confirmation_sha256`, la `piece_sha256` de la confirmation
qui autorise l'opération (consommée par le versement ou le relais), comme
l'outil de référence rend le SHA-256 du fichier `--confirmation` (CT-4
EX-8.21, revue de l'étape 8).

### 3.6 Données de l'agent

```text
<donnees>/                          compte de l'agent, groupe de l'interface, 0750
  journal-agent.ndjson              ajout seul : démarrage, pairs refusés, travaux reçus (identité), fins, sorties ; tourné à 16 Mio
  journal-agent.ndjson.1            génération précédente du journal (une seule gardée)
  confirmations.ndjson              ajout seul (EX-7.26), jamais tourné
  travaux/<id>.json                 $defs/travail, réécrit par renommage
  clients/<slug>/
    dossier.json                    inscription-client-v0 (EX-7.16)
    captures/                       même disposition que celle de l'outil (EX-7.24)
    demandes/                       demandes demande_signature préparées et relayées
    sorties/<id>.json               sortie de chaque travail
    parties/<n>/                    parties exportées (pas 10)
    paquets/<n>/paquet-client-<slug>/  paquet de la n-ième production (section 4), jamais remplacé
```

L'interface lit ces fichiers, en lecture seule, par son groupe ; aucun
fichier de clé, de graine ni de jeton n'y est jamais écrit (les clés restent
où leurs références les désignent, hors de `donnees`).

## 4. Paquet client (CT-4 §7.13)

### 4.1 Production

Le travail `paquet` rend la sortie de `paquet-client produire` (EX-7.30) et
suit son ordre : dossier (schéma, `entree_illisible` ; fini,
`dossier_inacheve`), instance de l'agent (même manifeste que le dossier,
`usage` ou `chaine_differente` ; sans manifeste, réseau 2124 seulement),
OP-4 hors ligne, résolution des références employées, gabarit, captures de
chaque étape contre CP-6 et contre l'étape (`capture_incomplete`, `CP-6`),
écriture dans un répertoire temporaire, contrôle d'EX-7.22, recherche
d'EX-7.21, renommage. Il écrit
`clients/<slug>/paquets/<n>/paquet-client-<slug>/`, `n` croissant (un paquet
remis n'est jamais remplacé), exactement selon EX-7.18 à EX-7.20 : `paquet-client.json`, `inscription-client.json`,
`instance-registre.json` (si `manifest_sha256` n'est pas nul),
`jeu-approbateurs.json` (`result.approver_set`), `gabarit-service-approbation.json`
(`$defs/gabarit_service`), `captures/` (chaque index des étapes et chaque
fichier qu'il nomme) ; les documents créés par `JSON.stringify(objet, null,
2)` et un LF ; le reste recopié octet pour octet ; `source` =
`@noortrace/inscription <version>`. Puis la recherche d'EX-7.21 (chaque clé
et graine désignées par l'inscription et le jeton : hexadécimal sans casse,
avec et sans `0x`, base64 et base64url avec et sans remplissage ; le jeton
tel quel) : une valeur trouvée interdit la remise (`secret_present`, `outputs`
`{ requirement: "EX-7.21", point: null, file }`), le nom du fichier est
consigné, jamais la valeur, et le répertoire est supprimé. `outputs` d'une
réussite : `{ directory, org, org_id, files, manifest_sha256,
secrets_checked }` ; `secrets_checked` nomme les options de secrets
cherchées et leur nombre (EX-7.21, EX-7.30) : `{ count, references }`,
chaque référence `{ option, reference }` (nom de l'option de l'outil de
référence qui désigne le rôle, `--exploitant`, `--cle-chaine`, `--jeton`…,
et référence d'EX-7.3, jamais la valeur), sans doublon, triées par option
puis par référence ; références de clés employées par les travaux du
client, et jeton.

### 4.2 Remise

`GET /api/clients/<slug>/paquet` rend l'archive du dernier paquet produit
après le contrôle de 4.3 ; le registre des confirmations n'entre pas dans le
paquet.

### 4.3 Contrôle de réception (EX-7.22)

`src/commun/paquet.mjs` exporte `controlerPaquet(repertoire, { schemas })` →
`{ valide, ecarts: [ { point, fichier, code, erreur } ] }`, les six points
d'EX-7.22 dans leur ordre (`point` de 1 à 6, compléments de la révision 0.7
compris : écriture d'EX-7.18 des trois documents créés, dossier fini et
réponse brute JSON-RPC 2.0 complète au point 3, nom du répertoire au point 4,
index nommé par une étape au point 6), `erreur` étant le code d'EX-7.30 du
point (`paquet_manifeste` à `paquet_captures`), utilisable par le client hors
de l'application ; un fichier au-delà de 64 Mio n'est pas lu
(`fichier_trop_grand`, point 2) et le parcours s'arrête à 4 096 entrées
(`trop_de_fichiers`, point 2) (revue de l'étape 8) ; et `sortieControle(repertoire)`, qui rend la même sortie
que `paquet-client controler` (premier écart, `error.check` nul, `outputs`
`{ requirement, point, file }`). L'agent applique ce contrôle avant toute
remise.

## 5. Essais

Fichiers `test/inscription-*.test.js`, outils sous
`test/fixtures/inscription/`. Réseau Hardhat en mémoire (31337) pour chaque
refus OP- et la reprise de chaque état d'EX-7.16 ; réseau de développement
2124, mis en attente avec un message quand il n'est pas debout. Oracles :
TE-21 (le paquet), TE-22 (l'application), épreuve d'EX-7.24 (l'outil de
référence, relancé en boîte noire sur le dossier et les captures de
l'application, rend `deja_fait` et n'envoie rien ; `verifier` rend R-1 à R-10
`reussi` ; le paquet passe EX-7.22), épreuve d'EX-7.28 (aucune prise
`AF_INET`/`AF_INET6` de l'agent ; connexion d'un autre compte fermée et
consignée, essai sous un second compte quand l'essai tourne en
superutilisateur, en attente sinon ; aucune page ni aucun script servi ne
contient le chemin de la prise), EX-7.25 (chaque champ refuse une valeur
nue), EX-7.26, EX-7.27. Complément du 2026-11-17 (2.4) :
`test/inscription-presentation.test.js` (feuille de style, mots du
parcours, prochaine action, détail technique, bascule de thème ; sans
navigateur) et `test/inscription-presentation-chromium.test.js` (les écrans
dans Chromium par Playwright, sur des données fictives sans agent ; en
attente si Chromium manque, en échec sous `NOORTRACE_EXIGER_CHROMIUM=1`).
Complément du 2026-11-18 (2.5) : les mêmes fichiers portent les libellés du
langage courant, l'essai « aucun mot de technicien au premier niveau » sur
chaque écran et chaque état, les aides de saisie (empreinte égale à celle
de `sha256sum`, aucune requête au choix du fichier, instant accepté par le
contrôle de la route), le bouton qui nomme le compte qui envoie (aucun
choix à faire), la consigne unique d'un envoi resté sans réponse, les
erreurs en clair et la cohérence des états ; à la troisième lecture, les
fiches collées une par zone (corps envoyé au caractère près), « Copier »,
les phrases de chaque pas du formulaire de confirmation, la confirmation
attendue et les heures des données fictives dans l'ordre des étapes ;
`test/fixtures/inscription/langage.mjs` publie la liste des mots. Les
essais dans Chromium se jouent aussi avec les polices d'un poste qui n'a
pas Inter (une configuration de fontconfig qui la retire) : la mise en page
doit tenir avec l'une comme avec l'autre.

## 6. Précisions de la construction (étape 6)

Ces précisions complètent le contrat sans le contredire ; celles que le texte
de CT-4 ne permet pas de trancher sont aussi des questions du rapport de
l'étape. Le détail est dans `LISEZMOI.md`.

### 6.1 Agent

- **Ligne de commande et démarrage.** `noortrace-inscription-agent --config
  <fichier>` ; une configuration refusée (EX-7.3, EX-7.28, forme) rend le code
  2 et le message sur la sortie d'erreur. Complément du 2026-11-16 : toute
  autre ligne (option inconnue, en double ou sans sa valeur, argument en
  trop) rend l'usage et le code 2 ; une `prise` de plus de 103 octets est
  refusée (`chemin_prise_trop_long : <n> octets, au plus 103`), comme par
  l'interface (`lireConfigurationInterface`) et par le client de la prise
  (`remettre`, avant toute connexion). Le membre `comptes` admet les rôles
  `deployeur`, `administrateur`, `tresorerie`, `relayeur` et `exploitant` ;
  il peut être vide (production : aucune clé de l'exploitant n'y est admise,
  EX-7.3). Le jeton (`env:` ou `fichier:` lisible de son seul propriétaire)
  est un texte ASCII imprimable sans espace. Python 3 (`python3 -I`) est exigé
  à l'exécution.
- **Instance sans manifeste** (`instance` nul, EX-7.2) : `deployments/noorcore.json`,
  `chain/config/alloc-dev.json`, `chain/runtime/validators.json` et
  l'artefact de `CuratorSet` se lisent depuis le répertoire de travail de
  l'agent (la racine du dépôt sur le poste du réseau de développement).
- **Provision du dossier (OP-4, revue de l'étape 8).**
  `inscrire-client-preparer` et `inscrire-client` vérifient en OP-4, avant
  OP-5 comme l'outil, que `funding.funder` est le compte de rôle
  `tresorerie` du manifeste (`compte_inattendu`), que `daily_budget_gas` ne
  dépasse pas `fees.max_daily_budget_gas` quand le manifeste le fixe et que
  `amount_wei` est `provision_days × daily_budget_gas + gas_limit` recalculé
  depuis `fees` du manifeste (`provision_excessive`) ; la provision versée est
  toujours celle recalculée, jamais celle du dossier.
- **Journal de l'agent** (`journal-agent.ndjson`, `{ instant, evenement, … }`) :
  `demarrage`, `arret`, `pair_refuse` (`uid`, `pid`, `octets_lus`),
  `requete_refusee`, `travail_recu` (`id`, `commande`, `slug`, `exploitant`,
  `references` : forme et rôle de chaque référence de clé du travail, jamais
  une valeur), `travail_refuse` (`code`), `travail_debut`, `travail_fin`
  (`result`, `exit_code`), `travail_abandonne`,
  `confirmation_recue`, `confirmation_refusee`, `envoi_ecrit`,
  `paquet_secret_trouve` (`fichiers`), `travail_erreur_noeud`,
  `travail_erreur_interne`, `reference_employee` (`role`, `reference`
  effective, `alias`), `reference_non_resolue` (`role`, `forme`, `detail` :
  le détail que l'interface ne reçoit pas), `refus_cumules` (`refus`,
  `periode_debut`, `nombre` : refus au-delà de huit par minute et par
  événement, revue de l'étape 8).
- **Enregistrement d'un travail** (`$defs/travail`) : en plus des membres de
  3.3, `motif` (`{ code, message }`) pour l'état `refuse` (révision 0.7 :
  plus de `resultat_paquet`, le travail `paquet` rend sa sortie
  `paquet-client` dans `sortie`). Les travaux en attente ou en
  cours à l'arrêt de l'agent sont `abandonne` au démarrage suivant.
- **Paramètres des travaux.** `cles_essai` : chemin de `cles-essai.json`
  relatif au répertoire du client dans les données de l'agent, où
  l'exploitant l'a déposé (EX-7.25, révision 0.7 : chemin relatif sous le
  répertoire du client ; réseaux 2124 et 31337 seulement) ; sans lui, `approbateurs`, `admin_jeu` et `cles_enregistreur`
  sont requis. `tresorerie` et `cle_chaine` sont des références d'EX-7.3 ; la
  clé de chaîne d'`inscrire-cle` est celle de la demande. `approvisionner`
  admet une clé de chaîne du dossier du client (EX-8.20, `admitted_as`
  `dossier`). `capturer` : `transaction` (hachage d'une transaction incluse)
  ou `envoi` (hachage d'un envoi de l'agent, `envoi-<hachage>.json`) ; le rôle
  se lit dans l'étape du dossier qui porte ce hachage, sinon se déduit de la
  transaction comme EX-8.16 le fait pour `--envoi`. `exporter` et `verifier` :
  chemins relatifs au répertoire du client (`periode-<n>/manifeste.json`,
  `parties/<n>`, `cles.json`, fichier d'ancres) ; `exporter` écrit dans
  `parties/<n>/`, `n` croissant ; sans fichier d'ancres, `verifier` dérive
  l'ancre `registry` du manifeste d'instance (RG-20) ou des valeurs d'EX-7.2,
  et les `recorders` de l'ancre du dossier (`anchor_source`
  `publication_exploitant`).
- **Données** : `clients/<slug>/demandes/demande-inscription-<key_id>-<id>.json`
  (préparée par `condense-inscription`) et
  `demande-inscription-relayee-<key_id>-<id>.json` (relayée) ;
  `clients/<slug>/lecture-jeu.json` garde `set_read` de l'étape
  `lecture_jeu` ; le manifeste d'une période, produit par l'enregistreur, se
  dépose sous `clients/<slug>/periode-<n>/`.

### 6.2 Interface

- **Configuration** (`noortrace-inscription-web --config <fichier>`) :
  `{ version: 0, ecoute: { hote, port }, origine, prise, donnees, comptes:
  "fichier:<chemin>", nature }` (`LISEZMOI.md`) ; l'origine est
  `https://…` en production, où `ecoute.hote` est `127.0.0.1`, `::1` ou
  `localhost` (derrière le mandataire TLS) et chaque réponse porte
  `Strict-Transport-Security: max-age=63072000; includeSubDomains` (revue de
  l'étape 8, CT-7 CLE-37) ; toute requête dont l'en-tête `Host` n'est pas
  l'autorité de `origine` reçoit 421 `hote_refuse` ; le binaire pose
  sur chaque requête l'en-tête `x-noortrace-adresse-cliente` (adresse du
  pair ; en production, dernière adresse de `X-Forwarded-For`), que le verrou
  de connexion emploie.
- **Types de champ** : la liste close de 2.1 (EX-7.25, révision 0.7) ;
  chaque champ d'une page porte son type dans l'attribut `data-type`. Le seul champ de mot de passe est celui du compte
  d'exploitant (`/connexion`). Un champ de texte refuse aussi une valeur qui a
  la forme d'une clé, d'une graine ou d'une mnémonique.
- **Périmètre public** : `/connexion`, `POST /api/connexion` et les fichiers
  statiques de la construction (`/_next/static/`, sans donnée), nécessaires à
  l'écran de connexion.
- **Politique de sécurité du contenu** : celle de 2.3 et `connect-src
  'self'` (les formulaires remettent les travaux par `fetch`) ; en-têtes
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY` ; `Cache-Control: no-store` sur les routes.
- **Réponses d'erreur des routes** : `{ "error": { "code", "message",
  "data"? } }` ; 400 (forme, ou refus de l'agent : `reference_refusee`,
  `confirmation_absente` — message « confirmation hors bande absente » —,
  `client_inconnu`, `file_pleine`), 401 (session), 403 (`Origin`), 404, 409
  (paquet qui ne passe pas EX-7.22, code d'EX-7.30 et `data.sortie`, la
  sortie de `paquet-client controler`), 413, 415, 429
  (`essai_trop_tot`, `data.retry_after_s`), 503 (agent injoignable).
  `GET /api/clients/<slug>/confirmations` rend le registre du client.

### 6.3 Paquet

- `controlerPaquet` rend, pour chaque écart, un motif propre au paquet
  (`LISEZMOI.md`, « Contrôle du paquet ») et le code d'EX-7.30 de son point ;
  un écart au point 1 arrête le contrôle ; « le dossier fini » (table
  d'EX-7.18) est contrôlé au point 3 (`dossier_non_fini`).
- `instance-registre-v0` emploie `contains`, que `RegistreSchemas` refuse : le
  manifeste d'instance se valide par `verifierManifesteSchema` de
  `@noortrace/ancrage/registre`.
- La recherche d'EX-7.21 porte sur les références qu'ont employées les
  travaux du client, venues du travail ou des comptes de la configuration
  (lignes `reference_employee` du journal de l'agent, écrites quand
  `cleRole` résout une clé), et sur le jeton ; un compte de la configuration
  qu'aucun travail du client n'a employé n'est pas cherché, de sorte que
  `secrets_checked` égale celui de l'outil auquel l'exploitant donne les
  références employées pour cette inscription (EX-7.21, EX-7.24, étape 6) ; une référence qui ne se résout plus interdit la
  remise (`entree_illisible`, comme l'outil pour une option de secret
  illisible).

