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
    web/                  projet Next.js (répertoire racine de « next build ») : app/, proxy.mjs, next.config.mjs
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
| Lectures du registre (OP-8, OP-12) | `appelLecture`, `recorderOf`, `recorderByPubKey`, `isActiveRecorder`, `SELECTEURS`, `SIGNATURES_FONCTIONS`, `SIGNATURES_EVENEMENTS`, `SUJETS`, `EVENEMENT_PAR_ROLE` |
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
  échecs, `min(2^(f − 5), 900)` s).
- L'interface n'a qu'un rôle : un exploitant authentifié peut tout ce
  qu'elle offre. Chaque travail et chaque confirmation consignent son
  identité.

## 2. Interface web (`src/web/`, Next.js 16.4.6)

### 2.1 Ce qu'elle ne fait jamais (EX-7.23, EX-7.25, EX-7.27, EX-7.28)

- tenir une clé, une graine, une mnémonique, un jeton, un mot de passe de clé
  ou une référence **résolue** ; aucun champ de page ni de route n'en reçoit
  la valeur ; un champ de référence de clé n'admet que `fichier:<chemin>`,
  `env:<VARIABLE>`, `graine:<chemin>` et `hardhat:<i>` (EX-7.3), et refuse
  sans la garder ni la consigner une valeur nue (64 chiffres hexadécimaux
  avec ou sans `0x`, une mnémonique, tout texte hors de ces formes) ;
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
période, `texte` pour un identifiant de clé, une opération du jeu ou
« oui »/« non »). La valeur est contrôlée côté serveur par
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

## 3. Agent (`src/agent/`, `bin/noortrace-inscription-agent`)

### 3.1 Configuration et ligne de commande

```text
noortrace-inscription-agent --config <fichier>
```

Document JSON strict, `version` 0 :

| Membre | Contenu |
|---|---|
| `prise` | chemin absolu de la prise `AF_UNIX` (EX-7.28) |
| `interface_uid` | identifiant numérique du compte du serveur de l'interface, seul pair admis |
| `donnees` | répertoire des données de l'agent (3.6) |
| `nature` | `developpement` ou `production` (celle de l'instance) |
| `instance` | chemin d'`instance-registre.json`, ou `null` (réseau de développement, EX-7.2) |
| `rpc` | points JSON-RPC de validateurs (EX-7.1) |
| `jeton` | référence `env:`/`fichier:` du jeton du nœud, ou `null` |
| `comptes` | références par rôle : `deployeur`, `administrateur`, `tresorerie`, `relayeur` ; ou `exploitant` (réseaux 2124 et 31337 seulement, EX-7.3) |
| `delai_s` | attente du reçu (défaut 120) |

L'agent refuse de démarrer avec une référence qu'EX-7.3 refuse pour la
nature de l'instance, sur une prise dont le répertoire n'appartient pas à
son compte, n'est pas en `0750` ou dont le groupe a un autre membre que le
compte de l'interface, et s'il a une prise d'écoute `AF_INET` ou `AF_INET6`.
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
EX-7.25), `confirmation_absente` (EX-7.26), `client_inconnu`, `file_pleine`
(plus de 64 travaux en attente).

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

### 3.6 Données de l'agent

```text
<donnees>/                          compte de l'agent, groupe de l'interface, 0750
  journal-agent.ndjson              ajout seul : démarrage, pairs refusés, travaux reçus (identité), fins, sorties
  confirmations.ndjson              ajout seul (EX-7.26)
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
de l'application ; et `sortieControle(repertoire)`, qui rend la même sortie
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
nue), EX-7.26, EX-7.27.

## 6. Précisions de la construction (étape 6)

Ces précisions complètent le contrat sans le contredire ; celles que le texte
de CT-4 ne permet pas de trancher sont aussi des questions du rapport de
l'étape. Le détail est dans `LISEZMOI.md`.

### 6.1 Agent

- **Ligne de commande et démarrage.** `noortrace-inscription-agent --config
  <fichier>` ; une configuration refusée (EX-7.3, EX-7.28, forme) rend le code
  2 et le message sur la sortie d'erreur. Le membre `comptes` admet les rôles
  `deployeur`, `administrateur`, `tresorerie`, `relayeur` et `exploitant` ;
  il peut être vide (production : aucune clé de l'exploitant n'y est admise,
  EX-7.3). Le jeton (`env:` ou `fichier:` lisible de son seul propriétaire)
  est un texte ASCII imprimable sans espace. Python 3 (`python3 -I`) est exigé
  à l'exécution.
- **Instance sans manifeste** (`instance` nul, EX-7.2) : `deployments/noorcore.json`,
  `chain/config/alloc-dev.json`, `chain/runtime/validators.json` et
  l'artefact de `CuratorSet` se lisent depuis le répertoire de travail de
  l'agent (la racine du dépôt sur le poste du réseau de développement).
- **Journal de l'agent** (`journal-agent.ndjson`, `{ instant, evenement, … }`) :
  `demarrage`, `arret`, `pair_refuse` (`uid`, `pid`, `octets_lus`),
  `requete_refusee`, `travail_recu` (`id`, `commande`, `slug`, `exploitant`,
  `references` : forme et rôle de chaque référence de clé du travail, jamais
  une valeur), `travail_refuse` (`code`), `travail_debut`, `travail_fin`
  (`result`, `exit_code`), `travail_abandonne`,
  `confirmation_recue`, `envoi_ecrit`, `paquet_secret_trouve` (`fichiers`),
  `travail_erreur_noeud`, `travail_erreur_interne`.
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
  `https://…` en production.
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

