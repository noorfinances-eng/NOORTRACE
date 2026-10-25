# CT-4 — Registre

Version 0.2, 2026-10-25. Spécification normative, soumise à la revue de la
porte 1 du plan de projet (document interne). Elle met en œuvre le point 1 de
la section « Ancrage » et la section « Instance dédiée » de l'[architecture
cible](../ARCHITECTURE.md). Elle s'appuie sur les formats v0 de
[CT-1](CT-1-evenements-et-formats.md) sans les modifier, reprend ce que
[CT-2](CT-2-enregistreur.md) envoie au registre et en attend (CT-2 §11.3,
§14.2), sert la lecture du jeu d'approbateurs de
[CT-3](CT-3-approbations.md) (§8) et se conforme à ce que
[CT-6](CT-6-verificateur.md) §13.3 exige de CT-4, sans changer CT-6. Elle
touche les décisions ouvertes 6 et 7 de l'architecture (section 13).

La spécification a deux parties. La **partie A** (sections 0 à 6) dit qui
agit et ce que le registre prouve, ce qu'est une instance (genèse,
identifiants, validateurs, frais, versions de noorcore), quels contrats y sont
déployés et comment, et comment se calcule hors chaîne tout ce que l'on signe
ou envoie : identifiants, `docType`, empreintes d'ancre, condensés signés,
encodage des appels et des transactions. Un développeur qui écrit un client du
registre peut s'y arrêter : elle suffit pour produire, octet pour octet, une
inscription de clé, une ancre et une clôture de période. La **partie B**
(sections 7 à 14 et annexes) dit comment un client est inscrit, comment le
registre s'exploite au quotidien, comment le certificat de commit se capture
pour le dossier, comment se déploient l'image du nœud, les validateurs
partenaires et les relais RPC, selon quels critères la chaîne est maintenue ou
remplacée, quelles menaces sont traitées, ce que la version ne couvre pas,
comment les vecteurs sont disposés et d'où viennent les faits externes.

## 0. En-tête et conventions

Les mots DOIT, NE DOIT PAS, DEVRAIT et PEUT ont le sens de la RFC 2119, comme
dans CT-1, CT-2, CT-3 et CT-6.

Chaque règle normative porte un identifiant **EX-<section>.<n>** (EX-4.6 :
sixième règle de la section 4), stable, auquel le plan de tests (CT-9)
attache ses tests. Les identifiants sont numérotés dans l'ordre du texte à
l'intérieur de chaque section de premier niveau, sous-sections comprises.
Une règle ajoutée par une révision reçoit le numéro qui suit le plus grand de
sa section ; aucun numéro n'est réattribué ; une règle retirée garde son
numéro, marqué « retiré ».

Les vérifications élémentaires portent l'identifiant de leur famille :

| Famille | Objet | Définie par |
|---|---|---|
| RG- | Ce qui se calcule hors chaîne : identifiants, `docType`, empreinte d'ancre, champs d'une clôture, condensés signés et signatures, encodage des appels et des transactions, manifeste d'instance | section 6 (table en 6.9) |
| OP- | Vérifications des outils de référence avant et après chaque envoi | 7.3 |
| CP- | Capture d'une transaction du registre | 9.4 |
| SU- | Critères de la règle de substitution | 11.2 |
| R-, N- | Contrôle 8 et fichier d'ancres du réviseur | CT-6 §11 et §12, reprises sans changement |

Les documents JSON de CT-4 suivent les encodages de CT-1 §3 : octets en
hexadécimal minuscule préfixé `0x`, adresses comprises (une adresse servie en
casse mixte EIP-55 est mise en minuscules avant d'être écrite, comme le fait
l'exportateur de CT-6 §11.2.1) ; horodatages RFC 3339 en UTC à trois
décimales ; entiers JSON dans `[0, 2^53 − 1]`, au-delà chaîne décimale. Les
quantités JSON-RPC sont en hexadécimal sans zéro de tête (`0x0`, `0x84c`).
Les clés JSON sont en anglais ; les valeurs énumérées sont en français, sans
accent (`developpement`, `attribue_a_un_tiers`, `tresorerie`).

Notation des octets : `‖` concatène ; `u256(x)` est l'entier non signé `x`
sur 32 octets grand-boutistes, `u64(x)` sur 8 ; `a20(x)` les 20 octets d'une
adresse ; `b32(x)` 32 octets tels quels ; `utf8(s)` les octets UTF-8 de `s`,
sans terminateur ni longueur ; `keccak256` le Keccak-256 d'origine, celui de
l'EVM (pas SHA3-256 de FIPS 202) ; `sha256` le SHA-256 de FIPS 180-4.

« Les outils de référence » désignent les outils JavaScript de la partie B
(7.2), qui réutilisent `scripts/lib/` sans changer le comportement de
`scripts/deploy` ni de `scripts/e2e` : hors de la spécification, de ses
schémas et de ses vecteurs, ce lot ne modifie que `scripts/lib/noortrace.mjs`
(commentaire de gaz et paramètre facultatif `setAdmin` de `bootstrapOrg`,
défaut inchangé), l'en-tête de `scripts/deploy/bootstrap-org.mjs`,
`package.json` et `.github/workflows/ci.yml` (section 13). Eux et le
vérificateur Go indépendant de
`spec/vecteurs/ct-4/verificateur-independant` (annexe A), écrit depuis cette
seule spécification, rendent sur les mêmes entrées les mêmes valeurs et les
mêmes verdicts RG-, OP- et CP- (EX-A.5).

Les faits externes viennent de deux notes de recherche du lot CT-4, internes
et non publiées, relues le 2026-10-25 sur les sources primaires qu'elles
citent : R1 (noorcore et dépôt : code de noorcore au commit épinglé, dépôt
public, expériences du 2026-10-25 sur le réseau de développement) et R2
(pratiques externes : registre public des identifiants de chaîne, réseaux à
gaz sans monnaie échangeable, journaux signés, consensus byzantin et
validateurs opérés par des tiers, conventions d'identifiants). Chaque fait
porte le renvoi du fait dans sa note (« R1-F23 », « R2-F8 »), d'un point non
vérifié (« R1, point non vérifié 9 ») ou d'une conséquence pour la conception
(« R1, conséquence C5 »). L'annexe B donne, pour chaque renvoi, l'objet du
fait, les sources primaires publiques et leur date. Un fait tiré du code de
noorcore, dépôt privé, n'est pas recoupable publiquement (comme dans CT-6
annexe B.3) ; quelques faits de ce code ont été lus pour cette spécification
et portent leur fichier et leurs lignes au commit `618fcef` (annexes B.3 et
B.4). Un fait du dépôt
public porte son fichier et ses lignes à l'état de la branche `main` au
commit `3c6e896` ; pour les quatre fichiers que ce lot modifie hors de la
spécification (section 13), les lignes sont celles de l'arbre de travail du
lot, et les fonctions sont nommées. Ce qui n'a pas pu être vérifié est écrit
« non vérifié ».

Le **réseau de développement** est l'instance `noortrace-2124-dev` de
`chain/`, quatre validateurs sur une seule machine, lancée par
`bash chain/scripts/dev-net.sh start` (`chain/README.md:1-17`).

Lecture : un développeur lit les sections 5 et 6 ; un opérateur de
validateur, la section 4, puis la section 10 ; un réviseur, 3.4 et 4.8, puis
CT-6 §12.5.

**Révisions.** La version 0.1, du 2026-10-25, est la première. La version 0.2,
du même jour, applique les corrections de la revue de la porte 1 : CP-2, CP-3
et CP-6 délimitées (9.4), motifs des RG- fixés (6.9), types du constructeur de
`CuratorSet` (5.1, 6.7.2), ordre des signatures (EX-6.16), gaz de l'ancre
(4.5), étiquettes de l'exemple de 7.10, états d'une étape et reprise
(EX-7.16), contrôle du client (EX-7.17), demandes de clôture (EX-8.4,
EX-8.19), approvisionnement (EX-8.20), relais sur confirmation (EX-8.21),
garde d'admission et données des validateurs (EX-10.8, EX-10.9), sûreté
(3.5, section 12) et propositions (sections 13 et 14). L'épreuve de 7.12,
rejouée deux fois sur cette version par des relecteurs qui n'avaient que la
spécification, a été réussie les deux fois ; leurs remarques ont précisé,
sans nouvelle règle, 7.4 (effets de `npm ci` et de `npm run compile` sur
l'arbre de travail, sorties à rendre), 7.7 (`expires_at` réservé aux demandes
de clôture, absent des autres demandes), 7.9 (certificats à vérifier, arrêt
du réseau) et 7.12 (contenu, conservation et remise du répertoire de l'essai).

## 1. Objet, périmètre et relations

CT-4 fixe, pour la version 0 du registre :

1. le modèle : rôles, flux, ce qui est signé, ce que le registre prouve et ne
   prouve pas, adversaires (section 3) ;
2. l'instance : genèse et règles vérifiées au démarrage, identifiants,
   validateurs et quorum, frais sans jeton échangeable et leur borne contre le
   déni de service, versions de noorcore épinglées, correctif du certificat de
   commit, manifeste d'instance (section 4) ;
3. les contrats : liste et rôle, ordre de déploiement, adresses publiées,
   contrôle d'accès, administration, mises à jour, événements, refus
   (section 5) ;
4. les conventions calculées hors chaîne : `org_id`, `journal_id`,
   `docType`, empreinte d'ancre, condensés signés, ordre des signatures,
   encodage des appels et des transactions, vérifications RG- (section 6) ;
5. l'inscription d'un client (section 7), l'exploitation courante
   (section 8), le certificat de commit et sa capture pour le dossier
   (section 9), l'image conteneur et les topologies (section 10), la règle de
   substitution (section 11), la sûreté (section 12), l'alignement avec le
   dépôt (section 13), ce que la version ne couvre pas (section 14), les
   vecteurs (annexe A) et les sources (annexe B).

Hors périmètre : les formats de l'événement, du manifeste et du dossier
(CT-1, inchangés) ; l'enregistreur lui-même (CT-2) ; la politique
d'approbation et les tickets (CT-3) ; les ancres RFC 3161 et OpenTimestamps
(CT-5) ; le vérificateur et le contrôle 8 (CT-6, inchangé) ; les cérémonies
de clés et la revue de sécurité (CT-7) ; la supervision et la sauvegarde
(CT-8) ; le plan de tests (CT-9) ; toute modification du consensus de
noorcore, dont le mode observateur (décision ouverte 7) ; tout jeton
échangeable, toute émission, toute récompense.

Ce que la version 0 livre :

| Élément | Livré |
|---|---|
| Cette spécification ; le schéma `spec/schemas/instance-registre-v0.schema.json` (4.8) ; les schémas `inscription-client-v0` et `operations-registre-v0` de la partie B (sections 7 à 9) | avec CT-4 |
| Les outils de référence JavaScript qui inscrivent un client, inscrivent une clé d'enregistreur, ancrent et soumettent une période en suivant la spécification pas à pas, sans casser `scripts/deploy` ni `scripts/e2e` (section 7) | avec CT-4 |
| Les vecteurs `spec/vecteurs/ct-4` (annexe A), leurs tests, l'intégration continue | avec CT-4 |
| Le vérificateur Go indépendant `spec/vecteurs/ct-4/verificateur-independant` | avec CT-4 |
| L'instance de production et ses premiers validateurs partenaires | après le pilote (décision ouverte 6, section 13) |
| Un mode observateur de noorcore | non livré (décision ouverte 7, section 13) |

Relations avec les autres spécifications :

| Spécification | Ce que CT-4 lui fournit | Ce que CT-4 en attend |
|---|---|---|
| CT-1 | La dérivation de `org_id` et `journal_id` (6.2, 6.3), le `docType` des ancres (6.4) ; l'inscription et la révocation des clés que la règle 5 de CT-1 §8 lui renvoie (sections 7 et 8) ; la capture des parties `registre.json`, `certificat-commit.json` et `validateurs.json` (section 9) ; la `source` « registre CT-4 » de `cles.json` (CT-1 §11.2). Aucun format n'est changé. | `org_id` et `journal_id` opaques (§3) ; la correspondance du manifeste avec `PeriodMeta` (§10.4) ; `periodHash` (§10.2) et `anchorFingerprint` (§10.4), tels quels |
| CT-2 | Les adresses et identifiants de l'instance (4.8, section 7) ; l'encodage exact des appels et des transactions (6.7) ; la règle de frais et la provision de la clé de chaîne (4.5) ; la conduite d'envoi, de reprise et de rotation (section 8) ; la capture (section 9) | La clé publique, ses métadonnées et sa preuve d'origine (CT-2 EX-11.13) ; une clé de chaîne par clé Ed25519, qui signe les ancres et relaie les clôtures, et l'ordre des rotations (CT-2 EX-11.19, EX-11.15, EX-11.16) ; la révocation comme acte du registre (CT-2 EX-11.14) ; un registre jamais bloquant (§14.2) ; `anchoring.registry` (§15) |
| CT-3 | Le modèle d'administration du `CuratorSetRegistry` et des `CuratorSet` (5.5) ; les événements qu'il sonde et leurs sujets (5.7) ; la conduite d'un changement de jeu (section 8) ; le point RPC à interroger (section 10) | La lecture du jeu à une hauteur, le sondage et l'épinglage (CT-3 EX-8.1, EX-8.5 à EX-8.7) ; une personne par clé de jeu (CT-3 EX-8.11) |
| CT-5 | La troisième ancre de l'architecture, celle du registre, indépendante des deux siennes : CT-5 ancre `periodHash`, CT-4 ancre `keccak256(org_id ‖ journal_id ‖ periodHash)` (6.5) | — |
| CT-6 | Le manifeste d'instance (4.8), d'où le réviseur dérive l'ancre `registry` de son fichier d'ancres après recoupement (RG-20, CT-6 §12.5) ; la capture exigée par CT-6 EX-13.8 à EX-13.11, reprise comme exigence propre (section 9) ; ce que la substitution de la chaîne changerait pour le contrôle 8 (section 11), sans changer CT-6 dans cette version | Les formats de §11.2, R-1 à R-10 et N-4, inchangés ; les hypothèses H6 et H7 (§3.5) |
| CT-7 | L'inventaire des clés du registre (3.1) et leurs menaces (3.5, section 12) | Les cérémonies et la garde de ces clés |
| CT-8 | L'image, les topologies, les ports et les volumes (section 10) ; les seuils de provision à surveiller (4.5) ; la rétention à tenir (section 9) | La supervision, la sauvegarde des bases des validateurs, la publication des manifestes |
| CT-9 | Les identifiants EX- et RG-, les vecteurs `spec/vecteurs/ct-4` (annexe A) ; l'épreuve d'acceptation : un relecteur qui n'a que la spécification crée un client, ancre une racine et clôt une période sur le réseau de développement | Les tests |

## 2. Terminologie

Les termes de CT-1 §2 (journal, manifeste, racine, dossier, approbateur), de
CT-2 §2 (enregistreur, clé de chaîne), de CT-3 §2 (administrateur du jeu,
administrateur du registre, jeu épinglé) et de CT-6 §2 (réviseur, fichier
d'ancres, registre, certificat de commit, jeu de validateurs, quorum)
gardent leur sens. S'y ajoutent :

| Terme | Définition |
|---|---|
| Instance | Un réseau noorcore en mode BFT : un document de genèse, un identifiant BFT, un identifiant EVM, une suite de jeux de validateurs, une version de noorcore et les contrats de la section 5 ; son manifeste la décrit (4.8). |
| Instance de production | L'instance d'après le pilote ; son identifiant et ses premiers validateurs partenaires sont la décision ouverte 6. |
| Exploitant | NOORTRACE : il crée l'instance, déploie les contrats, tient la trésorerie et l'administration du registre, publie le manifeste. |
| Opérateur de validateur | L'organisation qui exploite un validateur et détient seule sa clé : l'exploitant ou un partenaire. |
| Validateur partenaire | Validateur opéré par un autre que l'exploitant : intégrateur, cabinet d'audit, client. |
| Domaine de panne | Ensemble de validateurs qu'une même cause peut rendre fautifs ensemble : un opérateur, un site (4.4). |
| Ligne de règles | Chaîne canonique des règles de consensus que le nœud compare au document de genèse avant de démarrer (4.2). |
| Manifeste d'instance | Le document `instance-registre-v0` que l'exploitant publie (4.8). |
| Client | Une organisation inscrite : un `org_id`, un `CuratorSet` assigné, un ou plusieurs journaux. |
| Slug | Identifiant textuel d'une organisation, préimage de `org_id` (6.2). |
| Nom de journal | Préimage de `journal_id` (6.3). |
| Clé de gouvernance | Clé secp256k1 de l'organisation qui administre son `CuratorSet` (5.5) ; sans NUR, elle agit par opérations signées que d'autres relaient. |
| Expéditeur | Compte qui signe une transaction EVM et en paie le gaz. |
| Relayeur | Expéditeur d'une transaction qui porte les signatures d'autres clés ; il ne détient aucune autorité (EX-3.3). |
| NUR | Unité native de l'instance. Sans valeur ni échange, elle ne sert qu'à payer le gaz (4.5). |
| Trésorerie | Compte de genèse qui détient l'offre de NUR et approvisionne les expéditeurs. |
| Provision | Solde de NUR attribué à un expéditeur : son quota d'écriture (4.5). |
| Condensé interne | Valeur de 32 octets que rendent `periodDigest`, `registerDigest`, `revokeDigest`, `anchorDigest` et `adminOpDigest`, avant le préfixe EIP-191 (6.6). |
| Hachage signé | `keccak256("\x19Ethereum Signed Message:\n32" ‖ condensé interne)`, ce que la clé signe (6.6). |
| Étiquette | Chaîne ASCII qui sépare les domaines des condensés internes : `noortrace-periode`, `noor-attestation-ancre`… (6.6). |
| `docType` | Type d'un document ancré dans `AttestationRegistry`, 32 octets (6.4). |
| Empreinte d'ancre | `anchorFingerprint` de CT-1 §10.4 : ce que `AttestationRegistry` ancre pour une période (6.5). |
| Relais RPC | Nœud noorcore en mode suiveur (`-role follower -follow-rpc`) : mandataire JSON-RPC devant un validateur, sans bloc, sans état, sans certificat (`chain/docker/README.md:377-407`). |
| Point RPC de validateur | Interface JSON-RPC qu'un validateur sert depuis sa propre base. |

## 3. Modèle

### 3.1 Rôles

| Rôle | Qui | Détient | Fait | Confiance |
|---|---|---|---|---|
| Exploitant | NOORTRACE | La trésorerie, la clé du déployeur, la clé de l'administrateur du registre ; au plus f validateurs en production (EX-4.12) | Crée l'instance (4.2), déploie les contrats (5.2), assigne un jeu à chaque organisation (`setCuratorSet`), approvisionne les expéditeurs (4.5), publie le manifeste (4.8) | Adversaire « fournisseur » de CT-6 §3.4 : rien de ce qu'il sert n'est cru sans certificat |
| Opérateur de validateur | L'exploitant ou un partenaire | Sa clé de validateur secp256k1, la base de son nœud, ses certificats de commit | Propose, vote, garde les certificats (300 000 hauteurs par défaut, R1-F16), sert le RPC à qui il admet | Individuellement non fiable ; au plus f fautifs par jeu (hypothèse H6 de CT-6) |
| Client | L'organisation | Son `org_id`, son jeu d'approbateurs, sa clé de gouvernance, son enregistreur | Demande son inscription (section 7), fait signer ses inscriptions de clés et ses clôtures | Maître de ses propres écritures, sans effet sur celles des autres (3.5) |
| Approbateurs | Membres du `CuratorSet` de l'organisation (CT-3 EX-8.11 : une personne par clé) | Chacun sa clé secp256k1, sans NUR | Signent hors chaîne, au seuil, les condensés internes d'inscription, de révocation et de clôture (6.6) | Individuellement non fiables ; il faut le seuil |
| Administrateur du jeu | La clé de gouvernance de l'organisation (5.5) | La clé `admin` du `CuratorSet` | Ajoute et retire des membres, fixe le seuil, transmet l'administration, par opérations signées (6.6) | Ses changements sont publics (5.7) |
| Enregistreur | Composant chez le client (CT-2) | Sa clé Ed25519, qui signe les événements ; sa clé de chaîne, qui signe les ancres et relaie les clôtures (CT-2 EX-11.19) | Remet la clé publique à inscrire, signe l'ancre de chaque période, relaie sa clôture | Compromis possible : borné par le seuil, la révocation et la provision (3.5) |
| Relayeur | Tout expéditeur approvisionné : clé de chaîne, relayeur de l'exploitant | Une provision de NUR | Envoie une transaction qui porte les signatures d'autres clés | Aucune autorité (EX-3.3) |
| Relais RPC | Suiveur noorcore chez un client | Rien de la chaîne | Relaie au validateur qu'il suit ; répond `eth_chainId` depuis son drapeau (`chain/docker/README.md:186-187`) | Aucune : il n'ajoute ni disponibilité ni vérification (`chain/docker/README.md:395-407`) |
| Réviseur | Celui qui vérifie un dossier (CT-6) | Son fichier d'ancres | Recoupe le manifeste (4.8) et en tire l'ancre `registry` (RG-20) | Il ne croit que ses ancres |

**EX-3.1** Sur une instance de production, l'exploitant DOIT tenir des clés
distinctes pour la trésorerie, le déploiement, l'administration du registre
et, s'il relaie, le relais ; aucune n'est une clé de validateur, une clé
d'approbateur ou une clé de chaîne, et aucune n'est employée sur une autre
chaîne (EX-4.8). Sur le réseau de développement, le compte Hardhat 0 tient
ces quatre rôles (`chain/README.md:263-278`).

### 3.2 Flux

1. **Instance.** L'exploitant écrit le document de genèse (4.2), réunit les
   opérateurs de validateurs et leur `validators.json` (4.4), démarre les
   validateurs, déploie les quatre contrats de l'instance (5.2), capture les
   preuves des blocs de déploiement et publie le manifeste (4.8).
2. **Inscription d'un client** (section 7). L'exploitant tire le slug
   (6.2), déploie le `CuratorSet` de l'organisation avec sa clé de
   gouvernance pour administrateur (5.5), l'assigne (`setCuratorSet`) et
   approvisionne la clé de chaîne de l'enregistreur (4.5), qui relaie par
   défaut sa propre inscription (7.7) ; puis les approbateurs signent
   `registerDigest` pour la clé de l'enregistreur et sa clé de chaîne, et
   l'inscription est relayée.
3. **Chaque période** (CT-1 §9 et §10). L'enregistreur clôt le manifeste et
   en tire `periodHash` ; la clé de chaîne signe `anchorDigest` de
   l'empreinte d'ancre et envoie `anchor` ; les approbateurs signent
   `periodDigest` au seuil et la clé de chaîne envoie `submitPeriod`
   (CT-2 EX-11.19). La façon de recueillir les signatures de clôture et
   l'ordre de ces envois sont fixés en section 8.
4. **Capture** (section 9). Dès chaque reçu, l'en-tête, tous les reçus du
   bloc et le certificat de commit sont capturés auprès d'un validateur
   (CT-6 EX-13.8).
5. **Rotation et révocation** (section 8). Nouvelle paire inscrite, ancienne
   clé de chaîne révoquée, dans l'ordre de CT-2 EX-11.19.
6. **Vérification** (CT-6). Le réviseur prend ses ancres dans le manifeste
   après recoupement et exécute le contrôle 8 hors ligne.

### 3.3 Ce qui est signé

| Objet | Signé par | Forme | Vérifié par |
|---|---|---|---|
| `periodDigest(meta)` | Les approbateurs, au seuil du jeu de `meta.orgId` | EIP-191, signature secp256k1 canonique (6.6) | `PeriodRegistry` (`ThresholdSignatures`), à la transaction |
| `registerDigest`, `revokeDigest` de `RecorderRegistry` | Les approbateurs, au seuil | idem | `RecorderRegistry`, à la transaction |
| `anchorDigest`, `revokeDigest` d'`AttestationRegistry` | L'émetteur : la clé de chaîne de l'enregistreur | EIP-191 | `AttestationRegistry` ; le contrôle 8 rattache l'émetteur à la clé du manifeste (R-10, N-4) |
| `adminOpDigest` | L'administrateur du `CuratorSet`, ou l'administrateur en attente pour `acceptAdminSigned` | EIP-191, nonce séquentiel | `CuratorSet` |
| `setCuratorSet`, `proposeAdmin`, `acceptAdmin` et les opérations directes d'un `CuratorSet` | Personne : `msg.sender` doit être l'administrateur | Transaction de l'administrateur | Le contrat |
| Transaction EVM | Son expéditeur | Type 2 (EIP-1559), identifiant EVM dans la charge signée (6.7.3) | noorcore |
| Proposition et precommits d'un bloc | Les validateurs | Enveloppe BFT (CT-6 EX-11.7) | Les validateurs ; le vérificateur (R-5) |
| Manifeste d'instance | Personne en version 0 ; chaque révision engage la précédente par son SHA-256 (RG-16) | — | Le réviseur, par recoupement (CT-6 §12.5) |

**EX-3.2** Aucun outil, document ni énoncé de CT-4 NE DOIT tirer une date du
registre autrement que comme heure déclarée : `publishedAt`, `issuedAt`,
`registeredAt`, `revokedAt` et l'horodatage d'un bloc sont l'horloge du
proposant, que les validateurs bornent sans la prouver (CT-6 EX-11.18). Les
dates d'un dossier viennent de CT-5.

**EX-3.3** Le relayeur ne détient aucune autorité : ce qu'un contrat du
registre autorise l'est par une signature sur un condensé interne (6.6) ou
par `msg.sender` égal à un administrateur (5.4)
(`contracts/ThresholdSignatures.sol:31-35`). Aucun outil de CT-4 ne fait
dépendre une décision de l'identité du relayeur, et un relayeur NE DOIT PAS
modifier les champs signés qu'il transporte : il les relaie tels qu'ils ont
été signés ou il ne relaie pas.

### 3.4 Ce que le registre prouve et ne prouve pas

Ce que prouve le registre est ce que le contrôle 8 de CT-6 en établit,
hors ligne, contre le jeu de validateurs du réviseur ; rien n'est lu comme un
avis du nœud (CT-6 §11.1).

| Fait | Établi par | Sous | Ce qui reste déclaratif ou hors de portée |
|---|---|---|---|
| La clôture de la période (`PeriodSubmitted`) figure dans un bloc signé par un quorum du jeu du réviseur | R-2, R-4 à R-9 | H6, H7 | L'heure : `publishedAt` est l'horodatage du bloc (EX-3.2) |
| Au bloc de la clôture, le contrat a vérifié le seuil du jeu assigné à l'organisation et la continuité du journal | Conditions d'émission de `PeriodSubmitted` (`contracts/PeriodRegistry.sol:176-205`) | H7 | Que ce jeu fût le jeu légitime de l'organisation : l'administrateur du registre l'assigne (5.5, 3.5) ; CT-3 §8.5 |
| L'ancre de la période, signée par la clé de chaîne (`Anchored`) | R-8, R-9, N-4 | H6, H7 | — |
| La clé Ed25519 du manifeste est inscrite sous la clé de chaîne émettrice de l'ancre | R-10 | H6, H7 | Sa non-révocation : un fait d'état (CT-6 §11.8) |
| Une seule clôture par `periodHash` et par organisation ; une seule ancre par empreinte sur toute la chaîne | Le code des contrats (`contracts/PeriodRegistry.sol:193`, `contracts/AttestationRegistry.sol:62`) | H7 | L'absence d'une autre clôture ou d'une autre ancre ne se prouve pas (CT-6 §11.8) |

Le registre ne prouve pas : le contenu d'un événement (CT-1) ; une date
(EX-3.2) ; la légitimité du jeu de validateurs, que le réviseur déclare ; le
code aux adresses des contrats (H7, non vérifié par CT-6) ; un fait d'état
(appartenance au `CuratorSet`, non-révocation, dernière période) ;
l'identité du client derrière un `org_id` ; quoi que ce soit contre une
coalition d'au moins un quorum de validateurs. Au-delà de f validateurs
fautifs, deux certificats contradictoires d'une même hauteur peuvent exister
(R2-F47) : la règle d'EX-4.12 sur les domaines de panne fait tenir H6 contre
l'exploitant lui-même. Le registre reste un composant d'exploitation
substituable (`contracts/PeriodRegistry.sol:18-22`, architecture « Instance
dédiée ») ; la section 11 dit quand il serait remplacé.

### 3.5 Adversaires

| Adversaire | Ce qu'on lui suppose | Ce que CT-4 empêche ou rend visible | Ce qui reste possible |
|---|---|---|---|
| **Exploitant** | Il tient la trésorerie, le déployeur et l'administration du registre, sert le RPC, publie le manifeste ; en développement il opère tous les validateurs, en production au plus f (EX-4.12). | Signer de faux blocs : il lui faudrait un quorum. Réécrire une période ou une inscription enregistrée : aucune fonction ne le permet (5.4). Changer le manifeste sans trace : révisions chaînées et publiées (EX-4.25). Faire décider un ticket de CT-3 par un jeu réassigné : épinglage (CT-3 EX-8.6). | Réassigner le jeu d'une organisation à un jeu qu'il contrôle, puis inscrire des clés et soumettre les clôtures suivantes de ses journaux : les contrats lisent le jeu à la transaction (`contracts/PeriodRegistry.sol:275-281`, `contracts/RecorderRegistry.sol:202-208`) ; `setCuratorSet` accepte toute adresse non nulle, même un compte externe ou un contrat qui n'est pas un `CuratorSet` (`contracts/CuratorSetRegistry.sol:76-84`), ce qui rend l'organisation inopérante ; `submitPeriod` n'exige ni ancre préalable ni clé inscrite, seulement le seuil du jeu lu à la transaction (`contracts/PeriodRegistry.sol:205`, `:275-281`) : une clôture à `periodEnd` = 2^64 − 2 sous un jeu réassigné rend le journal inachevable. C'est public (`CuratorSetAssigned`), le client le surveille (section 8) et `reassigner` ne part qu'avec une demande écrite et un jeu administré par la même clé de gouvernance (EX-8.10). Refuser les provisions ou ne pas inclure les transactions qu'il reçoit : le registre s'arrête pour ce client sans bloquer l'enregistreur (CT-2 §14.2). |
| **Validateurs fautifs, au plus f** | Ils signent n'importe quoi. | Un certificat sans quorum. | Retarder ou censurer les transactions qu'on leur soumet, puisque chacune n'est incluse qu'au tour du validateur qui l'a reçue (EX-4.14) ; arrêter la chaîne si f + 1 d'entre eux s'arrêtent (4.4). |
| **Client** | Il tient sa clé de chaîne, ses approbateurs, sa clé de gouvernance. | Écrire pour une autre organisation : chaque condensé lie `org_id` (6.6), l'unicité de `periodHash` est cloisonnée par organisation (`contracts/PeriodRegistry.sol:34-38`). | Inscrire ses propres clés et clore ses propres périodes : c'est son droit. Ancrer une empreinte quelconque (`AttestationRegistry` est commun à la chaîne) ; il ne peut occuper l'empreinte d'un autre qu'en connaissant son `periodHash` avant l'inclusion. |
| **Clé de chaîne compromise** | Un attaquant signe des ancres sous elle et dépense sa provision. | Une clôture sans le seuil des approbateurs ; une consommation au-delà de la provision (EX-4.20). | Des ancres d'empreintes qui ne correspondent à aucun manifeste ; l'occupation d'empreintes de son organisation ; jusqu'à la révocation (CT-2 EX-11.14), qui n'atteint ni le solde restant ni `anchor` (8.4). Disperser sa provision vers des adresses neuves, que rien ne révoque (noorcore n'a aucune liste d'expéditeurs, R1-F26) : la borne en gaz d'EX-4.20 tient (les wei se conservent), la cadence d'une transaction par expéditeur et par bloc (EX-4.14) et l'examen d'EX-8.18 ne tiennent plus (section 12). |
| **Approbateurs au seuil, de connivence** | Ils signent ce qu'ils veulent. | — | Inscrire une clé, clore une période de leur organisation : attribuable, signé. Une clôture frauduleuse (`periodEnd` = 2^64 − 2, ou toute clôture hors de la suite légitime) rend le journal définitivement inachevable : `PeriodRegistry` exige `periodStart` égal au `periodEnd` précédent et `periodEnd` < 2^64 − 1 (`contracts/PeriodRegistry.sol:179-181`, `:195-203`), et aucune correction n'existe sur la chaîne (7.11) ; seule issue : un nouveau nom de journal (EX-6.4) et les dossiers postérieurs sans contrôle 8. |
| **Clé de gouvernance compromise** | Il tient la clé qui administre le `CuratorSet` ; il lui faut en outre un expéditeur approvisionné (clé de chaîne du client ou relayeur de l'exploitant, EX-4.19, EX-5.7) et un accès RPC en écriture (EX-10.3). | Rien sur la chaîne : `addCuratorSigned` puis `setThresholdSigned(1)` prennent effet dès l'inclusion (`contracts/CuratorSet.sol:109-135`) ; le relais de l'exploitant n'est fait que sur confirmation hors bande du client (EX-8.21). | Prendre le jeu en deux blocs, inscrire sa clé de chaîne, clore une période frauduleuse : même conséquence que la ligne précédente (journal abandonné, réassignation sur demande du client, EX-8.10, nouveau nom de journal). Le client le voit en sondant les événements de son jeu et de ses journaux (EX-8.12). |
| **Expéditeur sans solde qui atteint un point RPC en écriture** : client authentifié mais compromis, poste qui atteint le relais RPC d'un client (10.3), tiers | Il envoie des transactions signées par des adresses vides. | Une écriture sans provision : écartée sans reçu (R1-F30). | Remplir la mempool d'un validateur (5 120 places) de transactions sans solde jamais prêtes, et y fermer l'accès aux transactions à 1 wei (EX-4.20) : en production, la garde d'admission d'EX-10.8 refuse toute transaction dont l'expéditeur n'a pas le solde et dont le nonce n'est pas celui de l'état, par client authentifié et sous quota. |
| **Point RPC ou relais RPC menteur** | Il sert un état, des reçus ou un identifiant de chaîne faux. | Un bloc ou un reçu faux dans un dossier : le contrôle 8 recalcule tout contre le jeu du réviseur. Une écriture sur une autre chaîne : EX-4.9. | Des lectures d'état fausses : noorcore ne sert pas de preuve d'état (CT-3 EX-8.2) ; d'où les lectures par un validateur que l'on croit (section 10). |
| **Rejeu** | Il rejoue une signature ou une transaction ailleurs. | Entre organisations, registres et opérations : `org_id`, adresse, étiquette et identifiant EVM dans chaque condensé (6.6). Entre chaînes : transactions de type 2 seulement, clés propres à l'instance (EX-4.8). | Sur une chaîne de même identifiant EVM où le même déployeur aurait les mêmes nonces : seulement pour le réseau de développement, dont l'identifiant et le déployeur sont publics (EX-4.7). |

La section 12 reprend ces menaces une à une avec leurs parades
d'exploitation.

## 4. Instance

### 4.1 Composition

Une instance se compose d'un document de genèse et de sa ligne de règles
(4.2), d'un identifiant BFT et d'un identifiant EVM (4.3), d'une suite de
jeux de validateurs (4.4), d'une règle de frais (4.5), d'une version de
noorcore et de ses correctifs (4.6, 4.7), des quatre contrats de
l'instance (section 5) et d'un manifeste qui décrit le tout (4.8).

| | Réseau de développement | Instance de production |
|---|---|---|
| Identifiants | `noortrace-2124-dev`, EVM 2124 (`0x84c`) (`chain/README.md:35-44`) | Décision ouverte 6 (critères : EX-4.6, EX-4.7) |
| Genèse | `chain/config/alloc-dev.json` : quatre comptes Hardhat de 1 NUR, section `rules` sans émission (`chain/config/alloc-dev.json:1-19`) | Trésorerie seule (EX-4.5) |
| Validateurs | Quatre, sur une seule machine, clés générées localement par `dev-net.sh` (`chain/scripts/dev-net.sh:99-124`) | Au moins quatre, au plus f par opérateur et par site (EX-4.12) |
| Profil réseau | `dev` (`chain/README.md:280-290`) | `prod-like`, authentification et TLS p2p (`chain/README.md:292-321`, section 10) |

**EX-4.1** Un client, un outil ou un réviseur désigne une instance par le
triplet (`bft_chain_id`, `evm_chain_id`, `genesis.sha256`) de son manifeste,
jamais par l'identifiant EVM seul : l'unicité de celui-ci ne tient qu'à une
convention de registre public (R2-F6), et l'identifiant BFT est celui que
signe chaque validateur (CT-6 EX-11.7).

### 4.2 Genèse

Le document de genèse a la forme `{ "chainId", "alloc": [ { "address",
"balanceWei" } ], "rules" }` : `chainId` entier EVM non nul, `balanceWei` en
décimal, `alloc` non vide, adresses valides et distinctes ; un document qui
manque à l'une de ces règles est refusé au chargement (R1-F2). Les soldes de
genèse s'appliquent une fois par répertoire de données (R1-F3). Au démarrage
en mode BFT, le nœud contrôle dans cet ordre : fichier de validateurs et
identifiant présent dans le jeu, jeu d'au moins quatre validateurs ; base ;
garde des règles de genèse ; ancre des paramètres d'émission ; tête et
hauteur finalisée ; état EVM ; journal durable des transactions (R1-F5).

**EX-4.2** Le document de genèse d'une instance DOIT porter la section
`rules` avec exactement : `chainId` égal à l'identifiant BFT ; `possEnabled`
`false` ; `possRewards` `"0x0000000000000000000000000000000000000000"` ;
`possCapWei` `"0"` ; `possGenesisUnix`, `possHalvingSec` et
`possSubperiodSec` `0` ; `possEmissionModel` `"noormint/v1"`
(`chain/README.md:132-148`). Sans section `rules`, le nœud ne vérifie rien
et le dit seulement dans son journal (R1-F4) : un tel document n'est pas
admis. Aucune émission n'existe donc sur une instance, et aucune ne peut y
être ajoutée sans changer la ligne de règles, ce que le nœud refuse
(R1-F6).

**EX-4.3** La **ligne de règles** d'un document de genèse est la chaîne
ASCII :

```text
chainId=<rules.chainId> evmChainId=<chainId> possEnabled=<rules.possEnabled> possRewards=<rules.possRewards> possCapWei=<rules.possCapWei> possGenesisUnix=<rules.possGenesisUnix> possHalvingSec=<rules.possHalvingSec> possSubperiodSec=<rules.possSubperiodSec> possEmissionModel=<rules.possEmissionModel>
```

champs séparés par une espace, entiers en décimal sans zéro de tête,
booléens `true` ou `false`, chaînes telles quelles. C'est la ligne que le
nœud compare, par égalité de chaînes, à sa propre ligne de règles, et qu'il
journalise après `genesis rules: verified against <fichier> | ` ; tout écart
refuse le démarrage (R1-F4, R1-F7, `chain/README.md:150-163`). Comme
`evmChainId` vient du `chainId` de tête, un document dont le `chainId` diffère
de `-evm-chain-id` refuse aussi le démarrage (R1-F4). Pour le réseau de
développement (RG-17) :

```text
chainId=noortrace-2124-dev evmChainId=2124 possEnabled=false possRewards=0x0000000000000000000000000000000000000000 possCapWei=0 possGenesisUnix=0 possHalvingSec=0 possSubperiodSec=0 possEmissionModel=noormint/v1
```

**EX-4.4** Chaque validateur d'une instance DOIT démarrer avec le document de
genèse du manifeste (même SHA-256), avec `-chain-id` et `-evm-chain-id`
explicites, et sans les variables `NOOR_POSS_*` ni
`NOOR_ACCEPT_NEW_EMISSION_PARAMS` dans son environnement
(`chain/scripts/dev-net.sh:58-66`, R1-F6). Son opérateur DOIT constater, à
chaque mise en service, la ligne `genesis rules: verified against … |`
suivie de la ligne de règles du manifeste, puis `emission params: anchored`
au premier démarrage ou `emission params: verified against anchor` aux
suivants (`chain/README.md:150-163`). Un écart arrête la mise en service.

**EX-4.5** Sur une instance de production, le document de genèse ne
précharge qu'un compte, la trésorerie, dont la clé est créée pour cette
instance et gardée par l'exploitant (`chain/README.md:276-278`, EX-3.1),
avec au moins 10^18 wei (1 NUR). Le total de `alloc` est l'offre définitive
de l'instance : sans émission, elle ne fait que baisser (4.5). Le réseau de
développement précharge les quatre premiers comptes Hardhat, dont les clés
sont publiques (`chain/config/alloc-dev.json:3-8`, `chain/README.md:263-278`).

### 4.3 Identifiants

| Identifiant | Où il est lié | Réseau de développement |
|---|---|---|
| EVM (`eth_chainId`, `-evm-chain-id`) | Charge signée de chaque transaction (6.7.3) ; `block.chainid` de chaque condensé interne (6.6) ; `approver_set.chain_id` des politiques de CT-3 (CT-3 EX-8.1) | 2124 (`0x84c`) |
| BFT (`-chain-id`, `rules.chainId`) | Chaque enveloppe signée par un validateur (CT-6 EX-11.7) ; la ligne de règles (EX-4.3) ; `registry.chain_id` du fichier d'ancres, comparé par R-4 | `noortrace-2124-dev` |

Le binaire, lancé sans ces drapeaux, prend l'identifiant EVM 2121 et
l'identifiant BFT `noorchain-2-1-local` (R1-F8).

**EX-4.6** L'identifiant BFT d'une instance a la forme
`noortrace-<n>-<suffixe>`, où `<n>` est l'identifiant EVM en décimal sans
zéro de tête et `<suffixe>` compte de 1 à 16 caractères `[a-z0-9]` (`dev`
pour le développement). Les deux identifiants d'une instance sont fixés avant
la première genèse et ne changent plus : ils entrent dans la ligne de règles,
ancrée au premier démarrage (`chain/README.md:319-321`).

**EX-4.7** L'identifiant EVM 2124 est inscrit dans le registre public
`ethereum-lists/chains` pour « Metaplayerone Dubai Testnet » depuis le
2023-04-23 (R2-F8) ; ce registre attribue un identifiant au premier qui le
demande, ne le réattribue qu'après dépréciation et ne supprime jamais une
entrée (R2-F6). 2124 reste l'identifiant du réseau de développement
(décision déjà prise, `chain/README.md:35-44`) avec le statut
`attribue_a_un_tiers` dans le manifeste : seuls les portefeuilles et outils
qui lisent ce registre en sont affectés, et le rejeu entre les deux chaînes
ne concerne que des clés publiques (EX-4.8). L'identifiant EVM d'une
instance de production DOIT être absent de ce registre quand il est choisi,
compris entre 1 et 2^31 − 1 (R2-F5), différent de 2121 à 2124 (que les
documents du dépôt attribuent à NOORCHAIN ou au développement), et inscrit
dans ce registre avant la première genèse, avec le statut `inscrit` dans le
manifeste (R2-F6, R2-F7). Le choix de la valeur est la décision ouverte 6.

**EX-4.8** Un outil de CT-4 ou un enregistreur ne signe que des
transactions de type 2 (6.7.3), dont la charge signée porte l'identifiant
EVM ; jamais une transaction de type 0 non protégée, que noorcore accepte et
inclut (R1-F33) et qui se rejoue sur toute chaîne où la clé a le même nonce.
Les clés d'une instance de production (trésorerie, déployeur,
administrateur du registre, relayeur, clés de chaîne) NE DOIVENT signer
aucune transaction sur une autre chaîne : l'adresse d'un contrat dérive du
déployeur et de son nonce (RG-19), et un condensé interne n'est unique que
si le couple (identifiant EVM, adresse du contrat) l'est.

**EX-4.9** Avant toute écriture, un outil vérifie que le point RPC sert
l'instance du manifeste : `eth_chainId` égal à `evm_chain_id`, code non
vide aux adresses des contrats en service (`eth_getCode`), et, quand le
manifeste le donne, `eth_getBlockByNumber` du bloc de déploiement
d'`AttestationRegistry` de hachage égal à son `block_hash`. Un relais RPC
répond `eth_chainId` depuis son drapeau et peut donc mentir
(`chain/docker/README.md:271-277`) ; un fichier de déploiement copié d'un
autre nœud ou survivant à une réinitialisation désignerait une autre chaîne
(`scripts/lib/noortrace.mjs:348-354`, `ensureDeployment`). Un écart arrête
l'outil.

### 4.4 Validateurs et quorum

Le jeu de validateurs est le fichier `validators.json`,
`{ "validators": [ { "id", "pubKeyHex" } ] }`, que chaque validateur charge
puis trie par identifiant ; en chargement de production, les clés sont non
vides, exploitables et distinctes (R1-F9). Les clés du réseau de
développement sont des clés secp256k1 non compressées de 65 octets générées
une fois par `dev-net.sh` (`chain/scripts/dev-net.sh:99-124`). Le nœud refuse
un jeu de moins de quatre validateurs (R1-F5). Le quorum est
`⌊(N + f) / 2⌋ + 1` avec `f = ⌊(N − 1) / 3⌋` (R1-F10, CT-6 EX-11.8) ; le
proposant de la hauteur `h` au tour `r` est le validateur d'indice
`(h + r) mod N` dans l'ordre trié (R1-F12) ; les délais de proposition, de
prevote et de precommit valent 2 s au tour 0 et doublent à chaque tour
jusqu'à 32 fois (R1-F11).

| N | f | Quorum | Validateurs arrêtés qui arrêtent la chaîne |
|---|---|---|---|
| 4 | 1 | 3 | 2 |
| 5 | 1 | 4 | 2 |
| 7 | 2 | 5 | 3 |
| 10 | 3 | 7 | 4 |

Mesures du réseau de développement : 1,10 bloc par seconde le 2026-10-25
(R1-F13), 1,14 le 2026-10-21 (`chain/README.md:219`) ; limite de gaz par
bloc 30 000 000 et plafond EIP-7825 de 16 777 216 gaz par transaction
(R1-F14).

**EX-4.10** Le jeu de validateurs d'une instance est publié dans le manifeste
octet pour octet tel que les validateurs le chargent
(`validator_sets[].validators`), avec son hachage (RG-18) : les clés ne sont
jamais réencodées, parce que le hachage du jeu porte sur les octets tels que
déclarés (CT-6 EX-11.8).

**EX-4.11** Tout jeu compte au moins quatre validateurs. La tolérance
byzantine exige `N ≥ 3f + 1` même avec des messages signés, en synchronie
partielle (R2-F42, R2-F44, R2-F45) ; c'est ce que la formule du quorum
suppose.

**EX-4.12** Sur une instance de production, aucun opérateur et aucun site ne
DOIT porter plus de f validateurs d'un jeu ; l'exploitant en porte au plus f.
La sûreté du consensus suppose des défaillances indépendantes, donc des
opérateurs et des administrateurs distincts (R2-F43) ; avec quatre
validateurs sur deux sites, la perte d'un site arrête la chaîne
(`chain/README.md:308-310`). Avec N = 4, l'exploitant opère un validateur et
trois partenaires un chacun ; avec N = 7, quatre opérateurs au moins, deux
validateurs au plus chacun. Chaque clé de validateur est créée sur son site
et n'en sort jamais, seule la clé publique circule
(`chain/README.md:298-299`) ; elle n'a qu'un signataire actif à la fois, deux
instances actives d'un KMS ne protégeant plus de la double signature
(R2-F49) ; cérémonie : CT-7. Sa garde en HSM ou en KMS (R2-F46, R2-F49,
R2-F50) est l'état visé : noorcore, au commit épinglé, ne lit la clé que dans
un fichier, et la version 0 s'en tient à EX-10.7 (section 14). Le réseau de
développement ne donne aucune de ces garanties.

**EX-4.13** En version 0, le jeu de validateurs d'une instance est fixe pour
toute sa vie. noorcore, au commit épinglé, refuse de reprendre le consensus
quand le hachage du jeu chargé diffère de celui de l'état de consensus
persisté, et laisse la réconciliation à l'opérateur (code de noorcore,
`core/consensus/state.go:184-190`, `core/node/node.go:2174-2196`, lus pour
cette spécification) ; aucune procédure de changement de jeu sur une chaîne
en service n'est établie (non vérifié). Un changement de jeu, remplacement
d'une clé compromise compris, passe donc par une nouvelle instance, avec une
nouvelle genèse et de nouveaux identifiants (EX-4.6, 9.7), ou par une
procédure à établir dans une version suivante (section 14). Le
manifeste admet plusieurs jeux, avec leurs hauteurs de validité, pour suivre
le format de CT-6 (§11.2.3, §12.2).

**EX-4.14** Un bloc est final quand son certificat de commit porte un quorum
vérifié (CT-6 R-5). Les étiquettes `finalized` et `safe` de
`eth_getBlockByNumber` rendent la tête, et la « hauteur finalisée » interne
du nœud vaut tête − 64 (R1-F15) : aucun outil de CT-4 ne s'appuie sur l'une
ou l'autre. Les validateurs ne se relaient pas les transactions : une
transaction n'est incluse qu'au tour de proposition du validateur qui l'a
reçue, au plus 64 par bloc et une seule par expéditeur (R1-F37, R1-F38) ; la
section 8 en tire la conduite d'envoi.

### 4.5 Frais sans jeton échangeable

Ce que fait noorcore au commit épinglé :

- le prix minimal de la mempool vaut 1 et ne peut pas être abaissé ; un prix
  nul est refusé à l'entrée, `-32000 "transaction underpriced"`, en type 0,
  1 et 2 (R1-F20, R1-F21, R1-F27) ;
- à l'exécution, le prix de base est fixé à 1 wei ; le prix effectif d'une
  transaction de type 2 vaut `min(maxFeePerGas, maxPriorityFeePerGas + 1)` ;
  l'expéditeur est débité de `gasUsed × prix effectif`, l'adresse nulle est
  créditée de `gasUsed × (prix effectif − 1)` et la part du prix de base ne
  l'est à personne (R1-F23, R1-F28) ; aucune liste d'expéditeurs
  autorisés, aucune exemption n'existe (R1-F26) ;
- `eth_sendRawTransaction` ne contrôle ni le solde, ni le plafond, ni la
  limite de gaz par transaction (R1-F22) ; une transaction dont l'application
  échoue, faute d'un solde au moins égal à `gasLimit × maxFeePerGas + value`
  (go-ethereum v1.17.0, `core/state_transition.go:266-294`), d'un plafond au
  moins égal à 1 ou d'une limite de gaz au plus égale à 2^24, est écartée
  sans reçu (R1-F24, R1-F30 à R1-F32), et peut revenir au redémarrage du
  nœud depuis son journal durable, dont la durée de vie est de 24 h
  (R1-F30, R1-F36) ;
- les valeurs par défaut d'ethers (plafond 3, pourboire 1) font payer 2 wei
  par gaz et le reçu annonce le plafond comme `effectiveGasPrice` (R1-F28,
  R1-F29) ; `eth_estimateGas` rend une valeur fixe, 300 000 pour tout appel
  de contrat (R1-F51).

Gaz mesuré des opérations NOORTRACE, en une transaction par bloc :
`registerRecorder` 171 955 à 172 279, et 189 229 pour la première clé d'une
organisation ; `anchor` 96 977 au plus ; `submitPeriod` 234 079 à 314 256
selon l'URI et l'état (R1-F35 ; blocs 16648 à 16672 de
`spec/vecteurs/ct-6/registre/capture/`, champ `gasUsed` ; exemple de CT-6
§11.2.1). Le gaz d'`anchor` ne dépend que des octets nuls des 196 octets de
données d'appel (4 gaz l'octet nul, 16 sinon, go-ethereum v1.17.0,
`params/protocol_params.go`) : 43 octets nuls sont incompressibles (31 du mot
`v`, 12 du mot `issuer` ; le sélecteur et le `docType` de période n'en ont
aucun), d'où 96 977 au plus pour une ancre de période, et 12 gaz de moins par
octet nul de l'empreinte, de l'adresse de l'émetteur, de `r` ou de `s` :
96 977 et 96 965 aux blocs 16660 et 16664 de la capture de CT-6 (43 et 44
octets nuls), 96 953 au bloc 17928 du réseau de développement le 2026-10-25
(45). Une instance sans émission ni échange suit donc la variante que
documentent Besu et GoQuorum : une monnaie allouée et un prix non nul pour
borner l'usage des ressources (R2-F13, R2-F20). Le gaz gratuit de ces
logiciels exige de désactiver le contrôle de solde et de remplacer le quota
par une liste de comptes appliquée à la validation des blocs (R2-F15,
R2-F18, R2-F21), que noorcore n'a pas.

**EX-4.15** Toute transaction qu'envoie un outil de CT-4 ou un enregistreur
est de type 2 avec `chainId` égal à `evm_chain_id`, `maxFeePerGas` = 1 wei,
`maxPriorityFeePerGas` = 1 wei, une liste d'accès vide et `value` nul, sauf
un approvisionnement par la trésorerie (EX-4.19). Le prix payé est alors
exactement 1 wei par gaz, rien n'est crédité à l'adresse nulle, et
l'`effectiveGasPrice` du reçu est exact. Les valeurs de frais par défaut
d'une bibliothèque ne sont jamais employées. Seule exception : le
remplacement d'une transaction au même nonce (section 8), dont les deux
champs valent `p' = ⌈1,1 × p⌉`, `p` étant ceux de la transaction remplacée
(soit 2, 3, 4… wei), parce que la mempool n'admet un remplacement que relevé
de 10 % (code de noorcore, `core/txpool/txpool.go:38-41`, lu pour cette
spécification).

**EX-4.16** Le NUR n'a pas d'autre usage que le gaz. Il NE DOIT être ni
vendu, ni acheté, ni échangé ; il ne circule que de la trésorerie vers un
expéditeur approvisionné selon EX-4.19, ou retour. Aucun contrat de jeton,
de récompense ou d'émission n'est déployé (EX-5.1).

**EX-4.17** La limite de gaz de chaque transaction est `fees.gas_limit` du
manifeste, 3 000 000 par défaut (`scripts/lib/noortrace.mjs:26-49`,
`GAS_LIMIT_RESEAU_DISTANT`), comprise entre 1 000 000 et 16 777 216 ; jamais
la valeur d'`eth_estimateGas`, qui
ferait tomber `submitPeriod` en épuisement de gaz
(`scripts/lib/noortrace.mjs:29-39`) ; jamais au-delà de 16 777 216, valeur
que le RPC accepte et que l'exécution écarte (R1-F32). Le gaz non consommé
n'est pas facturé (R1-F32).

**EX-4.18** Avant d'envoyer une transaction, l'outil vérifie que le solde de
l'expéditeur couvre `gasLimit × maxFeePerGas + value` ; sinon il n'envoie pas
et signale une provision insuffisante. Une transaction acceptée par le RPC
sans ce solde est écartée sans reçu (R1-F30) ; la conduite en cas d'absence
de reçu est fixée en section 8.

**EX-4.19** Ont une provision : la clé de chaîne de chaque enregistreur, le
relayeur de l'exploitant s'il en a un, le déployeur et l'administrateur du
registre. N'en ont pas : les approbateurs, les clés de gouvernance, les clés
Ed25519, les clés de validateur. Pour un expéditeur `k`, le budget
journalier `b_k` est la somme, sur ses opérations, du nombre attendu par jour
multiplié par le gaz de référence de la table ci-dessous ; sa provision est
`P_k = provision_days × b_k + gas_limit` wei ; la trésorerie la complète à
`P_k` quand le solde descend sous `refill_below_days × b_k + gas_limit`
(`fees` du manifeste, 30 et 7 jours par défaut).

| Opération | Gaz de référence | Origine |
|---|---|---|
| `anchor` | 100 000 | 96 977 mesurés au plus |
| `submitPeriod` | 350 000 | 314 256 mesurés au plus, URI d'au plus 64 octets (EX-6.8) |
| `registerRecorder`, `revokeRecorder` | 200 000 | 189 229 mesurés au plus pour `registerRecorder` ; `revokeRecorder` non mesuré |
| Opération signée d'un `CuratorSet`, `setCuratorSet` | `gas_limit` | non mesurées |

Exemple : la clé de chaîne d'un enregistreur qui tient un journal horaire a
`b = 24 × (100 000 + 350 000) = 10 800 000` wei par jour, donc
`P = 30 × 10 800 000 + 3 000 000 = 327 000 000` wei, soit 3,27 × 10^-10 NUR.
1 NUR couvre environ 9,3 × 10^10 journées d'un tel journal.

**EX-4.20** La provision borne la consommation d'un expéditeur
approvisionné ; elle ne borne pas l'occupation de la mempool par un
expéditeur sans solde. Un expéditeur ne consomme jamais plus de gaz que son
solde en wei : la clé de chaîne de l'exemple, compromise, consomme au plus
327 000 000 gaz, soit 19 transactions au plafond de 2^24 ou près de 11 blocs
pleins, à raison d'une transaction par bloc au plus (EX-4.14) tant que sa
provision reste sur une adresse ; dispersée vers des adresses neuves, elle
garde la même borne en gaz mais plus la cadence d'une transaction par bloc
(3.5, section 12). Sur une instance de production, la trésorerie NE DOIT PAS
approvisionner un expéditeur au-delà de `P_k`, ni recompléter sans examen un
expéditeur, sous le seuil de recomplément, dont la consommation depuis son
dernier approvisionnement dépasse deux fois son budget pour la même durée
(EX-8.18 ; seuil d'alerte : CT-8), mesure qui n'exige pas de lire un solde à
une hauteur passée. Un expéditeur sans solde, lui, n'est pas borné : sa
transaction est acceptée par le RPC sans contrôle du solde ni de la limite de
gaz (R1-F22 ; seuls « nonce too low » et « nonce too high » sont refusés,
code de noorcore, `core/rpc/jsonrpc_dispatch.go:1620-1651`), elle entre dans
la mempool, qui compte au plus 5 120 places et admet par expéditeur une file
de nonces contigus sans borne (`core/txpool/txpool.go:38-41`, `:659-700`) ;
prise au tour de proposition de son validateur, elle est écartée sans reçu et
sans avancer le nonce de l'état (`core/node/blockexec.go:360-369`), de sorte
que les nonces suivants ne sont jamais prêts et ne sont jamais évincés
(`core/txpool/txpool.go:559-607`) ; pleine, la mempool refuse toute
transaction dont le prix ne dépasse pas strictement le plus bas qu'elle
contient (`:489-507`), donc tout envoi conforme à EX-4.15 (`-32000
transaction underpriced`, `transaction_refusee`) ; le journal durable, quand
il est activé (`TxJournalEnabled`, `core/node/txjournal.go:63`), rétablit ces
entrées au redémarrage pendant 24 h (`core/txpool/journal.go:44`). Deux
adresses vides suffisent à remplir une mempool de façon permanente (2 × 5 119
entrées jamais prêtes), en 45 s environ par validateur à 100 requêtes par
seconde après une rafale de 700 (`core/rpc/limits.go:30-31`), sans autre
coût ; `eth_sendRawTransaction` n'a pas de limite propre
(`core/rpc/jsonrpc_http.go:347-357`), et le jeton `Bearer` du nœud est unique
par nœud, sans identité de client (`core/rpc/jsonrpc_http.go:18-33`). Tout
client a l'accès en écriture (EX-7.1, EX-10.3) et un relais RPC chez un client
relaie `eth_sendRawTransaction` à son meneur (`chain/docker/README.md:253`,
`:339`) : la menace vient aussi d'un client authentifié mais compromis, ou
d'un poste qui atteint son relais. L'envoi de transactions à un point RPC de
validateur de production passe donc par la garde d'admission d'EX-10.8, qui
authentifie chaque client, applique un quota par client et refuse toute
transaction dont l'expéditeur n'a pas le solde ou dont le nonce n'est pas
celui de l'état ; la soumission à au moins deux validateurs d'opérateurs
distincts (EX-8.15) et l'alerte de CT-8 sur la taille de la mempool et sur
tout `transaction underpriced` d'un envoi conforme à EX-4.15 complètent la
parade ; le contrôle du solde à l'admission par noorcore lui-même est une
proposition (section 14).

### 4.6 Versions de noorcore

| Élément | Valeur | Source |
|---|---|---|
| Dépôt | `https://github.com/noorfinances-eng/noorchain-core` (privé) | `chain/README.md:23`, `chain/docker/README.md:70-73` |
| Commit | `618fcef8805ef5b4cb9291a3dd97be710e489297` | `chain/scripts/build-noorcore.sh:32` |
| Go | 1.26.9, imposé par le `go.mod` de noorchain-core | `chain/README.md:51-53` ; R1-F65 |
| go-ethereum | module v1.17.0, que le `go.mod` de noorchain-core épingle | R1 ; CT-6 EX-11.5 |
| Binaire du réseau de développement | SHA-256 `0xb02a011a2fddd77b7ca6a00b8f376320dc7a419c6a5f47dcaca2a35a56ef33c6`, construit par `go build ./core` sans `-trimpath` | `chain/scripts/build-noorcore.sh:100-104` ; R1-F69 ; `spec/vecteurs/ct-6/registre/capture/CAPTURE.md` |
| Binaire de retour arrière, sans correctif | SHA-256 `0x2fd970dcd82ca5c8190cfeba9a33a046c9f05eb7ffadf27af17cb8277726448b` | fichier local `chain/runtime/bin/noorcore.618fcef`, nommé par `chain/README.md:26`, `sha256sum`, non versionné (comme la dernière ligne de B.4) |
| Image conteneur | `go build -trimpath`, images de base épinglées par étiquette seulement | R1-F65, R1-F69 ; section 10 |

Le binaire de l'image et celui du réseau de développement sont construits
avec des drapeaux différents et ne sont pas identiques octet pour octet
(R1, conséquence C18, déduction non comparée).

**EX-4.21** Tous les validateurs d'une instance exécutent des binaires
construits depuis le même commit de noorcore avec les mêmes correctifs,
désignés dans le manifeste (`noorcore`) avec l'empreinte de chaque artefact
distribué : SHA-256 du binaire, ou condensé de l'image conteneur. Une image
est désignée par son condensé, jamais par une étiquette seule (section 10).

**EX-4.22** Une nouvelle version de noorcore n'est admise sur une instance
que si elle garde la ligne de règles, le format sur disque, le domaine et le
condensé des enveloppes BFT et le hachage du jeu (CT-6 EX-11.7, EX-11.8), la
préimage du hachage de bloc (CT-6 EX-11.4) et l'encodage des reçus (CT-6
EX-11.5) ; elle est installée sur tous les validateurs et inscrite dans une
nouvelle révision du manifeste avant le premier bloc qu'elle produit. Une
version qui change l'un de ces points change le contrôle 8 : elle exige une
nouvelle version de CT-4 et de CT-6, jamais un changement silencieux.

### 4.7 Correctif du certificat de commit

Le binaire de l'instance est construit depuis le commit épinglé plus le
correctif `0001-noor_getCommitCertificate.patch`, qui ajoute la méthode
JSON-RPC `noor_getCommitCertificate` sans rien changer du consensus ni du
format sur disque (`chain/README.md:21-33`). Le correctif est fourni hors du
dépôt public, parce qu'il contient des extraits du code de noorchain-core, et
déposé dans `chain/patches/` avant la construction ; sans lui, le binaire n'a
pas la méthode (`chain/patches/LISEZMOI.md:1-9`). `build-noorcore.sh` et le
`Dockerfile` appliquent les correctifs de `chain/patches/*.patch` dans
l'ordre de leurs noms et refusent de construire sur un correctif qui ne
s'applique pas (`chain/scripts/build-noorcore.sh:84-98`, R1-F65). La
méthode, ses paramètres, ses réponses et sa rétention sont décrits en
section 9.

**EX-4.23** Le correctif est désigné par son nom et son SHA-256 dans le
manifeste (`noorcore.patches`) : pour l'instance de ce document,
`0001-noor_getCommitCertificate.patch`,
`0x04d4a48b28568bb6859abdfb1778985841fc547ea47649742b3b2763dd83ae82`. Son
contenu NE DOIT figurer ni dans le dépôt public, ni dans un manifeste, un
dossier, un vecteur ou un journal publié. L'opérateur d'un validateur
partenaire le reçoit de l'exploitant par un canal hors du dépôt public et
vérifie son SHA-256 avant de construire.

**EX-4.24** Tous les validateurs d'une instance exécutent le binaire
corrigé : la capture de la section 9 se fait auprès d'un validateur, jamais
d'un relais (CT-6 EX-13.8), et n'importe lequel doit pouvoir la servir.

### 4.8 Manifeste d'instance

Le manifeste d'instance est ce que l'exploitant publie, hors des dossiers,
pour que clients, opérateurs et réviseurs connaissent l'instance : ce
qu'exige CT-6 EX-13.11 (identifiant de chaîne, adresses des contrats avec
les blocs certifiés de leurs transactions de déploiement, jeux de
validateurs avec leurs hauteurs de validité), plus la genèse, les versions,
la règle de frais et les comptes de l'exploitant. Schéma :
`spec/schemas/instance-registre-v0.schema.json` (JSON Schema draft 2020-12,
sans référence croisée, compilé en mode strict).

| Clé | Contenu | Règle |
|---|---|---|
| `version`, `revision`, `previous_sha256`, `published_at` | Format 0 ; révision à partir de 1 ; SHA-256 du fichier de la révision précédente, `null` pour la première ; instant de publication | EX-4.25, RG-16 |
| `nature` | `developpement` ou `production` (valeurs de `recorder.environment` de CT-2 §15) | EX-4.28 |
| `bft_chain_id`, `evm_chain_id`, `evm_chain_id_registration` | Identifiants ; état de l'identifiant EVM dans `ethereum-lists/chains` (`inscrit`, `absent`, `attribue_a_un_tiers`), date et source | EX-4.6, EX-4.7, RG-17 |
| `genesis` | Fichier publié, SHA-256, ligne de règles, offre totale en wei | EX-4.2, EX-4.3, EX-4.5, RG-17 |
| `noorcore` | Dépôt, commit, version de Go, correctifs (nom, SHA-256, effet), artefacts (binaire ou image, empreinte, construction) | EX-4.21, EX-4.23 |
| `validator_sets[]` | `from_height`, `to_height`, `validators`, `source` (forme exacte d'un jeu du fichier d'ancres de CT-6 §12.2), `valset_hash`, `operators[]` (validateur, opérateur, site, rétention déclarée) | EX-4.10 à EX-4.13, RG-18, RG-20 |
| `fees` | Type 2, plafond et pourboire de 1 wei, limite de gaz, plafond 2^24, jours de provision et seuil de recomplément | EX-4.15 à EX-4.19 |
| `contracts[]` | Nom, adresse, déployeur, nonce, arguments du constructeur, transaction, bloc, hachage du bloc, index de capture du bloc de déploiement (9.4), `to_height` | EX-5.2, EX-5.9, EX-4.27, RG-19 |
| `compilation` | Version de solc, `via_ir`, exécutions de l'optimiseur, commit compilé | EX-5.8 |
| `accounts[]` | Comptes de l'exploitant par rôle (`tresorerie`, `deployeur`, `administrateur_registre`, `relayeur`) et hauteurs de validité | EX-3.1, 5.5 |
| `source` | Provenance du manifeste, texte libre | — |

**EX-4.25** L'exploitant publie la révision 1 du manifeste avant d'inscrire
le premier client, puis une nouvelle révision à chaque changement de version
de noorcore, de jeu de validateurs, de contrat en service, de compte ou de
paramètre de frais, avant que le changement ne prenne effet quand c'est
possible. Une révision publiée n'est jamais modifiée ; la suivante porte le
numéro suivant et le SHA-256 des octets du fichier de la précédente.

**EX-4.26** Le manifeste d'une instance de production et chacune de ses
révisions sont publiés dans le dépôt public sous
`chain/instances/<bft_chain_id>/instance-r<revision>.json`, avec le document de
genèse, le `validators.json` de chaque jeu et les fichiers de preuve qu'ils
désignent, par des chemins relatifs à ce répertoire. Le manifeste du réseau
de développement n'est pas versionné, comme `deployments/`
(`.gitignore:15-19`) : ses adresses ne valent que pour l'état local de
`chain/runtime/`. Un outil qui n'a pas de manifeste n'admet que le réseau de
développement et en reprend les valeurs de `deployments/noorcore.json` et de
`chain/runtime/validators.json` (EX-7.2).

**EX-4.27** Le bloc de déploiement de chaque contrat est capturé comme une
transaction du registre, rôle `deploiement` (9.4 : en-tête, reçus de toutes
les transactions du bloc, certificat de commit, index de capture), auprès
d'un validateur, dès le reçu de la transaction de déploiement et au plus
tard avant que le bloc ne sorte de la fenêtre de rétention (300 000 hauteurs
par défaut, R1-F16 ; 9.5) ; l'index de capture est `evidence.capture` du
contrat. Pour le réseau de développement, les blocs 8316 à 8328 restent dans
la fenêtre jusqu'à ce que la tête atteigne 308 316 (R1, conséquence C7).

**EX-4.28** Le manifeste d'une instance de production a `nature` égal à
`production`, `evm_chain_id_registration.status` égal à `inscrit`,
`block_hash` et `evidence` non nuls pour chaque contrat, un opérateur par
validateur, et passe RG-16 à RG-20.

Exemple : le manifeste du réseau de développement tel que les fichiers du
dépôt permettent de l'écrire au 2026-10-25 (`published_at` est celui de
l'exemple). Le hachage du bloc 8316 vient de `test/fixtures/certificat-commit/`,
qui porte son certificat et son en-tête mais pas ses reçus ; aucun des quatre
blocs n'a encore de capture complète au sens de 9.4, d'où `evidence` nul, et
les hachages des blocs 8320, 8324 et 8328 ne sont pas relevés (EX-4.27).
Valide contre le schéma (`ajv-cli` 5, `--spec=draft2020 --strict=true`).

<!-- schema: instance-registre -->
```json
{
  "version": 0,
  "revision": 1,
  "previous_sha256": null,
  "published_at": "2026-10-25T00:00:00.000Z",
  "nature": "developpement",
  "bft_chain_id": "noortrace-2124-dev",
  "evm_chain_id": 2124,
  "evm_chain_id_registration": {
    "status": "attribue_a_un_tiers",
    "checked_at": "2026-10-25T00:00:00.000Z",
    "source": "ethereum-lists/chains, _data/chains/eip155-2124.json : « Metaplayerone Dubai Testnet », inscrite le 2023-04-23 (R2-F8) ; sans effet sur le réseau de développement (EX-4.7)"
  },
  "genesis": {
    "file": "chain/config/alloc-dev.json",
    "sha256": "0x510e24e41cc401faa4e092338060cee0dc4629e5781a69af7a50b37edb6f4537",
    "rules_line": "chainId=noortrace-2124-dev evmChainId=2124 possEnabled=false possRewards=0x0000000000000000000000000000000000000000 possCapWei=0 possGenesisUnix=0 possHalvingSec=0 possSubperiodSec=0 possEmissionModel=noormint/v1",
    "alloc_total_wei": "4000000000000000000"
  },
  "noorcore": {
    "repository": "https://github.com/noorfinances-eng/noorchain-core",
    "commit": "618fcef8805ef5b4cb9291a3dd97be710e489297",
    "go_version": "1.26.9",
    "patches": [
      {
        "name": "0001-noor_getCommitCertificate.patch",
        "sha256": "0x04d4a48b28568bb6859abdfb1778985841fc547ea47649742b3b2763dd83ae82",
        "effect": "ajoute la méthode JSON-RPC noor_getCommitCertificate ; consensus et format sur disque inchangés (chain/README.md, « Source de noorcore »)"
      }
    ],
    "artifacts": [
      {
        "kind": "binaire",
        "name": "chain/runtime/bin/noorcore",
        "sha256": "0xb02a011a2fddd77b7ca6a00b8f376320dc7a419c6a5f47dcaca2a35a56ef33c6",
        "build": "bash chain/scripts/build-noorcore.sh --force : clone du commit, correctifs de chain/patches/, go build ./core sans -trimpath"
      }
    ]
  },
  "validator_sets": [
    {
      "from_height": 1,
      "to_height": null,
      "validators": [
        {
          "id": "v1",
          "pubKeyHex": "0x0405de9b275a0008b0013919700664ba64bab05c24fcac0585327478e88e40bbb69ffde05aca81fc8a108f62d417afe0aa22f1304861007a27d49ca57fa5189baf"
        },
        {
          "id": "v2",
          "pubKeyHex": "0x040506c4d376fdc84b69844114a7bca3f92ffc13da0a06ce17b5383ecfb11d7368ff73aa14526179fde60236fa0555d03c8aa0906a41271268f4c1896e0322052a"
        },
        {
          "id": "v3",
          "pubKeyHex": "0x040a9ee3f38241823ebfdde52feda9322ec271ca75338faf58b225ee547c6a696fe110f8ea7e9857654239d23eee6806ca57ad7ccae053c6de8b335426d4e2c532"
        },
        {
          "id": "v4",
          "pubKeyHex": "0x042cc90013f733942d895a08797c90d0f64111bfe94eabe1f1890a2dac17eeb76e65c6e5fe0e31b1d2205beda58bbf85775c377b2a9342db8ace7132c719885443"
        }
      ],
      "source": "chain/runtime/validators.json écrit par chain/scripts/dev-net.sh au premier démarrage ; copie publique test/fixtures/certificat-commit/validators.json",
      "valset_hash": "0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751",
      "operators": [
        { "validator": "v1", "operator": "NOORTRACE", "site": "machine unique du réseau de développement", "retention_heights": 300000 },
        { "validator": "v2", "operator": "NOORTRACE", "site": "machine unique du réseau de développement", "retention_heights": 300000 },
        { "validator": "v3", "operator": "NOORTRACE", "site": "machine unique du réseau de développement", "retention_heights": 300000 },
        { "validator": "v4", "operator": "NOORTRACE", "site": "machine unique du réseau de développement", "retention_heights": 300000 }
      ]
    }
  ],
  "fees": {
    "transaction_type": 2,
    "max_fee_per_gas_wei": "1",
    "max_priority_fee_per_gas_wei": "1",
    "gas_limit": 3000000,
    "gas_limit_max": 16777216,
    "provision_days": 30,
    "refill_below_days": 7
  },
  "contracts": [
    {
      "name": "AttestationRegistry",
      "address": "0xf4b146fba71f41e0592668ffbf264f1d186b2ca8",
      "deployer": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
      "nonce": 79,
      "constructor_args": [],
      "transaction_hash": "0xc5a3c23d597ad5f8be5f370fde4681b9e31ba6f9e7fe24952b9ce05e779671a3",
      "block_number": 8316,
      "block_hash": "0x8d74ec1247ecaa63a37d374b5757ef22b532577c4bd8145e2cc13f282cf2410c",
      "evidence": null,
      "to_height": null
    },
    {
      "name": "CuratorSetRegistry",
      "address": "0x172076e0166d1f9cc711c77adf8488051744980c",
      "deployer": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
      "nonce": 80,
      "constructor_args": [ "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266" ],
      "transaction_hash": "0x3117b9d89fb33f4db0f70038a06009a361c0af5c4427a4df2c6a083b56da4795",
      "block_number": 8320,
      "block_hash": null,
      "evidence": null,
      "to_height": null
    },
    {
      "name": "PeriodRegistry",
      "address": "0x4ee6ecad1c2dae9f525404de8555724e3c35d07b",
      "deployer": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
      "nonce": 81,
      "constructor_args": [ "0x172076e0166d1f9cc711c77adf8488051744980c" ],
      "transaction_hash": "0x17ce26160f6e5a2fb3fe0fdcea79555df86da197374d1f1501454c16e4549e8e",
      "block_number": 8324,
      "block_hash": null,
      "evidence": null,
      "to_height": null
    },
    {
      "name": "RecorderRegistry",
      "address": "0xbec49fa140acaa83533fb00a2bb19bddd0290f25",
      "deployer": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
      "nonce": 82,
      "constructor_args": [ "0x172076e0166d1f9cc711c77adf8488051744980c" ],
      "transaction_hash": "0x29b3b93dbc7da2db13cfdca9f7b1fab09ebcda6c6b85785f64a8f4f38525cfa4",
      "block_number": 8328,
      "block_hash": null,
      "evidence": null,
      "to_height": null
    }
  ],
  "compilation": {
    "solc": "0.8.20",
    "via_ir": true,
    "optimizer_runs": 200,
    "source_commit": null
  },
  "accounts": [
    { "role": "tresorerie", "address": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "from_height": 0, "to_height": null },
    { "role": "deployeur", "address": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "from_height": 0, "to_height": null },
    { "role": "administrateur_registre", "address": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "from_height": 8320, "to_height": null },
    { "role": "relayeur", "address": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "from_height": 0, "to_height": null }
  ],
  "source": "exemple de CT-4 §4.8 : réseau de développement de chain/README.md, déploiement du 2026-10-21 (blocs 8316 à 8328) ; blocs de déploiement non encore capturés (9.4)"
}
```

Les adresses, nonces, transactions et blocs viennent du fichier de
déploiement local du réseau de développement (non versionné,
`.gitignore:15-19`) ; les adresses des trois contrats que lit le contrôle 8
sont aussi celles de `spec/vecteurs/ct-6/registre/capture/CAPTURE.md`, et
chaque adresse est `CREATE(deployer, nonce)` (RG-19). `source_commit` est
nul : le déploiement (2026-10-21, 12:31 UTC) précède le premier commit qui
contient `contracts/` (12:40 UTC), et aucun commit n'est établi comme source
exacte (EX-5.8).

## 5. Contrats

### 5.1 Liste et rôle

| Contrat | Origine | Rôle | Sur une instance | Constructeur |
|---|---|---|---|---|
| `AttestationRegistry` | Identique au fichier de noorchain-core (R1-F43) | Ancre une empreinte de 32 octets avec un `docType`, un émetteur et deux instants ; révocation par l'émetteur seul | Un | aucun argument |
| `CuratorSetRegistry` | Identique (R1-F46) | Associe à chaque `org_id` le `CuratorSet` qui le gouverne ; un administrateur unique | Un | `address initialAdmin` |
| `PeriodRegistry` | Dérivé de `PoSSRegistry` (R1-F41) | Enregistre les clôtures de période sous le seuil du jeu de l'organisation, avec la continuité par journal | Un | `address curatorSetRegistry` |
| `RecorderRegistry` | NOORTRACE | Inscrit et révoque les clés d'enregistreur par organisation, sous le seuil | Un | `address curatorSetRegistry` |
| `CuratorSet` | Identique (R1-F45) | Membres et seuil d'une organisation ; administrateur ; opérations signées relayées | Un par organisation (section 7) | `CuratorSet(address initialAdmin, address[] initialCurators, uint256 initialThreshold)` (`contracts/CuratorSet.sol:168`) |
| `ThresholdSignatures` | NOORTRACE | Bibliothèque interne : compte des signatures au seuil | Non déployée : compilée dans `PeriodRegistry` et `RecorderRegistry` | — |

`PeriodRegistry` est le `PoSSRegistry` de noorchain-core adapté à la
clôture de période : sans le hachage des paiements, condensé sur tous les
champs de `PeriodMeta`, continuité par journal en temps et en séquence,
unicité de `periodHash` cloisonnée par organisation au lieu d'une table
globale (`contracts/PeriodRegistry.sol:24-38`, R1-F41).

**EX-5.1** L'exploitant ne déploie sur une instance que les contrats de cette
table : ni `PoSSRegistry`, ni `PoSSRewards`, ni contrat de jeton, de
récompense ou de mandataire (architecture, « Instance dédiée »). Tout
expéditeur approvisionné peut déployer un contrat, rien ne l'empêche dans
noorcore (R1-F26) ; un tel contrat n'est pas du registre et ses événements
n'entrent pas dans le contrôle 8, qui compare l'adresse émettrice aux
adresses du fichier d'ancres (CT-6 R-8).

### 5.2 Ordre de déploiement

**EX-5.2** Les quatre contrats de l'instance sont déployés dans cet ordre,
chaque transaction attendue jusqu'à son reçu avant la suivante :
`AttestationRegistry` ; `CuratorSetRegistry(initialAdmin)`, `initialAdmin`
étant l'administrateur du registre ; `PeriodRegistry(curatorSetRegistry)` ;
`RecorderRegistry(curatorSetRegistry)` (`scripts/lib/noortrace.mjs:187-233`,
`deployNoortrace`, R1-F48). Puis les preuves des quatre blocs sont capturées
(EX-4.27) et la
révision du manifeste publiée (EX-4.25). Un fichier de déploiement existant
n'est jamais écrasé sans `--force`, qui l'archive
(`scripts/lib/noortrace.mjs:245-285`, `writeDeployment`). Sur le réseau de
développement, le déployeur est aussi `initialAdmin`
(`scripts/lib/noortrace.mjs:210-213`) ; en production, les deux clés sont
distinctes (EX-3.1).

### 5.3 Adresses publiées

Contrats du réseau de développement, déployés le 2026-10-21 par le compte
Hardhat 0 (`0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266`), et chacun égal à
`CREATE(déployeur, nonce)` :

| Contrat | Adresse | Nonce | Bloc |
|---|---|---|---|
| `AttestationRegistry` | `0xf4b146fba71f41e0592668ffbf264f1d186b2ca8` | 79 | 8316 |
| `CuratorSetRegistry` | `0x172076e0166d1f9cc711c77adf8488051744980c` | 80 | 8320 |
| `PeriodRegistry` | `0x4ee6ecad1c2dae9f525404de8555724e3c35d07b` | 81 | 8324 |
| `RecorderRegistry` | `0xbec49fa140acaa83533fb00a2bb19bddd0290f25` | 82 | 8328 |

**EX-5.3** Les adresses qu'emploient un outil, un enregistreur, un service
d'approbation ou un réviseur viennent du manifeste de l'instance, contrôlées
par RG-19 et, en ligne, par EX-4.9 ; jamais d'un fichier copié d'un autre
nœud ni d'une adresse saisie à la main. Le code aux adresses n'est pas
prouvé par le contrôle 8 (H7) : la compilation publiée (EX-5.8) permet au
réviseur de comparer le code de création porté par la transaction de
déploiement, dont le corps signé de la proposition du bloc contient les
octets bruts (CT-6 EX-11.2).

### 5.4 Contrôle d'accès

| Fonction | Appelant | Autorisation | Condensé (6.6) | Événement |
|---|---|---|---|---|
| `AttestationRegistry.anchor(fingerprint, docType, issuer, sig)` | Quiconque | Signature de `issuer` ; empreinte non nulle et jamais ancrée (`contracts/AttestationRegistry.sol:60-66`) | `anchorDigest` | `Anchored` |
| `AttestationRegistry.revoke(fingerprint, sig)` | Quiconque | Signature de l'émetteur enregistré (`:69-76`) | `revokeDigest` | `Revoked` |
| `CuratorSetRegistry.setCuratorSet(orgId, set)` | L'administrateur du registre | `msg.sender` (`contracts/CuratorSetRegistry.sol:76-84`) | — | `CuratorSetAssigned` |
| `CuratorSetRegistry.proposeAdmin(a)`, `acceptAdmin()` | L'administrateur ; l'administrateur proposé | `msg.sender` (`:104-117`) ; pas de forme signée (R1-F46) | — | `AdminProposed`, `AdminAccepted` |
| `PeriodRegistry.submitPeriod(meta, sigs)` | Quiconque | Seuil du jeu de `meta.orgId`, lu à la transaction ; bornes, unicité et continuité (`contracts/PeriodRegistry.sol:172-242`) | `periodDigest` | `PeriodSubmitted` |
| `RecorderRegistry.registerRecorder(orgId, journalId, chainKey, ed25519PubKey, sigs)` | Quiconque | Seuil ; clé de chaîne jamais inscrite ; clé Ed25519 active sous une seule clé de chaîne (`contracts/RecorderRegistry.sol:128-158`) | `registerDigest` | `RecorderRegistered` |
| `RecorderRegistry.revokeRecorder(orgId, chainKey, sigs)` | Quiconque | Seuil ; clé inscrite et non révoquée (`:162-173`) | `revokeDigest` | `RecorderRevoked` |
| `CuratorSet.addCurator`, `removeCurator`, `setThreshold`, `proposeAdmin` ; `acceptAdmin` | L'administrateur du jeu ; l'administrateur proposé | `msg.sender` (`contracts/CuratorSet.sol:180-231`) | — | `CuratorAdded`, `CuratorRemoved`, `ThresholdUpdated`, `AdminProposed`, `AdminAccepted` |
| `CuratorSet.addCuratorSigned`, `removeCuratorSigned`, `setThresholdSigned`, `proposeAdminSigned` ; `acceptAdminSigned` | Quiconque | Signature de l'administrateur, de l'administrateur proposé pour `acceptAdminSigned`, au nonce `opNonce` (`:109-166`) | `adminOpDigest` | les mêmes, plus `AdminOpRelayed` |

Le seuil est compté par `ThresholdSignatures` : seule la forme canonique
d'une signature compte (`s ≤ n/2`, `v` égal à 27 ou 28), un signataire nul,
hors du jeu ou déjà compté est ignoré, les signatures sont prises dans
n'importe quel ordre, le compte s'arrête au seuil, un seuil nul n'est jamais
atteint (`contracts/ThresholdSignatures.sol:20-29`, `:63-64`, `:68-115`) ;
les registres exigent en outre au moins autant de signatures que le seuil
(`contracts/PeriodRegistry.sol:275-281`,
`contracts/RecorderRegistry.sol:202-208`).
`AttestationRegistry` et `CuratorSet` ne refusent pas une signature à `s`
haut (R1-F43, R1-F45) ; les outils n'en produisent ni n'en acceptent
(RG-12).

### 5.5 Administration

Aucun contrat n'a d'interrupteur de pause (`contracts/CuratorSet.sol:7-19`,
`contracts/CuratorSetRegistry.sol:38-40`). Deux administrations existent.

L'**administrateur du registre** (`CuratorSetRegistry.admin`), une seule
clé, assigne ou réassigne le jeu de n'importe quelle organisation (R1-F46).
Réassigner décide qui autorise, à partir de la transaction suivante, les
inscriptions de clés et les clôtures de l'organisation : les deux registres
lisent le jeu à chaque transaction (`contracts/PeriodRegistry.sol:275-281`,
`contracts/RecorderRegistry.sol:202-208`). Cela ne modifie aucune période ni
aucune inscription enregistrée, et la continuité interdit d'insérer une
période ; CT-3 neutralise ce pouvoir pour les approbations par l'épinglage
du jeu (CT-3 EX-8.6), pas pour le registre.

**EX-5.4** Sur une instance de production, la clé de l'administrateur du
registre est gardée par l'exploitant en HSM (CT-7), distincte des autres
(EX-3.1), et ne sert qu'à : assigner le jeu d'une organisation à son
inscription (section 7) ; le réassigner dans les seules conditions d'EX-8.10
(demande écrite de l'organisation, nouvelle version de politique publiée) ;
transférer l'administration (EX-5.5). Chaque `CuratorSetAssigned` est
notifié à l'organisation concernée, qui le surveille de son côté (8.5).
L'outil de référence ne désigne une clé que par `fichier:`, `env:` ou
`hardhat:` (EX-7.3) et la charge en mémoire : une clé d'administrateur en HSM
n'est pas prise en charge en version 0 (section 14).

**EX-5.5** Le transfert de l'administration du registre suit
`proposeAdmin` puis `acceptAdmin`, envoyé par la nouvelle clé, qui doit donc
avoir une provision (`contracts/CuratorSetRegistry.sol:104-117`) ; il est
inscrit dans `accounts` par une nouvelle révision du manifeste (EX-4.25).

L'**administrateur du jeu** (`CuratorSet.admin`) ajoute et retire des
membres, fixe le seuil et transmet l'administration. Un retrait qui
rendrait le seuil supérieur au nombre de membres est refusé, le seuil vérifie
`1 ≤ t ≤ n` (`contracts/CuratorSet.sol:188-202`, `:257-262`). Chaque
opération a une forme signée que n'importe qui relaie, parce qu'une clé
d'organisation n'a pas de NUR (`contracts/CuratorSet.sol:31-53`).

**EX-5.6** Sur une instance de production, l'administrateur du `CuratorSet`
d'un client est sa clé de gouvernance, jamais une clé de l'exploitant, dès le
déploiement de son jeu : la section 7 déploie le `CuratorSet` avec la clé de
gouvernance pour administrateur (EX-7.7), le constructeur la prenant en
paramètre (`contracts/CuratorSet.sol:168-178`). L'amorçage de développement
de `scripts/deploy/bootstrap-org.mjs` laisse le déployeur administrateur
(`scripts/lib/noortrace.mjs:378-380`, `bootstrapOrg`) ; un jeu ainsi déployé
ne passe à l'organisation que par `proposeAdmin`, puis `acceptAdminSigned`
signé par la clé de gouvernance.

**EX-5.7** Les clés des approbateurs et la clé de gouvernance d'une
organisation ne reçoivent pas de provision (EX-4.19) : leurs actes sont des
signatures hors chaîne (6.6), relayées par la clé de chaîne de
l'enregistreur ou par le relayeur de l'exploitant.

**EX-5.8** Le manifeste inscrit la version de solc et ses réglages de la
compilation déployée (`compilation` ; `hardhat.config.mjs:9-15` : solc
0.8.20, `viaIR`, optimiseur à 200 exécutions) et le commit du dépôt public
dont `contracts/` a été compilé. Sur une instance de production, ce commit
est connu et étiqueté dans le dépôt public, pour qu'un réviseur recompile et
compare le code de création ; seuls les octets des immuables (adresse du
`CuratorSetRegistry`) et les métadonnées finales peuvent différer
(`spec/vecteurs/ct-6/registre/capture/CAPTURE.md`).

### 5.6 Mises à jour

Les contrats n'ont ni mandataire, ni appel délégué, ni fonction de
remplacement de code.

**EX-5.9** Aucune mise à niveau en place : une version corrigée d'un contrat
est déployée à une nouvelle adresse, inscrite dans le manifeste, et
l'ancienne reçoit un `to_height` ; l'ancienne reste lisible et ses
enregistrements gardent leur sens. Conséquences à traiter avant tout
redéploiement : un nouveau `PeriodRegistry` n'a pas de période précédente,
la première clôture d'un journal y est libre
(`contracts/PeriodRegistry.sol:195-203`), et l'outil DOIT y faire commencer
chaque journal où il s'arrêtait dans l'ancien ; un nouveau `RecorderRegistry`
exige de réinscrire les clés
actives ; un nouveau `CuratorSetRegistry` exige de réassigner chaque
organisation ; un nouvel `AttestationRegistry` n'a pas l'unicité des
empreintes de l'ancien, et l'outil DOIT consulter les deux. Le fichier
d'ancres de CT-6 ne porte qu'une adresse par rôle (`registry.contracts`,
CT-6 §12.2) : un dossier dont les transactions sont réparties entre deux
générations de contrats ne passe pas R-8. Un redéploiement n'a donc lieu
qu'après une faille établie (section 12) ; la prise en charge de plusieurs
générations par CT-6 est une proposition pour une version suivante
(section 14).

**EX-5.10** En version 0, le code, les événements, les étiquettes et les
condensés des contrats de ce dépôt sont figés : le contrôle 8 en dépend
(CT-6 EX-11.9, EX-11.18, EX-11.19 ; CT-1 §10.4). Tout changement est une
nouvelle version de CT-4 et du contrôle 8 de CT-6, jamais un changement
silencieux.

### 5.7 Événements

| Événement | Contrat | `topics[0]` | Sujets indexés | `data` | Lu par |
|---|---|---|---|---|---|
| `PeriodSubmitted(uint256,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint64,uint32,address,string,uint64)` | `PeriodRegistry` | `0x6d6cb8da98056d2abd84165b9f6d64d8097b1e28deaf23013228f6bdd5370fba` | `id`, `periodHash`, `publisher` | disposition de CT-6 EX-11.9 | Contrôle 8 (`cloture`) |
| `Anchored(bytes32,address,bytes32)` | `AttestationRegistry` | `0x4450fd19f5dafd45e52f91aa82897967b7469e348fd7d5083f4e0515df90706e` | `fingerprint`, `issuer` | `docType` | Contrôle 8 (`ancre`) |
| `Revoked(bytes32,address)` | `AttestationRegistry` | `0x5bc2baf870c5baf189838b5e0b0e3b04a3263e2df5d305d1c15f3e6022f5dc45` | `fingerprint`, `issuer` | — | Client, réviseur ; non prouvé |
| `RecorderRegistered(bytes32,address,bytes32,bytes32,address)` | `RecorderRegistry` | `0xe29e846d78f0b22a87c669add67dec8daa3b0935e6f4c96d7f627a60e7ae44ec` | `orgId`, `chainKey`, `journalId` | `ed25519PubKey`, `publisher` | Contrôle 8 (`inscription`) ; enregistreur (CT-2 EX-11.13) |
| `RecorderRevoked(bytes32,address,address)` | `RecorderRegistry` | `0x74ae31d8dbb96eed3dc2e0064cb3b980f6289d88b35c82b2863e40705567fa74` | `orgId`, `chainKey` | `publisher` | Client, enregistreur ; son absence ne se prouve pas |
| `CuratorSetAssigned(bytes32,address,address)` | `CuratorSetRegistry` | `0xe3dc53929964ea6820df23c3069981538b21f654bd176471a4befe2eb6da9b23` | `orgId`, `curatorSet`, `previous` | — | CT-3 EX-8.5 ; client |
| `CuratorAdded(address)`, `CuratorRemoved(address)` | `CuratorSet` | `0x18c43d122320e51fe6358fec30ac29762ead2d8f27e59d405344cb9e09b68b5c`, `0x94444aede86802e5301b671c64873189b3e1ab371ad0dbf9eb182b71de1bf2fc` | `curator` | — | CT-3 EX-8.1, EX-8.5 |
| `ThresholdUpdated(uint256)` | `CuratorSet` | `0xadfa8ecb21b6962ebcd0adbd9ab985b7b4c5b5eb3b0dead683171565c7bfe171` | — | seuil | CT-3 EX-8.5 |
| `AdminProposed(address,address)`, `AdminAccepted(address,address)` | `CuratorSetRegistry`, `CuratorSet` | `0xfd22260ca7b3d2a5f6332770491ab546b6235bc73909c334f5e304d2fae455b1`, `0x12309f939c005790a0458600b5b21d505bb0d61ad30e57962e52c68748788bdc` | les deux adresses | — | Client, exploitant |
| `AdminOpRelayed(bytes32,address,uint256)` | `CuratorSet` | `0x2e0e19053817f36938ec18c54c0901f672942223a90e78527399eb1b1db54b0a` | `op`, `relayer` | nonce | Client |

Chaque `topics[0]` est `keccak256(utf8(signature))` ; les trois premiers
sont ceux de CT-6 EX-11.9, recalculés pour cette table depuis les ABI de
compilation, comme les autres.

**EX-5.11** Les événements se lisent par `eth_getLogs`, en tranches d'au
plus 16 384 blocs, borne du nœud (R1-F58), et par sondage. Aucun outil de
CT-4 ne dépend d'`eth_subscribe` : le binaire épinglé le sert en WebSocket
(`newHeads`, `logs`), mais la spécification RPC de noorchain-core le déclare
non pris en charge, et ce n'est donc pas un contrat (R1-F55).

### 5.8 Refus

Les refus d'un appel, par fonction, avec leur texte exact (`Error(string)`,
sélecteur `0x08c379a0`) ou leur erreur et son sélecteur :

| Fonction | Refus |
|---|---|
| `anchor` | `BadFingerprint()` `0xc943233a` ; `AlreadyAnchored()` `0xa0094ce3` ; `NotTheIssuer()` `0xa7a00f0a` |
| `revoke` (attestation) | `Unknown()` `0x0cf64598` ; `AlreadyRevoked()` `0x905e7107` ; `NotTheIssuer()` |
| `submitPeriod` | `PeriodRegistry: orgId=0`, `journalId=0`, `periodHash=0`, `periode invalide`, `periodEnd hors plage`, `lastSeq hors plage`, `root d'une periode vide != 0`, `sequence invalide`, `root=0`, `doublon`, `discontinuite temporelle`, `discontinuite de sequence`, `seuil=0`, `signatures insuffisantes`, `seuil non atteint` (chaque texte précédé de `PeriodRegistry: `) ; `UnknownOrganization(bytes32)` `0xda45d573` |
| `registerRecorder` | `RecorderRegistry: orgId=0`, `journalId=0`, `chainKey=0`, `ed25519PubKey=0`, `cle revoquee`, `cle deja active`, `cle Ed25519 deja active`, `seuil=0`, `signatures insuffisantes`, `seuil non atteint` (chaque texte précédé de `RecorderRegistry: `) ; `UnknownOrganization(bytes32)` |
| `revokeRecorder` | `RecorderRegistry: cle inconnue`, `cle deja revoquee`, `seuil=0`, `signatures insuffisantes`, `seuil non atteint` ; `UnknownOrganization(bytes32)` |
| `setCuratorSet` | `CuratorSetRegistry: not admin`, `CuratorSetRegistry: orgId=0` ; `ZeroAddress()` `0xd92e233d` |
| `proposeAdmin`, `acceptAdmin` (registre) | `CuratorSetRegistry: not admin` ; `ZeroAddress()` ; `NotPendingAdmin()` `0x058d9a1b` |
| Opérations d'un `CuratorSet` | `CuratorSet: not admin`, `CuratorSet: curator=0`, `already curator`, `not curator`, `no curators`, `bad threshold` ; `BadNonce(uint256,uint256)` `0x3ddd5131` ; `NotAuthorized()` `0xea8e4eb5` ; `NotPendingAdmin()` ; `ThresholdWouldExceedCurators(uint256,uint256)` `0x886b311d` ; `ZeroAddress()` |

Un reçu de noorcore ne porte pas la raison d'un refus, seulement son
`status` (R1-F57), et la donnée de retour d'un refus servie par `eth_call`
n'a pas été relevée (non vérifié).

**EX-5.12** Avant d'envoyer une transaction, l'outil reproduit hors chaîne
les conditions de refus qu'il peut calculer (RG-4, RG-5, RG-13) et lit par
`eth_call` celles qui dépendent de l'état (empreinte déjà ancrée,
organisation sans jeu, clé déjà inscrite, période précédente du journal,
seuil, `opNonce`) ; il ne s'appuie pas sur le texte d'un refus pour décider
d'une reprise (section 8).

## 6. Conventions

### 6.1 Principe

Tout ce qu'un contrat recalcule, l'outil le calcule d'abord hors chaîne,
octet pour octet : c'est ce que les approbateurs et la clé de chaîne signent,
et un écart d'encodage se verrait autrement comme un « seuil non atteint »
sans cause apparente (`contracts/PeriodRegistry.sol:150-156`). Les
vérifications de cette section s'exécutent sans réseau, sur les seules
valeurs qu'elles nomment ; les vecteurs de l'annexe A les fixent.

**EX-6.1** Quand le point RPC est joignable, l'outil compare chaque condensé
interne qu'il a calculé (RG-6 à RG-11) à celui que rend la fonction de lecture
du contrat à l'adresse visée (`periodDigest`, `registerDigest`,
`revokeDigest`, `anchorDigest`, `adminOpDigest`), avant de le faire signer ;
un écart arrête l'opération. Les parcours existants le font déjà
(`scripts/e2e/dev-roundtrip.mjs:139-140`, `:206-207`).

### 6.2 Organisation : slug et `org_id`

**EX-6.2 (RG-1, slug et `org_id`)** `org_id = keccak256(utf8(slug))`
(`scripts/lib/noortrace.mjs:72-75`, `orgIdOf`,
`contracts/CuratorSetRegistry.sol:42-45`).
Le slug vérifie `^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$` : 1 à 64
caractères ASCII minuscules, chiffres et traits d'union, sans trait d'union
au début ni à la fin. `org_id` n'est jamais nul. Le slug d'une organisation
de production est `o-` suivi de 32 chiffres hexadécimaux minuscules tirés
d'un générateur aléatoire cryptographique : `org_id` est public sur la
chaîne, et un slug tiré du nom du client permettrait de retrouver, par un
dictionnaire, la liste des clients et leur activité. Les slugs d'essai sont
libres sous la même grammaire (`assureur-demo`, `canton-demo`,
`e2e-<millisecondes>`).

Exemples : `keccak256(utf8("assureur-demo")) =
0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab` (l'`org_id`
des vecteurs de CT-1 §13) ; `keccak256(utf8("canton-demo")) =
0x71917bc4f50a62e09e2bd4bd01f694e77b055c42fee74846e2469f5a79de3b88`.

**EX-6.3** Un `org_id` n'est attribué qu'une fois sur une instance : un slug
dont l'`org_id` a déjà un jeu (`isRegistered`) ou figure dans un dossier
d'inscription n'est jamais donné à un autre client, et le slug d'une
organisation qui part n'est jamais réutilisé. Ses périodes, ses clés et la
continuité de ses journaux restent sur la chaîne sous cet `org_id`.

### 6.3 Journal : nom et `journal_id`

**EX-6.4 (RG-2, nom de journal et `journal_id`)** `journal_id =
keccak256(utf8(nom))` (`scripts/lib/noortrace.mjs:77-80`, `journalIdOf`), avec
la grammaire du slug ; `journal_id` n'est jamais nul. Un nom est unique dans
son organisation et n'y est jamais réutilisé : `PeriodRegistry` continue un
journal là où sa dernière période s'arrête
(`contracts/PeriodRegistry.sol:195-203`), et un
nom repris prolongerait l'ancien journal. En production, le nom NE DEVRAIT
PAS décrire l'activité (`journal-01` plutôt que `journal-sinistres`). CT-1
tient ces identifiants pour opaques (§3) : seuls les outils de CT-4 en
connaissent la préimage, et ni un vérificateur ni un dossier n'en ont besoin.

Exemples : `keccak256(utf8("journal-principal")) =
0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b`,
`keccak256(utf8("journal-sinistres")) =
0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164` (CT-1 §13).

### 6.4 `docType`

**EX-6.5 (RG-3, `docType`)** `docType = keccak256(utf8(libellé))`, où le
libellé vérifie `^noortrace/[a-z0-9][a-z0-9-]{0,31}/v(0|[1-9][0-9]{0,2})$` :
ASCII sans espace ni majuscule, ce qui écarte toute normalisation Unicode
(R2-F57, R2-F58), au plus 47 caractères. Le libellé et sa valeur figurent
dans la table ci-dessous ; une valeur hors de la table n'est pas un
`docType` de CT-4.

| Libellé | `docType` | Usage | Depuis |
|---|---|---|---|
| `noortrace/periode/v0` | `0x2970f32daf26845541b559f8505ddade17ab51994fab81cbfe0dbd81ab9671ee` | Ancre de la période d'un journal, empreinte de 6.5 | version 0 (`scripts/lib/noortrace.mjs:60-61`, `DOC_TYPE_PERIODE`, CT-6 EX-11.18) |

**EX-6.6** En version 0, toute ancre qu'envoie la clé de chaîne d'un
enregistreur porte `docType = keccak256(utf8("noortrace/periode/v0"))`, la
seule valeur que R-9 admet (CT-6 EX-11.18). Un libellé ne s'ajoute à la
table que par une nouvelle version de CT-4, avec son vecteur ; un libellé
n'est jamais réattribué à un autre sens : un sens nouveau est un libellé
nouveau ou une version nouvelle (`…/v1`), comme un identifiant de schéma EAS
dérive de son contenu et ne se renomme pas (R2-F52, R2-F54). La valeur nulle
`0x00…00` n'est jamais un `docType` (R2-F53, R2-F56), bien
qu'`AttestationRegistry` ne la refuse pas
(`contracts/AttestationRegistry.sol:60-66`). La préimage reste publique :
c'est l'inverse des emplacements de stockage d'ERC-1967, dont on cache la
préimage (R2-F57).

### 6.5 Empreinte d'ancre

L'empreinte ancrée pour une période est celle de CT-1 §10.4 :
`keccak256(b32(org_id) ‖ b32(journal_id) ‖ b32(periodHash))`, préimage de 96
octets. On n'ancre pas la racine : une racine se répète (période vide,
événements identiques), et `AttestationRegistry` n'ancre une empreinte
qu'une fois pour toute la chaîne (`scripts/lib/noortrace.mjs:117-128`,
`anchorFingerprint`, `contracts/AttestationRegistry.sol:62`).

**EX-6.7 (RG-4, empreinte d'ancre)** L'empreinte est recalculée depuis
`org_id`, `journal_id` et `periodHash` du manifeste (CT-1 §10.2) ; elle
n'est pas nulle. Exemple, période 1 de la capture de CT-6
(`spec/vecteurs/ct-6/registre/capture/`, organisation `assureur-demo`,
journal `journal-sinistres`, `periodHash`
`0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914`) :
`0x3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6`, celle
du bloc 16660.

### 6.6 Condensés signés

#### 6.6.1 `PeriodMeta` d'une clôture

**EX-6.8 (RG-5, champs d'une clôture)** `PeriodMeta` se tire du manifeste
de la période champ pour champ selon CT-1 §10.4 (`orgId`, `journalId`,
`periodHash`, `root`, `periodStart`, `periodEnd`, `firstSeq`, `lastSeq`,
`version`) et `uri`. Avant toute signature, l'outil vérifie ce que le
contrat refuserait (`contracts/PeriodRegistry.sol:176-193`) : `orgId`,
`journalId` et `periodHash` non nuls ; `periodStart < periodEnd < 2^64 − 1` ;
`lastSeq < 2^64 − 1` ; si `lastSeq + 1 = firstSeq` (période vide), `root`
nulle, sinon `firstSeq ≤ lastSeq` et `root` non nulle ; et, quand la
période précédente du journal est connue, `periodStart` égal à son
`periodEnd` et `firstSeq` égal à son `lastSeq + 1`. `uri` est la chaîne vide
ou au plus 64 octets ASCII imprimables (`0x20` à `0x7e`) qui ne contiennent
ni le slug, ni le nom du journal, ni une donnée de l'activité : l'URI est
publique et figure dans `PeriodSubmitted`, et sa longueur se paie en gaz
(4.5). Les outils de référence écrivent la chaîne vide.

#### 6.6.2 Préimages

Les six condensés internes sont des `keccak256` de préimages formées par
`abi.encodePacked` : chaque valeur à sa largeur naturelle, sans remplissage,
les chaînes sans longueur.

| Condensé interne | Préimage | Octets | Signé par | Source |
|---|---|---|---|---|
| `periodDigest(meta)` | `u256(chainid) ‖ a20(PeriodRegistry) ‖ utf8("noortrace-periode") ‖ keccak256(E(meta))` | 32 + 20 + 17 + 32 = 101 | Approbateurs, au seuil | `contracts/PeriodRegistry.sol:157-159` |
| `registerDigest(orgId, journalId, chainKey, ed25519PubKey)` | `u256(chainid) ‖ a20(RecorderRegistry) ‖ utf8("noortrace-enregistreur-inscrit") ‖ b32(orgId) ‖ b32(journalId) ‖ a20(chainKey) ‖ b32(ed25519PubKey)` | 32 + 20 + 30 + 32 + 32 + 20 + 32 = 198 | Approbateurs, au seuil | `contracts/RecorderRegistry.sol:104-112` |
| `revokeDigest(orgId, chainKey)` (enregistreur) | `u256(chainid) ‖ a20(RecorderRegistry) ‖ utf8("noortrace-enregistreur-revoque") ‖ b32(orgId) ‖ a20(chainKey) ‖ u64(registeredAt)` | 32 + 20 + 30 + 32 + 20 + 8 = 142 | Approbateurs, au seuil | `contracts/RecorderRegistry.sol:119-123` |
| `anchorDigest(fingerprint, docType)` | `u256(chainid) ‖ a20(AttestationRegistry) ‖ utf8("noor-attestation-ancre") ‖ b32(fingerprint) ‖ b32(docType)` | 32 + 20 + 22 + 32 + 32 = 138 | L'émetteur, clé de chaîne | `contracts/AttestationRegistry.sol:49-51` |
| `revokeDigest(fingerprint)` (attestation) | `u256(chainid) ‖ a20(AttestationRegistry) ‖ utf8("noor-attestation-revoque") ‖ b32(fingerprint)` | 32 + 20 + 24 + 32 = 108 | L'émetteur | `contracts/AttestationRegistry.sol:53-56` |
| `adminOpDigest(op, arg, nonce)` | `u256(chainid) ‖ a20(CuratorSet) ‖ b32(op) ‖ b32(arg) ‖ u256(nonce)` | 32 + 20 + 32 + 32 + 32 = 148 | L'administrateur du jeu, ou l'administrateur proposé pour `acceptAdmin` | `contracts/CuratorSet.sol:105-107` |

`chainid` est l'identifiant EVM ; l'adresse est celle du contrat qui
vérifiera la signature ; `E(meta)` est `abi.encode(meta)` (6.7.2). Les
étiquettes, en octets : `noortrace-periode` =
`0x6e6f6f7274726163652d706572696f6465` (17) ; `noortrace-enregistreur-inscrit`
= `0x6e6f6f7274726163652d656e726567697374726575722d696e7363726974` (30) ;
`noortrace-enregistreur-revoque` =
`0x6e6f6f7274726163652d656e726567697374726575722d7265766f717565` (30) ;
`noor-attestation-ancre` = `0x6e6f6f722d6174746573746174696f6e2d616e637265`
(22) ; `noor-attestation-revoque` =
`0x6e6f6f722d6174746573746174696f6e2d7265766f717565` (24). Deux étiquettes
distinctes séparent toujours deux opérations : une signature d'inscription ne
révoque jamais, une signature d'ancre ne révoque jamais.

Opérations d'un `CuratorSet` (`contracts/CuratorSet.sol:84-88`,
`:120-166`) ; `nonce` est la valeur de `opNonce()` au moment où l'opération
sera exécutée, et chaque opération exécutée l'incrémente :

| Opération | `op` = `keccak256(utf8(…))` | `arg` |
|---|---|---|
| `addCuratorSigned(curator, …)` | `CuratorSet.addCurator` = `0x90676d1923a8a97480098534555883cdbc62ebae7fcd057b915a730b244f58da` | 12 octets nuls ‖ `a20(curator)` |
| `removeCuratorSigned(curator, …)` | `CuratorSet.removeCurator` = `0xd4fead8aad35a3f84500546ae62a90bd1b0d5d8cc7012e79149844febf5929fc` | 12 octets nuls ‖ `a20(curator)` |
| `setThresholdSigned(t, …)` | `CuratorSet.setThreshold` = `0x80b84408d410e35bce630bf67e150eddb5ecf898b4009e7deeb26ae3838c38e8` | `u256(t)` |
| `proposeAdminSigned(newAdmin, …)` | `CuratorSet.proposeAdmin` = `0xc9d8d482eeca2566b117e8a890e79e8048bf35f570e2ad62132b3e967459e995` | 12 octets nuls ‖ `a20(newAdmin)` |
| `acceptAdminSigned(…)` | `CuratorSet.acceptAdmin` = `0xe0d1968273ca8a1ca2680cc6bea43e6d6824797741e9a721c4588ef3bc7414b4` | 32 octets nuls |

**EX-6.9 (RG-6, `periodDigest`)** Le condensé de clôture est calculé selon
la table depuis l'identifiant EVM, l'adresse du `PeriodRegistry` en service
et le `PeriodMeta` qui a passé RG-5.

**EX-6.10 (RG-7, `registerDigest`)** Le condensé d'inscription est calculé
depuis `org_id`, `journal_id`, l'adresse de la clé de chaîne et la clé
publique Ed25519 de 32 octets que l'enregistreur fournit (CT-2 EX-11.13) ;
aucun des quatre n'est nul (`contracts/RecorderRegistry.sol:135-138`).

**EX-6.11 (RG-8, `revokeDigest` d'enregistreur)** `registeredAt` est
l'instant d'inscription de la clé de chaîne visée, `uint64`, égal à
l'horodatage du bloc de son `RecorderRegistered`
(`contracts/RecorderRegistry.sol:153`) : il se calcule hors chaîne depuis
l'en-tête de ce bloc, que la capture conserve (section 9). Une révocation
signée pour une autre inscription, ou avant l'inscription, ne vérifie pas.

**EX-6.12 (RG-9, `anchorDigest`)** Le condensé d'ancre est calculé depuis
l'empreinte de RG-4, le `docType` de RG-3 et l'adresse de
l'`AttestationRegistry` en service.

**EX-6.13 (RG-10, `revokeDigest` d'attestation)** Le condensé de révocation
d'une ancre est calculé depuis la seule empreinte. Une ancre de période n'est
pas révoquée en version 0 : une ancre révoquée garde son `Anchored`, que le
contrôle 8 lit, et `Revoked` n'est pas prouvé.

**EX-6.14 (RG-11, `adminOpDigest`)** Le condensé d'une opération signée est
calculé depuis `op` et `arg` de la table, le nonce et l'adresse du
`CuratorSet` de l'organisation.

#### 6.6.3 Hachage signé et forme de la signature

Le hachage signé est `keccak256(P ‖ condensé interne)` avec le préfixe
EIP-191 de 28 octets
`P` = `0x19457468657265756d205369676e6564204d6573736167653a0a3332`
(`"\x19Ethereum Signed Message:\n32"`) : c'est ce que fait
`signMessage(getBytes(condensé))` d'ethers
(`scripts/lib/noortrace.mjs:153-161`, `signDigest`), et ce que recouvrent
les contrats (`contracts/ThresholdSignatures.sol:51-56`,
`contracts/AttestationRegistry.sol:87-91`, `contracts/CuratorSet.sol:109-117`).
Une signature sur le condensé nu ne vérifie pas.

**EX-6.15 (RG-12, signature)** Une signature est une signature ECDSA
secp256k1 du hachage signé, de forme canonique : `r` dans `[1, n − 1]`, `s`
dans `[1, n/2]` (`n/2` =
`0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0`,
`contracts/ThresholdSignatures.sol:47`), `v` égal à 27 ou 28. Elle se passe
au contrat sous la forme `(v, r, s)` et s'écrit dans un document sur 65
octets `r ‖ s ‖ u8(v)`. La clé publique se recouvre du hachage signé avec
l'identifiant de récupération `v − 27` ; l'adresse est les 20 derniers octets
du `keccak256` des 64 octets de la clé publique non compressée, sans son
préfixe `04` ; elle est celle du signataire déclaré.
Un outil ne produit ni n'accepte une signature à `s` haut, même pour
`AttestationRegistry` et `CuratorSet`, qui l'accepteraient (5.4).

**EX-6.16 (RG-13, jeu de signatures au seuil)** Pour `submitPeriod`,
`registerRecorder` et `revokeRecorder`, l'outil joint exactement `t`
signatures, `t` étant le seuil du jeu de l'organisation lu à la hauteur où
il construit la transaction, de `t` signataires distincts déclarés membres du
jeu, rangées par adresse de signataire croissante (comparaison des écritures
hexadécimales minuscules). Le contrat accepte tout ordre, au moins `t`
signatures, et ignore celles qui suivent la `t`-ième valide
(`contracts/ThresholdSignatures.sol:63-64`, `:68-102`) : l'ordre croissant
est une convention des outils, qui rend la transaction reproductible. RG-13
et OP-7 rendent `echoue` sur un ordre non croissant avant l'envoi (motif
`ordre_signatures` pour RG-13, code `signature_non_canonique` pour OP-7,
7.3) ; la relecture d'une transaction déjà incluse (6.6.4, EX-A.4, CP-4 et
CP-5, contrôle 8 de CT-6) n'en refuse pas l'ordre : RG-13 y est consignée
`echoue` sans invalider la transaction, et le contrôle 8, qui ne lit que les
événements et les certificats, n'a rien à en refuser. L'appartenance au jeu
est un fait d'état, que RG-13 ne prouve pas.

#### 6.6.4 Exemples

Les trois transactions suivantes sont celles de la capture publique de CT-6
(`spec/vecteurs/ct-6/registre/capture/`) ; leurs octets bruts sont dans le
corps signé de la proposition de chaque certificat, et chaque valeur
ci-dessous a été recalculée depuis eux pour cette spécification. Identifiant
EVM 2124, contrats du réseau de développement (5.3), approbateurs Hardhat 1
et 2 du jeu de `assureur-demo` (seuil 2).

`submitPeriod`, bloc 16668, transaction
`0xd9fb0d69567fa4f5ecbf51179198fa02f30524a3275678405cfc11307374bbc0`,
`uri` vide :

```text
E(meta)       = 0000000000000000000000000000000000000000000000000000000000000020
                a581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab   orgId
                41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164   journalId
                ae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914   periodHash
                b16c288f2864e5e311646bc4af84e2752f0fe1f71266841ce65ddb28fa21298b   root
                000000000000000000000000000000000000000000000000000000006aec4590   periodStart 1793869200
                000000000000000000000000000000000000000000000000000000006aec53a0   periodEnd   1793872800
                0000000000000000000000000000000000000000000000000000000000000001   firstSeq
                0000000000000000000000000000000000000000000000000000000000000009   lastSeq
                0000000000000000000000000000000000000000000000000000000000000000   version
                0000000000000000000000000000000000000000000000000000000000000140   position de uri
                0000000000000000000000000000000000000000000000000000000000000000   longueur de uri
              (384 octets)
keccak256(E)  = 0x41736cf76da6bd1017655efe478045529617cf26e91f7a76adc1a80aff0bf133
préimage      = 000000000000000000000000000000000000000000000000000000000000084c
                4ee6ecad1c2dae9f525404de8555724e3c35d07b
                6e6f6f7274726163652d706572696f6465
                41736cf76da6bd1017655efe478045529617cf26e91f7a76adc1a80aff0bf133   (101 octets)
periodDigest  = 0x21c3fd75e15d573638a5c3ec46e986cffec31b2c7b359e1f586da03022491674
hachage signé = 0x89072ae7b6c13cf3d65d0215ee3dce6e1c533a393877e33314574e3cf9b1936e
signatures    = (v 28, r 0x4937ed029f4003dbe1e83311b9a9c3f98eb28ed6d1bfe01d425d8b618c60bcd2,
                       s 0x342d5e58a71eaec4a6ed532d450a1f7c215ca4ea9b18a3e009394b53c5ea1fe8)
                  -> 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 (Hardhat 1)
                (v 27, r 0x612963407511b7d05170e3e6b9dd2ef850d0f5ea7f5a29d7d1c8d1945ddee5cc,
                       s 0x39f64d25f34d9594adccb389562f49791c39f8806748a0551878fdfc7e1f9dfa)
                  -> 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc (Hardhat 2)
```

Les signatures de cette transaction, antérieure à cette spécification, ne
sont pas rangées par adresse croissante : le contrat l'a acceptée, et un
outil conforme les aurait rangées autrement (RG-13).

`anchor`, bloc 16660, transaction
`0x70edd263160e4fcd6c6887ac21daf4556720ef662facdf9bb12292366f120779` :

```text
préimage      = 000000000000000000000000000000000000000000000000000000000000084c
                f4b146fba71f41e0592668ffbf264f1d186b2ca8
                6e6f6f722d6174746573746174696f6e2d616e637265
                3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6   empreinte (RG-4)
                2970f32daf26845541b559f8505ddade17ab51994fab81cbfe0dbd81ab9671ee   docType   (138 octets)
anchorDigest  = 0xb1eb8a317f588d9484ebf839effd88727b92525bdb487402c57a7f5a1fc8cbe9
hachage signé = 0xb56e7a39c5cb2baab700bf0ea017ed29e441c4b451cd1d5fe37c47eae0dc320a
signature     = (v 28, r 0x51412a0867e5a514a48b3f5bb1be9f72c249fe707ecd459faef9cd9309f92c0b,
                       s 0x114b2aba6d972afbbd2e1a9b78f364fcccbc40252d67a01946291be59b8a42c4)
                  -> 0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49 (clé de chaîne de rec-test-02)
```

`registerRecorder`, bloc 16648, transaction
`0x932ae471728698ae648a109858081ccfadbf20e472bd85cdc47115550dc85158`, clé
`rec-test-01`
(`0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045`)
sous la clé de chaîne `0xaa2a59656361352e96ef2eed355316ef8b29dab7`, journal
`journal-sinistres` : préimage de 198 octets, `registerDigest` =
`0x90362e40306221d7f95b803857dab38f80d1ddb9b59c51441f464cb0334d1108`,
hachage signé
`0x42a30faa83ec49fa894c8ad6fd5c6735dab9fdc9ada2dc3f232cf76ea9947856`,
signataires Hardhat 1 puis Hardhat 2.

Deux condensés sans transaction, calculés pour cette spécification :
`revokeDigest` de RecorderRegistry pour la même clé de chaîne, `registeredAt`
= `0x6ada8c36` (1792707638, horodatage du bloc 16648) : préimage de 142
octets, condensé
`0x63e4dfd071d6f365a39772d9ca34e9791f6426e9dfc654178d280c9a1152b9df` ;
`adminOpDigest` de `proposeAdminSigned` sur le `CuratorSet` de
`assureur-demo` (`0xc0f115a19107322cfbf1cdbc7ea011c19ebdb4f8`,
`spec/vecteurs/ct-6/registre/capture/capture.json`) vers le compte Hardhat 3,
au nonce 0 : préimage de 148 octets, condensé
`0xd0840fa693828406974358cd14061f33c59a826cc51f954f39972f615b816be2`.

### 6.7 Encodage des appels

#### 6.7.1 Sélecteurs

Le sélecteur d'une fonction est les quatre premiers octets de
`keccak256(utf8(signature))`, la signature s'écrivant sans espace avec les
types canoniques, un `struct` comme un tuple.

| Signature | Sélecteur |
|---|---|
| `anchor(bytes32,bytes32,address,(uint8,bytes32,bytes32))` | `0x73deb4ad` |
| `revoke(bytes32,(uint8,bytes32,bytes32))` | `0x7e9d5abd` |
| `submitPeriod((bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint64,uint32,string),(uint8,bytes32,bytes32)[])` | `0x8af03732` |
| `registerRecorder(bytes32,bytes32,address,bytes32,(uint8,bytes32,bytes32)[])` | `0x982f962e` |
| `revokeRecorder(bytes32,address,(uint8,bytes32,bytes32)[])` | `0x7b2025ea` |
| `setCuratorSet(bytes32,address)` | `0x53823884` |
| `proposeAdmin(address)`, `acceptAdmin()` (registre et jeu) | `0x147bf6c4`, `0x0e18b681` |
| `addCuratorSigned(address,uint256,(uint8,bytes32,bytes32))` | `0xd3dc8837` |
| `removeCuratorSigned(address,uint256,(uint8,bytes32,bytes32))` | `0xa7484439` |
| `setThresholdSigned(uint256,uint256,(uint8,bytes32,bytes32))` | `0xf4db2a99` |
| `proposeAdminSigned(address,uint256,(uint8,bytes32,bytes32))` | `0x34e182a6` |
| `acceptAdminSigned(uint256,(uint8,bytes32,bytes32))` | `0x7af25fd9` |
| `periodDigest((bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint64,uint32,string))` | `0x113946de` |
| `registerDigest(bytes32,bytes32,address,bytes32)`, `revokeDigest(bytes32,address)` | `0xeeaa91a2`, `0x77bd6e5b` |
| `anchorDigest(bytes32,bytes32)`, `revokeDigest(bytes32)` | `0x5fa9b02d`, `0x45226438` |
| `adminOpDigest(bytes32,bytes32,uint256)`, `opNonce()`, `pendingAdmin()` | `0xe3dd717d`, `0x969ea86b`, `0x26782247` |
| `curatorSetOf(bytes32)`, `isRegistered(bytes32)`, `admin()` | `0x0642c24a`, `0x27258b22`, `0xf851a440` |
| `isCurator(address)`, `getThreshold()`, `getCuratorCount()` | `0x6c7b79d4`, `0xe75235b8`, `0xc097c07f` |
| `lookup(bytes32)`, `isAnchored(bytes32)` | `0xf39ec1f7`, `0x4f0b5801` |
| `getPeriod(uint256)`, `latestPeriodOf(bytes32,bytes32)`, `isKnown(bytes32,bytes32)` | `0x4b2c0706`, `0x9992f0d9`, `0x1a6a514c` |
| `isActiveRecorder(bytes32,address)`, `recorderOf(bytes32,address)`, `recorderByPubKey(bytes32,bytes32)` | `0x0d219123`, `0x98022b90`, `0xb0732ef4` |

#### 6.7.2 Arguments

Règles de l'ABI de Solidity, restreintes aux types du registre. Un mot fait
32 octets.

1. **Valeurs statiques.** `bytes32` : ses 32 octets. `address` : 12 octets
   nuls ‖ `a20`. `uint8`, `uint32`, `uint64`, `uint256` : `u256` de la
   valeur. Le tuple `Signature` `(uint8 v, bytes32 r, bytes32 s)` est
   statique : trois mots `u256(v) ‖ r ‖ s`, en place.
2. **Valeurs dynamiques.** Une `string` s'encode `u256(longueur) ‖ octets`,
   complétés par des octets nuls jusqu'à un multiple de 32 (rien après la
   longueur si elle est nulle). Un tableau `Signature[]` s'encode
   `u256(k) ‖` les `k` tuples de trois mots ; un tableau `address[]`
   s'encode `u256(k) ‖ k × (12 octets nuls ‖ a20)`. Un tuple qui contient
   une valeur dynamique est dynamique.
3. **Suite de valeurs** (les arguments d'un appel, les champs d'un tuple) :
   une tête, puis une queue. Dans la tête, chaque valeur statique est en
   place et chaque valeur dynamique est remplacée par un mot `u256(o)`, où
   `o` est la distance en octets entre le début de la tête et le début de
   son encodage dans la queue ; la queue concatène, dans l'ordre, les
   encodages des valeurs dynamiques.
4. **`PeriodMeta`.** `T(meta)` = `b32(orgId) ‖ b32(journalId) ‖
   b32(periodHash) ‖ b32(root) ‖ u256(periodStart) ‖ u256(periodEnd) ‖
   u256(firstSeq) ‖ u256(lastSeq) ‖ u256(version) ‖ u256(0x140) ‖
   encodage de uri`, de longueur `L = 352 + 32 × ⌈longueur(uri) / 32⌉` octets.
   `E(meta) = abi.encode(meta) = u256(0x20) ‖ T(meta)` (une seule valeur,
   dynamique) ; 384 octets pour une `uri` vide.
5. **Données d'appel** = sélecteur ‖ suite des arguments (règle 3).

| Appel | Données d'appel | Octets |
|---|---|---|
| `anchor` | `0x73deb4ad ‖ fingerprint ‖ docType ‖ issuer ‖ v ‖ r ‖ s` | 196 |
| `revoke` | `0x7e9d5abd ‖ fingerprint ‖ v ‖ r ‖ s` | 132 |
| `registerRecorder` | `0x982f962e ‖ orgId ‖ journalId ‖ chainKey ‖ ed25519PubKey ‖ u256(0xa0) ‖ u256(k) ‖ k × (v ‖ r ‖ s)` | 196 + 96k |
| `revokeRecorder` | `0x7b2025ea ‖ orgId ‖ chainKey ‖ u256(0x60) ‖ u256(k) ‖ k × (v ‖ r ‖ s)` | 132 + 96k |
| `submitPeriod` | `0x8af03732 ‖ u256(0x40) ‖ u256(0x40 + L) ‖ T(meta) ‖ u256(k) ‖ k × (v ‖ r ‖ s)` | 100 + L + 96k |
| `setCuratorSet` | `0x53823884 ‖ orgId ‖ curatorSet` | 68 |
| `addCuratorSigned`, `removeCuratorSigned`, `proposeAdminSigned` | sélecteur `‖ adresse ‖ u256(nonce) ‖ v ‖ r ‖ s` | 164 |
| `setThresholdSigned` | `0xf4db2a99 ‖ u256(t) ‖ u256(nonce) ‖ v ‖ r ‖ s` | 164 |
| `acceptAdminSigned` | `0x7af25fd9 ‖ u256(nonce) ‖ v ‖ r ‖ s` | 132 |

Pour un déploiement, les données de la transaction sont le code de création
issu de la compilation (EX-5.8) suivi de la suite des arguments du
constructeur selon la règle 3 : un mot (12 octets nuls ‖ `a20`) pour
`CuratorSetRegistry`, `PeriodRegistry` et `RecorderRegistry` ; pour
`CuratorSet(address initialAdmin, address[] initialCurators, uint256
initialThreshold)` (5.1), `12 octets nuls ‖ a20(initialAdmin) ‖ u256(0x60) ‖
u256(initialThreshold) ‖ u256(k) ‖ k × (12 octets nuls ‖ a20)`, soit
128 + 32k octets (224 pour k = 3, cas `constructeur-curator-set` de
`appels.json`) ; ce code n'est pas reproduit ici.

**EX-6.17 (RG-14, données d'appel)** Les données d'appel d'une
transaction du registre sont celles de la table, construites depuis des
valeurs qui ont passé RG-1 à RG-13. Exemple : les données d'appel de la
transaction `submitPeriod` du bloc 16668 (644 octets, `uri` vide, `k = 2`,
signatures dans l'ordre de la transaction) commencent par
`0x8af03732 ‖ u256(0x40) ‖ u256(0x1a0)` et sont égales, octet pour octet, à
l'encodage de 6.6.4 ; de même les 196 octets de l'`anchor` du bloc 16660 et
les 388 octets du `registerRecorder` du bloc 16648.

#### 6.7.3 Transaction

Une transaction de type 2 (EIP-1559, enveloppe EIP-2718) se sérialise
`0x02 ‖ RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit,
to, value, data, accessList, yParity, r, s])` et se signe sur
`keccak256(0x02 ‖ RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
gasLimit, to, value, data, accessList]))` (go-ethereum v1.17.0,
`core/types/tx_dynamic_fee.go:28-43`, `:119-141`,
`core/types/transaction.go:125-140`, `core/types/hashing.go:68-76`). Les
entiers s'encodent en RLP sur leurs octets grand-boutistes minimaux, `to`
sur 20 octets (chaîne vide pour une création), `data` comme une chaîne, la
liste d'accès vide comme la liste vide `0xc0` ; règles RLP : CT-6 EX-11.5,
règle 1. La signature `(yParity, r, s)` a `yParity` dans {0, 1}, `r` et `s`
dans `[1, n − 1]` et `s ≤ n/2` (go-ethereum v1.17.0,
`crypto/crypto.go:240-251`). L'adresse d'un contrat
créé par l'expéditeur `a` à son nonce `x` est les 20 derniers octets de
`keccak256(RLP([a20(a), x]))` (`crypto/crypto.go:79-82`).

**EX-6.18 (RG-15, transaction)** Une transaction qu'envoie un outil de CT-4
est de type 2, de `chainId` égal à `evm_chain_id`, `maxPriorityFeePerGas` et
`maxFeePerGas` égaux entre eux et à 1, ou, pour le remplacement d'une
transaction au même nonce, à `⌈1,1 × p⌉` où `p` est la valeur de la
transaction remplacée (EX-4.15), `gasLimit` égal à `fees.gas_limit` et au plus
2^24, liste d'accès vide, signature canonique, et selon son objet : appel,
`to` égal à l'adresse du contrat en service visé, `value` nul et `data`
conforme à RG-14 ; déploiement, sans `to`, `value` nul et `data` égal au code
de création suivi des arguments du constructeur (6.7.2) ; approvisionnement,
`to` égal à l'expéditeur approvisionné, `value` au plus sa provision
(EX-4.19) et `data` vide. Son hachage est `keccak256` de sa sérialisation.

Exemple : l'`anchor` de 6.6.4 envoyé par la clé de chaîne elle-même, au
nonce 0 (clé de test de `spec/vecteurs/ct-6/registre/capture/CAPTURE.md`,
« Clés » : SHA-256 de `noortrace/vecteurs/v0/cle-chaine/rec-test-02`),
signature déterministe RFC 6979 :

```text
à signer      = 02 f8e7 82084c 80 01 01 832dc6c0 94f4b146fba71f41e0592668ffbf264f1d186b2ca8 80
                b8c4 <196 octets de données d'appel de l'anchor du bloc 16660> c0
hachage       = 0xedc5604b7cf7f755d1ba4237b5b1747f80b30ae6888848dcdbd9daa0630e9285
signature     = yParity 0,
                r 0x7577245b23f1d694f210238c116bb9403ddadfb3ca179883eea16d33f76fdc36,
                s 0x4445616640463df38baf6a37291df36d3295d8c4bb53c09ae29e43c468efdce9
transaction   = 0x02f9012a82084c800101832dc6c094f4b146fba71f41e0592668ffbf264f1d186b2ca880b8c4…c080a0…a0…  (302 octets)
hachage de la transaction = 0xf78912922ae35ecc19994b2c3ed8d5d7c53cd3702bb5f03ce5455c6b54eb486b
```

Les transactions de la capture de CT-6 ont été envoyées avec les frais par
défaut d'ethers (plafond 3, pourboire 1) par le compte Hardhat 0 : elles
sont antérieures à EX-4.15 et ne passent pas RG-15.

### 6.8 Manifeste d'instance

**EX-6.19 (RG-16, forme et révisions)** Le manifeste est conforme à
`instance-registre-v0` ; `revision` vaut 1 et `previous_sha256` est nul, ou
`revision` vaut `r + 1` et `previous_sha256` est le SHA-256 des octets du
fichier de la révision `r` ; `published_at` ne précède pas celui de la
révision précédente. Un document non conforme à son schéma n'est pas un
manifeste : RG-16 rend `echoue` (motif `schema`), et RG-17 à RG-20, qui
portent sur « le manifeste », rendent `echoue` avec lui, sans ancre dérivée.

**EX-6.20 (RG-17, genèse et identifiants)** Le SHA-256 des octets du
document de genèse publié est `genesis.sha256` ; le document a la forme de
4.2 et sa section `rules` les valeurs d'EX-4.2 ; la ligne de règles
recalculée selon EX-4.3 est `genesis.rules_line` ; `rules.chainId` est
`bft_chain_id`, le `chainId` de tête est `evm_chain_id`, et le nombre que
porte `bft_chain_id` est `evm_chain_id` (EX-4.6) ; `genesis.alloc_total_wei`
est la somme des `balanceWei`.

**EX-6.21 (RG-18, jeux de validateurs)** Pour chaque jeu : au moins quatre
validateurs, identifiants non vides et distincts, clés distinctes qui sont
des points de secp256k1 ; `valset_hash` égal au hachage recalculé selon CT-6
EX-11.8 sur les clés telles que déclarées ; `operators` nomme chaque
validateur du jeu une fois et rien d'autre ; `from_height ≤ to_height` quand
`to_height` n'est pas nul ; les intervalles ne se recouvrent pas et le premier
commence à 1. Pour une instance de production, en plus : aucun opérateur et
aucun site ne porte plus de `f = ⌊(N − 1)/3⌋` validateurs du jeu (EX-4.12).

**EX-6.22 (RG-19, contrats)** Pour chaque contrat : `address` est l'adresse
de création de `deployer` à `nonce` (6.7.3) ; les arguments du constructeur
sont ceux d'EX-5.2 (`initialAdmin` pour `CuratorSetRegistry`, l'adresse du
`CuratorSetRegistry` en service pour `PeriodRegistry` et
`RecorderRegistry`) ; chacun des quatre noms a exactement un contrat de
`to_height` nul ; si `evidence` n'est pas nul, le SHA-256 de l'index de
capture est celui déclaré, l'index a le rôle `deploiement`, et ses
`contract`, `transaction_hash`, `block_number` et `block_hash` égalent
`address`, `transaction_hash`, `block_number` et `block_hash` du contrat ;
ses fichiers passent CP-2, CP-3 et CP-6 (9.4), et CP-4 contre le jeu du
manifeste dont l'intervalle contient la hauteur ; le reçu de la transaction
de déploiement a `status` `0x1` ; dans le corps signé de la proposition du
certificat, l'élément `transaction_index` des transactions brutes du bloc
(membre `txsRaw` du corps JSON de la proposition, 9.2 : tableau de chaînes,
une transaction par élément dans l'ordre du bloc, base64 standard de
l'encodage binaire de 6.7.3, lu selon la tolérance de CT-6 EX-11.6 ;
l'existence de ces transactions est constatée par CT-6 EX-11.2, leur nom de
membre par le code de noorcore et par les lignes capturées) a pour hachage
`transaction_hash`, n'a pas de destinataire, est signé par `deployer` au
nonce `nonce`, et la racine de ces transactions, calculée comme celle des
reçus (CT-6 EX-11.5, règle 4, la valeur de rang `i` étant l'encodage binaire
de la transaction `i`, 6.7.3), égale `transactionsRoot` de l'en-tête (noorcore
la calcule ainsi, `core/node/blockexec.go:544` ; recalcul vérifié pour cette
spécification sur les blocs 16648, 16660 et 16668 de la capture de CT-6).
Pour une instance de production, `block_hash` et `evidence` ne sont jamais
nuls. La vérification du certificat contre un jeu de validateurs se
fait comme au contrôle 8, avec le jeu que le réviseur a obtenu des
opérateurs (CT-6 §12.5).

**EX-6.23 (RG-20, ancre du réviseur)** L'ancre `registry` du fichier
d'ancres de CT-6 (§12.2) se dérive du manifeste ainsi : `chain_id` =
`bft_chain_id` ;
`contracts.period_registry`, `attestation_registry`, `recorder_registry`,
adresses des contrats de ces noms en service ; `validator_sets`, pour chaque
jeu, ses seuls membres `from_height`, `to_height`, `validators` et `source` ;
`source` à la discrétion du réviseur. Un nom qui n'a pas exactement un
contrat en service rend la dérivation impossible (RG-20 `echoue`, motif
`derivation_impossible`, toujours après `contrats_en_service` de RG-19) ;
l'ancre dérivée n'est rendue que si RG-20 réussit ; une ancre fournie est
comparée à l'ancre dérivée, membres `source` exceptés. La dérivation ne
remplace pas le recoupement : les jeux viennent d'au moins deux opérateurs de
validateurs indépendants, et les adresses se recoupent avec leurs
transactions de déploiement dans des blocs certifiés (CT-6 §12.5).

### 6.9 Vérifications RG-

| Id | Vérification | Entrées | Règle | Motifs d'échec |
|---|---|---|---|---|
| RG-1 | Slug et `org_id` | slug | EX-6.2 | `slug_invalide` |
| RG-2 | Nom de journal et `journal_id` | nom | EX-6.4 | `nom_journal_invalide` |
| RG-3 | `docType` | libellé, ou valeur | EX-6.5 | `libelle_invalide`, `libelle_hors_table`, `doctype_nul`, `doctype_hors_table` |
| RG-4 | Empreinte d'ancre | `org_id`, `journal_id`, `periodHash`, empreinte déclarée facultative | EX-6.7 | `entree_nulle`, `empreinte_differente` |
| RG-5 | Champs d'une clôture | manifeste de période, `uri`, période précédente si connue | EX-6.8 | `periode_invalide`, `discontinuite_temporelle`, `discontinuite_sequence` |
| RG-6 | `periodDigest` | identifiant EVM, adresse, `PeriodMeta`, condensé déclaré facultatif | EX-6.9 | `entree_invalide` (entrée hors de sa forme), `condense_different` |
| RG-7 | `registerDigest` | identifiant EVM, adresse, `org_id`, `journal_id`, clé de chaîne, clé Ed25519 | EX-6.10 | `entree_invalide` (un des quatre champs nul), `condense_different` |
| RG-8 | `revokeDigest` d'enregistreur | identifiant EVM, adresse, `org_id`, clé de chaîne, `registeredAt` | EX-6.11 | `entree_invalide` (`registeredAt` nul), `condense_different` |
| RG-9 | `anchorDigest` | identifiant EVM, adresse, empreinte, `docType` | EX-6.12 | `entree_invalide`, `condense_different` |
| RG-10 | `revokeDigest` d'attestation | identifiant EVM, adresse, empreinte | EX-6.13 | `entree_invalide`, `condense_different` |
| RG-11 | `adminOpDigest` | identifiant EVM, adresse du jeu, opération, argument, nonce | EX-6.14 | `entree_invalide` (opération inconnue), `condense_different` |
| RG-12 | Hachage signé et signature | condensé interne, signature, signataire déclaré, hachage signé déclaré facultatif | EX-6.15 | `signature_non_canonique`, `signataire_different`, `hachage_signe_different` |
| RG-13 | Jeu de signatures au seuil | signatures, signataires, seuil | EX-6.16 | `signataire_hors_jeu`, `signataire_double`, `ordre_signatures`, `nombre_signatures` ; une signature refusée par RG-12 garde le motif de RG-12 |
| RG-14 | Données d'appel | fonction, arguments, données déclarées facultatives | EX-6.17 | `entree_invalide`, `donnees_differentes` |
| RG-15 | Transaction | transaction sérialisée, contexte (identifiant EVM, `fees`, objet, destinataire, données, provision, frais remplacés) | EX-6.18 | `transaction_illisible`, `type_non_admis`, `chaine_differente`, `frais_non_conformes`, `limite_gaz`, `liste_acces`, `signature_non_canonique`, `objet_non_conforme` |
| RG-16 | Forme et révisions du manifeste | manifeste, révision précédente | EX-6.19 | `schema`, `revision_mal_chainee` |
| RG-17 | Genèse et identifiants | manifeste, document de genèse | EX-6.20 | `genese_differente`, `genese_invalide`, `regles_invalides`, `ligne_regles_differente`, `identifiants_incoherents`, `offre_differente` |
| RG-18 | Jeux de validateurs | manifeste | EX-6.21 | `jeu_invalide`, `valset_hash_different`, `operateurs_incoherents`, `intervalles_incoherents`, `domaine_de_panne` |
| RG-19 | Contrats | manifeste, index de capture et fichiers capturés | EX-6.22 | `contrats_en_service`, `adresse_creation`, `arguments_constructeur`, `preuve_absente`, `preuve_invalide` |
| RG-20 | Ancre du réviseur | manifeste, ancre `registry` facultative | EX-6.23 | `derivation_impossible` (jamais première vérification en échec : RG-19 `contrats_en_service` la précède), `ancre_differente` |

Chaque vérification rend `reussi` ou `echoue` ; en échec, elle porte un
motif de la colonne « Motifs d'échec », un identifiant stable que les
vecteurs de l'annexe A reportent dans `refusal.code`, et qu'un vérificateur
confronte comme le verdict (EX-A.3). Les motifs s'évaluent dans l'ordre où
leur règle les énonce et la première vérification en échec arrête le cas ;
RG-14 ne juge que l'encodage, depuis des valeurs tenues pour conformes, et
renvoie à RG-1 à RG-13 pour les valeurs elles-mêmes ; RG-13 est une
vérification distincte de RG-12, consignée `echoue` sur l'ordre même d'une
transaction déjà incluse (EX-6.16). Le motif `entree_invalide` de RG-6, RG-9
et RG-10 (entrée hors de sa forme : adresse qui n'a pas 20 octets, empreinte
qui n'en a pas 32) n'est pas exercé par un vecteur, le format des vecteurs
supposant des entrées bien formées. Les vecteurs donnent, pour chaque
vérification, des cas qui réussissent et des cas qui échouent, avec la valeur
attendue.

## 7. Inscription d'un client, pas à pas

Cette section suffit, avec les sections 4 à 6, pour inscrire un client sur
une instance, inscrire la clé de son enregistreur, ancrer la racine d'une
première période et clore cette période. Chaque pas donne la commande de
l'outil de référence, ce qu'elle vérifie avant d'écrire, ce qu'elle écrit, sa
sortie et ses erreurs. Les rôles sont ceux de la section 3 ; l'instance, ses
identifiants, ses frais et ses comptes, ceux de la section 4 ; les contrats et
leurs adresses, ceux de la section 5 ; les identifiants, les condensés signés
et les empreintes, ceux de la section 6.

### 7.1 Vue d'ensemble

| Pas | Étape (`step` du dossier) | Acteur | Transaction | Signatures hors chaîne | Commande |
|---|---|---|---|---|---|
| 1 | préparer le dossier d'inscription | exploitant, client | — | — | `inscrire-client --preparer` |
| 2 | `jeu_approbateurs` : déployer le `CuratorSet` du client | déployeur de l'exploitant | création `CuratorSet(clé de gouvernance, membres, seuil)` | — | `inscrire-client --dossier` |
| 3 | `assignation` | administrateur du registre | `setCuratorSet(orgId, jeu)` | — | idem |
| 4 | `lecture_jeu` : relire le jeu comme CT-3 le lira | outil | — | — | idem |
| 5 | `approvisionnement` de chaque clé de chaîne | trésorerie | virement de NUR (`value`, données vides, RG-15) | — | idem |
| 6 | `inscription` de chaque clé d'enregistreur | approbateurs, clé de chaîne | `RecorderRegistry.registerRecorder` | condensé d'inscription, au seuil | `condense inscription`, `signer`, `inscrire-cle` |
| 7 | manifeste de la première période | enregistreur (CT-2) ; `manifeste-essai` sur le réseau de développement | — | signature Ed25519 du manifeste (CT-1 §10) | `manifeste-essai` |
| 8 | `premiere_ancre` | clé de chaîne | `AttestationRegistry.anchor` | condensé d'ancre, par la clé de chaîne | `ancrer` |
| 9 | `premiere_cloture` | approbateurs, clé de chaîne | `PeriodRegistry.submitPeriod` | condensé de clôture, au seuil | `condense cloture`, `signer`, `clore` |
| 10 | exporter et vérifier les parties du registre | outil, client | — | — | `exporter`, `verifier` |

Chaque transaction est capturée dès son reçu (section 9) ; les pas 2 à 5
s'exécutent par une seule commande, qui s'arrête au premier refus et reprend
au pas où elle s'est arrêtée (7.11).

### 7.2 Outil de référence

L'outil de référence est `scripts/registre/noortrace-registre.mjs` (Node.js
et ethers, sans Hardhat à l'exécution ; ABI lues dans `hh-artifacts/`, donc
après `npm run compile`). Il suit cette section pas à pas et réutilise les
fonctions de `scripts/lib/noortrace.mjs`, `scripts/lib/journal.mjs`,
`scripts/lib/registre.mjs` et `scripts/lib/certificat-commit.mjs` ; il ne
change le comportement ni de `scripts/deploy/` ni de `scripts/e2e/` (les
quatre fichiers que le lot touche hors de la spécification sont nommés en
section 0 et 13).

```text
node scripts/registre/noortrace-registre.mjs <commande> [options]
```

L'outil, le générateur des vecteurs et les tests valident les documents par
`validerSchema` de `scripts/lib/journal.mjs`, qui met en œuvre un sous-ensemble
fermé de JSON Schema 2020-12 (`$ref`, `type`, `const`, `enum`, `pattern`,
`minLength`, `maxLength`, `minimum`, `maximum`, `multipleOf`, `required`,
`minProperties`, `propertyNames`, `properties`, `additionalProperties`,
`prefixItems`, `items`, `minItems`, `maxItems`, `uniqueItems`, `allOf`,
`anyOf`, `oneOf`, `not`, `if`, `then`, `else`) et ignore sans bruit tout
autre mot-clé. Les trois schémas de CT-4 n'emploient hors de ce sous-ensemble
que les quatre `contains` d'`instance-registre-v0` (`contracts` : les quatre
noms présents), que RG-16 vérifie explicitement ; `test/registreCt4.test.js`
inventorie les mots-clés des trois schémas (`motsClesHorsSousEnsemble`) et
échoue sur tout autre mot-clé, pour qu'un schéma ne soit jamais appliqué en
partie sans que personne le sache. La validation de référence des exemples
imprimés est celle d'`ajv-cli` 5 (`spec/README.md`), exécutée à la main, hors
de l'intégration continue, qui n'installe pas `ajv` (il n'est pas une
dépendance du dépôt).

**EX-7.1** Options communes à toutes les commandes qui lisent la chaîne :

| Option | Défaut | Rôle |
|---|---|---|
| `--instance <fichier>` | voir EX-7.2 | manifeste d'instance (`instance-registre-v0`, 4.8), révision en vigueur : identifiants, genèse, adresses, jeux de validateurs, frais, comptes de l'exploitant |
| `--rpc <url>[,<url>…]` | `http://127.0.0.1:8645` | points JSON-RPC de **validateurs** (jamais de suiveurs, OP-2) ; une transaction est soumise à chacun, les lectures et la capture se font au premier qui répond ; sur une instance de `nature` `production`, `http://` n'est admis que vers `127.0.0.1`, `::1` ou `localhost` (tunnel ou mandataire local, EX-10.8), sinon OP-2 refuse (`noeud_injoignable`) |
| `--jeton <env:VARIABLE \| fichier:chemin>` | — | jeton `NOOR_HTTP_AUTH_TOKEN` du nœud (EX-10.3), envoyé en `Authorization: Bearer` à chaque point `--rpc` ; jamais en clair sur la ligne de commande, jamais écrit dans un envoi ni une sortie |
| `--captures <répertoire>` | obligatoire pour une commande qui envoie une transaction | où l'outil écrit les envois (`envoi-<hachage>.json`), leur issue connue (`issue-<hachage>.json`, `#/$defs/issue`, 8.6), les envois refusés par tous les points (`refus-envoi-<hachage>.json`, 7.11), les demandes de clôture relayées (`demande-cloture-<periodHash>.json`, EX-8.19), les réponses brutes et les index de capture (9.4) |
| `--delai <secondes>` | `120` | attente du reçu, sondé toutes les 100 ms (8.6) |
| `--dossier <fichier>` | — | dossier d'inscription (`inscription-client-v0`) à lire et à mettre à jour |

**EX-7.2** Sans `--instance`, l'outil n'admet que le réseau de développement :
il lit `deployments/noorcore.json` (écrit par
`scripts/deploy/deploy-noortrace.mjs`), prend l'identifiant EVM 2124 et
l'identifiant BFT `noortrace-2124-dev` (`chain/README.md`, « Identifiants »),
le document de genèse `chain/config/alloc-dev.json`, les `fees` par défaut de
4.8 et le jeu `chain/runtime/validators.json` à partir de la hauteur 1
(EX-4.26), et écrit `manifest_sha256: null` dans le dossier. Il refuse ce
défaut (`reseau_non_developpement`) si `eth_chainId` ne vaut pas `0x84c`.

**EX-7.3** Une clé se désigne par une référence, jamais par sa valeur en
ligne de commande : `fichier:<chemin>` (clé secp256k1 de 32 octets en
hexadécimal, fichier lisible de son seul propriétaire, sinon refus),
`env:<VARIABLE>`, `graine:<chemin>` (graine Ed25519 de 32 octets, CT-1 §6),
ou `hardhat:<i>` (compte `i` de la mnémonique publique `test test … junk`,
`m/44'/60'/0'/0/i`). Les références de clés de test `hardhat:` et `graine:`,
quelle que soit l'option qui les porte (`--deployeur`, `--administrateur`,
`--tresorerie`, `--relayeur`, `--exploitant`, `--cle`, `--cle-chaine`,
`--expediteur`, `--graine`), les commandes `cles-essai` et `manifeste-essai`,
l'option `--cles-essai` et `signer` avec `hardhat:` ne sont admis que pour une
instance de `nature` `developpement` dont l'identifiant EVM est 2124 (réseau
de développement, EX-7.2) ou 31337 (réseau Hardhat en mémoire des tests,
EX-A.6) ; l'option `--sans-capture`, elle, reste propre à 31337 (EX-A.6).
En production, les clés sont gardées selon CT-2 §11 et CT-7, et les
approbateurs signent dans leur portefeuille (CT-3 §13), en suivant EX-7.10 ;
`signer` est l'outil de développement : il écrit sur la sortie d'erreur les
champs en clair de la demande (`fields`, `signer_set`) avant de signer, mais
n'affiche rien dans un portefeuille. `fichier:` et `env:` chargent la clé en
mémoire : ils correspondent à la classe de garde D de CT-2 §11.2 et ne sont
admis en production que pour une clé de chaîne via le backend de
l'enregistreur (classes A à C, CT-2 EX-11.19), jamais pour l'administrateur
du registre ni la trésorerie, dont la signature externe est une proposition
(section 14). Les comptes de l'exploitant se désignent par rôle (EX-3.1) :
`--deployeur`, `--administrateur` (administrateur du registre),
`--tresorerie`, `--relayeur` ; `--exploitant <référence>` les désigne tous à
la fois et n'est admis que sur ces deux réseaux, où le compte Hardhat 0 tient
les quatre rôles. Avec un manifeste, chaque adresse est celle de son rôle
dans `accounts` à la tête (OP-5).

**EX-7.4** La sortie standard d'une commande est un seul objet JSON
conforme à `operations-registre-v0.schema.json#/$defs/sortie` ; les messages
d'avancement vont sur la sortie d'erreur. `result` et `exit_code` :

| `result` | `exit_code` | Sens |
|---|---|---|
| `reussi` | 0 | l'étape est faite, chaque vérification de `checks` a réussi |
| `deja_fait` | 0 | l'état de la chaîne montre l'étape déjà faite par cet acteur (reprise) ; rien n'a été envoyé |
| `refuse` | 1 | une vérification préalable a échoué : **rien n'a été envoyé** |
| `echoue` | 1 | la transaction est incluse avec `status` `0x0`, ou une relecture (OP-12) contredit l'écriture ; pour `verifier`, le contrôle 8 rend un statut autre que `reussi` : `error` reste nul et le détail est dans `outputs.status` et `outputs.verifications` (R-1 à R-10) |
| `inutilisable` | 2 | usage, fichier illisible, instance illisible, nœud injoignable : rien n'est affirmé |
| `incertain` | 3 | une transaction est partie et son issue n'est pas établie (pas de reçu, capture incomplète) : reprise par `capturer` (7.11) |

`checks` liste les vérifications dans l'ordre où la commande les exécute : les
OP- préalables de 7.3 (OP-2 avant OP-1, puis celles de la commande, OP-3 en
dernier), OP-11, puis CP-1 à CP-6 quand la capture est faite, puis OP-12.
Exemple de sortie (valeurs de l'exemple de 7.10 ; `cost_wei` selon EX-8.17,
`retention` selon EX-9.6, présents dès qu'une transaction est incluse) :

<!-- schema: operations-registre/sortie -->
```json
{
  "version": 0,
  "command": "inscrire-cle",
  "result": "reussi",
  "exit_code": 0,
  "checks": [
    {
      "id": "OP-2",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "OP-1",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "OP-6",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "OP-7",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "OP-8",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "OP-3",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "OP-11",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "CP-1",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "CP-2",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "CP-3",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "CP-4",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "CP-5",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "CP-6",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "OP-12",
      "status": "reussi",
      "detail": ""
    }
  ],
  "error": null,
  "outputs": {
    "transaction_hash": "0x3ab07056650f93ed3c6090cfbfdc9fa456128c684660734c781d307c9cfd0d84",
    "block_number": 20012,
    "gas_used": 172279,
    "cost_wei": "172279",
    "capture": "capture-20012-0-inscription.json",
    "is_active_recorder": true,
    "retention": {
      "retention_heights": 300000,
      "margin_heights": 299988,
      "alert": false
    }
  }
}
```

**EX-7.5** Une commande qui envoie une transaction vérifie RG-15 sur les
octets signés, écrit l'envoi (`#/$defs/envoi`, octets signés compris) dans
`--captures` **avant** de le soumettre, attend le reçu, écrit l'issue
(`issue-<hachage>.json`, 8.6), exécute OP-11, capture le bloc (CP-1 à CP-6,
section 9), puis exécute OP-12. Quand `--dossier` est donné, l'étape suit
l'envoi pas à pas (EX-7.16) : `envoyee` (hachage) dès l'envoi écrit,
`incluse` (hauteur, hachage de bloc) dès le reçu, `capturee` (index) après
CP-6, `echec` (avec `error`) sur un `status` `0x0` ou une relecture
contredite ; le dossier est réécrit à chaque passage. Elle ne rend `reussi`
qu'avec l'index de capture écrit.

### 7.3 Vérifications OP-

Les vérifications OP- sont faites par l'outil avant d'envoyer (OP-1 à OP-10)
ou après le reçu (OP-11, OP-12). Une vérification préalable en échec arrête la
commande avant tout envoi. Elles mettent en œuvre EX-4.9, EX-5.12 et EX-6.1 ;
les lectures d'état qu'elles font (`eth_call`) ne sont pas des preuves (CT-6
§11.1) : elles évitent une transaction qui échouerait ou qui écrirait autre
chose que voulu.

| Id | Vérification | Commandes | Erreur |
|---|---|---|---|
| OP-1 | **Instance** (EX-4.9). `eth_chainId` égale l'identifiant EVM de l'instance ; `noor_getCommitCertificate("latest")` (réessayé selon 9.3) a pour `chainId` l'identifiant BFT et pour `valsetHash` le `valset_hash` du jeu en vigueur du manifeste ; `eth_getCode` n'est pas vide aux quatre adresses en service (5.3) ; quand le manifeste donne le `block_hash` du déploiement d'`AttestationRegistry`, `eth_getBlockByNumber` de ce bloc rend ce hachage | toutes celles qui lisent la chaîne | `chaine_differente`, `jeu_validateurs_different`, `code_absent` |
| OP-2 | **Nœud validateur.** Chaque point de `--rpc` répond (en production, `http://` seulement vers `127.0.0.1`, `::1` ou `localhost`, EX-7.1), et `noor_txindexStatus` y rend `last_indexed_height` non nul et au moins égal à la hauteur lue ou capturée : un suiveur décrit son index local vide (`last_indexed_height` 0, `chain/docker/README.md`, « Mesures ») | toutes celles qui lisent la chaîne | `noeud_injoignable`, `noeud_suiveur` |
| OP-3 | **Expéditeur** (EX-4.18). Solde (`eth_getBalance`, `latest`) ≥ `gas_limit × maxFeePerGas` + `value`, `maxFeePerGas` étant celui de la transaction à envoyer (`p' = ⌈1,1 × p⌉` pour un remplacement, EX-8.16) ; pour un approvisionnement, solde du destinataire + `value` ≤ sa provision `P_k` (EX-4.20) ; aucun envoi du même expéditeur dans `--captures` sans issue connue (8.6 ; l'envoi qu'un remplacement remplace n'est pas compté) | celles qui envoient, `capturer --remplacer` compris | `solde_insuffisant`, `provision_excessive`, `transaction_en_attente` |
| OP-4 | **Organisation, journaux, jeu.** Slug et noms de journal conformes à RG-1 et RG-2, `org_id` et `journal_id` recalculés égaux à ceux du dossier ; membres non nuls, distincts, en minuscules et triés ; `1 ≤ seuil ≤ membres` ; administrateur du jeu (clé de gouvernance) non nul et, sur une instance de `nature` `production`, distinct de tout compte de `accounts` (EX-5.6) ; sur une instance de `nature` `production`, aucune clé d'enregistreur ni clé de chaîne de classe de garde D (`custody_class`, `chain_key_class`, CT-2 §11.2, EX-11.19) ; pour `inscrire-client`, `isRegistered(orgId)` faux (EX-6.3), ou vrai pour un jeu que cet acteur a déjà déployé pour ce dossier (reprise, EX-7.16) | `inscrire-client`, `etat --organisation` | `jeu_invalide`, `cle_invalide`, `organisation_existante` |
| OP-5 | **Comptes et administrateurs.** Chaque compte de l'exploitant que la commande emploie est celui de son rôle dans `accounts` du manifeste à la tête, et deux rôles n'ont pas la même adresse hors du réseau de développement (EX-3.1) ; `CuratorSetRegistry.admin()` égale l'administrateur du registre (`inscrire-client`, `reassigner`) ; pour `reassigner`, le nouveau jeu répond à `admin()`, `getThreshold()` et `getCuratorCount()` par `eth_call` et son `admin()` est celui du jeu précédent, sauf `--changement-administrateur` (EX-8.10) ; pour `administrer-jeu`, le signataire est `CuratorSet.admin()` (`pendingAdmin()` pour `acceptAdmin`) et le nonce de la demande égale `opNonce()` ; pour `approvisionner`, le destinataire est admis par EX-8.20 | `inscrire-client`, `approvisionner`, `reassigner`, `administrer-jeu`, `inscrire-cle` et `clore` avec `--relayeur` | `compte_inattendu`, `pas_administrateur`, `jeu_invalide` |
| OP-6 | **Condensé** (EX-6.1). Le condensé de la demande, recalculé depuis `fields`, `evm_chain_id` et `contract` selon RG-6 à RG-11, égale celui de la demande et celui que rend la fonction de vue du contrat par `eth_call` (`registerDigest`, `revokeDigest`, `periodDigest`, `anchorDigest`, `adminOpDigest`) ; `eip191_digest` égale le hachage signé de 6.6.3 | `condense`, `signer` (hors ligne : recalcul seul), commandes d'écriture | `condense_different` |
| OP-7 | **Signatures** (RG-12, RG-13). Chaque signature est canonique et recouvre son `signer` ; les signataires sont distincts et rangés par adresse croissante ; pour une opération au seuil, chacun est membre du jeu de l'organisation (`isCurator` à `latest`), leur nombre atteint `t` = `getThreshold()` lu à `latest`, et la transaction en joint exactement `t`, les `t` premières dans l'ordre des adresses ; pour une ancre, le signataire est l'émetteur, la clé de chaîne | `signer`, `inscrire-cle`, `revoquer-cle`, `ancrer`, `clore`, `administrer-jeu` | `signature_non_canonique`, `signataire_hors_jeu`, `signatures_insuffisantes` |
| OP-8 | **Clé d'enregistreur.** Inscription : organisation enregistrée (`curatorSetOf(orgId)` non nul ; cette partie précède OP-7, qui lit le seuil du jeu) ; `recorderOf(orgId, chainKey)` a `registeredAt` et `revokedAt` nuls, sauf reprise : une clé active sous le même `journalId` et la même clé Ed25519 que la demande rend `deja_fait`, dossier ou non (EX-7.13) ; `recorderByPubKey(orgId, clé)` a une `chainKey` nulle ou un `revokedAt` non nul. Révocation : `registeredAt` non nul et égal au `registered_at` de la demande, `revokedAt` nul | `condense`, `inscrire-cle`, `revoquer-cle`, `clore` | `organisation_inconnue`, `cle_deja_active`, `cle_revoquee`, `cle_ed25519_active`, `cle_inconnue` |
| OP-9 | **Ancre.** `periodHash` recalculé depuis le manifeste (CT-1 §10.2), empreinte et `docType` de la section 6 ; `isActiveRecorder(orgId, clé de chaîne)` vrai et `recorderByPubKey(orgId, clé du manifeste).chainKey` égale la clé de chaîne ; `isAnchored(empreinte)` faux, sinon `deja_fait` si `lookup` rend cet émetteur et ce `docType`, et `empreinte_squattee` dans tout autre cas (8.3) | `ancrer` | `cle_chaine_non_inscrite`, `empreinte_squattee` |
| OP-10 | **Clôture.** `PeriodMeta` et `uri` passent RG-5 ; `isKnown(orgId, periodHash)` faux, sinon `deja_fait` si la dernière période du journal porte ce `periodHash`, et `doublon` sinon ; continuité avec `getPeriod(latestPeriodOf(orgId, journalId))` ; ancre de la même période présente (`lookup(empreinte).issuer` égal à la clé de chaîne sous laquelle la clé du manifeste est inscrite, EX-8.4) et, pour `condense cloture`, capturée dans `--captures` ; pour `condense cloture`, aucune demande de clôture déjà relayée pour la même position (`org_id`, `journal_id`, `first_seq`) avec un autre `periodHash` (EX-8.19) | `condense cloture` (RG-5, continuité, ancre, position), `clore` (tout) | `periode_invalide`, `doublon`, `discontinuite_temporelle`, `discontinuite_sequence`, `ancre_manquante`, `demande_existante` |
| OP-11 | **Reçu.** `status` `0x1` ; le reçu porte, émis par l'adresse du contrat, l'événement attendu (`CuratorSetAssigned`, `RecorderRegistered`, `RecorderRevoked`, `Anchored`, `PeriodSubmitted`, `AdminOpRelayed` ; adresse créée pour un déploiement ; aucun journal pour un approvisionnement), et ses valeurs décodées égalent les valeurs envoyées | celles qui envoient | `transaction_annulee` |
| OP-12 | **Relecture.** Après le reçu, l'état relu à la hauteur du bloc confirme l'écriture : `curatorSetOf`, `getThreshold`, `getCuratorCount`, `isCurator` ; `isActiveRecorder`, `recorderByPubKey` ; `lookup` ; `getPeriod(latestPeriodOf)` ; la relecture est déclarative | celles qui envoient | `transaction_annulee` |

### 7.4 Prérequis sur le réseau de développement

Depuis la racine du dépôt, une fois :

```bash
npm ci
npm run compile
bash chain/scripts/dev-net.sh start
bash chain/scripts/dev-net.sh status
```

`npm ci` installe les dépendances épinglées par `package-lock.json` et, par
défaut, soumet un rapport d'audit avec l'installation (option `audit` de npm,
documentation de npm 10.9.4, `npm-ci.md`) : le résumé de vulnérabilités qu'il
peut imprimer porte sur les dépendances de développement, ne change pas son
code de retour (épreuve du 2026-10-25 : seize vulnérabilités signalées,
code 0) et n'entre pas dans les critères d'EX-7.15. `npm run compile` imprime
`No contracts to compile` quand `hh-artifacts/` est à jour, mais réécrit à
chaque exécution `hh-cache/compile-cache.json`, `hh-artifacts/artifacts.d.ts`
et les dix-huit fichiers de `types/ethers-contracts/` : le greffon TypeChain
de la boîte à outils Hardhat (`hardhat.config.mjs:5-8`) régénère les types
après toute compilation, contrats modifiés ou non
(`@nomicfoundation/hardhat-typechain` 3.1.2,
`dist/src/internal/hook-handlers/solidity.js`,
`dist/src/internal/generate-types.js:8-34`), et le contenu de `hardhat.d.ts`
et d'`index.ts` peut différer d'une exécution à l'autre (ordre des lignes
`CuratorSet` et `CuratorSetRegistry` ; trois exécutions successives le
2026-10-25). Ces trois répertoires sont des produits de la compilation,
ignorés par git (`.gitignore:12-14`) : ils ne font partie ni de ce que
l'épreuve rend ni de ce qu'elle supprime, et l'outil de référence y lit ses
ABI (7.2).

`status` se termine par `dev-net: 4/4 validateurs debout (quorum 3 requis) ;
journaux sous …` et le code 0 (`chain/scripts/dev-net.sh:343-344`). Si
`deployments/noorcore.json` n'existe pas, déployer les contrats (5.2) avec le
compte Hardhat 0, qui tient sur le réseau de développement les quatre rôles de
l'exploitant (EX-3.1) :

```bash
export NOOR_PRIVATE_KEY="$(node --input-type=module -e "import { Wallet } from 'ethers'; console.log(Wallet.fromPhrase('test test test test test test test test test test test junk').privateKey)")"
test -f deployments/noorcore.json || node scripts/deploy/deploy-noortrace.mjs --network noorcore
```

La seconde commande imprime
`Fichier de déploiement : …/deployments/noorcore.json`
(`scripts/deploy/deploy-noortrace.mjs:40`) ; un fichier existant n'est jamais
écrasé sans `--force` (`scripts/lib/noortrace.mjs:259-264`), et il ne faut pas
le forcer : les organisations existantes y sont rattachées. Puis :

```bash
export R="node scripts/registre/noortrace-registre.mjs"
export E="$HOME/noortrace-essai-ct4" ORG="relecteur-$(date -u +%Y%m%d%H%M%S)"
mkdir -p "$E/sorties"
$R etat > "$E/sorties/01-etat.json"
```

`E` est le répertoire de l'essai, hors du dépôt : tout ce que l'épreuve crée
y va (clés, dossier, captures, manifeste, demandes, parties, sorties), chaque
commande créant le sous-répertoire ou le fichier qu'elle écrit, et c'est lui
que le relecteur rend (EX-7.14). Chaque commande `$R …` écrit sur la sortie
standard un seul objet JSON (EX-7.4) : pour rendre les sorties, le relecteur
redirige celle de chaque commande de 7.4 à 7.9 vers un fichier de
`$E/sorties/`, numéroté dans l'ordre d'exécution (`01-etat.json`,
`02-cles-essai.json`, …), comme ci-dessus ; les commandes de 7.5 à 7.9 sont
imprimées sans cette redirection, qui s'ajoute à chacune. Les messages
d'avancement et, pour `signer`, les champs en clair de la demande (EX-7.10)
vont sur la sortie d'erreur et restent à l'écran.

`etat` exécute OP-1 et OP-2 et rend `result: "reussi"`, avec dans `outputs`
`evm_chain_id` 2124, `bft_chain_id` `noortrace-2124-dev`, `genesis_sha256`
`0x510e24e41cc401faa4e092338060cee0dc4629e5781a69af7a50b37edb6f4537` (4.8), la
hauteur de tête, `validator_set_hash`
`0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751` (jeu de
`test/fixtures/certificat-commit/validators.json`, copie de
`chain/runtime/validators.json`) et les quatre adresses de contrat. Un réseau
de développement recréé (7.11, dernière ligne) a un autre jeu, donc un autre
hachage.

**EX-7.6** Le slug d'un essai DOIT être neuf : une organisation enregistrée
n'est jamais réutilisée par `inscrire-client` (OP-4), et `bootstrap-org.mjs`,
outil de développement, ne suit pas cette section (13).

### 7.5 Pas 1 : dossier d'inscription

Le dossier (`spec/schemas/inscription-client-v0.schema.json`) porte la
demande du client et l'état de chaque étape. Sur le réseau de développement,
les clés de l'essai se créent par :

```bash
$R cles-essai --sortie "$E/cles"
```

qui écrit, en mode 0600, `admin-jeu.cle`, `approbateur-1.cle` à
`approbateur-3.cle`, `cle-chaine-rec-essai-01.cle`, `rec-essai-01.graine`,
puis `rec-essai-01.json` (la clé d'enregistreur au format
`#/$defs/cle_enregistreur`, classes `D`, `backend_type` `fichier`) et
`cles-essai.json` (adresses et clé publique, aucune valeur secrète). Elle
refuse un répertoire non vide. Puis :

```bash
$R inscrire-client --preparer --org "$ORG" --journal journal-principal --seuil 2 \
  --cles-essai "$E/cles/cles-essai.json" --exploitant hardhat:0 --sortie "$E/dossier.json"
```

| Option de `--preparer` | Contenu |
|---|---|
| `--org <slug>` | slug de l'organisation (RG-1 ; en production, `o-` et 32 chiffres hexadécimaux aléatoires, EX-6.2) |
| `--journal <nom>[,<nom>…]` | journaux du client (RG-2) |
| `--cles-essai <fichier>` | réseau de développement seulement : prend dans `cles-essai.json` les approbateurs, la clé de gouvernance et la clé d'enregistreur |
| `--approbateurs <adresse>,…` | membres du jeu ; avec `--cles-essai`, les trois approbateurs de l'essai |
| `--seuil <t>` | seuil du jeu |
| `--admin-jeu <adresse>` | clé de gouvernance, administrateur du `CuratorSet` (EX-7.7) ; avec `--cles-essai`, `admin-jeu` |
| `--cle-enregistreur <fichier>` (répétable) | une clé au format `#/$defs/cle_enregistreur` (ce que CT-2 EX-11.13 fournit : `custody_class` et `chain_key_class` sont les classes de garde de CT-2 §11.2, D refusée en production par OP-4) ; avec `--cles-essai`, `rec-essai-01.json` |
| `--budget-jour <gaz>` | budget journalier `b_k` de chaque clé de chaîne (EX-4.19) ; défaut : un journal horaire, 24 × (100 000 + 350 000) = 10 800 000 |
| `--tresorerie <référence>` | trésorerie (EX-7.3), dont l'adresse va dans `funding.funder` ; `--exploitant` sur le réseau de développement |
| `--sortie <fichier>` | dossier écrit ; refusé s'il existe |

`--preparer` n'envoie rien : il exécute OP-1, OP-2, OP-4 et OP-5, calcule la
provision `P_k = provision_days × b_k + gas_limit` (EX-4.19 ; 327 000 000 wei
avec les `fees` par défaut) et écrit le dossier avec les étapes à `a_faire` et
`result` nul. Sortie : `reussi`, `outputs` = `{ org_id, journal_ids,
amount_wei, dossier }`.

**EX-7.7** L'administrateur du `CuratorSet` est la clé de gouvernance du
client (EX-5.6) : l'outil déploie le jeu directement avec `set_admin` pour
administrateur, le constructeur le prenant en paramètre
(`contracts/CuratorSet.sol:168-178`), sans remise ultérieure ; sur une
instance de production, il refuse un `set_admin` qui est un compte de
l'exploitant (OP-4). La clé de gouvernance n'a pas de NUR (EX-5.7) : toutes
ses opérations existent sous forme signée et relayée
(`contracts/CuratorSet.sol:119-166`, 8.5).

**EX-7.8** Chaque membre du jeu est la clé d'une seule personne et une
personne ne tient qu'une clé du jeu (CT-3 EX-8.11) ; l'outil ne peut pas le
vérifier, l'exploitant le consigne à la cérémonie (CT-7). Le dossier n'est
authentifié par personne en version 0 : aucune signature de la clé de
gouvernance sur la demande, aucune preuve de possession de la clé de chaîne
ni de la clé Ed25519 (`origin_proof` est facultatif et n'est qu'une empreinte,
`prepared_by` un texte libre), et les adresses arrivent par les options de
l'exploitant. Un fichier de clés altéré ou une adresse mal copiée ferait
déployer un jeu, approvisionner une clé de chaîne et inscrire une clé qui ne
sont pas celles du client, sans que l'outil le voie ; d'où l'obligation de
contrôle du client d'EX-7.17 dès cette version, et la demande signée et les
preuves de possession proposées en section 14 (version 0.1 du schéma
`inscription-client`).

### 7.6 Pas 2 à 5 : jeu, assignation, lecture, approvisionnement

```bash
$R inscrire-client --dossier "$E/dossier.json" --exploitant hardhat:0 --captures "$E/captures"
```

Hors du réseau de développement, `--exploitant` est remplacé par
`--deployeur`, `--administrateur` et `--tresorerie` (EX-7.3). La commande
enchaîne, pour chaque étape encore à faire, dans cet ordre :

1. **`jeu_approbateurs`** : OP-1 à OP-5 ; déploiement par le déployeur de
   `CuratorSet(set_admin, members, threshold)` (RG-15, déploiement) ; OP-11
   (événements `AdminAccepted`, `CuratorAdded` par membre,
   `ThresholdUpdated`), capture (rôle `jeu_approbateurs`), OP-12
   (`getThreshold`, `getCuratorCount`, `isCurator` de chaque membre, `admin`).
2. **`assignation`** : OP-5 ; `curatorSetOf(orgId)` lu à `latest` : égal au
   jeu attendu, l'étape est déjà faite par cet acteur (reprise : l'envoi est
   retrouvé dans `--captures` ou par `eth_getLogs` de `CuratorSetAssigned`,
   puis capturé) ; un autre jeu non nul rend `organisation_existante` ; nul,
   `setCuratorSet(orgId, jeu)` est envoyé par l'administrateur du registre ;
   OP-11 (`CuratorSetAssigned(orgId, jeu, 0x0…0)`), capture (rôle
   `assignation`). `setCuratorSet` n'a pas de garde contre le même jeu
   (`contracts/CuratorSetRegistry.sol:76-84`) : un envoi sans cette lecture
   serait inclus, coûterait du gaz et émettrait une réassignation que le
   client surveille (EX-8.12).
3. **`lecture_jeu`** : lecture du jeu à une hauteur `H` au moins égale au bloc
   d'assignation, par la procédure de CT-3 EX-8.1 (registre, jeu épinglé =
   l'adresse déployée au pas 2) ; le résultat va dans `result.set_read`.
4. **`approvisionnement`** de chaque clé de chaîne : OP-3 et OP-5 pour la
   trésorerie ; virement de `P_k` moins le solde de la clé (EX-4.19 ;
   RG-15, approvisionnement) ; OP-11 (`status` `0x1`), capture (rôle
   `approvisionnement`) ; une clé dont le solde atteint déjà `P_k` est
   `deja_fait`.

Le dossier est réécrit après chaque changement d'état d'une étape (fichier
temporaire puis renommage) : c'est l'état de reprise. Sortie : `reussi` avec
`outputs` = `{ curator_set, set_deployment, assignment, set_read, funded }` ;
un refus préalable laisse l'étape à `a_faire` et les étapes suivantes
intactes.

**EX-7.16** États d'une étape (`steps[].state`) et reprise :

| État | Sens | Écrit quand | Reprise par `inscrire-client --dossier` |
|---|---|---|---|
| `a_faire` | rien n'a été envoyé pour cette étape | à la préparation | l'étape est exécutée, après lecture de l'état de la chaîne (pas 1 et 2 ci-dessus) |
| `envoyee` | l'envoi est écrit et soumis, le reçu n'est pas obtenu (`transaction_hash` renseigné) | juste avant `eth_sendRawTransaction` | `eth_getTransactionReceipt(transaction_hash)` : reçu présent, l'étape passe par `incluse` ; absent, `transaction_en_attente` et reprise par `capturer --envoi --dossier` (8.6) ; jamais un nouvel envoi |
| `incluse` | reçu à `status` `0x1` et OP-11 réussi, capture non faite (`block_number`, `block_hash` renseignés ; `contract` pour `jeu_approbateurs`) | dès le reçu, avant la capture | la capture est reprise sur la transaction connue (`capturer --transaction --dossier`, ou `inscrire-client` lui-même), puis `capturee` ; sur le réseau Hardhat (`--sans-capture`, EX-A.6) l'étape reste `incluse` et `result` reste nul |
| `capturee` | index de capture écrit (`capture` renseigné) | après CP-6 | `deja_fait` |
| `faite` | étape sans transaction (`lecture_jeu`, approvisionnement d'une clé déjà au-dessus de `P_k`) | à l'exécution | `deja_fait` |
| `echec` | transaction incluse à `status` `0x0`, ou relecture OP-12 contredite ; `error` et `transaction_hash` renseignés | à l'issue d'OP-11 ou OP-12 | la commande relit l'état de la chaîne (EX-5.12) et refait l'étape ; jamais un renvoi à l'identique |

Pour `jeu_approbateurs`, si `isRegistered(orgId)` est vrai alors que l'étape
n'est pas faite, l'outil lit le jeu assigné (`admin`, `getThreshold`,
`getCuratorCount`, `isCurator` de chaque membre) : égal au dossier et égal à
`CREATE(déployeur, nonce)` d'un envoi de ce déployeur retrouvé dans
`--captures` dont les données sont le code de création suivi des arguments
du dossier, le jeu est adopté (reprise, capture de sa transaction) ; sinon
`organisation_existante`. L'adresse du jeu est écrite dans `contract` de
l'étape dès le reçu, pour qu'une reprise depuis un autre poste ou un autre
répertoire de captures ne dépende pas de l'index de capture.

**EX-7.9** Chaque clé de chaîne DOIT avoir sa provision avant sa première
transaction (EX-4.19) : toute écriture coûte au moins 1 wei par gaz à son
expéditeur (4.5). Le montant versé est `P_k` d'EX-4.19, calculé depuis
`--budget-jour` et `fees` du manifeste, jamais davantage (EX-4.20). Une
période (ancre et clôture) consomme de 331 000 à 411 000 gaz environ
(`anchor` au plus 96 977, `submitPeriod` 234 079 à 314 256, 4.5), soit autant
de wei à 1 wei par gaz : la provision par défaut, 327 000 000 wei, couvre au
moins 30 jours d'un journal horaire, inscription de la clé comprise, OP-3
gardant toujours `gas_limit` wei en réserve.

### 7.7 Pas 6 : demande de signature et inscription de la clé

Une opération au seuil passe par une **demande de signature**
(`operations-registre-v0.schema.json#/$defs/demande_signature`) : l'outil la
prépare, chaque signataire la recalcule et la signe, puis l'outil la relaie.

```bash
$R condense inscription --dossier "$E/dossier.json" --key-id rec-essai-01 --sortie "$E/demande-inscription.json"
$R signer --demande "$E/demande-inscription.json" --cle "fichier:$E/cles/approbateur-1.cle"
$R signer --demande "$E/demande-inscription.json" --cle "fichier:$E/cles/approbateur-2.cle"
$R inscrire-cle --demande "$E/demande-inscription.json" --cle-chaine "fichier:$E/cles/cle-chaine-rec-essai-01.cle" \
  --dossier "$E/dossier.json" --captures "$E/captures"
```

| Commande | Options | Effet |
|---|---|---|
| `condense <operation>` | `inscription` : `--dossier` et `--key-id`, ou `--org-id`, `--journal-id`, `--cle-chaine-adresse`, `--cle-ed25519` ; `revocation` : `--org-id`, `--cle-chaine-adresse` ; `cloture` : `--manifeste`, `--uri` (défaut : chaîne vide), `--captures` (ancre capturée et demandes relayées, OP-10), `--expiration <secondes>` (défaut 86 400, EX-8.19) ; `ancre` : `--manifeste`, `--emetteur` ; `administration_jeu` : `--jeu`, `--op`, `--arg` ; toujours `--sortie` | calcule le condensé (section 6), exécute OP-6 par `eth_call`, lit pour une opération au seuil le jeu et le seuil à la tête (`signer_set`, après la partie « organisation enregistrée » d'OP-8), pour une révocation `registeredAt` (OP-8), pour une opération du jeu `opNonce` ; pour `cloture`, exécute OP-10 avant d'écrire : RG-5 et la continuité avec la période précédente, l'ancre de la période incluse et capturée (EX-8.4, `ancre_manquante`), aucune demande déjà relayée pour la même position (EX-8.19, `demande_existante`) ; écrit la demande sans signature ; `expires_at` n'y figure que pour une `cloture` (`--expiration`, EX-8.19) : une demande d'inscription, de révocation, d'ancre ou d'opération du jeu n'a pas ce membre, que le schéma admet absent ou nul ; `outputs.expires_at` de la commande vaut alors `null`, et `signer` affiche « expires_at absent » parmi les champs en clair |
| `signer` | `--demande`, `--cle` | recalcule le condensé hors ligne (OP-6), refuse une demande dont le condensé ne se recalcule pas (`condense_different`) ou dont `expires_at` est passé (`demande_expiree`), écrit sur la sortie d'erreur les champs en clair (`fields`, `signer_set`, EX-7.10), signe le hachage signé (RFC 6979, `s` bas, RG-12), insère la signature à sa place dans l'ordre des adresses (RG-13) ; refuse un signataire déjà présent |
| `inscrire-cle` | `--demande`, `--cle-chaine` (expéditeur par défaut), `--relayeur` (relayeur de l'exploitant, EX-7.3), `--dossier`, `--captures` | OP-1, OP-2, OP-5 avec `--relayeur`, OP-6, OP-8 (organisation enregistrée), OP-7, OP-8 (clés), OP-3 ; `registerRecorder(orgId, journalId, chainKey, ed25519PubKey, sigs)` ; OP-11, capture (rôle `inscription`), OP-12 ; étape `inscription` du dossier (EX-7.16) |

Exemple : la demande d'inscription de la clé `rec-exemple-01` de 7.10,
signée par deux approbateurs. Le condensé, son préfixe EIP-191 et les
signatures sont calculés pour cette spécification (RFC 6979, signatures
déterministes) ; l'adresse du jeu, la hauteur et le hachage de bloc de
`signer_set` sont synthétiques (7.10). Elle n'a pas de membre `expires_at`,
réservé aux demandes de clôture (table ci-dessus).

<!-- schema: operations-registre/demande_signature -->
```json
{
  "version": 0,
  "operation": "inscription",
  "evm_chain_id": 2124,
  "contract": "0xbec49fa140acaa83533fb00a2bb19bddd0290f25",
  "fields": {
    "org_id": "0x15424c5b6d09deed88ad408275c50812e2c7cc9e142f746f936fc96b05d560fc",
    "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
    "chain_key": "0xaf1056f6fd93594a0a71c87d3b18723232c61714",
    "ed25519_public_key": "0xa34b5d38605d5b729c42eee01465e4e9f7a361c362561ebd8ec2f7c984463fbb"
  },
  "digest": "0xd0b3adc4a42e8b3d9efea626a0dcd526d88fce25c7ad9f1abc3f3577d49d00fa",
  "eip191_digest": "0xa60aa4161f809a429ff15ba9435bfedca919005966cc6b5918faea987bfe36b5",
  "signer_set": {
    "curator_set": "0xa1a165880c7af8f1150efa652507ebe9561b73bd",
    "threshold": 2,
    "height": 20009,
    "block_hash": "0x9d677845e821a226f80370d906f8f6a3b915fa0d4893623dba9c8de6804169b3"
  },
  "signatures": [
    {
      "signer": "0x19d8bddeed23cb80dca47e16b74dd29bc020c138",
      "v": 27,
      "r": "0x5364702e45a64c7580613a69e79e06bed8e7e7806a5452556194a505f191ff1c",
      "s": "0x51f06ca186dc9703a1b681167234d8bff0cc054eed2c34cd23e0a7cc7b78dbd4"
    },
    {
      "signer": "0x5747a77dda82031f8dd96a06a75c52a672a0a4c3",
      "v": 28,
      "r": "0x2d3b796f6cbadde20a50cbfc3591d3c347264cacabe74af4d57391e95ba78584",
      "s": "0x04444d0bfa65f9d800437c51df16a18a6aa1bc7069c87289ea0337ad5e382082"
    }
  ],
  "prepared_at": "2026-11-01T08:46:00.000Z"
}
```

**EX-7.10** Un signataire NE DOIT signer qu'une demande dont il a recalculé
le condensé depuis `fields`, `evm_chain_id` et `contract` (OP-6), et dont il
a lu les champs en clair : l'organisation, le journal, la clé de chaîne et la
clé Ed25519 pour une inscription ; les bornes, la séquence, `root` et
`periodHash` pour une clôture. Un condensé reçu tout fait n'est jamais signé :
le préfixe EIP-191 sur 32 octets bruts ne montre rien de lisible dans un
portefeuille (CT-3 §9.3).

**EX-7.11** L'inscription d'une clé DOIT précéder le premier événement que
cette clé signe (CT-2 EX-11.13) ; l'enregistreur n'attend pas la
confirmation pour écrire, mais aucune ancre n'est envoyée sous une clé de
chaîne non inscrite (OP-9).

Sortie de `inscrire-cle` : celle de EX-7.4 ; `gas_used` mesuré de 171 955 à
189 229 pour cette fonction (R1-F35 et capture de CT-6, B.4).

### 7.8 Pas 7 à 9 : première période

```bash
$R manifeste-essai --dossier "$E/dossier.json" --key-id rec-essai-01 \
  --graine "graine:$E/cles/rec-essai-01.graine" --sortie "$E/periode-1"
$R ancrer --manifeste "$E/periode-1/manifeste.json" --cle-chaine "fichier:$E/cles/cle-chaine-rec-essai-01.cle" \
  --dossier "$E/dossier.json" --captures "$E/captures"
$R condense cloture --manifeste "$E/periode-1/manifeste.json" --captures "$E/captures" --sortie "$E/demande-cloture-1.json"
$R signer --demande "$E/demande-cloture-1.json" --cle "fichier:$E/cles/approbateur-1.cle"
$R signer --demande "$E/demande-cloture-1.json" --cle "fichier:$E/cles/approbateur-3.cle"
$R clore --demande "$E/demande-cloture-1.json" --manifeste "$E/periode-1/manifeste.json" \
  --cle-chaine "fichier:$E/cles/cle-chaine-rec-essai-01.cle" --dossier "$E/dossier.json" --captures "$E/captures"
```

| Commande | Effet | `outputs` |
|---|---|---|
| `manifeste-essai` | réseau de développement seulement : lit `latestPeriodOf(orgId, journalId)` ; sans période, `period_start` = début de l'heure UTC précédente, `first_seq` 1 et `prev_period_hash` nul ; sinon la suite de la dernière période (`period_start` = `periodEnd`, `first_seq` = `lastSeq + 1`, `prev_period_hash` = `periodHash`, CT-1 §10.3) ; `--evenements <n>` hachages d'essai (défaut 3) ; `construireManifeste`, `signerManifeste` (CT-1 §10) ; écrit `manifeste.json` et `manifeste.sig` | `period_hash`, `fingerprint`, `period_start`, `period_end`, `first_seq`, `last_seq`, `root` |
| `ancrer` | OP-1 à OP-3, OP-6, OP-9 ; la clé de chaîne signe `anchorDigest(empreinte, docType)` (EIP-191) et envoie elle-même `anchor(empreinte, docType, clé de chaîne, signature)` ; OP-11 (`Anchored`), capture (rôle `ancre`), OP-12 (`lookup`) ; étape `premiere_ancre` du dossier si c'est la première ancre du journal | `transaction_hash`, `block_number`, `gas_used`, `fingerprint`, `capture` |
| `clore` | OP-1 à OP-3, OP-6, OP-7, OP-10 ; `submitPeriod(meta, sigs)` envoyé par la clé de chaîne (CT-2 EX-11.19) ; OP-11 (`PeriodSubmitted`, identifiant), capture (rôle `cloture`), OP-12 ; étape `premiere_cloture` du dossier si c'est la première clôture du journal | `transaction_hash`, `block_number`, `gas_used`, `period_id`, `capture` |

Hors du réseau de développement, le manifeste et sa signature viennent de
l'enregistreur (CT-2 §9, CT-1 §10) : `manifeste-essai` n'existe que pour
l'épreuve.

Deux transactions d'une même clé de chaîne envoyées au même validateur sont
incluses à au moins N blocs l'une de l'autre, N étant le nombre de
validateurs (une transaction par expéditeur et par bloc, inclusion au tour du
validateur qui l'a reçue, R1-F37, R1-F38) : sur le réseau de développement,
l'ancre et la clôture sont au moins 4 blocs à part. Le reçu est rendu en 2,4 à
3,6 s pour ces trois fonctions (R1-F35, R1-F39).

### 7.9 Pas 10 : export et vérification

```bash
$R exporter --manifeste "$E/periode-1/manifeste.json" --dossier "$E/dossier.json" \
  --captures "$E/captures" --sortie "$E/parties-1"
$R verifier --parties "$E/parties-1" --manifeste "$E/periode-1/manifeste.json" --dossier "$E/dossier.json"
for c in "$E"/captures/certificat-*.json; do
  node scripts/verify/certificat-commit.mjs "$c" --validateurs chain/runtime/validators.json --chaine noortrace-2124-dev \
    || echo "certificat non valide : $c"
done
```

- `exporter` écrit dans `--sortie` les trois parties de CT-6 §11.2 pour la
  période du manifeste, selon 9.6 : `registre.json`, `certificat-commit.json`
  et `validateurs.json`, chacune validée contre son schéma ; les clés qui
  signent dans le dossier viennent de `--cles <cles.json>` (CT-1 §11.2) ou, à
  défaut, du dossier d'inscription. Sortie : `reussi`,
  `outputs` = `{ entries: [{ role, block_number }], certificates, files }`.
- `verifier` exécute le contrôle 8 de CT-6 (`verifierControle8` de
  `scripts/lib/registre.mjs`) sur ces parties, avec le manifeste et, pour
  R-10, la clé Ed25519 lue dans le dossier. Sans `--ancres <fichier>` (CT-6
  §12), il dérive l'ancre `registry` du manifeste par RG-20, ou, sans
  manifeste, des valeurs d'EX-7.2, et le signale dans `outputs.anchor_source`
  (`publication_exploitant`) : ce n'est pas une ancre indépendante (CT-6
  §12.5). Résultat attendu : R-1, R-2, R-4 à R-10 `reussi` ; R-3 `reussi` (le
  jeu exporté est celui de l'ancre) ;
  `exit_code` 0.
- `certificat-commit.mjs` vérifie un certificat capturé par appel ; la boucle
  les passe tous : chaque `certificat-<h>.json` du répertoire des captures,
  soit six pour l'épreuve, `<h>` étant le `block_number` des étapes
  `jeu_approbateurs`, `assignation` et `approvisionnement` (7.6),
  `inscription` (7.7), `premiere_ancre` et `premiere_cloture` (7.8) ; c'est
  « chaque certificat capturé » d'EX-7.15. Attendu pour chacun : code 0 et un
  rapport dont la ligne `Résultat` est « VALIDE — un quorum du jeu fourni a
  signé ce bloc » (`scripts/verify/certificat-commit.mjs:250`,
  `scripts/verify/README.md`, « Usage ») ; la ligne `certificat non valide`
  n'apparaît pas ; la sortie de la boucle (texte, pas JSON) est gardée dans
  `$E/sorties/` comme celle des autres commandes (7.4). Cet outil prend une
  réponse brute de `noor_getCommitCertificate` (ou son champ `result`,
  `certificat-<h>.json` de CP-6) et un `validators.json` au format du nœud ;
  les parties exportées `certificat-commit.json` (`{version, certificates}`,
  CT-6 §11.2.2) et `validateurs.json` (`{version, sets}`, CT-6 §11.2.3) ne lui
  sont pas destinées (code 2, « l'entrée n'est pas un certificat de commit »,
  « tableau ou {validators:[…]} attendu ») : elles se vérifient par `verifier`
  ou par le contrôle 8 de `scripts/verify/dossier.mjs` (CT-6).

Enfin `bash chain/scripts/dev-net.sh stop` : chaque nœud imprime « arrêt
demandé » puis « arrêté » (`chain/scripts/dev-net.sh:292`, `:316`) ; `status`
rend ensuite « 0/4 validateurs debout » et le code 1, état attendu à l'arrêt
(`:343-344`). `chain/runtime/` (données de la chaîne, clés des validateurs,
`validators.json`, journaux) est conservé : la chaîne reprend au prochain
`start` (`chain/README.md:116-119`), et 7.11 dit ce qu'un réseau recréé
change.

### 7.10 Ce que le client reçoit

À la fin, `result` du dossier est rempli et chaque étape est `capturee` ou
`faite`. Le client reçoit le dossier, les captures de ses transactions
(section 9) et la révision en vigueur du manifeste d'instance (4.8), qui porte
le jeu de validateurs. Chaque valeur a une destination :

| Valeur du dossier | Destination | Où elle sert |
|---|---|---|
| `result.approver_set` | `approver_set` de la politique d'approbation, tel quel | CT-3 §4.2 ; CT-3 EX-8.1 (jeu épinglé) |
| `instance.bft_chain_id`, `evm_chain_id`, `genesis_sha256` | désignation de l'instance (EX-4.1) ; `recorder.environment` et `anchoring.registry` de l'enregistreur | CT-2 §15 |
| `instance.contracts.recorder_registry`, `period_registry`, `attestation_registry` ; `instance.bft_chain_id` | ancre `registry` du réviseur (`contracts`, `chain_id`), dérivée du manifeste par RG-20 | CT-6 §12.2, après recoupement (CT-6 §12.5, 9.7) |
| `instance.validator_set_hash` | comparaison au jeu obtenu des opérateurs partenaires | CT-6 §12.5 |
| `recorders[]` : `key_id`, `public_key`, `chain_key`, `journal_id`, et `organisation.org_id` | `recorders[]` du fichier d'ancres ; procès-verbal d'inscription de la clé | CT-6 §12.2, §12.5 ; CT-2 EX-11.13 |
| `recorders[].chain_key` et la référence de son secret | `anchoring.registry.chain_key` de la configuration de l'enregistreur | CT-2 §15 ; CT-2 EX-11.19 |
| point RPC des validateurs que l'exploitant ouvre au client | `anchoring.registry.rpc_url` | CT-2 §15 (un seul point en version 0.3, voir 13) |
| `result.recorders[].registration` | capture de l'inscription, jointe aux dossiers de preuve | CT-6 EX-13.9 |

**EX-7.12** L'exploitant DOIT remettre au client le dossier complet et les
captures de ses transactions, et NE DOIT y mettre aucune valeur secrète. Il
garde une copie du dossier ; l'original est au client.

Exemple : dossier d'inscription fini de l'organisation `relecteur-exemple`.
L'organisation, les journaux, les clés et les adresses sont calculés pour
cette spécification (clés d'exemple de graine
SHA-256(UTF-8(`noortrace/exemple/ct4/…`)), sans valeur) ; les adresses des
contrats, le SHA-256 de la genèse et le hachage du jeu sont ceux du réseau de
développement ; la provision est celle d'EX-4.19 pour un journal horaire ; les
hachages de transaction et de bloc, les hauteurs et l'adresse du jeu sont
synthétiques (SHA-256(UTF-8(`noortrace/exemple/ct4/transaction/<étape>`)),
`<étape>` étant le `step` de l'étape : `jeu_approbateurs`, `assignation`,
`approvisionnement`, `inscription`, `premiere_ancre`, `premiere_cloture` ;
SHA-256(UTF-8(`noortrace/exemple/ct4/bloc/<h>`)) ; 20 premiers octets de
SHA-256(UTF-8(`noortrace/exemple/ct4/curator-set`))). Le `subject` des deux
dernières étapes est le `periodHash` du manifeste d'exemple de A.2.

**EX-7.17** Avant de publier sa politique d'approbation (CT-3) et de
configurer son enregistreur (CT-2 §15), le client DOIT comparer à ses propres
clés : `result.set_read.members` et `threshold`, `CuratorSet.admin()` du jeu
`result.curator_set` (lu auprès d'un validateur qu'il croit, 10.3) et
`recorders[].chain_key` et `public_key` du dossier ; un écart est un refus du
dossier, signalé à l'exploitant, et aucune demande n'est signée pour cette
organisation tant qu'il n'est pas éclairci (EX-7.8).

<!-- schema: inscription-client -->
```json
{
  "version": 0,
  "instance": {
    "evm_chain_id": 2124,
    "bft_chain_id": "noortrace-2124-dev",
    "genesis_sha256": "0x510e24e41cc401faa4e092338060cee0dc4629e5781a69af7a50b37edb6f4537",
    "contracts": {
      "curator_set_registry": "0x172076e0166d1f9cc711c77adf8488051744980c",
      "recorder_registry": "0xbec49fa140acaa83533fb00a2bb19bddd0290f25",
      "period_registry": "0x4ee6ecad1c2dae9f525404de8555724e3c35d07b",
      "attestation_registry": "0xf4b146fba71f41e0592668ffbf264f1d186b2ca8"
    },
    "manifest_sha256": null,
    "validator_set_hash": "0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751"
  },
  "organisation": {
    "slug": "relecteur-exemple",
    "org_id": "0x15424c5b6d09deed88ad408275c50812e2c7cc9e142f746f936fc96b05d560fc"
  },
  "approvers": {
    "members": [
      "0x19d8bddeed23cb80dca47e16b74dd29bc020c138",
      "0x5747a77dda82031f8dd96a06a75c52a672a0a4c3",
      "0xdd2db1636768f86c546563f0368c5c8d5c777990"
    ],
    "threshold": 2,
    "set_admin": "0x436b0cee00aef664dd71949195231b609dbe1314"
  },
  "journals": [
    {
      "name": "journal-principal",
      "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b"
    }
  ],
  "recorders": [
    {
      "key_id": "rec-exemple-01",
      "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
      "algorithm": "ed25519",
      "public_key": "0xa34b5d38605d5b729c42eee01465e4e9f7a361c362561ebd8ec2f7c984463fbb",
      "custody_class": "D",
      "backend_type": "fichier",
      "created_at": "2026-11-01T08:40:00.000Z",
      "chain_key": "0xaf1056f6fd93594a0a71c87d3b18723232c61714",
      "chain_key_class": "D",
      "origin_proof": null
    }
  ],
  "funding": {
    "funder": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
    "daily_budget_gas": 10800000,
    "amount_wei": "327000000"
  },
  "steps": [
    {
      "step": "jeu_approbateurs",
      "subject": "relecteur-exemple",
      "state": "capturee",
      "transaction_hash": "0x33a18d1e1bfd3159f60965659ae023244e61dabdafd71a9e9817f6e367c152a1",
      "block_number": 20000,
      "block_hash": "0x138aaa2e7ae431cf8b1428ffea83e6f385b9857970acd67d8dab3b3c6dcd2e78",
      "capture": "capture-20000-0-jeu_approbateurs.json",
      "error": null,
      "updated_at": "2026-11-01T08:45:04.000Z"
    },
    {
      "step": "assignation",
      "subject": "relecteur-exemple",
      "state": "capturee",
      "transaction_hash": "0x4c12d0f20c60b690c8f0589a1b932e98d5ff8362aaa875433a9c307eabd302b8",
      "block_number": 20004,
      "block_hash": "0xbf49f43b2e5372a82f1205cc0be4b963dba0a1d39a2a8a448fcbdfe0a4891db4",
      "capture": "capture-20004-0-assignation.json",
      "error": null,
      "updated_at": "2026-11-01T08:45:08.000Z"
    },
    {
      "step": "lecture_jeu",
      "subject": "relecteur-exemple",
      "state": "faite",
      "transaction_hash": null,
      "block_number": 20005,
      "block_hash": "0x80fe4333c28e99446e84f0e6bf5fff28581c5c2f0fd18f0b16d0278feb9126ab",
      "capture": null,
      "error": null,
      "updated_at": "2026-11-01T08:45:09.000Z"
    },
    {
      "step": "approvisionnement",
      "subject": "0xaf1056f6fd93594a0a71c87d3b18723232c61714",
      "state": "capturee",
      "transaction_hash": "0xa5e2e12e2e7d0d473ef6a4ab1c44abfa7580fa662fb20f1db3f5ec809728035e",
      "block_number": 20008,
      "block_hash": "0x42465f257652a8b38f741bb4a8f48d9d9bb084d67ce5f81021a0db37d825152b",
      "capture": "capture-20008-0-approvisionnement.json",
      "error": null,
      "updated_at": "2026-11-01T08:45:12.000Z"
    },
    {
      "step": "inscription",
      "subject": "rec-exemple-01",
      "state": "capturee",
      "transaction_hash": "0x3ab07056650f93ed3c6090cfbfdc9fa456128c684660734c781d307c9cfd0d84",
      "block_number": 20012,
      "block_hash": "0x042049f52611cec20e926636f887aa9fda4bc2a40c022cea929d1cdab55899cd",
      "capture": "capture-20012-0-inscription.json",
      "error": null,
      "updated_at": "2026-11-01T08:52:30.000Z"
    },
    {
      "step": "premiere_ancre",
      "subject": "0x266dd53a36a4c33232bd8dc4758eb036cc7adf8f483cb1ae8e7fc2a77034e8fb",
      "state": "capturee",
      "transaction_hash": "0x77e86ffd2ee0c4c67f5f5964b491a9068e3b2a6c75c2fc5403b027332aec0045",
      "block_number": 20016,
      "block_hash": "0x9e0b7c9d3b488954e8337753936c99502e927646375546a77eff651d5fe24ca5",
      "capture": "capture-20016-0-ancre.json",
      "error": null,
      "updated_at": "2026-11-01T09:00:20.000Z"
    },
    {
      "step": "premiere_cloture",
      "subject": "0x266dd53a36a4c33232bd8dc4758eb036cc7adf8f483cb1ae8e7fc2a77034e8fb",
      "state": "capturee",
      "transaction_hash": "0x5b9b3bc12cc93abf106e78d8f21c603c40188e38af2ddde40a8f9e23129d2ab0",
      "block_number": 20020,
      "block_hash": "0x31593561dd7267113583c65b2971b4f3da0de7fa15bb14c2a08a40694a911b8a",
      "capture": "capture-20020-0-cloture.json",
      "error": null,
      "updated_at": "2026-11-01T09:06:41.000Z"
    }
  ],
  "result": {
    "curator_set": "0xa1a165880c7af8f1150efa652507ebe9561b73bd",
    "set_deployment": {
      "transaction_hash": "0x33a18d1e1bfd3159f60965659ae023244e61dabdafd71a9e9817f6e367c152a1",
      "block_number": 20000,
      "block_hash": "0x138aaa2e7ae431cf8b1428ffea83e6f385b9857970acd67d8dab3b3c6dcd2e78",
      "capture": "capture-20000-0-jeu_approbateurs.json"
    },
    "assignment": {
      "transaction_hash": "0x4c12d0f20c60b690c8f0589a1b932e98d5ff8362aaa875433a9c307eabd302b8",
      "block_number": 20004,
      "block_hash": "0xbf49f43b2e5372a82f1205cc0be4b963dba0a1d39a2a8a448fcbdfe0a4891db4",
      "capture": "capture-20004-0-assignation.json"
    },
    "approver_set": {
      "source": "registre",
      "chain_id": 2124,
      "registry": "0x172076e0166d1f9cc711c77adf8488051744980c",
      "set": "0xa1a165880c7af8f1150efa652507ebe9561b73bd",
      "members": null,
      "threshold": null
    },
    "set_read": {
      "height": 20005,
      "block_hash": "0x80fe4333c28e99446e84f0e6bf5fff28581c5c2f0fd18f0b16d0278feb9126ab",
      "threshold": 2,
      "size": 3,
      "members": [
        "0x19d8bddeed23cb80dca47e16b74dd29bc020c138",
        "0x5747a77dda82031f8dd96a06a75c52a672a0a4c3",
        "0xdd2db1636768f86c546563f0368c5c8d5c777990"
      ]
    },
    "recorders": [
      {
        "key_id": "rec-exemple-01",
        "chain_key": "0xaf1056f6fd93594a0a71c87d3b18723232c61714",
        "funding": {
          "transaction_hash": "0xa5e2e12e2e7d0d473ef6a4ab1c44abfa7580fa662fb20f1db3f5ec809728035e",
          "block_number": 20008,
          "block_hash": "0x42465f257652a8b38f741bb4a8f48d9d9bb084d67ce5f81021a0db37d825152b",
          "capture": "capture-20008-0-approvisionnement.json"
        },
        "registration": {
          "transaction_hash": "0x3ab07056650f93ed3c6090cfbfdc9fa456128c684660734c781d307c9cfd0d84",
          "block_number": 20012,
          "block_hash": "0x042049f52611cec20e926636f887aa9fda4bc2a40c022cea929d1cdab55899cd",
          "capture": "capture-20012-0-inscription.json"
        }
      }
    ],
    "completed_at": "2026-11-01T09:06:41.000Z"
  },
  "prepared_by": "relecteur de l'épreuve d'acceptation (exemple)",
  "prepared_at": "2026-11-01T08:41:00.000Z",
  "source": "exemple de CT-4 §7.10 : valeurs de transaction et de bloc synthétiques, SHA-256(UTF-8(\"noortrace/exemple/ct4/…\"))"
}
```

### 7.11 Erreurs et reprise

**EX-7.13** Toute commande est **reprenable** : relancée avec les mêmes
arguments, elle relit l'état de la chaîne et le dossier, rend `deja_fait`
pour une étape faite (pour `inscrire-cle`, dès que `recorderOf(orgId,
chainKey)` est actif sous le même `journalId` et la même clé Ed25519 que la
demande, dossier ou non ; `cle_deja_active` est réservé au cas où ces champs
diffèrent), et ne renvoie jamais une transaction dont l'issue est connue. Une
étape `envoyee` ou `incluse` se reprend par la capture de la transaction
connue (`capturer --envoi` ou `--transaction`, avec `--dossier` pour passer
l'étape à `capturee`, 8.6), jamais en signant une nouvelle transaction
(EX-7.16).

| Erreur | Vérification | Cause | Reprise |
|---|---|---|---|
| `usage`, `instance_illisible` | — | option, manifeste d'instance | corriger l'entrée (code 2) |
| `entree_illisible` | — ; OP-6 (demande) ou OP-4 (dossier) quand c'est un document non conforme à son schéma, première vérification du cas | fichier illisible, envoi tronqué ou non conforme à `#/$defs/envoi`, demande ou dossier hors de son schéma | corriger l'entrée (code 2) |
| `reseau_non_developpement` | EX-7.2, EX-7.3 | défaut sans `--instance` hors du réseau 2124 ; clé de développement (`hardhat:`, `graine:`, `--exploitant`, `cles-essai`, `manifeste-essai`) hors d'une instance de `nature` `developpement` d'identifiant EVM 2124 ou 31337 | donner `--instance` et des clés de production |
| `chaine_differente`, `jeu_validateurs_different`, `code_absent` | OP-1 | mauvais réseau, manifeste d'une autre instance, réseau recréé | vérifier `--rpc` et `--instance` ; ne jamais forcer |
| `noeud_injoignable`, `noeud_suiveur` | OP-2, CP-1 | nœud arrêté ; point d'un suiveur | interroger un validateur (10.3) |
| `organisation_existante` | OP-4 | slug déjà enregistré | autre slug ; un changement de jeu suit 8.5 |
| `jeu_invalide` | OP-4, OP-5 | membres, seuil, administrateur ; nouveau jeu de `reassigner` sans code de `CuratorSet` ou administré par une autre clé que le jeu précédent | corriger le dossier préparé et le préparer de nouveau ; `--changement-administrateur` avec la demande consignée (EX-8.10) |
| `cle_invalide` | OP-4 | clé d'enregistreur ou clé de chaîne de classe de garde D sur une instance de production | clé gardée en classe A à C (CT-2 §11.2) |
| `compte_inattendu` | OP-5 | compte qui n'est pas celui de son rôle dans `accounts`, ou deux rôles sous une adresse hors du réseau de développement | compte du rôle (EX-3.1, 4.8) |
| `pas_administrateur` | OP-5 | l'administrateur du registre n'est pas `admin()` ; signataire qui n'est pas l'administrateur du jeu ; nonce périmé | compte du rôle ; relire `opNonce()` et refaire la demande |
| `solde_insuffisant` | OP-3 | expéditeur sans provision suffisante | `approvisionner` (8.7) |
| `provision_excessive` | OP-3 | approvisionnement au-delà de `P_k` | revoir `--budget-jour` (EX-4.19, EX-4.20) |
| `examen_requis` | 8.7 | consommation au-delà de deux fois le budget | examen par l'exploitant, puis `--apres-examen` (EX-8.18) |
| `transaction_en_attente` | OP-3 | un envoi du même expéditeur est sans issue ; une étape `envoyee` dont la transaction n'a pas de reçu | `capturer --envoi [--dossier]` (8.6) |
| `condense_different` | OP-6 | demande altérée, autre contrat, autre chaîne | refaire la demande par `condense` ; ne pas signer |
| `signature_non_canonique`, `signataire_hors_jeu`, `signatures_insuffisantes` | OP-7 | `signature_non_canonique` : signature à `s` haut ou à `v` hors {27, 28}, signataires non rangés par adresse croissante, signataire en double, signature qui ne recouvre pas son `signer` déclaré ; `signataire_hors_jeu` : non-membre, ou signataire d'une ancre autre que l'émetteur, ou signataire d'une opération du jeu autre que son administrateur ; `signatures_insuffisantes` : seuil non atteint ou relevé depuis la demande | obtenir d'autres signatures ; relire le jeu |
| `cle_deja_active`, `cle_revoquee`, `cle_ed25519_active`, `cle_inconnue`, `organisation_inconnue` | OP-8 | clé de chaîne déjà inscrite ou révoquée (jamais réinscrite), clé Ed25519 active sous une autre clé de chaîne | nouvelle clé de chaîne (8.4) |
| `cle_chaine_non_inscrite` | OP-9 | ancre avant l'inscription, ou sous une autre clé de chaîne | inscrire d'abord (pas 6) |
| `empreinte_squattee` | OP-9 | empreinte ancrée par un autre émetteur | ne pas réessayer ; signaler (8.3) |
| `ancre_manquante` | OP-10 | demande de clôture préparée ou clôture soumise avant que l'ancre de la période soit incluse et capturée (EX-8.4) | `ancrer` d'abord, puis `capturer` si la capture manque |
| `demande_existante` | OP-10 | une demande de clôture d'un autre `periodHash` a déjà été relayée pour la même position du journal (EX-8.19) | ne pas refaire la demande : le manifeste relayé est celui du dossier |
| `demande_expiree` | — | `signer` : `expires_at` de la demande est passé (EX-8.19 ; seule une demande de clôture porte ce membre, 7.7) | refaire la demande par `condense` ; ne pas signer l'ancienne |
| `periode_invalide`, `doublon`, `discontinuite_temporelle`, `discontinuite_sequence` | OP-10 | manifeste malformé, déjà enregistré, hors de la suite du journal | aucune correction sur la chaîne : le manifeste est refait par l'enregistreur, ce qui n'est possible que tant que le manifeste suivant ne chaîne pas son `periodHash` (CT-1 §10.3, continuité), avant toute signature et après avoir abandonné la demande précédente (EX-8.19) |
| `transaction_refusee` | — | erreur JSON-RPC à l'envoi (par exemple `-32000 transaction underpriced`, 4.5) | corriger les frais selon EX-4.15 ; rien n'est parti |
| `transaction_annulee` | OP-11, OP-12 | `status` `0x0`, événement absent | relancer la commande, dont les vérifications préalables relisent l'état (EX-5.12) ; ne pas renvoyer à l'identique |
| `recu_absent` | — | aucun reçu dans le délai (code 3) | `capturer --envoi` ; 8.6 |
| `certificat_indisponible`, `certificat_elague`, `certificat_invalide`, `capture_incomplete` | CP-1 à CP-6 | 9.3 ; `incertain` (code 3) pour toute commande qui capture, `capturer --transaction` compris, sauf un appel mal formé ou un binaire sans correctif (`inutilisable`) | `capturer` ; un certificat élagué est perdu pour ce nœud (9.5) |

Recréer le réseau de développement (arrêt, puis suppression de
`chain/runtime/keys/`, `chain/runtime/validators.json` et
`chain/runtime/data/`, `chain/README.md:116-119` ; `dev-net.sh` n'a pas de
commande `reset`, R1-F18) change le jeu de validateurs et efface les contrats :
`deployments/noorcore.json` ne décrit plus la chaîne et OP-1 refuse
(`code_absent`).

### 7.12 Épreuve d'acceptation

Critère du plan : un relecteur qui n'a que la spécification crée un client,
ancre une racine et clôt une période sur l'instance de développement.

**EX-7.14** Le relecteur reçoit cette spécification (sections 0 à 14), le
dépôt au commit de la revue et un poste où `chain/runtime/bin/noorcore`
existe. Il exécute 7.4 à 7.9 dans l'ordre, sans lire le code de `scripts/`,
avec un slug neuf, et rend le répertoire `$E` de 7.4, moins `cles/` (les
fichiers `.cle` et `.graine` sont des secrets, même d'essai, EX-7.12) : le
dossier d'inscription (`dossier.json`), le répertoire des captures
(`captures/`), le manifeste d'essai et sa signature (`periode-1/`, que
`verifier` relit), les demandes de signature (`demande-*.json`), les parties
exportées (`parties-1/`) et les sorties JSON de chaque commande (`sorties/`),
avec son compte rendu. Ce répertoire est hors du dépôt
(`$HOME/noortrace-essai-ct4` par défaut) : nettoyer l'arbre du dépôt après
l'épreuve ne le touche pas, et il n'est pas détruit avant la seconde
relecture d'EX-7.15 ; une consigne d'effacement du poste s'applique après
cette relecture, ou après que le relecteur a archivé le répertoire rendu hors
du poste (archive `tar`, SHA-256 consigné dans le compte rendu). Rien de `$E`
n'entre dans le dépôt ni dans `spec/vecteurs/` (EX-A.8).

**EX-7.15** L'épreuve est réussie si : chaque commande a rendu `exit_code` 0 ;
toutes les étapes du dossier sont `capturee` ou `faite` et `result` est rempli
et conforme au schéma ; `verifier` rend R-1 à R-10 `reussi` ;
`certificat-commit.mjs` rend 0 sur chaque certificat capturé, c'est-à-dire
sur chaque `certificat-<h>.json` de `captures/` (six pour l'épreuve, boucle
de 7.9) ; et une seconde personne, avec le seul répertoire rendu, rejoue
`verifier` de 7.9 et obtient le même résultat (`outputs.status`,
`verifications`, `n4`, `statement`). Cette relecture se fait réseau arrêté :
`verifier` ne lit que les fichiers qu'on lui donne et, sans `--instance`,
`deployments/noorcore.json` et `chain/runtime/validators.json` du poste de
l'épreuve (EX-7.2), que la seconde personne a sous la main si elle rejoue sur
ce poste et qu'elle reçoit avec le répertoire sinon (ni l'un ni l'autre n'est
secret). Un écart entre ce que la spécification annonce et ce que l'outil
fait est un défaut de l'une ou de l'autre, consigné comme tel.

## 8. Exploitation courante

### 8.1 Qui fait quoi

| Acteur | Opération | Entrée | Sortie | Fréquence |
|---|---|---|---|---|
| Enregistreur (CT-2) | manifeste et sa signature | événements de la période | `manifeste.json`, `manifeste.sig` (CT-1 §10) | chaque heure UTC |
| Enregistreur, clé de chaîne | ancre (`anchor`), capture | manifeste | index de capture (9.4) | chaque période, dès le manifeste |
| Enregistreur | demande de signature de clôture | manifeste, jeu lu | `demande_signature` `cloture` | chaque période |
| Approbateurs, par la console (CT-3 §13) | signature de la clôture | demande, recalculée (EX-7.10) | signatures EIP-191 | chaque période, au seuil |
| Enregistreur, clé de chaîne | clôture (`submitPeriod`), capture | demande signée | index de capture | dès le seuil atteint |
| Approbateurs | inscription, révocation d'une clé | demande `inscription`, `revocation` | signatures | à la rotation (8.4) |
| Administrateur du jeu (client) | `…Signed` du `CuratorSet` | demande `administration_jeu` | signature | au changement de membres ou de seuil (8.5) |
| Exploitant | assignation, réassignation, approvisionnement, révisions du manifeste (4.8) | demande écrite du client ; soldes | transactions, captures, manifeste | à l'inscription, au changement de jeu, à la recharge, à chaque changement d'EX-4.25 |
| Client | surveillance des événements de son `org_id`, de son jeu et de ses journaux (EX-8.12) | sondage `eth_getLogs` (EX-5.11) | alerte | continue |
| Service d'approbation (CT-3) | lecture du jeu épinglé, sondage de ses événements | `approver_set` | jeu figé des tickets (CT-3 §8) | continue |

**EX-8.1** Le registre ne bloque jamais l'enregistreur : une ancre, une
clôture ou une inscription en attente est réessayée et signalée
(`registry_pending`, CT-2 §14.2), sans arrêter la journalisation.

### 8.2 Cycle d'une période

1. L'enregistreur clôt la période (CT-1 §10).
2. La clé de chaîne ancre l'empreinte de la période (`ancrer`), sans attendre
   les approbateurs : l'ancre ne demande que sa propre signature ; l'ancre
   est incluse et capturée avant le pas 3.
3. L'enregistreur prépare la demande de clôture (`condense cloture`) : jeu et
   seuil lus à la tête (`signer_set`), `PeriodMeta` du manifeste, `uri` selon
   RG-5, `expires_at` ; la commande refuse (`ancre_manquante`) tant que
   l'ancre du pas 2 n'est pas incluse et capturée (EX-8.4), et
   (`demande_existante`) si une demande d'un autre `periodHash` a déjà été
   relayée pour la même position (EX-8.19). Le `periodHash` n'est remis à
   personne avant ce pas.
4. Les approbateurs recalculent et signent (EX-7.10) ; la demande est
   complète au seuil.
5. La clé de chaîne envoie la clôture (`clore`), copie la demande relayée dans
   `--captures` et capture la transaction.

**EX-8.2** Les clôtures d'un journal sont soumises dans l'ordre de ses
périodes : le contrat refuse toute autre suite (OP-10). Une clôture en retard
retient les suivantes au registre, pas au journal ; l'enregistreur continue
d'ancrer chaque période.

**EX-8.3** Une clôture non soumise 24 heures après la fin de sa période
DEVRAIT lever une alerte de l'exploitation (CT-8) : les dossiers des
événements de cette période ne passent pas le contrôle 8 tant qu'elle manque
(CT-6 EX-11.10).

**EX-8.4** L'ancre d'une période DOIT être incluse et capturée avant que la
demande de clôture ne soit préparée (`condense cloture`, OP-10) et avant que
la clôture ne soit soumise (`clore`, OP-10) : `lookup(empreinte).issuer` est
la clé de chaîne sous laquelle la clé du manifeste est inscrite, et l'index
de capture de l'ancre existe dans `--captures` (une ancre `incertain` ou
`recu_absent` ne suffit pas). Motif : la demande de clôture porte `periodHash`
en clair (EX-7.10) et la transaction de clôture le publie ; l'empreinte
d'ancre s'en déduit (6.5), et qui la voit avant l'inclusion de l'ancre peut
l'ancrer sous son adresse (8.3). L'enregistreur ne remet donc `periodHash` à
aucune partie avant l'inclusion de l'ancre.

**EX-8.5** Les demandes de signature de clôture sont présentées une à une ;
un approbateur PEUT en signer plusieurs dans une même séance de la console,
chacune recalculée et lue (EX-7.10). La présentation de ces demandes par la
console et leur transport entre l'enregistreur et le service d'approbation ne
sont pas fixés par cette version : la demande de signature en est l'objet
échangé (section 14 ; propositions pour CT-2 et CT-3 en 13).

**EX-8.19** Une demande de clôture signée est une autorisation sans échéance
pour le contrat : `periodDigest` ne couvre que `PeriodMeta`
(`contracts/PeriodRegistry.sol:150-160`), et une demande complète au seuil
reste relayable par quiconque la détient (`contracts/PeriodRegistry.sol:45-54`
l'écrit : un seul manifeste signé par position de journal, aucune voie de
correction). Il en va de même d'une demande d'inscription tant que
(`orgId`, `chainKey`) n'est pas inscrit
(`contracts/RecorderRegistry.sol:44-50`).
Règles : (1) l'enregistreur n'émet qu'une demande de clôture par position
(`org_id`, `journal_id`, `first_seq`) ; un manifeste dont la demande a été
émise n'est ni détruit ni remplacé : s'il est enregistré, c'est lui qui va au
dossier ; (2) s'il doit refaire le manifeste (7.11, possible seulement avant
que le manifeste suivant ne chaîne `prev_period_hash`, CT-1 §10.3), il
déclare d'abord la demande précédente abandonnée (fichier détruit chez lui,
incident consigné avec son `periodHash`, approbateurs et console informés)
et relaie la version voulue dès le seuil atteint, l'enregistrement de la
version voulue étant la seule neutralisation que le contrat offre ; (3)
`condense cloture` écrit `expires_at` (défaut : 24 h), que la console
(CT-3 §13, proposition en 13) et `signer` (`demande_expiree`) refusent de
dépasser : c'est une borne de la fenêtre de signature pour les honnêtes, qui
ne lie ni le contrat ni un relayeur détenant déjà les signatures ; la borne
contractuelle est une proposition (section 14) ; (4) `clore` copie la
demande qu'il relaie dans
`--captures` (`demande-cloture-<periodHash>.json`) et `condense cloture`
refuse (`demande_existante`) une demande pour une position qui a déjà la
sienne avec un autre `periodHash` ; (5) une demande d'inscription n'est
signée qu'une fois la clé de chaîne générée dans son backend et sa preuve de
possession obtenue, et toute demande dont la clé est abandonnée est détruite
; une demande signée dont la clé de chaîne est compromise avant le relais se
neutralise en la relayant soi-même puis en révoquant aussitôt (8.4), une clé
révoquée ne se réinscrivant jamais (EX-8.8).

### 8.3 Ancre refusée ou empreinte prise

`AttestationRegistry` n'ancre une empreinte qu'une fois pour toute la chaîne,
quel que soit l'émetteur (`AlreadyAnchored`, R1-F43). Le contrôle 8 rejette
une ancre dont l'émetteur n'est pas la clé de chaîne sous laquelle la clé du
manifeste est inscrite (CT-6 EX-11.19, N-4). Un tiers qui verrait l'empreinte
avant son inclusion pourrait donc l'ancrer le premier et empêcher l'ancre
légitime (lecture du code, non provoqué, R1, point non vérifié 9 ; provoqué
sur le réseau Hardhat des tests). Il lui faut un expéditeur approvisionné et
un accès RPC en écriture (EX-4.20, EX-10.3) : l'adversaire est l'exploitant,
un client, un relayeur ou leur complice, pas un approbateur, un horodateur ou
un calendrier seuls. Avant l'inclusion, l'empreinte est calculable par
quiconque détient `periodHash` (`org_id` et `journal_id` sont publics, 5.7) :
l'hôte de l'enregistreur ; la console et les approbateurs (EX-7.10 l'exige) ;
le transport des demandes (EX-8.5) ; l'horodateur RFC 3161, dont le
`messageImprint` est `periodHash` (CT-6 EX-13.1, CT-6 T-2) ; le mandataire
TLS devant le validateur (EX-10.3) et tout intermédiaire du chemin RPC côté
client ; le validateur qui tient la transaction, et quiconque lit son point
RPC et connaît son hachage (faute de relais entre validateurs et sans
`txpool_content` ni abonnement aux transactions en attente, R1-F37, R1-F54,
R1-F55). Les calendriers OpenTimestamps ne voient pas `periodHash` : `ots
stamp` ajoute un nonce de 16 octets puis SHA-256 avant la soumission (CT-6
EX-A.7). D'où EX-8.4 (ancre incluse avant toute remise de `periodHash`),
la proposition pour CT-2 et CT-5 en 13 (ancre du registre incluse, puis
requête RFC 3161 ; OpenTimestamps peut partir en parallèle) et EX-10.5
(aucun intermédiaire côté client pour les ancres).

**EX-8.6** Sur `empreinte_squattee` (OP-9), l'outil NE DOIT PAS réessayer :
il rend `refuse`, l'enregistreur signale la période (`registry_pending`) et
l'exploitant consigne l'incident avec `lookup(empreinte)` et le bloc de
l'ancre étrangère. La période garde ses ancres RFC 3161 et OpenTimestamps
(CT-5) ; son dossier ne passe pas le contrôle 8. La correction est une
évolution du contrat (empreinte liée à l'émetteur), proposée en section 14.

### 8.4 Rotation et révocation d'une clé

Les règles de rotation sont celles de CT-2 EX-11.15, EX-11.16 et EX-11.19 ;
CT-4 fixe les opérations du registre qui les servent.

| Cas | Opérations du registre, dans l'ordre | Commandes |
|---|---|---|
| Rotation de la clé Ed25519 (planifiée) | approvisionner la nouvelle clé de chaîne ; inscrire la nouvelle paire ; (événement de rotation au journal, CT-2) ; ancres et clôtures des périodes de l'ancienne clé avec l'ancienne clé de chaîne, puis avec la nouvelle ; révoquer l'ancienne clé de chaîne après la dernière ancre et la dernière clôture qu'elle porte | `approvisionner`, `condense inscription`, `signer`, `inscrire-cle` ; puis `condense revocation`, `signer`, `revoquer-cle` |
| Rotation d'urgence | mêmes opérations, immédiatement, révocation **après** l'événement de rotation (CT-2 EX-11.16) | idem |
| Compromission de la seule clé de chaîne | révoquer l'ancienne clé de chaîne, puis inscrire la même clé Ed25519 sous une nouvelle ; les ancres attendent entre les deux (CT-2 EX-11.19, point 4) | `revoquer-cle`, puis `inscrire-cle` |

**EX-8.7** La demande de révocation DOIT porter le `registeredAt` lu dans
`recorderOf(orgId, chainKey)`, que le condensé inclut (RG-8).

**EX-8.8** Une clé de chaîne révoquée ne se réinscrit jamais
(`contracts/RecorderRegistry.sol:140-142`) : toute rotation emploie une
nouvelle clé de chaîne, approvisionnée avant. La révocation exige le seuil
des approbateurs (`contracts/RecorderRegistry.sol:162-173`) : ni la clé de
chaîne ni la clé de gouvernance ne peuvent révoquer seules, et le délai de
révocation est celui de leur disponibilité, que le contrat de service des
approbateurs DEVRAIT borner (4 h, astreinte : CT-3 §13, CT-7).
`AttestationRegistry` ne consulte pas `RecorderRegistry`
(`contracts/AttestationRegistry.sol:60-66`) : une clé révoquée continue
d'ancrer tant qu'elle a du NUR, et le contrôle 8 seul écarte ses ancres
(R-10, N-4). L'enregistreur DEVRAIT reverser le solde d'une clé saine à la
trésorerie avant de la détruire (EX-4.16) ; l'exploitant consigne le solde
résiduel d'une clé compromise comme capacité de nuisance restante (3.5,
section 12). Une révocation d'urgence par la clé de chaîne elle-même ou par la
clé de gouvernance est une proposition (section 14).

**EX-8.9** La révocation est publiée par l'événement `RecorderRevoked`,
capturé comme une autre transaction (rôle `revocation`). Le contrôle 8 ne
prouve pas la non-révocation d'une clé (CT-6 §11.8) : la capture sert
l'exploitation et la réponse aux incidents, pas le dossier.

### 8.5 Changement du jeu d'approbateurs

Deux voies, de portée différente :

| Voie | Qui | Effet sur le registre | Effet sur CT-3 |
|---|---|---|---|
| Changement dans le jeu : ajouter ou retirer un membre, changer le seuil, transmettre l'administration | administrateur du jeu, par une demande `administration_jeu` signée et relayée (`addCuratorSigned`, `removeCuratorSigned`, `setThresholdSigned`, `proposeAdminSigned`, `acceptAdminSigned`) | les contrats relisent le jeu et le seuil à chaque transaction (`_requireThreshold`) : une demande signée avant le changement peut ne plus suffire | les tickets se re-figent sur le jeu épinglé (CT-3 EX-8.6) |
| Réassignation : un autre `CuratorSet` pour l'organisation | administrateur du `CuratorSetRegistry` (`setCuratorSet`, `reassigner`) | effet immédiat pour toute inscription et toute clôture | le jeu épinglé ne correspond plus (`jeu_non_attendu`) : les tickets en cours expirent, le nouveau jeu n'est adopté que par une nouvelle version de politique (CT-3 EX-8.1, EX-8.6, EX-4.12) |

**EX-8.10** L'exploitant NE DOIT réassigner le jeu d'une organisation que sur
demande écrite du client, consignée, et après que le client a publié la
version de politique qui épingle le nouveau jeu ; `reassigner` exige
`--confirmer <org_id>` et `--demande <fichier>` (la demande écrite, dont le
SHA-256 va dans `outputs.request_sha256`), vérifie par `eth_call` que le
nouveau jeu répond à `admin()`, `getThreshold()` et `getCuratorCount()`
(`setCuratorSet` accepterait toute adresse non nulle,
`contracts/CuratorSetRegistry.sol:76-84`), refuse (`jeu_invalide`) un nouveau
jeu dont `admin()` diffère de celui du jeu précédent sauf
`--changement-administrateur`, réservé à la perte de la clé de gouvernance et
accompagné d'une demande consignée selon CT-7, et capture la transaction
(rôle `reassignation`), dont l'exploitant remet la capture au client
(EX-5.4). Ces gardes protègent de l'erreur d'opérateur ; contre une clé
d'administrateur compromise, seules la garde en HSM (EX-5.4) et la
réassignation cosignée par le jeu en place (section 14) valent. Un jeu
réassigné à l'insu du client peut clore une période frauduleuse qui rend le
journal inachevable (3.5) : la reprise est un nouveau nom de journal (EX-6.4).
`removeCurator` refuse de laisser le seuil au-dessus du nombre de membres
(`ThresholdWouldExceedCurators`, `contracts/CuratorSet.sol:192-197`) : on
abaisse d'abord le seuil.

**EX-8.11** Une demande de clôture ou d'inscription en cours de signature
pendant un changement du jeu est refaite par `condense` après le changement
(OP-7 compte les membres à `latest`). `acceptAdmin` du `CuratorSetRegistry`
n'a pas de forme signée : le nouvel administrateur du registre doit avoir une
provision (EX-5.5).

**EX-8.12** Le client sonde (`eth_getLogs` en tranches, EX-5.11), auprès
d'un validateur qu'il croit (10.3), en plus de la notification de
l'exploitant (EX-5.4) : `CuratorSetAssigned` dont `topics[1]` est son
`org_id` ; `AdminOpRelayed` (un seul sujet pour les cinq opérations signées)
et `AdminAccepted` de son jeu ; `RecorderRegistered` dont `topics[1]` est son
`org_id` et `PeriodSubmitted` de ses journaux, comparés à l'état de son propre
enregistreur (clés inscrites, dernière période close). Toute écriture qu'il
n'a pas produite (réassignation non demandée, opération du jeu non signée par
lui, inscription ou clôture inconnues de l'enregistreur) est un incident :
ses approbateurs ne signent plus de demande d'inscription ni de clôture tant
qu'il n'est pas éclairci ; le service d'approbation, lui, ne fige aucun
ticket sur le jeu réassigné (`jeu_non_attendu`, CT-3 EX-8.1, EX-8.6).

**EX-8.21** L'exploitant ne relaie une demande `administration_jeu`
(`administrer-jeu`) et n'approvisionne une clé de chaîne (`approvisionner`)
que sur confirmation hors bande du client, consignée comme la demande écrite
d'EX-8.10 ; `approvisionner` n'admet que les destinataires d'EX-8.20. La clé
de gouvernance d'un client de production est gardée en classe A à C de CT-2
§11.2, jamais D (cérémonie : CT-7) ; un délai ou une cosignature sur
l'abaissement du seuil et l'ajout d'un membre sont une proposition
(section 14).

### 8.6 Envoi des transactions

**EX-8.13** L'outil signe selon RG-15 (EX-4.8, EX-4.15, EX-4.17) et vérifie
RG-15 sur les octets signés avant de les écrire dans l'envoi (EX-7.5).
noorcore refuse une transaction de type 2 signée pour une autre chaîne, mais
accepte une transaction non protégée (R1-F33) : la protection tient à l'outil
seul.

**EX-8.14** Le nonce est `eth_getTransactionCount(expéditeur, "latest")`. Le
nonce `pending` de noorcore ne compte pas une transaction en attente
(observé, R1-F30) : l'outil tient lui-même ses envois (`envoi-<hachage>.json`)
et refuse d'en signer un autre pour un expéditeur dont un envoi est sans issue
(OP-3).

**EX-8.15** Une transaction est soumise, en mêmes octets, à chaque validateur
de `--rpc` : noorcore ne relaie pas les transactions entre validateurs et
n'inclut une transaction qu'au tour de proposition du validateur qui l'a
reçue ; la même transaction envoyée à deux validateurs garde un seul hachage
et n'est incluse qu'une fois (R1-F37, R1-F38). En production, l'enregistreur
DOIT la soumettre à au moins deux validateurs d'opérateurs distincts
(`anchoring.registry.rpc_url` de CT-2 §15 n'a qu'un point : proposition en
13).
L'effet d'une copie restée dans la mempool d'un second validateur après
l'inclusion n'a pas été observé (R1, point non vérifié 3).

**EX-8.16** Absence de reçu : après `--delai`, l'outil rend `incertain`
(`recu_absent`, code 3) avec l'envoi. La reprise est, dans cet ordre :
`capturer --envoi <fichier> --renvoyer`, qui soumet les mêmes octets aux
validateurs de `--rpc` et attend de nouveau (un refus « nonce too low » y
signifie que le nonce est consommé : l'outil relit les reçus, il ne compte
pas de refus) ; puis, si la transaction reste inconnue de tous
(`eth_getTransactionByHash` nul sur chaque point, un point injoignable
comptant comme un refus, `noeud_injoignable`), `capturer --envoi <fichier>
--remplacer --cle <expéditeur>`, qui exécute OP-3 avec le prix relevé, signe
le même appel au **même nonce** avec les deux champs de frais à `⌈1,1 × p⌉`,
`p` étant ceux de l'envoi remplacé (EX-4.15, RG-15 ; R1, conséquence C5), et
n'écrit l'issue de l'original (`issue-<hachage>.json`, `state` `remplacee`,
`replaced_by`) qu'une fois le remplaçant accepté par au moins un point ;
jusqu'à l'inclusion de l'un des deux, l'outil sonde les deux hachages, et
celui qui obtient le reçu est capturé, l'autre reçoit l'issue `remplacee` ou
`ecartee` ; un remplaçant refusé par tous les points ne laisse aucune issue à
l'original, qui reste sans issue pour OP-3. Un envoi `remplacee` reste tenu
pour sans issue tant que son remplaçant n'a pas d'issue d'inclusion. Un nonce
n'est jamais employé pour un autre contenu. Une transaction écartée peut
revenir au redémarrage d'un nœud, depuis son journal durable, pendant 24
heures, si son nonce est encore valable (R1-F30, R1-F36) : c'est pourquoi le
remplacement garde le nonce. L'issue d'un envoi est le fichier
`issue-<hachage>.json` (`#/$defs/issue`) : inclusion (`block_number`,
`status`), remplacement accepté (`remplacee`, `replaced_by`) ou mise à
l'écart (`ecartee`, `replaces`) ; un envoi sans fichier d'issue est sans
issue connue (OP-3). Le rôle et le contrat d'un envoi repris par `capturer
--envoi` sont déduits de la transaction signée et de son reçu : destinataire
nul, `deploiement`, ou `jeu_approbateurs` si les données commencent par le
code de création de `CuratorSet` ; données vides, `approvisionnement` ;
sélecteur de 6.7.1, `inscription`, `revocation`, `ancre`, `cloture` ou
`administration_jeu` ; `setCuratorSet`, `assignation`, ou `reassignation` si
`topics[3]` de `CuratorSetAssigned` n'est pas nul ; `--role` et `--contrat`
priment, et sont obligatoires sur un sélecteur non reconnu (`usage`). Avec
`--dossier`, `capturer` passe à `capturee` l'étape dont `transaction_hash`
est celui de la transaction capturée (EX-7.16).

**EX-8.17** Le coût d'une transaction est `gasUsed × maxFeePerGas` de son
envoi : les deux champs de frais étant égaux (EX-4.15), c'est aussi
`effectiveGasPrice` du reçu, qui vaut le plafond (R1-F29). L'outil le consigne
dans `outputs.cost_wei` ; il ne lit jamais le prix payé dans le reçu d'une
transaction qu'il n'a pas signée selon EX-4.15.

### 8.7 Soldes et approvisionnement

```bash
$R approvisionner --vers <adresse> (--dossier <fichier> | --demande <fichier> | --org-id <org_id>) \
  [--budget-jour <gaz>] --tresorerie <référence> --captures <répertoire>
```

`approvisionner` lit le solde de `--vers` et, s'il est sous le seuil de
recomplément `refill_below_days × b_k + gas_limit`, verse `P_k` moins le solde
(EX-4.19) ; sinon il rend `deja_fait`, sans examen (l'examen d'EX-8.18 ne
s'applique qu'à un versement). `--budget-jour` vaut par défaut celui
du dossier ou d'un journal horaire (7.5) ; il DOIT être un entier positif
(`usage` sinon) et au plus `fees.max_daily_budget_gas` du manifeste quand il
est donné (EX-8.20). `outputs` porte le solde avant et après, `P_k`, et la
consommation depuis le dernier approvisionnement capturé, rapportée à la durée
écoulée.

**EX-8.20** Le destinataire `--vers` d'un approvisionnement DOIT être l'un
de : la clé de chaîne d'un dossier d'inscription (`--dossier`,
`recorders[].chain_key`) ; la `fields.chain_key` d'une demande `inscription`
préparée par `condense` (`--demande`) ; une clé de chaîne active
(`isActiveRecorder(orgId, vers)` vrai, `--org-id`) ; un compte de `accounts`
du manifeste (relayeur, déployeur, administrateur du registre, EX-4.19) ;
tout autre destinataire est refusé (`compte_inattendu`, OP-5). Le budget
journalier retenu ne dépasse jamais `fees.max_daily_budget_gas` quand le
manifeste le fixe (`provision_excessive`, OP-3) : sans plafond, `P_k` et la
borne d'OP-3 dérivent de la même option et `provision_excessive` ne peut pas
se déclencher. Ces gardes protègent de l'erreur d'opérateur ; une trésorerie
compromise signe sans l'outil : sur une instance de production, la genèse
DEVRAIT précharger deux comptes, une trésorerie froide jamais en ligne et un
compte d'approvisionnement (rôle `approvisionnement`, proposition de
section 14 pour le schéma) limité à 30 jours des budgets de tous les clients
et recomplété par cérémonie (CT-7), et la garde d'admission d'EX-10.8 limite
les expéditeurs. L'examen d'EX-8.18 se fonde sur les captures
`approvisionnement` du répertoire `--captures` : il DEVRAIT se fonder sur un
registre d'approvisionnements tenu par l'exploitant pour l'instance (fichier
signé listant hachage, bloc, destinataire et montant de chaque virement de la
trésorerie), la consommation étant alors `eth_getBalance` du destinataire à
la hauteur du dernier virement moins à la tête (noorcore sert les lectures à
une hauteur, R1-F58) ; un autre répertoire ou un autre poste rend l'examen
local muet.

**EX-8.18** L'exploitant surveille le solde de chaque expéditeur
approvisionné (EX-4.19 ; seuils d'alerte : CT-8) et le complète par
`approvisionner` ; une clé sans solde voit ses transactions acceptées par le
RPC puis écartées sans reçu (R1-F30), ce qu'OP-3 empêche à l'envoi. Quand la
consommation depuis le dernier approvisionnement dépasse deux fois le budget
de la même durée, `approvisionner` refuse (`examen_requis`) : l'exploitant
examine la consommation (EX-4.20), puis relance avec `--apres-examen <motif>`,
que la sortie consigne. Chaque virement est capturé (rôle
`approvisionnement`).

## 9. Certificat de commit

### 9.1 La méthode `noor_getCommitCertificate`

Le binaire de l'instance (commit épinglé de noorchain-core et correctif de
`chain/patches/`, 4.6 et 4.7) sert le certificat de commit d'un bloc : la
proposition signée du tour décisif et les precommits signés qui forment le
quorum, tels que chaque validateur les a vérifiés avant de commettre
(`chain/README.md`, « Certificat de commit BFT »). La méthode est au niveau
« Experimental » de la politique de stabilité de noorchain-core : codes
stables, champs ajoutés mais jamais retirés. Le binaire de retour arrière
`noorcore.618fcef`, sans correctif, ne la sert pas (`-32601 method not found`).

Paramètre : **exactement un**, une chaîne.

| Paramètre | Effet | Réponse mesurée sur l'instance de développement (R1-F61) |
|---|---|---|
| quantité hexadécimale sans zéro de tête (`"0x4108"`) | certificat de cette hauteur | le certificat ; `["0x0443c"]` : `-32602 invalid params: hex block quantity with leading zeros (…)` |
| `"latest"` | certificat de la tête | le certificat, ou, pendant quelques millisecondes, `-32000 commit certificate for block 0x… not yet persisted …` (2 réponses sur 600 appels) |
| hachage de 32 octets | résolu par la table canonique ; un bloc de branche latérale rend `unknown block` | même certificat que par la hauteur |
| `[]`, deux paramètres, `["17468"]`, `[17468]` | refus | `-32602` (paramètre absent, surnuméraire, mal formé, non chaîne) |

### 9.2 Réponse

| Champ | Contenu | Lu par CT-4 et CT-6 |
|---|---|---|
| `height`, `round` | quantités | oui |
| `chainId` | identifiant BFT (`noortrace-2124-dev`) | oui (OP-1, CP-4, CT-6 R-4) |
| `valsetHash` | hachage du jeu qui a signé (CT-6 EX-11.8) | oui (OP-1, CP-4, CT-6 R-2) |
| `blockHash` | hachage BFT du bloc (CT-6 EX-11.4) | oui (CP-2, CP-4, CT-6 R-6) |
| `proposal.line`, `precommits[].line` | lignes brutes des enveloppes signées (membres de l'enveloppe : CT-6 EX-11.7) ; le corps signé de la proposition est l'objet JSON `Proposal` de noorcore, membres `height`, `round`, `proposer`, `blockHash`, `parentHash`, `timestamp`, `stateRoot`, `receiptsRoot`, `txRoot`, `gasUsed`, `gasLimit`, `baseFeeHex`, `txsRaw` (tableau des transactions brutes du bloc dans l'ordre d'inclusion, chacune en base64 standard avec bourrage de l'encodage de 6.7.3), `polkaRound`, `polkaLines`, `sig` ; le corps d'un precommit est l'objet `Vote`, membres `Height`, `Round`, `Voter`, `Type`, `BlockHash`, `Sig` (code de noorcore, `core/consensus/types.go:25-45`, `:89-96`, lu pour cette spécification ; recoupé sur les lignes capturées de `spec/vecteurs/ct-6/registre/capture/` ; lecture tolérante de CT-6 EX-11.6 : noms comparés sans la casse, dernière occurrence retenue, membres inconnus ignorés) | oui, octet pour octet (CT-6 EX-11.3, CT-6 EX-11.6) ; `txsRaw` par RG-19 et CP-4 |
| `proposal.{validatorId, bodyHash, sig}`, `precommits[].{validatorId, height, round, blockHash, bodyHash, sig}` | champs décodés par le nœud | non : relus dans les lignes |
| `canonical.{blockHash, matchesCertificate}`, `quorum.{validators, required, precommits}`, `validatorSet[]`, `validatorSetHash`, `validatorSetMatchesCertificate`, `signing.{domain, digestPrefix, scheme}` | avis du nœud et jeu qu'il emploie **maintenant** | non |
| `retention.{heights, pruned}` | fenêtre du nœud, hauteur élaguée ou non | seulement pour l'alerte de 9.5 |

Un certificat d'un bloc à une transaction fait 6 548 à 7 520 octets ; la
taille pour un bloc plein (64 transactions) n'est pas mesurée (R1-F61 ; R1,
point non vérifié 14). Le nœud ne revérifie pas les signatures en servant
(R1-F60) : tout se vérifie hors ligne contre le jeu du manifeste (4.8, 9.7).

**EX-9.1** Les outils de CT-4 ne tirent du certificat que les champs que lit
CT-6 EX-11.3 ; ils ne prennent jamais `validatorSet` pour le jeu de
validateurs (CT-6 EX-13.10).

### 9.3 Erreurs et conduite

| Réponse | Sens | Conduite de l'outil |
|---|---|---|
| `-32602 invalid params: …` | appel mal formé | défaut de l'outil : `inutilisable` (code 2) |
| `-32000 … not yet persisted … retry shortly` | tête dont le certificat s'écrit juste après le bloc (`chain/README.md`) | réessai toutes les 50 ms, au plus 100 fois et jusqu'à ce que la tête dépasse le bloc ; ensuite `certificat_indisponible`, `incertain` ; jamais archivé comme une absence |
| `-32000 unknown block` | hauteur au-delà de la tête, hachage inconnu ou non canonique | relire la tête ; si elle dépasse la hauteur, `certificat_indisponible` |
| `-32000 no commit certificate stored for block …: inside the retention window …` | ce nœud n'a pas de certificat pour cette hauteur (genèse, nœud entré après) | essayer le validateur suivant de `--rpc` ; sinon `certificat_indisponible` |
| `-32000` qui nomme la rétention, ou `retention.pruned` vrai | certificat élagué chez ce nœud | `certificat_elague` : perdu pour ce nœud (9.5) |
| `-32000 leader unreachable` | point d'un suiveur sans meneur (`chain/docker/README.md`) | `noeud_suiveur` |
| `-32601 method not found` | binaire sans correctif | `inutilisable` |
| `-32603 internal error` | suiveur dont la réponse du meneur dépasse 2 Mio (`chain/README.md`) | interroger un validateur directement |

### 9.4 Capture au moment de chaque transaction

**EX-9.2** Pour chaque transaction du registre qu'un dossier prouvera
(`registerRecorder` de chaque clé qui signe dans le journal, `anchor`,
`submitPeriod`), dès que `eth_getTransactionReceipt` rend le reçu, l'outil ou
l'enregistreur capture, auprès d'un validateur (CT-6 EX-13.8) :

1. l'en-tête, `eth_getBlockByNumber(h, false)`, `h` = `receipt.blockNumber` ;
2. le reçu de **chaque** transaction de `transactions` de l'en-tête, par
   `eth_getTransactionReceipt`, jamais par `eth_getBlockReceipts`, qui rend
   une liste vide sur noorcore (R1-F56) ;
3. le certificat, `noor_getCommitCertificate(h)` (9.3) ;

puis exécute CP-1 à CP-6 et écrit l'index de capture
(`operations-registre-v0.schema.json`). Les autres rôles de cet index se
capturent de la même façon : `deploiement` pour le manifeste d'instance
(`evidence`, EX-4.27, RG-19) ; `jeu_approbateurs`, `assignation`,
`approvisionnement`, `revocation`, `administration_jeu` et `reassignation`
pour le dossier d'inscription et l'exploitation.

| Id | Vérification | Erreur |
|---|---|---|
| CP-1 | **Nœud.** Le point interrogé est un validateur de l'instance : OP-2 avec `last_indexed_height ≥ h`, `eth_chainId` de l'instance | `noeud_suiveur`, `chaine_differente` |
| CP-2 | **En-tête.** `number` de l'en-tête égale `block_number` de l'index et `hash` de l'en-tête égale `block_hash` de l'index et `blockHash` du reçu de la transaction capturée (`receipts[transaction_index]`, quand il est lisible) ; `BFTBlockHash` recalculé sur les dix champs (CT-6 EX-11.4) égale `hash` | `capture_incomplete` |
| CP-3 | **Reçus.** Un reçu par hachage de `transactions`, dans cet ordre : le reçu de rang `i` (fichier désigné par `files.receipts[i]`) a `transactionHash` égal à `transactions[i]` de l'en-tête, la correspondance se lisant dans le reçu, pas dans son nom (CP-6) ; la racine recalculée (CT-6 EX-11.5) égale `receiptsRoot` ; la transaction capturée est à `transaction_index` | `capture_incomplete` |
| CP-4 | **Certificat.** Obtenu par 9.3 ; vérifié contre le jeu du manifeste dont l'intervalle contient `h` (4.8) comme CT-6 EX-11.6 à EX-11.8 et CT-6 EX-11.14 (`scripts/lib/certificat-commit.mjs`) ; `chainId` = identifiant BFT ; `height` = `h` ; `blockHash` = `hash` de l'en-tête ; `validator_set_hash` de l'index égale le hachage de ce jeu (CT-6 EX-11.8) ; dans le corps signé de la proposition, l'élément `transaction_index` de `txsRaw` (9.2) a pour hachage `transaction_hash`, et la racine de ces transactions égale `transactionsRoot` de l'en-tête (calcul de RG-19) | `certificat_indisponible`, `certificat_elague`, `certificat_invalide` |
| CP-5 | **Journal prouvé.** Pour un rôle à événement, `receipts[transaction_index].logs[log_index]` est émis par `contract` avec le `topics[0]` du rôle ; pour `inscription`, `ancre` et `cloture`, sa disposition est celle de CT-6 EX-11.9 | `capture_incomplete` |
| CP-6 | **Écriture.** Les réponses sont écrites **telles que reçues** (octets de la réponse JSON-RPC complète) dans `bloc-<h>.json`, `recu-<hachage de transactions[i]>.json` pour le reçu de rang `i` et `certificat-<h>.json`, comme la capture de CT-6 (annexe A.5), et l'index dans `capture-<h>-<transaction_index>-<rôle>.json`, tous dans le répertoire des captures, sans sous-répertoire ; ces noms sont ceux que porte l'index (un reçu sous un autre nom est un défaut de CP-6, même identique octet pour octet) ; leurs SHA-256 sont dans l'index ; fichiers et index sont synchronisés sur le disque et l'index est conforme à son schéma avant que la capture soit dite faite | `capture_incomplete` |

**EX-9.3** Une capture est **idempotente** : un fichier déjà présent n'est
jamais réécrit ; une seconde capture d'un même bloc reprend les fichiers
présents s'ils passent CP-2 à CP-4. Deux validateurs pourraient tenir pour un
même bloc des certificats différents et tous deux valides, chacun gardant les
precommits qu'il a reçus (déduction, non observée : deux validateurs ont rendu
les mêmes signataires pour un même bloc, R1-F61) : le premier certificat
valide capturé est gardé.

**EX-9.4** La capture DEVRAIT être faite dans l'heure qui suit le reçu, et
DOIT l'être avant que le bloc ne sorte de la fenêtre de rétention du
validateur interrogé (9.5) ; une capture non faite dans l'heure lève une
alerte de l'exploitation (CT-8).

**EX-9.5** Le reçu d'un bloc d'ancre ou de clôture porte aussi les
transactions des autres organisations incluses dans ce bloc : leurs reçus
sont capturés (CP-3) et vont au dossier, comme le certificat porte déjà leurs
transactions brutes (CT-6 EX-11.2).

Exemple : index de capture de l'inscription de `rec-test-01` (bloc 16648),
transaction de la capture unique de CT-6
(`spec/vecteurs/ct-6/registre/capture/`), dont les trois fichiers et leurs
SHA-256 sont ceux de ce répertoire. `attempts`
et `captured_at` (date de la capture de CT-6) sont reportés pour l'exemple :
l'index par transaction n'existait pas lors de cette capture.

<!-- schema: operations-registre -->
```json
{
  "version": 0,
  "role": "inscription",
  "evm_chain_id": 2124,
  "bft_chain_id": "noortrace-2124-dev",
  "contract": "0xbec49fa140acaa83533fb00a2bb19bddd0290f25",
  "transaction_hash": "0x932ae471728698ae648a109858081ccfadbf20e472bd85cdc47115550dc85158",
  "block_number": 16648,
  "block_hash": "0x73f5b9980d64ce2b8c63d20d3590281cf09eec86a980fe4293eca4157fcc2da2",
  "transaction_index": 0,
  "log_index": 0,
  "files": {
    "block": {
      "name": "bloc-16648.json",
      "sha256": "0xdfe050463b77b54a0cea5d2882ca82bb310257126aeb66fd23680f89c8978887"
    },
    "receipts": [
      {
        "name": "recu-0x932ae471728698ae648a109858081ccfadbf20e472bd85cdc47115550dc85158.json",
        "sha256": "0x7df1c476b06cbae070a19424308777bf9187f609ee8d7abd5f8a78440627783c"
      }
    ],
    "certificate": {
      "name": "certificat-16648.json",
      "sha256": "0xb3f1aa38506e5bb7a983173758ea15d577a672f58b7e85727b6ad402992ff80c"
    }
  },
  "node": {
    "rpc": "http://127.0.0.1:8645",
    "validator_id": "v1"
  },
  "validator_set_hash": "0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751",
  "captured_at": "2026-10-22T22:21:03.442Z",
  "attempts": 1,
  "checks": [
    {
      "id": "CP-1",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "CP-2",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "CP-3",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "CP-4",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "CP-5",
      "status": "reussi",
      "detail": ""
    },
    {
      "id": "CP-6",
      "status": "reussi",
      "detail": ""
    }
  ],
  "sending": null
}
```

### 9.5 Rétention

Un validateur ne garde que les certificats des 300 000 dernières hauteurs
(défaut, réglable par `NOOR_BFT_CERT_RETENTION_HEIGHTS`, R1-F16) ; à
1,10 bloc par seconde, cadence mesurée le 2026-10-25 (R1-F13), la fenêtre
couvre environ 75,8 heures ; CT-6 EX-13.8 écrit « environ 73 h » à
1,14 bloc par seconde, cadence annoncée par `chain/README.md` : la cadence
varie d'une mesure à l'autre. Au-delà, le certificat n'est plus récupérable
auprès de ce nœud : l'archive des captures du client est la seule copie
(`chain/docker/README.md`, « Ce qu'il faudrait pour une copie
indépendante », R1-F64).

**EX-9.6** L'outil calcule, à chaque capture, la marge `h +
retention.heights − tête` et la consigne ; une marge sous 10 % de la fenêtre
lève une alerte.

**EX-9.7** Les validateurs partenaires et ceux auxquels les clients
s'adressent pour leurs captures DEVRAIENT porter
`NOOR_BFT_CERT_RETENTION_HEIGHTS` à au moins 3 000 000 hauteurs (CT-6
EX-13.11), soit environ 31,6 jours à 1,10 bloc par seconde et environ 23 Go à
7,5 Ko par certificat (calcul de cette spécification ; la taille d'un
certificat de bloc plein n'est pas mesurée), et la déclarer dans
`operators[].retention_heights` du manifeste (4.8). La valeur effective se lit
dans `retention.heights` de chaque réponse.

### 9.6 Export des parties du dossier

**EX-9.8** `registre.json` (CT-6 §11.2.1) se construit à partir des seules
captures, par la fonction `entreeRegistre` de `scripts/lib/registre.mjs`
(champs engagés de l'en-tête, reçus réduits à `type`, `status`,
`cumulativeGasUsed`, `logs`, hexadécimal en minuscules) :

| Rôle | Capture retenue |
|---|---|
| `cloture` | celle dont le journal `PeriodSubmitted` a pour `topics[2]` le `periodHash` recalculé du manifeste |
| `ancre` | celle dont le journal `Anchored` a pour `topics[1]` l'empreinte recalculée (section 6) |
| `inscription` | l'inscription de la clé du manifeste (`recorder_key_id`) sous la clé de chaîne émettrice de l'ancre ; puis, pour chaque autre clé qui signe dans le dossier (événement, voisins, décisions : `cles.json`), sa dernière inscription ; au plus 8 en tout (CT-6 EX-13.9) |

Les entrées sont rangées par hauteur de bloc croissante, puis par
`transaction_index` ; `source` nomme l'instance, le validateur interrogé et
les dates des captures (au plus 512 caractères). Aucune valeur d'état
(`getPeriod`, `lookup`, `recorderByPubKey`) n'y entre (CT-6 EX-13.9).

**EX-9.9** `certificat-commit.json` (CT-6 §11.2.2) porte, pour chaque
hauteur distincte de `registre.json` et dans l'ordre croissant, le champ
`result` du certificat capturé, tel quel.

**EX-9.10** `validateurs.json` (CT-6 §11.2.3) reprend les jeux de
`validator_sets` du manifeste dont l'intervalle contient les hauteurs de
`registre.json`, réduits à `from_height`, `to_height`, `validators` et
`source` comme pour l'ancre du réviseur (RG-20) ; sans manifeste (EX-7.2), le
fichier de `publier-jeu` (9.7) ; jamais `validatorSet` d'une réponse du nœud
(CT-6 EX-13.10).

**EX-9.11** Une capture manquante ou en échec arrête l'export
(`capture_incomplete`) : l'exportateur ne reconstruit jamais une entrée depuis
un nœud après coup, sauf par une nouvelle capture (`capturer`) faite dans la
fenêtre de rétention.

### 9.7 Publication de l'instance et jeux de validateurs

**EX-9.12** La publication qu'exige CT-6 EX-13.11 est le manifeste d'instance
(4.8, EX-4.25 à EX-4.27) : identifiants, contrats avec l'index de capture du
bloc de leur déploiement (`evidence`, rôle `deploiement`, capturé avant
l'élagage), et `validator_sets` avec leurs hauteurs de validité. Un jeu y
figure octet pour octet tel que les validateurs le chargent (EX-4.10) ;
`from_height` est la première hauteur décidée sous ce jeu, 1 pour le jeu de
la genèse (la hauteur 0 est la genèse, jamais décidée, R1-F61) ; `to_height`
est nul tant que le jeu est en vigueur.

```bash
$R capturer --transaction <hachage> --role deploiement --contrat <adresse> --captures "$E/publication"
$R publier-jeu --validateurs chain/runtime/validators.json --depuis 1 \
  --source "chain/runtime/validators.json du réseau de développement noortrace-2124-dev" --sortie "$E/jeu-publie.json"
```

`capturer --role deploiement` écrit l'index que `contracts[].evidence.capture`
désigne, après CP-1 à CP-6 et les contrôles propres au déploiement de RG-19
(adresse créée, transaction sans destinataire signée par le déployeur au
nonce déclaré). `publier-jeu` lit un `validators.json`, vérifie RG-18 sur ce
jeu (hors `operators`), recalcule son hachage (CT-6 EX-11.8), l'écrit dans
`outputs.validator_set_hash` et dans `source`, et écrit le fichier
`validateurs-v0` d'un seul jeu, que reprend `exporter` sans manifeste
(EX-9.10). Pour le réseau de développement, les captures des blocs 8316 à
8328 restent à faire avant que la tête n'atteigne 308 316 (EX-4.27).

Exemple : la sortie de `publier-jeu` pour le réseau de développement.

<!-- schema: validateurs -->
```json
{
  "version": 0,
  "sets": [
    {
      "from_height": 1,
      "to_height": null,
      "validators": [
        {
          "id": "v1",
          "pubKeyHex": "0x0405de9b275a0008b0013919700664ba64bab05c24fcac0585327478e88e40bbb69ffde05aca81fc8a108f62d417afe0aa22f1304861007a27d49ca57fa5189baf"
        },
        {
          "id": "v2",
          "pubKeyHex": "0x040506c4d376fdc84b69844114a7bca3f92ffc13da0a06ce17b5383ecfb11d7368ff73aa14526179fde60236fa0555d03c8aa0906a41271268f4c1896e0322052a"
        },
        {
          "id": "v3",
          "pubKeyHex": "0x040a9ee3f38241823ebfdde52feda9322ec271ca75338faf58b225ee547c6a696fe110f8ea7e9857654239d23eee6806ca57ad7ccae053c6de8b335426d4e2c532"
        },
        {
          "id": "v4",
          "pubKeyHex": "0x042cc90013f733942d895a08797c90d0f64111bfe94eabe1f1890a2dac17eeb76e65c6e5fe0e31b1d2205beda58bbf85775c377b2a9342db8ace7132c719885443"
        }
      ],
      "source": "chain/runtime/validators.json du réseau de développement noortrace-2124-dev, publié par l'exploitant ; hachage 0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751"
    }
  ]
}
```

**EX-9.13** Le réviseur obtient le jeu d'au moins deux opérateurs de
validateurs indépendants et compare les hachages (CT-6 §12.5, RG-20) ; un
jeu publié par le seul exploitant ne vaut pas ancre de confiance.

**EX-9.14** Le jeu d'une instance étant fixe en version 0 (EX-4.13), un
dossier n'a qu'un jeu par instance. Le jeu reçoit un `to_height`, la dernière
hauteur décidée, dans une révision du manifeste publiée avant l'arrêt de
l'instance (EX-4.25), après la capture des dernières transactions prouvées ;
la nouvelle instance a son propre manifeste.

## 10. Image conteneur et topologies

### 10.1 Image du nœud

`chain/docker/Dockerfile` construit l'image du binaire de l'instance : Go
1.26.9 épinglé, clone du commit de noorchain-core épinglé et vérification de
sa tête, correctifs de `chain/patches/` appliqués après `git apply --check`,
`go build -trimpath`, image finale distroless sans shell, utilisateur
`65532:65532`, volume `/var/lib/noorcore`, `ENTRYPOINT` sans `CMD` (R1-F65,
R1-F66). Construite sans correctif le 2026-10-21 : 67,5 Mo, suiveur en
conteneur égal au meneur ; la construction **avec** correctif n'a pas été
rejouée (R1-F69).

**EX-10.1** L'image livrée à un partenaire DOIT : (a) épingler ses deux
images de base par condensé (`FROM …@sha256:…`), et non par étiquette comme le
`Dockerfile` actuel (R1-F65) ; (b) avoir été construite avec le correctif et
reconstruite à l'identique au moins une fois ; (c) être inscrite dans le
manifeste par son condensé (`noorcore.artifacts`), avec le commit de
noorchain-core, le nom et le SHA-256 de chaque correctif appliqué, jamais son
contenu, et la version de Go (EX-4.21, EX-4.23). Le partenaire l'emploie par
son condensé (`noortrace/noorcore@sha256:…`), jamais par une étiquette. Son
binaire n'est pas celui du réseau de développement (4.6).

### 10.2 Validateur chez un partenaire

| Ce que le partenaire reçoit | Ce qu'il produit | Ce qu'il renvoie |
|---|---|---|
| condensé de l'image (EX-10.1), document de genèse et son SHA-256, identifiants BFT et EVM, `validators.json` final, adresses des pairs, CA du maillage p2p | sa clé de validateur, générée sur son site et jamais copiée (`chain/README.md`, « Ce qui change pour un réseau prod-like ») ; son certificat TLS de nœud | sa clé **publique** et son identifiant, avant la genèse ; puis la ligne de journal de EX-10.4, point 3 |

**EX-10.2** Un validateur partenaire DOIT tourner en profil `prod-like`
(`-network-profile prod-like`, `-bft-allow-experimental`), avec la clé dans un
fichier lisible du seul utilisateur 65532 (`-validator-key-file`), le
`validators.json` du manifeste et la genèse dans les conditions d'EX-4.4.
noorcore n'exige
l'authentification et TLS du maillage que pour une écoute sans hôte, sur
`0.0.0.0` ou sur `::` (`core/main.go:525-533`, `697-713` de noorchain-core) :
CT-4 les exige pour toute
adresse p2p non locale (`-p2p-require-auth` avec un jeton d'au moins 32
caractères, `-p2p-tls`, `-p2p-tls-ca`, `-p2p-tls-require-client-cert`,
`-p2p-allowed-cidrs` restreint aux pairs).

**EX-10.3** Le RPC d'un validateur n'est jamais public : derrière un
mandataire TLS opéré par l'opérateur du validateur, sur son site et dans son
domaine de panne (EX-4.12), `-rpc-trusted-proxies` posé et jeton
`NOOR_HTTP_AUTH_TOKEN` (`chain/README.md`, point 5) ; il n'est ouvert qu'aux
clients et aux outils que l'exploitant désigne (section 12), à travers la
garde d'admission d'EX-10.8. Le jeton du nœud est unique par nœud et sans
identité de client (`core/rpc/jsonrpc_http.go:18-33`) : l'identité vient de
la garde.

**EX-10.8** Sur une instance de production, toute écriture
(`eth_sendRawTransaction`) vers un validateur passe par une **garde
d'admission** (mandataire devant le point RPC, dans le domaine de panne du
validateur) qui DOIT : authentifier chaque client (jeton par client ou
certificat client mTLS, le quota se mesurant par jeton ou certificat, jamais
par le jeton `Bearer` du nœud) ; appliquer un quota par client (par exemple
10 transactions par minute) ; n'accepter qu'une transaction de type 2 de la
chaîne (RG-15) dont l'expéditeur a un solde au moins égal à `gasLimit ×
maxFeePerGas + value` (`eth_getBalance`) et dont le nonce est exactement
`eth_getTransactionCount(expéditeur, "latest")`, ce qui admet le renvoi des
mêmes octets (`--renvoyer`) et le remplacement au même nonce avec les frais à
`⌈1,1 × p⌉` (EX-8.16), le nonce d'état n'ayant pas avancé ; refuser toute
transaction dont l'expéditeur a déjà une transaction en attente (ce que fait
OP-3 côté outil, `transaction_en_attente`) ; journaliser les refus. Le
mandataire ajoute le jeton `Bearer` du nœud ; un mandataire local par client
(écoute sur `127.0.0.1`, certificat client vers le validateur) préserve
l'identité du client, contrairement à un mandataire partagé qui ajouterait le
jeton pour tous. CT-8 alerte sur la taille de la mempool de chaque validateur
et sur tout `transaction underpriced` reçu pour un envoi conforme à EX-4.15.
Le réseau de développement n'a pas cette garde (EX-4.20).

**EX-10.9** Le répertoire de données d'un validateur (`db/leveldb` : chaîne,
état de consensus `cons/v1/*`, marqueur de reprise) N'EST JAMAIS restauré
depuis une sauvegarde ni répliqué à chaud, et aucun instantané de volume n'en
est pris à chaud : l'état de consensus est dans la même base que la chaîne
(`core/node/node.go:1071`, `core/main.go:746`), un état dont la hauteur est au
plus la tête durable est tenu pour périmé et effacé, le nœud repartant à tête
+ 1 (`core/consensus/state.go:192-205`, `core/node/node.go:2158-2210`), aucun
journal de votes ni fichier « dernière hauteur signée » n'existe hors de la
base, et la garde de démarrage `prod-like` accepte un instantané cohérent avec
lui-même (`core/main.go:741-790`, `core/recovery/decision.go:60-128`). Un
validateur ainsi restauré à moins de 64 hauteurs de la tête attestée par
f + 1 pairs, ou sur une hauteur non encore décidée, revote sans mémoire de ses
votes : la quarantaine de rattrapage (écart ≥ 64,
`core/node/loop_bft_state.go:365-383`) protège le cas « instantané de la
veille », pas celui d'une chaîne arrêtée.
Seule la clé est sauvegardée, hors ligne (EX-10.7 : un signataire actif). Un
validateur qui perd ses données repart d'un répertoire vide et se rattrape
auprès de ses pairs par les certificats décidés (32 hauteurs par requête,
`core/consensus/catchup_wire.go:11-33`), tant que son retard tient dans la
rétention des certificats des pairs (300 000 hauteurs par défaut, EX-9.7) ;
ce rattrapage n'a pas été mesuré (SU-4, pilote) ; au-delà, la clé est retirée
et l'instance renouvelée (EX-4.13). Un seul validateur à la fois dans cet
état : avec deux validateurs perdus sur quatre et la chaîne arrêtée, on en
remet un, on attend qu'il soit rattrapé et qu'une hauteur nouvelle soit
décidée, puis le second (f = 1 : un seul validateur amnésique est toléré sur
la hauteur non décidée). La métrique `noor_bft_equivocations_total`
(`-metrics-addr`, 10.4 ; `core/metrics/snapshot.go:139-141`) vaut 0 et est
supervisée : toute hausse est un incident, dont les preuves sont publiées
(section 14). CT-8 (sauvegarde) et noorcore (garde « dernière hauteur et tour
signés » hors de la base) reçoivent les propositions correspondantes (13, 14).

**EX-10.4** Mise en service, dans cet ordre : (1) vérifier le condensé de
l'image et le SHA-256 de la genèse contre le manifeste ; (2) démarrer ; (3)
constater dans le journal les lignes d'EX-4.4, la ligne de règles égale à
`genesis.rules_line` (R1-F7), et les envoyer à l'exploitant ; (4) vérifier,
depuis l'outil, OP-1 et OP-2 contre ce validateur ; (5) relever
`retention.heights` (EX-9.7).

Commande type (modèle de `chain/docker/README.md`, « Exécution en
validateur », adapté au profil `prod-like` ; **non éprouvée** : ni le profil
`prod-like` ni l'image avec correctif n'ont été mesurés, R1, points non
vérifiés 4 et 8) :

```bash
docker run -d --name noorcore-<id> --network host --read-only --restart unless-stopped \
  --env-file /etc/noortrace/noorcore.env \
  -v noorcore-<id>:/var/lib/noorcore \
  -v /etc/noortrace/validators.json:/etc/noorcore/validators.json:ro \
  -v /etc/noortrace/validator.key:/etc/noorcore/validator.key:ro \
  -v /etc/noortrace/genese.json:/etc/noorcore/alloc.json:ro \
  -v /etc/noortrace/tls:/etc/noorcore/tls:ro \
  noortrace/noorcore@sha256:<condensé publié> \
    -chain-id <identifiant BFT> -evm-chain-id <identifiant EVM> -data-dir /var/lib/noorcore \
    -role follower -consensus bft -validator-id <id> \
    -validators-file /etc/noorcore/validators.json -validator-key-file /etc/noorcore/validator.key \
    -alloc-file /etc/noorcore/alloc.json -network-profile prod-like -bft-allow-experimental \
    -p2p-addr <adresse p2p>:<port> -boot-peers <pairs> -p2p-allowed-cidrs <adresses des pairs> \
    -p2p-require-auth -p2p-tls -p2p-tls-cert /etc/noorcore/tls/noeud.pem -p2p-tls-key /etc/noorcore/tls/noeud.cle \
    -p2p-tls-ca /etc/noorcore/tls/ca.pem -p2p-tls-require-client-cert \
    -rpc-addr 127.0.0.1:8545 -rpc-trusted-proxies <adresse du mandataire> \
    -health-addr 127.0.0.1:8080 -metrics-addr 127.0.0.1:9090
```

`/etc/noortrace/noorcore.env` (mode 0600) porte `NOOR_P2P_AUTH_TOKEN`,
`NOOR_HTTP_AUTH_TOKEN` et `NOOR_BFT_CERT_RETENTION_HEIGHTS` (EX-9.7). Un seul
validateur de l'instance prend `-role leader` ; ce rôle ne change que le
routage RPC, pas le consensus (`chain/docker/README.md`).

### 10.3 Relais RPC chez un client

Un suiveur (`-role follower -follow-rpc <meneur>`) est un **mandataire
JSON-RPC** devant un meneur : il ne détient ni bloc, ni état, ni certificat,
et n'en vérifie aucun (`chain/docker/README.md`, mesures du 2026-10-21,
R1-F63) :

| Mesuré | Valeur |
|---|---|
| Surcoût par appel, boucle locale | +0,6 à 2 ms |
| Données locales | 52 Kio, inchangées après 5 minutes |
| Meneur injoignable | `-32000 leader unreachable` pour tout sauf `eth_chainId`, `net_version`, `web3_clientVersion`, `noor_txindexStatus` (index local vide) ; `/healthz` répond `ok` quand même |
| `eth_chainId`, `net_version` | répondus localement depuis `-evm-chain-id` : faux si le drapeau est faux |
| Réponses relayées | décodées puis réencodées (clés en ordre alphabétique) ; au-delà de 2 Mio, `-32603 internal error` |
| Écritures | `eth_sendRawTransaction` relayée au seul meneur |

**EX-10.5** Un relais PEUT servir les applications du client (jeton, limites
de débit, journaux propres) ; il NE DOIT PAS servir à une capture (CP-1) ni
à la soumission d'une ancre ou d'une clôture, seule ou non (EX-8.15) : une
ancre est soumise au point RPC d'un validateur (par la garde d'EX-10.8, dans
le domaine de panne du validateur) sans aucun intermédiaire côté client, qui
verrait l'empreinte avant son inclusion (8.3). Pour la lecture
du jeu d'approbateurs, CT-3 §8.1 recommande déjà un validateur que le client
opère ou un validateur partenaire. La sonde `/healthz` d'un relais ne dit pas
que le meneur répond : la supervision du client sonde `eth_blockNumber` à
travers lui.

### 10.4 Ports et volumes

| Élément | Drapeau ou chemin | Défaut du binaire | Réseau de développement (node1) | Remarque |
|---|---|---|---|---|
| JSON-RPC | `-rpc-addr` | désactivé | `127.0.0.1:8645` | EX-10.3 |
| Santé | `-health-addr` | `127.0.0.1:8080` | `127.0.0.1:8745` | |
| Métriques | `-metrics-addr` | désactivé | `127.0.0.1:9645` | |
| P2P BFT | `-p2p-addr` | `127.0.0.1:30303` | `127.0.0.1:31400` | EX-10.2 |
| Données | `/var/lib/noorcore` | `-data-dir` | `chain/runtime/data/node1` | `db/leveldb/` (chaîne, certificats `cert/v1/…`), `db/geth/`, `oprec/` ; propriété 65532 |
| Secrets et configuration | `/etc/noorcore/…` (convention) | — | `chain/runtime/` | lecture seule ; clé en 0600 |

Source : `chain/docker/README.md`, « Ports » et « Volumes » ;
`chain/README.md`, « Ports ».

### 10.5 Topologie de production

**EX-10.6** Un jeu de production compte N = 3f + 1 validateurs, f ≥ 1
(EX-4.11 ; R2-F50), répartis selon EX-4.12 ; avec f fautes indépendantes au
plus, deux
certificats contradictoires d'une même hauteur ne peuvent pas exister et la
production de blocs continue (R2-F47, R2-F50). Le premier jeu de production a
N = 4 : quatre opérateurs, quatre sites, chacun joint aux trois autres par
`-boot-peers` et `-p2p-allowed-cidrs`, comme les nœuds du réseau de
développement (`chain/scripts/dev-net.sh:138-165`). Un jeu plus grand est une
nouvelle instance (EX-4.13).

**EX-10.7** Une clé de validateur n'a qu'un signataire actif : jamais deux
instances du même validateur en même temps (R2-F49, EX-4.12). noorcore, au
commit épinglé, ne lit la clé que dans un fichier (`-validator-key-file`,
`core/main.go:81`) ; aucune prise en charge d'un HSM ou d'un service de
signature distant n'a été trouvée dans `core/` (recherche du 2026-10-25). La
garde en HSM ou en KMS, état visé par EX-4.12, n'est donc pas réalisable sans
changer noorcore (section 14) : en version 0, la clé est un fichier lisible du
seul utilisateur du nœud, sur son seul site, et sa cérémonie relève de CT-7.

## 11. Règle de substitution

### 11.1 Ce qui se décide à la porte 4

Le registre est « d'exploitation substituable » (`chain/README.md`,
architecture « Instance dédiée ») : ce que prouve le contrôle 8 tient à un
quorum de validateurs que le réviseur déclare (CT-6 §11.1). Une chaîne dont
le fournisseur tient le quorum n'est pas plus indépendante de lui qu'un journal
qu'il signe seul ; elle ne vaut que si des tiers indépendants tiennent assez de
validateurs (EX-4.12, EX-10.6). À la porte 4 du plan, sur les mesures du
pilote, la décision est binaire : **garder la chaîne** avec des validateurs
partenaires, ou la **remplacer par un journal signé en base de données**.

### 11.2 Critères

| Id | Critère | Mesure | Seuil |
|---|---|---|---|
| SU-1 | Opérateurs indépendants | engagements écrits d'opérateurs de validateurs, fournisseur compris, pour l'instance de production | N = 3f + 1 validateurs, f ≥ 1, aucun opérateur ni site avec plus de f validateurs (EX-4.12, EX-10.6) ; pour N = 4, quatre opérateurs |
| SU-2 | Disponibilité | sur au moins 30 jours consécutifs du pilote en profil `prod-like` : délai entre `submitted_at` de l'envoi et l'obtention du reçu, pour chaque ancre et chaque clôture ; écarts d'horodatage entre blocs consécutifs ; épreuve provoquée du remplissage de la mempool par deux expéditeurs sans solde (EX-4.20) à travers la garde d'EX-10.8 | au moins 99 % des transactions incluses en moins de 60 s ; aucun arrêt de la production de blocs de plus de 15 minutes ; la garde refuse l'épreuve et aucune transaction conforme à EX-4.15 n'est refusée `underpriced` |
| SU-3 | Preuves complètes | captures du pilote (9.4) | 100 % des transactions prouvées capturées avec CP-1 à CP-6 réussies, dans l'heure ; aucun certificat perdu par élagage |
| SU-4 | Validateurs partenaires en état | pour chaque validateur partenaire, sur la même période : profil `prod-like`, lignes de démarrage d'EX-4.4 (EX-10.4), rétention de EX-9.7, authentification et TLS du maillage (EX-10.2), RPC fermé au public derrière la garde d'admission (EX-10.3, EX-10.8), aucune restauration du répertoire de données et rattrapage d'un validateur vide éprouvé (EX-10.9), `noor_bft_equivocations_total` à 0 | tous remplis, attestés par chaque opérateur |
| SU-5 | Effort d'exploitation | heures d'exploitation par mois et incidents du registre, relevés pendant le pilote | comparés au budget du plan (document interne) ; aucun chiffre dans le dépôt public |
| SU-6 | Exigence des clients et réviseurs | demandes écrites des clients et réviseurs du pilote | nombre de ceux qui exigent des validateurs tiers plutôt qu'un journal à témoins ; rapporté, sans seuil |
| SU-7 | Maintenance de noorcore | reconstruction de l'image de EX-10.1 à la porte 4 ; disponibilité de `noor_getCommitCertificate` dans le binaire construit | reconstruction à l'identique réussie ; méthode servie |

**EX-11.1** La chaîne est gardée si SU-1, SU-2, SU-3, SU-4 et SU-7 sont
remplis. Si SU-1 ou SU-4 ne l'est pas, elle est remplacée. Si seuls SU-2,
SU-3 ou SU-7 manquent, la porte 4 décide entre correction et remplacement au
vu de SU-5 et SU-6. La décision, les mesures et leurs sources sont consignées
dans le document de la porte.

### 11.3 Journal signé de remplacement : propriétés exigées

Un journal en base de données ne remplace le registre sans affaiblir le
contrôle 8 que s'il a les propriétés suivantes, tirées des journaux de
transparence publiés (R2, conséquences de la section 3.3) :

| Propriété | Exigence | Ce qui ne suffit pas |
|---|---|---|
| Tête signée vérifiable hors ligne | tête signée périodiquement (RFC 9162, R2-F26 ; point de contrôle C2SP, R2-F29), même sans nouvelle entrée, clé épinglée dans le fichier d'ancres du réviseur | un condensé non signé (R2-F36) ; une vérification qui exige la base elle-même (R2-F40) |
| Inclusion et ajout seul | preuve d'inclusion par entrée et preuve de cohérence entre têtes (R2-F25) | l'affirmation de l'opérateur |
| Vue unique | cosignatures d'au moins deux témoins indépendants du fournisseur, quorum épinglé dans les ancres (R2-F30, R2-F32) ; sans eux, le journal est un tiers de confiance (R2-F24) | les seules signatures du fournisseur |
| Temps | aucun : la date reste celle des ancres RFC 3161 et OpenTimestamps (CT-5) ; un journal ne date pas forcément ses entrées (R2-F34) | — |
| Cycle de vie | formats ouverts, preuves autonomes dans le dossier, export complet, tête finale publiée à l'arrêt (R2-F28) ; clés de journal et de témoins avec périodes de validité (R2-F34) | un service fermé qu'on peut retirer avec sa documentation (R2-F35) |
| Entrées | les trois actes du registre, mêmes champs et mêmes signatures : inscription au seuil, ancre par la clé de chaîne, clôture au seuil ; condensés liés à l'origine du journal au lieu de (`block.chainid`, `address(this)`) | — |

### 11.4 Conséquences pour CT-6

Cette version ne change rien à CT-6. Une substitution demanderait :

- une nouvelle version des trois parties du registre : `registre.json` porterait
  l'entrée, sa preuve d'inclusion et la tête cosignée ; `certificat-commit.json`
  et `validateurs.json` n'auraient plus d'objet ;
- une nouvelle version du fichier d'ancres : `registry` désignerait l'origine
  du journal, sa clé et les clés des témoins avec leur quorum, au lieu de
  `chain_id`, des adresses et des jeux de validateurs ;
- au contrôle 8, R-2 à R-7 remplacés par la vérification de la tête, des
  cosignatures et de la preuve d'inclusion ; R-8 par l'origine du journal ;
  R-9 et R-10 inchangés sur le fond (valeurs de la période, inscriptions).

Les dossiers déjà exportés avec des parties de chaîne restent vérifiables tant
que le réviseur dispose du jeu de validateurs : un certificat de commit se
vérifie hors ligne sans limite de temps. Ces changements sont des propositions
écrites (section 14), jamais faits en silence.

### 11.5 Conséquences pour les clients

| Élément | Avec la chaîne | Après substitution |
|---|---|---|
| Journal, manifeste, ancres RFC 3161 et OpenTimestamps | CT-1, CT-2, CT-5 | inchangés |
| Clé de chaîne de l'enregistreur | signe les ancres, relaie les clôtures, a une provision de NUR (EX-4.19) | signe encore l'entrée d'ancre ; plus de NUR ni de frais |
| Configuration `anchoring.registry` (CT-2 §15) | point RPC, clé de chaîne | point du journal ; nouvelle version du schéma de configuration |
| Jeu d'approbateurs (CT-3 §8) | lu au `CuratorSetRegistry` | lu dans les entrées du journal : nouvelle source pour CT-3 |
| Signatures des approbateurs | EIP-191 sur les condensés de la section 6 | mêmes champs, condensés liés à l'origine du journal |
| Indépendance du registre | validateurs partenaires | témoins ; le fournisseur opère le journal |

### 11.6 Migration

En cas de substitution : publier la dernière hauteur et le dernier jeu
(`to_height`, EX-9.14), capturer les certificats en attente, inscrire dans le
journal l'état final de chaque organisation (dernière période par journal,
clés actives), puis arrêter l'instance. L'architecture prévoit déjà l'arrêt de
la chaîne de production après le pilote (« Instance dédiée »).

## 12. Sûreté

| Menace | Constat | Réponse |
|---|---|---|
| Empoisonnement de la mempool par un expéditeur sans solde : client authentifié mais compromis, poste atteignant le relais RPC d'un client, tiers | Le RPC accepte une transaction sans contrôler le solde ni la limite de gaz (R1-F22) ; elle entre en mempool (5 120 places, file de nonces contigus sans borne par expéditeur), n'est écartée qu'au tour de proposition de son validateur sans avancer le nonce, ses suivantes ne sont jamais prêtes ni évincées, et le journal durable les rétablit au redémarrage pendant 24 h quand il est activé (R1-F24, R1-F30) ; pleine, la mempool refuse les transactions à 1 wei et le remplacement à 2 wei (EX-4.20, lecture du code, non provoqué) ; deux adresses vides suffisent, en 45 s par validateur, sans coût | Garde d'admission par client (EX-10.8 : authentification, quota, solde et nonce exacts, journal des refus) ; RPC des validateurs fermé derrière elle (EX-10.3) ; soumission à au moins deux validateurs d'opérateurs distincts (EX-8.15, DOIT) ; alerte CT-8 sur la taille de la mempool et sur tout `transaction underpriced` d'un envoi conforme à EX-4.15 ; limites du serveur : lots de 50, corps de 2 Mio, 32 requêtes simultanées, 100 requêtes/s par adresse (R1-F59) ; seuls les expéditeurs que la trésorerie approvisionne, jusqu'à `P_k`, paient le gaz (EX-4.19, EX-4.20) ; épreuve SU-2 ; contrôle du solde à l'admission par noorcore, plafond par expéditeur, éviction des transactions non prêtes et limite propre à `eth_sendRawTransaction` proposés (section 14) |
| Débit d'une clé | une transaction par expéditeur et par bloc, au tour du validateur qui l'a reçue, au plus 64 par bloc (R1-F37) ; 30 000 000 de gaz par bloc (R1-F14) | une clé de chaîne par clé Ed25519 (CT-2 EX-11.19) ; deux opérations par période et par journal suffisent largement |
| Clés des validateurs | fichier seulement ; la garde en HSM ou en KMS, état visé par EX-4.12, n'est pas possible sans changer noorcore (EX-10.7) ; un validateur restauré depuis une sauvegarde de sa base (chaîne et état de consensus ensemble) revote sans mémoire de ses votes sur une hauteur non décidée : deux validateurs sur quatre ainsi amnésiques peuvent produire deux certificats contradictoires (EX-10.9, R2-F47) | génération sur site, 0600, un seul signataire actif (EX-10.7), au plus f par opérateur et par site (EX-4.12), cérémonie selon CT-7 ; aucune restauration ni réplication à chaud du répertoire de données, un validateur perdu repart vide et se rattrape, un seul à la fois (EX-10.9) ; supervision de `noor_bft_equivocations_total` et publication des preuves (section 14) |
| Clé de chaîne compromise | elle signe des ancres et dépense sa provision (3.5) ; elle peut disperser sa provision vers des adresses neuves, que la révocation n'atteint pas, défaisant la cadence d'une transaction par bloc et l'examen d'EX-8.18 mais pas la borne en gaz ; après révocation, elle continue d'ancrer tant qu'elle a du NUR (EX-8.8) | consommation bornée par `P_k` et alerte au-delà de deux fois le budget (EX-4.20, EX-8.18) ; révocation (8.4), délai cible du contrat de service des approbateurs ; une clôture exige toujours le seuil des approbateurs ; le contrôle 8 écarte les ancres d'une clé révoquée (R-10) ; solde résiduel consigné comme capacité de nuisance restante ; garde d'admission limitée aux adresses connues proposée (section 14) |
| Clé de gouvernance compromise, ou approbateurs de connivence | la clé prend le jeu en deux blocs (`addCuratorSigned`, `setThresholdSigned`, effet immédiat), avec un expéditeur approvisionné et un accès en écriture ; le jeu au seuil inscrit une clé et clôt une période frauduleuse qui rend le journal inachevable (3.5) | garde de la clé en classe A à C (EX-8.21, CT-7) ; relais de l'exploitant sur confirmation hors bande (EX-8.21) ; sondage des événements du jeu et des journaux par le client (EX-8.12) ; journal abandonné, réassignation sur demande, nouveau nom de journal (EX-8.10, EX-6.4) ; délai ou cosignature proposés (section 14) |
| Clé de l'administrateur du registre | une seule clé réassigne le jeu de toute organisation (R1-F46), vers toute adresse non nulle (3.5) ; chargée en mémoire par l'outil (EX-7.3) | épinglage du jeu par CT-3 (CT-3 EX-8.6) ; réassignation sur demande écrite, nouveau jeu administré par la même clé de gouvernance et répondant comme un `CuratorSet`, capturée (EX-8.10) ; notification et surveillance de `CuratorSetAssigned` (EX-5.4, EX-8.12) ; garde en HSM (EX-5.4, CT-7) et réassignation cosignée par le jeu en place proposée (section 14) |
| Trésorerie | toute l'offre sur un seul compte chaud dont la clé signe en ligne chaque virement ; `--budget-jour` libre sans plafond du manifeste ; examen d'EX-8.18 local au répertoire des captures (8.7) | destinataires admis et plafond `fees.max_daily_budget_gas` (EX-8.20) ; trésorerie froide et compte d'approvisionnement borné proposés (EX-8.20, section 14) ; registre d'approvisionnements de l'exploitant (EX-8.20) ; cérémonie CT-7 |
| Dossier d'inscription non authentifié | aucune signature du client ni preuve de possession des clés : un fichier de clés altéré fait inscrire d'autres clés et approvisionner une autre clé de chaîne (EX-7.8) | contrôle du client avant toute politique (EX-7.17) ; demande signée et preuves de possession proposées (section 14) |
| Demande signée rejouée | une demande de clôture ou d'inscription signée au seuil est relayable par quiconque la détient, sans échéance (EX-8.19) | une demande par position, abandon consigné, `expires_at` pour la console et `signer`, copie de la demande relayée, `demande_existante` (EX-8.19) ; échéance vérifiée par le contrat proposée (section 14) |
| Substitution d'adresses | un manifeste d'instance ou un fichier de déploiement d'une autre chaîne | OP-1 (EX-4.9 : identifiants, jeu, code présent, bloc de déploiement) ; adresses recoupées avec les captures de déploiement (RG-19, 9.7) ; R-8 de CT-6 sur l'ancre du réviseur |
| Rejeu entre chaînes | transaction non protégée acceptée et incluse (R1-F33) ; l'identifiant EVM 2124 est inscrit pour une autre chaîne dans le registre public des identifiants (R2-F8) | jamais de transaction non protégée (EX-4.8, EX-8.13) ; clés distinctes par instance (EX-4.8) ; condensés liés à `block.chainid` et à l'adresse du contrat (section 6) ; certificats liés à l'identifiant BFT, comparé par CT-6 R-4 |
| Rejeu entre organisations | une signature d'une organisation présentée pour une autre | `orgId` dans chaque condensé au seuil (section 6) ; `periodHash` unique par organisation (`PeriodRegistry`) |
| Empreinte prise | ancre unique pour toute la chaîne (R1-F43) ; `periodHash` est vu avant inclusion par la console, les approbateurs, l'horodateur RFC 3161 et le chemin RPC (8.3) ; il faut à l'attaquant un expéditeur approvisionné et l'accès en écriture | ancre incluse et capturée avant toute remise de `periodHash` (EX-8.4, `condense cloture`) ; aucun intermédiaire côté client pour les ancres (EX-10.5) ; RPC fermés derrière la garde (EX-10.8) ; conduite de EX-8.6 ; ordre proposé à CT-2 et CT-5 (13) ; empreinte liée à l'émetteur proposée (section 14) |
| Faille d'un contrat | aucune mise à niveau en place ; le contrôle 8 dépend du code et des événements figés (EX-5.9, EX-5.10) | redéploiement à une nouvelle adresse après une faille établie, nouvelle révision du manifeste (EX-4.25) ; un dossier réparti entre deux générations de contrats ne passe pas R-8 (EX-5.9 ; section 14) |
| Réorganisation | `finalized` et `safe` rendent la tête ; la « hauteur finalisée » interne vaut tête − 64 (R1-F15) | un bloc est décidé quand son certificat porte un quorum vérifié (CP-4) ; aucun outil ne s'appuie sur `finalized` |
| Panne d'un validateur | quorum de 3 sur 4 : une panne tolérée ; délais de tour de 2 s doublés jusqu'à × 32 (R1-F10, R1-F11) ; les transactions qu'il détient attendent son retour (déduction ; R1, point non vérifié 2) | soumission à plusieurs validateurs (EX-8.15), renvoi des mêmes octets (EX-8.16) |
| Relais RPC menteur | un relais répète le meneur sans vérifier ; `eth_chainId` local peut mentir (10.3) | capture auprès d'un validateur (CP-1) ; certificat vérifié contre le jeu du manifeste avant d'être tenu pour capturé (CP-4) ; un relais peut retenir, il ne peut pas forger un quorum |
| Validateurs coalisés | si un tiers ou plus des voix est fautif, deux certificats contradictoires peuvent exister (R2-F47) | EX-4.12, EX-10.6 ; publication de toute preuve de double signature (section 14) |

## 13. Alignement avec le dépôt

Points du dépôt que CT-4 rend caducs ou complète. Hors de la spécification,
de ses schémas et de ses vecteurs, ce lot change : l'index `spec/README.md`
et des renvois textuels de CT-1 et CT-2 devenus faux, sans changer de ligne
ni de format ; `scripts/lib/noortrace.mjs` (commentaire de gaz de
`submitPeriod`, paramètre facultatif `setAdmin` de `bootstrapOrg`, défaut
inchangé) ; l'en-tête de `scripts/deploy/bootstrap-org.mjs` ; `package.json`
(scripts `vecteurs:ct4` et `registre`) ; `.github/workflows/ci.yml` (étapes
de A.6). « fait » ; « à faire » désigne un alignement à faire avec CT-4,
« proposition » un changement d'une autre spécification, écrit ici et non
appliqué.

| Emplacement | Avant | Attendu | État |
|---|---|---|---|
| `chain/README.md`, « Identifiants (à réserver) », l. 35-44, et point 3 de « Ce qui change pour un réseau prod-like », l. 300-302 ; commentaire de `chain/scripts/dev-net.sh`, l. 30-31 | 2124 « à réserver », distinct de « 2121 (chaîne PoSS de NOORCHAIN), 2122 et 2123 » | 2124 est inscrit pour « Metaplayerone Dubai Testnet » depuis le 2023-04-23 et 2121 pour « Catena Mainnet » (R2-F8, R2-F9) : 2124 reste l'identifiant du seul réseau de développement, sans réservation possible ; l'identifiant de production est choisi absent du registre public et inscrit avant la première genèse (EX-4.7) | à faire |
| `chain/README.md`, l. 39, et `ARCHITECTURE.md`, « Instance dédiée », l. 321-322 | 2121 et 2123 pour la chaîne du PoSS | une seule valeur, à établir (R1, point non vérifié 10) | à faire |
| `chain/README.md`, « Rétention », l. 216-219 | « ≈ 73 h à la cadence de 1,14 bloc par seconde » | une fourchette : 1,10 bloc/s mesuré le 2026-10-25 (≈ 75,8 h), 1,14 annoncé (9.5) | à faire |
| `chain/README.md`, « Ce qui change pour un réseau prod-like », point 4 | quatre validateurs sur deux sites, deux par site | aucun opérateur ni site avec plus de f validateurs (EX-4.12, EX-10.6) | à faire |
| `chain/docker/Dockerfile` | images de base épinglées par étiquette | par condensé ; image publiée par condensé (EX-10.1) | à faire |
| CT-6 EX-13.8 | « environ 73 h à la cadence de 1,14 bloc/s » | même fourchette, renvoi à CT-4 §9.5 | proposition (renvoi non indispensable : CT-6 inchangé dans ce lot) |
| CT-6 EX-13.11 et §12.5, ligne `registry.contracts` | « CT-4 DEVRAIT prévoir une rétention étendue » ; « publiés par CT-4 (section 13) » | renvois à CT-4 EX-9.7 (au moins 3 000 000 hauteurs) et au manifeste d'instance de CT-4 §4.8 (EX-9.12) | proposition (renvoi non indispensable : CT-6 inchangé dans ce lot) |
| CT-1 §8, règle 5, l. 627-630 | « la cohérence entre l'événement de rotation et le registre est un contrôle de CT-4 (section 11.4, contrôle 8) » | « relèvent de CT-4 (§8.4) ; la cohérence entre l'événement de rotation et le registre relève du contrôle 8 (CT-6 §11) » | fait (renvoi textuel) |
| CT-1 §10.4, l. 915 | « Le contrôle de ces valeurs contre le registre est le contrôle 8 (CT-4). » | « … est le contrôle 8 (CT-6 §11). » | fait (renvoi textuel) |
| CT-1 §15, l. 1415 | « Sans le contrôle 8 (CT-4) » | « Sans le contrôle 8 (CT-6) » | fait (renvoi textuel) |
| CT-2 EX-11.13 | « le contrôle 8 de CT-4 fait le reste » | « le contrôle 8 de CT-6 fait le reste » | fait (renvoi textuel) |
| CT-2 §15, `anchoring.registry.rpc_url` | un seul point RPC | une liste de points de validateurs d'opérateurs distincts (EX-8.15, DOIT en production) ; schéma de configuration figé en version 0.3 | proposition |
| CT-2 §9 et CT-5 : ordre des ancres | la racine est remise « à l'ancrage (CT-5) et au registre (CT-4) » sans ordre ; le jeton RFC 3161 révèle `periodHash` en clair (CT-6 EX-13.1) | ancre du registre incluse d'abord, puis requête RFC 3161 ; OpenTimestamps peut partir en parallèle (nonce avant les calendriers) ; ou risque accepté écrit (8.3, EX-8.4) | proposition |
| CT-3 §13 (console) | signe toute demande présentée | refuse une demande dont `expires_at` est passé et une seconde clôture pour une position (`org_id`, `journal_id`, `first_seq`) déjà signée (EX-8.19) | proposition |
| CT-6 EX-11.2, `scripts/verify/README.md` (table des tolérances) | « transactions brutes du bloc entier » dans le corps signé, sans membre ni encodage | nommer le membre `txsRaw` (base64 standard, une transaction par élément dans l'ordre du bloc) et les membres des corps `Proposal` et `Vote` (9.2) | proposition (CT-6 inchangé dans ce lot) |
| CT-8 : sauvegarde et supervision des validateurs | sauvegarde des bases « à définir » | interdire la restauration de `db/leveldb` et de l'état de consensus et tout instantané à chaud (une sauvegarde ne sert qu'à l'analyse) ; superviser la taille de la mempool, `transaction underpriced` sur un envoi conforme à EX-4.15 et `noor_bft_equivocations_total` (EX-10.8, EX-10.9) ; `--bft-recovery-reset` n'existe qu'en profil `dev` (`core/main.go:778-790`) | proposition |
| CT-2 et CT-3 : signatures de clôture et d'inscription | ni l'enregistreur ni le service d'approbation ne fixent comment les approbateurs reçoivent et signent `periodDigest` et `registerDigest` | l'enregistreur prépare la demande de signature (EX-8.5, `#/$defs/demande_signature`) et la remet au service d'approbation ; la console la recalcule, l'affiche en clair (EX-7.10) et rend les signatures ; le registre ne bloque jamais (EX-8.1) | proposition |
| CT-3 EX-8.5 (« noorcore n'a pas `eth_subscribe` ») | exact en HTTP et pour la spécification RPC documentée | le binaire sert `eth_subscribe` (`newHeads`, `logs`) en WebSocket, hors du contrat documenté (R1-F55) : le sondage reste la règle | proposition (note) |
| `scripts/lib/noortrace.mjs`, commentaire de gaz de `submitPeriod` (l. 31-34 de l'arbre de travail) | « submitPeriod consomme plus de 300000 gaz » | « de 234 079 à 314 256 gaz mesurés » (R1-F35, capture de CT-6) ; la limite explicite reste nécessaire | fait |
| `scripts/lib/noortrace.mjs`, `bootstrapOrg` | administrateur du `CuratorSet` = déployeur | paramètre facultatif `setAdmin` d'administrateur du jeu (EX-7.7), défaut inchangé pour `bootstrap-org.mjs` et `dev-roundtrip.mjs` | fait (outil de référence) |
| `scripts/deploy/bootstrap-org.mjs` | remplace le jeu d'une organisation existante après un avertissement | outil de développement, hors de la section 7 : dit en tête du fichier | fait |
| `scripts/deploy/deploy-noortrace.mjs` | déploie sans capturer les blocs de déploiement ni écrire de manifeste | inchangé ; l'outil de référence capture ces blocs (`capturer --role deploiement`, EX-4.27) ; la révision du manifeste (EX-5.2, EX-4.25) reste manuelle | fait pour la capture (outil de référence) ; révision du manifeste à faire |
| `spec/README.md` | CT-4 « à écrire » | CT-4 en revue ; schémas `instance-registre-v0`, `inscription-client-v0` et `operations-registre-v0` ; vecteurs `ct-4/` | fait |
| `package.json`, `.github/workflows/ci.yml` | rien pour CT-4 | scripts `vecteurs:ct4` et `registre` ; étapes de A.6 | fait |
| `README.md`, `README.fr.md`, `CHANGELOG.md`, `ARCHITECTURE.md` (« Ancrage », point 1 ; « Écrit au … », « À construire » ; « Décisions ouvertes », 6 et 7) | CT-4 absent | CT-4 écrit ; ancre avant clôture (EX-8.4) ; règle de substitution (section 11) ; outils de référence ; décisions 6 et 7 ci-dessous | fait |

Décisions de l'architecture touchées :

- **Décision 6** (identifiant de la chaîne de production et premiers
  validateurs partenaires, après le pilote) : non close. CT-4 en fixe les
  conditions : l'identifiant est choisi absent du registre public des
  identifiants à la date du choix et inscrit avant la première genèse
  (EX-4.7) ; les partenaires remplissent EX-4.12, SU-1 et SU-4 ; la décision
  se prend à la porte 4 selon la règle de la section 11.
- **Décision 7** (mode observateur) : reste ouverte. CT-4 ne s'appuie pas sur
  lui : la copie indépendante est l'archive des captures (9.5) et, en
  production, les validateurs partenaires (10.2). Un observateur exigerait
  aussi un moyen vérifié de reconstituer l'historique au-delà de la rétention
  (`chain/docker/README.md`, « Ce qu'il faudrait pour une copie
  indépendante », R1-F64). Le déclencheur reste celui de l'architecture.

## 14. Ce que cette version ne couvre pas

- **Le changement du jeu de validateurs** sur une chaîne en service (EX-4.13,
  EX-9.14) : en version 0, une nouvelle instance.
- **Le mode observateur** (décision 7) et toute copie de la chaîne hors des
  validateurs.
- **La clé de validateur en HSM** ou sous un service de signature distant,
  état visé par EX-4.12, que noorcore ne permet pas (EX-10.7).
- **Les preuves d'état** : appartenance au jeu, non-révocation d'une clé,
  dernière période (`eth_getProof` absent, R1-F54) ; elles restent des
  lectures déclaratives (OP-12).
- **Les évolutions de contrats**, toutes à une nouvelle adresse (EX-5.9),
  proposées pour une version suivante : dans `AttestationRegistry`, une
  empreinte liée à l'émetteur, contre l'empreinte prise (8.3), le contrôle
  de `s` bas et le refus du `docType` nul (EX-6.6) ; dans `CuratorSet`, le
  contrôle de `s` bas des opérations signées, un délai ou la cosignature d'un
  membre en place sur l'abaissement du seuil et l'ajout d'un membre
  (EX-8.21) ; dans `CuratorSetRegistry`, une forme signée d'`acceptAdmin` et
  une réassignation qui exige aussi la signature du jeu en place (EX-8.10 ;
  R1, conséquences C12 à C14) ; dans `PeriodRegistry` et `RecorderRegistry`,
  une échéance dans `periodDigest` et `registerDigest`, vérifiée par le
  contrat (EX-8.19) ; dans `RecorderRegistry`, une révocation d'urgence par
  la clé de chaîne elle-même et par la clé de gouvernance (EX-8.8).
- **Le dossier d'inscription signé** (version 0.1 du schéma
  `inscription-client`, `additionalProperties` fermé oblige) : signature
  EIP-191 de la clé de gouvernance (`request_signature`) sur le SHA-256 de la
  JCS (RFC 8785) de `instance.evm_chain_id`, `instance.bft_chain_id`,
  `instance.genesis_sha256`, `organisation`, `approvers`, `journals` et
  `recorders` sans `origin_proof` ; preuves de possession par chaque clé de
  chaîne (secp256k1 sur le même condensé) et par chaque clé Ed25519 (format
  CT-1), membres obligatoires mais nuls en `nature` `developpement`, exigés
  en production par OP-4, qui refuserait aussi `set_admin` parmi les membres,
  `set_admin` égal à une clé de chaîne et une clé de chaîne parmi les membres
  ; `cles-essai` et `inscrire-client --preparer` les produiraient sur le
  réseau de développement, `signer --dossier` en production ; le dossier signé
  vaudrait demande écrite d'EX-5.4 et EX-8.10 et son SHA-256 irait dans la
  capture `jeu_approbateurs` ; `exporter` et `verifier` recalculeraient depuis
  `txsRaw[transaction_index]` du certificat capturé les arguments du
  constructeur et `CREATE(déployeur, nonce) = result.curator_set` (EX-7.8,
  EX-7.17).
- **La garde d'admission dans noorcore** : contrôle du solde et du nonce à
  l'admission, plafond de transactions par expéditeur, éviction des
  transactions non prêtes après k tours, limite de débit propre à
  `eth_sendRawTransaction`, garde d'admission limitée aux adresses connues
  (EX-4.20, EX-10.8, section 12).
- **La trésorerie de production** : rôle `approvisionnement` dans
  `accounts` (schéma `instance-registre`, EX-3.1, 4.8, OP-5), trésorerie
  froide et compte d'approvisionnement borné (EX-8.20) ; un membre
  `request_sha256` dans l'index de capture pour la demande écrite d'une
  réassignation (schéma `operations-registre`, EX-8.10).
- **La signature externe des clés de l'exploitant** : `--jeton` et mTLS
  côté outil existent (EX-7.1) ; il manque une forme de signature externe
  secp256k1 (transaction non signée écrite avec les champs de 6.7.3 et son
  hachage à signer, transaction signée reprise par `capturer --envoi` ;
  condensés de 6.6.3 pour l'ancre et les opérations du jeu) pour que
  l'administrateur du registre et la trésorerie restent en HSM (EX-5.4,
  EX-7.3) ; l'interface de signataire de CT-2 §11.5 est Ed25519 et ne
  convient pas telle quelle.
- **La double signature des validateurs** : garde « dernière hauteur et tour
  signés » dans un fichier hors de `db/leveldb`, refus de signer en dessous,
  quarantaine qui s'applique aussi quand les réclamations fraîches sont
  insuffisantes (EX-10.9) ; en attendant, la règle d'exploitation d'EX-10.9.
- **Plusieurs générations de contrats** dans un même dossier : le fichier
  d'ancres de CT-6 n'a qu'une adresse par rôle et R-8 refuse le reste
  (EX-5.9) ; proposition pour une version suivante de CT-6.
- **La signature horaire des clôtures par des personnes** : en version 0, le
  jeu de l'organisation, une personne par clé (CT-3 EX-8.11) ; un jeu propre
  aux clôtures ou une délégation bornée demanderait un autre contrat.
- **Le transport des demandes de signature** entre l'enregistreur, le service
  d'approbation et la console (EX-8.5), et plusieurs points RPC dans la
  configuration de l'enregistreur (13).
- **`AttestationRegistry.revoke`** : aucun outil ne l'appelle ; une ancre de
  période n'est pas révoquée en version 0 (EX-6.13), et le sens d'une ancre
  révoquée n'est défini ni par CT-1 ni par CT-6.
- **La publication des preuves de double signature** des validateurs et leur
  format (section 12).
- **Le journal signé de remplacement** lui-même (section 11) : ses formats et
  la nouvelle version des parties du dossier.
- **La signature du manifeste d'instance** : en version 0, personne ne le
  signe (3.3) et le réviseur le recoupe (RG-20) ; une attestation de chaque
  révision par les opérateurs de validateurs partenaires est proposée pour une
  version suivante.
- **Les mesures en profil `prod-like`** : débit, latence et refus avec
  authentification et TLS du maillage, plus de quatre validateurs ou deux
  sites (R1, point non vérifié 8) ; la commande de 10.2 n'est pas éprouvée.
- **La procédure d'inscription de l'identifiant de production** au registre
  public des identifiants (décision 6).

## Annexe A — Vecteurs CT-4

### A.1 Principes

**EX-A.1** Les vecteurs sont sous `spec/vecteurs/ct-4/`, produits par
`scripts/vecteurs/generer-ct4.mjs` (`npm run vecteurs:ct4`) et rejoués à
l'identique : clés, nonces, frais, horodatages et identifiants fixes, aucune
valeur aléatoire ; les signatures secp256k1 sont celles de la RFC 6979, donc
déterministes. Les fichiers JSON sont écrits par `JSON.stringify(objet, null,
2)` suivi d'un saut de ligne. Le générateur n'efface et ne réécrit que ses
propres entrées de premier niveau, jamais `verificateur-independant/` ; il
refuse, sans rien effacer, un répertoire de sortie qui porte une autre entrée.

**EX-A.2** Entrées lues, jamais réécrites : `spec/vecteurs/ct-1/manifestes/`
et `spec/vecteurs/ct-1/cles/` (CT-1 §13), la capture unique de CT-6
`spec/vecteurs/ct-6/registre/capture/` (CT-6 annexe A.5) et
`test/fixtures/certificat-commit/validators.json`, `chain/config/alloc-dev.json`
et l'exemple de manifeste d'instance de 4.8. Le générateur ne dépend ni du
réseau ni de `hh-artifacts/` : les signatures de fonctions et d'événements
sont celles de 5.7 et 6.7.1. Les vecteurs de CT-1, CT-2, CT-3 et CT-6 ne
changent pas.

**EX-A.3** Chaque fichier de famille est conforme à
`operations-registre-v0.schema.json#/$defs/fichier_vecteurs`. Chacune des
vérifications RG-1 à RG-20 (6.9), chaque vérification OP- qui se calcule hors
chaîne (OP-4, OP-6, OP-7) et chaque vérification CP- qui se recalcule sur une
capture (CP-2, CP-3, CP-4 sans réseau, CP-5, CP-6) a au moins un cas qui
réussit et au moins un cas qui échoue, dont `refusal` nomme la vérification et
le code : le motif de la table de 6.9 pour une RG-, le code d'erreur de 7.11
ou de 9.3 pour une OP- ou une CP-, `entree_illisible` sur la première
vérification du cas (OP-6 pour une demande, OP-4 pour un dossier) pour un
document non conforme à son schéma ; le verdict d'une RG- est `reussi` ou
`echoue` (6.9). `expected` est nul pour un refus, sauf : famille
`transactions`, tout cas dont `input.fields` est donné (transaction
recalculée et signée depuis `fields`, EX-A.4 et cas de refus sur les frais,
la chaîne, la limite de gaz ou l'objet) ; familles `manifestes` et `capture`
(`expected.verdicts`, et `expected.registry` pour `manifestes`).

### A.2 Constantes

| Grandeur | Valeur | Usage |
|---|---|---|
| Chaîne | identifiant EVM 2124, identifiant BFT `noortrace-2124-dev` | toutes les familles |
| Contrats | `CuratorSetRegistry` `0x172076e0166d1f9cc711c77adf8488051744980c`, `RecorderRegistry` `0xbec49fa140acaa83533fb00a2bb19bddd0290f25`, `PeriodRegistry` `0x4ee6ecad1c2dae9f525404de8555724e3c35d07b`, `AttestationRegistry` `0xf4b146fba71f41e0592668ffbf264f1d186b2ca8` (réseau de développement, `capture.json` de CT-6) | condensés, appels, transactions |
| Jeu de validateurs | celui de l'exemple de 4.8 (`validator_sets[0].validators`, versionné dans `manifestes/valides/developpement/instance-r1.json`), copie publique `test/fixtures/certificat-commit/validators.json`, hachage `0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751` | capture, inscription, manifestes |
| Genèse et manifeste d'instance | `chain/config/alloc-dev.json`, SHA-256 `0x510e24e41cc401faa4e092338060cee0dc4629e5781a69af7a50b37edb6f4537` ; exemple de manifeste de 4.8 | manifestes |
| Jeu de validateurs d'essai | quatre clés secp256k1 de graine SHA-256(UTF-8(`noortrace/vecteurs/ct4/validateur/v<i>`)), `i` de 1 à 4, identifiants `v1` à `v4`, pour les certificats synthétiques d'un bloc de déploiement | manifestes |
| Organisation et journal des vecteurs | `assureur-demo` et `journal-sinistres` (CT-1 §13) | toutes |
| Approbateurs | comptes Hardhat 1 à 3, seuil 2 ; relayeur : compte Hardhat 0 (`capture.json` de CT-6) | condensés, demandes, transactions |
| Clés d'enregistreur | `rec-test-01`, `rec-test-02`, `rec-test-03` de CT-6 annexe A.5, avec leurs clés de chaîne de graine SHA-256(UTF-8(`noortrace/vecteurs/v0/cle-chaine/rec-test-0N`)) | condensés, empreintes, demandes |
| Manifestes | `spec/vecteurs/ct-1/manifestes/periode-1.json` à `periode-3.json` (`periodHash` et `anchor_fingerprint` de leur `attendu.json`) | empreintes, condensés de clôture, capture |
| Exemples de 7.7 et 7.10 | organisation `relecteur-exemple`, journal `journal-principal`, clés de graine SHA-256(UTF-8(`noortrace/exemple/ct4/…`)) (7.7, 7.10) ; manifeste d'exemple : `period_start` 1793520000, trois événements de hachage SHA-256(UTF-8(`noortrace/exemple/ct4/evenement/<i>`)), nonce SHA-256(UTF-8(`noortrace/exemple/ct4/nonce/1`)), `generated_at` `2026-11-01T09:00:01.000Z`, `periodHash` `0x266dd53a36a4c33232bd8dc4758eb036cc7adf8f483cb1ae8e7fc2a77034e8fb`, empreinte `0xe9d0f7920aa2156e93aab68d210ea95738d9631d9911b544063ecda33034c18c` | demandes, inscription |
| Transactions | celles de la capture de CT-6 avec leurs propres champs (type 2, identifiant 2124, `maxFeePerGas` 3, `maxPriorityFeePerGas` 1, limite 3 000 000, nonces 109 à 115, B.4) ; les autres de type 2, identifiant 2124, champs de frais et limite de gaz d'EX-4.15 et EX-4.17, nonces fixes | transactions |

Ces clés sont publiques et ne doivent jamais porter de valeur ;
`constantes.json` les porte toutes, et `INDEX.md` les imprime.

### A.3 Disposition

```text
spec/vecteurs/ct-4/
  INDEX.md                     généré : chaque cas, son attendu en une ligne, les constantes
  constantes.json              A.2
  identifiants.json            slugs et noms de journal, valides et refusés (RG-1, RG-2)
  doctypes.json                libellés de docType, valides et refusés (RG-3)
  empreintes.json              empreintes d'ancre (RG-4)
  condenses.json               champs de clôture, six condensés internes, hachage signé, signatures attendues, ordre, signatures refusées (RG-5 à RG-13)
  appels.json                  données d'appel des fonctions écrites par les outils, arguments des constructeurs (RG-14)
  transactions.json            transactions brutes de type 2 signées, et transactions à refuser (RG-15)
  manifestes/
    valides/                   manifestes d'instance conformes, avec leur genèse, leur jeu et leurs index de capture
    invalides/                 manifestes refusés (RG-16 à RG-20)
    manifestes.json            verdict RG- de chaque manifeste et ancre registry dérivée
  demandes/
    valides/                   demandes de signature conformes et complètes
    invalides/                 demandes refusées (schéma, OP-6, OP-7)
    demandes.json              verdict de chaque demande
  inscription/
    valides/                   dossiers d'inscription
    invalides/                 dossiers refusés (schéma, OP-4)
    inscription.json           verdict de chaque dossier
  capture/
    periode-1/                 copies octet pour octet des réponses brutes de la capture de CT-6 utiles à la période 1, et les index de capture
    variantes/                 index et réponses altérés (CP-2, CP-3, CP-4, CP-5, CP-6)
    capture.json               verdicts CP- et export attendu
  verificateur-independant/    module Go, jamais écrit par le générateur (A.5)
```

### A.4 Familles

| Famille | Cas | Vérifications | Attendu |
|---|---|---|---|
| `identifiants` | slugs et noms de journal admis et refusés (longueur, alphabet, casse, trait d'union au bord, espace, Unicode) ; les exemples d'EX-6.2 et EX-6.4 | RG-1, RG-2 | `org_id`, `journal_id`, ou `echoue` |
| `doctypes` | libellés admis et refusés ; `noortrace/periode/v0` | RG-3 | `docType` (`0x2970f32d…71ee` pour le libellé de période) ou `echoue` |
| `empreintes` | les trois manifestes de CT-1, période vide, cas synthétiques | RG-4 | égale à `anchor_fingerprint` de `spec/vecteurs/ct-1/manifestes/attendu.json` pour les trois manifestes |
| `condenses` | champs de clôture admis et refusés ; inscription, révocation (`registeredAt` fixé), clôture des trois manifestes de CT-1, ancre et révocation d'ancre, cinq opérations du jeu ; les exemples de 6.6.4 | RG-5 à RG-13, OP-6, OP-7 | préimage, condensé, hachage signé, signatures des comptes de A.2 rangées par adresse ; `echoue` pour une signature à `s` haut, à `v` hors {27, 28}, d'un non-membre, d'un doublon, d'un autre ordre, d'un nombre autre que `t` |
| `appels` | `registerRecorder`, `revokeRecorder`, `anchor`, `submitPeriod`, `setCuratorSet`, les cinq `…Signed`, arguments du constructeur de `CuratorSet` (sans le code de création, qui vient de la compilation, 6.7.2 et EX-A.2) | RG-14 | octets de l'appel ; pour chaque fonction de la capture de CT-6, la donnée de la transaction réelle (EX-A.4) |
| `transactions` | les transactions de la capture de CT-6 ; l'exemple de 6.7.3 ; transactions de A.2 ; remplacements à 2 et 3 wei ; refus : remplacement insuffisant, transaction non protégée, autre identifiant de chaîne, frais nuls, frais inégaux, limite au-delà de 2²⁴, liste d'accès, `s` haut, approvisionnement excessif, déploiement avec destinataire, enveloppe illisible | RG-15 | octets RLP signés et hachage ; `echoue` pour les transactions de la capture de CT-6 (frais 3 et 1, 6.7.3) et pour les onze cas de refus ; `expected` porte la transaction recalculée dès que `input.fields` est donné, refus compris |
| `manifestes` | l'exemple de 4.8 (`evidence` nul) ; un manifeste synthétique de production avec l'index de capture d'un bloc de déploiement signé par le jeu d'essai de A.2 ; une révision 2 chaînée ; refus : schéma, révision mal chaînée, SHA-256 de genèse, genèse invalide, règles absentes, ligne de règles ou identifiants ou offre faux, `valset_hash` faux, clé hors de secp256k1, opérateurs ou intervalles incohérents, opérateur avec plus de f validateurs en production, deux contrats d'un nom en service, adresse autre que `CREATE(deployer, nonce)`, arguments du constructeur, preuve absente, index d'un autre rôle (inscription du bloc 16648), transaction de déploiement avec destinataire, ancre fournie différente | RG-16 à RG-20 | verdict de chaque RG- (`expected.verdicts`), première vérification en échec et son motif (`refusal`) ; ancre `registry` dérivée (RG-20), nulle quand RG-20 échoue |
| `demandes` | demandes de 7.7 et de A.2 | schéma, OP-6, OP-7 | `valide`, ou refus nommé |
| `inscription` | dossiers de 7.10 et de A.2, à toutes les étapes ; refus : schéma, identifiants, membres, seuil, administrateur, classe de garde D en production | schéma, OP-4 | `valide`, ou refus nommé |
| `capture` | les quatre transactions de la période 1 de la capture de CT-6 (deux inscriptions, ancre, clôture) ; variantes : en-tête modifié, `block_hash` de l'index, `blockHash` du reçu capturé (CP-2) ; reçu falsifié, reçu d'une autre transaction (CP-3) ; autre jeu, `validator_set_hash` de l'index, certificat d'un autre bloc (CP-4) ; autre rôle, journal absent (CP-5) ; SHA-256 faux, en-tête et reçu sous un autre nom (CP-6) | CP-2 à CP-6 (CP-4 hors ligne, contre le jeu de A.2) ; EX-9.8 à EX-9.10 | statut de chaque CP- (`expected.verdicts`), première vérification en échec (`refusal`) ; parties exportées égales, en valeurs JSON et hors `source`, à celles de `spec/vecteurs/ct-6/registre/periode-1/` |

**EX-A.4** Confrontation avec la capture : pour chaque transaction de la
capture de CT-6, `appels` et `transactions` recalculent, avec les clés de A.2,
la donnée d'appel et la transaction signée, et l'attendu est la transaction
réelle lue dans la proposition du certificat capturé (membre `txsRaw` du
corps de la proposition, 9.2) : mêmes octets, même hachage que le reçu
(RG-14 et sérialisation de 6.7.3), et RG-15 `echoue` sur les seuls champs de
frais. Les signatures des cinq opérations au seuil de la capture (blocs
16648, 16652, 16656, 16668 et 16672) sont prises dans l'ordre de la
transaction, Hardhat 1 puis Hardhat 2 : RG-13 y `echoue` sur ce seul ordre
(6.6.4). Une discordance d'octets signale un écart entre la section 6 et ce
que les contrats ont réellement accepté.

### A.5 Vérificateur Go indépendant

**EX-A.5** Le module `spec/vecteurs/ct-4/verificateur-independant`
(`noortrace-ct4`, `go 1.24`, bibliothèque standard seulement) est écrit depuis
la seule spécification (CT-4, et CT-1 §10 et CT-6 §11.3 pour ce qu'ils
définissent), sans lire le code de `scripts/` ni de `test/`, comme ceux de
CT-1, CT-2 et CT-3 ; il PEUT copier les fichiers de keccak256, secp256k1 et
JSON de ces modules en le disant en tête de fichier. Il recalcule toutes les
familles de A.4 (RLP, ABI, EIP-191, RFC 6979, adresses de création,
`BFTBlockHash`, racines des reçus et des transactions, schémas), rend sur les
mêmes entrées les mêmes valeurs et les mêmes verdicts RG-, OP- et CP- que les
outils de référence (section 0), s'exécute par `go run . ..` depuis son
répertoire, et rend `0` si tout concorde, `1` s'il trouve une discordance,
qu'il liste, `2` pour un usage incorrect. Les motifs des schémas de CT-4
tiennent dans RE2 (bibliothèque `regexp` de Go, sans répétition bornée
au-delà de 1000) : la longueur d'une transaction sérialisée est bornée par
`maxLength`, pas par le motif.

### A.6 Tests et intégration continue

**EX-A.6** `test/registreCt4.test.js` (lancé par `npm test`) régénère les
vecteurs dans un répertoire temporaire et exige les mêmes octets, rejoue
chaque famille par l'implémentation de référence, valide chaque exemple
annoté `<!-- schema: … -->` de CT-4 contre son schéma, et exerce les
commandes de l'outil : `signer`, `exporter`, `verifier` et `publier-jeu`
sur les vecteurs, hors ligne ; `etat`, `condense` et les commandes d'écriture
sur le réseau Hardhat en mémoire (identifiant EVM 31337), qui ne sert pas
`noor_getCommitCertificate`, avec un manifeste d'essai (`nature`
`developpement`, identifiant BFT `noortrace-31337-essai`). Les références de
clés de test (`hardhat:`, `graine:`, `--exploitant`, `--cles-essai`) y sont
admises comme sur le réseau 2124 (EX-7.3). Le réseau Hardhat démarre avec un
prix de base EIP-1559 de 1 gwei et refuserait à l'envoi
(`transaction_refusee`, toutes les vérifications OP- préalables ayant réussi)
toute transaction d'EX-4.15 : avant le premier envoi, les tests fixent le
prix de base du bloc suivant à 1 wei par `hardhat_setNextBlockBaseFeePerGas`,
après quoi il reste à 1 wei tant qu'aucun bloc ne dépasse la cible de gaz
(noorcore, lui, le fixe à 1 wei, 4.5). Les commandes d'écriture y tournent
avec `--sans-capture`, option propre à 31337, refusée pour tout autre
identifiant EVM, qui saute CP-1 à CP-6 et les appels d'OP-1 et OP-2 propres à
noorcore (`noor_getCommitCertificate`, `noor_txindexStatus`) : les étapes du
dossier restent `incluse` et `result` reste nul (EX-7.16), de sorte que
l'épreuve d'EX-7.15 (`capturee` ou `faite`) n'est pas satisfaite par ce
réseau ; pour `condense cloture`, l'ancre incluse y suffit, l'index de capture
d'EX-8.4 n'y existant pas. La capture elle-même (CP-1 à CP-6, conduite de
9.3), la reprise de 8.6 (`capturer --transaction`, `--envoi --renvoyer`,
`--envoi --remplacer`) et l'examen d'EX-8.18 sont exercés sur le réseau
Hardhat derrière un pont
JSON-RPC des tests qui, pour la hauteur capturée, sert un en-tête dont
`hash` est le `BFTBlockHash`, des reçus cohérents et un certificat
synthétique signé par le jeu d'essai de A.2 (`noor_getCommitCertificate`,
`noor_txindexStatus`), avec un second manifeste d'essai qui déclare ce jeu.
Chaque vérification OP- a au moins un test de refus.

**EX-A.7** L'intégration continue régénère `spec/vecteurs/ct-4` et exige
`git diff --exit-code` et aucun fichier non suivi, puis lance dans le module
Go `gofmt -l` (sortie vide), `go vet ./...`, `go test ./...` et `go run . ..`,
à côté des tâches de CT-1, CT-2, CT-3 et CT-6.

**EX-A.8** L'épreuve de 7.12 se fait sur le réseau de développement, lancé par
`chain/scripts/dev-net.sh` seulement ; elle n'est pas rejouée par
l'intégration continue, et ses sorties ne sont pas des vecteurs.

## Annexe B — Sources des faits externes

Les renvois R1 et R2 désignent deux notes de recherche du lot CT-4, internes
et non publiées, relues le 2026-10-25 sur les sources qu'elles citent : R1
(noorcore et dépôt : code de noorchain-core au commit `618fcef`, dépôt public,
expériences sur le réseau de développement du 2026-10-25), R2 (pratiques
externes : identifiants de chaîne, gaz sans monnaie échangeable, journaux
signés, validateurs opérés par des tiers, conventions d'identifiants). Cette
annexe donne, pour chaque fait des deux notes et pour chaque point non vérifié
ou conséquence que cite cette spécification, l'objet et les sources
primaires ; ces sources font foi, pas la note. Un fait marqué « non vérifié »
le reste. B.3 et B.4 donnent les faits lus pour cette spécification hors des
notes, pour les sections 3 à 6 et pour les sections 7 à 14 et l'annexe A.

Conventions, reprises de CT-6 et CT-3 annexe B :

- un renvoi s'écrit comme dans le texte (section 0) : « R1-F38 », « R2-F8 »
  pour un fait ; « R1, point non vérifié 9 » pour un point non vérifié ;
  « R1, conséquence C7 » pour une conséquence de la note ; « R2, conséquences
  de la section 3.3 » pour un groupe de conséquences désigné par la section de
  la note qui les porte ;
- « présent dépôt » désigne un fichier de ce dépôt public, avec ses lignes au
  commit `3c6e896` : source publique, recoupable ;
- « noorcore » désigne le code de noorchain-core au commit `618fcef`, dépôt
  privé, non publiable : un fait qui en est tiré n'est pas recoupable
  publiquement ; le correctif de `chain/patches/` n'est ni copié ni cité ;
- « go-ethereum v1.17.0 » désigne le module que noorchain-core épingle, code
  public (https://github.com/ethereum/go-ethereum, étiquette `v1.17.0`) ;
- « expérience de la note » désigne une manipulation de R1 sur le réseau de
  développement, le 2026-10-25 entre 12:12 et 12:23 UTC, dont les sorties ne
  sont pas publiées.

### B.1 R1 — noorcore et dépôt

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R1-F1 | document de genèse du réseau de développement : 2124, quatre comptes, `rules` sans émission | présent dépôt, `chain/config/alloc-dev.json` L1-L19 | 2026-10-25 |
| R1-F2 | format du document de genèse et ses refus | noorcore, `core/node/alloc.go` | 2026-10-25 |
| R1-F3 | soldes de genèse appliqués une fois par répertoire de données | noorcore, `core/node/alloc.go`, `loop_local_setup.go`, `loop_bft_worldstate.go` | 2026-10-25 |
| R1-F4 | garde des règles de genèse, refus de démarrer sur écart | noorcore, `core/node/genesis_rules_guard.go`, `blockexec_divergence_diag.go` | 2026-10-25 |
| R1-F5 | ordre des contrôles au démarrage en mode BFT ; jeu d'au moins 4 | noorcore, `core/node/node.go` | 2026-10-25 |
| R1-F6 | ancre des paramètres d'émission ; variables effacées par `dev-net.sh` | noorcore, `core/node/emission_params_guard.go` ; présent dépôt, `chain/scripts/dev-net.sh` L64-L66 | 2026-10-25 |
| R1-F7 | journal de démarrage observé, ligne `genesis rules: verified against` | expérience de la note ; journal local `chain/runtime/logs/node1.log`, non versionné | 2026-10-25 |
| R1-F8 | identifiants `noortrace-2124-dev` et 2124 ; défauts du binaire | présent dépôt, `chain/scripts/dev-net.sh` L32-L34, `chain/README.md` L37-L44 ; noorcore, `core/main.go`, `core/config/config.go` ; expérience de la note | 2026-10-25 |
| R1-F9 | fichier de validateurs, tri par identifiant, clés de développement | noorcore, `core/consensus/valset.go` ; présent dépôt, `chain/scripts/dev-net.sh` L99-L124 | 2026-10-25 |
| R1-F10 | quorum de 3 sur 4 | noorcore, `core/consensus/quorum.go` ; expérience de la note | 2026-10-25 |
| R1-F11 | délais de consensus, doublés jusqu'à × 32 | noorcore, `core/consensus/timeouts.go`, `core/main.go` ; expérience de la note | 2026-10-25 |
| R1-F12 | rotation du proposant | noorcore, `core/consensus/engine.go` ; expérience de la note | 2026-10-25 |
| R1-F13 | cadence mesurée : 1,10 bloc/s | mesure de la note ; noorcore, `core/node/node.go` ; présent dépôt, `chain/README.md` L219 (valeur annoncée) | 2026-10-25 |
| R1-F14 | 30 000 000 de gaz par bloc ; plafond EIP-7825 de 2²⁴ par transaction | noorcore, `core/node/blockexec.go` ; go-ethereum v1.17.0, `params/config.go`, `params/protocol_params.go`, `core/state_transition.go` | 2026-10-25 |
| R1-F15 | `finalized` et `safe` rendent la tête ; hauteur finalisée interne tête − 64 | noorcore, `core/config/config.go`, `core/node/blockexec.go`, `core/rpc/jsonrpc_dispatch.go` ; expérience de la note | 2026-10-25 |
| R1-F16 | rétention des certificats : 300 000 hauteurs | noorcore, `core/consensus/cert_store.go`, `core/main.go` ; présent dépôt, `chain/README.md` L214-L222 | 2026-10-25 |
| R1-F17 | comptes préchargés : comptes Hardhat publics | présent dépôt, `chain/README.md` L263-L278 ; expérience de la note | 2026-10-25 |
| R1-F18 | `dev-net.sh` sans commande `reset` | présent dépôt, `chain/scripts/dev-net.sh` L351-L356, `chain/README.md` L116-L119 ; expérience de la note | 2026-10-25 |
| R1-F19 | profils ; gardes de production en mode BFT | noorcore, `core/main.go` ; présent dépôt, `chain/README.md` L280-L321 | 2026-10-25 |
| R1-F20 | prix minimal de la mempool, non abaissable sous 1 | noorcore, `core/txpool/txpool.go`, `core/config/config.go`, `core/main.go` | 2026-10-25 |
| R1-F21 | prix retenu par la mempool ; refus `transaction underpriced` | noorcore, `core/txpool/txpool.go`, `core/rpc/jsonrpc_dispatch.go` | 2026-10-25 |
| R1-F22 | `eth_sendRawTransaction` sans contrôle de solde ni de plafonds | noorcore, `core/rpc/jsonrpc_dispatch.go` | 2026-10-25 |
| R1-F23 | exécution au prix de base fixe de 1 wei ; débit et crédit | noorcore, `core/node/blockexec.go` ; go-ethereum v1.17.0, `core/state_transition.go` | 2026-10-25 |
| R1-F24 | transaction écartée sans reçu à la proposition | noorcore, `core/node/blockexec.go`, `core/txpool/txpool.go`, `core/node/loop_bft_events.go` | 2026-10-25 |
| R1-F25 | suggestions de prix servies ; valeurs par défaut d'ethers | noorcore, `core/rpc/jsonrpc_dispatch.go` ; expérience de la note ; ethers 6.17.0 (présent dépôt, `node_modules/ethers`) | 2026-10-25 |
| R1-F26 | aucune liste blanche, exemption ni parrainage de frais | noorcore, recherche dans `core/` ; `docs/FEE_MARKET_DECISION_2.1.md` | 2026-10-25 |
| R1-F27 | prix nul refusé à l'entrée, types 0, 1 et 2 | expérience de la note | 2026-10-25 |
| R1-F28 | coût réel par gaz et crédit de l'adresse nulle | expérience de la note | 2026-10-25 |
| R1-F29 | `effectiveGasPrice` d'un reçu de type 2 égal au plafond | noorcore, `core/rpc/jsonrpc_dispatch.go` ; expérience de la note | 2026-10-25 |
| R1-F30 | transaction d'un compte sans solde acceptée, retirée, puis rétablie au redémarrage | expérience de la note | 2026-10-25 |
| R1-F31 | plafond nul et pourboire 1 : acceptée, jamais incluse ; remplacement au même nonce | expérience de la note | 2026-10-25 |
| R1-F32 | limite de gaz au-delà de 2²⁴ : acceptée, jamais incluse | expérience de la note | 2026-10-25 |
| R1-F33 | autre identifiant de chaîne refusé ; transaction non protégée acceptée et incluse | expérience de la note ; noorcore, `core/rpc/jsonrpc_dispatch.go` ; go-ethereum v1.17.0, `core/types/transaction_signing.go` | 2026-10-25 |
| R1-F34 | lectures sans frais | expérience de la note | 2026-10-25 |
| R1-F35 | gaz de `registerRecorder`, `anchor`, `submitPeriod` ; délais des reçus | expérience de la note (`scripts/e2e/mesure-finalite.mjs`, présent dépôt) ; présent dépôt, `spec/CT-6-verificateur.md` L3006 | 2026-10-25 |
| R1-F36 | journal durable des transactions, durée de vie 24 h | noorcore, `core/config/config.go`, `core/node/node.go` ; expérience de la note | 2026-10-25 |
| R1-F37 | aucun relais entre validateurs ; une transaction par expéditeur et par bloc, au plus 64 | noorcore, `core/rpc/jsonrpc_dispatch.go`, `core/txpool/txpool.go`, `core/node/loop_bft_events.go` | 2026-10-25 |
| R1-F38 | inclusion au tour du validateur qui a reçu ; double envoi, inclusion unique | expérience de la note | 2026-10-25 |
| R1-F39 | délais entre envoi et reçu | expérience de la note | 2026-10-25 |
| R1-F40 | `ThresholdSignatures` : EIP-191, `s` bas, ordre libre, seuil nul | présent dépôt, `contracts/ThresholdSignatures.sol` L39-L56, L63-L101, L107-L115 | 2026-10-25 |
| R1-F41 | `PeriodRegistry` : champs, condensé, contrôles, événement | présent dépôt, `contracts/PeriodRegistry.sol` ; noorcore, `contracts/poss/PoSSRegistry.sol` (comparaison) | 2026-10-25 |
| R1-F42 | `RecorderRegistry` : état, condensés, règles d'inscription, événements | présent dépôt, `contracts/RecorderRegistry.sol` | 2026-10-25 |
| R1-F43 | `AttestationRegistry` : condensés, ancre unique pour toute la chaîne, pas de `s` bas | présent dépôt, `contracts/AttestationRegistry.sol` ; noorcore, `contracts/poss/AttestationRegistry.sol` (identité des fichiers) | 2026-10-25 |
| R1-F44 | `DOC_TYPE_PERIODE` et empreinte d'ancre | présent dépôt, `scripts/lib/noortrace.mjs` L60-L61, L117-L128 (arbre de travail), `scripts/lib/registre.mjs` L68-L69, `spec/CT-1-evenements-et-formats.md` L908-L915 | 2026-10-25 |
| R1-F45 | `CuratorSet` : administration, opérations signées, nonce | présent dépôt, `contracts/CuratorSet.sol` | 2026-10-25 |
| R1-F46 | `CuratorSetRegistry` : administrateur unique, sans forme signée | présent dépôt, `contracts/CuratorSetRegistry.sol`, `scripts/lib/noortrace.mjs` L210-L213 (arbre de travail) | 2026-10-25 |
| R1-F47 | sujets des événements prouvés par le contrôle 8 | présent dépôt, `spec/CT-6-verificateur.md` L3182-L3195 | 2026-10-25 |
| R1-F48 | ordre réel de déploiement ; blocs 8316 à 8328 | présent dépôt, `scripts/lib/noortrace.mjs`, `scripts/deploy/deploy-noortrace.mjs` ; fichier local `deployments/noorcore.json`, non versionné | 2026-10-25 |
| R1-F49 | `bootstrap-org.mjs` pas à pas | présent dépôt, `scripts/deploy/bootstrap-org.mjs` L30-L78, `scripts/lib/noortrace.mjs` L335-L404 (arbre de travail) | 2026-10-25 |
| R1-F50 | `dev-roundtrip.mjs` pas à pas | présent dépôt, `scripts/e2e/dev-roundtrip.mjs` | 2026-10-25 |
| R1-F51 | limite de gaz explicite ; `eth_estimateGas` heuristique | présent dépôt, `scripts/lib/noortrace.mjs` L26-L58 (arbre de travail) ; noorcore, `core/rpc/jsonrpc_dispatch.go` ; expérience de la note | 2026-10-25 |
| R1-F52 | compilation : Solidity 0.8.20, `viaIR`, réseau `noorcore` | présent dépôt, `hardhat.config.mjs` L9-L15, L22-L26 | 2026-10-25 |
| R1-F53 | méthodes JSON-RPC servies | noorcore, `core/rpc/jsonrpc_dispatch.go` ; expérience de la note | 2026-10-25 |
| R1-F54 | méthodes non servies (`eth_getProof`, `txpool_*`, …) | expérience de la note ; noorcore, `core/rpc/jsonrpc_dispatch.go`, `docs/RPC_SPEC_2.1.md` | 2026-10-25 |
| R1-F55 | `eth_subscribe` en WebSocket, hors du contrat documenté | noorcore, `core/rpc/jsonrpc_ws.go`, `jsonrpc_http.go`, `docs/RPC_SPEC_2.1.md` ; expérience de la note | 2026-10-25 |
| R1-F56 | `eth_getBlockReceipts` rend une liste vide | noorcore, `core/rpc/jsonrpc_dispatch.go` ; expérience de la note | 2026-10-25 |
| R1-F57 | reçu servi sans `logsBloom` ; en-tête servi | expérience de la note | 2026-10-25 |
| R1-F58 | `eth_getLogs` borné à 16 384 blocs ; `eth_call` à une hauteur | expérience de la note ; noorcore, `core/config/config.go` | 2026-10-25 |
| R1-F59 | bornes du serveur RPC | noorcore, `core/rpc/limits.go` | 2026-10-25 |
| R1-F60 | `noor_getCommitCertificate` selon le dépôt | présent dépôt, `chain/README.md` L165-L261, `scripts/verify/certificat-commit.mjs`, `scripts/verify/README.md` L9-L80 | 2026-10-25 |
| R1-F61 | réponses et erreurs mesurées de `noor_getCommitCertificate` | expérience de la note | 2026-10-25 |
| R1-F62 | constantes de signature BFT | noorcore, `core/consensus/signing.go`, `state.go` ; présent dépôt, `scripts/lib/certificat-commit.mjs` | 2026-10-25 |
| R1-F63 | mode suiveur : relais sans données ni vérification | noorcore, `core/node/loop_follower.go`, `core/rpc/jsonrpc_dispatch.go`, `limits.go` ; présent dépôt, `chain/docker/README.md` L230-L407, `chain/README.md` L209-L212 | 2026-10-25 |
| R1-F64 | copie indépendante : ce qui manque à un observateur | présent dépôt, `chain/docker/README.md` L409-L488 | 2026-10-25 |
| R1-F65 | ce que le `Dockerfile` épingle ; images de base par étiquette | présent dépôt, `chain/docker/Dockerfile`, `chain/docker/README.md` L96-L98 | 2026-10-25 |
| R1-F66 | image finale : binaire, volume, utilisateur, pas de `CMD` | présent dépôt, `chain/docker/Dockerfile` L96-L119, `chain/docker/README.md` L46-L58 | 2026-10-25 |
| R1-F67 | rôles validateur et suiveur en conteneur | présent dépôt, `chain/docker/README.md` L112-L187, `chain/docker/docker-compose.yml` L21-L66 | 2026-10-25 |
| R1-F68 | volumes, ports et variables du nœud | présent dépôt, `chain/docker/README.md` L189-L228 | 2026-10-25 |
| R1-F69 | état de vérification de l'image ; drapeaux de construction | présent dépôt, `chain/docker/README.md` L80-L110, `chain/scripts/build-noorcore.sh` L100-L104 | 2026-10-25 |
| R1-F70 | exigences de CT-6 §13.3 envers CT-4 | présent dépôt, `spec/CT-6-verificateur.md` L3633-L3730 | 2026-10-25 |
| R1-F71 | formats et règles de CT-6 §11 pour les parties du registre | présent dépôt, `spec/CT-6-verificateur.md` L2931-L3405, L3627-L3628, L4000-L4009 | 2026-10-25 |
| R1-F72 | CT-3 §8 : lecture du jeu, jeu épinglé, source | présent dépôt, `spec/CT-3-approbations.md` L160, L1981-L2178, L3507-L3511 | 2026-10-25 |
| R1-F73 | CT-2 : inscription, clé de chaîne, panne du registre, configuration | présent dépôt, `spec/CT-2-enregistreur.md` L257-L270, L3307-L3311, L4970-L5075, L5935, L6086, L6338-L6349, L7234-L7286 | 2026-10-25 |
| R1-F74 | CT-1 : renvois au registre | présent dépôt, `spec/CT-1-evenements-et-formats.md` L561, L627-L630, L893-L915, L966-L990, L1128, L1192-L1194, L1305, L1415-L1420 | 2026-10-25 |
| R1, point non vérifié 1 | rétablissement d'une transaction écartée observé sur node1 seulement | point non vérifié de la note | 2026-10-25 |
| R1, point non vérifié 2 | sort des transactions détenues par un validateur arrêté | point non vérifié de la note ; déduction de R1-F37 et R1-F38 | 2026-10-25 |
| R1, point non vérifié 3 | effet d'une copie restée en mempool après un double envoi | point non vérifié de la note | 2026-10-25 |
| R1, point non vérifié 4 | construction de l'image avec correctif non rejouée | point non vérifié de la note ; présent dépôt, `chain/docker/README.md` L80-L110 | 2026-10-25 |
| R1, point non vérifié 5 | suiveur réel non relancé ; mesures reprises du README | point non vérifié de la note ; présent dépôt, `chain/docker/README.md` | 2026-10-25 |
| R1, point non vérifié 6 | lien entre la boucle de 1 s et la cadence | point non vérifié de la note | 2026-10-25 |
| R1, point non vérifié 7 | certificat élagué non observé | point non vérifié de la note | 2026-10-25 |
| R1, point non vérifié 8 | profil `prod-like` non mesuré | point non vérifié de la note | 2026-10-25 |
| R1, point non vérifié 9 | empreinte prise par un tiers avant inclusion : lecture du code | point non vérifié de la note ; présent dépôt, `contracts/AttestationRegistry.sol` | 2026-10-25 |
| R1, point non vérifié 10 | identifiant de la chaîne du PoSS : 2121 ou 2123 | point non vérifié de la note ; présent dépôt, `chain/README.md` L39, `ARCHITECTURE.md` L321-L322 ; noorcore, `core/main.go` | 2026-10-25 |
| R1, point non vérifié 11 | destruction de la part de base des frais | point non vérifié de la note | 2026-10-25 |
| R1, point non vérifié 12 | correction ultérieure de `effectiveGasPrice` | point non vérifié de la note | 2026-10-25 |
| R1, point non vérifié 13 | `eth_estimateGas` qui propage un échec d'exécution | point non vérifié de la note ; noorcore, `core/rpc/jsonrpc_dispatch.go` | 2026-10-25 |
| R1, point non vérifié 14 | taille d'un certificat de bloc plein | point non vérifié de la note | 2026-10-25 |
| R1, conséquence C5 | une transaction acceptée peut ne jamais être incluse, puis revenir : remplacement au même nonce, relevé de 10 % | R1-F30 à R1-F32 ; noorcore, `core/txpool/txpool.go` (B.3) | 2026-10-25 |
| R1, conséquence C7 | certificats des blocs de déploiement du réseau de développement dans la fenêtre jusqu'à une tête d'environ 308 316 | calcul de la note sur R1-F16 et R1-F48 | 2026-10-25 |
| R1, conséquences C12 à C14 | contrats figés en version 0 ; clé unique de réassignation ; empreinte unique pour toute la chaîne | présent dépôt, `contracts/` ; R1-F43, R1-F45, R1-F46 | 2026-10-25 |
| R1, conséquence C18 | image épinglée par condensé ; binaires de l'image et du réseau de développement construits avec des drapeaux différents, non interchangeables (déduction, non comparée) | R1-F65, R1-F69 ; présent dépôt, `chain/docker/Dockerfile`, `chain/scripts/build-noorcore.sh` L100-L104 | 2026-10-25 |

### B.2 R2 — Pratiques externes

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R2-F1 | EIP-155 : identifiant de chaîne dans le hachage signé | https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md | 2026-10-25 |
| R2-F2 | EIP-155 : valeur unique, renvoi aux registres d'identifiants | https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md | 2026-10-25 |
| R2-F3 | EIP-1344 : opcode `CHAINID` | https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1344.md | 2026-10-25 |
| R2-F4 | EIP-695 : `eth_chainId` | https://github.com/ethereum/EIPs/blob/master/EIPS/eip-695.md | 2026-10-25 |
| R2-F5 | bornes des identifiants (EIP-2294, profil CAIP-2 `eip155`) | https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2294.md ; https://github.com/ChainAgnostic/namespaces/blob/main/eip155/caip2.md | 2026-10-25 |
| R2-F6 | règles d'attribution d'ethereum-lists/chains | https://github.com/ethereum-lists/chains/blob/master/README.md | 2026-10-25 |
| R2-F7 | contraintes vérifiées par l'intégration continue du registre | https://github.com/ethereum-lists/chains (`processor/src/main/kotlin/org/ethereum/lists/chains/Env.kt`, `Main.kt`, `README.md`) | 2026-10-25 |
| R2-F8 | 2124 inscrit pour « Metaplayerone Dubai Testnet » | https://github.com/ethereum-lists/chains/blob/master/_data/chains/eip155-2124.json ; https://chainid.network/chains.json | 2026-10-25 |
| R2-F9 | 2121 « Catena Mainnet », 2122 inscrit, 2123 absent | https://github.com/ethereum-lists/chains (`_data/chains/eip155-2121.json`, `eip155-2122.json`, `eip155-2123.json`) ; https://chainid.network/chains.json | 2026-10-25 |
| R2-F10 | identifiants absents de la plage 2100-2159 au 2026-10-24 | https://chainid.network/chains.json (calcul de la note) | 2026-10-25 |
| R2-F11 | identifiant de réseau et identifiant de chaîne (Besu, GoQuorum) | https://github.com/hyperledger/besu-docs (`docs/public-networks/concepts/network-and-chain-id.md`) ; https://github.com/Consensys/doc.goquorum (`docs/concepts/network-and-chain-id.md`) | 2026-10-25 |
| R2-F12 | CAIP-2 : nommage `namespace:reference` | https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md | 2026-10-25 |
| R2-F13 | Besu : gaz gratuit, ou monnaie allouée et prix non nul | https://github.com/hyperledger/besu-docs (`docs/private-networks/how-to/configure/free-gas.md`) ; https://besu.hyperledger.org/private-networks/how-to/configure/free-gas | 2026-10-25 |
| R2-F14 | Besu : limites de taille, plafond EIP-7825 | https://github.com/hyperledger/besu-docs (`docs/private-networks/how-to/configure/free-gas.md`) | 2026-10-25 |
| R2-F15 | Besu : prix minimal nul, contrôle de solde désactivé | https://github.com/hyperledger/besu-docs (`free-gas.md`, `docs/public-networks/reference/options.md`, `docs/public-networks/concepts/transactions/pool.md`) | 2026-10-25 |
| R2-F16 | Besu : bornes du pool et du RPC contre le déni de service | https://github.com/hyperledger/besu-docs (`pool.md`, `options.md`) | 2026-10-25 |
| R2-F17 | Besu : permissions de nœuds et de comptes | https://github.com/hyperledger/besu-docs (`docs/private-networks/concepts/permissioning.md`) | 2026-10-25 |
| R2-F18 | Besu : liste de comptes non contrôlée à l'import d'un bloc | https://github.com/hyperledger/besu-docs (`docs/private-networks/how-to/use-local-permissioning.md`) | 2026-10-25 |
| R2-F19 | Besu : retrait des permissions par contrat en 25.6.0 | https://github.com/hyperledger/besu/blob/main/CHANGELOG.md | 2026-10-25 |
| R2-F20 | GoQuorum : gaz gratuit par défaut | https://github.com/Consensys/doc.goquorum (`docs/concepts/free-gas-network.md`, `docs/concepts/gas-enabled-network.md`) | 2026-10-25 |
| R2-F21 | GoQuorum : permissions, taille de transaction | https://github.com/Consensys/doc.goquorum (`docs/concepts/permissions-overview.md`, `docs/reference/genesis.md`) | 2026-10-25 |
| R2-F22 | GoQuorum archivé ; cadre de sécurité | https://github.com/Consensys/quorum/blob/master/README.md ; https://github.com/Consensys/doc.goquorum (`docs/concepts/security-framework.md`) | 2026-10-25 |
| R2-F23 | CometBFT : sentinelles, RPC des validateurs jamais public | https://github.com/cometbft/cometbft (`docs/core/validators.md`, `docs/core/running-in-production.md`) | 2026-10-25 |
| R2-F24 | RFC 9162 : journal en ajout seul, tiers de confiance sans audit des vues | https://www.rfc-editor.org/rfc/rfc9162.txt | 2026-10-25 |
| R2-F25 | RFC 9162 : preuves d'inclusion et de cohérence | https://www.rfc-editor.org/rfc/rfc9162.txt | 2026-10-25 |
| R2-F26 | RFC 9162 : tête signée périodique | https://www.rfc-editor.org/rfc/rfc9162.txt | 2026-10-25 |
| R2-F27 | RFC 9162 : audit, comparaison des têtes | https://www.rfc-editor.org/rfc/rfc9162.txt | 2026-10-25 |
| R2-F28 | RFC 9162 : arrêt d'un journal, tête finale | https://www.rfc-editor.org/rfc/rfc9162.txt | 2026-10-25 |
| R2-F29 | C2SP : point de contrôle signé | https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md | 2026-10-25 |
| R2-F30 | C2SP : cosignatures et témoins | https://github.com/C2SP/C2SP (`tlog-cosignature.md`, `tlog-witness.md`) | 2026-10-25 |
| R2-F31 | Trillian en maintenance | https://github.com/google/trillian/blob/master/README.md | 2026-10-25 |
| R2-F32 | Tessera : points de contrôle et politique de témoins | https://github.com/transparency-dev/tessera/blob/main/README.md | 2026-10-25 |
| R2-F33 | Sigstore Rekor : moniteurs, paquet de vérification | https://github.com/sigstore/docs (`content/en/logging/overview.md`, `content/en/about/bundle.md`) | 2026-10-25 |
| R2-F34 | Rekor v2 : instances tournantes, aucun horodatage | https://github.com/sigstore/rekor-tiles (`README.md`, `CLIENTS.md`) | 2026-10-25 |
| R2-F35 | Amazon QLDB en arrêt complet depuis le 2025-07-31 | https://docs.aws.amazon.com/general/latest/gr/full_shutdown_services.html | 2026-10-25 |
| R2-F36 | API QLDB : condensé sans signature | https://raw.githubusercontent.com/boto/botocore/1.35.0/botocore/data/qldb/2019-01-02/service-2.json ; https://github.com/boto/botocore/blob/develop/CHANGELOG.rst | 2026-10-25 |
| R2-F37 | Azure Confidential Ledger : reçus fondés sur un arbre de Merkle | https://learn.microsoft.com/en-us/azure/confidential-ledger/overview | 2026-10-25 |
| R2-F38 | Azure Confidential Ledger : vérification d'un reçu, certificat de service | https://learn.microsoft.com/en-us/azure/confidential-ledger/verify-write-transaction-receipts ; https://learn.microsoft.com/en-us/azure/confidential-ledger/write-transaction-receipts | 2026-10-25 |
| R2-F39 | SQL Server Ledger : preuve d'altération, condensés hors base | https://learn.microsoft.com/en-us/sql/relational-databases/security/ledger/ledger-overview | 2026-10-25 |
| R2-F40 | SQL Server Ledger : vérification par la base | https://learn.microsoft.com/en-us/sql/relational-databases/security/ledger/ledger-database-verification ; https://learn.microsoft.com/en-us/sql/relational-databases/security/ledger/ledger-digest-management | 2026-10-25 |
| R2-F41 | Lamport, Shostak, Pease (1982) | https://lamport.azurewebsites.net/pubs/byz.pdf | 2026-10-25 |
| R2-F42 | Dwork, Lynch, Stockmeyer (1988) : N ≥ 3t + 1 avec signatures | https://groups.csail.mit.edu/tds/papers/Lynch/jacm88.pdf | 2026-10-25 |
| R2-F43 | Castro, Liskov (1999) : 3f + 1, défaillances indépendantes | https://css.csail.mit.edu/6.824/2014/papers/castro-practicalbft.pdf | 2026-10-25 |
| R2-F44 | Tendermint : n > 3f, décision sur 2f + 1 | https://arxiv.org/abs/1807.04938 | 2026-10-25 |
| R2-F45 | HotStuff : n ≥ 3f + 1, quorum 2f + 1 | https://arxiv.org/abs/1803.05069 | 2026-10-25 |
| R2-F46 | CometBFT : jeu permissionné, garde de la clé, contrôle de double signature | https://github.com/cometbft/cometbft (`docs/core/validators.md`) | 2026-10-25 |
| R2-F47 | CometBFT : un tiers fautif ou plus, accord violable | https://github.com/cometbft/cometbft (`spec/light-client/accountability/README.md`, `spec/consensus/consensus.md`) | 2026-10-25 |
| R2-F48 | CometBFT : journal de consensus, sentinelles | https://github.com/cometbft/cometbft (`docs/core/running-in-production.md`) | 2026-10-25 |
| R2-F49 | tmkms : HSM, aucune défense avec plusieurs instances actives | https://github.com/iqlusioninc/tmkms/blob/main/README.md | 2026-10-25 |
| R2-F50 | Besu QBFT et IBFT 2.0 : quatre validateurs au moins, N = 3F + 1, répartition | https://github.com/hyperledger/besu-docs (`qbft.md`, `poa.md`, `charts.md`, `cloud.md`, `ibft.md`) | 2026-10-25 |
| R2-F51 | GoQuorum : pas de Raft avec des tiers | https://github.com/Consensys/doc.goquorum (`docs/concepts/security-framework.md`) | 2026-10-25 |
| R2-F52 | EAS : identifiant de schéma dérivé du contenu | https://github.com/ethereum-attestation-service/eas-contracts/blob/master/contracts/SchemaRegistry.sol | 2026-10-25 |
| R2-F53 | EAS : identifiant d'attestation, identifiant nul | https://github.com/ethereum-attestation-service/eas-contracts (`contracts/EAS.sol`, `contracts/Common.sol`) | 2026-10-25 |
| R2-F54 | EAS : nom d'un schéma par une attestation séparée | https://github.com/ethereum-attestation-service/eas-docs-site (`docs/tutorials/naming-your-schema.md`, `docs/core--concepts/schemas.md`) | 2026-10-25 |
| R2-F55 | EIP-712 : `typeHash` | https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md | 2026-10-25 |
| R2-F56 | OpenZeppelin `AccessControl` : rôles `bytes32` | https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/AccessControl.sol | 2026-10-25 |
| R2-F57 | ERC-1967 et ERC-7201 : emplacements dérivés d'un libellé | https://github.com/ethereum/ERCs/blob/master/ERCS/erc-1967.md ; https://github.com/ethereum/ERCs/blob/master/ERCS/erc-7201.md | 2026-10-25 |
| R2-F58 | ERC-137 : normalisation des libellés | https://github.com/ethereum/ERCs/blob/master/ERCS/erc-137.md | 2026-10-25 |
| R2-F59 | dépôt : 2124 « à réserver », 2121 attribué au PoSS | présent dépôt, `chain/README.md` L36-L44, L299-L302, L319-L321 | 2026-10-25 |
| R2-F60 | noorcore : 2121 par défaut | noorcore, `core/config/config.go` L199 | 2026-10-25 |
| R2-F61 | instance sans jeton ; relais qui paie le gaz | présent dépôt, `chain/README.md` L16-L17, `contracts/AttestationRegistry.sol` L7, L50, L55 | 2026-10-25 |
| R2-F62 | `DOC_TYPE_PERIODE` recalculé | présent dépôt, `scripts/lib/registre.mjs` L68-L69, `spec/CT-6-verificateur.md` L1999 ; calcul de la note | 2026-10-25 |
| R2-F63 | quatre validateurs sur deux sites ; registre substituable | présent dépôt, `chain/README.md` L11, L309-L310, `spec/CT-1-evenements-et-formats.md` L1305 | 2026-10-25 |
| R2, conséquences de la section 3.3 | critères de substitution tirés des journaux signés : tête signée, preuves d'inclusion et de cohérence, témoins, cycle de vie | sources de R2-F24 à R2-F40 | 2026-10-25 |

### B.3 Lectures hors des notes : sections 3 à 6

Faits de code lus hors des notes pour les sections 3 à 6, relus pour cette
annexe.

| Fait | Règle | Source primaire | Consultée le |
|---|---|---|---|
| Un nœud refuse de reprendre un état de consensus dont le hachage du jeu diffère du jeu chargé, et laisse la réconciliation à l'opérateur | EX-4.13 | noorcore, `core/consensus/state.go` L184-L190, `core/node/node.go` L2174-L2196 | 2026-10-25 |
| Mempool : prix minimal 1, relèvement de remplacement de 10 %, 5 120 transactions ; pleine, refus de toute transaction dont le prix ne dépasse pas le plus bas présent ; file de nonces contigus sans borne par expéditeur ; une transaction par expéditeur et par tour, aucune éviction des transactions non prêtes | EX-4.15, EX-4.20 | noorcore, `core/txpool/txpool.go` L38-L41, L489-L507, L559-L607, L659-L700 | 2026-10-25 |
| Admission par `eth_sendRawTransaction` : taille, décodage, expéditeur, « nonce too low/too high » seulement ; aucune limite propre à la méthode ; 100 requêtes/s et rafale de 700 par adresse IP ; jeton `Bearer` unique par nœud ; transaction sans fonds écartée sans reçu ni avance du nonce ; journal durable de 24 h quand `TxJournalEnabled` | EX-4.20, EX-10.8 | noorcore, `core/rpc/jsonrpc_dispatch.go` L1620-L1651, `core/rpc/jsonrpc_http.go` L18-L33, L347-L357, `core/rpc/limits.go` L30-L31, `core/node/blockexec.go` L360-L369, `core/txpool/journal.go` L44, `core/node/txjournal.go` L63 | 2026-10-25 |
| Corps signés des enveloppes BFT : `Proposal` (membres `height` … `txsRaw`, `polkaRound`, `polkaLines`, `sig`) et `Vote` (`Height`, `Round`, `Voter`, `Type`, `BlockHash`, `Sig`) | 9.2, RG-19, CP-4 | noorcore, `core/consensus/types.go` L25-L45, L89-L96 ; recoupé sur `spec/vecteurs/ct-6/registre/capture/certificat-*.json` (présent dépôt) | 2026-10-25 |
| État de consensus dans la base de la chaîne ; état périmé effacé et reprise à tête + 1 ; aucun journal de votes ; garde de démarrage `prod-like` ; quarantaine de rattrapage à 64 hauteurs ; rattrapage par certificats décidés ; métrique d'équivocations | EX-10.9 | noorcore, `core/node/node.go` L1071, L2158-L2210, `core/main.go` L741-L790, `core/consensus/state.go` L192-L205, `core/recovery/decision.go` L60-L128, `core/node/loop_bft_state.go` L365-L383, `core/node/loop_bft_tick.go` L505-L508, `core/consensus/catchup_wire.go` L11-L33, `core/consensus/engine.go` L93-L99, L202-L208, `core/metrics/snapshot.go` L139-L141 | 2026-10-25 |
| Tarif des données d'appel : 4 gaz l'octet nul, 16 sinon | 4.5 | go-ethereum v1.17.0, `params/protocol_params.go` ; mesure sur le réseau Hardhat en mémoire (40 ancres : `gasUsed + 12 × octets nuls` constant) et décodage RLP des ancres des blocs 16660, 16664 (capture de CT-6) et 17928 (réseau de développement) | 2026-10-25 |
| Racine des transactions d'un bloc : `DeriveSha` des transactions incluses | RG-19 | noorcore, `core/node/blockexec.go` L544 ; recalcul refait pour cette annexe sur les blocs 16648, 16660 et 16668 de `spec/vecteurs/ct-6/registre/capture/` (`txsRaw` des propositions, `racineTrie` de `scripts/lib/registre.mjs`), égal à `transactionsRoot` des trois en-têtes | 2026-10-25 |
| Solde exigé avant l'exécution : `gasLimit × gasFeeCap + value` | EX-4.18 | go-ethereum v1.17.0, `core/state_transition.go` L266-L294 | 2026-10-25 |
| Transaction de type 2 : champs, encodage typé, charge signée préfixée du type | 6.7.3 | go-ethereum v1.17.0, `core/types/tx_dynamic_fee.go` L28-L43, L119-L141, `core/types/transaction.go` L125-L140, `core/types/hashing.go` L68-L76 | 2026-10-25 |
| Signature de transaction : `r` et `s` dans `[1, n − 1]`, `s ≤ n/2`, `v` dans {0, 1} ; adresse de création `keccak256(RLP([a, x]))` | 6.7.3, RG-19 | go-ethereum v1.17.0, `crypto/crypto.go` L240-L251, L79-L82 | 2026-10-25 |

### B.4 Lectures hors des notes : sections 7 à 14 et annexe A

| Fait | Source primaire | Consultée le |
|---|---|---|
| Drapeaux du nœud ; écoute « publique » limitée à une adresse vide, `0.0.0.0` ou `::` ; durcissement du maillage exigé seulement dans ce cas ; clé de validateur en fichier (EX-10.2, EX-10.7) | noorcore, `core/main.go` L50-L87, L502-L533, L697-L736 ; recherche de `pkcs11`, `yubihsm`, `kms` et signataire distant dans `core/`, sans occurrence pertinente | 2026-10-25 |
| Pairs de chaque nœud du réseau de développement : tous les autres (EX-10.6) | présent dépôt, `chain/scripts/dev-net.sh` L138-L165 | 2026-10-25 |
| Transactions brutes de la capture de CT-6 : type 2, identifiant 2124, `maxFeePerGas` 3, `maxPriorityFeePerGas` 1, limite 3 000 000, relayeur compte Hardhat 0, nonces 109 à 115 ; gaz des blocs 16648 à 16672 (`registerRecorder` 189 229, 172 279, 171 955 ; `anchor` 96 977, 96 965 ; `submitPeriod` 248 548, 234 079) | présent dépôt, `spec/vecteurs/ct-6/registre/capture/certificat-16648.json` à `certificat-16672.json` (membre `txsRaw` du corps des propositions, 9.2), décodés pour cette spécification avec ethers 6 (présent dépôt, `node_modules/ethers`) | 2026-10-25 |
| Relais d'`eth_sendRawTransaction` par un suiveur à son meneur | présent dépôt, `chain/docker/README.md` L253, L339 | 2026-10-25 |
| Organisation `assureur-demo` amorcée aux blocs 16636 et 16640, non capturés | présent dépôt, `spec/vecteurs/ct-6/registre/capture/capture.json`, `CAPTURE.md` | 2026-10-25 |
| Forme de la réponse de `noor_getCommitCertificate` ; hachage du jeu du réseau de développement | présent dépôt, `test/fixtures/certificat-commit/certificat-8316.json`, `validators.json` | 2026-10-25 |
| Administrateur initial du `CuratorSet` en paramètre ; opérations signées ; retrait d'un membre qui dépasserait le seuil | présent dépôt, `contracts/CuratorSet.sol` L119-L166, L168-L178, L188-L202 | 2026-10-25 |
| Clé de chaîne révoquée jamais réinscrite | présent dépôt, `contracts/RecorderRegistry.sol` L140-L142 | 2026-10-25 |
| Manifeste : heure pleine, `period_end = period_start + 3600` | présent dépôt, `scripts/lib/journal.mjs` L1074-L1095 | 2026-10-25 |
| Sorties de `dev-net.sh status` (code 0 avec quatre validateurs debout, 1 sinon) et de `dev-net.sh stop` ; matériel de validateur et données conservés entre deux démarrages ; sortie de `deploy-noortrace.mjs` ; refus d'écraser un fichier de déploiement | présent dépôt, `chain/scripts/dev-net.sh` L287-L316, L343-L344, `chain/README.md` L116-L119, `scripts/deploy/deploy-noortrace.mjs` L40, `scripts/lib/noortrace.mjs` L258-L263 | 2026-10-25 |
| Effets de `npm ci` et de `npm run compile` sur l'arbre de travail (7.4) : rapport d'audit soumis par défaut ; types TypeChain régénérés après toute compilation, `hh-cache/compile-cache.json` et `hh-artifacts/artifacts.d.ts` réécrits ; produits ignorés par git | présent dépôt, `.gitignore` L12-L14, `hardhat.config.mjs` L5-L8, L28-L32 ; `node_modules/@nomicfoundation/hardhat-toolbox-mocha-ethers/dist/src/index.js` L11 et `node_modules/@nomicfoundation/hardhat-typechain` 3.1.2 (`dist/src/index.js`, `dist/src/internal/hook-handlers/solidity.js`, `dist/src/internal/generate-types.js` L8-L34), Hardhat 3.20.0 ; npm 10.9.4, `docs/content/commands/npm-ci.md` (option `audit`) ; trois exécutions successives de `npm run compile` et l'épreuve d'acceptation rejouée, le 2026-10-25 | 2026-10-25 |
| Rapport de `certificat-commit.mjs` (ligne `Résultat`, codes 0, 1 et 2) ; `verifier` réseau arrêté et sans `--instance` (7.9, EX-7.15) | présent dépôt, `scripts/verify/certificat-commit.mjs` L27-L32, L250 ; `scripts/registre/noortrace-registre.mjs`, `chargerInstance` et `cmdVerifier` (arbre de travail), rejoué réseau arrêté sur `spec/vecteurs/ct-6/registre/periode-1/` le 2026-10-25 | 2026-10-25 |
| `expires_at` écrit par `condense` pour la seule opération `cloture`, membre absent des autres demandes, `outputs.expires_at` nul, « expires_at absent » affiché par `signer` (7.7) | présent dépôt, `scripts/registre/noortrace-registre.mjs`, `cmdCondense` et `cmdSigner` (arbre de travail) ; `spec/schemas/operations-registre-v0.schema.json`, `expires_at` de `demande_signature` (nul ou horodatage, non requis) ; épreuve d'acceptation rejouée le 2026-10-25 | 2026-10-25 |
| SHA-256 de `chain/config/alloc-dev.json` (EX-7.2, 7.4) | présent dépôt, fichier lu, `sha256sum` | 2026-10-25 |
| Valeurs d'exemple de 7.7, 7.10, 9.4 et A.2 (identifiants, condensés, provision, signatures RFC 6979, SHA-256 des fichiers de la capture de CT-6) | calcul pour cette spécification avec `scripts/lib/noortrace.mjs`, `scripts/lib/journal.mjs` et ethers 6 (présent dépôt) | 2026-10-25 |
